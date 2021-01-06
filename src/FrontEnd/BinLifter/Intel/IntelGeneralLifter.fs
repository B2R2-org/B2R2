(*
  B2R2 - the Next-Generation Reversing Platform

  Copyright (c) SoftSec Lab. @ KAIST, since 2016

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*)

module internal B2R2.FrontEnd.BinLifter.Intel.GeneralLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.Intel
open B2R2.FrontEnd.BinLifter.Intel.RegGroup
open B2R2.FrontEnd.BinLifter.Intel.Helper
open B2R2.FrontEnd.BinLifter.Intel.LiftingUtils

type PackType =
  | PackMask
  | PackSelect

let getInstrPtr ctxt = getRegVar ctxt (if is64bit ctxt then R.RIP else R.EIP)
let getStackPtr ctxt = getRegVar ctxt (if is64bit ctxt then R.RSP else R.ESP)
let getBasePtr ctxt = getRegVar ctxt (if is64bit ctxt then R.RBP else R.EBP)
let getRegOfSize ctxt oprSize regGrp =
  getRegVar ctxt <| match oprSize with
                    | 8<rt> -> regGrp 0
                    | 16<rt> -> regGrp 1
                    | 32<rt> -> regGrp 2
                    | 64<rt> -> regGrp 3
                    | _ -> raise InvalidOperandSizeException

let getDividend ctxt = function
  | 8<rt> -> getRegVar ctxt R.AX
  | 16<rt> -> AST.concat (getRegVar ctxt R.DX) (getRegVar ctxt R.AX)
  | 32<rt> -> AST.concat (getRegVar ctxt R.EDX) (getRegVar ctxt R.EAX)
  | 64<rt> -> AST.concat (getRegVar ctxt R.RDX) (getRegVar ctxt R.RAX)
  | _ -> raise InvalidOperandSizeException

let packCmp cmp typ e1 e2 oprSize unitWidth builder =
  let maxIdx = RegType.toBitWidth oprSize / unitWidth
  let unitSz = RegType.fromBitWidth unitWidth
  let t1, t2 = tmpVars2 oprSize
  let tmps = [| for _ in 1 .. maxIdx -> AST.tmpvar unitSz |]
  let getSrc s idx = AST.extract s unitSz (unitWidth * idx)
  let packMask e1 e2 unitSz cmp =
    let zero = AST.num0 unitSz
    AST.ite (cmp e1 e2) (maxNum unitSz) zero
  let getDst idx =
    let src1 = getSrc t1 idx
    let src2 = getSrc t2 idx
    match typ with
    | PackMask -> packMask src1 src2 unitSz cmp
    | PackSelect -> AST.ite (cmp src1 src2) src1 src2
  builder <! (t1 := e1)
  builder <! (t2 := e2)
  Array.iteri (fun i e -> builder <! (e := getDst i)) tmps
  AST.concatArr tmps

let inline padPushExpr oprSize opr =
  let isSegReg = function
    | Register.CS | Register.DS | Register.SS | Register.ES | Register.FS
    | Register.GS -> true
    | _ -> false
  match opr with
  | Var (_, s, _, _) ->
    if isSegReg <| Register.ofRegID s then AST.zext oprSize opr else opr
  | Num (_) -> AST.sext oprSize opr
  | _ -> opr

let inline getStackWidth wordSize oprSize =
  numI32 (RegType.toByteWidth oprSize) wordSize

let auxPush oprSize ctxt expr builder =
  let t = AST.tmpvar oprSize
  let sp = getStackPtr ctxt
  builder <! (t := expr)
  builder <! (sp := sp .- (getStackWidth ctxt.WordBitSize oprSize))
  builder <! (AST.loadLE oprSize sp := t)

let auxPop oprSize ctxt dst builder =
  let sp = getStackPtr ctxt
  let isSegReg = function
    | Register.GS | Register.FS | Register.DS
    | Register.SS | Register.ES -> true
    | _ -> false
  let handleSegPop oprSize = function
    | Var (_, x, _, _) when isSegReg <| Register.ofRegID x -> 16<rt>
    | _ -> oprSize
  builder <! (dst := AST.loadLE (handleSegPop oprSize dst) sp)
  builder <! (sp := sp .+ (getStackWidth ctxt.WordBitSize oprSize))

let getCondOfJcc (ins: InsInfo) (ctxt: TranslationContext) oprSize =
  if ctxt.WordBitSize = 64<rt> && oprSize = 16<rt>
  then Utils.impossible ()
  match ins.Opcode with
  | Opcode.JO -> getRegVar ctxt R.OF
  | Opcode.JNO -> getRegVar ctxt R.OF == AST.b0
  | Opcode.JB -> getRegVar ctxt R.CF
  | Opcode.JNB -> getRegVar ctxt R.CF == AST.b0
  | Opcode.JZ -> getRegVar ctxt R.ZF
  | Opcode.JNZ -> getRegVar ctxt R.ZF == AST.b0
  | Opcode.JBE -> (getRegVar ctxt R.CF) .| (getRegVar ctxt R.ZF)
  | Opcode.JA -> ((getRegVar ctxt R.CF) .| (getRegVar ctxt R.ZF)) == AST.b0
  | Opcode.JS -> getRegVar ctxt R.SF
  | Opcode.JNS -> getRegVar ctxt R.SF == AST.b0
  | Opcode.JP -> getRegVar ctxt R.PF
  | Opcode.JNP -> getRegVar ctxt R.PF == AST.b0
  | Opcode.JL -> getRegVar ctxt R.SF != getRegVar ctxt R.OF
  | Opcode.JNL -> getRegVar ctxt R.SF == getRegVar ctxt R.OF
  | Opcode.JLE -> (getRegVar ctxt R.ZF) .|
                  (getRegVar ctxt R.SF != getRegVar ctxt R.OF)
  | Opcode.JG -> (getRegVar ctxt R.ZF == AST.b0) .&
                 (getRegVar ctxt R.SF == getRegVar ctxt R.OF)
  | Opcode.JCXZ -> (getRegVar ctxt R.CX) == (AST.num0 ctxt.WordBitSize)
  | Opcode.JECXZ ->
    let addrSize = ctxt.WordBitSize
    (AST.cast CastKind.ZeroExt addrSize (getRegVar ctxt R.ECX)) == (AST.num0 addrSize)
  | Opcode.JRCXZ -> (getRegVar ctxt R.RCX) == (AST.num0 ctxt.WordBitSize)
  | _ -> raise InvalidOpcodeException

let getCondOfSet (ins: InsInfo) ctxt =
  match ins.Opcode with
  | Opcode.SETO   -> getRegVar ctxt R.OF
  | Opcode.SETNO  -> getRegVar ctxt R.OF == AST.b0
  | Opcode.SETB   -> getRegVar ctxt R.CF
  | Opcode.SETNB  -> getRegVar ctxt R.CF == AST.b0
  | Opcode.SETZ   -> getRegVar ctxt R.ZF
  | Opcode.SETNZ  -> getRegVar ctxt R.ZF == AST.b0
  | Opcode.SETBE  -> (getRegVar ctxt R.CF) .| (getRegVar ctxt R.ZF)
  | Opcode.SETA   -> ((getRegVar ctxt R.CF) .| (getRegVar ctxt R.ZF)) == AST.b0
  | Opcode.SETS   -> getRegVar ctxt R.SF
  | Opcode.SETNS  -> getRegVar ctxt R.SF == AST.b0
  | Opcode.SETP   -> getRegVar ctxt R.PF
  | Opcode.SETNP  -> getRegVar ctxt R.PF == AST.b0
  | Opcode.SETL   -> getRegVar ctxt R.SF != getRegVar ctxt R.OF
  | Opcode.SETNL  -> getRegVar ctxt R.SF == getRegVar ctxt R.OF
  | Opcode.SETLE  -> getRegVar ctxt R.ZF .|
                     (getRegVar ctxt R.SF != getRegVar ctxt R.OF)
  | Opcode.SETG   -> (getRegVar ctxt R.ZF == AST.b0) .&
                     (getRegVar ctxt R.SF == getRegVar ctxt R.OF)
  | _ -> raise InvalidOpcodeException

let convertSrc = function
  | Load (_, _, expr, _, _) -> expr
  | _ -> Utils.impossible ()

let getCondOfCMov (ins: InsInfo) ctxt =
  match ins.Opcode with
  | Opcode.CMOVO   -> getRegVar ctxt R.OF
  | Opcode.CMOVNO  -> getRegVar ctxt R.OF == AST.b0
  | Opcode.CMOVB   -> getRegVar ctxt R.CF
  | Opcode.CMOVAE  -> getRegVar ctxt R.CF == AST.b0
  | Opcode.CMOVZ   -> getRegVar ctxt R.ZF
  | Opcode.CMOVNZ  -> getRegVar ctxt R.ZF == AST.b0
  | Opcode.CMOVBE  -> (getRegVar ctxt R.CF) .| (getRegVar ctxt R.ZF)
  | Opcode.CMOVA   -> ((getRegVar ctxt R.CF) .| (getRegVar ctxt R.ZF)) == AST.b0
  | Opcode.CMOVS   -> getRegVar ctxt R.SF
  | Opcode.CMOVNS  -> getRegVar ctxt R.SF == AST.b0
  | Opcode.CMOVP   -> getRegVar ctxt R.PF
  | Opcode.CMOVNP  -> getRegVar ctxt R.PF == AST.b0
  | Opcode.CMOVL   -> getRegVar ctxt R.SF != getRegVar ctxt R.OF
  | Opcode.CMOVGE  -> getRegVar ctxt R.SF == getRegVar ctxt R.OF
  | Opcode.CMOVLE  -> getRegVar ctxt R.ZF .|
                      (getRegVar ctxt R.SF != getRegVar ctxt R.OF)
  | Opcode.CMOVG   -> getRegVar ctxt R.ZF == AST.b0 .&
                      (getRegVar ctxt R.SF == getRegVar ctxt R.OF)
  | _ -> raise InvalidOpcodeException

let maskOffset offset oprSize =
  let offset = AST.zext oprSize offset
  match oprSize with
  | 16<rt> -> offset .& numU32 0xFu 16<rt>
  | 32<rt> -> offset .& numU32 0x1Fu 32<rt>
  | 64<rt> -> offset .& numU32 0x3Fu 64<rt>
  | _ -> raise InvalidOperandSizeException

let rec isVar = function
  | Var _ | TempVar _ -> true
  | Extract (e, _, _, _, _) -> isVar e
  | _ -> false

let calculateOffset offset oprSize =
  let offset = AST.zext oprSize offset
  match oprSize with
  | 16<rt> -> numU32 2u 16<rt> .* (offset ./ numU32 16u 16<rt>),
              offset .& numU32 15u 16<rt>
  | 32<rt> -> numU32 4u 32<rt> .* (offset ./ numU32 32u 32<rt>),
              offset .& numU32 31u 32<rt>
  | 64<rt> -> numU32 4u 64<rt> .* (offset ./ numU32 32u 64<rt>),
              offset .& numU32 31u 64<rt>
  | _ -> raise InvalidOperandSizeException

let bit ins bitBase bitOffset oprSize =
  match bitBase with
  | Load (e, t, expr, _, _) ->
    let effAddrSz = getEffAddrSz ins
    let addrOffset, bitOffset = calculateOffset bitOffset oprSize
    let addrOffset = AST.zext effAddrSz addrOffset
    AST.xtlo 1<rt> ((AST.load e t (expr .+ addrOffset)) >> bitOffset)
  | _ -> if isVar bitBase
         then AST.xtlo 1<rt> (bitBase >> maskOffset bitOffset oprSize)
         else raise InvalidExprException

let setBit ins bitBase bitOffset oprSize setValue =
  match bitBase with
  | Load (e, t, expr, _, _) ->
    let effAddrSz = getEffAddrSz ins
    let addrOffset, bitOffset = calculateOffset bitOffset oprSize
    let addrOffset = AST.zext effAddrSz addrOffset
    let mask = setValue << bitOffset
    let loadMem = AST.load e t (expr .+ addrOffset)
    loadMem := (loadMem .& (getMask oprSize .- mask)) .| mask
  | _ -> if isVar bitBase
         then let mask = setValue << maskOffset bitOffset oprSize
              bitBase := (bitBase .& (getMask oprSize .- mask)) .| mask
         else raise InvalidExprException

let rec subPackedByte opFn s1 s2 (tDstArr: Expr []) oprSz sepSz idx sz builder =
  let tS1, tS2 = tmpVars2 sepSz
  if sz = 0 then ()
  else builder <! (tS1 := AST.extract s1 sepSz (idx * 8))
       builder <! (tS2 := AST.extract s2 sepSz (idx * 8))
       builder <! (tDstArr.[int idx] := opFn tS1 tS2)
       subPackedByte opFn s1 s2 tDstArr oprSz sepSz (idx + 1) (sz - 1) builder

let getPsubbExpr src1 src2 oprSize builder =
  let size = RegType.toByteWidth oprSize
  let tDstArr = [| for _ in 1 .. size -> AST.tmpvar 8<rt> |]
  subPackedByte (.-) src1 src2 tDstArr oprSize 8<rt> 0 size builder
  AST.concatArr tDstArr

let oneOperandImul ins insAddr insLen ctxt oprSize builder =
  let src = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  let sF = getRegVar ctxt R.SF
  let shiftNum = RegType.toBitWidth oprSize
  let mulSize = RegType.double oprSize
  let t = AST.tmpvar mulSize
  let cond = AST.sext mulSize (AST.xtlo oprSize t) == t
  match oprSize with
  | 8<rt> ->
    builder <! (t := AST.sext mulSize (getRegVar ctxt R.AL) .* AST.sext mulSize src)
    builder <! (dstAssign oprSize (getRegVar ctxt R.AX) t)
  | 16<rt> | 32<rt> | 64<rt> ->
    let r1 = getRegOfSize ctxt oprSize grpEDX
    let r2 = getRegOfSize ctxt oprSize grpEAX
    builder <! (t := AST.sext mulSize r2 .* AST.sext mulSize src)
    builder <! (dstAssign oprSize r1 (AST.xthi oprSize t))
    builder <! (dstAssign oprSize r2 (AST.xtlo oprSize t))
  | _ -> raise InvalidOperandSizeException
  builder <! (sF := AST.extract t 1<rt> (shiftNum - 1))
  builder <! (getRegVar ctxt R.CF := cond == AST.b0)
  builder <! (getRegVar ctxt R.OF := cond == AST.b0)

let operandsImul (ins: InsInfo) insAddr insLen ctxt oprSize builder =
  let dst, src1, src2 =
    match ins.Operands with
    | TwoOperands _ ->
      let d, s = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
      d, d, s
    | ThreeOperands _ ->
      getThreeOprs ins |> transThreeOprs ins insAddr insLen ctxt
    | _ -> raise InvalidOperandException
  let doubleWidth = RegType.double oprSize
  let t = AST.tmpvar doubleWidth
  let cond = (AST.sext doubleWidth dst) != t
  builder <! (t := AST.sext doubleWidth src1 .* AST.sext doubleWidth src2)
  builder <! (dstAssign oprSize dst (AST.xtlo oprSize t))
  builder <! (getRegVar ctxt R.SF := AST.xthi 1<rt> dst)
  builder <! (getRegVar ctxt R.CF := cond)
  builder <! (getRegVar ctxt R.OF := cond)

let strRepeat (ctxt: TranslationContext) body cond insAddr insLen builder =
  let lblExit = AST.symbol "Exit"
  let lblCont = AST.symbol "Continue"
  let lblNext = AST.symbol "Next"
  let n0 = AST.num0 ctxt.WordBitSize
  let cx = getRegVar ctxt (if is64bit ctxt then R.RCX else R.ECX)
  let pc = getInstrPtr ctxt
  let cinstAddr = numAddr insAddr ctxt
  let ninstAddr = cinstAddr .+ numInsLen insLen ctxt
  builder <! (CJmp (cx == n0, Name lblExit, Name lblCont))
  builder <! (LMark lblCont)
  body ()
  builder <! (cx := cx .- AST.num1 ctxt.WordBitSize)
  match cond with
  | None -> builder <! (InterJmp (pc, cinstAddr, InterJmpInfo.Base))
  | Some cond ->
    builder <! (CJmp (cx == n0, Name lblExit, Name lblNext))
    builder <! (LMark lblNext)
    builder <! (InterCJmp (cond, pc, ninstAddr, cinstAddr))
  builder <! (LMark lblExit)
  (* We consider each individual loop from a REP-prefixed instruction as an
     independent basic block, because it is more intuitive and matches with
     the definition of basic block from text books. *)
  builder <! (InterJmp (pc, ninstAddr, InterJmpInfo.Base))

let aaa ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let oprSize = getOperationSize ins
  let al = getRegVar ctxt R.AL
  let af = getRegVar ctxt R.AF
  let ax = getRegVar ctxt R.AX
  let cf = getRegVar ctxt R.CF
  let alAnd0f = al .& numI32 0x0f 8<rt>
  let cond1 = AST.gt alAnd0f (numI32 9 8<rt>)
  let cond2 = af == AST.b1
  let cond = AST.tmpvar 1<rt>
  startMark insAddr insLen builder
  if oprSize = 64<rt> then ()
  else
    builder <! (cond := cond1 .| cond2)
    builder <! (ax := AST.ite cond (ax .+ numI32 0x106 16<rt>) ax)
    builder <! (af := AST.ite cond AST.b1 AST.b0)
    builder <! (cf := AST.ite cond AST.b1 AST.b0)
    builder <! (al := alAnd0f)
    builder <! (getRegVar ctxt R.OF := undefOF)
    builder <! (getRegVar ctxt R.SF := undefSF)
    builder <! (getRegVar ctxt R.ZF := undefZF)
    builder <! (getRegVar ctxt R.PF := undefPF)
  endMark insAddr insLen builder

let aad ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let imm8 =
    getOneOpr ins |> transOneOpr ins insAddr insLen ctxt |> AST.xtlo 8<rt>
  let oprSize = getOperationSize ins
  let al = getRegVar ctxt R.AL
  let ah = getRegVar ctxt R.AH
  startMark insAddr insLen builder
  if oprSize = 64<rt> then ()
  else
    builder <! (al := (al .+ (ah .* imm8)) .& (numI32 0xff 8<rt>))
    builder <! (ah := AST.num0 8<rt>)
    enumSZPFlags ctxt al 8<rt> builder
    builder <! (getRegVar ctxt R.OF := undefOF)
    builder <! (getRegVar ctxt R.AF := undefAF)
    builder <! (getRegVar ctxt R.CF := undefCF)
  endMark insAddr insLen builder

let aam ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let imm8 =
    getOneOpr ins |> transOneOpr ins insAddr insLen ctxt |>  AST.xtlo 8<rt>
  let oprSize = getOperationSize ins
  let al = getRegVar ctxt R.AL
  let ah = getRegVar ctxt R.AH
  startMark insAddr insLen builder
  if oprSize = 64<rt> then ()
  else
    builder <! (ah := al ./ imm8)
    builder <! (al := al .% imm8)
    enumSZPFlags ctxt al 8<rt> builder
    builder <! (getRegVar ctxt R.OF := undefOF)
    builder <! (getRegVar ctxt R.AF := undefAF)
    builder <! (getRegVar ctxt R.CF := undefCF)
  endMark insAddr insLen builder

let aas ins insAddr insLen ctxt =
  let builder = StmtBuilder (14)
  let oprSize = getOperationSize ins
  let ax = getRegVar ctxt R.AX
  let al = getRegVar ctxt R.AL
  let af = getRegVar ctxt R.AF
  let cf = getRegVar ctxt R.CF
  let ah = getRegVar ctxt R.AH
  let alAnd0f = al .& numI32 0x0f 8<rt>
  let cond1 = AST.gt alAnd0f (numI32 9 8<rt>)
  let cond2 = af == AST.b1
  let cond = AST.tmpvar 1<rt>
  startMark insAddr insLen builder
  if oprSize = 64<rt> then ()
  else
    builder <! (cond := cond1 .| cond2)
    builder <! (ax := AST.ite cond (ax .- numI32 6 16<rt>) ax)
    builder <! (ah := AST.ite cond (ah .- AST.num1 8<rt>) ah)
    builder <! (af := AST.ite cond AST.b1 AST.b0)
    builder <! (cf := AST.ite cond AST.b1 AST.b0)
    builder <! (al := alAnd0f)
  endMark insAddr insLen builder

let adc ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let cf = getRegVar ctxt R.CF
  let t1, t2, t3, t4 = tmpVars4 oprSize
  startMark insAddr insLen builder
  builder <! (t1 := dst)
  builder <! (t2 := AST.sext oprSize src)
  builder <! (t3 := t2 .+ AST.zext oprSize cf)
  builder <! (t4 := t1 .+ t3)
  builder <! (dstAssign oprSize dst t4)
  builder <! (cf := AST.lt t3 t2 .| AST.lt t4 t1)
  builder <! (getRegVar ctxt R.OF := getOFlagOnAdd t1 t2 t4)
  enumASZPFlags ctxt t1 t2 t4 oprSize builder
  endMark insAddr insLen builder

let add ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let t1, t2, t3 = tmpVars3 oprSize
  startMark insAddr insLen builder
  builder <! (t1 := dst)
  builder <! (t2 := src)
  builder <! (t3 := t1 .+ t2)
  builder <! (dstAssign oprSize dst t3)
  enumEFLAGS ctxt t1 t2 t3 oprSize getCFlagOnAdd getOFlagOnAdd builder
  endMark insAddr insLen builder

let logAnd ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let t = AST.tmpvar oprSize
  startMark insAddr insLen builder
  builder <! (t := dst .& AST.sext oprSize src)
  builder <! (dstAssign oprSize dst t)
  builder <! (getRegVar ctxt R.OF := AST.b0)
  builder <! (getRegVar ctxt R.CF := AST.b0)
  builder <! (getRegVar ctxt R.AF := undefAF)
  enumSZPFlags ctxt t oprSize builder
  endMark insAddr insLen builder

let arpl ins insAddr insLen ctxt =
  if is64bit ctxt then Utils.impossible () else ()
  let builder = StmtBuilder (8)
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let t1, t2 = tmpVars2 16<rt>
  let mask = numI32 0xfffc 16<rt>
  let zF = getRegVar ctxt R.ZF
  startMark insAddr insLen builder
  builder <! (t1 := dst .& numI32 0x3 16<rt>)
  builder <! (t2 := src .& numI32 0x3 16<rt>)
  builder <! (dst := AST.ite (AST.lt t1 t2) ((dst .& mask) .| t2) dst)
  builder <! (zF := AST.lt t1 t2)
  endMark insAddr insLen builder

let bndmov ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let dst, src = getTwoOprs ins
  startMark insAddr insLen builder
  if is64bit ctxt then
    let dst1, dst2 = transOprToExpr128 ins insAddr insLen ctxt dst
    let src1, src2 = transOprToExpr128 ins insAddr insLen ctxt src
    startMark insAddr insLen builder
    builder <! (dst1 := src1)
    builder <! (dst2 := src2)
  else
    match dst, src with
    | OprReg _, OprMem _ ->
      let dst1, dst2 = transOprToExpr128 ins insAddr insLen ctxt dst
      let src = transOprToExpr ins insAddr insLen ctxt src
      builder <! (dst1 := AST.xthi 32<rt> src |> AST.zext 64<rt>)
      builder <! (dst2 := AST.xtlo 32<rt> src |> AST.zext 64<rt>)
    | OprMem _, OprReg _ ->
      let src1, src2 = transOprToExpr128 ins insAddr insLen ctxt src
      let dst = transOprToExpr ins insAddr insLen ctxt dst
      builder <! (AST.xthi 32<rt> dst := AST.xtlo 32<rt> src1)
      builder <! (AST.xtlo 32<rt> dst := AST.xtlo 32<rt> src2)
    | _ -> raise InvalidOperandException
  endMark insAddr insLen builder

let bsf ins insAddr insLen ctxt =
  let builder = StmtBuilder (32)
  let lblL0 = AST.symbol "L0"
  let lblL1 = AST.symbol "L1"
  let lblEnd = AST.symbol "End"
  let lblLoopCond = AST.symbol "LoopCond"
  let lblLoopEnd = AST.symbol "LoopEnd"
  let lblLoop = AST.symbol "Loop"
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let cond = src == AST.num0 oprSize
  let t = AST.tmpvar oprSize
  startMark insAddr insLen builder
  builder <! (CJmp (cond, Name lblL0, Name lblL1))
  builder <! (LMark lblL0)
  builder <! (getRegVar ctxt R.ZF := AST.b1)
  builder <! (dst := AST.undef oprSize "DEST is undefined.")
  builder <! (Jmp (Name lblEnd))
  builder <! (LMark lblL1)
  builder <! (getRegVar ctxt R.ZF := AST.b0)
  builder <! (t := AST.num0 oprSize)
  builder <! (LMark lblLoopCond)
  builder <!
    (CJmp ((AST.xtlo 1<rt> (src >> t)) == AST.b0, Name lblLoop, Name lblLoopEnd))
  builder <! (LMark lblLoop)
  builder <! (t := t .+ AST.num1 oprSize)
  builder <! (Jmp (Name lblLoopCond))
  builder <! (LMark lblLoopEnd)
  builder <! (dstAssign oprSize dst t)
  builder <! (LMark lblEnd)
  builder <! (getRegVar ctxt R.CF := undefCF)
  builder <! (getRegVar ctxt R.OF := undefOF)
  builder <! (getRegVar ctxt R.AF := undefAF)
  builder <! (getRegVar ctxt R.SF := undefSF)
  builder <! (getRegVar ctxt R.PF := undefPF)
  endMark insAddr insLen builder

let bsr ins insAddr insLen ctxt =
  let builder = StmtBuilder (32)
  let lblL0 = AST.symbol "L0"
  let lblL1 = AST.symbol "L1"
  let lblEnd = AST.symbol "End"
  let lblLoopCond = AST.symbol "LoopCond"
  let lblLoopE = AST.symbol "LoopEnd"
  let lblLoop = AST.symbol "Loop"
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let cond = src == AST.num0 oprSize
  let t = AST.tmpvar oprSize
  startMark insAddr insLen builder
  builder <! (CJmp (cond, Name lblL0, Name lblL1))
  builder <! (LMark lblL0)
  builder <! (getRegVar ctxt R.ZF := AST.b1)
  builder <! (dst := AST.undef oprSize "DEST is undefined.")
  builder <! (Jmp (Name lblEnd))
  builder <! (LMark lblL1)
  builder <! (getRegVar ctxt R.ZF := AST.b0)
  builder <! (t := numOprSize oprSize .- AST.num1 oprSize)
  builder <! (LMark lblLoopCond)
  builder <!
    (CJmp ((AST.xtlo 1<rt> (src >> t)) == AST.b0, Name lblLoop, Name lblLoopE))
  builder <! (LMark lblLoop)
  builder <! (t := t .- AST.num1 oprSize)
  builder <! (Jmp (Name lblLoopCond))
  builder <! (LMark lblLoopE)
  builder <! (dst := t)
  builder <! (LMark lblEnd)
  builder <! (getRegVar ctxt R.CF := undefCF)
  builder <! (getRegVar ctxt R.OF := undefOF)
  builder <! (getRegVar ctxt R.AF := undefAF)
  builder <! (getRegVar ctxt R.SF := undefSF)
  builder <! (getRegVar ctxt R.PF := undefPF)
  endMark insAddr insLen builder

let bswap ins insAddr insLen ctxt =
  let dst = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let t = AST.tmpvar oprSize
  let cnt = RegType.toByteWidth oprSize |> int
  let tmps = Array.init cnt (fun _ -> AST.tmpvar 8<rt>)
  let builder = StmtBuilder (2 * cnt)
  startMark insAddr insLen builder
  builder <! (t := dst)
  for i in 0 .. cnt - 1 do
    builder <! (tmps.[i] := AST.extract t 8<rt> (i * 8))
  done
  builder <! (dstAssign oprSize dst (AST.concatArr (Array.rev tmps)))
  endMark insAddr insLen builder

let bt ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let bitBase, bitOffset =
    getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  builder <! (getRegVar ctxt R.CF := bit ins bitBase bitOffset oprSize)
  builder <! (getRegVar ctxt R.OF := undefOF)
  builder <! (getRegVar ctxt R.SF := undefSF)
  builder <! (getRegVar ctxt R.AF := undefAF)
  builder <! (getRegVar ctxt R.PF := undefPF)
  endMark insAddr insLen builder

let bitTest ins insAddr insLen ctxt setValue =
  let builder = StmtBuilder (8)
  let bitBase, bitOffset =
    getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let setValue = AST.zext oprSize setValue
  startMark insAddr insLen builder
  builder <! (getRegVar ctxt R.CF := bit ins bitBase bitOffset oprSize)
  builder <! (setBit ins bitBase bitOffset oprSize setValue)
  builder <! (getRegVar ctxt R.OF := undefOF)
  builder <! (getRegVar ctxt R.SF := undefSF)
  builder <! (getRegVar ctxt R.AF := undefAF)
  builder <! (getRegVar ctxt R.PF := undefPF)
  endMark insAddr insLen builder

let btc ins insAddr insLen ctxt =
  bitTest ins insAddr insLen ctxt (getRegVar ctxt R.CF |> AST.not)
let btr ins insAddr insLen ctxt = bitTest ins insAddr insLen ctxt AST.b0
let bts ins insAddr insLen ctxt = bitTest ins insAddr insLen ctxt AST.b1

let call ins insAddr insLen ctxt isFar =
  let builder = StmtBuilder (4)
  match isFar with
  | false ->
    let pc = getInstrPtr ctxt
    let target = AST.tmpvar ctxt.WordBitSize
    let oprSize = getOperationSize ins
    startMark insAddr insLen builder
    builder <! (target := getOneOpr ins |> transOneOpr ins insAddr insLen ctxt)
    let r = (numAddr insAddr ctxt .+ numInsLen insLen ctxt)
    auxPush oprSize ctxt r builder
    builder <! (InterJmp (pc, target, InterJmpInfo.IsCall))
    endMark insAddr insLen builder
  | true -> sideEffects insAddr insLen UnsupportedFAR

let convBWQ ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let oprSize = getOperationSize ins
  let opr = getRegVar ctxt (if is64bit ctxt then R.RAX else R.EAX)
  startMark insAddr insLen builder
  match oprSize with
  | 16<rt> ->
    builder <! (AST.xtlo 16<rt> opr := AST.sext 16<rt> (AST.xtlo 8<rt> opr))
  | 32<rt> ->
    builder <! (AST.xtlo 32<rt> opr := AST.sext 32<rt> (AST.xtlo 16<rt> opr))
  | 64<rt> ->
    builder <! (opr := AST.sext 64<rt> (AST.xtlo 32<rt> opr))
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let clearFlag insAddr insLen ctxt flagReg =
  let builder = StmtBuilder (4)
  startMark insAddr insLen builder
  builder <! (getRegVar ctxt flagReg := AST.b0)
  endMark insAddr insLen builder

let cmc ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let cf = getRegVar ctxt R.CF
  startMark insAddr insLen builder
  builder <! (cf := AST.not cf)
  builder <! (getRegVar ctxt R.OF := undefOF)
  builder <! (getRegVar ctxt R.AF := undefAF)
  builder <! (getRegVar ctxt R.SF := undefSF)
  builder <! (getRegVar ctxt R.ZF := undefZF)
  builder <! (getRegVar ctxt R.PF := undefPF)
  endMark insAddr insLen builder

let cmovcc ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  builder <! (dstAssign oprSize dst (AST.ite (getCondOfCMov ins ctxt) src dst))
  endMark insAddr insLen builder

let cmp ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let src1, src2 = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let s1 = AST.tmpvar oprSize
  let r, ext = tmpVars2 oprSize
  startMark insAddr insLen builder
  builder <! (s1 := src1)
  builder <! (ext := AST.sext oprSize src2)
  builder <! (r := s1 .- ext)
  enumEFLAGS ctxt s1 ext r oprSize getCFlagOnSub getOFlagOnSub builder
  endMark insAddr insLen builder

let cmps ins insAddr insLen ctxt =
  let builder = StmtBuilder (32)
  startMark insAddr insLen builder
  let pref = ins.Prefixes
  let body () =
    let oprSize = getOperationSize ins
    let df = getRegVar ctxt R.DF
    let si = getRegVar ctxt (if is64bit ctxt then R.RSI else R.ESI)
    let di = getRegVar ctxt (if is64bit ctxt then R.RDI else R.EDI)
    let src1 = AST.loadLE oprSize si
    let src2 = AST.loadLE oprSize di
    let t1, t2, t3 = tmpVars3 oprSize
    builder <! (t1 := src1)
    builder <! (t2 := src2)
    builder <! (t3 := t1 .- t2)
    let amount = numI32 (RegType.toByteWidth oprSize) ctxt.WordBitSize
    builder <! (si := AST.ite df (si .- amount) (si .+ amount))
    builder <! (di := AST.ite df (di .- amount) (di .+ amount))
    enumEFLAGS ctxt t1 t2 t3 oprSize getCFlagOnSub getOFlagOnSub builder
  let zf = getRegVar ctxt R.ZF
  if hasREPZ pref then
    strRepeat ctxt body (Some (zf == AST.b0)) insAddr insLen builder
  elif hasREPNZ pref then
    strRepeat ctxt body (Some (zf)) insAddr insLen builder
  else body ()
  endMark insAddr insLen builder

let cmpxchg ins insAddr insLen ctxt =
  let builder = StmtBuilder (32)
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  if hasLock ins.Prefixes then builder <! (SideEffect Lock)
  let t = AST.tmpvar oprSize
  builder <! (t := dst)
  let r = AST.tmpvar oprSize
  let acc = getRegOfSize ctxt oprSize grpEAX
  let cond = AST.tmpvar 1<rt>
  builder <! (r := acc .- t)
  builder <! (cond := acc == t)
  builder <! (getRegVar ctxt R.ZF := AST.ite cond AST.b1 AST.b0)
  builder <! (dstAssign oprSize dst (AST.ite cond src t))
  builder <! (dstAssign oprSize acc (AST.ite cond acc t))
  builder <! (getRegVar ctxt R.OF := getOFlagOnSub acc t r)
  builder <! (getRegVar ctxt R.SF := AST.xthi 1<rt> r)
  builder <! (buildAF ctxt acc t r oprSize)
  buildPF ctxt r oprSize None builder
  builder <! (getRegVar ctxt R.CF := AST.lt (acc .+ t) acc)
  endMark insAddr insLen builder

let compareExchangeBytes ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst = getOneOpr ins
  let oprSize = getOperationSize ins
  let zf = getRegVar ctxt R.ZF
  let cond = AST.tmpvar 1<rt>
  startMark insAddr insLen builder
  match oprSize with
  | 64<rt> ->
    let dst = transOneOpr ins insAddr insLen ctxt dst
    let edx = getRegOfSize ctxt 32<rt> grpEDX
    let eax = getRegOfSize ctxt 32<rt> grpEAX
    let ecx = getRegOfSize ctxt 32<rt> grpECX
    let ebx = getRegOfSize ctxt 32<rt> grpEBX
    let t = AST.tmpvar oprSize
    builder <! (t := dst)
    builder <! (cond := AST.concat edx eax == t)
    builder <! (zf := cond)
    builder <! (eax := AST.ite cond eax (AST.extract t 32<rt> 0))
    builder <! (edx := AST.ite cond edx (AST.extract t 32<rt> 32))
    builder <! (dst := AST.ite cond (AST.concat ecx ebx) t)
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let rdx = getRegOfSize ctxt 64<rt> grpEDX
    let rax = getRegOfSize ctxt 64<rt> grpEAX
    let rcx = getRegOfSize ctxt 64<rt> grpECX
    let rbx = getRegOfSize ctxt 64<rt> grpEBX
    builder <! (cond := (dstB == rdx) .& (dstA == rax))
    builder <! (zf := cond)
    builder <! (rax := AST.ite cond rax dstA)
    builder <! (rdx := AST.ite cond rdx dstB)
    builder <! (dstA := AST.ite cond rbx dstA)
    builder <! (dstB := AST.ite cond rcx dstB)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let convWDQ ins insAddr insLen (ctxt: TranslationContext) =
  let builder = StmtBuilder (8)
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  match oprSize, ctxt.WordBitSize with
  | 16<rt>, _ ->
    let t = AST.tmpvar 32<rt>
    let ax = getRegVar ctxt R.AX
    let dx = getRegVar ctxt R.DX
    builder <! (t := AST.sext 32<rt> ax)
    builder <! (dx := AST.xthi 16<rt> t)
    builder <! (ax := AST.xtlo 16<rt> t)
  | 32<rt>, _ ->
    let t = AST.tmpvar 64<rt>
    let eax = getRegVar ctxt R.EAX
    let edx = getRegVar ctxt R.EDX
    builder <! (t := AST.sext 64<rt> eax)
    builder <! (edx := AST.xthi 32<rt> t)
    builder <! (eax := AST.xtlo 32<rt> t)
  | 64<rt>, 64<rt> ->
    let t = AST.tmpvar 128<rt>
    let rdx = getRegVar ctxt R.RDX
    let rax = getRegVar ctxt R.RAX
    builder <! (t := AST.sext 128<rt> rax)
    builder <! (rdx := AST.xthi 64<rt> t)
    builder <! (rax := AST.xtlo 64<rt> t)
  | _, _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let daa ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let oprSize = getOperationSize ins
  let al = getRegVar ctxt R.AL
  let cf = getRegVar ctxt R.CF
  let af = getRegVar ctxt R.AF
  let oldAl = AST.tmpvar 8<rt>
  let oldCf = AST.tmpvar 1<rt>
  let alAnd0f = al .& numI32 0x0f 8<rt>
  let subCond1 = AST.gt alAnd0f (numI32 9 8<rt>)
  let subCond2 = af == AST.b1
  let cond1 = AST.tmpvar 1<rt>
  let subCond3 = AST.gt oldAl (numI32 0x99 8<rt>)
  let subCond4 = oldCf == AST.b1
  let cond2 = AST.tmpvar 1<rt>
  startMark insAddr insLen builder
  if oprSize = 64<rt> then ()
  else
    builder <! (oldAl := al)
    builder <! (oldCf := cf)
    builder <! (cf := AST.b0)
    builder <! (cond1 := subCond1 .| subCond2)
    builder <! (al := AST.ite cond1 (al .+ numI32 6 8<rt>) al)
    builder <! (cf := AST.ite cond1 oldCf cf)
    builder <! (af := cond1)
    builder <! (cond2 := subCond3 .| subCond4)
    builder <! (al := AST.ite cond2 (al .+ numI32 0x60 8<rt>) al)
    builder <! (cf := cond2)
    enumSZPFlags ctxt al 8<rt> builder
    builder <! (getRegVar ctxt R.OF := undefOF)
  endMark insAddr insLen builder

let das ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let oprSize = getOperationSize ins
  let al = getRegVar ctxt R.AL
  let cf = getRegVar ctxt R.CF
  let af = getRegVar ctxt R.AF
  let oldAl = AST.tmpvar 8<rt>
  let oldCf = AST.tmpvar 1<rt>
  let alAnd0f = al .& numI32 0x0f 8<rt>
  let subCond1 = AST.gt alAnd0f (numI32 9 8<rt>)
  let subCond2 = af == AST.b1
  let cond1 = AST.tmpvar 1<rt>
  let subCond3 = AST.gt oldAl (numI32 0x99 8<rt>)
  let subCond4 = oldCf == AST.b1
  let cond2 = AST.tmpvar 1<rt>
  startMark insAddr insLen builder
  if oprSize = 64<rt> then ()
  else
    builder <! (oldAl := al)
    builder <! (oldCf := cf)
    builder <! (cf := AST.b0)
    builder <! (cond1 := subCond1 .| subCond2)
    builder <! (al := AST.ite cond1 (al .- numI32 6 8<rt>) al)
    builder <! (cf := AST.ite cond1 oldCf cf)
    builder <! (af := cond1)
    builder <! (cond2 := subCond3 .| subCond4)
    builder <! (al := AST.ite cond2 (al .- numI32 0x60 8<rt>) al)
    builder <! (cf := cond2)
    enumSZPFlags ctxt al 8<rt> builder
    builder <! (getRegVar ctxt R.OF := undefOF)
  endMark insAddr insLen builder

let dec ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let dst = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let t1, t2, t3 = tmpVars3 oprSize
  startMark insAddr insLen builder
  builder <! (t1 := dst)
  builder <! (t2 := AST.num1 oprSize)
  builder <! (t3 := (t1 .- t2))
  builder <! (dstAssign oprSize dst t3)
  builder <! (getRegVar ctxt R.OF := getOFlagOnSub t1 t2 t3)
  enumASZPFlags ctxt t1 t2 t3 oprSize builder
  endMark insAddr insLen builder

let div ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let lblAssign = AST.symbol "Assign"
  let lblChk = AST.symbol "Check"
  let lblErr = AST.symbol "DivErr"
  let divisor = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  builder <! (CJmp (divisor == AST.num0 oprSize, Name lblErr, Name lblChk))
  builder <! (LMark lblErr)
  builder <! SideEffect (Trap "DivErr")
  builder <! (LMark lblChk)
  let dividend = getDividend ctxt oprSize
  let sz = AST.typeOf dividend
  let quotient = AST.tmpvar sz
  let remainder = AST.tmpvar sz
  let checkQuotientDIV q =
    CJmp (AST.xthi oprSize q == AST.num0 oprSize, Name lblAssign, Name lblErr)
  let checkQuotientIDIV q =
    let amount =
      AST.num (BitVector.ofInt32 (RegType.toBitWidth oprSize - 1) oprSize)
    let mask = AST.num1 oprSize << amount
    let msb = AST.xthi 1<rt> q
    let negRes = AST.lt q (AST.zext sz mask)
    let posRes = AST.gt q (AST.zext sz (mask .- (AST.num1 oprSize)))
    let cond = AST.ite (msb == AST.b1) negRes posRes
    CJmp (cond, Name lblErr, Name lblAssign)
  match ins.Opcode with
  | Opcode.DIV -> let divisor = AST.zext sz divisor
                  builder <! (quotient := dividend ./ divisor)
                  builder <! (remainder := dividend .% divisor)
                  builder <! (checkQuotientDIV quotient)
  | Opcode.IDIV -> let divisor = AST.sext sz divisor
                   builder <! (quotient := dividend ?/ divisor)
                   builder <! (remainder := dividend ?% divisor)
                   builder <! (checkQuotientIDIV quotient)
  | _ ->  raise InvalidOpcodeException
  builder <! (LMark lblAssign)
  match oprSize with
  | 8<rt> ->
    builder <! (getRegVar ctxt R.AL := AST.xtlo oprSize quotient)
    builder <! (getRegVar ctxt R.AH := AST.xtlo oprSize remainder)
  | 16<rt> | 32<rt> | 64<rt> ->
    let q = getRegOfSize ctxt oprSize grpEAX
    let r = getRegOfSize ctxt oprSize grpEDX
    builder <! (dstAssign oprSize q (AST.xtlo oprSize quotient))
    builder <! (dstAssign oprSize r (AST.xtlo oprSize remainder))
  | _ -> raise InvalidOperandSizeException
  allEFLAGSUndefined ctxt builder
  endMark insAddr insLen builder

let enter ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let imm16, imm8 = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oSz = getOperationSize ins
  let allocSize, nestingLevel, cnt = tmpVars3 oSz
  let frameTemp, addrSize = tmpVars2 ctxt.WordBitSize
  let bp = getBasePtr ctxt
  let sp = getStackPtr ctxt
  let lblLoop = AST.symbol "Loop"
  let lblCont = AST.symbol "Continue"
  let lblLevelCheck = AST.symbol "NestingLevelCheck"
  let lblLv1 = AST.symbol "NestingLevel1"
  let getAddrSize bitSize =
    if bitSize = 64<rt> then numI32 8 bitSize else numI32 4 bitSize
  startMark insAddr insLen builder
  builder <! (allocSize := imm16)
  builder <! (nestingLevel := imm8 .% (numI32 32 oSz))
  auxPush ctxt.WordBitSize ctxt bp builder
  builder <! (frameTemp := sp)
  builder <! (addrSize := getAddrSize ctxt.WordBitSize)
  builder <! (CJmp (nestingLevel == AST.num0 oSz, Name lblCont, Name lblLevelCheck))
  builder <! (LMark lblLevelCheck)
  builder <! (cnt := nestingLevel .- AST.num1 oSz)
  builder <! (CJmp (AST.gt nestingLevel (AST.num1 oSz), Name lblLoop, Name lblLv1))
  builder <! (LMark lblLoop)
  builder <! (bp := bp .- addrSize)
  auxPush ctxt.WordBitSize ctxt (AST.loadLE ctxt.WordBitSize bp) builder
  builder <! (cnt := cnt .- AST.num1 oSz)
  builder <! (CJmp (cnt == AST.num0 oSz, Name lblCont, Name lblLoop))
  builder <! (LMark lblLv1)
  auxPush ctxt.WordBitSize ctxt frameTemp builder
  builder <! (LMark lblCont)
  builder <! (bp := frameTemp)
  builder <! (sp := sp .- AST.zext ctxt.WordBitSize allocSize)
  endMark insAddr insLen builder

let imul ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  match ins.Operands with
  | OneOperand _ -> oneOperandImul ins insAddr insLen ctxt oprSize builder
  | TwoOperands _
  | ThreeOperands _ -> operandsImul ins insAddr insLen ctxt oprSize builder
  | _ -> raise InvalidOperandException
  builder <! (getRegVar ctxt R.ZF := undefZF)
  builder <! (getRegVar ctxt R.AF := undefAF)
  builder <! (getRegVar ctxt R.PF := undefPF)
  endMark insAddr insLen builder

let inc ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let dst = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let t1, t2, t3 = tmpVars3 oprSize
  startMark insAddr insLen builder
  builder <! (t1 := dst)
  builder <! (t2 := AST.num1 oprSize)
  builder <! (t3 := (t1 .+ t2))
  builder <! (dstAssign oprSize dst t3)
  builder <! (getRegVar ctxt R.OF := getOFlagOnAdd t1 t2 t3)
  enumASZPFlags ctxt t1 t2 t3 oprSize builder
  endMark insAddr insLen builder

let insinstr ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  startMark insAddr insLen builder
  let body () =
    let oprSize = getOperationSize ins
    let df = getRegVar ctxt R.DF
    let di = getRegVar ctxt (if is64bit ctxt then R.RDI else R.EDI)
    let src = AST.zext ctxt.WordBitSize (getRegVar ctxt R.DX)
    builder <! (AST.loadLE ctxt.WordBitSize di := src)
    let amount = numI32 (RegType.toByteWidth oprSize) ctxt.WordBitSize
    builder <! (di := AST.ite df (di .- amount) (di .+ amount))
  if hasREPZ ins.Prefixes then
    strRepeat ctxt body None insAddr insLen builder
  elif hasREPNZ ins.Prefixes then Utils.impossible ()
  else body ()
  endMark insAddr insLen builder

let interrupt ins insAddr insLen ctxt =
  match getOneOpr ins |> transOneOpr ins insAddr insLen ctxt with
  | Num n -> Interrupt (BitVector.toInt32 n) |> sideEffects insAddr insLen
  | _ -> raise InvalidOperandException

let jcc ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let pc = getInstrPtr ctxt
  let jmpTarget = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let cond = getCondOfJcc ins ctxt oprSize
  let fallThrough =
    numAddr insAddr ctxt .+ numInsLen insLen ctxt
  startMark insAddr insLen builder
  builder <! (InterCJmp (cond, pc, jmpTarget, fallThrough))
  endMark insAddr insLen builder

let jmp ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let opr = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  let pc = getInstrPtr ctxt
  startMark insAddr insLen builder
  builder <! (InterJmp (pc, opr, InterJmpInfo.Base))
  endMark insAddr insLen builder

let lea ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let src = convertSrc src
  let addrSize = getEffAddrSz ins
  startMark insAddr insLen builder
  match oprSize, addrSize with
  | 16<rt>, 16<rt> | 32<rt>, 32<rt> | 64<rt>, 64<rt> ->
    builder <! (dstAssign oprSize dst src)
  | 16<rt>, 32<rt> | 16<rt>, 64<rt> ->
    builder <! (dstAssign oprSize dst (AST.xtlo 16<rt> src))
  | 32<rt>, 16<rt> -> builder <! (dstAssign oprSize dst (AST.zext 32<rt> src))
  | 32<rt>, 64<rt> -> builder <! (dstAssign oprSize dst (AST.xtlo 32<rt> src))
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let leave ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let sp = getStackPtr ctxt
  let bp = getBasePtr ctxt
  startMark insAddr insLen builder
  builder <! (sp := bp)
  auxPop ctxt.WordBitSize ctxt bp builder
  endMark insAddr insLen builder

let lods ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  startMark insAddr insLen builder
  let body () =
    let oprSize = getOperationSize ins
    let df = getRegVar ctxt R.DF
    let di = getRegVar ctxt (if is64bit ctxt then R.RDI else R.EDI)
    let dst = getRegOfSize ctxt oprSize grpEAX
    builder <! (dst := AST.loadLE oprSize di)
    let amount = numI32 (RegType.toByteWidth oprSize) ctxt.WordBitSize
    builder <! (di := AST.ite df (di .- amount) (di .+ amount))
  if hasREPZ ins.Prefixes then
    strRepeat ctxt body None insAddr insLen builder
  elif hasREPNZ ins.Prefixes then Utils.impossible ()
  else body ()
  endMark insAddr insLen builder

let loop ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  let addrSize = getEffAddrSz ins
  let oprSize = getOperationSize ins
  let pc = getInstrPtr ctxt
  let count, cntSize =
    if addrSize = 32<rt> then getRegVar ctxt R.ECX, 32<rt>
    elif addrSize = 64<rt> then getRegVar ctxt R.RCX, 64<rt>
    else getRegVar ctxt R.CX, 16<rt>
  let zf = getRegVar ctxt R.ZF
  startMark insAddr insLen builder
  builder <! (count := count .- AST.num1 cntSize)
  let branchCond =
    match ins.Opcode with
    | Opcode.LOOP -> count != AST.num0 cntSize
    | Opcode.LOOPE -> (zf == AST.b1) .& (count != AST.num0 cntSize)
    | Opcode.LOOPNE -> (zf == AST.b0) .& (count != AST.num0 cntSize)
    | _ -> raise InvalidOpcodeException
  let fallThrough = numAddr insAddr ctxt .+ numInsLen insLen ctxt
  let jumpTarget = if oprSize = 16<rt> then pc .& numI32 0xFFFF 32<rt>
                   else AST.sext oprSize dst
  builder <! (InterCJmp (branchCond, pc, jumpTarget, fallThrough))
  endMark insAddr insLen builder

let lzcnt ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let lblLoop = AST.symbol "Loop"
  let lblExit = AST.symbol "Exit"
  let lblLoopCond = AST.symbol "LoopCond"
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let n = AST.num0 oprSize
  startMark insAddr insLen builder
  let temp = AST.tmpvar oprSize
  builder <! (temp := numI32 (RegType.toBitWidth oprSize - 1) oprSize)
  builder <! (dst := n)
  builder <! (LMark lblLoopCond)
  let cond1 = (AST.ge temp n) .& ((AST.xtlo 1<rt> (src >> temp)) == AST.b0)
  builder <! (CJmp (cond1, Name lblLoop, Name lblExit))
  builder <! (LMark lblLoop)
  builder <! (temp := temp .- AST.num1 oprSize)
  builder <! (dst := dst .+ AST.num1 oprSize)
  builder <! (Jmp (Name lblLoopCond))
  builder <! (LMark lblExit)
  let oprSize = numI32 (RegType.toBitWidth oprSize) oprSize
  builder <! (getRegVar ctxt R.CF := dst == oprSize)
  builder <! (getRegVar ctxt R.ZF := dst == n)
  builder <! (getRegVar ctxt R.OF := undefOF)
  builder <! (getRegVar ctxt R.SF := undefSF)
  builder <! (getRegVar ctxt R.PF := undefPF)
  builder <! (getRegVar ctxt R.AF := undefAF)
  endMark insAddr insLen builder

let mov ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  builder <! (dstAssign oprSize dst (AST.zext oprSize src))
  endMark insAddr insLen builder

let movbe ins insAddr insLen ctxt =
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let t = AST.tmpvar oprSize
  let cnt = RegType.toByteWidth oprSize |> int
  let tmps = Array.init cnt (fun _ -> AST.tmpvar 8<rt>)
  let builder = StmtBuilder (2 * cnt)
  startMark insAddr insLen builder
  builder <! (t := src)
  for i in 0 .. cnt - 1 do
    builder <! (tmps.[i] := AST.extract t 8<rt> (i * 8))
  done
  builder <! (dstAssign oprSize dst (AST.concatArr (Array.rev tmps)))
  endMark insAddr insLen builder

let movs ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  startMark insAddr insLen builder
  let body () =
    let oprSize = getOperationSize ins
    let df = getRegVar ctxt R.DF
    let si = getRegVar ctxt (if is64bit ctxt then R.RSI else R.ESI)
    let di = getRegVar ctxt (if is64bit ctxt then R.RDI else R.EDI)
    builder <! (AST.loadLE oprSize di := AST.loadLE oprSize si)
    let amount = numI32 (RegType.toByteWidth oprSize) ctxt.WordBitSize
    builder <! (si := AST.ite df (si .- amount) (si .+ amount))
    builder <! (di := AST.ite df (di .- amount) (di .+ amount))
  if hasREPZ ins.Prefixes then
    strRepeat ctxt body None insAddr insLen builder
  elif hasREPNZ ins.Prefixes then Utils.impossible ()
  else body ()
  endMark insAddr insLen builder

let movsx ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  builder <! (dstAssign oprSize dst (AST.sext oprSize src))
  endMark insAddr insLen builder

let movzx ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  builder <! (dstAssign oprSize dst (AST.zext oprSize src))
  endMark insAddr insLen builder

let mul ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let oprSize = getOperationSize ins
  let dblWidth = RegType.double oprSize
  let src1 = AST.zext dblWidth (getRegOfSize ctxt oprSize grpEAX)
  let src2 = AST.zext dblWidth (getOneOpr ins |> transOneOpr ins insAddr insLen ctxt)
  let t = AST.tmpvar dblWidth
  startMark insAddr insLen builder
  builder <! (t := src1 .* src2)
  let cond = AST.tmpvar 1<rt>
  match oprSize with
  | 8<rt> -> builder <! (getRegVar ctxt R.AX := t)
  | 16<rt> | 32<rt> | 64<rt> ->
    builder <! (getRegOfSize ctxt oprSize grpEDX := AST.xthi oprSize t)
    builder <! (getRegOfSize ctxt oprSize grpEAX := AST.xtlo oprSize t)
  | _ -> raise InvalidOperandSizeException
  builder <! (cond := AST.xthi oprSize t != (AST.num0 oprSize))
  builder <! (getRegVar ctxt R.CF := cond)
  builder <! (getRegVar ctxt R.OF := cond)
  builder <! (getRegVar ctxt R.SF := undefSF)
  builder <! (getRegVar ctxt R.ZF := undefZF)
  builder <! (getRegVar ctxt R.AF := undefAF)
  builder <! (getRegVar ctxt R.PF := undefPF)
  endMark insAddr insLen builder

let neg ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let dst = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let t = AST.tmpvar oprSize
  let oFCond = t == (AST.num1 oprSize << (numU32 31u oprSize) )
  startMark insAddr insLen builder
  builder <! (t := dst)
  builder <! (dstAssign oprSize dst (AST.neg t))
  builder <! (getRegVar ctxt R.CF := t != AST.num0 oprSize)
  builder <! (getRegVar ctxt R.OF := oFCond)
  enumASZPFlags ctxt t (AST.num0 oprSize) dst oprSize builder
  endMark insAddr insLen builder

let nop insAddr insLen =
  let builder = StmtBuilder (4)
  startMark insAddr insLen builder
  endMark insAddr insLen builder

let not ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let dst = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  builder <! (dstAssign oprSize dst (AST.unop UnOpType.NOT dst))
  endMark insAddr insLen builder

let logOr ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let t = AST.tmpvar oprSize
  startMark insAddr insLen builder
  builder <! (t := (dst .| AST.sext oprSize src))
  builder <! (dstAssign oprSize dst t)
  builder <! (getRegVar ctxt R.CF := AST.b0)
  builder <! (getRegVar ctxt R.OF := AST.b0)
  builder <! (getRegVar ctxt R.AF := undefAF)
  enumSZPFlags ctxt t oprSize builder
  endMark insAddr insLen builder

let outs ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  startMark insAddr insLen builder
  let body () =
    let oprSize = getOperationSize ins
    let df = getRegVar ctxt R.DF
    let si = getRegVar ctxt (if is64bit ctxt then R.RSI else R.ESI)
    let src = getRegVar ctxt R.DX
    let amount = numI32 (RegType.toByteWidth oprSize) ctxt.WordBitSize
    match oprSize with
    | 8<rt> ->
      builder <! (src := AST.zext 16<rt> (AST.loadLE oprSize si))
      builder <! (si := AST.ite df (si .- amount) (si .+ amount))
    | 16<rt> ->
      builder <! (src := AST.loadLE oprSize si)
      builder <! (si := AST.ite df (si .- amount) (si .+ amount))
    | 32<rt> ->
      builder <! (si := AST.ite df (si .- amount) (si .+ amount))
      builder <! (src := AST.xtlo 16<rt> (AST.loadLE oprSize si))
    | _ -> raise InvalidOperandSizeException
  if hasREPZ ins.Prefixes then
    strRepeat ctxt body None insAddr insLen builder
  elif hasREPNZ ins.Prefixes then Utils.impossible ()
  else body ()
  endMark insAddr insLen builder

let pop ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let dst = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  auxPop oprSize ctxt dst builder
  endMark insAddr insLen builder

let popa ins insAddr insLen ctxt oprSize =
  let builder = StmtBuilder (16)
  let sp = getRegVar ctxt R.ESP
  let di = if oprSize = 32<rt> then R.EDI else R.DI
  let si = if oprSize = 32<rt> then R.ESI else R.SI
  let bp = if oprSize = 32<rt> then R.EBP else R.BP
  let bx = if oprSize = 32<rt> then R.EBX else R.BX
  let dx = if oprSize = 32<rt> then R.EDX else R.DX
  let cx = if oprSize = 32<rt> then R.ECX else R.CX
  let ax = if oprSize = 32<rt> then R.EAX else R.AX
  startMark insAddr insLen builder
  auxPop oprSize ctxt (getRegVar ctxt di) builder
  auxPop oprSize ctxt (getRegVar ctxt si) builder
  auxPop oprSize ctxt (getRegVar ctxt bp) builder
  builder <! (sp := sp .+ (numI32 (int oprSize / 8) 32<rt>))
  auxPop oprSize ctxt (getRegVar ctxt bx) builder
  auxPop oprSize ctxt (getRegVar ctxt dx) builder
  auxPop oprSize ctxt (getRegVar ctxt cx) builder
  auxPop oprSize ctxt (getRegVar ctxt ax) builder
  endMark insAddr insLen builder

let popcnt ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let lblLoop = AST.symbol "Loop"
  let lblExit = AST.symbol "Exit"
  let lblLoopCond = AST.symbol "LoopCond"
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let max = numI32 (RegType.toBitWidth oprSize) oprSize
  startMark insAddr insLen builder
  let i = AST.tmpvar oprSize
  let count = AST.tmpvar oprSize
  builder <! (i := AST.num0 oprSize)
  builder <! (count := AST.num0 oprSize)
  builder <! (LMark lblLoopCond)
  builder <! (CJmp (AST.lt i max, Name lblLoop, Name lblExit))
  builder <! (LMark lblLoop)
  let cond = (AST.xtlo 1<rt> (src >> i)) == AST.b1
  builder <! (count := AST.ite cond (count .+ AST.num1 oprSize) count)
  builder <! (i := i .+ AST.num1 oprSize)
  builder <! (Jmp (Name lblLoopCond))
  builder <! (LMark lblExit)
  builder <! (dstAssign oprSize dst count)
  builder <! (getRegVar ctxt R.OF := AST.b0)
  builder <! (getRegVar ctxt R.SF := AST.b0)
  builder <! (getRegVar ctxt R.ZF := src == AST.num0 oprSize)
  builder <! (getRegVar ctxt R.AF := AST.b0)
  builder <! (getRegVar ctxt R.CF := AST.b0)
  builder <! (getRegVar ctxt R.PF := AST.b0)
  endMark insAddr insLen builder

let popf ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let oprSize = getOperationSize ins
  let t = AST.tmpvar oprSize
  startMark insAddr insLen builder
  auxPop oprSize ctxt t builder
  builder <! (getRegVar ctxt R.OF := AST.extract t 1<rt> 11)
  builder <! (getRegVar ctxt R.DF := AST.extract t 1<rt> 10)
  builder <! (getRegVar ctxt R.IF := AST.extract t 1<rt> 9)
  builder <! (getRegVar ctxt R.TF := AST.extract t 1<rt> 8)
  builder <! (getRegVar ctxt R.SF := AST.extract t 1<rt> 7)
  builder <! (getRegVar ctxt R.ZF := AST.extract t 1<rt> 6)
  builder <! (getRegVar ctxt R.AF := AST.extract t 1<rt> 4)
  builder <! (getRegVar ctxt R.PF := AST.extract t 1<rt> 2)
  builder <! (getRegVar ctxt R.CF := AST.xtlo 1<rt> t)
  endMark insAddr insLen builder

let logicalLeftShiftDwords oprSize src cntSrc builder =
  let cntSrc = AST.zext oprSize cntSrc
  let tCnt = int oprSize / 32
  let tmps = Array.init tCnt (fun _ -> AST.tmpvar (oprSize / tCnt))
  for i in 0 .. tCnt - 1 do
    let t = AST.zext oprSize ((src >> numI32 (i * 32) oprSize) << cntSrc)
    builder <! (tmps.[i] := AST.xtlo 32<rt> t)
  done
  AST.ite (AST.gt cntSrc (numU32 31u oprSize)) (AST.num0 oprSize) (AST.concatArr tmps)

let push ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let src = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  auxPush oprSize ctxt (padPushExpr oprSize src) builder
  endMark insAddr insLen builder

let pusha ins insAddr insLen ctxt oprSize =
  let builder = StmtBuilder (16)
  let t = AST.tmpvar oprSize
  let sp = if oprSize = 32<rt> then R.ESP else R.SP
  let ax = if oprSize = 32<rt> then R.EAX else R.AX
  let cx = if oprSize = 32<rt> then R.ECX else R.CX
  let dx = if oprSize = 32<rt> then R.EDX else R.DX
  let bx = if oprSize = 32<rt> then R.EBX else R.BX
  let bp = if oprSize = 32<rt> then R.EBP else R.BP
  let si = if oprSize = 32<rt> then R.ESI else R.SI
  let di = if oprSize = 32<rt> then R.EDI else R.DI
  startMark insAddr insLen builder
  builder <! (dstAssign oprSize t (getRegVar ctxt sp))
  auxPush oprSize ctxt (getRegVar ctxt ax) builder
  auxPush oprSize ctxt (getRegVar ctxt cx) builder
  auxPush oprSize ctxt (getRegVar ctxt dx) builder
  auxPush oprSize ctxt (getRegVar ctxt bx) builder
  auxPush oprSize ctxt t builder
  auxPush oprSize ctxt (getRegVar ctxt bp) builder
  auxPush oprSize ctxt (getRegVar ctxt si) builder
  auxPush oprSize ctxt (getRegVar ctxt di) builder
  endMark insAddr insLen builder

let pushf ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let oprSize = getOperationSize ins
  let e = AST.zext oprSize <| getRegVar ctxt R.CF
  (* We only consider 9 flags (we ignore system flags). *)
  let e = e .| ((AST.zext oprSize (getRegVar ctxt R.PF)) << numI32 2 oprSize)
  let e = e .| ((AST.zext oprSize (getRegVar ctxt R.AF)) << numI32 4 oprSize)
  let e = e .| ((AST.zext oprSize (getRegVar ctxt R.ZF)) << numI32 6 oprSize)
  let e = e .| ((AST.zext oprSize (getRegVar ctxt R.SF)) << numI32 7 oprSize)
  let e = e .| ((AST.zext oprSize (getRegVar ctxt R.TF)) << numI32 8 oprSize)
  let e = e .| ((AST.zext oprSize (getRegVar ctxt R.IF)) << numI32 9 oprSize)
  let e = e .| ((AST.zext oprSize (getRegVar ctxt R.DF)) << numI32 10 oprSize)
  let e = e .| ((AST.zext oprSize (getRegVar ctxt R.OF)) << numI32 11 oprSize)
  let e = match oprSize with
          | 16<rt> -> e
          | 32<rt> -> e .& (numI32 0xfcffff 32<rt>)
          | 64<rt> -> e .& (numI32 0xfcffff 64<rt>)
          | _ -> raise InvalidOperandSizeException
  startMark insAddr insLen builder
  auxPush oprSize ctxt e builder
  endMark insAddr insLen builder

let rcl ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, count = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let cF = getRegVar ctxt R.CF
  let oF = getRegVar ctxt R.OF
  let tmpCount = AST.tmpvar oprSize
  let size = numI32 (RegType.toBitWidth oprSize) oprSize
  let count = AST.zext oprSize count
  let cnt =
    match oprSize with
    | 8<rt> -> (count .& numI32 0x1f oprSize) .% numI32 9 oprSize
    | 16<rt> -> (count .& numI32 0x1f oprSize) .% numI32 17 oprSize
    | 32<rt> -> count .& numI32 0x1f oprSize
    | 64<rt> -> count .& numI32 0x3f oprSize
    | _ -> raise InvalidOperandSizeException
  let cond = count == AST.num1 oprSize
  startMark insAddr insLen builder
  builder <! (tmpCount := cnt)
  builder <! (dst := (dst << tmpCount) .| (dst >> (size .- tmpCount)))
  builder <! (cF := AST.xthi 1<rt> dst)
  builder <! (oF := AST.ite cond (AST.xthi 1<rt> dst <+> cF) undefOF)
  endMark insAddr insLen builder

let rcr ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, count = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let cF = getRegVar ctxt R.CF
  let oF = getRegVar ctxt R.OF
  let tmpCount = AST.tmpvar oprSize
  let size = numI32 (RegType.toBitWidth oprSize) oprSize
  let count = AST.zext oprSize count
  let cnt =
    match oprSize with
    | 8<rt> -> (count .& numI32 0x1f oprSize) .% numI32 9 oprSize
    | 16<rt> -> (count .& numI32 0x1f oprSize) .% numI32 17 oprSize
    | 32<rt> -> count .& numI32 0x1f oprSize
    | 64<rt> -> count .& numI32 0x3f oprSize
    | _ -> raise InvalidOperandSizeException
  let cond = count == AST.num1 oprSize
  startMark insAddr insLen builder
  builder <! (tmpCount := cnt)
  builder <! (oF := AST.ite cond (AST.xthi 1<rt> dst <+> cF) undefOF)
  builder <! (dst := (dst >> tmpCount) .| (dst << (size .- tmpCount)))
  builder <! (cF := AST.xthi 1<rt> dst)
  endMark insAddr insLen builder

let rdpkru ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let lblSucc = AST.symbol "Succ"
  let lblErr = AST.symbol "Err"
  let oprSize = getOperationSize ins
  let ecx = getRegVar ctxt R.ECX
  let eax = getRegOfSize ctxt ctxt.WordBitSize grpEAX
  let edx = getRegOfSize ctxt ctxt.WordBitSize grpEDX
  startMark insAddr insLen builder
  builder <! (CJmp (ecx == AST.num0 oprSize, Name lblSucc, Name lblErr))
  builder <! (LMark lblErr)
  builder <! SideEffect (Trap "GP")
  builder <! (LMark lblSucc)
  builder <! (eax := AST.zext ctxt.WordBitSize (getRegVar ctxt R.PKRU))
  builder <! (edx := AST.num0 ctxt.WordBitSize)
  endMark insAddr insLen builder

let ret ins insAddr insLen ctxt isFar isImm =
  let builder = StmtBuilder (8)
  let oprSize = getOperationSize ins
  let t = AST.tmpvar oprSize
  let pc = getInstrPtr ctxt
  let sp = getStackPtr ctxt
  match isFar, isImm with
  | false, true ->
    let src = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
    startMark insAddr insLen builder
    auxPop oprSize ctxt t builder
    builder <! (sp := sp .+ (AST.zext oprSize src))
    builder <! (InterJmp (pc, t, InterJmpInfo.IsRet))
    endMark insAddr insLen builder
  | false, false ->
    startMark insAddr insLen builder
    auxPop oprSize ctxt t builder
    builder <! (InterJmp (pc, t, InterJmpInfo.IsRet))
    endMark insAddr insLen builder
  | true, true
  | true, false -> sideEffects insAddr insLen UnsupportedFAR

let rotate ins insAddr insLen ctxt lfn hfn cfFn ofFn =
  let builder = StmtBuilder (8)
  let dst, count = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let cF = getRegVar ctxt R.CF
  let oF = getRegVar ctxt R.OF
  let countMask = if is64REXW ctxt ins then numU32 0x3Fu oprSize
                  else numU32 0x1Fu oprSize
  let size = numI32 (RegType.toBitWidth oprSize) oprSize
  let orgCount = AST.tmpvar oprSize
  let cond1 = orgCount == AST.num0 oprSize
  let cond2 = orgCount == AST.num1 oprSize
  startMark insAddr insLen builder
  builder <! (orgCount := (AST.zext oprSize count .& countMask))
  builder <! (dst := (lfn dst orgCount) .| (hfn dst (size .- orgCount)))
  builder <! (cF := AST.ite cond1 cF (cfFn 1<rt> dst))
  builder <! (oF := AST.ite cond2 (ofFn dst cF) undefOF)
  endMark insAddr insLen builder

let rol ins insAddr insLen ctxt =
  let ofFn dst cF = cF <+> AST.xthi 1<rt> dst
  rotate ins insAddr insLen ctxt (<<) (>>) AST.xtlo ofFn

let ror ins insAddr insLen ctxt =
  let ofFn dst _cF =
    AST.xthi 1<rt> dst <+> AST.extract dst 1<rt> 1
  rotate ins insAddr insLen ctxt (>>) (<<) AST.xthi ofFn

let rorx ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src, imm =
    getThreeOprs ins |> transThreeOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let y = AST.tmpvar oprSize
  if oprSize = 32<rt> then
    builder <! (y := imm .& (numI32 0x1F oprSize))
    builder <! (dst := (src >> y) .| (src << (numI32 32 oprSize .- y)))
  else (* OperandSize = 64 *)
    builder <! (y := imm .& (numI32 0x3F oprSize))
    builder <! (dst := (src >> y) .| (src << (numI32 64 oprSize .- y)))
  endMark insAddr insLen builder

let sahf ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let ah = getRegVar ctxt R.AH
  startMark insAddr insLen builder
  builder <! (getRegVar ctxt R.CF := AST.xtlo 1<rt> ah)
  builder <! (getRegVar ctxt R.PF := AST.extract ah 1<rt> 2)
  builder <! (getRegVar ctxt R.AF := AST.extract ah 1<rt> 4)
  builder <! (getRegVar ctxt R.ZF := AST.extract ah 1<rt> 6)
  builder <! (getRegVar ctxt R.SF := AST.extract ah 1<rt> 7)
  endMark insAddr insLen builder

let shift ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let n0 = AST.num0 oprSize
  let n1 = AST.num1 oprSize
  let countMask = if is64REXW ctxt ins then numU32 0x3Fu oprSize
                  else numU32 0x1Fu oprSize
  let cnt = (AST.zext oprSize src) .& countMask
  let cond1 = cnt == n1
  let cond2 = cnt == n0
  let oF = getRegVar ctxt R.OF
  let cF = getRegVar ctxt R.CF
  let sF = getRegVar ctxt R.SF
  let zF = getRegVar ctxt R.ZF
  let aF = getRegVar ctxt R.AF
  let tDst = AST.tmpvar oprSize
  let tCnt = AST.tmpvar oprSize
  startMark insAddr insLen builder
  builder <! (tDst := dst)
  match ins.Opcode with
  | Opcode.SAR ->
    builder <! (dst := dst ?>> cnt)
    builder <! (tCnt := cnt .- n1)
    let prevLBit = AST.xtlo 1<rt> (tDst ?>> tCnt)
    builder <! (cF := AST.ite cond2 cF prevLBit)
    builder <! (oF := AST.ite cond1 AST.b0 (AST.ite cond2 oF undefOF))
  | Opcode.SHL ->
    builder <! (dstAssign oprSize dst (dst << cnt))
    builder <! (tCnt := cnt .- n1)
    let prevHBit = AST.xthi 1<rt> (tDst << tCnt)
    builder <! (cF := AST.ite cond2 cF prevHBit)
    let of1 = AST.xthi 1<rt> dst <+> cF
    builder <! (oF := AST.ite cond1 of1 (AST.ite cond2 oF undefOF))
  | Opcode.SHR ->
    builder <! (dstAssign oprSize dst (dst >> cnt))
    builder <! (tCnt := cnt .- n1)
    let prevLBit = AST.xtlo 1<rt> (tDst ?>> tCnt)
    builder <! (cF := AST.ite cond2 cF prevLBit)
    builder <!
      (oF := AST.ite cond1 (AST.xthi 1<rt> tDst) (AST.ite cond2 oF undefOF))
  | _ -> raise InvalidOpcodeException
  builder <! (sF := AST.ite cond2 sF (AST.xthi 1<rt> dst))
  let cbPF computedPF = AST.ite cond2 (getRegVar ctxt R.PF) computedPF
  buildPF ctxt dst oprSize (Some cbPF) builder
  builder <! (zF := AST.ite cond2 zF (dst == n0))
  builder <! (aF := AST.ite cond2 aF undefAF)
  endMark insAddr insLen builder

let sbb ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let t1, t2, t3, t4 = tmpVars4 oprSize
  let cf = getRegVar ctxt R.CF
  startMark insAddr insLen builder
  builder <! (t1 := dst)
  builder <! (t2 := AST.sext oprSize src)
  builder <! (t3 := t2 .+ AST.zext oprSize cf)
  builder <! (t4 := t1 .- t3)
  builder <! (dstAssign oprSize dst t4)
  builder <! (cf := (AST.lt t1 t3) .| (AST.lt t3 t2))
  builder <! (getRegVar ctxt R.OF := getOFlagOnSub t1 t2 t4)
  enumASZPFlags ctxt t1 t2 t4 oprSize builder
  endMark insAddr insLen builder

let scas ins insAddr insLen ctxt =
  let builder = StmtBuilder (32)
  startMark insAddr insLen builder
  let pref = ins.Prefixes
  let body () =
    let oprSize = getOperationSize ins
    let t = AST.tmpvar oprSize
    let df = getRegVar ctxt R.DF
    let ax = getRegOfSize ctxt oprSize grpEAX
    let di = getRegVar ctxt (if is64bit ctxt then R.RDI else R.EDI)
    let tSrc = AST.tmpvar oprSize
    builder <! (tSrc := AST.loadLE oprSize di)
    builder <! (t := ax .- tSrc)
    enumEFLAGS ctxt ax tSrc t oprSize getCFlagOnSub getOFlagOnSub builder
    let amount = numI32 (RegType.toByteWidth oprSize) ctxt.WordBitSize
    builder <! (di := AST.ite df (di .- amount) (di .+ amount))
  let zfCond n = Some (getRegVar ctxt R.ZF == n)
  if hasREPZ pref then strRepeat ctxt body (zfCond AST.b0) insAddr insLen builder
  elif hasREPNZ pref then strRepeat ctxt body (zfCond AST.b1) insAddr insLen builder
  else body ()
  endMark insAddr insLen builder

let setcc ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let dst = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let cond = getCondOfSet ins ctxt |> AST.zext oprSize
  startMark insAddr insLen builder
  builder <! (dstAssign oprSize dst cond)
  endMark insAddr insLen builder

let inline shiftDblPrec ins insAddr insLen ctxt fnDst fnSrc isShl =
  let builder = StmtBuilder (16)
  let dst, src, cnt = getThreeOprs ins |> transThreeOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let orig = AST.tmpvar oprSize
  let c = AST.tmpvar oprSize
  let cond1 = c == AST.num0 oprSize
  let cond2 = c == AST.num1 oprSize
  let cF = getRegVar ctxt R.CF
  let oF = getRegVar ctxt R.OF
  let aF = getRegVar ctxt R.AF
  startMark insAddr insLen builder
  builder <! (orig := dst)
  let maxSz = numI32 (if is64REXW ctxt ins then 64 else 32) oprSize
  builder <! (c := (AST.zext oprSize cnt) .% maxSz)
  let final = AST.ite cond1 orig ((fnDst orig c) .| (fnSrc src (maxSz .- c)))
  builder <! (dstAssign oprSize dst final)
  if isShl then
    builder <! (cF := AST.ite cond1 cF (AST.xtlo 1<rt> (orig >> (maxSz .- c))))
  else
    builder <!
      (cF := AST.ite cond1 cF (AST.xtlo 1<rt> (orig >> (c .- AST.num1 oprSize))))
  builder <!
    (oF := AST.ite cond1 oF
               (AST.ite cond2 (AST.xthi 1<rt> (orig <+> dst)) undefOF))
  builder <! (aF := AST.ite cond1 aF undefAF)
  enumSZPFlags ctxt dst oprSize builder
  endMark insAddr insLen builder

let shld ins insAddr insLen ctxt =
  shiftDblPrec ins insAddr insLen ctxt (<<) (>>) true

let shrd ins insAddr insLen ctxt =
  shiftDblPrec ins insAddr insLen ctxt (>>) (<<) false

let shlx ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src1, src2 =
    getThreeOprs ins |> transThreeOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let temp = AST.tmpvar oprSize
  let countMask = if is64REXW ctxt ins then 0x3F else 0x1F // FIXME: CS.L = 1
  let count = src2 .& (numI32 countMask oprSize)
  startMark insAddr insLen builder
  builder <! (temp := src1)
  builder <! (AST.xthi 1<rt> dst := AST.xthi 1<rt> temp)
  builder <! (dst := dst << count)
  endMark insAddr insLen builder

let setFlag insAddr insLen ctxt flag =
  let builder = StmtBuilder (4)
  startMark insAddr insLen builder
  builder <! (getRegVar ctxt flag := AST.b1)
  endMark insAddr insLen builder

let stc insAddr insLen ctxt = setFlag insAddr insLen ctxt R.CF
let std insAddr insLen ctxt = setFlag insAddr insLen ctxt R.DF
let sti insAddr insLen ctxt = setFlag insAddr insLen ctxt R.IF

let stos ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  startMark insAddr insLen builder
  let body () =
    let oprSize = getOperationSize ins
    let df = getRegVar ctxt R.DF
    let di = getRegVar ctxt (if is64bit ctxt then R.RDI else R.EDI)
    let src = getRegOfSize ctxt oprSize grpEAX
    builder <! (AST.loadLE oprSize di := src)
    let amount = numI32 (RegType.toByteWidth oprSize) ctxt.WordBitSize
    builder <! (di := AST.ite df (di .- amount) (di .+ amount))
  if hasREPZ ins.Prefixes then
    strRepeat ctxt body None insAddr insLen builder
  elif hasREPNZ ins.Prefixes then Utils.impossible ()
  else body ()
  endMark insAddr insLen builder

let sub ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let t1, t2, t3 = tmpVars3 oprSize
  startMark insAddr insLen builder
  builder <! (t1 := dst)
  builder <! (t2 := src)
  builder <! (t3 := t1 .- t2)
  builder <! (dstAssign oprSize dst t3)
  enumEFLAGS ctxt t1 t2 t3 oprSize getCFlagOnSub getOFlagOnSub builder
  endMark insAddr insLen builder

let test ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let src1, src2 = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let t = AST.tmpvar oprSize
  startMark insAddr insLen builder
  builder <! (t := src1 .& src2)
  builder <! (getRegVar ctxt R.SF := AST.xthi 1<rt> t)
  builder <! (getRegVar ctxt R.ZF := t == (AST.num0 oprSize))
  buildPF ctxt t oprSize None builder
  builder <! (getRegVar ctxt R.CF := AST.b0)
  builder <! (getRegVar ctxt R.OF := AST.b0)
  builder <! (getRegVar ctxt R.AF := undefAF)
  endMark insAddr insLen builder

let tzcnt ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let lblLoop = AST.symbol "Loop"
  let lblExit = AST.symbol "Exit"
  let lblLoopCond = AST.symbol "LoopCond"
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let max = numI32 (RegType.toBitWidth oprSize) oprSize
  startMark insAddr insLen builder
  let t1 = AST.tmpvar oprSize
  builder <! (t1 := AST.num0 oprSize)
  builder <! (LMark lblLoopCond)
  let cond = (AST.lt t1 max) .& (AST.xtlo 1<rt> (src >> t1) == AST.b0)
  builder <! (CJmp (cond, Name lblLoop, Name lblExit))
  builder <! (LMark lblLoop)
  builder <! (t1 := t1 .+ AST.num1 oprSize)
  builder <! (Jmp (Name lblLoopCond))
  builder <! (LMark lblExit)
  builder <! (dstAssign oprSize dst t1)
  builder <! (getRegVar ctxt R.CF := dst == max)
  builder <! (getRegVar ctxt R.ZF := dst == AST.num0 oprSize)
  builder <! (getRegVar ctxt R.OF := undefOF)
  builder <! (getRegVar ctxt R.SF := undefSF)
  builder <! (getRegVar ctxt R.PF := undefPF)
  builder <! (getRegVar ctxt R.AF := undefAF)
  endMark insAddr insLen builder

let wrfsbase ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let src = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  startMark insAddr insLen builder
  builder <! (getRegVar ctxt R.FSBase := AST.zext ctxt.WordBitSize src)
  endMark insAddr insLen builder

let wrgsbase ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let src = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  startMark insAddr insLen builder
  builder <! (getRegVar ctxt R.GSBase := AST.zext ctxt.WordBitSize src)
  endMark insAddr insLen builder

let wrpkru ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let lblSucc = AST.symbol "Succ"
  let lblErr = AST.symbol "Err"
  let oprSize = getOperationSize ins
  let ecxIsZero = getRegVar ctxt R.ECX == AST.num0 oprSize
  let edxIsZero = getRegVar ctxt R.EDX == AST.num0 oprSize
  let cond = ecxIsZero .& edxIsZero
  startMark insAddr insLen builder
  builder <! (CJmp (cond, Name lblSucc, Name lblErr))
  builder <! (LMark lblErr)
  builder <! SideEffect (Trap "GP")
  builder <! (LMark lblSucc)
  builder <! (getRegVar ctxt R.PKRU := getRegVar ctxt R.EAX)
  endMark insAddr insLen builder

let xadd ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let t = AST.tmpvar oprSize
  startMark insAddr insLen builder
  builder <! (t := src .+ dst)
  builder <! (dstAssign oprSize src dst)
  builder <! (dstAssign oprSize dst t)
  enumEFLAGS ctxt dst src t oprSize getCFlagOnAdd getOFlagOnAdd builder
  endMark insAddr insLen builder

let xchg ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  startMark insAddr insLen builder
  if dst <> src then
    let oprSize = getOperationSize ins
    let t = AST.tmpvar oprSize
    builder <! (t := dst)
    builder <! (dstAssign oprSize dst src)
    builder <! (dstAssign oprSize src t)
  endMark insAddr insLen builder

let xlatb ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let addressSize = getEffAddrSz ins
  let al = AST.zext addressSize (getRegVar ctxt R.AL)
  let bx = getRegOfSize ctxt addressSize grpEBX
  startMark insAddr insLen builder
  builder <! (getRegVar ctxt R.AL := AST.loadLE 8<rt> (al .+ bx))
  endMark insAddr insLen builder

let xor ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let r = AST.tmpvar oprSize
  startMark insAddr insLen builder
  builder <! (r := dst <+> AST.sext oprSize src)
  builder <! (dstAssign oprSize dst r)
  builder <! (getRegVar ctxt R.OF := AST.b0)
  builder <! (getRegVar ctxt R.CF := AST.b0)
  builder <! (getRegVar ctxt R.SF := AST.xthi 1<rt> r)
  builder <! (getRegVar ctxt R.ZF := r == (AST.num0 oprSize))
  buildPF ctxt r oprSize None builder
  builder <! (getRegVar ctxt R.AF := undefAF)
  endMark insAddr insLen builder
