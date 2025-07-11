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

module internal B2R2.FrontEnd.Intel.GeneralLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.Intel
open B2R2.FrontEnd.Intel.RegGroup
open B2R2.FrontEnd.Intel.LiftingUtils

#if !EMULATION
let private undefCF = AST.undef 1<rt> "CF is undefined."

let private undefOF = AST.undef 1<rt> "OF is undefined."

let private undefAF = AST.undef 1<rt> "AF is undefined."

let private undefSF = AST.undef 1<rt> "SF is undefined."

let private undefZF = AST.undef 1<rt> "ZF is undefined."

let private undefPF = AST.undef 1<rt> "PF is undefined."
#endif

let private getInstrPtr bld =
  regVar bld (if is64bit bld then R.RIP else R.EIP)

let private getStackPtr bld =
  regVar bld (if is64bit bld then R.RSP else R.ESP)

let private getBasePtr bld =
  regVar bld (if is64bit bld then R.RBP else R.EBP)

let private getRegOfSize bld oprSize regGrp =
  regGrp oprSize |> regVar bld

let inline private getStackWidth wordSize oprSize =
  numI32 (RegType.toByteWidth oprSize) wordSize

/// Push the given expression to the stack, assuming that the expression does
/// not include stack pointer.
let private auxPush oprSize bld expr =
  let sp = getStackPtr bld
  bld <+ (sp := sp .- (getStackWidth bld.RegType oprSize))
  bld <+ (AST.loadLE oprSize sp := expr)

let private computePopSize oprSize = function
  | Var (_, id, _, _) when isSegReg (Register.ofRegID id) -> 16<rt>
  | _ -> oprSize

let private auxPop oprSize bld dst =
  let sp = getStackPtr bld
  bld <+ (dst := AST.loadLE (computePopSize oprSize dst) sp)
  bld <+ (sp := sp .+ (getStackWidth bld.RegType oprSize))

let private maskOffset offset oprSize =
  let offset = AST.zext oprSize offset
  match oprSize with
  | 16<rt> -> offset .& numU32 0xFu 16<rt>
  | 32<rt> -> offset .& numU32 0x1Fu 32<rt>
  | 64<rt> -> offset .& numU32 0x3Fu 64<rt>
  | _ -> raise InvalidOperandSizeException

let rec private isVar = function
  | Var _ | TempVar _ -> true
  | Extract (e, _, _, _) -> isVar e
  | _ -> false

let private calculateOffset offset oprSize =
  match offset with
  | Num _ ->
    numU32 0u oprSize, maskOffset offset oprSize
  | _ ->
    let offset = AST.zext oprSize offset
    match oprSize with
    | 16<rt> -> numU32 2u 16<rt> .* (offset ./ numU32 16u 16<rt>),
                offset .& numU32 15u 16<rt>
    | 32<rt> -> numU32 4u 32<rt> .* (offset ./ numU32 32u 32<rt>),
                offset .& numU32 31u 32<rt>
    | 64<rt> -> numU32 4u 64<rt> .* (offset ./ numU32 32u 64<rt>),
                offset .& numU32 31u 64<rt>
    | _ -> raise InvalidOperandSizeException

let private strRepeat ins insLen bld body cond =
  let lblExit = label bld "Exit"
  let lblCont = label bld "Continue"
  let lblNext = label bld "Next"
  let n0 = AST.num0 bld.RegType
  let cx = regVar bld (if is64bit bld then R.RCX else R.ECX)
  let pc = getInstrPtr bld
  let ninstAddr = pc .+ numInsLen insLen bld
  bld <+ (AST.cjmp (cx == n0) (AST.jmpDest lblExit) (AST.jmpDest lblCont))
  bld <+ (AST.lmark lblCont)
  body ins bld
  bld <+ (cx := cx .- AST.num1 bld.RegType)
#if EMULATION
  setCCOp bld
  bld.ConditionCodeOp <- ConditionCodeOp.TraceStart
#endif
  match cond with
  | None -> bld <+ (AST.interjmp pc InterJmpKind.Base)
  | Some cond ->
    bld <+ (AST.cjmp (cx == n0) (AST.jmpDest lblExit) (AST.jmpDest lblNext))
    bld <+ (AST.lmark lblNext)
    bld <+ (AST.intercjmp cond ninstAddr pc)
  bld <+ (AST.lmark lblExit)
  (* We consider each individual loop from a REP-prefixed instruction as an
     independent basic block, because it is more intuitive and matches with
     the definition of basic block from text books. *)
  bld <+ (AST.interjmp ninstAddr InterJmpKind.Base)

let aaa (ins: Instruction) insLen bld =
#if DEBUG
  assert32 bld
#endif
  let al = regVar bld R.AL
  let af = regVar bld R.AF
  let ax = regVar bld R.AX
  let cf = regVar bld R.CF
  let alAnd0f = al .& numI32 0x0f 8<rt>
  let cond1 = AST.gt alAnd0f (numI32 9 8<rt>)
  let cond = tmpVar bld 1<rt>
  bld <!-- (ins.Address, insLen)
#if EMULATION
  bld <+ (cond := cond1 .| ((getAFLazy bld) == AST.b1))
#else
  bld <+ (cond := cond1 .| (af == AST.b1))
#endif
  bld <+ (ax := AST.ite cond (ax .+ numI32 0x106 16<rt>) ax)
  bld <+ (af := AST.ite cond AST.b1 AST.b0)
  bld <+ (cf := AST.ite cond AST.b1 AST.b0)
  bld <+ (al := alAnd0f)
#if !EMULATION
  bld <+ (regVar bld R.OF := undefOF)
  bld <+ (regVar bld R.SF := undefSF)
  bld <+ (regVar bld R.ZF := undefZF)
  bld <+ (regVar bld R.PF := undefPF)
#else
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let aad (ins: Instruction) insLen bld =
#if DEBUG
  assert32 bld
#endif
  bld <!-- (ins.Address, insLen)
  let imm8 = transOneOpr bld ins insLen |> AST.xtlo 8<rt>
  let al = regVar bld R.AL
  let ah = regVar bld R.AH
  let sf = AST.xthi 1<rt> al
  bld <+ (al := (al .+ (ah .* imm8)) .& (numI32 0xff 8<rt>))
  bld <+ (ah := AST.num0 8<rt>)
  enumSZPFlags bld al 8<rt> sf
#if !EMULATION
  bld <+ (regVar bld R.OF := undefOF)
  bld <+ (regVar bld R.AF := undefAF)
  bld <+ (regVar bld R.CF := undefCF)
#else
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let aam (ins: Instruction) insLen bld =
#if DEBUG
  assert32 bld
#endif
  bld <!-- (ins.Address, insLen)
  let imm8 = transOneOpr bld ins insLen |> AST.xtlo 8<rt>
  let al = regVar bld R.AL
  let ah = regVar bld R.AH
  let sf = AST.xthi 1<rt> al
  bld <+ (ah := al ./ imm8)
  bld <+ (al := al .% imm8)
  enumSZPFlags bld al 8<rt> sf
#if !EMULATION
  bld <+ (regVar bld R.OF := undefOF)
  bld <+ (regVar bld R.AF := undefAF)
  bld <+ (regVar bld R.CF := undefCF)
#else
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let aas (ins: Instruction) insLen bld =
#if DEBUG
  assert32 bld
#endif
  let ax = regVar bld R.AX
  let al = regVar bld R.AL
  let af = regVar bld R.AF
  let cf = regVar bld R.CF
  let ah = regVar bld R.AH
  let alAnd0f = al .& numI32 0x0f 8<rt>
  let cond1 = AST.gt alAnd0f (numI32 9 8<rt>)
  let cond = tmpVar bld 1<rt>
  bld <!-- (ins.Address, insLen)
#if EMULATION
  bld <+ (cond := cond1 .| ((getAFLazy bld) == AST.b1))
#else
  bld <+ (cond := cond1 .| (af == AST.b1))
#endif
  bld <+ (ax := AST.ite cond (ax .- numI32 6 16<rt>) ax)
  bld <+ (ah := AST.ite cond (ah .- AST.num1 8<rt>) ah)
  bld <+ (af := AST.ite cond AST.b1 AST.b0)
  bld <+ (cf := AST.ite cond AST.b1 AST.b0)
  bld <+ (al := alAnd0f)
#if EMULATION
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let adc (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = transTwoOprs bld true ins insLen
  let oprSize = getOperationSize ins
  let cf = regVar bld R.CF
  let struct (t1, t2, t3, t4) = tmpVars4 bld oprSize
  bld <+ (t1 := dst)
  bld <+ (t2 := AST.sext oprSize src)
#if EMULATION
  bld <+ (t3 := t2 .+ AST.zext oprSize (getCFLazy bld))
#else
  bld <+ (t3 := t2 .+ AST.zext oprSize cf)
#endif
  bld <+ (t4 := t1 .+ t3)
  bld <+ (dstAssign oprSize dst t4)
  bld <+ (cf := (t3 .< t2) .| (t4 .< t1))
  let struct (ofl, sf) = osfOnAdd t1 t2 t4 bld
  bld <+ (regVar bld R.OF := ofl)
  enumASZPFlags bld t1 t2 t4 oprSize sf
#if EMULATION
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let add (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  match ins.Operands with
  | TwoOperands (o1, o2) when o1 = o2 ->
    let dst = transOprToExpr bld false ins insLen o1
    if Prefix.hasLock ins.Prefixes then bld <+ (AST.sideEffect Lock) else ()
#if !EMULATION
    let struct (t1, t2) = tmpVars2 bld oprSize
    bld <+ (t1 := dst)
    bld <+ (t2 := t1 .+ t1)
    bld <+ (dstAssign oprSize dst t2)
    let struct (ofl, sf) = osfOnAdd t1 t1 t2 bld
    enumEFLAGS bld t1 t1 t2 oprSize (cfOnAdd t1 t2) ofl sf
#else
    let t = tmpVar bld oprSize
    bld <+ (t := dst)
    bld <+ (dstAssign oprSize dst (t .+ t))
    setCCOperands2 bld t dst
    match oprSize with
    | 8<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.ADDB
    | 16<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.ADDW
    | 32<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.ADDD
    | 64<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.ADDQ
    | _ -> raise InvalidRegTypeException
#endif
  | TwoOperands (o1, o2) ->
    let dst = transOprToExpr bld true ins insLen o1
    let src = transOprToExpr bld false ins insLen o2 |> transReg bld true
    if Prefix.hasLock ins.Prefixes then bld <+ (AST.sideEffect Lock) else ()
#if !EMULATION
    let isSrcConst = isConst src
    let t1 = tmpVar bld oprSize
    let t2 = if isSrcConst then src else tmpVar bld oprSize
    let t3 = tmpVar bld oprSize
    bld <+ (t1 := dst)
    if isSrcConst then () else bld <+ (t2 := src)
    bld <+ (t3 := t1 .+ t2)
    bld <+ (dstAssign oprSize dst t3)
    let struct (ofl, sf) = osfOnAdd t1 t2 t3 bld
    enumEFLAGS bld t1 t2 t3 oprSize (cfOnAdd t1 t3) ofl sf
#else
    let src =
      if isConst src then src
      else
        let t = tmpVar bld oprSize
        bld <+ (t := src)
        t
    bld <+ (dstAssign oprSize dst (dst .+ src))
    setCCOperands2 bld src dst
    match oprSize with
    | 8<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.ADDB
    | 16<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.ADDW
    | 32<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.ADDD
    | 64<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.ADDQ
    | _ -> raise InvalidRegTypeException
#endif
  | _ -> raise InvalidOperandException
  if Prefix.hasLock ins.Prefixes then bld <+ (AST.sideEffect Unlock) else ()
  bld --!> insLen

let adox (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = transTwoOprs bld true ins insLen
  let oprSize = getOperationSize ins
#if EMULATION
  let oF = getOFLazy bld
#else
  let oF = regVar bld R.OF
#endif
  match oprSize with
  | 32<rt> ->
    let struct (t1, t2, t3) = tmpVars3 bld 64<rt>
    bld <+ (t1 := AST.zext 64<rt> dst)
    bld <+ (t2 := AST.zext 64<rt> src)
    bld <+ (t3 := t1 .+ t2 .+ AST.zext 64<rt> oF)
    bld <+ (dstAssign oprSize dst (AST.xtlo oprSize t3))
    bld <+ (oF := AST.extract t3 1<rt> 32)
  | 64<rt> ->
    let struct (t1a, t2a, t3a) = tmpVars3 bld 64<rt>
    let struct (t1b, t2b, t3b) = tmpVars3 bld 64<rt>
    let mask = tmpVar bld 64<rt>
    bld <+ (mask := numU64 0xFFFFFFFFUL 64<rt>)
    bld <+ (t1a := dst .& mask)
    bld <+ (t1b := (dst >> (numI32 32 64<rt>)) .& mask)
    bld <+ (t2a := src .& mask)
    bld <+ (t2b := (src >> (numI32 32 64<rt>)) .& mask)
    bld <+ (t3a := t1a .+ t2a .+ AST.zext 64<rt> oF)
    bld <+ (t3b := t1b .+ t2b .+ (t3a >> (numI32 32 64<rt>)))
    bld <+ (dstAssign oprSize dst (dst .+ src .+ (AST.zext 64<rt> oF)))
    bld <+ (oF := AST.extract t3b 1<rt> 32)
  | _ -> raise InvalidOperandSizeException
  bld --!> insLen

let ``and`` (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = transTwoOprs bld true ins insLen
  let oprSize = getOperationSize ins
  let t = tmpVar bld oprSize
  if Prefix.hasLock ins.Prefixes then bld <+ (AST.sideEffect Lock) else ()
  bld <+ (dstAssign oprSize dst (dst .& AST.sext oprSize src))
#if EMULATION
  setCCDst bld dst
  match oprSize with
  | 8<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.LOGICB
  | 16<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.LOGICW
  | 32<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.LOGICD
  | 64<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.LOGICQ
  | _ -> raise InvalidRegTypeException
#else
  let sf = AST.xthi 1<rt> dst
  bld <+ (regVar bld R.OF := AST.b0)
  bld <+ (regVar bld R.CF := AST.b0)
  enumSZPFlags bld dst oprSize sf
  bld <+ (regVar bld R.AF := undefAF)
#endif
  if Prefix.hasLock ins.Prefixes then bld <+ (AST.sideEffect Unlock) else ()
  bld --!> insLen

let andn (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = transThreeOprs bld false ins insLen
  let oprSize = getOperationSize ins
  let t = tmpVar bld oprSize
  bld <+ (t := (AST.not src1) .& src2)
  bld <+ (dstAssign oprSize dst t)
  bld <+ (regVar bld R.SF := AST.extract dst 1<rt> (int oprSize - 1))
  bld <+ (regVar bld R.ZF := AST.eq dst (AST.num0 oprSize))
  bld <+ (regVar bld R.OF := AST.b0)
  bld <+ (regVar bld R.CF := AST.b0)
#if !EMULATION
  bld <+ (regVar bld R.AF := undefAF)
  bld <+ (regVar bld R.PF := undefPF)
#else
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let arpl (ins: Instruction) insLen bld =
#if DEBUG
  assert32 bld
#endif
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = transTwoOprs bld false ins insLen
  let struct (t1, t2) = tmpVars2 bld 16<rt>
  let mask = numI32 0xfffc 16<rt>
  let zF = regVar bld R.ZF
  bld <+ (t1 := dst .& numI32 0x3 16<rt>)
  bld <+ (t2 := src .& numI32 0x3 16<rt>)
  bld <+ (dst := AST.ite (t1 .< t2) ((dst .& mask) .| t2) dst)
  bld <+ (zF := t1 .< t2)
#if EMULATION
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let bextr (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let struct (dst, src1, src2) = transThreeOprs bld false ins insLen
  let zF = regVar bld R.ZF
  let struct (tmp, mask, start, len) = tmpVars4 bld oprSize
  bld <+ (start := AST.zext oprSize (AST.extract src2 8<rt> 0))
  bld <+ (len := AST.zext oprSize (AST.extract src2 8<rt> 8))
  bld <+ (mask := AST.not(numI32 0 oprSize) << len)
  bld <+ (tmp := AST.zext oprSize src1)
  bld <+ (tmp := (tmp >> start) .& AST.not(mask))
  bld <+ (dstAssign oprSize dst tmp)
  bld <+ (zF := (dst == AST.num0 oprSize))
  bld <+ (regVar bld R.CF := AST.b0)
  bld <+ (regVar bld R.OF := AST.b0)
#if !EMULATION
  bld <+ (regVar bld R.AF := undefAF)
  bld <+ (regVar bld R.SF := undefSF)
  bld <+ (regVar bld R.PF := undefPF)
#else
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let blsi (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let struct (dst, src) = transTwoOprs bld false ins insLen
  let tmp = tmpVar bld oprSize
  bld <+ (tmp := AST.neg src .& src)
  bld <+ (regVar bld R.SF := AST.xthi 1<rt> tmp)
  bld <+ (regVar bld R.ZF := tmp == AST.num0 oprSize)
  bld <+ (regVar bld R.CF := src != AST.num0 oprSize)
  bld <+ (dstAssign oprSize dst tmp)
  bld <+ (regVar bld R.OF := AST.b0)
#if !EMULATION
  bld <+ (regVar bld R.AF := undefAF)
  bld <+ (regVar bld R.PF := undefPF)
#else
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let private bndmov64 (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let struct (dst1, dst2) = transOprToExpr128 bld false ins insLen dst
  let struct (src1, src2) = transOprToExpr128 bld false ins insLen src
  bld <+ (dst1 := src1)
  bld <+ (dst2 := src2)
  bld --!> insLen

let private bndmov32Aux (ins: Instruction) insLen bld =
  let struct (dst, src) = getTwoOprs ins
  match dst, src with
  | OprReg _, OprMem _ ->
    let struct (dst1, dst2) = transOprToExpr128 bld false ins insLen dst
    let src = transOprToExpr bld false ins insLen src
    bld <+ (dst1 := AST.xthi 32<rt> src |> AST.zext 64<rt>)
    bld <+ (dst2 := AST.xtlo 32<rt> src |> AST.zext 64<rt>)
  | OprMem _, OprReg _ ->
    let struct (src1, src2) = transOprToExpr128 bld false ins insLen src
    let dst = transOprToExpr bld false ins insLen dst
    bld <+ (dst := AST.concat (AST.xtlo 32<rt> src1) (AST.xtlo 32<rt> src2))
  | _ -> raise InvalidOperandException

let bndmov32 (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  bndmov32Aux ins insLen bld
  bld --!> insLen

let bndmov ins insLen bld =
  if is64bit bld then bndmov64 ins insLen bld
  else bndmov32 ins insLen bld

let bsf (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblEnd = label bld "End"
  let lblLoopCond = label bld "LoopCond"
  let lblLE = label bld "LoopEnd"
  let lblLoop = label bld "Loop"
  let struct (dst, src) = transTwoOprs bld true ins insLen
  let oprSize = getOperationSize ins
  let cond = src == AST.num0 oprSize
  let zf = regVar bld R.ZF
  let t = tmpVar bld oprSize
#if EMULATION
  genDynamicFlagsUpdate bld
#endif
  bld <+ (AST.cjmp cond (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (zf := AST.b1)
  bld <+ (dst := AST.undef oprSize "DEST is undefined.")
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (zf := AST.b0)
  bld <+ (t := AST.num0 oprSize)
  bld <+ (AST.lmark lblLoopCond)
  bld <+ (AST.cjmp ((AST.xtlo 1<rt> (src >> t)) == AST.b0)
                 (AST.jmpDest lblLoop) (AST.jmpDest lblLE))
  bld <+ (AST.lmark lblLoop)
  bld <+ (t := t .+ AST.num1 oprSize)
  bld <+ (AST.jmp (AST.jmpDest lblLoopCond))
  bld <+ (AST.lmark lblLE)
  bld <+ (dstAssign oprSize dst t)
  bld <+ (AST.lmark lblEnd)
#if !EMULATION
  bld <+ (regVar bld R.CF := undefCF)
  bld <+ (regVar bld R.OF := undefOF)
  bld <+ (regVar bld R.AF := undefAF)
  bld <+ (regVar bld R.SF := undefSF)
  bld <+ (regVar bld R.PF := undefPF)
#else
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let bsr (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblEnd = label bld "End"
  let lblLoopCond = label bld "LoopCond"
  let lblLE = label bld "LoopEnd"
  let lblLoop = label bld "Loop"
  let struct (dst, src) = transTwoOprs bld true ins insLen
  let oprSize = getOperationSize ins
  let cond = src == AST.num0 oprSize
  let zf = regVar bld R.ZF
  let t = tmpVar bld oprSize
#if EMULATION
  genDynamicFlagsUpdate bld
#endif
  bld <+ (AST.cjmp cond (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (zf := AST.b1)
  bld <+ (dst := AST.undef oprSize "DEST is undefined.")
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (zf := AST.b0)
  bld <+ (t := numOprSize oprSize .- AST.num1 oprSize)
  bld <+ (AST.lmark lblLoopCond)
  bld <+ (AST.cjmp ((AST.xtlo 1<rt> (src >> t)) == AST.b0)
                 (AST.jmpDest lblLoop) (AST.jmpDest lblLE))
  bld <+ (AST.lmark lblLoop)
  bld <+ (t := t .- AST.num1 oprSize)
  bld <+ (AST.jmp (AST.jmpDest lblLoopCond))
  bld <+ (AST.lmark lblLE)
  bld <+ (dstAssign oprSize dst t)
  bld <+ (AST.lmark lblEnd)
#if !EMULATION
  bld <+ (regVar bld R.CF := undefCF)
  bld <+ (regVar bld R.OF := undefOF)
  bld <+ (regVar bld R.AF := undefAF)
  bld <+ (regVar bld R.SF := undefSF)
  bld <+ (regVar bld R.PF := undefPF)
#else
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let bswap (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let dst = transOneOpr bld ins insLen
  let oprSize = getOperationSize ins
  let cnt = RegType.toByteWidth oprSize |> int
  let t = tmpVar bld oprSize
  let tmps = Array.init cnt (fun _ -> tmpVar bld 8<rt>)
  bld <+ (t := dst)
  for i in 0 .. cnt - 1 do
    bld <+ (tmps[i] := AST.extract t 8<rt> (i * 8))
  done
  bld <+ (dstAssign oprSize dst (AST.revConcat (Array.rev tmps)))
  bld --!> insLen

let private bit ins bitBase bitOffset oprSize =
  match bitBase with
  | Load (e, t, expr, _) ->
    let effAddrSz = getEffAddrSz ins
    let addrOffset, bitOffset = calculateOffset bitOffset oprSize
    let addrOffset = AST.zext effAddrSz addrOffset
    AST.xtlo 1<rt> ((AST.load e t (expr .+ addrOffset)) >> bitOffset)
  | _ ->
    if isVar bitBase then
      AST.xtlo 1<rt> (bitBase >> maskOffset bitOffset oprSize)
    else raise InvalidExprException

let bt (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (bitBase, bitOffset) = transTwoOprs bld true ins insLen
  let oprSize = getOperationSize ins
#if EMULATION
  bld <+ (regVar bld R.ZF := getZFLazy bld)
#endif
  bld <+ (regVar bld R.CF := bit ins bitBase bitOffset oprSize)
#if !EMULATION
  bld <+ (regVar bld R.OF := undefOF)
  bld <+ (regVar bld R.SF := undefSF)
  bld <+ (regVar bld R.AF := undefAF)
  bld <+ (regVar bld R.PF := undefPF)
#else
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let private setBit ins bitBase bitOffset oprSize setValue =
  match bitBase with
  | Load (e, t, expr, _) ->
    let effAddrSz = getEffAddrSz ins
    let addrOffset, bitOffset = calculateOffset bitOffset oprSize
    let addrOffset = AST.zext effAddrSz addrOffset
    let mask = setValue << bitOffset
    let bit = (AST.zext oprSize AST.b1) << bitOffset
    let loadMem = AST.load e t (expr .+ addrOffset)
    loadMem := (loadMem .& (getMask oprSize .- bit)) .| mask
  | _ ->
    if isVar bitBase then
      let mask = setValue << maskOffset bitOffset oprSize
      let bit = (AST.zext oprSize AST.b1) << maskOffset bitOffset oprSize
      dstAssign oprSize bitBase ((bitBase .& (getMask oprSize .- bit)) .| mask)
    else
      raise InvalidExprException

let bitTest (ins: Instruction) insLen bld setValue =
  bld <!-- (ins.Address, insLen)
  let struct (bitBase, bitOffset) = transTwoOprs bld true ins insLen
  let oprSize = getOperationSize ins
  let setValue = AST.zext oprSize setValue
  if Prefix.hasLock ins.Prefixes then bld <+ (AST.sideEffect Lock) else ()
#if EMULATION
  bld <+ (regVar bld R.ZF := getZFLazy bld)
#endif
  bld <+ (regVar bld R.CF := bit ins bitBase bitOffset oprSize)
  bld <+ (setBit ins bitBase bitOffset oprSize setValue)
#if !EMULATION
  bld <+ (regVar bld R.OF := undefOF)
  bld <+ (regVar bld R.SF := undefSF)
  bld <+ (regVar bld R.AF := undefAF)
  bld <+ (regVar bld R.PF := undefPF)
#else
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  if Prefix.hasLock ins.Prefixes then bld <+ (AST.sideEffect Unlock) else ()
  bld --!> insLen

let btc (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (bitBase, bitOffset) = transTwoOprs bld true ins insLen
  let oprSize = getOperationSize ins
  if Prefix.hasLock ins.Prefixes then bld <+ (AST.sideEffect Lock) else ()
#if !EMULATION
  let setValue = AST.zext oprSize (regVar bld R.CF |> AST.not)
#else
  let setValue = AST.zext oprSize (getCFLazy bld |> AST.not)
  bld <+ (regVar bld R.ZF := getZFLazy bld)
#endif
  bld <+ (regVar bld R.CF := bit ins bitBase bitOffset oprSize)
  bld <+ (setBit ins bitBase bitOffset oprSize setValue)
#if !EMULATION
  bld <+ (regVar bld R.OF := undefOF)
  bld <+ (regVar bld R.SF := undefSF)
  bld <+ (regVar bld R.AF := undefAF)
  bld <+ (regVar bld R.PF := undefPF)
#else
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  if Prefix.hasLock ins.Prefixes then bld <+ (AST.sideEffect Unlock) else ()
  bld --!> insLen

let btr ins insLen bld =
  bitTest ins insLen bld AST.b0

let bts ins insLen bld =
  bitTest ins insLen bld AST.b1

let bzhi (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = transThreeOprs bld false ins insLen
  let oprSize = getOperationSize ins
  let n = tmpVar bld 8<rt>
  bld <+ (n := AST.xtlo 8<rt> src2)
  let cond1 = n .< numI32 (RegType.toBitWidth oprSize) 8<rt>
  let cond2 = n .> numI32 ((RegType.toBitWidth oprSize) - 1) 8<rt>
  let tmp = AST.zext oprSize (numI32 (RegType.toBitWidth oprSize) 8<rt> .- n)
  let cf = regVar bld R.CF
  bld <+ (dstAssign oprSize dst (AST.ite cond1 ((src1 << tmp) >> tmp) src1))
  bld <+ (cf := AST.ite cond2 AST.b1 AST.b0)
  bld <+ (regVar bld R.SF := AST.xthi 1<rt> dst)
  bld <+ (regVar bld R.ZF := dst == (AST.num0 oprSize))
  bld <+ (regVar bld R.OF := AST.b0)
#if !EMULATION
  bld <+ (regVar bld R.AF := undefAF)
  bld <+ (regVar bld R.PF := undefPF)
#else
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let call (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let pc = numU64 (ins: Instruction).Address bld.RegType
  let oprSize = getOperationSize ins
#if EMULATION
  setCCOp bld
  bld.ConditionCodeOp <- ConditionCodeOp.TraceStart
#endif
  let struct (target, ispcrel) = transJumpTargetOpr bld false ins pc insLen
  if ispcrel || not (hasStackPtr ins) then
    auxPush oprSize bld (pc .+ numInsLen insLen bld)
    bld <+ (AST.interjmp target InterJmpKind.IsCall)
  else
    let t = tmpVar bld oprSize (* Use tmpvar because the target can use RSP *)
    bld <+ (t := target)
    auxPush oprSize bld (pc .+ numInsLen insLen bld)
    bld <+ (AST.interjmp t InterJmpKind.IsCall)
  bld --!> insLen

let convBWQ (ins: Instruction) insLen bld =
  let opr = regVar bld (if is64bit bld then R.RAX else R.EAX)
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let src = AST.sext oprSize (AST.xtlo (oprSize / 2) opr)
  bld <+ (dstAssign oprSize (AST.xtlo oprSize opr) src)
  bld --!> insLen

let clearFlag (ins: Instruction) insLen bld flagReg =
  bld <!-- (ins.Address, insLen)
  bld <+ (regVar bld flagReg := AST.b0)
#if EMULATION
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let cmc (ins: Instruction) insLen bld =
  let cf = regVar bld R.CF
  bld <!-- (ins.Address, insLen)
#if EMULATION
  bld <+ (cf := AST.not (getCFLazy bld))
#else
  bld <+ (cf := AST.not cf)
#endif
#if !EMULATION
  bld <+ (regVar bld R.OF := undefOF)
  bld <+ (regVar bld R.AF := undefAF)
  bld <+ (regVar bld R.SF := undefSF)
  bld <+ (regVar bld R.ZF := undefZF)
  bld <+ (regVar bld R.PF := undefPF)
#else
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let private getCondOfCMov (ins: Instruction) bld =
  match ins.Opcode with
  | Opcode.CMOVO -> regVar bld R.OF
  | Opcode.CMOVNO -> regVar bld R.OF == AST.b0
  | Opcode.CMOVB -> regVar bld R.CF
  | Opcode.CMOVAE -> regVar bld R.CF == AST.b0
  | Opcode.CMOVZ -> regVar bld R.ZF
  | Opcode.CMOVNZ -> regVar bld R.ZF == AST.b0
  | Opcode.CMOVBE -> (regVar bld R.CF) .| (regVar bld R.ZF)
  | Opcode.CMOVA -> ((regVar bld R.CF) .| (regVar bld R.ZF)) == AST.b0
  | Opcode.CMOVS -> regVar bld R.SF
  | Opcode.CMOVNS -> regVar bld R.SF == AST.b0
  | Opcode.CMOVP -> regVar bld R.PF
  | Opcode.CMOVNP -> regVar bld R.PF == AST.b0
  | Opcode.CMOVL -> regVar bld R.SF != regVar bld R.OF
  | Opcode.CMOVGE -> regVar bld R.SF == regVar bld R.OF
  | Opcode.CMOVLE -> regVar bld R.ZF .|
                     (regVar bld R.SF != regVar bld R.OF)
  | Opcode.CMOVG -> regVar bld R.ZF == AST.b0 .&
                    (regVar bld R.SF == regVar bld R.OF)
  | _ -> raise InvalidOpcodeException

#if EMULATION
let private getCondOfCMovLazy (ins: Instruction) bld =
  match ins.Opcode with
  | Opcode.CMOVO -> getOFLazy bld
  | Opcode.CMOVNO -> getOFLazy bld |> AST.not
  | Opcode.CMOVB -> getCFLazy bld
  | Opcode.CMOVAE -> getCFLazy bld |> AST.not
  | Opcode.CMOVZ -> getZFLazy bld
  | Opcode.CMOVNZ -> getZFLazy bld |> AST.not
  | Opcode.CMOVBE ->
    let ccOp = bld.ConditionCodeOp
    match ccOp with
    | ConditionCodeOp.SUBB
    | ConditionCodeOp.SUBW
    | ConditionCodeOp.SUBD
    | ConditionCodeOp.SUBQ ->
      let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
      let regType = RegType.fromByteWidth size
      let src2 = getCCSrc1 bld regType
      let src1 = getCCDst bld regType .+ src2
      src1 .<= src2
    | _ -> (getCFLazy bld) .| (getZFLazy bld)
  | Opcode.CMOVA -> (getCFLazy bld .| getZFLazy bld) |> AST.not
  | Opcode.CMOVS -> getSFLazy bld
  | Opcode.CMOVNS -> getSFLazy bld |> AST.not
  | Opcode.CMOVP -> getPFLazy bld
  | Opcode.CMOVNP -> getPFLazy bld |> AST.not
  | Opcode.CMOVL ->
    let ccOp = bld.ConditionCodeOp
    match ccOp with
    | ConditionCodeOp.SUBB
    | ConditionCodeOp.SUBW
    | ConditionCodeOp.SUBD
    | ConditionCodeOp.SUBQ ->
      let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
      let regType = RegType.fromByteWidth size
      let src2 = getCCSrc1 bld regType
      let src1 = getCCDst bld regType .+ src2
      src1 ?< src2
    | _ -> getOFLazy bld != getSFLazy bld
  | Opcode.CMOVGE -> getOFLazy bld == getSFLazy bld
  | Opcode.CMOVLE ->
    let ccOp = bld.ConditionCodeOp
    match ccOp with
    | ConditionCodeOp.SUBB
    | ConditionCodeOp.SUBW
    | ConditionCodeOp.SUBD
    | ConditionCodeOp.SUBQ ->
      let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
      let regType = RegType.fromByteWidth size
      let src2 = getCCSrc1 bld regType
      let src1 = getCCDst bld regType .+ src2
      src1 ?<= src2
    | _ -> (getOFLazy bld != getSFLazy bld) .| (getZFLazy bld)
  | Opcode.CMOVG ->
    (getOFLazy bld == getSFLazy bld) .& (getZFLazy bld |> AST.not)
  | _ -> raise InvalidOpcodeException
#endif

let cmovcc (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = transTwoOprs bld false ins insLen
  let oprSize = getOperationSize ins
#if EMULATION
  bld <+ (dstAssign oprSize dst (AST.ite (getCondOfCMovLazy ins bld) src dst))
#else
  bld <+ (dstAssign oprSize dst (AST.ite (getCondOfCMov ins bld) src dst))
#endif
  bld --!> insLen

let cmp (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (src1, src2) = transTwoOprs bld false ins insLen
  let oprSize = getOperationSize ins
#if EMULATION
  setCCOperands2 bld src2 (src1 .- src2)
  match oprSize with
  | 8<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SUBB
  | 16<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SUBW
  | 32<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SUBD
  | 64<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SUBQ
  | _ -> raise InvalidRegTypeException
#else
  let isRhsConst = isConst src2
  let t1 = tmpVar bld oprSize
  let t2 = if isRhsConst then AST.sext oprSize src2 else tmpVar bld oprSize
  let t3 = tmpVar bld oprSize
  bld <+ (t1 := src1)
  if isRhsConst then () else bld <+ (t2 := AST.sext oprSize src2)
  bld <+ (t3 := t1 .- t2)
  let sf = AST.xthi 1<rt> t3
  enumEFLAGS bld t1 t2 t3 oprSize (cfOnSub t1 t2) (ofOnSub t1 t2 t3) sf
#endif
  bld --!> insLen

let private cmpsBody ins bld =
  let oprSize = getOperationSize ins
  let df = regVar bld R.DF
  let si = regVar bld (if is64bit bld then R.RSI else R.ESI)
  let di = regVar bld (if is64bit bld then R.RDI else R.EDI)
  let src1 = AST.loadLE oprSize si
  let src2 = AST.loadLE oprSize di
  let struct (t1, t2, t3) = tmpVars3 bld oprSize
  let amount = numI32 (RegType.toByteWidth oprSize) bld.RegType
  let sf = AST.xthi 1<rt> t3
  bld <+ (t1 := src1)
  bld <+ (t2 := src2)
  bld <+ (t3 := t1 .- t2)
  bld <+ (si := AST.ite df (si .- amount) (si .+ amount))
  bld <+ (di := AST.ite df (di .- amount) (di .+ amount))
  enumEFLAGS bld t1 t2 t3 oprSize (cfOnSub t1 t2) (ofOnSub t1 t2 t3) sf
#if EMULATION
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif

let cmps (ins: Instruction) insLen bld =
  let pref = ins.Prefixes
  let zf = regVar bld R.ZF
  bld <!-- (ins.Address, insLen)
  (if Prefix.hasREPZ pref then
     strRepeat ins insLen bld cmpsBody (Some (zf == AST.b0))
   elif Prefix.hasREPNZ pref then
     strRepeat ins insLen bld cmpsBody (Some (zf))
   else cmpsBody ins bld)
  bld --!> insLen

let cmpxchg (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = transTwoOprs bld true ins insLen
  let oprSize = getOperationSize ins
  if Prefix.hasLock ins.Prefixes then bld <+ (AST.sideEffect Lock) else ()
  let t = tmpVar bld oprSize
  let r = tmpVar bld oprSize
  let acc = getRegOfSize bld oprSize grpEAX
  let tAcc = tmpVar bld oprSize
  let cond = tmpVar bld 1<rt>
  let lblEq = label bld "Equal"
  let lblNeq = label bld "NotEqual"
  let lblEnd = label bld "End"
  bld <+ (t := dst)
  bld <+ (tAcc := acc)
  bld <+ (r := tAcc .- t)
  bld <+ (cond := tAcc == t)
  bld <+ (AST.cjmp cond (AST.jmpDest lblEq) (AST.jmpDest lblNeq))
  bld <+ (AST.lmark lblEq)
  bld <+ (regVar bld R.ZF := AST.b1)
  bld <+ (dstAssign oprSize dst src)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblNeq)
  bld <+ (regVar bld R.ZF := AST.b0)
  bld <+ (dstAssign oprSize acc t)
  bld <+ (AST.lmark lblEnd)
  bld <+ (regVar bld R.OF := ofOnSub tAcc t r)
  bld <+ (regVar bld R.SF := AST.xthi 1<rt> r)
  bld <+ (buildAF bld tAcc t r oprSize)
  buildPF bld r oprSize None
  bld <+ (regVar bld R.CF := cfOnSub tAcc t)
  if Prefix.hasLock ins.Prefixes then bld <+ (AST.sideEffect Unlock) else ()
#if EMULATION
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let private saveOprMem (bld: ILowUIRBuilder) expr =
  let sz = bld.RegType
  let t = tmpVar bld sz
  match expr with
  | Load (e, rt, expr, _) ->
    bld <+ (t := AST.zext sz expr)
    AST.load e rt t
  | _ -> expr

let compareExchangeBytes ins insLen bld =
  let oprSize = getOperationSize ins
  let zf = regVar bld R.ZF
  let cond = tmpVar bld 1<rt>
  bld <!-- (ins.Address, insLen)
  match oprSize with
  | 64<rt> ->
    let dst = transOneOpr bld ins insLen
    let orgDstMem = saveOprMem bld dst
    let eax = regVar bld R.EAX
    let ecx = regVar bld R.ECX
    let edx = regVar bld R.EDX
    let ebx = regVar bld R.EBX
    let t = tmpVar bld oprSize
    bld <+ (t := dst)
    bld <+ (cond := AST.concat edx eax == t)
    bld <+ (zf := cond)
    bld <+ (dstAssign 32<rt> eax (AST.ite cond eax (AST.xtlo 32<rt> t)))
    bld <+ (dstAssign 32<rt> edx (AST.ite cond edx (AST.xthi 32<rt> t)))
    bld <+ (orgDstMem := AST.ite cond (AST.concat ecx ebx) t)
  | 128<rt> ->
    let struct (dstB, dstA) =
      match ins.Operands with
      | OneOperand opr -> transOprToExpr128 bld false ins insLen opr
      | _ -> raise InvalidOperandException
    let orgDstAMem = saveOprMem bld dstA
    let orgDstBMem = saveOprMem bld dstB
    let rax = regVar bld R.RAX
    let rcx = regVar bld R.RCX
    let rdx = regVar bld R.RDX
    let rbx = regVar bld R.RBX
    let struct (t1, t2) = tmpVars2 bld 64<rt>
    bld <+ (t1 := dstA)
    bld <+ (t2 := dstB)
    bld <+ (cond := (t2 == rdx) .& (t1 == rax))
    bld <+ (zf := cond)
    bld <+ (rax := AST.ite cond rax t1)
    bld <+ (rdx := AST.ite cond rdx t2)
    bld <+ (orgDstAMem := AST.ite cond rbx t1)
    bld <+ (orgDstBMem := AST.ite cond rcx t2)
  | _ -> raise InvalidOperandSizeException
  bld --!> insLen

let convWDQ ins insLen bld =
  let oprSize = getOperationSize ins
  bld <!-- (ins.Address, insLen)
  match oprSize, bld.RegType with
  | 16<rt>, _ ->
    let t = tmpVar bld 32<rt>
    let ax = regVar bld R.AX
    let dx = regVar bld R.DX
    bld <+ (t := AST.sext 32<rt> ax)
    bld <+ (dx := AST.xthi 16<rt> t)
    bld <+ (ax := AST.xtlo 16<rt> t)
  | 32<rt>, _ ->
    let t = tmpVar bld 64<rt>
    let eax = regVar bld R.EAX
    let edx = regVar bld R.EDX
    bld <+ (t := AST.sext 64<rt> eax)
    bld <+ (dstAssign oprSize edx (AST.xthi 32<rt> t))
    bld <+ (eax := AST.xtlo 32<rt> t)
  | 64<rt>, 64<rt> ->
    let rdx = regVar bld R.RDX
    let rax = regVar bld R.RAX
    let cond = AST.extract rax 1<rt> 63
    bld <+ (rdx := AST.ite cond (numI32 -1 64<rt>) (AST.num0 64<rt>))
  | _, _ -> raise InvalidOperandSizeException
  bld --!> insLen

let private bitReflect bld src =
  let oprSize = Expr.TypeOf src
  let struct (res, tmp) = tmpVars2 bld oprSize
  bld <+ (tmp := src)
  let oSz = int oprSize
  for i in 0 .. oSz - 1 do
    bld <+ (AST.extract res 1<rt> (oSz - 1 - i) := AST.extract tmp 1<rt> i)
  done
  res |> AST.zext 64<rt>

let private mod2 bld dividend divisor divdnSz =
  let divsSz = 33
  let struct (remainder, mask) = tmpVars2 bld 64<rt>
  let divdnSzMask = numI64 ((1L <<< (int divdnSz)) - 1L) 64<rt>
  bld <+ (mask := if divdnSz = 64 then getMask 64<rt> else divdnSzMask)
  for i in (divdnSz - 1) .. -1 .. divsSz - 1 do
    let shfAmt = numI32 (i + 1 - divsSz) 64<rt>
    let pDivdn = dividend >> shfAmt
    let cond = AST.extract dividend 1<rt> i
    bld <+ (remainder := AST.ite cond (pDivdn <+> divisor) pDivdn)
    let m = mask >> (numI32 divdnSz 64<rt> .- shfAmt)
    bld <+ (dividend := (dividend .& m) .| (remainder << shfAmt))
  done
  dividend |> AST.xtlo 32<rt>

let crc32 (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = transTwoOprs bld true ins insLen
  let divisor = tmpVar bld 64<rt>
  bld <+ (divisor := numI64 0x11EDC6F41L 64<rt>)
  let srcSz = Expr.TypeOf src
  match srcSz with
  | 32<rt> | 16<rt> | 8<rt> ->
    let struct (t1, t2, t3) = tmpVars3 bld 64<rt>
    let struct (t4, t5) = tmpVars2 bld 64<rt>
    let t6 = tmpVar bld 32<rt>
    bld <+ (t1 := bitReflect bld src)
    bld <+ (t2 := bitReflect bld (AST.xtlo 32<rt> dst))
    bld <+ (t3 := t1 << numI32 32 64<rt>)
    bld <+ (t4 := t2 << numI32 (int srcSz) 64<rt>)
    bld <+ (t5 := t3 <+> t4)
    bld <+ (t6 := mod2 bld t5 divisor (int srcSz + 32))
    bld <+ (dstAssign 32<rt> dst (bitReflect bld t6))
  | 64<rt> ->
    let struct (t1, t2) = tmpVars2 bld 64<rt>
    let struct (t3a, t3b) = tmpVars2 bld 64<rt>
    let struct (t4a, t4b) = tmpVars2 bld 64<rt>
    let struct (t5a, t5b) = tmpVars2 bld 64<rt>
    let t6 = tmpVar bld 32<rt>
    bld <+ (t1 := bitReflect bld src)
    bld <+ (t2 := bitReflect bld (AST.xtlo 32<rt> dst))
    bld <+ (t3a := (AST.xtlo 32<rt> t1 |> AST.zext 64<rt>) << numI32 32 64<rt>)
    bld <+ (t3b := AST.xthi 32<rt> t1 |> AST.zext 64<rt>)
    bld <+ (t4a := AST.num0 64<rt>)
    bld <+ (t4b := AST.xtlo 32<rt> t2 |> AST.zext 64<rt>)
    bld <+ (t5a := t3a <+> t4a)
    bld <+ (t5b := t3b <+> t4b)
    bld <+ (t5b := AST.concat (AST.xtlo 32<rt> t5b) (AST.xthi 32<rt> t5a))
    bld <+ (t6 := mod2 bld t5b divisor 64)
    bld <+ (t5a := AST.concat (AST.xtlo 32<rt> t6) (AST.xtlo 32<rt> t5a))
    bld <+ (t6 := mod2 bld t5a divisor 64)
    bld <+ (dstAssign 32<rt> dst (bitReflect bld t6))
  | _ -> raise InvalidOperandSizeException
  bld --!> insLen

let daa insAddr insLen bld =
#if DEBUG
  assert32 bld
#endif
  let al = regVar bld R.AL
  let cf = regVar bld R.CF
  let af = regVar bld R.AF
  let oldAl = tmpVar bld 8<rt>
  let oldCf = tmpVar bld 1<rt>
  let alAnd0f = al .& numI32 0x0f 8<rt>
  let subCond1 = AST.gt alAnd0f (numI32 9 8<rt>)
  let cond1 = tmpVar bld 1<rt>
  let subCond3 = AST.gt oldAl (numI32 0x99 8<rt>)
  let subCond4 = oldCf == AST.b1
  let cond2 = tmpVar bld 1<rt>
  let sf = AST.xthi 1<rt> al
  bld <!-- (insAddr, insLen)
  bld <+ (oldAl := al)
#if EMULATION
  bld <+ (oldCf := getCFLazy bld)
#else
  bld <+ (oldCf := cf)
#endif
  bld <+ (cf := AST.b0)
#if EMULATION
  bld <+ (cond1 := subCond1 .| ((getAFLazy bld) == AST.b1))
#else
  bld <+ (cond1 := subCond1 .| (af == AST.b1))
#endif
  bld <+ (al := AST.ite cond1 (al .+ numI32 6 8<rt>) al)
  bld <+ (cf := AST.ite cond1 oldCf cf)
  bld <+ (af := cond1)
  bld <+ (cond2 := subCond3 .| subCond4)
  bld <+ (al := AST.ite cond2 (al .+ numI32 0x60 8<rt>) al)
  bld <+ (cf := cond2)
  enumSZPFlags bld al 8<rt> sf
#if !EMULATION
  bld <+ (regVar bld R.OF := undefOF)
#else
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let das insAddr insLen bld =
#if DEBUG
  assert32 bld
#endif
  let al = regVar bld R.AL
  let cf = regVar bld R.CF
  let af = regVar bld R.AF
  let oldAl = tmpVar bld 8<rt>
  let oldCf = tmpVar bld 1<rt>
  let alAnd0f = al .& numI32 0x0f 8<rt>
  let subCond1 = AST.gt alAnd0f (numI32 9 8<rt>)
  let subCond2 = af == AST.b1
  let cond1 = tmpVar bld 1<rt>
  let subCond3 = AST.gt oldAl (numI32 0x99 8<rt>)
  let subCond4 = oldCf == AST.b1
  let cond2 = tmpVar bld 1<rt>
  let sf = AST.xthi 1<rt> al
  bld <!-- (insAddr, insLen)
  bld <+ (oldAl := al)
#if EMULATION
  bld <+ (oldCf := getCFLazy bld)
#else
  bld <+ (oldCf := cf)
#endif
  bld <+ (cf := AST.b0)
#if EMULATION
  bld <+ (cond1 := subCond1 .| ((getAFLazy bld) == AST.b1))
#else
  bld <+ (cond1 := subCond1 .| (af == AST.b1))
#endif
  bld <+ (al := AST.ite cond1 (al .- numI32 6 8<rt>) al)
  bld <+ (cf := AST.ite cond1 oldCf cf)
  bld <+ (af := cond1)
  bld <+ (cond2 := subCond3 .| subCond4)
  bld <+ (al := AST.ite cond2 (al .- numI32 0x60 8<rt>) al)
  bld <+ (cf := cond2)
  enumSZPFlags bld al 8<rt> sf
#if !EMULATION
  bld <+ (regVar bld R.OF := undefOF)
#else
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let dec (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let dst = transOneOpr bld ins insLen
  let oprSize = getOperationSize ins
  let struct (t1, t2, t3) = tmpVars3 bld oprSize
  let sf = AST.xthi 1<rt> t3
  if Prefix.hasLock ins.Prefixes then bld <+ (AST.sideEffect Lock) else ()
  bld <+ (t1 := dst)
  bld <+ (t2 := AST.num1 oprSize)
  bld <+ (t3 := (t1 .- t2))
  bld <+ (dstAssign oprSize dst t3)
  bld <+ (regVar bld R.OF := ofOnSub t1 t2 t3)
  enumASZPFlags bld t1 t2 t3 oprSize sf
  if Prefix.hasLock ins.Prefixes then bld <+ (AST.sideEffect Unlock) else ()
#if EMULATION
  bld <+ (regVar bld R.CF := getCFLazy bld)
  setCCOperands2 bld t2 t3
  match oprSize with
  | 8<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.DECB
  | 16<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.DECW
  | 32<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.DECD
  | 64<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.DECQ
  | _ -> raise InvalidRegTypeException
#endif
  bld --!> insLen

let private mul64Bit src1 src2 bld =
  let struct (hiSrc1, loSrc1, hiSrc2, loSrc2) = tmpVars4 bld 64<rt>
  let struct (tSrc1, tSrc2) = tmpVars2 bld 64<rt>
  let struct (tHigh, tLow) = tmpVars2 bld 64<rt>
  let struct (pMid, pLow) = tmpVars2 bld 64<rt>
  let struct (hi1Lo2, lo1Hi2) = tmpVars2 bld 64<rt>
  let n32 = numI32 32 64<rt>
  let mask = numI64 0xFFFFFFFFL 64<rt>
  bld <+ (tSrc1 := src1)
  bld <+ (tSrc2 := src2)
  bld <+ (hiSrc1 := (tSrc1 >> n32) .& mask) (* SRC1[63:32] *)
  bld <+ (loSrc1 := tSrc1 .& mask) (* SRC1[31:0] *)
  bld <+ (hiSrc2 := (tSrc2 >> n32) .& mask) (* SRC2[63:32] *)
  bld <+ (loSrc2 := tSrc2 .& mask) (* SRC2[31:0] *)
  let pHigh = hiSrc1 .* hiSrc2
  bld <+ (hi1Lo2 := hiSrc1 .* loSrc2)
  bld <+ (lo1Hi2 := loSrc1 .* hiSrc2)
  bld <+ (pMid := hi1Lo2 .+ lo1Hi2)
  bld <+ (pLow := loSrc1 .* loSrc2)
  let high = pHigh .+ ((pMid .+ (pLow >> n32)) >> n32)
  let low = pLow .+ ((pMid .& mask) << n32)
  let isOverflow = hi1Lo2 .> numI64 0xffffffff_ffffffffL 64<rt> .- lo1Hi2
  bld <+ (tHigh :=
    high .+ AST.ite isOverflow (numI64 0x100000000L 64<rt>) (AST.num0 64<rt>))
  bld <+ (tLow := low)
  struct (tHigh, tLow)

let private helperRemSub remHi remLo srcHi srcLo bld =
  let t = tmpVar bld 1<rt>
  bld <+ (t := remLo .< srcLo)
  bld <+ (remLo := remLo .- srcLo)
  bld <+ (remHi := remHi .- srcHi)
  bld <+ (remHi := remHi .- AST.ite t (AST.num1 64<rt>) (AST.num0 64<rt>))

let helperRemAdd remHi remLo srcHi srcLo remMsb bld =
  let r = tmpVar bld 64<rt>
  let t = tmpVar bld 1<rt>
  let cond = r .< remLo
  bld <+ (r := remLo .+ srcLo)
  bld <+ (t := cond)
  bld <+ (remLo := AST.ite remMsb r remLo)
  let toAdd = AST.ite t (AST.num1 64<rt>) (AST.num0 64<rt>)
  bld <+ (remHi := AST.ite remMsb (remHi .+ srcHi .+ toAdd) remHi)

let divideWithoutConcat opcode oprSize divisor lblAssign lblErr bld =
  let struct (trdx, trax, tdivisor) = tmpVars3 bld oprSize
  let rdx, rax = regVar bld R.RDX, regVar bld R.RAX
  let struct (lz, y, t, nrmDvsr) = tmpVars4 bld oprSize
  let struct (remHi, remLo) = tmpVars2 bld oprSize
  let struct (qh, ql, q) = tmpVars3 bld oprSize
  let remMsb = tmpVar bld 1<rt>
  let n32 = numI32 32 64<rt>
  let zero = AST.num0 64<rt>
  let one = AST.num1 64<rt>
  let numF = numI64 0xffffffff oprSize
  let struct (nrmDvsrShl32, nrmDvsrShr32) = tmpVars2 bld oprSize
  let condGE = (remHi >> n32) .>= nrmDvsrShr32
  let updateSign = tmpVar bld 1<rt>
  let lblComputable = label bld "Computable"
  let lblEasy = label bld "Easy"
  let lblHard = label bld "Hard"
  let isEasy = trdx == AST.num0 oprSize
  let errChk = AST.gt divisor trdx
  let quotient = tmpVar bld oprSize
  let remainder = tmpVar bld oprSize
  match opcode with
  | Opcode.DIV ->
    bld <+ (trdx := rdx)
    bld <+ (trax := rax)
    bld <+ (tdivisor := divisor)
  | Opcode.IDIV ->
    let struct (dividendIsNeg, divisorIsNeg) = tmpVars2 bld 1<rt>
    bld <+ (dividendIsNeg := (AST.xthi 1<rt> rdx == AST.b1))
    bld <+ (divisorIsNeg := (AST.xthi 1<rt> divisor == AST.b1))
    bld <+ (trdx := AST.ite dividendIsNeg (AST.not rdx) rdx)
    bld <+ (trax := AST.ite dividendIsNeg (AST.not rax .+ numI32 1 oprSize) rax)
    let carry = AST.ite (AST.``and`` dividendIsNeg (AST.eq trax zero)) one zero
    bld <+ (trdx := trdx .+ carry)
    bld <+ (tdivisor := AST.ite divisorIsNeg (AST.neg divisor) divisor)
    bld <+ (updateSign := dividendIsNeg <+> divisorIsNeg)
  | _ -> raise InvalidOpcodeException
  bld <+ (AST.cjmp errChk (AST.jmpDest lblComputable) (AST.jmpDest lblErr))
  bld <+ (AST.lmark lblComputable)
  bld <+ (AST.cjmp isEasy (AST.jmpDest lblEasy) (AST.jmpDest lblHard))
  bld <+ (AST.lmark lblEasy)
  bld <+ (quotient := trax ./ tdivisor)
  bld <+ (remainder := trax .% tdivisor)
  bld <+ (AST.jmp (AST.jmpDest lblAssign))
  bld <+ (AST.lmark lblHard)
  (* normalize divisor; adjust dividend
     accordingly (initial partial remainder) *)
  let z = tmpVar bld 1<rt>
  bld <+ (lz := (numI64 64L oprSize))
  bld <+ (t := tdivisor)
  bld <+ (y := (t >> (numI64 32 oprSize)))
  bld <+ (z := y != zero)
  bld <+ (lz := (AST.ite z (lz .- numI64 32 oprSize) lz))
  bld <+ (t := (AST.ite z y t))
  bld <+ (y := (t >> (numI64 16 oprSize)))
  bld <+ (z := y != zero)
  bld <+ (lz := (AST.ite z (lz .- numI64 16 oprSize) lz))
  bld <+ (t := (AST.ite z y t))
  bld <+ (y := (t >> (numI64 8 oprSize)))
  bld <+ (z := y != zero)
  bld <+ (lz := (AST.ite z (lz .- numI64 8 oprSize) lz))
  bld <+ (t := (AST.ite z y t))
  bld <+ (y := (t >> (numI64 4 oprSize)))
  bld <+ (z := y != zero)
  bld <+ (lz := (AST.ite z (lz .- numI64 4 oprSize) lz))
  bld <+ (t := (AST.ite z y t))
  bld <+ (y := (t >> (numI64 2 oprSize)))
  bld <+ (z := y != zero)
  bld <+ (lz := (AST.ite z (lz .- numI64 2 oprSize) lz))
  bld <+ (t := (AST.ite z y t))
  bld <+ (y := (t >> (numI64 1 oprSize)))
  bld <+ (z := y != zero)
  bld <+ (lz := (AST.ite z (lz .- numI64 2 oprSize) (lz .- t)))
  bld <+ (nrmDvsr := tdivisor << lz)
  bld <+ (nrmDvsrShl32 := nrmDvsr << n32)
  bld <+ (nrmDvsrShr32 := nrmDvsr >> n32)
  bld <+ (t := AST.ite (lz != zero) (trax >> ((numI64 64 oprSize) .- lz)) zero)
  bld <+ (remHi := (trdx << lz) .| t)
  bld <+ (remLo := trax << lz)
  bld <+ (qh := AST.ite condGE numF (remHi ./ nrmDvsrShr32))
  (* compute remainder; correct quotient "digit" if remainder negative *)
  let struct (prodHi, prodLo) = mul64Bit (qh << n32) nrmDvsr bld
  helperRemSub remHi remLo prodHi prodLo bld
  bld <+ (remMsb := (AST.xthi 1<rt> remHi))
  bld <+ (qh := (AST.ite remMsb (qh .- one) (qh)))
  helperRemAdd remHi remLo nrmDvsrShr32 (nrmDvsrShl32) remMsb bld
  bld <+ (remMsb := (AST.xthi 1<rt> remHi))
  bld <+ (qh := (AST.ite remMsb (qh .- one) (qh)))
  helperRemAdd remHi remLo nrmDvsrShr32 (nrmDvsrShl32) remMsb bld
  bld <+ (remHi := (remHi << n32) .| (remLo >> n32))
  bld <+ (remLo := (remLo << n32))
  (* compute least significant quotient "digit";
     TAOCP: may be off by 0, +1, +2 *)
  bld <+ (ql := AST.ite condGE numF (remHi ./ nrmDvsrShr32))
  bld <+ (q := (qh << n32) .+ ql)
  (* compute remainder; correct quotient "digit" if remainder negative *)
  let struct (prodHi, prodLo) = mul64Bit q tdivisor bld
  bld <+ (remLo := trax)
  bld <+ (remHi := trdx)
  helperRemSub remHi remLo prodHi prodLo bld
  bld <+ (remMsb := (AST.xthi 1<rt> remHi))
  bld <+ (q := (AST.ite remMsb (q .- one) q))
  helperRemAdd remHi remLo zero tdivisor remMsb bld
  bld <+ (remMsb := (AST.xthi 1<rt> remHi))
  bld <+ (q := (AST.ite remMsb (q .- one) q))
  let struct (prodHi, prodLo) = mul64Bit q tdivisor bld
  helperRemSub trdx trax prodHi prodLo bld
  bld <+ (quotient := q)
  bld <+ (remainder := trax)
  bld <+ (AST.lmark lblAssign)
  match opcode with
  | Opcode.DIV ->
    bld <+ (dstAssign oprSize rax quotient)
    bld <+ (dstAssign oprSize rdx remainder)
  | Opcode.IDIV ->
    let isDividendNeg = AST.xthi 1<rt> rdx == AST.b1
    bld <+ (rax := (AST.ite updateSign (AST.neg quotient) quotient))
    bld <+ (rdx := (AST.ite isDividendNeg (AST.neg remainder) remainder))
  | _ -> raise InvalidOpcodeException

let private getDividend bld = function
  | 8<rt> -> regVar bld R.AX
  | 16<rt> -> AST.concat (regVar bld R.DX) (regVar bld R.AX)
  | 32<rt> -> AST.concat (regVar bld R.EDX) (regVar bld R.EAX)
  | _ -> raise InvalidOperandSizeException

let private checkQuotientDIV oprSize lblAssign lblErr q =
  AST.cjmp (AST.xthi oprSize q == AST.num0 oprSize)
           (AST.jmpDest lblAssign) (AST.jmpDest lblErr)

let private checkQuotientIDIV oprSize sz lblAssign lblErr q =
  let amount = numI32 (RegType.toBitWidth oprSize - 1) oprSize
  let mask = AST.num1 oprSize << amount
  let msb = AST.xthi 1<rt> q
  let negRes =  q .< (AST.zext sz mask)
  let posRes = q .> (AST.zext sz (mask .- (AST.num1 oprSize)))
  let cond = AST.ite (msb == AST.b1) negRes posRes
  AST.cjmp cond (AST.jmpDest lblErr) (AST.jmpDest lblAssign)

let divideWithConcat opcode oprSize divisor lblAssign lblErr bld =
  let dividend = getDividend bld oprSize
  let sz = Expr.TypeOf dividend
  let quotient = tmpVar bld sz
  let remainder = tmpVar bld sz
  match opcode with
  | Opcode.DIV ->
    let divisor = AST.zext sz divisor
    bld <+ (quotient := dividend ./ divisor)
    bld <+ (remainder := dividend .% divisor)
    bld <+ (checkQuotientDIV oprSize lblAssign lblErr quotient)
  | Opcode.IDIV ->
    let divisor = AST.sext sz divisor
    bld <+ (quotient := dividend ?/ divisor)
    bld <+ (remainder := dividend ?% divisor)
    bld <+ (checkQuotientIDIV oprSize sz lblAssign lblErr quotient)
  | _ -> raise InvalidOpcodeException
  bld <+ (AST.lmark lblAssign)
  match oprSize with
  | 8<rt> ->
    bld <+ (regVar bld R.AL := AST.xtlo oprSize quotient)
    bld <+ (regVar bld R.AH := AST.xtlo oprSize remainder)
  | 16<rt> | 32<rt> ->
    let q = getRegOfSize bld oprSize grpEAX
    let r = getRegOfSize bld oprSize grpEDX
    bld <+ (dstAssign oprSize q (AST.xtlo oprSize quotient))
    bld <+ (dstAssign oprSize r (AST.xtlo oprSize remainder))
  | _ -> raise InvalidOperandSizeException

let div (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let lblAssign = label bld "Assign"
  let lblChk = label bld "Check"
  let lblErr = label bld "DivErr"
  let divisor = transOneOpr bld ins insLen
  let oprSize = getOperationSize ins
  bld <+ (AST.cjmp (divisor == AST.num0 oprSize)
                 (AST.jmpDest lblErr) (AST.jmpDest lblChk))
  bld <+ (AST.lmark lblErr)
  bld <+ (AST.sideEffect (Exception "DivErr"))
  bld <+ (AST.lmark lblChk)
  match oprSize with
  | 64<rt> ->
    divideWithoutConcat ins.Opcode oprSize divisor lblAssign lblErr bld
  | _ ->
    divideWithConcat ins.Opcode oprSize divisor lblAssign lblErr bld
#if !EMULATION
  bld <+ (regVar bld R.CF := undefCF)
  bld <+ (regVar bld R.OF := undefOF)
  bld <+ (regVar bld R.AF := undefAF)
  bld <+ (regVar bld R.SF := undefSF)
  bld <+ (regVar bld R.ZF := undefZF)
  bld <+ (regVar bld R.PF := undefPF)
#else
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let enter ins insLen bld =
  let oSz = getOperationSize ins
  bld <!-- (ins.Address, insLen)
  let struct (imm16, imm8) = transTwoOprs bld false ins insLen
  let struct (allocSize, nestingLevel, cnt) = tmpVars3 bld oSz
  let struct (frameTemp, addrSize) = tmpVars2 bld bld.RegType
  let bp = getBasePtr bld
  let sp = getStackPtr bld
  let lblLoop = label bld "Loop"
  let lblCont = label bld "Continue"
  let lblLevelCheck = label bld "NestingLevelCheck"
  let lblLv1 = label bld "NestingLevel1"
  let getAddrSize bitSize =
    if bitSize = 64<rt> then numI32 8 bitSize else numI32 4 bitSize
  bld <+ (allocSize := imm16)
  bld <+ (nestingLevel := imm8 .% (numI32 32 oSz))
  auxPush bld.RegType bld bp
  bld <+ (frameTemp := sp)
  bld <+ (addrSize := getAddrSize bld.RegType)
  if imm8 .% (numI32 32 oSz) = (numI32 0 oSz) then
    () (* IR Optimization: Do not add unnecessary IRs *)
  else
    bld <+ (AST.cjmp (nestingLevel == AST.num0 oSz)
                   (AST.jmpDest lblCont) (AST.jmpDest lblLevelCheck))
    bld <+ (AST.lmark lblLevelCheck)
    bld <+ (cnt := nestingLevel .- AST.num1 oSz)
    bld <+ (AST.cjmp (AST.gt nestingLevel (AST.num1 oSz))
                   (AST.jmpDest lblLoop) (AST.jmpDest lblLv1))
    bld <+ (AST.lmark lblLoop)
    bld <+ (bp := bp .- addrSize)
    auxPush bld.RegType bld (AST.loadLE bld.RegType bp)
    bld <+ (cnt := cnt .- AST.num1 oSz)
    bld <+ (AST.cjmp (cnt == AST.num0 oSz)
                   (AST.jmpDest lblCont) (AST.jmpDest lblLoop))
    bld <+ (AST.lmark lblLv1)
    auxPush bld.RegType bld frameTemp
    bld <+ (AST.lmark lblCont)
  bld <+ (bp := frameTemp)
  bld <+ (sp := sp .- AST.zext bld.RegType allocSize)
  bld --!> insLen

let private imul64Bit src1 src2 bld =
  let struct (hiSrc1, loSrc1, hiSrc2, loSrc2) = tmpVars4 bld 64<rt>
  let struct (tSrc1, tSrc2) = tmpVars2 bld 64<rt>
  let struct (tHigh, tLow) = tmpVars2 bld 64<rt>
  let struct (pHigh, pMid, pLow) = tmpVars3 bld 64<rt>
  let struct (pMid1, pMid2) = tmpVars2 bld 64<rt>
  let struct (high, low) = tmpVars2 bld 64<rt>
  let n32 = numI32 32 64<rt>
  let zero = numI32 0 64<rt>
  let one = numI32 1 64<rt>
  let mask = numI64 0xFFFFFFFFL 64<rt>
  let struct (src1IsNeg, src2IsNeg, isSign) = tmpVars3 bld 1<rt>
  bld <+ (src1IsNeg := AST.xthi 1<rt> src1)
  bld <+ (src2IsNeg := AST.xthi 1<rt> src2)
  bld <+ (tSrc1 := AST.ite src1IsNeg (AST.neg src1) src1)
  bld <+ (tSrc2 := AST.ite src2IsNeg (AST.neg src2) src2)
  bld <+ (hiSrc1 := (tSrc1 >> n32) .& mask) (* SRC1[63:32] *)
  bld <+ (loSrc1 := tSrc1 .& mask) (* SRC1[31:0] *)
  bld <+ (hiSrc2 := (tSrc2 >> n32) .& mask) (* SRC2[63:32] *)
  bld <+ (loSrc2 := tSrc2 .& mask) (* SRC2[31:0] *)
  bld <+ (pHigh := hiSrc1 .* hiSrc2)
  bld <+ (pMid1 := hiSrc1 .* loSrc2)
  bld <+ (pMid2 := loSrc1 .* hiSrc2)
  bld <+ (pMid := pMid1 .+ pMid2)
  bld <+ (pLow := loSrc1 .* loSrc2)
  let isOverflow =
    pMid1 .> numI64 0xffffffff_ffffffffL 64<rt> .- pMid2
  let c = AST.ite isOverflow (numI64 0x100000000L 64<rt>) (AST.num0 64<rt>)
  bld <+ (high := pHigh .+ ((pMid .+ (pLow >> n32)) >> n32) .+ c)
  bld <+ (low := pLow .+ ((pMid .& mask) << n32))
  bld <+ (isSign := src1IsNeg <+> src2IsNeg) // T11
  bld <+ (tHigh := AST.ite isSign (AST.not high) high)
  bld <+ (tLow := AST.ite isSign (AST.neg low) low)
  let carry = AST.ite (AST.``and`` isSign (AST.eq tLow zero)) one zero
  bld <+ (tHigh := tHigh .+ carry)
  struct (tHigh, tLow)

let private oneOperandImul bld oprSize src =
  match oprSize with
  | 8<rt> ->
    let mulSize = oprSize * 2
    let t = tmpVar bld mulSize
    let cond = AST.sext mulSize (AST.xtlo oprSize t) == t
    bld <+ (t := AST.sext mulSize (regVar bld R.AL) .* AST.sext mulSize src)
    bld <+ (dstAssign oprSize (regVar bld R.AX) t)
    bld <+ (regVar bld R.CF := cond == AST.b0)
    bld <+ (regVar bld R.OF := cond == AST.b0)
  | 16<rt> | 32<rt> ->
    let mulSize = oprSize * 2
    let t = tmpVar bld mulSize
    let cond = AST.sext mulSize (AST.xtlo oprSize t) == t
    let r1 = getRegOfSize bld oprSize grpEDX
    let r2 = getRegOfSize bld oprSize grpEAX
    bld <+ (t := AST.sext mulSize r2 .* AST.sext mulSize src)
    bld <+ (dstAssign oprSize r1 (AST.xthi oprSize t))
    bld <+ (dstAssign oprSize r2 (AST.xtlo oprSize t))
    bld <+ (regVar bld R.CF := cond == AST.b0)
    bld <+ (regVar bld R.OF := cond == AST.b0)
  | 64<rt> ->
    let r1 = getRegOfSize bld oprSize grpEDX
    let r2 = getRegOfSize bld oprSize grpEAX
    let struct (high, low) = imul64Bit r2 src bld
    bld <+ (dstAssign oprSize r1 high)
    bld <+ (dstAssign oprSize r2 low)
    let num0 = AST.num0 64<rt>
    let numF = numI64 0xFFFFFFFFFFFFFFFFL 64<rt>
    let cond = tmpVar bld 1<rt>
    bld <+ (cond := AST.ite (AST.xthi 1<rt> low) (high == numF) (high == num0))
    bld <+ (regVar bld R.CF := cond == AST.b0)
    bld <+ (regVar bld R.OF := cond == AST.b0)
  | _ -> raise InvalidOperandSizeException

let private operandsImul bld oprSize dst src1 src2 =
  match oprSize with
  | 8<rt> | 16<rt> | 32<rt> ->
    let doubleWidth = oprSize * 2
    let t = tmpVar bld doubleWidth
    let cond = (AST.sext doubleWidth dst) != t
    bld <+ (t := AST.sext doubleWidth src1 .* AST.sext doubleWidth src2)
    bld <+ (dstAssign oprSize dst (AST.xtlo oprSize t))
    bld <+ (regVar bld R.CF := cond)
    bld <+ (regVar bld R.OF := cond)
  | 64<rt> ->
    let struct (high, low) = imul64Bit src1 src2 bld
    bld <+ (dstAssign oprSize dst low)
    let num0 = AST.num0 64<rt>
    let numF = numI64 0xFFFFFFFFFFFFFFFFL 64<rt>
    let cond = tmpVar bld 1<rt>
    bld <+ (cond := AST.ite (AST.xthi 1<rt> low) (high != numF) (high != num0))
    bld <+ (regVar bld R.CF := cond)
    bld <+ (regVar bld R.OF := cond)
  | _ -> raise InvalidOperandSizeException

let private buildMulBody ins insLen bld =
  let oprSize = getOperationSize ins
  match ins.Operands with
  | OneOperand op ->
    let src = transOprToExpr bld false ins insLen op
    oneOperandImul bld oprSize src
  | TwoOperands (o1, o2) ->
    let dst = transOprToExpr bld false ins insLen o1
    let src = transOprToExpr bld false ins insLen o2
    operandsImul bld oprSize dst dst src
  | ThreeOperands (o1, o2, o3) ->
    let dst = transOprToExpr bld false ins insLen o1
    let src1 = transOprToExpr bld false ins insLen o2
    let src2 = transOprToExpr bld false ins insLen o3
    operandsImul bld oprSize dst src1 src2
  | _ -> raise InvalidOperandException

let imul (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  buildMulBody ins insLen bld
#if !EMULATION
  bld <+ (regVar bld R.SF := undefSF)
  bld <+ (regVar bld R.ZF := undefZF)
  bld <+ (regVar bld R.AF := undefAF)
  bld <+ (regVar bld R.PF := undefPF)
#else
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let inc (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let dst = transOneOpr bld ins insLen
  let oprSize = getOperationSize ins
  let struct (t1, t2, t3) = tmpVars3 bld oprSize
  if Prefix.hasLock ins.Prefixes then bld <+ (AST.sideEffect Lock) else ()
  bld <+ (t1 := dst)
  bld <+ (t2 := AST.num1 oprSize)
  bld <+ (t3 := (t1 .+ t2))
  bld <+ (dstAssign oprSize dst t3)
  let struct (ofl, sf) = osfOnAdd t1 t2 t3 bld
  bld <+ (regVar bld R.OF := ofl)
  enumASZPFlags bld t1 t2 t3 oprSize sf
  if Prefix.hasLock ins.Prefixes then bld <+ (AST.sideEffect Unlock) else ()
#if EMULATION
  bld <+ (regVar bld R.CF := getCFLazy bld)
  setCCOperands2 bld t1 t3
  match oprSize with
  | 8<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.INCB
  | 16<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.INCW
  | 32<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.INCD
  | 64<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.INCQ
  | _ -> raise InvalidRegTypeException
#endif
  bld --!> insLen

let interrupt ins insLen bld =
  match transOneOpr bld ins insLen with
  | Num (n, _) ->
    Interrupt (BitVector.ToInt32 n)
    |> sideEffects bld ins insLen
  | _ -> raise InvalidOperandException

let private getCondOfJcc (ins: Instruction) (bld: ILowUIRBuilder) =
#if DEBUG
  if bld.RegType = 64<rt> && (getOperationSize ins) = 16<rt> then
    Terminator.impossible ()
  else ()
#endif
  match ins.Opcode with
  | Opcode.JO -> regVar bld R.OF
  | Opcode.JNO -> regVar bld R.OF == AST.b0
  | Opcode.JB -> regVar bld R.CF
  | Opcode.JNB -> regVar bld R.CF == AST.b0
  | Opcode.JZ -> regVar bld R.ZF
  | Opcode.JNZ -> regVar bld R.ZF == AST.b0
  | Opcode.JBE -> (regVar bld R.CF) .| (regVar bld R.ZF)
  | Opcode.JA -> ((regVar bld R.CF) .| (regVar bld R.ZF)) == AST.b0
  | Opcode.JS -> regVar bld R.SF
  | Opcode.JNS -> regVar bld R.SF == AST.b0
  | Opcode.JP -> regVar bld R.PF
  | Opcode.JNP -> regVar bld R.PF == AST.b0
  | Opcode.JL -> regVar bld R.SF != regVar bld R.OF
  | Opcode.JNL -> regVar bld R.SF == regVar bld R.OF
  | Opcode.JLE -> (regVar bld R.ZF) .|
                  (regVar bld R.SF != regVar bld R.OF)
  | Opcode.JG -> (regVar bld R.ZF == AST.b0) .&
                 (regVar bld R.SF == regVar bld R.OF)
  | Opcode.JCXZ -> (regVar bld R.CX) == (AST.num0 bld.RegType)
  | Opcode.JECXZ ->
    let sz = bld.RegType
    (AST.cast CastKind.ZeroExt sz (regVar bld R.ECX)) == (AST.num0 sz)
  | Opcode.JRCXZ -> (regVar bld R.RCX) == (AST.num0 bld.RegType)
  | _ -> raise InvalidOpcodeException

#if EMULATION
let private getCondOfJccLazy (ins: Instruction)
                             (bld: ILowUIRBuilder) =
#if DEBUG
  if bld.RegType = 64<rt> && (getOperationSize ins) = 16<rt> then
    Terminator.impossible ()
  else ()
#endif
  match ins.Opcode with
  | Opcode.JO -> getOFLazy bld
  | Opcode.JNO -> getOFLazy bld |> AST.not
  | Opcode.JB -> getCFLazy bld
  | Opcode.JNB -> getCFLazy bld |> AST.not
  | Opcode.JZ -> getZFLazy bld
  | Opcode.JNZ -> getZFLazy bld |> AST.not
  | Opcode.JBE ->
    let ccOp = bld.ConditionCodeOp
    match ccOp with
    | ConditionCodeOp.SUBB
    | ConditionCodeOp.SUBW
    | ConditionCodeOp.SUBD
    | ConditionCodeOp.SUBQ ->
      let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
      let regType = RegType.fromByteWidth size
      let src2 = getCCSrc1 bld regType
      let src1 = getCCDst bld regType .+ src2
      src1 .<= src2
    | _ -> (getCFLazy bld) .| (getZFLazy bld)
  | Opcode.JA -> (getCFLazy bld .| getZFLazy bld) |> AST.not
  | Opcode.JS -> getSFLazy bld
  | Opcode.JNS -> getSFLazy bld |> AST.not
  | Opcode.JP -> getPFLazy bld
  | Opcode.JNP -> getPFLazy bld |> AST.not
  | Opcode.JL ->
    let ccOp = bld.ConditionCodeOp
    match ccOp with
    | ConditionCodeOp.SUBB
    | ConditionCodeOp.SUBW
    | ConditionCodeOp.SUBD
    | ConditionCodeOp.SUBQ ->
      let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
      let regType = RegType.fromByteWidth size
      let src2 = getCCSrc1 bld regType
      let src1 = getCCDst bld regType .+ src2
      src1 ?< src2
    | _ -> getOFLazy bld != getSFLazy bld
  | Opcode.JNL -> getOFLazy bld == getSFLazy bld
  | Opcode.JLE ->
    let ccOp = bld.ConditionCodeOp
    match ccOp with
    | ConditionCodeOp.SUBB
    | ConditionCodeOp.SUBW
    | ConditionCodeOp.SUBD
    | ConditionCodeOp.SUBQ ->
      let size = 1 <<< ((int ccOp  - int ConditionCodeOp.SUBB) &&& 0b11)
      let regType = RegType.fromByteWidth size
      let src2 = getCCSrc1 bld regType
      let src1 = getCCDst bld regType .+ src2
      src1 ?<= src2
    | _ -> (getOFLazy bld != getSFLazy bld) .| (getZFLazy bld)
  | Opcode.JG ->
    (getOFLazy bld == getSFLazy bld) .& (getZFLazy bld |> AST.not)
  | Opcode.JCXZ -> regVar bld R.CX == AST.num0 bld.RegType
  | Opcode.JECXZ ->
    let sz = bld.RegType
    (AST.cast CastKind.ZeroExt sz (regVar bld R.ECX)) == (AST.num0 sz)
  | Opcode.JRCXZ -> (regVar bld R.RCX) == (AST.num0 bld.RegType)
  | _ -> raise InvalidOpcodeException
#endif

let jcc (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let pc = numU64 ins.Address bld.RegType
  let jmpTarget = pc .+ transOneOpr bld ins insLen
#if EMULATION
  let cond = getCondOfJccLazy ins bld
  setCCOp bld
  bld.ConditionCodeOp <- ConditionCodeOp.TraceStart
#else
  let cond = getCondOfJcc ins bld
#endif
  let fallThrough = pc .+ numInsLen insLen bld
  bld <+ (AST.intercjmp cond jmpTarget fallThrough)
  bld --!> insLen

let jmp (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
#if EMULATION
  setCCOp bld
  bld.ConditionCodeOp <- ConditionCodeOp.TraceStart
#endif
  let pc = numU64 (ins: Instruction).Address bld.RegType
  let struct (target, _) = transJumpTargetOpr bld false ins pc insLen
  bld <+ (AST.interjmp target InterJmpKind.Base)
  bld --!> insLen

let lahf (ins: Instruction) insLen bld =
  let t = tmpVar bld 8<rt>
  bld <!-- (ins.Address, insLen)
  let ah = regVar bld R.AH
#if EMULATION
  let cf = getCFLazy bld
  let pf = getPFLazy bld
  let af = getAFLazy bld
  let zf = getZFLazy bld
  let sf = getSFLazy bld
#else
  let cf = AST.zext 8<rt> (regVar bld R.CF)
  let pf = AST.zext 8<rt> (regVar bld R.PF)
  let af = AST.zext 8<rt> (regVar bld R.AF)
  let zf = AST.zext 8<rt> (regVar bld R.ZF)
  let sf = AST.zext 8<rt> (regVar bld R.SF)
#endif
  let cf = AST.zext 8<rt> (regVar bld R.CF)
  let pf = AST.zext 8<rt> (regVar bld R.PF)
  let af = AST.zext 8<rt> (regVar bld R.AF)
  let zf = AST.zext 8<rt> (regVar bld R.ZF)
  let sf = AST.zext 8<rt> (regVar bld R.SF)
  bld <+ (t := numI32 2 8<rt>)
  bld <+ (t := t .| cf)
  bld <+ (t := t .| (pf << numI32 2 8<rt>))
  bld <+ (t := t .| (af << numI32 4 8<rt>))
  bld <+ (t := t .| (zf << numI32 6 8<rt>))
  bld <+ (t := t .| (sf << numI32 7 8<rt>))
  bld <+ (ah := t)
  bld --!> insLen

let private unwrapLeaSrc = function
  | Load (_, _,
          BinOp (BinOpType.ADD, _, e, Num (n, _), _), _) when n.IsZero () -> e
  | Load (_, _, expr, _) -> expr
  | _ -> Terminator.impossible ()

let lea (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = transTwoOprs bld false ins insLen
  let oprSize = getOperationSize ins
  let src = unwrapLeaSrc src
  let addrSize = getEffAddrSz ins
  bld <+
    (match oprSize, addrSize with
     | 16<rt>, 16<rt> | 32<rt>, 32<rt> | 64<rt>, 64<rt> ->
       dstAssign oprSize dst src
     | 16<rt>, 32<rt> | 16<rt>, 64<rt> ->
       dstAssign oprSize dst (AST.xtlo 16<rt> src)
     | 32<rt>, 16<rt> -> dstAssign oprSize dst (AST.zext 32<rt> src)
     | 32<rt>, 64<rt> -> dstAssign oprSize dst (AST.xtlo 32<rt> src)
     | 64<rt>, 32<rt> -> dstAssign oprSize dst (AST.zext 64<rt> src)
     | _ -> raise InvalidOperandSizeException)
  bld --!> insLen

let leave (ins: Instruction) insLen bld =
  let sp = getStackPtr bld
  let bp = getBasePtr bld
  bld <!-- (ins.Address, insLen)
  bld <+ (sp := bp)
  auxPop bld.RegType bld bp
  bld --!> insLen

let private lodsBody ins bld =
  let oprSize = getOperationSize ins
  let df = regVar bld R.DF
  let si = regVar bld (if is64bit bld then R.RSI else R.ESI)
  let dst = getRegOfSize bld oprSize grpEAX
  let amount = numI32 (RegType.toByteWidth oprSize) bld.RegType
  bld <+ (dst := AST.loadLE oprSize si)
  bld <+ (si := AST.ite df (si .- amount) (si .+ amount))

let lods (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  if Prefix.hasREPZ ins.Prefixes then
    strRepeat ins insLen bld lodsBody None
  elif Prefix.hasREPNZ ins.Prefixes then Terminator.impossible ()
  else lodsBody ins bld
  bld --!> insLen

let loop (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let dst = transOneOpr bld ins insLen
  let addrSize = getEffAddrSz ins
  let pc = getInstrPtr bld
  let count, cntSize =
    if addrSize = 32<rt> then regVar bld R.ECX, 32<rt>
    elif addrSize = 64<rt> then regVar bld R.RCX, 64<rt>
    else regVar bld R.CX, 16<rt>
#if EMULATION
  let zf = getZFLazy bld
#else
  let zf = regVar bld R.ZF
#endif
  bld <+ (count := count .- AST.num1 cntSize)
  let branchCond =
    match ins.Opcode with
    | Opcode.LOOP -> count != AST.num0 cntSize
    | Opcode.LOOPE -> (zf == AST.b1) .& (count != AST.num0 cntSize)
    | Opcode.LOOPNE -> (zf == AST.b0) .& (count != AST.num0 cntSize)
    | _ -> raise InvalidOpcodeException
  let fallThrough = pc .+ numInsLen insLen bld
  let jumpTarget = if addrSize = 16<rt> then pc .& numI32 0xFFFF 32<rt>
                   else pc .+ AST.sext bld.RegType dst
  bld <+ (AST.intercjmp branchCond jumpTarget fallThrough)
  bld --!> insLen

let lzcnt ins insLen bld =
  let oprSize = getOperationSize ins
  let struct (dst, src) = transTwoOprs bld true ins insLen
  bld <!-- (ins.Address, insLen)
  let x = tmpVar bld oprSize
  let n = AST.num0 oprSize
  match oprSize with
  | 16<rt> ->
    let mask1 = numI32 0x5555 16<rt>
    let mask2 = numI32 0x3333 16<rt>
    let mask3 = numI32 0x0f0f 16<rt>
    bld <+ (x := src)
    bld <+ (x := x .| (x >> numI32 1 16<rt>))
    bld <+ (x := x .| (x >> numI32 2 16<rt>))
    bld <+ (x := x .| (x >> numI32 4 16<rt>))
    bld <+ (x := x .| (x >> numI32 8 16<rt>))
    bld <+ (x := x .- ((x >> numI32 1 16<rt>) .& mask1))
    bld <+ (x := ((x >> numI32 2 16<rt>) .& mask2) .+ (x .& mask2))
    bld <+ (x := ((x >> numI32 4 16<rt>) .+ x) .& mask3)
    bld <+ (x := x .+ (x >> numI32 8 16<rt>))
    bld <+ (dstAssign oprSize dst (numI32 16 16<rt> .- (x .& numI32 31 16<rt>)))
  | 32<rt> ->
    let mask1 = numI32 0x55555555 32<rt>
    let mask2 = numI32 0x33333333 32<rt>
    let mask3 = numI32 0x0f0f0f0f 32<rt>
    bld <+ (x := src)
    bld <+ (x := x .| (x >> numI32 1 32<rt>))
    bld <+ (x := x .| (x >> numI32 2 32<rt>))
    bld <+ (x := x .| (x >> numI32 4 32<rt>))
    bld <+ (x := x .| (x >> numI32 8 32<rt>))
    bld <+ (x := x .| (x >> numI32 16 32<rt>))
    bld <+ (x := x .- ((x >> numI32 1 32<rt>) .& mask1))
    bld <+ (x := ((x >> numI32 2 32<rt>) .& mask2) .+ (x .& mask2))
    bld <+ (x := ((x >> numI32 4 32<rt>) .+ x) .& mask3)
    bld <+ (x := x .+ (x >> numI32 8 32<rt>))
    bld <+ (x := x .+ (x >> numI32 16 32<rt>))
    bld <+ (dstAssign oprSize dst (numI32 32 32<rt> .- (x .& numI32 63 32<rt>)))
  | 64<rt> ->
    let mask1 = numU64 0x5555555555555555UL 64<rt>
    let mask2 = numU64 0x3333333333333333UL 64<rt>
    let mask3 = numU64 0x0f0f0f0f0f0f0f0fUL 64<rt>
    bld <+ (x := src)
    bld <+ (x := x .| (x >> numI32 1 64<rt>))
    bld <+ (x := x .| (x >> numI32 2 64<rt>))
    bld <+ (x := x .| (x >> numI32 4 64<rt>))
    bld <+ (x := x .| (x >> numI32 8 64<rt>))
    bld <+ (x := x .| (x >> numI32 16 64<rt>))
    bld <+ (x := x .| (x >> numI32 32 64<rt>))
    bld <+ (x := x .- ((x >> numI32 1 64<rt>) .& mask1))
    bld <+ (x := ((x >> numI32 2 64<rt>) .& mask2) .+ (x .& mask2))
    bld <+ (x := ((x >> numI32 4 64<rt>) .+ x) .& mask3)
    bld <+ (x := x .+ (x >> numI32 8 64<rt>))
    bld <+ (x := x .+ (x >> numI32 16 64<rt>))
    bld <+ (x := x .+ (x >> numI32 32 64<rt>))
    bld
    <+ (dstAssign oprSize dst (numI32 64 64<rt> .- (x .& numI32 127 64<rt>)))
  | _ -> raise InvalidOperandSizeException
  let oprSize = numI32 (RegType.toBitWidth oprSize) oprSize
  bld <+ (regVar bld R.CF := dst == oprSize)
  bld <+ (regVar bld R.ZF := dst == n)
#if !EMULATION
  bld <+ (regVar bld R.OF := undefOF)
  bld <+ (regVar bld R.SF := undefSF)
  bld <+ (regVar bld R.PF := undefPF)
  bld <+ (regVar bld R.AF := undefAF)
#else
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let mov (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = transTwoOprs bld false ins insLen
  let oprSize = getOperationSize ins
  bld <+ (dstAssign oprSize dst (AST.zext oprSize src))
  bld --!> insLen

let movbe (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = transTwoOprs bld false ins insLen
  let oprSize = getOperationSize ins
  let cnt = RegType.toByteWidth oprSize |> int
  let t = tmpVar bld oprSize
  let tmps = Array.init cnt (fun _ -> tmpVar bld 8<rt>)
  bld <+ (t := src)
  for i in 0 .. cnt - 1 do
    bld <+ (tmps[i] := AST.extract t 8<rt> (i * 8))
  done
  bld <+ (dstAssign oprSize dst (AST.revConcat (Array.rev tmps)))
  bld --!> insLen

let private movsBody ins bld =
  let oprSize = getOperationSize ins
  let df = regVar bld R.DF
  let si = regVar bld (if is64bit bld then R.RSI else R.ESI)
  let di = regVar bld (if is64bit bld then R.RDI else R.EDI)
  let amount = numI32 (RegType.toByteWidth oprSize) bld.RegType
  bld <+ (AST.loadLE oprSize di := AST.loadLE oprSize si)
  bld <+ (si := AST.ite df (si .- amount) (si .+ amount))
  bld <+ (di := AST.ite df (di .- amount) (di .+ amount))

let movs (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  if Prefix.hasREPZ ins.Prefixes then strRepeat ins insLen bld movsBody None
  else movsBody ins bld
  bld --!> insLen

let movsx (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = transTwoOprs bld false ins insLen
  let oprSize = getOperationSize ins
  bld <+ (dstAssign oprSize dst (AST.sext oprSize src))
  bld --!> insLen

let movzx (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = transTwoOprs bld false ins insLen
  let oprSize = getOperationSize ins
  bld <+ (dstAssign oprSize dst (AST.zext oprSize src))
  bld --!> insLen

let mul ins insLen bld =
  let oprSize = getOperationSize ins
  bld <!-- (ins.Address, insLen)
  match oprSize with
  | 8<rt> ->
    let dblWidth = oprSize * 2
    let src1 = AST.zext dblWidth (getRegOfSize bld oprSize grpEAX)
    let src2 = AST.zext dblWidth (transOneOpr bld ins insLen)
    let t = tmpVar bld dblWidth
    bld <+ (t := src1 .* src2)
    let cond = tmpVar bld 1<rt>
    bld <+ (regVar bld R.AX := t)
    bld <+ (cond := AST.xthi oprSize t != (AST.num0 oprSize))
    bld <+ (regVar bld R.CF := cond)
    bld <+ (regVar bld R.OF := cond)
#if !EMULATION
    bld <+ (regVar bld R.SF := undefSF)
    bld <+ (regVar bld R.ZF := undefZF)
    bld <+ (regVar bld R.AF := undefAF)
    bld <+ (regVar bld R.PF := undefPF)
#else
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  | 16<rt> | 32<rt> ->
    let dblWidth = oprSize * 2
    let edx = getRegOfSize bld oprSize grpEDX
    let eax = getRegOfSize bld oprSize grpEAX
    let src1 = AST.zext dblWidth eax
    let src2 = AST.zext dblWidth (transOneOpr bld ins insLen)
    let t = tmpVar bld dblWidth
    bld <+ (t := src1 .* src2)
    let cond = tmpVar bld 1<rt>
    bld <+ (dstAssign oprSize edx (AST.xthi oprSize t))
    bld <+ (dstAssign oprSize eax (AST.xtlo oprSize t))
    bld <+ (cond := AST.xthi oprSize t != (AST.num0 oprSize))
    bld <+ (regVar bld R.CF := cond)
    bld <+ (regVar bld R.OF := cond)
#if !EMULATION
    bld <+ (regVar bld R.SF := undefSF)
    bld <+ (regVar bld R.ZF := undefZF)
    bld <+ (regVar bld R.AF := undefAF)
    bld <+ (regVar bld R.PF := undefPF)
#else
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  | 64<rt> ->
    let rax = getRegOfSize bld oprSize grpEAX
    let rdx = getRegOfSize bld oprSize grpEDX
    let src = transOneOpr bld ins insLen
    let struct (hiRAX, loRAX, hiSrc, loSrc) = tmpVars4 bld 64<rt>
    let struct (tHigh, tLow) = tmpVars2 bld 64<rt>
    let n32 = numI32 32 64<rt>
    let mask = numI64 0xFFFFFFFFL 64<rt>
    bld <+ (hiRAX := (rax >> n32) .& mask) (* RAX[63:32] *)
    bld <+ (loRAX := rax .& mask) (* RAX[31:0] *)
    bld <+ (hiSrc := (src >> n32) .& mask) (* SRC[63:32] *)
    bld <+ (loSrc := src .& mask) (* SRC[31:0] *)
    let pHigh = hiRAX .* hiSrc
    let pMid = (hiRAX .* loSrc) .+ (loRAX .* hiSrc)
    let pLow = (loRAX .* loSrc)
    let high = pHigh .+ ((pMid .+ (pLow >> n32)) >> n32)
    let low = pLow .+ ((pMid .& mask) << n32)
    let isOverflow =
      hiRAX .* loSrc .> numI64 0xffffffff_ffffffffL 64<rt> .- loRAX .* hiSrc
    bld <+ (tHigh :=
      high .+ AST.ite isOverflow (numI64 0x100000000L 64<rt>) (AST.num0 64<rt>))
    bld <+ (tLow := low)
    bld <+ (dstAssign oprSize rdx tHigh)
    bld <+ (dstAssign oprSize rax tLow)
    let cond = tmpVar bld 1<rt>
    bld <+ (cond := tHigh != (AST.num0 oprSize))
    bld <+ (regVar bld R.CF := cond)
    bld <+ (regVar bld R.OF := cond)
#if !EMULATION
    bld <+ (regVar bld R.SF := undefSF)
    bld <+ (regVar bld R.ZF := undefZF)
    bld <+ (regVar bld R.AF := undefAF)
    bld <+ (regVar bld R.PF := undefPF)
#else
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  | _ -> raise InvalidOperandSizeException
  bld --!> insLen

let mulx ins insLen bld =
  let oprSize = getOperationSize ins
  bld <!-- (ins.Address, insLen)
  match oprSize with
  | 32<rt> ->
    let struct (dst1, dst2, src) = transThreeOprs bld false ins insLen
    let dblWidth = oprSize * 2
    let src1 = AST.zext dblWidth (getRegOfSize bld oprSize grpEDX)
    let src2 = AST.zext dblWidth src
    let t = tmpVar bld dblWidth
    bld <+ (t := src1 .* src2)
    bld <+ (dstAssign oprSize dst2 (AST.xtlo 32<rt> t))
    bld <+ (dstAssign oprSize dst1 (AST.xthi 32<rt> t))
  | 64<rt> ->
    let struct (dst1, dst2, src) = transThreeOprs bld false ins insLen
    let src1 = getRegOfSize bld oprSize grpEDX
    let struct (hiSrc1, loSrc1, hiSrc, loSrc) = tmpVars4 bld 64<rt>
    let struct (tHigh, tLow) = tmpVars2 bld 64<rt>
    let n32 = numI32 32 64<rt>
    let mask = numI64 0xFFFFFFFFL 64<rt>
    bld <+ (hiSrc1 := (src1 >> n32) .& mask) (* SRC1[63:32] *)
    bld <+ (loSrc1 := src1 .& mask) (* SRC1[31:0] *)
    bld <+ (hiSrc := (src >> n32) .& mask) (* SRC[63:32] *)
    bld <+ (loSrc := src .& mask) (* SRC[31:0] *)
    let pHigh = hiSrc1 .* hiSrc
    let pMid = (hiSrc1 .* loSrc) .+ (loSrc1 .* hiSrc)
    let pLow = (loSrc1 .* loSrc)
    let high = pHigh .+ ((pMid .+ (pLow >> n32)) >> n32)
    let low = pLow .+ ((pMid .& mask) << n32)
    let isOverflow =
      hiSrc1 .* loSrc .> numI64 0xffffffff_ffffffffL 64<rt> .- loSrc1 .* hiSrc
    bld <+ (tHigh :=
      high .+ AST.ite isOverflow (numI64 0x100000000L 64<rt>) (AST.num0 64<rt>))
    bld <+ (tLow := low)
    bld <+ (dstAssign oprSize dst2 tLow)
    bld <+ (dstAssign oprSize dst1 tHigh)
  | _ -> raise InvalidOperandSizeException
  bld --!> insLen

let neg (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let dst = transOneOpr bld ins insLen
  let oprSize = getOperationSize ins
  let t = tmpVar bld oprSize
  let zero = AST.num0 oprSize
  bld <+ (t := dst)
  bld <+ (dstAssign oprSize dst (AST.neg t))
#if EMULATION
  setCCOperands2 bld t dst
  match oprSize with
  | 8<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SUBB
  | 16<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SUBW
  | 32<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SUBD
  | 64<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SUBQ
  | _ -> raise InvalidRegTypeException
#else
  let sf = AST.xthi 1<rt> dst
  let cf = cfOnSub zero t
  let ofl = ofOnSub zero t dst
  enumEFLAGS bld zero t dst oprSize cf ofl sf
#endif
  bld --!> insLen

let nop insAddr insLen bld =
  bld <!-- (insAddr, insLen)
  bld --!> insLen

let not (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let dst = transOneOpr bld ins insLen
  let oprSize = getOperationSize ins
  bld <+ (dstAssign oprSize dst (AST.unop UnOpType.NOT dst))
  bld --!> insLen

let logOr (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = transTwoOprs bld true ins insLen
  let oprSize = getOperationSize ins
  if Prefix.hasLock ins.Prefixes then bld <+ (AST.sideEffect Lock) else ()
  bld <+ (dstAssign oprSize dst (dst .| src))
#if EMULATION
  setCCDst bld dst
  match oprSize with
  | 8<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.LOGICB
  | 16<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.LOGICW
  | 32<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.LOGICD
  | 64<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.LOGICQ
  | _ -> raise InvalidRegTypeException
#else
  let sf = AST.xthi 1<rt> dst
  bld <+ (regVar bld R.CF := AST.b0)
  bld <+ (regVar bld R.OF := AST.b0)
  enumSZPFlags bld dst oprSize sf
  bld <+ (regVar bld R.AF := undefAF)
#endif
  if Prefix.hasLock ins.Prefixes then bld <+ (AST.sideEffect Unlock) else ()
  bld --!> insLen

let pdep (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = transThreeOprs bld false ins insLen
  let oprSize = getOperationSize ins
  let struct (temp, mask, dest) = tmpVars3 bld oprSize
  let cond = tmpVar bld 1<rt>
  let k = tmpVar bld oprSize
  bld <+ (temp := src1)
  bld <+ (mask := src2)
  bld <+ (dest := AST.num0 oprSize)
  bld <+ (k := AST.num0 oprSize)
  for i in 0 .. (int oprSize) - 1 do
    bld <+ (cond := AST.extract mask 1<rt> i)
    let tempk = (temp >> k) |> AST.xtlo 1<rt>
    bld <+ (AST.extract dest 1<rt> i := AST.ite cond tempk AST.b0)
    bld <+ (k := AST.ite cond (k .+ AST.num1 oprSize) k)
  done
  bld <+ (dstAssign oprSize dst dest)
  bld --!> insLen

let pext (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src, mask) = transThreeOprs bld false ins insLen
  let oSz = getOperationSize ins
  let struct (t, k) = tmpVars2 bld oSz
  let cond = tmpVar bld 1<rt>
  bld <+ (t := AST.num0 oSz)
  bld <+ (k := AST.num0 oSz)
  for i in 0 .. (int oSz) - 1 do
    bld <+ (cond := AST.extract mask 1<rt> i)
    let extSrc = AST.zext oSz (AST.extract src 1<rt> i)
    bld <+ (t := t .| (AST.ite cond (extSrc << k) t))
    bld <+ (k := k .+ (AST.zext oSz cond))
  done
  bld <+ (dstAssign oSz dst t)
  bld --!> insLen

let pop (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let dst = transOneOpr bld ins insLen
  let oprSize = getOperationSize ins
  auxPop oprSize bld dst
  bld --!> insLen

let popa (ins: Instruction) insLen bld oprSize =
  let sp = regVar bld R.ESP
  let di = if oprSize = 32<rt> then R.EDI else R.DI
  let si = if oprSize = 32<rt> then R.ESI else R.SI
  let bp = if oprSize = 32<rt> then R.EBP else R.BP
  let bx = if oprSize = 32<rt> then R.EBX else R.BX
  let dx = if oprSize = 32<rt> then R.EDX else R.DX
  let cx = if oprSize = 32<rt> then R.ECX else R.CX
  let ax = if oprSize = 32<rt> then R.EAX else R.AX
  bld <!-- (ins.Address, insLen)
  auxPop oprSize bld (regVar bld di)
  auxPop oprSize bld (regVar bld si)
  auxPop oprSize bld (regVar bld bp)
  bld <+ (sp := sp .+ (numI32 (int oprSize / 8) 32<rt>))
  auxPop oprSize bld (regVar bld bx)
  auxPop oprSize bld (regVar bld dx)
  auxPop oprSize bld (regVar bld cx)
  auxPop oprSize bld (regVar bld ax)
  bld --!> insLen

let popcnt (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let lblLoop = label bld "Loop"
  let lblExit = label bld "Exit"
  let lblLoopCond = label bld "LoopCond"
  let struct (dst, src) = transTwoOprs bld false ins insLen
  let oprSize = getOperationSize ins
  let max = numI32 (RegType.toBitWidth oprSize) oprSize
  let struct (i, count, orgSrc) = tmpVars3 bld oprSize
  bld <+ (i := AST.num0 oprSize)
  bld <+ (count := AST.num0 oprSize)
  bld <+ (orgSrc := src)
  bld <+ (AST.lmark lblLoopCond)
  bld <+ (AST.cjmp (i .< max) (AST.jmpDest lblLoop) (AST.jmpDest lblExit))
  bld <+ (AST.lmark lblLoop)
  let cond = (AST.xtlo 1<rt> (src >> i)) == AST.b1
  bld <+ (count := AST.ite cond (count .+ AST.num1 oprSize) count)
  bld <+ (i := i .+ AST.num1 oprSize)
  bld <+ (AST.jmp (AST.jmpDest lblLoopCond))
  bld <+ (AST.lmark lblExit)
  bld <+ (dstAssign oprSize dst count)
  bld <+ (regVar bld R.OF := AST.b0)
  bld <+ (regVar bld R.SF := AST.b0)
  bld <+ (regVar bld R.ZF := orgSrc == AST.num0 oprSize)
  bld <+ (regVar bld R.AF := AST.b0)
  bld <+ (regVar bld R.CF := AST.b0)
  bld <+ (regVar bld R.PF := AST.b0)
#if EMULATION
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let popf ins insLen bld =
  let oprSize = getOperationSize ins
  let t = tmpVar bld oprSize
  bld <!-- (ins.Address, insLen)
  auxPop oprSize bld t
  bld <+ (regVar bld R.OF := AST.extract t 1<rt> 11)
  bld <+ (regVar bld R.DF := AST.extract t 1<rt> 10)
  bld <+ (regVar bld R.IF := AST.extract t 1<rt> 9)
  bld <+ (regVar bld R.TF := AST.extract t 1<rt> 8)
  bld <+ (regVar bld R.SF := AST.extract t 1<rt> 7)
  bld <+ (regVar bld R.ZF := AST.extract t 1<rt> 6)
  bld <+ (regVar bld R.AF := AST.extract t 1<rt> 4)
  bld <+ (regVar bld R.PF := AST.extract t 1<rt> 2)
  bld <+ (regVar bld R.CF := AST.xtlo 1<rt> t)
#if EMULATION
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let inline private padPushExpr oprSize opr =
  match opr with
  | Var (_, s, _, _) ->
    if isSegReg <| Register.ofRegID s then AST.zext oprSize opr
    else opr
  | Num (_) -> AST.sext oprSize opr
  | _ -> opr

let push (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let src = transOneOpr bld ins insLen
  let oprSize = getOperationSize ins
  if hasStackPtr ins then
    let t = tmpVar bld oprSize
    bld <+ (t := padPushExpr oprSize src)
    auxPush oprSize bld (padPushExpr oprSize t)
  else
    auxPush oprSize bld (padPushExpr oprSize src)
  bld --!> insLen

let pusha (ins: Instruction) insLen bld oprSize =
  let t = tmpVar bld oprSize
  let sp = if oprSize = 32<rt> then R.ESP else R.SP
  let ax = if oprSize = 32<rt> then R.EAX else R.AX
  let cx = if oprSize = 32<rt> then R.ECX else R.CX
  let dx = if oprSize = 32<rt> then R.EDX else R.DX
  let bx = if oprSize = 32<rt> then R.EBX else R.BX
  let bp = if oprSize = 32<rt> then R.EBP else R.BP
  let si = if oprSize = 32<rt> then R.ESI else R.SI
  let di = if oprSize = 32<rt> then R.EDI else R.DI
  bld <!-- (ins.Address, insLen)
  bld <+ (dstAssign oprSize t (regVar bld sp))
  auxPush oprSize bld (regVar bld ax)
  auxPush oprSize bld (regVar bld cx)
  auxPush oprSize bld (regVar bld dx)
  auxPush oprSize bld (regVar bld bx)
  auxPush oprSize bld t
  auxPush oprSize bld (regVar bld bp)
  auxPush oprSize bld (regVar bld si)
  auxPush oprSize bld (regVar bld di)
  bld --!> insLen

let pushf ins insLen bld =
  let oprSize = getOperationSize ins
  let e = AST.zext oprSize <| regVar bld R.CF
  (* We only consider 9 flags (we ignore system flags). *)
  bld <!-- (ins.Address, insLen)
#if EMULATION
  let e = e .| ((AST.zext oprSize (getPFLazy bld)) << numI32 2 oprSize)
  let e = e .| ((AST.zext oprSize (getAFLazy bld)) << numI32 4 oprSize)
  let e = e .| ((AST.zext oprSize (getZFLazy bld)) << numI32 6 oprSize)
  let e = e .| ((AST.zext oprSize (getSFLazy bld)) << numI32 7 oprSize)
  let e = e .| ((AST.zext oprSize (regVar bld R.TF)) << numI32 8 oprSize)
  let e = e .| ((AST.zext oprSize (regVar bld R.IF)) << numI32 9 oprSize)
  let e = e .| ((AST.zext oprSize (regVar bld R.DF)) << numI32 10 oprSize)
  let e = e .| ((AST.zext oprSize (getOFLazy bld)) << numI32 11 oprSize)
#else
#endif
  let e = e .| ((AST.zext oprSize (regVar bld R.PF)) << numI32 2 oprSize)
  let e = e .| ((AST.zext oprSize (regVar bld R.AF)) << numI32 4 oprSize)
  let e = e .| ((AST.zext oprSize (regVar bld R.ZF)) << numI32 6 oprSize)
  let e = e .| ((AST.zext oprSize (regVar bld R.SF)) << numI32 7 oprSize)
  let e = e .| ((AST.zext oprSize (regVar bld R.TF)) << numI32 8 oprSize)
  let e = e .| ((AST.zext oprSize (regVar bld R.IF)) << numI32 9 oprSize)
  let e = e .| ((AST.zext oprSize (regVar bld R.DF)) << numI32 10 oprSize)
  let e = e .| ((AST.zext oprSize (regVar bld R.OF)) << numI32 11 oprSize)
  let e = match oprSize with
          | 16<rt> -> e
          | 32<rt> -> e .& (numI32 0xfcffff 32<rt>)
          | 64<rt> -> e .& (numI32 0xfcffff 64<rt>)
          | _ -> raise InvalidOperandSizeException
  auxPush oprSize bld e
  bld --!> insLen

let rcl (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, count) = transTwoOprs bld true ins insLen
  let oprSize = getOperationSize ins
  let cF = regVar bld R.CF
  let oF = regVar bld R.OF
  let tmpCF = tmpVar bld 1<rt>
  let count = AST.zext oprSize count
  let tmpCnt = tmpVar bld oprSize
  let cnt =
    match oprSize with
    | 8<rt> -> (count .& numI32 0x1f oprSize) .% numI32 9 oprSize
    | 16<rt> -> (count .& numI32 0x1f oprSize) .% numI32 17 oprSize
    | 32<rt> -> count .& numI32 0x1f oprSize
    | 64<rt> -> count .& numI32 0x3f oprSize
    | _ -> raise InvalidOperandSizeException
  bld <+ (tmpCnt := cnt)
  let cond1 = tmpCnt != AST.num0 oprSize
  let cntMask = numI32 (if oprSize = 64<rt> then 0x3F else 0x1F) oprSize
  let cond2 = (count .& cntMask) == AST.num1 oprSize
#if EMULATION
  bld <+ (cF := getCFLazy bld)
#endif
  let lblRotate = label bld "Rotate"
  let lblZero = label bld "Zero"
  let lblExit = label bld "Exit"
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblRotate) (AST.jmpDest lblZero))
  bld <+ (AST.lmark lblRotate)
  bld <+ (tmpCF := AST.xthi 1<rt> dst)
  let r = (dst << AST.num1 oprSize) .+ (AST.zext oprSize cF)
  bld <+ (dstAssign oprSize dst r)
  bld <+ (cF := tmpCF)
  bld <+ (tmpCnt := tmpCnt .- AST.num1 oprSize)
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblRotate) (AST.jmpDest lblExit))
  bld <+ (AST.lmark lblZero)
  bld <+ (dstAssign oprSize dst dst)
  bld <+ (AST.lmark lblExit)
#if !EMULATION
  bld <+ (oF := AST.ite cond2 (AST.xthi 1<rt> dst <+> cF) undefOF)
#else
  bld <+ (oF := AST.ite cond2 (AST.xthi 1<rt> dst <+> cF) (getOFLazy bld))
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let rcr (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, count) = transTwoOprs bld true ins insLen
  let oprSize = getOperationSize ins
  let cF = regVar bld R.CF
  let oF = regVar bld R.OF
  let struct (tmpCF, tmpOF) = tmpVars2 bld 1<rt>
  let count = AST.zext oprSize count
  let tmpCnt = tmpVar bld oprSize
  let cnt =
    match oprSize with
    | 8<rt> -> (count .& numI32 0x1f oprSize) .% numI32 9 oprSize
    | 16<rt> -> (count .& numI32 0x1f oprSize) .% numI32 17 oprSize
    | 32<rt> -> count .& numI32 0x1f oprSize
    | 64<rt> -> count .& numI32 0x3f oprSize
    | _ -> raise InvalidOperandSizeException
  bld <+ (tmpCnt := cnt)
  let cond1 = tmpCnt != AST.num0 oprSize
  let cntMask = numI32 (if oprSize = 64<rt> then 0x3F else 0x1F) oprSize
  let cond2 = (count .& cntMask) == AST.num1 oprSize
#if EMULATION
  bld <+ (cF := getCFLazy bld)
#endif
  bld <+ (tmpOF := AST.xthi 1<rt> dst <+> cF)
  let lblRotate = label bld "Rotate"
  let lblZero = label bld "Zero"
  let lblExit = label bld "Exit"
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblRotate) (AST.jmpDest lblZero))
  bld <+ (AST.lmark lblRotate)
  bld <+ (tmpCF := AST.xtlo 1<rt> dst)
  let extCF = (AST.zext oprSize cF) << (numI32 (int oprSize - 1) oprSize)
  bld <+ (dstAssign oprSize dst ((dst >> AST.num1 oprSize) .+ extCF))
  bld <+ (cF := tmpCF)
  bld <+ (tmpCnt := tmpCnt .- AST.num1 oprSize)
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblRotate) (AST.jmpDest lblExit))
  bld <+ (AST.lmark lblZero)
  bld <+ (dstAssign oprSize dst dst)
  bld <+ (AST.lmark lblExit)
#if !EMULATION
  bld <+ (oF := AST.ite cond2 tmpOF undefOF)
#else
  bld <+ (oF := AST.ite cond2 tmpOF (getOFLazy bld))
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let rdpkru ins insLen bld =
  let lblSucc = label bld "Succ"
  let lblErr = label bld "Err"
  let oprSize = getOperationSize ins
  let ecx = regVar bld R.ECX
  let eax = getRegOfSize bld bld.RegType grpEAX
  let edx = getRegOfSize bld bld.RegType grpEDX
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.cjmp (ecx == AST.num0 oprSize)
                 (AST.jmpDest lblSucc) (AST.jmpDest lblErr))
  bld <+ (AST.lmark lblErr)
  bld <+ (AST.sideEffect (Exception "GP"))
  bld <+ (AST.lmark lblSucc)
  bld <+ (eax := AST.zext bld.RegType (regVar bld R.PKRU))
  bld <+ (edx := AST.num0 bld.RegType)
  bld --!> insLen

let retWithImm (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let t = tmpVar bld oprSize
  let sp = getStackPtr bld
  let src = transOneOpr bld ins insLen
#if EMULATION
  setCCOp bld
  bld.ConditionCodeOp <- ConditionCodeOp.TraceStart
#endif
  auxPop oprSize bld t
  bld <+ (sp := sp .+ (AST.zext oprSize src))
  bld <+ (AST.interjmp t InterJmpKind.IsRet)
  bld --!> insLen

let ret ins insLen bld =
  let oprSize = getOperationSize ins
  let t = tmpVar bld oprSize
  bld <!-- (ins.Address, insLen)
#if EMULATION
  setCCOp bld
  bld.ConditionCodeOp <- ConditionCodeOp.TraceStart
#endif
  auxPop oprSize bld t
  bld <+ (AST.interjmp t InterJmpKind.IsRet)
  bld --!> insLen

let rotate (ins: Instruction) insLen bld lfn hfn cfFn ofFn =
  bld <!-- (ins.Address, insLen)
  let struct (dst, count) = transTwoOprs bld true ins insLen
  let oprSize = getOperationSize ins
  let cF = regVar bld R.CF
  let oF = regVar bld R.OF
  let struct (orgCount, maskedCnt) = tmpVars2 bld oprSize
  let size = numI32 (RegType.toBitWidth oprSize) oprSize
  bld <+ (orgCount := AST.zext oprSize count .% (numI32 (int oprSize) oprSize))
  let countmask = if oprSize = 64<rt> then 0x3F else 0x1F
  bld <+ (maskedCnt := AST.zext oprSize count .& numI32 countmask oprSize)
  let cond1 = maskedCnt == AST.num0 oprSize
  let cond2 = maskedCnt == AST.num1 oprSize
  let value = (lfn dst orgCount) .| (hfn dst (size .- orgCount))
  bld <+ (dstAssign oprSize dst value)
#if !EMULATION
  bld <+ (cF := AST.ite cond1 cF (cfFn 1<rt> dst))
  bld <+ (oF := AST.ite cond2 (ofFn dst cF) undefOF)
#else
  genDynamicFlagsUpdate bld
  bld <+ (cF := AST.ite cond1 cF (cfFn 1<rt> dst))
  bld <+ (oF := AST.ite cond2 (ofFn dst cF) oF)
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let rol ins insLen bld =
  let ofFn dst cF = cF <+> AST.xthi 1<rt> dst
  rotate ins insLen bld (<<) (>>) AST.xtlo ofFn

let ror ins insLen bld =
  let oprSize = getOperationSize ins
  let ofFn dst _cF =
    AST.xthi 1<rt> dst <+> AST.extract dst 1<rt> ((int oprSize - 1) - 1)
  rotate ins insLen bld (>>) (<<) AST.xthi ofFn

let rorx (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src, imm) = transThreeOprs bld false ins insLen
  let oprSize = getOperationSize ins
  let y = tmpVar bld oprSize
  if oprSize = 32<rt> then
    bld <+ (y := imm .& (numI32 0x1F oprSize))
    bld <+ (dstAssign oprSize dst
      ((src >> y) .| (src << (numI32 32 oprSize .- y))))
  else (* OperandSize = 64 *)
    bld <+ (y := imm .& (numI32 0x3F oprSize))
    bld <+ (dstAssign oprSize dst
      ((src >> y) .| (src << (numI32 64 oprSize .- y))))
  bld --!> insLen

let sahf (ins: Instruction) insLen bld =
  let ah = regVar bld R.AH
  bld <!-- (ins.Address, insLen)
  bld <+ (regVar bld R.CF := AST.xtlo 1<rt> ah)
  bld <+ (regVar bld R.PF := AST.extract ah 1<rt> 2)
  bld <+ (regVar bld R.AF := AST.extract ah 1<rt> 4)
  bld <+ (regVar bld R.ZF := AST.extract ah 1<rt> 6)
  bld <+ (regVar bld R.SF := AST.extract ah 1<rt> 7)
#if EMULATION
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let shift (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = transTwoOprs bld true ins insLen
  let oprSize = getOperationSize ins
  let countMask = if is64REXW bld ins then numU32 0x3Fu oprSize
                  else numU32 0x1Fu oprSize
  let cnt = (AST.zext oprSize src) .& countMask
  let tDst = tmpVar bld oprSize
#if !EMULATION
  let n0 = AST.num0 oprSize
  let n1 = AST.num1 oprSize
  let isCntConst = isConst src
  let cond1 = cnt == n1
  let cond2 = cnt == n0
  let oF = regVar bld R.OF
  let cF = regVar bld R.CF
  let sF = regVar bld R.SF
  let zF = regVar bld R.ZF
  let tCnt = if isCntConst then cnt .- n1 else tmpVar bld oprSize
  bld <+ (tDst := dst)
#endif
  match ins.Opcode with
  | Opcode.SHL ->
#if EMULATION
    bld <+ (tDst := dst << cnt)
    setCCOperands3 bld dst cnt tDst
    bld <+ (dstAssign oprSize dst tDst)
    match oprSize with
    | 8<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SHLB
    | 16<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SHLW
    | 32<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SHLD
    | 64<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SHLQ
    | _ -> raise InvalidRegTypeException
#else
    bld <+ (dstAssign oprSize dst (tDst << cnt))
    if isCntConst then () else bld <+ (tCnt := cnt .- n1)
    bld <+ (cF := AST.ite cond2 cF (AST.xthi 1<rt> (tDst << tCnt)))
    let of1 = AST.xthi 1<rt> dst <+> cF
    bld <+ (oF := AST.ite cond1 of1 (AST.ite cond2 oF undefOF))
#endif
  | Opcode.SHR ->
#if EMULATION
    bld <+ (tDst := dst >> cnt)
    setCCOperands3 bld dst cnt tDst
    bld <+ (dstAssign oprSize dst tDst)
    match oprSize with
    | 8<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SHRB
    | 16<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SHRW
    | 32<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SHRD
    | 64<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SHRQ
    | _ -> raise InvalidRegTypeException
#else
    bld <+ (dstAssign oprSize dst (tDst >> cnt))
    if isCntConst then () else bld <+ (tCnt := cnt .- n1)
    bld <+ (cF := AST.ite cond2 cF (AST.xtlo 1<rt> (tDst >> tCnt)))
    bld <+ (oF := AST.ite cond1
                          (AST.xthi 1<rt> tDst) (AST.ite cond2 oF undefOF))
#endif
  | Opcode.SAR ->
#if EMULATION
    bld <+ (tDst := dst ?>> cnt)
    setCCOperands3 bld dst cnt tDst
    bld <+ (dstAssign oprSize dst tDst)
    match oprSize with
    | 8<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SARB
    | 16<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SARW
    | 32<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SARD
    | 64<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SARQ
    | _ -> raise InvalidRegTypeException
#else
    bld <+ (dstAssign oprSize dst (tDst ?>> cnt))
    if isCntConst then () else bld <+ (tCnt := cnt .- n1)
    bld <+ (cF := AST.ite cond2 cF (AST.xtlo 1<rt> (tDst ?>> tCnt)))
    bld <+ (oF := AST.ite cond1 AST.b0 (AST.ite cond2 oF undefOF))
#endif
  | _ -> raise InvalidOpcodeException
#if !EMULATION
  let aF = regVar bld R.AF
  bld <+ (aF := AST.ite cond2 aF undefAF)
  bld <+ (sF := AST.ite cond2 sF (AST.xthi 1<rt> dst))
  buildPF bld dst oprSize (Some cond2)
  bld <+ (zF := AST.ite cond2 zF (dst == n0))
#endif
  bld --!> insLen

let sbb (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = transTwoOprs bld true ins insLen
  let oprSize = getOperationSize ins
  let struct (t1, t2, t3, t4) = tmpVars4 bld oprSize
  let cf = regVar bld R.CF
  let sf = AST.xthi 1<rt> t4
  bld <+ (t1 := dst)
  bld <+ (t2 := AST.sext oprSize src)
#if EMULATION
  bld <+ (t3 := t2 .+ AST.zext oprSize (getCFLazy bld))
#else
  bld <+ (t3 := t2 .+ AST.zext oprSize cf)
#endif
  bld <+ (t4 := t1 .- t3)
  bld <+ (dstAssign oprSize dst t4)
  bld <+ (cf := (t1 .< t3) .| (t3 .< t2))
  bld <+ (regVar bld R.OF := ofOnSub t1 t2 t4)
  enumASZPFlags bld t1 t2 t4 oprSize sf
#if EMULATION
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let private scasBody ins bld =
  let oprSize = getOperationSize ins
  let t = tmpVar bld oprSize
  let df = regVar bld R.DF
  let x = getRegOfSize bld oprSize grpEAX
  let di = regVar bld (if is64bit bld then R.RDI else R.EDI)
  let tSrc = tmpVar bld oprSize
  let amount = numI32 (RegType.toByteWidth oprSize) bld.RegType
  let sf = AST.xthi 1<rt> t
  bld <+ (tSrc := AST.loadLE oprSize di)
  bld <+ (t := x .- tSrc)
  enumEFLAGS bld x tSrc t oprSize (cfOnSub x tSrc) (ofOnSub x tSrc t) sf
  bld <+ (di := AST.ite df (di .- amount) (di .+ amount))

let scas (ins: Instruction) insLen bld =
  let pref = ins.Prefixes
  let zfCond n = Some (regVar bld R.ZF == n)
  bld <!-- (ins.Address, insLen)
  if Prefix.hasREPZ pref then
    strRepeat ins insLen bld scasBody (zfCond AST.b0)
  elif Prefix.hasREPNZ pref then
    strRepeat ins insLen bld scasBody (zfCond AST.b1)
  else scasBody ins bld
#if EMULATION
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let private getCondOfSet (ins: Instruction) bld =
  match ins.Opcode with
  | Opcode.SETO   -> regVar bld R.OF
  | Opcode.SETNO  -> regVar bld R.OF == AST.b0
  | Opcode.SETB   -> regVar bld R.CF
  | Opcode.SETNB  -> regVar bld R.CF == AST.b0
  | Opcode.SETZ   -> regVar bld R.ZF
  | Opcode.SETNZ  -> regVar bld R.ZF == AST.b0
  | Opcode.SETBE  -> (regVar bld R.CF) .| (regVar bld R.ZF)
  | Opcode.SETA   -> ((regVar bld R.CF) .| (regVar bld R.ZF)) == AST.b0
  | Opcode.SETS   -> regVar bld R.SF
  | Opcode.SETNS  -> regVar bld R.SF == AST.b0
  | Opcode.SETP   -> regVar bld R.PF
  | Opcode.SETNP  -> regVar bld R.PF == AST.b0
  | Opcode.SETL   -> regVar bld R.SF != regVar bld R.OF
  | Opcode.SETNL  -> regVar bld R.SF == regVar bld R.OF
  | Opcode.SETLE  -> regVar bld R.ZF .|
                     (regVar bld R.SF != regVar bld R.OF)
  | Opcode.SETG   -> (regVar bld R.ZF == AST.b0) .&
                     (regVar bld R.SF == regVar bld R.OF)
  | _ -> raise InvalidOpcodeException

#if EMULATION
let private getCondOfSetLazy (ins: Instruction) bld =
  match ins.Opcode with
  | Opcode.SETO -> getOFLazy bld
  | Opcode.SETNO -> getOFLazy bld |> AST.not
  | Opcode.SETB -> getCFLazy bld
  | Opcode.SETNB -> getCFLazy bld |> AST.not
  | Opcode.SETZ -> getZFLazy bld
  | Opcode.SETNZ -> getZFLazy bld |> AST.not
  | Opcode.SETBE -> (getCFLazy bld) .| (getZFLazy bld)
  | Opcode.SETA -> (getCFLazy bld .| getZFLazy bld) |> AST.not
  | Opcode.SETS -> getSFLazy bld
  | Opcode.SETNS -> getSFLazy bld |> AST.not
  | Opcode.SETP -> getPFLazy bld
  | Opcode.SETNP -> getPFLazy bld |> AST.not
  | Opcode.SETL -> getSFLazy bld != getOFLazy bld
  | Opcode.SETNL -> getSFLazy bld == getOFLazy bld
  | Opcode.SETLE -> (getZFLazy bld) .|
                    (getSFLazy bld != getOFLazy bld)
  | Opcode.SETG   -> (getZFLazy bld |> AST.not) .&
                     (getSFLazy bld == getOFLazy bld)
  | _ -> raise InvalidOpcodeException
#endif

let setcc (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let dst = transOneOpr bld ins insLen
  let oprSize = getOperationSize ins
#if EMULATION
  let cond = getCondOfSetLazy ins bld |> AST.zext oprSize
#else
  let cond = getCondOfSet ins bld |> AST.zext oprSize
#endif
  bld <+ (dstAssign oprSize dst cond)
  bld --!> insLen

let inline shiftDblPrec (ins: Instruction) insLen bld fnDst fnSrc isShl =
  bld <!-- (ins.Address, insLen)
  let oprSz = getOperationSize ins
  let exprOprSz = numI32 (int oprSz) oprSz
  let struct (dst, src, cnt) = transThreeOprs bld false ins insLen
  let struct (count, size, tDst, tSrc) = tmpVars4 bld oprSz
  let struct (cond1, cond2, cond3) = tmpVars3 bld 1<rt>
  let org = tmpVar bld oprSz
  let cF = regVar bld R.CF
  let oF = regVar bld R.OF
  let sf = regVar bld R.SF
  let zf = regVar bld R.ZF
  let wordSize = numI32 (if REXPrefix.hasW ins.REXPrefix then 64 else 32) oprSz
  bld <+ (count := (AST.zext oprSz cnt .% wordSize))
  bld <+ (size := exprOprSz)
  bld <+ (cond1 := count == AST.num0 oprSz)
  bld <+ (cond2 := count .> size)
  bld <+ (cond3 := count == AST.num1 oprSz)
  bld <+ (org := dst)
  bld <+ (tDst := dst)
  bld <+ (tSrc := src)
  bld <+ (tDst := fnDst tDst count)
  bld <+ (tSrc := fnSrc tSrc (size .- count))
#if !EMULATION
  let undefDEST = AST.undef oprSz "DEST is undefined."
  let fallThrough = AST.ite cond2 undefDEST (tDst .| tSrc)
  bld <+ (dstAssign oprSz dst (AST.ite cond1 org fallThrough))
#else
  bld <+ (dstAssign oprSz dst (AST.ite (cond1 .| cond2) org (tDst .| tSrc)))
#endif
  let amount = if isShl then size .- count else count .- AST.num1 oprSz
#if !EMULATION
  let fallThrough = AST.ite cond2 undefCF (AST.xtlo 1<rt> (org >> amount))
  bld <+ (cF := AST.ite cond1 cF fallThrough)
#else
  bld <+ (cF := AST.ite (cond1 .| cond2) cF (AST.xtlo 1<rt> (org >> amount)))
#endif
  let overflow = AST.xthi 1<rt> (org <+> dst)
#if !EMULATION
  let aF = regVar bld R.AF
  let fallThrough = AST.ite cond2 undefOF (AST.ite cond3 overflow undefOF)
  bld <+ (oF := AST.ite cond1 oF fallThrough)
  bld <+ (aF := AST.ite cond1 aF undefAF)
#else
  bld <+ (oF := AST.ite (cond1 .| cond2) oF (AST.ite cond3 overflow oF))
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
#if !EMULATION
  bld <+ (sf := AST.ite cond1 sf (AST.ite cond2 undefSF (AST.xthi 1<rt> dst)))
  bld <+ (zf := AST.ite cond1
                        zf (AST.ite cond2 undefZF (dst == AST.num0 oprSz)))
#else
  bld <+ (sf := AST.ite (cond1 .| cond2) sf (AST.xthi 1<rt> dst))
  bld <+ (zf := AST.ite (cond1 .| cond2) zf (dst == AST.num0 oprSz))
#endif
  buildPF bld dst oprSz (Some (cond1 .| cond2))
  bld --!> insLen

let shld ins insLen bld =
  shiftDblPrec ins insLen bld (<<) (>>) true

let shrd ins insLen bld =
  shiftDblPrec ins insLen bld (>>) (<<) false

let private shiftWithoutFlags (ins: Instruction) insLen bld opFn =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = transThreeOprs bld false ins insLen
  let oprSize = getOperationSize ins
  let countMask = if is64REXW bld ins then 0x3F else 0x1F // FIXME: CS.L = 1
  let count = src2 .& (numI32 countMask oprSize)
  bld <+ (dstAssign oprSize dst (opFn src1 count))
  bld --!> insLen

let sarx ins insLen bld = shiftWithoutFlags ins insLen bld (?>>)

let shlx ins insLen bld = shiftWithoutFlags ins insLen bld (<<)

let shrx ins insLen bld = shiftWithoutFlags ins insLen bld (>>)

let setFlag (ins: Instruction) insLen bld flag =
  bld <!-- (ins.Address, insLen)
  bld <+ (regVar bld flag := AST.b1)
#if EMULATION
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let stc ins insLen bld = setFlag ins insLen bld R.CF

let std ins insLen bld = setFlag ins insLen bld R.DF

let sti ins insLen bld = setFlag ins insLen bld R.IF

let private stosBody ins bld =
  let oprSize = getOperationSize ins
  let df = regVar bld R.DF
  let di = regVar bld (if is64bit bld then R.RDI else R.EDI)
  let src = getRegOfSize bld oprSize grpEAX
  let amount = numI32 (RegType.toByteWidth oprSize) bld.RegType
  bld <+ (AST.loadLE oprSize di := src)
  bld <+ (di := AST.ite df (di .- amount) (di .+ amount))

let stos (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  if Prefix.hasREPZ ins.Prefixes then
    strRepeat ins insLen bld stosBody None
  elif Prefix.hasREPNZ ins.Prefixes then Terminator.impossible ()
  else stosBody ins bld
  bld --!> insLen

let sub (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = transTwoOprs bld true ins insLen
  let oprSize = getOperationSize ins
  if Prefix.hasLock ins.Prefixes then bld <+ (AST.sideEffect Lock) else ()
#if !EMULATION
  let isSrcConst = isConst src
  let t1 = tmpVar bld oprSize
  let t2 = if isSrcConst then src else tmpVar bld oprSize
  let t3 = tmpVar bld oprSize
  bld <+ (t1 := dst)
  if isSrcConst then () else bld <+ (t2 := src)
  bld <+ (t3 := t1 .- t2)
  bld <+ (dstAssign oprSize dst t3)
  let sf = AST.xthi 1<rt> t3
  enumEFLAGS bld t1 t2 t3 oprSize (cfOnSub t1 t2) (ofOnSub t1 t2 t3) sf
#else
  let src =
    if isConst src then src
    else
      let t = tmpVar bld oprSize
      bld <+ (t := src)
      t
  bld <+ (dstAssign oprSize dst (dst .- src))
  setCCOperands2 bld src dst
  match oprSize with
  | 8<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SUBB
  | 16<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SUBW
  | 32<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SUBD
  | 64<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.SUBQ
  | _ -> raise InvalidRegTypeException
#endif
  if Prefix.hasLock ins.Prefixes then bld <+ (AST.sideEffect Unlock) else ()
  bld --!> insLen

let test (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (src1, src2) = transTwoOprs bld false ins insLen
  let oprSize = getOperationSize ins
  let r = if src1 = src2 then src1 else src1 .& src2
#if EMULATION
  setCCDst bld r
  match oprSize with
  | 8<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.LOGICB
  | 16<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.LOGICW
  | 32<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.LOGICD
  | 64<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.LOGICQ
  | _ -> raise InvalidRegTypeException
#else
  let t = tmpVar bld oprSize
  bld <+ (t := r)
  bld <+ (regVar bld R.SF := AST.xthi 1<rt> t)
  bld <+ (regVar bld R.ZF := t == (AST.num0 oprSize))
  buildPF bld t oprSize None
  bld <+ (regVar bld R.CF := AST.b0)
  bld <+ (regVar bld R.OF := AST.b0)
  bld <+ (regVar bld R.AF := undefAF)
#endif
  bld --!> insLen

let tzcnt ins insLen bld =
  let oprSize = getOperationSize ins
  let struct (dst, src) = transTwoOprs bld true ins insLen
  bld <!-- (ins.Address, insLen)
  let lblCnt = label bld "Count"
  let lblZero = label bld "Zero"
  let lblEnd = label bld "End"
  let z = AST.num0 oprSize
  let max = numI32 (RegType.toBitWidth oprSize) oprSize
  let struct (t1, t2, res) = tmpVars3 bld oprSize
  bld <+ (t1 := src)
  bld <+ (AST.cjmp (t1 == z) (AST.jmpDest lblZero) (AST.jmpDest lblCnt))
  bld <+ (AST.lmark lblZero)
  bld <+ (dstAssign oprSize dst max)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblCnt)
  bld <+ (res := z)
  bld <+ (t1 := t1 .& (t1 .* numI32 0xFFFFFFFF oprSize))
  match oprSize with
  | 16<rt> ->
    bld <+ (t2 := t1 >> numI32 8 16<rt>)
    bld <+ (t1 := AST.ite (t2 != z) t2 t1)
    bld <+ (res := AST.ite (t2 != z) (res .+ numI32 8 16<rt>) res)
    bld <+ (t2 := t1 >> numI32 4 16<rt>)
    bld <+ (t1 := AST.ite (t2 != z) t2 t1)
    bld <+ (res := AST.ite (t2 != z) (res .+ numI32 4 16<rt>) res)
  | 32<rt> ->
    bld <+ (t2 := t1 >> numI32 16 32<rt>)
    bld <+ (t1 := AST.ite (t2 != z) t2 t1)
    bld <+ (res := AST.ite (t2 != z) (res .+ numI32 16 32<rt>) res)
    bld <+ (t2 := t1 >> numI32 8 32<rt>)
    bld <+ (t1 := AST.ite (t2 != z) t2 t1)
    bld <+ (res := AST.ite (t2 != z) (res .+ numI32 8 32<rt>) res)
    bld <+ (t2 := t1 >> numI32 4 32<rt>)
    bld <+ (t1 := AST.ite (t2 != z) t2 t1)
    bld <+ (res := AST.ite (t2 != z) (res .+ numI32 4 32<rt>) res)
  | 64<rt> ->
    bld <+ (t2 := t1 >> numI32 32 64<rt>)
    bld <+ (t1 := AST.ite (t2 != z) t2 t1)
    bld <+ (res := AST.ite (t2 != z) (res .+ numI32 32 64<rt>) res)
    bld <+ (t2 := t1 >> numI32 16 64<rt>)
    bld <+ (t1 := AST.ite (t2 != z) t2 t1)
    bld <+ (res := AST.ite (t2 != z) (res .+ numI32 16 64<rt>) res)
    bld <+ (t2 := t1 >> numI32 8 64<rt>)
    bld <+ (t1 := AST.ite (t2 != z) t2 t1)
    bld <+ (res := AST.ite (t2 != z) (res .+ numI32 8 64<rt>) res)
    bld <+ (t2 := t1 >> numI32 4 64<rt>)
    bld <+ (t1 := AST.ite (t2 != z) t2 t1)
    bld <+ (res := AST.ite (t2 != z) (res .+ numI32 4 64<rt>) res)
  | _ -> raise InvalidOperandSizeException
  let v = (res .+ ((t1 >> numI32 1 oprSize) .- (t1 >> numI32 3 oprSize)))
  bld <+ (dstAssign oprSize dst v)
  bld <+ (AST.lmark lblEnd)
  bld <+ (regVar bld R.CF := dst == max)
  bld <+ (regVar bld R.ZF := dst == z)
#if !EMULATION
  bld <+ (regVar bld R.OF := undefOF)
  bld <+ (regVar bld R.SF := undefSF)
  bld <+ (regVar bld R.PF := undefPF)
  bld <+ (regVar bld R.AF := undefAF)
#else
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let wrfsbase (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let src = transOneOpr bld ins insLen
  bld <+ (regVar bld R.FSBase := AST.zext bld.RegType src)
  bld --!> insLen

let wrgsbase (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let src = transOneOpr bld ins insLen
  bld <+ (regVar bld R.GSBase := AST.zext bld.RegType src)
  bld --!> insLen

let wrpkru ins insLen bld =
  let lblSucc = label bld "Succ"
  let lblErr = label bld "Err"
  let oprSize = getOperationSize ins
  let ecxIsZero = regVar bld R.ECX == AST.num0 oprSize
  let edxIsZero = regVar bld R.EDX == AST.num0 oprSize
  let cond = ecxIsZero .& edxIsZero
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.cjmp cond (AST.jmpDest lblSucc) (AST.jmpDest lblErr))
  bld <+ (AST.lmark lblErr)
  bld <+ (AST.sideEffect (Exception "GP"))
  bld <+ (AST.lmark lblSucc)
  bld <+ (regVar bld R.PKRU := regVar bld R.EAX)
  bld --!> insLen

let xadd (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = transTwoOprs bld false ins insLen
  let orgDst = saveOprMem bld dst
  let oprSize = getOperationSize ins
  let struct (t1, t2, t3) = tmpVars3 bld oprSize
  if Prefix.hasLock ins.Prefixes then bld <+ (AST.sideEffect Lock) else ()
  bld <+ (t1 := dst)
  bld <+ (t2 := src)
  bld <+ (t3 := t1 .+ t2)
  bld <+ (dstAssign oprSize src dst)
  bld <+ (dstAssign oprSize orgDst t3)
#if EMULATION
  setCCOperands2 bld t2 t3
  match oprSize with
  | 8<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.ADDB
  | 16<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.ADDW
  | 32<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.ADDD
  | 64<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.ADDQ
  | _ -> raise InvalidRegTypeException
#else
  let struct (ofl, sf) = osfOnAdd t1 t2 t3 bld
  enumEFLAGS bld t1 t2 t3 oprSize (cfOnAdd t1 t3) ofl sf
#endif
  if Prefix.hasLock ins.Prefixes then bld <+ (AST.sideEffect Unlock) else ()
  bld --!> insLen

let xchg (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = transTwoOprs bld false ins insLen
  let oprSize = getOperationSize ins
  if dst <> src then
    let t = tmpVar bld oprSize
    bld <+ (t := dst)
    bld <+ (dstAssign oprSize dst src)
    bld <+ (dstAssign oprSize src t)
  else
    bld <+ (dstAssign oprSize dst src)
  bld --!> insLen

let xlatb ins insLen bld =
  let addressSize = getEffAddrSz ins
  let al = AST.zext addressSize (regVar bld R.AL)
  let bx = getRegOfSize bld addressSize grpEBX
  bld <!-- (ins.Address, insLen)
  bld <+ (regVar bld R.AL := AST.loadLE 8<rt> (al .+ bx))
  bld --!> insLen

let xor (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  match ins.Operands with
  | TwoOperands (o1, o2) when o1 = o2 ->
    let dst = transOprToExpr bld false ins insLen o1
    let r = AST.num0 oprSize
    bld <+ (dstAssign oprSize dst r)
#if EMULATION
    setCCDst bld r
    bld.ConditionCodeOp <- ConditionCodeOp.XORXX
#else
    bld <+ (regVar bld R.OF := AST.b0)
    bld <+ (regVar bld R.CF := AST.b0)
    bld <+ (regVar bld R.SF := AST.b0)
    bld <+ (regVar bld R.ZF := AST.b1)
    bld <+ (regVar bld R.PF := AST.b1)
#endif
  | TwoOperands (o1, o2) ->
    let dst = transOprToExpr bld false ins insLen o1
    let src = transOprToExpr bld false ins insLen o2 |> transReg bld true
    bld <+ (dstAssign oprSize dst (dst <+> src))
#if EMULATION
    setCCDst bld dst
    match oprSize with
    | 8<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.LOGICB
    | 16<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.LOGICW
    | 32<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.LOGICD
    | 64<rt> -> bld.ConditionCodeOp <- ConditionCodeOp.LOGICQ
    | _ -> raise InvalidRegTypeException
#else
    bld <+ (regVar bld R.OF := AST.b0)
    bld <+ (regVar bld R.CF := AST.b0)
    bld <+ (regVar bld R.SF := AST.xthi 1<rt> dst)
    bld <+ (regVar bld R.ZF := dst == (AST.num0 oprSize))
    buildPF bld dst oprSize None
#endif
  | _ -> raise InvalidOperandException
#if !EMULATION
  bld <+ (regVar bld R.AF := undefAF)
#endif
  bld --!> insLen
