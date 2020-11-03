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

module internal B2R2.FrontEnd.BinLifter.Intel.Lifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.Intel
open B2R2.FrontEnd.BinLifter.Intel.RegGroup
open B2R2.FrontEnd.BinLifter.Intel.Helper

type PackType =
  | PackMask
  | PackSelect

/// XXX (cleanup required)
/// imm8 control byte operation for PCMPESTRI, PCMPESTRM, etc..
/// See Chapter 4.1 of the manual vol. 2B.
type Imm8ControlByte = {
  PackSize   : RegType
  NumElems   : uint32
  Sign       : Sign
  Agg        : Agg
  Polarity   : Polarity
  OutSelect  : OutSelect
  Len        : Length
  Ret        : Return
}
and Sign =
  | Signed
  | UnSigned
and Agg =
  | EqualAny
  | Ranges
  | EqualEach
  | EqualOrdered
and Polarity =
  | PosPolarity
  | NegPolarity
  | PosMasked
  | NegMasked
and OutSelect =
  | Least
  | Most
and Length =
  | Implicit
  | Explicit
and Return =
  | Index
  | Mask

let inline getPseudoRegVar (ctxt: TranslationContext) name pos =
  ctxt.GetPseudoRegVar (Register.toRegID name) pos

let inline getRegVar (ctxt: TranslationContext) name =
  Register.toRegID name |> ctxt.GetRegVar

let inline numU32 n t = BitVector.ofUInt32 n t |> num
let inline numI32 n t = BitVector.ofInt32 n t |> num
let inline numU64 n t = BitVector.ofUInt64 n t |> num
let inline numI64 n t = BitVector.ofInt64 n t |> num

let bvOfBaseAddr addr (ctxt: TranslationContext) = numU64 addr ctxt.WordBitSize

let bvOfInstrLen insLen (ctxt: TranslationContext) =
  numU32 insLen ctxt.WordBitSize

let bvOfOprSize = function
  | 8<rt> | 16<rt> | 32<rt> | 64<rt> | 128<rt> | 256<rt> | 512<rt> as x ->
    numI32 (int x) x
  | _ -> raise InvalidOperandSizeException

let inline is64bit (ctxt: TranslationContext) = ctxt.WordBitSize = 64<rt>
let is64REXW ctxt (ins: InsInfo) =
  is64bit ctxt && hasREXW ins.REXPrefix

let inline private addSeg ctxt expr (ins: InsInfo) =
  match getSegment ins.Prefixes with
  | Some s -> getRegVar ctxt (segRegToBase s) .+ expr
  | None -> expr

let inline private ldMem ins ctxt oprSize e =
  loadLE oprSize <| addSeg ctxt e ins

let inline private numOfAddrSz (ins: InsInfo) (ctxt: TranslationContext) n =
  let pref = ins.Prefixes
  let sz =
    if ctxt.WordBitSize = 32<rt> then if hasAddrSz pref then 16<rt> else 32<rt>
    else if hasAddrSz pref then 32<rt> else 64<rt>
  numI64 n sz

let inline private sIdx ins ctxt (r, s) =
  (getRegVar ctxt r) .* (numOfAddrSz ins ctxt (int64 s))

let transMem ins insAddr insLen ctxt b index (disp: Disp option) oprSize =
  match b, index, disp with
  | None, None, Some d ->
    numOfAddrSz ins ctxt d
    |> zExt ctxt.WordBitSize
    |> ldMem ins ctxt oprSize
  | None, Some i, Some d ->
    (sIdx ins ctxt i) .+ (numOfAddrSz ins ctxt d)
    |> zExt ctxt.WordBitSize
    |> ldMem ins ctxt oprSize
  | Some b, None, None ->
    getRegVar ctxt b
    |> zExt ctxt.WordBitSize
    |> ldMem ins ctxt oprSize
  | Some R.RIP, None, Some d -> (* RIP-relative addressing *)
    int64 insAddr + d + int64 insLen
    |> numOfAddrSz ins ctxt
    |> ldMem ins ctxt oprSize
  | Some b, None, Some d ->
    getRegVar ctxt b .+ (numOfAddrSz ins ctxt d)
    |> zExt ctxt.WordBitSize
    |> ldMem ins ctxt oprSize
  | Some b, Some i, None ->
    getRegVar ctxt b .+ (sIdx ins ctxt i)
    |> zExt ctxt.WordBitSize
    |> ldMem ins ctxt oprSize
  | Some b, Some i, Some d ->
    getRegVar ctxt b .+ (sIdx ins ctxt i) .+ (numOfAddrSz ins ctxt d)
    |> zExt ctxt.WordBitSize
    |> ldMem ins ctxt oprSize
  | _, _, _ -> raise InvalidOperandException

let transDirAddr wordSize (addr: Addr) = function
  | Absolute (_, addr, _) -> numU64 addr wordSize
  | Relative (offset) -> let offset = numI64 offset wordSize |> sExt wordSize
                         let addr = numU64 addr wordSize
                         offset .+ addr

let inline private tmpVars2 t = tmpVar t, tmpVar t
let inline private tmpVars3 t = tmpVar t, tmpVar t, tmpVar t
let inline private tmpVars4 t = tmpVar t, tmpVar t, tmpVar t, tmpVar t

let inline private getOperationSize (i: InsInfo) = i.InsSize.OperationSize
let inline private getEffAddrSz (i: InsInfo) = i.InsSize.MemSize.EffAddrSize
let inline private (<!) (builder: StmtBuilder) (s) = builder.Append (s)

let getCFlagOnAdd e1 _ r = lt r e1
let getCFlagOnSub e1 e2 _ = lt e1 e2

let getOFlagOnAdd e1 e2 r =
  let e1High = extractHigh 1<rt> e1
  let e2High = extractHigh 1<rt> e2
  let rHigh = extractHigh 1<rt> r
  (e1High == e2High) .& (e1High <+> rHigh)

let getOFlagOnSub e1 e2 r =
  extractHigh 1<rt> (binop BinOpType.AND (e1 <+> e2) (e1 <+> r))

let buildAF ctxt e1 e2 r size =
  let t1 = r <+> e1
  let t2 = t1 <+> e2
  let t3 = binop BinOpType.SHL (num1 size) (numU32 4ul size)
  let t4 = t2 .& t3
  getRegVar ctxt R.AF := t4 == t3

let buildPF ctxt r size cond builder =
  let t1, t2 = tmpVars2 size
  let s2 = r <+> (binop BinOpType.SHR r (zExt size (numU32 4ul 8<rt>)))
  let s4 = s2 <+> (binop BinOpType.SHR t1 (zExt size (numU32 2ul 8<rt>)))
  let s5 = s4 <+> (binop BinOpType.SHR t2 (zExt size (num1 8<rt>)))
  builder <! (t1 := s2)
  builder <! (t2 := s4)
  let pf = unop UnOpType.NOT (extractLow 1<rt> s5)
  match cond with
  | None -> builder <! (getRegVar ctxt R.PF := pf)
  | Some condFn -> builder <! (getRegVar ctxt R.PF := condFn pf)

let enumSZPFlags ctxt r size builder =
  builder <! (getRegVar ctxt R.SF := extractHigh 1<rt> r)
  builder <! (getRegVar ctxt R.ZF := r == (num0 size))
  buildPF ctxt r size None builder

let enumASZPFlags ctxt e1 e2 r size builder =
  builder <! (buildAF ctxt e1 e2 r size)
  enumSZPFlags ctxt r size builder

let enumEFLAGS ctxt e1 e2 e3 size cfGetter ofGetter builder =
  builder <! (getRegVar ctxt R.CF := cfGetter e1 e2 e3)
  builder <! (getRegVar ctxt R.OF := ofGetter e1 e2 e3)
  builder <! (buildAF ctxt e1 e2 e3 size)
  builder <! (getRegVar ctxt R.SF := extractHigh 1<rt> e3)
  builder <! (getRegVar ctxt R.ZF := e3 == (num0 size))
  buildPF ctxt e3 size None builder

let undefCF = unDef 1<rt> "CF is undefined."
let undefOF = unDef 1<rt> "OF is undefined."
let undefAF = unDef 1<rt> "AF is undefined."
let undefSF = unDef 1<rt> "SF is undefined."
let undefZF = unDef 1<rt> "ZF is undefined."
let undefPF = unDef 1<rt> "PF is undefined."
let undefC0 = unDef 1<rt> "C0 is undefined."
let undefC1 = unDef 1<rt> "C1 is undefined."
let undefC2 = unDef 1<rt> "C2 is undefined."
let undefC3 = unDef 1<rt> "C3 is undefined."

let allEFLAGSUndefined ctxt builder =
  builder <! (getRegVar ctxt R.CF := undefCF)
  builder <! (getRegVar ctxt R.OF := undefOF)
  builder <! (getRegVar ctxt R.AF := undefAF)
  builder <! (getRegVar ctxt R.SF := undefSF)
  builder <! (getRegVar ctxt R.ZF := undefZF)
  builder <! (getRegVar ctxt R.PF := undefPF)

let allCFlagsUndefined ctxt builder =
  builder <! (getRegVar ctxt R.FSWC0 := undefC0)
  builder <! (getRegVar ctxt R.FSWC1 := undefC1)
  builder <! (getRegVar ctxt R.FSWC2 := undefC2)
  builder <! (getRegVar ctxt R.FSWC3 := undefC3)

let cflagsUndefined023 ctxt builder =
  builder <! (getRegVar ctxt R.FSWC0 := undefC0)
  builder <! (getRegVar ctxt R.FSWC2 := undefC2)
  builder <! (getRegVar ctxt R.FSWC3 := undefC3)

let transOprToExpr ins insAddr insLen ctxt = function
  | OprReg reg -> getRegVar ctxt reg
  | OprMem (b, index, disp, oprSize) ->
    transMem ins insAddr insLen ctxt b index disp oprSize
  | OprImm imm -> getOperationSize ins |> BitVector.ofInt64 imm |> num
  | OprDirAddr jumpTarget ->
    transDirAddr ctxt.WordBitSize insAddr jumpTarget
  | _ -> Utils.impossible ()

let getMemExpr128 expr =
  match expr with
  | Load (e, 128<rt>, expr, _, _) ->
    AST.load e 64<rt> (expr .+ numI32 8 (AST.typeOf expr)),
    AST.load e 64<rt> expr
  | _ -> raise InvalidOperandException

let getMemExpr256 expr =
  match expr with
  | Load (e, 256<rt>, expr, _, _) ->
    AST.load e 64<rt> (expr .+ numI32 24 (AST.typeOf expr)),
    AST.load e 64<rt> (expr .+ numI32 16 (AST.typeOf expr)),
    AST.load e 64<rt> (expr .+ numI32 8 (AST.typeOf expr)),
    AST.load e 64<rt> expr
  | _ -> raise InvalidOperandException

let getMemExpr512 expr =
  match expr with
  | Load (e, 512<rt>, expr, _, _) ->
    AST.load e 64<rt> (expr .+ numI32 56 (AST.typeOf expr)),
    AST.load e 64<rt> (expr .+ numI32 48 (AST.typeOf expr)),
    AST.load e 64<rt> (expr .+ numI32 40 (AST.typeOf expr)),
    AST.load e 64<rt> (expr .+ numI32 32 (AST.typeOf expr)),
    AST.load e 64<rt> (expr .+ numI32 24 (AST.typeOf expr)),
    AST.load e 64<rt> (expr .+ numI32 16 (AST.typeOf expr)),
    AST.load e 64<rt> (expr .+ numI32 8 (AST.typeOf expr)),
    AST.load e 64<rt> expr
  | _ -> raise InvalidOperandException

let getMemExprs expr =
  match expr with
  | Load (e, 128<rt>, expr, _, _) ->
    [ AST.load e 64<rt> expr;
      AST.load e 64<rt> (expr .+ numI32 8 (AST.typeOf expr)) ]
  | Load (e, 256<rt>, expr, _, _) ->
    [ AST.load e 64<rt> expr
      AST.load e 64<rt> (expr .+ numI32 8 (AST.typeOf expr));
      AST.load e 64<rt> (expr .+ numI32 16 (AST.typeOf expr));
      AST.load e 64<rt> (expr .+ numI32 24 (AST.typeOf expr)); ]
  | _ -> raise InvalidOperandException

let getPseudoRegVar128 ctxt r =
  getPseudoRegVar ctxt r 2, getPseudoRegVar ctxt r 1

let getPseudoRegVar256 ctxt r =
  getPseudoRegVar ctxt r 4, getPseudoRegVar ctxt r 3,
  getPseudoRegVar ctxt r 2, getPseudoRegVar ctxt r 1

let getPseudoRegVar512 ctxt r =
  getPseudoRegVar ctxt r 8, getPseudoRegVar ctxt r 7,
  getPseudoRegVar ctxt r 6, getPseudoRegVar ctxt r 5,
  getPseudoRegVar ctxt r 4, getPseudoRegVar ctxt r 3,
  getPseudoRegVar ctxt r 2, getPseudoRegVar ctxt r 1

let getPseudoRegVars ctxt r =
  match Register.getKind r with
  | Register.Kind.XMM -> [ getPseudoRegVar ctxt r 1; getPseudoRegVar ctxt r 2 ]
  | Register.Kind.YMM -> [ getPseudoRegVar ctxt r 1; getPseudoRegVar ctxt r 2
                           getPseudoRegVar ctxt r 3; getPseudoRegVar ctxt r 4 ]
  | _ -> raise InvalidOperandException

let getFPUPseudoRegVars ctxt r =
  getPseudoRegVar ctxt r 2, getPseudoRegVar ctxt r 1

let transOprToExprVec ins insAddr insLen ctxt opr =
  match opr with
  | OprReg r -> getPseudoRegVars ctxt r
  | OprMem (b, index, disp, oprSize) ->
    transMem ins insAddr insLen ctxt b index disp oprSize |> getMemExprs
  | OprImm imm -> [ getOperationSize ins |> BitVector.ofInt64 imm |> num ]
  | _ -> raise InvalidOperandException

let transOprToExpr32 ins insAddr insLen ctxt opr =
  match opr with
  | OprReg r when Register.toRegType r > 64<rt> ->
    getPseudoRegVar ctxt r 1 |> extractLow 32<rt>
  | OprReg r -> getRegVar ctxt r
  | OprMem (b, index, disp, 32<rt>) ->
    transMem ins insAddr insLen ctxt b index disp 32<rt>
  | _ -> raise InvalidOperandException

let transOprToExpr64 ins insAddr insLen ctxt opr =
  match opr with
  | OprReg r when Register.toRegType r > 64<rt> -> getPseudoRegVar ctxt r 1
  | OprReg r -> getRegVar ctxt r
  | OprMem (b, index, disp, 64<rt>) ->
    transMem ins insAddr insLen ctxt b index disp 64<rt>
  | _ -> raise InvalidOperandException

let transOprToExpr128 ins insAddr insLen ctxt opr =
  match opr with
  | OprReg r -> getPseudoRegVar128 ctxt r
  | OprMem (b, index, disp, oprSize) ->
    transMem ins insAddr insLen ctxt b index disp oprSize |> getMemExpr128
  | _ -> raise InvalidOperandException

let transOprToExpr256 ins insAddr insLen ctxt opr =
  match opr with
  | OprReg r -> getPseudoRegVar256 ctxt r
  | OprMem (b, index, disp, oprSize) ->
    transMem ins insAddr insLen ctxt b index disp oprSize |> getMemExpr256
  | _ -> raise InvalidOperandException

let transOprToExpr512 ins insAddr insLen ctxt opr =
  match opr with
  | OprReg r -> getPseudoRegVar512 ctxt r
  | OprMem (b, index, disp, oprSize) ->
    transMem ins insAddr insLen ctxt b index disp oprSize |> getMemExpr512
  | _ -> raise InvalidOperandException

let transOprToFloat80 ins insAddr insLen ctxt opr =
  match opr with
  | OprReg r when Register.toRegType r = 80<rt> -> getRegVar ctxt r
  | OprReg r ->
    getRegVar ctxt r |> cast CastKind.FloatExt 80<rt>
  | OprMem (b, index, disp, 80<rt>) ->
    transMem ins insAddr insLen ctxt b index disp 80<rt>
  | OprMem (b, index, disp, len) ->
    transMem ins insAddr insLen ctxt b index disp len
    |> cast CastKind.FloatExt 80<rt>
  | _ -> raise InvalidOperandException

let getOneOpr (ins: InsInfo) =
  match ins.Operands with
  | OneOperand opr -> opr
  | _ -> raise InvalidOperandException

let getTwoOprs (ins: InsInfo) =
  match ins.Operands with
  | TwoOperands (o1, o2) -> o1, o2
  | _ -> raise InvalidOperandException

let getThreeOprs (ins: InsInfo) =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) -> o1, o2, o3
  | _ -> raise InvalidOperandException

let getFourOprs (ins: InsInfo) =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) -> o1, o2, o3, o4
  | _ -> raise InvalidOperandException

let transOneOpr ins insAddr insLen ctxt opr =
  transOprToExpr ins insAddr insLen ctxt opr

let transTwoOprs ins insAddr insLen ctxt (o1, o2) =
  transOprToExpr ins insAddr insLen ctxt o1,
  transOprToExpr ins insAddr insLen ctxt o2

let transThreeOprs ins insAddr insLen ctxt (o1, o2, o3) =
  transOprToExpr ins insAddr insLen ctxt o1,
  transOprToExpr ins insAddr insLen ctxt o2,
  transOprToExpr ins insAddr insLen ctxt o3

let castNum newType = function
  | Num num -> Num <| BitVector.cast num newType
  | _ -> raise InvalidOperandException

let getInstrPtr ctxt = getRegVar ctxt (if is64bit ctxt then R.RIP else R.EIP)
let getStackPtr ctxt = getRegVar ctxt (if is64bit ctxt then R.RSP else R.ESP)
let getBasePtr ctxt = getRegVar ctxt (if is64bit ctxt then R.RBP else R.EBP)
let getRegOfSize ctxt oprSize (regGrp: Register []) =
  getRegVar ctxt <| match oprSize with
                    | 8<rt> -> regGrp.[0]
                    | 16<rt> -> regGrp.[1]
                    | 32<rt> -> regGrp.[2]
                    | 64<rt> -> regGrp.[3]
                    | _ -> raise InvalidOperandSizeException

let getFstOperand = function
  | OneOperand o -> o
  | TwoOperands (o, _) -> o
  | ThreeOperands (o, _, _) -> o
  | FourOperands (o, _, _, _) -> o
  | _ -> raise InvalidOperandException

let getSndOperand = function
  | TwoOperands (_, o) -> o
  | ThreeOperands (_, o, _) -> o
  | FourOperands (_, o, _, _) -> o
  | _ -> raise InvalidOperandException

/// This is an Intel-specific assignment to a destination operand.
/// Unlike typical assignments, this function performs zero-padding when
/// necessary (See Intel Manual 3.4.1.1).
/// In 64-bit mode, operand size determines the number of valid bits.
/// 64-bit operands generate a 64-bit result in the destination general-purpose
/// register. 32-bit operands generate a 32-bit result, zero-extended to a
/// 64-bit result in the destination general-purpose register. 8-bit and 16-bit
/// operands generate 8-bit or 16-bit result. The upper 56 or 48 bits
/// (respectively) of the destination general-purpose register are not modified.
let dstAssign oprSize dst src =
  match oprSize with
  | 8<rt> | 16<rt> -> dst := src (* No extension for 8- and 16-bit operands *)
  | _ -> let dst = unwrapExpr dst
         let dstOrigSz = dst |> AST.typeOf
         let oprBitSize = RegType.toBitWidth oprSize
         let dstBitSize = RegType.toBitWidth dstOrigSz
         if dstBitSize > oprBitSize then dst := zExt dstOrigSz src
         elif dstBitSize = oprBitSize then dst := src
         else raise InvalidOperandSizeException

let getDividend ctxt = function
  | 8<rt> -> getRegVar ctxt R.AX
  | 16<rt> -> concat (getRegVar ctxt R.DX) (getRegVar ctxt R.AX)
  | 32<rt> -> concat (getRegVar ctxt R.EDX) (getRegVar ctxt R.EAX)
  | 64<rt> -> concat (getRegVar ctxt R.RDX) (getRegVar ctxt R.RAX)
  | _ -> raise InvalidOperandSizeException

let maxNum = function
  | 8<rt> -> BitVector.maxNum8
  | 16<rt> -> BitVector.maxNum16
  | 32<rt> -> BitVector.maxNum32
  | 64<rt> -> BitVector.maxNum64
  | _ -> raise InvalidOperandSizeException

let packCmp cmp typ e1 e2 oprSize unitWidth builder =
  let maxIdx = RegType.toBitWidth oprSize / unitWidth
  let unitSz = RegType.fromBitWidth unitWidth
  let t1, t2 = tmpVars2 oprSize
  let tmps = [| for _ in 1 .. maxIdx -> tmpVar unitSz |]
  let getSrc s idx = extract s unitSz (unitWidth * idx)
  let packMask e1 e2 unitSz cmp =
    let zero = num0 unitSz
    let maxVal = num <| maxNum unitSz
    ite (cmp e1 e2) maxVal zero
  let getDst idx =
    let src1 = getSrc t1 idx
    let src2 = getSrc t2 idx
    match typ with
    | PackMask -> packMask src1 src2 unitSz cmp
    | PackSelect -> ite (cmp src1 src2) src1 src2
  builder <! (t1 := e1)
  builder <! (t2 := e2)
  Array.iteri (fun i e -> builder <! (e := getDst i)) tmps
  concatExprs tmps

let inline padPushExpr oprSize opr =
  let isSegReg = function
    | Register.CS | Register.DS | Register.SS | Register.ES | Register.FS
    | Register.GS -> true
    | _ -> false
  match opr with
  | Var (_, s, _, _) ->
    if isSegReg <| Register.ofRegID s then zExt oprSize opr else opr
  | Num (_) -> sExt oprSize opr
  | _ -> opr

let inline getStackWidth wordSize oprSize =
  numI32 (RegType.toByteWidth oprSize) wordSize

let auxPush oprSize ctxt expr builder =
  let t = tmpVar oprSize
  let sp = getStackPtr ctxt
  builder <! (t := expr)
  builder <! (sp := sp .- (getStackWidth ctxt.WordBitSize oprSize))
  builder <! (loadLE oprSize sp := t)

let auxPop oprSize ctxt dst builder =
  let sp = getStackPtr ctxt
  let isSegReg = function
    | Register.GS | Register.FS | Register.DS
    | Register.SS | Register.ES -> true
    | _ -> false
  let handleSegPop oprSize = function
    | Var (_, x, _, _) when isSegReg <| Register.ofRegID x -> 16<rt>
    | _ -> oprSize
  builder <! (dst := loadLE (handleSegPop oprSize dst) sp)
  builder <! (sp := sp .+ (getStackWidth ctxt.WordBitSize oprSize))

let getCondOfJcc (ins: InsInfo) (ctxt: TranslationContext) oprSize =
  if ctxt.WordBitSize = 64<rt> && oprSize = 16<rt>
  then raise InvalidOn64Exception
  match ins.Opcode with
  | Opcode.JO -> getRegVar ctxt R.OF
  | Opcode.JNO -> getRegVar ctxt R.OF == b0
  | Opcode.JB -> getRegVar ctxt R.CF
  | Opcode.JNB -> getRegVar ctxt R.CF == b0
  | Opcode.JZ -> getRegVar ctxt R.ZF
  | Opcode.JNZ -> getRegVar ctxt R.ZF == b0
  | Opcode.JBE -> (getRegVar ctxt R.CF) .| (getRegVar ctxt R.ZF)
  | Opcode.JA -> ((getRegVar ctxt R.CF) .| (getRegVar ctxt R.ZF)) == b0
  | Opcode.JS -> getRegVar ctxt R.SF
  | Opcode.JNS -> getRegVar ctxt R.SF == b0
  | Opcode.JP -> getRegVar ctxt R.PF
  | Opcode.JNP -> getRegVar ctxt R.PF == b0
  | Opcode.JL -> getRegVar ctxt R.SF != getRegVar ctxt R.OF
  | Opcode.JNL -> getRegVar ctxt R.SF == getRegVar ctxt R.OF
  | Opcode.JLE -> (getRegVar ctxt R.ZF) .|
                  (getRegVar ctxt R.SF != getRegVar ctxt R.OF)
  | Opcode.JG -> (getRegVar ctxt R.ZF == b0) .&
                 (getRegVar ctxt R.SF == getRegVar ctxt R.OF)
  | Opcode.JCXZ -> (getRegVar ctxt R.CX) == (num0 ctxt.WordBitSize)
  | Opcode.JECXZ ->
    let addrSize = ctxt.WordBitSize
    (cast CastKind.ZeroExt addrSize (getRegVar ctxt R.ECX)) == (num0 addrSize)
  | Opcode.JRCXZ -> (getRegVar ctxt R.RCX) == (num0 ctxt.WordBitSize)
  | _ -> raise InvalidOpcodeException

let getCondOfSet (ins: InsInfo) ctxt =
  match ins.Opcode with
  | Opcode.SETO   -> getRegVar ctxt R.OF
  | Opcode.SETNO  -> getRegVar ctxt R.OF == b0
  | Opcode.SETB   -> getRegVar ctxt R.CF
  | Opcode.SETNB  -> getRegVar ctxt R.CF == b0
  | Opcode.SETZ   -> getRegVar ctxt R.ZF
  | Opcode.SETNZ  -> getRegVar ctxt R.ZF == b0
  | Opcode.SETBE  -> (getRegVar ctxt R.CF) .| (getRegVar ctxt R.ZF)
  | Opcode.SETA   -> ((getRegVar ctxt R.CF) .| (getRegVar ctxt R.ZF)) == b0
  | Opcode.SETS   -> getRegVar ctxt R.SF
  | Opcode.SETNS  -> getRegVar ctxt R.SF == b0
  | Opcode.SETP   -> getRegVar ctxt R.PF
  | Opcode.SETNP  -> getRegVar ctxt R.PF == b0
  | Opcode.SETL   -> getRegVar ctxt R.SF != getRegVar ctxt R.OF
  | Opcode.SETNL  -> getRegVar ctxt R.SF == getRegVar ctxt R.OF
  | Opcode.SETLE  -> getRegVar ctxt R.ZF .|
                     (getRegVar ctxt R.SF != getRegVar ctxt R.OF)
  | Opcode.SETG   -> (getRegVar ctxt R.ZF == b0) .&
                     (getRegVar ctxt R.SF == getRegVar ctxt R.OF)
  | _ -> raise InvalidOpcodeException

let convertSrc = function
  | Load (_, _, expr, _, _) -> expr
  | _ -> failwith "Does not apply.(convert SRC)"

let getCondOfCMov (ins: InsInfo) ctxt =
  match ins.Opcode with
  | Opcode.CMOVO   -> getRegVar ctxt R.OF
  | Opcode.CMOVNO  -> getRegVar ctxt R.OF == b0
  | Opcode.CMOVB   -> getRegVar ctxt R.CF
  | Opcode.CMOVAE  -> getRegVar ctxt R.CF == b0
  | Opcode.CMOVZ   -> getRegVar ctxt R.ZF
  | Opcode.CMOVNZ  -> getRegVar ctxt R.ZF == b0
  | Opcode.CMOVBE  -> (getRegVar ctxt R.CF) .| (getRegVar ctxt R.ZF)
  | Opcode.CMOVA   -> ((getRegVar ctxt R.CF) .| (getRegVar ctxt R.ZF)) == b0
  | Opcode.CMOVS   -> getRegVar ctxt R.SF
  | Opcode.CMOVNS  -> getRegVar ctxt R.SF == b0
  | Opcode.CMOVP   -> getRegVar ctxt R.PF
  | Opcode.CMOVNP  -> getRegVar ctxt R.PF == b0
  | Opcode.CMOVL   -> getRegVar ctxt R.SF != getRegVar ctxt R.OF
  | Opcode.CMOVGE  -> getRegVar ctxt R.SF == getRegVar ctxt R.OF
  | Opcode.CMOVLE  -> getRegVar ctxt R.ZF .|
                      (getRegVar ctxt R.SF != getRegVar ctxt R.OF)
  | Opcode.CMOVG   -> getRegVar ctxt R.ZF == b0 .&
                      (getRegVar ctxt R.SF == getRegVar ctxt R.OF)
  | _ -> raise InvalidOpcodeException

let movqRegToReg ctxt r1 r2 builder =
  match Register.getKind r1, Register.getKind r2 with
  | Register.Kind.XMM, Register.Kind.XMM ->
    builder <! (getPseudoRegVar ctxt r1 1 := getPseudoRegVar ctxt r2 1 )
    builder <! (getPseudoRegVar ctxt r1 2 := num0 64<rt>)
  | Register.Kind.XMM, _ ->
    builder <! (getPseudoRegVar ctxt r1 1 := getRegVar ctxt r2)
    builder <! (getPseudoRegVar ctxt r1 2 := num0 64<rt>)
  | Register.Kind.GP, Register.Kind.XMM ->
    builder <! (getRegVar ctxt r1 := getPseudoRegVar ctxt r2 1)
  | Register.Kind.MMX, Register.Kind.MMX
  | Register.Kind.MMX, Register.Kind.GP
  | Register.Kind.GP, Register.Kind.MMX ->
    builder <! (getRegVar ctxt r1 := getRegVar ctxt r2)
  | _, _ -> failwith "Not a Register to Register."

let movqRegToMem ctxt dst r builder =
  match Register.getKind r with
  | Register.Kind.XMM -> builder <! (dst := getPseudoRegVar ctxt r 1)
  | Register.Kind.MMX -> builder <! (dst := getRegVar ctxt r)
  | _ -> failwith "Not a Register to Memory."

let movqMemToReg ctxt src r builder =
  match Register.getKind r with
  | Register.Kind.XMM ->
    builder <! (getPseudoRegVar ctxt r 1 := src)
    builder <! (getPseudoRegVar ctxt r 2 := num0 64<rt>)
  | Register.Kind.MMX -> builder <! (getRegVar ctxt r := src)
  | _ -> failwith "Not a Memory to Register."

let movdRegToReg ctxt r1 r2 builder =
  let tmp = tmpVar 32<rt>
  match Register.getKind r1, Register.getKind r2 with
  | Register.Kind.XMM, _ ->
    builder <! (getPseudoRegVar ctxt r1 1 := zExt 64<rt> (getRegVar ctxt r2))
    builder <! (getPseudoRegVar ctxt r1 2 := num0 64<rt>)
  | _, Register.Kind.XMM ->
    builder <! (tmp := extractLow 32<rt> (getPseudoRegVar ctxt r2 1))
    builder <! (dstAssign 32<rt> (getRegVar ctxt r1) tmp)
  | Register.Kind.MMX, _ ->
    builder <! (getRegVar ctxt r1 := zExt 64<rt> (getRegVar ctxt r2))
  | _, Register.Kind.MMX ->
    builder <! (tmp := extractLow 32<rt> (getRegVar ctxt r2))
    builder <! (dstAssign 32<rt> (getRegVar ctxt r1) tmp)
  | _, _ -> failwith "Not a Register to Register."

let movdRegToMem ctxt dst r builder =
  match Register.getKind r with
  | Register.Kind.XMM ->
    builder <! (dst := extractLow 32<rt> (getPseudoRegVar ctxt r 1))
  | Register.Kind.MMX -> builder <! (dst := extractLow 32<rt> (getRegVar ctxt r))
  | _ -> failwith "Not a Register to Memory."

let movdMemToReg ctxt src r builder =
  match Register.getKind r with
  | Register.Kind.XMM ->
    builder <! (getPseudoRegVar ctxt r 1 := zExt 64<rt> src)
    builder <! (getPseudoRegVar ctxt r 2 := num0 64<rt>)
  | Register.Kind.MMX -> builder <! (getRegVar ctxt r := zExt 64<rt> src)
  | _ -> failwith "Not a Register to Memory."

let maskOffset offset oprSize =
  let offset = zExt oprSize offset
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
  let offset = zExt oprSize offset
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
    let addrOffset = zExt effAddrSz addrOffset
    extractLow 1<rt> ((AST.load e t (expr .+ addrOffset)) >> bitOffset)
  | _ -> if isVar bitBase
         then extractLow 1<rt> (bitBase >> maskOffset bitOffset oprSize)
         else raise InvalidExprException

let getMask oprSize =
  match oprSize with
  | 8<rt> -> numI64 0xffL oprSize
  | 16<rt> -> numI64 0xffffL oprSize
  | 32<rt> -> numI64 0xffffffffL oprSize
  | 64<rt> -> numI64 0xffffffffffffffffL oprSize
  | _ -> raise InvalidOperandSizeException

let setBit ins bitBase bitOffset oprSize setValue =
  match bitBase with
  | Load (e, t, expr, _, _) ->
    let effAddrSz = getEffAddrSz ins
    let addrOffset, bitOffset = calculateOffset bitOffset oprSize
    let addrOffset = zExt effAddrSz addrOffset
    let mask = setValue << bitOffset
    let loadMem = AST.load e t (expr .+ addrOffset)
    loadMem := (loadMem .& (getMask oprSize .- mask)) .| mask
  | _ -> if isVar bitBase
         then let mask = setValue << maskOffset bitOffset oprSize
              bitBase := (bitBase .& (getMask oprSize .- mask)) .| mask
         else raise InvalidExprException

let isFPUStackReg = function
  | R.ST0 | R.ST1 | R.ST2 | R.ST3 | R.ST4 | R.ST5 | R.ST6 | R.ST7  -> true
  | _ -> false

let isFPUStackOpr = function
  | OprReg r when isFPUStackReg r -> true
  | _ -> false

let checkC1Flag ctxt builder topTagReg =
  let c1 = getRegVar ctxt R.FSWC1
  let tagV = getRegVar ctxt topTagReg
  let rc = extract (getRegVar ctxt R.FCW) 2<rt> 10
  builder <! (c1 := ite (rc == numI32 2 2<rt>) b1 b0)
  builder <! (c1 := ite (tagV == numI32 3 2<rt>) b0 c1)

let checkFPUOnLoad ctxt builder =
  let top = getRegVar ctxt R.FTOP
  let c1Flag = getRegVar ctxt R.FSWC1
  let cond1, cond2 = tmpVars2 1<rt>
  builder <! (cond1 := top == num0 3<rt>)
  builder <! (cond2 := (getRegVar ctxt R.FTW0 .+ num1 2<rt>) != num0 2<rt>)
  builder <! (c1Flag := ite (cond1 .& cond2) b1 b0)
  builder <! (getRegVar ctxt R.FSWC0 := undefC0)
  builder <! (getRegVar ctxt R.FSWC2 := undefC2)
  builder <! (getRegVar ctxt R.FSWC3 := undefC3)
  builder <! (top := top .- num1 3<rt>)

let fpuRegValue ctxt reg =
  let stb, sta = getFPUPseudoRegVars ctxt reg
  concat stb sta

let assignFPUReg reg expr80 ctxt builder =
  let stb, sta = getFPUPseudoRegVars ctxt reg
  builder <! (sta := extractLow 64<rt> expr80)
  builder <! (stb := extractHigh 16<rt> expr80)

let getTagValueOnLoad ctxt builder =
  let tmp = tmpVar 2<rt>
  let st0 = fpuRegValue ctxt R.ST0
  let exponent = extract st0 11<rt> 52
  let zero = num0 11<rt>
  let max = BitVector.unsignedMax 11<rt> |> num
  let cond0 = (extractLow 63<rt> st0) == num0 63<rt>
  let condSpecial = (exponent == zero) .| (exponent == max)
  builder <! (tmp := num0 2<rt>)
  builder <! (tmp := ite condSpecial (BitVector.ofInt32 2 2<rt> |> num) tmp)
  builder <! (tmp := ite cond0 (num1 2<rt>) tmp)
  tmp

let updateTagWordOnLoad ctxt builder =
  let top = getRegVar ctxt R.FTOP
  let tagWord = getRegVar ctxt R.FTW
  let top16, mask, shifter, tagValue16 = tmpVars4 16<rt>
  let tagValue = getTagValueOnLoad ctxt builder
  let value3 = BitVector.ofInt32 3 16<rt> |> num
  builder <! (top16 := cast CastKind.ZeroExt 16<rt> top)
  builder <! (shifter := (BitVector.ofInt32 2 16<rt> |> num) .* top16)
  builder <! (tagValue16 := cast CastKind.ZeroExt 16<rt> tagValue)
  builder <! (tagValue16 := (tagValue16 << shifter))
  builder <! (mask := value3 << shifter)
  builder <! (tagWord := tagWord .& (not mask))
  builder <! (tagWord := tagWord .| tagValue16)

let updateTagWordOnPop ctxt builder =
  let top = getRegVar ctxt R.FTOP
  let tagWord = getRegVar ctxt R.FTW
  let top16, mask, shifter, tagValue16 = tmpVars4 16<rt>
  let value3 = BitVector.ofInt32 3 16<rt> |> num
  builder <! (top16 := cast CastKind.ZeroExt 16<rt> top)
  builder <! (shifter := (BitVector.ofInt32 2 16<rt> |> num) .* top16)
  builder <! (mask := value3 << shifter)
  builder <! (tagWord := tagWord .| mask)

let shiftFPUStackDown ctxt builder =
  assignFPUReg R.ST7 (fpuRegValue ctxt R.ST6) ctxt builder
  assignFPUReg R.ST6 (fpuRegValue ctxt R.ST5) ctxt builder
  assignFPUReg R.ST5 (fpuRegValue ctxt R.ST4) ctxt builder
  assignFPUReg R.ST4 (fpuRegValue ctxt R.ST3) ctxt builder
  assignFPUReg R.ST3 (fpuRegValue ctxt R.ST2) ctxt builder
  assignFPUReg R.ST2 (fpuRegValue ctxt R.ST1) ctxt builder
  assignFPUReg R.ST1 (fpuRegValue ctxt R.ST0) ctxt builder

let popFPUStack ctxt builder =
  let top = getRegVar ctxt R.FTOP
  let c1Flag = getRegVar ctxt R.FSWC1
  let cond1, cond2 = tmpVars2 1<rt>
  assignFPUReg R.ST0 (fpuRegValue ctxt R.ST1) ctxt builder
  assignFPUReg R.ST1 (fpuRegValue ctxt R.ST2) ctxt builder
  assignFPUReg R.ST2 (fpuRegValue ctxt R.ST3) ctxt builder
  assignFPUReg R.ST3 (fpuRegValue ctxt R.ST4) ctxt builder
  assignFPUReg R.ST4 (fpuRegValue ctxt R.ST5) ctxt builder
  assignFPUReg R.ST5 (fpuRegValue ctxt R.ST6) ctxt builder
  assignFPUReg R.ST6 (fpuRegValue ctxt R.ST7) ctxt builder
  assignFPUReg R.ST7 (num0 80<rt>) ctxt builder
  builder <! (cond1 := top == num0 3<rt>)
  builder <! (cond2 := (getRegVar ctxt R.FTW7 .+ num1 2<rt>) == num0 2<rt>)
  builder <! (c1Flag := ite (cond1 .& cond2) (b0) (c1Flag))
  builder <! (getRegVar ctxt R.FSWC0 := undefC0)
  builder <! (getRegVar ctxt R.FSWC2 := undefC2)
  builder <! (getRegVar ctxt R.FSWC3 := undefC3)
  updateTagWordOnPop ctxt builder
  builder <! (top := top .+ num1 3<rt>)

let rec subPackedByte opFn s1 s2 (tDstArr: Expr []) oprSz sepSz idx sz builder =
  let tS1, tS2 = tmpVars2 sepSz
  if sz = 0 then ()
  else builder <! (tS1 := extract s1 sepSz (idx * 8))
       builder <! (tS2 := extract s2 sepSz (idx * 8))
       builder <! (tDstArr.[int idx] := opFn tS1 tS2)
       subPackedByte opFn s1 s2 tDstArr oprSz sepSz (idx + 1) (sz - 1) builder

let getPsubbExpr src1 src2 oprSize builder =
  let size = RegType.toByteWidth oprSize
  let tDstArr = [| for _ in 1 .. size -> tmpVar 8<rt> |]
  subPackedByte (.-) src1 src2 tDstArr oprSize 8<rt> 0 size builder
  concatExprs tDstArr

let oneOperandImul ins insAddr insLen ctxt oprSize builder =
  let src = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  let sF = getRegVar ctxt R.SF
  let shiftNum = RegType.toBitWidth oprSize
  let mulSize = RegType.double oprSize
  let t = tmpVar mulSize
  let cond = sExt mulSize (extractLow oprSize t) == t
  match oprSize with
  | 8<rt> ->
    builder <! (t := sExt mulSize (getRegVar ctxt R.AL) .* sExt mulSize src)
    builder <! (dstAssign oprSize (getRegVar ctxt R.AX) t)
  | 16<rt> | 32<rt> | 64<rt> ->
    let r1 = getRegOfSize ctxt oprSize GrpEDX
    let r2 = getRegOfSize ctxt oprSize GrpEAX
    builder <! (t := sExt mulSize r2 .* sExt mulSize src)
    builder <! (dstAssign oprSize r1 (extractHigh oprSize t))
    builder <! (dstAssign oprSize r2 (extractLow oprSize t))
  | _ -> raise InvalidOperandSizeException
  builder <! (sF := extract t 1<rt> (shiftNum - 1))
  builder <! (getRegVar ctxt R.CF := cond == b0)
  builder <! (getRegVar ctxt R.OF := cond == b0)

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
  let t = tmpVar doubleWidth
  let cond = (sExt doubleWidth dst) != t
  builder <! (t := sExt doubleWidth src1 .* sExt doubleWidth src2)
  builder <! (dstAssign oprSize dst (extractLow oprSize t))
  builder <! (getRegVar ctxt R.SF := extractHigh 1<rt> dst)
  builder <! (getRegVar ctxt R.CF := cond)
  builder <! (getRegVar ctxt R.OF := cond)

let startMark insAddr insLen builder =
  builder <! (ISMark (insAddr, insLen))

let endMark insAddr insLen builder =
  builder <! (IEMark (insAddr + uint64 insLen)); builder

let getPcmpstrInfo opCode (imm: Expr) =
  let immByte = match imm with
                | Num n -> BitVector.getValue n
                | _ -> raise InvalidExprException
  let agg = match (immByte >>> 2) &&& 3I with
            | v when v = 0I -> EqualAny
            | v when v = 1I -> Ranges
            | v when v = 2I -> EqualEach
            | v when v = 3I -> EqualOrdered
            | _ -> failwith "Invalid value"
  let pol = match (immByte >>> 4) &&& 3I with
            | v when v = 0I -> PosPolarity
            | v when v = 1I -> NegPolarity
            | v when v = 2I -> PosMasked
            | v when v = 3I -> NegMasked
            | _ -> failwith "Invalid value"
  let size, nElem =
    if immByte &&& 1I = 0I then 8<rt>, 16u else 16<rt>, 8u
  let len, ret =
    match opCode with
    | Opcode.PCMPISTRI | Opcode.VPCMPISTRI -> Implicit, Index
    | Opcode.PCMPESTRI | Opcode.VPCMPESTRI -> Explicit, Index
    | Opcode.PCMPISTRM | Opcode.VPCMPISTRM -> Implicit, Mask
    | Opcode.PCMPESTRM | Opcode.VPCMPESTRM -> Explicit, Mask
    | _ -> raise InvalidOpcodeException
  {
    PackSize = size
    NumElems = nElem
    Sign = if (immByte >>> 1) &&& 1I = 0I then UnSigned else Signed
    Agg = agg
    Polarity = pol
    OutSelect = if (immByte >>> 6) &&& 1I = 0I then Least else Most
    Len = len
    Ret = ret
  }

let getIntRes2 e ctrInfo (booRes: Expr []) =
  let elemSz = RegType.fromBitWidth <| int ctrInfo.NumElems
  let elemCnt = ctrInfo.NumElems |> int
  match ctrInfo.Polarity with
  | PosPolarity | PosMasked -> e
  | NegPolarity -> numI32 -1 elemSz <+> e
  | NegMasked ->
    List.fold (fun acc i ->
      let e1 = e .& numI32 (pown 2 i) elemSz
      let e2 = (AST.not e) .& numI32 (pown 2 i) elemSz
      (ite (booRes.[i]) e2 e1) :: acc) [] [0 .. elemCnt - 1]
    |> List.reduce (.|)

let rec genOutput ctrl e acc i =
  let elemSz = RegType.fromBitWidth <| int ctrl.NumElems
  let isSmallOut = ctrl.OutSelect = Least
  let e' = e >> numI32 i elemSz
  let next = if isSmallOut then i - 1 else i + 1
  let cond = if isSmallOut then i = 0 else i = int ctrl.NumElems - 1
  if cond then ite (extractLow 1<rt> e') (numI32 i elemSz) acc
  else genOutput ctrl e (ite (extractLow 1<rt> e') (numI32 i elemSz) acc) next

let implicitValidCheck ctrl srcB srcA builder =
  let unitWidth = RegType.toBitWidth ctrl.PackSize
  let tmps = [| for _ in 1u .. ctrl.NumElems -> tmpVar 1<rt> |]
  let getSrc idx e = extract e ctrl.PackSize (unitWidth * idx)
  let rec getValue idx =
    if idx = int ctrl.NumElems then ()
    else
      let half = int ctrl.NumElems / 2
      let e, amount = if idx < half then srcA, idx else srcB, idx - half
      let v e = tmps.[idx - 1] .& (getSrc amount e != num0 ctrl.PackSize)
      builder <! (tmps.[idx] := v e)
      getValue (idx + 1)
  builder <! (tmps.[0] := b1 .& (getSrc 0 srcA != num0 ctrl.PackSize))
  getValue 1
  tmps

let explicitValidCheck ctrl reg rSz builder =
  let tmps = [| for _ in 1u .. ctrl.NumElems -> tmpVar 1<rt> |]
  let checkNum = numU32 ctrl.NumElems rSz
  let rec getValue idx =
    let v = lt (numU32 idx rSz) (ite (lt checkNum reg) checkNum reg)
    if idx = ctrl.NumElems then ()
    else builder <! (tmps.[int idx] := v)
         getValue (idx + 1u)
  getValue 0u
  tmps

let genValidCheck ins insAddr insLen ctxt ctrl e1 e2 builder =
  let src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt e1
  let src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt e2
  match ctrl.Len with
  | Implicit -> implicitValidCheck ctrl src1B src1A builder,
                implicitValidCheck ctrl src2B src2A builder
  | Explicit ->
    let regSize, ax, dx =
      if hasREXW ins.REXPrefix
      then 64<rt>, getRegVar ctxt R.RAX, getRegVar ctxt R.RDX
      else 32<rt>, getRegVar ctxt R.EAX, getRegVar ctxt R.EDX
    explicitValidCheck ctrl ax regSize builder,
    explicitValidCheck ctrl dx regSize builder

let genBoolRes ins insAddr insLen // XXX
               ctrl ctxt e1 e2 (ck1: Expr []) (ck2: Expr []) j i cmp =
  let src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt e1
  let src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt e2
  let elemSz = RegType.fromBitWidth <| int ctrl.NumElems
  let getSrc s idx =
    let unitWidth = RegType.toBitWidth ctrl.PackSize
    let amount = unitWidth * idx
    let amount = if amount < 64 then amount else amount - 64
    extract s ctrl.PackSize amount
  let b =
    let e1 = if j < int ctrl.NumElems / 2 then src1A else src1B
    let e2 = if i < int ctrl.NumElems / 2 then src2A else src2B
    (ite (cmp (getSrc e1 j) (getSrc e2 i)) (num1 elemSz) (num0 elemSz))
  match ctrl.Agg with
  | EqualAny | Ranges ->
    ite (AST.not ck1.[j] .& AST.not ck2.[i]) (num0 elemSz)
      (ite (AST.not ck1.[j] .| AST.not ck2.[i]) (num0 elemSz) b)
  | EqualEach ->
    ite (AST.not ck1.[i] .& AST.not ck2.[i]) (num1 elemSz)
      (ite (AST.not ck1.[i] .| AST.not ck2.[i]) (num0 elemSz) b)
  | EqualOrdered ->
    ite (AST.not ck1.[j] .& AST.not ck2.[i]) (num1 elemSz)
      (ite (AST.not ck1.[j] .& ck2.[i]) (num1 elemSz)
        (ite (ck1.[j] .& AST.not ck2.[i]) (num0 elemSz) b))

let sideEffects insAddr insLen name =
  let builder = new StmtBuilder (4)
  startMark insAddr insLen builder
  builder <! (SideEffect name)
  endMark insAddr insLen builder

let strRepeat (ctxt: TranslationContext) body cond insAddr insLen builder =
  let lblExit = lblSymbol "Exit"
  let lblCont = lblSymbol "Continue"
  let lblNext = lblSymbol "Next"
  let n0 = num0 ctxt.WordBitSize
  let cx = getRegVar ctxt (if is64bit ctxt then R.RCX else R.ECX)
  let pc = getInstrPtr ctxt
  let cinstAddr = bvOfBaseAddr insAddr ctxt
  let ninstAddr = cinstAddr .+ bvOfInstrLen insLen ctxt
  builder <! (CJmp (cx == n0, Name lblExit, Name lblCont))
  builder <! (LMark lblCont)
  body ()
  builder <! (cx := cx .- num1 ctxt.WordBitSize)
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

(* FIXME: To replace dstAssign *)
let r128to256 = function
  | OprReg R.XMM0 -> R.YMM0
  | OprReg R.XMM1 -> R.YMM1
  | OprReg R.XMM2 -> R.YMM2
  | OprReg R.XMM3 -> R.YMM3
  | OprReg R.XMM4 -> R.YMM4
  | OprReg R.XMM5 -> R.YMM5
  | OprReg R.XMM6 -> R.YMM6
  | OprReg R.XMM7 -> R.YMM7
  | OprReg R.XMM8 -> R.YMM8
  | OprReg R.XMM9 -> R.YMM9
  | OprReg R.XMM10 -> R.YMM10
  | OprReg R.XMM11 -> R.YMM11
  | OprReg R.XMM12 -> R.YMM12
  | OprReg R.XMM13 -> R.YMM13
  | OprReg R.XMM14 -> R.YMM14
  | OprReg R.XMM15 -> R.YMM15
  | _ -> raise InvalidOperandException

let r128to512 = function
  | OprReg R.XMM0 -> R.ZMM0
  | OprReg R.XMM1 -> R.ZMM1
  | OprReg R.XMM2 -> R.ZMM2
  | OprReg R.XMM3 -> R.ZMM3
  | OprReg R.XMM4 -> R.ZMM4
  | OprReg R.XMM5 -> R.ZMM5
  | OprReg R.XMM6 -> R.ZMM6
  | OprReg R.XMM7 -> R.ZMM7
  | OprReg R.XMM8 -> R.ZMM8
  | OprReg R.XMM9 -> R.ZMM9
  | OprReg R.XMM10 -> R.ZMM10
  | OprReg R.XMM11 -> R.ZMM11
  | OprReg R.XMM12 -> R.ZMM12
  | OprReg R.XMM13 -> R.ZMM13
  | OprReg R.XMM14 -> R.ZMM14
  | OprReg R.XMM15 -> R.ZMM15
  | _ -> raise InvalidOperandException

let r256to512 = function
  | OprReg R.YMM0 -> R.ZMM0
  | OprReg R.YMM1 -> R.ZMM1
  | OprReg R.YMM2 -> R.ZMM2
  | OprReg R.YMM3 -> R.ZMM3
  | OprReg R.YMM4 -> R.ZMM4
  | OprReg R.YMM5 -> R.ZMM5
  | OprReg R.YMM6 -> R.ZMM6
  | OprReg R.YMM7 -> R.ZMM7
  | OprReg R.YMM8 -> R.ZMM8
  | OprReg R.YMM9 -> R.ZMM9
  | OprReg R.YMM10 -> R.ZMM10
  | OprReg R.YMM11 -> R.ZMM11
  | OprReg R.YMM12 -> R.ZMM12
  | OprReg R.YMM13 -> R.ZMM13
  | OprReg R.YMM14 -> R.ZMM14
  | OprReg R.YMM15 -> R.ZMM15
  | _ -> raise InvalidOperandException

let fillZeroHigh ins ctxt dst builder =
  match getOperationSize ins with
  | 128<rt> ->
    let dst = r128to256 dst
    let dstC, dstD = getPseudoRegVar ctxt dst 3, getPseudoRegVar ctxt dst 4
    let n0 = num0 64<rt>
    builder <! (dstC := n0)
    builder <! (dstD := n0)
  | 256<rt> ->
    let dst = r256to512 dst
    let dstE, dstF, dstG, dstH =
      getPseudoRegVar ctxt dst 3, getPseudoRegVar ctxt dst 4,
      getPseudoRegVar ctxt dst 5, getPseudoRegVar ctxt dst 6
    let n0 = num0 64<rt>
    builder <! (dstE := n0)
    builder <! (dstF := n0)
    builder <! (dstG := n0)
    builder <! (dstH := n0)
  | _ -> raise InvalidOperandSizeException

let fillZeroHigh128 ctxt dst builder =
  let dst = r128to256 dst
  let dstC, dstD = getPseudoRegVar ctxt dst 3, getPseudoRegVar ctxt dst 4
  let n0 = num0 64<rt>
  builder <! (dstC := n0)
  builder <! (dstD := n0)

let fillZeroHigh256 ctxt dst builder =
  let dst = r256to512 dst
  let dstE, dstF, dstG, dstH =
    getPseudoRegVar ctxt dst 3, getPseudoRegVar ctxt dst 4,
    getPseudoRegVar ctxt dst 5, getPseudoRegVar ctxt dst 6
  let n0 = num0 64<rt>
  builder <! (dstE := n0)
  builder <! (dstF := n0)
  builder <! (dstG := n0)
  builder <! (dstH := n0)

let fillZeroFromVLToMaxVL ctxt dst vl maxVl builder =
  let n0 = num0 64<rt>
  match maxVl, vl with
  | 512, 128 ->
    let dst = r128to512 dst
    let dstC, dstD, dstE, dstF, dstG, dstH =
      getPseudoRegVar ctxt dst 3, getPseudoRegVar ctxt dst 4,
      getPseudoRegVar ctxt dst 5, getPseudoRegVar ctxt dst 6,
      getPseudoRegVar ctxt dst 7, getPseudoRegVar ctxt dst 8
    builder <! (dstC := n0)
    builder <! (dstD := n0)
    builder <! (dstE := n0)
    builder <! (dstF := n0)
    builder <! (dstG := n0)
    builder <! (dstH := n0)
  | 512, 256 ->
    let dst = r256to512 dst
    let dstE, dstF, dstG, dstH =
      getPseudoRegVar ctxt dst 5, getPseudoRegVar ctxt dst 6,
      getPseudoRegVar ctxt dst 7, getPseudoRegVar ctxt dst 8
    builder <! (dstE := n0)
    builder <! (dstF := n0)
    builder <! (dstG := n0)
    builder <! (dstH := n0)
  | _ -> failwith "Invalid MAX Vector Length"

let saturateSignedWordToSignedByte expr =
  let checkMin = slt expr (numI32 -128 16<rt>)
  let checkMax = sgt expr (numI32 127 16<rt>)
  let minNum = numI32 -128 8<rt>
  let maxNum = numI32 127 8<rt>
  ite checkMin minNum (ite checkMax maxNum (extractLow 8<rt> expr))

let saturateSignedDwordToSignedWord expr =
  let checkMin = slt expr (numI32 -32768 32<rt>)
  let checkMax = sgt expr (numI32 32767 32<rt>)
  let minNum = numI32 -32768 16<rt>
  let maxNum = numI32 32767 16<rt>
  ite checkMin minNum (ite checkMax maxNum (extractLow 16<rt> expr))

let saturateSignedWordToUnsignedByte expr =
  let checkMin = slt expr (numI32 0 16<rt>)
  let checkMax = sgt expr (numI32 255 16<rt>)
  let minNum = numU32 0u 8<rt>
  let maxNum = numU32 0xffu 8<rt>
  ite checkMin minNum (ite checkMax maxNum (extractLow 8<rt> expr))

let saturateToSignedByte expr =
  let checkMin = slt expr (numI32 -128 8<rt>)
  let checkMax = sgt expr (numI32 127 8<rt>)
  let minNum = numI32 -128 8<rt>
  let maxNum = numI32 127 8<rt>
  ite checkMin minNum (ite checkMax maxNum expr)

let saturateToSignedWord expr =
  let checkMin = slt expr (numI32 -32768 16<rt>)
  let checkMax = sgt expr (numI32 32767 16<rt>)
  let minNum = numI32 -32768 16<rt>
  let maxNum = numI32 32767 16<rt>
  ite checkMin minNum (ite checkMax maxNum expr)

let saturateToUnsignedByte expr =
  let checkMin = lt expr (numU32 0u 8<rt>)
  let checkMax = gt expr (numU32 0xffu 8<rt>)
  let minNum = numU32 0u 8<rt>
  let maxNum = numU32 0xffu 8<rt>
  ite checkMin minNum (ite checkMax maxNum expr)

let saturateToUnsignedWord expr =
  let checkMin = lt expr (numU32 0u 16<rt>)
  let checkMax = gt expr (numU32 0xffffu 16<rt>)
  let minNum = numU32 0u 16<rt>
  let maxNum = numU32 0xffu 16<rt>
  ite checkMin minNum (ite checkMax maxNum expr)

let buildMove ins insAddr insLen ctxt bufSize =
  let builder = new StmtBuilder (bufSize)
  let dst, src = getTwoOprs ins
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  match oprSize with
  | 32<rt> | 64<rt> ->
    let dst, src = transTwoOprs ins insAddr insLen ctxt (dst, src)
    builder <! (dst := src)
  | 128<rt> | 256<rt> | 512<rt> ->
    let dst = transOprToExprVec ins insAddr insLen ctxt dst
    let src = transOprToExprVec ins insAddr insLen ctxt src
    List.iter2 (fun d s -> builder <! (d := s)) dst src
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let makeSrc builder packSize packNum src =
  let tSrc = Array.init packNum (fun _ -> tmpVar packSize)
  for i in 0 .. packNum - 1 do
    builder <! (tSrc.[i] := extract src packSize (i * (int packSize)))
  tSrc

let buildPackedInstrTwoOprs ins insAddr insLen ctxt packSz opFn bufSz dst src =
  let builder = new StmtBuilder (bufSz)
  let oprSize = getOperationSize ins
  let packNum = oprSize / packSz
  let makeSrc = makeSrc builder packSz
  startMark insAddr insLen builder
  match oprSize with
  | 64<rt> ->
    let dst, src = transTwoOprs ins insAddr insLen ctxt (dst, src)
    let src1 = makeSrc packNum dst
    let src2 = match src with
               | Load (_, rt, _, _, _) -> makeSrc (rt / packSz) src
               | _ -> makeSrc packNum src
    builder <! (dst := opFn oprSize src1 src2 |> concatExprs)
  | 128<rt> ->
    let packNum = packNum / (oprSize / 64<rt>)
    let srcAppend src =
      let src = transOprToExprVec ins insAddr insLen ctxt src
      List.map (makeSrc packNum) src |> List.fold Array.append [||]
    let tSrc = opFn oprSize (srcAppend dst) (srcAppend src)
    let dst = transOprToExprVec ins insAddr insLen ctxt dst
    let packNum = Array.length tSrc / List.length dst
    let assign idx dst =
      builder <! (dst := Array.sub tSrc (packNum * idx) packNum |> concatExprs)
    List.iteri assign dst
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let buildPackedInstrThreeOprs ins iAddr iLen ctxt packSz opFn bufSz dst s1 s2 =
  let builder = new StmtBuilder (bufSz)
  let oprSize = getOperationSize ins
  let packNum = oprSize / packSz
  let makeSrc = makeSrc builder packSz
  startMark iAddr iLen builder
  match oprSize with
  | 64<rt> ->
    let dst, src1, src2 = transThreeOprs ins iAddr iLen ctxt (dst, s1, s2)
    let src1 = makeSrc packNum src1
    let src2 = makeSrc packNum src2
    builder <! (dst := opFn oprSize src1 src2 |> concatExprs)
  | 128<rt> | 256<rt> ->
    let packNum = packNum / (oprSize / 64<rt>)
    let dst = transOprToExprVec ins iAddr iLen ctxt dst
    let srcAppend src =
      let src = transOprToExprVec ins iAddr iLen ctxt src
      List.map (makeSrc packNum) src |> List.fold Array.append [||]
    let tSrc = opFn oprSize (srcAppend s1) (srcAppend s2)
    let assign idx dst =
      builder <! (dst := Array.sub tSrc (packNum * idx) packNum |> concatExprs)
    List.iteri assign dst
  | _ -> raise InvalidOperandSizeException
  endMark iAddr iLen builder

let buildPackedInstr ins insAddr insLen ctxt packSz opFn bufSz =
  match ins.Operands with
  | TwoOperands (o1, o2) ->
    buildPackedInstrTwoOprs ins insAddr insLen ctxt packSz opFn bufSz o1 o2
  | ThreeOperands (o1, o2, o3) ->
    buildPackedInstrThreeOprs ins insAddr insLen ctxt packSz opFn bufSz o1 o2 o3
  | _ -> raise InvalidOperandException

let getTwoSrcOperands = function
  | TwoOperands (op1, op2) -> (op1, op2)
  | ThreeOperands (_op1, op2, op3) -> (op2, op3)
  | _ -> raise InvalidOperandException

let handleScalarFPOp ins insAddr insLen ctxt sz op =
  let builder = new StmtBuilder(8)
  let _dst2, dst1 =
    ins.Operands |> getFstOperand |> transOprToExpr128 ins insAddr insLen ctxt
  let src1, src2 = getTwoSrcOperands ins.Operands
  let src1 = transOprToExpr64 ins insAddr insLen ctxt src1
  let src2 =
    if sz = 32<rt> then transOprToExpr32 ins insAddr insLen ctxt src2
    else transOprToExpr64 ins insAddr insLen ctxt src2
  let dst1, src1 =
    if sz = 32<rt> then extractLow 32<rt> dst1, extractLow 32<rt> src1
    else dst1, src1
  let t1, t2, t3 = tmpVars3 sz
  startMark insAddr insLen builder
  builder <! (t1 := src1)
  builder <! (t2 := src2)
  builder <! (t3 := op t1 t2)
  builder <! (dst1 := t3)
  endMark insAddr insLen builder


let bcdToInt intgr bcd builder =
  let getDigit startPos =
    extract bcd 4<rt> startPos |> sExt 64<rt>
  let n num =
    numI64 num 64<rt>
  builder <! (intgr := num0 64<rt>)
  builder <! (intgr := intgr .+ getDigit 0)
  builder <! (intgr := intgr .+ (getDigit 4 .* n 10L))
  builder <! (intgr := intgr .+ (getDigit 8 .* n 100L))
  builder <! (intgr := intgr .+ (getDigit 12 .* n 1000L))
  builder <! (intgr := intgr .+ (getDigit 16 .* n 10000L))
  builder <! (intgr := intgr .+ (getDigit 20 .* n 100000L))
  builder <! (intgr := intgr .+ (getDigit 24 .* n 1000000L))
  builder <! (intgr := intgr .+ (getDigit 28 .* n 10000000L))
  builder <! (intgr := intgr .+ (getDigit 32 .* n 100000000L))
  builder <! (intgr := intgr .+ (getDigit 36 .* n 1000000000L))
  builder <! (intgr := intgr .+ (getDigit 40 .* n 10000000000L))
  builder <! (intgr := intgr .+ (getDigit 44 .* n 100000000000L))
  builder <! (intgr := intgr .+ (getDigit 48 .* n 1000000000000L))
  builder <! (intgr := intgr .+ (getDigit 52 .* n 10000000000000L))
  builder <! (intgr := intgr .+ (getDigit 56 .* n 100000000000000L))
  builder <! (intgr := intgr .+ (getDigit 60 .* n 1000000000000000L))
  builder <! (intgr := intgr .+ (getDigit 64 .* n 10000000000000000L))
  builder <! (intgr := intgr .+ (getDigit 68 .* n 100000000000000000L))

let intTobcd bcd intgr builder =
  let n10 = numI32 10 64<rt>
  let mod10 = intgr .% n10 |> zExt 4<rt>
  let digitAt startPos = extract bcd 4<rt> startPos
  let rec doAssign startPos =
    if startPos >= 72 then ()
    else
      builder <! (digitAt startPos := mod10)
      builder <! (intgr := intgr ./ n10)
      doAssign (startPos + 4)
  doAssign 0

/// A module for all x86-IR translation functions
let aaa ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let oprSize = getOperationSize ins
  let al = getRegVar ctxt R.AL
  let af = getRegVar ctxt R.AF
  let ax = getRegVar ctxt R.AX
  let cf = getRegVar ctxt R.CF
  let alAnd0f = al .& numI32 0x0f 8<rt>
  let cond1 = gt alAnd0f (numI32 9 8<rt>)
  let cond2 = af == b1
  let cond = tmpVar 1<rt>
  startMark insAddr insLen builder
  if oprSize = 64<rt> then ()
  else
    builder <! (cond := cond1 .| cond2)
    builder <! (ax := ite cond (ax .+ numI32 0x106 16<rt>) ax)
    builder <! (af := ite cond b1 b0)
    builder <! (cf := ite cond b1 b0)
    builder <! (al := alAnd0f)
    builder <! (getRegVar ctxt R.OF := undefOF)
    builder <! (getRegVar ctxt R.SF := undefSF)
    builder <! (getRegVar ctxt R.ZF := undefZF)
    builder <! (getRegVar ctxt R.PF := undefPF)
  endMark insAddr insLen builder

let aad ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let imm8 =
    getOneOpr ins |> transOneOpr ins insAddr insLen ctxt |> extractLow 8<rt>
  let oprSize = getOperationSize ins
  let al = getRegVar ctxt R.AL
  let ah = getRegVar ctxt R.AH
  startMark insAddr insLen builder
  if oprSize = 64<rt> then ()
  else
    builder <! (al := (al .+ (ah .* imm8)) .& (numI32 0xff 8<rt>))
    builder <! (ah := num0 8<rt>)
    enumSZPFlags ctxt al 8<rt> builder
    builder <! (getRegVar ctxt R.OF := undefOF)
    builder <! (getRegVar ctxt R.AF := undefAF)
    builder <! (getRegVar ctxt R.CF := undefCF)
  endMark insAddr insLen builder

let aam ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let imm8 =
    getOneOpr ins |> transOneOpr ins insAddr insLen ctxt |>  extractLow 8<rt>
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
  let builder = new StmtBuilder (14)
  let oprSize = getOperationSize ins
  let ax = getRegVar ctxt R.AX
  let al = getRegVar ctxt R.AL
  let af = getRegVar ctxt R.AF
  let cf = getRegVar ctxt R.CF
  let ah = getRegVar ctxt R.AH
  let alAnd0f = al .& numI32 0x0f 8<rt>
  let cond1 = gt alAnd0f (numI32 9 8<rt>)
  let cond2 = af == b1
  let cond = tmpVar 1<rt>
  startMark insAddr insLen builder
  if oprSize = 64<rt> then ()
  else
    builder <! (cond := cond1 .| cond2)
    builder <! (ax := ite cond (ax .- numI32 6 16<rt>) ax)
    builder <! (ah := ite cond (ah .- num1 8<rt>) ah)
    builder <! (af := ite cond b1 b0)
    builder <! (cf := ite cond b1 b0)
    builder <! (al := alAnd0f)
  endMark insAddr insLen builder

let adc ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let cf = getRegVar ctxt R.CF
  let t1, t2, t3, t4 = tmpVars4 oprSize
  startMark insAddr insLen builder
  builder <! (t1 := dst)
  builder <! (t2 := sExt oprSize src)
  builder <! (t3 := t2 .+ zExt oprSize cf)
  builder <! (t4 := t1 .+ t3)
  builder <! (dstAssign oprSize dst t4)
  builder <! (cf := lt t3 t2 .| lt t4 t1)
  builder <! (getRegVar ctxt R.OF := getOFlagOnAdd t1 t2 t4)
  enumASZPFlags ctxt t1 t2 t4 oprSize builder
  endMark insAddr insLen builder

let add ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
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

let opP op _ = Array.map2 (op)

let addpd ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> (opP fadd) 8

let addps ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> (opP fadd) 8

let addsd ins insAddr insLen ctxt =
  handleScalarFPOp ins insAddr insLen ctxt 64<rt> fadd

let addss ins insAddr insLen ctxt =
  handleScalarFPOp ins insAddr insLen ctxt 32<rt> fadd

let divpd ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> (opP fdiv) 8

let divps ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> (opP fdiv) 8

let divsd ins insAddr insLen ctxt =
  handleScalarFPOp ins insAddr insLen ctxt 64<rt> fdiv

let divss ins insAddr insLen ctxt =
  handleScalarFPOp ins insAddr insLen ctxt 32<rt> fdiv

let mulpd ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> (opP fmul) 8

let mulps ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> (opP fmul) 8

let mulsd ins insAddr insLen ctxt =
  handleScalarFPOp ins insAddr insLen ctxt 64<rt> fmul

let mulss ins insAddr insLen ctxt =
  handleScalarFPOp ins insAddr insLen ctxt 32<rt> fmul

let subps ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> (opP fsub) 8

let subsd ins insAddr insLen ctxt =
  handleScalarFPOp ins insAddr insLen ctxt 64<rt> fsub

let subss ins insAddr insLen ctxt =
  handleScalarFPOp ins insAddr insLen ctxt 32<rt> fsub

let sqrtpd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let opr1, opr2 = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt opr1
  let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt opr2
  startMark insAddr insLen builder
  builder <! (dst1 := unop UnOpType.FSQRT src1)
  builder <! (dst2 := unop UnOpType.FSQRT src2)
  endMark insAddr insLen builder

let sqrtps ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let opr1, opr2 = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt opr1
  let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt opr2
  let tmp1, tmp2, tmp3, tmp4 = tmpVars4 32<rt>
  startMark insAddr insLen builder
  builder <! (tmp1 := extractLow 32<rt> src1)
  builder <! (tmp2 := extractHigh 32<rt> src1)
  builder <! (tmp3 := extractLow 32<rt> src2)
  builder <! (tmp4 := extractHigh 32<rt> src2)
  builder <! (extractLow 32<rt> dst1 := unop UnOpType.FSQRT tmp1)
  builder <! (extractHigh 32<rt> dst1 := unop UnOpType.FSQRT tmp2)
  builder <! (extractLow 32<rt> dst2 := unop UnOpType.FSQRT tmp3)
  builder <! (extractHigh 32<rt> dst2 := unop UnOpType.FSQRT tmp4)
  endMark insAddr insLen builder

let sqrtsd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let opr1, opr2 = getTwoOprs ins
  let dst = transOprToExpr64 ins insAddr insLen ctxt opr1
  let src = transOprToExpr64 ins insAddr insLen ctxt opr2
  startMark insAddr insLen builder
  builder <! (dst := unop UnOpType.FSQRT src)
  endMark insAddr insLen builder

let sqrtss ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let opr1, opr2 = getTwoOprs ins
  let dst = transOprToExpr32 ins insAddr insLen ctxt opr1
  let src = transOprToExpr32 ins insAddr insLen ctxt opr2
  startMark insAddr insLen builder
  builder <! (dst := unop UnOpType.FSQRT src)
  endMark insAddr insLen builder

let logAnd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let t = tmpVar oprSize
  startMark insAddr insLen builder
  builder <! (t := dst .& sExt oprSize src)
  builder <! (dstAssign oprSize dst t)
  builder <! (getRegVar ctxt R.OF := b0)
  builder <! (getRegVar ctxt R.CF := b0)
  builder <! (getRegVar ctxt R.AF := undefAF)
  enumSZPFlags ctxt t oprSize builder
  endMark insAddr insLen builder

let opPandn _ = Array.map2 (fun e1 e2 -> (AST.not e1) .& e2)

let andnpd ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opPandn 8

let andnps ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> opPandn 8

let opPand _ = Array.map2 (.&)

let andpd ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opPand 16

let andps ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> opPand 16

let arpl ins insAddr insLen ctxt =
  if is64bit ctxt then raise InvalidOn64Exception
  let builder = new StmtBuilder (8)
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let t1, t2 = tmpVars2 16<rt>
  let mask = numI32 0xfffc 16<rt>
  let zF = getRegVar ctxt R.ZF
  startMark insAddr insLen builder
  builder <! (t1 := dst .& numI32 0x3 16<rt>)
  builder <! (t2 := src .& numI32 0x3 16<rt>)
  builder <! (dst := ite (lt t1 t2) ((dst .& mask) .| t2) dst)
  builder <! (zF := lt t1 t2)
  endMark insAddr insLen builder

let bndmov ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
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
      builder <! (dst1 := extractHigh 32<rt> src |> zExt 64<rt>)
      builder <! (dst2 := extractLow 32<rt> src |> zExt 64<rt>)
    | OprMem _, OprReg _ ->
      let src1, src2 = transOprToExpr128 ins insAddr insLen ctxt src
      let dst = transOprToExpr ins insAddr insLen ctxt dst
      builder <! (extractHigh 32<rt> dst := extractLow 32<rt> src1)
      builder <! (extractLow 32<rt> dst := extractLow 32<rt> src2)
    | _ -> raise InvalidOperandException
  endMark insAddr insLen builder

let bsf ins insAddr insLen ctxt =
  let builder = new StmtBuilder (32)
  let lblL0 = lblSymbol "L0"
  let lblL1 = lblSymbol "L1"
  let lblEnd = lblSymbol "End"
  let lblLoopCond = lblSymbol "LoopCond"
  let lblLoopEnd = lblSymbol "LoopEnd"
  let lblLoop = lblSymbol "Loop"
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let cond = src == num0 oprSize
  let t = tmpVar oprSize
  startMark insAddr insLen builder
  builder <! (CJmp (cond, Name lblL0, Name lblL1))
  builder <! (LMark lblL0)
  builder <! (getRegVar ctxt R.ZF := b1)
  builder <! (dst := unDef oprSize "DEST is undefined.")
  builder <! (Jmp (Name lblEnd))
  builder <! (LMark lblL1)
  builder <! (getRegVar ctxt R.ZF := b0)
  builder <! (t := num0 oprSize)
  builder <! (LMark lblLoopCond)
  builder <!
    (CJmp ((extractLow 1<rt> (src >> t)) == b0, Name lblLoop, Name lblLoopEnd))
  builder <! (LMark lblLoop)
  builder <! (t := t .+ num1 oprSize)
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
  let builder = new StmtBuilder (32)
  let lblL0 = lblSymbol "L0"
  let lblL1 = lblSymbol "L1"
  let lblEnd = lblSymbol "End"
  let lblLoopCond = lblSymbol "LoopCond"
  let lblLoopE = lblSymbol "LoopEnd"
  let lblLoop = lblSymbol "Loop"
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let cond = src == num0 oprSize
  let t = tmpVar oprSize
  startMark insAddr insLen builder
  builder <! (CJmp (cond, Name lblL0, Name lblL1))
  builder <! (LMark lblL0)
  builder <! (getRegVar ctxt R.ZF := b1)
  builder <! (dst := unDef oprSize "DEST is undefined.")
  builder <! (Jmp (Name lblEnd))
  builder <! (LMark lblL1)
  builder <! (getRegVar ctxt R.ZF := b0)
  builder <! (t := bvOfOprSize oprSize .- num1 oprSize)
  builder <! (LMark lblLoopCond)
  builder <!
    (CJmp ((extractLow 1<rt> (src >> t)) == b0, Name lblLoop, Name lblLoopE))
  builder <! (LMark lblLoop)
  builder <! (t := t .- num1 oprSize)
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
  let t = tmpVar oprSize
  let cnt = RegType.toByteWidth oprSize |> int
  let tmps = Array.init cnt (fun _ -> tmpVar 8<rt>)
  let builder = new StmtBuilder (2 * cnt)
  startMark insAddr insLen builder
  builder <! (t := dst)
  for i in 0 .. cnt - 1 do
    builder <! (tmps.[i] := extract t 8<rt> (i * 8))
  done
  builder <! (dstAssign oprSize dst (concatExprs (Array.rev tmps)))
  endMark insAddr insLen builder

let bt ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
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
  let builder = new StmtBuilder (8)
  let bitBase, bitOffset =
    getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let setValue = zExt oprSize setValue
  startMark insAddr insLen builder
  builder <! (getRegVar ctxt R.CF := bit ins bitBase bitOffset oprSize)
  builder <! (setBit ins bitBase bitOffset oprSize setValue)
  builder <! (getRegVar ctxt R.OF := undefOF)
  builder <! (getRegVar ctxt R.SF := undefSF)
  builder <! (getRegVar ctxt R.AF := undefAF)
  builder <! (getRegVar ctxt R.PF := undefPF)
  endMark insAddr insLen builder

let btc ins insAddr insLen ctxt =
  bitTest ins insAddr insLen ctxt (getRegVar ctxt R.CF |> not)
let btr ins insAddr insLen ctxt = bitTest ins insAddr insLen ctxt b0
let bts ins insAddr insLen ctxt = bitTest ins insAddr insLen ctxt b1

let call ins insAddr insLen ctxt isFar =
  let builder = new StmtBuilder (4)
  match isFar with
  | false ->
    let pc = getInstrPtr ctxt
    let target = tmpVar ctxt.WordBitSize
    let oprSize = getOperationSize ins
    startMark insAddr insLen builder
    builder <! (target := getOneOpr ins |> transOneOpr ins insAddr insLen ctxt)
    let r = (bvOfBaseAddr insAddr ctxt .+ bvOfInstrLen insLen ctxt)
    auxPush oprSize ctxt r builder
    builder <! (InterJmp (pc, target, InterJmpInfo.IsCall))
    endMark insAddr insLen builder
  | true -> sideEffects insAddr insLen UnsupportedFAR

let convBWQ ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let oprSize = getOperationSize ins
  let opr = getRegVar ctxt (if is64bit ctxt then R.RAX else R.EAX)
  startMark insAddr insLen builder
  match oprSize with
  | 16<rt> ->
    builder <! (extractLow 16<rt> opr := sExt 16<rt> (extractLow 8<rt> opr))
  | 32<rt> ->
    builder <! (extractLow 32<rt> opr := sExt 32<rt> (extractLow 16<rt> opr))
  | 64<rt> ->
    builder <! (opr := sExt 64<rt> (extractLow 32<rt> opr))
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let clearFlag insAddr insLen ctxt flagReg =
  let builder = new StmtBuilder (4)
  startMark insAddr insLen builder
  builder <! (getRegVar ctxt flagReg := b0)
  endMark insAddr insLen builder

let cmc ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let cf = getRegVar ctxt R.CF
  startMark insAddr insLen builder
  builder <! (cf := not cf)
  builder <! (getRegVar ctxt R.OF := undefOF)
  builder <! (getRegVar ctxt R.AF := undefAF)
  builder <! (getRegVar ctxt R.SF := undefSF)
  builder <! (getRegVar ctxt R.ZF := undefZF)
  builder <! (getRegVar ctxt R.PF := undefPF)
  endMark insAddr insLen builder

let cmovcc ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  builder <! (dstAssign oprSize dst (ite (getCondOfCMov ins ctxt) src dst))
  endMark insAddr insLen builder

let cmp ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let src1, src2 = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let s1 = tmpVar oprSize
  let r, ext = tmpVars2 oprSize
  startMark insAddr insLen builder
  builder <! (s1 := src1)
  builder <! (ext := sExt oprSize src2)
  builder <! (r := s1 .- ext)
  enumEFLAGS ctxt s1 ext r oprSize getCFlagOnSub getOFlagOnSub builder
  endMark insAddr insLen builder

let cmppd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (32)
  let op1, op2, op3 = getThreeOprs ins
  let dst1, dst2 = transOprToExpr128 ins insAddr insLen ctxt op1
  let src1, src2 = transOprToExpr128 ins insAddr insLen ctxt op2
  let imm = transOprToExpr ins insAddr insLen ctxt op3
  let isNan expr =
    (extract expr 11<rt> 52  == num (BitVector.unsignedMax 11<rt>))
     .& (extractLow 52<rt> expr != num0 52<rt>)
  let cmpCond c expr1 expr2 =
    builder <! (c := b0)
    builder <! (c := ite (imm == num0 3<rt>) (expr1 == expr2) c)
    builder <! (c := ite (imm == num1 3<rt>) (flt expr1  expr2) c)
    builder <! (c := ite (imm == numI32 2 3<rt>) (fle expr1 expr2) c)
    builder <! (c := ite (imm == numI32 3 3<rt>) (isNan expr1 .| isNan expr2) c)
    builder <! (c := ite (imm == numI32 4 3<rt>) (expr1 != expr2) c)
    builder <! (c := ite (imm == numI32 5 3<rt>) (flt expr1 expr2 |> not) c)
    builder <! (c := ite (imm == numI32 6 3<rt>) (fle expr1 expr2 |> not) c)
    builder <!
      (c := ite (imm == numI32 7 3<rt>) (isNan expr1 .| isNan expr2 |> not) c)
  let cond1, cond2 = tmpVars2 1<rt>
  startMark insAddr insLen builder
  cmpCond cond1 dst1 src1
  cmpCond cond2 dst2 src2
  builder <! (dst1 := ite cond1 (maxNum 64<rt> |> num) (num0 64<rt>))
  builder <! (dst2 := ite cond2 (maxNum 64<rt> |> num) (num0 64<rt>))
  endMark insAddr insLen builder

let cmpps ins insAddr insLen ctxt =
  let builder = new StmtBuilder (64)
  let op1, op2, op3 = getThreeOprs ins
  let dst1, dst2 = transOprToExpr128 ins insAddr insLen ctxt op1
  let src1, src2 = transOprToExpr128 ins insAddr insLen ctxt op2
  let dst1A, dst1B = extractLow 32<rt> dst1, extractHigh 32<rt> dst1
  let dst2A, dst2B = extractLow 32<rt> dst2, extractHigh 32<rt> dst2
  let imm = transOprToExpr ins insAddr insLen ctxt op3
  let isNan expr =
    (extract expr 8<rt> 23  == num (BitVector.unsignedMax 8<rt>))
     .& (extractLow 23<rt> expr != num0 23<rt>)
  let cmpCond c expr1 expr2 =
    builder <! (c := b0)
    builder <! (c := ite (imm == num0 3<rt>) (expr1 == expr2) c)
    builder <! (c := ite (imm == num1 3<rt>) (flt expr1  expr2) c)
    builder <! (c := ite (imm == numI32 2 3<rt>) (fle expr1 expr2) c)
    builder <! (c := ite (imm == numI32 3 3<rt>) (isNan expr1 .| isNan expr2) c)
    builder <! (c := ite (imm == numI32 4 3<rt>) (expr1 != expr2) c)
    builder <! (c := ite (imm == numI32 5 3<rt>) (flt expr1 expr2 |> not) c)
    builder <! (c := ite (imm == numI32 6 3<rt>) (fle expr1 expr2 |> not) c)
    builder <!
      (c := ite (imm == numI32 7 3<rt>) (isNan expr1 .| isNan expr2 |> not) c)
  let cond1, cond2, cond3, cond4 = tmpVars4 1<rt>
  startMark insAddr insLen builder
  cmpCond cond1 dst1A (extractLow 32<rt> src1)
  cmpCond cond2 dst1B (extractHigh 32<rt> src1)
  cmpCond cond3 dst2A (extractLow 32<rt> src2)
  cmpCond cond4 dst2B (extractHigh 32<rt> src2)
  builder <! (dst1A := ite cond1 (maxNum 32<rt> |> num) (num0 32<rt>))
  builder <! (dst1B := ite cond2 (maxNum 32<rt> |> num) (num0 32<rt>))
  builder <! (dst2A := ite cond3 (maxNum 32<rt> |> num) (num0 32<rt>))
  builder <! (dst2B := ite cond4 (maxNum 32<rt> |> num) (num0 32<rt>))
  endMark insAddr insLen builder

let cmps ins insAddr insLen ctxt =
  let builder = new StmtBuilder (32)
  startMark insAddr insLen builder
  let pref = ins.Prefixes
  let body () =
    let oprSize = getOperationSize ins
    let df = getRegVar ctxt R.DF
    let si = getRegVar ctxt (if is64bit ctxt then R.RSI else R.ESI)
    let di = getRegVar ctxt (if is64bit ctxt then R.RDI else R.EDI)
    let src1 = loadLE oprSize si
    let src2 = loadLE oprSize di
    let t1, t2, t3 = tmpVars3 oprSize
    builder <! (t1 := src1)
    builder <! (t2 := src2)
    builder <! (t3 := t1 .- t2)
    let amount = numI32 (RegType.toByteWidth oprSize) ctxt.WordBitSize
    builder <! (si := ite df (si .- amount) (si .+ amount))
    builder <! (di := ite df (di .- amount) (di .+ amount))
    enumEFLAGS ctxt t1 t2 t3 oprSize getCFlagOnSub getOFlagOnSub builder
  let zf = getRegVar ctxt R.ZF
  if hasREPZ pref then
    strRepeat ctxt body (Some (zf == b0)) insAddr insLen builder
  elif hasREPNZ pref then
    strRepeat ctxt body (Some (zf)) insAddr insLen builder
  else body ()
  endMark insAddr insLen builder

let cmpsd ins insAddr insLen ctxt =
  match ins.Operands with
  | NoOperand -> cmps ins insAddr insLen ctxt
  | ThreeOperands (dst, src, imm) ->
    let builder = new StmtBuilder (16)
    let dst = transOprToExpr64 ins insAddr insLen ctxt dst
    let src = transOprToExpr64 ins insAddr insLen ctxt src
    let imm = transOprToExpr ins insAddr insLen ctxt imm |> extractLow 8<rt>
    let n num = numI32 num 8<rt>
    let max64 = maxNum 64<rt> |> num
    let isNan expr =
      (extract expr 11<rt> 52  == num (BitVector.unsignedMax 11<rt>))
       .& (extractLow 52<rt> expr != num0 52<rt>)
    let cond = tmpVar 1<rt>
    startMark insAddr insLen builder
    builder <! (cond := (dst == src))
    builder <! (cond := ite (imm == n 1) (flt dst src) cond)
    builder <! (cond := ite (imm == n 2) (fle dst src) cond)
    builder <! (cond := ite (imm == n 3) ((isNan dst) .| (isNan src)) cond)
    builder <! (cond := ite (imm == n 4) (dst != src) cond)
    builder <! (cond := ite (imm == n 5) (flt dst src |> not) cond)
    builder <! (cond := ite (imm == n 6) (fle dst src |> not) cond)
    builder <! (cond := ite (imm == n 7)
                            ((isNan dst) .| (isNan src) |> not) cond)
    builder <! (dst := ite cond max64 (num0 64<rt>))
    endMark insAddr insLen builder
  | _ -> raise InvalidOperandException

let cmpss ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let dst, src, imm = getThreeOprs ins
  let dst = transOprToExpr32 ins insAddr insLen ctxt dst
  let src = transOprToExpr32 ins insAddr insLen ctxt src
  let imm = transOprToExpr ins insAddr insLen ctxt imm |> extractLow 8<rt>
  let n num = numI32 num 8<rt>
  let max32 = maxNum 32<rt> |> num
  let isNan expr =
    (extract expr 8<rt> 23  == num (BitVector.unsignedMax 8<rt>))
     .& (extractLow 23<rt> expr != num0 23<rt>)
  let cond = tmpVar 1<rt>
  startMark insAddr insLen builder
  builder <! (cond := (dst == src))
  builder <! (cond := ite (imm == n 1) (flt dst src) cond)
  builder <! (cond := ite (imm == n 2) (fle dst src) cond)
  builder <! (cond := ite (imm == n 3) ((isNan dst) .| (isNan src)) cond)
  builder <! (cond := ite (imm == n 4) (dst != src) cond)
  builder <! (cond := ite (imm == n 5) (flt dst src |> not) cond)
  builder <! (cond := ite (imm == n 6) (fle dst src |> not) cond)
  builder <! (cond := ite (imm == n 7)
                          ((isNan dst) .| (isNan src) |> not) cond)
  builder <! (dst := ite cond max32 (num0 32<rt>))
  endMark insAddr insLen builder

let cmpxchg ins insAddr insLen ctxt =
  let builder = new StmtBuilder (32)
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  if hasLock ins.Prefixes then builder <! (SideEffect Lock)
  let t = tmpVar oprSize
  builder <! (t := dst)
  let r = tmpVar oprSize
  let acc = getRegOfSize ctxt oprSize GrpEAX
  let cond = tmpVar 1<rt>
  builder <! (r := acc .- t)
  builder <! (cond := acc == t)
  builder <! (getRegVar ctxt R.ZF := ite cond b1 b0)
  builder <! (dstAssign oprSize dst (ite cond src t))
  builder <! (dstAssign oprSize acc (ite cond acc t))
  builder <! (getRegVar ctxt R.OF := getOFlagOnSub acc t r)
  builder <! (getRegVar ctxt R.SF := extractHigh 1<rt> r)
  builder <! (buildAF ctxt acc t r oprSize)
  buildPF ctxt r oprSize None builder
  builder <! (getRegVar ctxt R.CF := lt (acc .+ t) acc)
  endMark insAddr insLen builder

let comisd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let opr1, opr2 = getTwoOprs ins
  let opr1 = transOprToExpr64 ins insAddr insLen ctxt opr1
  let opr2 = transOprToExpr64 ins insAddr insLen ctxt opr2
  let lblNan = lblSymbol "IsNan"
  let lblExit = lblSymbol "Exit"
  let zf = getRegVar ctxt R.ZF
  let pf = getRegVar ctxt R.PF
  let cf = getRegVar ctxt R.CF
  startMark insAddr insLen builder
  builder <! (zf := ite (opr1 == opr2) b1 b0)
  builder <! (pf := b0)
  builder <! (cf := ite (flt opr1 opr2) b1 b0)
  let isNan expr =
    (extract expr 11<rt> 52  == num (BitVector.unsignedMax 11<rt>))
     .& (extractLow 52<rt> expr != num0 52<rt>)
  builder <! (CJmp (isNan opr1 .| isNan opr2, Name lblNan, Name lblExit))
  builder <! (LMark lblNan)
  builder <! (zf := b1)
  builder <! (pf := b1)
  builder <! (cf := b1)
  builder <! (LMark lblExit)
  builder <! (getRegVar ctxt R.OF := b0)
  builder <! (getRegVar ctxt R.AF := b0)
  builder <! (getRegVar ctxt R.SF := b0)
  endMark insAddr insLen builder

let comiss ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let opr1, opr2 = getTwoOprs ins
  let opr1 = transOprToExpr32 ins insAddr insLen ctxt opr1
  let opr2 = transOprToExpr32 ins insAddr insLen ctxt opr2
  let lblNan = lblSymbol "IsNan"
  let lblExit = lblSymbol "Exit"
  let zf = getRegVar ctxt R.ZF
  let pf = getRegVar ctxt R.PF
  let cf = getRegVar ctxt R.CF
  startMark insAddr insLen builder
  builder <! (zf := ite (opr1 == opr2) b1 b0)
  builder <! (pf := b0)
  builder <! (cf := ite (flt opr1 opr2) b1 b0)
  let isNan expr =
    (extract expr 8<rt> 23  == num (BitVector.unsignedMax 8<rt>))
     .& (extractLow 23<rt> expr != num0 23<rt>)
  builder <! (CJmp (isNan opr1 .| isNan opr2, Name lblNan, Name lblExit))
  builder <! (LMark lblNan)
  builder <! (zf := b1)
  builder <! (pf := b1)
  builder <! (cf := b1)
  builder <! (LMark lblExit)
  builder <! (getRegVar ctxt R.OF := b0)
  builder <! (getRegVar ctxt R.AF := b0)
  builder <! (getRegVar ctxt R.SF := b0)
  endMark insAddr insLen builder

let compareExchangeBytes ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst = getOneOpr ins
  let oprSize = getOperationSize ins
  let zf = getRegVar ctxt R.ZF
  let cond = tmpVar 1<rt>
  startMark insAddr insLen builder
  match oprSize with
  | 64<rt> ->
    let dst = transOneOpr ins insAddr insLen ctxt dst
    let edx = getRegOfSize ctxt 32<rt> GrpEDX
    let eax = getRegOfSize ctxt 32<rt> GrpEAX
    let ecx = getRegOfSize ctxt 32<rt> GrpECX
    let ebx = getRegOfSize ctxt 32<rt> GrpEBX
    let t = tmpVar oprSize
    builder <! (t := dst)
    builder <! (cond := concat edx eax == t)
    builder <! (zf := cond)
    builder <! (eax := ite cond eax (extract t 32<rt> 0))
    builder <! (edx := ite cond edx (extract t 32<rt> 32))
    builder <! (dst := ite cond (concat ecx ebx) t)
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let rdx = getRegOfSize ctxt 64<rt> GrpEDX
    let rax = getRegOfSize ctxt 64<rt> GrpEAX
    let rcx = getRegOfSize ctxt 64<rt> GrpECX
    let rbx = getRegOfSize ctxt 64<rt> GrpEBX
    builder <! (cond := (dstB == rdx) .& (dstA == rax))
    builder <! (zf := cond)
    builder <! (rax := ite cond rax dstA)
    builder <! (rdx := ite cond rdx dstB)
    builder <! (dstA := ite cond rbx dstA)
    builder <! (dstB := ite cond rcx dstB)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let convWDQ ins insAddr insLen (ctxt: TranslationContext) =
  let builder = new StmtBuilder (8)
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  match oprSize, ctxt.WordBitSize with
  | 16<rt>, _ ->
    let t = tmpVar 32<rt>
    let ax = getRegVar ctxt R.AX
    let dx = getRegVar ctxt R.DX
    builder <! (t := sExt 32<rt> ax)
    builder <! (dx := extractHigh 16<rt> t)
    builder <! (ax := extractLow 16<rt> t)
  | 32<rt>, _ ->
    let t = tmpVar 64<rt>
    let eax = getRegVar ctxt R.EAX
    let edx = getRegVar ctxt R.EDX
    builder <! (t := sExt 64<rt> eax)
    builder <! (edx := extractHigh 32<rt> t)
    builder <! (eax := extractLow 32<rt> t)
  | 64<rt>, 64<rt> ->
    let t = tmpVar 128<rt>
    let rdx = getRegVar ctxt R.RDX
    let rax = getRegVar ctxt R.RAX
    builder <! (t := sExt 128<rt> rax)
    builder <! (rdx := extractHigh 64<rt> t)
    builder <! (rax := extractLow 64<rt> t)
  | _, _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let cvtdq2pd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src = transOprToExpr64 ins insAddr insLen ctxt src
  let tmp1, tmp2 = tmpVars2 32<rt>
  startMark insAddr insLen builder
  builder <! (tmp1 := extractLow 32<rt> src)
  builder <! (tmp2 := extractHigh 32<rt> src)
  builder <! (dst1 := cast CastKind.IntToFloat 64<rt> tmp1)
  builder <! (dst2 := cast CastKind.IntToFloat 64<rt> tmp2)
  endMark insAddr insLen builder

let cvtdq2ps ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let dst, src = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
  let tmp1, tmp2, tmp3, tmp4 = tmpVars4 32<rt>
  startMark insAddr insLen builder
  builder <! (tmp1 := extractLow 32<rt> src1)
  builder <! (tmp2 := extractHigh 32<rt> src1)
  builder <! (tmp3 := extractLow 32<rt> src2)
  builder <! (tmp4 := extractHigh 32<rt> src2)
  builder <! (extractLow 32<rt> dst1 := cast CastKind.IntToFloat 32<rt> tmp1)
  builder <! (extractHigh 32<rt> dst1 := cast CastKind.IntToFloat 32<rt> tmp2)
  builder <! (extractLow 32<rt> dst2 := cast CastKind.IntToFloat 32<rt> tmp3)
  builder <! (extractHigh 32<rt> dst2 := cast CastKind.IntToFloat 32<rt> tmp4)
  endMark insAddr insLen builder

let cvtpd2dq ins insAddr insLen ctxt rounded =
  let builder = new StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
  let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
  startMark insAddr insLen builder
  builder <! (extractLow 32<rt> dst1 := cast castKind 32<rt> src1)
  builder <! (extractHigh 32<rt> dst1 := cast castKind 32<rt> src2)
  builder <! (dst2 := num0 64<rt>)
  endMark insAddr insLen builder

let cvtpd2pi ins insAddr insLen ctxt rounded =
  let builder = new StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr ins insAddr insLen ctxt dst
  let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
  let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
  startMark insAddr insLen builder
  builder <! (extractLow 32<rt> dst := cast castKind 32<rt> src1)
  builder <! (extractHigh 32<rt> dst := cast castKind 32<rt> src2)
  endMark insAddr insLen builder

let cvtpd2ps ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
  startMark insAddr insLen builder
  builder <! (extractLow 32<rt> dst1 := cast CastKind.FloatExt 32<rt> src1)
  builder <! (extractHigh 32<rt> dst1 := cast CastKind.FloatExt 32<rt> src2)
  builder <! (dst2 := num0 64<rt>)
  endMark insAddr insLen builder

let cvtpi2pd ins insAddr insLen ctxt = cvtdq2pd ins insAddr insLen ctxt

let cvtpi2ps ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr64 ins insAddr insLen ctxt dst
  let src = transOprToExpr64 ins insAddr insLen ctxt src
  let tmp2, tmp1 = tmpVars2 32<rt>
  startMark insAddr insLen builder
  builder <! (tmp1 := extractLow 32<rt> src)
  builder <! (tmp2 := extractHigh 32<rt> src)
  builder <! (extractLow 32<rt> dst := cast CastKind.IntToFloat 32<rt> tmp1)
  builder <! (extractHigh 32<rt> dst := cast CastKind.IntToFloat 32<rt> tmp2)
  endMark insAddr insLen builder

let cvtps2dq ins insAddr insLen ctxt rounded =
  let builder = new StmtBuilder (16)
  let dst, src = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
  let tmp1, tmp2, tmp3, tmp4 = tmpVars4 32<rt>
  let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
  startMark insAddr insLen builder
  builder <! (tmp1 := extractLow 32<rt> src1)
  builder <! (tmp2 := extractHigh 32<rt> src1)
  builder <! (tmp3 := extractLow 32<rt> src2)
  builder <! (tmp4 := extractHigh 32<rt> src2)
  builder <! (extractLow 32<rt> dst1 := cast castKind 32<rt> tmp1)
  builder <! (extractHigh 32<rt> dst1 := cast castKind 32<rt> tmp2)
  builder <! (extractLow 32<rt> dst2 := cast castKind 32<rt> tmp3)
  builder <! (extractHigh 32<rt> dst2 := cast castKind 32<rt> tmp4)
  endMark insAddr insLen builder

let cvtps2pd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src = transOprToExpr64 ins insAddr insLen ctxt src
  let tmp1, tmp2 = tmpVars2 32<rt>
  startMark insAddr insLen builder
  builder <! (tmp1 := extractLow 32<rt> src)
  builder <! (tmp2 := extractHigh 32<rt> src)
  builder <! (dst1 := cast CastKind.FloatExt 64<rt> tmp1)
  builder <! (dst2 := cast CastKind.FloatExt 64<rt> tmp2)
  endMark insAddr insLen builder

let cvtps2pi ins insAddr insLen ctxt rounded =
  let builder = new StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr ins insAddr insLen ctxt dst
  let src = transOprToExpr64 ins insAddr insLen ctxt src
  let tmp1, tmp2 = tmpVars2 32<rt>
  let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
  startMark insAddr insLen builder
  builder <! (tmp1 := extractLow 32<rt> src)
  builder <! (tmp2 := extractHigh 32<rt> src)
  builder <! (extractLow 32<rt> dst := cast castKind 32<rt> tmp1)
  builder <! (extractHigh 32<rt> dst := cast castKind 32<rt> tmp2)
  endMark insAddr insLen builder

let cvtsd2si ins insAddr insLen ctxt rounded =
  let builder = new StmtBuilder (8)
  let oprSize = getOperationSize ins
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr ins insAddr insLen ctxt dst
  let src = transOprToExpr64 ins insAddr insLen ctxt src
  let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
  let tmp = tmpVar 32<rt>
  startMark insAddr insLen builder
  if is64bit ctxt && oprSize = 64<rt> then
    builder <! (dst := cast castKind 64<rt> src)
  else
    builder <! (tmp := cast castKind 32<rt> src)
    builder <! dstAssign 32<rt> dst tmp
  endMark insAddr insLen builder

let cvtsd2ss ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr64 ins insAddr insLen ctxt dst
  let src = transOprToExpr64 ins insAddr insLen ctxt src
  startMark insAddr insLen builder
  builder <! (extractLow 32<rt> dst := cast CastKind.FloatExt 32<rt> src)
  endMark insAddr insLen builder

let cvtsi2sd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr64 ins insAddr insLen ctxt dst
  let src = transOprToExpr ins insAddr insLen ctxt src
  startMark insAddr insLen builder
  builder <! (dst := cast CastKind.IntToFloat 64<rt> src)
  endMark insAddr insLen builder

let cvtsi2ss ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr64 ins insAddr insLen ctxt dst
  let src = transOprToExpr ins insAddr insLen ctxt src
  startMark insAddr insLen builder
  builder <! (extractLow 32<rt> dst := cast CastKind.IntToFloat 32<rt> src)
  endMark insAddr insLen builder

let cvtss2sd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr64 ins insAddr insLen ctxt dst
  let src = transOprToExpr32 ins insAddr insLen ctxt src
  startMark insAddr insLen builder
  builder <! (dst := cast CastKind.FloatExt 64<rt> src)
  endMark insAddr insLen builder

let cvtss2si ins insAddr insLen ctxt rounded =
  let builder = new StmtBuilder (4)
  let oprSize = getOperationSize ins
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr ins insAddr insLen ctxt dst
  let src = transOprToExpr32 ins insAddr insLen ctxt src
  let tmp = tmpVar 32<rt>
  let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
  startMark insAddr insLen builder
  if is64bit ctxt && oprSize = 64<rt> then
    builder <! (dst := cast castKind 64<rt> src)
  else
    builder <! (tmp := cast castKind 32<rt> src)
    builder <! (dstAssign 32<rt> dst tmp)
  endMark insAddr insLen builder

let daa ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let oprSize = getOperationSize ins
  let al = getRegVar ctxt R.AL
  let cf = getRegVar ctxt R.CF
  let af = getRegVar ctxt R.AF
  let oldAl = tmpVar 8<rt>
  let oldCf = tmpVar 1<rt>
  let alAnd0f = al .& numI32 0x0f 8<rt>
  let subCond1 = gt alAnd0f (numI32 9 8<rt>)
  let subCond2 = af == b1
  let cond1 = tmpVar 1<rt>
  let subCond3 = gt oldAl (numI32 0x99 8<rt>)
  let subCond4 = oldCf == b1
  let cond2 = tmpVar 1<rt>
  startMark insAddr insLen builder
  if oprSize = 64<rt> then ()
  else
    builder <! (oldAl := al)
    builder <! (oldCf := cf)
    builder <! (cf := b0)
    builder <! (cond1 := subCond1 .| subCond2)
    builder <! (al := ite cond1 (al .+ numI32 6 8<rt>) al)
    builder <! (cf := ite cond1 oldCf cf)
    builder <! (af := cond1)
    builder <! (cond2 := subCond3 .| subCond4)
    builder <! (al := ite cond2 (al .+ numI32 0x60 8<rt>) al)
    builder <! (cf := cond2)
    enumSZPFlags ctxt al 8<rt> builder
    builder <! (getRegVar ctxt R.OF := undefOF)
  endMark insAddr insLen builder

let das ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let oprSize = getOperationSize ins
  let al = getRegVar ctxt R.AL
  let cf = getRegVar ctxt R.CF
  let af = getRegVar ctxt R.AF
  let oldAl = tmpVar 8<rt>
  let oldCf = tmpVar 1<rt>
  let alAnd0f = al .& numI32 0x0f 8<rt>
  let subCond1 = gt alAnd0f (numI32 9 8<rt>)
  let subCond2 = af == b1
  let cond1 = tmpVar 1<rt>
  let subCond3 = gt oldAl (numI32 0x99 8<rt>)
  let subCond4 = oldCf == b1
  let cond2 = tmpVar 1<rt>
  startMark insAddr insLen builder
  if oprSize = 64<rt> then ()
  else
    builder <! (oldAl := al)
    builder <! (oldCf := cf)
    builder <! (cf := b0)
    builder <! (cond1 := subCond1 .| subCond2)
    builder <! (al := ite cond1 (al .- numI32 6 8<rt>) al)
    builder <! (cf := ite cond1 oldCf cf)
    builder <! (af := cond1)
    builder <! (cond2 := subCond3 .| subCond4)
    builder <! (al := ite cond2 (al .- numI32 0x60 8<rt>) al)
    builder <! (cf := cond2)
    enumSZPFlags ctxt al 8<rt> builder
    builder <! (getRegVar ctxt R.OF := undefOF)
  endMark insAddr insLen builder

let dec ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let dst = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let t1, t2, t3 = tmpVars3 oprSize
  startMark insAddr insLen builder
  builder <! (t1 := dst)
  builder <! (t2 := num1 oprSize)
  builder <! (t3 := (t1 .- t2))
  builder <! (dstAssign oprSize dst t3)
  builder <! (getRegVar ctxt R.OF := getOFlagOnSub t1 t2 t3)
  enumASZPFlags ctxt t1 t2 t3 oprSize builder
  endMark insAddr insLen builder

let div ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let lblAssign = lblSymbol "Assign"
  let lblChk = lblSymbol "Check"
  let errExp = unDef 1<rt> "Divide Error"
  let divisor = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  builder <! (CJmp (divisor == num0 oprSize, errExp, Name lblChk))
  builder <! (LMark lblChk)
  let dividend = getDividend ctxt oprSize
  let sz = AST.typeOf dividend
  let quotient = tmpVar sz
  let remainder = tmpVar sz
  let checkQuotientDIV q =
    CJmp (extractHigh oprSize q == num0 oprSize, Name lblAssign, errExp)
  let checkQuotientIDIV q =
    let amount =
      num (BitVector.ofInt32 (RegType.toBitWidth oprSize - 1) oprSize)
    let mask = num1 oprSize << amount
    let msb = extractHigh 1<rt> q
    let negRes = lt q (zExt sz mask)
    let posRes = gt q (zExt sz (mask .- (num1 oprSize)))
    let cond = ite (msb == b1) negRes posRes
    CJmp (cond, errExp, Name lblAssign)
  match ins.Opcode with
  | Opcode.DIV -> let divisor = zExt sz divisor
                  builder <! (quotient := dividend ./ divisor)
                  builder <! (remainder := dividend .% divisor)
                  builder <! (checkQuotientDIV quotient)
  | Opcode.IDIV -> let divisor = sExt sz divisor
                   builder <! (quotient := dividend ?/ divisor)
                   builder <! (remainder := dividend ?% divisor)
                   builder <! (checkQuotientIDIV quotient)
  | _ ->  raise InvalidOpcodeException
  builder <! (LMark lblAssign)
  match oprSize with
  | 8<rt> ->
    builder <! (getRegVar ctxt R.AL := extractLow oprSize quotient)
    builder <! (getRegVar ctxt R.AH := extractLow oprSize remainder)
  | 16<rt> | 32<rt> | 64<rt> ->
    let q = getRegOfSize ctxt oprSize GrpEAX
    let r = getRegOfSize ctxt oprSize GrpEDX
    builder <! (dstAssign oprSize q (extractLow oprSize quotient))
    builder <! (dstAssign oprSize r (extractLow oprSize remainder))
  | _ -> raise InvalidOperandSizeException
  allEFLAGSUndefined ctxt builder
  endMark insAddr insLen builder

let emms _ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  startMark insAddr insLen builder
  builder <! (getRegVar ctxt R.FTW := maxNum 16<rt> |> num)
  endMark insAddr insLen builder

let enter ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let imm16, imm8 = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oSz = getOperationSize ins
  let allocSize, nestingLevel, cnt = tmpVars3 oSz
  let frameTemp, addrSize = tmpVars2 ctxt.WordBitSize
  let bp = getBasePtr ctxt
  let sp = getStackPtr ctxt
  let lblLoop = lblSymbol "Loop"
  let lblCont = lblSymbol "Continue"
  let lblLevelCheck = lblSymbol "NestingLevelCheck"
  let lblLv1 = lblSymbol "NestingLevel1"
  let getAddrSize bitSize =
    if bitSize = 64<rt> then numI32 8 bitSize else numI32 4 bitSize
  startMark insAddr insLen builder
  builder <! (allocSize := imm16)
  builder <! (nestingLevel := imm8 .% (numI32 32 oSz))
  auxPush ctxt.WordBitSize ctxt bp builder
  builder <! (frameTemp := sp)
  builder <! (addrSize := getAddrSize ctxt.WordBitSize)
  builder <! (CJmp (nestingLevel == num0 oSz, Name lblCont, Name lblLevelCheck))
  builder <! (LMark lblLevelCheck)
  builder <! (cnt := nestingLevel .- num1 oSz)
  builder <! (CJmp (gt nestingLevel (num1 oSz), Name lblLoop, Name lblLv1))
  builder <! (LMark lblLoop)
  builder <! (bp := bp .- addrSize)
  auxPush ctxt.WordBitSize ctxt (loadLE ctxt.WordBitSize bp) builder
  builder <! (cnt := cnt .- num1 oSz)
  builder <! (CJmp (cnt == num0 oSz, Name lblCont, Name lblLoop))
  builder <! (LMark lblLv1)
  auxPush ctxt.WordBitSize ctxt frameTemp builder
  builder <! (LMark lblCont)
  builder <! (bp := frameTemp)
  builder <! (sp := sp .- zExt ctxt.WordBitSize allocSize)
  endMark insAddr insLen builder

let getBaseReg = function
  | Load (_, _, BinOp (_, _, BinOp (_, _, reg, _, _, _), _, _, _), _, _) -> reg
  | Load (_, _, BinOp (_, _, e, _, _, _), _, _) -> e
  | Load (_, _, expr, _, _) -> expr
  | _ -> failwith "Invalid memory"

let updateAddrByOffset addr offset =
  match addr with
  (* Save *)
  | Load (_, _, BinOp (_, _, BinOp (_, _, reg, _, _, _), _, _, _), _, _) ->
    reg := reg .+ offset (* SIB *)
  | Load (_, _, BinOp (_, _, e, _, _, _), _, _) ->
    e := e .+ offset (* Displacemnt *)
  | Load (_, _, expr, _, _) -> expr := expr .+ offset
  | _ -> failwith "Invalid memory"

let extendAddr src regType =
  match src with
  | Load (e, _, expr, _, _) -> AST.load e regType expr
  | _ -> failwith "Invalid memory"

let getAddrRegSize = function
  (* Save *)
  | Load (_, _, Var (t, _, _, _), _, _) -> t
  | Load (_, _, BinOp (_, t, _, _, _, _), _, _) -> t
  (* Load *)
  | TempVar (t, _) -> t
  | _ -> failwith "Invalid memory"

let saveFxsaveMMX addr offset grv builder =
  let r64 = num0 64<rt>
  let mRegs = [ r64; grv R.MM0; r64; grv R.MM1; r64; grv R.MM2; r64; grv R.MM3;
                r64; grv R.MM4; r64; grv R.MM5; r64; grv R.MM6; r64; grv R.MM7 ]
  List.iter (fun reg -> builder <! (updateAddrByOffset addr offset)
                        builder <! (addr := reg)) mRegs

let loadFxrstorMMX addr grv builder =
  let offset = num (BitVector.ofInt32 16 (getAddrRegSize addr))
  let mRegs = [ R.MM0; R.MM1; R.MM2; R.MM3; R.MM4; R.MM5; R.MM6; R.MM7 ]
  List.iter (fun reg -> builder <! (updateAddrByOffset addr (offset))
                        builder <! (grv reg := addr)) mRegs

let saveFxsaveXMM ctxt addr offset xRegs builder =
  let pv r = getPseudoRegVar128 ctxt r
  let exprs =
    List.fold(fun acc r -> let r2, r1 = pv r in r1 :: (r2 :: acc)) [] xRegs
  List.iter (fun reg -> builder <! (updateAddrByOffset addr offset)
                        builder <! (addr := reg)) exprs

let loadFxrstorXMM ctxt addr xRegs builder =
  let pv r = getPseudoRegVar128 ctxt r
  let offset = num (BitVector.ofInt32 8 (getAddrRegSize addr))
  let exprs =
    List.fold (fun acc r -> let r2, r1 = pv r in r1 :: (r2 :: acc)) [] xRegs
  List.iter (fun reg -> builder <! (updateAddrByOffset addr offset)
                        builder <! (reg := addr)) exprs

let save64BitPromotedFxsave ctxt dst builder =
  let reserved8 = num0 8<rt>
  let num3 = numI32 3 2<rt>
  let v r = getRegVar ctxt r
  let t0, t1, t2, t3 = tmpVars4 1<rt>
  let t4, t5, t6, t7 = tmpVars4 1<rt>
  let abrTagW = tmpVar 8<rt>
  let offset = num (BitVector.ofInt32 8 (getAddrRegSize dst))
  let regSave = tmpVar (getAddrRegSize dst)
  let baseReg = getBaseReg dst
  let xRegs =
    [ R.XMM0; R.XMM1; R.XMM2; R.XMM3; R.XMM4; R.XMM5; R.XMM6; R.XMM7;
      R.XMM8; R.XMM9; R.XMM10; R.XMM11; R.XMM12; R.XMM13; R.XMM14; R.XMM15 ]
  builder <! (regSave := baseReg)
  builder <! (abrTagW := concat (concat (concat t7 t6) (concat t5 t4))
                                (concat (concat t3 t2) (concat t1 t0)))
  builder <! (t0 := (v R.FTW0 != num3))
  builder <! (t1 := (v R.FTW1 != num3))
  builder <! (t2 := (v R.FTW2 != num3))
  builder <! (t3 := (v R.FTW3 != num3))
  builder <! (t4 := (v R.FTW4 != num3))
  builder <! (t5 := (v R.FTW5 != num3))
  builder <! (t6 := (v R.FTW6 != num3))
  builder <! (t7 := (v R.FTW7 != num3))
  builder <! (dst := concat (concat (v R.FOP) (concat reserved8 abrTagW))
                            (concat (v R.FSW) (v R.FCW)))
  builder <! (updateAddrByOffset dst offset)
  builder <! (dst := v R.FIP)
  builder <! (updateAddrByOffset dst offset)
  builder <! (dst := v R.FDP)
  builder <! (updateAddrByOffset dst offset)
  builder <! (dst := concat (v R.MXCSRMASK) (v R.MXCSR))
  saveFxsaveMMX dst offset v builder
  saveFxsaveXMM ctxt dst offset (List.rev xRegs) builder
  builder <! (baseReg := regSave)

let save64BitDefaultFxsave ctxt dst builder =
  let reserved8 = num0 8<rt>
  let reserved16 = num0 16<rt>
  let num3 = numI32 3 2<rt>
  let v r = getRegVar ctxt r
  let t0, t1, t2, t3 = tmpVars4 1<rt>
  let t4, t5, t6, t7 = tmpVars4 1<rt>
  let abrTagW = tmpVar 8<rt>
  let offset = num (BitVector.ofInt32 8 (getAddrRegSize dst))
  let regSave = tmpVar (getAddrRegSize dst)
  let baseReg = getBaseReg dst
  let xRegs =
    [ R.XMM0; R.XMM1; R.XMM2; R.XMM3; R.XMM4; R.XMM5; R.XMM6; R.XMM7;
      R.XMM8; R.XMM9; R.XMM10; R.XMM11; R.XMM12; R.XMM13; R.XMM14; R.XMM15 ]
  builder <! (regSave := baseReg)
  builder <! (t0 := (v R.FTW0 != num3))
  builder <! (t1 := (v R.FTW1 != num3))
  builder <! (t2 := (v R.FTW2 != num3))
  builder <! (t3 := (v R.FTW3 != num3))
  builder <! (t4 := (v R.FTW4 != num3))
  builder <! (t5 := (v R.FTW5 != num3))
  builder <! (t6 := (v R.FTW6 != num3))
  builder <! (t7 := (v R.FTW7 != num3))
  builder <! (abrTagW := concat (concat (concat t7 t6) (concat t5 t4))
                                (concat (concat t3 t2) (concat t1 t0)))
  builder <! (dst := concat (concat (v R.FOP) (concat reserved8 abrTagW))
                            (concat (v R.FSW) (v R.FCW)))
  builder <! (updateAddrByOffset dst offset)
  builder <! (dst := concat (extractLow 32<rt> (v R.FIP))
                            (concat (v R.FCS) reserved16))
  builder <! (updateAddrByOffset dst offset)
  builder <! (dst := concat (extractLow 32<rt> (v R.FDP))
                            (concat (v R.FDS) reserved16))
  builder <! (updateAddrByOffset dst offset)
  builder <! (dst := concat (v R.MXCSRMASK) (v R.MXCSR))
  saveFxsaveMMX dst offset v builder
  saveFxsaveXMM ctxt dst offset (List.rev xRegs) builder
  builder <! (baseReg := regSave)

let saveLegacyFxsave ctxt dst builder =
  let reserved8 = num0 8<rt>
  let reserved16 = num0 16<rt>
  let num3 = numI32 3 2<rt>
  let v r = getRegVar ctxt r
  let t0, t1, t2, t3 = tmpVars4 1<rt>
  let t4, t5, t6, t7 = tmpVars4 1<rt>
  let abrTagW = tmpVar 8<rt>
  let offset = num (BitVector.ofInt32 8 (getAddrRegSize dst))
  let regSave = tmpVar (getAddrRegSize dst)
  let baseReg = getBaseReg dst
  let xRegs = [ R.XMM0; R.XMM1; R.XMM2; R.XMM3; R.XMM4; R.XMM5; R.XMM6; R.XMM7 ]
  builder <! (regSave := baseReg)
  builder <! (t0 := (v R.FTW0 != num3))
  builder <! (t1 := (v R.FTW1 != num3))
  builder <! (t2 := (v R.FTW2 != num3))
  builder <! (t3 := (v R.FTW3 != num3))
  builder <! (t4 := (v R.FTW4 != num3))
  builder <! (t5 := (v R.FTW5 != num3))
  builder <! (t6 := (v R.FTW6 != num3))
  builder <! (t7 := (v R.FTW7 != num3))
  builder <! (abrTagW := concat (concat (concat t7 t6) (concat t5 t4))
                                (concat (concat t3 t2) (concat t1 t0)))
  builder <! (dst := concat (concat (v R.FOP) (concat reserved8 abrTagW))
                            (concat (v R.FSW) (v R.FCW)))
  builder <! (updateAddrByOffset dst offset)
  builder <!
    (dst := concat (extractLow 32<rt> (v R.FIP)) (concat (v R.FCS) reserved16))
  builder <! (updateAddrByOffset dst offset)
  builder <! (dst := concat (extractLow 32<rt> (v R.FDP))
                            (concat (v R.FDS) reserved16))
  builder <! (updateAddrByOffset dst offset)
  builder <! (dst := concat (v R.MXCSRMASK) (v R.MXCSR))
  saveFxsaveMMX dst offset v builder
  saveFxsaveXMM ctxt dst offset (List.rev xRegs) builder
  builder <! (baseReg := regSave)

let load64BitPromotedFxrstor ctxt src builder =
  let grv r = getRegVar ctxt r
  let offset = num (BitVector.ofInt32 8 (getAddrRegSize src))
  let xRegs =
    [ R.XMM0; R.XMM1; R.XMM2; R.XMM3; R.XMM4; R.XMM5; R.XMM6; R.XMM7;
      R.XMM8; R.XMM9; R.XMM10; R.XMM11; R.XMM12; R.XMM13; R.XMM14; R.XMM15 ]
  let tSrc = tmpVar 64<rt>
  builder <! (tSrc := src)
  builder <! (grv R.FCW := extractLow 16<rt> tSrc)
  builder <! (grv R.FSW := extract tSrc 16<rt> 16)
  builder <! (grv R.FTW := extract tSrc 8<rt> 32)
  builder <! (grv R.FOP := extract tSrc 16<rt> 48)
  builder <! (updateAddrByOffset src offset)
  builder <! (tSrc := src)
  builder <! (grv R.FIP := tSrc)
  builder <! (updateAddrByOffset src offset)
  builder <! (tSrc := src)
  builder <! (grv R.FDP := tSrc)
  builder <! (updateAddrByOffset src offset)
  builder <! (tSrc := src)
  builder <! (grv R.MXCSR := extractLow 32<rt> tSrc)
  builder <! (grv R.MXCSRMASK := extractHigh 32<rt> tSrc)
  loadFxrstorMMX src grv builder
  loadFxrstorXMM ctxt src xRegs builder

let load64BitDefaultFxrstor ctxt src builder =
  let grv r = getRegVar ctxt r
  let offset = num (BitVector.ofInt32 8 (getAddrRegSize src))
  let regSave = tmpVar (getAddrRegSize src)
  let baseReg = getBaseReg src
  let t0, t1, t2, t3 = tmpVars4 2<rt>
  let t4, t5, t6, t7 = tmpVars4 2<rt>
  let tmp8 = tmpVar 8<rt>
  let zero2 = num0 2<rt>
  let three2 = numI32 3 2<rt>
  let xRegs =
    [ R.XMM0; R.XMM1; R.XMM2; R.XMM3; R.XMM4; R.XMM5; R.XMM6; R.XMM7;
      R.XMM8; R.XMM9; R.XMM10; R.XMM11; R.XMM12; R.XMM13; R.XMM14; R.XMM15 ]
  builder <! (regSave := baseReg)
  builder <! (tmp8 := extract src 8<rt> 32)
  builder <! (t0 := ite (extractLow 1<rt> tmp8) zero2 three2)
  builder <! (t1 := ite (extract tmp8 1<rt> 1) zero2 three2)
  builder <! (t2 := ite (extract tmp8 1<rt> 2) zero2 three2)
  builder <! (t3 := ite (extract tmp8 1<rt> 3) zero2 three2)
  builder <! (t4 := ite (extract tmp8 1<rt> 4) zero2 three2)
  builder <! (t5 := ite (extract tmp8 1<rt> 5) zero2 three2)
  builder <! (t6 := ite (extract tmp8 1<rt> 6) zero2 three2)
  builder <! (t7 := ite (extract tmp8 1<rt> 7) zero2 three2)
  builder <! (grv R.FCW := extractLow 16<rt> src)
  builder <! (grv R.FSW := extract src 16<rt> 16)
  builder <! (grv R.FTW := concat (concat (concat t7 t6) (concat t5 t4))
                                  (concat (concat t3 t2) (concat t1 t0)))
  builder <! (grv R.FOP := extract src 16<rt> 48)
  builder <! (updateAddrByOffset src offset)
  builder <! (extractLow 32<rt> (grv R.FIP) := extractLow 32<rt> src)
  builder <! (grv R.FCS := extract src 16<rt> 32)
  builder <! (updateAddrByOffset src offset)
  builder <! (extractLow 32<rt> (grv R.FDP) := extractLow 32<rt> src)
  builder <! (grv R.FDS := extract src 16<rt> 32)
  builder <! (updateAddrByOffset src offset)
  builder <! (grv R.MXCSR := extractLow 32<rt> src)
  builder <! (grv R.MXCSRMASK := extractHigh 32<rt> src)
  loadFxrstorMMX src grv builder
  loadFxrstorXMM ctxt src (List.rev xRegs) builder
  builder <! (baseReg := regSave)

let loadLegacyFxrstor ctxt src builder =
  let grv r = getRegVar ctxt r
  let offset = num (BitVector.ofInt32 8 (getAddrRegSize src))
  let xRegs = [ R.XMM0; R.XMM1; R.XMM2; R.XMM3; R.XMM4; R.XMM5; R.XMM6; R.XMM7 ]
  let tSrc = tmpVar 64<rt>
  builder <! (tSrc := src)
  builder <! (grv R.FCW := extractLow 16<rt> tSrc)
  builder <! (grv R.FSW := extract tSrc 16<rt> 16)
  builder <! (grv R.FTW := extract tSrc 8<rt> 32)
  builder <! (grv R.FOP := extract tSrc 16<rt> 48)
  builder <! (updateAddrByOffset src offset)
  builder <! (tSrc := src)
  builder <! (extractLow 32<rt> (grv R.FIP) := extractLow 32<rt> tSrc)
  builder <! (grv R.FCS := extract tSrc 16<rt> 32)
  builder <! (updateAddrByOffset src offset)
  builder <! (tSrc := src)
  builder <! (extractLow 32<rt> (grv R.FDP) := extractLow 32<rt> tSrc)
  builder <! (grv R.FDS := extract tSrc 16<rt> 32)
  builder <! (updateAddrByOffset src offset)
  builder <! (tSrc := src)
  builder <! (grv R.MXCSR := extractLow 32<rt> tSrc)
  builder <! (grv R.MXCSRMASK := extractHigh 32<rt>tSrc)
  loadFxrstorMMX src grv builder
  loadFxrstorXMM ctxt src xRegs builder

let fpuFBinOp ins insAddr insLen ctxt binOp doPop leftToRight =
  let builder = new StmtBuilder (64)
  let res = tmpVar 80<rt>
  startMark insAddr insLen builder
  match ins.Operands with
  | NoOperand ->
    let st0 = fpuRegValue ctxt R.ST0
    let st1 = fpuRegValue ctxt R.ST1
    if leftToRight then builder <! (res := binOp st0 st1)
    else builder <! (res := binOp st1 st0)
    assignFPUReg R.ST1 res ctxt builder
    checkC1Flag ctxt builder R.FTW6
  | OneOperand opr ->
    let oprExpr = transOprToFloat80 ins insAddr insLen ctxt opr
    let st0 = fpuRegValue ctxt R.ST0
    if leftToRight then builder <! (res := binOp st0 oprExpr)
    else builder <! (res := binOp oprExpr st0)
    assignFPUReg R.ST0 res ctxt builder
    checkC1Flag ctxt builder R.FTW7
  | TwoOperands (OprReg reg1, opr2) ->
    let oprExpr1 = getRegVar ctxt reg1
    let oprExpr2 = transOprToExpr ins insAddr insLen ctxt opr2
    if leftToRight then builder <! (res := binOp oprExpr1 oprExpr2)
    else builder <! (res := binOp oprExpr2 oprExpr1)
    assignFPUReg reg1 res ctxt builder
  | _ -> raise InvalidOperandException
  if doPop then popFPUStack ctxt builder else ()
  endMark insAddr insLen builder

let fpuIntOp ins insAddr insLen ctxt binOp leftToRight =
  let builder = new StmtBuilder (8)
  let st0 = fpuRegValue ctxt R.ST0
  let oprExpr = getOneOpr ins |> transOprToExpr ins insAddr insLen ctxt
  let tmp = tmpVar 80<rt>
  startMark insAddr insLen builder
  builder <! (tmp := cast CastKind.IntToFloat 80<rt> oprExpr)
  if leftToRight then builder <! (tmp := binOp st0 tmp)
  else builder <! (tmp := binOp tmp st0)
  assignFPUReg R.ST0 tmp ctxt builder
  endMark insAddr insLen builder

let fabs _ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let st0b, _st0a = getFPUPseudoRegVars ctxt R.ST0
  startMark insAddr insLen builder
  builder <! (extract st0b 1<rt> 15 := b1)
  builder <! (getRegVar ctxt R.FSWC1 := b0)
  builder <! (getRegVar ctxt R.FSWC0 := undefC0)
  builder <! (getRegVar ctxt R.FSWC2 := undefC2)
  builder <! (getRegVar ctxt R.FSWC3 := undefC3)
  endMark insAddr insLen builder

let fcmov ins insAddr insLen ctxt cond =
  let builder = new StmtBuilder (8)
  let _dst, src = getTwoOprs ins
  let src = transOprToExpr ins insAddr insLen ctxt src
  let st0b, st0a = getFPUPseudoRegVars ctxt R.ST0
  startMark insAddr insLen builder
  builder <! (st0a := ite cond (extractLow 64<rt> src) st0a)
  builder <! (st0b := ite cond (extractHigh 16<rt> src) st0b)
  builder <! (getRegVar ctxt R.FSWC0 := undefC0)
  builder <! (getRegVar ctxt R.FSWC2 := undefC2)
  builder <! (getRegVar ctxt R.FSWC3 := undefC3)
  endMark insAddr insLen builder

let f2xm1 _isn insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let st0 = fpuRegValue ctxt R.ST0
  let flt1 = num1 32<rt> |> cast CastKind.IntToFloat 80<rt>
  let flt2 = numI32 2 32<rt> |> cast CastKind.IntToFloat 80<rt>
  let tmp = tmpVar 80<rt>
  startMark insAddr insLen builder
  builder <! (tmp := fpow flt2 st0)
  builder <! (tmp := fsub tmp flt1)
  assignFPUReg R.ST0 tmp ctxt builder
  checkC1Flag ctxt builder R.FTW7
  cflagsUndefined023 ctxt builder
  endMark insAddr insLen builder

let fpuadd ins insAddr insLen ctxt doPop =
  fpuFBinOp ins insAddr insLen ctxt fadd doPop true

let fbld ins insAddr insLen ctxt =
  let builder = new StmtBuilder (64)
  let src = getOneOpr ins |> transOprToExpr ins insAddr insLen ctxt
  let sign = extractHigh 1<rt> src
  let intgr = tmpVar 64<rt>
  let bcdNum = tmpVar 72<rt>
  let tmp = tmpVar 80<rt>
  startMark insAddr insLen builder
  bcdToInt intgr bcdNum builder
  builder <! (extractHigh 1<rt> intgr := sign)
  builder <! (tmp := cast CastKind.IntToFloat 80<rt> intgr)
  checkFPUOnLoad ctxt builder
  shiftFPUStackDown ctxt builder
  assignFPUReg R.ST0 tmp ctxt builder
  updateTagWordOnLoad ctxt builder
  endMark insAddr insLen builder

let fbstp ins insAddr insLen ctxt =
  let builder = new StmtBuilder (64)
  let dst = getOneOpr ins |> transOprToExpr ins insAddr insLen ctxt
  let st0 = fpuRegValue ctxt R.ST0
  let sign = extractHigh 1<rt> st0
  let intgr = tmpVar 64<rt>
  let bcdNum = tmpVar 72<rt>
  let tmp = tmpVar 80<rt>
  startMark insAddr insLen builder
  builder <! (intgr := cast CastKind.FtoIRound 64<rt> st0)
  intTobcd bcdNum intgr builder
  builder <! (tmp := num0 80<rt>)
  builder <! (extractHigh 1<rt> tmp := sign)
  builder <! (extractLow 72<rt> tmp := bcdNum)
  builder <! (dst := tmp)
  endMark insAddr insLen builder

let fcmovb ins insAddr insLen ctxt =
  getRegVar ctxt R.CF |> fcmov ins insAddr insLen ctxt

let fcmove ins insAddr insLen ctxt =
  getRegVar ctxt R.ZF |> fcmov ins insAddr insLen ctxt

let fcmovbe ins insAddr insLen ctxt =
  (getRegVar ctxt R.CF .| getRegVar ctxt R.ZF) |> fcmov ins insAddr insLen ctxt

let fcmovu ins insAddr insLen ctxt =
  getRegVar ctxt R.PF |> fcmov ins insAddr insLen ctxt

let fcmovnb ins insAddr insLen ctxt =
  getRegVar ctxt R.CF |> not |> fcmov ins insAddr insLen ctxt

let fcmovne ins insAddr insLen ctxt =
  getRegVar ctxt R.ZF |> not |> fcmov ins insAddr insLen ctxt

let fcmovnbe ins insAddr insLen ctxt =
  let cond1 = getRegVar ctxt R.CF |> not
  let cond2 = getRegVar ctxt R.ZF |> not
  cond1 .& cond2 |> fcmov ins insAddr insLen ctxt

let fcmovnu ins insAddr insLen ctxt =
  getRegVar ctxt R.PF |> not |> fcmov ins insAddr insLen ctxt

let fchs _ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let st0b, _st0a = getFPUPseudoRegVars ctxt R.ST0
  let tmp = tmpVar 1<rt>
  startMark insAddr insLen builder
  builder <! (tmp := extractHigh 1<rt> st0b)
  builder <! (extractHigh 1<rt> st0b := not tmp)
  builder <! (getRegVar ctxt R.FSWC1 := b0)
  builder <! (getRegVar ctxt R.FSWC0 := undefC0)
  builder <! (getRegVar ctxt R.FSWC2 := undefC2)
  builder <! (getRegVar ctxt R.FSWC3 := undefC3)
  endMark insAddr insLen builder

let fclex _ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let stsWrd = getRegVar ctxt R.FSW
  startMark insAddr insLen builder
  builder <! (extractLow 7<rt> stsWrd := num0 7<rt>)
  builder <! (extractHigh 1<rt> stsWrd := b0)
  builder <! (getRegVar ctxt R.FSWC0 := undefC0)
  builder <! (getRegVar ctxt R.FSWC1 := undefC1)
  builder <! (getRegVar ctxt R.FSWC2 := undefC2)
  builder <! (getRegVar ctxt R.FSWC3 := undefC3)
  endMark insAddr insLen builder

let fcom ins insAddr insLen ctxt nPop unordered =
  let builder = new StmtBuilder (64)
  let lblNan = lblSymbol "IsNan"
  let lblExit = lblSymbol "Exit"
  let c0 = getRegVar ctxt R.FSWC0
  let c2 = getRegVar ctxt R.FSWC2
  let c3 = getRegVar ctxt R.FSWC3
  let im = getRegVar ctxt R.FCW |> extractLow 1<rt>
  let tmp1, tmp2 = tmpVars2 80<rt>
  startMark insAddr insLen builder
  match ins.Operands with
  | NoOperand ->
    builder <! (tmp1 := fpuRegValue ctxt R.ST0)
    builder <! (tmp2 := fpuRegValue ctxt R.ST1)
  | OneOperand opr ->
    let oprExpr = transOprToFloat80 ins insAddr insLen ctxt opr
    builder <! (tmp1 := fpuRegValue ctxt R.ST0)
    builder <! (tmp2 := oprExpr)
  | _ -> raise InvalidOperandException
  builder <! (c0 := ite (flt tmp1 tmp2) b1 b0)
  builder <! (c2 := b0)
  builder <! (c3 := ite (tmp1 == tmp2) b1 b0)
  let isNan expr =
    (extract expr 15<rt> 64  == num (BitVector.unsignedMax 15<rt>))
     .& (extractLow 62<rt> expr != num0 62<rt>)
  let cond =
    if unordered then
        let tmp1qNanCond = isNan tmp1 .& (extract tmp1 1<rt> 62 == b1)
        let tmp2qNanCond = isNan tmp2 .& (extract tmp2 1<rt> 62 == b1)
        tmp1qNanCond .| tmp2qNanCond .& (im == b0)
    else isNan tmp1 .| isNan tmp2 .& (im == b0)
  builder <! (CJmp (cond, Name lblNan, Name lblExit))
  builder <! (LMark lblNan)
  builder <! (c0 := b1)
  builder <! (c2 := b1)
  builder <! (c3 := b1)
  builder <! (LMark lblExit)
  builder <! (getRegVar ctxt R.FSWC1 := b0)
  if nPop > 0 then popFPUStack ctxt builder else ()
  if nPop = 2 then popFPUStack ctxt builder else ()
  endMark insAddr insLen builder

let fcomi ins insAddr insLen ctxt doPop =
  let builder = new StmtBuilder (64)
  let opr1, opr2 = getTwoOprs ins
  let opr1 = transOprToExpr ins insAddr insLen ctxt opr1
  let opr2 = transOprToExpr ins insAddr insLen ctxt opr2
  let im = getRegVar ctxt R.FCW |> extractLow 1<rt>
  let lblQNan = lblSymbol "IsQNan"
  let lblNan = lblSymbol "IsNan"
  let lblExit = lblSymbol "Exit"
  let lblCond = lblSymbol "IsNanCond"
  let zf = getRegVar ctxt R.ZF
  let pf = getRegVar ctxt R.PF
  let cf = getRegVar ctxt R.CF
  startMark insAddr insLen builder
  builder <! (zf := ite (opr1 == opr2) b1 b0)
  builder <! (pf := b0)
  builder <! (cf := ite (flt opr1 opr2) b1 b0)
  let opr1NanCond =
    (extract opr1 15<rt> 64  == num (BitVector.unsignedMax 15<rt>))
      .& (extractLow 62<rt> opr1 != num0 62<rt>)
  let opr2NanCond =
    (extract opr2 15<rt> 64 == num (BitVector.unsignedMax 15<rt>))
      .& (extractLow 62<rt> opr2 != num0 62<rt>)
  let cond = opr1NanCond .| opr2NanCond .& (im == b0)
  match ins.Opcode with
  | Opcode.FCOMI | Opcode.FCOMIP ->
    builder <! (CJmp (cond, Name lblNan, Name lblExit))
  | Opcode.FUCOMI | Opcode.FUCOMIP ->
    let opr1qNanCond = opr1NanCond .& (extract opr1 1<rt> 62 == b1)
    let opr2qNanCond = opr2NanCond .& (extract opr2 1<rt> 62 == b1)
    builder <! (CJmp (opr1qNanCond .| opr2qNanCond, Name lblQNan, Name lblCond))
    builder <! (LMark lblQNan)
    builder <! (zf:= b1)
    builder <! (pf := b1)
    builder <! (cf := b1)
    builder <! (Jmp (Name lblExit))
    builder <! (LMark lblCond)
    builder <! (CJmp (cond, Name lblNan, Name lblExit))
  | _ -> raise InvalidOpcodeException
  builder <! (LMark lblNan)
  builder <! (zf := b1)
  builder <! (pf := b1)
  builder <! (cf := b1)
  builder <! (LMark lblExit)
  if doPop then popFPUStack ctxt builder else ()
  endMark insAddr insLen builder

let ftrig _ins insAddr insLen ctxt trigFunc =
  let builder = new StmtBuilder (32)
  let st0 = fpuRegValue ctxt R.ST0
  let tmp = tmpVar 80<rt>
  let float80SignUnmask = BitVector.signedMax 80<rt> |> num
  let maxLimit = numI64 (1L <<< 63) 64<rt>
  let maxFloat = cast CastKind.IntToFloat 80<rt> maxLimit
  let num3 = BitVector.ofInt32 3 2<rt> |> num
  let c0 = getRegVar ctxt R.FSWC0
  let c1 = getRegVar ctxt R.FSWC1
  let c2 = getRegVar ctxt R.FSWC2
  let c3 = getRegVar ctxt R.FSWC3
  let lblOutOfRange = lblSymbol "IsOutOfRange"
  let lblInRange = lblSymbol "IsInRange"
  let tmp = tmpVar 80<rt>
  startMark insAddr insLen builder
  builder <! (tmp := st0 .& float80SignUnmask)
  builder <! (CJmp (flt tmp maxFloat, Name lblInRange, Name lblOutOfRange ))
  builder <! (LMark lblInRange)
  builder <! (tmp := trigFunc st0)
  assignFPUReg R.ST0 tmp ctxt builder
  builder <! (c1 := ite (getRegVar ctxt R.FTW7 == num3) b0 c1)
  builder <! (c2 := b0)
  builder <! (c0 := undefC0)
  builder <! (c3 := undefC3)
  builder <! (LMark lblOutOfRange)
  builder <! (c2 := b1)
  builder <! (c0 := undefC0)
  builder <! (c1 := undefC1)
  builder <! (c3 := undefC3)
  endMark insAddr insLen builder

let fcos ins insAddr insLen ctxt =
  ftrig ins insAddr insLen ctxt fCos

let fdecstp _ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let top = getRegVar ctxt R.FTOP
  startMark insAddr insLen builder
  builder <! (top := top .+ num1 3<rt>)
  builder <! (getRegVar ctxt R.FSWC1 := b0)
  builder <! (getRegVar ctxt R.FSWC0 := undefC0)
  builder <! (getRegVar ctxt R.FSWC2 := undefC2)
  builder <! (getRegVar ctxt R.FSWC3 := undefC3)
  endMark insAddr insLen builder

let fpudiv ins insAddr insLen ctxt doPop =
  fpuFBinOp ins insAddr insLen ctxt fdiv doPop true

let fdivr ins insAddr insLen ctxt doPop =
  fpuFBinOp ins insAddr insLen ctxt fdiv doPop false

let ffree ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let top = getRegVar ctxt R.FTOP
  let tagWord = getRegVar ctxt R.FTW
  let top16,shifter, tagValue = tmpVars3 16<rt>
  let value3 = BitVector.ofInt32 3 16<rt> |> num
  let offset =
    match getOneOpr ins with
    | OprReg R.ST0 -> BitVector.ofInt32 0 16<rt> |> num
    | OprReg R.ST1 -> BitVector.ofInt32 1 16<rt> |> num
    | OprReg R.ST2 -> BitVector.ofInt32 2 16<rt> |> num
    | OprReg R.ST3 -> BitVector.ofInt32 3 16<rt> |> num
    | OprReg R.ST4 -> BitVector.ofInt32 4 16<rt> |> num
    | OprReg R.ST5 -> BitVector.ofInt32 5 16<rt> |> num
    | OprReg R.ST6 -> BitVector.ofInt32 6 16<rt> |> num
    | OprReg R.ST7 -> BitVector.ofInt32 7 16<rt> |> num
    | _ -> raise InvalidOperandException
  startMark insAddr insLen builder
  builder <! (top16 := cast CastKind.ZeroExt 16<rt> top)
  builder <! (top16 := top16 .+ offset)
  builder <! (shifter := (BitVector.ofInt32 2 16<rt> |> num) .* top16)
  builder <! (tagValue := (value3 << shifter))
  builder <! (tagWord := tagWord .| tagValue)
  endMark insAddr insLen builder

let fiadd ins insAddr insLen ctxt =
  fpuIntOp ins insAddr insLen ctxt fadd true

let ficom ins insAddr insLen ctxt doPop =
  let builder = new StmtBuilder (32)
  let oprExpr = getOneOpr ins |> transOprToExpr ins insAddr insLen ctxt
  let st0 = fpuRegValue ctxt R.ST0
  let tmp = tmpVar 80<rt>
  startMark insAddr insLen builder
  builder <! (tmp := cast CastKind.IntToFloat 80<rt> oprExpr)
  builder <! (getRegVar ctxt R.FSWC0 := ite (flt st0 tmp) b1 b0)
  builder <! (getRegVar ctxt R.FSWC2 := b0)
  builder <! (getRegVar ctxt R.FSWC3 := ite (st0 == tmp) b1 b0)
  builder <! (getRegVar ctxt R.FSWC1 := b0)
  if doPop then popFPUStack ctxt builder else ()
  endMark insAddr insLen builder

let fidiv ins insAddr insLen ctxt =
  fpuIntOp ins insAddr insLen ctxt fdiv true

let fidivr ins insAddr insLen ctxt =
  fpuIntOp ins insAddr insLen ctxt fdiv false

let fild ins insAddr insLen ctxt =
  let builder = new StmtBuilder (32)
  let oprExpr = getOneOpr ins |> transOprToExpr ins insAddr insLen ctxt
  let tmp = tmpVar 80<rt>
  startMark insAddr insLen builder
  builder <! (tmp := cast CastKind.IntToFloat 80<rt> oprExpr)
  checkFPUOnLoad ctxt builder
  shiftFPUStackDown ctxt builder
  assignFPUReg R.ST0 tmp ctxt builder
  updateTagWordOnLoad ctxt builder
  endMark insAddr insLen builder

let fimul ins insAddr insLen ctxt =
  fpuIntOp ins insAddr insLen ctxt fmul true

let fincstp _ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let top = getRegVar ctxt R.FTOP
  startMark insAddr insLen builder
  builder <! (top := top .+ num1 3<rt>)
  builder <! (getRegVar ctxt R.FSWC1 := b0)
  builder <! (getRegVar ctxt R.FSWC0 := undefC0)
  builder <! (getRegVar ctxt R.FSWC2 := undefC2)
  builder <! (getRegVar ctxt R.FSWC3 := undefC3)
  endMark insAddr insLen builder

// FixMe: check all unmasked pending floating point exceptions.
let checkFPUExceptions ctxt builder = ()

let clearFPU ctxt builder =
  let cw = BitVector.ofInt32 895 16<rt> |> num
  let tw = BitVector.maxNum16 |> num
  builder <! (getRegVar ctxt R.FCW := cw)
  builder <! (getRegVar ctxt R.FSW := num0 16<rt>)
  builder <! (getRegVar ctxt R.FTW := tw)

let finit _ins insAddr insLen ctxt =
  let builder = new StmtBuilder (32)
  startMark insAddr insLen builder
  checkFPUExceptions ctxt builder
  clearFPU ctxt builder
  endMark insAddr insLen builder

let fist ins insAddr insLen ctxt doPop =
  let builder = new StmtBuilder (32)
  let oprExpr = getOneOpr ins |> transOprToExpr ins insAddr insLen ctxt
  let sz = AST.typeOf oprExpr
  let st0 = fpuRegValue ctxt R.ST0
  let tmp1 = tmpVar sz
  let tmp2 = tmpVar 2<rt>
  let num2 = numI32 2 2<rt>
  let cstK castKind = cast castKind sz st0
  startMark insAddr insLen builder
  builder <! (tmp2 := extract (getRegVar ctxt R.FCW) 2<rt> 10)
  builder <! (tmp1 := ite (tmp2 == num0 2<rt>)
    (cstK CastKind.FtoIRound) (cstK CastKind.FtoITrunc))
  builder <! (tmp1 := ite (tmp2 == num1 2<rt>) (cstK CastKind.FtoIFloor) tmp1)
  builder <! (tmp1 := ite (tmp2 == num2) (cstK CastKind.FtoICeil) tmp1)
  builder <! (oprExpr := tmp1)
  builder <! (getRegVar ctxt R.FSWC1 := ite (tmp2 == num2) b1 b0)
  cflagsUndefined023 ctxt builder
  if doPop then popFPUStack ctxt builder else ()
  endMark insAddr insLen builder

let fisttp ins insAddr insLen ctxt =
  let builder = new StmtBuilder (64)
  let oprExpr = getOneOpr ins |> transOprToExpr ins insAddr insLen ctxt
  let sz = AST.typeOf oprExpr
  let st0 = fpuRegValue ctxt R.ST0
  startMark insAddr insLen builder
  builder <! (oprExpr := cast CastKind.FtoICeil sz st0)
  builder <! (getRegVar ctxt R.FSWC1 := b0)
  builder <! (getRegVar ctxt R.FSWC0 := undefC0)
  builder <! (getRegVar ctxt R.FSWC2 := undefC2)
  builder <! (getRegVar ctxt R.FSWC3 := undefC3)
  popFPUStack ctxt builder
  endMark insAddr insLen builder

let fninit _ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  startMark insAddr insLen builder
  clearFPU ctxt builder
  endMark insAddr insLen builder

let fnop _ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  startMark insAddr insLen builder
  allCFlagsUndefined ctxt builder
  endMark insAddr insLen builder

let fnstcw ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let oprExpr = getOneOpr ins |> transOprToExpr ins insAddr insLen ctxt
  startMark insAddr insLen builder
  builder <! (oprExpr := getRegVar ctxt R.FCW)
  allCFlagsUndefined ctxt builder
  endMark insAddr insLen builder

let fnstsw ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let oprExpr = getOneOpr ins |> transOprToExpr ins insAddr insLen ctxt
  startMark insAddr insLen builder
  builder <! (oprExpr := getRegVar ctxt R.FSW)
  allCFlagsUndefined ctxt builder
  endMark insAddr insLen builder

let fpatan _ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let c1 = getRegVar ctxt R.FSWC1
  let tmp = tmpVar 80<rt>
  startMark insAddr insLen builder
  builder <! (tmp := fpuRegValue ctxt R.ST1 ./ fpuRegValue ctxt R.ST0)
  builder <! (tmp := fAtan tmp)
  assignFPUReg R.ST1 tmp ctxt builder
  builder <! (c1 := b0)
  cflagsUndefined023 ctxt builder
  endMark insAddr insLen builder

let fptan _ins insAddr insLen ctxt =
  let builder = new StmtBuilder (64)
  let st0 = fpuRegValue ctxt R.ST0
  let float80SignUnmask = BitVector.signedMax 80<rt> |> num
  let maxLimit = numI64 (1L <<< 63) 64<rt>
  let maxFloat = cast CastKind.IntToFloat 80<rt> maxLimit
  let num3 = BitVector.ofInt32 3 2<rt> |> num
  let c0 = getRegVar ctxt R.FSWC0
  let c1 = getRegVar ctxt R.FSWC1
  let c2 = getRegVar ctxt R.FSWC2
  let c3 = getRegVar ctxt R.FSWC3
  let lblOutOfRange = lblSymbol "IsOutOfRange"
  let lblInRange = lblSymbol "IsInRange"
  let tmp = tmpVar 80<rt>
  let tmp64 = tmpVar 64<rt>
  startMark insAddr insLen builder
  builder <! (tmp := st0 .& float80SignUnmask)
  builder <! (CJmp (flt tmp maxFloat, Name lblInRange, Name lblOutOfRange ))
  builder <! (LMark lblInRange)
  builder <! (tmp := fTan st0)
  assignFPUReg R.ST0 tmp ctxt builder
  builder <! (c1 := ite (getRegVar ctxt R.FTW7 == num3) b0 c1)
  builder <! (c2 := b0)
  builder <! (c0 := undefC0)
  builder <! (c3 := undefC3)
  builder <! (LMark lblOutOfRange)
  builder <! (c2 := b1)
  builder <! (c0 := undefC0)
  builder <! (c1 := undefC1)
  builder <! (c3 := undefC3)
  builder <! (tmp64 := numI64 4607182418800017408L 64<rt>)
  builder <! (tmp := cast CastKind.FloatExt 80<rt> tmp64)
  checkFPUOnLoad ctxt builder
  shiftFPUStackDown ctxt builder
  assignFPUReg R.ST0 tmp ctxt builder
  updateTagWordOnLoad ctxt builder
  endMark insAddr insLen builder

let fisub ins insAddr insLen ctxt =
  fpuIntOp ins insAddr insLen ctxt fsub true

let fisubr ins insAddr insLen ctxt =
  fpuIntOp ins insAddr insLen ctxt fsub false

let fpumul ins insAddr insLen ctxt doPop =
  fpuFBinOp ins insAddr insLen ctxt fmul doPop true

let fprem _ins insAddr insLen ctxt round =
  let builder = new StmtBuilder (32)
  let st0 = fpuRegValue ctxt R.ST0
  let st1 = fpuRegValue ctxt R.ST1
  let caster = if round then CastKind.FtoIRound else CastKind.FtoITrunc
  let lblLT64 = lblSymbol "ExpDiffInRange"
  let lblGT64 = lblSymbol "ExpDiffOutOfRange"
  let lblExit = lblSymbol "Exit"
  let expDiff = tmpVar 15<rt>
  let tmp80A, tmp80B, tmpres = tmpVars3 80<rt>
  let tmp64 = tmpVar 64<rt>
  startMark insAddr insLen builder
  builder <! (expDiff := extract st0 15<rt> 64 .- extract st1 15<rt> 64)
  builder <! (CJmp (lt expDiff (numI32 64 15<rt>), Name lblLT64, Name lblGT64))
  builder <! (LMark lblLT64)
  builder <! (tmp80A := fdiv st0 st1)
  builder <! (tmp64 := cast caster 64<rt> tmp80A)
  builder <! (tmp80B := fmul st1 (cast CastKind.IntToFloat 80<rt> tmp64))
  builder <! (tmpres := fsub st0 tmp80B)
  assignFPUReg R.ST0 tmpres ctxt builder
  builder <! (getRegVar ctxt R.FSWC2 := b0)
  builder <! (getRegVar ctxt R.FSWC1 := extractLow 1<rt> tmp64)
  builder <! (getRegVar ctxt R.FSWC3 := extract tmp64 1<rt> 1)
  builder <! (getRegVar ctxt R.FSWC0 := extract tmp64 1<rt> 2)
  builder <! (Jmp (Name lblExit))
  builder <! (LMark lblGT64)
  builder <! (getRegVar ctxt R.FSWC2 := b1)
  builder <! (tmp64 := (zExt 64<rt> expDiff) .- numI32 63 64<rt>)
  builder <! (tmp64 := tmp64 .* numI32 2 64<rt>)
  builder <! (tmp80B := cast CastKind.IntToFloat 80<rt> tmp64)
  builder <! (tmp80A := fdiv (fdiv st0 st1) tmp80B)
  builder <! (tmp64 := cast CastKind.FtoITrunc 64<rt> tmp80A)
  builder <! (tmp80A := cast CastKind.IntToFloat 80<rt> tmp64)
  builder <! (tmp80A := fsub st0 (fmul st1 (fmul tmp80A tmp80B)))
  assignFPUReg R.ST0 tmp80A ctxt builder
  builder <! (LMark lblExit)
  endMark insAddr insLen builder

let frndint _ins insAddr insLen ctxt =
  let builder = new StmtBuilder (32)
  let st0 = fpuRegValue ctxt R.ST0
  let tmp = tmpVar 80<rt>
  let tmp1 = tmpVar 64<rt>
  let tmp2 = tmpVar 2<rt>
  let num2 = numI32 2 2<rt>
  let cstK castKind = cast castKind 64<rt> st0
  startMark insAddr insLen builder
  builder <! (tmp2 := extract (getRegVar ctxt R.FCW) 2<rt> 10)
  builder <! (tmp1 := ite (tmp2 == num0 2<rt>)
    (cstK CastKind.FtoIRound) (cstK CastKind.FtoITrunc))
  builder <! (tmp1 := ite (tmp2 == num1 2<rt>) (cstK CastKind.FtoIFloor) tmp1)
  builder <! (tmp1 := ite (tmp2 == num2) (cstK CastKind.FtoICeil) tmp1)
  builder <! (tmp := cast CastKind.IntToFloat 80<rt> tmp1)
  assignFPUReg R.ST0 tmp ctxt builder
  builder <! (getRegVar ctxt R.FSWC1 := ite (tmp2 == num2) b1 b0)
  cflagsUndefined023 ctxt builder
  endMark insAddr insLen builder

let fscale _ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let tmp1, tmp2 = tmpVars2 64<rt>
  let tmp3 = tmpVar 80<rt>
  let st0 = fpuRegValue ctxt R.ST0
  let st1 = fpuRegValue ctxt R.ST1
  startMark insAddr insLen builder
  builder <! (tmp1 := cast CastKind.FtoITrunc 64<rt> st1)
  builder <! (tmp2 := numI32 1 64<rt> << tmp1)
  builder <! (tmp3 := cast CastKind.IntToFloat 80<rt> tmp2)
  builder <! (tmp3 := fmul st0 tmp3)
  assignFPUReg R.ST0 tmp3 ctxt builder
  checkC1Flag ctxt builder R.FTW6
  cflagsUndefined023 ctxt builder
  endMark insAddr insLen builder

let fsin ins insAddr insLen ctxt =
  ftrig ins insAddr insLen ctxt fSin

let fsincos _ins insAddr insLen ctxt =
  let builder = new StmtBuilder (64)
  let st0 = fpuRegValue ctxt R.ST0
  let c0 = getRegVar ctxt R.FSWC0
  let c1 = getRegVar ctxt R.FSWC1
  let c2 = getRegVar ctxt R.FSWC2
  let c3 = getRegVar ctxt R.FSWC3
  let float80SignUnmask = BitVector.signedMax 80<rt> |> num
  let maxLimit = numI64 (1L <<< 63) 64<rt>
  let maxFloat = cast CastKind.IntToFloat 80<rt> maxLimit
  let num3 = BitVector.ofInt32 3 2<rt> |> num
  let lblOutOfRange = lblSymbol "IsOutOfRange"
  let lblInRange = lblSymbol "IsInRange"
  let tmp1, tmp2 = tmpVars2 80<rt>
  startMark insAddr insLen builder
  builder <! (tmp1 := st0 .& float80SignUnmask)
  builder <! (CJmp (flt tmp1 maxFloat, Name lblInRange, Name lblOutOfRange ))
  builder <! (LMark lblInRange)
  builder <! (tmp1 := fCos st0)
  builder <! (tmp2 := fSin st0)
  assignFPUReg R.ST0 tmp2 ctxt builder
  builder <! (c1 := ite (getRegVar ctxt R.FTW7 == num3) b0 c1)
  builder <! (c2 := b0)
  builder <! (c0 := undefC0)
  builder <! (c3 := undefC3)
  checkFPUOnLoad ctxt builder
  shiftFPUStackDown ctxt builder
  assignFPUReg R.ST0 tmp1 ctxt builder
  updateTagWordOnLoad ctxt builder
  builder <! (LMark lblOutOfRange)
  builder <! (c2 := b1)
  builder <! (c0 := undefC0)
  builder <! (c1 := undefC1)
  builder <! (c3 := undefC3)
  endMark insAddr insLen builder

let ffst ins insAddr insLen ctxt doPop =
  let builder = new StmtBuilder (32)
  let opr = getOneOpr ins
  let oprExpr = transOprToExpr ins insAddr insLen ctxt opr
  let st0 = fpuRegValue ctxt R.ST0
  let sz = AST.typeOf oprExpr
  let tmp = tmpVar sz
  startMark insAddr insLen builder
  builder <! (tmp := cast CastKind.FloatExt sz st0)
  match opr with
  | OprReg r -> assignFPUReg r tmp ctxt builder
  | _ -> builder <! (oprExpr := tmp)
  checkC1Flag ctxt builder R.FTW7
  cflagsUndefined023 ctxt builder
  if doPop then popFPUStack ctxt builder else ()
  endMark insAddr insLen builder

let fstcw ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let oprExpr = getOneOpr ins |> transOprToExpr ins insAddr insLen ctxt
  startMark insAddr insLen builder
  checkFPUExceptions ctxt builder
  builder <! (oprExpr := getRegVar ctxt R.FCW)
  allCFlagsUndefined ctxt builder
  endMark insAddr insLen builder

let fstsw ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let oprExpr = getOneOpr ins |> transOprToExpr ins insAddr insLen ctxt
  startMark insAddr insLen builder
  checkFPUExceptions ctxt builder
  builder <! (oprExpr := getRegVar ctxt R.FSW)
  allCFlagsUndefined ctxt builder
  endMark insAddr insLen builder

let ftst _ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let st0 = fpuRegValue ctxt R.ST0
  let num0V = num0 80<rt>
  let c0 = getRegVar ctxt R.FSWC0
  let c2 = getRegVar ctxt R.FSWC2
  let c3 = getRegVar ctxt R.FSWC3
  let lblNan = lblSymbol "IsNan"
  let lblExit = lblSymbol "Exit"
  startMark insAddr insLen builder
  builder <! (c0 := ite (flt st0 num0V) b1 b0)
  builder <! (c2 := b0)
  builder <! (c3 := ite (st0 == num0V) b1 b0)
  let st0Exponent = extract st0 15<rt> 64
  let st0NanCond =
    (st0Exponent == num (BitVector.unsignedMax 15<rt>))
     .& (extractLow 62<rt> st0 != num0 62<rt>)
  builder <! (CJmp (st0NanCond, Name lblNan, Name lblExit))
  builder <! (LMark lblNan)
  builder <! (c0 := b1)
  builder <! (c2 := b1)
  builder <! (c3 := b1)
  builder <! (LMark lblExit)
  builder <! (getRegVar ctxt R.FSWC1 := b0)
  endMark insAddr insLen builder

let fsqrt _ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let st0 = fpuRegValue ctxt R.ST0
  let tmp = tmpVar 80<rt>
  startMark insAddr insLen builder
  builder <! (tmp := unop UnOpType.FSQRT st0)
  assignFPUReg R.ST0 tmp ctxt builder
  checkC1Flag ctxt builder R.FTW7
  endMark insAddr insLen builder

let fpusub ins insAddr insLen ctxt doPop =
  fpuFBinOp ins insAddr insLen ctxt fsub doPop true

let fsubr ins insAddr insLen ctxt doPop =
  fpuFBinOp ins insAddr insLen ctxt fsub doPop false

let fpuLoad insAddr insLen ctxt oprExpr =
  let builder = new StmtBuilder (64)
  let tmp = tmpVar 80<rt>
  startMark insAddr insLen builder
  builder <! (tmp := cast CastKind.FloatExt 80<rt> oprExpr)
  checkFPUOnLoad ctxt builder
  shiftFPUStackDown ctxt builder
  assignFPUReg R.ST0 tmp ctxt builder
  updateTagWordOnLoad ctxt builder
  endMark insAddr insLen builder

let fld ins insAddr insLen ctxt =
  let opr = getOneOpr ins
  let oprExpr = transOprToExpr ins insAddr insLen ctxt opr
  fpuLoad insAddr insLen ctxt oprExpr

let fld1 _ins insAddr insLen ctxt =
  let oprExpr = BitVector.ofUInt64 0x3FF0000000000000UL 64<rt> |> num
  fpuLoad insAddr insLen ctxt oprExpr

let fldcw ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let oprExpr = getOneOpr ins |> transOprToExpr ins insAddr insLen ctxt
  startMark insAddr insLen builder
  builder <! (getRegVar ctxt R.FCW := oprExpr)
  builder <! (getRegVar ctxt R.FSWC0 := undefC0)
  builder <! (getRegVar ctxt R.FSWC1 := undefC1)
  builder <! (getRegVar ctxt R.FSWC2 := undefC2)
  builder <! (getRegVar ctxt R.FSWC3 := undefC3)
  endMark insAddr insLen builder

let fldl2t _ins insAddr insLen ctxt =
  let oprExpr = BitVector.ofUInt64 4614662735865160561UL 64<rt> |> num
  fpuLoad insAddr insLen ctxt oprExpr

let fldl2e _ins insAddr insLen ctxt =
  let oprExpr = BitVector.ofUInt64 4599094494223104509UL 64<rt> |> num
  fpuLoad insAddr insLen ctxt oprExpr

let fldpi _ins insAddr insLen ctxt =
  let oprExpr = BitVector.ofUInt64 4614256656552045848UL 64<rt> |> num
  fpuLoad insAddr insLen ctxt oprExpr

let fldlg2 _ins insAddr insLen ctxt =
  let oprExpr = BitVector.ofUInt64 4599094494223104511UL 64<rt> |> num
  fpuLoad insAddr insLen ctxt oprExpr

let fldln2 _ins insAddr insLen ctxt =
  let oprExpr = BitVector.ofUInt64 4604418534313441775UL 64<rt> |> num
  fpuLoad insAddr insLen ctxt oprExpr

let fldz _ins insAddr insLen ctxt =
  let oprExpr = num0 64<rt>
  fpuLoad insAddr insLen ctxt oprExpr

let m14Stenv dst ctxt builder =
  let v r = getRegVar ctxt r
  let tmp = tmpVar 112<rt>
  builder <! (tmp := num0 112<rt>)
  builder <! (extractLow 48<rt> tmp := concat (v R.FCW)
                                        (concat (v R.FSW) (v R.FTW)))
  builder <! (extract tmp 16<rt> 48 := extractLow 16<rt> (v R.FIP))
  builder <! (extract tmp 11<rt> 64 := extractLow 11<rt> (v R.FOP))
  builder <! (extract tmp 4<rt> 76 := extract (v R.FIP) 4<rt> 16)
  builder <! (extract tmp 16<rt> 80 := extractLow 16<rt> (v R.FDP))
  builder <! (extractHigh 4<rt> tmp := extract (v R.FDP) 4<rt> 16)
  builder <! (dst := tmp)

let m14fldenv src ctxt builder =
  let v r = getRegVar ctxt r
  let tmp = tmpVar 112<rt>
  builder <! (tmp := src)
  builder <! (v R.FCW := extractLow 16<rt> tmp)
  builder <! (v R.FSW := extract tmp 16<rt> 16)
  builder <! (v R.FTW := extract tmp 16<rt> 32)
  builder <! (extractLow 16<rt> (v R.FIP) := extract tmp 16<rt> 48)
  builder <! (extractLow 11<rt> (v R.FOP) := extract tmp 11<rt> 64)
  builder <! (extract (v R.FIP) 4<rt> 16 := extract tmp 4<rt> 76)
  builder <! (extractLow 16<rt> (v R.FDP) := extract tmp 16<rt> 80)
  builder <! (extract (v R.FDP) 4<rt> 16 := extractHigh 4<rt> tmp)

let m28fldenv src ctxt builder =
  let v r = getRegVar ctxt r
  let tmp = tmpVar 224<rt>
  builder <! (tmp := src)
  builder <! (v R.FCW := extractLow 16<rt> tmp)
  builder <! (v R.FSW := extract tmp 16<rt> 32)
  builder <! (v R.FTW := extract tmp 16<rt> 64)
  builder <! (extractLow 16<rt> (v R.FIP) := extract tmp 16<rt> 96)
  builder <! (extractLow 11<rt> (v R.FOP) := extract tmp 11<rt> 128)
  builder <! (extract (v R.FIP) 16<rt> 16 := extract tmp 16<rt> 139)
  builder <! (extractLow 16<rt> (v R.FDP) := extract tmp 16<rt> 160)
  builder <! (extract (v R.FDP) 16<rt> 16 := extract tmp 16<rt> 204)

let m28fstenv dst ctxt builder =
  let v r = getRegVar ctxt r
  let tmp = tmpVar 224<rt>
  builder <! (tmp := num0 224<rt>)
  builder <! (extractLow 16<rt> tmp := v R.FCW)
  builder <! (extract tmp 16<rt> 32 := v R.FSW)
  builder <! (extract tmp 16<rt> 64 := v R.FTW)
  builder <! (extract tmp 16<rt> 96 := extractLow 16<rt> (v R.FIP))
  builder <! (extract tmp 11<rt> 128 := extractLow 11<rt> (v R.FOP))
  builder <! (extract tmp 16<rt> 139 := extract (v R.FIP) 16<rt> 16)
  builder <! (extract tmp 16<rt> 160 := extractLow 16<rt> (v R.FDP))
  builder <! (extract tmp 16<rt> 204 := extract (v R.FDP) 16<rt> 16)
  builder <! (dst := tmp)

let ldSts src ctxt builder =
  assignFPUReg R.ST0 (extractLow 80<rt> src) ctxt builder
  assignFPUReg R.ST1 (extract src 80<rt> 80) ctxt builder
  assignFPUReg R.ST2 (extract src 80<rt> 160) ctxt builder
  assignFPUReg R.ST3 (extract src 80<rt> 240) ctxt builder
  assignFPUReg R.ST4 (extract src 80<rt> 320) ctxt builder
  assignFPUReg R.ST5 (extract src 80<rt> 400) ctxt builder
  assignFPUReg R.ST6 (extract src 80<rt> 480) ctxt builder
  assignFPUReg R.ST7 (extract src 80<rt> 560) ctxt builder

let stSts dst ctxt builder =
  let v r = getRegVar ctxt r
  builder <! (extractLow 80<rt> dst := v R.ST0)
  builder <! (extract dst 80<rt> 80 := v R.ST1)
  builder <! (extract dst 80<rt> 160 := v R.ST2)
  builder <! (extract dst 80<rt> 240 := v R.ST3)
  builder <! (extract dst 80<rt> 320 := v R.ST4)
  builder <! (extract dst 80<rt> 400 := v R.ST5)
  builder <! (extract dst 80<rt> 480 := v R.ST6)
  builder <! (extract dst 80<rt> 560 := v R.ST7)

let fldenv ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let src = getOneOpr ins |> transOprToExpr ins insAddr insLen ctxt
  startMark insAddr insLen builder
  match AST.typeOf src with
  | 112<rt> -> m14fldenv src ctxt builder
  | 224<rt> -> m28fldenv src ctxt builder
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let frstor ins insAddr insLen ctxt =
  let builder = new StmtBuilder (32)
  let src = getOneOpr ins |> transOprToExpr ins insAddr insLen ctxt
  startMark insAddr insLen builder
  match AST.typeOf src with
  | 752<rt> ->
    m14fldenv (extractLow 112<rt> src) ctxt builder
  | 864<rt> ->
    m28fldenv (extractLow 224<rt> src) ctxt builder
  | _ -> raise InvalidOperandSizeException
  ldSts (extractHigh 640<rt> src) ctxt builder
  endMark insAddr insLen builder

let fsave ins insAddr insLen ctxt =
  let builder = new StmtBuilder (32)
  let dst = getOneOpr ins |> transOprToExpr ins insAddr insLen ctxt
  let v r = getRegVar ctxt r
  startMark insAddr insLen builder
  m14Stenv (extractLow 112<rt> dst) ctxt builder
  stSts (extractHigh 640<rt> dst) ctxt builder
  builder <! (v R.FCW := numI32 0x037F 16<rt>)
  builder <! (v R.FSW := num0 16<rt>)
  builder <! (v R.FTW := numI32 0xFFFF 16<rt>)
  builder <! (v R.FDP := num0 16<rt>)
  builder <! (v R.FIP := num0 16<rt>)
  builder <! (v R.FOP := num0 16<rt>)
  endMark insAddr insLen builder

let fstenv ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let dst = getOneOpr ins |> transOprToExpr ins insAddr insLen ctxt
  startMark insAddr insLen builder
  match AST.typeOf dst with
  | 112<rt> -> m14Stenv dst ctxt builder
  | 224<rt> -> m28fstenv dst ctxt builder
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let fxam _ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let st0 = fpuRegValue ctxt R.ST0
  let exponent = extract st0 15<rt> 64
  let maxExponent = BitVector.unsignedMax 15<rt> |> num
  let tag7 = getRegVar ctxt R.FTW7
  let nanCond =
    (exponent == maxExponent) .& (extractLow 62<rt> st0 != num0 62<rt>)
  let c3Cond1 = (tag7 == numI32 3 2<rt>) .| (exponent == num0 15<rt>)
  let c2Cond0 = (tag7 == numI32 3 2<rt>) .| (st0 == num0 80<rt>) .| nanCond
  let c0Cond1 = (tag7 == numI32 3 2<rt>) .| (exponent == maxExponent)
  startMark insAddr insLen builder
  builder <! (getRegVar ctxt R.FSWC1 := extractHigh 1<rt> st0)
  builder <! (getRegVar ctxt R.FSWC3 := ite (c3Cond1) b1 b0)
  builder <! (getRegVar ctxt R.FSWC2 := ite (c2Cond0) b0 b1)
  builder <! (getRegVar ctxt R.FSWC0 := ite (c0Cond1) b1 b0)
  endMark insAddr insLen builder

let fxtract _ins insAddr insLen ctxt =
  let builder = new StmtBuilder (64)
  let st0 = fpuRegValue ctxt R.ST0
  let tmp = tmpVar 80<rt>
  let exponent = tmpVar 64<rt>
  let significand = tmpVar 80<rt>
  startMark insAddr insLen builder
  builder <! (exponent := num0 64<rt>)
  builder <! (significand := num0 80<rt>)
  builder <! (extractLow 64<rt> significand := extractLow 64<rt> st0)
  builder <! (extractHigh 1<rt> significand := extractHigh 1<rt> st0)
  builder <! (extract significand 15<rt> 64 := numI32 16383 15<rt>)
  builder <! (extractLow 15<rt> exponent := extract st0 15<rt> 64)
  builder <! (exponent := exponent .- numI32 16383 64<rt>)
  builder <! (tmp := cast CastKind.IntToFloat 80<rt> exponent)
  assignFPUReg R.ST0 tmp ctxt builder
  checkFPUOnLoad ctxt builder
  shiftFPUStackDown ctxt builder
  assignFPUReg R.ST0 significand ctxt builder
  updateTagWordOnLoad ctxt builder
  checkC1Flag ctxt builder R.FTW7
  cflagsUndefined023 ctxt builder
  endMark insAddr insLen builder

let fyl2x _ins insAddr insLen ctxt =
  let builder = new StmtBuilder (64)
  let st0 = fpuRegValue ctxt R.ST0
  let st1 = fpuRegValue ctxt R.ST1
  let flt2 = numI32 2 32<rt> |> cast CastKind.IntToFloat 80<rt>
  let t1, t2 = tmpVars2 80<rt>
  startMark insAddr insLen builder
  builder <! (t1 := flog flt2 st0)
  builder <! (t2 := fmul st1 t1)
  assignFPUReg R.ST1 t2 ctxt builder
  popFPUStack ctxt builder
  checkC1Flag ctxt builder R.FTW6
  cflagsUndefined023 ctxt builder
  endMark insAddr insLen builder

let fyl2xp1 _ins insAddr insLen ctxt =
  let builder = new StmtBuilder (64)
  let st0 = fpuRegValue ctxt R.ST0
  let st1 = fpuRegValue ctxt R.ST1
  let flt2 = numI32 2 32<rt> |> cast CastKind.IntToFloat 80<rt>
  let f1 = numI32 1 32<rt> |> cast CastKind.IntToFloat 80<rt>
  let tmp = tmpVar 80<rt>
  startMark insAddr insLen builder
  builder <! (tmp := fadd f1 (flog flt2 st0))
  builder <! (tmp := fmul st1 tmp)
  assignFPUReg R.ST1 tmp ctxt builder
  popFPUStack ctxt builder
  checkC1Flag ctxt builder R.FTW6
  cflagsUndefined023 ctxt builder
  endMark insAddr insLen builder

let fxrstor ins insAddr insLen ctxt =
  let builder = new StmtBuilder (128)
  let src = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  let eSrc = extendAddr src 64<rt>
  startMark insAddr insLen builder
  if ctxt.WordBitSize = 64<rt> then
    if hasREXW ins.REXPrefix then load64BitPromotedFxrstor ctxt eSrc builder
    else load64BitDefaultFxrstor ctxt eSrc builder
  else loadLegacyFxrstor ctxt eSrc builder
  endMark insAddr insLen builder

let fxch ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let tmp = tmpVar 80<rt>
  let st0 = fpuRegValue ctxt R.ST0
  startMark insAddr insLen builder
  match ins.Operands with
  | OneOperand (OprReg reg as opr) ->
      let oprExpr = transOprToExpr ins insAddr insLen ctxt opr
      builder <! (tmp := st0)
      assignFPUReg R.ST0 oprExpr ctxt builder
      assignFPUReg reg tmp ctxt builder
  | NoOperand ->
      let st1 = fpuRegValue ctxt R.ST1
      builder <! (tmp := st0)
      assignFPUReg R.ST0 st1 ctxt builder
      assignFPUReg R.ST1 tmp ctxt builder
  | _ -> raise InvalidOperandException
  builder <! (getRegVar ctxt R.FSWC1 := b0)
  cflagsUndefined023 ctxt builder
  endMark insAddr insLen builder

let fxsave ins insAddr insLen ctxt =
  let builder = new StmtBuilder (128)
  let dst = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  let eDst = extendAddr dst 64<rt>
  startMark insAddr insLen builder
  if ctxt.WordBitSize = 64<rt> then
    if hasREXW ins.REXPrefix then save64BitPromotedFxsave ctxt eDst builder
    else save64BitDefaultFxsave ctxt eDst builder
  else saveLegacyFxsave ctxt eDst builder
  endMark insAddr insLen builder

let imul ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
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
  let builder = new StmtBuilder (16)
  let dst = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let t1, t2, t3 = tmpVars3 oprSize
  startMark insAddr insLen builder
  builder <! (t1 := dst)
  builder <! (t2 := num1 oprSize)
  builder <! (t3 := (t1 .+ t2))
  builder <! (dstAssign oprSize dst t3)
  builder <! (getRegVar ctxt R.OF := getOFlagOnAdd t1 t2 t3)
  enumASZPFlags ctxt t1 t2 t3 oprSize builder
  endMark insAddr insLen builder

let insinstr ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  startMark insAddr insLen builder
  let body () =
    let oprSize = getOperationSize ins
    let df = getRegVar ctxt R.DF
    let di = getRegVar ctxt (if is64bit ctxt then R.RDI else R.EDI)
    let src = zExt ctxt.WordBitSize (getRegVar ctxt R.DX)
    builder <! (loadLE ctxt.WordBitSize di := src)
    let amount = numI32 (RegType.toByteWidth oprSize) ctxt.WordBitSize
    builder <! (di := ite df (di .- amount) (di .+ amount))
  if hasREPZ ins.Prefixes then
    strRepeat ctxt body None insAddr insLen builder
  elif hasREPNZ ins.Prefixes then raise InvalidPrefixException
  else body ()
  endMark insAddr insLen builder

let interrupt ins insAddr insLen ctxt =
  match getOneOpr ins |> transOneOpr ins insAddr insLen ctxt with
  | Num n -> Interrupt (BitVector.toInt32 n) |> sideEffects insAddr insLen
  | _ -> raise InvalidOperandException

let jcc ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let pc = getInstrPtr ctxt
  let jmpTarget = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let cond = getCondOfJcc ins ctxt oprSize
  let fallThrough =
    bvOfBaseAddr insAddr ctxt .+ bvOfInstrLen insLen ctxt
  startMark insAddr insLen builder
  builder <! (InterCJmp (cond, pc, jmpTarget, fallThrough))
  endMark insAddr insLen builder

let jmp ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let opr = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  let pc = getInstrPtr ctxt
  startMark insAddr insLen builder
  builder <! (InterJmp (pc, opr, InterJmpInfo.Base))
  endMark insAddr insLen builder

let lddqu ins insAddr insLen ctxt = buildMove ins insAddr insLen ctxt 4

let lea ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let src = convertSrc src
  let addrSize = getEffAddrSz ins
  startMark insAddr insLen builder
  match oprSize, addrSize with
  | 16<rt>, 16<rt> | 32<rt>, 32<rt> | 64<rt>, 64<rt> ->
    builder <! (dstAssign oprSize dst src)
  | 16<rt>, 32<rt> | 16<rt>, 64<rt> ->
    builder <! (dstAssign oprSize dst (extractLow 16<rt> src))
  | 32<rt>, 16<rt> -> builder <! (dstAssign oprSize dst (zExt 32<rt> src))
  | 32<rt>, 64<rt> -> builder <! (dstAssign oprSize dst (extractLow 32<rt> src))
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let leave ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let sp = getStackPtr ctxt
  let bp = getBasePtr ctxt
  startMark insAddr insLen builder
  builder <! (sp := bp)
  auxPop ctxt.WordBitSize ctxt bp builder
  endMark insAddr insLen builder

let lods ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  startMark insAddr insLen builder
  let body () =
    let oprSize = getOperationSize ins
    let df = getRegVar ctxt R.DF
    let di = getRegVar ctxt (if is64bit ctxt then R.RDI else R.EDI)
    let dst = getRegOfSize ctxt oprSize GrpEAX
    builder <! (dst := loadLE oprSize di)
    let amount = numI32 (RegType.toByteWidth oprSize) ctxt.WordBitSize
    builder <! (di := ite df (di .- amount) (di .+ amount))
  if hasREPZ ins.Prefixes then
    strRepeat ctxt body None insAddr insLen builder
  elif hasREPNZ ins.Prefixes then raise InvalidPrefixException
  else body ()
  endMark insAddr insLen builder

let ldmxcsr ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let src = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  startMark insAddr insLen builder
  builder <! (getRegVar ctxt R.MXCSR := src)
  endMark insAddr insLen builder

let loop ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
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
  builder <! (count := count .- num1 cntSize)
  let branchCond =
    match ins.Opcode with
    | Opcode.LOOP -> count != num0 cntSize
    | Opcode.LOOPE -> (zf == b1) .& (count != num0 cntSize)
    | Opcode.LOOPNE -> (zf == b0) .& (count != num0 cntSize)
    | _ -> raise InvalidOpcodeException
  let fallThrough = bvOfBaseAddr insAddr ctxt .+ bvOfInstrLen insLen ctxt
  let jumpTarget = if oprSize = 16<rt> then pc .& numI32 0xFFFF 32<rt>
                   else sExt oprSize dst
  builder <! (InterCJmp (branchCond, pc, jumpTarget, fallThrough))
  endMark insAddr insLen builder

let lzcnt ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let lblLoop = lblSymbol "Loop"
  let lblExit = lblSymbol "Exit"
  let lblLoopCond = lblSymbol "LoopCond"
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let num0 = num0 oprSize
  startMark insAddr insLen builder
  let temp = tmpVar oprSize
  builder <! (temp := numI32 (RegType.toBitWidth oprSize - 1) oprSize)
  builder <! (dst := num0)
  builder <! (LMark lblLoopCond)
  let cond1 = (ge temp num0) .& ((extractLow 1<rt> (src >> temp)) == b0)
  builder <! (CJmp (cond1, Name lblLoop, Name lblExit))
  builder <! (LMark lblLoop)
  builder <! (temp := temp .- num1 oprSize)
  builder <! (dst := dst .+ num1 oprSize)
  builder <! (Jmp (Name lblLoopCond))
  builder <! (LMark lblExit)
  let oprSize = numI32 (RegType.toBitWidth oprSize) oprSize
  builder <! (getRegVar ctxt R.CF := dst == oprSize)
  builder <! (getRegVar ctxt R.ZF := dst == num0)
  builder <! (getRegVar ctxt R.OF := undefOF)
  builder <! (getRegVar ctxt R.SF := undefSF)
  builder <! (getRegVar ctxt R.PF := undefPF)
  builder <! (getRegVar ctxt R.AF := undefAF)
  endMark insAddr insLen builder

let minMaxPD ins insAddr insLen ctxt compare =
  let builder = new StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
  let val2, val1 = tmpVars2 64<rt>
  startMark insAddr insLen builder
  builder <! (val1 := ite (compare dst1 src1) dst1 src1)
  builder <! (val2 := ite (compare dst2 src2) dst2 src2)
  builder <! (dst1 := val1)
  builder <! (dst2 := val2)
  endMark insAddr insLen builder

let minMaxPS ins insAddr insLen ctxt compare =
  let builder = new StmtBuilder (16)
  let dst, src = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
  let dst1A, dst1B = extractLow 32<rt> dst1, extractHigh 32<rt> dst1
  let dst2A, dst2B = extractLow 32<rt> dst2, extractHigh 32<rt> dst2
  let src1A, src1B = extractLow 32<rt> src1, extractHigh 32<rt> src1
  let src2A, src2B = extractLow 32<rt> src2, extractHigh 32<rt> src2
  let val4, val3, val2, val1 = tmpVars4 32<rt>
  startMark insAddr insLen builder
  builder <! (val1 := ite (compare dst1A src1A) dst1A src1A)
  builder <! (val2 := ite (compare dst1B src1B) dst1B src1B)
  builder <! (val3 := ite (compare dst2A src2A) dst2A src2A)
  builder <! (val4 := ite (compare dst2B src2B) dst2B src2B)
  builder <! (dst1A := val1)
  builder <! (dst1B := val2)
  builder <! (dst2A := val3)
  builder <! (dst2B := val4)
  endMark insAddr insLen builder

let minMaxSD ins insAddr insLen ctxt compare =
  let builder = new StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr64 ins insAddr insLen ctxt dst
  let src = transOprToExpr64 ins insAddr insLen ctxt src
  let tmp = tmpVar 64<rt>
  startMark insAddr insLen builder
  builder <! (tmp := ite (compare dst src) dst src)
  builder <! (dst := tmp)
  endMark insAddr insLen builder

let minMaxSS ins insAddr insLen ctxt compare =
  let builder = new StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr32 ins insAddr insLen ctxt dst
  let src = transOprToExpr32 ins insAddr insLen ctxt src
  let tmp = tmpVar 32<rt>
  startMark insAddr insLen builder
  builder <! (tmp := ite (compare dst src) dst src)
  builder <! (dst := tmp)
  endMark insAddr insLen builder

let maxpd ins insAddr insLen ctxt =
  minMaxPD ins insAddr insLen ctxt fgt

let maxps ins insAddr insLen ctxt =
  minMaxPS ins insAddr insLen ctxt fgt

let maxsd ins insAddr insLen ctxt =
  minMaxSD ins insAddr insLen ctxt fgt

let maxss ins insAddr insLen ctxt =
  minMaxSS ins insAddr insLen ctxt fgt

let minpd ins insAddr insLen ctxt =
  minMaxPD ins insAddr insLen ctxt flt

let minps ins insAddr insLen ctxt =
  minMaxPS ins insAddr insLen ctxt flt

let minsd ins insAddr insLen ctxt =
  minMaxSD ins insAddr insLen ctxt flt

let minss ins insAddr insLen ctxt =
  minMaxSS ins insAddr insLen ctxt flt

let mov ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  builder <! (dstAssign oprSize dst (zExt oprSize src))
  endMark insAddr insLen builder

let movapd ins insAddr insLen ctxt = buildMove ins insAddr insLen ctxt 4
let movaps ins insAddr insLen ctxt = buildMove ins insAddr insLen ctxt 4

let movbe ins insAddr insLen ctxt =
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let t = tmpVar oprSize
  let cnt = RegType.toByteWidth oprSize |> int
  let tmps = Array.init cnt (fun _ -> tmpVar 8<rt>)
  let builder = new StmtBuilder (2 * cnt)
  startMark insAddr insLen builder
  builder <! (t := src)
  for i in 0 .. cnt - 1 do
    builder <! (tmps.[i] := extract t 8<rt> (i * 8))
  done
  builder <! (dstAssign oprSize dst (concatExprs (Array.rev tmps)))
  endMark insAddr insLen builder

let movd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src = getTwoOprs ins
  startMark insAddr insLen builder
  match dst, src  with
  | OprReg r1, OprReg r2 -> movdRegToReg ctxt r1 r2 builder
  | OprMem _, OprReg r -> let dst = transOprToExpr ins insAddr insLen ctxt dst
                          movdRegToMem ctxt dst r builder
  | OprReg r, OprMem _ -> let src = transOprToExpr ins insAddr insLen ctxt src
                          movdMemToReg ctxt src r builder
  | _, _ -> raise InvalidOperandException
  endMark insAddr insLen builder

let movddup ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dst1, dst0 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src = transOprToExpr64 ins insAddr insLen ctxt src
  startMark insAddr insLen builder
  builder <! (dst0 := src)
  builder <! (dst1 := src)
  endMark insAddr insLen builder

let movdq2q ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr ins insAddr insLen ctxt dst
  let _, srcA = transOprToExpr128 ins insAddr insLen ctxt src
  startMark insAddr insLen builder
  builder <! (dst := srcA)
  endMark insAddr insLen builder

let movdqa ins insAddr insLen ctxt = buildMove ins insAddr insLen ctxt 4
let movdqu ins insAddr insLen ctxt = buildMove ins insAddr insLen ctxt 4

let movhpd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let dst, src = getTwoOprs ins
  startMark insAddr insLen builder
  match dst, src with
  | OprReg r, OprMem _ ->
    let src = transOprToExpr ins insAddr insLen ctxt src
    builder <! (getPseudoRegVar ctxt r 2 := src)
  | OprMem _, OprReg r ->
    let dst = transOprToExpr ins insAddr insLen ctxt dst
    builder <! (dst := getPseudoRegVar ctxt r 1)
  | _ -> raise InvalidOperandException
  endMark insAddr insLen builder

let movhlps ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr128 ins insAddr insLen ctxt dst |> snd
  let src = transOprToExpr128 ins insAddr insLen ctxt src |> fst
  startMark insAddr insLen builder
  builder <! (dst := src)
  endMark insAddr insLen builder

let movhps ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let dst, src = getTwoOprs ins
  startMark insAddr insLen builder
  match dst, src with
  | OprMem (_, _, _, 64<rt>), OprReg r ->
    let dst = transOprToExpr ins insAddr insLen ctxt dst
    builder <! (dst := getPseudoRegVar ctxt r 2)
  | OprReg r, OprMem (_, _, _, 64<rt>)->
    let src = transOprToExpr ins insAddr insLen ctxt src
    builder <! (getPseudoRegVar ctxt r 2 := src)
  | _ -> raise InvalidOperandException
  endMark insAddr insLen builder

let movlhps ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr128 ins insAddr insLen ctxt dst |> fst
  let src = transOprToExpr128 ins insAddr insLen ctxt src |> snd
  startMark insAddr insLen builder
  builder <! (dst := src)
  endMark insAddr insLen builder

let movlpd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let dst, src = getTwoOprs ins
  startMark insAddr insLen builder
  match dst, src with
  | OprReg r, OprMem _ ->
    let src = transOprToExpr ins insAddr insLen ctxt src
    builder <! (getPseudoRegVar ctxt r 1 := src)
  | OprMem _, OprReg r ->
    let dst = transOprToExpr ins insAddr insLen ctxt dst
    builder <! (dst := getPseudoRegVar ctxt r 1)
  | _ -> raise InvalidOperandException
  endMark insAddr insLen builder

let movlps ins insAddr insLen ctxt = movlpd ins insAddr insLen ctxt

let movmskpd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr ins insAddr insLen ctxt dst
  let src1, src2 = transOprToExpr128 ins insAddr insLen ctxt src
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  let src63 = sExt oprSize (extractHigh 1<rt> src2)
  let src127 = (sExt oprSize (extractHigh 1<rt> src1)) << num1 oprSize
  builder <! (dst := src63 .| src127)
  endMark insAddr insLen builder

let movmskps ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr ins insAddr insLen ctxt dst
  let srcB, srcA= transOprToExpr128 ins insAddr insLen ctxt src
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  let srcA = concat (extract srcA 1<rt> 63) (extract srcA 1<rt> 31)
  let srcB = concat (extract srcB 1<rt> 63) (extract srcB 1<rt> 31)
  builder <! (dst := zExt oprSize <| concat srcB srcA)
  endMark insAddr insLen builder

let movntdq ins insAddr insLen ctxt = buildMove ins insAddr insLen ctxt 4

let movntpd ins insAddr insLen ctxt = buildMove ins insAddr insLen ctxt 4

let movntps ins insAddr insLen ctxt = buildMove ins insAddr insLen ctxt 4

let movnti ins insAddr insLen ctxt = buildMove ins insAddr insLen ctxt 4

let movntq ins insAddr insLen ctxt = buildMove ins insAddr insLen ctxt 4

let movq ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let dst, src = getTwoOprs ins
  startMark insAddr insLen builder
  match dst, src with
  | OprReg r1, OprReg r2 -> movqRegToReg ctxt r1 r2 builder
  | OprMem _, OprReg r -> let dst = transOprToExpr ins insAddr insLen ctxt dst
                          movqRegToMem ctxt dst r builder
  | OprReg r, OprMem _ -> let src = transOprToExpr ins insAddr insLen ctxt src
                          movqMemToReg ctxt src r builder
  | _, _ -> raise InvalidOperandException
  endMark insAddr insLen builder

let movq2dq ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
  let src = transOprToExpr ins insAddr insLen ctxt src
  startMark insAddr insLen builder
  builder <! (dstA := src)
  builder <! (dstB := num0 64<rt>)
  endMark insAddr insLen builder

let movs ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  startMark insAddr insLen builder
  let body () =
    let oprSize = getOperationSize ins
    let df = getRegVar ctxt R.DF
    let si = getRegVar ctxt (if is64bit ctxt then R.RSI else R.ESI)
    let di = getRegVar ctxt (if is64bit ctxt then R.RDI else R.EDI)
    builder <! (loadLE oprSize di := loadLE oprSize si)
    let amount = numI32 (RegType.toByteWidth oprSize) ctxt.WordBitSize
    builder <! (si := ite df (si .- amount) (si .+ amount))
    builder <! (di := ite df (di .- amount) (di .+ amount))
  if hasREPZ ins.Prefixes then
    strRepeat ctxt body None insAddr insLen builder
  elif hasREPNZ ins.Prefixes then raise InvalidPrefixException
  else body ()
  endMark insAddr insLen builder

let movsd (ins: InsInfo) insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  if ins.Operands = Operands.NoOperand then movs ins insAddr insLen ctxt
  else
    let dst, src = getTwoOprs ins
    startMark insAddr insLen builder
    match dst, src with
    | OprReg r1, OprReg r2 ->
      let dst = getPseudoRegVar ctxt r1 1
      let src = getPseudoRegVar ctxt r2 1
      builder <! (dst := src)
    | OprReg r1, OprMem _ ->
      let dst2, dst1 = getPseudoRegVar128 ctxt r1
      let src = transOprToExpr ins insAddr insLen ctxt src
      builder <! (dst1 := src)
      builder <! (dst2 := num0 64<rt>)
    | OprMem _ , OprReg r1 ->
      let dst = transOprToExpr ins insAddr insLen ctxt dst
      let src = getPseudoRegVar ctxt r1 1
      builder <! (dstAssign 64<rt> dst src)
    | _ -> raise InvalidOperandException
    endMark insAddr insLen builder

let movss (ins: InsInfo) insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let dst, src = getTwoOprs ins
  startMark insAddr insLen builder
  match dst, src with
  | OprReg r1, OprReg r2 ->
    let dst = getPseudoRegVar ctxt r1 1 |> extractLow 32<rt>
    let src = getPseudoRegVar ctxt r2 1 |> extractLow 32<rt>
    builder <! (dst := src)
  | OprReg r1, OprMem _ ->
    let dst2, dst1 = getPseudoRegVar128 ctxt r1
    let src = transOprToExpr ins insAddr insLen ctxt src
    builder <! (dstAssign 32<rt> dst1 src)
    builder <! (dst2 := num0 64<rt>)
  | OprMem _ , OprReg r1 ->
    let dst = transOprToExpr ins insAddr insLen ctxt dst
    let src = getPseudoRegVar ctxt r1 1 |> extractLow 32<rt>
    builder <! (dstAssign 32<rt> dst src)
  | _ -> raise InvalidOperandException
  endMark insAddr insLen builder

let movshdup ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
  let tmp1, tmp2 = tmpVars2 32<rt>
  startMark insAddr insLen builder
  builder <! (tmp1 := extractHigh 32<rt> src1)
  builder <! (tmp2 := extractHigh 32<rt> src2)
  builder <! (extractLow 32<rt> dst1 := tmp1)
  builder <! (extractHigh 32<rt> dst1 := tmp1)
  builder <! (extractLow 32<rt> dst2 := tmp2)
  builder <! (extractHigh 32<rt> dst2 := tmp2)
  endMark insAddr insLen builder

let movsldup ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
  let tmp1, tmp2 = tmpVars2 32<rt>
  startMark insAddr insLen builder
  builder <! (tmp1 := extractLow 32<rt> src1)
  builder <! (tmp2 := extractLow 32<rt> src2)
  builder <! (extractLow 32<rt> dst1 := tmp1)
  builder <! (extractHigh 32<rt> dst1 := tmp1)
  builder <! (extractLow 32<rt> dst2 := tmp2)
  builder <! (extractHigh 32<rt> dst2 := tmp2)
  endMark insAddr insLen builder

let movsx ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  builder <! (dstAssign oprSize dst (sExt oprSize src))
  endMark insAddr insLen builder

let movupd ins insAddr insLen ctxt = buildMove ins insAddr insLen ctxt 4

let movups ins insAddr insLen ctxt = buildMove ins insAddr insLen ctxt 4

let movzx ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  builder <! (dstAssign oprSize dst (zExt oprSize src))
  endMark insAddr insLen builder

let mul ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let oprSize = getOperationSize ins
  let dblWidth = RegType.double oprSize
  let src1 = zExt dblWidth (getRegOfSize ctxt oprSize GrpEAX)
  let src2 = zExt dblWidth (getOneOpr ins |> transOneOpr ins insAddr insLen ctxt)
  let t = tmpVar dblWidth
  startMark insAddr insLen builder
  builder <! (t := src1 .* src2)
  let cond = tmpVar 1<rt>
  match oprSize with
  | 8<rt> -> builder <! (getRegVar ctxt R.AX := t)
  | 16<rt> | 32<rt> | 64<rt> ->
    builder <! (getRegOfSize ctxt oprSize GrpEDX := extractHigh oprSize t)
    builder <! (getRegOfSize ctxt oprSize GrpEAX := extractLow oprSize t)
  | _ -> raise InvalidOperandSizeException
  builder <! (cond := extractHigh oprSize t != (num0 oprSize))
  builder <! (getRegVar ctxt R.CF := cond)
  builder <! (getRegVar ctxt R.OF := cond)
  builder <! (getRegVar ctxt R.SF := undefSF)
  builder <! (getRegVar ctxt R.ZF := undefZF)
  builder <! (getRegVar ctxt R.AF := undefAF)
  builder <! (getRegVar ctxt R.PF := undefPF)
  endMark insAddr insLen builder

let neg ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let dst = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let t = tmpVar oprSize
  let oFCond = t == (num1 oprSize << (numU32 31u oprSize) )
  startMark insAddr insLen builder
  builder <! (t := dst)
  builder <! (dstAssign oprSize dst (neg t))
  builder <! (getRegVar ctxt R.CF := t != num0 oprSize)
  builder <! (getRegVar ctxt R.OF := oFCond)
  enumASZPFlags ctxt t (num0 oprSize) dst oprSize builder
  endMark insAddr insLen builder

let nop insAddr insLen =
  let builder = new StmtBuilder (4)
  startMark insAddr insLen builder
  endMark insAddr insLen builder

let not ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let dst = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  builder <! (dstAssign oprSize dst (unop UnOpType.NOT dst))
  endMark insAddr insLen builder

let logOr ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let t = tmpVar oprSize
  startMark insAddr insLen builder
  builder <! (t := (dst .| sExt oprSize src))
  builder <! (dstAssign oprSize dst t)
  builder <! (getRegVar ctxt R.CF := b0)
  builder <! (getRegVar ctxt R.OF := b0)
  builder <! (getRegVar ctxt R.AF := undefAF)
  enumSZPFlags ctxt t oprSize builder
  endMark insAddr insLen builder

let opPor _ = Array.map2 (.|)

let orpd ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opPor 16

let orps ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> opPor 16

let outs ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  startMark insAddr insLen builder
  let body () =
    let oprSize = getOperationSize ins
    let df = getRegVar ctxt R.DF
    let si = getRegVar ctxt (if is64bit ctxt then R.RSI else R.ESI)
    let src = getRegVar ctxt R.DX
    let amount = numI32 (RegType.toByteWidth oprSize) ctxt.WordBitSize
    match oprSize with
    | 8<rt> ->
      builder <! (src := zExt 16<rt> (loadLE oprSize si))
      builder <! (si := ite df (si .- amount) (si .+ amount))
    | 16<rt> ->
      builder <! (src := loadLE oprSize si)
      builder <! (si := ite df (si .- amount) (si .+ amount))
    | 32<rt> ->
      builder <! (si := ite df (si .- amount) (si .+ amount))
      builder <! (src := extractLow 16<rt> (loadLE oprSize si))
    | _ -> raise InvalidOperandSizeException
  if hasREPZ ins.Prefixes then
    strRepeat ctxt body None insAddr insLen builder
  elif hasREPNZ ins.Prefixes then raise InvalidPrefixException
  else body ()
  endMark insAddr insLen builder

let opPackssdw _ src1 src2 =
  Array.append src1 src2 |> Array.map saturateSignedDwordToSignedWord

let packssdw ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> opPackssdw 16

let opPacksswb _ src1 src2 =
  Array.append src1 src2 |> Array.map saturateSignedWordToSignedByte

let packsswb ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 16<rt> opPacksswb 16

let opPackuswb _ src1 src2 =
  Array.append src1 src2 |> Array.map saturateSignedWordToUnsignedByte

let packuswb ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 16<rt> opPackuswb 16

let paddb ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 8<rt> (opP (.+)) 8

let paddd ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> (opP (.+)) 8

let paddq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> (opP (.+)) 8

let opPaddsb oprSize src1 src2 =
  (opP (.+)) oprSize src1 src2 |> Array.map saturateToSignedByte

let paddsb ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 8<rt> opPaddsb 16

let opPaddsw oprSize src1 src2 =
  (opP (.+)) oprSize src1 src2 |> Array.map saturateToSignedWord

let paddsw ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 16<rt> opPaddsw 16

let opPaddusb oprSize src1 src2 =
  (opP (.+)) oprSize src1 src2 |> Array.map saturateToUnsignedByte

let paddusb ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 8<rt> opPaddusb 16

let opPaddusw oprSize src1 src2 =
  (opP (.+)) oprSize src1 src2 |> Array.map saturateToUnsignedWord

let paddusw ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 16<rt> opPaddusw 16

let paddw ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 16<rt> (opP (.+)) 8

let palignr ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src, imm = getThreeOprs ins
  let imm = transOprToExpr ins insAddr insLen ctxt imm
  startMark insAddr insLen builder
  match getOperationSize ins with
  | 64<rt> ->
    let dst = transOprToExpr ins insAddr insLen ctxt dst
    let src = transOprToExpr ins insAddr insLen ctxt src
    let t = tmpVar 128<rt>
    builder <!
      (t := (concat dst src) >> (zExt 128<rt> (imm .* numU32 8u 64<rt>)))
    builder <! (dst := extractLow 64<rt> t)
  | 128<rt> ->
    let dst1, dst2 = transOprToExpr128 ins insAddr insLen ctxt dst
    let src1, src2 = transOprToExpr128 ins insAddr insLen ctxt src
    let dst = concat dst1 dst2
    let src = concat src1 src2
    let t = tmpVar 256<rt>
    builder <!
      (t := (concat dst src) >> (zExt 256<rt> (imm .* numU32 8u 128<rt>)))
    builder <! (dst1 := extract t 64<rt> 64)
    builder <! (dst2 := extractLow 64<rt> t)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let pand ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opPand 8

let pandn ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opPandn 8

let opAveragePackedInt (packSz: int<rt>) =
  let dblSz = packSz * 2
  let dblExt expr = zExt dblSz expr
  let avg e1 e2 = extract (dblExt e1 .+ dblExt e2 .+ num1 dblSz) packSz 1
  Array.map2 avg

let opPavgb _ = opAveragePackedInt 8<rt>

let pavgb ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 8<rt> opPavgb 64

let opPavgw _ = opAveragePackedInt 16<rt>

let pavgw ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 16<rt> opPavgw 32

let opPcmp packSz cmpOp =
  Array.map2 (fun e1 e2 -> ite (cmpOp e1 e2) (getMask packSz) (num0 packSz))

let opPcmpeqb _ = opPcmp 8<rt> (==)
let opPcmpeqd _ = opPcmp 32<rt> (==)
let opPcmpeqq _ = opPcmp 64<rt> (==)
let opPcmpeqw _ = opPcmp 16<rt> (==)
let opPcmpgtb _ = opPcmp 8<rt> sgt
let opPcmpgtd _ = opPcmp 32<rt> sgt
let opPcmpgtw _ = opPcmp 16<rt> sgt

let pcmpeqb ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 8<rt> opPcmpeqb 32

let pcmpeqd ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> opPcmpeqd 16

let pcmpeqq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opPcmpeqq 8

let pcmpeqw ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 16<rt> opPcmpeqw 32

let pcmpgtb ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 8<rt> opPcmpgtb 32

let pcmpgtd ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> opPcmpgtd 16

let pcmpgtw ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 16<rt> opPcmpgtw 32

let aggOpr ins insAddr insLen
           ctxt ctrl src1 src2 ck1 ck2 (res1 : Expr []) builder =
  let nElem = int ctrl.NumElems
  let elemSz = RegType.fromBitWidth <| nElem
  let boolRes = genBoolRes ins insAddr insLen ctrl ctxt src2 src1 ck2 ck1
  let rangesCmp idx =
    match ctrl.Sign, idx % 2 = 0 with
    | Signed, true -> sge | Signed, _ -> sle | _, true -> ge | _, _ -> le
  match ctrl.Agg with
  | EqualAny ->
    for j in 0 .. nElem - 1 do
      let tRes = [| for _ in 1 .. nElem -> tmpVar elemSz |]
      let boolRes i = boolRes j i (==)
      builder <! (tRes.[0] := num0 elemSz .| boolRes 0)
      for i in 1 .. nElem - 1 do
        builder <! (tRes.[i] := tRes.[i - 1] .| boolRes i)
      done
      builder <! (res1.[j] := tRes.[nElem - 1] << numI32 j elemSz)
    done
  | EqualEach ->
    for i in 0 .. nElem - 1 do
      let boolRes i = boolRes i i (==)
      builder <! (res1.[i] := boolRes i << numI32 i elemSz)
    done
  | EqualOrdered ->
    for j in 0 .. nElem - 1 do
      let tRes = [| for _ in 1 .. nElem -> tmpVar elemSz |]
      let boolRes k i = boolRes k i (==)
      builder <! (tRes.[0] := numI32 -1 elemSz .& boolRes j 0)
      for i in 1 .. nElem - 1 - j do
        let k = i + j
        builder <! (tRes.[i] := tRes.[i - 1] .& boolRes k i)
      done
      builder <! (res1.[j] := tRes.[nElem - 1] << numI32 j elemSz)
    done
  | Ranges ->
    for j in 0 .. nElem - 1 do
      let tRes = [| for _ in 1 .. nElem -> tmpVar elemSz |]
      let cmp i = rangesCmp i
      let boolRes i = boolRes j i (cmp i)
      builder <! (tRes.[0] := num0 elemSz .| (boolRes 0 .& boolRes 1))
      for i in 2 .. 2 .. nElem - 1 do
        builder <!
          (tRes.[i] := tRes.[i - 1] .| (boolRes i .& boolRes (i + 1)))
      done
      builder <! (res1.[j] := tRes.[nElem - 1] << numI32 j elemSz)
    done

let getZSFForPCMPSTR ins insAddr insLen ctrl ctxt src1 src2 builder =
  let src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
  let src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt src2
  let getExZSFlag r =
    let reg = getRegVar ctxt r
    lt (ite (extractHigh 1<rt> reg) (AST.neg reg) reg)
       (numU32 ctrl.NumElems 32<rt>)
  let rec getImZSFlag acc srcB srcA idx =
    let packSz = ctrl.PackSize
    let packWidth = RegType.toBitWidth packSz
    let half = ctrl.NumElems / 2u |> int
    let e, amount = if idx < half then srcA, idx else srcB, idx - half
    let v e = e >> numI32 (amount * packWidth) 64<rt>
    let next, cond = idx - 1, idx = 0
    if cond then ite (extractLow packSz (v e) == num0 packSz) b1 acc
    else let acc = ite (extractLow packSz (v e) == num0 packSz) b1 acc
         getImZSFlag acc srcB srcA next
  match ctrl.Len with
  | Implicit ->
    builder <! (getRegVar ctxt R.ZF :=
      getImZSFlag b0 src2B src2A (ctrl.NumElems - 1u |> int))
    builder <! (getRegVar ctxt R.SF :=
      getImZSFlag b0 src1B src1A (ctrl.NumElems - 1u |> int))
  | Explicit ->
    builder <! (getRegVar ctxt R.ZF := getExZSFlag R.EDX)
    builder <! (getRegVar ctxt R.SF := getExZSFlag R.EAX)

let pcmpStrRet (ins: InsInfo) info ctxt intRes2 builder =
  let nElem = int info.NumElems
  let elemSz = RegType.fromBitWidth <| nElem
  match info.Ret with
  | Index ->
    let outSz, cx =
      if hasREXW ins.REXPrefix then 64<rt>, R.RCX else 32<rt>, R.ECX
    let cx = getRegVar ctxt cx
    let nMaxSz = numI32 nElem elemSz
    let idx = if info.OutSelect = Least then nElem - 1 else 0
    let out = zExt outSz <| genOutput info intRes2 nMaxSz idx
    builder <! (dstAssign outSz cx out)
  | Mask ->
    let xmmB, xmmA = getPseudoRegVar128 ctxt Register.XMM0
    let loop (acc1, acc2) i =
      let src = extract intRes2 1<rt> i
      if (i < nElem / 2) then (acc1, (zExt info.PackSize src) :: acc2)
      else ((zExt info.PackSize src) :: acc1, acc2)
    if info.OutSelect = Least then
      builder <! (xmmA := zExt 64<rt> intRes2)
      builder <! (xmmB := num0 64<rt>)
    else let r1, r2 = List.fold loop ([], []) [0 .. nElem - 1]
         builder <! (xmmB := concatExprs (List.toArray r1))
         builder <! (xmmA := concatExprs (List.toArray r2))

let pcmpstr ins insAddr insLen ctxt =
  let builder = new StmtBuilder (64)
  startMark insAddr insLen builder
  let src1, src2, imm = getThreeOprs ins
  let imm = transOprToExpr ins insAddr insLen ctxt imm
  let ctrl = getPcmpstrInfo ins.Opcode imm
  let nElem = int ctrl.NumElems
  let elemSz = RegType.fromBitWidth <| nElem
  let ck1, ck2 = genValidCheck ins insAddr insLen ctxt ctrl src1 src2 builder
  let intRes1, intRes2 = tmpVars2 elemSz
  let res1 = [| for _ in 1 .. nElem -> tmpVar elemSz |]
  aggOpr ins insAddr insLen ctxt ctrl src1 src2 ck1 ck2 res1 builder
  builder <! (intRes1 := Array.reduce (.|) res1)
  builder <! (intRes2 := getIntRes2 intRes1 ctrl ck2)
  pcmpStrRet ins ctrl ctxt intRes2 builder
  builder <! (getRegVar ctxt R.CF := intRes2 != num0 elemSz)
  getZSFForPCMPSTR ins insAddr insLen ctrl ctxt src1 src2 builder
  builder <! (getRegVar ctxt R.OF := extractLow 1<rt> intRes2)
  builder <! (getRegVar ctxt R.AF := b0)
  builder <! (getRegVar ctxt R.PF := b0)
  endMark insAddr insLen builder

let pextrw ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src, count = getThreeOprs ins
  let dst = transOprToExpr ins insAddr insLen ctxt dst
  let count =
    transOprToExpr ins insAddr insLen ctxt count
    |> extractLow 8<rt> .& numU32 7u 8<rt>
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  match src with
  | OprReg reg ->
    match Register.getKind reg with
    | Register.Kind.MMX ->
      let src = transOprToExpr ins insAddr insLen ctxt src
      let srcOffset = tmpVar 64<rt>
      builder <! (srcOffset := zExt 64<rt> count)
      let t = (src >> (srcOffset .* numU32 16u 64<rt>)) .& numU32 0xFFFFu 64<rt>
      builder <! (dstAssign oprSize dst (extractLow oprSize t))
    | Register.Kind.XMM ->
      let srcB, srcA = getPseudoRegVar128 ctxt reg
      let tSrc = tmpVar 128<rt>
      let srcOffset = tmpVar 128<rt>
      builder <! (srcOffset := zExt 128<rt> count)
      builder <! (tSrc := concat srcB srcA)
      let t = (tSrc >> (srcOffset .* numU32 16u 128<rt>)) .&
              numU32 0xFFFFu 128<rt>
      builder <! (dstAssign oprSize dst (extractLow oprSize t))
    | _ -> raise InvalidRegisterException
  | _ -> raise InvalidOperandException
  endMark insAddr insLen builder

let pinsrb ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src, count = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
  let src, count = transTwoOprs ins insAddr insLen ctxt (src, count)
  let oprSize = getOperationSize ins
  let sel, mask, temp, tDst = tmpVars4 oprSize
  let sel8 = sel .* numI32 8 oprSize
  startMark insAddr insLen builder
  builder <! (sel := count .& numI32 0xf oprSize)
  builder <! (mask := (numI32 0x0ff oprSize) << sel8)
  builder <! (temp := (zExt oprSize (extract src 8<rt> 0) << sel8) .& mask)
  builder <! (tDst := ((concat dstB dstA) .& (AST.not mask)) .| temp)
  builder <! (dstA := extractLow 64<rt> tDst)
  builder <! (dstB := extractHigh 64<rt> tDst)
  endMark insAddr insLen builder

let pinsrw ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src, count = getThreeOprs ins
  let src = transOprToExpr ins insAddr insLen ctxt src
  let sel = tmpVar 64<rt>
  let getImm = function
    | OprImm imm -> imm
    | _ -> raise InvalidOperandException
  startMark insAddr insLen builder
  match getOperationSize ins with
  | 64<rt> ->
    let dst = transOprToExpr ins insAddr insLen ctxt dst
    let count = transOprToExpr ins insAddr insLen ctxt count
    let mask = tmpVar 64<rt>
    builder <! (sel := count .| numI64 3L 64<rt>)
    let pos = sel .* numU64 0x10UL 64<rt>
    builder <! (mask := (numU64 0xffffUL 64<rt>) << pos)
    builder <!
      (dst := (dst .& (AST.not mask)) .| (zExt 64<rt> src << pos .& mask))
  | 128<rt> ->
    let dst1, dst2 = transOprToExpr128 ins insAddr insLen ctxt dst
    let mask = tmpVar 64<rt>
    let count = getImm count
    builder <! (sel := numI64 count 64<rt> .| numI64 7L 64<rt>)
    if count > 3L then
      let pos = (sel .- numI32 4 64<rt>) .* numI32 16 64<rt>
      builder <! (mask := (numU64 0xffffUL 64<rt>) << pos)
      builder <! (dst1 := (dst1 .& (AST.not mask))
                          .| (zExt 64<rt> src << pos .& mask))
    else
      let pos = sel .* numI32 16 64<rt>
      builder <! (mask := (numU64 0xffffUL 64<rt>) << pos)
      builder <! (dst2 := (dst2 .& (AST.not mask))
                          .| (zExt 64<rt> src << pos .& mask))
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let opPmaddwd _ =
  let lowAndSExt expr = extractLow 16<rt> expr |> sExt 32<rt>
  let highAndSExt expr = extractHigh 16<rt> expr |> sExt 32<rt>
  let mulLow e1 e2 = lowAndSExt e1 .* lowAndSExt e2
  let mulHigh e1 e2 = highAndSExt e1 .* highAndSExt e2
  let packAdd e1 e2 = mulLow e1 e2 .+ mulHigh e1 e2
  Array.map2 packAdd

let pmaddwd ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> opPmaddwd 16

let opMaxMinPacked cmp = Array.map2 (fun e1 e2 -> ite (cmp e1 e2) e1 e2)

let opPmaxsb _ = opMaxMinPacked sgt

let pmaxsb ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 8<rt> opPmaxsb 64

let opPmaxsw _ = opMaxMinPacked sgt

let pmaxsw ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 16<rt> opPmaxsw 32

let opPmaxub _ = opMaxMinPacked gt

let pmaxub ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 8<rt> opPmaxub 64

let opPminsb _ = opMaxMinPacked slt

let pminsb ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 8<rt> opPminsb 32

let opPminsw _ = opMaxMinPacked slt

let pminsw ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 16<rt> opPminsw 32

let opPminub _ = opMaxMinPacked lt

let pminub ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 8<rt> opPminub 64

let opPminud _ = opMaxMinPacked lt

let pminud ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> opPminud 32

let pmovmskb ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  let r = match src with | OprReg r -> r | _ -> raise InvalidOperandException
  let arrayInit cnt src =
    Array.init cnt (fun i -> extract src 1<rt> (i * 8 + 7))
  match Register.getKind r with
  | Register.Kind.MMX ->
    let dst, src = transTwoOprs ins insAddr insLen ctxt (dst, src)
    let srcSize = AST.typeOf src
    let cnt = RegType.toByteWidth srcSize
    let tmps = arrayInit cnt src
    builder <! (dstAssign oprSize dst <| zExt oprSize (concatExprs tmps))
  | Register.Kind.XMM ->
    let dst = transOprToExpr ins insAddr insLen ctxt dst
    let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
    let srcSize = AST.typeOf srcA
    let cnt = RegType.toByteWidth srcSize
    let tmpsA = arrayInit cnt srcA
    let tmpsB = arrayInit cnt srcB
    let tmps = concat (concatExprs tmpsB) (concatExprs tmpsA)
    builder <! (dstAssign oprSize dst <| zExt oprSize tmps)
  | Register.Kind.YMM ->
    let dst = transOprToExpr ins insAddr insLen ctxt dst
    let srcD, srcC, srcB, srcA = transOprToExpr256 ins insAddr insLen ctxt src
    let srcSize = AST.typeOf srcA
    let cnt = RegType.toByteWidth srcSize
    let tmpsA = arrayInit cnt srcA
    let tmpsB = arrayInit cnt srcB
    let tmpsC = arrayInit cnt srcC
    let tmpsD = arrayInit cnt srcD
    let tmps = concat (concat (concatExprs tmpsD) (concatExprs tmpsC))
                      (concat (concatExprs tmpsB) (concatExprs tmpsA))
    builder <! (dstAssign oprSize dst <| zExt oprSize tmps)
  | _ -> raise InvalidOperandException
  endMark insAddr insLen builder

let opPmul resType extr extSz packSz src1 src2 =
  Array.map2 (fun e1 e2 -> extr extSz e1 .* extr extSz e2) src1 src2
  |> Array.map (resType packSz)

let opPmulhw _ = opPmul extractHigh sExt 32<rt> 16<rt>

let pmulhw ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 16<rt> opPmulhw 32

let opPmulhuw _ = opPmul extractHigh zExt 32<rt> 16<rt>

let pmulhuw ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 16<rt> opPmulhuw 32

let opPmullw _ = opPmul extractLow sExt 32<rt> 16<rt>

let pmullw ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 16<rt> opPmullw 32

let opPmuludq _ =
  let low32 expr = expr .& numI64 0xffffffffL 64<rt>
  Array.map2 (fun e1 e2 -> low32 e1 .* low32 e2)

let pmuludq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opPmuludq 8

let pop ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let dst = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  auxPop oprSize ctxt dst builder
  endMark insAddr insLen builder

let popa ins insAddr insLen ctxt oprSize =
  let builder = new StmtBuilder (16)
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
  let builder = new StmtBuilder (16)
  let lblLoop = lblSymbol "Loop"
  let lblExit = lblSymbol "Exit"
  let lblLoopCond = lblSymbol "LoopCond"
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let max = numI32 (RegType.toBitWidth oprSize) oprSize
  startMark insAddr insLen builder
  let i = tmpVar oprSize
  let count = tmpVar oprSize
  builder <! (i := num0 oprSize)
  builder <! (count := num0 oprSize)
  builder <! (LMark lblLoopCond)
  builder <! (CJmp (lt i max, Name lblLoop, Name lblExit))
  builder <! (LMark lblLoop)
  let cond = (extractLow 1<rt> (src >> i)) == b1
  builder <! (count := ite cond (count .+ num1 oprSize) count)
  builder <! (i := i .+ num1 oprSize)
  builder <! (Jmp (Name lblLoopCond))
  builder <! (LMark lblExit)
  builder <! (dstAssign oprSize dst count)
  builder <! (getRegVar ctxt R.OF := b0)
  builder <! (getRegVar ctxt R.SF := b0)
  builder <! (getRegVar ctxt R.ZF := src == num0 oprSize)
  builder <! (getRegVar ctxt R.AF := b0)
  builder <! (getRegVar ctxt R.CF := b0)
  builder <! (getRegVar ctxt R.PF := b0)
  endMark insAddr insLen builder

let popf ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let oprSize = getOperationSize ins
  let t = tmpVar oprSize
  startMark insAddr insLen builder
  auxPop oprSize ctxt t builder
  builder <! (getRegVar ctxt R.OF := extract t 1<rt> 11)
  builder <! (getRegVar ctxt R.DF := extract t 1<rt> 10)
  builder <! (getRegVar ctxt R.IF := extract t 1<rt> 9)
  builder <! (getRegVar ctxt R.TF := extract t 1<rt> 8)
  builder <! (getRegVar ctxt R.SF := extract t 1<rt> 7)
  builder <! (getRegVar ctxt R.ZF := extract t 1<rt> 6)
  builder <! (getRegVar ctxt R.AF := extract t 1<rt> 4)
  builder <! (getRegVar ctxt R.PF := extract t 1<rt> 2)
  builder <! (getRegVar ctxt R.CF := extractLow 1<rt> t)
  endMark insAddr insLen builder

let por ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opPor 8

let opPsadbw _ =
  let abs expr = ite (lt expr (num0 8<rt>)) (AST.neg expr) (expr)
  Array.map2 (fun e1 e2 -> abs (e1 .- e2))

let psadbw ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 8<rt> opPsadbw 64

let pshufb ins insAddr insLen ctxt =
  let dst, src = getTwoOprs ins
  let oprSize = getOperationSize ins
  let cnt = RegType.toBitWidth oprSize / 8
  let builder = new StmtBuilder (2 * cnt)
  startMark insAddr insLen builder
  let tmps = Array.init cnt (fun _ -> tmpVar 8<rt>)
  let mask = numI32 (cnt - 1) 8<rt>
  let genTmps dst src =
    for i in 0 .. cnt - 1 do
      let cond = extract src 1<rt> (i * 8 + 7)
      let idx = (extract src 8<rt> (i * 8)) .& mask
      let numShift = zExt oprSize idx .* numI32 8 oprSize
      builder <!
        (tmps.[i] := ite cond (num0 8<rt>) (extractLow 8<rt> (dst >> numShift)))
    done
  match oprSize with
  | 64<rt> ->
    let dst, src = transTwoOprs ins insAddr insLen ctxt (dst, src)
    genTmps dst src
    builder <! (dst := concatExprs tmps)
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
    let conDst, conSrc = tmpVars2 oprSize
    let tDst = tmpVar oprSize
    builder <! (conDst := concat dstB dstA)
    builder <! (conSrc := concat srcB srcA)
    genTmps conDst conSrc
    builder <! (tDst := concatExprs tmps)
    builder <! (dstA := extractLow 64<rt> tDst)
    builder <! (dstB := extractHigh 64<rt> tDst)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let pshufd ins insAddr insLen ctxt =
  let dst, src, ord = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
  let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
  let ord = transOprToExpr ins insAddr insLen ctxt ord
  let oprSize = getOperationSize ins
  let cnt = RegType.toBitWidth oprSize / 32
  let builder = new StmtBuilder (2 * cnt)
  startMark insAddr insLen builder
  let tmps = Array.init cnt (fun _ -> tmpVar 32<rt>)
  let n32 = numI32 32 oprSize
  let mask2 = numI32 3 32<rt> (* 2-bit mask *)
  let tSrc = tmpVar oprSize
  let tDst = tmpVar oprSize
  builder <! (tSrc := concat srcB srcA)
  for i in 1 .. cnt do
    let order =
      ((extractLow 32<rt> ord) >> (numI32 ((i - 1) * 2) 32<rt>)) .& mask2
    let order' = zExt oprSize order
    builder <! (tmps.[i - 1] := extractLow 32<rt> (tSrc >> (order' .* n32)))
  done
  builder <! (tDst := concatExprs tmps)
  builder <! (dstA := extractLow 64<rt> tDst)
  builder <! (dstB := extractHigh 64<rt> tDst)
  endMark insAddr insLen builder

let pshufhw ins insAddr insLen ctxt =
  let dst, src, imm = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
  let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
  let imm = transOprToExpr ins insAddr insLen ctxt imm
  let builder = new StmtBuilder (8)
  startMark insAddr insLen builder
  let tmps = Array.init 4 (fun _ -> tmpVar 16<rt>)
  let n16 = numI32 16 64<rt>
  let mask2 = numI32 3 64<rt> (* 2-bit mask *)
  for i in 1 .. 4 do
    let imm =
      ((extractLow 64<rt> imm) >> (numI32 ((i - 1) * 2) 64<rt>)) .& mask2
    builder <! (tmps.[i - 1] := extractLow 16<rt> (srcB >> (imm .* n16)))
  done
  builder <! (dstA := srcA)
  builder <! (dstB := concatExprs tmps)
  endMark insAddr insLen builder

let pshuflw ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src, imm = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
  let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
  let imm = transOprToExpr ins insAddr insLen ctxt imm
  startMark insAddr insLen builder
  let tmps = Array.init 4 (fun _ -> tmpVar 16<rt>)
  let n16 = numI32 16 64<rt>
  let mask2 = numI32 3 64<rt> (* 2-bit mask *)
  for i in 1 .. 4 do
    let imm =
      ((extractLow 64<rt> imm) >> (numI32 ((i - 1) * 2) 64<rt>)) .& mask2
    builder <! (tmps.[i - 1] := extractLow 16<rt> (srcA >> (imm .* n16)))
  done
  builder <! (dstA := concatExprs tmps)
  builder <! (dstB := srcB)
  endMark insAddr insLen builder

let pshufw ins insAddr insLen ctxt =
  let dst, src, ord = getThreeOprs ins |> transThreeOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let cnt = RegType.toBitWidth oprSize / 16
  let builder = new StmtBuilder (2 * cnt)
  startMark insAddr insLen builder
  let tmps = Array.init cnt (fun _ -> tmpVar 16<rt>)
  let n16 = numI32 16 oprSize
  let mask2 = numI32 3 16<rt> (* 2-bit mask *)
  for i in 1 .. cnt do
    let order =
      ((extractLow 16<rt> ord) >> (numI32 ((i - 1) * 2) 16<rt>)) .& mask2
    let order' = zExt oprSize order
    builder <! (tmps.[i - 1] := extractLow 16<rt> (src >> (order' .* n16)))
  done
  builder <! (dst := concatExprs tmps)
  endMark insAddr insLen builder

let logicalLeftShiftDwords oprSize src cntSrc builder =
  let cntSrc = zExt oprSize cntSrc
  let tCnt = int oprSize / 32
  let tmps = Array.init tCnt (fun _ -> tmpVar (oprSize / tCnt))
  for i in 0 .. tCnt - 1 do
    let t = zExt oprSize ((src >> numI32 (i * 32) oprSize) << cntSrc)
    builder <! (tmps.[i] := extractLow 32<rt> t)
  done
  ite (gt cntSrc (numU32 31u oprSize)) (num0 oprSize) (concatExprs tmps)

let opShiftPackedDataLogical oprSize packSz shift src1 src2 =
  let count = concatExprs src2 |> zExt oprSize
  let cond = gt count (numI32 ((int packSz) - 1) oprSize)
  let shifted expr = extract (shift (zExt oprSize expr) count) packSz 0
  Array.map (fun e -> ite cond (num0 packSz) (shifted e)) src1

let opPslld oprSize = opShiftPackedDataLogical oprSize 32<rt> (<<)

let pslld ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> opPslld 8

let opPsllq oprSize = opShiftPackedDataLogical oprSize 64<rt> (<<)

let psllq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opPsllq 8

let opPsllw oprSize = opShiftPackedDataLogical oprSize 16<rt> (<<)

let psllw ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 16<rt> opPsllw 8

let shiftDQ ins insAddr insLen ctxt shift =
  let builder = new StmtBuilder (8)
  let dst, cnt = getTwoOprs ins
  let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
  let cnt = transOprToExpr ins insAddr insLen ctxt cnt |> castNum 8<rt>
  let oprSize = getOperationSize ins
  let t1 = tmpVar 8<rt>
  let t2, tDst = tmpVars2 oprSize
  startMark insAddr insLen builder
  builder <! (t1 := ite (lt (numU32 15u 8<rt>) cnt) (numU32 16u 8<rt>) cnt)
  builder <! (t2 := concat dstB dstA)
  builder <! (tDst := (shift t2 (zExt oprSize (t1 .* numU32 8u 8<rt>))))
  builder <! (dstA := extractLow 64<rt> tDst)
  builder <! (dstB := extractHigh 64<rt> tDst)
  endMark insAddr insLen builder

let pslldq ins insAddr insLen ctxt = shiftDQ ins insAddr insLen ctxt (<<)
let psrldq ins insAddr insLen ctxt = shiftDQ ins insAddr insLen ctxt (>>)

let opShiftPackedDataRightArith oprSize packSz src1 src2 =
  let count = concatExprs src2 |> zExt oprSize
  let cond = gt count (numI32 ((int packSz) - 1) oprSize)
  let count = ite cond (numI32 (int packSz) oprSize) count
  let shifted expr = extract ((sExt oprSize expr) ?>> count) packSz 0
  Array.map shifted src1

let opPsrad oprSize = opShiftPackedDataRightArith oprSize 32<rt>

let psrad ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> opPsrad 16

let opPsraw oprSize = opShiftPackedDataRightArith oprSize 16<rt>

let psraw ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 16<rt> opPsraw 32

let opPsrld oprSize = opShiftPackedDataLogical oprSize 32<rt> (>>)

let psrld ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> opPsrld 16

let opPsrlq oprSize = opShiftPackedDataLogical oprSize 64<rt> (>>)

let psrlq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opPsrlq 8

let opPsrlw oprSize = opShiftPackedDataLogical oprSize 16<rt> (>>)

let psrlw ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 16<rt> opPsrlw 32

let opPsub _ = Array.map2 (.-)

let psubb ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 8<rt> opPsub 8

let psubq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opPsub 8

let psubw ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 16<rt> opPsub 8

let psubd ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> opPsub 8

let opPsubsb oprSize src1 src2 =
  opPsub oprSize src1 src2 |> Array.map saturateToSignedByte

let psubsb ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 8<rt> opPsubsb 8

let opPsubsw oprSize src1 src2 =
  opPsub oprSize src1 src2 |> Array.map saturateToSignedWord

let psubsw ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 16<rt> opPsubsw 8

let opPsubusb oprSize src1 src2 =
  opPsub oprSize src1 src2 |> Array.map saturateToUnsignedByte

let psubusb ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 8<rt> opPsubusb 8

let opPsubusw oprSize src1 src2 =
  opPsub oprSize src1 src2 |> Array.map saturateToUnsignedWord

let psubusw ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 16<rt> opPsubusw 8

let ptest ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let src1, src2 = getTwoOprs ins
  let src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
  let src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt src2
  let t1, t2, t3, t4 = tmpVars4 64<rt>
  startMark insAddr insLen builder
  builder <! (t1 := src2A .& src1A)
  builder <! (t2 := src2B .& src1B)
  builder <! (getRegVar ctxt R.ZF := (t1 .| t2) == (num0 64<rt>))
  builder <! (t3 := src2A .& AST.not src1A)
  builder <! (t4 := src2B .& AST.not src1B)
  builder <! (getRegVar ctxt R.CF := (t3 .| t4) == (num0 64<rt>))
  builder <! (getRegVar ctxt R.AF := b0)
  builder <! (getRegVar ctxt R.OF := b0)
  builder <! (getRegVar ctxt R.PF := b0)
  builder <! (getRegVar ctxt R.SF := b0)
  endMark insAddr insLen builder

let vptest ins insAddr insLen ctxt =
  if getOperationSize ins = 128<rt> then ptest ins insAddr insLen ctxt
  else
    let builder = new StmtBuilder (16)
    let src1, src2 = getTwoOprs ins
    let src1D, src1C, src1B, src1A =
      transOprToExpr256 ins insAddr insLen ctxt src1
    let src2D, src2C, src2B, src2A =
      transOprToExpr256 ins insAddr insLen ctxt src2
    let t1, t2, t3, t4 = tmpVars4 64<rt>
    let t5, t6, t7, t8 = tmpVars4 64<rt>
    startMark insAddr insLen builder
    builder <! (t1 := src1A .& src2A)
    builder <! (t2 := src1B .& src2B)
    builder <! (t3 := src1C .& src2C)
    builder <! (t4 := src1D .& src2D)
    builder <! (getRegVar ctxt R.ZF := (t1 .| t2 .| t3 .| t4) == (num0 64<rt>))
    builder <! (t5 := src1A .& AST.not src2A)
    builder <! (t6 := src1B .& AST.not src2B)
    builder <! (t7 := src1C .& AST.not src2C)
    builder <! (t8 := src1D .& AST.not src2D)
    builder <! (getRegVar ctxt R.CF := (t5 .| t6 .| t7 .| t8) == (num0 64<rt>))
    builder <! (getRegVar ctxt R.AF := b0)
    builder <! (getRegVar ctxt R.OF := b0)
    builder <! (getRegVar ctxt R.PF := b0)
    builder <! (getRegVar ctxt R.SF := b0)
    endMark insAddr insLen builder

let opPunpck oprSize src1 src2 isHigh =
  match oprSize with
  | 64<rt> | 128<rt> ->
    let half = Array.length src1 / 2
    let sPos = if isHigh then half else 0
    let src1 = Array.sub src1 sPos half
    let src2 = Array.sub src2 sPos half
    Array.fold2 (fun acc e1 e2 -> e2 :: e1 :: acc) [] src1 src2
    |> List.rev |> List.toArray
  | 256<rt> ->
    let half = Array.length src1 / 2
    let src1A = Array.sub src1 0 half
    let src1B = Array.sub src1 half half
    let src2A = Array.sub src2 0 half
    let src2B = Array.sub src2 half half
    let half = Array.length src1A / 2
    let sPos = if isHigh then half else 0
    let src1A = Array.sub src1A sPos half
    let src2A = Array.sub src2A sPos half
    let src1B = Array.sub src1B sPos half
    let src2B = Array.sub src2B sPos half
    List.append
      (Array.fold2 (fun acc e1 e2 -> e2 :: e1 :: acc) [] src1B src2B)
      (Array.fold2 (fun acc e1 e2 -> e2 :: e1 :: acc) [] src1A src2A)
    |> List.rev |> List.toArray
  | _ -> raise InvalidOperandSizeException

let opPunpckHigh oprSize src1 src2 = opPunpck oprSize src1 src2 true

let punpckhbw ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 8<rt> opPunpckHigh 64

let punpckhdq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> opPunpckHigh 16

let punpckhqdq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opPunpckHigh 8

let punpckhwd ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 16<rt> opPunpckHigh 32

let opPunpckLow oprSize src1 src2 = opPunpck oprSize src1 src2 false

let punpcklbw ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 8<rt> opPunpckLow 64

let punpckldq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> opPunpckLow 16

let punpcklqdq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opPunpckLow 8

let punpcklwd ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 16<rt> opPunpckLow 32

let push ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let src = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  auxPush oprSize ctxt (padPushExpr oprSize src) builder
  endMark insAddr insLen builder

let pusha ins insAddr insLen ctxt oprSize =
  let builder = new StmtBuilder (16)
  let t = tmpVar oprSize
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
  let builder = new StmtBuilder (8)
  let oprSize = getOperationSize ins
  let e = zExt oprSize <| getRegVar ctxt R.CF
  (* We only consider 9 flags (we ignore system flags). *)
  let e = e .| ((zExt oprSize (getRegVar ctxt R.PF)) << numI32 2 oprSize)
  let e = e .| ((zExt oprSize (getRegVar ctxt R.AF)) << numI32 4 oprSize)
  let e = e .| ((zExt oprSize (getRegVar ctxt R.ZF)) << numI32 6 oprSize)
  let e = e .| ((zExt oprSize (getRegVar ctxt R.SF)) << numI32 7 oprSize)
  let e = e .| ((zExt oprSize (getRegVar ctxt R.TF)) << numI32 8 oprSize)
  let e = e .| ((zExt oprSize (getRegVar ctxt R.IF)) << numI32 9 oprSize)
  let e = e .| ((zExt oprSize (getRegVar ctxt R.DF)) << numI32 10 oprSize)
  let e = e .| ((zExt oprSize (getRegVar ctxt R.OF)) << numI32 11 oprSize)
  let e = match oprSize with
          | 16<rt> -> e
          | 32<rt> -> e .& (numI32 0xfcffff 32<rt>)
          | 64<rt> -> e .& (numI32 0xfcffff 64<rt>)
          | _ -> raise InvalidOperandSizeException
  startMark insAddr insLen builder
  auxPush oprSize ctxt e builder
  endMark insAddr insLen builder

let pxor ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  match oprSize with
  | 64<rt> ->
    let dst, src = transTwoOprs ins insAddr insLen ctxt (dst, src)
    builder <! (dst := dst <+> src)
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
    builder <! (dstA := dstA <+> srcA)
    builder <! (dstB := dstB <+> srcB)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let rcl ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, count = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let cF = getRegVar ctxt R.CF
  let oF = getRegVar ctxt R.OF
  let tmpCount = tmpVar oprSize
  let size = numI32 (RegType.toBitWidth oprSize) oprSize
  let count = zExt oprSize count
  let cnt =
    match oprSize with
    | 8<rt> -> (count .& numI32 0x1f oprSize) .% numI32 9 oprSize
    | 16<rt> -> (count .& numI32 0x1f oprSize) .% numI32 17 oprSize
    | 32<rt> -> count .& numI32 0x1f oprSize
    | 64<rt> -> count .& numI32 0x3f oprSize
    | _ -> raise InvalidOperandSizeException
  let cond = count == num1 oprSize
  startMark insAddr insLen builder
  builder <! (tmpCount := cnt)
  builder <! (dst := (dst << tmpCount) .| (dst >> (size .- tmpCount)))
  builder <! (cF := extractHigh 1<rt> dst)
  builder <! (oF := ite cond (extractHigh 1<rt> dst <+> cF) undefOF)
  endMark insAddr insLen builder

let rcr ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, count = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let cF = getRegVar ctxt R.CF
  let oF = getRegVar ctxt R.OF
  let tmpCount = tmpVar oprSize
  let size = numI32 (RegType.toBitWidth oprSize) oprSize
  let count = zExt oprSize count
  let cnt =
    match oprSize with
    | 8<rt> -> (count .& numI32 0x1f oprSize) .% numI32 9 oprSize
    | 16<rt> -> (count .& numI32 0x1f oprSize) .% numI32 17 oprSize
    | 32<rt> -> count .& numI32 0x1f oprSize
    | 64<rt> -> count .& numI32 0x3f oprSize
    | _ -> raise InvalidOperandSizeException
  let cond = count == num1 oprSize
  startMark insAddr insLen builder
  builder <! (tmpCount := cnt)
  builder <! (oF := ite cond (extractHigh 1<rt> dst <+> cF) undefOF)
  builder <! (dst := (dst >> tmpCount) .| (dst << (size .- tmpCount)))
  builder <! (cF := extractHigh 1<rt> dst)
  endMark insAddr insLen builder

let rdpkru ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let errExp = unDef 1<rt> "#GP(0) error"
  let lblSucc = lblSymbol "Succ"
  let oprSize = getOperationSize ins
  let ecx = getRegVar ctxt R.ECX
  let eax = getRegOfSize ctxt ctxt.WordBitSize GrpEAX
  let edx = getRegOfSize ctxt ctxt.WordBitSize GrpEDX
  startMark insAddr insLen builder
  builder <! (CJmp (ecx == num0 oprSize, Name lblSucc, errExp))
  builder <! (LMark lblSucc)
  builder <! (eax := zExt ctxt.WordBitSize (getRegVar ctxt R.PKRU))
  builder <! (edx := num0 ctxt.WordBitSize)
  endMark insAddr insLen builder

let ret ins insAddr insLen ctxt isFar isImm =
  let builder = new StmtBuilder (8)
  let oprSize = getOperationSize ins
  let t = tmpVar oprSize
  let pc = getInstrPtr ctxt
  let sp = getStackPtr ctxt
  match isFar, isImm with
  | false, true ->
    let src = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
    startMark insAddr insLen builder
    auxPop oprSize ctxt t builder
    builder <! (sp := sp .+ (zExt oprSize src))
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
  let builder = new StmtBuilder (8)
  let dst, count = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let cF = getRegVar ctxt R.CF
  let oF = getRegVar ctxt R.OF
  let countMask = if is64REXW ctxt ins then numU32 0x3Fu oprSize
                  else numU32 0x1Fu oprSize
  let size = numI32 (RegType.toBitWidth oprSize) oprSize
  let orgCount = tmpVar oprSize
  let cond1 = orgCount == num0 oprSize
  let cond2 = orgCount == num1 oprSize
  startMark insAddr insLen builder
  builder <! (orgCount := (zExt oprSize count .& countMask))
  builder <! (dst := (lfn dst orgCount) .| (hfn dst (size .- orgCount)))
  builder <! (cF := ite cond1 cF (cfFn 1<rt> dst))
  builder <! (oF := ite cond2 (ofFn dst cF) undefOF)
  endMark insAddr insLen builder

let rol ins insAddr insLen ctxt =
  let ofFn dst cF = cF <+> extractHigh 1<rt> dst
  rotate ins insAddr insLen ctxt (<<) (>>) extractLow ofFn

let ror ins insAddr insLen ctxt =
  let ofFn dst _cF =
    extractHigh 1<rt> dst <+> extract dst 1<rt> 1
  rotate ins insAddr insLen ctxt (>>) (<<) extractHigh ofFn

let rorx ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src, imm =
    getThreeOprs ins |> transThreeOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let y = tmpVar oprSize
  if oprSize = 32<rt> then
    builder <! (y := imm .& (numI32 0x1F oprSize))
    builder <! (dst := (src >> y) .| (src << (numI32 32 oprSize .- y)))
  else (* OperandSize = 64 *)
    builder <! (y := imm .& (numI32 0x3F oprSize))
    builder <! (dst := (src >> y) .| (src << (numI32 64 oprSize .- y)))
  endMark insAddr insLen builder

let rcpps ins insAddr insLen ctxt =
  let builder = new StmtBuilder(8)
  let opr1, opr2 = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt opr1
  let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt opr2
  let dst1b, dst1a = extractHigh 32<rt> dst1, extractLow 32<rt> dst1
  let dst2b, dst2a = extractHigh 32<rt> dst2, extractLow 32<rt> dst2
  let src1b, src1a = extractHigh 32<rt> src1, extractLow 32<rt> src1
  let src2b, src2a = extractHigh 32<rt> src2, extractLow 32<rt> src2
  let tmp = tmpVar 32<rt>
  let flt1 = BitVector.ofInt32 0x3f800000 32<rt> |> Num
  startMark insAddr insLen builder
  builder <! (dst1a := fdiv flt1 src1a)
  builder <! (dst1b := fdiv flt1 src1b)
  builder <! (dst2a := fdiv flt1 src2a)
  builder <! (dst2b := fdiv flt1 src2b)
  endMark insAddr insLen builder

let rcpss ins insAddr insLen ctxt =
  let builder = new StmtBuilder(4)
  let opr1, opr2 = getTwoOprs ins
  let dst = transOprToExpr32 ins insAddr insLen ctxt opr1
  let src = transOprToExpr32 ins insAddr insLen ctxt opr2
  let tmp = tmpVar 32<rt>
  let flt1 = BitVector.ofInt32 0x3f800000 32<rt> |> Num
  startMark insAddr insLen builder
  builder <! (dst := fdiv flt1 src)
  endMark insAddr insLen builder

let roundsd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src, imm = getThreeOprs ins
  let dst = transOprToExpr64 ins insAddr insLen ctxt dst
  let src = transOprToExpr64 ins insAddr insLen ctxt src
  let imm = transOprToExpr ins insAddr insLen ctxt imm
  let rc = extract (getRegVar ctxt R.FCW) 2<rt> 10
  let tmp = tmpVar 2<rt>
  let cster castKind = cast castKind 64<rt> src
  startMark insAddr insLen builder
  builder <! (tmp := ite (extract imm 1<rt> 2) rc (extractLow 2<rt> imm))
  builder <! (dst := num0 64<rt>)
  builder <! (dst := ite (tmp == num0 2<rt>) (cster CastKind.FtoIRound) dst)
  builder <! (dst := ite (tmp == num1 2<rt>) (cster CastKind.FtoIFloor) dst)
  builder <! (dst := ite (tmp == numI32 2 2<rt>) (cster CastKind.FtoICeil) dst)
  builder <! (dst := ite (tmp == numI32 3 2<rt>) (cster CastKind.FtoITrunc) dst)
  endMark insAddr insLen builder

let rsqrtps ins insAddr insLen ctxt =
  let builder = new StmtBuilder(16)
  let opr1, opr2 = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt opr1
  let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt opr2
  let dst1b, dst1a = extractHigh 32<rt> dst1, extractLow 32<rt> dst1
  let dst2b, dst2a = extractHigh 32<rt> dst2, extractLow 32<rt> dst2
  let src1b, src1a = extractHigh 32<rt> src1, extractLow 32<rt> src1
  let src2b, src2a = extractHigh 32<rt> src2, extractLow 32<rt> src2
  let tmp = tmpVar 32<rt>
  let flt1 = BitVector.ofInt32 0x3f800000 32<rt> |> Num
  startMark insAddr insLen builder
  builder <! (tmp := unop UnOpType.FSQRT src1a)
  builder <! (dst1a := fdiv flt1 tmp)
  builder <! (tmp := unop UnOpType.FSQRT src1b)
  builder <! (dst1b := fdiv flt1 tmp)
  builder <! (tmp := unop UnOpType.FSQRT src2a)
  builder <! (dst2a := fdiv flt1 tmp)
  builder <! (tmp := unop UnOpType.FSQRT src2b)
  builder <! (dst2b := fdiv flt1 tmp)
  endMark insAddr insLen builder

let rsqrtss ins insAddr insLen ctxt =
  let builder = new StmtBuilder(4)
  let opr1, opr2 = getTwoOprs ins
  let dst = transOprToExpr32 ins insAddr insLen ctxt opr1
  let src = transOprToExpr32 ins insAddr insLen ctxt opr2
  let tmp = tmpVar 32<rt>
  let flt1 = BitVector.ofInt32 0x3f800000 32<rt> |> Num
  startMark insAddr insLen builder
  builder <! (tmp := unop UnOpType.FSQRT src)
  builder <! (dst := fdiv flt1 tmp)
  endMark insAddr insLen builder

let sahf ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let ah = getRegVar ctxt R.AH
  startMark insAddr insLen builder
  builder <! (getRegVar ctxt R.CF := extractLow 1<rt> ah)
  builder <! (getRegVar ctxt R.PF := extract ah 1<rt> 2)
  builder <! (getRegVar ctxt R.AF := extract ah 1<rt> 4)
  builder <! (getRegVar ctxt R.ZF := extract ah 1<rt> 6)
  builder <! (getRegVar ctxt R.SF := extract ah 1<rt> 7)
  endMark insAddr insLen builder

let shufpd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src, imm = getThreeOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
  let imm = transOprToExpr ins insAddr insLen ctxt imm
  let cond1 = extractLow 1<rt> imm
  let cond2 = extract imm 1<rt> 1
  startMark insAddr insLen builder
  builder <! (dst1 := ite cond1 dst2 dst1)
  builder <! (dst2 := ite cond2 src2 src1)
  endMark insAddr insLen builder

let shufps ins insAddr insLen ctxt =
  let builder = new StmtBuilder (32)
  let dst, src, imm = getThreeOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
  let imm = transOprToExpr ins insAddr insLen ctxt imm
  let dst1A, dst1B = extractLow 32<rt> dst1, extractHigh 32<rt> dst1
  let dst2A, dst2B = extractLow 32<rt> dst2, extractHigh 32<rt> dst2
  let src1A, src1B = extractLow 32<rt> src1, extractHigh 32<rt> src1
  let src2A, src2B = extractLow 32<rt> src2, extractHigh 32<rt> src2
  let doShuf cond dst e0 e1 e2 e3 =
    builder <! (dst := num0 32<rt>)
    builder <! (dst := ite (cond == num0 2<rt>) e0 dst)
    builder <! (dst := ite (cond == num1 2<rt>) e1 dst)
    builder <! (dst := ite (cond == numI32 2 2<rt>) e2 dst)
    builder <! (dst := ite (cond == numI32 3 2<rt>) e3 dst)
  let cond1 = extractLow 2<rt> imm
  let cond2 = extract imm 2<rt> 2
  let cond3 = extract imm 2<rt> 4
  let cond4 = extract imm 2<rt> 6
  let tmp1, tmp2, tmp3, tmp4 = tmpVars4 32<rt>
  startMark insAddr insLen builder
  doShuf cond1 tmp1 dst1A dst1B dst2A dst2B
  doShuf cond2 tmp2 dst1A dst1B dst2A dst2B
  doShuf cond3 tmp3 src1A src1B src2A src2B
  doShuf cond4 tmp4 src1A src1B src2A src2B
  builder <! (dst1A := tmp1)
  builder <! (dst1B := tmp2)
  builder <! (dst2A := tmp3)
  builder <! (dst2B := tmp4)
  endMark insAddr insLen builder

let shift ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let n0 = num0 oprSize
  let n1 = num1 oprSize
  let countMask = if is64REXW ctxt ins then numU32 0x3Fu oprSize
                  else numU32 0x1Fu oprSize
  let cnt = (zExt oprSize src) .& countMask
  let cond1 = cnt == n1
  let cond2 = cnt == n0
  let oF = getRegVar ctxt R.OF
  let cF = getRegVar ctxt R.CF
  let sF = getRegVar ctxt R.SF
  let zF = getRegVar ctxt R.ZF
  let aF = getRegVar ctxt R.AF
  let tDst = tmpVar oprSize
  let tCnt = tmpVar oprSize
  startMark insAddr insLen builder
  builder <! (tDst := dst)
  match ins.Opcode with
  | Opcode.SAR ->
    builder <! (dst := dst ?>> cnt)
    builder <! (tCnt := cnt .- n1)
    let prevLBit = extractLow 1<rt> (tDst ?>> tCnt)
    builder <! (cF := ite cond2 cF prevLBit)
    builder <! (oF := ite cond1 b0 (ite cond2 oF undefOF))
  | Opcode.SHL ->
    builder <! (dstAssign oprSize dst (dst << cnt))
    builder <! (tCnt := cnt .- n1)
    let prevHBit = extractHigh 1<rt> (tDst << tCnt)
    builder <! (cF := ite cond2 cF prevHBit)
    let of1 = extractHigh 1<rt> dst <+> cF
    builder <! (oF := ite cond1 of1 (ite cond2 oF undefOF))
  | Opcode.SHR ->
    builder <! (dstAssign oprSize dst (dst >> cnt))
    builder <! (tCnt := cnt .- n1)
    let prevLBit = extractLow 1<rt> (tDst ?>> tCnt)
    builder <! (cF := ite cond2 cF prevLBit)
    builder <!
      (oF := ite cond1 (extractHigh 1<rt> tDst) (ite cond2 oF undefOF))
  | _ -> raise InvalidOpcodeException
  builder <! (sF := ite cond2 sF (extractHigh 1<rt> dst))
  let cbPF computedPF = ite cond2 (getRegVar ctxt R.PF) computedPF
  buildPF ctxt dst oprSize (Some cbPF) builder
  builder <! (zF := ite cond2 zF (dst == n0))
  builder <! (aF := ite cond2 aF undefAF)
  endMark insAddr insLen builder

let sbb ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let t1, t2, t3, t4 = tmpVars4 oprSize
  let cf = getRegVar ctxt R.CF
  startMark insAddr insLen builder
  builder <! (t1 := dst)
  builder <! (t2 := sExt oprSize src)
  builder <! (t3 := t2 .+ zExt oprSize cf)
  builder <! (t4 := t1 .- t3)
  builder <! (dstAssign oprSize dst t4)
  builder <! (cf := (lt t1 t3) .| (lt t3 t2))
  builder <! (getRegVar ctxt R.OF := getOFlagOnSub t1 t2 t4)
  enumASZPFlags ctxt t1 t2 t4 oprSize builder
  endMark insAddr insLen builder

let scas ins insAddr insLen ctxt =
  let builder = new StmtBuilder (32)
  startMark insAddr insLen builder
  let pref = ins.Prefixes
  let body () =
    let oprSize = getOperationSize ins
    let t = tmpVar oprSize
    let df = getRegVar ctxt R.DF
    let ax = getRegOfSize ctxt oprSize GrpEAX
    let di = getRegVar ctxt (if is64bit ctxt then R.RDI else R.EDI)
    let tSrc = tmpVar oprSize
    builder <! (tSrc := loadLE oprSize di)
    builder <! (t := ax .- tSrc)
    enumEFLAGS ctxt ax tSrc t oprSize getCFlagOnSub getOFlagOnSub builder
    let amount = numI32 (RegType.toByteWidth oprSize) ctxt.WordBitSize
    builder <! (di := ite df (di .- amount) (di .+ amount))
  let zfCond n = Some (getRegVar ctxt R.ZF == n)
  if hasREPZ pref then strRepeat ctxt body (zfCond b0) insAddr insLen builder
  elif hasREPNZ pref then strRepeat ctxt body (zfCond b1) insAddr insLen builder
  else body ()
  endMark insAddr insLen builder

let setcc ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let dst = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let cond = getCondOfSet ins ctxt |> zExt oprSize
  startMark insAddr insLen builder
  builder <! (dstAssign oprSize dst cond)
  endMark insAddr insLen builder

let inline shiftDblPrec ins insAddr insLen ctxt fnDst fnSrc isShl =
  let builder = new StmtBuilder (16)
  let dst, src, cnt = getThreeOprs ins |> transThreeOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let orig = tmpVar oprSize
  let c = tmpVar oprSize
  let cond1 = c == num0 oprSize
  let cond2 = c == num1 oprSize
  let cF = getRegVar ctxt R.CF
  let oF = getRegVar ctxt R.OF
  let aF = getRegVar ctxt R.AF
  startMark insAddr insLen builder
  builder <! (orig := dst)
  let maxSz = numI32 (if is64REXW ctxt ins then 64 else 32) oprSize
  builder <! (c := (zExt oprSize cnt) .% maxSz)
  let final = ite cond1 orig ((fnDst orig c) .| (fnSrc src (maxSz .- c)))
  builder <! (dstAssign oprSize dst final)
  if isShl then
    builder <! (cF := ite cond1 cF (extractLow 1<rt> (orig >> (maxSz .- c))))
  else
    builder <!
      (cF := ite cond1 cF (extractLow 1<rt> (orig >> (c .- num1 oprSize))))
  builder <!
    (oF := ite cond1 oF
               (ite cond2 (extractHigh 1<rt> (orig <+> dst)) undefOF))
  builder <! (aF := ite cond1 aF undefAF)
  enumSZPFlags ctxt dst oprSize builder
  endMark insAddr insLen builder

let shld ins insAddr insLen ctxt =
  shiftDblPrec ins insAddr insLen ctxt (<<) (>>) true

let shrd ins insAddr insLen ctxt =
  shiftDblPrec ins insAddr insLen ctxt (>>) (<<) false

let shlx ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src1, src2 =
    getThreeOprs ins |> transThreeOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let temp = tmpVar oprSize
  let countMask = if is64REXW ctxt ins then 0x3F else 0x1F // FIXME: CS.L = 1
  let count = src2 .& (numI32 countMask oprSize)
  startMark insAddr insLen builder
  builder <! (temp := src1)
  builder <! (extractHigh 1<rt> dst := extractHigh 1<rt> temp)
  builder <! (dst := dst << count)
  endMark insAddr insLen builder

let stmxcsr ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let dst = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  startMark insAddr insLen builder
  builder <! (dst := getRegVar ctxt R.MXCSR)
  endMark insAddr insLen builder

let setFlag insAddr insLen ctxt flag =
  let builder = new StmtBuilder (4)
  startMark insAddr insLen builder
  builder <! (getRegVar ctxt flag := b1)
  endMark insAddr insLen builder

let stc insAddr insLen ctxt = setFlag insAddr insLen ctxt R.CF
let std insAddr insLen ctxt = setFlag insAddr insLen ctxt R.DF
let sti insAddr insLen ctxt = setFlag insAddr insLen ctxt R.IF

let stos ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  startMark insAddr insLen builder
  let body () =
    let oprSize = getOperationSize ins
    let df = getRegVar ctxt R.DF
    let di = getRegVar ctxt (if is64bit ctxt then R.RDI else R.EDI)
    let src = getRegOfSize ctxt oprSize GrpEAX
    builder <! (loadLE oprSize di := src)
    let amount = numI32 (RegType.toByteWidth oprSize) ctxt.WordBitSize
    builder <! (di := ite df (di .- amount) (di .+ amount))
  if hasREPZ ins.Prefixes then
    strRepeat ctxt body None insAddr insLen builder
  elif hasREPNZ ins.Prefixes then raise InvalidPrefixException
  else body ()
  endMark insAddr insLen builder

let sub ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
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

let subpd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let dst, src = getTwoOprs ins
  startMark insAddr insLen builder
  let dst1, dst2 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src1, src2 = transOprToExpr128 ins insAddr insLen ctxt src
  builder <! (dst1 := dst1 .- src1)
  builder <! (dst2 := dst2 .- src2)
  endMark insAddr insLen builder

let test ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let src1, src2 = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let t = tmpVar oprSize
  startMark insAddr insLen builder
  builder <! (t := src1 .& src2)
  builder <! (getRegVar ctxt R.SF := extractHigh 1<rt> t)
  builder <! (getRegVar ctxt R.ZF := t == (num0 oprSize))
  buildPF ctxt t oprSize None builder
  builder <! (getRegVar ctxt R.CF := b0)
  builder <! (getRegVar ctxt R.OF := b0)
  builder <! (getRegVar ctxt R.AF := undefAF)
  endMark insAddr insLen builder

let tzcnt ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let lblLoop = lblSymbol "Loop"
  let lblExit = lblSymbol "Exit"
  let lblLoopCond = lblSymbol "LoopCond"
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let max = numI32 (RegType.toBitWidth oprSize) oprSize
  startMark insAddr insLen builder
  let t1 = tmpVar oprSize
  builder <! (t1 := num0 oprSize)
  builder <! (LMark lblLoopCond)
  let cond = (lt t1 max) .& (extractLow 1<rt> (src >> t1) == b0)
  builder <! (CJmp (cond, Name lblLoop, Name lblExit))
  builder <! (LMark lblLoop)
  builder <! (t1 := t1 .+ num1 oprSize)
  builder <! (Jmp (Name lblLoopCond))
  builder <! (LMark lblExit)
  builder <! (dstAssign oprSize dst t1)
  builder <! (getRegVar ctxt R.CF := dst == max)
  builder <! (getRegVar ctxt R.ZF := dst == num0 oprSize)
  builder <! (getRegVar ctxt R.OF := undefOF)
  builder <! (getRegVar ctxt R.SF := undefSF)
  builder <! (getRegVar ctxt R.PF := undefPF)
  builder <! (getRegVar ctxt R.AF := undefAF)
  endMark insAddr insLen builder

let ucomisd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let opr1, opr2 = getTwoOprs ins
  let opr1 = transOprToExpr64 ins insAddr insLen ctxt opr1
  let opr2 = transOprToExpr64 ins insAddr insLen ctxt opr2
  let lblNan = lblSymbol "IsNan"
  let lblExit = lblSymbol "Exit"
  let zf = getRegVar ctxt R.ZF
  let pf = getRegVar ctxt R.PF
  let cf = getRegVar ctxt R.CF
  startMark insAddr insLen builder
  builder <! (zf := ite (opr1 == opr2) b1 b0)
  builder <! (pf := b0)
  builder <! (cf := ite (flt opr1 opr2) b1 b0)
  let isNan expr =
    (extract expr 11<rt> 52  == num (BitVector.unsignedMax 11<rt>))
     .& (extractLow 52<rt> expr != num0 52<rt>)
  builder <! (CJmp (isNan opr1 .| isNan opr2, Name lblNan, Name lblExit))
  builder <! (LMark lblNan)
  builder <! (zf := b1)
  builder <! (pf := b1)
  builder <! (cf := b1)
  builder <! (LMark lblExit)
  builder <! (getRegVar ctxt R.OF := b0)
  builder <! (getRegVar ctxt R.AF := b0)
  builder <! (getRegVar ctxt R.SF := b0)
  endMark insAddr insLen builder

let ucomiss ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let opr1, opr2 = getTwoOprs ins
  let opr1 = transOprToExpr32 ins insAddr insLen ctxt opr1
  let opr2 = transOprToExpr32 ins insAddr insLen ctxt opr2
  let lblNan = lblSymbol "IsNan"
  let lblExit = lblSymbol "Exit"
  let zf = getRegVar ctxt R.ZF
  let pf = getRegVar ctxt R.PF
  let cf = getRegVar ctxt R.CF
  startMark insAddr insLen builder
  builder <! (zf := ite (opr1 == opr2) b1 b0)
  builder <! (pf := b0)
  builder <! (cf := ite (flt opr1 opr2) b1 b0)
  let isNan expr =
    (extract expr 8<rt> 23  == num (BitVector.unsignedMax 8<rt>))
     .& (extractLow 23<rt> expr != num0 23<rt>)
  builder <! (CJmp (isNan opr1 .| isNan opr2, Name lblNan, Name lblExit))
  builder <! (LMark lblNan)
  builder <! (zf := b1)
  builder <! (pf := b1)
  builder <! (cf := b1)
  builder <! (LMark lblExit)
  builder <! (getRegVar ctxt R.OF := b0)
  builder <! (getRegVar ctxt R.AF := b0)
  builder <! (getRegVar ctxt R.SF := b0)
  endMark insAddr insLen builder

let unpckhpd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src2, _src1 = transOprToExpr128 ins insAddr insLen ctxt src
  startMark insAddr insLen builder
  builder <! (dst1 := dst2)
  builder <! (dst2 := src2)
  endMark insAddr insLen builder

let unpckhps ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src2, _src1 = transOprToExpr128 ins insAddr insLen ctxt src
  let dst1A, dst1B = extractLow 32<rt> dst1, extractHigh 32<rt> dst1
  let dst2A, dst2B = extractLow 32<rt> dst2, extractHigh 32<rt> dst2
  let src2A, src2B = extractLow 32<rt> src2, extractHigh 32<rt> src2
  startMark insAddr insLen builder
  builder <! (dst1A := dst2A)
  builder <! (dst1B := src2A)
  builder <! (dst2A := dst2B)
  builder <! (dst2B := src2B)
  endMark insAddr insLen builder

let unpcklpd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let _src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
  startMark insAddr insLen builder
  builder <! (dst2 := src1)
  endMark insAddr insLen builder

let unpcklps ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let _src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
  let dst1A, dst1B = extractLow 32<rt> dst1, extractHigh 32<rt> dst1
  let dst2A, dst2B = extractLow 32<rt> dst2, extractHigh 32<rt> dst2
  let src1A, src1B = extractLow 32<rt> src1, extractHigh 32<rt> src1
  startMark insAddr insLen builder
  builder <! (dst2A := dst1B)
  builder <! (dst1B := src1A)
  builder <! (dst2B := src1B)
  endMark insAddr insLen builder

let vexedPackedFPBinOp64 ins insAddr insLen ctxt op =
  let builder = new StmtBuilder (16)
  let dst, src1, src2 = getThreeOprs ins
  let oprSz = getOperationSize ins
  startMark insAddr insLen builder
  match oprSz with
  | 128<rt> ->
    let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
    let src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
    let src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt src2
    builder <! (dst1 := op src1A src2A)
    builder <! (dst2 := op src1B src2B)
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dst4, dst3, dst2, dst1 = transOprToExpr256 ins insAddr insLen ctxt dst
    let sr1D, sr1C, sr1B, sr1A = transOprToExpr256 ins insAddr insLen ctxt src1
    let sr2D, sr2C, sr2B, sr2A = transOprToExpr256 ins insAddr insLen ctxt src2
    builder <! (dst1 := op sr1A sr2A)
    builder <! (dst2 := op sr1B sr2B)
    builder <! (dst3 := op sr1C sr2C)
    builder <! (dst4 := op sr1D sr2D)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vexedPackedFPBinOp32 ins insAddr insLen ctxt op =
  let builder = new StmtBuilder (16)
  let dst, src1, src2 = getThreeOprs ins
  let oprSz = getOperationSize ins
  let do32PackedOp dst64 src1 src2 builder =
    let dstA, dstB = extractLow 32<rt> dst64, extractHigh 32<rt> dst64
    let src1A, src1B = extractLow 32<rt> src1, extractHigh 32<rt> src1
    let src2A, src2B = extractLow 32<rt> src2, extractHigh 32<rt> src2
    builder <! (dstA := op src1A src2A)
    builder <! (dstB := op src1B src2B)
  startMark insAddr insLen builder
  match oprSz with
  | 128<rt> ->
    let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
    let src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
    let src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt src2
    do32PackedOp dst1 src1A src2A builder
    do32PackedOp dst2 src1B src2B builder
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dst4, dst3, dst2, dst1 = transOprToExpr256 ins insAddr insLen ctxt dst
    let sr1D, sr1C, sr1B, sr1A = transOprToExpr256 ins insAddr insLen ctxt src1
    let sr2D, sr2C, sr2B, sr2A = transOprToExpr256 ins insAddr insLen ctxt src2
    do32PackedOp dst1 sr1A sr2A builder
    do32PackedOp dst2 sr1B sr2B builder
    do32PackedOp dst3 sr1C sr2C builder
    do32PackedOp dst4 sr1D sr2D builder
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vexedScalarFPBinOp ins insAddr insLen ctxt sz op =
  let builder = new StmtBuilder (8)
  let dst, src1, src2 = getThreeOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
  startMark insAddr insLen builder
  match sz with
  | 32<rt> ->
    let src2 = transOprToExpr32 ins insAddr insLen ctxt src2
    builder <! (extractLow 32<rt> dst1 := op (extractLow 32<rt> src1A) src2)
    builder <! (extractHigh 32<rt> dst1 := extractHigh 32<rt> src1A)
  | 64<rt> ->
    let src2 = transOprToExpr64 ins insAddr insLen ctxt src2
    builder <! (dst1 := op src1A src2)
  | _ -> raise InvalidOperandSizeException
  builder <! (dst2 := src1B)
  fillZeroHigh128 ctxt dst builder
  endMark insAddr insLen builder

let isEvexEncoded = function
  | Some v -> v.EVEXPrx <> None
  | _ -> false

let vaddpd ins insAddr insLen ctxt =
  vexedPackedFPBinOp64 ins insAddr insLen ctxt fadd

let vaddps ins insAddr insLen ctxt =
  vexedPackedFPBinOp32 ins insAddr insLen ctxt fadd

let vaddsd ins insAddr insLen ctxt =
  vexedScalarFPBinOp ins insAddr insLen ctxt 64<rt> fadd

let vaddss ins insAddr insLen ctxt =
  vexedScalarFPBinOp ins insAddr insLen ctxt 32<rt> fadd

let vandpd ins insAddr insLen ctxt =
  vexedPackedFPBinOp64 ins insAddr insLen ctxt (.&)

let vandps ins insAddr insLen ctxt =
  vexedPackedFPBinOp32 ins insAddr insLen ctxt (.&)

let andnpdOp e1 e2 = (AST.not e1) .& e2

let vandnpd ins insAddr insLen ctxt =
  vexedPackedFPBinOp64 ins insAddr insLen ctxt andnpdOp

let vandnps ins insAddr insLen ctxt =
  vexedPackedFPBinOp32 ins insAddr insLen ctxt andnpdOp

let vbroadcasti128 ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
  let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
  startMark insAddr insLen builder
  builder <! (dstA := srcA)
  builder <! (dstB := srcB)
  builder <! (dstC := srcA)
  builder <! (dstD := srcB)
  endMark insAddr insLen builder

let vbroadcastss ins insAddr insLen ctxt =
  let builder = new StmtBuilder (32)
  let dst, src = getTwoOprs ins
  let src = transOprToExpr32 ins insAddr insLen ctxt src
  let tmp = tmpVar 32<rt>
  startMark insAddr insLen builder
  match getOperationSize ins with
  | 128<rt> ->
    let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
    builder <! (tmp := src)
    builder <! (extractLow 32<rt> dst1 := tmp)
    builder <! (extractHigh 32<rt> dst1 := tmp)
    builder <! (extractLow 32<rt> dst2 := tmp)
    builder <! (extractHigh 32<rt> dst2 := tmp)
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dst4, dst3, dst2, dst1 = transOprToExpr256 ins insAddr insLen ctxt dst
    builder <! (tmp := src)
    builder <! (extractLow 32<rt> dst1 := tmp)
    builder <! (extractHigh 32<rt> dst1 := tmp)
    builder <! (extractLow 32<rt> dst2 := tmp)
    builder <! (extractHigh 32<rt> dst2 := tmp)
    builder <! (extractLow 32<rt> dst3 := tmp)
    builder <! (extractHigh 32<rt> dst3 := tmp)
    builder <! (extractLow 32<rt> dst4 := tmp)
    builder <! (extractHigh 32<rt> dst4 := tmp)
  | _ -> raise InvalidOperandException
  endMark insAddr insLen builder

let vcvtsd2ss ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src1, src2 = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
  let src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
  let src2 = transOprToExpr64 ins insAddr insLen ctxt src2
  startMark insAddr insLen builder
  builder <! (extractLow 32<rt> dstA := cast CastKind.FloatExt 32<rt> src2)
  builder <! (extractHigh 32<rt> dstA := extractHigh 32<rt> src1A)
  builder <! (dstB := src1B)
  fillZeroHigh128 ctxt dst builder
  endMark insAddr insLen builder

let vcvtss2sd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src1, src2 = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
  let src1B, _src1A = transOprToExpr128 ins insAddr insLen ctxt src1
  let src2 = transOprToExpr32 ins insAddr insLen ctxt src2
  startMark insAddr insLen builder
  builder <! (dstA := cast CastKind.FloatExt 64<rt> src2)
  builder <! (dstB := src1B)
  fillZeroHigh128 ctxt dst builder
  endMark insAddr insLen builder

let vcvtsi2sd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src1, src2 = getThreeOprs ins
  let dstB , dstA = transOprToExpr128 ins insAddr insLen ctxt dst
  let src1B, _src1A = transOprToExpr128 ins insAddr insLen ctxt src1
  let src2 = transOprToExpr ins insAddr insLen ctxt src2
  startMark insAddr insLen builder
  builder <! (dstA := cast CastKind.IntToFloat 64<rt> src2)
  builder <! (dstB := src1B)
  fillZeroHigh128 ctxt dst builder
  endMark insAddr insLen builder

let vcvtsi2ss ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src1, src2 = getThreeOprs ins
  let dstB , dstA = transOprToExpr128 ins insAddr insLen ctxt dst
  let src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
  let src2 = transOprToExpr ins insAddr insLen ctxt src2
  startMark insAddr insLen builder
  builder <! (extractLow 32<rt> dstA := cast CastKind.IntToFloat 32<rt> src2)
  builder <! (extractHigh 32<rt> dstA := extractHigh 32<rt> src1A)
  builder <! (dstB := src1B)
  fillZeroHigh128 ctxt dst builder
  endMark insAddr insLen builder

let vdivpd ins insAddr insLen ctxt =
  vexedPackedFPBinOp64 ins insAddr insLen ctxt fdiv

let vdivps ins insAddr insLen ctxt =
  vexedPackedFPBinOp32 ins insAddr insLen ctxt fdiv

let vdivsd ins insAddr insLen ctxt =
  vexedScalarFPBinOp ins insAddr insLen ctxt 64<rt> fdiv

let vdivss ins insAddr insLen ctxt =
  vexedScalarFPBinOp ins insAddr insLen ctxt 32<rt> fdiv

let getEVEXPrx = function
  | Some v -> match v.EVEXPrx with
              | Some ev -> ev
              | None -> raise InvalidPrefixException
  | None -> raise InvalidPrefixException

let vextracti32x8 ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src, imm = getThreeOprs ins
  let oprSize = getOperationSize ins
  let ePrx = getEVEXPrx ins.VEXInfo
  let k = getRegVar ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
  let masking dst =
    match ePrx.Z with
    | Zeroing -> num0 32<rt>
    | Merging -> dst
  let cond idx =
    (* no write mask *)
    let noWritemask = if ePrx.AAA = 0uy then num1 1<rt> else num0 1<rt>
    extract k 1<rt> idx .| noWritemask
  let tDest = tmpVar 256<rt>
  let vl = 512
  let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
  let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
    transOprToExpr512 ins insAddr insLen ctxt src
  let imm = transOprToExpr ins insAddr insLen ctxt imm
  startMark insAddr insLen builder
  let srcLow = concat (concat srcD srcC) (concat srcB srcA)
  let srcHigh = concat (concat srcH srcG) (concat srcF srcE)
  builder <! (tDest := ite (extractLow 1<rt> imm) srcHigh srcLow)
  match dst with
  | OprReg _ ->
    let tmps = Array.init 2 (fun _ -> tmpVar 32<rt>)
    let assign dst src idx =
      for i in 0 .. 1 do
        let dstPos = i * 32
        let srcPos = 32 * (idx + i)
        let dst = extract dst 32<rt> dstPos
        let src = extract src 32<rt> srcPos
        builder <!
          (tmps.[i] := ite (cond (idx + i)) src (masking dst))
      concatExprs tmps
    builder <! (dstA := assign dstA tDest 0)
    builder <! (dstB := assign dstB tDest 2)
    builder <! (dstC := assign dstC tDest 4)
    builder <! (dstD := assign dstD tDest 6)
  | OprMem _ ->
    let tmps = Array.init 2 (fun _ -> tmpVar 32<rt>)
    let assign dst src idx =
      for i in 0 .. 1 do
        let dstPos = i * 32
        let srcPos = 32 * (idx + i)
        let dst = extract dst 32<rt> dstPos
        builder <!
          (tmps.[i] := ite (cond (idx + i)) (extract src 32<rt> srcPos) dst)
      concatExprs tmps
    builder <! (dstA := assign dstA tDest 0)
    builder <! (dstB := assign dstB tDest 2)
    builder <! (dstC := assign dstC tDest 4)
    builder <! (dstD := assign dstD tDest 6)
  | _ -> raise InvalidOperandException
  endMark insAddr insLen builder

let vextracti64x4 ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src, imm = getThreeOprs ins
  let oprSize = getOperationSize ins
  let ePrx = getEVEXPrx ins.VEXInfo
  let k = getRegVar ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
  let masking dst =
    match ePrx.Z with
    | Zeroing -> num0 64<rt>
    | Merging -> dst
  let cond idx =
    (* no write mask *)
    let noWritemask = if ePrx.AAA = 0uy then num1 1<rt> else num0 1<rt>
    extract k 1<rt> idx .| noWritemask
  let tDest = tmpVar 256<rt>
  let vl = 512
  let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
  let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
    transOprToExpr512 ins insAddr insLen ctxt src
  let imm = transOprToExpr ins insAddr insLen ctxt imm
  startMark insAddr insLen builder
  let srcLow = concat (concat srcD srcC) (concat srcB srcA)
  let srcHigh = concat (concat srcH srcG) (concat srcF srcE)
  builder <! (tDest := ite (extractLow 1<rt> imm) srcHigh srcLow)
  match dst with
  | OprReg _ ->
    builder <! (dstA := ite (cond 0) (extract tDest 64<rt> 0) (masking dstA))
    builder <! (dstB := ite (cond 1) (extract tDest 64<rt> 64) (masking dstB))
    builder <! (dstC := ite (cond 2) (extract tDest 64<rt> 128) (masking dstC))
    builder <! (dstD := ite (cond 3) (extract tDest 64<rt> 192) (masking dstD))
  | OprMem _ ->
    builder <! (dstA := ite (cond 0) (extract tDest 64<rt> 0) dstA)
    builder <! (dstB := ite (cond 1) (extract tDest 64<rt> 64) dstB)
    builder <! (dstC := ite (cond 2) (extract tDest 64<rt> 128) dstC)
    builder <! (dstD := ite (cond 3) (extract tDest 64<rt> 192) dstD)
  | _ -> raise InvalidOperandException
  endMark insAddr insLen builder

let vfmadd132sd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src2, src3 = getThreeOprs ins
  let _dstB , dstA = transOprToExpr128 ins insAddr insLen ctxt dst
  let src2 = transOprToExpr64 ins insAddr insLen ctxt src2
  let src3 = transOprToExpr64 ins insAddr insLen ctxt src3
  let tmp = tmpVar 64<rt>
  startMark insAddr insLen builder
  builder <! (tmp := fmul dstA src3)
  builder <! (dstA := fadd tmp src2)
  fillZeroHigh128 ctxt dst builder
  endMark insAddr insLen builder

let vfmadd213sd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src2, src3 = getThreeOprs ins
  let _dstB , dstA = transOprToExpr128 ins insAddr insLen ctxt dst
  let src2 = transOprToExpr64 ins insAddr insLen ctxt src2
  let src3 = transOprToExpr64 ins insAddr insLen ctxt src3
  let tmp = tmpVar 64<rt>
  startMark insAddr insLen builder
  builder <! (tmp := fmul dstA src2)
  builder <! (dstA := fadd tmp src3)
  fillZeroHigh128 ctxt dst builder
  endMark insAddr insLen builder

let vfmadd231sd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src2, src3 = getThreeOprs ins
  let _dstB , dstA = transOprToExpr128 ins insAddr insLen ctxt dst
  let src2 = transOprToExpr64 ins insAddr insLen ctxt src2
  let src3 = transOprToExpr64 ins insAddr insLen ctxt src3
  let tmp = tmpVar 64<rt>
  startMark insAddr insLen builder
  builder <! (tmp := fmul src2 src3)
  builder <! (dstA := fadd dstA tmp)
  fillZeroHigh128 ctxt dst builder
  endMark insAddr insLen builder

let vinserti128 ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src1, src2, imm = getFourOprs ins
  let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
  let src1D, src1C, src1B, src1A = transOprToExpr256 ins insAddr insLen ctxt src1
  let src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt src2
  let imm = transOprToExpr ins insAddr insLen ctxt imm
  let cond = tmpVar 1<rt>
  startMark insAddr insLen builder
  builder <! (cond := extractLow 1<rt> imm)
  builder <! (dstA := ite cond src1A src2A)
  builder <! (dstB := ite cond src1B src2B)
  builder <! (dstC := ite cond src2A src1C)
  builder <! (dstD := ite cond src2B src1D)
  endMark insAddr insLen builder

let vmovd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  let n0 = num0 64<rt>
  let regToReg r1 r2 =
    match Register.getKind r1, Register.getKind r2 with
    | Register.Kind.XMM, Register.Kind.GP ->
      let dstD, dstC, dstB, dstA = getPseudoRegVar256 ctxt (r128to256 dst)
      let src = getRegVar ctxt r2
      builder <! (dstAssign 32<rt> dstA src)
      builder <! (dstB := n0)
      builder <! (dstC := n0)
      builder <! (dstD := n0)
    | Register.Kind.GP, Register.Kind.XMM ->
      let dst = getRegVar ctxt r1
      let srcA = getPseudoRegVar ctxt r2 1
      builder <! (dstAssign oprSize dst (extractLow 32<rt> srcA))
    | _ -> raise InvalidOperandException
  match dst, src with
  | OprReg r1, OprReg r2 -> regToReg r1 r2
  | OprReg r, OprMem _ ->
    let dstD, dstC, dstB, dstA = getPseudoRegVar256 ctxt (r128to256 dst)
    let src = transOprToExpr ins insAddr insLen ctxt src
    builder <! (dstAssign 32<rt> dstA src)
    builder <! (dstB := n0)
    builder <! (dstC := n0)
    builder <! (dstD := n0)
  | OprMem _, OprReg r ->
    let dst = transOprToExpr ins insAddr insLen ctxt dst
    let srcA = getPseudoRegVar ctxt r 1
    builder <! (dst := extractLow 32<rt> srcA)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vmovddup ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src = getTwoOprs ins
  startMark insAddr insLen builder
  match getOperationSize ins with
  | 128<rt> ->
    let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
    let src = transOprToExpr64 ins insAddr insLen ctxt src
    builder <! (dst1 := src)
    builder <! (dst2 := src)
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dst4, dst3, dst2, dst1 = transOprToExpr256 ins insAddr insLen ctxt dst
    let _src4, src3, _src2, src1 = transOprToExpr256 ins insAddr insLen ctxt src
    builder <! (dst1 := src1)
    builder <! (dst2 := src1)
    builder <! (dst3 := src3)
    builder <! (dst4 := src3)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let buildVectorMove ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  if oprSize = 128<rt> then
    match dst with
    | OprReg _ ->
      let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
      let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
      builder <! (dstA := srcA)
      builder <! (dstB := srcB)
      fillZeroHigh128 ctxt dst builder
    | OprMem _ ->
      let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
      let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
      builder <! (dstA := srcA)
      builder <! (dstB := srcB)
    | _ -> raise InvalidOperandException
  elif oprSize = 256<rt> then
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
    let srcD, srcC, srcB, srcA = transOprToExpr256 ins insAddr insLen ctxt src
    builder <! (dstA := srcA)
    builder <! (dstB := srcB)
    builder <! (dstC := srcC)
    builder <! (dstD := srcD)
  elif oprSize = 512<rt> then
    let ePrx = getEVEXPrx ins.VEXInfo
    let k = getRegVar ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
    let masking dst =
      match ePrx.Z with
      | Zeroing -> num0 32<rt>
      | Merging -> dst
    let cond idx =
      (* no write mask *)
      let noWritemask = if ePrx.AAA = 0uy then num1 1<rt> else num0 1<rt>
      extract k 1<rt> idx .| noWritemask
    let kl, vl = 16, 512
    match dst with
    | OprReg _ ->
      let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
        transOprToExpr512 ins insAddr insLen ctxt dst
      let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
        transOprToExpr512 ins insAddr insLen ctxt src
      let ite i src dst extFn =
        ite (cond i) (extFn 32<rt> src) (masking (extFn 32<rt> dst))
      builder <! (extractLow 32<rt> dstA := ite 0 srcA dstA extractLow)
      builder <! (extractHigh 32<rt> dstA := ite 1 srcA dstA extractHigh)
      builder <! (extractLow 32<rt> dstB := ite 2 srcB dstB extractLow)
      builder <! (extractHigh 32<rt> dstB := ite 3 srcB dstB extractHigh)
      builder <! (extractLow 32<rt> dstC := ite 4 srcC dstC extractLow)
      builder <! (extractHigh 32<rt> dstC := ite 5 srcC dstC extractHigh)
      builder <! (extractLow 32<rt> dstD := ite 6 srcD dstD extractLow)
      builder <! (extractHigh 32<rt> dstD := ite 7 srcD dstD extractHigh)
      builder <! (extractLow 32<rt> dstE := ite 8 srcE dstE extractLow)
      builder <! (extractHigh 32<rt> dstE := ite 9 srcE dstE extractHigh)
      builder <! (extractLow 32<rt> dstF := ite 10 srcF dstF extractLow)
      builder <! (extractHigh 32<rt> dstF := ite 11 srcF dstF extractHigh)
      builder <! (extractLow 32<rt> dstG := ite 12 srcG dstG extractLow)
      builder <! (extractHigh 32<rt> dstG := ite 13 srcG dstG extractHigh)
      builder <! (extractLow 32<rt> dstH := ite 14 srcH dstH extractLow)
      builder <! (extractHigh 32<rt> dstH := ite 15 srcH dstH extractHigh)
    | OprMem _ ->
      let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
        transOprToExpr512 ins insAddr insLen ctxt dst
      let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
        transOprToExpr512 ins insAddr insLen ctxt src
      let ite i src dst extFn =
        ite (cond i) (extFn 32<rt> src) (extFn 32<rt> dst)
      builder <! (extractLow 32<rt> dstA := ite 0 srcA dstA extractLow)
      builder <! (extractHigh 32<rt> dstA := ite 1 srcA dstA extractHigh)
      builder <! (extractLow 32<rt> dstB := ite 2 srcB dstB extractLow)
      builder <! (extractHigh 32<rt> dstB := ite 3 srcB dstB extractHigh)
      builder <! (extractLow 32<rt> dstC := ite 4 srcC dstC extractLow)
      builder <! (extractHigh 32<rt> dstC := ite 5 srcC dstC extractHigh)
      builder <! (extractLow 32<rt> dstD := ite 6 srcD dstD extractLow)
      builder <! (extractHigh 32<rt> dstD := ite 7 srcD dstD extractHigh)
      builder <! (extractLow 32<rt> dstE := ite 8 srcE dstE extractLow)
      builder <! (extractHigh 32<rt> dstE := ite 9 srcE dstE extractHigh)
      builder <! (extractLow 32<rt> dstF := ite 10 srcF dstF extractLow)
      builder <! (extractHigh 32<rt> dstF := ite 11 srcF dstF extractHigh)
      builder <! (extractLow 32<rt> dstG := ite 12 srcG dstG extractLow)
      builder <! (extractHigh 32<rt> dstG := ite 13 srcG dstG extractHigh)
      builder <! (extractLow 32<rt> dstH := ite 14 srcH dstH extractLow)
      builder <! (extractHigh 32<rt> dstH := ite 15 srcH dstH extractHigh)
    | _ -> raise InvalidOperandException
  else raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vmovdqa ins insAddr insLen ctxt = buildVectorMove ins insAddr insLen ctxt

let vmovdqu ins insAddr insLen ctxt = buildVectorMove ins insAddr insLen ctxt

let vmovntdq ins insAddr insLen ctxt = buildMove ins insAddr insLen ctxt 16

let vmovntpd ins insAddr insLen ctxt = buildMove ins insAddr insLen ctxt 16

let vmovntps ins insAddr insLen ctxt = buildMove ins insAddr insLen ctxt 16

let vmovdqa64 ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let oprSize = getOperationSize ins
  let ePrx = getEVEXPrx ins.VEXInfo
  let k = getRegVar ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
  let masking dst =
    match ePrx.Z with
    | Zeroing -> num0 64<rt>
    | Merging -> dst
  let cond idx =
    (* no write mask *)
    let noWritemask = if ePrx.AAA = 0uy then num1 1<rt> else num0 1<rt>
    extract k 1<rt> idx .| noWritemask
  startMark insAddr insLen builder
  match oprSize with
  | 128<rt> ->
    let kl, vl = 2, 128
    match dst with
    | OprReg _ ->
      let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
      let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
      builder <! (dstA := ite (cond 0) srcA (masking dstA))
      builder <! (dstB := ite (cond 1) srcB (masking dstB))
      fillZeroFromVLToMaxVL ctxt dst vl 512 builder
    | OprMem _ ->
      let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
      let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
      builder <! (dstA := ite (cond 0) srcA dstA)
      builder <! (dstB := ite (cond 1) srcB dstB)
    | _ -> raise InvalidOperandException
  | 256<rt> ->
    let kl, vl = 4, 256
    match dst with
    | OprReg _ ->
      let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
      let srcD, srcC, srcB, srcA = transOprToExpr256 ins insAddr insLen ctxt src
      builder <! (dstA := ite (cond 0) srcA (masking dstA))
      builder <! (dstB := ite (cond 1) srcB (masking dstB))
      builder <! (dstC := ite (cond 2) srcC (masking dstC))
      builder <! (dstD := ite (cond 3) srcD (masking dstD))
      fillZeroFromVLToMaxVL ctxt dst vl 512 builder
    | OprMem _ ->
      let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
      let srcD, srcC, srcB, srcA = transOprToExpr256 ins insAddr insLen ctxt src
      builder <! (dstA := ite (cond 0) srcA dstA)
      builder <! (dstB := ite (cond 1) srcB dstB)
      builder <! (dstC := ite (cond 2) srcC dstC)
      builder <! (dstD := ite (cond 3) srcD dstD)
    | _ -> raise InvalidOperandException
  | 512<rt> ->
    let kl, vl = 8, 512
    match dst with
    | OprReg _ ->
      let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
        transOprToExpr512 ins insAddr insLen ctxt dst
      let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
        transOprToExpr512 ins insAddr insLen ctxt src
      builder <! (dstA := ite (cond 0) srcA (masking dstA))
      builder <! (dstB := ite (cond 1) srcB (masking dstB))
      builder <! (dstC := ite (cond 2) srcC (masking dstC))
      builder <! (dstD := ite (cond 3) srcD (masking dstD))
      builder <! (dstE := ite (cond 4) srcE (masking dstE))
      builder <! (dstF := ite (cond 5) srcF (masking dstF))
      builder <! (dstG := ite (cond 6) srcG (masking dstG))
      builder <! (dstH := ite (cond 7) srcH (masking dstH))
    | OprMem _ ->
      let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
        transOprToExpr512 ins insAddr insLen ctxt dst
      let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
        transOprToExpr512 ins insAddr insLen ctxt src
      builder <! (dstA := ite (cond 0) srcA dstA)
      builder <! (dstB := ite (cond 1) srcB dstB)
      builder <! (dstC := ite (cond 2) srcC dstC)
      builder <! (dstD := ite (cond 3) srcD dstD)
      builder <! (dstE := ite (cond 4) srcE dstE)
      builder <! (dstF := ite (cond 5) srcF dstF)
      builder <! (dstG := ite (cond 6) srcG dstG)
      builder <! (dstH := ite (cond 7) srcH dstH)
    | _ -> raise InvalidOperandException
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vmovdqu16 ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let oprSize = getOperationSize ins
  let ePrx = getEVEXPrx ins.VEXInfo
  let k = getRegVar ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
  let masking dst =
    match ePrx.Z with
    | Zeroing -> num0 16<rt>
    | Merging -> dst
  let cond idx =
    (* no write mask *)
    let noWritemask = if ePrx.AAA = 0uy then num1 1<rt> else num0 1<rt>
    extract k 1<rt> idx .| noWritemask
  startMark insAddr insLen builder
  match oprSize with
  | 128<rt> ->
    let kl, vl = 8, 128
    match dst with
    | OprReg _ ->
      let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
      let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
      let assign dst src idx =
        let pos = (idx % 4) * 16
        let dst = extract dst 16<rt> pos
        dst := ite (cond idx) (extract src 16<rt> pos) (masking dst)
      builder <! (assign dstA srcA 0)
      builder <! (assign dstA srcA 1)
      builder <! (assign dstA srcA 2)
      builder <! (assign dstA srcA 3)
      builder <! (assign dstB srcB 4)
      builder <! (assign dstB srcB 5)
      builder <! (assign dstB srcB 6)
      builder <! (assign dstB srcB 7)
      fillZeroFromVLToMaxVL ctxt dst vl 512 builder
    | OprMem _ ->
      let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
      let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
      let tmps = Array.init 4 (fun _ -> tmpVar 16<rt>)
      let assign dst src idx =
        for i in 0 .. 3 do
          let pos = i * 16
          let dst = extract dst 16<rt> pos
          builder <!
            (tmps.[i] := ite (cond (idx + i)) (extract src 16<rt> pos) dst)
        concatExprs tmps
      builder <! (dstA := assign dstA srcA 0)
      builder <! (dstB := assign dstB srcB 4)
    | _ -> raise InvalidOperandException
  | 256<rt> ->
    let kl, vl = 16, 256
    match dst with
    | OprReg _ ->
      let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
      let srcD, srcC, srcB, srcA = transOprToExpr256 ins insAddr insLen ctxt src
      let assign dst src idx =
        let pos = (idx % 4) * 16
        let dst = extract dst 16<rt> pos
        dst := ite (cond idx) (extract src 16<rt> pos) (masking dst)
      builder <! (assign dstA srcA 0)
      builder <! (assign dstA srcA 1)
      builder <! (assign dstA srcA 2)
      builder <! (assign dstA srcA 3)
      builder <! (assign dstB srcB 4)
      builder <! (assign dstB srcB 5)
      builder <! (assign dstB srcB 6)
      builder <! (assign dstB srcB 7)
      builder <! (assign dstC srcA 8)
      builder <! (assign dstC srcA 9)
      builder <! (assign dstC srcA 10)
      builder <! (assign dstC srcA 11)
      builder <! (assign dstD srcB 12)
      builder <! (assign dstD srcB 13)
      builder <! (assign dstD srcB 14)
      builder <! (assign dstD srcB 15)
      fillZeroFromVLToMaxVL ctxt dst vl 512 builder
    | OprMem _ ->
      let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
      let srcD, srcC, srcB, srcA = transOprToExpr256 ins insAddr insLen ctxt src
      let tmps = Array.init 4 (fun _ -> tmpVar 16<rt>)
      let assign dst src idx =
        for i in 0 .. 3 do
          let pos = i * 16
          let dst = extract dst 16<rt> pos
          builder <!
            (tmps.[i] := ite (cond (idx + i)) (extract src 16<rt> pos) dst)
        concatExprs tmps
      builder <! (dstA := assign dstA srcA 0)
      builder <! (dstB := assign dstB srcB 4)
      builder <! (dstC := assign dstC srcC 8)
      builder <! (dstD := assign dstD srcD 12)
    | _ -> raise InvalidOperandException
  | 512<rt> ->
    let kl, vl = 32, 512
    match dst with
    | OprReg _ ->
      let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
        transOprToExpr512 ins insAddr insLen ctxt dst
      let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
        transOprToExpr512 ins insAddr insLen ctxt src
      let assign dst src idx =
        let pos = (idx % 4) * 16
        let dst = extract dst 16<rt> pos
        dst := ite (cond idx) (extract src 16<rt> pos) (masking dst)
      builder <! (assign dstA srcA 0)
      builder <! (assign dstA srcA 1)
      builder <! (assign dstA srcA 2)
      builder <! (assign dstA srcA 3)
      builder <! (assign dstB srcB 4)
      builder <! (assign dstB srcB 5)
      builder <! (assign dstB srcB 6)
      builder <! (assign dstB srcB 7)
      builder <! (assign dstC srcA 8)
      builder <! (assign dstC srcA 9)
      builder <! (assign dstC srcA 10)
      builder <! (assign dstC srcA 11)
      builder <! (assign dstD srcB 12)
      builder <! (assign dstD srcB 13)
      builder <! (assign dstD srcB 14)
      builder <! (assign dstD srcB 15)
      builder <! (assign dstF srcA 16)
      builder <! (assign dstF srcA 17)
      builder <! (assign dstF srcA 18)
      builder <! (assign dstF srcA 19)
      builder <! (assign dstG srcB 20)
      builder <! (assign dstG srcB 21)
      builder <! (assign dstG srcB 22)
      builder <! (assign dstG srcB 23)
      builder <! (assign dstH srcA 24)
      builder <! (assign dstH srcA 25)
      builder <! (assign dstH srcA 26)
      builder <! (assign dstH srcA 27)
      builder <! (assign dstG srcB 28)
      builder <! (assign dstG srcB 29)
      builder <! (assign dstG srcB 30)
      builder <! (assign dstG srcB 31)
    | OprMem _ ->
      let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
        transOprToExpr512 ins insAddr insLen ctxt dst
      let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
        transOprToExpr512 ins insAddr insLen ctxt src
      let tmps = Array.init 4 (fun _ -> tmpVar 16<rt>)
      let assign dst src idx =
        for i in 0 .. 3 do
          let pos = i * 16
          let dst = extract dst 16<rt> pos
          builder <!
            (tmps.[i] := ite (cond (idx + i)) (extract src 16<rt> pos) dst)
        concatExprs tmps
      builder <! (dstA := assign dstA srcA 0)
      builder <! (dstB := assign dstB srcB 4)
      builder <! (dstC := assign dstC srcC 8)
      builder <! (dstD := assign dstD srcD 12)
      builder <! (dstE := assign dstE srcE 16)
      builder <! (dstF := assign dstF srcF 20)
      builder <! (dstG := assign dstG srcG 24)
      builder <! (dstH := assign dstH srcH 28)
    | _ -> raise InvalidOperandException
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vmovdqu64 ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let oprSize = getOperationSize ins
  let ePrx = getEVEXPrx ins.VEXInfo
  let k = getRegVar ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
  let masking dst =
    match ePrx.Z with
    | Zeroing -> num0 64<rt>
    | Merging -> dst
  let cond idx =
    if ePrx.AAA = 0uy then num0 1<rt> (* no write mask *)
    else extract k 1<rt> idx
  startMark insAddr insLen builder
  match oprSize with
  | 128<rt> ->
    let kl, vl = 4, 128
    match dst with
    | OprReg _ ->
      let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
      let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
      builder <! (dstA := ite (cond 0) srcA (masking dstA))
      builder <! (dstB := ite (cond 1) srcB (masking dstB))
      fillZeroFromVLToMaxVL ctxt dst vl 512 builder
    | OprMem _ ->
      let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
      let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
      builder <! (dstA := ite (cond 0) srcA dstA)
      builder <! (dstB := ite (cond 1) srcB dstB)
    | _ -> raise InvalidOperandException
  | 256<rt> ->
    let kl, vl = 8, 256
    match dst with
    | OprReg _ ->
      let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
      let srcD, srcC, srcB, srcA = transOprToExpr256 ins insAddr insLen ctxt src
      builder <! (dstA := ite (cond 0) srcA (masking dstA))
      builder <! (dstB := ite (cond 1) srcB (masking dstB))
      builder <! (dstC := ite (cond 2) srcC (masking dstC))
      builder <! (dstD := ite (cond 3) srcD (masking dstD))
      fillZeroFromVLToMaxVL ctxt dst vl 512 builder
    | OprMem _ ->
      let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
      let srcD, srcC, srcB, srcA = transOprToExpr256 ins insAddr insLen ctxt src
      builder <! (dstA := ite (cond 0) srcA dstA)
      builder <! (dstB := ite (cond 1) srcB dstB)
      builder <! (dstC := ite (cond 2) srcC dstC)
      builder <! (dstD := ite (cond 3) srcD dstD)
    | _ -> raise InvalidOperandException
  | 512<rt> ->
    let kl, vl = 16, 512
    match dst with
    | OprReg _ ->
      let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
        transOprToExpr512 ins insAddr insLen ctxt dst
      let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
        transOprToExpr512 ins insAddr insLen ctxt src
      builder <! (dstA := ite (cond 0) srcA (masking dstA))
      builder <! (dstB := ite (cond 1) srcB (masking dstB))
      builder <! (dstC := ite (cond 2) srcC (masking dstC))
      builder <! (dstD := ite (cond 3) srcD (masking dstD))
      builder <! (dstE := ite (cond 4) srcE (masking dstE))
      builder <! (dstF := ite (cond 5) srcF (masking dstF))
      builder <! (dstG := ite (cond 6) srcG (masking dstG))
      builder <! (dstH := ite (cond 7) srcH (masking dstH))
    | OprMem _ ->
      let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
        transOprToExpr512 ins insAddr insLen ctxt dst
      let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
        transOprToExpr512 ins insAddr insLen ctxt src
      builder <! (dstA := ite (cond 0) srcA dstA)
      builder <! (dstB := ite (cond 1) srcB dstB)
      builder <! (dstC := ite (cond 2) srcC dstC)
      builder <! (dstD := ite (cond 3) srcD dstD)
      builder <! (dstE := ite (cond 4) srcE dstE)
      builder <! (dstF := ite (cond 5) srcF dstF)
      builder <! (dstG := ite (cond 6) srcG dstG)
      builder <! (dstH := ite (cond 7) srcH dstH)
    | _ -> raise InvalidOperandException
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vmovhpd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  startMark insAddr insLen builder
  match ins.Operands with
  | TwoOperands (dst, src) ->
    let dst = transOprToExpr64 ins insAddr insLen ctxt dst
    let src2, _src1 = transOprToExpr128 ins insAddr insLen ctxt src
    builder <! (dst := src2)
  | ThreeOperands (dst, src1, src2)->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let _src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
    let _src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt src2
    builder <! (dstA := src1A)
    builder <! (dstB := src2A)
    fillZeroHigh128 ctxt dst builder
  | _ -> raise InvalidOperandException
  endMark insAddr insLen builder

let vmovhlps ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src1, src2 = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
  let src1B, _src1A = transOprToExpr128 ins insAddr insLen ctxt src1
  let src2B, _src2A = transOprToExpr128 ins insAddr insLen ctxt src2
  startMark insAddr insLen builder
  builder <! (dstA := src1B)
  builder <! (dstB := src2B)
  fillZeroHigh128 ctxt dst builder
  endMark insAddr insLen builder

let vmovlhps ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src1, src2 = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
  let _src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
  let _src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt src2
  startMark insAddr insLen builder
  builder <! (dstA := src1A)
  builder <! (dstB := src2A)
  fillZeroHigh128 ctxt dst builder
  endMark insAddr insLen builder

let vmovlpd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  startMark insAddr insLen builder
  match ins.Operands with
  | TwoOperands (dst, src) ->
    let dst = transOprToExpr64 ins insAddr insLen ctxt dst
    let _src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
    builder <! (dst := src1)
  | ThreeOperands (dst, src1, src2)->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let src1B, _src1A = transOprToExpr128 ins insAddr insLen ctxt src1
    let _src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt src2
    builder <! (dstA := src2A)
    builder <! (dstB := src1B)
    fillZeroHigh128 ctxt dst builder
  | _ -> raise InvalidOperandException
  endMark insAddr insLen builder

let vmovmskpd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr ins insAddr insLen ctxt dst
  let dstSz = typeOf dst
  let mskpd r =
    match Register.getKind r with
    | Register.Kind.XMM -> movmskpd ins insAddr insLen ctxt
    | Register.Kind.YMM ->
      startMark insAddr insLen builder
      let src4, src3, src2, src1 = transOprToExpr256 ins insAddr insLen ctxt src
      let src63 = sExt dstSz (extractHigh 1<rt> src1)
      let src127 = (sExt dstSz (extractHigh 1<rt> src2)) << num1 dstSz
      let src191 = (sExt dstSz (extractHigh 1<rt> src3)) << numI32 2 dstSz
      let src255 = (sExt dstSz (extractHigh 1<rt> src4)) << numI32 3 dstSz
      builder <! (dst := src63 .| src127 .| src191 .| src255)
      endMark insAddr insLen builder
    | _ -> raise InvalidOperandException
  match src with
  | OprReg r -> mskpd r
  | _ -> raise InvalidOperandSizeException

let vmovmskps ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr ins insAddr insLen ctxt dst
  let dstSz = typeOf dst
  let mskpd r =
    match Register.getKind r with
    | Register.Kind.XMM -> movmskps ins insAddr insLen ctxt
    | Register.Kind.YMM ->
      startMark insAddr insLen builder
      let src4, src3, src2, src1 = transOprToExpr256 ins insAddr insLen ctxt src
      let src1A, src1B = extractLow 32<rt> src1, extractHigh 32<rt> src1
      let src2A, src2B = extractLow 32<rt> src2, extractHigh 32<rt> src2
      let src3A, src3B = extractLow 32<rt> src3, extractHigh 32<rt> src3
      let src4A, src4B = extractLow 32<rt> src4, extractHigh 32<rt> src4
      let src31 = sExt dstSz (extractHigh 1<rt> src1A)
      let src63 = sExt dstSz (extractHigh 1<rt> src1B) << num1 dstSz
      let src95 = (sExt dstSz (extractHigh 1<rt> src2A)) << numI32 2 dstSz
      let src127 = (sExt dstSz (extractHigh 1<rt> src2B)) << numI32 3 dstSz
      let src159 = (sExt dstSz (extractHigh 1<rt> src3A)) << numI32 4 dstSz
      let src191 = (sExt dstSz (extractHigh 1<rt> src3B)) << numI32 5 dstSz
      let src223 = (sExt dstSz (extractHigh 1<rt> src4A)) << numI32 6 dstSz
      let src255 = (sExt dstSz (extractHigh 1<rt> src4B)) << numI32 7 dstSz
      builder <! (dst := src31 .| src63 .| src95 .| src127)
      builder <! (dst := dst .| src159 .| src191 .| src223 .| src255)
      endMark insAddr insLen builder
    | _ -> raise InvalidOperandException
  match src with
  | OprReg r -> mskpd r
  | _ -> raise InvalidOperandSizeException

let vmovq ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let dst, src = getTwoOprs ins
  startMark insAddr insLen builder
  let n0 = num0 64<rt>
  let regToReg r1 r2 =
    match Register.getKind r1, Register.getKind r2 with
    | Register.Kind.XMM, Register.Kind.XMM ->
      let dstD, dstC, dstB, dstA = getPseudoRegVar256 ctxt (r128to256 dst)
      let srcA = getPseudoRegVar ctxt r2 1
      builder <! (dstA := srcA)
      builder <! (dstB := n0)
      builder <! (dstC := n0)
      builder <! (dstD := n0)
    | Register.Kind.XMM, Register.Kind.GP ->
      let dstD, dstC, dstB, dstA = getPseudoRegVar256 ctxt (r128to256 dst)
      let src = getRegVar ctxt r2
      builder <! (dstA := src)
      builder <! (dstB := n0)
      builder <! (dstC := n0)
      builder <! (dstD := n0)
    | Register.Kind.GP, Register.Kind.XMM ->
      let dst = getRegVar ctxt r1
      let srcA = getPseudoRegVar ctxt r2 1
      builder <! (dst := srcA)
    | _ -> raise InvalidOperandException
  match dst, src with
  | OprReg r1, OprReg r2 -> regToReg r1 r2
  | OprReg _, OprMem _ ->
    let dstD, dstC, dstB, dstA = getPseudoRegVar256 ctxt (r128to256 dst)
    let src = transOprToExpr ins insAddr insLen ctxt src
    builder <! (dstA := src)
    builder <! (dstB := n0)
    builder <! (dstC := n0)
    builder <! (dstD := n0)
  | OprMem _, OprReg r ->
    let dst = transOprToExpr ins insAddr insLen ctxt dst
    let srcA = getPseudoRegVar ctxt r 1
    builder <! (dst := srcA)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vmovsd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  startMark insAddr insLen builder
  match ins.Operands with
  | TwoOperands (OprMem _ , _) -> movsd ins insAddr insLen ctxt
  | TwoOperands (OprReg _ as dst, src) ->
    let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
    let src = transOprToExpr64 ins insAddr insLen ctxt src
    builder <! (dst1 := src)
    builder <! (dst2 := num0 64<rt>)
    fillZeroHigh128 ctxt dst builder
    endMark insAddr insLen builder
  | ThreeOperands (dst, src1, src2)->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let src1B, _src1A = transOprToExpr128 ins insAddr insLen ctxt src1
    let _src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt src2
    builder <! (dstA := src2A)
    builder <! (dstB := src1B)
    fillZeroHigh128 ctxt dst builder
    endMark insAddr insLen builder
  | _ -> raise InvalidOperandException

let vmovshdup ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let dst, src = getTwoOprs ins
  startMark insAddr insLen builder
  match getOperationSize ins with
  | 128<rt> ->
    let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
    let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
    builder <! (extractLow 32<rt> dst1 := extractHigh 32<rt> src1)
    builder <! (extractHigh 32<rt> dst1 := extractHigh 32<rt> src1)
    builder <! (extractLow 32<rt> dst2 := extractHigh 32<rt> src2)
    builder <! (extractHigh 32<rt> dst2 := extractHigh 32<rt> src2)
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dst4, dst3, dst2, dst1 = transOprToExpr256 ins insAddr insLen ctxt dst
    let src4, src3, src2, src1 = transOprToExpr256 ins insAddr insLen ctxt src
    builder <! (extractLow 32<rt> dst1 := extractHigh 32<rt> src1)
    builder <! (extractHigh 32<rt> dst1 := extractHigh 32<rt> src1)
    builder <! (extractLow 32<rt> dst2 := extractHigh 32<rt> src2)
    builder <! (extractHigh 32<rt> dst2 := extractHigh 32<rt> src2)
    builder <! (extractLow 32<rt> dst3 := extractHigh 32<rt> src3)
    builder <! (extractHigh 32<rt> dst3 := extractHigh 32<rt> src3)
    builder <! (extractLow 32<rt> dst4 := extractHigh 32<rt> src4)
    builder <! (extractHigh 32<rt> dst4 := extractHigh 32<rt> src4)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vmovsldup ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let dst, src = getTwoOprs ins
  startMark insAddr insLen builder
  match getOperationSize ins with
  | 128<rt> ->
    let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
    let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
    builder <! (extractLow 32<rt> dst1 := extractLow 32<rt> src1)
    builder <! (extractHigh 32<rt> dst1 := extractLow 32<rt> src1)
    builder <! (extractLow 32<rt> dst2 := extractLow 32<rt> src2)
    builder <! (extractHigh 32<rt> dst2 := extractLow 32<rt> src2)
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dst4, dst3, dst2, dst1 = transOprToExpr256 ins insAddr insLen ctxt dst
    let src4, src3, src2, src1 = transOprToExpr256 ins insAddr insLen ctxt src
    builder <! (extractLow 32<rt> dst1 := extractLow 32<rt> src1)
    builder <! (extractHigh 32<rt> dst1 := extractLow 32<rt> src1)
    builder <! (extractLow 32<rt> dst2 := extractLow 32<rt> src2)
    builder <! (extractHigh 32<rt> dst2 := extractLow 32<rt> src2)
    builder <! (extractLow 32<rt> dst3 := extractLow 32<rt> src3)
    builder <! (extractHigh 32<rt> dst3 := extractLow 32<rt> src3)
    builder <! (extractLow 32<rt> dst4 := extractLow 32<rt> src4)
    builder <! (extractHigh 32<rt> dst4 := extractLow 32<rt> src4)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vmovss ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  startMark insAddr insLen builder
  match ins.Operands with
  | TwoOperands (OprMem _ , _) -> movss ins insAddr insLen ctxt
  | TwoOperands (OprReg _ as dst, src) ->
    let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
    let src = transOprToExpr32 ins insAddr insLen ctxt src
    builder <! (extractLow 32<rt> dst1 := src)
    builder <! (extractHigh 32<rt> dst1 := num0 32<rt>)
    builder <! (dst2 := num0 64<rt>)
    fillZeroHigh128 ctxt dst builder
    endMark insAddr insLen builder
  | ThreeOperands (dst, src1, src2)->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
    let _src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt src2
    builder <! (extractLow 32<rt> dstA := extractLow 32<rt> src2A)
    builder <! (extractHigh 32<rt> dstA := extractHigh 32<rt> src1A)
    builder <! (dstB := src1B)
    fillZeroHigh128 ctxt dst builder
    endMark insAddr insLen builder
  | _ -> raise InvalidOperandException

let vmovups ins insAddr insLen ctxt = buildVectorMove ins insAddr insLen ctxt

let vmovupd ins insAddr insLen ctxt = buildVectorMove ins insAddr insLen ctxt

let vmulpd ins insAddr insLen ctxt =
  vexedPackedFPBinOp64 ins insAddr insLen ctxt fmul

let vmulps ins insAddr insLen ctxt =
  vexedPackedFPBinOp32 ins insAddr insLen ctxt fmul

let vmulsd ins insAddr insLen ctxt =
  vexedScalarFPBinOp ins insAddr insLen ctxt 64<rt> fmul

let vmulss ins insAddr insLen ctxt =
  vexedScalarFPBinOp ins insAddr insLen ctxt 32<rt> fmul

let vorpd ins insAddr insLen ctxt =
  vexedPackedFPBinOp64 ins insAddr insLen ctxt (.|)

let vorps ins insAddr insLen ctxt =
  vexedPackedFPBinOp32 ins insAddr insLen ctxt (.|)

let vpaddb ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 8<rt> (opP (.+)) 32

let vpaddd ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> (opP (.+)) 16

let vpaddq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> (opP (.+)) 16

let vpalignr ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let dst, src1, src2, imm = getFourOprs ins
  let oprSize = getOperationSize ins
  let imm = transOprToExpr ins insAddr insLen ctxt imm
  let n8 = numU32 8u 256<rt>
  let imm = zExt 256<rt> imm
  startMark insAddr insLen builder
  if oprSize = 128<rt> then
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
    let src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt src2
    let t = tmpVar 256<rt>
    let tSrc1, tSrc2 = tmpVars2 oprSize
    builder <! (tSrc1 := concat src1B src1A)
    builder <! (tSrc2 := concat src2B src2A)
    builder <! (t := (concat tSrc1 tSrc2) >> (imm .* n8))
    builder <! (dstA := extractLow 64<rt> t)
    builder <! (dstB := extractHigh 64<rt> (extractLow 128<rt> t))
    fillZeroHigh128 ctxt dst builder
  elif oprSize = 256<rt> then
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
    let src1D, src1C, src1B, src1A = transOprToExpr256 ins insAddr insLen ctxt src1
    let src2D, src2C, src2B, src2A = transOprToExpr256 ins insAddr insLen ctxt src2
    let t1, t2 = tmpVars2 256<rt>
    let tSrc1High, tSrc1Low, tSrc2High, tSrc2Low = tmpVars4 128<rt>
    builder <! (tSrc1Low := concat src1B src1A)
    builder <! (tSrc1High := concat src1D src1C)
    builder <! (tSrc2Low := concat src2B src2A)
    builder <! (tSrc2High := concat src2D src2C)
    builder <! (t1 := (concat tSrc1Low tSrc2Low) >> (imm .* n8))
    builder <! (dstA := extractLow 64<rt> t1)
    builder <! (dstB := extractHigh 64<rt> (extractLow 128<rt> t1))
    builder <! (t2 := (concat tSrc1High tSrc2High) >> (imm .* n8))
    builder <! (dstC := extractLow 64<rt> t2)
    builder <! (dstD := extractHigh 64<rt> (extractLow 128<rt> t2))
  else raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vpand ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opPand 16

let vpandn ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opPandn 16

let vpbroadcastb ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let oprSize = getOperationSize ins
  let src =
    match src with
    | OprReg _ -> transOprToExpr128 ins insAddr insLen ctxt src |> snd
    | OprMem _ -> transOprToExpr ins insAddr insLen ctxt src
    | _ -> raise InvalidOperandException
    |> extractLow 8<rt>
  let tSrc = tmpVar 8<rt>
  startMark insAddr insLen builder
  builder <! (tSrc := src)
  let tmps = Array.init 8 (fun _ -> tmpVar 8<rt>)
  for i in 0 .. 7 do builder <! (tmps.[i] := tSrc) done
  let t = tmpVar 64<rt>
  builder <! (t := concatExprs tmps)
  match oprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    builder <! (dstA := t)
    builder <! (dstB := t)
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
    builder <! (dstA := t)
    builder <! (dstB := t)
    builder <! (dstC := t)
    builder <! (dstD := t)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vpbroadcastd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let oprSize = getOperationSize ins
  let temp = tmpVar 32<rt>
  let src =
    match src with
    | OprReg _ -> transOprToExpr128 ins insAddr insLen ctxt src |> snd
    | OprMem _ -> transOprToExpr ins insAddr insLen ctxt src
    | _ -> raise InvalidOperandException
    |> extractLow 32<rt>
  startMark insAddr insLen builder
  builder <! (temp := src)
  match oprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    builder <! (dstA := temp)
    builder <! (dstB := temp)
    fillZeroFromVLToMaxVL ctxt dst 128 512 builder
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
    builder <! (dstA := temp)
    builder <! (dstB := temp)
    builder <! (dstC := temp)
    builder <! (dstD := temp)
    fillZeroFromVLToMaxVL ctxt dst 256 512 builder
  | 512<rt> ->
    let kl, vl = 16, 512
    let ePrx = getEVEXPrx ins.VEXInfo
    let k = getRegVar ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
    let masking dst =
      match ePrx.Z with
      | Zeroing -> num0 32<rt>
      | Merging -> dst
    let cond idx =
      (* no write mask *)
      let noWritemask = if ePrx.AAA = 0uy then num1 1<rt> else num0 1<rt>
      extract k 1<rt> idx .| noWritemask
    let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
      transOprToExpr512 ins insAddr insLen ctxt dst
    let assign dst idx sPos =
      let extDst = extract dst 32<rt> sPos
      extDst := ite (cond idx) temp (masking extDst)
    builder <! (assign dstA 0 0)
    builder <! (assign dstA 1 32)
    builder <! (assign dstB 2 0)
    builder <! (assign dstB 3 32)
    builder <! (assign dstC 4 0)
    builder <! (assign dstC 5 32)
    builder <! (assign dstD 6 0)
    builder <! (assign dstD 7 32)
    builder <! (assign dstE 8 0)
    builder <! (assign dstE 9 32)
    builder <! (assign dstF 10 0)
    builder <! (assign dstF 11 32)
    builder <! (assign dstG 12 0)
    builder <! (assign dstG 13 32)
    builder <! (assign dstH 14 0)
    builder <! (assign dstH 15 32)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vpcmpeqb ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 8<rt> opPcmpeqb 64

let vpcmpeqd ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> opPcmpeqd 32

let vpcmpeqq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opPcmpeqq 16

let vpcmpgtb ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 8<rt> opPcmpgtb 64

let vpinsrd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src1, src2, imm = getFourOprs ins
  let oprSize = getOperationSize ins
  let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
  let src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
  let src2 = transOprToExpr ins insAddr insLen ctxt src2
  let imm = transOprToExpr ins insAddr insLen ctxt imm
  let sel, mask, temp, tDst = tmpVars4 128<rt>
  startMark insAddr insLen builder (* write_d_element *)
  builder <! (sel := zExt 128<rt> (extractLow 2<rt> imm))
  builder <! (mask := numU64 0xFFFFFFFFUL 128<rt> << (sel .* numI32 32 128<rt>))
  builder <!
    (temp := ((zExt 128<rt> src2) << (sel .* numI32 32 128<rt>)) .& mask)
  builder <! (tDst := (((concat src1B src1A) .& AST.not mask) .| temp))
  builder <! (dstA := extract tDst 64<rt> 0)
  builder <! (dstB := extract tDst 64<rt> 64)
  fillZeroFromVLToMaxVL ctxt dst 128 512 builder
  endMark insAddr insLen builder

let vpminub ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 8<rt> opPminub 64

let vpminud ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> opPminud 32

let opVpmuludq _ =
  let low32 expr = expr .& numI64 0xffffffffL 64<rt>
  Array.map2 (fun e1 e2 -> low32 e1 .* low32 e2)

let vpmuludq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opVpmuludq 16

let vpor ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opPor 8

let vpshufb ins insAddr insLen ctxt =
  let dst, src1, src2 = getThreeOprs ins
  let oprSize = getOperationSize ins
  let cnt = if oprSize = 128<rt> then 16 else 32
  let builder = new StmtBuilder (2 * cnt)
  let tDst, tSrc1, tSrc2 = tmpVars3 oprSize
  startMark insAddr insLen builder
  match oprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
    let src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt src2
    builder <! (tSrc1 := concat src1B src1A)
    builder <! (tSrc2 := concat src2B src2A)
    let tmps = Array.init cnt (fun _ -> tmpVar 8<rt>)
    let mask = numU32 0x0Fu 8<rt>
    for i in 0 .. cnt - 1 do
      let cond = extract tSrc2 1<rt> (i * 8 + 7)
      let idx = (extract tSrc2 8<rt> (i * 8)) .& mask
      let s = zExt oprSize idx .* numI32 8 oprSize
      builder <!
        (tmps.[i] := ite cond (num0 8<rt>) (extractLow 8<rt> (tSrc1 >> s)))
    done
    builder <! (tDst := concatExprs tmps)
    builder <! (dstA := extractLow 64<rt> tDst)
    builder <! (dstB := extractHigh 64<rt> tDst)
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
    let src1D, src1C, src1B, src1A =
      transOprToExpr256 ins insAddr insLen ctxt src1
    let src2D, src2C, src2B, src2A =
      transOprToExpr256 ins insAddr insLen ctxt src2
    builder <! (tSrc1 := concat (concat src1D src1C) (concat src1B src1A))
    builder <! (tSrc2 := concat (concat src2D src2C) (concat src2B src2A))
    let tmps = Array.init cnt (fun _ -> tmpVar 8<rt>)
    let mask = numU32 0x0Fu 8<rt>
    for i in 0 .. cnt - 1 do
      let cond = extract tSrc2 1<rt> (i * 8 + 7)
      let idx = (extract tSrc2 8<rt> (i * 8)) .& mask
      let s = zExt oprSize idx .* numI32 8 oprSize
      builder <!
        (tmps.[i] := ite cond (num0 8<rt>) (extractLow 8<rt> (tSrc1 >> s)))
    done
    builder <! (tDst := concatExprs tmps)
    builder <! (dstA := extractLow 64<rt> tDst)
    builder <! (dstB := extract tDst 64<rt> 64)
    builder <!
      (dstC := extract tDst 64<rt> (RegType.toBitWidth (typeOf tDst) - 64))
    builder <! (dstD := extractHigh 64<rt> tDst)
  | 512<rt> ->
    let kl, vl = 64, 512
    let ePrx = getEVEXPrx ins.VEXInfo
    let k = getRegVar ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
    let cond idx =
      if ePrx.AAA = 0uy then num0 1<rt> (* no write mask *)
      else extract k 1<rt> idx
    let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
      transOprToExpr512 ins insAddr insLen ctxt dst
    let src1H, src1G, src1F, src1E, src1D, src1C, src1B, src1A =
      transOprToExpr512 ins insAddr insLen ctxt src1
    let src2H, src2G, src2F, src2E, src2D, src2C, src2B, src2A =
      transOprToExpr512 ins insAddr insLen ctxt src2
    builder <!
      (tSrc1 := concat (concat (concat src1H src1G) (concat src1F src1E))
                       (concat (concat src1D src1C) (concat src1B src1A)))
    builder <!
      (tSrc2 := concat (concat (concat src2H src2G) (concat src2F src2E))
                       (concat (concat src2D src2C) (concat src2B src2A)))
    let num0F = numU32 0x0Fu 8<rt>
    let jmask = tmpVar 8<rt>
    let tmps = Array.init kl (fun _ -> tmpVar 8<rt>)
    builder <! (jmask := numI32 (kl - 1) 8<rt> .& (AST.not num0F))
    for i in 0 .. kl - 1 do
      let cond idx =
        (* no write mask *)
        let noWritemask = if ePrx.AAA = 0uy then num1 1<rt> else num0 1<rt>
        extract k 1<rt> idx .| noWritemask
      let index1 = extract tSrc2 8<rt> (i * 8)
      let index2 = (index1 .& num0F) .+ (numI32 i 8<rt> .& jmask)
      let src1 =
        extractLow 8<rt> (tSrc1 >> (zExt oprSize (index2 .* numI32 8 8<rt>)))
      builder <! (tmps.[i] := ite (cond i) (ite (extractHigh 1<rt> index1)
                                                (num0 8<rt>) src1) (num0 8<rt>))
    done
    builder <! (tDst := concatExprs tmps)
    builder <! (dstA := extract tDst 64<rt> 0)
    builder <! (dstB := extract tDst 64<rt> 64)
    builder <! (dstC := extract tDst 64<rt> 128)
    builder <! (dstD := extract tDst 64<rt> 192)
    builder <! (dstE := extract tDst 64<rt> 256)
    builder <! (dstF := extract tDst 64<rt> 320)
    builder <! (dstG := extract tDst 64<rt> 384)
    builder <! (dstH := extract tDst 64<rt> 448)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vpshufd ins insAddr insLen ctxt =
  let dst, src, ord = getThreeOprs ins
  let ord = transOprToExpr ins insAddr insLen ctxt ord
  let oprSize = getOperationSize ins
  let cnt = RegType.toBitWidth oprSize / 32
  let builder = new StmtBuilder (2 * cnt)
  let tmps = Array.init cnt (fun _ -> tmpVar 32<rt>)
  let n32 = numI32 32 oprSize
  let mask2 = numI32 3 32<rt> (* 2-bit mask *)
  let tSrc = tmpVar oprSize
  let tDst = tmpVar oprSize
  let shuffleDword src =
    for i in 1 .. cnt do
      let order =
        ((extractLow 32<rt> ord) >> (numI32 ((i - 1) * 2) 32<rt>)) .& mask2
      let order' = zExt oprSize order
      builder <! (tmps.[i - 1] := extractLow 32<rt> (src >> (order' .* n32)))
    done
  startMark insAddr insLen builder
  match oprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
    builder <! (tSrc := concat srcB srcA)
    shuffleDword tSrc
    builder <! (tDst := concatExprs tmps)
    builder <! (dstA := extract tDst 64<rt> 0)
    builder <! (dstB := extract tDst 64<rt> 64)
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
    let srcD, srcC, srcB, srcA = transOprToExpr256 ins insAddr insLen ctxt src
    builder <! (tSrc := concat (concat srcD srcC) (concat srcB srcA))
    shuffleDword tSrc
    builder <! (tDst := concatExprs tmps)
    builder <! (dstA := extract tDst 64<rt> 0)
    builder <! (dstB := extract tDst 64<rt> 64)
    builder <! (dstC := extract tDst 64<rt> 128)
    builder <! (dstD := extract tDst 64<rt> 192)
    fillZeroHigh256 ctxt dst builder
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let opShiftVpackedDataLogical oprSize packSz shift src1 (src2: Expr []) =
  let count = src2.[0] |> zExt oprSize
  let cond = gt count (numI32 ((int packSz) - 1) oprSize)
  let shifted expr = extract (shift (zExt oprSize expr) count) packSz 0
  Array.map (fun e -> ite cond (num0 packSz) (shifted e)) src1

let opVpslld oprSize = opShiftVpackedDataLogical oprSize 32<rt> (<<)

let vpslld ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> opVpslld 16

let opVpsrld oprSize = opShiftVpackedDataLogical oprSize 32<rt> (<<)

let vpsrld ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> opVpsrld 16

let shiftVDQ ins insAddr insLen ctxt shift =
  let builder = new StmtBuilder (8)
  let dst, src, cnt = getThreeOprs ins
  let cnt = transOprToExpr ins insAddr insLen ctxt cnt |> castNum 8<rt>
  let oprSize = getOperationSize ins
  let t = tmpVar 8<rt>
  startMark insAddr insLen builder
  builder <! (t := ite (lt (numU32 15u 8<rt>) cnt) (numU32 16u 8<rt>) cnt)
  match oprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
    let tDst, tSrc = tmpVars2 128<rt>
    builder <! (tDst := concat dstB dstA)
    builder <! (tSrc := concat srcB srcA)
    builder <! (tDst := (shift tSrc (zExt oprSize (t .* numU32 8u 8<rt>))))
    builder <! (dstA := extractLow 64<rt> tDst)
    builder <! (dstB := extractHigh 64<rt> tDst)
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
    let srcD, srcC, srcB, srcA = transOprToExpr256 ins insAddr insLen ctxt src
    let tDst, tSrc = tmpVars2 256<rt>
    builder <! (tDst := concat (concat dstD dstC) (concat dstB dstA))
    builder <! (tSrc := concat (concat srcD srcC) (concat srcB srcA))
    builder <! (tDst := (shift tSrc (zExt oprSize (t .* numU32 8u 8<rt>))))
    builder <! (dstA := extractLow 64<rt> tDst)
    builder <! (dstB := extractLow 64<rt> tDst)
    builder <! (dstC := extract tDst 64<rt> 128)
    builder <! (dstD := extractHigh 64<rt> tDst)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

(*
let opVpslldq oprSize = opShiftVpackedDataLogical oprSize 128<rt> (<<)
let opVpslrdq oprSize = opShiftVpackedDataLogical oprSize 128<rt> (>>)

let vpslldq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 128<rt> opVpslldq 16

let vpsrldq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 128<rt> opVpslrdq 16
*)

let vpslldq ins insAddr insLen ctxt = shiftVDQ ins insAddr insLen ctxt (<<)
let vpsrldq ins insAddr insLen ctxt = shiftVDQ ins insAddr insLen ctxt (>>)

let opVpsllq oprSize = opShiftVpackedDataLogical oprSize 64<rt> (<<)
let opVpsrlq oprSize = opShiftVpackedDataLogical oprSize 64<rt> (>>)

let vpsllq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opVpsllq 16

let vpsrlq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opVpsllq 16

let vpsubb ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 8<rt> opPsub 128

let vpunpckhdq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> opPunpckHigh 16

let vpunpckhqdq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opPunpckHigh 16

let vpunpckldq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> opPunpckLow 16

let vpunpcklqdq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opPunpckLow 16

let vpxor ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src1, src2 = getThreeOprs ins
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  match oprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
    let src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt src2
    builder <! (dstB := src1B <+> src2B)
    builder <! (dstA := src1A <+> src2A)
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
    let src1D, src1C, src1B, src1A =
      transOprToExpr256 ins insAddr insLen ctxt src1
    let src2D, src2C, src2B, src2A =
      transOprToExpr256 ins insAddr insLen ctxt src2
    builder <! (dstD := src1D <+> src2D)
    builder <! (dstC := src1C <+> src2C)
    builder <! (dstB := src1B <+> src2B)
    builder <! (dstA := src1A <+> src2A)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vshufi32x4 ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let dst, src1, src2, imm = getFourOprs ins
  let oprSize = getOperationSize ins
  let ePrx = getEVEXPrx ins.VEXInfo
  let k = getRegVar ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
  let masking dst =
    match ePrx.Z with
    | Zeroing -> num0 32<rt>
    | Merging -> dst
  let cond idx =
    (* no write mask *)
    let noWritemask = if ePrx.AAA = 0uy then num1 1<rt> else num0 1<rt>
    extract k 1<rt> idx .| noWritemask
  let imm = transOprToExpr ins insAddr insLen ctxt imm
  let tmpDest, tmp = tmpVars2 oprSize
  startMark insAddr insLen builder
  match oprSize with
  | 256<rt> ->
    let kl, vl = 8, 256
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
    let src1D, src1C, src1B, src1A =
      transOprToExpr256 ins insAddr insLen ctxt src1
    let src2D, src2C, src2B, src2A =
      transOprToExpr256 ins insAddr insLen ctxt src2
    let conSrc1 = concat (concat src1D src1C) (concat src1B src1A)
    let conSrc2 = concat (concat src2D src2C) (concat src2B src2A)
    let srcLow src = extract src 128<rt> 0
    let srcHigh src = extract src 128<rt> 128
    let select2 src pos = ite (extract imm 1<rt> pos) (srcHigh src) (srcLow src)
    builder <! (extract tmpDest 128<rt> 0 := select2 conSrc1 0)
    builder <! (extract tmpDest 128<rt> 128 := select2 conSrc2 1)
    let assign dst idx dstPos tmpPos =
      let dst = extract dst 32<rt> dstPos
      dst := ite (cond idx) (extract tmpDest 32<rt> tmpPos) (masking dst)
    builder <! (assign dstA 0 0 0)
    builder <! (assign dstA 1 32 32)
    builder <! (assign dstB 2 0 64)
    builder <! (assign dstB 3 32 96)
    builder <! (assign dstC 4 0 128)
    builder <! (assign dstC 5 32 160)
    builder <! (assign dstD 6 0 192)
    builder <! (assign dstD 7 32 224)
  | 512<rt> ->
    let kl, vl = 16, 512
    let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
      transOprToExpr512 ins insAddr insLen ctxt dst
    let src1H, src1G, src1F, src1E, src1D, src1C, src1B, src1A =
      transOprToExpr512 ins insAddr insLen ctxt src1
    let src2H, src2G, src2F, src2E, src2D, src2C, src2B, src2A =
      transOprToExpr512 ins insAddr insLen ctxt src2
    let conSrc1 = concat (concat (concat src1H src1G) (concat src1F src1E))
                         (concat (concat src1D src1C) (concat src1B src1A))
    let conSrc2 = concat (concat (concat src2H src2G) (concat src2F src2E))
                         (concat (concat src2D src2C) (concat src2B src2A))
    let src128 src = extract src 128<rt> 0
    let src256 src = extract src 128<rt> 128
    let src384 src = extract src 128<rt> 256
    let src512 src = extract src 128<rt> 384
    let num0 = num0 2<rt>
    let num1 = num1 2<rt>
    let num2 = numI32 2 2<rt>
    let control pos = extract imm 2<rt> pos
    let select4 src pos =
      let control = control pos
      ite (control == num0) (src128 src)
       (ite (control == num1) (src256 src) (ite (control == num2) (src384 src)
                                             (src512 src)))
    let tmpSrc2 = Array.init kl (fun _ -> tmpVar 32<rt>)
    for i in 0 .. kl - 1 do
      let tSrc2 =
        match src2 with
          | OprMem _ when ePrx.B = 1uy -> extract src2A 32<rt> 0
          | _ -> extract conSrc2 32<rt> (i * 32)
      builder <! (tmpSrc2.[i] := tSrc2)
    let tmpSrc2 = concatExprs tmpSrc2
    builder <! (extract tmpDest 128<rt> 0 := select4 conSrc1 0)
    builder <! (extract tmpDest 128<rt> 128 := select4 conSrc2 2)
    builder <! (extract tmpDest 128<rt> 256 := select4 tmpSrc2 4)
    builder <! (extract tmpDest 128<rt> 384 := select4 tmpSrc2 6)
    let assign dst idx dstPos tmpPos =
      let dst = extract dst 32<rt> dstPos
      dst := ite (cond idx) (extract tmpDest 32<rt> tmpPos) (masking dst)
    builder <! (assign dstA 0 0 0)
    builder <! (assign dstA 1 32 32)
    builder <! (assign dstB 2 0 64)
    builder <! (assign dstB 3 32 96)
    builder <! (assign dstC 4 0 128)
    builder <! (assign dstC 5 32 160)
    builder <! (assign dstD 6 0 192)
    builder <! (assign dstD 7 32 224)
    builder <! (assign dstE 8 0 256)
    builder <! (assign dstE 9 32 288)
    builder <! (assign dstF 10 0 320)
    builder <! (assign dstF 11 32 352)
    builder <! (assign dstG 12 0 384)
    builder <! (assign dstG 13 32 416)
    builder <! (assign dstH 14 0 448)
    builder <! (assign dstH 15 32 480)
  | _ -> raise InvalidOperandException
  endMark insAddr insLen builder

let vshufpd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src1, src2, imm = getFourOprs ins
  let imm = transOprToExpr ins insAddr insLen ctxt imm
  let cond1 = extractLow 1<rt> imm
  let cond2 = extract imm 1<rt> 1
  let cond3 = extract imm 1<rt> 2
  let cond4 = extract imm 1<rt> 3
  startMark insAddr insLen builder
  match getOperationSize ins with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
    let src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt src2
    builder <! (dstA := ite cond1 src1B src1A)
    builder <! (dstB := ite cond2 src2B src2A)
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
    let sr1D, sr1C, sr1B, sr1A = transOprToExpr256 ins insAddr insLen ctxt src1
    let sr2D, sr2C, sr2B, sr2A = transOprToExpr256 ins insAddr insLen ctxt src2
    builder <! (dstA := ite cond1 sr1B sr1A)
    builder <! (dstB := ite cond2 sr2B sr2A)
    builder <! (dstC := ite cond3 sr1C sr1D)
    builder <! (dstB := ite cond4 sr2C sr2D)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vshufps ins insAddr insLen ctxt =
  let builder = new StmtBuilder (32)
  let dst, src1, src2, imm = getFourOprs ins
  let imm = transOprToExpr ins insAddr insLen ctxt imm
  let cond1 = extractLow 2<rt> imm
  let cond2 = extract imm 2<rt> 2
  let cond3 = extract imm 2<rt> 4
  let cond4 = extract imm 2<rt> 6
  let doShuf cond dst e1 e2 =
    builder <! (dst := num0 32<rt>)
    builder <! (dst := ite (cond == num0 2<rt>) (extractLow 32<rt> e1) dst)
    builder <! (dst := ite (cond == num1 2<rt>) (extractHigh 32<rt> e1) dst)
    builder <! (dst := ite (cond == numI32 2 2<rt>) (extractLow 32<rt> e2) dst)
    builder <! (dst := ite (cond == numI32 3 2<rt>) (extractHigh 32<rt> e2) dst)
  startMark insAddr insLen builder
  match getOperationSize ins with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let sr1B, sr1A = transOprToExpr128 ins insAddr insLen ctxt src1
    let sr2B, sr2A = transOprToExpr128 ins insAddr insLen ctxt src2
    doShuf cond1 (extractLow 32<rt> dstA) sr1A sr1B
    doShuf cond2 (extractHigh 32<rt> dstA) sr1A sr1B
    doShuf cond3 (extractLow 32<rt> dstB) sr2A sr2B
    doShuf cond4 (extractHigh 32<rt> dstB) sr2A sr2B
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
    let sr1D, sr1C, sr1B, sr1A = transOprToExpr256 ins insAddr insLen ctxt src1
    let sr2D, sr2C, sr2B, sr2A = transOprToExpr256 ins insAddr insLen ctxt src2
    doShuf cond1 (extractLow 32<rt> dstA) sr1A sr1B
    doShuf cond2 (extractHigh 32<rt> dstA) sr1A sr1B
    doShuf cond3 (extractLow 32<rt> dstB) sr2A sr2B
    doShuf cond4 (extractHigh 32<rt> dstB) sr2A sr2B
    doShuf cond1 (extractLow 32<rt> dstC) sr1C sr1D
    doShuf cond2 (extractHigh 32<rt> dstC) sr1C sr1D
    doShuf cond3 (extractLow 32<rt> dstD) sr2C sr2D
    doShuf cond4 (extractHigh 32<rt> dstD) sr2C sr2D
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vsqrtpd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let dst, src = getTwoOprs ins
  let oprSz = getOperationSize ins
  startMark insAddr insLen builder
  match oprSz with
  | 128<rt> ->
    let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
    let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
    builder <! (dst1 := fSqrt src1)
    builder <! (dst2 := fSqrt src2)
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dst4, dst3, dst2, dst1 = transOprToExpr256 ins insAddr insLen ctxt dst
    let sr4, sr3, sr2, sr1 = transOprToExpr256 ins insAddr insLen ctxt src
    builder <! (dst1 := fSqrt sr1)
    builder <! (dst2 := fSqrt sr2)
    builder <! (dst3 := fSqrt sr3)
    builder <! (dst4 := fSqrt sr4)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vsqrtps ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let dst, src = getTwoOprs ins
  let oprSz = getOperationSize ins
  let do32PackedSqrt dst64 src builder =
    let dstA, dstB = extractLow 32<rt> dst64, extractHigh 32<rt> dst64
    let srcA, srcB = extractLow 32<rt> src, extractHigh 32<rt> src
    builder <! (dstA := fSqrt srcA)
    builder <! (dstB := fSqrt srcB)
  startMark insAddr insLen builder
  match oprSz with
  | 128<rt> ->
    let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
    let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
    do32PackedSqrt dst1 srcA builder
    do32PackedSqrt dst2 srcB builder
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dst4, dst3, dst2, dst1 = transOprToExpr256 ins insAddr insLen ctxt dst
    let srD, srC, srB, srA = transOprToExpr256 ins insAddr insLen ctxt src
    do32PackedSqrt dst1 srA  builder
    do32PackedSqrt dst2 srB  builder
    do32PackedSqrt dst3 srC  builder
    do32PackedSqrt dst4 srD  builder
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vsqrts ins insAddr insLen ctxt sz =
  let builder = new StmtBuilder (16)
  let dst, src1, src2 = getThreeOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
  startMark insAddr insLen builder
  match sz with
  | 32<rt> ->
    let src2 = transOprToExpr32 ins insAddr insLen ctxt src2
    builder <! (extractLow 32<rt> dst1 := fSqrt src2)
    builder <! (extractHigh 32<rt> dst1 := extractHigh 32<rt> src1A)
  | 64<rt> ->
    let src2 = transOprToExpr64 ins insAddr insLen ctxt src2
    builder <! (dst1 := fSqrt src2)
  | _ -> raise InvalidOperandSizeException
  builder <! (dst2 := src1B)
  fillZeroHigh128 ctxt dst builder
  endMark insAddr insLen builder

let vsqrtsd ins insAddr insLen ctxt =
  vsqrts ins insAddr insLen ctxt 64<rt>

let vsqrtss ins insAddr insLen ctxt =
  vsqrts ins insAddr insLen ctxt 32<rt>

let vsubpd ins insAddr insLen ctxt =
  vexedPackedFPBinOp64 ins insAddr insLen ctxt fsub

let vsubps ins insAddr insLen ctxt =
  vexedPackedFPBinOp32 ins insAddr insLen ctxt fsub

let vsubsd ins insAddr insLen ctxt =
  vexedScalarFPBinOp ins insAddr insLen ctxt 64<rt> fsub

let vsubss ins insAddr insLen ctxt =
  vexedScalarFPBinOp ins insAddr insLen ctxt 32<rt> fsub

let vunpckhpd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src1, src2 = getThreeOprs ins
  startMark insAddr insLen builder
  match getOperationSize ins with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let src1B, _src1A = transOprToExpr128 ins insAddr insLen ctxt src1
    let src2B, _src2A = transOprToExpr128 ins insAddr insLen ctxt src2
    builder <! (dstA := src1B)
    builder <! (dstB := src2B)
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
    let sr1D, _, sr1B, _ = transOprToExpr256 ins insAddr insLen ctxt src1
    let sr2D, _, sr2B, _ = transOprToExpr256 ins insAddr insLen ctxt src2
    builder <! (dstA := sr1B)
    builder <! (dstB := sr2B)
    builder <! (dstC := sr1D)
    builder <! (dstD := sr2D)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vunpckhps ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let dst, src1, src2 = getThreeOprs ins
  startMark insAddr insLen builder
  match getOperationSize ins with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let src1B, _src1A = transOprToExpr128 ins insAddr insLen ctxt src1
    let src2B, _src2A = transOprToExpr128 ins insAddr insLen ctxt src2
    builder <! (extractLow 32<rt> dstA := extractLow 32<rt> src1B)
    builder <! (extractHigh 32<rt> dstA := extractLow 32<rt> src2B)
    builder <! (extractLow 32<rt> dstB := extractHigh 32<rt> src1B)
    builder <! (extractHigh 32<rt> dstB := extractHigh 32<rt> src2B)
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
    let sr1D, _, sr1B, _ = transOprToExpr256 ins insAddr insLen ctxt src1
    let sr2D, _, sr2B, _ = transOprToExpr256 ins insAddr insLen ctxt src2
    builder <! (extractLow 32<rt> dstA := extractLow 32<rt> sr1B)
    builder <! (extractHigh 32<rt> dstA := extractLow 32<rt> sr2B)
    builder <! (extractLow 32<rt> dstB := extractHigh 32<rt> sr1B)
    builder <! (extractHigh 32<rt> dstB := extractHigh 32<rt> sr2B)
    builder <! (extractLow 32<rt> dstC := extractLow 32<rt> sr1D)
    builder <! (extractHigh 32<rt> dstC := extractLow 32<rt> sr2D)
    builder <! (extractLow 32<rt> dstD := extractHigh 32<rt> sr1D)
    builder <! (extractHigh 32<rt> dstD := extractHigh 32<rt> sr2D)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vunpcklpd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src1, src2 = getThreeOprs ins
  startMark insAddr insLen builder
  match getOperationSize ins with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let _src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
    let _src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt src2
    builder <! (dstA := src1A)
    builder <! (dstB := src2A)
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
    let _, src1C, _, src1A = transOprToExpr256 ins insAddr insLen ctxt src1
    let _, src2C, _, src2A = transOprToExpr256 ins insAddr insLen ctxt src2
    builder <! (dstA := src1A)
    builder <! (dstB := src2A)
    builder <! (dstC := src1C)
    builder <! (dstD := src2C)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vunpcklps ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let dst, src1, src2 = getThreeOprs ins
  startMark insAddr insLen builder
  match getOperationSize ins with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let _src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
    let _src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt src2
    builder <! (extractLow 32<rt> dstA := extractLow 32<rt> src1A)
    builder <! (extractHigh 32<rt> dstA := extractLow 32<rt> src2A)
    builder <! (extractLow 32<rt> dstB := extractHigh 32<rt> src1A)
    builder <! (extractHigh 32<rt> dstB := extractHigh 32<rt> src2A)
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
    let _, src1C, _, src1A = transOprToExpr256 ins insAddr insLen ctxt src1
    let _, src2C, _, src2A = transOprToExpr256 ins insAddr insLen ctxt src2
    builder <! (extractLow 32<rt> dstA := extractLow 32<rt> src1A)
    builder <! (extractHigh 32<rt> dstA := extractLow 32<rt> src2A)
    builder <! (extractLow 32<rt> dstB := extractHigh 32<rt> src1A)
    builder <! (extractHigh 32<rt> dstB := extractHigh 32<rt> src2A)
    builder <! (extractLow 32<rt> dstC := extractLow 32<rt> src1C)
    builder <! (extractHigh 32<rt> dstC := extractLow 32<rt> src2C)
    builder <! (extractLow 32<rt> dstD := extractHigh 32<rt> src1C)
    builder <! (extractHigh 32<rt> dstD := extractHigh 32<rt> src2C)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vxorpd ins insAddr insLen ctxt =
  vexedPackedFPBinOp64 ins insAddr insLen ctxt (<+>)

let vxorps ins insAddr insLen ctxt =
  vexedPackedFPBinOp32 ins insAddr insLen ctxt (<+>)

let vzeroupper ins insAddr insLen ctxt =
  let builder = new StmtBuilder (32)
  startMark insAddr insLen builder
  let n0 = num0 64<rt>
  builder <! (getPseudoRegVar ctxt R.YMM0 3 := n0)
  builder <! (getPseudoRegVar ctxt R.YMM0 4 := n0)
  builder <! (getPseudoRegVar ctxt R.YMM1 3 := n0)
  builder <! (getPseudoRegVar ctxt R.YMM1 4 := n0)
  builder <! (getPseudoRegVar ctxt R.YMM2 3 := n0)
  builder <! (getPseudoRegVar ctxt R.YMM2 4 := n0)
  builder <! (getPseudoRegVar ctxt R.YMM3 3 := n0)
  builder <! (getPseudoRegVar ctxt R.YMM3 4 := n0)
  builder <! (getPseudoRegVar ctxt R.YMM4 3 := n0)
  builder <! (getPseudoRegVar ctxt R.YMM4 4 := n0)
  builder <! (getPseudoRegVar ctxt R.YMM5 3 := n0)
  builder <! (getPseudoRegVar ctxt R.YMM5 4 := n0)
  builder <! (getPseudoRegVar ctxt R.YMM6 3 := n0)
  builder <! (getPseudoRegVar ctxt R.YMM6 4 := n0)
  builder <! (getPseudoRegVar ctxt R.YMM7 3 := n0)
  builder <! (getPseudoRegVar ctxt R.YMM7 4 := n0)
  if is64bit ctxt then
    builder <! (getPseudoRegVar ctxt R.YMM8 3 := n0)
    builder <! (getPseudoRegVar ctxt R.YMM8 4 := n0)
    builder <! (getPseudoRegVar ctxt R.YMM9 3 := n0)
    builder <! (getPseudoRegVar ctxt R.YMM9 4 := n0)
    builder <! (getPseudoRegVar ctxt R.YMM10 3 := n0)
    builder <! (getPseudoRegVar ctxt R.YMM10 4 := n0)
    builder <! (getPseudoRegVar ctxt R.YMM11 3 := n0)
    builder <! (getPseudoRegVar ctxt R.YMM11 4 := n0)
    builder <! (getPseudoRegVar ctxt R.YMM12 3 := n0)
    builder <! (getPseudoRegVar ctxt R.YMM12 4 := n0)
    builder <! (getPseudoRegVar ctxt R.YMM13 3 := n0)
    builder <! (getPseudoRegVar ctxt R.YMM13 4 := n0)
    builder <! (getPseudoRegVar ctxt R.YMM14 3 := n0)
    builder <! (getPseudoRegVar ctxt R.YMM14 4 := n0)
    builder <! (getPseudoRegVar ctxt R.YMM15 3 := n0)
    builder <! (getPseudoRegVar ctxt R.YMM15 4 := n0)
  endMark insAddr insLen builder

let wait _ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  startMark insAddr insLen builder
  allCFlagsUndefined ctxt builder
  endMark insAddr insLen builder

let wrfsbase ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let src = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  startMark insAddr insLen builder
  builder <! (getRegVar ctxt R.FSBase := zExt ctxt.WordBitSize src)
  endMark insAddr insLen builder

let wrgsbase ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let src = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  startMark insAddr insLen builder
  builder <! (getRegVar ctxt R.GSBase := zExt ctxt.WordBitSize src)
  endMark insAddr insLen builder

let wrpkru ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let errExp = unDef 1<rt> "#GP(0) error"
  let lblSucc = lblSymbol "Succ"
  let oprSize = getOperationSize ins
  let ecxIsZero = getRegVar ctxt R.ECX == num0 oprSize
  let edxIsZero = getRegVar ctxt R.EDX == num0 oprSize
  let cond = ecxIsZero .& edxIsZero
  startMark insAddr insLen builder
  builder <! (CJmp (cond, Name lblSucc, errExp))
  builder <! (LMark lblSucc)
  builder <! (getRegVar ctxt R.PKRU := getRegVar ctxt R.EAX)
  endMark insAddr insLen builder

let xadd ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let t = tmpVar oprSize
  startMark insAddr insLen builder
  builder <! (t := src .+ dst)
  builder <! (dstAssign oprSize src dst)
  builder <! (dstAssign oprSize dst t)
  enumEFLAGS ctxt dst src t oprSize getCFlagOnAdd getOFlagOnAdd builder
  endMark insAddr insLen builder

let xchg ins insAddr insLen ctxt =
  let builder = new StmtBuilder (8)
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  startMark insAddr insLen builder
  if dst <> src then
    let oprSize = getOperationSize ins
    let t = tmpVar oprSize
    builder <! (t := dst)
    builder <! (dstAssign oprSize dst src)
    builder <! (dstAssign oprSize src t)
  endMark insAddr insLen builder

let xlatb ins insAddr insLen ctxt =
  let builder = new StmtBuilder (4)
  let addressSize = getEffAddrSz ins
  let al = zExt addressSize (getRegVar ctxt R.AL)
  let bx = getRegOfSize ctxt addressSize GrpEBX
  startMark insAddr insLen builder
  builder <! (getRegVar ctxt R.AL := loadLE 8<rt> (al .+ bx))
  endMark insAddr insLen builder

let xor ins insAddr insLen ctxt =
  let builder = new StmtBuilder (16)
  let dst, src = getTwoOprs ins |> transTwoOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let r = tmpVar oprSize
  startMark insAddr insLen builder
  builder <! (r := dst <+> sExt oprSize src)
  builder <! (dstAssign oprSize dst r)
  builder <! (getRegVar ctxt R.OF := b0)
  builder <! (getRegVar ctxt R.CF := b0)
  builder <! (getRegVar ctxt R.SF := extractHigh 1<rt> r)
  builder <! (getRegVar ctxt R.ZF := r == (num0 oprSize))
  buildPF ctxt r oprSize None builder
  builder <! (getRegVar ctxt R.AF := undefAF)
  endMark insAddr insLen builder

let opPxor _ = Array.map2 (.|)

let xorpd ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opPxor 16

let xorps ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> opPxor 16

/// Translate IR.
let translate (ins: InsInfo) insAddr insLen ctxt =
  match ins.Opcode with
  | Opcode.AAA -> aaa ins insAddr insLen ctxt
  | Opcode.AAD -> aad ins insAddr insLen ctxt
  | Opcode.AAM -> aam ins insAddr insLen ctxt
  | Opcode.AAS -> aas ins insAddr insLen ctxt
  | Opcode.ADC -> adc ins insAddr insLen ctxt
  | Opcode.ADD -> add ins insAddr insLen ctxt
  | Opcode.ADDPD -> addpd ins insAddr insLen ctxt
  | Opcode.AND -> logAnd ins insAddr insLen ctxt
  | Opcode.ANDNPD -> andnpd ins insAddr insLen ctxt
  | Opcode.ANDPS -> andps ins insAddr insLen ctxt
  | Opcode.ARPL -> arpl ins insAddr insLen ctxt
  | Opcode.BNDMOV -> bndmov ins insAddr insLen ctxt
  | Opcode.BOUND -> nop insAddr insLen
  | Opcode.BSF -> bsf ins insAddr insLen ctxt
  | Opcode.BSR -> bsr ins insAddr insLen ctxt
  | Opcode.BSWAP -> bswap ins insAddr insLen ctxt
  | Opcode.BT -> bt ins insAddr insLen ctxt
  | Opcode.BTC -> btc ins insAddr insLen ctxt
  | Opcode.BTR -> btr ins insAddr insLen ctxt
  | Opcode.BTS -> bts ins insAddr insLen ctxt
  | Opcode.CALLNear -> call ins insAddr insLen ctxt false
  | Opcode.CALLFar -> call ins insAddr insLen ctxt true
  | Opcode.CBW | Opcode.CWDE | Opcode.CDQE -> convBWQ ins insAddr insLen ctxt
  | Opcode.CLC -> clearFlag insAddr insLen ctxt R.CF
  | Opcode.CLD -> clearFlag insAddr insLen ctxt R.DF
  | Opcode.CLFLUSH -> nop insAddr insLen
  | Opcode.CLI -> clearFlag insAddr insLen ctxt R.IF
  | Opcode.CLRSSBSY -> nop insAddr insLen
  | Opcode.CMC -> cmc ins insAddr insLen ctxt
  | Opcode.CMOVO | Opcode.CMOVNO | Opcode.CMOVB | Opcode.CMOVAE
  | Opcode.CMOVZ | Opcode.CMOVNZ | Opcode.CMOVBE | Opcode.CMOVA
  | Opcode.CMOVS  | Opcode.CMOVNS | Opcode.CMOVP | Opcode.CMOVNP
  | Opcode.CMOVL | Opcode.CMOVGE | Opcode.CMOVLE | Opcode.CMOVG ->
    cmovcc ins insAddr insLen ctxt
  | Opcode.CMP -> cmp ins insAddr insLen ctxt
  | Opcode.CMPSB | Opcode.CMPSW | Opcode.CMPSQ -> cmps ins insAddr insLen ctxt
  | Opcode.CMPXCHG -> cmpxchg ins insAddr insLen ctxt
  | Opcode.CMPXCHG8B | Opcode.CMPXCHG16B ->
    compareExchangeBytes ins insAddr insLen ctxt
  | Opcode.CPUID -> sideEffects insAddr insLen ProcessorID
  | Opcode.CRC32 -> nop insAddr insLen
  | Opcode.CWD | Opcode.CDQ | Opcode.CQO -> convWDQ ins insAddr insLen ctxt
  | Opcode.DAA -> daa ins insAddr insLen ctxt
  | Opcode.DAS -> das ins insAddr insLen ctxt
  | Opcode.DEC -> dec ins insAddr insLen ctxt
  | Opcode.DIV | Opcode.IDIV -> div ins insAddr insLen ctxt
  | Opcode.ENDBR32 | Opcode.ENDBR64 -> nop insAddr insLen
  | Opcode.ENTER -> enter ins insAddr insLen ctxt
  | Opcode.FXRSTOR | Opcode.FXRSTOR64 -> fxrstor ins insAddr insLen ctxt
  | Opcode.FXSAVE | Opcode.FXSAVE64 -> fxsave ins insAddr insLen ctxt
  | Opcode.HLT -> sideEffects insAddr insLen Halt
  | Opcode.IMUL -> imul ins insAddr insLen ctxt
  | Opcode.INC -> inc ins insAddr insLen ctxt
  | Opcode.INCSSPD | Opcode.INCSSPQ -> nop insAddr insLen
  | Opcode.INSB | Opcode.INSW | Opcode.INSD -> insinstr ins insAddr insLen ctxt
  | Opcode.INT -> interrupt ins insAddr insLen ctxt
  | Opcode.INT3 -> sideEffects insAddr insLen Breakpoint
  | Opcode.JMPFar | Opcode.JMPNear -> jmp ins insAddr insLen ctxt
  | Opcode.JO | Opcode.JNO | Opcode.JB | Opcode.JNB
  | Opcode.JZ | Opcode.JNZ | Opcode.JBE | Opcode.JA
  | Opcode.JS | Opcode.JNS | Opcode.JP | Opcode.JNP
  | Opcode.JL | Opcode.JNL | Opcode.JLE | Opcode.JG
  | Opcode.JECXZ | Opcode.JRCXZ -> jcc ins insAddr insLen ctxt
  | Opcode.LAHF -> sideEffects insAddr insLen ProcessorID
  | Opcode.LDDQU -> lddqu ins insAddr insLen ctxt
  | Opcode.LDMXCSR -> ldmxcsr ins insAddr insLen ctxt
  | Opcode.LEA -> lea ins insAddr insLen ctxt
  | Opcode.LEAVE -> leave ins insAddr insLen ctxt
  | Opcode.LFENCE -> sideEffects insAddr insLen Fence
  | Opcode.LODSB | Opcode.LODSW | Opcode.LODSD | Opcode.LODSQ ->
    lods ins insAddr insLen ctxt
  | Opcode.LOOP | Opcode.LOOPE | Opcode.LOOPNE -> loop ins insAddr insLen ctxt
  | Opcode.LZCNT -> lzcnt ins insAddr insLen ctxt
  | Opcode.LDS | Opcode.LES | Opcode.LFS | Opcode.LGS | Opcode.LSS ->
    sideEffects insAddr insLen UnsupportedFAR
  | Opcode.MFENCE -> sideEffects insAddr insLen Fence
  | Opcode.MOV -> mov ins insAddr insLen ctxt
  | Opcode.MOVAPD -> movapd ins insAddr insLen ctxt
  | Opcode.MOVAPS -> movaps ins insAddr insLen ctxt
  | Opcode.MOVBE -> movbe ins insAddr insLen ctxt
  | Opcode.MOVD -> movd ins insAddr insLen ctxt
  | Opcode.MOVDQ2Q -> movdq2q ins insAddr insLen ctxt
  | Opcode.MOVDQA -> movdqa ins insAddr insLen ctxt
  | Opcode.MOVDQU -> movdqu ins insAddr insLen ctxt
  | Opcode.MOVHPD -> movhpd ins insAddr insLen ctxt
  | Opcode.MOVLPD -> movlpd ins insAddr insLen ctxt
  | Opcode.MOVMSKPD -> movmskpd ins insAddr insLen ctxt
  | Opcode.MOVMSKPS -> movmskps ins insAddr insLen ctxt
  | Opcode.MOVNTDQ -> movntdq ins insAddr insLen ctxt
  | Opcode.MOVNTI -> movnti ins insAddr insLen ctxt
  | Opcode.MOVQ -> movq ins insAddr insLen ctxt
  | Opcode.MOVQ2DQ -> movq2dq ins insAddr insLen ctxt
  | Opcode.MOVSB | Opcode.MOVSW | Opcode.MOVSQ -> movs ins insAddr insLen ctxt
  | Opcode.MOVSD -> movsd ins insAddr insLen ctxt
  | Opcode.MOVSX | Opcode.MOVSXD -> movsx ins insAddr insLen ctxt
  | Opcode.MOVUPS -> movups ins insAddr insLen ctxt
  | Opcode.MOVZX -> movzx ins insAddr insLen ctxt
  | Opcode.MUL -> mul ins insAddr insLen ctxt
  | Opcode.NEG -> neg ins insAddr insLen ctxt
  | Opcode.NOP -> nop insAddr insLen
  | Opcode.NOT -> not ins insAddr insLen ctxt
  | Opcode.OR -> logOr ins insAddr insLen ctxt
  | Opcode.OUTSB | Opcode.OUTSW | Opcode.OUTSD -> outs ins insAddr insLen ctxt
  | Opcode.PACKSSDW -> packssdw ins insAddr insLen ctxt
  | Opcode.PACKSSWB -> packsswb ins insAddr insLen ctxt
  | Opcode.PACKUSWB -> packuswb ins insAddr insLen ctxt
  | Opcode.PADDB -> paddb ins insAddr insLen ctxt
  | Opcode.PADDD -> paddd ins insAddr insLen ctxt
  | Opcode.PADDQ -> paddq ins insAddr insLen ctxt
  | Opcode.PADDSB -> paddsb ins insAddr insLen ctxt
  | Opcode.PADDSW -> paddsw ins insAddr insLen ctxt
  | Opcode.PADDUSB -> paddusb ins insAddr insLen ctxt
  | Opcode.PADDUSW -> paddusw ins insAddr insLen ctxt
  | Opcode.PADDW -> paddw ins insAddr insLen ctxt
  | Opcode.PALIGNR -> palignr ins insAddr insLen ctxt
  | Opcode.PAND -> pand ins insAddr insLen ctxt
  | Opcode.PANDN -> pandn ins insAddr insLen ctxt
  | Opcode.PAUSE -> sideEffects insAddr insLen Pause
  | Opcode.PAVGB -> pavgb ins insAddr insLen ctxt
  | Opcode.PAVGW -> pavgw ins insAddr insLen ctxt
  | Opcode.PCMPEQB -> pcmpeqb ins insAddr insLen ctxt
  | Opcode.PCMPEQD -> pcmpeqd ins insAddr insLen ctxt
  | Opcode.PCMPEQQ -> pcmpeqq ins insAddr insLen ctxt
  | Opcode.PCMPEQW -> pcmpeqw ins insAddr insLen ctxt
  | Opcode.PCMPGTB -> pcmpgtb ins insAddr insLen ctxt
  | Opcode.PCMPGTD -> pcmpgtd ins insAddr insLen ctxt
  | Opcode.PCMPGTW -> pcmpgtw ins insAddr insLen ctxt
  | Opcode.PCMPESTRI | Opcode.PCMPESTRM | Opcode.PCMPISTRI | Opcode.PCMPISTRM ->
    pcmpstr ins insAddr insLen ctxt
  | Opcode.PEXTRW -> pextrw ins insAddr insLen ctxt
  | Opcode.PINSRB -> pinsrb ins insAddr insLen ctxt
  | Opcode.PINSRW -> pinsrw ins insAddr insLen ctxt
  | Opcode.PMADDWD -> pmaddwd ins insAddr insLen ctxt
  | Opcode.PMAXSB -> pmaxsb ins insAddr insLen ctxt
  | Opcode.PMAXSW -> pmaxsw ins insAddr insLen ctxt
  | Opcode.PMAXUB -> pmaxub ins insAddr insLen ctxt
  | Opcode.PMINSB -> pminsb ins insAddr insLen ctxt
  | Opcode.PMINSW -> pminsw ins insAddr insLen ctxt
  | Opcode.PMINUB -> pminub ins insAddr insLen ctxt
  | Opcode.PMINUD -> pminud ins insAddr insLen ctxt
  | Opcode.PMOVMSKB -> pmovmskb ins insAddr insLen ctxt
  | Opcode.PMULHW -> pmulhw ins insAddr insLen ctxt
  | Opcode.PMULHUW -> pmulhuw ins insAddr insLen ctxt
  | Opcode.PMULLW -> pmullw ins insAddr insLen ctxt
  | Opcode.PMULUDQ -> pmuludq ins insAddr insLen ctxt
  | Opcode.POP -> pop ins insAddr insLen ctxt
  | Opcode.POPA -> popa ins insAddr insLen ctxt 16<rt>
  | Opcode.POPAD -> popa ins insAddr insLen ctxt 32<rt>
  | Opcode.POPCNT -> popcnt ins insAddr insLen ctxt
  | Opcode.POPF | Opcode.POPFD | Opcode.POPFQ -> popf ins insAddr insLen ctxt
  | Opcode.POR -> por ins insAddr insLen ctxt
  | Opcode.PREFETCHNTA
  | Opcode.PREFETCHT0 | Opcode.PREFETCHT1
  | Opcode.PREFETCHW | Opcode.PREFETCHT2 -> nop insAddr insLen
  | Opcode.PSADBW -> psadbw ins insAddr insLen ctxt
  | Opcode.PSHUFB -> pshufb ins insAddr insLen ctxt
  | Opcode.PSHUFD -> pshufd ins insAddr insLen ctxt
  | Opcode.PSHUFHW -> pshufhw ins insAddr insLen ctxt
  | Opcode.PSHUFLW -> pshuflw ins insAddr insLen ctxt
  | Opcode.PSHUFW -> pshufw ins insAddr insLen ctxt
  | Opcode.PSLLD -> pslld ins insAddr insLen ctxt
  | Opcode.PSLLDQ -> pslldq ins insAddr insLen ctxt
  | Opcode.PSLLQ -> psllq ins insAddr insLen ctxt
  | Opcode.PSLLW -> psllw ins insAddr insLen ctxt
  | Opcode.PSRAD -> psrad ins insAddr insLen ctxt
  | Opcode.PSRAW -> psraw ins insAddr insLen ctxt
  | Opcode.PSRLD -> psrld ins insAddr insLen ctxt
  | Opcode.PSRLDQ -> psrldq ins insAddr insLen ctxt
  | Opcode.PSRLQ -> psrlq ins insAddr insLen ctxt
  | Opcode.PSRLW -> psrlw ins insAddr insLen ctxt
  | Opcode.PSUBB -> psubb ins insAddr insLen ctxt
  | Opcode.PSUBD -> psubd ins insAddr insLen ctxt
  | Opcode.PSUBQ -> psubq ins insAddr insLen ctxt
  | Opcode.PSUBSB -> psubsb ins insAddr insLen ctxt
  | Opcode.PSUBSW -> psubsw ins insAddr insLen ctxt
  | Opcode.PSUBUSB -> psubusb ins insAddr insLen ctxt
  | Opcode.PSUBUSW -> psubusw ins insAddr insLen ctxt
  | Opcode.PSUBW -> psubw ins insAddr insLen ctxt
  | Opcode.PTEST -> ptest ins insAddr insLen ctxt
  | Opcode.PUNPCKHBW -> punpckhbw ins insAddr insLen ctxt
  | Opcode.PUNPCKHDQ -> punpckhdq ins insAddr insLen ctxt
  | Opcode.PUNPCKHQDQ -> punpckhqdq ins insAddr insLen ctxt
  | Opcode.PUNPCKHWD -> punpckhwd ins insAddr insLen ctxt
  | Opcode.PUNPCKLBW -> punpcklbw ins insAddr insLen ctxt
  | Opcode.PUNPCKLDQ -> punpckldq ins insAddr insLen ctxt
  | Opcode.PUNPCKLQDQ -> punpcklqdq ins insAddr insLen ctxt
  | Opcode.PUNPCKLWD -> punpcklwd ins insAddr insLen ctxt
  | Opcode.PUSH -> push ins insAddr insLen ctxt
  | Opcode.PUSHA -> pusha ins insAddr insLen ctxt 16<rt>
  | Opcode.PUSHAD -> pusha ins insAddr insLen ctxt 32<rt>
  | Opcode.PUSHF | Opcode.PUSHFD | Opcode.PUSHFQ -> pushf ins insAddr insLen ctxt
  | Opcode.PXOR -> pxor ins insAddr insLen ctxt
  | Opcode.RCL -> rcl ins insAddr insLen ctxt
  | Opcode.RCR -> rcr ins insAddr insLen ctxt
  | Opcode.RDMSR | Opcode.RSM -> sideEffects insAddr insLen UnsupportedExtension
  | Opcode.RDPKRU -> rdpkru ins insAddr insLen ctxt
  | Opcode.RDPMC -> sideEffects insAddr insLen UnsupportedExtension
  | Opcode.RDRAND -> sideEffects insAddr insLen UnsupportedExtension
  | Opcode.RDSSPD | Opcode.RDSSPQ -> nop insAddr insLen
  | Opcode.RDTSC -> sideEffects insAddr insLen ClockCounter
  | Opcode.RDTSCP -> sideEffects insAddr insLen ClockCounter
  | Opcode.RETNear -> ret ins insAddr insLen ctxt false false
  | Opcode.RETNearImm -> ret ins insAddr insLen ctxt false true
  | Opcode.RETFar -> ret ins insAddr insLen ctxt true false
  | Opcode.RETFarImm -> ret ins insAddr insLen ctxt true true
  | Opcode.ROL -> rol ins insAddr insLen ctxt
  | Opcode.ROR -> ror ins insAddr insLen ctxt
  | Opcode.RORX -> rorx ins insAddr insLen ctxt
  | Opcode.RSTORSSP -> nop insAddr insLen
  | Opcode.SAHF -> sahf ins insAddr insLen ctxt
  | Opcode.SAR | Opcode.SHR | Opcode.SHL -> shift ins insAddr insLen ctxt
  | Opcode.SAVEPREVSSP -> nop insAddr insLen
  | Opcode.SBB -> sbb ins insAddr insLen ctxt
  | Opcode.SCASB | Opcode.SCASW | Opcode.SCASD | Opcode.SCASQ ->
    scas ins insAddr insLen ctxt
  | Opcode.SETO | Opcode.SETNO | Opcode.SETB | Opcode.SETNB
  | Opcode.SETZ | Opcode.SETNZ | Opcode.SETBE | Opcode.SETA
  | Opcode.SETS | Opcode.SETNS | Opcode.SETP | Opcode.SETNP
  | Opcode.SETL | Opcode.SETNL | Opcode.SETLE | Opcode.SETG ->
    setcc ins insAddr insLen ctxt
  | Opcode.SETSSBSY -> nop insAddr insLen
  | Opcode.SFENCE -> sideEffects insAddr insLen Fence
  | Opcode.SHLD -> shld ins insAddr insLen ctxt
  | Opcode.SHLX -> shlx ins insAddr insLen ctxt
  | Opcode.SHRD -> shrd ins insAddr insLen ctxt
  | Opcode.STC -> stc insAddr insLen ctxt
  | Opcode.STD -> std insAddr insLen ctxt
  | Opcode.STI -> sti insAddr insLen ctxt
  | Opcode.STMXCSR -> stmxcsr ins insAddr insLen ctxt
  | Opcode.STOSB | Opcode.STOSW | Opcode.STOSD | Opcode.STOSQ ->
    stos ins insAddr insLen ctxt
  | Opcode.SUB -> sub ins insAddr insLen ctxt
  | Opcode.SUBPD -> subpd ins insAddr insLen ctxt
  | Opcode.SYSCALL | Opcode.SYSENTER -> sideEffects insAddr insLen SysCall
  | Opcode.TEST -> test ins insAddr insLen ctxt
  | Opcode.TZCNT -> tzcnt ins insAddr insLen ctxt
  | Opcode.UD2 -> sideEffects insAddr insLen UndefinedInstr
  | Opcode.VBROADCASTI128 -> vbroadcasti128 ins insAddr insLen ctxt
  | Opcode.VEXTRACTF32X8 -> vextracti32x8 ins insAddr insLen ctxt
  | Opcode.VEXTRACTI64X4 -> vextracti64x4 ins insAddr insLen ctxt
  | Opcode.VINSERTI128 -> vinserti128 ins insAddr insLen ctxt
  | Opcode.VMOVD -> vmovd ins insAddr insLen ctxt
  | Opcode.VMOVDQA -> vmovdqa ins insAddr insLen ctxt
  | Opcode.VMOVDQA64 -> vmovdqa64 ins insAddr insLen ctxt
  | Opcode.VMOVDQU -> vmovdqu ins insAddr insLen ctxt
  | Opcode.VMOVDQU16 -> vmovdqu16 ins insAddr insLen ctxt
  | Opcode.VMOVDQU64 -> vmovdqu64 ins insAddr insLen ctxt
  | Opcode.VMOVNTDQ -> vmovntdq ins insAddr insLen ctxt
  | Opcode.VMOVQ -> vmovq ins insAddr insLen ctxt
  | Opcode.VMOVUPS -> vmovups ins insAddr insLen ctxt
  | Opcode.VMPTRLD -> sideEffects insAddr insLen UnsupportedExtension
  | Opcode.VPADDB -> vpaddb ins insAddr insLen ctxt
  | Opcode.VPADDD -> vpaddd ins insAddr insLen ctxt
  | Opcode.VPADDQ -> vpaddq ins insAddr insLen ctxt
  | Opcode.VPALIGNR -> vpalignr ins insAddr insLen ctxt
  | Opcode.VPAND -> vpand ins insAddr insLen ctxt
  | Opcode.VPANDN -> vpandn ins insAddr insLen ctxt
  | Opcode.VPBROADCASTB -> vpbroadcastb ins insAddr insLen ctxt
  | Opcode.VPBROADCASTD -> vpbroadcastd ins insAddr insLen ctxt
  | Opcode.VPCMPEQB -> vpcmpeqb ins insAddr insLen ctxt
  | Opcode.VPCMPEQD -> vpcmpeqd ins insAddr insLen ctxt
  | Opcode.VPCMPEQQ -> vpcmpeqq ins insAddr insLen ctxt
  | Opcode.VPCMPESTRI | Opcode.VPCMPESTRM | Opcode.VPCMPISTRI
  | Opcode.VPCMPISTRM -> pcmpstr ins insAddr insLen ctxt
  | Opcode.VPCMPGTB -> vpcmpgtb ins insAddr insLen ctxt
  | Opcode.VPINSRD -> vpinsrd ins insAddr insLen ctxt
  | Opcode.VPMINUB -> vpminub ins insAddr insLen ctxt
  | Opcode.VPMINUD -> vpminud ins insAddr insLen ctxt
  | Opcode.VPMOVMSKB -> pmovmskb ins insAddr insLen ctxt
  | Opcode.VPMULUDQ -> vpmuludq ins insAddr insLen ctxt
  | Opcode.VPOR -> vpor ins insAddr insLen ctxt
  | Opcode.VPSHUFB -> vpshufb ins insAddr insLen ctxt
  | Opcode.VPSHUFD -> vpshufd ins insAddr insLen ctxt
  | Opcode.VPSLLD -> vpslld ins insAddr insLen ctxt
  | Opcode.VPSLLDQ -> vpslldq ins insAddr insLen ctxt
  | Opcode.VPSLLQ -> vpsllq ins insAddr insLen ctxt
  | Opcode.VPSRLD -> vpsrld ins insAddr insLen ctxt
  | Opcode.VPSRLDQ -> vpsrldq ins insAddr insLen ctxt
  | Opcode.VPSRLQ -> vpsrlq ins insAddr insLen ctxt
  | Opcode.VPSUBB -> vpsubb ins insAddr insLen ctxt
  | Opcode.VPTEST -> vptest ins insAddr insLen ctxt
  | Opcode.VPUNPCKHDQ -> vpunpckhdq ins insAddr insLen ctxt
  | Opcode.VPUNPCKHQDQ -> vpunpckhqdq ins insAddr insLen ctxt
  | Opcode.VPUNPCKLDQ -> vpunpckldq ins insAddr insLen ctxt
  | Opcode.VPUNPCKLQDQ -> vpunpcklqdq ins insAddr insLen ctxt
  | Opcode.VPXOR -> vpxor ins insAddr insLen ctxt
  | Opcode.VSHUFI32X4 -> vshufi32x4 ins insAddr insLen ctxt
  | Opcode.VZEROUPPER -> vzeroupper ins insAddr insLen ctxt
  | Opcode.WRFSBASE -> wrfsbase ins insAddr insLen ctxt
  | Opcode.WRGSBASE -> wrgsbase ins insAddr insLen ctxt
  | Opcode.WRPKRU -> wrpkru ins insAddr insLen ctxt
  | Opcode.WRSSD | Opcode.WRSSQ -> nop insAddr insLen
  | Opcode.WRUSSD | Opcode.WRUSSQ -> nop insAddr insLen
  | Opcode.XABORT -> sideEffects insAddr insLen UnsupportedExtension
  | Opcode.XADD -> xadd ins insAddr insLen ctxt
  | Opcode.XBEGIN -> sideEffects insAddr insLen UnsupportedExtension
  | Opcode.XCHG -> xchg ins insAddr insLen ctxt
  | Opcode.XEND -> sideEffects insAddr insLen UnsupportedExtension
  | Opcode.XGETBV -> sideEffects insAddr insLen UnsupportedExtension
  | Opcode.XLATB -> xlatb ins insAddr insLen ctxt
  | Opcode.XOR -> xor ins insAddr insLen ctxt
  | Opcode.XRSTOR | Opcode.XRSTORS | Opcode.XSAVE | Opcode.XSAVEC
  | Opcode.XSAVEC64 | Opcode.XSAVEOPT | Opcode.XSAVES | Opcode.XSAVES64 ->
    sideEffects insAddr insLen UnsupportedExtension
  | Opcode.XTEST -> sideEffects insAddr insLen UnsupportedExtension
  | Opcode.IN | Opcode.INTO | Opcode.INVD | Opcode.INVLPG | Opcode.IRETD
  | Opcode.IRETQ | Opcode.IRETW | Opcode.LAR | Opcode.LGDT | Opcode.LLDT
  | Opcode.LMSW | Opcode.LSL | Opcode.LTR | Opcode.OUT | Opcode.SGDT
  | Opcode.SIDT | Opcode.SLDT | Opcode.SMSW | Opcode.STR | Opcode.VERR
  | Opcode.VERW -> sideEffects insAddr insLen UnsupportedPrivInstr
  | Opcode.ADDPS -> addps ins insAddr insLen ctxt
  | Opcode.ADDSD -> addsd ins insAddr insLen ctxt
  | Opcode.ADDSS -> addss ins insAddr insLen ctxt
  | Opcode.ANDNPS -> andnps ins insAddr insLen ctxt
  | Opcode.ANDPD -> andpd ins insAddr insLen ctxt
  | Opcode.CMPPD -> cmppd ins insAddr insLen ctxt
  | Opcode.CMPPS -> cmpps ins insAddr insLen ctxt
  | Opcode.COMISD | Opcode.VCOMISD -> comisd ins insAddr insLen ctxt
  | Opcode.COMISS | Opcode.VCOMISS -> comiss ins insAddr insLen ctxt
  | Opcode.CMPSD -> cmpsd ins insAddr insLen ctxt
  | Opcode.CMPSS -> cmpss ins insAddr insLen ctxt
  | Opcode.CVTDQ2PD -> cvtdq2pd ins insAddr insLen ctxt
  | Opcode.CVTDQ2PS -> cvtdq2ps ins insAddr insLen ctxt
  | Opcode.CVTPD2DQ -> cvtpd2dq ins insAddr insLen ctxt true
  | Opcode.CVTPD2PI -> cvtpd2pi ins insAddr insLen ctxt true
  | Opcode.CVTPD2PS -> cvtpd2ps ins insAddr insLen ctxt
  | Opcode.CVTPI2PD -> cvtpi2pd ins insAddr insLen ctxt
  | Opcode.CVTPI2PS -> cvtpi2ps ins insAddr insLen ctxt
  | Opcode.CVTPS2DQ -> cvtps2dq ins insAddr insLen ctxt true
  | Opcode.CVTPS2PD -> cvtps2pd ins insAddr insLen ctxt
  | Opcode.CVTPS2PI -> cvtps2pi ins insAddr insLen ctxt true
  | Opcode.CVTSD2SI | Opcode.VCVTSD2SI -> cvtsd2si ins insAddr insLen ctxt true
  | Opcode.CVTSD2SS -> cvtsd2ss ins insAddr insLen ctxt
  | Opcode.CVTSI2SD -> cvtsi2sd ins insAddr insLen ctxt
  | Opcode.CVTSI2SS -> cvtsi2ss ins insAddr insLen ctxt
  | Opcode.CVTSS2SD -> cvtss2sd ins insAddr insLen ctxt
  | Opcode.CVTSS2SI | Opcode.VCVTSS2SI -> cvtss2si ins insAddr insLen ctxt true
  | Opcode.CVTTPD2DQ -> cvtpd2dq ins insAddr insLen ctxt false
  | Opcode.CVTTPD2PI -> cvtpd2pi ins insAddr insLen ctxt false
  | Opcode.CVTTPS2DQ -> cvtps2dq ins insAddr insLen ctxt false
  | Opcode.CVTTPS2PI -> cvtps2pi ins insAddr insLen ctxt false
  | Opcode.CVTTSD2SI | Opcode.VCVTTSD2SI ->
    cvtsd2si ins insAddr insLen ctxt false
  | Opcode.CVTTSS2SI | Opcode.VCVTTSS2SI ->
    cvtss2si ins insAddr insLen ctxt false
  | Opcode.DIVPD -> divpd ins insAddr insLen ctxt
  | Opcode.DIVPS -> divps ins insAddr insLen ctxt
  | Opcode.DIVSD -> divsd ins insAddr insLen ctxt
  | Opcode.DIVSS -> divss ins insAddr insLen ctxt
  | Opcode.EMMS -> emms ins insAddr insLen ctxt
  | Opcode.F2XM1 -> f2xm1 ins insAddr insLen ctxt
  | Opcode.FABS -> fabs ins insAddr insLen ctxt
  | Opcode.FADD -> fpuadd ins insAddr insLen ctxt false
  | Opcode.FADDP -> fpuadd ins insAddr insLen ctxt true
  | Opcode.FBLD -> fbld ins insAddr insLen ctxt
  | Opcode.FBSTP -> fbstp ins insAddr insLen ctxt
  | Opcode.FCHS -> fchs ins insAddr insLen ctxt
  | Opcode.FCLEX -> fclex ins insAddr insLen ctxt
  | Opcode.FCMOVB -> fcmovb ins insAddr insLen ctxt
  | Opcode.FCMOVBE -> fcmovbe ins insAddr insLen ctxt
  | Opcode.FCMOVE -> fcmove ins insAddr insLen ctxt
  | Opcode.FCMOVNB -> fcmovnb ins insAddr insLen ctxt
  | Opcode.FCMOVNBE -> fcmovnbe ins insAddr insLen ctxt
  | Opcode.FCMOVNE -> fcmovne ins insAddr insLen ctxt
  | Opcode.FCMOVNU -> fcmovnu ins insAddr insLen ctxt
  | Opcode.FCMOVU -> fcmovu ins insAddr insLen ctxt
  | Opcode.FDIV -> fpudiv ins insAddr insLen ctxt false
  | Opcode.FDIVP -> fpudiv ins insAddr insLen ctxt true
  | Opcode.FIADD -> fiadd ins insAddr insLen ctxt
  | Opcode.FIDIV -> fidiv ins insAddr insLen ctxt
  | Opcode.FIMUL -> fimul ins insAddr insLen ctxt
  | Opcode.FISUB -> fisub ins insAddr insLen ctxt
  | Opcode.FLD -> fld ins insAddr insLen ctxt
  | Opcode.FLD1 -> fld1 ins insAddr insLen ctxt
  | Opcode.FLDENV -> fldenv ins insAddr insLen ctxt
  | Opcode.FLDL2E -> fldl2e ins insAddr insLen ctxt
  | Opcode.FLDL2T -> fldl2t ins insAddr insLen ctxt
  | Opcode.FLDPI -> fldpi ins insAddr insLen ctxt
  | Opcode.FLDZ -> fldz ins insAddr insLen ctxt
  | Opcode.FLDLG2 -> fldlg2 ins insAddr insLen ctxt
  | Opcode.FLDLN2 -> fldln2 ins insAddr insLen ctxt
  | Opcode.FLDCW -> fldcw ins insAddr insLen ctxt
  | Opcode.FMUL -> fpumul ins insAddr insLen ctxt false
  | Opcode.FMULP -> fpumul ins insAddr insLen ctxt true
  | Opcode.FPREM -> fprem ins insAddr insLen ctxt false
  | Opcode.FPREM1 -> fprem ins insAddr insLen ctxt true
  | Opcode.FSQRT -> fsqrt ins insAddr insLen ctxt
  | Opcode.FSUB -> fpusub ins insAddr insLen ctxt false
  | Opcode.FSUBP -> fpusub ins insAddr insLen ctxt true
  | Opcode.FCOM -> fcom ins insAddr insLen ctxt 0 false
  | Opcode.FCOMP -> fcom ins insAddr insLen ctxt 1 false
  | Opcode.FCOMPP -> fcom ins insAddr insLen ctxt 2 false
  | Opcode.FCOMI -> fcomi ins insAddr insLen ctxt false
  | Opcode.FCOMIP -> fcomi ins insAddr insLen ctxt true
  | Opcode.FUCOMI -> fcomi ins insAddr insLen ctxt false
  | Opcode.FUCOMIP -> fcomi ins insAddr insLen ctxt true
  | Opcode.FCOS -> fcos ins insAddr insLen ctxt
  | Opcode.FSIN -> fsin ins insAddr insLen ctxt
  | Opcode.FDECSTP -> fdecstp ins insAddr insLen ctxt
  | Opcode.FDIVR -> fdivr ins insAddr insLen ctxt false
  | Opcode.FDIVRP -> fdivr  ins insAddr insLen ctxt true
  | Opcode.FSUBR -> fsubr ins insAddr insLen ctxt false
  | Opcode.FSUBRP -> fsubr ins insAddr insLen ctxt true
  | Opcode.FIDIVR -> fidivr ins insAddr insLen ctxt
  | Opcode.FISUBR  -> fisubr ins insAddr insLen ctxt
  | Opcode.FFREE -> ffree ins insAddr insLen ctxt
  | Opcode.FICOM -> ficom ins insAddr insLen ctxt false
  | Opcode.FICOMP -> ficom ins insAddr insLen ctxt true
  | Opcode.FILD -> fild ins insAddr insLen ctxt
  | Opcode.FINCSTP -> fincstp ins insAddr insLen ctxt
  | Opcode.FINIT -> finit ins insAddr insLen ctxt
  | Opcode.FIST -> fist ins insAddr insLen ctxt false
  | Opcode.FISTP -> fist ins insAddr insLen ctxt true
  | Opcode.FISTTP -> fisttp ins insAddr insLen ctxt
  | Opcode.FNOP -> fnop ins insAddr insLen ctxt
  | Opcode.FNSTCW -> fnstcw ins insAddr insLen ctxt
  | Opcode.FNSTSW -> fnstsw ins insAddr insLen ctxt
  | Opcode.FPATAN -> fpatan ins insAddr insLen ctxt
  | Opcode.FPTAN -> fptan ins insAddr insLen ctxt
  | Opcode.FRNDINT -> frndint ins insAddr insLen ctxt
  | Opcode.FRSTOR -> frstor ins insAddr insLen ctxt
  | Opcode.FSAVE -> fsave ins insAddr insLen ctxt
  | Opcode.FSCALE -> fscale ins insAddr insLen ctxt
  | Opcode.FSINCOS -> fsincos ins insAddr insLen ctxt
  | Opcode.FST -> ffst ins insAddr insLen ctxt false
  | Opcode.FSTP -> ffst ins insAddr insLen ctxt true
  | Opcode.FSTENV -> fstenv ins insAddr insLen ctxt
  | Opcode.FSTCW -> fstcw ins insAddr insLen ctxt
  | Opcode.FSTSW -> fstsw ins insAddr insLen ctxt
  | Opcode.FTST -> ftst ins insAddr insLen ctxt
  | Opcode.FUCOM -> fcom ins insAddr insLen ctxt 0 true
  | Opcode.FUCOMP -> fcom ins insAddr insLen ctxt 1 true
  | Opcode.FUCOMPP -> fcom ins insAddr insLen ctxt 2 true
  | Opcode.FXCH -> fxch ins insAddr insLen ctxt
  | Opcode.FXAM -> fxam ins insAddr insLen ctxt
  | Opcode.FXTRACT -> fxtract ins insAddr insLen ctxt
  | Opcode.FYL2X -> fyl2x ins insAddr insLen ctxt
  | Opcode.FYL2XP1 -> fyl2xp1 ins insAddr insLen ctxt
  | Opcode.MOVDDUP -> movddup ins insAddr insLen ctxt
  | Opcode.MOVHLPS -> movhlps ins insAddr insLen ctxt
  | Opcode.MOVHPS -> movhps ins insAddr insLen ctxt
  | Opcode.MOVLHPS -> movlhps ins insAddr insLen ctxt
  | Opcode.MOVLPS -> movlps ins insAddr insLen ctxt
  | Opcode.MOVNTPD -> movntpd ins insAddr insLen ctxt
  | Opcode.MOVNTPS -> movntps ins insAddr insLen ctxt
  | Opcode.MOVNTQ -> movntq ins insAddr insLen ctxt
  | Opcode.MOVSHDUP -> movshdup ins insAddr insLen ctxt
  | Opcode.MOVSLDUP -> movsldup ins insAddr insLen ctxt
  | Opcode.MOVSS -> movss ins insAddr insLen ctxt
  | Opcode.MOVUPD -> movupd ins insAddr insLen ctxt
  | Opcode.MULPD -> mulpd ins insAddr insLen ctxt
  | Opcode.MULPS -> mulps ins insAddr insLen ctxt
  | Opcode.MULSD -> mulsd ins insAddr insLen ctxt
  | Opcode.MULSS -> mulss ins insAddr insLen ctxt
  | Opcode.ORPD -> orpd ins insAddr insLen ctxt
  | Opcode.ORPS -> orps ins insAddr insLen ctxt
  | Opcode.SUBPS -> subps ins insAddr insLen ctxt
  | Opcode.SUBSD -> subsd ins insAddr insLen ctxt
  | Opcode.SUBSS -> subss ins insAddr insLen ctxt
  | Opcode.SQRTPD -> sqrtpd ins insAddr insLen ctxt
  | Opcode.SQRTPS -> sqrtps ins insAddr insLen ctxt
  | Opcode.SQRTSD -> sqrtsd ins insAddr insLen ctxt
  | Opcode.SQRTSS -> sqrtss ins insAddr insLen ctxt
  | Opcode.XORPD -> xorpd ins insAddr insLen ctxt
  | Opcode.XORPS -> xorps ins insAddr insLen ctxt
  | Opcode.MAXPD -> maxpd ins insAddr insLen ctxt
  | Opcode.MAXPS -> maxps ins insAddr insLen ctxt
  | Opcode.MAXSD -> maxsd ins insAddr insLen ctxt
  | Opcode.MAXSS -> maxss ins insAddr insLen ctxt
  | Opcode.MINPD -> minpd ins insAddr insLen ctxt
  | Opcode.MINPS -> minps ins insAddr insLen ctxt
  | Opcode.MINSD -> minsd ins insAddr insLen ctxt
  | Opcode.MINSS -> minss ins insAddr insLen ctxt
  | Opcode.RCPSS -> rcpss ins insAddr insLen ctxt
  | Opcode.RCPPS -> rcpps ins insAddr insLen ctxt
  | Opcode.ROUNDSD -> roundsd ins insAddr insLen ctxt
  | Opcode.RSQRTSS -> rsqrtss ins insAddr insLen ctxt
  | Opcode.RSQRTPS -> rsqrtps ins insAddr insLen ctxt
  | Opcode.SHUFPD -> shufpd ins insAddr insLen ctxt
  | Opcode.SHUFPS -> shufps ins insAddr insLen ctxt
  | Opcode.UCOMISD | Opcode.VUCOMISD -> ucomisd ins insAddr insLen ctxt
  | Opcode.UCOMISS | Opcode.VUCOMISS -> ucomiss ins insAddr insLen ctxt
  | Opcode.UNPCKHPD -> unpckhpd ins insAddr insLen ctxt
  | Opcode.UNPCKHPS -> unpckhps ins insAddr insLen ctxt
  | Opcode.UNPCKLPD -> unpcklpd ins insAddr insLen ctxt
  | Opcode.UNPCKLPS -> unpcklps ins insAddr insLen ctxt
  | Opcode.VADDPD -> vaddpd ins insAddr insLen ctxt
  | Opcode.VADDPS -> vaddps ins insAddr insLen ctxt
  | Opcode.VADDSD -> vaddsd ins insAddr insLen ctxt
  | Opcode.VADDSS -> vaddss ins insAddr insLen ctxt
  | Opcode.VANDNPD -> vandnpd ins insAddr insLen ctxt
  | Opcode.VANDNPS -> vandnps ins insAddr insLen ctxt
  | Opcode.VANDPD -> vandpd ins insAddr insLen ctxt
  | Opcode.VANDPS -> vandps ins insAddr insLen ctxt
  | Opcode.VBROADCASTSS -> vbroadcastss ins insAddr insLen ctxt
  | Opcode.VCVTSI2SD -> vcvtsi2sd ins insAddr insLen ctxt
  | Opcode.VCVTSI2SS -> vcvtsi2ss ins insAddr insLen ctxt
  | Opcode.VDIVSD -> vdivsd ins insAddr insLen ctxt
  | Opcode.VDIVSS -> vdivss ins insAddr insLen ctxt
  | Opcode.VDIVPD -> vdivpd ins insAddr insLen ctxt
  | Opcode.VDIVPS -> vdivps ins insAddr insLen ctxt
  | Opcode.VCVTSD2SS -> vcvtsd2ss ins insAddr insLen ctxt
  | Opcode.VCVTSS2SD -> vcvtss2sd ins insAddr insLen ctxt
  | Opcode.VFMADD132SD -> vfmadd132sd ins insAddr insLen ctxt
  | Opcode.VFMADD213SD -> vfmadd213sd ins insAddr insLen ctxt
  | Opcode.VFMADD231SD -> vfmadd231sd ins insAddr insLen ctxt
  | Opcode.VMOVAPS -> vmovdqu ins insAddr insLen ctxt
  | Opcode.VMOVAPD -> vmovdqu ins insAddr insLen ctxt
  | Opcode.VMOVDDUP -> vmovddup ins insAddr insLen ctxt
  | Opcode.VMOVHLPS -> vmovhlps ins insAddr insLen ctxt
  | Opcode.VMOVHPD | Opcode.VMOVHPS-> vmovhpd ins insAddr insLen ctxt
  | Opcode.VMOVLHPS -> vmovlhps ins insAddr insLen ctxt
  | Opcode.VMOVLPD | Opcode.VMOVLPS -> vmovlpd ins insAddr insLen ctxt
  | Opcode.VMOVMSKPD -> vmovmskpd ins insAddr insLen ctxt
  | Opcode.VMOVMSKPS -> vmovmskps ins insAddr insLen ctxt
  | Opcode.VMOVNTPD -> vmovntpd ins insAddr insLen ctxt
  | Opcode.VMOVNTPS -> vmovntps ins insAddr insLen ctxt
  | Opcode.VMOVSD -> vmovsd ins insAddr insLen ctxt
  | Opcode.VMOVSHDUP -> vmovshdup ins insAddr insLen ctxt
  | Opcode.VMOVSLDUP -> vmovsldup ins insAddr insLen ctxt
  | Opcode.VMOVSS -> vmovss ins insAddr insLen ctxt
  | Opcode.VMOVUPD -> vmovupd ins insAddr insLen ctxt
  | Opcode.VMULSD -> vmulsd ins insAddr insLen ctxt
  | Opcode.VMULSS -> vmulss ins insAddr insLen ctxt
  | Opcode.VMULPD -> vmulpd ins insAddr insLen ctxt
  | Opcode.VMULPS -> vmulps ins insAddr insLen ctxt
  | Opcode.VORPD -> vorpd ins insAddr insLen ctxt
  | Opcode.VORPS -> vorps ins insAddr insLen ctxt
  | Opcode.VSHUFPD -> vshufpd ins insAddr insLen ctxt
  | Opcode.VSHUFPS -> vshufps ins insAddr insLen ctxt
  | Opcode.VSQRTSD -> vsqrtsd ins insAddr insLen ctxt
  | Opcode.VSQRTSS -> vsqrtss ins insAddr insLen ctxt
  | Opcode.VSUBSD -> vsubsd ins insAddr insLen ctxt
  | Opcode.VSUBSS -> vsubss ins insAddr insLen ctxt
  | Opcode.VSUBPD -> vsubpd ins insAddr insLen ctxt
  | Opcode.VSUBPS -> vsubps ins insAddr insLen ctxt
  | Opcode.VSQRTPD -> vsqrtpd ins insAddr insLen ctxt
  | Opcode.VSQRTPS -> vsqrtps ins insAddr insLen ctxt
  | Opcode.VUNPCKHPD -> vunpckhpd ins insAddr insLen ctxt
  | Opcode.VUNPCKHPS -> vunpckhps ins insAddr insLen ctxt
  | Opcode.VUNPCKLPD -> vunpcklpd ins insAddr insLen ctxt
  | Opcode.VUNPCKLPS -> vunpcklps ins insAddr insLen ctxt
  | Opcode.VXORPD -> vxorpd ins insAddr insLen ctxt
  | Opcode.VXORPS -> vxorps ins insAddr insLen ctxt
  | Opcode.WAIT -> wait ins insAddr insLen ctxt
  | o ->
#if DEBUG
         eprintfn "%A" o
         eprintfn "%A" ins
#endif
         raise <| NotImplementedIRException (Disasm.opCodeToString o)
  |> fun builder -> builder.ToStmts ()

// vim: set tw=80 sts=2 sw=2:
