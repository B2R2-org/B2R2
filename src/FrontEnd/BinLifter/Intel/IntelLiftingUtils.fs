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

module internal B2R2.FrontEnd.BinLifter.Intel.LiftingUtils

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.Intel.Helper

let inline getPseudoRegVar (ctxt: TranslationContext) name pos =
  ctxt.GetPseudoRegVar (Register.toRegID name) pos

let inline getRegVar (ctxt: TranslationContext) name =
  Register.toRegID name |> ctxt.GetRegVar

let inline numU32 n t = BitVector.ofUInt32 n t |> AST.num

let inline numI32 n t = BitVector.ofInt32 n t |> AST.num

let inline numU64 n t = BitVector.ofUInt64 n t |> AST.num

let inline numI64 n t = BitVector.ofInt64 n t |> AST.num

let numAddr addr (ctxt: TranslationContext) = numU64 addr ctxt.WordBitSize

let numInsLen insLen (ctxt: TranslationContext) = numU32 insLen ctxt.WordBitSize

let numOprSize = function
  | 8<rt> | 16<rt> | 32<rt> | 64<rt> | 128<rt> | 256<rt> | 512<rt> as rt ->
    numI32 (int rt) rt
  | _ -> raise InvalidOperandSizeException

let inline is64bit (ctxt: TranslationContext) = ctxt.WordBitSize = 64<rt>

let is64REXW ctxt (ins: InsInfo) =
  is64bit ctxt && hasREXW ins.REXPrefix

let inline tmpVars2 t =
  AST.tmpvar t, AST.tmpvar t

let inline tmpVars3 t =
  AST.tmpvar t, AST.tmpvar t, AST.tmpvar t

let inline tmpVars4 t =
  AST.tmpvar t, AST.tmpvar t, AST.tmpvar t, AST.tmpvar t

let inline getOperationSize (i: InsInfo) = i.InsSize.OperationSize
let inline getEffAddrSz (i: InsInfo) = i.InsSize.MemEffAddrSize

let inline (<!) (builder: StmtBuilder) (s) = builder.Append (s)

let inline ( |>> ) (b: StmtBuilder) (s) = b.Append (s); b

let undefCF = AST.undef 1<rt> "CF is undefined."
let undefOF = AST.undef 1<rt> "OF is undefined."
let undefAF = AST.undef 1<rt> "AF is undefined."
let undefSF = AST.undef 1<rt> "SF is undefined."
let undefZF = AST.undef 1<rt> "ZF is undefined."
let undefPF = AST.undef 1<rt> "PF is undefined."
let undefC0 = AST.undef 1<rt> "C0 is undefined."
let undefC1 = AST.undef 1<rt> "C1 is undefined."
let undefC2 = AST.undef 1<rt> "C2 is undefined."
let undefC3 = AST.undef 1<rt> "C3 is undefined."

let buildAF ctxt e1 e2 r size =
  let t1 = r <+> e1
  let t2 = t1 <+> e2
  let t3 = AST.binop BinOpType.SHL (AST.num1 size) (numU32 4ul size)
  let t4 = t2 .& t3
  getRegVar ctxt R.AF := t4 == t3

let buildPF ctxt r size cond builder =
  let t1, t2 = tmpVars2 size
  let s2 = r <+> (AST.binop BinOpType.SHR r (AST.zext size (numU32 4ul 8<rt>)))
  let s4 = s2 <+> (AST.binop BinOpType.SHR t1 (AST.zext size (numU32 2ul 8<rt>)))
  let s5 = s4 <+> (AST.binop BinOpType.SHR t2 (AST.zext size (AST.num1 8<rt>)))
  builder <! (t1 := s2)
  builder <! (t2 := s4)
  let pf = AST.unop UnOpType.NOT (AST.xtlo 1<rt> s5)
  match cond with
  | None -> builder <! (getRegVar ctxt R.PF := pf)
  | Some condFn -> builder <! (getRegVar ctxt R.PF := condFn pf)

let enumSZPFlags ctxt r size builder =
  builder <! (getRegVar ctxt R.SF := AST.xthi 1<rt> r)
  builder <! (getRegVar ctxt R.ZF := r == (AST.num0 size))
  buildPF ctxt r size None builder

let enumASZPFlags ctxt e1 e2 r size builder =
  builder <! (buildAF ctxt e1 e2 r size)
  enumSZPFlags ctxt r size builder

let enumEFLAGS ctxt e1 e2 e3 size cfGetter ofGetter builder =
  builder <! (getRegVar ctxt R.CF := cfGetter e1 e2 e3)
  builder <! (getRegVar ctxt R.OF := ofGetter e1 e2 e3)
  builder <! (buildAF ctxt e1 e2 e3 size)
  builder <! (getRegVar ctxt R.SF := AST.xthi 1<rt> e3)
  builder <! (getRegVar ctxt R.ZF := e3 == (AST.num0 size))
  buildPF ctxt e3 size None builder

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
  | Load (e, 512<rt>, expr, _, _) ->
    [ AST.load e 64<rt> expr
      AST.load e 64<rt> (expr .+ numI32 8 (AST.typeOf expr));
      AST.load e 64<rt> (expr .+ numI32 16 (AST.typeOf expr));
      AST.load e 64<rt> (expr .+ numI32 24 (AST.typeOf expr));
      AST.load e 64<rt> (expr .+ numI32 32 (AST.typeOf expr));
      AST.load e 64<rt> (expr .+ numI32 40 (AST.typeOf expr));
      AST.load e 64<rt> (expr .+ numI32 48 (AST.typeOf expr));
      AST.load e 64<rt> (expr .+ numI32 56 (AST.typeOf expr)); ]
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
  | Register.Kind.ZMM -> [ getPseudoRegVar ctxt r 1; getPseudoRegVar ctxt r 2
                           getPseudoRegVar ctxt r 3; getPseudoRegVar ctxt r 4
                           getPseudoRegVar ctxt r 5; getPseudoRegVar ctxt r 6
                           getPseudoRegVar ctxt r 7; getPseudoRegVar ctxt r 8 ]
  | _ -> raise InvalidOperandException

let private segRegToBase = function
  | R.CS -> R.CSBase
  | R.DS -> R.DSBase
  | R.ES -> R.ESBase
  | R.FS -> R.FSBase
  | R.GS -> R.GSBase
  | R.SS -> R.SSBase
  | _ -> Utils.impossible ()

let inline private ldMem ins ctxt oprSize e =
  match getSegment ins.Prefixes with
  | Some s -> getRegVar ctxt (segRegToBase s) .+ e
  | None -> e
  |> AST.loadLE oprSize

let inline private numOfAddrSz (ins: InsInfo) (ctxt: TranslationContext) n =
  let pref = ins.Prefixes
  let sz =
    if ctxt.WordBitSize = 32<rt> then if hasAddrSz pref then 16<rt> else 32<rt>
    else if hasAddrSz pref then 32<rt> else 64<rt>
  numI64 n sz

let inline private sIdx ins ctxt (r, s) =
  (getRegVar ctxt r) .* (numOfAddrSz ins ctxt (int64 s))

let transMem ins insAddr (insLen: uint32) ctxt b index (disp: Disp option) oprSize =
  match b, index, disp with
  | None, None, Some d ->
    numOfAddrSz ins ctxt d
    |> AST.zext ctxt.WordBitSize
    |> ldMem ins ctxt oprSize
  | None, Some i, Some d ->
    (sIdx ins ctxt i) .+ (numOfAddrSz ins ctxt d)
    |> AST.zext ctxt.WordBitSize
    |> ldMem ins ctxt oprSize
  | Some b, None, None ->
    getRegVar ctxt b
    |> AST.zext ctxt.WordBitSize
    |> ldMem ins ctxt oprSize
  | Some R.RIP, None, Some d -> (* RIP-relative addressing *)
    int64 insAddr + d + int64 insLen
    |> numOfAddrSz ins ctxt
    |> ldMem ins ctxt oprSize
  | Some b, None, Some d ->
    getRegVar ctxt b .+ (numOfAddrSz ins ctxt d)
    |> AST.zext ctxt.WordBitSize
    |> ldMem ins ctxt oprSize
  | Some b, Some i, None ->
    getRegVar ctxt b .+ (sIdx ins ctxt i)
    |> AST.zext ctxt.WordBitSize
    |> ldMem ins ctxt oprSize
  | Some b, Some i, Some d ->
    getRegVar ctxt b .+ (sIdx ins ctxt i) .+ (numOfAddrSz ins ctxt d)
    |> AST.zext ctxt.WordBitSize
    |> ldMem ins ctxt oprSize
  | _, _, _ -> raise InvalidOperandException

let transDirAddr wordSize (addr: Addr) = function
  | Absolute (_, addr, _) -> numU64 addr wordSize
  | Relative (offset) ->
    let offset = numI64 offset wordSize |> AST.sext wordSize
    let addr = numU64 addr wordSize
    offset .+ addr

let getCFlagOnAdd e1 _ r = AST.lt r e1
let getCFlagOnSub e1 e2 _ = AST.lt e1 e2

let getOFlagOnAdd e1 e2 r =
  let e1High = AST.xthi 1<rt> e1
  let e2High = AST.xthi 1<rt> e2
  let rHigh = AST.xthi 1<rt> r
  (e1High == e2High) .& (e1High <+> rHigh)

let getOFlagOnSub e1 e2 r =
  AST.xthi 1<rt> (AST.binop BinOpType.AND (e1 <+> e2) (e1 <+> r))

let transOprToExpr ins insAddr insLen ctxt = function
  | OprReg reg -> getRegVar ctxt reg
  | OprMem (b, index, disp, oprSize) ->
    transMem ins insAddr insLen ctxt b index disp oprSize
  | OprImm imm -> numI64 imm (getOperationSize ins)
  | OprDirAddr jumpTarget ->
    transDirAddr ctxt.WordBitSize insAddr jumpTarget
  | _ -> Utils.impossible ()

let transOprToExprVec ins insAddr insLen ctxt opr =
  match opr with
  | OprReg r -> getPseudoRegVars ctxt r
  | OprMem (b, index, disp, oprSize) ->
    transMem ins insAddr insLen ctxt b index disp oprSize |> getMemExprs
  | OprImm imm -> [ numI64 imm (getOperationSize ins) ]
  | _ -> raise InvalidOperandException

let transOprToExpr32 ins insAddr insLen ctxt opr =
  match opr with
  | OprReg r when Register.toRegType r > 64<rt> ->
    getPseudoRegVar ctxt r 1 |> AST.xtlo 32<rt>
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
    getRegVar ctxt r |> AST.cast CastKind.FloatExt 80<rt>
  | OprMem (b, index, disp, 80<rt>) ->
    transMem ins insAddr insLen ctxt b index disp 80<rt>
  | OprMem (b, index, disp, len) ->
    transMem ins insAddr insLen ctxt b index disp len
    |> AST.cast CastKind.FloatExt 80<rt>
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
  | _ -> let dst = AST.unwrap dst
         let dstOrigSz = dst |> AST.typeOf
         let oprBitSize = RegType.toBitWidth oprSize
         let dstBitSize = RegType.toBitWidth dstOrigSz
         if dstBitSize > oprBitSize then dst := AST.zext dstOrigSz src
         elif dstBitSize = oprBitSize then dst := src
         else raise InvalidOperandSizeException

let maxNum rt =
  match rt with
  | 8<rt> -> BitVector.maxNum8
  | 16<rt> -> BitVector.maxNum16
  | 32<rt> -> BitVector.maxNum32
  | 64<rt> -> BitVector.maxNum64
  | _ -> raise InvalidOperandSizeException
  |> AST.num

let castNum newType = function
  | Num n -> Num <| BitVector.cast n newType
  | _ -> raise InvalidOperandException

let getMask oprSize =
  match oprSize with
  | 8<rt> -> numI64 0xffL oprSize
  | 16<rt> -> numI64 0xffffL oprSize
  | 32<rt> -> numI64 0xffffffffL oprSize
  | 64<rt> -> numI64 0xffffffffffffffffL oprSize
  | _ -> raise InvalidOperandSizeException

let startMark insAddr insLen builder =
  builder <! (ISMark (insAddr, insLen))

let endMark insAddr (insLen: uint32) builder =
  builder <! (IEMark (insAddr + uint64 insLen)); builder

let sideEffects insAddr insLen name =
  let builder = StmtBuilder (4)
  startMark insAddr insLen builder
  builder <! (SideEffect name)
  endMark insAddr insLen builder
