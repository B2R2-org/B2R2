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
open B2R2.FrontEnd.BinLifter.LiftingOperators
open B2R2.FrontEnd.BinLifter.Intel.Helper

open type BinOpType

let inline ( !. ) (ctxt: TranslationContext) name =
  Register.toRegID name |> ctxt.GetRegVar

let inline getPseudoRegVar (ctxt: TranslationContext) name pos =
  ctxt.GetPseudoRegVar (Register.toRegID name) pos

let inline numU32 n t = BitVector.ofUInt32 n t |> AST.num

let inline numI32 n t = BitVector.ofInt32 n t |> AST.num

let inline numU64 n t = BitVector.ofUInt64 n t |> AST.num

let inline numI64 n t = BitVector.ofInt64 n t |> AST.num

let numInsLen insLen (ctxt: TranslationContext) = numU32 insLen ctxt.WordBitSize

let numOprSize = function
  | 8<rt> | 16<rt> | 32<rt> | 64<rt> | 128<rt> | 256<rt> | 512<rt> as rt ->
    numI32 (int rt) rt
  | _ -> raise InvalidOperandSizeException

let inline is64bit (ctxt: TranslationContext) = ctxt.WordBitSize = 64<rt>

let is64REXW ctxt (ins: InsInfo) =
  is64bit ctxt && hasREXW ins.REXPrefix

#if DEBUG
let assert32 ctxt =
  if is64bit ctxt then raise InvalidISAException else ()
#endif

let inline tmpVars2 ir t =
  struct (!*ir t, !*ir t)

let inline tmpVars3 ir t =
  struct (!*ir t, !*ir t, !*ir t)

let inline tmpVars4 ir t =
  struct (!*ir t, !*ir t, !*ir t, !*ir t)

let inline getOperationSize (i: InsInfo) = i.MainOperationSize

let inline getEffAddrSz (i: InsInfo) = i.PointerSize

let inline getImmValue imm =
  match imm with
  | OprImm (imm, _) -> imm
  | _ -> raise InvalidOperandException

let private getMemExpr128 expr =
  match expr.E with
  | Load (e, 128<rt>, expr, _) ->
    AST.load e 64<rt> (expr .+ numI32 8 (TypeCheck.typeOf expr)),
    AST.load e 64<rt> expr
  | _ -> raise InvalidOperandException

let private getMemExpr256 expr =
  match expr.E with
  | Load (e, 256<rt>, expr, _) ->
    AST.load e 64<rt> (expr .+ numI32 24 (TypeCheck.typeOf expr)),
    AST.load e 64<rt> (expr .+ numI32 16 (TypeCheck.typeOf expr)),
    AST.load e 64<rt> (expr .+ numI32 8 (TypeCheck.typeOf expr)),
    AST.load e 64<rt> expr
  | _ -> raise InvalidOperandException

let private getMemExpr512 expr =
  match expr.E with
  | Load (e, 512<rt>, expr, _) ->
    AST.load e 64<rt> (expr .+ numI32 56 (TypeCheck.typeOf expr)),
    AST.load e 64<rt> (expr .+ numI32 48 (TypeCheck.typeOf expr)),
    AST.load e 64<rt> (expr .+ numI32 40 (TypeCheck.typeOf expr)),
    AST.load e 64<rt> (expr .+ numI32 32 (TypeCheck.typeOf expr)),
    AST.load e 64<rt> (expr .+ numI32 24 (TypeCheck.typeOf expr)),
    AST.load e 64<rt> (expr .+ numI32 16 (TypeCheck.typeOf expr)),
    AST.load e 64<rt> (expr .+ numI32 8 (TypeCheck.typeOf expr)),
    AST.load e 64<rt> expr
  | _ -> raise InvalidOperandException

let private getMemExprs expr =
  match expr.E with
  | Load (e, 128<rt>, expr, _) ->
    [ AST.load e 64<rt> expr
      AST.load e 64<rt> (expr .+ numI32 8 (TypeCheck.typeOf expr)) ]
  | Load (e, 256<rt>, expr, _) ->
    [ AST.load e 64<rt> expr
      AST.load e 64<rt> (expr .+ numI32 8 (TypeCheck.typeOf expr))
      AST.load e 64<rt> (expr .+ numI32 16 (TypeCheck.typeOf expr))
      AST.load e 64<rt> (expr .+ numI32 24 (TypeCheck.typeOf expr)) ]
  | Load (e, 512<rt>, expr, _) ->
    [ AST.load e 64<rt> expr
      AST.load e 64<rt> (expr .+ numI32 8 (TypeCheck.typeOf expr))
      AST.load e 64<rt> (expr .+ numI32 16 (TypeCheck.typeOf expr))
      AST.load e 64<rt> (expr .+ numI32 24 (TypeCheck.typeOf expr))
      AST.load e 64<rt> (expr .+ numI32 32 (TypeCheck.typeOf expr))
      AST.load e 64<rt> (expr .+ numI32 40 (TypeCheck.typeOf expr))
      AST.load e 64<rt> (expr .+ numI32 48 (TypeCheck.typeOf expr))
      AST.load e 64<rt> (expr .+ numI32 56 (TypeCheck.typeOf expr)) ]
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

let private getPseudoRegVars ctxt r =
  match Register.getKind r with
  | Register.Kind.XMM -> [ getPseudoRegVar ctxt r 1; getPseudoRegVar ctxt r 2 ]
  | Register.Kind.YMM -> [ getPseudoRegVar ctxt r 1; getPseudoRegVar ctxt r 2
                           getPseudoRegVar ctxt r 3; getPseudoRegVar ctxt r 4 ]
  | Register.Kind.ZMM -> [ getPseudoRegVar ctxt r 1; getPseudoRegVar ctxt r 2
                           getPseudoRegVar ctxt r 3; getPseudoRegVar ctxt r 4
                           getPseudoRegVar ctxt r 5; getPseudoRegVar ctxt r 6
                           getPseudoRegVar ctxt r 7; getPseudoRegVar ctxt r 8 ]
  | _ -> raise InvalidOperandException

let isSegReg = function
  | Register.CS
  | Register.DS
  | Register.SS
  | Register.ES
  | Register.FS
  | Register.GS -> true
  | _ -> false

let private segRegToBase = function
  | R.CS -> R.CSBase
  | R.DS -> R.DSBase
  | R.ES -> R.ESBase
  | R.FS -> R.FSBase
  | R.GS -> R.GSBase
  | R.SS -> R.SSBase
  | _ -> Utils.impossible ()

let private ldMem (ins: InsInfo) ctxt oprSize e =
  match getSegment ins.Prefixes with
  | Some s -> !.ctxt (segRegToBase s) .+ e
  | None -> e
  |> AST.loadLE oprSize

let private numOfAddrSz (ins: InsInfo) (ctxt: TranslationContext) n =
  let pref = ins.Prefixes
  let sz =
    if ctxt.WordBitSize = 32<rt> then if hasAddrSz pref then 16<rt> else 32<rt>
    else if hasAddrSz pref then 32<rt> else 64<rt>
  numI64 n sz

let inline private sIdx ins ctxt (r, s: Scale) =
  (!.ctxt r) .* (numOfAddrSz ins ctxt (int64 s))

let private transMem ins insLen ctxt b index disp oprSize =
  match b, index, (disp: Disp option) with
  | None, None, Some d ->
    numOfAddrSz ins ctxt d
    |> ldMem ins ctxt oprSize
  | None, Some i, Some d ->
    (sIdx ins ctxt i) .+ (numOfAddrSz ins ctxt d)
    |> ldMem ins ctxt oprSize
  | Some b, None, None ->
    !.ctxt b
    |> ldMem ins ctxt oprSize
  | Some R.RIP, None, Some d -> (* RIP-relative addressing *)
    !.ctxt R.RIP .+ numOfAddrSz ins ctxt (d + int64 (insLen: uint32))
    |> ldMem ins ctxt oprSize
  | Some b, None, Some d ->
    !.ctxt b .+ (numOfAddrSz ins ctxt d)
    |> ldMem ins ctxt oprSize
  | Some b, Some i, None ->
    !.ctxt b .+ (sIdx ins ctxt i)
    |> ldMem ins ctxt oprSize
  | Some b, Some i, Some d ->
    !.ctxt b .+ (sIdx ins ctxt i) .+ (numOfAddrSz ins ctxt d)
    |> ldMem ins ctxt oprSize
  | _, _, _ -> raise InvalidOperandException

let transOprToExpr ins insLen ctxt = function
  | OprReg reg -> !.ctxt reg
  | OprMem (b, index, disp, oprSize) ->
    transMem ins insLen ctxt b index disp oprSize
  | OprImm (imm, _) -> numI64 imm (getOperationSize ins)
  | OprDirAddr (Relative offset) -> numI64 offset ctxt.WordBitSize
  | OprDirAddr (Absolute (_, addr, _)) -> numU64 addr ctxt.WordBitSize
  | _ -> Utils.impossible ()

let transOprToExprVec ins insLen ctxt opr =
  match opr with
  | OprReg r -> getPseudoRegVars ctxt r
  | OprMem (b, index, disp, oprSize) ->
    transMem ins insLen ctxt b index disp oprSize |> getMemExprs
  | OprImm (imm, _) -> [ numI64 imm (getOperationSize ins) ]
  | _ -> raise InvalidOperandException

let transOprToExpr32 ins insLen ctxt opr =
  match opr with
  | OprReg r when Register.toRegType r > 64<rt> ->
    getPseudoRegVar ctxt r 1 |> AST.xtlo 32<rt>
  | OprReg r -> !.ctxt r
  | OprMem (b, index, disp, 32<rt>) ->
    transMem ins insLen ctxt b index disp 32<rt>
  | _ -> raise InvalidOperandException

let transOprToExpr64 ins insLen ctxt opr =
  match opr with
  | OprReg r when Register.toRegType r > 64<rt> -> getPseudoRegVar ctxt r 1
  | OprReg r -> !.ctxt r
  | OprMem (b, index, disp, 64<rt>) ->
    transMem ins insLen ctxt b index disp 64<rt>
  | _ -> raise InvalidOperandException

let transOprToExpr128 ins insLen ctxt opr =
  match opr with
  | OprReg r -> getPseudoRegVar128 ctxt r
  | OprMem (b, index, disp, oprSize) ->
    transMem ins insLen ctxt b index disp oprSize |> getMemExpr128
  | _ -> raise InvalidOperandException

let transOprToExpr256 ins insLen ctxt opr =
  match opr with
  | OprReg r -> getPseudoRegVar256 ctxt r
  | OprMem (b, index, disp, oprSize) ->
    transMem ins insLen ctxt b index disp oprSize |> getMemExpr256
  | _ -> raise InvalidOperandException

let transOprToExpr512 ins insLen ctxt opr =
  match opr with
  | OprReg r -> getPseudoRegVar512 ctxt r
  | OprMem (b, index, disp, oprSize) ->
    transMem ins insLen ctxt b index disp oprSize |> getMemExpr512
  | _ -> raise InvalidOperandException

let transOprToFloat80 ins insLen ctxt opr =
  match opr with
  | OprReg r when Register.toRegType r = 80<rt> -> !.ctxt r
  | OprReg r ->
    !.ctxt r |> AST.cast CastKind.FloatCast 80<rt>
  | OprMem (b, index, disp, 80<rt>) ->
    transMem ins insLen ctxt b index disp 80<rt>
  | OprMem (b, index, disp, len) ->
    transMem ins insLen ctxt b index disp len
    |> AST.cast CastKind.FloatCast 80<rt>
  | _ -> raise InvalidOperandException

/// Return a tuple (jump target expr, is pc-relative?)
let transJumpTargetOpr (ins: InsInfo) pc insLen (ctxt: TranslationContext) =
  match ins.Operands with
  | OneOperand (OprDirAddr (Absolute (_, addr, _))) ->
    struct (numU64 addr ctxt.WordBitSize, false)
  | OneOperand (OprDirAddr (Relative offset)) ->
    let wordSize = ctxt.WordBitSize
    let offset = numI64 offset wordSize |> AST.sext wordSize
    struct (pc .+ offset, true)
  | OneOperand (OprReg reg) -> struct (!.ctxt reg, false)
  | OneOperand (OprMem (b, index, disp, oprSize)) ->
    struct (transMem ins insLen ctxt b index disp oprSize, false)
  | _ -> raise InvalidOperandException

let getTwoOprs (ins: InsInfo) =
  match ins.Operands with
  | TwoOperands (o1, o2) -> struct (o1, o2)
  | _ -> raise InvalidOperandException

let getThreeOprs (ins: InsInfo) =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) -> struct (o1, o2, o3)
  | _ -> raise InvalidOperandException

let getFourOprs (ins: InsInfo) =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) -> struct (o1, o2, o3, o4)
  | _ -> raise InvalidOperandException

let transOneOpr (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | OneOperand opr -> transOprToExpr ins insLen ctxt opr
  | _ -> raise InvalidOperandException

let transTwoOprs (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands (o1, o2) ->
    struct (transOprToExpr ins insLen ctxt o1,
            transOprToExpr ins insLen ctxt o2)
  | _ -> raise InvalidOperandException

let transThreeOprs (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) ->
    struct (transOprToExpr ins insLen ctxt o1,
            transOprToExpr ins insLen ctxt o2,
            transOprToExpr ins insLen ctxt o3)
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
  | _ -> let dst = AST.unwrap dst
         let dstOrigSz = dst |> TypeCheck.typeOf
         let oprBitSize = RegType.toBitWidth oprSize
         let dstBitSize = RegType.toBitWidth dstOrigSz
         if dstBitSize > oprBitSize then dst := AST.zext dstOrigSz src
         elif dstBitSize = oprBitSize then dst := src
         else raise InvalidOperandSizeException

let maxNum rt =
  match rt with
  | 8<rt> -> BitVector.maxUInt8
  | 16<rt> -> BitVector.maxUInt16
  | 32<rt> -> BitVector.maxUInt32
  | 64<rt> -> BitVector.maxUInt64
  | _ -> raise InvalidOperandSizeException
  |> AST.num

let castNum newType e =
  match e.E with
  | Num n -> BitVector.cast n newType |> AST.num
  | _ -> raise InvalidOperandException

let getMask oprSize =
  match oprSize with
  | 8<rt> -> numI64 0xffL oprSize
  | 16<rt> -> numI64 0xffffL oprSize
  | 32<rt> -> numI64 0xffffffffL oprSize
  | 64<rt> -> numI64 0xffffffffffffffffL oprSize
  | _ -> raise InvalidOperandSizeException

let sideEffects insLen name =
  let ir = IRBuilder (4)
  !<ir insLen
  !!ir (AST.sideEffect name)
  !>ir insLen
