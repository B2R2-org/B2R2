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

namespace B2R2.MiddleEnd.DataFlow

open B2R2
open B2R2.BinIR

/// Defines the constant domain and its operations for constant propagation
/// analysis.
[<RequireQualifiedAccess>]
module ConstantDomain =

  /// Represents a lattice element in the constant propagation domain.
  type Lattice =
    | NotAConst
    | Const of BitVector
    | Undef

  /// Checks if the first lattice element subsumes the second, i.e., whether
  /// joining the second into the first would leave the first unchanged.
  let subsume a b =
    match a, b with
    | a, b when a = b -> true
    | NotAConst, Const _
    | NotAConst, Undef
    | Const _, Undef -> true
    | _ -> false

  /// Joins two constant domains.
  let join a b =
    match a, b with
    | Undef, c | c, Undef -> c
    | Const x, Const y when x = y -> a
    | _ -> NotAConst

  let private unOp op = function
    | Const bv -> Const(op bv)
    | c -> c

  /// Negates the given lattice element.
  let neg c = unOp BitVector.Neg c

  /// Applies bitwise negation to the given lattice element.
  let not c = unOp BitVector.Not c

  let private binOp op c1 c2 =
    match c1, c2 with
    | Undef, _ | _, Undef -> Undef
    | Const bv1, Const bv2 -> Const(op (bv1, bv2))
    | _ -> NotAConst

  /// Adds the two lattice elements.
  let add c1 c2 = binOp BitVector.Add c1 c2

  /// Subtracts the second lattice element from the first.
  let sub c1 c2 = binOp BitVector.Sub c1 c2

  /// Multiplies the two lattice elements.
  let mul c1 c2 = binOp BitVector.Mul c1 c2

  let private divAux divop c1 c2 =
    match c1, c2 with
    | Undef, _ | _, Undef ->
      Undef
    | Const bv1, Const bv2 ->
      if bv2.IsZero then NotAConst else Const(divop (bv1, bv2))
    | _ ->
      NotAConst

  /// Divides the first lattice element by the second, unsigned. A division
  /// by zero is not a constant.
  let div c1 c2 = divAux BitVector.Div c1 c2

  /// Divides the first lattice element by the second, signed. A division by
  /// zero is not a constant.
  let sdiv c1 c2 = divAux BitVector.SDiv c1 c2

  /// Computes the unsigned remainder of the first lattice element divided by
  /// the second. A division by zero is not a constant.
  let ``mod`` c1 c2 = divAux BitVector.Modulo c1 c2

  /// Computes the signed remainder of the first lattice element divided by the
  /// second. A division by zero is not a constant.
  let smod c1 c2 = divAux BitVector.SModulo c1 c2

  let private adjustShiftOperand c =
    match c with
    | Const bv ->
      let rt = bv.Length
      let upperBound = BitVector(0xFFFFFFFFFFFFFFFFUL, rt)
      let isOkay = BitVector.Le(bv, upperBound).IsTrue
      if isOkay then c else NotAConst
    | _ ->
      c

  /// Shifts the first lattice element left by the second.
  let shl c1 c2 = binOp BitVector.Shl c1 (adjustShiftOperand c2)

  /// Shifts the first lattice element right by the second, unsigned.
  let shr c1 c2 = binOp BitVector.Shr c1 (adjustShiftOperand c2)

  /// Shifts the first lattice element right by the second, signed.
  let sar c1 c2 = binOp BitVector.Sar c1 (adjustShiftOperand c2)

  /// Computes the bitwise AND of the two lattice elements.
  let ``and`` c1 c2 = binOp BitVector.And c1 c2

  /// Computes the bitwise OR of the two lattice elements.
  let ``or`` c1 c2 = binOp BitVector.Or c1 c2

  /// Computes the bitwise XOR of the two lattice elements.
  let xor c1 c2 = binOp BitVector.Xor c1 c2

  /// Concatenates the two lattice elements.
  let concat c1 c2 = binOp BitVector.Concat c1 c2

  /// Checks if the two lattice elements are equal.
  let eq c1 c2 = binOp BitVector.Eq c1 c2

  /// Checks if the two lattice elements are not equal.
  let neq c1 c2 = binOp BitVector.Neq c1 c2

  /// Checks if the first lattice element is greater than the second, unsigned.
  let gt c1 c2 = binOp BitVector.Gt c1 c2

  /// Checks if the first lattice element is greater than or equal to the
  /// second, unsigned.
  let ge c1 c2 = binOp BitVector.Ge c1 c2

  /// Checks if the first lattice element is greater than the second, signed.
  let sgt c1 c2 = binOp BitVector.SGt c1 c2

  /// Checks if the first lattice element is greater than or equal to the
  /// second, signed.
  let sge c1 c2 = binOp BitVector.SGe c1 c2

  /// Checks if the first lattice element is less than the second, unsigned.
  let lt c1 c2 = binOp BitVector.Lt c1 c2

  /// Checks if the first lattice element is less than or equal to the second,
  /// unsigned.
  let le c1 c2 = binOp BitVector.Le c1 c2

  /// Checks if the first lattice element is less than the second, signed.
  let slt c1 c2 = binOp BitVector.SLt c1 c2

  /// Checks if the first lattice element is less than or equal to the second,
  /// signed.
  let sle c1 c2 = binOp BitVector.SLe c1 c2

  /// Selects one of the two lattice elements by the given condition. A
  /// condition that is not a constant joins both.
  let ite cond c1 c2 =
    match cond with
    | Undef -> Undef
    | Const bv -> if bv.IsZero then c2 else c1
    | NotAConst -> join c1 c2

  /// Casts the given lattice element to the given type with the given operator.
  let cast op rt c = unOp (fun bv -> op (bv, rt)) c

  /// Sign-extends the given lattice element to the given type.
  let signExt rt c = cast BitVector.SExt rt c

  /// Zero-extends the given lattice element to the given type.
  let zeroExt rt c = cast BitVector.ZExt rt c

  /// Extracts a sub-element of the given type at the given bit position.
  let extract c rt pos = unOp (fun bv -> BitVector.Extract(bv, rt, pos)) c

  /// Evaluates the given unary operator in this domain.
  let internal evalUnOp op c =
    match op with
    | UnOpType.NEG -> neg c
    | UnOpType.NOT -> not c
    | _ -> NotAConst

  /// Evaluates the given binary operator in this domain.
  let internal evalBinOp op c1 c2 =
    match op with
    | BinOpType.ADD -> add c1 c2
    | BinOpType.SUB -> sub c1 c2
    | BinOpType.MUL -> mul c1 c2
    | BinOpType.DIV -> div c1 c2
    | BinOpType.SDIV -> sdiv c1 c2
    | BinOpType.MOD -> ``mod`` c1 c2
    | BinOpType.SMOD -> smod c1 c2
    | BinOpType.SHL -> shl c1 c2
    | BinOpType.SHR -> shr c1 c2
    | BinOpType.SAR -> sar c1 c2
    | BinOpType.AND -> ``and`` c1 c2
    | BinOpType.OR -> ``or`` c1 c2
    | BinOpType.XOR -> xor c1 c2
    | BinOpType.CONCAT -> concat c1 c2
    | _ -> NotAConst

  /// Evaluates the given relational operator in this domain.
  let internal evalRelOp op c1 c2 =
    match op with
    | RelOpType.EQ -> eq c1 c2
    | RelOpType.NEQ -> neq c1 c2
    | RelOpType.GT -> gt c1 c2
    | RelOpType.GE -> ge c1 c2
    | RelOpType.SGT -> sgt c1 c2
    | RelOpType.SGE -> sge c1 c2
    | RelOpType.LT -> lt c1 c2
    | RelOpType.LE -> le c1 c2
    | RelOpType.SLT -> slt c1 c2
    | RelOpType.SLE -> sle c1 c2
    | _ -> NotAConst

  /// Evaluates the given cast operator in this domain.
  let internal evalCast op rt c =
    match op with
    | CastKind.SignExt -> signExt rt c
    | CastKind.ZeroExt -> zeroExt rt c
    | _ -> NotAConst
