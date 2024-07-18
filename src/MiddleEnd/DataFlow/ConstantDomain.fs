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

/// A domain for constant propagation analysis.
[<RequireQualifiedAccess>]
module ConstantDomain =
  type Lattice =
    | NotAConst
    | Const of BitVector
    | Undef

  /// Check if the transition from the old domain to the new domain is
  /// non-monotonic or the same.
  let isSubsumable oldDomain newDomain =
    match oldDomain, newDomain with
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
    | Const bv -> Const (op bv)
    | c -> c

  let neg c = unOp BitVector.Neg c

  let not c = unOp BitVector.BNot c

  let private binOp op c1 c2 =
    match c1, c2 with
    | Undef, _ | _, Undef -> Undef
    | Const bv1, Const bv2 -> Const (op (bv1, bv2))
    | _ -> NotAConst

  let add c1 c2 =
    match c1, c2 with
    | Undef, _ | _, Undef -> Undef
    | Const bv1, Const bv2 -> Const (BitVector.Add (bv1, bv2))
    | _ -> NotAConst

  let sub c1 c2 = binOp BitVector.Sub c1 c2

  let mul c1 c2 = binOp BitVector.Mul c1 c2

  let private divAux divop c1 c2 =
    match c1, c2 with
    | Undef, _ | _, Undef -> Undef
    | Const bv1, Const bv2 ->
      if BitVector.IsZero bv2 then NotAConst
      else Const (divop (bv1, bv2))
    | _ -> NotAConst

  let div c1 c2 = divAux BitVector.Div c1 c2

  let sdiv c1 c2 = divAux BitVector.SDiv c1 c2

  let ``mod`` c1 c2 = divAux BitVector.Modulo c1 c2

  let smod c1 c2 = divAux BitVector.SModulo c1 c2

  let shl c1 c2 = binOp BitVector.Shl c1 c2

  let shr c1 c2 = binOp BitVector.Shr c1 c2

  let sar c1 c2 = binOp BitVector.Sar c1 c2

  let ``and`` c1 c2 = binOp BitVector.BAnd c1 c2

  let ``or`` c1 c2 = binOp BitVector.BOr c1 c2

  let xor c1 c2 = binOp BitVector.BXor c1 c2

  let concat c1 c2 = binOp BitVector.Concat c1 c2

  let relOp op c1 c2 = binOp op c1 c2

  let eq c1 c2 = relOp BitVector.Eq c1 c2

  let neq c1 c2 = relOp BitVector.Neq c1 c2

  let gt c1 c2 = relOp BitVector.Gt c1 c2

  let ge c1 c2 = relOp BitVector.Ge c1 c2

  let sgt c1 c2 = relOp BitVector.SGt c1 c2

  let sge c1 c2 = relOp BitVector.SGe c1 c2

  let lt c1 c2 = relOp BitVector.Lt c1 c2

  let le c1 c2 = relOp BitVector.Le c1 c2

  let slt c1 c2 = relOp BitVector.SLt c1 c2

  let sle c1 c2 = relOp BitVector.SLe c1 c2

  let ite cond c1 c2 =
    match cond with
    | Undef -> Undef
    | Const bv -> if BitVector.IsZero bv then c2 else c1
    | NotAConst -> join c1 c2

  let cast op rt c =
    unOp (fun bv -> op (bv, rt)) c

  let signExt rt c = cast BitVector.SExt rt c

  let zeroExt rt c = cast BitVector.ZExt rt c

  let extract c rt pos =
    unOp (fun bv -> BitVector.Extract (bv, rt, pos)) c
