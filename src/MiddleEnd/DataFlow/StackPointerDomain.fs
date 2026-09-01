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

/// Defines the stack pointer domain and its operations for stack pointer
/// propagation analysis.
[<RequireQualifiedAccess>]
module StackPointerDomain =

  /// Represents a lattice element in the stack pointer propagation domain.
  type Lattice =
    /// Represents a stack pointer value that is not a constant, i.e., the top
    /// of the lattice.
    | NotConstSP
    /// Represents a stack pointer value known to be the given constant.
    | ConstSP of BitVector
    /// Represents a stack pointer value that is not known yet, i.e., the
    /// bottom of the lattice.
    | Undef

  /// Checks if the first lattice element subsumes the second, i.e., whether
  /// joining the second into the first would leave the first unchanged.
  let subsume a b =
    match a, b with
    | a, b when a = b -> true
    | ConstSP _, Undef
    | NotConstSP, Undef
    | NotConstSP, ConstSP _ -> true
    | _ -> false

  /// Joins the two lattice elements.
  let join c1 c2 =
    match c1, c2 with
    | Undef, c | c, Undef -> c
    | ConstSP bv1, ConstSP bv2 -> if bv1 = bv2 then c1 else NotConstSP
    | _ -> NotConstSP

  /// Adds the two lattice elements.
  let add c1 c2 =
    match c1, c2 with
    | Undef, _ | _, Undef -> Undef
    | ConstSP bv1, ConstSP bv2 -> ConstSP(BitVector.Add(bv1, bv2))
    | _ -> NotConstSP

  /// Subtracts the second lattice element from the first.
  let sub c1 c2 =
    match c1, c2 with
    | Undef, _ | _, Undef -> Undef
    | ConstSP bv1, ConstSP bv2 -> ConstSP(BitVector.Sub(bv1, bv2))
    | _ -> NotConstSP

  /// Computes the bitwise AND of the two lattice elements.
  let ``and`` c1 c2 =
    match c1, c2 with
    | Undef, _ | _, Undef -> Undef
    | ConstSP bv1, ConstSP bv2 -> ConstSP(BitVector.And(bv1, bv2))
    | _ -> NotConstSP

  /// Evaluates the given binary operator in this domain.
  let internal evalBinOp op c1 c2 =
    match op with
    | BinOpType.ADD -> add c1 c2
    | BinOpType.SUB -> sub c1 c2
    | BinOpType.AND -> ``and`` c1 c2
    | _ -> NotConstSP
