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

/// Defines the address domain and its operations, in which the stack pointer
/// propagation runs. It keeps the addresses on the stack, counted from where
/// the stack pointer points on entry, apart from the constants that the stack
/// pointer has no part in, such as the address of a global variable.
[<RequireQualifiedAccess>]
module AddressDomain =

  /// Represents a lattice element in the address domain.
  type Lattice =
    /// Represents a value that is neither a known address on the stack nor a
    /// known constant, i.e., the top of the lattice.
    | NotAConst
    /// Represents an address on the stack, as its offset from where the stack
    /// pointer points on entry.
    | StackAddr of BitVector
    /// Represents a constant that the stack pointer has no part in, e.g., the
    /// address of a global variable.
    | Const of BitVector
    /// Represents a value that is not known yet, i.e., the bottom of the
    /// lattice.
    | Undef

  /// Checks if the first lattice element subsumes the second, i.e., whether
  /// joining the second into the first would leave the first unchanged.
  let subsume a b =
    match a, b with
    | a, b when a = b -> true
    | _, Undef -> true
    | NotAConst, _ -> true
    | _ -> false

  /// Joins the two lattice elements.
  let join c1 c2 =
    match c1, c2 with
    | Undef, c | c, Undef -> c
    | _ when c1 = c2 -> c1
    | _ -> NotAConst

  /// Creates the lattice of this domain.
  let createLattice () =
    { new ILattice<Lattice> with
        member _.Bottom = Undef
        member _.Join(a, b) = join a b
        member _.Subsume(a, b) = subsume a b }

  /// Adds the two lattice elements. A constant moves an address on the stack
  /// along it, whereas two addresses on the stack add up to nothing known.
  let add c1 c2 =
    match c1, c2 with
    | Undef, _ | _, Undef ->
      Undef
    | StackAddr off, Const bv | Const bv, StackAddr off ->
      StackAddr(BitVector.Add(off, bv))
    | Const bv1, Const bv2 ->
      Const(BitVector.Add(bv1, bv2))
    | _ ->
      NotAConst

  /// Subtracts the second lattice element from the first. Two addresses on the
  /// stack lie a constant apart.
  let sub c1 c2 =
    match c1, c2 with
    | Undef, _ | _, Undef -> Undef
    | StackAddr off, Const bv -> StackAddr(BitVector.Sub(off, bv))
    | StackAddr off1, StackAddr off2 -> Const(BitVector.Sub(off1, off2))
    | Const bv1, Const bv2 -> Const(BitVector.Sub(bv1, bv2))
    | _ -> NotAConst

  /// Checks if the given mask clears only low bits, as code aligns the stack
  /// pointer with one.
  let private isAlignmentMask (mask: BitVector) =
    let one = BitVector.One mask.Length
    let step = BitVector.Add(BitVector.Not mask, one)
    not step.IsZero && BitVector.And(step, BitVector.Sub(step, one)).IsZero

  /// Computes the bitwise AND of the two lattice elements. Aligning an address
  /// on the stack keeps it there, taking the stack pointer on entry to be
  /// aligned at least as much.
  let ``and`` c1 c2 =
    match c1, c2 with
    | Undef, _ | _, Undef ->
      Undef
    | StackAddr off, Const m | Const m, StackAddr off when isAlignmentMask m ->
      StackAddr(BitVector.And(off, m))
    | Const bv1, Const bv2 ->
      Const(BitVector.And(bv1, bv2))
    | _ ->
      NotAConst

  /// Evaluates the given binary operator in this domain.
  let internal evalBinOp op c1 c2 =
    match op with
    | BinOpType.ADD -> add c1 c2
    | BinOpType.SUB -> sub c1 c2
    | BinOpType.AND -> ``and`` c1 c2
    | _ -> NotAConst
