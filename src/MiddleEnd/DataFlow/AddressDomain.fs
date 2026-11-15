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
/// propagation runs to name the memory that the code reads and writes. It
/// keeps the addresses on the stack, counted from where the stack pointer
/// points on entry, apart from the constants that the stack pointer has no
/// part in. A constant that an instruction holds names a global variable,
/// whereas one that a register holds only moves an address on the stack.
[<RequireQualifiedAccess>]
module AddressDomain =

  /// Represents a lattice element in the address domain.
  type Lattice =
    /// Represents a value that is neither a known address on the stack nor a
    /// known constant, i.e., the top of the lattice.
    | NotAConst
    /// Represents an address on the stack, as its offset from where the stack
    /// pointer points on entry, that the stack or frame pointer holds, or that
    /// an instruction reaches from one with a constant it holds.
    | StackAddr of BitVector
    /// Represents an address on the stack, as its offset from where the stack
    /// pointer points on entry, that the code reaches with a constant that a
    /// register holds, as it reaches a slot of a big frame beyond what an
    /// instruction holds. The code forms such an address anew for each access,
    /// so it names its slot even where a register holds it.
    | FarStackAddr of BitVector
    /// Represents a constant that an instruction holds, or a register on entry
    /// as the binary fixes it, and the stack pointer has no part in, e.g., the
    /// address of a global variable.
    | Const of BitVector
    /// Represents a constant that a register holds, which moves an address on
    /// the stack along it, as the size of a big frame does, but names no
    /// memory itself. A register that holds any other address may walk memory
    /// in a loop, and a CFG that still lacks the way back shows only the first
    /// pass, so the register looks constant while what it reads is not.
    | Offset of BitVector
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

  /// Turns the given lattice element into what the stack or frame pointer
  /// holds once the code puts it there: an address on the stack however the
  /// code reaches it, and a constant as one that names no memory.
  let holdInStackPointer c =
    match c with
    | FarStackAddr off -> StackAddr off
    | Const bv -> Offset bv
    | _ -> c

  /// Turns the given lattice element into what any other register holds once
  /// the code puts it there: a constant as one that names no memory, and no
  /// address on the stack that an instruction reaches. The code takes such an
  /// address into a register to pass it on or to walk the stack with it, and
  /// a CFG that still lacks the way back of a loop shows only the first pass
  /// of a walk, so the register would look as if it held one slot.
  let hold c =
    match c with
    | StackAddr _ -> NotAConst
    | Const bv -> Offset bv
    | _ -> c

  /// Matches a constant of either kind.
  let private (|Number|_|) c =
    match c with
    | Const bv | Offset bv -> Some bv
    | _ -> None

  /// Matches an address on the stack of either kind, giving its offset from
  /// where the stack pointer points on entry.
  let (|OnStack|_|) c =
    match c with
    | StackAddr off | FarStackAddr off -> Some off
    | _ -> None

  /// Combines the two lattice elements with the given operation if both are
  /// constants. The result is one that a register holds if either is.
  let private combine op c1 c2 =
    match c1, c2 with
    | Const bv1, Const bv2 -> Const(op (bv1, bv2))
    | Number bv1, Number bv2 -> Offset(op (bv1, bv2))
    | _ -> NotAConst

  /// Adds the two lattice elements. A constant moves an address on the stack
  /// along it, and takes it far if a register holds the constant, whereas two
  /// addresses on the stack add up to nothing known.
  let add c1 c2 =
    match c1, c2 with
    | Undef, _ | _, Undef ->
      Undef
    | StackAddr off, Const bv | Const bv, StackAddr off ->
      StackAddr(BitVector.Add(off, bv))
    | OnStack off, Number bv | Number bv, OnStack off ->
      FarStackAddr(BitVector.Add(off, bv))
    | _ ->
      combine BitVector.Add c1 c2

  /// Subtracts the second lattice element from the first. Two addresses on the
  /// stack lie a constant apart.
  let sub c1 c2 =
    match c1, c2 with
    | Undef, _ | _, Undef -> Undef
    | StackAddr off, Const bv -> StackAddr(BitVector.Sub(off, bv))
    | OnStack off, Number bv -> FarStackAddr(BitVector.Sub(off, bv))
    | OnStack off1, OnStack off2 -> Const(BitVector.Sub(off1, off2))
    | _ -> combine BitVector.Sub c1 c2

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
    | OnStack off, Number m | Number m, OnStack off when isAlignmentMask m ->
      FarStackAddr(BitVector.And(off, m))
    | _ ->
      combine BitVector.And c1 c2

  /// Computes the bitwise OR of the two lattice elements. Oring an address on
  /// the stack with zero keeps it, as MIPS copies a register that way, and MIPS
  /// builds a wide constant by oring its low half into its high one.
  let ``or`` c1 c2 =
    match c1, c2 with
    | Undef, _ | _, Undef ->
      Undef
    | StackAddr off, Const z | Const z, StackAddr off when z.IsZero ->
      StackAddr off
    | OnStack off, Number z | Number z, OnStack off when z.IsZero ->
      FarStackAddr off
    | _ ->
      combine BitVector.Or c1 c2

  /// Evaluates the given binary operator in this domain.
  let internal evalBinOp op c1 c2 =
    match op with
    | BinOpType.ADD -> add c1 c2
    | BinOpType.SUB -> sub c1 c2
    | BinOpType.AND -> ``and`` c1 c2
    | BinOpType.OR -> ``or`` c1 c2
    | _ -> NotAConst
