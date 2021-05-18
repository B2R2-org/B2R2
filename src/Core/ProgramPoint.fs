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

namespace B2R2

/// A program point (ProgramPoint) is a fine-grained location in a program,
/// which can point to a specific IR statement. We represent it as a tuple:
/// (Address of the instruction, Index of the IR stmt for the instruction).
type ProgramPoint (addr, pos) =
  /// Address of the instruction.
  member val Address: Addr = addr
  /// Index of the IR statement within the instruction.
  member val Position: int = pos
  override __.Equals (o) =
    match o with
    | :? ProgramPoint as o -> o.Address = __.Address && o.Position = __.Position
    | _ -> false
  override __.GetHashCode () = hash (__.Address, __.Position)
  override __.ToString () = String.u64ToHexNoPrefix addr + ":" + pos.ToString ()

  /// Get a fake program point to represent a fake vertex, which does not exist
  /// in a CFG. Fake vertices are useful for representing external function
  /// calls and their nodes in the SCFG.
  static member GetFake () = ProgramPoint (0UL, -1)
  static member IsFake (p: ProgramPoint) = p.Address = 0UL && p.Position = -1

  static member Next (p: ProgramPoint) =
    if ProgramPoint.IsFake p then p
    else ProgramPoint (p.Address, p.Position + 1)

  interface System.IComparable with
    member __.CompareTo (rhs) =
      match rhs with
      | :? ProgramPoint as rhs ->
        (* To lexicographically sort leaders. Being too pedantic here. *)
        if __.Address = rhs.Address then compare __.Position rhs.Position
        else compare __.Address rhs.Address
      | _ -> invalidArg (nameof rhs) "Invalid comparison"
