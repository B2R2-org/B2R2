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

/// A program point (ProgramPoint) is a specific location in a lifted program.
/// We represent it as a three-tuple: (Address of the instruction, Index of the
/// IR stmt for the instruction, Address of a callsite). The third element is
/// optional and only meaningful for abstract vertices.
type ProgramPoint private (addr, pos, callsite) =

  new (addr, pos: int) = ProgramPoint (addr, pos, None)

  new (callsite, addr, pos: int) = ProgramPoint (addr, pos, Some callsite)

  /// Address of the instruction.
  member __.Address with get(): Addr = addr

  /// Index of the IR statement within the instruction.
  member __.Position with get(): int = pos

  /// Address of the callsite if this program point refers to an abstract
  /// vertex.
  member __.CallSite with get(): Addr option = callsite

  /// Compare against another program point.
  member __.CompareTo (rhs: ProgramPoint) =
    let result = compare __.Address rhs.Address
    if result <> 0 then result
    elif __.Position = rhs.Position then compare __.CallSite rhs.CallSite
    else compare __.Position rhs.Position

  override __.Equals (o) =
    match o with
    | :? ProgramPoint as o ->
      o.Address = __.Address
      && o.Position = __.Position
      && o.CallSite = __.CallSite
    | _ -> false

  override __.GetHashCode () =
    match __.CallSite with
    | None -> int __.Address ^^^ (__.Position <<< 16)
    | Some callSite -> int __.Address ^^^ (__.Position <<< 16) + int callSite

  override __.ToString () =
    match __.CallSite with
    | Some callsite -> $"{callsite:x}-{addr:x}"
    | None -> $"{addr:x}:{pos}"

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
      | :? ProgramPoint as rhs -> __.CompareTo rhs
      | _ -> invalidArg (nameof rhs) "Invalid comparison"

  interface System.IComparable<ProgramPoint> with
    member __.CompareTo (rhs) = __.CompareTo rhs
