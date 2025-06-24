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

/// <summary>
/// Represents a specific location in a lifted program. We represent this as a
/// three-tuple: (address of the instruction, index of the IR stmt for the
/// instruction, call site information). The third element (call site) is
/// optional and only meaningful for abstract vertices.
/// </summary>
type ProgramPoint private (addr, pos, callsite) =

  new (addr, pos: int) = ProgramPoint (addr, pos, None)

  new (callsite, addr, pos: int) = ProgramPoint (addr, pos, Some callsite)

  /// Address of the instruction.
  member _.Address with get(): Addr = addr

  /// Index of the IR statement within the instruction.
  member _.Position with get(): int = pos

  /// Address of the callsite if this program point refers to an abstract
  /// vertex.
  member _.CallSite with get(): CallSite option = callsite

  /// Compares against another program point.
  member this.CompareTo (rhs: ProgramPoint) =
    let result = compare this.Address rhs.Address
    if result <> 0 then result
    elif this.Position = rhs.Position then compare this.CallSite rhs.CallSite
    else compare this.Position rhs.Position

  override this.Equals (o) =
    match o with
    | :? ProgramPoint as o ->
      o.Address = this.Address
      && o.Position = this.Position
      && o.CallSite = this.CallSite
    | _ -> false

  override this.GetHashCode () =
    let addrHash = int this.Address
    let posHash = this.Position <<< 16
    match this.CallSite with
    | None -> addrHash ^^^ posHash
    | Some callSite -> addrHash ^^^ posHash + callSite.GetHashCode ()

  override this.ToString () =
    match this.CallSite with
    | Some callsite -> $"{callsite:x}-{addr:x}"
    | None -> $"{addr:x}:{pos}"

  /// Gets a fake program point to represent a fake vertex, which does not exist
  /// in a CFG. Fake vertices are useful for representing external function
  /// calls and their nodes in the SCFG.
  static member GetFake () = ProgramPoint (0UL, -1)

  /// Checks if the given program point is a fake one.
  static member IsFake (p: ProgramPoint) = p.Address = 0UL && p.Position = -1

  static member Next (p: ProgramPoint) =
    if ProgramPoint.IsFake p then p
    else ProgramPoint (p.Address, p.Position + 1)

  interface System.IComparable with
    member this.CompareTo (rhs) =
      match rhs with
      | :? ProgramPoint as rhs -> this.CompareTo rhs
      | _ -> invalidArg (nameof rhs) "Invalid comparison"

  interface System.IComparable<ProgramPoint> with
    member this.CompareTo (rhs) = this.CompareTo rhs

/// Call site information of an abstract vertex in a control flow graph.
/// Typically, there is a single concrete caller vertex that calls an abstract
/// vertex. But in some cases, such as Continuation-Passing Style (CPS) patterns
/// found in EVM binaries, an abstract vertex can have a chain of callers.
and CallSite =
  /// Call site address of a concrete vertex. This serves as an end point of a
  /// call site chain.
  | LeafCallSite of callsite: Addr
  /// Chained call history from a callee to its original caller. The history
  /// always ends with a LeafCallSite, and the caller address is the address of
  /// the caller vertex, not the call site address. This is particularly useful
  /// to represent CPS patterns present in EVM binaries.
  | ChainedCallSite of history: CallSite * caller: Addr

with
  /// Returns the address of the leaf call site.
  member this.CallSiteAddress with get (): Addr =
    match this with
    | LeafCallSite addr -> addr
    | ChainedCallSite (cs, _) -> cs.CallSiteAddress