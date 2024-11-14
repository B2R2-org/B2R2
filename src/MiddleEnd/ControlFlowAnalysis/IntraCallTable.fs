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

namespace B2R2.MiddleEnd.ControlFlowAnalysis

open System.Collections.Generic
open B2R2

/// A per-function table that maintains function call information within a
/// function, such as callsites in the function, callees, and their
/// relationships.
[<AllowNullLiteral>]
type IntraCallTable () =
  let callees = SortedList<Addr, CalleeKind> ()

  /// The addresses of calling nodes (which terminate a basic block with a call
  /// instruction) in this function. This is a mapping from a callee address to
  /// its callsite addresses.
  let callingBBLs = Dictionary<Addr, HashSet<Addr>> ()

  /// The frame distances of callees in this function. This is a mapping from a
  /// callsite address to the distance from the stack base address of this
  /// function to the stack base address of the callee.
  let frameDistances = Dictionary<Addr, int> ()

  /// The callees of this function. This is a mapping from a callsite (call
  /// instruction) address to its callee kind.
  member _.Callees with get() = callees

  /// Add information about a regular function call.
  member _.AddRegularCall (srcPPoint: ProgramPoint) callsiteAddr calleeAddr =
    callees[callsiteAddr] <- RegularCallee calleeAddr
    match callingBBLs.TryGetValue calleeAddr with
    | true, callsites -> callsites.Add srcPPoint.Address |> ignore
    | false, _ -> callingBBLs[calleeAddr] <- HashSet [ srcPPoint.Address ]

  /// Add information about a syscall.
  member _.AddSystemCall callsiteAddr isExit =
    callees[callsiteAddr] <- SyscallCallee isExit

  /// Get a callee information for the given call instruction address.
  member _.GetCallee (callsiteAddr: Addr) =
    callees[callsiteAddr]

  /// Try to get a callee information for the given call instruction address.
  member _.TryGetCallee (callsiteAddr: Addr) =
    callees.TryGetValue callsiteAddr

  /// Get a set of calling BBL addresses of a callee.
  member _.GetCallingBBLs (calleeAddr: Addr) =
    callingBBLs[calleeAddr]

  /// Try to get a set of calling BBL addresses of a callee.
  member _.TryGetCallingBBLs (calleeAddr: Addr) =
    callingBBLs.TryGetValue calleeAddr

  /// Update call frame distance information for the given callsite address.
  member _.UpdateFrameDistance (callsiteAddr: Addr) distance =
    frameDistances[callsiteAddr] <- distance

  /// Try to get a frame distance for the given callsite address.
  member _.TryGetFrameDistance (callsiteAddr: Addr) =
    frameDistances.TryGetValue callsiteAddr

  member _.Reset () =
    callees.Clear ()
    callingBBLs.Clear ()
    frameDistances.Clear ()

/// What kind of callee is this?
and CalleeKind =
  /// Callee is a regular function.
  | RegularCallee of Addr
  /// Callee is a syscall of the given number.
  | SyscallCallee of isExit: bool
  /// Callee is a set of indirect call targets. This means potential callees
  /// have been analyzed already.
  | IndirectCallees of Set<Addr>
  /// Callee (call target) is unresolved yet. This eventually will become
  /// IndirectCallees after indirect call analyses.
  | UnresolvedIndirectCallees
  /// There can be "call 0" to call an external function. This pattern is
  /// typically observed by object files, but sometimes we do see this pattern
  /// in regular binaries, e.g., GNU libc.
  | NullCallee
