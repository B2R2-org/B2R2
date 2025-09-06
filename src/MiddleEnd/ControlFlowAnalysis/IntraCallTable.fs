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
type IntraCallTable() =
  let callees = SortedList<CallSite, CalleeKind>()

  /// Mapping from a callee address to its callsite address (i.e., the address
  /// of the call instruction).
  let callsites = Dictionary<Addr, HashSet<CallSite>>()

  /// The frame distances of callees in this function. This is a mapping from a
  /// callsite address to the distance from the stack base address of this
  /// function to the stack base address of the callee.
  let frameDistances = Dictionary<CallSite, int>()

  /// The callees of this function. This is a mapping from a callsite (call
  /// instruction) address to its callee kind.
  member _.Callees with get() = callees

  /// Add information about a regular function call.
  member _.AddRegularCall(callsite, calleeAddr) =
    callees[callsite] <- RegularCallee calleeAddr
    match callsites.TryGetValue calleeAddr with
    | true, callsites -> callsites.Add callsite |> ignore
    | false, _ -> callsites[calleeAddr] <- HashSet [ callsite ]

  /// Add information about a syscall.
  member _.AddSystemCall(callsiteAddr, isExit) =
    callees[callsiteAddr] <- SyscallCallee isExit

  /// Get a callee information for the given call instruction address.
  member _.GetCallee(callsite: CallSite) =
    callees[callsite]

  /// Try to get a callee information for the given call instruction address.
  member _.TryGetCallee(callsite: CallSite) =
    callees.TryGetValue callsite

  /// Get a set of callsite addresses of a callee.
  member _.GetCallsites(calleeAddr: Addr) =
    callsites[calleeAddr]

  /// Try to get a set of callsite addresses of a callee.
  member _.TryGetCallsites(calleeAddr: Addr) =
    callsites.TryGetValue calleeAddr

  /// Update call frame distance information for the given callsite address.
  member _.UpdateFrameDistance(callsite: CallSite, distance) =
    frameDistances[callsite] <- distance

  /// Try to get a frame distance for the given callsite address.
  member _.TryGetFrameDistance(callsite: CallSite) =
    frameDistances.TryGetValue callsite

  member _.Reset() =
    callees.Clear()
    callsites.Clear()
    frameDistances.Clear()

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
