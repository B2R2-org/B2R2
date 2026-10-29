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

namespace B2R2.MiddleEnd.ControlFlowAnalysis.Strategies

open System.Collections.Generic
open B2R2

/// Represents the global context for EVM, which keeps what the recovery of one
/// function finds out about another. Only the task manager touches it, through
/// the manager channel, so it needs no lock.
type EVMGlobalContext() =
  let returnTargetStackOffs = Dictionary<Addr, uint64>()

  let publicFunctions = HashSet<Addr>()

  let sharedRegions = HashSet<Addr>()

  /// Returns the stack offset of the return target that the function at the
  /// given address returns to, which is zero (the top) until it is known.
  member _.GetReturnTargetStackOff(addr: Addr) =
    match returnTargetStackOffs.TryGetValue addr with
    | true, off -> off
    | false, _ -> 0UL

  /// Sets the stack offset of the return target of the given function.
  member _.SetReturnTargetStackOff(addr: Addr, off) =
    returnTargetStackOffs[addr] <- off

  /// Checks if the function at the given address is a public function, which
  /// the dispatcher of the contract calls.
  member _.IsPublicFunction(addr: Addr) = publicFunctions.Contains addr

  /// Marks the function at the given address as a public function.
  member _.SetPublicFunction(addr: Addr) = publicFunctions.Add addr |> ignore

  /// Checks if the function at the given address is a shared region, which
  /// several functions jump into.
  member _.IsSharedRegion(addr: Addr) = sharedRegions.Contains addr

  /// Marks the function at the given address as a shared region.
  member _.SetSharedRegion(addr: Addr) = sharedRegions.Add addr |> ignore
