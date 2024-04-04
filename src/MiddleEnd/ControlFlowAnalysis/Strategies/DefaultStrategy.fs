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
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis

type CFGAction<'Abs when 'Abs: null> =
  /// Build an initial CFG that is reachable from the given entry point.
  | BuildCFG of entryPoint: Addr
  | CallEdge of calleeAddr: Addr
  | IndirectEdge of IRBasicBlock<'Abs>
  | SyscallEdge of IRBasicBlock<'Abs>
  | JumpTableEntryStart of IRBasicBlock<'Abs> * Addr * Addr
  | JumpTableEntryEnd of IRBasicBlock<'Abs> * Addr * Addr
with
  interface ICFGAction with
    member __.Priority =
      match __ with
      | BuildCFG _ -> 4
      | CallEdge _ -> 3
      | IndirectEdge _ -> 2
      | SyscallEdge _ -> 1
      | JumpTableEntryStart _ -> 0
      | JumpTableEntryEnd _ -> 0

type BuildingState = {
  mutable WorkingJumpTable: (Addr * Addr) option
  UnresolvedCalls: Dictionary<Addr, HashSet<IRBasicBlock<FunctionAbstraction>>>
}
with
  interface IResettable with
    member __.Reset () =
      __.WorkingJumpTable <- None
      __.UnresolvedCalls.Clear ()

type CFGQuery =
  | FunctionInfo of calleeAddr: Addr
  | JumpTableRegistration of jtAddr: Addr
  | JumpTableConfirmation of entryPoint: Addr * jtAddr: Addr

type DefaultStrategy<'Abs when 'Abs: null> () =
  interface IFunctionBuildingStrategy<IRBasicBlock<'Abs>,
                                      CFGEdgeKind,
                                      'Abs,
                                      CFGAction<'Abs>,
                                      BuildingState,
                                      CFGQuery,
                                      int> with
    member _.OnAction (ctxt, queue, action) =
      failwith "X"

    member _.OnFinish (ctxt, noret) =
      failwith "X"

    member _.OnQuery (msg, validator) =
      failwith "X"
