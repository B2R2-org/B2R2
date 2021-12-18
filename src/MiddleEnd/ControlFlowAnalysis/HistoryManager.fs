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

/// To support the rollback mechanism, we remember inter-function edges created
/// during the recovery of an indirect branch. If a vertex has been promoted due
/// to such an edge, and the edge has turned out to be invalid, then we should
/// be able to revert the promotion.
type HistoricalFact =
  | CreatedFunction of func: Addr

module private HistoricalFact =
  let toString = function
    | CreatedFunction (func) -> "CreatedFunction(" + func.ToString("x") + ")"

/// Record and manage the CFG recovery history.
type HistoryManager () =
  let functionStack = Stack<Addr> ()
  let history = Dictionary<Addr, Stack<HistoricalFact>> ()

  /// Record the history of a certain function.
  member __.StartRecordingFunctionHistory addr =
    functionStack.Push (addr)

  /// Stop recording the history of a certain function.
  member __.StopRecordingFunctionHistory addr =
    let top = functionStack.Pop ()
    assert (addr = top)

  /// Check if the given function address exists in the function stack excluding
  /// the stack top.
  member __.HasFunctionLater addr =
    if functionStack.Count = 0 then false
    else Seq.tail functionStack |> Seq.exists (fun a -> addr = a)

  /// Record the historical fact.
  member __.Record fact =
    match functionStack.TryPeek () with
    | true, funcAddr ->
      match history.TryGetValue funcAddr with
      | true, stack -> stack.Push fact
      | false, _ ->
        let stack = Stack()
        stack.Push fact
        history[funcAddr] <- stack
    | false, _ -> ()

  /// Peek the history of the current function.
  member __.PeekFunctionHistory fnAddr =
    let arr =
      match history.TryGetValue fnAddr with
      | true, stack ->
        history[fnAddr] <- Stack ()
        stack |> Seq.toArray
      | false, _ -> [||]
    Array.append arr [| CreatedFunction (fnAddr) |]

#if CFGDEBUG
  /// Debug print the history.
  member __.DebugPrint () =
    match functionStack.TryPeek () with
    | true, funcAddr ->
      match history.TryGetValue funcAddr with
      | true, stack ->
        stack |> Seq.iter (fun fact ->
          HistoricalFact.toString fact
          |> dbglog (nameof HistoryManager) "%s")
      | false, _ -> ()
    | false, _ -> ()
#endif
