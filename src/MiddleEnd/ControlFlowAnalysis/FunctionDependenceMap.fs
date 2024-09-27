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
open B2R2.MiddleEnd.BinGraph

/// Map from a function (callee) to its caller functions. This is not
/// thread-safe, and thus should be used only by TaskManager.
type FunctionDependenceMap () =
  /// A temporary graph that only contains unconfirmed edges.
  let tg = ImperativeDiGraph<Addr, unit> () :> IGraph<Addr, unit>

  /// Vertices in the temporary graph.
  let tgVertices = Dictionary<Addr, IVertex<Addr>> ()

  /// A complete inter-procedural call graph.
  let cg = ImperativeDiGraph<Addr, uint> () :> IGraph<Addr, uint>

  /// Vertices in the call graph.
  let cgVertices = Dictionary<Addr, IVertex<Addr>> ()

  let getTGVertex addr =
    match tgVertices.TryGetValue addr with
    | true, v -> v
    | false, _ ->
      let v, _ = tg.AddVertex addr
      tgVertices[addr] <- v
      v

  let getCGVertex addr =
    match cgVertices.TryGetValue addr with
    | true, v -> v
    | false, _ ->
      let v, _ = cg.AddVertex addr
      cgVertices[addr] <- v
      v

  let addResolvedDependency callee callers =
    let calleeV = getCGVertex callee
    callers
    |> Array.iter (fun caller ->
      let callerV = getCGVertex caller
      cg.AddEdge (callerV, calleeV) |> ignore)

  /// Add a dependency between two functions.
  member _.AddDependency (caller: Addr, callee: Addr) =
    if caller = callee then () (* skip recursive call *)
    else
      let callerV = getTGVertex caller
      let calleeV = getTGVertex callee
#if CFGDEBUG
      dbglog ManagerTid (nameof AddDependency) $"{caller:x} -> {callee:x}"
#endif
      tg.AddEdge (callerV, calleeV) |> ignore

  /// Mark a function as completed and returns the immediate callers of the
  /// function excluding the recursive calls. This means we remove the function
  /// from the temporary dependence graph. We also update the call graph only if
  /// `isSuccessful` is true.
  member _.MarkComplete (callee: Addr) isSuccessful =
    let calleeV = getTGVertex callee
    let preds = tg.GetPreds calleeV
    tgVertices.Remove callee |> ignore
    tg.RemoveVertex calleeV |> ignore
    let callers =
      preds
      |> Array.choose (fun v ->
        if v.VData <> callee then Some v.VData else None)
    if isSuccessful then addResolvedDependency callee callers else ()
    callers

  /// Get the immediate **confirmed** caller functions of the given callee from
  /// the call graph, but excluding the recursive calls.
  member _.GetConfirmedCallers (callee: Addr) =
    let calleeV = getCGVertex callee
    let preds = cg.GetPreds calleeV
    preds
    |> Array.choose (fun v ->
      if v.VData <> callee then Some v.VData else None)

  /// Return an array of sets of mutually recurive nodes in the temporary
  /// dependence graph.
  member _.GetCyclicDependencies () =
    SCC.compute tg
    |> Array.choose (fun scc ->
      if scc.Count > 1 then
        let arr = Array.zeroCreate scc.Count
        let mutable i = 0
        for v in scc do arr[i] <- v.VData; i <- i + 1 done
        Some arr
      else None)
