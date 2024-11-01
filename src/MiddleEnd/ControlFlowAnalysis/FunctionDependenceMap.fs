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

  let addTGDependency (caller: IVertex<Addr>) (callee: IVertex<Addr>) =
    if caller = callee then () (* skip recursive call *)
    else
#if CFGDEBUG
      dbglog ManagerTid "AddTGDependency"
      <| $"{caller.VData:x} -> {callee.VData:x}"
#endif
      tg.AddEdge (caller, callee) |> ignore

  let addCGDependency (caller: IVertex<Addr>) (callee: IVertex<Addr>) =
    if caller = callee then () (* skip recursive call *)
    else
#if CFGDEBUG
      dbglog ManagerTid "AddCGDependency"
      <| $"{caller.VData:x} -> {callee.VData:x}"
#endif
      cg.AddEdge (caller, callee) |> ignore

  let removeTGVertex (v: IVertex<Addr>) =
#if CFGDEBUG
    dbglog ManagerTid "RemoveTGVertex" $"{v.VData:x}"
#endif
    tgVertices.Remove v.VData |> ignore
    tg.RemoveVertex v |> ignore

  let removeCGVertex (v: IVertex<Addr>) =
#if CFGDEBUG
    dbglog ManagerTid "RemoveCGVertex" $"{v.VData:x}"
#endif
    cgVertices.Remove v.VData |> ignore
    cg.RemoveVertex v |> ignore

  let filterOutNonRecursiveCallers calleeAddr callers =
    callers
    |> Array.choose (fun (v: IVertex<Addr>) ->
      if v.VData <> calleeAddr then Some v.VData else None)

  /// Add a dependency between two functions. When the third parameter is true,
  /// we only update the temporary graph, and when it is false, we update the
  /// call graph.
  member _.AddDependency (caller, callee, isTemp) =
    if isTemp then addTGDependency (getTGVertex caller) (getTGVertex callee)
    else addCGDependency (getCGVertex caller) (getCGVertex callee)

  /// Update the call graph by adding the dependencies between the callee and
  /// the callers, and return the given callers as is. This will only update the
  /// call graph.
  member _.AddResolvedDependencies callee callers =
    let calleeV = getCGVertex callee
    callers
    |> Array.iter (fun caller ->
      let callerV = getCGVertex caller
      addCGDependency callerV calleeV)
    callers

  /// Remove a function from the dependence map and return the immediate
  /// callers' addresses of the function excluding the recursive calls. When the
  /// second parameter is true, we remove the function from the temporary graph,
  /// and when it is false, we remove the function from the call graph.
  member _.RemoveFunctionAndGetDependentAddrs callee isTemp =
    if isTemp then
      let calleeV = getTGVertex callee
      let preds = tg.GetPreds calleeV
      removeTGVertex calleeV
      preds |> filterOutNonRecursiveCallers callee
    else
      let calleeV = getCGVertex callee
      let preds = cg.GetPreds calleeV
      removeCGVertex calleeV
      preds |> filterOutNonRecursiveCallers callee

  /// Get the immediate **confirmed** caller functions of the given callee from
  /// the call graph, but excluding the recursive calls.
  member _.GetConfirmedCallers (callee: Addr) =
    let calleeV = getCGVertex callee
    let preds = cg.GetPreds calleeV
    preds |> filterOutNonRecursiveCallers callee

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
