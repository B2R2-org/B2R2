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
  let g = ImperativeDiGraph<Addr, unit> () :> IGraph<Addr, unit>

  let vertices = Dictionary<Addr, IVertex<Addr>> ()

  let getVertex addr =
    match vertices.TryGetValue addr with
    | true, v -> v
    | false, _ ->
      let v, _ = g.AddVertex addr
      vertices[addr] <- v
      v

  /// Add a dependency between two functions.
  member _.AddDependency (caller: Addr, callee: Addr) =
    let callerV = getVertex caller
    let calleeV = getVertex callee
    g.AddEdge (callerV, calleeV) |> ignore

  /// Remove a callee function from the map, and return its immediate caller
  /// functions, excluding the recursive calls.
  member _.RemoveAndGetCallers (callee: Addr) =
    let calleeV = getVertex callee
    let preds = g.GetPreds calleeV
    vertices.Remove callee |> ignore
    g.RemoveVertex calleeV |> ignore
    preds
    |> Seq.choose (fun v ->
      if v.VData <> callee then Some v.VData else None)
    |> Seq.toList

  /// Get the immediate caller functions of the given callee, but excluding the
  /// recursive calls.
  member _.GetCallers (callee: Addr) =
    let calleeV = getVertex callee
    let preds = g.GetPreds calleeV
    preds
    |> Seq.choose (fun v ->
      if v.VData <> callee then Some v.VData else None)
    |> Seq.toList

  /// Return an array of sets of mutually recurive nodes in the current
  /// dependence graph.
  member _.GetCyclicDependencies () =
    SCC.compute g
    |> Array.choose (fun scc ->
      if scc.Count > 1 then
        let arr = Array.zeroCreate scc.Count
        let mutable i = 0
        for v in scc do arr[i] <- v.VData; i <- i + 1 done
        Some arr
      else None)
