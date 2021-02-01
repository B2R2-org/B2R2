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

namespace B2R2.MiddleEnd.BinEssence

open B2R2
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open System.Collections.Generic

/// A mapping from an address to a CallCFG vertex.
type CallVMap = Dictionary<Addr, CGVertex>

/// A graph lens for obtaining CallGraph.
module CallGraphLens =

  let private getVertex ess vMap entry g =
    match (vMap: CallVMap).TryGetValue entry with
    | false, _ ->
      let func = ess.CodeManager.FunctionMaintainer.Find entry
      let id = func.FunctionID
      let name = func.FunctionName
      let ext = func.FunctionKind <> FunctionKind.Regular
      let v, g =
        DiGraph.addVertex g (CallGraphBlock (entry, id, name, false, ext))
      vMap.Add (entry, v)
      v, g
    | true, v -> v, g

  let private addEdge ess vMap entry target callCFG =
    let src, callCFG = getVertex ess vMap entry callCFG
    let dst, callCFG = getVertex ess vMap target callCFG
    DiGraph.addEdge callCFG src dst CallEdge

  let private buildCG callCFG vMap ess =
    ess.CodeManager.FunctionMaintainer.RegularFunctions
    |> Seq.fold (fun callCFG func ->
      func.CallEdges
      |> Array.fold (fun callCFG (_, callee) ->
        match callee with
        | RegularCallee target -> addEdge ess vMap func.Entry target callCFG
        | IndirectCallees targets ->
          targets
          |> Set.fold (fun callCFG target ->
            addEdge ess vMap func.Entry target callCFG) callCFG
        | UnresolvedIndirectCallees (_) -> callCFG
      ) callCFG) callCFG

  let build ess =
    let vMap = CallVMap ()
    let callCFG = buildCG (CallCFG.init PersistentGraph) vMap ess
    callCFG, DiGraph.getUnreachables callCFG |> Seq.toList
