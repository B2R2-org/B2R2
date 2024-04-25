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

namespace B2R2.MiddleEnd

open System.Collections.Generic
open B2R2
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis

/// A lens that converts a BinaryBrew to a CallCFG.
[<RequireQualifiedAccess>]
module CallGraph =
  /// A mapping from an addrbrew to a CallCFG vertex.
  type private CallVMap = Dictionary<Addr, IVertex<CallBlock>>

  let private getVertex (brew: BinaryBrew<_, _, _, _, _>) vMap addr g =
    match (vMap: CallVMap).TryGetValue addr with
    | false, _ ->
      let fn = brew.Functions[addr]
      let name = fn.Name
      // let ext = fn.FunctionKind <> FunctionKind.Regular
      let blk = CallBlock (addr, name, false)
      let v, g = (g: IGraph<_, _>).AddVertex blk
      vMap.Add (addr, v)
      v, g
    | true, v -> v, g

  let private addEdge brew vMap entryPoint target callCFG =
    let src, callCFG = getVertex brew vMap entryPoint callCFG
    let dst, callCFG = getVertex brew vMap target callCFG
    callCFG.AddEdge (src, dst, CallEdge)

  let private buildCG callCFG vMap (brew: BinaryBrew<_, _, _, _, _>) =
    brew.Functions.Sequence
    |> Seq.fold (fun callCFG func ->
      func.Callees
      |> Seq.fold (fun callCFG (KeyValue (_, callee)) ->
        match callee with
        | RegularCallee target ->
          addEdge brew vMap func.EntryPoint target callCFG
        | IndirectCallees targets ->
          targets
          |> Set.fold (fun callCFG target ->
            addEdge brew vMap func.EntryPoint target callCFG
          ) callCFG
        | SyscallCallee _
        | UnresolvedIndirectCallees
        | NullCallee -> callCFG
      ) callCFG) callCFG

  /// Create a CallCFG from a BinaryBrew.
  [<CompiledName "Create">]
  let create implType brew =
    let callGraph =
      match implType with
      | Imperative ->
        ImperativeDiGraph<CallBlock, CFGEdgeKind> () :> CallCFG<_>
      | Persistent ->
        PersistentDiGraph<CallBlock, CFGEdgeKind> () :> CallCFG<_>
    let vMap = CallVMap ()
    let callGraph = buildCG callGraph vMap brew
    callGraph, callGraph.Unreachables |> Array.toList
