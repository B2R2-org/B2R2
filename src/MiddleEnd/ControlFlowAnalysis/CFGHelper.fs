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

[<AutoOpen>]
module internal B2R2.MiddleEnd.ControlFlowAnalysis.CFGHelper

open B2R2.MiddleEnd.BinGraph

#if CFGDEBUG
open System.IO

[<AutoOpen>]
module internal Dbg =
  let logger =
    let path = Path.Combine (Directory.GetCurrentDirectory (), "cfg.log")
    new FileLogger (path) :> ILogger

  let inline dbglog (locationName: string) fmt =
    let after str = logger.LogLine (locationName.PadRight 20 + "| " + str)
    Printf.ksprintf after fmt
#endif

/// Categorize neighboring edges of a given vertex (v) in the graph (g). This
/// function returns three different groups of edges: (1) incoming edges, (2)
/// outgoing edges, and (3) self-cycle edge.
let categorizeNeighboringEdges (g: IGraph<_, _>) v =
  let incomings, cycle =
    g.GetPreds v
    |> Seq.fold (fun (incomings, cycle) p ->
      let e = g.FindEdge (p, v)
      if p.ID = v.ID then incomings, Some e.Label
      else (p, e.Label) :: incomings, cycle) ([], None)
  let outgoings =
    g.GetSuccs v
    |> Seq.fold (fun outgoings s ->
      let e = g.FindEdge (v, s)
      if s.ID = v.ID then outgoings else (s, e.Label) :: outgoings) []
  incomings, outgoings, cycle

/// Get reachable vertices and edges from v in g.
let getReachables g v =
  let reachables =
    Set.empty |> Traversal.foldPostorder g [v] (fun acc v -> Set.add v acc)
  let edges = (* Collect corresponding edges. *)
    g.FoldEdge (fun acc e ->
      let src, dst = e.First, e.Second
      (* Collect only when both src and dst belong to vertices. *)
      if Set.contains src reachables && Set.contains dst reachables then
        (src, dst, e.Label) :: acc
      else acc) []
  reachables, edges
