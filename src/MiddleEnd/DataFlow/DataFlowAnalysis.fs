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

namespace B2R2.MiddleEnd.DataFlow

open B2R2
open B2R2.MiddleEnd.BinGraph
open System.Collections.Generic

/// Defined variable.
type VarExpr =
  | Regular of RegisterID
  | Temporary of int
  | Memory of Addr

/// Program point of a defined variable.
type VarPoint = {
  ProgramPoint: ProgramPoint
  VarExpr: VarExpr
}

/// Either forward or backward analysis.
type DataFlowDirection =
  | Forward
  | Backward

/// Data-flow analysis framework. 'L is a lattice, 'V is a vertex data type of a
/// graph.
[<AbstractClass>]
type DataFlowAnalysis<'L, 'V when 'L: equality
                              and 'V :> VertexData> () =
  /// The top of the lattice. A data-flow analysis solution is computed by
  /// iterating down from top to bottom.
  abstract Top: 'L

/// Classic data-flow analysis with topological worklist algorithm.
[<AbstractClass>]
type TopologicalDataFlowAnalysis<'L, 'V
    when 'L: equality
     and 'V :> VertexData and 'V : equality> (direction) =
  inherit DataFlowAnalysis<'L, 'V> ()

  /// Exit lattice per vertex.
  let outs = Dictionary<VertexID, 'L> ()

  /// Entry lattice per vertex.
  let ins = Dictionary<VertexID, 'L> ()

  /// Neighboring vertices to compute dataflow. This is dependent on the
  /// direction of the analysis.
  let neighbor g =
    match direction with
    | Forward -> fun (v: Vertex<'V>) -> DiGraph.getPreds g v
    | Backward -> fun (v: Vertex<'V>) -> DiGraph.getSuccs g v

  /// Expand the worklist depending on the direction of the analysis.
  let addToWorklist g =
    match direction with
    | Forward ->
      fun (worklist: Queue<Vertex<'V>>) (v: Vertex<'V>) ->
        DiGraph.getSuccs g v |> List.iter worklist.Enqueue
    | Backward ->
      fun (worklist: Queue<Vertex<'V>>) (v: Vertex<'V>) ->
        DiGraph.getPreds g v |> List.iter worklist.Enqueue

  /// Initialize worklist queue. This should be a topologically sorted list to
  /// be efficient.
  let initWorklist g (root: Vertex<'V>) =
    let q = Queue<Vertex<'V>> ()
    Traversal.iterRevPostorder g root q.Enqueue
    q

  /// Meet operation of the lattice.
  abstract Meet: 'L -> 'L -> 'L

  /// The transfer function from an input lattice to an output lattice. The
  /// second parameter is to specify the current block of interest.
  abstract Transfer: 'L -> Vertex<'V> -> 'L

  /// Initialize ints and outs.
  member private __.InitInsOuts g (root: Vertex<'V>) =
    Traversal.iterPreorder g root (fun v ->
      let blkid = v.GetID ()
      outs.[blkid] <- __.Top
      ins.[blkid] <- __.Top)

  /// Compute data-flow with the iterative worklist algorithm.
  member __.Compute g (root: Vertex<'V>) =
    __.InitInsOuts g root
    let worklist = initWorklist g root
    while worklist.Count <> 0 do
      let blk = worklist.Dequeue ()
      let blkid = blk.GetID ()
      ins.[blkid] <-
        neighbor g blk
        |> List.fold (fun eff v -> __.Meet eff outs.[v.GetID()]) __.Top
      let outeffect = __.Transfer ins.[blkid] blk
      if outs.[blkid] <> outeffect then
        outs.[blkid] <- outeffect
        addToWorklist g worklist blk
      else ()
    ins, outs
