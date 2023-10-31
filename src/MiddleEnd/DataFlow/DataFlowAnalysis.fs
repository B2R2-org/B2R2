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
type VarPoint<'E> = {
  ProgramPoint: ProgramPoint
  VarExpr: 'E
}

/// Either forward or backward analysis.
type DataFlowDirection =
  | Forward
  | Backward

[<AbstractClass>]
type DataFlowHelper () =
  /// Obtain the neighboring vertices.
  abstract Neighbor:
    IGraph<'V, 'E> -> IVertex<'V> -> IReadOnlyCollection<IVertex<'V>>

  /// Add next vertices to the worklist queue.
  abstract AddToWorkList:
    IGraph<'V, 'E> -> IVertex<'V> -> Queue<IVertex<'V>> -> unit

type private ForwardDataFlowHelper () =
  inherit DataFlowHelper ()
  override __.Neighbor (g: IGraph<_, _>) v = g.GetPreds v
  override __.AddToWorkList (g: IGraph<_, _>) v worklist =
    g.GetSuccs v |> Seq.iter worklist.Enqueue

type BackwardDataFlowHelper () =
  inherit DataFlowHelper ()
  override __.Neighbor (g: IGraph<_, _>) v = g.GetSuccs v
  override __.AddToWorkList (g: IGraph<_, _>) v worklist =
    g.GetPreds v |> Seq.iter worklist.Enqueue

/// Data-flow analysis framework. 'L is a lattice, 'V is a vertex data type of a
/// graph.
[<AbstractClass>]
type DataFlowAnalysis<'L, 'V when 'L: equality
                              and 'V: equality> () =
  /// The top of the lattice. A data-flow analysis solution is computed by
  /// iterating down from top to bottom.
  abstract Top: 'L

/// Classic data-flow analysis with topological worklist algorithm.
[<AbstractClass>]
type TopologicalDataFlowAnalysis<'L, 'V
    when 'L: equality and 'V: equality> (direction) =
  inherit DataFlowAnalysis<'L, 'V> ()
  /// Exit lattice per vertex.
  let outs = Dictionary<VertexID, 'L> ()

  /// Entry lattice per vertex.
  let ins = Dictionary<VertexID, 'L> ()

  /// Accessor of the vertices to compute dataflow. This is dependent on the
  /// direction of the analysis.
  let helper =
    match direction with
    | Forward -> ForwardDataFlowHelper () :> DataFlowHelper
    | Backward -> BackwardDataFlowHelper () :> DataFlowHelper

  /// Initialize worklist queue. This should be a topologically sorted list to
  /// be efficient.
  let initWorklist g (root: IVertex<'V>) =
    let q = Queue<IVertex<'V>> ()
    Traversal.iterRevPostorder g [root] q.Enqueue
    q

  /// Meet operation of the lattice.
  abstract Meet: 'L -> 'L -> 'L

  /// The transfer function from an input lattice to an output lattice. The
  /// second parameter is to specify the current block of interest.
  abstract Transfer: 'L -> IVertex<'V> -> 'L

  /// Initialize ints and outs.
  member private __.InitInsOuts g (root: IVertex<'V>) =
    Traversal.iterPreorder g [root] (fun v ->
      let blkid = v.ID
      outs[blkid] <- __.Top
      ins[blkid] <- __.Top)

  /// Compute data-flow with the iterative worklist algorithm.
  member __.Compute g (root: IVertex<'V>) =
    __.InitInsOuts g root
    let worklist = initWorklist g root
    while worklist.Count <> 0 do
      let blk = worklist.Dequeue ()
      let blkid = blk.ID
      ins[blkid] <-
        helper.Neighbor g blk
        |> Seq.fold (fun eff v -> __.Meet eff outs[v.ID]) __.Top
      let outeffect = __.Transfer ins[blkid] blk
      if outs[blkid] <> outeffect then
        outs[blkid] <- outeffect
        helper.AddToWorkList g blk worklist
      else ()
    ins, outs
