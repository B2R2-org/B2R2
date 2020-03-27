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

namespace B2R2.DataFlow

open B2R2
open B2R2.BinGraph
open System.Collections.Generic

/// Defined variable.
type VarExpr =
  | Regular of RegisterID
  | Temporary of int

/// Program point of a defined variable.
type VarPoint = {
  ProgramPoint: ProgramPoint
  VarExpr: VarExpr
}

/// Either forward or backward analysis.
type DataFlowDirection =
  | Forward
  | Backward

/// Data-flow analysis framework.
[<AbstractClass>]
type DataFlowAnalysis<'V when 'V: equality> (direction) =
  /// Exit lattice per vertex.
  let outs = Dictionary<VertexID, 'V> ()

  /// Entry lattice per vertex.
  let ins = Dictionary<VertexID, 'V> ()

  /// Neighboring vertices to compute dataflow. This is dependent on the
  /// direction of the analysis.
  let neighbor =
    match direction with
    | Forward -> fun (v: Vertex<IRBasicBlock>) -> v.Preds
    | Backward -> fun (v: Vertex<IRBasicBlock>) -> v.Succs

  /// Expand the worklist depending on the direction of the analysis.
  let addToWorklist =
    match direction with
    | Forward ->
      fun (worklist: Queue<Vertex<IRBasicBlock>>) (v: Vertex<IRBasicBlock>) ->
        v.Succs |> List.iter worklist.Enqueue
    | Backward ->
      fun (worklist: Queue<Vertex<IRBasicBlock>>) (v: Vertex<IRBasicBlock>) ->
        v.Preds |> List.iter worklist.Enqueue

  /// Meet operation of the lattice.
  abstract Meet: 'V -> 'V -> 'V

  /// The bottom of the lattice.
  abstract Bottom: 'V

  /// The initial worklist queue. This should be a topologically sorted list to
  /// be efficient.
  abstract Worklist: Vertex<IRBasicBlock> -> Queue<Vertex<IRBasicBlock>>

  /// The transfer function from an input lattice to an output lattice. The
  /// second parameter is to specify the current block of interest.
  abstract Transfer: 'V -> Vertex<IRBasicBlock> -> 'V

  member private __.InitInsOuts (root: Vertex<IRBasicBlock>) =
    Traversal.iterPreorder root (fun v ->
      let blkid = v.GetID ()
      outs.[blkid] <- __.Bottom
      ins.[blkid] <- __.Bottom)

  /// Compute data-flow with the iterative worklist algorithm.
  member __.Compute (root: Vertex<IRBasicBlock>) =
    __.InitInsOuts root
    let worklist = __.Worklist root
    while worklist.Count <> 0 do
      let blk = worklist.Dequeue ()
      let blkid = blk.GetID ()
      ins.[blkid] <-
        neighbor blk
        |> List.fold (fun eff v -> __.Meet eff outs.[v.GetID()]) __.Bottom
      let outeffect = __.Transfer ins.[blkid] blk
      if outs.[blkid] <> outeffect then
        outs.[blkid] <- outeffect
        addToWorklist worklist blk
      else ()
    ins, outs
