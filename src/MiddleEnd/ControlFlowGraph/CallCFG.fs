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

namespace B2R2.MiddleEnd.ControlFlowGraph

open B2R2.MiddleEnd.BinGraph

/// Represents a call graph, where each node stands for a function. This is
/// essentially a wrapper class of `IMutableDiGraph<CallBasicBlock,
/// CFGEdgeKind>`, which provides a uniform interface for both mutable and
/// persistent graphs.
type CallCFG(t: ImplementationType) =
  let g =
    match t with
    | Mutable ->
      MutableDiGraph<CallBasicBlock, CFGEdgeKind>() :> IMutableDiGraph<_, _>
    | Persistent ->
      let g = PersistentDiGraph<CallBasicBlock, CFGEdgeKind>()
      MutablePersistentDiGraph g :> IMutableDiGraph<_, _>

  /// Gets the number of vertices.
  member _.VertexCount with get() = g.VertexCount

  /// Gets the number of edges.
  member _.EdgeCount with get() = g.EdgeCount

  /// Gets an array of all vertices in this CFG.
  member _.Vertices with get() = g.Vertices

  /// Gets an array of all edges in this CFG.
  member _.Edges with get() = g.Edges

  /// Gets an array of exit vertices in this CFG.
  member _.Exits with get() = g.Exits

  /// Gets the root vertices of this CFG.
  member _.Roots with get() = g.Roots

  /// Gets the implementation type of this CFG.
  member _.ImplementationType with get() = g.ImplementationType

  /// Checks if this CFG is empty. A CFG is empty when there is no vertex.
  member _.IsEmpty with get() = g.IsEmpty

  /// Adds a vertex containing the given BBL to this CFG, and returns the added
  /// vertex.
  member _.AddVertex blk = g.AddVertex blk

  /// Adds an edge between the given source and destination vertices with a
  /// label.
  member _.AddEdge(src, dst, label) = g.AddEdge(src, dst, label)

  interface IDiGraph<CallBasicBlock, CFGEdgeKind> with
    member _.VertexCount = g.VertexCount

    member _.EdgeCount = g.EdgeCount
    member _.Vertices = g.Vertices
    member _.Edges = g.Edges
    member _.Exits = g.Exits

    member _.Roots = g.Roots
    member _.SingleRoot = g.SingleRoot
    member _.ImplementationType = g.ImplementationType
    member _.IsEmpty with get() = g.IsEmpty
    member _.Contains v = g.Contains v
    member _.HasEdge(src, dst) = g.HasEdge(src, dst)
    member _.FindVertexByData vdata = g.FindVertexByData vdata
    member _.TryFindVertexByData vdata = g.TryFindVertexByData vdata
    member _.FindVertexBy fn = g.FindVertexBy fn
    member _.TryFindVertexBy fn = g.TryFindVertexBy fn
    member _.FindEdge(src, dst) = g.FindEdge(src, dst)
    member _.TryFindEdge(src, dst) = g.TryFindEdge(src, dst)
    member _.GetPreds v = g.GetPreds v
    member _.GetPredEdges v = g.GetPredEdges v
    member _.GetSuccs v = g.GetSuccs v
    member _.GetSuccEdges v = g.GetSuccEdges v

    member _.Reverse vs = g.Reverse vs

  interface IMutableDiGraph<CallBasicBlock, CFGEdgeKind> with
    member _.AddVertex data = g.AddVertex data
    member _.AddVertex(data, vid) = g.AddVertex(data, vid)
    member _.AddVertex() = g.AddVertex()
    member _.AddVertexCopy v = g.AddVertexCopy v
    member _.RemoveVertex v = g.RemoveVertex v
    member _.AddEdge(src, dst) = g.AddEdge(src, dst)
    member _.AddEdge(src, dst, label) = g.AddEdge(src, dst, label)
    member _.RemoveEdge(src, dst) = g.RemoveEdge(src, dst)
    member _.RemoveEdge edge = g.RemoveEdge edge
    member _.AddRoot v = g.AddRoot v
    member _.SetRoots vs = g.SetRoots vs

  interface ISCCEnumerable<CallBasicBlock> with
    member _.GetSCCEnumerator() = SCC.Tarjan.compute g
