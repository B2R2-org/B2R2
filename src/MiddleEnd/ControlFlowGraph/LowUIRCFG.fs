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

open System.Collections.Generic
open B2R2
open B2R2.MiddleEnd.BinGraph

/// CFG where each node is an IR-level basic block. This is the main data
/// structure that we use to represent the control flow graph of a function.
/// This is essentially a wrapper class of `IMutableDiGraph<LowUIRBasicBlock,
/// CFGEdgeKind>`, which provides a uniform interface for both mutable and
/// persistent graphs.
type LowUIRCFG private(g: IMutableDiGraph<LowUIRBasicBlock, CFGEdgeKind>) =

  // FIXME: use this to later to remove dictionary from CFGBuildingContext.
  // let vertexCache = Dictionary<ProgramPoint, IVertex<LowUIRBasicBlock>>()

  /// Creates an empty graph of the given implementation type.
  static let empty t =
    match t with
    | Mutable ->
      MutableDiGraph<LowUIRBasicBlock, CFGEdgeKind>() :> IMutableDiGraph<_, _>
    | Persistent ->
      let g = PersistentDiGraph<LowUIRBasicBlock, CFGEdgeKind>()
      MutablePersistentDiGraph g :> IMutableDiGraph<_, _>

  /// Creates an empty persistent CFG.
  new() = LowUIRCFG(empty Persistent)

  /// Creates a new CFG with the given implementation type.
  new(t: ImplementationType) = LowUIRCFG(empty t)

  /// Number of vertices.
  member _.VertexCount with get() = g.VertexCount

  /// Number of edges.
  member _.EdgeCount with get() = g.EdgeCount

  /// Get an array of all vertices in this CFG.
  member _.Vertices with get() = g.Vertices

  /// Get an array of all edges in this CFG.
  member _.Edges with get() = g.Edges

  /// Get an array of exit vertices in this CFG.
  member _.Exits with get() = g.Exits

  /// <summary>
  /// Get exactly one root vertex of this CFG.
  /// </summary>
  /// <exception cref='T:B2R2.MiddleEnd.BinGraph.NoRootVertexException'>
  /// Thrown when this CFG has no root vertex.
  /// </exception>
  /// <exception
  ///   cref='T:B2R2.MiddleEnd.BinGraph.MultipleRootVerticesException'>
  /// Thrown when this CFG has more than one root vertex.
  /// </exception>
  member _.SingleRoot with get() = g.SingleRoot

  /// Get the root vertices of this CFG.
  member _.Roots with get() = g.Roots

  /// Get the implementation type of this CFG.
  member _.ImplementationType with get() = g.ImplementationType

  /// Is this empty? A CFG is empty when there is no vertex.
  member _.IsEmpty with get() = g.IsEmpty

  /// Add a vertex containing this BBL to this CFG, and return the added vertex.
  member _.AddVertex bbl = g.AddVertex bbl

  /// Remove the given vertex from this CFG.
  member _.RemoveVertex v = g.RemoveVertex v

  /// Check whether this very vertex belongs to this CFG.
  member _.Contains v = g.Contains v

  /// Find a vertex that satisfies the given predicate function.
  member _.FindVertex fn = g.FindVertexBy fn

  /// Find a vertex that satisfies the given predicate function. This function
  /// returns an Option type. If there is no such a vertex, it returns None.
  member _.TryFindVertex fn = g.TryFindVertexBy fn

  /// Add an edge between the given source and destination vertices.
  member _.AddEdge(src, dst) = g.AddEdge(src, dst)

  /// Add an edge between the given source and destination vertices with a
  /// label.
  member _.AddEdge(src, dst, label) = g.AddEdge(src, dst, label)

  /// Remove an edge between the given source and destination vertices.
  member _.RemoveEdge(src, dst) = g.RemoveEdge(src, dst)

  /// Remove the given edge from this CFG.
  member _.RemoveEdge edge = g.RemoveEdge edge

  /// Find an edge between the given source and destination vertices.
  member _.FindEdge(src, dst) = g.FindEdge(src, dst)

  /// Find an edge between the given source and destination vertices. This
  /// function returns an Option type. If there is no such an edge, it returns
  /// None.
  member _.TryFindEdge(src, dst) = g.TryFindEdge(src, dst)

  /// Get the predecessors of the given vertex.
  member _.GetPreds v = g.GetPreds v

  /// Get the predecessor edges of the given vertex.
  member _.GetPredEdges v = g.GetPredEdges v

  /// Get the successors of the given vertex.
  member _.GetSuccs v = g.GetSuccs v

  /// Get the successor edges of the given vertex.
  member _.GetSuccEdges v = g.GetSuccEdges v

  /// Add a root vertex to this CFG.
  member _.AddRoot v = g.AddRoot v

  /// Set root vertices of this CFG.
  member _.SetRoots vs = g.SetRoots vs

  interface IDiGraph<LowUIRBasicBlock, CFGEdgeKind> with
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
    member _.HasEdge(src, vid) = g.HasEdge(src, vid)
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

  interface IMutableDiGraph<LowUIRBasicBlock, CFGEdgeKind> with
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
