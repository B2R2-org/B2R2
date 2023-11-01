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

namespace B2R2.MiddleEnd.BinGraph

open System.Collections.Generic

/// General graph data type. This one can be either directed or undirected.
type IGraph<'V, 'E when 'V: equality and 'E: equality> =
  /// Is this empty? A graph is empty when there is no vertex in the graph.
  abstract IsEmpty: unit -> bool

  /// Number of vertices.
  abstract Size: int

  /// Get an array of all vertices in the graph.
  abstract Vertices: IVertex<'V>[]

  /// Get an array of all edges in the graph.
  abstract Edges: Edge<'V, 'E>[]

  /// Get a collection of unreachable vertices in the graph.
  abstract Unreachables: IVertex<'V>[]

  /// Get an array of exit vertices in the graph. This is always empty for
  /// undirected graphs.
  abstract Exits: IVertex<'V>[]

  /// Get the implementation type of this graph.
  abstract ImplementationType: ImplementationType

  /// Add a vertex to the graph using a data value, and return a reference to
  /// the added vertex.
  abstract AddVertex: data: 'V -> IVertex<'V> * IGraph<'V, 'E>

  /// Add a vertex to the grpah without any data attached to it.
  abstract AddVertex: unit -> IVertex<'V> * IGraph<'V, 'E>

  /// Remove the given vertex from the graph.
  abstract RemoveVertex: IVertex<'V> -> IGraph<'V, 'E>

  /// Check the existence of the given vertex from the graph.
  abstract HasVertex: VertexID -> bool

  /// Find a vertex by its VertexID. This function raises an exception when
  /// there is no such a vertex.
  abstract FindVertexByID: VertexID -> IVertex<'V>

  /// Find a vertex by its VertexID. This function returns an Option type.
  abstract TryFindVertexByID: VertexID -> IVertex<'V> option

  /// Find a vertex that has the given data value from the graph. It will raise
  /// an exception if such a vertex does not exist. Note that this function
  /// should be used only when one knows each vertex in the graph has a unique
  /// data value.
  abstract FindVertexByData: 'V -> IVertex<'V>

  /// Find a vertex that has the given VertexData from the graph. This function
  /// does not raise an exception unlike FindVertexByData.
  abstract TryFindVertexByData: 'V -> IVertex<'V> option

  /// Find a vertex by the given function. This function returns the first
  /// element, in which the function returns true. When there is no such an
  /// element, the function raises an exception.
  abstract FindVertexBy: (IVertex<'V> -> bool) -> IVertex<'V>

  /// Find a vertex by the given function without raising an exception.
  abstract TryFindVertexBy: (IVertex<'V> -> bool) -> IVertex<'V> option

  /// Add an edge between src and dst. If this is a directed graph, add an edge
  /// from src to dst.
  abstract AddEdge: src: IVertex<'V> * dst: IVertex<'V> -> IGraph<'V, 'E>

  /// Add an edge from src to dst with the given label. If this is a directed
  /// graph, add an edge from src to dst.
  abstract AddEdge:
    src: IVertex<'V> * dst: IVertex<'V> * label: 'E -> IGraph<'V, 'E>

  /// Remove the edge that spans between src and dst. If this is a directed
  /// graph, remove the edge from src to dst.
  abstract RemoveEdge: src: IVertex<'V> * dst: IVertex<'V> -> IGraph<'V, 'E>

  /// Remove the given edge from the graph. The input edge does not need to have
  /// the same label as the one in the graph; we only check the source and
  /// destination vertices to perform this operation.
  abstract RemoveEdge: edge: Edge<'V, 'E> -> IGraph<'V, 'E>

  /// Find the edge between src and dst. If this is a directed graph, find the
  /// edge from src to dst. If this is an undirected graph, find the edge that
  /// spans between src and dst.
  abstract FindEdge: src: IVertex<'V> * dst: IVertex<'V> -> Edge<'V, 'E>

  /// Find the edge between src and dst. If this is a directed graph, find the
  /// edge from src to dst. If this is an undirected graph, find the edge that
  /// spans between src and dst.
  abstract TryFindEdge:
    src: IVertex<'V> * dst: IVertex<'V> -> Edge<'V, 'E> option

  /// Get the predecessors of the given vertex. This is only meaningful for
  /// directed graphs. For undirected graphs, this function returns an empty
  /// sequence.
  abstract GetPreds: IVertex<'V> -> IReadOnlyCollection<IVertex<'V>>

  /// Get the successors of the given vertex. This is only meaningful for
  /// directed graphs. For undirected graphs, this function returns an empty
  /// sequence.
  abstract GetSuccs: IVertex<'V> -> IReadOnlyCollection<IVertex<'V>>

  /// Fold every vertex (the order can be arbitrary).
  abstract FoldVertex: ('a -> IVertex<'V> -> 'a) -> 'a -> 'a

  /// Iterate every vertex (the order can be arbitrary).
  abstract IterVertex: (IVertex<'V> -> unit) -> unit

  /// Fold every edge in the graph (the order can be arbitrary).
  abstract FoldEdge: ('a -> Edge<'V, 'E> -> 'a) -> 'a -> 'a

  /// Fold every edge in the graph (the order can be arbitrary).
  abstract IterEdge: (Edge<'V, 'E> -> unit) -> unit

  /// Return a subgraph that contains only the set of vertices.
  abstract SubGraph: Set<IVertex<'V>> -> IGraph<'V, 'E>

  /// Return a new transposed (i.e., reversed) graph. This will return the same
  /// graph if this is an undirected graph.
  abstract Reverse: unit -> IGraph<'V, 'E>

  /// Return a cloned copy of this graph.
  abstract Clone: unit -> IGraph<'V, 'E>

  /// Return the DOT-representation of this graph. The first argument specifies
  /// the name of the graph. The second argument specifies the callback function
  /// that returns the id and label of a vertex. The third argument specifies
  /// the callback function that returns the label of an edge.
  abstract ToDOTStr:
       name: string
     * vFn: (IVertex<'V> -> (string * string))
     * eFn: (Edge<'V, 'E> -> string)
    -> string