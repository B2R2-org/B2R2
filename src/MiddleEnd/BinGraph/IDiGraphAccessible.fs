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

/// Represents a read-only directed graph information accessor. This interface
/// provides a way to access the information of a directed graph without
/// modifying it.
type IDiGraphAccessible<'V, 'E when 'V: equality and 'E: equality> =
  /// Gets the number of vertices.
  abstract Size: int

  /// Gets an array of all vertices in the graph.
  abstract Vertices: IVertex<'V>[]

  /// Gets an array of all edges in the graph.
  abstract Edges: Edge<'V, 'E>[]

  /// Gets an array of exit vertices in the graph.
  abstract Exits: IVertex<'V>[]

  /// <summary>
  /// Gets exactly one root vertex of this graph.
  /// </summary>
  /// <exception cref='T:B2R2.MiddleEnd.BinGraph.NoRootVertexException'>
  /// Thrown when this graph has no root vertex.
  /// </exception>
  /// <exception
  ///   cref='T:B2R2.MiddleEnd.BinGraph.MultipleRootVerticesException'>
  /// Thrown when this graph has more than one root vertex.
  /// </exception>
  abstract SingleRoot: IVertex<'V>

  /// Gets the implementation type of this graph.
  abstract ImplementationType: ImplementationType

  /// Checks if this graph is empty. A graph is empty when there is no vertex in
  /// the graph.
  abstract IsEmpty: unit -> bool

  /// Checks the existence of the given vertex from the graph.
  abstract HasVertex: VertexID -> bool

  /// Checks the existence of the given edge from the graph.
  abstract HasEdge: src: IVertex<'V> * dst: IVertex<'V> -> bool

  /// Finds a vertex by its VertexID. This function raises
  /// `VertexNotFoundException` when there is no such a vertex.
  abstract FindVertexByID: VertexID -> IVertex<'V>

  /// Finds a vertex by its VertexID. This function returns an Option type.
  abstract TryFindVertexByID: VertexID -> IVertex<'V> option

  /// Finds a vertex that has the given data value from the graph. It raises
  /// `VertexNotFoundException` if such a vertex does not exist. Note that this
  /// function should be used only when one knows each vertex in the graph has a
  /// unique data value.
  abstract FindVertexByData: 'V -> IVertex<'V>

  /// Finds a vertex that has the given VertexData from the graph. This function
  /// does not raise an exception unlike FindVertexByData.
  abstract TryFindVertexByData: 'V -> IVertex<'V> option

  /// Finds a vertex by the given function. This function returns the first
  /// element, in which the function returns true. When there is no such an
  /// element, the function raises `VertexNotFoundException`.
  abstract FindVertexBy: (IVertex<'V> -> bool) -> IVertex<'V>

  /// Finds a vertex by the given function without raising an exception.
  abstract TryFindVertexBy: (IVertex<'V> -> bool) -> IVertex<'V> option

  /// Finds the edge from src to dst. This function raises
  /// `EdgeNotFoundException` when there is no such an edge.
  abstract FindEdge: src: IVertex<'V> * dst: IVertex<'V> -> Edge<'V, 'E>

  /// Finds the edge from src to dst. This function returns an Option type.
  abstract TryFindEdge:
    src: IVertex<'V> * dst: IVertex<'V> -> Edge<'V, 'E> option

  /// Gets the predecessors of the given vertex. This returns an empty array
  /// when the given vertex does not belong to this graph.
  abstract GetPreds: IVertex<'V> -> IVertex<'V>[]

  /// Gets the predecessor edges of the given vertex. This returns an empty
  /// array when the given vertex does not belong to this graph.
  abstract GetPredEdges: IVertex<'V> -> Edge<'V, 'E>[]

  /// Gets the successors of the given vertex. This returns an empty array when
  /// the given vertex does not belong to this graph.
  abstract GetSuccs: IVertex<'V> -> IVertex<'V>[]

  /// Gets the successor edges of the given vertex. This returns an empty array
  /// when the given vertex does not belong to this graph.
  abstract GetSuccEdges: IVertex<'V> -> Edge<'V, 'E>[]

  /// Gets the root vertices of this graph. When there's no root, this will
  /// return an empty collection.
  abstract GetRoots: unit -> IVertex<'V>[]

  /// Folds every vertex (the order can be arbitrary).
  abstract FoldVertex: ('a -> IVertex<'V> -> 'a) * 'a -> 'a

  /// Iterates every vertex (the order can be arbitrary).
  abstract IterVertex: (IVertex<'V> -> unit) -> unit

  /// Folds every edge in the graph (the order can be arbitrary).
  abstract FoldEdge: ('a -> Edge<'V, 'E> -> 'a) * 'a -> 'a

  /// Iterates every edge in the graph (the order can be arbitrary).
  abstract IterEdge: (Edge<'V, 'E> -> unit) -> unit

  /// Returns a new transposed (i.e., reversed) graph. The given set of vertices
  /// will be used to set the root vertices of the transposed graph.
  abstract Reverse: IEnumerable<IVertex<'V>> -> IDiGraphAccessible<'V, 'E>
