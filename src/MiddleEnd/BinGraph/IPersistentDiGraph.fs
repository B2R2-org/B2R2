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

/// Represents an immutable directed graph. Every modification leaves this
/// graph untouched and returns a new one, as opposed to `IMutableDiGraph`,
/// which modifies the graph in place. Thus, the returned graph is the one to
/// use afterwards; the graph this modification was asked of remains a valid
/// snapshot of the state before it.
type IPersistentDiGraph<'V, 'E when 'V: equality and 'E: equality> =
  inherit IDiGraph<'V, 'E>

  /// Adds a vertex to the graph using a data value, and returns a reference to
  /// the added vertex along with the resulting graph.
  abstract AddVertex: data: 'V -> IVertex<'V> * IPersistentDiGraph<'V, 'E>

  /// Adds a vertex to the graph using a data value and a vertex ID, and returns
  /// a reference to the added vertex along with the resulting graph. This
  /// function assumes that the vertex ID is unique in the graph, thus it needs
  /// to be used with caution. It raises `ArgumentException` for -1, an ID this
  /// package keeps for itself.
  abstract AddVertex:
    data: 'V * vid: VertexID -> IVertex<'V> * IPersistentDiGraph<'V, 'E>

  /// Adds a vertex to the graph without any data attached to it.
  abstract AddVertex: unit -> IVertex<'V> * IPersistentDiGraph<'V, 'E>

  /// Adds a copy of the given vertex, which may come from another graph, to
  /// this graph. The copy keeps the ID of the given vertex as well as the
  /// absence of its data, which is what copying a graph requires. This
  /// function assumes that the vertex ID is unique in the graph, thus it
  /// needs to be used with caution. It raises `ArgumentException` when the
  /// vertex carries -1, an ID this package keeps for itself.
  abstract AddVertexCopy:
    v: IVertex<'V> -> IVertex<'V> * IPersistentDiGraph<'V, 'E>

  /// Removes the given vertex from the graph. This raises
  /// `VertexNotFoundException` when the given vertex is not in the graph.
  abstract RemoveVertex: IVertex<'V> -> IPersistentDiGraph<'V, 'E>

  /// Adds an edge from src to dst. A graph holds at most one edge for an
  /// ordered pair of vertices, so this returns an equivalent graph when such an
  /// edge is already there. This raises `VertexNotFoundException` when either
  /// src or dst is not in the graph.
  abstract AddEdge:
    src: IVertex<'V> * dst: IVertex<'V> -> IPersistentDiGraph<'V, 'E>

  /// Adds an edge from src to dst with the given label. A graph holds at most
  /// one edge for an ordered pair of vertices, so this returns an equivalent
  /// graph when such an edge is already there, which means the label of the
  /// existing edge is the one that stays. This raises
  /// `VertexNotFoundException` when either src or dst is not in the graph.
  abstract AddEdge:
    src: IVertex<'V> * dst: IVertex<'V> * label: 'E
      -> IPersistentDiGraph<'V, 'E>

  /// Removes the edge that spans from src to dst. This raises
  /// `VertexNotFoundException` when either src or dst is not in the graph.
  abstract RemoveEdge:
    src: IVertex<'V> * dst: IVertex<'V> -> IPersistentDiGraph<'V, 'E>

  /// Removes the edge that spans the endpoints of the given edge, which only
  /// names the pair: neither its label nor the edge object itself takes any
  /// part, so a freshly made edge naming a pair of this graph's own vertices
  /// does. This raises `VertexNotFoundException` when either endpoint is not
  /// in the graph.
  abstract RemoveEdge: edge: Edge<'V, 'E> -> IPersistentDiGraph<'V, 'E>

  /// Adds a root vertex to this graph explicitly. `AddVertex` will
  /// automatically set the root vertex to the first vertex added to the graph,
  /// but this function allows the user to add root vertices explicitly. This
  /// raises `VertexNotFoundException` when the given vertex is not in the
  /// graph.
  abstract AddRoot: IVertex<'V> -> IPersistentDiGraph<'V, 'E>

  /// Sets root vertices for this graph. `AddVertex` will automatically set the
  /// root vertex to the first vertex added to the graph, but this function
  /// allows the user to set root vertices explicitly. This raises
  /// `VertexNotFoundException` when any of the given vertices is not in the
  /// graph, and leaves the current roots untouched in that case.
  abstract SetRoots:
    IEnumerable<IVertex<'V>> -> IPersistentDiGraph<'V, 'E>
