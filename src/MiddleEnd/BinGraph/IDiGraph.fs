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

/// Directed graph interface.
type IDiGraph<'V, 'E when 'V: equality and 'E: equality> =
  inherit IDiGraphAccessible<'V, 'E>

  /// Add a vertex to the graph using a data value, and return a reference to
  /// the added vertex.
  abstract AddVertex: data: 'V -> IVertex<'V> * IDiGraph<'V, 'E>

  /// Add a vertex to the graph using a data value and a vertex ID, and return a
  /// reference to the added vertex. This function assumes that the vertex ID is
  /// unique in the graph, thus it needs to be used with caution.
  abstract AddVertex: data: 'V * vid: VertexID -> IVertex<'V> * IDiGraph<'V, 'E>

  /// Add a vertex to the grpah without any data attached to it.
  abstract AddVertex: unit -> IVertex<'V> * IDiGraph<'V, 'E>

  /// Remove the given vertex from the graph.
  abstract RemoveVertex: IVertex<'V> -> IDiGraph<'V, 'E>

  /// Add an edge from src to dst.
  abstract AddEdge: src: IVertex<'V> * dst: IVertex<'V> -> IDiGraph<'V, 'E>

  /// Add an edge from src to dst with the given label.
  abstract AddEdge:
    src: IVertex<'V> * dst: IVertex<'V> * label: 'E -> IDiGraph<'V, 'E>

  /// Remove the edge that spans from src to dst.
  abstract RemoveEdge: src: IVertex<'V> * dst: IVertex<'V> -> IDiGraph<'V, 'E>

  /// Remove the given edge from the graph. The input edge does not need to have
  /// the same label as the one in the graph; we only check the source and
  /// destination vertices to perform this operation.
  abstract RemoveEdge: edge: Edge<'V, 'E> -> IDiGraph<'V, 'E>

  /// Explicitly add a root vertex to this graph. `AddVertex` will automatically
  /// set the root vertex to the first vertex added to the graph, but this
  /// function allows the user to add root vertices explicitly.
  abstract AddRoot: IVertex<'V> -> IDiGraph<'V, 'E>

  /// Set root vertices for this graph. `AddVertex` will automatically set the
  /// root vertex to the first vertex added to the graph, but this function
  /// allows the user to set root vertices explicitly.
  abstract SetRoots: IEnumerable<IVertex<'V>> -> IDiGraph<'V, 'E>

  /// Return a new transposed (i.e., reversed) graph. The given set of vertices
  /// will be used to set the root vertices of the transposed graph.
  abstract Reverse: IEnumerable<IVertex<'V>> -> IDiGraph<'V, 'E>

  /// Return a cloned copy of this graph.
  abstract Clone: unit -> IDiGraph<'V, 'E>
