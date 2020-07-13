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

namespace B2R2.BinGraph

[<AbstractClass>]
type Graph<'D, 'E, 'G
    when 'D :> VertexData
     and 'G :> Graph<'D, 'E, 'G>> () =

  /// Is this empty? A graph is empty when there is no vertex in the graph.
  abstract IsEmpty: unit -> bool

  /// Number of vertices.
  abstract GetSize: unit -> int

  /// Add a vertex into the graph, and return a reference to the added vertex.
  abstract AddVertex: 'D -> Vertex<'D> * 'G

  /// Remove the given vertex from the graph.
  abstract RemoveVertex: Vertex<'D> -> 'G

  /// Get a set of all vertices in the graph.
  abstract GetVertices: unit -> Set<Vertex<'D>>

  /// Check the existence of the given vertex from the graph.
  abstract ExistsVertex: VertexID -> bool

  /// Find a vertex by its VertexID. This function raises an exception when
  /// there is no such a vertex.
  abstract FindVertexByID: VertexID -> Vertex<'D>

  /// Find a vertex by its VertexID. This function returns an Option type.
  abstract TryFindVertexByID: VertexID -> Vertex<'D> option

  /// Find a vertex that has the given VertexData from the graph. It will raise
  /// an exception if such a vertex does not exist. Note that this function can
  /// be used only when each vertex always has unique VertexData.
  abstract FindVertexByData: 'D -> Vertex<'D>

  /// Find a vertex that has the given VertexData from the graph. This function
  /// does not raise an exception unlike FindVertexByData.
  abstract TryFindVertexByData: 'D -> Vertex<'D> option

  /// Find a vertex by the given function. This function returns the first
  /// element, in which the function returns true. When there is no such an
  /// element, the function raises an exception.
  abstract FindVertexBy: (Vertex<'D> -> bool) -> Vertex<'D>

  /// Find a vertex by the given function without raising an exception.
  abstract TryFindVertexBy: (Vertex<'D> -> bool) -> Vertex<'D> option

  /// Add an edge from src to dst.
  abstract AddEdge: src: Vertex<'D> -> dst: Vertex<'D> -> 'E -> 'G

  /// Remove the edge that spans from src to dst.
  abstract RemoveEdge: src: Vertex<'D> -> dst: Vertex<'D> -> 'G

  /// Find the data of the edge that spans from src to dst.
  abstract FindEdgeData: src: Vertex<'D> -> dst: Vertex<'D> -> 'E

  abstract TryFindEdgeData: src: Vertex<'D> -> dst: Vertex<'D> -> 'E option

  /// Fold every vertex (the order can be arbitrary).
  abstract FoldVertex: ('a -> Vertex<'D> -> 'a) -> 'a -> 'a

  /// Iterate every vertex (the order can be arbitrary).
  abstract IterVertex: (Vertex<'D> -> unit) -> unit

  /// Fold every edge in the graph (the order can be arbitrary).
  abstract FoldEdge: ('a -> Vertex<'D> -> Vertex<'D> -> 'E -> 'a) -> 'a -> 'a

  /// Fold every edge in the graph (the order can be arbitrary).
  abstract IterEdge: (Vertex<'D> -> Vertex<'D> -> 'E -> unit) -> unit

  abstract Clone: unit -> 'G

  abstract SubGraph: Set<Vertex<'D>> -> 'G

  /// Return the DOT-representation of this graph.
  abstract ToDOTStr:
    string -> (Vertex<'D> -> string) -> (Edge<'E> -> string) -> string
