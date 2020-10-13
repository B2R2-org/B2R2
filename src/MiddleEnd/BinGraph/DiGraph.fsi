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

/// Directedg graph inehrited from Graph. This type is mostly used by primary
/// graph algorithms, such as the dominator algorithm. We only expose static
/// members here to make code consistent for both persistent and imperative
/// graphs.
[<AbstractClass>]
type DiGraph<'D, 'E when 'D :> VertexData and 'D : equality> =
  inherit Graph<'D, 'E, DiGraph<'D, 'E>>

  new: GraphCore<'D, 'E, DiGraph<'D, 'E>> -> DiGraph<'D, 'E>
  override private ImplementationType: GraphImplementationType
  override private IsEmpty: unit -> bool
  override private GetSize: unit -> int
  override private AddVertex: 'D -> Vertex<'D> * DiGraph<'D, 'E>
  override private RemoveVertex: Vertex<'D> -> DiGraph<'D, 'E>
  override private GetVertices: unit -> Set<Vertex<'D>>
  override private ExistsVertex: VertexID -> bool
  override private FindVertexByID: VertexID -> Vertex<'D>
  override private TryFindVertexByID: VertexID -> Vertex<'D> option
  override private FindVertexByData: 'D -> Vertex<'D>
  override private TryFindVertexByData: 'D -> Vertex<'D> option
  override private FindVertexBy: (Vertex<'D> -> bool) -> Vertex<'D>
  override private TryFindVertexBy: (Vertex<'D> -> bool) -> Vertex<'D> option
  override private AddEdge: Vertex<'D> -> Vertex<'D> -> 'E -> DiGraph<'D, 'E>
  override private RemoveEdge: Vertex<'D> -> Vertex<'D> -> DiGraph<'D, 'E>
  override private FindEdgeData: Vertex<'D> -> Vertex<'D> -> 'E
  override private TryFindEdgeData: Vertex<'D> -> Vertex<'D> -> 'E option
  override private FoldVertex: ('a -> Vertex<'D> -> 'a) -> 'a -> 'a
  override private IterVertex: (Vertex<'D> -> unit) -> unit
  override private FoldEdge:
    ('a -> Vertex<'D> -> Vertex<'D> -> 'E -> 'a) -> 'a -> 'a
  override private IterEdge: (Vertex<'D> -> Vertex<'D> -> 'E -> unit) -> unit
  override private Clone: unit -> DiGraph<'D, 'E>
  override private SubGraph: Set<Vertex<'D>> -> DiGraph<'D, 'E>
  override private ToDOTStr:
    string -> (Vertex<'D> -> string) -> (Edge<'E> -> string) -> string

  /// Check if the graph is empty.
  [<CompiledName("IsEmpty")>]
  static member isEmpty: DiGraph<'D, 'E> -> bool

  /// Get the number of vertices of the graph.
  [<CompiledName("GetSize")>]
  static member getSize: DiGraph<'D, 'E> -> int

  /// Add a dummy vertex to the graph. Dummy nodes are necessary when we run
  /// some graph algorithms, and such nodes should be removed appropriately
  /// before we return the final results.
  [<CompiledName("AddDummyVertex")>]
  static member addDummyVertex:
    DiGraph<'D, 'E> -> Vertex<'D> * DiGraph<'D, 'E>

  /// Add a vertex to the graph.
  [<CompiledName("AddVertex")>]
  static member addVertex:
    DiGraph<'D, 'E> -> 'D -> Vertex<'D> * DiGraph<'D, 'E>

  /// Remove a vertex from the graph.
  [<CompiledName("RemoveVertex")>]
  static member removeVertex:
    DiGraph<'D, 'E> -> Vertex<'D> -> DiGraph<'D, 'E>

  /// Get the predecessors of the given vertex in the graph.
  [<CompiledName("GetPreds")>]
  static member getPreds:
    DiGraph<'D, 'E> -> Vertex<'D> -> Vertex<'D> list

  /// Get the successors of the given vertex in the graph.
  [<CompiledName("GetSuccs")>]
  static member getSuccs:
    DiGraph<'D, 'E> -> Vertex<'D> -> Vertex<'D> list

  /// Get unreachable nodes from the graph.
  [<CompiledName("GetUnreachables")>]
  static member getUnreachables: DiGraph<'D, 'E> -> Vertex<'D> list

  /// Get leaf (exit) nodes from the graph.
  [<CompiledName("GetExits")>]
  static member getExits: DiGraph<'D, 'E> -> Vertex<'D> list

  /// Get the whole set of vertices from the graph.
  [<CompiledName("GetVertices")>]
  static member getVertices: DiGraph<'D, 'E> -> Set<Vertex<'D>>

  /// Check if the given vertex exists in the graph.
  [<CompiledName("ExistsVertex")>]
  static member existsVertex: DiGraph<'D, 'E> -> VertexID -> bool

  /// Find vertex by VertexID. This function raises an exception when the given
  /// ID does not exist in the graph.
  [<CompiledName("FindVertexByID")>]
  static member findVertexByID:
    DiGraph<'D, 'E> -> VertexID -> Vertex<'D>

  /// Try to find vertex by VertexID.
  [<CompiledName("TryFindVertexByID")>]
  static member tryFindVertexByID:
    DiGraph<'D, 'E> -> VertexID -> Vertex<'D> option

  /// Find vertex by given data. This function raises an exception when there is
  /// no matching vertex in the graph.
  [<CompiledName("FindVertexByData")>]
  static member findVertexByData:
    DiGraph<'D, 'E> -> 'D -> Vertex<'D>

  /// Try to find vertex by given data.
  [<CompiledName("TryFindVertexByData")>]
  static member tryFindVertexByData:
    DiGraph<'D, 'E> -> 'D -> Vertex<'D> option

  /// Find vertex by the given predicate. This function raises an exception when
  /// there is no matching vertex.
  [<CompiledName("FindVertexBy")>]
  static member findVertexBy:
    DiGraph<'D, 'E> -> (Vertex<'D> -> bool) -> Vertex<'D>

  /// Try to find vertex by given data.
  [<CompiledName("TryFindVertexBy")>]
  static member tryFindVertexBy:
    DiGraph<'D, 'E> -> (Vertex<'D> -> bool) -> Vertex<'D> option

  /// Add an edge to the graph without attaching data to it.
  [<CompiledName("AddDummyEdge")>]
  static member addDummyEdge:
    DiGraph<'D, 'E> -> Vertex<'D> -> Vertex<'D> -> DiGraph<'D, 'E>

  /// Add an edge to the graph.
  [<CompiledName("AddEdge")>]
  static member addEdge:
    DiGraph<'D, 'E> -> Vertex<'D> -> Vertex<'D> -> 'E -> DiGraph<'D, 'E>

  /// Remove an edge from the graph.
  [<CompiledName("RemoveEdge")>]
  static member removeEdge:
    DiGraph<'D, 'E> -> Vertex<'D> -> Vertex<'D> -> DiGraph<'D, 'E>

  /// Find an edge and return the data attached to it. This function raises an
  /// exception when there is no matching edge.
  [<CompiledName("FindEdgeData")>]
  static member findEdgeData:
    DiGraph<'D, 'E> -> Vertex<'D> -> Vertex<'D> -> 'E

  /// Try to find an edge and return the data attached to it.
  [<CompiledName("TryFindEdgeData")>]
  static member tryFindEdgeData:
    DiGraph<'D, 'E> -> Vertex<'D> -> Vertex<'D> -> 'E option

  /// Fold vertices in the graph.
  [<CompiledName("FoldVertex")>]
  static member foldVertex:
    DiGraph<'D, 'E> -> ('a -> Vertex<'D> -> 'a) -> 'a -> 'a

  /// Iterate vertices in the graph.
  [<CompiledName("IterVertex")>]
  static member iterVertex:
    DiGraph<'D, 'E> -> (Vertex<'D> -> unit) -> unit

  /// Fold edges in the graph.
  [<CompiledName("FoldEdge")>]
  static member foldEdge:
    DiGraph<'D, 'E> -> ('a -> Vertex<'D> -> Vertex<'D> -> 'E -> 'a) -> 'a -> 'a

  /// Iterate edges in the graph.
  [<CompiledName("IterEdge")>]
  static member iterEdge:
    DiGraph<'D, 'E> -> (Vertex<'D> -> Vertex<'D> -> 'E -> unit) -> unit

  /// Clone a graph. For imperative graphs, this function involves deep copying.
  [<CompiledName("Clone")>]
  static member clone:
    DiGraph<'D, 'E> -> DiGraph<'D, 'E>

  /// Create a reverse graph.
  [<CompiledName("Reverse")>]
  static member reverse:
    DiGraph<'D, 'E> -> DiGraph<'D, 'E>

  /// Return a subgraph of the given vertices.
  [<CompiledName("SubGraph")>]
  static member subGraph:
    DiGraph<'D, 'E> -> Set<Vertex<'D>> -> DiGraph<'D, 'E>

  /// Return a DOT-formatted string from the graph.
  [<CompiledName("ToDOTStr")>]
  static member toDOTStr:
       DiGraph<'D, 'E>
    -> string
    -> (Vertex<'D> -> string)
    -> (Edge<'E> -> string)
    -> string

// vim: set tw=80 sts=2 sw=2:
