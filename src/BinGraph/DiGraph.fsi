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

type DiGraph<'D, 'E when 'D :> VertexData and 'D : equality> =
  inherit Graph<'D, 'E, DiGraph<'D, 'E>>

  new: GraphCore<'D, 'E, DiGraph<'D, 'E>> -> DiGraph<'D, 'E>
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
  override private FindEdgeData: src: Vertex<'D> -> dst: Vertex<'D> -> 'E
  override private TryFindEdgeData: src: Vertex<'D> -> dst: Vertex<'D> -> 'E option
  override private FoldVertex: ('a -> Vertex<'D> -> 'a) -> 'a -> 'a
  override private IterVertex: (Vertex<'D> -> unit) -> unit
  override private FoldEdge: ('a -> Vertex<'D> -> Vertex<'D> -> 'E -> 'a) -> 'a -> 'a
  override private IterEdge: (Vertex<'D> -> Vertex<'D> -> 'E -> unit) -> unit
  override private Clone: unit -> DiGraph<'D, 'E>
  override private SubGraph: Set<Vertex<'D>> -> DiGraph<'D, 'E>
  override private ToDOTStr:
    string -> (Vertex<'D> -> string) -> (Edge<'E> -> string) -> string

  static member isEmpty: DiGraph<'D, 'E> -> bool

  static member getSize: DiGraph<'D, 'E> -> int

  static member addDummyVertex:
    DiGraph<'D, 'E> -> Vertex<'D> * DiGraph<'D, 'E>

  static member addVertex:
    DiGraph<'D, 'E> -> 'D -> Vertex<'D> * DiGraph<'D, 'E>

  static member removeVertex:
    DiGraph<'D, 'E> -> Vertex<'D> -> DiGraph<'D, 'E>

  static member getPreds:
    DiGraph<'D, 'E> -> Vertex<'D> -> Vertex<'D> list

  static member getSuccs:
    DiGraph<'D, 'E> -> Vertex<'D> -> Vertex<'D> list

  static member getUnreachables: DiGraph<'D, 'E> -> Vertex<'D> list

  static member getExits: DiGraph<'D, 'E> -> Vertex<'D> list

  static member getVertices: DiGraph<'D, 'E> -> Set<Vertex<'D>>

  static member existsVertex: DiGraph<'D, 'E> -> VertexID -> bool

  static member findVertexByID:
    DiGraph<'D, 'E> -> VertexID -> Vertex<'D>

  static member tryFindVertexByID:
    DiGraph<'D, 'E> -> VertexID -> Vertex<'D> option

  static member findVertexByData:
    DiGraph<'D, 'E> -> 'D -> Vertex<'D>

  static member tryFindVertexByData:
    DiGraph<'D, 'E> -> 'D -> Vertex<'D> option

  static member findVertexBy:
    DiGraph<'D, 'E> -> (Vertex<'D> -> bool) -> Vertex<'D>

  static member tryFindVertexBy:
    DiGraph<'D, 'E> -> (Vertex<'D> -> bool) -> Vertex<'D> option

  static member addDummyEdge:
    DiGraph<'D, 'E> -> Vertex<'D> -> Vertex<'D> -> DiGraph<'D, 'E>

  static member addEdge:
    DiGraph<'D, 'E> -> Vertex<'D> -> Vertex<'D> -> 'E -> DiGraph<'D, 'E>

  static member removeEdge:
    DiGraph<'D, 'E> -> Vertex<'D> -> Vertex<'D> -> DiGraph<'D, 'E>

  static member findEdgeData:
    DiGraph<'D, 'E> -> Vertex<'D> -> Vertex<'D> -> 'E

  static member tryFindEdgeData:
    DiGraph<'D, 'E> -> Vertex<'D> -> Vertex<'D> -> 'E option

  static member foldVertex:
    DiGraph<'D, 'E> -> ('a -> Vertex<'D> -> 'a) -> 'a -> 'a

  static member iterVertex:
    DiGraph<'D, 'E> -> (Vertex<'D> -> unit) -> unit

  static member foldEdge:
    DiGraph<'D, 'E> -> ('a -> Vertex<'D> -> Vertex<'D> -> 'E -> 'a) -> 'a -> 'a

  static member iterEdge:
    DiGraph<'D, 'E> -> (Vertex<'D> -> Vertex<'D> -> 'E -> unit) -> unit

  static member clone:
    DiGraph<'D, 'E> -> DiGraph<'D, 'E>

  static member reverse:
    DiGraph<'D, 'E> -> DiGraph<'D, 'E>

  static member subGraph:
    DiGraph<'D, 'E> -> Set<Vertex<'D>> -> DiGraph<'D, 'E>

  static member toDOTStr:
       DiGraph<'D, 'E>
    -> string
    -> (Vertex<'D> -> string)
    -> (Edge<'E> -> string)
    -> string

// vim: set tw=80 sts=2 sw=2:
