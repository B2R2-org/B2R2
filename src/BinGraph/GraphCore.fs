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

/// GraphCore is an internal representation for the core graph operations, and
/// this should not be directly accessed by the user.
[<AbstractClass>]
type GraphCore<'D, 'E, 'G
    when 'D :> VertexData and 'G :> Graph<'D, 'E, 'G>> internal () =

  abstract ImplementationType: GraphImplementationType

  abstract InitGraph: GraphCore<'D, 'E, 'G> option -> 'G

  abstract Vertices: Set<Vertex<'D>>

  abstract Unreachables: Vertex<'D> list

  abstract Exits: Vertex<'D> list

  abstract GetSize: unit -> int

  abstract AddDummyVertex: 'G -> Vertex<'D> * 'G

  abstract AddVertex: 'G -> 'D -> Vertex<'D> * 'G

  abstract GetVertex: VertexID -> Vertex<'D>

  abstract ContainsVertex: VertexID -> bool

  abstract RemoveVertex: 'G -> Vertex<'D> -> 'G

  abstract FoldVertex: ('a -> Vertex<'D> -> 'a) -> 'a -> 'a

  abstract IterVertex: (Vertex<'D> -> unit) -> unit

  abstract FindVertexBy: (Vertex<'D> -> bool) -> Vertex<'D>

  abstract TryFindVertexBy: (Vertex<'D> -> bool) -> Vertex<'D> option

  abstract GetPreds: Vertex<'D> -> Vertex<'D> list

  abstract GetSuccs: Vertex<'D> -> Vertex<'D> list

  abstract AddDummyEdge: 'G -> Vertex<'D> -> Vertex<'D> -> 'G

  abstract AddEdge: 'G -> Vertex<'D> -> Vertex<'D> -> 'E -> 'G

  abstract GetEdge: Vertex<'D> -> Vertex<'D> -> 'E

  abstract RemoveEdge: 'G -> Vertex<'D> -> Vertex<'D> -> 'G

  abstract FoldEdge: ('a -> Vertex<'D> -> Vertex<'D> -> 'E -> 'a) -> 'a -> 'a

  abstract IterEdge: (Vertex<'D> -> Vertex<'D> -> 'E -> unit) -> unit

  abstract FindEdge: Vertex<'D> -> Vertex<'D> -> 'E

  abstract TryFindEdge: Vertex<'D> -> Vertex<'D> -> 'E option

  abstract Clone: unit -> GraphCore<'D, 'E, 'G>
