(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>
          Soomin Kim <soomink@kaist.ac.kr>

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

/// A simple directed graph, where vertices are managed with a set. Vertex Data
/// should support equality operation, to support FindVertexByData method. This
/// graph considers the firstly added node as its root node.
type SimpleDiGraph<'V, 'E when 'V :> VertexData and 'V : equality> =
  inherit DiGraph<'V, 'E>
  new: unit -> SimpleDiGraph<'V, 'E>
  override IsEmpty : unit -> bool
  override Size : unit -> int
  override AddVertex : 'V -> Vertex<'V>
  override RemoveVertex : Vertex<'V> -> unit
  override FindVertex : Vertex<'V> -> Vertex<'V>
  override FindVertexByData : 'V -> Vertex<'V>
  override TryFindVertexByData : 'V -> Vertex<'V> option
  override AddEdge : Vertex<'V> -> Vertex<'V> -> 'E -> unit
  override RemoveEdge : Vertex<'V> -> Vertex<'V> -> unit
  /// Find edge data.
  override FindEdge : Vertex<'V> -> Vertex<'V> -> 'E
  override Reverse : unit -> DiGraph<'V, 'E>

  /// Clone this graph and return a new one. Copied vertices will have the same
  /// IDs assigned. The reverse parameter tells whether the graph is constructed
  /// with transposed (reversed) edges or not. If the parameter is not given,
  /// this function will simply return the same graph by default.
  member Clone : ?reverse: bool -> SimpleDiGraph<'V, 'E>

  member TryFindEdge : Vertex<'V> -> Vertex<'V> -> 'E option

  member GenID : unit -> VertexID

  member GetMaxID : unit -> VertexID

  member GetVertices : unit -> Set<Vertex<'V>>

// vim: set tw=80 sts=2 sw=2:
