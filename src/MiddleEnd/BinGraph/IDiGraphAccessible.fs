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

/// Read-only directed graph information accessor. This interface provides a way
/// to access the information of a directed graph without modifying it.
type IDiGraphAccessible<'V, 'E when 'V: equality and 'E: equality> =
  inherit IGraphAccessible<'V, 'E>

  /// Get an array of exit vertices in the graph.
  abstract Exits: IVertex<'V>[]

  /// Get the predecessors of the given vertex. This is only meaningful for
  /// directed graphs.
  abstract GetPreds: IVertex<'V> -> IVertex<'V>[]

  /// Get the predecessor edges of the given vertex. This is only meaningful for
  /// directed graphs.
  abstract GetPredEdges: IVertex<'V> -> Edge<'V, 'E>[]

  /// Get the successors of the given vertex. This is only meaningful for
  /// directed graphs.
  abstract GetSuccs: IVertex<'V> -> IVertex<'V>[]

  /// Get the successor edges of the given vertex. This is only meaningful for
  /// directed graphs.
  abstract GetSuccEdges: IVertex<'V> -> Edge<'V, 'E>[]

  /// Get the root vertices of this graph. When there's no root, this will
  /// return an empty collection.
  abstract GetRoots: unit -> IVertex<'V>[]

  /// Return a new transposed (i.e., reversed) graph. The given set of vertices
  /// will be used to set the root vertices of the transposed graph.
  abstract Reverse: IEnumerable<IVertex<'V>> -> IDiGraphAccessible<'V, 'E>
