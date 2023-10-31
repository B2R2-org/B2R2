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

/// Missing edge.
exception EdgeNotFoundException

/// Edge of a graph.
type Edge<'V, 'E when 'V: equality and 'E: equality> (fst, snd, label) =
  /// Source vertex of the edge. For undirected graphs, this is the first vertex
  /// that was added to the edge.
  member __.First with get(): IVertex<'V> = fst

  /// Target vertex of the edge. For undirected graphs, this is the second
  /// vertex that was added to the edge.
  member __.Second with get(): IVertex<'V> = snd

  /// Label of the edge.
  member __.Label with get(): EdgeLabel<'E> = label

and [<AllowNullLiteral>] EdgeLabel<'E when 'E: equality> (value: 'E) =
  member __.Value = value

  interface System.IEquatable<EdgeLabel<'E>> with
    member __.Equals (other: EdgeLabel<'E>) =
      __.Value = other.Value
