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
type Edge<'V, 'E when 'V: equality
                  and 'E: equality> internal(fst, snd, label: EdgeLabel<'E>) =
  /// Source vertex of the edge. For undirected graphs, this is the first vertex
  /// that was added to the edge.
  member _.First with get(): IVertex<'V> = fst

  /// Target vertex of the edge. For undirected graphs, this is the second
  /// vertex that was added to the edge.
  member _.Second with get(): IVertex<'V> = snd

  /// Label of the edge. This can raise `DummyDataAccessException` when the
  /// edge has no label.
  member _.Label with get(): 'E =
    if isNull label then raise DummyDataAccessException
    else label.Value

  /// Check if the edge has a label.
  member _.HasLabel with get() = not (isNull label)

  override _.ToString() =
    if isNull label then ""
    else $"{label}"

and [<AllowNullLiteral>] internal EdgeLabel<'E when 'E: equality>(value: 'E) =
  member _.Value = value

  override _.ToString() = $"{value}"

  interface System.IEquatable<EdgeLabel<'E>> with
    member this.Equals(other: EdgeLabel<'E>) =
      this.Value = other.Value
