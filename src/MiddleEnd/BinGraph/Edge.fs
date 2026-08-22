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

/// Raised when an edge is not found in the graph.
exception EdgeNotFoundException

/// Represents an edge of a graph.
type Edge<'V, 'E when 'V: equality and 'E: equality>
  internal(fst, snd, label: EdgeLabel<'E> | null) =

  /// Returns the source vertex of the edge.
  member _.First with get(): IVertex<'V> = fst

  /// Returns the target vertex of the edge.
  member _.Second with get(): IVertex<'V> = snd

  /// Returns the label of the edge. This can raise `DummyDataAccessException`
  /// when the edge has no label.
  member _.Label with get(): 'E =
    if isNull label then raise DummyDataAccessException else label.Value

  /// Returns true if the edge has a label. When this is true, `Label` should
  /// not raise `DummyDataAccessException`.
  member _.HasLabel with get() = not (isNull label)

  (* An edge is the ordered pair of its endpoints and nothing else, and an
     endpoint is the object it is, so the edge of another graph that spans a
     pair carrying the same IDs is another edge. Within one graph there is at
     most one edge for a pair, which is what lets RemoveEdge be handed a
     freshly made edge that does no more than name the pair. *)
  member private _.HasEnds(first: IVertex<'V>, second: IVertex<'V>) =
    obj.ReferenceEquals(fst, first) && obj.ReferenceEquals(snd, second)

  interface System.IEquatable<Edge<'V, 'E>> with
    member this.Equals(other: Edge<'V, 'E>) =
      this.HasEnds(other.First, other.Second)

  override _.GetHashCode() = System.HashCode.Combine(fst.ID, snd.ID)

  override this.Equals(other) =
    match other with
    | :? Edge<'V, 'E> as other -> this.HasEnds(other.First, other.Second)
    | _ -> false

  override _.ToString() = if isNull label then "" else $"{label}"

and internal EdgeLabel<'E when 'E: equality>(value: 'E) =
  member _.Value = value

  override _.ToString() = $"{value}"

  interface System.IEquatable<EdgeLabel<'E>> with
    member this.Equals(other: EdgeLabel<'E>) = this.Value = other.Value
