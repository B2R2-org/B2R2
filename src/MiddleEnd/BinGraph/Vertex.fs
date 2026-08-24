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

open System.Globalization

/// Represents a vertex of a graph. Graphs, not vertices, own the adjacency
/// information, so a vertex is just an ID paired with its data.
type Vertex<'V when 'V: equality>
  internal(id, vData: VertexData<'V> | null) =

  /// Gets the unique identifier of this vertex.
  member _.ID with get(): VertexID = id

  interface IVertex<'V> with
    member _.ID = id

    member _.VData =
      if isNull vData then raise DummyDataAccessException else vData.Value

    member _.HasData = not (isNull vData)

  (* A vertex carrying no data has nothing but its ID to be named by, hence
     that is what it reads as, marked with a '#' so that it is not taken for
     the data of a vertex that has some. *)
  interface System.IFormattable with
    member _.ToString(_, _) =
      if isNull vData then $"{nameof Vertex}(#{id})"
      else $"{nameof Vertex}({vData.ToString()})"

  (* A vertex is the object it is. The graph that made one hands out that very
     object every time, so a vertex of another graph is another vertex even
     when the two of them carry one ID. Hashing still goes by the ID, that
     being the cheapest hash reference equality allows. *)
  override _.GetHashCode() = id

  override this.Equals(other) = obj.ReferenceEquals(this, other)

  override this.ToString() =
    (this :> System.IFormattable).ToString(null, CultureInfo.CurrentCulture)
