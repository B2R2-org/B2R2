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
open System.Collections.Generic
open B2R2

/// Imperative vertex.
type ImperativeVertex<'V when 'V: equality>
  internal(id, vData: VertexData<'V> | null) =
  let preds = List<ImperativeVertex<'V>>()
  let succs = List<ImperativeVertex<'V>>()

  /// Unique identifier of this vertex.
  member _.ID with get() = id

  /// List of predecessors.
  member _.Preds with get() = preds

  /// List of successors.
  member _.Succs with get() = succs

  interface IVertex<'V> with
    member _.ID = id

    member _.VData =
      if isNull vData then raise DummyDataAccessException
      else vData.Value

    member _.HasData = not (isNull vData)

    member _.CompareTo(other: obj) =
      match other with
      | :? IVertex<'V> as other -> id.CompareTo other.ID
      | _ -> Terminator.impossible ()

  interface System.IFormattable with
    member _.ToString(_, _) = $"{nameof ImperativeVertex}({vData.ToString ()})"

  override _.GetHashCode() = id

  override _.Equals(other) =
    match other with
    | :? IVertex<'V> as other -> id = other.ID
    | _ -> false

  override this.ToString() =
    (this :> System.IFormattable).ToString(null, CultureInfo.CurrentCulture)
