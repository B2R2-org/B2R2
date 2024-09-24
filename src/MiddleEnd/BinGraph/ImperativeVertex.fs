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
open B2R2

/// Imperative vertex.
type ImperativeVertex<'V when 'V: equality>
  internal (id, vData: VertexData<'V>) =
  let preds = List<ImperativeVertex<'V>> ()
  let succs = List<ImperativeVertex<'V>> ()

  /// Unique identifier of this vertex.
  member __.ID with get() = id

  /// List of predecessors.
  member __.Preds with get () = preds

  /// List of successors.
  member __.Succs with get () = succs

  interface IVertex<'V> with
    member __.ID = id

    member __.VData =
      if isNull vData then raise DummyDataAccessException
      else vData.Value

    member __.HasData = not (isNull vData)

    member __.CompareTo (other: obj) =
      match other with
      | :? IVertex<'V> as other -> id.CompareTo other.ID
      | _ -> Utils.impossible ()

  override __.GetHashCode () = id

  override __.Equals (other) =
    match other with
    | :? IVertex<'V> as other -> id = other.ID
    | _ -> false
