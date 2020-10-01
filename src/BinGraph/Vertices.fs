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

open B2R2

/// Missing vertex.
exception VertexNotFoundException

/// Multiple vertices found when looking for a vertex containing certain data
exception MultipleVerticesFoundException

/// Trying to access dummy node's data
exception DummyDataAccessException

/// A unique ID for a vertex.
type VertexID = int

/// A data type for vertex. A VertexData should have an ID.
[<AbstractClass>]
type VertexData (id) =
  member __.ID: VertexID = id

module VertexData =
  let private freshID = ref 0

  let genID () = System.Threading.Interlocked.Increment (freshID)

type RangedVertexData (range: AddrRange) =
  inherit VertexData(VertexData.genID ())
  member __.AddrRange = range

/// A vertex of a graph. The vertex data (v) is optional, and if it is None, we
/// will consider the vertex as a dummy node. Dummy nodes are useful for
/// representing entry/exit node in a CFG.
[<AbstractClass>]
type Vertex<'V when 'V :> VertexData> (v: 'V option) =
  let myid =
    match v with
    | Some v -> v.ID
    | None -> 0

  /// Create a dummy vertex.
  new () = Vertex (None)
  /// Create a regular vertex.
  new (v: 'V) = Vertex (Some v)

  abstract Preds : Vertex<'V> list with get, set
  abstract Succs : Vertex<'V> list with get, set

  /// Data attached to the vertex.
  member __.VData =
    match v with
    | Some v -> v
    | None -> raise DummyDataAccessException

  /// Check whether vertex is a dummy node.
  member __.IsDummy () = Option.isNone v

  /// Each vertex has a unique ID attached to it. We sometimes need to access ID
  /// of dummy vertex for example calculating dominators.
  member __.GetID () = myid

  /// Return the ID of the given vertex.
  static member GetID (v: Vertex<#VertexData>) = v.GetID ()

  // Each vertex has a unique ID, so ID can be used to check equality.
  override __.Equals obj =
    match obj with
    | :? Vertex<'V> as obj ->  __.GetID () = obj.GetID ()
    | _ -> false

  override __.GetHashCode () = __.GetID ()

  override __.ToString () =
    match v with
    | Some v -> sprintf "Vertex<%s>" <| v.ToString ()
    | None -> "DummyVertex"

  // Each vertex has a unique ID, so ID can be used for comparison.
  interface System.IComparable with
    member __.CompareTo obj =
      match obj with
      | :? Vertex<'V> as v -> compare (__.GetID ()) (v.GetID ())
      | _ -> failwith "Invalid comparison"

type V<'V when 'V :> VertexData> = Vertex<'V>

// vim: set tw=80 sts=2 sw=2:
