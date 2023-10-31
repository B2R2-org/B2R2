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

/// Missing vertex.
exception VertexNotFoundException

/// Trying to access dummy data
exception DummyDataAccessException

/// A unique ID for a vertex.
type VertexID = int

/// A vertex of a graph.
type IVertex<'V when 'V: equality> =
  inherit System.IComparable

  /// Unique ID of the vertex.
  abstract ID: VertexID

  /// Data attached to the vertex. This can raise `DummyDataAccessException`
  /// when the vertex has no data.
  abstract VData: 'V

  /// Check if the vertex has data. When this is true, `VData` should not raise
  /// an exception.
  abstract HasData: bool

/// This is an internal data type used by a vertex implementation in order to
/// represent nullable data.
[<AllowNullLiteral>]
type internal VertexData<'V when 'V: equality> (v) =
  member __.Value: 'V = v

  interface System.IEquatable<VertexData<'V>> with
    member __.Equals (other: VertexData<'V>) =
      __.Value = other.Value