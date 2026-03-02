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

open System.Text.Json.Serialization

/// Represents a serializable graph. This is not supposed to be used as a graph
/// representation in the middle-end, but rather as a temporary data structure
/// for importing/exporting graphs.
[<CLIMutable>]
type SerializableGraph =
  { [<JsonPropertyName("roots")>]
    Roots: VertexID[]
    [<JsonPropertyName("vertices")>]
    Vertices: SerializableVertex[]
    [<JsonPropertyName("edges")>]
    Edges: SerializableEdge[] }

/// Represents a serializable edge.
and [<CLIMutable>] SerializableEdge =
  { [<JsonPropertyName("from")>]
    From: int
    [<JsonPropertyName("to")>]
    To: int
    [<JsonPropertyName("label")>]
    Label: string }

/// Represents a serializable vertex.
and [<CLIMutable>] SerializableVertex =
  { [<JsonPropertyName("id")>]
    ID: int
    [<JsonPropertyName("label")>]
    Label: string }
