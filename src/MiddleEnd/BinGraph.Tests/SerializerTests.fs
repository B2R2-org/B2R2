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

namespace B2R2.MiddleEnd.BinGraph.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open System
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.BinGraph.Tests.Examples

[<TestClass>]
type SerializerTests() =
  let strToInt (s: string) = Convert.ToInt32 s

  let strToIntOrDefault (s: string) = if s = "" then -1 else Convert.ToInt32 s

  (* Which of the two protocols the import takes is what the implementation
     type decides here; what comes out of it is only ever read. *)
  let importWith t labelToData (json: string) =
    match t with
    | Mutable ->
      let empty = MutableDiGraph<int, int>()
      Serializer.FromJson(json, empty, labelToData, labelToData)
      :> IDiGraphAccessible<int, int>
    | Persistent ->
      let empty = PersistentDiGraph<int, int>()
      Serializer.FromJson(json, empty, labelToData, labelToData)

  let importGraph t json = importWith t strToIntOrDefault json

  let assertInvalidGraph f =
    Assert.Throws<InvalidSerializedGraphException>(Action f) |> ignore

  static member GraphTypes = [| [| box Persistent |]; [| box Mutable |] |]

  [<TestMethod>]
  [<DynamicData(nameof SerializerTests.GraphTypes)>]
  member _.``Import/Export test 1``(t) =
    let g, _ = digraph1 t
    let json = Serializer.ToJson g
    let g' = importWith t strToInt json
    let expected = Traversal.DFS.foldPreorder g (fun acc v -> v.VData + acc) 0
    let actual = Traversal.DFS.foldPreorder g' (fun acc v -> v.VData + acc) 0
    Assert.AreEqual<int>(expected, actual)

  [<TestMethod>]
  [<DynamicData(nameof SerializerTests.GraphTypes)>]
  member _.``Import/Export test 2``(t) =
    let g, _ = digraph4 t
    let json = Serializer.ToJson g
    let g' = importWith t strToInt json
    let expected = g.Vertices |> Array.map (fun v -> v.VData)
    let actual = g'.Vertices |> Array.map (fun v -> v.VData)
    CollectionAssert.AreEqual(expected, actual)

  [<TestMethod>]
  [<DynamicData(nameof SerializerTests.GraphTypes)>]
  member _.``Reject an edge referring to an undefined vertex``(t) =
    let json = """{ "roots": [ 1 ],
                    "vertices": [ { "id": 1, "label": "1" } ],
                    "edges": [ { "from": 1, "to": 9, "label": "1" } ] }"""
    assertInvalidGraph (fun () -> importGraph t json |> ignore)

  [<TestMethod>]
  [<DynamicData(nameof SerializerTests.GraphTypes)>]
  member _.``Reject a root referring to an undefined vertex``(t) =
    let json = """{ "roots": [ 9 ],
                    "vertices": [ { "id": 1, "label": "1" } ],
                    "edges": [] }"""
    assertInvalidGraph (fun () -> importGraph t json |> ignore)

  [<TestMethod>]
  [<DynamicData(nameof SerializerTests.GraphTypes)>]
  member _.``Reject a duplicate vertex ID``(t) =
    let json = """{ "roots": [ 1 ],
                    "vertices": [ { "id": 1, "label": "1" },
                                  { "id": 1, "label": "2" } ],
                    "edges": [] }"""
    assertInvalidGraph (fun () -> importGraph t json |> ignore)

  [<TestMethod>]
  [<DynamicData(nameof SerializerTests.GraphTypes)>]
  member _.``Reject a non-empty graph having no root``(t) =
    let json = """{ "roots": [],
                    "vertices": [ { "id": 1, "label": "1" } ],
                    "edges": [] }"""
    assertInvalidGraph (fun () -> importGraph t json |> ignore)

  [<TestMethod>]
  [<DynamicData(nameof SerializerTests.GraphTypes)>]
  member _.``Reject a JSON string that is not a graph``(t) =
    assertInvalidGraph (fun () -> importGraph t "{" |> ignore)
    assertInvalidGraph (fun () -> importGraph t "null" |> ignore)

  [<TestMethod>]
  [<DynamicData(nameof SerializerTests.GraphTypes)>]
  member _.``Import a graph having missing fields``(t) =
    let empty = importGraph t "{}"
    Assert.AreEqual<int>(0, empty.Size)
    let json = """{ "roots": [ 1 ], "vertices": [ { "id": 1 } ] }"""
    let g = importGraph t json
    Assert.AreEqual<int>(1, g.Size)
    Assert.AreEqual<int>(-1, (g.FindVertexByID 1).VData)

  [<TestMethod>]
  [<DynamicData(nameof SerializerTests.GraphTypes)>]
  member _.``Leave the output graph intact on a failed import``(t) =
    let json = """{ "roots": [ 1 ],
                    "vertices": [ { "id": 1, "label": "1" },
                                  { "id": 2, "label": "2" } ],
                    "edges": [ { "from": 1, "to": 9, "label": "1" } ] }"""
    let g =
      match t with
      | Mutable ->
        let g = MutableDiGraph<int, int>()
        assertInvalidGraph (fun () ->
          Serializer.FromJson(json, g, strToInt, strToInt) |> ignore)
        g :> IDiGraphAccessible<int, int>
      | Persistent ->
        let g = PersistentDiGraph<int, int>()
        assertInvalidGraph (fun () ->
          Serializer.FromJson(json, g, strToInt, strToInt) |> ignore)
        g
    Assert.AreEqual<int>(0, g.Size)
