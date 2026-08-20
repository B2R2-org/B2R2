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

open System.Text
open System.Text.Json
open System.Collections.Generic

/// Represents a serializer of a graph.
type Serializer =
  static member private NewGraph<'V, 'E when 'V: equality
                                         and 'E: equality>(g) =
    let roots =
      (g: IDiGraphAccessible<'V, 'E>).GetRoots() |> Array.map (fun v -> v.ID)
    let vertices =
      g.Vertices
      |> Array.map (fun v -> { ID = v.ID; Label = v.VData.ToString() })
    let edges =
      g.Edges
      |> Array.map (fun e ->
        let lbl = if e.HasLabel then e.Label.ToString() else ""
        { From = e.First.ID; To = e.Second.ID; Label = lbl })
    { Roots = roots; Vertices = vertices; Edges = edges }

  static member private NewGraph<'V, 'E when 'V: equality
                                         and 'E: equality>(g, vFn, edgeFn) =
    let roots =
      (g: IDiGraphAccessible<'V, 'E>).GetRoots() |> Array.map (fun v -> v.ID)
    let vertices =
      g.Vertices
      |> Array.map (fun v -> { ID = v.ID; Label = vFn v })
    let edges =
      g.Edges
      |> Array.map (fun e ->
        { From = e.First.ID; To = e.Second.ID; Label = edgeFn e })
    { Roots = roots; Vertices = vertices; Edges = edges }

  static member private ToJson(g: SerializableGraph) =
    JsonSerializer.Serialize g

  /// Exports the given graph to a string in the JSON format using the default
  /// string representations of vertices and edges as labels.
  static member ToJson g = Serializer.ToJson(Serializer.NewGraph g)

  /// <summary>
  /// Exports the given graph to a string in the JSON format.
  /// </summary>
  /// <param name="g">The graph to export.</param>
  /// <param name="vertexFn">Converts each vertex to a label.</param>
  /// <param name="edgeFn">Converts each edge to a label.</param>
  static member ToJson(g, vertexFn, edgeFn) =
    Serializer.ToJson(Serializer.NewGraph(g, vertexFn, edgeFn))

  /// Raises `InvalidSerializedGraphException` with the given message.
  static member private RaiseInvalidGraph msg =
    raise <| InvalidSerializedGraphException msg

  /// Deserializes the given JSON string, rejecting an input that carries no
  /// graph at all.
  static member private Deserialize(json: string) =
    let sg =
      try
        JsonSerializer.Deserialize<SerializableGraph> json
      with :? JsonException as e ->
        Serializer.RaiseInvalidGraph $"Malformed JSON: {e.Message}"
    if isNull (box sg) then Serializer.RaiseInvalidGraph "No graph in JSON"
    else sg

  /// Returns an empty array for a missing (null) array of a serialized graph.
  static member private NullToEmpty(arr: 'T[]) =
    if isNull arr then [||] else arr

  /// Collects the IDs of the given vertices, rejecting a duplicate one.
  static member private CollectVertexIDs(vertices: SerializableVertex[]) =
    let ids = HashSet<VertexID>()
    for v in vertices do
      if ids.Add v.ID then ()
      else Serializer.RaiseInvalidGraph $"Duplicate vertex ID {v.ID}"
    ids

  /// Ensures that the given ID is one of the declared vertex IDs.
  static member private CheckDefined(ids: HashSet<VertexID>, what, id) =
    if ids.Contains id then ()
    else Serializer.RaiseInvalidGraph $"{what} refers to unknown ID {id}"

  /// Ensures that a graph having vertices also has at least one root, which
  /// every graph built through `IDiGraph` maintains.
  static member private CheckRoots(vertices: 'a[], roots: 'b[]) =
    if vertices.Length = 0 || roots.Length > 0 then ()
    else Serializer.RaiseInvalidGraph "A non-empty graph has no root"

  /// Validates the given serialized graph before any vertex of it is built,
  /// and returns its vertices, edges, and roots with the missing ones filled
  /// in as empty arrays.
  static member private Validate(g: SerializableGraph) =
    let vertices = Serializer.NullToEmpty g.Vertices
    let edges = Serializer.NullToEmpty g.Edges
    let roots = Serializer.NullToEmpty g.Roots
    let ids = Serializer.CollectVertexIDs vertices
    for e in edges do
      Serializer.CheckDefined(ids, "An edge", e.From)
      Serializer.CheckDefined(ids, "An edge", e.To)
    for r in roots do Serializer.CheckDefined(ids, "A root", r)
    Serializer.CheckRoots(vertices, roots)
    vertices, edges, roots

  /// Returns an empty label for a missing (null) label of a serialized graph.
  static member private NullToEmptyLabel(label: string) =
    if isNull label then "" else label

  static member private CopyGraph<'V, 'E when 'V: equality
                                          and 'E: equality>(inGraph,
                                                            outGraph,
                                                            vConstructor,
                                                            eConstructor) =
    let vertices, edges, roots =
      Serializer.Validate(inGraph: SerializableGraph)
    let vMap = Dictionary<VertexID, IVertex<'V>>()
    vertices
    |> Array.fold (fun (outGraph: IDiGraph<'V, 'E>) v ->
      let data = vConstructor (Serializer.NullToEmptyLabel v.Label)
      let v', outGraph = outGraph.AddVertex(data, v.ID)
      vMap[v.ID] <- v'
      outGraph
    ) outGraph
    |> fun outGraph ->
      edges
      |> Array.fold (fun (outGraph: IDiGraph<'V, 'E>) e ->
        (* Validated above: every ID an edge or a root refers to is in vMap. *)
        let data = eConstructor (Serializer.NullToEmptyLabel e.Label)
        outGraph.AddEdge(vMap[e.From], vMap[e.To], data)
      ) outGraph
      |> fun outGraph ->
        roots
        |> Array.map (fun id -> vMap[id])
        |> outGraph.SetRoots

  /// <summary>
  /// Imports the graph from the given JSON string.
  /// </summary>
  /// <param name="json">The JSON string that contains a serialized
  /// graph.</param>
  /// <param name="gConstructor">Constructs an empty graph.</param>
  /// <param name="vConstructor">Constructs vertex data from a vertex
  /// label.</param>
  /// <param name="eConstructor">Constructs edge data from an edge
  /// label.</param>
  /// <exception
  ///   cref="T:B2R2.MiddleEnd.BinGraph.InvalidSerializedGraphException">
  /// Thrown when the given JSON string does not represent a valid graph.
  /// </exception>
  static member FromJson<'V, 'E when 'V: equality
                                 and 'E: equality>(json: string,
                                                   gConstructor,
                                                   vConstructor,
                                                   eConstructor) =
    let sg = Serializer.Deserialize json
    let g: IDiGraph<'V, 'E> = gConstructor ()
    Serializer.CopyGraph(sg, g, vConstructor, eConstructor)

  /// Exports the given graph to a string in the DOT format.
  static member ToDOT(g: IDiGraphAccessible<_, _>, name) =
    let vertexFn v = v.ToString()
    let edgeFn e = e.ToString()
    Serializer.ToDOT(g, name, vertexFn, edgeFn)

  /// Exports the given graph to a string in the DOT format using the given
  /// vertex and edge label functions.
  static member ToDOT(g: IDiGraphAccessible<_, _>, name, vertexFn, edgeFn) =
    let (!!) (sb: StringBuilder) (s: string) = sb.Append s |> ignore
    let sb = StringBuilder()
    let vertexToString (v: IVertex<_>) =
      let lbl = vertexFn v
      !!sb $"  {v.ID}{lbl};\n"
    let edgeToString (e: Edge<_, _>) =
      !!sb $"  {e.First.ID} -> {e.Second.ID} [label=\"{edgeFn e}\"];\n"
    !!sb $"digraph {name} {{\n"
    !!sb $"  node[shape=box]\n"
    g.IterVertex vertexToString
    g.IterEdge edgeToString
    sb.Append("}\n").ToString()
