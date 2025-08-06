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

open System.IO
open System.Text
open System.Runtime.Serialization
open System.Runtime.Serialization.Json
open System.Collections.Generic

[<CLIMutable>]
[<DataContract>]
type private SerializableVertex =
  { [<field: DataMember(Name = "id")>]
    ID: int
    [<field: DataMember(Name = "label")>]
    Label: string }

[<CLIMutable>]
[<DataContract>]
type private SerializableEdge =
  { [<field: DataMember(Name = "from")>]
    From: int
    [<field: DataMember(Name = "to")>]
    To: int
    [<field: DataMember(Name = "label")>]
    Label: string }

/// Serializable graph. This is not supposed to be used as a graph
/// representation in the middle-end, but rather as a temporary data structure
/// for importing/exporting graphs.
[<CLIMutable>]
[<DataContract>]
type private SerializableGraph =
  { [<field: DataMember(Name = "roots")>]
    Roots: VertexID[]
    [<field: DataMember(Name = "vertices")>]
    Vertices: SerializableVertex[]
    [<field: DataMember(Name = "edges")>]
    Edges: SerializableEdge[] }

/// The serializer of a graph.
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
    let enc = Encoding.UTF8
    use ms = new MemoryStream()
    use writer = JsonReaderWriterFactory.CreateJsonWriter(ms, enc, true, true)
    let ser = DataContractJsonSerializer(typedefof<SerializableGraph>)
    ser.WriteObject(writer, g)
    writer.Flush()
    ms.Position <- 0
    use reader = new StreamReader(ms)
    reader.ReadToEnd()

  /// Export the given graph to a string in the JSON format.
  static member ToJson(g) =
    Serializer.ToJson(Serializer.NewGraph g)

  /// Export the given graph to a string in the JSON format with the given
  /// vertex and edge label functions.
  static member ToJson(g, vertexFn, edgeFn) =
    Serializer.ToJson(Serializer.NewGraph(g, vertexFn, edgeFn))

  static member private CopyGraph<'V, 'E when 'V: equality
                                          and 'E: equality>(inGraph,
                                                            outGraph,
                                                            vConstructor,
                                                            eConstructor) =
    let vMap = Dictionary<VertexID, IVertex<'V>>()
    (inGraph: SerializableGraph).Vertices
    |> Array.fold (fun (outGraph: IDiGraph<'V, 'E>) v ->
      let data = vConstructor v.Label
      let v', outGraph = outGraph.AddVertex(data, v.ID)
      vMap[v.ID] <- v'
      outGraph
    ) outGraph
    |> fun outGraph ->
      inGraph.Edges
      |> Array.fold (fun (outGraph: IDiGraph<'V, 'E>) e ->
        let data = eConstructor e.Label
        outGraph.AddEdge(vMap[e.From], vMap[e.To], data)
      ) outGraph
      |> fun outGraph ->
        inGraph.Roots
        |> Array.map (fun id -> vMap[id])
        |> outGraph.SetRoots

  /// Import the graph from the given JSON string using the graph, vertex, and
  /// edge constructors.
  static member FromJson<'V, 'E when 'V: equality
                                 and 'E: equality>(json: string,
                                                   gConstructor,
                                                   vConstructor,
                                                   eConstructor) =
    use ms = new MemoryStream(Encoding.ASCII.GetBytes json)
    let ser = DataContractJsonSerializer(typeof<SerializableGraph>)
    let sg = ser.ReadObject(ms) :?> SerializableGraph
    let g: IDiGraph<'V, 'E> = gConstructor ()
    Serializer.CopyGraph(sg, g, vConstructor, eConstructor)

  /// Export the given graph to a string in the DOT format.
  static member ToDOT(g: IDiGraphAccessible<_, _>, name) =
    let vertexFn v = v.ToString()
    let edgeFn e = e.ToString()
    Serializer.ToDOT(g, name, vertexFn, edgeFn)

  /// Export the given graph to a string in the DOT format using the given
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
