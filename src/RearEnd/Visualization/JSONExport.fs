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

namespace B2R2.RearEnd.Visualization

open System.IO
open System.Text
open System.Runtime.Serialization
open System.Runtime.Serialization.Json
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph

[<CLIMutable>]
[<DataContract>]
type JSONCoordinate =
  { [<field: DataMember(Name = "X")>]
    X: float
    [<field: DataMember(Name = "Y")>]
    Y: float }

[<CLIMutable>]
[<DataContract>]
type JSONNode =
  { [<field: DataMember(Name = "PPoint")>]
    PPoint: Addr
    [<field: DataMember(Name = "Terms")>]
    Terms: string[][][]
    [<field: DataMember(Name = "Width")>]
    Width: float
    [<field: DataMember(Name = "Height")>]
    Height: float
    [<field: DataMember(Name = "Coordinate")>]
    Coordinate: JSONCoordinate }

[<CLIMutable>]
[<DataContract>]
type JSONEdge =
  { [<field: DataMember(Name = "Type")>]
    Type: string
    [<field: DataMember(Name = "Points")>]
    Points: JSONCoordinate[]
    [<field: DataMember(Name = "IsBackEdge")>]
    IsBackEdge: bool }

/// This is Visualization module's final output type.
[<CLIMutable>]
[<DataContract>]
type JSONGraph =
  { [<field: DataMember(Name = "Roots")>]
    Roots: Addr[]
    [<field: DataMember(Name = "Nodes")>]
    Nodes: JSONNode[]
    [<field: DataMember(Name = "Edges")>]
    Edges: JSONEdge[] }

module JSONExport =
  let private getJSONTerms (visualizableAsm: AsmWord[][]) =
    visualizableAsm
    |> Array.map (Array.map AsmWord.ToStringArray)

  let private ofVisGraph (g: VisGraph) (roots: IVertex<_> list) =
    let roots =
      roots
      |> List.map (fun r -> (r.VData :> IVisualizable).BlockAddress)
      |> List.toArray
    let nodes =
      g.FoldVertex((fun acc v ->
        let vData = v.VData :> IVisualizable
        { PPoint = vData.BlockAddress
          Terms = vData.Visualize() |> getJSONTerms
          Width = v.VData.Width
          Height = v.VData.Height
          Coordinate = { X = v.VData.Coordinate.X
                         Y = v.VData.Coordinate.Y } } :: acc), [])
      |> List.toArray
    let edges =
      g.FoldEdge((fun acc e ->
        let e = e.Label
        let points = e.Points |> List.toArray
        { Type = CFGEdgeKind.toString e.Type
          Points = points |> Array.map (fun p -> { X = p.X; Y = p.Y })
          IsBackEdge = e.IsBackEdge } :: acc), [])
      |> List.toArray
    { Roots = roots; Nodes = nodes; Edges = edges }

  let private toJson (g: JSONGraph) =
    let enc = Encoding.UTF8
    use ms = new MemoryStream()
    use writer = JsonReaderWriterFactory.CreateJsonWriter(ms, enc, true)
    let ser = DataContractJsonSerializer(typedefof<JSONGraph>)
    ser.WriteObject(writer, g)
    writer.Flush()
    ms.Position <- 0
    use reader = new StreamReader(ms)
    reader.ReadToEnd()

  let toFile path roots g =
    ofVisGraph g roots
    |> toJson
    |> fun jsonStr ->
      File.WriteAllText(path, jsonStr, Encoding.UTF8)

  let toStr roots g =
    ofVisGraph g roots
    |> toJson