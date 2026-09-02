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
open System.Text.Json
open System.Text.Json.Serialization
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph

[<CLIMutable>]
type JSONCoordinate =
  { [<JsonPropertyName("x")>]
    X: float
    [<JsonPropertyName("y")>]
    Y: float }

[<CLIMutable>]
type JSONNode =
  { [<JsonPropertyName("pPoint")>]
    PPoint: Addr
    [<JsonPropertyName("terms")>]
    Terms: string[][][]
    [<JsonPropertyName("width")>]
    Width: float
    [<JsonPropertyName("height")>]
    Height: float
    [<JsonPropertyName("coordinate")>]
    Coordinate: JSONCoordinate }

[<CLIMutable>]
type JSONEdge =
  { [<JsonPropertyName("type")>]
    Type: string
    [<JsonPropertyName("points")>]
    Points: JSONCoordinate[]
    [<JsonPropertyName("isBackEdge")>]
    IsBackEdge: bool }

/// This is Visualization module's final output type.
[<CLIMutable>]
type JSONGraph =
  { [<JsonPropertyName("roots")>]
    Roots: Addr[]
    [<JsonPropertyName("nodes")>]
    Nodes: JSONNode[]
    [<JsonPropertyName("edges")>]
    Edges: JSONEdge[] }

module JSONExport =
  let private getJSONTerms (visualizableAsm: AsmWord[][]) =
    visualizableAsm
    |> Array.map (Array.map AsmWord.ToStringArray)

  let private ofVisGraph (g: VisGraph) =
    let roots =
      g.Roots |> Array.map (fun r -> (r.VData :> IVisualizable).BlockAddress)
    let nodes =
      g |> DiGraph.foldVertex (fun acc v ->
        let vData = v.VData :> IVisualizable
        { PPoint = vData.BlockAddress
          Terms = vData.Visualize() |> getJSONTerms
          Width = v.VData.Width
          Height = v.VData.Height
          Coordinate = { X = v.VData.Coordinate.X
                         Y = v.VData.Coordinate.Y } } :: acc) []
      |> List.toArray
    let edges =
      g |> DiGraph.foldEdge (fun acc e ->
        let e = e.Label
        { Type = CFGEdgeKind.toString e.Type
          Points = e.Points |> Array.map (fun p -> { X = p.X; Y = p.Y })
          IsBackEdge = e.IsBackEdge } :: acc) []
      |> List.toArray
    { Roots = roots; Nodes = nodes; Edges = edges }

  /// Renders the given laid-out graph as the JSON a viewer reads. What the
  /// graph is rooted at rides along in it, so there is nothing to say about
  /// the roots that the graph does not already answer.
  let toStr g =
    ofVisGraph g
    |> JsonSerializer.Serialize

  /// Writes the JSON of the given laid-out graph to the given path. Nothing in
  /// the repository calls this; it is here for dumping a graph by hand when a
  /// layout wants looking at.
  let toFile path g =
    let jsonStr = toStr g
    File.WriteAllText(path, jsonStr, Encoding.UTF8)
