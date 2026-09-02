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

/// Represents an x-y coordinate as the JSON output carries it.
[<CLIMutable>]
type JSONCoordinate =
  { /// The x position, growing to the right.
    [<JsonPropertyName("x")>]
    X: float
    /// The y position, growing downwards.
    [<JsonPropertyName("y")>]
    Y: float }

/// Represents a node of the graph as the JSON output carries it.
[<CLIMutable>]
type JSONNode =
  { /// The address of the basic block that this node stands for.
    [<JsonPropertyName("pPoint")>]
    PPoint: Addr
    /// The assembly words of the block, by line and then by word within the
    /// line, each word being its text paired with the name of its kind.
    [<JsonPropertyName("terms")>]
    Terms: string[][][]
    /// The width of the node.
    [<JsonPropertyName("width")>]
    Width: float
    /// The height of the node.
    [<JsonPropertyName("height")>]
    Height: float
    /// The top-left corner of the node.
    [<JsonPropertyName("coordinate")>]
    Coordinate: JSONCoordinate }

/// Represents an edge of the graph as the JSON output carries it.
[<CLIMutable>]
type JSONEdge =
  { /// The name of the kind of control flow that this edge stands for.
    [<JsonPropertyName("type")>]
    Type: string
    /// The points of the polyline that the edge is drawn as, from its source
    /// port to its destination port.
    [<JsonPropertyName("points")>]
    Points: JSONCoordinate[]
    /// Whether the edge runs against the layering.
    [<JsonPropertyName("isBackEdge")>]
    IsBackEdge: bool }

/// Represents a whole laid-out graph as the JSON output carries it. This is
/// what the visualization finally answers.
[<CLIMutable>]
type JSONGraph =
  { /// The addresses of the blocks that the graph is rooted at.
    [<JsonPropertyName("roots")>]
    Roots: Addr[]
    /// The nodes of the graph, in no particular order.
    [<JsonPropertyName("nodes")>]
    Nodes: JSONNode[]
    /// The edges of the graph, in no particular order.
    [<JsonPropertyName("edges")>]
    Edges: JSONEdge[] }

/// Provides the JSON rendering of a laid-out graph.
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
