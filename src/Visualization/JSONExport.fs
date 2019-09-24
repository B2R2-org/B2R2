(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Soomin Kim <soomink@kaist.ac.kr>
          Sang Kil Cha <sangkilc@kaist.ac.kr>

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

namespace B2R2.Visualization

open B2R2
open B2R2.FrontEnd
open B2R2.BinGraph
open Microsoft.FSharpLu.Json

type JSONCoordinate = {
  X: float
  Y: float
}

type JSONNode = {
  PPoint: Addr * int
  Terms: (string * string) [] []
  Width: float
  Height: float
  Coordinate: JSONCoordinate
}

type JSONEdge = {
  Type: CFGEdgeKind
  Points: JSONCoordinate list
  IsBackEdge: bool
}

/// This is Visualization module's final output type.
type JSONGraph = {
  Nodes: JSONNode list
  Edges: JSONEdge list
}

module JSONExport =
  let private getJSONTerms (visualBlock: VisualBlock) =
    visualBlock |> Array.map (Array.map AsmWord.ToStringTuple)

  let private ofVisGraph (g: VisGraph) =
    let nodes =
      g.FoldVertex (fun acc v ->
        { PPoint = v.VData.PPoint.Address, v.VData.PPoint.Position
          Terms = v.VData.ToVisualBlock () |> getJSONTerms
          Width = v.VData.Width
          Height = v.VData.Height
          Coordinate = { X = v.VData.Coordinate.X
                         Y = v.VData.Coordinate.Y } } :: acc) []
    let edges =
      g.FoldEdge (fun acc _ _ e ->
        { Type = e.Type
          Points = e.Points |> List.map (fun p -> { X = p.X; Y = p.Y })
          IsBackEdge = e.IsBackEdge } :: acc) []
    { Nodes = nodes; Edges = edges }

  let toFile s g =
    ofVisGraph g
    |> Compact.serializeToFile<JSONGraph> s

  let toStr g =
    ofVisGraph g
    |> Compact.serialize<JSONGraph>
