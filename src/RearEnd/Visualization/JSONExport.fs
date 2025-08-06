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

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open Microsoft.FSharpLu.Json

type JSONCoordinate =
  { X: float
    Y: float }

type JSONNode =
  { PPoint: Addr
    Terms: (string * string) [][]
    Width: float
    Height: float
    Coordinate: JSONCoordinate }

type JSONEdge =
  { Type: CFGEdgeKind
    Points: JSONCoordinate list
    IsBackEdge: bool }

/// This is Visualization module's final output type.
type JSONGraph =
  { Roots: Addr list
    Nodes: JSONNode list
    Edges: JSONEdge list }

module JSONExport =
  let private getJSONTerms (visualizableAsm: AsmWord[][]) =
    visualizableAsm |> Array.map (Array.map AsmWord.ToStringTuple)

  let private ofVisGraph (g: VisGraph) (roots: IVertex<_> list) =
    let roots =
      roots |> List.map (fun r -> (r.VData :> IVisualizable).BlockAddress)
    let nodes =
      g.FoldVertex((fun acc v ->
        let vData = v.VData :> IVisualizable
        { PPoint = vData.BlockAddress
          Terms = vData.Visualize() |> getJSONTerms
          Width = v.VData.Width
          Height = v.VData.Height
          Coordinate = { X = v.VData.Coordinate.X
                         Y = v.VData.Coordinate.Y } } :: acc), [])
    let edges =
      g.FoldEdge((fun acc e ->
        let e = e.Label
        { Type = e.Type
          Points = e.Points |> List.map (fun p -> { X = p.X; Y = p.Y })
          IsBackEdge = e.IsBackEdge } :: acc), [])
    { Roots = roots; Nodes = nodes; Edges = edges }

  let toFile s roots g =
    ofVisGraph g roots
    |> Compact.serializeToFile<JSONGraph> s

  let toStr roots g =
    ofVisGraph g roots
    |> Compact.serialize<JSONGraph>
