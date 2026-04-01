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

module B2R2.RearEnd.Visualization.Visualizer

open B2R2.MiddleEnd.BinGraph

let private convert iGraph roots charWidth charHeight =
  try
    let vGraph, roots = VisGraph.ofCFG iGraph roots charWidth charHeight
    let backEdgeList = CycleRemoval.run vGraph
    let backEdgeList, dummyMap = LayerAssignment.run vGraph backEdgeList
    let vLayout = CrossMinimization.run vGraph
    CoordAssignment.run vGraph vLayout
    EdgeDrawing.drawEdges vGraph vLayout backEdgeList dummyMap
    Some(roots, vGraph)
  with e ->
    eprintfn "%s" <| e.ToString()
    None

/// Converts the given graph to JSON format.
let toJSON (iGraph: IDiGraphAccessible<_, _>) roots charWidth charHeight =
  if iGraph.Size = 0 then
    "{}"
  else
    match convert iGraph roots charWidth charHeight with
    | Some(roots, vGraph) -> JSONExport.toStr roots vGraph
    | None -> "{}"

/// Converts the given graph to a VisGraph for visualization.
let toVisGraph (iGraph: IDiGraphAccessible<_, _>) roots charWidth charHeight =
  if iGraph.Size = 0 then
    VisGraph.init ()
  else
    convert iGraph roots charWidth charHeight
    |> Option.map snd
    |> Option.defaultValue (VisGraph.init ())

/// Default character width used for layout calculations.
let [<Literal>] CharWidth = 7.5

/// Default character height used for layout calculations.
let [<Literal>] CharHeight = 14.0