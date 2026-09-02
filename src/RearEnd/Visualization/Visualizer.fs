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

/// Provides the entry points that lay a control flow graph out for viewing.
module B2R2.RearEnd.Visualization.Visualizer

#if DEBUG
open B2R2
#endif
open B2R2.MiddleEnd.BinGraph

(* Whatever the layout runs into is left to reach the caller. Answering an
   empty graph instead would read as a function of no blocks, which is a thing
   a binary really has, and the caller deciding what to make of a failure is
   the caller's to do. *)
let private convert iGraph charWidth charHeight =
  let vGraph = VisGraph.ofCFG iGraph charWidth charHeight
  let backEdgeList = CycleRemoval.run vGraph
  let backEdgeList, dummyMap = LayerAssignment.run vGraph backEdgeList
  let vLayout = CrossMinimization.run vGraph
  CoordAssignment.run vGraph vLayout
  EdgeDrawing.drawEdges vGraph vLayout backEdgeList dummyMap
  vGraph

/// Converts the given graph to JSON format, raising whatever laying it out
/// runs into. A graph of no vertices answers the same shape as any other, so
/// that a reader never has two of them to tell apart. Nothing in the
/// repository calls this; it is here for dumping a graph by hand when a layout
/// wants looking at.
let toJSON (iGraph: IDiGraph<_, _>) charWidth charHeight =
  if iGraph.VertexCount = 0 then
    JSONExport.toStr (VisGraph.init ())
  else
    convert iGraph charWidth charHeight |> JSONExport.toStr

/// Converts the given graph to a VisGraph for visualization, raising whatever
/// laying it out runs into.
let toVisGraph (iGraph: IDiGraph<_, _>) charWidth charHeight =
  if iGraph.VertexCount = 0 then
    VisGraph.init ()
  else
#if DEBUG
    let sw = System.Diagnostics.Stopwatch.StartNew()
    let vGraph = convert iGraph charWidth charHeight
    sw.Stop()
    printsn $"[*] Visualization took {sw.Elapsed.TotalSeconds} sec."
    vGraph
#else
    convert iGraph charWidth charHeight
#endif

/// Represents the default character width used for layout calculations.
let [<Literal>] CharWidth = 7.5

/// Represents the default character height used for layout calculations.
let [<Literal>] CharHeight = 14.0
