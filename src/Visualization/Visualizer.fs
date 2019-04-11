(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Soomin Kim <soomink@kaist.ac.kr>

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

module B2R2.Visualization.Visualizer

let visualize iGraph =
  let vGraph = VGraph.ofIGraph iGraph
#if DEBUG
  VGraph.pp vGraph
#endif
  let backEdgeList = CycleRemoval.removeCycles vGraph
#if DEBUG
  VGraph.pp vGraph
#endif
  let backEdgeList, dummyMap =
    LayerAssignment.assignLayers vGraph backEdgeList
#if DEBUG
  VGraph.pp vGraph
#endif
  let vLayout = CrossMinimization.minimizeCrosses vGraph
  CoordAssignment.assignCoordinates vGraph vLayout
  EdgeDrawing.drawEdges vGraph vLayout backEdgeList dummyMap
  VGraph.toOutputGraph vGraph

let visualizeFile inputFile outputFile =
  let iGraph = InputGraph.ofFile inputFile
  let oGraph = visualize iGraph
  OutputGraph.toFile outputFile oGraph

let visualizeDisasmCFG hdl disasmCFG =
  try
    let iGraph = InputGraph.ofCFG hdl disasmCFG
    let oGraph = visualize iGraph
    OutputGraph.toStr oGraph
  with e ->
    eprintfn "%s" <| e.ToString ()
    "{}"

let visualizeIRCFG hdl irCFG =
  try
    let iGraph = InputGraph.ofCFG hdl irCFG
    let oGraph = visualize iGraph
    OutputGraph.toStr oGraph
  with e ->
    eprintfn "%s" <| e.ToString ()
    "{}"