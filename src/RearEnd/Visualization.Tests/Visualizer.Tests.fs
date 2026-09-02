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

namespace B2R2.RearEnd.Visualization.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.RearEnd.Visualization

[<TestClass>]
type VisualizerTests() =
  let charWidth, charHeight = 7.5, 14.0

  let emptyGraph () =
    MutableDiGraph<PlainBlock, CFGEdgeKind>() :> IMutableDiGraph<_, _>

  [<TestMethod>]
  member _.``toVisGraph answers an empty graph for an empty one``() =
    let g = emptyGraph () :> IDiGraph<_, _>
    Assert.AreEqual<int>(0, (Visualizer.toVisGraph g charWidth charHeight)
                              .VertexCount)

  [<TestMethod>]
  member _.``toVisGraph does not hide a failure as an empty graph``() =
    (* A vertex carrying no data raises as soon as its data is read, which is
       the first thing the conversion does. *)
    let g = emptyGraph ()
    g.AddVertex() |> ignore
    Assert.Throws<DummyDataAccessException>(fun () ->
      Visualizer.toVisGraph (g :> IDiGraph<_, _>) charWidth charHeight
      |> ignore)
    |> ignore

  [<TestMethod>]
  member _.``toVisGraph lays a layer out without overlap``() =
    (* The long edge from a to d is what puts a dummy between the layers and
       sends the coordinate pass through its block placement. *)
    let g = emptyGraph ()
    let a = g.AddVertex(PlainBlock 0x1000UL)
    let b = g.AddVertex(PlainBlock 0x2000UL)
    let c = g.AddVertex(PlainBlock 0x3000UL)
    let d = g.AddVertex(PlainBlock 0x4000UL)
    let edge = CFGEdgeKind.FallThroughEdge
    for src, dst in [ a, b; a, c; b, d; c, d; a, d ] do
      g.AddEdge(src, dst, edge)
    g.SetRoots [ a ]
    let vGraph = Visualizer.toVisGraph (g :> IDiGraph<_, _>) 7.5 14.0
    Assert.AreEqual<int>(4, vGraph.VertexCount)
    for _, layer in Array.groupBy VisGraph.getLayer vGraph.Vertices do
      let sorted = Array.sortBy VisGraph.getXPos layer
      for i in 0 .. sorted.Length - 2 do
        let left = sorted[i]
        let right = sorted[i + 1]
        let rightEdgeOfLeft = VisGraph.getXPos left + VisGraph.getWidth left
        let gap = VisGraph.getXPos right - rightEdgeOfLeft
        Assert.AreEqual<bool>(true, gap >= 0.0, $"nodes overlap by {-gap}")
