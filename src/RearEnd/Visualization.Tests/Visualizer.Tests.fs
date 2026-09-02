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
