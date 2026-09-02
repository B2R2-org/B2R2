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
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.RearEnd.Visualization

[<TestClass>]
type CoordAssignmentTests() =
  let g = VisGraph.init ()

  /// Adds a real vertex of the given width, standing at the given x position.
  let realVertex addr x width =
    let v = g.AddVertex(VisBBlock(FakeBlock addr, 7.5, 14.0, false))
    v.VData.Width <- width
    v.VData.Coordinate.X <- x
    v

  /// Adds a real vertex as `realVertex` does, noting its x position in the
  /// given map, so that a layout and the coordinates of its vertices are built
  /// together.
  let place (xs: CoordAssignment.FloatMap) addr x width =
    let v = realVertex addr x width
    xs[v] <- x
    v

  /// Three layers whose middle one is by far the narrowest, so that neither
  /// the first layer nor the last one answers for the narrowest by accident.
  /// Layer 0 spans 0..210, layer 1 spans 5..15, and layer 2 spans 0..110.
  let buildLayout () =
    let xs = CoordAssignment.FloatMap()
    let wide = [| place xs 0x1000UL 0.0 10.0; place xs 0x1001UL 200.0 10.0 |]
    let narrow = [| place xs 0x2000UL 5.0 10.0 |]
    let middling =
      [| place xs 0x3000UL 0.0 10.0; place xs 0x3001UL 100.0 10.0 |]
    [| wide; narrow; middling |], xs

  let boundOf vLayout xs hDir =
    let bound, _, _ = CoordAssignment.getBound vLayout (xs, hDir)
    bound

  [<TestMethod>]
  member _.``getBound reads the left edge of the narrowest layer``() =
    let vLayout, xs = buildLayout ()
    Assert.AreEqual<float>(5.0, boundOf vLayout xs CoordAssignment.Leftmost)

  [<TestMethod>]
  member _.``getBound reads the right edge of the narrowest layer``() =
    let vLayout, xs = buildLayout ()
    Assert.AreEqual<float>(15.0, boundOf vLayout xs CoordAssignment.Rightmost)

  [<TestMethod>]
  member _.``averageMedian centres the median of the alignments``() =
    let a = g.AddVertex(VisBBlock(FakeBlock 0x1000UL, 7.5, 14.0, false))
    let b = g.AddVertex(VisBBlock(FakeBlock 0x2000UL, 7.5, 14.0, false))
    let alignment (xa, xb) =
      let xs = CoordAssignment.FloatMap()
      xs[a] <- xa
      xs[b] <- xb
      xs
    (* A is seen at 0, 10, 20 and 30, whose median is 15; B at 100, 200, 100
       and 200, whose median is 150. The two are then centred on 82.5, the
       midpoint of the medians. *)
    [ alignment (0.0, 100.0)
      alignment (10.0, 200.0)
      alignment (20.0, 100.0)
      alignment (30.0, 200.0) ]
    |> CoordAssignment.averageMedian
    Assert.AreEqual<float>(-67.5, a.VData.Coordinate.X)
    Assert.AreEqual<float>(67.5, b.VData.Coordinate.X)

  [<TestMethod>]
  member _.``adjustCoordinates centres the real vertices``() =
    let a = realVertex 0x1000UL 0.0 10.0
    let b = realVertex 0x2000UL 100.0 20.0
    (* Both stand in one layer, which the singleton pull leaves alone. They
       span 0 to 120, so everything shifts left by that span's midpoint. *)
    CoordAssignment.adjustCoordinates g [| [| a; b |] |]
    Assert.AreEqual<float>(-60.0, a.VData.Coordinate.X)
    Assert.AreEqual<float>(40.0, b.VData.Coordinate.X)

  [<TestMethod>]
  member _.``adjustCoordinates takes a graph of nothing but dummies``() =
    (* A dummy has no width to be measured by, so a graph of nothing else has
       no extent to be centred on. *)
    let a = g.AddVertex(VisBBlock(FakeBlock 0x1000UL, true))
    let b = g.AddVertex(VisBBlock(FakeBlock 0x2000UL, true))
    g.AddEdge(a, b, VisEdge CFGEdgeKind.FallThroughEdge)
    VisGraph.setLayer a 0
    VisGraph.setLayer b 1
    CoordAssignment.adjustCoordinates g [| [| a |]; [| b |] |]
    Assert.AreEqual<float>(0.0, a.VData.Coordinate.X)
    Assert.AreEqual<float>(0.0, b.VData.Coordinate.X)
