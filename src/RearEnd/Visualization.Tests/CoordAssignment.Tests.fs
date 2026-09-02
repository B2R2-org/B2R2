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

  /// Adds a real vertex standing at the given x, showing a line of the given
  /// number of characters. A character is one wide here, so the count is that
  /// line's share of the node's width.
  let realVertex addr x chars =
    let text = System.String('x', chars)
    let v = g.AddVertex(VisBBlock(FakeBlock(addr, text), 1.0, 1.0))
    v.VData.Coordinate.X <- x
    v

  /// Adds a real vertex as `realVertex` does, noting its x position in the
  /// given map, so that a layout and the coordinates of its vertices are built
  /// together.
  let place (xs: CoordAssignment.FloatMap) addr x chars =
    let v = realVertex addr x chars
    xs[v] <- x
    v

  /// Three layers whose middle one is by far the narrowest, so that neither
  /// the first layer nor the last one answers for the narrowest by accident.
  /// Layer 0 spans 0..210, layer 1 spans 5..15, and layer 2 spans 0..110.
  let buildLayout () =
    let xs = CoordAssignment.FloatMap()
    let wide = [| place xs 0x1000UL 0.0 10; place xs 0x1001UL 200.0 10 |]
    let narrow = [| place xs 0x2000UL 5.0 10 |]
    let middling = [| place xs 0x3000UL 0.0 10; place xs 0x3001UL 100.0 10 |]
    [| wide; narrow; middling |], xs, narrow[0]

  let boundOf vLayout xs hDir =
    let _, left, right, _, _ = CoordAssignment.getBound vLayout (xs, hDir)
    match hDir with
    | CoordAssignment.Leftmost -> left
    | CoordAssignment.Rightmost -> right

  /// Adds a dummy vertex of the given width standing at the given x. A dummy
  /// shows nothing, so the width it takes up is its own to say rather than
  /// something a line it holds answers for.
  let dummyVertex addr x width =
    let v = g.AddVertex(VisBBlock(FakeBlock addr, width))
    v.VData.Coordinate.X <- x
    v

  [<TestMethod>]
  member _.``getBound reads the left edge of the narrowest layer``() =
    let vLayout, xs, _ = buildLayout ()
    Assert.AreEqual<float>(0.0, boundOf vLayout xs CoordAssignment.Leftmost)

  [<TestMethod>]
  member _.``getBound reads the right edge of the narrowest layer``() =
    let vLayout, xs, narrow = buildLayout ()
    let hDir = CoordAssignment.Rightmost
    let expected = 200.0 + narrow.VData.Width
    Assert.AreEqual<float>(expected, boundOf vLayout xs hDir)

  [<TestMethod>]
  member _.``averageMedian centres the median of the alignments``() =
    let a = g.AddVertex(VisBBlock(FakeBlock 0x1000UL, 7.5, 14.0))
    let b = g.AddVertex(VisBBlock(FakeBlock 0x2000UL, 7.5, 14.0))
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
    let a = realVertex 0x1000UL 0.0 10
    let b = realVertex 0x2000UL 100.0 10
    (* The two span from a's left edge to b's right one, and everything shifts
       left by the midpoint of that span. *)
    let shift = (100.0 + b.VData.Width) / 2.0
    CoordAssignment.adjustCoordinates g
    Assert.AreEqual<float>(-shift, a.VData.Coordinate.X)
    Assert.AreEqual<float>(100.0 - shift, b.VData.Coordinate.X)

  [<TestMethod>]
  member _.``adjustCoordinates measures nothing but the real vertices``() =
    let a = realVertex 0x1000UL 0.0 10
    let b = realVertex 0x2000UL 100.0 10
    (* Either dummy lies well outside the two real vertices, and neither is
       measured, so the span centred on is still a's left edge to b's right
       one. A dummy is carried along by the shift like anything else, which is
       what tells being left out of the measuring from being left alone. *)
    let left = dummyVertex 0x3000UL -500.0 40.0
    let right = dummyVertex 0x4000UL 500.0 40.0
    let shift = (100.0 + b.VData.Width) / 2.0
    CoordAssignment.adjustCoordinates g
    Assert.AreEqual<float>(-shift, a.VData.Coordinate.X)
    Assert.AreEqual<float>(100.0 - shift, b.VData.Coordinate.X)
    Assert.AreEqual<float>(-500.0 - shift, left.VData.Coordinate.X)
    Assert.AreEqual<float>(500.0 - shift, right.VData.Coordinate.X)

  [<TestMethod>]
  member _.``adjustCoordinates takes a graph of nothing but dummies``() =
    (* A dummy is never measured, whatever width it takes up, so a graph of
       nothing else has no extent to be centred on and every vertex is left
       standing where it was. *)
    let a = dummyVertex 0x1000UL 30.0 40.0
    let b = dummyVertex 0x2000UL 70.0 40.0
    CoordAssignment.adjustCoordinates g
    Assert.AreEqual<float>(30.0, a.VData.Coordinate.X)
    Assert.AreEqual<float>(70.0, b.VData.Coordinate.X)

  [<TestMethod>]
  member _.``the layout indexes every vertex by its place in its layer``() =
    (* The coordinate assignment reads a vertex's index for its place in its
       layer, so this is what the layout owes it. *)
    let mk addr layer =
      let v = g.AddVertex(VisBBlock(FakeBlock addr, 1.0, 1.0))
      VisGraph.setLayer v layer
      v
    let a = mk 0x1000UL 0
    let b = mk 0x2000UL 1
    let c = mk 0x3000UL 1
    let d = mk 0x4000UL 2
    let edge () = VisEdge CFGEdgeKind.FallThroughEdge
    g.AddEdge(a, b, edge ())
    g.AddEdge(a, c, edge ())
    g.AddEdge(b, d, edge ())
    g.AddEdge(c, d, edge ())
    for layer in CrossMinimization.run g do
      for i in 0 .. layer.Length - 1 do
        Assert.AreEqual<int>(i, layer[i].VData.Index)
