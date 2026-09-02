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
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.RearEnd.Visualization

/// A minimal basic block standing in for a real one, carrying nothing but the
/// address that names it.
type private FakeBlock(addr: Addr) =
  interface IVisualizable with
    member _.BlockAddress with get() = addr

    member _.LineAddrRanges with get() = [| { Min = addr; Max = addr } |]

    member _.Visualize() =
      let value = $"blk{addr}"
      [| [| { AsmWordKind = AsmWordKind.String; AsmWordValue = value } |] |]

  interface IAddressable with
    member _.PPoint with get() = ProgramPoint(addr, 0)

    member _.Range with get() = { Min = addr; Max = addr }

[<TestClass>]
type VisGraphTests() =
  let charWidth, charHeight = 7.5, 14.0

  /// Builds a graph of the given block addresses, rooted at the vertices whose
  /// addresses are the given ones, and edged as the given pairs of addresses
  /// say.
  let build addrs rootAddrs edges =
    let g = MutableDiGraph<FakeBlock, CFGEdgeKind>() :> IMutableDiGraph<_, _>
    let vertices =
      addrs
      |> List.map (fun addr -> addr, g.AddVertex(FakeBlock addr))
      |> dict
    for src, dst in edges do
      g.AddEdge(vertices[src], vertices[dst], CFGEdgeKind.FallThroughEdge)
    g.SetRoots(rootAddrs |> List.map (fun addr -> vertices[addr]))
    g :> IDiGraph<_, _>

  let rootAddrsOf (g: VisGraph) =
    g.Roots
    |> Array.map (fun r -> (r.VData :> IVisualizable).BlockAddress)
    |> Array.sort

  [<TestMethod>]
  member _.``ofCFG keeps the root of the given graph``() =
    (* The root is added last, so a graph that took whichever vertex reached it
       first for its root would answer 0x1000 here. *)
    let edges = [ 0x3000UL, 0x1000UL; 0x1000UL, 0x2000UL ]
    let g = build [ 0x1000UL; 0x2000UL; 0x3000UL ] [ 0x3000UL ] edges
    let vGraph = VisGraph.ofCFG g charWidth charHeight
    CollectionAssert.AreEqual([| 0x3000UL |], rootAddrsOf vGraph)

  [<TestMethod>]
  member _.``ofCFG keeps every root of a multi-rooted graph``() =
    let edges = [ 0x1000UL, 0x3000UL; 0x2000UL, 0x3000UL ]
    let g = build [ 0x1000UL; 0x2000UL; 0x3000UL ] [ 0x1000UL; 0x2000UL ] edges
    let vGraph = VisGraph.ofCFG g charWidth charHeight
    CollectionAssert.AreEqual([| 0x1000UL; 0x2000UL |], rootAddrsOf vGraph)
