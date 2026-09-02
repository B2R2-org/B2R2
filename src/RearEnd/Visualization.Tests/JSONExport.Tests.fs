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

open System.Text.Json
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.RearEnd.Visualization

[<TestClass>]
type JSONExportTests() =
  let charWidth, charHeight = 7.5, 14.0

  let rootsOf (json: string) =
    let doc = JsonDocument.Parse json
    doc.RootElement.GetProperty("roots").EnumerateArray()
    |> Seq.map (fun e -> e.GetUInt64())
    |> Seq.toArray

  [<TestMethod>]
  member _.``toStr reads the roots off the graph it is given``() =
    let g = MutableDiGraph<PlainBlock, CFGEdgeKind>() :> IMutableDiGraph<_, _>
    let src = g.AddVertex(PlainBlock 0x1000UL)
    let dst = g.AddVertex(PlainBlock 0x2000UL)
    g.AddEdge(src, dst, CFGEdgeKind.FallThroughEdge)
    g.SetRoots [ dst ]
    let vGraph = VisGraph.ofCFG (g :> IDiGraph<_, _>) charWidth charHeight
    CollectionAssert.AreEqual([| 0x2000UL |], rootsOf (JSONExport.toStr vGraph))

  [<TestMethod>]
  member _.``toJSON answers the whole shape for an empty graph``() =
    let g = MutableDiGraph<PlainBlock, CFGEdgeKind>() :> IDiGraph<_, _>
    let doc = JsonDocument.Parse(Visualizer.toJSON g charWidth charHeight)
    for name in [ "roots"; "nodes"; "edges" ] do
      match doc.RootElement.TryGetProperty name with
      | true, e -> Assert.AreEqual<int>(0, e.GetArrayLength())
      | false, _ -> Assert.Fail $"No '{name}' in the empty graph's JSON."
