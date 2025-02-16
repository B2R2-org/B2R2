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

namespace B2R2.MiddleEnd.BinGraph.Tests

open System.Collections.Generic
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.BinGraph.Tests.Examples

[<TestClass>]
type SCCTests () =
  static member GraphTypes = [| [| box Persistent |]; [| box Imperative |] |]

  [<TestMethod>]
  [<DynamicData(nameof SCCTests.GraphTypes)>]
  member __.``SCC Test1`` (t) =
    let g, _ = digraph7 t
    let sccs = SCC.compute g
    Assert.AreEqual<int> (5, sccs.Length)

  [<TestMethod>]
  [<DynamicData(nameof SCCTests.GraphTypes)>]
  member __.``SCC Test2`` (t) =
    let g, vmap = digraph8 t
    let n1, n8 = vmap[1], vmap[8]
    let s = [ vmap[2]; vmap[3]; vmap[4]; vmap[5]; vmap[6]; vmap[7] ]
    let sccs = SCC.compute g
    Assert.AreEqual<int> (3, sccs.Length)
    let scc1 = HashSet [ n1 ]
    sccs |> Array.exists (fun scc -> scc.SetEquals scc1) |> Assert.IsTrue
    let scc2 = HashSet [ n8 ]
    sccs |> Array.exists (fun scc -> scc.SetEquals scc2) |> Assert.IsTrue
    let scc3 = HashSet s
    sccs |> Array.exists (fun scc -> scc.SetEquals scc3) |> Assert.IsTrue

  [<TestMethod>]
  [<DynamicData(nameof SCCTests.GraphTypes)>]
  member __.``SCC Test3`` (t) =
    let g, vmap = digraph9 t
    let s1 = [ vmap[1]; vmap[2]; vmap[5] ]
    let s2 = [ vmap[3]; vmap[4]; vmap[8] ]
    let s3 = [ vmap[6]; vmap[7] ]
    let sccs = SCC.compute g
    Assert.AreEqual<int> (3, sccs.Length)
    let scc1 = HashSet s1
    sccs |> Array.exists (fun scc -> scc.SetEquals scc1) |> Assert.IsTrue
    let scc2 = HashSet s2
    sccs |> Array.exists (fun scc -> scc.SetEquals scc2) |> Assert.IsTrue
    let scc3 = HashSet s3
    sccs |> Array.exists (fun scc -> scc.SetEquals scc3) |> Assert.IsTrue

  [<TestMethod>]
  [<DynamicData(nameof SCCTests.GraphTypes)>]
  member __.``SCC Test4`` (t) =
    let g, vmap = digraph10 t
    let s1 = [ vmap[1]; vmap[2]; vmap[3] ]
    let s2 = [ vmap[4]; vmap[5] ]
    let sccs = SCC.compute g
    Assert.AreEqual<int> (2, sccs.Length)
    let scc1 = HashSet s1
    sccs |> Array.exists (fun scc -> scc.SetEquals scc1) |> Assert.IsTrue
    let scc2 = HashSet s2
    sccs |> Array.exists (fun scc -> scc.SetEquals scc2) |> Assert.IsTrue
