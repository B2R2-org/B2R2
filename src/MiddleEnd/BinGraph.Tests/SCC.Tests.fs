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

open B2R2.MiddleEnd.BinGraph
open Microsoft.VisualStudio.TestTools.UnitTesting

[<AutoOpen>]
module GraphExample =
  let example1 (g: IGraph<_, _>) =
    let n1, g = g.AddVertex 1
    let n2, g = g.AddVertex 2
    let n3, g = g.AddVertex 3
    let n4, g = g.AddVertex 4
    let n5, g = g.AddVertex 5
    let g = g.AddEdge (n1, n2, 1)
    let g = g.AddEdge (n1, n3, 2)
    let g = g.AddEdge (n2, n4, 3)
    let g = g.AddEdge (n3, n4, 4)
    let g = g.AddEdge (n3, n5, 5)
    g

  let example2 (g: IGraph<_, _>) =
    let n1, g = g.AddVertex 1
    let n2, g = g.AddVertex 2
    let n3, g = g.AddVertex 3
    let n4, g = g.AddVertex 4
    let n5, g = g.AddVertex 5
    let n6, g = g.AddVertex 6
    let n7, g = g.AddVertex 7
    let n8, g = g.AddVertex 8
    let g = g.AddEdge (n1, n2, 1)
    let g = g.AddEdge (n2, n3, 2)
    let g = g.AddEdge (n3, n4, 3)
    let g = g.AddEdge (n4, n5, 4)
    let g = g.AddEdge (n5, n2, 5)
    let g = g.AddEdge (n5, n6, 6)
    let g = g.AddEdge (n6, n3, 7)
    let g = g.AddEdge (n6, n7, 8)
    let g = g.AddEdge (n7, n2, 9)
    let g = g.AddEdge (n7, n8, 10)
    (g, n1, n8, [ n2; n3; n4; n5; n6; n7 ])

  let example3 (g: IGraph<_, _>) =
    let na, g = g.AddVertex 1
    let nb, g = g.AddVertex 2
    let nc, g = g.AddVertex 3
    let nd, g = g.AddVertex 4
    let ne, g = g.AddVertex 5
    let nf, g = g.AddVertex 6
    let ng, g = g.AddVertex 7
    let nh, g = g.AddVertex 8
    let g = g.AddEdge (na, nb, 1)
    let g = g.AddEdge (nb, nc, 2)
    let g = g.AddEdge (nb, ne, 3)
    let g = g.AddEdge (nb, nf, 4)
    let g = g.AddEdge (nc, nd, 5)
    let g = g.AddEdge (nc, ng, 6)
    let g = g.AddEdge (nd, nc, 7)
    let g = g.AddEdge (nd, nh, 8)
    let g = g.AddEdge (ne, na, 9)
    let g = g.AddEdge (ne, nf, 10)
    let g = g.AddEdge (nf, ng, 11)
    let g = g.AddEdge (ng, nf, 12)
    let g = g.AddEdge (nh, nd, 13)
    let g = g.AddEdge (nh, ng, 14)
    (g, [ na; nb; ne ], [ nc; nd; nh ], [ nf; ng ])

  let example4 (g: IGraph<_, _>) =
    let na, g = g.AddVertex 1
    let nb, g = g.AddVertex 2
    let nc, g = g.AddVertex 3
    let nd, g = g.AddVertex 4
    let ne, g = g.AddVertex 5
    let g = g.AddEdge (na, nb, 1)
    let g = g.AddEdge (nb, nc, 2)
    let g = g.AddEdge (nc, na, 3)
    let g = g.AddEdge (nd, ne, 4)
    let g = g.AddEdge (ne, nd, 5)
    (g, [ na; nb; nc ], [ nd; ne ])

[<AutoOpen>]
module Tests =
  let SCCTest1 g =
    let g = example1 g
    let sccs = SCC.compute g
    Assert.AreEqual (5, Set.count sccs)

  let SCCTest2 g =
    let g, n1, n8, s = example2 g
    let sccs = SCC.compute g
    Assert.AreEqual (3, Set.count sccs)
    let scc1 = Set.singleton n1
    Assert.IsTrue (Set.contains scc1 sccs)
    let scc2 = Set.singleton n8
    Assert.IsTrue (Set.contains scc2 sccs)
    let scc3 = Set.ofList s
    Assert.IsTrue (Set.contains scc3 sccs)

  let SCCTest3 g =
    let g, s1, s2, s3 = example3 g
    let sccs = SCC.compute g
    Assert.AreEqual (3, Set.count sccs)
    let scc1 = Set.ofList s1
    Assert.IsTrue (Set.contains scc1 sccs)
    let scc2 = Set.ofList s2
    Assert.IsTrue (Set.contains scc2 sccs)
    let scc3 = Set.ofList s3
    Assert.IsTrue (Set.contains scc3 sccs)

  let SCCTest4 g =
    let g, s1, s2 = example4 g
    let sccs = SCC.compute g
    Assert.AreEqual (2, Set.count sccs)
    let scc1 = Set.ofList s1
    Assert.IsTrue (Set.contains scc1 sccs)
    let scc2 = Set.ofList s2
    Assert.IsTrue (Set.contains scc2 sccs)

[<TestClass>]
type ImperativeSCCTest() =
  (* Arbitrary graph example *)
  [<TestMethod>]
  member __.``SCC Test1``() = SCCTest1 <| ImperativeDiGraph ()

  (* Example from article about Bourdoncle Components by Matt Elder *)
  [<TestMethod>]
  member __.``SCC Test2`` () = SCCTest2 <| ImperativeDiGraph ()

  (* Example from Wikipedia *)
  [<TestMethod>]
  member __.``SCC Test3`` () = SCCTest3 <| ImperativeDiGraph ()

  (* Example with isolated sub-graphs *)
  [<TestMethod>]
  member __.``SCC Test4`` () = SCCTest4 <| ImperativeDiGraph ()

[<TestClass>]
type PersistentSCCTest () =
  (* Arbitrary graph example *)
  [<TestMethod>]
  member __.``SCC Test1``() = SCCTest1 <| PersistentDiGraph ()

  (* Example from article about Bourdoncle Components by Matt Elder *)
  [<TestMethod>]
  member __.``SCC Test2`` () = SCCTest2 <| PersistentDiGraph ()

  (* Example from Wikipedia *)
  [<TestMethod>]
  member __.``SCC Test3`` () = SCCTest3 <| PersistentDiGraph ()

  (* Example with isolated sub-graphs *)
  [<TestMethod>]
  member __.``SCC Test4`` () = SCCTest4 <| PersistentDiGraph ()

