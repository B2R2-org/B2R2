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

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2.MiddleEnd.BinGraph

[<TestClass>]
type GraphFactoryTests() =
  static member GraphTypes = [| [| box Persistent |]; [| box Mutable |] |]

  (* The implementation type a caller names is the one that comes back, and
     the graph is modified in place either way: a persistent one arrives
     wrapped in the graph that replaces its snapshot on every modification. *)
  [<TestMethod>]
  [<DynamicData(nameof GraphFactoryTests.GraphTypes)>]
  member _.``Graph Creation Test``(t) =
    let g: IMutableDiGraph<int, int> = GraphFactory.create t
    Assert.AreEqual<ImplementationType>(t, g.ImplementationType)
    Assert.AreEqual<bool>(true, g.IsEmpty)
    let v = g.AddVertex 1
    Assert.AreEqual<int>(1, g.VertexCount)
    Assert.AreEqual<int>(1, v.VData)
