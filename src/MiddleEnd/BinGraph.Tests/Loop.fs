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
open B2R2.MiddleEnd.BinGraph.Tests.Examples

[<TestClass>]
type Loop () =
  static member GraphTypes = [| [| box Persistent |]; [| box Imperative |] |]

  [<TestMethod>]
  [<DynamicData(nameof Basic.GraphTypes)>]
  member __.`` Natural Loop Test `` (t) =
    let g, vmap = digraph11 t
    let root = vmap[1]
    let s = Loop.getNaturalLoops g root |> Seq.toArray
    Assert.AreEqual (5, s.Length)
    Assert.IsFalse (s[0].Contains vmap[9])
    Assert.IsTrue (s[1].Contains vmap[10])
    Assert.IsFalse (s[2].Contains vmap[1])
    Assert.IsTrue (s[3].Contains vmap[7])
    Assert.IsTrue (s[4].Contains vmap[8])
