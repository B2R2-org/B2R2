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
open B2R2.RearEnd.Visualization

[<TestClass>]
type VisBBlockTests() =
  [<TestMethod>]
  member _.``a dummy does not visualize the block it stands in for``() =
    (* A dummy shows nothing and is measured by nothing, so rendering the
       block it was made from is work thrown away. *)
    let blk = CountingBlock 0x1000UL
    let dummy = VisBBlock(blk, 40.0)
    Assert.AreEqual<int>(0, blk.VisualizeCount)
    Assert.AreEqual<bool>(true, dummy.IsDummy)

  [<TestMethod>]
  member _.``a dummy takes the width it is created with``() =
    let dummy = VisBBlock(CountingBlock 0x1000UL, 40.0)
    Assert.AreEqual<float>(40.0, dummy.Width)
    Assert.AreEqual<float>(0.0, dummy.Height)

  [<TestMethod>]
  member _.``a real node is measured by its widest line``() =
    let blk = CountingBlock 0x1000UL
    let node = VisBBlock(blk, 10.0, 20.0)
    Assert.AreEqual<int>(1, blk.VisualizeCount)
    (* One line of "count4096", so 9 chars wide and 1 line tall, plus the
       padding and the border on either side. *)
    Assert.AreEqual<float>(9.0 * 10.0 + 10.0, node.Width)
    Assert.AreEqual<float>(1.0 * 20.0 + 10.0, node.Height)
