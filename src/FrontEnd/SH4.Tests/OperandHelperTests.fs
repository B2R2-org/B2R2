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

namespace B2R2.FrontEnd.SH4.Tests

open B2R2.FrontEnd.SH4.OperandHelper
open Microsoft.VisualStudio.TestTools.UnitTesting

/// Pins the bit reader that every SH4 operand goes through. It numbers bit
/// positions from one, as the SH4 manual does and unlike the rest of the front
/// end, so the numbering is what these tests are mostly about.
[<TestClass>]
type OperandHelperTests() =
  (* 0xabcd = 1010 1011 1100 1101, whose one-based bit 16 is the leading 1. *)
  static let sample = 0xabcdus

  [<TestMethod>]
  member _.``[SH4] Bits Are Numbered From One Test``() =
    Assert.AreEqual<uint16>(0b1us, getBits sample 16 16)
    Assert.AreEqual<uint16>(0b1us, getBits sample 1 1)
    Assert.AreEqual<uint16>(0b1010us, getBits sample 16 13)
    Assert.AreEqual<uint16>(0b1101us, getBits sample 4 1)

  (* The fields operands are actually read from: register numbers at 12..9 and
     8..5, and the widest field in use, a twelve-bit displacement. *)
  [<TestMethod>]
  member _.``[SH4] Operand Fields Are Read Test``() =
    Assert.AreEqual<uint16>(0b1011us, getBits sample 12 9)
    Assert.AreEqual<uint16>(0b1100us, getBits sample 8 5)
    Assert.AreEqual<uint16>(0xbcdus, getBits sample 12 1)

  [<TestMethod>]
  member _.``[SH4] Bits Ignore Position Order Test``() =
    Assert.AreEqual<uint16>(getBits sample 12 9, getBits sample 9 12)
    Assert.AreEqual<uint16>(getBits sample 16 1, getBits sample 1 16)

  (* A full-width read is meaningful over sixteen bits, and used to be rejected
     because the guard bounded the width at fifteen. *)
  [<TestMethod>]
  member _.``[SH4] A Full Width Read Is Allowed Test``() =
    Assert.AreEqual<uint16>(sample, getBits sample 16 1)

  (* Positions outside 1..16 name a field this instruction set does not have.
     The guard used to bound only the width, so a pair like 20..10 passed it and
     read bits the value does not hold, quietly yielding zero. *)
  [<TestMethod>]
  member _.``[SH4] Positions Outside The Word Are Rejected Test``() =
    for hi, lo in [ 20, 10; 17, 1; 8, 0; 0, 0 ] do
      Assert.ThrowsExactly<System.InvalidOperationException>(fun () ->
        getBits sample hi lo |> ignore) |> ignore

  [<TestMethod>]
  member _.``[SH4] A Single Bit Is Numbered From One Test``() =
    Assert.AreEqual<bool>(true, get1Bit sample 1)
    Assert.AreEqual<bool>(false, get1Bit sample 2)
    Assert.AreEqual<bool>(true, get1Bit sample 16)
