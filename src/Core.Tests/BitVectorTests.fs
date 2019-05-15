(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>
          Minkyu Jung <hestati@kaist.ac.kr>
          Dongkwan Kim <dkay@kaist.ac.kr>

  Copyright (c) SoftSec Lab. @ KAIST, since 2016

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*)

module B2R2.Core.Tests.BitVector

open System
open Microsoft.VisualStudio.TestTools.UnitTesting

open B2R2

[<TestClass>]
type TestClass () =

  [<TestMethod>]
  member __.``Equality`` () =
    Assert.AreEqual (BitVector.ofInt32 5l 16<rt>,
                     BitVector.ofUBInt 5I 16<rt>)
    Assert.AreEqual (BitVector.ofUInt32 5ul 16<rt>,
                     BitVector.ofInt64 5L 16<rt>)
    Assert.AreEqual (BitVector.ofInt64 -5L 128<rt>,
                     BitVector.ofInt32 -5l 128<rt>)
    Assert.AreEqual (int64 -1,
                     BitVector.ofInt64 -1L 64<rt> |> BitVector.toInt64)

  [<TestMethod>]
  member __.``Comparison`` () =
    let lt = BitVector.lt
    let gt = BitVector.gt
    let ge = BitVector.ge
    let tr = BitVector.one 1<rt>
    (lt (BitVector.ofInt32 5l 16<rt>) (BitVector.ofInt32 10l 16<rt>) = tr)
    |> Assert.IsTrue
    (gt (BitVector.ofInt32 21l 128<rt>) (BitVector.ofInt32 20l 128<rt>) = tr)
    |> Assert.IsTrue
    (ge (BitVector.ofInt32 5l 32<rt>) (BitVector.ofInt32 5l 32<rt>) = tr)
    |> Assert.IsTrue
    (BitVector.ofInt32 1l 32<rt> <> BitVector.ofInt32 -1l 32<rt>)
    |> Assert.IsTrue
    (BitVector.ofInt32 1l 64<rt> <> BitVector.ofInt32 1l 8<rt>)
    |> Assert.IsTrue

  [<TestMethod>]
  member __.``Basic Arithmetic 1`` () =
    let n1 = BitVector.ofInt32 1l 64<rt>
    let n2 = BitVector.ofInt32 -1l 64<rt>
    Assert.AreEqual (BitVector.add n1 n2, BitVector.zero 64<rt>)
    Assert.AreEqual (BitVector.sub n1 n2, BitVector.ofInt32 2l 64<rt>)
    Assert.AreEqual (BitVector.sub n2 n1, BitVector.ofInt32 -2l 64<rt>)
    Assert.AreEqual (BitVector.mul n1 n2, n2)
    Assert.AreEqual (BitVector.div n1 n2, BitVector.zero 64<rt>)
    Assert.AreEqual (BitVector.sdiv n1 n2, n2)

  [<TestMethod>]
  member __.``Basic Arithmetic 2`` () =
    let e1 = BitVector.ofUBInt 10I 8<rt>
    let e2 = BitVector.ofUBInt 3I 8<rt>
    let n1 = BitVector.ofUInt64 (uint8 -10 |> uint64) 8<rt>
    let n2 = BitVector.ofUInt64 (uint8 -3 |> uint64) 8<rt>
    Assert.AreEqual (BitVector.toString <| BitVector.add e1 e2, "0xD:I8")
    Assert.AreEqual (BitVector.toString <| BitVector.sub e1 e2, "0x7:I8")
    Assert.AreEqual (BitVector.toString <| BitVector.mul e1 e2, "0x1E:I8")
    Assert.AreEqual (BitVector.toString <| BitVector.div e1 e2, "0x3:I8")
    Assert.AreEqual (BitVector.toString <| BitVector.sdiv e1 n2, "0xFD:I8")
    Assert.AreEqual (BitVector.toString <| BitVector.sdiv n1 e2, "0xFD:I8")
    let e1 = BitVector.ofUBInt 10000I 16<rt>
    let e2 = BitVector.ofUBInt 3000I 16<rt>
    let n1 = BitVector.ofInt32 (-10000l) 16<rt>
    let n2 = BitVector.ofInt32 (-3000l) 16<rt>
    Assert.AreEqual (BitVector.toString <| BitVector.add e1 e2, "0x32C8:I16")
    Assert.AreEqual (BitVector.toString <| BitVector.sub e1 e2, "0x1B58:I16")
    Assert.AreEqual (BitVector.toString <| BitVector.mul e1 e2, "0xC380:I16")
    Assert.AreEqual (BitVector.toString <| BitVector.div e1 e2, "0x3:I16")
    Assert.AreEqual (BitVector.toString <| BitVector.sdiv e1 n2, "0xFFFD:I16")
    Assert.AreEqual (BitVector.toString <| BitVector.sdiv n1 e2, "0xFFFD:I16")

  [<TestMethod>]
  member __.``Basic Arithmetic 3`` () =
    let e1 = BitVector.ofUBInt 100000I 32<rt>
    let e2 = BitVector.ofUBInt 30000I 32<rt>
    let n1 = BitVector.ofInt32 (-100000l) 32<rt>
    let n2 = BitVector.ofInt32 (-30000l) 32<rt>
    Assert.AreEqual (BitVector.toString <| BitVector.add e1 e2, "0x1FBD0:I32")
    Assert.AreEqual (BitVector.toString <| BitVector.sub e1 e2, "0x11170:I32")
    Assert.AreEqual (BitVector.toString <| BitVector.mul e1 e2,
                     "0xB2D05E00:I32")
    Assert.AreEqual (BitVector.toString <| BitVector.div e1 e2, "0x3:I32")
    Assert.AreEqual (BitVector.toString <| BitVector.sdiv e1 n2,
                     "0xFFFFFFFD:I32")
    Assert.AreEqual (BitVector.toString <| BitVector.sdiv n1 e2,
                     "0xFFFFFFFD:I32")
    let e1 = BitVector.ofUBInt 1000000I 64<rt>
    let e2 = BitVector.ofUBInt 300000I 64<rt>
    let n1 = BitVector.ofInt64 (-1000000L) 64<rt>
    let n2 = BitVector.ofInt64 (-300000L) 64<rt>
    Assert.AreEqual (BitVector.toString <| BitVector.add e1 e2, "0x13D620:I64")
    Assert.AreEqual (BitVector.toString <| BitVector.sub e1 e2, "0xAAE60:I64")
    Assert.AreEqual (BitVector.toString <| BitVector.mul e1 e2,
                     "0x45D964B800:I64")
    Assert.AreEqual (BitVector.toString <| BitVector.div e1 e2, "0x3:I64")
    Assert.AreEqual (BitVector.toString <| BitVector.sdiv e1 n2,
                      "0xFFFFFFFFFFFFFFFD:I64")
    Assert.AreEqual (BitVector.toString <| BitVector.sdiv n1 e2,
                      "0xFFFFFFFFFFFFFFFD:I64")

  [<TestMethod>]
  member __.``Basic Arithmetic 4`` () =
    let e1 = BitVector.ofUBInt 10000000I 128<rt>
    let e2 = BitVector.ofUBInt 3000000I 128<rt>
    let n1 = BitVector.ofInt64 (-10000000L) 128<rt>
    let n2 = BitVector.ofInt64 (-3000000L) 128<rt>
    Assert.AreEqual (BitVector.toString <| BitVector.add e1 e2, "0xC65D40:I128")
    Assert.AreEqual (BitVector.toString <| BitVector.sub e1 e2, "0x6ACFC0:I128")
    Assert.AreEqual (BitVector.toString <| BitVector.mul e1 e2,
                     "0x1B48EB57E000:I128")
    Assert.AreEqual (BitVector.toString <| BitVector.div e1 e2, "0x3:I128")
    Assert.AreEqual (BitVector.toString <| BitVector.sdiv e1 n2,
                      "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD:I128")
    Assert.AreEqual (BitVector.toString <| BitVector.sdiv n1 e2,
                      "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD:I128")
    let e1 = BitVector.ofInt32 0xDFFFFDEA 32<rt>
    let e2 = BitVector.ofInt32 1 32<rt>
    Assert.AreEqual (BitVector.toString <| BitVector.sar e1 e2,
                     "0xEFFFFEF5:I32")

  [<TestMethod>]
  member __.``Basic Arithmetic 5`` () =
    // test for signed division
    let n1 = BitVector.ofInt64 (-4L) 64<rt>
    let n2 = BitVector.ofInt64 (-2L) 64<rt>
    Assert.AreEqual (BitVector.toString <| BitVector.sdiv n1 n2, "0x2:I64")
    Assert.AreEqual (BitVector.toString <| BitVector.sdiv n2 n1, "0x0:I64")
    let n1 = BitVector.ofInt64 (-4L) 64<rt>
    let n2 = BitVector.ofInt64 (2L) 64<rt>
    Assert.AreEqual (BitVector.toString <| BitVector.sdiv n1 n2,
                     "0xFFFFFFFFFFFFFFFE:I64")
    Assert.AreEqual (BitVector.toString <| BitVector.sdiv n2 n1, "0x0:I64")
    let n1 = BitVector.ofInt64 (4L) 64<rt>
    let n2 = BitVector.ofInt64 (-2L) 64<rt>
    Assert.AreEqual (BitVector.toString <| BitVector.sdiv n1 n2,
                     "0xFFFFFFFFFFFFFFFE:I64")
    Assert.AreEqual (BitVector.toString <| BitVector.sdiv n2 n1, "0x0:I64")

  [<TestMethod>]
  member __.``Basic Arithmetic 6`` () =
    // test for shift operations
    let n1 = BitVector.ofInt64 1L 32<rt>
    let n2 = BitVector.ofInt64 31L 32<rt>
    let n3 = BitVector.ofInt64 32L 32<rt>
    let n4 = BitVector.ofInt64 (-1L) 32<rt>
    Assert.AreEqual (BitVector.toString <| BitVector.shl n1 n2, "0x80000000:I32")
    Assert.AreEqual (BitVector.toString <| BitVector.shl n1 n3, "0x0:I32")
    Assert.AreEqual (BitVector.toString <| BitVector.shl n4 n1, "0xFFFFFFFE:I32")
    Assert.AreEqual (BitVector.toString <| BitVector.shl n4 n2, "0x80000000:I32")

    Assert.AreEqual (BitVector.toString <| BitVector.shr n1 n2, "0x0:I32")
    Assert.AreEqual (BitVector.toString <| BitVector.shr n4 n2, "0x1:I32")
    Assert.AreEqual (BitVector.toString <| BitVector.shr n4 n3, "0x0:I32")
    Assert.AreEqual (BitVector.toString <| BitVector.shr n4 n1, "0x7FFFFFFF:I32")

    Assert.AreEqual (BitVector.toString <| BitVector.sar n1 n2, "0x0:I32")
    Assert.AreEqual (BitVector.toString <| BitVector.sar n4 n3, "0xFFFFFFFF:I32")
    Assert.AreEqual (BitVector.toString <| BitVector.sar n4 n1, "0xFFFFFFFF:I32")
    Assert.AreEqual (BitVector.toString <| BitVector.sar n4 n3, "0xFFFFFFFF:I32")

  [<TestMethod>]
  member __.``Basic Arithmetic 7`` () =
    // test for 1 bit operation
    let n0 = BitVector.ofInt64 (0L) 1<rt>
    let n1 = BitVector.ofInt64 (1L) 1<rt>
    Assert.AreEqual (BitVector.toString <| BitVector.add n1 n0, "0x1:I1")
    Assert.AreEqual (BitVector.toString <| BitVector.add n1 n1, "0x0:I1")
    Assert.AreEqual (BitVector.toString <| BitVector.sub n1 n0, "0x1:I1")
    Assert.AreEqual (BitVector.toString <| BitVector.sub n1 n1, "0x0:I1")
    Assert.AreEqual (BitVector.toString <| BitVector.sub n0 n1, "0x1:I1")
    Assert.AreEqual (BitVector.toString <| BitVector.mul n1 n0, "0x0:I1")
    Assert.AreEqual (BitVector.toString <| BitVector.mul n0 n1, "0x0:I1")
    Assert.AreEqual (BitVector.toString <| BitVector.mul n1 n1, "0x1:I1")
    Assert.AreEqual (BitVector.toString <| BitVector.div n0 n1, "0x0:I1")
    Assert.AreEqual (BitVector.toString <| BitVector.div n1 n1, "0x1:I1")
    Assert.AreEqual (BitVector.toString <| BitVector.sdiv n0 n1, "0x0:I1")
    Assert.AreEqual (BitVector.toString <| BitVector.sdiv n1 n1, "0x1:I1")
    Assert.AreEqual (BitVector.toString <| BitVector.shl n1 n0, "0x1:I1")
    Assert.AreEqual (BitVector.toString <| BitVector.shl n0 n1, "0x0:I1")
    Assert.AreEqual (BitVector.toString <| BitVector.shl n1 n1, "0x0:I1")
    Assert.AreEqual (BitVector.toString <| BitVector.shr n1 n0, "0x1:I1")
    Assert.AreEqual (BitVector.toString <| BitVector.shr n0 n1, "0x0:I1")
    Assert.AreEqual (BitVector.toString <| BitVector.shr n1 n1, "0x0:I1")
    Assert.AreEqual (BitVector.toString <| BitVector.sar n1 n0, "0x1:I1")
    Assert.AreEqual (BitVector.toString <| BitVector.sar n0 n1, "0x0:I1")
    Assert.AreEqual (BitVector.toString <| BitVector.sar n1 n1, "0x0:I1")

  [<TestMethod>]
  member __.``Unsigned Modulo`` () =
    let n1 = BitVector.ofUInt32 5ul 32<rt>
    let n2 = BitVector.ofInt32 -3l 32<rt>
    Assert.AreEqual (BitVector.toString <| BitVector.modulo n1 n2, "0x5:I32")
    let n1 = BitVector.ofUBInt 5I 256<rt>
    let n2 = BitVector.ofInt64 -3L 256<rt>
    Assert.AreEqual (BitVector.toString <| BitVector.modulo n1 n2, "0x5:I256")

  [<TestMethod>]
  member __.``Signed Modulo`` () =
    // Added for signed modulo bug test
    let n1 = BitVector.ofUInt32 5ul 32<rt>
    let n2 = BitVector.ofInt32 3l 32<rt>
    Assert.AreEqual (BitVector.smodulo n1 n2, BitVector.ofInt32 2l 32<rt>)
    let n1 = BitVector.ofUBInt 5I 256<rt>
    let n2 = BitVector.ofInt64 3L 256<rt>
    Assert.AreEqual (BitVector.smodulo n1 n2, BitVector.ofInt32 2l 256<rt>)
    let n1 = BitVector.ofUInt32 5ul 32<rt>
    let n2 = BitVector.ofInt32 -3l 32<rt>
    Assert.AreEqual (BitVector.smodulo n1 n2, BitVector.ofInt32 -1l 32<rt>)
    let n1 = BitVector.ofUBInt 5I 256<rt>
    let n2 = BitVector.ofInt64 -3L 256<rt>
    Assert.AreEqual (BitVector.smodulo n1 n2, BitVector.ofInt32 -1l 256<rt>)
    let n1 = BitVector.ofInt32 -5l 32<rt>
    let n2 = BitVector.ofInt32 -3l 32<rt>
    Assert.AreEqual (BitVector.smodulo n1 n2, BitVector.ofInt32 -2l 32<rt>)
    let n1 = BitVector.ofUBInt -5I 256<rt>
    let n2 = BitVector.ofInt64 -3L 256<rt>
    Assert.AreEqual (BitVector.smodulo n1 n2, BitVector.ofInt32 -2l 256<rt>)
    let n1 = BitVector.ofInt32 -5l 32<rt>
    let n2 = BitVector.ofInt32 3l 32<rt>
    Assert.AreEqual (BitVector.smodulo n1 n2, BitVector.ofInt32 1l 32<rt>)
    let n1 = BitVector.ofUBInt -5I 256<rt>
    let n2 = BitVector.ofInt64 3L 256<rt>
    Assert.AreEqual (BitVector.smodulo n1 n2, BitVector.ofInt32 1l 256<rt>)

  [<TestMethod>]
  member __.``Logical Operators`` () =
    let n1 = BitVector.ofUBInt 100I 32<rt>
    let n2 = BitVector.ofInt32 -500l 32<rt>
    Assert.AreEqual (BitVector.toString <| BitVector.band n1 n2, "0x4:I32")
    let n1 = BitVector.ofUBInt 100I 256<rt>
    let n2 = BitVector.ofInt32 -500l 256<rt>
    Assert.AreEqual (BitVector.toString <| BitVector.band n1 n2, "0x4:I256")
    let n1 = BitVector.ofUBInt 100I 32<rt>
    let n2 = BitVector.ofInt32 -500l 32<rt>
    Assert.AreEqual (BitVector.toString <| BitVector.bor n1 n2,
                     "0xFFFFFE6C:I32")
    let n1 = BitVector.ofUBInt 100I 256<rt>
    let n2 = BitVector.ofInt32 -500l 256<rt>
    Assert.AreEqual (BitVector.bor n1 n2, BitVector.ofInt64 -404L 256<rt>)
    let n1 = BitVector.ofUBInt 100I 32<rt>
    let n2 = BitVector.ofInt32 -500l 32<rt>
    Assert.AreEqual (BitVector.toString <| BitVector.bxor n1 n2,
                     "0xFFFFFE68:I32")
    let n1 = BitVector.ofUBInt 100I 256<rt>
    let n2 = BitVector.ofInt32 -500l 256<rt>
    Assert.AreEqual (BitVector.bxor n1 n2,  BitVector.ofInt64 -408L 256<rt>)

  [<TestMethod>]
  member __.``Comparison Operators`` () =
    let n1 = BitVector.ofUBInt 100I 32<rt>
    let n2 = BitVector.ofUBInt 100I 32<rt>
    Assert.AreEqual (BitVector.slt n1 n2, BitVector.zero 1<rt>)
    Assert.AreEqual (BitVector.sle n1 n2, BitVector.one 1<rt>)
    let n1 = BitVector.ofUBInt 100I 256<rt>
    let n2 = BitVector.ofUBInt 100I 256<rt>
    Assert.AreEqual (BitVector.slt n1 n2, BitVector.zero 1<rt>)
    Assert.AreEqual (BitVector.sle n1 n2, BitVector.one 1<rt>)
    let n1 = BitVector.ofUBInt 100I 32<rt>
    let n2 = BitVector.ofInt32 -500l 32<rt>
    Assert.AreEqual (BitVector.lt n1 n2, BitVector.one 1<rt>)
    Assert.AreEqual (BitVector.le n1 n2, BitVector.one 1<rt>)
    Assert.AreEqual (BitVector.slt n1 n2, BitVector.zero 1<rt>)
    Assert.AreEqual (BitVector.sle n1 n2, BitVector.zero 1<rt>)
    let n1 = BitVector.ofUBInt 100I 256<rt>
    let n2 = BitVector.ofInt32 -500l 256<rt>
    Assert.AreEqual (BitVector.slt n1 n2, BitVector.zero 1<rt>)
    Assert.AreEqual (BitVector.sle n1 n2, BitVector.zero 1<rt>)

  [<TestMethod>]
  member __.``Unary Operators`` () =
    let n1 = BitVector.ofUBInt 100I 32<rt>
    let n2 = BitVector.ofUBInt 0I 16<rt>
    let n3 = BitVector.ofInt32 0xffffffff 32<rt>
    Assert.AreEqual (BitVector.bnot n1, BitVector.ofInt32 0xffffff9bl 32<rt>)
    Assert.AreEqual (BitVector.bnot n2, BitVector.ofInt32 0xffffl 16<rt>)
    Assert.AreEqual (BitVector.bnot n3, BitVector.ofInt32 0 32<rt>)
    Assert.AreEqual (BitVector.toString <| BitVector.neg n1, "0xFFFFFF9C:I32")
    Assert.AreEqual (BitVector.neg n2, BitVector.ofInt32 0l 16<rt>)
    let n1 = BitVector.ofUBInt 0I 128<rt>
    Assert.AreEqual (BitVector.neg n1, BitVector.ofInt32 0l 128<rt>)

  [<TestMethod>]
  member __.``Concatenation Operator`` () =
    let e1 = BitVector.ofUBInt 1000I 32<rt>
    let e2 = BitVector.ofUBInt 300I 32<rt>
    Assert.AreEqual (BitVector.toString <| BitVector.concat e1 e2,
                     "0x3E80000012C:I64")
    let e1 = BitVector.ofUBInt 1000I 32<rt>
    let e2 = BitVector.ofInt64 -300L 32<rt>
    Assert.AreEqual (BitVector.toString <| BitVector.concat e1 e2,
                     "0x3E8FFFFFED4:I64")

  [<TestMethod>]
  member __.``Size Extension``() =
    // Extension.
    let e1 = BitVector.ofInt32 -1 8<rt>
    Assert.AreEqual (BitVector.zext e1 32<rt>, BitVector.ofInt32 0xff 32<rt>)
    let e1 = BitVector.ofUInt32 0xffu 8<rt>
    Assert.AreEqual (BitVector.sext e1 32<rt>, BitVector.ofInt32 -1 32<rt>)
    let e1 = BitVector.ofInt32 0x1 8<rt>
    Assert.AreEqual (BitVector.sext e1 32<rt>, BitVector.ofInt32 1 32<rt>)

  [<TestMethod>]
  member __.``Absolute Operator``() =
    let e1 = BitVector.ofInt32 -1 8<rt>
    let e2 = BitVector.ofInt32 -16 32<rt>
    Assert.AreEqual (BitVector.toString <| BitVector.abs e1, "0x1:I8")
    Assert.AreEqual (BitVector.toString <| BitVector.abs e2, "0x10:I32")

  [<TestMethod>]
  member __.``Extract``() =
    let e1 = BitVector.ofInt32 13453 32<rt>
    Assert.AreEqual (BitVector.toString <| BitVector.extract e1 16<rt> 4,
                     "0x348:I16")

  [<TestMethod>]
  member __.``Infix Operator``() =
    let e1 = BitVector.ofInt32 4 64<rt>
    let e2 = BitVector.ofInt32 20 64<rt>
    Assert.AreEqual (e1 + e2, BitVector.ofInt32 24 64<rt>)
    Assert.AreEqual (e1 - e2, BitVector.ofInt32 -16 64<rt>)
    Assert.AreEqual (e1 * e2, BitVector.ofInt32 80 64<rt>)
    Assert.AreEqual (e1 &&& e2, BitVector.ofInt32 4 64<rt>)
    Assert.AreEqual (e1 ||| e2, BitVector.ofInt32 20 64<rt>)
    Assert.AreEqual (e1 ^^^ e2, BitVector.ofInt32 16 64<rt>)
    Assert.AreEqual (e1 / e2, BitVector.zero 64<rt>)
    Assert.AreEqual (e2 / e1, BitVector.ofInt32 5 64<rt>)
    Assert.AreEqual (e1 % e2, BitVector.ofInt32 4 64<rt>)
    Assert.AreEqual (e2 % e1, BitVector.zero 64<rt>)
    Assert.AreEqual (-e1, BitVector.ofInt32 -4 64<rt>)
