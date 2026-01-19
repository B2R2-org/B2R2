(*
  B2R2 - the Next-Generation Reversing Platform

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

namespace B2R2.Core.Tests

open System
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open type B2R2.BitVector

[<TestClass>]
type BitVectorTests() =

  [<TestMethod>]
  member _.``Equality``() =
    Assert.AreEqual<BitVector>(BitVector(5l, 16<rt>), BitVector(5I, 16<rt>))
    Assert.AreEqual<BitVector>(BitVector(5ul, 16<rt>), BitVector(5L, 16<rt>))
    Assert.AreEqual<BitVector>(BitVector(-5L, 128<rt>), BitVector(-5l, 128<rt>))
    Assert.AreEqual<int64>(int64 -1, BitVector(-1L, 64<rt>) |> ToInt64)

  [<TestMethod>]
  member _.``Comparison``() =
    let tr = One 1<rt>
    Assert.IsTrue(Lt(BitVector(5l, 16<rt>), BitVector(10l, 16<rt>)) = tr)
    Assert.IsTrue(Gt(BitVector(21l, 128<rt>), BitVector(20l, 128<rt>)) = tr)
    Assert.IsTrue(Ge(BitVector(5l, 32<rt>), BitVector(5l, 32<rt>)) = tr)
    Assert.IsTrue(BitVector(1l, 32<rt>) <> BitVector(-1l, 32<rt>))
    Assert.IsTrue(BitVector(1l, 64<rt>) <> BitVector(1l, 8<rt>))

  [<TestMethod>]
  member _.``Basic Arithmetic 1``() =
    let n1 = BitVector(1l, 64<rt>)
    let n2 = BitVector(-1l, 64<rt>)
    Assert.AreEqual(Add(n1, n2), Zero 64<rt>)
    Assert.AreEqual(Sub(n1, n2), BitVector(2l, 64<rt>))
    Assert.AreEqual(Sub(n2, n1), BitVector(-2l, 64<rt>))
    Assert.AreEqual(Mul(n1, n2), n2)
    Assert.AreEqual(Div(n1, n2), Zero 64<rt>)
    Assert.AreEqual(SDiv(n1, n2), n2)

  [<TestMethod>]
  member _.``Basic Arithmetic 2``() =
    let e1 = BitVector(10I, 8<rt>)
    let e2 = BitVector(3I, 8<rt>)
    let n1 = BitVector(uint8 -10 |> uint64, 8<rt>)
    let n2 = BitVector(uint8 -3 |> uint64, 8<rt>)
    Assert.AreEqual<string>(ToString(Add(e1, e2)), "0xd:I8")
    Assert.AreEqual<string>(ToString(Sub(e1, e2)), "0x7:I8")
    Assert.AreEqual<string>(ToString(Mul(e1, e2)), "0x1e:I8")
    Assert.AreEqual<string>(ToString(Div(e1, e2)), "0x3:I8")
    Assert.AreEqual<string>(ToString(SDiv(e1, n2)), "0xfd:I8")
    Assert.AreEqual<string>(ToString(SDiv(n1, e2)), "0xfd:I8")
    let e1 = BitVector(10000I, 16<rt>)
    let e2 = BitVector(3000I, 16<rt>)
    let n1 = BitVector(-10000l, 16<rt>)
    let n2 = BitVector(-3000l, 16<rt>)
    Assert.AreEqual<string>(ToString(Add(e1, e2)), "0x32c8:I16")
    Assert.AreEqual<string>(ToString(Sub(e1, e2)), "0x1b58:I16")
    Assert.AreEqual<string>(ToString(Mul(e1, e2)), "0xc380:I16")
    Assert.AreEqual<string>(ToString(Div(e1, e2)), "0x3:I16")
    Assert.AreEqual<string>(ToString(SDiv(e1, n2)), "0xfffd:I16")
    Assert.AreEqual<string>(ToString(SDiv(n1, e2)), "0xfffd:I16")

  [<TestMethod>]
  member _.``Basic Arithmetic 3``() =
    let e1 = BitVector(100000I, 32<rt>)
    let e2 = BitVector(30000I, 32<rt>)
    let n1 = BitVector(-100000l, 32<rt>)
    let n2 = BitVector(-30000l, 32<rt>)
    Assert.AreEqual<string>(ToString(Add(e1, e2)), "0x1fbd0:I32")
    Assert.AreEqual<string>(ToString(Sub(e1, e2)), "0x11170:I32")
    Assert.AreEqual<string>(ToString(Mul(e1, e2)), "0xb2d05e00:I32")
    Assert.AreEqual<string>(ToString(Div(e1, e2)), "0x3:I32")
    Assert.AreEqual<string>(ToString(SDiv(e1, n2)), "0xfffffffd:I32")
    Assert.AreEqual<string>(ToString(SDiv(n1, e2)), "0xfffffffd:I32")
    let e1 = BitVector(1000000I, 64<rt>)
    let e2 = BitVector(300000I, 64<rt>)
    let n1 = BitVector(-1000000L, 64<rt>)
    let n2 = BitVector(-300000L, 64<rt>)
    Assert.AreEqual<string>(ToString(Add(e1, e2)), "0x13d620:I64")
    Assert.AreEqual<string>(ToString(Sub(e1, e2)), "0xaae60:I64")
    Assert.AreEqual<string>(ToString(Mul(e1, e2)), "0x45d964b800:I64")
    Assert.AreEqual<string>(ToString(Div(e1, e2)), "0x3:I64")
    Assert.AreEqual<string>(ToString(SDiv(e1, n2)), "0xfffffffffffffffd:I64")
    Assert.AreEqual<string>(ToString(SDiv(n1, e2)), "0xfffffffffffffffd:I64")

  [<TestMethod>]
  member _.``Basic Arithmetic 4``() =
    let e1 = BitVector(10000000I, 128<rt>)
    let e2 = BitVector(3000000I, 128<rt>)
    let n1 = BitVector(-10000000L, 128<rt>)
    let n2 = BitVector(-3000000L, 128<rt>)
    Assert.AreEqual<string>(ToString(Add(e1, e2)), "0xc65d40:I128")
    Assert.AreEqual<string>(ToString(Sub(e1, e2)), "0x6acfc0:I128")
    Assert.AreEqual<string>(ToString(Mul(e1, e2)), "0x1b48eb57e000:I128")
    Assert.AreEqual<string>(ToString(Div(e1, e2)), "0x3:I128")
    Assert.AreEqual<string>(ToString(SDiv(e1, n2)),
                             "0xfffffffffffffffffffffffffffffffd:I128")
    Assert.AreEqual<string>(ToString(SDiv(n1, e2)),
                             "0xfffffffffffffffffffffffffffffffd:I128")
    let e1 = BitVector(0xDFFFFDEA, 32<rt>)
    let e2 = BitVector(1, 32<rt>)
    Assert.AreEqual<string>(ToString(Sar(e1, e2)), "0xeffffef5:I32")

  [<TestMethod>]
  member _.``Basic Arithmetic 5``() =
    (* test for signed division *)
    let n1 = BitVector(-4L, 64<rt>)
    let n2 = BitVector(-2L, 64<rt>)
    Assert.AreEqual<string>(ToString(SDiv(n1, n2)), "0x2:I64")
    Assert.AreEqual<string>(ToString(SDiv(n2, n1)), "0x0:I64")
    let n1 = BitVector(-4L, 64<rt>)
    let n2 = BitVector(2L, 64<rt>)
    Assert.AreEqual<string>(ToString(SDiv(n1, n2)), "0xfffffffffffffffe:I64")
    Assert.AreEqual<string>(ToString(SDiv(n2, n1)), "0x0:I64")
    let n1 = BitVector(4L, 64<rt>)
    let n2 = BitVector(-2L, 64<rt>)
    Assert.AreEqual<string>(ToString(SDiv(n1, n2)), "0xfffffffffffffffe:I64")
    Assert.AreEqual<string>(ToString(SDiv(n2, n1)), "0x0:I64")

  [<TestMethod>]
  member _.``Basic Arithmetic 6``() =
    (* test for shift operations *)
    let n1 = BitVector(1L, 32<rt>)
    let n2 = BitVector(31L, 32<rt>)
    let n3 = BitVector(32L, 32<rt>)
    let n4 = BitVector(-1L, 32<rt>)
    Assert.AreEqual<string>(ToString(Shl(n1, n2)), "0x80000000:I32")
    Assert.AreEqual<string>(ToString(Shl(n1, n3)), "0x0:I32")
    Assert.AreEqual<string>(ToString(Shl(n4, n1)), "0xfffffffe:I32")
    Assert.AreEqual<string>(ToString(Shl(n4, n2)), "0x80000000:I32")
    Assert.AreEqual<string>(ToString(Shr(n1, n2)), "0x0:I32")
    Assert.AreEqual<string>(ToString(Shr(n4, n2)), "0x1:I32")
    Assert.AreEqual<string>(ToString(Shr(n4, n3)), "0x0:I32")
    Assert.AreEqual<string>(ToString(Shr(n4, n1)), "0x7fffffff:I32")
    Assert.AreEqual<string>(ToString(Sar(n1, n2)), "0x0:I32")
    Assert.AreEqual<string>(ToString(Sar(n4, n3)), "0xffffffff:I32")
    Assert.AreEqual<string>(ToString(Sar(n4, n1)), "0xffffffff:I32")
    Assert.AreEqual<string>(ToString(Sar(n4, n3)), "0xffffffff:I32")

  [<TestMethod>]
  member _.``Basic Arithmetic 7``() =
    (* test for 1 bit operation *)
    let n0 = BitVector(0L, 1<rt>)
    let n1 = BitVector(1L, 1<rt>)
    Assert.AreEqual<string>(ToString(Add(n1, n0)), "0x1:I1")
    Assert.AreEqual<string>(ToString(Add(n1, n1)), "0x0:I1")
    Assert.AreEqual<string>(ToString(Sub(n1, n0)), "0x1:I1")
    Assert.AreEqual<string>(ToString(Sub(n1, n1)), "0x0:I1")
    Assert.AreEqual<string>(ToString(Sub(n0, n1)), "0x1:I1")
    Assert.AreEqual<string>(ToString(Mul(n1, n0)), "0x0:I1")
    Assert.AreEqual<string>(ToString(Mul(n0, n1)), "0x0:I1")
    Assert.AreEqual<string>(ToString(Mul(n1, n1)), "0x1:I1")
    Assert.AreEqual<string>(ToString(Div(n0, n1)), "0x0:I1")
    Assert.AreEqual<string>(ToString(Div(n1, n1)), "0x1:I1")
    Assert.AreEqual<string>(ToString(SDiv(n0, n1)), "0x0:I1")
    Assert.AreEqual<string>(ToString(SDiv(n1, n1)), "0x1:I1")
    Assert.AreEqual<string>(ToString(Shl(n1, n0)), "0x1:I1")
    Assert.AreEqual<string>(ToString(Shl(n0, n1)), "0x0:I1")
    Assert.AreEqual<string>(ToString(Shl(n1, n1)), "0x0:I1")
    Assert.AreEqual<string>(ToString(Shr(n1, n0)), "0x1:I1")
    Assert.AreEqual<string>(ToString(Shr(n0, n1)), "0x0:I1")
    Assert.AreEqual<string>(ToString(Shr(n1, n1)), "0x0:I1")
    Assert.AreEqual<string>(ToString(Sar(n1, n0)), "0x1:I1")
    Assert.AreEqual<string>(ToString(Sar(n0, n1)), "0x0:I1")
    Assert.AreEqual<string>(ToString(Sar(n1, n1)), "0x1:I1")

  [<TestMethod>]
  member _.``Shift by a Large Amount``() =
    let n1 = BitVector(1ul, 32<rt>)
    let n2 = BitVector(128, 32<rt>)
    let n3 = BitVector(0x8000000000000000UL, 64<rt>)
    let n4 = BitVector(64, 64<rt>)
    let n5 = BitVector(1I <<< 127, 128<rt>)
    let n6 = BitVector(128, 128<rt>)
    Assert.AreEqual<string>(ToString(Shr(n1, n2)), "0x0:I32")
    Assert.AreEqual<string>(ToString(Shl(n1, n2)), "0x0:I32")
    Assert.AreEqual<string>(ToString(Shr(n3, n4)), "0x0:I64")
    Assert.AreEqual<string>(ToString(Sar(n3, n4)), "0xffffffffffffffff:I64")
    Assert.AreEqual<string>(ToString(Shl(n3, n4)), "0x0:I64")
    Assert.AreEqual<string>(ToString(Shr(n5, n6)), "0x0:I128")
    Assert.AreEqual<string>(ToString(Sar(n5, n6)),
                            "0xffffffffffffffffffffffffffffffff:I128")
    Assert.AreEqual<string>(ToString(Shl(n5, n6)), "0x0:I128")

  [<TestMethod>]
  member _.``Unsigned Modulo``() =
    let n1 = BitVector(5ul, 32<rt>)
    let n2 = BitVector(-3l, 32<rt>)
    Assert.AreEqual<string>(ToString(Modulo(n1, n2)), "0x5:I32")
    let n1 = BitVector(5I, 256<rt>)
    let n2 = BitVector(-3L, 256<rt>)
    Assert.AreEqual<string>(ToString(Modulo(n1, n2)), "0x5:I256")

  [<TestMethod>]
  member _.``Signed Modulo``() =
    (* Added for signed modulo bug test *)
    let n1 = BitVector(5ul, 32<rt>)
    let n2 = BitVector(3l, 32<rt>)
    Assert.AreEqual(SModulo(n1, n2), BitVector(2, 32<rt>))
    let n1 = BitVector(5I, 256<rt>)
    let n2 = BitVector(3L, 256<rt>)
    Assert.AreEqual(SModulo(n1, n2), BitVector(2, 256<rt>))
    let n1 = BitVector(5ul, 32<rt>)
    let n2 = BitVector(-3l, 32<rt>)
    Assert.AreEqual(SModulo(n1, n2), BitVector(2, 32<rt>))
    let n1 = BitVector(5I, 256<rt>)
    let n2 = BitVector(-3L, 256<rt>)
    Assert.AreEqual(SModulo(n1, n2), BitVector(2, 256<rt>))
    let n1 = BitVector(-5l, 32<rt>)
    let n2 = BitVector(-3l, 32<rt>)
    Assert.AreEqual(SModulo(n1, n2), BitVector(-2, 32<rt>))
    let n1 = BitVector(-5I, 256<rt>)
    let n2 = BitVector(-3L, 256<rt>)
    Assert.AreEqual(SModulo(n1, n2), BitVector(-2, 256<rt>))
    let n1 = BitVector(-5l, 32<rt>)
    let n2 = BitVector(3l, 32<rt>)
    Assert.AreEqual(SModulo(n1, n2), BitVector(-2, 32<rt>))
    let n1 = BitVector(-5I, 256<rt>)
    let n2 = BitVector(3L, 256<rt>)
    Assert.AreEqual(SModulo(n1, n2), BitVector(-2, 256<rt>))
    (* zero value test *)
    let n1 = BitVector(6ul, 32<rt>)
    let n2 = BitVector(3l, 32<rt>)
    Assert.AreEqual(SModulo(n1, n2), BitVector(0l, 32<rt>))
    let n1 = BitVector(6I, 256<rt>)
    let n2 = BitVector(3L, 256<rt>)
    Assert.AreEqual(SModulo(n1, n2), BitVector(0l, 256<rt>))
    let n1 = BitVector(6ul, 32<rt>)
    let n2 = BitVector(-3l, 32<rt>)
    Assert.AreEqual(SModulo(n1, n2), BitVector(0l, 32<rt>))
    let n1 = BitVector(6I, 256<rt>)
    let n2 = BitVector(-3L, 256<rt>)
    Assert.AreEqual(SModulo(n1, n2), BitVector(0l, 256<rt>))
    let n1 = BitVector(-6l, 32<rt>)
    let n2 = BitVector(-3l, 32<rt>)
    Assert.AreEqual(SModulo(n1, n2), BitVector(0l, 32<rt>))
    let n1 = BitVector(-6I, 256<rt>)
    let n2 = BitVector(-3L, 256<rt>)
    Assert.AreEqual(SModulo(n1, n2), BitVector(0l, 256<rt>))
    let n1 = BitVector(-6l, 32<rt>)
    let n2 = BitVector(3l, 32<rt>)
    Assert.AreEqual(SModulo(n1, n2), BitVector(0l, 32<rt>))
    let n1 = BitVector(-6I, 256<rt>)
    let n2 = BitVector(3L, 256<rt>)
    Assert.AreEqual(SModulo(n1, n2), BitVector(0l, 256<rt>))

  [<TestMethod>]
  member _.``Logical Operators``() =
    let n1 = BitVector(100I, 32<rt>)
    let n2 = BitVector(-500l, 32<rt>)
    Assert.AreEqual<string>(ToString(n1 &&& n2), "0x4:I32")
    let n1 = BitVector(100I, 256<rt>)
    let n2 = BitVector(-500l, 256<rt>)
    Assert.AreEqual<string>(ToString(n1 &&& n2), "0x4:I256")
    let n1 = BitVector(100I, 32<rt>)
    let n2 = BitVector(-500l, 32<rt>)
    Assert.AreEqual<string>(ToString(n1 ||| n2), "0xfffffe6c:I32")
    let n1 = BitVector(100I, 256<rt>)
    let n2 = BitVector(-500l, 256<rt>)
    Assert.AreEqual(n1 ||| n2, BitVector(-404L, 256<rt>))
    let n1 = BitVector(100I, 32<rt>)
    let n2 = BitVector(-500l, 32<rt>)
    Assert.AreEqual<string>(ToString(n1 ^^^ n2), "0xfffffe68:I32")
    let n1 = BitVector(100I, 256<rt>)
    let n2 = BitVector(-500l, 256<rt>)
    Assert.AreEqual(n1 ^^^ n2, BitVector(-408L, 256<rt>))

  [<TestMethod>]
  member _.``Comparison Operators``() =
    let n1 = BitVector(100I, 32<rt>)
    let n2 = BitVector(100I, 32<rt>)
    Assert.AreEqual(SLt(n1, n2), Zero 1<rt>)
    Assert.AreEqual(SLe(n1, n2), One 1<rt>)
    let n1 = BitVector(100I, 256<rt>)
    let n2 = BitVector(100I, 256<rt>)
    Assert.AreEqual(SLt(n1, n2), Zero 1<rt>)
    Assert.AreEqual(SLe(n1, n2), One 1<rt>)
    let n1 = BitVector(100I, 32<rt>)
    let n2 = BitVector(-500l, 32<rt>)
    Assert.AreEqual(Lt(n1, n2), One 1<rt>)
    Assert.AreEqual(Le(n1, n2), One 1<rt>)
    Assert.AreEqual(SLt(n1, n2), Zero 1<rt>)
    Assert.AreEqual(SLe(n1, n2), Zero 1<rt>)
    let n1 = BitVector(100I, 256<rt>)
    let n2 = BitVector(-500l, 256<rt>)
    Assert.AreEqual(SLt(n1, n2), Zero 1<rt>)
    Assert.AreEqual(SLe(n1, n2), Zero 1<rt>)
    let n1 = BitVector(-200, 256<rt>)
    let n2 = BitVector(-500, 256<rt>)
    Assert.AreEqual(SLt(n1, n2), Zero 1<rt>)
    Assert.AreEqual(SLe(n1, n2), Zero 1<rt>)
    let n1 = BitVector(0x5b, 8<rt>)
    let n2 = BitVector(0x98, 8<rt>)
    Assert.AreEqual(SGt(n1, n2), One 1<rt>)

  [<TestMethod>]
  member _.``Unary Operators``() =
    let n1 = BitVector(100I, 32<rt>)
    let n2 = BitVector(0I, 16<rt>)
    let n3 = BitVector(0xffffffff, 32<rt>)
    Assert.AreEqual(~~~n1, BitVector(0xffffff9bl, 32<rt>))
    Assert.AreEqual(~~~n2, BitVector(0xffffl, 16<rt>))
    Assert.AreEqual(~~~n3, BitVector(0, 32<rt>))
    Assert.AreEqual<string>(ToString(Neg n1), "0xffffff9c:I32")
    Assert.AreEqual(Neg n2, BitVector(0l, 16<rt>))
    let n1 = BitVector(0I, 128<rt>)
    Assert.AreEqual(Neg n1, BitVector(0l, 128<rt>))

  [<TestMethod>]
  member _.``Concatenation Operator``() =
    let e1 = BitVector(1000I, 32<rt>)
    let e2 = BitVector(300I, 32<rt>)
    Assert.AreEqual<string>(ToString(Concat(e1, e2)), "0x3e80000012c:I64")
    let e1 = BitVector(1000I, 32<rt>)
    let e2 = BitVector(-300L, 32<rt>)
    Assert.AreEqual<string>(ToString(Concat(e1, e2)), "0x3e8fffffed4:I64")

  [<TestMethod>]
  member _.``Size Extension``() =
    (* Extension. *)
    let e1 = BitVector(-1, 8<rt>)
    Assert.AreEqual(ZExt(e1, 32<rt>), BitVector(0xff, 32<rt>))
    let e1 = BitVector(0xffu, 8<rt>)
    Assert.AreEqual(SExt(e1, 32<rt>), BitVector(-1, 32<rt>))
    let e1 = BitVector(0x1, 8<rt>)
    Assert.AreEqual(SExt(e1, 32<rt>), BitVector(1, 32<rt>))

  [<TestMethod>]
  member _.``Absolute Operator``() =
    let e1 = BitVector(-1, 8<rt>)
    let e2 = BitVector(-16, 32<rt>)
    Assert.AreEqual<string>(ToString(Abs e1), "0x1:I8")
    Assert.AreEqual<string>(ToString(Abs e2), "0x10:I32")

  [<TestMethod>]
  member _.``Extract``() =
    let e1 = BitVector(13453, 32<rt>)
    Assert.AreEqual<string>(ToString(Extract(e1, 16<rt>, 4)), "0x348:I16")

  [<TestMethod>]
  member _.``Infix Operator``() =
    let e1 = BitVector(4, 64<rt>)
    let e2 = BitVector(20, 64<rt>)
    Assert.AreEqual(e1 + e2, BitVector(24, 64<rt>))
    Assert.AreEqual(e1 - e2, BitVector(-16, 64<rt>))
    Assert.AreEqual(e1 * e2, BitVector(80, 64<rt>))
    Assert.AreEqual(e1 &&& e2, BitVector(4, 64<rt>))
    Assert.AreEqual(e1 ||| e2, BitVector(20, 64<rt>))
    Assert.AreEqual(e1 ^^^ e2, BitVector(16, 64<rt>))
    Assert.AreEqual(e1 / e2, Zero 64<rt>)
    Assert.AreEqual(e2 / e1, BitVector(5, 64<rt>))
    Assert.AreEqual(e1 % e2, BitVector(4, 64<rt>))
    Assert.AreEqual(e2 % e1, Zero 64<rt>)
    Assert.AreEqual(-e1, BitVector(-4, 64<rt>))

  [<TestMethod>]
  member _.``BitVector from Array (Beware of the MSB)``() =
    let arr =
      [| 0uy
         0uy
         0uy
         0uy
         0uy
         0uy
         248uy
         127uy
         0uy
         0uy
         0uy
         0uy
         0uy
         0uy
         240uy
         255uy |]
    let e1 = BitVector arr
    let t1 = BitVector(0xFFF0000000000000UL, 64<rt>)
    let t2 = BitVector(0x7FF8000000000000UL, 64<rt>)
    let e2 = Concat(t1, t2)
    Assert.AreEqual(T, Eq(e1, e2))
