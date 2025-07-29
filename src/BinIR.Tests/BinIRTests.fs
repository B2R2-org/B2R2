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

namespace B2R2.BinIR.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR.LowUIR

[<TestClass>]
type BinIRTests() =

  [<TestMethod>]
  member _.``Inline Optimization Test``() =
    let n1 = AST.num <| BitVector.OfInt32 1 32<rt>
    let n2 = AST.num <| BitVector.OfInt32 2 32<rt>
    let n3 = AST.num <| BitVector.OfInt32 3 32<rt>
    let e1 = AST.add (AST.mul n1 n2) n3
    let e2 = AST.sub (AST.mul n2 n3) n1
    Assert.AreEqual<Expr>(e1, e2)

  [<TestMethod>]
  member _.``Expr Commutative Equivalence Test 1``() =
    let n1 = AST.tmpvar 32<rt> 0
    let n2 = AST.tmpvar 32<rt> 1
    let e1 = AST.add n1 n2
    let e2 = AST.add n2 n1
#if ! HASHCONS
    Assert.AreNotEqual(e1, e2)
#else
    Assert.AreEqual(e1, e2)
    Assert.AreEqual<int>(e1.GetHashCode(), e2.GetHashCode())
#endif

  [<TestMethod>]
  member _.``Expr Commutative Equivalence Test 2``() =
    let n1 = AST.tmpvar 32<rt> 0
    let n2 = AST.tmpvar 32<rt> 1
    let n3 = AST.tmpvar 32<rt> 2
    let e1 = AST.mul n3 (AST.div n1 n2)
    let e2 = AST.mul (AST.div n1 n2) n3
#if ! HASHCONS
    Assert.AreNotEqual(e1, e2)
#else
    Assert.AreEqual(e1, e2)
    Assert.AreEqual<int>(e1.GetHashCode(), e2.GetHashCode())
#endif
