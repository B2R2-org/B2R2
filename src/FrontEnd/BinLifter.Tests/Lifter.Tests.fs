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

namespace B2R2.FrontEnd.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting

module Lifter =
  open B2R2
  open B2R2.BinIR
  open B2R2.BinIR.LowUIR

  [<TestClass>]
  type TestClass () =

    [<TestMethod>]
    member __.``PP Test`` () =
      let e = BitVector.ofUInt32 42ul 32<rt> |> AST.num
      Assert.AreEqual (Pp.expToString e, "0x2a:I32")
      let e0 = AST.tmpvar 32<rt>
      Assert.AreEqual (Pp.expToString e0, "T_0:I32")
      let e1 = AST.tmpvar 32<rt>
      Assert.AreEqual (Pp.expToString e1, "T_1:I32")
      let e = AST.unop UnOpType.NEG e1
      Assert.AreEqual (Pp.expToString e, "(- T_1:I32)")
      let e = AST.unop UnOpType.NOT (AST.binop BinOpType.ADD e0 e1)
      Assert.AreEqual (Pp.expToString e, "(~ (T_0:I32 + T_1:I32))")
      let e = AST.load Endian.Little 32<rt> e0
      Assert.AreEqual (Pp.expToString e, "[T_0:I32]:I32")
      let e = AST.ite (AST.tmpvar 1<rt>) e0 e1
      Assert.AreEqual (Pp.expToString e, "((T_2:I1) ? (T_0:I32) : (T_1:I32))")

// vim: set tw=80 sts=2 sw=2:
