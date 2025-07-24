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
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR

[<TestClass>]
type PpTests () =
  let assertEqualOfStrAndStmt (expected: string) stmt =
    (expected, Pp.stmtToString stmt)
    |> Assert.AreEqual<string>

  let assertEqualOfStrAndExpr (expected: string) expr =
    (expected, Pp.expToString expr)
    |> Assert.AreEqual<string>

  let tmpvarNum0 = AST.tmpvar 32<rt> 0

  let tmpvarNum1 = AST.tmpvar 32<rt> 1

  [<TestMethod>]
  member _.``PP bitVector from uint32 test`` () =
    let e = BitVector.OfUInt32(42ul, 32<rt>) |> AST.num
    assertEqualOfStrAndExpr "0x2a:I32" e

  [<TestMethod>]
  member _.``PP construct tempVar test (1)`` () =
    assertEqualOfStrAndExpr "T_0:I32" tmpvarNum0

  [<TestMethod>]
  member _.``PP construct tempVar test (2)`` () =
    assertEqualOfStrAndExpr "T_1:I32" tmpvarNum1

  [<TestMethod>]
  member _.``PP binary operator test (1)`` () =
    let e = AST.binop BinOpType.ADD tmpvarNum0 tmpvarNum1
    assertEqualOfStrAndExpr "(T_0:I32 + T_1:I32)" e

  [<TestMethod>]
  member _.``PP binary operator test (2)`` () =
    let e = AST.binop BinOpType.AND tmpvarNum0 tmpvarNum1
    assertEqualOfStrAndExpr "(T_0:I32 & T_1:I32)" e

  [<TestMethod>]
  member _.``PP binary operator test (3)`` () =
    let e = AST.binop BinOpType.DIV tmpvarNum0 tmpvarNum1
    assertEqualOfStrAndExpr "(T_0:I32 / T_1:I32)" e

  [<TestMethod>]
  member _.``PP unary operator test (1)`` () =
    assertEqualOfStrAndExpr "(- T_1:I32)" (AST.unop UnOpType.NEG tmpvarNum1)

  [<TestMethod>]
  member _.``PP unary operator test (2)`` () =
    let binop = AST.binop BinOpType.ADD tmpvarNum0 tmpvarNum1
    let e = AST.unop UnOpType.NOT binop
    assertEqualOfStrAndExpr "(~ (T_0:I32 + T_1:I32))" e

  [<TestMethod>]
  member _.``PP construct load test (1)`` () =
    let e = AST.load Endian.Little 32<rt> tmpvarNum0
    assertEqualOfStrAndExpr "[T_0:I32]:I32" e

  [<TestMethod>]
  member _.``PP construct load test (2)`` () =
    let e = AST.load Endian.Big 64<rt> tmpvarNum0
    assertEqualOfStrAndExpr "[T_0:I32]:I64" e

  [<TestMethod>]
  member _.``PP construct ite test`` () =
    let e = AST.ite (AST.tmpvar 1<rt> 2) tmpvarNum0 tmpvarNum1
    assertEqualOfStrAndExpr "((T_2:I1) ? (T_0:I32) : (T_1:I32))" e

  [<TestMethod>]
  member _.``PP relative operator test`` () =
    let e = AST.relop RelOpType.EQ tmpvarNum0 tmpvarNum1
    assertEqualOfStrAndExpr "(T_0:I32 = T_1:I32)" e

  [<TestMethod>]
  member _.``PP conditional jump test`` () =
    let e = AST.cjmp tmpvarNum0 tmpvarNum0 tmpvarNum1
    assertEqualOfStrAndStmt "if T_0:I32 then jmp T_0:I32 else jmp T_1:I32" e

  [<TestMethod>]
  member _.``PP interConditional jump test`` () =
    let e = AST.intercjmp tmpvarNum0 tmpvarNum0 tmpvarNum1
    assertEqualOfStrAndStmt "if T_0:I32 then ijmp T_0:I32 else ijmp T_1:I32" e

  [<TestMethod>]
  member _.``PP assignment statement test`` () =
    let e = AST.assign tmpvarNum0 tmpvarNum1
    assertEqualOfStrAndStmt "T_0:I32 := T_1:I32" e
