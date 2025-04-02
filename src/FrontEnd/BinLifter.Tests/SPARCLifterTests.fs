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
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.SPARC
open type Register

[<TestClass>]
type SPARCLifterTest () =
  let num v = BitVector.OfInt64 v 64<rt> |> AST.num

  let t64 id = AST.tmpvar 64<rt> id

  let isa = ISA.Init Architecture.SPARC Endian.Little

  let ctxt = SPARCTranslationContext isa

  let ( !. ) reg = Register.toRegID reg |> ctxt.GetRegVar

  let unwrapStmts stmts = Array.sub stmts 1 (Array.length stmts - 2)

  let test (bytes: byte[], givenStmts) =
    let parser = SPARCParser (isa) :> IInstructionParsable
    let ins = parser.Parse (bytes, 0UL)
    CollectionAssert.AreEqual (givenStmts, unwrapStmts <| ins.Translate ctxt)

  let ( ++ ) byteString givenStmts =
    ByteArray.ofHexString byteString, givenStmts

  [<TestMethod>]
  member __.``[SPARC] ADD (three reg operands) lift Test`` () =
    "0d80029e"
    ++ [| t64 1 := !.O2 .+ !.O5
          !.O7 := t64 1 |]
    |> test

  [<TestMethod>]
  member __.``[SPARC] ADD (two reg op, one imm op) lift Test`` () =
    "8ab6029e"
    ++ [| t64 1 := !.O2 .+ num 0xfffffffffffff68aL
          !.O7 := t64 1 |]
    |> test

  [<TestMethod>]
  member __.``[SPARC] ADD (with carry) lift Test`` () =
    "0d80429e"
    ++ [| t64 1 := !.O2 .+ !.O5 .+ AST.zext 64<rt> (AST.extract !.CCR 1<rt> 0)
          !.O7 := t64 1 |]
    |> test

  [<TestMethod>]
  member __.``[SPARC] ADD (with carry and modify icc) lift Test`` () =
    "0d80429e"
    ++ [| t64 1 := !.O2 .+ !.O5 .+ AST.zext 64<rt> (AST.extract !.CCR 1<rt> 0)
          !.O7 := t64 1 |]
    |> test
