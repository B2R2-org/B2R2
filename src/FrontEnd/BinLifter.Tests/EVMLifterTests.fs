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
open B2R2.FrontEnd.EVM
open type Register

[<TestClass>]
type EVMLifterTests () =
  let num v rt = BitVector.OfInt32 v rt |> AST.num

  let bigint v = BitVectorBig (v, 256<rt>) |> AST.num

  let isa = ISA.Init Architecture.EVM Endian.Little

  let ctxt = EVMTranslationContext isa

  let ( !. ) name = Register.toRegID name |> ctxt.GetRegVar

  let ( ++ ) byteString givenStmts =
    ByteArray.ofHexString byteString, givenStmts

  let unwrapStmts stmts = Array.sub stmts 1 (Array.length stmts - 2)

  let test (bytes: byte[], givenStmts) =
    let parser = EVMParser (isa) :> IInstructionParsable
    let ins = parser.Parse (bytes, 0UL)
    CollectionAssert.AreEqual (givenStmts, unwrapStmts <| ins.Translate ctxt)

  [<TestMethod>]
  member __.``[EVM] PUSH8 lift test`` () =
    "670011223344556677"
    ++ [| !.SP := !.SP .+ num 32 256<rt>
          AST.store Endian.Big !.SP (bigint 4822678189205111I)
          !.GAS := !.GAS .+ num 3 64<rt> |]
    |> test

  [<TestMethod>]
  member __.``[EVM] PUSH9 lift test`` () =
    "68001122334455667788"
    ++ [| !.SP := !.SP .+ num 32 256<rt>
          AST.store Endian.Big !.SP (bigint 1234605616436508552I)
          !.GAS := !.GAS .+ num 3 64<rt> |]
    |> test

  [<TestMethod>]
  member __.``[EVM] PUSH10 lift test`` () =
    "6900112233445566778899"
    ++ [| !.SP := !.SP .+ num 32 256<rt>
          AST.store Endian.Big !.SP (bigint 316059037807746189465I)
          !.GAS := !.GAS .+ num 3 64<rt> |]
    |> test
