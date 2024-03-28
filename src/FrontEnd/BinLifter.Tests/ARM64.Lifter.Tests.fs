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

module B2R2.FrontEnd.Tests.ARM64Lifter

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.ARM64
open B2R2.BinIR.LowUIR.AST.InfixOp
open type Register

[<AutoOpen>]
module TestHelper =
  let num v = BitVector.OfUInt32 v 32<rt> |> AST.num

  let unwrapStmts stmts = Array.sub stmts 1 (Array.length stmts - 2)

  let isa = ISA.Init Architecture.AARCH64 Endian.Big

  let ctxt = ARM64TranslationContext isa

  let inline ( !. ) name = Register.toRegID name |> ctxt.GetRegVar

  let inline ( ++ ) (byteStr: string) (givenStmts: Stmt[]) =
    ByteArray.ofHexString byteStr, givenStmts

  let test (bytes: byte[], givenStmts) =
    let parser = ARM64Parser (isa) :> IInstructionParsable
    let ins = parser.Parse (bytes, 0UL)
    CollectionAssert.AreEqual (givenStmts, unwrapStmts <| ins.Translate ctxt)

[<TestClass>]
type ARM64UnitTest () =
  [<TestMethod>]
  member __.``[AArch64] ADD (immedate) lift test`` () =
    "114dc4ba"
    ++ [| !.X26 := AST.zext 64<rt>
           ((AST.xtlo 32<rt> !.X5 .+ num 0x371000u .+ num 0x0u)) |]
    |> test

  [<TestMethod>]
  member __.``[AArch64] ADD (extended register) lift test`` () =
    "0b3f43ff"
    ++ [| !.SP := AST.zext 64<rt>
           (AST.xtlo 32<rt> !.SP .+ AST.xtlo 32<rt> !.XZR .+ num 0x0u) |]
    |> test

  [<TestMethod>]
  member __.``[AArch64] ADD (shifted register) lift test`` () =
    "0b8e5f9b"
    ++ [| !.X27 := AST.zext 64<rt>
           (AST.xtlo 32<rt> !.X28 .+ (AST.xtlo 32<rt> !.X14 ?>> num 0x17u)
             .+ num 0x0u) |]
    |> test
