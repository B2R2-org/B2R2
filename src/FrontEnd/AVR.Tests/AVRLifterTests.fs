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

namespace B2R2.FrontEnd.AVR.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.AVR
open B2R2.BinIR.LowUIR.AST.InfixOp
open type Register

[<TestClass>]
type AVRLifterTests () =
  let isa = ISA Architecture.AVR

  let reader = BinReader.Init Endian.Little

  let regFactory = RegisterFactory isa.WordSize :> IRegisterFactory

  let unwrapStmts stmts = Array.sub stmts 1 (Array.length stmts - 2)

  let ( ++ ) (byteStr: string) givenStmts =
    ByteArray.ofHexString byteStr, givenStmts

  let ( !. ) reg = Register.toRegID reg |> regFactory.GetRegVar

  let test (bytes: byte[], givenStmts: Stmt[])  =
    let parser = AVRParser (reader) :> IInstructionParsable
    let builder = ILowUIRBuilder.Default (isa, regFactory, LowUIRStream ())
    let ins = parser.Parse (bytes, 0UL)
    CollectionAssert.AreEqual (givenStmts, unwrapStmts <| ins.Translate builder)

  [<TestMethod>]
  member _.``[AVR] Instructions with start and end statements lift Test`` () =
    "0000"
    ++ [||]
    |> test

  [<TestMethod>]
  member _.``[AVR] Instructions with Put statements lift Test (1)`` () =
    "4c2f"
    ++ [| !.R20 := !.R28 |]
    |> test

  [<TestMethod>]
  member _.``[AVR] Instructions with Put statements lift Test (2)`` () =
    "5401"
    ++ [| !.R10 := !.R8
          !.R11 := !.R9 |]
    |> test

  [<TestMethod>]
  member _.``[AVR] Put statements for flag registers lift Test (1)`` () =
    "f894"
    ++ [| !.IF := AST.b0 |]
    |> test

  [<TestMethod>]
  member _.``[AVR] Put statements for flag registers lift Test (2)`` () =
    "1124"
    ++ [| !.R1 := !.R1 <+> !.R1
          !.VF := AST.b0
          !.NF := AST.xthi 1<rt> !.R1
          !.ZF := !.R1 == AST.num0 8<rt>
          !.SF := !.NF <+> !.VF |]
    |> test

  [<TestMethod>]
  member _.``[AVR] Load statements lift Test`` () =
    "6f92"
    ++ [| AST.loadLE 8<rt> !.SP := !.R6
          !.SP := !.SP .- AST.num1 16<rt> |]
    |> test
