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

module B2R2.FrontEnd.Tests.AVRLifter

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter.AVR
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR.AST.InfixOp

let isa = ISA.Init Architecture.AVR Endian.Little

let struct (ctxt, _) = AVR.Basis.init isa

let inline ( !. ) (ctxt: TranslationContext) name =
  Register.toRegID name |> ctxt.GetRegVar

let private test (bytes: byte[]) len (actStmts: Stmt[])  =
  let reader = BinReader.binReaderLE
  let span = System.ReadOnlySpan bytes
  let ins = Parser.parse span reader 0UL
  let expStmts = (Lifter.translate ins.Info len ctxt).ToStmts ()
  Assert.AreEqual (Array.toList expStmts, Array.toList actStmts)

[<TestClass>]
type AVRUnitTest () =
  [<TestMethod>]
  member __.``[AVR] Instructions with start and end statements lift Test`` () =
    test [| 0x00uy; 0x00uy |] 2u [| AST.ismark 2u; AST.iemark 2u |]

  [<TestMethod>]
  member __.``[AVR] Instructions with Put statements lift Test`` () =
    test [| 0x4cuy; 0x2fuy |] 2u
         [| AST.ismark 2u
            (!.ctxt R.R20 := !.ctxt R.R28)
            AST.iemark 2u |]
    test [| 0x54uy; 0x01uy |] 2u
         [| AST.ismark 2u
            (!.ctxt R.R10 := !.ctxt R.R8)
            (!.ctxt R.R11 := !.ctxt R.R9)
            AST.iemark 2u |]

  [<TestMethod>]
  member __.``[AVR] Put statements for flag registers lift Test`` () =
    test [| 0xf8uy; 0x94uy |] 2u
         [| AST.ismark 2u
            (!.ctxt R.IF := AST.b0)
            AST.iemark 2u |]
    test [| 0x11uy; 0x24uy |] 2u
         [| AST.ismark 2u
            (!.ctxt R.R1 := !.ctxt R.R1 <+> !.ctxt R.R1)
            (!.ctxt R.VF := AST.b0)
            (!.ctxt R.NF := AST.xthi 1<rt> (!.ctxt R.R1))
            (!.ctxt R.ZF := !. ctxt R.R1 == AST.num0 8<rt>)
            (!.ctxt R.SF := !.ctxt R.NF <+> !.ctxt R.VF)
            AST.iemark 2u |]

  [<TestMethod>]
  member __.``[AVR] Load statements lift Test`` () =
    test [| 0x6fuy; 0x92uy |] 2u
         [| AST.ismark 2u
            (AST.loadLE 8<rt> (!.ctxt R.SP) := !.ctxt R.R6)
            (!.ctxt R.SP := !.ctxt R.SP .- AST.num1 16<rt>)
            AST.iemark 2u |]
