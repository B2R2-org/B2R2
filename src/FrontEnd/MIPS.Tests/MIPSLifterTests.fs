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

namespace B2R2.FrontEnd.MIPS.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingOperators
open B2R2.FrontEnd.MIPS
open type Register

[<TestClass>]
type MIPSLifterTests () =
  let checkOverflowOnAdd e1 e2 r =
    let e1High = AST.extract e1 1<rt> 31
    let e2High = AST.extract e2 1<rt> 31
    let rHigh = AST.extract r 1<rt> 31
    (e1High == e2High) .& (e1High <+> rHigh)

  let unwrapStmts stmts = Array.sub stmts 1 (Array.length stmts - 2)

  let ( ++ ) (byteStr: string) (givenStmts: Stmt[]) =
    ByteArray.ofHexString byteStr, givenStmts

  let test isa ctxt (bytes: byte[], givenStmts) =
    let parser = MIPSParser (isa) :> IInstructionParsable
    let ins = parser.Parse (bytes, 0UL)
    CollectionAssert.AreEqual (givenStmts, unwrapStmts <| ins.Translate ctxt)

  [<TestMethod>]
  member _.``[MIPS64] ADD lift test`` () =
    let isa = ISA.Init Architecture.MIPS64 Endian.Big
    let ctxt = MIPSTranslationContext isa
    let ( !. ) name = Register.toRegID name |> ctxt.GetRegVar
    let ir = IRBuilder (241)
    let lblL0 = !%ir "L0"
    let lblL1 = !%ir "L1"
    let lblEnd = !%ir "End"
    let signExtLo64 = AST.sext 64<rt> <| AST.xtlo 32<rt> (!.R1 .+ !.R2)
    let cond = checkOverflowOnAdd !.R1 !.R2 signExtLo64
    "00220820"
    ++ [| AST.cjmp cond (AST.jmpDest lblL0) (AST.jmpDest lblL1)
          AST.lmark lblL0
          AST.sideEffect (Exception "int overflow")
          AST.jmp (AST.jmpDest lblEnd)
          AST.lmark lblL1
          !.R1 := AST.sext 64<rt> <| AST.xtlo 32<rt> (!.R1 .+ !.R2)
          AST.lmark lblEnd |]
    |> test isa ctxt

  [<TestMethod>]
  member _.``[MIPS32] ADD lift test`` () =
    let isa = ISA.Init Architecture.MIPS32 Endian.Big
    let ctxt = MIPSTranslationContext isa
    let ( !. ) name = Register.toRegID name |> ctxt.GetRegVar
    let ir = IRBuilder 241
    let lblL0 = !%ir "L0"
    let lblL1 = !%ir "L1"
    let lblEnd = !%ir "End"
    let cond = checkOverflowOnAdd !.R1 !.R2 (!.R1 .+ !.R2)
    "00220820"
    ++ [| AST.cjmp cond (AST.jmpDest lblL0) (AST.jmpDest lblL1)
          AST.lmark lblL0
          AST.sideEffect (Exception "int overflow")
          AST.jmp (AST.jmpDest lblEnd)
          AST.lmark lblL1
          !.R1 := !.R1 .+ !.R2
          AST.lmark lblEnd |]
    |> test isa ctxt
