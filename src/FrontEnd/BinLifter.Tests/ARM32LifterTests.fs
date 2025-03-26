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

namespace B2R2.FrontEnd.BinLifter.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.ARM32
open B2R2.BinIR.LowUIR.AST.InfixOp
open type Register

[<TestClass>]
type ARM32LifterTests () =
  let num v = BitVector.OfUInt32 v 32<rt> |> AST.num

  let t32 id = AST.tmpvar 32<rt> id

  let unwrapStmts stmts = Array.sub stmts 1 (Array.length stmts - 2)

  let isa = ISA.Init Architecture.ARMv7 Endian.Big

  let ctxt = ARM32TranslationContext isa

  let ( !. ) name = Register.toRegID name |> ctxt.GetRegVar

  let ( ++ ) (byteStr: string) givenStmts =
    ByteArray.ofHexString byteStr, givenStmts

  let test mode (bytes: byte[]) (givenStmts: Stmt[]) =
    let parser = ARM32Parser (isa, mode) :> IInstructionParsable
    let ctxt = GroundWork.CreateTranslationContext isa
    let ins = parser.Parse (bytes, 0UL)
    let liftInstr = ins.Translate ctxt
    CollectionAssert.AreEqual (givenStmts, unwrapStmts liftInstr)

  let testARM (bytes: byte[], givenStmts: Stmt[]) =
    test ArchOperationMode.ARMMode bytes givenStmts

  let testThumb (bytes: byte[], givenStmts: Stmt[]) =
    test ArchOperationMode.ThumbMode bytes givenStmts

  [<TestMethod>]
  member __.``[ARMv7] ADD (shifted register) lift test`` () =
    let shiftAmt = AST.zext 32<rt> (AST.xtlo 8<rt> !.R8)
    "e080285e"
    ++ [| t32 1 :=
            !.R0 .+ (AST.ite (shiftAmt == num 0x0u) !.LR (!.LR ?>> shiftAmt))
              .+ num 0x0u
          !.R2 := t32 1 |]
    |> testARM

  [<TestMethod>]
  member __.``[ARMv7] ADD (immedate) lift test`` () =
    "e28f0ff0"
    ++ [| t32 1 := !.PC .+ num 0x8u .+ num 0x3c0u .+ num 0x0u
          !.R0 := t32 1 |]
    |> testARM

  [<TestMethod>]
  member __.``[Thumb] ADD (Two Reg Operands) lift test`` () =
    "448b"
    ++ [| t32 1 := !.FP .+ !.R1 .+ num 0u
          !.FP := t32 1 |]
    |> testThumb

  [<TestMethod>]
  member __.``[Thumb] ADD (Three Reg Operands) lift test`` () =
    "44ec"
    ++ [| t32 1 := !.SP .+ !.IP .+ num 0u
          !.IP := t32 1 |]
    |> testThumb

  [<TestMethod>]
  member __.``[Thumb] ADD (Immediate) lift test`` () =
    "b066"
    ++ [| t32 1 := !.SP .+ num 0x198u .+ num 0u
          !.SP := t32 1 |]
    |> testThumb
