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

namespace B2R2.FrontEnd.SPARC.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.SPARC
open type Register

[<TestClass>]
type LifterTest() =
  let num (v: int64) = BitVector(v, 64<rt>) |> AST.num

  let t64 id = AST.tmpvar 64<rt> id

  let isa = ISA(Architecture.SPARC, Endian.Little)

  let reader = BinReader.Init Endian.Little

  let regFactory = RegisterFactory isa :> IRegisterFactory

  let ( !. ) reg = Register.toRegID reg |> regFactory.GetRegVar

  let unwrapStmts stmts = Array.sub stmts 1 (Array.length stmts - 2)

  let test (bytes: byte[], givenStmts) =
    (* a fresh builder per test: the SPARC builder carries delayed-branch state
       across instructions, which must not leak between independent tests *)
    let builder = LowUIRBuilder(isa, regFactory, LowUIRStream())
    let parser = SPARCParser(reader) :> IInstructionParsable
    let ins = parser.Parse(bytes, 0UL)
    CollectionAssert.AreEqual(givenStmts, unwrapStmts <| ins.Translate builder)

  let ( ++ ) byteString givenStmts =
    ByteArray.ofHexString byteString, givenStmts

  [<TestMethod>]
  member _.``[SPARC] ADD (three reg operands) lift Test``() =
    "0d80029e"
    ++ [| t64 1 := !.O2 .+ !.O5
          !.O7 := t64 1 |]
    |> test

  [<TestMethod>]
  member _.``[SPARC] ADD (two reg op, one imm op) lift Test``() =
    "8ab6029e"
    ++ [| t64 1 := !.O2 .+ num 0xfffffffffffff68aL
          !.O7 := t64 1 |]
    |> test

  [<TestMethod>]
  member _.``[SPARC] ADD (with carry) lift Test``() =
    "0d80429e"
    ++ [| t64 1 := !.O2 .+ !.O5 .+ AST.zext 64<rt> (AST.extract !.CCR 1<rt> 0)
          !.O7 := t64 1 |]
    |> test

  [<TestMethod>]
  member _.``[SPARC] ADD (with carry and modify icc) lift Test``() =
    "0d80429e"
    ++ [| t64 1 := !.O2 .+ !.O5 .+ AST.zext 64<rt> (AST.extract !.CCR 1<rt> 0)
          !.O7 := t64 1 |]
    |> test

  [<TestMethod>]
  member _.``[SPARC] JMPL arms a delayed jump via nPC lift Test``() =
    "0600c09f"
    ++ [| !.NPC := !.G0 .+ !.G6
          !.O7 := !.PC |]
    |> test

  [<TestMethod>]
  member _.``[SPARC] JMPL to %g0 discards the link (ret) lift Test``() =
    "08e0c781"
    ++ [| !.NPC := !.I7 .+ num 8L
          !.G0 := !.G0 |]
    |> test

  [<TestMethod>]
  member _.``[SPARC] CALL arms a delayed call via nPC lift Test``() =
    "02000040"
    ++ [| !.O7 := !.PC
          !.NPC := !.PC .+ num 8L |]
    |> test

  [<TestMethod>]
  member _.``[SPARC] RETURN arms a delayed return via nPC lift Test``() =
    "08e0cf81"
    ++ [| !.NPC := !.I7 .+ num 8L |]
    |> test

  [<TestMethod>]
  member _.``[SPARC] SAVE rotates the window in lift Test``() =
    "0240e091"
    ++ [| t64 1 := !.G1 .+ !.G2
          AST.sideEffect SaveWindow
          !.I0 := !.O0
          !.I1 := !.O1
          !.I2 := !.O2
          !.I3 := !.O3
          !.I4 := !.O4
          !.I5 := !.O5
          !.I6 := !.O6
          !.I7 := !.O7
          !.O0 := t64 1 |]
    |> test

  [<TestMethod>]
  member _.``[SPARC] RESTORE rotates the window out lift Test``() =
    "0240e891"
    ++ [| t64 1 := !.G1 .+ !.G2
          !.O0 := !.I0
          !.O1 := !.I1
          !.O2 := !.I2
          !.O3 := !.I3
          !.O4 := !.I4
          !.O5 := !.I5
          !.O6 := !.I6
          !.O7 := !.I7
          AST.sideEffect RestoreWindow
          !.O0 := t64 1 |]
    |> test

  [<TestMethod>]
  member _.``[SPARC] FLUSHW flushes the windows lift Test``() =
    "00005881"
    ++ [| AST.sideEffect FlushWindows |]
    |> test

  [<TestMethod>]
  member _.``[SPARC] TA to the syscall trap becomes a SysCall lift Test``() =
    "6d20d091"
    ++ [| AST.sideEffect SysCall |]
    |> test

  [<TestMethod>]
  member _.``[SPARC] TA to another trap number is a no-op lift Test``() =
    "0520d091"
    ++ [||]
    |> test
