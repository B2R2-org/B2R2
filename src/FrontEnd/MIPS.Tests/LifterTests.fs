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
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.MIPS
open type Register

[<TestClass>]
type LifterTests() =
  let checkOverflowOnAdd e1 e2 r =
    let e1High = AST.extract e1 1<rt> 31
    let e2High = AST.extract e2 1<rt> 31
    let rHigh = AST.extract r 1<rt> 31
    (e1High == e2High) .& (e1High <+> rHigh)

  let unwrapStmts stmts = Array.sub stmts 1 (Array.length stmts - 2)

  let ( ++ ) (byteStr: string) (givenStmts: Stmt[]) =
    ByteArray.ofHexString byteStr, givenStmts

  let test (isa: ISA) (bytes: byte[], givenStmts) =
    let reader = BinReader.Init isa.Endian
    let regFactory = RegisterFactory isa
    let builder = LowUIRBuilder(isa, regFactory, LowUIRStream())
    let parser = MIPSParser(isa, reader) :> IInstructionParsable
    let ins = parser.Parse(bytes, 0UL)
    CollectionAssert.AreEqual(givenStmts, unwrapStmts <| ins.Translate builder)

  [<TestMethod>]
  member _.``[MIPS64] ADD lift test``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64)
    let regFactory = RegisterFactory isa :> IRegisterFactory
    let ( !. ) name = Register.toRegID name |> regFactory.GetRegVar
    let stream = LowUIRStream()
    let lblL0 = stream.NewLabel "L0"
    let lblL1 = stream.NewLabel "L1"
    let lblEnd = stream.NewLabel "End"
    let signExtLo64 = AST.sext 64<rt> <| AST.xtlo 32<rt> (!.R1 .+ !.R2)
    let cond = checkOverflowOnAdd !.R1 !.R2 signExtLo64
    "00220820"
    ++ [| AST.cjmp cond (AST.jmpDest lblL0) (AST.jmpDest lblL1)
          AST.lmark lblL0
          AST.sideEffect (Exception IntegerOverflow)
          AST.jmp (AST.jmpDest lblEnd)
          AST.lmark lblL1
          !.R1 := AST.sext 64<rt> <| AST.xtlo 32<rt> (!.R1 .+ !.R2)
          AST.lmark lblEnd |]
    |> test isa

  [<TestMethod>]
  member _.``[MIPS64] CLZ scans only the low 32-bit word``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64)
    let regFactory = RegisterFactory isa :> IRegisterFactory
    let ( !. ) name = Register.toRegID name |> regFactory.GetRegVar
    let stream = LowUIRStream()
    let lblLoop = stream.NewLabel "Loop"
    let lblCont = stream.NewLabel "Continue"
    let lblEnd = stream.NewLabel "End"
    let t = AST.tmpvar 64<rt> 1
    let rs = AST.zext 64<rt> (AST.xtlo 32<rt> !.R1)
    "70221020"
    ++ [| t := numI32 31 64<rt>
          AST.lmark lblLoop
          AST.cjmp (rs >> t == AST.num1 64<rt>)
                   (AST.jmpDest lblEnd) (AST.jmpDest lblCont)
          AST.lmark lblCont
          t := t .- AST.num1 64<rt>
          AST.cjmp (t == numI32 -1 64<rt>)
                   (AST.jmpDest lblEnd) (AST.jmpDest lblLoop)
          AST.lmark lblEnd
          !.R2 := numI32 31 64<rt> .- t |]
    |> test isa

  [<TestMethod>]
  member _.``[MIPS64BE] LDL loads its base doubleword big-endian``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64)
    let regFactory = RegisterFactory isa :> IRegisterFactory
    let ( !. ) name = Register.toRegID name |> regFactory.GetRegVar
    let baseOff = AST.tmpvar 64<rt> 1
    let vaddr = AST.tmpvar 64<rt> 2
    let shR = AST.tmpvar 64<rt> 3
    let shL = AST.tmpvar 64<rt> 4
    let baseMask = AST.tmpvar 64<rt> 5
    let n7 = numI32 7 64<rt>
    let n8 = numI32 8 64<rt>
    "68220000"
    ++ [| baseOff := !.R1 .+ numI64 0L 64<rt>
          baseMask := baseOff .& numI32 0xFFFFFFF8 64<rt>
          vaddr := AST.xtlo 64<rt> ((baseOff .& n7) <+> n7)
          shR := ((vaddr .& n7) .+ AST.num1 64<rt>) .* n8
          shL := ((n7 .- vaddr) .& n7) .* n8
          !.R2 := ((!.R2 << shR) >> shR)
                  .| (AST.loadBE 64<rt> baseMask << shL) |]
    |> test isa

  [<TestMethod>]
  member _.``[MIPS64] DIV sign-extends its operands``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64)
    let regFactory = RegisterFactory isa :> IRegisterFactory
    let ( !. ) name = Register.toRegID name |> regFactory.GetRegVar
    let sx e = AST.sext 64<rt> (AST.xtlo 32<rt> e)
    "0022001a"
    ++ [| !.R2 := AST.ite (!.R2 == numI64 0L 64<rt>)
                          (AST.undef 64<rt> "UNPREDICTABLE") !.R2
          !.LO := sx (sx !.R1 ?/ sx !.R2)
          !.HI := sx (sx !.R1 ?% sx !.R2) |]
    |> test isa

  [<TestMethod>]
  member _.``[MIPS64] MULT sign-extends its operands``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64)
    let regFactory = RegisterFactory isa :> IRegisterFactory
    let ( !. ) name = Register.toRegID name |> regFactory.GetRegVar
    let sx e = AST.sext 64<rt> (AST.xtlo 32<rt> e)
    let t = AST.tmpvar 64<rt> 1
    "00220018"
    ++ [| t := sx !.R1 .* sx !.R2
          !.LO := AST.sext 64<rt> (AST.xtlo 32<rt> t)
          !.HI := AST.sext 64<rt> (AST.xthi 32<rt> t) |]
    |> test isa

  [<TestMethod>]
  member _.``[MIPS32] ADD lift test``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit32)
    let regFactory = RegisterFactory isa :> IRegisterFactory
    let ( !. ) name = Register.toRegID name |> regFactory.GetRegVar
    let stream = LowUIRStream()
    let lblL0 = stream.NewLabel "L0"
    let lblL1 = stream.NewLabel "L1"
    let lblEnd = stream.NewLabel "End"
    let cond = checkOverflowOnAdd !.R1 !.R2 (!.R1 .+ !.R2)
    "00220820"
    ++ [| AST.cjmp cond (AST.jmpDest lblL0) (AST.jmpDest lblL1)
          AST.lmark lblL0
          AST.sideEffect (Exception IntegerOverflow)
          AST.jmp (AST.jmpDest lblEnd)
          AST.lmark lblL1
          !.R1 := !.R1 .+ !.R2
          AST.lmark lblEnd |]
    |> test isa
