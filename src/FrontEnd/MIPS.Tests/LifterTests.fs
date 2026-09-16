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

  /// The statements one encoding lifts to, for a test that asserts on the
  /// SHAPE of the IR rather than on every statement of it.
  let lifted (isa: ISA) (hex: string) =
    let reader = BinReader.Init isa.Endian
    let regFactory = RegisterFactory isa
    let builder = LowUIRBuilder(isa, regFactory, LowUIRStream())
    let parser = MIPSParser(isa, reader) :> IInstructionParsable
    let ins = parser.Parse(ByteArray.ofHexString hex, 0UL)
    ins.Translate builder

  let test (isa: ISA) (bytes: byte[], givenStmts) =
    let reader = BinReader.Init isa.Endian
    let regFactory = RegisterFactory isa
    let builder = LowUIRBuilder(isa, regFactory, LowUIRStream())
    let parser = MIPSParser(isa, reader) :> IInstructionParsable
    let ins = parser.Parse(bytes, 0UL)
    CollectionAssert.AreEqual(givenStmts, unwrapStmts <| ins.Translate builder)

  (* A branch emits no transfer of its own; the delay slot that follows it
     consumes the armed branch and emits the transfer. A slot that closes
     without consuming it leaks the transfer into the instruction after the
     slot, which the branch was meant to skip. *)
  let testDelaySlot (isa: ISA) branch slot givenStmts =
    let reader = BinReader.Init isa.Endian
    let regFactory = RegisterFactory isa
    let builder = LowUIRBuilder(isa, regFactory, LowUIRStream())
    let parser = MIPSParser(isa, reader) :> IInstructionParsable
    let branch = parser.Parse(ByteArray.ofHexString branch, 0UL)
    branch.Translate builder |> ignore
    let ins = parser.Parse(ByteArray.ofHexString slot, 4UL)
    let actual = ins.Translate builder
    let actual = Array.sub actual 1 (actual.Length - 1)
    CollectionAssert.AreEqual(givenStmts, actual)

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

  (* A likely branch runs its delay slot only when it is taken. The lifter
     cannot suppress the next instruction, so the not-taken path has to leave
     immediately for PC+8, stepping over the slot at PC+4. That interjmp on the
     false arm is the whole of the difference from BEQ, which writes NPC on
     both arms and lets the slot carry the transfer either way. *)
  (* The equal term of a comparison is a floating-point equality, not a
     comparison of magnitudes. Comparing the operands with their signs shifted
     away made every value equal to its own negation, and the signed-zero case
     that presumably motivated it falls out of IEEE equality anyway. Asserting
     on the term itself is what catches this: the printed IR looks the same
     either way, and only the operator differs. *)
  [<TestMethod>]
  member _.``[MIPS32] the equal term of a comparison is a float equality``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit32)
    let regFactory = RegisterFactory isa :> IRegisterFactory
    let ( !. ) name = Register.toRegID name |> regFactory.GetRegVar
    let text =
      lifted isa "46043032" |> Array.map string |> String.concat "
"
    (* `=.` is the printed form of a floating-point equality and `<.` of a
       floating-point less-than. Both terms of the comparison must be of that
       kind. The old code wrote the equal term as an integer `=` over operands
       shifted left and back to clear the sign, so the tell is a `<< 0x1` next
       to a `>> 0x1` -- the FCSR write further down shifts by 0x17 and must not
       be confused for it. *)
    Assert.AreEqual<bool>(
      true,
      text.Contains "=.",
      "the equal term is not a floating-point equality: " + text
    )
    Assert.AreEqual<bool>(
      false,
      text.Contains "<< 0x1:I32) >> 0x1",
      "the sign bit is still being shifted away: " + text
    )

  (* SUB and DSUB are SUBU and DSUBU plus a trap. SUB's integer encoding was
     not decoded at all -- the parser only produced Op.SUB for sub.s and
     sub.d -- and DSUB had no opcode, so neither reached a lifter. Asserting
     on the shape rather than the statements keeps the test about the trap. *)
  [<TestMethod>]
  member _.``[MIPS] SUB traps on signed overflow``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit32)
    let text = lifted isa "012a4022" |> Array.map string |> String.concat "|"
    Assert.AreEqual<bool>(
      true,
      text.Contains "IntegerOverflow",
      "SUB does not signal Integer Overflow: " + text
    )

  [<TestMethod>]
  member _.``[MIPS64] DSUB traps on signed overflow``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64)
    let text = lifted isa "012a402e" |> Array.map string |> String.concat "|"
    Assert.AreEqual<bool>(
      true,
      text.Contains "IntegerOverflow",
      "DSUB does not signal Integer Overflow: " + text
    )

  (* On a 32-bit target a double is an even-odd register pair, and the
     compiler routinely makes the destination pair the source pair. The result
     therefore has to be latched before either half is written: writing the low
     half first changes what the result expression means, and the high half is
     then computed from a register that no longer holds the operand. *)
  [<TestMethod>]
  member _.``[MIPS32] a double result is latched before it is written``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit32)
    let regFactory = RegisterFactory isa :> IRegisterFactory
    let ( !. ) name = Register.toRegID name |> regFactory.GetRegVar
    let t = AST.tmpvar 64<rt> 1
    "46200005"
    ++ [| t := AST.concat !.F1 !.F0 .& numU64 0x7FFFFFFFFFFFFFFFUL 64<rt>
          !.F0 := AST.xtlo 32<rt> t
          !.F1 := AST.xthi 32<rt> t |]
    |> test isa

  [<TestMethod>]
  member _.``[MIPS64] BEQL skips its delay slot when not taken``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64)
    let regFactory = RegisterFactory isa :> IRegisterFactory
    let ( !. ) name = Register.toRegID name |> regFactory.GetRegVar
    let stream = LowUIRStream()
    let lblTrue = stream.NewLabel "TrueCase"
    let lblFalse = stream.NewLabel "FalseCase"
    let lblEnd = stream.NewLabel "End"
    "50220002"
    ++ [| AST.cjmp (!.R1 == !.R2) (AST.jmpDest lblTrue) (AST.jmpDest lblFalse)
          AST.lmark lblTrue
          !.NPC := numI64 12L 64<rt>
          AST.jmp (AST.jmpDest lblEnd)
          AST.lmark lblFalse
          !.NPC := !.PC .+ numI32 8 64<rt>
          AST.interjmp !.NPC InterJmpKind.Base
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
                   (AST.jmpDest lblEnd)
                   (AST.jmpDest lblCont)
          AST.lmark lblCont
          t := t .- AST.num1 64<rt>
          AST.cjmp (t == numI32 -1 64<rt>)
                   (AST.jmpDest lblEnd)
                   (AST.jmpDest lblLoop)
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
    let num0 = AST.num0 64<rt>
    let guard e = AST.ite (!.R2 == num0) num0 e
    "0022001a"
    ++ [| !.LO := guard (sx (sx !.R1 ?/ sx !.R2))
          !.HI := guard (sx (sx !.R1 ?% sx !.R2)) |]
    |> test isa

  (* MD00087 Vol. II, DDIV: no arithmetic exception occurs under any
     circumstances. A zero divisor leaves HI and LO UNPREDICTABLE, and the one
     pair whose quotient does not fit is not even that -- it is the truncated
     quotient. Neither may reach a division in the IR. *)
  [<TestMethod>]
  member _.``[MIPS64] DDIV guards zero and the overflow pair``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64)
    let regFactory = RegisterFactory isa :> IRegisterFactory
    let ( !. ) name = Register.toRegID name |> regFactory.GetRegVar
    let num0 = AST.num0 64<rt>
    let intMin = AST.num (BitVector.SignedMin 64<rt>)
    let isOvf = (!.R1 == intMin) .& (!.R2 == numI64 -1L 64<rt>)
    let guard e = AST.ite (!.R2 == num0) num0 e
    "0022001e"
    ++ [| !.LO := guard (AST.ite isOvf intMin (AST.sdiv !.R1 !.R2))
          !.HI := guard (AST.ite isOvf num0 (AST.smod !.R1 !.R2)) |]
    |> test isa

  [<TestMethod>]
  member _.``[MIPS64] DDIVU guards its zero divisor``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64)
    let regFactory = RegisterFactory isa :> IRegisterFactory
    let ( !. ) name = Register.toRegID name |> regFactory.GetRegVar
    let num0 = AST.num0 64<rt>
    let guard e = AST.ite (!.R2 == num0) num0 e
    "0022001f"
    ++ [| !.LO := guard (AST.div !.R1 !.R2)
          !.HI := guard (AST.(mod) !.R1 !.R2) |]
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
  member _.``[MIPS32] SYSCALL in a delay slot takes the armed branch``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit32)
    let regFactory = RegisterFactory isa :> IRegisterFactory
    let ( !. ) name = Register.toRegID name |> regFactory.GetRegVar
    (* beq $a0, $a1, 0xc ; syscall *)
    testDelaySlot isa "10850002" "0000000C"
    <| [| AST.sideEffect SysCall
          AST.interjmp !.NPC InterJmpKind.Base |]

  [<TestMethod>]
  member _.``[MIPS32] BREAK in a delay slot takes the armed branch``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit32)
    let regFactory = RegisterFactory isa :> IRegisterFactory
    let ( !. ) name = Register.toRegID name |> regFactory.GetRegVar
    (* beq $a0, $a1, 0xc ; break *)
    testDelaySlot isa "10850002" "0000000D"
    <| [| AST.sideEffect Breakpoint
          AST.interjmp !.NPC InterJmpKind.Base |]

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

  /// <summary>
  /// The whole TLB family is lifted, and none of it is a side effect.
  ///
  /// The array is thirty-two entries of four values, held as registers
  /// because registers are the only state LowUIR has -- so what these lift to
  /// is assignments. Nothing translates an address through what they write,
  /// which is why they can be modelled without an MMU being modelled: TLBWI
  /// and TLBWR store an entry, TLBR reads one back, TLBP searches for one,
  /// and TLBINV and TLBINVF mark entries so a search will not find them.
  /// </summary>
  [<TestMethod>]
  member _.``[MIPS64] The whole TLB family is lifted``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64)
    let encodings =
      [ "42000001"   (* TLBR *)
        "42000002"   (* TLBWI *)
        "42000003"   (* TLBINV *)
        "42000004"   (* TLBINVF *)
        "42000006"   (* TLBWR *)
        "42000008" ] (* TLBP *)
    for hex in encodings do
      let stmts = lifted isa hex
      let effects =
        stmts
        |> Array.choose (function
          | SideEffect(e) -> Some e
          | _ -> None)
      Assert.AreEqual<int>(0, effects.Length, hex)
      let puts = stmts |> Array.filter (function Put _ -> true | _ -> false)
      if puts.Length = 0 then Assert.Fail hex else ()

  /// <summary>
  /// TLBWR steps the register that chose the entry it wrote.
  ///
  /// It is the difference between TLBWR and TLBWI: one writes where the
  /// program said and the other writes where Random says, and a Random that
  /// never moved would make every TLBWR write the same entry -- which is the
  /// one thing a refill handler must not do. The rate a processor steps it at
  /// is a clock's and is not here; that it steps at all is.
  /// </summary>
  [<TestMethod>]
  member _.``[MIPS64] TLBWR steps Random``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64)
    let random = RegisterID.create (int CP0Register.Random)
    let written =
      lifted isa "42000006"
      |> Array.exists (function
        | Put(Var(_, rid, _), _) -> rid = random
        | _ -> false)
    Assert.AreEqual<bool>(true, written)

  /// <summary>
  /// The five arithmetic operations record in FCSR what they raised.
  ///
  /// An IEEE operation answers with a number AND with what that number cost,
  /// and MIPS keeps the record in the same register as the rounding mode and
  /// the condition codes. A lifter that writes only the number leaves a
  /// program that asks what it lost with the answer it started from -- which
  /// is the one part of a floating-point result nothing could disagree about.
  /// Both formats are here: the two are separate arms of each lifter.
  /// </summary>
  [<TestMethod>]
  member _.``[MIPS64] The arithmetic records what it raised``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64)
    let fcsr = Register.toRegID Register.FCSR
    let encodings =
      [ "46041000"   (* ADD.S *)
        "46241000"   (* ADD.D *)
        "46041001"   (* SUB.S *)
        "46241001"   (* SUB.D *)
        "46041002"   (* MUL.S *)
        "46241002"   (* MUL.D *)
        "46041003"   (* DIV.S *)
        "46241003"   (* DIV.D *)
        "46001004"   (* SQRT.S *)
        "46201004" ] (* SQRT.D *)
    for hex in encodings do
      let written =
        lifted isa hex
        |> Array.exists (function
          | Put(Var(_, rid, _), _) -> rid = fcsr
          | _ -> false)
      if written then () else Assert.Fail hex

  /// <summary>
  /// An instruction that moves a value rather than computing one leaves FCSR
  /// alone.
  ///
  /// MOV.fmt, ABS.fmt and NEG.fmt copy a number and touch at most its sign,
  /// and a load writes a register from memory. None of them rounds, so none
  /// has anything to record -- and since Cause is written WHOLE by every
  /// instruction that does, a lifter that recorded on every floating-point
  /// instruction would clear the record of the one that did.
  ///
  /// ABS and NEG are here on measurement rather than on the manual's word:
  /// where ABS2008 is clear they are defined as signalling on a signalling
  /// NaN, and a processor reporting it clear was asked and records nothing.
  /// </summary>
  [<TestMethod>]
  member _.``[MIPS64] Moving a value records nothing``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64)
    let fcsr = Register.toRegID Register.FCSR
    let encodings =
      [ "46001006"   (* MOV.S *)
        "46201006"   (* MOV.D *)
        "46001005"   (* ABS.S *)
        "46201005"   (* ABS.D *)
        "46001007"   (* NEG.S *)
        "46201007"   (* NEG.D *)
        "c4410000" ] (* LWC1 *)
    for hex in encodings do
      let written =
        lifted isa hex
        |> Array.exists (function
          | Put(Var(_, rid, _), _) -> rid = fcsr
          | _ -> false)
      if written then Assert.Fail hex else ()

  /// <summary>
  /// DMFC0 widens a thirty-two bit coprocessor 0 register by its sign.
  ///
  /// A MIPS64 processor keeps the registers that carry an address or a page
  /// number at the full width and the rest at thirty-two, and a thirty-two
  /// bit value moved into a sixty-four bit register is SIGN extended -- the
  /// way every thirty-two bit value on this architecture travels. It shows
  /// on the first register whose top bit is set: Config reads 0x80004482 on
  /// the processor this front end's values were measured on, so a zero
  /// extension answers 0x0000000080004482 where the processor answers
  /// 0xFFFFFFFF80004482.
  /// </summary>
  [<TestMethod>]
  member _.``[MIPS64] DMFC0 widens a word register by its sign``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64)
    let widensBySign hex =
      lifted isa hex
      |> Array.exists (function
        | Put(_, Cast(CastKind.SignExt, 64<rt>, _)) -> true
        | _ -> false)
    (* Config is thirty-two bits wide; EntryHi is not. *)
    if widensBySign "40228000" then () else Assert.Fail "40228000"
    if widensBySign "40225000" then Assert.Fail "40225000" else ()
