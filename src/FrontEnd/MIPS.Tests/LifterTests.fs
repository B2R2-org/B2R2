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
open B2R2.FrontEnd.MIPS.Tests.ManualLift

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
    let parser = Parser(isa, reader) :> IInstructionParsable
    let ins = parser.Parse(ByteArray.ofHexString hex, 0UL)
    ins.Translate builder

  /// What one floating-point encoding leaves in $f0 and in FCSR, run on a
  /// processor an ISA names from the FCSR and the registers given, with the
  /// exception query answering the given flags.
  let fpRunAnswering flags (isa: ISA) hex (fcsr: uint32) fprs =
    let regs = RegisterFactory isa :> IRegisterFactory
    let var r = Register.toRegID r |> regs.GetRegVar
    let fpr (r, v: uint64) = var r, BitVector(v, Expr.typeOf (var r))
    let inputs = (var FCSR, BitVector(fcsr, 32<rt>)) :: List.map fpr fprs
    let read = IRRunner.runAnswering flags (lifted isa hex) inputs
    (read (var F0)).ToUInt64(), uint32 ((read (var FCSR)).ToUInt64())

  /// The same with the query answering that nothing was raised.
  let fpRun isa hex fcsr fprs = fpRunAnswering 0u isa hex fcsr fprs

  /// FCSR.FS, flush subnormal results to zero.
  let fs = 0x01000000u

  /// The kinds of the jumps a branch and its delay slot lift to, the parser
  /// reading the encoding a mode names on the processor an ISA names.
  let jumpKinds (isa: ISA) mode branch slot =
    let builder = LowUIRBuilder(isa, RegisterFactory isa, LowUIRStream())
    let parser = Parser(isa, BinReader.Init isa.Endian)
    parser.ISAMode <- mode
    let p = parser :> IInstructionParsable
    let ins = p.Parse(ByteArray.ofHexString branch, 0UL)
    ins.Translate builder |> ignore
    (p.Parse(ByteArray.ofHexString slot, uint64 ins.Length)).Translate builder
    |> Array.choose (function
      | InterJmp(Kind = kind) -> Some kind
      | _ -> None)

  let test (isa: ISA) (bytes: byte[], givenStmts) =
    let reader = BinReader.Init isa.Endian
    let regFactory = RegisterFactory isa
    let builder = LowUIRBuilder(isa, regFactory, LowUIRStream())
    let parser = Parser(isa, reader) :> IInstructionParsable
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
    let parser = Parser(isa, reader) :> IInstructionParsable
    let branch = parser.Parse(ByteArray.ofHexString branch, 0UL)
    branch.Translate builder |> ignore
    let ins = parser.Parse(ByteArray.ofHexString slot, 4UL)
    let actual = ins.Translate builder
    let actual = Array.sub actual 1 (actual.Length - 1)
    CollectionAssert.AreEqual(givenStmts, actual)

  /// microMIPS64 at Release 6, read from big-endian bytes so that the hex is
  /// the word as the manuals draw it: the major halfword first.
  let microR6 =
    let flags = int MIPSISAMode.MicroMIPS ||| int MIPSRelease.R6
    ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64, flags)

  let r2 =
    ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64)

  let r6 =
    ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64, int MIPSRelease.R6)

  let m16 =
    ISA(Architecture.MIPS, Endian.Big, WordSize.Bit32, int MIPSISAMode.MIPS16)

  let m16x64 =
    ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64, int MIPSISAMode.MIPS16)

  let um =
    ISA(Architecture.MIPS,
        Endian.Big,
        WordSize.Bit64,
        int MIPSISAMode.MicroMIPS)

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
      (* In Kernel Mode, which a zeroed Status is. *)
      let effects, _ = IRRunner.follow stmts []
      Assert.AreEqual<int>(0, List.length effects, hex)
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
        | Put(Dst = Var(RegisterID = rid)) -> rid = random
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
        "46201004"   (* SQRT.D *)
        "46001015"   (* RECIP.S *)
        "46201015"   (* RECIP.D *)
        "46001016"   (* RSQRT.S *)
        "46201016" ] (* RSQRT.D *)
    for hex in encodings do
      let written =
        lifted isa hex
        |> Array.exists (function
          | Put(Dst = Var(RegisterID = rid)) -> rid = fcsr
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
          | Put(Dst = Var(RegisterID = rid)) -> rid = fcsr
          | _ -> false)
      if written then Assert.Fail hex else ()

  /// <summary>
  /// FCSR.FS flushes a result whose exact value is below the smallest normal
  /// to a zero of its own sign: 2^-126 times a half is 2^-127, a subnormal,
  /// which comes out +0, and -0 from -2^-126. With FS clear it is the
  /// subnormal itself.
  /// </summary>
  [<TestMethod>]
  member _.``[MIPS32] FS flushes a subnormal product to zero``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit32)
    let mul fcsr a = fpRun isa "46041002" fcsr [ F2, a; F4, 0x3f000000UL ]
    Assert.AreEqual<uint64 * uint32>((0UL, fs), mul fs 0x00800000UL)
    Assert.AreEqual<uint64 * uint32>((0x80000000UL, fs), mul fs 0x80800000UL)
    Assert.AreEqual<uint64 * uint32>((0x00400000UL, 0u), mul 0u 0x00800000UL)

  /// CVT.W.D writes a word into the low half of a 64-bit FPR, as the rounding
  /// conversions to a word do. On a 64-bit FPU it took the destination at the
  /// width of the source, which is an assignment of a word to a doubleword.
  [<TestMethod>]
  member _.``[MIPS64] CVT.W.D writes the low word``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64)
    let fprs = [ F0, 0xdeadbeef00000000UL; F2, 0x4004000000000000UL ]
    let cvt = fpRun isa "46201024" 0u fprs
    (* 2.5 rounds to 2, which is inexact: the cause and the flag *)
    Assert.AreEqual<uint64 * uint32>((0xdeadbeef00000002UL, 0x1004u), cvt)

  /// <summary>
  /// What FS asks of is the exact value, and what goes with a flush is
  /// everything the operation raised. (2 - 2^-23) 2^-126 times a half is
  /// 2^-126 (1 - 2^-24), which rounds to nearest up to the smallest normal,
  /// and the evaluator, asked before rounding and after, answers Underflow
  /// and Inexact for it. Under FS the answer is +0 and Cause is clear.
  /// </summary>
  [<TestMethod>]
  member _.``[MIPS32] FS flushes on the exact value and drops the flags``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit32)
    let fprs = [ F2, 0x00ffffffUL; F4, 0x3f000000UL ]
    let mul fcsr = fpRunAnswering 0x3u isa "46041002" fcsr fprs
    Assert.AreEqual<uint64 * uint32>((0UL, fs), mul fs)
    Assert.AreEqual<uint64 * uint32>((0x00800000UL, 0x300cu), mul 0u)

  /// FS flushes what an operation answers and not what it is given: the
  /// reference reads a subnormal operand as it is, so 2^-127 times 2^23 is
  /// 2^-104 under FS as well.
  [<TestMethod>]
  member _.``[MIPS32] FS leaves a subnormal operand alone``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit32)
    let fprs = [ F2, 0x00400000UL; F4, 0x4b000000UL ]
    let mul = fpRun isa "46041002" fs fprs
    Assert.AreEqual<uint64 * uint32>((0x0b800000UL, fs), mul)

  /// <summary>
  /// CVT.S.D flushes under FS as the arithmetic does, on the operand, which is
  /// the exact value, and drops what it raised: 2^-140 is a subnormal single,
  /// exactly, and a hair above it the same rounded, Underflow and Inexact;
  /// 2^-126 (1 - 2^-25) rounds up to the smallest normal, Inexact alone,
  /// tininess being judged after rounding.
  /// </summary>
  [<TestMethod>]
  member _.``[MIPS32] FS flushes a narrowing to a subnormal``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit32)
    let cvt fcsr hi lo = fpRun isa "46201020" fcsr [ F2, lo; F3, hi ]
    Assert.AreEqual<uint64 * uint32>((0UL, fs), cvt fs 0x37300000UL 0UL)
    Assert.AreEqual<uint64 * uint32>((0x200UL, 0u), cvt 0u 0x37300000UL 0UL)
    Assert.AreEqual<uint64 * uint32>((0x80000000UL, fs),
                                     cvt fs 0xb7300000UL 0UL)
    Assert.AreEqual<uint64 * uint32>((0UL, fs), cvt fs 0x37300000UL 1UL)
    Assert.AreEqual<uint64 * uint32>((0x200UL, 0x300cu),
                                     cvt 0u 0x37300000UL 1UL)
    Assert.AreEqual<uint64 * uint32>((0UL, fs),
                                     cvt fs 0x380fffffUL 0xf0000000UL)
    Assert.AreEqual<uint64 * uint32>((0x00800000UL, 0x1004u),
                                     cvt 0u 0x380fffffUL 0xf0000000UL)

  /// <summary>
  /// An unfused MADD.fmt flushes its product before the sum reads it, and the
  /// sum after: 2^-127 is flushed to +0, so less 2^-127 the sum is -2^-127,
  /// flushed to -0, where with FS clear the two cancel to +0.
  /// </summary>
  [<TestMethod>]
  member _.``[MIPS32] FS flushes MADD's product before the sum``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit32)
    let fprs = [ F2, 0x00800000UL; F4, 0x3f000000UL; F6, 0x80400000UL ]
    let madd fcsr = fpRun isa "4cc41020" fcsr fprs
    Assert.AreEqual<uint64 * uint32>((0x80000000UL, fs), madd fs)
    Assert.AreEqual<uint64 * uint32>((0UL, 0u), madd 0u)

  /// MAX.fmt answers one of its operands rather than rounding anything, and
  /// the reference still flushes a subnormal one under FS.
  [<TestMethod>]
  member _.``[MIPS64R6] FS flushes a subnormal MAX``() =
    let r6 =
      ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64, int MIPSRelease.R6)
    let negative = [ F2, 0x8000000000000001UL; F4, 0xbff0000000000000UL ]
    let negativeMax = fpRun r6 "4624101e" fs negative
    Assert.AreEqual<uint64 * uint32>((0x8000000000000000UL, fs), negativeMax)
    let fprs = [ F2, 0x1UL; F4, 0x8000000000000000UL ]
    let max fcsr = fpRun r6 "4624101e" fcsr fprs
    Assert.AreEqual<uint64 * uint32>((0UL, fs), max fs)
    Assert.AreEqual<uint64 * uint32>((1UL, 0u), max 0u)

  /// The comparisons Release 6 adds as negations answer what their names
  /// say: NE is ordered and unequal, UNE unordered or unequal, OR ordered.
  [<TestMethod>]
  member _.``[MIPS64R6] CMP.NE, CMP.UNE and CMP.OR compare``() =
    let r6 =
      ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64, int MIPSRelease.R6)
    let cmp hex b =
      let fprs = [ F2, 0x3f800000UL; F4, b ]
      fst (fpRun r6 hex 0u fprs) &&& 0xffffffffUL
    let one, two, nan = 0x3f800000UL, 0x40000000UL, 0x7fc00000UL
    let ones = 0xffffffffUL
    Assert.AreEqual<uint64>(ones, cmp "46841013" two)
    Assert.AreEqual<uint64>(0UL, cmp "46841013" one)
    Assert.AreEqual<uint64>(0UL, cmp "46841013" nan)
    Assert.AreEqual<uint64>(ones, cmp "46841012" nan)
    Assert.AreEqual<uint64>(0UL, cmp "46841012" one)
    Assert.AreEqual<uint64>(0UL, cmp "46841011" nan)
    Assert.AreEqual<uint64>(ones, cmp "46841011" two)

  /// <summary>
  /// Release 6 reads a NaN as IEEE-2008 does, and so does the reference: an
  /// operation hands back the first signalling operand quieted, ahead of any
  /// quiet one, where the host hands back its first NaN operand; and a NaN no
  /// operand brought is the positive default, where the host's is negative.
  /// </summary>
  [<TestMethod>]
  member _.``[MIPS64R6] The arithmetic answers IEEE-2008's NaN``() =
    let r6 =
      ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64, int MIPSRelease.R6)
    let qnan, snan = 0x7ff8000000000001UL, 0x7ff0000000000002UL
    let add, _ = fpRun r6 "46241000" 0u [ F2, qnan; F4, snan ]
    Assert.AreEqual<uint64>(0x7ff8000000000002UL, add)
    let sqrt, _ = fpRun r6 "46001004" 0u [ F2, 0xbf800000UL ]
    Assert.AreEqual<uint64>(0x7fc00000UL, sqrt &&& 0xffffffffUL)

  /// MADDF.fmt asks the addend about a NaN first, and the multiplicands after
  /// it.
  [<TestMethod>]
  member _.``[MIPS64R6] MADDF takes the addend's NaN first``() =
    let r6 =
      ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64, int MIPSRelease.R6)
    let fprs = [ F0, 0xffc00000UL; F2, 0x7fc00000UL; F4, 0x3f800000UL ]
    let maddf, _ = fpRun r6 "46041018" 0u fprs
    Assert.AreEqual<uint64>(0xffc00000UL, maddf &&& 0xffffffffUL)

  /// With NAN2008 a conversion to an integer saturates as IEEE-2008 does: a
  /// NaN is zero and a negative magnitude too large the smallest word, where
  /// before it every such operand answered the largest.
  [<TestMethod>]
  member _.``[MIPS64R6] CVT.W.S saturates as IEEE-2008 does``() =
    let r6 =
      ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64, int MIPSRelease.R6)
    let cvt v = fst (fpRun r6 "46001024" 0u [ F2, v ]) &&& 0xffffffffUL
    Assert.AreEqual<uint64>(0UL, cvt 0x7fc00000UL)
    Assert.AreEqual<uint64>(0x80000000UL, cvt 0xcf800000UL)
    Assert.AreEqual<uint64>(0x7fffffffUL, cvt 0x4f800000UL)

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
        | Put(Src = Cast(Kind = CastKind.SignExt; Type = 64<rt>)) -> true
        | _ -> false)
    (* Config is thirty-two bits wide; EntryHi is not. *)
    if widensBySign "40228000" then () else Assert.Fail "40228000"
    if widensBySign "40225000" then Assert.Fail "40225000" else ()

  /// <summary>
  /// A double in an odd register of a thirty-two bit FPU is a Reserved
  /// Instruction.
  ///
  /// This front end's MIPS32 FPU keeps a double in a PAIR of registers, the
  /// even one and the one above it, which is what Status.FR = 0 means; an odd
  /// register names no pair, and MD00087 makes the operation UNPREDICTABLE.
  /// The reference running a program built for that mode raises a Reserved
  /// Instruction for it, where this lifter stopped with an internal error.
  /// </summary>
  [<TestMethod>]
  member _.``[MIPS32] An odd register holds no double``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit32)
    let effects hex =
      lifted isa hex
      |> Array.choose (function
        | SideEffect(Effect = e) -> Some e
        | _ -> None)
    (* ADD.D f0, f1, f2 and ADD.D f0, f2, f4 *)
    CollectionAssert.AreEqual([| UndefinedInstruction |], effects "46220800")
    CollectionAssert.AreEqual([||], effects "46241000")

  /// <summary>
  /// An instruction that moves a double without reading it as a number moves
  /// the pair an odd register is the upper half of.
  ///
  /// That is LDC1 and SDC1, MFHC1 and MTHC1, and the conditional moves. The
  /// operand is UNPREDICTABLE as it is for the arithmetic, but the reference
  /// runs these rather than refusing them, on the pair the register belongs
  /// to -- so MFHC1 of $f1 reads $f1, as MFHC1 of $f0 does.
  /// </summary>
  [<TestMethod>]
  member _.``[MIPS32] A move takes the pair an odd register is in``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit32)
    let regs = RegisterFactory isa :> IRegisterFactory
    let var r = Register.toRegID r |> regs.GetRegVar
    let f0, f1 = var F0, var F1
    let read hex =
      let inputs =
        [ f0, BitVector(0x11111111UL, 32<rt>)
          f1, BitVector(0x22222222UL, 32<rt>)
          var R2, BitVector(0x33333333UL, 32<rt>) ]
      IRRunner.run (lifted isa hex) inputs
    (* MFHC1 v0, f1 and MTHC1 v0, f1 *)
    Assert.AreEqual<uint64>(0x22222222UL, (read "44620800" (var R2)).ToUInt64())
    let wrote = read "44e20800"
    Assert.AreEqual<uint64>(0x11111111UL, (wrote f0).ToUInt64())
    Assert.AreEqual<uint64>(0x33333333UL, (wrote f1).ToUInt64())

  /// <summary>
  /// A thirty-two bit Release 6 FPU holds a double in each register.
  ///
  /// Release 6 removed Status.FR = 0, so its FPRs are sixty-four bits wide
  /// whatever the general registers are, and MFHC1 reads the upper half of
  /// the register it names -- where the older thirty-two bit FPU reads the
  /// register above it. This front end gave the thirty-two bit Release 6 FPU
  /// the paired registers, so $f1 held no double of its own.
  /// </summary>
  [<TestMethod>]
  member _.``[MIPS32] Release 6 holds a double in each register``() =
    let isa =
      ISA(Architecture.MIPS, Endian.Big, WordSize.Bit32, int MIPSRelease.R6)
    let regs = RegisterFactory isa :> IRegisterFactory
    let var r = Register.toRegID r |> regs.GetRegVar
    let f1 = var F1
    Assert.AreEqual<RegType>(64<rt>, Expr.typeOf f1)
    let inputs = [ f1, BitVector(0x1122334455667788UL, 64<rt>) ]
    (* MFHC1 v0, f1 *)
    let read = IRRunner.run (lifted isa "44620800") inputs
    Assert.AreEqual<uint64>(0x11223344UL, (read (var R2)).ToUInt64())

  /// <summary>
  /// Every instruction that reaches coprocessor 2 takes Coprocessor Unusable.
  ///
  /// Coprocessor 2 is the implementation's, and the processor this front end
  /// models has none -- Config1.C2 is clear -- so there is nothing for a move,
  /// a branch on its condition or an operation to reach. Each one's
  /// Exceptions list Coprocessor Unusable, and that is the whole of its
  /// effect.
  /// </summary>
  [<TestMethod>]
  member _.``[MIPS64] Coprocessor 2 is unusable``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64)
    for hex in [ "48021805"; "49010003"; "4a123456"; "c8820010" ] do
      let effects =
        lifted isa hex
        |> Array.choose (function
          | SideEffect(Effect = e) -> Some e
          | _ -> None)
      CollectionAssert.AreEqual([| UndefinedInstruction |], effects, hex)

  /// <summary>
  /// CP0 is refused outside Kernel Mode unless Status.CU0 lets it through.
  ///
  /// MD00087 1.2 says where the privileged state may be reached: "in Kernel
  /// Mode or Debug Mode, or with the CP0 usable bit set in the Status
  /// register", and every instruction that reaches it -- the EVA loads and
  /// stores among them -- lists Coprocessor Unusable for everywhere else.
  /// Kernel Mode is Status.KSU zero, or EXL or ERL set whatever KSU says, so
  /// Supervisor Mode is refused as User Mode is. A Linux process runs in
  /// User Mode, and an MFC0 that answered there would hand it a register
  /// its kernel keeps from it: the processor raises the exception, and
  /// Linux turns it into SIGILL.
  /// </summary>
  [<TestMethod>]
  member _.``[MIPS32] CP0 is refused outside kernel mode``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit32)
    let regs = RegisterFactory isa :> IRegisterFactory
    let status = regs.GetRegVar(RegisterID.create (int CP0Register.Status))
    let v0 = regs.GetRegVar(Register.toRegID R2)
    let run hex (value: uint64) =
      IRRunner.follow (lifted isa hex) [ status, BitVector(value, 64<rt>) ]
    let refused hex value = fst (run hex value) = [ UndefinedInstruction ]
    (* MFC0 v0, Status in User and in Supervisor Mode, and LBE v1, 0(v0). *)
    if refused "40026000" 0x10UL then () else Assert.Fail "user"
    if refused "40026000" 0x08UL then () else Assert.Fail "supervisor"
    if refused "7c43002c" 0x10UL then () else Assert.Fail "lbe"
    (* Kernel Mode three ways, and User Mode with CU0 set. *)
    for value in [ 0UL; 0x12UL; 0x14UL; 0x10000010UL ] do
      let effects, read = run "40026000" value
      Assert.AreEqual<int>(0, List.length effects, $"{value:x}")
      Assert.AreEqual<uint64>(value, (read v0).ToUInt64(), $"{value:x}")

  /// <summary>
  /// Every name this front end decodes has a lifter arm.
  ///
  /// Decoding and lifting are two tables, and a change to one that forgets
  /// the other leaves an instruction that disassembles and then throws --
  /// which is what happened to the floating-point select the moment it was
  /// given the name the manual uses, because the arm still matched the
  /// integer one. The encodings below are one per family this branch added.
  /// </summary>
  [<TestMethod>]
  member _.``[MIPS64] What decodes also lifts``() =
    let r2 = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64)
    let r6 =
      ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64, int MIPSRelease.R6)
    let cases =
      [ r2, "42000002"   (* TLBWI *)
        r2, "42000006"   (* TLBWR *)
        r2, "42000003"   (* TLBINV *)
        r2, "42000004"   (* TLBINVF *)
        r2, "46c41000"   (* ADD.PS *)
        r2, "46041000"   (* ADD.S *)
        r2, "04100000"   (* NAL *)
        r2, "4620100d"   (* TRUNC.W.D *)
        r6, "7ca4000f"   (* CRC32B *)
        r6, "46041018"   (* MADDF.S *)
        r6, "46041017"   (* SELNEQZ.S *)
        r6, "46841002"   (* CMP.EQ.S *)
        r6, "42000018"   (* ERET *)
        r6, "4600101a" ] (* RINT.S *)
    for isa, hex in cases do
      let stmts = lifted isa hex
      if Array.isEmpty stmts then Assert.Fail hex else ()

  /// <summary>
  /// BC1EQZ and BC1NEZ keep their delay slot.
  ///
  /// Release 6 added compact branches with no delay slot, but these two are
  /// not among them: MD00087 BC1EQZ says to "Execute the instruction in the
  /// delay slot before the instruction at the target", as BEQ does. Lifted as
  /// compact, a taken branch skipped its slot. The transfer therefore belongs
  /// to the slot, the way it does after BEQ.
  /// </summary>
  [<TestMethod>]
  member _.``[MIPS64] BC1EQZ and BC1NEZ keep their delay slot``() =
    let isa =
      ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64, int MIPSRelease.R6)
    (* BC1EQZ f2, and BC1NEZ f2, each with a NOP in its slot *)
    for branch in [ "45220001"; "45a20001" ] do
      let kinds = jumpKinds isa MIPSISAMode.MIPS branch "00000000"
      CollectionAssert.AreEqual([| InterJmpKind.Base |], kinds, branch)

  /// ASMACRO's macros are the implementation's, and the processor modelled
  /// here implements none, for which "a Reserved Instruction exception is
  /// signaled" (MD00076 ASMACRO); that is the whole of its effect.
  [<TestMethod>]
  member _.``[MIPS16e] ASMACRO is a Reserved Instruction``() =
    let effects =
      lifted (ISA "mips16el") "fff7ffe7"
      |> Array.choose (function
        | SideEffect(Effect = e) -> Some e
        | _ -> None)
    CollectionAssert.AreEqual([| UndefinedInstruction |], effects)

  /// <summary>
  /// A JALX from MIPS32 code crosses into the compressed encoding of the
  /// processor, and on a MIPS16e processor that is MIPS16e, not microMIPS. No
  /// processor has both, and nothing at the target says which one the words
  /// there are in, so the jump has to.
  /// </summary>
  [<TestMethod>]
  member _.``[MIPS16e] JALX from MIPS32 crosses into MIPS16e``() =
    let isa = ISA "mips16el"
    let kinds = jumpKinds isa MIPSISAMode.MIPS "00000074" "00000000"
    let call = InterJmpKind.IsCall ||| InterJmpKind.SwitchToMIPS16
    CollectionAssert.AreEqual([| call |], kinds)

  /// A JR whose target has bit 0 set goes on in the compressed encoding, which
  /// on a MIPS16e processor is MIPS16e; with bit 0 clear it goes on in MIPS32.
  [<TestMethod>]
  member _.``[MIPS16e] JR to an odd address goes on in MIPS16e``() =
    let isa = ISA "mips16el"
    let kinds = jumpKinds isa MIPSISAMode.MIPS "0800e003" "00000000"
    let expected = [| InterJmpKind.SwitchToMIPS16; InterJmpKind.SwitchToMIPS |]
    CollectionAssert.AreEqual(expected, kinds)

  /// <summary>
  /// microMIPS's Release 6 multiplies (MD00582 revision 6.04, p.256) lift as
  /// the older encoding's Release 6 multiplies do: one register gets the low
  /// or the high word of the 64-bit product of the two low words, signed or
  /// unsigned, sign-extended. MUL goes through the MUL every encoding shares,
  /// which leaves HI and LO UNPREDICTABLE.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS64R6] MUL MUH MULU MUHU lift (32r6 p.256)``() =
    let regFactory = RegisterFactory microR6 :> IRegisterFactory
    let ( !. ) name = Register.toRegID name |> regFactory.GetRegVar
    let lo32 e = AST.xtlo 32<rt> e
    let hi32 e = AST.xthi 32<rt> e
    let sx e = AST.sext 64<rt> (lo32 e)
    let zx e = AST.zext 64<rt> (lo32 e)
    let t = AST.tmpvar 64<rt> 1
    let undef = AST.undef 64<rt> "UNPREDICTABLE"
    "00831018"
    ++ [| !.R2 := sx (!.R3 .* !.R4)
          !.HI := undef
          !.LO := undef |]
    |> test microR6
    "00831058"
    ++ [| t := sx !.R3 .* sx !.R4
          !.R2 := AST.sext 64<rt> (hi32 t) |]
    |> test microR6
    "00831098"
    ++ [| t := zx !.R3 .* zx !.R4
          !.R2 := AST.sext 64<rt> (lo32 t) |]
    |> test microR6
    "008310d8"
    ++ [| t := zx !.R3 .* zx !.R4
          !.R2 := AST.sext 64<rt> (hi32 t) |]
    |> test microR6

  /// <summary>
  /// microMIPS's Release 6 divides (MD00582 revision 6.04, p.182) lift as the
  /// older encoding's do: the quotient or the remainder of the two low words
  /// into one register, sign-extended. A zero divisor is UNPREDICTABLE and
  /// guarded, and the most negative word over minus one is the truncated
  /// quotient, whose remainder is zero.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS64R6] DIV MOD DIVU MODU lift (32r6 p.182)``() =
    let regFactory = RegisterFactory microR6 :> IRegisterFactory
    let ( !. ) name = Register.toRegID name |> regFactory.GetRegVar
    let rs, rt = AST.xtlo 32<rt> !.R3, AST.xtlo 32<rt> !.R4
    let num0 = AST.num0 32<rt>
    let intMin = AST.num (BitVector.SignedMin 32<rt>)
    let isOvf = (rs == intMin) .& (rt == numI64 -1L 32<rt>)
    let guard e = AST.sext 64<rt> (AST.ite (rt == num0) num0 e)
    "00831118"
    ++ [| !.R2 := guard (AST.ite isOvf intMin (AST.sdiv rs rt)) |]
    |> test microR6
    "00831158"
    ++ [| !.R2 := guard (AST.ite isOvf num0 (AST.smod rs rt)) |]
    |> test microR6
    "00831198"
    ++ [| !.R2 := guard (AST.div rs rt) |]
    |> test microR6
    "008311d8"
    ++ [| !.R2 := guard (AST.(mod) rs rt) |]
    |> test microR6

  /// <summary>
  /// DDIV, DMOD, DDIVU and DMODU (MD00594 revision 6.01, p.210) lift as the
  /// older encoding's Release 6 forms do: the whole doublewords, with the
  /// same two guards as the word forms.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS64R6] DDIV DMOD DDIVU DMODU lift (64r6 p.210)``() =
    let regFactory = RegisterFactory microR6 :> IRegisterFactory
    let ( !. ) name = Register.toRegID name |> regFactory.GetRegVar
    let rs, rt = !.R3, !.R4
    let num0 = AST.num0 64<rt>
    let intMin = AST.num (BitVector.SignedMin 64<rt>)
    let isOvf = (rs == intMin) .& (rt == numI64 -1L 64<rt>)
    let guard e = AST.ite (rt == num0) num0 e
    "58831118"
    ++ [| !.R2 := guard (AST.ite isOvf intMin (AST.sdiv rs rt)) |]
    |> test microR6
    "58831158"
    ++ [| !.R2 := guard (AST.ite isOvf num0 (AST.smod rs rt)) |]
    |> test microR6
    "58831198"
    ++ [| !.R2 := guard (AST.div rs rt) |]
    |> test microR6
    "588311d8"
    ++ [| !.R2 := guard (AST.(mod) rs rt) |]
    |> test microR6

  /// <summary>
  /// DMUL, DMUH, DMULU and DMUHU (MD00594 revision 6.01, p.312) lift as the
  /// older encoding's do: the 128-bit product of the two doublewords, signed
  /// or unsigned, of which one register gets the low or the high half.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS64R6] DMUL DMUH DMULU DMUHU lift (64r6 p.312)``() =
    let regFactory = RegisterFactory microR6 :> IRegisterFactory
    let ( !. ) name = Register.toRegID name |> regFactory.GetRegVar
    let sx e = AST.sext 128<rt> e
    let zx e = AST.zext 128<rt> e
    let t = AST.tmpvar 128<rt> 1
    "58831018"
    ++ [| t := sx !.R3 .* sx !.R4
          !.R2 := AST.xtlo 64<rt> t |]
    |> test microR6
    "58831058"
    ++ [| t := sx !.R3 .* sx !.R4
          !.R2 := AST.xthi 64<rt> t |]
    |> test microR6
    "58831098"
    ++ [| t := zx !.R3 .* zx !.R4
          !.R2 := AST.xtlo 64<rt> t |]
    |> test microR6
    "588310d8"
    ++ [| t := zx !.R3 .* zx !.R4
          !.R2 := AST.xthi 64<rt> t |]
    |> test microR6

  /// <summary>
  /// JALRC and JALRC.HB (MD00582 revision 6.04, pp.202 to 205) jump from the
  /// instruction itself, with no delay slot, and link "PC + 4" with the ISA
  /// mode in bit 0, which section 2.4 has every jump-and-link-register
  /// instruction save. Before Release 6 the same words are JALR and JALR.HB,
  /// which leave the same jump armed for the slot after them.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS64R6] JALRC and JALRC.HB have no slot (32r6 p.202)``() =
    let regs = RegisterFactory microR6 :> IRegisterFactory
    let var r = Register.toRegID r |> regs.GetRegVar
    let link = var R31 := (var PC .+ numI32 4 64<rt>) .| AST.num1 64<rt>
    let call = InterJmpKind.IsCall
    let jumps =
      [| call ||| InterJmpKind.SwitchToMicroMIPS
         call ||| InterJmpKind.SwitchToMIPS |]
    let preR6 = int MIPSISAMode.MicroMIPS
    let pre = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64, preR6)
    let micro = MIPSISAMode.MicroMIPS
    (* JALRC ra, a1 and JALRC.HB ra, a1, each with a NOP after it *)
    for hex in [ "03e50f3c"; "03e51f3c" ] do
      let stmts = lifted microR6 hex
      let own =
        stmts
        |> Array.choose (function
          | InterJmp(Kind = kind) -> Some kind
          | _ -> None)
      CollectionAssert.AreEqual(jumps, own, hex)
      let slot = jumpKinds microR6 micro hex "00000000"
      CollectionAssert.AreEqual(Array.empty<InterJmpKind>, slot, hex)
      CollectionAssert.AreEqual(jumps, jumpKinds pre micro hex "00000000", hex)
      CollectionAssert.Contains(stmts, link, hex)

  /// <summary>
  /// DAHI and DATI (MD00594 revision 6.01, p.134) add the immediate shifted
  /// into the upper halves of the register they name:
  /// "GPR[rs] &lt;- GPR[rs] + sign_extend(immediate &lt;&lt; 32)", and 48
  /// for DATI. With v1 = 0x12345678 and an immediate of 0x1234 that is
  /// 0x0000123412345678 and 0x1234000012345678.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS64R6] DAHI and DATI lift (64r6 p.134)``() =
    let regs = RegisterFactory microR6 :> IRegisterFactory
    let var r = Register.toRegID r |> regs.GetRegVar
    let inputs = [ var R3, BitVector(0x12345678UL, 64<rt>) ]
    let after hex =
      (IRRunner.run (lifted microR6 hex) inputs (var R3)).ToUInt64()
    (* DAHI v1, 0x1234 and DATI v1, 0x1234 *)
    Assert.AreEqual<uint64>(0x0000123412345678UL, after "42231234")
    Assert.AreEqual<uint64>(0x1234000012345678UL, after "42031234")

  /// <summary>
  /// DAUI, DAHI and DATI (MD00087 revision 6.06, AUI DAUI DAHI DATI) add
  /// the immediate SIGN-EXTENDED once shifted: "GPR[rt] &lt;- GPR[rs] +
  /// sign_extend(immediate &lt;&lt; 16)", 32 for DAHI and 48 for DATI. An
  /// immediate with its top bit set is therefore negative: with v1 =
  /// 0x12345678, DAUI by 0x8000 adds 0xFFFFFFFF80000000 and DAHI by 0x8001
  /// adds 0xFFFF800100000000, in the 32-bit encoding and in microMIPS alike.
  /// </summary>
  [<TestMethod>]
  member _.``[MIPS64R6] DAUI and DAHI sign-extend the shifted immediate``() =
    let r6 =
      ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64, int MIPSRelease.R6)
    let regs = RegisterFactory r6 :> IRegisterFactory
    let var r = Register.toRegID r |> regs.GetRegVar
    let inputs = [ var R3, BitVector(0x12345678UL, 64<rt>) ]
    let after isa hex dst =
      (IRRunner.run (lifted isa hex) inputs (var dst)).ToUInt64()
    (* DAUI v0, v1, 0x8000; DAHI v1, 0x8001; DATI v1, 0x8001 *)
    Assert.AreEqual<uint64>(0xFFFFFFFF92345678UL, after r6 "74628000" R2)
    Assert.AreEqual<uint64>(0xFFFF800112345678UL, after r6 "04668001" R3)
    Assert.AreEqual<uint64>(0x8001000012345678UL, after r6 "047e8001" R3)
    (* DAHI v1, 0x8001 in microMIPS *)
    Assert.AreEqual<uint64>(0xFFFF800112345678UL,
                            after microR6 "42238001" R3)

  /// SYNCI at Release 6 (MD00582 revision 6.04, p.338) lifts as SYNCI does in
  /// the older encoding: to no statement at all.
  [<TestMethod>]
  member _.``[microMIPS64R6] SYNCI lifts to nothing (32r6 p.338)``() =
    (* SYNCI 8(a0) *)
    "41840008" ++ [||] |> test microR6

  /// <summary>
  /// ADDU16 and SUBU16 at Release 6 (MD00582 revision 6.04, pp.71 and 105)
  /// write rd, bits 3..1, from rs, bits 9..7, and rt, bits 6..4:
  /// "GPR[rd] &lt;- GPR[rs] + GPR[rt]". With v1 = 10 and a0 = 3, the
  /// halfwords 05c4 and 05c5 leave 13 and 7 in v0, and v1 as it was.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS64R6] ADDU16 and SUBU16 write rd (32r6 p.71)``() =
    let regs = RegisterFactory microR6 :> IRegisterFactory
    let var r = Register.toRegID r |> regs.GetRegVar
    let inputs =
      [ var R3, BitVector(10UL, 64<rt>)
        var R4, BitVector(3UL, 64<rt>) ]
    for hex, result in [ "05c4", 13UL; "05c5", 7UL ] do
      let read = IRRunner.run (lifted microR6 hex) inputs
      Assert.AreEqual<uint64>(result, (read (var R2)).ToUInt64(), hex)
      Assert.AreEqual<uint64>(10UL, (read (var R3)).ToUInt64(), hex)

  /// <summary>
  /// LWPC, LLWP and SCWP move memory in the processor's own byte order. Each
  /// page reaches memory through LoadMemory or StoreMemory (MD00582 revision
  /// 6.04, LWPC p.236, LLWP p.227, SCWP p.295), which order the bytes the way
  /// BigEndianCPU says, and LLWP's two words are the halves of the doubleword
  /// read so: "GPR[rt] &lt;- memdoubleword31..0" and "GPR[rd] &lt;-
  /// memdoubleword63..32". These three read and wrote little-endian whatever
  /// the processor, so on a big-endian one a word came back with its bytes
  /// reversed and LLWP's pair the wrong way round.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS64R6] LWPC, LLWP and SCWP use the native order``() =
    let regs = RegisterFactory microR6 :> IRegisterFactory
    let ( !. ) name = Register.toRegID name |> regs.GetRegVar
    let t = AST.tmpvar 64<rt> 1
    let lo32 e = AST.xtlo 32<rt> e
    let one, zero = AST.num1 1<rt>, AST.num0 1<rt>
    (* LWPC a1, at -0xffff4 *)
    let target = numU64 0xfffffffffff0000cUL 64<rt>
    "78ac0003"
    ++ [| !.R5 := AST.sext 64<rt> (AST.loadBE 32<rt> target) |]
    |> test microR6
    (* LLWP v1, t2, 0(s0) *)
    let addr = !.R16 .+ numI64 0L 64<rt>
    "607010e0"
    ++ [| t := AST.loadBE 64<rt> addr
          !.ExMonAddr := addr
          !.ExMonVal := AST.zext 64<rt> (lo32 t)
          !.R14 := AST.sext 64<rt> (AST.xthi 32<rt> t)
          !.R3 := AST.sext 64<rt> (lo32 t) |]
    |> test microR6
    (* SCWP a7, v0, 0(sp) *)
    let addr = !.R29 .+ numI64 0L 64<rt>
    let ok = !.ExMonAddr == addr
    let pair = AST.concat (lo32 !.R2) (lo32 !.R11)
    "617d9020"
    ++ [| AST.loadBE 64<rt> addr := AST.ite ok pair (AST.loadBE 64<rt> addr)
          !.R11 := AST.zext 64<rt> (AST.ite ok one zero) |]
    |> test microR6

  /// <summary>
  /// microMIPS64's LWUPC counts from its own address, "PC +
  /// sign_extend(offset &lt;&lt; 2)" (MD00594 revision 6.01, p.291), and LDPC
  /// from the doubleword holding it, "(PC&amp;~0x7) + sign_extend(offset
  /// &lt;&lt; 3)" (p.262). The decoder cleared the address's two low bits for
  /// both, as ADDIUPC and LWPC do (MD00582 revision 6.04, pp.119 and 236), so
  /// at 0x1002 LWUPC read two bytes below its place and LDPC, aligned again
  /// by the lifter, two bytes below its own.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS64R6] LWUPC and LDPC count from their own PC``() =
    let regs = RegisterFactory microR6 :> IRegisterFactory
    let var r = Register.toRegID r |> regs.GetRegVar
    let liftedAt (hex: string) =
      let bld = LowUIRBuilder(microR6, RegisterFactory microR6, LowUIRStream())
      let p = Parser(microR6, BinReader.Init Endian.Big)
      let p = p :> IInstructionParsable
      (p.Parse(ByteArray.ofHexString hex, 0x1002UL)).Translate bld
    let at (v: uint64) = numU64 v 64<rt>
    (* LWUPC t2 by -0xfffe4 and LDPC s4 by -0xfffb8, at 0x1002 *)
    let lwupc =
      var R14 := AST.zext 64<rt> (AST.loadBE 32<rt> (at 0xfffffffffff0101eUL))
    CollectionAssert.Contains(liftedAt "79d40007", lwupc)
    let ldpc = var R20 := AST.loadBE 64<rt> (at 0xfffffffffff01048UL)
    CollectionAssert.Contains(liftedAt "7a9a0009", ldpc)

  /// <summary>
  /// A microMIPS compact call leaves the ISA mode in bit 0 of its link, as
  /// JALRC does. Table 1.1 (MD00582 revision 6.04, p.18) has a
  /// "branch-and-link instruction" store "a combined value of the upper bits
  /// of PC and the ISA Mode", and section 2.4 (p.22) names JIALC among the
  /// jump-and-link-register instructions that "save the ISA mode into bit 0
  /// of the destination register"; BALC's, the B{LE,GE,GT,LT,EQ,NE}ZALC and
  /// JIALC's pages (pp.128, 134 and 207) write the link "PC+4" as JALRC16's
  /// writes "PC + 2". A return through JRC reads that bit for the mode to go
  /// back to, so a link of PC + 4 alone sent the return into MIPS32.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS64R6] BALC, the ZALC branches and JIALC link odd``() =
    let regs = RegisterFactory microR6 :> IRegisterFactory
    let var r = Register.toRegID r |> regs.GetRegVar
    let link = var R31 := (var PC .+ numI32 4 64<rt>) .| AST.num1 64<rt>
    (* BALC, BLEZALC a2, BEQZALC a5 and JIALC t9 *)
    for hex in [ "b6000003"; "c0c08007"; "75208000"; "a0198011" ] do
      CollectionAssert.Contains(lifted microR6 hex, link, hex)

  /// <summary>
  /// microMIPS's JIC and JIALC go on in the encoding bit 0 of their target
  /// names, at the target with that bit cleared: "PC &lt;- (tempGPRLEN-1..1
  /// || 0); ISAMode &lt;- temp0" (MD00582 revision 6.04, pp.207-209), which
  /// section 2.4 (p.22) has every jump-register instruction do. These jumped
  /// to the sum as it was, naming no encoding, where JRC16 and JALRC16 pick
  /// one.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS64R6] JIC and JIALC take the mode from bit 0``() =
    let jumps kind =
      [| kind ||| InterJmpKind.SwitchToMicroMIPS
         kind ||| InterJmpKind.SwitchToMIPS |]
    let masked = AST.tmpvar 64<rt> 1 .& AST.not (AST.num1 64<rt>)
    (* JIC a3 and JIALC t9 *)
    for hex, kind in [ "8007fff1", InterJmpKind.Base
                       "a0198011", InterJmpKind.IsCall ] do
      let stmts = lifted microR6 hex
      let kinds =
        stmts
        |> Array.choose (function
          | InterJmp(Target = t; Kind = k) when t = masked -> Some k
          | _ -> None)
      CollectionAssert.AreEqual(jumps kind, kinds, hex)

  /// <summary>
  /// On a 64-bit processor BOVC and BNVC count an operand that is not a
  /// sign-extended word as an overflow: "input_overflow &lt;-
  /// NotWordValue(GPR[rs]) or NotWordValue(GPR[rt])", and "BOVC: cond &lt;-
  /// sum_overflow or input_overflow" (MD00594 revision 6.01, p.155). These
  /// looked at the low words alone, so 0x100000000 plus zero did not
  /// overflow and BOVC a5, a0 was not taken, BNVC s5, zero taken.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS64R6] BOVC and BNVC check their inputs are words``() =
    let regs = RegisterFactory microR6 :> IRegisterFactory
    let var r = Register.toRegID r |> regs.GetRegVar
    let taken hex first second (a: uint64) =
      let stmts =
        lifted microR6 hex
        |> Array.map (function
          | InterCJmp(Cond = c) -> var NPC := AST.zext 64<rt> c
          | stmt -> stmt)
      let zero = BitVector(0UL, 64<rt>)
      let inputs = [ var first, BitVector(a, 64<rt>); var second, zero ]
      (IRRunner.run stmts inputs (var NPC)).ToUInt64() = 1UL
    let bovc = taken "7489800d" R9 R4
    Assert.AreEqual<bool>(true, bovc 0x100000000UL)
    Assert.AreEqual<bool>(false, bovc 0xffffffff80000000UL)
    let bnvc = taken "7c150007" R21 R0
    Assert.AreEqual<bool>(false, bnvc 0x100000000UL)
    Assert.AreEqual<bool>(true, bnvc 0x7fffffffUL)

  /// <summary>
  /// RDHWR reads through a select only the hardware register that has more
  /// than one instance, the performance counters (4): "In Release 6, when
  /// the 3-bit sel is undefined for use with a specific register number, then
  /// a Reserved Instruction Exception is signaled" (MD00582 revision 6.04,
  /// p.275). UserLocal (29) has one, so RDHWR a4, $29 reads it with select 0
  /// and is a Reserved Instruction with select 5, where this lifter read it
  /// either way.
  /// </summary>
  [<TestMethod>]
  member _.``[microMIPS64R6] RDHWR refuses a select its register lacks``() =
    let effects hex =
      lifted microR6 hex
      |> Array.choose (function
        | SideEffect(Effect = e) -> Some e
        | _ -> None)
    CollectionAssert.AreEqual([| UndefinedInstruction |], effects "011d29c0")
    CollectionAssert.AreEqual(Array.empty<SideEffect>, effects "011d01c0")

  /// <summary>
  /// The SmartMIPS ASE (MD00101), which no QEMU model runs, so these follow
  /// its Operation sections: MULTP and MADDP multiply as binary polynomials
  /// (carry-less), MULTP clearing ACX and MADDP adding with exclusive-OR into
  /// HI and LO and leaving ACX; PPERM shifts ACX, HI and LO left by six as one
  /// accumulator and fills the bottom six bits of LO with the bits of rs that
  /// rt's six five-bit fields name, the lowest field for bit 0; MFLHXU and
  /// MTLHX shift the accumulator down and up a register. The words are
  /// binutils' under -msmartmips.
  /// </summary>
  [<TestMethod>]
  member _.``[SmartMIPS] The accumulator instructions follow MD00101``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit32)
    let regs = RegisterFactory isa :> IRegisterFactory
    let var r = Register.toRegID r |> regs.GetRegVar
    let bv r (v: uint64) = var r, BitVector(v, Expr.typeOf (var r))
    let run hex rs rt =
      let inputs =
        [ bv HI 0x87654321UL
          bv LO 0x0fedcba9UL
          bv ACX 0x3cUL
          bv R2 rs
          bv R3 rt ]
      let read = IRRunner.run (lifted isa hex) inputs
      fun r -> (read (var r)).ToUInt64()
    let check hex rs rt (expected: (Register * uint64) list) =
      let read = run hex rs rt
      for r, v in expected do
        Assert.AreEqual<uint64>(v, read r, $"{hex} {r}")
    (* MULTP v0, v1 *)
    [ HI, 0x60000003UL; LO, 0xc000000fUL; ACX, 0x0UL ]
    |> check "00430459" 0x80000003UL 0xc0000005UL
    (* MADDP v0, v1 *)
    [ HI, 0xe7654322UL; LO, 0xcfedcba6UL; ACX, 0x3cUL ]
    |> check "70430441" 0x80000003UL 0xc0000005UL
    (* PPERM v0, v1 *)
    [ HI, 0xd950c843UL; LO, 0xfb72ea77UL; ACX, 0x21UL ]
    |> check "70430481" 0xdeadbeefUL 0x3e0243c1UL
    (* MFLHXU a0 *)
    [ R4, 0x0fedcba9UL; LO, 0x87654321UL; HI, 0x3cUL; ACX, 0x0UL ]
    |> check "00002052" 0UL 0UL
    (* MTLHX v0 *)
    [ ACX, 0x21UL; HI, 0x0fedcba9UL; LO, 0x80000003UL ]
    |> check "00400053" 0x80000003UL 0UL

  (* One test for each instruction MD00087, MD00076, MD00077 and microMIPS64
     5.04 describes, in the order of its sections. A value test runs a word's
     lifting over inputs QEMU ran the word on (qemu-mips64 and qemu-mips on the
     CPU each needs) and asserts what QEMU left. A structural test is for a word
     a user-mode run cannot execute alone; its doc comment says what it checks,
     and its expectation is the manual's. *)
  /// <summary>
  /// 46002085, abs.s f2, f4, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ABS.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run r2 [ "46002085" ]
    |> is [ F 2, 0x40100000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL ]
    |> run r2 [ "46002085" ]
    |> is [ F 2, 0x40c00000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL ]
    |> run r2 [ "46002085" ]
    |> is [ F 2, 0x447a0000UL ]

  /// <summary>
  /// 00641020, add v0, v1, a0, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGFPE (Exception IntegerOverflow here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ADD``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "00641020" ]
    |> is [ G 2, 0x8UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "00641020" ]
    |> is [ G 2, 0xffffffffffffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "00641020" ]
    |> is [ G 2, 0x11111110UL ]
    [ G 2, 0x7UL; G 3, 0x7fffffffUL; G 4, 0x1UL ]
    |> run r2 [ "00641020" ]
    |> raises [ Exception IntegerOverflow ] []

  /// <summary>
  /// 46062080, add.s f2, f4, f6, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ADD.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; F 6, 0x3fc00000UL ]
    |> run r2 [ "46062080" ]
    |> is [ F 2, 0x40700000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; F 6, 0x3f400000UL ]
    |> run r2 [ "46062080" ]
    |> is [ F 2, 0xc0a80000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL ]
    |> run r2 [ "46062080" ]
    |> is [ F 2, 0x447a0800UL ]

  /// <summary>
  /// 20620100, addi v0, v1, 0x100, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGFPE (Exception IntegerOverflow here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ADDI``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "20620100" ]
    |> is [ G 2, 0x103UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "20620100" ]
    |> is [ G 2, 0x101UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "20620100" ]
    |> is [ G 2, 0x12345778UL ]
    [ G 2, 0x7UL; G 3, 0x7fffffffUL ]
    |> run r2 [ "20620100" ]
    |> raises [ Exception IntegerOverflow ] []

  /// <summary>
  /// 24620100, addiu v0, v1, 0x100, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ADDIU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "24620100" ]
    |> is [ G 2, 0x103UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "24620100" ]
    |> is [ G 2, 0x101UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "24620100" ]
    |> is [ G 2, 0x12345778UL ]

  /// <summary>
  /// ec400001, addiupc v0, 0x20100004, against QEMU's I6400, a Release 6
  /// processor: the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ADDIUPC``() =
    [ G 2, 0x7UL ]
    |> run r6 [ "ec400001" ]
    |> is [ G 2, 0x20100004UL ]
    [ G 2, 0x7fffffffUL ]
    |> run r6 [ "ec400001" ]
    |> is [ G 2, 0x20100004UL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r6 [ "ec400001" ]
    |> is [ G 2, 0x20100004UL ]

  /// <summary>
  /// 00641021, addu v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ADDU``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "00641021" ]
    |> is [ G 2, 0x8UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "00641021" ]
    |> is [ G 2, 0xffffffffffffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "00641021" ]
    |> is [ G 2, 0x11111110UL ]

  /// <summary>
  /// 7c641260, align v0, v1, a0, 0x1, against QEMU's I6400, a Release 6
  /// processor: the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ALIGN``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "7c641260" ]
    |> is [ G 2, 0x500UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "7c641260" ]
    |> is [ G 2, 0xfffffffffffffe00UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r6 [ "7c641260" ]
    |> is [ G 2, 0xffffffffdcba9812UL ]

  /// <summary>
  /// 4c46209e, alnv.ps f2, f4, f6, v0, against QEMU's MIPS64R2-generic: the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ALNV.PS``() =
    let given0 =
      [ F 2, 0xbf8000003f800000UL
        F 4, 0x40100000bfc00000UL
        F 6, 0x3fc000003e800000UL ]
    given0
    |> run r2 [ "4c46209e" ]
    |> is [ F 2, 0x40100000bfc00000UL ]
    let given1 =
      [ G 2, 0x4UL
        F 2, 0x40600000c0600000UL
        F 4, 0xc0c000003f000000UL
        F 6, 0x3f40000040000000UL ]
    given1
    |> run r2 [ "4c46209e" ]
    |> is [ F 2, 0x3f0000003f400000UL ]
    let given2 =
      [ G 2, 0x4UL
        F 2, 0x3e8000003f400000UL
        F 4, 0x447a000040400000UL
        F 6, 0x3e000000c0800000UL ]
    given2
    |> run r2 [ "4c46209e" ]
    |> is [ F 2, 0x404000003e000000UL ]

  /// <summary>
  /// ec5f1900, aluipc v0, 0x1900, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ALUIPC``() =
    [ G 2, 0x7UL ]
    |> run r6 [ "ec5f1900" ]
    |> is [ G 2, 0x39100000UL ]
    [ G 2, 0x7fffffffUL ]
    |> run r6 [ "ec5f1900" ]
    |> is [ G 2, 0x39100000UL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r6 [ "ec5f1900" ]
    |> is [ G 2, 0x39100000UL ]

  /// <summary>
  /// 00641024, and v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 AND``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "00641024" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "00641024" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "00641024" ]
    |> is [ G 2, 0x12141218UL ]

  /// <summary>
  /// 30620100, andi v0, v1, 0x100, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ANDI``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "30620100" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "30620100" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "30620100" ]
    |> is [ G 2, 0x0UL ]

  /// <summary>
  /// 3c620100, aui v0, v1, 0x100, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 AUI``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r6 [ "3c620100" ]
    |> is [ G 2, 0x1000003UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r6 [ "3c620100" ]
    |> is [ G 2, 0x1000001UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r6 [ "3c620100" ]
    |> is [ G 2, 0x13345678UL ]

  /// <summary>
  /// ec5e1900, auipc v0, 0x1900, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 AUIPC``() =
    [ G 2, 0x7UL ]
    |> run r6 [ "ec5e1900" ]
    |> is [ G 2, 0x39100000UL ]
    [ G 2, 0x7fffffffUL ]
    |> run r6 [ "ec5e1900" ]
    |> is [ G 2, 0x39100000UL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r6 [ "ec5e1900" ]
    |> is [ G 2, 0x39100000UL ]

  /// <summary>
  /// 10000100, b 0x20100404 (binutils: b 20100404). A branch is not run against
  /// QEMU: it moves the PC, and its delay slot makes one word meaningless to
  /// run alone. Checked structurally from the manual: the transfer is left to
  /// the delay slot, which holds a NOP; control goes to 0x20100404 (the target
  /// binutils reads) when it always does.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 B``() =
    let words = [ "10000100"; "00000000" ]
    ownsJump r2 "10000100" false
    goes r2 words [] 0x20100404UL

  /// <summary>
  /// 04110100, bal 0x20100404 (binutils: bal 20100404). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100404 (the target binutils reads) when it always does; ra becomes
  /// 0x20100008 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BAL``() =
    let words = [ "04110100"; "00000000" ]
    ownsJump r2 "04110100" false
    goes r2 words [] 0x20100404UL
    []
    |> run r2 words
    |> is [ G 31, 0x20100008UL ]

  /// <summary>
  /// e8000100, balc 0x20100404 (binutils: balc 20100404). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100404 (the target binutils reads) when it always does; ra becomes
  /// 0x20100004 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BALC``() =
    let words = [ "e8000100" ]
    ownsJump r6 "e8000100" true
    goes r6 words [] 0x20100404UL
    []
    |> run r6 words
    |> is [ G 31, 0x20100004UL ]

  /// <summary>
  /// c8000100, bc 0x20100404 (binutils: bc 20100404). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100404 (the target binutils reads) when it always does.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BC``() =
    let words = [ "c8000100" ]
    ownsJump r6 "c8000100" true
    goes r6 words [] 0x20100404UL

  /// <summary>
  /// 45200100, bc1eqz f0, 0x20100404 (binutils: bc1eqz $f0,20100404). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100404 (the target binutils reads) when it always does; to 0x20100008,
  /// past the slot, when F 0 is 0x1.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BC1EQZ``() =
    let words = [ "45200100"; "00000000" ]
    ownsJump r6 "45200100" false
    goes r6 words [] 0x20100404UL
    goes r6 words [ F 0, 0x1UL ] 0x20100008UL

  /// <summary>
  /// 45000100, bc1f 0x20100404 (binutils: bc1f 20100404). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100404 (the target binutils reads) when it always does; to 0x20100008,
  /// past the slot, when Fcsr is 0x800000.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BC1F``() =
    let words = [ "45000100"; "00000000" ]
    ownsJump r2 "45000100" false
    goes r2 words [] 0x20100404UL
    goes r2 words [ Fcsr, 0x800000UL ] 0x20100008UL

  /// <summary>
  /// 45021901, bc1fl 0x20106408 (binutils: bc1fl 20106408). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: control
  /// goes to 0x20106408 (the target binutils reads) when it always does; to
  /// 0x20100008, past the slot, when Fcsr is 0x800000.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BC1FL``() =
    let words = [ "45021901"; "00000000" ]
    goes r2 words [] 0x20106408UL
    goes r2 words [ Fcsr, 0x800000UL ] 0x20100008UL

  /// <summary>
  /// 45a00100, bc1nez f0, 0x20100404 (binutils: bc1nez $f0,20100404). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100404 (the target binutils reads) when F 0 is 0x1; to 0x20100008,
  /// past the slot, when nothing is given.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BC1NEZ``() =
    let words = [ "45a00100"; "00000000" ]
    ownsJump r6 "45a00100" false
    goes r6 words [ F 0, 0x1UL ] 0x20100404UL
    goes r6 words [] 0x20100008UL

  /// <summary>
  /// 45011801, bc1t 0x20106008 (binutils: bc1t 20106008). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20106008 (the target binutils reads) when Fcsr is 0x800000; to
  /// 0x20100008, past the slot, when nothing is given.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BC1T``() =
    let words = [ "45011801"; "00000000" ]
    ownsJump r2 "45011801" false
    goes r2 words [ Fcsr, 0x800000UL ] 0x20106008UL
    goes r2 words [] 0x20100008UL

  /// <summary>
  /// 45031801, bc1tl 0x20106008 (binutils: bc1tl 20106008). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: control
  /// goes to 0x20106008 (the target binutils reads) when Fcsr is 0x800000; to
  /// 0x20100008, past the slot, when nothing is given.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BC1TL``() =
    let words = [ "45031801"; "00000000" ]
    goes r2 words [ Fcsr, 0x800000UL ] 0x20106008UL
    goes r2 words [] 0x20100008UL

  /// <summary>
  /// 49200000, bc2eqz 0x0, 0x20100004. A branch is not run against QEMU; this
  /// processor has no coprocessor 2 (Config1.C2 is clear), and every
  /// instruction that reaches it takes Coprocessor Unusable, a branch on its
  /// condition before it branches. The lift raises UndefinedInstruction and
  /// changes nothing.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BC2EQZ``() =
    []
    |> run r6 [ "49200000" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 49000001, bc2f 0x20100008. A branch is not run against QEMU; this
  /// processor has no coprocessor 2 (Config1.C2 is clear), and every
  /// instruction that reaches it takes Coprocessor Unusable, a branch on its
  /// condition before it branches. The lift raises UndefinedInstruction and
  /// changes nothing.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BC2F``() =
    []
    |> run r2 [ "49000001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 49021901, bc2fl 0x20106408. A branch is not run against QEMU; this
  /// processor has no coprocessor 2 (Config1.C2 is clear), and every
  /// instruction that reaches it takes Coprocessor Unusable, a branch on its
  /// condition before it branches. The lift raises UndefinedInstruction and
  /// changes nothing.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BC2FL``() =
    []
    |> run r2 [ "49021901" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 49a00000, bc2nez 0x0, 0x20100004. A branch is not run against QEMU; this
  /// processor has no coprocessor 2 (Config1.C2 is clear), and every
  /// instruction that reaches it takes Coprocessor Unusable, a branch on its
  /// condition before it branches. The lift raises UndefinedInstruction and
  /// changes nothing.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BC2NEZ``() =
    []
    |> run r6 [ "49a00000" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 49010004, bc2t 0x20100014. A branch is not run against QEMU; this
  /// processor has no coprocessor 2 (Config1.C2 is clear), and every
  /// instruction that reaches it takes Coprocessor Unusable, a branch on its
  /// condition before it branches. The lift raises UndefinedInstruction and
  /// changes nothing.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BC2T``() =
    []
    |> run r2 [ "49010004" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 49030002, bc2tl 0x2010000c. A branch is not run against QEMU; this
  /// processor has no coprocessor 2 (Config1.C2 is clear), and every
  /// instruction that reaches it takes Coprocessor Unusable, a branch on its
  /// condition before it branches. The lift raises UndefinedInstruction and
  /// changes nothing.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BC2TL``() =
    []
    |> run r2 [ "49030002" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 10430101, beq v0, v1, 0x20100408 (binutils: beq $2,$3,20100408). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100408 (the target binutils reads) when G 2 is 0x5 and G 3 is 0x5; to
  /// 0x20100008, past the slot, when G 2 is 0x5 and G 3 is 0x6.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BEQ``() =
    let words = [ "10430101"; "00000000" ]
    ownsJump r2 "10430101" false
    goes r2 words [ G 2, 0x5UL; G 3, 0x5UL ] 0x20100408UL
    goes r2 words [ G 2, 0x5UL; G 3, 0x6UL ] 0x20100008UL

  /// <summary>
  /// 20430101, beqc v0, v1, 0x20100408 (binutils: beqc $2,$3,20100408). A
  /// branch is not run against QEMU: it moves the PC, and its delay slot makes
  /// one word meaningless to run alone. Checked structurally from the manual:
  /// the transfer is the branch's own, there being no delay slot; control goes
  /// to 0x20100408 (the target binutils reads) when G 2 is 0x5 and G 3 is 0x5;
  /// to 0x20100004, past the branch, when G 2 is 0x5 and G 3 is 0x6.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BEQC``() =
    let words = [ "20430101" ]
    ownsJump r6 "20430101" true
    goes r6 words [ G 2, 0x5UL; G 3, 0x5UL ] 0x20100408UL
    goes r6 words [ G 2, 0x5UL; G 3, 0x6UL ] 0x20100004UL

  /// <summary>
  /// 50430101, beql v0, v1, 0x20100408 (binutils: beql $2,$3,20100408). A
  /// branch is not run against QEMU: it moves the PC, and its delay slot makes
  /// one word meaningless to run alone. Checked structurally from the manual:
  /// control goes to 0x20100408 (the target binutils reads) when G 2 is 0x5 and
  /// G 3 is 0x5; to 0x20100008, past the slot, when G 2 is 0x5 and G 3 is 0x6.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BEQL``() =
    let words = [ "50430101"; "00000000" ]
    goes r2 words [ G 2, 0x5UL; G 3, 0x5UL ] 0x20100408UL
    goes r2 words [ G 2, 0x5UL; G 3, 0x6UL ] 0x20100008UL

  /// <summary>
  /// 20010100, beqzalc at, 0x20100404 (binutils: beqzalc $1,20100404). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100404 (the target binutils reads) when it always does; to 0x20100004,
  /// past the branch, when G 1 is 0x5; ra becomes 0x20100004 and nothing else
  /// changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BEQZALC``() =
    let words = [ "20010100" ]
    ownsJump r6 "20010100" true
    goes r6 words [] 0x20100404UL
    goes r6 words [ G 1, 0x5UL ] 0x20100004UL
    []
    |> run r6 words
    |> is [ G 31, 0x20100004UL ]

  /// <summary>
  /// d8200100, beqzc at, 0x20100404 (binutils: beqzc $1,20100404). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100404 (the target binutils reads) when it always does; to 0x20100004,
  /// past the branch, when G 1 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BEQZC``() =
    let words = [ "d8200100" ]
    ownsJump r6 "d8200100" true
    goes r6 words [] 0x20100404UL
    goes r6 words [ G 1, 0x5UL ] 0x20100004UL

  /// <summary>
  /// 58430101, bgec v0, v1, 0x20100408 (binutils: bgec $2,$3,20100408). A
  /// branch is not run against QEMU: it moves the PC, and its delay slot makes
  /// one word meaningless to run alone. Checked structurally from the manual:
  /// the transfer is the branch's own, there being no delay slot; control goes
  /// to 0x20100408 (the target binutils reads) when G 2 is 0x5 and G 3 is 0x3;
  /// to 0x20100004, past the branch, when G 2 is 0x3 and G 3 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BGEC``() =
    let words = [ "58430101" ]
    ownsJump r6 "58430101" true
    goes r6 words [ G 2, 0x5UL; G 3, 0x3UL ] 0x20100408UL
    goes r6 words [ G 2, 0x3UL; G 3, 0x5UL ] 0x20100004UL

  /// <summary>
  /// 18430101, bgeuc v0, v1, 0x20100408 (binutils: bgeuc $2,$3,20100408). A
  /// branch is not run against QEMU: it moves the PC, and its delay slot makes
  /// one word meaningless to run alone. Checked structurally from the manual:
  /// the transfer is the branch's own, there being no delay slot; control goes
  /// to 0x20100408 (the target binutils reads) when G 2 is 0xffffffffffffffff
  /// and G 3 is 0x3; to 0x20100004, past the branch, when G 2 is 0x3 and G 3 is
  /// 0xffffffffffffffff.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BGEUC``() =
    let words = [ "18430101" ]
    ownsJump r6 "18430101" true
    goes r6 words [ G 2, 0xffffffffffffffffUL; G 3, 0x3UL ] 0x20100408UL
    goes r6 words [ G 2, 0x3UL; G 3, 0xffffffffffffffffUL ] 0x20100004UL

  /// <summary>
  /// 04411901, bgez v0, 0x20106408 (binutils: bgez $2,20106408). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20106408 (the target binutils reads) when G 2 is 0x5; to 0x20100008,
  /// past the slot, when G 2 is 0xfffffffffffffffb.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BGEZ``() =
    let words = [ "04411901"; "00000000" ]
    ownsJump r2 "04411901" false
    goes r2 words [ G 2, 0x5UL ] 0x20106408UL
    goes r2 words [ G 2, 0xfffffffffffffffbUL ] 0x20100008UL

  /// <summary>
  /// 04511901, bgezal v0, 0x20106408 (binutils: bgezal $2,20106408). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20106408 (the target binutils reads) when G 2 is 0x5; to 0x20100008,
  /// past the slot, when G 2 is 0xfffffffffffffffb; ra becomes 0x20100008 and
  /// nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BGEZAL``() =
    let words = [ "04511901"; "00000000" ]
    ownsJump r2 "04511901" false
    goes r2 words [ G 2, 0x5UL ] 0x20106408UL
    goes r2 words [ G 2, 0xfffffffffffffffbUL ] 0x20100008UL
    [ G 2, 0x5UL ]
    |> run r2 words
    |> is [ G 31, 0x20100008UL ]

  /// <summary>
  /// 18421901, bgezalc v0, 0x20106408 (binutils: bgezalc $2,20106408). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20106408 (the target binutils reads) when G 2 is 0x5; to 0x20100004,
  /// past the branch, when G 2 is 0xfffffffffffffffb; ra becomes 0x20100004 and
  /// nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BGEZALC``() =
    let words = [ "18421901" ]
    ownsJump r6 "18421901" true
    goes r6 words [ G 2, 0x5UL ] 0x20106408UL
    goes r6 words [ G 2, 0xfffffffffffffffbUL ] 0x20100004UL
    [ G 2, 0x5UL ]
    |> run r6 words
    |> is [ G 31, 0x20100004UL ]

  /// <summary>
  /// 04531901, bgezall v0, 0x20106408 (binutils: bgezall $2,20106408). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual:
  /// control goes to 0x20106408 (the target binutils reads) when G 2 is 0x5; to
  /// 0x20100008, past the slot, when G 2 is 0xfffffffffffffffb; ra becomes
  /// 0x20100008 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BGEZALL``() =
    let words = [ "04531901"; "00000000" ]
    goes r2 words [ G 2, 0x5UL ] 0x20106408UL
    goes r2 words [ G 2, 0xfffffffffffffffbUL ] 0x20100008UL
    [ G 2, 0x5UL ]
    |> run r2 words
    |> is [ G 31, 0x20100008UL ]

  /// <summary>
  /// 58421901, bgezc v0, 0x20106408 (binutils: bgezc $2,20106408). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20106408 (the target binutils reads) when G 2 is 0x5; to 0x20100004,
  /// past the branch, when G 2 is 0xfffffffffffffffb.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BGEZC``() =
    let words = [ "58421901" ]
    ownsJump r6 "58421901" true
    goes r6 words [ G 2, 0x5UL ] 0x20106408UL
    goes r6 words [ G 2, 0xfffffffffffffffbUL ] 0x20100004UL

  /// <summary>
  /// 04431901, bgezl v0, 0x20106408 (binutils: bgezl $2,20106408). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: control
  /// goes to 0x20106408 (the target binutils reads) when G 2 is 0x5; to
  /// 0x20100008, past the slot, when G 2 is 0xfffffffffffffffb.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BGEZL``() =
    let words = [ "04431901"; "00000000" ]
    goes r2 words [ G 2, 0x5UL ] 0x20106408UL
    goes r2 words [ G 2, 0xfffffffffffffffbUL ] 0x20100008UL

  /// <summary>
  /// 1c200100, bgtz at, 0x20100404 (binutils: bgtz $1,20100404). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100404 (the target binutils reads) when G 1 is 0x5; to 0x20100008,
  /// past the slot, when nothing is given.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BGTZ``() =
    let words = [ "1c200100"; "00000000" ]
    ownsJump r2 "1c200100" false
    goes r2 words [ G 1, 0x5UL ] 0x20100404UL
    goes r2 words [] 0x20100008UL

  /// <summary>
  /// 1c010100, bgtzalc at, 0x20100404 (binutils: bgtzalc $1,20100404). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100404 (the target binutils reads) when G 1 is 0x5; to 0x20100004,
  /// past the branch, when nothing is given; ra becomes 0x20100004 and nothing
  /// else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BGTZALC``() =
    let words = [ "1c010100" ]
    ownsJump r6 "1c010100" true
    goes r6 words [ G 1, 0x5UL ] 0x20100404UL
    goes r6 words [] 0x20100004UL
    [ G 1, 0x5UL ]
    |> run r6 words
    |> is [ G 31, 0x20100004UL ]

  /// <summary>
  /// 5c010100, bgtzc at, 0x20100404 (binutils: bgtzc $1,20100404). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100404 (the target binutils reads) when G 1 is 0x5; to 0x20100004,
  /// past the branch, when nothing is given.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BGTZC``() =
    let words = [ "5c010100" ]
    ownsJump r6 "5c010100" true
    goes r6 words [ G 1, 0x5UL ] 0x20100404UL
    goes r6 words [] 0x20100004UL

  /// <summary>
  /// 5c200100, bgtzl at, 0x20100404 (binutils: bgtzl $1,20100404). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: control
  /// goes to 0x20100404 (the target binutils reads) when G 1 is 0x5; to
  /// 0x20100008, past the slot, when nothing is given.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BGTZL``() =
    let words = [ "5c200100"; "00000000" ]
    goes r2 words [ G 1, 0x5UL ] 0x20100404UL
    goes r2 words [] 0x20100008UL

  /// <summary>
  /// 7c031020, bitswap v0, v1, against QEMU's I6400, a Release 6 processor: the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BITSWAP``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r6 [ "7c031020" ]
    |> is [ G 2, 0xc0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r6 [ "7c031020" ]
    |> is [ G 2, 0x80UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r6 [ "7c031020" ]
    |> is [ G 2, 0x482c6a1eUL ]

  /// <summary>
  /// 18200100, blez at, 0x20100404 (binutils: blez $1,20100404). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100404 (the target binutils reads) when G 1 is 0xfffffffffffffffb; to
  /// 0x20100008, past the slot, when G 1 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BLEZ``() =
    let words = [ "18200100"; "00000000" ]
    ownsJump r2 "18200100" false
    goes r2 words [ G 1, 0xfffffffffffffffbUL ] 0x20100404UL
    goes r2 words [ G 1, 0x5UL ] 0x20100008UL

  /// <summary>
  /// 18010100, blezalc at, 0x20100404 (binutils: blezalc $1,20100404). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100404 (the target binutils reads) when G 1 is 0xfffffffffffffffb; to
  /// 0x20100004, past the branch, when G 1 is 0x5; ra becomes 0x20100004 and
  /// nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BLEZALC``() =
    let words = [ "18010100" ]
    ownsJump r6 "18010100" true
    goes r6 words [ G 1, 0xfffffffffffffffbUL ] 0x20100404UL
    goes r6 words [ G 1, 0x5UL ] 0x20100004UL
    [ G 1, 0xfffffffffffffffbUL ]
    |> run r6 words
    |> is [ G 31, 0x20100004UL ]

  /// <summary>
  /// 58010100, blezc at, 0x20100404 (binutils: blezc $1,20100404). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100404 (the target binutils reads) when G 1 is 0xfffffffffffffffb; to
  /// 0x20100004, past the branch, when G 1 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BLEZC``() =
    let words = [ "58010100" ]
    ownsJump r6 "58010100" true
    goes r6 words [ G 1, 0xfffffffffffffffbUL ] 0x20100404UL
    goes r6 words [ G 1, 0x5UL ] 0x20100004UL

  /// <summary>
  /// 58200100, blezl at, 0x20100404 (binutils: blezl $1,20100404). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: control
  /// goes to 0x20100404 (the target binutils reads) when G 1 is
  /// 0xfffffffffffffffb; to 0x20100008, past the slot, when G 1 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BLEZL``() =
    let words = [ "58200100"; "00000000" ]
    goes r2 words [ G 1, 0xfffffffffffffffbUL ] 0x20100404UL
    goes r2 words [ G 1, 0x5UL ] 0x20100008UL

  /// <summary>
  /// 5c430101, bltc v0, v1, 0x20100408 (binutils: bltc $2,$3,20100408). A
  /// branch is not run against QEMU: it moves the PC, and its delay slot makes
  /// one word meaningless to run alone. Checked structurally from the manual:
  /// the transfer is the branch's own, there being no delay slot; control goes
  /// to 0x20100408 (the target binutils reads) when G 2 is 0x3 and G 3 is 0x5;
  /// to 0x20100004, past the branch, when G 2 is 0x5 and G 3 is 0x3.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BLTC``() =
    let words = [ "5c430101" ]
    ownsJump r6 "5c430101" true
    goes r6 words [ G 2, 0x3UL; G 3, 0x5UL ] 0x20100408UL
    goes r6 words [ G 2, 0x5UL; G 3, 0x3UL ] 0x20100004UL

  /// <summary>
  /// 1c430101, bltuc v0, v1, 0x20100408 (binutils: bltuc $2,$3,20100408). A
  /// branch is not run against QEMU: it moves the PC, and its delay slot makes
  /// one word meaningless to run alone. Checked structurally from the manual:
  /// the transfer is the branch's own, there being no delay slot; control goes
  /// to 0x20100408 (the target binutils reads) when G 2 is 0x3 and G 3 is
  /// 0xffffffffffffffff; to 0x20100004, past the branch, when G 2 is
  /// 0xffffffffffffffff and G 3 is 0x3.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BLTUC``() =
    let words = [ "1c430101" ]
    ownsJump r6 "1c430101" true
    goes r6 words [ G 2, 0x3UL; G 3, 0xffffffffffffffffUL ] 0x20100408UL
    goes r6 words [ G 2, 0xffffffffffffffffUL; G 3, 0x3UL ] 0x20100004UL

  /// <summary>
  /// 04200100, bltz at, 0x20100404 (binutils: bltz $1,20100404). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100404 (the target binutils reads) when G 1 is 0xfffffffffffffffb; to
  /// 0x20100008, past the slot, when G 1 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BLTZ``() =
    let words = [ "04200100"; "00000000" ]
    ownsJump r2 "04200100" false
    goes r2 words [ G 1, 0xfffffffffffffffbUL ] 0x20100404UL
    goes r2 words [ G 1, 0x5UL ] 0x20100008UL

  /// <summary>
  /// 04501901, bltzal v0, 0x20106408 (binutils: bltzal $2,20106408). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20106408 (the target binutils reads) when G 2 is 0xfffffffffffffffb; to
  /// 0x20100008, past the slot, when G 2 is 0x5; ra becomes 0x20100008 and
  /// nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BLTZAL``() =
    let words = [ "04501901"; "00000000" ]
    ownsJump r2 "04501901" false
    goes r2 words [ G 2, 0xfffffffffffffffbUL ] 0x20106408UL
    goes r2 words [ G 2, 0x5UL ] 0x20100008UL
    [ G 2, 0xfffffffffffffffbUL ]
    |> run r2 words
    |> is [ G 31, 0x20100008UL ]

  /// <summary>
  /// 1c421901, bltzalc v0, 0x20106408 (binutils: bltzalc $2,20106408). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20106408 (the target binutils reads) when G 2 is 0xfffffffffffffffb; to
  /// 0x20100004, past the branch, when G 2 is 0x5; ra becomes 0x20100004 and
  /// nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BLTZALC``() =
    let words = [ "1c421901" ]
    ownsJump r6 "1c421901" true
    goes r6 words [ G 2, 0xfffffffffffffffbUL ] 0x20106408UL
    goes r6 words [ G 2, 0x5UL ] 0x20100004UL
    [ G 2, 0xfffffffffffffffbUL ]
    |> run r6 words
    |> is [ G 31, 0x20100004UL ]

  /// <summary>
  /// 04521901, bltzall v0, 0x20106408 (binutils: bltzall $2,20106408). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual:
  /// control goes to 0x20106408 (the target binutils reads) when G 2 is
  /// 0xfffffffffffffffb; to 0x20100008, past the slot, when G 2 is 0x5; ra
  /// becomes 0x20100008 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BLTZALL``() =
    let words = [ "04521901"; "00000000" ]
    goes r2 words [ G 2, 0xfffffffffffffffbUL ] 0x20106408UL
    goes r2 words [ G 2, 0x5UL ] 0x20100008UL
    [ G 2, 0xfffffffffffffffbUL ]
    |> run r2 words
    |> is [ G 31, 0x20100008UL ]

  /// <summary>
  /// 5c421901, bltzc v0, 0x20106408 (binutils: bltzc $2,20106408). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20106408 (the target binutils reads) when G 2 is 0xfffffffffffffffb; to
  /// 0x20100004, past the branch, when G 2 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BLTZC``() =
    let words = [ "5c421901" ]
    ownsJump r6 "5c421901" true
    goes r6 words [ G 2, 0xfffffffffffffffbUL ] 0x20106408UL
    goes r6 words [ G 2, 0x5UL ] 0x20100004UL

  /// <summary>
  /// 04420101, bltzl v0, 0x20100408 (binutils: bltzl $2,20100408). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: control
  /// goes to 0x20100408 (the target binutils reads) when G 2 is
  /// 0xfffffffffffffffb; to 0x20100008, past the slot, when G 2 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BLTZL``() =
    let words = [ "04420101"; "00000000" ]
    goes r2 words [ G 2, 0xfffffffffffffffbUL ] 0x20100408UL
    goes r2 words [ G 2, 0x5UL ] 0x20100008UL

  /// <summary>
  /// 14430101, bne v0, v1, 0x20100408 (binutils: bne $2,$3,20100408). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100408 (the target binutils reads) when G 2 is 0x5 and G 3 is 0x6; to
  /// 0x20100008, past the slot, when G 2 is 0x5 and G 3 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BNE``() =
    let words = [ "14430101"; "00000000" ]
    ownsJump r2 "14430101" false
    goes r2 words [ G 2, 0x5UL; G 3, 0x6UL ] 0x20100408UL
    goes r2 words [ G 2, 0x5UL; G 3, 0x5UL ] 0x20100008UL

  /// <summary>
  /// 60430101, bnec v0, v1, 0x20100408 (binutils: bnec $2,$3,20100408). A
  /// branch is not run against QEMU: it moves the PC, and its delay slot makes
  /// one word meaningless to run alone. Checked structurally from the manual:
  /// the transfer is the branch's own, there being no delay slot; control goes
  /// to 0x20100408 (the target binutils reads) when G 2 is 0x5 and G 3 is 0x6;
  /// to 0x20100004, past the branch, when G 2 is 0x5 and G 3 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BNEC``() =
    let words = [ "60430101" ]
    ownsJump r6 "60430101" true
    goes r6 words [ G 2, 0x5UL; G 3, 0x6UL ] 0x20100408UL
    goes r6 words [ G 2, 0x5UL; G 3, 0x5UL ] 0x20100004UL

  /// <summary>
  /// 54430101, bnel v0, v1, 0x20100408 (binutils: bnel $2,$3,20100408). A
  /// branch is not run against QEMU: it moves the PC, and its delay slot makes
  /// one word meaningless to run alone. Checked structurally from the manual:
  /// control goes to 0x20100408 (the target binutils reads) when G 2 is 0x5 and
  /// G 3 is 0x6; to 0x20100008, past the slot, when G 2 is 0x5 and G 3 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BNEL``() =
    let words = [ "54430101"; "00000000" ]
    goes r2 words [ G 2, 0x5UL; G 3, 0x6UL ] 0x20100408UL
    goes r2 words [ G 2, 0x5UL; G 3, 0x5UL ] 0x20100008UL

  /// <summary>
  /// 60010100, bnezalc at, 0x20100404 (binutils: bnezalc $1,20100404). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100404 (the target binutils reads) when G 1 is 0x5; to 0x20100004,
  /// past the branch, when nothing is given; ra becomes 0x20100004 and nothing
  /// else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BNEZALC``() =
    let words = [ "60010100" ]
    ownsJump r6 "60010100" true
    goes r6 words [ G 1, 0x5UL ] 0x20100404UL
    goes r6 words [] 0x20100004UL
    [ G 1, 0x5UL ]
    |> run r6 words
    |> is [ G 31, 0x20100004UL ]

  /// <summary>
  /// f8200100, bnezc at, 0x20100404 (binutils: bnezc $1,20100404). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100404 (the target binutils reads) when G 1 is 0x5; to 0x20100004,
  /// past the branch, when nothing is given.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BNEZC``() =
    let words = [ "f8200100" ]
    ownsJump r6 "f8200100" true
    goes r6 words [ G 1, 0x5UL ] 0x20100404UL
    goes r6 words [] 0x20100004UL

  /// <summary>
  /// 60621900, bnvc v1, v0, 0x20106404 (binutils: bnvc $3,$2,20106404). A
  /// branch is not run against QEMU: it moves the PC, and its delay slot makes
  /// one word meaningless to run alone. Checked structurally from the manual:
  /// the transfer is the branch's own, there being no delay slot; control goes
  /// to 0x20106404 (the target binutils reads) when G 3 is 0x1 and G 2 is 0x1;
  /// to 0x20100004, past the branch, when G 3 is 0x7fffffff and G 2 is 0x1.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BNVC``() =
    let words = [ "60621900" ]
    ownsJump r6 "60621900" true
    goes r6 words [ G 3, 0x1UL; G 2, 0x1UL ] 0x20106404UL
    goes r6 words [ G 3, 0x7fffffffUL; G 2, 0x1UL ] 0x20100004UL

  /// <summary>
  /// 20621900, bovc v1, v0, 0x20106404 (binutils: bovc $3,$2,20106404). A
  /// branch is not run against QEMU: it moves the PC, and its delay slot makes
  /// one word meaningless to run alone. Checked structurally from the manual:
  /// the transfer is the branch's own, there being no delay slot; control goes
  /// to 0x20106404 (the target binutils reads) when G 3 is 0x7fffffff and G 2
  /// is 0x1; to 0x20100004, past the branch, when G 3 is 0x1 and G 2 is 0x1.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BOVC``() =
    let words = [ "20621900" ]
    ownsJump r6 "20621900" true
    goes r6 words [ G 3, 0x7fffffffUL; G 2, 0x1UL ] 0x20106404UL
    goes r6 words [ G 3, 0x1UL; G 2, 0x1UL ] 0x20100004UL

  /// <summary>
  /// 0000000d, break, against QEMU's MIPS64R2-generic: QEMU raised SIGTRAP
  /// (Breakpoint here); the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BREAK``() =
    []
    |> run r2 [ "0000000d" ]
    |> raises [ Breakpoint ] []
    []
    |> run r2 [ "0000000d" ]
    |> raises [ Breakpoint ] []
    []
    |> run r2 [ "0000000d" ]
    |> raises [ Breakpoint ] []

  /// <summary>
  /// 46241134, c.olt.d 0x1, f2, f4, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 C.cond.fmt``() =
    [ F 2, 0x4002000000000000UL; F 4, 0x3ff8000000000000UL ]
    |> run r2 [ "46241134" ]
    |> is []
    [ F 2, 0x3fe8000000000000UL; F 4, 0x3fe8000000000000UL ]
    |> run r2 [ "46241134" ]
    |> is []
    [ F 2, 0xc018000000000000UL; F 4, 0x3fc0000000000000UL ]
    |> run r2 [ "46241134" ]
    |> is [ Fcsr, 0x2000000UL ]
    [ F 2, 0x7ff8000000000000UL; F 4, 0x3ff0000000000000UL ]
    |> run r2 [ "46241134" ]
    |> is [ Fcsr, 0x10040UL ]

  /// <summary>
  /// bc400008, cache 0x0, 8(v0), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CACHE``() =
    let given0 =
      [ G 2, 0x20200078UL
        Status, 0x10UL
        M 0x20200078UL, 0xbc29558e42232f1fUL
        M 0x20200080UL, 0x4c2c0472113165e0UL
        M 0x20200088UL, 0xe224577b71fb184eUL ]
    given0
    |> run r2 [ "bc400008" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x20200078UL
        Status, 0x10UL
        M 0x20200078UL, 0xe6d0ce3c47ae1ab2UL
        M 0x20200080UL, 0x7a13efc31d120b30UL
        M 0x20200088UL, 0x818cd3e5aba5be67UL ]
    given1
    |> run r2 [ "bc400008" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0x20200078UL
        Status, 0x10UL
        M 0x20200078UL, 0x21215457f8d5b7fUL
        M 0x20200080UL, 0xddaa38e43822f89dUL
        M 0x20200088UL, 0xd1095995f92afcc4UL ]
    given2
    |> run r2 [ "bc400008" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 7c40041b, cachee 0x0, 8(v0), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CACHEE``() =
    let given0 =
      [ G 2, 0x20200078UL
        Status, 0x10UL
        M 0x20200078UL, 0xffb14204fb60fa55UL
        M 0x20200080UL, 0x2216fa562948408bUL
        M 0x20200088UL, 0xab0425bfb9505a75UL ]
    given0
    |> run r2 [ "7c40041b" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x20200078UL
        Status, 0x10UL
        M 0x20200078UL, 0x6676a3f29cb3d821UL
        M 0x20200080UL, 0x6e994c31ef4f27dfUL
        M 0x20200088UL, 0x1c3f47dfad39b97UL ]
    given1
    |> run r2 [ "7c40041b" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0x20200078UL
        Status, 0x10UL
        M 0x20200078UL, 0x310232ba1a01e2dfUL
        M 0x20200080UL, 0xabc2d8beed84826bUL
        M 0x20200088UL, 0xb240e35996a08350UL ]
    given2
    |> run r2 [ "7c40041b" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 4600208a, ceil.l.s f2, f4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CEIL.L.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run r2 [ "4600208a" ]
    |> is [ F 2, 0x3UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run r2 [ "4600208a" ]
    |> is [ F 2, 0xffffffffffffffffUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run r2 [ "4600208a" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 4600208e, ceil.w.s f2, f4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CEIL.W.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run r2 [ "4600208e" ]
    |> is [ F 2, 0x3UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run r2 [ "4600208e" ]
    |> is [ F 2, 0xffffffffUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run r2 [ "4600208e" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 4442f800, cfc1 v0, f31, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CFC1``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "4442f800" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "4442f800" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "4442f800" ]
    |> is [ G 2, 0x0UL ]

  /// <summary>
  /// 48421900, cfc2 v0, 0x1900, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CFC2``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "48421900" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "48421900" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "48421900" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 4600209b, class.s f2, f4, against QEMU's I6400, a Release 6 processor: the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CLASS.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40100000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4600209b" ]
    |> is [ F 2, 0x80UL ]
    [ F 2, 0xbUL; F 4, 0x80000000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4600209b" ]
    |> is [ F 2, 0x20UL ]
    [ F 2, 0xdUL; F 4, 0x7fc00000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4600209b" ]
    |> is [ F 2, 0x2UL ]
    [ F 2, 0x9UL; F 4, 0xff800000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4600209b" ]
    |> is [ F 2, 0x4UL ]
    [ F 2, 0xbUL; F 4, 0x116c2UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4600209b" ]
    |> is [ F 2, 0x100UL ]

  /// <summary>
  /// 70621021, clo v0, v1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CLO``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "70621021" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "70621021" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "70621021" ]
    |> is [ G 2, 0x0UL ]

  /// <summary>
  /// 70621020, clz v0, v1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CLZ``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "70621020" ]
    |> is [ G 2, 0x1eUL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "70621020" ]
    |> is [ G 2, 0x1fUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "70621020" ]
    |> is [ G 2, 0x3UL ]

  /// <summary>
  /// 46862080, cmp.af.s f2, f4, f6, against QEMU's I6400, a Release 6
  /// processor: the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CMP.condn.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40100000UL; F 6, 0x3fc00000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46862080" ]
    |> is [ F 2, 0x0UL ]
    [ F 2, 0xbUL; F 4, 0x3f400000UL; F 6, 0x3f400000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46862080" ]
    |> is [ F 2, 0x0UL ]
    [ F 2, 0xdUL; F 4, 0xc0c00000UL; F 6, 0x3e000000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46862080" ]
    |> is [ F 2, 0x0UL ]
    [ F 2, 0x9UL; F 4, 0x7fc00000UL; F 6, 0x3f800000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46862080" ]
    |> is [ F 2, 0x0UL ]

  /// <summary>
  /// 4a200000, cop2 0x200000, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 COP2``() =
    []
    |> run r2 [ "4a200000" ]
    |> raises [ UndefinedInstruction ] []
    []
    |> run r2 [ "4a200000" ]
    |> raises [ UndefinedInstruction ] []
    []
    |> run r2 [ "4a200000" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 7c62000f, crc32b v0, v1, v0. QEMU's I6400 does not implement the CRC
  /// instructions (it raises SIGILL for them), and no other model of it does,
  /// so the values are the CRC MD00087 defines: the polynomial 0xEDB88320
  /// reflected, the low 1 byte of v1 taken least significant first, no
  /// inversion, the result sign-extended -- computed by the bitwise update in
  /// optest-mips/oracle/structural.py, which is checked against zlib's CRC-32
  /// and the CRC-32C check value of RFC 3720.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CRC32B``() =
    [ G 2, 0xffffffffffffffffUL; G 3, 0x123456789abcdefUL ]
    |> run r6 [ "7c62000f" ]
    |> is [ G 2, 0x1d48ef9bUL ]
    [ G 2, 0x12345678UL; G 3, 0xfedcba9876543210UL ]
    |> run r6 [ "7c62000f" ]
    |> is [ G 2, 0x437bdd3cUL ]
    [ G 2, 0x0UL; G 3, 0xa5UL ]
    |> run r6 [ "7c62000f" ]
    |> is [ G 2, 0xffffffffa6bc5767UL ]

  /// <summary>
  /// 7c62010f, crc32cb v0, v1, v0. QEMU's I6400 does not implement the CRC
  /// instructions (it raises SIGILL for them), and no other model of it does,
  /// so the values are the CRC MD00087 defines: the polynomial 0x82F63B78
  /// reflected, the low 1 byte of v1 taken least significant first, no
  /// inversion, the result sign-extended -- computed by the bitwise update in
  /// optest-mips/oracle/structural.py, which is checked against zlib's CRC-32
  /// and the CRC-32C check value of RFC 3720.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CRC32CB``() =
    [ G 2, 0xffffffffffffffffUL; G 3, 0x123456789abcdefUL ]
    |> run r6 [ "7c62010f" ]
    |> is [ G 2, 0x10a13890UL ]
    [ G 2, 0x12345678UL; G 3, 0xfedcba9876543210UL ]
    |> run r6 [ "7c62010f" ]
    |> is [ G 2, 0xffffffffeb0dfffbUL ]
    [ G 2, 0x0UL; G 3, 0xa5UL ]
    |> run r6 [ "7c62010f" ]
    |> is [ G 2, 0xffffffff97baa1baUL ]

  /// <summary>
  /// 7c6201cf, crc32cd v0, v1, v0. QEMU's I6400 does not implement the CRC
  /// instructions (it raises SIGILL for them), and no other model of it does,
  /// so the values are the CRC MD00087 defines: the polynomial 0x82F63B78
  /// reflected, the low 8 bytes of v1 taken least significant first, no
  /// inversion, the result sign-extended -- computed by the bitwise update in
  /// optest-mips/oracle/structural.py, which is checked against zlib's CRC-32
  /// and the CRC-32C check value of RFC 3720.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CRC32CD``() =
    [ G 2, 0xffffffffffffffffUL; G 3, 0x123456789abcdefUL ]
    |> run r6 [ "7c6201cf" ]
    |> is [ G 2, 0xffffffff9a4f27dcUL ]
    [ G 2, 0x12345678UL; G 3, 0xfedcba9876543210UL ]
    |> run r6 [ "7c6201cf" ]
    |> is [ G 2, 0x679dfef3UL ]
    [ G 2, 0x0UL; G 3, 0xa5UL ]
    |> run r6 [ "7c6201cf" ]
    |> is [ G 2, 0x51200cb7UL ]

  /// <summary>
  /// 7c62014f, crc32ch v0, v1, v0. QEMU's I6400 does not implement the CRC
  /// instructions (it raises SIGILL for them), and no other model of it does,
  /// so the values are the CRC MD00087 defines: the polynomial 0x82F63B78
  /// reflected, the low 2 bytes of v1 taken least significant first, no
  /// inversion, the result sign-extended -- computed by the bitwise update in
  /// optest-mips/oracle/structural.py, which is checked against zlib's CRC-32
  /// and the CRC-32C check value of RFC 3720.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CRC32CH``() =
    [ G 2, 0xffffffffffffffffUL; G 3, 0x123456789abcdefUL ]
    |> run r6 [ "7c62014f" ]
    |> is [ G 2, 0xffffffffee1d3738UL ]
    [ G 2, 0x12345678UL; G 3, 0xfedcba9876543210UL ]
    |> run r6 [ "7c62014f" ]
    |> is [ G 2, 0xffffffffbbd4f0f7UL ]
    [ G 2, 0x0UL; G 3, 0xa5UL ]
    |> run r6 [ "7c62014f" ]
    |> is [ G 2, 0xffffffffd960e050UL ]

  /// <summary>
  /// 7c62018f, crc32cw v0, v1, v0. QEMU's I6400 does not implement the CRC
  /// instructions (it raises SIGILL for them), and no other model of it does,
  /// so the values are the CRC MD00087 defines: the polynomial 0x82F63B78
  /// reflected, the low 4 bytes of v1 taken least significant first, no
  /// inversion, the result sign-extended -- computed by the bitwise update in
  /// optest-mips/oracle/structural.py, which is checked against zlib's CRC-32
  /// and the CRC-32C check value of RFC 3720.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CRC32CW``() =
    [ G 2, 0xffffffffffffffffUL; G 3, 0x123456789abcdefUL ]
    |> run r6 [ "7c62018f" ]
    |> is [ G 2, 0xffffffffee8c8012UL ]
    [ G 2, 0x12345678UL; G 3, 0xfedcba9876543210UL ]
    |> run r6 [ "7c62018f" ]
    |> is [ G 2, 0x14f8d626UL ]
    [ G 2, 0x0UL; G 3, 0xa5UL ]
    |> run r6 [ "7c62018f" ]
    |> is [ G 2, 0x23e246ffUL ]

  /// <summary>
  /// 7c6200cf, crc32d v0, v1, v0. QEMU's I6400 does not implement the CRC
  /// instructions (it raises SIGILL for them), and no other model of it does,
  /// so the values are the CRC MD00087 defines: the polynomial 0xEDB88320
  /// reflected, the low 8 bytes of v1 taken least significant first, no
  /// inversion, the result sign-extended -- computed by the bitwise update in
  /// optest-mips/oracle/structural.py, which is checked against zlib's CRC-32
  /// and the CRC-32C check value of RFC 3720.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CRC32D``() =
    [ G 2, 0xffffffffffffffffUL; G 3, 0x123456789abcdefUL ]
    |> run r6 [ "7c6200cf" ]
    |> is [ G 2, 0xffffffffbbc41db8UL ]
    [ G 2, 0x12345678UL; G 3, 0xfedcba9876543210UL ]
    |> run r6 [ "7c6200cf" ]
    |> is [ G 2, 0xffffffffdf04eaaaUL ]
    [ G 2, 0x0UL; G 3, 0xa5UL ]
    |> run r6 [ "7c6200cf" ]
    |> is [ G 2, 0xffffffffe2ade9e8UL ]

  /// <summary>
  /// 7c62004f, crc32h v0, v1, v0. QEMU's I6400 does not implement the CRC
  /// instructions (it raises SIGILL for them), and no other model of it does,
  /// so the values are the CRC MD00087 defines: the polynomial 0xEDB88320
  /// reflected, the low 2 bytes of v1 taken least significant first, no
  /// inversion, the result sign-extended -- computed by the bitwise update in
  /// optest-mips/oracle/structural.py, which is checked against zlib's CRC-32
  /// and the CRC-32C check value of RFC 3720.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CRC32H``() =
    [ G 2, 0xffffffffffffffffUL; G 3, 0x123456789abcdefUL ]
    |> run r6 [ "7c62004f" ]
    |> is [ G 2, 0xffffffff8215bc2eUL ]
    [ G 2, 0x12345678UL; G 3, 0xfedcba9876543210UL ]
    |> run r6 [ "7c62004f" ]
    |> is [ G 2, 0xffffffffe7fb56daUL ]
    [ G 2, 0x0UL; G 3, 0xa5UL ]
    |> run r6 [ "7c62004f" ]
    |> is [ G 2, 0xffffffffd37048acUL ]

  /// <summary>
  /// 7c62008f, crc32w v0, v1, v0. QEMU's I6400 does not implement the CRC
  /// instructions (it raises SIGILL for them), and no other model of it does,
  /// so the values are the CRC MD00087 defines: the polynomial 0xEDB88320
  /// reflected, the low 4 bytes of v1 taken least significant first, no
  /// inversion, the result sign-extended -- computed by the bitwise update in
  /// optest-mips/oracle/structural.py, which is checked against zlib's CRC-32
  /// and the CRC-32C check value of RFC 3720.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CRC32W``() =
    [ G 2, 0xffffffffffffffffUL; G 3, 0x123456789abcdefUL ]
    |> run r6 [ "7c62008f" ]
    |> is [ G 2, 0x10472a38UL ]
    [ G 2, 0x12345678UL; G 3, 0xfedcba9876543210UL ]
    |> run r6 [ "7c62008f" ]
    |> is [ G 2, 0xffffffff9e6e72f6UL ]
    [ G 2, 0x0UL; G 3, 0xa5UL ]
    |> run r6 [ "7c62008f" ]
    |> is [ G 2, 0x7ab5e937UL ]

  /// <summary>
  /// 44c2f800, ctc1 v0, f31, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CTC1``() =
    [ G 2, 0x3UL ]
    |> run r2 [ "44c2f800" ]
    |> is [ Fcsr, 0x3UL ]
    [ G 2, 0x1000000UL ]
    |> run r2 [ "44c2f800" ]
    |> is [ Fcsr, 0x1000000UL ]
    [ G 2, 0xfe800002UL ]
    |> run r2 [ "44c2f800" ]
    |> is [ Fcsr, 0xfe800002UL ]

  /// <summary>
  /// 48c21900, ctc2 v0, 0x1900, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CTC2``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "48c21900" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "48c21900" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "48c21900" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 460020a1, cvt.d.s f2, f4, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CVT.D.fmt``() =
    [ F 2, 0xbff0000000000000UL; F 4, 0x40200000UL ]
    |> run r2 [ "460020a1" ]
    |> is [ F 2, 0x4004000000000000UL ]
    [ F 2, 0x400c000000000000UL; F 4, 0xbfe00000UL ]
    |> run r2 [ "460020a1" ]
    |> is [ F 2, 0xbffc000000000000UL ]
    [ F 2, 0x3fd0000000000000UL; F 4, 0x447a0000UL ]
    |> run r2 [ "460020a1" ]
    |> is [ F 2, 0x408f400000000000UL ]

  /// <summary>
  /// 460020a5, cvt.l.s f2, f4, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CVT.L.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run r2 [ "460020a5" ]
    |> is [ F 2, 0x2UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run r2 [ "460020a5" ]
    |> is [ F 2, 0xfffffffffffffffeUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run r2 [ "460020a5" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 460620a6, cvt.ps.s f2, f4, f6, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CVT.PS.S``() =
    [ F 2, 0xbf8000003f800000UL; F 4, 0x40200000UL; F 6, 0x3fc00000UL ]
    |> run r2 [ "460620a6" ]
    |> is [ F 2, 0x402000003fc00000UL ]
    [ F 2, 0x40600000c0600000UL; F 4, 0xbfe00000UL; F 6, 0x3f400000UL ]
    |> run r2 [ "460620a6" ]
    |> is [ F 2, 0xbfe000003f400000UL ]
    [ F 2, 0x3e8000003f400000UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL ]
    |> run r2 [ "460620a6" ]
    |> is [ F 2, 0x447a00003e000000UL ]

  /// <summary>
  /// 46c020a8, cvt.s.pl f2, f4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CVT.S.PL``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000bfc00000UL ]
    |> run r2 [ "46c020a8" ]
    |> is [ F 2, 0xbfc00000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c000003f000000UL ]
    |> run r2 [ "46c020a8" ]
    |> is [ F 2, 0x3f000000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a000040400000UL ]
    |> run r2 [ "46c020a8" ]
    |> is [ F 2, 0x40400000UL ]

  /// <summary>
  /// 46c020a0, cvt.s.pu f2, f4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CVT.S.PU``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000bfc00000UL ]
    |> run r2 [ "46c020a0" ]
    |> is [ F 2, 0x40100000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c000003f000000UL ]
    |> run r2 [ "46c020a0" ]
    |> is [ F 2, 0xc0c00000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a000040400000UL ]
    |> run r2 [ "46c020a0" ]
    |> is [ F 2, 0x447a0000UL ]

  /// <summary>
  /// 462020a0, cvt.s.d f2, f4, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CVT.S.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x4004000000000000UL ]
    |> run r2 [ "462020a0" ]
    |> is [ F 2, 0x40200000UL ]
    [ F 2, 0x40600000UL; F 4, 0xbffc000000000000UL ]
    |> run r2 [ "462020a0" ]
    |> is [ F 2, 0xbfe00000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x408f400000000000UL ]
    |> run r2 [ "462020a0" ]
    |> is [ F 2, 0x447a0000UL ]

  /// <summary>
  /// 460020a4, cvt.w.s f2, f4, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CVT.W.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run r2 [ "460020a4" ]
    |> is [ F 2, 0x2UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run r2 [ "460020a4" ]
    |> is [ F 2, 0xfffffffeUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run r2 [ "460020a4" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 0064102c, dadd v0, v1, a0, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGFPE (Exception IntegerOverflow here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DADD``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "0064102c" ]
    |> is [ G 2, 0x8UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "0064102c" ]
    |> is [ G 2, 0xffffffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL; G 4, 0xffffffffUL ]
    |> run r2 [ "0064102c" ]
    |> is [ G 2, 0xfedcba997654320fUL ]
    [ G 2, 0x7UL; G 3, 0x7fffffffffffffffUL; G 4, 0x1UL ]
    |> run r2 [ "0064102c" ]
    |> raises [ Exception IntegerOverflow ] []

  /// <summary>
  /// 60620100, daddi v0, v1, 0x100, against QEMU's MIPS64R2-generic: QEMU
  /// raised SIGFPE (Exception IntegerOverflow here); the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DADDI``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "60620100" ]
    |> is [ G 2, 0x103UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "60620100" ]
    |> is [ G 2, 0x101UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "60620100" ]
    |> is [ G 2, 0xfedcba9876543310UL ]
    [ G 2, 0x7UL; G 3, 0x7fffffffffffffffUL ]
    |> run r2 [ "60620100" ]
    |> raises [ Exception IntegerOverflow ] []

  /// <summary>
  /// 64620100, daddiu v0, v1, 0x100, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DADDIU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "64620100" ]
    |> is [ G 2, 0x103UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "64620100" ]
    |> is [ G 2, 0x101UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "64620100" ]
    |> is [ G 2, 0xfedcba9876543310UL ]

  /// <summary>
  /// 0064102d, daddu v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DADDU``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "0064102d" ]
    |> is [ G 2, 0x8UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "0064102d" ]
    |> is [ G 2, 0xffffffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL; G 4, 0xffffffffUL ]
    |> run r2 [ "0064102d" ]
    |> is [ G 2, 0xfedcba997654320fUL ]

  /// <summary>
  /// 04661900, dahi v1, 0x1900, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DAHI``() =
    [ G 3, 0x7UL ]
    |> run r6 [ "04661900" ]
    |> is [ G 3, 0x190000000007UL ]
    [ G 3, 0x7fffffffffffffffUL ]
    |> run r6 [ "04661900" ]
    |> is [ G 3, 0x800018ffffffffffUL ]
    [ G 3, 0x123456789abcdefUL ]
    |> run r6 [ "04661900" ]
    |> is [ G 3, 0x1235e6789abcdefUL ]

  /// <summary>
  /// 7c641264, dalign v0, v1, a0, 0x1, against QEMU's I6400, a Release 6
  /// processor: the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DALIGN``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "7c641264" ]
    |> is [ G 2, 0x500UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "7c641264" ]
    |> is [ G 2, 0xfffffffffffffe00UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL; G 4, 0xffffffffUL ]
    |> run r6 [ "7c641264" ]
    |> is [ G 2, 0xfffffffffeUL ]

  /// <summary>
  /// 047e1900, dati v1, 0x1900, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DATI``() =
    [ G 3, 0x7UL ]
    |> run r6 [ "047e1900" ]
    |> is [ G 3, 0x1900000000000007UL ]
    [ G 3, 0x7fffffffffffffffUL ]
    |> run r6 [ "047e1900" ]
    |> is [ G 3, 0x98ffffffffffffffUL ]
    [ G 3, 0x123456789abcdefUL ]
    |> run r6 [ "047e1900" ]
    |> is [ G 3, 0x1a23456789abcdefUL ]

  /// <summary>
  /// 74620100, daui v0, v1, 0x100, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DAUI``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r6 [ "74620100" ]
    |> is [ G 2, 0x1000003UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r6 [ "74620100" ]
    |> is [ G 2, 0x1000001UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r6 [ "74620100" ]
    |> is [ G 2, 0xfedcba9877543210UL ]

  /// <summary>
  /// 7c031024, dbitswap v0, v1, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DBITSWAP``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r6 [ "7c031024" ]
    |> is [ G 2, 0xc0UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r6 [ "7c031024" ]
    |> is [ G 2, 0x80UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r6 [ "7c031024" ]
    |> is [ G 2, 0x7f3b5d196e2a4c08UL ]

  /// <summary>
  /// 70621025, dclo v0, v1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DCLO``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "70621025" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "70621025" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "70621025" ]
    |> is [ G 2, 0x7UL ]

  /// <summary>
  /// 70621024, dclz v0, v1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DCLZ``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "70621024" ]
    |> is [ G 2, 0x3eUL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "70621024" ]
    |> is [ G 2, 0x3fUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "70621024" ]
    |> is [ G 2, 0x0UL ]

  /// <summary>
  /// 0043001e, ddiv v0, v1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DDIV``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "0043001e" ]
    |> is [ Hi, 0x1UL; Lo, 0x2UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "0043001e" ]
    |> is [ Lo, 0x7fffffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "0043001e" ]
    |> is [ Hi, 0x123456789abcdefUL ]

  /// <summary>
  /// 0043001f, ddivu v0, v1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DDIVU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "0043001f" ]
    |> is [ Hi, 0x1UL; Lo, 0x2UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "0043001f" ]
    |> is [ Lo, 0x7fffffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "0043001f" ]
    |> is [ Hi, 0x123456789abcdefUL ]

  /// <summary>
  /// 4200001f, deret, against QEMU's MIPS64R2-generic: QEMU raised SIGILL
  /// (UndefinedInstruction here); Status = 0x10 puts the lift in User Mode, the
  /// mode QEMU runs every word in; the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DERET``() =
    [ Status, 0x10UL ]
    |> run r2 [ "4200001f" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "4200001f" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "4200001f" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 7c620103, dext v0, v1, 0x4, 0x1, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DEXT``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "7c620103" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "7c620103" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "7c620103" ]
    |> is [ G 2, 0x1UL ]

  /// <summary>
  /// 7c620101, dextm v0, v1, 0x4, 0x21, against QEMU's MIPS64R2-generic: the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DEXTM``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "7c620101" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "7c620101" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "7c620101" ]
    |> is [ G 2, 0x187654321UL ]

  /// <summary>
  /// 7c620102, dextu v0, v1, 0x24, 0x1, against QEMU's MIPS64R2-generic: the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DEXTU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "7c620102" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "7c620102" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "7c620102" ]
    |> is [ G 2, 0x1UL ]

  /// <summary>
  /// 41626000, di v0, against QEMU's MIPS64R2-generic: QEMU raised SIGILL
  /// (UndefinedInstruction here); Status = 0x10 puts the lift in User Mode, the
  /// mode QEMU runs every word in; the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DI``() =
    [ G 2, 0x7UL; Status, 0x10UL ]
    |> run r2 [ "41626000" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0x7fffffffUL; Status, 0x10UL ]
    |> run r2 [ "41626000" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0xffffffff89abcdefUL; Status, 0x10UL ]
    |> run r2 [ "41626000" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 7c621847, dins v0, v1, 0x1, 0x3, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DINS``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "7c621847" ]
    |> is []
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "7c621847" ]
    |> is [ G 2, 0x7ffffffffffffff3UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "7c621847" ]
    |> is [ G 2, 0x123456789abcde1UL ]

  /// <summary>
  /// 7c620105, dinsm v0, v1, 0x4, 0x1d, against QEMU's MIPS64R2-generic: the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DINSM``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "7c620105" ]
    |> is [ G 2, 0x37UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "7c620105" ]
    |> is [ G 2, 0x7ffffffe0000001fUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "7c620105" ]
    |> is [ G 2, 0x12345676543210fUL ]

  /// <summary>
  /// 7c621806, dinsu v0, v1, 0x20, 0x4, against QEMU's MIPS64R2-generic: the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DINSU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "7c621806" ]
    |> is [ G 2, 0x300000007UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "7c621806" ]
    |> is [ G 2, 0x7ffffff1ffffffffUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "7c621806" ]
    |> is [ G 2, 0x123456089abcdefUL ]

  /// <summary>
  /// 0043001a, div v0, v1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DIV``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "0043001a" ]
    |> is [ Hi, 0x1UL; Lo, 0x2UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "0043001a" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "0043001a" ]
    |> is [ Hi, 0xfffffffff6e5d4bfUL; Lo, 0xfffffffffffffffaUL ]

  /// <summary>
  /// 46062083, div.s f2, f4, f6, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DIV.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; F 6, 0x3fc00000UL ]
    |> run r2 [ "46062083" ]
    |> is [ F 2, 0x3fc00000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; F 6, 0x3f400000UL ]
    |> run r2 [ "46062083" ]
    |> is [ F 2, 0xc1000000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL ]
    |> run r2 [ "46062083" ]
    |> is [ F 2, 0x45fa0000UL ]

  /// <summary>
  /// 0043001b, divu v0, v1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DIVU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "0043001b" ]
    |> is [ Hi, 0x1UL; Lo, 0x2UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "0043001b" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "0043001b" ]
    |> is [ Hi, 0xa3d70a7UL; Lo, 0x7UL ]

  /// <summary>
  /// 00641015, dlsa v0, v1, a0, 0x0, against QEMU's I6400, a Release 6
  /// processor: the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DLSA``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "00641015" ]
    |> is [ G 2, 0xbUL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "00641015" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL; G 4, 0xffffffffUL ]
    |> run r6 [ "00641015" ]
    |> is [ G 2, 0xfdb97531eca8641fUL ]

  /// <summary>
  /// 40221801, dmfc0 v0, 0x3, 0x1, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DMFC0``() =
    [ G 2, 0x7UL; Status, 0x10UL ]
    |> run r2 [ "40221801" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0x7fffffffUL; Status, 0x10UL ]
    |> run r2 [ "40221801" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0xffffffff89abcdefUL; Status, 0x10UL ]
    |> run r2 [ "40221801" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 44221000, dmfc1 v0, f2, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DMFC1``() =
    [ G 2, 0x7UL; F 2, 0x1122334455667788UL ]
    |> run r2 [ "44221000" ]
    |> is [ G 2, 0x1122334455667788UL ]
    [ G 2, 0x7fffffffffffffffUL; F 2, 0xbf800000UL ]
    |> run r2 [ "44221000" ]
    |> is [ G 2, 0xbf800000UL ]
    [ G 2, 0x123456789abcdefUL; F 2, 0x8899aabbccddeeffUL ]
    |> run r2 [ "44221000" ]
    |> is [ G 2, 0x8899aabbccddeeffUL ]

  /// <summary>
  /// 48211900, dmfc2 at, 0x1900, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DMFC2``() =
    [ G 1, 0x7UL ]
    |> run r2 [ "48211900" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL ]
    |> run r2 [ "48211900" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL ]
    |> run r2 [ "48211900" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 006410de, dmod v0, v1, a0, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DMOD``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "006410de" ]
    |> is [ G 2, 0x3UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "006410de" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL; G 4, 0xffffffffUL ]
    |> run r6 [ "006410de" ]
    |> is [ G 2, 0xffffffff7530eca9UL ]

  /// <summary>
  /// 006410df, dmodu v0, v1, a0, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DMODU``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "006410df" ]
    |> is [ G 2, 0x3UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "006410df" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL; G 4, 0xffffffffUL ]
    |> run r6 [ "006410df" ]
    |> is [ G 2, 0x7530eca9UL ]

  /// <summary>
  /// 40a00001, dmtc0 r0, 0x0, 0x1, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DMTC0``() =
    [ Status, 0x10UL ]
    |> run r2 [ "40a00001" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "40a00001" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "40a00001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 44a21000, dmtc1 v0, f2, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DMTC1``() =
    [ G 2, 0x7UL; F 2, 0x1122334455667788UL ]
    |> run r2 [ "44a21000" ]
    |> is [ F 2, 0x7UL ]
    [ G 2, 0x7fffffffffffffffUL; F 2, 0xbf800000UL ]
    |> run r2 [ "44a21000" ]
    |> is [ F 2, 0x7fffffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL; F 2, 0x8899aabbccddeeffUL ]
    |> run r2 [ "44a21000" ]
    |> is [ F 2, 0x123456789abcdefUL ]

  /// <summary>
  /// 48a21900, dmtc2 v0, 0x1900, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DMTC2``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "48a21900" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "48a21900" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "48a21900" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 006410dc, dmuh v0, v1, a0, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DMUH``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "006410dc" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "006410dc" ]
    |> is [ G 2, 0xffffffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL; G 4, 0xffffffffUL ]
    |> run r6 [ "006410dc" ]
    |> is [ G 2, 0xfffffffffedcba98UL ]

  /// <summary>
  /// 006410dd, dmuhu v0, v1, a0, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DMUHU``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "006410dd" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "006410dd" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL; G 4, 0xffffffffUL ]
    |> run r6 [ "006410dd" ]
    |> is [ G 2, 0xfedcba97UL ]

  /// <summary>
  /// 0064109c, dmul v0, v1, a0, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DMUL``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "0064109c" ]
    |> is [ G 2, 0xfUL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "0064109c" ]
    |> is [ G 2, 0xfffffffffffffffeUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL; G 4, 0xffffffffUL ]
    |> run r6 [ "0064109c" ]
    |> is [ G 2, 0x7777777789abcdf0UL ]

  /// <summary>
  /// 0043001c, dmult v0, v1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DMULT``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "0043001c" ]
    |> is [ Lo, 0x15UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "0043001c" ]
    |> is [ Lo, 0x7fffffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "0043001c" ]
    |> is [ Hi, 0xfffeb49923cc0953UL; Lo, 0x2236d88fe5618cf0UL ]

  /// <summary>
  /// 0043001d, dmultu v0, v1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DMULTU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "0043001d" ]
    |> is [ Lo, 0x15UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "0043001d" ]
    |> is [ Lo, 0x7fffffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "0043001d" ]
    |> is [ Hi, 0x121fa00ad77d742UL; Lo, 0x2236d88fe5618cf0UL ]

  /// <summary>
  /// 0064109d, dmulu v0, v1, a0, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DMULU``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "0064109d" ]
    |> is [ G 2, 0xfUL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "0064109d" ]
    |> is [ G 2, 0xfffffffffffffffeUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL; G 4, 0xffffffffUL ]
    |> run r6 [ "0064109d" ]
    |> is [ G 2, 0x7777777789abcdf0UL ]

  /// <summary>
  /// 0023113a, drotr v0, v1, 0x4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DROTR``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "0023113a" ]
    |> is [ G 2, 0x3000000000000000UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "0023113a" ]
    |> is [ G 2, 0x1000000000000000UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "0023113a" ]
    |> is [ G 2, 0xfedcba987654321UL ]

  /// <summary>
  /// 0023113e, drotr32 v0, v1, 0x4, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DROTR32``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "0023113e" ]
    |> is [ G 2, 0x30000000UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "0023113e" ]
    |> is [ G 2, 0x10000000UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "0023113e" ]
    |> is [ G 2, 0x876543210fedcba9UL ]

  /// <summary>
  /// 00831056, drotrv v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DROTRV``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "00831056" ]
    |> is [ G 2, 0x1800000000000000UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "00831056" ]
    |> is [ G 2, 0x4UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL; G 4, 0xffffffffUL ]
    |> run r2 [ "00831056" ]
    |> is [ G 2, 0xfdb97530eca86421UL ]

  /// <summary>
  /// 7c0210a4, dsbh v0, v0, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DSBH``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "7c0210a4" ]
    |> is [ G 2, 0x700UL ]
    [ G 2, 0x7fffffffffffffffUL ]
    |> run r2 [ "7c0210a4" ]
    |> is [ G 2, 0xff7fffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL ]
    |> run r2 [ "7c0210a4" ]
    |> is [ G 2, 0x23016745ab89efcdUL ]

  /// <summary>
  /// 7c021164, dshd v0, v0, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DSHD``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "7c021164" ]
    |> is [ G 2, 0x7000000000000UL ]
    [ G 2, 0x7fffffffffffffffUL ]
    |> run r2 [ "7c021164" ]
    |> is [ G 2, 0xffffffffffff7fffUL ]
    [ G 2, 0x123456789abcdefUL ]
    |> run r2 [ "7c021164" ]
    |> is [ G 2, 0xcdef89ab45670123UL ]

  /// <summary>
  /// 00031138, dsll v0, v1, 0x4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DSLL``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "00031138" ]
    |> is [ G 2, 0x30UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "00031138" ]
    |> is [ G 2, 0x10UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "00031138" ]
    |> is [ G 2, 0xedcba98765432100UL ]

  /// <summary>
  /// 0003113c, dsll32 v0, v1, 0x4, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DSLL32``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "0003113c" ]
    |> is [ G 2, 0x3000000000UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "0003113c" ]
    |> is [ G 2, 0x1000000000UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "0003113c" ]
    |> is [ G 2, 0x6543210000000000UL ]

  /// <summary>
  /// 00831014, dsllv v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DSLLV``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "00831014" ]
    |> is [ G 2, 0x60UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "00831014" ]
    |> is [ G 2, 0x4000000000000000UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL; G 4, 0xffffffffUL ]
    |> run r2 [ "00831014" ]
    |> is [ G 2, 0x0UL ]

  /// <summary>
  /// 0003113b, dsra v0, v1, 0x4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DSRA``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "0003113b" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "0003113b" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "0003113b" ]
    |> is [ G 2, 0xffedcba987654321UL ]

  /// <summary>
  /// 0003113f, dsra32 v0, v1, 0x4, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DSRA32``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "0003113f" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "0003113f" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "0003113f" ]
    |> is [ G 2, 0xffffffffffedcba9UL ]

  /// <summary>
  /// 00831017, dsrav v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DSRAV``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "00831017" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "00831017" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL; G 4, 0xffffffffUL ]
    |> run r2 [ "00831017" ]
    |> is [ G 2, 0xffffffffffffffffUL ]

  /// <summary>
  /// 0003113a, dsrl v0, v1, 0x4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DSRL``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "0003113a" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "0003113a" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "0003113a" ]
    |> is [ G 2, 0xfedcba987654321UL ]

  /// <summary>
  /// 0003113e, dsrl32 v0, v1, 0x4, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DSRL32``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "0003113e" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "0003113e" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "0003113e" ]
    |> is [ G 2, 0xfedcba9UL ]

  /// <summary>
  /// 00831016, dsrlv v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DSRLV``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "00831016" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "00831016" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL; G 4, 0xffffffffUL ]
    |> run r2 [ "00831016" ]
    |> is [ G 2, 0x1UL ]

  /// <summary>
  /// 0064102e, dsub v0, v1, a0, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGFPE (Exception IntegerOverflow here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DSUB``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "0064102e" ]
    |> is [ G 2, 0xfffffffffffffffeUL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "0064102e" ]
    |> is [ G 2, 0x3UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL; G 4, 0xffffffffUL ]
    |> run r2 [ "0064102e" ]
    |> is [ G 2, 0xfedcba9776543211UL ]
    [ G 2, 0x7UL; G 3, 0x8000000000000000UL; G 4, 0x1UL ]
    |> run r2 [ "0064102e" ]
    |> raises [ Exception IntegerOverflow ] []

  /// <summary>
  /// 0064102f, dsubu v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DSUBU``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "0064102f" ]
    |> is [ G 2, 0xfffffffffffffffeUL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "0064102f" ]
    |> is [ G 2, 0x3UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL; G 4, 0xffffffffUL ]
    |> run r2 [ "0064102f" ]
    |> is [ G 2, 0xfedcba9776543211UL ]

  /// <summary>
  /// 41620024, dvp v0, against QEMU's I6400, a Release 6 processor: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DVP``() =
    [ G 2, 0x7UL; Status, 0x10UL ]
    |> run r6 [ "41620024" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0x7fffffffUL; Status, 0x10UL ]
    |> run r6 [ "41620024" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0xffffffff89abcdefUL; Status, 0x10UL ]
    |> run r6 [ "41620024" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 000000c0, ehb, against QEMU's MIPS64R2-generic: the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 EHB``() =
    []
    |> run r2 [ "000000c0" ]
    |> is []
    []
    |> run r2 [ "000000c0" ]
    |> is []
    []
    |> run r2 [ "000000c0" ]
    |> is []

  /// <summary>
  /// 41626020, ei v0, against QEMU's MIPS64R2-generic: QEMU raised SIGILL
  /// (UndefinedInstruction here); Status = 0x10 puts the lift in User Mode, the
  /// mode QEMU runs every word in; the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 EI``() =
    [ G 2, 0x7UL; Status, 0x10UL ]
    |> run r2 [ "41626020" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0x7fffffffUL; Status, 0x10UL ]
    |> run r2 [ "41626020" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0xffffffff89abcdefUL; Status, 0x10UL ]
    |> run r2 [ "41626020" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 42000018, eret, against QEMU's MIPS64R2-generic: QEMU raised SIGILL
  /// (UndefinedInstruction here); Status = 0x10 puts the lift in User Mode, the
  /// mode QEMU runs every word in; the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ERET``() =
    [ Status, 0x10UL ]
    |> run r2 [ "42000018" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000018" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000018" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 42000058, eretnc, against QEMU's MIPS64R2-generic: QEMU raised SIGILL
  /// (UndefinedInstruction here); Status = 0x10 puts the lift in User Mode, the
  /// mode QEMU runs every word in; the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ERETNC``() =
    [ Status, 0x10UL ]
    |> run r2 [ "42000058" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000058" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000058" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 41620004, evp v0, against QEMU's I6400, a Release 6 processor: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 EVP``() =
    [ G 2, 0x7UL; Status, 0x10UL ]
    |> run r6 [ "41620004" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0x7fffffffUL; Status, 0x10UL ]
    |> run r6 [ "41620004" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0xffffffff89abcdefUL; Status, 0x10UL ]
    |> run r6 [ "41620004" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 7c620100, ext v0, v1, 0x4, 0x1, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 EXT``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "7c620100" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "7c620100" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "7c620100" ]
    |> is [ G 2, 0x1UL ]

  /// <summary>
  /// 4600208b, floor.l.s f2, f4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 FLOOR.L.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run r2 [ "4600208b" ]
    |> is [ F 2, 0x2UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run r2 [ "4600208b" ]
    |> is [ F 2, 0xfffffffffffffffeUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run r2 [ "4600208b" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 4600208f, floor.w.s f2, f4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 FLOOR.W.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run r2 [ "4600208f" ]
    |> is [ F 2, 0x2UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run r2 [ "4600208f" ]
    |> is [ F 2, 0xfffffffeUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run r2 [ "4600208f" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 7c40003d, ginvi v0, against QEMU's I6400, a Release 6 processor: QEMU
  /// raised SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in
  /// User Mode, the mode QEMU runs every word in; the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 GINVI``() =
    [ G 2, 0x7UL; Status, 0x10UL ]
    |> run r6 [ "7c40003d" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0x7fffffffUL; Status, 0x10UL ]
    |> run r6 [ "7c40003d" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0xffffffff89abcdefUL; Status, 0x10UL ]
    |> run r6 [ "7c40003d" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 7c4001bd, ginvt v0, 0x1, against QEMU's I6400, a Release 6 processor: QEMU
  /// raised SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in
  /// User Mode, the mode QEMU runs every word in; the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 GINVT``() =
    [ G 2, 0x7UL; Status, 0x10UL ]
    |> run r6 [ "7c4001bd" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0x7fffffffUL; Status, 0x10UL ]
    |> run r6 [ "7c4001bd" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0xffffffff89abcdefUL; Status, 0x10UL ]
    |> run r6 [ "7c4001bd" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 7c621844, ins v0, v1, 0x1, 0x3, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 INS``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "7c621844" ]
    |> is []
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "7c621844" ]
    |> is [ G 2, 0x7ffffff3UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "7c621844" ]
    |> is [ G 2, 0xffffffff89abcde1UL ]

  /// <summary>
  /// 08000000, j 0x20000000 (binutils: j 20000000). A branch is not run against
  /// QEMU: it moves the PC, and its delay slot makes one word meaningless to
  /// run alone. Checked structurally from the manual: the transfer is left to
  /// the delay slot, which holds a NOP; control goes to 0x20000000 (the target
  /// binutils reads) when it always does.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 J``() =
    let words = [ "08000000"; "00000000" ]
    ownsJump r2 "08000000" false
    goes r2 words [] 0x20000000UL

  /// <summary>
  /// 0c000000, jal 0x20000000 (binutils: jal 20000000). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20000000 (the target binutils reads) when it always does; ra becomes
  /// 0x20100008 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 JAL``() =
    let words = [ "0c000000"; "00000000" ]
    ownsJump r2 "0c000000" false
    goes r2 words [] 0x20000000UL
    []
    |> run r2 words
    |> is [ G 31, 0x20100008UL ]

  /// <summary>
  /// 0040f809, jalr v0 (binutils: jalr $2). A branch is not run against QEMU:
  /// it moves the PC, and its delay slot makes one word meaningless to run
  /// alone. Checked structurally from the manual: the transfer is left to the
  /// delay slot, which holds a NOP; control goes to 0x20100400 when G 2 is
  /// 0x20100400; ra becomes 0x20100008 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 JALR``() =
    let words = [ "0040f809"; "00000000" ]
    ownsJump r2 "0040f809" false
    goes r2 words [ G 2, 0x20100400UL ] 0x20100400UL
    [ G 2, 0x20100400UL ]
    |> run r2 words
    |> is [ G 31, 0x20100008UL ]

  /// <summary>
  /// 00601409, jalr.hb v0, v1 (binutils: jalr.hb $2,$3). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100400 when G 3 is 0x20100400; the link register becomes 0x20100008
  /// and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 JALR.HB``() =
    let words = [ "00601409"; "00000000" ]
    ownsJump r2 "00601409" false
    goes r2 words [ G 3, 0x20100400UL ] 0x20100400UL
    [ G 3, 0x20100400UL ]
    |> run r2 words
    |> is [ G 2, 0x20100008UL ]

  /// <summary>
  /// 74000000, jalx 0x20000000 (binutils: jalx 20000000). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20000000 (the target binutils reads) when it always does; ra becomes
  /// 0x20100008 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 JALX``() =
    let words = [ "74000000"; "00000000" ]
    ownsJump r2 "74000000" false
    goes r2 words [] 0x20000000UL
    []
    |> run r2 words
    |> is [ G 31, 0x20100008UL ]

  /// <summary>
  /// f8020001, jialc v0, 0x1 (binutils: jialc $2,1). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100400 when G 2 is 0x201003ff; ra becomes 0x20100004 and nothing else
  /// changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 JIALC``() =
    let words = [ "f8020001" ]
    ownsJump r6 "f8020001" true
    goes r6 words [ G 2, 0x201003ffUL ] 0x20100400UL
    [ G 2, 0x201003ffUL ]
    |> run r6 words
    |> is [ G 31, 0x20100004UL ]

  /// <summary>
  /// d8020001, jic v0, 0x1 (binutils: jic $2,1). A branch is not run against
  /// QEMU: it moves the PC, and its delay slot makes one word meaningless to
  /// run alone. Checked structurally from the manual: the transfer is the
  /// branch's own, there being no delay slot; control goes to 0x20100400 when G
  /// 2 is 0x201003ff.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 JIC``() =
    let words = [ "d8020001" ]
    ownsJump r6 "d8020001" true
    goes r6 words [ G 2, 0x201003ffUL ] 0x20100400UL

  /// <summary>
  /// 00400008, jr v0 (binutils: jr $2). A branch is not run against QEMU: it
  /// moves the PC, and its delay slot makes one word meaningless to run alone.
  /// Checked structurally from the manual: the transfer is left to the delay
  /// slot, which holds a NOP; control goes to 0x20100400 when G 2 is
  /// 0x20100400.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 JR``() =
    let words = [ "00400008"; "00000000" ]
    ownsJump r2 "00400008" false
    goes r2 words [ G 2, 0x20100400UL ] 0x20100400UL

  /// <summary>
  /// 00400408, jr.hb v0 (binutils: jr.hb $2). A branch is not run against QEMU:
  /// it moves the PC, and its delay slot makes one word meaningless to run
  /// alone. Checked structurally from the manual: the transfer is left to the
  /// delay slot, which holds a NOP; control goes to 0x20100400 when G 2 is
  /// 0x20100400.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 JR.HB``() =
    let words = [ "00400408"; "00000000" ]
    ownsJump r2 "00400408" false
    goes r2 words [ G 2, 0x20100400UL ] 0x20100400UL

  /// <summary>
  /// 80620001, lb v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LB``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x5b898c14e4741671UL
        M 0x20200080UL, 0xe44e31a26fcc95a3UL
        M 0x20200088UL, 0x833bf6ec1a537189UL ]
    given0
    |> run r2 [ "80620001" ]
    |> is [ G 2, 0xffffffffffffffe4UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xcb0b04e6e9078a81UL
        M 0x20200080UL, 0x52cb1e9f8f8d924eUL
        M 0x20200088UL, 0xe59b34b0448edda1UL ]
    given1
    |> run r2 [ "80620001" ]
    |> is [ G 2, 0x52UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xcba93aa0f8604546UL
        M 0x20200080UL, 0x7bd5eaa77427c95UL
        M 0x20200088UL, 0x84a2458863467545UL ]
    given2
    |> run r2 [ "80620001" ]
    |> is [ G 2, 0x7UL ]

  /// <summary>
  /// 7c62012c, lbe v0, 2(v1), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LBE``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x131a6fead8721a3UL
        M 0x20200080UL, 0x992224651c812addUL
        M 0x20200088UL, 0x4c5ce054f33744a3UL ]
    given0
    |> run r2 [ "7c62012c" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0xfdd2cb0fef564c4cUL
        M 0x20200080UL, 0x1fb6c4c58a400531UL
        M 0x20200088UL, 0x1bc905de1aa54576UL ]
    given1
    |> run r2 [ "7c62012c" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x2c0c5541ea9c4ac2UL
        M 0x20200080UL, 0x753ce2603920d3dcUL
        M 0x20200088UL, 0x8434903c2e134c33UL ]
    given2
    |> run r2 [ "7c62012c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 90620001, lbu v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LBU``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xe7978f12b5e98ee7UL
        M 0x20200080UL, 0xae48ea6dbad6b0eUL
        M 0x20200088UL, 0x50ee3fc4763ed60eUL ]
    given0
    |> run r2 [ "90620001" ]
    |> is [ G 2, 0xaUL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x6a4b072da0a7eafUL
        M 0x20200080UL, 0x773c4fdfe1beb93UL
        M 0x20200088UL, 0x6ce581bd0a26331dUL ]
    given1
    |> run r2 [ "90620001" ]
    |> is [ G 2, 0x7UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x2d6ec9b26d63f375UL
        M 0x20200080UL, 0xb9019ae02a3ab7beUL
        M 0x20200088UL, 0x30598ab07131eb37UL ]
    given2
    |> run r2 [ "90620001" ]
    |> is [ G 2, 0xb9UL ]

  /// <summary>
  /// 7c620128, lbue v0, 2(v1), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LBUE``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0xd96cb1f5f7dfd1dfUL
        M 0x20200080UL, 0x6494374e0575513UL
        M 0x20200088UL, 0x3a4fdc4e4f2fad86UL ]
    given0
    |> run r2 [ "7c620128" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x4de4545e8ec127b6UL
        M 0x20200080UL, 0xcd51e61d0b410cb3UL
        M 0x20200088UL, 0x754fe8d712b31068UL ]
    given1
    |> run r2 [ "7c620128" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x6e085f9dc5239472UL
        M 0x20200080UL, 0x21532842485782d7UL
        M 0x20200088UL, 0x2e774662e8cdf4c4UL ]
    given2
    |> run r2 [ "7c620128" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// dc620001, ld v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LD``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xc2a8e8eaa0d86d5eUL
        M 0x20200080UL, 0xd89486e7c7223995UL
        M 0x20200088UL, 0x3b4c2bdc279ab769UL ]
    given0
    |> run r2 [ "dc620001" ]
    |> is [ G 2, 0xd89486e7c7223995UL ]
    let given1 =
      [ G 2, 0x7fffffffffffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x7966abd47584f263UL
        M 0x20200080UL, 0x6e6b75c7d8ae3d7cUL
        M 0x20200088UL, 0x74a0d0e3acd90185UL ]
    given1
    |> run r2 [ "dc620001" ]
    |> is [ G 2, 0x6e6b75c7d8ae3d7cUL ]
    let given2 =
      [ G 2, 0x123456789abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xf2c6b001f2add1b9UL
        M 0x20200080UL, 0x98874ec908b172a2UL
        M 0x20200088UL, 0x1d2483a831585868UL ]
    given2
    |> run r2 [ "dc620001" ]
    |> is [ G 2, 0x98874ec908b172a2UL ]

  /// <summary>
  /// d4420001, ldc1 f2, 1(v0), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LDC1``() =
    let given0 =
      [ G 2, 0x2020007fUL
        F 2, 0xbff0000000000000UL
        M 0x20200078UL, 0xb097842a97b61a75UL
        M 0x20200080UL, 0xa922e0d9eb5b44abUL
        M 0x20200088UL, 0x3820cffffa34343aUL ]
    given0
    |> run r2 [ "d4420001" ]
    |> is [ F 2, 0xa922e0d9eb5b44abUL ]
    let given1 =
      [ G 2, 0x2020007fUL
        F 2, 0x400c000000000000UL
        M 0x20200078UL, 0x2905f060c2699bf5UL
        M 0x20200080UL, 0xb61fc548733d111fUL
        M 0x20200088UL, 0xc5e3329865c573a1UL ]
    given1
    |> run r2 [ "d4420001" ]
    |> is [ F 2, 0xb61fc548733d111fUL ]
    let given2 =
      [ G 2, 0x2020007fUL
        F 2, 0x3fd0000000000000UL
        M 0x20200078UL, 0x2d9b07fba5d634abUL
        M 0x20200080UL, 0xca5407a196dea096UL
        M 0x20200088UL, 0xd044a1bc05d35890UL ]
    given2
    |> run r2 [ "d4420001" ]
    |> is [ F 2, 0xca5407a196dea096UL ]

  /// <summary>
  /// d8000000, ldc2 0x0, 0(r0), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LDC2``() =
    let given0 =
      [ M 0x20200078UL, 0xf551f55a2a3a3a87UL
        M 0x20200080UL, 0x2318f89dbbdd1c67UL
        M 0x20200088UL, 0x602dc6ab9b690eb3UL ]
    given0
    |> run r2 [ "d8000000" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ M 0x20200078UL, 0xc854ad5d228727ffUL
        M 0x20200080UL, 0x13b9c2062f8b5565UL
        M 0x20200088UL, 0xe3b7bdcc921cbc84UL ]
    given1
    |> run r2 [ "d8000000" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ M 0x20200078UL, 0x6d0829c82bf746fUL
        M 0x20200080UL, 0x12d71a19132b4bc3UL
        M 0x20200088UL, 0x33e4d24e72b51158UL ]
    given2
    |> run r2 [ "d8000000" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 68620001, ldl v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LDL``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x20200080UL
        M 0x20200078UL, 0x97463021110a4a0dUL
        M 0x20200080UL, 0xd101443feb885be0UL
        M 0x20200088UL, 0x1112f9537b4efc91UL ]
    given0
    |> run r2 [ "68620001" ]
    |> is [ G 2, 0x1443feb885be007UL ]
    let given1 =
      [ G 2, 0x7fffffffffffffffUL
        G 3, 0x20200081UL
        M 0x20200078UL, 0x82867fd9c53d3fa8UL
        M 0x20200080UL, 0x6e6cc1a590257bcbUL
        M 0x20200088UL, 0x658096dd88364d6cUL ]
    given1
    |> run r2 [ "68620001" ]
    |> is [ G 2, 0xc1a590257bcbffffUL ]
    let given2 =
      [ G 2, 0x123456789abcdefUL
        G 3, 0x20200084UL
        M 0x20200078UL, 0xe55fa6e5b0ef26e8UL
        M 0x20200080UL, 0x1185b3316302b503UL
        M 0x20200088UL, 0xdf065129a83c6384UL ]
    given2
    |> run r2 [ "68620001" ]
    |> is [ G 2, 0x2b5036789abcdefUL ]

  /// <summary>
  /// ec580080, ldpc v0, 0x20100400, against QEMU's I6400, a Release 6
  /// processor: the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LDPC``() =
    let given0 =
      [ G 2, 0x7UL
        M 0x201003f8UL, 0xe5ca621fa5c07aabUL
        M 0x20100400UL, 0x2fd7c9b4f199d2c8UL
        M 0x20100408UL, 0xf294d13915b163efUL ]
    given0
    |> run r6 [ "ec580080" ]
    |> is [ G 2, 0x2fd7c9b4f199d2c8UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        M 0x201003f8UL, 0x38a36c4ffc7673c4UL
        M 0x20100400UL, 0x7f923a801ba01dc1UL
        M 0x20100408UL, 0xa8891f683704ad8dUL ]
    given1
    |> run r6 [ "ec580080" ]
    |> is [ G 2, 0x7f923a801ba01dc1UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        M 0x201003f8UL, 0xd466de45a1bd74f8UL
        M 0x20100400UL, 0xc7cedd1eba65d350UL
        M 0x20100408UL, 0xefeea73ce4f902c8UL ]
    given2
    |> run r6 [ "ec580080" ]
    |> is [ G 2, 0xc7cedd1eba65d350UL ]

  /// <summary>
  /// 6c620001, ldr v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LDR``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x20200080UL
        M 0x20200078UL, 0x2a54ba9e11889790UL
        M 0x20200080UL, 0x409a2d7d70ea1e19UL
        M 0x20200088UL, 0xdfbd2e7dc026fb22UL ]
    given0
    |> run r2 [ "6c620001" ]
    |> is [ G 2, 0x409aUL ]
    let given1 =
      [ G 2, 0x7fffffffffffffffUL
        G 3, 0x20200081UL
        M 0x20200078UL, 0x2062b573952bb1f8UL
        M 0x20200080UL, 0x17af9164b3f45427UL
        M 0x20200088UL, 0xcd17bb3dc2bc19dfUL ]
    given1
    |> run r2 [ "6c620001" ]
    |> is [ G 2, 0x7fffffffff17af91UL ]
    let given2 =
      [ G 2, 0x123456789abcdefUL
        G 3, 0x20200084UL
        M 0x20200078UL, 0xbd83a2840d2384c5UL
        M 0x20200080UL, 0x82d03f33aa722795UL
        M 0x20200088UL, 0xcaba8b8ed7248f2fUL ]
    given2
    |> run r2 [ "6c620001" ]
    |> is [ G 2, 0x12382d03f33aa72UL ]

  /// <summary>
  /// 4c430081, ldxc1 f2, v1(v0), against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LDXC1``() =
    let given0 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0xbff0000000000000UL
        M 0x20200078UL, 0xb38cb2c538065f1bUL
        M 0x20200080UL, 0xaed52993a301f505UL
        M 0x20200088UL, 0x7251b9d5083ba48cUL ]
    given0
    |> run r2 [ "4c430081" ]
    |> is [ F 2, 0xaed52993a301f505UL ]
    let given1 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0x400c000000000000UL
        M 0x20200078UL, 0xfcc49d44131c87b8UL
        M 0x20200080UL, 0x5ec848fae8888c8aUL
        M 0x20200088UL, 0xa73fefb995e0660cUL ]
    given1
    |> run r2 [ "4c430081" ]
    |> is [ F 2, 0x5ec848fae8888c8aUL ]
    let given2 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0x3fd0000000000000UL
        M 0x20200078UL, 0x3f8c0fb591a8afb0UL
        M 0x20200080UL, 0x776aaec866354e73UL
        M 0x20200088UL, 0x84890cf390d63c3fUL ]
    given2
    |> run r2 [ "4c430081" ]
    |> is [ F 2, 0x776aaec866354e73UL ]

  /// <summary>
  /// 84620001, lh v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LH``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x7fa02394a5eaa650UL
        M 0x20200080UL, 0xbf8a7df0819c5a6aUL
        M 0x20200088UL, 0xa329e18221629d1aUL ]
    given0
    |> run r2 [ "84620001" ]
    |> is [ G 2, 0xffffffffffffbf8aUL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x59f5e92e8f9ff682UL
        M 0x20200080UL, 0xba945da918bfd2d8UL
        M 0x20200088UL, 0x1efabd76634158eeUL ]
    given1
    |> run r2 [ "84620001" ]
    |> is [ G 2, 0xffffffffffffba94UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x5d119e6f434bbc0fUL
        M 0x20200080UL, 0x29a6fc26ce347b1bUL
        M 0x20200088UL, 0x9af65f8b9fff3217UL ]
    given2
    |> run r2 [ "84620001" ]
    |> is [ G 2, 0x29a6UL ]

  /// <summary>
  /// 7c62012d, lhe v0, 2(v1), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LHE``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x35fefde95cd40f8aUL
        M 0x20200080UL, 0xa264603242838ccUL
        M 0x20200088UL, 0x5e60e05fb7a26bf7UL ]
    given0
    |> run r2 [ "7c62012d" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0xed0dd629d6a96d7dUL
        M 0x20200080UL, 0x75928a80dd293a0eUL
        M 0x20200088UL, 0x8c18e7a729e1fa35UL ]
    given1
    |> run r2 [ "7c62012d" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0xcf3f487e99f84cafUL
        M 0x20200080UL, 0x5d796f4cc940df7fUL
        M 0x20200088UL, 0x44a4593b13e8b63aUL ]
    given2
    |> run r2 [ "7c62012d" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 94620001, lhu v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LHU``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x41dd986680d020a7UL
        M 0x20200080UL, 0x87b655536c83771aUL
        M 0x20200088UL, 0x77921f976b49a924UL ]
    given0
    |> run r2 [ "94620001" ]
    |> is [ G 2, 0x87b6UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xe6797ba15de1cf3dUL
        M 0x20200080UL, 0xef8c618a092ec4fdUL
        M 0x20200088UL, 0xf1abfcd890281ad9UL ]
    given1
    |> run r2 [ "94620001" ]
    |> is [ G 2, 0xef8cUL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xe6dd6f2d951325f6UL
        M 0x20200080UL, 0xb854a7b5e0d55c80UL
        M 0x20200088UL, 0x63cffd591b38ba2bUL ]
    given2
    |> run r2 [ "94620001" ]
    |> is [ G 2, 0xb854UL ]

  /// <summary>
  /// 7c620129, lhue v0, 2(v1), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LHUE``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0xa67b7db236ca1ea2UL
        M 0x20200080UL, 0xc3644127126f3f7aUL
        M 0x20200088UL, 0x29e9485bd78eed45UL ]
    given0
    |> run r2 [ "7c620129" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0xed5ef22346c8f12dUL
        M 0x20200080UL, 0x79ae392cc97966daUL
        M 0x20200088UL, 0xa0fdda4d105459bfUL ]
    given1
    |> run r2 [ "7c620129" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x380c0d74357f992aUL
        M 0x20200080UL, 0x1b375ea653f4a009UL
        M 0x20200088UL, 0x76ce5f41ec4cf4e6UL ]
    given2
    |> run r2 [ "7c620129" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// c0620001, ll v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LL``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x34f2bc9f7be6afcaUL
        M 0x20200080UL, 0x895d892fb9a238dUL
        M 0x20200088UL, 0x496dfa0b8bf0a483UL ]
    given0
    |> run r2 [ "c0620001" ]
    |> is [ G 2, 0x895d892UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x1fb545b050cec211UL
        M 0x20200080UL, 0x7ffab3249b4d799bUL
        M 0x20200088UL, 0xf3beeb1fc2c51259UL ]
    given1
    |> run r2 [ "c0620001" ]
    |> is [ G 2, 0x7ffab324UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x363fa599bb9d70e5UL
        M 0x20200080UL, 0x240e6f62709cbc1aUL
        M 0x20200088UL, 0xdf7a7a93dc40c7aaUL ]
    given2
    |> run r2 [ "c0620001" ]
    |> is [ G 2, 0x240e6f62UL ]

  /// <summary>
  /// d0620001, lld v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LLD``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x7b5cc91a4b664ec2UL
        M 0x20200080UL, 0xbabb0e01031b2b90UL
        M 0x20200088UL, 0x85466c9567463711UL ]
    given0
    |> run r2 [ "d0620001" ]
    |> is [ G 2, 0xbabb0e01031b2b90UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x5dd70fefb5f3fd42UL
        M 0x20200080UL, 0xd44b321c43741c3aUL
        M 0x20200088UL, 0x22792a2bd471683fUL ]
    given1
    |> run r2 [ "d0620001" ]
    |> is [ G 2, 0xd44b321c43741c3aUL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x3a5c0fa44924431UL
        M 0x20200080UL, 0x8e02cc4395fbd8b6UL
        M 0x20200088UL, 0x23e74e88c7da5e4aUL ]
    given2
    |> run r2 [ "d0620001" ]
    |> is [ G 2, 0x8e02cc4395fbd8b6UL ]

  /// <summary>
  /// 7c221877, lldp v0, v1, (at). The less significant doubleword of the
  /// quadword at the base goes to rt and the more significant to rd; on a
  /// big-endian processor the more significant doubleword is the one at the
  /// lower address.
  /// No reference runs it: QEMU's I6400 reads the word as an unpaired
  /// LLD. Checked against the manual's Operation instead.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LLDP``() =
    [ G 1, 0x20200080UL
      M 0x20200080UL, 0x1011121314151617UL
      M 0x20200088UL, 0x18191a1b1c1d1e1fUL ]
    |> run r6 [ "7c221877" ]
    |> is [ G 2, 0x18191a1b1c1d1e1fUL; G 3, 0x1011121314151617UL ]

  /// <summary>
  /// 7c62012e, lle v0, 2(v1), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LLE``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x8174110c4724d8eeUL
        M 0x20200080UL, 0xccc18e67a3882f72UL
        M 0x20200088UL, 0x72b4483fdb13ff88UL ]
    given0
    |> run r2 [ "7c62012e" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x289809b1e4531347UL
        M 0x20200080UL, 0x533a5b440d64a00cUL
        M 0x20200088UL, 0x461176a58155152aUL ]
    given1
    |> run r2 [ "7c62012e" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0xcf304e2ea9a75318UL
        M 0x20200080UL, 0xe8d9d9053cd1c169UL
        M 0x20200088UL, 0xe71b9fd0bf355f79UL ]
    given2
    |> run r2 [ "7c62012e" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 7c221876, llwp v0, v1, (at). The least significant word of the
  /// doubleword at the base goes to rt and the most significant to rd, each
  /// sign-extended; on a big-endian processor the most significant word is
  /// the one at the lower address.
  /// No reference runs it: QEMU's I6400 reads the word as an unpaired
  /// LL. Checked against the manual's Operation instead.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LLWP``() =
    [ G 1, 0x20200080UL
      M 0x20200080UL, 0x1011121394959697UL ]
    |> run r6 [ "7c221876" ]
    |> is [ G 2, 0xffffffff94959697UL; G 3, 0x10111213UL ]

  /// <summary>
  /// 7c22186e, llwpe v0, v1, 0(at), against QEMU's I6400, a Release 6
  /// processor: QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LLWPE``() =
    let given0 =
      [ G 1, 0x20200080UL
        G 2, 0x7UL
        G 3, 0x3UL
        Status, 0x10UL
        M 0x20200078UL, 0xab998b6b3cb3f386UL
        M 0x20200080UL, 0xda141613805ff49eUL
        M 0x20200088UL, 0xfd426b3ae3647ba5UL ]
    given0
    |> run r6 [ "7c22186e" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 1, 0x20200080UL
        G 2, 0x7fffffffUL
        G 3, 0x1UL
        Status, 0x10UL
        M 0x20200078UL, 0xf028ce7fa6953c9bUL
        M 0x20200080UL, 0xa271611633a83b41UL
        M 0x20200088UL, 0x424c31bc6d91d484UL ]
    given1
    |> run r6 [ "7c22186e" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 1, 0x20200080UL
        G 2, 0xffffffff89abcdefUL
        G 3, 0x12345678UL
        Status, 0x10UL
        M 0x20200078UL, 0xa798c47b7be819e7UL
        M 0x20200080UL, 0x851c7d085d021feaUL
        M 0x20200088UL, 0x63b45ce2966d87aUL ]
    given2
    |> run r6 [ "7c22186e" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 00641005, lsa v0, v1, a0, 0x0, against QEMU's I6400, a Release 6
  /// processor: the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LSA``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "00641005" ]
    |> is [ G 2, 0xbUL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "00641005" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r6 [ "00641005" ]
    |> is [ G 2, 0x23456788UL ]

  /// <summary>
  /// 3c020001, lui v0, 0x1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LUI``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "3c020001" ]
    |> is [ G 2, 0x10000UL ]
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "3c020001" ]
    |> is [ G 2, 0x10000UL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "3c020001" ]
    |> is [ G 2, 0x10000UL ]

  /// <summary>
  /// 4c430085, luxc1 f2, v1(v0), against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LUXC1``() =
    let given0 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0xbff0000000000000UL
        M 0x20200078UL, 0x66dc0c176450de4fUL
        M 0x20200080UL, 0xebbb4c878c0320a3UL
        M 0x20200088UL, 0x4b458f8837336314UL ]
    given0
    |> run r2 [ "4c430085" ]
    |> is [ F 2, 0xebbb4c878c0320a3UL ]
    let given1 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0x400c000000000000UL
        M 0x20200078UL, 0x7e200e35bbf9a72cUL
        M 0x20200080UL, 0x2944dc94848ad128UL
        M 0x20200088UL, 0xb7ff09e29410bdd6UL ]
    given1
    |> run r2 [ "4c430085" ]
    |> is [ F 2, 0x2944dc94848ad128UL ]
    let given2 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0x3fd0000000000000UL
        M 0x20200078UL, 0xb58c19b6910b8d4bUL
        M 0x20200080UL, 0xdf87f62d6206ace7UL
        M 0x20200088UL, 0x6096b8f97e594dd3UL ]
    given2
    |> run r2 [ "4c430085" ]
    |> is [ F 2, 0xdf87f62d6206ace7UL ]

  /// <summary>
  /// 8c620001, lw v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LW``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x19c1eac7961b0c9dUL
        M 0x20200080UL, 0x29cf09bec6f7dcecUL
        M 0x20200088UL, 0xfb8c5de5d86be136UL ]
    given0
    |> run r2 [ "8c620001" ]
    |> is [ G 2, 0x29cf09beUL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x57e5ea060bb9e149UL
        M 0x20200080UL, 0x8031ea8f2a20345fUL
        M 0x20200088UL, 0xa9bc5c8034efb57UL ]
    given1
    |> run r2 [ "8c620001" ]
    |> is [ G 2, 0xffffffff8031ea8fUL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xc09c7b57ae09ea6dUL
        M 0x20200080UL, 0xa25598fb36c8df84UL
        M 0x20200088UL, 0x14ab832c2048c996UL ]
    given2
    |> run r2 [ "8c620001" ]
    |> is [ G 2, 0xffffffffa25598fbUL ]

  /// <summary>
  /// c4420001, lwc1 f2, 1(v0), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LWC1``() =
    let given0 =
      [ G 2, 0x2020007fUL
        F 2, 0xbf800000UL
        M 0x20200078UL, 0xc28765bb874b9cf3UL
        M 0x20200080UL, 0x45d80cd9a44b3969UL
        M 0x20200088UL, 0xf32ca029980239a1UL ]
    given0
    |> run r2 [ "c4420001" ]
    |> is [ F 2, 0x45d80cd9UL ]
    let given1 =
      [ G 2, 0x2020007fUL
        F 2, 0x40600000UL
        M 0x20200078UL, 0xe3c5772f9ad016a4UL
        M 0x20200080UL, 0xd0028a1ed6d2bf73UL
        M 0x20200088UL, 0x384c1f666cb3bef8UL ]
    given1
    |> run r2 [ "c4420001" ]
    |> is [ F 2, 0xd0028a1eUL ]
    let given2 =
      [ G 2, 0x2020007fUL
        F 2, 0x3e800000UL
        M 0x20200078UL, 0xc5b5bf7c0c5a4483UL
        M 0x20200080UL, 0xdbde6e1357f8ead9UL
        M 0x20200088UL, 0xf606b25fb3101ccUL ]
    given2
    |> run r2 [ "c4420001" ]
    |> is [ F 2, 0xdbde6e13UL ]

  /// <summary>
  /// c8000000, lwc2 0x0, 0(r0), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LWC2``() =
    let given0 =
      [ M 0x20200078UL, 0x8e0c8848e8736669UL
        M 0x20200080UL, 0xfdf954e04dee2dc8UL
        M 0x20200088UL, 0xdcdf2d34ddbee55fUL ]
    given0
    |> run r2 [ "c8000000" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ M 0x20200078UL, 0x20d0bee0c4f69fd3UL
        M 0x20200080UL, 0xd16f31936d3a78bdUL
        M 0x20200088UL, 0x87809dd14c4c4a3aUL ]
    given1
    |> run r2 [ "c8000000" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ M 0x20200078UL, 0x5aae1248675af81eUL
        M 0x20200080UL, 0xed7f52065ffe326cUL
        M 0x20200088UL, 0xf589ce22713d0331UL ]
    given2
    |> run r2 [ "c8000000" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 7c62012f, lwe v0, 2(v1), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LWE``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x260231a6998fb87fUL
        M 0x20200080UL, 0xaa4d65c14650bbeaUL
        M 0x20200088UL, 0x55e981eeff552631UL ]
    given0
    |> run r2 [ "7c62012f" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x755c46e2da23cf68UL
        M 0x20200080UL, 0x33324ea797cdc37aUL
        M 0x20200088UL, 0x217f2544ae4bf535UL ]
    given1
    |> run r2 [ "7c62012f" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x8d914a9e9f2a6ad7UL
        M 0x20200080UL, 0x9c61aaa774c7de14UL
        M 0x20200088UL, 0x62951807905ed1b1UL ]
    given2
    |> run r2 [ "7c62012f" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 88620001, lwl v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LWL``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x20200080UL
        M 0x20200078UL, 0x4fa784f10a71f241UL
        M 0x20200080UL, 0x535198a3396cb581UL
        M 0x20200088UL, 0xd3ac3f3d81752c57UL ]
    given0
    |> run r2 [ "88620001" ]
    |> is [ G 2, 0x5198a307UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x20200081UL
        M 0x20200078UL, 0x2e51841d72fd5af9UL
        M 0x20200080UL, 0x7e799eddc7b52069UL
        M 0x20200088UL, 0x2c4277fda6fa7013UL ]
    given1
    |> run r2 [ "88620001" ]
    |> is [ G 2, 0xffffffff9eddffffUL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x20200084UL
        M 0x20200078UL, 0x10608c6c3399f933UL
        M 0x20200080UL, 0x5e232c871a164c6bUL
        M 0x20200088UL, 0xf8eab2e315cfbcecUL ]
    given2
    |> run r2 [ "88620001" ]
    |> is [ G 2, 0x164c6befUL ]

  /// <summary>
  /// 7c620119, lwle v0, 2(v1), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LWLE``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xe662bbba78e20a3cUL
        M 0x20200080UL, 0x27d36e26d14c440cUL
        M 0x20200088UL, 0x69a2789f635889deUL ]
    given0
    |> run r2 [ "7c620119" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x20200080UL
        Status, 0x10UL
        M 0x20200078UL, 0x27118a9ab080defUL
        M 0x20200080UL, 0xd3d128d54b3d9c6dUL
        M 0x20200088UL, 0x30a394adcac25ecbUL ]
    given1
    |> run r2 [ "7c620119" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x20200083UL
        Status, 0x10UL
        M 0x20200078UL, 0x4efa15002aea4f3UL
        M 0x20200080UL, 0x2394df489f387a97UL
        M 0x20200088UL, 0x8a88b0a524970b2cUL ]
    given2
    |> run r2 [ "7c620119" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// ec480100, lwpc v0, 0x20100400, against QEMU's I6400, a Release 6
  /// processor: the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LWPC``() =
    let given0 =
      [ G 2, 0x7UL
        M 0x201003f8UL, 0xc93e2a0680be7c32UL
        M 0x20100400UL, 0x6d0780cddbc42328UL
        M 0x20100408UL, 0x1a7cc4109dad56b7UL ]
    given0
    |> run r6 [ "ec480100" ]
    |> is [ G 2, 0x6d0780cdUL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        M 0x201003f8UL, 0xf867e109d8bc1822UL
        M 0x20100400UL, 0x8753a0b4dacfe1b6UL
        M 0x20100408UL, 0x35caa7c37c291577UL ]
    given1
    |> run r6 [ "ec480100" ]
    |> is [ G 2, 0xffffffff8753a0b4UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        M 0x201003f8UL, 0x5b36aa781dc614aeUL
        M 0x20100400UL, 0xe296011941d2b2ecUL
        M 0x20100408UL, 0x8ae2e38fe1135ae9UL ]
    given2
    |> run r6 [ "ec480100" ]
    |> is [ G 2, 0xffffffffe2960119UL ]

  /// <summary>
  /// 98620001, lwr v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LWR``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x20200080UL
        M 0x20200078UL, 0x4fbdf3ae5b73441bUL
        M 0x20200080UL, 0x12c8872ed55a275bUL
        M 0x20200088UL, 0xc4aff3ca7c3d5b4dUL ]
    given0
    |> run r2 [ "98620001" ]
    |> is [ G 2, 0x12c8UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x20200081UL
        M 0x20200078UL, 0x5fd9688a4523f545UL
        M 0x20200080UL, 0x60e59cce1d79fbe2UL
        M 0x20200088UL, 0xec353354832544f9UL ]
    given1
    |> run r2 [ "98620001" ]
    |> is [ G 2, 0x7f60e59cUL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x20200084UL
        M 0x20200078UL, 0x720129112ffd4948UL
        M 0x20200080UL, 0xe2a3dc34a8259c54UL
        M 0x20200088UL, 0xb48202f749685d42UL ]
    given2
    |> run r2 [ "98620001" ]
    |> is [ G 2, 0xffffffff89aba825UL ]

  /// <summary>
  /// 7c62011a, lwre v0, 2(v1), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LWRE``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x4833c3d87740c952UL
        M 0x20200080UL, 0x9f765ca5dffd8a8fUL
        M 0x20200088UL, 0xb7b55a7e420c73c3UL ]
    given0
    |> run r2 [ "7c62011a" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x20200080UL
        Status, 0x10UL
        M 0x20200078UL, 0x761155b405f729d3UL
        M 0x20200080UL, 0xc9d31290d95f49e0UL
        M 0x20200088UL, 0x5fceb6b4e19b5474UL ]
    given1
    |> run r2 [ "7c62011a" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x20200083UL
        Status, 0x10UL
        M 0x20200078UL, 0xd0b29c8eaa16232eUL
        M 0x20200080UL, 0xf0a5799ace8fc81UL
        M 0x20200088UL, 0xf56bb135466213eeUL ]
    given2
    |> run r2 [ "7c62011a" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 9c620001, lwu v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LWU``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xeb010a9ecce57475UL
        M 0x20200080UL, 0xc3f4b6c4fcca6170UL
        M 0x20200088UL, 0xab5f47ff40b118a4UL ]
    given0
    |> run r2 [ "9c620001" ]
    |> is [ G 2, 0xc3f4b6c4UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xbfc5dee7a70fa3bUL
        M 0x20200080UL, 0xed1239103347ec0eUL
        M 0x20200088UL, 0x5ea219ba82c7ea35UL ]
    given1
    |> run r2 [ "9c620001" ]
    |> is [ G 2, 0xed123910UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x34fcb7b1868c00eUL
        M 0x20200080UL, 0x7d732bb2bc177475UL
        M 0x20200088UL, 0x1d57c7c2e7b65c30UL ]
    given2
    |> run r2 [ "9c620001" ]
    |> is [ G 2, 0x7d732bb2UL ]

  /// <summary>
  /// ec500100, lwupc v0, 0x20100400, against QEMU's I6400, a Release 6
  /// processor: the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LWUPC``() =
    let given0 =
      [ G 2, 0x7UL
        M 0x201003f8UL, 0x45b0397e4b15024fUL
        M 0x20100400UL, 0x25c994bce5f12e99UL
        M 0x20100408UL, 0x88c55495363749e6UL ]
    given0
    |> run r6 [ "ec500100" ]
    |> is [ G 2, 0x25c994bcUL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        M 0x201003f8UL, 0x503624865d930e22UL
        M 0x20100400UL, 0x609939d10c1908fbUL
        M 0x20100408UL, 0x38ae56f03d29a7bUL ]
    given1
    |> run r6 [ "ec500100" ]
    |> is [ G 2, 0x609939d1UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        M 0x201003f8UL, 0x3b2c0bad8a334f4fUL
        M 0x20100400UL, 0xc23025d9b28a3a4fUL
        M 0x20100408UL, 0x68e8514084fb169bUL ]
    given2
    |> run r6 [ "ec500100" ]
    |> is [ G 2, 0xc23025d9UL ]

  /// <summary>
  /// 4c430080, lwxc1 f2, v1(v0), against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LWXC1``() =
    let given0 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0xbf800000UL
        M 0x20200078UL, 0x9692e8496dc2d47eUL
        M 0x20200080UL, 0x5cd754bf05d21498UL
        M 0x20200088UL, 0x6b7aa45b977f74e7UL ]
    given0
    |> run r2 [ "4c430080" ]
    |> is [ F 2, 0x5cd754bfUL ]
    let given1 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0x40600000UL
        M 0x20200078UL, 0x6f48bc8d1a8b0903UL
        M 0x20200080UL, 0x17688a199252ba73UL
        M 0x20200088UL, 0x6d88232363262c3cUL ]
    given1
    |> run r2 [ "4c430080" ]
    |> is [ F 2, 0x17688a19UL ]
    let given2 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0x3e800000UL
        M 0x20200078UL, 0x1b1e236aa2c71c1cUL
        M 0x20200080UL, 0xc6dd785f8f290261UL
        M 0x20200088UL, 0xcdb696978d213483UL ]
    given2
    |> run r2 [ "4c430080" ]
    |> is [ F 2, 0xc6dd785fUL ]

  /// <summary>
  /// 70430000, madd v0, v1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MADD``() =
    [ G 2, 0x7UL; G 3, 0x3UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run r2 [ "70430000" ]
    |> is [ Lo, 0x39UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x1UL
        Hi, 0x7fffffffUL
        Lo, 0xffffffff80000001UL ]
    given1
    |> run r2 [ "70430000" ]
    |> is [ Hi, 0xffffffff80000000UL; Lo, 0x0UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x12345678UL
        Hi, 0xffffffffdeadbeefUL
        Lo, 0x12345678UL ]
    given2
    |> run r2 [ "70430000" ]
    |> is [ Hi, 0xffffffffd643a257UL; Lo, 0xfffffffff4772880UL ]

  /// <summary>
  /// 4c8830a0, madd.s f2, f4, f6, f8, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MADD.fmt``() =
    let given0 =
      [ F 2, 0xbf800000UL
        F 4, 0x40100000UL
        F 6, 0x3fc00000UL
        F 8, 0x3f000000UL ]
    given0
    |> run r2 [ "4c8830a0" ]
    |> is [ F 2, 0x40400000UL ]
    let given1 =
      [ F 2, 0x40600000UL
        F 4, 0xc0c00000UL
        F 6, 0x3f400000UL
        F 8, 0x40800000UL ]
    given1
    |> run r2 [ "4c8830a0" ]
    |> is [ F 2, 0xc0400000UL ]
    let given2 =
      [ F 2, 0x3e800000UL
        F 4, 0x447a0000UL
        F 6, 0x3e000000UL
        F 8, 0xc0200000UL ]
    given2
    |> run r2 [ "4c8830a0" ]
    |> is [ F 2, 0x4479ec00UL ]

  /// <summary>
  /// 46062098, maddf.s f2, f4, f6, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MADDF.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; F 6, 0x3fc00000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46062098" ]
    |> is [ F 2, 0x40180000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; F 6, 0x3f400000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46062098" ]
    |> is [ F 2, 0xbf800000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46062098" ]
    |> is [ F 2, 0x42fa8000UL ]

  /// <summary>
  /// 70430001, maddu v0, v1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MADDU``() =
    [ G 2, 0x7UL; G 3, 0x3UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run r2 [ "70430001" ]
    |> is [ Lo, 0x39UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x1UL
        Hi, 0x7fffffffUL
        Lo, 0xffffffff80000001UL ]
    given1
    |> run r2 [ "70430001" ]
    |> is [ Hi, 0xffffffff80000000UL; Lo, 0x0UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x12345678UL
        Hi, 0xffffffffdeadbeefUL
        Lo, 0x12345678UL ]
    given2
    |> run r2 [ "70430001" ]
    |> is [ Hi, 0xffffffffe877f8cfUL; Lo, 0xfffffffff4772880UL ]

  /// <summary>
  /// 4606209e, max.s f2, f4, f6, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MAX.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; F 6, 0x3fc00000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4606209e" ]
    |> is [ F 2, 0x40100000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; F 6, 0x3f400000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4606209e" ]
    |> is [ F 2, 0x3f400000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4606209e" ]
    |> is [ F 2, 0x447a0000UL ]

  /// <summary>
  /// 4606209f, maxa.s f2, f4, f6, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MAXA.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; F 6, 0x3fc00000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4606209f" ]
    |> is [ F 2, 0x40100000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; F 6, 0x3f400000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4606209f" ]
    |> is [ F 2, 0xc0c00000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4606209f" ]
    |> is [ F 2, 0x447a0000UL ]

  /// <summary>
  /// 40010001, mfc0 at, 0x0, 0x1, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MFC0``() =
    [ G 1, 0x7UL; Status, 0x10UL ]
    |> run r2 [ "40010001" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL; Status, 0x10UL ]
    |> run r2 [ "40010001" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL; Status, 0x10UL ]
    |> run r2 [ "40010001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 44021000, mfc1 v0, f2, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MFC1``() =
    [ G 2, 0x7UL; F 2, 0x1122334455667788UL ]
    |> run r2 [ "44021000" ]
    |> is [ G 2, 0x55667788UL ]
    [ G 2, 0x7fffffffUL; F 2, 0xbf800000UL ]
    |> run r2 [ "44021000" ]
    |> is [ G 2, 0xffffffffbf800000UL ]
    [ G 2, 0xffffffff89abcdefUL; F 2, 0x8899aabbccddeeffUL ]
    |> run r2 [ "44021000" ]
    |> is [ G 2, 0xffffffffccddeeffUL ]

  /// <summary>
  /// 48010001, mfc2 at, 0x1, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MFC2``() =
    [ G 1, 0x7UL ]
    |> run r2 [ "48010001" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL ]
    |> run r2 [ "48010001" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL ]
    |> run r2 [ "48010001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 40400001, mfhc0 r0, 0x0, 0x1, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MFHC0``() =
    [ Status, 0x10UL ]
    |> run r2 [ "40400001" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "40400001" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "40400001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 44621000, mfhc1 v0, f2, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MFHC1``() =
    [ G 2, 0x7UL; F 2, 0x1122334455667788UL ]
    |> run r2 [ "44621000" ]
    |> is [ G 2, 0x11223344UL ]
    [ G 2, 0x7fffffffffffffffUL; F 2, 0xbf800000UL ]
    |> run r2 [ "44621000" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x123456789abcdefUL; F 2, 0x8899aabbccddeeffUL ]
    |> run r2 [ "44621000" ]
    |> is [ G 2, 0xffffffff8899aabbUL ]

  /// <summary>
  /// 48621900, mfhc2 v0, 0x1900, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MFHC2``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "48621900" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "48621900" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "48621900" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 00001010, mfhi v0, against QEMU's MIPS64R2-generic: the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MFHI``() =
    [ G 2, 0x7UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run r2 [ "00001010" ]
    |> is [ G 2, 0x13UL ]
    [ G 2, 0x7fffffffUL; Hi, 0x7fffffffUL; Lo, 0xffffffff80000001UL ]
    |> run r2 [ "00001010" ]
    |> is []
    [ G 2, 0xffffffff89abcdefUL; Hi, 0xffffffffdeadbeefUL; Lo, 0x12345678UL ]
    |> run r2 [ "00001010" ]
    |> is [ G 2, 0xffffffffdeadbeefUL ]

  /// <summary>
  /// 00001012, mflo v0, against QEMU's MIPS64R2-generic: the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MFLO``() =
    [ G 2, 0x7UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run r2 [ "00001012" ]
    |> is [ G 2, 0x24UL ]
    [ G 2, 0x7fffffffUL; Hi, 0x7fffffffUL; Lo, 0xffffffff80000001UL ]
    |> run r2 [ "00001012" ]
    |> is [ G 2, 0xffffffff80000001UL ]
    [ G 2, 0xffffffff89abcdefUL; Hi, 0xffffffffdeadbeefUL; Lo, 0x12345678UL ]
    |> run r2 [ "00001012" ]
    |> is [ G 2, 0x12345678UL ]

  /// <summary>
  /// 4606209c, min.s f2, f4, f6, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MIN.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; F 6, 0x3fc00000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4606209c" ]
    |> is [ F 2, 0x3fc00000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; F 6, 0x3f400000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4606209c" ]
    |> is [ F 2, 0xc0c00000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4606209c" ]
    |> is [ F 2, 0x3e000000UL ]

  /// <summary>
  /// 4606209d, mina.s f2, f4, f6, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MINA.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; F 6, 0x3fc00000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4606209d" ]
    |> is [ F 2, 0x3fc00000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; F 6, 0x3f400000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4606209d" ]
    |> is [ F 2, 0x3f400000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4606209d" ]
    |> is [ F 2, 0x3e000000UL ]

  /// <summary>
  /// 006410da, mod v0, v1, a0, against QEMU's I6400, a Release 6 processor: the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MOD``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "006410da" ]
    |> is [ G 2, 0x3UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "006410da" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r6 [ "006410da" ]
    |> is [ G 2, 0x1234560UL ]

  /// <summary>
  /// 006410db, modu v0, v1, a0, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MODU``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "006410db" ]
    |> is [ G 2, 0x3UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "006410db" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r6 [ "006410db" ]
    |> is [ G 2, 0x12345678UL ]

  /// <summary>
  /// 46002086, mov.s f2, f4, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MOV.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run r2 [ "46002086" ]
    |> is [ F 2, 0x40100000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL ]
    |> run r2 [ "46002086" ]
    |> is [ F 2, 0xc0c00000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL ]
    |> run r2 [ "46002086" ]
    |> is [ F 2, 0x447a0000UL ]

  /// <summary>
  /// 00641001, movf v0, v1, 0x1, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MOVF``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "00641001" ]
    |> is [ G 2, 0x3UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; Fcsr, 0xfe800000UL ]
    |> run r2 [ "00641001" ]
    |> is []
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; Fcsr, 0x800000UL ]
    |> run r2 [ "00641001" ]
    |> is [ G 2, 0x12345678UL ]
    [ G 2, 0x7UL; G 3, 0x3UL; Fcsr, 0x2000000UL ]
    |> run r2 [ "00641001" ]
    |> is []

  /// <summary>
  /// 46042091, movf.s f2, f4, 0x1, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MOVF.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run r2 [ "46042091" ]
    |> is [ F 2, 0x40100000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; Fcsr, 0xfe800000UL ]
    |> run r2 [ "46042091" ]
    |> is []
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; Fcsr, 0x800000UL ]
    |> run r2 [ "46042091" ]
    |> is [ F 2, 0x447a0000UL ]
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; Fcsr, 0x2000000UL ]
    |> run r2 [ "46042091" ]
    |> is []

  /// <summary>
  /// 0064100b, movn v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MOVN``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "0064100b" ]
    |> is [ G 2, 0x3UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "0064100b" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "0064100b" ]
    |> is [ G 2, 0x12345678UL ]
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "0064100b" ]
    |> is []

  /// <summary>
  /// 46022093, movn.s f2, f4, v0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MOVN.fmt``() =
    [ G 2, 0x7UL; F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run r2 [ "46022093" ]
    |> is [ F 2, 0x40100000UL ]
    [ G 2, 0x7fffffffUL; F 2, 0x40600000UL; F 4, 0xc0c00000UL ]
    |> run r2 [ "46022093" ]
    |> is [ F 2, 0xc0c00000UL ]
    [ G 2, 0xffffffff89abcdefUL; F 2, 0x3e800000UL; F 4, 0x447a0000UL ]
    |> run r2 [ "46022093" ]
    |> is [ F 2, 0x447a0000UL ]
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run r2 [ "46022093" ]
    |> is []

  /// <summary>
  /// 00651001, movt v0, v1, 0x1, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MOVT``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "00651001" ]
    |> is []
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; Fcsr, 0xfe800000UL ]
    |> run r2 [ "00651001" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; Fcsr, 0x800000UL ]
    |> run r2 [ "00651001" ]
    |> is []
    [ G 2, 0x7UL; G 3, 0x3UL; Fcsr, 0x2000000UL ]
    |> run r2 [ "00651001" ]
    |> is [ G 2, 0x3UL ]

  /// <summary>
  /// 46052091, movt.s f2, f4, 0x1, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MOVT.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run r2 [ "46052091" ]
    |> is []
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; Fcsr, 0xfe800000UL ]
    |> run r2 [ "46052091" ]
    |> is [ F 2, 0xc0c00000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; Fcsr, 0x800000UL ]
    |> run r2 [ "46052091" ]
    |> is []
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; Fcsr, 0x2000000UL ]
    |> run r2 [ "46052091" ]
    |> is [ F 2, 0x40100000UL ]

  /// <summary>
  /// 0064100a, movz v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MOVZ``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "0064100a" ]
    |> is []
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "0064100a" ]
    |> is []
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "0064100a" ]
    |> is []
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "0064100a" ]
    |> is [ G 2, 0x3UL ]

  /// <summary>
  /// 46022092, movz.s f2, f4, v0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MOVZ.fmt``() =
    [ G 2, 0x7UL; F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run r2 [ "46022092" ]
    |> is []
    [ G 2, 0x7fffffffUL; F 2, 0x40600000UL; F 4, 0xc0c00000UL ]
    |> run r2 [ "46022092" ]
    |> is []
    [ G 2, 0xffffffff89abcdefUL; F 2, 0x3e800000UL; F 4, 0x447a0000UL ]
    |> run r2 [ "46022092" ]
    |> is []
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run r2 [ "46022092" ]
    |> is [ F 2, 0x40100000UL ]

  /// <summary>
  /// 70430004, msub v0, v1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MSUB``() =
    [ G 2, 0x7UL; G 3, 0x3UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run r2 [ "70430004" ]
    |> is [ Lo, 0xfUL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x1UL
        Hi, 0x7fffffffUL
        Lo, 0xffffffff80000001UL ]
    given1
    |> run r2 [ "70430004" ]
    |> is [ Lo, 0x2UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x12345678UL
        Hi, 0xffffffffdeadbeefUL
        Lo, 0x12345678UL ]
    given2
    |> run r2 [ "70430004" ]
    |> is [ Hi, 0xffffffffe717db86UL; Lo, 0x2ff18470UL ]

  /// <summary>
  /// 4c8830a8, msub.s f2, f4, f6, f8, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MSUB.fmt``() =
    let given0 =
      [ F 2, 0xbf800000UL
        F 4, 0x40100000UL
        F 6, 0x3fc00000UL
        F 8, 0x3f000000UL ]
    given0
    |> run r2 [ "4c8830a8" ]
    |> is [ F 2, 0xbfc00000UL ]
    let given1 =
      [ F 2, 0x40600000UL
        F 4, 0xc0c00000UL
        F 6, 0x3f400000UL
        F 8, 0x40800000UL ]
    given1
    |> run r2 [ "4c8830a8" ]
    |> is [ F 2, 0x41100000UL ]
    let given2 =
      [ F 2, 0x3e800000UL
        F 4, 0x447a0000UL
        F 6, 0x3e000000UL
        F 8, 0xc0200000UL ]
    given2
    |> run r2 [ "4c8830a8" ]
    |> is [ F 2, 0xc47a1400UL ]

  /// <summary>
  /// 46062099, msubf.s f2, f4, f6, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MSUBF.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; F 6, 0x3fc00000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46062099" ]
    |> is [ F 2, 0xc08c0000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; F 6, 0x3f400000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46062099" ]
    |> is [ F 2, 0x41000000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46062099" ]
    |> is [ F 2, 0xc2f98000UL ]

  /// <summary>
  /// 70430005, msubu v0, v1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MSUBU``() =
    [ G 2, 0x7UL; G 3, 0x3UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run r2 [ "70430005" ]
    |> is [ Lo, 0xfUL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x1UL
        Hi, 0x7fffffffUL
        Lo, 0xffffffff80000001UL ]
    given1
    |> run r2 [ "70430005" ]
    |> is [ Lo, 0x2UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x12345678UL
        Hi, 0xffffffffdeadbeefUL
        Lo, 0x12345678UL ]
    given2
    |> run r2 [ "70430005" ]
    |> is [ Hi, 0xffffffffd4e3850eUL; Lo, 0x2ff18470UL ]

  /// <summary>
  /// 40800001, mtc0 r0, 0x0, 0x1, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MTC0``() =
    [ Status, 0x10UL ]
    |> run r2 [ "40800001" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "40800001" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "40800001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 44821000, mtc1 v0, f2, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MTC1``() =
    [ G 2, 0x7UL; F 2, 0x1122334455667788UL ]
    |> run r2 [ "44821000" ]
    |> is [ F 2, 0x1122334400000007UL ]
    [ G 2, 0x7fffffffUL; F 2, 0xbf800000UL ]
    |> run r2 [ "44821000" ]
    |> is [ F 2, 0x7fffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; F 2, 0x8899aabbccddeeffUL ]
    |> run r2 [ "44821000" ]
    |> is [ F 2, 0x8899aabb89abcdefUL ]

  /// <summary>
  /// 48821900, mtc2 v0, 0x1900, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MTC2``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "48821900" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "48821900" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "48821900" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 40c00001, mthc0 r0, 0x0, 0x1, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MTHC0``() =
    [ Status, 0x10UL ]
    |> run r2 [ "40c00001" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "40c00001" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "40c00001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 44e21000, mthc1 v0, f2, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MTHC1``() =
    [ G 2, 0x7UL; F 2, 0x1122334455667788UL ]
    |> run r2 [ "44e21000" ]
    |> is [ F 2, 0x755667788UL ]
    [ G 2, 0x7fffffffffffffffUL; F 2, 0xbf800000UL ]
    |> run r2 [ "44e21000" ]
    |> is [ F 2, 0xffffffffbf800000UL ]
    [ G 2, 0x123456789abcdefUL; F 2, 0x8899aabbccddeeffUL ]
    |> run r2 [ "44e21000" ]
    |> is [ F 2, 0x89abcdefccddeeffUL ]

  /// <summary>
  /// 48e21900, mthc2 v0, 0x1900, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MTHC2``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "48e21900" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "48e21900" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "48e21900" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 00400011, mthi v0, against QEMU's MIPS64R2-generic: the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MTHI``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "00400011" ]
    |> is [ Hi, 0x7UL ]
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "00400011" ]
    |> is [ Hi, 0x7fffffffUL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "00400011" ]
    |> is [ Hi, 0xffffffff89abcdefUL ]

  /// <summary>
  /// 00400013, mtlo v0, against QEMU's MIPS64R2-generic: the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MTLO``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "00400013" ]
    |> is [ Lo, 0x7UL ]
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "00400013" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "00400013" ]
    |> is [ Lo, 0xffffffff89abcdefUL ]

  /// <summary>
  /// 006410d8, muh v0, v1, a0, against QEMU's I6400, a Release 6 processor: the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MUH``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "006410d8" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "006410d8" ]
    |> is [ G 2, 0xffffffffffffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r6 [ "006410d8" ]
    |> is [ G 2, 0xffffffffffeb4992UL ]

  /// <summary>
  /// 006410d9, muhu v0, v1, a0, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MUHU``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "006410d9" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "006410d9" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r6 [ "006410d9" ]
    |> is [ G 2, 0x121fa00aUL ]

  /// <summary>
  /// 70641002, mul v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MUL``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "70641002" ]
    |> is [ G 2, 0xfUL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "70641002" ]
    |> is [ G 2, 0xfffffffffffffffeUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "70641002" ]
    |> is [ G 2, 0x35068740UL ]

  /// <summary>
  /// 46062082, mul.s f2, f4, f6, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MUL.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; F 6, 0x3fc00000UL ]
    |> run r2 [ "46062082" ]
    |> is [ F 2, 0x40580000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; F 6, 0x3f400000UL ]
    |> run r2 [ "46062082" ]
    |> is [ F 2, 0xc0900000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL ]
    |> run r2 [ "46062082" ]
    |> is [ F 2, 0x42fa0000UL ]

  /// <summary>
  /// 00430018, mult v0, v1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MULT``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "00430018" ]
    |> is [ Lo, 0x15UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "00430018" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "00430018" ]
    |> is [ Hi, 0xfffffffff795e368UL; Lo, 0xffffffffe242d208UL ]

  /// <summary>
  /// 00430019, multu v0, v1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MULTU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "00430019" ]
    |> is [ Lo, 0x15UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "00430019" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "00430019" ]
    |> is [ Hi, 0x9ca39e0UL; Lo, 0xffffffffe242d208UL ]

  /// <summary>
  /// 00641099, mulu v0, v1, a0, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MULU``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "00641099" ]
    |> is [ G 2, 0xfUL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "00641099" ]
    |> is [ G 2, 0xfffffffffffffffeUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r6 [ "00641099" ]
    |> is [ G 2, 0x35068740UL ]

  /// <summary>
  /// 04100000, nal 0x20100004 (binutils: bltzal $0,20100004). A branch is not
  /// run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: to
  /// 0x20100008, past the slot, when nothing is given; ra becomes 0x20100008
  /// and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 NAL``() =
    let words = [ "04100000"; "00000000" ]
    goes r2 words [] 0x20100008UL
    []
    |> run r2 words
    |> is [ G 31, 0x20100008UL ]

  /// <summary>
  /// 46002087, neg.s f2, f4, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 NEG.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run r2 [ "46002087" ]
    |> is [ F 2, 0xc0100000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL ]
    |> run r2 [ "46002087" ]
    |> is [ F 2, 0x40c00000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL ]
    |> run r2 [ "46002087" ]
    |> is [ F 2, 0xc47a0000UL ]

  /// <summary>
  /// 4c8830b0, nmadd.s f2, f4, f6, f8, against QEMU's MIPS64R2-generic: the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 NMADD.fmt``() =
    let given0 =
      [ F 2, 0xbf800000UL
        F 4, 0x40100000UL
        F 6, 0x3fc00000UL
        F 8, 0x3f000000UL ]
    given0
    |> run r2 [ "4c8830b0" ]
    |> is [ F 2, 0xc0400000UL ]
    let given1 =
      [ F 2, 0x40600000UL
        F 4, 0xc0c00000UL
        F 6, 0x3f400000UL
        F 8, 0x40800000UL ]
    given1
    |> run r2 [ "4c8830b0" ]
    |> is [ F 2, 0x40400000UL ]
    let given2 =
      [ F 2, 0x3e800000UL
        F 4, 0x447a0000UL
        F 6, 0x3e000000UL
        F 8, 0xc0200000UL ]
    given2
    |> run r2 [ "4c8830b0" ]
    |> is [ F 2, 0xc479ec00UL ]

  /// <summary>
  /// 4c8830b8, nmsub.s f2, f4, f6, f8, against QEMU's MIPS64R2-generic: the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 NMSUB.fmt``() =
    let given0 =
      [ F 2, 0xbf800000UL
        F 4, 0x40100000UL
        F 6, 0x3fc00000UL
        F 8, 0x3f000000UL ]
    given0
    |> run r2 [ "4c8830b8" ]
    |> is [ F 2, 0x3fc00000UL ]
    let given1 =
      [ F 2, 0x40600000UL
        F 4, 0xc0c00000UL
        F 6, 0x3f400000UL
        F 8, 0x40800000UL ]
    given1
    |> run r2 [ "4c8830b8" ]
    |> is [ F 2, 0xc1100000UL ]
    let given2 =
      [ F 2, 0x3e800000UL
        F 4, 0x447a0000UL
        F 6, 0x3e000000UL
        F 8, 0xc0200000UL ]
    given2
    |> run r2 [ "4c8830b8" ]
    |> is [ F 2, 0x447a1400UL ]

  /// <summary>
  /// 00000000, nop, against QEMU's MIPS64R2-generic: the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 NOP``() =
    []
    |> run r2 [ "00000000" ]
    |> is []
    []
    |> run r2 [ "00000000" ]
    |> is []
    []
    |> run r2 [ "00000000" ]
    |> is []

  /// <summary>
  /// 00641027, nor v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 NOR``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "00641027" ]
    |> is [ G 2, 0xfffffffffffffff8UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "00641027" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "00641027" ]
    |> is [ G 2, 0x1030107UL ]

  /// <summary>
  /// 00641025, or v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 OR``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "00641025" ]
    |> is []
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "00641025" ]
    |> is [ G 2, 0xffffffffffffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "00641025" ]
    |> is [ G 2, 0xfffffffffefcfef8UL ]

  /// <summary>
  /// 34620100, ori v0, v1, 0x100, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ORI``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "34620100" ]
    |> is [ G 2, 0x103UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "34620100" ]
    |> is [ G 2, 0x101UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "34620100" ]
    |> is [ G 2, 0x12345778UL ]

  /// <summary>
  /// 00000140, pause, against QEMU's MIPS64R2-generic: the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 PAUSE``() =
    []
    |> run r2 [ "00000140" ]
    |> is []
    []
    |> run r2 [ "00000140" ]
    |> is []
    []
    |> run r2 [ "00000140" ]
    |> is []

  /// <summary>
  /// 46c620ac, pll.ps f2, f4, f6, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 PLL.PS``() =
    let given0 =
      [ F 2, 0xbf8000003f800000UL
        F 4, 0x40100000bfc00000UL
        F 6, 0x3fc000003e800000UL ]
    given0
    |> run r2 [ "46c620ac" ]
    |> is [ F 2, 0xbfc000003e800000UL ]
    let given1 =
      [ F 2, 0x40600000c0600000UL
        F 4, 0xc0c000003f000000UL
        F 6, 0x3f40000040000000UL ]
    given1
    |> run r2 [ "46c620ac" ]
    |> is [ F 2, 0x3f00000040000000UL ]
    let given2 =
      [ F 2, 0x3e8000003f400000UL
        F 4, 0x447a000040400000UL
        F 6, 0x3e000000c0800000UL ]
    given2
    |> run r2 [ "46c620ac" ]
    |> is [ F 2, 0x40400000c0800000UL ]

  /// <summary>
  /// 46c620ad, plu.ps f2, f4, f6, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 PLU.PS``() =
    let given0 =
      [ F 2, 0xbf8000003f800000UL
        F 4, 0x40100000bfc00000UL
        F 6, 0x3fc000003e800000UL ]
    given0
    |> run r2 [ "46c620ad" ]
    |> is [ F 2, 0xbfc000003fc00000UL ]
    let given1 =
      [ F 2, 0x40600000c0600000UL
        F 4, 0xc0c000003f000000UL
        F 6, 0x3f40000040000000UL ]
    given1
    |> run r2 [ "46c620ad" ]
    |> is [ F 2, 0x3f0000003f400000UL ]
    let given2 =
      [ F 2, 0x3e8000003f400000UL
        F 4, 0x447a000040400000UL
        F 6, 0x3e000000c0800000UL ]
    given2
    |> run r2 [ "46c620ad" ]
    |> is [ F 2, 0x404000003e000000UL ]

  /// <summary>
  /// cc400008, pref 0x0, 8(v0), against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 PREF``() =
    let given0 =
      [ G 2, 0x20200078UL
        M 0x20200078UL, 0x1c1e546c5e63e13eUL
        M 0x20200080UL, 0x6df88337c95d8820UL
        M 0x20200088UL, 0x6f2f5170c580c627UL ]
    given0
    |> run r2 [ "cc400008" ]
    |> is []
    let given1 =
      [ G 2, 0x20200078UL
        M 0x20200078UL, 0xd84fcc47b23abe25UL
        M 0x20200080UL, 0x64a8cf748676e8a9UL
        M 0x20200088UL, 0xafd12b48dcd42baaUL ]
    given1
    |> run r2 [ "cc400008" ]
    |> is []
    let given2 =
      [ G 2, 0x20200078UL
        M 0x20200078UL, 0x4930c92fd0fb4188UL
        M 0x20200080UL, 0xe5e1ea073929b35fUL
        M 0x20200088UL, 0xf6b959a1784cdb2fUL ]
    given2
    |> run r2 [ "cc400008" ]
    |> is []

  /// <summary>
  /// 7c400423, prefe 0x0, 8(v0), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 PREFE``() =
    let given0 =
      [ G 2, 0x20200078UL
        Status, 0x10UL
        M 0x20200078UL, 0xfa03be607277d0f0UL
        M 0x20200080UL, 0xe3344034af659872UL
        M 0x20200088UL, 0xeca78e2153361b45UL ]
    given0
    |> run r2 [ "7c400423" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x20200078UL
        Status, 0x10UL
        M 0x20200078UL, 0x126770a6a281167aUL
        M 0x20200080UL, 0x5d961e67ac447030UL
        M 0x20200088UL, 0x325241ab23d6be56UL ]
    given1
    |> run r2 [ "7c400423" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0x20200078UL
        Status, 0x10UL
        M 0x20200078UL, 0x3f926f35cf94f3f5UL
        M 0x20200080UL, 0xd13565fdfd0ca6d5UL
        M 0x20200088UL, 0xa85d9cff64df2b4aUL ]
    given2
    |> run r2 [ "7c400423" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 4c43100f, prefx 0x3, v1(v0), against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 PREFX``() =
    let given0 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        M 0x20200078UL, 0x74bb42817776fd23UL
        M 0x20200080UL, 0xf2332143af2f66c3UL
        M 0x20200088UL, 0x28e2435e8c137078UL ]
    given0
    |> run r2 [ "4c43100f" ]
    |> is []
    let given1 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        M 0x20200078UL, 0xc25dda2883225b89UL
        M 0x20200080UL, 0xa211bb90cea1739dUL
        M 0x20200088UL, 0x7399a80b5ea9eacfUL ]
    given1
    |> run r2 [ "4c43100f" ]
    |> is []
    let given2 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        M 0x20200078UL, 0xb4ace59c9a8e0b0cUL
        M 0x20200080UL, 0x44603cecfd55682cUL
        M 0x20200088UL, 0x2d17f3ce038a7c1aUL ]
    given2
    |> run r2 [ "4c43100f" ]
    |> is []

  /// <summary>
  /// 46c620ae, pul.ps f2, f4, f6, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 PUL.PS``() =
    let given0 =
      [ F 2, 0xbf8000003f800000UL
        F 4, 0x40100000bfc00000UL
        F 6, 0x3fc000003e800000UL ]
    given0
    |> run r2 [ "46c620ae" ]
    |> is [ F 2, 0x401000003e800000UL ]
    let given1 =
      [ F 2, 0x40600000c0600000UL
        F 4, 0xc0c000003f000000UL
        F 6, 0x3f40000040000000UL ]
    given1
    |> run r2 [ "46c620ae" ]
    |> is [ F 2, 0xc0c0000040000000UL ]
    let given2 =
      [ F 2, 0x3e8000003f400000UL
        F 4, 0x447a000040400000UL
        F 6, 0x3e000000c0800000UL ]
    given2
    |> run r2 [ "46c620ae" ]
    |> is [ F 2, 0x447a0000c0800000UL ]

  /// <summary>
  /// 46c620af, puu.ps f2, f4, f6, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 PUU.PS``() =
    let given0 =
      [ F 2, 0xbf8000003f800000UL
        F 4, 0x40100000bfc00000UL
        F 6, 0x3fc000003e800000UL ]
    given0
    |> run r2 [ "46c620af" ]
    |> is [ F 2, 0x401000003fc00000UL ]
    let given1 =
      [ F 2, 0x40600000c0600000UL
        F 4, 0xc0c000003f000000UL
        F 6, 0x3f40000040000000UL ]
    given1
    |> run r2 [ "46c620af" ]
    |> is [ F 2, 0xc0c000003f400000UL ]
    let given2 =
      [ F 2, 0x3e8000003f400000UL
        F 4, 0x447a000040400000UL
        F 6, 0x3e000000c0800000UL ]
    given2
    |> run r2 [ "46c620af" ]
    |> is [ F 2, 0x447a00003e000000UL ]

  /// <summary>
  /// 7c02e83b, rdhwr v0, sp, 0x0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 RDHWR``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "7c02e83b" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "7c02e83b" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "7c02e83b" ]
    |> is [ G 2, 0x0UL ]

  /// <summary>
  /// 41431000, rdpgpr v0, v1, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 RDPGPR``() =
    [ G 2, 0x7UL; G 3, 0x3UL; Status, 0x10UL ]
    |> run r2 [ "41431000" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; Status, 0x10UL ]
    |> run r2 [ "41431000" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; Status, 0x10UL ]
    |> run r2 [ "41431000" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 46002095, recip.s f2, f4, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 RECIP.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x3f000000UL ]
    |> run r2 [ "46002095" ]
    |> is [ F 2, 0x40000000UL ]
    [ F 2, 0x40600000UL; F 4, 0x40800000UL ]
    |> run r2 [ "46002095" ]
    |> is [ F 2, 0x3e800000UL ]
    [ F 2, 0x3e800000UL; F 4, 0xbe000000UL ]
    |> run r2 [ "46002095" ]
    |> is [ F 2, 0xc1000000UL ]

  /// <summary>
  /// 4600209a, rint.s f2, f4, against QEMU's I6400, a Release 6 processor: the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 RINT.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40200000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4600209a" ]
    |> is [ F 2, 0x40000000UL; Fcsr, 0xc1004UL ]
    [ F 2, 0x40600000UL; F 4, 0xbfe00000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4600209a" ]
    |> is [ F 2, 0xc0000000UL; Fcsr, 0xc1004UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4600209a" ]
    |> is [ F 2, 0x447a0000UL ]

  /// <summary>
  /// 00231102, rotr v0, v1, 0x4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ROTR``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "00231102" ]
    |> is [ G 2, 0x30000000UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "00231102" ]
    |> is [ G 2, 0x10000000UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "00231102" ]
    |> is [ G 2, 0xffffffff81234567UL ]

  /// <summary>
  /// 00831046, rotrv v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ROTRV``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "00831046" ]
    |> is [ G 2, 0x18000000UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "00831046" ]
    |> is [ G 2, 0x4UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "00831046" ]
    |> is [ G 2, 0x34567812UL ]

  /// <summary>
  /// 46002088, round.l.s f2, f4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ROUND.L.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run r2 [ "46002088" ]
    |> is [ F 2, 0x2UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run r2 [ "46002088" ]
    |> is [ F 2, 0xfffffffffffffffeUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run r2 [ "46002088" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 4600208c, round.w.s f2, f4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ROUND.W.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run r2 [ "4600208c" ]
    |> is [ F 2, 0x2UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run r2 [ "4600208c" ]
    |> is [ F 2, 0xfffffffeUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run r2 [ "4600208c" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 46002096, rsqrt.s f2, f4, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 RSQRT.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x3e800000UL ]
    |> run r2 [ "46002096" ]
    |> is [ F 2, 0x40000000UL ]
    [ F 2, 0x40600000UL; F 4, 0x40800000UL ]
    |> run r2 [ "46002096" ]
    |> is [ F 2, 0x3f000000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x41800000UL ]
    |> run r2 [ "46002096" ]
    |> is []

  /// <summary>
  /// a0620001, sb v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SB``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x7ffcf3fe92f3c6bdUL
        M 0x20200080UL, 0x33209ee5f9697d9dUL
        M 0x20200088UL, 0xbcad3c7bc46b4bd4UL ]
    given0
    |> run r2 [ "a0620001" ]
    |> is [ M 0x20200080UL, 0x7209ee5f9697d9dUL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x6582a4234a62c117UL
        M 0x20200080UL, 0x71672e43f91e6539UL
        M 0x20200088UL, 0x25936bec8dfe41d7UL ]
    given1
    |> run r2 [ "a0620001" ]
    |> is [ M 0x20200080UL, 0xff672e43f91e6539UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x613d4d336c37f17dUL
        M 0x20200080UL, 0xa2dfead807383107UL
        M 0x20200088UL, 0x42c1c9b81b97f245UL ]
    given2
    |> run r2 [ "a0620001" ]
    |> is [ M 0x20200080UL, 0xefdfead807383107UL ]

  /// <summary>
  /// 7c62011c, sbe v0, 2(v1), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SBE``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0xca76a3115febd09aUL
        M 0x20200080UL, 0x44f1793940666deUL
        M 0x20200088UL, 0xaf4e8f5224f2c2f9UL ]
    given0
    |> run r2 [ "7c62011c" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x1cebaea05aeeb0f9UL
        M 0x20200080UL, 0x6bc93a38d3d10ffaUL
        M 0x20200088UL, 0xc6f57d1b5929477dUL ]
    given1
    |> run r2 [ "7c62011c" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x5b45605a1db3430bUL
        M 0x20200080UL, 0xd3bf62c7ee497059UL
        M 0x20200088UL, 0x8df05ff26bc70bc5UL ]
    given2
    |> run r2 [ "7c62011c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// e0620001, sc v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SC``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x4b6aa287db97c533UL
        M 0x20200080UL, 0x91e63bf63ced6e2UL
        M 0x20200088UL, 0x7440b189faeb1b53UL ]
    given0
    |> run r2 [ "e0620001" ]
    |> is [ G 2, 0x0UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x93b964f41774590cUL
        M 0x20200080UL, 0xe3c370ef013aac28UL
        M 0x20200088UL, 0x5f83e0dc7b651ba0UL ]
    given1
    |> run r2 [ "e0620001" ]
    |> is [ G 2, 0x0UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x6ce93a9aeca368b2UL
        M 0x20200080UL, 0x972e4b8aebd2b011UL
        M 0x20200088UL, 0x677d73f7bba94428UL ]
    given2
    |> run r2 [ "e0620001" ]
    |> is [ G 2, 0x0UL ]

  /// <summary>
  /// f0620001, scd v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SCD``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x86b35c8f09ab473cUL
        M 0x20200080UL, 0xacca2945f8c21a43UL
        M 0x20200088UL, 0x21de66b16e974ff1UL ]
    given0
    |> run r2 [ "f0620001" ]
    |> is [ G 2, 0x0UL ]
    let given1 =
      [ G 2, 0x7fffffffffffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x74c433b657679bbcUL
        M 0x20200080UL, 0xcc5954754809cc44UL
        M 0x20200088UL, 0x4e1308ccf005bdb0UL ]
    given1
    |> run r2 [ "f0620001" ]
    |> is [ G 2, 0x0UL ]
    let given2 =
      [ G 2, 0x123456789abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x5d4147bb9949a174UL
        M 0x20200080UL, 0x59b6e8d3603780ddUL
        M 0x20200088UL, 0x1b8c63a7a9813c0cUL ]
    given2
    |> run r2 [ "f0620001" ]
    |> is [ G 2, 0x0UL ]

  /// <summary>
  /// 7c242877 7c221867, lldp a0, a1, (at) then scdp v0, v1, (at). The store
  /// writes rd and rt as one quadword, rd the more significant, and sets rt
  /// to one; on a big-endian processor the more significant doubleword is the
  /// one at the lower address.
  /// No reference runs it: QEMU's I6400 reads the word as an unpaired
  /// SCD. Checked against the manual's Operation instead.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SCDP``() =
    let given =
      [ G 1, 0x20200080UL
        G 2, 0x2021222324252627UL
        G 3, 0x3031323334353637UL
        M 0x20200080UL, 0x1011121314151617UL
        M 0x20200088UL, 0x18191a1b1c1d1e1fUL ]
    given
    |> run r6 [ "7c242877"; "7c221867" ]
    |> is
      [ G 2, 0x1UL
        G 4, 0x18191a1b1c1d1e1fUL
        G 5, 0x1011121314151617UL
        M 0x20200080UL, 0x3031323334353637UL
        M 0x20200088UL, 0x2021222324252627UL ]

  /// <summary>
  /// 7c62011e, sce v0, 2(v1), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SCE``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x7299521e821a027bUL
        M 0x20200080UL, 0xc868520ac964979dUL
        M 0x20200088UL, 0x6748bf6d8167f553UL ]
    given0
    |> run r2 [ "7c62011e" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x96e85f6637616550UL
        M 0x20200080UL, 0x6e2d47e377443887UL
        M 0x20200088UL, 0x2b71fcefe728cfccUL ]
    given1
    |> run r2 [ "7c62011e" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x75683761cb124365UL
        M 0x20200080UL, 0x845d6f7f97e43d12UL
        M 0x20200088UL, 0xf1c02b5118cfce06UL ]
    given2
    |> run r2 [ "7c62011e" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 7c242876 7c221866, llwp a0, a1, (at) then scwp v0, v1, (at). The store
  /// writes the low word of rd and the low word of rt as one doubleword, rd's
  /// the more significant, and sets rt to one; on a big-endian processor the
  /// more significant word is the one at the lower address.
  /// No reference runs it: QEMU's I6400 reads the word as an unpaired
  /// SC. Checked against the manual's Operation instead.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SCWP``() =
    let given =
      [ G 1, 0x20200080UL
        G 2, 0xa0a1a2a3UL
        G 3, 0xb0b1b2b3UL
        M 0x20200080UL, 0x1011121314151617UL ]
    given
    |> run r6 [ "7c242876"; "7c221866" ]
    |> is
      [ G 2, 0x1UL
        G 4, 0x14151617UL
        G 5, 0x10111213UL
        M 0x20200080UL, 0xb0b1b2b3a0a1a2a3UL ]

  /// <summary>
  /// 7c22185e, scwpe v0, v1, 0(at), against QEMU's I6400, a Release 6
  /// processor: QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SCWPE``() =
    let given0 =
      [ G 1, 0x20200080UL
        G 2, 0x7UL
        G 3, 0x3UL
        Status, 0x10UL
        M 0x20200078UL, 0x66fd55de177d9fb9UL
        M 0x20200080UL, 0xfd0966bc5bea070fUL
        M 0x20200088UL, 0x794aaacfe0b9eed4UL ]
    given0
    |> run r6 [ "7c22185e" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 1, 0x20200080UL
        G 2, 0x7fffffffUL
        G 3, 0x1UL
        Status, 0x10UL
        M 0x20200078UL, 0x74c2731354eeed9UL
        M 0x20200080UL, 0xebf4d770116c3a57UL
        M 0x20200088UL, 0x50a05b4ce1fe083eUL ]
    given1
    |> run r6 [ "7c22185e" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 1, 0x20200080UL
        G 2, 0xffffffff89abcdefUL
        G 3, 0x12345678UL
        Status, 0x10UL
        M 0x20200078UL, 0x7553df5179d9424bUL
        M 0x20200080UL, 0x83a7933a9bb3ab13UL
        M 0x20200088UL, 0x3b0aa399a0d065d6UL ]
    given2
    |> run r6 [ "7c22185e" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// fc620001, sd v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SD``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x75578e48c31d4fc1UL
        M 0x20200080UL, 0x80abb8f30f69345cUL
        M 0x20200088UL, 0x515fd29a7857c407UL ]
    given0
    |> run r2 [ "fc620001" ]
    |> is [ M 0x20200080UL, 0x7UL ]
    let given1 =
      [ G 2, 0x7fffffffffffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x83c2e05feb023459UL
        M 0x20200080UL, 0x165fb1314915fa6fUL
        M 0x20200088UL, 0xa58d18523b981e48UL ]
    given1
    |> run r2 [ "fc620001" ]
    |> is [ M 0x20200080UL, 0x7fffffffffffffffUL ]
    let given2 =
      [ G 2, 0x123456789abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x53ab91abe248f9a1UL
        M 0x20200080UL, 0xc0d26baa447a5dcbUL
        M 0x20200088UL, 0xba482a4a9b252509UL ]
    given2
    |> run r2 [ "fc620001" ]
    |> is [ M 0x20200080UL, 0x123456789abcdefUL ]

  /// <summary>
  /// 7000003f, sdbbp 0x0. Not run against QEMU, whose user mode aborts on the
  /// debug exception it raises; the manual enters the debug handler, which is
  /// this architecture's breakpoint. The lift raises Breakpoint and changes
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SDBBP``() =
    []
    |> run r2 [ "7000003f" ]
    |> raises [ Breakpoint ] []

  /// <summary>
  /// f4420001, sdc1 f2, 1(v0), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SDC1``() =
    let given0 =
      [ G 2, 0x2020007fUL
        F 2, 0xbff0000000000000UL
        M 0x20200078UL, 0xef968d83af9c3484UL
        M 0x20200080UL, 0x1fc3e93cb18ec245UL
        M 0x20200088UL, 0x463182c98d1f2313UL ]
    given0
    |> run r2 [ "f4420001" ]
    |> is [ M 0x20200080UL, 0xbff0000000000000UL ]
    let given1 =
      [ G 2, 0x2020007fUL
        F 2, 0x400c000000000000UL
        M 0x20200078UL, 0x61464052f28ffb99UL
        M 0x20200080UL, 0xb2c06c97ade16cf5UL
        M 0x20200088UL, 0x4c9f2312774f98cUL ]
    given1
    |> run r2 [ "f4420001" ]
    |> is [ M 0x20200080UL, 0x400c000000000000UL ]
    let given2 =
      [ G 2, 0x2020007fUL
        F 2, 0x3fd0000000000000UL
        M 0x20200078UL, 0x97414070316ce4bdUL
        M 0x20200080UL, 0x14c999d09e0a3d26UL
        M 0x20200088UL, 0x5c1a569ec322d15UL ]
    given2
    |> run r2 [ "f4420001" ]
    |> is [ M 0x20200080UL, 0x3fd0000000000000UL ]

  /// <summary>
  /// f8000000, sdc2 0x0, 0(r0), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SDC2``() =
    let given0 =
      [ M 0x20200078UL, 0x8366d2174f6c376UL
        M 0x20200080UL, 0x8aba5204acf474beUL
        M 0x20200088UL, 0x3dfe93e9a2253931UL ]
    given0
    |> run r2 [ "f8000000" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ M 0x20200078UL, 0x3d7d765d031abbcfUL
        M 0x20200080UL, 0x6847dc520fc5c2d6UL
        M 0x20200088UL, 0x580ba0c2a3353f5cUL ]
    given1
    |> run r2 [ "f8000000" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ M 0x20200078UL, 0x6908ce823ca4ae52UL
        M 0x20200080UL, 0x6a5d2a28c3bd8a52UL
        M 0x20200088UL, 0xce5e86ad6917fd0fUL ]
    given2
    |> run r2 [ "f8000000" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// b0620001, sdl v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SDL``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x20200080UL
        M 0x20200078UL, 0xaa57e9c0106410caUL
        M 0x20200080UL, 0x50ffaa8a7c92d440UL
        M 0x20200088UL, 0x24be0786506911bfUL ]
    given0
    |> run r2 [ "b0620001" ]
    |> is [ M 0x20200080UL, 0x5000000000000000UL ]
    let given1 =
      [ G 2, 0x7fffffffffffffffUL
        G 3, 0x20200081UL
        M 0x20200078UL, 0xf1a6593ff43043a5UL
        M 0x20200080UL, 0xce50417cbf2d5759UL
        M 0x20200088UL, 0xd27aa2f8096eb0abUL ]
    given1
    |> run r2 [ "b0620001" ]
    |> is [ M 0x20200080UL, 0xce507fffffffffffUL ]
    let given2 =
      [ G 2, 0x123456789abcdefUL
        G 3, 0x20200084UL
        M 0x20200078UL, 0x7a1e2baa67d4bdc6UL
        M 0x20200080UL, 0x13e461ebc6a3739eUL
        M 0x20200088UL, 0xb206dfa00b46cab0UL ]
    given2
    |> run r2 [ "b0620001" ]
    |> is [ M 0x20200080UL, 0x13e461ebc6012345UL ]

  /// <summary>
  /// b4620001, sdr v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SDR``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x20200080UL
        M 0x20200078UL, 0xb49326878a92e2c7UL
        M 0x20200080UL, 0x83fbe15c0d7ca353UL
        M 0x20200088UL, 0xbad43ac67f87f418UL ]
    given0
    |> run r2 [ "b4620001" ]
    |> is [ M 0x20200080UL, 0x7e15c0d7ca353UL ]
    let given1 =
      [ G 2, 0x7fffffffffffffffUL
        G 3, 0x20200081UL
        M 0x20200078UL, 0x81a274bc54a3f28eUL
        M 0x20200080UL, 0xf31957fc208e8d63UL
        M 0x20200088UL, 0x9a7eda58885c5f51UL ]
    given1
    |> run r2 [ "b4620001" ]
    |> is [ M 0x20200080UL, 0xfffffffc208e8d63UL ]
    let given2 =
      [ G 2, 0x123456789abcdefUL
        G 3, 0x20200084UL
        M 0x20200078UL, 0x77d462a9a34ed599UL
        M 0x20200080UL, 0xbde5a53c115aa072UL
        M 0x20200088UL, 0x837ae491ccdf0244UL ]
    given2
    |> run r2 [ "b4620001" ]
    |> is [ M 0x20200080UL, 0x456789abcdefa072UL ]

  /// <summary>
  /// 4c431009, sdxc1 f2, v1(v0), against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SDXC1``() =
    let given0 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0xbff0000000000000UL
        M 0x20200078UL, 0xc51df20395e59328UL
        M 0x20200080UL, 0x91c9597defa5c176UL
        M 0x20200088UL, 0x374c17702d2c430eUL ]
    given0
    |> run r2 [ "4c431009" ]
    |> is [ M 0x20200080UL, 0xbff0000000000000UL ]
    let given1 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0x400c000000000000UL
        M 0x20200078UL, 0x6adb904476411efUL
        M 0x20200080UL, 0x421b9052990b7aa6UL
        M 0x20200088UL, 0xfc48bb2c5184e1acUL ]
    given1
    |> run r2 [ "4c431009" ]
    |> is [ M 0x20200080UL, 0x400c000000000000UL ]
    let given2 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0x3fd0000000000000UL
        M 0x20200078UL, 0x4190349898ae19aaUL
        M 0x20200080UL, 0xe435c71caf15d8a2UL
        M 0x20200088UL, 0x7ccaa2bf3e652695UL ]
    given2
    |> run r2 [ "4c431009" ]
    |> is [ M 0x20200080UL, 0x3fd0000000000000UL ]

  /// <summary>
  /// 7c021420, seb v0, v0, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SEB``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "7c021420" ]
    |> is []
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "7c021420" ]
    |> is [ G 2, 0xffffffffffffffffUL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "7c021420" ]
    |> is [ G 2, 0xffffffffffffffefUL ]

  /// <summary>
  /// 7c021620, seh v0, v0, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SEH``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "7c021620" ]
    |> is []
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "7c021620" ]
    |> is [ G 2, 0xffffffffffffffffUL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "7c021620" ]
    |> is [ G 2, 0xffffffffffffcdefUL ]

  /// <summary>
  /// 46062090, sel.s f2, f4, f6, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SEL.fmt``() =
    [ F 2, 0x3f800000UL; F 4, 0x40100000UL; F 6, 0x3fc00000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46062090" ]
    |> is [ F 2, 0x40100000UL ]
    [ F 2, 0x3f800001UL; F 4, 0xc0c00000UL; F 6, 0x3f400000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46062090" ]
    |> is [ F 2, 0x3f400000UL ]
    [ F 2, 0x1UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46062090" ]
    |> is [ F 2, 0x3e000000UL ]

  /// <summary>
  /// 00641035, seleqz v0, v1, a0, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SELEQZ``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "00641035" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "00641035" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r6 [ "00641035" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r6 [ "00641035" ]
    |> is [ G 2, 0x3UL ]

  /// <summary>
  /// 46062094, seleqz.s f2, f4, f6, against QEMU's I6400, a Release 6
  /// processor: the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SELEQZ.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46062094" ]
    |> is [ F 2, 0x40100000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; F 6, 0x1UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46062094" ]
    |> is [ F 2, 0x0UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; F 6, 0x3f800000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46062094" ]
    |> is [ F 2, 0x447a0000UL ]

  /// <summary>
  /// 46011817, selneqz.s f0, f3, f1, against QEMU's I6400, a Release 6
  /// processor: the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SELNEQZ.fmt``() =
    [ F 0, 0xbf800000UL; F 3, 0x40100000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46011817" ]
    |> is [ F 0, 0x0UL ]
    [ F 0, 0x40600000UL; F 1, 0x1UL; F 3, 0xc0c00000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46011817" ]
    |> is [ F 0, 0xc0c00000UL ]
    [ F 0, 0x3e800000UL; F 1, 0x3f800000UL; F 3, 0x447a0000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46011817" ]
    |> is [ F 0, 0x0UL ]

  /// <summary>
  /// 00641037, selnez v0, v1, a0, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SELNEZ``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "00641037" ]
    |> is [ G 2, 0x3UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "00641037" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r6 [ "00641037" ]
    |> is [ G 2, 0x12345678UL ]
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r6 [ "00641037" ]
    |> is [ G 2, 0x0UL ]

  /// <summary>
  /// a4620001, sh v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SH``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xf7a3e9b84caece6aUL
        M 0x20200080UL, 0x7026a551307b994fUL
        M 0x20200088UL, 0xd0e0487dae34b36dUL ]
    given0
    |> run r2 [ "a4620001" ]
    |> is [ M 0x20200080UL, 0x7a551307b994fUL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xf60363b29582716UL
        M 0x20200080UL, 0x11ae03d72408101eUL
        M 0x20200088UL, 0x89d8be1f34323501UL ]
    given1
    |> run r2 [ "a4620001" ]
    |> is [ M 0x20200080UL, 0xffff03d72408101eUL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xb9b8145ef8ce8971UL
        M 0x20200080UL, 0xf574a5b7b1b4a61UL
        M 0x20200088UL, 0xe55e28df756496e5UL ]
    given2
    |> run r2 [ "a4620001" ]
    |> is [ M 0x20200080UL, 0xcdef4a5b7b1b4a61UL ]

  /// <summary>
  /// 7c62011d, she v0, 2(v1), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SHE``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x883ad4bbf8dd0eacUL
        M 0x20200080UL, 0x740c795f70a56940UL
        M 0x20200088UL, 0x72b7874095ee513dUL ]
    given0
    |> run r2 [ "7c62011d" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x74e37124bd8f191aUL
        M 0x20200080UL, 0x7292a53dcd242014UL
        M 0x20200088UL, 0xc0177ac4e0739c54UL ]
    given1
    |> run r2 [ "7c62011d" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x6715dbe58180891eUL
        M 0x20200080UL, 0xe7ec614440a394a6UL
        M 0x20200088UL, 0xf4e5e6e429df1559UL ]
    given2
    |> run r2 [ "7c62011d" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 04170001, sigrie 0x1, against QEMU's I6400, a Release 6 processor: QEMU
  /// raised SIGILL (UndefinedInstruction here); the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SIGRIE``() =
    []
    |> run r6 [ "04170001" ]
    |> raises [ UndefinedInstruction ] []
    []
    |> run r6 [ "04170001" ]
    |> raises [ UndefinedInstruction ] []
    []
    |> run r6 [ "04170001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 00031100, sll v0, v1, 0x4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SLL``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "00031100" ]
    |> is [ G 2, 0x30UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "00031100" ]
    |> is [ G 2, 0x10UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "00031100" ]
    |> is [ G 2, 0x23456780UL ]

  /// <summary>
  /// 00831004, sllv v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SLLV``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "00831004" ]
    |> is [ G 2, 0x60UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "00831004" ]
    |> is [ G 2, 0x40000000UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "00831004" ]
    |> is [ G 2, 0x78000000UL ]

  /// <summary>
  /// 0064102a, slt v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SLT``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "0064102a" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "0064102a" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "0064102a" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x2UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "0064102a" ]
    |> is [ G 2, 0x1UL ]

  /// <summary>
  /// 28620100, slti v0, v1, 0x100, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SLTI``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "28620100" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "28620100" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "28620100" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x2UL; G 3, 0x3UL ]
    |> run r2 [ "28620100" ]
    |> is [ G 2, 0x1UL ]

  /// <summary>
  /// 2c620100, sltiu v0, v1, 0x100, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SLTIU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "2c620100" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "2c620100" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "2c620100" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x2UL; G 3, 0x3UL ]
    |> run r2 [ "2c620100" ]
    |> is [ G 2, 0x1UL ]

  /// <summary>
  /// 0064102b, sltu v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SLTU``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "0064102b" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "0064102b" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "0064102b" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0x2UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "0064102b" ]
    |> is [ G 2, 0x1UL ]

  /// <summary>
  /// 46002084, sqrt.s f2, f4, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SQRT.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run r2 [ "46002084" ]
    |> is [ F 2, 0x3fc00000UL ]
    [ F 2, 0x40600000UL; F 4, 0x41800000UL ]
    |> run r2 [ "46002084" ]
    |> is [ F 2, 0x40800000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x3d800000UL ]
    |> run r2 [ "46002084" ]
    |> is []

  /// <summary>
  /// 00031103, sra v0, v1, 0x4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SRA``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "00031103" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "00031103" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "00031103" ]
    |> is [ G 2, 0x1234567UL ]

  /// <summary>
  /// 00831007, srav v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SRAV``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "00831007" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "00831007" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "00831007" ]
    |> is [ G 2, 0x12UL ]

  /// <summary>
  /// 00031102, srl v0, v1, 0x4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SRL``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "00031102" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "00031102" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "00031102" ]
    |> is [ G 2, 0x1234567UL ]

  /// <summary>
  /// 00831006, srlv v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SRLV``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "00831006" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "00831006" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "00831006" ]
    |> is [ G 2, 0x12UL ]

  /// <summary>
  /// 00000040, ssnop, against QEMU's MIPS64R2-generic: the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SSNOP``() =
    []
    |> run r2 [ "00000040" ]
    |> is []
    []
    |> run r2 [ "00000040" ]
    |> is []
    []
    |> run r2 [ "00000040" ]
    |> is []

  /// <summary>
  /// 00641022, sub v0, v1, a0, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGFPE (Exception IntegerOverflow here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SUB``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "00641022" ]
    |> is [ G 2, 0xfffffffffffffffeUL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "00641022" ]
    |> is [ G 2, 0x3UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "00641022" ]
    |> is [ G 2, 0x13579be0UL ]
    [ G 2, 0x7UL; G 3, 0xffffffff80000000UL; G 4, 0x1UL ]
    |> run r2 [ "00641022" ]
    |> raises [ Exception IntegerOverflow ] []

  /// <summary>
  /// 46062081, sub.s f2, f4, f6, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SUB.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; F 6, 0x3fc00000UL ]
    |> run r2 [ "46062081" ]
    |> is [ F 2, 0x3f400000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; F 6, 0x3f400000UL ]
    |> run r2 [ "46062081" ]
    |> is [ F 2, 0xc0d80000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL ]
    |> run r2 [ "46062081" ]
    |> is [ F 2, 0x4479f800UL ]

  /// <summary>
  /// 00641023, subu v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SUBU``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "00641023" ]
    |> is [ G 2, 0xfffffffffffffffeUL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "00641023" ]
    |> is [ G 2, 0x3UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "00641023" ]
    |> is [ G 2, 0x13579be0UL ]

  /// <summary>
  /// 4c43100d, suxc1 f2, v1(v0), against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SUXC1``() =
    let given0 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0xbff0000000000000UL
        M 0x20200078UL, 0x249ffb6d55382050UL
        M 0x20200080UL, 0xbdb3ed06adeb396bUL
        M 0x20200088UL, 0xd8ddc60d20cddb62UL ]
    given0
    |> run r2 [ "4c43100d" ]
    |> is [ M 0x20200080UL, 0xbff0000000000000UL ]
    let given1 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0x400c000000000000UL
        M 0x20200078UL, 0xda4cc6e6e859fb9dUL
        M 0x20200080UL, 0xe8df6f0738dc6b18UL
        M 0x20200088UL, 0xf77cef6d23f871f6UL ]
    given1
    |> run r2 [ "4c43100d" ]
    |> is [ M 0x20200080UL, 0x400c000000000000UL ]
    let given2 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0x3fd0000000000000UL
        M 0x20200078UL, 0x80226bf10c877263UL
        M 0x20200080UL, 0x26d014cf8036b19aUL
        M 0x20200088UL, 0x60a52ccdd2c1137aUL ]
    given2
    |> run r2 [ "4c43100d" ]
    |> is [ M 0x20200080UL, 0x3fd0000000000000UL ]

  /// <summary>
  /// ac620001, sw v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SW``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xe0e12b6e04d3e1f0UL
        M 0x20200080UL, 0xe78bfacd75ab29a6UL
        M 0x20200088UL, 0xeeedc31f62ad6498UL ]
    given0
    |> run r2 [ "ac620001" ]
    |> is [ M 0x20200080UL, 0x775ab29a6UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x414e219037f4d1d4UL
        M 0x20200080UL, 0xb5bf17f8be356e7aUL
        M 0x20200088UL, 0x37b96f2e617e1821UL ]
    given1
    |> run r2 [ "ac620001" ]
    |> is [ M 0x20200080UL, 0x7fffffffbe356e7aUL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x3c70d7a613f076d5UL
        M 0x20200080UL, 0xa97f310c9389e721UL
        M 0x20200088UL, 0xb8b7653822dbc228UL ]
    given2
    |> run r2 [ "ac620001" ]
    |> is [ M 0x20200080UL, 0x89abcdef9389e721UL ]

  /// <summary>
  /// e4420001, swc1 f2, 1(v0), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SWC1``() =
    let given0 =
      [ G 2, 0x2020007fUL
        F 2, 0xbf800000UL
        M 0x20200078UL, 0x592e5e9659b476e1UL
        M 0x20200080UL, 0x426a5b9489287d5aUL
        M 0x20200088UL, 0xd9072cd65b8d2c07UL ]
    given0
    |> run r2 [ "e4420001" ]
    |> is [ M 0x20200080UL, 0xbf80000089287d5aUL ]
    let given1 =
      [ G 2, 0x2020007fUL
        F 2, 0x40600000UL
        M 0x20200078UL, 0x717fa72374fba68dUL
        M 0x20200080UL, 0x55ccac50c2e72e74UL
        M 0x20200088UL, 0xc7d2537155fa1b56UL ]
    given1
    |> run r2 [ "e4420001" ]
    |> is [ M 0x20200080UL, 0x40600000c2e72e74UL ]
    let given2 =
      [ G 2, 0x2020007fUL
        F 2, 0x3e800000UL
        M 0x20200078UL, 0xce11a24fc5d85a0fUL
        M 0x20200080UL, 0x419bd17d1a82ac1aUL
        M 0x20200088UL, 0x15e764559fb97d90UL ]
    given2
    |> run r2 [ "e4420001" ]
    |> is [ M 0x20200080UL, 0x3e8000001a82ac1aUL ]

  /// <summary>
  /// e8000000, swc2 0x0, 0(r0), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SWC2``() =
    let given0 =
      [ M 0x20200078UL, 0x26446f39a36fa505UL
        M 0x20200080UL, 0x4010b61daeed3ff5UL
        M 0x20200088UL, 0x1eaf992ac8dae8c0UL ]
    given0
    |> run r2 [ "e8000000" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ M 0x20200078UL, 0xf6970766f76c7bcaUL
        M 0x20200080UL, 0xd5c4a31c0f4ef1c5UL
        M 0x20200088UL, 0x8d93345fb48241b1UL ]
    given1
    |> run r2 [ "e8000000" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ M 0x20200078UL, 0xc86297ba2d4435f1UL
        M 0x20200080UL, 0x9ffa51c25915501bUL
        M 0x20200088UL, 0xc982b13d29f32306UL ]
    given2
    |> run r2 [ "e8000000" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 7c62011f, swe v0, 2(v1), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SWE``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x9455b0ebebc2d82UL
        M 0x20200080UL, 0xd4bba5d5d77f4ebfUL
        M 0x20200088UL, 0xa949f86eb619abd9UL ]
    given0
    |> run r2 [ "7c62011f" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x4c3087180c96bea0UL
        M 0x20200080UL, 0xe8ca5597957cacf0UL
        M 0x20200088UL, 0x74d3f468a7c1f03dUL ]
    given1
    |> run r2 [ "7c62011f" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x87bcfb907980cfedUL
        M 0x20200080UL, 0x8f3d6f1347e862d1UL
        M 0x20200088UL, 0x931ef5ea49172e91UL ]
    given2
    |> run r2 [ "7c62011f" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// a8620001, swl v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SWL``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x20200080UL
        M 0x20200078UL, 0xad8cedb51c91fab0UL
        M 0x20200080UL, 0xf1b06cc94adfbac4UL
        M 0x20200088UL, 0x397e0b8cd93cc38aUL ]
    given0
    |> run r2 [ "a8620001" ]
    |> is [ M 0x20200080UL, 0xf10000004adfbac4UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x20200081UL
        M 0x20200078UL, 0xe6e3e5ff91b5b7bUL
        M 0x20200080UL, 0x54cd0d8dd36de91dUL
        M 0x20200088UL, 0xaae22dc75359c3a0UL ]
    given1
    |> run r2 [ "a8620001" ]
    |> is [ M 0x20200080UL, 0x54cd7fffd36de91dUL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x20200084UL
        M 0x20200078UL, 0xda9ebf63cb75d67dUL
        M 0x20200080UL, 0xad0e4b2a56d808f5UL
        M 0x20200088UL, 0x972108dd1ae5f563UL ]
    given2
    |> run r2 [ "a8620001" ]
    |> is [ M 0x20200080UL, 0xad0e4b2a5689abcdUL ]

  /// <summary>
  /// 7c620121, swle v0, 2(v1), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SWLE``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x1f05a20329bdc6f6UL
        M 0x20200080UL, 0xc70d42343d97352dUL
        M 0x20200088UL, 0x1e9bdad7e5e89149UL ]
    given0
    |> run r2 [ "7c620121" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x20200080UL
        Status, 0x10UL
        M 0x20200078UL, 0x4db76ead2fa42c39UL
        M 0x20200080UL, 0x6778f07c754e7c6dUL
        M 0x20200088UL, 0x41d7861dd0a2a670UL ]
    given1
    |> run r2 [ "7c620121" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x20200083UL
        Status, 0x10UL
        M 0x20200078UL, 0x9012013a89af9cb2UL
        M 0x20200080UL, 0xd5847994ceab9b7eUL
        M 0x20200088UL, 0x5d282b163d1fd92cUL ]
    given2
    |> run r2 [ "7c620121" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// b8620001, swr v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SWR``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x20200080UL
        M 0x20200078UL, 0x2827c0dc5e9a4f22UL
        M 0x20200080UL, 0x94f84263e4988f90UL
        M 0x20200088UL, 0x2e7f7390ce1e6ef8UL ]
    given0
    |> run r2 [ "b8620001" ]
    |> is [ M 0x20200080UL, 0x74263e4988f90UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x20200081UL
        M 0x20200078UL, 0xf2bd2dcca1a2f71fUL
        M 0x20200080UL, 0x91100447a045f37aUL
        M 0x20200088UL, 0x2b82e47a88ba11a4UL ]
    given1
    |> run r2 [ "b8620001" ]
    |> is [ M 0x20200080UL, 0xffffff47a045f37aUL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x20200084UL
        M 0x20200078UL, 0x36ad5112091226efUL
        M 0x20200080UL, 0x8a450f7695b4d8ffUL
        M 0x20200088UL, 0xb6748cba1952e385UL ]
    given2
    |> run r2 [ "b8620001" ]
    |> is [ M 0x20200080UL, 0x8a450f76cdefd8ffUL ]

  /// <summary>
  /// 7c620122, swre v0, 2(v1), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SWRE``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xd8a576bdf4e91c5fUL
        M 0x20200080UL, 0x5740186ebfd928dUL
        M 0x20200088UL, 0xbde0d9c94818dfbeUL ]
    given0
    |> run r2 [ "7c620122" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x20200080UL
        Status, 0x10UL
        M 0x20200078UL, 0xf33b5075f57912c5UL
        M 0x20200080UL, 0x34384d22c440308bUL
        M 0x20200088UL, 0x1130556f3ee6fc4cUL ]
    given1
    |> run r2 [ "7c620122" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x20200083UL
        Status, 0x10UL
        M 0x20200078UL, 0x597a1bb5a4eb3802UL
        M 0x20200080UL, 0x2e656b0ccf0d4c4fUL
        M 0x20200088UL, 0x391823a9f4b607d7UL ]
    given2
    |> run r2 [ "7c620122" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 4c431008, swxc1 f2, v1(v0), against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SWXC1``() =
    let given0 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0xbf800000UL
        M 0x20200078UL, 0x71178933329394acUL
        M 0x20200080UL, 0xffca40cdd4877733UL
        M 0x20200088UL, 0x172b6ef2a4368b08UL ]
    given0
    |> run r2 [ "4c431008" ]
    |> is [ M 0x20200080UL, 0xbf800000d4877733UL ]
    let given1 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0x40600000UL
        M 0x20200078UL, 0xae2f71f974d55e09UL
        M 0x20200080UL, 0xeb4ca4e722ee403fUL
        M 0x20200088UL, 0x662de2490aacaa43UL ]
    given1
    |> run r2 [ "4c431008" ]
    |> is [ M 0x20200080UL, 0x4060000022ee403fUL ]
    let given2 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0x3e800000UL
        M 0x20200078UL, 0x1cdff8f3a112f919UL
        M 0x20200080UL, 0x9495c7f750cf77caUL
        M 0x20200088UL, 0x509d1efdefd40765UL ]
    given2
    |> run r2 [ "4c431008" ]
    |> is [ M 0x20200080UL, 0x3e80000050cf77caUL ]

  /// <summary>
  /// 0000000f, sync 0x0, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SYNC``() =
    []
    |> run r2 [ "0000000f" ]
    |> is []
    []
    |> run r2 [ "0000000f" ]
    |> is []
    []
    |> run r2 [ "0000000f" ]
    |> is []

  /// <summary>
  /// 045f0001, synci 1(v0), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SYNCI``() =
    let given0 =
      [ G 2, 0x2020007fUL
        M 0x20200078UL, 0xe15ed567d9966b43UL
        M 0x20200080UL, 0xb1eba2f02e2b6ba2UL
        M 0x20200088UL, 0x7b92ae28f301f824UL ]
    given0
    |> run r2 [ "045f0001" ]
    |> is []
    let given1 =
      [ G 2, 0x2020007fUL
        M 0x20200078UL, 0x503fefde6d7cfaf8UL
        M 0x20200080UL, 0xda475da259b62e7cUL
        M 0x20200088UL, 0x3e248080d8736424UL ]
    given1
    |> run r2 [ "045f0001" ]
    |> is []
    let given2 =
      [ G 2, 0x2020007fUL
        M 0x20200078UL, 0x7665605f94c4cd9dUL
        M 0x20200080UL, 0xb2be774364ad5117UL
        M 0x20200088UL, 0x25837d930a0571f1UL ]
    given2
    |> run r2 [ "045f0001" ]
    |> is []

  /// <summary>
  /// 0000000c, syscall. Not run against QEMU, where a system call is the host
  /// kernel answering rather than the instruction. The lift raises SysCall and
  /// changes nothing.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SYSCALL``() =
    []
    |> run r2 [ "0000000c" ]
    |> raises [ SysCall ] []

  /// <summary>
  /// 00430034, teq v0, v1, against QEMU's MIPS64R2-generic: QEMU raised SIGTRAP
  /// (Interrupt 13 here); the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TEQ``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "00430034" ]
    |> is []
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "00430034" ]
    |> is []
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "00430034" ]
    |> is []
    [ G 2, 0x7UL; G 3, 0x7UL ]
    |> run r2 [ "00430034" ]
    |> raises [ Interrupt 13 ] []
    [ G 3, 0x1UL ]
    |> run r2 [ "00430034" ]
    |> is []

  /// <summary>
  /// 044c1900, teqi v0, 0x1900, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGTRAP (Interrupt 13 here); the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TEQI``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "044c1900" ]
    |> is []
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "044c1900" ]
    |> is []
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "044c1900" ]
    |> is []
    [ G 2, 0x1900UL ]
    |> run r2 [ "044c1900" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0x18ffUL ]
    |> run r2 [ "044c1900" ]
    |> is []

  /// <summary>
  /// 00430030, tge v0, v1, against QEMU's MIPS64R2-generic: QEMU raised SIGTRAP
  /// (Interrupt 13 here); the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TGE``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "00430030" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "00430030" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "00430030" ]
    |> is []
    [ G 2, 0x7UL; G 3, 0x7UL ]
    |> run r2 [ "00430030" ]
    |> raises [ Interrupt 13 ] []
    [ G 3, 0x1UL ]
    |> run r2 [ "00430030" ]
    |> is []

  /// <summary>
  /// 04481900, tgei v0, 0x1900, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGTRAP (Interrupt 13 here); the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TGEI``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "04481900" ]
    |> is []
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "04481900" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "04481900" ]
    |> is []
    [ G 2, 0x1900UL ]
    |> run r2 [ "04481900" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0x18ffUL ]
    |> run r2 [ "04481900" ]
    |> is []

  /// <summary>
  /// 04491900, tgeiu v0, 0x1900, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGTRAP (Interrupt 13 here); the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TGEIU``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "04491900" ]
    |> is []
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "04491900" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "04491900" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0x1900UL ]
    |> run r2 [ "04491900" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0x18ffUL ]
    |> run r2 [ "04491900" ]
    |> is []

  /// <summary>
  /// 00430031, tgeu v0, v1, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGTRAP (Interrupt 13 here); the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TGEU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "00430031" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "00430031" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "00430031" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0x7UL; G 3, 0x7UL ]
    |> run r2 [ "00430031" ]
    |> raises [ Interrupt 13 ] []
    [ G 3, 0x1UL ]
    |> run r2 [ "00430031" ]
    |> is []

  /// <summary>
  /// 42000003, tlbinv, against QEMU's MIPS64R2-generic: QEMU raised SIGILL
  /// (UndefinedInstruction here); Status = 0x10 puts the lift in User Mode, the
  /// mode QEMU runs every word in; the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TLBINV``() =
    [ Status, 0x10UL ]
    |> run r2 [ "42000003" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000003" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000003" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 42000004, tlbinvf, against QEMU's MIPS64R2-generic: QEMU raised SIGILL
  /// (UndefinedInstruction here); Status = 0x10 puts the lift in User Mode, the
  /// mode QEMU runs every word in; the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TLBINVF``() =
    [ Status, 0x10UL ]
    |> run r2 [ "42000004" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000004" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000004" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 42000008, tlbp, against QEMU's MIPS64R2-generic: QEMU raised SIGILL
  /// (UndefinedInstruction here); Status = 0x10 puts the lift in User Mode, the
  /// mode QEMU runs every word in; the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TLBP``() =
    [ Status, 0x10UL ]
    |> run r2 [ "42000008" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000008" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000008" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 42000001, tlbr, against QEMU's MIPS64R2-generic: QEMU raised SIGILL
  /// (UndefinedInstruction here); Status = 0x10 puts the lift in User Mode, the
  /// mode QEMU runs every word in; the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TLBR``() =
    [ Status, 0x10UL ]
    |> run r2 [ "42000001" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000001" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 42000002, tlbwi, against QEMU's MIPS64R2-generic: QEMU raised SIGILL
  /// (UndefinedInstruction here); Status = 0x10 puts the lift in User Mode, the
  /// mode QEMU runs every word in; the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TLBWI``() =
    [ Status, 0x10UL ]
    |> run r2 [ "42000002" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000002" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000002" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 42000006, tlbwr, against QEMU's MIPS64R2-generic: QEMU raised SIGILL
  /// (UndefinedInstruction here); Status = 0x10 puts the lift in User Mode, the
  /// mode QEMU runs every word in; the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TLBWR``() =
    [ Status, 0x10UL ]
    |> run r2 [ "42000006" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000006" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000006" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 00430032, tlt v0, v1, against QEMU's MIPS64R2-generic: QEMU raised SIGTRAP
  /// (Interrupt 13 here); the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TLT``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "00430032" ]
    |> is []
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "00430032" ]
    |> is []
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "00430032" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0x7UL; G 3, 0x7UL ]
    |> run r2 [ "00430032" ]
    |> is []
    [ G 3, 0x1UL ]
    |> run r2 [ "00430032" ]
    |> raises [ Interrupt 13 ] []

  /// <summary>
  /// 044a1900, tlti v0, 0x1900, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGTRAP (Interrupt 13 here); the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TLTI``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "044a1900" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "044a1900" ]
    |> is []
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "044a1900" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0x1900UL ]
    |> run r2 [ "044a1900" ]
    |> is []
    [ G 2, 0x18ffUL ]
    |> run r2 [ "044a1900" ]
    |> raises [ Interrupt 13 ] []

  /// <summary>
  /// 044b1900, tltiu v0, 0x1900, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGTRAP (Interrupt 13 here); the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TLTIU``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "044b1900" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "044b1900" ]
    |> is []
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "044b1900" ]
    |> is []
    [ G 2, 0x1900UL ]
    |> run r2 [ "044b1900" ]
    |> is []
    [ G 2, 0x18ffUL ]
    |> run r2 [ "044b1900" ]
    |> raises [ Interrupt 13 ] []

  /// <summary>
  /// 00430033, tltu v0, v1, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGTRAP (Interrupt 13 here); the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TLTU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "00430033" ]
    |> is []
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "00430033" ]
    |> is []
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "00430033" ]
    |> is []
    [ G 2, 0x7UL; G 3, 0x7UL ]
    |> run r2 [ "00430033" ]
    |> is []
    [ G 3, 0x1UL ]
    |> run r2 [ "00430033" ]
    |> raises [ Interrupt 13 ] []

  /// <summary>
  /// 00430036, tne v0, v1, against QEMU's MIPS64R2-generic: QEMU raised SIGTRAP
  /// (Interrupt 13 here); the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TNE``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "00430036" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "00430036" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "00430036" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0x7UL; G 3, 0x7UL ]
    |> run r2 [ "00430036" ]
    |> is []
    [ G 3, 0x1UL ]
    |> run r2 [ "00430036" ]
    |> raises [ Interrupt 13 ] []

  /// <summary>
  /// 044e1900, tnei v0, 0x1900, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGTRAP (Interrupt 13 here); the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TNEI``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "044e1900" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "044e1900" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "044e1900" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0x1900UL ]
    |> run r2 [ "044e1900" ]
    |> is []
    [ G 2, 0x18ffUL ]
    |> run r2 [ "044e1900" ]
    |> raises [ Interrupt 13 ] []

  /// <summary>
  /// 46002089, trunc.l.s f2, f4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TRUNC.L.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run r2 [ "46002089" ]
    |> is [ F 2, 0x2UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run r2 [ "46002089" ]
    |> is [ F 2, 0xffffffffffffffffUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run r2 [ "46002089" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 4600208d, trunc.w.s f2, f4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TRUNC.W.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run r2 [ "4600208d" ]
    |> is [ F 2, 0x2UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run r2 [ "4600208d" ]
    |> is [ F 2, 0xffffffffUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run r2 [ "4600208d" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 42000020, wait, against QEMU's MIPS64R2-generic: QEMU raised SIGILL
  /// (UndefinedInstruction here); Status = 0x10 puts the lift in User Mode, the
  /// mode QEMU runs every word in; the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 WAIT``() =
    [ Status, 0x10UL ]
    |> run r2 [ "42000020" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000020" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000020" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 41c31000, wrpgpr v0, v1, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 WRPGPR``() =
    [ G 2, 0x7UL; G 3, 0x3UL; Status, 0x10UL ]
    |> run r2 [ "41c31000" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; Status, 0x10UL ]
    |> run r2 [ "41c31000" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; Status, 0x10UL ]
    |> run r2 [ "41c31000" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 7c0210a0, wsbh v0, v0, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 WSBH``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "7c0210a0" ]
    |> is [ G 2, 0x700UL ]
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "7c0210a0" ]
    |> is [ G 2, 0xffffffffff7fffffUL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "7c0210a0" ]
    |> is [ G 2, 0xffffffffab89efcdUL ]

  /// <summary>
  /// 00641026, xor v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 XOR``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "00641026" ]
    |> is [ G 2, 0x6UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "00641026" ]
    |> is [ G 2, 0xffffffffffffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "00641026" ]
    |> is [ G 2, 0xffffffffece8ece0UL ]

  /// <summary>
  /// 38620100, xori v0, v1, 0x100, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 XORI``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "38620100" ]
    |> is [ G 2, 0x103UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "38620100" ]
    |> is [ G 2, 0x101UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "38620100" ]
    |> is [ G 2, 0x12345778UL ]

  /// <summary>
  /// 4261, addiu v1, v0, 0x1, against QEMU's 24Kf: the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 ADDIU``() =
    [ G 2, 0x3UL; G 3, 0x7UL ]
    |> run m16 [ "4261" ]
    |> is [ G 3, 0x4UL ]
    [ G 2, 0x1UL; G 3, 0x7fffffffUL ]
    |> run m16 [ "4261" ]
    |> is [ G 3, 0x2UL ]
    [ G 2, 0x12345678UL; G 3, 0x89abcdefUL ]
    |> run m16 [ "4261" ]
    |> is [ G 3, 0x12345679UL ]

  /// <summary>
  /// e271, addu a0, v0, v1, against QEMU's 24Kf: the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 ADDU``() =
    [ G 2, 0x3UL; G 3, 0x5UL; G 4, 0x7UL ]
    |> run m16 [ "e271" ]
    |> is [ G 4, 0x8UL ]
    [ G 2, 0x1UL; G 3, 0xfffffffeUL; G 4, 0x7fffffffUL ]
    |> run m16 [ "e271" ]
    |> is [ G 4, 0xffffffffUL ]
    [ G 2, 0x12345678UL; G 3, 0xfedcba98UL; G 4, 0x89abcdefUL ]
    |> run m16 [ "e271" ]
    |> is [ G 4, 0x11111110UL ]

  /// <summary>
  /// ea6c, and v0, v0, v1, against QEMU's 24Kf: the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 AND``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16 [ "ea6c" ]
    |> is [ G 2, 0x3UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16 [ "ea6c" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL ]
    |> run m16 [ "ea6c" ]
    |> is [ G 2, 0x204468UL ]

  /// <summary>
  /// f000e001, asmacro 0x1, against QEMU's 24Kf: QEMU raised SIGILL
  /// (UndefinedInstruction here); the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 ASMACRO``() =
    []
    |> run m16 [ "f000e001" ]
    |> raises [ UndefinedInstruction ] []
    []
    |> run m16 [ "f000e001" ]
    |> raises [ UndefinedInstruction ] []
    []
    |> run m16 [ "f000e001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 1010, b 0x20100022 (binutils: b 20100022). A branch is not run against
  /// QEMU: it moves the PC, and its delay slot makes one word meaningless to
  /// run alone. Checked structurally from the manual: the transfer is the
  /// branch's own, there being no delay slot; control goes to 0x20100022 (the
  /// target binutils reads) when it always does.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 B``() =
    let words = [ "1010" ]
    ownsJump m16 "1010" true
    goes m16 words [] 0x20100022UL

  /// <summary>
  /// 2210, beqz v0, 0x20100022 (binutils: beqz $2,20100022). A branch is not
  /// run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100022 (the target binutils reads) when it always does; to 0x20100002,
  /// past the branch, when G 2 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 BEQZ``() =
    let words = [ "2210" ]
    ownsJump m16 "2210" true
    goes m16 words [] 0x20100022UL
    goes m16 words [ G 2, 0x5UL ] 0x20100002UL

  /// <summary>
  /// 2a10, bnez v0, 0x20100022 (binutils: bnez $2,20100022). A branch is not
  /// run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100022 (the target binutils reads) when G 2 is 0x5; to 0x20100002,
  /// past the branch, when nothing is given.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 BNEZ``() =
    let words = [ "2a10" ]
    ownsJump m16 "2a10" true
    goes m16 words [ G 2, 0x5UL ] 0x20100022UL
    goes m16 words [] 0x20100002UL

  /// <summary>
  /// e825, break 0x1, against QEMU's 24Kf: QEMU raised SIGTRAP (Breakpoint
  /// here); the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 BREAK``() =
    []
    |> run m16 [ "e825" ]
    |> raises [ Breakpoint ] []
    []
    |> run m16 [ "e825" ]
    |> raises [ Breakpoint ] []
    []
    |> run m16 [ "e825" ]
    |> raises [ Breakpoint ] []

  /// <summary>
  /// 6010, bteqz 0x20100022 (binutils: bteqz 20100022). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100022 (the target binutils reads) when it always does; to 0x20100002,
  /// past the branch, when G 24 is 0x1.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 BTEQZ``() =
    let words = [ "6010" ]
    ownsJump m16 "6010" true
    goes m16 words [] 0x20100022UL
    goes m16 words [ G 24, 0x1UL ] 0x20100002UL

  /// <summary>
  /// 6110, btnez 0x20100022 (binutils: btnez 20100022). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100022 (the target binutils reads) when G 24 is 0x1; to 0x20100002,
  /// past the branch, when nothing is given.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 BTNEZ``() =
    let words = [ "6110" ]
    ownsJump m16 "6110" true
    goes m16 words [ G 24, 0x1UL ] 0x20100022UL
    goes m16 words [] 0x20100002UL

  /// <summary>
  /// ea6a, cmp v0, v1, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 CMP``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 24, 0x1234UL ]
    |> run m16 [ "ea6a" ]
    |> is [ G 24, 0x4UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 24, 0x1234UL ]
    |> run m16 [ "ea6a" ]
    |> is [ G 24, 0x7ffffffeUL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL; G 24, 0x1234UL ]
    |> run m16 [ "ea6a" ]
    |> is [ G 24, 0x9b9f9b97UL ]

  /// <summary>
  /// 7201, cmpi v0, 0x1, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 CMPI``() =
    [ G 2, 0x7UL; G 24, 0x1234UL ]
    |> run m16 [ "7201" ]
    |> is [ G 24, 0x6UL ]
    [ G 2, 0x7fffffffUL; G 24, 0x1234UL ]
    |> run m16 [ "7201" ]
    |> is [ G 24, 0x7ffffffeUL ]
    [ G 2, 0x89abcdefUL; G 24, 0x1234UL ]
    |> run m16 [ "7201" ]
    |> is [ G 24, 0x89abcdeeUL ]

  /// <summary>
  /// ea7a, div v0, v1, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 DIV``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16 [ "ea7a" ]
    |> is [ Hi, 0x1UL; Lo, 0x2UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16 [ "ea7a" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL ]
    |> run m16 [ "ea7a" ]
    |> is [ Hi, 0xf6e5d4bfUL; Lo, 0xfffffffaUL ]

  /// <summary>
  /// ea7b, divu v0, v1, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 DIVU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16 [ "ea7b" ]
    |> is [ Hi, 0x1UL; Lo, 0x2UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16 [ "ea7b" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL ]
    |> run m16 [ "ea7b" ]
    |> is [ Hi, 0xa3d70a7UL; Lo, 0x7UL ]

  /// <summary>
  /// 18000100, jal 0x20000400 (binutils: jal 20000400). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20000400 (the target binutils reads) when it always does; ra becomes
  /// 0x20100007 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 JAL``() =
    let words = [ "18000100"; "6500" ]
    ownsJump m16 "18000100" false
    goes m16 words [] 0x20000400UL
    []
    |> run m16 words
    |> is [ G 31, 0x20100007UL ]

  /// <summary>
  /// ea40, jalr ra, v0 (binutils: jalr $2). A branch is not run against QEMU:
  /// it moves the PC, and its delay slot makes one word meaningless to run
  /// alone. Checked structurally from the manual: the transfer is left to the
  /// delay slot, which holds a NOP; control goes to 0x20100400 when G 2 is
  /// 0x20100401; the jump goes on in MIPS16; ra becomes 0x20100005 and nothing
  /// else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 JALR``() =
    let words = [ "ea40"; "6500" ]
    ownsJump m16 "ea40" false
    goes m16 words [ G 2, 0x20100401UL ] 0x20100400UL
    switches m16 words [ G 2, 0x20100401UL ] InterJmpKind.SwitchToMIPS16
    [ G 2, 0x20100401UL ]
    |> run m16 words
    |> is [ G 31, 0x20100005UL ]

  /// <summary>
  /// eac0, jalrc ra, v0 (binutils: jalrc $2). A branch is not run against QEMU:
  /// it moves the PC, and its delay slot makes one word meaningless to run
  /// alone. Checked structurally from the manual: the transfer is the branch's
  /// own, there being no delay slot; control goes to 0x20100400 when G 2 is
  /// 0x20100401; the jump goes on in MIPS16; ra becomes 0x20100003 and nothing
  /// else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 JALRC``() =
    let words = [ "eac0" ]
    ownsJump m16 "eac0" true
    goes m16 words [ G 2, 0x20100401UL ] 0x20100400UL
    switches m16 words [ G 2, 0x20100401UL ] InterJmpKind.SwitchToMIPS16
    [ G 2, 0x20100401UL ]
    |> run m16 words
    |> is [ G 31, 0x20100003UL ]

  /// <summary>
  /// 1c000100, jalx 0x20000400 (binutils: jalx 20000400). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20000400 (the target binutils reads) when it always does; the jump goes
  /// on in MIPS; ra becomes 0x20100007 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 JALX``() =
    let words = [ "1c000100"; "6500" ]
    ownsJump m16 "1c000100" false
    goes m16 words [] 0x20000400UL
    switches m16 words [] InterJmpKind.SwitchToMIPS
    []
    |> run m16 words
    |> is [ G 31, 0x20100007UL ]

  /// <summary>
  /// ea00, jr v0 (binutils: jr $2). A branch is not run against QEMU: it moves
  /// the PC, and its delay slot makes one word meaningless to run alone.
  /// Checked structurally from the manual: the transfer is left to the delay
  /// slot, which holds a NOP; control goes to 0x20100400 when G 2 is
  /// 0x20100401; the jump goes on in MIPS16.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 JR``() =
    let words = [ "ea00"; "6500" ]
    ownsJump m16 "ea00" false
    goes m16 words [ G 2, 0x20100401UL ] 0x20100400UL
    switches m16 words [ G 2, 0x20100401UL ] InterJmpKind.SwitchToMIPS16

  /// <summary>
  /// ea80, jrc v0 (binutils: jrc $2). A branch is not run against QEMU: it
  /// moves the PC, and its delay slot makes one word meaningless to run alone.
  /// Checked structurally from the manual: the transfer is the branch's own,
  /// there being no delay slot; control goes to 0x20100400 when G 2 is
  /// 0x20100401; the jump goes on in MIPS16.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 JRC``() =
    let words = [ "ea80" ]
    ownsJump m16 "ea80" true
    goes m16 words [ G 2, 0x20100401UL ] 0x20100400UL
    switches m16 words [ G 2, 0x20100401UL ] InterJmpKind.SwitchToMIPS16

  /// <summary>
  /// 8041, lb v0, 1(s0), against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 LB``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0xf2909bee6bff355bUL
        M 0x20200080UL, 0x8dcaca8e50400ea5UL
        M 0x20200088UL, 0x7e2a94a9f1bc1ab9UL ]
    given0
    |> run m16 [ "8041" ]
    |> is [ G 2, 0xffffff8dUL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0x301f9533d9cfbb39UL
        M 0x20200080UL, 0x2964557bcfcd77dfUL
        M 0x20200088UL, 0x472e01bb4e2dc4cUL ]
    given1
    |> run m16 [ "8041" ]
    |> is [ G 2, 0x29UL ]
    let given2 =
      [ G 2, 0x89abcdefUL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0xe7fba05932a34c5aUL
        M 0x20200080UL, 0x8151fa5c04a0f4c7UL
        M 0x20200088UL, 0x7df18c4d9caf7c1dUL ]
    given2
    |> run m16 [ "8041" ]
    |> is [ G 2, 0xffffff81UL ]

  /// <summary>
  /// a041, lbu v0, 1(s0), against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 LBU``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0xd5a81f7896d3b11eUL
        M 0x20200080UL, 0x6314f139636356b7UL
        M 0x20200088UL, 0xaa4c4efcbdcfc871UL ]
    given0
    |> run m16 [ "a041" ]
    |> is [ G 2, 0x63UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0xd71f1f7086d58a0eUL
        M 0x20200080UL, 0x3b59d8e71a10d3e7UL
        M 0x20200088UL, 0xa94f4eb9c78ae5afUL ]
    given1
    |> run m16 [ "a041" ]
    |> is [ G 2, 0x3bUL ]
    let given2 =
      [ G 2, 0x89abcdefUL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0xde65adb4e8dfb12bUL
        M 0x20200080UL, 0x2f3bcfdcb2633a39UL
        M 0x20200088UL, 0x22a0114c2c4be47bUL ]
    given2
    |> run m16 [ "a041" ]
    |> is [ G 2, 0x2fUL ]

  /// <summary>
  /// 8841, lh v0, 2(s0), against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 LH``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0x37c5ac0ed6fd8f64UL
        M 0x20200080UL, 0x7619c7274f355c7UL
        M 0x20200088UL, 0xa49a8463048742d9UL ]
    given0
    |> run m16 [ "8841" ]
    |> is [ G 2, 0x761UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0x64e08280089c24e7UL
        M 0x20200080UL, 0x7c406cc164a820adUL
        M 0x20200088UL, 0x854c10e5a4932f75UL ]
    given1
    |> run m16 [ "8841" ]
    |> is [ G 2, 0x7c40UL ]
    let given2 =
      [ G 2, 0x89abcdefUL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0x32d207a4e8e92adbUL
        M 0x20200080UL, 0xd192ef95f13a5f9fUL
        M 0x20200088UL, 0x62333524afc29cb3UL ]
    given2
    |> run m16 [ "8841" ]
    |> is [ G 2, 0xffffd192UL ]

  /// <summary>
  /// a841, lhu v0, 2(s0), against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 LHU``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0x5357de8e464fbddbUL
        M 0x20200080UL, 0xaa39e408e1c2391eUL
        M 0x20200088UL, 0x3f4f792f4bed42f7UL ]
    given0
    |> run m16 [ "a841" ]
    |> is [ G 2, 0xaa39UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0x489196e321036ab6UL
        M 0x20200080UL, 0xa8e659cdb44253dUL
        M 0x20200088UL, 0x5e5a2f7a6eb6ee50UL ]
    given1
    |> run m16 [ "a841" ]
    |> is [ G 2, 0xa8eUL ]
    let given2 =
      [ G 2, 0x89abcdefUL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0x5cbd719829acf969UL
        M 0x20200080UL, 0x2e66cae7228cb336UL
        M 0x20200088UL, 0xd6bdebd1fbf9f7c3UL ]
    given2
    |> run m16 [ "a841" ]
    |> is [ G 2, 0x2e66UL ]

  /// <summary>
  /// 6a01, li v0, 0x1, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 LI``() =
    [ G 2, 0x7UL ]
    |> run m16 [ "6a01" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0x7fffffffUL ]
    |> run m16 [ "6a01" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0x89abcdefUL ]
    |> run m16 [ "6a01" ]
    |> is [ G 2, 0x1UL ]

  /// <summary>
  /// 9201, lw v0, 4(sp), against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 LW``() =
    let given0 =
      [ G 2, 0x7UL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x6bdf9ccd6419029bUL
        M 0x20200080UL, 0xac45a893487971bcUL
        M 0x20200088UL, 0x31e7c46f8cf2e7c3UL ]
    given0
    |> run m16 [ "9201" ]
    |> is [ G 2, 0xac45a893UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x972fe369d09b43c2UL
        M 0x20200080UL, 0xfac3a853b119ac2cUL
        M 0x20200088UL, 0x47dd015971760f4aUL ]
    given1
    |> run m16 [ "9201" ]
    |> is [ G 2, 0xfac3a853UL ]
    let given2 =
      [ G 2, 0x89abcdefUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x1e278743e6863a4eUL
        M 0x20200080UL, 0x42b2a3c01654e538UL
        M 0x20200088UL, 0xae198d0b7c5f3521UL ]
    given2
    |> run m16 [ "9201" ]
    |> is [ G 2, 0x42b2a3c0UL ]

  /// <summary>
  /// ea10, mfhi v0, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 MFHI``() =
    [ G 2, 0x7UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run m16 [ "ea10" ]
    |> is [ G 2, 0x13UL ]
    [ G 2, 0x7fffffffUL; Hi, 0x7fffffffUL; Lo, 0x80000001UL ]
    |> run m16 [ "ea10" ]
    |> is []
    [ G 2, 0x89abcdefUL; Hi, 0xdeadbeefUL; Lo, 0x12345678UL ]
    |> run m16 [ "ea10" ]
    |> is [ G 2, 0xdeadbeefUL ]

  /// <summary>
  /// ea12, mflo v0, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 MFLO``() =
    [ G 2, 0x7UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run m16 [ "ea12" ]
    |> is [ G 2, 0x24UL ]
    [ G 2, 0x7fffffffUL; Hi, 0x7fffffffUL; Lo, 0x80000001UL ]
    |> run m16 [ "ea12" ]
    |> is [ G 2, 0x80000001UL ]
    [ G 2, 0x89abcdefUL; Hi, 0xdeadbeefUL; Lo, 0x12345678UL ]
    |> run m16 [ "ea12" ]
    |> is [ G 2, 0x12345678UL ]

  /// <summary>
  /// 6522, move at, v0, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 MOVE``() =
    [ G 1, 0x7UL; G 2, 0x3UL ]
    |> run m16 [ "6522" ]
    |> is [ G 1, 0x3UL ]
    [ G 1, 0x7fffffffUL; G 2, 0x1UL ]
    |> run m16 [ "6522" ]
    |> is [ G 1, 0x1UL ]
    [ G 1, 0x89abcdefUL; G 2, 0x12345678UL ]
    |> run m16 [ "6522" ]
    |> is [ G 1, 0x12345678UL ]

  /// <summary>
  /// ea78, mult v0, v1, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 MULT``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16 [ "ea78" ]
    |> is [ Lo, 0x15UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16 [ "ea78" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL ]
    |> run m16 [ "ea78" ]
    |> is [ Hi, 0xf795e368UL; Lo, 0xe242d208UL ]

  /// <summary>
  /// ea79, multu v0, v1, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 MULTU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16 [ "ea79" ]
    |> is [ Lo, 0x15UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16 [ "ea79" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL ]
    |> run m16 [ "ea79" ]
    |> is [ Hi, 0x9ca39e0UL; Lo, 0xe242d208UL ]

  /// <summary>
  /// ea6b, neg v0, v1, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 NEG``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16 [ "ea6b" ]
    |> is [ G 2, 0xfffffffdUL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16 [ "ea6b" ]
    |> is [ G 2, 0xffffffffUL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL ]
    |> run m16 [ "ea6b" ]
    |> is [ G 2, 0xedcba988UL ]

  /// <summary>
  /// 6500, nop, against QEMU's 24Kf: the lift has to change what QEMU changed
  /// and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 NOP``() =
    []
    |> run m16 [ "6500" ]
    |> is []
    []
    |> run m16 [ "6500" ]
    |> is []
    []
    |> run m16 [ "6500" ]
    |> is []

  /// <summary>
  /// ea6f, not v0, v1, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 NOT``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16 [ "ea6f" ]
    |> is [ G 2, 0xfffffffcUL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16 [ "ea6f" ]
    |> is [ G 2, 0xfffffffeUL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL ]
    |> run m16 [ "ea6f" ]
    |> is [ G 2, 0xedcba987UL ]

  /// <summary>
  /// ea6d, or v0, v0, v1, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 OR``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16 [ "ea6d" ]
    |> is []
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16 [ "ea6d" ]
    |> is []
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL ]
    |> run m16 [ "ea6d" ]
    |> is [ G 2, 0x9bbfdfffUL ]

  /// <summary>
  /// 6432, restore 0x10, s0, s1, against QEMU's 24Kf: the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 RESTORE``() =
    let given0 =
      [ G 16, 0x7UL
        G 17, 0x3UL
        G 29, 0x20200080UL
        M 0x20200060UL, 0xf0c4934c9077f4a3UL
        M 0x20200068UL, 0x31184a587ffac785UL
        M 0x20200070UL, 0x221b7809c6e2494eUL
        M 0x20200078UL, 0xb5e0572ead0f5c38UL
        M 0x20200080UL, 0x403735a73d1f9923UL
        M 0x20200088UL, 0xe533f6430d71c8e0UL
        M 0x20200090UL, 0x44b7ef486176c2e0UL
        M 0x20200098UL, 0x347f933a8b32a7beUL ]
    given0
    |> run m16 [ "6432" ]
    |> is [ G 16, 0xe533f643UL; G 17, 0xd71c8e0UL; G 29, 0x20200090UL ]
    let given1 =
      [ G 16, 0x7fffffffUL
        G 17, 0x1UL
        G 29, 0x20200080UL
        M 0x20200060UL, 0x71bdde44336e78b4UL
        M 0x20200068UL, 0x22c908328de8056cUL
        M 0x20200070UL, 0x5bb28184fe4428ceUL
        M 0x20200078UL, 0x9867ae5dade00f56UL
        M 0x20200080UL, 0xe569f8520b488d2cUL
        M 0x20200088UL, 0xfb52bfc27bba6386UL
        M 0x20200090UL, 0xcad601b5634a5866UL
        M 0x20200098UL, 0xc083f5d737a1479UL ]
    given1
    |> run m16 [ "6432" ]
    |> is [ G 16, 0xfb52bfc2UL; G 17, 0x7bba6386UL; G 29, 0x20200090UL ]
    let given2 =
      [ G 16, 0x89abcdefUL
        G 17, 0x12345678UL
        G 29, 0x20200080UL
        M 0x20200060UL, 0x1f8515e5030884dfUL
        M 0x20200068UL, 0x85ddf7b75e3075bbUL
        M 0x20200070UL, 0xa5c726847b70e56UL
        M 0x20200078UL, 0x262635083fbcf4e9UL
        M 0x20200080UL, 0xe416143271628b1dUL
        M 0x20200088UL, 0x978545b7e80b4deeUL
        M 0x20200090UL, 0xcd2812a253749b03UL
        M 0x20200098UL, 0x90e82824b77eaaf2UL ]
    given2
    |> run m16 [ "6432" ]
    |> is [ G 16, 0x978545b7UL; G 17, 0xe80b4deeUL; G 29, 0x20200090UL ]

  /// <summary>
  /// 64f2, save 0x10, ra, s0, s1, against QEMU's 24Kf: the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SAVE``() =
    let given0 =
      [ G 16, 0x3UL
        G 17, 0x5UL
        G 29, 0x20200080UL
        G 31, 0x400cacUL
        M 0x20200060UL, 0x1821defda759663fUL
        M 0x20200068UL, 0x55cbf6dfd7f0041fUL
        M 0x20200070UL, 0x5f83004441ff181UL
        M 0x20200078UL, 0xb32b5b22e3efc784UL
        M 0x20200080UL, 0xa82e76029722abc3UL
        M 0x20200088UL, 0x1769f0e7c552b040UL
        M 0x20200090UL, 0xe4cf8e6ed4c880fdUL
        M 0x20200098UL, 0xc470897437da1cdbUL ]
    let expected0 =
      [ G 29, 0x20200070UL
        M 0x20200070UL, 0x5f8300400000003UL
        M 0x20200078UL, 0x500400cacUL ]
    given0
    |> run m16 [ "64f2" ]
    |> is expected0
    let given1 =
      [ G 16, 0x1UL
        G 17, 0xfffffffeUL
        G 29, 0x20200080UL
        G 31, 0x400cacUL
        M 0x20200060UL, 0x1e8f79a072fda07UL
        M 0x20200068UL, 0xfca64d436d2a3688UL
        M 0x20200070UL, 0x4dbcb8b42240bf02UL
        M 0x20200078UL, 0x77d89a8415ce8184UL
        M 0x20200080UL, 0xe634aeb0dab4940UL
        M 0x20200088UL, 0x85801cced6962eb6UL
        M 0x20200090UL, 0x51253ceb3fe09436UL
        M 0x20200098UL, 0x8a7c514639cf6e09UL ]
    let expected1 =
      [ G 29, 0x20200070UL
        M 0x20200070UL, 0x4dbcb8b400000001UL
        M 0x20200078UL, 0xfffffffe00400cacUL ]
    given1
    |> run m16 [ "64f2" ]
    |> is expected1
    let given2 =
      [ G 16, 0x12345678UL
        G 17, 0xfedcba98UL
        G 29, 0x20200080UL
        G 31, 0x400cacUL
        M 0x20200060UL, 0xdfd512d76464ac89UL
        M 0x20200068UL, 0x6849ffa7f9177060UL
        M 0x20200070UL, 0x83a41a487312bb23UL
        M 0x20200078UL, 0x640def0e18214fdbUL
        M 0x20200080UL, 0x9a428d53199ad16eUL
        M 0x20200088UL, 0x78ddcba26e75f764UL
        M 0x20200090UL, 0xa40ec19311239c88UL
        M 0x20200098UL, 0x80cb072a0471d302UL ]
    let expected2 =
      [ G 29, 0x20200070UL
        M 0x20200070UL, 0x83a41a4812345678UL
        M 0x20200078UL, 0xfedcba9800400cacUL ]
    given2
    |> run m16 [ "64f2" ]
    |> is expected2

  /// <summary>
  /// c041, sb v0, 1(s0), against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SB``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0x14e7d61cab359221UL
        M 0x20200080UL, 0x34e9220a32dedf16UL
        M 0x20200088UL, 0xd1b1361efc52a0b5UL ]
    given0
    |> run m16 [ "c041" ]
    |> is [ M 0x20200080UL, 0x7e9220a32dedf16UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0xec5f190585e8cb2UL
        M 0x20200080UL, 0x5486248ad0e055ddUL
        M 0x20200088UL, 0xfcae0d2eeb611b22UL ]
    given1
    |> run m16 [ "c041" ]
    |> is [ M 0x20200080UL, 0xff86248ad0e055ddUL ]
    let given2 =
      [ G 2, 0x89abcdefUL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0x6d75574f932533baUL
        M 0x20200080UL, 0x7540fa53655a4a2UL
        M 0x20200088UL, 0x4cf5bb589bfa5353UL ]
    given2
    |> run m16 [ "c041" ]
    |> is [ M 0x20200080UL, 0xef540fa53655a4a2UL ]

  /// <summary>
  /// e821, sdbbp 0x1. Not run against QEMU, whose user mode aborts on the debug
  /// exception it raises; the manual enters the debug handler, which is this
  /// architecture's breakpoint. The lift raises Breakpoint and changes nothing.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SDBBP``() =
    []
    |> run m16 [ "e821" ]
    |> raises [ Breakpoint ] []

  /// <summary>
  /// ea91, seb v0, v0, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SEB``() =
    [ G 2, 0x7UL ]
    |> run m16 [ "ea91" ]
    |> is []
    [ G 2, 0x7fffffffUL ]
    |> run m16 [ "ea91" ]
    |> is [ G 2, 0xffffffffUL ]
    [ G 2, 0x89abcdefUL ]
    |> run m16 [ "ea91" ]
    |> is [ G 2, 0xffffffefUL ]

  /// <summary>
  /// eab1, seh v0, v0, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SEH``() =
    [ G 2, 0x7UL ]
    |> run m16 [ "eab1" ]
    |> is []
    [ G 2, 0x7fffffffUL ]
    |> run m16 [ "eab1" ]
    |> is [ G 2, 0xffffffffUL ]
    [ G 2, 0x89abcdefUL ]
    |> run m16 [ "eab1" ]
    |> is [ G 2, 0xffffcdefUL ]

  /// <summary>
  /// c841, sh v0, 2(s0), against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SH``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0x216f66f6e8889d03UL
        M 0x20200080UL, 0xfe0b07788aecacf5UL
        M 0x20200088UL, 0x77c25a5398f3c412UL ]
    given0
    |> run m16 [ "c841" ]
    |> is [ M 0x20200080UL, 0x707788aecacf5UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0xaf372c7e649512dbUL
        M 0x20200080UL, 0x268bb0d01d7a2ac1UL
        M 0x20200088UL, 0x32f1b9399d18ec5aUL ]
    given1
    |> run m16 [ "c841" ]
    |> is [ M 0x20200080UL, 0xffffb0d01d7a2ac1UL ]
    let given2 =
      [ G 2, 0x89abcdefUL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0xbcddd1f6b46dc79cUL
        M 0x20200080UL, 0xdda6241e554fec9eUL
        M 0x20200088UL, 0x8bf481b85ce3d60bUL ]
    given2
    |> run m16 [ "c841" ]
    |> is [ M 0x20200080UL, 0xcdef241e554fec9eUL ]

  /// <summary>
  /// 3260, sll v0, v1, 0x8, against QEMU's 24Kf: the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SLL``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16 [ "3260" ]
    |> is [ G 2, 0x300UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16 [ "3260" ]
    |> is [ G 2, 0x100UL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL ]
    |> run m16 [ "3260" ]
    |> is [ G 2, 0x34567800UL ]

  /// <summary>
  /// eb44, sllv v0, v0, v1, against QEMU's 24Kf: the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SLLV``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16 [ "eb44" ]
    |> is [ G 2, 0x38UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16 [ "eb44" ]
    |> is [ G 2, 0xfffffffeUL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL ]
    |> run m16 [ "eb44" ]
    |> is [ G 2, 0xef000000UL ]

  /// <summary>
  /// ea62, slt v0, v1, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SLT``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 24, 0x1234UL ]
    |> run m16 [ "ea62" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 24, 0x1234UL ]
    |> run m16 [ "ea62" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL; G 24, 0x1234UL ]
    |> run m16 [ "ea62" ]
    |> is [ G 24, 0x1UL ]
    [ G 2, 0x2UL; G 3, 0x3UL; G 24, 0x1234UL ]
    |> run m16 [ "ea62" ]
    |> is [ G 24, 0x1UL ]

  /// <summary>
  /// 5201, slti v0, 0x1, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SLTI``() =
    [ G 2, 0x7UL; G 24, 0x1234UL ]
    |> run m16 [ "5201" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 24, 0x1234UL ]
    |> run m16 [ "5201" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0x89abcdefUL; G 24, 0x1234UL ]
    |> run m16 [ "5201" ]
    |> is [ G 24, 0x1UL ]
    [ G 24, 0x1234UL ]
    |> run m16 [ "5201" ]
    |> is [ G 24, 0x1UL ]

  /// <summary>
  /// 5a01, sltiu v0, 0x1, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SLTIU``() =
    [ G 2, 0x7UL; G 24, 0x1234UL ]
    |> run m16 [ "5a01" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 24, 0x1234UL ]
    |> run m16 [ "5a01" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0x89abcdefUL; G 24, 0x1234UL ]
    |> run m16 [ "5a01" ]
    |> is [ G 24, 0x0UL ]
    [ G 24, 0x1234UL ]
    |> run m16 [ "5a01" ]
    |> is [ G 24, 0x1UL ]

  /// <summary>
  /// ea63, sltu v0, v1, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SLTU``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 24, 0x1234UL ]
    |> run m16 [ "ea63" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 24, 0x1234UL ]
    |> run m16 [ "ea63" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL; G 24, 0x1234UL ]
    |> run m16 [ "ea63" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0x2UL; G 3, 0x3UL; G 24, 0x1234UL ]
    |> run m16 [ "ea63" ]
    |> is [ G 24, 0x1UL ]

  /// <summary>
  /// 3263, sra v0, v1, 0x8, against QEMU's 24Kf: the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SRA``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 31, 0x400cacUL ]
    |> run m16 [ "3263" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 31, 0x400cacUL ]
    |> run m16 [ "3263" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL; G 31, 0x400cacUL ]
    |> run m16 [ "3263" ]
    |> is [ G 2, 0x123456UL ]

  /// <summary>
  /// eb47, srav v0, v0, v1, against QEMU's 24Kf: the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SRAV``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 31, 0x400cacUL ]
    |> run m16 [ "eb47" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 31, 0x400cacUL ]
    |> run m16 [ "eb47" ]
    |> is [ G 2, 0x3fffffffUL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL; G 31, 0x400cacUL ]
    |> run m16 [ "eb47" ]
    |> is [ G 2, 0xffffff89UL ]

  /// <summary>
  /// 3262, srl v0, v1, 0x8, against QEMU's 24Kf: the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SRL``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16 [ "3262" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16 [ "3262" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL ]
    |> run m16 [ "3262" ]
    |> is [ G 2, 0x123456UL ]

  /// <summary>
  /// eb46, srlv v0, v0, v1, against QEMU's 24Kf: the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SRLV``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16 [ "eb46" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16 [ "eb46" ]
    |> is [ G 2, 0x3fffffffUL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL ]
    |> run m16 [ "eb46" ]
    |> is [ G 2, 0x89UL ]

  /// <summary>
  /// e273, subu a0, v0, v1, against QEMU's 24Kf: the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SUBU``() =
    [ G 2, 0x3UL; G 3, 0x5UL; G 4, 0x7UL ]
    |> run m16 [ "e273" ]
    |> is [ G 4, 0xfffffffeUL ]
    [ G 2, 0x1UL; G 3, 0xfffffffeUL; G 4, 0x7fffffffUL ]
    |> run m16 [ "e273" ]
    |> is [ G 4, 0x3UL ]
    [ G 2, 0x12345678UL; G 3, 0xfedcba98UL; G 4, 0x89abcdefUL ]
    |> run m16 [ "e273" ]
    |> is [ G 4, 0x13579be0UL ]

  /// <summary>
  /// d201, sw v0, 4(sp), against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SW``() =
    let given0 =
      [ G 2, 0x7UL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0xb4e8bdaa9dc32870UL
        M 0x20200080UL, 0x5f23fd520873435aUL
        M 0x20200088UL, 0x2b8ee80903dded35UL ]
    given0
    |> run m16 [ "d201" ]
    |> is [ M 0x20200080UL, 0x70873435aUL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x2494d589b3562303UL
        M 0x20200080UL, 0xe9797ad618f4c157UL
        M 0x20200088UL, 0xfeb810f1ffe3bedaUL ]
    given1
    |> run m16 [ "d201" ]
    |> is [ M 0x20200080UL, 0x7fffffff18f4c157UL ]
    let given2 =
      [ G 2, 0x89abcdefUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x3ac98b7dc74c645eUL
        M 0x20200080UL, 0x93a6c7097e97ef69UL
        M 0x20200088UL, 0xb7db38bfc5bedec9UL ]
    given2
    |> run m16 [ "d201" ]
    |> is [ M 0x20200080UL, 0x89abcdef7e97ef69UL ]

  /// <summary>
  /// ea6e, xor v0, v0, v1, against QEMU's 24Kf: the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 XOR``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16 [ "ea6e" ]
    |> is [ G 2, 0x4UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16 [ "ea6e" ]
    |> is [ G 2, 0x7ffffffeUL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL ]
    |> run m16 [ "ea6e" ]
    |> is [ G 2, 0x9b9f9b97UL ]

  /// <summary>
  /// ea11, zeb v0, v0, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 ZEB``() =
    [ G 2, 0x7UL ]
    |> run m16 [ "ea11" ]
    |> is []
    [ G 2, 0x7fffffffUL ]
    |> run m16 [ "ea11" ]
    |> is [ G 2, 0xffUL ]
    [ G 2, 0x89abcdefUL ]
    |> run m16 [ "ea11" ]
    |> is [ G 2, 0xefUL ]

  /// <summary>
  /// ea31, zeh v0, v0, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 ZEH``() =
    [ G 2, 0x7UL ]
    |> run m16 [ "ea31" ]
    |> is []
    [ G 2, 0x7fffffffUL ]
    |> run m16 [ "ea31" ]
    |> is [ G 2, 0xffffUL ]
    [ G 2, 0x89abcdefUL ]
    |> run m16 [ "ea31" ]
    |> is [ G 2, 0xcdefUL ]

  /// <summary>
  /// 4261, addiu v1, v0, 0x1, against QEMU's 24Kf: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 ADDIU``() =
    [ G 2, 0x3UL; G 3, 0x7UL ]
    |> run m16x64 [ "4261" ]
    |> is [ G 3, 0x4UL ]
    [ G 2, 0x1UL; G 3, 0x7fffffffUL ]
    |> run m16x64 [ "4261" ]
    |> is [ G 3, 0x2UL ]
    [ G 2, 0x12345678UL; G 3, 0xffffffff89abcdefUL ]
    |> run m16x64 [ "4261" ]
    |> is [ G 3, 0x12345679UL ]

  /// <summary>
  /// e271, addu a0, v0, v1, against QEMU's 24Kf: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 ADDU``() =
    [ G 2, 0x3UL; G 3, 0x5UL; G 4, 0x7UL ]
    |> run m16x64 [ "e271" ]
    |> is [ G 4, 0x8UL ]
    [ G 2, 0x1UL; G 3, 0xfffffffffffffffeUL; G 4, 0x7fffffffUL ]
    |> run m16x64 [ "e271" ]
    |> is [ G 4, 0xffffffffffffffffUL ]
    [ G 2, 0x12345678UL; G 3, 0xfffffffffedcba98UL; G 4, 0xffffffff89abcdefUL ]
    |> run m16x64 [ "e271" ]
    |> is [ G 4, 0x11111110UL ]

  /// <summary>
  /// ea6c, and v0, v0, v1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 AND``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "ea6c" ]
    |> is [ G 2, 0x3UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "ea6c" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run m16x64 [ "ea6c" ]
    |> is [ G 2, 0x204468UL ]

  /// <summary>
  /// f000e001, asmacro 0x1, against QEMU's 24Kf: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGILL (UndefinedInstruction here); the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 ASMACRO``() =
    []
    |> run m16x64 [ "f000e001" ]
    |> raises [ UndefinedInstruction ] []
    []
    |> run m16x64 [ "f000e001" ]
    |> raises [ UndefinedInstruction ] []
    []
    |> run m16x64 [ "f000e001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 1010, b 0x20100022 (binutils: b 20100022). A branch is not run against
  /// QEMU: it moves the PC, and its delay slot makes one word meaningless to
  /// run alone. Checked structurally from the manual: the transfer is the
  /// branch's own, there being no delay slot; control goes to 0x20100022 (the
  /// target binutils reads) when it always does.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 B``() =
    let words = [ "1010" ]
    ownsJump m16x64 "1010" true
    goes m16x64 words [] 0x20100022UL

  /// <summary>
  /// 2210, beqz v0, 0x20100022 (binutils: beqz $2,20100022). A branch is not
  /// run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100022 (the target binutils reads) when it always does; to 0x20100002,
  /// past the branch, when G 2 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 BEQZ``() =
    let words = [ "2210" ]
    ownsJump m16x64 "2210" true
    goes m16x64 words [] 0x20100022UL
    goes m16x64 words [ G 2, 0x5UL ] 0x20100002UL

  /// <summary>
  /// 2a10, bnez v0, 0x20100022 (binutils: bnez $2,20100022). A branch is not
  /// run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100022 (the target binutils reads) when G 2 is 0x5; to 0x20100002,
  /// past the branch, when nothing is given.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 BNEZ``() =
    let words = [ "2a10" ]
    ownsJump m16x64 "2a10" true
    goes m16x64 words [ G 2, 0x5UL ] 0x20100022UL
    goes m16x64 words [] 0x20100002UL

  /// <summary>
  /// e825, break 0x1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGTRAP (Breakpoint here); the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 BREAK``() =
    []
    |> run m16x64 [ "e825" ]
    |> raises [ Breakpoint ] []
    []
    |> run m16x64 [ "e825" ]
    |> raises [ Breakpoint ] []
    []
    |> run m16x64 [ "e825" ]
    |> raises [ Breakpoint ] []

  /// <summary>
  /// 6010, bteqz 0x20100022 (binutils: bteqz 20100022). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100022 (the target binutils reads) when it always does; to 0x20100002,
  /// past the branch, when G 24 is 0x1.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 BTEQZ``() =
    let words = [ "6010" ]
    ownsJump m16x64 "6010" true
    goes m16x64 words [] 0x20100022UL
    goes m16x64 words [ G 24, 0x1UL ] 0x20100002UL

  /// <summary>
  /// 6110, btnez 0x20100022 (binutils: btnez 20100022). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100022 (the target binutils reads) when G 24 is 0x1; to 0x20100002,
  /// past the branch, when nothing is given.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 BTNEZ``() =
    let words = [ "6110" ]
    ownsJump m16x64 "6110" true
    goes m16x64 words [ G 24, 0x1UL ] 0x20100022UL
    goes m16x64 words [] 0x20100002UL

  /// <summary>
  /// ea6a, cmp v0, v1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 CMP``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 24, 0x1234UL ]
    |> run m16x64 [ "ea6a" ]
    |> is [ G 24, 0x4UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 24, 0x1234UL ]
    |> run m16x64 [ "ea6a" ]
    |> is [ G 24, 0x7ffffffeUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 24, 0x1234UL ]
    |> run m16x64 [ "ea6a" ]
    |> is [ G 24, 0xffffffff9b9f9b97UL ]

  /// <summary>
  /// 7201, cmpi v0, 0x1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 CMPI``() =
    [ G 2, 0x7UL; G 24, 0x1234UL ]
    |> run m16x64 [ "7201" ]
    |> is [ G 24, 0x6UL ]
    [ G 2, 0x7fffffffUL; G 24, 0x1234UL ]
    |> run m16x64 [ "7201" ]
    |> is [ G 24, 0x7ffffffeUL ]
    [ G 2, 0xffffffff89abcdefUL; G 24, 0x1234UL ]
    |> run m16x64 [ "7201" ]
    |> is [ G 24, 0xffffffff89abcdeeUL ]

  /// <summary>
  /// 4271, daddiu v1, v0, 0x1, against QEMU's MIPS64R2-generic: QEMU runs
  /// MIPS16e only on a 32-bit processor, so the values are what it left after
  /// daddiu $3,$2,1, the MIPS64 instruction binutils reads this word as. the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 DADDIU``() =
    [ G 2, 0x3UL; G 3, 0x7UL ]
    |> run m16x64 [ "4271" ]
    |> is [ G 3, 0x4UL ]
    [ G 2, 0x1UL; G 3, 0x7fffffffffffffffUL ]
    |> run m16x64 [ "4271" ]
    |> is [ G 3, 0x2UL ]
    [ G 2, 0xfedcba9876543210UL; G 3, 0x123456789abcdefUL ]
    |> run m16x64 [ "4271" ]
    |> is [ G 3, 0xfedcba9876543211UL ]

  /// <summary>
  /// e270, daddu a0, v0, v1, against QEMU's MIPS64R2-generic: QEMU runs MIPS16e
  /// only on a 32-bit processor, so the values are what it left after daddu
  /// $4,$2,$3, the MIPS64 instruction binutils reads this word as. the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 DADDU``() =
    [ G 2, 0x3UL; G 3, 0x5UL; G 4, 0x7UL ]
    |> run m16x64 [ "e270" ]
    |> is [ G 4, 0x8UL ]
    [ G 2, 0x1UL; G 3, 0xfffffffffffffffeUL; G 4, 0x7fffffffffffffffUL ]
    |> run m16x64 [ "e270" ]
    |> is [ G 4, 0xffffffffffffffffUL ]
    [ G 2, 0xfedcba9876543210UL; G 3, 0xffffffffUL; G 4, 0x123456789abcdefUL ]
    |> run m16x64 [ "e270" ]
    |> is [ G 4, 0xfedcba997654320fUL ]

  /// <summary>
  /// ea7e, ddiv v0, v1, against QEMU's MIPS64R2-generic: QEMU runs MIPS16e only
  /// on a 32-bit processor, so the values are what it left after ddiv $0,$2,$3,
  /// the MIPS64 instruction binutils reads this word as. the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 DDIV``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "ea7e" ]
    |> is [ Hi, 0x1UL; Lo, 0x2UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "ea7e" ]
    |> is [ Lo, 0x7fffffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run m16x64 [ "ea7e" ]
    |> is [ Hi, 0x123456789abcdefUL ]

  /// <summary>
  /// ea7f, ddivu v0, v1, against QEMU's MIPS64R2-generic: QEMU runs MIPS16e
  /// only on a 32-bit processor, so the values are what it left after ddivu
  /// $0,$2,$3, the MIPS64 instruction binutils reads this word as. the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 DDIVU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "ea7f" ]
    |> is [ Hi, 0x1UL; Lo, 0x2UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "ea7f" ]
    |> is [ Lo, 0x7fffffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run m16x64 [ "ea7f" ]
    |> is [ Hi, 0x123456789abcdefUL ]

  /// <summary>
  /// ea7a, div v0, v1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 DIV``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "ea7a" ]
    |> is [ Hi, 0x1UL; Lo, 0x2UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "ea7a" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run m16x64 [ "ea7a" ]
    |> is [ Hi, 0xfffffffff6e5d4bfUL; Lo, 0xfffffffffffffffaUL ]

  /// <summary>
  /// ea7b, divu v0, v1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 DIVU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "ea7b" ]
    |> is [ Hi, 0x1UL; Lo, 0x2UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "ea7b" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run m16x64 [ "ea7b" ]
    |> is [ Hi, 0xa3d70a7UL; Lo, 0x7UL ]

  /// <summary>
  /// ea7c, dmult v0, v1, against QEMU's MIPS64R2-generic: QEMU runs MIPS16e
  /// only on a 32-bit processor, so the values are what it left after dmult
  /// $2,$3, the MIPS64 instruction binutils reads this word as. the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 DMULT``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "ea7c" ]
    |> is [ Lo, 0x15UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "ea7c" ]
    |> is [ Lo, 0x7fffffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run m16x64 [ "ea7c" ]
    |> is [ Hi, 0xfffeb49923cc0953UL; Lo, 0x2236d88fe5618cf0UL ]

  /// <summary>
  /// ea7d, dmultu v0, v1, against QEMU's MIPS64R2-generic: QEMU runs MIPS16e
  /// only on a 32-bit processor, so the values are what it left after dmultu
  /// $2,$3, the MIPS64 instruction binutils reads this word as. the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 DMULTU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "ea7d" ]
    |> is [ Lo, 0x15UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "ea7d" ]
    |> is [ Lo, 0x7fffffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run m16x64 [ "ea7d" ]
    |> is [ Hi, 0x121fa00ad77d742UL; Lo, 0x2236d88fe5618cf0UL ]

  /// <summary>
  /// 3261, dsll v0, v1, 0x8, against QEMU's MIPS64R2-generic: QEMU runs MIPS16e
  /// only on a 32-bit processor, so the values are what it left after dsll
  /// $2,$3,8, the MIPS64 instruction binutils reads this word as. the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 DSLL``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "3261" ]
    |> is [ G 2, 0x300UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "3261" ]
    |> is [ G 2, 0x100UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run m16x64 [ "3261" ]
    |> is [ G 2, 0xdcba987654321000UL ]

  /// <summary>
  /// eb54, dsllv v0, v0, v1, against QEMU's MIPS64R2-generic: QEMU runs MIPS16e
  /// only on a 32-bit processor, so the values are what it left after dsllv
  /// $2,$2,$3, the MIPS64 instruction binutils reads this word as. the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 DSLLV``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "eb54" ]
    |> is [ G 2, 0x38UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "eb54" ]
    |> is [ G 2, 0xfffffffffffffffeUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run m16x64 [ "eb54" ]
    |> is [ G 2, 0x456789abcdef0000UL ]

  /// <summary>
  /// e853, dsra v0, v0, 0x8, against QEMU's MIPS64R2-generic: QEMU runs MIPS16e
  /// only on a 32-bit processor, so the values are what it left after dsra
  /// $2,8, the MIPS64 instruction binutils reads this word as. the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 DSRA``() =
    [ G 2, 0x7UL ]
    |> run m16x64 [ "e853" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffffffffffUL ]
    |> run m16x64 [ "e853" ]
    |> is [ G 2, 0x7fffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL ]
    |> run m16x64 [ "e853" ]
    |> is [ G 2, 0x123456789abcdUL ]

  /// <summary>
  /// eb57, dsrav v0, v0, v1, against QEMU's MIPS64R2-generic: QEMU runs MIPS16e
  /// only on a 32-bit processor, so the values are what it left after dsrav
  /// $2,$2,$3, the MIPS64 instruction binutils reads this word as. the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 DSRAV``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "eb57" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "eb57" ]
    |> is [ G 2, 0x3fffffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run m16x64 [ "eb57" ]
    |> is [ G 2, 0x123456789abUL ]

  /// <summary>
  /// e848, dsrl v0, v0, 0x8, against QEMU's MIPS64R2-generic: QEMU runs MIPS16e
  /// only on a 32-bit processor, so the values are what it left after dsrl
  /// $2,8, the MIPS64 instruction binutils reads this word as. the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 DSRL``() =
    [ G 2, 0x7UL ]
    |> run m16x64 [ "e848" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffffffffffUL ]
    |> run m16x64 [ "e848" ]
    |> is [ G 2, 0x7fffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL ]
    |> run m16x64 [ "e848" ]
    |> is [ G 2, 0x123456789abcdUL ]

  /// <summary>
  /// eb56, dsrlv v0, v0, v1, against QEMU's MIPS64R2-generic: QEMU runs MIPS16e
  /// only on a 32-bit processor, so the values are what it left after dsrlv
  /// $2,$2,$3, the MIPS64 instruction binutils reads this word as. the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 DSRLV``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "eb56" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "eb56" ]
    |> is [ G 2, 0x3fffffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run m16x64 [ "eb56" ]
    |> is [ G 2, 0x123456789abUL ]

  /// <summary>
  /// e272, dsubu a0, v0, v1, against QEMU's MIPS64R2-generic: QEMU runs MIPS16e
  /// only on a 32-bit processor, so the values are what it left after dsubu
  /// $4,$2,$3, the MIPS64 instruction binutils reads this word as. the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 DSUBU``() =
    [ G 2, 0x3UL; G 3, 0x5UL; G 4, 0x7UL ]
    |> run m16x64 [ "e272" ]
    |> is [ G 4, 0xfffffffffffffffeUL ]
    [ G 2, 0x1UL; G 3, 0xfffffffffffffffeUL; G 4, 0x7fffffffffffffffUL ]
    |> run m16x64 [ "e272" ]
    |> is [ G 4, 0x3UL ]
    [ G 2, 0xfedcba9876543210UL; G 3, 0xffffffffUL; G 4, 0x123456789abcdefUL ]
    |> run m16x64 [ "e272" ]
    |> is [ G 4, 0xfedcba9776543211UL ]

  /// <summary>
  /// 18000100, jal 0x20000400 (binutils: jal 20000400). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20000400 (the target binutils reads) when it always does; ra becomes
  /// 0x20100007 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 JAL``() =
    let words = [ "18000100"; "6500" ]
    ownsJump m16x64 "18000100" false
    goes m16x64 words [] 0x20000400UL
    []
    |> run m16x64 words
    |> is [ G 31, 0x20100007UL ]

  /// <summary>
  /// ea40, jalr ra, v0 (binutils: jalr $2). A branch is not run against QEMU:
  /// it moves the PC, and its delay slot makes one word meaningless to run
  /// alone. Checked structurally from the manual: the transfer is left to the
  /// delay slot, which holds a NOP; control goes to 0x20100400 when G 2 is
  /// 0x20100401; the jump goes on in MIPS16; ra becomes 0x20100005 and nothing
  /// else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 JALR``() =
    let words = [ "ea40"; "6500" ]
    ownsJump m16x64 "ea40" false
    goes m16x64 words [ G 2, 0x20100401UL ] 0x20100400UL
    switches m16x64 words [ G 2, 0x20100401UL ] InterJmpKind.SwitchToMIPS16
    [ G 2, 0x20100401UL ]
    |> run m16x64 words
    |> is [ G 31, 0x20100005UL ]

  /// <summary>
  /// eac0, jalrc ra, v0 (binutils: jalrc $2). A branch is not run against QEMU:
  /// it moves the PC, and its delay slot makes one word meaningless to run
  /// alone. Checked structurally from the manual: the transfer is the branch's
  /// own, there being no delay slot; control goes to 0x20100400 when G 2 is
  /// 0x20100401; the jump goes on in MIPS16; ra becomes 0x20100003 and nothing
  /// else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 JALRC``() =
    let words = [ "eac0" ]
    ownsJump m16x64 "eac0" true
    goes m16x64 words [ G 2, 0x20100401UL ] 0x20100400UL
    switches m16x64 words [ G 2, 0x20100401UL ] InterJmpKind.SwitchToMIPS16
    [ G 2, 0x20100401UL ]
    |> run m16x64 words
    |> is [ G 31, 0x20100003UL ]

  /// <summary>
  /// 1c000100, jalx 0x20000400 (binutils: jalx 20000400). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20000400 (the target binutils reads) when it always does; the jump goes
  /// on in MIPS; ra becomes 0x20100007 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 JALX``() =
    let words = [ "1c000100"; "6500" ]
    ownsJump m16x64 "1c000100" false
    goes m16x64 words [] 0x20000400UL
    switches m16x64 words [] InterJmpKind.SwitchToMIPS
    []
    |> run m16x64 words
    |> is [ G 31, 0x20100007UL ]

  /// <summary>
  /// ea00, jr v0 (binutils: jr $2). A branch is not run against QEMU: it moves
  /// the PC, and its delay slot makes one word meaningless to run alone.
  /// Checked structurally from the manual: the transfer is left to the delay
  /// slot, which holds a NOP; control goes to 0x20100400 when G 2 is
  /// 0x20100401; the jump goes on in MIPS16.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 JR``() =
    let words = [ "ea00"; "6500" ]
    ownsJump m16x64 "ea00" false
    goes m16x64 words [ G 2, 0x20100401UL ] 0x20100400UL
    switches m16x64 words [ G 2, 0x20100401UL ] InterJmpKind.SwitchToMIPS16

  /// <summary>
  /// ea80, jrc v0 (binutils: jrc $2). A branch is not run against QEMU: it
  /// moves the PC, and its delay slot makes one word meaningless to run alone.
  /// Checked structurally from the manual: the transfer is the branch's own,
  /// there being no delay slot; control goes to 0x20100400 when G 2 is
  /// 0x20100401; the jump goes on in MIPS16.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 JRC``() =
    let words = [ "ea80" ]
    ownsJump m16x64 "ea80" true
    goes m16x64 words [ G 2, 0x20100401UL ] 0x20100400UL
    switches m16x64 words [ G 2, 0x20100401UL ] InterJmpKind.SwitchToMIPS16

  /// <summary>
  /// 8041, lb v0, 1(s0), against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 LB``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0x60731e1249e481a1UL
        M 0x20200080UL, 0x2a7c89eb2f8fd28bUL
        M 0x20200088UL, 0x733109c42f3394cUL ]
    given0
    |> run m16x64 [ "8041" ]
    |> is [ G 2, 0x2aUL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0x5592c7b26ab880beUL
        M 0x20200080UL, 0xd250d5e84b89ab63UL
        M 0x20200088UL, 0x92490cccd873b364UL ]
    given1
    |> run m16x64 [ "8041" ]
    |> is [ G 2, 0xffffffffffffffd2UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0x1f1bdc1e3c7e7630UL
        M 0x20200080UL, 0x19eb9e4f53b87ddeUL
        M 0x20200088UL, 0x2b99dec7cd501c7dUL ]
    given2
    |> run m16x64 [ "8041" ]
    |> is [ G 2, 0x19UL ]

  /// <summary>
  /// a041, lbu v0, 1(s0), against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 LBU``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0x747a478c2285e948UL
        M 0x20200080UL, 0xd223da4bc5f3b1abUL
        M 0x20200088UL, 0x80dfb78762b42c41UL ]
    given0
    |> run m16x64 [ "a041" ]
    |> is [ G 2, 0xd2UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0xc96e378611d35ae8UL
        M 0x20200080UL, 0x3783bea2bc5d1808UL
        M 0x20200088UL, 0x677170823009decbUL ]
    given1
    |> run m16x64 [ "a041" ]
    |> is [ G 2, 0x37UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0x40f542d168f3aeacUL
        M 0x20200080UL, 0x32da52298c14894dUL
        M 0x20200088UL, 0xb1d7fc1242d6ad2bUL ]
    given2
    |> run m16x64 [ "a041" ]
    |> is [ G 2, 0x32UL ]

  /// <summary>
  /// 3841, ld v0, 8(s0), against QEMU's MIPS64R2-generic: QEMU runs MIPS16e
  /// only on a 32-bit processor, so the values are what it left after ld
  /// $2,8($16), the MIPS64 instruction binutils reads this word as. the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 LD``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x20200078UL
        M 0x20200078UL, 0x2b7df8fa90c21e64UL
        M 0x20200080UL, 0x9006ce5919877c2cUL
        M 0x20200088UL, 0xe274e8dbd5e38a79UL ]
    given0
    |> run m16x64 [ "3841" ]
    |> is [ G 2, 0x9006ce5919877c2cUL ]
    let given1 =
      [ G 2, 0x7fffffffffffffffUL
        G 16, 0x20200078UL
        M 0x20200078UL, 0x3f5af6179ccddb0fUL
        M 0x20200080UL, 0x4d4fc664766c85d1UL
        M 0x20200088UL, 0x2dd28fc05a162a99UL ]
    given1
    |> run m16x64 [ "3841" ]
    |> is [ G 2, 0x4d4fc664766c85d1UL ]
    let given2 =
      [ G 2, 0x123456789abcdefUL
        G 16, 0x20200078UL
        M 0x20200078UL, 0xb3399766106b1a55UL
        M 0x20200080UL, 0x2af7a483c1331fbeUL
        M 0x20200088UL, 0x16f752af7905faeeUL ]
    given2
    |> run m16x64 [ "3841" ]
    |> is [ G 2, 0x2af7a483c1331fbeUL ]

  /// <summary>
  /// 8841, lh v0, 2(s0), against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 LH``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0xcf5f9772b55750deUL
        M 0x20200080UL, 0xf3d797e502a537d2UL
        M 0x20200088UL, 0xb498530b9994abb9UL ]
    given0
    |> run m16x64 [ "8841" ]
    |> is [ G 2, 0xfffffffffffff3d7UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0xefa2e57b1d9b114bUL
        M 0x20200080UL, 0x383fc11eea0d8fe0UL
        M 0x20200088UL, 0x63f893bb031eafdUL ]
    given1
    |> run m16x64 [ "8841" ]
    |> is [ G 2, 0x383fUL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0x5ed96a3731248d7bUL
        M 0x20200080UL, 0xc3f384b76c1a405dUL
        M 0x20200088UL, 0xd62170492578efebUL ]
    given2
    |> run m16x64 [ "8841" ]
    |> is [ G 2, 0xffffffffffffc3f3UL ]

  /// <summary>
  /// a841, lhu v0, 2(s0), against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 LHU``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0xd21229b252e9e73bUL
        M 0x20200080UL, 0xfa95031214736ee3UL
        M 0x20200088UL, 0xf9644c3a3aa90ba4UL ]
    given0
    |> run m16x64 [ "a841" ]
    |> is [ G 2, 0xfa95UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0x7647e9edce01c894UL
        M 0x20200080UL, 0xfed9ee3f84156ceaUL
        M 0x20200088UL, 0x7c0585680e33d31fUL ]
    given1
    |> run m16x64 [ "a841" ]
    |> is [ G 2, 0xfed9UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0x87ee2fb0c77525b5UL
        M 0x20200080UL, 0x6830a279e8d3a1a9UL
        M 0x20200088UL, 0x341e7007cabc94ebUL ]
    given2
    |> run m16x64 [ "a841" ]
    |> is [ G 2, 0x6830UL ]

  /// <summary>
  /// 6a01, li v0, 0x1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 LI``() =
    [ G 2, 0x7UL ]
    |> run m16x64 [ "6a01" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0x7fffffffUL ]
    |> run m16x64 [ "6a01" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run m16x64 [ "6a01" ]
    |> is [ G 2, 0x1UL ]

  /// <summary>
  /// 9201, lw v0, 4(sp), against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 LW``() =
    let given0 =
      [ G 2, 0x7UL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0xde67efea1b9ff1f6UL
        M 0x20200080UL, 0x8890a4f8fbdfeabcUL
        M 0x20200088UL, 0x27efcb9723250e39UL ]
    given0
    |> run m16x64 [ "9201" ]
    |> is [ G 2, 0xffffffff8890a4f8UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x13caa252adcd3891UL
        M 0x20200080UL, 0x7096319bf85dc4f1UL
        M 0x20200088UL, 0x8ffb0b43bbed2fb1UL ]
    given1
    |> run m16x64 [ "9201" ]
    |> is [ G 2, 0x7096319bUL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0xb4911b65967757a1UL
        M 0x20200080UL, 0x81258ad75f22ed4cUL
        M 0x20200088UL, 0x9e1f340ee0dae260UL ]
    given2
    |> run m16x64 [ "9201" ]
    |> is [ G 2, 0xffffffff81258ad7UL ]

  /// <summary>
  /// b841, lwu v0, 4(s0), against QEMU's MIPS64R2-generic: QEMU runs MIPS16e
  /// only on a 32-bit processor, so the values are what it left after lwu
  /// $2,4($16), the MIPS64 instruction binutils reads this word as. the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 LWU``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007cUL
        M 0x20200078UL, 0x853e28e781a4dd39UL
        M 0x20200080UL, 0x8ca324a8fc5ea486UL
        M 0x20200088UL, 0xa310e31aa64fc94eUL ]
    given0
    |> run m16x64 [ "b841" ]
    |> is [ G 2, 0x8ca324a8UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007cUL
        M 0x20200078UL, 0x7294ded984baa8c2UL
        M 0x20200080UL, 0xb64bdaf3269ebe04UL
        M 0x20200088UL, 0xcca7b29e4844a476UL ]
    given1
    |> run m16x64 [ "b841" ]
    |> is [ G 2, 0xb64bdaf3UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 16, 0x2020007cUL
        M 0x20200078UL, 0x76b797e57cc60e5cUL
        M 0x20200080UL, 0xe71d444e4e06bec5UL
        M 0x20200088UL, 0xa245977baf8e6514UL ]
    given2
    |> run m16x64 [ "b841" ]
    |> is [ G 2, 0xe71d444eUL ]

  /// <summary>
  /// ea10, mfhi v0, against QEMU's 24Kf: that processor is 32-bit, and a 64-bit
  /// one holds each word sign-extended, which is what the values here are. the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 MFHI``() =
    [ G 2, 0x7UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run m16x64 [ "ea10" ]
    |> is [ G 2, 0x13UL ]
    [ G 2, 0x7fffffffUL; Hi, 0x7fffffffUL; Lo, 0xffffffff80000001UL ]
    |> run m16x64 [ "ea10" ]
    |> is []
    [ G 2, 0xffffffff89abcdefUL; Hi, 0xffffffffdeadbeefUL; Lo, 0x12345678UL ]
    |> run m16x64 [ "ea10" ]
    |> is [ G 2, 0xffffffffdeadbeefUL ]

  /// <summary>
  /// ea12, mflo v0, against QEMU's 24Kf: that processor is 32-bit, and a 64-bit
  /// one holds each word sign-extended, which is what the values here are. the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 MFLO``() =
    [ G 2, 0x7UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run m16x64 [ "ea12" ]
    |> is [ G 2, 0x24UL ]
    [ G 2, 0x7fffffffUL; Hi, 0x7fffffffUL; Lo, 0xffffffff80000001UL ]
    |> run m16x64 [ "ea12" ]
    |> is [ G 2, 0xffffffff80000001UL ]
    [ G 2, 0xffffffff89abcdefUL; Hi, 0xffffffffdeadbeefUL; Lo, 0x12345678UL ]
    |> run m16x64 [ "ea12" ]
    |> is [ G 2, 0x12345678UL ]

  /// <summary>
  /// 6522, move at, v0, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 MOVE``() =
    [ G 1, 0x7UL; G 2, 0x3UL ]
    |> run m16x64 [ "6522" ]
    |> is [ G 1, 0x3UL ]
    [ G 1, 0x7fffffffUL; G 2, 0x1UL ]
    |> run m16x64 [ "6522" ]
    |> is [ G 1, 0x1UL ]
    [ G 1, 0xffffffff89abcdefUL; G 2, 0x12345678UL ]
    |> run m16x64 [ "6522" ]
    |> is [ G 1, 0x12345678UL ]

  /// <summary>
  /// ea78, mult v0, v1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 MULT``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "ea78" ]
    |> is [ Lo, 0x15UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "ea78" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run m16x64 [ "ea78" ]
    |> is [ Hi, 0xfffffffff795e368UL; Lo, 0xffffffffe242d208UL ]

  /// <summary>
  /// ea79, multu v0, v1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 MULTU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "ea79" ]
    |> is [ Lo, 0x15UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "ea79" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run m16x64 [ "ea79" ]
    |> is [ Hi, 0x9ca39e0UL; Lo, 0xffffffffe242d208UL ]

  /// <summary>
  /// ea6b, neg v0, v1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 NEG``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "ea6b" ]
    |> is [ G 2, 0xfffffffffffffffdUL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "ea6b" ]
    |> is [ G 2, 0xffffffffffffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run m16x64 [ "ea6b" ]
    |> is [ G 2, 0xffffffffedcba988UL ]

  /// <summary>
  /// 6500, nop, against QEMU's 24Kf: that processor is 32-bit, and a 64-bit one
  /// holds each word sign-extended, which is what the values here are. the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 NOP``() =
    []
    |> run m16x64 [ "6500" ]
    |> is []
    []
    |> run m16x64 [ "6500" ]
    |> is []
    []
    |> run m16x64 [ "6500" ]
    |> is []

  /// <summary>
  /// ea6f, not v0, v1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 NOT``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "ea6f" ]
    |> is [ G 2, 0xfffffffffffffffcUL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "ea6f" ]
    |> is [ G 2, 0xfffffffffffffffeUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run m16x64 [ "ea6f" ]
    |> is [ G 2, 0xffffffffedcba987UL ]

  /// <summary>
  /// ea6d, or v0, v0, v1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 OR``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "ea6d" ]
    |> is []
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "ea6d" ]
    |> is []
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run m16x64 [ "ea6d" ]
    |> is [ G 2, 0xffffffff9bbfdfffUL ]

  /// <summary>
  /// 6432, restore 0x10, s0, s1, against QEMU's 24Kf: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 RESTORE``() =
    let given0 =
      [ G 16, 0x7UL
        G 17, 0x3UL
        G 29, 0x20200080UL
        M 0x20200060UL, 0xc9970bd2e7d55c49UL
        M 0x20200068UL, 0x4792c53e95b6e541UL
        M 0x20200070UL, 0x2545c6776588e42bUL
        M 0x20200078UL, 0xaf459b845d732aaaUL
        M 0x20200080UL, 0xd050173007becea8UL
        M 0x20200088UL, 0x4bd40ec00c7a8ddfUL
        M 0x20200090UL, 0x303f3d0ced60f16bUL
        M 0x20200098UL, 0xf8400ec5b3b1448bUL ]
    given0
    |> run m16x64 [ "6432" ]
    |> is [ G 16, 0x4bd40ec0UL; G 17, 0xc7a8ddfUL; G 29, 0x20200090UL ]
    let given1 =
      [ G 16, 0x7fffffffUL
        G 17, 0x1UL
        G 29, 0x20200080UL
        M 0x20200060UL, 0xafe50180b8be1463UL
        M 0x20200068UL, 0xfdfc55ce81e64b89UL
        M 0x20200070UL, 0xde77d64cdd11d9dbUL
        M 0x20200078UL, 0xf51d2f68483d944aUL
        M 0x20200080UL, 0x9a03882af8216554UL
        M 0x20200088UL, 0x6f17b3691b04e42cUL
        M 0x20200090UL, 0x5430eb91c3931ec2UL
        M 0x20200098UL, 0x4a1a7fb11c2279fbUL ]
    given1
    |> run m16x64 [ "6432" ]
    |> is [ G 16, 0x6f17b369UL; G 17, 0x1b04e42cUL; G 29, 0x20200090UL ]
    let given2 =
      [ G 16, 0xffffffff89abcdefUL
        G 17, 0x12345678UL
        G 29, 0x20200080UL
        M 0x20200060UL, 0xad8eed7154a41520UL
        M 0x20200068UL, 0xa17bb6fc66de3e43UL
        M 0x20200070UL, 0x86379530cf8b418bUL
        M 0x20200078UL, 0xfa6860f30a86e34eUL
        M 0x20200080UL, 0xe02f48ad614999acUL
        M 0x20200088UL, 0x459d352abd871421UL
        M 0x20200090UL, 0xb2032ab5f01e80d0UL
        M 0x20200098UL, 0xea0fb5c3dced07cfUL ]
    given2
    |> run m16x64 [ "6432" ]
    |> is [ G 16, 0x459d352aUL; G 17, 0xffffffffbd871421UL; G 29, 0x20200090UL ]

  /// <summary>
  /// 64f2, save 0x10, ra, s0, s1, against QEMU's 24Kf: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SAVE``() =
    let given0 =
      [ G 16, 0x3UL
        G 17, 0x5UL
        G 29, 0x20200080UL
        G 31, 0x400cacUL
        M 0x20200060UL, 0xef1ec0d1422d6b49UL
        M 0x20200068UL, 0x39e4dcb381721e1dUL
        M 0x20200070UL, 0xefe8bf71a3ee8c7bUL
        M 0x20200078UL, 0xcca16b8fd5a8464fUL
        M 0x20200080UL, 0x9a80220e91a88248UL
        M 0x20200088UL, 0xb26b5763ad017956UL
        M 0x20200090UL, 0x24a38da9e59a5b97UL
        M 0x20200098UL, 0x4b5110f1f094c3dUL ]
    let expected0 =
      [ G 29, 0x20200070UL
        M 0x20200070UL, 0xefe8bf7100000003UL
        M 0x20200078UL, 0x500400cacUL ]
    given0
    |> run m16x64 [ "64f2" ]
    |> is expected0
    let given1 =
      [ G 16, 0x1UL
        G 17, 0xfffffffffffffffeUL
        G 29, 0x20200080UL
        G 31, 0x400cacUL
        M 0x20200060UL, 0xaebfb9f0c23b0c51UL
        M 0x20200068UL, 0x658dd38b673e14f1UL
        M 0x20200070UL, 0xc0809c450756040fUL
        M 0x20200078UL, 0x1bfa632989064770UL
        M 0x20200080UL, 0xdb8ae71b639c748eUL
        M 0x20200088UL, 0x968318fb40df6805UL
        M 0x20200090UL, 0x45be6cd634602388UL
        M 0x20200098UL, 0xcd5973ba1de8b843UL ]
    let expected1 =
      [ G 29, 0x20200070UL
        M 0x20200070UL, 0xc0809c4500000001UL
        M 0x20200078UL, 0xfffffffe00400cacUL ]
    given1
    |> run m16x64 [ "64f2" ]
    |> is expected1
    let given2 =
      [ G 16, 0x12345678UL
        G 17, 0xfffffffffedcba98UL
        G 29, 0x20200080UL
        G 31, 0x400cacUL
        M 0x20200060UL, 0xef9e59258f9311c3UL
        M 0x20200068UL, 0xc3d3a8b3848c478bUL
        M 0x20200070UL, 0x81c4cf8d8aad3abdUL
        M 0x20200078UL, 0xe2f4f8680a5c0c47UL
        M 0x20200080UL, 0xd3580aee866e3cb4UL
        M 0x20200088UL, 0x5eb2cece265a85fbUL
        M 0x20200090UL, 0x9703504eb04d437dUL
        M 0x20200098UL, 0xc21c09996dae4cebUL ]
    let expected2 =
      [ G 29, 0x20200070UL
        M 0x20200070UL, 0x81c4cf8d12345678UL
        M 0x20200078UL, 0xfedcba9800400cacUL ]
    given2
    |> run m16x64 [ "64f2" ]
    |> is expected2

  /// <summary>
  /// c041, sb v0, 1(s0), against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SB``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0xd86f09e52c4578a5UL
        M 0x20200080UL, 0xf88481a46b9034aaUL
        M 0x20200088UL, 0xbb0b588f897fe96cUL ]
    given0
    |> run m16x64 [ "c041" ]
    |> is [ M 0x20200080UL, 0x78481a46b9034aaUL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0xce1146d87760e1bUL
        M 0x20200080UL, 0x839980c866cd18c0UL
        M 0x20200088UL, 0xbc1393c4d338997bUL ]
    given1
    |> run m16x64 [ "c041" ]
    |> is [ M 0x20200080UL, 0xff9980c866cd18c0UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0x1f2b206b72d8784fUL
        M 0x20200080UL, 0x18353872b0516498UL
        M 0x20200088UL, 0x60d61987751c910aUL ]
    given2
    |> run m16x64 [ "c041" ]
    |> is [ M 0x20200080UL, 0xef353872b0516498UL ]

  /// <summary>
  /// 7841, sd v0, 8(s0), against QEMU's MIPS64R2-generic: QEMU runs MIPS16e
  /// only on a 32-bit processor, so the values are what it left after sd
  /// $2,8($16), the MIPS64 instruction binutils reads this word as. the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SD``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x20200078UL
        M 0x20200078UL, 0xca45620b379b4de2UL
        M 0x20200080UL, 0x7f613f626c5f9760UL
        M 0x20200088UL, 0xd95882a1e203e6f4UL ]
    given0
    |> run m16x64 [ "7841" ]
    |> is [ M 0x20200080UL, 0x7UL ]
    let given1 =
      [ G 2, 0x7fffffffffffffffUL
        G 16, 0x20200078UL
        M 0x20200078UL, 0xaa2b45c4ad98890cUL
        M 0x20200080UL, 0xb8aa98dc07c8d492UL
        M 0x20200088UL, 0x49a71229fdf46308UL ]
    given1
    |> run m16x64 [ "7841" ]
    |> is [ M 0x20200080UL, 0x7fffffffffffffffUL ]
    let given2 =
      [ G 2, 0x123456789abcdefUL
        G 16, 0x20200078UL
        M 0x20200078UL, 0x600c37e059b86d0cUL
        M 0x20200080UL, 0xc62523c5af394eedUL
        M 0x20200088UL, 0xb32a155389a67b90UL ]
    given2
    |> run m16x64 [ "7841" ]
    |> is [ M 0x20200080UL, 0x123456789abcdefUL ]

  /// <summary>
  /// e821, sdbbp 0x1. Not run against QEMU, whose user mode aborts on the debug
  /// exception it raises; the manual enters the debug handler, which is this
  /// architecture's breakpoint. The lift raises Breakpoint and changes nothing.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SDBBP``() =
    []
    |> run m16x64 [ "e821" ]
    |> raises [ Breakpoint ] []

  /// <summary>
  /// ea91, seb v0, v0, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SEB``() =
    [ G 2, 0x7UL ]
    |> run m16x64 [ "ea91" ]
    |> is []
    [ G 2, 0x7fffffffUL ]
    |> run m16x64 [ "ea91" ]
    |> is [ G 2, 0xffffffffffffffffUL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run m16x64 [ "ea91" ]
    |> is [ G 2, 0xffffffffffffffefUL ]

  /// <summary>
  /// eab1, seh v0, v0, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SEH``() =
    [ G 2, 0x7UL ]
    |> run m16x64 [ "eab1" ]
    |> is []
    [ G 2, 0x7fffffffUL ]
    |> run m16x64 [ "eab1" ]
    |> is [ G 2, 0xffffffffffffffffUL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run m16x64 [ "eab1" ]
    |> is [ G 2, 0xffffffffffffcdefUL ]

  /// <summary>
  /// ead1, sew v0, v0, against QEMU's MIPS64R2-generic: QEMU runs MIPS16e only
  /// on a 32-bit processor, so the values are what it left after sll $2,$2,0,
  /// the MIPS64 instruction binutils reads this word as. the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SEW``() =
    [ G 2, 0x7UL ]
    |> run m16x64 [ "ead1" ]
    |> is []
    [ G 2, 0x7fffffffffffffffUL ]
    |> run m16x64 [ "ead1" ]
    |> is [ G 2, 0xffffffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL ]
    |> run m16x64 [ "ead1" ]
    |> is [ G 2, 0xffffffff89abcdefUL ]

  /// <summary>
  /// c841, sh v0, 2(s0), against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SH``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0xc301b029a05ed52fUL
        M 0x20200080UL, 0x29afec30e561e916UL
        M 0x20200088UL, 0x79ef19f6d68e9a6cUL ]
    given0
    |> run m16x64 [ "c841" ]
    |> is [ M 0x20200080UL, 0x7ec30e561e916UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0x117984704c2f6470UL
        M 0x20200080UL, 0x6eff424adce40b27UL
        M 0x20200088UL, 0xebbd3287be9f6f0cUL ]
    given1
    |> run m16x64 [ "c841" ]
    |> is [ M 0x20200080UL, 0xffff424adce40b27UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0xa79bdaf709925048UL
        M 0x20200080UL, 0xd32dcfa9f0844bafUL
        M 0x20200088UL, 0xfd552f353bc712b3UL ]
    given2
    |> run m16x64 [ "c841" ]
    |> is [ M 0x20200080UL, 0xcdefcfa9f0844bafUL ]

  /// <summary>
  /// 3260, sll v0, v1, 0x8, against QEMU's 24Kf: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SLL``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "3260" ]
    |> is [ G 2, 0x300UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "3260" ]
    |> is [ G 2, 0x100UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run m16x64 [ "3260" ]
    |> is [ G 2, 0x34567800UL ]

  /// <summary>
  /// eb44, sllv v0, v0, v1, against QEMU's 24Kf: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SLLV``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "eb44" ]
    |> is [ G 2, 0x38UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "eb44" ]
    |> is [ G 2, 0xfffffffffffffffeUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run m16x64 [ "eb44" ]
    |> is [ G 2, 0xffffffffef000000UL ]

  /// <summary>
  /// ea62, slt v0, v1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SLT``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 24, 0x1234UL ]
    |> run m16x64 [ "ea62" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 24, 0x1234UL ]
    |> run m16x64 [ "ea62" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 24, 0x1234UL ]
    |> run m16x64 [ "ea62" ]
    |> is [ G 24, 0x1UL ]
    [ G 2, 0x2UL; G 3, 0x3UL; G 24, 0x1234UL ]
    |> run m16x64 [ "ea62" ]
    |> is [ G 24, 0x1UL ]

  /// <summary>
  /// 5201, slti v0, 0x1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SLTI``() =
    [ G 2, 0x7UL; G 24, 0x1234UL ]
    |> run m16x64 [ "5201" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 24, 0x1234UL ]
    |> run m16x64 [ "5201" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 24, 0x1234UL ]
    |> run m16x64 [ "5201" ]
    |> is [ G 24, 0x1UL ]
    [ G 24, 0x1234UL ]
    |> run m16x64 [ "5201" ]
    |> is [ G 24, 0x1UL ]

  /// <summary>
  /// 5a01, sltiu v0, 0x1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SLTIU``() =
    [ G 2, 0x7UL; G 24, 0x1234UL ]
    |> run m16x64 [ "5a01" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 24, 0x1234UL ]
    |> run m16x64 [ "5a01" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 24, 0x1234UL ]
    |> run m16x64 [ "5a01" ]
    |> is [ G 24, 0x0UL ]
    [ G 24, 0x1234UL ]
    |> run m16x64 [ "5a01" ]
    |> is [ G 24, 0x1UL ]

  /// <summary>
  /// ea63, sltu v0, v1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SLTU``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 24, 0x1234UL ]
    |> run m16x64 [ "ea63" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 24, 0x1234UL ]
    |> run m16x64 [ "ea63" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 24, 0x1234UL ]
    |> run m16x64 [ "ea63" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0x2UL; G 3, 0x3UL; G 24, 0x1234UL ]
    |> run m16x64 [ "ea63" ]
    |> is [ G 24, 0x1UL ]

  /// <summary>
  /// 3263, sra v0, v1, 0x8, against QEMU's 24Kf: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SRA``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 31, 0x400cacUL ]
    |> run m16x64 [ "3263" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 31, 0x400cacUL ]
    |> run m16x64 [ "3263" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 31, 0x400cacUL ]
    |> run m16x64 [ "3263" ]
    |> is [ G 2, 0x123456UL ]

  /// <summary>
  /// eb47, srav v0, v0, v1, against QEMU's 24Kf: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SRAV``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 31, 0x400cacUL ]
    |> run m16x64 [ "eb47" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 31, 0x400cacUL ]
    |> run m16x64 [ "eb47" ]
    |> is [ G 2, 0x3fffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 31, 0x400cacUL ]
    |> run m16x64 [ "eb47" ]
    |> is [ G 2, 0xffffffffffffff89UL ]

  /// <summary>
  /// 3262, srl v0, v1, 0x8, against QEMU's 24Kf: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SRL``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "3262" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "3262" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run m16x64 [ "3262" ]
    |> is [ G 2, 0x123456UL ]

  /// <summary>
  /// eb46, srlv v0, v0, v1, against QEMU's 24Kf: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SRLV``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "eb46" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "eb46" ]
    |> is [ G 2, 0x3fffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run m16x64 [ "eb46" ]
    |> is [ G 2, 0x89UL ]

  /// <summary>
  /// e273, subu a0, v0, v1, against QEMU's 24Kf: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SUBU``() =
    [ G 2, 0x3UL; G 3, 0x5UL; G 4, 0x7UL ]
    |> run m16x64 [ "e273" ]
    |> is [ G 4, 0xfffffffffffffffeUL ]
    [ G 2, 0x1UL; G 3, 0xfffffffffffffffeUL; G 4, 0x7fffffffUL ]
    |> run m16x64 [ "e273" ]
    |> is [ G 4, 0x3UL ]
    [ G 2, 0x12345678UL; G 3, 0xfffffffffedcba98UL; G 4, 0xffffffff89abcdefUL ]
    |> run m16x64 [ "e273" ]
    |> is [ G 4, 0x13579be0UL ]

  /// <summary>
  /// d201, sw v0, 4(sp), against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SW``() =
    let given0 =
      [ G 2, 0x7UL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x40c519308c7bb986UL
        M 0x20200080UL, 0xfaf65414c4d22066UL
        M 0x20200088UL, 0xa1714c4cab887d85UL ]
    given0
    |> run m16x64 [ "d201" ]
    |> is [ M 0x20200080UL, 0x7c4d22066UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0xd34515152f22ef99UL
        M 0x20200080UL, 0x4368fc06cbfc9602UL
        M 0x20200088UL, 0x355f5157a96e9e2bUL ]
    given1
    |> run m16x64 [ "d201" ]
    |> is [ M 0x20200080UL, 0x7fffffffcbfc9602UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0xb3e44261bf5033f1UL
        M 0x20200080UL, 0xc05c9bf1cbd94c50UL
        M 0x20200088UL, 0xb31352c25622d8a1UL ]
    given2
    |> run m16x64 [ "d201" ]
    |> is [ M 0x20200080UL, 0x89abcdefcbd94c50UL ]

  /// <summary>
  /// ea6e, xor v0, v0, v1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 XOR``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "ea6e" ]
    |> is [ G 2, 0x4UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "ea6e" ]
    |> is [ G 2, 0x7ffffffeUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run m16x64 [ "ea6e" ]
    |> is [ G 2, 0xffffffff9b9f9b97UL ]

  /// <summary>
  /// ea11, zeb v0, v0, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 ZEB``() =
    [ G 2, 0x7UL ]
    |> run m16x64 [ "ea11" ]
    |> is []
    [ G 2, 0x7fffffffUL ]
    |> run m16x64 [ "ea11" ]
    |> is [ G 2, 0xffUL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run m16x64 [ "ea11" ]
    |> is [ G 2, 0xefUL ]

  /// <summary>
  /// ea31, zeh v0, v0, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 ZEH``() =
    [ G 2, 0x7UL ]
    |> run m16x64 [ "ea31" ]
    |> is []
    [ G 2, 0x7fffffffUL ]
    |> run m16x64 [ "ea31" ]
    |> is [ G 2, 0xffffUL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run m16x64 [ "ea31" ]
    |> is [ G 2, 0xcdefUL ]

  /// <summary>
  /// ea51, zew v0, v0, against QEMU's MIPS64R2-generic: QEMU runs MIPS16e only
  /// on a 32-bit processor, so the values are what it left after dext
  /// $2,$2,0,32, the MIPS64 instruction binutils reads this word as. the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 ZEW``() =
    [ G 2, 0x7UL ]
    |> run m16x64 [ "ea51" ]
    |> is []
    [ G 2, 0x7fffffffffffffffUL ]
    |> run m16x64 [ "ea51" ]
    |> is [ G 2, 0xffffffffUL ]
    [ G 2, 0x123456789abcdefUL ]
    |> run m16x64 [ "ea51" ]
    |> is [ G 2, 0x89abcdefUL ]

  /// <summary>
  /// 5444037b, abs.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after abs.s $f2,$f4, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ABS.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run um [ "5444037b" ]
    |> is [ F 2, 0x40100000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL ]
    |> run um [ "5444037b" ]
    |> is [ F 2, 0x40c00000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL ]
    |> run um [ "5444037b" ]
    |> is [ F 2, 0x447a0000UL ]

  /// <summary>
  /// 01494110, add a4, a5, a6, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGFPE (Exception IntegerOverflow here); the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ADD``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "01494110" ]
    |> is [ G 8, 0x8UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "01494110" ]
    |> is [ G 8, 0xffffffffffffffffUL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "01494110" ]
    |> is [ G 8, 0x11111110UL ]
    [ G 8, 0x7UL; G 9, 0x7fffffffUL; G 10, 0x1UL ]
    |> run um [ "01494110" ]
    |> raises [ Exception IntegerOverflow ] []

  /// <summary>
  /// 54c41030, add.s f2, f4, f6, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after add.s $f2,$f4,$f6, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ADD.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; F 6, 0x3fc00000UL ]
    |> run um [ "54c41030" ]
    |> is [ F 2, 0x40700000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; F 6, 0x3f400000UL ]
    |> run um [ "54c41030" ]
    |> is [ F 2, 0xc0a80000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL ]
    |> run um [ "54c41030" ]
    |> is [ F 2, 0x447a0800UL ]

  /// <summary>
  /// 11090001, addi a4, a5, 0x1, against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. QEMU raised SIGFPE (Exception IntegerOverflow here); the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDI``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "11090001" ]
    |> is [ G 8, 0x4UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "11090001" ]
    |> is [ G 8, 0x2UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "11090001" ]
    |> is [ G 8, 0x12345679UL ]
    [ G 8, 0x7UL; G 9, 0x7fffffffUL ]
    |> run um [ "11090001" ]
    |> raises [ Exception IntegerOverflow ] []

  /// <summary>
  /// 31090001, addiu a4, a5, 0x1, against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDIU``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "31090001" ]
    |> is [ G 8, 0x4UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "31090001" ]
    |> is [ G 8, 0x2UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "31090001" ]
    |> is [ G 8, 0x12345679UL ]

  /// <summary>
  /// 79030000, addiupc v0, 0x201c0000, against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDIUPC``() =
    [ G 2, 0x7UL ]
    |> run um [ "79030000" ]
    |> is [ G 2, 0x201c0000UL ]
    [ G 2, 0x7fffffffUL ]
    |> run um [ "79030000" ]
    |> is [ G 2, 0x201c0000UL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run um [ "79030000" ]
    |> is [ G 2, 0x201c0000UL ]

  /// <summary>
  /// 6d03, addiu v0, sp, 0x4, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDIUR1SP``() =
    [ G 2, 0x7UL; G 29, 0x3UL ]
    |> run um [ "6d03" ]
    |> is []
    [ G 2, 0x7fffffffUL; G 29, 0x1UL ]
    |> run um [ "6d03" ]
    |> is [ G 2, 0x5UL ]
    [ G 2, 0xffffffff89abcdefUL; G 29, 0x12345678UL ]
    |> run um [ "6d03" ]
    |> is [ G 2, 0x1234567cUL ]

  /// <summary>
  /// 6d30, addiu v0, v1, 0x1, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDIUR2``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run um [ "6d30" ]
    |> is [ G 2, 0x4UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run um [ "6d30" ]
    |> is [ G 2, 0x2UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run um [ "6d30" ]
    |> is [ G 2, 0x12345679UL ]

  /// <summary>
  /// 4c22, addiu at, at, 0x1, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDIUS5``() =
    [ G 1, 0x7UL ]
    |> run um [ "4c22" ]
    |> is [ G 1, 0x8UL ]
    [ G 1, 0x7fffffffUL ]
    |> run um [ "4c22" ]
    |> is [ G 1, 0xffffffff80000000UL ]
    [ G 1, 0xffffffff89abcdefUL ]
    |> run um [ "4c22" ]
    |> is [ G 1, 0xffffffff89abcdf0UL ]

  /// <summary>
  /// 4c01, addiu sp, sp, 0x400, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDIUSP``() =
    [ G 29, 0x7UL ]
    |> run um [ "4c01" ]
    |> is [ G 29, 0x407UL ]
    [ G 29, 0x7fffffffUL ]
    |> run um [ "4c01" ]
    |> is [ G 29, 0xffffffff800003ffUL ]
    [ G 29, 0xffffffff89abcdefUL ]
    |> run um [ "4c01" ]
    |> is [ G 29, 0xffffffff89abd1efUL ]

  /// <summary>
  /// 01494150, addu a4, a5, a6, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDU``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "01494150" ]
    |> is [ G 8, 0x8UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "01494150" ]
    |> is [ G 8, 0xffffffffffffffffUL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "01494150" ]
    |> is [ G 8, 0x11111110UL ]

  /// <summary>
  /// 0538, addu v0, a0, v1, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDU16``() =
    [ G 2, 0x7UL; G 3, 0x5UL; G 4, 0x3UL ]
    |> run um [ "0538" ]
    |> is [ G 2, 0x8UL ]
    [ G 2, 0x7fffffffUL; G 3, 0xfffffffffffffffeUL; G 4, 0x1UL ]
    |> run um [ "0538" ]
    |> is [ G 2, 0xffffffffffffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0xfffffffffedcba98UL; G 4, 0x12345678UL ]
    |> run um [ "0538" ]
    |> is [ G 2, 0x11111110UL ]

  /// <summary>
  /// 54c41219, alnv.ps f2, f4, f6, a4, against QEMU's MIPS64R2-generic: QEMU
  /// has no microMIPS64 or microMIPS processor with an FPU, so the values are
  /// what it left after alnv.ps $f2,$f4,$f6,$8, the MIPS64 instruction binutils
  /// reads this word as. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ALNV.PS``() =
    let given0 =
      [ F 2, 0xbf8000003f800000UL
        F 4, 0x40100000bfc00000UL
        F 6, 0x3fc000003e800000UL ]
    given0
    |> run um [ "54c41219" ]
    |> is [ F 2, 0x40100000bfc00000UL ]
    let given1 =
      [ G 8, 0x4UL
        F 2, 0x40600000c0600000UL
        F 4, 0xc0c000003f000000UL
        F 6, 0x3f40000040000000UL ]
    given1
    |> run um [ "54c41219" ]
    |> is [ F 2, 0x3f0000003f400000UL ]
    let given2 =
      [ G 8, 0x4UL
        F 2, 0x3e8000003f400000UL
        F 4, 0x447a000040400000UL
        F 6, 0x3e000000c0800000UL ]
    given2
    |> run um [ "54c41219" ]
    |> is [ F 2, 0x404000003e000000UL ]

  /// <summary>
  /// 01494250, and a4, a5, a6, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 AND``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "01494250" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "01494250" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "01494250" ]
    |> is [ G 8, 0x12141218UL ]

  /// <summary>
  /// 4493, and v0, v0, v1, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 AND16``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run um [ "4493" ]
    |> is [ G 2, 0x3UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run um [ "4493" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run um [ "4493" ]
    |> is [ G 2, 0x204468UL ]

  /// <summary>
  /// d1090001, andi a4, a5, 0x1, against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ANDI``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "d1090001" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "d1090001" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "d1090001" ]
    |> is [ G 8, 0x0UL ]

  /// <summary>
  /// 2d30, andi v0, v1, 0x80, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ANDI16``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run um [ "2d30" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run um [ "2d30" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run um [ "2d30" ]
    |> is [ G 2, 0x0UL ]

  /// <summary>
  /// cc10, b 0x20100022 (binutils: b 20100022). A branch is not run against
  /// QEMU: it moves the PC, and its delay slot makes one word meaningless to
  /// run alone. Checked structurally from the manual: the transfer is left to
  /// the delay slot, which holds a NOP; control goes to 0x20100022 (the target
  /// binutils reads) when it always does.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 B``() =
    let words = [ "cc10"; "00000000" ]
    ownsJump um "cc10" false
    goes um words [] 0x20100022UL

  /// <summary>
  /// cc10, b 0x20100022 (binutils: b 20100022). A branch is not run against
  /// QEMU: it moves the PC, and its delay slot makes one word meaningless to
  /// run alone. Checked structurally from the manual: the transfer is left to
  /// the delay slot, which holds a NOP; control goes to 0x20100022 (the target
  /// binutils reads) when it always does.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 B16``() =
    let words = [ "cc10"; "00000000" ]
    ownsJump um "cc10" false
    goes um words [] 0x20100022UL

  /// <summary>
  /// 40600100, bgezal r0, 0x20100204 (binutils: bal 20100204). A branch is not
  /// run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100204 (the target binutils reads) when it always does; ra becomes
  /// 0x20100009 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BAL``() =
    let words = [ "40600100"; "00000000" ]
    ownsJump um "40600100" false
    goes um words [] 0x20100204UL
    []
    |> run um words
    |> is [ G 31, 0x20100009UL ]

  /// <summary>
  /// 43830100, bc1f 0x0, 0x20100204 (binutils: bc1f $fcc0,20100204). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100204 (the target binutils reads) when it always does; to 0x20100008,
  /// past the slot, when Fcsr is 0x800000.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BC1F``() =
    let words = [ "43830100"; "00000000" ]
    ownsJump um "43830100" false
    goes um words [] 0x20100204UL
    goes um words [ Fcsr, 0x800000UL ] 0x20100008UL

  /// <summary>
  /// 43a30100, bc1t 0x0, 0x20100204 (binutils: bc1t $fcc0,20100204). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100204 (the target binutils reads) when Fcsr is 0x800000; to
  /// 0x20100008, past the slot, when nothing is given.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BC1T``() =
    let words = [ "43a30100"; "00000000" ]
    ownsJump um "43a30100" false
    goes um words [ Fcsr, 0x800000UL ] 0x20100204UL
    goes um words [] 0x20100008UL

  /// <summary>
  /// 42830000, bc2f 0x0, 0x20100004. A branch is not run against QEMU; this
  /// processor has no coprocessor 2 (Config1.C2 is clear), and every
  /// instruction that reaches it takes Coprocessor Unusable, a branch on its
  /// condition before it branches. The lift raises UndefinedInstruction and
  /// changes nothing.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BC2F``() =
    []
    |> run um [ "42830000" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 42a30000, bc2t 0x0, 0x20100004. A branch is not run against QEMU; this
  /// processor has no coprocessor 2 (Config1.C2 is clear), and every
  /// instruction that reaches it takes Coprocessor Unusable, a branch on its
  /// condition before it branches. The lift raises UndefinedInstruction and
  /// changes nothing.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BC2T``() =
    []
    |> run um [ "42a30000" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 94230100, beq v1, at, 0x20100204 (binutils: beq $3,$1,20100204). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100204 (the target binutils reads) when G 3 is 0x5 and G 1 is 0x5; to
  /// 0x20100008, past the slot, when G 3 is 0x5 and G 1 is 0x6.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BEQ``() =
    let words = [ "94230100"; "00000000" ]
    ownsJump um "94230100" false
    goes um words [ G 3, 0x5UL; G 1, 0x5UL ] 0x20100204UL
    goes um words [ G 3, 0x5UL; G 1, 0x6UL ] 0x20100008UL

  /// <summary>
  /// 8d10, beq v0, r0, 0x20100022 (binutils: beqz $2,20100022). A branch is not
  /// run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100022 (the target binutils reads) when it always does; to 0x20100006,
  /// past the slot, when G 2 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BEQZ16``() =
    let words = [ "8d10"; "00000000" ]
    ownsJump um "8d10" false
    goes um words [] 0x20100022UL
    goes um words [ G 2, 0x5UL ] 0x20100006UL

  /// <summary>
  /// 40e30100, beqzc v1, 0x20100204 (binutils: beqzc $3,20100204). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100204 (the target binutils reads) when it always does; to 0x20100004,
  /// past the branch, when G 3 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BEQZC``() =
    let words = [ "40e30100" ]
    ownsJump um "40e30100" true
    goes um words [] 0x20100204UL
    goes um words [ G 3, 0x5UL ] 0x20100004UL

  /// <summary>
  /// 40430100, bgez v1, 0x20100204 (binutils: bgez $3,20100204). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100204 (the target binutils reads) when G 3 is 0x5; to 0x20100008,
  /// past the slot, when G 3 is 0xfffffffffffffffb.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BGEZ``() =
    let words = [ "40430100"; "00000000" ]
    ownsJump um "40430100" false
    goes um words [ G 3, 0x5UL ] 0x20100204UL
    goes um words [ G 3, 0xfffffffffffffffbUL ] 0x20100008UL

  /// <summary>
  /// 40610100, bgezal at, 0x20100204 (binutils: bgezal $1,20100204). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100204 (the target binutils reads) when G 1 is 0x5; to 0x20100008,
  /// past the slot, when G 1 is 0xfffffffffffffffb; ra becomes 0x20100009 and
  /// nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BGEZAL``() =
    let words = [ "40610100"; "00000000" ]
    ownsJump um "40610100" false
    goes um words [ G 1, 0x5UL ] 0x20100204UL
    goes um words [ G 1, 0xfffffffffffffffbUL ] 0x20100008UL
    [ G 1, 0x5UL ]
    |> run um words
    |> is [ G 31, 0x20100009UL ]

  /// <summary>
  /// 42630100, bgezals v1, 0x20100204 (binutils: bgezals $3,20100204). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100204 (the target binutils reads) when G 3 is 0x5; to 0x20100006,
  /// past the slot, when G 3 is 0xfffffffffffffffb; ra becomes 0x20100007 and
  /// nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BGEZALS``() =
    let words = [ "42630100"; "0c00" ]
    ownsJump um "42630100" false
    goes um words [ G 3, 0x5UL ] 0x20100204UL
    goes um words [ G 3, 0xfffffffffffffffbUL ] 0x20100006UL
    [ G 3, 0x5UL ]
    |> run um words
    |> is [ G 31, 0x20100007UL ]

  /// <summary>
  /// 40c30100, bgtz v1, 0x20100204 (binutils: bgtz $3,20100204). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100204 (the target binutils reads) when G 3 is 0x5; to 0x20100008,
  /// past the slot, when nothing is given.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BGTZ``() =
    let words = [ "40c30100"; "00000000" ]
    ownsJump um "40c30100" false
    goes um words [ G 3, 0x5UL ] 0x20100204UL
    goes um words [] 0x20100008UL

  /// <summary>
  /// 40830100, blez v1, 0x20100204 (binutils: blez $3,20100204). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100204 (the target binutils reads) when G 3 is 0xfffffffffffffffb; to
  /// 0x20100008, past the slot, when G 3 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BLEZ``() =
    let words = [ "40830100"; "00000000" ]
    ownsJump um "40830100" false
    goes um words [ G 3, 0xfffffffffffffffbUL ] 0x20100204UL
    goes um words [ G 3, 0x5UL ] 0x20100008UL

  /// <summary>
  /// 40030100, bltz v1, 0x20100204 (binutils: bltz $3,20100204). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100204 (the target binutils reads) when G 3 is 0xfffffffffffffffb; to
  /// 0x20100008, past the slot, when G 3 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BLTZ``() =
    let words = [ "40030100"; "00000000" ]
    ownsJump um "40030100" false
    goes um words [ G 3, 0xfffffffffffffffbUL ] 0x20100204UL
    goes um words [ G 3, 0x5UL ] 0x20100008UL

  /// <summary>
  /// 40220100, bltzal v0, 0x20100204 (binutils: bltzal $2,20100204). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100204 (the target binutils reads) when G 2 is 0xfffffffffffffffb; to
  /// 0x20100008, past the slot, when G 2 is 0x5; ra becomes 0x20100009 and
  /// nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BLTZAL``() =
    let words = [ "40220100"; "00000000" ]
    ownsJump um "40220100" false
    goes um words [ G 2, 0xfffffffffffffffbUL ] 0x20100204UL
    goes um words [ G 2, 0x5UL ] 0x20100008UL
    [ G 2, 0xfffffffffffffffbUL ]
    |> run um words
    |> is [ G 31, 0x20100009UL ]

  /// <summary>
  /// 42230100, bltzals v1, 0x20100204 (binutils: bltzals $3,20100204). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100204 (the target binutils reads) when G 3 is 0xfffffffffffffffb; to
  /// 0x20100006, past the slot, when G 3 is 0x5; ra becomes 0x20100007 and
  /// nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BLTZALS``() =
    let words = [ "42230100"; "0c00" ]
    ownsJump um "42230100" false
    goes um words [ G 3, 0xfffffffffffffffbUL ] 0x20100204UL
    goes um words [ G 3, 0x5UL ] 0x20100006UL
    [ G 3, 0xfffffffffffffffbUL ]
    |> run um words
    |> is [ G 31, 0x20100007UL ]

  /// <summary>
  /// b4230100, bne v1, at, 0x20100204 (binutils: bne $3,$1,20100204). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100204 (the target binutils reads) when G 3 is 0x5 and G 1 is 0x6; to
  /// 0x20100008, past the slot, when G 3 is 0x5 and G 1 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BNE``() =
    let words = [ "b4230100"; "00000000" ]
    ownsJump um "b4230100" false
    goes um words [ G 3, 0x5UL; G 1, 0x6UL ] 0x20100204UL
    goes um words [ G 3, 0x5UL; G 1, 0x5UL ] 0x20100008UL

  /// <summary>
  /// ad10, bne v0, r0, 0x20100022 (binutils: bnez $2,20100022). A branch is not
  /// run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100022 (the target binutils reads) when G 2 is 0x5; to 0x20100006,
  /// past the slot, when nothing is given.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BNEZ16``() =
    let words = [ "ad10"; "00000000" ]
    ownsJump um "ad10" false
    goes um words [ G 2, 0x5UL ] 0x20100022UL
    goes um words [] 0x20100006UL

  /// <summary>
  /// 40a30100, bnezc v1, 0x20100204 (binutils: bnezc $3,20100204). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100204 (the target binutils reads) when G 3 is 0x5; to 0x20100004,
  /// past the branch, when nothing is given.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BNEZC``() =
    let words = [ "40a30100" ]
    ownsJump um "40a30100" true
    goes um words [ G 3, 0x5UL ] 0x20100204UL
    goes um words [] 0x20100004UL

  /// <summary>
  /// 4681, break 0x1, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGTRAP (Breakpoint here); the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BREAK``() =
    []
    |> run um [ "4681" ]
    |> raises [ Breakpoint ] []
    []
    |> run um [ "4681" ]
    |> raises [ Breakpoint ] []
    []
    |> run um [ "4681" ]
    |> raises [ Breakpoint ] []

  /// <summary>
  /// 4681, break 0x1, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGTRAP (Breakpoint here); the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BREAK16``() =
    []
    |> run um [ "4681" ]
    |> raises [ Breakpoint ] []
    []
    |> run um [ "4681" ]
    |> raises [ Breakpoint ] []
    []
    |> run um [ "4681" ]
    |> raises [ Breakpoint ] []

  /// <summary>
  /// 5482253c, c.olt.d 0x1, f2, f4, against QEMU's MIPS64R2-generic: QEMU has
  /// no microMIPS64 or microMIPS processor with an FPU, so the values are what
  /// it left after c.olt.d $fcc1,$f2,$f4, the MIPS64 instruction binutils reads
  /// this word as. the lift has to change what QEMU changed and nothing else,
  /// over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 C.cond.fmt``() =
    [ F 2, 0x4002000000000000UL; F 4, 0x3ff8000000000000UL ]
    |> run um [ "5482253c" ]
    |> is []
    [ F 2, 0x3fe8000000000000UL; F 4, 0x3fe8000000000000UL ]
    |> run um [ "5482253c" ]
    |> is []
    [ F 2, 0xc018000000000000UL; F 4, 0x3fc0000000000000UL ]
    |> run um [ "5482253c" ]
    |> is [ Fcsr, 0x2000000UL ]
    [ F 2, 0x7ff8000000000000UL; F 4, 0x3ff0000000000000UL ]
    |> run um [ "5482253c" ]
    |> is [ Fcsr, 0x10040UL ]

  /// <summary>
  /// 20086001, cache 0x0, 1(a4), against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. QEMU raised SIGILL (UndefinedInstruction here); Status =
  /// 0x10 puts the lift in User Mode, the mode QEMU runs every word in; the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CACHE``() =
    let given0 =
      [ G 8, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x8c18f03cb424aeedUL
        M 0x20200080UL, 0x6b45524da216e604UL
        M 0x20200088UL, 0xf935b56ea8cd86a4UL ]
    given0
    |> run um [ "20086001" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x585cf66c15dc3208UL
        M 0x20200080UL, 0xaf39075837cf77d4UL
        M 0x20200088UL, 0xec074b40aa78f598UL ]
    given1
    |> run um [ "20086001" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xe86855e18d37e12UL
        M 0x20200080UL, 0xb0db596d8efa3134UL
        M 0x20200088UL, 0xb5e92fa639a43fedUL ]
    given2
    |> run um [ "20086001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 6008a601, cachee 0x0, 1(a4), against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. QEMU raised SIGILL (UndefinedInstruction here); Status =
  /// 0x10 puts the lift in User Mode, the mode QEMU runs every word in; the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CACHEE``() =
    let given0 =
      [ G 8, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xad2890fa6d0161acUL
        M 0x20200080UL, 0xaa51dc8275969de0UL
        M 0x20200088UL, 0x4ebe4f5602e96663UL ]
    given0
    |> run um [ "6008a601" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x97d6ebe16009e99eUL
        M 0x20200080UL, 0xbcb1be9163c835e6UL
        M 0x20200088UL, 0xd51a700c324f980bUL ]
    given1
    |> run um [ "6008a601" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x612934330ddda0f5UL
        M 0x20200080UL, 0xc5a7578e6b89def0UL
        M 0x20200088UL, 0x1ec2ed401fee773eUL ]
    given2
    |> run um [ "6008a601" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 5444133b, ceil.l.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after ceil.l.s $f2,$f4, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CEIL.L.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run um [ "5444133b" ]
    |> is [ F 2, 0x3UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run um [ "5444133b" ]
    |> is [ F 2, 0xffffffffffffffffUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run um [ "5444133b" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 54441b3b, ceil.w.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after ceil.w.s $f2,$f4, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CEIL.W.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run um [ "54441b3b" ]
    |> is [ F 2, 0x3UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run um [ "54441b3b" ]
    |> is [ F 2, 0xffffffffUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run um [ "54441b3b" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 551f103b, cfc1 a4, f31, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after cfc1 $8,$31, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CFC1``() =
    [ G 8, 0x7UL ]
    |> run um [ "551f103b" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x7fffffffUL ]
    |> run um [ "551f103b" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0xffffffff89abcdefUL ]
    |> run um [ "551f103b" ]
    |> is [ G 8, 0x0UL ]

  /// <summary>
  /// 0022cd3c, cfc2 at, 0x2, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CFC2``() =
    [ G 1, 0x7UL ]
    |> run um [ "0022cd3c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL ]
    |> run um [ "0022cd3c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL ]
    |> run um [ "0022cd3c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 01094b3c, clo a4, a5, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CLO``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "01094b3c" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "01094b3c" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "01094b3c" ]
    |> is [ G 8, 0x0UL ]

  /// <summary>
  /// 01095b3c, clz a4, a5, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CLZ``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "01095b3c" ]
    |> is [ G 8, 0x1eUL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "01095b3c" ]
    |> is [ G 8, 0x1fUL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "01095b3c" ]
    |> is [ G 8, 0x3UL ]

  /// <summary>
  /// 0000000a, cop2 0x1, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGILL (UndefinedInstruction here); the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 COP2``() =
    []
    |> run um [ "0000000a" ]
    |> raises [ UndefinedInstruction ] []
    []
    |> run um [ "0000000a" ]
    |> raises [ UndefinedInstruction ] []
    []
    |> run um [ "0000000a" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 551f183b, ctc1 a4, f31, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after ctc1 $8,$31, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CTC1``() =
    [ G 8, 0x3UL ]
    |> run um [ "551f183b" ]
    |> is [ Fcsr, 0x3UL ]
    [ G 8, 0x1000000UL ]
    |> run um [ "551f183b" ]
    |> is [ Fcsr, 0x1000000UL ]
    [ G 8, 0xfe800002UL ]
    |> run um [ "551f183b" ]
    |> is [ Fcsr, 0xfe800002UL ]

  /// <summary>
  /// 0022dd3c, ctc2 at, 0x2, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CTC2``() =
    [ G 1, 0x7UL ]
    |> run um [ "0022dd3c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL ]
    |> run um [ "0022dd3c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL ]
    |> run um [ "0022dd3c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 5444137b, cvt.d.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after cvt.d.s $f2,$f4, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CVT.D.fmt``() =
    [ F 2, 0xbff0000000000000UL; F 4, 0x40200000UL ]
    |> run um [ "5444137b" ]
    |> is [ F 2, 0x4004000000000000UL ]
    [ F 2, 0x400c000000000000UL; F 4, 0xbfe00000UL ]
    |> run um [ "5444137b" ]
    |> is [ F 2, 0xbffc000000000000UL ]
    [ F 2, 0x3fd0000000000000UL; F 4, 0x447a0000UL ]
    |> run um [ "5444137b" ]
    |> is [ F 2, 0x408f400000000000UL ]

  /// <summary>
  /// 5444013b, cvt.l.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after cvt.l.s $f2,$f4, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CVT.L.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run um [ "5444013b" ]
    |> is [ F 2, 0x2UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run um [ "5444013b" ]
    |> is [ F 2, 0xfffffffffffffffeUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run um [ "5444013b" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 54c41180, cvt.ps.s f2, f4, f6, against QEMU's MIPS64R2-generic: QEMU has
  /// no microMIPS64 or microMIPS processor with an FPU, so the values are what
  /// it left after cvt.ps.s $f2,$f4,$f6, the MIPS64 instruction binutils reads
  /// this word as. the lift has to change what QEMU changed and nothing else,
  /// over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CVT.PS.S``() =
    [ F 2, 0xbf8000003f800000UL; F 4, 0x40200000UL; F 6, 0x3fc00000UL ]
    |> run um [ "54c41180" ]
    |> is [ F 2, 0x402000003fc00000UL ]
    [ F 2, 0x40600000c0600000UL; F 4, 0xbfe00000UL; F 6, 0x3f400000UL ]
    |> run um [ "54c41180" ]
    |> is [ F 2, 0xbfe000003f400000UL ]
    [ F 2, 0x3e8000003f400000UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL ]
    |> run um [ "54c41180" ]
    |> is [ F 2, 0x447a00003e000000UL ]

  /// <summary>
  /// 5444213b, cvt.s.pl f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after cvt.s.pl $f2,$f4, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CVT.S.PL``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000bfc00000UL ]
    |> run um [ "5444213b" ]
    |> is [ F 2, 0xbfc00000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c000003f000000UL ]
    |> run um [ "5444213b" ]
    |> is [ F 2, 0x3f000000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a000040400000UL ]
    |> run um [ "5444213b" ]
    |> is [ F 2, 0x40400000UL ]

  /// <summary>
  /// 5444293b, cvt.s.pu f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after cvt.s.pu $f2,$f4, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CVT.S.PU``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000bfc00000UL ]
    |> run um [ "5444293b" ]
    |> is [ F 2, 0x40100000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c000003f000000UL ]
    |> run um [ "5444293b" ]
    |> is [ F 2, 0xc0c00000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a000040400000UL ]
    |> run um [ "5444293b" ]
    |> is [ F 2, 0x447a0000UL ]

  /// <summary>
  /// 54441b7b, cvt.s.d f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after cvt.s.d $f2,$f4, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CVT.S.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x4004000000000000UL ]
    |> run um [ "54441b7b" ]
    |> is [ F 2, 0x40200000UL ]
    [ F 2, 0x40600000UL; F 4, 0xbffc000000000000UL ]
    |> run um [ "54441b7b" ]
    |> is [ F 2, 0xbfe00000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x408f400000000000UL ]
    |> run um [ "54441b7b" ]
    |> is [ F 2, 0x447a0000UL ]

  /// <summary>
  /// 5444093b, cvt.w.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after cvt.w.s $f2,$f4, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CVT.W.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run um [ "5444093b" ]
    |> is [ F 2, 0x2UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run um [ "5444093b" ]
    |> is [ F 2, 0xfffffffeUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run um [ "5444093b" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 59494110, dadd a4, a5, a6, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dadd $8,$9,$10, the MIPS64 instruction binutils reads this word
  /// as. QEMU raised SIGFPE (Exception IntegerOverflow here); the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DADD``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "59494110" ]
    |> is [ G 8, 0x8UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "59494110" ]
    |> is [ G 8, 0xffffffffffffffffUL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL; G 10, 0xffffffffUL ]
    |> run um [ "59494110" ]
    |> is [ G 8, 0xfedcba997654320fUL ]
    [ G 8, 0x7UL; G 9, 0x7fffffffffffffffUL; G 10, 0x1UL ]
    |> run um [ "59494110" ]
    |> raises [ Exception IntegerOverflow ] []

  /// <summary>
  /// 5909005c, daddi a4, a5, 0x1, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after daddi $8,$9,1, the MIPS64 instruction binutils reads this word
  /// as. QEMU raised SIGFPE (Exception IntegerOverflow here); the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DADDI``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "5909005c" ]
    |> is [ G 8, 0x4UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "5909005c" ]
    |> is [ G 8, 0x2UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "5909005c" ]
    |> is [ G 8, 0xfedcba9876543211UL ]
    [ G 8, 0x7UL; G 9, 0x7fffffffffffffffUL ]
    |> run um [ "5909005c" ]
    |> raises [ Exception IntegerOverflow ] []

  /// <summary>
  /// 5d090001, daddiu a4, a5, 0x1, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after daddiu $8,$9,1, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DADDIU``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "5d090001" ]
    |> is [ G 8, 0x4UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "5d090001" ]
    |> is [ G 8, 0x2UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "5d090001" ]
    |> is [ G 8, 0xfedcba9876543211UL ]

  /// <summary>
  /// 59494150, daddu a4, a5, a6, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after daddu $8,$9,$10, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DADDU``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "59494150" ]
    |> is [ G 8, 0x8UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "59494150" ]
    |> is [ G 8, 0xffffffffffffffffUL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL; G 10, 0xffffffffUL ]
    |> run um [ "59494150" ]
    |> is [ G 8, 0xfedcba997654320fUL ]

  /// <summary>
  /// 59094b3c, dclo a4, a5, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dclo $8,$9, the MIPS64 instruction binutils reads this word as.
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DCLO``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "59094b3c" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "59094b3c" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "59094b3c" ]
    |> is [ G 8, 0x7UL ]

  /// <summary>
  /// 59095b3c, dclz a4, a5, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dclz $8,$9, the MIPS64 instruction binutils reads this word as.
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DCLZ``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "59095b3c" ]
    |> is [ G 8, 0x3eUL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "59095b3c" ]
    |> is [ G 8, 0x3fUL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "59095b3c" ]
    |> is [ G 8, 0x0UL ]

  /// <summary>
  /// 5928ab3c, ddiv a4, a5, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after ddiv $0,$8,$9, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DDIV``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "5928ab3c" ]
    |> is [ Hi, 0x1UL; Lo, 0x2UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "5928ab3c" ]
    |> is [ Lo, 0x7fffffffffffffffUL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "5928ab3c" ]
    |> is [ Hi, 0x123456789abcdefUL ]

  /// <summary>
  /// 5928bb3c, ddivu a4, a5, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after ddivu $0,$8,$9, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DDIVU``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "5928bb3c" ]
    |> is [ Hi, 0x1UL; Lo, 0x2UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "5928bb3c" ]
    |> is [ Lo, 0x7fffffffffffffffUL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "5928bb3c" ]
    |> is [ Hi, 0x123456789abcdefUL ]

  /// <summary>
  /// 0000e37c, deret, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10 puts
  /// the lift in User Mode, the mode QEMU runs every word in; the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DERET``() =
    [ Status, 0x10UL ]
    |> run um [ "0000e37c" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run um [ "0000e37c" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run um [ "0000e37c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 5909006c, dext a4, a5, 0x1, 0x1, against QEMU's MIPS64R2-generic: QEMU has
  /// no microMIPS64 or microMIPS processor with an FPU, so the values are what
  /// it left after dext $8,$9,0x1,0x1, the MIPS64 instruction binutils reads
  /// this word as. the lift has to change what QEMU changed and nothing else,
  /// over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DEXT``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "5909006c" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "5909006c" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "5909006c" ]
    |> is [ G 8, 0x0UL ]

  /// <summary>
  /// 59090064, dextm a4, a5, 0x1, 0x21, against QEMU's MIPS64R2-generic: QEMU
  /// has no microMIPS64 or microMIPS processor with an FPU, so the values are
  /// what it left after dext $8,$9,0x1,0x21, the MIPS64 instruction binutils
  /// reads this word as. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DEXTM``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "59090064" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "59090064" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "59090064" ]
    |> is [ G 8, 0x3b2a1908UL ]

  /// <summary>
  /// 59090014, dextu a4, a5, 0x20, 0x1, against QEMU's MIPS64R2-generic: QEMU
  /// has no microMIPS64 or microMIPS processor with an FPU, so the values are
  /// what it left after dext $8,$9,0x20,0x1, the MIPS64 instruction binutils
  /// reads this word as. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DEXTU``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "59090014" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "59090014" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "59090014" ]
    |> is [ G 8, 0x0UL ]

  /// <summary>
  /// 0008477c, di a4, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10 puts
  /// the lift in User Mode, the mode QEMU runs every word in; the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DI``() =
    [ G 8, 0x7UL; Status, 0x10UL ]
    |> run um [ "0008477c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 8, 0x7fffffffUL; Status, 0x10UL ]
    |> run um [ "0008477c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 8, 0xffffffff89abcdefUL; Status, 0x10UL ]
    |> run um [ "0008477c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 5909084c, dins a4, a5, 0x1, 0x1, against QEMU's MIPS64R2-generic: QEMU has
  /// no microMIPS64 or microMIPS processor with an FPU, so the values are what
  /// it left after dins $8,$9,0x1,0x1, the MIPS64 instruction binutils reads
  /// this word as. the lift has to change what QEMU changed and nothing else,
  /// over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DINS``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "5909084c" ]
    |> is []
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "5909084c" ]
    |> is []
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "5909084c" ]
    |> is [ G 8, 0x123456789abcdedUL ]

  /// <summary>
  /// 59090044, dinsm a4, a5, 0x1, 0x20, against QEMU's MIPS64R2-generic: QEMU
  /// has no microMIPS64 or microMIPS processor with an FPU, so the values are
  /// what it left after dins $8,$9,0x1,0x20, the MIPS64 instruction binutils
  /// reads this word as. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DINSM``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "59090044" ]
    |> is []
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "59090044" ]
    |> is [ G 8, 0x7ffffffe00000003UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "59090044" ]
    |> is [ G 8, 0x1234566eca86421UL ]

  /// <summary>
  /// 59090034, dinsu a4, a5, 0x20, 0x1, against QEMU's MIPS64R2-generic: QEMU
  /// has no microMIPS64 or microMIPS processor with an FPU, so the values are
  /// what it left after dins $8,$9,0x20,0x1, the MIPS64 instruction binutils
  /// reads this word as. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DINSU``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "59090034" ]
    |> is [ G 8, 0x100000007UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "59090034" ]
    |> is []
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "59090034" ]
    |> is [ G 8, 0x123456689abcdefUL ]

  /// <summary>
  /// 0128ab3c, div a4, a5, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DIV``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "0128ab3c" ]
    |> is [ Hi, 0x1UL; Lo, 0x2UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "0128ab3c" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "0128ab3c" ]
    |> is [ Hi, 0xfffffffff6e5d4bfUL; Lo, 0xfffffffffffffffaUL ]

  /// <summary>
  /// 54c410f0, div.s f2, f4, f6, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after div.s $f2,$f4,$f6, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DIV.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; F 6, 0x3fc00000UL ]
    |> run um [ "54c410f0" ]
    |> is [ F 2, 0x3fc00000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; F 6, 0x3f400000UL ]
    |> run um [ "54c410f0" ]
    |> is [ F 2, 0xc1000000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL ]
    |> run um [ "54c410f0" ]
    |> is [ F 2, 0x45fa0000UL ]

  /// <summary>
  /// 0128bb3c, divu a4, a5, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DIVU``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "0128bb3c" ]
    |> is [ Hi, 0x1UL; Lo, 0x2UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "0128bb3c" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "0128bb3c" ]
    |> is [ Hi, 0xa3d70a7UL; Lo, 0x7UL ]

  /// <summary>
  /// 582208fc, dmfc0 at, 0x2, 0x1, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dmfc0 $1,$2,1, the MIPS64 instruction binutils reads this word
  /// as. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10 puts the
  /// lift in User Mode, the mode QEMU runs every word in; the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DMFC0``() =
    [ G 1, 0x7UL; Status, 0x10UL ]
    |> run um [ "582208fc" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL; Status, 0x10UL ]
    |> run um [ "582208fc" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL; Status, 0x10UL ]
    |> run um [ "582208fc" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 5502243b, dmfc1 a4, f2, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dmfc1 $8,$f2, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DMFC1``() =
    [ G 8, 0x7UL; F 2, 0x1122334455667788UL ]
    |> run um [ "5502243b" ]
    |> is [ G 8, 0x1122334455667788UL ]
    [ G 8, 0x7fffffffffffffffUL; F 2, 0xbf800000UL ]
    |> run um [ "5502243b" ]
    |> is [ G 8, 0xbf800000UL ]
    [ G 8, 0x123456789abcdefUL; F 2, 0x8899aabbccddeeffUL ]
    |> run um [ "5502243b" ]
    |> is [ G 8, 0x8899aabbccddeeffUL ]

  /// <summary>
  /// 00226d3c, dmfc2 at, 0x2, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dmfc2 $1,$2, the MIPS64 instruction binutils reads this word
  /// as. QEMU raised SIGILL (UndefinedInstruction here); the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DMFC2``() =
    [ G 1, 0x7UL ]
    |> run um [ "00226d3c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL ]
    |> run um [ "00226d3c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL ]
    |> run um [ "00226d3c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 58220afc, dmtc0 at, 0x2, 0x1, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dmtc0 $1,$2,1, the MIPS64 instruction binutils reads this word
  /// as. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10 puts the
  /// lift in User Mode, the mode QEMU runs every word in; the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DMTC0``() =
    [ G 1, 0x7UL; Status, 0x10UL ]
    |> run um [ "58220afc" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL; Status, 0x10UL ]
    |> run um [ "58220afc" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL; Status, 0x10UL ]
    |> run um [ "58220afc" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 55022c3b, dmtc1 a4, f2, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dmtc1 $8,$f2, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DMTC1``() =
    [ G 8, 0x7UL; F 2, 0x1122334455667788UL ]
    |> run um [ "55022c3b" ]
    |> is [ F 2, 0x7UL ]
    [ G 8, 0x7fffffffffffffffUL; F 2, 0xbf800000UL ]
    |> run um [ "55022c3b" ]
    |> is [ F 2, 0x7fffffffffffffffUL ]
    [ G 8, 0x123456789abcdefUL; F 2, 0x8899aabbccddeeffUL ]
    |> run um [ "55022c3b" ]
    |> is [ F 2, 0x123456789abcdefUL ]

  /// <summary>
  /// 00227d3c, dmtc2 at, 0x2, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dmtc2 $1,$2, the MIPS64 instruction binutils reads this word
  /// as. QEMU raised SIGILL (UndefinedInstruction here); the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DMTC2``() =
    [ G 1, 0x7UL ]
    |> run um [ "00227d3c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL ]
    |> run um [ "00227d3c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL ]
    |> run um [ "00227d3c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 59288b3c, dmult a4, a5, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dmult $8,$9, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DMULT``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "59288b3c" ]
    |> is [ Lo, 0x15UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "59288b3c" ]
    |> is [ Lo, 0x7fffffffffffffffUL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "59288b3c" ]
    |> is [ Hi, 0xfffeb49923cc0953UL; Lo, 0x2236d88fe5618cf0UL ]

  /// <summary>
  /// 59289b3c, dmultu a4, a5, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dmultu $8,$9, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DMULTU``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "59289b3c" ]
    |> is [ Lo, 0x15UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "59289b3c" ]
    |> is [ Lo, 0x7fffffffffffffffUL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "59289b3c" ]
    |> is [ Hi, 0x121fa00ad77d742UL; Lo, 0x2236d88fe5618cf0UL ]

  /// <summary>
  /// 590908c0, drotr a4, a5, 0x1, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dror $8,$9,0x1, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DROTR``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "590908c0" ]
    |> is [ G 8, 0x8000000000000001UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "590908c0" ]
    |> is [ G 8, 0x8000000000000000UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "590908c0" ]
    |> is [ G 8, 0x7f6e5d4c3b2a1908UL ]

  /// <summary>
  /// 590908c8, drotr32 a4, a5, 0x1, against QEMU's MIPS64R2-generic: QEMU has
  /// no microMIPS64 or microMIPS processor with an FPU, so the values are what
  /// it left after dror32 $8,$9,0x1, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DROTR32``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "590908c8" ]
    |> is [ G 8, 0x180000000UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "590908c8" ]
    |> is [ G 8, 0x80000000UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "590908c8" ]
    |> is [ G 8, 0x3b2a19087f6e5d4cUL ]

  /// <summary>
  /// 592a40d0, drotrv a4, a5, a6, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after drorv $8,$9,$10, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DROTRV``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "592a40d0" ]
    |> is [ G 8, 0x1800000000000000UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "592a40d0" ]
    |> is [ G 8, 0x4UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL; G 10, 0xffffffffUL ]
    |> run um [ "592a40d0" ]
    |> is [ G 8, 0xfdb97530eca86421UL ]

  /// <summary>
  /// 59097b3c, dsbh a4, a5, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dsbh $8,$9, the MIPS64 instruction binutils reads this word as.
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DSBH``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "59097b3c" ]
    |> is [ G 8, 0x300UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "59097b3c" ]
    |> is [ G 8, 0x100UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "59097b3c" ]
    |> is [ G 8, 0xdcfe98ba54761032UL ]

  /// <summary>
  /// 5909fb3c, dshd a4, a5, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dshd $8,$9, the MIPS64 instruction binutils reads this word as.
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DSHD``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "5909fb3c" ]
    |> is [ G 8, 0x3000000000000UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "5909fb3c" ]
    |> is [ G 8, 0x1000000000000UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "5909fb3c" ]
    |> is [ G 8, 0x32107654ba98fedcUL ]

  /// <summary>
  /// 59090800, dsll a4, a5, 0x1, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dsll $8,$9,0x1, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DSLL``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "59090800" ]
    |> is [ G 8, 0x6UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "59090800" ]
    |> is [ G 8, 0x2UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "59090800" ]
    |> is [ G 8, 0xfdb97530eca86420UL ]

  /// <summary>
  /// 59090808, dsll32 a4, a5, 0x1, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dsll32 $8,$9,0x1, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DSLL32``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "59090808" ]
    |> is [ G 8, 0x600000000UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "59090808" ]
    |> is [ G 8, 0x200000000UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "59090808" ]
    |> is [ G 8, 0xeca8642000000000UL ]

  /// <summary>
  /// 592a4010, dsllv a4, a5, a6, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dsllv $8,$9,$10, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DSLLV``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "592a4010" ]
    |> is [ G 8, 0x60UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "592a4010" ]
    |> is [ G 8, 0x4000000000000000UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL; G 10, 0xffffffffUL ]
    |> run um [ "592a4010" ]
    |> is [ G 8, 0x0UL ]

  /// <summary>
  /// 59090880, dsra a4, a5, 0x1, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dsra $8,$9,0x1, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DSRA``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "59090880" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "59090880" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "59090880" ]
    |> is [ G 8, 0xff6e5d4c3b2a1908UL ]

  /// <summary>
  /// 59090888, dsra32 a4, a5, 0x1, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dsra32 $8,$9,0x1, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DSRA32``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "59090888" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "59090888" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "59090888" ]
    |> is [ G 8, 0xffffffffff6e5d4cUL ]

  /// <summary>
  /// 592a4090, dsrav a4, a5, a6, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dsrav $8,$9,$10, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DSRAV``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "592a4090" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "592a4090" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL; G 10, 0xffffffffUL ]
    |> run um [ "592a4090" ]
    |> is [ G 8, 0xffffffffffffffffUL ]

  /// <summary>
  /// 59090840, dsrl a4, a5, 0x1, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dsrl $8,$9,0x1, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DSRL``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "59090840" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "59090840" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "59090840" ]
    |> is [ G 8, 0x7f6e5d4c3b2a1908UL ]

  /// <summary>
  /// 59090848, dsrl32 a4, a5, 0x1, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dsrl32 $8,$9,0x1, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DSRL32``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "59090848" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "59090848" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "59090848" ]
    |> is [ G 8, 0x7f6e5d4cUL ]

  /// <summary>
  /// 592a4050, dsrlv a4, a5, a6, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dsrlv $8,$9,$10, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DSRLV``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "592a4050" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "592a4050" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL; G 10, 0xffffffffUL ]
    |> run um [ "592a4050" ]
    |> is [ G 8, 0x1UL ]

  /// <summary>
  /// 59494190, dsub a4, a5, a6, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dsub $8,$9,$10, the MIPS64 instruction binutils reads this word
  /// as. QEMU raised SIGFPE (Exception IntegerOverflow here); the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DSUB``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "59494190" ]
    |> is [ G 8, 0xfffffffffffffffeUL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "59494190" ]
    |> is [ G 8, 0x3UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL; G 10, 0xffffffffUL ]
    |> run um [ "59494190" ]
    |> is [ G 8, 0xfedcba9776543211UL ]
    [ G 8, 0x7UL; G 9, 0x8000000000000000UL; G 10, 0x1UL ]
    |> run um [ "59494190" ]
    |> raises [ Exception IntegerOverflow ] []

  /// <summary>
  /// 594941d0, dsubu a4, a5, a6, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dsubu $8,$9,$10, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DSUBU``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "594941d0" ]
    |> is [ G 8, 0xfffffffffffffffeUL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "594941d0" ]
    |> is [ G 8, 0x3UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL; G 10, 0xffffffffUL ]
    |> run um [ "594941d0" ]
    |> is [ G 8, 0xfedcba9776543211UL ]

  /// <summary>
  /// 00001800, ehb, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 EHB``() =
    []
    |> run um [ "00001800" ]
    |> is []
    []
    |> run um [ "00001800" ]
    |> is []
    []
    |> run um [ "00001800" ]
    |> is []

  /// <summary>
  /// 0008577c, ei a4, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10 puts
  /// the lift in User Mode, the mode QEMU runs every word in; the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 EI``() =
    [ G 8, 0x7UL; Status, 0x10UL ]
    |> run um [ "0008577c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 8, 0x7fffffffUL; Status, 0x10UL ]
    |> run um [ "0008577c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 8, 0xffffffff89abcdefUL; Status, 0x10UL ]
    |> run um [ "0008577c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 0000f37c, eret, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10 puts
  /// the lift in User Mode, the mode QEMU runs every word in; the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ERET``() =
    [ Status, 0x10UL ]
    |> run um [ "0000f37c" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run um [ "0000f37c" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run um [ "0000f37c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 0001f37c, eretnc, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10 puts
  /// the lift in User Mode, the mode QEMU runs every word in; the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ERETNC``() =
    [ Status, 0x10UL ]
    |> run um [ "0001f37c" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run um [ "0001f37c" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run um [ "0001f37c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 0109006c, ext a4, a5, 0x1, 0x1, against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 EXT``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "0109006c" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "0109006c" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "0109006c" ]
    |> is [ G 8, 0x0UL ]

  /// <summary>
  /// 5444033b, floor.l.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after floor.l.s $f2,$f4, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 FLOOR.L.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run um [ "5444033b" ]
    |> is [ F 2, 0x2UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run um [ "5444033b" ]
    |> is [ F 2, 0xfffffffffffffffeUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run um [ "5444033b" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 54440b3b, floor.w.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after floor.w.s $f2,$f4, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 FLOOR.W.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run um [ "54440b3b" ]
    |> is [ F 2, 0x2UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run um [ "54440b3b" ]
    |> is [ F 2, 0xfffffffeUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run um [ "54440b3b" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 0109084c, ins a4, a5, 0x1, 0x1, against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 INS``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "0109084c" ]
    |> is []
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "0109084c" ]
    |> is []
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "0109084c" ]
    |> is [ G 8, 0xffffffff89abcdedUL ]

  /// <summary>
  /// d4030000, j 0x20060000 (binutils: j 20060000). A branch is not run against
  /// QEMU: it moves the PC, and its delay slot makes one word meaningless to
  /// run alone. Checked structurally from the manual: the transfer is left to
  /// the delay slot, which holds a NOP; control goes to 0x20060000 (the target
  /// binutils reads) when it always does.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 J``() =
    let words = [ "d4030000"; "00000000" ]
    ownsJump um "d4030000" false
    goes um words [] 0x20060000UL

  /// <summary>
  /// f4030000, jal 0x20060000 (binutils: jal 20060000). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20060000 (the target binutils reads) when it always does; ra becomes
  /// 0x20100009 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 JAL``() =
    let words = [ "f4030000"; "00000000" ]
    ownsJump um "f4030000" false
    goes um words [] 0x20060000UL
    []
    |> run um words
    |> is [ G 31, 0x20100009UL ]

  /// <summary>
  /// 01090f3c, jalr a4, a5 (binutils: jalr $8,$9). A branch is not run against
  /// QEMU: it moves the PC, and its delay slot makes one word meaningless to
  /// run alone. Checked structurally from the manual: the transfer is left to
  /// the delay slot, which holds a NOP; control goes to 0x20100400 when G 9 is
  /// 0x20100401; the jump goes on in MicroMIPS; the link register becomes
  /// 0x20100009 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 JALR``() =
    let words = [ "01090f3c"; "00000000" ]
    ownsJump um "01090f3c" false
    goes um words [ G 9, 0x20100401UL ] 0x20100400UL
    switches um words [ G 9, 0x20100401UL ] InterJmpKind.SwitchToMicroMIPS
    [ G 9, 0x20100401UL ]
    |> run um words
    |> is [ G 8, 0x20100009UL ]

  /// <summary>
  /// 01091f3c, jalr.hb a4, a5 (binutils: jalr.hb $8,$9). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100400 when G 9 is 0x20100401; the jump goes on in MicroMIPS; the link
  /// register becomes 0x20100009 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 JALR.HB``() =
    let words = [ "01091f3c"; "00000000" ]
    ownsJump um "01091f3c" false
    goes um words [ G 9, 0x20100401UL ] 0x20100400UL
    switches um words [ G 9, 0x20100401UL ] InterJmpKind.SwitchToMicroMIPS
    [ G 9, 0x20100401UL ]
    |> run um words
    |> is [ G 8, 0x20100009UL ]

  /// <summary>
  /// 45c1, jalr at (binutils: jalr $1). A branch is not run against QEMU: it
  /// moves the PC, and its delay slot makes one word meaningless to run alone.
  /// Checked structurally from the manual: the transfer is left to the delay
  /// slot, which holds a NOP; control goes to 0x20100400 when G 1 is
  /// 0x20100401; the jump goes on in MicroMIPS; ra becomes 0x20100007 and
  /// nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 JALR16``() =
    let words = [ "45c1"; "00000000" ]
    ownsJump um "45c1" false
    goes um words [ G 1, 0x20100401UL ] 0x20100400UL
    switches um words [ G 1, 0x20100401UL ] InterJmpKind.SwitchToMicroMIPS
    [ G 1, 0x20100401UL ]
    |> run um words
    |> is [ G 31, 0x20100007UL ]

  /// <summary>
  /// 01094f3c, jalrs a4, a5 (binutils: jalrs $8,$9). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100400 when G 9 is 0x20100401; the jump goes on in MicroMIPS; the link
  /// register becomes 0x20100007 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 JALRS``() =
    let words = [ "01094f3c"; "0c00" ]
    ownsJump um "01094f3c" false
    goes um words [ G 9, 0x20100401UL ] 0x20100400UL
    switches um words [ G 9, 0x20100401UL ] InterJmpKind.SwitchToMicroMIPS
    [ G 9, 0x20100401UL ]
    |> run um words
    |> is [ G 8, 0x20100007UL ]

  /// <summary>
  /// 01095f3c, jalrs.hb a4, a5 (binutils: jalrs.hb $8,$9). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100400 when G 9 is 0x20100401; the jump goes on in MicroMIPS; the link
  /// register becomes 0x20100007 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 JALRS.HB``() =
    let words = [ "01095f3c"; "0c00" ]
    ownsJump um "01095f3c" false
    goes um words [ G 9, 0x20100401UL ] 0x20100400UL
    switches um words [ G 9, 0x20100401UL ] InterJmpKind.SwitchToMicroMIPS
    [ G 9, 0x20100401UL ]
    |> run um words
    |> is [ G 8, 0x20100007UL ]

  /// <summary>
  /// 45e1, jalrs at (binutils: jalrs $1). A branch is not run against QEMU: it
  /// moves the PC, and its delay slot makes one word meaningless to run alone.
  /// Checked structurally from the manual: the transfer is left to the delay
  /// slot, which holds a NOP; control goes to 0x20100400 when G 1 is
  /// 0x20100401; the jump goes on in MicroMIPS; ra becomes 0x20100005 and
  /// nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 JALRS16``() =
    let words = [ "45e1"; "0c00" ]
    ownsJump um "45e1" false
    goes um words [ G 1, 0x20100401UL ] 0x20100400UL
    switches um words [ G 1, 0x20100401UL ] InterJmpKind.SwitchToMicroMIPS
    [ G 1, 0x20100401UL ]
    |> run um words
    |> is [ G 31, 0x20100005UL ]

  /// <summary>
  /// 74030000, jals 0x20060000 (binutils: jals 20060000). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20060000 (the target binutils reads) when it always does; ra becomes
  /// 0x20100007 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 JALS``() =
    let words = [ "74030000"; "0c00" ]
    ownsJump um "74030000" false
    goes um words [] 0x20060000UL
    []
    |> run um words
    |> is [ G 31, 0x20100007UL ]

  /// <summary>
  /// f0030000, jalx 0x200c0000 (binutils: jalx 200c0000). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x200c0000 (the target binutils reads) when it always does; the jump goes
  /// on in MIPS; ra becomes 0x20100009 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 JALX``() =
    let words = [ "f0030000"; "00000000" ]
    ownsJump um "f0030000" false
    goes um words [] 0x200c0000UL
    switches um words [] InterJmpKind.SwitchToMIPS
    []
    |> run um words
    |> is [ G 31, 0x20100009UL ]

  /// <summary>
  /// 00090f3c, jalr r0, a5 (binutils: jr $9). A branch is not run against QEMU:
  /// it moves the PC, and its delay slot makes one word meaningless to run
  /// alone. Checked structurally from the manual: the transfer is left to the
  /// delay slot, which holds a NOP; control goes to 0x20100400 when G 9 is
  /// 0x20100401; the jump goes on in MicroMIPS.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 JR``() =
    let words = [ "00090f3c"; "00000000" ]
    ownsJump um "00090f3c" false
    goes um words [ G 9, 0x20100401UL ] 0x20100400UL
    switches um words [ G 9, 0x20100401UL ] InterJmpKind.SwitchToMicroMIPS

  /// <summary>
  /// 00091f3c, jalr.hb r0, a5 (binutils: jr.hb $9). A branch is not run against
  /// QEMU: it moves the PC, and its delay slot makes one word meaningless to
  /// run alone. Checked structurally from the manual: the transfer is left to
  /// the delay slot, which holds a NOP; control goes to 0x20100400 when G 9 is
  /// 0x20100401; the jump goes on in MicroMIPS.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 JR.HB``() =
    let words = [ "00091f3c"; "00000000" ]
    ownsJump um "00091f3c" false
    goes um words [ G 9, 0x20100401UL ] 0x20100400UL
    switches um words [ G 9, 0x20100401UL ] InterJmpKind.SwitchToMicroMIPS

  /// <summary>
  /// 4581, jr at (binutils: jr $1). A branch is not run against QEMU: it moves
  /// the PC, and its delay slot makes one word meaningless to run alone.
  /// Checked structurally from the manual: the transfer is left to the delay
  /// slot, which holds a NOP; control goes to 0x20100400 when G 1 is
  /// 0x20100401; the jump goes on in MicroMIPS.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 JR16``() =
    let words = [ "4581"; "00000000" ]
    ownsJump um "4581" false
    goes um words [ G 1, 0x20100401UL ] 0x20100400UL
    switches um words [ G 1, 0x20100401UL ] InterJmpKind.SwitchToMicroMIPS

  /// <summary>
  /// 4701, jraddiusp 0x4 (binutils: jraddiusp 4). A branch is not run against
  /// QEMU: it moves the PC, and its delay slot makes one word meaningless to
  /// run alone. Checked structurally from the manual: the transfer is the
  /// branch's own, there being no delay slot; control goes to 0x20100400 when G
  /// 31 is 0x20100401; the jump goes on in MicroMIPS; sp grows by 4.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 JRADDIUSP``() =
    let words = [ "4701" ]
    ownsJump um "4701" true
    goes um words [ G 31, 0x20100401UL ] 0x20100400UL
    switches um words [ G 31, 0x20100401UL ] InterJmpKind.SwitchToMicroMIPS
    [ G 29, 0x20200000UL; G 31, 0x20100401UL ]
    |> run um words
    |> is [ G 29, 0x20200004UL ]

  /// <summary>
  /// 45a1, jrc at (binutils: jrc $1). A branch is not run against QEMU: it
  /// moves the PC, and its delay slot makes one word meaningless to run alone.
  /// Checked structurally from the manual: the transfer is the branch's own,
  /// there being no delay slot; control goes to 0x20100400 when G 1 is
  /// 0x20100401; the jump goes on in MicroMIPS.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 JRC``() =
    let words = [ "45a1" ]
    ownsJump um "45a1" true
    goes um words [ G 1, 0x20100401UL ] 0x20100400UL
    switches um words [ G 1, 0x20100401UL ] InterJmpKind.SwitchToMicroMIPS

  /// <summary>
  /// 1d090001, lb a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LB``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x1d8297ff9f58fdaaUL
        M 0x20200080UL, 0x6d6d8410e74d61cdUL
        M 0x20200088UL, 0x5ca5975d620d74efUL ]
    given0
    |> run um [ "1d090001" ]
    |> is [ G 8, 0x6dUL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0xdabaa3b35cdb29edUL
        M 0x20200080UL, 0x8ac01adecd58805cUL
        M 0x20200088UL, 0x3881035086aeb06UL ]
    given1
    |> run um [ "1d090001" ]
    |> is [ G 8, 0xffffffffffffff8aUL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x24aba6780245a1bdUL
        M 0x20200080UL, 0x55d20d8622f6318bUL
        M 0x20200088UL, 0x206367a6776fe74dUL ]
    given2
    |> run um [ "1d090001" ]
    |> is [ G 8, 0x55UL ]

  /// <summary>
  /// 61096801, lbe a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LBE``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xbdda38d14f89029fUL
        M 0x20200080UL, 0x39c761f75f5992aUL
        M 0x20200088UL, 0xc03cd94d5cf204dcUL ]
    given0
    |> run um [ "61096801" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x7f8e706de5b234ceUL
        M 0x20200080UL, 0x3247d34a4f2e299UL
        M 0x20200088UL, 0x83b0e3fca2245c8eUL ]
    given1
    |> run um [ "61096801" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xa5cb365a01bc3a11UL
        M 0x20200080UL, 0xb110f21136cc505UL
        M 0x20200088UL, 0xd9c58f2f62aa9a4cUL ]
    given2
    |> run um [ "61096801" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 15090001, lbu a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LBU``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0xb3d2ce386ab30aceUL
        M 0x20200080UL, 0x102cf778e34b207UL
        M 0x20200088UL, 0x518bcd5e63511062UL ]
    given0
    |> run um [ "15090001" ]
    |> is [ G 8, 0x1UL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x648d306faa163331UL
        M 0x20200080UL, 0xa81ed140378fc9d7UL
        M 0x20200088UL, 0x36ea4355abaf89b7UL ]
    given1
    |> run um [ "15090001" ]
    |> is [ G 8, 0xa8UL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x3867e7561c976ef8UL
        M 0x20200080UL, 0x9efa22786c55b016UL
        M 0x20200088UL, 0x670632e7af06cd5cUL ]
    given2
    |> run um [ "15090001" ]
    |> is [ G 8, 0x9eUL ]

  /// <summary>
  /// 0901, lbu v0, 1(s0), against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LBU16``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0x8191332abd2fd5feUL
        M 0x20200080UL, 0x5e46ce4894ef04b1UL
        M 0x20200088UL, 0x34d3446c24a20c5dUL ]
    given0
    |> run um [ "0901" ]
    |> is [ G 2, 0x5eUL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0xb35ddea3470f8d22UL
        M 0x20200080UL, 0x81482865707d689fUL
        M 0x20200088UL, 0x244f1b55f084dddcUL ]
    given1
    |> run um [ "0901" ]
    |> is [ G 2, 0x81UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0x7a54e044e1259e30UL
        M 0x20200080UL, 0xbdb5482467e6999eUL
        M 0x20200088UL, 0x691575f5f0f20c14UL ]
    given2
    |> run um [ "0901" ]
    |> is [ G 2, 0xbdUL ]

  /// <summary>
  /// 61096001, lbue a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LBUE``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x239b7ec97e1673fbUL
        M 0x20200080UL, 0x7a28f3e9ec312eaeUL
        M 0x20200088UL, 0xc02b2f3f3ebe4d8cUL ]
    given0
    |> run um [ "61096001" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xe8d4bd6bb0a72edbUL
        M 0x20200080UL, 0x3d69efb9fb84ce11UL
        M 0x20200088UL, 0x51265d3a0cbde505UL ]
    given1
    |> run um [ "61096001" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xd6f873ad81926bdaUL
        M 0x20200080UL, 0xf82de1737d31b6c2UL
        M 0x20200088UL, 0x95e60cbb36963ef8UL ]
    given2
    |> run um [ "61096001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// dd090001, ld a4, 1(a5), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after ld $8,1($9), the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LD``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x9ba80fdf14aeda88UL
        M 0x20200080UL, 0x1a0bfcd3a47ae116UL
        M 0x20200088UL, 0xe5d6324154ad3904UL ]
    given0
    |> run um [ "dd090001" ]
    |> is [ G 8, 0x1a0bfcd3a47ae116UL ]
    let given1 =
      [ G 8, 0x7fffffffffffffffUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0xd3f1d2ad363ddf48UL
        M 0x20200080UL, 0x4c1cdf62cf941b1bUL
        M 0x20200088UL, 0x68eecc93b0e84cdcUL ]
    given1
    |> run um [ "dd090001" ]
    |> is [ G 8, 0x4c1cdf62cf941b1bUL ]
    let given2 =
      [ G 8, 0x123456789abcdefUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x80465652711ddceUL
        M 0x20200080UL, 0x1901e665a42727beUL
        M 0x20200088UL, 0x109de3cddd795444UL ]
    given2
    |> run um [ "dd090001" ]
    |> is [ G 8, 0x1901e665a42727beUL ]

  /// <summary>
  /// bc480001, ldc1 f2, 1(a4), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after ldc1 $f2,1($8), the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LDC1``() =
    let given0 =
      [ G 8, 0x2020007fUL
        F 2, 0xbff0000000000000UL
        M 0x20200078UL, 0xa34fa19bcd672d96UL
        M 0x20200080UL, 0xb4f07a3b88c5050fUL
        M 0x20200088UL, 0x1b535e2bf5e0fe3fUL ]
    given0
    |> run um [ "bc480001" ]
    |> is [ F 2, 0xb4f07a3b88c5050fUL ]
    let given1 =
      [ G 8, 0x2020007fUL
        F 2, 0x400c000000000000UL
        M 0x20200078UL, 0x9eeb0ed349ddf3ccUL
        M 0x20200080UL, 0xc3e99c7cea3fbbf2UL
        M 0x20200088UL, 0x78153d049952a0a1UL ]
    given1
    |> run um [ "bc480001" ]
    |> is [ F 2, 0xc3e99c7cea3fbbf2UL ]
    let given2 =
      [ G 8, 0x2020007fUL
        F 2, 0x3fd0000000000000UL
        M 0x20200078UL, 0x82df3e0f61799ae2UL
        M 0x20200080UL, 0x43f8ba331dd84cf4UL
        M 0x20200088UL, 0x75b9f52c5b087c68UL ]
    given2
    |> run um [ "bc480001" ]
    |> is [ F 2, 0x43f8ba331dd84cf4UL ]

  /// <summary>
  /// 20002001, ldc2 0x0, 1(r0), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LDC2``() =
    let given0 =
      [ M 0x20200078UL, 0xe7a2950cbe977fb4UL
        M 0x20200080UL, 0xa19062729f051c93UL
        M 0x20200088UL, 0xd148452b6d995e9aUL ]
    given0
    |> run um [ "20002001" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ M 0x20200078UL, 0x7c1b4dbd10bc8a4UL
        M 0x20200080UL, 0xf170548785dfad6fUL
        M 0x20200088UL, 0xb7a8c51df44ab4f8UL ]
    given1
    |> run um [ "20002001" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ M 0x20200078UL, 0x607c6e1c58c1368fUL
        M 0x20200080UL, 0x774cb6fe88d64daUL
        M 0x20200088UL, 0x124203ff468372d6UL ]
    given2
    |> run um [ "20002001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 61094001, ldl a4, 1(a5), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after ldl $8,1($9), the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LDL``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x20200080UL
        M 0x20200078UL, 0x9faadc7403d56c61UL
        M 0x20200080UL, 0x20ce34dbe78cfa5fUL
        M 0x20200088UL, 0xe23249d45c4b1ceaUL ]
    given0
    |> run um [ "61094001" ]
    |> is [ G 8, 0xce34dbe78cfa5f07UL ]
    let given1 =
      [ G 8, 0x7fffffffffffffffUL
        G 9, 0x20200081UL
        M 0x20200078UL, 0xc0272ce82975efbcUL
        M 0x20200080UL, 0xf062b48220306bddUL
        M 0x20200088UL, 0xef64ff168f812c55UL ]
    given1
    |> run um [ "61094001" ]
    |> is [ G 8, 0xb48220306bddffffUL ]
    let given2 =
      [ G 8, 0x123456789abcdefUL
        G 9, 0x20200084UL
        M 0x20200078UL, 0xf24ac23eb1ecc6eaUL
        M 0x20200080UL, 0x99c87ffb4f9db22eUL
        M 0x20200088UL, 0x1623eb5eea6ed408UL ]
    given2
    |> run um [ "61094001" ]
    |> is [ G 8, 0x9db22e6789abcdefUL ]

  /// <summary>
  /// 20447008, ldm s0, s1, 8(a0), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after ld $16,8($4); ld $17,16($4), the MIPS64 instruction binutils
  /// reads this word as. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LDM``() =
    let given0 =
      [ G 4, 0x20200078UL
        G 16, 0x7UL
        G 17, 0x3UL
        M 0x20200078UL, 0x27fda155f571517bUL
        M 0x20200080UL, 0xed7895add9e8b22fUL
        M 0x20200088UL, 0xfb767eb2e017aa1eUL ]
    given0
    |> run um [ "20447008" ]
    |> is [ G 16, 0xed7895add9e8b22fUL; G 17, 0xfb767eb2e017aa1eUL ]
    let given1 =
      [ G 4, 0x20200078UL
        G 16, 0x7fffffffffffffffUL
        G 17, 0x1UL
        M 0x20200078UL, 0x50c0b28a0601c3dfUL
        M 0x20200080UL, 0xde82b872f8f274daUL
        M 0x20200088UL, 0x3c8805ccb2783439UL ]
    given1
    |> run um [ "20447008" ]
    |> is [ G 16, 0xde82b872f8f274daUL; G 17, 0x3c8805ccb2783439UL ]
    let given2 =
      [ G 4, 0x20200078UL
        G 16, 0x123456789abcdefUL
        G 17, 0xfedcba9876543210UL
        M 0x20200078UL, 0xfa10dc5d2b043858UL
        M 0x20200080UL, 0xbabaa95e5a789274UL
        M 0x20200088UL, 0x24c16fa9855a083bUL ]
    given2
    |> run um [ "20447008" ]
    |> is [ G 16, 0xbabaa95e5a789274UL; G 17, 0x24c16fa9855a083bUL ]

  /// <summary>
  /// 20444008, ldp v0, v1, 8(a0), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after ld $2,8($4); ld $3,16($4), the MIPS64 instruction binutils
  /// reads this word as. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LDP``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x3UL
        G 4, 0x20200078UL
        M 0x20200078UL, 0x4080e5e7b00d8b62UL
        M 0x20200080UL, 0x845f704d569ecdbbUL
        M 0x20200088UL, 0x7fe419e97141fb2aUL ]
    given0
    |> run um [ "20444008" ]
    |> is [ G 2, 0x845f704d569ecdbbUL; G 3, 0x7fe419e97141fb2aUL ]
    let given1 =
      [ G 2, 0x7fffffffffffffffUL
        G 3, 0x1UL
        G 4, 0x20200078UL
        M 0x20200078UL, 0x5536d28a94101c5dUL
        M 0x20200080UL, 0xb85714e23168c88dUL
        M 0x20200088UL, 0xb99318cb1d7af2e9UL ]
    given1
    |> run um [ "20444008" ]
    |> is [ G 2, 0xb85714e23168c88dUL; G 3, 0xb99318cb1d7af2e9UL ]
    let given2 =
      [ G 2, 0x123456789abcdefUL
        G 3, 0xfedcba9876543210UL
        G 4, 0x20200078UL
        M 0x20200078UL, 0xa84bb0a5cf63887bUL
        M 0x20200080UL, 0x67938a78d290f463UL
        M 0x20200088UL, 0x5cecc62518211570UL ]
    given2
    |> run um [ "20444008" ]
    |> is [ G 2, 0x67938a78d290f463UL; G 3, 0x5cecc62518211570UL ]

  /// <summary>
  /// 61095001, ldr a4, 1(a5), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after ldr $8,1($9), the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LDR``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x20200080UL
        M 0x20200078UL, 0x3cfb40b0ef9c7459UL
        M 0x20200080UL, 0xfdedded5cf56b7abUL
        M 0x20200088UL, 0xb3f8753e878f3fd3UL ]
    given0
    |> run um [ "61095001" ]
    |> is [ G 8, 0xfdedUL ]
    let given1 =
      [ G 8, 0x7fffffffffffffffUL
        G 9, 0x20200081UL
        M 0x20200078UL, 0xd932f6b028fa9e7bUL
        M 0x20200080UL, 0xeb4f9b18eb7e43fcUL
        M 0x20200088UL, 0x82bce50360b30de0UL ]
    given1
    |> run um [ "61095001" ]
    |> is [ G 8, 0x7fffffffffeb4f9bUL ]
    let given2 =
      [ G 8, 0x123456789abcdefUL
        G 9, 0x20200084UL
        M 0x20200078UL, 0xb054e8716fe14156UL
        M 0x20200080UL, 0x7ea1def79b393499UL
        M 0x20200088UL, 0x9d292378ca743515UL ]
    given2
    |> run um [ "61095001" ]
    |> is [ G 8, 0x1237ea1def79b39UL ]

  /// <summary>
  /// 552810c8, ldxc1 f2, a5(a4), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after ldxc1 $f2,$9($8), the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LDXC1``() =
    let given0 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0xbff0000000000000UL
        M 0x20200078UL, 0x9cf1a0ca54641636UL
        M 0x20200080UL, 0x4f706b4ef9483f79UL
        M 0x20200088UL, 0xdf0c38f5a46e1be1UL ]
    given0
    |> run um [ "552810c8" ]
    |> is [ F 2, 0x4f706b4ef9483f79UL ]
    let given1 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0x400c000000000000UL
        M 0x20200078UL, 0x891b0ec9c8bafa51UL
        M 0x20200080UL, 0xaeabed27d22be16UL
        M 0x20200088UL, 0x170ef0ab51c624bdUL ]
    given1
    |> run um [ "552810c8" ]
    |> is [ F 2, 0xaeabed27d22be16UL ]
    let given2 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0x3fd0000000000000UL
        M 0x20200078UL, 0x8cf99becc9551543UL
        M 0x20200080UL, 0xc87db1b66814b13bUL
        M 0x20200088UL, 0xd5997a560eb82e60UL ]
    given2
    |> run um [ "552810c8" ]
    |> is [ F 2, 0xc87db1b66814b13bUL ]

  /// <summary>
  /// 3d090001, lh a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LH``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x1269e668c5b04c54UL
        M 0x20200080UL, 0xf2ec55aed372641bUL
        M 0x20200088UL, 0xf565910831e8fdc8UL ]
    given0
    |> run um [ "3d090001" ]
    |> is [ G 8, 0xfffffffffffff2ecUL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0xba3995c7b79b4c9UL
        M 0x20200080UL, 0xabaac5e0fa097690UL
        M 0x20200088UL, 0x1ebcf4c499ceca88UL ]
    given1
    |> run um [ "3d090001" ]
    |> is [ G 8, 0xffffffffffffabaaUL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x1e988eca98aef980UL
        M 0x20200080UL, 0xd5cd2a13cfebb9c7UL
        M 0x20200088UL, 0xab82ba98ad43109cUL ]
    given2
    |> run um [ "3d090001" ]
    |> is [ G 8, 0xffffffffffffd5cdUL ]

  /// <summary>
  /// 61096a01, lhe a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LHE``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xd3736001a222376bUL
        M 0x20200080UL, 0xa2b6a3a14c0a212fUL
        M 0x20200088UL, 0x4d122fac5cf950deUL ]
    given0
    |> run um [ "61096a01" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xe406a6f32ea2ea9eUL
        M 0x20200080UL, 0x69944239bc17b670UL
        M 0x20200088UL, 0xd2e9159e9aef8884UL ]
    given1
    |> run um [ "61096a01" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xaec8ba8ee5ef3d54UL
        M 0x20200080UL, 0x40f268360331f2dfUL
        M 0x20200088UL, 0xb806285b1c4a8f46UL ]
    given2
    |> run um [ "61096a01" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 35090001, lhu a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LHU``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x8a55f23b81f4f3c6UL
        M 0x20200080UL, 0xe13f765516837fa8UL
        M 0x20200088UL, 0x3d05be6673094397UL ]
    given0
    |> run um [ "35090001" ]
    |> is [ G 8, 0xe13fUL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x13c075a977686442UL
        M 0x20200080UL, 0x721044643a08132cUL
        M 0x20200088UL, 0x179ae07e7a49262fUL ]
    given1
    |> run um [ "35090001" ]
    |> is [ G 8, 0x7210UL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x545ecb306c8050b7UL
        M 0x20200080UL, 0x311626417289dbd7UL
        M 0x20200088UL, 0x965b2a6b0ab0e762UL ]
    given2
    |> run um [ "35090001" ]
    |> is [ G 8, 0x3116UL ]

  /// <summary>
  /// 2901, lhu v0, 2(s0), against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LHU16``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0x439f0da0e050cb1eUL
        M 0x20200080UL, 0x978d421fe1f21a3fUL
        M 0x20200088UL, 0x49c62b9368eb8c50UL ]
    given0
    |> run um [ "2901" ]
    |> is [ G 2, 0x978dUL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0x43e6299f74c2e5ecUL
        M 0x20200080UL, 0x9556cdb84b7ec920UL
        M 0x20200088UL, 0x2d4f4444306c14c6UL ]
    given1
    |> run um [ "2901" ]
    |> is [ G 2, 0x9556UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0x53de71ba0666239fUL
        M 0x20200080UL, 0xd4d0af2d0c246320UL
        M 0x20200088UL, 0x6ffd80863da46e48UL ]
    given2
    |> run um [ "2901" ]
    |> is [ G 2, 0xd4d0UL ]

  /// <summary>
  /// 61096201, lhue a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LHUE``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xe50ee0c6d801301UL
        M 0x20200080UL, 0xbc2a46ea3d6c7951UL
        M 0x20200088UL, 0x4b8c9c7418b889b1UL ]
    given0
    |> run um [ "61096201" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x83e8141b5d69af25UL
        M 0x20200080UL, 0xd1eb49cf70daf60bUL
        M 0x20200088UL, 0x281a751341022d53UL ]
    given1
    |> run um [ "61096201" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xd5078017d26d4230UL
        M 0x20200080UL, 0xc17c8638f32567b7UL
        M 0x20200088UL, 0xdfe277efa35999dcUL ]
    given2
    |> run um [ "61096201" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// ed01, addiu v0, r0, 0x1, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LI16``() =
    [ G 2, 0x7UL ]
    |> run um [ "ed01" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0x7fffffffUL ]
    |> run um [ "ed01" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run um [ "ed01" ]
    |> is [ G 2, 0x1UL ]

  /// <summary>
  /// 61093001, ll a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LL``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x3805cd4cd1844ed5UL
        M 0x20200080UL, 0x52d58f720b7b547eUL
        M 0x20200088UL, 0xc1d4a1f81f8388e8UL ]
    given0
    |> run um [ "61093001" ]
    |> is [ G 8, 0x52d58f72UL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0xed4ea7234d755650UL
        M 0x20200080UL, 0xdc3fbea550753fdfUL
        M 0x20200088UL, 0xadb1b4f44ea50c35UL ]
    given1
    |> run um [ "61093001" ]
    |> is [ G 8, 0xffffffffdc3fbea5UL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x7c9464b6677d2f3UL
        M 0x20200080UL, 0xdd42d3bf350685e7UL
        M 0x20200088UL, 0xbc3c1cdb9a9d33cbUL ]
    given2
    |> run um [ "61093001" ]
    |> is [ G 8, 0xffffffffdd42d3bfUL ]

  /// <summary>
  /// 61097001, lld a4, 1(a5), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after lld $8,1($9), the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LLD``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x636335ec30cee6cUL
        M 0x20200080UL, 0xa0f7746b2d605798UL
        M 0x20200088UL, 0xa467b575bd490bd6UL ]
    given0
    |> run um [ "61097001" ]
    |> is [ G 8, 0xa0f7746b2d605798UL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x33fc2fb328a1ef88UL
        M 0x20200080UL, 0xf6f312a71bf68265UL
        M 0x20200088UL, 0x6cee1408f15643e2UL ]
    given1
    |> run um [ "61097001" ]
    |> is [ G 8, 0xf6f312a71bf68265UL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x6b582c22ba15bbdcUL
        M 0x20200080UL, 0x29e0cfcb8e89d42cUL
        M 0x20200088UL, 0x7b307cdcfd140b07UL ]
    given2
    |> run um [ "61097001" ]
    |> is [ G 8, 0x29e0cfcb8e89d42cUL ]

  /// <summary>
  /// 61096c01, lle a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LLE``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xebccab4105d3608UL
        M 0x20200080UL, 0xf1cd1deaa0449236UL
        M 0x20200088UL, 0x4ff8fd674aabdb96UL ]
    given0
    |> run um [ "61096c01" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xd1d1bc80cc52bf61UL
        M 0x20200080UL, 0x345481a2af77ee9UL
        M 0x20200088UL, 0xb46f14ac86b34570UL ]
    given1
    |> run um [ "61096c01" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x34aa33bdae21c38fUL
        M 0x20200080UL, 0x717c903a6a9f7795UL
        M 0x20200088UL, 0x93b533684a3976fbUL ]
    given2
    |> run um [ "61096c01" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 41a80001, lui a4, 0x1, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LUI``() =
    [ G 8, 0x7UL ]
    |> run um [ "41a80001" ]
    |> is [ G 8, 0x10000UL ]
    [ G 8, 0x7fffffffUL ]
    |> run um [ "41a80001" ]
    |> is [ G 8, 0x10000UL ]
    [ G 8, 0xffffffff89abcdefUL ]
    |> run um [ "41a80001" ]
    |> is [ G 8, 0x10000UL ]

  /// <summary>
  /// 55281148, luxc1 f2, a5(a4), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after luxc1 $f2,$9($8), the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LUXC1``() =
    let given0 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0xbff0000000000000UL
        M 0x20200078UL, 0xb4a931434431b9d9UL
        M 0x20200080UL, 0x6e8e89ef8c5d8a44UL
        M 0x20200088UL, 0x4fce75340a133b51UL ]
    given0
    |> run um [ "55281148" ]
    |> is [ F 2, 0x6e8e89ef8c5d8a44UL ]
    let given1 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0x400c000000000000UL
        M 0x20200078UL, 0x3ca0557c68c4149bUL
        M 0x20200080UL, 0xa5684c51f6d04cbaUL
        M 0x20200088UL, 0xd8f63937c1416d21UL ]
    given1
    |> run um [ "55281148" ]
    |> is [ F 2, 0xa5684c51f6d04cbaUL ]
    let given2 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0x3fd0000000000000UL
        M 0x20200078UL, 0x3920c5c31acd265bUL
        M 0x20200080UL, 0x3ca1401d4ad0f5d2UL
        M 0x20200088UL, 0x9063bbf7b61317afUL ]
    given2
    |> run um [ "55281148" ]
    |> is [ F 2, 0x3ca1401d4ad0f5d2UL ]

  /// <summary>
  /// 4821, lw at, 4(sp), against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LW``() =
    let given0 =
      [ G 1, 0x7UL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0xa020fcf6a1963728UL
        M 0x20200080UL, 0x3122c0fc221f6608UL
        M 0x20200088UL, 0x6be54e95871dc22eUL ]
    given0
    |> run um [ "4821" ]
    |> is [ G 1, 0x3122c0fcUL ]
    let given1 =
      [ G 1, 0x7fffffffUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x929bc8dcc123e82fUL
        M 0x20200080UL, 0xd5f5642548db8a3bUL
        M 0x20200088UL, 0xcd6be721fe9e6963UL ]
    given1
    |> run um [ "4821" ]
    |> is [ G 1, 0xffffffffd5f56425UL ]
    let given2 =
      [ G 1, 0xffffffff89abcdefUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x930da9d86b59da06UL
        M 0x20200080UL, 0x7ca10f278c3bd4f7UL
        M 0x20200088UL, 0x28c40efa3708ad17UL ]
    given2
    |> run um [ "4821" ]
    |> is [ G 1, 0x7ca10f27UL ]

  /// <summary>
  /// 4821, lw at, 4(sp), against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LW16``() =
    let given0 =
      [ G 1, 0x7UL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0xb28a0dde6bfdfa2aUL
        M 0x20200080UL, 0x69810fbc41e5e20dUL
        M 0x20200088UL, 0xa4866dc3519dd8b1UL ]
    given0
    |> run um [ "4821" ]
    |> is [ G 1, 0x69810fbcUL ]
    let given1 =
      [ G 1, 0x7fffffffUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0xb34255fe7bbf7ca1UL
        M 0x20200080UL, 0xf4ef2b2a20d1a273UL
        M 0x20200088UL, 0x23c70b61738f6c0cUL ]
    given1
    |> run um [ "4821" ]
    |> is [ G 1, 0xfffffffff4ef2b2aUL ]
    let given2 =
      [ G 1, 0xffffffff89abcdefUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x7ff17e5afd0cf5afUL
        M 0x20200080UL, 0xca25dd1a9352a159UL
        M 0x20200088UL, 0x75322945a368a4d0UL ]
    given2
    |> run um [ "4821" ]
    |> is [ G 1, 0xffffffffca25dd1aUL ]

  /// <summary>
  /// 9c480001, lwc1 f2, 1(a4), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after lwc1 $f2,1($8), the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LWC1``() =
    let given0 =
      [ G 8, 0x2020007fUL
        F 2, 0xbf800000UL
        M 0x20200078UL, 0x608c1e952f1eee1eUL
        M 0x20200080UL, 0x5132041d2d6980c5UL
        M 0x20200088UL, 0x34c2454c85e3016aUL ]
    given0
    |> run um [ "9c480001" ]
    |> is [ F 2, 0x5132041dUL ]
    let given1 =
      [ G 8, 0x2020007fUL
        F 2, 0x40600000UL
        M 0x20200078UL, 0xd7d9cdce80d41453UL
        M 0x20200080UL, 0x442be94c2ccd0bc5UL
        M 0x20200088UL, 0xe4e9512d42328b5fUL ]
    given1
    |> run um [ "9c480001" ]
    |> is [ F 2, 0x442be94cUL ]
    let given2 =
      [ G 8, 0x2020007fUL
        F 2, 0x3e800000UL
        M 0x20200078UL, 0xc31df1cc3d170e52UL
        M 0x20200080UL, 0xf9a4657ce6d67839UL
        M 0x20200088UL, 0x9850618cb605111aUL ]
    given2
    |> run um [ "9c480001" ]
    |> is [ F 2, 0xf9a4657cUL ]

  /// <summary>
  /// 20000001, lwc2 0x0, 1(r0), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LWC2``() =
    let given0 =
      [ M 0x20200078UL, 0xb435616f82e24b9cUL
        M 0x20200080UL, 0x7f07d2ca3ea5a706UL
        M 0x20200088UL, 0x3dd09225650454daUL ]
    given0
    |> run um [ "20000001" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ M 0x20200078UL, 0x17645395c2836924UL
        M 0x20200080UL, 0xa7a5b4a147ffae1eUL
        M 0x20200088UL, 0x97b578160a57b9dcUL ]
    given1
    |> run um [ "20000001" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ M 0x20200078UL, 0xcd52e41d1488386cUL
        M 0x20200080UL, 0xd78e7a76af0a9c98UL
        M 0x20200088UL, 0x4db6283b0e2e44bUL ]
    given2
    |> run um [ "20000001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 61096e01, lwe a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LWE``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x90b672a70898e683UL
        M 0x20200080UL, 0x59d95a8c34b18097UL
        M 0x20200088UL, 0x933a8872232a58b9UL ]
    given0
    |> run um [ "61096e01" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xde89528065b729adUL
        M 0x20200080UL, 0x912a6e097e173211UL
        M 0x20200088UL, 0x400cee05bc68dcb2UL ]
    given1
    |> run um [ "61096e01" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xf99a7bf337a4846aUL
        M 0x20200080UL, 0x2b6ef301ad5a9d75UL
        M 0x20200088UL, 0xad4e5c9eb7e287f2UL ]
    given2
    |> run um [ "61096e01" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 4821, lw at, 4(sp), against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LWGP``() =
    let given0 =
      [ G 1, 0x7UL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x46248a276cb0a5b5UL
        M 0x20200080UL, 0x1ae321647d7facc2UL
        M 0x20200088UL, 0xf97a06124f6d10f3UL ]
    given0
    |> run um [ "4821" ]
    |> is [ G 1, 0x1ae32164UL ]
    let given1 =
      [ G 1, 0x7fffffffUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0xa4633f63f930b062UL
        M 0x20200080UL, 0xc5d6c089567c54daUL
        M 0x20200088UL, 0x4d121fd046dde9acUL ]
    given1
    |> run um [ "4821" ]
    |> is [ G 1, 0xffffffffc5d6c089UL ]
    let given2 =
      [ G 1, 0xffffffff89abcdefUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x8885484d47376f4bUL
        M 0x20200080UL, 0x4492da8111833e9fUL
        M 0x20200088UL, 0x47442e79e0fbe105UL ]
    given2
    |> run um [ "4821" ]
    |> is [ G 1, 0x4492da81UL ]

  /// <summary>
  /// 61090001, lwl a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LWL``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x20200080UL
        M 0x20200078UL, 0x4b34625818852a4eUL
        M 0x20200080UL, 0x6c08db015dbd4cafUL
        M 0x20200088UL, 0x6789a56dded7bfc2UL ]
    given0
    |> run um [ "61090001" ]
    |> is [ G 8, 0x8db0107UL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x20200081UL
        M 0x20200078UL, 0x34a83defb6a414c3UL
        M 0x20200080UL, 0xc0f0baa73220ba5cUL
        M 0x20200088UL, 0x409b3ebf33d7faa4UL ]
    given1
    |> run um [ "61090001" ]
    |> is [ G 8, 0xffffffffbaa7ffffUL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x20200084UL
        M 0x20200078UL, 0xf9e2076db183bc7aUL
        M 0x20200080UL, 0x40466ca17968d23UL
        M 0x20200088UL, 0x9bea88095cde652dUL ]
    given2
    |> run um [ "61090001" ]
    |> is [ G 8, 0xffffffff968d23efUL ]

  /// <summary>
  /// 61096401, lwle a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LWLE``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x20200080UL
        Status, 0x10UL
        M 0x20200078UL, 0xa8feef83d42bd6c8UL
        M 0x20200080UL, 0xbf58575cd2c5b5e1UL
        M 0x20200088UL, 0xd8d4ced65dd53b3cUL ]
    given0
    |> run um [ "61096401" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x20200081UL
        Status, 0x10UL
        M 0x20200078UL, 0xa3d0e9f671ebd395UL
        M 0x20200080UL, 0xb3a52e1626cc9f57UL
        M 0x20200088UL, 0xa8258fb1f64c94d4UL ]
    given1
    |> run um [ "61096401" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x20200084UL
        Status, 0x10UL
        M 0x20200078UL, 0x3566caa61c92cff1UL
        M 0x20200080UL, 0xb7b1743528c05aefUL
        M 0x20200088UL, 0x21bc1bd66d07eed1UL ]
    given2
    |> run um [ "61096401" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 4501, lwm s0, ra, 4(sp), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LWM16``() =
    let given0 =
      [ G 16, 0x7UL
        G 29, 0x2020007cUL
        G 31, 0x3UL
        M 0x20200078UL, 0x91c39fb79a415bbcUL
        M 0x20200080UL, 0x7e0a4427674d1230UL
        M 0x20200088UL, 0x72121d5097db54c1UL ]
    given0
    |> run um [ "4501" ]
    |> is [ G 16, 0x7e0a4427UL; G 31, 0x674d1230UL ]
    let given1 =
      [ G 16, 0x7fffffffUL
        G 29, 0x2020007cUL
        G 31, 0x1UL
        M 0x20200078UL, 0x1473be90e2c3e3f1UL
        M 0x20200080UL, 0xc1efa49dad233ac3UL
        M 0x20200088UL, 0x4d2dd0ce2e4d61b8UL ]
    given1
    |> run um [ "4501" ]
    |> is [ G 16, 0xffffffffc1efa49dUL; G 31, 0xffffffffad233ac3UL ]
    let given2 =
      [ G 16, 0xffffffff89abcdefUL
        G 29, 0x2020007cUL
        G 31, 0x12345678UL
        M 0x20200078UL, 0x5d4582b786322398UL
        M 0x20200080UL, 0x3bd4327761f93ed7UL
        M 0x20200088UL, 0x3bf14c41de39a0f4UL ]
    given2
    |> run um [ "4501" ]
    |> is [ G 16, 0x3bd43277UL; G 31, 0x61f93ed7UL ]

  /// <summary>
  /// 20445008, lwm s0, s1, 8(a0), against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LWM32``() =
    let given0 =
      [ G 4, 0x20200078UL
        G 16, 0x7UL
        G 17, 0x3UL
        M 0x20200078UL, 0x1a7c67698b5dabafUL
        M 0x20200080UL, 0xad2afa9e44169adcUL
        M 0x20200088UL, 0xd99ab98d253f5706UL ]
    given0
    |> run um [ "20445008" ]
    |> is [ G 16, 0xffffffffad2afa9eUL; G 17, 0x44169adcUL ]
    let given1 =
      [ G 4, 0x20200078UL
        G 16, 0x7fffffffUL
        G 17, 0x1UL
        M 0x20200078UL, 0xdd6821fb9a90120aUL
        M 0x20200080UL, 0xc39851c62cee62edUL
        M 0x20200088UL, 0xc175cd3b881a2017UL ]
    given1
    |> run um [ "20445008" ]
    |> is [ G 16, 0xffffffffc39851c6UL; G 17, 0x2cee62edUL ]
    let given2 =
      [ G 4, 0x20200078UL
        G 16, 0xffffffff89abcdefUL
        G 17, 0x12345678UL
        M 0x20200078UL, 0x1ea9084008959590UL
        M 0x20200080UL, 0xfafd707203b228faUL
        M 0x20200088UL, 0xbd0579fa31858366UL ]
    given2
    |> run um [ "20445008" ]
    |> is [ G 16, 0xfffffffffafd7072UL; G 17, 0x3b228faUL ]

  /// <summary>
  /// 20441008, lwp v0, v1, 8(a0), against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LWP``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x3UL
        G 4, 0x20200078UL
        M 0x20200078UL, 0xbcab2d2c134dcc83UL
        M 0x20200080UL, 0x3a3c983481fd5c70UL
        M 0x20200088UL, 0x25aa1e9cf94b3a29UL ]
    given0
    |> run um [ "20441008" ]
    |> is [ G 2, 0x3a3c9834UL; G 3, 0xffffffff81fd5c70UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x1UL
        G 4, 0x20200078UL
        M 0x20200078UL, 0xec2d8aa178dff12dUL
        M 0x20200080UL, 0x846ca9bfaf89f4a7UL
        M 0x20200088UL, 0x43b35c82f273917UL ]
    given1
    |> run um [ "20441008" ]
    |> is [ G 2, 0xffffffff846ca9bfUL; G 3, 0xffffffffaf89f4a7UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x12345678UL
        G 4, 0x20200078UL
        M 0x20200078UL, 0xa36d1196a4535b6cUL
        M 0x20200080UL, 0xa877e8fd82abdd45UL
        M 0x20200088UL, 0x7d34115bdc5dbca4UL ]
    given2
    |> run um [ "20441008" ]
    |> is [ G 2, 0xffffffffa877e8fdUL; G 3, 0xffffffff82abdd45UL ]

  /// <summary>
  /// 61091001, lwr a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LWR``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x20200080UL
        M 0x20200078UL, 0x425c08f8a3919e1bUL
        M 0x20200080UL, 0x9da069c9bcad8b8UL
        M 0x20200088UL, 0xd740c3d80e33befcUL ]
    given0
    |> run um [ "61091001" ]
    |> is [ G 8, 0x9daUL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x20200081UL
        M 0x20200078UL, 0xafc5d8062f66109cUL
        M 0x20200080UL, 0x1cc403c55f6a807UL
        M 0x20200088UL, 0xafd59e77593e5334UL ]
    given1
    |> run um [ "61091001" ]
    |> is [ G 8, 0x7f01cc40UL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x20200084UL
        M 0x20200078UL, 0x1347a8cfe223d3b1UL
        M 0x20200080UL, 0x33cfd239dee6372dUL
        M 0x20200088UL, 0xfec2421c69fbdba5UL ]
    given2
    |> run um [ "61091001" ]
    |> is [ G 8, 0xffffffff89abdee6UL ]

  /// <summary>
  /// 61096601, lwre a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LWRE``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x20200080UL
        Status, 0x10UL
        M 0x20200078UL, 0xf02c2da7f9332723UL
        M 0x20200080UL, 0xd3e82d880f65ac1UL
        M 0x20200088UL, 0x5d6e70dc2a9ca94aUL ]
    given0
    |> run um [ "61096601" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x20200081UL
        Status, 0x10UL
        M 0x20200078UL, 0xa4bb441838b725bdUL
        M 0x20200080UL, 0xfdde5998ef3ac42dUL
        M 0x20200088UL, 0x80478c9dd884fb8dUL ]
    given1
    |> run um [ "61096601" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x20200084UL
        Status, 0x10UL
        M 0x20200078UL, 0xd6db39b17ab40128UL
        M 0x20200080UL, 0xb33389bb8534b5a5UL
        M 0x20200088UL, 0x7638dadae6410216UL ]
    given2
    |> run um [ "61096601" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 4821, lw at, 4(sp), against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LWSP``() =
    let given0 =
      [ G 1, 0x7UL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0xbfc79a580c668794UL
        M 0x20200080UL, 0x5ab74a04244fbf28UL
        M 0x20200088UL, 0xb59fadf5c2265d52UL ]
    given0
    |> run um [ "4821" ]
    |> is [ G 1, 0x5ab74a04UL ]
    let given1 =
      [ G 1, 0x7fffffffUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0xb8800bf419568d4fUL
        M 0x20200080UL, 0xd8afffd02ca9ac4eUL
        M 0x20200088UL, 0x1778582e94e587fbUL ]
    given1
    |> run um [ "4821" ]
    |> is [ G 1, 0xffffffffd8afffd0UL ]
    let given2 =
      [ G 1, 0xffffffff89abcdefUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x1526fdc747232cd4UL
        M 0x20200080UL, 0x19e1ce73bab116faUL
        M 0x20200088UL, 0x24e40ed190a3e69bUL ]
    given2
    |> run um [ "4821" ]
    |> is [ G 1, 0x19e1ce73UL ]

  /// <summary>
  /// 6109e001, lwu a4, 1(a5), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after lwu $8,1($9), the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LWU``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x1343e3a471a498ffUL
        M 0x20200080UL, 0x9c038af997ad7f9bUL
        M 0x20200088UL, 0x7626b3ffec9fce17UL ]
    given0
    |> run um [ "6109e001" ]
    |> is [ G 8, 0x9c038af9UL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0xdccba52a288c2a5fUL
        M 0x20200080UL, 0xb91ef9189222857fUL
        M 0x20200088UL, 0xe85d5fa5eb47fe8cUL ]
    given1
    |> run um [ "6109e001" ]
    |> is [ G 8, 0xb91ef918UL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0xcd7c6881fe226d1cUL
        M 0x20200080UL, 0xe9477cf0b759cd3aUL
        M 0x20200088UL, 0x67c4f1615c382b46UL ]
    given2
    |> run um [ "6109e001" ]
    |> is [ G 8, 0xe9477cf0UL ]

  /// <summary>
  /// 55281048, lwxc1 f2, a5(a4), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after lwxc1 $f2,$9($8), the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LWXC1``() =
    let given0 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0xbf800000UL
        M 0x20200078UL, 0xd309be4a58a640adUL
        M 0x20200080UL, 0x77126cc324337ed6UL
        M 0x20200088UL, 0x6e3bba6882d154ddUL ]
    given0
    |> run um [ "55281048" ]
    |> is [ F 2, 0x77126cc3UL ]
    let given1 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0x40600000UL
        M 0x20200078UL, 0x1e5949498280908eUL
        M 0x20200080UL, 0x5dc82eb8c4f3e26bUL
        M 0x20200088UL, 0x5d3271e98784084cUL ]
    given1
    |> run um [ "55281048" ]
    |> is [ F 2, 0x5dc82eb8UL ]
    let given2 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0x3e800000UL
        M 0x20200078UL, 0xc0cfad405bce031aUL
        M 0x20200080UL, 0xe35bc70c66488c80UL
        M 0x20200088UL, 0x43f7d12fc931e042UL ]
    given2
    |> run um [ "55281048" ]
    |> is [ F 2, 0xe35bc70cUL ]

  /// <summary>
  /// 01494118, lwxs a4, a6(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LWXS``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x20200078UL
        G 10, 0x2UL
        M 0x20200078UL, 0xb1166d42295d8db8UL
        M 0x20200080UL, 0x438c5438d62f127bUL
        M 0x20200088UL, 0x458119b8cde9c00bUL ]
    given0
    |> run um [ "01494118" ]
    |> is [ G 8, 0x438c5438UL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x20200078UL
        G 10, 0x2UL
        M 0x20200078UL, 0xcb41bbdee547b354UL
        M 0x20200080UL, 0x947880437f777a84UL
        M 0x20200088UL, 0x6167174f25e7cee7UL ]
    given1
    |> run um [ "01494118" ]
    |> is [ G 8, 0xffffffff94788043UL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x20200078UL
        G 10, 0x2UL
        M 0x20200078UL, 0x5c666081d6852d9bUL
        M 0x20200080UL, 0xdedc8fda0f0a9b16UL
        M 0x20200088UL, 0xb23a712f359c725cUL ]
    given2
    |> run um [ "01494118" ]
    |> is [ G 8, 0xffffffffdedc8fdaUL ]

  /// <summary>
  /// 0128cb3c, madd a4, a5, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MADD``() =
    [ G 8, 0x7UL; G 9, 0x3UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run um [ "0128cb3c" ]
    |> is [ Lo, 0x39UL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x1UL
        Hi, 0x7fffffffUL
        Lo, 0xffffffff80000001UL ]
    given1
    |> run um [ "0128cb3c" ]
    |> is [ Hi, 0xffffffff80000000UL; Lo, 0x0UL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x12345678UL
        Hi, 0xffffffffdeadbeefUL
        Lo, 0x12345678UL ]
    given2
    |> run um [ "0128cb3c" ]
    |> is [ Hi, 0xffffffffd643a257UL; Lo, 0xfffffffff4772880UL ]

  /// <summary>
  /// 55061101, madd.s f2, f4, f6, f8, against QEMU's MIPS64R2-generic: QEMU has
  /// no microMIPS64 or microMIPS processor with an FPU, so the values are what
  /// it left after madd.s $f2,$f4,$f6,$f8, the MIPS64 instruction binutils
  /// reads this word as. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MADD.fmt``() =
    let given0 =
      [ F 2, 0xbf800000UL
        F 4, 0x40100000UL
        F 6, 0x3fc00000UL
        F 8, 0x3f000000UL ]
    given0
    |> run um [ "55061101" ]
    |> is [ F 2, 0x40400000UL ]
    let given1 =
      [ F 2, 0x40600000UL
        F 4, 0xc0c00000UL
        F 6, 0x3f400000UL
        F 8, 0x40800000UL ]
    given1
    |> run um [ "55061101" ]
    |> is [ F 2, 0xc0400000UL ]
    let given2 =
      [ F 2, 0x3e800000UL
        F 4, 0x447a0000UL
        F 6, 0x3e000000UL
        F 8, 0xc0200000UL ]
    given2
    |> run um [ "55061101" ]
    |> is [ F 2, 0x4479ec00UL ]

  /// <summary>
  /// 0128db3c, maddu a4, a5, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MADDU``() =
    [ G 8, 0x7UL; G 9, 0x3UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run um [ "0128db3c" ]
    |> is [ Lo, 0x39UL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x1UL
        Hi, 0x7fffffffUL
        Lo, 0xffffffff80000001UL ]
    given1
    |> run um [ "0128db3c" ]
    |> is [ Hi, 0xffffffff80000000UL; Lo, 0x0UL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x12345678UL
        Hi, 0xffffffffdeadbeefUL
        Lo, 0x12345678UL ]
    given2
    |> run um [ "0128db3c" ]
    |> is [ Hi, 0xffffffffe877f8cfUL; Lo, 0xfffffffff4772880UL ]

  /// <summary>
  /// 002208fc, mfc0 at, 0x2, 0x1, against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. QEMU raised SIGILL (UndefinedInstruction here); Status =
  /// 0x10 puts the lift in User Mode, the mode QEMU runs every word in; the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MFC0``() =
    [ G 1, 0x7UL; Status, 0x10UL ]
    |> run um [ "002208fc" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL; Status, 0x10UL ]
    |> run um [ "002208fc" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL; Status, 0x10UL ]
    |> run um [ "002208fc" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 5502203b, mfc1 a4, f2, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after mfc1 $8,$f2, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MFC1``() =
    [ G 8, 0x7UL; F 2, 0x1122334455667788UL ]
    |> run um [ "5502203b" ]
    |> is [ G 8, 0x55667788UL ]
    [ G 8, 0x7fffffffUL; F 2, 0xbf800000UL ]
    |> run um [ "5502203b" ]
    |> is [ G 8, 0xffffffffbf800000UL ]
    [ G 8, 0xffffffff89abcdefUL; F 2, 0x8899aabbccddeeffUL ]
    |> run um [ "5502203b" ]
    |> is [ G 8, 0xffffffffccddeeffUL ]

  /// <summary>
  /// 00224d3c, mfc2 at, 0x2, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MFC2``() =
    [ G 1, 0x7UL ]
    |> run um [ "00224d3c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL ]
    |> run um [ "00224d3c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL ]
    |> run um [ "00224d3c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 002208f4, mfhc0 at, 0x2, 0x1, against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. QEMU raised SIGILL (UndefinedInstruction here); Status =
  /// 0x10 puts the lift in User Mode, the mode QEMU runs every word in; the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MFHC0``() =
    [ G 1, 0x7UL; Status, 0x10UL ]
    |> run um [ "002208f4" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL; Status, 0x10UL ]
    |> run um [ "002208f4" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL; Status, 0x10UL ]
    |> run um [ "002208f4" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 5502303b, mfhc1 a4, f2, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after mfhc1 $8,$f2, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MFHC1``() =
    [ G 8, 0x7UL; F 2, 0x1122334455667788UL ]
    |> run um [ "5502303b" ]
    |> is [ G 8, 0x11223344UL ]
    [ G 8, 0x7fffffffffffffffUL; F 2, 0xbf800000UL ]
    |> run um [ "5502303b" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x123456789abcdefUL; F 2, 0x8899aabbccddeeffUL ]
    |> run um [ "5502303b" ]
    |> is [ G 8, 0xffffffff8899aabbUL ]

  /// <summary>
  /// 00228d3c, mfhc2 at, 0x2, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MFHC2``() =
    [ G 1, 0x7UL ]
    |> run um [ "00228d3c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL ]
    |> run um [ "00228d3c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL ]
    |> run um [ "00228d3c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 00220d7c, mfhi v0, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MFHI``() =
    [ G 2, 0x7UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run um [ "00220d7c" ]
    |> is [ G 2, 0x13UL ]
    [ G 2, 0x7fffffffUL; Hi, 0x7fffffffUL; Lo, 0xffffffff80000001UL ]
    |> run um [ "00220d7c" ]
    |> is []
    [ G 2, 0xffffffff89abcdefUL; Hi, 0xffffffffdeadbeefUL; Lo, 0x12345678UL ]
    |> run um [ "00220d7c" ]
    |> is [ G 2, 0xffffffffdeadbeefUL ]

  /// <summary>
  /// 4601, mfhi at, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MFHI16``() =
    [ G 1, 0x7UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run um [ "4601" ]
    |> is [ G 1, 0x13UL ]
    [ G 1, 0x7fffffffUL; Hi, 0x7fffffffUL; Lo, 0xffffffff80000001UL ]
    |> run um [ "4601" ]
    |> is []
    [ G 1, 0xffffffff89abcdefUL; Hi, 0xffffffffdeadbeefUL; Lo, 0x12345678UL ]
    |> run um [ "4601" ]
    |> is [ G 1, 0xffffffffdeadbeefUL ]

  /// <summary>
  /// 00221d7c, mflo v0, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MFLO``() =
    [ G 2, 0x7UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run um [ "00221d7c" ]
    |> is [ G 2, 0x24UL ]
    [ G 2, 0x7fffffffUL; Hi, 0x7fffffffUL; Lo, 0xffffffff80000001UL ]
    |> run um [ "00221d7c" ]
    |> is [ G 2, 0xffffffff80000001UL ]
    [ G 2, 0xffffffff89abcdefUL; Hi, 0xffffffffdeadbeefUL; Lo, 0x12345678UL ]
    |> run um [ "00221d7c" ]
    |> is [ G 2, 0x12345678UL ]

  /// <summary>
  /// 4641, mflo at, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MFLO16``() =
    [ G 1, 0x7UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run um [ "4641" ]
    |> is [ G 1, 0x24UL ]
    [ G 1, 0x7fffffffUL; Hi, 0x7fffffffUL; Lo, 0xffffffff80000001UL ]
    |> run um [ "4641" ]
    |> is [ G 1, 0xffffffff80000001UL ]
    [ G 1, 0xffffffff89abcdefUL; Hi, 0xffffffffdeadbeefUL; Lo, 0x12345678UL ]
    |> run um [ "4641" ]
    |> is [ G 1, 0x12345678UL ]

  /// <summary>
  /// 5444007b, mov.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after mov.s $f2,$f4, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MOV.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run um [ "5444007b" ]
    |> is [ F 2, 0x40100000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL ]
    |> run um [ "5444007b" ]
    |> is [ F 2, 0xc0c00000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL ]
    |> run um [ "5444007b" ]
    |> is [ F 2, 0x447a0000UL ]

  /// <summary>
  /// 0c22, or at, v0, r0, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVE16``() =
    [ G 1, 0x7UL; G 2, 0x3UL ]
    |> run um [ "0c22" ]
    |> is [ G 1, 0x3UL ]
    [ G 1, 0x7fffffffUL; G 2, 0x1UL ]
    |> run um [ "0c22" ]
    |> is [ G 1, 0x1UL ]
    [ G 1, 0xffffffff89abcdefUL; G 2, 0x12345678UL ]
    |> run um [ "0c22" ]
    |> is [ G 1, 0x12345678UL ]

  /// <summary>
  /// 86a6, movep a0, a1, v1, v0, against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVEP``() =
    [ G 2, 0x2UL; G 3, 0x5UL; G 4, 0x7UL; G 5, 0x3UL ]
    |> run um [ "86a6" ]
    |> is [ G 4, 0x5UL; G 5, 0x2UL ]
    let given1 =
      [ G 2, 0xffffffff80000000UL
        G 3, 0xfffffffffffffffeUL
        G 4, 0x7fffffffUL
        G 5, 0x1UL ]
    given1
    |> run um [ "86a6" ]
    |> is [ G 4, 0xfffffffffffffffeUL; G 5, 0xffffffff80000000UL ]
    let given2 =
      [ G 2, 0xf0f0f0fUL
        G 3, 0xfffffffffedcba98UL
        G 4, 0xffffffff89abcdefUL
        G 5, 0x12345678UL ]
    given2
    |> run um [ "86a6" ]
    |> is [ G 4, 0xfffffffffedcba98UL; G 5, 0xf0f0f0fUL ]

  /// <summary>
  /// 5509217b, movf a4, a5, 0x1, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after movf $8,$9,$fcc1, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVF``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "5509217b" ]
    |> is [ G 8, 0x3UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; Fcsr, 0xfe800000UL ]
    |> run um [ "5509217b" ]
    |> is []
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; Fcsr, 0x800000UL ]
    |> run um [ "5509217b" ]
    |> is [ G 8, 0x12345678UL ]
    [ G 8, 0x7UL; G 9, 0x3UL; Fcsr, 0x2000000UL ]
    |> run um [ "5509217b" ]
    |> is []

  /// <summary>
  /// 54440020, movf.s f2, f4, 0x0, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after movf.s $f2,$f4,$fcc0, the MIPS64 instruction binutils reads
  /// this word as. the lift has to change what QEMU changed and nothing else,
  /// over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVF.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run um [ "54440020" ]
    |> is [ F 2, 0x40100000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; Fcsr, 0xfe800000UL ]
    |> run um [ "54440020" ]
    |> is []
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; Fcsr, 0x800000UL ]
    |> run um [ "54440020" ]
    |> is []
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; Fcsr, 0x2000000UL ]
    |> run um [ "54440020" ]
    |> is [ F 2, 0x40100000UL ]

  /// <summary>
  /// 01494018, movn a4, a5, a6, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVN``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "01494018" ]
    |> is [ G 8, 0x3UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "01494018" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "01494018" ]
    |> is [ G 8, 0x12345678UL ]
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "01494018" ]
    |> is []

  /// <summary>
  /// 55041038, movn.s f2, f4, a4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after movn.s $f2,$f4,$8, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVN.fmt``() =
    [ G 8, 0x7UL; F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run um [ "55041038" ]
    |> is [ F 2, 0x40100000UL ]
    [ G 8, 0x7fffffffUL; F 2, 0x40600000UL; F 4, 0xc0c00000UL ]
    |> run um [ "55041038" ]
    |> is [ F 2, 0xc0c00000UL ]
    [ G 8, 0xffffffff89abcdefUL; F 2, 0x3e800000UL; F 4, 0x447a0000UL ]
    |> run um [ "55041038" ]
    |> is [ F 2, 0x447a0000UL ]
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run um [ "55041038" ]
    |> is []

  /// <summary>
  /// 5509297b, movt a4, a5, 0x1, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after movt $8,$9,$fcc1, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVT``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "5509297b" ]
    |> is []
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; Fcsr, 0xfe800000UL ]
    |> run um [ "5509297b" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; Fcsr, 0x800000UL ]
    |> run um [ "5509297b" ]
    |> is []
    [ G 8, 0x7UL; G 9, 0x3UL; Fcsr, 0x2000000UL ]
    |> run um [ "5509297b" ]
    |> is [ G 8, 0x3UL ]

  /// <summary>
  /// 54440060, movt.s f2, f4, 0x0, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after movt.s $f2,$f4,$fcc0, the MIPS64 instruction binutils reads
  /// this word as. the lift has to change what QEMU changed and nothing else,
  /// over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVT.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run um [ "54440060" ]
    |> is []
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; Fcsr, 0xfe800000UL ]
    |> run um [ "54440060" ]
    |> is [ F 2, 0xc0c00000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; Fcsr, 0x800000UL ]
    |> run um [ "54440060" ]
    |> is [ F 2, 0x447a0000UL ]
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; Fcsr, 0x2000000UL ]
    |> run um [ "54440060" ]
    |> is []

  /// <summary>
  /// 01494058, movz a4, a5, a6, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVZ``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "01494058" ]
    |> is []
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "01494058" ]
    |> is []
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "01494058" ]
    |> is []
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "01494058" ]
    |> is [ G 8, 0x3UL ]

  /// <summary>
  /// 55041078, movz.s f2, f4, a4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after movz.s $f2,$f4,$8, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVZ.fmt``() =
    [ G 8, 0x7UL; F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run um [ "55041078" ]
    |> is []
    [ G 8, 0x7fffffffUL; F 2, 0x40600000UL; F 4, 0xc0c00000UL ]
    |> run um [ "55041078" ]
    |> is []
    [ G 8, 0xffffffff89abcdefUL; F 2, 0x3e800000UL; F 4, 0x447a0000UL ]
    |> run um [ "55041078" ]
    |> is []
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run um [ "55041078" ]
    |> is [ F 2, 0x40100000UL ]

  /// <summary>
  /// 0128eb3c, msub a4, a5, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MSUB``() =
    [ G 8, 0x7UL; G 9, 0x3UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run um [ "0128eb3c" ]
    |> is [ Lo, 0xfUL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x1UL
        Hi, 0x7fffffffUL
        Lo, 0xffffffff80000001UL ]
    given1
    |> run um [ "0128eb3c" ]
    |> is [ Lo, 0x2UL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x12345678UL
        Hi, 0xffffffffdeadbeefUL
        Lo, 0x12345678UL ]
    given2
    |> run um [ "0128eb3c" ]
    |> is [ Hi, 0xffffffffe717db86UL; Lo, 0x2ff18470UL ]

  /// <summary>
  /// 55061121, msub.s f2, f4, f6, f8, against QEMU's MIPS64R2-generic: QEMU has
  /// no microMIPS64 or microMIPS processor with an FPU, so the values are what
  /// it left after msub.s $f2,$f4,$f6,$f8, the MIPS64 instruction binutils
  /// reads this word as. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MSUB.fmt``() =
    let given0 =
      [ F 2, 0xbf800000UL
        F 4, 0x40100000UL
        F 6, 0x3fc00000UL
        F 8, 0x3f000000UL ]
    given0
    |> run um [ "55061121" ]
    |> is [ F 2, 0xbfc00000UL ]
    let given1 =
      [ F 2, 0x40600000UL
        F 4, 0xc0c00000UL
        F 6, 0x3f400000UL
        F 8, 0x40800000UL ]
    given1
    |> run um [ "55061121" ]
    |> is [ F 2, 0x41100000UL ]
    let given2 =
      [ F 2, 0x3e800000UL
        F 4, 0x447a0000UL
        F 6, 0x3e000000UL
        F 8, 0xc0200000UL ]
    given2
    |> run um [ "55061121" ]
    |> is [ F 2, 0xc47a1400UL ]

  /// <summary>
  /// 0128fb3c, msubu a4, a5, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MSUBU``() =
    [ G 8, 0x7UL; G 9, 0x3UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run um [ "0128fb3c" ]
    |> is [ Lo, 0xfUL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x1UL
        Hi, 0x7fffffffUL
        Lo, 0xffffffff80000001UL ]
    given1
    |> run um [ "0128fb3c" ]
    |> is [ Lo, 0x2UL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x12345678UL
        Hi, 0xffffffffdeadbeefUL
        Lo, 0x12345678UL ]
    given2
    |> run um [ "0128fb3c" ]
    |> is [ Hi, 0xffffffffd4e3850eUL; Lo, 0x2ff18470UL ]

  /// <summary>
  /// 00220afc, mtc0 at, 0x2, 0x1, against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. QEMU raised SIGILL (UndefinedInstruction here); Status =
  /// 0x10 puts the lift in User Mode, the mode QEMU runs every word in; the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MTC0``() =
    [ G 1, 0x7UL; Status, 0x10UL ]
    |> run um [ "00220afc" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL; Status, 0x10UL ]
    |> run um [ "00220afc" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL; Status, 0x10UL ]
    |> run um [ "00220afc" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 5502283b, mtc1 a4, f2, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after mtc1 $8,$f2, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MTC1``() =
    [ G 8, 0x7UL; F 2, 0x1122334455667788UL ]
    |> run um [ "5502283b" ]
    |> is [ F 2, 0x1122334400000007UL ]
    [ G 8, 0x7fffffffUL; F 2, 0xbf800000UL ]
    |> run um [ "5502283b" ]
    |> is [ F 2, 0x7fffffffUL ]
    [ G 8, 0xffffffff89abcdefUL; F 2, 0x8899aabbccddeeffUL ]
    |> run um [ "5502283b" ]
    |> is [ F 2, 0x8899aabb89abcdefUL ]

  /// <summary>
  /// 00225d3c, mtc2 at, 0x2, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MTC2``() =
    [ G 1, 0x7UL ]
    |> run um [ "00225d3c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL ]
    |> run um [ "00225d3c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL ]
    |> run um [ "00225d3c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 00220af4, mthc0 at, 0x2, 0x1, against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. QEMU raised SIGILL (UndefinedInstruction here); Status =
  /// 0x10 puts the lift in User Mode, the mode QEMU runs every word in; the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MTHC0``() =
    [ G 1, 0x7UL; Status, 0x10UL ]
    |> run um [ "00220af4" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL; Status, 0x10UL ]
    |> run um [ "00220af4" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL; Status, 0x10UL ]
    |> run um [ "00220af4" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 5502383b, mthc1 a4, f2, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after mthc1 $8,$f2, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MTHC1``() =
    [ G 8, 0x7UL; F 2, 0x1122334455667788UL ]
    |> run um [ "5502383b" ]
    |> is [ F 2, 0x755667788UL ]
    [ G 8, 0x7fffffffffffffffUL; F 2, 0xbf800000UL ]
    |> run um [ "5502383b" ]
    |> is [ F 2, 0xffffffffbf800000UL ]
    [ G 8, 0x123456789abcdefUL; F 2, 0x8899aabbccddeeffUL ]
    |> run um [ "5502383b" ]
    |> is [ F 2, 0x89abcdefccddeeffUL ]

  /// <summary>
  /// 00229d3c, mthc2 at, 0x2, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MTHC2``() =
    [ G 1, 0x7UL ]
    |> run um [ "00229d3c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL ]
    |> run um [ "00229d3c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL ]
    |> run um [ "00229d3c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 00082d7c, mthi a4, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MTHI``() =
    [ G 8, 0x7UL ]
    |> run um [ "00082d7c" ]
    |> is [ Hi, 0x7UL ]
    [ G 8, 0x7fffffffUL ]
    |> run um [ "00082d7c" ]
    |> is [ Hi, 0x7fffffffUL ]
    [ G 8, 0xffffffff89abcdefUL ]
    |> run um [ "00082d7c" ]
    |> is [ Hi, 0xffffffff89abcdefUL ]

  /// <summary>
  /// 00083d7c, mtlo a4, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MTLO``() =
    [ G 8, 0x7UL ]
    |> run um [ "00083d7c" ]
    |> is [ Lo, 0x7UL ]
    [ G 8, 0x7fffffffUL ]
    |> run um [ "00083d7c" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 8, 0xffffffff89abcdefUL ]
    |> run um [ "00083d7c" ]
    |> is [ Lo, 0xffffffff89abcdefUL ]

  /// <summary>
  /// 01494210, mul a4, a5, a6, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MUL``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "01494210" ]
    |> is [ G 8, 0xfUL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "01494210" ]
    |> is [ G 8, 0xfffffffffffffffeUL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "01494210" ]
    |> is [ G 8, 0x35068740UL ]

  /// <summary>
  /// 54c410b0, mul.s f2, f4, f6, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after mul.s $f2,$f4,$f6, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MUL.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; F 6, 0x3fc00000UL ]
    |> run um [ "54c410b0" ]
    |> is [ F 2, 0x40580000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; F 6, 0x3f400000UL ]
    |> run um [ "54c410b0" ]
    |> is [ F 2, 0xc0900000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL ]
    |> run um [ "54c410b0" ]
    |> is [ F 2, 0x42fa0000UL ]

  /// <summary>
  /// 01288b3c, mult a4, a5, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MULT``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "01288b3c" ]
    |> is [ Lo, 0x15UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "01288b3c" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "01288b3c" ]
    |> is [ Hi, 0xfffffffff795e368UL; Lo, 0xffffffffe242d208UL ]

  /// <summary>
  /// 01289b3c, multu a4, a5, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MULTU``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "01289b3c" ]
    |> is [ Lo, 0x15UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "01289b3c" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "01289b3c" ]
    |> is [ Hi, 0x9ca39e0UL; Lo, 0xffffffffe242d208UL ]

  /// <summary>
  /// 54440b7b, neg.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after neg.s $f2,$f4, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 NEG.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run um [ "54440b7b" ]
    |> is [ F 2, 0xc0100000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL ]
    |> run um [ "54440b7b" ]
    |> is [ F 2, 0x40c00000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL ]
    |> run um [ "54440b7b" ]
    |> is [ F 2, 0xc47a0000UL ]

  /// <summary>
  /// 55061102, nmadd.s f2, f4, f6, f8, against QEMU's MIPS64R2-generic: QEMU
  /// has no microMIPS64 or microMIPS processor with an FPU, so the values are
  /// what it left after nmadd.s $f2,$f4,$f6,$f8, the MIPS64 instruction
  /// binutils reads this word as. the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 NMADD.fmt``() =
    let given0 =
      [ F 2, 0xbf800000UL
        F 4, 0x40100000UL
        F 6, 0x3fc00000UL
        F 8, 0x3f000000UL ]
    given0
    |> run um [ "55061102" ]
    |> is [ F 2, 0xc0400000UL ]
    let given1 =
      [ F 2, 0x40600000UL
        F 4, 0xc0c00000UL
        F 6, 0x3f400000UL
        F 8, 0x40800000UL ]
    given1
    |> run um [ "55061102" ]
    |> is [ F 2, 0x40400000UL ]
    let given2 =
      [ F 2, 0x3e800000UL
        F 4, 0x447a0000UL
        F 6, 0x3e000000UL
        F 8, 0xc0200000UL ]
    given2
    |> run um [ "55061102" ]
    |> is [ F 2, 0xc479ec00UL ]

  /// <summary>
  /// 55061122, nmsub.s f2, f4, f6, f8, against QEMU's MIPS64R2-generic: QEMU
  /// has no microMIPS64 or microMIPS processor with an FPU, so the values are
  /// what it left after nmsub.s $f2,$f4,$f6,$f8, the MIPS64 instruction
  /// binutils reads this word as. the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 NMSUB.fmt``() =
    let given0 =
      [ F 2, 0xbf800000UL
        F 4, 0x40100000UL
        F 6, 0x3fc00000UL
        F 8, 0x3f000000UL ]
    given0
    |> run um [ "55061122" ]
    |> is [ F 2, 0x3fc00000UL ]
    let given1 =
      [ F 2, 0x40600000UL
        F 4, 0xc0c00000UL
        F 6, 0x3f400000UL
        F 8, 0x40800000UL ]
    given1
    |> run um [ "55061122" ]
    |> is [ F 2, 0xc1100000UL ]
    let given2 =
      [ F 2, 0x3e800000UL
        F 4, 0x447a0000UL
        F 6, 0x3e000000UL
        F 8, 0xc0200000UL ]
    given2
    |> run um [ "55061122" ]
    |> is [ F 2, 0x447a1400UL ]

  /// <summary>
  /// 00000000, nop, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 NOP``() =
    []
    |> run um [ "00000000" ]
    |> is []
    []
    |> run um [ "00000000" ]
    |> is []
    []
    |> run um [ "00000000" ]
    |> is []

  /// <summary>
  /// 014942d0, nor a4, a5, a6, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 NOR``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "014942d0" ]
    |> is [ G 8, 0xfffffffffffffff8UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "014942d0" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "014942d0" ]
    |> is [ G 8, 0x1030107UL ]

  /// <summary>
  /// 4413, nor v0, v1, r0, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 NOT16``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run um [ "4413" ]
    |> is [ G 2, 0xfffffffffffffffcUL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run um [ "4413" ]
    |> is [ G 2, 0xfffffffffffffffeUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run um [ "4413" ]
    |> is [ G 2, 0xffffffffedcba987UL ]

  /// <summary>
  /// 01494290, or a4, a5, a6, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 OR``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "01494290" ]
    |> is []
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "01494290" ]
    |> is [ G 8, 0xffffffffffffffffUL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "01494290" ]
    |> is [ G 8, 0xfffffffffefcfef8UL ]

  /// <summary>
  /// 0c22, or at, v0, r0, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 OR16``() =
    [ G 1, 0x7UL; G 2, 0x3UL ]
    |> run um [ "0c22" ]
    |> is [ G 1, 0x3UL ]
    [ G 1, 0x7fffffffUL; G 2, 0x1UL ]
    |> run um [ "0c22" ]
    |> is [ G 1, 0x1UL ]
    [ G 1, 0xffffffff89abcdefUL; G 2, 0x12345678UL ]
    |> run um [ "0c22" ]
    |> is [ G 1, 0x12345678UL ]

  /// <summary>
  /// 51090001, ori a4, a5, 0x1, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ORI``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "51090001" ]
    |> is [ G 8, 0x3UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "51090001" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "51090001" ]
    |> is [ G 8, 0x12345679UL ]

  /// <summary>
  /// 00002800, pause, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 PAUSE``() =
    []
    |> run um [ "00002800" ]
    |> is []
    []
    |> run um [ "00002800" ]
    |> is []
    []
    |> run um [ "00002800" ]
    |> is []

  /// <summary>
  /// 54c41080, pll.ps f2, f4, f6, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after pll.ps $f2,$f4,$f6, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 PLL.PS``() =
    let given0 =
      [ F 2, 0xbf8000003f800000UL
        F 4, 0x40100000bfc00000UL
        F 6, 0x3fc000003e800000UL ]
    given0
    |> run um [ "54c41080" ]
    |> is [ F 2, 0xbfc000003e800000UL ]
    let given1 =
      [ F 2, 0x40600000c0600000UL
        F 4, 0xc0c000003f000000UL
        F 6, 0x3f40000040000000UL ]
    given1
    |> run um [ "54c41080" ]
    |> is [ F 2, 0x3f00000040000000UL ]
    let given2 =
      [ F 2, 0x3e8000003f400000UL
        F 4, 0x447a000040400000UL
        F 6, 0x3e000000c0800000UL ]
    given2
    |> run um [ "54c41080" ]
    |> is [ F 2, 0x40400000c0800000UL ]

  /// <summary>
  /// 54c410c0, plu.ps f2, f4, f6, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after plu.ps $f2,$f4,$f6, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 PLU.PS``() =
    let given0 =
      [ F 2, 0xbf8000003f800000UL
        F 4, 0x40100000bfc00000UL
        F 6, 0x3fc000003e800000UL ]
    given0
    |> run um [ "54c410c0" ]
    |> is [ F 2, 0xbfc000003fc00000UL ]
    let given1 =
      [ F 2, 0x40600000c0600000UL
        F 4, 0xc0c000003f000000UL
        F 6, 0x3f40000040000000UL ]
    given1
    |> run um [ "54c410c0" ]
    |> is [ F 2, 0x3f0000003f400000UL ]
    let given2 =
      [ F 2, 0x3e8000003f400000UL
        F 4, 0x447a000040400000UL
        F 6, 0x3e000000c0800000UL ]
    given2
    |> run um [ "54c410c0" ]
    |> is [ F 2, 0x404000003e000000UL ]

  /// <summary>
  /// 60082001, pref 0x0, 1(a4), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 PREF``() =
    let given0 =
      [ G 8, 0x2020007fUL
        M 0x20200078UL, 0x9fed8e50b2f1835dUL
        M 0x20200080UL, 0xf0a76f33e498cc21UL
        M 0x20200088UL, 0x984ccef41d17b580UL ]
    given0
    |> run um [ "60082001" ]
    |> is []
    let given1 =
      [ G 8, 0x2020007fUL
        M 0x20200078UL, 0xe371fa9ac2020709UL
        M 0x20200080UL, 0x69ecf5ffbd96706UL
        M 0x20200088UL, 0x888154859447e667UL ]
    given1
    |> run um [ "60082001" ]
    |> is []
    let given2 =
      [ G 8, 0x2020007fUL
        M 0x20200078UL, 0xc794c753775fbeaUL
        M 0x20200080UL, 0xc52f693ade503722UL
        M 0x20200088UL, 0xaccbb1a6ca17904aUL ]
    given2
    |> run um [ "60082001" ]
    |> is []

  /// <summary>
  /// 6008a401, prefe 0x0, 1(a4), against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. QEMU raised SIGILL (UndefinedInstruction here); Status =
  /// 0x10 puts the lift in User Mode, the mode QEMU runs every word in; the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 PREFE``() =
    let given0 =
      [ G 8, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xf78ce82f5db8687UL
        M 0x20200080UL, 0xe692b88f392ce73fUL
        M 0x20200088UL, 0xfaa08d5427d67955UL ]
    given0
    |> run um [ "6008a401" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xe0a6f4739cd188b8UL
        M 0x20200080UL, 0xa924079b4040c2fcUL
        M 0x20200088UL, 0x70fcb5fe6a85a1a5UL ]
    given1
    |> run um [ "6008a401" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x62c7cacc139206aUL
        M 0x20200080UL, 0xd9553313d86fe1aaUL
        M 0x20200088UL, 0x4c6dff58e38e4623UL ]
    given2
    |> run um [ "6008a401" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 552801a0, prefx 0x0, a5(a4), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after prefx 0x0,$9($8), the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 PREFX``() =
    let given0 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        M 0x20200078UL, 0x21584be820f6ecbUL
        M 0x20200080UL, 0x93784e20b75c9e9bUL
        M 0x20200088UL, 0x759a4988c22b0806UL ]
    given0
    |> run um [ "552801a0" ]
    |> is []
    let given1 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        M 0x20200078UL, 0xeb3d978a3fa76585UL
        M 0x20200080UL, 0xac1ac71f11641845UL
        M 0x20200088UL, 0x557782645804314UL ]
    given1
    |> run um [ "552801a0" ]
    |> is []
    let given2 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        M 0x20200078UL, 0xc072434cc1d5e60fUL
        M 0x20200080UL, 0xae453f3b1f6376dbUL
        M 0x20200088UL, 0xf0c53c79b7d67ed1UL ]
    given2
    |> run um [ "552801a0" ]
    |> is []

  /// <summary>
  /// 54c41100, pul.ps f2, f4, f6, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after pul.ps $f2,$f4,$f6, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 PUL.PS``() =
    let given0 =
      [ F 2, 0xbf8000003f800000UL
        F 4, 0x40100000bfc00000UL
        F 6, 0x3fc000003e800000UL ]
    given0
    |> run um [ "54c41100" ]
    |> is [ F 2, 0x401000003e800000UL ]
    let given1 =
      [ F 2, 0x40600000c0600000UL
        F 4, 0xc0c000003f000000UL
        F 6, 0x3f40000040000000UL ]
    given1
    |> run um [ "54c41100" ]
    |> is [ F 2, 0xc0c0000040000000UL ]
    let given2 =
      [ F 2, 0x3e8000003f400000UL
        F 4, 0x447a000040400000UL
        F 6, 0x3e000000c0800000UL ]
    given2
    |> run um [ "54c41100" ]
    |> is [ F 2, 0x447a0000c0800000UL ]

  /// <summary>
  /// 54c41140, puu.ps f2, f4, f6, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after puu.ps $f2,$f4,$f6, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 PUU.PS``() =
    let given0 =
      [ F 2, 0xbf8000003f800000UL
        F 4, 0x40100000bfc00000UL
        F 6, 0x3fc000003e800000UL ]
    given0
    |> run um [ "54c41140" ]
    |> is [ F 2, 0x401000003fc00000UL ]
    let given1 =
      [ F 2, 0x40600000c0600000UL
        F 4, 0xc0c000003f000000UL
        F 6, 0x3f40000040000000UL ]
    given1
    |> run um [ "54c41140" ]
    |> is [ F 2, 0xc0c000003f400000UL ]
    let given2 =
      [ F 2, 0x3e8000003f400000UL
        F 4, 0x447a000040400000UL
        F 6, 0x3e000000c0800000UL ]
    given2
    |> run um [ "54c41140" ]
    |> is [ F 2, 0x447a00003e000000UL ]

  /// <summary>
  /// 01026b3c, rdhwr a4, v0, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 RDHWR``() =
    [ G 8, 0x7UL ]
    |> run um [ "01026b3c" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x7fffffffUL ]
    |> run um [ "01026b3c" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0xffffffff89abcdefUL ]
    |> run um [ "01026b3c" ]
    |> is [ G 8, 0x0UL ]

  /// <summary>
  /// 0109e17c, rdpgpr a4, a5, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 RDPGPR``() =
    [ G 8, 0x7UL; G 9, 0x3UL; Status, 0x10UL ]
    |> run um [ "0109e17c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; Status, 0x10UL ]
    |> run um [ "0109e17c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; Status, 0x10UL ]
    |> run um [ "0109e17c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 5444123b, recip.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after recip.s $f2,$f4, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 RECIP.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x3f000000UL ]
    |> run um [ "5444123b" ]
    |> is [ F 2, 0x40000000UL ]
    [ F 2, 0x40600000UL; F 4, 0x40800000UL ]
    |> run um [ "5444123b" ]
    |> is [ F 2, 0x3e800000UL ]
    [ F 2, 0x3e800000UL; F 4, 0xbe000000UL ]
    |> run um [ "5444123b" ]
    |> is [ F 2, 0xc1000000UL ]

  /// <summary>
  /// 010908c0, rotr a4, a5, 0x1, against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ROTR``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "010908c0" ]
    |> is [ G 8, 0xffffffff80000001UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "010908c0" ]
    |> is [ G 8, 0xffffffff80000000UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "010908c0" ]
    |> is [ G 8, 0x91a2b3cUL ]

  /// <summary>
  /// 012a40d0, rotrv a4, a5, a6, against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ROTRV``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "012a40d0" ]
    |> is [ G 8, 0x18000000UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "012a40d0" ]
    |> is [ G 8, 0x4UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "012a40d0" ]
    |> is [ G 8, 0x34567812UL ]

  /// <summary>
  /// 5444333b, round.l.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after round.l.s $f2,$f4, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ROUND.L.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run um [ "5444333b" ]
    |> is [ F 2, 0x2UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run um [ "5444333b" ]
    |> is [ F 2, 0xfffffffffffffffeUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run um [ "5444333b" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 54443b3b, round.w.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after round.w.s $f2,$f4, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ROUND.W.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run um [ "54443b3b" ]
    |> is [ F 2, 0x2UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run um [ "54443b3b" ]
    |> is [ F 2, 0xfffffffeUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run um [ "54443b3b" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 5444023b, rsqrt.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after rsqrt.s $f2,$f4, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 RSQRT.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x3e800000UL ]
    |> run um [ "5444023b" ]
    |> is [ F 2, 0x40000000UL ]
    [ F 2, 0x40600000UL; F 4, 0x40800000UL ]
    |> run um [ "5444023b" ]
    |> is [ F 2, 0x3f000000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x41800000UL ]
    |> run um [ "5444023b" ]
    |> is []

  /// <summary>
  /// 18230001, sb at, 1(v1), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SB``() =
    let given0 =
      [ G 1, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xe31db1d4e40b049eUL
        M 0x20200080UL, 0xb1a83b67c125b555UL
        M 0x20200088UL, 0x672bfe2d0d07db0eUL ]
    given0
    |> run um [ "18230001" ]
    |> is [ M 0x20200080UL, 0x7a83b67c125b555UL ]
    let given1 =
      [ G 1, 0x7fffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xa87d1a4ec1523488UL
        M 0x20200080UL, 0x96d6e962ebba02a3UL
        M 0x20200088UL, 0x2f4e519b5a27501fUL ]
    given1
    |> run um [ "18230001" ]
    |> is [ M 0x20200080UL, 0xffd6e962ebba02a3UL ]
    let given2 =
      [ G 1, 0xffffffff89abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xe26611c8b114bbf6UL
        M 0x20200080UL, 0x2eced3e00e02b8b5UL
        M 0x20200088UL, 0x97d0480411238bcfUL ]
    given2
    |> run um [ "18230001" ]
    |> is [ M 0x20200080UL, 0xefced3e00e02b8b5UL ]

  /// <summary>
  /// 8901, sb v0, 1(s0), against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SB16``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0xce1b44f659e6e22bUL
        M 0x20200080UL, 0x3b1f35e170e10455UL
        M 0x20200088UL, 0x739aa57987156e64UL ]
    given0
    |> run um [ "8901" ]
    |> is [ M 0x20200080UL, 0x71f35e170e10455UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0xdc7aebf372e796e2UL
        M 0x20200080UL, 0x6ab013ad56c2ad2UL
        M 0x20200088UL, 0xf5e923751f7e20a9UL ]
    given1
    |> run um [ "8901" ]
    |> is [ M 0x20200080UL, 0xffab013ad56c2ad2UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0xfb32c091ed8b765fUL
        M 0x20200080UL, 0x24218f0b5c289f58UL
        M 0x20200088UL, 0x1f23dd0995aadb42UL ]
    given2
    |> run um [ "8901" ]
    |> is [ M 0x20200080UL, 0xef218f0b5c289f58UL ]

  /// <summary>
  /// 6109a801, sbe a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SBE``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x74847bdfc1cdb628UL
        M 0x20200080UL, 0xe49d32b695d6075fUL
        M 0x20200088UL, 0xd3119bf0aa3d5e25UL ]
    given0
    |> run um [ "6109a801" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xffd38808c1161ee2UL
        M 0x20200080UL, 0x11d4c7ede95cb260UL
        M 0x20200088UL, 0xc4eecd804f30e52fUL ]
    given1
    |> run um [ "6109a801" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xe26c9039ce26a8f2UL
        M 0x20200080UL, 0xb6ffaf0e28ad787fUL
        M 0x20200088UL, 0x105199724cab5f37UL ]
    given2
    |> run um [ "6109a801" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 6109b001, sc a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SC``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x68b83787debd2aacUL
        M 0x20200080UL, 0xae822a8f6a01a4acUL
        M 0x20200088UL, 0x611bddf15396ed57UL ]
    given0
    |> run um [ "6109b001" ]
    |> is [ G 8, 0x0UL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x5fe09534b7680408UL
        M 0x20200080UL, 0x7421c50cf6d85c47UL
        M 0x20200088UL, 0x411ea44ed4b6b6b1UL ]
    given1
    |> run um [ "6109b001" ]
    |> is [ G 8, 0x0UL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x458565c2f77a1932UL
        M 0x20200080UL, 0x655b4192beeee699UL
        M 0x20200088UL, 0x70f9260787e5af71UL ]
    given2
    |> run um [ "6109b001" ]
    |> is [ G 8, 0x0UL ]

  /// <summary>
  /// 6109f001, scd a4, 1(a5), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after scd $8,1($9), the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SCD``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x27b652d99b98a8eeUL
        M 0x20200080UL, 0xb887d13a98693448UL
        M 0x20200088UL, 0x703a3d2947fd8a32UL ]
    given0
    |> run um [ "6109f001" ]
    |> is [ G 8, 0x0UL ]
    let given1 =
      [ G 8, 0x7fffffffffffffffUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0xd76271ee86652eeaUL
        M 0x20200080UL, 0xefe2c7e63c75978cUL
        M 0x20200088UL, 0x62c2a69fa043e08dUL ]
    given1
    |> run um [ "6109f001" ]
    |> is [ G 8, 0x0UL ]
    let given2 =
      [ G 8, 0x123456789abcdefUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x26d6908dda78b157UL
        M 0x20200080UL, 0xbce4898c25c2715aUL
        M 0x20200088UL, 0xdec40a623d984967UL ]
    given2
    |> run um [ "6109f001" ]
    |> is [ G 8, 0x0UL ]

  /// <summary>
  /// 6109ac01, sce a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SCE``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x1b8e13144ae1b932UL
        M 0x20200080UL, 0xc7485781dcedce05UL
        M 0x20200088UL, 0xcabe829bf7b62941UL ]
    given0
    |> run um [ "6109ac01" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xf5f413e672ca1d82UL
        M 0x20200080UL, 0xc15accc201175352UL
        M 0x20200088UL, 0x2baa60f0fa597a67UL ]
    given1
    |> run um [ "6109ac01" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xb6639f1fe68bea8eUL
        M 0x20200080UL, 0xa2c468e839b6f57bUL
        M 0x20200088UL, 0x31fa8fa884fe70f3UL ]
    given2
    |> run um [ "6109ac01" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// d9090001, sd a4, 1(a5), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after sd $8,1($9), the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SD``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x4e88b33a97e8ac71UL
        M 0x20200080UL, 0xb16a0832e5ef7a41UL
        M 0x20200088UL, 0x10dbb254524fda49UL ]
    given0
    |> run um [ "d9090001" ]
    |> is [ M 0x20200080UL, 0x7UL ]
    let given1 =
      [ G 8, 0x7fffffffffffffffUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0xe141e02389ee68a3UL
        M 0x20200080UL, 0x9aa9e6abbb26a14fUL
        M 0x20200088UL, 0x63a2efeb31fbc924UL ]
    given1
    |> run um [ "d9090001" ]
    |> is [ M 0x20200080UL, 0x7fffffffffffffffUL ]
    let given2 =
      [ G 8, 0x123456789abcdefUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x74ea0307d91821ebUL
        M 0x20200080UL, 0xa16347d80ae1ff6UL
        M 0x20200088UL, 0xff2b1eb709ada1f2UL ]
    given2
    |> run um [ "d9090001" ]
    |> is [ M 0x20200080UL, 0x123456789abcdefUL ]

  /// <summary>
  /// 0020db7c, sdbbp 0x20. Not run against QEMU, whose user mode aborts on the
  /// debug exception it raises; the manual enters the debug handler, which is
  /// this architecture's breakpoint. The lift raises Breakpoint and changes
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SDBBP``() =
    []
    |> run um [ "0020db7c" ]
    |> raises [ Breakpoint ] []

  /// <summary>
  /// 46c1, sdbbp 0x1. Not run against QEMU, whose user mode aborts on the debug
  /// exception it raises; the manual enters the debug handler, which is this
  /// architecture's breakpoint. The lift raises Breakpoint and changes nothing.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SDBBP16``() =
    []
    |> run um [ "46c1" ]
    |> raises [ Breakpoint ] []

  /// <summary>
  /// b8480001, sdc1 f2, 1(a4), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after sdc1 $f2,1($8), the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SDC1``() =
    let given0 =
      [ G 8, 0x2020007fUL
        F 2, 0xbff0000000000000UL
        M 0x20200078UL, 0x82ae9c6b57c82933UL
        M 0x20200080UL, 0x738615bc7ded6734UL
        M 0x20200088UL, 0xab66a974706a23abUL ]
    given0
    |> run um [ "b8480001" ]
    |> is [ M 0x20200080UL, 0xbff0000000000000UL ]
    let given1 =
      [ G 8, 0x2020007fUL
        F 2, 0x400c000000000000UL
        M 0x20200078UL, 0x720f7174e65e3073UL
        M 0x20200080UL, 0x8a83874d7014d546UL
        M 0x20200088UL, 0x7e3c28dd11263f0fUL ]
    given1
    |> run um [ "b8480001" ]
    |> is [ M 0x20200080UL, 0x400c000000000000UL ]
    let given2 =
      [ G 8, 0x2020007fUL
        F 2, 0x3fd0000000000000UL
        M 0x20200078UL, 0x68c610b911b90593UL
        M 0x20200080UL, 0xb3876b8f096f535eUL
        M 0x20200088UL, 0xd602eecb8e3d8468UL ]
    given2
    |> run um [ "b8480001" ]
    |> is [ M 0x20200080UL, 0x3fd0000000000000UL ]

  /// <summary>
  /// 2000a001, sdc2 0x0, 1(r0), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SDC2``() =
    let given0 =
      [ M 0x20200078UL, 0x7f86485290f86669UL
        M 0x20200080UL, 0x6a7cb195f101e6edUL
        M 0x20200088UL, 0xc005b9fc1ab1b0efUL ]
    given0
    |> run um [ "2000a001" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ M 0x20200078UL, 0x7465107aba6ec549UL
        M 0x20200080UL, 0x19aee2c33db97349UL
        M 0x20200088UL, 0xe55538a5cbee30eUL ]
    given1
    |> run um [ "2000a001" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ M 0x20200078UL, 0x45a40bf488020461UL
        M 0x20200080UL, 0x1452c856bf1ee373UL
        M 0x20200088UL, 0x7110f90acabb77bUL ]
    given2
    |> run um [ "2000a001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 6109c001, sdl a4, 1(a5), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after sdl $8,1($9), the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SDL``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x20200080UL
        M 0x20200078UL, 0x14fcc730fdcf2a72UL
        M 0x20200080UL, 0xb9bae0860de913cbUL
        M 0x20200088UL, 0x436958e4cf3f3024UL ]
    given0
    |> run um [ "6109c001" ]
    |> is [ M 0x20200080UL, 0xb900000000000000UL ]
    let given1 =
      [ G 8, 0x7fffffffffffffffUL
        G 9, 0x20200081UL
        M 0x20200078UL, 0x347901df8924043fUL
        M 0x20200080UL, 0xcb3fd3f7f6926becUL
        M 0x20200088UL, 0x58eb2d41bd7de591UL ]
    given1
    |> run um [ "6109c001" ]
    |> is [ M 0x20200080UL, 0xcb3f7fffffffffffUL ]
    let given2 =
      [ G 8, 0x123456789abcdefUL
        G 9, 0x20200084UL
        M 0x20200078UL, 0x5a3af71a36bcf7b9UL
        M 0x20200080UL, 0xf597e03c5ed1b60UL
        M 0x20200088UL, 0xdbb318a42992e253UL ]
    given2
    |> run um [ "6109c001" ]
    |> is [ M 0x20200080UL, 0xf597e03c5012345UL ]

  /// <summary>
  /// 2044f008, sdm s0, s1, 8(a0), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after sd $16,8($4); sd $17,16($4), the MIPS64 instruction binutils
  /// reads this word as. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SDM``() =
    let given0 =
      [ G 4, 0x20200078UL
        G 16, 0x7UL
        G 17, 0x3UL
        M 0x20200078UL, 0x307a19c56e2a40e7UL
        M 0x20200080UL, 0xef5d15e3659412bdUL
        M 0x20200088UL, 0x7a9cd9d48178e6c2UL ]
    given0
    |> run um [ "2044f008" ]
    |> is [ M 0x20200080UL, 0x7UL; M 0x20200088UL, 0x3UL ]
    let given1 =
      [ G 4, 0x20200078UL
        G 16, 0x7fffffffffffffffUL
        G 17, 0x1UL
        M 0x20200078UL, 0x81801b3baf7f9883UL
        M 0x20200080UL, 0x9d1fb22de1c85101UL
        M 0x20200088UL, 0x8e4f7ea92071ffe5UL ]
    given1
    |> run um [ "2044f008" ]
    |> is [ M 0x20200080UL, 0x7fffffffffffffffUL; M 0x20200088UL, 0x1UL ]
    let given2 =
      [ G 4, 0x20200078UL
        G 16, 0x123456789abcdefUL
        G 17, 0xfedcba9876543210UL
        M 0x20200078UL, 0x54075b81783759baUL
        M 0x20200080UL, 0xcb65a6e03b8068d5UL
        M 0x20200088UL, 0x76578aa7cda601b7UL ]
    let expected2 =
      [ M 0x20200080UL, 0x123456789abcdefUL
        M 0x20200088UL, 0xfedcba9876543210UL ]
    given2
    |> run um [ "2044f008" ]
    |> is expected2

  /// <summary>
  /// 2044c008, sdp v0, v1, 8(a0), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after sd $2,8($4); sd $3,16($4), the MIPS64 instruction binutils
  /// reads this word as. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SDP``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x3UL
        G 4, 0x20200078UL
        M 0x20200078UL, 0x7e818b33ffc8db89UL
        M 0x20200080UL, 0x7303a9b4f7ec9763UL
        M 0x20200088UL, 0x26e7f23097ab44d6UL ]
    given0
    |> run um [ "2044c008" ]
    |> is [ M 0x20200080UL, 0x7UL; M 0x20200088UL, 0x3UL ]
    let given1 =
      [ G 2, 0x7fffffffffffffffUL
        G 3, 0x1UL
        G 4, 0x20200078UL
        M 0x20200078UL, 0x3fdc2339f3200736UL
        M 0x20200080UL, 0x1e2198731864d20fUL
        M 0x20200088UL, 0x952925cfc4779a35UL ]
    given1
    |> run um [ "2044c008" ]
    |> is [ M 0x20200080UL, 0x7fffffffffffffffUL; M 0x20200088UL, 0x1UL ]
    let given2 =
      [ G 2, 0x123456789abcdefUL
        G 3, 0xfedcba9876543210UL
        G 4, 0x20200078UL
        M 0x20200078UL, 0xb44bf9a119045f01UL
        M 0x20200080UL, 0x878902645b8b6baeUL
        M 0x20200088UL, 0xc5e750aefe8703e6UL ]
    let expected2 =
      [ M 0x20200080UL, 0x123456789abcdefUL
        M 0x20200088UL, 0xfedcba9876543210UL ]
    given2
    |> run um [ "2044c008" ]
    |> is expected2

  /// <summary>
  /// 6109d001, sdr a4, 1(a5), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after sdr $8,1($9), the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SDR``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x20200080UL
        M 0x20200078UL, 0x7fcc95498ad586baUL
        M 0x20200080UL, 0xd9805929d91a245eUL
        M 0x20200088UL, 0x378892d7ec9fbf24UL ]
    given0
    |> run um [ "6109d001" ]
    |> is [ M 0x20200080UL, 0x75929d91a245eUL ]
    let given1 =
      [ G 8, 0x7fffffffffffffffUL
        G 9, 0x20200081UL
        M 0x20200078UL, 0x4a147237baf5829aUL
        M 0x20200080UL, 0x2c2c3de620e36a2fUL
        M 0x20200088UL, 0x59214e3542aea8daUL ]
    given1
    |> run um [ "6109d001" ]
    |> is [ M 0x20200080UL, 0xffffffe620e36a2fUL ]
    let given2 =
      [ G 8, 0x123456789abcdefUL
        G 9, 0x20200084UL
        M 0x20200078UL, 0x4d14b87cb9c78308UL
        M 0x20200080UL, 0x39af6bf8b860a7b2UL
        M 0x20200088UL, 0xd6317788ca42dcbaUL ]
    given2
    |> run um [ "6109d001" ]
    |> is [ M 0x20200080UL, 0x456789abcdefa7b2UL ]

  /// <summary>
  /// 55281108, sdxc1 f2, a5(a4), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after sdxc1 $f2,$9($8), the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SDXC1``() =
    let given0 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0xbff0000000000000UL
        M 0x20200078UL, 0xfac72d4d01c4c6bdUL
        M 0x20200080UL, 0xfead298fa788d6fbUL
        M 0x20200088UL, 0x58840f60509526edUL ]
    given0
    |> run um [ "55281108" ]
    |> is [ M 0x20200080UL, 0xbff0000000000000UL ]
    let given1 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0x400c000000000000UL
        M 0x20200078UL, 0x445c461be083d474UL
        M 0x20200080UL, 0x36149eb348929fbdUL
        M 0x20200088UL, 0x74e82db08ce94825UL ]
    given1
    |> run um [ "55281108" ]
    |> is [ M 0x20200080UL, 0x400c000000000000UL ]
    let given2 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0x3fd0000000000000UL
        M 0x20200078UL, 0xc2d25d16efd1e650UL
        M 0x20200080UL, 0x692ad42cad97af8UL
        M 0x20200088UL, 0x6b443719c4c0e37eUL ]
    given2
    |> run um [ "55281108" ]
    |> is [ M 0x20200080UL, 0x3fd0000000000000UL ]

  /// <summary>
  /// 01092b3c, seb a4, a5, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SEB``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "01092b3c" ]
    |> is [ G 8, 0x3UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "01092b3c" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "01092b3c" ]
    |> is [ G 8, 0x78UL ]

  /// <summary>
  /// 01093b3c, seh a4, a5, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SEH``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "01093b3c" ]
    |> is [ G 8, 0x3UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "01093b3c" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "01093b3c" ]
    |> is [ G 8, 0x5678UL ]

  /// <summary>
  /// 38230001, sh at, 1(v1), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SH``() =
    let given0 =
      [ G 1, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xf347d039c1db73e0UL
        M 0x20200080UL, 0x5963c2a9b4c91f10UL
        M 0x20200088UL, 0x109b430fe5b2ef6UL ]
    given0
    |> run um [ "38230001" ]
    |> is [ M 0x20200080UL, 0x7c2a9b4c91f10UL ]
    let given1 =
      [ G 1, 0x7fffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xff29b6de62a966dUL
        M 0x20200080UL, 0x8a6dc9b9c2565197UL
        M 0x20200088UL, 0x7e4f47116197bc56UL ]
    given1
    |> run um [ "38230001" ]
    |> is [ M 0x20200080UL, 0xffffc9b9c2565197UL ]
    let given2 =
      [ G 1, 0xffffffff89abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xfc7f443587efadfdUL
        M 0x20200080UL, 0x38b40d935298d79aUL
        M 0x20200088UL, 0x37e49559cb7d529fUL ]
    given2
    |> run um [ "38230001" ]
    |> is [ M 0x20200080UL, 0xcdef0d935298d79aUL ]

  /// <summary>
  /// a901, sh v0, 2(s0), against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SH16``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0x295b4c11c36517deUL
        M 0x20200080UL, 0xfeb8325746993fbcUL
        M 0x20200088UL, 0x85a425ac460784bUL ]
    given0
    |> run um [ "a901" ]
    |> is [ M 0x20200080UL, 0x7325746993fbcUL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0xb904f8e73c542e69UL
        M 0x20200080UL, 0x6a976607cf45bacaUL
        M 0x20200088UL, 0x5e2853559a8bbd68UL ]
    given1
    |> run um [ "a901" ]
    |> is [ M 0x20200080UL, 0xffff6607cf45bacaUL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0x894e8fe6f5ad217cUL
        M 0x20200080UL, 0xb611a592e915bdb3UL
        M 0x20200088UL, 0xe7c43e7b6e50f0d1UL ]
    given2
    |> run um [ "a901" ]
    |> is [ M 0x20200080UL, 0xcdefa592e915bdb3UL ]

  /// <summary>
  /// 6109aa01, she a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SHE``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xed6ca7bb4050f6ccUL
        M 0x20200080UL, 0x1efc3d6b47f94beaUL
        M 0x20200088UL, 0x420f8c29f14fa679UL ]
    given0
    |> run um [ "6109aa01" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xb1c9153cb6414409UL
        M 0x20200080UL, 0x3a4df6c44ac34b38UL
        M 0x20200088UL, 0x5c1ee2ebb80a6f4dUL ]
    given1
    |> run um [ "6109aa01" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xef60bd9ae8727380UL
        M 0x20200080UL, 0x3fbacec3fd7457deUL
        M 0x20200088UL, 0x1bbe4c7065c21c9bUL ]
    given2
    |> run um [ "6109aa01" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 01090800, sll a4, a5, 0x1, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SLL``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "01090800" ]
    |> is [ G 8, 0x6UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "01090800" ]
    |> is [ G 8, 0x2UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "01090800" ]
    |> is [ G 8, 0x2468acf0UL ]

  /// <summary>
  /// 2530, sll v0, v1, 0x8, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SLL16``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run um [ "2530" ]
    |> is [ G 2, 0x300UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run um [ "2530" ]
    |> is [ G 2, 0x100UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run um [ "2530" ]
    |> is [ G 2, 0x34567800UL ]

  /// <summary>
  /// 012a4010, sllv a4, a5, a6, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SLLV``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "012a4010" ]
    |> is [ G 8, 0x60UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "012a4010" ]
    |> is [ G 8, 0x40000000UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "012a4010" ]
    |> is [ G 8, 0x78000000UL ]

  /// <summary>
  /// 01494350, slt a4, a5, a6, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SLT``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "01494350" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "01494350" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "01494350" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x2UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "01494350" ]
    |> is [ G 8, 0x1UL ]

  /// <summary>
  /// 91090001, slti a4, a5, 0x1, against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SLTI``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "91090001" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "91090001" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "91090001" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x2UL; G 9, 0x3UL ]
    |> run um [ "91090001" ]
    |> is [ G 8, 0x0UL ]

  /// <summary>
  /// b1090001, sltiu a4, a5, 0x1, against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SLTIU``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "b1090001" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "b1090001" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "b1090001" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x2UL; G 9, 0x3UL ]
    |> run um [ "b1090001" ]
    |> is [ G 8, 0x0UL ]

  /// <summary>
  /// 01494390, sltu a4, a5, a6, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SLTU``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "01494390" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "01494390" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "01494390" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0x2UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "01494390" ]
    |> is [ G 8, 0x1UL ]

  /// <summary>
  /// 54440a3b, sqrt.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after sqrt.s $f2,$f4, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SQRT.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run um [ "54440a3b" ]
    |> is [ F 2, 0x3fc00000UL ]
    [ F 2, 0x40600000UL; F 4, 0x41800000UL ]
    |> run um [ "54440a3b" ]
    |> is [ F 2, 0x40800000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x3d800000UL ]
    |> run um [ "54440a3b" ]
    |> is []

  /// <summary>
  /// 01090880, sra a4, a5, 0x1, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SRA``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "01090880" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "01090880" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "01090880" ]
    |> is [ G 8, 0x91a2b3cUL ]

  /// <summary>
  /// 012a4090, srav a4, a5, a6, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SRAV``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "012a4090" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "012a4090" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "012a4090" ]
    |> is [ G 8, 0x12UL ]

  /// <summary>
  /// 01090840, srl a4, a5, 0x1, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SRL``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "01090840" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "01090840" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "01090840" ]
    |> is [ G 8, 0x91a2b3cUL ]

  /// <summary>
  /// 2531, srl v0, v1, 0x8, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SRL16``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run um [ "2531" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run um [ "2531" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run um [ "2531" ]
    |> is [ G 2, 0x123456UL ]

  /// <summary>
  /// 012a4050, srlv a4, a5, a6, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SRLV``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "012a4050" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "012a4050" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "012a4050" ]
    |> is [ G 8, 0x12UL ]

  /// <summary>
  /// 00000800, ssnop, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SSNOP``() =
    []
    |> run um [ "00000800" ]
    |> is []
    []
    |> run um [ "00000800" ]
    |> is []
    []
    |> run um [ "00000800" ]
    |> is []

  /// <summary>
  /// 01494190, sub a4, a5, a6, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGFPE (Exception IntegerOverflow here); the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SUB``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "01494190" ]
    |> is [ G 8, 0xfffffffffffffffeUL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "01494190" ]
    |> is [ G 8, 0x3UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "01494190" ]
    |> is [ G 8, 0x13579be0UL ]
    [ G 8, 0x7UL; G 9, 0xffffffff80000000UL; G 10, 0x1UL ]
    |> run um [ "01494190" ]
    |> raises [ Exception IntegerOverflow ] []

  /// <summary>
  /// 54c41070, sub.s f2, f4, f6, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after sub.s $f2,$f4,$f6, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SUB.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; F 6, 0x3fc00000UL ]
    |> run um [ "54c41070" ]
    |> is [ F 2, 0x3f400000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; F 6, 0x3f400000UL ]
    |> run um [ "54c41070" ]
    |> is [ F 2, 0xc0d80000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL ]
    |> run um [ "54c41070" ]
    |> is [ F 2, 0x4479f800UL ]

  /// <summary>
  /// 014941d0, subu a4, a5, a6, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SUBU``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "014941d0" ]
    |> is [ G 8, 0xfffffffffffffffeUL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "014941d0" ]
    |> is [ G 8, 0x3UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "014941d0" ]
    |> is [ G 8, 0x13579be0UL ]

  /// <summary>
  /// 0539, subu v0, a0, v1, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SUBU16``() =
    [ G 2, 0x7UL; G 3, 0x5UL; G 4, 0x3UL ]
    |> run um [ "0539" ]
    |> is [ G 2, 0xfffffffffffffffeUL ]
    [ G 2, 0x7fffffffUL; G 3, 0xfffffffffffffffeUL; G 4, 0x1UL ]
    |> run um [ "0539" ]
    |> is [ G 2, 0x3UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0xfffffffffedcba98UL; G 4, 0x12345678UL ]
    |> run um [ "0539" ]
    |> is [ G 2, 0x13579be0UL ]

  /// <summary>
  /// 55281188, suxc1 f2, a5(a4), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after suxc1 $f2,$9($8), the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SUXC1``() =
    let given0 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0xbff0000000000000UL
        M 0x20200078UL, 0x30984d1979159f2eUL
        M 0x20200080UL, 0x1fcadc1e4d6b5745UL
        M 0x20200088UL, 0x7b6e4ced3bb45e9fUL ]
    given0
    |> run um [ "55281188" ]
    |> is [ M 0x20200080UL, 0xbff0000000000000UL ]
    let given1 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0x400c000000000000UL
        M 0x20200078UL, 0x6bced19415854ffeUL
        M 0x20200080UL, 0xf84ab467a25d7998UL
        M 0x20200088UL, 0x2e29afce34d30463UL ]
    given1
    |> run um [ "55281188" ]
    |> is [ M 0x20200080UL, 0x400c000000000000UL ]
    let given2 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0x3fd0000000000000UL
        M 0x20200078UL, 0x133e8195378d3c86UL
        M 0x20200080UL, 0xd7643ddf45f8faa6UL
        M 0x20200088UL, 0x6396849a260ed841UL ]
    given2
    |> run um [ "55281188" ]
    |> is [ M 0x20200080UL, 0x3fd0000000000000UL ]

  /// <summary>
  /// c821, sw at, 4(sp), against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SW``() =
    let given0 =
      [ G 1, 0x7UL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x437ee6ed4eb91715UL
        M 0x20200080UL, 0x95f2ddc581579062UL
        M 0x20200088UL, 0x555aaecba8bea92fUL ]
    given0
    |> run um [ "c821" ]
    |> is [ M 0x20200080UL, 0x781579062UL ]
    let given1 =
      [ G 1, 0x7fffffffUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x31ebb6b5aa792dc7UL
        M 0x20200080UL, 0x28518eab29509d4UL
        M 0x20200088UL, 0xa0a9c742cd32965bUL ]
    given1
    |> run um [ "c821" ]
    |> is [ M 0x20200080UL, 0x7fffffffb29509d4UL ]
    let given2 =
      [ G 1, 0xffffffff89abcdefUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0xea35728d05c95e0cUL
        M 0x20200080UL, 0x1ae4be633879a4d3UL
        M 0x20200088UL, 0xe5221b97f8807116UL ]
    given2
    |> run um [ "c821" ]
    |> is [ M 0x20200080UL, 0x89abcdef3879a4d3UL ]

  /// <summary>
  /// c821, sw at, 4(sp), against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SW16``() =
    let given0 =
      [ G 1, 0x7UL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0xfaaa39456e10b7f8UL
        M 0x20200080UL, 0x8a14fb8c7e45c621UL
        M 0x20200088UL, 0x973b6307f0d59179UL ]
    given0
    |> run um [ "c821" ]
    |> is [ M 0x20200080UL, 0x77e45c621UL ]
    let given1 =
      [ G 1, 0x7fffffffUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0xccb842b7079a5bb9UL
        M 0x20200080UL, 0x90cf0104905d85bdUL
        M 0x20200088UL, 0x410e84f61eb83cd3UL ]
    given1
    |> run um [ "c821" ]
    |> is [ M 0x20200080UL, 0x7fffffff905d85bdUL ]
    let given2 =
      [ G 1, 0xffffffff89abcdefUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x94726041f158fe42UL
        M 0x20200080UL, 0xc6f811717bb984b1UL
        M 0x20200088UL, 0xec9227bc389f62b3UL ]
    given2
    |> run um [ "c821" ]
    |> is [ M 0x20200080UL, 0x89abcdef7bb984b1UL ]

  /// <summary>
  /// 98480001, swc1 f2, 1(a4), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after swc1 $f2,1($8), the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SWC1``() =
    let given0 =
      [ G 8, 0x2020007fUL
        F 2, 0xbf800000UL
        M 0x20200078UL, 0xb93f8c99ac585435UL
        M 0x20200080UL, 0x565116df36579843UL
        M 0x20200088UL, 0x997c037d1464576UL ]
    given0
    |> run um [ "98480001" ]
    |> is [ M 0x20200080UL, 0xbf80000036579843UL ]
    let given1 =
      [ G 8, 0x2020007fUL
        F 2, 0x40600000UL
        M 0x20200078UL, 0x222944e0ea621f24UL
        M 0x20200080UL, 0xbff09f3d575be969UL
        M 0x20200088UL, 0xb8448bd24b8c2644UL ]
    given1
    |> run um [ "98480001" ]
    |> is [ M 0x20200080UL, 0x40600000575be969UL ]
    let given2 =
      [ G 8, 0x2020007fUL
        F 2, 0x3e800000UL
        M 0x20200078UL, 0xf4b24ccafec68fb2UL
        M 0x20200080UL, 0x22165aefd95d8901UL
        M 0x20200088UL, 0x9d93e8d141a7954eUL ]
    given2
    |> run um [ "98480001" ]
    |> is [ M 0x20200080UL, 0x3e800000d95d8901UL ]

  /// <summary>
  /// 20008001, swc2 0x0, 1(r0), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SWC2``() =
    let given0 =
      [ M 0x20200078UL, 0xfad92745ff7edb9dUL
        M 0x20200080UL, 0x26c4e0a1c06e013dUL
        M 0x20200088UL, 0xcdb7f47b6da29af2UL ]
    given0
    |> run um [ "20008001" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ M 0x20200078UL, 0xe7e1fb5fff05c3feUL
        M 0x20200080UL, 0x5c670cab76b35b40UL
        M 0x20200088UL, 0x495661cd9d5a11bdUL ]
    given1
    |> run um [ "20008001" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ M 0x20200078UL, 0x4a54692338dd5738UL
        M 0x20200080UL, 0xaf0c554729b93ef0UL
        M 0x20200088UL, 0x3f09351142f830ebUL ]
    given2
    |> run um [ "20008001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 6109ae01, swe a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SWE``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x5d349a31edad6db7UL
        M 0x20200080UL, 0x70e271644920a616UL
        M 0x20200088UL, 0xeb8e0e120747f6fdUL ]
    given0
    |> run um [ "6109ae01" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x6dcecef6a336e1e2UL
        M 0x20200080UL, 0x47bbb870bbe29a61UL
        M 0x20200088UL, 0xd6c508530aeb994eUL ]
    given1
    |> run um [ "6109ae01" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x958690698f3a9915UL
        M 0x20200080UL, 0x3133fb8ea17b83f6UL
        M 0x20200088UL, 0x3d9cd05acc64a84dUL ]
    given2
    |> run um [ "6109ae01" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 61098001, swl a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SWL``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x20200080UL
        M 0x20200078UL, 0xced4a8de7264eadUL
        M 0x20200080UL, 0x3f8c3366c9aa8f5eUL
        M 0x20200088UL, 0x6fe2032404f7a790UL ]
    given0
    |> run um [ "61098001" ]
    |> is [ M 0x20200080UL, 0x3f000000c9aa8f5eUL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x20200081UL
        M 0x20200078UL, 0xfd98013dfc640287UL
        M 0x20200080UL, 0x696a5ce5e3f694ebUL
        M 0x20200088UL, 0x3d89d1dde198866aUL ]
    given1
    |> run um [ "61098001" ]
    |> is [ M 0x20200080UL, 0x696a7fffe3f694ebUL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x20200084UL
        M 0x20200078UL, 0xc9d951ddda98aa39UL
        M 0x20200080UL, 0x81d777f30eb0419fUL
        M 0x20200088UL, 0x6c64d0d04e9e9d2aUL ]
    given2
    |> run um [ "61098001" ]
    |> is [ M 0x20200080UL, 0x81d777f30e89abcdUL ]

  /// <summary>
  /// 6109a001, swle a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SWLE``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x20200080UL
        Status, 0x10UL
        M 0x20200078UL, 0xf1693e443150864aUL
        M 0x20200080UL, 0x6e1dca6a815aeb72UL
        M 0x20200088UL, 0x5b91c8cf7dc0959UL ]
    given0
    |> run um [ "6109a001" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x20200081UL
        Status, 0x10UL
        M 0x20200078UL, 0x924a18f010ad6f89UL
        M 0x20200080UL, 0x9215a0ad682d3f22UL
        M 0x20200088UL, 0xed978f7ea38e97adUL ]
    given1
    |> run um [ "6109a001" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x20200084UL
        Status, 0x10UL
        M 0x20200078UL, 0x173843191472bf3aUL
        M 0x20200080UL, 0x8e5bea0a2bb32353UL
        M 0x20200088UL, 0x19559ba571827131UL ]
    given2
    |> run um [ "6109a001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 4541, swm s0, ra, 4(sp), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SWM16``() =
    let given0 =
      [ G 16, 0x7UL
        G 29, 0x2020007cUL
        G 31, 0x3UL
        M 0x20200078UL, 0xe7771764ca901cf6UL
        M 0x20200080UL, 0xd83f14ce6f5cccf4UL
        M 0x20200088UL, 0x1a04a5e5e343e95UL ]
    given0
    |> run um [ "4541" ]
    |> is [ M 0x20200080UL, 0x700000003UL ]
    let given1 =
      [ G 16, 0x7fffffffUL
        G 29, 0x2020007cUL
        G 31, 0x1UL
        M 0x20200078UL, 0xbbb802a0f3d1d44fUL
        M 0x20200080UL, 0xf78016e744f574afUL
        M 0x20200088UL, 0x21d7a3568d86288dUL ]
    given1
    |> run um [ "4541" ]
    |> is [ M 0x20200080UL, 0x7fffffff00000001UL ]
    let given2 =
      [ G 16, 0xffffffff89abcdefUL
        G 29, 0x2020007cUL
        G 31, 0x12345678UL
        M 0x20200078UL, 0x17d99c3d37b41ac0UL
        M 0x20200080UL, 0xf7967a3bdd7b8d8UL
        M 0x20200088UL, 0x62c6ccb60e0284f0UL ]
    given2
    |> run um [ "4541" ]
    |> is [ M 0x20200080UL, 0x89abcdef12345678UL ]

  /// <summary>
  /// 2044d008, swm s0, s1, 8(a0), against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SWM32``() =
    let given0 =
      [ G 4, 0x20200078UL
        G 16, 0x7UL
        G 17, 0x3UL
        M 0x20200078UL, 0xfac1f3b3e7188f10UL
        M 0x20200080UL, 0xd9f1df9aeccbd416UL
        M 0x20200088UL, 0xbaf7edc46be38a0UL ]
    given0
    |> run um [ "2044d008" ]
    |> is [ M 0x20200080UL, 0x700000003UL ]
    let given1 =
      [ G 4, 0x20200078UL
        G 16, 0x7fffffffUL
        G 17, 0x1UL
        M 0x20200078UL, 0xff9485e04e3d6c4bUL
        M 0x20200080UL, 0x440c9a7e2da1b761UL
        M 0x20200088UL, 0xbfd78c45df5e3971UL ]
    given1
    |> run um [ "2044d008" ]
    |> is [ M 0x20200080UL, 0x7fffffff00000001UL ]
    let given2 =
      [ G 4, 0x20200078UL
        G 16, 0xffffffff89abcdefUL
        G 17, 0x12345678UL
        M 0x20200078UL, 0x42546bcd0a5ad7eaUL
        M 0x20200080UL, 0x3710f7bc653f6bbcUL
        M 0x20200088UL, 0xd87e2ffc24ddac5fUL ]
    given2
    |> run um [ "2044d008" ]
    |> is [ M 0x20200080UL, 0x89abcdef12345678UL ]

  /// <summary>
  /// 20449008, swp v0, v1, 8(a0), against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SWP``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x3UL
        G 4, 0x20200078UL
        M 0x20200078UL, 0x480cf8dfc5729723UL
        M 0x20200080UL, 0x56bfdf34423df99eUL
        M 0x20200088UL, 0x85e0c305d02e6e5dUL ]
    given0
    |> run um [ "20449008" ]
    |> is [ M 0x20200080UL, 0x700000003UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x1UL
        G 4, 0x20200078UL
        M 0x20200078UL, 0xe41fc6f2d5da524aUL
        M 0x20200080UL, 0x4908b9bfc2579e0cUL
        M 0x20200088UL, 0xee108d2bd9ea39c5UL ]
    given1
    |> run um [ "20449008" ]
    |> is [ M 0x20200080UL, 0x7fffffff00000001UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x12345678UL
        G 4, 0x20200078UL
        M 0x20200078UL, 0x70ac8032b9a7c62bUL
        M 0x20200080UL, 0x5d0601b3dea7e4bdUL
        M 0x20200088UL, 0x41de56d99d25adc3UL ]
    given2
    |> run um [ "20449008" ]
    |> is [ M 0x20200080UL, 0x89abcdef12345678UL ]

  /// <summary>
  /// 61099001, swr a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SWR``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x20200080UL
        M 0x20200078UL, 0x9520a9538f71ab7UL
        M 0x20200080UL, 0x7f01634ee889e65bUL
        M 0x20200088UL, 0x9153f03dc5c5e811UL ]
    given0
    |> run um [ "61099001" ]
    |> is [ M 0x20200080UL, 0x7634ee889e65bUL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x20200081UL
        M 0x20200078UL, 0x29bd0caac162c4a8UL
        M 0x20200080UL, 0x12c2cb4120070521UL
        M 0x20200088UL, 0xc7ab1658a1cbc3b3UL ]
    given1
    |> run um [ "61099001" ]
    |> is [ M 0x20200080UL, 0xffffff4120070521UL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x20200084UL
        M 0x20200078UL, 0x2f0367fc340fe3eaUL
        M 0x20200080UL, 0x621d9bdad9a8e4f3UL
        M 0x20200088UL, 0xa4288882244c506cUL ]
    given2
    |> run um [ "61099001" ]
    |> is [ M 0x20200080UL, 0x621d9bdacdefe4f3UL ]

  /// <summary>
  /// 6109a201, swre a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SWRE``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x20200080UL
        Status, 0x10UL
        M 0x20200078UL, 0x3d3d10d61eceba92UL
        M 0x20200080UL, 0x158e699bd94a5d1cUL
        M 0x20200088UL, 0x96f406466caa05eeUL ]
    given0
    |> run um [ "6109a201" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x20200081UL
        Status, 0x10UL
        M 0x20200078UL, 0x291078743ed83d2UL
        M 0x20200080UL, 0x4cb6fbf62c94f130UL
        M 0x20200088UL, 0x71c16764dbd7869bUL ]
    given1
    |> run um [ "6109a201" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x20200084UL
        Status, 0x10UL
        M 0x20200078UL, 0x7096163cd5eb4f0eUL
        M 0x20200080UL, 0xaccbc948d08c95e3UL
        M 0x20200088UL, 0xcb3fcdc7bc35e796UL ]
    given2
    |> run um [ "6109a201" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// c821, sw at, 4(sp), against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SWSP``() =
    let given0 =
      [ G 1, 0x7UL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x2a1260c708ad28f8UL
        M 0x20200080UL, 0x32e48ac233fc28aeUL
        M 0x20200088UL, 0x684f9548e6176f74UL ]
    given0
    |> run um [ "c821" ]
    |> is [ M 0x20200080UL, 0x733fc28aeUL ]
    let given1 =
      [ G 1, 0x7fffffffUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0xd2f056d0bcac5fd1UL
        M 0x20200080UL, 0xe293973fab321287UL
        M 0x20200088UL, 0x74a93d3057e9a24bUL ]
    given1
    |> run um [ "c821" ]
    |> is [ M 0x20200080UL, 0x7fffffffab321287UL ]
    let given2 =
      [ G 1, 0xffffffff89abcdefUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0xa0eb669cd8ff2fcaUL
        M 0x20200080UL, 0x5112652afd8fc361UL
        M 0x20200088UL, 0xa9601a4d458811eUL ]
    given2
    |> run um [ "c821" ]
    |> is [ M 0x20200080UL, 0x89abcdeffd8fc361UL ]

  /// <summary>
  /// 55281088, swxc1 f2, a5(a4), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after swxc1 $f2,$9($8), the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SWXC1``() =
    let given0 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0xbf800000UL
        M 0x20200078UL, 0x280a2769a1f8c7d7UL
        M 0x20200080UL, 0x50343a834d10756eUL
        M 0x20200088UL, 0x346912c075149b52UL ]
    given0
    |> run um [ "55281088" ]
    |> is [ M 0x20200080UL, 0xbf8000004d10756eUL ]
    let given1 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0x40600000UL
        M 0x20200078UL, 0xf86038b6cad42053UL
        M 0x20200080UL, 0x48c84175832f138UL
        M 0x20200088UL, 0xac4843c639219b61UL ]
    given1
    |> run um [ "55281088" ]
    |> is [ M 0x20200080UL, 0x406000005832f138UL ]
    let given2 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0x3e800000UL
        M 0x20200078UL, 0xae3126bf297126f2UL
        M 0x20200080UL, 0x6a2e44c3fb920857UL
        M 0x20200088UL, 0xafceb9c3cbd3a5a6UL ]
    given2
    |> run um [ "55281088" ]
    |> is [ M 0x20200080UL, 0x3e800000fb920857UL ]

  /// <summary>
  /// 00026b7c, sync 0x2, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SYNC``() =
    []
    |> run um [ "00026b7c" ]
    |> is []
    []
    |> run um [ "00026b7c" ]
    |> is []
    []
    |> run um [ "00026b7c" ]
    |> is []

  /// <summary>
  /// 42080001, synci 1(a4), against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SYNCI``() =
    let given0 =
      [ G 8, 0x2020007fUL
        M 0x20200078UL, 0x4cfb9cb94b16b965UL
        M 0x20200080UL, 0x61c8abeaa9a577caUL
        M 0x20200088UL, 0xf9c7f550a4b646aaUL ]
    given0
    |> run um [ "42080001" ]
    |> is []
    let given1 =
      [ G 8, 0x2020007fUL
        M 0x20200078UL, 0x5ab43f6692fc3985UL
        M 0x20200080UL, 0xcc7db2214e746089UL
        M 0x20200088UL, 0x562608572db565bbUL ]
    given1
    |> run um [ "42080001" ]
    |> is []
    let given2 =
      [ G 8, 0x2020007fUL
        M 0x20200078UL, 0xe8c48f4c606884e5UL
        M 0x20200080UL, 0x3845db31077c62a0UL
        M 0x20200088UL, 0x252d416aa5318402UL ]
    given2
    |> run um [ "42080001" ]
    |> is []

  /// <summary>
  /// 00228b7c, syscall 0x22. Not run against QEMU, where a system call is the
  /// host kernel answering rather than the instruction. The lift raises SysCall
  /// and changes nothing.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SYSCALL``() =
    []
    |> run um [ "00228b7c" ]
    |> raises [ SysCall ] []

  /// <summary>
  /// 0128003c, teq a4, a5, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGTRAP (Interrupt 13 here); the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TEQ``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "0128003c" ]
    |> is []
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "0128003c" ]
    |> is []
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "0128003c" ]
    |> is []
    [ G 8, 0x7UL; G 9, 0x7UL ]
    |> run um [ "0128003c" ]
    |> raises [ Interrupt 13 ] []
    [ G 9, 0x1UL ]
    |> run um [ "0128003c" ]
    |> is []

  /// <summary>
  /// 41c80001, teqi a4, 0x1, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGTRAP (Interrupt 13 here); the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TEQI``() =
    [ G 8, 0x7UL ]
    |> run um [ "41c80001" ]
    |> is []
    [ G 8, 0x7fffffffUL ]
    |> run um [ "41c80001" ]
    |> is []
    [ G 8, 0xffffffff89abcdefUL ]
    |> run um [ "41c80001" ]
    |> is []
    [ G 8, 0x1UL ]
    |> run um [ "41c80001" ]
    |> raises [ Interrupt 13 ] []
    []
    |> run um [ "41c80001" ]
    |> is []

  /// <summary>
  /// 0128023c, tge a4, a5, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGTRAP (Interrupt 13 here); the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TGE``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "0128023c" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "0128023c" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "0128023c" ]
    |> is []
    [ G 8, 0x7UL; G 9, 0x7UL ]
    |> run um [ "0128023c" ]
    |> raises [ Interrupt 13 ] []
    [ G 9, 0x1UL ]
    |> run um [ "0128023c" ]
    |> is []

  /// <summary>
  /// 41280001, tgei a4, 0x1, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGTRAP (Interrupt 13 here); the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TGEI``() =
    [ G 8, 0x7UL ]
    |> run um [ "41280001" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0x7fffffffUL ]
    |> run um [ "41280001" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0xffffffff89abcdefUL ]
    |> run um [ "41280001" ]
    |> is []
    [ G 8, 0x1UL ]
    |> run um [ "41280001" ]
    |> raises [ Interrupt 13 ] []
    []
    |> run um [ "41280001" ]
    |> is []

  /// <summary>
  /// 41680001, tgeiu a4, 0x1, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGTRAP (Interrupt 13 here); the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TGEIU``() =
    [ G 8, 0x7UL ]
    |> run um [ "41680001" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0x7fffffffUL ]
    |> run um [ "41680001" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0xffffffff89abcdefUL ]
    |> run um [ "41680001" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0x1UL ]
    |> run um [ "41680001" ]
    |> raises [ Interrupt 13 ] []
    []
    |> run um [ "41680001" ]
    |> is []

  /// <summary>
  /// 0128043c, tgeu a4, a5, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGTRAP (Interrupt 13 here); the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TGEU``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "0128043c" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "0128043c" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "0128043c" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0x7UL; G 9, 0x7UL ]
    |> run um [ "0128043c" ]
    |> raises [ Interrupt 13 ] []
    [ G 9, 0x1UL ]
    |> run um [ "0128043c" ]
    |> is []

  /// <summary>
  /// 0000037c, tlbp, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10 puts
  /// the lift in User Mode, the mode QEMU runs every word in; the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TLBP``() =
    [ Status, 0x10UL ]
    |> run um [ "0000037c" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run um [ "0000037c" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run um [ "0000037c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 0000137c, tlbr, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10 puts
  /// the lift in User Mode, the mode QEMU runs every word in; the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TLBR``() =
    [ Status, 0x10UL ]
    |> run um [ "0000137c" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run um [ "0000137c" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run um [ "0000137c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 0000237c, tlbwi, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10 puts
  /// the lift in User Mode, the mode QEMU runs every word in; the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TLBWI``() =
    [ Status, 0x10UL ]
    |> run um [ "0000237c" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run um [ "0000237c" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run um [ "0000237c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 0000337c, tlbwr, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10 puts
  /// the lift in User Mode, the mode QEMU runs every word in; the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TLBWR``() =
    [ Status, 0x10UL ]
    |> run um [ "0000337c" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run um [ "0000337c" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run um [ "0000337c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 0128083c, tlt a4, a5, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGTRAP (Interrupt 13 here); the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TLT``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "0128083c" ]
    |> is []
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "0128083c" ]
    |> is []
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "0128083c" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0x7UL; G 9, 0x7UL ]
    |> run um [ "0128083c" ]
    |> is []
    [ G 9, 0x1UL ]
    |> run um [ "0128083c" ]
    |> raises [ Interrupt 13 ] []

  /// <summary>
  /// 41080001, tlti a4, 0x1, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGTRAP (Interrupt 13 here); the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TLTI``() =
    [ G 8, 0x7UL ]
    |> run um [ "41080001" ]
    |> is []
    [ G 8, 0x7fffffffUL ]
    |> run um [ "41080001" ]
    |> is []
    [ G 8, 0xffffffff89abcdefUL ]
    |> run um [ "41080001" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0x1UL ]
    |> run um [ "41080001" ]
    |> is []
    []
    |> run um [ "41080001" ]
    |> raises [ Interrupt 13 ] []

  /// <summary>
  /// 41480001, tltiu a4, 0x1, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGTRAP (Interrupt 13 here); the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TLTIU``() =
    [ G 8, 0x7UL ]
    |> run um [ "41480001" ]
    |> is []
    [ G 8, 0x7fffffffUL ]
    |> run um [ "41480001" ]
    |> is []
    [ G 8, 0xffffffff89abcdefUL ]
    |> run um [ "41480001" ]
    |> is []
    [ G 8, 0x1UL ]
    |> run um [ "41480001" ]
    |> is []
    []
    |> run um [ "41480001" ]
    |> raises [ Interrupt 13 ] []

  /// <summary>
  /// 01280a3c, tltu a4, a5, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGTRAP (Interrupt 13 here); the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TLTU``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "01280a3c" ]
    |> is []
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "01280a3c" ]
    |> is []
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "01280a3c" ]
    |> is []
    [ G 8, 0x7UL; G 9, 0x7UL ]
    |> run um [ "01280a3c" ]
    |> is []
    [ G 9, 0x1UL ]
    |> run um [ "01280a3c" ]
    |> raises [ Interrupt 13 ] []

  /// <summary>
  /// 01280c3c, tne a4, a5, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGTRAP (Interrupt 13 here); the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TNE``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "01280c3c" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "01280c3c" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "01280c3c" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0x7UL; G 9, 0x7UL ]
    |> run um [ "01280c3c" ]
    |> is []
    [ G 9, 0x1UL ]
    |> run um [ "01280c3c" ]
    |> raises [ Interrupt 13 ] []

  /// <summary>
  /// 41880001, tnei a4, 0x1, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGTRAP (Interrupt 13 here); the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TNEI``() =
    [ G 8, 0x7UL ]
    |> run um [ "41880001" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0x7fffffffUL ]
    |> run um [ "41880001" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0xffffffff89abcdefUL ]
    |> run um [ "41880001" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0x1UL ]
    |> run um [ "41880001" ]
    |> is []
    []
    |> run um [ "41880001" ]
    |> raises [ Interrupt 13 ] []

  /// <summary>
  /// 5444233b, trunc.l.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after trunc.l.s $f2,$f4, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TRUNC.L.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run um [ "5444233b" ]
    |> is [ F 2, 0x2UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run um [ "5444233b" ]
    |> is [ F 2, 0xffffffffffffffffUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run um [ "5444233b" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 54442b3b, trunc.w.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after trunc.w.s $f2,$f4, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TRUNC.W.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run um [ "54442b3b" ]
    |> is [ F 2, 0x2UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run um [ "54442b3b" ]
    |> is [ F 2, 0xffffffffUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run um [ "54442b3b" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 0022937c, wait 0x22, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10 puts
  /// the lift in User Mode, the mode QEMU runs every word in; the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 WAIT``() =
    [ Status, 0x10UL ]
    |> run um [ "0022937c" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run um [ "0022937c" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run um [ "0022937c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 0109f17c, wrpgpr a4, a5, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 WRPGPR``() =
    [ G 8, 0x7UL; G 9, 0x3UL; Status, 0x10UL ]
    |> run um [ "0109f17c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; Status, 0x10UL ]
    |> run um [ "0109f17c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; Status, 0x10UL ]
    |> run um [ "0109f17c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 01097b3c, wsbh a4, a5, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 WSBH``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "01097b3c" ]
    |> is [ G 8, 0x300UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "01097b3c" ]
    |> is [ G 8, 0x100UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "01097b3c" ]
    |> is [ G 8, 0x34127856UL ]

  /// <summary>
  /// 01494310, xor a4, a5, a6, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 XOR``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "01494310" ]
    |> is [ G 8, 0x6UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "01494310" ]
    |> is [ G 8, 0xffffffffffffffffUL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "01494310" ]
    |> is [ G 8, 0xffffffffece8ece0UL ]

  /// <summary>
  /// 4453, xor v0, v0, v1, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 XOR16``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run um [ "4453" ]
    |> is [ G 2, 0x4UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run um [ "4453" ]
    |> is [ G 2, 0x7ffffffeUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run um [ "4453" ]
    |> is [ G 2, 0xffffffff9b9f9b97UL ]

  /// <summary>
  /// 71090001, xori a4, a5, 0x1, against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 XORI``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "71090001" ]
    |> is [ G 8, 0x2UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "71090001" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "71090001" ]
    |> is [ G 8, 0x12345679UL ]
