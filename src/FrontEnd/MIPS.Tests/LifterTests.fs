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
