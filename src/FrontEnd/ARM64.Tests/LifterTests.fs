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

namespace B2R2.FrontEnd.ARM64.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.ARM64
open B2R2.BinIR.LowUIR.AST.InfixOp
open type Register

[<TestClass>]
type LifterTests() =
  let num (v: uint32) = BitVector(v, 32<rt>) |> AST.num

  let num64 (v: uint64) = BitVector(v, 64<rt>) |> AST.num

  let bv64 (v: uint64) = BitVector(v, 64<rt>)

  let unwrapStmts stmts = Array.sub stmts 1 (Array.length stmts - 2)

  let isa = ISA(Architecture.ARMv8, Endian.Big)

  let reader = BinReader.Init Endian.Big

  let regFactory = RegisterFactory isa :> IRegisterFactory

  let ( !. ) name = Register.toRegID name |> regFactory.GetRegVar

  (* The halves of a vector register are pseudo registers: V0A is Q0's
     first, V0B its second. *)
  let ( !@ ) (name, pos) =
    regFactory.GetPseudoRegVar(Register.toRegID name, pos)

  let ( ++ ) (byteStr: string) (givenStmts: Stmt[]) =
    ByteArray.ofHexString byteStr, givenStmts

  let unsupported = AST.sideEffect BinIR.SideEffect.UnsupportedInstruction

  /// The statements one encoding lifts to, for a test whose claim is that
  /// the encoding lifts at all rather than what it lifts to.
  let lifted (hex: string) =
    let parser = Parser reader :> IInstructionParsable
    let builder = ILowUIRBuilder.Default(isa, regFactory, LowUIRStream())
    let ins = parser.Parse(ByteArray.ofHexString hex, 0UL)
    ins.Translate builder

  let test (bytes: byte[], givenStmts) =
    let parser = Parser reader :> IInstructionParsable
    let builder = ILowUIRBuilder.Default(isa, regFactory, LowUIRStream())
    let ins = parser.Parse(bytes, 0UL)
    CollectionAssert.AreEqual(givenStmts, unwrapStmts <| ins.Translate builder)

  /// The statements one encoding lifts to, as the text they print as.
  let liftedText (hex: string) =
    lifted hex |> Array.map string |> String.concat "\n"

  /// How a failed authentication writes its error code over bits 62:61, as
  /// the lifted text spells it.
  let poison (code: uint64) =
    $"& 0x9fffffffffffffff:I64) | 0x{code:x16}:I64"

  /// Whether a statement jumps to the given expression.
  let jumpsTo target (stmt: Stmt) =
    match stmt with
    | InterJmp(Target = t) -> t = target
    | _ -> false

  /// What one encoding assigns to a register or a temporary, if anything.
  let assigned (hex: string) dst =
    lifted hex
    |> Array.tryPick (function
      | Put(Dst = d; Src = src) when d = dst -> Some src
      | _ -> None)

  /// QC after one encoding ran on both halves of V1 and V2 set to the given
  /// words.
  let qcAfter hex v1 v2 =
    let inputs =
      [ !@(Q1, 1), bv64 v1
        !@(Q1, 2), bv64 v1
        !@(Q2, 1), bv64 v2
        !@(Q2, 2), bv64 v2 ]
    let read = IRRunner.run (lifted hex) inputs
    (read !.FPSR).ToUInt64() >>> 27 &&& 1UL

  (* FPCR.FZ, FPCR.FZ16 and FPCR.AHP, as FPCR holds them *)
  let fz = 1UL <<< 24

  let fz16 = 1UL <<< 19

  let ahp = 1UL <<< 26

  /// What one encoding leaves in the low half of V0 and in FPSR, run with
  /// FPCR and the low half of V1 set to the given words.
  let fpAfter hex fpcr v1 =
    let inputs = [ !.FPCR, bv64 fpcr; !@(Q1, 1), bv64 v1 ]
    let read = IRRunner.run (lifted hex) inputs
    (read !@(Q0, 1)).ToUInt64(), (read !.FPSR).ToUInt64()

  (* NGC, NGCS and a BFC with a non-zero lsb all reached the raising
     fall-through in `translate`, so a block containing one did not lift at
     all. The claim these pin is exactly that -- each encoding produces
     statements instead of NotImplementedIRException. *)
  [<TestMethod>]
  member _.``[AArch64] NGC lifts``() =
    Assert.AreEqual<bool>(true, (lifted "da0103e0").Length > 0, "NGC")

  [<TestMethod>]
  member _.``[AArch64] NGCS lifts``() =
    Assert.AreEqual<bool>(true, (lifted "fa0103e0").Length > 0, "NGCS")

  [<TestMethod>]
  member _.``[AArch64] BFC with a non-zero lsb lifts``() =
    Assert.AreEqual<bool>(true, (lifted "b3781fe0").Length > 0, "BFC")

  /// <summary>
  /// What EL1 keeps to itself is UNDEFINED at EL0 and nothing at EL1, where
  /// there is no TLB or cache to maintain (C5.1.1): TLBI VMALLE1, IC IALLU
  /// and DC IVAC. TLBI ALLE2 needs EL2, which this model does not have, and
  /// is UNDEFINED at both; CFP RCTX runs at EL0 only where SCTLR_EL1.EnRCTX
  /// lets it; AT is UNDEFINED at EL0, runs at EL1 with the MMU off and is
  /// unsupported with it on, there being no table walk; and a SYS no alias
  /// names is UNDEFINED.
  /// </summary>
  [<TestMethod>]
  member _.``[AArch64] System maintenance needs its exception level``() =
    let at el (sctlr: uint64) hex =
      let inputs =
        [ !.CURRENTEL, bv64 (uint64 el <<< 2); !.SCTLREL1, bv64 sctlr ]
      IRRunner.effects (lifted hex) inputs
    let undef = [ BinIR.SideEffect.UndefinedInstruction ]
    let none: BinIR.SideEffect list = []
    for hex in [ "d508871f"; "d508751f"; "d5087621" ] do
      Assert.AreEqual<BinIR.SideEffect list>(undef, at 0 0UL hex, hex)
      Assert.AreEqual<BinIR.SideEffect list>(none, at 1 0UL hex, hex)
    Assert.AreEqual<BinIR.SideEffect list>(undef, at 1 0UL "d50c871f")
    Assert.AreEqual<BinIR.SideEffect list>(undef, at 0 0UL "d50b7384")
    Assert.AreEqual<BinIR.SideEffect list>(none, at 0 0x400UL "d50b7384")
    Assert.AreEqual<BinIR.SideEffect list>(undef, at 0 0UL "d5087802")
    let unsupported = [ BinIR.SideEffect.UnsupportedInstruction ]
    Assert.AreEqual<BinIR.SideEffect list>(none, at 1 0UL "d5087802")
    Assert.AreEqual<BinIR.SideEffect list>(unsupported, at 1 1UL "d5087802")
    Assert.AreEqual<BinIR.SideEffect list>(undef, at 1 0UL "d5080005")

  /// <summary>
  /// AT S1E1R X2 with the MMU off, as a Cortex-A57 answers it (D13.2.100): an
  /// address below 2^44 is its own page, Device-nGnRnE, SH 0b10, NS and bit
  /// 11 set; one at or above it is an Address size fault at level 0. A tag in
  /// the top byte is outside the range unless TCR_EL1.TBI0 ignores it, and
  /// bit 55 selects TBI1, past which the range still ends at bit 44.
  /// </summary>
  [<TestMethod>]
  member _.``[AArch64] AT with the MMU off answers the identity``() =
    let par (tcr: uint64) va =
      let inputs =
        [ !.CURRENTEL, bv64 0x4UL
          !.SCTLREL1, bv64 0x00c50838UL
          !.TCREL1, bv64 tcr
          !.X2, bv64 va ]
      let read = IRRunner.run (lifted "d5087802") inputs
      (read !.PAREL1).ToUInt64()
    let tbi = 3UL <<< 37
    Assert.AreEqual<uint64>(0x40080b00UL, par 0UL 0x40080abcUL)
    Assert.AreEqual<uint64>(0xfffffffeb00UL, par 0UL 0xfffffffe123UL)
    Assert.AreEqual<uint64>(0x801UL, par 0UL 0x100000000456UL)
    Assert.AreEqual<uint64>(0x801UL, par 0UL 0xff00000040080abcUL)
    Assert.AreEqual<uint64>(0x40080b00UL, par tbi 0xff00000040080abcUL)
    Assert.AreEqual<uint64>(0x801UL, par tbi 0x0080000040080123UL)

  /// PAR_EL1 is a system register MRS reads by name, from reset on.
  [<TestMethod>]
  member _.``[AArch64] PAR_EL1 is a modelled system register``() =
    Assert.AreEqual<bool>(true, List.contains PAREL1 SysReg.modelled)
    Assert.AreEqual<uint64>(0UL, SysReg.resetValue PAREL1)

  /// <summary>
  /// What MRS and MSR reach at EL0 (AArch64.CheckSystemAccess, J1.1): only
  /// a register whose op1 is 3. MIDR_EL1, CurrentEL and an unnamed register
  /// with op1 0 are UNDEFINED there and read at EL1; NZCV and TPIDR_EL0 are
  /// EL0's; DAIF needs SCTLR_EL1.UMA and a read of CTR_EL0 SCTLR_EL1.UCT, and
  /// CTR_EL0 takes no write. An unnamed register with op1 3 is EL0's and
  /// still unsupported.
  /// </summary>
  [<TestMethod>]
  member _.``[AArch64] MRS and MSR reach EL0's registers only``() =
    let at el (sctlr: uint64) hex =
      let inputs =
        [ !.CURRENTEL, bv64 (uint64 el <<< 2); !.SCTLREL1, bv64 sctlr ]
      IRRunner.effects (lifted hex) inputs
    let undef = [ BinIR.SideEffect.UndefinedInstruction ]
    let none: BinIR.SideEffect list = []
    let uma, uct = 1UL <<< 9, 1UL <<< 15
    for hex in [ "d5380000"; "d5384240"; "d538f200" ] do
      Assert.AreEqual<BinIR.SideEffect list>(undef, at 0 0UL hex, hex)
    Assert.AreEqual<BinIR.SideEffect list>(none, at 1 0UL "d5380000")
    Assert.AreEqual<BinIR.SideEffect list>(none, at 0 0UL "d53b4200")
    Assert.AreEqual<BinIR.SideEffect list>(none, at 0 0UL "d53bd040")
    Assert.AreEqual<BinIR.SideEffect list>(undef, at 0 0UL "d53b4220")
    Assert.AreEqual<BinIR.SideEffect list>(undef, at 0 0UL "d51b4220")
    Assert.AreEqual<BinIR.SideEffect list>(none, at 0 uma "d53b4220")
    Assert.AreEqual<BinIR.SideEffect list>(undef, at 0 0UL "d53b0020")
    Assert.AreEqual<BinIR.SideEffect list>(none, at 0 uct "d53b0020")
    Assert.AreEqual<BinIR.SideEffect list>(undef, at 0 uct "d51b0020")
    let unsupported = [ BinIR.SideEffect.UnsupportedInstruction ]
    Assert.AreEqual<BinIR.SideEffect list>(unsupported, at 0 0UL "d53bf200")

  /// MSR (immediate) at EL0 (C6.2.194): SPSel, PAN and UAO need EL1, and
  /// DAIFSet and DAIFClr SCTLR_EL1.UMA; DIT is EL0's.
  [<TestMethod>]
  member _.``[AArch64] MSR (immediate) reaches EL0's fields only``() =
    let at el (sctlr: uint64) hex =
      let inputs =
        [ !.CURRENTEL, bv64 (uint64 el <<< 2); !.SCTLREL1, bv64 sctlr ]
      IRRunner.effects (lifted hex) inputs
    let undef = [ BinIR.SideEffect.UndefinedInstruction ]
    let none: BinIR.SideEffect list = []
    for hex in [ "d50041bf"; "d500419f"; "d500407f"; "d50342df" ] do
      Assert.AreEqual<BinIR.SideEffect list>(undef, at 0 0UL hex, hex)
      Assert.AreEqual<BinIR.SideEffect list>(none, at 1 0UL hex, hex)
    Assert.AreEqual<BinIR.SideEffect list>(none, at 0 (1UL <<< 9) "d50342df")
    Assert.AreEqual<BinIR.SideEffect list>(none, at 0 0UL "d503405f")

  /// DC GZVA clears the block DC ZVA does and the allocation tags no memory
  /// here holds, and DC GVA writes only those tags: it lifts to nothing, as
  /// IC IVAU does, there being no cache to maintain.
  [<TestMethod>]
  member _.``[AArch64] DC GZVA clears what DC ZVA does``() =
    let body hex =
      lifted hex
      |> Array.filter (function
        | ISMark _ | IEMark _ -> false
        | _ -> true)
    CollectionAssert.AreEqual(body "d50b7421", body "d50b7481")
    Assert.AreEqual<int>(0, (body "d50b7461").Length)
    Assert.AreEqual<int>(0, (body "d50b7520").Length)

  /// BFC clears the field it names and keeps the rest (C6.2.27): BFC X0, #8,
  /// #8 on all ones leaves bits 15:8 clear.
  [<TestMethod>]
  member _.``[AArch64] BFC clears its field``() =
    let inputs = [ !.X0, bv64 0xffffffffffffffffUL ]
    let read = IRRunner.run (lifted "b3781fe0") inputs
    Assert.AreEqual<uint64>(0xffffffffffff00ffUL, (read !.X0).ToUInt64())

  /// BLR X30 goes where X30 pointed, not to the instruction after it: the
  /// target is taken before the link register is written, so the jump is to
  /// that copy and never to X30 itself.
  [<TestMethod>]
  member _.``[AArch64] BLR X30 branches to the old X30``() =
    let jumps = lifted "d63f03c0" |> Array.exists (jumpsTo !.X30)
    Assert.AreEqual<bool>(false, jumps)

  [<TestMethod>]
  member _.``[AArch64] ADD (immedate) lift test``() =
    "114dc4ba"
    ++ [| !.X26 := AST.zext 64<rt>
           ((AST.xtlo 32<rt> !.X5 .+ num 0x371000u .+ num 0x0u)) |]
    |> test

  [<TestMethod>]
  member _.``[AArch64] ADD (extended register) lift test``() =
    "0b3f43ff"
    ++ [| !.SP := AST.zext 64<rt>
           (AST.xtlo 32<rt> !.SP .+ AST.xtlo 32<rt> !.XZR .+ num 0x0u) |]
    |> test

  [<TestMethod>]
  member _.``[AArch64] ADD (shifted register) lift test``() =
    "0b8e5f9b"
    ++ [| !.X27 := AST.zext 64<rt>
           (AST.xtlo 32<rt> !.X28 .+ (AST.xtlo 32<rt> !.X14 ?>> num 0x17u)
             .+ num 0x0u) |]
    |> test

  [<TestMethod>]
  member _.``[AArch64] ADD (extended register, UXTX) lift test``() =
    "8b336280"
    ++ [| !.X0 := !.X20 .+ (!.X19 << num64 0x0UL) .+ num64 0x0UL |]
    |> test

  /// DC ZVA clears the block DCZID_EL0 names, so the register has to be one
  /// this front end models, with a value from reset on.
  [<TestMethod>]
  member _.``[AArch64] DCZID_EL0 is a modelled system register``() =
    Assert.AreEqual<bool>(true, List.contains DCZIDEL0 SysReg.modelled)

  /// What it holds is what the processor holds: a Cortex-A57 clears sixteen
  /// words, which DCZID_EL0.BS spells as four.
  [<TestMethod>]
  member _.``[AArch64] DCZID_EL0 holds a Cortex-A57's block size``() =
    Assert.AreEqual<uint64>(0x4UL, SysReg.resetValue DCZIDEL0)

  /// CTR_EL0 is a Cortex-A57's, which gives sixty-four-byte lines on both
  /// sides: DminLine and IminLine are log2 words, four each.
  [<TestMethod>]
  member _.``[AArch64] CTR_EL0 holds a Cortex-A57's line sizes``() =
    Assert.AreEqual<bool>(true, List.contains CTREL0 SysReg.modelled)
    Assert.AreEqual<uint64>(0x8444c004UL, SysReg.resetValue CTREL0)

  /// DAIFSet and DAIFClr set and clear the masks their immediate names, at the
  /// bits DAIF keeps them in, and leave the other masks as they were. Each
  /// runs at EL1, where nothing stops it.
  [<TestMethod>]
  member _.``[AArch64] MSR DAIFSet ORs its masks into DAIF``() =
    let inputs = [ !.CURRENTEL, bv64 0x4UL; !.DAIF, bv64 0x200UL ]
    let read = IRRunner.run (lifted "d50345df") inputs
    Assert.AreEqual<uint64>(0x340UL, (read !.DAIF).ToUInt64())

  [<TestMethod>]
  member _.``[AArch64] MSR DAIFClr clears its masks from DAIF``() =
    let inputs = [ !.CURRENTEL, bv64 0x4UL; !.DAIF, bv64 0x3c0UL ]
    let read = IRRunner.run (lifted "d50343ff") inputs
    Assert.AreEqual<uint64>(0x300UL, (read !.DAIF).ToUInt64())

  /// Every other field takes the low bit of the immediate and nothing else.
  [<TestMethod>]
  member _.``[AArch64] MSR PAN takes the low bit of its immediate``() =
    let inputs = [ !.CURRENTEL, bv64 0x4UL ]
    let read = IRRunner.run (lifted "d5004f9f") inputs
    Assert.AreEqual<uint64>(0x400000UL, (read !.PAN).ToUInt64())

  /// A register that is a window onto PSTATE keeps only its field's bits.
  [<TestMethod>]
  member _.``[AArch64] MSR DAIF keeps only the mask bits``() =
    let inputs = [ !.CURRENTEL, bv64 0x4UL; !.X0, bv64 ~~~0UL ]
    let read = IRRunner.run (lifted "d51b4220") inputs
    Assert.AreEqual<uint64>(0x3c0UL, (read !.DAIF).ToUInt64())

  /// What a system register with no name holds is the processor's own, so a
  /// read or a write of one is left to the emulator to report rather than
  /// given a value nothing stands behind -- at EL1, where either may run.
  [<TestMethod>]
  member _.``[AArch64] MRS of an unnamed system register is unsupported``() =
    let inputs = [ !.CURRENTEL, bv64 0x4UL ]
    let effects = IRRunner.effects (lifted "d538f200") inputs
    let unsupported = [ BinIR.SideEffect.UnsupportedInstruction ]
    Assert.AreEqual<BinIR.SideEffect list>(unsupported, effects)

  [<TestMethod>]
  member _.``[AArch64] MSR to an unnamed system register is unsupported``() =
    let inputs = [ !.CURRENTEL, bv64 0x4UL ]
    let effects = IRRunner.effects (lifted "d51ff001") inputs
    let unsupported = [ BinIR.SideEffect.UnsupportedInstruction ]
    Assert.AreEqual<BinIR.SideEffect list>(unsupported, effects)

  /// A failed authentication puts key_number:NOT(key_number) in bits 62:61 in
  /// place of what was there (Auth(), J1-7662): 01 under an A key, 10 under a
  /// B key. Setting one bit on top of the address would leave an address in
  /// the upper half, whose top bits are all ones, exactly as it was.
  [<TestMethod>]
  member _.``[AArch64] A failed AUTIA leaves 01 in bits 62:61``() =
    StringAssert.Contains(liftedText "dac11020", poison 0x2000000000000000UL)

  [<TestMethod>]
  member _.``[AArch64] A failed AUTIB leaves 10 in bits 62:61``() =
    StringAssert.Contains(liftedText "dac11420", poison 0x4000000000000000UL)

  [<TestMethod>]
  member _.``[AArch64] A failed AUTDA leaves 01 in bits 62:61``() =
    StringAssert.Contains(liftedText "dac11820", poison 0x2000000000000000UL)

  [<TestMethod>]
  member _.``[AArch64] A failed AUTDB leaves 10 in bits 62:61``() =
    StringAssert.Contains(liftedText "dac11c20", poison 0x4000000000000000UL)

  /// A hint changes nothing a program can see: with one thread and nothing
  /// to wait for, each of these lifts to no statement at all.
  [<TestMethod>]
  member _.``[AArch64] YIELD lifts to nothing``() =
    "d503203f" ++ [||] |> test

  [<TestMethod>]
  member _.``[AArch64] WFE lifts to nothing``() =
    "d503205f" ++ [||] |> test

  [<TestMethod>]
  member _.``[AArch64] WFI lifts to nothing``() =
    "d503207f" ++ [||] |> test

  [<TestMethod>]
  member _.``[AArch64] SEV lifts to nothing``() =
    "d503209f" ++ [||] |> test

  [<TestMethod>]
  member _.``[AArch64] SEVL lifts to nothing``() =
    "d50320bf" ++ [||] |> test

  [<TestMethod>]
  member _.``[AArch64] BTI lifts to nothing``() =
    "d503241f" ++ [||] |> test

  [<TestMethod>]
  member _.``[AArch64] ESB lifts to nothing``() =
    "d503221f" ++ [||] |> test

  [<TestMethod>]
  member _.``[AArch64] PSB CSYNC lifts to nothing``() =
    "d503223f" ++ [||] |> test

  [<TestMethod>]
  member _.``[AArch64] TSB CSYNC lifts to nothing``() =
    "d503225f" ++ [||] |> test

  [<TestMethod>]
  member _.``[AArch64] CSDB lifts to nothing``() =
    "d503229f" ++ [||] |> test

  /// The tag stores write the base back in their indexed forms, as any store
  /// does, and a post-index one accesses the base itself (DDI0487F.c C6.2.256
  /// STG, C6.2.306 STZG, C6.2.258 STGP).
  [<TestMethod>]
  member _.``[AArch64] STG (post-index) writes the base back``() =
    Assert.AreEqual<Expr option>(Some(!.X1 .+ num64 16UL),
                                 assigned "d9201420" !.X1)

  [<TestMethod>]
  member _.``[AArch64] STG (pre-index) writes the base back``() =
    Assert.AreEqual<Expr option>(Some(!.X1 .+ num64 16UL),
                                 assigned "d9201c20" !.X1)

  [<TestMethod>]
  member _.``[AArch64] STG (signed offset) leaves the base``() =
    Assert.AreEqual<Expr option>(None, assigned "d9201820" !.X1)

  [<TestMethod>]
  member _.``[AArch64] STZG (post-index) zeroes at the base``() =
    Assert.AreEqual<Expr option>(Some !.X1,
                                 assigned "d9601420" (AST.tmpvar 64<rt> 1))

  [<TestMethod>]
  member _.``[AArch64] STGP (post-index) stores at the base``() =
    Assert.AreEqual<Expr option>(Some !.X1,
                                 assigned "68808c22" (AST.tmpvar 64<rt> 1))

  /// CLREX clears the reservation, leaving it on the last byte of memory, so
  /// that a store-exclusive after it fails (DDI0487F.c C6.2.54).
  [<TestMethod>]
  member _.``[AArch64] CLREX clears the reservation``() =
    let cleared = Some(num64 0xffffffffffffffffUL)
    Assert.AreEqual<Expr option>(cleared, assigned "d5033f5f" !.ExMonAddr)
    Assert.AreEqual<Expr option>(cleared, assigned "d503355f" !.ExMonAddr)

  /// The rounding narrows add the rounding constant to the integer value of
  /// the element, which no width bounds (DDI0487F.c C7.2.300 SQRSHRN), so a
  /// lane at the top of its range rounds up and saturates instead of wrapping.
  [<TestMethod>]
  member _.``[AArch64] SQRSHRN rounds 0x7fff to the largest byte``() =
    let read = IRRunner.run (lifted "0f0f9c20") [ !@(Q1, 1), bv64 0x7fffUL ]
    Assert.AreEqual<uint64>(0x7fUL, (read !@(Q0, 1)).ToUInt64() &&& 0xffUL)

  [<TestMethod>]
  member _.``[AArch64] SQRSHRUN rounds 0x7fff to the largest byte``() =
    let read = IRRunner.run (lifted "2f0f8c20") [ !@(Q1, 1), bv64 0x7fffUL ]
    Assert.AreEqual<uint64>(0xffUL, (read !@(Q0, 1)).ToUInt64() &&& 0xffUL)

  [<TestMethod>]
  member _.``[AArch64] UQRSHRN rounds 0xffff to the largest byte``() =
    let read = IRRunner.run (lifted "2f0f9c20") [ !@(Q1, 1), bv64 0xffffUL ]
    Assert.AreEqual<uint64>(0xffUL, (read !@(Q0, 1)).ToUInt64() &&& 0xffUL)
    Assert.AreEqual<uint64>(1UL, (read !.FPSR).ToUInt64() >>> 27 &&& 1UL)

  /// A negative amount shifts right, which cannot saturate (C7.2.378 UQSHL,
  /// C7.2.375 UQRSHL), even when every set bit goes; nor can a zero element.
  [<TestMethod>]
  member _.``[AArch64] UQSHL by -1 leaves QC``() =
    Assert.AreEqual<uint64>(0UL, qcAfter "6e224c20" 0x0101010101010101UL
                                   0xffffffffffffffffUL)

  [<TestMethod>]
  member _.``[AArch64] UQSHL of zero leaves QC``() =
    Assert.AreEqual<uint64>(0UL, qcAfter "6e224c20" 0UL 0UL)

  [<TestMethod>]
  member _.``[AArch64] UQSHL of 0x80 by 1 sets QC``() =
    Assert.AreEqual<uint64>(1UL, qcAfter "6e224c20" 0x8080808080808080UL
                                   0x0101010101010101UL)

  [<TestMethod>]
  member _.``[AArch64] UQRSHL by -2 leaves QC``() =
    Assert.AreEqual<uint64>(0UL, qcAfter "6e225c20" 0x0101010101010101UL
                                   0xfefefefefefefefeUL)

  [<TestMethod>]
  member _.``[AArch64] UQRSHL of zero leaves QC``() =
    Assert.AreEqual<uint64>(0UL, qcAfter "6e225c20" 0UL 0UL)

  /// TBX keeps the destination's byte where the index is past the table, in
  /// the top eight lanes as in the bottom eight (DDI0487F.c C7.2.336).
  [<TestMethod>]
  member _.``[AArch64] TBX of sixteen bytes keeps the top lanes``() =
    let inputs =
      [ !@(Q0, 1), bv64 0xeeeeeeeeeeeeeeeeUL
        !@(Q0, 2), bv64 0xeeeeeeeeeeeeeeeeUL
        !@(Q1, 1), bv64 0x4746454443424140UL
        !@(Q1, 2), bv64 0x4f4e4d4c4b4a4948UL
        !@(Q2, 1), bv64 0x0a082005ff100f00UL
        !@(Q2, 2), bv64 0x40071003800e1101UL ]
    let read = IRRunner.run (lifted "4e021020") inputs
    Assert.AreEqual<uint64>(0x4a48ee45eeee4f40UL, (read !@(Q0, 1)).ToUInt64())
    Assert.AreEqual<uint64>(0xee47ee43ee4eee41UL, (read !@(Q0, 2)).ToUInt64())

  /// FPUnpackCV flushes a denormal single under FPCR.FZ and raises Input
  /// Denormal alone (DDI0487F.c J1.3): what is left converts exactly.
  [<TestMethod>]
  member _.``[AArch64] FCVT flushes a denormal single under FZ``() =
    Assert.AreEqual<uint64 * uint64>((0UL, 0x80UL), fpAfter "1e23c020" fz 1UL)

  /// The alternative half-precision format FPCR.AHP selects has no infinity
  /// and no NaN (J1.3 FPConvert): an infinity becomes the largest magnitude
  /// and a NaN a zero of its own sign, each raising Invalid.
  [<TestMethod>]
  member _.``[AArch64] FCVT under AHP saturates an infinity``() =
    Assert.AreEqual<uint64 * uint64>((0x7fffUL, 1UL),
                                     fpAfter "1e23c020" ahp 0x7f800000UL)

  [<TestMethod>]
  member _.``[AArch64] FCVT under AHP makes a NaN a zero``() =
    Assert.AreEqual<uint64 * uint64>((0x8000UL, 1UL),
                                     fpAfter "1e23c020" ahp 0xffc00000UL)

  /// Its top exponent is an ordinary one, so 131008 converts exactly, and
  /// anything past it saturates with Invalid and without Inexact (J1.3
  /// FPRoundBase).
  [<TestMethod>]
  member _.``[AArch64] FCVT under AHP reaches the top exponent``() =
    Assert.AreEqual<uint64 * uint64>((0x7fffUL, 0UL),
                                     fpAfter "1e23c020" ahp 0x47ffe000UL)

  [<TestMethod>]
  member _.``[AArch64] FCVT under AHP saturates past 2^17 as Invalid``() =
    Assert.AreEqual<uint64 * uint64>((0x7fffUL, 1UL),
                                     fpAfter "1e23c020" ahp 0x48000001UL)

  /// Read back, the top exponent is a number too: 7c01 is 65600, not a
  /// signalling NaN.
  [<TestMethod>]
  member _.``[AArch64] FCVT from a half under AHP reads 7c01 as 65600``() =
    Assert.AreEqual<uint64 * uint64>((0x47802000UL, 0UL),
                                     fpAfter "1ee24020" ahp 0x7c01UL)

  /// FPConvertBF unpacks its operand, so FZ flushes a denormal single that
  /// would otherwise round up to the smallest normal bfloat16.
  [<TestMethod>]
  member _.``[AArch64] BFCVT flushes a denormal single under FZ``() =
    Assert.AreEqual<uint64 * uint64>((0UL, 0x80UL),
                                     fpAfter "1e634020" fz 0x7fffffUL)

  /// FPToFixedJS clears Z for a denormal flushed to zero, though the zero
  /// it converts to is exact (J1.3: `!IsZero(op<51:0>)`).
  [<TestMethod>]
  member _.``[AArch64] FJCVTZS clears Z for a flushed denormal``() =
    let inputs =
      [ !.FPCR, bv64 fz
        !@(Q1, 1), bv64 1UL
        !.Z, BitVector.One 1<rt> ]
    let read = IRRunner.run (lifted "1e7e0020") inputs
    Assert.AreEqual<uint64>(0UL, (read !.Z).ToUInt64())
    Assert.AreEqual<uint64>(0x80UL, (read !.FPSR).ToUInt64())

  /// The flush keeps the operand's sign: a negative denormal is minus zero.
  [<TestMethod>]
  member _.``[AArch64] FCVT flushes a negative denormal to minus zero``() =
    Assert.AreEqual<uint64 * uint64>((0x8000UL, 0x80UL),
                                     fpAfter "1e23c020" fz 0x80000001UL)

  /// A negative half with the top exponent reads back as a negative number.
  [<TestMethod>]
  member _.``[AArch64] FCVT from a half under AHP reads fc01 as -65600``() =
    Assert.AreEqual<uint64 * uint64>((0xc7802000UL, 0UL),
                                     fpAfter "1ee24020" ahp 0xfc01UL)

  /// FixedToFP rounds by FPRound, so FZ16 flushes a half result that was
  /// tiny before rounding, raising Underflow alone, even an exact one: 1 with
  /// 20 fraction bits is 2^-20, a subnormal half (J1.3 FPRoundBase).
  [<TestMethod>]
  member _.``[AArch64] SCVTF to a half flushes 2^-20 under FZ16``() =
    let inputs = [ !.FPCR, bv64 fz16; !.X1, bv64 1UL ]
    let read = IRRunner.run (lifted "1ec2b020") inputs
    Assert.AreEqual<uint64>(0UL, (read !@(Q0, 1)).ToUInt64())
    Assert.AreEqual<uint64>(8UL, (read !.FPSR).ToUInt64())

  /// The flushed zero keeps the result's sign: -1 gives minus zero.
  [<TestMethod>]
  member _.``[AArch64] SCVTF to a half flushes -2^-20 to minus zero``() =
    let inputs = [ !.FPCR, bv64 fz16; !.X1, bv64 0xffffffffUL ]
    let read = IRRunner.run (lifted "1ec2b020") inputs
    Assert.AreEqual<uint64>(0x8000UL, (read !@(Q0, 1)).ToUInt64())
    Assert.AreEqual<uint64>(8UL, (read !.FPSR).ToUInt64())

  /// Without FZ16 the same subnormal half is written as it is.
  [<TestMethod>]
  member _.``[AArch64] SCVTF to a half keeps 2^-20 without FZ16``() =
    let read = IRRunner.run (lifted "1ec2b020") [ !.X1, bv64 1UL ]
    Assert.AreEqual<uint64>(0x10UL, (read !@(Q0, 1)).ToUInt64())
    Assert.AreEqual<uint64>(0UL, (read !.FPSR).ToUInt64())

  /// <summary>
  /// A 64-bit integer with 64 fraction bits is a half inside its range, and
  /// rounds to it once (DDI0487F.c C7.2.235, FixedToFP): (2^62 + 2^51 + 1) /
  /// 2^64 is just past the middle of two halves and rounds up to 0.25 +
  /// 2^-12, where a double of the integer, rounded first, lands on the middle
  /// and rounds to the even one; and (2^63 - 1) / 2^64 is inexact however
  /// close a double of it comes.
  /// </summary>
  [<TestMethod>]
  member _.``[AArch64] SCVTF of a 64-bit integer to a half rounds once``() =
    let run x = IRRunner.run (lifted "9ec20020") [ !.X1, bv64 x ]
    let up = run 0x4008000000000001UL
    Assert.AreEqual<uint64>(0x3401UL, (up !@(Q0, 1)).ToUInt64())
    Assert.AreEqual<uint64>(0x10UL, (up !.FPSR).ToUInt64())
    let near = run 0x7fffffffffffffffUL
    Assert.AreEqual<uint64>(0x3800UL, (near !@(Q0, 1)).ToUInt64())
    Assert.AreEqual<uint64>(0x10UL, (near !.FPSR).ToUInt64())

  /// The same for UCVTF (C7.2.354): (2^63 + 2^52 + 1) / 2^64 rounds up to
  /// 0.5 + 2^-11.
  [<TestMethod>]
  member _.``[AArch64] UCVTF of a 64-bit integer to a half rounds once``() =
    let inputs = [ !.X1, bv64 0x8010000000000001UL ]
    let read = IRRunner.run (lifted "9ec30020") inputs
    Assert.AreEqual<uint64>(0x3801UL, (read !@(Q0, 1)).ToUInt64())
    Assert.AreEqual<uint64>(0x10UL, (read !.FPSR).ToUInt64())

  /// FZ16 is a half's FZ: FRECPE of 2^14 is under the smallest normal half
  /// and gives a zero, raising Underflow alone.
  [<TestMethod>]
  member _.``[AArch64] FRECPE of the half 2^14 is zero under FZ16``() =
    Assert.AreEqual<uint64 * uint64>((0UL, 8UL),
                                     fpAfter "5ef9d820" fz16 0x7400UL)

  /// FPRecipEstimate gives a zero, raising Underflow alone, for a reciprocal
  /// FZ would flush: 2^127's is under the smallest normal.
  [<TestMethod>]
  member _.``[AArch64] FRECPE of 2^127 is zero under FZ``() =
    Assert.AreEqual<uint64 * uint64>((0UL, 8UL),
                                     fpAfter "5ea1d820" fz 0x7f000000UL)

  /// UDF raises an Undefined Instruction exception wherever it runs.
  [<TestMethod>]
  member _.``[AArch64] UDF lifts to an undefined instruction``() =
    let undefined = AST.sideEffect BinIR.SideEffect.UndefinedInstruction
    "0000abcd" ++ [| undefined |] |> test

  /// <summary>
  /// This model runs one exception level, with no EL2 or EL3 above it, and is
  /// never in Debug state, so what would leave for one of those is UNDEFINED:
  /// HVC and SMC (DDI0487F.c C6.2.94 and C6.2.240), HLT with halting not
  /// allowed (C6.2.93), and DCPS1 to DCPS3 and DRPS outside Debug state
  /// (C6.2.76 to C6.2.78 and C6.2.81).
  /// </summary>
  [<TestMethod>]
  member _.``[AArch64] HLT, DCPS, DRPS, HVC and SMC are undefined``() =
    let undefined = AST.sideEffect BinIR.SideEffect.UndefinedInstruction
    let words =
      [ "d4400020" (* HLT #1 *)
        "d4a00001" (* DCPS1 *)
        "d4a00002" (* DCPS2 *)
        "d4a00003" (* DCPS3 *)
        "d6bf03e0" (* DRPS *)
        "d4000002" (* HVC #0 *)
        "d4000003" (* SMC #0 *) ]
    for hex in words do
      hex ++ [| undefined |] |> test

  /// <summary>
  /// The cache maintenance EL0 may run under SCTLR_EL1.UCI, which Linux sets:
  /// DC CVAU, CVAC, CIVAC, CVAP and CVADP, and IC IVAU (DDI0487F.c C5.3.19,
  /// C5.3.16, C5.3.14, C5.3.18, C5.3.17 and C5.3.31). Nothing in this model
  /// stands between the processor and memory, so none of them has an effect
  /// to show.
  /// </summary>
  [<TestMethod>]
  member _.``[AArch64] The cache maintenance EL0 runs lifts to nothing``() =
    let words =
      [ "d50b7b21" (* DC CVAU *)
        "d50b7a21" (* DC CVAC *)
        "d50b7e21" (* DC CIVAC *)
        "d50b7c21" (* DC CVAP *)
        "d50b7d21" (* DC CVADP *)
        "d50b7520" (* IC IVAU *) ]
    for hex in words do
      hex ++ [||] |> test
