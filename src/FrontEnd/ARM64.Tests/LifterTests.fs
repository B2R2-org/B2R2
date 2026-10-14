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

  /// Checks a word over each input set against the places given as the
  /// ones it changes: what the oracle found for a value test, what the
  /// manual says for a structural one.
  let check hex inputs expected =
    let found = A64Machine.mismatches hex inputs expected
    Assert.AreEqual<string>("", String.concat "\n" found, hex)

  /// Checks that a word raises the given exception over every input set,
  /// as the oracle's process took the signal for it.
  let raises effect hex =
    for k in 0 .. A64Machine.sets - 1 do
      let found = A64Machine.effectsOver hex [] k
      Assert.AreEqual<BinIR.SideEffect list>([ effect ], found, hex)

  /// Checks that a word goes to the given address over every input set,
  /// and changes nothing else.
  let goesTo hex inputs (target: uint64) =
    check hex inputs (List.replicate A64Machine.sets [ Pc target ])

  /// Checks that a word goes to the given address over every input set,
  /// with X30 the address after it, and changes nothing else.
  let links hex inputs (target: uint64) =
    let back = X(30, A64Machine.code + 4UL)
    check hex inputs (List.replicate A64Machine.sets [ back; Pc target ])

  /// How a word's statements leave the instruction: the kind of a jump out
  /// of it, or a conditional one.
  let exitOf hex =
    A64Machine.lift hex
    |> Array.tryPick (function
      | InterJmp(Kind = k) -> Some(string k)
      | InterCJmp _ -> Some "InterCJmp"
      | _ -> None)

  /// The pointer the authentication tests sign: canonical and in the lower
  /// half, its field above bit 47 a copy of bit 55.
  let pointer = 0x0000123456789abcUL

  /// Checks what Auth() fixes about an authenticator over each input set: a
  /// pointer the matching signer signed comes back, and one nothing signed,
  /// or the other key's signer did, fails, leaving the key's error code in
  /// bits 62:61.
  let authenticates aut pac other reg (code: uint64) =
    for k in 0 .. A64Machine.sets - 1 do
      let after hexes = (A64Machine.after hexes [ X(reg, pointer) ] k).Xs
      Assert.AreEqual<uint64>(pointer, (after [ pac; aut ])[reg], aut)
      Assert.AreEqual<uint64>(pointer ||| code, (after [ aut ])[reg], aut)
      Assert.AreEqual<uint64>(pointer ||| code, (after [ other; aut ])[reg])

  /// Checks an authenticated branch over each input set: with its target
  /// signed by the given word it goes to the pointer, unsigned to the
  /// pointer with the key's error code in bits 62:61, and where it links,
  /// X30 is the address after it.
  let branchesSigned pac hex reg (code: uint64) links =
    for k in 0 .. A64Machine.sets - 1 do
      let inputs = [ X(reg, pointer) ]
      let signed = A64Machine.after [ pac; hex ] inputs k
      let unsigned = A64Machine.after [ hex ] inputs k
      Assert.AreEqual<uint64>(pointer, signed.Pc, hex)
      Assert.AreEqual<uint64>(pointer ||| code, unsigned.Pc, hex)
      if links then
        Assert.AreEqual<uint64>(A64Machine.code + 4UL, signed.Xs[30], hex)
      else
        ()

  /// A pointer whose bits above 47 are not a copy of bit 55: AddPAC
  /// corrupts the code it signs such a pointer with, so no AUT gives it back.
  let nonCanonical = 0x0001000012345678UL

  /// Checks what AddPAC and Auth() fix about a signer over each input set:
  /// it keeps bit 55 and the address below bit 48 and changes the pointer;
  /// the matching AUT gives it back, unless the pointer was not canonical,
  /// when it fails with the key's own error code in bits 62:61; and the
  /// other key's AUT fails, leaving that key's error code there.
  let signs pac aut wrong reg (code: uint64) =
    for k in 0 .. A64Machine.sets - 1 do
      let from p hexes = (A64Machine.after hexes [ X(reg, p) ] k).Xs
      let after = from pointer
      let signed = (after [ pac ])[reg]
      Assert.AreEqual<uint64>(pointer, signed &&& 0x0080ffffffffffffUL, pac)
      Assert.AreNotEqual<uint64>(pointer, signed, pac)
      Assert.AreEqual<uint64>(pointer, (after [ pac; aut ])[reg], aut)
      let failed = (after [ pac; wrong ])[reg]
      Assert.AreEqual<uint64>(pointer ||| code, failed, wrong)
      let own = code ^^^ 0x6000000000000000UL
      let corrupt = (from nonCanonical [ pac; aut ])[reg]
      Assert.AreEqual<uint64>(0x12345678UL ||| own, corrupt, aut)

  /// Checks an authenticated load over each input set: with the window
  /// signed by the given word, it reads the q-th doubleword of the window,
  /// and the base keeps the signed pointer.
  let loadsSigned pac hex (q: int) =
    for k in 0 .. A64Machine.sets - 1 do
      let inputs = [ X(1, A64Machine.window) ]
      let signed = A64Machine.after [ pac ] inputs k
      let loaded = A64Machine.after [ pac; hex ] inputs k
      let mem = (A64Machine.inputSet k).Mem
      Assert.AreEqual<uint64>(mem[q], loaded.Xs[0], hex)
      Assert.AreEqual<uint64>(signed.Xs[1], loaded.Xs[1], hex)

  /// Checks a pre-indexed authenticated load over each input set: with the
  /// window signed by the given word, it reads the q-th doubleword of the
  /// window, and the base becomes that doubleword's address.
  let loadsSignedBack pac hex (q: int) =
    for k in 0 .. A64Machine.sets - 1 do
      let inputs = [ X(1, A64Machine.window) ]
      let loaded = A64Machine.after [ pac; hex ] inputs k
      let mem = (A64Machine.inputSet k).Mem
      let address = A64Machine.window + uint64 (q * 8)
      Assert.AreEqual<uint64>(mem[q], loaded.Xs[0], hex)
      Assert.AreEqual<uint64>(address, loaded.Xs[1], hex)

  /// The statements a word lifts to, as text, without the instruction's
  /// marks.
  let statementsOf hex =
    A64Machine.lift hex
    |> Array.filter (function
      | ISMark _ | IEMark _ -> false
      | _ -> true)
    |> Array.map string
    |> List.ofArray

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

  /// <summary>
  /// MSR of a register the manual gives only an MRS is UNDEFINED at every
  /// level: MIDR_EL1, CTR_EL0, CurrentEL, and ID_AA64PFR0_EL1, which this
  /// front end does not name. TPIDRRO_EL0 and CNTFRQ_EL0 EL0 reads and EL1
  /// writes as well.
  /// </summary>
  [<TestMethod>]
  member _.``[AArch64] MSR cannot write a read-only register``() =
    let at el hex =
      let inputs = [ !.CURRENTEL, bv64 (uint64 el <<< 2) ]
      IRRunner.effects (lifted hex) inputs
    let undef = [ BinIR.SideEffect.UndefinedInstruction ]
    let none: BinIR.SideEffect list = []
    for hex in [ "d5180000"; "d51b0020"; "d5184240"; "d5180400" ] do
      Assert.AreEqual<BinIR.SideEffect list>(undef, at 1 hex, hex)
    for hex in [ "d53bd060"; "d53be000" ] do
      Assert.AreEqual<BinIR.SideEffect list>(none, at 0 hex, hex)
    for hex in [ "d51bd060"; "d51be000" ] do
      Assert.AreEqual<BinIR.SideEffect list>(undef, at 0 hex, hex)
      Assert.AreEqual<BinIR.SideEffect list>(none, at 1 hex, hex)

  /// <summary>
  /// The ID space reads a Cortex-A57's values at EL1 (SysReg.idRegister):
  /// ID_AA64PFR0_EL1, MPIDR_EL1, ID_AA64MMFR0_EL1 and ID_PFR0_EL1 here. CRm
  /// 0 allocates nothing at op2 1, so that is UNDEFINED, and the whole space
  /// is EL1's, so UNDEFINED at EL0.
  /// </summary>
  [<TestMethod>]
  member _.``[AArch64] MRS reads the ID registers at EL1``() =
    let read hex =
      let inputs = [ !.CURRENTEL, bv64 0x4UL ]
      (IRRunner.run (lifted hex) inputs !.X0).ToUInt64()
    Assert.AreEqual<uint64>(0x22UL, read "d5380400")
    Assert.AreEqual<uint64>(0x80000000UL, read "d53800a0")
    Assert.AreEqual<uint64>(0x1124UL, read "d5380700")
    Assert.AreEqual<uint64>(0x131UL, read "d5380100")
    let at el hex =
      let inputs = [ !.CURRENTEL, bv64 (uint64 el <<< 2) ]
      IRRunner.effects (lifted hex) inputs
    let undef = [ BinIR.SideEffect.UndefinedInstruction ]
    Assert.AreEqual<BinIR.SideEffect list>(undef, at 1 "d5380020")
    Assert.AreEqual<BinIR.SideEffect list>(undef, at 0 "d5380400")

  /// <summary>
  /// DCZID_EL0.DZP reads 1 at EL0 where SCTLR_EL1.DZE prohibits DC ZVA, and
  /// 0 where it does not or at EL1 (D13.2.113); CCSIDR_EL1 describes the
  /// cache CSSELR_EL1 selects.
  /// </summary>
  [<TestMethod>]
  member _.``[AArch64] DCZID_EL0 and CCSIDR_EL1 read what selects them``() =
    let dczid el (sctlr: uint64) =
      let inputs =
        [ !.CURRENTEL, bv64 (uint64 el <<< 2)
          !.SCTLREL1, bv64 sctlr
          !.DCZIDEL0, bv64 0x4UL ]
      (IRRunner.run (lifted "d53b00e0") inputs !.X0).ToUInt64()
    Assert.AreEqual<uint64>(0x14UL, dczid 0 0UL)
    Assert.AreEqual<uint64>(0x4UL, dczid 0 0x4000UL)
    Assert.AreEqual<uint64>(0x4UL, dczid 1 0UL)
    let ccsidr (sel: uint64) =
      let inputs = [ !.CURRENTEL, bv64 0x4UL; !.CSSELREL1, bv64 sel ]
      (IRRunner.run (lifted "d5390000") inputs !.X0).ToUInt64()
    Assert.AreEqual<uint64>(0x701fe00aUL, ccsidr 0UL)
    Assert.AreEqual<uint64>(0x201fe012UL, ccsidr 1UL)
    Assert.AreEqual<uint64>(0x70ffe07aUL, ccsidr 2UL)
    Assert.AreEqual<uint64>(0UL, ccsidr 3UL)

  /// ERET puts the exception level SPSR_EL1 names in CurrentEL, at the bits
  /// both keep it in, and is UNDEFINED at EL0 (C6.2.87).
  [<TestMethod>]
  member _.``[AArch64] ERET restores CurrentEL``() =
    let expected = !.SPSREL1 .& num64 0xcUL
    Assert.AreEqual(Some expected, assigned "d69f03e0" !.CURRENTEL)
    let inputs = [ !.CURRENTEL, bv64 0UL ]
    let undef = [ BinIR.SideEffect.UndefinedInstruction ]
    let effects = IRRunner.effects (lifted "d69f03e0") inputs
    Assert.AreEqual<BinIR.SideEffect list>(undef, effects)

  /// DC GZVA clears the block DC ZVA does and the allocation tags no memory
  /// here holds, and DC GVA writes only those tags: it does nothing, there
  /// being no tag memory. All three need SCTLR_EL1.DZE at EL0 (D13.2.113).
  [<TestMethod>]
  member _.``[AArch64] DC GZVA clears what DC ZVA does``() =
    let body hex =
      lifted hex
      |> Array.filter (function
        | ISMark _ | IEMark _ -> false
        | _ -> true)
    CollectionAssert.AreEqual(body "d50b7421", body "d50b7481")
    let at el (sctlr: uint64) hex =
      let inputs =
        [ !.CURRENTEL, bv64 (uint64 el <<< 2); !.SCTLREL1, bv64 sctlr ]
      IRRunner.effects (lifted hex) inputs
    let undef = [ BinIR.SideEffect.UndefinedInstruction ]
    let none: BinIR.SideEffect list = []
    for hex in [ "d50b7421"; "d50b7481"; "d50b7461" ] do
      Assert.AreEqual<BinIR.SideEffect list>(undef, at 0 0UL hex, hex)
    Assert.AreEqual<BinIR.SideEffect list>(none, at 0 0x4000UL "d50b7461")
    Assert.AreEqual<BinIR.SideEffect list>(none, at 1 0UL "d50b7461")

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
  /// C5.3.16, C5.3.14, C5.3.18, C5.3.17 and C5.3.31; D13.2.113). Nothing in
  /// this model stands between the processor and memory, so where one runs
  /// it has no effect to show; with UCI clear it is UNDEFINED at EL0.
  /// </summary>
  [<TestMethod>]
  member _.``[AArch64] The cache maintenance EL0 runs needs UCI``() =
    let words =
      [ "d50b7b21" (* DC CVAU *)
        "d50b7a21" (* DC CVAC *)
        "d50b7e21" (* DC CIVAC *)
        "d50b7c21" (* DC CVAP *)
        "d50b7d21" (* DC CVADP *)
        "d50b7520" (* IC IVAU *) ]
    let at el (sctlr: uint64) hex =
      let inputs =
        [ !.CURRENTEL, bv64 (uint64 el <<< 2); !.SCTLREL1, bv64 sctlr ]
      IRRunner.effects (lifted hex) inputs
    let undef = [ BinIR.SideEffect.UndefinedInstruction ]
    let none: BinIR.SideEffect list = []
    for hex in words do
      Assert.AreEqual<BinIR.SideEffect list>(undef, at 0 0UL hex, hex)
      Assert.AreEqual<BinIR.SideEffect list>(none, at 0 (1UL <<< 26) hex, hex)
      Assert.AreEqual<BinIR.SideEffect list>(none, at 1 0UL hex, hex)

  (* One test for each instruction DDI0487F.c describes, in the order of its
     sections. A value test runs a word's lifting over inputs QEMU ran the word
     on (qemu-aarch64 -cpu max) and asserts what QEMU left. A structural test is
     for a word a user-mode run cannot execute alone; its doc comment says what
     it checks, and its expectation is the manual's. The input sets and the
     comparison are A64Machine's. *)
  /// C6.2.1 ADC
  [<TestMethod>]
  member _.``C6.2.1 ADC``() =
    check "1a020020" []
      [ [ X(0, 0x60c141c5UL) ]
        [ X(0, 0xe97a7171UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x55555555UL) ] ]
    check "9a020020" []
      [ [ X(0, 0xb77f309060c141c5UL) ]
        [ X(0, 0x584402cfe97a7171UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x5555555655555555UL) ] ]

  /// C6.2.2 ADCS
  [<TestMethod>]
  member _.``C6.2.2 ADCS``() =
    check "3a020020" []
      [ [ X(0, 0x60c141c5UL); Nzcv 0x20000000UL ]
        [ X(0, 0xe97a7171UL); Nzcv 0x80000000UL ]
        [ X(0, 0x1UL); Nzcv 0x20000000UL ]
        [ X(0, 0x55555555UL); Nzcv 0x0UL ] ]
    check "ba020020" []
      [ [ X(0, 0xb77f309060c141c5UL); Nzcv 0xa0000000UL ]
        [ X(0, 0x584402cfe97a7171UL); Nzcv 0x30000000UL ]
        [ X(0, 0x1UL); Nzcv 0x20000000UL ]
        [ X(0, 0x5555555655555555UL); Nzcv 0x0UL ] ]

  /// C6.2.3 ADD (extended register)
  [<TestMethod>]
  member _.``C6.2.3 ADD``() =
    check "0b020020" []
      [ [ X(0, 0x60c141c5UL) ]
        [ X(0, 0xe97a7171UL) ]
        []
        [ X(0, 0x55555555UL) ] ]
    check "11004020" []
      [ [ X(0, 0x658eec77UL) ]
        [ X(0, 0xbfc1e52UL) ]
        [ X(0, 0x11UL) ]
        [ X(0, 0x10UL) ] ]
    check "91004020" []
      [ [ X(0, 0xbeeb8da1658eec77UL) ]
        [ X(0, 0xbfc846100bfc1e52UL) ]
        [ X(0, 0x11UL) ]
        [ X(0, 0x100000010UL) ] ]
    check "8b020020" []
      [ [ X(0, 0xb77f309060c141c5UL) ]
        [ X(0, 0x584402cfe97a7171UL) ]
        []
        [ X(0, 0x5555555655555555UL) ] ]
    check "0e228420" []
      [ [ Q(0, 0xf7ff9d519edadf28UL, 0x0UL) ]
        [ Q(0, 0xb0152f9948dffbf7UL, 0x0UL) ]
        [ Q(0, 0xffffffff80000001UL, 0x0UL) ]
        [ Q(0, 0xc008000000000000UL, 0x0UL) ] ]
    check "4e228420" []
      [ [ Q(0, 0xf7ff9d519edadf28UL, 0xcb0484928c3edc0cUL) ]
        [ Q(0, 0xb0152f9948dffbf7UL, 0x2991454d3ff84ce5UL) ]
        [ Q(0, 0xffffffff80000001UL, 0x7f200000fe3fffffUL) ]
        [ Q(0, 0xc008000000000000UL, 0xbea999999999999aUL) ] ]
    check "0e628420" []
      [ [ Q(0, 0xf7ff9d519fdadf28UL, 0x0UL) ]
        [ Q(0, 0xb1152f9948dffbf7UL, 0x0UL) ]
        [ Q(0, 0xffffffff80000001UL, 0x0UL) ]
        [ Q(0, 0xc008000000000000UL, 0x0UL) ] ]
    check "4e628420" []
      [ [ Q(0, 0xf7ff9d519fdadf28UL, 0xcc0484928d3edd0cUL) ]
        [ Q(0, 0xb1152f9948dffbf7UL, 0x2991464d3ff84ce5UL) ]
        [ Q(0, 0xffffffff80000001UL, 0x80200000ff3fffffUL) ]
        [ Q(0, 0xc008000000000000UL, 0xbfa999999999999aUL) ] ]
    check "0ea28420" []
      [ [ Q(0, 0xf7ff9d519fdbdf28UL, 0x0UL) ]
        [ Q(0, 0xb1162f9948dffbf7UL, 0x0UL) ]
        [ Q(0, 0xffffffff80000001UL, 0x0UL) ]
        [ Q(0, 0xc008000000000000UL, 0x0UL) ] ]
    check "4ee28420" []
      [ [ Q(0, 0xf7ff9d519fdbdf28UL, 0xcc0484928d3fdd0cUL) ]
        [ Q(0, 0xb1162f9a48dffbf7UL, 0x2991464e3ff94ce5UL) ]
        [ Q(0, 0xffffffff80000001UL, 0x80200000ff3fffffUL) ]
        [ Q(0, 0xc008000000000000UL, 0xbfa999999999999aUL) ] ]
    check "912af020" []
      [ [ X(0, 0xbeeb8da1658ef723UL) ]
        [ X(0, 0xbfc846100bfc28feUL) ]
        [ X(0, 0xabdUL) ]
        [ X(0, 0x100000abcUL) ] ]
    check "4ea28420" []
      [ [ Q(0, 0xf7ff9d519fdbdf28UL, 0xcc0484928d3fdd0cUL) ]
        [ Q(0, 0xb1162f9948dffbf7UL, 0x2991464d3ff94ce5UL) ]
        [ Q(0, 0xffffffff80000001UL, 0x80200000ff3fffffUL) ]
        [ Q(0, 0xc008000000000000UL, 0xbfa999999999999aUL) ] ]

  /// C6.2.6 ADDG
  [<TestMethod>]
  member _.``C6.2.6 ADDG``() =
    check "91800020" []
      [ [ X(0, 0xb0eb8da1658eec67UL) ]
        [ X(0, 0xb0c846100bfc1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x100000000UL) ] ]

  /// C6.2.7 ADDS (extended register)
  [<TestMethod>]
  member _.``C6.2.7 ADDS``() =
    check "2b020020" []
      [ [ X(0, 0x60c141c5UL); Nzcv 0x20000000UL ]
        [ X(0, 0xe97a7171UL); Nzcv 0x80000000UL ]
        []
        [ X(0, 0x55555555UL); Nzcv 0x0UL ] ]
    check "31004020" []
      [ [ X(0, 0x658eec77UL); Nzcv 0x0UL ]
        [ X(0, 0xbfc1e52UL); Nzcv 0x0UL ]
        [ X(0, 0x11UL); Nzcv 0x0UL ]
        [ X(0, 0x10UL); Nzcv 0x0UL ] ]
    check "b1004020" []
      [ [ X(0, 0xbeeb8da1658eec77UL); Nzcv 0x80000000UL ]
        [ X(0, 0xbfc846100bfc1e52UL); Nzcv 0x80000000UL ]
        [ X(0, 0x11UL); Nzcv 0x0UL ]
        [ X(0, 0x100000010UL); Nzcv 0x0UL ] ]
    check "ab020020" []
      [ [ X(0, 0xb77f309060c141c5UL); Nzcv 0xa0000000UL ]
        [ X(0, 0x584402cfe97a7171UL); Nzcv 0x30000000UL ]
        []
        [ X(0, 0x5555555655555555UL); Nzcv 0x0UL ] ]
    check "b1448c20" []
      [ [ X(0, 0xbeeb8da165a11c67UL); Nzcv 0x80000000UL ]
        [ X(0, 0xbfc846100c0e4e42UL); Nzcv 0x80000000UL ]
        [ X(0, 0x123001UL); Nzcv 0x0UL ]
        [ X(0, 0x100123000UL); Nzcv 0x0UL ] ]

  /// C6.2.10 ADR
  [<TestMethod>]
  member _.``C6.2.10 ADR``() =
    check "10000020" []
      [ [ X(0, 0x1000004UL) ]
        [ X(0, 0x1000004UL) ]
        [ X(0, 0x1000004UL) ]
        [ X(0, 0x1000004UL) ] ]

  /// C6.2.11 ADRP
  [<TestMethod>]
  member _.``C6.2.11 ADRP``() =
    check "90000000" []
      [ [ X(0, 0x1000000UL) ]
        [ X(0, 0x1000000UL) ]
        [ X(0, 0x1000000UL) ]
        [ X(0, 0x1000000UL) ] ]

  /// C6.2.12 AND (immediate)
  [<TestMethod>]
  member _.``C6.2.12 AND``() =
    check "9200f020" []
      [ [ X(0, 0x1441050145044445UL) ]
        [ X(0, 0x1540441001541440UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x100000000UL) ] ]
    check "121c0020" []
      [ [ X(0, 0x0UL) ]
        [ X(0, 0x0UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "927c0020" []
      [ [ X(0, 0x0UL) ]
        [ X(0, 0x0UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "0a020020" []
      [ [ X(0, 0x61024446UL) ]
        [ X(0, 0x97c1202UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]
    check "8a020020" []
      [ [ X(0, 0xb88380a061024446UL) ]
        [ X(0, 0x98480410097c1202UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x100000000UL) ] ]
    check "0e221c20" []
      [ [ Q(0, 0x2e2240dce00cUL, 0x0UL) ]
        [ Q(0, 0x5148802449001c00UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "4e221c20" []
      [ [ Q(0, 0x2e2240dce00cUL, 0x602440e43e015UL) ]
        [ Q(0, 0x5148802449001c00UL, 0x42200a5240199028UL) ]
        [ Q(0, 0x0UL, 0x8000007f400000UL) ]
        [ Q(0, 0x0UL, 0x3fb0000000000000UL) ] ]
    check "9240bc00" []
      [ [ X(0, 0x2dec89025cc1UL) ]
        [ X(0, 0x35de1c9756ceUL) ]
        []
        [] ]
    check "9240bc11" []
      [ [ X(17, 0x2dec89025cc1UL) ]
        [ X(17, 0x35de1c9756ceUL) ]
        [ X(17, 0x0UL) ]
        [ X(17, 0xffffffffUL) ] ]
    check "9240bc1e" []
      [ [ X(30, 0x2dec89025cc1UL) ]
        [ X(30, 0x35de1c9756ceUL) ]
        [ X(30, 0x0UL) ]
        [ X(30, 0xffffffffUL) ] ]

  /// C6.2.14 ANDS (immediate)
  [<TestMethod>]
  member _.``C6.2.14 ANDS``() =
    check "f2089c20" []
      [ [ X(0, 0xbe008d006500ec00UL); Nzcv 0x80000000UL ]
        [ X(0, 0xbf0046000b001e00UL); Nzcv 0x80000000UL ]
        [ Nzcv 0x40000000UL ]
        [ X(0, 0x0UL); Nzcv 0x40000000UL ] ]
    check "721c0020" []
      [ [ X(0, 0x0UL); Nzcv 0x40000000UL ]
        [ X(0, 0x0UL); Nzcv 0x40000000UL ]
        [ Nzcv 0x40000000UL ]
        [ X(0, 0x0UL); Nzcv 0x40000000UL ] ]
    check "f27c0020" []
      [ [ X(0, 0x0UL); Nzcv 0x40000000UL ]
        [ X(0, 0x0UL); Nzcv 0x40000000UL ]
        [ Nzcv 0x40000000UL ]
        [ X(0, 0x0UL); Nzcv 0x40000000UL ] ]
    check "6a020020" []
      [ [ X(0, 0x61024446UL); Nzcv 0x0UL ]
        [ X(0, 0x97c1202UL); Nzcv 0x0UL ]
        [ X(0, 0x1UL); Nzcv 0x0UL ]
        [ X(0, 0x0UL); Nzcv 0x40000000UL ] ]
    check "ea020020" []
      [ [ X(0, 0xb88380a061024446UL); Nzcv 0x80000000UL ]
        [ X(0, 0x98480410097c1202UL); Nzcv 0x80000000UL ]
        [ X(0, 0x1UL); Nzcv 0x0UL ]
        [ X(0, 0x100000000UL); Nzcv 0x0UL ] ]

  /// C6.2.16 ASR (register)
  [<TestMethod>]
  member _.``C6.2.16 ASR``() =
    check "1ac22820" []
      [ [ X(0, 0x1UL) ]
        [ X(0, 0x17f8UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "13017c20" []
      [ [ X(0, 0x32c77633UL) ]
        [ X(0, 0x5fe0f21UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "9341fc20" []
      [ [ X(0, 0xdf75c6d0b2c77633UL) ]
        [ X(0, 0xdfe4230805fe0f21UL) ]
        []
        [ X(0, 0x80000000UL) ] ]
    check "9ac22820" []
      [ [ X(0, 0xfffffffefbae3685UL) ]
        [ X(0, 0xffffffffffff7f90UL) ]
        []
        [ X(0, 0x800UL) ] ]

  /// C6.2.18 ASRV
  [<TestMethod>]
  member _.``C6.2.18 ASRV``() =
    check "1ac22820" []
      [ [ X(0, 0x1UL) ]
        [ X(0, 0x17f8UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "9ac22820" []
      [ [ X(0, 0xfffffffefbae3685UL) ]
        [ X(0, 0xffffffffffff7f90UL) ]
        []
        [ X(0, 0x800UL) ] ]

  /// C6.2.19 AT
  [<TestMethod>]
  member _.``C6.2.19 AT``() =
    raises BinIR.SideEffect.UndefinedInstruction "d5087841"

  /// <summary>
  /// The code AUTDA checks comes from a key the oracle's process draws
  /// at random, so no signed value can be given to it. What the manual
  /// fixes is checked instead (C6.2.20, Auth()), over every input set with
  /// X0 a canonical pointer and X1 the modifier: a pointer PACDA signed
  /// comes back as it was, and one nothing signed, or the other key's
  /// signer did, fails, leaving key A's error code in bits 62:61. The
  /// oracle agrees with the round trip and both failures, which its
  /// processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.20 AUTDA``() =
    authenticates "dac11820" "dac10820" "dac10c20" 0 0x2000000000000000UL

  /// <summary>
  /// The code AUTDZA checks comes from a key the oracle's process draws
  /// at random, so no signed value can be given to it. What the manual
  /// fixes is checked instead (C6.2.20, Auth()), over every input set with
  /// X0 a canonical pointer and zero the modifier: a pointer PACDZA signed
  /// comes back as it was, and one nothing signed, or the other key's
  /// signer did, fails, leaving key A's error code in bits 62:61. The
  /// oracle agrees with the round trip and both failures, which its
  /// processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.20 AUTDZA``() =
    authenticates "dac13be0" "dac12be0" "dac12fe0" 0 0x2000000000000000UL

  /// <summary>
  /// The code AUTDB checks comes from a key the oracle's process draws
  /// at random, so no signed value can be given to it. What the manual
  /// fixes is checked instead (C6.2.21, Auth()), over every input set with
  /// X0 a canonical pointer and X1 the modifier: a pointer PACDB signed
  /// comes back as it was, and one nothing signed, or the other key's
  /// signer did, fails, leaving key B's error code in bits 62:61. The
  /// oracle agrees with the round trip and both failures, which its
  /// processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.21 AUTDB``() =
    authenticates "dac11c20" "dac10c20" "dac10820" 0 0x4000000000000000UL

  /// <summary>
  /// The code AUTDZB checks comes from a key the oracle's process draws
  /// at random, so no signed value can be given to it. What the manual
  /// fixes is checked instead (C6.2.21, Auth()), over every input set with
  /// X0 a canonical pointer and zero the modifier: a pointer PACDZB signed
  /// comes back as it was, and one nothing signed, or the other key's
  /// signer did, fails, leaving key B's error code in bits 62:61. The
  /// oracle agrees with the round trip and both failures, which its
  /// processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.21 AUTDZB``() =
    authenticates "dac13fe0" "dac12fe0" "dac12be0" 0 0x4000000000000000UL

  /// <summary>
  /// The code AUTIA checks comes from a key the oracle's process draws
  /// at random, so no signed value can be given to it. What the manual
  /// fixes is checked instead (C6.2.22, Auth()), over every input set with
  /// X0 a canonical pointer and X1 the modifier: a pointer PACIA signed
  /// comes back as it was, and one nothing signed, or the other key's
  /// signer did, fails, leaving key A's error code in bits 62:61. The
  /// oracle agrees with the round trip and both failures, which its
  /// processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.22 AUTIA``() =
    authenticates "dac11020" "dac10020" "dac10420" 0 0x2000000000000000UL

  /// <summary>
  /// The code AUTIA1716 checks comes from a key the oracle's process draws
  /// at random, so no signed value can be given to it. What the manual
  /// fixes is checked instead (C6.2.22, Auth()), over every input set with
  /// X17 a canonical pointer and X16 the modifier: a pointer PACIA1716 signed
  /// comes back as it was, and one nothing signed, or the other key's
  /// signer did, fails, leaving key A's error code in bits 62:61. The
  /// oracle agrees with the round trip and both failures, which its
  /// processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.22 AUTIA1716``() =
    authenticates "d503219f" "d503211f" "d503215f" 17 0x2000000000000000UL

  /// <summary>
  /// The code AUTIASP checks comes from a key the oracle's process draws
  /// at random, so no signed value can be given to it. What the manual
  /// fixes is checked instead (C6.2.22, Auth()), over every input set with
  /// X30 a canonical pointer and SP the modifier: a pointer PACIASP signed
  /// comes back as it was, and one nothing signed, or the other key's
  /// signer did, fails, leaving key A's error code in bits 62:61. The
  /// oracle agrees with the round trip and both failures, which its
  /// processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.22 AUTIASP``() =
    authenticates "d50323bf" "d503233f" "d503237f" 30 0x2000000000000000UL

  /// <summary>
  /// The code AUTIAZ checks comes from a key the oracle's process draws
  /// at random, so no signed value can be given to it. What the manual
  /// fixes is checked instead (C6.2.22, Auth()), over every input set with
  /// X30 a canonical pointer and zero the modifier: a pointer PACIAZ signed
  /// comes back as it was, and one nothing signed, or the other key's
  /// signer did, fails, leaving key A's error code in bits 62:61. The
  /// oracle agrees with the round trip and both failures, which its
  /// processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.22 AUTIAZ``() =
    authenticates "d503239f" "d503231f" "d503235f" 30 0x2000000000000000UL

  /// <summary>
  /// The code AUTIZA checks comes from a key the oracle's process draws
  /// at random, so no signed value can be given to it. What the manual
  /// fixes is checked instead (C6.2.22, Auth()), over every input set with
  /// X0 a canonical pointer and zero the modifier: a pointer PACIZA signed
  /// comes back as it was, and one nothing signed, or the other key's
  /// signer did, fails, leaving key A's error code in bits 62:61. The
  /// oracle agrees with the round trip and both failures, which its
  /// processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.22 AUTIZA``() =
    authenticates "dac133e0" "dac123e0" "dac127e0" 0 0x2000000000000000UL

  /// <summary>
  /// The code AUTIB checks comes from a key the oracle's process draws
  /// at random, so no signed value can be given to it. What the manual
  /// fixes is checked instead (C6.2.23, Auth()), over every input set with
  /// X0 a canonical pointer and X1 the modifier: a pointer PACIB signed
  /// comes back as it was, and one nothing signed, or the other key's
  /// signer did, fails, leaving key B's error code in bits 62:61. The
  /// oracle agrees with the round trip and both failures, which its
  /// processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.23 AUTIB``() =
    authenticates "dac11420" "dac10420" "dac10020" 0 0x4000000000000000UL

  /// <summary>
  /// The code AUTIB1716 checks comes from a key the oracle's process draws
  /// at random, so no signed value can be given to it. What the manual
  /// fixes is checked instead (C6.2.23, Auth()), over every input set with
  /// X17 a canonical pointer and X16 the modifier: a pointer PACIB1716 signed
  /// comes back as it was, and one nothing signed, or the other key's
  /// signer did, fails, leaving key B's error code in bits 62:61. The
  /// oracle agrees with the round trip and both failures, which its
  /// processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.23 AUTIB1716``() =
    authenticates "d50321df" "d503215f" "d503211f" 17 0x4000000000000000UL

  /// <summary>
  /// The code AUTIBSP checks comes from a key the oracle's process draws
  /// at random, so no signed value can be given to it. What the manual
  /// fixes is checked instead (C6.2.23, Auth()), over every input set with
  /// X30 a canonical pointer and SP the modifier: a pointer PACIBSP signed
  /// comes back as it was, and one nothing signed, or the other key's
  /// signer did, fails, leaving key B's error code in bits 62:61. The
  /// oracle agrees with the round trip and both failures, which its
  /// processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.23 AUTIBSP``() =
    authenticates "d50323ff" "d503237f" "d503233f" 30 0x4000000000000000UL

  /// <summary>
  /// The code AUTIBZ checks comes from a key the oracle's process draws
  /// at random, so no signed value can be given to it. What the manual
  /// fixes is checked instead (C6.2.23, Auth()), over every input set with
  /// X30 a canonical pointer and zero the modifier: a pointer PACIBZ signed
  /// comes back as it was, and one nothing signed, or the other key's
  /// signer did, fails, leaving key B's error code in bits 62:61. The
  /// oracle agrees with the round trip and both failures, which its
  /// processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.23 AUTIBZ``() =
    authenticates "d50323df" "d503235f" "d503231f" 30 0x4000000000000000UL

  /// <summary>
  /// The code AUTIZB checks comes from a key the oracle's process draws
  /// at random, so no signed value can be given to it. What the manual
  /// fixes is checked instead (C6.2.23, Auth()), over every input set with
  /// X0 a canonical pointer and zero the modifier: a pointer PACIZB signed
  /// comes back as it was, and one nothing signed, or the other key's
  /// signer did, fails, leaving key B's error code in bits 62:61. The
  /// oracle agrees with the round trip and both failures, which its
  /// processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.23 AUTIZB``() =
    authenticates "dac137e0" "dac127e0" "dac123e0" 0 0x4000000000000000UL

  /// C6.2.24 AXFLAG
  [<TestMethod>]
  member _.``C6.2.24 AXFLAG``() =
    check "d500405f" []
      [ [ Nzcv 0x40000000UL ]
        [ Nzcv 0x40000000UL ]
        []
        [ Nzcv 0x40000000UL ] ]

  /// <summary>
  /// B.cond cannot run in the oracle, which has nowhere for it to go, so
  /// this checks the jump: a conditional one out of the instruction, to its
  /// own address plus imm19 times four where the condition holds and to the
  /// next instruction where it does not, for every condition under every
  /// Nzcv (C6.2.25).
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.25 B.COND``() =
    (* Bit n of entry c says whether condition c holds for NZCV n, as
       ConditionHolds gives it. *)
    let holds =
      [| 0xf0f0
         0x0f0f
         0xcccc
         0x3333
         0xff00
         0x00ff
         0xaaaa
         0x5555
         0x0c0c
         0xf3f3
         0xaa55
         0x55aa
         0x0a05
         0xf5fa
         0xffff
         0xffff |]
    for c in 0 .. 15 do
      let hex = $"{0x54000200 ||| c:x8}"
      Assert.AreEqual<string option>(Some "InterCJmp", exitOf hex)
      for n in 0 .. 15 do
        let taken = (holds[c] >>> n) &&& 1 = 1
        let target = if taken then 0x40UL else 0x4UL
        let inputs = [ Nzcv(uint64 n <<< 28) ]
        goesTo hex inputs (A64Machine.code + target)

  /// <summary>
  /// B cannot run in the oracle, which has nowhere for it to go, so this
  /// checks the jump: one out of the instruction, of the plain kind, to the
  /// address the encoding names -- its own plus imm26 times four (C6.2.26)
  /// -- whatever the registers hold, and nothing else changed.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.26 B``() =
    Assert.AreEqual<string option>(Some "Base", exitOf "14000001")
    goesTo "14000001" [] (A64Machine.code + 0x4UL)
    goesTo "14000040" [] (A64Machine.code + 0x100UL)
    goesTo "17ffffc0" [] (A64Machine.code - 0x100UL)

  /// C6.2.27 BFC
  [<TestMethod>]
  member _.``C6.2.27 BFC``() =
    check "331d13e0" []
      [ [ X(0, 0x89025c01UL) ]
        [ X(0, 0x1c975606UL) ]
        []
        [ X(0, 0xffffff07UL) ] ]
    check "b37d13e0" []
      [ [ X(0, 0x910a2dec89025c01UL) ]
        [ X(0, 0x975835de1c975606UL) ]
        []
        [ X(0, 0xffffff07UL) ] ]

  /// C6.2.28 BFI
  [<TestMethod>]
  member _.``C6.2.28 BFI``() =
    check "331d1020" []
      [ [ X(0, 0x89025c39UL) ]
        [ X(0, 0x1c975616UL) ]
        [ X(0, 0x8UL) ]
        [ X(0, 0xffffff07UL) ] ]
    check "b37d1020" []
      [ [ X(0, 0x910a2dec89025c39UL) ]
        [ X(0, 0x975835de1c975616UL) ]
        [ X(0, 0x8UL) ]
        [ X(0, 0xffffff07UL) ] ]
    check "b3430820" []
      [ [ X(0, 0xf10a2dec89025cc1UL) ]
        [ X(0, 0x575835de1c9756ceUL) ]
        [ X(0, 0x2000000000000000UL) ]
        [] ]

  /// C6.2.29 BFM
  [<TestMethod>]
  member _.``C6.2.29 BFM``() =
    check "331d13e0" []
      [ [ X(0, 0x89025c01UL) ]
        [ X(0, 0x1c975606UL) ]
        []
        [ X(0, 0xffffff07UL) ] ]
    check "b37d13e0" []
      [ [ X(0, 0x910a2dec89025c01UL) ]
        [ X(0, 0x975835de1c975606UL) ]
        []
        [ X(0, 0xffffff07UL) ] ]
    check "331d1020" []
      [ [ X(0, 0x89025c39UL) ]
        [ X(0, 0x1c975616UL) ]
        [ X(0, 0x8UL) ]
        [ X(0, 0xffffff07UL) ] ]
    check "b37d1020" []
      [ [ X(0, 0x910a2dec89025c39UL) ]
        [ X(0, 0x975835de1c975616UL) ]
        [ X(0, 0x8UL) ]
        [ X(0, 0xffffff07UL) ] ]
    check "33031420" []
      [ [ X(0, 0x89025cc4UL) ]
        [ X(0, 0x1c9756c8UL) ]
        []
        [ X(0, 0xfffffff8UL) ] ]
    check "b3431420" []
      [ [ X(0, 0x910a2dec89025cc4UL) ]
        [ X(0, 0x975835de1c9756c8UL) ]
        []
        [ X(0, 0xfffffff8UL) ] ]
    check "33031c20" []
      [ [ X(0, 0x89025cccUL) ]
        [ X(0, 0x1c9756c8UL) ]
        []
        [ X(0, 0xffffffe0UL) ] ]
    check "b3431c20" []
      [ [ X(0, 0x910a2dec89025cccUL) ]
        [ X(0, 0x975835de1c9756c8UL) ]
        []
        [ X(0, 0xffffffe0UL) ] ]
    check "b34003e0" []
      [ [ X(0, 0x910a2dec89025cc0UL) ]
        []
        []
        [ X(0, 0xfffffffeUL) ] ]
    check "b3400020" [] [ []; []; [ X(0, 0x1UL) ]; [ X(0, 0xfffffffeUL) ] ]
    check "b3430820" []
      [ [ X(0, 0xf10a2dec89025cc1UL) ]
        [ X(0, 0x575835de1c9756ceUL) ]
        [ X(0, 0x2000000000000000UL) ]
        [] ]

  /// C6.2.30 BFXIL
  [<TestMethod>]
  member _.``C6.2.30 BFXIL``() =
    check "33031420" []
      [ [ X(0, 0x89025cc4UL) ]
        [ X(0, 0x1c9756c8UL) ]
        []
        [ X(0, 0xfffffff8UL) ] ]
    check "b3431420" []
      [ [ X(0, 0x910a2dec89025cc4UL) ]
        [ X(0, 0x975835de1c9756c8UL) ]
        []
        [ X(0, 0xfffffff8UL) ] ]
    check "33031c20" []
      [ [ X(0, 0x89025cccUL) ]
        [ X(0, 0x1c9756c8UL) ]
        []
        [ X(0, 0xffffffe0UL) ] ]
    check "b3431c20" []
      [ [ X(0, 0x910a2dec89025cccUL) ]
        [ X(0, 0x975835de1c9756c8UL) ]
        []
        [ X(0, 0xffffffe0UL) ] ]
    check "b34003e0" []
      [ [ X(0, 0x910a2dec89025cc0UL) ]
        []
        []
        [ X(0, 0xfffffffeUL) ] ]
    check "b3400020" [] [ []; []; [ X(0, 0x1UL) ]; [ X(0, 0xfffffffeUL) ] ]

  /// C6.2.31 BIC (shifted register)
  [<TestMethod>]
  member _.``C6.2.31 BIC``() =
    check "0a220020" []
      [ [ X(0, 0x48ca821UL) ]
        [ X(0, 0x2800c40UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "2f009460" []
      [ [ Q(0, 0x96281964c90489b8UL, 0x0UL) ]
        [ Q(0, 0x9a78a72430f8ca54UL, 0x0UL) ]
        [ Q(0, 0xbfc000003f800000UL, 0x0UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ] ]
    check "6f009460" []
      [ [ Q(0, 0x96281964c90489b8UL, 0x65ace2685a042c6cUL) ]
        [ Q(0, 0x9a78a72430f8ca54UL, 0x4448cab822b8690cUL) ]
        [ Q(0, 0xbfc000003f800000UL, 0x3dcccccc40400000UL) ]
        [] ]
    check "2f001460" []
      [ [ Q(0, 0x962b1964c90789b8UL, 0x0UL) ]
        [ Q(0, 0x9a7aa72430f9ca54UL, 0x0UL) ]
        [ Q(0, 0xbfc000003f800000UL, 0x0UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ] ]
    check "6f001460" []
      [ [ Q(0, 0x962b1964c90789b8UL, 0x65ace2685a072c6cUL) ]
        [ Q(0, 0x9a7aa72430f9ca54UL, 0x444bcab822bb690cUL) ]
        [ Q(0, 0xbfc000003f800000UL, 0x3dcccccc40400000UL) ]
        [] ]
    check "0e621c20" []
      [ [ Q(0, 0x7061410d08000010UL, 0x0UL) ]
        [ Q(0, 0x6800301160f8224UL, 0x0UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4e621c20" []
      [ [ Q(0, 0x7061410d08000010UL, 0x40d0800a20b01c02UL) ]
        [ Q(0, 0x6800301160f8224UL, 0xa01111011f062081UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x7f20000000800000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x999999999999aUL) ] ]
    check "8a220020" []
      [ [ X(0, 0x6680d01048ca821UL) ]
        [ X(0, 0x2780420002800c40UL) ]
        []
        [ X(0, 0x0UL) ] ]

  /// C6.2.32 BICS (shifted register)
  [<TestMethod>]
  member _.``C6.2.32 BICS``() =
    check "6a220020" []
      [ [ X(0, 0x48ca821UL); Nzcv 0x0UL ]
        [ X(0, 0x2800c40UL); Nzcv 0x0UL ]
        [ Nzcv 0x40000000UL ]
        [ X(0, 0x0UL); Nzcv 0x40000000UL ] ]
    check "ea220020" []
      [ [ X(0, 0x6680d01048ca821UL); Nzcv 0x0UL ]
        [ X(0, 0x2780420002800c40UL); Nzcv 0x0UL ]
        [ Nzcv 0x40000000UL ]
        [ X(0, 0x0UL); Nzcv 0x40000000UL ] ]

  /// <summary>
  /// BL cannot run in the oracle, which has nowhere for it to go, so this
  /// checks the jump: a call out of the instruction to its own address
  /// plus imm26 times four, with X30 the address after it (C6.2.33).
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.33 BL``() =
    Assert.AreEqual<string option>(Some "IsCall", exitOf "94000001")
    links "94000001" [] (A64Machine.code + 0x4UL)
    links "94000040" [] (A64Machine.code + 0x100UL)

  /// <summary>
  /// BLR cannot run in the oracle, which has nowhere for it to go, so this
  /// checks the jump: a call out of the instruction to what Xn holds, with
  /// X30 the address after it, over every input set (C6.2.34).
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.34 BLR``() =
    Assert.AreEqual<string option>(Some "IsCall", exitOf "d63f0020")
    check "d63f0020" []
      [ [ X(30, 0x1000004UL); Pc 0xbeeb8da1658eec67UL ]
        [ X(30, 0x1000004UL); Pc 0xbfc846100bfc1e42UL ]
        [ X(30, 0x1000004UL); Pc 0x1UL ]
        [ X(30, 0x1000004UL); Pc 0x100000000UL ] ]

  /// <summary>
  /// BLRAA cannot run in the oracle, which has nowhere for it to go, and
  /// its target is authenticated with a key the oracle's process draws
  /// at random. What the manual fixes is checked instead (C6.2.35): with X1
  /// a canonical pointer the matching PAC signed, the jump, a call,
  /// goes to the pointer; unsigned, to the pointer with the key's error
  /// code in bits 62:61; and X30 is the address after it, over every input set.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.35 BLRAA``() =
    Assert.AreEqual<string option>(Some "IsCall", exitOf "d73f0822")
    branchesSigned "dac10041" "d73f0822" 1 0x2000000000000000UL true

  /// <summary>
  /// BLRAAZ cannot run in the oracle, which has nowhere for it to go, and
  /// its target is authenticated with a key the oracle's process draws
  /// at random. What the manual fixes is checked instead (C6.2.35): with X1
  /// a canonical pointer the matching PAC signed, the jump, a call,
  /// goes to the pointer; unsigned, to the pointer with the key's error
  /// code in bits 62:61; and X30 is the address after it, over every input set.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.35 BLRAAZ``() =
    Assert.AreEqual<string option>(Some "IsCall", exitOf "d63f083f")
    branchesSigned "dac123e1" "d63f083f" 1 0x2000000000000000UL true

  /// <summary>
  /// BLRAB cannot run in the oracle, which has nowhere for it to go, and
  /// its target is authenticated with a key the oracle's process draws
  /// at random. What the manual fixes is checked instead (C6.2.35): with X1
  /// a canonical pointer the matching PAC signed, the jump, a call,
  /// goes to the pointer; unsigned, to the pointer with the key's error
  /// code in bits 62:61; and X30 is the address after it, over every input set.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.35 BLRAB``() =
    Assert.AreEqual<string option>(Some "IsCall", exitOf "d73f0c22")
    branchesSigned "dac10441" "d73f0c22" 1 0x4000000000000000UL true

  /// <summary>
  /// BLRABZ cannot run in the oracle, which has nowhere for it to go, and
  /// its target is authenticated with a key the oracle's process draws
  /// at random. What the manual fixes is checked instead (C6.2.35): with X1
  /// a canonical pointer the matching PAC signed, the jump, a call,
  /// goes to the pointer; unsigned, to the pointer with the key's error
  /// code in bits 62:61; and X30 is the address after it, over every input set.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.35 BLRABZ``() =
    Assert.AreEqual<string option>(Some "IsCall", exitOf "d63f0c3f")
    branchesSigned "dac127e1" "d63f0c3f" 1 0x4000000000000000UL true

  /// <summary>
  /// BR cannot run in the oracle, which has nowhere for it to go, so this
  /// checks the jump: out of the instruction, of the plain kind, to what
  /// Xn holds, over every input set (C6.2.36).
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.36 BR``() =
    Assert.AreEqual<string option>(Some "Base", exitOf "d61f0020")
    check "d61f0020" []
      [ [ Pc 0xbeeb8da1658eec67UL ]
        [ Pc 0xbfc846100bfc1e42UL ]
        [ Pc 0x1UL ]
        [ Pc 0x100000000UL ] ]

  /// <summary>
  /// BRAA cannot run in the oracle, which has nowhere for it to go, and
  /// its target is authenticated with a key the oracle's process draws
  /// at random. What the manual fixes is checked instead (C6.2.37): with X1
  /// a canonical pointer the matching PAC signed, the jump, of the plain kind,
  /// goes to the pointer; unsigned, to the pointer with the key's error
  /// code in bits 62:61, over every input set.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.37 BRAA``() =
    Assert.AreEqual<string option>(Some "Base", exitOf "d71f0822")
    branchesSigned "dac10041" "d71f0822" 1 0x2000000000000000UL false

  /// <summary>
  /// BRAAZ cannot run in the oracle, which has nowhere for it to go, and
  /// its target is authenticated with a key the oracle's process draws
  /// at random. What the manual fixes is checked instead (C6.2.37): with X1
  /// a canonical pointer the matching PAC signed, the jump, of the plain kind,
  /// goes to the pointer; unsigned, to the pointer with the key's error
  /// code in bits 62:61, over every input set.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.37 BRAAZ``() =
    Assert.AreEqual<string option>(Some "Base", exitOf "d61f083f")
    branchesSigned "dac123e1" "d61f083f" 1 0x2000000000000000UL false

  /// <summary>
  /// BRAB cannot run in the oracle, which has nowhere for it to go, and
  /// its target is authenticated with a key the oracle's process draws
  /// at random. What the manual fixes is checked instead (C6.2.37): with X1
  /// a canonical pointer the matching PAC signed, the jump, of the plain kind,
  /// goes to the pointer; unsigned, to the pointer with the key's error
  /// code in bits 62:61, over every input set.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.37 BRAB``() =
    Assert.AreEqual<string option>(Some "Base", exitOf "d71f0c22")
    branchesSigned "dac10441" "d71f0c22" 1 0x4000000000000000UL false

  /// <summary>
  /// BRABZ cannot run in the oracle, which has nowhere for it to go, and
  /// its target is authenticated with a key the oracle's process draws
  /// at random. What the manual fixes is checked instead (C6.2.37): with X1
  /// a canonical pointer the matching PAC signed, the jump, of the plain kind,
  /// goes to the pointer; unsigned, to the pointer with the key's error
  /// code in bits 62:61, over every input set.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.37 BRABZ``() =
    Assert.AreEqual<string option>(Some "Base", exitOf "d61f0c3f")
    branchesSigned "dac127e1" "d61f0c3f" 1 0x4000000000000000UL false

  /// C6.2.38 BRK
  [<TestMethod>]
  member _.``C6.2.38 BRK``() =
    raises BinIR.SideEffect.Breakpoint "d4200000"

  /// C6.2.39 BTI
  [<TestMethod>]
  member _.``C6.2.39 BTI``() =
    check "d503241f" [] [ []; []; []; [] ]

  /// C6.2.40 CASB, CASAB, CASALB, CASLB
  [<TestMethod>]
  member _.``C6.2.40 CASAB``() =
    check "08e27c20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0x81UL) ]
        [ X(2, 0xe4UL) ]
        [ X(2, 0x0UL) ]
        [ X(2, 0x55UL); M(0, 0x55555555555555ffUL) ] ]

  /// C6.2.40 CASB, CASAB, CASALB, CASLB
  [<TestMethod>]
  member _.``C6.2.40 CASALB``() =
    check "08e2fc20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0x81UL) ]
        [ X(2, 0xe4UL) ]
        [ X(2, 0x0UL) ]
        [ X(2, 0x55UL); M(0, 0x55555555555555ffUL) ] ]

  /// C6.2.40 CASB, CASAB, CASALB, CASLB
  [<TestMethod>]
  member _.``C6.2.40 CASB``() =
    check "08a27c20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0x81UL) ]
        [ X(2, 0xe4UL) ]
        [ X(2, 0x0UL) ]
        [ X(2, 0x55UL); M(0, 0x55555555555555ffUL) ] ]

  /// C6.2.40 CASB, CASAB, CASALB, CASLB
  [<TestMethod>]
  member _.``C6.2.40 CASLB``() =
    check "08a2fc20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0x81UL) ]
        [ X(2, 0xe4UL) ]
        [ X(2, 0x0UL) ]
        [ X(2, 0x55UL); M(0, 0x55555555555555ffUL) ] ]

  /// C6.2.41 CASH, CASAH, CASALH, CASLH
  [<TestMethod>]
  member _.``C6.2.41 CASAH``() =
    check "48e27c20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0x4a81UL) ]
        [ X(2, 0xe1e4UL) ]
        [ X(2, 0x0UL) ]
        [ X(2, 0x5555UL); M(0, 0x555555555555ffffUL) ] ]

  /// C6.2.41 CASH, CASAH, CASALH, CASLH
  [<TestMethod>]
  member _.``C6.2.41 CASALH``() =
    check "48e2fc20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0x4a81UL) ]
        [ X(2, 0xe1e4UL) ]
        [ X(2, 0x0UL) ]
        [ X(2, 0x5555UL); M(0, 0x555555555555ffffUL) ] ]

  /// C6.2.41 CASH, CASAH, CASALH, CASLH
  [<TestMethod>]
  member _.``C6.2.41 CASH``() =
    check "48a27c20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0x4a81UL) ]
        [ X(2, 0xe1e4UL) ]
        [ X(2, 0x0UL) ]
        [ X(2, 0x5555UL); M(0, 0x555555555555ffffUL) ] ]

  /// C6.2.41 CASH, CASAH, CASALH, CASLH
  [<TestMethod>]
  member _.``C6.2.41 CASLH``() =
    check "48a2fc20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0x4a81UL) ]
        [ X(2, 0xe1e4UL) ]
        [ X(2, 0x0UL) ]
        [ X(2, 0x5555UL); M(0, 0x555555555555ffffUL) ] ]

  /// C6.2.42 CASP, CASPA, CASPAL, CASPL
  [<TestMethod>]
  member _.``C6.2.42 CASP``() =
    check "48227c80" [ X(4, 0x2008000UL) ]
      [ [ X(2, 0xdb20290ac13e4a81UL); X(3, 0xd80391ffb30d1390UL) ]
        [ X(2, 0x912f822b1e8fe1e4UL); X(3, 0xf8606cc314fb6b96UL) ]
        [ X(2, 0x0UL); X(3, 0x1UL) ]
        [ M(0, 0xffffffffUL); M(8, 0x100000000UL) ] ]
    check "48227c20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0xdb20290ac13e4a81UL); X(3, 0xd80391ffb30d1390UL) ]
        [ X(2, 0x912f822b1e8fe1e4UL); X(3, 0xf8606cc314fb6b96UL) ]
        [ X(2, 0x0UL); X(3, 0x1UL) ]
        [ M(0, 0xffffffffUL); M(8, 0x2008000UL) ] ]

  /// C6.2.42 CASP, CASPA, CASPAL, CASPL
  [<TestMethod>]
  member _.``C6.2.42 CASPA``() =
    check "48627c80" [ X(4, 0x2008000UL) ]
      [ [ X(2, 0xdb20290ac13e4a81UL); X(3, 0xd80391ffb30d1390UL) ]
        [ X(2, 0x912f822b1e8fe1e4UL); X(3, 0xf8606cc314fb6b96UL) ]
        [ X(2, 0x0UL); X(3, 0x1UL) ]
        [ M(0, 0xffffffffUL); M(8, 0x100000000UL) ] ]
    check "48627c20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0xdb20290ac13e4a81UL); X(3, 0xd80391ffb30d1390UL) ]
        [ X(2, 0x912f822b1e8fe1e4UL); X(3, 0xf8606cc314fb6b96UL) ]
        [ X(2, 0x0UL); X(3, 0x1UL) ]
        [ M(0, 0xffffffffUL); M(8, 0x2008000UL) ] ]

  /// C6.2.42 CASP, CASPA, CASPAL, CASPL
  [<TestMethod>]
  member _.``C6.2.42 CASPAL``() =
    check "4862fc80" [ X(4, 0x2008000UL) ]
      [ [ X(2, 0xdb20290ac13e4a81UL); X(3, 0xd80391ffb30d1390UL) ]
        [ X(2, 0x912f822b1e8fe1e4UL); X(3, 0xf8606cc314fb6b96UL) ]
        [ X(2, 0x0UL); X(3, 0x1UL) ]
        [ M(0, 0xffffffffUL); M(8, 0x100000000UL) ] ]
    check "4862fc20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0xdb20290ac13e4a81UL); X(3, 0xd80391ffb30d1390UL) ]
        [ X(2, 0x912f822b1e8fe1e4UL); X(3, 0xf8606cc314fb6b96UL) ]
        [ X(2, 0x0UL); X(3, 0x1UL) ]
        [ M(0, 0xffffffffUL); M(8, 0x2008000UL) ] ]

  /// C6.2.42 CASP, CASPA, CASPAL, CASPL
  [<TestMethod>]
  member _.``C6.2.42 CASPL``() =
    check "4822fc80" [ X(4, 0x2008000UL) ]
      [ [ X(2, 0xdb20290ac13e4a81UL); X(3, 0xd80391ffb30d1390UL) ]
        [ X(2, 0x912f822b1e8fe1e4UL); X(3, 0xf8606cc314fb6b96UL) ]
        [ X(2, 0x0UL); X(3, 0x1UL) ]
        [ M(0, 0xffffffffUL); M(8, 0x100000000UL) ] ]
    check "4822fc20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0xdb20290ac13e4a81UL); X(3, 0xd80391ffb30d1390UL) ]
        [ X(2, 0x912f822b1e8fe1e4UL); X(3, 0xf8606cc314fb6b96UL) ]
        [ X(2, 0x0UL); X(3, 0x1UL) ]
        [ M(0, 0xffffffffUL); M(8, 0x2008000UL) ] ]

  /// C6.2.43 CAS, CASA, CASAL, CASL
  [<TestMethod>]
  member _.``C6.2.43 CAS``() =
    check "c8a27c20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0xdb20290ac13e4a81UL) ]
        [ X(2, 0x912f822b1e8fe1e4UL) ]
        [ X(2, 0x0UL) ]
        [ M(0, 0xffffffffUL) ] ]
    check "88a27c20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0xc13e4a81UL) ]
        [ X(2, 0x1e8fe1e4UL) ]
        [ X(2, 0x0UL) ]
        [ X(2, 0x55555555UL); M(0, 0x55555555ffffffffUL) ] ]

  /// C6.2.43 CAS, CASA, CASAL, CASL
  [<TestMethod>]
  member _.``C6.2.43 CASA``() =
    check "88e27c20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0xc13e4a81UL) ]
        [ X(2, 0x1e8fe1e4UL) ]
        [ X(2, 0x0UL) ]
        [ X(2, 0x55555555UL); M(0, 0x55555555ffffffffUL) ] ]

  /// C6.2.43 CAS, CASA, CASAL, CASL
  [<TestMethod>]
  member _.``C6.2.43 CASAL``() =
    check "88e2fc20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0xc13e4a81UL) ]
        [ X(2, 0x1e8fe1e4UL) ]
        [ X(2, 0x0UL) ]
        [ X(2, 0x55555555UL); M(0, 0x55555555ffffffffUL) ] ]

  /// C6.2.43 CAS, CASA, CASAL, CASL
  [<TestMethod>]
  member _.``C6.2.43 CASL``() =
    check "88a2fc20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0xc13e4a81UL) ]
        [ X(2, 0x1e8fe1e4UL) ]
        [ X(2, 0x0UL) ]
        [ X(2, 0x55555555UL); M(0, 0x55555555ffffffffUL) ] ]

  /// <summary>
  /// CBNZ cannot run in the oracle, which has nowhere for it to go, so
  /// this checks the jump: a conditional one out of the instruction, to
  /// its own address plus imm19 times four where W0 or X0 is not zero and to
  /// the next instruction where it is, over 0, 2^32 and 1 (C6.2.44).
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.44 CBNZ``() =
    Assert.AreEqual<string option>(Some "InterCJmp", exitOf "35000200")
    goesTo "35000200" [ X(0, 0x0UL) ] (A64Machine.code + 0x4UL)
    goesTo "35000200" [ X(0, 0x100000000UL) ] (A64Machine.code + 0x4UL)
    goesTo "35000200" [ X(0, 0x1UL) ] (A64Machine.code + 0x40UL)
    Assert.AreEqual<string option>(Some "InterCJmp", exitOf "b5000200")
    goesTo "b5000200" [ X(0, 0x0UL) ] (A64Machine.code + 0x4UL)
    goesTo "b5000200" [ X(0, 0x100000000UL) ] (A64Machine.code + 0x40UL)
    goesTo "b5000200" [ X(0, 0x1UL) ] (A64Machine.code + 0x40UL)

  /// <summary>
  /// CBZ cannot run in the oracle, which has nowhere for it to go, so
  /// this checks the jump: a conditional one out of the instruction, to
  /// its own address plus imm19 times four where W0 or X0 is zero and to
  /// the next instruction where it is not, over 0, 2^32 and 1 (C6.2.45).
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.45 CBZ``() =
    Assert.AreEqual<string option>(Some "InterCJmp", exitOf "34000200")
    goesTo "34000200" [ X(0, 0x0UL) ] (A64Machine.code + 0x40UL)
    goesTo "34000200" [ X(0, 0x100000000UL) ] (A64Machine.code + 0x40UL)
    goesTo "34000200" [ X(0, 0x1UL) ] (A64Machine.code + 0x4UL)
    Assert.AreEqual<string option>(Some "InterCJmp", exitOf "b4000200")
    goesTo "b4000200" [ X(0, 0x0UL) ] (A64Machine.code + 0x40UL)
    goesTo "b4000200" [ X(0, 0x100000000UL) ] (A64Machine.code + 0x4UL)
    goesTo "b4000200" [ X(0, 0x1UL) ] (A64Machine.code + 0x4UL)

  /// C6.2.46 CCMN (immediate)
  [<TestMethod>]
  member _.``C6.2.46 CCMN``() =
    check "3a500829" []
      [ [ Nzcv 0x90000000UL ]
        [ Nzcv 0x0UL ]
        [ Nzcv 0x0UL ]
        [] ]
    check "ba500829" []
      [ [ Nzcv 0x90000000UL ]
        [ Nzcv 0x80000000UL ]
        [ Nzcv 0x0UL ]
        [] ]
    check "3a420029" [] [ [ Nzcv 0x90000000UL ]; [ Nzcv 0x80000000UL ]; []; [] ]
    check "ba420029" [] [ [ Nzcv 0x90000000UL ]; [ Nzcv 0x30000000UL ]; []; [] ]
    check "ba400820" []
      [ [ Nzcv 0x0UL ]
        [ Nzcv 0x80000000UL ]
        [ Nzcv 0x0UL ]
        [ Nzcv 0x0UL ] ]

  /// C6.2.48 CCMP (immediate)
  [<TestMethod>]
  member _.``C6.2.48 CCMP``() =
    check "7a500829" []
      [ [ Nzcv 0x90000000UL ]
        [ Nzcv 0x20000000UL ]
        [ Nzcv 0x80000000UL ]
        [] ]
    check "fa500829" []
      [ [ Nzcv 0x90000000UL ]
        [ Nzcv 0xa0000000UL ]
        [ Nzcv 0x80000000UL ]
        [] ]
    check "7a420029" []
      [ [ Nzcv 0x90000000UL ]
        [ Nzcv 0x0UL ]
        [ Nzcv 0x0UL ]
        [] ]
    check "fa420029" []
      [ [ Nzcv 0x90000000UL ]
        [ Nzcv 0x20000000UL ]
        [ Nzcv 0x0UL ]
        [] ]
    check "fa400820" []
      [ [ Nzcv 0x0UL ]
        [ Nzcv 0xa0000000UL ]
        [ Nzcv 0x20000000UL ]
        [ Nzcv 0x0UL ] ]

  /// C6.2.50 CFINV
  [<TestMethod>]
  member _.``C6.2.50 CFINV``() =
    check "d500401f" []
      [ [ Nzcv 0x30000000UL ]
        [ Nzcv 0x70000000UL ]
        [ Nzcv 0x40000000UL ]
        [ Nzcv 0xb0000000UL ] ]

  /// C6.2.51 CFP
  [<TestMethod>]
  member _.``C6.2.51 CFP``() =
    raises BinIR.SideEffect.UndefinedInstruction "d50b7380"

  /// C6.2.52 CINC
  [<TestMethod>]
  member _.``C6.2.52 CINC``() =
    check "1a811420" []
      [ [ X(0, 0x658eec67UL) ]
        [ X(0, 0xbfc1e43UL) ]
        [ X(0, 0x2UL) ]
        [ X(0, 0x0UL) ] ]
    check "9a811420" []
      [ [ X(0, 0xbeeb8da1658eec67UL) ]
        [ X(0, 0xbfc846100bfc1e43UL) ]
        [ X(0, 0x2UL) ]
        [ X(0, 0x100000000UL) ] ]

  /// C6.2.53 CINV
  [<TestMethod>]
  member _.``C6.2.53 CINV``() =
    check "5a811020" []
      [ [ X(0, 0x658eec67UL) ]
        [ X(0, 0xf403e1bdUL) ]
        [ X(0, 0xfffffffeUL) ]
        [ X(0, 0x0UL) ] ]
    check "da811020" []
      [ [ X(0, 0xbeeb8da1658eec67UL) ]
        [ X(0, 0x4037b9eff403e1bdUL) ]
        [ X(0, 0xfffffffffffffffeUL) ]
        [ X(0, 0x100000000UL) ] ]

  /// C6.2.54 CLREX
  [<TestMethod>]
  member _.``C6.2.54 CLREX``() =
    check "d5033f5f" [] [ []; []; []; [] ]

  /// C6.2.55 CLS
  [<TestMethod>]
  member _.``C6.2.55 CLS``() =
    check "5ac01420" []
      [ [ X(0, 0x0UL) ]
        [ X(0, 0x3UL) ]
        [ X(0, 0x1eUL) ]
        [ X(0, 0x1fUL) ] ]
    check "0e204820" []
      [ [ Q(0, 0x100010202UL, 0x0UL) ]
        [ Q(0, 0x1000100030001UL, 0x0UL) ]
        [ Q(0, 0x70700070707UL, 0x0UL) ]
        [ Q(0, 0x3070707070707UL, 0x0UL) ] ]
    check "4e204820" []
      [ [ Q(0, 0x100010202UL, 0x1000001030502UL) ]
        [ Q(0, 0x1000100030001UL, 0x201020000020000UL) ]
        [ Q(0, 0x70700070707UL, 0x70700010707UL) ]
        [ Q(0, 0x3070707070707UL, 0x100000000000000UL) ] ]
    check "0e604820" []
      [ [ Q(0, 0x2UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xf0000000fUL, 0x0UL) ]
        [ Q(0, 0xf000f000fUL, 0x0UL) ] ]
    check "4e604820" []
      [ [ Q(0, 0x2UL, 0x10005UL) ]
        [ Q(0, 0x0UL, 0x2000200000000UL) ]
        [ Q(0, 0xf0000000fUL, 0xf0000000fUL) ]
        [ Q(0, 0xf000f000fUL, 0x1000000000000UL) ] ]
    check "0ea04820" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x1fUL, 0x0UL) ] ]
    check "4ea04820" []
      [ [ Q(0, 0x0UL, 0x1UL) ]
        [ Q(0, 0x0UL, 0x200000000UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x1fUL, 0x100000000UL) ] ]
    check "dac01420" []
      [ [ X(0, 0x0UL) ]
        [ X(0, 0x0UL) ]
        [ X(0, 0x3eUL) ]
        [ X(0, 0x1eUL) ] ]

  /// C6.2.56 CLZ
  [<TestMethod>]
  member _.``C6.2.56 CLZ``() =
    check "5ac01020" []
      [ [ X(0, 0x1UL) ]
        [ X(0, 0x4UL) ]
        [ X(0, 0x1fUL) ]
        [ X(0, 0x20UL) ] ]
    check "2e204820" []
      [ [ Q(0, 0x101010201000003UL, 0x0UL) ]
        [ Q(0, 0x100000201040002UL, 0x0UL) ]
        [ Q(0, 0x100080800080808UL, 0x0UL) ]
        [ Q(0, 0x104080808080808UL, 0x0UL) ] ]
    check "6e204820" []
      [ [ Q(0, 0x101010201000003UL, 0x100000102000003UL) ]
        [ Q(0, 0x100000201040002UL, 0x2030101030000UL) ]
        [ Q(0, 0x100080800080808UL, 0x100080801000808UL) ]
        [ Q(0, 0x104080808080808UL, 0x200000000000000UL) ] ]
    check "2e604820" []
      [ [ Q(0, 0x1000100010000UL, 0x0UL) ]
        [ Q(0, 0x1000000010000UL, 0x0UL) ]
        [ Q(0, 0x1001000000010UL, 0x0UL) ]
        [ Q(0, 0x1001000100010UL, 0x0UL) ] ]
    check "6e604820" []
      [ [ Q(0, 0x1000100010000UL, 0x1000000020000UL) ]
        [ Q(0, 0x1000000010000UL, 0x300010000UL) ]
        [ Q(0, 0x1001000000010UL, 0x1001000010010UL) ]
        [ Q(0, 0x1001000100010UL, 0x2000000000000UL) ] ]
    check "2ea04820" []
      [ [ Q(0, 0x100000001UL, 0x0UL) ]
        [ Q(0, 0x100000001UL, 0x0UL) ]
        [ Q(0, 0x100000000UL, 0x0UL) ]
        [ Q(0, 0x100000020UL, 0x0UL) ] ]
    check "6ea04820" []
      [ [ Q(0, 0x100000001UL, 0x100000002UL) ]
        [ Q(0, 0x100000001UL, 0x1UL) ]
        [ Q(0, 0x100000000UL, 0x100000001UL) ]
        [ Q(0, 0x100000020UL, 0x200000000UL) ] ]
    check "dac01020" []
      [ [ X(0, 0x0UL) ]
        [ X(0, 0x0UL) ]
        [ X(0, 0x3fUL) ]
        [ X(0, 0x1fUL) ] ]

  /// C6.2.57 CMN (extended register)
  [<TestMethod>]
  member _.``C6.2.57 CMN``() =
    check "2b02003f" []
      [ [ Nzcv 0x20000000UL ]
        [ Nzcv 0x80000000UL ]
        []
        [ Nzcv 0x0UL ] ]
    check "3100403f" []
      [ [ Nzcv 0x0UL ]
        [ Nzcv 0x0UL ]
        [ Nzcv 0x0UL ]
        [ Nzcv 0x0UL ] ]
    check "b100403f" []
      [ [ Nzcv 0x80000000UL ]
        [ Nzcv 0x80000000UL ]
        [ Nzcv 0x0UL ]
        [ Nzcv 0x0UL ] ]
    check "ab02003f" []
      [ [ Nzcv 0xa0000000UL ]
        [ Nzcv 0x30000000UL ]
        []
        [ Nzcv 0x0UL ] ]
    check "b140043f" []
      [ [ Nzcv 0x80000000UL ]
        [ Nzcv 0x80000000UL ]
        [ Nzcv 0x0UL ]
        [ Nzcv 0x0UL ] ]

  /// C6.2.60 CMP (extended register)
  [<TestMethod>]
  member _.``C6.2.60 CMP``() =
    check "6b02003f" []
      [ [ Nzcv 0x0UL ]
        [ Nzcv 0x0UL ]
        [ Nzcv 0x0UL ]
        [ Nzcv 0x80000000UL ] ]
    check "7100403f" []
      [ [ Nzcv 0x20000000UL ]
        [ Nzcv 0x20000000UL ]
        [ Nzcv 0x80000000UL ]
        [ Nzcv 0x80000000UL ] ]
    check "f100403f" []
      [ [ Nzcv 0xa0000000UL ]
        [ Nzcv 0xa0000000UL ]
        [ Nzcv 0x80000000UL ]
        [ Nzcv 0x20000000UL ] ]
    check "eb02003f" []
      [ [ Nzcv 0x80000000UL ]
        [ Nzcv 0x20000000UL ]
        [ Nzcv 0x0UL ]
        [ Nzcv 0x80000000UL ] ]
    check "f11ffc3f" []
      [ [ Nzcv 0xa0000000UL ]
        [ Nzcv 0xa0000000UL ]
        [ Nzcv 0x80000000UL ]
        [ Nzcv 0x20000000UL ] ]

  /// C6.2.63 CMPP
  [<TestMethod>]
  member _.``C6.2.63 CMPP``() =
    check "bac1001f" []
      [ [ Nzcv 0x0UL ]
        [ Nzcv 0x0UL ]
        [ Nzcv 0x80000000UL ]
        [ Nzcv 0x80000000UL ] ]

  /// C6.2.64 CNEG
  [<TestMethod>]
  member _.``C6.2.64 CNEG``() =
    check "5a811420" []
      [ [ X(0, 0x658eec67UL) ]
        [ X(0, 0xf403e1beUL) ]
        [ X(0, 0xffffffffUL) ]
        [ X(0, 0x0UL) ] ]
    check "da811420" []
      [ [ X(0, 0xbeeb8da1658eec67UL) ]
        [ X(0, 0x4037b9eff403e1beUL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x100000000UL) ] ]

  /// C6.2.65 CPP
  [<TestMethod>]
  member _.``C6.2.65 CPP``() =
    raises BinIR.SideEffect.UndefinedInstruction "d50b73e0"

  /// C6.2.66 CRC32B, CRC32H, CRC32W, CRC32X
  [<TestMethod>]
  member _.``C6.2.66 CRC32B``() =
    check "1ac24020" []
      [ [ X(0, 0x5f6006e4UL) ]
        [ X(0, 0x3308e1fbUL) ]
        [ X(0, 0x5a05df1bUL) ]
        [ X(0, 0x1b01a57bUL) ] ]

  /// C6.2.66 CRC32B, CRC32H, CRC32W, CRC32X
  [<TestMethod>]
  member _.``C6.2.66 CRC32H``() =
    check "1ac24420" []
      [ [ X(0, 0xbc39e31cUL) ]
        [ X(0, 0xd83e233bUL) ]
        [ X(0, 0xa73d23beUL) ]
        [ X(0, 0xdccd0c6aUL) ] ]

  /// C6.2.66 CRC32B, CRC32H, CRC32W, CRC32X
  [<TestMethod>]
  member _.``C6.2.66 CRC32W``() =
    check "1ac24820" []
      [ [ X(0, 0x186b2d43UL) ]
        [ X(0, 0xd70bbc65UL) ]
        [ X(0, 0x66074786UL) ]
        [ X(0, 0x4a691fa1UL) ] ]

  /// C6.2.66 CRC32B, CRC32H, CRC32W, CRC32X
  [<TestMethod>]
  member _.``C6.2.66 CRC32X``() =
    check "9ac24c20" []
      [ [ X(0, 0x290714a8UL) ]
        [ X(0, 0x80b57c0aUL) ]
        [ X(0, 0x88cc00ebUL) ]
        [ X(0, 0x8af2fdecUL) ] ]

  /// C6.2.67 CRC32CB, CRC32CH, CRC32CW, CRC32CX
  [<TestMethod>]
  member _.``C6.2.67 CRC32CB``() =
    check "1ac25020" []
      [ [ X(0, 0x48341c91UL) ]
        [ X(0, 0xdee523afUL) ]
        [ X(0, 0x5f16d052UL) ]
        [ X(0, 0x64d4cecfUL) ] ]

  /// C6.2.67 CRC32CB, CRC32CH, CRC32CW, CRC32CX
  [<TestMethod>]
  member _.``C6.2.67 CRC32CH``() =
    check "1ac25420" []
      [ [ X(0, 0x45f85c7UL) ]
        [ X(0, 0xbef34586UL) ]
        [ X(0, 0x1d3cefa5UL) ]
        [ X(0, 0xf92e00e1UL) ] ]

  /// C6.2.67 CRC32CB, CRC32CH, CRC32CW, CRC32CX
  [<TestMethod>]
  member _.``C6.2.67 CRC32CW``() =
    check "1ac25820" []
      [ [ X(0, 0xc45238a0UL) ]
        [ X(0, 0xc1fff7edUL) ]
        [ X(0, 0x6add1e80UL) ]
        [ X(0, 0x91d3be47UL) ] ]

  /// C6.2.67 CRC32CB, CRC32CH, CRC32CW, CRC32CX
  [<TestMethod>]
  member _.``C6.2.67 CRC32CX``() =
    check "9ac25c20" []
      [ [ X(0, 0x7fca6a99UL) ]
        [ X(0, 0x7461290eUL) ]
        [ X(0, 0x8d73846aUL) ]
        [ X(0, 0xbf617a94UL) ] ]

  /// C6.2.68 CSDB
  [<TestMethod>]
  member _.``C6.2.68 CSDB``() =
    check "d503229f" [] [ []; []; []; [] ]

  /// C6.2.69 CSEL
  [<TestMethod>]
  member _.``C6.2.69 CSEL``() =
    check "1a820020" []
      [ [ X(0, 0xfb32555eUL) ]
        [ X(0, 0xbfc1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x55555555UL) ] ]
    check "9a820020" []
      [ [ X(0, 0xf893a2eefb32555eUL) ]
        [ X(0, 0xbfc846100bfc1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x5555555555555555UL) ] ]

  /// C6.2.70 CSET
  [<TestMethod>]
  member _.``C6.2.70 CSET``() =
    check "1a9f17e0" []
      [ [ X(0, 0x0UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]
    check "9a9f17e0" []
      [ [ X(0, 0x0UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.71 CSETM
  [<TestMethod>]
  member _.``C6.2.71 CSETM``() =
    check "5a9f13e0" []
      [ [ X(0, 0x0UL) ]
        [ X(0, 0xffffffffUL) ]
        [ X(0, 0xffffffffUL) ]
        [ X(0, 0x0UL) ] ]
    check "da9f13e0" []
      [ [ X(0, 0x0UL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.72 CSINC
  [<TestMethod>]
  member _.``C6.2.72 CSINC``() =
    check "1a820420" []
      [ [ X(0, 0xfb32555fUL) ]
        [ X(0, 0xbfc1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x55555556UL) ] ]
    check "9a820420" []
      [ [ X(0, 0xf893a2eefb32555fUL) ]
        [ X(0, 0xbfc846100bfc1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x5555555555555556UL) ] ]

  /// C6.2.73 CSINV
  [<TestMethod>]
  member _.``C6.2.73 CSINV``() =
    check "5a820020" []
      [ [ X(0, 0x4cdaaa1UL) ]
        [ X(0, 0xbfc1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0xaaaaaaaaUL) ] ]
    check "da820020" []
      [ [ X(0, 0x76c5d1104cdaaa1UL) ]
        [ X(0, 0xbfc846100bfc1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0xaaaaaaaaaaaaaaaaUL) ] ]

  /// C6.2.74 CSNEG
  [<TestMethod>]
  member _.``C6.2.74 CSNEG``() =
    check "5a820420" []
      [ [ X(0, 0x4cdaaa2UL) ]
        [ X(0, 0xbfc1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0xaaaaaaabUL) ] ]
    check "da820420" []
      [ [ X(0, 0x76c5d1104cdaaa2UL) ]
        [ X(0, 0xbfc846100bfc1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0xaaaaaaaaaaaaaaabUL) ] ]

  /// C6.2.75 DC
  [<TestMethod>]
  member _.``C6.2.75 DC``() =
    check "d50b7b21" [] [ []; []; []; [] ]
    check "d50b7e21" [] [ []; []; []; [] ]

  /// C6.2.76 DCPS1
  [<TestMethod>]
  member _.``C6.2.76 DCPS1``() =
    raises BinIR.SideEffect.UndefinedInstruction "d4a00001"

  /// C6.2.77 DCPS2
  [<TestMethod>]
  member _.``C6.2.77 DCPS2``() =
    raises BinIR.SideEffect.UndefinedInstruction "d4a00002"

  /// C6.2.78 DCPS3
  [<TestMethod>]
  member _.``C6.2.78 DCPS3``() =
    raises BinIR.SideEffect.UndefinedInstruction "d4a00003"

  /// C6.2.79 DGH
  [<TestMethod>]
  member _.``C6.2.79 DGH``() =
    check "d50320df" [] [ []; []; []; [] ]

  /// C6.2.80 DMB
  [<TestMethod>]
  member _.``C6.2.80 DMB``() =
    check "d5033bbf" [] [ []; []; []; [] ]

  /// C6.2.81 DRPS
  [<TestMethod>]
  member _.``C6.2.81 DRPS``() =
    raises BinIR.SideEffect.UndefinedInstruction "d6bf03e0"

  /// C6.2.82 DSB
  [<TestMethod>]
  member _.``C6.2.82 DSB``() =
    check "d5033f9f" [] [ []; []; []; [] ]

  /// C6.2.83 DVP
  [<TestMethod>]
  member _.``C6.2.83 DVP``() =
    raises BinIR.SideEffect.UndefinedInstruction "d50b73a0"

  /// C6.2.84 EON (shifted register)
  [<TestMethod>]
  member _.``C6.2.84 EON``() =
    check "4a220020" []
      [ [ X(0, 0x614346c6UL) ]
        [ X(0, 0x297db292UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0xaaaaaaaaUL) ] ]
    check "ca220020" []
      [ [ X(0, 0xb987d0b0614346c6UL) ]
        [ X(0, 0xd84c0550297db292UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0xaaaaaaabaaaaaaaaUL) ] ]

  /// C6.2.85 EOR (immediate)
  [<TestMethod>]
  member _.``C6.2.85 EOR``() =
    check "d200cc20" []
      [ [ X(0, 0xb1e482ae6a81e368UL) ]
        [ X(0, 0xb0c7491f04f3114dUL) ]
        [ X(0, 0xf0f0f0f0f0f0f0eUL) ]
        [ X(0, 0xf0f0f0e0f0f0f0fUL) ] ]
    check "521c0020" []
      [ [ X(0, 0x658eec77UL) ]
        [ X(0, 0xbfc1e52UL) ]
        [ X(0, 0x11UL) ]
        [ X(0, 0x10UL) ] ]
    check "d27c0020" []
      [ [ X(0, 0xbeeb8da1658eec77UL) ]
        [ X(0, 0xbfc846100bfc1e52UL) ]
        [ X(0, 0x11UL) ]
        [ X(0, 0x100000010UL) ] ]
    check "4a020020" []
      [ [ X(0, 0x9ebcb939UL) ]
        [ X(0, 0xd6824d6dUL) ]
        [ X(0, 0xfffffffeUL) ]
        [ X(0, 0x55555555UL) ] ]
    check "ca020020" []
      [ [ X(0, 0x46782f4f9ebcb939UL) ]
        [ X(0, 0x27b3faafd6824d6dUL) ]
        [ X(0, 0xfffffffffffffffeUL) ]
        [ X(0, 0x5555555455555555UL) ] ]
    check "2e221c20" []
      [ [ Q(0, 0xf7ff410d1e221f10UL, 0x0UL) ]
        [ Q(0, 0xe852f51b6dfc3f7UL, 0x0UL) ]
        [ Q(0, 0xffffffff80000001UL, 0x0UL) ]
        [ Q(0, 0xc008000000000000UL, 0x0UL) ] ]
    check "6e221c20" []
      [ [ Q(0, 0xf7ff410d1e221f10UL, 0xcbf8800a70b81ce2UL) ]
        [ Q(0, 0xe852f51b6dfc3f7UL, 0xa55131a9bfc62c95UL) ]
        [ Q(0, 0xffffffff80000001UL, 0x7f20000000bfffffUL) ]
        [ Q(0, 0xc008000000000000UL, 0x404999999999999aUL) ] ]

  /// C6.2.87 ERET
  [<TestMethod>]
  member _.``C6.2.87 ERET``() =
    raises BinIR.SideEffect.UndefinedInstruction "d69f03e0"

  /// C6.2.88 ERETAA, ERETAB
  [<TestMethod>]
  member _.``C6.2.88 ERETAA``() =
    raises BinIR.SideEffect.UndefinedInstruction "d69f0bff"

  /// C6.2.88 ERETAA, ERETAB
  [<TestMethod>]
  member _.``C6.2.88 ERETAB``() =
    raises BinIR.SideEffect.UndefinedInstruction "d69f0fff"

  /// C6.2.89 ESB
  [<TestMethod>]
  member _.``C6.2.89 ESB``() =
    check "d503221f" [] [ []; []; []; [] ]

  /// C6.2.90 EXTR
  [<TestMethod>]
  member _.``C6.2.90 EXTR``() =
    check "13820c20" []
      [ [ X(0, 0xff664aabUL) ]
        [ X(0, 0x5bafca65UL) ]
        [ X(0, 0x3fffffffUL) ]
        [ X(0, 0xaaaaaaaUL) ] ]
    check "93c20c20" []
      [ [ X(0, 0xff12745ddf664aabUL) ]
        [ X(0, 0x530f7797fbafca65UL) ]
        [ X(0, 0x3fffffffffffffffUL) ]
        [ X(0, 0xaaaaaaaaaaaaaaaUL) ] ]
    check "93c20020" []
      [ [ X(0, 0xf893a2eefb32555eUL) ]
        [ X(0, 0x987bbcbfdd7e532fUL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x5555555555555555UL) ] ]

  /// C6.2.91 GMI
  [<TestMethod>]
  member _.``C6.2.91 GMI``() =
    check "9ac21420" []
      [ [ X(0, 0xf893a2eefb32555eUL) ]
        [ X(0, 0x987bbcbfdd7ed32fUL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x5555555555555555UL) ] ]

  /// C6.2.92 HINT
  [<TestMethod>]
  member _.``C6.2.92 HINT``() =
    check "d50320df" [] [ []; []; []; [] ]

  /// C6.2.93 HLT
  [<TestMethod>]
  member _.``C6.2.93 HLT``() =
    raises BinIR.SideEffect.UndefinedInstruction "d4400000"

  /// C6.2.94 HVC
  [<TestMethod>]
  member _.``C6.2.94 HVC``() =
    raises BinIR.SideEffect.UndefinedInstruction "d4000002"

  /// C6.2.95 IC
  [<TestMethod>]
  member _.``C6.2.95 IC``() =
    check "d50b7521" [] [ []; []; []; [] ]

  /// C6.2.96 IRG
  [<TestMethod>]
  member _.``C6.2.96 IRG``() =
    check "9adf1020" []
      [ [ X(0, 0xb0eb8da1658eec67UL) ]
        [ X(0, 0xb0c846100bfc1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x100000000UL) ] ]
    check "9ac21020" []
      [ [ X(0, 0xb0eb8da1658eec67UL) ]
        [ X(0, 0xb0c846100bfc1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x100000000UL) ] ]

  /// C6.2.97 ISB
  [<TestMethod>]
  member _.``C6.2.97 ISB``() =
    check "d5033fdf" [] [ []; []; []; [] ]

  /// C6.2.98 LDADDB, LDADDAB, LDADDALB, LDADDLB
  [<TestMethod>]
  member _.``C6.2.98 LDADDAB``() =
    check "38a20020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4adfUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe113UL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL); M(0, 0x55555555555555aaUL) ] ]

  /// C6.2.98 LDADDB, LDADDAB, LDADDALB, LDADDLB
  [<TestMethod>]
  member _.``C6.2.98 LDADDALB``() =
    check "38e20020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4adfUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe113UL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL); M(0, 0x55555555555555aaUL) ] ]

  /// C6.2.98 LDADDB, LDADDAB, LDADDALB, LDADDLB
  [<TestMethod>]
  member _.``C6.2.98 LDADDB``() =
    check "38220020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4adfUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe113UL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL); M(0, 0x55555555555555aaUL) ] ]

  /// C6.2.98 LDADDB, LDADDAB, LDADDALB, LDADDLB
  [<TestMethod>]
  member _.``C6.2.98 LDADDLB``() =
    check "38620020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4adfUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe113UL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL); M(0, 0x55555555555555aaUL) ] ]

  /// C6.2.99 LDADDH, LDADDAH, LDADDALH, LDADDLH
  [<TestMethod>]
  member _.``C6.2.99 LDADDAH``() =
    check "78a20020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e9fdfUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8f3513UL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL); M(0, 0x555555555555aaaaUL) ] ]

  /// C6.2.99 LDADDH, LDADDAH, LDADDALH, LDADDLH
  [<TestMethod>]
  member _.``C6.2.99 LDADDALH``() =
    check "78e20020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e9fdfUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8f3513UL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL); M(0, 0x555555555555aaaaUL) ] ]

  /// C6.2.99 LDADDH, LDADDAH, LDADDALH, LDADDLH
  [<TestMethod>]
  member _.``C6.2.99 LDADDH``() =
    check "78220020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e9fdfUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8f3513UL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL); M(0, 0x555555555555aaaaUL) ] ]

  /// C6.2.99 LDADDH, LDADDAH, LDADDALH, LDADDLH
  [<TestMethod>]
  member _.``C6.2.99 LDADDLH``() =
    check "78620020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e9fdfUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8f3513UL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL); M(0, 0x555555555555aaaaUL) ] ]

  /// C6.2.100 LDADD, LDADDA, LDADDAL, LDADDL
  [<TestMethod>]
  member _.``C6.2.100 LDADD``() =
    check "f8220020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL); M(0, 0xd3b3cbf9bc709fdfUL) ]
        [ X(0, 0x912f822b1e8fe1e4UL); M(0, 0x29ab3eeafc0e3513UL) ]
        [ M(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x5555555555555555UL); M(0, 0xaaaaaaaaaaaaaaaaUL) ] ]
    check "b8220020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290abc709fdfUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bfc0e3513UL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL); M(0, 0x55555555aaaaaaaaUL) ] ]

  /// C6.2.100 LDADD, LDADDA, LDADDAL, LDADDL
  [<TestMethod>]
  member _.``C6.2.100 LDADDA``() =
    check "b8a20020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290abc709fdfUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bfc0e3513UL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL); M(0, 0x55555555aaaaaaaaUL) ] ]

  /// C6.2.100 LDADD, LDADDA, LDADDAL, LDADDL
  [<TestMethod>]
  member _.``C6.2.100 LDADDAL``() =
    check "b8e20020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290abc709fdfUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bfc0e3513UL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL); M(0, 0x55555555aaaaaaaaUL) ] ]

  /// C6.2.100 LDADD, LDADDA, LDADDAL, LDADDL
  [<TestMethod>]
  member _.``C6.2.100 LDADDL``() =
    check "b8620020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290abc709fdfUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bfc0e3513UL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL); M(0, 0x55555555aaaaaaaaUL) ] ]

  /// C6.2.101 LDAPR
  [<TestMethod>]
  member _.``C6.2.101 LDAPR``() =
    check "f8bfc020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL) ]
        []
        [ X(0, 0x5555555555555555UL) ] ]
    check "b8bfc020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.102 LDAPRB
  [<TestMethod>]
  member _.``C6.2.102 LDAPRB``() =
    check "38bfc020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.103 LDAPRH
  [<TestMethod>]
  member _.``C6.2.103 LDAPRH``() =
    check "78bfc020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.104 LDAPUR
  [<TestMethod>]
  member _.``C6.2.104 LDAPUR``() =
    check "d9400020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL) ]
        []
        [ X(0, 0x5555555555555555UL) ] ]
    check "99410020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]
    check "d9410020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL) ]
        []
        [ X(0, 0x5555555555555555UL) ] ]
    check "99400020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.105 LDAPURB
  [<TestMethod>]
  member _.``C6.2.105 LDAPURB``() =
    check "19400020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "19410020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.106 LDAPURH
  [<TestMethod>]
  member _.``C6.2.106 LDAPURH``() =
    check "59400020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "59410020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.107 LDAPURSB
  [<TestMethod>]
  member _.``C6.2.107 LDAPURSB``() =
    check "19800020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffffffffffff81UL) ]
        [ X(0, 0xffffffffffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "19c10020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xffffff81UL) ]
        [ X(0, 0xffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "19810020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xffffffffffffff81UL) ]
        [ X(0, 0xffffffffffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "19c00020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffff81UL) ]
        [ X(0, 0xffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.108 LDAPURSH
  [<TestMethod>]
  member _.``C6.2.108 LDAPURSH``() =
    check "59800020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffffffffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "59c10020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "59810020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffffffffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "59c00020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.109 LDAPURSW
  [<TestMethod>]
  member _.``C6.2.109 LDAPURSW``() =
    check "99800020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffffffc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]
    check "99810020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xffffffffc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.110 LDAR
  [<TestMethod>]
  member _.``C6.2.110 LDAR``() =
    check "c8dffc20" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL) ]
        []
        [ X(0, 0x5555555555555555UL) ] ]
    check "88dffc20" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.111 LDARB
  [<TestMethod>]
  member _.``C6.2.111 LDARB``() =
    check "08dffc20" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.112 LDARH
  [<TestMethod>]
  member _.``C6.2.112 LDARH``() =
    check "48dffc20" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.113 LDAXP
  [<TestMethod>]
  member _.``C6.2.113 LDAXP``() =
    check "887f8022" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290aUL); X(2, 0xc13e4a81UL) ]
        [ X(0, 0x912f822bUL); X(2, 0x1e8fe1e4UL) ]
        [ X(2, 0x0UL) ]
        [ X(0, 0x55555555UL); X(2, 0x55555555UL) ] ]

  /// C6.2.114 LDAXR
  [<TestMethod>]
  member _.``C6.2.114 LDAXR``() =
    check "885ffc20" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.115 LDAXRB
  [<TestMethod>]
  member _.``C6.2.115 LDAXRB``() =
    check "085ffc20" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.116 LDAXRH
  [<TestMethod>]
  member _.``C6.2.116 LDAXRH``() =
    check "485ffc20" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.117 LDCLRB, LDCLRAB, LDCLRALB, LDCLRLB
  [<TestMethod>]
  member _.``C6.2.117 LDCLRAB``() =
    check "38a21020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe1c0UL) ]
        []
        [ X(0, 0x55UL); M(0, 0x5555555555555500UL) ] ]

  /// C6.2.117 LDCLRB, LDCLRAB, LDCLRALB, LDCLRLB
  [<TestMethod>]
  member _.``C6.2.117 LDCLRALB``() =
    check "38e21020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe1c0UL) ]
        []
        [ X(0, 0x55UL); M(0, 0x5555555555555500UL) ] ]

  /// C6.2.117 LDCLRB, LDCLRAB, LDCLRALB, LDCLRLB
  [<TestMethod>]
  member _.``C6.2.117 LDCLRB``() =
    check "38221020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe1c0UL) ]
        []
        [ X(0, 0x55UL); M(0, 0x5555555555555500UL) ] ]

  /// C6.2.117 LDCLRB, LDCLRAB, LDCLRALB, LDCLRLB
  [<TestMethod>]
  member _.``C6.2.117 LDCLRLB``() =
    check "38621020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe1c0UL) ]
        []
        [ X(0, 0x55UL); M(0, 0x5555555555555500UL) ] ]

  /// C6.2.118 LDCLRH, LDCLRAH, LDCLRALH, LDCLRLH
  [<TestMethod>]
  member _.``C6.2.118 LDCLRAH``() =
    check "78a21020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e0a81UL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8fa0c0UL) ]
        []
        [ X(0, 0x5555UL); M(0, 0x5555555555550000UL) ] ]

  /// C6.2.118 LDCLRH, LDCLRAH, LDCLRALH, LDCLRLH
  [<TestMethod>]
  member _.``C6.2.118 LDCLRALH``() =
    check "78e21020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e0a81UL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8fa0c0UL) ]
        []
        [ X(0, 0x5555UL); M(0, 0x5555555555550000UL) ] ]

  /// C6.2.118 LDCLRH, LDCLRAH, LDCLRALH, LDCLRLH
  [<TestMethod>]
  member _.``C6.2.118 LDCLRH``() =
    check "78221020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e0a81UL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8fa0c0UL) ]
        []
        [ X(0, 0x5555UL); M(0, 0x5555555555550000UL) ] ]

  /// C6.2.118 LDCLRH, LDCLRAH, LDCLRALH, LDCLRLH
  [<TestMethod>]
  member _.``C6.2.118 LDCLRLH``() =
    check "78621020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e0a81UL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8fa0c0UL) ]
        []
        [ X(0, 0x5555UL); M(0, 0x5555555555550000UL) ] ]

  /// C6.2.119 LDCLR, LDCLRA, LDCLRAL, LDCLRL
  [<TestMethod>]
  member _.``C6.2.119 LDCLR``() =
    check "f8221020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL); M(0, 0x3200900000c0a81UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL); M(0, 0x10402000281a0c0UL) ]
        []
        [ X(0, 0x5555555555555555UL); M(0, 0x0UL) ] ]
    check "b8221020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290a000c0a81UL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822b0281a0c0UL) ]
        []
        [ X(0, 0x55555555UL); M(0, 0x5555555500000000UL) ] ]

  /// C6.2.119 LDCLR, LDCLRA, LDCLRAL, LDCLRL
  [<TestMethod>]
  member _.``C6.2.119 LDCLRA``() =
    check "b8a21020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290a000c0a81UL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822b0281a0c0UL) ]
        []
        [ X(0, 0x55555555UL); M(0, 0x5555555500000000UL) ] ]

  /// C6.2.119 LDCLR, LDCLRA, LDCLRAL, LDCLRL
  [<TestMethod>]
  member _.``C6.2.119 LDCLRAL``() =
    check "b8e21020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290a000c0a81UL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822b0281a0c0UL) ]
        []
        [ X(0, 0x55555555UL); M(0, 0x5555555500000000UL) ] ]

  /// C6.2.119 LDCLR, LDCLRA, LDCLRAL, LDCLRL
  [<TestMethod>]
  member _.``C6.2.119 LDCLRL``() =
    check "b8621020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290a000c0a81UL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822b0281a0c0UL) ]
        []
        [ X(0, 0x55555555UL); M(0, 0x5555555500000000UL) ] ]

  /// C6.2.120 LDEORB, LDEORAB, LDEORALB, LDEORLB
  [<TestMethod>]
  member _.``C6.2.120 LDEORAB``() =
    check "38a22020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4adfUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe1cbUL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL); M(0, 0x5555555555555500UL) ] ]

  /// C6.2.120 LDEORB, LDEORAB, LDEORALB, LDEORLB
  [<TestMethod>]
  member _.``C6.2.120 LDEORALB``() =
    check "38e22020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4adfUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe1cbUL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL); M(0, 0x5555555555555500UL) ] ]

  /// C6.2.120 LDEORB, LDEORAB, LDEORALB, LDEORLB
  [<TestMethod>]
  member _.``C6.2.120 LDEORB``() =
    check "38222020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4adfUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe1cbUL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL); M(0, 0x5555555555555500UL) ] ]

  /// C6.2.120 LDEORB, LDEORAB, LDEORALB, LDEORLB
  [<TestMethod>]
  member _.``C6.2.120 LDEORLB``() =
    check "38622020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4adfUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe1cbUL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL); M(0, 0x5555555555555500UL) ] ]

  /// C6.2.121 LDEORH, LDEORAH, LDEORALH, LDEORLH
  [<TestMethod>]
  member _.``C6.2.121 LDEORAH``() =
    check "78a22020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e1fdfUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8fb2cbUL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL); M(0, 0x5555555555550000UL) ] ]

  /// C6.2.121 LDEORH, LDEORAH, LDEORALH, LDEORLH
  [<TestMethod>]
  member _.``C6.2.121 LDEORALH``() =
    check "78e22020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e1fdfUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8fb2cbUL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL); M(0, 0x5555555555550000UL) ] ]

  /// C6.2.121 LDEORH, LDEORAH, LDEORALH, LDEORLH
  [<TestMethod>]
  member _.``C6.2.121 LDEORH``() =
    check "78222020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e1fdfUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8fb2cbUL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL); M(0, 0x5555555555550000UL) ] ]

  /// C6.2.121 LDEORH, LDEORAH, LDEORALH, LDEORLH
  [<TestMethod>]
  member _.``C6.2.121 LDEORLH``() =
    check "78622020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e1fdfUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8fb2cbUL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL); M(0, 0x5555555555550000UL) ] ]

  /// C6.2.122 LDEOR, LDEORA, LDEORAL, LDEORL
  [<TestMethod>]
  member _.``C6.2.122 LDEOR``() =
    check "f8222020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL); M(0, 0x23b38be43a0c1fdfUL) ]
        [ X(0, 0x912f822b1e8fe1e4UL); M(0, 0x9543e94c3f1b2cbUL) ]
        [ M(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x5555555555555555UL); M(0, 0x0UL) ] ]
    check "b8222020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290a3a0c1fdfUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bc3f1b2cbUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL); M(0, 0x5555555500000000UL) ] ]

  /// C6.2.122 LDEOR, LDEORA, LDEORAL, LDEORL
  [<TestMethod>]
  member _.``C6.2.122 LDEORA``() =
    check "b8a22020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290a3a0c1fdfUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bc3f1b2cbUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL); M(0, 0x5555555500000000UL) ] ]

  /// C6.2.122 LDEOR, LDEORA, LDEORAL, LDEORL
  [<TestMethod>]
  member _.``C6.2.122 LDEORAL``() =
    check "b8e22020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290a3a0c1fdfUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bc3f1b2cbUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL); M(0, 0x5555555500000000UL) ] ]

  /// C6.2.122 LDEOR, LDEORA, LDEORAL, LDEORL
  [<TestMethod>]
  member _.``C6.2.122 LDEORL``() =
    check "b8622020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290a3a0c1fdfUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bc3f1b2cbUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL); M(0, 0x5555555500000000UL) ] ]

  /// C6.2.123 LDG
  [<TestMethod>]
  member _.``C6.2.123 LDG``() =
    check "d9600020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x900a2dec89025cc1UL) ]
        [ X(0, 0x905835de1c9756ceUL) ]
        []
        [] ]
    check "d9601020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x900a2dec89025cc1UL) ]
        [ X(0, 0x905835de1c9756ceUL) ]
        []
        [] ]

  /// C6.2.124 LDGM
  [<TestMethod>]
  member _.``C6.2.124 LDGM``() =
    raises BinIR.SideEffect.UndefinedInstruction "d9e00020"

  /// C6.2.125 LDLARB
  [<TestMethod>]
  member _.``C6.2.125 LDLARB``() =
    check "08df7c20" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.126 LDLARH
  [<TestMethod>]
  member _.``C6.2.126 LDLARH``() =
    check "48df7c20" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.127 LDLAR
  [<TestMethod>]
  member _.``C6.2.127 LDLAR``() =
    check "c8df7c20" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL) ]
        []
        [ X(0, 0x5555555555555555UL) ] ]
    check "88df7c20" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.128 LDNP
  [<TestMethod>]
  member _.``C6.2.128 LDNP``() =
    check "28400c22" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0xc13e4a81UL); X(3, 0xdb20290aUL) ]
        [ X(2, 0x1e8fe1e4UL); X(3, 0x912f822bUL) ]
        [ X(2, 0x0UL); X(3, 0x0UL) ]
        [ X(2, 0x55555555UL); X(3, 0x55555555UL) ] ]
    check "28420c22" [ X(1, 0x2007ff0UL) ]
      [ [ X(2, 0xc13e4a81UL); X(3, 0xdb20290aUL) ]
        [ X(2, 0x1e8fe1e4UL); X(3, 0x912f822bUL) ]
        [ X(2, 0x0UL); X(3, 0x0UL) ]
        [ X(2, 0x55555555UL); X(3, 0x55555555UL) ] ]
    check "a8400c22" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0xdb20290ac13e4a81UL); X(3, 0xd80391ffb30d1390UL) ]
        [ X(2, 0x912f822b1e8fe1e4UL); X(3, 0xf8606cc314fb6b96UL) ]
        [ X(2, 0x0UL); X(3, 0x1UL) ]
        [] ]
    check "a8410c22" [ X(1, 0x2007ff0UL) ]
      [ [ X(2, 0xdb20290ac13e4a81UL); X(3, 0xd80391ffb30d1390UL) ]
        [ X(2, 0x912f822b1e8fe1e4UL); X(3, 0xf8606cc314fb6b96UL) ]
        [ X(2, 0x0UL); X(3, 0x1UL) ]
        [] ]
    check "28400420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); X(1, 0xdb20290aUL) ]
        [ X(0, 0x1e8fe1e4UL); X(1, 0x912f822bUL) ]
        [ X(1, 0x0UL) ]
        [ X(0, 0x55555555UL); X(1, 0x55555555UL) ] ]

  /// C6.2.129 LDP
  [<TestMethod>]
  member _.``C6.2.129 LDP``() =
    check "28c20c22" [ X(1, 0x2008000UL) ]
      [ [ X(1, 0x2008010UL); X(2, 0xc13e4a81UL); X(3, 0xdb20290aUL) ]
        [ X(1, 0x2008010UL); X(2, 0x1e8fe1e4UL); X(3, 0x912f822bUL) ]
        [ X(1, 0x2008010UL); X(2, 0x0UL); X(3, 0x0UL) ]
        [ X(1, 0x2008010UL); X(2, 0x55555555UL); X(3, 0x55555555UL) ] ]
    check "a8c10c22" [ X(1, 0x2008000UL) ]
      [ [ X(1, 0x2008010UL)
          X(2, 0xdb20290ac13e4a81UL)
          X(3, 0xd80391ffb30d1390UL) ]
        [ X(1, 0x2008010UL)
          X(2, 0x912f822b1e8fe1e4UL)
          X(3, 0xf8606cc314fb6b96UL) ]
        [ X(1, 0x2008010UL); X(2, 0x0UL); X(3, 0x1UL) ]
        [ X(1, 0x2008010UL) ] ]
    check "29c20c22" [ X(1, 0x2007ff0UL) ]
      [ [ X(1, 0x2008000UL); X(2, 0xc13e4a81UL); X(3, 0xdb20290aUL) ]
        [ X(1, 0x2008000UL); X(2, 0x1e8fe1e4UL); X(3, 0x912f822bUL) ]
        [ X(1, 0x2008000UL); X(2, 0x0UL); X(3, 0x0UL) ]
        [ X(1, 0x2008000UL); X(2, 0x55555555UL); X(3, 0x55555555UL) ] ]
    check "a9c10c22" [ X(1, 0x2007ff0UL) ]
      [ [ X(1, 0x2008000UL)
          X(2, 0xdb20290ac13e4a81UL)
          X(3, 0xd80391ffb30d1390UL) ]
        [ X(1, 0x2008000UL)
          X(2, 0x912f822b1e8fe1e4UL)
          X(3, 0xf8606cc314fb6b96UL) ]
        [ X(1, 0x2008000UL); X(2, 0x0UL); X(3, 0x1UL) ]
        [ X(1, 0x2008000UL) ] ]
    check "29400c22" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0xc13e4a81UL); X(3, 0xdb20290aUL) ]
        [ X(2, 0x1e8fe1e4UL); X(3, 0x912f822bUL) ]
        [ X(2, 0x0UL); X(3, 0x0UL) ]
        [ X(2, 0x55555555UL); X(3, 0x55555555UL) ] ]
    check "29420c22" [ X(1, 0x2007ff0UL) ]
      [ [ X(2, 0xc13e4a81UL); X(3, 0xdb20290aUL) ]
        [ X(2, 0x1e8fe1e4UL); X(3, 0x912f822bUL) ]
        [ X(2, 0x0UL); X(3, 0x0UL) ]
        [ X(2, 0x55555555UL); X(3, 0x55555555UL) ] ]
    check "a9400c22" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0xdb20290ac13e4a81UL); X(3, 0xd80391ffb30d1390UL) ]
        [ X(2, 0x912f822b1e8fe1e4UL); X(3, 0xf8606cc314fb6b96UL) ]
        [ X(2, 0x0UL); X(3, 0x1UL) ]
        [] ]
    check "a9410c22" [ X(1, 0x2007ff0UL) ]
      [ [ X(2, 0xdb20290ac13e4a81UL); X(3, 0xd80391ffb30d1390UL) ]
        [ X(2, 0x912f822b1e8fe1e4UL); X(3, 0xf8606cc314fb6b96UL) ]
        [ X(2, 0x0UL); X(3, 0x1UL) ]
        [] ]
    check "28c00420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.130 LDPSW
  [<TestMethod>]
  member _.``C6.2.130 LDPSW``() =
    check "68c20c22" [ X(1, 0x2008000UL) ]
      [ [ X(1, 0x2008010UL)
          X(2, 0xffffffffc13e4a81UL)
          X(3, 0xffffffffdb20290aUL) ]
        [ X(1, 0x2008010UL); X(2, 0x1e8fe1e4UL); X(3, 0xffffffff912f822bUL) ]
        [ X(1, 0x2008010UL); X(2, 0x0UL); X(3, 0x0UL) ]
        [ X(1, 0x2008010UL); X(2, 0x55555555UL); X(3, 0x55555555UL) ] ]
    check "69c20c22" [ X(1, 0x2007ff0UL) ]
      [ [ X(1, 0x2008000UL)
          X(2, 0xffffffffc13e4a81UL)
          X(3, 0xffffffffdb20290aUL) ]
        [ X(1, 0x2008000UL); X(2, 0x1e8fe1e4UL); X(3, 0xffffffff912f822bUL) ]
        [ X(1, 0x2008000UL); X(2, 0x0UL); X(3, 0x0UL) ]
        [ X(1, 0x2008000UL); X(2, 0x55555555UL); X(3, 0x55555555UL) ] ]
    check "69400c22" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0xffffffffc13e4a81UL); X(3, 0xffffffffdb20290aUL) ]
        [ X(2, 0x1e8fe1e4UL); X(3, 0xffffffff912f822bUL) ]
        [ X(2, 0x0UL); X(3, 0x0UL) ]
        [ X(2, 0x55555555UL); X(3, 0x55555555UL) ] ]
    check "69420c22" [ X(1, 0x2007ff0UL) ]
      [ [ X(2, 0xffffffffc13e4a81UL); X(3, 0xffffffffdb20290aUL) ]
        [ X(2, 0x1e8fe1e4UL); X(3, 0xffffffff912f822bUL) ]
        [ X(2, 0x0UL); X(3, 0x0UL) ]
        [ X(2, 0x55555555UL); X(3, 0x55555555UL) ] ]
    check "68c10c22" [ X(1, 0x2008000UL) ]
      [ [ X(1, 0x2008008UL)
          X(2, 0xffffffffc13e4a81UL)
          X(3, 0xffffffffdb20290aUL) ]
        [ X(1, 0x2008008UL); X(2, 0x1e8fe1e4UL); X(3, 0xffffffff912f822bUL) ]
        [ X(1, 0x2008008UL); X(2, 0x0UL); X(3, 0x0UL) ]
        [ X(1, 0x2008008UL); X(2, 0x55555555UL); X(3, 0x55555555UL) ] ]

  /// C6.2.131 LDR (immediate)
  [<TestMethod>]
  member _.``C6.2.131 LDR``() =
    check "b8410420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); X(1, 0x2008010UL) ]
        [ X(0, 0x1e8fe1e4UL); X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL) ]
        [ X(0, 0x55555555UL); X(1, 0x2008010UL) ] ]
    check "f8410420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL); X(1, 0x2008010UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL); X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL) ]
        [ X(0, 0x5555555555555555UL); X(1, 0x2008010UL) ] ]
    check "b8410c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xc13e4a81UL); X(1, 0x2008000UL) ]
        [ X(0, 0x1e8fe1e4UL); X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL) ]
        [ X(0, 0x55555555UL); X(1, 0x2008000UL) ] ]
    check "f8410c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL); X(1, 0x2008000UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL); X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL) ]
        [ X(0, 0x5555555555555555UL); X(1, 0x2008000UL) ] ]
    check "b9400020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]
    check "b9400820" [ X(1, 0x2007ff8UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]
    check "f9400020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL) ]
        []
        [ X(0, 0x5555555555555555UL) ] ]
    check "f9400420" [ X(1, 0x2007ff8UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL) ]
        []
        [ X(0, 0x5555555555555555UL) ] ]
    check "18000200" [ Window 0x1000040UL ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]
    check "58000200" [ Window 0x1000040UL ]
      [ [ X(0, 0xdb20290ac13e4a81UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL) ]
        []
        [ X(0, 0x5555555555555555UL) ] ]
    check "b8400420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// <summary>
  /// LDRAA authenticates its base with a key the oracle's process draws
  /// at random, so the base must be signed first, and a signed value
  /// cannot be compared. What the manual fixes is checked instead
  /// (C6.2.134): with the window signed as the matching PACDZA signs it,
  /// the load reads the doubleword at the window plus the offset, and the
  /// base keeps the signed pointer, over every input set. The oracle
  /// agrees with the value loaded, and with the pre-indexed forms
  /// writing the authenticated address plus the offset back to the base.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.134 LDRAA``() =
    loadsSigned "dac12be1" "f8200420" 0
    loadsSigned "dac12be1" "f8202420" 2
    loadsSignedBack "dac12be1" "f8200c20" 0
    loadsSignedBack "dac12be1" "f8202c20" 2

  /// <summary>
  /// LDRAB authenticates its base with a key the oracle's process draws
  /// at random, so the base must be signed first, and a signed value
  /// cannot be compared. What the manual fixes is checked instead
  /// (C6.2.134): with the window signed as the matching PACDZB signs it,
  /// the load reads the doubleword at the window plus the offset, and the
  /// base keeps the signed pointer, over every input set. The oracle
  /// agrees with the value loaded, and with the pre-indexed forms
  /// writing the authenticated address plus the offset back to the base.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.134 LDRAB``() =
    loadsSigned "dac12fe1" "f8a00420" 0
    loadsSignedBack "dac12fe1" "f8a02c20" 2

  /// C6.2.135 LDRB (immediate)
  [<TestMethod>]
  member _.``C6.2.135 LDRB``() =
    check "38410420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); X(1, 0x2008010UL) ]
        [ X(0, 0xe4UL); X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL) ]
        [ X(0, 0x55UL); X(1, 0x2008010UL) ] ]
    check "38410c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x81UL); X(1, 0x2008000UL) ]
        [ X(0, 0xe4UL); X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL) ]
        [ X(0, 0x55UL); X(1, 0x2008000UL) ] ]
    check "39400020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "39402020" [ X(1, 0x2007ff8UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "38626820" [ X(1, 0x2008000UL); X(2, 0x1UL) ]
      [ [ X(0, 0x4aUL) ]
        [ X(0, 0xe1UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "38400420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.137 LDRH (immediate)
  [<TestMethod>]
  member _.``C6.2.137 LDRH``() =
    check "78410420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); X(1, 0x2008010UL) ]
        [ X(0, 0xe1e4UL); X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL) ]
        [ X(0, 0x5555UL); X(1, 0x2008010UL) ] ]
    check "78410c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x4a81UL); X(1, 0x2008000UL) ]
        [ X(0, 0xe1e4UL); X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL) ]
        [ X(0, 0x5555UL); X(1, 0x2008000UL) ] ]
    check "79400020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "79401020" [ X(1, 0x2007ff8UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "78400420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.139 LDRSB (immediate)
  [<TestMethod>]
  member _.``C6.2.139 LDRSB``() =
    check "38c10420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffff81UL); X(1, 0x2008010UL) ]
        [ X(0, 0xffffffe4UL); X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL) ]
        [ X(0, 0x55UL); X(1, 0x2008010UL) ] ]
    check "38810420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffffffffffff81UL); X(1, 0x2008010UL) ]
        [ X(0, 0xffffffffffffffe4UL); X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL) ]
        [ X(0, 0x55UL); X(1, 0x2008010UL) ] ]
    check "38c10c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xffffff81UL); X(1, 0x2008000UL) ]
        [ X(0, 0xffffffe4UL); X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL) ]
        [ X(0, 0x55UL); X(1, 0x2008000UL) ] ]
    check "38810c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xffffffffffffff81UL); X(1, 0x2008000UL) ]
        [ X(0, 0xffffffffffffffe4UL); X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL) ]
        [ X(0, 0x55UL); X(1, 0x2008000UL) ] ]
    check "39c00020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffff81UL) ]
        [ X(0, 0xffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "39c02020" [ X(1, 0x2007ff8UL) ]
      [ [ X(0, 0xffffff81UL) ]
        [ X(0, 0xffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "39800020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffffffffffff81UL) ]
        [ X(0, 0xffffffffffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "39802020" [ X(1, 0x2007ff8UL) ]
      [ [ X(0, 0xffffffffffffff81UL) ]
        [ X(0, 0xffffffffffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "38e26820" [ X(1, 0x2008000UL); X(2, 0x1UL) ]
      [ [ X(0, 0x4aUL) ]
        [ X(0, 0xffffffe1UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "38a26820" [ X(1, 0x2008000UL); X(2, 0x1UL) ]
      [ [ X(0, 0x4aUL) ]
        [ X(0, 0xffffffffffffffe1UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "38c00420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffff81UL) ]
        [ X(0, 0xffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.141 LDRSH (immediate)
  [<TestMethod>]
  member _.``C6.2.141 LDRSH``() =
    check "78c10420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); X(1, 0x2008010UL) ]
        [ X(0, 0xffffe1e4UL); X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL) ]
        [ X(0, 0x5555UL); X(1, 0x2008010UL) ] ]
    check "78810420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); X(1, 0x2008010UL) ]
        [ X(0, 0xffffffffffffe1e4UL); X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL) ]
        [ X(0, 0x5555UL); X(1, 0x2008010UL) ] ]
    check "78c10c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x4a81UL); X(1, 0x2008000UL) ]
        [ X(0, 0xffffe1e4UL); X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL) ]
        [ X(0, 0x5555UL); X(1, 0x2008000UL) ] ]
    check "78810c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x4a81UL); X(1, 0x2008000UL) ]
        [ X(0, 0xffffffffffffe1e4UL); X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL) ]
        [ X(0, 0x5555UL); X(1, 0x2008000UL) ] ]
    check "79c00020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "79c01020" [ X(1, 0x2007ff8UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "79800020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffffffffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "79801020" [ X(1, 0x2007ff8UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffffffffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "78c00420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.143 LDRSW (immediate)
  [<TestMethod>]
  member _.``C6.2.143 LDRSW``() =
    check "b8810420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffffffc13e4a81UL); X(1, 0x2008010UL) ]
        [ X(0, 0x1e8fe1e4UL); X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL) ]
        [ X(0, 0x55555555UL); X(1, 0x2008010UL) ] ]
    check "b8810c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xffffffffc13e4a81UL); X(1, 0x2008000UL) ]
        [ X(0, 0x1e8fe1e4UL); X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL) ]
        [ X(0, 0x55555555UL); X(1, 0x2008000UL) ] ]
    check "b9800020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffffffc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]
    check "b9800820" [ X(1, 0x2007ff8UL) ]
      [ [ X(0, 0xffffffffc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]
    check "98000200" [ Window 0x1000040UL ]
      [ [ X(0, 0xffffffffc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]
    check "b8800420" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffffffc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.146 LDSETB, LDSETAB, LDSETALB, LDSETLB
  [<TestMethod>]
  member _.``C6.2.146 LDSETAB``() =
    check "38a23020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4adfUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe1efUL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL) ] ]

  /// C6.2.146 LDSETB, LDSETAB, LDSETALB, LDSETLB
  [<TestMethod>]
  member _.``C6.2.146 LDSETALB``() =
    check "38e23020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4adfUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe1efUL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL) ] ]

  /// C6.2.146 LDSETB, LDSETAB, LDSETALB, LDSETLB
  [<TestMethod>]
  member _.``C6.2.146 LDSETB``() =
    check "38223020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4adfUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe1efUL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL) ] ]

  /// C6.2.146 LDSETB, LDSETAB, LDSETALB, LDSETLB
  [<TestMethod>]
  member _.``C6.2.146 LDSETLB``() =
    check "38623020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4adfUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe1efUL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL) ] ]

  /// C6.2.147 LDSETH, LDSETAH, LDSETALH, LDSETLH
  [<TestMethod>]
  member _.``C6.2.147 LDSETAH``() =
    check "78a23020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e5fdfUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8ff3efUL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL) ] ]

  /// C6.2.147 LDSETH, LDSETAH, LDSETALH, LDSETLH
  [<TestMethod>]
  member _.``C6.2.147 LDSETALH``() =
    check "78e23020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e5fdfUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8ff3efUL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL) ] ]

  /// C6.2.147 LDSETH, LDSETAH, LDSETALH, LDSETLH
  [<TestMethod>]
  member _.``C6.2.147 LDSETH``() =
    check "78223020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e5fdfUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8ff3efUL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL) ] ]

  /// C6.2.147 LDSETH, LDSETAH, LDSETALH, LDSETLH
  [<TestMethod>]
  member _.``C6.2.147 LDSETLH``() =
    check "78623020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e5fdfUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8ff3efUL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL) ] ]

  /// C6.2.148 LDSET, LDSETA, LDSETAL, LDSETL
  [<TestMethod>]
  member _.``C6.2.148 LDSET``() =
    check "f8223020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL); M(0, 0xfbb3abeefb3e5fdfUL) ]
        [ X(0, 0x912f822b1e8fe1e4UL); M(0, 0x997fbebfdffff3efUL) ]
        [ M(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x5555555555555555UL) ] ]
    check "b8223020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290afb3e5fdfUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bdffff3efUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.148 LDSET, LDSETA, LDSETAL, LDSETL
  [<TestMethod>]
  member _.``C6.2.148 LDSETA``() =
    check "b8a23020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290afb3e5fdfUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bdffff3efUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.148 LDSET, LDSETA, LDSETAL, LDSETL
  [<TestMethod>]
  member _.``C6.2.148 LDSETAL``() =
    check "b8e23020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290afb3e5fdfUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bdffff3efUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.148 LDSET, LDSETA, LDSETAL, LDSETL
  [<TestMethod>]
  member _.``C6.2.148 LDSETL``() =
    check "b8623020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290afb3e5fdfUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bdffff3efUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.149 LDSMAXB, LDSMAXAB, LDSMAXALB, LDSMAXLB
  [<TestMethod>]
  member _.``C6.2.149 LDSMAXAB``() =
    check "38a24020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4a5eUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe12fUL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.149 LDSMAXB, LDSMAXAB, LDSMAXALB, LDSMAXLB
  [<TestMethod>]
  member _.``C6.2.149 LDSMAXALB``() =
    check "38e24020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4a5eUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe12fUL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.149 LDSMAXB, LDSMAXAB, LDSMAXALB, LDSMAXLB
  [<TestMethod>]
  member _.``C6.2.149 LDSMAXB``() =
    check "38224020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4a5eUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe12fUL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.149 LDSMAXB, LDSMAXAB, LDSMAXALB, LDSMAXLB
  [<TestMethod>]
  member _.``C6.2.149 LDSMAXLB``() =
    check "38624020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4a5eUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe12fUL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.150 LDSMAXH, LDSMAXAH, LDSMAXALH, LDSMAXLH
  [<TestMethod>]
  member _.``C6.2.150 LDSMAXAH``() =
    check "78a24020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e555eUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8f532fUL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.150 LDSMAXH, LDSMAXAH, LDSMAXALH, LDSMAXLH
  [<TestMethod>]
  member _.``C6.2.150 LDSMAXALH``() =
    check "78e24020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e555eUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8f532fUL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.150 LDSMAXH, LDSMAXAH, LDSMAXALH, LDSMAXLH
  [<TestMethod>]
  member _.``C6.2.150 LDSMAXH``() =
    check "78224020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e555eUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8f532fUL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.150 LDSMAXH, LDSMAXAH, LDSMAXALH, LDSMAXLH
  [<TestMethod>]
  member _.``C6.2.150 LDSMAXLH``() =
    check "78624020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e555eUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8f532fUL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.151 LDSMAX, LDSMAXA, LDSMAXAL, LDSMAXL
  [<TestMethod>]
  member _.``C6.2.151 LDSMAX``() =
    check "f8224020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL); M(0, 0xf893a2eefb32555eUL) ]
        [ X(0, 0x912f822b1e8fe1e4UL); M(0, 0x987bbcbfdd7e532fUL) ]
        []
        [ X(0, 0x5555555555555555UL) ] ]
    check "b8224020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290afb32555eUL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.151 LDSMAX, LDSMAXA, LDSMAXAL, LDSMAXL
  [<TestMethod>]
  member _.``C6.2.151 LDSMAXA``() =
    check "b8a24020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290afb32555eUL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.151 LDSMAX, LDSMAXA, LDSMAXAL, LDSMAXL
  [<TestMethod>]
  member _.``C6.2.151 LDSMAXAL``() =
    check "b8e24020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290afb32555eUL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.151 LDSMAX, LDSMAXA, LDSMAXAL, LDSMAXL
  [<TestMethod>]
  member _.``C6.2.151 LDSMAXL``() =
    check "b8624020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290afb32555eUL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.152 LDSMINB, LDSMINAB, LDSMINALB, LDSMINLB
  [<TestMethod>]
  member _.``C6.2.152 LDSMINAB``() =
    check "38a25020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL) ] ]

  /// C6.2.152 LDSMINB, LDSMINAB, LDSMINALB, LDSMINLB
  [<TestMethod>]
  member _.``C6.2.152 LDSMINALB``() =
    check "38e25020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL) ] ]

  /// C6.2.152 LDSMINB, LDSMINAB, LDSMINALB, LDSMINLB
  [<TestMethod>]
  member _.``C6.2.152 LDSMINB``() =
    check "38225020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL) ] ]

  /// C6.2.152 LDSMINB, LDSMINAB, LDSMINALB, LDSMINLB
  [<TestMethod>]
  member _.``C6.2.152 LDSMINLB``() =
    check "38625020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL) ] ]

  /// C6.2.153 LDSMINH, LDSMINAH, LDSMINALH, LDSMINLH
  [<TestMethod>]
  member _.``C6.2.153 LDSMINAH``() =
    check "78a25020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL) ] ]

  /// C6.2.153 LDSMINH, LDSMINAH, LDSMINALH, LDSMINLH
  [<TestMethod>]
  member _.``C6.2.153 LDSMINALH``() =
    check "78e25020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL) ] ]

  /// C6.2.153 LDSMINH, LDSMINAH, LDSMINALH, LDSMINLH
  [<TestMethod>]
  member _.``C6.2.153 LDSMINH``() =
    check "78225020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL) ] ]

  /// C6.2.153 LDSMINH, LDSMINAH, LDSMINALH, LDSMINLH
  [<TestMethod>]
  member _.``C6.2.153 LDSMINLH``() =
    check "78625020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL) ] ]

  /// C6.2.154 LDSMIN, LDSMINA, LDSMINAL, LDSMINL
  [<TestMethod>]
  member _.``C6.2.154 LDSMIN``() =
    check "f8225020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL) ]
        [ M(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x5555555555555555UL) ] ]
    check "b8225020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bdd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.154 LDSMIN, LDSMINA, LDSMINAL, LDSMINL
  [<TestMethod>]
  member _.``C6.2.154 LDSMINA``() =
    check "b8a25020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bdd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.154 LDSMIN, LDSMINA, LDSMINAL, LDSMINL
  [<TestMethod>]
  member _.``C6.2.154 LDSMINAL``() =
    check "b8e25020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bdd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.154 LDSMIN, LDSMINA, LDSMINAL, LDSMINL
  [<TestMethod>]
  member _.``C6.2.154 LDSMINL``() =
    check "b8625020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bdd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.155 LDTR
  [<TestMethod>]
  member _.``C6.2.155 LDTR``() =
    check "b8410820" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]
    check "f8400820" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL) ]
        []
        [ X(0, 0x5555555555555555UL) ] ]
    check "f8410820" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL) ]
        []
        [ X(0, 0x5555555555555555UL) ] ]
    check "b8400820" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.156 LDTRB
  [<TestMethod>]
  member _.``C6.2.156 LDTRB``() =
    check "38410820" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "38400820" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.157 LDTRH
  [<TestMethod>]
  member _.``C6.2.157 LDTRH``() =
    check "78410820" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "78400820" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.158 LDTRSB
  [<TestMethod>]
  member _.``C6.2.158 LDTRSB``() =
    check "38c10820" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xffffff81UL) ]
        [ X(0, 0xffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "38800820" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffffffffffff81UL) ]
        [ X(0, 0xffffffffffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "38810820" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xffffffffffffff81UL) ]
        [ X(0, 0xffffffffffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "38c00820" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffff81UL) ]
        [ X(0, 0xffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.159 LDTRSH
  [<TestMethod>]
  member _.``C6.2.159 LDTRSH``() =
    check "78c10820" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "78800820" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffffffffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "78810820" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffffffffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "78c00820" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.160 LDTRSW
  [<TestMethod>]
  member _.``C6.2.160 LDTRSW``() =
    check "b8810820" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xffffffffc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]
    check "b8800820" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffffffc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.161 LDUMAXB, LDUMAXAB, LDUMAXALB, LDUMAXLB
  [<TestMethod>]
  member _.``C6.2.161 LDUMAXAB``() =
    check "38a26020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL) ] ]

  /// C6.2.161 LDUMAXB, LDUMAXAB, LDUMAXALB, LDUMAXLB
  [<TestMethod>]
  member _.``C6.2.161 LDUMAXALB``() =
    check "38e26020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL) ] ]

  /// C6.2.161 LDUMAXB, LDUMAXAB, LDUMAXALB, LDUMAXLB
  [<TestMethod>]
  member _.``C6.2.161 LDUMAXB``() =
    check "38226020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL) ] ]

  /// C6.2.161 LDUMAXB, LDUMAXAB, LDUMAXALB, LDUMAXLB
  [<TestMethod>]
  member _.``C6.2.161 LDUMAXLB``() =
    check "38626020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL) ] ]

  /// C6.2.162 LDUMAXH, LDUMAXAH, LDUMAXALH, LDUMAXLH
  [<TestMethod>]
  member _.``C6.2.162 LDUMAXAH``() =
    check "78a26020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e555eUL) ]
        [ X(0, 0xe1e4UL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL) ] ]

  /// C6.2.162 LDUMAXH, LDUMAXAH, LDUMAXALH, LDUMAXLH
  [<TestMethod>]
  member _.``C6.2.162 LDUMAXALH``() =
    check "78e26020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e555eUL) ]
        [ X(0, 0xe1e4UL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL) ] ]

  /// C6.2.162 LDUMAXH, LDUMAXAH, LDUMAXALH, LDUMAXLH
  [<TestMethod>]
  member _.``C6.2.162 LDUMAXH``() =
    check "78226020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e555eUL) ]
        [ X(0, 0xe1e4UL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL) ] ]

  /// C6.2.162 LDUMAXH, LDUMAXAH, LDUMAXALH, LDUMAXLH
  [<TestMethod>]
  member _.``C6.2.162 LDUMAXLH``() =
    check "78626020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e555eUL) ]
        [ X(0, 0xe1e4UL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL) ] ]

  /// C6.2.163 LDUMAX, LDUMAXA, LDUMAXAL, LDUMAXL
  [<TestMethod>]
  member _.``C6.2.163 LDUMAX``() =
    check "f8226020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL); M(0, 0xf893a2eefb32555eUL) ]
        [ X(0, 0x912f822b1e8fe1e4UL); M(0, 0x987bbcbfdd7e532fUL) ]
        [ M(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x5555555555555555UL) ] ]
    check "b8226020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290afb32555eUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bdd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.163 LDUMAX, LDUMAXA, LDUMAXAL, LDUMAXL
  [<TestMethod>]
  member _.``C6.2.163 LDUMAXA``() =
    check "b8a26020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290afb32555eUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bdd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.163 LDUMAX, LDUMAXA, LDUMAXAL, LDUMAXL
  [<TestMethod>]
  member _.``C6.2.163 LDUMAXAL``() =
    check "b8e26020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290afb32555eUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bdd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.163 LDUMAX, LDUMAXA, LDUMAXAL, LDUMAXL
  [<TestMethod>]
  member _.``C6.2.163 LDUMAXL``() =
    check "b8626020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290afb32555eUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bdd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.164 LDUMINB, LDUMINAB, LDUMINALB, LDUMINLB
  [<TestMethod>]
  member _.``C6.2.164 LDUMINAB``() =
    check "38a27020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4a5eUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe12fUL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.164 LDUMINB, LDUMINAB, LDUMINALB, LDUMINLB
  [<TestMethod>]
  member _.``C6.2.164 LDUMINALB``() =
    check "38e27020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4a5eUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe12fUL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.164 LDUMINB, LDUMINAB, LDUMINALB, LDUMINLB
  [<TestMethod>]
  member _.``C6.2.164 LDUMINB``() =
    check "38227020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4a5eUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe12fUL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.164 LDUMINB, LDUMINAB, LDUMINALB, LDUMINLB
  [<TestMethod>]
  member _.``C6.2.164 LDUMINLB``() =
    check "38627020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4a5eUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe12fUL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.165 LDUMINH, LDUMINAH, LDUMINALH, LDUMINLH
  [<TestMethod>]
  member _.``C6.2.165 LDUMINAH``() =
    check "78a27020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8f532fUL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.165 LDUMINH, LDUMINAH, LDUMINALH, LDUMINLH
  [<TestMethod>]
  member _.``C6.2.165 LDUMINALH``() =
    check "78e27020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8f532fUL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.165 LDUMINH, LDUMINAH, LDUMINALH, LDUMINLH
  [<TestMethod>]
  member _.``C6.2.165 LDUMINH``() =
    check "78227020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8f532fUL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.165 LDUMINH, LDUMINAH, LDUMINALH, LDUMINLH
  [<TestMethod>]
  member _.``C6.2.165 LDUMINLH``() =
    check "78627020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8f532fUL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.166 LDUMIN, LDUMINA, LDUMINAL, LDUMINL
  [<TestMethod>]
  member _.``C6.2.166 LDUMIN``() =
    check "f8227020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL) ]
        []
        [ X(0, 0x5555555555555555UL) ] ]
    check "b8227020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.166 LDUMIN, LDUMINA, LDUMINAL, LDUMINL
  [<TestMethod>]
  member _.``C6.2.166 LDUMINA``() =
    check "b8a27020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.166 LDUMIN, LDUMINA, LDUMINAL, LDUMINL
  [<TestMethod>]
  member _.``C6.2.166 LDUMINAL``() =
    check "b8e27020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.166 LDUMIN, LDUMINA, LDUMINAL, LDUMINL
  [<TestMethod>]
  member _.``C6.2.166 LDUMINL``() =
    check "b8627020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.167 LDUR
  [<TestMethod>]
  member _.``C6.2.167 LDUR``() =
    check "b8410020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]
    check "f8400020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL) ]
        []
        [ X(0, 0x5555555555555555UL) ] ]
    check "f8410020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL) ]
        [ X(0, 0x912f822b1e8fe1e4UL) ]
        []
        [ X(0, 0x5555555555555555UL) ] ]
    check "b8400020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.168 LDURB
  [<TestMethod>]
  member _.``C6.2.168 LDURB``() =
    check "38410020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "38400020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.169 LDURH
  [<TestMethod>]
  member _.``C6.2.169 LDURH``() =
    check "78410020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "78400020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.170 LDURSB
  [<TestMethod>]
  member _.``C6.2.170 LDURSB``() =
    check "38c10020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xffffff81UL) ]
        [ X(0, 0xffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "38800020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffffffffffff81UL) ]
        [ X(0, 0xffffffffffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "38810020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xffffffffffffff81UL) ]
        [ X(0, 0xffffffffffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]
    check "38c00020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffff81UL) ]
        [ X(0, 0xffffffe4UL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.171 LDURSH
  [<TestMethod>]
  member _.``C6.2.171 LDURSH``() =
    check "78c10020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "78800020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffffffffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "78810020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffffffffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]
    check "78c00020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xffffe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.172 LDURSW
  [<TestMethod>]
  member _.``C6.2.172 LDURSW``() =
    check "b8810020" [ X(1, 0x2007ff0UL) ]
      [ [ X(0, 0xffffffffc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]
    check "b8800020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xffffffffc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.173 LDXP
  [<TestMethod>]
  member _.``C6.2.173 LDXP``() =
    check "887f0022" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290aUL); X(2, 0xc13e4a81UL) ]
        [ X(0, 0x912f822bUL); X(2, 0x1e8fe1e4UL) ]
        [ X(2, 0x0UL) ]
        [ X(0, 0x55555555UL); X(2, 0x55555555UL) ] ]

  /// C6.2.174 LDXR
  [<TestMethod>]
  member _.``C6.2.174 LDXR``() =
    check "885f7c20" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL) ]
        [ X(0, 0x1e8fe1e4UL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.175 LDXRB
  [<TestMethod>]
  member _.``C6.2.175 LDXRB``() =
    check "085f7c20" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL) ]
        [ X(0, 0xe4UL) ]
        []
        [ X(0, 0x55UL) ] ]

  /// C6.2.176 LDXRH
  [<TestMethod>]
  member _.``C6.2.176 LDXRH``() =
    check "485f7c20" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL) ]
        [ X(0, 0xe1e4UL) ]
        []
        [ X(0, 0x5555UL) ] ]

  /// C6.2.177 LSL (register)
  [<TestMethod>]
  member _.``C6.2.177 LSL``() =
    check "1ac22020" []
      [ [ X(0, 0xc0000000UL) ]
        [ X(0, 0xf210000UL) ]
        [ X(0, 0x80000000UL) ]
        [ X(0, 0x0UL) ] ]
    check "531f7820" []
      [ [ X(0, 0xcb1dd8ceUL) ]
        [ X(0, 0x17f83c84UL) ]
        [ X(0, 0x2UL) ]
        [ X(0, 0x0UL) ] ]
    check "d37ff820" []
      [ [ X(0, 0x7dd71b42cb1dd8ceUL) ]
        [ X(0, 0x7f908c2017f83c84UL) ]
        [ X(0, 0x2UL) ]
        [ X(0, 0x200000000UL) ] ]
    check "9ac22020" []
      [ [ X(0, 0x5963bb19c0000000UL) ]
        [ X(0, 0xf21000000000000UL) ]
        [ X(0, 0x8000000000000000UL) ]
        [ X(0, 0x20000000000000UL) ] ]
    check "d3430820" []
      [ [ X(0, 0xe000000000000000UL) ]
        [ X(0, 0x4000000000000000UL) ]
        [ X(0, 0x2000000000000000UL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.179 LSLV
  [<TestMethod>]
  member _.``C6.2.179 LSLV``() =
    check "1ac22020" []
      [ [ X(0, 0xc0000000UL) ]
        [ X(0, 0xf210000UL) ]
        [ X(0, 0x80000000UL) ]
        [ X(0, 0x0UL) ] ]
    check "9ac22020" []
      [ [ X(0, 0x5963bb19c0000000UL) ]
        [ X(0, 0xf21000000000000UL) ]
        [ X(0, 0x8000000000000000UL) ]
        [ X(0, 0x20000000000000UL) ] ]

  /// C6.2.180 LSR (register)
  [<TestMethod>]
  member _.``C6.2.180 LSR``() =
    check "1ac22420" []
      [ [ X(0, 0x1UL) ]
        [ X(0, 0x17f8UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "53017c20" []
      [ [ X(0, 0x32c77633UL) ]
        [ X(0, 0x5fe0f21UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "d341fc20" []
      [ [ X(0, 0x5f75c6d0b2c77633UL) ]
        [ X(0, 0x5fe4230805fe0f21UL) ]
        []
        [ X(0, 0x80000000UL) ] ]
    check "9ac22420" []
      [ [ X(0, 0x2fbae3685UL) ]
        [ X(0, 0x17f90UL) ]
        []
        [ X(0, 0x800UL) ] ]

  /// C6.2.182 LSRV
  [<TestMethod>]
  member _.``C6.2.182 LSRV``() =
    check "1ac22420" []
      [ [ X(0, 0x1UL) ]
        [ X(0, 0x17f8UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "9ac22420" []
      [ [ X(0, 0x2fbae3685UL) ]
        [ X(0, 0x17f90UL) ]
        []
        [ X(0, 0x800UL) ] ]

  /// C6.2.183 MADD
  [<TestMethod>]
  member _.``C6.2.183 MADD``() =
    check "1b020c20" []
      [ [ X(0, 0xd659c9ddUL) ]
        [ X(0, 0xcf7cea82UL) ]
        [ X(0, 0xffffffffUL) ]
        [ X(0, 0xaaaaaaaaUL) ] ]
    check "9b020c20" []
      [ [ X(0, 0xdfd0c01d659c9ddUL) ]
        [ X(0, 0xfb62ac3cf7cea82UL) ]
        [ X(0, 0x7fffffffffffffffUL) ]
        [ X(0, 0xffffffffaaaaaaaaUL) ] ]

  /// C6.2.184 MNEG
  [<TestMethod>]
  member _.``C6.2.184 MNEG``() =
    check "1b02fc20" []
      [ [ X(0, 0x17e8ff2eUL) ]
        [ X(0, 0x306b0be2UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]
    check "9b02fc20" []
      [ [ X(0, 0x63c47a8f17e8ff2eUL) ]
        [ X(0, 0xb43c57b7306b0be2UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0xaaaaaaab00000000UL) ] ]

  /// C6.2.185 MOV (to/from SP)
  [<TestMethod>]
  member _.``C6.2.185 MOV``() =
    check "2a0103e0" []
      [ [ X(0, 0x658eec67UL) ]
        [ X(0, 0xbfc1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]
    check "52800200" []
      [ [ X(0, 0x10UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0x10UL) ] ]
    check "d2800200" []
      [ [ X(0, 0x10UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0x10UL) ] ]
    check "2a0203e0" []
      [ [ X(0, 0xfb32555eUL) ]
        [ X(0, 0xdd7e532fUL) ]
        [ X(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]
    check "aa0203e0" []
      [ [ X(0, 0xf893a2eefb32555eUL) ]
        [ X(0, 0x987bbcbfdd7e532fUL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x5555555555555555UL) ] ]
    check "12800200" []
      [ [ X(0, 0xffffffefUL) ]
        [ X(0, 0xffffffefUL) ]
        [ X(0, 0xffffffefUL) ]
        [ X(0, 0xffffffefUL) ] ]
    check "92800200" []
      [ [ X(0, 0xffffffffffffffefUL) ]
        [ X(0, 0xffffffffffffffefUL) ]
        [ X(0, 0xffffffffffffffefUL) ]
        [ X(0, 0xffffffffffffffefUL) ] ]
    check "0ea11c20" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x0UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4ea11c20" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x40d6824e2ef3fc17UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0xe2311b535f1fb0a9UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x7fa000007fc00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fb999999999999aUL) ] ]
    check "0e0c3c20" []
      [ [ X(0, 0x70616f2fUL) ]
        [ X(0, 0x57c88325UL) ]
        [ X(0, 0x7f800000UL) ]
        [ X(0, 0x40080000UL) ] ]
    check "4e183c20" []
      [ [ X(0, 0x40d6824e2ef3fc17UL) ]
        [ X(0, 0xe2311b535f1fb0a9UL) ]
        [ X(0, 0x7fa000007fc00000UL) ]
        [ X(0, 0x3fb999999999999aUL) ] ]
    check "4e081c20" []
      [ [ Q(0, 0xbeeb8da1658eec67UL, 0x65ace2685a072c6dUL) ]
        [ Q(0, 0xbfc846100bfc1e42UL, 0x444bcaba22bb690fUL) ]
        [ Q(0, 0x1UL, 0x3dcccccd40400000UL) ]
        [ Q(0, 0x100000000UL, 0xbff8000000000000UL) ] ]
    check "4e083c20" []
      [ [ X(0, 0x70616f2f48dce01cUL) ]
        [ X(0, 0x57c883255f0f9e24UL) ]
        [ X(0, 0x7f80000080000000UL) ]
        [ X(0, 0x4008000000000000UL) ] ]
    check "aa0203f0" []
      [ [ X(16, 0xf893a2eefb32555eUL) ]
        [ X(16, 0x987bbcbfdd7e532fUL) ]
        [ X(16, 0xffffffffffffffffUL) ]
        [ X(16, 0x5555555555555555UL) ] ]
    check "aa1103e0" []
      [ [ X(0, 0xd0bad0da572baaf1UL) ]
        [ X(0, 0x5d3e47ecad6ef3d4UL) ]
        [ X(0, 0x2UL) ]
        [ X(0, 0x40UL) ] ]
    check "aa1e03e0" []
      [ [ X(0, 0x990cd70b12c5d084UL) ]
        [ X(0, 0xddfcd92ab490c639UL) ]
        [ X(0, 0x8000000080000000UL) ]
        [ X(0, 0x7fffffffUL) ] ]
    check "aa0003fe" []
      [ [ X(30, 0x910a2dec89025cc1UL) ]
        [ X(30, 0x975835de1c9756ceUL) ]
        [ X(30, 0x0UL) ]
        [ X(30, 0xffffffffUL) ] ]
    check "aa0103e0" []
      [ [ X(0, 0xbeeb8da1658eec67UL) ]
        [ X(0, 0xbfc846100bfc1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x100000000UL) ] ]
    check "92800000" []
      [ [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0xffffffffffffffffUL) ] ]
    check "d2800000" []
      [ [ X(0, 0x0UL) ]
        [ X(0, 0x0UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "d2a24680" []
      [ [ X(0, 0x12340000UL) ]
        [ X(0, 0x12340000UL) ]
        [ X(0, 0x12340000UL) ]
        [ X(0, 0x12340000UL) ] ]
    check "52900000" []
      [ [ X(0, 0x8000UL) ]
        [ X(0, 0x8000UL) ]
        [ X(0, 0x8000UL) ]
        [ X(0, 0x8000UL) ] ]
    check "92c24680" []
      [ [ X(0, 0xffffedcbffffffffUL) ]
        [ X(0, 0xffffedcbffffffffUL) ]
        [ X(0, 0xffffedcbffffffffUL) ]
        [ X(0, 0xffffedcbffffffffUL) ] ]
    check "128000a0" []
      [ [ X(0, 0xfffffffaUL) ]
        [ X(0, 0xfffffffaUL) ]
        [ X(0, 0xfffffffaUL) ]
        [ X(0, 0xfffffffaUL) ] ]

  /// C6.2.190 MOVK
  [<TestMethod>]
  member _.``C6.2.190 MOVK``() =
    check "72800200" []
      [ [ X(0, 0x89020010UL) ]
        [ X(0, 0x1c970010UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0xffff0010UL) ] ]
    check "f2800200" []
      [ [ X(0, 0x910a2dec89020010UL) ]
        [ X(0, 0x975835de1c970010UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0xffff0010UL) ] ]
    check "f2800000" []
      [ [ X(0, 0x910a2dec89020000UL) ]
        [ X(0, 0x975835de1c970000UL) ]
        []
        [ X(0, 0xffff0000UL) ] ]

  /// C6.2.191 MOVN
  [<TestMethod>]
  member _.``C6.2.191 MOVN``() =
    check "12800200" []
      [ [ X(0, 0xffffffefUL) ]
        [ X(0, 0xffffffefUL) ]
        [ X(0, 0xffffffefUL) ]
        [ X(0, 0xffffffefUL) ] ]
    check "92800200" []
      [ [ X(0, 0xffffffffffffffefUL) ]
        [ X(0, 0xffffffffffffffefUL) ]
        [ X(0, 0xffffffffffffffefUL) ]
        [ X(0, 0xffffffffffffffefUL) ] ]
    check "92800000" []
      [ [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0xffffffffffffffffUL) ] ]
    check "92c24680" []
      [ [ X(0, 0xffffedcbffffffffUL) ]
        [ X(0, 0xffffedcbffffffffUL) ]
        [ X(0, 0xffffedcbffffffffUL) ]
        [ X(0, 0xffffedcbffffffffUL) ] ]
    check "128000a0" []
      [ [ X(0, 0xfffffffaUL) ]
        [ X(0, 0xfffffffaUL) ]
        [ X(0, 0xfffffffaUL) ]
        [ X(0, 0xfffffffaUL) ] ]

  /// C6.2.192 MOVZ
  [<TestMethod>]
  member _.``C6.2.192 MOVZ``() =
    check "52800200" []
      [ [ X(0, 0x10UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0x10UL) ] ]
    check "d2800200" []
      [ [ X(0, 0x10UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0x10UL) ] ]
    check "d2800000" []
      [ [ X(0, 0x0UL) ]
        [ X(0, 0x0UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "d2a24680" []
      [ [ X(0, 0x12340000UL) ]
        [ X(0, 0x12340000UL) ]
        [ X(0, 0x12340000UL) ]
        [ X(0, 0x12340000UL) ] ]
    check "52900000" []
      [ [ X(0, 0x8000UL) ]
        [ X(0, 0x8000UL) ]
        [ X(0, 0x8000UL) ]
        [ X(0, 0x8000UL) ] ]

  /// C6.2.193 MRS
  [<TestMethod>]
  member _.``C6.2.193 MRS``() =
    check "d53b4200" []
      [ [ X(0, 0x10000000UL) ]
        [ X(0, 0x50000000UL) ]
        [ X(0, 0x60000000UL) ]
        [ X(0, 0x90000000UL) ] ]
    check "d53b4420" []
      [ [ X(0, 0x0UL) ]
        [ X(0, 0x0UL) ]
        []
        [ X(0, 0x0UL) ] ]

  /// C6.2.194 MSR (immediate)
  [<TestMethod>]
  member _.``C6.2.194 MSR``() =
    check "d51b4200" []
      [ [ Nzcv 0x80000000UL ]
        [ Nzcv 0x10000000UL ]
        [ Nzcv 0x0UL ]
        [ Nzcv 0xf0000000UL ] ]
    check "d503415f" [] [ []; []; []; [] ]
    check "d51b4420" []
      [ [ Fpsr 0x88000081UL ]
        [ Fpsr 0x1800008eUL ]
        []
        [ Fpsr 0xf800009fUL ] ]

  /// C6.2.196 MSUB
  [<TestMethod>]
  member _.``C6.2.196 MSUB``() =
    check "1b028c20" []
      [ [ X(0, 0x62bc839UL) ]
        [ X(0, 0x30530246UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0xaaaaaaaaUL) ] ]
    check "9b028c20" []
      [ [ X(0, 0xd5860120062bc839UL) ]
        [ X(0, 0x782eda3230530246UL) ]
        [ X(0, 0x8000000000000001UL) ]
        [ X(0, 0x55555555aaaaaaaaUL) ] ]

  /// C6.2.197 MUL
  [<TestMethod>]
  member _.``C6.2.197 MUL``() =
    check "1b027c20" []
      [ [ X(0, 0xe81700d2UL) ]
        [ X(0, 0xcf94f41eUL) ]
        [ X(0, 0xffffffffUL) ]
        [ X(0, 0x0UL) ] ]
    check "0f528020" []
      [ [ Q(0, 0x163e1aa23248c3c8UL, 0x0UL) ]
        [ Q(0, 0x5a803b10e3304140UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "4f528020" []
      [ [ Q(0, 0x163e1aa23248c3c8UL, 0x38547d64371ad8d2UL) ]
        [ Q(0, 0x5a803b10e3304140UL, 0x60d0be7080305a50UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "0fa28020" []
      [ [ Q(0, 0xd6ed363e72e2cbb8UL, 0x0UL) ]
        [ Q(0, 0xce1948c4a627d850UL, 0x0UL) ]
        [ Q(0, 0x8080000080000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "4fa28020" []
      [ [ Q(0, 0xd6ed363e72e2cbb8UL, 0xb60b525ccae59d0eUL) ]
        [ Q(0, 0xce1948c4a627d850UL, 0x8f93259c48e29894UL) ]
        [ Q(0, 0x8080000080000000UL, 0x8060000080400000UL) ]
        [ Q(0, 0x0UL, 0x8000000000000000UL) ] ]
    check "0e229c20" []
      [ [ Q(0, 0x10def23e30482050UL, 0x0UL) ]
        [ Q(0, 0x3f2804c4773066acUL, 0x0UL) ]
        [ Q(0, 0x8080000000000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "4e229c20" []
      [ [ Q(0, 0x10def23e30482050UL, 0xc07404b8e4318003UL) ]
        [ Q(0, 0x3f2804c4773066acUL, 0xae606e0e2047409cUL) ]
        [ Q(0, 0x8080000000000000UL, 0x1400000UL) ]
        [ Q(0, 0x0UL, 0x4170000000000000UL) ] ]
    check "0e629c20" []
      [ [ Q(0, 0x82de363e32486550UL, 0x0UL) ]
        [ Q(0, 0xef2848c4e3306bacUL, 0x0UL) ]
        [ Q(0, 0x4080000000000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "4e629c20" []
      [ [ Q(0, 0x82de363e32486550UL, 0xd87438b8fb316203UL) ]
        [ Q(0, 0xef2848c4e3306bacUL, 0x69604d0ec147639cUL) ]
        [ Q(0, 0x4080000000000000UL, 0xd0000000a0400000UL) ]
        [ Q(0, 0x0UL, 0x8470000000000000UL) ] ]
    check "0ea29c20" []
      [ [ Q(0, 0xd6ed363e315e6550UL, 0x0UL) ]
        [ Q(0, 0xce1948c447926bacUL, 0x0UL) ]
        [ Q(0, 0x8080000080000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "4ea29c20" []
      [ [ Q(0, 0xd6ed363e315e6550UL, 0xaa0338b8b8d16203UL) ]
        [ Q(0, 0xce1948c447926bacUL, 0x36904d0e3a55639cUL) ]
        [ Q(0, 0x8080000080000000UL, 0x80400000UL) ]
        [ Q(0, 0x0UL, 0xe670000000000000UL) ] ]
    check "9b027c20" []
      [ [ X(0, 0x9c3b8570e81700d2UL) ]
        [ X(0, 0x4bc3a848cf94f41eUL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x5555555500000000UL) ] ]

  /// C6.2.198 MVN
  [<TestMethod>]
  member _.``C6.2.198 MVN``() =
    check "6e205820" []
      [ [ Q(0, 0x8f9e90d0b7231fe3UL, 0xbf297db1d10c03e8UL) ]
        [ Q(0, 0xa8377cdaa0f061dbUL, 0x1dcee4aca0e04f56UL) ]
        [ Q(0, 0x807fffff7fffffffUL, 0x805fffff803fffffUL) ]
        [ Q(0, 0xbff7ffffffffffffUL, 0xc046666666666665UL) ] ]
    check "2a2203e0" []
      [ [ X(0, 0x4cdaaa1UL) ]
        [ X(0, 0x2281acd0UL) ]
        []
        [ X(0, 0xaaaaaaaaUL) ] ]
    check "2e205820" []
      [ [ Q(0, 0x8f9e90d0b7231fe3UL, 0x0UL) ]
        [ Q(0, 0xa8377cdaa0f061dbUL, 0x0UL) ]
        [ Q(0, 0x807fffff7fffffffUL, 0x0UL) ]
        [ Q(0, 0xbff7ffffffffffffUL, 0x0UL) ] ]
    check "aa2203e0" []
      [ [ X(0, 0x76c5d1104cdaaa1UL) ]
        [ X(0, 0x678443402281acd0UL) ]
        []
        [ X(0, 0xaaaaaaaaaaaaaaaaUL) ] ]

  /// C6.2.199 NEG (shifted register)
  [<TestMethod>]
  member _.``C6.2.199 NEG``() =
    check "4b0203e0" []
      [ [ X(0, 0x4cdaaa2UL) ]
        [ X(0, 0x2281acd1UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0xaaaaaaabUL) ] ]
    check "2e20b820" []
      [ [ Q(0, 0x909f91d1b82420e4UL, 0x0UL) ]
        [ Q(0, 0xa9387ddba1f162dcUL, 0x0UL) ]
        [ Q(0, 0x8180000080000000UL, 0x0UL) ]
        [ Q(0, 0xc0f8000000000000UL, 0x0UL) ] ]
    check "6e20b820" []
      [ [ Q(0, 0x909f91d1b82420e4UL, 0xc02a7eb2d20d04e9UL) ]
        [ Q(0, 0xa9387ddba1f162dcUL, 0x1ecfe5ada1e15057UL) ]
        [ Q(0, 0x8180000080000000UL, 0x8160000081400000UL) ]
        [ Q(0, 0xc0f8000000000000UL, 0xc147676767676766UL) ] ]
    check "2e60b820" []
      [ [ Q(0, 0x8f9f90d1b7241fe4UL, 0x0UL) ]
        [ Q(0, 0xa8387cdba0f161dcUL, 0x0UL) ]
        [ Q(0, 0x8080000080000000UL, 0x0UL) ]
        [ Q(0, 0xbff8000000000000UL, 0x0UL) ] ]
    check "6e60b820" []
      [ [ Q(0, 0x8f9f90d1b7241fe4UL, 0xbf2a7db2d10d03e9UL) ]
        [ Q(0, 0xa8387cdba0f161dcUL, 0x1dcfe4ada0e14f57UL) ]
        [ Q(0, 0x8080000080000000UL, 0x8060000080400000UL) ]
        [ Q(0, 0xbff8000000000000UL, 0xc047666766676666UL) ] ]
    check "2ea0b820" []
      [ [ Q(0, 0x8f9e90d1b7231fe4UL, 0x0UL) ]
        [ Q(0, 0xa8377cdba0f061dcUL, 0x0UL) ]
        [ Q(0, 0x8080000080000000UL, 0x0UL) ]
        [ Q(0, 0xbff8000000000000UL, 0x0UL) ] ]
    check "6ea0b820" []
      [ [ Q(0, 0x8f9e90d1b7231fe4UL, 0xbf297db2d10c03e9UL) ]
        [ Q(0, 0xa8377cdba0f061dcUL, 0x1dcee4ada0e04f57UL) ]
        [ Q(0, 0x8080000080000000UL, 0x8060000080400000UL) ]
        [ Q(0, 0xbff8000000000000UL, 0xc046666766666666UL) ] ]
    check "6ee0b820" []
      [ [ Q(0, 0x8f9e90d0b7231fe4UL, 0xbf297db1d10c03e9UL) ]
        [ Q(0, 0xa8377cdaa0f061dcUL, 0x1dcee4aca0e04f57UL) ]
        [ Q(0, 0x807fffff80000000UL, 0x805fffff80400000UL) ]
        [ Q(0, 0xbff8000000000000UL, 0xc046666666666666UL) ] ]
    check "cb0203e0" []
      [ [ X(0, 0x76c5d1104cdaaa2UL) ]
        [ X(0, 0x678443402281acd1UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0xaaaaaaaaaaaaaaabUL) ] ]

  /// C6.2.200 NEGS
  [<TestMethod>]
  member _.``C6.2.200 NEGS``() =
    check "6b0203e0" []
      [ [ X(0, 0x4cdaaa2UL); Nzcv 0x0UL ]
        [ X(0, 0x2281acd1UL); Nzcv 0x0UL ]
        [ X(0, 0x1UL); Nzcv 0x0UL ]
        [ X(0, 0xaaaaaaabUL); Nzcv 0x80000000UL ] ]
    check "eb0203e0" []
      [ [ X(0, 0x76c5d1104cdaaa2UL); Nzcv 0x0UL ]
        [ X(0, 0x678443402281acd1UL); Nzcv 0x0UL ]
        [ X(0, 0x1UL); Nzcv 0x0UL ]
        [ X(0, 0xaaaaaaaaaaaaaaabUL); Nzcv 0x80000000UL ] ]

  /// C6.2.201 NGC
  [<TestMethod>]
  member _.``C6.2.201 NGC``() =
    check "5a0203e0" []
      [ [ X(0, 0x4cdaaa1UL) ]
        [ X(0, 0x2281acd0UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0xaaaaaaaaUL) ] ]
    check "da0203e0" []
      [ [ X(0, 0x76c5d1104cdaaa1UL) ]
        [ X(0, 0x678443402281acd0UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0xaaaaaaaaaaaaaaaaUL) ] ]

  /// C6.2.202 NGCS
  [<TestMethod>]
  member _.``C6.2.202 NGCS``() =
    check "7a0203e0" []
      [ [ X(0, 0x4cdaaa1UL); Nzcv 0x0UL ]
        [ X(0, 0x2281acd0UL); Nzcv 0x0UL ]
        [ X(0, 0x1UL); Nzcv 0x0UL ]
        [ X(0, 0xaaaaaaaaUL); Nzcv 0x80000000UL ] ]
    check "fa0203e0" []
      [ [ X(0, 0x76c5d1104cdaaa1UL); Nzcv 0x0UL ]
        [ X(0, 0x678443402281acd0UL); Nzcv 0x0UL ]
        [ X(0, 0x1UL); Nzcv 0x0UL ]
        [ X(0, 0xaaaaaaaaaaaaaaaaUL); Nzcv 0x80000000UL ] ]

  /// C6.2.203 NOP
  [<TestMethod>]
  member _.``C6.2.203 NOP``() =
    check "d503201f" [] [ []; []; []; [] ]

  /// C6.2.204 ORN (shifted register)
  [<TestMethod>]
  member _.``C6.2.204 ORN``() =
    check "2a220020" []
      [ [ X(0, 0x65cfeee7UL) ]
        [ X(0, 0x2bfdbed2UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0xaaaaaaaaUL) ] ]
    check "0ee21c20" []
      [ [ Q(0, 0x7861ffffe9dde0ffUL, 0x0UL) ]
        [ Q(0, 0xf7fad3af5f2fbe2cUL, 0x0UL) ]
        [ Q(0, 0x7f800000fffffffeUL, 0x0UL) ]
        [ Q(0, 0x7fffffffffffffffUL, 0x0UL) ] ]
    check "4ee21c20" []
      [ [ Q(0, 0x7861ffffe9dde0ffUL, 0x74d7ffffaff7ff1fUL) ]
        [ Q(0, 0xf7fad3af5f2fbe2cUL, 0xfabfdf575f3ff3ebUL) ]
        [ Q(0, 0x7f800000fffffffeUL, 0xffffffffffc00000UL) ]
        [ Q(0, 0x7fffffffffffffffUL, 0xbfbfffffffffffffUL) ] ]
    check "aa220020" []
      [ [ X(0, 0xbfefddb165cfeee7UL) ]
        [ X(0, 0xffcc47502bfdbed2UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0xaaaaaaabaaaaaaaaUL) ] ]

  /// C6.2.205 ORR (immediate)
  [<TestMethod>]
  member _.``C6.2.205 ORR``() =
    check "b2410420" []
      [ [ X(0, 0xbeeb8da1658eec67UL) ]
        [ X(0, 0xbfc846100bfc1e43UL) ]
        [ X(0, 0x8000000000000001UL) ]
        [ X(0, 0x8000000100000001UL) ] ]
    check "321c0020" []
      [ [ X(0, 0x658eec77UL) ]
        [ X(0, 0xbfc1e52UL) ]
        [ X(0, 0x11UL) ]
        [ X(0, 0x10UL) ] ]
    check "b27c0020" []
      [ [ X(0, 0xbeeb8da1658eec77UL) ]
        [ X(0, 0xbfc846100bfc1e52UL) ]
        [ X(0, 0x11UL) ]
        [ X(0, 0x100000010UL) ] ]
    check "2a020020" []
      [ [ X(0, 0xffbefd7fUL) ]
        [ X(0, 0xdffe5f6fUL) ]
        [ X(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]
    check "aa020020" []
      [ [ X(0, 0xfefbafefffbefd7fUL) ]
        [ X(0, 0xbffbfebfdffe5f6fUL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x5555555555555555UL) ] ]
    check "0f009460" []
      [ [ Q(0, 0x962b1967c90789bbUL, 0x0UL) ]
        [ Q(0, 0x9a7ba72730fbca57UL, 0x0UL) ]
        [ Q(0, 0xbfc300033f830003UL, 0x0UL) ]
        [ Q(0, 0x3ff3000300030003UL, 0x0UL) ] ]
    check "4f009460" []
      [ [ Q(0, 0x962b1967c90789bbUL, 0x65afe26b5a072c6fUL) ]
        [ Q(0, 0x9a7ba72730fbca57UL, 0x444bcabb22bb690fUL) ]
        [ Q(0, 0xbfc300033f830003UL, 0x3dcfcccf40430003UL) ]
        [ Q(0, 0x3ff3000300030003UL, 0xbffb000300030003UL) ] ]
    check "0f001460" []
      [ [ Q(0, 0x962b1967c90789bbUL, 0x0UL) ]
        [ Q(0, 0x9a7aa72730f9ca57UL, 0x0UL) ]
        [ Q(0, 0xbfc000033f800003UL, 0x0UL) ]
        [ Q(0, 0x3ff0000300000003UL, 0x0UL) ] ]
    check "4f001460" []
      [ [ Q(0, 0x962b1967c90789bbUL, 0x65ace26b5a072c6fUL) ]
        [ Q(0, 0x9a7aa72730f9ca57UL, 0x444bcabb22bb690fUL) ]
        [ Q(0, 0xbfc000033f800003UL, 0x3dcccccf40400003UL) ]
        [ Q(0, 0x3ff0000300000003UL, 0xbff8000300000003UL) ] ]
    check "0ea21c20" []
      [ [ Q(0, 0xf7ff6f2f5efeff1cUL, 0x0UL) ]
        [ Q(0, 0x5fcdaf75ffdfdff7UL, 0x0UL) ]
        [ Q(0, 0xffffffff80000001UL, 0x0UL) ]
        [ Q(0, 0xc008000000000000UL, 0x0UL) ] ]
    check "4ea21c20" []
      [ [ Q(0, 0xf7ff6f2f5efeff1cUL, 0xcbfe824e7efbfcf7UL) ]
        [ Q(0, 0x5fcdaf75ffdfdff7UL, 0xe7713bfbffdfbcbdUL) ]
        [ Q(0, 0xffffffff80000001UL, 0x7fa000007fffffffUL) ]
        [ Q(0, 0xc008000000000000UL, 0x7ff999999999999aUL) ] ]

  /// <summary>
  /// The code PACDA computes comes from a key the oracle's process
  /// draws at random, so no value of it can be compared. What the manual
  /// fixes is checked instead (C6.2.207, AddPAC, Auth()), over every input
  /// set with X0 a canonical pointer and X1 the modifier: signing keeps
  /// bit 55 and the address below bit 48 and changes the pointer; AUTDA
  /// gives it back; and the other key's AUT fails, leaving key B's
  /// error code in bits 62:61. The oracle agrees with the round trip and
  /// the failure, which its processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.207 PACDA``() =
    signs "dac10820" "dac11820" "dac11c20" 0 0x4000000000000000UL

  /// <summary>
  /// The code PACDZA computes comes from a key the oracle's process
  /// draws at random, so no value of it can be compared. What the manual
  /// fixes is checked instead (C6.2.207, AddPAC, Auth()), over every input
  /// set with X0 a canonical pointer and zero the modifier: signing keeps
  /// bit 55 and the address below bit 48 and changes the pointer; AUTDZA
  /// gives it back; and the other key's AUT fails, leaving key B's
  /// error code in bits 62:61. The oracle agrees with the round trip and
  /// the failure, which its processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.207 PACDZA``() =
    signs "dac12be0" "dac13be0" "dac13fe0" 0 0x4000000000000000UL

  /// <summary>
  /// The code PACDB computes comes from a key the oracle's process
  /// draws at random, so no value of it can be compared. What the manual
  /// fixes is checked instead (C6.2.208, AddPAC, Auth()), over every input
  /// set with X0 a canonical pointer and X1 the modifier: signing keeps
  /// bit 55 and the address below bit 48 and changes the pointer; AUTDB
  /// gives it back; and the other key's AUT fails, leaving key A's
  /// error code in bits 62:61. The oracle agrees with the round trip and
  /// the failure, which its processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.208 PACDB``() =
    signs "dac10c20" "dac11c20" "dac11820" 0 0x2000000000000000UL

  /// <summary>
  /// The code PACDZB computes comes from a key the oracle's process
  /// draws at random, so no value of it can be compared. What the manual
  /// fixes is checked instead (C6.2.208, AddPAC, Auth()), over every input
  /// set with X0 a canonical pointer and zero the modifier: signing keeps
  /// bit 55 and the address below bit 48 and changes the pointer; AUTDZB
  /// gives it back; and the other key's AUT fails, leaving key A's
  /// error code in bits 62:61. The oracle agrees with the round trip and
  /// the failure, which its processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.208 PACDZB``() =
    signs "dac12fe0" "dac13fe0" "dac13be0" 0 0x2000000000000000UL

  /// <summary>
  /// The code PACGA computes comes from a key the oracle's process draws
  /// at random, so no value of it can be compared. What the manual fixes is
  /// checked instead (C6.2.209): the code goes to the top half of Xd and
  /// the bottom half is zero, over every input set, and it is a function
  /// of both operands, changing with each.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.209 PACGA``() =
    for k in 0 .. A64Machine.sets - 1 do
      let code inputs = (A64Machine.after [ "9ac23020" ] inputs k).Xs[0]
      let given = code []
      Assert.AreEqual<uint64>(0UL, given &&& 0xffffffffUL)
      Assert.AreNotEqual<uint64>(given, code [ X(1, pointer) ])
      Assert.AreNotEqual<uint64>(given, code [ X(2, pointer) ])

  /// <summary>
  /// The code PACIA computes comes from a key the oracle's process
  /// draws at random, so no value of it can be compared. What the manual
  /// fixes is checked instead (C6.2.210, AddPAC, Auth()), over every input
  /// set with X0 a canonical pointer and X1 the modifier: signing keeps
  /// bit 55 and the address below bit 48 and changes the pointer; AUTIA
  /// gives it back; and the other key's AUT fails, leaving key B's
  /// error code in bits 62:61. The oracle agrees with the round trip and
  /// the failure, which its processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.210 PACIA``() =
    signs "dac10020" "dac11020" "dac11420" 0 0x4000000000000000UL

  /// <summary>
  /// The code PACIA1716 computes comes from a key the oracle's process
  /// draws at random, so no value of it can be compared. What the manual
  /// fixes is checked instead (C6.2.210, AddPAC, Auth()), over every input
  /// set with X17 a canonical pointer and X16 the modifier: signing keeps
  /// bit 55 and the address below bit 48 and changes the pointer; AUTIA1716
  /// gives it back; and the other key's AUT fails, leaving key B's
  /// error code in bits 62:61. The oracle agrees with the round trip and
  /// the failure, which its processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.210 PACIA1716``() =
    signs "d503211f" "d503219f" "d50321df" 17 0x4000000000000000UL

  /// <summary>
  /// The code PACIASP computes comes from a key the oracle's process
  /// draws at random, so no value of it can be compared. What the manual
  /// fixes is checked instead (C6.2.210, AddPAC, Auth()), over every input
  /// set with X30 a canonical pointer and SP the modifier: signing keeps
  /// bit 55 and the address below bit 48 and changes the pointer; AUTIASP
  /// gives it back; and the other key's AUT fails, leaving key B's
  /// error code in bits 62:61. The oracle agrees with the round trip and
  /// the failure, which its processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.210 PACIASP``() =
    signs "d503233f" "d50323bf" "d50323ff" 30 0x4000000000000000UL

  /// <summary>
  /// The code PACIAZ computes comes from a key the oracle's process
  /// draws at random, so no value of it can be compared. What the manual
  /// fixes is checked instead (C6.2.210, AddPAC, Auth()), over every input
  /// set with X30 a canonical pointer and zero the modifier: signing keeps
  /// bit 55 and the address below bit 48 and changes the pointer; AUTIAZ
  /// gives it back; and the other key's AUT fails, leaving key B's
  /// error code in bits 62:61. The oracle agrees with the round trip and
  /// the failure, which its processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.210 PACIAZ``() =
    signs "d503231f" "d503239f" "d50323df" 30 0x4000000000000000UL

  /// <summary>
  /// The code PACIZA computes comes from a key the oracle's process
  /// draws at random, so no value of it can be compared. What the manual
  /// fixes is checked instead (C6.2.210, AddPAC, Auth()), over every input
  /// set with X0 a canonical pointer and zero the modifier: signing keeps
  /// bit 55 and the address below bit 48 and changes the pointer; AUTIZA
  /// gives it back; and the other key's AUT fails, leaving key B's
  /// error code in bits 62:61. The oracle agrees with the round trip and
  /// the failure, which its processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.210 PACIZA``() =
    signs "dac123e0" "dac133e0" "dac137e0" 0 0x4000000000000000UL

  /// <summary>
  /// The code PACIB computes comes from a key the oracle's process
  /// draws at random, so no value of it can be compared. What the manual
  /// fixes is checked instead (C6.2.211, AddPAC, Auth()), over every input
  /// set with X0 a canonical pointer and X1 the modifier: signing keeps
  /// bit 55 and the address below bit 48 and changes the pointer; AUTIB
  /// gives it back; and the other key's AUT fails, leaving key A's
  /// error code in bits 62:61. The oracle agrees with the round trip and
  /// the failure, which its processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.211 PACIB``() =
    signs "dac10420" "dac11420" "dac11020" 0 0x2000000000000000UL

  /// <summary>
  /// The code PACIB1716 computes comes from a key the oracle's process
  /// draws at random, so no value of it can be compared. What the manual
  /// fixes is checked instead (C6.2.211, AddPAC, Auth()), over every input
  /// set with X17 a canonical pointer and X16 the modifier: signing keeps
  /// bit 55 and the address below bit 48 and changes the pointer; AUTIB1716
  /// gives it back; and the other key's AUT fails, leaving key A's
  /// error code in bits 62:61. The oracle agrees with the round trip and
  /// the failure, which its processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.211 PACIB1716``() =
    signs "d503215f" "d50321df" "d503219f" 17 0x2000000000000000UL

  /// <summary>
  /// The code PACIBSP computes comes from a key the oracle's process
  /// draws at random, so no value of it can be compared. What the manual
  /// fixes is checked instead (C6.2.211, AddPAC, Auth()), over every input
  /// set with X30 a canonical pointer and SP the modifier: signing keeps
  /// bit 55 and the address below bit 48 and changes the pointer; AUTIBSP
  /// gives it back; and the other key's AUT fails, leaving key A's
  /// error code in bits 62:61. The oracle agrees with the round trip and
  /// the failure, which its processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.211 PACIBSP``() =
    signs "d503237f" "d50323ff" "d50323bf" 30 0x2000000000000000UL

  /// <summary>
  /// The code PACIBZ computes comes from a key the oracle's process
  /// draws at random, so no value of it can be compared. What the manual
  /// fixes is checked instead (C6.2.211, AddPAC, Auth()), over every input
  /// set with X30 a canonical pointer and zero the modifier: signing keeps
  /// bit 55 and the address below bit 48 and changes the pointer; AUTIBZ
  /// gives it back; and the other key's AUT fails, leaving key A's
  /// error code in bits 62:61. The oracle agrees with the round trip and
  /// the failure, which its processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.211 PACIBZ``() =
    signs "d503235f" "d50323df" "d503239f" 30 0x2000000000000000UL

  /// <summary>
  /// The code PACIZB computes comes from a key the oracle's process
  /// draws at random, so no value of it can be compared. What the manual
  /// fixes is checked instead (C6.2.211, AddPAC, Auth()), over every input
  /// set with X0 a canonical pointer and zero the modifier: signing keeps
  /// bit 55 and the address below bit 48 and changes the pointer; AUTIZB
  /// gives it back; and the other key's AUT fails, leaving key A's
  /// error code in bits 62:61. The oracle agrees with the round trip and
  /// the failure, which its processor (FEAT_FPAC) raises as an exception.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.211 PACIZB``() =
    signs "dac127e0" "dac137e0" "dac133e0" 0 0x2000000000000000UL

  /// C6.2.212 PRFM (immediate)
  [<TestMethod>]
  member _.``C6.2.212 PRFM``() =
    check "f9800020" [ X(1, 0x2008000UL) ] [ []; []; []; [] ]

  /// C6.2.215 PRFUM
  [<TestMethod>]
  member _.``C6.2.215 PRFUM``() =
    check "f8800020" [ X(1, 0x2008000UL) ] [ []; []; []; [] ]

  /// C6.2.216 PSB CSYNC
  [<TestMethod>]
  member _.``C6.2.216 PSB``() =
    check "d503223f" [] [ []; []; []; [] ]

  /// C6.2.217 PSSBB
  [<TestMethod>]
  member _.``C6.2.217 PSSBB``() =
    check "d503349f" [] [ []; []; []; [] ]

  /// C6.2.218 RBIT
  [<TestMethod>]
  member _.``C6.2.218 RBIT``() =
    check "5ac00020" []
      [ [ X(0, 0xe63771a6UL) ]
        [ X(0, 0x42783fd0UL) ]
        [ X(0, 0x80000000UL) ]
        [ X(0, 0x0UL) ] ]
    check "2e605820" []
      [ [ Q(0, 0xe86f6f4123b0738UL, 0x0UL) ]
        [ Q(0, 0xea13c1a4faf07924UL, 0x0UL) ]
        [ Q(0, 0xfe01000001000000UL, 0x0UL) ]
        [ Q(0, 0x210000000000000UL, 0x0UL) ] ]
    check "6e605820" []
      [ [ Q(0, 0xe86f6f4123b0738UL, 0x26b417274cf3fe8UL) ]
        [ Q(0, 0xea13c1a4faf07924UL, 0x478cd8cafaf80d95UL) ]
        [ Q(0, 0xfe01000001000000UL, 0xfe050000fe030000UL) ]
        [ Q(0, 0x210000000000000UL, 0xfc9d999999999959UL) ] ]
    check "dac00020" []
      [ [ X(0, 0xe63771a685b1d77dUL) ]
        [ X(0, 0x42783fd0086213fdUL) ]
        [ X(0, 0x8000000000000000UL) ]
        [ X(0, 0x80000000UL) ] ]

  /// <summary>
  /// RET cannot run in the oracle, which has nowhere for it to go, so this
  /// checks the jump: a return out of the instruction to what X30 holds, or
  /// the register it names, over every input set (C6.2.219).
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.219 RET``() =
    Assert.AreEqual<string option>(Some "IsRet", exitOf "d65f03c0")
    check "d65f03c0" []
      [ [ Pc 0x990cd70b12c5d084UL ]
        [ Pc 0xddfcd92ab490c639UL ]
        [ Pc 0x8000000080000000UL ]
        [ Pc 0x7fffffffUL ] ]
    check "d65f0020" []
      [ [ Pc 0xbeeb8da1658eec67UL ]
        [ Pc 0xbfc846100bfc1e42UL ]
        [ Pc 0x1UL ]
        [ Pc 0x100000000UL ] ]

  /// <summary>
  /// RETAA cannot run in the oracle, which has nowhere for it to go, and
  /// its target is authenticated with a key the oracle's process draws
  /// at random. What the manual fixes is checked instead (C6.2.220): with X30
  /// a canonical pointer the matching PAC signed, the jump, a return,
  /// goes to the pointer; unsigned, to the pointer with the key's error
  /// code in bits 62:61, over every input set.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.220 RETAA``() =
    Assert.AreEqual<string option>(Some "IsRet", exitOf "d65f0bff")
    branchesSigned "d503233f" "d65f0bff" 30 0x2000000000000000UL false

  /// <summary>
  /// RETAB cannot run in the oracle, which has nowhere for it to go, and
  /// its target is authenticated with a key the oracle's process draws
  /// at random. What the manual fixes is checked instead (C6.2.220): with X30
  /// a canonical pointer the matching PAC signed, the jump, a return,
  /// goes to the pointer; unsigned, to the pointer with the key's error
  /// code in bits 62:61, over every input set.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.220 RETAB``() =
    Assert.AreEqual<string option>(Some "IsRet", exitOf "d65f0fff")
    branchesSigned "d503237f" "d65f0fff" 30 0x4000000000000000UL false

  /// C6.2.221 REV
  [<TestMethod>]
  member _.``C6.2.221 REV``() =
    check "5ac00820" []
      [ [ X(0, 0x67ec8e65UL) ]
        [ X(0, 0x421efc0bUL) ]
        [ X(0, 0x1000000UL) ]
        [ X(0, 0x0UL) ] ]
    check "dac00c20" []
      [ [ X(0, 0x67ec8e65a18debbeUL) ]
        [ X(0, 0x421efc0b1046c8bfUL) ]
        [ X(0, 0x100000000000000UL) ]
        [ X(0, 0x1000000UL) ] ]

  /// C6.2.222 REV16
  [<TestMethod>]
  member _.``C6.2.222 REV16``() =
    check "5ac00420" []
      [ [ X(0, 0x8e6567ecUL) ]
        [ X(0, 0xfc0b421eUL) ]
        [ X(0, 0x100UL) ]
        [ X(0, 0x0UL) ] ]
    check "0e201820" []
      [ [ Q(0, 0x61702f6fdc481ce0UL, 0x0UL) ]
        [ Q(0, 0xc85725830f5f249eUL, 0x0UL) ]
        [ Q(0, 0x807f000000800000UL, 0x0UL) ]
        [ Q(0, 0x840000000000000UL, 0x0UL) ] ]
    check "4e201820" []
      [ [ Q(0, 0x61702f6fdc481ce0UL, 0xd6404e82f32e17fcUL) ]
        [ Q(0, 0xc85725830f5f249eUL, 0x31e2531b1f5fa9b0UL) ]
        [ Q(0, 0x807f000000800000UL, 0xa07f0000c07f0000UL) ]
        [ Q(0, 0x840000000000000UL, 0xb93f999999999a99UL) ] ]
    check "dac00420" []
      [ [ X(0, 0xebbea18d8e6567ecUL) ]
        [ X(0, 0xc8bf1046fc0b421eUL) ]
        [ X(0, 0x100UL) ]
        [ X(0, 0x10000000000UL) ] ]

  /// C6.2.223 REV32
  [<TestMethod>]
  member _.``C6.2.223 REV32``() =
    check "2e200820" []
      [ [ Q(0, 0x2f6f61701ce0dc48UL, 0x0UL) ]
        [ Q(0, 0x2583c857249e0f5fUL, 0x0UL) ]
        [ Q(0, 0x807f00000080UL, 0x0UL) ]
        [ Q(0, 0x84000000000UL, 0x0UL) ] ]
    check "6e200820" []
      [ [ Q(0, 0x2f6f61701ce0dc48UL, 0x4e82d64017fcf32eUL) ]
        [ Q(0, 0x2583c857249e0f5fUL, 0x531b31e2a9b01f5fUL) ]
        [ Q(0, 0x807f00000080UL, 0xa07f0000c07fUL) ]
        [ Q(0, 0x84000000000UL, 0x9999b93f9a999999UL) ] ]
    check "2e600820" []
      [ [ Q(0, 0x6f2f7061e01c48dcUL, 0x0UL) ]
        [ Q(0, 0x832557c89e245f0fUL, 0x0UL) ]
        [ Q(0, 0x7f8000008000UL, 0x0UL) ]
        [ Q(0, 0x400800000000UL, 0x0UL) ] ]
    check "6e600820" []
      [ [ Q(0, 0x6f2f7061e01c48dcUL, 0x824e40d6fc172ef3UL) ]
        [ Q(0, 0x832557c89e245f0fUL, 0x1b53e231b0a95f1fUL) ]
        [ Q(0, 0x7f8000008000UL, 0x7fa000007fc0UL) ]
        [ Q(0, 0x400800000000UL, 0x99993fb9999a9999UL) ] ]
    check "dac00820" []
      [ [ X(0, 0xa18debbe67ec8e65UL) ]
        [ X(0, 0x1046c8bf421efc0bUL) ]
        [ X(0, 0x1000000UL) ]
        [ X(0, 0x100000000000000UL) ] ]

  /// C6.2.224 REV64
  [<TestMethod>]
  member _.``C6.2.224 REV64``() =
    check "0e200820" []
      [ [ Q(0, 0x1ce0dc482f6f6170UL, 0x0UL) ]
        [ Q(0, 0x249e0f5f2583c857UL, 0x0UL) ]
        [ Q(0, 0x800000807fUL, 0x0UL) ]
        [ Q(0, 0x840UL, 0x0UL) ] ]
    check "4e200820" []
      [ [ Q(0, 0x1ce0dc482f6f6170UL, 0x17fcf32e4e82d640UL) ]
        [ Q(0, 0x249e0f5f2583c857UL, 0xa9b01f5f531b31e2UL) ]
        [ Q(0, 0x800000807fUL, 0xc07f0000a07fUL) ]
        [ Q(0, 0x840UL, 0x9a9999999999b93fUL) ] ]
    check "0e600820" []
      [ [ Q(0, 0xe01c48dc6f2f7061UL, 0x0UL) ]
        [ Q(0, 0x9e245f0f832557c8UL, 0x0UL) ]
        [ Q(0, 0x800000007f80UL, 0x0UL) ]
        [ Q(0, 0x4008UL, 0x0UL) ] ]
    check "4e600820" []
      [ [ Q(0, 0xe01c48dc6f2f7061UL, 0xfc172ef3824e40d6UL) ]
        [ Q(0, 0x9e245f0f832557c8UL, 0xb0a95f1f1b53e231UL) ]
        [ Q(0, 0x800000007f80UL, 0x7fc000007fa0UL) ]
        [ Q(0, 0x4008UL, 0x999a999999993fb9UL) ] ]
    check "0ea00820" []
      [ [ Q(0, 0x48dce01c70616f2fUL, 0x0UL) ]
        [ Q(0, 0x5f0f9e2457c88325UL, 0x0UL) ]
        [ Q(0, 0x800000007f800000UL, 0x0UL) ]
        [ Q(0, 0x40080000UL, 0x0UL) ] ]
    check "4ea00820" []
      [ [ Q(0, 0x48dce01c70616f2fUL, 0x2ef3fc1740d6824eUL) ]
        [ Q(0, 0x5f0f9e2457c88325UL, 0x5f1fb0a9e2311b53UL) ]
        [ Q(0, 0x800000007f800000UL, 0x7fc000007fa00000UL) ]
        [ Q(0, 0x40080000UL, 0x9999999a3fb99999UL) ] ]

  /// C6.2.225 RMIF
  [<TestMethod>]
  member _.``C6.2.225 RMIF``() =
    check "ba03840f" []
      [ [ Nzcv 0x90000000UL ]
        [ Nzcv 0xd0000000UL ]
        [ Nzcv 0x0UL ]
        [ Nzcv 0xf0000000UL ] ]

  /// C6.2.226 ROR (immediate)
  [<TestMethod>]
  member _.``C6.2.226 ROR``() =
    check "13820440" []
      [ [ X(0, 0x7d992aafUL) ]
        [ X(0, 0xeebf2997UL) ]
        [ X(0, 0xffffffffUL) ]
        [ X(0, 0xaaaaaaaaUL) ] ]
    check "93c20440" []
      [ [ X(0, 0x7c49d1777d992aafUL) ]
        [ X(0, 0xcc3dde5feebf2997UL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0xaaaaaaaaaaaaaaaaUL) ] ]
    check "1ac22c20" []
      [ [ X(0, 0x963bb19dUL) ]
        [ X(0, 0x3c8417f8UL) ]
        [ X(0, 0x2UL) ]
        [ X(0, 0x0UL) ] ]
    check "93c20040" []
      [ [ X(0, 0xf893a2eefb32555eUL) ]
        [ X(0, 0x987bbcbfdd7e532fUL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x5555555555555555UL) ] ]
    check "9ac22c20" []
      [ [ X(0, 0x963bb19efbae3685UL) ]
        [ X(0, 0x8c2017f83c857f90UL) ]
        [ X(0, 0x2UL) ]
        [ X(0, 0x800UL) ] ]

  /// C6.2.228 RORV
  [<TestMethod>]
  member _.``C6.2.228 RORV``() =
    check "1ac22c20" []
      [ [ X(0, 0x963bb19dUL) ]
        [ X(0, 0x3c8417f8UL) ]
        [ X(0, 0x2UL) ]
        [ X(0, 0x0UL) ] ]
    check "9ac22c20" []
      [ [ X(0, 0x963bb19efbae3685UL) ]
        [ X(0, 0x8c2017f83c857f90UL) ]
        [ X(0, 0x2UL) ]
        [ X(0, 0x800UL) ] ]

  /// C6.2.229 SB
  [<TestMethod>]
  member _.``C6.2.229 SB``() =
    check "d50330ff" [] [ []; []; []; [] ]

  /// C6.2.230 SBC
  [<TestMethod>]
  member _.``C6.2.230 SBC``() =
    check "5a020020" []
      [ [ X(0, 0x6a5c9708UL) ]
        [ X(0, 0x2e7dcb12UL) ]
        [ X(0, 0x2UL) ]
        [ X(0, 0xaaaaaaaaUL) ] ]
    check "da020020" []
      [ [ X(0, 0xc657eab26a5c9708UL) ]
        [ X(0, 0x274c89502e7dcb12UL) ]
        [ X(0, 0x2UL) ]
        [ X(0, 0xaaaaaaabaaaaaaaaUL) ] ]

  /// C6.2.231 SBCS
  [<TestMethod>]
  member _.``C6.2.231 SBCS``() =
    check "7a020020" []
      [ [ X(0, 0x6a5c9708UL); Nzcv 0x0UL ]
        [ X(0, 0x2e7dcb12UL); Nzcv 0x0UL ]
        [ X(0, 0x2UL); Nzcv 0x0UL ]
        [ X(0, 0xaaaaaaaaUL); Nzcv 0x80000000UL ] ]
    check "fa020020" []
      [ [ X(0, 0xc657eab26a5c9708UL); Nzcv 0x80000000UL ]
        [ X(0, 0x274c89502e7dcb12UL); Nzcv 0x20000000UL ]
        [ X(0, 0x2UL); Nzcv 0x0UL ]
        [ X(0, 0xaaaaaaabaaaaaaaaUL); Nzcv 0x80000000UL ] ]

  /// C6.2.232 SBFIZ
  [<TestMethod>]
  member _.``C6.2.232 SBFIZ``() =
    check "131d1020" []
      [ [ X(0, 0x38UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0x8UL) ]
        [ X(0, 0x0UL) ] ]
    check "937d1020" []
      [ [ X(0, 0x38UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0x8UL) ]
        [ X(0, 0x0UL) ] ]
    check "93430820" []
      [ [ X(0, 0xe000000000000000UL) ]
        [ X(0, 0x4000000000000000UL) ]
        [ X(0, 0x2000000000000000UL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.233 SBFM
  [<TestMethod>]
  member _.``C6.2.233 SBFM``() =
    check "13017c20" []
      [ [ X(0, 0x32c77633UL) ]
        [ X(0, 0x5fe0f21UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "9341fc20" []
      [ [ X(0, 0xdf75c6d0b2c77633UL) ]
        [ X(0, 0xdfe4230805fe0f21UL) ]
        []
        [ X(0, 0x80000000UL) ] ]
    check "131d1020" []
      [ [ X(0, 0x38UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0x8UL) ]
        [ X(0, 0x0UL) ] ]
    check "937d1020" []
      [ [ X(0, 0x38UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0x8UL) ]
        [ X(0, 0x0UL) ] ]
    check "13031420" []
      [ [ X(0, 0xfffffffcUL) ]
        [ X(0, 0x0UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "93431420" []
      [ [ X(0, 0xfffffffffffffffcUL) ]
        [ X(0, 0x0UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "13031c20" []
      [ [ X(0, 0xcUL) ]
        [ X(0, 0x8UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "93431c20" []
      [ [ X(0, 0xcUL) ]
        [ X(0, 0x8UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "13001c20" []
      [ [ X(0, 0x67UL) ]
        [ X(0, 0x42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]
    check "13003c20" []
      [ [ X(0, 0xffffec67UL) ]
        [ X(0, 0x1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]
    check "93400020" []
      [ [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x0UL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x0UL) ] ]
    check "93401c20" []
      [ [ X(0, 0x67UL) ]
        [ X(0, 0x42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]
    check "93403c20" []
      [ [ X(0, 0xffffffffffffec67UL) ]
        [ X(0, 0x1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]
    check "93407c20" []
      [ [ X(0, 0x658eec67UL) ]
        [ X(0, 0xbfc1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]
    check "93430820" []
      [ [ X(0, 0xe000000000000000UL) ]
        [ X(0, 0x4000000000000000UL) ]
        [ X(0, 0x2000000000000000UL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.234 SBFX
  [<TestMethod>]
  member _.``C6.2.234 SBFX``() =
    check "13031420" []
      [ [ X(0, 0xfffffffcUL) ]
        [ X(0, 0x0UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "93431420" []
      [ [ X(0, 0xfffffffffffffffcUL) ]
        [ X(0, 0x0UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "13031c20" []
      [ [ X(0, 0xcUL) ]
        [ X(0, 0x8UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "93431c20" []
      [ [ X(0, 0xcUL) ]
        [ X(0, 0x8UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "93400020" []
      [ [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x0UL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.235 SDIV
  [<TestMethod>]
  member _.``C6.2.235 SDIV``() =
    check "1ac20c20" []
      [ [ X(0, 0xffffffebUL) ]
        [ X(0, 0x0UL) ]
        [ X(0, 0xffffffffUL) ]
        [ X(0, 0x0UL) ] ]
    check "9ac20c20" []
      [ [ X(0, 0x8UL) ]
        [ X(0, 0x0UL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.236 SETF8, SETF16
  [<TestMethod>]
  member _.``C6.2.236 SETF16``() =
    check "3a00480d" []
      [ [ Nzcv 0x0UL ]
        [ Nzcv 0x10000000UL ]
        []
        [ Nzcv 0x80000000UL ] ]
    check "3a00482d" []
      [ [ Nzcv 0x90000000UL ]
        [ Nzcv 0x0UL ]
        [ Nzcv 0x20000000UL ]
        [ Nzcv 0x40000000UL ] ]

  /// C6.2.236 SETF8, SETF16
  [<TestMethod>]
  member _.``C6.2.236 SETF8``() =
    check "3a00080d" []
      [ [ Nzcv 0x90000000UL ]
        [ Nzcv 0x90000000UL ]
        []
        [ Nzcv 0x80000000UL ] ]
    check "3a00082d" []
      [ [ Nzcv 0x0UL ]
        [ Nzcv 0x0UL ]
        [ Nzcv 0x20000000UL ]
        [ Nzcv 0x40000000UL ] ]

  /// C6.2.237 SEV
  [<TestMethod>]
  member _.``C6.2.237 SEV``() =
    check "d503209f" [] [ []; []; []; [] ]

  /// C6.2.238 SEVL
  [<TestMethod>]
  member _.``C6.2.238 SEVL``() =
    check "d50320bf" [] [ []; []; []; [] ]

  /// C6.2.239 SMADDL
  [<TestMethod>]
  member _.``C6.2.239 SMADDL``() =
    check "9b220c20" []
      [ [ X(0, 0x6fd9b3bad659c9ddUL) ]
        [ X(0, 0xc254f453cf7cea82UL) ]
        [ X(0, 0x7fffffffffffffffUL) ]
        [ X(0, 0xaaaaaaaaaaaaaaaaUL) ] ]

  /// C6.2.240 SMC
  [<TestMethod>]
  member _.``C6.2.240 SMC``() =
    raises BinIR.SideEffect.UndefinedInstruction "d4000003"

  /// C6.2.241 SMNEGL
  [<TestMethod>]
  member _.``C6.2.241 SMNEGL``() =
    check "9b22fc20" []
      [ [ X(0, 0x1e7d2d617e8ff2eUL) ]
        [ X(0, 0x19d8e27306b0be2UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.242 SMSUBL
  [<TestMethod>]
  member _.``C6.2.242 SMSUBL``() =
    check "9b228c20" []
      [ [ X(0, 0x73a95967062bc839UL) ]
        [ X(0, 0xc59010a230530246UL) ]
        [ X(0, 0x8000000000000001UL) ]
        [ X(0, 0xaaaaaaaaaaaaaaaaUL) ] ]

  /// C6.2.243 SMULH
  [<TestMethod>]
  member _.``C6.2.243 SMULH``() =
    check "9b427c20" []
      [ [ X(0, 0x1e31b699742d02aUL) ]
        [ X(0, 0x19f7996a172798ceUL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.244 SMULL
  [<TestMethod>]
  member _.``C6.2.244 SMULL``() =
    check "0f52a020" []
      [ [ Q(0, 0x18c23248f529c3c8UL, 0x2630163e25c81aa2UL) ]
        [ Q(0, 0xf7c2e330087b4140UL, 0xf8645a800ad23b10UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "0fa2a020" []
      [ [ Q(0, 0xddbc9f8672e2cbb8UL, 0xcb2762d5d6ed363eUL) ]
        [ Q(0, 0x212945b6a627d850UL, 0x1e9f5809ce1948c4UL) ]
        [ Q(0, 0x3fc0000080000000UL, 0xc07fbfff80800000UL) ]
        [ Q(0, 0x0UL, 0xdffc000000000000UL) ] ]
    check "0e22c020" []
      [ [ Q(0, 0x1830004800200150UL, 0xcb10dade13f2063eUL) ]
        [ Q(0, 0xf777fd30dc66f9acUL, 0x1e3fef28290410c4UL) ]
        [ Q(0, 0x0UL, 0xc080c08000000000UL) ]
        [ Q(0, 0x0UL, 0xe000000000000000UL) ] ]
    check "0e62c020" []
      [ [ Q(0, 0x18c23248001e6550UL, 0xcb2782de1409363eUL) ]
        [ Q(0, 0xf7c2e330dc226bacUL, 0x1e9eef2828bf48c4UL) ]
        [ Q(0, 0x0UL, 0xc07f408000000000UL) ]
        [ Q(0, 0x0UL, 0xdffc000000000000UL) ] ]
    check "0ea2c020" []
      [ [ Q(0, 0x18c2c707315e6550UL, 0xcb2762d5d6ed363eUL) ]
        [ Q(0, 0xf7c2f85247926bacUL, 0x1e9f5809ce1948c4UL) ]
        [ Q(0, 0xffffffff80000000UL, 0xc07fbfff80800000UL) ]
        [ Q(0, 0x0UL, 0xdffc000000000000UL) ] ]
    check "9b227c20" []
      [ [ X(0, 0xfe182d29e81700d2UL) ]
        [ X(0, 0xfe6271d8cf94f41eUL) ]
        [ X(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.245 SSBB
  [<TestMethod>]
  member _.``C6.2.245 SSBB``() =
    check "d503309f" [] [ []; []; []; [] ]

  /// C6.2.246 ST2G
  [<TestMethod>]
  member _.``C6.2.246 ST2G``() =
    check "d9a00820" [ X(1, 0x2008000UL) ] [ []; []; []; [] ]
    check "d9a01420" [ X(1, 0x2008000UL) ]
      [ [ X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL) ] ]
    check "d9a01c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL) ] ]
    check "d9a01820" [ X(1, 0x2007ff0UL) ] [ []; []; []; [] ]
    check "d9a00420" [ X(1, 0x2008000UL) ] [ []; []; []; [] ]

  /// C6.2.247 STADDB, STADDLB
  [<TestMethod>]
  member _.``C6.2.247 STADDB``() =
    check "3822003f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4adfUL) ]
        [ M(0, 0x912f822b1e8fe113UL) ]
        [ M(0, 0xffUL) ]
        [ M(0, 0x55555555555555aaUL) ] ]

  /// C6.2.247 STADDB, STADDLB
  [<TestMethod>]
  member _.``C6.2.247 STADDLB``() =
    check "3862003f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4adfUL) ]
        [ M(0, 0x912f822b1e8fe113UL) ]
        [ M(0, 0xffUL) ]
        [ M(0, 0x55555555555555aaUL) ] ]

  /// C6.2.248 STADDH, STADDLH
  [<TestMethod>]
  member _.``C6.2.248 STADDH``() =
    check "7822003f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e9fdfUL) ]
        [ M(0, 0x912f822b1e8f3513UL) ]
        [ M(0, 0xffffUL) ]
        [ M(0, 0x555555555555aaaaUL) ] ]

  /// C6.2.248 STADDH, STADDLH
  [<TestMethod>]
  member _.``C6.2.248 STADDLH``() =
    check "7862003f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e9fdfUL) ]
        [ M(0, 0x912f822b1e8f3513UL) ]
        [ M(0, 0xffffUL) ]
        [ M(0, 0x555555555555aaaaUL) ] ]

  /// C6.2.249 STADD, STADDL
  [<TestMethod>]
  member _.``C6.2.249 STADD``() =
    check "f822003f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xd3b3cbf9bc709fdfUL) ]
        [ M(0, 0x29ab3eeafc0e3513UL) ]
        [ M(0, 0xffffffffffffffffUL) ]
        [ M(0, 0xaaaaaaaaaaaaaaaaUL) ] ]
    check "b822003f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290abc709fdfUL) ]
        [ M(0, 0x912f822bfc0e3513UL) ]
        [ M(0, 0xffffffffUL) ]
        [ M(0, 0x55555555aaaaaaaaUL) ] ]

  /// C6.2.249 STADD, STADDL
  [<TestMethod>]
  member _.``C6.2.249 STADDL``() =
    check "b862003f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290abc709fdfUL) ]
        [ M(0, 0x912f822bfc0e3513UL) ]
        [ M(0, 0xffffffffUL) ]
        [ M(0, 0x55555555aaaaaaaaUL) ] ]

  /// C6.2.250 STCLRB, STCLRLB
  [<TestMethod>]
  member _.``C6.2.250 STCLRB``() =
    check "3822103f" [ X(1, 0x2008000UL) ]
      [ []
        [ M(0, 0x912f822b1e8fe1c0UL) ]
        []
        [ M(0, 0x5555555555555500UL) ] ]

  /// C6.2.250 STCLRB, STCLRLB
  [<TestMethod>]
  member _.``C6.2.250 STCLRLB``() =
    check "3862103f" [ X(1, 0x2008000UL) ]
      [ []
        [ M(0, 0x912f822b1e8fe1c0UL) ]
        []
        [ M(0, 0x5555555555555500UL) ] ]

  /// C6.2.251 STCLRH, STCLRLH
  [<TestMethod>]
  member _.``C6.2.251 STCLRH``() =
    check "7822103f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e0a81UL) ]
        [ M(0, 0x912f822b1e8fa0c0UL) ]
        []
        [ M(0, 0x5555555555550000UL) ] ]

  /// C6.2.251 STCLRH, STCLRLH
  [<TestMethod>]
  member _.``C6.2.251 STCLRLH``() =
    check "7862103f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e0a81UL) ]
        [ M(0, 0x912f822b1e8fa0c0UL) ]
        []
        [ M(0, 0x5555555555550000UL) ] ]

  /// C6.2.252 STCLR, STCLRL
  [<TestMethod>]
  member _.``C6.2.252 STCLR``() =
    check "f822103f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0x3200900000c0a81UL) ]
        [ M(0, 0x10402000281a0c0UL) ]
        []
        [ M(0, 0x0UL) ] ]
    check "b822103f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290a000c0a81UL) ]
        [ M(0, 0x912f822b0281a0c0UL) ]
        []
        [ M(0, 0x5555555500000000UL) ] ]

  /// C6.2.252 STCLR, STCLRL
  [<TestMethod>]
  member _.``C6.2.252 STCLRL``() =
    check "b862103f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290a000c0a81UL) ]
        [ M(0, 0x912f822b0281a0c0UL) ]
        []
        [ M(0, 0x5555555500000000UL) ] ]

  /// C6.2.253 STEORB, STEORLB
  [<TestMethod>]
  member _.``C6.2.253 STEORB``() =
    check "3822203f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4adfUL) ]
        [ M(0, 0x912f822b1e8fe1cbUL) ]
        [ M(0, 0xffUL) ]
        [ M(0, 0x5555555555555500UL) ] ]

  /// C6.2.253 STEORB, STEORLB
  [<TestMethod>]
  member _.``C6.2.253 STEORLB``() =
    check "3862203f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4adfUL) ]
        [ M(0, 0x912f822b1e8fe1cbUL) ]
        [ M(0, 0xffUL) ]
        [ M(0, 0x5555555555555500UL) ] ]

  /// C6.2.254 STEORH, STEORLH
  [<TestMethod>]
  member _.``C6.2.254 STEORH``() =
    check "7822203f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e1fdfUL) ]
        [ M(0, 0x912f822b1e8fb2cbUL) ]
        [ M(0, 0xffffUL) ]
        [ M(0, 0x5555555555550000UL) ] ]

  /// C6.2.254 STEORH, STEORLH
  [<TestMethod>]
  member _.``C6.2.254 STEORLH``() =
    check "7862203f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e1fdfUL) ]
        [ M(0, 0x912f822b1e8fb2cbUL) ]
        [ M(0, 0xffffUL) ]
        [ M(0, 0x5555555555550000UL) ] ]

  /// C6.2.255 STEOR, STEORL
  [<TestMethod>]
  member _.``C6.2.255 STEOR``() =
    check "f822203f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0x23b38be43a0c1fdfUL) ]
        [ M(0, 0x9543e94c3f1b2cbUL) ]
        [ M(0, 0xffffffffffffffffUL) ]
        [ M(0, 0x0UL) ] ]
    check "b822203f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290a3a0c1fdfUL) ]
        [ M(0, 0x912f822bc3f1b2cbUL) ]
        [ M(0, 0xffffffffUL) ]
        [ M(0, 0x5555555500000000UL) ] ]

  /// C6.2.255 STEOR, STEORL
  [<TestMethod>]
  member _.``C6.2.255 STEORL``() =
    check "b862203f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290a3a0c1fdfUL) ]
        [ M(0, 0x912f822bc3f1b2cbUL) ]
        [ M(0, 0xffffffffUL) ]
        [ M(0, 0x5555555500000000UL) ] ]

  /// C6.2.256 STG
  [<TestMethod>]
  member _.``C6.2.256 STG``() =
    check "d9200820" [ X(1, 0x2008000UL) ] [ []; []; []; [] ]
    check "d9201420" [ X(1, 0x2008000UL) ]
      [ [ X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL) ] ]
    check "d9201c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL) ] ]
    check "d9201820" [ X(1, 0x2007ff0UL) ] [ []; []; []; [] ]
    check "d9200420" [ X(1, 0x2008000UL) ] [ []; []; []; [] ]

  /// C6.2.257 STGM
  [<TestMethod>]
  member _.``C6.2.257 STGM``() =
    raises BinIR.SideEffect.UndefinedInstruction "d9a00020"

  /// C6.2.258 STGP
  [<TestMethod>]
  member _.``C6.2.258 STGP``() =
    check "69000820" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0x910a2dec89025cc1UL); M(8, 0xf893a2eefb32555eUL) ]
        [ M(0, 0x975835de1c9756ceUL); M(8, 0x987bbcbfdd7e532fUL) ]
        [ M(8, 0xffffffffffffffffUL) ]
        [ M(0, 0xffffffffUL); M(8, 0x5555555555555555UL) ] ]
    check "68808c22" [ X(1, 0x2008000UL) ]
      [ [ X(1, 0x2008010UL)
          M(0, 0xf893a2eefb32555eUL)
          M(8, 0x71c18690ee42c90bUL) ]
        [ X(1, 0x2008010UL)
          M(0, 0x987bbcbfdd7e532fUL)
          M(8, 0xc3f2827affe7f664UL) ]
        [ X(1, 0x2008010UL)
          M(0, 0xffffffffffffffffUL)
          M(8, 0x8000000000000000UL) ]
        [ X(1, 0x2008010UL) ] ]
    check "69808c22" [ X(1, 0x2007ff0UL) ]
      [ [ X(1, 0x2008000UL)
          M(0, 0xf893a2eefb32555eUL)
          M(8, 0x71c18690ee42c90bUL) ]
        [ X(1, 0x2008000UL)
          M(0, 0x987bbcbfdd7e532fUL)
          M(8, 0xc3f2827affe7f664UL) ]
        [ X(1, 0x2008000UL)
          M(0, 0xffffffffffffffffUL)
          M(8, 0x8000000000000000UL) ]
        [ X(1, 0x2008000UL) ] ]
    check "69000c22" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xf893a2eefb32555eUL); M(8, 0x71c18690ee42c90bUL) ]
        [ M(0, 0x987bbcbfdd7e532fUL); M(8, 0xc3f2827affe7f664UL) ]
        [ M(0, 0xffffffffffffffffUL); M(8, 0x8000000000000000UL) ]
        [] ]
    check "69008c22" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0xf893a2eefb32555eUL); M(8, 0x71c18690ee42c90bUL) ]
        [ M(0, 0x987bbcbfdd7e532fUL); M(8, 0xc3f2827affe7f664UL) ]
        [ M(0, 0xffffffffffffffffUL); M(8, 0x8000000000000000UL) ]
        [] ]
    check "68800420" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0x910a2dec89025cc1UL); M(8, 0x2008000UL) ]
        [ M(0, 0x975835de1c9756ceUL); M(8, 0x2008000UL) ]
        [ M(8, 0x2008000UL) ]
        [ M(0, 0xffffffffUL); M(8, 0x2008000UL) ] ]

  /// C6.2.259 STLLRB
  [<TestMethod>]
  member _.``C6.2.259 STLLRB``() =
    check "089f7c20" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4ac1UL) ]
        [ M(0, 0x912f822b1e8fe1ceUL) ]
        []
        [ M(0, 0x55555555555555ffUL) ] ]

  /// C6.2.260 STLLRH
  [<TestMethod>]
  member _.``C6.2.260 STLLRH``() =
    check "489f7c20" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e5cc1UL) ]
        [ M(0, 0x912f822b1e8f56ceUL) ]
        []
        [ M(0, 0x555555555555ffffUL) ] ]

  /// C6.2.261 STLLR
  [<TestMethod>]
  member _.``C6.2.261 STLLR``() =
    check "c89f7c20" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0x910a2dec89025cc1UL) ]
        [ M(0, 0x975835de1c9756ceUL) ]
        []
        [ M(0, 0xffffffffUL) ] ]
    check "889f7c20" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290a89025cc1UL) ]
        [ M(0, 0x912f822b1c9756ceUL) ]
        []
        [ M(0, 0x55555555ffffffffUL) ] ]

  /// C6.2.262 STLR
  [<TestMethod>]
  member _.``C6.2.262 STLR``() =
    check "c89ffc20" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0x910a2dec89025cc1UL) ]
        [ M(0, 0x975835de1c9756ceUL) ]
        []
        [ M(0, 0xffffffffUL) ] ]
    check "889ffc20" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290a89025cc1UL) ]
        [ M(0, 0x912f822b1c9756ceUL) ]
        []
        [ M(0, 0x55555555ffffffffUL) ] ]

  /// C6.2.263 STLRB
  [<TestMethod>]
  member _.``C6.2.263 STLRB``() =
    check "089ffc20" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4ac1UL) ]
        [ M(0, 0x912f822b1e8fe1ceUL) ]
        []
        [ M(0, 0x55555555555555ffUL) ] ]

  /// C6.2.264 STLRH
  [<TestMethod>]
  member _.``C6.2.264 STLRH``() =
    check "489ffc20" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e5cc1UL) ]
        [ M(0, 0x912f822b1e8f56ceUL) ]
        []
        [ M(0, 0x555555555555ffffUL) ] ]

  /// C6.2.265 STLUR
  [<TestMethod>]
  member _.``C6.2.265 STLUR``() =
    check "d9000020" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0x910a2dec89025cc1UL) ]
        [ M(0, 0x975835de1c9756ceUL) ]
        []
        [ M(0, 0xffffffffUL) ] ]
    check "99010020" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0xdb20290a89025cc1UL) ]
        [ M(0, 0x912f822b1c9756ceUL) ]
        []
        [ M(0, 0x55555555ffffffffUL) ] ]
    check "d9010020" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0x910a2dec89025cc1UL) ]
        [ M(0, 0x975835de1c9756ceUL) ]
        []
        [ M(0, 0xffffffffUL) ] ]
    check "99000020" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290a89025cc1UL) ]
        [ M(0, 0x912f822b1c9756ceUL) ]
        []
        [ M(0, 0x55555555ffffffffUL) ] ]

  /// C6.2.266 STLURB
  [<TestMethod>]
  member _.``C6.2.266 STLURB``() =
    check "19000020" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4ac1UL) ]
        [ M(0, 0x912f822b1e8fe1ceUL) ]
        []
        [ M(0, 0x55555555555555ffUL) ] ]
    check "19010020" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0xdb20290ac13e4ac1UL) ]
        [ M(0, 0x912f822b1e8fe1ceUL) ]
        []
        [ M(0, 0x55555555555555ffUL) ] ]

  /// C6.2.267 STLURH
  [<TestMethod>]
  member _.``C6.2.267 STLURH``() =
    check "59000020" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e5cc1UL) ]
        [ M(0, 0x912f822b1e8f56ceUL) ]
        []
        [ M(0, 0x555555555555ffffUL) ] ]
    check "59010020" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0xdb20290ac13e5cc1UL) ]
        [ M(0, 0x912f822b1e8f56ceUL) ]
        []
        [ M(0, 0x555555555555ffffUL) ] ]

  /// C6.2.268 STLXP
  [<TestMethod>]
  member _.``C6.2.268 STLXP``() =
    check "88238820" [ X(1, 0x2008000UL) ]
      [ [ X(3, 0x1UL) ]
        [ X(3, 0x1UL) ]
        [ X(3, 0x1UL) ]
        [ X(3, 0x1UL) ] ]

  /// C6.2.269 STLXR
  [<TestMethod>]
  member _.``C6.2.269 STLXR``() =
    check "8802fc20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ] ]

  /// C6.2.270 STLXRB
  [<TestMethod>]
  member _.``C6.2.270 STLXRB``() =
    check "0802fc20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ] ]

  /// C6.2.271 STLXRH
  [<TestMethod>]
  member _.``C6.2.271 STLXRH``() =
    check "4802fc20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ] ]

  /// C6.2.272 STNP
  [<TestMethod>]
  member _.``C6.2.272 STNP``() =
    check "28000c22" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xee42c90bfb32555eUL) ]
        [ M(0, 0xffe7f664dd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [ M(0, 0xaaaaaaaa55555555UL) ] ]
    check "28020c22" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0xee42c90bfb32555eUL) ]
        [ M(0, 0xffe7f664dd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [ M(0, 0xaaaaaaaa55555555UL) ] ]
    check "a8000c22" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xf893a2eefb32555eUL); M(8, 0x71c18690ee42c90bUL) ]
        [ M(0, 0x987bbcbfdd7e532fUL); M(8, 0xc3f2827affe7f664UL) ]
        [ M(0, 0xffffffffffffffffUL); M(8, 0x8000000000000000UL) ]
        [] ]
    check "a8010c22" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0xf893a2eefb32555eUL); M(8, 0x71c18690ee42c90bUL) ]
        [ M(0, 0x987bbcbfdd7e532fUL); M(8, 0xc3f2827affe7f664UL) ]
        [ M(0, 0xffffffffffffffffUL); M(8, 0x8000000000000000UL) ]
        [] ]
    check "28000420" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0x200800089025cc1UL) ]
        [ M(0, 0x20080001c9756ceUL) ]
        [ M(0, 0x200800000000000UL) ]
        [ M(0, 0x2008000ffffffffUL) ] ]

  /// C6.2.273 STP
  [<TestMethod>]
  member _.``C6.2.273 STP``() =
    check "28820c22" [ X(1, 0x2008000UL) ]
      [ [ X(1, 0x2008010UL); M(0, 0xee42c90bfb32555eUL) ]
        [ X(1, 0x2008010UL); M(0, 0xffe7f664dd7e532fUL) ]
        [ X(1, 0x2008010UL); M(0, 0xffffffffUL) ]
        [ X(1, 0x2008010UL); M(0, 0xaaaaaaaa55555555UL) ] ]
    check "a8810c22" [ X(1, 0x2008000UL) ]
      [ [ X(1, 0x2008010UL)
          M(0, 0xf893a2eefb32555eUL)
          M(8, 0x71c18690ee42c90bUL) ]
        [ X(1, 0x2008010UL)
          M(0, 0x987bbcbfdd7e532fUL)
          M(8, 0xc3f2827affe7f664UL) ]
        [ X(1, 0x2008010UL)
          M(0, 0xffffffffffffffffUL)
          M(8, 0x8000000000000000UL) ]
        [ X(1, 0x2008010UL) ] ]
    check "29820c22" [ X(1, 0x2007ff0UL) ]
      [ [ X(1, 0x2008000UL); M(0, 0xee42c90bfb32555eUL) ]
        [ X(1, 0x2008000UL); M(0, 0xffe7f664dd7e532fUL) ]
        [ X(1, 0x2008000UL); M(0, 0xffffffffUL) ]
        [ X(1, 0x2008000UL); M(0, 0xaaaaaaaa55555555UL) ] ]
    check "a9810c22" [ X(1, 0x2007ff0UL) ]
      [ [ X(1, 0x2008000UL)
          M(0, 0xf893a2eefb32555eUL)
          M(8, 0x71c18690ee42c90bUL) ]
        [ X(1, 0x2008000UL)
          M(0, 0x987bbcbfdd7e532fUL)
          M(8, 0xc3f2827affe7f664UL) ]
        [ X(1, 0x2008000UL)
          M(0, 0xffffffffffffffffUL)
          M(8, 0x8000000000000000UL) ]
        [ X(1, 0x2008000UL) ] ]
    check "29000c22" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xee42c90bfb32555eUL) ]
        [ M(0, 0xffe7f664dd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [ M(0, 0xaaaaaaaa55555555UL) ] ]
    check "29020c22" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0xee42c90bfb32555eUL) ]
        [ M(0, 0xffe7f664dd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [ M(0, 0xaaaaaaaa55555555UL) ] ]
    check "a9000c22" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xf893a2eefb32555eUL); M(8, 0x71c18690ee42c90bUL) ]
        [ M(0, 0x987bbcbfdd7e532fUL); M(8, 0xc3f2827affe7f664UL) ]
        [ M(0, 0xffffffffffffffffUL); M(8, 0x8000000000000000UL) ]
        [] ]
    check "a9010c22" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0xf893a2eefb32555eUL); M(8, 0x71c18690ee42c90bUL) ]
        [ M(0, 0x987bbcbfdd7e532fUL); M(8, 0xc3f2827affe7f664UL) ]
        [ M(0, 0xffffffffffffffffUL); M(8, 0x8000000000000000UL) ]
        [] ]
    check "28810c22" [ X(1, 0x2008000UL) ]
      [ [ X(1, 0x2008008UL); M(0, 0xee42c90bfb32555eUL) ]
        [ X(1, 0x2008008UL); M(0, 0xffe7f664dd7e532fUL) ]
        [ X(1, 0x2008008UL); M(0, 0xffffffffUL) ]
        [ X(1, 0x2008008UL); M(0, 0xaaaaaaaa55555555UL) ] ]

  /// C6.2.274 STR (immediate)
  [<TestMethod>]
  member _.``C6.2.274 STR``() =
    check "b8010420" [ X(1, 0x2008000UL) ]
      [ [ X(1, 0x2008010UL); M(0, 0xdb20290a89025cc1UL) ]
        [ X(1, 0x2008010UL); M(0, 0x912f822b1c9756ceUL) ]
        [ X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL); M(0, 0x55555555ffffffffUL) ] ]
    check "f8010420" [ X(1, 0x2008000UL) ]
      [ [ X(1, 0x2008010UL); M(0, 0x910a2dec89025cc1UL) ]
        [ X(1, 0x2008010UL); M(0, 0x975835de1c9756ceUL) ]
        [ X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL); M(0, 0xffffffffUL) ] ]
    check "b8010c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(1, 0x2008000UL); M(0, 0xdb20290a89025cc1UL) ]
        [ X(1, 0x2008000UL); M(0, 0x912f822b1c9756ceUL) ]
        [ X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL); M(0, 0x55555555ffffffffUL) ] ]
    check "f8010c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(1, 0x2008000UL); M(0, 0x910a2dec89025cc1UL) ]
        [ X(1, 0x2008000UL); M(0, 0x975835de1c9756ceUL) ]
        [ X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL); M(0, 0xffffffffUL) ] ]
    check "b9000020" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290a89025cc1UL) ]
        [ M(0, 0x912f822b1c9756ceUL) ]
        []
        [ M(0, 0x55555555ffffffffUL) ] ]
    check "b9000820" [ X(1, 0x2007ff8UL) ]
      [ [ M(0, 0xdb20290a89025cc1UL) ]
        [ M(0, 0x912f822b1c9756ceUL) ]
        []
        [ M(0, 0x55555555ffffffffUL) ] ]
    check "f9000020" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0x910a2dec89025cc1UL) ]
        [ M(0, 0x975835de1c9756ceUL) ]
        []
        [ M(0, 0xffffffffUL) ] ]
    check "f9000420" [ X(1, 0x2007ff8UL) ]
      [ [ M(0, 0x910a2dec89025cc1UL) ]
        [ M(0, 0x975835de1c9756ceUL) ]
        []
        [ M(0, 0xffffffffUL) ] ]
    check "b8000420" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290a89025cc1UL) ]
        [ M(0, 0x912f822b1c9756ceUL) ]
        []
        [ M(0, 0x55555555ffffffffUL) ] ]

  /// C6.2.276 STRB (immediate)
  [<TestMethod>]
  member _.``C6.2.276 STRB``() =
    check "38010420" [ X(1, 0x2008000UL) ]
      [ [ X(1, 0x2008010UL); M(0, 0xdb20290ac13e4ac1UL) ]
        [ X(1, 0x2008010UL); M(0, 0x912f822b1e8fe1ceUL) ]
        [ X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL); M(0, 0x55555555555555ffUL) ] ]
    check "38010c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(1, 0x2008000UL); M(0, 0xdb20290ac13e4ac1UL) ]
        [ X(1, 0x2008000UL); M(0, 0x912f822b1e8fe1ceUL) ]
        [ X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL); M(0, 0x55555555555555ffUL) ] ]
    check "39000020" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4ac1UL) ]
        [ M(0, 0x912f822b1e8fe1ceUL) ]
        []
        [ M(0, 0x55555555555555ffUL) ] ]
    check "39002020" [ X(1, 0x2007ff8UL) ]
      [ [ M(0, 0xdb20290ac13e4ac1UL) ]
        [ M(0, 0x912f822b1e8fe1ceUL) ]
        []
        [ M(0, 0x55555555555555ffUL) ] ]
    check "38226820" [ X(1, 0x2008000UL); X(2, 0x1UL) ]
      [ [ M(0, 0xdb20290ac13ec181UL) ]
        [ M(0, 0x912f822b1e8fcee4UL) ]
        []
        [ M(0, 0x555555555555ff55UL) ] ]
    check "38000420" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4ac1UL) ]
        [ M(0, 0x912f822b1e8fe1ceUL) ]
        []
        [ M(0, 0x55555555555555ffUL) ] ]

  /// C6.2.278 STRH (immediate)
  [<TestMethod>]
  member _.``C6.2.278 STRH``() =
    check "78010420" [ X(1, 0x2008000UL) ]
      [ [ X(1, 0x2008010UL); M(0, 0xdb20290ac13e5cc1UL) ]
        [ X(1, 0x2008010UL); M(0, 0x912f822b1e8f56ceUL) ]
        [ X(1, 0x2008010UL) ]
        [ X(1, 0x2008010UL); M(0, 0x555555555555ffffUL) ] ]
    check "78010c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(1, 0x2008000UL); M(0, 0xdb20290ac13e5cc1UL) ]
        [ X(1, 0x2008000UL); M(0, 0x912f822b1e8f56ceUL) ]
        [ X(1, 0x2008000UL) ]
        [ X(1, 0x2008000UL); M(0, 0x555555555555ffffUL) ] ]
    check "79000020" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e5cc1UL) ]
        [ M(0, 0x912f822b1e8f56ceUL) ]
        []
        [ M(0, 0x555555555555ffffUL) ] ]
    check "79001020" [ X(1, 0x2007ff8UL) ]
      [ [ M(0, 0xdb20290ac13e5cc1UL) ]
        [ M(0, 0x912f822b1e8f56ceUL) ]
        []
        [ M(0, 0x555555555555ffffUL) ] ]
    check "78000420" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e5cc1UL) ]
        [ M(0, 0x912f822b1e8f56ceUL) ]
        []
        [ M(0, 0x555555555555ffffUL) ] ]

  /// C6.2.280 STSETB, STSETLB
  [<TestMethod>]
  member _.``C6.2.280 STSETB``() =
    check "3822303f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4adfUL) ]
        [ M(0, 0x912f822b1e8fe1efUL) ]
        [ M(0, 0xffUL) ]
        [] ]

  /// C6.2.280 STSETB, STSETLB
  [<TestMethod>]
  member _.``C6.2.280 STSETLB``() =
    check "3862303f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4adfUL) ]
        [ M(0, 0x912f822b1e8fe1efUL) ]
        [ M(0, 0xffUL) ]
        [] ]

  /// C6.2.281 STSETH, STSETLH
  [<TestMethod>]
  member _.``C6.2.281 STSETH``() =
    check "7822303f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e5fdfUL) ]
        [ M(0, 0x912f822b1e8ff3efUL) ]
        [ M(0, 0xffffUL) ]
        [] ]

  /// C6.2.281 STSETH, STSETLH
  [<TestMethod>]
  member _.``C6.2.281 STSETLH``() =
    check "7862303f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e5fdfUL) ]
        [ M(0, 0x912f822b1e8ff3efUL) ]
        [ M(0, 0xffffUL) ]
        [] ]

  /// C6.2.282 STSET, STSETL
  [<TestMethod>]
  member _.``C6.2.282 STSET``() =
    check "f822303f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xfbb3abeefb3e5fdfUL) ]
        [ M(0, 0x997fbebfdffff3efUL) ]
        [ M(0, 0xffffffffffffffffUL) ]
        [] ]
    check "b822303f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290afb3e5fdfUL) ]
        [ M(0, 0x912f822bdffff3efUL) ]
        [ M(0, 0xffffffffUL) ]
        [] ]

  /// C6.2.282 STSET, STSETL
  [<TestMethod>]
  member _.``C6.2.282 STSETL``() =
    check "b862303f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290afb3e5fdfUL) ]
        [ M(0, 0x912f822bdffff3efUL) ]
        [ M(0, 0xffffffffUL) ]
        [] ]

  /// C6.2.283 STSMAXB, STSMAXLB
  [<TestMethod>]
  member _.``C6.2.283 STSMAXB``() =
    check "3822403f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4a5eUL) ]
        [ M(0, 0x912f822b1e8fe12fUL) ]
        []
        [] ]

  /// C6.2.283 STSMAXB, STSMAXLB
  [<TestMethod>]
  member _.``C6.2.283 STSMAXLB``() =
    check "3862403f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4a5eUL) ]
        [ M(0, 0x912f822b1e8fe12fUL) ]
        []
        [] ]

  /// C6.2.284 STSMAXH, STSMAXLH
  [<TestMethod>]
  member _.``C6.2.284 STSMAXH``() =
    check "7822403f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e555eUL) ]
        [ M(0, 0x912f822b1e8f532fUL) ]
        []
        [] ]

  /// C6.2.284 STSMAXH, STSMAXLH
  [<TestMethod>]
  member _.``C6.2.284 STSMAXLH``() =
    check "7862403f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e555eUL) ]
        [ M(0, 0x912f822b1e8f532fUL) ]
        []
        [] ]

  /// C6.2.285 STSMAX, STSMAXL
  [<TestMethod>]
  member _.``C6.2.285 STSMAX``() =
    check "f822403f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xf893a2eefb32555eUL) ]
        [ M(0, 0x987bbcbfdd7e532fUL) ]
        []
        [] ]
    check "b822403f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290afb32555eUL) ]
        []
        []
        [] ]

  /// C6.2.285 STSMAX, STSMAXL
  [<TestMethod>]
  member _.``C6.2.285 STSMAXL``() =
    check "b862403f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290afb32555eUL) ]
        []
        []
        [] ]

  /// C6.2.286 STSMINB, STSMINLB
  [<TestMethod>]
  member _.``C6.2.286 STSMINB``() =
    check "3822503f" [ X(1, 0x2008000UL) ] [ []; []; [ M(0, 0xffUL) ]; [] ]

  /// C6.2.286 STSMINB, STSMINLB
  [<TestMethod>]
  member _.``C6.2.286 STSMINLB``() =
    check "3862503f" [ X(1, 0x2008000UL) ] [ []; []; [ M(0, 0xffUL) ]; [] ]

  /// C6.2.287 STSMINH, STSMINLH
  [<TestMethod>]
  member _.``C6.2.287 STSMINH``() =
    check "7822503f" [ X(1, 0x2008000UL) ] [ []; []; [ M(0, 0xffffUL) ]; [] ]

  /// C6.2.287 STSMINH, STSMINLH
  [<TestMethod>]
  member _.``C6.2.287 STSMINLH``() =
    check "7862503f" [ X(1, 0x2008000UL) ] [ []; []; [ M(0, 0xffffUL) ]; [] ]

  /// C6.2.288 STSMIN, STSMINL
  [<TestMethod>]
  member _.``C6.2.288 STSMIN``() =
    check "f822503f" [ X(1, 0x2008000UL) ]
      [ []
        []
        [ M(0, 0xffffffffffffffffUL) ]
        [] ]
    check "b822503f" [ X(1, 0x2008000UL) ]
      [ []
        [ M(0, 0x912f822bdd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [] ]

  /// C6.2.288 STSMIN, STSMINL
  [<TestMethod>]
  member _.``C6.2.288 STSMINL``() =
    check "b862503f" [ X(1, 0x2008000UL) ]
      [ []
        [ M(0, 0x912f822bdd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [] ]

  /// C6.2.289 STTR
  [<TestMethod>]
  member _.``C6.2.289 STTR``() =
    check "b8010820" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0xdb20290a89025cc1UL) ]
        [ M(0, 0x912f822b1c9756ceUL) ]
        []
        [ M(0, 0x55555555ffffffffUL) ] ]
    check "f8000820" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0x910a2dec89025cc1UL) ]
        [ M(0, 0x975835de1c9756ceUL) ]
        []
        [ M(0, 0xffffffffUL) ] ]
    check "f8010820" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0x910a2dec89025cc1UL) ]
        [ M(0, 0x975835de1c9756ceUL) ]
        []
        [ M(0, 0xffffffffUL) ] ]
    check "b8000820" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290a89025cc1UL) ]
        [ M(0, 0x912f822b1c9756ceUL) ]
        []
        [ M(0, 0x55555555ffffffffUL) ] ]

  /// C6.2.290 STTRB
  [<TestMethod>]
  member _.``C6.2.290 STTRB``() =
    check "38010820" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0xdb20290ac13e4ac1UL) ]
        [ M(0, 0x912f822b1e8fe1ceUL) ]
        []
        [ M(0, 0x55555555555555ffUL) ] ]
    check "38000820" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4ac1UL) ]
        [ M(0, 0x912f822b1e8fe1ceUL) ]
        []
        [ M(0, 0x55555555555555ffUL) ] ]

  /// C6.2.291 STTRH
  [<TestMethod>]
  member _.``C6.2.291 STTRH``() =
    check "78010820" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0xdb20290ac13e5cc1UL) ]
        [ M(0, 0x912f822b1e8f56ceUL) ]
        []
        [ M(0, 0x555555555555ffffUL) ] ]
    check "78000820" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e5cc1UL) ]
        [ M(0, 0x912f822b1e8f56ceUL) ]
        []
        [ M(0, 0x555555555555ffffUL) ] ]

  /// C6.2.292 STUMAXB, STUMAXLB
  [<TestMethod>]
  member _.``C6.2.292 STUMAXB``() =
    check "3822603f" [ X(1, 0x2008000UL) ] [ []; []; [ M(0, 0xffUL) ]; [] ]

  /// C6.2.292 STUMAXB, STUMAXLB
  [<TestMethod>]
  member _.``C6.2.292 STUMAXLB``() =
    check "3862603f" [ X(1, 0x2008000UL) ] [ []; []; [ M(0, 0xffUL) ]; [] ]

  /// C6.2.293 STUMAXH, STUMAXLH
  [<TestMethod>]
  member _.``C6.2.293 STUMAXH``() =
    check "7822603f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e555eUL) ]
        []
        [ M(0, 0xffffUL) ]
        [] ]

  /// C6.2.293 STUMAXH, STUMAXLH
  [<TestMethod>]
  member _.``C6.2.293 STUMAXLH``() =
    check "7862603f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e555eUL) ]
        []
        [ M(0, 0xffffUL) ]
        [] ]

  /// C6.2.294 STUMAX, STUMAXL
  [<TestMethod>]
  member _.``C6.2.294 STUMAX``() =
    check "f822603f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xf893a2eefb32555eUL) ]
        [ M(0, 0x987bbcbfdd7e532fUL) ]
        [ M(0, 0xffffffffffffffffUL) ]
        [] ]
    check "b822603f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290afb32555eUL) ]
        [ M(0, 0x912f822bdd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [] ]

  /// C6.2.294 STUMAX, STUMAXL
  [<TestMethod>]
  member _.``C6.2.294 STUMAXL``() =
    check "b862603f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290afb32555eUL) ]
        [ M(0, 0x912f822bdd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [] ]

  /// C6.2.295 STUMINB, STUMINLB
  [<TestMethod>]
  member _.``C6.2.295 STUMINB``() =
    check "3822703f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4a5eUL) ]
        [ M(0, 0x912f822b1e8fe12fUL) ]
        []
        [] ]

  /// C6.2.295 STUMINB, STUMINLB
  [<TestMethod>]
  member _.``C6.2.295 STUMINLB``() =
    check "3862703f" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4a5eUL) ]
        [ M(0, 0x912f822b1e8fe12fUL) ]
        []
        [] ]

  /// C6.2.296 STUMINH, STUMINLH
  [<TestMethod>]
  member _.``C6.2.296 STUMINH``() =
    check "7822703f" [ X(1, 0x2008000UL) ]
      [ []
        [ M(0, 0x912f822b1e8f532fUL) ]
        []
        [] ]

  /// C6.2.296 STUMINH, STUMINLH
  [<TestMethod>]
  member _.``C6.2.296 STUMINLH``() =
    check "7862703f" [ X(1, 0x2008000UL) ]
      [ []
        [ M(0, 0x912f822b1e8f532fUL) ]
        []
        [] ]

  /// C6.2.297 STUMIN, STUMINL
  [<TestMethod>]
  member _.``C6.2.297 STUMIN``() =
    check "f822703f" [ X(1, 0x2008000UL) ] [ []; []; []; [] ]
    check "b822703f" [ X(1, 0x2008000UL) ] [ []; []; []; [] ]

  /// C6.2.297 STUMIN, STUMINL
  [<TestMethod>]
  member _.``C6.2.297 STUMINL``() =
    check "b862703f" [ X(1, 0x2008000UL) ] [ []; []; []; [] ]

  /// C6.2.298 STUR
  [<TestMethod>]
  member _.``C6.2.298 STUR``() =
    check "b8010020" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0xdb20290a89025cc1UL) ]
        [ M(0, 0x912f822b1c9756ceUL) ]
        []
        [ M(0, 0x55555555ffffffffUL) ] ]
    check "f8000020" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0x910a2dec89025cc1UL) ]
        [ M(0, 0x975835de1c9756ceUL) ]
        []
        [ M(0, 0xffffffffUL) ] ]
    check "f8010020" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0x910a2dec89025cc1UL) ]
        [ M(0, 0x975835de1c9756ceUL) ]
        []
        [ M(0, 0xffffffffUL) ] ]
    check "b8000020" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290a89025cc1UL) ]
        [ M(0, 0x912f822b1c9756ceUL) ]
        []
        [ M(0, 0x55555555ffffffffUL) ] ]

  /// C6.2.299 STURB
  [<TestMethod>]
  member _.``C6.2.299 STURB``() =
    check "38010020" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0xdb20290ac13e4ac1UL) ]
        [ M(0, 0x912f822b1e8fe1ceUL) ]
        []
        [ M(0, 0x55555555555555ffUL) ] ]
    check "38000020" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e4ac1UL) ]
        [ M(0, 0x912f822b1e8fe1ceUL) ]
        []
        [ M(0, 0x55555555555555ffUL) ] ]

  /// C6.2.300 STURH
  [<TestMethod>]
  member _.``C6.2.300 STURH``() =
    check "78010020" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0xdb20290ac13e5cc1UL) ]
        [ M(0, 0x912f822b1e8f56ceUL) ]
        []
        [ M(0, 0x555555555555ffffUL) ] ]
    check "78000020" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdb20290ac13e5cc1UL) ]
        [ M(0, 0x912f822b1e8f56ceUL) ]
        []
        [ M(0, 0x555555555555ffffUL) ] ]

  /// C6.2.301 STXP
  [<TestMethod>]
  member _.``C6.2.301 STXP``() =
    check "88230820" [ X(1, 0x2008000UL) ]
      [ [ X(3, 0x1UL) ]
        [ X(3, 0x1UL) ]
        [ X(3, 0x1UL) ]
        [ X(3, 0x1UL) ] ]

  /// C6.2.302 STXR
  [<TestMethod>]
  member _.``C6.2.302 STXR``() =
    check "88027c20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ] ]

  /// C6.2.303 STXRB
  [<TestMethod>]
  member _.``C6.2.303 STXRB``() =
    check "08027c20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ] ]

  /// C6.2.304 STXRH
  [<TestMethod>]
  member _.``C6.2.304 STXRH``() =
    check "48027c20" [ X(1, 0x2008000UL) ]
      [ [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ]
        [ X(2, 0x1UL) ] ]

  /// C6.2.305 STZ2G
  [<TestMethod>]
  member _.``C6.2.305 STZ2G``() =
    check "d9e00820" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0x0UL); M(8, 0x0UL); M(16, 0x0UL); M(24, 0x0UL) ]
        [ M(0, 0x0UL); M(8, 0x0UL); M(16, 0x0UL); M(24, 0x0UL) ]
        [ M(8, 0x0UL); M(16, 0x0UL); M(24, 0x0UL) ]
        [ M(0, 0x0UL); M(8, 0x0UL); M(16, 0x0UL); M(24, 0x0UL) ] ]
    check "d9e01420" [ X(1, 0x2008000UL) ]
      [ [ X(1, 0x2008010UL)
          M(0, 0x0UL)
          M(8, 0x0UL)
          M(16, 0x0UL)
          M(24, 0x0UL) ]
        [ X(1, 0x2008010UL)
          M(0, 0x0UL)
          M(8, 0x0UL)
          M(16, 0x0UL)
          M(24, 0x0UL) ]
        [ X(1, 0x2008010UL); M(8, 0x0UL); M(16, 0x0UL); M(24, 0x0UL) ]
        [ X(1, 0x2008010UL)
          M(0, 0x0UL)
          M(8, 0x0UL)
          M(16, 0x0UL)
          M(24, 0x0UL) ] ]
    check "d9e01c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(1, 0x2008000UL)
          M(0, 0x0UL)
          M(8, 0x0UL)
          M(16, 0x0UL)
          M(24, 0x0UL) ]
        [ X(1, 0x2008000UL)
          M(0, 0x0UL)
          M(8, 0x0UL)
          M(16, 0x0UL)
          M(24, 0x0UL) ]
        [ X(1, 0x2008000UL); M(8, 0x0UL); M(16, 0x0UL); M(24, 0x0UL) ]
        [ X(1, 0x2008000UL)
          M(0, 0x0UL)
          M(8, 0x0UL)
          M(16, 0x0UL)
          M(24, 0x0UL) ] ]
    check "d9e01820" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0x0UL); M(8, 0x0UL); M(16, 0x0UL); M(24, 0x0UL) ]
        [ M(0, 0x0UL); M(8, 0x0UL); M(16, 0x0UL); M(24, 0x0UL) ]
        [ M(8, 0x0UL); M(16, 0x0UL); M(24, 0x0UL) ]
        [ M(0, 0x0UL); M(8, 0x0UL); M(16, 0x0UL); M(24, 0x0UL) ] ]
    check "d9e00420" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0x0UL); M(8, 0x0UL); M(16, 0x0UL); M(24, 0x0UL) ]
        [ M(0, 0x0UL); M(8, 0x0UL); M(16, 0x0UL); M(24, 0x0UL) ]
        [ M(8, 0x0UL); M(16, 0x0UL); M(24, 0x0UL) ]
        [ M(0, 0x0UL); M(8, 0x0UL); M(16, 0x0UL); M(24, 0x0UL) ] ]

  /// C6.2.306 STZG
  [<TestMethod>]
  member _.``C6.2.306 STZG``() =
    check "d9600820" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0x0UL); M(8, 0x0UL) ]
        [ M(0, 0x0UL); M(8, 0x0UL) ]
        [ M(8, 0x0UL) ]
        [ M(0, 0x0UL); M(8, 0x0UL) ] ]
    check "d9601420" [ X(1, 0x2008000UL) ]
      [ [ X(1, 0x2008010UL); M(0, 0x0UL); M(8, 0x0UL) ]
        [ X(1, 0x2008010UL); M(0, 0x0UL); M(8, 0x0UL) ]
        [ X(1, 0x2008010UL); M(8, 0x0UL) ]
        [ X(1, 0x2008010UL); M(0, 0x0UL); M(8, 0x0UL) ] ]
    check "d9601c20" [ X(1, 0x2007ff0UL) ]
      [ [ X(1, 0x2008000UL); M(0, 0x0UL); M(8, 0x0UL) ]
        [ X(1, 0x2008000UL); M(0, 0x0UL); M(8, 0x0UL) ]
        [ X(1, 0x2008000UL); M(8, 0x0UL) ]
        [ X(1, 0x2008000UL); M(0, 0x0UL); M(8, 0x0UL) ] ]
    check "d9601820" [ X(1, 0x2007ff0UL) ]
      [ [ M(0, 0x0UL); M(8, 0x0UL) ]
        [ M(0, 0x0UL); M(8, 0x0UL) ]
        [ M(8, 0x0UL) ]
        [ M(0, 0x0UL); M(8, 0x0UL) ] ]
    check "d9600420" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0x0UL); M(8, 0x0UL) ]
        [ M(0, 0x0UL); M(8, 0x0UL) ]
        [ M(8, 0x0UL) ]
        [ M(0, 0x0UL); M(8, 0x0UL) ] ]

  /// C6.2.307 STZGM
  [<TestMethod>]
  member _.``C6.2.307 STZGM``() =
    raises BinIR.SideEffect.UndefinedInstruction "d9200020"

  /// C6.2.308 SUB (extended register)
  [<TestMethod>]
  member _.``C6.2.308 SUB``() =
    check "4b020020" []
      [ [ X(0, 0x6a5c9709UL) ]
        [ X(0, 0x2e7dcb13UL) ]
        [ X(0, 0x2UL) ]
        [ X(0, 0xaaaaaaabUL) ] ]
    check "51004020" []
      [ [ X(0, 0x658eec57UL) ]
        [ X(0, 0xbfc1e32UL) ]
        [ X(0, 0xfffffff1UL) ]
        [ X(0, 0xfffffff0UL) ] ]
    check "d1004020" []
      [ [ X(0, 0xbeeb8da1658eec57UL) ]
        [ X(0, 0xbfc846100bfc1e32UL) ]
        [ X(0, 0xfffffffffffffff1UL) ]
        [ X(0, 0xfffffff0UL) ] ]
    check "cb020020" []
      [ [ X(0, 0xc657eab26a5c9709UL) ]
        [ X(0, 0x274c89502e7dcb13UL) ]
        [ X(0, 0x2UL) ]
        [ X(0, 0xaaaaaaabaaaaaaabUL) ] ]
    check "2e228420" []
      [ [ Q(0, 0xe9c3410df2dee110UL, 0x0UL) ]
        [ Q(0, 0xfe7bd7b1763f4151UL, 0x0UL) ]
        [ Q(0, 0xff010101800000ffUL, 0x0UL) ]
        [ Q(0, 0xc008000000000000UL, 0x0UL) ] ]
    check "6e228420" []
      [ [ Q(0, 0xe9c3410df2dee110UL, 0xb5a8800ad0a81c22UL) ]
        [ Q(0, 0xfe7bd7b1763f4151UL, 0x9bd1f1597f46146dUL) ]
        [ Q(0, 0xff010101800000ffUL, 0x7f20000000410101UL) ]
        [ Q(0, 0xc008000000000000UL, 0xc0c999999999999aUL) ] ]
    check "2e628420" []
      [ [ Q(0, 0xe8c3410df1dee110UL, 0x0UL) ]
        [ Q(0, 0xfe7bd6b1753f4051UL, 0x0UL) ]
        [ Q(0, 0xff0100018000ffffUL, 0x0UL) ]
        [ Q(0, 0xc008000000000000UL, 0x0UL) ] ]
    check "6e628420" []
      [ [ Q(0, 0xe8c3410df1dee110UL, 0xb5a8800ad0a81b22UL) ]
        [ Q(0, 0xfe7bd6b1753f4051UL, 0x9ad1f0597e46146dUL) ]
        [ Q(0, 0xff0100018000ffffUL, 0x7f20000000410001UL) ]
        [ Q(0, 0xc008000000000000UL, 0xbfc999999999999aUL) ] ]
    check "2ea28420" []
      [ [ Q(0, 0xe8c3410df1dde110UL, 0x0UL) ]
        [ Q(0, 0xfe7ad6b1753f4051UL, 0x0UL) ]
        [ Q(0, 0xff0000017fffffffUL, 0x0UL) ]
        [ Q(0, 0xc008000000000000UL, 0x0UL) ] ]
    check "6ea28420" []
      [ [ Q(0, 0xe8c3410df1dde110UL, 0xb5a8800ad0a81b22UL) ]
        [ Q(0, 0xfe7ad6b1753f4051UL, 0x9ad0f0597e46146dUL) ]
        [ Q(0, 0xff0000017fffffffUL, 0x7f20000000400001UL) ]
        [ Q(0, 0xc008000000000000UL, 0xbfc999999999999aUL) ] ]
    check "6ee28420" []
      [ [ Q(0, 0xe8c3410cf1dde110UL, 0xb5a88009d0a81b22UL) ]
        [ Q(0, 0xfe7ad6b0753f4051UL, 0x9ad0f0587e46146dUL) ]
        [ Q(0, 0xff0000017fffffffUL, 0x7f20000000400001UL) ]
        [ Q(0, 0xc008000000000000UL, 0xbfc999999999999aUL) ] ]
    check "d13ffc20" []
      [ [ X(0, 0xbeeb8da1658edc68UL) ]
        [ X(0, 0xbfc846100bfc0e43UL) ]
        [ X(0, 0xfffffffffffff002UL) ]
        [ X(0, 0xfffff001UL) ] ]

  /// C6.2.311 SUBG
  [<TestMethod>]
  member _.``C6.2.311 SUBG``() =
    check "d1800020" []
      [ [ X(0, 0xb0eb8da1658eec67UL) ]
        [ X(0, 0xb0c846100bfc1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x100000000UL) ] ]

  /// C6.2.312 SUBP
  [<TestMethod>]
  member _.``C6.2.312 SUBP``() =
    check "9ac20020" []
      [ [ X(0, 0x57eab26a5c9709UL) ]
        [ X(0, 0xff4c89502e7dcb13UL) ]
        [ X(0, 0x2UL) ]
        [ X(0, 0xffaaaaabaaaaaaabUL) ] ]

  /// C6.2.313 SUBPS
  [<TestMethod>]
  member _.``C6.2.313 SUBPS``() =
    check "bac20020" []
      [ [ X(0, 0x57eab26a5c9709UL); Nzcv 0x20000000UL ]
        [ X(0, 0xff4c89502e7dcb13UL); Nzcv 0xa0000000UL ]
        [ X(0, 0x2UL); Nzcv 0x0UL ]
        [ X(0, 0xffaaaaabaaaaaaabUL); Nzcv 0x80000000UL ] ]

  /// C6.2.314 SUBS (extended register)
  [<TestMethod>]
  member _.``C6.2.314 SUBS``() =
    check "6b020020" []
      [ [ X(0, 0x6a5c9709UL); Nzcv 0x0UL ]
        [ X(0, 0x2e7dcb13UL); Nzcv 0x0UL ]
        [ X(0, 0x2UL); Nzcv 0x0UL ]
        [ X(0, 0xaaaaaaabUL); Nzcv 0x80000000UL ] ]
    check "71004020" []
      [ [ X(0, 0x658eec57UL); Nzcv 0x20000000UL ]
        [ X(0, 0xbfc1e32UL); Nzcv 0x20000000UL ]
        [ X(0, 0xfffffff1UL); Nzcv 0x80000000UL ]
        [ X(0, 0xfffffff0UL); Nzcv 0x80000000UL ] ]
    check "f1004020" []
      [ [ X(0, 0xbeeb8da1658eec57UL); Nzcv 0xa0000000UL ]
        [ X(0, 0xbfc846100bfc1e32UL); Nzcv 0xa0000000UL ]
        [ X(0, 0xfffffffffffffff1UL); Nzcv 0x80000000UL ]
        [ X(0, 0xfffffff0UL); Nzcv 0x20000000UL ] ]
    check "eb020020" []
      [ [ X(0, 0xc657eab26a5c9709UL); Nzcv 0x80000000UL ]
        [ X(0, 0x274c89502e7dcb13UL); Nzcv 0x20000000UL ]
        [ X(0, 0x2UL); Nzcv 0x0UL ]
        [ X(0, 0xaaaaaaabaaaaaaabUL); Nzcv 0x80000000UL ] ]
    check "f1600020" []
      [ [ X(0, 0xbeeb8da1650eec67UL); Nzcv 0xa0000000UL ]
        [ X(0, 0xbfc846100b7c1e42UL); Nzcv 0xa0000000UL ]
        [ X(0, 0xffffffffff800001UL); Nzcv 0x80000000UL ]
        [ X(0, 0xff800000UL); Nzcv 0x20000000UL ] ]

  /// <summary>
  /// SVC calls the kernel the oracle runs under, which would make a system
  /// call of whatever X8 holds, so it is not run. What the manual fixes is
  /// checked instead (C6.2.317): it ends the instruction in an exception
  /// that carries its 16-bit immediate, over every input set.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.317 SVC``() =
    for k in 0 .. A64Machine.sets - 1 do
      let found hex = A64Machine.effectsOver hex [] k
      let svc n = BinIR.SideEffect.Interrupt n
      Assert.AreEqual<BinIR.SideEffect list>([ svc 0 ], found "d4000001")
      Assert.AreEqual<BinIR.SideEffect list>([ svc 0x802 ], found "d4010041")

  /// C6.2.318 SWPB, SWPAB, SWPALB, SWPLB
  [<TestMethod>]
  member _.``C6.2.318 SWPAB``() =
    check "38a28020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4a5eUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe12fUL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL) ] ]

  /// C6.2.318 SWPB, SWPAB, SWPALB, SWPLB
  [<TestMethod>]
  member _.``C6.2.318 SWPALB``() =
    check "38e28020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4a5eUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe12fUL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL) ] ]

  /// C6.2.318 SWPB, SWPAB, SWPALB, SWPLB
  [<TestMethod>]
  member _.``C6.2.318 SWPB``() =
    check "38228020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4a5eUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe12fUL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL) ] ]

  /// C6.2.318 SWPB, SWPAB, SWPALB, SWPLB
  [<TestMethod>]
  member _.``C6.2.318 SWPLB``() =
    check "38628020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x81UL); M(0, 0xdb20290ac13e4a5eUL) ]
        [ X(0, 0xe4UL); M(0, 0x912f822b1e8fe12fUL) ]
        [ M(0, 0xffUL) ]
        [ X(0, 0x55UL) ] ]

  /// C6.2.319 SWPH, SWPAH, SWPALH, SWPLH
  [<TestMethod>]
  member _.``C6.2.319 SWPAH``() =
    check "78a28020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e555eUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8f532fUL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL) ] ]

  /// C6.2.319 SWPH, SWPAH, SWPALH, SWPLH
  [<TestMethod>]
  member _.``C6.2.319 SWPALH``() =
    check "78e28020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e555eUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8f532fUL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL) ] ]

  /// C6.2.319 SWPH, SWPAH, SWPALH, SWPLH
  [<TestMethod>]
  member _.``C6.2.319 SWPH``() =
    check "78228020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e555eUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8f532fUL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL) ] ]

  /// C6.2.319 SWPH, SWPAH, SWPALH, SWPLH
  [<TestMethod>]
  member _.``C6.2.319 SWPLH``() =
    check "78628020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0x4a81UL); M(0, 0xdb20290ac13e555eUL) ]
        [ X(0, 0xe1e4UL); M(0, 0x912f822b1e8f532fUL) ]
        [ M(0, 0xffffUL) ]
        [ X(0, 0x5555UL) ] ]

  /// C6.2.320 SWP, SWPA, SWPAL, SWPL
  [<TestMethod>]
  member _.``C6.2.320 SWP``() =
    check "f8228020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xdb20290ac13e4a81UL); M(0, 0xf893a2eefb32555eUL) ]
        [ X(0, 0x912f822b1e8fe1e4UL); M(0, 0x987bbcbfdd7e532fUL) ]
        [ M(0, 0xffffffffffffffffUL) ]
        [ X(0, 0x5555555555555555UL) ] ]
    check "b8228020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290afb32555eUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bdd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.320 SWP, SWPA, SWPAL, SWPL
  [<TestMethod>]
  member _.``C6.2.320 SWPA``() =
    check "b8a28020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290afb32555eUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bdd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.320 SWP, SWPA, SWPAL, SWPL
  [<TestMethod>]
  member _.``C6.2.320 SWPAL``() =
    check "b8e28020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290afb32555eUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bdd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.320 SWP, SWPA, SWPAL, SWPL
  [<TestMethod>]
  member _.``C6.2.320 SWPL``() =
    check "b8628020" [ X(1, 0x2008000UL) ]
      [ [ X(0, 0xc13e4a81UL); M(0, 0xdb20290afb32555eUL) ]
        [ X(0, 0x1e8fe1e4UL); M(0, 0x912f822bdd7e532fUL) ]
        [ M(0, 0xffffffffUL) ]
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.321 SXTB
  [<TestMethod>]
  member _.``C6.2.321 SXTB``() =
    check "13001c20" []
      [ [ X(0, 0x67UL) ]
        [ X(0, 0x42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]
    check "93401c20" []
      [ [ X(0, 0x67UL) ]
        [ X(0, 0x42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.322 SXTH
  [<TestMethod>]
  member _.``C6.2.322 SXTH``() =
    check "13003c20" []
      [ [ X(0, 0xffffec67UL) ]
        [ X(0, 0x1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]
    check "93403c20" []
      [ [ X(0, 0xffffffffffffec67UL) ]
        [ X(0, 0x1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.323 SXTW
  [<TestMethod>]
  member _.``C6.2.323 SXTW``() =
    check "93407c20" []
      [ [ X(0, 0x658eec67UL) ]
        [ X(0, 0xbfc1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.324 SYS
  [<TestMethod>]
  member _.``C6.2.324 SYS``() =
    raises BinIR.SideEffect.UndefinedInstruction "d50b7380"
    raises BinIR.SideEffect.UndefinedInstruction "d50b73e0"
    raises BinIR.SideEffect.UndefinedInstruction "d50b73a0"
    check "d50b7b21" [] [ []; []; []; [] ]
    raises BinIR.SideEffect.UndefinedInstruction "d5087841"
    check "d50b7e21" [] [ []; []; []; [] ]
    check "d50b7521" [] [ []; []; []; [] ]
    raises BinIR.SideEffect.UndefinedInstruction "d508871f"

  /// C6.2.325 SYSL
  [<TestMethod>]
  member _.``C6.2.325 SYSL``() =
    raises BinIR.SideEffect.UndefinedInstruction "d5290000"

  /// <summary>
  /// TBNZ cannot run in the oracle, which has nowhere for it to go, so
  /// this checks the jump: a conditional one out of the instruction, to
  /// its own address plus imm14 times four where the bit it names is 1
  /// and to the next instruction where it is not, with that bit alone
  /// set and alone clear, bit 3, 0 and 63 among them (C6.2.326).
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.326 TBNZ``() =
    Assert.AreEqual<string option>(Some "InterCJmp", exitOf "37000081")
    goesTo "37000081" [ X(1, 0x1UL) ] (A64Machine.code + 0x10UL)
    goesTo "37000081" [ X(1, 0xfffffffffffffffeUL) ] (A64Machine.code + 0x4UL)
    Assert.AreEqual<string option>(Some "InterCJmp", exitOf "b7f80201")
    goesTo "b7f80201" [ X(1, 0x8000000000000000UL) ] (A64Machine.code + 0x40UL)
    goesTo "b7f80201" [ X(1, 0x7fffffffffffffffUL) ] (A64Machine.code + 0x4UL)

  /// <summary>
  /// TBZ cannot run in the oracle, which has nowhere for it to go, so
  /// this checks the jump: a conditional one out of the instruction, to
  /// its own address plus imm14 times four where the bit it names is 0
  /// and to the next instruction where it is not, with that bit alone
  /// set and alone clear, bit 3, 0 and 63 among them (C6.2.327).
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.327 TBZ``() =
    Assert.AreEqual<string option>(Some "InterCJmp", exitOf "36180041")
    goesTo "36180041" [ X(1, 0x8UL) ] (A64Machine.code + 0x4UL)
    goesTo "36180041" [ X(1, 0xfffffffffffffff7UL) ] (A64Machine.code + 0x8UL)
    Assert.AreEqual<string option>(Some "InterCJmp", exitOf "b6f80201")
    goesTo "b6f80201" [ X(1, 0x8000000000000000UL) ] (A64Machine.code + 0x4UL)
    goesTo "b6f80201" [ X(1, 0x7fffffffffffffffUL) ] (A64Machine.code + 0x40UL)

  /// C6.2.328 TLBI
  [<TestMethod>]
  member _.``C6.2.328 TLBI``() =
    raises BinIR.SideEffect.UndefinedInstruction "d508871f"

  /// C6.2.329 TSB CSYNC
  [<TestMethod>]
  member _.``C6.2.329 TSB``() =
    check "d503225f" [] [ []; []; []; [] ]

  /// C6.2.330 TST (immediate)
  [<TestMethod>]
  member _.``C6.2.330 TST``() =
    check "f240783f" []
      [ [ Nzcv 0x0UL ]
        [ Nzcv 0x0UL ]
        [ Nzcv 0x0UL ]
        [ Nzcv 0x40000000UL ] ]
    check "721c003f" []
      [ [ Nzcv 0x40000000UL ]
        [ Nzcv 0x40000000UL ]
        [ Nzcv 0x40000000UL ]
        [ Nzcv 0x40000000UL ] ]
    check "f27c003f" []
      [ [ Nzcv 0x40000000UL ]
        [ Nzcv 0x40000000UL ]
        [ Nzcv 0x40000000UL ]
        [ Nzcv 0x40000000UL ] ]
    check "6a02003f" []
      [ [ Nzcv 0x0UL ]
        [ Nzcv 0x0UL ]
        [ Nzcv 0x0UL ]
        [ Nzcv 0x40000000UL ] ]
    check "ea02003f" []
      [ [ Nzcv 0x80000000UL ]
        [ Nzcv 0x80000000UL ]
        [ Nzcv 0x0UL ]
        [ Nzcv 0x0UL ] ]

  /// C6.2.332 UBFIZ
  [<TestMethod>]
  member _.``C6.2.332 UBFIZ``() =
    check "531d1020" []
      [ [ X(0, 0x38UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0x8UL) ]
        [ X(0, 0x0UL) ] ]
    check "d37d1020" []
      [ [ X(0, 0x38UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0x8UL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.333 UBFM
  [<TestMethod>]
  member _.``C6.2.333 UBFM``() =
    check "531f7820" []
      [ [ X(0, 0xcb1dd8ceUL) ]
        [ X(0, 0x17f83c84UL) ]
        [ X(0, 0x2UL) ]
        [ X(0, 0x0UL) ] ]
    check "d37ff820" []
      [ [ X(0, 0x7dd71b42cb1dd8ceUL) ]
        [ X(0, 0x7f908c2017f83c84UL) ]
        [ X(0, 0x2UL) ]
        [ X(0, 0x200000000UL) ] ]
    check "53017c20" []
      [ [ X(0, 0x32c77633UL) ]
        [ X(0, 0x5fe0f21UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "d341fc20" []
      [ [ X(0, 0x5f75c6d0b2c77633UL) ]
        [ X(0, 0x5fe4230805fe0f21UL) ]
        []
        [ X(0, 0x80000000UL) ] ]
    check "531d1020" []
      [ [ X(0, 0x38UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0x8UL) ]
        [ X(0, 0x0UL) ] ]
    check "d37d1020" []
      [ [ X(0, 0x38UL) ]
        [ X(0, 0x10UL) ]
        [ X(0, 0x8UL) ]
        [ X(0, 0x0UL) ] ]
    check "53031420" []
      [ [ X(0, 0x4UL) ]
        [ X(0, 0x0UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "d3431420" []
      [ [ X(0, 0x4UL) ]
        [ X(0, 0x0UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "53031c20" []
      [ [ X(0, 0xcUL) ]
        [ X(0, 0x8UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "d3431c20" []
      [ [ X(0, 0xcUL) ]
        [ X(0, 0x8UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "d3400020" []
      [ [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]
    check "53001c20" []
      [ [ X(0, 0x67UL) ]
        [ X(0, 0x42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]
    check "53003c20" []
      [ [ X(0, 0xec67UL) ]
        [ X(0, 0x1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]
    check "d3430820" []
      [ [ X(0, 0xe000000000000000UL) ]
        [ X(0, 0x4000000000000000UL) ]
        [ X(0, 0x2000000000000000UL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.334 UBFX
  [<TestMethod>]
  member _.``C6.2.334 UBFX``() =
    check "53031420" []
      [ [ X(0, 0x4UL) ]
        [ X(0, 0x0UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "d3431420" []
      [ [ X(0, 0x4UL) ]
        [ X(0, 0x0UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "53031c20" []
      [ [ X(0, 0xcUL) ]
        [ X(0, 0x8UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "d3431c20" []
      [ [ X(0, 0xcUL) ]
        [ X(0, 0x8UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "d3400020" []
      [ [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.335 UDF
  [<TestMethod>]
  member _.``C6.2.335 UDF``() =
    raises BinIR.SideEffect.UndefinedInstruction "00000005"

  /// C6.2.336 UDIV
  [<TestMethod>]
  member _.``C6.2.336 UDIV``() =
    check "1ac20820" []
      [ [ X(0, 0x0UL) ]
        [ X(0, 0x0UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "9ac20820" []
      [ [ X(0, 0x0UL) ]
        [ X(0, 0x1UL) ]
        []
        [ X(0, 0x0UL) ] ]

  /// C6.2.337 UMADDL
  [<TestMethod>]
  member _.``C6.2.337 UMADDL``() =
    check "9ba20c20" []
      [ [ X(0, 0xd568a021d659c9ddUL) ]
        [ X(0, 0xce511295cf7cea82UL) ]
        [ X(0, 0x80000000ffffffffUL) ]
        [ X(0, 0xaaaaaaaaaaaaaaaaUL) ] ]

  /// C6.2.338 UMNEGL
  [<TestMethod>]
  member _.``C6.2.338 UMNEGL``() =
    check "9ba2fc20" []
      [ [ X(0, 0x9c58e66f17e8ff2eUL) ]
        [ X(0, 0xf5a16fe5306b0be2UL) ]
        [ X(0, 0xffffffff00000001UL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.339 UMSUBL
  [<TestMethod>]
  member _.``C6.2.339 UMSUBL``() =
    check "9ba28c20" []
      [ [ X(0, 0xe1a6d00062bc839UL) ]
        [ X(0, 0xb993f26030530246UL) ]
        [ X(0, 0x7fffffff00000001UL) ]
        [ X(0, 0xaaaaaaaaaaaaaaaaUL) ] ]

  /// C6.2.340 UMULH
  [<TestMethod>]
  member _.``C6.2.340 UMULH``() =
    check "9bc27c20" []
      [ [ X(0, 0xb9624bf9f80411efUL) ]
        [ X(0, 0x723b9c3a00a20a3fUL) ]
        []
        [ X(0, 0x55555555UL) ] ]

  /// C6.2.341 UMULL
  [<TestMethod>]
  member _.``C6.2.341 UMULL``() =
    check "2f52a020" []
      [ [ Q(0, 0x18c232484c27c3c8UL, 0x2630163e25c81aa2UL) ]
        [ Q(0, 0x56d1e330906f4140UL, 0x502c5a8077c73b10UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "2fa2a020" []
      [ [ Q(0, 0x26997fa272e2cbb8UL, 0x3b88d204d6ed363eUL) ]
        [ Q(0, 0x212945b6a627d850UL, 0x1e9f5809ce1948c4UL) ]
        [ Q(0, 0x403fffff80000000UL, 0x3fffbfff80800000UL) ]
        [ Q(0, 0x0UL, 0x2004000000000000UL) ] ]
    check "2e22c020" []
      [ [ Q(0, 0x1830da48df200150UL, 0x3b103bde13f2063eUL) ]
        [ Q(0, 0x56770c3039661dacUL, 0x1e3f3c28580410c4UL) ]
        [ Q(0, 0x0UL, 0x3f803f8000000000UL) ]
        [ Q(0, 0x0UL, 0x2000000000000000UL) ] ]
    check "2e62c020" []
      [ [ Q(0, 0x18c23248df466550UL, 0x3b8882de1409363eUL) ]
        [ Q(0, 0x56d1e33039f56bacUL, 0x1e9eef28585848c4UL) ]
        [ Q(0, 0x0UL, 0x3fff408000000000UL) ]
        [ Q(0, 0x0UL, 0x2004000000000000UL) ] ]
    check "2ea2c020" []
      [ [ Q(0, 0x18c2c707315e6550UL, 0x3b88d204d6ed363eUL) ]
        [ Q(0, 0x56d2967647926bacUL, 0x1e9f5809ce1948c4UL) ]
        [ Q(0, 0x80000000UL, 0x3fffbfff80800000UL) ]
        [ Q(0, 0x0UL, 0x2004000000000000UL) ] ]
    check "9ba27c20" []
      [ [ X(0, 0x63a71990e81700d2UL) ]
        [ X(0, 0xa5e901acf94f41eUL) ]
        [ X(0, 0xffffffffUL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.342 UXTB
  [<TestMethod>]
  member _.``C6.2.342 UXTB``() =
    check "53001c20" []
      [ [ X(0, 0x67UL) ]
        [ X(0, 0x42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]

  /// C6.2.343 UXTH
  [<TestMethod>]
  member _.``C6.2.343 UXTH``() =
    check "53003c20" []
      [ [ X(0, 0xec67UL) ]
        [ X(0, 0x1e42UL) ]
        [ X(0, 0x1UL) ]
        [ X(0, 0x0UL) ] ]

  /// <summary>
  /// WFE waits for an event, which may never come, so the oracle does not
  /// run it. With one thread and nothing to wait for, the manual
  /// leaves it nothing a program can see (C6.2.344): it lifts to no
  /// statement.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.344 WFE``() =
    Assert.AreEqual<string list>([], statementsOf "d503205f")

  /// <summary>
  /// WFI waits for an interrupt, which may never come, so the oracle does not
  /// run it. With one thread and nothing to wait for, the manual
  /// leaves it nothing a program can see (C6.2.345): it lifts to no
  /// statement.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.345 WFI``() =
    Assert.AreEqual<string list>([], statementsOf "d503207f")

  /// C6.2.346 XAFLAG
  [<TestMethod>]
  member _.``C6.2.346 XAFLAG``() =
    check "d500403f" []
      [ [ Nzcv 0x80000000UL ]
        [ Nzcv 0x30000000UL ]
        []
        [ Nzcv 0x80000000UL ] ]

  /// <summary>
  /// The oracle's process runs with TCR_EL1.TBI0 set, as Linux sets it,
  /// under which Strip() keeps the top byte; this front end models TBI
  /// off for pointer authentication, as stripPAC says, so the oracle's
  /// values are not this model's. What Strip() gives with TBI off is
  /// checked instead (C6.2.347): bit 55 copied over bits 63:48 of X0, over
  /// every input set; and a canonical pointer PAC signed comes back, as
  /// the oracle agrees.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.347 XPACD``() =
    check "dac147e0" []
      [ [ X(0, 0x2dec89025cc1UL) ]
        [ X(0, 0x35de1c9756ceUL) ]
        []
        [] ]
    let back = A64Machine.after [ "dac10820"; "dac147e0" ] [ X(0, pointer) ]
    for k in 0 .. A64Machine.sets - 1 do
      Assert.AreEqual<uint64>(pointer, (back k).Xs[0], "dac147e0")

  /// <summary>
  /// The oracle's process runs with TCR_EL1.TBI0 set, as Linux sets it,
  /// under which Strip() keeps the top byte; this front end models TBI
  /// off for pointer authentication, as stripPAC says, so the oracle's
  /// values are not this model's. What Strip() gives with TBI off is
  /// checked instead (C6.2.347): bit 55 copied over bits 63:48 of X0, over
  /// every input set; and a canonical pointer PAC signed comes back, as
  /// the oracle agrees.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.347 XPACI``() =
    check "dac143e0" []
      [ [ X(0, 0x2dec89025cc1UL) ]
        [ X(0, 0x35de1c9756ceUL) ]
        []
        [] ]
    let back = A64Machine.after [ "dac10020"; "dac143e0" ] [ X(0, pointer) ]
    for k in 0 .. A64Machine.sets - 1 do
      Assert.AreEqual<uint64>(pointer, (back k).Xs[0], "dac143e0")

  /// <summary>
  /// The oracle's process runs with TCR_EL1.TBI0 set, as Linux sets it,
  /// under which Strip() keeps the top byte; this front end models TBI
  /// off for pointer authentication, as stripPAC says, so the oracle's
  /// values are not this model's. What Strip() gives with TBI off is
  /// checked instead (C6.2.347): bit 55 copied over bits 63:48 of X30, over
  /// every input set; and a canonical pointer PAC signed comes back, as
  /// the oracle agrees.
  /// </summary>
  [<TestMethod>]
  member _.``C6.2.347 XPACLRI``() =
    check "d50320ff" []
      [ [ X(30, 0xd70b12c5d084UL) ]
        [ X(30, 0xffffd92ab490c639UL) ]
        [ X(30, 0x80000000UL) ]
        [] ]
    let back = A64Machine.after [ "d503233f"; "d50320ff" ] [ X(30, pointer) ]
    for k in 0 .. A64Machine.sets - 1 do
      Assert.AreEqual<uint64>(pointer, (back k).Xs[30], "d50320ff")

  /// C6.2.348 YIELD
  [<TestMethod>]
  member _.``C6.2.348 YIELD``() =
    check "d503203f" [] [ []; []; []; [] ]

  /// C7.2.1 ABS
  [<TestMethod>]
  member _.``C7.2.1 ABS``() =
    check "0e20b820" []
      [ [ Q(0, 0x70616f2f4824201cUL, 0x0UL) ]
        [ Q(0, 0x57387d255f0f6224UL, 0x0UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "0e60b820" []
      [ [ Q(0, 0x70616f2f48dc1fe4UL, 0x0UL) ]
        [ Q(0, 0x57c87cdb5f0f61dcUL, 0x0UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4e60b820" []
      [ [ Q(0, 0x70616f2f48dc1fe4UL, 0x40d67db22ef303e9UL) ]
        [ Q(0, 0x57c87cdb5f0f61dcUL, 0x1dcf1b535f1f4f57UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x7fa000007fc00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fb9666766676666UL) ] ]
    check "0ea0b820" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x0UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4ea0b820" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x40d6824e2ef3fc17UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x1dcee4ad5f1fb0a9UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x7fa000007fc00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fb9999966666666UL) ] ]
    check "4ee0b820" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x40d6824e2ef3fc17UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x1dcee4aca0e04f57UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x7fa000007fc00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fb999999999999aUL) ] ]
    check "4e20b820" []
      [ [ Q(0, 0x70616f2f4824201cUL, 0x402a7e4e2e0d0417UL) ]
        [ Q(0, 0x57387d255f0f6224UL, 0x1e311b535f1f5057UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x7f6000007f400000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3f47676767676766UL) ] ]

  /// C7.2.3 ADDHN, ADDHN2
  [<TestMethod>]
  member _.``C7.2.3 ADDHN``() =
    check "0e624020" []
      [ [ Q(0, 0xcc048d3ff7ff9fdbUL, 0x0UL) ]
        [ Q(0, 0x29913ff9b11648dfUL, 0x0UL) ]
        [ Q(0, 0x8020ff3fffff8000UL, 0x0UL) ]
        [ Q(0, 0xbfa99999c0080000UL, 0x0UL) ] ]
    check "0ea24020" []
      [ [ Q(0, 0xcc048492f7ff9d51UL, 0x0UL) ]
        [ Q(0, 0x2991464eb1162f9aUL, 0x0UL) ]
        [ Q(0, 0x80200000ffffffffUL, 0x0UL) ]
        [ Q(0, 0xbfa99999c0080000UL, 0x0UL) ] ]
    check "0e224020" []
      [ [ Q(0, 0xcc848dddf79d9fdfUL, 0x0UL) ]
        [ Q(0, 0x29463f4cb12f48fbUL, 0x0UL) ]
        [ Q(0, 0x8000ffffffff8000UL, 0x0UL) ]
        [ Q(0, 0xbf999999c0000000UL, 0x0UL) ] ]

  /// C7.2.3 ADDHN, ADDHN2
  [<TestMethod>]
  member _.``C7.2.3 ADDHN2``() =
    check "4e624020" []
      [ [ Q(0, 0x962b1967c90789baUL, 0xcc048d3ff7ff9fdbUL) ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0x29913ff9b11648dfUL) ]
        [ Q(0, 0xbfc000003f800000UL, 0x8020ff3fffff8000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xbfa99999c0080000UL) ] ]
    check "4ea24020" []
      [ [ Q(0, 0x962b1967c90789baUL, 0xcc048492f7ff9d51UL) ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0x2991464eb1162f9aUL) ]
        [ Q(0, 0xbfc000003f800000UL, 0x80200000ffffffffUL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xbfa99999c0080000UL) ] ]
    check "4e224020" []
      [ [ Q(0, 0x962b1967c90789baUL, 0xcc848dddf79d9fdfUL) ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0x29463f4cb12f48fbUL) ]
        [ Q(0, 0xbfc000003f800000UL, 0x8000ffffffff8000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xbf999999c0000000UL) ] ]

  /// C7.2.4 ADDP (scalar)
  [<TestMethod>]
  member _.``C7.2.4 ADDP``() =
    check "0e22bc20" []
      [ [ Q(0, 0x2550540bd19e24fcUL, 0x0UL) ]
        [ Q(0, 0xa620b9301fa86ec2UL, 0x0UL) ]
        [ Q(0, 0xfffe0001ff008000UL, 0x0UL) ]
        [ Q(0, 0x8000000048000000UL, 0x0UL) ] ]
    check "4e22bc20" []
      [ [ Q(0, 0x16d02113d19e24fcUL, 0xb946a9d52550540bUL) ]
        [ Q(0, 0x136e7e591fa86ec2UL, 0xa724b9d8a620b930UL) ]
        [ Q(0, 0x1f003f00ff008000UL, 0x8000fefefffe0001UL) ]
        [ Q(0, 0xf832323348000000UL, 0x6f00000080000000UL) ] ]
    check "0e62bc20" []
      [ [ Q(0, 0xb5c0560adf9028f8UL, 0x0UL) ]
        [ Q(0, 0x5c147a3daedfd33UL, 0x0UL) ]
        [ Q(0, 0x807e00017f808000UL, 0x0UL) ]
        [ Q(0, 0x8000000040080000UL, 0x0UL) ] ]
    check "4e62bc20" []
      [ [ Q(0, 0xc3242b0adf9028f8UL, 0x8d723f40b5c0560aUL) ]
        [ Q(0, 0xfd840fc8daedfd33UL, 0x725a7d1505c147a3UL) ]
        [ Q(0, 0x7fa07fc07f808000UL, 0x807f7e807e0001UL) ]
        [ Q(0, 0xd952333340080000UL, 0x7ff0000080000000UL) ] ]
    check "0ea2bc20" []
      [ [ Q(0, 0xde9d2d2eb93e4f4bUL, 0x0UL) ]
        [ Q(0, 0x431e0a47b6d82149UL, 0x0UL) ]
        [ Q(0, 0x80800000ff800000UL, 0x0UL) ]
        [ Q(0, 0x8000000040080000UL, 0x0UL) ] ]
    check "4ee2bc20" []
      [ [ Q(0, 0xb137f17d77d0dc33UL, 0x12cc3066b54ae001UL) ]
        [ Q(0, 0x39f99e78be2f4ecdUL, 0xa0add76fcaa9fa0fUL) ]
        [ Q(0, 0xff200000ffc00000UL, 0x80ffffff7f800000UL) ]
        [ Q(0, 0x7fc199999999999aUL, 0xfff0000000000000UL) ] ]
    check "4ea2bc20" []
      [ [ Q(0, 0x6fca7e65b93e4f4bUL, 0xe979e339de9d2d2eUL) ]
        [ Q(0, 0x4150cbfcb6d82149UL, 0x2839c736431e0a47UL) ]
        [ Q(0, 0xff600000ff800000UL, 0x7fffffff80800000UL) ]
        [ Q(0, 0xd953333340080000UL, 0x7ff0000080000000UL) ] ]

  /// C7.2.6 ADDV
  [<TestMethod>]
  member _.``C7.2.6 ADDV``() =
    check "4eb1b820" []
      [ [ Q(0, 0x2908cdb0UL, 0x0UL) ]
        [ Q(0, 0xf828ed45UL, 0x0UL) ]
        [ Q(0, 0xfee00000UL, 0x0UL) ]
        [ Q(0, 0x195b3333UL, 0x0UL) ] ]

  /// <summary>
  /// AESD is InvSubBytes(InvShiftRows(Vd EOR Vn)) (C7.2.7); with no AES
  /// unit in IRRunner it is checked as the statements it lifts to: the EOR
  /// of the two registers handed to AESDECLAST with a zero round key,
  /// which is InvShiftRows then InvSubBytes then the EOR of that key.
  /// </summary>
  [<TestMethod>]
  member _.``C7.2.7 AESD``() =
    let expected =
      [ "T_1:I128 := AESDECLAST(((V0B ++ V0A) ^ (V1B ++ V1A)), 0x0:I128):I128"
        "V0A := (T_1:I128[63:0])"
        "V0B := (T_1:I128[127:64])" ]
    Assert.AreEqual<string list>(expected, statementsOf "4e285820")

  /// <summary>
  /// AESE is SubBytes(ShiftRows(Vd EOR Vn)) (C7.2.8); with no AES unit in
  /// IRRunner it is checked as the statements it lifts to: the EOR of the
  /// two registers handed to AESENCLAST with a zero round key, which is
  /// ShiftRows then SubBytes then the EOR of that zero key.
  /// </summary>
  [<TestMethod>]
  member _.``C7.2.8 AESE``() =
    let expected =
      [ "T_1:I128 := AESENCLAST(((V0B ++ V0A) ^ (V1B ++ V1A)), 0x0:I128):I128"
        "V0A := (T_1:I128[63:0])"
        "V0B := (T_1:I128[127:64])" ]
    Assert.AreEqual<string list>(expected, statementsOf "4e284820")

  /// <summary>
  /// AESIMC is InvMixColumns(Vn) (C7.2.9); with no AES unit in IRRunner
  /// it is checked as the statements it lifts to: Vn handed to AESIMC,
  /// which is InvMixColumns.
  /// </summary>
  [<TestMethod>]
  member _.``C7.2.9 AESIMC``() =
    let expected =
      [ "T_1:I128 := AESIMC((V1B ++ V1A)):I128"
        "V0A := (T_1:I128[63:0])"
        "V0B := (T_1:I128[127:64])" ]
    Assert.AreEqual<string list>(expected, statementsOf "4e287820")

  /// <summary>
  /// AESMC is MixColumns(Vn) (C7.2.10); with no AES unit in IRRunner it is
  /// checked as the statements it lifts to: AESDECLAST with a zero key
  /// undoes the ShiftRows and SubBytes AESENC with a zero key then does,
  /// which leaves AESENC's MixColumns alone.
  /// </summary>
  [<TestMethod>]
  member _.``C7.2.10 AESMC``() =
    let expected =
      [ "T_1:I128 := AESDECLAST((V1B ++ V1A), 0x0:I128):I128"
        "T_1:I128 := AESENC(T_1:I128, 0x0:I128):I128"
        "V0A := (T_1:I128[63:0])"
        "V0B := (T_1:I128[127:64])" ]
    Assert.AreEqual<string list>(expected, statementsOf "4e286820")

  /// C7.2.12 BCAX
  [<TestMethod>]
  member _.``C7.2.12 BCAX``() =
    check "ce220c20" []
      [ [ Q(0, 0x7073492f1e164c10UL, 0x4ad2800a66f39cf2UL) ]
        [ Q(0, 0xe88a34536cf9626UL, 0xe3311353bfdeac91UL) ]
        [ Q(0, 0x7f97ffff80000000UL, 0x7fa000003fbfffffUL) ]
        [ Q(0, 0xc008000000000000UL, 0x3fb999999999999aUL) ] ]

  /// C7.2.13 BFCVT
  [<TestMethod>]
  member _.``C7.2.13 BFCVT``() =
    check "1e634020" []
      [ [ Q(0, 0x48ddUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x5f10UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x8000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]

  /// C7.2.14 BFCVTN, BFCVTN2
  [<TestMethod>]
  member _.``C7.2.14 BFCVTN``() =
    check "0ea16820" []
      [ [ Q(0, 0x40d72ef4706148ddUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xe2315f2057c95f10UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x7fe07fc07f808000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x3fba999a40080000UL, 0x0UL); Fpsr 0x10UL ] ]

  /// C7.2.14 BFCVTN, BFCVTN2
  [<TestMethod>]
  member _.``C7.2.14 BFCVTN2``() =
    check "4ea16820" []
      [ [ Q(0, 0x962b1967c90789baUL, 0x40d72ef4706148ddUL); Fpsr 0x10UL ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0xe2315f2057c95f10UL); Fpsr 0x10UL ]
        [ Q(0, 0xbfc000003f800000UL, 0x7fe07fc07f808000UL); Fpsr 0x1UL ]
        [ Q(0, 0x3ff0000000000000UL, 0x3fba999a40080000UL); Fpsr 0x10UL ] ]

  /// C7.2.15 BFDOT (by element)
  [<TestMethod>]
  member _.``C7.2.15 BFDOT``() =
    check "2e42fc20" []
      [ [ Q(0, 0x5ddd7bff7f800000UL, 0x0UL) ]
        [ Q(0, 0x71a027ffff800000UL, 0x0UL) ]
        [ Q(0, 0x7fc000003f800000UL, 0x0UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ] ]
    check "0f62f020" []
      [ [ Q(0, 0x5ddd7bffcec580f3UL, 0x0UL) ]
        [ Q(0, 0x71a027ff78e50601UL, 0x0UL) ]
        [ Q(0, 0x7fc000007fc00000UL, 0x0UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ] ]
    check "4f62f020" []
      [ [ Q(0, 0x5ddd7bffcec580f3UL, 0x65ace267eabf1bffUL) ]
        [ Q(0, 0x71a027ff78e50601UL, 0xfc0dbd0178fea601UL) ]
        [ Q(0, 0x7fc000007fc00000UL, 0x7fc000007fc00000UL) ]
        [] ]
    check "6e42fc20" []
      [ [ Q(0, 0x5ddd7bff7f800000UL, 0x65ace2677f800000UL) ]
        [ Q(0, 0x71a027ffff800000UL, 0xea1adfffff800000UL) ]
        [ Q(0, 0x7fc000003f800000UL, 0x7fc000007fc00000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x7fc0000000000000UL) ] ]

  /// C7.2.17 BFMLALB, BFMLALT (by element)
  [<TestMethod>]
  member _.``C7.2.17 BFMLALB``() =
    check "2ec2fc20" []
      [ [ Q(0, 0x5ddd7c007f800000UL, 0x65ace2687f800000UL); Fpsr 0x14UL ]
        [ Q(0, 0x9a7aa724bc872bffUL, 0x444bcaba22bb690fUL); Fpsr 0x10UL ]
        [ Q(0, 0xffff00003f800000UL, 0x3dcccccdffff0000UL) ]
        [] ]

  /// C7.2.17 BFMLALB, BFMLALT (by element)
  [<TestMethod>]
  member _.``C7.2.17 BFMLALT``() =
    check "6ec2fc20" []
      [ [ Q(0, 0xb88ade00605a4800UL, 0x65ace2685a072c6dUL); Fpsr 0x10UL ]
        [ Q(0, 0x71a02800ff800000UL, 0xea1ae000ff800000UL); Fpsr 0x14UL ]
        [ Q(0, 0xff8000003f800000UL, 0x7fe000007fc00000UL); Fpsr 0x1UL ]
        [ Q(0, 0x3ff0000000000000UL, 0x7fc0000000000000UL) ] ]

  /// C7.2.19 BFMMLA
  [<TestMethod>]
  member _.``C7.2.19 BFMMLA``() =
    check "6e42ec20" []
      [ [ Q(0, 0x7f8000007f800000UL, 0x7f8000007f800000UL) ]
        [ Q(0, 0xff800000ff800000UL, 0xff800000ff800000UL) ]
        [ Q(0, 0x7fc000007fc00000UL, 0x7fc000007fc00000UL) ]
        [ Q(0, 0x7fc0000000000000UL, 0x7fc0000000000000UL) ] ]

  /// C7.2.22 BIF
  [<TestMethod>]
  member _.``C7.2.22 BIF``() =
    check "6ee21c20" []
      [ [ Q(0, 0xf66b492f48068918UL, 0x41fc824a7ab33c67UL) ]
        [ Q(0, 0x1ec8a72536dfca75UL, 0xe4511bbb3f9f288dUL) ]
        [ Q(0, 0xffc0000080000000UL, 0x7fa0000040c00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3ff999999999999aUL) ] ]
    check "2ee21c20" []
      [ [ Q(0, 0xf66b492f48068918UL, 0x0UL) ]
        [ Q(0, 0x1ec8a72536dfca75UL, 0x0UL) ]
        [ Q(0, 0xffc0000080000000UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]

  /// C7.2.23 BIT
  [<TestMethod>]
  member _.``C7.2.23 BIT``() =
    check "6ea21c20" []
      [ [ Q(0, 0x10213f67c9dde0beUL, 0x6486e26c0e47ec1dUL) ]
        [ Q(0, 0xd37a832459299e04UL, 0x422bca52423bf12bUL) ]
        [ Q(0, 0x3f8000003f800000UL, 0x3dcccccd7f400000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xbfb8000000000000UL) ] ]
    check "2ea21c20" []
      [ [ Q(0, 0x10213f67c9dde0beUL, 0x0UL) ]
        [ Q(0, 0xd37a832459299e04UL, 0x0UL) ]
        [ Q(0, 0x3f8000003f800000UL, 0x0UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ] ]

  /// C7.2.24 BSL
  [<TestMethod>]
  member _.``C7.2.24 BSL``() =
    check "6e621c20" []
      [ [ Q(0, 0x11b52f275efcf61cUL, 0xca86824c0e4bec95UL) ]
        [ Q(0, 0x534d8b74d9099f86UL, 0x43212a52c25bb439UL) ]
        [ Q(0, 0x3fbfffff00000001UL, 0x3d8000007f7fffffUL) ]
        [ Q(0, 0x8000000000000000UL, 0x7fb8000000000000UL) ] ]
    check "2e621c20" []
      [ [ Q(0, 0x11b52f275efcf61cUL, 0x0UL) ]
        [ Q(0, 0x534d8b74d9099f86UL, 0x0UL) ]
        [ Q(0, 0x3fbfffff00000001UL, 0x0UL) ]
        [ Q(0, 0x8000000000000000UL, 0x0UL) ] ]

  /// C7.2.27 CMEQ (register)
  [<TestMethod>]
  member _.``C7.2.27 CMEQ``() =
    check "2e228c20" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffff00UL, 0x0UL) ]
        [ Q(0, 0xffffffffffffUL, 0x0UL) ] ]
    check "2e628c20" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffffffffffffUL, 0x0UL) ] ]
    check "6e628c20" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0xffff00000000UL) ]
        [ Q(0, 0xffffffffffffUL, 0x0UL) ] ]
    check "2ea28c20" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffffffffUL, 0x0UL) ] ]
    check "6ea28c20" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffffffffUL, 0x0UL) ] ]
    check "6ee28c20" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "0e209820" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffff00ffffffUL, 0x0UL) ]
        [ Q(0, 0xffffffffffffUL, 0x0UL) ] ]
    check "4e209820" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffff00ffffffUL, 0xffff0000ffffUL) ]
        [ Q(0, 0xffffffffffffUL, 0x0UL) ] ]
    check "0e609820" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffff0000ffffUL, 0x0UL) ]
        [ Q(0, 0xffffffffffffUL, 0x0UL) ] ]
    check "4e609820" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffff0000ffffUL, 0xffff0000ffffUL) ]
        [ Q(0, 0xffffffffffffUL, 0x0UL) ] ]
    check "0ea09820" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffffffffUL, 0x0UL) ] ]
    check "4ea09820" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffffffffUL, 0x0UL) ] ]
    check "4ee09820" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "6e228c20" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffff00UL, 0xffffff000000UL) ]
        [ Q(0, 0xffffffffffffUL, 0x0UL) ] ]

  /// C7.2.29 CMGE (register)
  [<TestMethod>]
  member _.``C7.2.29 CMGE``() =
    check "0e223c20" []
      [ [ Q(0, 0xffffffff000000ffUL, 0x0UL) ]
        [ Q(0, 0xffff00ffUL, 0x0UL) ]
        [ Q(0, 0xff00ffff00ffff00UL, 0x0UL) ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ] ]
    check "0e623c20" []
      [ [ Q(0, 0xffffffff00000000UL, 0x0UL) ]
        [ Q(0, 0xffff0000UL, 0x0UL) ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL) ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ] ]
    check "4e623c20" []
      [ [ Q(0, 0xffffffff00000000UL, 0xffff00000000ffffUL) ]
        [ Q(0, 0xffff0000UL, 0xffffffffUL) ]
        [ Q(0, 0xffffffff00000000UL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ] ]
    check "0ea23c20" []
      [ [ Q(0, 0xffffffff00000000UL, 0x0UL) ]
        [ Q(0, 0xffffffffUL, 0x0UL) ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL) ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ] ]
    check "4ea23c20" []
      [ [ Q(0, 0xffffffff00000000UL, 0xffffffff00000000UL) ]
        [ Q(0, 0xffffffffUL, 0xffffffffUL) ]
        [ Q(0, 0xffffffff00000000UL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ] ]
    check "4ee23c20" []
      [ [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ] ]
    check "2e208820" []
      [ [ Q(0, 0xffffffffff0000ffUL, 0x0UL) ]
        [ Q(0, 0xff0000ffffff00ffUL, 0x0UL) ]
        [ Q(0, 0xff00ffff00ffffffUL, 0x0UL) ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ] ]
    check "6e208820" []
      [ [ Q(0, 0xffffffffff0000ffUL, 0xff0000ffff0000ffUL) ]
        [ Q(0, 0xff0000ffffff00ffUL, 0xffffffffff0000UL) ]
        [ Q(0, 0xff00ffff00ffffffUL, 0xff00ffffff00ffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0xff00000000000000UL) ] ]
    check "2e608820" []
      [ [ Q(0, 0xffffffffffff0000UL, 0x0UL) ]
        [ Q(0, 0xffff0000ffff0000UL, 0x0UL) ]
        [ Q(0, 0xffffffff0000ffffUL, 0x0UL) ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ] ]
    check "6e608820" []
      [ [ Q(0, 0xffffffffffff0000UL, 0xffff0000ffff0000UL) ]
        [ Q(0, 0xffff0000ffff0000UL, 0xffffffff0000UL) ]
        [ Q(0, 0xffffffff0000ffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0xffff000000000000UL) ] ]
    check "2ea08820" []
      [ [ Q(0, 0xffffffffffffffffUL, 0x0UL) ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL) ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ] ]
    check "6ea08820" []
      [ [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffUL) ]
        [ Q(0, 0xffffffff00000000UL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffff00000000UL) ] ]
    check "6ee08820" []
      [ [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ] ]
    check "4e223c20" []
      [ [ Q(0, 0xffffffff000000ffUL, 0xff0000ff0000ffffUL) ]
        [ Q(0, 0xffff00ffUL, 0xffffffff00UL) ]
        [ Q(0, 0xff00ffff00ffff00UL, 0xffffffffff00ffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ] ]

  /// C7.2.31 CMGT (register)
  [<TestMethod>]
  member _.``C7.2.31 CMGT``() =
    check "0e223420" []
      [ [ Q(0, 0xffffffff000000ffUL, 0x0UL) ]
        [ Q(0, 0xffff00ffUL, 0x0UL) ]
        [ Q(0, 0xff00ffff00000000UL, 0x0UL) ]
        [ Q(0, 0xffff000000000000UL, 0x0UL) ] ]
    check "0e623420" []
      [ [ Q(0, 0xffffffff00000000UL, 0x0UL) ]
        [ Q(0, 0xffff0000UL, 0x0UL) ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL) ]
        [ Q(0, 0xffff000000000000UL, 0x0UL) ] ]
    check "4e623420" []
      [ [ Q(0, 0xffffffff00000000UL, 0xffff00000000ffffUL) ]
        [ Q(0, 0xffff0000UL, 0xffffffffUL) ]
        [ Q(0, 0xffffffff00000000UL, 0xffff0000ffffffffUL) ]
        [ Q(0, 0xffff000000000000UL, 0x0UL) ] ]
    check "0ea23420" []
      [ [ Q(0, 0xffffffff00000000UL, 0x0UL) ]
        [ Q(0, 0xffffffffUL, 0x0UL) ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL) ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL) ] ]
    check "4ea23420" []
      [ [ Q(0, 0xffffffff00000000UL, 0xffffffff00000000UL) ]
        [ Q(0, 0xffffffffUL, 0xffffffffUL) ]
        [ Q(0, 0xffffffff00000000UL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL) ] ]
    check "4ee23420" []
      [ [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ] ]
    check "0e208820" []
      [ [ Q(0, 0xffffffffff0000ffUL, 0x0UL) ]
        [ Q(0, 0xff0000ffffff00ffUL, 0x0UL) ]
        [ Q(0, 0xff00000000000000UL, 0x0UL) ]
        [ Q(0, 0xffff000000000000UL, 0x0UL) ] ]
    check "4e208820" []
      [ [ Q(0, 0xffffffffff0000ffUL, 0xff0000ffff0000ffUL) ]
        [ Q(0, 0xff0000ffffff00ffUL, 0xffffffffff0000UL) ]
        [ Q(0, 0xff00000000000000UL, 0xff000000ff000000UL) ]
        [ Q(0, 0xffff000000000000UL, 0xff00000000000000UL) ] ]
    check "0e608820" []
      [ [ Q(0, 0xffffffffffff0000UL, 0x0UL) ]
        [ Q(0, 0xffff0000ffff0000UL, 0x0UL) ]
        [ Q(0, 0xffff000000000000UL, 0x0UL) ]
        [ Q(0, 0xffff000000000000UL, 0x0UL) ] ]
    check "4e608820" []
      [ [ Q(0, 0xffffffffffff0000UL, 0xffff0000ffff0000UL) ]
        [ Q(0, 0xffff0000ffff0000UL, 0xffffffff0000UL) ]
        [ Q(0, 0xffff000000000000UL, 0xffff0000ffff0000UL) ]
        [ Q(0, 0xffff000000000000UL, 0xffff000000000000UL) ] ]
    check "0ea08820" []
      [ [ Q(0, 0xffffffffffffffffUL, 0x0UL) ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL) ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL) ] ]
    check "4ea08820" []
      [ [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffUL) ]
        [ Q(0, 0xffffffff00000000UL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffff00000000UL, 0xffffffff00000000UL) ] ]
    check "4ee08820" []
      [ [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ] ]
    check "4e223420" []
      [ [ Q(0, 0xffffffff000000ffUL, 0xff0000ff0000ffffUL) ]
        [ Q(0, 0xffff00ffUL, 0xffffffff00UL) ]
        [ Q(0, 0xff00ffff00000000UL, 0xffff00000000ffffUL) ]
        [ Q(0, 0xffff000000000000UL, 0x0UL) ] ]

  /// C7.2.33 CMHI (register)
  [<TestMethod>]
  member _.``C7.2.33 CMHI``() =
    check "2e223420" []
      [ [ Q(0, 0xffff000000ffUL, 0x0UL) ]
        [ Q(0, 0xff00000000ff00UL, 0x0UL) ]
        [ Q(0, 0xff0000ff000000UL, 0x0UL) ]
        [ Q(0, 0xff000000000000UL, 0x0UL) ] ]
    check "2e623420" []
      [ [ Q(0, 0xffff00000000UL, 0x0UL) ]
        [ Q(0, 0xffffUL, 0x0UL) ]
        [ Q(0, 0xffff0000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "6e623420" []
      [ [ Q(0, 0xffff00000000UL, 0xffff0000ffffUL) ]
        [ Q(0, 0xffffUL, 0xffff00000000ffffUL) ]
        [ Q(0, 0xffff0000UL, 0xffff0000ffff0000UL) ]
        [ Q(0, 0x0UL, 0xffffffffffffUL) ] ]
    check "2ea23420" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffffffffUL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "6ea23420" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0xffffffff00000000UL) ]
        [ Q(0, 0xffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0x0UL, 0xffffffffUL) ] ]
    check "6ee23420" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0xffffffffffffffffUL) ]
        [ Q(0, 0x0UL, 0xffffffffffffffffUL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "6e223420" []
      [ [ Q(0, 0xffff000000ffUL, 0xffffff00ffff00UL) ]
        [ Q(0, 0xff00000000ff00UL, 0xff0000000000ffffUL) ]
        [ Q(0, 0xff0000ff000000UL, 0xffff000000ff0000UL) ]
        [ Q(0, 0xff000000000000UL, 0xffffffffffffUL) ] ]

  /// C7.2.34 CMHS (register)
  [<TestMethod>]
  member _.``C7.2.34 CMHS``() =
    check "2e223c20" []
      [ [ Q(0, 0xffff000000ffUL, 0x0UL) ]
        [ Q(0, 0xff00000000ff00UL, 0x0UL) ]
        [ Q(0, 0xff0000ffffff00UL, 0x0UL) ]
        [ Q(0, 0xffffffffffffffUL, 0x0UL) ] ]
    check "2e623c20" []
      [ [ Q(0, 0xffff00000000UL, 0x0UL) ]
        [ Q(0, 0xffffUL, 0x0UL) ]
        [ Q(0, 0xffff0000UL, 0x0UL) ]
        [ Q(0, 0xffffffffffffUL, 0x0UL) ] ]
    check "6e623c20" []
      [ [ Q(0, 0xffff00000000UL, 0xffff0000ffffUL) ]
        [ Q(0, 0xffffUL, 0xffff00000000ffffUL) ]
        [ Q(0, 0xffff0000UL, 0xffffffffffff0000UL) ]
        [ Q(0, 0xffffffffffffUL, 0xffffffffffffUL) ] ]
    check "2ea23c20" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffffffffUL, 0x0UL) ]
        [ Q(0, 0xffffffffUL, 0x0UL) ] ]
    check "6ea23c20" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0xffffffff00000000UL) ]
        [ Q(0, 0xffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffffUL, 0xffffffffUL) ] ]
    check "6ee23c20" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0xffffffffffffffffUL) ]
        [ Q(0, 0x0UL, 0xffffffffffffffffUL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "6e223c20" []
      [ [ Q(0, 0xffff000000ffUL, 0xffffff00ffff00UL) ]
        [ Q(0, 0xff00000000ff00UL, 0xff0000000000ffffUL) ]
        [ Q(0, 0xff0000ffffff00UL, 0xffffffffffff0000UL) ]
        [ Q(0, 0xffffffffffffffUL, 0xffffffffffffUL) ] ]

  /// C7.2.35 CMLE (zero)
  [<TestMethod>]
  member _.``C7.2.35 CMLE``() =
    check "2e209820" []
      [ [ Q(0, 0xffff00UL, 0x0UL) ]
        [ Q(0, 0xffff000000ff00UL, 0x0UL) ]
        [ Q(0, 0xffffffffffffffUL, 0x0UL) ]
        [ Q(0, 0xffffffffffffUL, 0x0UL) ] ]
    check "6e209820" []
      [ [ Q(0, 0xffff00UL, 0xffff0000ffff00UL) ]
        [ Q(0, 0xffff000000ff00UL, 0xff0000000000ffffUL) ]
        [ Q(0, 0xffffffffffffffUL, 0xffffff00ffffffUL) ]
        [ Q(0, 0xffffffffffffUL, 0xffffffffffffffUL) ] ]
    check "2e609820" []
      [ [ Q(0, 0xffffUL, 0x0UL) ]
        [ Q(0, 0xffff0000ffffUL, 0x0UL) ]
        [ Q(0, 0xffffffffffffUL, 0x0UL) ]
        [ Q(0, 0xffffffffffffUL, 0x0UL) ] ]
    check "6e609820" []
      [ [ Q(0, 0xffffUL, 0xffff0000ffffUL) ]
        [ Q(0, 0xffff0000ffffUL, 0xffff00000000ffffUL) ]
        [ Q(0, 0xffffffffffffUL, 0xffff0000ffffUL) ]
        [ Q(0, 0xffffffffffffUL, 0xffffffffffffUL) ] ]
    check "2ea09820" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffffffffUL, 0x0UL) ]
        [ Q(0, 0xffffffffUL, 0x0UL) ] ]
    check "6ee09820" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0xffffffffffffffffUL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "6ea09820" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0xffffffff00000000UL) ]
        [ Q(0, 0xffffffffUL, 0x0UL) ]
        [ Q(0, 0xffffffffUL, 0xffffffffUL) ] ]

  /// C7.2.36 CMLT (zero)
  [<TestMethod>]
  member _.``C7.2.36 CMLT``() =
    check "0e20a820" []
      [ [ Q(0, 0xffff00UL, 0x0UL) ]
        [ Q(0, 0xffff000000ff00UL, 0x0UL) ]
        [ Q(0, 0xff0000ff000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "0e60a820" []
      [ [ Q(0, 0xffffUL, 0x0UL) ]
        [ Q(0, 0xffff0000ffffUL, 0x0UL) ]
        [ Q(0, 0xffff0000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "4e60a820" []
      [ [ Q(0, 0xffffUL, 0xffff0000ffffUL) ]
        [ Q(0, 0xffff0000ffffUL, 0xffff00000000ffffUL) ]
        [ Q(0, 0xffff0000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0xffffffffffffUL) ] ]
    check "0ea0a820" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffffffffUL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "4ea0a820" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0xffffffff00000000UL) ]
        [ Q(0, 0xffffffffUL, 0x0UL) ]
        [ Q(0, 0x0UL, 0xffffffffUL) ] ]
    check "4ee0a820" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0xffffffffffffffffUL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "4e20a820" []
      [ [ Q(0, 0xffff00UL, 0xffff0000ffff00UL) ]
        [ Q(0, 0xffff000000ff00UL, 0xff0000000000ffffUL) ]
        [ Q(0, 0xff0000ff000000UL, 0xff000000ff0000UL) ]
        [ Q(0, 0x0UL, 0xffffffffffffffUL) ] ]

  /// C7.2.37 CMTST
  [<TestMethod>]
  member _.``C7.2.37 CMTST``() =
    check "0e228c20" []
      [ [ Q(0, 0xffffffffffffUL, 0x0UL) ]
        [ Q(0, 0xffffffffff00ff00UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "0e628c20" []
      [ [ Q(0, 0xffffffffffffUL, 0x0UL) ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "4e628c20" []
      [ [ Q(0, 0xffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0x0UL, 0xffff0000ffff0000UL) ]
        [ Q(0, 0x0UL, 0xffff000000000000UL) ] ]
    check "0ea28c20" []
      [ [ Q(0, 0xffffffffffffffffUL, 0x0UL) ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "4ea28c20" []
      [ [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0x0UL, 0xffffffffffffffffUL) ]
        [ Q(0, 0x0UL, 0xffffffff00000000UL) ] ]
    check "4ee28c20" []
      [ [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0x0UL, 0xffffffffffffffffUL) ]
        [ Q(0, 0x0UL, 0xffffffffffffffffUL) ] ]
    check "4e228c20" []
      [ [ Q(0, 0xffffffffffffUL, 0xffffffffffffffUL) ]
        [ Q(0, 0xffffffffff00ff00UL, 0xffffffffffffffffUL) ]
        [ Q(0, 0x0UL, 0xff0000ffff0000UL) ]
        [ Q(0, 0x0UL, 0xffff000000000000UL) ] ]

  /// C7.2.38 CNT
  [<TestMethod>]
  member _.``C7.2.38 CNT``() =
    check "4e205820" []
      [ [ Q(0, 0x303060502050303UL, 0x105020404060604UL) ]
        [ Q(0, 0x503030306040502UL, 0x403040406050304UL) ]
        [ Q(0, 0x701000001000000UL, 0x702000007020000UL) ]
        [ Q(0, 0x101000000000000UL, 0x605040404040404UL) ] ]
    check "0e205820" []
      [ [ Q(0, 0x303060502050303UL, 0x0UL) ]
        [ Q(0, 0x503030306040502UL, 0x0UL) ]
        [ Q(0, 0x701000001000000UL, 0x0UL) ]
        [ Q(0, 0x101000000000000UL, 0x0UL) ] ]

  /// C7.2.39 DUP (element)
  [<TestMethod>]
  member _.``C7.2.39 DUP``() =
    check "0e030420" []
      [ [ Q(0, 0xe0e0e0e0e0e0e0e0UL, 0x0UL) ]
        [ Q(0, 0x9e9e9e9e9e9e9e9eUL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "4e030420" []
      [ [ Q(0, 0xe0e0e0e0e0e0e0e0UL, 0xe0e0e0e0e0e0e0e0UL) ]
        [ Q(0, 0x9e9e9e9e9e9e9e9eUL, 0x9e9e9e9e9e9e9e9eUL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "0e060420" []
      [ [ Q(0, 0x48dc48dc48dc48dcUL, 0x0UL) ]
        [ Q(0, 0x5f0f5f0f5f0f5f0fUL, 0x0UL) ]
        [ Q(0, 0x8000800080008000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "4e060420" []
      [ [ Q(0, 0x48dc48dc48dc48dcUL, 0x48dc48dc48dc48dcUL) ]
        [ Q(0, 0x5f0f5f0f5f0f5f0fUL, 0x5f0f5f0f5f0f5f0fUL) ]
        [ Q(0, 0x8000800080008000UL, 0x8000800080008000UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "0e0c0420" []
      [ [ Q(0, 0x70616f2f70616f2fUL, 0x0UL) ]
        [ Q(0, 0x57c8832557c88325UL, 0x0UL) ]
        [ Q(0, 0x7f8000007f800000UL, 0x0UL) ]
        [ Q(0, 0x4008000040080000UL, 0x0UL) ] ]
    check "4e0c0420" []
      [ [ Q(0, 0x70616f2f70616f2fUL, 0x70616f2f70616f2fUL) ]
        [ Q(0, 0x57c8832557c88325UL, 0x57c8832557c88325UL) ]
        [ Q(0, 0x7f8000007f800000UL, 0x7f8000007f800000UL) ]
        [ Q(0, 0x4008000040080000UL, 0x4008000040080000UL) ] ]
    check "4e180420" []
      [ [ Q(0, 0x40d6824e2ef3fc17UL, 0x40d6824e2ef3fc17UL) ]
        [ Q(0, 0xe2311b535f1fb0a9UL, 0xe2311b535f1fb0a9UL) ]
        [ Q(0, 0x7fa000007fc00000UL, 0x7fa000007fc00000UL) ]
        [ Q(0, 0x3fb999999999999aUL, 0x3fb999999999999aUL) ] ]
    check "4e040420" []
      [ [ Q(0, 0x48dce01c48dce01cUL, 0x48dce01c48dce01cUL) ]
        [ Q(0, 0x5f0f9e245f0f9e24UL, 0x5f0f9e245f0f9e24UL) ]
        [ Q(0, 0x8000000080000000UL, 0x8000000080000000UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]

  /// C7.2.42 EOR3
  [<TestMethod>]
  member _.``C7.2.42 EOR3``() =
    check "ce020c20" []
      [ [ Q(0, 0x487318b61e174cd1UL, 0x1a9224b8e65381faUL) ]
        [ Q(0, 0xc38f1cc30c53426UL, 0x43be9653a8daefd2UL) ]
        [ Q(0, 0x3f17ffffd01502f8UL, 0x3de800003fbfffffUL) ]
        [ Q(0, 0xbff0000000000000UL, 0x3fbd99999999999aUL) ] ]

  /// C7.2.43 EXT
  [<TestMethod>]
  member _.``C7.2.43 EXT``() =
    check "6e020820" []
      [ [ Q(0, 0x1770616f2f48dce0UL, 0xc40d6824e2ef3fcUL) ]
        [ Q(0, 0xa957c883255f0f9eUL, 0xd3e2311b535f1fb0UL) ]
        [ Q(0, 0x7f800000800000UL, 0x17fa000007fc000UL) ]
        [ Q(0, 0x9a40080000000000UL, 0x3fb99999999999UL) ] ]
    check "2e020820" []
      [ [ Q(0, 0xc70616f2f48dce0UL, 0x0UL) ]
        [ Q(0, 0xd357c883255f0f9eUL, 0x0UL) ]
        [ Q(0, 0x17f800000800000UL, 0x0UL) ]
        [ Q(0, 0x40080000000000UL, 0x0UL) ] ]

  /// C7.2.44 FABD
  [<TestMethod>]
  member _.``C7.2.44 FABD``() =
    check "7ec21420" []
      [ [ Q(0, 0x7f0cUL, 0x0UL) ]
        [ Q(0, 0x5dd3UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x1UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "2ec21420" []
      [ [ Q(0, 0x70616f2f56627f0cUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x51a42c736ab25dd3UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x7f807fff00000001UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "2ea2d420" []
      [ [ Q(0, 0x70616f2f56feff0cUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x59349c0f69d05dd7UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x7f80000000000001UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "6ea2d420" []
      [ [ Q(0, 0x70616f2f56feff0cUL, 0x40d6824e5e4be0f5UL); Fpsr 0x10UL ]
        [ Q(0, 0x59349c0f69d05dd7UL, 0x62311b5360ed9251UL); Fpsr 0x10UL ]
        [ Q(0, 0x7f80000000000001UL, 0x7fe000007fc00000UL); Fpsr 0x1UL ]
        [ Q(0, 0x4008000000000000UL, 0x7fc000001999999aUL) ] ]
    check "6ee2d420" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x40d6824e2ef3fc17UL); Fpsr 0x10UL ]
        [ Q(0, 0x594dac74d14d3874UL, 0x62311b535f1fb0a9UL); Fpsr 0x10UL ]
        [ Q(0, 0x7f80000080000000UL, 0x7fa000007fc00000UL); Fpsr 0x10UL ]
        [ Q(0, 0x4008000000000000UL, 0x7ff0000000000000UL) ] ]
    check "6ec21420" []
      [ [ Q(0, 0x70616f2f56627f0cUL, 0x40d604925e4b7e17UL); Fpsr 0x11UL ]
        [ Q(0, 0x51a42c736ab25dd3UL, 0x62402a8564343087UL); Fpsr 0x10UL ]
        [ Q(0, 0x7f807fff00000001UL, 0x7fa000007fc07fffUL) ]
        [ Q(0, 0x4008000000000000UL, 0x7e0019991999199aUL) ] ]

  /// C7.2.45 FABS (vector)
  [<TestMethod>]
  member _.``C7.2.45 FABS``() =
    check "0ef8f820" []
      [ [ Q(0, 0x70616f2f48dc601cUL, 0x0UL) ]
        [ Q(0, 0x57c803255f0f1e24UL, 0x0UL) ]
        [ Q(0, 0x7f80000000000000UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4ef8f820" []
      [ [ Q(0, 0x70616f2f48dc601cUL, 0x40d6024e2ef37c17UL) ]
        [ Q(0, 0x57c803255f0f1e24UL, 0x62311b535f1f30a9UL) ]
        [ Q(0, 0x7f80000000000000UL, 0x7fa000007fc00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fb919991999199aUL) ] ]
    check "0ea0f820" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x0UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x7f80000000000000UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4ee0f820" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x40d6824e2ef3fc17UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x62311b535f1fb0a9UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x7fa000007fc00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fb999999999999aUL) ] ]
    check "1ee0c020" []
      [ [ Q(0, 0x601cUL, 0x0UL) ]
        [ Q(0, 0x1e24UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e20c020" []
      [ [ Q(0, 0x48dce01cUL, 0x0UL) ]
        [ Q(0, 0x5f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e60c020" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x0UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4ea0f820" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x40d6824e2ef3fc17UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x62311b535f1fb0a9UL) ]
        [ Q(0, 0x7f80000000000000UL, 0x7fa000007fc00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fb999991999999aUL) ] ]

  /// C7.2.47 FACGE
  [<TestMethod>]
  member _.``C7.2.47 FACGE``() =
    check "7e422c20" []
      [ [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffffUL, 0x0UL) ] ]
    check "2e422c20" []
      [ [ Q(0, 0xffffffff00000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffff0000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ] ]
    check "6e422c20" []
      [ [ Q(0, 0xffffffff00000000UL, 0xffffffff00000000UL); Fpsr 0x1UL ]
        [ Q(0, 0x0UL, 0xffff00000000ffffUL) ]
        [ Q(0, 0xffff0000UL, 0xffff00000000UL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffUL); Fpsr 0x1UL ] ]
    check "2e22ec20" []
      [ [ Q(0, 0xffffffff00000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL) ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ] ]
    check "6e62ec20" []
      [ [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0x0UL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ] ]
    check "6e22ec20" []
      [ [ Q(0, 0xffffffff00000000UL, 0xffffffff00000000UL) ]
        [ Q(0, 0x0UL, 0xffffffff00000000UL) ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffUL); Fpsr 0x1UL ] ]

  /// C7.2.48 FACGT
  [<TestMethod>]
  member _.``C7.2.48 FACGT``() =
    check "7ec22c20" []
      [ [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "2ec22c20" []
      [ [ Q(0, 0xffffffff00000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffff000000000000UL, 0x0UL) ] ]
    check "2ea2ec20" []
      [ [ Q(0, 0xffffffff00000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL) ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL) ] ]
    check "6ea2ec20" []
      [ [ Q(0, 0xffffffff00000000UL, 0xffffffff00000000UL) ]
        [ Q(0, 0x0UL, 0xffffffff00000000UL) ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffff00000000UL, 0xffffffffUL); Fpsr 0x1UL ] ]
    check "6ee2ec20" []
      [ [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0x0UL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ] ]
    check "6ec22c20" []
      [ [ Q(0, 0xffffffff00000000UL, 0xffffffff00000000UL); Fpsr 0x1UL ]
        [ Q(0, 0x0UL, 0xffff00000000ffffUL) ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffff000000000000UL, 0xffffffffffffUL); Fpsr 0x1UL ] ]

  /// C7.2.49 FADD (vector)
  [<TestMethod>]
  member _.``C7.2.49 FADD``() =
    check "0e421420" []
      [ [ Q(0, 0x70616f2f579aff0cUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x5c98ac75e8ee5dd3UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x7f80ffff00000001UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4e421420" []
      [ [ Q(0, 0x70616f2f579aff0cUL, 0x40d6800a5e4bfe17UL); Fpsr 0x11UL ]
        [ Q(0, 0x5c98ac75e8ee5dd3UL, 0xe2222b6fd926b0cbUL); Fpsr 0x10UL ]
        [ Q(0, 0x7f80ffff00000001UL, 0x7fa000007fc0ffffUL) ]
        [ Q(0, 0x4008000000000000UL, 0x7e0099999999999aUL) ] ]
    check "0e22d420" []
      [ [ Q(0, 0x70616f2f56feff0cUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x5966bcd9e9d05dcfUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x7f80000000000001UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4e62d420" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x40d6824e2ef3fc17UL); Fpsr 0x10UL ]
        [ Q(0, 0x594dac7502538332UL, 0xe2311b535f1fb0a9UL); Fpsr 0x10UL ]
        [ Q(0, 0x7f80000080000000UL, 0x7fa000007fc00000UL); Fpsr 0x10UL ]
        [ Q(0, 0x4008000000000000UL, 0x7ff0000000000000UL) ] ]
    check "1ee22820" []
      [ [ Q(0, 0xff0cUL, 0x0UL) ]
        [ Q(0, 0x5dd3UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x1UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e222820" []
      [ [ Q(0, 0x56feff0cUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xe9d05dcfUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x1UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e622820" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x594dac7502538332UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4e22d420" []
      [ [ Q(0, 0x70616f2f56feff0cUL, 0x40d6824e5e4be0f5UL); Fpsr 0x10UL ]
        [ Q(0, 0x5966bcd9e9d05dcfUL, 0xe2311b53e0c5a627UL); Fpsr 0x10UL ]
        [ Q(0, 0x7f80000000000001UL, 0x7fe000007fc00000UL); Fpsr 0x1UL ]
        [ Q(0, 0x4008000000000000UL, 0x7fc000009999999aUL) ] ]

  /// C7.2.51 FADDP (scalar)
  [<TestMethod>]
  member _.``C7.2.51 FADDP``() =
    check "2e421420" []
      [ [ Q(0, 0x2e20ff0c73f8e009UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x594ce91657c85f0fUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xffff00017f800000UL, 0x0UL) ]
        [ Q(0, 0x40080000UL, 0x0UL) ] ]
    check "6e421420" []
      [ [ Q(0, 0x40d6fe1773f8e009UL, 0x8a0cdb3e2e20ff0cUL); Fpsr 0x11UL ]
        [ Q(0, 0xe2315f1e57c85f0fUL, 0x476ee0d9594ce916UL); Fpsr 0x10UL ]
        [ Q(0, 0x7fa07fc07f800000UL, 0x80ffffffff0001UL) ]
        [ Q(0, 0x3fb69d9a40080000UL, 0x7e00000000000000UL); Fpsr 0x10UL ] ]
    check "2e22d420" []
      [ [ Q(0, 0x56feff0c70616f2fUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xe9d05dd35f0f9fb5UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x807ffffe7f800000UL, 0x0UL) ]
        [ Q(0, 0x40080000UL, 0x0UL) ] ]
    check "6e62d420" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x8b2e02445e4be0f5UL); Fpsr 0x10UL ]
        [ Q(0, 0xe2311b535f1fb0a9UL, 0x594dac74e9d05dd3UL); Fpsr 0x10UL ]
        [ Q(0, 0x7fa400009fc00000UL, 0x7fbfffff40UL) ]
        [ Q(0, 0x4008cccccccccccdUL, 0x7ff0000000000000UL); Fpsr 0x10UL ] ]
    check "6e22d420" []
      [ [ Q(0, 0x40d6824e70616f2fUL, 0x5e4be0f556feff0cUL); Fpsr 0x10UL ]
        [ Q(0, 0xe22e9c905f0f9fb5UL, 0xe0d99c3ce9d05dd3UL); Fpsr 0x10UL ]
        [ Q(0, 0x7fe000007f800000UL, 0x7f7fffff807ffffeUL); Fpsr 0x11UL ]
        [ Q(0, 0x3fb9999940080000UL, 0x7fc0000000000000UL); Fpsr 0x10UL ] ]

  /// C7.2.53 FCADD
  [<TestMethod>]
  member _.``C7.2.53 FCADD``() =
    check "6e82e420" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x5e4be0f52ef3fc17UL); Fpsr 0x10UL ]
        [ Q(0, 0xe9d05dd35f0f9149UL, 0xe24c4eda5f1fb0a9UL); Fpsr 0x10UL ]
        [ Q(0, 0x7f800000007fffffUL, 0x7fe000007fc00000UL); Fpsr 0x1UL ]
        [ Q(0, 0x4008000000000000UL, 0x3fb999997fc00000UL) ] ]

  /// C7.2.54 FCCMP
  [<TestMethod>]
  member _.``C7.2.54 FCCMP``() =
    check "1ee20429" []
      [ [ Nzcv 0x90000000UL ]
        [ Nzcv 0x80000000UL ]
        [ Nzcv 0x80000000UL ]
        [] ]
    check "1e220429" []
      [ [ Nzcv 0x90000000UL ]
        [ Nzcv 0x20000000UL ]
        [ Nzcv 0x80000000UL ]
        [] ]
    check "1e620429" []
      [ [ Nzcv 0x90000000UL ]
        [ Nzcv 0x80000000UL ]
        [ Nzcv 0x20000000UL ]
        [] ]
    check "1e620420" []
      [ [ Nzcv 0x0UL ]
        [ Nzcv 0x80000000UL ]
        [ Nzcv 0x20000000UL ]
        [ Nzcv 0x0UL ] ]

  /// C7.2.55 FCCMPE
  [<TestMethod>]
  member _.``C7.2.55 FCCMPE``() =
    check "1ee20439" []
      [ [ Nzcv 0x90000000UL ]
        [ Nzcv 0x80000000UL ]
        [ Nzcv 0x80000000UL ]
        [] ]
    check "1e220439" []
      [ [ Nzcv 0x90000000UL ]
        [ Nzcv 0x20000000UL ]
        [ Nzcv 0x80000000UL ]
        [] ]
    check "1e620439" []
      [ [ Nzcv 0x90000000UL ]
        [ Nzcv 0x80000000UL ]
        [ Nzcv 0x20000000UL ]
        [] ]
    check "1e620430" []
      [ [ Nzcv 0x0UL ]
        [ Nzcv 0x80000000UL ]
        [ Nzcv 0x20000000UL ]
        [ Nzcv 0x0UL ] ]

  /// C7.2.56 FCMEQ (register)
  [<TestMethod>]
  member _.``C7.2.56 FCMEQ``() =
    check "5e422420" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffffUL, 0x0UL) ] ]
    check "0e422420" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffff0000UL, 0x0UL) ]
        [ Q(0, 0xffffffffffffUL, 0x0UL) ] ]
    check "4e422420" []
      [ [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffff0000UL, 0xffff00000000UL) ]
        [ Q(0, 0xffffffffffffUL, 0x0UL) ] ]
    check "0e22e420" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffffffffUL, 0x0UL) ] ]
    check "4e62e420" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "5ef8d820" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffffUL, 0x0UL) ]
        [ Q(0, 0xffffUL, 0x0UL) ] ]
    check "0ef8d820" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffffffffffffUL, 0x0UL) ]
        [ Q(0, 0xffffffffffffUL, 0x0UL) ] ]
    check "4ef8d820" []
      [ [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffffffffffffUL, 0xffff0000ffffUL) ]
        [ Q(0, 0xffffffffffffUL, 0x0UL) ] ]
    check "0ea0d820" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffffffffUL, 0x0UL) ]
        [ Q(0, 0xffffffffUL, 0x0UL) ] ]
    check "4ea0d820" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffffffffUL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffffUL, 0x0UL) ] ]
    check "4ee0d820" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "4e22e420" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffffUL, 0x0UL) ] ]

  /// C7.2.58 FCMGE (register)
  [<TestMethod>]
  member _.``C7.2.58 FCMGE``() =
    check "7e422420" []
      [ [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffffUL, 0x0UL) ] ]
    check "2e422420" []
      [ [ Q(0, 0xffffffff00000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffff0000UL, 0x0UL) ]
        [ Q(0, 0xffff0000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ] ]
    check "6e422420" []
      [ [ Q(0, 0xffffffff00000000UL, 0xffff000000000000UL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffff0000UL, 0xffff0000UL) ]
        [ Q(0, 0xffff0000UL, 0xffff00000000UL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x1UL ] ]
    check "2e22e420" []
      [ [ Q(0, 0xffffffff00000000UL, 0x0UL) ]
        [ Q(0, 0xffffffffUL, 0x0UL) ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL) ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ] ]
    check "6e62e420" []
      [ [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ] ]
    check "7ef8c820" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffffUL, 0x0UL) ]
        [ Q(0, 0xffffUL, 0x0UL) ] ]
    check "2ef8c820" []
      [ [ Q(0, 0xffffffffffff0000UL, 0x0UL) ]
        [ Q(0, 0xffff0000ffff0000UL, 0x0UL) ]
        [ Q(0, 0xffffffffffffUL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ] ]
    check "6ef8c820" []
      [ [ Q(0, 0xffffffffffff0000UL, 0xffff0000ffff0000UL); Fpsr 0x1UL ]
        [ Q(0, 0xffff0000ffff0000UL, 0xffffffff0000UL) ]
        [ Q(0, 0xffffffffffffUL, 0xffff0000ffffUL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffffffffffffUL, 0xffff000000000000UL) ] ]
    check "2ea0c820" []
      [ [ Q(0, 0xffffffffffffffffUL, 0x0UL) ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ] ]
    check "6ea0c820" []
      [ [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffff00000000UL) ] ]
    check "6ee0c820" []
      [ [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ] ]
    check "6e22e420" []
      [ [ Q(0, 0xffffffff00000000UL, 0xffffffff00000000UL) ]
        [ Q(0, 0xffffffffUL, 0xffffffffUL) ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x1UL ] ]

  /// C7.2.60 FCMGT (register)
  [<TestMethod>]
  member _.``C7.2.60 FCMGT``() =
    check "7ec22420" []
      [ [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "2ec22420" []
      [ [ Q(0, 0xffffffff00000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffff0000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffff000000000000UL, 0x0UL) ] ]
    check "2ea2e420" []
      [ [ Q(0, 0xffffffff00000000UL, 0x0UL) ]
        [ Q(0, 0xffffffffUL, 0x0UL) ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL) ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL) ] ]
    check "6ea2e420" []
      [ [ Q(0, 0xffffffff00000000UL, 0xffffffff00000000UL) ]
        [ Q(0, 0xffffffffUL, 0xffffffffUL) ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL); Fpsr 0x1UL ] ]
    check "6ee2e420" []
      [ [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ] ]
    check "5ef8c820" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "0ef8c820" []
      [ [ Q(0, 0xffffffffffff0000UL, 0x0UL) ]
        [ Q(0, 0xffff0000ffff0000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffff000000000000UL, 0x0UL) ] ]
    check "4ef8c820" []
      [ [ Q(0, 0xffffffffffff0000UL, 0xffff0000ffff0000UL); Fpsr 0x1UL ]
        [ Q(0, 0xffff0000ffff0000UL, 0xffffffff0000UL) ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffff000000000000UL, 0xffff000000000000UL) ] ]
    check "0ea0c820" []
      [ [ Q(0, 0xffffffffffffffffUL, 0x0UL) ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL) ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL) ] ]
    check "4ea0c820" []
      [ [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffUL) ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffff00000000UL, 0xffffffff00000000UL) ] ]
    check "4ee0c820" []
      [ [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ] ]
    check "6ec22420" []
      [ [ Q(0, 0xffffffff00000000UL, 0xffff000000000000UL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffff0000UL, 0xffff0000UL) ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffff000000000000UL, 0x0UL); Fpsr 0x1UL ] ]

  /// C7.2.62 FCMLA (by element)
  [<TestMethod>]
  member _.``C7.2.62 FCMLA``() =
    check "6e82cc20" []
      [ [ Q(0, 0x7f800000c90789baUL, 0x65aced155a072c6dUL); Fpsr 0x14UL ]
        [ Q(0, 0xff800000f1a11818UL, 0x7f8000006a1b15a4UL); Fpsr 0x14UL ]
        [ Q(0, 0x7f8000007f800000UL, 0x7fe000007fe00000UL); Fpsr 0x1UL ]
        [ Q(0, 0x3ff0000000000000UL, 0xbff800007fc00000UL) ] ]
    check "6e82c420" []
      [ [ Q(0, 0x962b3b86605c0269UL, 0x65ace2685a072c6dUL); Fpsr 0x10UL ]
        [ Q(0, 0x78e6c4c4ff800000UL, 0x670bd563ff800000UL); Fpsr 0x14UL ]
        [ Q(0, 0xbfc000003f800000UL, 0x7fc000007fc00000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x7fc0000000000000UL) ] ]

  /// C7.2.64 FCMLE (zero)
  [<TestMethod>]
  member _.``C7.2.64 FCMLE``() =
    check "7ef8d820" []
      [ [ Q(0, 0xffffUL, 0x0UL) ]
        [ Q(0, 0xffffUL, 0x0UL) ]
        [ Q(0, 0xffffUL, 0x0UL) ]
        [ Q(0, 0xffffUL, 0x0UL) ] ]
    check "2ef8d820" []
      [ [ Q(0, 0xffffUL, 0x0UL) ]
        [ Q(0, 0xffff0000ffffUL, 0x0UL) ]
        [ Q(0, 0xffffffffffffUL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffffffffUL, 0x0UL) ] ]
    check "2ea0d820" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xffffffffUL, 0x0UL) ]
        [ Q(0, 0xffffffffUL, 0x0UL) ] ]
    check "6ea0d820" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0xffffffff00000000UL) ]
        [ Q(0, 0xffffffffUL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffffUL, 0xffffffffUL) ] ]
    check "6ee0d820" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0xffffffffffffffffUL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "6ef8d820" []
      [ [ Q(0, 0xffffUL, 0xffff00000000UL); Fpsr 0x1UL ]
        [ Q(0, 0xffff0000ffffUL, 0xffff00000000ffffUL) ]
        [ Q(0, 0xffffffffffffUL, 0xffff0000ffffUL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffffffffUL, 0xffffffffffffUL) ] ]

  /// C7.2.65 FCMLT (zero)
  [<TestMethod>]
  member _.``C7.2.65 FCMLT``() =
    check "5ef8e820" []
      [ [ Q(0, 0xffffUL, 0x0UL) ]
        [ Q(0, 0xffffUL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "0ef8e820" []
      [ [ Q(0, 0xffffUL, 0x0UL) ]
        [ Q(0, 0xffff0000ffffUL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "0ea0e820" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "4ea0e820" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0xffffffff00000000UL) ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x0UL, 0xffffffffUL) ] ]
    check "4ee0e820" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0xffffffffffffffffUL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "4ef8e820" []
      [ [ Q(0, 0xffffUL, 0xffff00000000UL); Fpsr 0x1UL ]
        [ Q(0, 0xffff0000ffffUL, 0xffff00000000ffffUL) ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x0UL, 0xffffffffffffUL) ] ]

  /// C7.2.66 FCMP
  [<TestMethod>]
  member _.``C7.2.66 FCMP``() =
    check "1ee22020" []
      [ [ Nzcv 0x30000000UL ]
        [ Nzcv 0x80000000UL ]
        [ Nzcv 0x80000000UL ]
        [ Nzcv 0x60000000UL ] ]
    check "1ee02028" []
      [ [ Nzcv 0x80000000UL ]
        [ Nzcv 0x80000000UL ]
        []
        [ Nzcv 0x60000000UL ] ]
    check "1e222020" []
      [ [ Nzcv 0x80000000UL ]
        [ Nzcv 0x20000000UL ]
        [ Nzcv 0x80000000UL ]
        [ Nzcv 0x60000000UL ] ]
    check "1e202028" []
      [ [ Nzcv 0x20000000UL ]
        [ Nzcv 0x20000000UL ]
        []
        [ Nzcv 0x60000000UL ] ]
    check "1e602028" []
      [ [ Nzcv 0x20000000UL ]
        [ Nzcv 0x20000000UL ]
        [ Nzcv 0x20000000UL ]
        [ Nzcv 0x20000000UL ] ]
    check "1e622020" []
      [ [ Nzcv 0x20000000UL ]
        [ Nzcv 0x80000000UL ]
        [ Nzcv 0x20000000UL ]
        [ Nzcv 0x20000000UL ] ]

  /// C7.2.67 FCMPE
  [<TestMethod>]
  member _.``C7.2.67 FCMPE``() =
    check "1ee22030" []
      [ [ Nzcv 0x30000000UL; Fpsr 0x1UL ]
        [ Nzcv 0x80000000UL ]
        [ Nzcv 0x80000000UL ]
        [ Nzcv 0x60000000UL ] ]
    check "1ee02038" []
      [ [ Nzcv 0x80000000UL ]
        [ Nzcv 0x80000000UL ]
        []
        [ Nzcv 0x60000000UL ] ]
    check "1e222030" []
      [ [ Nzcv 0x80000000UL ]
        [ Nzcv 0x20000000UL ]
        [ Nzcv 0x80000000UL ]
        [ Nzcv 0x60000000UL ] ]
    check "1e202038" []
      [ [ Nzcv 0x20000000UL ]
        [ Nzcv 0x20000000UL ]
        []
        [ Nzcv 0x60000000UL ] ]
    check "1e602038" []
      [ [ Nzcv 0x20000000UL ]
        [ Nzcv 0x20000000UL ]
        [ Nzcv 0x20000000UL ]
        [ Nzcv 0x20000000UL ] ]
    check "1e622030" []
      [ [ Nzcv 0x20000000UL ]
        [ Nzcv 0x80000000UL ]
        [ Nzcv 0x20000000UL ]
        [ Nzcv 0x20000000UL ] ]
    check "1e212010" []
      [ [ Nzcv 0x80000000UL ]
        [ Nzcv 0x80000000UL ]
        [ Nzcv 0x20000000UL ]
        [ Nzcv 0x60000000UL ] ]
    check "1e602018" []
      [ [ Nzcv 0x80000000UL ]
        [ Nzcv 0x80000000UL ]
        [ Nzcv 0x80000000UL ]
        [ Nzcv 0x20000000UL ] ]

  /// C7.2.68 FCSEL
  [<TestMethod>]
  member _.``C7.2.68 FCSEL``() =
    check "1ee20c20" []
      [ [ Q(0, 0xff0cUL, 0x0UL) ]
        [ Q(0, 0x9e24UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e220c20" []
      [ [ Q(0, 0x56feff0cUL, 0x0UL) ]
        [ Q(0, 0x5f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x80000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e620c20" []
      [ [ Q(0, 0x879e2e2256feff0cUL, 0x0UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x8000000000000000UL, 0x0UL) ] ]

  /// C7.2.69 FCVT
  [<TestMethod>]
  member _.``C7.2.69 FCVT``() =
    check "1e22c020" []
      [ [ Q(0, 0x411b9c0380000000UL, 0x0UL) ]
        [ Q(0, 0x43e1f3c480000000UL, 0x0UL) ]
        [ Q(0, 0x8000000000000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1ee24020" []
      [ [ Q(0, 0xc4038000UL, 0x0UL) ]
        [ Q(0, 0xbbc48000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e23c020" []
      [ [ Q(0, 0x7c00UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x7c00UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x8000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e63c020" []
      [ [ Q(0, 0x7c00UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x7c00UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x7c00UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x4200UL, 0x0UL) ] ]
    check "1e624020" []
      [ [ Q(0, 0x7f800000UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x7f800000UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x7f800000UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x40400000UL, 0x0UL) ] ]
    check "1ee2c020" []
      [ [ Q(0, 0xc080700000000000UL, 0x0UL) ]
        [ Q(0, 0xbf78900000000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]

  /// C7.2.70 FCVTAS (vector)
  [<TestMethod>]
  member _.``C7.2.70 FCVTAS``() =
    check "9e640020" []
      [ [ X(0, 0x7fffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x7fffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x7fffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x3UL) ] ]
    check "5e79c820" []
      [ [ Q(0, 0xfdf2UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "0e79c820" []
      [ [ Q(0, 0x23081cbc000afdf2UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x7d000001c40000UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x2000000000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "4e79c820" []
      [ [ Q(0, 0x23081cbc000afdf2UL, 0x2000000000000UL); Fpsr 0x11UL ]
        [ Q(0, 0x7d000001c40000UL, 0xfce7000001c80000UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x2000000000000UL, 0x2000000000000UL); Fpsr 0x10UL ] ]
    check "0e21c820" []
      [ [ Q(0, 0x7fffffff0006e701UL, 0x0UL); Fpsr 0x11UL ]
        [ Q(0, 0x7fffffff7fffffffUL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x7fffffff00000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x200000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "4e21c820" []
      [ [ Q(0, 0x7fffffff0006e701UL, 0x700000000UL); Fpsr 0x11UL ]
        [ Q(0, 0x7fffffff7fffffffUL, 0x800000007fffffffUL); Fpsr 0x1UL ]
        [ Q(0, 0x7fffffff00000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x200000000UL, 0x100000000UL); Fpsr 0x10UL ] ]
    check "4e61c820" []
      [ [ Q(0, 0x7fffffffffffffffUL, 0x5a09UL); Fpsr 0x11UL ]
        [ Q(0, 0x7fffffffffffffffUL, 0x8000000000000000UL); Fpsr 0x1UL ]
        [ Q(0, 0x7fffffffffffffffUL, 0x7fffffffffffffffUL); Fpsr 0x1UL ]
        [ Q(0, 0x3UL, 0x0UL); Fpsr 0x10UL ] ]
    check "1ee40020" []
      [ [ X(0, 0xfffffdf2UL) ]
        [ X(0, 0x0UL); Fpsr 0x10UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "1e240020" []
      [ [ X(0, 0x6e701UL); Fpsr 0x10UL ]
        [ X(0, 0x7fffffffUL); Fpsr 0x1UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "9e240020" []
      [ [ X(0, 0x6e701UL); Fpsr 0x10UL ]
        [ X(0, 0x7fffffffffffffffUL); Fpsr 0x1UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "1e640020" []
      [ [ X(0, 0x7fffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x7fffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x7fffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x3UL) ] ]
    check "9ee40020" []
      [ [ X(0, 0xfffffffffffffdf2UL) ]
        [ X(0, 0x0UL); Fpsr 0x10UL ]
        []
        [ X(0, 0x0UL) ] ]

  /// C7.2.72 FCVTAU (vector)
  [<TestMethod>]
  member _.``C7.2.72 FCVTAU``() =
    check "9e650020" []
      [ [ X(0, 0xffffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0xffffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0xffffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x3UL) ] ]
    check "7e79c820" []
      [ [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "2e79c820" []
      [ [ Q(0, 0x23081cbc000a0000UL, 0x0UL); Fpsr 0x11UL ]
        [ Q(0, 0x7d000001c40000UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x2000000000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "6e79c820" []
      [ [ Q(0, 0x23081cbc000a0000UL, 0x2000000000000UL); Fpsr 0x11UL ]
        [ Q(0, 0x7d000001c40000UL, 0x1c80000UL); Fpsr 0x11UL ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x2000000000000UL, 0x2000000000000UL); Fpsr 0x10UL ] ]
    check "2e21c820" []
      [ [ Q(0, 0xffffffff0006e701UL, 0x0UL); Fpsr 0x11UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x200000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "6e21c820" []
      [ [ Q(0, 0xffffffff0006e701UL, 0x700000000UL); Fpsr 0x11UL ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffUL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x200000000UL, 0x100000000UL); Fpsr 0x10UL ] ]
    check "6e61c820" []
      [ [ Q(0, 0xffffffffffffffffUL, 0x5a09UL); Fpsr 0x11UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL); Fpsr 0x1UL ]
        [ Q(0, 0x3UL, 0x0UL); Fpsr 0x10UL ] ]
    check "1ee50020" []
      [ [ X(0, 0x0UL); Fpsr 0x1UL ]
        [ X(0, 0x0UL); Fpsr 0x10UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "1e250020" []
      [ [ X(0, 0x6e701UL); Fpsr 0x10UL ]
        [ X(0, 0xffffffffUL); Fpsr 0x1UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "9e250020" []
      [ [ X(0, 0x6e701UL); Fpsr 0x10UL ]
        [ X(0, 0x8f9e240000000000UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "1e650020" []
      [ [ X(0, 0xffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0xffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0xffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x3UL) ] ]
    check "9ee50020" []
      [ [ X(0, 0x0UL); Fpsr 0x1UL ]
        [ X(0, 0x0UL); Fpsr 0x10UL ]
        []
        [ X(0, 0x0UL) ] ]

  /// C7.2.74 FCVTL, FCVTL2
  [<TestMethod>]
  member _.``C7.2.74 FCVTL``() =
    check "0e217820" []
      [ [ Q(0, 0x411b8000c4038000UL, 0x460c200045e5e000UL) ]
        [ Q(0, 0x43e1e000bbc48000UL, 0x42f90000b8494000UL) ]
        [ Q(0, 0x8000000000000000UL, 0x7ff0000000000000UL) ]
        [ Q(0, 0x0UL, 0x4001000000000000UL) ] ]
    check "0e617820" []
      [ [ Q(0, 0x411b9c0380000000UL, 0x460c2de5e0000000UL) ]
        [ Q(0, 0x43e1f3c480000000UL, 0x42f91064a0000000UL) ]
        [ Q(0, 0x8000000000000000UL, 0x7ff0000000000000UL) ]
        [ Q(0, 0x0UL, 0x4001000000000000UL) ] ]

  /// C7.2.74 FCVTL, FCVTL2
  [<TestMethod>]
  member _.``C7.2.74 FCVTL2``() =
    check "4e617820" []
      [ [ Q(0, 0x3dde7f82e0000000UL, 0x401ad049c0000000UL) ]
        [ Q(0, 0x43e3f61520000000UL, 0xc446236a60000000UL) ]
        [ Q(0, 0x7ff8000000000000UL, 0x7ffc000000000000UL); Fpsr 0x1UL ]
        [ Q(0, 0xbb33333340000000UL, 0x3ff7333320000000UL) ] ]
    check "4e217820" []
      [ [ Q(0, 0x3dde6000ffc2e000UL, 0x401ac000b8138000UL); Fpsr 0x1UL ]
        [ Q(0, 0x43e3e000be152000UL, 0xc44620003b6a6000UL) ]
        [ Q(0, 0x7ff8000000000000UL, 0x7ff4000000000000UL) ]
        [ Q(0, 0xbb332000bb334000UL, 0x3ff72000bb332000UL) ] ]

  /// C7.2.75 FCVTMS (vector)
  [<TestMethod>]
  member _.``C7.2.75 FCVTMS``() =
    check "9e700020" []
      [ [ X(0, 0x7fffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x7fffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x7fffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x3UL) ] ]
    check "5e79b820" []
      [ [ Q(0, 0xfdf2UL, 0x0UL) ]
        [ Q(0, 0xffffUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "0e79b820" []
      [ [ Q(0, 0x23081cbc0009fdf2UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x7cffff01c3ffffUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x2000000000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "4e79b820" []
      [ [ Q(0, 0x23081cbc0009fdf2UL, 0x2ffff00000000UL); Fpsr 0x11UL ]
        [ Q(0, 0x7cffff01c3ffffUL, 0xfce7000001c7ffffUL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x2000000000000UL, 0x1ffffffffffffUL); Fpsr 0x10UL ] ]
    check "0e21b820" []
      [ [ Q(0, 0x7fffffff0006e700UL, 0x0UL); Fpsr 0x11UL ]
        [ Q(0, 0x7fffffff7fffffffUL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x7fffffff00000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x200000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "4e21b820" []
      [ [ Q(0, 0x7fffffff0006e700UL, 0x600000000UL); Fpsr 0x11UL ]
        [ Q(0, 0x7fffffff7fffffffUL, 0x800000007fffffffUL); Fpsr 0x1UL ]
        [ Q(0, 0x7fffffff00000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x200000000UL, 0x1ffffffffUL); Fpsr 0x10UL ] ]
    check "4e61b820" []
      [ [ Q(0, 0x7fffffffffffffffUL, 0x5a09UL); Fpsr 0x11UL ]
        [ Q(0, 0x7fffffffffffffffUL, 0x8000000000000000UL); Fpsr 0x1UL ]
        [ Q(0, 0x7fffffffffffffffUL, 0x7fffffffffffffffUL); Fpsr 0x1UL ]
        [ Q(0, 0x3UL, 0x0UL); Fpsr 0x10UL ] ]
    check "1ef00020" []
      [ [ X(0, 0xfffffdf2UL) ]
        [ X(0, 0xffffffffUL); Fpsr 0x10UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "1e300020" []
      [ [ X(0, 0x6e700UL); Fpsr 0x10UL ]
        [ X(0, 0x7fffffffUL); Fpsr 0x1UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "9e300020" []
      [ [ X(0, 0x6e700UL); Fpsr 0x10UL ]
        [ X(0, 0x7fffffffffffffffUL); Fpsr 0x1UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "1e700020" []
      [ [ X(0, 0x7fffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x7fffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x7fffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x3UL) ] ]
    check "9ef00020" []
      [ [ X(0, 0xfffffffffffffdf2UL) ]
        [ X(0, 0xffffffffffffffffUL); Fpsr 0x10UL ]
        []
        [ X(0, 0x0UL) ] ]

  /// C7.2.77 FCVTMU (vector)
  [<TestMethod>]
  member _.``C7.2.77 FCVTMU``() =
    check "9e710020" []
      [ [ X(0, 0xffffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0xffffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0xffffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x3UL) ] ]
    check "7e79b820" []
      [ [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "2e79b820" []
      [ [ Q(0, 0x23081cbc00090000UL, 0x0UL); Fpsr 0x11UL ]
        [ Q(0, 0x7c000001c30000UL, 0x0UL); Fpsr 0x11UL ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x2000000000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "6e79b820" []
      [ [ Q(0, 0x23081cbc00090000UL, 0x2000000000000UL); Fpsr 0x11UL ]
        [ Q(0, 0x7c000001c30000UL, 0x1c70000UL); Fpsr 0x11UL ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x2000000000000UL, 0x1000000000000UL); Fpsr 0x11UL ] ]
    check "2e21b820" []
      [ [ Q(0, 0xffffffff0006e700UL, 0x0UL); Fpsr 0x11UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x200000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "6e21b820" []
      [ [ Q(0, 0xffffffff0006e700UL, 0x600000000UL); Fpsr 0x11UL ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffUL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x200000000UL, 0x100000000UL); Fpsr 0x11UL ] ]
    check "6e61b820" []
      [ [ Q(0, 0xffffffffffffffffUL, 0x5a09UL); Fpsr 0x11UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL); Fpsr 0x1UL ]
        [ Q(0, 0x3UL, 0x0UL); Fpsr 0x10UL ] ]
    check "1ef10020" []
      [ [ X(0, 0x0UL); Fpsr 0x1UL ]
        [ X(0, 0x0UL); Fpsr 0x1UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "1e310020" []
      [ [ X(0, 0x6e700UL); Fpsr 0x10UL ]
        [ X(0, 0xffffffffUL); Fpsr 0x1UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "9e310020" []
      [ [ X(0, 0x6e700UL); Fpsr 0x10UL ]
        [ X(0, 0x8f9e240000000000UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "1e710020" []
      [ [ X(0, 0xffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0xffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0xffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x3UL) ] ]
    check "9ef10020" []
      [ [ X(0, 0x0UL); Fpsr 0x1UL ]
        [ X(0, 0x0UL); Fpsr 0x1UL ]
        []
        [ X(0, 0x0UL) ] ]

  /// C7.2.79 FCVTN, FCVTN2
  [<TestMethod>]
  member _.``C7.2.79 FCVTN``() =
    check "0e216820" []
      [ [ Q(0, 0x46b400007c007c00UL, 0x0UL); Fpsr 0x1cUL ]
        [ Q(0, 0xfc007c007c007c00UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x7f007e007c008000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x3dcd800040400000UL, 0x0UL); Fpsr 0x18UL ] ]
    check "0e616820" []
      [ [ Q(0, 0x46b412717f800000UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0xff8000007f800000UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x7f8000007f800000UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x3dcccccd40400000UL, 0x0UL); Fpsr 0x10UL ] ]

  /// C7.2.79 FCVTN, FCVTN2
  [<TestMethod>]
  member _.``C7.2.79 FCVTN2``() =
    check "4e616820" []
      [ [ Q(0, 0x962b1967c90789baUL, 0x46b412717f800000UL); Fpsr 0x14UL ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0xff8000007f800000UL); Fpsr 0x14UL ]
        [ Q(0, 0xbfc000003f800000UL, 0x7f8000007f800000UL); Fpsr 0x14UL ]
        [ Q(0, 0x3ff0000000000000UL, 0x3dcccccd40400000UL); Fpsr 0x10UL ] ]
    check "4e216820" []
      [ [ Q(0, 0x962b1967c90789baUL, 0x46b400007c007c00UL); Fpsr 0x1cUL ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0xfc007c007c007c00UL); Fpsr 0x14UL ]
        [ Q(0, 0xbfc000003f800000UL, 0x7f007e007c008000UL); Fpsr 0x1UL ]
        [ Q(0, 0x3ff0000000000000UL, 0x3dcd800040400000UL); Fpsr 0x18UL ] ]

  /// C7.2.80 FCVTNS (vector)
  [<TestMethod>]
  member _.``C7.2.80 FCVTNS``() =
    check "9e600020" []
      [ [ X(0, 0x7fffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x7fffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x7fffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x3UL) ] ]
    check "5e79a820" []
      [ [ Q(0, 0xfdf2UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "0e79a820" []
      [ [ Q(0, 0x23081cbc000afdf2UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x7c000001c40000UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x2000000000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "4e79a820" []
      [ [ Q(0, 0x23081cbc000afdf2UL, 0x2000000000000UL); Fpsr 0x11UL ]
        [ Q(0, 0x7c000001c40000UL, 0xfce8000001c80000UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x2000000000000UL, 0x2000000000000UL); Fpsr 0x10UL ] ]
    check "0e21a820" []
      [ [ Q(0, 0x7fffffff0006e701UL, 0x0UL); Fpsr 0x11UL ]
        [ Q(0, 0x7fffffff7fffffffUL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x7fffffff00000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x200000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "4e61a820" []
      [ [ Q(0, 0x7fffffffffffffffUL, 0x5a09UL); Fpsr 0x11UL ]
        [ Q(0, 0x7fffffffffffffffUL, 0x8000000000000000UL); Fpsr 0x1UL ]
        [ Q(0, 0x7fffffffffffffffUL, 0x7fffffffffffffffUL); Fpsr 0x1UL ]
        [ Q(0, 0x3UL, 0x0UL); Fpsr 0x10UL ] ]
    check "1ee00020" []
      [ [ X(0, 0xfffffdf2UL) ]
        [ X(0, 0x0UL); Fpsr 0x10UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "1e200020" []
      [ [ X(0, 0x6e701UL); Fpsr 0x10UL ]
        [ X(0, 0x7fffffffUL); Fpsr 0x1UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "9e200020" []
      [ [ X(0, 0x6e701UL); Fpsr 0x10UL ]
        [ X(0, 0x7fffffffffffffffUL); Fpsr 0x1UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "1e600020" []
      [ [ X(0, 0x7fffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x7fffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x7fffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x3UL) ] ]
    check "9ee00020" []
      [ [ X(0, 0xfffffffffffffdf2UL) ]
        [ X(0, 0x0UL); Fpsr 0x10UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "4e21a820" []
      [ [ Q(0, 0x7fffffff0006e701UL, 0x700000000UL); Fpsr 0x11UL ]
        [ Q(0, 0x7fffffff7fffffffUL, 0x800000007fffffffUL); Fpsr 0x1UL ]
        [ Q(0, 0x7fffffff00000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x200000000UL, 0x100000000UL); Fpsr 0x10UL ] ]

  /// C7.2.82 FCVTNU (vector)
  [<TestMethod>]
  member _.``C7.2.82 FCVTNU``() =
    check "9e610020" []
      [ [ X(0, 0xffffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0xffffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0xffffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x3UL) ] ]
    check "7e79a820" []
      [ [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "2e79a820" []
      [ [ Q(0, 0x23081cbc000a0000UL, 0x0UL); Fpsr 0x11UL ]
        [ Q(0, 0x7c000001c40000UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x2000000000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "6e79a820" []
      [ [ Q(0, 0x23081cbc000a0000UL, 0x2000000000000UL); Fpsr 0x11UL ]
        [ Q(0, 0x7c000001c40000UL, 0x1c80000UL); Fpsr 0x11UL ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x2000000000000UL, 0x2000000000000UL); Fpsr 0x10UL ] ]
    check "2e21a820" []
      [ [ Q(0, 0xffffffff0006e701UL, 0x0UL); Fpsr 0x11UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x200000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "6e21a820" []
      [ [ Q(0, 0xffffffff0006e701UL, 0x700000000UL); Fpsr 0x11UL ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffUL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x200000000UL, 0x100000000UL); Fpsr 0x10UL ] ]
    check "6e61a820" []
      [ [ Q(0, 0xffffffffffffffffUL, 0x5a09UL); Fpsr 0x11UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL); Fpsr 0x1UL ]
        [ Q(0, 0x3UL, 0x0UL); Fpsr 0x10UL ] ]
    check "1ee10020" []
      [ [ X(0, 0x0UL); Fpsr 0x1UL ]
        [ X(0, 0x0UL); Fpsr 0x10UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "1e210020" []
      [ [ X(0, 0x6e701UL); Fpsr 0x10UL ]
        [ X(0, 0xffffffffUL); Fpsr 0x1UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "9e210020" []
      [ [ X(0, 0x6e701UL); Fpsr 0x10UL ]
        [ X(0, 0x8f9e240000000000UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "1e610020" []
      [ [ X(0, 0xffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0xffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0xffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x3UL) ] ]
    check "9ee10020" []
      [ [ X(0, 0x0UL); Fpsr 0x1UL ]
        [ X(0, 0x0UL); Fpsr 0x10UL ]
        []
        [ X(0, 0x0UL) ] ]

  /// C7.2.84 FCVTPS (vector)
  [<TestMethod>]
  member _.``C7.2.84 FCVTPS``() =
    check "9e680020" []
      [ [ X(0, 0x7fffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x7fffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x7fffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x3UL) ] ]
    check "5ef9a820" []
      [ [ Q(0, 0xfdf2UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "0ef9a820" []
      [ [ Q(0, 0x23081cbc000afdf2UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x7d000001c40000UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x3000000000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "4ef9a820" []
      [ [ Q(0, 0x23081cbc000afdf2UL, 0x3000000010000UL); Fpsr 0x11UL ]
        [ Q(0, 0x7d000001c40000UL, 0xfce8000101c80000UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x3000000000000UL, 0x2000000000000UL); Fpsr 0x10UL ] ]
    check "0ea1a820" []
      [ [ Q(0, 0x7fffffff0006e701UL, 0x0UL); Fpsr 0x11UL ]
        [ Q(0, 0x7fffffff7fffffffUL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x7fffffff00000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x300000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "4ea1a820" []
      [ [ Q(0, 0x7fffffff0006e701UL, 0x700000001UL); Fpsr 0x11UL ]
        [ Q(0, 0x7fffffff7fffffffUL, 0x800000007fffffffUL); Fpsr 0x1UL ]
        [ Q(0, 0x7fffffff00000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x300000000UL, 0x200000000UL); Fpsr 0x10UL ] ]
    check "4ee1a820" []
      [ [ Q(0, 0x7fffffffffffffffUL, 0x5a0aUL); Fpsr 0x11UL ]
        [ Q(0, 0x7fffffffffffffffUL, 0x8000000000000000UL); Fpsr 0x1UL ]
        [ Q(0, 0x7fffffffffffffffUL, 0x7fffffffffffffffUL); Fpsr 0x1UL ]
        [ Q(0, 0x3UL, 0x1UL); Fpsr 0x10UL ] ]
    check "1ee80020" []
      [ [ X(0, 0xfffffdf2UL) ]
        [ X(0, 0x0UL); Fpsr 0x10UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "1e280020" []
      [ [ X(0, 0x6e701UL); Fpsr 0x10UL ]
        [ X(0, 0x7fffffffUL); Fpsr 0x1UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "9e280020" []
      [ [ X(0, 0x6e701UL); Fpsr 0x10UL ]
        [ X(0, 0x7fffffffffffffffUL); Fpsr 0x1UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "1e680020" []
      [ [ X(0, 0x7fffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x7fffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x7fffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x3UL) ] ]
    check "9ee80020" []
      [ [ X(0, 0xfffffffffffffdf2UL) ]
        [ X(0, 0x0UL); Fpsr 0x10UL ]
        []
        [ X(0, 0x0UL) ] ]

  /// C7.2.86 FCVTPU (vector)
  [<TestMethod>]
  member _.``C7.2.86 FCVTPU``() =
    check "9e690020" []
      [ [ X(0, 0xffffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0xffffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0xffffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x3UL) ] ]
    check "7ef9a820" []
      [ [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "2ef9a820" []
      [ [ Q(0, 0x23081cbc000a0000UL, 0x0UL); Fpsr 0x11UL ]
        [ Q(0, 0x7d000001c40000UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x3000000000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "6ef9a820" []
      [ [ Q(0, 0x23081cbc000a0000UL, 0x3000000010000UL); Fpsr 0x11UL ]
        [ Q(0, 0x7d000001c40000UL, 0x101c80000UL); Fpsr 0x11UL ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x3000000000000UL, 0x2000000000000UL); Fpsr 0x10UL ] ]
    check "2ea1a820" []
      [ [ Q(0, 0xffffffff0006e701UL, 0x0UL); Fpsr 0x11UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x300000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "6ea1a820" []
      [ [ Q(0, 0xffffffff0006e701UL, 0x700000001UL); Fpsr 0x11UL ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffUL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x300000000UL, 0x200000000UL); Fpsr 0x10UL ] ]
    check "6ee1a820" []
      [ [ Q(0, 0xffffffffffffffffUL, 0x5a0aUL); Fpsr 0x11UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL); Fpsr 0x1UL ]
        [ Q(0, 0x3UL, 0x1UL); Fpsr 0x10UL ] ]
    check "1ee90020" []
      [ [ X(0, 0x0UL); Fpsr 0x1UL ]
        [ X(0, 0x0UL); Fpsr 0x10UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "1e290020" []
      [ [ X(0, 0x6e701UL); Fpsr 0x10UL ]
        [ X(0, 0xffffffffUL); Fpsr 0x1UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "9e290020" []
      [ [ X(0, 0x6e701UL); Fpsr 0x10UL ]
        [ X(0, 0x8f9e240000000000UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "1e690020" []
      [ [ X(0, 0xffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0xffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0xffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x3UL) ] ]
    check "9ee90020" []
      [ [ X(0, 0x0UL); Fpsr 0x1UL ]
        [ X(0, 0x0UL); Fpsr 0x10UL ]
        []
        [ X(0, 0x0UL) ] ]

  /// C7.2.88 FCVTXN, FCVTXN2
  [<TestMethod>]
  member _.``C7.2.88 FCVTXN``() =
    check "2e616820" []
      [ [ Q(0, 0x46b412717f7fffffUL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0xff7fffff7f7fffffUL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x7f7fffff7f7fffffUL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x3dcccccd40400000UL, 0x0UL); Fpsr 0x10UL ] ]

  /// C7.2.88 FCVTXN, FCVTXN2
  [<TestMethod>]
  member _.``C7.2.88 FCVTXN2``() =
    check "6e616820" []
      [ [ Q(0, 0x962b1967c90789baUL, 0x46b412717f7fffffUL); Fpsr 0x14UL ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0xff7fffff7f7fffffUL); Fpsr 0x14UL ]
        [ Q(0, 0xbfc000003f800000UL, 0x7f7fffff7f7fffffUL); Fpsr 0x14UL ]
        [ Q(0, 0x3ff0000000000000UL, 0x3dcccccd40400000UL); Fpsr 0x10UL ] ]

  /// C7.2.89 FCVTZS (vector, fixed-point)
  [<TestMethod>]
  member _.``C7.2.89 FCVTZS``() =
    check "9e780020" []
      [ [ X(0, 0x7fffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x7fffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x7fffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x3UL) ] ]
    check "0f1bfc20" []
      [ [ Q(0, 0x7fff7fff0137be40UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xf90000038780000UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x40000000000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "4f1bfc20" []
      [ [ Q(0, 0x7fff7fff0137be40UL, 0x4d000000030000UL); Fpsr 0x11UL ]
        [ Q(0, 0xf90000038780000UL, 0x9cf0000038f8fffcUL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x40000000000000UL, 0x3d000000000000UL); Fpsr 0x10UL ] ]
    check "0f3bfc20" []
      [ [ Q(0, 0x7fffffff00dce01cUL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x7fffffff7fffffffUL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x7fffffff00000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x4400000000UL, 0x0UL) ] ]
    check "4f3bfc20" []
      [ [ Q(0, 0x7fffffff00dce01cUL, 0xd600000000UL); Fpsr 0x11UL ]
        [ Q(0, 0x7fffffff7fffffffUL, 0x800000007fffffffUL); Fpsr 0x1UL ]
        [ Q(0, 0x7fffffff00000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x4400000000UL, 0x2e00000000UL); Fpsr 0x10UL ] ]
    check "4f7bfc20" []
      [ [ Q(0, 0x7fffffffffffffffUL, 0xb4127UL); Fpsr 0x11UL ]
        [ Q(0, 0x7fffffffffffffffUL, 0x8000000000000000UL); Fpsr 0x1UL ]
        [ Q(0, 0x7fffffffffffffffUL, 0x7fffffffffffffffUL); Fpsr 0x1UL ]
        [ Q(0, 0x60UL, 0x3UL); Fpsr 0x10UL ] ]
    check "5ef9b820" []
      [ [ Q(0, 0xfdf2UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "0ef9b820" []
      [ [ Q(0, 0x23081cbc0009fdf2UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x7c000001c30000UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x2000000000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "4ef9b820" []
      [ [ Q(0, 0x23081cbc0009fdf2UL, 0x2000000000000UL); Fpsr 0x11UL ]
        [ Q(0, 0x7c000001c30000UL, 0xfce8000001c70000UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x2000000000000UL, 0x1000000000000UL); Fpsr 0x10UL ] ]
    check "0ea1b820" []
      [ [ Q(0, 0x7fffffff0006e700UL, 0x0UL); Fpsr 0x11UL ]
        [ Q(0, 0x7fffffff7fffffffUL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x7fffffff00000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x200000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "4ea1b820" []
      [ [ Q(0, 0x7fffffff0006e700UL, 0x600000000UL); Fpsr 0x11UL ]
        [ Q(0, 0x7fffffff7fffffffUL, 0x800000007fffffffUL); Fpsr 0x1UL ]
        [ Q(0, 0x7fffffff00000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x200000000UL, 0x100000000UL); Fpsr 0x10UL ] ]
    check "4ee1b820" []
      [ [ Q(0, 0x7fffffffffffffffUL, 0x5a09UL); Fpsr 0x11UL ]
        [ Q(0, 0x7fffffffffffffffUL, 0x8000000000000000UL); Fpsr 0x1UL ]
        [ Q(0, 0x7fffffffffffffffUL, 0x7fffffffffffffffUL); Fpsr 0x1UL ]
        [ Q(0, 0x3UL, 0x0UL); Fpsr 0x10UL ] ]
    check "1ed8ec20" []
      [ [ X(0, 0xffffbe40UL) ]
        [ X(0, 0x0UL); Fpsr 0x10UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "9ed8ec20" []
      [ [ X(0, 0xffffffffffffbe40UL) ]
        [ X(0, 0x0UL); Fpsr 0x10UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "1e18ec20" []
      [ [ X(0, 0xdce01cUL) ]
        [ X(0, 0x7fffffffUL); Fpsr 0x1UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "9e18ec20" []
      [ [ X(0, 0xdce01cUL) ]
        [ X(0, 0x7fffffffffffffffUL); Fpsr 0x1UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "1e58ec20" []
      [ [ X(0, 0x7fffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x7fffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x7fffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x60UL) ] ]
    check "9e58ec20" []
      [ [ X(0, 0x7fffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x7fffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x7fffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x60UL) ] ]
    check "1ef80020" []
      [ [ X(0, 0xfffffdf2UL) ]
        [ X(0, 0x0UL); Fpsr 0x10UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "9ef80020" []
      [ [ X(0, 0xfffffffffffffdf2UL) ]
        [ X(0, 0x0UL); Fpsr 0x10UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "1e380020" []
      [ [ X(0, 0x6e700UL); Fpsr 0x10UL ]
        [ X(0, 0x7fffffffUL); Fpsr 0x1UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "9e380020" []
      [ [ X(0, 0x6e700UL); Fpsr 0x10UL ]
        [ X(0, 0x7fffffffffffffffUL); Fpsr 0x1UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "1e780020" []
      [ [ X(0, 0x7fffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x7fffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x7fffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x3UL) ] ]
    check "9ed8fc20" []
      [ [ X(0, 0xfffffffffffffbe4UL) ]
        [ X(0, 0x0UL); Fpsr 0x10UL ]
        []
        [ X(0, 0x0UL) ] ]

  /// C7.2.93 FCVTZU (vector, fixed-point)
  [<TestMethod>]
  member _.``C7.2.93 FCVTZU``() =
    check "9e790020" []
      [ [ X(0, 0xffffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0xffffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0xffffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x3UL) ] ]
    check "2f1bfc20" []
      [ [ Q(0, 0xffffffff01370000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xf90000038780000UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x40000000000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "6f1bfc20" []
      [ [ Q(0, 0xffffffff01370000UL, 0x4d000000030000UL); Fpsr 0x11UL ]
        [ Q(0, 0xf90000038780000UL, 0x38f80000UL); Fpsr 0x11UL ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x40000000000000UL, 0x3d000000000000UL); Fpsr 0x10UL ] ]
    check "2f3bfc20" []
      [ [ Q(0, 0xffffffff00dce01cUL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x4400000000UL, 0x0UL) ] ]
    check "6f3bfc20" []
      [ [ Q(0, 0xffffffff00dce01cUL, 0xd600000000UL); Fpsr 0x11UL ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffUL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x4400000000UL, 0x2e00000000UL); Fpsr 0x10UL ] ]
    check "6f7bfc20" []
      [ [ Q(0, 0xffffffffffffffffUL, 0xb4127UL); Fpsr 0x11UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL); Fpsr 0x1UL ]
        [ Q(0, 0x60UL, 0x3UL); Fpsr 0x10UL ] ]
    check "7ef9b820" []
      [ [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "2ef9b820" []
      [ [ Q(0, 0x23081cbc00090000UL, 0x0UL); Fpsr 0x11UL ]
        [ Q(0, 0x7c000001c30000UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x2000000000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "6ef9b820" []
      [ [ Q(0, 0x23081cbc00090000UL, 0x2000000000000UL); Fpsr 0x11UL ]
        [ Q(0, 0x7c000001c30000UL, 0x1c70000UL); Fpsr 0x11UL ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x2000000000000UL, 0x1000000000000UL); Fpsr 0x10UL ] ]
    check "2ea1b820" []
      [ [ Q(0, 0xffffffff0006e700UL, 0x0UL); Fpsr 0x11UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x200000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "6ea1b820" []
      [ [ Q(0, 0xffffffff0006e700UL, 0x600000000UL); Fpsr 0x11UL ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffUL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x200000000UL, 0x100000000UL); Fpsr 0x10UL ] ]
    check "6ee1b820" []
      [ [ Q(0, 0xffffffffffffffffUL, 0x5a09UL); Fpsr 0x11UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL); Fpsr 0x1UL ]
        [ Q(0, 0x3UL, 0x0UL); Fpsr 0x10UL ] ]
    check "1ed9ec20" []
      [ [ X(0, 0x0UL); Fpsr 0x1UL ]
        [ X(0, 0x0UL); Fpsr 0x10UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "9ed9ec20" []
      [ [ X(0, 0x0UL); Fpsr 0x1UL ]
        [ X(0, 0x0UL); Fpsr 0x10UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "1e19ec20" []
      [ [ X(0, 0xdce01cUL) ]
        [ X(0, 0xffffffffUL); Fpsr 0x1UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "9e19ec20" []
      [ [ X(0, 0xdce01cUL) ]
        [ X(0, 0xffffffffffffffffUL); Fpsr 0x1UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "1e59ec20" []
      [ [ X(0, 0xffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0xffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0xffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x60UL) ] ]
    check "9e59ec20" []
      [ [ X(0, 0xffffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0xffffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0xffffffffffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x60UL) ] ]
    check "1ef90020" []
      [ [ X(0, 0x0UL); Fpsr 0x1UL ]
        [ X(0, 0x0UL); Fpsr 0x10UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "9ef90020" []
      [ [ X(0, 0x0UL); Fpsr 0x1UL ]
        [ X(0, 0x0UL); Fpsr 0x10UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "1e390020" []
      [ [ X(0, 0x6e700UL); Fpsr 0x10UL ]
        [ X(0, 0xffffffffUL); Fpsr 0x1UL ]
        []
        [ X(0, 0x0UL) ] ]
    check "9e390020" []
      [ [ X(0, 0x6e700UL); Fpsr 0x10UL ]
        [ X(0, 0x8f9e240000000000UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "1e790020" []
      [ [ X(0, 0xffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0xffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0xffffffffUL); Fpsr 0x1UL ]
        [ X(0, 0x3UL) ] ]
    check "9ed9fc20" []
      [ [ X(0, 0x0UL); Fpsr 0x1UL ]
        [ X(0, 0x0UL); Fpsr 0x10UL ]
        []
        [ X(0, 0x0UL) ] ]

  /// C7.2.97 FDIV (vector)
  [<TestMethod>]
  member _.``C7.2.97 FDIV``() =
    check "2e423c20" []
      [ [ Q(0, 0xfc007c002d8fff0cUL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x39df11a6b0dc810eUL, 0x0UL); Fpsr 0x18UL ]
        [ Q(0, 0x7f80ffff7e000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xfc007e007e007e00UL, 0x0UL); Fpsr 0x3UL ] ]
    check "6e423c20" []
      [ [ Q(0, 0xfc007c002d8fff0cUL, 0xf163bc120c6bfe17UL); Fpsr 0x15UL ]
        [ Q(0, 0x39df11a6b0dc810eUL, 0xd6b72c33b9e05067UL); Fpsr 0x18UL ]
        [ Q(0, 0x7f80ffff7e000000UL, 0x7fa07e007fc0ffffUL); Fpsr 0x1UL ]
        [ Q(0, 0xfc007e007e007e00UL, 0x7e00fc00fc00fc00UL); Fpsr 0x3UL ] ]
    check "2e22fc20" []
      [ [ Q(0, 0xff800000315dbeaeUL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x3df99361b4b0730bUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xff80000080000000UL, 0x0UL) ]
        [ Q(0, 0xff8000007fc00000UL, 0x0UL); Fpsr 0x3UL ] ]
    check "6e62fc20" []
      [ [ Q(0, 0xfff0000000000000UL, 0xf59800a52f7f21d9UL); Fpsr 0x14UL ]
        [ Q(0, 0x3e6a6f1a10a1d253UL, 0xdac0edd991b194eeUL); Fpsr 0x10UL ]
        [ Q(0, 0xfff0000000000000UL, 0x7ff0000000000000UL); Fpsr 0x14UL ]
        [ Q(0, 0xfff0000000000000UL, 0x0UL); Fpsr 0x2UL ] ]
    check "1ee21820" []
      [ [ Q(0, 0xff0cUL, 0x0UL) ]
        [ Q(0, 0x810eUL, 0x0UL); Fpsr 0x18UL ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x7e00UL, 0x0UL); Fpsr 0x1UL ] ]
    check "1e221820" []
      [ [ Q(0, 0x315dbeaeUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xb4b0730bUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x80000000UL, 0x0UL) ]
        [ Q(0, 0x7fc00000UL, 0x0UL); Fpsr 0x1UL ] ]
    check "1e621820" []
      [ [ Q(0, 0xfff0000000000000UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x3e6a6f1a10a1d253UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xfff0000000000000UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0xfff0000000000000UL, 0x0UL); Fpsr 0x2UL ] ]
    check "6e22fc20" []
      [ [ Q(0, 0xff800000315dbeaeUL, 0xf51dcaad10192df4UL); Fpsr 0x14UL ]
        [ Q(0, 0x3df99361b4b0730bUL, 0xda4a4191bdbbdc9fUL); Fpsr 0x10UL ]
        [ Q(0, 0xff80000080000000UL, 0x7fe000007fc00000UL); Fpsr 0x1UL ]
        [ Q(0, 0xff8000007fc00000UL, 0x7fc00000ff800000UL); Fpsr 0x3UL ] ]

  /// C7.2.99 FJCVTZS
  [<TestMethod>]
  member _.``C7.2.99 FJCVTZS``() =
    check "1e7e0020" []
      [ [ X(0, 0x0UL); Nzcv 0x0UL; Fpsr 0x1UL ]
        [ X(0, 0x0UL); Nzcv 0x0UL; Fpsr 0x1UL ]
        [ Nzcv 0x0UL; Fpsr 0x1UL ]
        [ X(0, 0x3UL); Nzcv 0x40000000UL ] ]

  /// C7.2.100 FMADD
  [<TestMethod>]
  member _.``C7.2.100 FMADD``() =
    check "1fc20c20" []
      [ [ Q(0, 0xff0cUL, 0x0UL) ]
        [ Q(0, 0xf7d1UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x2f9UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1f020c20" []
      [ [ Q(0, 0x605c0269UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xff800000UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x501502f9UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1f420c20" []
      [ [ Q(0, 0xbf8c59bb003553c1UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x7126baf455871849UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xc0e80080501502f9UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x7ff8000000000000UL, 0x0UL) ] ]

  /// C7.2.101 FMAX (vector)
  [<TestMethod>]
  member _.``C7.2.101 FMAX``() =
    check "0e423420" []
      [ [ Q(0, 0x70616f2f56feff0cUL, 0x0UL) ]
        [ Q(0, 0x594d83255f0f5dd3UL, 0x0UL) ]
        [ Q(0, 0x7f80ffff00000001UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4e423420" []
      [ [ Q(0, 0x70616f2f56feff0cUL, 0x40d602445e4bfe17UL); Fpsr 0x1UL ]
        [ Q(0, 0x594d83255f0f5dd3UL, 0x47602afa5f1f9c3cUL) ]
        [ Q(0, 0x7f80ffff00000001UL, 0x7fa000007fc0ffffUL) ]
        [ Q(0, 0x4008000000000000UL, 0x7e00000000000000UL) ] ]
    check "0e22f420" []
      [ [ Q(0, 0x70616f2f56feff0cUL, 0x0UL) ]
        [ Q(0, 0x594dac745f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x7f80000000000001UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4e62f420" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x40d6824e2ef3fc17UL) ]
        [ Q(0, 0x594dac74e9d05dd3UL, 0x47602afae0d99c3cUL) ]
        [ Q(0, 0x7f80000080000000UL, 0x7fa000007fc00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x7ff0000000000000UL) ] ]
    check "1ee24820" []
      [ [ Q(0, 0xff0cUL, 0x0UL) ]
        [ Q(0, 0x5dd3UL, 0x0UL) ]
        [ Q(0, 0x1UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e224820" []
      [ [ Q(0, 0x56feff0cUL, 0x0UL) ]
        [ Q(0, 0x5f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x1UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e624820" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x0UL) ]
        [ Q(0, 0x594dac74e9d05dd3UL, 0x0UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4e22f420" []
      [ [ Q(0, 0x70616f2f56feff0cUL, 0x40d6824e5e4be0f5UL) ]
        [ Q(0, 0x594dac745f0f9e24UL, 0x47602afa5f1fb0a9UL) ]
        [ Q(0, 0x7f80000000000001UL, 0x7fe000007fc00000UL); Fpsr 0x1UL ]
        [ Q(0, 0x4008000000000000UL, 0x7fc0000000000000UL) ] ]

  /// C7.2.103 FMAXNM (vector)
  [<TestMethod>]
  member _.``C7.2.103 FMAXNM``() =
    check "0e420420" []
      [ [ Q(0, 0x70616f2f56fee01cUL, 0x0UL) ]
        [ Q(0, 0x594d83255f0f5dd3UL, 0x0UL) ]
        [ Q(0, 0x807f000000000001UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4e420420" []
      [ [ Q(0, 0x70616f2f56fee01cUL, 0x40d602445e4bfe17UL); Fpsr 0x1UL ]
        [ Q(0, 0x594d83255f0f5dd3UL, 0x47602afa5f1f9c3cUL) ]
        [ Q(0, 0x807f000000000001UL, 0x8000007fc00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fb9000000000000UL) ] ]
    check "0e22c420" []
      [ [ Q(0, 0x70616f2f56feff0cUL, 0x0UL) ]
        [ Q(0, 0x594dac745f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x7f80000000000001UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4e62c420" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x40d6824e2ef3fc17UL) ]
        [ Q(0, 0x594dac74e9d05dd3UL, 0x47602afae0d99c3cUL) ]
        [ Q(0, 0x7f80000080000000UL, 0x7fa000007fc00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x7ff0000000000000UL) ] ]
    check "1ee26820" []
      [ [ Q(0, 0xe01cUL, 0x0UL) ]
        [ Q(0, 0x5dd3UL, 0x0UL) ]
        [ Q(0, 0x1UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e226820" []
      [ [ Q(0, 0x56feff0cUL, 0x0UL) ]
        [ Q(0, 0x5f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x1UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e626820" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x0UL) ]
        [ Q(0, 0x594dac74e9d05dd3UL, 0x0UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4e22c420" []
      [ [ Q(0, 0x70616f2f56feff0cUL, 0x40d6824e5e4be0f5UL) ]
        [ Q(0, 0x594dac745f0f9e24UL, 0x47602afa5f1fb0a9UL) ]
        [ Q(0, 0x7f80000000000001UL, 0x7fe000007f7fffffUL); Fpsr 0x1UL ]
        [ Q(0, 0x4008000000000000UL, 0x3fb9999900000000UL) ] ]

  /// C7.2.105 FMAXNMP (scalar)
  [<TestMethod>]
  member _.``C7.2.105 FMAXNMP``() =
    check "2e420420" []
      [ [ Q(0, 0x2e2256fe706148dcUL, 0x0UL) ]
        [ Q(0, 0x594d5dd357c85f0fUL, 0x0UL) ]
        [ Q(0, 0x807f000100000000UL, 0x0UL) ]
        [ Q(0, 0x40080000UL, 0x0UL) ] ]
    check "6e420420" []
      [ [ Q(0, 0x40d6fe17706148dcUL, 0x2445e4b2e2256feUL); Fpsr 0x1UL ]
        [ Q(0, 0x1b535f1f57c85f0fUL, 0x47609c3c594d5dd3UL) ]
        [ Q(0, 0x0UL, 0x80ffff807f0001UL) ]
        [ Q(0, 0x3fb9999940080000UL, 0x0UL) ] ]
    check "2e22c420" []
      [ [ Q(0, 0x56feff0c70616f2fUL, 0x0UL) ]
        [ Q(0, 0x594dac745f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x17f800000UL, 0x0UL) ]
        [ Q(0, 0x40080000UL, 0x0UL) ] ]
    check "6e62c420" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x879e2e2256feff0cUL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x594dac74e9d05dd3UL) ]
        [ Q(0, 0x7fa000007fc00000UL, 0x8000007f7fffffUL) ]
        [ Q(0, 0x4008000000000000UL, 0x7ff0000000000000UL) ] ]
    check "6e22c420" []
      [ [ Q(0, 0x40d6824e70616f2fUL, 0x5e4be0f556feff0cUL) ]
        [ Q(0, 0x5f1fb0a95f0f9e24UL, 0x47602afa594dac74UL) ]
        [ Q(0, 0x7fe000007f800000UL, 0x7f7fffff00000001UL); Fpsr 0x1UL ]
        [ Q(0, 0x3fb9999940080000UL, 0x0UL) ] ]

  /// C7.2.107 FMAXNMV
  [<TestMethod>]
  member _.``C7.2.107 FMAXNMV``() =
    check "6e30c820" []
      [ [ Q(0, 0x70616f2fUL, 0x0UL) ]
        [ Q(0, 0x5f1fb0a9UL, 0x0UL) ]
        [ Q(0, 0x7f800000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x40080000UL, 0x0UL) ] ]

  /// C7.2.108 FMAXP (scalar)
  [<TestMethod>]
  member _.``C7.2.108 FMAXP``() =
    check "2e423420" []
      [ [ Q(0, 0x2e22ff0c706148dcUL, 0x0UL) ]
        [ Q(0, 0x594d5dd357c85f0fUL, 0x0UL) ]
        [ Q(0, 0xffff00017f800000UL, 0x0UL) ]
        [ Q(0, 0x40080000UL, 0x0UL) ] ]
    check "6e423420" []
      [ [ Q(0, 0x40d6fe17706148dcUL, 0x2445e4b2e22ff0cUL); Fpsr 0x1UL ]
        [ Q(0, 0x1b535f1f57c85f0fUL, 0x47609c3c594d5dd3UL) ]
        [ Q(0, 0x7fa07fc07f800000UL, 0x80ffffffff0001UL) ]
        [ Q(0, 0x3fb9999940080000UL, 0x7e00000000000000UL) ] ]
    check "2e22f420" []
      [ [ Q(0, 0x56feff0c70616f2fUL, 0x0UL) ]
        [ Q(0, 0x594dac745f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x17f800000UL, 0x0UL) ]
        [ Q(0, 0x40080000UL, 0x0UL) ] ]
    check "6e62f420" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x879e2e2256feff0cUL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x594dac74e9d05dd3UL) ]
        [ Q(0, 0x7fa000007fc00000UL, 0x8000007f7fffffUL) ]
        [ Q(0, 0x4008000000000000UL, 0x7ff0000000000000UL) ] ]
    check "6e22f420" []
      [ [ Q(0, 0x40d6824e70616f2fUL, 0x5e4be0f556feff0cUL) ]
        [ Q(0, 0x5f1fb0a95f0f9e24UL, 0x47602afa594dac74UL) ]
        [ Q(0, 0x7fe000007f800000UL, 0x7f7fffff00000001UL); Fpsr 0x1UL ]
        [ Q(0, 0x3fb9999940080000UL, 0x7fc0000000000000UL) ] ]

  /// C7.2.110 FMAXV
  [<TestMethod>]
  member _.``C7.2.110 FMAXV``() =
    check "6e30f820" []
      [ [ Q(0, 0x70616f2fUL, 0x0UL) ]
        [ Q(0, 0x5f1fb0a9UL, 0x0UL) ]
        [ Q(0, 0x7fe00000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x40080000UL, 0x0UL) ] ]

  /// C7.2.111 FMIN (vector)
  [<TestMethod>]
  member _.``C7.2.111 FMIN``() =
    check "0ec23420" []
      [ [ Q(0, 0x879e2e2248dcff0cUL, 0x0UL) ]
        [ Q(0, 0x57c8ac74e9d09e24UL, 0x0UL) ]
        [ Q(0, 0x7f80ffff80000000UL, 0x0UL) ]
        [ Q(0, 0x8000000000000000UL, 0x0UL) ] ]
    check "4ec23420" []
      [ [ Q(0, 0x879e2e2248dcff0cUL, 0x8b2e824e2ef3fe17UL); Fpsr 0x1UL ]
        [ Q(0, 0x57c8ac74e9d09e24UL, 0xe2311b53e0d9b0a9UL) ]
        [ Q(0, 0x7f80ffff80000000UL, 0x7fa000007fc0ffffUL) ]
        [ Q(0, 0x8000000000000000UL, 0x7e0099999999999aUL) ] ]
    check "0ea2f420" []
      [ [ Q(0, 0x879e2e2248dce01cUL, 0x0UL) ]
        [ Q(0, 0x57c88325e9d05dd3UL, 0x0UL) ]
        [ Q(0, 0x807fffff80000000UL, 0x0UL) ]
        [ Q(0, 0x8000000000000000UL, 0x0UL) ] ]
    check "4ee2f420" []
      [ [ Q(0, 0x879e2e2256feff0cUL, 0x8b2e02445e4be0f5UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0xe2311b535f1fb0a9UL) ]
        [ Q(0, 0x807fffff00000001UL, 0x8000007f7fffffUL) ]
        [ Q(0, 0x8000000000000000UL, 0x3fb999999999999aUL) ] ]
    check "1ee25820" []
      [ [ Q(0, 0xff0cUL, 0x0UL) ]
        [ Q(0, 0x9e24UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e225820" []
      [ [ Q(0, 0x48dce01cUL, 0x0UL) ]
        [ Q(0, 0xe9d05dd3UL, 0x0UL) ]
        [ Q(0, 0x80000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e625820" []
      [ [ Q(0, 0x879e2e2256feff0cUL, 0x0UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x807fffff00000001UL, 0x0UL) ]
        [ Q(0, 0x8000000000000000UL, 0x0UL) ] ]
    check "4ea2f420" []
      [ [ Q(0, 0x879e2e2248dce01cUL, 0x8b2e02442ef3fc17UL) ]
        [ Q(0, 0x57c88325e9d05dd3UL, 0xe2311b53e0d99c3cUL) ]
        [ Q(0, 0x807fffff80000000UL, 0x7fe000007fc00000UL); Fpsr 0x1UL ]
        [ Q(0, 0x8000000000000000UL, 0x7fc000009999999aUL) ] ]

  /// C7.2.113 FMINNM (vector)
  [<TestMethod>]
  member _.``C7.2.113 FMINNM``() =
    check "0ec20420" []
      [ [ Q(0, 0x879e2e2248dce01cUL, 0x0UL) ]
        [ Q(0, 0x57c8ac74e9d09e24UL, 0x0UL) ]
        [ Q(0, 0x807f000080000000UL, 0x0UL) ]
        [ Q(0, 0x8000000000000000UL, 0x0UL) ] ]
    check "4ec20420" []
      [ [ Q(0, 0x879e2e2248dce01cUL, 0x8b2e824e2ef3fe17UL); Fpsr 0x1UL ]
        [ Q(0, 0x57c8ac74e9d09e24UL, 0xe2311b53e0d9b0a9UL) ]
        [ Q(0, 0x807f000080000000UL, 0x8000007fc00000UL) ]
        [ Q(0, 0x8000000000000000UL, 0x3fb999999999999aUL) ] ]
    check "0ea2c420" []
      [ [ Q(0, 0x879e2e2248dce01cUL, 0x0UL) ]
        [ Q(0, 0x57c88325e9d05dd3UL, 0x0UL) ]
        [ Q(0, 0x807fffff80000000UL, 0x0UL) ]
        [ Q(0, 0x8000000000000000UL, 0x0UL) ] ]
    check "4ee2c420" []
      [ [ Q(0, 0x879e2e2256feff0cUL, 0x8b2e02445e4be0f5UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0xe2311b535f1fb0a9UL) ]
        [ Q(0, 0x807fffff00000001UL, 0x8000007f7fffffUL) ]
        [ Q(0, 0x8000000000000000UL, 0x3fb999999999999aUL) ] ]
    check "1ee27820" []
      [ [ Q(0, 0xe01cUL, 0x0UL) ]
        [ Q(0, 0x9e24UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e227820" []
      [ [ Q(0, 0x48dce01cUL, 0x0UL) ]
        [ Q(0, 0xe9d05dd3UL, 0x0UL) ]
        [ Q(0, 0x80000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e627820" []
      [ [ Q(0, 0x879e2e2256feff0cUL, 0x0UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x807fffff00000001UL, 0x0UL) ]
        [ Q(0, 0x8000000000000000UL, 0x0UL) ] ]
    check "4ea2c420" []
      [ [ Q(0, 0x879e2e2248dce01cUL, 0x8b2e02442ef3fc17UL) ]
        [ Q(0, 0x57c88325e9d05dd3UL, 0xe2311b53e0d99c3cUL) ]
        [ Q(0, 0x807fffff80000000UL, 0x7fe000007f7fffffUL); Fpsr 0x1UL ]
        [ Q(0, 0x8000000000000000UL, 0x3fb999999999999aUL) ] ]

  /// C7.2.115 FMINNMP (scalar)
  [<TestMethod>]
  member _.``C7.2.115 FMINNMP``() =
    check "2ec20420" []
      [ [ Q(0, 0x879e56fe6f2fe01cUL, 0x0UL) ]
        [ Q(0, 0xac74e9d083259e24UL, 0x0UL) ]
        [ Q(0, 0x807f000000008000UL, 0x0UL) ]
        [ Q(0, 0x8000000000000000UL, 0x0UL) ] ]
    check "6ec20420" []
      [ [ Q(0, 0x824efe176f2fe01cUL, 0x8b2ee0f5879e56feUL); Fpsr 0x1UL ]
        [ Q(0, 0xe231b0a983259e24UL, 0x2afae0d9ac74e9d0UL) ]
        [ Q(0, 0x8000UL, 0xffff807f0000UL) ]
        [ Q(0, 0x9999999a00000000UL, 0x80000000UL) ] ]
    check "2ea2c420" []
      [ [ Q(0, 0x879e2e2248dce01cUL, 0x0UL) ]
        [ Q(0, 0xe9d05dd357c88325UL, 0x0UL) ]
        [ Q(0, 0x807fffff80000000UL, 0x0UL) ]
        [ Q(0, 0x8000000000000000UL, 0x0UL) ] ]
    check "6ee2c420" []
      [ [ Q(0, 0x40d6824e2ef3fc17UL, 0x8b2e02445e4be0f5UL) ]
        [ Q(0, 0xe2311b535f1fb0a9UL, 0x47602afae0d99c3cUL) ]
        [ Q(0, 0x7f80000080000000UL, 0x807fffff00000001UL) ]
        [ Q(0, 0x3fb999999999999aUL, 0x8000000000000000UL) ] ]
    check "6ea2c420" []
      [ [ Q(0, 0x2ef3fc1748dce01cUL, 0x8b2e0244879e2e22UL) ]
        [ Q(0, 0xe2311b5357c88325UL, 0xe0d99c3ce9d05dd3UL) ]
        [ Q(0, 0x7fe0000080000000UL, 0x800000807fffffUL); Fpsr 0x1UL ]
        [ Q(0, 0x9999999a00000000UL, 0x80000000UL) ] ]

  /// C7.2.117 FMINNMV
  [<TestMethod>]
  member _.``C7.2.117 FMINNMV``() =
    check "6eb0c820" []
      [ [ Q(0, 0x2ef3fc17UL, 0x0UL) ]
        [ Q(0, 0xe2311b53UL, 0x0UL) ]
        [ Q(0, 0x80000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x9999999aUL, 0x0UL) ] ]

  /// C7.2.118 FMINP (scalar)
  [<TestMethod>]
  member _.``C7.2.118 FMINP``() =
    check "2ec23420" []
      [ [ Q(0, 0x879eff0c6f2fe01cUL, 0x0UL) ]
        [ Q(0, 0xac74e9d083259e24UL, 0x0UL) ]
        [ Q(0, 0xffff00007f808000UL, 0x0UL) ]
        [ Q(0, 0x8000000000000000UL, 0x0UL) ] ]
    check "6ec23420" []
      [ [ Q(0, 0x824efe176f2fe01cUL, 0x8b2ee0f5879eff0cUL); Fpsr 0x1UL ]
        [ Q(0, 0xe231b0a983259e24UL, 0x2afae0d9ac74e9d0UL) ]
        [ Q(0, 0x7fa07fc07f808000UL, 0xffffffff0000UL) ]
        [ Q(0, 0x9999999a00000000UL, 0x7e00000080000000UL) ] ]
    check "2ea2f420" []
      [ [ Q(0, 0x879e2e2248dce01cUL, 0x0UL) ]
        [ Q(0, 0xe9d05dd357c88325UL, 0x0UL) ]
        [ Q(0, 0x807fffff80000000UL, 0x0UL) ]
        [ Q(0, 0x8000000000000000UL, 0x0UL) ] ]
    check "6ee2f420" []
      [ [ Q(0, 0x40d6824e2ef3fc17UL, 0x8b2e02445e4be0f5UL) ]
        [ Q(0, 0xe2311b535f1fb0a9UL, 0x47602afae0d99c3cUL) ]
        [ Q(0, 0x7f80000080000000UL, 0x807fffff00000001UL) ]
        [ Q(0, 0x3fb999999999999aUL, 0x8000000000000000UL) ] ]
    check "6ea2f420" []
      [ [ Q(0, 0x2ef3fc1748dce01cUL, 0x8b2e0244879e2e22UL) ]
        [ Q(0, 0xe2311b5357c88325UL, 0xe0d99c3ce9d05dd3UL) ]
        [ Q(0, 0x7fe0000080000000UL, 0x800000807fffffUL); Fpsr 0x1UL ]
        [ Q(0, 0x9999999a00000000UL, 0x7fc0000080000000UL) ] ]

  /// C7.2.120 FMINV
  [<TestMethod>]
  member _.``C7.2.120 FMINV``() =
    check "6eb0f820" []
      [ [ Q(0, 0x2ef3fc17UL, 0x0UL) ]
        [ Q(0, 0xe2311b53UL, 0x0UL) ]
        [ Q(0, 0x7fe00000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x9999999aUL, 0x0UL) ] ]

  /// C7.2.121 FMLA (by element)
  [<TestMethod>]
  member _.``C7.2.121 FMLA``() =
    check "5f121020" []
      [ [ Q(0, 0xfb2fUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x452fUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "0f121020" []
      [ [ Q(0, 0x7c007c006435fb2fUL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0xfc002f5bfc00452fUL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x7f8000003f800000UL, 0x0UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ] ]
    check "4f121020" []
      [ [ Q(0, 0x7c007c006435fb2fUL, 0x66bbe2685a68fe17UL); Fpsr 0x15UL ]
        [ Q(0, 0xfc002f5bfc00452fUL, 0x7c00ce06fc0069e8UL); Fpsr 0x14UL ]
        [ Q(0, 0x7f8000003f800000UL, 0x7fa0cccd7fc00000UL) ]
        [] ]
    check "0fa21020" []
      [ [ Q(0, 0xb88b4b3fc90789baUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x71a1181878e6c4c4UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xff8000003f800000UL, 0x0UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ] ]
    check "4fa21020" []
      [ [ Q(0, 0xb88b4b3fc90789baUL, 0x65ace2685a072c6dUL); Fpsr 0x10UL ]
        [ Q(0, 0x71a1181878e6c4c4UL, 0xfc0e4a3079004c0aUL); Fpsr 0x10UL ]
        [ Q(0, 0xff8000003f800000UL, 0x7fe000007fc00000UL); Fpsr 0x1UL ]
        [] ]
    check "4fc21820" []
      [ [ Q(0, 0xbba0597886e80ccaUL, 0x65ace2685a072c6dUL); Fpsr 0x10UL ]
        [ Q(0, 0x5f38c4fdfaca81afUL, 0xe9a1494755574b01UL); Fpsr 0x10UL ]
        [ Q(0, 0x400f0001fb0807f6UL, 0x40300000ff403d93UL); Fpsr 0x10UL ]
        [ Q(0, 0x7ff0000000000000UL, 0x7ff0000000000000UL) ] ]
    check "0e420c20" []
      [ [ Q(0, 0xbc2d61826435ff0cUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x7528a724fc00cb73UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x7f80ffff3f800000UL, 0x0UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ] ]
    check "4e420c20" []
      [ [ Q(0, 0xbc2d61826435ff0cUL, 0x65ace2685b65fe17UL); Fpsr 0x11UL ]
        [ Q(0, 0x7528a724fc00cb73UL, 0xedb4cabafc00690fUL); Fpsr 0x14UL ]
        [ Q(0, 0x7f80ffff3f800000UL, 0x7fa0cccd7fc0ffffUL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x7e00000000000000UL) ] ]
    check "0e22cc20" []
      [ [ Q(0, 0xb88b4b3f605c0269UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x71a11818ff800000UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0xff8000003f800000UL, 0x0UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ] ]
    check "4e62cc20" []
      [ [ Q(0, 0xb810715eddcfc997UL, 0x65ace2685a072c6dUL); Fpsr 0x10UL ]
        [ Q(0, 0x7126baf455871849UL, 0xe9a1494755574b01UL); Fpsr 0x10UL ]
        [ Q(0, 0xc010800001fbfc01UL, 0x40300000ff403d93UL); Fpsr 0x10UL ]
        [ Q(0, 0x3ff0000000000000UL, 0x7ff0000000000000UL) ] ]
    check "4e22cc20" []
      [ [ Q(0, 0xb88b4b3f605c0269UL, 0x65ace2685a072c6dUL); Fpsr 0x10UL ]
        [ Q(0, 0x71a11818ff800000UL, 0xea1b15a4ff800000UL); Fpsr 0x14UL ]
        [ Q(0, 0xff8000003f800000UL, 0x7fe000007fc00000UL); Fpsr 0x1UL ]
        [ Q(0, 0x3ff0000000000000UL, 0x7fc0000000000000UL) ] ]

  /// C7.2.123 FMLAL, FMLAL2 (by element)
  [<TestMethod>]
  member _.``C7.2.123 FMLAL``() =
    check "0e22ec20" []
      [ [ Q(0, 0x4487e920ffe18000UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xc9a41cc0c00f0eb0UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xbfc000003f800000UL, 0x0UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ] ]
    check "4f920020" []
      [ [ Q(0, 0x4487e920c915e79eUL, 0x65ace2685a072c6dUL); Fpsr 0x10UL ]
        [ Q(0, 0xc9a41cc0418ec500UL, 0xc8b4841b3e123880UL); Fpsr 0x10UL ]
        [ Q(0, 0xbfc000003f800000UL, 0x7ff0000040400000UL) ]
        [] ]
    check "4e22ec20" []
      [ [ Q(0, 0x4487e920ffe18000UL, 0x65ace2685a072c6dUL); Fpsr 0x10UL ]
        [ Q(0, 0xc9a41cc0c00f0eb0UL, 0x46ab5af636600c40UL); Fpsr 0x10UL ]
        [ Q(0, 0xbfc000003f800000UL, 0x7ff00000ffffe000UL) ]
        [] ]

  /// C7.2.123 FMLAL, FMLAL2 (by element)
  [<TestMethod>]
  member _.``C7.2.123 FMLAL2``() =
    check "6e22cc20" []
      [ [ Q(0, 0x422eecc4ffc2e000UL, 0x65ace2685a072c6dUL); Fpsr 0x11UL ]
        [ Q(0, 0xc88a151c3a1ddcffUL, 0xc59d2c29394c6438UL); Fpsr 0x10UL ]
        [ Q(0, 0x7ff80000ffffe000UL, 0x7ff4000040400000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x7fc0000000000000UL) ] ]

  /// C7.2.125 FMLS (by element)
  [<TestMethod>]
  member _.``C7.2.125 FMLS``() =
    check "5f125020" []
      [ [ Q(0, 0x7b2fUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xcfa1UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "0f125020" []
      [ [ Q(0, 0xfc00fc00e4497b2fUL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x7c00b1767c00cfa1UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0xff8000003f800000UL, 0x0UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ] ]
    check "4f125020" []
      [ [ Q(0, 0xfc00fc00e4497b2fUL, 0x649de26859a67e17UL); Fpsr 0x15UL ]
        [ Q(0, 0x7c00b1767c00cfa1UL, 0xfc00c19f7c006836UL); Fpsr 0x14UL ]
        [ Q(0, 0xff8000003f800000UL, 0xffa0cccdffc00000UL) ]
        [] ]
    check "0fa25020" []
      [ [ Q(0, 0x388b4b3fc90789baUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xf1a11818f8e6c4c4UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x7f8000003f800000UL, 0x0UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ] ]
    check "4fa25020" []
      [ [ Q(0, 0x388b4b3fc90789baUL, 0x65ace2685a072c6dUL); Fpsr 0x10UL ]
        [ Q(0, 0xf1a11818f8e6c4c4UL, 0x7c0e4a30f9004c0aUL); Fpsr 0x10UL ]
        [ Q(0, 0x7f8000003f800000UL, 0xffe00000ffc00000UL); Fpsr 0x1UL ]
        [] ]
    check "4fc25820" []
      [ [ Q(0, 0x3ba0597886e80ccaUL, 0x65ace2685a072c6dUL); Fpsr 0x10UL ]
        [ Q(0, 0xdf38c4fdfaca81afUL, 0x69a1494755574b01UL); Fpsr 0x10UL ]
        [ Q(0, 0xc0108001017c03fbUL, 0xc0300000ff3fca5fUL); Fpsr 0x10UL ]
        [ Q(0, 0xfff0000000000000UL, 0xfff0000000000000UL) ] ]
    check "0ec20c20" []
      [ [ Q(0, 0x3c2ae182e449ff0cUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xf528a7247c00c937UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0xff80ffff3f800000UL, 0x0UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ] ]
    check "4ec20c20" []
      [ [ Q(0, 0x3c2ae182e449ff0cUL, 0x65ace26858a97e17UL); Fpsr 0x11UL ]
        [ Q(0, 0xf528a7247c00c937UL, 0x6db6caba7c00690fUL); Fpsr 0x14UL ]
        [ Q(0, 0xff80ffff3f800000UL, 0xffa0cccdffc0ffffUL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x7e00000000000000UL) ] ]
    check "0ea2cc20" []
      [ [ Q(0, 0x388b4b3fe05c0269UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xf1a118187f800000UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x7f8000003f800000UL, 0x0UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ] ]
    check "4ee2cc20" []
      [ [ Q(0, 0x3810715eddcfc997UL, 0x65ace2685a072c6dUL); Fpsr 0x10UL ]
        [ Q(0, 0xf126baf455871849UL, 0x69a1494755574b01UL); Fpsr 0x10UL ]
        [ Q(0, 0x400efffffc07f801UL, 0xc0300000ff3fca5fUL); Fpsr 0x10UL ]
        [ Q(0, 0x3ff0000000000000UL, 0xfff0000000000000UL) ] ]
    check "4ea2cc20" []
      [ [ Q(0, 0x388b4b3fe05c0269UL, 0x65ace2685a072c6dUL); Fpsr 0x10UL ]
        [ Q(0, 0xf1a118187f800000UL, 0x6a1b15a47f800000UL); Fpsr 0x14UL ]
        [ Q(0, 0x7f8000003f800000UL, 0xffe00000ffc00000UL); Fpsr 0x1UL ]
        [ Q(0, 0x3ff0000000000000UL, 0x7fc0000000000000UL) ] ]

  /// C7.2.127 FMLSL, FMLSL2 (by element)
  [<TestMethod>]
  member _.``C7.2.127 FMLSL``() =
    check "0ea2ec20" []
      [ [ Q(0, 0xc487e920ffe18000UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x49a41cc0400f0eb0UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xbfc000003f800000UL, 0x0UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ] ]
    check "4f924020" []
      [ [ Q(0, 0xc487e920c8f257acUL, 0x65ace2685a072c6dUL); Fpsr 0x10UL ]
        [ Q(0, 0x49a41cc0c18ec500UL, 0x48b54fe5be123880UL); Fpsr 0x10UL ]
        [ Q(0, 0xbfc000003f800000UL, 0xfff0000040400000UL) ]
        [] ]
    check "4ea2ec20" []
      [ [ Q(0, 0xc487e920ffe18000UL, 0x65ace2685a072c6dUL); Fpsr 0x10UL ]
        [ Q(0, 0x49a41cc0400f0eb0UL, 0xc69e9e4ab6600c40UL); Fpsr 0x10UL ]
        [ Q(0, 0xbfc000003f800000UL, 0xfff00000ffffe000UL) ]
        [] ]

  /// C7.2.127 FMLSL, FMLSL2 (by element)
  [<TestMethod>]
  member _.``C7.2.127 FMLSL2``() =
    check "6ea2cc20" []
      [ [ Q(0, 0xc22eecc47fc2e000UL, 0x65ace2685a072c6dUL); Fpsr 0x11UL ]
        [ Q(0, 0x488a151cba1ddcc1UL, 0x45d01ed7b94c6438UL); Fpsr 0x10UL ]
        [ Q(0, 0xfff80000ffffe000UL, 0xfff4000040400000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x7fc0000000000000UL) ] ]

  /// C7.2.129 FMOV (vector, immediate)
  [<TestMethod>]
  member _.``C7.2.129 FMOV``() =
    check "9e670020" []
      [ [ Q(0, 0xbeeb8da1658eec67UL, 0x0UL) ]
        [ Q(0, 0xbfc846100bfc1e42UL, 0x0UL) ]
        [ Q(0, 0x1UL, 0x0UL) ]
        [ Q(0, 0x100000000UL, 0x0UL) ] ]
    check "0f01fe00" []
      [ [ Q(0, 0x4c004c004c004c00UL, 0x0UL) ]
        [ Q(0, 0x4c004c004c004c00UL, 0x0UL) ]
        [ Q(0, 0x4c004c004c004c00UL, 0x0UL) ]
        [ Q(0, 0x4c004c004c004c00UL, 0x0UL) ] ]
    check "4f01fe00" []
      [ [ Q(0, 0x4c004c004c004c00UL, 0x4c004c004c004c00UL) ]
        [ Q(0, 0x4c004c004c004c00UL, 0x4c004c004c004c00UL) ]
        [ Q(0, 0x4c004c004c004c00UL, 0x4c004c004c004c00UL) ]
        [ Q(0, 0x4c004c004c004c00UL, 0x4c004c004c004c00UL) ] ]
    check "0f01f600" []
      [ [ Q(0, 0x4180000041800000UL, 0x0UL) ]
        [ Q(0, 0x4180000041800000UL, 0x0UL) ]
        [ Q(0, 0x4180000041800000UL, 0x0UL) ]
        [ Q(0, 0x4180000041800000UL, 0x0UL) ] ]
    check "4f01f600" []
      [ [ Q(0, 0x4180000041800000UL, 0x4180000041800000UL) ]
        [ Q(0, 0x4180000041800000UL, 0x4180000041800000UL) ]
        [ Q(0, 0x4180000041800000UL, 0x4180000041800000UL) ]
        [ Q(0, 0x4180000041800000UL, 0x4180000041800000UL) ] ]
    check "6f01f600" []
      [ [ Q(0, 0x4030000000000000UL, 0x4030000000000000UL) ]
        [ Q(0, 0x4030000000000000UL, 0x4030000000000000UL) ]
        [ Q(0, 0x4030000000000000UL, 0x4030000000000000UL) ]
        [ Q(0, 0x4030000000000000UL, 0x4030000000000000UL) ] ]
    check "1ee04020" []
      [ [ Q(0, 0xe01cUL, 0x0UL) ]
        [ Q(0, 0x9e24UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e204020" []
      [ [ Q(0, 0x48dce01cUL, 0x0UL) ]
        [ Q(0, 0x5f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x80000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e604020" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x0UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "1ee60020" []
      [ [ X(0, 0xe01cUL) ]
        [ X(0, 0x9e24UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "9ee60020" []
      [ [ X(0, 0xe01cUL) ]
        [ X(0, 0x9e24UL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "1ee70020" []
      [ [ Q(0, 0xec67UL, 0x0UL) ]
        [ Q(0, 0x1e42UL, 0x0UL) ]
        [ Q(0, 0x1UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e270020" []
      [ [ Q(0, 0x658eec67UL, 0x0UL) ]
        [ Q(0, 0xbfc1e42UL, 0x0UL) ]
        [ Q(0, 0x1UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e260020" []
      [ [ X(0, 0x48dce01cUL) ]
        [ X(0, 0x5f0f9e24UL) ]
        [ X(0, 0x80000000UL) ]
        [ X(0, 0x0UL) ] ]
    check "9ee70020" []
      [ [ Q(0, 0xec67UL, 0x0UL) ]
        [ Q(0, 0x1e42UL, 0x0UL) ]
        [ Q(0, 0x1UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "9eaf0020" []
      [ [ Q(0, 0x962b1967c90789baUL, 0xbeeb8da1658eec67UL) ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0xbfc846100bfc1e42UL) ]
        [ Q(0, 0xbfc000003f800000UL, 0x1UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x100000000UL) ] ]
    check "9e660020" []
      [ [ X(0, 0x70616f2f48dce01cUL) ]
        [ X(0, 0x57c883255f0f9e24UL) ]
        [ X(0, 0x7f80000080000000UL) ]
        [ X(0, 0x4008000000000000UL) ] ]
    check "9eae0020" []
      [ [ X(0, 0x40d6824e2ef3fc17UL) ]
        [ X(0, 0xe2311b535f1fb0a9UL) ]
        [ X(0, 0x7fa000007fc00000UL) ]
        [ X(0, 0x3fb999999999999aUL) ] ]
    check "1ee61000" []
      [ [ Q(0, 0x4c00UL, 0x0UL) ]
        [ Q(0, 0x4c00UL, 0x0UL) ]
        [ Q(0, 0x4c00UL, 0x0UL) ]
        [ Q(0, 0x4c00UL, 0x0UL) ] ]
    check "1e261000" []
      [ [ Q(0, 0x41800000UL, 0x0UL) ]
        [ Q(0, 0x41800000UL, 0x0UL) ]
        [ Q(0, 0x41800000UL, 0x0UL) ]
        [ Q(0, 0x41800000UL, 0x0UL) ] ]
    check "1e661000" []
      [ [ Q(0, 0x4030000000000000UL, 0x0UL) ]
        [ Q(0, 0x4030000000000000UL, 0x0UL) ]
        [ Q(0, 0x4030000000000000UL, 0x0UL) ]
        [ Q(0, 0x4030000000000000UL, 0x0UL) ] ]

  /// C7.2.133 FMSUB
  [<TestMethod>]
  member _.``C7.2.133 FMSUB``() =
    check "1fc28c20" []
      [ [ Q(0, 0xff0cUL, 0x0UL) ]
        [ Q(0, 0xf7d1UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x2f9UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1f028c20" []
      [ [ Q(0, 0xe05c0269UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x7f800000UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x501502f9UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1f428c20" []
      [ [ Q(0, 0xbf8c59bb003553c1UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xf126baf455871849UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xc0e7ff80501502f9UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x7ff8000000000000UL, 0x0UL) ] ]

  /// C7.2.134 FMUL (by element)
  [<TestMethod>]
  member _.``C7.2.134 FMUL``() =
    check "5f129020" []
      [ [ Q(0, 0xfb2fUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x4c76UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "0f129020" []
      [ [ Q(0, 0x7c007c00643ffb2fUL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0xfc003092fc004c76UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "4f129020" []
      [ [ Q(0, 0x7c007c00643ffb2fUL, 0x5c3a9c074a13fe17UL); Fpsr 0x15UL ]
        [ Q(0, 0xfc003092fc004c76UL, 0x7c00c952fc005ec6UL); Fpsr 0x14UL ]
        [ Q(0, 0x7f80000080000000UL, 0x7fa000007fc00000UL) ]
        [ Q(0, 0x0UL, 0x800080008000UL) ] ]
    check "0fa29020" []
      [ [ Q(0, 0xb88b4b3f91087a1fUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x71a1181878e6c4c4UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xff80000000000000UL, 0x0UL) ]
        [ Q(0, 0x8000000080000000UL, 0x0UL) ] ]
    check "4fa29020" []
      [ [ Q(0, 0xb88b4b3f91087a1fUL, 0x89048b1480000013UL); Fpsr 0x18UL ]
        [ Q(0, 0x71a1181878e6c4c4UL, 0xfc0e4a3079004c0aUL); Fpsr 0x10UL ]
        [ Q(0, 0xff80000000000000UL, 0x7fe000007fc00000UL); Fpsr 0x1UL ]
        [ Q(0, 0x8000000080000000UL, 0x8000000000000000UL) ] ]
    check "4fc29820" []
      [ [ Q(0, 0xbba0597886e80ccaUL, 0x8c151bc18821f4a9UL); Fpsr 0x10UL ]
        [ Q(0, 0x5f38c4fdfaca81afUL, 0xe9a1494755574b01UL); Fpsr 0x10UL ]
        [ Q(0, 0x40100000ff8003fbUL, 0x40300000ff4003f9UL); Fpsr 0x10UL ]
        [ Q(0, 0x7ff0000000000000UL, 0x7ff0000000000000UL) ] ]
    check "2e421c20" []
      [ [ Q(0, 0xbc2b6182643fff0cUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x75280038fc00c078UL, 0x0UL); Fpsr 0x1cUL ]
        [ Q(0, 0x7f80ffff80000000UL, 0x0UL) ]
        [ Q(0, 0x8000000000000000UL, 0x0UL) ] ]
    check "6e421c20" []
      [ [ Q(0, 0xbc2b6182643fff0cUL, 0x905780005177fe17UL); Fpsr 0x19UL ]
        [ Q(0, 0x75280038fc00c078UL, 0xedb50a63fc0010efUL); Fpsr 0x1cUL ]
        [ Q(0, 0x7f80ffff80000000UL, 0x7fa000007fc0ffffUL) ]
        [ Q(0, 0x8000000000000000UL, 0x7e00800080008000UL) ] ]
    check "2e22dc20" []
      [ [ Q(0, 0xb88b4b3f605c0269UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x71a11818ff800000UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0xff80000080000000UL, 0x0UL) ]
        [ Q(0, 0x8000000000000000UL, 0x0UL) ] ]
    check "6e62dc20" []
      [ [ Q(0, 0xb810715eddcfc997UL, 0x8c151bc18821f4a9UL); Fpsr 0x10UL ]
        [ Q(0, 0x7126baf455871849UL, 0xe9a1494755574b01UL); Fpsr 0x10UL ]
        [ Q(0, 0xc00ffffffffff801UL, 0x40300000ff4003f9UL); Fpsr 0x10UL ]
        [ Q(0, 0x8000000000000000UL, 0x7ff0000000000000UL) ] ]
    check "1ee20820" []
      [ [ Q(0, 0xff0cUL, 0x0UL) ]
        [ Q(0, 0xc078UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e220820" []
      [ [ Q(0, 0x605c0269UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xff800000UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x80000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e620820" []
      [ [ Q(0, 0xb810715eddcfc997UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x7126baf455871849UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xc00ffffffffff801UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x8000000000000000UL, 0x0UL) ] ]
    check "6e22dc20" []
      [ [ Q(0, 0xb88b4b3f605c0269UL, 0x8c91ce774dc24f4cUL); Fpsr 0x10UL ]
        [ Q(0, 0x71a11818ff800000UL, 0xea1b15a4ff800000UL); Fpsr 0x14UL ]
        [ Q(0, 0xff80000080000000UL, 0x7fe000007fc00000UL); Fpsr 0x1UL ]
        [ Q(0, 0x8000000000000000UL, 0x7fc0000080000000UL) ] ]

  /// C7.2.137 FMULX (by element)
  [<TestMethod>]
  member _.``C7.2.137 FMULX``() =
    check "7f129020" []
      [ [ Q(0, 0xfb2fUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x4c76UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "2f129020" []
      [ [ Q(0, 0x7c007c00643ffb2fUL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0xfc003092fc004c76UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "6f129020" []
      [ [ Q(0, 0x7c007c00643ffb2fUL, 0x5c3a9c074a13fe17UL); Fpsr 0x15UL ]
        [ Q(0, 0xfc003092fc004c76UL, 0x7c00c952fc005ec6UL); Fpsr 0x14UL ]
        [ Q(0, 0x7f80000080000000UL, 0x7fa000007fc00000UL) ]
        [ Q(0, 0x0UL, 0x800080008000UL) ] ]
    check "2fa29020" []
      [ [ Q(0, 0xb88b4b3f91087a1fUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x71a1181878e6c4c4UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xff80000000000000UL, 0x0UL) ]
        [ Q(0, 0x8000000080000000UL, 0x0UL) ] ]
    check "6fa29020" []
      [ [ Q(0, 0xb88b4b3f91087a1fUL, 0x89048b1480000013UL); Fpsr 0x18UL ]
        [ Q(0, 0x71a1181878e6c4c4UL, 0xfc0e4a3079004c0aUL); Fpsr 0x10UL ]
        [ Q(0, 0xff80000000000000UL, 0x7fe000007fc00000UL); Fpsr 0x1UL ]
        [ Q(0, 0x8000000080000000UL, 0x8000000000000000UL) ] ]
    check "6fc29820" []
      [ [ Q(0, 0xbba0597886e80ccaUL, 0x8c151bc18821f4a9UL); Fpsr 0x10UL ]
        [ Q(0, 0x5f38c4fdfaca81afUL, 0xe9a1494755574b01UL); Fpsr 0x10UL ]
        [ Q(0, 0x40100000ff8003fbUL, 0x40300000ff4003f9UL); Fpsr 0x10UL ]
        [ Q(0, 0x7ff0000000000000UL, 0x7ff0000000000000UL) ] ]
    check "5e421c20" []
      [ [ Q(0, 0xff0cUL, 0x0UL) ]
        [ Q(0, 0xc078UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "0e421c20" []
      [ [ Q(0, 0xbc2b6182643fff0cUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x75280038fc00c078UL, 0x0UL); Fpsr 0x1cUL ]
        [ Q(0, 0x7f80ffff80000000UL, 0x0UL) ]
        [ Q(0, 0x8000000000000000UL, 0x0UL) ] ]
    check "4e421c20" []
      [ [ Q(0, 0xbc2b6182643fff0cUL, 0x905780005177fe17UL); Fpsr 0x19UL ]
        [ Q(0, 0x75280038fc00c078UL, 0xedb50a63fc0010efUL); Fpsr 0x1cUL ]
        [ Q(0, 0x7f80ffff80000000UL, 0x7fa000007fc0ffffUL) ]
        [ Q(0, 0x8000000000000000UL, 0x7e00800080008000UL) ] ]
    check "0e22dc20" []
      [ [ Q(0, 0xb88b4b3f605c0269UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x71a11818ff800000UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0xff80000080000000UL, 0x0UL) ]
        [ Q(0, 0x8000000000000000UL, 0x0UL) ] ]
    check "4e62dc20" []
      [ [ Q(0, 0xb810715eddcfc997UL, 0x8c151bc18821f4a9UL); Fpsr 0x10UL ]
        [ Q(0, 0x7126baf455871849UL, 0xe9a1494755574b01UL); Fpsr 0x10UL ]
        [ Q(0, 0xc00ffffffffff801UL, 0x40300000ff4003f9UL); Fpsr 0x10UL ]
        [ Q(0, 0x8000000000000000UL, 0x7ff0000000000000UL) ] ]
    check "4e22dc20" []
      [ [ Q(0, 0xb88b4b3f605c0269UL, 0x8c91ce774dc24f4cUL); Fpsr 0x10UL ]
        [ Q(0, 0x71a11818ff800000UL, 0xea1b15a4ff800000UL); Fpsr 0x14UL ]
        [ Q(0, 0xff80000080000000UL, 0x7fe000007fc00000UL); Fpsr 0x1UL ]
        [ Q(0, 0x8000000000000000UL, 0x7fc0000080000000UL) ] ]

  /// C7.2.139 FNEG (vector)
  [<TestMethod>]
  member _.``C7.2.139 FNEG``() =
    check "2ef8f820" []
      [ [ Q(0, 0xf061ef2fc8dc601cUL, 0x0UL) ]
        [ Q(0, 0xd7c80325df0f1e24UL, 0x0UL) ]
        [ Q(0, 0xff80800000008000UL, 0x0UL) ]
        [ Q(0, 0xc008800080008000UL, 0x0UL) ] ]
    check "6ef8f820" []
      [ [ Q(0, 0xf061ef2fc8dc601cUL, 0xc0d6024eaef37c17UL) ]
        [ Q(0, 0xd7c80325df0f1e24UL, 0x62319b53df1f30a9UL) ]
        [ Q(0, 0xff80800000008000UL, 0xffa08000ffc08000UL) ]
        [ Q(0, 0xc008800080008000UL, 0xbfb919991999199aUL) ] ]
    check "2ea0f820" []
      [ [ Q(0, 0xf0616f2fc8dce01cUL, 0x0UL) ]
        [ Q(0, 0xd7c88325df0f9e24UL, 0x0UL) ]
        [ Q(0, 0xff80000000000000UL, 0x0UL) ]
        [ Q(0, 0xc008000080000000UL, 0x0UL) ] ]
    check "6ee0f820" []
      [ [ Q(0, 0xf0616f2f48dce01cUL, 0xc0d6824e2ef3fc17UL) ]
        [ Q(0, 0xd7c883255f0f9e24UL, 0x62311b535f1fb0a9UL) ]
        [ Q(0, 0xff80000080000000UL, 0xffa000007fc00000UL) ]
        [ Q(0, 0xc008000000000000UL, 0xbfb999999999999aUL) ] ]
    check "1ee14020" []
      [ [ Q(0, 0x601cUL, 0x0UL) ]
        [ Q(0, 0x1e24UL, 0x0UL) ]
        [ Q(0, 0x8000UL, 0x0UL) ]
        [ Q(0, 0x8000UL, 0x0UL) ] ]
    check "1e214020" []
      [ [ Q(0, 0xc8dce01cUL, 0x0UL) ]
        [ Q(0, 0xdf0f9e24UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x80000000UL, 0x0UL) ] ]
    check "1e614020" []
      [ [ Q(0, 0xf0616f2f48dce01cUL, 0x0UL) ]
        [ Q(0, 0xd7c883255f0f9e24UL, 0x0UL) ]
        [ Q(0, 0xff80000080000000UL, 0x0UL) ]
        [ Q(0, 0xc008000000000000UL, 0x0UL) ] ]
    check "6ea0f820" []
      [ [ Q(0, 0xf0616f2fc8dce01cUL, 0xc0d6824eaef3fc17UL) ]
        [ Q(0, 0xd7c88325df0f9e24UL, 0x62311b53df1fb0a9UL) ]
        [ Q(0, 0xff80000000000000UL, 0xffa00000ffc00000UL) ]
        [ Q(0, 0xc008000080000000UL, 0xbfb999991999999aUL) ] ]

  /// C7.2.141 FNMADD
  [<TestMethod>]
  member _.``C7.2.141 FNMADD``() =
    check "1fe20c20" []
      [ [ Q(0, 0xff0cUL, 0x0UL) ]
        [ Q(0, 0x77d1UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x82f9UL, 0x0UL) ]
        [ Q(0, 0x8000UL, 0x0UL) ] ]
    check "1f620c20" []
      [ [ Q(0, 0x3f8c59bb003553c1UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xf126baf455871849UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x40e80080501502f9UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x7ff8000000000000UL, 0x0UL) ] ]
    check "1f220c20" []
      [ [ Q(0, 0xe05c0269UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x7f800000UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0xd01502f9UL, 0x0UL) ]
        [ Q(0, 0x80000000UL, 0x0UL) ] ]

  /// C7.2.142 FNMSUB
  [<TestMethod>]
  member _.``C7.2.142 FNMSUB``() =
    check "1fe28c20" []
      [ [ Q(0, 0xff0cUL, 0x0UL) ]
        [ Q(0, 0x77d1UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x82f9UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1f228c20" []
      [ [ Q(0, 0x605c0269UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xff800000UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0xd01502f9UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1f628c20" []
      [ [ Q(0, 0x3f8c59bb003553c1UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x7126baf455871849UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x40e7ff80501502f9UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x7ff8000000000000UL, 0x0UL) ] ]

  /// C7.2.143 FNMUL (scalar)
  [<TestMethod>]
  member _.``C7.2.143 FNMUL``() =
    check "1ee28820" []
      [ [ Q(0, 0x7f0cUL, 0x0UL) ]
        [ Q(0, 0x4078UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x8000UL, 0x0UL) ]
        [ Q(0, 0x8000UL, 0x0UL) ] ]
    check "1e228820" []
      [ [ Q(0, 0xe05c0269UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x7f800000UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x80000000UL, 0x0UL) ] ]
    check "1e628820" []
      [ [ Q(0, 0x3810715eddcfc997UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xf126baf455871849UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x400ffffffffff801UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL) ] ]

  /// C7.2.144 FRECPE
  [<TestMethod>]
  member _.``C7.2.144 FRECPE``() =
    check "5ef9d820" []
      [ [ Q(0, 0x97c4UL, 0x0UL) ]
        [ Q(0, 0xd934UL, 0x0UL) ]
        [ Q(0, 0x7c00UL, 0x0UL); Fpsr 0x2UL ]
        [ Q(0, 0x7c00UL, 0x0UL); Fpsr 0x2UL ] ]
    check "0ef9d820" []
      [ [ Q(0, 0x74c08742e9497c4UL, 0x0UL) ]
        [ Q(0, 0x201cf5181888d934UL, 0x0UL) ]
        [ Q(0, 0x7f807c00fc007c00UL, 0x0UL); Fpsr 0x2UL ]
        [ Q(0, 0x37ec7c007c007c00UL, 0x0UL); Fpsr 0x2UL ] ]
    check "4ef9d820" []
      [ [ Q(0, 0x74c08742e9497c4UL, 0x369cf6f0489cfe17UL); Fpsr 0x1UL ]
        [ Q(0, 0x201cf5181888d934UL, 0x952c5c601880c6dcUL) ]
        [ Q(0, 0x7f807c00fc007c00UL, 0x7fa07c007fc07c00UL); Fpsr 0x2UL ]
        [ Q(0, 0x37ec7c007c007c00UL, 0x3824ddb8ddb8ddb8UL); Fpsr 0x2UL ] ]
    check "0ea1d820" []
      [ [ Q(0, 0xe91800036148000UL, 0x0UL) ]
        [ Q(0, 0x272300001fe40000UL, 0x0UL) ]
        [ Q(0, 0xff800000UL, 0x0UL); Fpsr 0x2UL ]
        [ Q(0, 0x3ef080007f800000UL, 0x0UL); Fpsr 0x2UL ] ]
    check "4ee1d820" []
      [ [ Q(0, 0xf7d700000000000UL, 0x3f06c00000000000UL) ]
        [ Q(0, 0x2814e00000000000UL, 0x9dadf00000000000UL) ]
        [ Q(0, 0x5ff00000000000UL, 0x3ff00000000000UL) ]
        [ Q(0, 0x3fd5500000000000UL, 0x4024000000000000UL) ] ]
    check "4ea1d820" []
      [ [ Q(0, 0xe91800036148000UL, 0x3e18800050068000UL) ]
        [ Q(0, 0x272300001fe40000UL, 0x9cb900001fcd0000UL) ]
        [ Q(0, 0xff800000UL, 0x7fe000007fc00000UL); Fpsr 0x3UL ]
        [ Q(0, 0x3ef080007f800000UL, 0x3f308000e5550000UL); Fpsr 0x2UL ] ]

  /// C7.2.145 FRECPS
  [<TestMethod>]
  member _.``C7.2.145 FRECPS``() =
    check "5e423c20" []
      [ [ Q(0, 0xff0cUL, 0x0UL) ]
        [ Q(0, 0x443cUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x4000UL, 0x0UL) ]
        [ Q(0, 0x4000UL, 0x0UL) ] ]
    check "0e423c20" []
      [ [ Q(0, 0x4216e17ee43dff0cUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xf52840007c00443cUL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0xff80ffff40004000UL, 0x0UL) ]
        [ Q(0, 0x4000400040004000UL, 0x0UL) ] ]
    check "0e22fc20" []
      [ [ Q(0, 0x40000117e05c0269UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xf1a118187f800000UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x7f80000040000000UL, 0x0UL) ]
        [ Q(0, 0x4000000040000000UL, 0x0UL) ] ]
    check "4e22fc20" []
      [ [ Q(0, 0x40000117e05c0269UL, 0x40000000cdc24f4cUL); Fpsr 0x10UL ]
        [ Q(0, 0xf1a118187f800000UL, 0x6a1b15a47f800000UL); Fpsr 0x14UL ]
        [ Q(0, 0x7f80000040000000UL, 0xffe00000ffc00000UL); Fpsr 0x1UL ]
        [ Q(0, 0x4000000040000000UL, 0x7fc0000040000000UL) ] ]
    check "4e62fc20" []
      [ [ Q(0, 0x4000000000000000UL, 0x4000000000000000UL); Fpsr 0x10UL ]
        [ Q(0, 0xf126baf455871849UL, 0x69a1494755574b01UL); Fpsr 0x10UL ]
        [ Q(0, 0x4017fffffffffc01UL, 0xc02c0001fe8007f2UL); Fpsr 0x10UL ]
        [ Q(0, 0x4000000000000000UL, 0xfff0000000000000UL) ] ]
    check "4e423c20" []
      [ [ Q(0, 0x4216e17ee43dff0cUL, 0x40004000d1377e17UL); Fpsr 0x11UL ]
        [ Q(0, 0xf52840007c00443cUL, 0x6db640007c003fffUL); Fpsr 0x14UL ]
        [ Q(0, 0xff80ffff40004000UL, 0xffa04000ffc0ffffUL) ]
        [ Q(0, 0x4000400040004000UL, 0x7e00400040004000UL) ] ]

  /// C7.2.146 FRECPX
  [<TestMethod>]
  member _.``C7.2.146 FRECPX``() =
    check "5ef9f820" []
      [ [ Q(0, 0x9c00UL, 0x0UL) ]
        [ Q(0, 0xe000UL, 0x0UL) ]
        [ Q(0, 0x7800UL, 0x0UL) ]
        [ Q(0, 0x7800UL, 0x0UL) ] ]
    check "5ee1f820" []
      [ [ Q(0, 0xf90000000000000UL, 0x0UL) ]
        [ Q(0, 0x2830000000000000UL, 0x0UL) ]
        [ Q(0, 0x70000000000000UL, 0x0UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ] ]

  /// C7.2.147 FRINT32X (vector)
  [<TestMethod>]
  member _.``C7.2.147 FRINT32X``() =
    check "1e68c020" []
      [ [ Q(0, 0xc1e0000000000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xc1e0000000000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xc1e0000000000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "2e21e820" []
      [ [ Q(0, 0xcf00000048dce020UL, 0x0UL); Fpsr 0x11UL ]
        [ Q(0, 0xcf000000cf000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xcf00000080000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x4000000000000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "6e61e820" []
      [ [ Q(0, 0xc1e0000000000000UL, 0x40d6824000000000UL); Fpsr 0x11UL ]
        [ Q(0, 0xc1e0000000000000UL, 0xc1e0000000000000UL); Fpsr 0x1UL ]
        [ Q(0, 0xc1e0000000000000UL, 0xc1e0000000000000UL); Fpsr 0x1UL ]
        [ Q(0, 0x4008000000000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "1e28c020" []
      [ [ Q(0, 0x48dce020UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xcf000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x80000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "6e21e820" []
      [ [ Q(0, 0xcf00000048dce020UL, 0x40e0000000000000UL); Fpsr 0x11UL ]
        [ Q(0, 0xcf000000cf000000UL, 0xcf000000cf000000UL); Fpsr 0x1UL ]
        [ Q(0, 0xcf00000080000000UL, 0xcf000000cf000000UL); Fpsr 0x1UL ]
        [ Q(0, 0x4000000000000000UL, 0x3f80000080000000UL); Fpsr 0x10UL ] ]

  /// C7.2.149 FRINT32Z (vector)
  [<TestMethod>]
  member _.``C7.2.149 FRINT32Z``() =
    check "1e684020" []
      [ [ Q(0, 0xc1e0000000000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xc1e0000000000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xc1e0000000000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "0e21e820" []
      [ [ Q(0, 0xcf00000048dce000UL, 0x0UL); Fpsr 0x11UL ]
        [ Q(0, 0xcf000000cf000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xcf00000080000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x4000000000000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "4e61e820" []
      [ [ Q(0, 0xc1e0000000000000UL, 0x40d6824000000000UL); Fpsr 0x11UL ]
        [ Q(0, 0xc1e0000000000000UL, 0xc1e0000000000000UL); Fpsr 0x1UL ]
        [ Q(0, 0xc1e0000000000000UL, 0xc1e0000000000000UL); Fpsr 0x1UL ]
        [ Q(0, 0x4008000000000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "1e284020" []
      [ [ Q(0, 0x48dce000UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xcf000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x80000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "4e21e820" []
      [ [ Q(0, 0xcf00000048dce000UL, 0x40c0000000000000UL); Fpsr 0x11UL ]
        [ Q(0, 0xcf000000cf000000UL, 0xcf000000cf000000UL); Fpsr 0x1UL ]
        [ Q(0, 0xcf00000080000000UL, 0xcf000000cf000000UL); Fpsr 0x1UL ]
        [ Q(0, 0x4000000000000000UL, 0x3f80000080000000UL); Fpsr 0x10UL ] ]

  /// C7.2.151 FRINT64X (vector)
  [<TestMethod>]
  member _.``C7.2.151 FRINT64X``() =
    check "1e69c020" []
      [ [ Q(0, 0xc3e0000000000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xc3e0000000000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xc3e0000000000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "2e21f820" []
      [ [ Q(0, 0xdf00000048dce020UL, 0x0UL); Fpsr 0x11UL ]
        [ Q(0, 0x57c88325df000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xdf00000080000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x4000000000000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "6e61f820" []
      [ [ Q(0, 0xc3e0000000000000UL, 0x40d6824000000000UL); Fpsr 0x11UL ]
        [ Q(0, 0xc3e0000000000000UL, 0xc3e0000000000000UL); Fpsr 0x1UL ]
        [ Q(0, 0xc3e0000000000000UL, 0xc3e0000000000000UL); Fpsr 0x1UL ]
        [ Q(0, 0x4008000000000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "1e29c020" []
      [ [ Q(0, 0x48dce020UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xdf000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x80000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "6e21f820" []
      [ [ Q(0, 0xdf00000048dce020UL, 0x40e0000000000000UL); Fpsr 0x11UL ]
        [ Q(0, 0x57c88325df000000UL, 0xdf000000df000000UL); Fpsr 0x1UL ]
        [ Q(0, 0xdf00000080000000UL, 0xdf000000df000000UL); Fpsr 0x1UL ]
        [ Q(0, 0x4000000000000000UL, 0x3f80000080000000UL); Fpsr 0x10UL ] ]

  /// C7.2.153 FRINT64Z (vector)
  [<TestMethod>]
  member _.``C7.2.153 FRINT64Z``() =
    check "1e694020" []
      [ [ Q(0, 0xc3e0000000000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xc3e0000000000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xc3e0000000000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "0e21f820" []
      [ [ Q(0, 0xdf00000048dce000UL, 0x0UL); Fpsr 0x11UL ]
        [ Q(0, 0x57c88325df000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0xdf00000080000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x4000000000000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "4e61f820" []
      [ [ Q(0, 0xc3e0000000000000UL, 0x40d6824000000000UL); Fpsr 0x11UL ]
        [ Q(0, 0xc3e0000000000000UL, 0xc3e0000000000000UL); Fpsr 0x1UL ]
        [ Q(0, 0xc3e0000000000000UL, 0xc3e0000000000000UL); Fpsr 0x1UL ]
        [ Q(0, 0x4008000000000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "1e294020" []
      [ [ Q(0, 0x48dce000UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xdf000000UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x80000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "4e21f820" []
      [ [ Q(0, 0xdf00000048dce000UL, 0x40c0000000000000UL); Fpsr 0x11UL ]
        [ Q(0, 0x57c88325df000000UL, 0xdf000000df000000UL); Fpsr 0x1UL ]
        [ Q(0, 0xdf00000080000000UL, 0xdf000000df000000UL); Fpsr 0x1UL ]
        [ Q(0, 0x4000000000000000UL, 0x3f80000080000000UL); Fpsr 0x10UL ] ]

  /// C7.2.155 FRINTA (vector)
  [<TestMethod>]
  member _.``C7.2.155 FRINTA``() =
    check "2e798820" []
      [ [ Q(0, 0x70616f2f4900e01cUL, 0x0UL) ]
        [ Q(0, 0x57d080005f108000UL, 0x0UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x4000000000000000UL, 0x0UL) ] ]
    check "6e798820" []
      [ [ Q(0, 0x70616f2f4900e01cUL, 0x400080000000fe17UL); Fpsr 0x1UL ]
        [ Q(0, 0x57d080005f108000UL, 0xe23200005f208000UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x7fa000007fc00000UL) ]
        [ Q(0, 0x4000000000000000UL, 0x4000800080008000UL) ] ]
    check "2e218820" []
      [ [ Q(0, 0x70616f2f48dce020UL, 0x0UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x4000000000000000UL, 0x0UL) ] ]
    check "6e618820" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x40d6824000000000UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0xe2311b535f1fb0a9UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x7fa000007fc00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "1ee64020" []
      [ [ Q(0, 0xe01cUL, 0x0UL) ]
        [ Q(0, 0x8000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e264020" []
      [ [ Q(0, 0x48dce020UL, 0x0UL) ]
        [ Q(0, 0x5f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x80000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e664020" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x0UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "6e218820" []
      [ [ Q(0, 0x70616f2f48dce020UL, 0x40e0000000000000UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0xe2311b535f1fb0a9UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x7fe000007fc00000UL); Fpsr 0x1UL ]
        [ Q(0, 0x4000000000000000UL, 0x3f80000080000000UL) ] ]

  /// C7.2.157 FRINTI (vector)
  [<TestMethod>]
  member _.``C7.2.157 FRINTI``() =
    check "2ef99820" []
      [ [ Q(0, 0x70616f2f4900e01cUL, 0x0UL) ]
        [ Q(0, 0x57c080005f108000UL, 0x0UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x4000000000000000UL, 0x0UL) ] ]
    check "6ef99820" []
      [ [ Q(0, 0x70616f2f4900e01cUL, 0x400080000000fe17UL); Fpsr 0x1UL ]
        [ Q(0, 0x57c080005f108000UL, 0xe23000005f208000UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x7fa000007fc00000UL) ]
        [ Q(0, 0x4000000000000000UL, 0x4000800080008000UL) ] ]
    check "2ea19820" []
      [ [ Q(0, 0x70616f2f48dce020UL, 0x0UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x4000000000000000UL, 0x0UL) ] ]
    check "6ee19820" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x40d6824000000000UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0xe2311b535f1fb0a9UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x7fa000007fc00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "1ee7c020" []
      [ [ Q(0, 0xe01cUL, 0x0UL) ]
        [ Q(0, 0x8000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e27c020" []
      [ [ Q(0, 0x48dce020UL, 0x0UL) ]
        [ Q(0, 0x5f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x80000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e67c020" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x0UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "6ea19820" []
      [ [ Q(0, 0x70616f2f48dce020UL, 0x40e0000000000000UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0xe2311b535f1fb0a9UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x7fe000007fc00000UL); Fpsr 0x1UL ]
        [ Q(0, 0x4000000000000000UL, 0x3f80000080000000UL) ] ]

  /// C7.2.159 FRINTM (vector)
  [<TestMethod>]
  member _.``C7.2.159 FRINTM``() =
    check "0e799820" []
      [ [ Q(0, 0x70616f2f4880e01cUL, 0x0UL) ]
        [ Q(0, 0x57c0bc005f0cbc00UL, 0x0UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x4000000000000000UL, 0x0UL) ] ]
    check "4e799820" []
      [ [ Q(0, 0x70616f2f4880e01cUL, 0x4000bc000000fe17UL); Fpsr 0x1UL ]
        [ Q(0, 0x57c0bc005f0cbc00UL, 0xe23200005f1cbc00UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x7fa000007fc00000UL) ]
        [ Q(0, 0x4000000000000000UL, 0x3c00bc00bc00bc00UL) ] ]
    check "0e219820" []
      [ [ Q(0, 0x70616f2f48dce000UL, 0x0UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x4000000000000000UL, 0x0UL) ] ]
    check "4e619820" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x40d6824000000000UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0xe2311b535f1fb0a9UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x7fa000007fc00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "1ee54020" []
      [ [ Q(0, 0xe01cUL, 0x0UL) ]
        [ Q(0, 0xbc00UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e254020" []
      [ [ Q(0, 0x48dce000UL, 0x0UL) ]
        [ Q(0, 0x5f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x80000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e654020" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x0UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4e219820" []
      [ [ Q(0, 0x70616f2f48dce000UL, 0x40c0000000000000UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0xe2311b535f1fb0a9UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x7fe000007fc00000UL); Fpsr 0x1UL ]
        [ Q(0, 0x4000000000000000UL, 0x3f800000bf800000UL) ] ]

  /// C7.2.161 FRINTN (vector)
  [<TestMethod>]
  member _.``C7.2.161 FRINTN``() =
    check "0e798820" []
      [ [ Q(0, 0x70616f2f4900e01cUL, 0x0UL) ]
        [ Q(0, 0x57c080005f108000UL, 0x0UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x4000000000000000UL, 0x0UL) ] ]
    check "4e798820" []
      [ [ Q(0, 0x70616f2f4900e01cUL, 0x400080000000fe17UL); Fpsr 0x1UL ]
        [ Q(0, 0x57c080005f108000UL, 0xe23000005f208000UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x7fa000007fc00000UL) ]
        [ Q(0, 0x4000000000000000UL, 0x4000800080008000UL) ] ]
    check "0e218820" []
      [ [ Q(0, 0x70616f2f48dce020UL, 0x0UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x4000000000000000UL, 0x0UL) ] ]
    check "4e618820" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x40d6824000000000UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0xe2311b535f1fb0a9UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x7fa000007fc00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "1ee44020" []
      [ [ Q(0, 0xe01cUL, 0x0UL) ]
        [ Q(0, 0x8000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e244020" []
      [ [ Q(0, 0x48dce020UL, 0x0UL) ]
        [ Q(0, 0x5f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x80000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e644020" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x0UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4e218820" []
      [ [ Q(0, 0x70616f2f48dce020UL, 0x40e0000000000000UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0xe2311b535f1fb0a9UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x7fe000007fc00000UL); Fpsr 0x1UL ]
        [ Q(0, 0x4000000000000000UL, 0x3f80000080000000UL) ] ]

  /// C7.2.163 FRINTP (vector)
  [<TestMethod>]
  member _.``C7.2.163 FRINTP``() =
    check "0ef98820" []
      [ [ Q(0, 0x70616f2f4900e01cUL, 0x0UL) ]
        [ Q(0, 0x57d080005f108000UL, 0x0UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x4200000000000000UL, 0x0UL) ] ]
    check "4ef98820" []
      [ [ Q(0, 0x70616f2f4900e01cUL, 0x420080003c00fe17UL); Fpsr 0x1UL ]
        [ Q(0, 0x57d080005f108000UL, 0xe2303c005f208000UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x7fa000007fc00000UL) ]
        [ Q(0, 0x4200000000000000UL, 0x4000800080008000UL) ] ]
    check "0ea18820" []
      [ [ Q(0, 0x70616f2f48dce020UL, 0x0UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x4040000000000000UL, 0x0UL) ] ]
    check "4ee18820" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x40d6828000000000UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0xe2311b535f1fb0a9UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x7fa000007fc00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3ff0000000000000UL) ] ]
    check "1ee4c020" []
      [ [ Q(0, 0xe01cUL, 0x0UL) ]
        [ Q(0, 0x8000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e24c020" []
      [ [ Q(0, 0x48dce020UL, 0x0UL) ]
        [ Q(0, 0x5f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x80000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e64c020" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x0UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4ea18820" []
      [ [ Q(0, 0x70616f2f48dce020UL, 0x40e000003f800000UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0xe2311b535f1fb0a9UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x7fe000007fc00000UL); Fpsr 0x1UL ]
        [ Q(0, 0x4040000000000000UL, 0x4000000080000000UL) ] ]

  /// C7.2.165 FRINTX (vector)
  [<TestMethod>]
  member _.``C7.2.165 FRINTX``() =
    check "2e799820" []
      [ [ Q(0, 0x70616f2f4900e01cUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x57c080005f108000UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x4000000000000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "6e799820" []
      [ [ Q(0, 0x70616f2f4900e01cUL, 0x400080000000fe17UL); Fpsr 0x11UL ]
        [ Q(0, 0x57c080005f108000UL, 0xe23000005f208000UL); Fpsr 0x10UL ]
        [ Q(0, 0x7f80000080000000UL, 0x7fa000007fc00000UL) ]
        [ Q(0, 0x4000000000000000UL, 0x4000800080008000UL); Fpsr 0x10UL ] ]
    check "2e219820" []
      [ [ Q(0, 0x70616f2f48dce020UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x4000000000000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "6e619820" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x40d6824000000000UL); Fpsr 0x10UL ]
        [ Q(0, 0x57c883255f0f9e24UL, 0xe2311b535f1fb0a9UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x7fa000007fc00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "1ee74020" []
      [ [ Q(0, 0xe01cUL, 0x0UL) ]
        [ Q(0, 0x8000UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e274020" []
      [ [ Q(0, 0x48dce020UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x5f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x80000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e674020" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x0UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "6e219820" []
      [ [ Q(0, 0x70616f2f48dce020UL, 0x40e0000000000000UL); Fpsr 0x10UL ]
        [ Q(0, 0x57c883255f0f9e24UL, 0xe2311b535f1fb0a9UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x7fe000007fc00000UL); Fpsr 0x1UL ]
        [ Q(0, 0x4000000000000000UL, 0x3f80000080000000UL); Fpsr 0x10UL ] ]

  /// C7.2.167 FRINTZ (vector)
  [<TestMethod>]
  member _.``C7.2.167 FRINTZ``() =
    check "0ef99820" []
      [ [ Q(0, 0x70616f2f4880e01cUL, 0x0UL) ]
        [ Q(0, 0x57c080005f0c8000UL, 0x0UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x4000000000000000UL, 0x0UL) ] ]
    check "4ef99820" []
      [ [ Q(0, 0x70616f2f4880e01cUL, 0x400080000000fe17UL); Fpsr 0x1UL ]
        [ Q(0, 0x57c080005f0c8000UL, 0xe23000005f1c8000UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x7fa000007fc00000UL) ]
        [ Q(0, 0x4000000000000000UL, 0x3c00800080008000UL) ] ]
    check "0ea19820" []
      [ [ Q(0, 0x70616f2f48dce000UL, 0x0UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x4000000000000000UL, 0x0UL) ] ]
    check "4ee19820" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x40d6824000000000UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0xe2311b535f1fb0a9UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x7fa000007fc00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "1ee5c020" []
      [ [ Q(0, 0xe01cUL, 0x0UL) ]
        [ Q(0, 0x8000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e25c020" []
      [ [ Q(0, 0x48dce000UL, 0x0UL) ]
        [ Q(0, 0x5f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x80000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e65c020" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x0UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4ea19820" []
      [ [ Q(0, 0x70616f2f48dce000UL, 0x40c0000000000000UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0xe2311b535f1fb0a9UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x7fe000007fc00000UL); Fpsr 0x1UL ]
        [ Q(0, 0x4000000000000000UL, 0x3f80000080000000UL) ] ]

  /// C7.2.169 FRSQRTE
  [<TestMethod>]
  member _.``C7.2.169 FRSQRTE``() =
    check "7ef9d820" []
      [ [ Q(0, 0x7e00UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x7e00UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x7c00UL, 0x0UL); Fpsr 0x2UL ]
        [ Q(0, 0x7c00UL, 0x0UL); Fpsr 0x2UL ] ]
    check "2ef9d820" []
      [ [ Q(0, 0x216821f835207e00UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x2dbc7e002a087e00UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x7f807c00fc007c00UL, 0x0UL); Fpsr 0x2UL ]
        [ Q(0, 0x39a07c007c007c00UL, 0x0UL); Fpsr 0x2UL ] ]
    check "6ef9d820" []
      [ [ Q(0, 0x216821f835207e00UL, 0x39287e004210fe17UL); Fpsr 0x1UL ]
        [ Q(0, 0x2dbc7e002a087e00UL, 0x7e004c2c2a007e00UL); Fpsr 0x1UL ]
        [ Q(0, 0x7f807c00fc007c00UL, 0x7fa07c007fc07c00UL); Fpsr 0x2UL ]
        [ Q(0, 0x39a07c007c007c00UL, 0x39c07e007e007e00UL); Fpsr 0x3UL ] ]
    check "2ea1d820" []
      [ [ Q(0, 0x270880003ac30000UL, 0x0UL) ]
        [ Q(0, 0x334c80002fab0000UL, 0x0UL) ]
        [ Q(0, 0xff800000UL, 0x0UL); Fpsr 0x2UL ]
        [ Q(0, 0x3f2f80007f800000UL, 0x0UL); Fpsr 0x2UL ] ]
    check "6ee1d820" []
      [ [ Q(0, 0x27b5b00000000000UL, 0x3f7af00000000000UL) ]
        [ Q(0, 0x3402400000000000UL, 0x7ff8000000000000UL); Fpsr 0x1UL ]
        [ Q(0, 0x2026900000000000UL, 0x2016900000000000UL) ]
        [ Q(0, 0x3fe2700000000000UL, 0x4009500000000000UL) ] ]
    check "6ea1d820" []
      [ [ Q(0, 0x270880003ac30000UL, 0x3ec6000047b98000UL) ]
        [ Q(0, 0x334c80002fab0000UL, 0x7fc000002fa20000UL); Fpsr 0x1UL ]
        [ Q(0, 0xff800000UL, 0x7fe000007fc00000UL); Fpsr 0x3UL ]
        [ Q(0, 0x3f2f80007f800000UL, 0x3f5480007fc00000UL); Fpsr 0x3UL ] ]

  /// C7.2.170 FRSQRTS
  [<TestMethod>]
  member _.``C7.2.170 FRSQRTS``() =
    check "5ec23c20" []
      [ [ Q(0, 0xff0cUL, 0x0UL) ]
        [ Q(0, 0x413cUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x3e00UL, 0x0UL) ]
        [ Q(0, 0x3e00UL, 0x0UL) ] ]
    check "0ec23c20" []
      [ [ Q(0, 0x400bdd7ce03cff0cUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xf1283e007c00413cUL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0xff80ffff3e003e00UL, 0x0UL) ]
        [ Q(0, 0x3e003e003e003e00UL, 0x0UL) ] ]
    check "0ea2fc20" []
      [ [ Q(0, 0x3fc00117dfdc0269UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xf12118187f800000UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x7f8000003fc00000UL, 0x0UL) ]
        [ Q(0, 0x3fc000003fc00000UL, 0x0UL) ] ]
    check "4ea2fc20" []
      [ [ Q(0, 0x3fc00117dfdc0269UL, 0x3fc00000cd424f4cUL); Fpsr 0x10UL ]
        [ Q(0, 0xf12118187f800000UL, 0x699b15a47f800000UL); Fpsr 0x14UL ]
        [ Q(0, 0x7f8000003fc00000UL, 0xffe00000ffc00000UL); Fpsr 0x1UL ]
        [ Q(0, 0x3fc000003fc00000UL, 0x7fc000003fc00000UL) ] ]
    check "4ee2fc20" []
      [ [ Q(0, 0x3ff8000000000000UL, 0x3ff8000000000000UL); Fpsr 0x10UL ]
        [ Q(0, 0xf116baf455871849UL, 0x6991494755574b01UL); Fpsr 0x10UL ]
        [ Q(0, 0x400bfffffffffc01UL, 0xc01a0001fe8007f2UL); Fpsr 0x10UL ]
        [ Q(0, 0x3ff8000000000000UL, 0xfff0000000000000UL) ] ]
    check "4ec23c20" []
      [ [ Q(0, 0x400bdd7ce03cff0cUL, 0x3e003e00cd177e17UL); Fpsr 0x11UL ]
        [ Q(0, 0xf1283e007c00413cUL, 0x69b63e007c003e00UL); Fpsr 0x14UL ]
        [ Q(0, 0xff80ffff3e003e00UL, 0xffa03e00ffc0ffffUL) ]
        [ Q(0, 0x3e003e003e003e00UL, 0x7e003e003e003e00UL) ] ]

  /// C7.2.171 FSQRT (vector)
  [<TestMethod>]
  member _.``C7.2.171 FSQRT``() =
    check "2ef9f820" []
      [ [ Q(0, 0x55eb555c423c7e00UL, 0x0UL); Fpsr 0x11UL ]
        [ Q(0, 0x49947e004d507e00UL, 0x0UL); Fpsr 0x11UL ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x3dae000000000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "6ef9f820" []
      [ [ Q(0, 0x55eb555c423c7e00UL, 0x3e387e003546fe17UL); Fpsr 0x11UL ]
        [ Q(0, 0x49947e004d507e00UL, 0x7e002ba84d567e00UL); Fpsr 0x11UL ]
        [ Q(0, 0x7f80000080000000UL, 0x7fa000007fc00000UL) ]
        [ Q(0, 0x3dae000000000000UL, 0x3d8f7e007e007e00UL); Fpsr 0x11UL ] ]
    check "2ea1f820" []
      [ [ Q(0, 0x57f03b4544282499UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x4ba0346d4f3fbeb8UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL) ]
        [ Q(0, 0x3fba972800000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "6ee1f820" []
      [ [ Q(0, 0x58279eaf9048f17cUL, 0x4062fa3afd9e9ce3UL); Fpsr 0x10UL ]
        [ Q(0, 0x4bdc01cc278cf511UL, 0x7ff8000000000000UL); Fpsr 0x11UL ]
        [ Q(0, 0x5fb6a09ec101b4b2UL, 0x5fc6a09ec0d47375UL); Fpsr 0x10UL ]
        [ Q(0, 0x3ffbb67ae8584caaUL, 0x3fd43d136248490fUL); Fpsr 0x10UL ] ]
    check "1ee1c020" []
      [ [ Q(0, 0x7e00UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x7e00UL, 0x0UL); Fpsr 0x1UL ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e21c020" []
      [ [ Q(0, 0x44282499UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x4f3fbeb8UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x80000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e61c020" []
      [ [ Q(0, 0x58279eaf9048f17cUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x4bdc01cc278cf511UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x5fb6a09ec101b4b2UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x3ffbb67ae8584caaUL, 0x0UL); Fpsr 0x10UL ] ]
    check "6ea1f820" []
      [ [ Q(0, 0x57f03b4544282499UL, 0x4025b3b63730b862UL); Fpsr 0x10UL ]
        [ Q(0, 0x4ba0346d4f3fbeb8UL, 0x7fc000004f4a308eUL); Fpsr 0x11UL ]
        [ Q(0, 0x7f80000080000000UL, 0x7fe000007fc00000UL); Fpsr 0x1UL ]
        [ Q(0, 0x3fba972800000000UL, 0x3f9a21e57fc00000UL); Fpsr 0x11UL ] ]

  /// C7.2.173 FSUB (vector)
  [<TestMethod>]
  member _.``C7.2.173 FSUB``() =
    check "0ec21420" []
      [ [ Q(0, 0x70616f2fd662ff0cUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xd1a42c736ab2ddd3UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x7f80ffff80008001UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4ec21420" []
      [ [ Q(0, 0x70616f2fd662ff0cUL, 0x40d68492de4bfe17UL); Fpsr 0x11UL ]
        [ Q(0, 0xd1a42c736ab2ddd3UL, 0xe240aa856434b087UL); Fpsr 0x10UL ]
        [ Q(0, 0x7f80ffff80008001UL, 0x7fa000007fc0ffffUL) ]
        [ Q(0, 0x4008000000000000UL, 0x7e0099999999999aUL) ] ]
    check "0ea2d420" []
      [ [ Q(0, 0x70616f2fd6feff0cUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xd9349c0f69d05dd7UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x7f80000080000001UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4ee2d420" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x40d6824e2ef3fc17UL); Fpsr 0x10UL ]
        [ Q(0, 0xd94dac74d14d3874UL, 0xe2311b535f1fb0a9UL); Fpsr 0x10UL ]
        [ Q(0, 0x7f80000080000000UL, 0x7fa000007fc00000UL); Fpsr 0x10UL ]
        [ Q(0, 0x4008000000000000UL, 0xfff0000000000000UL) ] ]
    check "1ee23820" []
      [ [ Q(0, 0xff0cUL, 0x0UL) ]
        [ Q(0, 0xddd3UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x8001UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e223820" []
      [ [ Q(0, 0xd6feff0cUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x69d05dd7UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x80000001UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e623820" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xd94dac74d14d3874UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4ea2d420" []
      [ [ Q(0, 0x70616f2fd6feff0cUL, 0x40d6824ede4be0f5UL); Fpsr 0x10UL ]
        [ Q(0, 0xd9349c0f69d05dd7UL, 0xe2311b5360ed9251UL); Fpsr 0x10UL ]
        [ Q(0, 0x7f80000080000001UL, 0x7fe000007fc00000UL); Fpsr 0x1UL ]
        [ Q(0, 0x4008000000000000UL, 0x7fc000009999999aUL) ] ]

  /// C7.2.175 INS (element)
  [<TestMethod>]
  member _.``C7.2.175 INS``() =
    check "4e081c20" []
      [ [ Q(0, 0xbeeb8da1658eec67UL, 0x65ace2685a072c6dUL) ]
        [ Q(0, 0xbfc846100bfc1e42UL, 0x444bcaba22bb690fUL) ]
        [ Q(0, 0x1UL, 0x3dcccccd40400000UL) ]
        [ Q(0, 0x100000000UL, 0xbff8000000000000UL) ] ]

  /// C7.2.177 LD1 (multiple structures)
  [<TestMethod>]
  member _.``C7.2.177 LD1``() =
    check "4c407020" [ X(1, 0x2008000UL) ]
      [ [ Q(0, 0xdb20290ac13e4a81UL, 0xd80391ffb30d1390UL) ]
        [ Q(0, 0x912f822b1e8fe1e4UL, 0xf8606cc314fb6b96UL) ]
        [ Q(0, 0x0UL, 0x1UL) ]
        [ Q(0, 0x5555555555555555UL, 0xaaaaaaaaaaaaaaaaUL) ] ]

  /// C7.2.179 LD1R
  [<TestMethod>]
  member _.``C7.2.179 LD1R``() =
    check "4d40c020" [ X(1, 0x2008000UL) ]
      [ [ Q(0, 0x8181818181818181UL, 0x8181818181818181UL) ]
        [ Q(0, 0xe4e4e4e4e4e4e4e4UL, 0xe4e4e4e4e4e4e4e4UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x5555555555555555UL, 0x5555555555555555UL) ] ]

  /// C7.2.180 LD2 (multiple structures)
  [<TestMethod>]
  member _.``C7.2.180 LD2``() =
    check "4c408020" [ X(1, 0x2008000UL) ]
      [ [ Q(0, 0x3ff0d90200a3e81UL, 0x537c35107a9a5f2UL)
          Q(1, 0xd891b313db29c14aUL, 0x4ff035b9007b9e24UL) ]
        [ Q(0, 0x60c3fb962f2b8fe4UL, 0xc5e56aab6722324fUL)
          Q(1, 0xf86c146b91821ee1UL, 0x8b13901820fecf2eUL) ]
        [ Q(0, 0x100000000UL, 0xffffffffUL); Q(1, 0x0UL, 0x80000000ffffffffUL) ]
        [ Q(0, 0xaaaaaaaa55555555UL, 0x100000000ffffUL)
          Q(1, 0xaaaaaaaa55555555UL, 0xffffUL) ] ]

  /// C7.2.182 LD2R
  [<TestMethod>]
  member _.``C7.2.182 LD2R``() =
    check "4d60c020" [ X(1, 0x2008000UL) ]
      [ [ Q(0, 0x8181818181818181UL, 0x8181818181818181UL)
          Q(1, 0x4a4a4a4a4a4a4a4aUL, 0x4a4a4a4a4a4a4a4aUL) ]
        [ Q(0, 0xe4e4e4e4e4e4e4e4UL, 0xe4e4e4e4e4e4e4e4UL)
          Q(1, 0xe1e1e1e1e1e1e1e1UL, 0xe1e1e1e1e1e1e1e1UL) ]
        [ Q(0, 0x0UL, 0x0UL); Q(1, 0x0UL, 0x0UL) ]
        [ Q(0, 0x5555555555555555UL, 0x5555555555555555UL)
          Q(1, 0x5555555555555555UL, 0x5555555555555555UL) ] ]

  /// C7.2.183 LD3 (multiple structures)
  [<TestMethod>]
  member _.``C7.2.183 LD3``() =
    check "4c404020" [ X(1, 0x2008000UL) ]
      [ [ Q(0, 0x7ba5d8ff1320c181UL, 0x5d51bc401d053551UL)
          Q(1, 0x79ef2910ddb0a4aUL, 0xbf515301144f37b9UL)
          Q(2, 0xa92403b390293eUL, 0x9640ec735001f0c3UL) ]
        [ Q(0, 0xfe32f8c36b2f1ee4UL, 0x760b1886bc590abUL)
          Q(1, 0x67cf4f6cfb912be1UL, 0xf15d9802fb8be518UL)
          Q(2, 0x20222e601496828fUL, 0xed2ddbea863c136aUL) ]
        [ Q(0, 0xffff000000000000UL, 0x7fffff000000UL)
          Q(1, 0xffffff0000000000UL, 0x8000ffff800000UL)
          Q(2, 0xffffff0000010000UL, 0xffffff0000UL) ]
        [ Q(0, 0xffaaaaaa555555UL, 0xff00000000UL)
          Q(1, 0xffffaaaa555555UL, 0xff000100UL)
          Q(2, 0xffaaaaaa5555UL, 0x80ff00ff0000UL) ] ]

  /// C7.2.185 LD3R
  [<TestMethod>]
  member _.``C7.2.185 LD3R``() =
    check "4d40e020" [ X(1, 0x2008000UL) ]
      [ [ Q(0, 0x8181818181818181UL, 0x8181818181818181UL)
          Q(1, 0x4a4a4a4a4a4a4a4aUL, 0x4a4a4a4a4a4a4a4aUL)
          Q(2, 0x3e3e3e3e3e3e3e3eUL, 0x3e3e3e3e3e3e3e3eUL) ]
        [ Q(0, 0xe4e4e4e4e4e4e4e4UL, 0xe4e4e4e4e4e4e4e4UL)
          Q(1, 0xe1e1e1e1e1e1e1e1UL, 0xe1e1e1e1e1e1e1e1UL)
          Q(2, 0x8f8f8f8f8f8f8f8fUL, 0x8f8f8f8f8f8f8f8fUL) ]
        [ Q(0, 0x0UL, 0x0UL); Q(1, 0x0UL, 0x0UL); Q(2, 0x0UL, 0x0UL) ]
        [ Q(0, 0x5555555555555555UL, 0x5555555555555555UL)
          Q(1, 0x5555555555555555UL, 0x5555555555555555UL)
          Q(2, 0x5555555555555555UL, 0x5555555555555555UL) ] ]

  /// C7.2.186 LD4 (multiple structures)
  [<TestMethod>]
  member _.``C7.2.186 LD4``() =
    check "4c400020" [ X(1, 0x2008000UL) ]
      [ [ Q(0, 0x3751a9f2ff900a81UL, 0x82923f5b40534001UL)
          Q(1, 0xf0b97b249113294aUL, 0x2ecbe5ae5dec011dUL)
          Q(2, 0x5c307a5030d203eUL, 0xc42a3de4bf517314UL)
          Q(3, 0x4f35009ed8b3dbc1UL, 0x7b78aabd9651bc50UL) ]
        [ Q(0, 0xe5ab224fc3962be4UL, 0xb44396412d98883cUL)
          Q(1, 0x1318fe2e6c6b82e1UL, 0x63a73e1a07db026bUL)
          Q(2, 0xc56a673260fb2f8fUL, 0x2f06ae29f160eafbUL)
          Q(3, 0x8b9020cff814911eUL, 0xd8815d24ed5db186UL) ]
        [ Q(0, 0xffff00010000UL, 0xff00ff0000ffffUL)
          Q(1, 0xffff00000000UL, 0xff00ff0000ffffUL)
          Q(2, 0xffff00000000UL, 0xff00ff0000ffffUL)
          Q(3, 0x8000ffff00000000UL, 0xff007f00807fffUL) ]
        [ Q(0, 0x10000ffaaaa5555UL, 0xff00ff0000ffffUL)
          Q(1, 0xffaaaa5555UL, 0xff007f00800000UL)
          Q(2, 0xffaaaa5555UL, 0xffffUL)
          Q(3, 0xffaaaa5555UL, 0x0UL) ] ]

  /// C7.2.188 LD4R
  [<TestMethod>]
  member _.``C7.2.188 LD4R``() =
    check "4d60e020" [ X(1, 0x2008000UL) ]
      [ [ Q(0, 0x8181818181818181UL, 0x8181818181818181UL)
          Q(1, 0x4a4a4a4a4a4a4a4aUL, 0x4a4a4a4a4a4a4a4aUL)
          Q(2, 0x3e3e3e3e3e3e3e3eUL, 0x3e3e3e3e3e3e3e3eUL)
          Q(3, 0xc1c1c1c1c1c1c1c1UL, 0xc1c1c1c1c1c1c1c1UL) ]
        [ Q(0, 0xe4e4e4e4e4e4e4e4UL, 0xe4e4e4e4e4e4e4e4UL)
          Q(1, 0xe1e1e1e1e1e1e1e1UL, 0xe1e1e1e1e1e1e1e1UL)
          Q(2, 0x8f8f8f8f8f8f8f8fUL, 0x8f8f8f8f8f8f8f8fUL)
          Q(3, 0x1e1e1e1e1e1e1e1eUL, 0x1e1e1e1e1e1e1e1eUL) ]
        [ Q(0, 0x0UL, 0x0UL)
          Q(1, 0x0UL, 0x0UL)
          Q(2, 0x0UL, 0x0UL)
          Q(3, 0x0UL, 0x0UL) ]
        [ Q(0, 0x5555555555555555UL, 0x5555555555555555UL)
          Q(1, 0x5555555555555555UL, 0x5555555555555555UL)
          Q(2, 0x5555555555555555UL, 0x5555555555555555UL)
          Q(3, 0x5555555555555555UL, 0x5555555555555555UL) ] ]

  /// C7.2.195 MLA (by element)
  [<TestMethod>]
  member _.``C7.2.195 MLA``() =
    check "2f520020" []
      [ [ Q(0, 0xac693409fb4f4d82UL, 0x0UL) ]
        [ Q(0, 0xf4fae23414290b95UL, 0x0UL) ]
        [ Q(0, 0xbfc000003f800000UL, 0x0UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ] ]
    check "6f520020" []
      [ [ Q(0, 0xac693409fb4f4d82UL, 0x9e005fcc9121053fUL) ]
        [ Q(0, 0xf4fae23414290b95UL, 0xa51b892aa2ebc35fUL) ]
        []
        [] ]
    check "2fa20020" []
      [ [ Q(0, 0x6d184fa53bea5572UL, 0x0UL) ]
        [ Q(0, 0x6893efe8d721a2a5UL, 0x0UL) ]
        [ Q(0, 0x40400000bf800000UL, 0x0UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ] ]
    check "6fa20020" []
      [ [ Q(0, 0x6d184fa53bea5572UL, 0x1bb834c424ecc97bUL) ]
        [ Q(0, 0x6893efe8d721a2a5UL, 0xd3def0566b9e01a3UL) ]
        [ Q(0, 0x40400000bf800000UL, 0xbe2ccccdc0800000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x3ff8000000000000UL) ] ]
    check "0e229420" []
      [ [ Q(0, 0xa6090ba5f94fa90aUL, 0x0UL) ]
        [ Q(0, 0xd9a2abe8a7293001UL, 0x0UL) ]
        [ Q(0, 0x3f4000003f800000UL, 0x0UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ] ]
    check "4e229420" []
      [ [ Q(0, 0xa6090ba5f94fa90aUL, 0x2520e6203e38ac70UL) ]
        [ Q(0, 0xd9a2abe8a7293001UL, 0xf2ab38c84202a9abUL) ]
        [ Q(0, 0x3f4000003f800000UL, 0x3dcccccd41800000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x68000000000000UL) ] ]
    check "0e629420" []
      [ [ Q(0, 0x19094fa5fb4fef0aUL, 0x0UL) ]
        [ Q(0, 0x89a2efe814293601UL, 0x0UL) ]
        [ Q(0, 0x4000003f800000UL, 0x0UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ] ]
    check "4e629420" []
      [ [ Q(0, 0x19094fa5fb4fef0aUL, 0x3e201b2055388e70UL) ]
        [ Q(0, 0x89a2efe814293601UL, 0xadab17c8e402ccabUL) ]
        [ Q(0, 0x4000003f800000UL, 0xdcccccde0800000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x4468000000000000UL) ] ]
    check "0ea29420" []
      [ [ Q(0, 0x6d184fa5fa65ef0aUL, 0x0UL) ]
        [ Q(0, 0x6893efe8788c3601UL, 0x0UL) ]
        [ Q(0, 0x40400000bf800000UL, 0x0UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ] ]
    check "4ea29420" []
      [ [ Q(0, 0x6d184fa5fa65ef0aUL, 0xfb01b2012d88e70UL) ]
        [ Q(0, 0x6893efe8788c3601UL, 0x7adc17c85d10ccabUL) ]
        [ Q(0, 0x40400000bf800000UL, 0x3dcccccdc0800000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xa668000000000000UL) ] ]

  /// C7.2.197 MLS (by element)
  [<TestMethod>]
  member _.``C7.2.197 MLS``() =
    check "2f524020" []
      [ [ Q(0, 0x7fedfec596bfc5f2UL, 0x0UL) ]
        [ Q(0, 0x3ffa6c144dc98915UL, 0x0UL) ]
        [ Q(0, 0xbfc000003f800000UL, 0x0UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ] ]
    check "6f524020" []
      [ [ Q(0, 0x7fedfec596bfc5f2UL, 0x2d58650422ed539bUL) ]
        [ Q(0, 0x3ffa6c144dc98915UL, 0xe37b0c4aa28b0ebfUL) ]
        []
        [] ]
    check "2fa24020" []
      [ [ Q(0, 0xbf3de3295624be02UL, 0x0UL) ]
        [ Q(0, 0xcc615e608ad1f205UL, 0x0UL) ]
        [ Q(0, 0x3f400000bf800000UL, 0x0UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ] ]
    check "6fa24020" []
      [ [ Q(0, 0xbf3de3295624be02UL, 0xafa1900c8f218f5fUL) ]
        [ Q(0, 0xcc615e608ad1f205UL, 0xb4b8a51ed9d8d07bUL) ]
        [ Q(0, 0x3f400000bf800000UL, 0xbd6ccccdc0000000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x3ff8000000000000UL) ] ]
    check "2e229420" []
      [ [ Q(0, 0x864d272999bf696aUL, 0x0UL) ]
        [ Q(0, 0x5b52a360b9c964a9UL, 0x0UL) ]
        [ Q(0, 0x3f4000003f800000UL, 0x0UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ] ]
    check "6e229420" []
      [ [ Q(0, 0x864d272999bf696aUL, 0xa538deb076d6ac6aUL) ]
        [ Q(0, 0x5b52a360b9c964a9UL, 0x96eb5cac02742973UL) ]
        [ Q(0, 0x3f4000003f800000UL, 0x3dcccccd3f000000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x7e88000000000000UL) ] ]
    check "2e629420" []
      [ [ Q(0, 0x134de32996bf246aUL, 0x0UL) ]
        [ Q(0, 0xab525e604dc95ea9UL, 0x0UL) ]
        [ Q(0, 0x7f4000003f800000UL, 0x0UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ] ]
    check "6e629420" []
      [ [ Q(0, 0x134de32996bf246aUL, 0x8d38a9b05ed6ca6aUL) ]
        [ Q(0, 0xab525e604dc95ea9UL, 0xdaeb7dac61740573UL) ]
        [ Q(0, 0x7f4000003f800000UL, 0x6dcccccda0000000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x3b88000000000000UL) ] ]
    check "2ea29420" []
      [ [ Q(0, 0xbf3de32997a9246aUL, 0x0UL) ]
        [ Q(0, 0xcc615e60e9675ea9UL, 0x0UL) ]
        [ Q(0, 0x3f400000bf800000UL, 0x0UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ] ]
    check "6ea29420" []
      [ [ Q(0, 0xbf3de32997a9246aUL, 0xbba9a9b0a135ca6aUL) ]
        [ Q(0, 0xcc615e60e9675ea9UL, 0xdbb7dace8660573UL) ]
        [ Q(0, 0x3f400000bf800000UL, 0x3dcccccdc0000000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xd988000000000000UL) ] ]

  /// C7.2.204 MOVI
  [<TestMethod>]
  member _.``C7.2.204 MOVI``() =
    check "0f00e460" []
      [ [ Q(0, 0x303030303030303UL, 0x0UL) ]
        [ Q(0, 0x303030303030303UL, 0x0UL) ]
        [ Q(0, 0x303030303030303UL, 0x0UL) ]
        [ Q(0, 0x303030303030303UL, 0x0UL) ] ]
    check "4f00e460" []
      [ [ Q(0, 0x303030303030303UL, 0x303030303030303UL) ]
        [ Q(0, 0x303030303030303UL, 0x303030303030303UL) ]
        [ Q(0, 0x303030303030303UL, 0x303030303030303UL) ]
        [ Q(0, 0x303030303030303UL, 0x303030303030303UL) ] ]
    check "0f008460" []
      [ [ Q(0, 0x3000300030003UL, 0x0UL) ]
        [ Q(0, 0x3000300030003UL, 0x0UL) ]
        [ Q(0, 0x3000300030003UL, 0x0UL) ]
        [ Q(0, 0x3000300030003UL, 0x0UL) ] ]
    check "4f008460" []
      [ [ Q(0, 0x3000300030003UL, 0x3000300030003UL) ]
        [ Q(0, 0x3000300030003UL, 0x3000300030003UL) ]
        [ Q(0, 0x3000300030003UL, 0x3000300030003UL) ]
        [ Q(0, 0x3000300030003UL, 0x3000300030003UL) ] ]
    check "0f000460" []
      [ [ Q(0, 0x300000003UL, 0x0UL) ]
        [ Q(0, 0x300000003UL, 0x0UL) ]
        [ Q(0, 0x300000003UL, 0x0UL) ]
        [ Q(0, 0x300000003UL, 0x0UL) ] ]
    check "4f000460" []
      [ [ Q(0, 0x300000003UL, 0x300000003UL) ]
        [ Q(0, 0x300000003UL, 0x300000003UL) ]
        [ Q(0, 0x300000003UL, 0x300000003UL) ]
        [ Q(0, 0x300000003UL, 0x300000003UL) ] ]
    check "4f000400" []
      [ [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]

  /// C7.2.208 MVNI
  [<TestMethod>]
  member _.``C7.2.208 MVNI``() =
    check "2f008460" []
      [ [ Q(0, 0xfffcfffcfffcfffcUL, 0x0UL) ]
        [ Q(0, 0xfffcfffcfffcfffcUL, 0x0UL) ]
        [ Q(0, 0xfffcfffcfffcfffcUL, 0x0UL) ]
        [ Q(0, 0xfffcfffcfffcfffcUL, 0x0UL) ] ]
    check "6f008460" []
      [ [ Q(0, 0xfffcfffcfffcfffcUL, 0xfffcfffcfffcfffcUL) ]
        [ Q(0, 0xfffcfffcfffcfffcUL, 0xfffcfffcfffcfffcUL) ]
        [ Q(0, 0xfffcfffcfffcfffcUL, 0xfffcfffcfffcfffcUL) ]
        [ Q(0, 0xfffcfffcfffcfffcUL, 0xfffcfffcfffcfffcUL) ] ]
    check "2f000460" []
      [ [ Q(0, 0xfffffffcfffffffcUL, 0x0UL) ]
        [ Q(0, 0xfffffffcfffffffcUL, 0x0UL) ]
        [ Q(0, 0xfffffffcfffffffcUL, 0x0UL) ]
        [ Q(0, 0xfffffffcfffffffcUL, 0x0UL) ] ]
    check "6f000460" []
      [ [ Q(0, 0xfffffffcfffffffcUL, 0xfffffffcfffffffcUL) ]
        [ Q(0, 0xfffffffcfffffffcUL, 0xfffffffcfffffffcUL) ]
        [ Q(0, 0xfffffffcfffffffcUL, 0xfffffffcfffffffcUL) ]
        [ Q(0, 0xfffffffcfffffffcUL, 0xfffffffcfffffffcUL) ] ]
    check "6f000400" []
      [ [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ] ]

  /// C7.2.210 NOT
  [<TestMethod>]
  member _.``C7.2.210 NOT``() =
    check "6e205820" []
      [ [ Q(0, 0x8f9e90d0b7231fe3UL, 0xbf297db1d10c03e8UL) ]
        [ Q(0, 0xa8377cdaa0f061dbUL, 0x1dcee4aca0e04f56UL) ]
        [ Q(0, 0x807fffff7fffffffUL, 0x805fffff803fffffUL) ]
        [ Q(0, 0xbff7ffffffffffffUL, 0xc046666666666665UL) ] ]
    check "2e205820" []
      [ [ Q(0, 0x8f9e90d0b7231fe3UL, 0x0UL) ]
        [ Q(0, 0xa8377cdaa0f061dbUL, 0x0UL) ]
        [ Q(0, 0x807fffff7fffffffUL, 0x0UL) ]
        [ Q(0, 0xbff7ffffffffffffUL, 0x0UL) ] ]

  /// C7.2.214 PMUL
  [<TestMethod>]
  member _.``C7.2.214 PMUL``() =
    check "2e229c20" []
      [ [ Q(0, 0x50defabe3068a090UL, 0x0UL) ]
        [ Q(0, 0x5fa8f42407b0762cUL, 0x0UL) ]
        [ Q(0, 0x8080000000000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "6e229c20" []
      [ [ Q(0, 0x50defabe3068a090UL, 0xc08404b8f44d809bUL) ]
        [ Q(0, 0x5fa8f42407b0762cUL, 0x2e608e2ea057405cUL) ]
        [ Q(0, 0x8080000000000000UL, 0x55400000UL) ]
        [ Q(0, 0x0UL, 0x9570000000000000UL) ] ]

  /// C7.2.215 PMULL, PMULL2
  [<TestMethod>]
  member _.``C7.2.215 PMULL``() =
    check "0e22e020" []
      [ [ Q(0, 0x17304b685fa00090UL, 0x395034de0ffa05beUL) ]
        [ Q(0, 0x310704b02876192cUL, 0x125f37a857f40f24UL) ]
        [ Q(0, 0x0UL, 0x3f803f8000000000UL) ]
        [ Q(0, 0x0UL, 0x2000000000000000UL) ] ]

  /// C7.2.215 PMULL, PMULL2
  [<TestMethod>]
  member _.``C7.2.215 PMULL2``() =
    check "4e22e020" []
      [ [ Q(0, 0x8f43a4d5e800d9bUL, 0x22c01e84010412b8UL) ]
        [ Q(0, 0x33a009575440185cUL, 0x3a2e0a60038e302eUL) ]
        [ Q(0, 0x1555204000000000UL, 0x500000000000UL) ]
        [ Q(0, 0x0UL, 0xa956e7000000000UL) ] ]

  /// C7.2.216 RADDHN, RADDHN2
  [<TestMethod>]
  member _.``C7.2.216 RADDHN``() =
    check "2e224020" []
      [ [ Q(0, 0xcc858dddf89da0dfUL, 0x0UL) ]
        [ Q(0, 0x2a46404db13049fcUL, 0x0UL) ]
        [ Q(0, 0x8000ff0000008000UL, 0x0UL) ]
        [ Q(0, 0xc09a9a9ac0000000UL, 0x0UL) ] ]
    check "2ea24020" []
      [ [ Q(0, 0xcc048493f7ff9d52UL, 0x0UL) ]
        [ Q(0, 0x2991464eb1162f9aUL, 0x0UL) ]
        [ Q(0, 0x8020000100000000UL, 0x0UL) ]
        [ Q(0, 0xbfa9999ac0080000UL, 0x0UL) ] ]
    check "2e624020" []
      [ [ Q(0, 0xcc058d40f8009fdcUL, 0x0UL) ]
        [ Q(0, 0x29913ff9b11648e0UL, 0x0UL) ]
        [ Q(0, 0x8020ff4000008000UL, 0x0UL) ]
        [ Q(0, 0xbfaa999ac0080000UL, 0x0UL) ] ]

  /// C7.2.216 RADDHN, RADDHN2
  [<TestMethod>]
  member _.``C7.2.216 RADDHN2``() =
    check "6e624020" []
      [ [ Q(0, 0x962b1967c90789baUL, 0xcc058d40f8009fdcUL) ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0x29913ff9b11648e0UL) ]
        [ Q(0, 0xbfc000003f800000UL, 0x8020ff4000008000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xbfaa999ac0080000UL) ] ]
    check "6ea24020" []
      [ [ Q(0, 0x962b1967c90789baUL, 0xcc048493f7ff9d52UL) ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0x2991464eb1162f9aUL) ]
        [ Q(0, 0xbfc000003f800000UL, 0x8020000100000000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xbfa9999ac0080000UL) ] ]
    check "6e224020" []
      [ [ Q(0, 0x962b1967c90789baUL, 0xcc858dddf89da0dfUL) ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0x2a46404db13049fcUL) ]
        [ Q(0, 0xbfc000003f800000UL, 0x8000ff0000008000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xc09a9a9ac0000000UL) ] ]

  /// C7.2.217 RAX1
  [<TestMethod>]
  member _.``C7.2.217 RAX1``() =
    check "ce628c20" []
      [ [ Q(0, 0x7f5d336be5211e05UL, 0x568a86c692643dfcUL) ]
        [ Q(0, 0xe553dbcc8caf2582UL, 0x6cf14ea69eac88d1UL) ]
        [ Q(0, 0x7f7ffffe80000003UL, 0x7ea00000813ffffeUL) ]
        [ Q(0, 0x4008000000000001UL, 0xc05999999999999aUL) ] ]

  /// C7.2.222 RSHRN, RSHRN2
  [<TestMethod>]
  member _.``C7.2.222 RSHRN``() =
    check "0f1f8c20" []
      [ [ Q(0, 0x4127fe0cb798700eUL, 0x0UL) ]
        [ Q(0, 0x8daad8554193cf12UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xcccdcccd00000000UL, 0x0UL) ] ]
    check "0f0f8c20" []
      [ [ Q(0, 0x6b277a0c31986e0eUL, 0x0UL) ]
        [ Q(0, 0x19aa9055e4938812UL, 0x0UL) ]
        [ Q(0, 0xd000e000c0000000UL, 0x0UL) ]
        [ Q(0, 0xddcdcdcd04000000UL, 0x0UL) ] ]
    check "0f3f8c20" []
      [ [ Q(0, 0x1779fe0ca46e700eUL, 0x0UL) ]
        [ Q(0, 0xaf8fd855af87cf12UL, 0x0UL) ]
        [ Q(0, 0x3fe0000040000000UL, 0x0UL) ]
        [ Q(0, 0xcccccccd00000000UL, 0x0UL) ] ]
    check "0f1d8c20" []
      [ [ Q(0, 0xd04a7f832de69c04UL, 0x0UL) ]
        [ Q(0, 0x236af6151065f3c5UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x3333333300000000UL, 0x0UL) ] ]

  /// C7.2.222 RSHRN, RSHRN2
  [<TestMethod>]
  member _.``C7.2.222 RSHRN2``() =
    check "4f1f8c20" []
      [ [ Q(0, 0x962b1967c90789baUL, 0x4127fe0cb798700eUL) ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0x8daad8554193cf12UL) ]
        [ Q(0, 0xbfc000003f800000UL, 0x0UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xcccdcccd00000000UL) ] ]
    check "4f3f8c20" []
      [ [ Q(0, 0x962b1967c90789baUL, 0x1779fe0ca46e700eUL) ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0xaf8fd855af87cf12UL) ]
        [ Q(0, 0xbfc000003f800000UL, 0x3fe0000040000000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xcccccccd00000000UL) ] ]
    check "4f0f8c20" []
      [ [ Q(0, 0x962b1967c90789baUL, 0x6b277a0c31986e0eUL) ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0x19aa9055e4938812UL) ]
        [ Q(0, 0xbfc000003f800000UL, 0xd000e000c0000000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xddcdcdcd04000000UL) ] ]

  /// C7.2.223 RSUBHN, RSUBHN2
  [<TestMethod>]
  member _.``C7.2.223 RSUBHN``() =
    check "2e226020" []
      [ [ Q(0, 0xb680d11be941f2e1UL, 0x0UL) ]
        [ Q(0, 0x9bf07e14fed77540UL, 0x0UL) ]
        [ Q(0, 0x7f000000ff008000UL, 0x0UL) ]
        [ Q(0, 0xc09a9a9ac0000000UL, 0x0UL) ] ]
    check "2ea26020" []
      [ [ Q(0, 0xb5a8800ae8c3410dUL, 0x0UL) ]
        [ Q(0, 0x9ad0f058fe7ad6b0UL, 0x0UL) ]
        [ Q(0, 0x7f200000ff000001UL, 0x0UL) ]
        [ Q(0, 0xbfc9999ac0080000UL, 0x0UL) ] ]
    check "2e626020" []
      [ [ Q(0, 0xb5a9d0a8e8c3f1deUL, 0x0UL) ]
        [ Q(0, 0x9ad17e46fe7b753fUL, 0x0UL) ]
        [ Q(0, 0x7f200040ff008000UL, 0x0UL) ]
        [ Q(0, 0xbfca999ac0080000UL, 0x0UL) ] ]

  /// C7.2.223 RSUBHN, RSUBHN2
  [<TestMethod>]
  member _.``C7.2.223 RSUBHN2``() =
    check "6e626020" []
      [ [ Q(0, 0x962b1967c90789baUL, 0xb5a9d0a8e8c3f1deUL) ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0x9ad17e46fe7b753fUL) ]
        [ Q(0, 0xbfc000003f800000UL, 0x7f200040ff008000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xbfca999ac0080000UL) ] ]
    check "6ea26020" []
      [ [ Q(0, 0x962b1967c90789baUL, 0xb5a8800ae8c3410dUL) ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0x9ad0f058fe7ad6b0UL) ]
        [ Q(0, 0xbfc000003f800000UL, 0x7f200000ff000001UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xbfc9999ac0080000UL) ] ]
    check "6e226020" []
      [ [ Q(0, 0x962b1967c90789baUL, 0xb680d11be941f2e1UL) ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0x9bf07e14fed77540UL) ]
        [ Q(0, 0xbfc000003f800000UL, 0x7f000000ff008000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xc09a9a9ac0000000UL) ] ]

  /// C7.2.224 SABA
  [<TestMethod>]
  member _.``C7.2.224 SABA``() =
    check "0e227c20" []
      [ [ Q(0, 0x7fee5a74d729a8caUL, 0x0UL) ]
        [ Q(0, 0x9cffd073a63889a6UL, 0x0UL) ]
        [ Q(0, 0xbebf0101bf800001UL, 0x0UL) ]
        [ Q(0, 0xfff8000000000000UL, 0x0UL) ] ]
    check "4e227c20" []
      [ [ Q(0, 0x7fee5a74d729a8caUL, 0x1a0462728a5f488fUL) ]
        [ Q(0, 0x9cffd073a63889a6UL, 0xa97ad913a1017da2UL) ]
        [ Q(0, 0xbebf0101bf800001UL, 0xbceccccd40ff0101UL) ]
        [ Q(0, 0xfff8000000000000UL, 0xff2f676767676766UL) ] ]
    check "0e627c20" []
      [ [ Q(0, 0x7eee5a74d729a8aaUL, 0x0UL) ]
        [ Q(0, 0x9bffd073a6388a04UL, 0x0UL) ]
        [ Q(0, 0xbec10001bf800001UL, 0x0UL) ]
        [ Q(0, 0xfff8000000000000UL, 0x0UL) ] ]
    check "4e627c20" []
      [ [ Q(0, 0x7eee5a74d729a8aaUL, 0x1b54625e895f478fUL) ]
        [ Q(0, 0x9bffd073a6388a04UL, 0xa97ada61a1017d7cUL) ]
        [ Q(0, 0xbec10001bf800001UL, 0xbceccccd40810001UL) ]
        [ Q(0, 0xfff8000000000000UL, 0x2f666766676666UL) ] ]
    check "0ea27c20" []
      [ [ Q(0, 0x7eee5a74d729a8aaUL, 0x0UL) ]
        [ Q(0, 0x9bffd073a6390aa6UL, 0x0UL) ]
        [ Q(0, 0xbec00001bf800001UL, 0x0UL) ]
        [ Q(0, 0xfff8000000000000UL, 0x0UL) ] ]
    check "4ea27c20" []
      [ [ Q(0, 0x7eee5a74d729a8aaUL, 0x1b556272895f114bUL) ]
        [ Q(0, 0x9bffd073a6390aa6UL, 0xa97ada61a1017d7cUL) ]
        [ Q(0, 0xbec00001bf800001UL, 0xbceccccd40800001UL) ]
        [ Q(0, 0xfff8000000000000UL, 0x2e666766666666UL) ] ]

  /// C7.2.225 SABAL, SABAL2
  [<TestMethod>]
  member _.``C7.2.225 SABAL``() =
    check "0e625020" []
      [ [ Q(0, 0x962b2789c907a8aaUL, 0x65adcb2b5a076d7aUL) ]
        [ Q(0, 0x9a7b1c6330fa8a04UL, 0x444bcc3f22bb925eUL) ]
        [ Q(0, 0xbfc080003f800001UL, 0x3dcdcbce40400001UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xbff8c00800000000UL) ] ]
    check "0e225020" []
      [ [ Q(0, 0x96391989c92689caUL, 0x6695e32b5a482c7aUL) ]
        [ Q(0, 0x9af0a76331b8caa6UL, 0x444dcb3f22e4695eUL) ]
        [ Q(0, 0xc04000003f800001UL, 0x3ecbcdcc40410001UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xc0b8000800000000UL) ] ]
    check "0ea25020" []
      [ [ Q(0, 0x962b1967d729a8aaUL, 0x65ace26942ca6d7aUL) ]
        [ Q(0, 0x9a7aa724a6390aa6UL, 0x444bcaba2440925eUL) ]
        [ Q(0, 0xbfc00000bf800001UL, 0x3dccccce3f400001UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xbff80000c0080000UL) ] ]

  /// C7.2.225 SABAL, SABAL2
  [<TestMethod>]
  member _.``C7.2.225 SABAL2``() =
    check "4e225020" []
      [ [ Q(0, 0x965b19bfc92389dcUL, 0x6661e2c05a872c77UL) ]
        [ Q(0, 0x9af9a76a310dcae8UL, 0x44b0cae922ca6968UL) ]
        [ Q(0, 0xbfc000bf3f810001UL, 0x3e4bcced40400000UL) ]
        [ Q(0, 0x4057006700670066UL, 0xc038003700670067UL) ] ]
    check "4ea25020" []
      [ [ Q(0, 0x962b1967f85f6e98UL, 0x65ace2690fafac77UL) ]
        [ Q(0, 0x9a7aa724af3fdec2UL, 0x444bcaba87ea78b6UL) ]
        [ Q(0, 0xbfc000003fc00001UL, 0x3dcccccdbf600000UL) ]
        [ Q(0, 0x3ff0000066666666UL, 0xbff8000040366667UL) ] ]
    check "4e625020" []
      [ [ Q(0, 0x962b48bfc907a4dcUL, 0x65ad98105a07ac63UL) ]
        [ Q(0, 0x9a7b256a30f9dec2UL, 0x444c2fe922bb78b6UL) ]
        [ Q(0, 0xbfc000413f800001UL, 0x3dcd4bed40400000UL) ]
        [ Q(0, 0x3ff0666700006666UL, 0xbff8403700006667UL) ] ]

  /// C7.2.226 SABD
  [<TestMethod>]
  member _.``C7.2.226 SABD``() =
    check "0e227420" []
      [ [ Q(0, 0xe9c3410d0e221f10UL, 0x0UL) ]
        [ Q(0, 0x285294f763fbf51UL, 0x0UL) ]
        [ Q(0, 0xffff010180000001UL, 0x0UL) ]
        [ Q(0, 0xc008000000000000UL, 0x0UL) ] ]
    check "4e227420" []
      [ [ Q(0, 0xe9c3410d0e221f10UL, 0xb558800a30581c22UL) ]
        [ Q(0, 0x285294f763fbf51UL, 0x652f0f597f461493UL) ]
        [ Q(0, 0xffff010180000001UL, 0x7f20000000bf0101UL) ]
        [ Q(0, 0xc008000000000000UL, 0x4037676767676766UL) ] ]
    check "0e627420" []
      [ [ Q(0, 0xe8c3410d0e221ef0UL, 0x0UL) ]
        [ Q(0, 0x185294f753fbfafUL, 0x0UL) ]
        [ Q(0, 0xff01000180000001UL, 0x0UL) ]
        [ Q(0, 0xc008000000000000UL, 0x0UL) ] ]
    check "4e627420" []
      [ [ Q(0, 0xe8c3410d0e221ef0UL, 0xb5a87ff62f581b22UL) ]
        [ Q(0, 0x185294f753fbfafUL, 0x652f0fa77e46146dUL) ]
        [ Q(0, 0xff01000180000001UL, 0x7f20000000410001UL) ]
        [ Q(0, 0xc008000000000000UL, 0x4037666766676666UL) ] ]
    check "0ea27420" []
      [ [ Q(0, 0xe8c3410d0e221ef0UL, 0x0UL) ]
        [ Q(0, 0x185294f753f4051UL, 0x0UL) ]
        [ Q(0, 0xff00000180000001UL, 0x0UL) ]
        [ Q(0, 0xc008000000000000UL, 0x0UL) ] ]
    check "4ea27420" []
      [ [ Q(0, 0xe8c3410d0e221ef0UL, 0xb5a8800a2f57e4deUL) ]
        [ Q(0, 0x185294f753f4051UL, 0x652f0fa77e46146dUL) ]
        [ Q(0, 0xff00000180000001UL, 0x7f20000000400001UL) ]
        [ Q(0, 0xc008000000000000UL, 0x4036666766666666UL) ] ]

  /// C7.2.227 SABDL, SABDL2
  [<TestMethod>]
  member _.``C7.2.227 SABDL``() =
    check "0e627020" []
      [ [ Q(0, 0xe2200001ef0UL, 0xe8c30000410dUL) ]
        [ Q(0, 0x753f0000bfafUL, 0x1850000294fUL) ]
        [ Q(0, 0x800000000001UL, 0xff0100000001UL) ]
        [ Q(0, 0x0UL, 0xc00800000000UL) ] ]
    check "0e227020" []
      [ [ Q(0, 0xe0022001f0010UL, 0xe900c30041000dUL) ]
        [ Q(0, 0x76003f00bf0051UL, 0x200850029004fUL) ]
        [ Q(0, 0x80000000000001UL, 0xff00ff00010001UL) ]
        [ Q(0, 0x0UL, 0xc0000800000000UL) ] ]
    check "0ea27020" []
      [ [ Q(0, 0xe221ef0UL, 0xe8c3410dUL) ]
        [ Q(0, 0x753f4051UL, 0x185294fUL) ]
        [ Q(0, 0x80000001UL, 0xff000001UL) ]
        [ Q(0, 0x0UL, 0xc0080000UL) ] ]

  /// C7.2.227 SABDL, SABDL2
  [<TestMethod>]
  member _.``C7.2.227 SABDL2``() =
    check "4e227020" []
      [ [ Q(0, 0x300058001c0022UL, 0xb500580080000aUL) ]
        [ Q(0, 0x7f004600140093UL, 0x65002f000f0059UL) ]
        [ Q(0, 0xbf00010001UL, 0x7f002000000000UL) ]
        [ Q(0, 0x67006700670066UL, 0x40003700670067UL) ] ]
    check "4ea27020" []
      [ [ Q(0, 0x2f57e4deUL, 0xb5a8800aUL) ]
        [ Q(0, 0x7e46146dUL, 0x652f0fa7UL) ]
        [ Q(0, 0x400001UL, 0x7f200000UL) ]
        [ Q(0, 0x66666666UL, 0x40366667UL) ] ]
    check "4e627020" []
      [ [ Q(0, 0x2f5800001b22UL, 0xb5a800007ff6UL) ]
        [ Q(0, 0x7e460000146dUL, 0x652f00000fa7UL) ]
        [ Q(0, 0x4100000001UL, 0x7f2000000000UL) ]
        [ Q(0, 0x666700006666UL, 0x403700006667UL) ] ]

  /// C7.2.228 SADALP
  [<TestMethod>]
  member _.``C7.2.228 SADALP``() =
    check "0e206820" []
      [ [ Q(0, 0x96fc1a05c92b89b6UL, 0x0UL) ]
        [ Q(0, 0x9a99a6cc3167ca17UL, 0x0UL) ]
        [ Q(0, 0xbfbf00003f000000UL, 0x0UL) ]
        [ Q(0, 0x4038000000000000UL, 0x0UL) ] ]
    check "4e206820" []
      [ [ Q(0, 0x96fc1a05c92b89b6UL, 0x65c2e2385a282c80UL) ]
        [ Q(0, 0x9a99a6cc3167ca17UL, 0x445ecb2823396868UL) ]
        [ Q(0, 0xbfbf00003f000000UL, 0x3debcccd407f0000UL) ]
        [ Q(0, 0x4038000000000000UL, 0xbff0ff32ff32ff33UL) ] ]
    check "0e606820" []
      [ [ Q(0, 0x962bf8f7c907b2b2UL, 0x0UL) ]
        [ Q(0, 0x9a7a821130f9c788UL, 0x0UL) ]
        [ Q(0, 0xbfc07f803f7f8000UL, 0x0UL) ]
        [ Q(0, 0x3ff0400800000000UL, 0x0UL) ] ]
    check "4e606820" []
      [ [ Q(0, 0x962bf8f7c907b2b2UL, 0x65aca58c5a075777UL) ]
        [ Q(0, 0x9a7a821130f9c788UL, 0x444bc83e22bb78d7UL) ]
        [ Q(0, 0xbfc07f803f7f8000UL, 0x3dcd4c6d40407fc0UL) ]
        [ Q(0, 0x3ff0400800000000UL, 0xbff7d952ffff3333UL) ] ]
    check "4ea06820" []
      [ [ Q(0, 0x962b19688245d905UL, 0x65ace268c9d1aad2UL) ]
        [ Q(0, 0x9a7aa724e7d1eb9eUL, 0x444bcaba640c350bUL) ]
        [ Q(0, 0xbfc000003f000000UL, 0x3dccccce3fa00000UL) ]
        [ Q(0, 0x3ff0000040080000UL, 0xbff7ffffd9533333UL) ] ]

  /// C7.2.229 SADDL, SADDL2
  [<TestMethod>]
  member _.``C7.2.229 SADDL``() =
    check "0e620020" []
      [ [ Q(0, 0x9fdaffffdf28UL, 0xfffff7ff00009d51UL) ]
        [ Q(0, 0x48dffffffbf7UL, 0xb115ffff2f99UL) ]
        [ Q(0, 0xffff800000000001UL, 0xffffffffffffffffUL) ]
        [ Q(0, 0x0UL, 0xffffc00800000000UL) ] ]
    check "0e220020" []
      [ [ Q(0, 0x9effdaffdf0028UL, 0xfff7ffff009d0051UL) ]
        [ Q(0, 0x48ffdffffbfff7UL, 0xb00015ff2f0099UL) ]
        [ Q(0, 0xff80000000000001UL, 0xffffffffffffffffUL) ]
        [ Q(0, 0x0UL, 0xffc0000800000000UL) ] ]
    check "0ea20020" []
      [ [ Q(0, 0x9fdbdf28UL, 0xfffffffff7ff9d51UL) ]
        [ Q(0, 0x48dffbf7UL, 0xb1162f99UL) ]
        [ Q(0, 0xffffffff80000001UL, 0xffffffffffffffffUL) ]
        [ Q(0, 0x0UL, 0xffffffffc0080000UL) ] ]

  /// C7.2.229 SADDL, SADDL2
  [<TestMethod>]
  member _.``C7.2.229 SADDL2``() =
    check "4e220020" []
      [ [ Q(0, 0x8c003effdc000cUL, 0xffcb0004ff840092UL) ]
        [ Q(0, 0x3ffff8ff4cffe5UL, 0x2900910045004dUL) ]
        [ Q(0, 0xfe003fffffffffUL, 0x7fff2000000000UL) ]
        [ Q(0, 0xff99ff99ff99ff9aUL, 0xbeffa9ff99ff99UL) ] ]
    check "4ea20020" []
      [ [ Q(0, 0x8d3fdd0cUL, 0xffffffffcc048492UL) ]
        [ Q(0, 0x3ff94ce5UL, 0x2991464dUL) ]
        [ Q(0, 0xff3fffffUL, 0x80200000UL) ]
        [ Q(0, 0xffffffff9999999aUL, 0xbfa99999UL) ] ]
    check "4e620020" []
      [ [ Q(0, 0x8d3effffdd0cUL, 0xffffcc04ffff8492UL) ]
        [ Q(0, 0x3ff8ffff4ce5UL, 0x29910000464dUL) ]
        [ Q(0, 0xff3fffffffffUL, 0x802000000000UL) ]
        [ Q(0, 0xffff9999ffff999aUL, 0xbfa9ffff9999UL) ] ]

  /// C7.2.230 SADDLP
  [<TestMethod>]
  member _.``C7.2.230 SADDLP``() =
    check "0e202820" []
      [ [ Q(0, 0xd1009e0024fffcUL, 0x0UL) ]
        [ Q(0, 0x1fffa8006effc2UL, 0x0UL) ]
        [ Q(0, 0xffff0000ff800000UL, 0x0UL) ]
        [ Q(0, 0x48000000000000UL, 0x0UL) ] ]
    check "4e202820" []
      [ [ Q(0, 0xd1009e0024fffcUL, 0x16ffd000210013UL) ]
        [ Q(0, 0x1fffa8006effc2UL, 0x13006e007eff59UL) ]
        [ Q(0, 0xffff0000ff800000UL, 0x1f0000003f0000UL) ]
        [ Q(0, 0x48000000000000UL, 0xfff8ff32ff32ff33UL) ] ]
    check "0e602820" []
      [ [ Q(0, 0xdf90000028f8UL, 0x0UL) ]
        [ Q(0, 0xffffdaedfffffd33UL, 0x0UL) ]
        [ Q(0, 0x7f80ffff8000UL, 0x0UL) ]
        [ Q(0, 0x400800000000UL, 0x0UL) ] ]
    check "4ea02820" []
      [ [ Q(0, 0xb93e4f4bUL, 0x6fca7e65UL) ]
        [ Q(0, 0xb6d82149UL, 0x4150cbfcUL) ]
        [ Q(0, 0xffffffffff800000UL, 0xff600000UL) ]
        [ Q(0, 0x40080000UL, 0xffffffffd9533333UL) ] ]
    check "4e602820" []
      [ [ Q(0, 0xdf90000028f8UL, 0xffffc32400002b0aUL) ]
        [ Q(0, 0xffffdaedfffffd33UL, 0xfffffd8400000fc8UL) ]
        [ Q(0, 0x7f80ffff8000UL, 0x7fa000007fc0UL) ]
        [ Q(0, 0x400800000000UL, 0xffffd952ffff3333UL) ] ]

  /// C7.2.231 SADDLV
  [<TestMethod>]
  member _.``C7.2.231 SADDLV``() =
    check "0e303820" []
      [ [ Q(0, 0x18fUL, 0x0UL) ]
        [ Q(0, 0xfff7UL, 0x0UL) ]
        [ Q(0, 0xff7fUL, 0x0UL) ]
        [ Q(0, 0x48UL, 0x0UL) ] ]

  /// C7.2.232 SADDW, SADDW2
  [<TestMethod>]
  member _.``C7.2.232 SADDW``() =
    check "0e621020" []
      [ [ Q(0, 0x7061c62d48dcdf28UL, 0x40d609ec2ef42a39UL) ]
        [ Q(0, 0x57c86cf55f0ffbf7UL, 0xe23174a05f1f5d1dUL) ]
        [ Q(0, 0x7f80000080000001UL, 0x7f9f807f7fbfffffUL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fb919999999999aUL) ] ]
    check "0e221020" []
      [ [ Q(0, 0x70b76f2d48dbe028UL, 0x405d81ec2f21fc39UL) ]
        [ Q(0, 0x57b182f55f6c9df7UL, 0xe28a1ba05ecbb11dUL) ]
        [ Q(0, 0x7f80000080000001UL, 0x7f20007f7fbfffffUL) ]
        [ Q(0, 0x4008000000000000UL, 0x3f3999999999999aUL) ] ]
    check "0ea21020" []
      [ [ Q(0, 0x70616f2f9fdbdf28UL, 0x40d6824db6922a39UL) ]
        [ Q(0, 0x57c8832548dffbf7UL, 0xe2311b53b86d5d1dUL) ]
        [ Q(0, 0x7f80000080000001UL, 0x7fa00000003fffffUL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fb999991999999aUL) ] ]

  /// C7.2.232 SADDW, SADDW2
  [<TestMethod>]
  member _.``C7.2.232 SADDW2``() =
    check "4e221020" []
      [ [ Q(0, 0x70bf6f7a48bce011UL, 0x4061827c2ef5fc5bUL) ]
        [ Q(0, 0x57a882fe5eab9e60UL, 0xe2781bb35f49b0a3UL) ]
        [ Q(0, 0x7fff007f7fffffffUL, 0x7fa0ff807fc00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x403899899999999aUL) ] ]
    check "4ea21020" []
      [ [ Q(0, 0x70616f2fa728c111UL, 0x40d6824dba21fe5bUL) ]
        [ Q(0, 0x57c883253fe93a60UL, 0xe2311b53a67fdba3UL) ]
        [ Q(0, 0x7f800000ff7fffffUL, 0x7fa0000080400000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fb9999a1989999aUL) ] ]
    check "4e621020" []
      [ [ Q(0, 0x7061cd7a48dcc111UL, 0x40d60d7c2ef3fe5bUL) ]
        [ Q(0, 0x57c863fe5f0f3a60UL, 0xe23162b35f1fdba3UL) ]
        [ Q(0, 0x7f807f7f7fffffffUL, 0x7fa000807fc00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fba19899999999aUL) ] ]

  /// C7.2.233 SCVTF (vector, fixed-point)
  [<TestMethod>]
  member _.``C7.2.233 SCVTF``() =
    check "0f1be420" []
      [ [ Q(0, 0x630662f3608edbf9UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x617ce3ce61f1e21eUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x63f80000e4000000UL, 0x0UL) ]
        [ Q(0, 0x6000000000000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "4f1be420" []
      [ [ Q(0, 0x630662f3608edbf9UL, 0x600de3db5ddecfd2UL); Fpsr 0x10UL ]
        [ Q(0, 0x617ce3ce61f1e21eUL, 0xdb745ad561f2e0f5UL); Fpsr 0x10UL ]
        [ Q(0, 0x63f80000e4000000UL, 0x63fa000063fc0000UL) ]
        [ Q(0, 0x6000000000000000UL, 0x5ff7e266e266e266UL); Fpsr 0x10UL ] ]
    check "0f3be420" []
      [ [ Q(0, 0x4c60c2de4c11b9c0UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x4c2f91064c3e1f3cUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x4c7f0000cc800000UL, 0x0UL) ]
        [ Q(0, 0x4c00100000000000UL, 0x0UL) ] ]
    check "4f3be420" []
      [ [ Q(0, 0x4c60c2de4c11b9c0UL, 0x4c01ad054bbbcff0UL); Fpsr 0x10UL ]
        [ Q(0, 0x4c2f91064c3e1f3cUL, 0xcb6e77254c3e3f61UL); Fpsr 0x10UL ]
        [ Q(0, 0x4c7f0000cc800000UL, 0x4c7f40004c7f8000UL) ]
        [ Q(0, 0x4c00100000000000UL, 0x4bfee666cc4ccccdUL); Fpsr 0x10UL ] ]
    check "4f7be420" []
      [ [ Q(0, 0x438c185bcbd23738UL, 0x438035a0938bbcffUL); Fpsr 0x10UL ]
        [ Q(0, 0x4385f220c957c3e8UL, 0xc36dcee4aca0e04fUL); Fpsr 0x10UL ]
        [ Q(0, 0x438fe00000200000UL, 0x438fe800001ff000UL) ]
        [ Q(0, 0x4380020000000000UL, 0x437fdccccccccccdUL); Fpsr 0x10UL ] ]
    check "5e79d820" []
      [ [ Q(0, 0xeff9UL, 0x0UL) ]
        [ Q(0, 0xf61eUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "0e79d820" []
      [ [ Q(0, 0x770676f3748eeff9UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x757cf7ce75f1f61eUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x77f80000f8000000UL, 0x0UL) ]
        [ Q(0, 0x7400000000000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "4e79d820" []
      [ [ Q(0, 0x770676f3748eeff9UL, 0x740df7db71dee3d2UL); Fpsr 0x10UL ]
        [ Q(0, 0x757cf7ce75f1f61eUL, 0xef746ed575f2f4f5UL); Fpsr 0x10UL ]
        [ Q(0, 0x77f80000f8000000UL, 0x77fa000077fc0000UL) ]
        [ Q(0, 0x7400000000000000UL, 0x73f7f666f666f666UL); Fpsr 0x10UL ] ]
    check "0e21d820" []
      [ [ Q(0, 0x4ee0c2de4e91b9c0UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x4eaf91064ebe1f3cUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x4eff0000cf000000UL, 0x0UL) ]
        [ Q(0, 0x4e80100000000000UL, 0x0UL) ] ]
    check "4e21d820" []
      [ [ Q(0, 0x4ee0c2de4e91b9c0UL, 0x4e81ad054e3bcff0UL); Fpsr 0x10UL ]
        [ Q(0, 0x4eaf91064ebe1f3cUL, 0xcdee77254ebe3f61UL); Fpsr 0x10UL ]
        [ Q(0, 0x4eff0000cf000000UL, 0x4eff40004eff8000UL) ]
        [ Q(0, 0x4e80100000000000UL, 0x4e7ee666cecccccdUL); Fpsr 0x10UL ] ]
    check "4e61d820" []
      [ [ Q(0, 0x43dc185bcbd23738UL, 0x43d035a0938bbcffUL); Fpsr 0x10UL ]
        [ Q(0, 0x43d5f220c957c3e8UL, 0xc3bdcee4aca0e04fUL); Fpsr 0x10UL ]
        [ Q(0, 0x43dfe00000200000UL, 0x43dfe800001ff000UL) ]
        [ Q(0, 0x43d0020000000000UL, 0x43cfdccccccccccdUL); Fpsr 0x10UL ] ]
    check "1ec2ec20" []
      [ [ Q(0, 0x7c00UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x7c00UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x2800UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e02ec20" []
      [ [ Q(0, 0x4c4b1dd9UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x4abfc1e4UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x3d000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e42ec20" []
      [ [ Q(0, 0x418963bb19c00000UL, 0x0UL) ]
        [ Q(0, 0x4157f83c84000000UL, 0x0UL) ]
        [ Q(0, 0x3fa0000000000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "9ec2ec20" []
      [ [ Q(0, 0xfc00UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0xfc00UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x2800UL, 0x0UL) ]
        [ Q(0, 0x7c00UL, 0x0UL); Fpsr 0x14UL ] ]
    check "9e02ec20" []
      [ [ Q(0, 0xdc0228e5UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xdc006f74UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x3d000000UL, 0x0UL) ]
        [ Q(0, 0x4d000000UL, 0x0UL) ] ]
    check "9e42ec20" []
      [ [ Q(0, 0xc380451c97a69c45UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xc3800dee7bfd00f8UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x3fa0000000000000UL, 0x0UL) ]
        [ Q(0, 0x41a0000000000000UL, 0x0UL) ] ]
    check "1ee20020" []
      [ [ Q(0, 0x7c00UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x7c00UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x3c00UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e220020" []
      [ [ Q(0, 0x4ecb1dd9UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x4d3fc1e4UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x3f800000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e620020" []
      [ [ Q(0, 0x41d963bb19c00000UL, 0x0UL) ]
        [ Q(0, 0x41a7f83c84000000UL, 0x0UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "9ee20020" []
      [ [ Q(0, 0xfc00UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0xfc00UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x3c00UL, 0x0UL) ]
        [ Q(0, 0x7c00UL, 0x0UL); Fpsr 0x14UL ] ]
    check "9e220020" []
      [ [ Q(0, 0xde8228e5UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xde806f74UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x3f800000UL, 0x0UL) ]
        [ Q(0, 0x4f800000UL, 0x0UL) ] ]
    check "9e620020" []
      [ [ Q(0, 0xc3d0451c97a69c45UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0xc3d00dee7bfd00f8UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ]
        [ Q(0, 0x41f0000000000000UL, 0x0UL) ] ]
    check "1e42fc20" []
      [ [ Q(0, 0x41c963bb19c00000UL, 0x0UL) ]
        [ Q(0, 0x4197f83c84000000UL, 0x0UL) ]
        [ Q(0, 0x3fe0000000000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]

  /// C7.2.237 SDOT (by element)
  [<TestMethod>]
  member _.``C7.2.237 SDOT``() =
    check "0e829420" []
      [ [ Q(0, 0x962ad985c907a3a2UL, 0x0UL) ]
        [ Q(0, 0x9a7aee5330f9950eUL, 0x0UL) ]
        [ Q(0, 0xbfbf81003f800000UL, 0x0UL) ]
        [ Q(0, 0x3fefe00000000000UL, 0x0UL) ] ]

  /// C7.2.239 SHA1C
  [<TestMethod>]
  member _.``C7.2.239 SHA1C``() =
    check "5e020020" []
      [ [ Q(0, 0x7d9298a23e35a48UL, 0x8d15403b52bb74abUL) ]
        [ Q(0, 0x69783ced6bbae68fUL, 0xeb952c0ea2b289fbUL) ]
        [ Q(0, 0xc47cef45dc500be8UL, 0x5c1333358de999deUL) ]
        [ Q(0, 0x2ef402086e6c4105UL, 0x20020000103e0004UL) ] ]

  /// C7.2.240 SHA1H
  [<TestMethod>]
  member _.``C7.2.240 SHA1H``() =
    check "5e280820" []
      [ [ Q(0, 0x12373807UL, 0x0UL) ]
        [ Q(0, 0x17c3e789UL, 0x0UL) ]
        [ Q(0, 0x20000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]

  /// C7.2.241 SHA1M
  [<TestMethod>]
  member _.``C7.2.241 SHA1M``() =
    check "5e022020" []
      [ [ Q(0, 0x2a6b4c8253fdc3d1UL, 0x85bf0fbb65769eb1UL) ]
        [ Q(0, 0xd1a67416fd8cb08dUL, 0xdaa54c7204bee67aUL) ]
        [ Q(0, 0xb139bc3387078676UL, 0x2b70000269833378UL) ]
        [ Q(0, 0xcef000e77be41cf9UL, 0xffc0000cf7e0001UL) ] ]

  /// C7.2.242 SHA1P
  [<TestMethod>]
  member _.``C7.2.242 SHA1P``() =
    check "5e021020" []
      [ [ Q(0, 0xa83fe7eb3df76fa5UL, 0xda937b786b64cc21UL) ]
        [ Q(0, 0xed758769d07809d3UL, 0x9928d2cb59b7b9e3UL) ]
        [ Q(0, 0xd4e9bb1fe90cb841UL, 0x4c933335960599dcUL) ]
        [ Q(0, 0xae74020acf624165UL, 0x20020000143d0004UL) ] ]

  /// C7.2.243 SHA1SU0
  [<TestMethod>]
  member _.``C7.2.243 SHA1SU0``() =
    check "5e023020" []
      [ [ Q(0, 0x7419d52dc5fe5adbUL, 0x9ee38f034c902c84UL) ]
        [ Q(0, 0x877cc1eafb92fe89UL, 0x54e363659d6d6b17UL) ]
        [ Q(0, 0x27333327fc00001UL, 0x42cccccdbf3fffffUL) ]
        [ Q(0, 0x8000000000000UL, 0x8000000000000000UL) ] ]

  /// C7.2.244 SHA1SU1
  [<TestMethod>]
  member _.``C7.2.244 SHA1SU1``() =
    check "5e281820" []
      [ [ Q(0, 0x71b1cae172cdcd2bUL, 0x2ec25e8635a35c46UL) ]
        [ Q(0, 0x8aca2f1bce6292e0UL, 0x1452b0b58114e4b9UL) ]
        [ Q(0, 0x8000000180000000UL, 0x7b99999b7fc00000UL) ]
        [ Q(0, 0x4cd3333580100000UL, 0x7fd000007f733332UL) ] ]

  /// C7.2.245 SHA256H2
  [<TestMethod>]
  member _.``C7.2.245 SHA256H2``() =
    check "5e025020" []
      [ [ Q(0, 0xf31a64bbffd21830UL, 0xef3f74dc613bd4abUL) ]
        [ Q(0, 0x81393fa1ca8d2c02UL, 0x8548b976463c8530UL) ]
        [ Q(0, 0x5a664ba13ea7c216UL, 0xfe26bcedb95928daUL) ]
        [ Q(0, 0x4f6190f980bdb016UL, 0xffb19999a5e79644UL) ] ]

  /// C7.2.246 SHA256H
  [<TestMethod>]
  member _.``C7.2.246 SHA256H``() =
    check "5e024020" []
      [ [ Q(0, 0x6bf615ad2ced925fUL, 0xd6cbae8673cd8184UL) ]
        [ Q(0, 0x36b604fc86ed1bf8UL, 0x220d761465cb4955UL) ]
        [ Q(0, 0xe720ff225f4bcdb1UL, 0x5111fd3f01e79e35UL) ]
        [ Q(0, 0x4615cdbbc6d7f6e7UL, 0xd9533333a37fff30UL) ] ]

  /// C7.2.247 SHA256SU0
  [<TestMethod>]
  member _.``C7.2.247 SHA256SU0``() =
    check "5e282820" []
      [ [ Q(0, 0xb11ad6bbe4b85a4eUL, 0x6f3a1a5c3eec094fUL) ]
        [ Q(0, 0x5acc7a8124ac5189UL, 0xe922c5f5b16ae8dfUL) ]
        [ Q(0, 0xc84890105607aff0UL, 0x4ecceccdef314f73UL) ]
        [ Q(0, 0x3ff000000781effcUL, 0xbff800001680dffeUL) ] ]

  /// C7.2.248 SHA256SU1
  [<TestMethod>]
  member _.``C7.2.248 SHA256SU1``() =
    check "5e026020" []
      [ [ Q(0, 0x866734f0c5dc8efdUL, 0x3973aba6716ddc31UL) ]
        [ Q(0, 0x9ce0b238664278aUL, 0xf313bee99c020f59UL) ]
        [ Q(0, 0x3f802050bf1f8fafUL, 0x51fac506f5edef8fUL) ]
        [ Q(0, 0xd9a965a040080000UL, 0x5e4a1db83fc9c39eUL) ] ]

  /// C7.2.249 SHA512H
  [<TestMethod>]
  member _.``C7.2.249 SHA512H``() =
    check "ce628020" []
      [ [ Q(0, 0x4d53791eb811f3c9UL, 0x61cffab646223fUL) ]
        [ Q(0, 0xbd6fe2419c6a417aUL, 0x962b3e724141b0f9UL) ]
        [ Q(0, 0xb76c97ff6846a7d4UL, 0xbda94aad4041a220UL) ]
        [ Q(0, 0x48b84cc5f46300acUL, 0x379d599d9919aUL) ] ]

  /// C7.2.250 SHA512H2
  [<TestMethod>]
  member _.``C7.2.250 SHA512H2``() =
    check "ce628420" []
      [ [ Q(0, 0x8452fb5a4938258eUL, 0xa7d8c383f9f0627aUL) ]
        [ Q(0, 0x8b5bb229601be08UL, 0xea36e029f0d03c4eUL) ]
        [ Q(0, 0xb01a4df9ddc864ebUL, 0x7c4ccce5a520fff1UL) ]
        [ Q(0, 0x47e2000fc181f080UL, 0xfff8000821000000UL) ] ]

  /// C7.2.251 SHA512SU0
  [<TestMethod>]
  member _.``C7.2.251 SHA512SU0``() =
    check "cec08020" []
      [ [ Q(0, 0x75a39d7a5ef528fcUL, 0x8a4cf68f2fbe419bUL) ]
        [ Q(0, 0x4863e02710344391UL, 0x5367e2d1e32248bfUL) ]
        [ Q(0, 0xde6033343760c000UL, 0x7d0d4ccd81c00000UL) ]
        [ Q(0, 0x9e2c080000000000UL, 0xe0bc180000000000UL) ] ]

  /// C7.2.252 SHA512SU1
  [<TestMethod>]
  member _.``C7.2.252 SHA512SU1``() =
    check "ce628820" []
      [ [ Q(0, 0x3c92ba54f628233eUL, 0x6910850f57c0f7f6UL) ]
        [ Q(0, 0x40a80578982e8ce3UL, 0x6fc118669a8095b9UL) ]
        [ Q(0, 0x3e3e0ff341801004UL, 0x3b4b5cc5bfbf0ffaUL) ]
        [ Q(0, 0xc130280100000002UL, 0xde96d5d99999984UL) ] ]

  /// C7.2.253 SHADD
  [<TestMethod>]
  member _.``C7.2.253 SHADD``() =
    check "0e220420" []
      [ [ Q(0, 0xfbff4e284fedef14UL, 0x0UL) ]
        [ Q(0, 0x580a974c24effdfbUL, 0x0UL) ]
        [ Q(0, 0xffffffffc0000000UL, 0x0UL) ]
        [ Q(0, 0xe004000000000000UL, 0x0UL) ] ]
    check "4e220420" []
      [ [ Q(0, 0xfbff4e284fedef14UL, 0xe502c249461fee06UL) ]
        [ Q(0, 0x580a974c24effdfbUL, 0x144822261ffca6f2UL) ]
        [ Q(0, 0xffffffffc0000000UL, 0x3f9000007f1fffffUL) ]
        [ Q(0, 0xe004000000000000UL, 0x5fd4cccccccccccdUL) ] ]
    check "0e620420" []
      [ [ Q(0, 0xfbff4ea84fedef94UL, 0x0UL) ]
        [ Q(0, 0x588a97cc246ffdfbUL, 0x0UL) ]
        [ Q(0, 0xffffffffc0000000UL, 0x0UL) ]
        [ Q(0, 0xe004000000000000UL, 0x0UL) ] ]
    check "4e620420" []
      [ [ Q(0, 0xfbff4ea84fedef94UL, 0xe602c249469fee86UL) ]
        [ Q(0, 0x588a97cc246ffdfbUL, 0x14c823261ffca672UL) ]
        [ Q(0, 0xffffffffc0000000UL, 0x401000007f9fffffUL) ]
        [ Q(0, 0xe004000000000000UL, 0x5fd4cccccccccccdUL) ] ]
    check "0ea20420" []
      [ [ Q(0, 0xfbffcea84fedef94UL, 0x0UL) ]
        [ Q(0, 0x588b17cc246ffdfbUL, 0x0UL) ]
        [ Q(0, 0xffffffffc0000000UL, 0x0UL) ]
        [ Q(0, 0xe004000000000000UL, 0x0UL) ] ]
    check "4ea20420" []
      [ [ Q(0, 0xfbffcea84fedef94UL, 0xe6024249469fee86UL) ]
        [ Q(0, 0x588b17cc246ffdfbUL, 0x14c8a3261ffca672UL) ]
        [ Q(0, 0xffffffffc0000000UL, 0x401000007f9fffffUL) ]
        [ Q(0, 0xe004000000000000UL, 0x5fd4cccccccccccdUL) ] ]

  /// C7.2.254 SHL
  [<TestMethod>]
  member _.``C7.2.254 SHL``() =
    check "0f095420" []
      [ [ Q(0, 0xe0c2de5e90b8c038UL, 0x0UL) ]
        [ Q(0, 0xae90064abe1e3c48UL, 0x0UL) ]
        [ Q(0, 0xfe00000000000000UL, 0x0UL) ]
        [ Q(0, 0x8010000000000000UL, 0x0UL) ] ]
    check "0f115420" []
      [ [ Q(0, 0xe0c2de5e91b8c038UL, 0x0UL) ]
        [ Q(0, 0xaf90064abe1e3c48UL, 0x0UL) ]
        [ Q(0, 0xff00000000000000UL, 0x0UL) ]
        [ Q(0, 0x8010000000000000UL, 0x0UL) ] ]
    check "4f115420" []
      [ [ Q(0, 0xe0c2de5e91b8c038UL, 0x81ac049c5de6f82eUL) ]
        [ Q(0, 0xaf90064abe1e3c48UL, 0xc46236a6be3e6152UL) ]
        [ Q(0, 0xff00000000000000UL, 0xff400000ff800000UL) ]
        [ Q(0, 0x8010000000000000UL, 0x7f72333233323334UL) ] ]
    check "0f215420" []
      [ [ Q(0, 0xe0c2de5e91b9c038UL, 0x0UL) ]
        [ Q(0, 0xaf91064abe1f3c48UL, 0x0UL) ]
        [ Q(0, 0xff00000000000000UL, 0x0UL) ]
        [ Q(0, 0x8010000000000000UL, 0x0UL) ] ]
    check "4f215420" []
      [ [ Q(0, 0xe0c2de5e91b9c038UL, 0x81ad049c5de7f82eUL) ]
        [ Q(0, 0xaf91064abe1f3c48UL, 0xc46236a6be3f6152UL) ]
        [ Q(0, 0xff00000000000000UL, 0xff400000ff800000UL) ]
        [ Q(0, 0x8010000000000000UL, 0x7f73333233333334UL) ] ]
    check "4f415420" []
      [ [ Q(0, 0xe0c2de5e91b9c038UL, 0x81ad049c5de7f82eUL) ]
        [ Q(0, 0xaf91064abe1f3c48UL, 0xc46236a6be3f6152UL) ]
        [ Q(0, 0xff00000100000000UL, 0xff400000ff800000UL) ]
        [ Q(0, 0x8010000000000000UL, 0x7f73333333333334UL) ] ]
    check "4f095420" []
      [ [ Q(0, 0xe0c2de5e90b8c038UL, 0x80ac049c5ce6f82eUL) ]
        [ Q(0, 0xae90064abe1e3c48UL, 0xc46236a6be3e6052UL) ]
        [ Q(0, 0xfe00000000000000UL, 0xfe400000fe800000UL) ]
        [ Q(0, 0x8010000000000000UL, 0x7e72323232323234UL) ] ]

  /// C7.2.255 SHLL, SHLL2
  [<TestMethod>]
  member _.``C7.2.255 SHLL``() =
    check "2e613820" []
      [ [ Q(0, 0x48dc0000e01c0000UL, 0x706100006f2f0000UL) ]
        [ Q(0, 0x5f0f00009e240000UL, 0x57c8000083250000UL) ]
        [ Q(0, 0x8000000000000000UL, 0x7f80000000000000UL) ]
        [ Q(0, 0x0UL, 0x4008000000000000UL) ] ]

  /// C7.2.255 SHLL, SHLL2
  [<TestMethod>]
  member _.``C7.2.255 SHLL2``() =
    check "6e213820" []
      [ [ Q(0, 0x2e00f300fc001700UL, 0x4000d60082004e00UL) ]
        [ Q(0, 0x5f001f00b000a900UL, 0xe20031001b005300UL) ]
        [ Q(0, 0x7f00c00000000000UL, 0x7f00a00000000000UL) ]
        [ Q(0, 0x9900990099009a00UL, 0x3f00b90099009900UL) ] ]

  /// C7.2.256 SHRN, SHRN2
  [<TestMethod>]
  member _.``C7.2.256 SHRN``() =
    check "0f1f8420" []
      [ [ Q(0, 0x4127fe0bb797700eUL, 0x0UL) ]
        [ Q(0, 0x8da9d8544192cf12UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0xcccccccd00000000UL, 0x0UL) ] ]
    check "0f0f8420" []
      [ [ Q(0, 0x6b27790b30976e0eUL, 0x0UL) ]
        [ Q(0, 0x18a98f54e4928712UL, 0x0UL) ]
        [ Q(0, 0xd000e000c0000000UL, 0x0UL) ]
        [ Q(0, 0xdccccccd04000000UL, 0x0UL) ] ]
    check "0f3f8420" []
      [ [ Q(0, 0x1779fe0ba46e700eUL, 0x0UL) ]
        [ Q(0, 0xaf8fd854af87cf12UL, 0x0UL) ]
        [ Q(0, 0x3fe0000040000000UL, 0x0UL) ]
        [ Q(0, 0xcccccccd00000000UL, 0x0UL) ] ]

  /// C7.2.256 SHRN, SHRN2
  [<TestMethod>]
  member _.``C7.2.256 SHRN2``() =
    check "4f1f8420" []
      [ [ Q(0, 0x962b1967c90789baUL, 0x4127fe0bb797700eUL) ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0x8da9d8544192cf12UL) ]
        [ Q(0, 0xbfc000003f800000UL, 0x0UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xcccccccd00000000UL) ] ]
    check "4f3f8420" []
      [ [ Q(0, 0x962b1967c90789baUL, 0x1779fe0ba46e700eUL) ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0xaf8fd854af87cf12UL) ]
        [ Q(0, 0xbfc000003f800000UL, 0x3fe0000040000000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xcccccccd00000000UL) ] ]
    check "4f0f8420" []
      [ [ Q(0, 0x962b1967c90789baUL, 0x6b27790b30976e0eUL) ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0x18a98f54e4928712UL) ]
        [ Q(0, 0xbfc000003f800000UL, 0xd000e000c0000000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xdccccccd04000000UL) ] ]

  /// C7.2.257 SHSUB
  [<TestMethod>]
  member _.``C7.2.257 SHSUB``() =
    check "0e222420" []
      [ [ Q(0, 0x74612006f9eff008UL, 0x0UL) ]
        [ Q(0, 0xffbdebd83b1fa028UL, 0x0UL) ]
        [ Q(0, 0x7f800000c00000ffUL, 0x0UL) ]
        [ Q(0, 0x6004000000000000UL, 0x0UL) ] ]
    check "4e222420" []
      [ [ Q(0, 0x74612006f9eff008UL, 0x5ad4c005e8d40e11UL) ]
        [ Q(0, 0xffbdebd83b1fa028UL, 0xcde8f82c3f230ab6UL) ]
        [ Q(0, 0x7f800000c00000ffUL, 0x3f10000000a00000UL) ]
        [ Q(0, 0x6004000000000000UL, 0xe0e4cccccccccccdUL) ] ]
    check "0e622420" []
      [ [ Q(0, 0x74612086f8eff088UL, 0x0UL) ]
        [ Q(0, 0xff3deb583a9fa028UL, 0x0UL) ]
        [ Q(0, 0x7f800000c000ffffUL, 0x0UL) ]
        [ Q(0, 0x6004000000000000UL, 0x0UL) ] ]
    check "4e622420" []
      [ [ Q(0, 0x74612086f8eff088UL, 0x5ad4c005e8540d91UL) ]
        [ Q(0, 0xff3deb583a9fa028UL, 0xcd68f82c3f230a36UL) ]
        [ Q(0, 0x7f800000c000ffffUL, 0x3f90000000200000UL) ]
        [ Q(0, 0x6004000000000000UL, 0xdfe4cccccccccccdUL) ] ]
    check "0ea22420" []
      [ [ Q(0, 0x7461a086f8eef088UL, 0x0UL) ]
        [ Q(0, 0xff3d6b583a9fa028UL, 0x0UL) ]
        [ Q(0, 0x7f800000bfffffffUL, 0x0UL) ]
        [ Q(0, 0x6004000000000000UL, 0x0UL) ] ]
    check "4ea22420" []
      [ [ Q(0, 0x7461a086f8eef088UL, 0x5ad44005e8540d91UL) ]
        [ Q(0, 0xff3d6b583a9fa028UL, 0xcd68782c3f230a36UL) ]
        [ Q(0, 0x7f800000bfffffffUL, 0x3f90000000200000UL) ]
        [ Q(0, 0x6004000000000000UL, 0xdfe4cccccccccccdUL) ] ]

  /// C7.2.258 SLI
  [<TestMethod>]
  member _.``C7.2.258 SLI``() =
    check "2f095420" []
      [ [ Q(0, 0xe0c3df5f91b9c138UL, 0x0UL) ]
        [ Q(0, 0xae90074abe1f3c49UL, 0x0UL) ]
        [ Q(0, 0xff00000001000000UL, 0x0UL) ]
        [ Q(0, 0x8110000000000000UL, 0x0UL) ] ]
    check "6f095420" []
      [ [ Q(0, 0xe0c3df5f91b9c138UL, 0x81ac049c5ce7f82fUL) ]
        [ Q(0, 0xae90074abe1f3c49UL, 0xc46336a6be3f6153UL) ]
        [ Q(0, 0xff00000001000000UL, 0xff400001fe800000UL) ]
        [ Q(0, 0x8110000000000000UL, 0x7f72323232323234UL) ] ]
    check "2f115420" []
      [ [ Q(0, 0xe0c3de5f91b9c038UL, 0x0UL) ]
        [ Q(0, 0xaf90064abe1f3c49UL, 0x0UL) ]
        [ Q(0, 0xff00000000000000UL, 0x0UL) ]
        [ Q(0, 0x8010000000000000UL, 0x0UL) ] ]
    check "6f115420" []
      [ [ Q(0, 0xe0c3de5f91b9c038UL, 0x81ac049c5de7f82fUL) ]
        [ Q(0, 0xaf90064abe1f3c49UL, 0xc46336a6be3f6153UL) ]
        [ Q(0, 0xff00000000000000UL, 0xff400001ff800000UL) ]
        [ Q(0, 0x8010000000000000UL, 0x7f72333233323334UL) ] ]
    check "2f215420" []
      [ [ Q(0, 0xe0c2de5f91b9c038UL, 0x0UL) ]
        [ Q(0, 0xaf91064abe1f3c49UL, 0x0UL) ]
        [ Q(0, 0xff00000000000000UL, 0x0UL) ]
        [ Q(0, 0x8010000000000000UL, 0x0UL) ] ]
    check "6f215420" []
      [ [ Q(0, 0xe0c2de5f91b9c038UL, 0x81ad049c5de7f82fUL) ]
        [ Q(0, 0xaf91064abe1f3c49UL, 0xc46236a6be3f6153UL) ]
        [ Q(0, 0xff00000000000000UL, 0xff400001ff800000UL) ]
        [ Q(0, 0x8010000000000000UL, 0x7f73333233333334UL) ] ]
    check "6f415420" []
      [ [ Q(0, 0xe0c2de5e91b9c038UL, 0x81ad049c5de7f82fUL) ]
        [ Q(0, 0xaf91064abe1f3c49UL, 0xc46236a6be3f6153UL) ]
        [ Q(0, 0xff00000100000000UL, 0xff400000ff800000UL) ]
        [ Q(0, 0x8010000000000000UL, 0x7f73333333333334UL) ] ]
    check "6f235420" []
      [ [ Q(0, 0x830b797f46e700e2UL, 0x6b41270779fe0bdUL) ]
        [ Q(0, 0xbe44192cf87cf125UL, 0x1188da9af8fd854fUL) ]
        [ Q(0, 0xfc00000000000000UL, 0xfd000005fe000000UL) ]
        [ Q(0, 0x40000000000000UL, 0xfdccccc8ccccccd0UL) ] ]

  /// C7.2.259 SM3PARTW1
  [<TestMethod>]
  member _.``C7.2.259 SM3PARTW1``() =
    check "ce62c020" []
      [ [ Q(0, 0xcc0d4a19b7358419UL, 0x64db735ac99ac44cUL) ]
        [ Q(0, 0x1f1b0391ee7b420dUL, 0x7e159b799ee6a287UL) ]
        [ Q(0, 0x3fffffbfbfc05fe0UL, 0xb2bcebaa1fbfdf80UL) ]
        [ Q(0, 0x7fc7c3fc20004020UL, 0xa84d71757be4267dUL) ] ]

  /// C7.2.260 SM3PARTW2
  [<TestMethod>]
  member _.``C7.2.260 SM3PARTW2``() =
    check "ce62c420" []
      [ [ Q(0, 0x295d670bfea4ef8dUL, 0x24518df25104aad5UL) ]
        [ Q(0, 0x6b641e2d87d8bd85UL, 0x48125e83116ac7d6UL) ]
        [ Q(0, 0xffbfffc0bf800080UL, 0x222caccd807fffbfUL) ]
        [ Q(0, 0x7ff8004000000000UL, 0x784199a69999999aUL) ] ]

  /// C7.2.261 SM3SS1
  [<TestMethod>]
  member _.``C7.2.261 SM3SS1``() =
    check "ce420c20" []
      [ [ Q(0, 0x0UL, 0x5ec581e200000000UL) ]
        [ Q(0, 0x0UL, 0x2888ba000000000UL) ]
        [ Q(0, 0x0UL, 0xa403fd2100000000UL) ]
        [ Q(0, 0x0UL, 0xbec9fdcc00000000UL) ] ]

  /// C7.2.262 SM3TT1A
  [<TestMethod>]
  member _.``C7.2.262 SM3TT1A``() =
    check "ce428020" []
      [ [ Q(0, 0xe58dab4962b1967UL, 0x5877643c65ace268UL) ]
        [ Q(0, 0x76d21e459a7aa724UL, 0x75eeebd0444bcabaUL) ]
        [ Q(0, 0x80000080bfc00000UL, 0xb539a0aa3dcccccdUL) ]
        [ Q(0, 0x3ff00000UL, 0x3fc19266bff80000UL) ] ]

  /// C7.2.263 SM3TT1B
  [<TestMethod>]
  member _.``C7.2.263 SM3TT1B``() =
    check "ce428420" []
      [ [ Q(0, 0xe58dab4962b1967UL, 0x525b54765ace268UL) ]
        [ Q(0, 0x76d21e459a7aa724UL, 0x7be0d26d444bcabaUL) ]
        [ Q(0, 0x80000080bfc00000UL, 0x30acd3dd3dcccccdUL) ]
        [ Q(0, 0x3ff00000UL, 0xffa99266bff80000UL) ] ]

  /// C7.2.264 SM3TT2A
  [<TestMethod>]
  member _.``C7.2.264 SM3TT2A``() =
    check "ce428820" []
      [ [ Q(0, 0x636ad039962b1967UL, 0x75751ad965ace268UL) ]
        [ Q(0, 0x487915db9a7aa724UL, 0x630ca2f5444bcabaUL) ]
        [ Q(0, 0x20200bfc00000UL, 0xc16853153dcccccdUL) ]
        [ Q(0, 0x3ff00000UL, 0xfc1d565bff80000UL) ] ]

  /// C7.2.265 SM3TT2B
  [<TestMethod>]
  member _.``C7.2.265 SM3TT2B``() =
    check "ce428c20" []
      [ [ Q(0, 0x636ad039962b1967UL, 0x736b272e65ace268UL) ]
        [ Q(0, 0x487915db9a7aa724UL, 0x9b448dca444bcabaUL) ]
        [ Q(0, 0x20200bfc00000UL, 0x816280433dcccccdUL) ]
        [ Q(0, 0x3ff00000UL, 0x7fb8d495bff80000UL) ] ]

  /// C7.2.266 SM4E
  [<TestMethod>]
  member _.``C7.2.266 SM4E``() =
    check "cec08420" []
      [ [ Q(0, 0xf4ae2de058aabfa1UL, 0x6382f1ae29047e80UL) ]
        [ Q(0, 0x8e8554358f33bbc9UL, 0x101fb97575a146bdUL) ]
        [ Q(0, 0xba5cd9d7f367584aUL, 0x414468f0a3f7ac12UL) ]
        [ Q(0, 0x91fbd72794a768a8UL, 0x6e83db0bc4dc5c31UL) ] ]

  /// C7.2.267 SM4EKEY
  [<TestMethod>]
  member _.``C7.2.267 SM4EKEY``() =
    check "ce62c820" []
      [ [ Q(0, 0xbeec4b399237c310UL, 0x7a2cd4926241a530UL) ]
        [ Q(0, 0x4a04115a2ffd26b8UL, 0x769a1925b705626eUL) ]
        [ Q(0, 0xd12cb1b86c1481aaUL, 0xcb80a09bff852a8dUL) ]
        [ Q(0, 0xaaf3216372d781f3UL, 0xcdb92ff1a7dccf92UL) ] ]

  /// C7.2.268 SMAX
  [<TestMethod>]
  member _.``C7.2.268 SMAX``() =
    check "0e226420" []
      [ [ Q(0, 0x70616f2f56feff1cUL, 0x0UL) ]
        [ Q(0, 0x594dac745f0f5d24UL, 0x0UL) ]
        [ Q(0, 0x7f7f000000000001UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4e226420" []
      [ [ Q(0, 0x70616f2f56feff1cUL, 0x402e024e5e4bfc17UL) ]
        [ Q(0, 0x594dac745f0f5d24UL, 0x47602a535f1fb03cUL) ]
        [ Q(0, 0x7f7f000000000001UL, 0x7fa000007f7f0000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x7ff0000000000000UL) ] ]
    check "0e626420" []
      [ [ Q(0, 0x70616f2f56feff0cUL, 0x0UL) ]
        [ Q(0, 0x594dac745f0f5dd3UL, 0x0UL) ]
        [ Q(0, 0x7f80000000000001UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4e626420" []
      [ [ Q(0, 0x70616f2f56feff0cUL, 0x40d602445e4bfc17UL) ]
        [ Q(0, 0x594dac745f0f5dd3UL, 0x47602afa5f1fb0a9UL) ]
        [ Q(0, 0x7f80000000000001UL, 0x7fa000007fc00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x7ff0000000000000UL) ] ]
    check "0ea26420" []
      [ [ Q(0, 0x70616f2f56feff0cUL, 0x0UL) ]
        [ Q(0, 0x594dac745f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x7f80000000000001UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4ea26420" []
      [ [ Q(0, 0x70616f2f56feff0cUL, 0x40d6824e5e4be0f5UL) ]
        [ Q(0, 0x594dac745f0f9e24UL, 0x47602afa5f1fb0a9UL) ]
        [ Q(0, 0x7f80000000000001UL, 0x7fa000007fc00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x7ff0000000000000UL) ] ]

  /// C7.2.269 SMAXP
  [<TestMethod>]
  member _.``C7.2.269 SMAXP``() =
    check "0e22a420" []
      [ [ Q(0, 0x9e2e560c706f481cUL, 0x0UL) ]
        [ Q(0, 0x5974e95d57255f24UL, 0x0UL) ]
        [ Q(0, 0x7fff00017f000000UL, 0x0UL) ]
        [ Q(0, 0x40000000UL, 0x0UL) ] ]
    check "4e22a420" []
      [ [ Q(0, 0x404e2e17706f481cUL, 0x2e445ef59e2e560cUL) ]
        [ Q(0, 0x31535fb057255f24UL, 0x602ae03c5974e95dUL) ]
        [ Q(0, 0x7f007f007f000000UL, 0x7fff7fff0001UL) ]
        [ Q(0, 0x3f99999a40000000UL, 0x7f00000000000000UL) ] ]
    check "0e62a420" []
      [ [ Q(0, 0x2e2256fe706148dcUL, 0x0UL) ]
        [ Q(0, 0x594d5dd357c85f0fUL, 0x0UL) ]
        [ Q(0, 0xffff00017f800000UL, 0x0UL) ]
        [ Q(0, 0x40080000UL, 0x0UL) ] ]
    check "4e62a420" []
      [ [ Q(0, 0x40d62ef3706148dcUL, 0x2445e4b2e2256feUL) ]
        [ Q(0, 0x1b535f1f57c85f0fUL, 0x4760e0d9594d5dd3UL) ]
        [ Q(0, 0x7fa07fc07f800000UL, 0x807f7fffff0001UL) ]
        [ Q(0, 0x3fb9999a40080000UL, 0x7ff0000000000000UL) ] ]
    check "0ea2a420" []
      [ [ Q(0, 0x56feff0c70616f2fUL, 0x0UL) ]
        [ Q(0, 0x594dac745f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x17f800000UL, 0x0UL) ]
        [ Q(0, 0x40080000UL, 0x0UL) ] ]
    check "4ea2a420" []
      [ [ Q(0, 0x40d6824e70616f2fUL, 0x5e4be0f556feff0cUL) ]
        [ Q(0, 0x5f1fb0a95f0f9e24UL, 0x47602afa594dac74UL) ]
        [ Q(0, 0x7fc000007f800000UL, 0x7f7fffff00000001UL) ]
        [ Q(0, 0x3fb9999940080000UL, 0x7ff0000000000000UL) ] ]

  /// C7.2.270 SMAXV
  [<TestMethod>]
  member _.``C7.2.270 SMAXV``() =
    check "4eb0a820" []
      [ [ Q(0, 0x70616f2fUL, 0x0UL) ]
        [ Q(0, 0x5f1fb0a9UL, 0x0UL) ]
        [ Q(0, 0x7fc00000UL, 0x0UL) ]
        [ Q(0, 0x40080000UL, 0x0UL) ] ]

  /// C7.2.271 SMIN
  [<TestMethod>]
  member _.``C7.2.271 SMIN``() =
    check "0e226c20" []
      [ [ Q(0, 0x879e2e2248dce00cUL, 0x0UL) ]
        [ Q(0, 0x57c88325e9d09ed3UL, 0x0UL) ]
        [ Q(0, 0x8080ffff80000000UL, 0x0UL) ]
        [ Q(0, 0x8000000000000000UL, 0x0UL) ] ]
    check "4e226c20" []
      [ [ Q(0, 0x879e2e2248dce00cUL, 0x8bd682442ef3e0f5UL) ]
        [ Q(0, 0x57c88325e9d09ed3UL, 0xe2311bfae0d99ca9UL) ]
        [ Q(0, 0x8080ffff80000000UL, 0x8000007fc0ffffUL) ]
        [ Q(0, 0x8000000000000000UL, 0x3fb999999999999aUL) ] ]
    check "0e626c20" []
      [ [ Q(0, 0x879e2e2248dce01cUL, 0x0UL) ]
        [ Q(0, 0x57c88325e9d09e24UL, 0x0UL) ]
        [ Q(0, 0x807fffff80000000UL, 0x0UL) ]
        [ Q(0, 0x8000000000000000UL, 0x0UL) ] ]
    check "4e626c20" []
      [ [ Q(0, 0x879e2e2248dce01cUL, 0x8b2e824e2ef3e0f5UL) ]
        [ Q(0, 0x57c88325e9d09e24UL, 0xe2311b53e0d99c3cUL) ]
        [ Q(0, 0x807fffff80000000UL, 0x8000007f7fffffUL) ]
        [ Q(0, 0x8000000000000000UL, 0x3fb999999999999aUL) ] ]
    check "0ea26c20" []
      [ [ Q(0, 0x879e2e2248dce01cUL, 0x0UL) ]
        [ Q(0, 0x57c88325e9d05dd3UL, 0x0UL) ]
        [ Q(0, 0x807fffff80000000UL, 0x0UL) ]
        [ Q(0, 0x8000000000000000UL, 0x0UL) ] ]
    check "4ea26c20" []
      [ [ Q(0, 0x879e2e2248dce01cUL, 0x8b2e02442ef3fc17UL) ]
        [ Q(0, 0x57c88325e9d05dd3UL, 0xe2311b53e0d99c3cUL) ]
        [ Q(0, 0x807fffff80000000UL, 0x8000007f7fffffUL) ]
        [ Q(0, 0x8000000000000000UL, 0x3fb999999999999aUL) ] ]

  /// C7.2.272 SMINP
  [<TestMethod>]
  member _.``C7.2.272 SMINP``() =
    check "0e22ac20" []
      [ [ Q(0, 0x8722feff612fdce0UL, 0x0UL) ]
        [ Q(0, 0x4dacd0d3c8830f9eUL, 0x0UL) ]
        [ Q(0, 0x80ff000080008000UL, 0x0UL) ]
        [ Q(0, 0x8000000008000000UL, 0x0UL) ] ]
    check "4e22ac20" []
      [ [ Q(0, 0xd682f3fc612fdce0UL, 0x8b024be08722feffUL) ]
        [ Q(0, 0xe21b1fa9c8830f9eUL, 0x47fad99c4dacd0d3UL) ]
        [ Q(0, 0xa000c00080008000UL, 0x80007fff80ff0000UL) ]
        [ Q(0, 0xb999999908000000UL, 0xf000000080000000UL) ] ]
    check "0e62ac20" []
      [ [ Q(0, 0x879eff0c6f2fe01cUL, 0x0UL) ]
        [ Q(0, 0xac74e9d083259e24UL, 0x0UL) ]
        [ Q(0, 0x807f000000008000UL, 0x0UL) ]
        [ Q(0, 0x8000000000000000UL, 0x0UL) ] ]
    check "4e62ac20" []
      [ [ Q(0, 0x824efc176f2fe01cUL, 0x8b2ee0f5879eff0cUL) ]
        [ Q(0, 0xe231b0a983259e24UL, 0x2afa9c3cac74e9d0UL) ]
        [ Q(0, 0x8000UL, 0xffff807f0000UL) ]
        [ Q(0, 0x9999999900000000UL, 0x80000000UL) ] ]
    check "0ea2ac20" []
      [ [ Q(0, 0x879e2e2248dce01cUL, 0x0UL) ]
        [ Q(0, 0xe9d05dd357c88325UL, 0x0UL) ]
        [ Q(0, 0x807fffff80000000UL, 0x0UL) ]
        [ Q(0, 0x8000000000000000UL, 0x0UL) ] ]
    check "4ea2ac20" []
      [ [ Q(0, 0x2ef3fc1748dce01cUL, 0x8b2e0244879e2e22UL) ]
        [ Q(0, 0xe2311b5357c88325UL, 0xe0d99c3ce9d05dd3UL) ]
        [ Q(0, 0x7fa0000080000000UL, 0x800000807fffffUL) ]
        [ Q(0, 0x9999999a00000000UL, 0x80000000UL) ] ]

  /// C7.2.273 SMINV
  [<TestMethod>]
  member _.``C7.2.273 SMINV``() =
    check "4eb1a820" []
      [ [ Q(0, 0x2ef3fc17UL, 0x0UL) ]
        [ Q(0, 0xe2311b53UL, 0x0UL) ]
        [ Q(0, 0x80000000UL, 0x0UL) ]
        [ Q(0, 0x9999999aUL, 0x0UL) ] ]

  /// C7.2.274 SMLAL, SMLAL2 (by element)
  [<TestMethod>]
  member _.``C7.2.274 SMLAL``() =
    check "0e628020" []
      [ [ Q(0, 0xaeed4bafc925ef0aUL, 0x30d465466e1062abUL) ]
        [ Q(0, 0x923d8a540d1c3601UL, 0x62eab9e24b7ab1d3UL) ]
        [ Q(0, 0xbfc000003f800000UL, 0xfe4c0d4d40400000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x9ff4000000000000UL) ] ]
    check "0f522020" []
      [ [ Q(0, 0xaeed4bafbe314d82UL, 0x8bdcf8a67fcf470fUL) ]
        [ Q(0, 0x923d8a5439750b95UL, 0x3cb0253a2d8da41fUL) ]
        []
        [] ]
    check "0fa22020" []
      [ [ Q(0, 0x73e7b8ee3bea5572UL, 0x30d4453e30f462abUL) ]
        [ Q(0, 0xbba3ecdad721a2a5UL, 0x62eb22c3f0d4b1d3UL) ]
        [ Q(0, 0xff800000bf800000UL, 0xfe4c8cccc0c00000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x9ff4000000000000UL) ] ]
    check "0e228020" []
      [ [ Q(0, 0xae5b19afc9278b0aUL, 0x30bcbd466df932abUL) ]
        [ Q(0, 0x91f1a4540d5fc401UL, 0x628ab9e24bbf79d3UL) ]
        [ Q(0, 0xbfc000003f800000UL, 0xfe4c8d4d40400000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x9ff8000000000000UL) ] ]
    check "0ea28020" []
      [ [ Q(0, 0xaeede06efa65ef0aUL, 0x30d4453e30f462abUL) ]
        [ Q(0, 0x923d9f76788c3601UL, 0x62eb22c3f0d4b1d3UL) ]
        [ Q(0, 0xbfbfffffbf800000UL, 0xfe4c8cccc0c00000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x9ff4000000000000UL) ] ]

  /// C7.2.274 SMLAL, SMLAL2 (by element)
  [<TestMethod>]
  member _.``C7.2.274 SMLAL2``() =
    check "4f522020" []
      [ [ Q(0, 0xa61f5081c7b3628cUL, 0x7bb51abc2f50a9d1UL) ]
        [ Q(0, 0x923c275437da24a5UL, 0x46e12b8a205d277fUL) ]
        []
        [] ]
    check "4fa22020" []
      [ [ Q(0, 0x8016ca4c93ed26c8UL, 0x472f8ee510127ec9UL) ]
        [ Q(0, 0xbba9882b79dc62e9UL, 0x39e5d1eab24e8eabUL) ]
        [ Q(0, 0x801fdfffbfc00000UL, 0xfe3c9cccc0a00000UL) ]
        [ Q(0, 0x7323333300000000UL, 0xa01b333380000000UL) ] ]
    check "4e228020" []
      [ [ Q(0, 0xa70f1598c98788bdUL, 0x486cdadc590b4125UL) ]
        [ Q(0, 0x8e9aa26b5039b5f1UL, 0x3bf9dd1a2729671dUL) ]
        [ Q(0, 0xfec1e0403f800000UL, 0x3dccfccd40400000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xdf39047000000000UL) ] ]
    check "4ea28020" []
      [ [ Q(0, 0xa7769ab581d8ebbdUL, 0x48167ff9040a6525UL) ]
        [ Q(0, 0x8ee78cf96b4f2df1UL, 0x3bfc36b7594bb61dUL) ]
        [ Q(0, 0xff601fffbfc00000UL, 0x3e0c9ccd40400000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xdfd0d132e6700000UL) ] ]
    check "4e628020" []
      [ [ Q(0, 0xa7761498c980ebbdUL, 0x4816badc58ea6525UL) ]
        [ Q(0, 0x8ee7686b4fe52df1UL, 0x3bfc341a2751b61dUL) ]
        [ Q(0, 0xff5fa0403f800000UL, 0x3e0c9ccd40400000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xdfd0847000000000UL) ] ]

  /// C7.2.276 SMLSL, SMLSL2 (by element)
  [<TestMethod>]
  member _.``C7.2.276 SMLSL``() =
    check "0e62a020" []
      [ [ Q(0, 0x7d68e71fc8e9246aUL, 0x9a855f8a45fdf62fUL) ]
        [ Q(0, 0xa2b7c3f454d75ea9UL, 0x25acdb92f9fc204bUL) ]
        [ Q(0, 0xbfc000003f800000UL, 0x7d4d8c4d40400000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xdffc000000000000UL) ] ]
    check "0f526020" []
      [ [ Q(0, 0x7d68e71fd3ddc5f2UL, 0x3f7ccc2a343f11cbUL) ]
        [ Q(0, 0xa2b7c3f4287e8915UL, 0x4be7703a17e92dffUL) ]
        []
        [] ]
    check "0fa26020" []
      [ [ Q(0, 0xb86e79e15624be02UL, 0x9a857f928319f62fUL) ]
        [ Q(0, 0x7951616d8ad1f205UL, 0x25ac72b054a2204bUL) ]
        [ Q(0, 0x7fffffffbf800000UL, 0x7d4d0ccdbfc00000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xdffc000000000000UL) ] ]
    check "0e22a020" []
      [ [ Q(0, 0x7dfb191fc8e7886aUL, 0x9a9c078a4615262fUL) ]
        [ Q(0, 0xa303a9f45493d0a9UL, 0x260cdb92f9b7584bUL) ]
        [ Q(0, 0xbfc000003f800000UL, 0x7d4c0c4d40400000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xdff8000000000000UL) ] ]
    check "0ea2a020" []
      [ [ Q(0, 0x7d68526097a9246aUL, 0x9a857f928319f62fUL) ]
        [ Q(0, 0xa2b7aed1e9675ea9UL, 0x25ac72b054a2204bUL) ]
        [ Q(0, 0xbfc00000bf800000UL, 0x7d4d0ccdbfc00000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xdffc000000000000UL) ] ]

  /// C7.2.276 SMLSL, SMLSL2 (by element)
  [<TestMethod>]
  member _.``C7.2.276 SMLSL2``() =
    check "4f526020" []
      [ [ Q(0, 0x8636e24dca5bb0e8UL, 0x4fa4aa1484bdaf09UL) ]
        [ Q(0, 0xa2b926f42a197005UL, 0x41b669ea2519aa9fUL) ]
        []
        [] ]
    check "4fa26020" []
      [ [ Q(0, 0xac3f6882fe21ecacUL, 0x842a35eba3fbda11UL) ]
        [ Q(0, 0x794bc61ce81731c1UL, 0x4eb1c38993284373UL) ]
        [ Q(0, 0xff602000bf400000UL, 0x7d5cfccdbfe00000UL) ]
        [ Q(0, 0xcbccccd00000000UL, 0xdfd4cccc80000000UL) ] ]
    check "4e22a020" []
      [ [ Q(0, 0x85471d36c8878ab7UL, 0x82ece9f45b0317b5UL) ]
        [ Q(0, 0xa65aabdd11b9deb9UL, 0x4c9db85a1e4d6b01UL) ]
        [ Q(0, 0x80bf1fc03f800000UL, 0x3dcc9ccd40400000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xa0b7fb9000000000UL) ] ]
    check "4ea2a020" []
      [ [ Q(0, 0x84df981a103627b7UL, 0x834344d7b003f3b5UL) ]
        [ Q(0, 0xa60dc14ef6a466b9UL, 0x4c9b5ebcec2b1c01UL) ]
        [ Q(0, 0x801fe000bf400000UL, 0x3d8cfccd40400000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xa01f2ecd19900000UL) ] ]
    check "4e62a020" []
      [ [ Q(0, 0x84e01e36c88e27b7UL, 0x834309f45b23f3b5UL) ]
        [ Q(0, 0xa60de5dd120e66b9UL, 0x4c9b615a1e251c01UL) ]
        [ Q(0, 0x80205fc03f800000UL, 0x3d8cfccd40400000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xa01f7b9000000000UL) ] ]

  /// C7.2.278 SMMLA (vector)
  [<TestMethod>]
  member _.``C7.2.278 SMMLA``() =
    check "4e82a420" []
      [ [ Q(0, 0x962b17afc90763c0UL, 0x65acddf05a07229fUL) ]
        [ Q(0, 0x9a7ab57430f9dc3dUL, 0x444bd18722bb6e00UL) ]
        [ Q(0, 0xbfc000803f7f8100UL, 0x3dcd1c0e403f90e0UL) ]
        [ Q(0, 0x3ff01f40ffffe000UL, 0xbff823b1ffffe080UL) ] ]

  /// C7.2.279 SMOV
  [<TestMethod>]
  member _.``C7.2.279 SMOV``() =
    check "0e032c20" []
      [ [ X(0, 0xffffffe0UL) ]
        [ X(0, 0xffffff9eUL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "0e062c20" []
      [ [ X(0, 0x48dcUL) ]
        [ X(0, 0x5f0fUL) ]
        [ X(0, 0xffff8000UL) ]
        [ X(0, 0x0UL) ] ]
    check "4e032c20" []
      [ [ X(0, 0xffffffffffffffe0UL) ]
        [ X(0, 0xffffffffffffff9eUL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "4e062c20" []
      [ [ X(0, 0x48dcUL) ]
        [ X(0, 0x5f0fUL) ]
        [ X(0, 0xffffffffffff8000UL) ]
        [ X(0, 0x0UL) ] ]
    check "4e0c2c20" []
      [ [ X(0, 0x70616f2fUL) ]
        [ X(0, 0x57c88325UL) ]
        [ X(0, 0x7f800000UL) ]
        [ X(0, 0x40080000UL) ] ]
    check "0e012c20" []
      [ [ X(0, 0x1cUL) ]
        [ X(0, 0x24UL) ]
        []
        [ X(0, 0x0UL) ] ]

  /// C7.2.280 SMULL, SMULL2 (by element)
  [<TestMethod>]
  member _.``C7.2.280 SMULL2``() =
    check "4f52a020" []
      [ [ Q(0, 0xff4371afeabd8d2UL, 0x16083854d5497d64UL) ]
        [ Q(0, 0xf7c1803006e05a50UL, 0x29560d0fda1be70UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "4fa2a020" []
      [ [ Q(0, 0xe9ebb0e4cae59d0eUL, 0xe182ac7cb60b525cUL) ]
        [ Q(0, 0x212ee10748e29894UL, 0xf59a07308f93259cUL) ]
        [ Q(0, 0xc05fdfff80400000UL, 0xc06fcfff80600000UL) ]
        [ Q(0, 0x3333333300000000UL, 0xe023333380000000UL) ] ]
    check "4e62c020" []
      [ [ Q(0, 0x114afb3100796203UL, 0xe269d874fee338b8UL) ]
        [ Q(0, 0xf46cc1471eeb639cUL, 0xf7b0696004964d0eUL) ]
        [ Q(0, 0x3f9fa04000000000UL, 0x3fd00000000000UL) ]
        [ Q(0, 0x0UL, 0x1fd8847000000000UL) ] ]
    check "4ea2c020" []
      [ [ Q(0, 0x114b814db8d16203UL, 0xe2699d90aa0338b8UL) ]
        [ Q(0, 0xf46ce5d53a55639cUL, 0xf7b06bfd36904d0eUL) ]
        [ Q(0, 0x3fa01fff80400000UL, 0x3fd00000000000UL) ]
        [ Q(0, 0x0UL, 0x1fd8d132e6700000UL) ] ]
    check "4e22c020" []
      [ [ Q(0, 0x10e4fc310080ff03UL, 0xe2c0f874ff0414b8UL) ]
        [ Q(0, 0xf420fb471f40eb9cUL, 0xf7ae1260046efe0eUL) ]
        [ Q(0, 0x3f01e04000000000UL, 0x300000000000UL) ]
        [ Q(0, 0x0UL, 0x1f41047000000000UL) ] ]

  /// C7.2.282 SQABS
  [<TestMethod>]
  member _.``C7.2.282 SQABS``() =
    check "0e207820" []
      [ [ Q(0, 0x70616f2f4824201cUL, 0x0UL) ]
        [ Q(0, 0x57387d255f0f6224UL, 0x0UL) ]
        [ Q(0, 0x7f7f00007f000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4e207820" []
      [ [ Q(0, 0x70616f2f4824201cUL, 0x402a7e4e2e0d0417UL) ]
        [ Q(0, 0x57387d255f0f6224UL, 0x1e311b535f1f5057UL) ]
        [ Q(0, 0x7f7f00007f000000UL, 0x7f6000007f400000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x4008000000000000UL, 0x3f47676767676766UL) ] ]
    check "0e607820" []
      [ [ Q(0, 0x70616f2f48dc1fe4UL, 0x0UL) ]
        [ Q(0, 0x57c87cdb5f0f61dcUL, 0x0UL) ]
        [ Q(0, 0x7f8000007fff0000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4e607820" []
      [ [ Q(0, 0x70616f2f48dc1fe4UL, 0x40d67db22ef303e9UL) ]
        [ Q(0, 0x57c87cdb5f0f61dcUL, 0x1dcf1b535f1f4f57UL) ]
        [ Q(0, 0x7f8000007fff0000UL, 0x7fa000007fc00000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x4008000000000000UL, 0x3fb9666766676666UL) ] ]
    check "0ea07820" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x0UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x7f8000007fffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4ee07820" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x40d6824e2ef3fc17UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x1dcee4aca0e04f57UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x7fa000007fc00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fb999999999999aUL) ] ]
    check "4ea07820" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x40d6824e2ef3fc17UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x1dcee4ad5f1fb0a9UL) ]
        [ Q(0, 0x7f8000007fffffffUL, 0x7fa000007fc00000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x4008000000000000UL, 0x3fb9999966666666UL) ] ]

  /// C7.2.283 SQADD
  [<TestMethod>]
  member _.``C7.2.283 SQADD``() =
    check "0e220c20" []
      [ [ Q(0, 0xf7ff7f517fdadf28UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7f15807f48dffbf7UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffff80000001UL, 0x0UL) ]
        [ Q(0, 0xc008000000000000UL, 0x0UL) ] ]
    check "4e220c20" []
      [ [ Q(0, 0xf7ff7f517fdadf28UL, 0xcb04847f7f3edc0cUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7f15807f48dffbf7UL, 0x297f454d3ff880e5UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffff80000001UL, 0x7f8000007f3fffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xc008000000000000UL, 0x7fa999999999999aUL); Fpsr 0x8000000UL ] ]
    check "0e620c20" []
      [ [ Q(0, 0xf7ff7fff7fffdf28UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fff800048dffbf7UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffff80000001UL, 0x0UL) ]
        [ Q(0, 0xc008000000000000UL, 0x0UL) ] ]
    check "4e620c20" []
      [ [ Q(0, 0xf7ff7fff7fffdf28UL, 0xcc0484927fffdd0cUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fff800048dffbf7UL, 0x2991464d3ff88000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffff80000001UL, 0x7fff00007fffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xc008000000000000UL, 0x7fff99999999999aUL); Fpsr 0x8000000UL ] ]
    check "0ea20c20" []
      [ [ Q(0, 0xf7ff9d517fffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fffffff48dffbf7UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffff80000001UL, 0x0UL) ]
        [ Q(0, 0xc008000000000000UL, 0x0UL) ] ]
    check "4ee20c20" []
      [ [ Q(0, 0xf7ff9d519fdbdf28UL, 0xcc0484928d3fdd0cUL) ]
        [ Q(0, 0x7fffffffffffffffUL, 0x2991464e3ff94ce5UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffff80000001UL, 0x7fffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xc008000000000000UL, 0x7fffffffffffffffUL); Fpsr 0x8000000UL ] ]
    check "4ea20c20" []
      [ [ Q(0, 0xf7ff9d517fffffffUL, 0xcc0484927fffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fffffff48dffbf7UL, 0x2991464d3ff94ce5UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffff80000001UL, 0x7fffffff7fffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xc008000000000000UL, 0x7fffffff9999999aUL); Fpsr 0x8000000UL ] ]

  /// C7.2.284 SQDMLAL, SQDMLAL2 (by element)
  [<TestMethod>]
  member _.``C7.2.284 SQDMLAL``() =
    check "0f523020" []
      [ [ Q(0, 0xc7af7df7b35b114aUL, 0x7fffffff7fffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x8a006d8441f04cd5UL, 0x35147fba385fdf2fUL) ]
        []
        [] ]
    check "0fa23020" []
      [ [ Q(0, 0x8000000000000000UL, 0xfbfba81407e198e9UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xdccd32917d497af5UL, 0x7fffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3f4000013f800000UL, 0xbecc4ccc41400000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x8000000000000000UL); Fpsr 0x8000000UL ] ]
    check "0ea29020" []
      [ [ Q(0, 0xc7b0a7762bc4545aUL, 0xfbfba81407e198e9UL) ]
        [ Q(0, 0x8a0097c8c01ea1adUL, 0x7fffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xbfbfffff3f800000UL, 0xbecc4ccc41400000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x8000000000000000UL); Fpsr 0x8000000UL ] ]
    check "0e629020" []
      [ [ Q(0, 0xc7af7df7c944545aUL, 0xfbfbe8247fffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x8a006d84e93ea1adUL, 0x7fffffff7439fa97UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xbfc000003f800000UL, 0xbecb4dcd40400000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x8000000000000000UL); Fpsr 0x8000000UL ] ]

  /// C7.2.284 SQDMLAL, SQDMLAL2 (by element)
  [<TestMethod>]
  member _.``C7.2.284 SQDMLAL2``() =
    check "4f523020" []
      [ [ Q(0, 0xb613879bc65f3b5eUL, 0x7fffffff049a2735UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x89fda7843eba7ef5UL, 0x49768c5a1dfee5efUL) ]
        []
        [] ]
    check "4fa23020" []
      [ [ Q(0, 0x8000000000000000UL, 0x28b23b61c61dd125UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xdcd86932c2befb7dUL, 0x2f7fd91b41e1b447UL) ]
        [ Q(0, 0x8000000000000000UL, 0xbeac6ccc41000000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fffffffffffffffUL, 0x803e666700000000UL); Fpsr 0x8000000UL ] ]
    check "4ea29020" []
      [ [ Q(0, 0xb8c21c033aaa4dc0UL, 0x2a801d89ae0d9dddUL) ]
        [ Q(0, 0x835472cea5a4918dUL, 0x33aca2b48fdc032bUL) ]
        [ Q(0, 0x3f003fff40000000UL, 0x3e4c6ccd40400000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xffa9a265cce00000UL) ] ]
    check "4e629020" []
      [ [ Q(0, 0xb8c10fc9c9fa4dc0UL, 0x2a80935057cd9dddUL) ]
        [ Q(0, 0x835429b26ed0918dUL, 0x33ac9d7a2be8032bUL) ]
        [ Q(0, 0x3eff40803f800000UL, 0x3e4c6ccd40400000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xffa908e000000000UL) ] ]

  /// C7.2.286 SQDMLSL, SQDMLSL2 (by element)
  [<TestMethod>]
  member _.``C7.2.286 SQDMLSL``() =
    check "0f527020" []
      [ [ Q(0, 0x80000000deb4022aUL, 0x194cb5ec0e76f729UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xaaf4e0c4200347d5UL, 0x538315ba0d16f2efUL) ]
        []
        [] ]
    check "0fa27020" []
      [ [ Q(0, 0xdab1da5ae341f24aUL, 0x7fffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x8000000000000000UL, 0x70d1aa68688d787UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x8000000000000000UL, 0x7fffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ] ]
    check "0ea2b020" []
      [ [ Q(0, 0x8000000000000000UL, 0x7fffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xaaf4b67fa1d4f2fdUL, 0x70d1aa68688d787UL) ]
        [ Q(0, 0xbfc000013f800000UL, 0x7fffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ] ]
    check "0e62b020" []
      [ [ Q(0, 0x80000000c8cabf1aUL, 0x7fffffff31f4bff1UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xaaf4e0c478b4f2fdUL, 0x70dec6ad13cd787UL) ]
        [ Q(0, 0xbfc000003f800000UL, 0x7fffffff40400000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ] ]

  /// C7.2.286 SQDMLSL, SQDMLSL2 (by element)
  [<TestMethod>]
  member _.``C7.2.286 SQDMLSL2``() =
    check "4f527020" []
      [ [ Q(0, 0x80000000cbafd816UL, 0x399c71c07fffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xaaf7a6c4233915b5UL, 0x3f21091a2777ec2fUL) ]
        []
        [] ]
    check "4fa27020" []
      [ [ Q(0, 0xc253b79e333c4f9eUL, 0x7fffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x8000000000000000UL, 0x5917bc5903951dd7UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3f0040013f000000UL, 0x7fffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xd989999a00000000UL, 0xffb1999900000000UL) ] ]
    check "4ea2b020" []
      [ [ Q(0, 0x8000000000000000UL, 0x7fffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xb1a0db79bc4f031dUL, 0x54eaf2bfb59acef3UL) ]
        [ Q(0, 0x8000000000000000UL, 0x3d4d2ccd40400000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ff0000000000000UL, 0x80465d9a33200000UL) ] ]
    check "4e62b020" []
      [ [ Q(0, 0x80000000c814c5b4UL, 0x7fffffff5c40bafdUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xb1a12496f323031dUL, 0x54eaf7fa198ecef3UL) ]
        [ Q(0, 0x800000003f800000UL, 0x3d4d2ccd40400000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ff0000000000000UL, 0x8046f72000000000UL) ] ]

  /// C7.2.288 SQDMULH (by element)
  [<TestMethod>]
  member _.``C7.2.288 SQDMULH``() =
    check "0f52c020" []
      [ [ Q(0, 0x4c604b903184ea53UL, 0x0UL) ]
        [ Q(0, 0xf0c815a4ef8510f6UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "4f52c020" []
      [ [ Q(0, 0x4c604b903184ea53UL, 0x2c10aa921fe8fd57UL) ]
        [ Q(0, 0xf0c815a4ef8510f6UL, 0x52afb43ef830dc0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "0fa2c020" []
      [ [ Q(0, 0x964ec5abbb793f0cUL, 0x0UL) ]
        [ Q(0, 0x3d3eb01342528b6dUL, 0x0UL) ]
        [ Q(0, 0x80ff7fff7f800001UL, 0x0UL) ]
        [ Q(0, 0xbff8000000000000UL, 0x0UL) ] ]
    check "4fa2c020" []
      [ [ Q(0, 0x964ec5abbb793f0cUL, 0xc30558f9d3d761c9UL) ]
        [ Q(0, 0x3d3eb01342528b6dUL, 0xeb340e61425dc20eUL) ]
        [ Q(0, 0x80ff7fff7f800001UL, 0x80df9fff80bfbfffUL) ]
        [ Q(0, 0xbff8000000000000UL, 0xc046666766666666UL) ] ]
    check "0e62b420" []
      [ [ Q(0, 0x964f28123184003cUL, 0x0UL) ]
        [ Q(0, 0x3d3d517eef85b844UL, 0x0UL) ]
        [ Q(0, 0x80fe000000000000UL, 0x0UL) ]
        [ Q(0, 0xbff8000000000000UL, 0x0UL) ] ]
    check "0ea2b420" []
      [ [ Q(0, 0x964ec5ab31858e0eUL, 0x0UL) ]
        [ Q(0, 0x3d3eb013ef85f0a4UL, 0x0UL) ]
        [ Q(0, 0x80ff7fffffffffffUL, 0x0UL) ]
        [ Q(0, 0xbff8000000000000UL, 0x0UL) ] ]
    check "4ea2b420" []
      [ [ Q(0, 0x964ec5ab31858e0eUL, 0xc4d33b212297029bUL) ]
        [ Q(0, 0x3d3eb013ef85f0a4UL, 0xef60d7fae8d9cbaaUL) ]
        [ Q(0, 0x80ff7fffffffffffUL, 0x7fa0007f403fffUL) ]
        [ Q(0, 0xbff8000000000000UL, 0x3fb1a26500000000UL) ] ]
    check "4e62b420" []
      [ [ Q(0, 0x964f28123184003cUL, 0xc4d3fdc6229500f2UL) ]
        [ Q(0, 0x3d3d517eef85b844UL, 0xef60092ce8d93dd6UL) ]
        [ Q(0, 0x80fe000000000000UL, 0x7f00007f3f0000UL) ]
        [ Q(0, 0xbff8000000000000UL, 0x3fb1000000000000UL) ] ]

  /// C7.2.290 SQDMULL, SQDMULL2 (by element)
  [<TestMethod>]
  member _.``C7.2.290 SQDMULL``() =
    check "0f52b020" []
      [ [ Q(0, 0x31846490ea538790UL, 0x4c602c7c4b903544UL) ]
        [ Q(0, 0xef85c66010f68280UL, 0xf0c8b50015a47620UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "0fa2b020" []
      [ [ Q(0, 0xbb793f0ce5c59770UL, 0x964ec5abadda6c7cUL) ]
        [ Q(0, 0x42528b6d4c4fb0a0UL, 0x3d3eb0139c329188UL) ]
        [ Q(0, 0x7f80000100000000UL, 0x80ff7fff01000000UL) ]
        [ Q(0, 0x0UL, 0xbff8000000000000UL) ] ]
    check "0ea2d020" []
      [ [ Q(0, 0x31858e0e62bccaa0UL, 0x964ec5abadda6c7cUL) ]
        [ Q(0, 0xef85f0a48f24d758UL, 0x3d3eb0139c329188UL) ]
        [ Q(0, 0xffffffff00000000UL, 0x80ff7fff01000000UL) ]
        [ Q(0, 0x0UL, 0xbff8000000000000UL) ] ]
    check "0e62d020" []
      [ [ Q(0, 0x31846490003ccaa0UL, 0x964f05bc28126c7cUL) ]
        [ Q(0, 0xef85c660b844d758UL, 0x3d3dde50517e9188UL) ]
        [ Q(0, 0x0UL, 0x80fe810000000000UL) ]
        [ Q(0, 0x0UL, 0xbff8000000000000UL) ] ]

  /// C7.2.290 SQDMULL, SQDMULL2 (by element)
  [<TestMethod>]
  member _.``C7.2.290 SQDMULL2``() =
    check "4f52b020" []
      [ [ Q(0, 0x1fe86e34fd57b1a4UL, 0x2c1070a8aa92fac8UL) ]
        [ Q(0, 0xef8300600dc0b4a0UL, 0x52ac1a0fb437ce0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "4fa2b020" []
      [ [ Q(0, 0xd3d761c995cb3a1cUL, 0xc30558f96c16a4b8UL) ]
        [ Q(0, 0x425dc20e91c53128UL, 0xeb340e611f264b38UL) ]
        [ Q(0, 0x80bfbfff00800000UL, 0x80df9fff00c00000UL) ]
        [ Q(0, 0x6666666600000000UL, 0xc046666700000000UL) ] ]
    check "4ea2d020" []
      [ [ Q(0, 0x2297029b71a2c406UL, 0xc4d33b2154067170UL) ]
        [ Q(0, 0xe8d9cbaa74aac738UL, 0xef60d7fa6d209a1cUL) ]
        [ Q(0, 0x7f403fff00800000UL, 0x7fa00000000000UL) ]
        [ Q(0, 0x0UL, 0x3fb1a265cce00000UL) ] ]
    check "4e62d020" []
      [ [ Q(0, 0x2295f66200f2c406UL, 0xc4d3b0e8fdc67170UL) ]
        [ Q(0, 0xe8d9828e3dd6c738UL, 0xef60d2c0092c9a1cUL) ]
        [ Q(0, 0x7f3f408000000000UL, 0x7fa00000000000UL) ]
        [ Q(0, 0x0UL, 0x3fb108e000000000UL) ] ]

  /// C7.2.292 SQNEG
  [<TestMethod>]
  member _.``C7.2.292 SQNEG``() =
    check "2e207820" []
      [ [ Q(0, 0x909f91d1b82420e4UL, 0x0UL) ]
        [ Q(0, 0xa9387ddba1f162dcUL, 0x0UL) ]
        [ Q(0, 0x817f00007f000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xc0f8000000000000UL, 0x0UL) ] ]
    check "6e207820" []
      [ [ Q(0, 0x909f91d1b82420e4UL, 0xc02a7eb2d20d04e9UL) ]
        [ Q(0, 0xa9387ddba1f162dcUL, 0x1ecfe5ada1e15057UL) ]
        [ Q(0, 0x817f00007f000000UL, 0x8160000081400000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xc0f8000000000000UL, 0xc147676767676766UL) ] ]
    check "2e607820" []
      [ [ Q(0, 0x8f9f90d1b7241fe4UL, 0x0UL) ]
        [ Q(0, 0xa8387cdba0f161dcUL, 0x0UL) ]
        [ Q(0, 0x808000007fff0000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xbff8000000000000UL, 0x0UL) ] ]
    check "6e607820" []
      [ [ Q(0, 0x8f9f90d1b7241fe4UL, 0xbf2a7db2d10d03e9UL) ]
        [ Q(0, 0xa8387cdba0f161dcUL, 0x1dcfe4ada0e14f57UL) ]
        [ Q(0, 0x808000007fff0000UL, 0x8060000080400000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xbff8000000000000UL, 0xc047666766676666UL) ] ]
    check "2ea07820" []
      [ [ Q(0, 0x8f9e90d1b7231fe4UL, 0x0UL) ]
        [ Q(0, 0xa8377cdba0f061dcUL, 0x0UL) ]
        [ Q(0, 0x808000007fffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xbff8000000000000UL, 0x0UL) ] ]
    check "6ee07820" []
      [ [ Q(0, 0x8f9e90d0b7231fe4UL, 0xbf297db1d10c03e9UL) ]
        [ Q(0, 0xa8377cdaa0f061dcUL, 0x1dcee4aca0e04f57UL) ]
        [ Q(0, 0x807fffff80000000UL, 0x805fffff80400000UL) ]
        [ Q(0, 0xbff8000000000000UL, 0xc046666666666666UL) ] ]
    check "6ea07820" []
      [ [ Q(0, 0x8f9e90d1b7231fe4UL, 0xbf297db2d10c03e9UL) ]
        [ Q(0, 0xa8377cdba0f061dcUL, 0x1dcee4ada0e04f57UL) ]
        [ Q(0, 0x808000007fffffffUL, 0x8060000080400000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xbff8000000000000UL, 0xc046666766666666UL) ] ]

  /// C7.2.293 SQRDMLAH (by element)
  [<TestMethod>]
  member _.``C7.2.293 SQRDMLAH``() =
    check "2f52d020" []
      [ [ Q(0, 0xe28b64f7fa8b8000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x8b43bcc8207fdb4cUL, 0x0UL) ]
        [ Q(0, 0xbfc000003f800000UL, 0x0UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ] ]
    check "6f52d020" []
      [ [ Q(0, 0xe28b64f7fa8b8000UL, 0x7fff8cfb79ef29c5UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x8b43bcc8207fdb4cUL, 0x4976c5fd123e76d0UL) ]
        []
        [] ]
    check "2fa2d020" []
      [ [ Q(0, 0x800000008480c8c7UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xd7b95738734c55c2UL, 0x0UL) ]
        [ Q(0, 0x800000007fffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffe8000000000000UL, 0x0UL) ] ]
    check "6fa2d020" []
      [ [ Q(0, 0x800000008480c8c7UL, 0x28b23b612dde8e37UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xd7b95738734c55c2UL, 0x2f7fd91b65192b1eUL) ]
        [ Q(0, 0x800000007fffffffUL, 0xbeac6cccc0ffbfffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffe8000000000000UL, 0x803e666766666666UL) ] ]
    check "2e428420" []
      [ [ Q(0, 0x80004179fa8b89f7UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xd7b8f8a3207f829aUL, 0x0UL) ]
        [ Q(0, 0x800000003f800000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffe8000000000000UL, 0x0UL) ] ]
    check "2e828420" []
      [ [ Q(0, 0x80000000fa8d17c8UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xd7b95738207fbafaUL, 0x0UL) ]
        [ Q(0, 0x800000003f7fffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffe8000000000000UL, 0x0UL) ] ]
    check "6e828420" []
      [ [ Q(0, 0x80000000fa8d17c8UL, 0x2a801d897c9e2f08UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xd7b95738207fbafaUL, 0x33aca2b40b9534b9UL) ]
        [ Q(0, 0x800000003f7fffffUL, 0x3e4c6ccd7fffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffe8000000000000UL, 0xffa9a26600000000UL) ] ]
    check "6e428420" []
      [ [ Q(0, 0x80004179fa8b89f7UL, 0x2a80e02e7c9d2d60UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xd7b8f8a3207f829aUL, 0x33acd3e70b957fffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x800000003f800000UL, 0x3e4ccccd7fff0000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffe8000000000000UL, 0xffa9000000000000UL) ] ]

  /// C7.2.295 SQRDMLSH (by element)
  [<TestMethod>]
  member _.``C7.2.295 SQRDMLSH``() =
    check "2f52f020" []
      [ [ Q(0, 0x8000cdd797839f66UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xa9b191804173b95eUL, 0x0UL) ]
        [ Q(0, 0xbfc000003f800000UL, 0x0UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ] ]
    check "6f52f020" []
      [ [ Q(0, 0x8000cdd797839f66UL, 0x399c37d53a1f2f15UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xa9b191804173b95eUL, 0x3f20cf7733385b4eUL) ]
        []
        [] ]
    check "2fa2f020" []
      [ [ Q(0, 0xffdc53bb0d8e4aadUL, 0x0UL) ]
        [ Q(0, 0x80000000eea73ee8UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ec08001bfffffffUL, 0x0UL) ]
        [ Q(0, 0x7ff8000000000000UL, 0x0UL) ] ]
    check "6fa2f020" []
      [ [ Q(0, 0xffdc53bb0d8e4aadUL, 0x7fffffff7fffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x80000000eea73ee8UL, 0x5917bc59e05da700UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ec08001bfffffffUL, 0x7fffffff7fffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7ff8000000000000UL, 0xffb199999999999aUL) ] ]
    check "2e428c20" []
      [ [ Q(0, 0xffdcf1559783897dUL, 0x0UL) ]
        [ Q(0, 0x8000800041731210UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ec100003f800000UL, 0x0UL) ]
        [ Q(0, 0x7ff8000000000000UL, 0x0UL) ] ]
    check "2e828c20" []
      [ [ Q(0, 0xffdc53bb9781fbacUL, 0x0UL) ]
        [ Q(0, 0x800000004173d9b0UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ec080013f800001UL, 0x0UL) ]
        [ Q(0, 0x7ff8000000000000UL, 0x0UL) ] ]
    check "6e828c20" []
      [ [ Q(0, 0xffdc53bb9781fbacUL, 0x7fffffff377029d2UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x800000004173d9b0UL, 0x54eaf2c039e19d65UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ec080013f800001UL, 0x3d4d2ccdc0ffc001UL) ]
        [ Q(0, 0x7ff8000000000000UL, 0x80465d9a00000000UL) ] ]
    check "6e428c20" []
      [ [ Q(0, 0xffdcf1559783897dUL, 0x7fffe4a237712b7aUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x8000800041731210UL, 0x54eac18d39e12b38UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ec100003f800000UL, 0x3d4ccccdc1010000UL) ]
        [ Q(0, 0x7ff8000000000000UL, 0x8047000000000000UL) ] ]

  /// C7.2.297 SQRDMULH (by element)
  [<TestMethod>]
  member _.``C7.2.297 SQRDMULH``() =
    check "0f52d020" []
      [ [ Q(0, 0x4c604b903184ea54UL, 0x0UL) ]
        [ Q(0, 0xf0c915a4ef8610f7UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "4f52d020" []
      [ [ Q(0, 0x4c604b903184ea54UL, 0x2c10aa931fe8fd58UL) ]
        [ Q(0, 0xf0c915a4ef8610f7UL, 0x52bfb43ef830dc1UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "0fa2d020" []
      [ [ Q(0, 0x964ec5acbb793f0dUL, 0x0UL) ]
        [ Q(0, 0x3d3eb01442528b6dUL, 0x0UL) ]
        [ Q(0, 0x80ff7fff7f800001UL, 0x0UL) ]
        [ Q(0, 0xbff8000000000000UL, 0x0UL) ] ]
    check "4fa2d020" []
      [ [ Q(0, 0x964ec5acbb793f0dUL, 0xc30558f9d3d761caUL) ]
        [ Q(0, 0x3d3eb01442528b6dUL, 0xeb340e61425dc20fUL) ]
        [ Q(0, 0x80ff7fff7f800001UL, 0x80df9fff80bfbfffUL) ]
        [ Q(0, 0xbff8000000000000UL, 0xc046666766666666UL) ] ]
    check "2e62b420" []
      [ [ Q(0, 0x964f28123184003dUL, 0x0UL) ]
        [ Q(0, 0x3d3e517fef86b845UL, 0x0UL) ]
        [ Q(0, 0x80ff000000000000UL, 0x0UL) ]
        [ Q(0, 0xbff8000000000000UL, 0x0UL) ] ]
    check "6e62b420" []
      [ [ Q(0, 0x964f28123184003dUL, 0xc4d4fdc6229600f3UL) ]
        [ Q(0, 0x3d3e517fef86b845UL, 0xef61092de8da3dd7UL) ]
        [ Q(0, 0x80ff000000000000UL, 0x8000007f3f0000UL) ]
        [ Q(0, 0xbff8000000000000UL, 0x3fb1000000000000UL) ] ]
    check "2ea2b420" []
      [ [ Q(0, 0x964ec5ac31858e0eUL, 0x0UL) ]
        [ Q(0, 0x3d3eb014ef85f0a5UL, 0x0UL) ]
        [ Q(0, 0x80ff7fffffffffffUL, 0x0UL) ]
        [ Q(0, 0xbff8000000000000UL, 0x0UL) ] ]
    check "6ea2b420" []
      [ [ Q(0, 0x964ec5ac31858e0eUL, 0xc4d33b212297029bUL) ]
        [ Q(0, 0x3d3eb014ef85f0a5UL, 0xef60d7fae8d9cbaaUL) ]
        [ Q(0, 0x80ff7fffffffffffUL, 0x7fa0007f403fffUL) ]
        [ Q(0, 0xbff8000000000000UL, 0x3fb1a26600000000UL) ] ]

  /// C7.2.299 SQRSHL
  [<TestMethod>]
  member _.``C7.2.299 SQRSHL``() =
    check "0e225c20" []
      [ [ Q(0, 0x7f7f7ff7f07fUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7f80007f00008000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x80000080000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x8000000000000UL, 0x0UL) ] ]
    check "4e225c20" []
      [ [ Q(0, 0x7f7f7ff7f07fUL, 0x80807f7f800000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7f80007f00008000UL, 0x807f7f0100000080UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x80000080000000UL, 0x7f0000007f800000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x8000000000000UL, 0x7f0099999999999aUL); Fpsr 0x8000000UL ] ]
    check "0e625c20" []
      [ [ Q(0, 0x7fff12378000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fff800000000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fff000080000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4e625c20" []
      [ [ Q(0, 0x7fff12378000UL, 0x7fff80007fff0000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fff800000000000UL, 0x8000006d00008000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fff000080000000UL, 0x7fff0000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x4008000000000000UL, 0x99999999999aUL) ] ]
    check "0ea25c20" []
      [ [ Q(0, 0x7fffffff7fffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fffffff00000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3fc0000080000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4ee25c20" []
      [ [ Q(0, 0x7fffffffffffffffUL, 0x81ad049c5de80UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x2be44UL, 0x8000000000000000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fffffffffffffffUL, 0x3fd000003fe00000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x4008000000000000UL, 0x3fb999999999999aUL) ] ]
    check "4ea25c20" []
      [ [ Q(0, 0x7fffffff7fffffffUL, 0x7fffffff0005de80UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fffffff00000000UL, 0xff88c46d7fffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3fc0000080000000UL, 0x7fa000003fe00000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x4008000000000000UL, 0x3fb999999999999aUL) ] ]

  /// C7.2.300 SQRSHRN, SQRSHRN2
  [<TestMethod>]
  member _.``C7.2.300 SQRSHRN``() =
    check "0f1f9c20" []
      [ [ Q(0, 0x7fff7fff7fff7fffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x80007fff7fff7fffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fff7fff7fff8000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fff80007fff0000UL, 0x0UL); Fpsr 0x8000000UL ] ]
    check "0f3f9c20" []
      [ [ Q(0, 0x7fffffff7fffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x800000007fffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fffffff7fffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fffffff7fffffffUL, 0x0UL); Fpsr 0x8000000UL ] ]
    check "0f0f9c20" []
      [ [ Q(0, 0x7f807f807f7f7f80UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x807f7f807f807f80UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7f007f007f008000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7f8080807f000000UL, 0x0UL); Fpsr 0x8000000UL ] ]

  /// C7.2.300 SQRSHRN, SQRSHRN2
  [<TestMethod>]
  member _.``C7.2.300 SQRSHRN2``() =
    check "4f1f9c20" []
      [ [ Q(0, 0x962b1967c90789baUL, 0x7fff7fff7fff7fffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0x80007fff7fff7fffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xbfc000003f800000UL, 0x7fff7fff7fff8000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ff0000000000000UL, 0x7fff80007fff0000UL); Fpsr 0x8000000UL ] ]
    check "4f3f9c20" []
      [ [ Q(0, 0x962b1967c90789baUL, 0x7fffffff7fffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0x800000007fffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xbfc000003f800000UL, 0x7fffffff7fffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ff0000000000000UL, 0x7fffffff7fffffffUL); Fpsr 0x8000000UL ] ]
    check "4f0f9c20" []
      [ [ Q(0, 0x962b1967c90789baUL, 0x7f807f807f7f7f80UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0x807f7f807f807f80UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xbfc000003f800000UL, 0x7f007f007f008000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ff0000000000000UL, 0x7f8080807f000000UL); Fpsr 0x8000000UL ] ]

  /// C7.2.301 SQRSHRUN, SQRSHRUN2
  [<TestMethod>]
  member _.``C7.2.301 SQRSHRUN``() =
    check "2f1f8c20" []
      [ [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffffff0000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffff0000ffff0000UL, 0x0UL); Fpsr 0x8000000UL ] ]
    check "2f3f8c20" []
      [ [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ] ]
    check "2f0f8c20" []
      [ [ Q(0, 0xff00ff00ffffff00UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffff00ff00ff00UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xff00ff00ff000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xff000000ff000000UL, 0x0UL); Fpsr 0x8000000UL ] ]

  /// C7.2.301 SQRSHRUN, SQRSHRUN2
  [<TestMethod>]
  member _.``C7.2.301 SQRSHRUN2``() =
    check "6f1f8c20" []
      [ [ Q(0, 0x962b1967c90789baUL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0xffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xbfc000003f800000UL, 0xffffffffffff0000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ff0000000000000UL, 0xffff0000ffff0000UL); Fpsr 0x8000000UL ] ]
    check "6f3f8c20" []
      [ [ Q(0, 0x962b1967c90789baUL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0xffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xbfc000003f800000UL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ff0000000000000UL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ] ]
    check "6f0f8c20" []
      [ [ Q(0, 0x962b1967c90789baUL, 0xff00ff00ffffff00UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0xffff00ff00ff00UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xbfc000003f800000UL, 0xff00ff00ff000000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ff0000000000000UL, 0xff000000ff000000UL); Fpsr 0x8000000UL ] ]

  /// C7.2.302 SQSHL (immediate)
  [<TestMethod>]
  member _.``C7.2.302 SQSHL``() =
    check "0f097420" []
      [ [ Q(0, 0x7f7f7f5e7fb8c038UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7f90804a7f1e8048UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7f80000080000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7f10000000000000UL, 0x0UL); Fpsr 0x8000000UL ] ]
    check "4f097420" []
      [ [ Q(0, 0x7f7f7f5e7fb8c038UL, 0x7fac807f5ce6f82eUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7f90804a7f1e8048UL, 0xc462367f7f3e8080UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7f80000080000000UL, 0x7f8000007f800000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7f10000000000000UL, 0x7e80808080808080UL); Fpsr 0x8000000UL ] ]
    check "0f117420" []
      [ [ Q(0, 0x7fff7fff7fffc038UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fff80007fff8000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fff000080000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fff000000000000UL, 0x0UL); Fpsr 0x8000000UL ] ]
    check "4f117420" []
      [ [ Q(0, 0x7fff7fff7fffc038UL, 0x7fff80005de6f82eUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fff80007fff8000UL, 0xc46236a67fff8000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fff000080000000UL, 0x7fff00007fff0000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fff000000000000UL, 0x7f72800080008000UL); Fpsr 0x8000000UL ] ]
    check "0f217420" []
      [ [ Q(0, 0x7fffffff7fffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fffffff7fffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fffffff80000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fffffff00000000UL, 0x0UL); Fpsr 0x8000000UL ] ]
    check "4f217420" []
      [ [ Q(0, 0x7fffffff7fffffffUL, 0x7fffffff5de7f82eUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fffffff7fffffffUL, 0xc46236a67fffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fffffff80000000UL, 0x7fffffff7fffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fffffff00000000UL, 0x7f73333280000000UL); Fpsr 0x8000000UL ] ]
    check "4f417420" []
      [ [ Q(0, 0x7fffffffffffffffUL, 0x7fffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fffffffffffffffUL, 0xc46236a6be3f6152UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fffffffffffffffUL, 0x7fffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fffffffffffffffUL, 0x7f73333333333334UL); Fpsr 0x8000000UL ] ]
    check "0e224c20" []
      [ [ Q(0, 0x7f7f7ff7f07fUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7f80ff7f00008000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x80000080000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x8000000000000UL, 0x0UL) ] ]
    check "4e224c20" []
      [ [ Q(0, 0x7f7f7ff7f07fUL, 0x80807f7f80ff00UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7f80ff7f00008000UL, 0x807f7f010000ff80UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x80000080000000UL, 0x7fff00007f800000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x8000000000000UL, 0x7fff99999999999aUL); Fpsr 0x8000000UL ] ]
    check "0e624c20" []
      [ [ Q(0, 0x7fff12378000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fff80000000ffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fff000080000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4e624c20" []
      [ [ Q(0, 0x7fff12378000UL, 0x7fff80007fffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fff80000000ffffUL, 0x8000006d00008000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fff000080000000UL, 0x7fff0000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x4008000000000000UL, 0x99999999999aUL) ] ]
    check "0ea24c20" []
      [ [ Q(0, 0x7fffffff7fffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fffffff00000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3fc0000080000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4ee24c20" []
      [ [ Q(0, 0x7fffffffffffffffUL, 0x81ad049c5de7fUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x2be44UL, 0x8000000000000000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fffffffffffffffUL, 0x3fd000003fe00000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x4008000000000000UL, 0x3fb999999999999aUL) ] ]
    check "4ea24c20" []
      [ [ Q(0, 0x7fffffff7fffffffUL, 0x7fffffff0005de7fUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fffffff00000000UL, 0xff88c46d7fffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3fc0000080000000UL, 0x7fa000003fe00000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x4008000000000000UL, 0x3fb999999999999aUL) ] ]

  /// C7.2.304 SQSHLU
  [<TestMethod>]
  member _.``C7.2.304 SQSHLU``() =
    check "2f096420" []
      [ [ Q(0, 0xe0c2de5e90000038UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xae00004abe1e0048UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xfe00000000000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x8010000000000000UL, 0x0UL) ] ]
    check "2f116420" []
      [ [ Q(0, 0xe0c2de5e91b80000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xaf900000be1e0000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xff00000000000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x8010000000000000UL, 0x0UL) ] ]
    check "6f116420" []
      [ [ Q(0, 0xe0c2de5e91b80000UL, 0x81ac00005de60000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xaf900000be1e0000UL, 0x36a6be3e0000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xff00000000000000UL, 0xff400000ff800000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x8010000000000000UL, 0x7f72000000000000UL); Fpsr 0x8000000UL ] ]
    check "2f216420" []
      [ [ Q(0, 0xe0c2de5e91b9c038UL, 0x0UL) ]
        [ Q(0, 0xaf91064abe1f3c48UL, 0x0UL) ]
        [ Q(0, 0xff00000000000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x8010000000000000UL, 0x0UL) ] ]
    check "6f216420" []
      [ [ Q(0, 0xe0c2de5e91b9c038UL, 0x81ad049c5de7f82eUL) ]
        [ Q(0, 0xaf91064abe1f3c48UL, 0xbe3f6152UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xff00000000000000UL, 0xff400000ff800000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x8010000000000000UL, 0x7f73333200000000UL); Fpsr 0x8000000UL ] ]
    check "6f416420" []
      [ [ Q(0, 0xe0c2de5e91b9c038UL, 0x81ad049c5de7f82eUL) ]
        [ Q(0, 0xaf91064abe1f3c48UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xff00000100000000UL, 0xff400000ff800000UL) ]
        [ Q(0, 0x8010000000000000UL, 0x7f73333333333334UL) ] ]
    check "6f096420" []
      [ [ Q(0, 0xe0c2de5e90000038UL, 0x8000009c5c00002eUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xae00004abe1e0048UL, 0x6236a6be3e0000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xfe00000000000000UL, 0xfe000000fe000000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x8010000000000000UL, 0x7e00000000000000UL); Fpsr 0x8000000UL ] ]

  /// C7.2.305 SQSHRN, SQSHRN2
  [<TestMethod>]
  member _.``C7.2.305 SQSHRN``() =
    check "0f0f9420" []
      [ [ Q(0, 0x7f807f807f7f7f80UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x807f7f807f807f80UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7f007f007f008000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7f8080807f000000UL, 0x0UL); Fpsr 0x8000000UL ] ]
    check "0f1f9420" []
      [ [ Q(0, 0x7fff7fff7fff7fffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x80007fff7fff7fffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fff7fff7fff8000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fff80007fff0000UL, 0x0UL); Fpsr 0x8000000UL ] ]
    check "0f3f9420" []
      [ [ Q(0, 0x7fffffff7fffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x800000007fffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fffffff7fffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fffffff7fffffffUL, 0x0UL); Fpsr 0x8000000UL ] ]
    check "0f1d9420" []
      [ [ Q(0, 0x7fff7fff7fff7fffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x80007fff7fff7fffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fff7fff7fff8000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fff80007fff0000UL, 0x0UL); Fpsr 0x8000000UL ] ]

  /// C7.2.305 SQSHRN, SQSHRN2
  [<TestMethod>]
  member _.``C7.2.305 SQSHRN2``() =
    check "4f1f9420" []
      [ [ Q(0, 0x962b1967c90789baUL, 0x7fff7fff7fff7fffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0x80007fff7fff7fffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xbfc000003f800000UL, 0x7fff7fff7fff8000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ff0000000000000UL, 0x7fff80007fff0000UL); Fpsr 0x8000000UL ] ]
    check "4f3f9420" []
      [ [ Q(0, 0x962b1967c90789baUL, 0x7fffffff7fffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0x800000007fffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xbfc000003f800000UL, 0x7fffffff7fffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ff0000000000000UL, 0x7fffffff7fffffffUL); Fpsr 0x8000000UL ] ]
    check "4f0f9420" []
      [ [ Q(0, 0x962b1967c90789baUL, 0x7f807f807f7f7f80UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0x807f7f807f807f80UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xbfc000003f800000UL, 0x7f007f007f008000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ff0000000000000UL, 0x7f8080807f000000UL); Fpsr 0x8000000UL ] ]

  /// C7.2.306 SQSHRUN, SQSHRUN2
  [<TestMethod>]
  member _.``C7.2.306 SQSHRUN``() =
    check "2f1f8420" []
      [ [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffffff0000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffff0000ffff0000UL, 0x0UL); Fpsr 0x8000000UL ] ]
    check "2f3f8420" []
      [ [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ] ]
    check "2f0f8420" []
      [ [ Q(0, 0xff00ff00ffffff00UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffff00ff00ff00UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xff00ff00ff000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xff000000ff000000UL, 0x0UL); Fpsr 0x8000000UL ] ]

  /// C7.2.306 SQSHRUN, SQSHRUN2
  [<TestMethod>]
  member _.``C7.2.306 SQSHRUN2``() =
    check "6f1f8420" []
      [ [ Q(0, 0x962b1967c90789baUL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0xffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xbfc000003f800000UL, 0xffffffffffff0000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ff0000000000000UL, 0xffff0000ffff0000UL); Fpsr 0x8000000UL ] ]
    check "6f3f8420" []
      [ [ Q(0, 0x962b1967c90789baUL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0xffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xbfc000003f800000UL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ff0000000000000UL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ] ]
    check "6f0f8420" []
      [ [ Q(0, 0x962b1967c90789baUL, 0xff00ff00ffffff00UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0xffff00ff00ff00UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xbfc000003f800000UL, 0xff00ff00ff000000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ff0000000000000UL, 0xff000000ff000000UL); Fpsr 0x8000000UL ] ]

  /// C7.2.307 SQSUB
  [<TestMethod>]
  member _.``C7.2.307 SQSUB``() =
    check "0e222c20" []
      [ [ Q(0, 0x7f7f410df2dee110UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xfe80d7b1763f8051UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7f800101800000ffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7f08000000000000UL, 0x0UL); Fpsr 0x8000000UL ] ]
    check "4e222c20" []
      [ [ Q(0, 0x7f7f410df2dee110UL, 0x7fa8800ad0a81c22UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xfe80d7b1763f8051UL, 0x9bd1f1597f461480UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7f800101800000ffUL, 0x7f20000000800101UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7f08000000000000UL, 0xc0c999999999999aUL); Fpsr 0x8000000UL ] ]
    check "0e622c20" []
      [ [ Q(0, 0x7fff410df1dee110UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xfe7bd6b1753f8000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fff00018000ffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fff000000000000UL, 0x0UL); Fpsr 0x8000000UL ] ]
    check "4e622c20" []
      [ [ Q(0, 0x7fff410df1dee110UL, 0x7fff800ad0a81b22UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xfe7bd6b1753f8000UL, 0x9ad1f0597e46146dUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fff00018000ffffUL, 0x7f20000000410001UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fff000000000000UL, 0xbfc999999999999aUL); Fpsr 0x8000000UL ] ]
    check "0ea22c20" []
      [ [ Q(0, 0x7ffffffff1dde110UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xfe7ad6b1753f4051UL, 0x0UL) ]
        [ Q(0, 0x7fffffff80000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fffffff00000000UL, 0x0UL); Fpsr 0x8000000UL ] ]
    check "4ee22c20" []
      [ [ Q(0, 0x7fffffffffffffffUL, 0x7fffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xfe7ad6b0753f4051UL, 0x9ad0f0587e46146dUL) ]
        [ Q(0, 0x7fffffffffffffffUL, 0x7f20000000400001UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fffffffffffffffUL, 0xbfc999999999999aUL); Fpsr 0x8000000UL ] ]
    check "4ea22c20" []
      [ [ Q(0, 0x7ffffffff1dde110UL, 0x7fffffffd0a81b22UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xfe7ad6b1753f4051UL, 0x9ad0f0597e46146dUL) ]
        [ Q(0, 0x7fffffff80000000UL, 0x7f20000000400001UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fffffff00000000UL, 0xbfc999999999999aUL); Fpsr 0x8000000UL ] ]

  /// C7.2.308 SQXTN, SQXTN2
  [<TestMethod>]
  member _.``C7.2.308 SQXTN``() =
    check "0e214820" []
      [ [ Q(0, 0x7f807f807f7f7f80UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x807f7f807f807f80UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7f007f007f008000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7f8080807f000000UL, 0x0UL); Fpsr 0x8000000UL ] ]
    check "0ea14820" []
      [ [ Q(0, 0x7fffffff7fffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x800000007fffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fffffff7fffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fffffff7fffffffUL, 0x0UL); Fpsr 0x8000000UL ] ]
    check "0e614820" []
      [ [ Q(0, 0x7fff7fff7fff7fffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x80007fff7fff7fffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fff7fff7fff8000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fff80007fff0000UL, 0x0UL); Fpsr 0x8000000UL ] ]

  /// C7.2.308 SQXTN, SQXTN2
  [<TestMethod>]
  member _.``C7.2.308 SQXTN2``() =
    check "4e614820" []
      [ [ Q(0, 0x962b1967c90789baUL, 0x7fff7fff7fff7fffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0x80007fff7fff7fffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xbfc000003f800000UL, 0x7fff7fff7fff8000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ff0000000000000UL, 0x7fff80007fff0000UL); Fpsr 0x8000000UL ] ]
    check "4ea14820" []
      [ [ Q(0, 0x962b1967c90789baUL, 0x7fffffff7fffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0x800000007fffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xbfc000003f800000UL, 0x7fffffff7fffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ff0000000000000UL, 0x7fffffff7fffffffUL); Fpsr 0x8000000UL ] ]
    check "4e214820" []
      [ [ Q(0, 0x962b1967c90789baUL, 0x7f807f807f7f7f80UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0x807f7f807f807f80UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xbfc000003f800000UL, 0x7f007f007f008000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ff0000000000000UL, 0x7f8080807f000000UL); Fpsr 0x8000000UL ] ]

  /// C7.2.309 SQXTUN, SQXTUN2
  [<TestMethod>]
  member _.``C7.2.309 SQXTUN``() =
    check "2e212820" []
      [ [ Q(0, 0xff00ff00ffffff00UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffff00ff00ff00UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xff00ff00ff000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xff000000ff000000UL, 0x0UL); Fpsr 0x8000000UL ] ]
    check "2ea12820" []
      [ [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ] ]
    check "2e612820" []
      [ [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffffff0000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffff0000ffff0000UL, 0x0UL); Fpsr 0x8000000UL ] ]

  /// C7.2.309 SQXTUN, SQXTUN2
  [<TestMethod>]
  member _.``C7.2.309 SQXTUN2``() =
    check "6e612820" []
      [ [ Q(0, 0x962b1967c90789baUL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0xffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xbfc000003f800000UL, 0xffffffffffff0000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ff0000000000000UL, 0xffff0000ffff0000UL); Fpsr 0x8000000UL ] ]
    check "6ea12820" []
      [ [ Q(0, 0x962b1967c90789baUL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0xffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xbfc000003f800000UL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ff0000000000000UL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ] ]
    check "6e212820" []
      [ [ Q(0, 0x962b1967c90789baUL, 0xff00ff00ffffff00UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0xffff00ff00ff00UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xbfc000003f800000UL, 0xff00ff00ff000000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ff0000000000000UL, 0xff000000ff000000UL); Fpsr 0x8000000UL ] ]

  /// C7.2.310 SRHADD
  [<TestMethod>]
  member _.``C7.2.310 SRHADD``() =
    check "0e221420" []
      [ [ Q(0, 0xfc004f294fedf014UL, 0x0UL) ]
        [ Q(0, 0x580b984d24f0fefcUL, 0x0UL) ]
        [ Q(0, 0xc0000001UL, 0x0UL) ]
        [ Q(0, 0xe004000000000000UL, 0x0UL) ] ]
    check "4e221420" []
      [ [ Q(0, 0xfc004f294fedf014UL, 0xe602c249461fee06UL) ]
        [ Q(0, 0x580b984d24f0fefcUL, 0x1549232720fca6f3UL) ]
        [ Q(0, 0xc0000001UL, 0x409000007f200000UL) ]
        [ Q(0, 0xe004000000000000UL, 0x5fd5cdcdcdcdcdcdUL) ] ]
    check "0e621420" []
      [ [ Q(0, 0xfc004ea94fedef94UL, 0x0UL) ]
        [ Q(0, 0x588b97cd2470fdfcUL, 0x0UL) ]
        [ Q(0, 0xc0000001UL, 0x0UL) ]
        [ Q(0, 0xe004000000000000UL, 0x0UL) ] ]
    check "4e621420" []
      [ [ Q(0, 0xfc004ea94fedef94UL, 0xe602c249469fee86UL) ]
        [ Q(0, 0x588b97cd2470fdfcUL, 0x14c923271ffca673UL) ]
        [ Q(0, 0xc0000001UL, 0x401000007fa00000UL) ]
        [ Q(0, 0xe004000000000000UL, 0x5fd5cccdcccdcccdUL) ] ]
    check "0ea21420" []
      [ [ Q(0, 0xfbffcea94fedef94UL, 0x0UL) ]
        [ Q(0, 0x588b17cd246ffdfcUL, 0x0UL) ]
        [ Q(0, 0xc0000001UL, 0x0UL) ]
        [ Q(0, 0xe004000000000000UL, 0x0UL) ] ]
    check "4ea21420" []
      [ [ Q(0, 0xfbffcea94fedef94UL, 0xe6024249469fee86UL) ]
        [ Q(0, 0x588b17cd246ffdfcUL, 0x14c8a3271ffca673UL) ]
        [ Q(0, 0xc0000001UL, 0x401000007fa00000UL) ]
        [ Q(0, 0xe004000000000000UL, 0x5fd4cccdcccccccdUL) ] ]

  /// C7.2.311 SRI
  [<TestMethod>]
  member _.``C7.2.311 SRI``() =
    check "2f0f4420" []
      [ [ Q(0, 0xb8303717a46ef08eUL, 0x0UL) ]
        [ Q(0, 0xab64c1122f87cf12UL, 0x0UL) ]
        [ Q(0, 0xbfc0000040800000UL, 0x0UL) ]
        [ Q(0, 0x2084000000000000UL, 0x0UL) ] ]
    check "6f0f4420" []
      [ [ Q(0, 0xb8303717a46ef08eUL, 0x20ebc12717797e0bUL) ]
        [ Q(0, 0xab64c1122f87cf12UL, 0x71188da92f8f5854UL) ]
        [ Q(0, 0xbfc0000040800000UL, 0x3fd080803f600000UL) ]
        [ Q(0, 0x2084000000000000UL, 0x9fdc4c4c4c4c4c4dUL) ] ]
    check "2f1f4420" []
      [ [ Q(0, 0xb8303797a46ef00eUL, 0x0UL) ]
        [ Q(0, 0xabe4c1922f87cf12UL, 0x0UL) ]
        [ Q(0, 0xbfc0000040000000UL, 0x0UL) ]
        [ Q(0, 0x2004000000000000UL, 0x0UL) ] ]
    check "6f1f4420" []
      [ [ Q(0, 0xb8303797a46ef00eUL, 0x206bc12717797e0bUL) ]
        [ Q(0, 0xabe4c1922f87cf12UL, 0x71188da92f8f5854UL) ]
        [ Q(0, 0xbfc0000040000000UL, 0x3fd080003fe00000UL) ]
        [ Q(0, 0x2004000000000000UL, 0x9fdc4ccc4ccc4ccdUL) ] ]
    check "2f3f4420" []
      [ [ Q(0, 0xb830b797a46e700eUL, 0x0UL) ]
        [ Q(0, 0xabe441922f87cf12UL, 0x0UL) ]
        [ Q(0, 0xbfc0000040000000UL, 0x0UL) ]
        [ Q(0, 0x2004000000000000UL, 0x0UL) ] ]
    check "6f3f4420" []
      [ [ Q(0, 0xb830b797a46e700eUL, 0x206b41271779fe0bUL) ]
        [ Q(0, 0xabe441922f87cf12UL, 0x71188da92f8fd854UL) ]
        [ Q(0, 0xbfc0000040000000UL, 0x3fd000003fe00000UL) ]
        [ Q(0, 0x2004000000000000UL, 0x9fdccccc4ccccccdUL) ] ]
    check "6f7f4420" []
      [ [ Q(0, 0xb830b797a46e700eUL, 0x206b41271779fe0bUL) ]
        [ Q(0, 0xabe44192af87cf12UL, 0x71188da9af8fd854UL) ]
        [ Q(0, 0xbfc0000040000000UL, 0x3fd000003fe00000UL) ]
        [ Q(0, 0x2004000000000000UL, 0x9fdccccccccccccdUL) ] ]
    check "6f3d4420" []
      [ [ Q(0, 0x8e0c2de5c91b9c03UL, 0x681ad04945de7f82UL) ]
        [ Q(0, 0x8af910642be1f3c4UL, 0x5c46236a2be3f615UL) ]
        [ Q(0, 0xaff0000030000000UL, 0x2ff400004ff80000UL) ]
        [ Q(0, 0x2801000000000000UL, 0xa7f7333313333333UL) ] ]

  /// C7.2.312 SRSHL
  [<TestMethod>]
  member _.``C7.2.312 SRSHL``() =
    check "0e225420" []
      [ [ Q(0, 0xf7f000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x80000000UL, 0x0UL) ]
        [ Q(0, 0x8000000000000UL, 0x0UL) ] ]
    check "0e625420" []
      [ [ Q(0, 0x1237c000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x80000000UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4e625420" []
      [ [ Q(0, 0x1237c000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x6d00000000UL) ]
        [ Q(0, 0x80000000UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x99999999999aUL) ] ]
    check "0ea25420" []
      [ [ Q(0, 0xce01c000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x3fc0000000000000UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4ea25420" []
      [ [ Q(0, 0xce01c000UL, 0x5de80UL) ]
        [ Q(0, 0x0UL, 0xff88c46d00000000UL) ]
        [ Q(0, 0x3fc0000000000000UL, 0x7fa000003fe00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fb999999999999aUL) ] ]
    check "4ee25420" []
      [ [ Q(0, 0x16f2f48dce01c000UL, 0x81ad049c5de80UL) ]
        [ Q(0, 0x2be44UL, 0x9000000000000000UL) ]
        [ Q(0, 0xff00000100000000UL, 0x3fd000003fe00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fb999999999999aUL) ] ]
    check "4e225420" []
      [ [ Q(0, 0xf7f000UL, 0x80000000000UL) ]
        [ Q(0, 0x0UL, 0x100000000UL) ]
        [ Q(0, 0x80000000UL, 0x7f00000000000000UL) ]
        [ Q(0, 0x8000000000000UL, 0x99999999999aUL) ] ]

  /// C7.2.313 SRSHR
  [<TestMethod>]
  member _.``C7.2.313 SRSHR``() =
    check "0f0f2420" []
      [ [ Q(0, 0x3831381824eef00eUL, 0x0UL) ]
        [ Q(0, 0x2ce4c2133008cf12UL, 0x0UL) ]
        [ Q(0, 0x40c00000c0000000UL, 0x0UL) ]
        [ Q(0, 0x2004000000000000UL, 0x0UL) ] ]
    check "4f0f2420" []
      [ [ Q(0, 0x3831381824eef00eUL, 0x20ebc12717fafe0cUL) ]
        [ Q(0, 0x2ce4c2133008cf12UL, 0xf1190e2a3010d8d5UL) ]
        [ Q(0, 0x40c00000c0000000UL, 0x40d0000040e00000UL) ]
        [ Q(0, 0x2004000000000000UL, 0x20ddcdcdcdcdcdcdUL) ] ]
    check "0f1f2420" []
      [ [ Q(0, 0x38313798246ef00eUL, 0x0UL) ]
        [ Q(0, 0x2be4c1932f88cf12UL, 0x0UL) ]
        [ Q(0, 0x3fc00000c0000000UL, 0x0UL) ]
        [ Q(0, 0x2004000000000000UL, 0x0UL) ] ]
    check "4f1f2420" []
      [ [ Q(0, 0x38313798246ef00eUL, 0x206bc127177afe0cUL) ]
        [ Q(0, 0x2be4c1932f88cf12UL, 0xf1190daa2f90d855UL) ]
        [ Q(0, 0x3fc00000c0000000UL, 0x3fd000003fe00000UL) ]
        [ Q(0, 0x2004000000000000UL, 0x1fddcccdcccdcccdUL) ] ]
    check "0f3f2420" []
      [ [ Q(0, 0x3830b798246e700eUL, 0x0UL) ]
        [ Q(0, 0x2be441932f87cf12UL, 0x0UL) ]
        [ Q(0, 0x3fc00000c0000000UL, 0x0UL) ]
        [ Q(0, 0x2004000000000000UL, 0x0UL) ] ]
    check "4f3f2420" []
      [ [ Q(0, 0x3830b798246e700eUL, 0x206b41271779fe0cUL) ]
        [ Q(0, 0x2be441932f87cf12UL, 0xf1188daa2f8fd855UL) ]
        [ Q(0, 0x3fc00000c0000000UL, 0x3fd000003fe00000UL) ]
        [ Q(0, 0x2004000000000000UL, 0x1fdccccdcccccccdUL) ] ]
    check "4f7f2420" []
      [ [ Q(0, 0x3830b797a46e700eUL, 0x206b41271779fe0cUL) ]
        [ Q(0, 0x2be44192af87cf12UL, 0xf1188da9af8fd855UL) ]
        [ Q(0, 0x3fc0000040000000UL, 0x3fd000003fe00000UL) ]
        [ Q(0, 0x2004000000000000UL, 0x1fdccccccccccccdUL) ] ]
    check "4f3d2420" []
      [ [ Q(0, 0xe0c2de6091b9c04UL, 0x81ad04a05de7f83UL) ]
        [ Q(0, 0xaf910650be1f3c5UL, 0xfc46236a0be3f615UL) ]
        [ Q(0, 0xff00000f0000000UL, 0xff400000ff80000UL) ]
        [ Q(0, 0x801000000000000UL, 0x7f73333f3333333UL) ] ]

  /// C7.2.314 SRSRA
  [<TestMethod>]
  member _.``C7.2.314 SRSRA``() =
    check "0f0f3420" []
      [ [ Q(0, 0xce5c517fedf579c8UL, 0x0UL) ]
        [ Q(0, 0xc65e693760019967UL, 0x0UL) ]
        [ Q(0, 0xff800000ff800000UL, 0x0UL) ]
        [ Q(0, 0x5ff4000000000000UL, 0x0UL) ] ]
    check "4f0f3420" []
      [ [ Q(0, 0xce5c517fedf579c8UL, 0x8597a38f71012a79UL) ]
        [ Q(0, 0xc65e693760019967UL, 0x3564d8e452cb41e4UL) ]
        [ Q(0, 0xff800000ff800000UL, 0x7d9ccccd80200000UL) ]
        [ Q(0, 0x5ff4000000000000UL, 0xdfd5cdcdcdcdcdcdUL) ] ]
    check "0f1f3420" []
      [ [ Q(0, 0xce5c50ffed7579c8UL, 0x0UL) ]
        [ Q(0, 0xc65e68b760819967UL, 0x0UL) ]
        [ Q(0, 0xff800000ff800000UL, 0x0UL) ]
        [ Q(0, 0x5ff4000000000000UL, 0x0UL) ] ]
    check "4f1f3420" []
      [ [ Q(0, 0xce5c50ffed7579c8UL, 0x8617a38f71812a79UL) ]
        [ Q(0, 0xc65e68b760819967UL, 0x3564d864524b4164UL) ]
        [ Q(0, 0xff800000ff800000UL, 0x7d9ccccd80200000UL) ]
        [ Q(0, 0x5ff4000000000000UL, 0xdfd5cccdcccdcccdUL) ] ]
    check "0f3f3420" []
      [ [ Q(0, 0xce5bd0ffed75f9c8UL, 0x0UL) ]
        [ Q(0, 0xc65ee8b760819967UL, 0x0UL) ]
        [ Q(0, 0xff800000ff800000UL, 0x0UL) ]
        [ Q(0, 0x5ff4000000000000UL, 0x0UL) ] ]
    check "4f3f3420" []
      [ [ Q(0, 0xce5bd0ffed75f9c8UL, 0x8618238f71812a79UL) ]
        [ Q(0, 0xc65ee8b760819967UL, 0x35645864524b4164UL) ]
        [ Q(0, 0xff800000ff800000UL, 0x7d9ccccd80200000UL) ]
        [ Q(0, 0x5ff4000000000000UL, 0xdfd4cccdcccccccdUL) ] ]
    check "4f7f3420" []
      [ [ Q(0, 0xce5bd0ff6d75f9c8UL, 0x8618238f71812a79UL) ]
        [ Q(0, 0xc65ee8b6e0819967UL, 0x35645863d24b4164UL) ]
        [ Q(0, 0xff8000007f800000UL, 0x7d9ccccd80200000UL) ]
        [ Q(0, 0x5ff4000000000000UL, 0xdfd4cccccccccccdUL) ] ]
    check "4f3d3420" []
      [ [ Q(0, 0xa437474dd22325beUL, 0x6dc7b2b25fe5abf0UL) ]
        [ Q(0, 0xa573b7893cdbbe1aUL, 0x4091ee242e9f5f24UL) ]
        [ Q(0, 0xcfb000002f800000UL, 0x4dc0cccd50380000UL) ]
        [ Q(0, 0x47f1000000000000UL, 0xc7ef3333f3333333UL) ] ]

  /// C7.2.315 SSHL
  [<TestMethod>]
  member _.``C7.2.315 SSHL``() =
    check "0e224420" []
      [ [ Q(0, 0xf7f000UL, 0x0UL) ]
        [ Q(0, 0xff0000000000UL, 0x0UL) ]
        [ Q(0, 0x80000000UL, 0x0UL) ]
        [ Q(0, 0x8000000000000UL, 0x0UL) ] ]
    check "0e624420" []
      [ [ Q(0, 0x1237c000UL, 0x0UL) ]
        [ Q(0, 0xffffUL, 0x0UL) ]
        [ Q(0, 0x80000000UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4e624420" []
      [ [ Q(0, 0x1237c000UL, 0xffffUL) ]
        [ Q(0, 0xffffUL, 0x6d00000000UL) ]
        [ Q(0, 0x80000000UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x99999999999aUL) ] ]
    check "0ea24420" []
      [ [ Q(0, 0xce01c000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x3fc0000000000000UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "4ea24420" []
      [ [ Q(0, 0xce01c000UL, 0x5de7fUL) ]
        [ Q(0, 0x0UL, 0xff88c46d00000000UL) ]
        [ Q(0, 0x3fc0000000000000UL, 0x7fa000003fe00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fb999999999999aUL) ] ]
    check "4ee24420" []
      [ [ Q(0, 0x16f2f48dce01c000UL, 0x81ad049c5de7fUL) ]
        [ Q(0, 0x2be44UL, 0x9000000000000000UL) ]
        [ Q(0, 0xff00000100000000UL, 0x3fd000003fe00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fb999999999999aUL) ] ]
    check "4e224420" []
      [ [ Q(0, 0xf7f000UL, 0x8000000ff00UL) ]
        [ Q(0, 0xff0000000000UL, 0x10000ff00UL) ]
        [ Q(0, 0x80000000UL, 0x7fff000000000000UL) ]
        [ Q(0, 0x8000000000000UL, 0xff99999999999aUL) ] ]

  /// C7.2.316 SSHLL, SSHLL2
  [<TestMethod>]
  member _.``C7.2.316 SSHLL``() =
    check "0f11a420" []
      [ [ Q(0, 0x91b8ffffc038UL, 0xe0c20000de5eUL) ]
        [ Q(0, 0xbe1effff3c48UL, 0xaf90ffff064aUL) ]
        [ Q(0, 0xffff000000000000UL, 0xff0000000000UL) ]
        [ Q(0, 0x0UL, 0x801000000000UL) ] ]
    check "0f10a420" []
      [ [ Q(0, 0x48dcffffe01cUL, 0x706100006f2fUL) ]
        [ Q(0, 0x5f0fffff9e24UL, 0x57c8ffff8325UL) ]
        [ Q(0, 0xffff800000000000UL, 0x7f8000000000UL) ]
        [ Q(0, 0x0UL, 0x400800000000UL) ] ]
    check "0f09a420" []
      [ [ Q(0, 0x90ffb8ffc00038UL, 0xe000c200de005eUL) ]
        [ Q(0, 0xbe001eff3c0048UL, 0xaeff90ff06004aUL) ]
        [ Q(0, 0xff00000000000000UL, 0xfeff0000000000UL) ]
        [ Q(0, 0x0UL, 0x80001000000000UL) ] ]
    check "0f21a420" []
      [ [ Q(0, 0x91b9c038UL, 0xe0c2de5eUL) ]
        [ Q(0, 0xbe1f3c48UL, 0xaf91064aUL) ]
        [ Q(0, 0xffffffff00000000UL, 0xff000000UL) ]
        [ Q(0, 0x0UL, 0x80100000UL) ] ]
    check "0f08a420" []
      [ [ Q(0, 0x48ffdcffe0001cUL, 0x700061006f002fUL) ]
        [ Q(0, 0x5f000fff9e0024UL, 0x57ffc8ff830025UL) ]
        [ Q(0, 0xff80000000000000UL, 0x7fff8000000000UL) ]
        [ Q(0, 0x0UL, 0x40000800000000UL) ] ]
    check "0f20a420" []
      [ [ Q(0, 0x48dce01cUL, 0x70616f2fUL) ]
        [ Q(0, 0x5f0f9e24UL, 0x57c88325UL) ]
        [ Q(0, 0xffffffff80000000UL, 0x7f800000UL) ]
        [ Q(0, 0x0UL, 0x40080000UL) ] ]

  /// C7.2.316 SSHLL, SSHLL2
  [<TestMethod>]
  member _.``C7.2.316 SSHLL2``() =
    check "4f09a420" []
      [ [ Q(0, 0x5cffe6fff8002eUL, 0x80ffacff04009cUL) ]
        [ Q(0, 0xbe003eff60ff52UL, 0xffc40062003600a6UL) ]
        [ Q(0, 0xfeff8000000000UL, 0xfeff4000000000UL) ]
        [ Q(0, 0xff32ff32ff32ff34UL, 0x7eff72ff32ff32UL) ] ]
    check "4f11a420" []
      [ [ Q(0, 0x5de6fffff82eUL, 0x81acffff049cUL) ]
        [ Q(0, 0xbe3effff6152UL, 0xffffc462000036a6UL) ]
        [ Q(0, 0xff8000000000UL, 0xff4000000000UL) ]
        [ Q(0, 0xffff3332ffff3334UL, 0x7f72ffff3332UL) ] ]
    check "4f21a420" []
      [ [ Q(0, 0x5de7f82eUL, 0x81ad049cUL) ]
        [ Q(0, 0xbe3f6152UL, 0xffffffffc46236a6UL) ]
        [ Q(0, 0xff800000UL, 0xff400000UL) ]
        [ Q(0, 0xffffffff33333334UL, 0x7f733332UL) ] ]
    check "4f08a420" []
      [ [ Q(0, 0x2efff3fffc0017UL, 0x40ffd6ff82004eUL) ]
        [ Q(0, 0x5f001fffb0ffa9UL, 0xffe20031001b0053UL) ]
        [ Q(0, 0x7fffc000000000UL, 0x7fffa000000000UL) ]
        [ Q(0, 0xff99ff99ff99ff9aUL, 0x3fffb9ff99ff99UL) ] ]
    check "4f20a420" []
      [ [ Q(0, 0x2ef3fc17UL, 0x40d6824eUL) ]
        [ Q(0, 0x5f1fb0a9UL, 0xffffffffe2311b53UL) ]
        [ Q(0, 0x7fc00000UL, 0x7fa00000UL) ]
        [ Q(0, 0xffffffff9999999aUL, 0x3fb99999UL) ] ]
    check "4f15a420" []
      [ [ Q(0, 0x5de60ffff82e0UL, 0x81ac0fff049c0UL) ]
        [ Q(0, 0xbe3e0fff61520UL, 0xfffc462000036a60UL) ]
        [ Q(0, 0xff80000000000UL, 0xff40000000000UL) ]
        [ Q(0, 0xfff33320fff33340UL, 0x7f720fff33320UL) ] ]
    check "4f10a420" []
      [ [ Q(0, 0x2ef3fffffc17UL, 0x40d6ffff824eUL) ]
        [ Q(0, 0x5f1fffffb0a9UL, 0xffffe23100001b53UL) ]
        [ Q(0, 0x7fc000000000UL, 0x7fa000000000UL) ]
        [ Q(0, 0xffff9999ffff999aUL, 0x3fb9ffff9999UL) ] ]

  /// C7.2.317 SSHR
  [<TestMethod>]
  member _.``C7.2.317 SSHR``() =
    check "0f0f0420" []
      [ [ Q(0, 0x3830371724eef00eUL, 0x0UL) ]
        [ Q(0, 0x2be4c1122f07cf12UL, 0x0UL) ]
        [ Q(0, 0x3fc00000c0000000UL, 0x0UL) ]
        [ Q(0, 0x2004000000000000UL, 0x0UL) ] ]
    check "0f1f0420" []
      [ [ Q(0, 0x38303797246ef00eUL, 0x0UL) ]
        [ Q(0, 0x2be4c1922f87cf12UL, 0x0UL) ]
        [ Q(0, 0x3fc00000c0000000UL, 0x0UL) ]
        [ Q(0, 0x2004000000000000UL, 0x0UL) ] ]
    check "4f1f0420" []
      [ [ Q(0, 0x38303797246ef00eUL, 0x206bc1271779fe0bUL) ]
        [ Q(0, 0x2be4c1922f87cf12UL, 0xf1180da92f8fd854UL) ]
        [ Q(0, 0x3fc00000c0000000UL, 0x3fd000003fe00000UL) ]
        [ Q(0, 0x2004000000000000UL, 0x1fdccccccccccccdUL) ] ]
    check "0f3f0420" []
      [ [ Q(0, 0x3830b797246e700eUL, 0x0UL) ]
        [ Q(0, 0x2be441922f87cf12UL, 0x0UL) ]
        [ Q(0, 0x3fc00000c0000000UL, 0x0UL) ]
        [ Q(0, 0x2004000000000000UL, 0x0UL) ] ]
    check "4f3f0420" []
      [ [ Q(0, 0x3830b797246e700eUL, 0x206b41271779fe0bUL) ]
        [ Q(0, 0x2be441922f87cf12UL, 0xf1188da92f8fd854UL) ]
        [ Q(0, 0x3fc00000c0000000UL, 0x3fd000003fe00000UL) ]
        [ Q(0, 0x2004000000000000UL, 0x1fdccccccccccccdUL) ] ]
    check "4f7f0420" []
      [ [ Q(0, 0x3830b797a46e700eUL, 0x206b41271779fe0bUL) ]
        [ Q(0, 0x2be44192af87cf12UL, 0xf1188da9af8fd854UL) ]
        [ Q(0, 0x3fc0000040000000UL, 0x3fd000003fe00000UL) ]
        [ Q(0, 0x2004000000000000UL, 0x1fdccccccccccccdUL) ] ]
    check "4f0f0420" []
      [ [ Q(0, 0x3830371724eef00eUL, 0x20ebc12717f9fe0bUL) ]
        [ Q(0, 0x2be4c1122f07cf12UL, 0xf1180d292f0fd8d4UL) ]
        [ Q(0, 0x3fc00000c0000000UL, 0x3fd000003fe00000UL) ]
        [ Q(0, 0x2004000000000000UL, 0x1fdccccccccccccdUL) ] ]

  /// C7.2.318 SSRA
  [<TestMethod>]
  member _.``C7.2.318 SSRA``() =
    check "0f0f1420" []
      [ [ Q(0, 0xce5b507eedf579c8UL, 0x0UL) ]
        [ Q(0, 0xc55e68365f009967UL, 0x0UL) ]
        [ Q(0, 0xfe800000ff800000UL, 0x0UL) ]
        [ Q(0, 0x5ff4000000000000UL, 0x0UL) ] ]
    check "0f1f1420" []
      [ [ Q(0, 0xce5b50feed7579c8UL, 0x0UL) ]
        [ Q(0, 0xc65e68b660809967UL, 0x0UL) ]
        [ Q(0, 0xff800000ff800000UL, 0x0UL) ]
        [ Q(0, 0x5ff4000000000000UL, 0x0UL) ] ]
    check "4f1f1420" []
      [ [ Q(0, 0xce5b50feed7579c8UL, 0x8617a38f71802a78UL) ]
        [ Q(0, 0xc65e68b660809967UL, 0x3563d863524a4163UL) ]
        [ Q(0, 0xff800000ff800000UL, 0x7d9ccccd80200000UL) ]
        [ Q(0, 0x5ff4000000000000UL, 0xdfd4cccccccccccdUL) ] ]
    check "0f3f1420" []
      [ [ Q(0, 0xce5bd0feed75f9c8UL, 0x0UL) ]
        [ Q(0, 0xc65ee8b660819967UL, 0x0UL) ]
        [ Q(0, 0xff800000ff800000UL, 0x0UL) ]
        [ Q(0, 0x5ff4000000000000UL, 0x0UL) ] ]
    check "4f3f1420" []
      [ [ Q(0, 0xce5bd0feed75f9c8UL, 0x8618238f71812a78UL) ]
        [ Q(0, 0xc65ee8b660819967UL, 0x35645863524b4163UL) ]
        [ Q(0, 0xff800000ff800000UL, 0x7d9ccccd80200000UL) ]
        [ Q(0, 0x5ff4000000000000UL, 0xdfd4cccccccccccdUL) ] ]
    check "4f7f1420" []
      [ [ Q(0, 0xce5bd0ff6d75f9c8UL, 0x8618238f71812a78UL) ]
        [ Q(0, 0xc65ee8b6e0819967UL, 0x35645863d24b4163UL) ]
        [ Q(0, 0xff8000007f800000UL, 0x7d9ccccd80200000UL) ]
        [ Q(0, 0x5ff4000000000000UL, 0xdfd4cccccccccccdUL) ] ]
    check "4f0f1420" []
      [ [ Q(0, 0xce5b507eedf579c8UL, 0x8597a38f71002a78UL) ]
        [ Q(0, 0xc55e68365f009967UL, 0x3563d7e351ca41e3UL) ]
        [ Q(0, 0xfe800000ff800000UL, 0x7c9ccccd7f200000UL) ]
        [ Q(0, 0x5ff4000000000000UL, 0xded4cccccccccccdUL) ] ]

  /// C7.2.319 SSUBL, SSUBL2
  [<TestMethod>]
  member _.``C7.2.319 SSUBL``() =
    check "0e622020" []
      [ [ Q(0, 0xfffff1deffffe110UL, 0xe8c30000410dUL) ]
        [ Q(0, 0x753fffff4051UL, 0xfffffe7bffffd6b1UL) ]
        [ Q(0, 0xffff8000ffffffffUL, 0xff0100000001UL) ]
        [ Q(0, 0x0UL, 0xc00800000000UL) ] ]
    check "0e222020" []
      [ [ Q(0, 0xfff2ffdeffe10010UL, 0xe900c30041000dUL) ]
        [ Q(0, 0x76003fff410051UL, 0xfffeff7bffd7ffb1UL) ]
        [ Q(0, 0xff8000000000ffffUL, 0xffff0100010001UL) ]
        [ Q(0, 0x0UL, 0xc0000800000000UL) ] ]
    check "0ea22020" []
      [ [ Q(0, 0xfffffffff1dde110UL, 0xe8c3410dUL) ]
        [ Q(0, 0x753f4051UL, 0xfffffffffe7ad6b1UL) ]
        [ Q(0, 0xffffffff7fffffffUL, 0xff000001UL) ]
        [ Q(0, 0x0UL, 0xc0080000UL) ] ]

  /// C7.2.319 SSUBL, SSUBL2
  [<TestMethod>]
  member _.``C7.2.319 SSUBL2``() =
    check "4e222020" []
      [ [ Q(0, 0xffd0ffa8001c0022UL, 0xb5ffa8ff80000aUL) ]
        [ Q(0, 0x7f00460014ff6dUL, 0xff9bffd1fff10059UL) ]
        [ Q(0, 0xff4100010001UL, 0x7f002000000000UL) ]
        [ Q(0, 0xff99ff99ff99ff9aUL, 0xffc0ffc9ff99ff99UL) ] ]
    check "4ea22020" []
      [ [ Q(0, 0xffffffffd0a81b22UL, 0xb5a8800aUL) ]
        [ Q(0, 0x7e46146dUL, 0xffffffff9ad0f059UL) ]
        [ Q(0, 0x400001UL, 0x7f200000UL) ]
        [ Q(0, 0xffffffff9999999aUL, 0xffffffffbfc99999UL) ] ]
    check "4e622020" []
      [ [ Q(0, 0xffffd0a800001b22UL, 0xb5a8ffff800aUL) ]
        [ Q(0, 0x7e460000146dUL, 0xffff9ad1fffff059UL) ]
        [ Q(0, 0x4100000001UL, 0x7f2000000000UL) ]
        [ Q(0, 0xffff9999ffff999aUL, 0xffffbfc9ffff9999UL) ] ]

  /// C7.2.320 SSUBW, SSUBW2
  [<TestMethod>]
  member _.``C7.2.320 SSUBW``() =
    check "0e623020" []
      [ [ Q(0, 0x7061183148dce110UL, 0x40d6fab02ef3cdf5UL) ]
        [ Q(0, 0x57c899555f0f4051UL, 0xe230c2065f200435UL) ]
        [ Q(0, 0x7f8000007fffffffUL, 0x7fa07f817fc00001UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fba19999999999aUL) ] ]
    check "0e223020" []
      [ [ Q(0, 0x700b6f3148dde010UL, 0x414f82b02ec5fbf5UL) ]
        [ Q(0, 0x57df83555eb29e51UL, 0xe1d81b065f73b035UL) ]
        [ Q(0, 0x7f8000008000ffffUL, 0x8020ff817fc10001UL) ]
        [ Q(0, 0x4008000000000000UL, 0x403999999999999aUL) ] ]
    check "0ea23020" []
      [ [ Q(0, 0x70616f2ef1dde110UL, 0x40d6824ea755cdf5UL) ]
        [ Q(0, 0x57c88325753f4051UL, 0xe2311b5305d20435UL) ]
        [ Q(0, 0x7f8000007fffffffUL, 0x7fa00000ff400001UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fb9999a1999999aUL) ] ]

  /// C7.2.320 SSUBW, SSUBW2
  [<TestMethod>]
  member _.``C7.2.320 SSUBW2``() =
    check "4e223020" []
      [ [ Q(0, 0x70036ee448fce027UL, 0x414b82202ef1fbd3UL) ]
        [ Q(0, 0x57e8834c5f739de8UL, 0xe1ea1af35ef5b0afUL) ]
        [ Q(0, 0x7f01ff8180010001UL, 0x7fa000807fc00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3f3a99a99999999aUL) ] ]
    check "4ea23020" []
      [ [ Q(0, 0x70616f2eea90ff27UL, 0x40d6824ea3c5f9d3UL) ]
        [ Q(0, 0x57c883257e3601e8UL, 0xe2311b5317bf85afUL) ]
        [ Q(0, 0x7f80000000800001UL, 0x7fa000007f400000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fb9999919a9999aUL) ] ]
    check "4e623020" []
      [ [ Q(0, 0x706110e448dcff27UL, 0x40d6f7202ef3f9d3UL) ]
        [ Q(0, 0x57c8a24c5f1001e8UL, 0xe230d3f35f1f85afUL) ]
        [ Q(0, 0x7f7f808180000001UL, 0x7f9fff807fc00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fb919a99999999aUL) ] ]

  /// C7.2.321 ST1 (multiple structures)
  [<TestMethod>]
  member _.``C7.2.321 ST1``() =
    check "4c007020" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0x962b1967c90789baUL); M(8, 0x65ace2685a072c6dUL) ]
        [ M(0, 0x9a7aa72430f9ca55UL); M(8, 0x444bcaba22bb690fUL) ]
        [ M(0, 0xbfc000003f800000UL); M(8, 0x3dcccccd40400000UL) ]
        [ M(0, 0x3ff0000000000000UL); M(8, 0xbff8000000000000UL) ] ]

  /// C7.2.323 ST2 (multiple structures)
  [<TestMethod>]
  member _.``C7.2.323 ST2``() =
    check "4c008020" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0x48c9dc07e0891cbaUL)
          M(8, 0x7096612b6f192f67UL)
          M(16, 0x2e5af307fc2c176dUL)
          M(24, 0x4065d6ac82e24e68UL) ]
        [ M(0, 0x5f300ff99eca2455UL)
          M(8, 0x579ac87a83a72524UL)
          M(16, 0x5f221fbbb069a90fUL)
          M(24, 0xe244314b1bca53baUL) ]
        [ M(0, 0x803f008000000000UL)
          M(8, 0x7fbf80c000000000UL)
          M(16, 0x7f40c04000000000UL)
          M(24, 0x7f3da0cc00cc00cdUL) ]
        [ M(0, 0x0UL)
          M(8, 0x403f08f000000000UL)
          M(16, 0x9900990099009a00UL)
          M(24, 0x3fbfb9f899009900UL) ] ]

  /// C7.2.325 ST3 (multiple structures)
  [<TestMethod>]
  member _.``C7.2.325 ST3``() =
    check "4c004020" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0xdc07ffe0890c1cbaUL)
          M(8, 0x19222f675648c9feUL)
          M(16, 0x8770969e612b2e6fUL)
          M(24, 0xf307e0fc2cf5176dUL)
          M(32, 0xe2444e685e2e5a4bUL)
          M(40, 0x8b40652ed6ac0282UL) ]
        [ M(0, 0xff95d9ecad32455UL)
          M(8, 0xa7742524e95f30d0UL)
          M(16, 0x59579a4dc87aac83UL)
          M(24, 0x1fbb9cb0693ca90fUL)
          M(32, 0xcafa53bae05f22d9UL)
          M(40, 0x47e24460314b2a1bUL) ]
        [ M(0, 0x80000000010000UL)
          M(8, 0xff000000803f00UL)
          M(16, 0x807fbf7f80c0ff00UL)
          M(24, 0xc040ff0000ff0000UL)
          M(32, 0xcc0000cd7f7f407fUL)
          M(40, 0x7f3d80a0cc0000UL) ]
        [ M(0, 0x0UL)
          M(8, 0x0UL)
          M(16, 0x80403f0008f00000UL)
          M(24, 0x9900009900009a00UL)
          M(32, 0x990000990000UL)
          M(40, 0x7f3fbff0b9f80099UL) ] ]

  /// C7.2.327 ST4 (multiple structures)
  [<TestMethod>]
  member _.``C7.2.327 ST4``() =
    check "4c000020" [ X(1, 0x2008000UL) ]
      [ [ M(0, 0x53ffe089c10c1cbaUL)
          M(8, 0x5648c935fedc07UL)
          M(16, 0x592e6f19bb222f67UL)
          M(24, 0xbf8770968c9e612bUL)
          M(32, 0x9de0fc2c18f5176dUL)
          M(40, 0x965e2e5aeb4bf307UL)
          M(48, 0xa40282e2b2444e68UL)
          M(56, 0xd18b40656a2ed6acUL) ]
        [ M(0, 0xf75d9ecad1d32455UL)
          M(8, 0x86e95f301ad00ff9UL)
          M(16, 0xdeac83a79d742524UL)
          M(24, 0x259579abd4dc87aUL)
          M(32, 0xc39cb069473ca90fUL)
          M(40, 0x17e05f221cd91fbbUL)
          M(48, 0xa72a1bcafafa53baUL)
          M(56, 0xe647e244ef60314bUL) ]
        [ M(0, 0x2000000f9010000UL)
          M(8, 0x5000803f15000080UL)
          M(16, 0xff000000ff0000UL)
          M(24, 0xc0807fbfe87f80c0UL)
          M(32, 0xff000000ff0000UL)
          M(40, 0x3f7f7f40007fc040UL)
          M(48, 0xcc000000cdUL)
          M(56, 0x42007f3dc880a0ccUL) ]
        [ M(0, 0x0UL)
          M(8, 0x0UL)
          M(16, 0x0UL)
          M(24, 0x7f80403ff80008f0UL)
          M(32, 0x990000009a00UL)
          M(40, 0x990000009900UL)
          M(48, 0x990000009900UL)
          M(56, 0x7f7f3fbff4f0b9f8UL) ] ]

  /// C7.2.335 SUBHN, SUBHN2
  [<TestMethod>]
  member _.``C7.2.335 SUBHN``() =
    check "0e626020" []
      [ [ Q(0, 0xb5a8d0a8e8c3f1ddUL, 0x0UL) ]
        [ Q(0, 0x9ad07e46fe7a753fUL, 0x0UL) ]
        [ Q(0, 0x7f200040ff007fffUL, 0x0UL) ]
        [ Q(0, 0xbfc99999c0080000UL, 0x0UL) ] ]
    check "0ea26020" []
      [ [ Q(0, 0xb5a88009e8c3410cUL, 0x0UL) ]
        [ Q(0, 0x9ad0f058fe7ad6b0UL, 0x0UL) ]
        [ Q(0, 0x7f200000ff000001UL, 0x0UL) ]
        [ Q(0, 0xbfc99999c0080000UL, 0x0UL) ] ]
    check "0e226020" []
      [ [ Q(0, 0xb580d01be841f1e1UL, 0x0UL) ]
        [ Q(0, 0x9af07e14fed67540UL, 0x0UL) ]
        [ Q(0, 0x7f000000ff0080ffUL, 0x0UL) ]
        [ Q(0, 0xbf999999c0000000UL, 0x0UL) ] ]

  /// C7.2.335 SUBHN, SUBHN2
  [<TestMethod>]
  member _.``C7.2.335 SUBHN2``() =
    check "4e626020" []
      [ [ Q(0, 0x962b1967c90789baUL, 0xb5a8d0a8e8c3f1ddUL) ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0x9ad07e46fe7a753fUL) ]
        [ Q(0, 0xbfc000003f800000UL, 0x7f200040ff007fffUL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xbfc99999c0080000UL) ] ]
    check "4ea26020" []
      [ [ Q(0, 0x962b1967c90789baUL, 0xb5a88009e8c3410cUL) ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0x9ad0f058fe7ad6b0UL) ]
        [ Q(0, 0xbfc000003f800000UL, 0x7f200000ff000001UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xbfc99999c0080000UL) ] ]
    check "4e226020" []
      [ [ Q(0, 0x962b1967c90789baUL, 0xb580d01be841f1e1UL) ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0x9af07e14fed67540UL) ]
        [ Q(0, 0xbfc000003f800000UL, 0x7f000000ff0080ffUL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xbf999999c0000000UL) ] ]

  /// C7.2.336 SUDOT (by element)
  [<TestMethod>]
  member _.``C7.2.336 SUDOT``() =
    check "4f02f020" []
      [ [ Q(0, 0x962c100ac9075fa2UL, 0x65ac54625a072c13UL) ]
        [ Q(0, 0x9a7ab9e930fa270eUL, 0x444c257422bb73f1UL) ]
        []
        [] ]

  /// C7.2.337 SUQADD
  [<TestMethod>]
  member _.``C7.2.337 SUQADD``() =
    check "0e203820" []
      [ [ Q(0, 0x67f7f7f117f69d6UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xf17f2a497f086879UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3e4000007f800000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7ff8000000000000UL, 0x0UL) ] ]
    check "4e203820" []
      [ [ Q(0, 0x67f7f7f117f69d6UL, 0x7f7f647f7f7f7f7fUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xf17f2a497f086879UL, 0x7f7ce50d7fda7f7fUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3e4000007f800000UL, 0x7f6ccccd7f7f0000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7ff8000000000000UL, 0xfe7f7f7f7f7f7f7fUL); Fpsr 0x8000000UL ] ]
    check "0e603820" []
      [ [ Q(0, 0x68c7fff11e369d6UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xf2422a497fff6879UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3f4000007fff0000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7ff8000000000000UL, 0x0UL) ] ]
    check "4e603820" []
      [ [ Q(0, 0x68c7fff11e369d6UL, 0x7fff64b67fff7fffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xf2422a497fff6879UL, 0x7fffe60d7fff7fffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3f4000007fff0000UL, 0x7fffcccd7fff0000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7ff8000000000000UL, 0xffb17fff7fff7fffUL); Fpsr 0x8000000UL ] ]
    check "0ea03820" []
      [ [ Q(0, 0x68c889611e469d6UL, 0x0UL) ]
        [ Q(0, 0xf2432a497fffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3f4000007fffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7ff8000000000000UL, 0x0UL) ] ]
    check "4ee03820" []
      [ [ Q(0, 0x68c889711e469d6UL, 0x7fffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xf2432a4990096879UL, 0x7fffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3f400000bf800000UL, 0x7fffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7ff8000000000000UL, 0xffb199999999999aUL) ] ]
    check "4ea03820" []
      [ [ Q(0, 0x68c889611e469d6UL, 0x7fffffff7fffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xf2432a497fffffffUL, 0x7fffffff7fffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3f4000007fffffffUL, 0x7fffffff7fffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7ff8000000000000UL, 0xffb199997fffffffUL); Fpsr 0x8000000UL ] ]

  /// C7.2.338 SXTL, SXTL2
  [<TestMethod>]
  member _.``C7.2.338 SXTL``() =
    check "0f10a420" []
      [ [ Q(0, 0x48dcffffe01cUL, 0x706100006f2fUL) ]
        [ Q(0, 0x5f0fffff9e24UL, 0x57c8ffff8325UL) ]
        [ Q(0, 0xffff800000000000UL, 0x7f8000000000UL) ]
        [ Q(0, 0x0UL, 0x400800000000UL) ] ]
    check "0f08a420" []
      [ [ Q(0, 0x48ffdcffe0001cUL, 0x700061006f002fUL) ]
        [ Q(0, 0x5f000fff9e0024UL, 0x57ffc8ff830025UL) ]
        [ Q(0, 0xff80000000000000UL, 0x7fff8000000000UL) ]
        [ Q(0, 0x0UL, 0x40000800000000UL) ] ]
    check "0f20a420" []
      [ [ Q(0, 0x48dce01cUL, 0x70616f2fUL) ]
        [ Q(0, 0x5f0f9e24UL, 0x57c88325UL) ]
        [ Q(0, 0xffffffff80000000UL, 0x7f800000UL) ]
        [ Q(0, 0x0UL, 0x40080000UL) ] ]

  /// C7.2.338 SXTL, SXTL2
  [<TestMethod>]
  member _.``C7.2.338 SXTL2``() =
    check "4f08a420" []
      [ [ Q(0, 0x2efff3fffc0017UL, 0x40ffd6ff82004eUL) ]
        [ Q(0, 0x5f001fffb0ffa9UL, 0xffe20031001b0053UL) ]
        [ Q(0, 0x7fffc000000000UL, 0x7fffa000000000UL) ]
        [ Q(0, 0xff99ff99ff99ff9aUL, 0x3fffb9ff99ff99UL) ] ]
    check "4f20a420" []
      [ [ Q(0, 0x2ef3fc17UL, 0x40d6824eUL) ]
        [ Q(0, 0x5f1fb0a9UL, 0xffffffffe2311b53UL) ]
        [ Q(0, 0x7fc00000UL, 0x7fa00000UL) ]
        [ Q(0, 0xffffffff9999999aUL, 0x3fb99999UL) ] ]
    check "4f10a420" []
      [ [ Q(0, 0x2ef3fffffc17UL, 0x40d6ffff824eUL) ]
        [ Q(0, 0x5f1fffffb0a9UL, 0xffffe23100001b53UL) ]
        [ Q(0, 0x7fc000000000UL, 0x7fa000000000UL) ]
        [ Q(0, 0xffff9999ffff999aUL, 0x3fb9ffff9999UL) ] ]

  /// C7.2.339 TBL
  [<TestMethod>]
  member _.``C7.2.339 TBL``() =
    check "0e020020" []
      [ [ Q(0, 0x4eUL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]

  /// C7.2.340 TBX
  [<TestMethod>]
  member _.``C7.2.340 TBX``() =
    check "0e021020" []
      [ [ Q(0, 0x962b1967c907894eUL, 0x0UL) ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0x0UL) ]
        [ Q(0, 0xbfc0000000000000UL, 0x0UL) ]
        [ Q(0, 0x3f00000000000000UL, 0x0UL) ] ]

  /// C7.2.341 TRN1
  [<TestMethod>]
  member _.``C7.2.341 TRN1``() =
    check "0e022820" []
      [ [ Q(0, 0x9e61222ffedc0c1cUL, 0x0UL) ]
        [ Q(0, 0x4dc87425d00fd324UL, 0x0UL) ]
        [ Q(0, 0x7f80ff0000000100UL, 0x0UL) ]
        [ Q(0, 0x8000000000000UL, 0x0UL) ] ]
    check "4e022820" []
      [ [ Q(0, 0x9e61222ffedc0c1cUL, 0x2ed6444e4bf3f517UL) ]
        [ Q(0, 0x4dc87425d00fd324UL, 0x6031fa53d91f3ca9UL) ]
        [ Q(0, 0x7f80ff0000000100UL, 0x80a000007fc0ff00UL) ]
        [ Q(0, 0x8000000000000UL, 0xf0b900990099009aUL) ] ]
    check "0e422820" []
      [ [ Q(0, 0x2e226f2fff0ce01cUL, 0x0UL) ]
        [ Q(0, 0xac7483255dd39e24UL, 0x0UL) ]
        [ Q(0, 0xffff000000010000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "4e422820" []
      [ [ Q(0, 0x2e226f2fff0ce01cUL, 0x244824ee0f5fc17UL) ]
        [ Q(0, 0xac7483255dd39e24UL, 0x2afa1b539c3cb0a9UL) ]
        [ Q(0, 0xffff000000010000UL, 0xffff0000UL) ]
        [ Q(0, 0x0UL, 0x99990000999aUL) ] ]
    check "0e822820" []
      [ [ Q(0, 0x56feff0c48dce01cUL, 0x0UL) ]
        [ Q(0, 0xe9d05dd35f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x180000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "4ec22820" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x879e2e2256feff0cUL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x594dac74e9d05dd3UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x807fffff00000001UL) ]
        [ Q(0, 0x4008000000000000UL, 0x8000000000000000UL) ] ]
    check "4e822820" []
      [ [ Q(0, 0x56feff0c48dce01cUL, 0x5e4be0f52ef3fc17UL) ]
        [ Q(0, 0xe9d05dd35f0f9e24UL, 0xe0d99c3c5f1fb0a9UL) ]
        [ Q(0, 0x180000000UL, 0x7f7fffff7fc00000UL) ]
        [ Q(0, 0x0UL, 0x9999999aUL) ] ]

  /// C7.2.342 TRN2
  [<TestMethod>]
  member _.``C7.2.342 TRN2``() =
    check "0e026820" []
      [ [ Q(0, 0x87702e6f5648ffe0UL, 0x0UL) ]
        [ Q(0, 0x5957ac83e95f5d9eUL, 0x0UL) ]
        [ Q(0, 0x807fff0000800000UL, 0x0UL) ]
        [ Q(0, 0x8040000000000000UL, 0x0UL) ] ]
    check "4e026820" []
      [ [ Q(0, 0x87702e6f5648ffe0UL, 0x8b4002825e2ee0fcUL) ]
        [ Q(0, 0x5957ac83e95f5d9eUL, 0x47e22a1be05f9cb0UL) ]
        [ Q(0, 0x807fff0000800000UL, 0x7f00007f7fff00UL) ]
        [ Q(0, 0x8040000000000000UL, 0x7f3f009900990099UL) ] ]
    check "0e426820" []
      [ [ Q(0, 0x879e706156fe48dcUL, 0x0UL) ]
        [ Q(0, 0x594d57c8e9d05f0fUL, 0x0UL) ]
        [ Q(0, 0x807f7f8000008000UL, 0x0UL) ]
        [ Q(0, 0x8000400800000000UL, 0x0UL) ] ]
    check "4e426820" []
      [ [ Q(0, 0x879e706156fe48dcUL, 0x8b2e40d65e4b2ef3UL) ]
        [ Q(0, 0x594d57c8e9d05f0fUL, 0x4760e231e0d95f1fUL) ]
        [ Q(0, 0x807f7f8000008000UL, 0x807fa07f7f7fc0UL) ]
        [ Q(0, 0x8000400800000000UL, 0x7ff03fb900009999UL) ] ]
    check "0e826820" []
      [ [ Q(0, 0x879e2e2270616f2fUL, 0x0UL) ]
        [ Q(0, 0x594dac7457c88325UL, 0x0UL) ]
        [ Q(0, 0x807fffff7f800000UL, 0x0UL) ]
        [ Q(0, 0x8000000040080000UL, 0x0UL) ] ]
    check "4ec26820" []
      [ [ Q(0, 0x40d6824e2ef3fc17UL, 0x8b2e02445e4be0f5UL) ]
        [ Q(0, 0xe2311b535f1fb0a9UL, 0x47602afae0d99c3cUL) ]
        [ Q(0, 0x7fa000007fc00000UL, 0x8000007f7fffffUL) ]
        [ Q(0, 0x3fb999999999999aUL, 0x7ff0000000000000UL) ] ]
    check "4e826820" []
      [ [ Q(0, 0x879e2e2270616f2fUL, 0x8b2e024440d6824eUL) ]
        [ Q(0, 0x594dac7457c88325UL, 0x47602afae2311b53UL) ]
        [ Q(0, 0x807fffff7f800000UL, 0x8000007fa00000UL) ]
        [ Q(0, 0x8000000040080000UL, 0x7ff000003fb99999UL) ] ]

  /// C7.2.343 UABA
  [<TestMethod>]
  member _.``C7.2.343 UABA``() =
    check "2e227c20" []
      [ [ Q(0, 0xad685a74d729a8caUL, 0x0UL) ]
        [ Q(0, 0x9cf5d073baba0b04UL, 0x0UL) ]
        [ Q(0, 0xc0c1ffffbf800001UL, 0x0UL) ]
        [ Q(0, 0x7ff8000000000000UL, 0x0UL) ] ]
    check "6e227c20" []
      [ [ Q(0, 0xad685a74d729a8caUL, 0xb05462728aaf484bUL) ]
        [ Q(0, 0x9cf5d073baba0b04UL, 0xdf7ad961a3757d7cUL) ]
        [ Q(0, 0xc0c1ffffbf800001UL, 0xbceccccd4081ffffUL) ]
        [ Q(0, 0x7ff8000000000000UL, 0xff2f99999999999aUL) ] ]
    check "2e627c20" []
      [ [ Q(0, 0xad685a74d729a8aaUL, 0x0UL) ]
        [ Q(0, 0x9bffd073bbba0aa6UL, 0x0UL) ]
        [ Q(0, 0xc0bfffffbf800001UL, 0x0UL) ]
        [ Q(0, 0x7fe8000000000000UL, 0x0UL) ] ]
    check "6e627c20" []
      [ [ Q(0, 0xad685a74d729a8aaUL, 0xb0046272895f478fUL) ]
        [ Q(0, 0x9bffd073bbba0aa6UL, 0xdf1cda61a4757d7cUL) ]
        [ Q(0, 0xc0bfffffbf800001UL, 0xbceccccd4081ffffUL) ]
        [ Q(0, 0x7fe8000000000000UL, 0x2f99999999999aUL) ] ]
    check "2ea27c20" []
      [ [ Q(0, 0xad67d85ad729a8aaUL, 0x0UL) ]
        [ Q(0, 0x9bffd073bbba8a04UL, 0x0UL) ]
        [ Q(0, 0xc0bfffffbf7fffffUL, 0x0UL) ]
        [ Q(0, 0x7fe8000000000000UL, 0x0UL) ] ]
    check "6ea27c20" []
      [ [ Q(0, 0xad67d85ad729a8aaUL, 0xb004625e895f114bUL) ]
        [ Q(0, 0x9bffd073bbba8a04UL, 0xdf1cbb13a47554a2UL) ]
        [ Q(0, 0xc0bfffffbf7fffffUL, 0xbceccccd40800001UL) ]
        [ Q(0, 0x7fe8000000000000UL, 0x2e66679999999aUL) ] ]

  /// C7.2.344 UABAL, UABAL2
  [<TestMethod>]
  member _.``C7.2.344 UABAL``() =
    check "2e625020" []
      [ [ Q(0, 0x962b2789c907a8aaUL, 0x65acf9a55a076d7aUL) ]
        [ Q(0, 0x9a7b31e530fa0aa6UL, 0x444bcc3f22bb925eUL) ]
        [ Q(0, 0xbfc080003f800001UL, 0x3dcccdcc4040ffffUL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xbff83ff800000000UL) ] ]
    check "2e225020" []
      [ [ Q(0, 0x96391989c92689caUL, 0x65c3e2a55a482c7aUL) ]
        [ Q(0, 0x9b04a7e5313acb04UL, 0x444dcb3522e4695eUL) ]
        [ Q(0, 0xc04000003f800001UL, 0x3dcdccce413f00ffUL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xc038000800000000UL) ] ]
    check "2ea25020" []
      [ [ Q(0, 0x962b1967d729a8aaUL, 0x65ace2687143eb60UL) ]
        [ Q(0, 0x9a7aa724bbba8a04UL, 0x444bcaba2440925eUL) ]
        [ Q(0, 0xbfc00000bf7fffffUL, 0x3dcccccd413fffffUL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xbff800003ff80000UL) ] ]

  /// C7.2.344 UABAL, UABAL2
  [<TestMethod>]
  member _.``C7.2.344 UABAL2``() =
    check "6e225020" []
      [ [ Q(0, 0x965b1a0fc9238a98UL, 0x65f7e3105a872c77UL) ]
        [ Q(0, 0x9afba7de310dcac2UL, 0x44e6cae922ca69b6UL) ]
        [ Q(0, 0xbfc00041407f00ffUL, 0x3e4bcced40400000UL) ]
        [ Q(0, 0x408900990099009aUL, 0xc038003700990099UL) ] ]
    check "6ea25020" []
      [ [ Q(0, 0x962b1967f85f6e98UL, 0x65ace268a45eac63UL) ]
        [ Q(0, 0x9a7aa724b2b3b5e8UL, 0x444bcababd8c5968UL) ]
        [ Q(0, 0xbfc000003fc00001UL, 0x3dcccccdbf600000UL) ]
        [ Q(0, 0x3ff000009999999aUL, 0xbff8000040366667UL) ] ]
    check "6e625020" []
      [ [ Q(0, 0x962b48bfc907a4dcUL, 0x65ad2cc05a07ac77UL) ]
        [ Q(0, 0x9a7b28de30f9dec2UL, 0x444c658b22bb78b6UL) ]
        [ Q(0, 0xbfc000413f80ffffUL, 0x3dcd4bed40400000UL) ]
        [ Q(0, 0x3ff099990000999aUL, 0xbff8403700009999UL) ] ]

  /// C7.2.345 UABD
  [<TestMethod>]
  member _.``C7.2.345 UABD``() =
    check "2e227420" []
      [ [ Q(0, 0x173d410d0e221f10UL, 0x0UL) ]
        [ Q(0, 0x27b294f8ac141afUL, 0x0UL) ]
        [ Q(0, 0x101ffff80000001UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "6e227420" []
      [ [ Q(0, 0x173d410d0e221f10UL, 0x4ba8800a30a81cdeUL) ]
        [ Q(0, 0x27b294f8ac141afUL, 0x9b2f0fa781ba146dUL) ]
        [ Q(0, 0x101ffff80000001UL, 0x7f2000000041ffffUL) ]
        [ Q(0, 0x4008000000000000UL, 0x403799999999999aUL) ] ]
    check "2e627420" []
      [ [ Q(0, 0x173d410d0e221ef0UL, 0x0UL) ]
        [ Q(0, 0x185294f8ac14051UL, 0x0UL) ]
        [ Q(0, 0xffffff80000001UL, 0x0UL) ]
        [ Q(0, 0x3ff8000000000000UL, 0x0UL) ] ]
    check "6e627420" []
      [ [ Q(0, 0x173d410d0e221ef0UL, 0x4a58800a2f581b22UL) ]
        [ Q(0, 0x185294f8ac14051UL, 0x9ad10fa781ba146dUL) ]
        [ Q(0, 0xffffff80000001UL, 0x7f2000000041ffffUL) ]
        [ Q(0, 0x3ff8000000000000UL, 0x403799999999999aUL) ] ]
    check "2ea27420" []
      [ [ Q(0, 0x173cbef30e221ef0UL, 0x0UL) ]
        [ Q(0, 0x185294f8ac0bfafUL, 0x0UL) ]
        [ Q(0, 0xffffff7fffffffUL, 0x0UL) ]
        [ Q(0, 0x3ff8000000000000UL, 0x0UL) ] ]
    check "6ea27420" []
      [ [ Q(0, 0x173cbef30e221ef0UL, 0x4a577ff62f57e4deUL) ]
        [ Q(0, 0x185294f8ac0bfafUL, 0x9ad0f05981b9eb93UL) ]
        [ Q(0, 0xffffff7fffffffUL, 0x7f20000000400001UL) ]
        [ Q(0, 0x3ff8000000000000UL, 0x403666679999999aUL) ] ]

  /// C7.2.346 UABDL, UABDL2
  [<TestMethod>]
  member _.``C7.2.346 UABDL``() =
    check "2e627020" []
      [ [ Q(0, 0xe2200001ef0UL, 0x173d0000410dUL) ]
        [ Q(0, 0x8ac100004051UL, 0x1850000294fUL) ]
        [ Q(0, 0x800000000001UL, 0xff0000ffffUL) ]
        [ Q(0, 0x0UL, 0x3ff800000000UL) ] ]
    check "2e227020" []
      [ [ Q(0, 0xe0022001f0010UL, 0x17003d0041000dUL) ]
        [ Q(0, 0x8a00c1004100afUL, 0x2007b0029004fUL) ]
        [ Q(0, 0x80000000000001UL, 0x1000100ff00ffUL) ]
        [ Q(0, 0x0UL, 0x40000800000000UL) ] ]
    check "2ea27020" []
      [ [ Q(0, 0xe221ef0UL, 0x173cbef3UL) ]
        [ Q(0, 0x8ac0bfafUL, 0x185294fUL) ]
        [ Q(0, 0x7fffffffUL, 0xffffffUL) ]
        [ Q(0, 0x0UL, 0x3ff80000UL) ] ]

  /// C7.2.346 UABDL, UABDL2
  [<TestMethod>]
  member _.``C7.2.346 UABDL2``() =
    check "6e227020" []
      [ [ Q(0, 0x3000a8001c00deUL, 0x4b00a80080000aUL) ]
        [ Q(0, 0x8100ba0014006dUL, 0x9b002f000f00a7UL) ]
        [ Q(0, 0x4100ff00ffUL, 0x7f002000000000UL) ]
        [ Q(0, 0x9900990099009aUL, 0x40003700990099UL) ] ]
    check "6ea27020" []
      [ [ Q(0, 0x2f57e4deUL, 0x4a577ff6UL) ]
        [ Q(0, 0x81b9eb93UL, 0x9ad0f059UL) ]
        [ Q(0, 0x400001UL, 0x7f200000UL) ]
        [ Q(0, 0x9999999aUL, 0x40366667UL) ] ]
    check "6e627020" []
      [ [ Q(0, 0x2f5800001b22UL, 0x4a580000800aUL) ]
        [ Q(0, 0x81ba0000146dUL, 0x9ad100000fa7UL) ]
        [ Q(0, 0x410000ffffUL, 0x7f2000000000UL) ]
        [ Q(0, 0x99990000999aUL, 0x403700009999UL) ] ]

  /// C7.2.347 UADALP
  [<TestMethod>]
  member _.``C7.2.347 UADALP``() =
    check "2e206820" []
      [ [ Q(0, 0x96fc1a05ca2b8ab6UL, 0x0UL) ]
        [ Q(0, 0x9b99a7cc3167cb17UL, 0x0UL) ]
        [ Q(0, 0xc0bf000040000000UL, 0x0UL) ]
        [ Q(0, 0x4038000000000000UL, 0x0UL) ] ]
    check "6e206820" []
      [ [ Q(0, 0x96fc1a05ca2b8ab6UL, 0x66c2e3385b282d80UL) ]
        [ Q(0, 0x9b99a7cc3167cb17UL, 0x455ecb2823396a68UL) ]
        [ Q(0, 0xc0bf000040000000UL, 0x3eebcccd417f0000UL) ]
        [ Q(0, 0x4038000000000000UL, 0xc0f0013201320133UL) ] ]
    check "2e606820" []
      [ [ Q(0, 0x962bf8f7c908b2b2UL, 0x0UL) ]
        [ Q(0, 0x9a7b821130fac788UL, 0x0UL) ]
        [ Q(0, 0xbfc07f803f808000UL, 0x0UL) ]
        [ Q(0, 0x3ff0400800000000UL, 0x0UL) ] ]
    check "6ea06820" []
      [ [ Q(0, 0x962b19688245d905UL, 0x65ace268c9d1aad2UL) ]
        [ Q(0, 0x9a7aa724e7d1eb9eUL, 0x444bcabb640c350bUL) ]
        [ Q(0, 0xbfc000013f000000UL, 0x3dccccce3fa00000UL) ]
        [ Q(0, 0x3ff0000040080000UL, 0xbff80000d9533333UL) ] ]
    check "6e606820" []
      [ [ Q(0, 0x962bf8f7c908b2b2UL, 0x65ada58c5a085777UL) ]
        [ Q(0, 0x9a7b821130fac788UL, 0x444cc83e22bc78d7UL) ]
        [ Q(0, 0xbfc07f803f808000UL, 0x3dcd4c6d40407fc0UL) ]
        [ Q(0, 0x3ff0400800000000UL, 0xbff8d95200013333UL) ] ]

  /// C7.2.348 UADDL, UADDL2
  [<TestMethod>]
  member _.``C7.2.348 UADDL``() =
    check "2e620020" []
      [ [ Q(0, 0x9fda0001df28UL, 0xf7ff00009d51UL) ]
        [ Q(0, 0x148df0000fbf7UL, 0xb11500012f99UL) ]
        [ Q(0, 0x800000000001UL, 0xffff0000ffffUL) ]
        [ Q(0, 0x0UL, 0xc00800000000UL) ] ]
    check "2e220020" []
      [ [ Q(0, 0x9e01da01df0028UL, 0xf700ff009d0051UL) ]
        [ Q(0, 0x14800df00fb00f7UL, 0xb00115012f0099UL) ]
        [ Q(0, 0x80000000000001UL, 0xff00ff00ff00ffUL) ]
        [ Q(0, 0x0UL, 0xc0000800000000UL) ] ]
    check "2ea20020" []
      [ [ Q(0, 0x9fdbdf28UL, 0xf7ff9d51UL) ]
        [ Q(0, 0x148dffbf7UL, 0xb1162f99UL) ]
        [ Q(0, 0x80000001UL, 0xffffffffUL) ]
        [ Q(0, 0x0UL, 0xc0080000UL) ] ]

  /// C7.2.348 UADDL, UADDL2
  [<TestMethod>]
  member _.``C7.2.348 UADDL2``() =
    check "6e220020" []
      [ [ Q(0, 0x8c013e01dc010cUL, 0xcb010400840092UL) ]
        [ Q(0, 0x13f00f8014c00e5UL, 0x12900910045014dUL) ]
        [ Q(0, 0xfe013f00ff00ffUL, 0x7f012000000000UL) ]
        [ Q(0, 0x9900990099009aUL, 0xbe01a900990099UL) ] ]
    check "6ea20020" []
      [ [ Q(0, 0x8d3fdd0cUL, 0xcc048492UL) ]
        [ Q(0, 0x13ff94ce5UL, 0x12991464dUL) ]
        [ Q(0, 0xff3fffffUL, 0x80200000UL) ]
        [ Q(0, 0x9999999aUL, 0xbfa99999UL) ] ]
    check "6e620020" []
      [ [ Q(0, 0x8d3e0001dd0cUL, 0xcc0400008492UL) ]
        [ Q(0, 0x13ff800014ce5UL, 0x129910000464dUL) ]
        [ Q(0, 0xff3f0000ffffUL, 0x802000000000UL) ]
        [ Q(0, 0x99990000999aUL, 0xbfa900009999UL) ] ]

  /// C7.2.349 UADDLP
  [<TestMethod>]
  member _.``C7.2.349 UADDLP``() =
    check "2e202820" []
      [ [ Q(0, 0xd1009e012400fcUL, 0x0UL) ]
        [ Q(0, 0x11f00a8006e00c2UL, 0x0UL) ]
        [ Q(0, 0xff000000800000UL, 0x0UL) ]
        [ Q(0, 0x48000000000000UL, 0x0UL) ] ]
    check "6e202820" []
      [ [ Q(0, 0xd1009e012400fcUL, 0x11600d001210113UL) ]
        [ Q(0, 0x11f00a8006e00c2UL, 0x113006e007e0159UL) ]
        [ Q(0, 0xff000000800000UL, 0x11f0000013f0000UL) ]
        [ Q(0, 0x48000000000000UL, 0xf8013201320133UL) ] ]
    check "2e602820" []
      [ [ Q(0, 0xdf90000128f8UL, 0x0UL) ]
        [ Q(0, 0xdaed0000fd33UL, 0x0UL) ]
        [ Q(0, 0x7f8000008000UL, 0x0UL) ]
        [ Q(0, 0x400800000000UL, 0x0UL) ] ]
    check "6ea02820" []
      [ [ Q(0, 0xb93e4f4bUL, 0x6fca7e65UL) ]
        [ Q(0, 0xb6d82149UL, 0x14150cbfcUL) ]
        [ Q(0, 0xff800000UL, 0xff600000UL) ]
        [ Q(0, 0x40080000UL, 0xd9533333UL) ] ]
    check "6e602820" []
      [ [ Q(0, 0xdf90000128f8UL, 0xc32400012b0aUL) ]
        [ Q(0, 0xdaed0000fd33UL, 0xfd8400010fc8UL) ]
        [ Q(0, 0x7f8000008000UL, 0x7fa000007fc0UL) ]
        [ Q(0, 0x400800000000UL, 0xd95200013333UL) ] ]

  /// C7.2.350 UADDLV
  [<TestMethod>]
  member _.``C7.2.350 UADDLV``() =
    check "2e303820" []
      [ [ Q(0, 0x38fUL, 0x0UL) ]
        [ Q(0, 0x2f7UL, 0x0UL) ]
        [ Q(0, 0x17fUL, 0x0UL) ]
        [ Q(0, 0x48UL, 0x0UL) ] ]

  /// C7.2.351 UADDW, UADDW2
  [<TestMethod>]
  member _.``C7.2.351 UADDW``() =
    check "2e621020" []
      [ [ Q(0, 0x7061c62d48dddf28UL, 0x40d709ec2ef42a39UL) ]
        [ Q(0, 0x57c96cf55f0ffbf7UL, 0xe23174a05f205d1dUL) ]
        [ Q(0, 0x7f80000080000001UL, 0x7fa0807f7fc0ffffUL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fba19999999999aUL) ] ]
    check "2e221020" []
      [ [ Q(0, 0x70b7702d49dbe028UL, 0x415d82ec2f21fc39UL) ]
        [ Q(0, 0x58b183f55f6c9ef7UL, 0xe28a1ba05fcbb11dUL) ]
        [ Q(0, 0x7f80000080000001UL, 0x8020007f80bf00ffUL) ]
        [ Q(0, 0x4008000000000000UL, 0x403999999999999aUL) ] ]
    check "2ea21020" []
      [ [ Q(0, 0x70616f2f9fdbdf28UL, 0x40d6824eb6922a39UL) ]
        [ Q(0, 0x57c8832648dffbf7UL, 0xe2311b53b86d5d1dUL) ]
        [ Q(0, 0x7f80000080000001UL, 0x7fa00001003fffffUL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fb9999a1999999aUL) ] ]

  /// C7.2.351 UADDW, UADDW2
  [<TestMethod>]
  member _.``C7.2.351 UADDW2``() =
    check "6e221020" []
      [ [ Q(0, 0x70bf6f7a49bce111UL, 0x4161827c2ef5fc5bUL) ]
        [ Q(0, 0x58a883fe5fab9e60UL, 0xe2781bb35f49b1a3UL) ]
        [ Q(0, 0x7fff007f80ff00ffUL, 0x7fa000807fc00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x40389a899999999aUL) ] ]
    check "6ea21020" []
      [ [ Q(0, 0x70616f2fa728c111UL, 0x40d6824eba21fe5bUL) ]
        [ Q(0, 0x57c883263fe93a60UL, 0xe2311b53a67fdba3UL) ]
        [ Q(0, 0x7f800000ff7fffffUL, 0x7fa0000080400000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fb9999a1989999aUL) ] ]
    check "6e621020" []
      [ [ Q(0, 0x7061cd7a48ddc111UL, 0x40d70d7c2ef3fe5bUL) ]
        [ Q(0, 0x57c963fe5f103a60UL, 0xe23162b35f1fdba3UL) ]
        [ Q(0, 0x7f807f7f8000ffffUL, 0x7fa000807fc00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fba19899999999aUL) ] ]

  /// C7.2.352 UCVTF (vector, fixed-point)
  [<TestMethod>]
  member _.``C7.2.352 UCVTF``() =
    check "2f1be420" []
      [ [ Q(0, 0x630662f3608e6701UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x617c641961f164f1UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x63f8000064000000UL, 0x0UL) ]
        [ Q(0, 0x6000000000000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "6f1be420" []
      [ [ Q(0, 0x630662f3608e6701UL, 0x600d64125dde67e1UL); Fpsr 0x10UL ]
        [ Q(0, 0x617c641961f164f1UL, 0x67125ad561f26585UL); Fpsr 0x10UL ]
        [ Q(0, 0x63f8000064000000UL, 0x63fa000063fc0000UL) ]
        [ Q(0, 0x6000000000000000UL, 0x5ff764cd64cd64cdUL); Fpsr 0x10UL ] ]
    check "2f3be420" []
      [ [ Q(0, 0x4c60c2de4c11b9c0UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x4c2f91064c3e1f3cUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x4c7f00004c800000UL, 0x0UL) ]
        [ Q(0, 0x4c00100000000000UL, 0x0UL) ] ]
    check "6f3be420" []
      [ [ Q(0, 0x4c60c2de4c11b9c0UL, 0x4c01ad054bbbcff0UL); Fpsr 0x10UL ]
        [ Q(0, 0x4c2f91064c3e1f3cUL, 0x4ce2311b4c3e3f61UL); Fpsr 0x10UL ]
        [ Q(0, 0x4c7f00004c800000UL, 0x4c7f40004c7f8000UL) ]
        [ Q(0, 0x4c00100000000000UL, 0x4bfee6664c99999aUL); Fpsr 0x10UL ] ]
    check "6f7be420" []
      [ [ Q(0, 0x438c185bcbd23738UL, 0x438035a0938bbcffUL); Fpsr 0x10UL ]
        [ Q(0, 0x4385f220c957c3e8UL, 0x439c46236a6be3f6UL); Fpsr 0x10UL ]
        [ Q(0, 0x438fe00000200000UL, 0x438fe800001ff000UL) ]
        [ Q(0, 0x4380020000000000UL, 0x437fdccccccccccdUL); Fpsr 0x10UL ] ]
    check "7e79d820" []
      [ [ Q(0, 0x7b01UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x78f1UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "2e79d820" []
      [ [ Q(0, 0x770676f3748e7b01UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x757c781975f178f1UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x77f8000078000000UL, 0x0UL) ]
        [ Q(0, 0x7400000000000000UL, 0x0UL); Fpsr 0x10UL ] ]
    check "6e79d820" []
      [ [ Q(0, 0x770676f3748e7b01UL, 0x740d781271de7be1UL); Fpsr 0x10UL ]
        [ Q(0, 0x757c781975f178f1UL, 0x7b126ed575f27985UL); Fpsr 0x10UL ]
        [ Q(0, 0x77f8000078000000UL, 0x77fa000077fc0000UL) ]
        [ Q(0, 0x7400000000000000UL, 0x73f778cd78cd78cdUL); Fpsr 0x10UL ] ]
    check "2e21d820" []
      [ [ Q(0, 0x4ee0c2de4e91b9c0UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x4eaf91064ebe1f3cUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x4eff00004f000000UL, 0x0UL) ]
        [ Q(0, 0x4e80100000000000UL, 0x0UL) ] ]
    check "6e21d820" []
      [ [ Q(0, 0x4ee0c2de4e91b9c0UL, 0x4e81ad054e3bcff0UL); Fpsr 0x10UL ]
        [ Q(0, 0x4eaf91064ebe1f3cUL, 0x4f62311b4ebe3f61UL); Fpsr 0x10UL ]
        [ Q(0, 0x4eff00004f000000UL, 0x4eff40004eff8000UL) ]
        [ Q(0, 0x4e80100000000000UL, 0x4e7ee6664f19999aUL); Fpsr 0x10UL ] ]
    check "6e61d820" []
      [ [ Q(0, 0x43dc185bcbd23738UL, 0x43d035a0938bbcffUL); Fpsr 0x10UL ]
        [ Q(0, 0x43d5f220c957c3e8UL, 0x43ec46236a6be3f6UL); Fpsr 0x10UL ]
        [ Q(0, 0x43dfe00000200000UL, 0x43dfe800001ff000UL) ]
        [ Q(0, 0x43d0020000000000UL, 0x43cfdccccccccccdUL); Fpsr 0x10UL ] ]
    check "1ec3ec20" []
      [ [ Q(0, 0x7c00UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x7c00UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x2800UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e03ec20" []
      [ [ Q(0, 0x4c4b1dd9UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x4abfc1e4UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x3d000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e43ec20" []
      [ [ Q(0, 0x418963bb19c00000UL, 0x0UL) ]
        [ Q(0, 0x4157f83c84000000UL, 0x0UL) ]
        [ Q(0, 0x3fa0000000000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "9ec3ec20" []
      [ [ Q(0, 0x7c00UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x7c00UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x2800UL, 0x0UL) ]
        [ Q(0, 0x7c00UL, 0x0UL); Fpsr 0x14UL ] ]
    check "9e03ec20" []
      [ [ Q(0, 0x5cbeeb8eUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x5cbfc846UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x3d000000UL, 0x0UL) ]
        [ Q(0, 0x4d000000UL, 0x0UL) ] ]
    check "9e43ec20" []
      [ [ Q(0, 0x4397dd71b42cb1deUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x4397f908c2017f84UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x3fa0000000000000UL, 0x0UL) ]
        [ Q(0, 0x41a0000000000000UL, 0x0UL) ] ]
    check "1ee30020" []
      [ [ Q(0, 0x7c00UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x7c00UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x3c00UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e230020" []
      [ [ Q(0, 0x4ecb1dd9UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x4d3fc1e4UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x3f800000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "1e630020" []
      [ [ Q(0, 0x41d963bb19c00000UL, 0x0UL) ]
        [ Q(0, 0x41a7f83c84000000UL, 0x0UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "9ee30020" []
      [ [ Q(0, 0x7c00UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x7c00UL, 0x0UL); Fpsr 0x14UL ]
        [ Q(0, 0x3c00UL, 0x0UL) ]
        [ Q(0, 0x7c00UL, 0x0UL); Fpsr 0x14UL ] ]
    check "9e230020" []
      [ [ Q(0, 0x5f3eeb8eUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x5f3fc846UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x3f800000UL, 0x0UL) ]
        [ Q(0, 0x4f800000UL, 0x0UL) ] ]
    check "9e630020" []
      [ [ Q(0, 0x43e7dd71b42cb1deUL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x43e7f908c2017f84UL, 0x0UL); Fpsr 0x10UL ]
        [ Q(0, 0x3ff0000000000000UL, 0x0UL) ]
        [ Q(0, 0x41f0000000000000UL, 0x0UL) ] ]
    check "1e43fc20" []
      [ [ Q(0, 0x41c963bb19c00000UL, 0x0UL) ]
        [ Q(0, 0x4197f83c84000000UL, 0x0UL) ]
        [ Q(0, 0x3fe0000000000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]

  /// C7.2.356 UDOT (by element)
  [<TestMethod>]
  member _.``C7.2.356 UDOT``() =
    check "2e829420" []
      [ [ Q(0, 0x962baa85c9095ca2UL, 0x0UL) ]
        [ Q(0, 0x9a7b6a5330fa840eUL, 0x0UL) ]
        [ Q(0, 0xbfc07f003f800000UL, 0x0UL) ]
        [ Q(0, 0x3ff0200000000000UL, 0x0UL) ] ]

  /// C7.2.358 UHADD
  [<TestMethod>]
  member _.``C7.2.358 UHADD``() =
    check "2e220420" []
      [ [ Q(0, 0x7b7f4e284fedef14UL, 0x0UL) ]
        [ Q(0, 0x588a974ca46f7d7bUL, 0x0UL) ]
        [ Q(0, 0x7f7f7f7f40000000UL, 0x0UL) ]
        [ Q(0, 0x6004000000000000UL, 0x0UL) ] ]
    check "6e220420" []
      [ [ Q(0, 0x7b7f4e284fedef14UL, 0x65824249469fee86UL) ]
        [ Q(0, 0x588a974ca46f7d7bUL, 0x944822a69f7ca672UL) ]
        [ Q(0, 0x7f7f7f7f40000000UL, 0x3f9000007f9f7f7fUL) ]
        [ Q(0, 0x6004000000000000UL, 0x5fd44c4c4c4c4c4dUL) ] ]
    check "2e620420" []
      [ [ Q(0, 0x7bff4ea84fedef94UL, 0x0UL) ]
        [ Q(0, 0x588a97cca46f7dfbUL, 0x0UL) ]
        [ Q(0, 0x7fff7fff40000000UL, 0x0UL) ]
        [ Q(0, 0x6004000000000000UL, 0x0UL) ] ]
    check "6e620420" []
      [ [ Q(0, 0x7bff4ea84fedef94UL, 0x66024249469fee86UL) ]
        [ Q(0, 0x588a97cca46f7dfbUL, 0x94c823269ffca672UL) ]
        [ Q(0, 0x7fff7fff40000000UL, 0x401000007f9f7fffUL) ]
        [ Q(0, 0x6004000000000000UL, 0x5fd44ccc4ccc4ccdUL) ] ]
    check "2ea20420" []
      [ [ Q(0, 0x7bffcea84fedef94UL, 0x0UL) ]
        [ Q(0, 0x588b17cca46ffdfbUL, 0x0UL) ]
        [ Q(0, 0x7fffffff40000000UL, 0x0UL) ]
        [ Q(0, 0x6004000000000000UL, 0x0UL) ] ]
    check "6ea20420" []
      [ [ Q(0, 0x7bffcea84fedef94UL, 0x66024249469fee86UL) ]
        [ Q(0, 0x588b17cca46ffdfbUL, 0x94c8a3269ffca672UL) ]
        [ Q(0, 0x7fffffff40000000UL, 0x401000007f9fffffUL) ]
        [ Q(0, 0x6004000000000000UL, 0x5fd4cccc4ccccccdUL) ] ]

  /// C7.2.359 UHSUB
  [<TestMethod>]
  member _.``C7.2.359 UHSUB``() =
    check "2e222420" []
      [ [ Q(0, 0xf4e12006f9eff008UL, 0x0UL) ]
        [ Q(0, 0xff3debd8bb9f20a8UL, 0x0UL) ]
        [ Q(0, 0xff008080400000ffUL, 0x0UL) ]
        [ Q(0, 0xe004000000000000UL, 0x0UL) ] ]
    check "6e222420" []
      [ [ Q(0, 0xf4e12006f9eff008UL, 0xda544005e8540e91UL) ]
        [ Q(0, 0xff3debd8bb9f20a8UL, 0x4de8f8acbfa30a36UL) ]
        [ Q(0, 0xff008080400000ffUL, 0x3f10000000208080UL) ]
        [ Q(0, 0xe004000000000000UL, 0xe0e44c4c4c4c4c4dUL) ] ]
    check "2e622420" []
      [ [ Q(0, 0xf4612086f8eff088UL, 0x0UL) ]
        [ Q(0, 0xff3deb58ba9f2028UL, 0x0UL) ]
        [ Q(0, 0xff8080004000ffffUL, 0x0UL) ]
        [ Q(0, 0xe004000000000000UL, 0x0UL) ] ]
    check "6e622420" []
      [ [ Q(0, 0xf4612086f8eff088UL, 0xdad44005e8540d91UL) ]
        [ Q(0, 0xff3deb58ba9f2028UL, 0x4d68f82cbf230a36UL) ]
        [ Q(0, 0xff8080004000ffffUL, 0x3f90000000208000UL) ]
        [ Q(0, 0xe004000000000000UL, 0xdfe44ccc4ccc4ccdUL) ] ]
    check "2ea22420" []
      [ [ Q(0, 0xf461a086f8eef088UL, 0x0UL) ]
        [ Q(0, 0xff3d6b58ba9fa028UL, 0x0UL) ]
        [ Q(0, 0xff8000003fffffffUL, 0x0UL) ]
        [ Q(0, 0xe004000000000000UL, 0x0UL) ] ]
    check "6ea22420" []
      [ [ Q(0, 0xf461a086f8eef088UL, 0xdad44005e8540d91UL) ]
        [ Q(0, 0xff3d6b58ba9fa028UL, 0x4d68782cbf230a36UL) ]
        [ Q(0, 0xff8000003fffffffUL, 0x3f90000000200000UL) ]
        [ Q(0, 0xe004000000000000UL, 0xdfe4cccc4ccccccdUL) ] ]

  /// C7.2.360 UMAX
  [<TestMethod>]
  member _.``C7.2.360 UMAX``() =
    check "2e226420" []
      [ [ Q(0, 0x879e6f2f56feff1cUL, 0x0UL) ]
        [ Q(0, 0x59c8ac74e9d09ed3UL, 0x0UL) ]
        [ Q(0, 0x8080ffff80000001UL, 0x0UL) ]
        [ Q(0, 0x8008000000000000UL, 0x0UL) ] ]
    check "6e226420" []
      [ [ Q(0, 0x879e6f2f56feff1cUL, 0x8bd6824e5ef3fcf5UL) ]
        [ Q(0, 0x59c8ac74e9d09ed3UL, 0xe2602afae0d9b0a9UL) ]
        [ Q(0, 0x8080ffff80000001UL, 0x7fa000007fc0ffffUL) ]
        [ Q(0, 0x8008000000000000UL, 0x7ff099999999999aUL) ] ]
    check "2e626420" []
      [ [ Q(0, 0x879e6f2f56feff0cUL, 0x0UL) ]
        [ Q(0, 0x594dac74e9d09e24UL, 0x0UL) ]
        [ Q(0, 0x807fffff80000001UL, 0x0UL) ]
        [ Q(0, 0x8000000000000000UL, 0x0UL) ] ]
    check "6e626420" []
      [ [ Q(0, 0x879e6f2f56feff0cUL, 0x8b2e824e5e4bfc17UL) ]
        [ Q(0, 0x594dac74e9d09e24UL, 0xe2312afae0d9b0a9UL) ]
        [ Q(0, 0x807fffff80000001UL, 0x7fa000007fc0ffffUL) ]
        [ Q(0, 0x8000000000000000UL, 0x7ff099999999999aUL) ] ]
    check "2ea26420" []
      [ [ Q(0, 0x879e2e2256feff0cUL, 0x0UL) ]
        [ Q(0, 0x594dac74e9d05dd3UL, 0x0UL) ]
        [ Q(0, 0x807fffff80000000UL, 0x0UL) ]
        [ Q(0, 0x8000000000000000UL, 0x0UL) ] ]
    check "6ea26420" []
      [ [ Q(0, 0x879e2e2256feff0cUL, 0x8b2e02445e4be0f5UL) ]
        [ Q(0, 0x594dac74e9d05dd3UL, 0xe2311b53e0d99c3cUL) ]
        [ Q(0, 0x807fffff80000000UL, 0x7fa000007fc00000UL) ]
        [ Q(0, 0x8000000000000000UL, 0x7ff000009999999aUL) ] ]

  /// C7.2.361 UMAXP
  [<TestMethod>]
  member _.``C7.2.361 UMAXP``() =
    check "2e22a420" []
      [ [ Q(0, 0x9e2efeff706fdce0UL, 0x0UL) ]
        [ Q(0, 0x59ace9d3c8835f9eUL, 0x0UL) ]
        [ Q(0, 0x80ff000180008000UL, 0x0UL) ]
        [ Q(0, 0x8000000040000000UL, 0x0UL) ] ]
    check "6e22a420" []
      [ [ Q(0, 0xd682f3fc706fdce0UL, 0x8b445ef59e2efeffUL) ]
        [ Q(0, 0xe2535fb0c8835f9eUL, 0x60fae09c59ace9d3UL) ]
        [ Q(0, 0xa000c00080008000UL, 0x80007fff80ff0001UL) ]
        [ Q(0, 0xb999999a40000000UL, 0xf000000080000000UL) ] ]
    check "2e62a420" []
      [ [ Q(0, 0x879eff0c7061e01cUL, 0x0UL) ]
        [ Q(0, 0xac74e9d083259e24UL, 0x0UL) ]
        [ Q(0, 0xffff00017f808000UL, 0x0UL) ]
        [ Q(0, 0x8000000040080000UL, 0x0UL) ] ]
    check "6e62a420" []
      [ [ Q(0, 0x824efc177061e01cUL, 0x8b2ee0f5879eff0cUL) ]
        [ Q(0, 0xe231b0a983259e24UL, 0x4760e0d9ac74e9d0UL) ]
        [ Q(0, 0x7fa07fc07f808000UL, 0x80ffffffff0001UL) ]
        [ Q(0, 0x9999999a40080000UL, 0x7ff0000080000000UL) ] ]
    check "2ea2a420" []
      [ [ Q(0, 0x879e2e2270616f2fUL, 0x0UL) ]
        [ Q(0, 0xe9d05dd35f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x807fffff80000000UL, 0x0UL) ]
        [ Q(0, 0x8000000040080000UL, 0x0UL) ] ]
    check "6ea2a420" []
      [ [ Q(0, 0x40d6824e70616f2fUL, 0x8b2e0244879e2e22UL) ]
        [ Q(0, 0xe2311b535f0f9e24UL, 0xe0d99c3ce9d05dd3UL) ]
        [ Q(0, 0x7fc0000080000000UL, 0x7f7fffff807fffffUL) ]
        [ Q(0, 0x9999999a40080000UL, 0x7ff0000080000000UL) ] ]

  /// C7.2.362 UMAXV
  [<TestMethod>]
  member _.``C7.2.362 UMAXV``() =
    check "6eb0a820" []
      [ [ Q(0, 0x70616f2fUL, 0x0UL) ]
        [ Q(0, 0xe2311b53UL, 0x0UL) ]
        [ Q(0, 0x80000000UL, 0x0UL) ]
        [ Q(0, 0x9999999aUL, 0x0UL) ] ]

  /// C7.2.363 UMIN
  [<TestMethod>]
  member _.``C7.2.363 UMIN``() =
    check "2e226c20" []
      [ [ Q(0, 0x70612e2248dce00cUL, 0x0UL) ]
        [ Q(0, 0x574d83255f0f5d24UL, 0x0UL) ]
        [ Q(0, 0x7f7f000000000000UL, 0x0UL) ]
        [ Q(0, 0x4000000000000000UL, 0x0UL) ] ]
    check "6e226c20" []
      [ [ Q(0, 0x70612e2248dce00cUL, 0x402e02442e4be017UL) ]
        [ Q(0, 0x574d83255f0f5d24UL, 0x47311b535f1f9c3cUL) ]
        [ Q(0, 0x7f7f000000000000UL, 0x8000007f7f0000UL) ]
        [ Q(0, 0x4000000000000000UL, 0x3fb9000000000000UL) ] ]
    check "2e626c20" []
      [ [ Q(0, 0x70612e2248dce01cUL, 0x0UL) ]
        [ Q(0, 0x57c883255f0f5dd3UL, 0x0UL) ]
        [ Q(0, 0x7f80000000000000UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "6e626c20" []
      [ [ Q(0, 0x70612e2248dce01cUL, 0x40d602442ef3e0f5UL) ]
        [ Q(0, 0x57c883255f0f5dd3UL, 0x47601b535f1f9c3cUL) ]
        [ Q(0, 0x7f80000000000000UL, 0x8000007f7f0000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fb9000000000000UL) ] ]
    check "2ea26c20" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x0UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x7f80000000000001UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "6ea26c20" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x40d6824e2ef3fc17UL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x47602afa5f1fb0a9UL) ]
        [ Q(0, 0x7f80000000000001UL, 0x8000007f7fffffUL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fb9999900000000UL) ] ]

  /// C7.2.364 UMINP
  [<TestMethod>]
  member _.``C7.2.364 UMINP``() =
    check "2e22ac20" []
      [ [ Q(0, 0x8722560c612f481cUL, 0x0UL) ]
        [ Q(0, 0x4d74d05d57250f24UL, 0x0UL) ]
        [ Q(0, 0x7fff00007f000000UL, 0x0UL) ]
        [ Q(0, 0x8000000UL, 0x0UL) ] ]
    check "6e22ac20" []
      [ [ Q(0, 0x404e2e17612f481cUL, 0x2e024be08722560cUL) ]
        [ Q(0, 0x311b1fa957250f24UL, 0x472ad93c4d74d05dUL) ]
        [ Q(0, 0x7f007f007f000000UL, 0x7fff7fff0000UL) ]
        [ Q(0, 0x3f99999908000000UL, 0x7f00000000000000UL) ] ]
    check "2e62ac20" []
      [ [ Q(0, 0x2e2256fe6f2f48dcUL, 0x0UL) ]
        [ Q(0, 0x594d5dd357c85f0fUL, 0x0UL) ]
        [ Q(0, 0x807f000000000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "6e62ac20" []
      [ [ Q(0, 0x40d62ef36f2f48dcUL, 0x2445e4b2e2256feUL) ]
        [ Q(0, 0x1b535f1f57c85f0fUL, 0x2afa9c3c594d5dd3UL) ]
        [ Q(0, 0x0UL, 0x7f7f807f0000UL) ]
        [ Q(0, 0x3fb9999900000000UL, 0x0UL) ] ]
    check "2ea2ac20" []
      [ [ Q(0, 0x56feff0c48dce01cUL, 0x0UL) ]
        [ Q(0, 0x594dac7457c88325UL, 0x0UL) ]
        [ Q(0, 0x17f800000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "6ea2ac20" []
      [ [ Q(0, 0x2ef3fc1748dce01cUL, 0x5e4be0f556feff0cUL) ]
        [ Q(0, 0x5f1fb0a957c88325UL, 0x47602afa594dac74UL) ]
        [ Q(0, 0x7fa000007f800000UL, 0x80000000000001UL) ]
        [ Q(0, 0x3fb9999900000000UL, 0x0UL) ] ]

  /// C7.2.365 UMINV
  [<TestMethod>]
  member _.``C7.2.365 UMINV``() =
    check "6eb1a820" []
      [ [ Q(0, 0x2ef3fc17UL, 0x0UL) ]
        [ Q(0, 0x57c88325UL, 0x0UL) ]
        [ Q(0, 0x7f800000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]

  /// C7.2.366 UMLAL, UMLAL2 (by element)
  [<TestMethod>]
  member _.``C7.2.366 UMLAL``() =
    check "2e628020" []
      [ [ Q(0, 0xaeed4bafa84def0aUL, 0xa13565466e1062abUL) ]
        [ Q(0, 0xf14c8a546aef3601UL, 0x62eab9e27b13b1d3UL) ]
        [ Q(0, 0xbfc000003f800000UL, 0x7dcc0d4d40400000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xdffc000000000000UL) ] ]
    check "2f522020" []
      [ [ Q(0, 0xaeed4baf152f4d82UL, 0x8bdcf8a67fcf470fUL) ]
        [ Q(0, 0xf14c8a54c1690b95UL, 0x9478253a9a82a41fUL) ]
        []
        [] ]
    check "2fa22020" []
      [ [ Q(0, 0xbcc4990a3bea5572UL, 0xa135b46d30f462abUL) ]
        [ Q(0, 0xbba3ecdad721a2a5UL, 0x62eb22c3f0d4b1d3UL) ]
        [ Q(0, 0xffffffffbf800000UL, 0x7dcc8cccc0c00000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xdffc000000000000UL) ] ]
    check "2e228020" []
      [ [ Q(0, 0xae5bf3afa8278b0aUL, 0xa0bc1e466df932abUL) ]
        [ Q(0, 0xf0f1b3546a5fe801UL, 0x628a06e27abf79d3UL) ]
        [ Q(0, 0xbfc000003f800000UL, 0x7d4c0c4d40400000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xdff8000000000000UL) ] ]
    check "2ea28020" []
      [ [ Q(0, 0xaeede06efa65ef0aUL, 0xa135b46d30f462abUL) ]
        [ Q(0, 0xf14d3d9a788c3601UL, 0x62eb22c3f0d4b1d3UL) ]
        [ Q(0, 0xbfc00000bf800000UL, 0x7dcc8cccc0c00000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xdffc000000000000UL) ] ]

  /// C7.2.366 UMLAL, UMLAL2 (by element)
  [<TestMethod>]
  member _.``C7.2.366 UMLAL2``() =
    check "6f522020" []
      [ [ Q(0, 0xa61f50811eb1628cUL, 0x7bb51abc864ea9d1UL) ]
        [ Q(0, 0xf15b2754d25324a5UL, 0x12e22b8a3bb0277fUL) ]
        []
        [] ]
    check "6fa22020" []
      [ [ Q(0, 0xaf0ac66393ed26c8UL, 0x8806113310127ec9UL) ]
        [ Q(0, 0xbba9882b79dc62e9UL, 0x93337e5eb24e8eabUL) ]
        [ Q(0, 0xffdfdfffbfc00000UL, 0x7ddc9cccc0a00000UL) ]
        [ Q(0, 0x8cbccccd00000000UL, 0xdfd4cccc80000000UL) ] ]
    check "6e228020" []
      [ [ Q(0, 0xa70f6098a5879fbdUL, 0x886c08dc5b0b4125UL) ]
        [ Q(0, 0xed9ac16b9c39f1f1UL, 0x82f9dd1a2729ba1dUL) ]
        [ Q(0, 0xfec15f403f800000UL, 0x3dcc1ccd40400000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xdf39ad7000000000UL) ] ]
    check "6ea28020" []
      [ [ Q(0, 0xa7769ab581d8ebbdUL, 0x88ed0247040a6525UL) ]
        [ Q(0, 0xee073da26b4f2df1UL, 0x835c61b1594bb61dUL) ]
        [ Q(0, 0xff601fffbfc00000UL, 0x3e0c9ccd40400000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xdfd0d132e6700000UL) ] ]
    check "6e628020" []
      [ [ Q(0, 0xa7761498a68cebbdUL, 0x88ecbadc5b2e6525UL) ]
        [ Q(0, 0xee06686b9cca2df1UL, 0x835c341a2751b61dUL) ]
        [ Q(0, 0xff5fa0403f800000UL, 0x3e0c9ccd40400000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xdfd0847000000000UL) ] ]

  /// C7.2.368 UMLSL, UMLSL2 (by element)
  [<TestMethod>]
  member _.``C7.2.368 UMLSL``() =
    check "2e62a020" []
      [ [ Q(0, 0x7d68e71fe9c1246aUL, 0x2a245f8a45fdf62fUL) ]
        [ Q(0, 0x43a8c3f4f7045ea9UL, 0x25acdb92ca63204bUL) ]
        [ Q(0, 0xbfc000003f800000UL, 0xfdcd8c4d40400000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x9ff4000000000000UL) ] ]
    check "2f526020" []
      [ [ Q(0, 0x7d68e71f7cdfc5f2UL, 0x3f7ccc2a343f11cbUL) ]
        [ Q(0, 0x43a8c3f4a08a8915UL, 0xf41f703aaaf42dffUL) ]
        []
        [] ]
    check "2fa26020" []
      [ [ Q(0, 0x6f9199c55624be02UL, 0x2a2410638319f62fUL) ]
        [ Q(0, 0x7951616d8ad1f205UL, 0x25ac72b054a2204bUL) ]
        [ Q(0, 0x7f800000bf800000UL, 0xfdcd0ccdbfc00000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x9ff4000000000000UL) ] ]
    check "2e22a020" []
      [ [ Q(0, 0x7dfb3f1fe9e7886aUL, 0x2a9ca68a4615262fUL) ]
        [ Q(0, 0x44039af4f793aca9UL, 0x260c8e92cab7584bUL) ]
        [ Q(0, 0xbfc000003f800000UL, 0xfe4c8d4d40400000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x9ff8000000000000UL) ] ]
    check "2ea2a020" []
      [ [ Q(0, 0x7d68526097a9246aUL, 0x2a2410638319f62fUL) ]
        [ Q(0, 0x43a810ade9675ea9UL, 0x25ac72b054a2204bUL) ]
        [ Q(0, 0xbfbfffffbf800000UL, 0xfdcd0ccdbfc00000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x9ff4000000000000UL) ] ]

  /// C7.2.368 UMLSL, UMLSL2 (by element)
  [<TestMethod>]
  member _.``C7.2.368 UMLSL2``() =
    check "6f526020" []
      [ [ Q(0, 0x8636e24d735db0e8UL, 0x4fa4aa142dbfaf09UL) ]
        [ Q(0, 0x439a26f48fa07005UL, 0x75b569ea09c6aa9fUL) ]
        []
        [] ]
    check "6fa26020" []
      [ [ Q(0, 0x7d4b6c6bfe21ecacUL, 0x4353b39da3fbda11UL) ]
        [ Q(0, 0x794bc61ce81731c1UL, 0xf564171593284373UL) ]
        [ Q(0, 0x7fa02000bf400000UL, 0xfdbcfccdbfe00000UL) ]
        [ Q(0, 0xf323333300000000UL, 0xa01b333380000000UL) ] ]
    check "6e22a020" []
      [ [ Q(0, 0x8547d236ec8773b7UL, 0x42ecbbf4590317b5UL) ]
        [ Q(0, 0x475a8cddc5b9a2b9UL, 0x59db85a1e4d1801UL) ]
        [ Q(0, 0x80bfa0c03f800000UL, 0x3dcc7ccd40400000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xa0b7529000000000UL) ] ]
    check "6ea2a020" []
      [ [ Q(0, 0x84df981a103627b7UL, 0x426cc289b003f3b5UL) ]
        [ Q(0, 0x46ee10a5f6a466b9UL, 0x53b33c2ec2b1c01UL) ]
        [ Q(0, 0x801fe000bf400000UL, 0x3d8cfccd40400000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xa01f2ecd19900000UL) ] ]
    check "6e62a020" []
      [ [ Q(0, 0x84e01e36eb8227b7UL, 0x426d09f458dff3b5UL) ]
        [ Q(0, 0x46eee5ddc52966b9UL, 0x53b615a1e251c01UL) ]
        [ Q(0, 0x80205fc03f800000UL, 0x3d8cfccd40400000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xa01f7b9000000000UL) ] ]

  /// C7.2.370 UMMLA (vector)
  [<TestMethod>]
  member _.``C7.2.370 UMMLA``() =
    check "6e82a420" []
      [ [ Q(0, 0x962caeafc909edc0UL, 0x65ae8bf05a09f09fUL) ]
        [ Q(0, 0x9a7c0c7430fb473dUL, 0x444d718722bd3900UL) ]
        [ Q(0, 0xbfc07f803f807f00UL, 0x3dcdbb0e40408ee0UL) ]
        [ Q(0, 0x3ff0274000002000UL, 0xbff8ccb100001f80UL) ] ]

  /// C7.2.371 UMOV
  [<TestMethod>]
  member _.``C7.2.371 UMOV``() =
    check "0e033c20" []
      [ [ X(0, 0xe0UL) ]
        [ X(0, 0x9eUL) ]
        []
        [ X(0, 0x0UL) ] ]
    check "0e063c20" []
      [ [ X(0, 0x48dcUL) ]
        [ X(0, 0x5f0fUL) ]
        [ X(0, 0x8000UL) ]
        [ X(0, 0x0UL) ] ]

  /// C7.2.372 UMULL, UMULL2 (by element)
  [<TestMethod>]
  member _.``C7.2.372 UMULL2``() =
    check "6f52a020" []
      [ [ Q(0, 0xff4371a55a9d8d2UL, 0x160838542c477d64UL) ]
        [ Q(0, 0x56e08030a1595a50UL, 0xce9660d018f4be70UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "6fa2a020" []
      [ [ Q(0, 0x18dfacfbcae59d0eUL, 0x22592ecab60b525cUL) ]
        [ Q(0, 0x212ee10748e29894UL, 0x4ee7b3a48f93259cUL) ]
        [ Q(0, 0x401fdfff80400000UL, 0x400fcfff80600000UL) ]
        [ Q(0, 0x4ccccccd00000000UL, 0x1fdccccc80000000UL) ] ]
    check "6e62c020" []
      [ [ Q(0, 0x114afb31dd856203UL, 0x233fd874012738b8UL) ]
        [ Q(0, 0x538bc1476bd0639cUL, 0x3f10696004964d0eUL) ]
        [ Q(0, 0x3f9fa04000000000UL, 0x3fd00000000000UL) ]
        [ Q(0, 0x0UL, 0x1fd8847000000000UL) ] ]
    check "6ea2c020" []
      [ [ Q(0, 0x114b814db8d16203UL, 0x23401fdeaa0338b8UL) ]
        [ Q(0, 0x538c967e3a55639cUL, 0x3f1096f736904d0eUL) ]
        [ Q(0, 0x3fa01fff80400000UL, 0x3fd00000000000UL) ]
        [ Q(0, 0x0UL, 0x1fd8d132e6700000UL) ] ]
    check "6e22c020" []
      [ [ Q(0, 0x10e44731dc801603UL, 0x22c02674010414b8UL) ]
        [ Q(0, 0x53201a476b40279cUL, 0x3eae1260046e510eUL) ]
        [ Q(0, 0x3f015f4000000000UL, 0x500000000000UL) ]
        [ Q(0, 0x0UL, 0x1f41ad7000000000UL) ] ]

  /// C7.2.374 UQADD
  [<TestMethod>]
  member _.``C7.2.374 UQADD``() =
    check "2e220c20" []
      [ [ Q(0, 0xf7ff9d519effff28UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xb0ffff99ffdffbf7UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffff80000001UL, 0x0UL) ]
        [ Q(0, 0xc008000000000000UL, 0x0UL) ] ]
    check "2e620c20" []
      [ [ Q(0, 0xf7ff9d519fdaffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xb115fffffffffbf7UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffff80000001UL, 0x0UL) ]
        [ Q(0, 0xc008000000000000UL, 0x0UL) ] ]
    check "6e620c20" []
      [ [ Q(0, 0xf7ff9d519fdaffffUL, 0xcc0484928d3effffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xb115fffffffffbf7UL, 0xffff464dffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffff80000001UL, 0x80200000ff3fffffUL) ]
        [ Q(0, 0xc008000000000000UL, 0xbfa999999999999aUL) ] ]
    check "2ea20c20" []
      [ [ Q(0, 0xf7ff9d519fdbdf28UL, 0x0UL) ]
        [ Q(0, 0xb1162f99ffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffff80000001UL, 0x0UL) ]
        [ Q(0, 0xc008000000000000UL, 0x0UL) ] ]
    check "6ea20c20" []
      [ [ Q(0, 0xf7ff9d519fdbdf28UL, 0xcc0484928d3fdd0cUL) ]
        [ Q(0, 0xb1162f99ffffffffUL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffff80000001UL, 0x80200000ff3fffffUL) ]
        [ Q(0, 0xc008000000000000UL, 0xbfa999999999999aUL) ] ]
    check "6ee20c20" []
      [ [ Q(0, 0xf7ff9d519fdbdf28UL, 0xcc0484928d3fdd0cUL) ]
        [ Q(0, 0xb1162f9a48dffbf7UL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffff80000001UL, 0x80200000ff3fffffUL) ]
        [ Q(0, 0xc008000000000000UL, 0xbfa999999999999aUL) ] ]
    check "6e220c20" []
      [ [ Q(0, 0xf7ff9d519effff28UL, 0xcbff84928cffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xb0ffff99ffdffbf7UL, 0xff9145fffff8ffe5UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffff80000001UL, 0x7fff0000feffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xc008000000000000UL, 0xbeff99999999999aUL); Fpsr 0x8000000UL ] ]

  /// C7.2.375 UQRSHL
  [<TestMethod>]
  member _.``C7.2.375 UQRSHL``() =
    check "2e225c20" []
      [ [ Q(0, 0xffffff3770ffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffff00ff0000ff00UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xff000080000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x8000000000000UL, 0x0UL) ] ]
    check "2e625c20" []
      [ [ Q(0, 0xffff1237ffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffff000080000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "6e625c20" []
      [ [ Q(0, 0xffff1237ffffUL, 0xffffffffffff0020UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffff00000000UL, 0xffff006d0000ffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffff000080000000UL, 0xffff0000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x4008000000000000UL, 0x99999999999aUL) ] ]
    check "2ea25c20" []
      [ [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3fc00000ffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "6ea25c20" []
      [ [ Q(0, 0xffffffffffffffffUL, 0xffffffff0005de80UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffff00000000UL, 0x388c46dffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3fc00000ffffffffUL, 0x7fa000003fe00000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x4008000000000000UL, 0x3fb999999999999aUL) ] ]
    check "6ee25c20" []
      [ [ Q(0, 0xffffffffffffffffUL, 0x81ad049c5de80UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x2be44UL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xff00000100000000UL, 0x3fd000003fe00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fb999999999999aUL) ] ]
    check "6e225c20" []
      [ [ Q(0, 0xffffff3770ffUL, 0xffffffffff0000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffff00ff0000ff00UL, 0xffffff01000000ffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xff000080000000UL, 0x7f000000ffff0000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x8000000000000UL, 0xff0099999999999aUL); Fpsr 0x8000000UL ] ]

  /// C7.2.376 UQRSHRN, UQRSHRN2
  [<TestMethod>]
  member _.``C7.2.376 UQRSHRN``() =
    check "2f1f9c20" []
      [ [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffffff0000UL, 0x0UL); Fpsr 0x8000000UL ] ]
    check "2f3f9c20" []
      [ [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ] ]
    check "2f0f9c20" []
      [ [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xff00ff00ff00ff00UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffff000000UL, 0x0UL); Fpsr 0x8000000UL ] ]

  /// C7.2.376 UQRSHRN, UQRSHRN2
  [<TestMethod>]
  member _.``C7.2.376 UQRSHRN2``() =
    check "6f1f9c20" []
      [ [ Q(0, 0x962b1967c90789baUL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xbfc000003f800000UL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ff0000000000000UL, 0xffffffffffff0000UL); Fpsr 0x8000000UL ] ]
    check "6f3f9c20" []
      [ [ Q(0, 0x962b1967c90789baUL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xbfc000003f800000UL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ff0000000000000UL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ] ]
    check "6f0f9c20" []
      [ [ Q(0, 0x962b1967c90789baUL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xbfc000003f800000UL, 0xff00ff00ff00ff00UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ff0000000000000UL, 0xffffffffff000000UL); Fpsr 0x8000000UL ] ]

  /// C7.2.377 UQSHL (immediate)
  [<TestMethod>]
  member _.``C7.2.377 UQSHL``() =
    check "2f097420" []
      [ [ Q(0, 0xe0c2de5e90ffff38UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xaeffff4abe1eff48UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xfeff0000ff000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x8010000000000000UL, 0x0UL) ] ]
    check "6f097420" []
      [ [ Q(0, 0xe0c2de5e90ffff38UL, 0x80ffff9c5cffff2eUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xaeffff4abe1eff48UL, 0xff6236a6be3effffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xfeff0000ff000000UL, 0xfeff0000feff0000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x8010000000000000UL, 0x7effffffffffffffUL); Fpsr 0x8000000UL ] ]
    check "2f117420" []
      [ [ Q(0, 0xe0c2de5e91b8ffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xaf90ffffbe1effffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xff000000ffff0000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x8010000000000000UL, 0x0UL) ] ]
    check "6f117420" []
      [ [ Q(0, 0xe0c2de5e91b8ffffUL, 0x81acffff5de6ffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xaf90ffffbe1effffUL, 0xffff36a6be3effffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xff000000ffff0000UL, 0xff400000ff800000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x8010000000000000UL, 0x7f72ffffffffffffUL); Fpsr 0x8000000UL ] ]
    check "2f217420" []
      [ [ Q(0, 0xe0c2de5e91b9c038UL, 0x0UL) ]
        [ Q(0, 0xaf91064abe1f3c48UL, 0x0UL) ]
        [ Q(0, 0xff000000ffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x8010000000000000UL, 0x0UL) ] ]
    check "6f217420" []
      [ [ Q(0, 0xe0c2de5e91b9c038UL, 0x81ad049c5de7f82eUL) ]
        [ Q(0, 0xaf91064abe1f3c48UL, 0xffffffffbe3f6152UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xff000000ffffffffUL, 0xff400000ff800000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x8010000000000000UL, 0x7f733332ffffffffUL); Fpsr 0x8000000UL ] ]
    check "6f417420" []
      [ [ Q(0, 0xe0c2de5e91b9c038UL, 0x81ad049c5de7f82eUL) ]
        [ Q(0, 0xaf91064abe1f3c48UL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xff00000100000000UL, 0xff400000ff800000UL) ]
        [ Q(0, 0x8010000000000000UL, 0x7f73333333333334UL) ] ]
    check "2e224c20" []
      [ [ Q(0, 0xffffff3770ffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffff00ff0000ff00UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xff000080000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x8000000000000UL, 0x0UL) ] ]
    check "2e624c20" []
      [ [ Q(0, 0xffff1237ffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffff000080000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "6e624c20" []
      [ [ Q(0, 0xffff1237ffffUL, 0xffffffffffff001fUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffff00000000UL, 0xffff006d0000ffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffff000080000000UL, 0xffff0000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x4008000000000000UL, 0x99999999999aUL) ] ]
    check "2ea24c20" []
      [ [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3fc00000ffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "6ea24c20" []
      [ [ Q(0, 0xffffffffffffffffUL, 0xffffffff0005de7fUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffff00000000UL, 0x388c46dffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3fc00000ffffffffUL, 0x7fa000003fe00000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x4008000000000000UL, 0x3fb999999999999aUL) ] ]
    check "6ee24c20" []
      [ [ Q(0, 0xffffffffffffffffUL, 0x81ad049c5de7fUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x2be44UL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xff00000100000000UL, 0x3fd000003fe00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fb999999999999aUL) ] ]
    check "6e224c20" []
      [ [ Q(0, 0xffffff3770ffUL, 0xffffffffff0000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffff00ff0000ff00UL, 0xffffff01000000ffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xff000080000000UL, 0x7f000000ffff0000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x8000000000000UL, 0xff0099999999999aUL); Fpsr 0x8000000UL ] ]

  /// C7.2.379 UQSHRN, UQSHRN2
  [<TestMethod>]
  member _.``C7.2.379 UQSHRN``() =
    check "2f1f9420" []
      [ [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffffff0000UL, 0x0UL); Fpsr 0x8000000UL ] ]
    check "2f3f9420" []
      [ [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ] ]
    check "2f0f9420" []
      [ [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xff00ff00ff00ff00UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffff000000UL, 0x0UL); Fpsr 0x8000000UL ] ]

  /// C7.2.379 UQSHRN, UQSHRN2
  [<TestMethod>]
  member _.``C7.2.379 UQSHRN2``() =
    check "6f1f9420" []
      [ [ Q(0, 0x962b1967c90789baUL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xbfc000003f800000UL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ff0000000000000UL, 0xffffffffffff0000UL); Fpsr 0x8000000UL ] ]
    check "6f3f9420" []
      [ [ Q(0, 0x962b1967c90789baUL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xbfc000003f800000UL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ff0000000000000UL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ] ]
    check "6f0f9420" []
      [ [ Q(0, 0x962b1967c90789baUL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xbfc000003f800000UL, 0xff00ff00ff00ff00UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ff0000000000000UL, 0xffffffffff000000UL); Fpsr 0x8000000UL ] ]

  /// C7.2.380 UQSUB
  [<TestMethod>]
  member _.``C7.2.380 UQSUB``() =
    check "2e222c20" []
      [ [ Q(0, 0x410d00000010UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7b000000004100UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x1000080000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x8000000000000UL, 0x0UL); Fpsr 0x8000000UL ] ]
    check "2e622c20" []
      [ [ Q(0, 0x410d00000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x4051UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x80000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x8000000UL ] ]
    check "6e622c20" []
      [ [ Q(0, 0x410d00000000UL, 0x800a00001b22UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x4051UL, 0x9ad100000000146dUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x80000000UL, 0x7f20000000410000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x0UL, 0x99999999999aUL); Fpsr 0x8000000UL ] ]
    check "2ea22c20" []
      [ [ Q(0, 0x0UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x8000000UL ] ]
    check "6ea22c20" []
      [ [ Q(0, 0x0UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x0UL, 0x9ad0f05900000000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7fffffffUL, 0x7f20000000400001UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x0UL, 0x9999999aUL); Fpsr 0x8000000UL ] ]
    check "6ee22c20" []
      [ [ Q(0, 0x0UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x0UL, 0x9ad0f0587e46146dUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x0UL, 0x7f20000000400001UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x0UL, 0x0UL); Fpsr 0x8000000UL ] ]
    check "6e222c20" []
      [ [ Q(0, 0x410d00000010UL, 0xa8800a00a81c00UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7b000000004100UL, 0x9b0000000000146dUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x1000080000000UL, 0x7f20000000410000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x8000000000000UL, 0x99999999999aUL); Fpsr 0x8000000UL ] ]

  /// C7.2.381 UQXTN, UQXTN2
  [<TestMethod>]
  member _.``C7.2.381 UQXTN``() =
    check "2e214820" []
      [ [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xff00ff00ff00ff00UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffff000000UL, 0x0UL); Fpsr 0x8000000UL ] ]
    check "2ea14820" []
      [ [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ] ]
    check "2e614820" []
      [ [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xffffffffffff0000UL, 0x0UL); Fpsr 0x8000000UL ] ]

  /// C7.2.381 UQXTN, UQXTN2
  [<TestMethod>]
  member _.``C7.2.381 UQXTN2``() =
    check "6e614820" []
      [ [ Q(0, 0x962b1967c90789baUL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xbfc000003f800000UL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ff0000000000000UL, 0xffffffffffff0000UL); Fpsr 0x8000000UL ] ]
    check "6ea14820" []
      [ [ Q(0, 0x962b1967c90789baUL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xbfc000003f800000UL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ff0000000000000UL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ] ]
    check "6e214820" []
      [ [ Q(0, 0x962b1967c90789baUL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0xffffffffffffffffUL); Fpsr 0x8000000UL ]
        [ Q(0, 0xbfc000003f800000UL, 0xff00ff00ff00ff00UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x3ff0000000000000UL, 0xffffffffff000000UL); Fpsr 0x8000000UL ] ]

  /// C7.2.382 URECPE
  [<TestMethod>]
  member _.``C7.2.382 URECPE``() =
    check "0ea1c820" []
      [ [ Q(0, 0xffffffffffffffffUL, 0x0UL) ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ]
        [ Q(0, 0xffffffffff800000UL, 0x0UL) ]
        [ Q(0, 0xffffffffffffffffUL, 0x0UL) ] ]
    check "4ea1c820" []
      [ [ Q(0, 0xffffffffffffffffUL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0x91000000ffffffffUL) ]
        [ Q(0, 0xffffffffff800000UL, 0xffffffffffffffffUL) ]
        [ Q(0, 0xffffffffffffffffUL, 0xffffffffd5000000UL) ] ]

  /// C7.2.383 URHADD
  [<TestMethod>]
  member _.``C7.2.383 URHADD``() =
    check "2e221420" []
      [ [ Q(0, 0x7c804f294fedf014UL, 0x0UL) ]
        [ Q(0, 0x588b984da4707e7cUL, 0x0UL) ]
        [ Q(0, 0x8080808040000001UL, 0x0UL) ]
        [ Q(0, 0x6004000000000000UL, 0x0UL) ] ]
    check "6e221420" []
      [ [ Q(0, 0x7c804f294fedf014UL, 0x66824249469fee86UL) ]
        [ Q(0, 0x588b984da4707e7cUL, 0x954923a7a07ca673UL) ]
        [ Q(0, 0x8080808040000001UL, 0x409000007fa08080UL) ]
        [ Q(0, 0x6004000000000000UL, 0x5fd54d4d4d4d4d4dUL) ] ]
    check "2e621420" []
      [ [ Q(0, 0x7c004ea94fedef94UL, 0x0UL) ]
        [ Q(0, 0x588b97cda4707dfcUL, 0x0UL) ]
        [ Q(0, 0x8000800040000001UL, 0x0UL) ]
        [ Q(0, 0x6004000000000000UL, 0x0UL) ] ]
    check "6e621420" []
      [ [ Q(0, 0x7c004ea94fedef94UL, 0x66024249469fee86UL) ]
        [ Q(0, 0x588b97cda4707dfcUL, 0x94c923279ffca673UL) ]
        [ Q(0, 0x8000800040000001UL, 0x401000007fa08000UL) ]
        [ Q(0, 0x6004000000000000UL, 0x5fd54ccd4ccd4ccdUL) ] ]
    check "2ea21420" []
      [ [ Q(0, 0x7bffcea94fedef94UL, 0x0UL) ]
        [ Q(0, 0x588b17cda46ffdfcUL, 0x0UL) ]
        [ Q(0, 0x8000000040000001UL, 0x0UL) ]
        [ Q(0, 0x6004000000000000UL, 0x0UL) ] ]
    check "6ea21420" []
      [ [ Q(0, 0x7bffcea94fedef94UL, 0x66024249469fee86UL) ]
        [ Q(0, 0x588b17cda46ffdfcUL, 0x94c8a3279ffca673UL) ]
        [ Q(0, 0x8000000040000001UL, 0x401000007fa00000UL) ]
        [ Q(0, 0x6004000000000000UL, 0x5fd4cccd4ccccccdUL) ] ]

  /// C7.2.384 URSHL
  [<TestMethod>]
  member _.``C7.2.384 URSHL``() =
    check "2e225420" []
      [ [ Q(0, 0x377000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x80000000UL, 0x0UL) ]
        [ Q(0, 0x8000000000000UL, 0x0UL) ] ]
    check "2e625420" []
      [ [ Q(0, 0x1237c000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x80000000UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "6e625420" []
      [ [ Q(0, 0x1237c000UL, 0x20UL) ]
        [ Q(0, 0x0UL, 0x6d00000000UL) ]
        [ Q(0, 0x80000000UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x99999999999aUL) ] ]
    check "2ea25420" []
      [ [ Q(0, 0xce01c000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x3fc0000000000000UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "6ea25420" []
      [ [ Q(0, 0xce01c000UL, 0x5de80UL) ]
        [ Q(0, 0x0UL, 0x388c46d00000000UL) ]
        [ Q(0, 0x3fc0000000000000UL, 0x7fa000003fe00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fb999999999999aUL) ] ]
    check "6ee25420" []
      [ [ Q(0, 0x16f2f48dce01c000UL, 0x81ad049c5de80UL) ]
        [ Q(0, 0x2be44UL, 0x9000000000000000UL) ]
        [ Q(0, 0xff00000100000000UL, 0x3fd000003fe00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fb999999999999aUL) ] ]
    check "6e225420" []
      [ [ Q(0, 0x377000UL, 0x80000000000UL) ]
        [ Q(0, 0x0UL, 0x100000000UL) ]
        [ Q(0, 0x80000000UL, 0x7f00000000000000UL) ]
        [ Q(0, 0x8000000000000UL, 0x99999999999aUL) ] ]

  /// C7.2.385 URSHR
  [<TestMethod>]
  member _.``C7.2.385 URSHR``() =
    check "2f0f2420" []
      [ [ Q(0, 0x38313818246e700eUL, 0x0UL) ]
        [ Q(0, 0x2c64421330084f12UL, 0x0UL) ]
        [ Q(0, 0x4040000040000000UL, 0x0UL) ]
        [ Q(0, 0x2004000000000000UL, 0x0UL) ] ]
    check "6f0f2420" []
      [ [ Q(0, 0x38313818246e700eUL, 0x206b4127177a7e0cUL) ]
        [ Q(0, 0x2c64421330084f12UL, 0x71190e2a30105855UL) ]
        [ Q(0, 0x4040000040000000UL, 0x4050000040600000UL) ]
        [ Q(0, 0x2004000000000000UL, 0x205d4d4d4d4d4d4dUL) ] ]
    check "2f1f2420" []
      [ [ Q(0, 0x38313798246e700eUL, 0x0UL) ]
        [ Q(0, 0x2be441932f884f12UL, 0x0UL) ]
        [ Q(0, 0x3fc0000040000000UL, 0x0UL) ]
        [ Q(0, 0x2004000000000000UL, 0x0UL) ] ]
    check "6f1f2420" []
      [ [ Q(0, 0x38313798246e700eUL, 0x206b4127177a7e0cUL) ]
        [ Q(0, 0x2be441932f884f12UL, 0x71190daa2f905855UL) ]
        [ Q(0, 0x3fc0000040000000UL, 0x3fd000003fe00000UL) ]
        [ Q(0, 0x2004000000000000UL, 0x1fdd4ccd4ccd4ccdUL) ] ]
    check "2f3f2420" []
      [ [ Q(0, 0x3830b798246e700eUL, 0x0UL) ]
        [ Q(0, 0x2be441932f87cf12UL, 0x0UL) ]
        [ Q(0, 0x3fc0000040000000UL, 0x0UL) ]
        [ Q(0, 0x2004000000000000UL, 0x0UL) ] ]
    check "6f3f2420" []
      [ [ Q(0, 0x3830b798246e700eUL, 0x206b41271779fe0cUL) ]
        [ Q(0, 0x2be441932f87cf12UL, 0x71188daa2f8fd855UL) ]
        [ Q(0, 0x3fc0000040000000UL, 0x3fd000003fe00000UL) ]
        [ Q(0, 0x2004000000000000UL, 0x1fdccccd4ccccccdUL) ] ]
    check "6f7f2420" []
      [ [ Q(0, 0x3830b797a46e700eUL, 0x206b41271779fe0cUL) ]
        [ Q(0, 0x2be44192af87cf12UL, 0x71188da9af8fd855UL) ]
        [ Q(0, 0x3fc0000040000000UL, 0x3fd000003fe00000UL) ]
        [ Q(0, 0x2004000000000000UL, 0x1fdccccccccccccdUL) ] ]
    check "6f3d2420" []
      [ [ Q(0, 0xe0c2de6091b9c04UL, 0x81ad04a05de7f83UL) ]
        [ Q(0, 0xaf910650be1f3c5UL, 0x1c46236a0be3f615UL) ]
        [ Q(0, 0xff0000010000000UL, 0xff400000ff80000UL) ]
        [ Q(0, 0x801000000000000UL, 0x7f7333313333333UL) ] ]

  /// C7.2.386 URSQRTE
  [<TestMethod>]
  member _.``C7.2.386 URSQRTE``() =
    check "2ea1c820" []
      [ [ Q(0, 0xc1800000f0000000UL, 0x0UL) ]
        [ Q(0, 0xda800000d2000000UL, 0x0UL) ]
        [ Q(0, 0xb5000000b4800000UL, 0x0UL) ]
        [ Q(0, 0xff800000ffffffffUL, 0x0UL) ] ]
    check "6ea1c820" []
      [ [ Q(0, 0xc1800000f0000000UL, 0xfe800000ffffffffUL) ]
        [ Q(0, 0xda800000d2000000UL, 0x88000000d2000000UL) ]
        [ Q(0, 0xb5000000b4800000UL, 0xb5000000b5000000UL) ]
        [ Q(0, 0xff800000ffffffffUL, 0xffffffffa5800000UL) ] ]

  /// C7.2.387 URSRA
  [<TestMethod>]
  member _.``C7.2.387 URSRA``() =
    check "2f0f3420" []
      [ [ Q(0, 0xce5c517fed75f9c8UL, 0x0UL) ]
        [ Q(0, 0xc6dee93760011967UL, 0x0UL) ]
        [ Q(0, 0xff0000007f800000UL, 0x0UL) ]
        [ Q(0, 0x5ff4000000000000UL, 0x0UL) ] ]
    check "2f1f3420" []
      [ [ Q(0, 0xce5c50ffed75f9c8UL, 0x0UL) ]
        [ Q(0, 0xc65ee8b760811967UL, 0x0UL) ]
        [ Q(0, 0xff8000007f800000UL, 0x0UL) ]
        [ Q(0, 0x5ff4000000000000UL, 0x0UL) ] ]
    check "6f1f3420" []
      [ [ Q(0, 0xce5c50ffed75f9c8UL, 0x8617238f7181aa79UL) ]
        [ Q(0, 0xc65ee8b760811967UL, 0xb564d864524bc164UL) ]
        [ Q(0, 0xff8000007f800000UL, 0x7d9ccccd80200000UL) ]
        [ Q(0, 0x5ff4000000000000UL, 0xdfd54ccd4ccd4ccdUL) ] ]
    check "2f3f3420" []
      [ [ Q(0, 0xce5bd0ffed75f9c8UL, 0x0UL) ]
        [ Q(0, 0xc65ee8b760819967UL, 0x0UL) ]
        [ Q(0, 0xff8000007f800000UL, 0x0UL) ]
        [ Q(0, 0x5ff4000000000000UL, 0x0UL) ] ]
    check "6f3f3420" []
      [ [ Q(0, 0xce5bd0ffed75f9c8UL, 0x8618238f71812a79UL) ]
        [ Q(0, 0xc65ee8b760819967UL, 0xb5645864524b4164UL) ]
        [ Q(0, 0xff8000007f800000UL, 0x7d9ccccd80200000UL) ]
        [ Q(0, 0x5ff4000000000000UL, 0xdfd4cccd4ccccccdUL) ] ]
    check "6f7f3420" []
      [ [ Q(0, 0xce5bd0ff6d75f9c8UL, 0x8618238f71812a79UL) ]
        [ Q(0, 0xc65ee8b6e0819967UL, 0xb5645863d24b4164UL) ]
        [ Q(0, 0xff8000007f800000UL, 0x7d9ccccd80200000UL) ]
        [ Q(0, 0x5ff4000000000000UL, 0xdfd4cccccccccccdUL) ] ]
    check "6f0f3420" []
      [ [ Q(0, 0xce5c517fed75f9c8UL, 0x8517238f7181aa79UL) ]
        [ Q(0, 0xc6dee93760011967UL, 0xb564d8e452cbc164UL) ]
        [ Q(0, 0xff0000007f800000UL, 0x7d1ccccd80a00000UL) ]
        [ Q(0, 0x5ff4000000000000UL, 0xdf554d4d4d4d4d4dUL) ] ]

  /// C7.2.388 USDOT (vector)
  [<TestMethod>]
  member _.``C7.2.388 USDOT``() =
    check "0e829c20" []
      [ [ Q(0, 0x962ad985c907a0a2UL, 0x0UL) ]
        [ Q(0, 0x9a7ae75330f9f20eUL, 0x0UL) ]
        [ Q(0, 0xbfc000003f800000UL, 0x0UL) ]
        [ Q(0, 0x3fefe00000000000UL, 0x0UL) ] ]

  /// C7.2.390 USHL
  [<TestMethod>]
  member _.``C7.2.390 USHL``() =
    check "2e224420" []
      [ [ Q(0, 0x377000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x80000000UL, 0x0UL) ]
        [ Q(0, 0x8000000000000UL, 0x0UL) ] ]
    check "2e624420" []
      [ [ Q(0, 0x1237c000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x80000000UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "6e624420" []
      [ [ Q(0, 0x1237c000UL, 0x1fUL) ]
        [ Q(0, 0x0UL, 0x6d00000000UL) ]
        [ Q(0, 0x80000000UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x99999999999aUL) ] ]
    check "2ea24420" []
      [ [ Q(0, 0xce01c000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x3fc0000000000000UL, 0x0UL) ]
        [ Q(0, 0x4008000000000000UL, 0x0UL) ] ]
    check "6ea24420" []
      [ [ Q(0, 0xce01c000UL, 0x5de7fUL) ]
        [ Q(0, 0x0UL, 0x388c46d00000000UL) ]
        [ Q(0, 0x3fc0000000000000UL, 0x7fa000003fe00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fb999999999999aUL) ] ]
    check "6ee24420" []
      [ [ Q(0, 0x16f2f48dce01c000UL, 0x81ad049c5de7fUL) ]
        [ Q(0, 0x2be44UL, 0x9000000000000000UL) ]
        [ Q(0, 0xff00000100000000UL, 0x3fd000003fe00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fb999999999999aUL) ] ]
    check "6e224420" []
      [ [ Q(0, 0x377000UL, 0x80000000000UL) ]
        [ Q(0, 0x0UL, 0x100000000UL) ]
        [ Q(0, 0x80000000UL, 0x7f00000000000000UL) ]
        [ Q(0, 0x8000000000000UL, 0x99999999999aUL) ] ]

  /// C7.2.391 USHLL, USHLL2
  [<TestMethod>]
  member _.``C7.2.391 USHLL``() =
    check "2f11a420" []
      [ [ Q(0, 0x91b80001c038UL, 0xe0c20000de5eUL) ]
        [ Q(0, 0xbe1e00013c48UL, 0xaf900001064aUL) ]
        [ Q(0, 0x1000000000000UL, 0xff0000000000UL) ]
        [ Q(0, 0x0UL, 0x801000000000UL) ] ]
    check "2f10a420" []
      [ [ Q(0, 0x48dc0000e01cUL, 0x706100006f2fUL) ]
        [ Q(0, 0x5f0f00009e24UL, 0x57c800008325UL) ]
        [ Q(0, 0x800000000000UL, 0x7f8000000000UL) ]
        [ Q(0, 0x0UL, 0x400800000000UL) ] ]
    check "2f09a420" []
      [ [ Q(0, 0x9001b801c00038UL, 0xe000c200de005eUL) ]
        [ Q(0, 0xbe001e013c0048UL, 0xae01900106004aUL) ]
        [ Q(0, 0x100000000000000UL, 0xfe010000000000UL) ]
        [ Q(0, 0x0UL, 0x80001000000000UL) ] ]
    check "2f21a420" []
      [ [ Q(0, 0x91b9c038UL, 0xe0c2de5eUL) ]
        [ Q(0, 0xbe1f3c48UL, 0xaf91064aUL) ]
        [ Q(0, 0x100000000UL, 0xff000000UL) ]
        [ Q(0, 0x0UL, 0x80100000UL) ] ]
    check "2f08a420" []
      [ [ Q(0, 0x4800dc00e0001cUL, 0x700061006f002fUL) ]
        [ Q(0, 0x5f000f009e0024UL, 0x5700c800830025UL) ]
        [ Q(0, 0x80000000000000UL, 0x7f008000000000UL) ]
        [ Q(0, 0x0UL, 0x40000800000000UL) ] ]
    check "2f20a420" []
      [ [ Q(0, 0x48dce01cUL, 0x70616f2fUL) ]
        [ Q(0, 0x5f0f9e24UL, 0x57c88325UL) ]
        [ Q(0, 0x80000000UL, 0x7f800000UL) ]
        [ Q(0, 0x0UL, 0x40080000UL) ] ]

  /// C7.2.391 USHLL, USHLL2
  [<TestMethod>]
  member _.``C7.2.391 USHLL2``() =
    check "6f09a420" []
      [ [ Q(0, 0x5c01e601f8002eUL, 0x8001ac0104009cUL) ]
        [ Q(0, 0xbe003e01600152UL, 0x1c40062003600a6UL) ]
        [ Q(0, 0xfe018000000000UL, 0xfe014000000000UL) ]
        [ Q(0, 0x132013201320134UL, 0x7e017201320132UL) ] ]
    check "6f11a420" []
      [ [ Q(0, 0x5de60001f82eUL, 0x81ac0001049cUL) ]
        [ Q(0, 0xbe3e00016152UL, 0x1c462000036a6UL) ]
        [ Q(0, 0xff8000000000UL, 0xff4000000000UL) ]
        [ Q(0, 0x1333200013334UL, 0x7f7200013332UL) ] ]
    check "6f21a420" []
      [ [ Q(0, 0x5de7f82eUL, 0x81ad049cUL) ]
        [ Q(0, 0xbe3f6152UL, 0x1c46236a6UL) ]
        [ Q(0, 0xff800000UL, 0xff400000UL) ]
        [ Q(0, 0x133333334UL, 0x7f733332UL) ] ]
    check "6f08a420" []
      [ [ Q(0, 0x2e00f300fc0017UL, 0x4000d60082004eUL) ]
        [ Q(0, 0x5f001f00b000a9UL, 0xe20031001b0053UL) ]
        [ Q(0, 0x7f00c000000000UL, 0x7f00a000000000UL) ]
        [ Q(0, 0x9900990099009aUL, 0x3f00b900990099UL) ] ]
    check "6f20a420" []
      [ [ Q(0, 0x2ef3fc17UL, 0x40d6824eUL) ]
        [ Q(0, 0x5f1fb0a9UL, 0xe2311b53UL) ]
        [ Q(0, 0x7fc00000UL, 0x7fa00000UL) ]
        [ Q(0, 0x9999999aUL, 0x3fb99999UL) ] ]
    check "6f19a420" []
      [ [ Q(0, 0x5de60001f82e00UL, 0x81ac0001049c00UL) ]
        [ Q(0, 0xbe3e0001615200UL, 0x1c462000036a600UL) ]
        [ Q(0, 0xff800000000000UL, 0xff400000000000UL) ]
        [ Q(0, 0x133320001333400UL, 0x7f720001333200UL) ] ]
    check "6f10a420" []
      [ [ Q(0, 0x2ef30000fc17UL, 0x40d60000824eUL) ]
        [ Q(0, 0x5f1f0000b0a9UL, 0xe23100001b53UL) ]
        [ Q(0, 0x7fc000000000UL, 0x7fa000000000UL) ]
        [ Q(0, 0x99990000999aUL, 0x3fb900009999UL) ] ]

  /// C7.2.392 USHR
  [<TestMethod>]
  member _.``C7.2.392 USHR``() =
    check "2f0f0420" []
      [ [ Q(0, 0x38303717246e700eUL, 0x0UL) ]
        [ Q(0, 0x2b6441122f074f12UL, 0x0UL) ]
        [ Q(0, 0x3f40000040000000UL, 0x0UL) ]
        [ Q(0, 0x2004000000000000UL, 0x0UL) ] ]
    check "2f1f0420" []
      [ [ Q(0, 0x38303797246e700eUL, 0x0UL) ]
        [ Q(0, 0x2be441922f874f12UL, 0x0UL) ]
        [ Q(0, 0x3fc0000040000000UL, 0x0UL) ]
        [ Q(0, 0x2004000000000000UL, 0x0UL) ] ]
    check "6f1f0420" []
      [ [ Q(0, 0x38303797246e700eUL, 0x206b412717797e0bUL) ]
        [ Q(0, 0x2be441922f874f12UL, 0x71180da92f8f5854UL) ]
        [ Q(0, 0x3fc0000040000000UL, 0x3fd000003fe00000UL) ]
        [ Q(0, 0x2004000000000000UL, 0x1fdc4ccc4ccc4ccdUL) ] ]
    check "2f3f0420" []
      [ [ Q(0, 0x3830b797246e700eUL, 0x0UL) ]
        [ Q(0, 0x2be441922f87cf12UL, 0x0UL) ]
        [ Q(0, 0x3fc0000040000000UL, 0x0UL) ]
        [ Q(0, 0x2004000000000000UL, 0x0UL) ] ]
    check "6f3f0420" []
      [ [ Q(0, 0x3830b797246e700eUL, 0x206b41271779fe0bUL) ]
        [ Q(0, 0x2be441922f87cf12UL, 0x71188da92f8fd854UL) ]
        [ Q(0, 0x3fc0000040000000UL, 0x3fd000003fe00000UL) ]
        [ Q(0, 0x2004000000000000UL, 0x1fdccccc4ccccccdUL) ] ]
    check "6f7f0420" []
      [ [ Q(0, 0x3830b797a46e700eUL, 0x206b41271779fe0bUL) ]
        [ Q(0, 0x2be44192af87cf12UL, 0x71188da9af8fd854UL) ]
        [ Q(0, 0x3fc0000040000000UL, 0x3fd000003fe00000UL) ]
        [ Q(0, 0x2004000000000000UL, 0x1fdccccccccccccdUL) ] ]
    check "6f0f0420" []
      [ [ Q(0, 0x38303717246e700eUL, 0x206b412717797e0bUL) ]
        [ Q(0, 0x2b6441122f074f12UL, 0x71180d292f0f5854UL) ]
        [ Q(0, 0x3f40000040000000UL, 0x3f5000003f600000UL) ]
        [ Q(0, 0x2004000000000000UL, 0x1f5c4c4c4c4c4c4dUL) ] ]

  /// C7.2.393 USMMLA (vector)
  [<TestMethod>]
  member _.``C7.2.393 USMMLA``() =
    check "4e82ac20" []
      [ [ Q(0, 0x962b42afc90760c0UL, 0x65ad38f05a06eb9fUL) ]
        [ Q(0, 0x9a7adb7430fa323dUL, 0x444bf08722bbf700UL) ]
        [ Q(0, 0xbfbfff803f800000UL, 0x3dcd1b0e40400fe0UL) ]
        [ Q(0, 0x3ff01f40ffffe000UL, 0xbff813b1ffffe080UL) ] ]

  /// C7.2.394 USQADD
  [<TestMethod>]
  member _.``C7.2.394 USQADD``() =
    check "2e203820" []
      [ [ Q(0, 0xff8c8896ff0069d6UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xf1422a498fff6879UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xff40000000800000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7ff8000000000000UL, 0x0UL) ] ]
    check "6e203820" []
      [ [ Q(0, 0xff8c8896ff0069d6UL, 0xa58264b688002884UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xf1422a498fff6879UL, 0x267ce5ff81da1900UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xff40000000800000UL, 0xbc6ccccdbf000000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7ff8000000000000UL, 0xfeb1000000000000UL); Fpsr 0x8000000UL ] ]
    check "2e603820" []
      [ [ Q(0, 0xffff8896ffff69d6UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xf2422a4990086879UL, 0x0UL) ]
        [ Q(0, 0xffff000000000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7ff8000000000000UL, 0x0UL) ] ]
    check "6e603820" []
      [ [ Q(0, 0xffff8896ffff69d6UL, 0xa68264b688fa2884UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xf2422a4990086879UL, 0x267ce60d81da19b8UL) ]
        [ Q(0, 0xffff000000000000UL, 0xbd6ccccdc0000000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7ff8000000000000UL, 0xffb1000000000000UL); Fpsr 0x8000000UL ] ]
    check "2ea03820" []
      [ [ Q(0, 0xffffffffffffffffUL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xf2432a4990096879UL, 0x0UL) ]
        [ Q(0, 0xffffffff00000000UL, 0x0UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7ff8000000000000UL, 0x0UL) ] ]
    check "6ee03820" []
      [ [ Q(0, 0xffffffffffffffffUL, 0xa68364b688fb2884UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xf2432a4990096879UL, 0x267ce60d81db19b8UL) ]
        [ Q(0, 0xffffffffffffffffUL, 0xbd6ccccdc0000000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7ff8000000000000UL, 0xffb199999999999aUL) ] ]
    check "6ea03820" []
      [ [ Q(0, 0xffffffffffffffffUL, 0xa68364b688fb2884UL); Fpsr 0x8000000UL ]
        [ Q(0, 0xf2432a4990096879UL, 0x267ce60d81db19b8UL) ]
        [ Q(0, 0xffffffff00000000UL, 0xbd6ccccdc0000000UL); Fpsr 0x8000000UL ]
        [ Q(0, 0x7ff8000000000000UL, 0xffb1999900000000UL); Fpsr 0x8000000UL ] ]

  /// C7.2.395 USRA
  [<TestMethod>]
  member _.``C7.2.395 USRA``() =
    check "2f0f1420" []
      [ [ Q(0, 0xce5b507eed75f9c8UL, 0x0UL) ]
        [ Q(0, 0xc5dee8365f001967UL, 0x0UL) ]
        [ Q(0, 0xfe0000007f800000UL, 0x0UL) ]
        [ Q(0, 0x5ff4000000000000UL, 0x0UL) ] ]
    check "2f1f1420" []
      [ [ Q(0, 0xce5b50feed75f9c8UL, 0x0UL) ]
        [ Q(0, 0xc65ee8b660801967UL, 0x0UL) ]
        [ Q(0, 0xff8000007f800000UL, 0x0UL) ]
        [ Q(0, 0x5ff4000000000000UL, 0x0UL) ] ]
    check "6f1f1420" []
      [ [ Q(0, 0xce5b50feed75f9c8UL, 0x8617238f7180aa78UL) ]
        [ Q(0, 0xc65ee8b660801967UL, 0xb563d863524ac163UL) ]
        [ Q(0, 0xff8000007f800000UL, 0x7d9ccccd80200000UL) ]
        [ Q(0, 0x5ff4000000000000UL, 0xdfd44ccc4ccc4ccdUL) ] ]
    check "2f3f1420" []
      [ [ Q(0, 0xce5bd0feed75f9c8UL, 0x0UL) ]
        [ Q(0, 0xc65ee8b660819967UL, 0x0UL) ]
        [ Q(0, 0xff8000007f800000UL, 0x0UL) ]
        [ Q(0, 0x5ff4000000000000UL, 0x0UL) ] ]
    check "6f3f1420" []
      [ [ Q(0, 0xce5bd0feed75f9c8UL, 0x8618238f71812a78UL) ]
        [ Q(0, 0xc65ee8b660819967UL, 0xb5645863524b4163UL) ]
        [ Q(0, 0xff8000007f800000UL, 0x7d9ccccd80200000UL) ]
        [ Q(0, 0x5ff4000000000000UL, 0xdfd4cccc4ccccccdUL) ] ]
    check "6f7f1420" []
      [ [ Q(0, 0xce5bd0ff6d75f9c8UL, 0x8618238f71812a78UL) ]
        [ Q(0, 0xc65ee8b6e0819967UL, 0xb5645863d24b4163UL) ]
        [ Q(0, 0xff8000007f800000UL, 0x7d9ccccd80200000UL) ]
        [ Q(0, 0x5ff4000000000000UL, 0xdfd4cccccccccccdUL) ] ]
    check "6f0f1420" []
      [ [ Q(0, 0xce5b507eed75f9c8UL, 0x8517238f7180aa78UL) ]
        [ Q(0, 0xc5dee8365f001967UL, 0xb563d7e351cac163UL) ]
        [ Q(0, 0xfe0000007f800000UL, 0x7c1ccccd7fa00000UL) ]
        [ Q(0, 0x5ff4000000000000UL, 0xde544c4c4c4c4c4dUL) ] ]

  /// C7.2.396 USUBL, USUBL2
  [<TestMethod>]
  member _.``C7.2.396 USUBL``() =
    check "2e622020" []
      [ [ Q(0, 0xfffff1deffffe110UL, 0xffffe8c30000410dUL) ]
        [ Q(0, 0xffff753f00004051UL, 0xfffffe7bffffd6b1UL) ]
        [ Q(0, 0x8000ffffffffUL, 0xffffff01ffff0001UL) ]
        [ Q(0, 0x0UL, 0xffffc00800000000UL) ] ]
    check "2e222020" []
      [ [ Q(0, 0xfff2ffdeffe10010UL, 0xffe9ffc30041000dUL) ]
        [ Q(0, 0xff76ff3f0041ff51UL, 0xfffe007bffd7ffb1UL) ]
        [ Q(0, 0x8000000000ffffUL, 0xffff0001ff01ff01UL) ]
        [ Q(0, 0x0UL, 0xffc0000800000000UL) ] ]
    check "2ea22020" []
      [ [ Q(0, 0xfffffffff1dde110UL, 0xffffffffe8c3410dUL) ]
        [ Q(0, 0xffffffff753f4051UL, 0xfffffffffe7ad6b1UL) ]
        [ Q(0, 0x7fffffffUL, 0xffffffffff000001UL) ]
        [ Q(0, 0x0UL, 0xffffffffc0080000UL) ] ]

  /// C7.2.396 USUBL, USUBL2
  [<TestMethod>]
  member _.``C7.2.396 USUBL2``() =
    check "6e222020" []
      [ [ Q(0, 0xffd000a8001cff22UL, 0xffb500a80080000aUL) ]
        [ Q(0, 0xff7fff460014006dUL, 0x9bffd1fff1ff59UL) ]
        [ Q(0, 0x41ff01ff01UL, 0x7f002000000000UL) ]
        [ Q(0, 0x9900990099009aUL, 0xffc0ffc900990099UL) ] ]
    check "6ea22020" []
      [ [ Q(0, 0xffffffffd0a81b22UL, 0xffffffffb5a8800aUL) ]
        [ Q(0, 0xffffffff7e46146dUL, 0x9ad0f059UL) ]
        [ Q(0, 0x400001UL, 0x7f200000UL) ]
        [ Q(0, 0x9999999aUL, 0xffffffffbfc99999UL) ] ]
    check "6e622020" []
      [ [ Q(0, 0xffffd0a800001b22UL, 0xffffb5a80000800aUL) ]
        [ Q(0, 0xffff7e460000146dUL, 0x9ad1fffff059UL) ]
        [ Q(0, 0x41ffff0001UL, 0x7f2000000000UL) ]
        [ Q(0, 0x99990000999aUL, 0xffffbfc900009999UL) ] ]

  /// C7.2.397 USUBW, USUBW2
  [<TestMethod>]
  member _.``C7.2.397 USUBW``() =
    check "2e623020" []
      [ [ Q(0, 0x7061183148dbe110UL, 0x40d5fab02ef3cdf5UL) ]
        [ Q(0, 0x57c799555f0f4051UL, 0xe230c2065f1f0435UL) ]
        [ Q(0, 0x7f8000007fffffffUL, 0x7f9f7f817fbf0001UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fb919999999999aUL) ] ]
    check "2e223020" []
      [ [ Q(0, 0x700b6e3147dde010UL, 0x404f81b02ec5fbf5UL) ]
        [ Q(0, 0x56df82555eb29d51UL, 0xe1d81b065e73b035UL) ]
        [ Q(0, 0x7f8000008000ffffUL, 0x7f20ff817ec1ff01UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3f3999999999999aUL) ] ]
    check "2ea23020" []
      [ [ Q(0, 0x70616f2ef1dde110UL, 0x40d6824da755cdf5UL) ]
        [ Q(0, 0x57c88324753f4051UL, 0xe2311b5305d20435UL) ]
        [ Q(0, 0x7f8000007fffffffUL, 0x7f9fffffff400001UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fb999991999999aUL) ] ]

  /// C7.2.397 USUBW, USUBW2
  [<TestMethod>]
  member _.``C7.2.397 USUBW2``() =
    check "6e223020" []
      [ [ Q(0, 0x70036ee447fcdf27UL, 0x404b82202ef1fbd3UL) ]
        [ Q(0, 0x56e8824c5e739de8UL, 0xe1ea1af35ef5afafUL) ]
        [ Q(0, 0x7f01ff817f01ff01UL, 0x7fa0ff807fc00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3f3a98a99999999aUL) ] ]
    check "6ea23020" []
      [ [ Q(0, 0x70616f2eea90ff27UL, 0x40d6824da3c5f9d3UL) ]
        [ Q(0, 0x57c883247e3601e8UL, 0xe2311b5317bf85afUL) ]
        [ Q(0, 0x7f80000000800001UL, 0x7fa000007f400000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fb9999919a9999aUL) ] ]
    check "6e623020" []
      [ [ Q(0, 0x706110e448dbff27UL, 0x40d5f7202ef3f9d3UL) ]
        [ Q(0, 0x57c7a24c5f0f01e8UL, 0xe230d3f35f1f85afUL) ]
        [ Q(0, 0x7f7f80817fff0001UL, 0x7f9fff807fc00000UL) ]
        [ Q(0, 0x4008000000000000UL, 0x3fb919a99999999aUL) ] ]

  /// C7.2.398 UXTL, UXTL2
  [<TestMethod>]
  member _.``C7.2.398 UXTL``() =
    check "2f10a420" []
      [ [ Q(0, 0x48dc0000e01cUL, 0x706100006f2fUL) ]
        [ Q(0, 0x5f0f00009e24UL, 0x57c800008325UL) ]
        [ Q(0, 0x800000000000UL, 0x7f8000000000UL) ]
        [ Q(0, 0x0UL, 0x400800000000UL) ] ]
    check "2f08a420" []
      [ [ Q(0, 0x4800dc00e0001cUL, 0x700061006f002fUL) ]
        [ Q(0, 0x5f000f009e0024UL, 0x5700c800830025UL) ]
        [ Q(0, 0x80000000000000UL, 0x7f008000000000UL) ]
        [ Q(0, 0x0UL, 0x40000800000000UL) ] ]
    check "2f20a420" []
      [ [ Q(0, 0x48dce01cUL, 0x70616f2fUL) ]
        [ Q(0, 0x5f0f9e24UL, 0x57c88325UL) ]
        [ Q(0, 0x80000000UL, 0x7f800000UL) ]
        [ Q(0, 0x0UL, 0x40080000UL) ] ]

  /// C7.2.398 UXTL, UXTL2
  [<TestMethod>]
  member _.``C7.2.398 UXTL2``() =
    check "6f08a420" []
      [ [ Q(0, 0x2e00f300fc0017UL, 0x4000d60082004eUL) ]
        [ Q(0, 0x5f001f00b000a9UL, 0xe20031001b0053UL) ]
        [ Q(0, 0x7f00c000000000UL, 0x7f00a000000000UL) ]
        [ Q(0, 0x9900990099009aUL, 0x3f00b900990099UL) ] ]
    check "6f20a420" []
      [ [ Q(0, 0x2ef3fc17UL, 0x40d6824eUL) ]
        [ Q(0, 0x5f1fb0a9UL, 0xe2311b53UL) ]
        [ Q(0, 0x7fc00000UL, 0x7fa00000UL) ]
        [ Q(0, 0x9999999aUL, 0x3fb99999UL) ] ]
    check "6f10a420" []
      [ [ Q(0, 0x2ef30000fc17UL, 0x40d60000824eUL) ]
        [ Q(0, 0x5f1f0000b0a9UL, 0xe23100001b53UL) ]
        [ Q(0, 0x7fc000000000UL, 0x7fa000000000UL) ]
        [ Q(0, 0x99990000999aUL, 0x3fb900009999UL) ] ]

  /// C7.2.399 UZP1
  [<TestMethod>]
  member _.``C7.2.399 UZP1``() =
    check "0e021820" []
      [ [ Q(0, 0x9e22fe0c612fdc1cUL, 0x0UL) ]
        [ Q(0, 0x4d74d0d3c8250f24UL, 0x0UL) ]
        [ Q(0, 0x7fff000180000000UL, 0x0UL) ]
        [ Q(0, 0x8000000UL, 0x0UL) ] ]
    check "4e021820" []
      [ [ Q(0, 0xd64ef317612fdc1cUL, 0x2e444bf59e22fe0cUL) ]
        [ Q(0, 0x31531fa9c8250f24UL, 0x60fad93c4d74d0d3UL) ]
        [ Q(0, 0xa000c00080000000UL, 0x80007fff7fff0001UL) ]
        [ Q(0, 0xb999999a08000000UL, 0xf000000000000000UL) ] ]
    check "0e421820" []
      [ [ Q(0, 0x2e22ff0c6f2fe01cUL, 0x0UL) ]
        [ Q(0, 0xac745dd383259e24UL, 0x0UL) ]
        [ Q(0, 0xffff000100000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "4e421820" []
      [ [ Q(0, 0x824efc176f2fe01cUL, 0x244e0f52e22ff0cUL) ]
        [ Q(0, 0x1b53b0a983259e24UL, 0x2afa9c3cac745dd3UL) ]
        [ Q(0, 0x0UL, 0xffffffff0001UL) ]
        [ Q(0, 0x9999999a00000000UL, 0x0UL) ] ]
    check "0e821820" []
      [ [ Q(0, 0x56feff0c48dce01cUL, 0x0UL) ]
        [ Q(0, 0xe9d05dd35f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x180000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "4ec21820" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x879e2e2256feff0cUL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x594dac74e9d05dd3UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x807fffff00000001UL) ]
        [ Q(0, 0x4008000000000000UL, 0x8000000000000000UL) ] ]
    check "4e821820" []
      [ [ Q(0, 0x2ef3fc1748dce01cUL, 0x5e4be0f556feff0cUL) ]
        [ Q(0, 0x5f1fb0a95f0f9e24UL, 0xe0d99c3ce9d05dd3UL) ]
        [ Q(0, 0x7fc0000080000000UL, 0x7f7fffff00000001UL) ]
        [ Q(0, 0x9999999a00000000UL, 0x0UL) ] ]

  /// C7.2.400 UZP2
  [<TestMethod>]
  member _.``C7.2.400 UZP2``() =
    check "0e025820" []
      [ [ Q(0, 0x872e56ff706f48e0UL, 0x0UL) ]
        [ Q(0, 0x59ace95d57835f9eUL, 0x0UL) ]
        [ Q(0, 0x80ff00007f008000UL, 0x0UL) ]
        [ Q(0, 0x8000000040000000UL, 0x0UL) ] ]
    check "4e025820" []
      [ [ Q(0, 0x40822efc706f48e0UL, 0x8b025ee0872e56ffUL) ]
        [ Q(0, 0xe21b5fb057835f9eUL, 0x472ae09c59ace95dUL) ]
        [ Q(0, 0x7f007f007f008000UL, 0x7fff80ff0000UL) ]
        [ Q(0, 0x3f99999940000000UL, 0x7f00000080000000UL) ] ]
    check "0e425820" []
      [ [ Q(0, 0x879e56fe706148dcUL, 0x0UL) ]
        [ Q(0, 0x594de9d057c85f0fUL, 0x0UL) ]
        [ Q(0, 0x807f00007f808000UL, 0x0UL) ]
        [ Q(0, 0x8000000040080000UL, 0x0UL) ] ]
    check "4e425820" []
      [ [ Q(0, 0x40d62ef3706148dcUL, 0x8b2e5e4b879e56feUL) ]
        [ Q(0, 0xe2315f1f57c85f0fUL, 0x4760e0d9594de9d0UL) ]
        [ Q(0, 0x7fa07fc07f808000UL, 0x807f7f807f0000UL) ]
        [ Q(0, 0x3fb9999940080000UL, 0x7ff0000080000000UL) ] ]
    check "0e825820" []
      [ [ Q(0, 0x879e2e2270616f2fUL, 0x0UL) ]
        [ Q(0, 0x594dac7457c88325UL, 0x0UL) ]
        [ Q(0, 0x807fffff7f800000UL, 0x0UL) ]
        [ Q(0, 0x8000000040080000UL, 0x0UL) ] ]
    check "4ec25820" []
      [ [ Q(0, 0x40d6824e2ef3fc17UL, 0x8b2e02445e4be0f5UL) ]
        [ Q(0, 0xe2311b535f1fb0a9UL, 0x47602afae0d99c3cUL) ]
        [ Q(0, 0x7fa000007fc00000UL, 0x8000007f7fffffUL) ]
        [ Q(0, 0x3fb999999999999aUL, 0x7ff0000000000000UL) ] ]
    check "4e825820" []
      [ [ Q(0, 0x40d6824e70616f2fUL, 0x8b2e0244879e2e22UL) ]
        [ Q(0, 0xe2311b5357c88325UL, 0x47602afa594dac74UL) ]
        [ Q(0, 0x7fa000007f800000UL, 0x800000807fffffUL) ]
        [ Q(0, 0x3fb9999940080000UL, 0x7ff0000080000000UL) ] ]

  /// C7.2.401 XAR
  [<TestMethod>]
  member _.``C7.2.401 XAR``() =
    check "ce820c20" []
      [ [ Q(0, 0x1effe821a3c443e2UL, 0x597f10014e17039cUL) ]
        [ Q(0, 0xe1d0a5ea36dbf87eUL, 0xb4aa263537f8c592UL) ]
        [ Q(0, 0x3ffffffff0000000UL, 0xefe400000017ffffUL) ]
        [ Q(0, 0x1801000000000000UL, 0x4809333333333333UL) ] ]
    check "ce825c20" []
      [ [ Q(0, 0x443e21effe821a3cUL, 0x7039c597f10014e1UL) ]
        [ Q(0, 0xbf87ee1d0a5ea36dUL, 0x8c592b4aa263537fUL) ]
        [ Q(0, 0x3ffffffff00UL, 0x7ffffefe40000001UL) ]
        [ Q(0, 0x18010000000UL, 0x3333348093333333UL) ] ]

  /// C7.2.402 XTN, XTN2
  [<TestMethod>]
  member _.``C7.2.402 XTN``() =
    check "0e612820" []
      [ [ Q(0, 0x824efc176f2fe01cUL, 0x0UL) ]
        [ Q(0, 0x1b53b0a983259e24UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ]
        [ Q(0, 0x9999999a00000000UL, 0x0UL) ] ]
    check "0e212820" []
      [ [ Q(0, 0xd64ef317612fdc1cUL, 0x0UL) ]
        [ Q(0, 0x31531fa9c8250f24UL, 0x0UL) ]
        [ Q(0, 0xa000c00080000000UL, 0x0UL) ]
        [ Q(0, 0xb999999a08000000UL, 0x0UL) ] ]
    check "0ea12820" []
      [ [ Q(0, 0x2ef3fc1748dce01cUL, 0x0UL) ]
        [ Q(0, 0x5f1fb0a95f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x7fc0000080000000UL, 0x0UL) ]
        [ Q(0, 0x9999999a00000000UL, 0x0UL) ] ]

  /// C7.2.402 XTN, XTN2
  [<TestMethod>]
  member _.``C7.2.402 XTN2``() =
    check "4e212820" []
      [ [ Q(0, 0x962b1967c90789baUL, 0xd64ef317612fdc1cUL) ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0x31531fa9c8250f24UL) ]
        [ Q(0, 0xbfc000003f800000UL, 0xa000c00080000000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0xb999999a08000000UL) ] ]
    check "4ea12820" []
      [ [ Q(0, 0x962b1967c90789baUL, 0x2ef3fc1748dce01cUL) ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0x5f1fb0a95f0f9e24UL) ]
        [ Q(0, 0xbfc000003f800000UL, 0x7fc0000080000000UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x9999999a00000000UL) ] ]
    check "4e612820" []
      [ [ Q(0, 0x962b1967c90789baUL, 0x824efc176f2fe01cUL) ]
        [ Q(0, 0x9a7aa72430f9ca55UL, 0x1b53b0a983259e24UL) ]
        [ Q(0, 0xbfc000003f800000UL, 0x0UL) ]
        [ Q(0, 0x3ff0000000000000UL, 0x9999999a00000000UL) ] ]

  /// C7.2.403 ZIP1
  [<TestMethod>]
  member _.``C7.2.403 ZIP1``() =
    check "0e023820" []
      [ [ Q(0, 0x5648fedcffe00c1cUL, 0x0UL) ]
        [ Q(0, 0xe95fd00f5d9ed324UL, 0x0UL) ]
        [ Q(0, 0x80000000000100UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "4e023820" []
      [ [ Q(0, 0x5648fedcffe00c1cUL, 0x87709e612e6f222fUL) ]
        [ Q(0, 0xe95fd00f5d9ed324UL, 0x59574dc8ac837425UL) ]
        [ Q(0, 0x80000000000100UL, 0x807f7f80ff00ff00UL) ]
        [ Q(0, 0x0UL, 0x8040000800000000UL) ] ]
    check "0e423820" []
      [ [ Q(0, 0x56fe48dcff0ce01cUL, 0x0UL) ]
        [ Q(0, 0xe9d05f0f5dd39e24UL, 0x0UL) ]
        [ Q(0, 0x800000010000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "4e423820" []
      [ [ Q(0, 0x56fe48dcff0ce01cUL, 0x879e70612e226f2fUL) ]
        [ Q(0, 0xe9d05f0f5dd39e24UL, 0x594d57c8ac748325UL) ]
        [ Q(0, 0x800000010000UL, 0x807f7f80ffff0000UL) ]
        [ Q(0, 0x0UL, 0x8000400800000000UL) ] ]
    check "0e823820" []
      [ [ Q(0, 0x56feff0c48dce01cUL, 0x0UL) ]
        [ Q(0, 0xe9d05dd35f0f9e24UL, 0x0UL) ]
        [ Q(0, 0x180000000UL, 0x0UL) ]
        [ Q(0, 0x0UL, 0x0UL) ] ]
    check "4ec23820" []
      [ [ Q(0, 0x70616f2f48dce01cUL, 0x879e2e2256feff0cUL) ]
        [ Q(0, 0x57c883255f0f9e24UL, 0x594dac74e9d05dd3UL) ]
        [ Q(0, 0x7f80000080000000UL, 0x807fffff00000001UL) ]
        [ Q(0, 0x4008000000000000UL, 0x8000000000000000UL) ] ]
    check "4e823820" []
      [ [ Q(0, 0x56feff0c48dce01cUL, 0x879e2e2270616f2fUL) ]
        [ Q(0, 0xe9d05dd35f0f9e24UL, 0x594dac7457c88325UL) ]
        [ Q(0, 0x180000000UL, 0x807fffff7f800000UL) ]
        [ Q(0, 0x0UL, 0x8000000040080000UL) ] ]

  /// C7.2.404 ZIP2
  [<TestMethod>]
  member _.``C7.2.404 ZIP2``() =
    check "0e027820" []
      [ [ Q(0, 0x87709e612e6f222fUL, 0x0UL) ]
        [ Q(0, 0x59574dc8ac837425UL, 0x0UL) ]
        [ Q(0, 0x807f7f80ff00ff00UL, 0x0UL) ]
        [ Q(0, 0x8040000800000000UL, 0x0UL) ] ]
    check "4e027820" []
      [ [ Q(0, 0x5e2e4bf3e0fcf517UL, 0x8b402ed60282444eUL) ]
        [ Q(0, 0xe05fd91f9cb03ca9UL, 0x47e260312a1bfa53UL) ]
        [ Q(0, 0x7f7f7fc0ff00ff00UL, 0x7f80a000000000UL) ]
        [ Q(0, 0x9900990099009aUL, 0x7f3ff0b900990099UL) ] ]
    check "0e427820" []
      [ [ Q(0, 0x879e70612e226f2fUL, 0x0UL) ]
        [ Q(0, 0x594d57c8ac748325UL, 0x0UL) ]
        [ Q(0, 0x807f7f80ffff0000UL, 0x0UL) ]
        [ Q(0, 0x8000400800000000UL, 0x0UL) ] ]
    check "4e427820" []
      [ [ Q(0, 0x5e4b2ef3e0f5fc17UL, 0x8b2e40d60244824eUL) ]
        [ Q(0, 0xe0d95f1f9c3cb0a9UL, 0x4760e2312afa1b53UL) ]
        [ Q(0, 0x7f7f7fc0ffff0000UL, 0x807fa000000000UL) ]
        [ Q(0, 0x99990000999aUL, 0x7ff03fb900009999UL) ] ]
    check "0e827820" []
      [ [ Q(0, 0x879e2e2270616f2fUL, 0x0UL) ]
        [ Q(0, 0x594dac7457c88325UL, 0x0UL) ]
        [ Q(0, 0x807fffff7f800000UL, 0x0UL) ]
        [ Q(0, 0x8000000040080000UL, 0x0UL) ] ]
    check "4ec27820" []
      [ [ Q(0, 0x40d6824e2ef3fc17UL, 0x8b2e02445e4be0f5UL) ]
        [ Q(0, 0xe2311b535f1fb0a9UL, 0x47602afae0d99c3cUL) ]
        [ Q(0, 0x7fa000007fc00000UL, 0x8000007f7fffffUL) ]
        [ Q(0, 0x3fb999999999999aUL, 0x7ff0000000000000UL) ] ]
    check "4e827820" []
      [ [ Q(0, 0x5e4be0f52ef3fc17UL, 0x8b2e024440d6824eUL) ]
        [ Q(0, 0xe0d99c3c5f1fb0a9UL, 0x47602afae2311b53UL) ]
        [ Q(0, 0x7f7fffff7fc00000UL, 0x8000007fa00000UL) ]
        [ Q(0, 0x9999999aUL, 0x7ff000003fb99999UL) ] ]
