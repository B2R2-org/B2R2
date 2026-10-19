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

namespace B2R2.FrontEnd.PPC.Tests

open System
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.PPC
open type Register

/// <summary>
/// Each test runs what one word lifts to over the register values it gives
/// and asserts what a register holds afterwards, as the Power ISA defines it,
/// on cases whose answer the ISA leaves no doubt about.
/// </summary>
[<TestClass>]
type LifterTests() =
  /// 32-bit PowerPC, big-endian.
  let ppc32 = ISA(Architecture.PPC, Endian.Big, WordSize.Bit32)

  /// 64-bit PowerPC, big-endian.
  let ppc64 = ISA(Architecture.PPC, Endian.Big, WordSize.Bit64)

  /// 64-bit PowerPC, little-endian.
  let ppc64le = ISA(Architecture.PPC, Endian.Little, WordSize.Bit64)

  /// The statements one word lifts to on the processor an ISA names. The hex
  /// is the word as the Power ISA draws it, most significant byte first, and
  /// it is laid in memory in the byte order of the ISA.
  let lifted (isa: ISA) (hex: string) =
    let word = ByteArray.ofHexString hex
    let bytes = if isa.Endian = Endian.Big then word else Array.rev word
    let reader = BinReader.Init isa.Endian
    let parser = Parser(isa.WordSize, reader) :> IInstructionParsable
    let regs = RegisterFactory isa :> IRegisterFactory
    let builder = ILowUIRBuilder.Default(isa, regs, LowUIRStream())
    (parser.Parse(bytes, 0UL)).Translate builder

  /// The variable of a register on the processor an ISA names.
  let var (isa: ISA) r =
    (RegisterFactory isa :> IRegisterFactory).GetRegVar(Register.toRegID r)

  /// The registers given values, each value at the width of its register.
  let inputsOf isa given =
    given
    |> List.map (fun (r, v: uint64) ->
      let x = var isa r
      x, BitVector(v, Expr.typeOf x))

  /// What each register holds after one word ran on the processor an ISA
  /// names, over the registers given values and zero everywhere else.
  let run isa hex given =
    let read = IRRunner.run (lifted isa hex) (inputsOf isa given)
    fun r -> (read (var isa r)).ToUInt64()

  /// Asserts that a run left the expected value, naming the case it ran.
  let expect (expected: uint64) (actual: uint64) (case: string) =
    Assert.AreEqual(box expected, box actual, case)

  /// The processor an ISA names, for a message.
  let nameOf (isa: ISA) = $"{isa.WordSize} {isa.Endian}"

  /// XER[CA], bit 34 of the Power ISA's XER, kept at bit 29 of XER here.
  let ca = 0x20000000UL

  /// Every bit of a register of the processor an ISA names.
  let ones (isa: ISA) =
    if isa.WordSize = WordSize.Bit32 then 0xffffffffUL else UInt64.MaxValue

  /// XER[SO], bit 32 of the Power ISA's XER, kept at bit 31 of XER here.
  let so = 0x80000000UL

  /// CR0 as the Power ISA draws a CR field: LT, GT, EQ and SO from the most
  /// significant bit down.
  let cr0 after =
    (after CR0_0 <<< 3) ||| (after CR0_1 <<< 2) ||| (after CR0_2 <<< 1)
    ||| after CR0_3

  /// What run gives, over the bytes of memory given as well, and every byte
  /// of memory given or written after the run.
  let exec isa hex given memory =
    let outcome = IRRunner.exec (lifted isa hex) (inputsOf isa given) memory
    (fun r -> (outcome.Read(var isa r)).ToUInt64()), outcome.Memory

  /// The bits of a double.
  let bits (d: float) = BitConverter.DoubleToUInt64Bits d

  /// FPSCR[FPRF], bits 47:51 of the Power ISA's FPSCR, kept at bits 16:12 of
  /// FPSCR here.
  let fprf (fpscr: uint64) = (fpscr >>> 12) &&& 0x1fUL

  /// <summary>
  /// add rD, rA, rB writes rA + rB at the width of a register: the sum wraps
  /// at 32 bits on a 32-bit processor and carries into the high word on a
  /// 64-bit one.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] ADD sums at the width of a register``() =
    (* add r3, r4, r5 *)
    for isa, sum in
      [ ppc32, 1UL; ppc64, 0x100000001UL; ppc64le, 0x100000001UL ] do
      let after = run isa "7c642a14" [ R4, 0xffffffffUL; R5, 2UL ]
      expect sum (after R3) (nameOf isa)

  /// <summary>
  /// addc rD, rA, rB writes rA + rB and sets XER[CA] to the carry out of the
  /// register: out of bit 32 in 32-bit mode and out of bit 0 in 64-bit mode,
  /// so a sum that carries only out of the low word clears it on a 64-bit
  /// processor. XER[CA] starts as the opposite of what the sum leaves, so
  /// the run has to write it either way.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] ADDC sets XER[CA] to the carry out of a register``() =
    (* addc r3, r4, r5 *)
    for isa, a, sum, carry in
      [ ppc32, 0xffffffffUL, 0UL, 1UL
        ppc32, 0x7fffffffUL, 0x80000000UL, 0UL
        ppc64, 0xffffffffUL, 0x100000000UL, 0UL
        ppc64, UInt64.MaxValue, 0UL, 1UL
        ppc64le, 0xffffffffUL, 0x100000000UL, 0UL
        ppc64le, UInt64.MaxValue, 0UL, 1UL ] do
      let xer = if carry = 1UL then 0UL else ca
      let after = run isa "7c642814" [ R4, a; R5, 1UL; XER, xer ]
      expect sum (after R3) (nameOf isa)
      expect carry ((after XER >>> 29) &&& 1UL) (nameOf isa)

  /// <summary>
  /// subf rD, rA, rB writes rB - rA, computed as ~rA + rB + 1, at the width
  /// of a register.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] SUBF subtracts rA from rB``() =
    (* subf r3, r4, r5 *)
    for isa in [ ppc32; ppc64; ppc64le ] do
      let after a b = run isa "7c642850" [ R4, a; R5, b ] R3
      expect 7UL (after 3UL 10UL) (nameOf isa)
      expect (ones isa - 6UL) (after 10UL 3UL) (nameOf isa)

  /// <summary>
  /// and. rA, rS, rB writes rS &amp; rB and records the result in CR0: LT,
  /// GT and EQ from a signed comparison of the result with zero -- of the
  /// whole doubleword in 64-bit mode, so a word with its top bit set is
  /// negative on a 32-bit processor and positive on a 64-bit one -- and SO
  /// copied from XER[SO].
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] AND. records the result in CR0``() =
    (* and. r3, r4, r5 *)
    for isa, a, b, xer, result, field in
      [ ppc32, 0x800000f0UL, 0x8000000fUL, 0UL, 0x80000000UL, 0b1000UL
        ppc64, 0x800000f0UL, 0x8000000fUL, 0UL, 0x80000000UL, 0b0100UL
        ppc64le, 0x800000f0UL, 0x8000000fUL, 0UL, 0x80000000UL, 0b0100UL
        ppc32, 0xf0UL, 0x0fUL, so, 0UL, 0b0011UL
        ppc64, 0xf0f0UL, 0xff00UL, so, 0xf000UL, 0b0101UL
        ppc64, UInt64.MaxValue, 1UL <<< 63, 0UL, 1UL <<< 63, 0b1000UL ] do
      let after = run isa "7c832839" [ R4, a; R5, b; XER, xer ]
      expect result (after R3) (nameOf isa)
      expect field (cr0 after) (nameOf isa)

  /// <summary>
  /// rlwinm rA, rS, SH, MB, ME rotates the low word of rS left by SH and
  /// keeps the bits of MASK(MB + 32, ME + 32). The rotated word, ROTL32, is
  /// the low word repeated in both halves of a 64-bit register, so on a
  /// 64-bit processor a mask that wraps round (MB &gt; ME) keeps a copy of
  /// the rotated word in the high half, where one that does not keeps
  /// nothing there.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] RLWINM rotates the low word under a mask``() =
    (* rlwinm r3, r4, 8, 24, 31; rlwinm r3, r4, 4, 0, 27;
       rlwinm r3, r4, 0, 31, 0 *)
    for isa, hex, rs, result in
      [ ppc32, "5483463e", 0x12345678UL, 0x12UL
        ppc64, "5483463e", 0xdeadbeef12345678UL, 0x12UL
        ppc64le, "5483463e", 0xdeadbeef12345678UL, 0x12UL
        ppc32, "54832036", 0x12345678UL, 0x23456780UL
        ppc64, "54832036", 0xdeadbeef12345678UL, 0x23456780UL
        ppc32, "548307c0", 0xf0000001UL, 0x80000001UL
        ppc64, "548307c0", 0xdeadbeeff0000001UL, 0xf000000180000001UL
        ppc64le, "548307c0", 0xdeadbeeff0000001UL, 0xf000000180000001UL ] do
      let after = run isa hex [ R4, rs ]
      expect result (after R3) $"{hex} {nameOf isa}"

  /// <summary>
  /// lwz rD, D(rA) loads the word at rA + D, in the byte order the processor
  /// runs in, and zero-extends it into rD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] LWZ loads a word in the processor's byte order``() =
    let memory = [ 0x1008UL, [| 0x11uy; 0x22uy; 0x33uy; 0x44uy |] ]
    (* lwz r3, 8(r4) *)
    for isa, word in
      [ ppc32, 0x11223344UL; ppc64, 0x11223344UL; ppc64le, 0x44332211UL ] do
      let given = [ R3, ones isa; R4, 0x1000UL ]
      let after, _ = exec isa "80640008" given memory
      expect word (after R3) (nameOf isa)

  /// <summary>
  /// stw rS, D(rA) stores the low word of rS at rA + D, in the byte order
  /// the processor runs in, and touches no other byte.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] STW stores a word in the processor's byte order``() =
    let big = [| 0x11uy; 0x22uy; 0x33uy; 0x44uy |]
    (* stw r3, 8(r4) *)
    for isa, rs, bytes in
      [ ppc32, 0x11223344UL, big
        ppc64, 0xaabbccdd11223344UL, big
        ppc64le, 0xaabbccdd11223344UL, Array.rev big ] do
      let _, memory = exec isa "90640008" [ R3, rs; R4, 0x1000UL ] []
      let written = Array.init 4 (fun i -> memory[0x1008UL + uint64 i])
      CollectionAssert.AreEqual(bytes, written, nameOf isa)
      expect 4UL (uint64 memory.Count) (nameOf isa)

  /// <summary>
  /// fadd frD, frA, frB writes frA + frB and puts the class of the result
  /// in FPSCR[FPRF]: 0b00100 for a positive normal number and 0b01000 for a
  /// negative one. Both sums are exact, so no rounding is involved.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] FADD sums doubles and classifies the result``() =
    (* fadd f1, f2, f3 *)
    for isa in [ ppc32; ppc64; ppc64le ] do
      for a, b, sum, cls in
        [ 1.5, 2.25, 3.75, 0b00100UL; 1.5, -2.25, -0.75, 0b01000UL ] do
        let after = run isa "fc22182a" [ F2, bits a; F3, bits b ]
        expect (bits sum) (after F1) (nameOf isa)
        expect cls (fprf (after FPSCR)) (nameOf isa)

  /// <summary>
  /// fctiw frD, frB converts frB to a signed word, into the low word of frD,
  /// in the direction FPSCR[RN] names: 0 to nearest with ties to even, 1
  /// toward zero, 2 toward +infinity, 3 toward -infinity. 2.5 and -2.5 tell
  /// the four apart.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] FCTIW rounds in the direction FPSCR[RN] names``() =
    (* fctiw f1, f2 *)
    for isa in [ ppc32; ppc64; ppc64le ] do
      for rn, positive, negative in
        [ 0UL, 2UL, 0xfffffffeUL
          1UL, 2UL, 0xfffffffeUL
          2UL, 3UL, 0xfffffffeUL
          3UL, 2UL, 0xfffffffdUL ] do
        let word x = run isa "fc20101c" [ F2, bits x; FPSCR, rn ] F1
        let message = $"RN {rn} {nameOf isa}"
        expect positive (word 2.5 &&& 0xffffffffUL) message
        expect negative (word (-2.5) &&& 0xffffffffUL) message

/// <summary>
/// Lane F's lifting tests: the binary floating-point instructions added
/// after the first PowerPC, the floating-point register pair accesses, the
/// FPSCR, and the Decimal Floating-Point facility. Every expected value is
/// QEMU's (optest-powerpc/oracle), unless a test says the manual and QEMU
/// part, in which case it is the manual's.
/// </summary>
[<TestClass>]
type FloatLifterTests() =
  /// 32-bit PowerPC, big-endian.
  let ppc32 = ISA(Architecture.PPC, Endian.Big, WordSize.Bit32)

  /// 64-bit PowerPC, big-endian.
  let ppc64 = ISA(Architecture.PPC, Endian.Big, WordSize.Bit64)

  /// 64-bit PowerPC, little-endian.
  let ppc64le = ISA(Architecture.PPC, Endian.Little, WordSize.Bit64)

  /// The statements one word lifts to on the processor an ISA names. The hex
  /// is the word as the Power ISA draws it, most significant byte first.
  let lifted (isa: ISA) (hex: string) =
    let word = ByteArray.ofHexString hex
    let bytes = if isa.Endian = Endian.Big then word else Array.rev word
    let reader = BinReader.Init isa.Endian
    let parser = Parser(isa.WordSize, reader) :> IInstructionParsable
    let regs = RegisterFactory isa :> IRegisterFactory
    let builder = ILowUIRBuilder.Default(isa, regs, LowUIRStream())
    (parser.Parse(bytes, 0UL)).Translate builder

  /// The variable of a register on the processor an ISA names.
  let var (isa: ISA) r =
    (RegisterFactory isa :> IRegisterFactory).GetRegVar(Register.toRegID r)

  /// The registers given values, each value at the width of its register.
  let inputsOf isa given =
    given
    |> List.map (fun (r, v: uint64) ->
      let x = var isa r
      x, BitVector(v, Expr.typeOf x))

  /// What each register holds after one word ran, over the registers given
  /// values and the bytes of memory given, and every byte of memory given or
  /// written after the run.
  let exec isa hex given memory =
    let outcome = IRRunner.exec (lifted isa hex) (inputsOf isa given) memory
    (fun r -> (outcome.Read(var isa r)).ToUInt64()), outcome.Memory

  /// What each register holds after one word ran, with no memory at all.
  let run isa hex given = exec isa hex given [] |> fst

  /// Asserts that a run left the expected value, naming the case it ran.
  let expect (expected: uint64) (actual: uint64) (case: string) =
    Assert.AreEqual(box expected, box actual, case)

  /// The processor an ISA names, for a message.
  let nameOf (isa: ISA) = $"{isa.WordSize} {isa.Endian}"

  /// The four bits of a CR field, as the Power ISA draws one: bit 0 (LT or
  /// FL) the most significant.
  let field after (b0, b1, b2, b3) =
    (after b0 <<< 3) ||| (after b1 <<< 2) ||| (after b2 <<< 1) ||| after b3

  /// CR1 as its four bit registers.
  let cr1 = CR1_0, CR1_1, CR1_2, CR1_3

  /// CR2 as its four bit registers.
  let cr2 = CR2_0, CR2_1, CR2_2, CR2_3

  /// The eight bytes of a doubleword as a big-endian processor stores it.
  let bigBytes (v: uint64) = Array.init 8 (fun i -> byte (v >>> (56 - 8 * i)))

  /// A doubleword with its bytes in the other order.
  let swap (v: uint64) =
    BitConverter.ToUInt64(Array.rev (BitConverter.GetBytes v), 0)

  /// The doubles the tests use most, by their bits.
  let one = 0x3ff0000000000000UL

  let oneHalf = 0x3ff8000000000000UL

  let tenth = 0x3fb999999999999aUL

  let infinity = 0x7ff0000000000000UL

  let minusInfinity = 0xfff0000000000000UL

  let qnan = 0x7ff8000000000000UL

  let maxDouble = 0x7fefffffffffffffUL

  let minusZero = 0x8000000000000000UL

  /// <summary>
  /// fcpsgn. frD, frA, frB writes frB with the sign of frA and records
  /// FPSCR[FX, FEX, VX, OX] in CR1.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] FCPSGN. copies the sign and records CR1``() =
    (* fcpsgn. f1, f2, f3 *)
    for isa in [ ppc32; ppc64; ppc64le ] do
      for a, b, fpscr, result, field1 in
        [ qnan, one, 0xbff80000UL, one, 0xbUL
          0UL, minusZero, 0x2UL, 0UL, 0UL
          maxDouble, maxDouble, 0x20000702UL, maxDouble, 0x2UL ] do
        let after = run isa "fc221811" [ F2, a; F3, b; FPSCR, fpscr ]
        expect result (after F1) (nameOf isa)
        expect field1 (field after cr1) (nameOf isa)

  /// <summary>
  /// fmrgew frD, frA, frB writes word 0 (the high word) of frA and then word
  /// 0 of frB; fmrgow writes word 1 of each.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] FMRGEW and FMRGOW merge words``() =
    (* fmrgew f1, f2, f3; fmrgow f1, f2, f3 *)
    for isa in [ ppc32; ppc64; ppc64le ] do
      for hex, a, b, result in
        [ "fc221f8c", oneHalf, 0x4002000000000000UL, 0x3ff8000040020000UL
          "fc221f8c", infinity, minusInfinity, 0x7ff00000fff00000UL
          "fc221e8c", one, tenth, 0x9999999aUL
          "fc221e8c", 0x1UL, 0xfffffffffffffUL, 0x1ffffffffUL ] do
        let after = run isa hex [ F2, a; F3, b ]
        expect result (after F1) $"{hex} {nameOf isa}"

  /// <summary>
  /// ftdiv BF, frA, frB sets CR field BF to fl || fg || fe || 0: fl is 1, as
  /// the estimates are the exact reciprocals; fe for a NaN or an infinity in
  /// frA, a zero, NaN or infinity in frB, or exponents a divide cannot take
  /// without special handling; fg for an infinity in frA or a zero, infinity
  /// or denormal in frB.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] FTDIV tests the operands of a divide``() =
    (* ftdiv cr2, f2, f3 *)
    for isa in [ ppc32; ppc64; ppc64le ] do
      for a, b, result in
        [ oneHalf, 0x4002000000000000UL, 0x8UL
          one, tenth, 0x8UL
          0UL, minusZero, 0xeUL
          infinity, minusInfinity, 0xeUL
          qnan, one, 0xaUL
          0x1UL, 0xfffffffffffffUL, 0xeUL
          maxDouble, maxDouble, 0xaUL
          one, 0UL, 0xeUL ] do
        let after = run isa "fd021900" [ F2, a; F3, b ]
        expect result (field after cr2) $"{a:x} {b:x} {nameOf isa}"

  /// <summary>
  /// ftsqrt BF, frB sets CR field BF to fl || fg || fe || 0: fe for a zero, a
  /// NaN, an infinity, a negative value or an exponent at or below -970; fg
  /// for a zero, an infinity or a denormal.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] FTSQRT tests the operand of a square root``() =
    (* ftsqrt cr2, f3 *)
    for isa in [ ppc32; ppc64; ppc64le ] do
      for b, result in
        [ oneHalf, 0x8UL
          0UL, 0xeUL
          infinity, 0xeUL
          qnan, 0xaUL
          0x1UL, 0xeUL
          maxDouble, 0x8UL ] do
        let after = run isa "fd001940" [ F3, b ]
        expect result (field after cr2) $"{b:x} {nameOf isa}"

  /// <summary>
  /// lfdp frTp, DS(rA) and lfdpx frTp, rA, rB load the doubleword at EA into
  /// the even register of the pair and the one at EA + 8 into the odd one,
  /// each in the processor's byte order. QEMU swaps the two in little-endian
  /// mode; the manual's pseudocode does not, and is followed here (see
  /// optest-powerpc/lanes/F.md).
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] LFDP and LFDPX load a register pair``() =
    let lo, hi = 0xff19a056aef92bd2UL, 0x3204aae99af7e745UL
    let memory = [ 0x1008UL, Array.append (bigBytes lo) (bigBytes hi) ]
    (* lfdp f2, 8(r6); lfdpx f2, r6, r7 *)
    for hex in [ "e4460008"; "7c463e2e" ] do
      for isa, even, odd in
        [ ppc32, lo, hi; ppc64, lo, hi; ppc64le, swap lo, swap hi ] do
        let given = [ R6, 0x1000UL; R7, 8UL; F2, 0x4045000000000000UL ]
        let after, _ = exec isa hex given memory
        expect even (after F2) $"{hex} {nameOf isa}"
        expect odd (after F3) $"{hex} {nameOf isa}"

  /// <summary>
  /// stfdp frSp, DS(rA) and stfdpx frSp, rA, rB store the even register of
  /// the pair at EA and the odd one at EA + 8, each in the processor's byte
  /// order.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] STFDP and STFDPX store a register pair``() =
    (* stfdp f2, 8(r6); stfdpx f2, r6, r7 *)
    for hex in [ "f4460008"; "7c463f2e" ] do
      for isa in [ ppc32; ppc64; ppc64le ] do
        let given = [ R6, 0x1000UL; R7, 8UL; F2, oneHalf; F3, 0x5UL ]
        let _, memory = exec isa hex given []
        let written = Array.init 16 (fun i -> memory[0x1008UL + uint64 i])
        let order = if isa.Endian = Endian.Big then id else Array.rev
        let expected =
          Array.append (order (bigBytes oneHalf)) (order (bigBytes 0x5UL))
        CollectionAssert.AreEqual(expected, written, $"{hex} {nameOf isa}")

  /// <summary>
  /// fre frD, frB and frsqrtes frD, frB estimate the reciprocal and the
  /// reciprocal square root; where the exact answer is representable, the
  /// estimate is it.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] FRE and FRSQRTES are exact where the answer is``() =
    (* fre f1, f3; frsqrtes f1, f3 *)
    for isa in [ ppc32; ppc64; ppc64le ] do
      for hex, b, result in
        [ "fc201830", one, one
          "fc201830", 0x4010000000000000UL, 0x3fd0000000000000UL
          "fc201830", infinity, 0UL
          "ec201834", one, one
          "ec201834", 0x4010000000000000UL, 0x3fe0000000000000UL
          "ec201834", infinity, 0UL ] do
        let after = run isa hex [ F3, b ]
        expect result (after F1) $"{hex} {b:x} {nameOf isa}"

  /// <summary>
  /// mffs frD reads the whole 64-bit FPSCR: DRN, in the high word, with the
  /// low word below it.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] MFFS reads both words of the FPSCR``() =
    (* mffs f1 *)
    for isa in [ ppc32; ppc64; ppc64le ] do
      let after = run isa "fc20048e" [ FPSCRH, 5UL; FPSCR, 0x82024003UL ]
      expect 0x582024003UL (after F1) (nameOf isa)

  /// <summary>
  /// mffsce frD reads the whole FPSCR and then clears VE, OE, UE, ZE and XE,
  /// and FEX with them.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] MFFSCE reads the FPSCR and clears the enables``() =
    (* mffsce f1 *)
    for isa in [ ppc32; ppc64; ppc64le ] do
      for fpscr, result in
        [ 0x82024003UL, 0x82024003UL
          0x7f001UL, 0x7f001UL
          0xc20000f9UL, 0x82000001UL ] do
        let after = run isa "fc21048e" [ FPSCR, fpscr ]
        expect fpscr (after F1) $"{fpscr:x} {nameOf isa}"
        expect result (after FPSCR) $"{fpscr:x} {nameOf isa}"

  /// <summary>
  /// mffsl frD reads the control bits (DRN and VE..RN) and the non-sticky
  /// status bits (FR, FI, FPRF) of the FPSCR, every other bit zero.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] MFFSL reads only the control and non-sticky bits``() =
    (* mffsl f1 *)
    for isa in [ ppc32; ppc64; ppc64le ] do
      for drn, fpscr, result in
        [ 0UL, 0x82024003UL, 0x24003UL
          0UL, 0xbff80000UL, 0UL
          0UL, 0x7f001UL, 0x7f001UL
          0UL, 0x20000702UL, 0x2UL
          6UL, 0x20000702UL, 0x600000002UL ] do
        let after = run isa "fc38048e" [ FPSCRH, drn; FPSCR, fpscr ]
        expect result (after F1) $"{fpscr:x} {nameOf isa}"

  /// <summary>
  /// mffscdrn frD, frB reads the control bits and then sets DRN from bits
  /// 29:31 of frB; mffscdrni frD, DRM sets it from the immediate.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] MFFSCDRN and MFFSCDRNI set DRN``() =
    (* mffscdrn f1, f3; mffscdrni f1, 1 *)
    for isa in [ ppc32; ppc64; ppc64le ] do
      for hex, b, fpscr, result, drn in
        [ "fc341c8e", maxDouble, 0x20000702UL, 0x2UL, 7UL
          "fc341c8e", oneHalf, 0x82024003UL, 0x3UL, 0UL
          "fc350c8e", 0UL, 0x82024003UL, 0x3UL, 1UL
          "fc350c8e", 0UL, 0xbff80000UL, 0UL, 1UL ] do
        let after = run isa hex [ F3, b; FPSCR, fpscr ]
        expect result (after F1) $"{hex} {nameOf isa}"
        expect drn (after FPSCRH) $"{hex} {nameOf isa}"
        expect fpscr (after FPSCR) $"{hex} {nameOf isa}"

  /// <summary>
  /// mtfsfi. BF, U writes field BF of the FPSCR's low word, recomputes VX
  /// and FEX, and records CR1; with W = 1 it writes the high word, where
  /// field 7 holds DRN.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] MTFSFI. records CR1 and MTFSFI W sets DRN``() =
    (* mtfsfi. 2, 0; mtfsfi 7, 1, 1 *)
    for isa in [ ppc32; ppc64; ppc64le ] do
      let after = run isa "fd00010d" [ FPSCR, 0xbff80000UL ]
      expect 0xbf080000UL (after FPSCR) (nameOf isa)
      expect 0xbUL (field after cr1) (nameOf isa)
      let after = run isa "ff81110c" [ FPSCRH, 6UL; FPSCR, 0x3UL ]
      expect 1UL (after FPSCRH) (nameOf isa)
      expect 0x3UL (after FPSCR) (nameOf isa)

  /// <summary>
  /// mtfsb1 BT sets FPSCR bit BT + 32 and, as the manual's Special Registers
  /// Altered says, FX where that is an exception bit turning on; VX follows.
  /// QEMU 8.2 leaves FX alone here (see optest-powerpc/lanes/F.md).
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] MTFSB1 sets FX with an exception bit``() =
    (* mtfsb1 9 (VXIDI) *)
    for isa in [ ppc32; ppc64; ppc64le ] do
      for fpscr, result in
        [ 0UL, 0xa0400000UL
          0x7f001UL, 0xa047f001UL
          0x82024003UL, 0xa2424003UL ] do
        let after = run isa "fd20004c" [ FPSCR, fpscr ]
        expect result (after FPSCR) $"{fpscr:x} {nameOf isa}"

  /// <summary>
  /// mtfsf FLM, frB with L = 1 writes the whole FPSCR from frB: DRN from
  /// the high word, the low word with FEX and VX recomputed.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] MTFSF with L writes both words``() =
    (* mtfsf 255, f3, 1, 0; mtfsf 255, f3 *)
    for isa in [ ppc32; ppc64; ppc64le ] do
      let b = 0x0000000582024003UL
      let after = run isa "fffe1d8e" [ F3, b; FPSCR, 0x20000702UL ]
      expect 0x82024003UL (after FPSCR) (nameOf isa)
      expect 5UL (after FPSCRH) (nameOf isa)
      let after = run isa "fdfe1d8e" [ F3, b; FPSCRH, 2UL ]
      expect 0x82024003UL (after FPSCR) (nameOf isa)
      expect 2UL (after FPSCRH) (nameOf isa)

  /// <summary>
  /// mfocrf rD, FXM reads the CR field FXM names into its place in rD; the
  /// rest of rD, which the manual leaves undefined, is zero, as QEMU makes
  /// it.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] MFOCRF reads one CR field``() =
    (* mfocrf r5, 32 *)
    for isa in [ ppc32; ppc64; ppc64le ] do
      for cr2Bits, result in [ 0b0110UL, 0x600000UL; 0b1111UL, 0xf00000UL ] do
        let bit n = (cr2Bits >>> n) &&& 1UL
        let given =
          [ CR2_0, bit 3
            CR2_1, bit 2
            CR2_2, bit 1
            CR2_3, bit 0
            CR0_0, 1UL
            CR7_3, 1UL
            R5, 0xbad0bad0UL ]
        let after = run isa "7cb20026" given
        expect result (after R5) (nameOf isa)
