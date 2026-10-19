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

  /// FPSCR[FR]. QEMU leaves it as it was where the manual sets or clears it
  /// (optest-powerpc/lanes/F.md), so the QEMU vectors compare everything
  /// but FR, and FR has tests of its own.
  let fr = 0x40000UL

  /// <summary>
  /// Runs a floating-point word on every target over the values given to the
  /// FPRs the text names after the target, in that order, and FPSCR, and
  /// checks frD and the FPSCR but for FR: one case per QEMU vector, as
  /// (operands, FPSCR before, frD after, FPSCR after).
  /// </summary>
  let checkFP hex dst srcs cases =
    for isa in [ ppc32; ppc64; ppc64le ] do
      for (ops: uint64 list), fpscr, result, after in cases do
        let given = (FPSCR, fpscr) :: List.zip srcs ops
        let out = run isa hex given
        let case = $"{hex} %A{ops} {fpscr:x} {nameOf isa}"
        expect result (out dst) case
        expect (after &&& ~~~fr) (out FPSCR &&& ~~~fr) case

  /// <summary>
  /// Runs a DFP word with its named calls answered from the given table
  /// (name to value), which stands in for BRemu's decimal arithmetic: the
  /// run shows which calls the lifter made with which arguments, and where
  /// their answers went. Gives the registers after the run and the calls
  /// made, each as its name and its arguments' values.
  /// </summary>
  let runDFP isa hex given (answers: (string * BitVector) list) =
    let answer name _ = List.tryFind (fst >> (=) name) answers |> Option.map snd
    let stmts = lifted isa hex
    let o = IRRunner.execAnswering answer stmts (inputsOf isa given) []
    let valuesOf (args: BitVector list) =
      args |> List.map (fun a -> a.ToBigInt())
    let calls = o.Calls |> List.map (fun (n, args) -> n, valuesOf args)
    (fun r -> (o.Read(var isa r)).ToUInt64()), calls

  /// A 128-bit value, its high doubleword first.
  let wide (hi: uint64) (lo: uint64) = (bigint hi <<< 64) + bigint lo

  /// An answer of a named call.
  let answerOf (v: bigint) (t: RegType) = BitVector(v, t)

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

  /// <summary>
  /// fadds rounds the exact sum to single precision once. 1.0 + (2^-24 +
  /// 2^-50) lies above the midpoint between 1.0 and 1.0 + 2^-23, so it rounds
  /// up; converting the operands to single first loses the 2^-50 and rounds
  /// the tie to even, down to 1.0. FR records the rounding up (QEMU leaves FR
  /// as it was).
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] FADDS rounds the exact sum to single once``() =
    (* fadds f1, f2, f3 *)
    checkFP "ec22182a" F1 [ F2; F3 ]
      [ [ one; 0x3e70000004000000UL ], 0UL, 0x3ff0000020000000UL, 0x82024000UL
        [ one; 0x3e70000004000000UL ], 1UL, one, 0x82024001UL ]
    for isa in [ ppc32; ppc64; ppc64le ] do
      let after = run isa "ec22182a" [ F2, one; F3, 0x3e70000004000000UL ]
      expect fr (after FPSCR &&& fr) (nameOf isa)

  /// <summary>
  /// fadds over QEMU's vectors: an exact sum, an inexact one truncated, a
  /// zero, infinities of opposite signs (VXISI, the default QNaN), a QNaN
  /// operand, a sum too small for a single (UX, XX), and one too large for
  /// it in round toward +infinity (OX, +infinity).
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] FADDS sets the FPSCR as QEMU does``() =
    (* fadds f1, f2, f3 *)
    checkFP "ec22182a" F1 [ F2; F3 ]
      [ [ oneHalf; 0x4002000000000000UL ], 0UL, 0x400e000000000000UL, 0x4000UL
        [ one; tenth ], 1UL, 0x3ff1999980000000UL, 0x82024001UL
        [ 0UL; minusZero ], 2UL, 0UL, 0x2002UL
        [ infinity; minusInfinity ], 3UL, qnan, 0xa0811003UL
        [ qnan; one ], 0xbff80000UL, qnan, 0xbff91000UL
        [ 1UL; 0xfffffffffffffUL ], 0x7f001UL, 0UL, 0x8a062001UL
        [ maxDouble; maxDouble ], 0x20000702UL, infinity, 0xb2025702UL
        [ one; 0UL ], 0x82024003UL, one, 0x82004003UL ]

  /// <summary>
  /// fmul, fdiv and fsqrt over QEMU's vectors: VXIMZ is not raised by a
  /// signed zero times a zero; 0/0 raises VXZDZ and infinity over infinity
  /// VXIDI; a divide by zero raises ZX and clears FR and FI; an exact result
  /// clears FI.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] FMUL FDIV FSQRT set the FPSCR as QEMU does``() =
    (* fmul f1, f2, f4; fdiv f1, f2, f3; fsqrt f1, f3 *)
    checkFP "fc220132" F1 [ F2; F4 ]
      [ [ oneHalf; 0x4002000000000000UL ], 0UL, 0x400b000000000000UL, 0x4000UL
        [ 0UL; minusZero ], 2UL, minusZero, 0x12002UL
        [ infinity; minusInfinity ], 3UL, minusInfinity, 0x9003UL
        [ 1UL; 0xfffffffffffffUL ], 0x7f001UL, 0UL, 0x8a062001UL
        [ maxDouble; maxDouble ], 0x20000702UL, infinity, 0xb2025702UL ]
    let third = 0x3fe5555555555555UL
    let tiny = 0x3cb0000000000001UL
    checkFP "fc221824" F1 [ F2; F3 ]
      [ [ oneHalf; 0x4002000000000000UL ], 0UL, third, 0x82024000UL
        [ one; tenth ], 1UL, 0x4023ffffffffffffUL, 0x82024001UL
        [ 0UL; minusZero ], 2UL, qnan, 0xa0211002UL
        [ infinity; minusInfinity ], 3UL, qnan, 0xa0411003UL
        [ 1UL; 0xfffffffffffffUL ], 0x7f001UL, tiny, 0x82064001UL
        [ maxDouble; maxDouble ], 0x20000702UL, one, 0x20004702UL
        [ one; 0UL ], 0x82024003UL, infinity, 0x86005003UL ]
    checkFP "fc20182c" F1 [ F3 ]
      [ [ oneHalf ], 0UL, 0x3ff3988e1409212eUL, 0x82024000UL
        [ 0UL ], 2UL, 0UL, 0x2002UL
        [ infinity ], 3UL, infinity, 0x5003UL
        [ 1UL ], 0x7f001UL, 0x1e60000000000000UL, 0x44001UL
        [ maxDouble ], 0x20000702UL, 0x5ff0000000000000UL, 0xa2024702UL ]

  /// <summary>
  /// fmadd, fmadds and fnmsubs over QEMU's vectors: one rounding of frA x
  /// frC + frB; a QNaN in frA wins over an SNaN in frB; a tiny single
  /// result underflows to zero.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] FMADD FMADDS FNMSUBS set the FPSCR as QEMU does``() =
    (* fmadd f1, f2, f4, f3; fmadds f1, f2, f4, f3; fnmsubs f1, f2, f4, f3 *)
    let snan = 0x7ff4000000000001UL
    let x, y, z = oneHalf, 0x4002000000000000UL, 0xbfe8000000000000UL
    let two, three = 0x4000000000000000UL, 0x4008000000000000UL
    let small, minNormal = 0xfffffffffffffUL, 0x10000000000000UL
    let near = 0x4007333320000000UL
    for hex, sum in
      [ "fc22193a", 0x4008ccccccccccccUL; "ec22193a", 0x4008ccccc0000000UL ] do
      checkFP hex F1 [ F2; F4; F3 ]
        [ [ x; y; z ], 0UL, 0x4005000000000000UL, 0x4000UL
          [ one; tenth; three ], 1UL, sum, 0x82024001UL
          [ infinity; minusInfinity; one ], 3UL, minusInfinity, 0x9003UL
          [ qnan; one; snan ], 0xbff80000UL, qnan, 0xbff91000UL
          [ maxDouble; maxDouble; two ], 0x20000702UL, infinity, 0xb2025702UL ]
    checkFP "ec22193c" F1 [ F2; F4; F3 ]
      [ [ x; y; z ], 0UL, 0xc010800000000000UL, 0x8000UL
        [ one; tenth; three ], 1UL, near, 0x82024001UL
        [ 1UL; small; minNormal ], 0x7f001UL, 0UL, 0x8a062001UL ]

  /// <summary>
  /// fnmsub rounds frA x frC - frB and THEN negates it (manual p. 164), so
  /// toward +infinity the magnitude of a positive product rounds up before
  /// the sign turns: -(max x max - 2) overflows to -infinity, and -(0.1 -
  /// 3) is 2.8999998 rather than 2.9000001. QEMU negates first.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] FNMSUBS negates the rounded result``() =
    (* fnmsubs f1, f2, f4, f3 *)
    let two, three = 0x4000000000000000UL, 0x4008000000000000UL
    let near = 0x4007333320000000UL
    checkFP "ec22193c" F1 [ F2; F4; F3 ]
      [ [ maxDouble; maxDouble; two ], 2UL, minusInfinity, 0x92029002UL
        [ one; tenth; three ], 2UL, near, 0x82024002UL ]

  /// <summary>
  /// frsp and fres over QEMU's vectors, where the manual agrees: frsp of a
  /// denormal underflows to zero, of the largest double overflows; fres of
  /// a denormal overflows to the largest single toward zero. Where the
  /// manual and QEMU part, the manual: fres of +0 is +infinity with ZX
  /// (QEMU answers 1/2), and a result that is a single denormal has the
  /// denormal FPRF (QEMU classes it as a double).
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] FRSP and FRES set the FPSCR``() =
    (* frsp f1, f3; fres f1, f3 *)
    checkFP "fc201818" F1 [ F3 ]
      [ [ oneHalf ], 0UL, oneHalf, 0x4000UL
        [ qnan ], 0xbff80000UL, qnan, 0xbff91000UL
        [ 1UL ], 0x7f001UL, 0UL, 0x8a062001UL
        [ maxDouble ], 0x20000702UL, infinity, 0xb2025702UL ]
    checkFP "ec201830" F1 [ F3 ]
      [ [ oneHalf ], 0UL, 0x3fe5555560000000UL, 0x82024000UL
        [ 0UL ], 2UL, infinity, 0x84005002UL
        [ infinity ], 3UL, 0UL, 0x2003UL
        [ 1UL ], 0x7f001UL, 0x47efffffe0000000UL, 0x92064001UL
        [ maxDouble ], 0x20000702UL, 0x36a0000000000000UL, 0xaa034702UL ]

  /// <summary>
  /// FR says the rounding moved the fraction up: 1 + 3 x 2^-54 rounds up to
  /// nearest and FR is 1, truncates toward zero and FR is 0, and an exact
  /// sum clears it (FR is not sticky). QEMU leaves FR as it was.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] FADD sets FR when it rounds up``() =
    (* fadd f1, f2, f3 *)
    for isa in [ ppc32; ppc64; ppc64le ] do
      for b, fpscr, result, fpscrAfter in
        [ 0x3ca8000000000000UL, 0UL, 0x3ff0000000000001UL, 0x82064000UL
          0x3ca8000000000000UL, 1UL, one, 0x82024001UL
          one, fr, 0x4000000000000000UL, 0x4000UL ] do
        let after = run isa "fc22182a" [ F2, one; F3, b; FPSCR, fpscr ]
        expect result (after F1) $"{b:x} {fpscr:x} {nameOf isa}"
        expect fpscrAfter (after FPSCR) $"{b:x} {fpscr:x} {nameOf isa}"

  /// <summary>
  /// A single-precision result that is a denormal single is classed as one
  /// (FPRF 0b10100), even though the double that holds it is normal: 2^-65
  /// x 2^-65 = 2^-130. QEMU classes it as a double (0b00100).
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] FMULS classes a single denormal as denormal``() =
    (* fmuls f1, f2, f4 *)
    let twoToMinus65 = 0x3be0000000000000UL
    let twoToMinus130 = 0x37d0000000000000UL
    let product = [ twoToMinus65; twoToMinus65 ], 0UL, twoToMinus130, 0x14000UL
    checkFP "ec220132" F1 [ F2; F4 ] [ product ]

  /// <summary>
  /// With ZE set, a divide by zero leaves frD and FPRF as they were, clears
  /// FR and FI, and sets ZX, FX and FEX.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] FDIV by zero with ZE keeps the target``() =
    (* fdiv f1, f2, f3 *)
    for isa in [ ppc32; ppc64; ppc64le ] do
      let given = [ F1, 0x4045000000000000UL; F2, one; FPSCR, 0x60010UL ]
      let after = run isa "fc221824" given
      expect 0x4045000000000000UL (after F1) (nameOf isa)
      expect 0xc4000010UL (after FPSCR) (nameOf isa)

  /// <summary>
  /// dadd frT, frA, frB asks DFPEXC (code 1) for its status and DADD for its
  /// result, both with frA, frB and the control byte: FPSCR[DRN] (5 here) in
  /// bits 2:0 under the enables. The result goes to frT; the status's
  /// exception bits are OR-ed into the FPSCR with FX, its FPRF, FR and FI
  /// replace the FPSCR's.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] DADD calls DADD and DFPEXC with DRN``() =
    let a, b = 0x2238000000000001UL, 0x2238000000000002UL
    let answers =
      [ "DFPEXC", answerOf (bigint 0x02024000UL) 32<rt>
        "DADD", answerOf (bigint 0x2238000000000003UL) 64<rt> ]
    (* dadd f1, f2, f3 *)
    for isa in [ ppc32; ppc64; ppc64le ] do
      let given = [ F2, a; F3, b; FPSCR, 0x3UL; FPSCRH, 5UL ]
      let after, calls = runDFP isa "ec221804" given answers
      let expected =
        [ "DFPEXC", [ 1I; bigint a; bigint b; 5I ]
          "DADD", [ bigint a; bigint b; 5I ] ]
      Assert.AreEqual<(string * bigint list) list>(expected, calls)
      expect 0x2238000000000003UL (after F1) (nameOf isa)
      expect 0x82024003UL (after FPSCR) (nameOf isa)

  /// <summary>
  /// daddq frTp, frAp, frBp passes each pair as one 128-bit value, the even
  /// register over the odd one, and writes the 128-bit result the same way.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] DADDQ passes and writes register pairs``() =
    let answers =
      [ "DFPEXC", answerOf (bigint 0x4000UL) 32<rt>
        "DADDQ", answerOf (wide 0x2208000000000000UL 7UL) 128<rt> ]
    (* daddq f2, f4, f6 *)
    for isa in [ ppc32; ppc64; ppc64le ] do
      let given = [ F4, 1UL; F5, 2UL; F6, 3UL; F7, 4UL; FPSCR, 0x80UL ]
      let after, calls = runDFP isa "fc443004" given answers
      let expected =
        [ "DFPEXC", [ 2I; wide 1UL 2UL; wide 3UL 4UL; (bigint 0x80UL) ]
          "DADDQ", [ wide 1UL 2UL; wide 3UL 4UL; (bigint 0x80UL) ] ]
      Assert.AreEqual<(string * bigint list) list>(expected, calls)
      expect 0x2208000000000000UL (after F2) (nameOf isa)
      expect 7UL (after F3) (nameOf isa)
      expect 0x4080UL (after FPSCR) (nameOf isa)

  /// <summary>
  /// With VE set, an invalid operation the status reports (VXIDI) leaves frT
  /// and FPRF as they were; VX, FX and FEX follow.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] DDIV keeps the target on an enabled invalid``() =
    let answers =
      [ "DFPEXC", answerOf (bigint 0x00411000UL) 32<rt>
        "DDIV", answerOf (bigint 0x7c00000000000000UL) 64<rt> ]
    (* ddiv f1, f2, f3 *)
    for isa in [ ppc32; ppc64; ppc64le ] do
      let given = [ F1, 0x1234UL; FPSCR, 0x80UL ]
      let after, _ = runDFP isa "ec221c44" given answers
      expect 0x1234UL (after F1) (nameOf isa)
      expect 0xe0400080UL (after FPSCR) (nameOf isa)

  /// <summary>
  /// dcmpu BF, frA, frB asks DFPEXC (code 9) alone: bits 15:12 of the status
  /// go into CR field BF and FPSCR[FPCC], leaving C as it was.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] DCMPU writes the status's FPCC into the CR field``() =
    let answers = [ "DFPEXC", answerOf (bigint 0x8000UL) 32<rt> ]
    (* dcmpu cr2, f2, f3 *)
    for isa in [ ppc32; ppc64; ppc64le ] do
      let given = [ F2, 6UL; F3, 7UL; FPSCR, 0x1f000UL; CR2_3, 1UL ]
      let after, calls = runDFP isa "ed021d04" given answers
      let expected = [ "DFPEXC", [ 9I; 6I; 7I; 0I ] ]
      Assert.AreEqual<(string * bigint list) list>(expected, calls)
      expect 0x8UL (field after cr2) (nameOf isa)
      expect 0x18000UL (after FPSCR) (nameOf isa)

  /// <summary>
  /// The rounding mode in the control byte: drintx with R = 1 reads RMC in
  /// the secondary encoding (RMC 2 is away from zero, 6), drintn with R = 0
  /// in the primary one (RMC 1 is toward zero, 1), and dqua's RMC 3 defers
  /// to DRN.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] DRINTX DRINTN DQUA take the mode RMC names``() =
    let answers =
      [ "DFPEXC", answerOf 0I 32<rt>
        "DRINTX", answerOf 1I 64<rt>
        "DRINTN", answerOf 1I 64<rt>
        "DQUA", answerOf 1I 64<rt> ]
    (* drintx 1, f1, f3, 2; drintn 0, f1, f3, 1; dqua f1, f2, f3, 3 *)
    for isa in [ ppc32; ppc64; ppc64le ] do
      for hex, call, code, ctl in
        [ "ec211cc6", "DRINTX", 29I, 6I
          "ec201bc6", "DRINTN", 31I, 1I
          "ec221e06", "DQUA", 25I, 4I ] do
        let given = [ F2, 2UL; F3, 3UL; FPSCRH, 4UL ]
        let _, calls = runDFP isa hex given answers
        let args = if call = "DQUA" then [ 2I; 3I; ctl ] else [ 3I; ctl ]
        let expected = [ "DFPEXC", code :: args; call, args ]
        Assert.AreEqual<(string * bigint list) list>(expected, calls, hex)

  /// <summary>
  /// dquai TE, frT, frB, RMC passes TE as a byte, sign and all: 3, and -16
  /// as 0xf0.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] DQUAI passes TE as a signed byte``() =
    let answers =
      [ "DFPEXC", answerOf 0I 32<rt>; "DQUAI", answerOf 1I 64<rt> ]
    (* dquai 3, f1, f3, 1; dquai -16, f1, f3, 1 *)
    for isa in [ ppc32; ppc64; ppc64le ] do
      for hex, te in [ "ec231a86", 3I; "ec301a86", (bigint 0xf0UL) ] do
        let _, calls = runDFP isa hex [ F3, 9UL ] answers
        let expected =
          [ "DFPEXC", [ 23I; te; 9I; 1I ]
            "DQUAI", [ te; 9I; 1I ] ]
        Assert.AreEqual<(string * bigint list) list>(expected, calls, hex)

  /// <summary>
  /// The conversions read and write what their forms name: dctdp the DFP
  /// Short in frB's low word, dcffixqq a VR into a pair, dctfixqq a pair into
  /// a VR -- whose FPRF is undefined and so is not taken from the status.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] DFP conversions read and write their forms``() =
    let answers =
      [ "DFPEXC", answerOf (bigint 0x0203f000UL) 32<rt>
        "DCTDP", answerOf 5I 64<rt>
        "DCFFIXQQ", answerOf (wide 8UL 9UL) 128<rt>
        "DCTFIXQQ", answerOf (wide 10UL 11UL) 128<rt> ]
    (* dctdp f1, f3; dcffixqq f2, v3; dctfixqq v1, f6 *)
    for isa in [ ppc32; ppc64; ppc64le ] do
      let given =
        [ F3, 0x1122334455667788UL; V3A, 1UL; V3B, 2UL; F6, 3UL; F7, 4UL ]
      let after, calls = runDFP isa "ec201a04" given answers
      let short = bigint 0x55667788UL
      let expected = [ "DFPEXC", [ 33I; short; 0I ]; "DCTDP", [ short; 0I ] ]
      Assert.AreEqual<(string * bigint list) list>(expected, calls)
      expect 5UL (after F1) (nameOf isa)
      let after, calls = runDFP isa "fc401fc4" given answers
      let vector = wide 1UL 2UL
      let expected =
        [ "DFPEXC", [ 39I; vector; 0I ]; "DCFFIXQQ", [ vector; 0I ] ]
      Assert.AreEqual<(string * bigint list) list>(expected, calls)
      expect 8UL (after F2) (nameOf isa)
      expect 9UL (after F3) (nameOf isa)
      let after, _ = runDFP isa "fc2137c4" given answers
      expect 10UL (after V1A) (nameOf isa)
      expect 11UL (after V1B) (nameOf isa)
      expect 0x82020000UL (after FPSCR) (nameOf isa)

  /// <summary>
  /// The format instructions alter no FPSCR bit and round nothing: dxex,
  /// ddedpd and dscli make only their result call, without the control byte;
  /// dxex. records CR1 from the FPSCR as it was.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] DXEX DDEDPD DSCLI make only their result call``() =
    let answers =
      [ "DXEX", answerOf 398I 64<rt>
        "DDEDPD", answerOf (bigint 0x123UL) 64<rt>
        "DSCLI", answerOf (bigint 0x40UL) 64<rt> ]
    (* dxex. f1, f3; ddedpd 0, f1, f3; dscli f1, f2, 5 *)
    for isa in [ ppc32; ppc64; ppc64le ] do
      for hex, call, args, result in
        [ "ec201ac5", "DXEX", [ 3I ], 398UL
          "ec201a84", "DDEDPD", [ 0I; 3I ], 0x123UL
          "ec221484", "DSCLI", [ 2I; 5I ], 0x40UL ] do
        let given = [ F2, 2UL; F3, 3UL; FPSCR, 0xa0000000UL ]
        let after, calls = runDFP isa hex given answers
        Assert.AreEqual<(string * bigint list) list>([ call, args ], calls, hex)
        expect result (after F1) hex
        expect 0xa0000000UL (after FPSCR) hex
      let after, _ = runDFP isa "ec201ac5" [ FPSCR, 0xa0000000UL ] answers
      expect 0xaUL (field after cr1) (nameOf isa)

  /// <summary>
  /// The tests pass what they test against: dtstsfi its UIM as a byte,
  /// dtstsf the significance in frA as it is, dtstdc its DCM as a byte.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] DTSTSFI DTSTSF DTSTDC pass their operands``() =
    let answers = [ "DFPEXC", answerOf (bigint 0x2000UL) 32<rt> ]
    (* dtstsfi cr2, 1, f3; dtstsf cr2, f2, f3; dtstdc cr2, f2, 1 *)
    for isa in [ ppc32; ppc64; ppc64le ] do
      for hex, args in
        [ "ed011d46", [ 21I; 1I; 3I; 0I ]
          "ed021d44", [ 19I; 2I; 3I; 0I ]
          "ed020584", [ 13I; 2I; 1I; 0I ] ] do
        let after, calls = runDFP isa hex [ F2, 2UL; F3, 3UL ] answers
        let expected = [ "DFPEXC", args ]
        Assert.AreEqual<(string * bigint list) list>(expected, calls, hex)
        expect 0x2UL (field after cr2) hex

  /// <summary>
  /// fcfids converts the doubleword integer in frB straight to a single,
  /// rounding once, sets FI and XX where that lost anything, and FPRF to the
  /// result's class, which QEMU leaves as it was. 2^62 + 2^38 + 1 rounds to
  /// nearest up past the tie a double would have left at 2^62 + 2^38.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] FCFIDS rounds once and sets FPRF``() =
    (* fcfids f1, f3 *)
    let tie = 0x4000004000000001UL
    checkFP "ec201e9c" F1 [ F3 ]
      [ [ oneHalf ], 0UL, 0x43cffc0000000000UL, 0x4000UL
        [ one ], 1UL, 0x43cff80000000000UL, 0x4001UL
        [ 0UL ], 2UL, 0UL, 0x2002UL
        [ 1UL ], 0x7f001UL, one, 0x4001UL
        [ maxDouble ], 0x20000702UL, 0x43dffc0000000000UL, 0xa2024702UL
        [ tie ], 0UL, 0x43d0000020000000UL, 0x82024000UL ]

  /// <summary>
  /// fctiw, fctiwz and fctidu: the integer, saturated where frB has none the
  /// width holds (VXCVI, and VXSNAN as well for an SNaN), FI and XX where a
  /// fraction was lost, FR where the integer is the farther from zero. FPRF
  /// is undefined (QEMU sets it to the QNaN class on VXCVI) and is not
  /// compared. FX is set only where an exception bit turns on, so a VXCVI
  /// already set leaves it (QEMU sets FX on every exception).
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] FCTIW FCTIWZ FCTIDU set the FPSCR``() =
    (* fctiw f1, f3; fctiwz f1, f3; fctidu f1, f3 *)
    let ignore = fr ||| 0x1f000UL
    let check hex cases =
      for isa in [ ppc32; ppc64; ppc64le ] do
        for b, fpscr, result, after in cases do
          let out = run isa hex [ F3, b; FPSCR, fpscr ]
          let case = $"{hex} {b:x} {fpscr:x} {nameOf isa}"
          expect result (out F1 &&& 0xffffffffUL) case
          expect (after &&& ~~~ignore) (out FPSCR &&& ~~~ignore) case
    check "fc20181c"
      [ oneHalf, 0UL, 2UL, 0x82020000UL
        one, 1UL, 1UL, 1UL
        infinity, 3UL, 0x7fffffffUL, 0xa0011103UL
        qnan, 0xbff80000UL, 0x80000000UL, 0xbff91100UL
        1UL, 0x7f001UL, 0UL, 0x8207f001UL
        maxDouble, 0x20000702UL, 0x7fffffffUL, 0x20000702UL ]
    check "fc20181e" [ oneHalf, 0UL, 1UL, 0x82020000UL ]
    check "fc201f5c"
      [ oneHalf, 0UL, 2UL, 0x82020000UL
        qnan, 0xbff80000UL, 0UL, 0xbff91100UL ]
    for isa in [ ppc32; ppc64; ppc64le ] do
      let out = run isa "fc20181c" [ F3, oneHalf ]
      expect fr (out FPSCR &&& fr) (nameOf isa)

  /// <summary>
  /// frin rounds to the nearest integral value, a tie away from zero, and
  /// sets FR and FI to 0 and FPRF to the result's class.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] FRIN sets FPRF and clears FR and FI``() =
    (* frin f1, f3 *)
    checkFP "fc201b10" F1 [ F3 ]
      [ [ oneHalf ], 0UL, 0x4000000000000000UL, 0x4000UL
        [ 0UL ], 2UL, 0UL, 0x2002UL
        [ infinity ], 3UL, infinity, 0x5003UL
        [ qnan ], 0xbff80000UL, qnan, 0xbff91000UL
        [ 1UL ], 0x7f001UL, 0UL, 0x2001UL
        [ maxDouble ], 0x20000702UL, maxDouble, 0x20004702UL ]
    for isa in [ ppc32; ppc64; ppc64le ] do
      let out = run isa "fc201b10" [ F3, 1UL; FPSCR, 0x7f001UL ]
      expect 0x2001UL (out FPSCR) (nameOf isa)

  /// <summary>
  /// fcmpo BF, frA, frB sets CR field BF and FPSCR[FPCC] to FL, FG, FE or
  /// FU, leaving C as it was (QEMU sets C on an unordered compare); a NaN
  /// raises VXVC, which sets FX where it turns on, and VX.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] FCMPO records the comparison and VXVC``() =
    (* fcmpo cr2, f2, f3 *)
    for isa in [ ppc32; ppc64; ppc64le ] do
      for a, b, fpscr, crField, after in
        [ oneHalf, 0x4002000000000000UL, 0UL, 0x8UL, 0x8000UL
          one, tenth, 1UL, 0x4UL, 0x4001UL
          0UL, minusZero, 2UL, 0x2UL, 0x2002UL
          qnan, one, 0xbff80000UL, 0x1UL, 0xbff81000UL
          qnan, one, 0UL, 0x1UL, 0xa0081000UL ] do
        let out = run isa "fd021840" [ F2, a; F3, b; FPSCR, fpscr ]
        let case = $"{a:x} {b:x} {fpscr:x} {nameOf isa}"
        expect crField (field out cr2) case
        expect after (out FPSCR) case
