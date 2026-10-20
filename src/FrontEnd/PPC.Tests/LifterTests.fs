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

  /// Every processor: 32-bit big-endian, and 64-bit big- and little-endian.
  let everyTarget = [ ppc32; ppc64; ppc64le ]

  /// The two 64-bit processors, for what the 32-bit reference -- a G4, which
  /// has the vector facility of its day -- does not run.
  let only64 = [ ppc64; ppc64le ]

  /// Runs a word on each processor named, over the registers given values,
  /// and asserts that each register wanted holds what QEMU left in it when it
  /// ran the word over the same values.
  let oracle isas hex given wanted =
    for isa in isas do
      let after = run isa hex given
      for r, v in wanted do expect v (after r) $"{hex} {r} {nameOf isa}"

  /// Eight bytes of memory in address order, given as the oracle writes them:
  /// one big-endian doubleword.
  let chunk (v: uint64) = Array.init 8 (fun i -> byte (v >>> (56 - 8 * i)))

  /// The eight bytes of memory from an address, read back as chunk writes
  /// them.
  let chunkAt (memory: Collections.Generic.IReadOnlyDictionary<_, _>) addr =
    Array.init 8 (fun i -> uint64 (memory[addr + uint64 i]: byte))
    |> Array.fold (fun acc b -> (acc <<< 8) ||| b) 0UL

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
  /// lvebx, lvehx and lvewx vD, rA, rB load the element at rA + rB, aligned
  /// down to its size, into the element of vD the address's low four bits
  /// eb name: bytes eb onward on a big-endian processor, and bytes 15 - eb
  /// down on a little-endian one, which numbers the bytes of a register from
  /// the other end. The rest of vD is left as it was.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] LVEBX LVEHX LVEWX place the element by byte order``() =
    let old = 0x0bad0bad0bad0badUL
    let check hex offset memory cases =
      for isa, a, b in cases do
        let given = [ R6, 0x20200078UL; R7, offset; V1A, old; V1B, old ]
        let after, _ = exec isa hex given memory
        expect a (after V1A) $"{hex} {nameOf isa}"
        expect b (after V1B) $"{hex} {nameOf isa}"
    (* lvebx v1, r6, r7 *)
    [ ppc32, 0x0bad0bad0baa0badUL, old
      ppc64, 0x0bad0bad0baa0badUL, old
      ppc64le, old, 0x0badaaad0bad0badUL ]
    |> check "7c26380e" 0xdUL [ 0x20200080UL, chunk 0x7a3e672140aa1b1cUL ]
    (* lvehx v1, r6, r7 *)
    [ ppc32, 0x0bad0bad0badde59UL, old
      ppc64, 0x0bad0bad0badde59UL, old
      ppc64le, old, 0x59de0bad0bad0badUL ]
    |> check "7c26384e" 0xeUL [ 0x20200080UL, chunk 0xc311418ff08fde59UL ]
    (* lvewx v1, r6, r7 *)
    [ ppc32, old, 0x0bad0bad51884f82UL
      ppc64, old, 0x0bad0bad51884f82UL
      ppc64le, 0x824f88510bad0badUL, old ]
    |> check "7c26388e" 0x14UL [ 0x20200088UL, chunk 0x4b4119e451884f82UL ]

  /// <summary>
  /// stvebx, stvehx and stvewx vS, rA, rB store the element of vS the low
  /// four bits eb of rA + rB name, at that address aligned down to the
  /// element's size: bytes eb onward on a big-endian processor and bytes
  /// 15 - eb down on a little-endian one, in the processor's byte order.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] STVEBX STVEHX STVEWX pick the element by byte order``() =
    let check hex offset at bytes cases =
      for isa, stored in cases do
        let given =
          [ R6, 0x20200078UL
            R7, offset
            V1A, 0x0001020304050607UL
            V1B, 0x08090a0b0c0d0e0fUL ]
        let _, memory = exec isa hex given [ at, chunk bytes ]
        expect stored (chunkAt memory at) $"{hex} {nameOf isa}"
    (* stvebx v1, r6, r7 *)
    [ ppc32, 0x77c682de4e057c2eUL
      ppc64, 0x77c682de4e057c2eUL
      ppc64le, 0x77c682de4e0a7c2eUL ]
    |> check "7c26390e" 0xdUL 0x20200080UL 0x77c682de4e967c2eUL
    (* stvehx v1, r6, r7 *)
    [ ppc32, 0x39d137c667e30607UL
      ppc64, 0x39d137c667e30607UL
      ppc64le, 0x39d137c667e30908UL ]
    |> check "7c26394e" 0xeUL 0x20200080UL 0x39d137c667e343f7UL
    (* stvewx v1, r6, r7 *)
    [ ppc32, 0xd4465b420c0d0e0fUL
      ppc64, 0xd4465b420c0d0e0fUL
      ppc64le, 0xd4465b4203020100UL ]
    |> check "7c26398e" 0x14UL 0x20200088UL 0xd4465b42e7cd5698UL

  /// <summary>
  /// vpkudum v12, v8, v12 and vmsumubm v0, v13, v12, v0 -- the two words a
  /// ppc64el C++ program and tar first stopped on -- name their target among
  /// their sources: every element of the result is computed from the
  /// registers as they were before any of it is written.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VPKUDUM and VMSUMUBM read a target that is a source``() =
    (* vpkudum v12, v8, v12 *)
    let given =
      [ V8A, 0x0123456789abcdefUL
        V8B, 0xfedcba9876543210UL
        V12A, 0x00000001ffffffffUL
        V12B, 0x8000000012345678UL ]
    let wanted = [ V12A, 0x89abcdef76543210UL; V12B, 0xffffffff12345678UL ]
    oracle only64 "1188644e" given wanted
    (* vmsumubm v0, v13, v12, v0 *)
    let given =
      [ V0A, 0x0000000100000002UL
        V0B, 0x80000000ffffffffUL
        V12A, 0xfffefdfc80808080UL
        V12B, 0x017f80ff11223344UL
        V13A, 0x0102030405060708UL
        V13B, 0x090a0b0c0d0e0f10UL ]
    let wanted = [ V0A, 0x000009e300000d02UL; V0B, 0x80001673000009f5UL ]
    oracle only64 "100d6024" given wanted

  /// <summary>
  /// vmulouw v0, v0, v13 and vmuleuw v0, v0, v13, the forms xxhash's
  /// accumulate loop uses, multiply into a target that is also a source: both
  /// products are formed from vA as it was before either reaches vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMULOUW and VMULEUW read a target that is a source``() =
    let given =
      [ V0A, 0x9e3779b185ebca77UL
        V0B, 0xc2b2ae3d27d4eb2fUL
        V13A, 0x165667b19e3779f9UL
        V13B, 0xfffffffe00000003UL ]
    (* vmulouw v0, v0, v13 *)
    let wanted = [ V0A, 0x52c48c6ca69b2cbfUL; V0B, 0x00000000777ec18dUL ]
    oracle only64 "10006888" given wanted
    (* vmuleuw v0, v0, v13 *)
    let wanted = [ V0A, 0x0dce2b2dcdc75a61UL; V0B, 0xc2b2ae3b7a9aa386UL ]
    oracle only64 "10006a88" given wanted

  /// <summary>
  /// vcipher, vcipherlast, vncipher, vncipherlast and vsbox go out as the
  /// named AES calls the other front ends use, IRRunner having no AES of its
  /// own: vcipher one full round (AESENC), vcipherlast and vsbox the last
  /// round (AESENCLAST, vsbox with a zero key and its ShiftRows undone),
  /// vncipherlast the last inverse round (AESDECLAST), and vncipher -- whose
  /// key is added before InvMixColumns -- that round followed by
  /// InvMixColumns on its own (AESIMC). Their values were checked against
  /// QEMU outside the suite, through the host's AES instructions.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] The AES rounds lift to the named AES calls``() =
    let rec callsIn (e: Expr) =
      match e with
      | BinOp(Op = BinIR.BinOpType.APP; Left = FuncName(Name = n)) ->
        [ n ]
      | BinOp(Left = l; Right = r) | RelOp(Left = l; Right = r) ->
        callsIn l @ callsIn r
      | UnOp(Operand = x) | Cast(Operand = x) | Extract(Operand = x) ->
        callsIn x
      | Ite(Cond = c; TrueExpr = a; FalseExpr = b) ->
        callsIn c @ callsIn a @ callsIn b
      | _ ->
        []
    let callsOf isa hex =
      lifted isa hex
      |> Array.toList
      |> List.collect (function
        | Put(Src = s) ->
          callsIn s
        | _ ->
          [])
      |> List.toArray
    (* vcipher v1, v2, v3; vcipherlast v1, v2, v3; vncipher v1, v2, v3;
       vncipherlast v1, v2, v3; vsbox v1, v2 *)
    for hex, calls in
      [ "10221d08", [| "AESENC" |]
        "10221d09", [| "AESENCLAST" |]
        "10221d48", [| "AESDECLAST"; "AESIMC" |]
        "10221d49", [| "AESDECLAST" |]
        "102205c8", [| "AESENCLAST" |] ] do
      for isa in only64 do
        CollectionAssert.AreEqual(calls, callsOf isa hex, hex)

  /// <summary>
  /// vshasigmaw and vshasigmad pick their function per element: ST the
  /// lower- or upper-case sigma, and a bit of SIX -- bit i for word i, bit 2i
  /// for doubleword i -- sigma 0 or 1, so one word mixes the four functions.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSHASIGMAW and VSHASIGMAD pick a function per element``() =
    let given = [ V2A, 0x0123456789abcdefUL; V2B, 0x7fffffff80000001UL ]
    (* vshasigmaw v1, v2, 0, 10; vshasigmaw v1, v2, 1, 5;
       vshasigmad v1, v2, 0, 2; vshasigmad v1, v2, 1, 8 *)
    for hex, hi, lo in
      [ "10225682", 0xca1f28643d5dcc4cUL, 0x001fafff13006000UL
        "1022ae82", 0x66654447d6316d8aUL, 0xdffbfdff063000c0UL
        "102216c2", 0x6f92c77c6c4f1aa1UL, 0xfe002ffc01fff00bUL
        "1022c6c2", 0x7703112333475567UL, 0x1f000017a2fffff8UL ] do
      oracle only64 hex given [ V1A, hi; V1B, lo ]

  /// <summary>
  /// bcdadd. and bcdsub. vD, vA, vB, PS work on signed packed decimals: 31
  /// digits and a sign code, 0b1011 and 0b1101 negative and the other four
  /// valid codes positive. The result's sign code is 0b1101 when negative and
  /// otherwise 0b1100, or 0b1111 where PS is 1; CR6 says less than, greater
  /// than or equal to zero, with its last bit set on overflowing 31 digits.
  /// An invalid operand makes the result undefined and CR6 0b0001; QEMU
  /// writes all ones there, which is what is lifted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] BCDADDdot and BCDSUBdot add signed packed decimals``() =
    let check hex a b result cr6 =
      let given = [ V2B, a; V3B, b ]
      let field =
        [ CR6_0, (cr6 >>> 3) &&& 1UL
          CR6_1, (cr6 >>> 2) &&& 1UL
          CR6_2, (cr6 >>> 1) &&& 1UL
          CR6_3, cr6 &&& 1UL ]
      let wanted = [ V1A, 0UL; V1B, result ] @ field
      oracle only64 hex given wanted
    (* bcdadd. v1, v2, v3, 0 *)
    check "10221c01" 0x123cUL 0x456cUL 0x579cUL 0b0100UL
    check "10221c01" 0x5dUL 0x3cUL 0x2dUL 0b1000UL
    check "10221c01" 0x7aUL 0x7bUL 0xcUL 0b0010UL
    check "10221c01" 0x987654321fUL 0x123456789eUL 0x1111111110cUL 0b0100UL
    (* bcdadd. v1, v2, v3, 1 *)
    check "10221e01" 0x123cUL 0x456cUL 0x579fUL 0b0100UL
    check "10221e01" 0x7aUL 0x7bUL 0xfUL 0b0010UL
    (* bcdsub. v1, v2, v3, 0 *)
    check "10221c41" 0x123cUL 0x456cUL 0x333dUL 0b1000UL
    check "10221c41" 0x5dUL 0x3cUL 0x8dUL 0b1000UL
    check "10221c41" 0x42cUL 0x42cUL 0xcUL 0b0010UL
    (* bcdsub. v1, v2, v3, 1 *)
    check "10221e41" 0x7aUL 0x7bUL 0x14fUL 0b0100UL
    check "10221e41" 0x42cUL 0x42cUL 0xfUL 0b0010UL

  /// <summary>
  /// bcdadd. keeps the low 31 digits of a sum that needs 32 and sets the
  /// last bit of CR6, the sign still that of the whole sum; an operand that
  /// is not a valid encoding sets CR6 to 0b0001 alone.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] BCDADDdot reports overflow and invalid operands``() =
    let nines = 0x9999999999999999UL
    (* bcdadd. v1, v2, v3, 0 *)
    let given =
      [ V2A, nines
        V2B, 0x999999999999999cUL
        V3B, 0x1cUL ]
    let wanted =
      [ V1A, 0UL
        V1B, 0xcUL
        CR6_0, 0UL
        CR6_1, 1UL
        CR6_2, 0UL
        CR6_3, 1UL ]
    oracle only64 "10221c01" given wanted
    let given =
      [ V2A, nines
        V2B, 0x999999999999999dUL
        V3B, 0x2dUL ]
    let wanted =
      [ V1A, 0UL
        V1B, 0x1dUL
        CR6_0, 1UL
        CR6_1, 0UL
        CR6_2, 0UL
        CR6_3, 1UL ]
    oracle only64 "10221c01" given wanted
    let given = [ V2B, 0x1cUL; V3B, 0xa0UL ]
    let wanted =
      [ V1A, UInt64.MaxValue
        V1B, UInt64.MaxValue
        CR6_0, 0UL
        CR6_1, 0UL
        CR6_2, 0UL
        CR6_3, 1UL ]
    oracle only64 "10221c01" given wanted

  /// <summary>
  /// vpkuhus vD, vA, vB narrows each of the unsigned halfwords of vA followed
  /// by those of vB to one of the unsigned bytes of vD; a value outside 0 ..
  /// 255 is clamped to the nearer end and sets VSCR[SAT], which is sticky.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VPKUHUS clamps unsigned halfwords to unsigned bytes``() =
    (* vpkuhus v1, v2, v3 *)
    let given =
      [ V2A, 0x0001020304050607UL
        V2B, 0x08090a0b0c0d0e0fUL
        V3A, 0x0f0e0d0c0b0a0908UL
        V3B, 0x0706050403020100UL
        VSCR, 0x10000UL ]
    let wanted =
      [ V1A, 0x01ffffffffffffffUL
        V1B, 0xffffffffffffffffUL
        VSCR, 0x10001UL ]
    oracle everyTarget "1022188e" given wanted

  /// <summary>
  /// vpkuwus vD, vA, vB narrows each of the unsigned words of vA followed by
  /// those of vB to one of the unsigned halfwords of vD; a value outside 0 ..
  /// 2^16 - 1 is clamped to the nearer end and sets VSCR[SAT], which is
  /// sticky.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VPKUWUS clamps unsigned words to unsigned halfwords``() =
    (* vpkuwus v1, v2, v3 *)
    let given =
      [ V2A, 0x0001020304050607UL
        V2B, 0x08090a0b0c0d0e0fUL
        V3A, 0x0f0e0d0c0b0a0908UL
        V3B, 0x0706050403020100UL
        VSCR, 0x10000UL ]
    let wanted =
      [ V1A, 0xffffffffffffffffUL
        V1B, 0xffffffffffffffffUL
        VSCR, 0x10001UL ]
    oracle everyTarget "102218ce" given wanted

  /// <summary>
  /// vpkshss vD, vA, vB narrows each of the signed halfwords of vA followed
  /// by those of vB to one of the signed bytes of vD; a value outside -128 ..
  /// 127 is clamped to the nearer end and sets VSCR[SAT], which is sticky.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VPKSHSS clamps signed halfwords to signed bytes``() =
    (* vpkshss v1, v2, v3 *)
    let given =
      [ V2A, 0x0001020304050607UL
        V2B, 0x08090a0b0c0d0e0fUL
        V3A, 0x0f0e0d0c0b0a0908UL
        V3B, 0x0706050403020100UL
        VSCR, 0x10000UL ]
    let wanted =
      [ V1A, 0x017f7f7f7f7f7f7fUL
        V1B, 0x7f7f7f7f7f7f7f7fUL
        VSCR, 0x10001UL ]
    oracle everyTarget "1022198e" given wanted

  /// <summary>
  /// vpkswss vD, vA, vB narrows each of the signed words of vA followed by
  /// those of vB to one of the signed halfwords of vD; a value outside -2^15
  /// .. 2^15 - 1 is clamped to the nearer end and sets VSCR[SAT], which is
  /// sticky.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VPKSWSS clamps signed words to signed halfwords``() =
    (* vpkswss v1, v2, v3 *)
    let given =
      [ V2A, 0x0001020304050607UL
        V2B, 0x08090a0b0c0d0e0fUL
        V3A, 0x0f0e0d0c0b0a0908UL
        V3B, 0x0706050403020100UL
        VSCR, 0x10000UL ]
    let wanted =
      [ V1A, 0x7fff7fff7fff7fffUL
        V1B, 0x7fff7fff7fff7fffUL
        VSCR, 0x10001UL ]
    oracle everyTarget "102219ce" given wanted

  /// <summary>
  /// vpkshus vD, vA, vB narrows each of the signed halfwords of vA followed
  /// by those of vB to one of the unsigned bytes of vD; a value outside 0 ..
  /// 255 is clamped to the nearer end and sets VSCR[SAT], which is sticky.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VPKSHUS clamps signed halfwords to unsigned bytes``() =
    (* vpkshus v1, v2, v3 *)
    let given =
      [ V2A, 0x0001020304050607UL
        V2B, 0x08090a0b0c0d0e0fUL
        V3A, 0x0f0e0d0c0b0a0908UL
        V3B, 0x0706050403020100UL
        VSCR, 0x10000UL ]
    let wanted =
      [ V1A, 0x01ffffffffffffffUL
        V1B, 0xffffffffffffffffUL
        VSCR, 0x10001UL ]
    oracle everyTarget "1022190e" given wanted

  /// <summary>
  /// vpkswus vD, vA, vB narrows each of the signed words of vA followed by
  /// those of vB to one of the unsigned halfwords of vD; a value outside 0 ..
  /// 2^16 - 1 is clamped to the nearer end and sets VSCR[SAT], which is
  /// sticky.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VPKSWUS clamps signed words to unsigned halfwords``() =
    (* vpkswus v1, v2, v3 *)
    let given =
      [ V2A, 0x0001020304050607UL
        V2B, 0x08090a0b0c0d0e0fUL
        V3A, 0x0f0e0d0c0b0a0908UL
        V3B, 0x0706050403020100UL
        VSCR, 0x10000UL ]
    let wanted =
      [ V1A, 0xffffffffffffffffUL
        V1B, 0xffffffffffffffffUL
        VSCR, 0x10001UL ]
    oracle everyTarget "1022194e" given wanted

  /// <summary>
  /// vpkpx vD, vA, vB packs each word of vA followed by vB, a pixel of four
  /// bytes, into a halfword of vD: the lowest bit of its first byte, then the
  /// top five bits of each of the other three.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VPKPX packs pixels into halfwords``() =
    (* vpkpx v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0xffff0000ffff0000UL; V1B, 0x0000ffffffff0000UL ]
    oracle everyTarget "10221b0e" given wanted

  /// <summary>
  /// vupkhpx vD, vB unpacks each of the high four halfwords of vB, a pixel of
  /// a bit and three five-bit fields, into a word of vD: the bit sign-
  /// extended to a byte and each field zero-extended to one.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VUPKHPX unpacks the high four pixels``() =
    (* vupkhpx v1, v3 *)
    let given = [ V3A, 0x7fffffff80000000UL; V3B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0x001f1f1fff1f1f1fUL; V1B, 0xff00000000000000UL ]
    oracle everyTarget "10201b4e" given wanted

  /// <summary>
  /// vupklpx vD, vB unpacks each of the low four halfwords of vB, a pixel of
  /// a bit and three five-bit fields, into a word of vD: the bit sign-
  /// extended to a byte and each field zero-extended to one.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VUPKLPX unpacks the low four pixels``() =
    (* vupklpx v1, v3 *)
    let given = [ V3A, 0x7fffffff80000000UL; V3B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0xff1f1f1fff1f1f1fUL; V1B, 0x0000000000000001UL ]
    oracle everyTarget "10201bce" given wanted

  /// <summary>
  /// vmhaddshs vD, vA, vB, vC adds to each signed halfword of vC the product
  /// of the matching halfwords of vA and vB shifted right 15 bits, clamping
  /// the sum to a signed halfword and setting VSCR[SAT] where it has to.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMHADDSHS adds high halves of halfword products``() =
    (* vmhaddshs v1, v2, v3, v4 *)
    let given =
      [ V2A, 0x0001020304050607UL
        V2B, 0x08090a0b0c0d0e0fUL
        V3A, 0x0f0e0d0c0b0a0908UL
        V3B, 0x0706050403020100UL
        V4A, 0x1011121314151617UL
        V4B, 0x18191a1b1c1d1e1fUL
        VSCR, 0x10000UL ]
    let wanted =
      [ V1A, 0x10111247146d1683UL
        V1B, 0x18891a7f1c651e3bUL
        VSCR, 0x10000UL ]
    oracle everyTarget "10221920" given wanted

  /// <summary>
  /// vmhraddshs vD, vA, vB, vC does what vmhaddshs does but adds 0x4000 to
  /// each product before the shift, rounding it to nearest.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMHRADDSHS adds rounded high halves of products``() =
    (* vmhraddshs v1, v2, v3, v4 *)
    let given =
      [ V2A, 0x0001020304050607UL
        V2B, 0x08090a0b0c0d0e0fUL
        V3A, 0x0f0e0d0c0b0a0908UL
        V3B, 0x0706050403020100UL
        V4A, 0x1011121314151617UL
        V4B, 0x18191a1b1c1d1e1fUL
        VSCR, 0x10000UL ]
    let wanted =
      [ V1A, 0x10111247146e1684UL
        V1B, 0x188a1a801c651e3bUL
        VSCR, 0x10000UL ]
    oracle everyTarget "10221921" given wanted

  /// <summary>
  /// vmladduhm vD, vA, vB, vC writes the low 16 bits of each halfword product
  /// of vA and vB plus the matching halfword of vC.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMLADDUHM multiplies and adds halfwords modulo``() =
    (* vmladduhm v1, v2, v3, v4 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL
        V4A, 0x0000000100000001UL
        V4B, 0x0000000100000001UL ]
    let wanted = [ V1A, 0x0000000080000001UL; V1B, 0x8001000200000001UL ]
    oracle everyTarget "10221922" given wanted

  /// <summary>
  /// vmsumubm vD, vA, vB, vC adds to each word of vC the four products of the
  /// unsigned bytes of vA and vB that lie within it, keeping the low 32 bits
  /// of the sum.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMSUMUBM sums unsigned byte products into words``() =
    (* vmsumubm v1, v2, v3, v4 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL
        V4A, 0x0000000100000001UL
        V4B, 0x0000000100000001UL ]
    let wanted = [ V1A, 0x0000010000007f81UL; V1B, 0x0003788500000001UL ]
    oracle everyTarget "10221924" given wanted

  /// <summary>
  /// vmsummbm vD, vA, vB, vC adds to each word of vC the four products of the
  /// signed bytes of vA and the unsigned bytes of vB that lie within it,
  /// keeping the low 32 bits of the sum.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMSUMMBM sums mixed byte products into words``() =
    (* vmsummbm v1, v2, v3, v4 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL
        V4A, 0x0000000100000001UL
        V4B, 0x0000000100000001UL ]
    let wanted = [ V1A, 0x00000000ffff8081UL; V1B, 0xfffffc8500000001UL ]
    oracle everyTarget "10221925" given wanted

  /// <summary>
  /// vmsumuhm vD, vA, vB, vC adds to each word of vC the two products of the
  /// unsigned halfwords of vA and vB that lie within it, keeping the low 32
  /// bits of the sum.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMSUMUHM sums unsigned halfword products into words``() =
    (* vmsumuhm v1, v2, v3, v4 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL
        V4A, 0x0000000100000001UL
        V4B, 0x0000000100000001UL ]
    let wanted = [ V1A, 0x000100007fff8001UL; V1B, 0x7ffc800300000001UL ]
    oracle everyTarget "10221926" given wanted

  /// <summary>
  /// vmsumuhs vD, vA, vB, vC adds to each unsigned word of vC the two
  /// products of the unsigned halfwords of vA and vB within it; a sum above
  /// 2^32 - 1 is clamped to it and sets VSCR[SAT], which is sticky.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMSUMUHS sums unsigned halfword products saturating``() =
    (* vmsumuhs v1, v2, v3, v4 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL
        V4A, 0x0000000100000001UL
        V4B, 0x0000000100000001UL ]
    let wanted =
      [ V1A, 0x000100007fff8001UL
        V1B, 0xffffffff00000001UL
        VSCR, 0x1UL ]
    oracle everyTarget "10221927" given wanted
    let given =
      [ V2A, 0x0001020304050607UL
        V2B, 0x08090a0b0c0d0e0fUL
        V3A, 0x0f0e0d0c0b0a0908UL
        V3B, 0x0706050403020100UL
        V4A, 0x1011121314151617UL
        V4B, 0x18191a1b1c1d1e1fUL
        VSCR, 0x10000UL ]
    let wanted =
      [ V1A, 0x102b60451477e481UL
        V1B, 0x1883e87d1c4f6c39UL
        VSCR, 0x10000UL ]
    oracle everyTarget "10221927" given wanted

  /// <summary>
  /// vmsumshm vD, vA, vB, vC adds to each word of vC the two products of the
  /// signed halfwords of vA and vB that lie within it, keeping the low 32
  /// bits of the sum.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMSUMSHM sums signed halfword products into words``() =
    (* vmsumshm v1, v2, v3, v4 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL
        V4A, 0x0000000100000001UL
        V4B, 0x0000000100000001UL ]
    let wanted = [ V1A, 0x0000000000008001UL; V1B, 0xffff800300000001UL ]
    oracle everyTarget "10221928" given wanted

  /// <summary>
  /// vmsumshs vD, vA, vB, vC adds to each signed word of vC the two products
  /// of the signed halfwords of vA and vB within it; a sum outside the range
  /// of a signed word is clamped to the nearer end and sets VSCR[SAT].
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMSUMSHS sums signed halfword products saturating``() =
    (* vmsumshs v1, v2, v3, v4 *)
    let given =
      [ V2A, 0x0001020304050607UL
        V2B, 0x08090a0b0c0d0e0fUL
        V3A, 0x0f0e0d0c0b0a0908UL
        V3B, 0x0706050403020100UL
        V4A, 0x1011121314151617UL
        V4B, 0x18191a1b1c1d1e1fUL
        VSCR, 0x10000UL ]
    let wanted =
      [ V1A, 0x102b60451477e481UL
        V1B, 0x1883e87d1c4f6c39UL
        VSCR, 0x10000UL ]
    oracle everyTarget "10221929" given wanted

  /// <summary>
  /// vmsumudm vD, vA, vB, vC adds the two products of the unsigned
  /// doublewords of vA and vB to vC, a 128-bit number, and keeps the low 128
  /// bits of the sum.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMSUMUDM sums unsigned doubleword products``() =
    (* vmsumudm v1, v2, v3, v4 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL
        V4A, 0x0000000100000001UL
        V4B, 0x0000000100000001UL ]
    let wanted = [ V1A, 0x8000000100000000UL; V1B, 0x8000000100000001UL ]
    oracle only64 "10221923" given wanted

  /// <summary>
  /// vmsumcud vD, vA, vB, vC writes into vD what the exact sum vmsumudm keeps
  /// the low 128 bits of holds above them: 0, 1 or 2.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMSUMCUD writes the carry out of vmsumudm``() =
    (* vmsumcud v1, v2, v3, v4 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL
        V4A, 0x0000000100000001UL
        V4B, 0x0000000100000001UL ]
    let wanted = [ V1A, 0x0000000000000000UL; V1B, 0x0000000000000000UL ]
    oracle only64 "10221917" given wanted

  /// <summary>
  /// vpkudum vD, vA, vB writes the low word of each doubleword of vA followed
  /// by those of vB into the four words of vD, dropping the high words
  /// whatever they hold.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VPKUDUM packs the low words of doublewords``() =
    (* vpkudum v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x8000000000000001UL; V1B, 0xffffffff80000000UL ]
    oracle only64 "10221c4e" given wanted

  /// <summary>
  /// vpksdss vD, vA, vB narrows each of the signed doublewords of vA followed
  /// by those of vB to one of the signed words of vD; a value outside -2^31
  /// .. 2^31 - 1 is clamped to the nearer end and sets VSCR[SAT], which is
  /// sticky.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VPKSDSS clamps signed doublewords to signed words``() =
    (* vpksdss v1, v2, v3 *)
    let given =
      [ V2A, 0x0001020304050607UL
        V2B, 0x08090a0b0c0d0e0fUL
        V3A, 0x0f0e0d0c0b0a0908UL
        V3B, 0x0706050403020100UL
        VSCR, 0x10000UL ]
    let wanted =
      [ V1A, 0x7fffffff7fffffffUL
        V1B, 0x7fffffff7fffffffUL
        VSCR, 0x10001UL ]
    oracle only64 "10221dce" given wanted

  /// <summary>
  /// vpksdus vD, vA, vB narrows each of the signed doublewords of vA followed
  /// by those of vB to one of the unsigned words of vD; a value outside 0 ..
  /// 2^32 - 1 is clamped to the nearer end and sets VSCR[SAT], which is
  /// sticky.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VPKSDUS clamps signed doublewords to unsigned words``() =
    (* vpksdus v1, v2, v3 *)
    let given =
      [ V2A, 0x0001020304050607UL
        V2B, 0x08090a0b0c0d0e0fUL
        V3A, 0x0f0e0d0c0b0a0908UL
        V3B, 0x0706050403020100UL
        VSCR, 0x10000UL ]
    let wanted =
      [ V1A, 0xffffffffffffffffUL
        V1B, 0xffffffffffffffffUL
        VSCR, 0x10001UL ]
    oracle only64 "10221d4e" given wanted

  /// <summary>
  /// vpkudus vD, vA, vB narrows each of the unsigned doublewords of vA
  /// followed by those of vB to one of the unsigned words of vD; a value
  /// outside 0 .. 2^32 - 1 is clamped to the nearer end and sets VSCR[SAT],
  /// which is sticky.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VPKUDUS clamps unsigned doublewords to unsigned words``() =
    (* vpkudus v1, v2, v3 *)
    let given =
      [ V2A, 0x0001020304050607UL
        V2B, 0x08090a0b0c0d0e0fUL
        V3A, 0x0f0e0d0c0b0a0908UL
        V3B, 0x0706050403020100UL
        VSCR, 0x10000UL ]
    let wanted =
      [ V1A, 0xffffffffffffffffUL
        V1B, 0xffffffffffffffffUL
        VSCR, 0x10001UL ]
    oracle only64 "10221cce" given wanted

  /// <summary>
  /// vmuleub vD, vA, vB multiplies the unsigned bytes 0, 2, ... of vA and vB,
  /// writing each exact product into a halfword of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMULEUB multiplies the even unsigned bytes``() =
    (* vmuleub v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x000000007f800000UL; V1B, 0x7e81fe0100000000UL ]
    oracle everyTarget "10221a08" given wanted

  /// <summary>
  /// vmuloub vD, vA, vB multiplies the unsigned bytes 1, 3, ... of vA and vB,
  /// writing each exact product into a halfword of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMULOUB multiplies the odd unsigned bytes``() =
    (* vmuloub v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x000000ff00000000UL; V1B, 0xfe01fe0100000000UL ]
    oracle everyTarget "10221808" given wanted

  /// <summary>
  /// vmulesb vD, vA, vB multiplies the signed bytes 0, 2, ... of vA and vB,
  /// writing each exact product into a halfword of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMULESB multiplies the even signed bytes``() =
    (* vmulesb v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x0000000000800000UL; V1B, 0xff81000100000000UL ]
    oracle everyTarget "10221b08" given wanted

  /// <summary>
  /// vmulosb vD, vA, vB multiplies the signed bytes 1, 3, ... of vA and vB,
  /// writing each exact product into a halfword of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMULOSB multiplies the odd signed bytes``() =
    (* vmulosb v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x0000ffff00000000UL; V1B, 0x0001000100000000UL ]
    oracle everyTarget "10221908" given wanted

  /// <summary>
  /// vmuleuh vD, vA, vB multiplies the unsigned halfwords 0, 2, ... of vA and
  /// vB, writing each exact product into a word of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMULEUH multiplies the even unsigned halfwords``() =
    (* vmuleuh v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x000000007fff8000UL; V1B, 0x7ffe800100000000UL ]
    oracle everyTarget "10221a48" given wanted

  /// <summary>
  /// vmulouh vD, vA, vB multiplies the unsigned halfwords 1, 3, ... of vA and
  /// vB, writing each exact product into a word of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMULOUH multiplies the odd unsigned halfwords``() =
    (* vmulouh v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x0000ffff00000000UL; V1B, 0xfffe000100000000UL ]
    oracle everyTarget "10221848" given wanted

  /// <summary>
  /// vmulesh vD, vA, vB multiplies the signed halfwords 0, 2, ... of vA and
  /// vB, writing each exact product into a word of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMULESH multiplies the even signed halfwords``() =
    (* vmulesh v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x0000000000008000UL; V1B, 0xffff800100000000UL ]
    oracle everyTarget "10221b48" given wanted

  /// <summary>
  /// vmulosh vD, vA, vB multiplies the signed halfwords 1, 3, ... of vA and
  /// vB, writing each exact product into a word of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMULOSH multiplies the odd signed halfwords``() =
    (* vmulosh v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0xffffffff00000000UL; V1B, 0x0000000100000000UL ]
    oracle everyTarget "10221948" given wanted

  /// <summary>
  /// vmuleuw vD, vA, vB multiplies the unsigned words 0 and 2 of vA and vB
  /// into the two doublewords of vD, each product exact.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMULEUW multiplies the even unsigned words``() =
    (* vmuleuw v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x000000007fffffffUL; V1B, 0x7ffffffe80000001UL ]
    oracle only64 "10221a88" given wanted

  /// <summary>
  /// vmulouw vD, vA, vB multiplies the unsigned words 1 and 3 of vA and vB
  /// into the two doublewords of vD, each product exact.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMULOUW multiplies the odd unsigned words``() =
    (* vmulouw v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x7fffffff80000000UL; V1B, 0x0000000080000000UL ]
    oracle only64 "10221888" given wanted

  /// <summary>
  /// vmuleud vD, vA, vB multiplies the unsigned doublewords 0, 2, ... of vA
  /// and vB, writing each exact product into a quadword of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMULEUD multiplies the even unsigned doublewords``() =
    (* vmuleud v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x00000000fffffffeUL; V1B, 0x8000000080000000UL ]
    oracle only64 "10221ac8" given wanted

  /// <summary>
  /// vmuloud vD, vA, vB multiplies the unsigned doublewords 1, 3, ... of vA
  /// and vB, writing each exact product into a quadword of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMULOUD multiplies the odd unsigned doublewords``() =
    (* vmuloud v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x7fffffff00000000UL; V1B, 0xffffffff80000000UL ]
    oracle only64 "102218c8" given wanted

  /// <summary>
  /// vmulesd vD, vA, vB multiplies the signed doublewords 0, 2, ... of vA and
  /// vB, writing each exact product into a quadword of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMULESD multiplies the even signed doublewords``() =
    (* vmulesd v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x00000000fffffffeUL; V1B, 0x8000000080000000UL ]
    oracle only64 "10221bc8" given wanted

  /// <summary>
  /// vmulosd vD, vA, vB multiplies the signed doublewords 1, 3, ... of vA and
  /// vB, writing each exact product into a quadword of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMULOSD multiplies the odd signed doublewords``() =
    (* vmulosd v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0xffffffff80000000UL; V1B, 0xffffffff80000000UL ]
    oracle only64 "102219c8" given wanted

  /// <summary>
  /// vadduqm vD, vA, vB writes into vD the low 128 bits of vA + vB, the two
  /// registers read as 128-bit numbers, so a carry crosses the middle of the
  /// register.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VADDUQM computes a quadword sum``() =
    (* vadduqm v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x8000000180000000UL; V1B, 0x7ffffffe80000001UL ]
    oracle only64 "10221900" given wanted

  /// <summary>
  /// vaddcuq vD, vA, vB writes into vD, as a 128-bit number, the carry out of
  /// vA + vB computed over the two registers as 128-bit unsigned numbers: 0
  /// or 1.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VADDCUQ writes the carry out of a quadword sum``() =
    (* vaddcuq v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x0000000000000000UL; V1B, 0x0000000000000000UL ]
    oracle only64 "10221940" given wanted

  /// <summary>
  /// vaddeuqm vD, vA, vB, vC writes into vD the low 128 bits of vA + vB + the
  /// lowest bit of vC, the two registers read as 128-bit numbers, so a carry
  /// crosses the middle of the register.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VADDEUQM computes a quadword sum``() =
    (* vaddeuqm v1, v2, v3, v4 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL
        V4A, 0x0000000100000001UL
        V4B, 0x0000000100000001UL ]
    let wanted = [ V1A, 0x8000000180000000UL; V1B, 0x7ffffffe80000002UL ]
    oracle only64 "1022193c" given wanted

  /// <summary>
  /// vaddecuq vD, vA, vB, vC writes into vD, as a 128-bit number, the carry
  /// out of vA + vB + the lowest bit of vC computed over the two registers as
  /// 128-bit unsigned numbers: 0 or 1.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VADDECUQ writes the carry out of a quadword sum``() =
    (* vaddecuq v1, v2, v3, v4 *)
    let given =
      [ V2A, 0x0123456789abcdefUL
        V2B, 0xfedcba9876543210UL
        V3A, 0xfedcba9876543210UL
        V3B, 0x0123456789abcdefUL
        V4A, 0x00000000ffffffffUL
        V4B, 0x00000000ffffffffUL ]
    let wanted = [ V1A, 0x0000000000000000UL; V1B, 0x0000000000000001UL ]
    oracle only64 "1022193d" given wanted

  /// <summary>
  /// vsubuqm vD, vA, vB writes into vD the low 128 bits of vA + ~vB + 1, the
  /// two registers read as 128-bit numbers, so a carry crosses the middle of
  /// the register.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSUBUQM computes a quadword difference``() =
    (* vsubuqm v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x7ffffffd80000001UL; V1B, 0x7fffffff80000001UL ]
    oracle only64 "10221d00" given wanted

  /// <summary>
  /// vsubcuq vD, vA, vB writes into vD, as a 128-bit number, the carry out of
  /// vA + ~vB + 1 computed over the two registers as 128-bit unsigned
  /// numbers: 0 or 1.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSUBCUQ writes the carry out of a quadword difference``() =
    (* vsubcuq v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x0000000000000000UL; V1B, 0x0000000000000001UL ]
    oracle only64 "10221d40" given wanted

  /// <summary>
  /// vsubeuqm vD, vA, vB, vC writes into vD the low 128 bits of vA + ~vB +
  /// the lowest bit of vC, the two registers read as 128-bit numbers, so a
  /// carry crosses the middle of the register.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSUBEUQM computes a quadword difference``() =
    (* vsubeuqm v1, v2, v3, v4 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL
        V4A, 0x0000000100000001UL
        V4B, 0x0000000100000001UL ]
    let wanted = [ V1A, 0x7ffffffd80000001UL; V1B, 0x7fffffff80000001UL ]
    oracle only64 "1022193e" given wanted

  /// <summary>
  /// vsubecuq vD, vA, vB, vC writes into vD, as a 128-bit number, the carry
  /// out of vA + ~vB + the lowest bit of vC computed over the two registers
  /// as 128-bit unsigned numbers: 0 or 1.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSUBECUQ writes the carry out of a quadword difference``() =
    (* vsubecuq v1, v2, v3, v4 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL
        V4A, 0x0000000100000001UL
        V4B, 0x0000000100000001UL ]
    let wanted = [ V1A, 0x0000000000000000UL; V1B, 0x0000000000000001UL ]
    oracle only64 "1022193f" given wanted

  /// <summary>
  /// vshasigmaw vD, vA, ST, SIX applies to each word of vA one of the four
  /// SHA-256 sigma functions: the lower-case ones (rotates and a shift) where
  /// ST is 0, the upper-case ones (three rotates) where it is 1, and sigma 0
  /// or 1 as bit i of SIX says for word i.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSHASIGMAW applies the SHA-256 sigma functions``() =
    (* vshasigmaw v1, v2, 0, 0 *)
    let given = [ V2A, 0x7fffffff80000000UL; V2B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0x0effdfff11002000UL; V1B, 0x1fffffff02004000UL ]
    oracle only64 "10220682" given wanted

  /// <summary>
  /// vshasigmad vD, vA, ST, SIX applies to each doubleword of vA one of the
  /// four SHA-512 sigma functions: ST picks the lower- or upper-case pair and
  /// bit 2i of SIX picks sigma 0 or 1 for doubleword i.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSHASIGMAD applies the SHA-512 sigma functions``() =
    (* vshasigmad v1, v2, 0, 0 *)
    let given = [ V2A, 0x7fffffff80000000UL; V2B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0x3f7fffffc0800000UL; V1B, 0xffffffff81000000UL ]
    oracle only64 "102206c2" given wanted

  /// <summary>
  /// vpmsumb vD, vA, vB multiplies each pair of bytes of vA and vB as
  /// polynomials over GF(2) -- shifting and XORing, never carrying -- and
  /// writes the XOR of each even and odd product into a halfword of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VPMSUMB XORs carry-less byte products``() =
    (* vpmsumb v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x000000ff7f800000UL; V1B, 0x7f80000000000000UL ]
    oracle only64 "10221c08" given wanted

  /// <summary>
  /// vpmsumh vD, vA, vB multiplies each pair of halfwords of vA and vB as
  /// polynomials over GF(2) -- shifting and XORing, never carrying -- and
  /// writes the XOR of each even and odd product into a word of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VPMSUMH XORs carry-less halfword products``() =
    (* vpmsumh v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x0000ffff7fff8000UL; V1B, 0x7fff800000000000UL ]
    oracle only64 "10221c48" given wanted

  /// <summary>
  /// vpmsumw vD, vA, vB multiplies each pair of words of vA and vB as
  /// polynomials over GF(2) -- shifting and XORing, never carrying -- and
  /// writes the XOR of each even and odd product into a doubleword of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VPMSUMW XORs carry-less word products``() =
    (* vpmsumw v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x7fffffffffffffffUL; V1B, 0x2aaaaaaa55555555UL ]
    oracle only64 "10221c88" given wanted

  /// <summary>
  /// vpmsumd vD, vA, vB multiplies each pair of doublewords of vA and vB as
  /// polynomials over GF(2) -- shifting and XORing, never carrying -- and
  /// writes the XOR of each even and odd product into a quadword of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VPMSUMD XORs carry-less doubleword products``() =
    (* vpmsumd v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x2aaaaaaaffffffffUL; V1B, 0xd555555500000000UL ]
    oracle only64 "10221cc8" given wanted

  /// <summary>
  /// vpermxor vD, vA, vB, vC writes into each byte of vD the XOR of the byte
  /// of vA the high nibble of the matching byte of vC names and the byte of
  /// vB its low nibble names.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VPERMXOR XORs bytes picked by nibbles``() =
    (* vpermxor v1, v2, v3, v4 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL
        V4A, 0x0000000100000001UL
        V4B, 0x0000000100000001UL ]
    let wanted = [ V1A, 0x7f7f7f7f7f7f7f7fUL; V1B, 0x7f7f7f7f7f7f7f7fUL ]
    oracle only64 "1022192d" given wanted

  /// <summary>
  /// vaddsbs vD, vA, vB adds each signed byte of vB to the matching one of
  /// vA; a sum outside -128 .. 127 is clamped to the nearer end and sets
  /// VSCR[SAT], which is sticky: an instruction that clamps nothing leaves it
  /// as it was.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VADDSBS adds signed bytes with saturation``() =
    (* vaddsbs v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted =
      [ V1A, 0x7fffff0080ffffffUL
        V1B, 0x7efefefe80000001UL
        VSCR, 0x1UL ]
    oracle everyTarget "10221b00" given wanted
    let given =
      [ V2A, 0x0001020304050607UL
        V2B, 0x08090a0b0c0d0e0fUL
        V3A, 0x0f0e0d0c0b0a0908UL
        V3B, 0x0706050403020100UL
        VSCR, 0x10000UL ]
    let wanted =
      [ V1A, 0x0f0f0f0f0f0f0f0fUL
        V1B, 0x0f0f0f0f0f0f0f0fUL
        VSCR, 0x10000UL ]
    oracle everyTarget "10221b00" given wanted

  /// <summary>
  /// vaddshs vD, vA, vB adds each signed halfword of vB to the matching one
  /// of vA; a sum outside -2^15 .. 2^15 - 1 is clamped to the nearer end and
  /// sets VSCR[SAT], which is sticky: an instruction that clamps nothing
  /// leaves it as it was.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VADDSHS adds signed halfwords with saturation``() =
    (* vaddshs v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted =
      [ V1A, 0x7fff00008000ffffUL
        V1B, 0x7ffefffe80000001UL
        VSCR, 0x1UL ]
    oracle everyTarget "10221b40" given wanted
    let given =
      [ V2A, 0x0001020304050607UL
        V2B, 0x08090a0b0c0d0e0fUL
        V3A, 0x0f0e0d0c0b0a0908UL
        V3B, 0x0706050403020100UL
        VSCR, 0x10000UL ]
    let wanted =
      [ V1A, 0x0f0f0f0f0f0f0f0fUL
        V1B, 0x0f0f0f0f0f0f0f0fUL
        VSCR, 0x10000UL ]
    oracle everyTarget "10221b40" given wanted

  /// <summary>
  /// vaddsws vD, vA, vB adds each signed word of vB to the matching one of
  /// vA; a sum outside -2^31 .. 2^31 - 1 is clamped to the nearer end and
  /// sets VSCR[SAT], which is sticky: an instruction that clamps nothing
  /// leaves it as it was.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VADDSWS adds signed words with saturation``() =
    (* vaddsws v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted =
      [ V1A, 0x7fffffff80000000UL
        V1B, 0x7ffffffe80000001UL
        VSCR, 0x1UL ]
    oracle everyTarget "10221b80" given wanted
    let given =
      [ V2A, 0x0001020304050607UL
        V2B, 0x08090a0b0c0d0e0fUL
        V3A, 0x0f0e0d0c0b0a0908UL
        V3B, 0x0706050403020100UL
        VSCR, 0x10000UL ]
    let wanted =
      [ V1A, 0x0f0f0f0f0f0f0f0fUL
        V1B, 0x0f0f0f0f0f0f0f0fUL
        VSCR, 0x10000UL ]
    oracle everyTarget "10221b80" given wanted

  /// <summary>
  /// vadduhs vD, vA, vB adds each unsigned halfword of vB to the matching one
  /// of vA; a sum outside 0 .. 2^16 - 1 is clamped to the nearer end and sets
  /// VSCR[SAT], which is sticky: an instruction that clamps nothing leaves it
  /// as it was.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VADDUHS adds unsigned halfwords with saturation``() =
    (* vadduhs v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted =
      [ V1A, 0x7fffffffffffffffUL
        V1B, 0xffffffff80000001UL
        VSCR, 0x1UL ]
    oracle everyTarget "10221a40" given wanted
    let given =
      [ V2A, 0x0001020304050607UL
        V2B, 0x08090a0b0c0d0e0fUL
        V3A, 0x0f0e0d0c0b0a0908UL
        V3B, 0x0706050403020100UL
        VSCR, 0x10000UL ]
    let wanted =
      [ V1A, 0x0f0f0f0f0f0f0f0fUL
        V1B, 0x0f0f0f0f0f0f0f0fUL
        VSCR, 0x10000UL ]
    oracle everyTarget "10221a40" given wanted

  /// <summary>
  /// vadduws vD, vA, vB adds each unsigned word of vB to the matching one of
  /// vA; a sum outside 0 .. 2^32 - 1 is clamped to the nearer end and sets
  /// VSCR[SAT], which is sticky: an instruction that clamps nothing leaves it
  /// as it was.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VADDUWS adds unsigned words with saturation``() =
    (* vadduws v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted =
      [ V1A, 0x80000000ffffffffUL
        V1B, 0xffffffff80000001UL
        VSCR, 0x1UL ]
    oracle everyTarget "10221a80" given wanted
    let given =
      [ V2A, 0x0001020304050607UL
        V2B, 0x08090a0b0c0d0e0fUL
        V3A, 0x0f0e0d0c0b0a0908UL
        V3B, 0x0706050403020100UL
        VSCR, 0x10000UL ]
    let wanted =
      [ V1A, 0x0f0f0f0f0f0f0f0fUL
        V1B, 0x0f0f0f0f0f0f0f0fUL
        VSCR, 0x10000UL ]
    oracle everyTarget "10221a80" given wanted

  /// <summary>
  /// vsubsbs vD, vA, vB subtracts each signed byte of vB from the matching
  /// one of vA; a difference outside -128 .. 127 is clamped to the nearer end
  /// and sets VSCR[SAT], which is sticky: an instruction that clamps nothing
  /// leaves it as it was.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSUBSBS subtracts signed bytes with saturation``() =
    (* vsubsbs v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted =
      [ V1A, 0x7ffffffe81010101UL
        V1B, 0x800000007f000001UL
        VSCR, 0x1UL ]
    oracle everyTarget "10221f00" given wanted
    let given =
      [ V2A, 0x0001020304050607UL
        V2B, 0x08090a0b0c0d0e0fUL
        V3A, 0x0f0e0d0c0b0a0908UL
        V3B, 0x0706050403020100UL
        VSCR, 0x10000UL ]
    let wanted =
      [ V1A, 0xf1f3f5f7f9fbfdffUL
        V1B, 0x01030507090b0d0fUL
        VSCR, 0x10000UL ]
    oracle everyTarget "10221f00" given wanted

  /// <summary>
  /// vsubshs vD, vA, vB subtracts each signed halfword of vB from the
  /// matching one of vA; a difference outside -2^15 .. 2^15 - 1 is clamped to
  /// the nearer end and sets VSCR[SAT], which is sticky: an instruction that
  /// clamps nothing leaves it as it was.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSUBSHS subtracts signed halfwords with saturation``() =
    (* vsubshs v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted =
      [ V1A, 0x7ffffffe80010001UL
        V1B, 0x800000007fff0001UL
        VSCR, 0x1UL ]
    oracle everyTarget "10221f40" given wanted
    let given =
      [ V2A, 0x0001020304050607UL
        V2B, 0x08090a0b0c0d0e0fUL
        V3A, 0x0f0e0d0c0b0a0908UL
        V3B, 0x0706050403020100UL
        VSCR, 0x10000UL ]
    let wanted =
      [ V1A, 0xf0f3f4f7f8fbfcffUL
        V1B, 0x01030507090b0d0fUL
        VSCR, 0x10000UL ]
    oracle everyTarget "10221f40" given wanted

  /// <summary>
  /// vsubsws vD, vA, vB subtracts each signed word of vB from the matching
  /// one of vA; a difference outside -2^31 .. 2^31 - 1 is clamped to the
  /// nearer end and sets VSCR[SAT], which is sticky: an instruction that
  /// clamps nothing leaves it as it was.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSUBSWS subtracts signed words with saturation``() =
    (* vsubsws v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted =
      [ V1A, 0x7ffffffe80000001UL
        V1B, 0x800000007fffffffUL
        VSCR, 0x1UL ]
    oracle everyTarget "10221f80" given wanted
    let given =
      [ V2A, 0x0001020304050607UL
        V2B, 0x08090a0b0c0d0e0fUL
        V3A, 0x0f0e0d0c0b0a0908UL
        V3B, 0x0706050403020100UL
        VSCR, 0x10000UL ]
    let wanted =
      [ V1A, 0xf0f2f4f7f8fafcffUL
        V1B, 0x01030507090b0d0fUL
        VSCR, 0x10000UL ]
    oracle everyTarget "10221f80" given wanted

  /// <summary>
  /// vsubuhs vD, vA, vB subtracts each unsigned halfword of vB from the
  /// matching one of vA; a difference outside 0 .. 2^16 - 1 is clamped to the
  /// nearer end and sets VSCR[SAT], which is sticky: an instruction that
  /// clamps nothing leaves it as it was.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSUBUHS subtracts unsigned halfwords with saturation``() =
    (* vsubuhs v1, v2, v3 *)
    let given =
      [ V2A, 0x0001020304050607UL
        V2B, 0x08090a0b0c0d0e0fUL
        V3A, 0x0f0e0d0c0b0a0908UL
        V3B, 0x0706050403020100UL
        VSCR, 0x10000UL ]
    let wanted =
      [ V1A, 0x0000000000000000UL
        V1B, 0x01030507090b0d0fUL
        VSCR, 0x10001UL ]
    oracle everyTarget "10221e40" given wanted

  /// <summary>
  /// vsubuws vD, vA, vB subtracts each unsigned word of vB from the matching
  /// one of vA; a difference outside 0 .. 2^32 - 1 is clamped to the nearer
  /// end and sets VSCR[SAT], which is sticky: an instruction that clamps
  /// nothing leaves it as it was.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSUBUWS subtracts unsigned words with saturation``() =
    (* vsubuws v1, v2, v3 *)
    let given =
      [ V2A, 0x0001020304050607UL
        V2B, 0x08090a0b0c0d0e0fUL
        V3A, 0x0f0e0d0c0b0a0908UL
        V3B, 0x0706050403020100UL
        VSCR, 0x10000UL ]
    let wanted =
      [ V1A, 0x0000000000000000UL
        V1B, 0x01030507090b0d0fUL
        VSCR, 0x10001UL ]
    oracle everyTarget "10221e80" given wanted
    let given =
      [ V2A, 0x7fff8000ffff0001UL
        V2B, 0x7f80ff00017f80ffUL
        V3A, 0x0001ffff80007fffUL
        V3B, 0x7f7f808001010000UL
        VSCR, 0x10000UL ]
    let wanted =
      [ V1A, 0x7ffd80017ffe8002UL
        V1B, 0x00017e80007e80ffUL
        VSCR, 0x10000UL ]
    oracle everyTarget "10221e80" given wanted

  /// <summary>
  /// vaddcuw vD, vA, vB writes into each word of vD the carry out of the
  /// unsigned sum of the matching words of vA and vB: 1 where the sum does
  /// not fit 32 bits, 0 where it does.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VADDCUW writes the carry out of each word sum``() =
    (* vaddcuw v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x0000000000000001UL; V1B, 0x0000000100000000UL ]
    oracle everyTarget "10221980" given wanted

  /// <summary>
  /// vsubcuw vD, vA, vB writes into each word of vD the carry out of vA + ~vB
  /// + 1 for the matching words, which is 1 exactly where vA is not below vB
  /// as unsigned numbers.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSUBCUW writes the carry out of each word difference``() =
    (* vsubcuw v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x0000000100000000UL; V1B, 0x0000000100000000UL ]
    oracle everyTarget "10221d80" given wanted

  /// <summary>
  /// vavgsb vD, vA, vB writes the average of each pair of signed bytes, (a +
  /// b + 1) / 2 computed without overflow, so a half rounds up toward plus
  /// infinity.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VAVGSB averages signed bytes rounding up``() =
    (* vavgsb v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x40000000c0000000UL; V1B, 0x3fffffffc0000001UL ]
    oracle everyTarget "10221d02" given wanted

  /// <summary>
  /// vavgsh vD, vA, vB writes the average of each pair of signed halfwords,
  /// (a + b + 1) / 2 computed without overflow, so a half rounds up toward
  /// plus infinity.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VAVGSH averages signed halfwords rounding up``() =
    (* vavgsh v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x40000000c0000000UL; V1B, 0x3fffffffc0000001UL ]
    oracle everyTarget "10221d42" given wanted

  /// <summary>
  /// vavgsw vD, vA, vB writes the average of each pair of signed words, (a +
  /// b + 1) / 2 computed without overflow, so a half rounds up toward plus
  /// infinity.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VAVGSW averages signed words rounding up``() =
    (* vavgsw v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x40000000c0000000UL; V1B, 0x3fffffffc0000001UL ]
    oracle everyTarget "10221d82" given wanted

  /// <summary>
  /// vavgub vD, vA, vB writes the average of each pair of unsigned bytes, (a
  /// + b + 1) / 2 computed without overflow, so a half rounds up toward plus
  /// infinity.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VAVGUB averages unsigned bytes rounding up``() =
    (* vavgub v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x40808080c0808080UL; V1B, 0xbfffffff40000001UL ]
    oracle everyTarget "10221c02" given wanted

  /// <summary>
  /// vavguh vD, vA, vB writes the average of each pair of unsigned halfwords,
  /// (a + b + 1) / 2 computed without overflow, so a half rounds up toward
  /// plus infinity.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VAVGUH averages unsigned halfwords rounding up``() =
    (* vavguh v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x40008000c0008000UL; V1B, 0xbfffffff40000001UL ]
    oracle everyTarget "10221c42" given wanted

  /// <summary>
  /// vavguw vD, vA, vB writes the average of each pair of unsigned words, (a
  /// + b + 1) / 2 computed without overflow, so a half rounds up toward plus
  /// infinity.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VAVGUW averages unsigned words rounding up``() =
    (* vavguw v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x40000000c0000000UL; V1B, 0xbfffffff40000001UL ]
    oracle everyTarget "10221c82" given wanted

  /// <summary>
  /// vabsdub vD, vA, vB writes the absolute difference of each pair of
  /// unsigned bytes of vA and vB, which never wraps.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VABSDUB writes the distance between unsigned bytes``() =
    (* vabsdub v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x7ffffffe7fffffffUL; V1B, 0x8000000080000001UL ]
    oracle only64 "10221c03" given wanted

  /// <summary>
  /// vabsduh vD, vA, vB writes the absolute difference of each pair of
  /// unsigned halfwords of vA and vB, which never wraps.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VABSDUH writes the distance between unsigned halfwords``() =
    (* vabsduh v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x7ffffffe7fffffffUL; V1B, 0x8000000080000001UL ]
    oracle only64 "10221c43" given wanted

  /// <summary>
  /// vabsduw vD, vA, vB writes the absolute difference of each pair of
  /// unsigned words of vA and vB, which never wraps.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VABSDUW writes the distance between unsigned words``() =
    (* vabsduw v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x7ffffffe7fffffffUL; V1B, 0x800000007fffffffUL ]
    oracle only64 "10221c83" given wanted

  /// <summary>
  /// vcmpequq vD, vA, vB sets all 128 bits of vD where vA is equal to vB as
  /// 128-bit numbers and clears them where it is not.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCMPEQUQ compares quadwords``() =
    (* vcmpequq v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x0000000000000000UL; V1B, 0x0000000000000000UL ]
    oracle everyTarget "102219c7" given wanted

  /// <summary>
  /// vcmpequq. vD, vA, vB writes vD as vcmpequq does and sets CR6 to 0b1000
  /// where the compare is true and 0b0010 where it is false.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCMPEQUQdot records a quadword compare in CR6``() =
    (* vcmpequq. v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted =
      [ CR6_0, 0UL
        CR6_1, 0UL
        CR6_2, 1UL
        CR6_3, 0UL
        V1A, 0x0000000000000000UL
        V1B, 0x0000000000000000UL ]
    oracle everyTarget "10221dc7" given wanted

  /// <summary>
  /// vcmpgtuq vD, vA, vB sets all 128 bits of vD where vA is greater than vB
  /// as unsigned 128-bit numbers and clears them where it is not.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCMPGTUQ compares unsigned quadwords``() =
    (* vcmpgtuq v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0xffffffffffffffffUL; V1B, 0xffffffffffffffffUL ]
    oracle everyTarget "10221a87" given wanted

  /// <summary>
  /// vcmpgtuq. vD, vA, vB writes vD as vcmpgtuq does and sets CR6 to 0b1000
  /// where the compare is true and 0b0010 where it is false.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCMPGTUQdot records a unsigned quadword compare in CR6``() =
    (* vcmpgtuq. v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted =
      [ CR6_0, 1UL
        CR6_1, 0UL
        CR6_2, 0UL
        CR6_3, 0UL
        V1A, 0xffffffffffffffffUL
        V1B, 0xffffffffffffffffUL ]
    oracle everyTarget "10221e87" given wanted

  /// <summary>
  /// vcmpgtsq vD, vA, vB sets all 128 bits of vD where vA is greater than vB
  /// as signed 128-bit numbers and clears them where it is not.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCMPGTSQ compares signed quadwords``() =
    (* vcmpgtsq v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0xffffffffffffffffUL; V1B, 0xffffffffffffffffUL ]
    oracle everyTarget "10221b87" given wanted

  /// <summary>
  /// vcmpgtsq. vD, vA, vB writes vD as vcmpgtsq does and sets CR6 to 0b1000
  /// where the compare is true and 0b0010 where it is false.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCMPGTSQdot records a signed quadword compare in CR6``() =
    (* vcmpgtsq. v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted =
      [ CR6_0, 1UL
        CR6_1, 0UL
        CR6_2, 0UL
        CR6_3, 0UL
        V1A, 0xffffffffffffffffUL
        V1B, 0xffffffffffffffffUL ]
    oracle everyTarget "10221f87" given wanted

  /// <summary>
  /// vcmpsq BF, vA, vB compares vA with vB as signed 128-bit numbers and sets
  /// CR field BF to less than, greater than or equal, its fourth bit cleared.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCMPSQ orders signed quadwords in a CR field``() =
    (* vcmpsq cr2, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ CR2_0, 0UL; CR2_1, 1UL; CR2_2, 0UL; CR2_3, 0UL ]
    oracle only64 "11021941" given wanted

  /// <summary>
  /// vcmpuq BF, vA, vB compares vA with vB as unsigned 128-bit numbers and
  /// sets CR field BF to less than, greater than or equal, its fourth bit
  /// cleared.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCMPUQ orders unsigned quadwords in a CR field``() =
    (* vcmpuq cr2, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ CR2_0, 0UL; CR2_1, 1UL; CR2_2, 0UL; CR2_3, 0UL ]
    oracle only64 "11021901" given wanted

  /// <summary>
  /// vcmpneb vD, vA, vB sets each byte of vD to all ones where the matching
  /// bytes of vA and vB differ and to all zeros where they are equal.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCMPNEB compares bytes for inequality``() =
    (* vcmpneb v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0xffffffffffffffffUL; V1B, 0xff000000ff0000ffUL ]
    oracle only64 "10221807" given wanted

  /// <summary>
  /// vcmpneb. vD, vA, vB writes vD as vcmpneb does and sets CR6: its first
  /// bit where every element differs, its third where none does.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCMPNEBdot records byte inequality in CR6``() =
    (* vcmpneb. v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted =
      [ CR6_0, 0UL
        CR6_1, 0UL
        CR6_2, 0UL
        CR6_3, 0UL
        V1A, 0xffffffffffffffffUL
        V1B, 0xff000000ff0000ffUL ]
    oracle only64 "10221c07" given wanted

  /// <summary>
  /// vcmpneh vD, vA, vB sets each halfword of vD to all ones where the
  /// matching halfwords of vA and vB differ and to all zeros where they are
  /// equal.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCMPNEH compares halfwords for inequality``() =
    (* vcmpneh v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0xffffffffffffffffUL; V1B, 0xffff0000ffffffffUL ]
    oracle only64 "10221847" given wanted

  /// <summary>
  /// vcmpneh. vD, vA, vB writes vD as vcmpneh does and sets CR6: its first
  /// bit where every element differs, its third where none does.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCMPNEHdot records halfword inequality in CR6``() =
    (* vcmpneh. v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted =
      [ CR6_0, 0UL
        CR6_1, 0UL
        CR6_2, 0UL
        CR6_3, 0UL
        V1A, 0xffffffffffffffffUL
        V1B, 0xffff0000ffffffffUL ]
    oracle only64 "10221c47" given wanted

  /// <summary>
  /// vcmpnew vD, vA, vB sets each word of vD to all ones where the matching
  /// words of vA and vB differ and to all zeros where they are equal.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCMPNEW compares words for inequality``() =
    (* vcmpnew v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0xffffffffffffffffUL; V1B, 0xffffffffffffffffUL ]
    oracle only64 "10221887" given wanted

  /// <summary>
  /// vcmpnew. vD, vA, vB writes vD as vcmpnew does and sets CR6: its first
  /// bit where every element differs, its third where none does.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCMPNEWdot records word inequality in CR6``() =
    (* vcmpnew. v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted =
      [ CR6_0, 1UL
        CR6_1, 0UL
        CR6_2, 0UL
        CR6_3, 0UL
        V1A, 0xffffffffffffffffUL
        V1B, 0xffffffffffffffffUL ]
    oracle only64 "10221c87" given wanted

  /// <summary>
  /// vcmpnezb vD, vA, vB sets each byte of vD to all ones where the matching
  /// bytes of vA and vB differ or either of them is zero, and to all zeros
  /// otherwise.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCMPNEZB compares bytes for inequality or zero``() =
    (* vcmpnezb v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0xffffffffffffffffUL; V1B, 0xff000000ffffffffUL ]
    oracle only64 "10221907" given wanted

  /// <summary>
  /// vcmpnezb. vD, vA, vB writes vD as vcmpnezb does and sets CR6: its first
  /// bit where every element compared true, its third where none did.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCMPNEZBdot records byte inequality or zero in CR6``() =
    (* vcmpnezb. v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted =
      [ CR6_0, 0UL
        CR6_1, 0UL
        CR6_2, 0UL
        CR6_3, 0UL
        V1A, 0xffffffffffffffffUL
        V1B, 0xff000000ffffffffUL ]
    oracle only64 "10221d07" given wanted

  /// <summary>
  /// vcmpnezh vD, vA, vB sets each halfword of vD to all ones where the
  /// matching halfwords of vA and vB differ or either of them is zero, and to
  /// all zeros otherwise.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCMPNEZH compares halfwords for inequality or zero``() =
    (* vcmpnezh v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0xffffffffffffffffUL; V1B, 0xffff0000ffffffffUL ]
    oracle only64 "10221947" given wanted

  /// <summary>
  /// vcmpnezh. vD, vA, vB writes vD as vcmpnezh does and sets CR6: its first
  /// bit where every element compared true, its third where none did.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCMPNEZHdot records halfword inequality or zero in CR6``() =
    (* vcmpnezh. v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted =
      [ CR6_0, 0UL
        CR6_1, 0UL
        CR6_2, 0UL
        CR6_3, 0UL
        V1A, 0xffffffffffffffffUL
        V1B, 0xffff0000ffffffffUL ]
    oracle only64 "10221d47" given wanted

  /// <summary>
  /// vcmpnezw vD, vA, vB sets each word of vD to all ones where the matching
  /// words of vA and vB differ or either of them is zero, and to all zeros
  /// otherwise.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCMPNEZW compares words for inequality or zero``() =
    (* vcmpnezw v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0xffffffffffffffffUL; V1B, 0xffffffffffffffffUL ]
    oracle only64 "10221987" given wanted

  /// <summary>
  /// vcmpnezw. vD, vA, vB writes vD as vcmpnezw does and sets CR6: its first
  /// bit where every element compared true, its third where none did.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCMPNEZWdot records word inequality or zero in CR6``() =
    (* vcmpnezw. v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted =
      [ CR6_0, 1UL
        CR6_1, 0UL
        CR6_2, 0UL
        CR6_3, 0UL
        V1A, 0xffffffffffffffffUL
        V1B, 0xffffffffffffffffUL ]
    oracle only64 "10221d87" given wanted

  /// <summary>
  /// vmulhsw vD, vA, vB writes into each word of vD the high half of the
  /// exact product of the matching signed words of vA and vB.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMULHSW keeps the high half of each word product``() =
    (* vmulhsw v1, v2, v3 *)
    let given =
      [ V2A, 0x7fff8000ffff0001UL
        V2B, 0x7f80ff00017f80ffUL
        V3A, 0x0001ffff80007fffUL
        V3B, 0x7f7f808001010000UL ]
    let wanted = [ V1A, 0x0000fffe00007fffUL; V1B, 0x3f807f7f00018100UL ]
    oracle only64 "10221b89" given wanted

  /// <summary>
  /// vmulhuw vD, vA, vB writes into each word of vD the high half of the
  /// exact product of the matching unsigned words of vA and vB.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMULHUW keeps the high half of each word product``() =
    (* vmulhuw v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x000000007fffffffUL; V1B, 0x7ffffffe00000000UL ]
    oracle only64 "10221a89" given wanted

  /// <summary>
  /// vmulhsd vD, vA, vB writes into each doubleword of vD the high half of
  /// the exact product of the matching signed doublewords of vA and vB.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMULHSD keeps the high half of each doubleword product``() =
    (* vmulhsd v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x00000000fffffffeUL; V1B, 0xffffffff80000000UL ]
    oracle only64 "10221bc9" given wanted

  /// <summary>
  /// vmulhud vD, vA, vB writes into each doubleword of vD the high half of
  /// the exact product of the matching unsigned doublewords of vA and vB.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMULHUD keeps the high half of each doubleword product``() =
    (* vmulhud v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x00000000fffffffeUL; V1B, 0x7fffffff00000000UL ]
    oracle only64 "10221ac9" given wanted

  /// <summary>
  /// vmulld vD, vA, vB writes into each doubleword of vD the low 64 bits of
  /// the product of the matching doublewords of vA and vB.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMULLD keeps the low halves of doubleword products``() =
    (* vmulld v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x8000000080000000UL; V1B, 0xffffffff80000000UL ]
    oracle only64 "102219c9" given wanted

  /// <summary>
  /// maddhd rD, rA, rB, rC writes the high doubleword of the 128-bit signed
  /// product of rA and rB plus rC, sign-extended.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] MADDHD keeps the high doubleword of a signed sum``() =
    (* maddhd r5, r6, r7, r9 *)
    let given =
      [ R6, 0x5555555555555555UL
        R7, 0xaaaaaaaaaaaaaaaaUL
        R9, 0xf0f0f0f0f0f0f0fUL ]
    let wanted = [ R5, 0xe38e38e38e38e38eUL ]
    oracle only64 "10a63a70" given wanted

  /// <summary>
  /// maddhdu rD, rA, rB, rC writes the high doubleword of the 128-bit
  /// unsigned product of rA and rB plus rC, zero-extended.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] MADDHDU keeps the high doubleword of an unsigned sum``() =
    (* maddhdu r5, r6, r7, r9 *)
    let given =
      [ R6, 0x7fffffffffffffffUL
        R7, 0x1UL
        R9, 0xfffffffffffffffeUL ]
    let wanted = [ R5, 0x1UL ]
    oracle only64 "10a63a71" given wanted

  /// <summary>
  /// maddld rD, rA, rB, rC writes the low doubleword of rA times rB plus rC.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] MADDLD keeps the low doubleword of a product sum``() =
    (* maddld r5, r6, r7, r9 *)
    let given =
      [ R6, 0x7fffffffffffffffUL
        R7, 0x1UL
        R9, 0xfffffffffffffffeUL ]
    let wanted = [ R5, 0x7ffffffffffffffdUL ]
    oracle only64 "10a63a73" given wanted

  /// <summary>
  /// vdivsw vD, vA, vB divides each signed word of vA by the matching one of
  /// vB, and writes the quotient, rounded toward zero; a zero divisor or a
  /// quotient that does not fit leaves the element undefined, and no such
  /// case is asserted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VDIVSW writes signed word quotients``() =
    (* vdivsw v1, v2, v3 *)
    let given =
      [ V2A, 0x7fff8000ffff0001UL
        V2B, 0x7f80ff00017f80ffUL
        V3A, 0x0001ffff80007fffUL
        V3B, 0x7f7f808001010000UL ]
    let wanted = [ V1A, 0x00003fff00000000UL; V1B, 0x0000000100000001UL ]
    oracle only64 "1022198b" given wanted

  /// <summary>
  /// vdivuw vD, vA, vB divides each unsigned word of vA by the matching one
  /// of vB, and writes the quotient, rounded toward zero; a zero divisor or a
  /// quotient that does not fit leaves the element undefined, and no such
  /// case is asserted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VDIVUW writes unsigned word quotients``() =
    (* vdivuw v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x7fffffff00000000UL; V1B, 0x0000000200000000UL ]
    oracle only64 "1022188b" given wanted

  /// <summary>
  /// vdivsd vD, vA, vB divides each signed doubleword of vA by the matching
  /// one of vB, and writes the quotient, rounded toward zero; a zero divisor
  /// or a quotient that does not fit leaves the element undefined, and no
  /// such case is asserted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VDIVSD writes signed doubleword quotients``() =
    (* vdivsd v1, v2, v3 *)
    let given =
      [ V2A, 0x7fff8000ffff0001UL
        V2B, 0x7f80ff00017f80ffUL
        V3A, 0x0001ffff80007fffUL
        V3B, 0x7f7f808001010000UL ]
    let wanted = [ V1A, 0x0000000000003fffUL; V1B, 0x0000000000000001UL ]
    oracle only64 "102219cb" given wanted

  /// <summary>
  /// vdivud vD, vA, vB divides each unsigned doubleword of vA by the matching
  /// one of vB, and writes the quotient, rounded toward zero; a zero divisor
  /// or a quotient that does not fit leaves the element undefined, and no
  /// such case is asserted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VDIVUD writes unsigned doubleword quotients``() =
    (* vdivud v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x000000003fffffffUL; V1B, 0x0000000000000002UL ]
    oracle only64 "102218cb" given wanted

  /// <summary>
  /// vdivsq vD, vA, vB divides each signed quadword of vA by the matching one
  /// of vB, and writes the quotient, rounded toward zero; a zero divisor or a
  /// quotient that does not fit leaves the element undefined, and no such
  /// case is asserted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VDIVSQ writes signed quadword quotients``() =
    (* vdivsq v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x0000000000000000UL; V1B, 0x000000003fffffffUL ]
    oracle only64 "1022190b" given wanted

  /// <summary>
  /// vdivuq vD, vA, vB divides each unsigned quadword of vA by the matching
  /// one of vB, and writes the quotient, rounded toward zero; a zero divisor
  /// or a quotient that does not fit leaves the element undefined, and no
  /// such case is asserted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VDIVUQ writes unsigned quadword quotients``() =
    (* vdivuq v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x0000000000000000UL; V1B, 0x000000003fffffffUL ]
    oracle only64 "1022180b" given wanted

  /// <summary>
  /// vdivesw vD, vA, vB divides each signed word of vA by the matching one of
  /// vB, the dividend shifted up by the width of an element first, and writes
  /// the quotient, rounded toward zero; a zero divisor or a quotient that
  /// does not fit leaves the element undefined, and no such case is asserted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VDIVESW writes signed word extended quotients``() =
    (* vdivesw v1, v2, v3 *)
    let given = [ V3A, 0xffffffffffffffffUL; V3B, 0xffffffffffffffffUL ]
    let wanted = [ V1A, 0x0000000000000000UL; V1B, 0x0000000000000000UL ]
    oracle everyTarget "10221b8b" given wanted

  /// <summary>
  /// vdiveuw vD, vA, vB divides each unsigned word of vA by the matching one
  /// of vB, the dividend shifted up by the width of an element first, and
  /// writes the quotient, rounded toward zero; a zero divisor or a quotient
  /// that does not fit leaves the element undefined, and no such case is
  /// asserted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VDIVEUW writes unsigned word extended quotients``() =
    (* vdiveuw v1, v2, v3 *)
    let given =
      [ V2A, 0x5555555555555555UL
        V2B, 0x5555555555555555UL
        V3A, 0xaaaaaaaaaaaaaaaaUL
        V3B, 0xaaaaaaaaaaaaaaaaUL ]
    let wanted = [ V1A, 0x8000000080000000UL; V1B, 0x8000000080000000UL ]
    oracle only64 "10221a8b" given wanted

  /// <summary>
  /// vdivesd vD, vA, vB divides each signed doubleword of vA by the matching
  /// one of vB, the dividend shifted up by the width of an element first, and
  /// writes the quotient, rounded toward zero; a zero divisor or a quotient
  /// that does not fit leaves the element undefined, and no such case is
  /// asserted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VDIVESD writes signed doubleword extended quotients``() =
    (* vdivesd v1, v2, v3 *)
    let given = [ V3A, 0xffffffffffffffffUL; V3B, 0xffffffffffffffffUL ]
    let wanted = [ V1A, 0x0000000000000000UL; V1B, 0x0000000000000000UL ]
    oracle everyTarget "10221bcb" given wanted

  /// <summary>
  /// vdiveud vD, vA, vB divides each unsigned doubleword of vA by the
  /// matching one of vB, the dividend shifted up by the width of an element
  /// first, and writes the quotient, rounded toward zero; a zero divisor or a
  /// quotient that does not fit leaves the element undefined, and no such
  /// case is asserted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VDIVEUD writes unsigned doubleword extended quotients``() =
    (* vdiveud v1, v2, v3 *)
    let given =
      [ V2A, 0x5555555555555555UL
        V2B, 0x5555555555555555UL
        V3A, 0xaaaaaaaaaaaaaaaaUL
        V3B, 0xaaaaaaaaaaaaaaaaUL ]
    let wanted = [ V1A, 0x8000000000000000UL; V1B, 0x8000000000000000UL ]
    oracle only64 "10221acb" given wanted

  /// <summary>
  /// vdivesq vD, vA, vB divides each signed quadword of vA by the matching
  /// one of vB, the dividend shifted up by the width of an element first, and
  /// writes the quotient, rounded toward zero; a zero divisor or a quotient
  /// that does not fit leaves the element undefined, and no such case is
  /// asserted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VDIVESQ writes signed quadword extended quotients``() =
    (* vdivesq v1, v2, v3 *)
    let given =
      [ V2A, 0x0001020304050607UL
        V2B, 0x08090a0b0c0d0e0fUL
        V3A, 0x0f0e0d0c0b0a0908UL
        V3B, 0x0706050403020100UL ]
    let wanted = [ V1A, 0x00112358e75d3033UL; V1B, 0x6a0ab617909a3e1fUL ]
    oracle only64 "10221b0b" given wanted

  /// <summary>
  /// vdiveuq vD, vA, vB divides each unsigned quadword of vA by the matching
  /// one of vB, the dividend shifted up by the width of an element first, and
  /// writes the quotient, rounded toward zero; a zero divisor or a quotient
  /// that does not fit leaves the element undefined, and no such case is
  /// asserted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VDIVEUQ writes unsigned quadword extended quotients``() =
    (* vdiveuq v1, v2, v3 *)
    let given =
      [ V2A, 0x0123456789abcdefUL
        V2B, 0xfedcba9876543210UL
        V3A, 0xfedcba9876543210UL
        V3B, 0x0123456789abcdefUL ]
    let wanted = [ V1A, 0x0124924924924924UL; V1B, 0x7ec5397829cbc14eUL ]
    oracle only64 "10221a0b" given wanted

  /// <summary>
  /// vmodsw vD, vA, vB divides each signed word of vA by the matching one of
  /// vB, and writes the remainder, which takes the sign of the dividend; a
  /// zero divisor or a quotient that does not fit leaves the element
  /// undefined, and no such case is asserted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMODSW writes signed word remainders``() =
    (* vmodsw v1, v2, v3 *)
    let given =
      [ V2A, 0x7fff8000ffff0001UL
        V2B, 0x7f80ff00017f80ffUL
        V3A, 0x0001ffff80007fffUL
        V3B, 0x7f7f808001010000UL ]
    let wanted = [ V1A, 0x0001bfffffff0001UL; V1B, 0x00017e80007e80ffUL ]
    oracle only64 "10221f8b" given wanted

  /// <summary>
  /// vmoduw vD, vA, vB divides each unsigned word of vA by the matching one
  /// of vB, and writes the remainder, which takes the sign of the dividend; a
  /// zero divisor or a quotient that does not fit leaves the element
  /// undefined, and no such case is asserted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMODUW writes unsigned word remainders``() =
    (* vmoduw v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x0000000080000000UL; V1B, 0x0000000100000001UL ]
    oracle only64 "10221e8b" given wanted

  /// <summary>
  /// vmodsd vD, vA, vB divides each signed doubleword of vA by the matching
  /// one of vB, and writes the remainder, which takes the sign of the
  /// dividend; a zero divisor or a quotient that does not fit leaves the
  /// element undefined, and no such case is asserted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMODSD writes signed doubleword remainders``() =
    (* vmodsd v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x00000001bfffffffUL; V1B, 0xffffffff00000001UL ]
    oracle only64 "10221fcb" given wanted

  /// <summary>
  /// vmodud vD, vA, vB divides each unsigned doubleword of vA by the matching
  /// one of vB, and writes the remainder, which takes the sign of the
  /// dividend; a zero divisor or a quotient that does not fit leaves the
  /// element undefined, and no such case is asserted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMODUD writes unsigned doubleword remainders``() =
    (* vmodud v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x00000001bfffffffUL; V1B, 0x0000000000000001UL ]
    oracle only64 "10221ecb" given wanted

  /// <summary>
  /// vmodsq vD, vA, vB divides each signed quadword of vA by the matching one
  /// of vB, and writes the remainder, which takes the sign of the dividend; a
  /// zero divisor or a quotient that does not fit leaves the element
  /// undefined, and no such case is asserted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMODSQ writes signed quadword remainders``() =
    (* vmodsq v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x00000001a0000000UL; V1B, 0x9ffffffe80000001UL ]
    oracle only64 "10221f0b" given wanted

  /// <summary>
  /// vmoduq vD, vA, vB divides each unsigned quadword of vA by the matching
  /// one of vB, and writes the remainder, which takes the sign of the
  /// dividend; a zero divisor or a quotient that does not fit leaves the
  /// element undefined, and no such case is asserted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMODUQ writes unsigned quadword remainders``() =
    (* vmoduq v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x00000001a0000000UL; V1B, 0x9ffffffe80000001UL ]
    oracle only64 "10221e0b" given wanted

  /// <summary>
  /// vsum4ubs vD, vA, vB adds the unsigned bytes of vA within each word to
  /// the matching unsigned word of vB, clamping the sum to a unsigned word
  /// and setting VSCR[SAT], which is sticky, where it has to.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSUM4UBS sums unsigned bytes into words saturating``() =
    (* vsum4ubs v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted =
      [ V1A, 0x0000037dffffffffUL
        V1B, 0x800003fb80000001UL
        VSCR, 0x1UL ]
    oracle everyTarget "10221e08" given wanted
    let given =
      [ V2A, 0x0001020304050607UL
        V2B, 0x08090a0b0c0d0e0fUL
        V3A, 0x0f0e0d0c0b0a0908UL
        V3B, 0x0706050403020100UL
        VSCR, 0x10000UL ]
    let wanted =
      [ V1A, 0x0f0e0d120b0a091eUL
        V1B, 0x0706052a03020136UL
        VSCR, 0x10000UL ]
    oracle everyTarget "10221e08" given wanted

  /// <summary>
  /// vsum4sbs vD, vA, vB adds the signed bytes of vA within each word to the
  /// matching signed word of vB, clamping the sum to a signed word and
  /// setting VSCR[SAT], which is sticky, where it has to.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSUM4SBS sums signed bytes into words saturating``() =
    (* vsum4sbs v1, v2, v3 *)
    let given =
      [ V2A, 0x0001020304050607UL
        V2B, 0x08090a0b0c0d0e0fUL
        V3A, 0x0f0e0d0c0b0a0908UL
        V3B, 0x0706050403020100UL
        VSCR, 0x10000UL ]
    let wanted =
      [ V1A, 0x0f0e0d120b0a091eUL
        V1B, 0x0706052a03020136UL
        VSCR, 0x10000UL ]
    oracle everyTarget "10221f08" given wanted

  /// <summary>
  /// vsum4shs vD, vA, vB adds the signed halfwords of vA within each word to
  /// the matching signed word of vB, clamping the sum to a signed word and
  /// setting VSCR[SAT], which is sticky, where it has to.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSUM4SHS sums signed halfwords into words saturating``() =
    (* vsum4shs v1, v2, v3 *)
    let given =
      [ V2A, 0x0001020304050607UL
        V2B, 0x08090a0b0c0d0e0fUL
        V3A, 0x0f0e0d0c0b0a0908UL
        V3B, 0x0706050403020100UL
        VSCR, 0x10000UL ]
    let wanted =
      [ V1A, 0x0f0e0f100b0a1314UL
        V1B, 0x0706171803021b1cUL
        VSCR, 0x10000UL ]
    oracle everyTarget "10221e48" given wanted

  /// <summary>
  /// vsum2sws vD, vA, vB writes into words 1 and 3 of vD the sums of words
  /// 0-1 and 2-3 of vA plus words 1 and 3 of vB, clamped to a signed word,
  /// and clears words 0 and 2; a clamp sets VSCR[SAT].
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSUM2SWS sums signed word pairs saturating``() =
    (* vsum2sws v1, v2, v3 *)
    let given =
      [ V2A, 0x7fff8000ffff0001UL
        V2B, 0x7f80ff00017f80ffUL
        V3A, 0x0001ffff80007fffUL
        V3B, 0x7f7f808001010000UL
        VSCR, 0x10000UL ]
    let wanted =
      [ V1A, 0x00000000ffff0000UL
        V1B, 0x000000007fffffffUL
        VSCR, 0x10001UL ]
    oracle everyTarget "10221e88" given wanted
    let given =
      [ V2A, 0x0001020304050607UL
        V2B, 0x08090a0b0c0d0e0fUL
        V3A, 0x0f0e0d0c0b0a0908UL
        V3B, 0x0706050403020100UL
        VSCR, 0x10000UL ]
    let wanted =
      [ V1A, 0x000000000f101112UL
        V1B, 0x000000001718191aUL
        VSCR, 0x10000UL ]
    oracle everyTarget "10221e88" given wanted

  /// <summary>
  /// vsumsws vD, vA, vB writes into word 3 of vD the sum of the four signed
  /// words of vA and word 3 of vB, clamped to a signed word, and clears the
  /// other three; a clamp sets VSCR[SAT].
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSUMSWS sums all signed words saturating``() =
    (* vsumsws v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted =
      [ V1A, 0x0000000000000000UL
        V1B, 0x0000000080000000UL
        VSCR, 0x1UL ]
    oracle everyTarget "10221f88" given wanted
    let given =
      [ V2A, 0x0001020304050607UL
        V2B, 0x08090a0b0c0d0e0fUL
        V3A, 0x0f0e0d0c0b0a0908UL
        V3B, 0x0706050403020100UL
        VSCR, 0x10000UL ]
    let wanted =
      [ V1A, 0x0000000000000000UL
        V1B, 0x000000001b1e2124UL
        VSCR, 0x10000UL ]
    oracle everyTarget "10221f88" given wanted

  /// <summary>
  /// vctzb vD, vB writes into each byte of vD how many zero bits end the
  /// matching byte of vB, its width for a zero one.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCTZB counts the trailing zeros of each byte``() =
    (* vctzb v1, v3 *)
    let given = [ V3A, 0x7fffffff80000000UL; V3B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0x0000000007080808UL; V1B, 0x0000000008080800UL ]
    oracle only64 "103c1e02" given wanted

  /// <summary>
  /// vctzh vD, vB writes into each halfword of vD how many zero bits end the
  /// matching halfword of vB, its width for a zero one.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCTZH counts the trailing zeros of each halfword``() =
    (* vctzh v1, v3 *)
    let given = [ V3A, 0x7fffffff80000000UL; V3B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0x00000000000f0010UL; V1B, 0x0000000000100000UL ]
    oracle only64 "103d1e02" given wanted

  /// <summary>
  /// vctzw vD, vB writes into each word of vD how many zero bits end the
  /// matching word of vB, its width for a zero one.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCTZW counts the trailing zeros of each word``() =
    (* vctzw v1, v3 *)
    let given = [ V3A, 0x7fff8000ffff0001UL; V3B, 0x7f80ff00017f80ffUL ]
    let wanted = [ V1A, 0x0000000f00000000UL; V1B, 0x0000000800000000UL ]
    oracle only64 "103e1e02" given wanted

  /// <summary>
  /// vctzd vD, vB writes into each doubleword of vD how many zero bits end
  /// the matching doubleword of vB, its width for a zero one.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCTZD counts the trailing zeros of each doubleword``() =
    (* vctzd v1, v3 *)
    let given = [ V3A, 0x8000000000000000UL ]
    let wanted = [ V1A, 0x000000000000003fUL; V1B, 0x0000000000000040UL ]
    oracle only64 "103f1e02" given wanted

  /// <summary>
  /// vclzlsbb rD, vB writes into rD how many bytes of vB, from byte 0 on,
  /// have their lowest bit clear before the first one that has it set: 16
  /// when none does.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCLZLSBB counts leading bytes with a clear lowest bit``() =
    (* vclzlsbb r5, v3 *)
    let given = [ V3A, 0x8000000000000000UL ]
    let wanted = [ R5, 0x10UL ]
    oracle only64 "10a01e02" given wanted

  /// <summary>
  /// vctzlsbb rD, vB counts as vclzlsbb does, from byte 15 back.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCTZLSBB counts trailing bytes with a clear lowest bit``() =
    (* vctzlsbb r5, v3 *)
    let given = [ V3A, 0x0123456789abcdefUL; V3B, 0xfedcba9876543210UL ]
    let wanted = [ R5, 0x8UL ]
    oracle only64 "10a11e02" given wanted

  /// <summary>
  /// vnegw vD, vB writes the two's complement negation of each word of vB.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VNEGW negates each word``() =
    (* vnegw v1, v3 *)
    let given = [ V3A, 0x7fffffff80000000UL; V3B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0x8000000180000000UL; V1B, 0x00000001ffffffffUL ]
    oracle only64 "10261e02" given wanted

  /// <summary>
  /// vnegd vD, vB writes the two's complement negation of each doubleword of
  /// vB.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VNEGD negates each doubleword``() =
    (* vnegd v1, v3 *)
    let given = [ V3A, 0x7fffffff80000000UL; V3B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0x8000000080000000UL; V1B, 0x00000000ffffffffUL ]
    oracle only64 "10271e02" given wanted

  /// <summary>
  /// vprtybw vD, vB writes into each word of vD 1 or 0 as the lowest bits of
  /// the bytes of the matching word of vB hold an odd or an even number of
  /// ones.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VPRTYBW writes the byte parity of each word``() =
    (* vprtybw v1, v3 *)
    let given = [ V3A, 0x7fff8000ffff0001UL; V3B, 0x7f80ff00017f80ffUL ]
    let wanted = [ V1A, 0x0000000000000001UL; V1B, 0x0000000000000001UL ]
    oracle only64 "10281e02" given wanted

  /// <summary>
  /// vprtybd vD, vB writes into each doubleword of vD 1 or 0 as the lowest
  /// bits of the bytes of the matching doubleword of vB hold an odd or an
  /// even number of ones.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VPRTYBD writes the byte parity of each doubleword``() =
    (* vprtybd v1, v3 *)
    let given = [ V3A, 0x7fff8000ffff0001UL; V3B, 0x7f80ff00017f80ffUL ]
    let wanted = [ V1A, 0x0000000000000001UL; V1B, 0x0000000000000001UL ]
    oracle only64 "10291e02" given wanted

  /// <summary>
  /// vprtybq vD, vB writes into each quadword of vD 1 or 0 as the lowest bits
  /// of the bytes of the matching quadword of vB hold an odd or an even
  /// number of ones.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VPRTYBQ writes the byte parity of each quadword``() =
    (* vprtybq v1, v3 *)
    let given = [ V3A, 0x7fffffff80000000UL; V3B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0x0000000000000000UL; V1B, 0x0000000000000001UL ]
    oracle only64 "102a1e02" given wanted

  /// <summary>
  /// vextsb2w vD, vB writes into each word of vD the lowest byte of the
  /// matching word of vB, sign-extended.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXTSB2W sign-extends a low byte to each word``() =
    (* vextsb2w v1, v3 *)
    let given = [ V3A, 0x7fffffff80000000UL; V3B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0xffffffff00000000UL; V1B, 0xffffffff00000001UL ]
    oracle only64 "10301e02" given wanted

  /// <summary>
  /// vextsh2w vD, vB writes into each word of vD the lowest halfword of the
  /// matching word of vB, sign-extended.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXTSH2W sign-extends a low halfword to each word``() =
    (* vextsh2w v1, v3 *)
    let given = [ V3A, 0x7fffffff80000000UL; V3B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0xffffffff00000000UL; V1B, 0xffffffff00000001UL ]
    oracle only64 "10311e02" given wanted

  /// <summary>
  /// vextsb2d vD, vB writes into each doubleword of vD the lowest byte of the
  /// matching doubleword of vB, sign-extended.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXTSB2D sign-extends a low byte to each doubleword``() =
    (* vextsb2d v1, v3 *)
    let given = [ V3A, 0x7fff8000ffff0001UL; V3B, 0x7f80ff00017f80ffUL ]
    let wanted = [ V1A, 0x0000000000000001UL; V1B, 0xffffffffffffffffUL ]
    oracle only64 "10381e02" given wanted

  /// <summary>
  /// vextsh2d vD, vB writes into each doubleword of vD the lowest halfword of
  /// the matching doubleword of vB, sign-extended.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXTSH2D sign-extends each low halfword``() =
    (* vextsh2d v1, v3 *)
    let given = [ V3A, 0x7fff8000ffff0001UL; V3B, 0x7f80ff00017f80ffUL ]
    let wanted = [ V1A, 0x0000000000000001UL; V1B, 0xffffffffffff80ffUL ]
    oracle only64 "10391e02" given wanted

  /// <summary>
  /// vextsw2d vD, vB writes into each doubleword of vD the lowest word of the
  /// matching doubleword of vB, sign-extended.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXTSW2D sign-extends a low word to each doubleword``() =
    (* vextsw2d v1, v3 *)
    let given = [ V3A, 0x7fffffff80000000UL; V3B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0xffffffff80000000UL; V1B, 0x0000000000000001UL ]
    oracle only64 "103a1e02" given wanted

  /// <summary>
  /// vextsd2q vD, vB writes into each quadword of vD the lowest doubleword of
  /// the matching quadword of vB, sign-extended.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXTSD2Q sign-extends each low doubleword``() =
    (* vextsd2q v1, v3 *)
    let given = [ V3A, 0x7fffffff80000000UL; V3B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0xffffffffffffffffUL; V1B, 0xffffffff00000001UL ]
    oracle only64 "103b1e02" given wanted

  /// <summary>
  /// vrldmi vD, vA, vB rotates each doubleword of vA by the count in bits
  /// 58:63 of the matching doubleword of vB and inserts the bits of MASK(b,
  /// e) of it into vD, b and e being bits 42:47 and 50:55, the rest of vD kept
  /// (Book I 6.9.3, p. 411). Where the mask is whole, nothing of vD is kept
  /// and QEMU agrees; where it is not, qemu-ppc64 -cpu power10 (8.2.2) writes
  /// the masked rotate alone, dropping vD, which the manual rules out (the
  /// case is deviations/ppc64/vrldmi.c), so the second run asserts the
  /// manual: one bit inserted at the bottom of doubleword 0, one at the top
  /// of doubleword 1.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VRLDMI inserts the rotated bits into vD``() =
    (* vrldmi v1, v2, v3 *)
    let given =
      [ V1A, 0x0bad0bad0bad0badUL
        V1B, 0x0bad0bad0bad0badUL
        V2A, 0x0001020304050607UL
        V2B, 0x08090a0b0c0d0e0fUL
        V3A, 0x0f0e0d0c0b0a0908UL
        V3B, 0x0706050403020100UL ]
    let wanted = [ V1A, 0x0102030405060700UL; V1B, 0x08090a0b0c0d0e0fUL ]
    oracle only64 "102218c5" given wanted
    let given =
      [ V1A, 0x0bad0bad0bad0badUL
        V1B, 0x0bad0bad0bad0badUL
        V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x0bad0bad0bad0bacUL; V1B, 0x8bad0bad0bad0badUL ]
    oracle only64 "102218c5" given wanted

  /// <summary>
  /// vrlwnm vD, vA, vB rotates each word of vA left by the count in the low
  /// bits of the matching word of vB and keeps the bits of MASK(b, e), b and
  /// e being the two fields eight and sixteen bits above the count.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VRLWNM rotates each word and ANDs a mask``() =
    (* vrlwnm v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x8000000000000000UL; V1B, 0x0000000100000000UL ]
    oracle only64 "10221985" given wanted

  /// <summary>
  /// vrldnm vD, vA, vB rotates each doubleword of vA left by the count in the
  /// low bits of the matching doubleword of vB and keeps the bits of MASK(b,
  /// e), b and e being the two fields eight and sixteen bits above the count.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VRLDNM rotates each doubleword and ANDs a mask``() =
    (* vrldnm v1, v2, v3 *)
    let given =
      [ V2A, 0x7fff8000ffff0001UL
        V2B, 0x7f80ff00017f80ffUL
        V3A, 0x0001ffff80007fffUL
        V3B, 0x7f7f808001010000UL ]
    let wanted = [ V1A, 0xbfffc0007fff8000UL; V1B, 0x7f80ff00017f80ffUL ]
    oracle only64 "102219c5" given wanted

  /// <summary>
  /// vrlqnm vD, vA, vB rotates each quadword of vA left by the count in the
  /// low bits of the matching quadword of vB and keeps the bits of MASK(b,
  /// e), b and e being the two fields eight and sixteen bits above the count.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VRLQNM rotates each quadword and ANDs a mask``() =
    (* vrlqnm v1, v2, v3 *)
    let given =
      [ V2A, 0x7fff8000ffff0001UL
        V2B, 0x7f80ff00017f80ffUL
        V3A, 0x0001ffff80007fffUL
        V3B, 0x7f7f808001010000UL ]
    let wanted = [ V1A, 0xbfffc0007fff8000UL; V1B, 0xbfc07f8000bfc07fUL ]
    oracle only64 "10221945" given wanted

  /// <summary>
  /// vrlwmi vD, vA, vB rotates each word of vA as the matching word of vB
  /// says and inserts the bits of MASK(b, e) of the result into vD, keeping
  /// the rest of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VRLWMI rotates each word and inserts it``() =
    (* vrlwmi v1, v2, v3 *)
    let given =
      [ V1A, 0x0bad0bad0bad0badUL
        V1B, 0x0bad0bad0bad0badUL
        V2A, 0x7fff8000ffff0001UL
        V2B, 0x7f80ff00017f80ffUL
        V3A, 0x0001ffff80007fffUL
        V3B, 0x7f7f808001010000UL ]
    let wanted = [ V1A, 0x3fffc000ffff8000UL; V1B, 0x0bad0bac017f80ffUL ]
    oracle only64 "10221885" given wanted

  /// <summary>
  /// vrlqmi vD, vA, vB rotates each quadword of vA as the matching quadword
  /// of vB says and inserts the bits of MASK(b, e) of the result into vD,
  /// keeping the rest of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VRLQMI rotates each quadword and inserts it``() =
    (* vrlqmi v1, v2, v3 *)
    let given =
      [ V1A, 0x0bad0bad0bad0badUL
        V1B, 0x0bad0bad0bad0badUL
        V2A, 0x7fff8000ffff0001UL
        V2B, 0x7f80ff00017f80ffUL
        V3A, 0x0001ffff80007fffUL
        V3B, 0x7f7f808001010000UL ]
    let wanted = [ V1A, 0xbfffc0007fff8000UL; V1B, 0xbfc07f8000bfc07fUL ]
    oracle only64 "10221845" given wanted

  /// <summary>
  /// vslq vD, vA, vB shifts vA, one 128-bit number, left by the count in bits
  /// 57:63 of vB.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSLQ shifts the quadword left``() =
    (* vslq v1, v2, v3 *)
    let given =
      [ V2A, 0x5555555555555555UL
        V2B, 0x5555555555555555UL
        V3A, 0xaaaaaaaaaaaaaaaaUL
        V3B, 0xaaaaaaaaaaaaaaaaUL ]
    let wanted = [ V1A, 0x5555555555555555UL; V1B, 0x5555540000000000UL ]
    oracle only64 "10221905" given wanted

  /// <summary>
  /// vsrq vD, vA, vB shifts vA, one 128-bit number, right by the count in
  /// bits 57:63 of vB.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSRQ shifts the quadword right``() =
    (* vsrq v1, v2, v3 *)
    let given =
      [ V2A, 0x5555555555555555UL
        V2B, 0x5555555555555555UL
        V3A, 0xaaaaaaaaaaaaaaaaUL
        V3B, 0xaaaaaaaaaaaaaaaaUL ]
    let wanted = [ V1A, 0x0000000000155555UL; V1B, 0x5555555555555555UL ]
    oracle only64 "10221a05" given wanted

  /// <summary>
  /// vsraq vD, vA, vB shifts vA, one 128-bit number, right algebraically by
  /// the count in bits 57:63 of vB.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSRAQ shifts the quadword right algebraically``() =
    (* vsraq v1, v2, v3 *)
    let given =
      [ V2A, 0x5555555555555555UL
        V2B, 0x5555555555555555UL
        V3A, 0xaaaaaaaaaaaaaaaaUL
        V3B, 0xaaaaaaaaaaaaaaaaUL ]
    let wanted = [ V1A, 0x0000000000155555UL; V1B, 0x5555555555555555UL ]
    oracle only64 "10221b05" given wanted

  /// <summary>
  /// vrlq vD, vA, vB rotates vA, one 128-bit number, left by the count in
  /// bits 57:63 of vB.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VRLQ rotates the quadword left``() =
    (* vrlq v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0xbfffffffc0000000UL; V1B, 0x7fffffff80000000UL ]
    oracle only64 "10221805" given wanted

  /// <summary>
  /// vslv vD, vA, vB shifts each byte of vA left by the low three bits of the
  /// matching byte of vB, filling from the next byte of vA, and from zero
  /// after the last.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSLV shifts each byte left by its own count``() =
    (* vslv v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x7fffffff0000007fUL; V1B, 0xffffff8000000001UL ]
    oracle only64 "10221f44" given wanted

  /// <summary>
  /// vsrv vD, vA, vB shifts each byte of vA right by the low three bits of
  /// the matching byte of vB, filling from the previous byte of vA, and from
  /// zero before the first.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSRV shifts each byte right by its own count``() =
    (* vsrv v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x7fffffffff000000UL; V1B, 0x01ffffff00000001UL ]
    oracle only64 "10221f04" given wanted

  /// <summary>
  /// vsldbi vD, vA, vB, SH writes the 128 bits of vA || vB that start SH bits
  /// from its left end.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSLDBI shifts a register pair left by bits``() =
    (* vsldbi v1, v2, v3, 2 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0xfffffffe00000003UL; V1B, 0xfffffffc00000004UL ]
    oracle only64 "10221896" given wanted

  /// <summary>
  /// vsrdbi vD, vA, vB, SH writes the 128 bits of vA || vB that end SH bits
  /// from its right end.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSRDBI shifts a register pair right by bits``() =
    (* vsrdbi v1, v2, v3, 2 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x400000007fffffffUL; V1B, 0xdfffffffe0000000UL ]
    oracle only64 "10221a96" given wanted

  /// <summary>
  /// vexpandbm vD, vB sets each byte of vD to all ones where the top bit of
  /// the matching byte of vB is set and to all zeros where it is clear.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXPANDBM spreads each byte's top bit across it``() =
    (* vexpandbm v1, v3 *)
    let given = [ V3A, 0x7fffffff80000000UL; V3B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0x00ffffffff000000UL; V1B, 0xffffffff00000000UL ]
    oracle only64 "10201e42" given wanted

  /// <summary>
  /// vexpandhm vD, vB sets each halfword of vD to all ones where the top bit
  /// of the matching halfword of vB is set and to all zeros where it is
  /// clear.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXPANDHM spreads each halfword's top bit across it``() =
    (* vexpandhm v1, v3 *)
    let given = [ V3A, 0x7fffffff80000000UL; V3B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0x0000ffffffff0000UL; V1B, 0xffffffff00000000UL ]
    oracle only64 "10211e42" given wanted

  /// <summary>
  /// vexpandwm vD, vB sets each word of vD to all ones where the top bit of
  /// the matching word of vB is set and to all zeros where it is clear.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXPANDWM spreads each word's top bit across it``() =
    (* vexpandwm v1, v3 *)
    let given = [ V3A, 0x7fffffff80000000UL; V3B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0x00000000ffffffffUL; V1B, 0xffffffff00000000UL ]
    oracle only64 "10221e42" given wanted

  /// <summary>
  /// vexpanddm vD, vB sets each doubleword of vD to all ones where the top
  /// bit of the matching doubleword of vB is set and to all zeros where it is
  /// clear.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXPANDDM spreads each doubleword's top bit across it``() =
    (* vexpanddm v1, v3 *)
    let given = [ V3A, 0x7fffffff80000000UL; V3B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0x0000000000000000UL; V1B, 0xffffffffffffffffUL ]
    oracle only64 "10231e42" given wanted

  /// <summary>
  /// vexpandqm vD, vB sets each quadword of vD to all ones where the top bit
  /// of the matching quadword of vB is set and to all zeros where it is
  /// clear.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXPANDQM spreads each quadword's top bit across it``() =
    (* vexpandqm v1, v3 *)
    let given = [ V3A, 0x8000000000000000UL ]
    let wanted = [ V1A, 0xffffffffffffffffUL; V1B, 0xffffffffffffffffUL ]
    oracle only64 "10241e42" given wanted

  /// <summary>
  /// vextractbm rD, vB writes the top bits of the bytes of vB, that of byte 0
  /// the most significant, into the low bits of rD and clears the rest.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXTRACTBM gathers the top bit of each byte``() =
    (* vextractbm r5, v3 *)
    let given = [ V3A, 0x7fffffff80000000UL; V3B, 0xffffffff00000001UL ]
    let wanted = [ R5, 0x78f0UL ]
    oracle only64 "10a81e42" given wanted

  /// <summary>
  /// vextracthm rD, vB writes the top bits of the halfwords of vB, that of
  /// halfword 0 the most significant, into the low bits of rD and clears the
  /// rest.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXTRACTHM gathers the top bit of each halfword``() =
    (* vextracthm r5, v3 *)
    let given = [ V3A, 0x7fffffff80000000UL; V3B, 0xffffffff00000001UL ]
    let wanted = [ R5, 0x6cUL ]
    oracle only64 "10a91e42" given wanted

  /// <summary>
  /// vextractwm rD, vB writes the top bits of the words of vB, that of word 0
  /// the most significant, into the low bits of rD and clears the rest.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXTRACTWM gathers the top bit of each word``() =
    (* vextractwm r5, v3 *)
    let given = [ V3A, 0x7fffffff80000000UL; V3B, 0xffffffff00000001UL ]
    let wanted = [ R5, 0x6UL ]
    oracle only64 "10aa1e42" given wanted

  /// <summary>
  /// vextractdm rD, vB writes the top bits of the doublewords of vB, that of
  /// doubleword 0 the most significant, into the low bits of rD and clears
  /// the rest.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXTRACTDM gathers the top bit of each doubleword``() =
    (* vextractdm r5, v3 *)
    let given = [ V3A, 0x7fffffff80000000UL; V3B, 0xffffffff00000001UL ]
    let wanted = [ R5, 0x1UL ]
    oracle only64 "10ab1e42" given wanted

  /// <summary>
  /// vextractqm rD, vB writes the top bits of the quadwords of vB, that of
  /// quadword 0 the most significant, into the low bits of rD and clears the
  /// rest.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXTRACTQM gathers the top bit of each quadword``() =
    (* vextractqm r5, v3 *)
    let given = [ V3A, 0x8000000000000000UL ]
    let wanted = [ R5, 0x1UL ]
    oracle only64 "10ac1e42" given wanted

  /// <summary>
  /// mtvsrbm vD, rB sets each byte of vD to all ones or all zeros as the
  /// matching low bit of rB, that of byte 0 the most significant, is set or
  /// clear.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] MTVSRBM builds a byte mask from a register``() =
    (* mtvsrbm v1, r7 *)
    let given =
      [ R7, 0x7fffffffffffffffUL
        V1A, 0x7fffffff80000000UL
        V1B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0xffffffffffffffffUL; V1B, 0xffffffffffffffffUL ]
    oracle only64 "10303e42" given wanted

  /// <summary>
  /// mtvsrhm vD, rB sets each halfword of vD to all ones or all zeros as the
  /// matching low bit of rB, that of halfword 0 the most significant, is set
  /// or clear.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] MTVSRHM builds a halfword mask from a register``() =
    (* mtvsrhm v1, r7 *)
    let given =
      [ R7, 0x7fffffffffffffffUL
        V1A, 0x7fffffff80000000UL
        V1B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0xffffffffffffffffUL; V1B, 0xffffffffffffffffUL ]
    oracle only64 "10313e42" given wanted

  /// <summary>
  /// mtvsrwm vD, rB sets each word of vD to all ones or all zeros as the
  /// matching low bit of rB, that of word 0 the most significant, is set or
  /// clear.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] MTVSRWM builds a word mask from a register``() =
    (* mtvsrwm v1, r7 *)
    let given =
      [ R7, 0x7fffffffffffffffUL
        V1A, 0x7fffffff80000000UL
        V1B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0xffffffffffffffffUL; V1B, 0xffffffffffffffffUL ]
    oracle only64 "10323e42" given wanted

  /// <summary>
  /// mtvsrdm vD, rB sets each doubleword of vD to all ones or all zeros as
  /// the matching low bit of rB, that of doubleword 0 the most significant,
  /// is set or clear.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] MTVSRDM builds a doubleword mask from a register``() =
    (* mtvsrdm v1, r7 *)
    let given =
      [ R7, 0x7fffffffffffffffUL
        V1A, 0x7fffffff80000000UL
        V1B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0xffffffffffffffffUL; V1B, 0xffffffffffffffffUL ]
    oracle only64 "10333e42" given wanted

  /// <summary>
  /// mtvsrqm vD, rB sets each quadword of vD to all ones or all zeros as the
  /// matching low bit of rB, that of quadword 0 the most significant, is set
  /// or clear.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] MTVSRQM builds a quadword mask from a register``() =
    (* mtvsrqm v1, r7 *)
    let given =
      [ R7, 0x7fffffffffffffffUL
        V1A, 0x7fffffff80000000UL
        V1B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0xffffffffffffffffUL; V1B, 0xffffffffffffffffUL ]
    oracle only64 "10343e42" given wanted

  /// <summary>
  /// mtvsrbmi vD, bm sets each byte of vD to all ones or all zeros as the
  /// matching bit of the sixteen-bit bm, byte 0's the most significant, is
  /// set or clear.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] MTVSRBMI builds a byte mask from an immediate``() =
    (* mtvsrbmi v1, 4660 *)
    let given = [ V1A, 0x7fffffff80000000UL; V1B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0x000000ff0000ff00UL; V1B, 0x0000ffff00ff0000UL ]
    oracle only64 "103a1214" given wanted

  /// <summary>
  /// vcntmbb rD, vB, MP writes into the top bits of rD how many bytes of vB
  /// have their top bit equal to MP, and clears the rest.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCNTMBB counts the bytes with a given top bit``() =
    (* vcntmbb r5, v3, 1 *)
    let given = [ V3A, 0x7fffffff80000000UL; V3B, 0xffffffff00000001UL ]
    let wanted = [ R5, 0x800000000000000UL ]
    oracle only64 "10b91e42" given wanted

  /// <summary>
  /// vcntmbh rD, vB, MP writes into the top bits of rD how many halfwords of
  /// vB have their top bit equal to MP, and clears the rest.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCNTMBH counts the halfwords with a given top bit``() =
    (* vcntmbh r5, v3, 1 *)
    let given = [ V3A, 0x7fffffff80000000UL; V3B, 0xffffffff00000001UL ]
    let wanted = [ R5, 0x800000000000000UL ]
    oracle only64 "10bb1e42" given wanted

  /// <summary>
  /// vcntmbw rD, vB, MP writes into the top bits of rD how many words of vB
  /// have their top bit equal to MP, and clears the rest.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCNTMBW counts the words with a given top bit``() =
    (* vcntmbw r5, v3, 1 *)
    let given = [ V3A, 0x7fffffff80000000UL; V3B, 0xffffffff00000001UL ]
    let wanted = [ R5, 0x800000000000000UL ]
    oracle only64 "10bd1e42" given wanted

  /// <summary>
  /// vcntmbd rD, vB, MP writes into the top bits of rD how many doublewords
  /// of vB have their top bit equal to MP, and clears the rest.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCNTMBD counts the doublewords with a given top bit``() =
    (* vcntmbd r5, v3, 1 *)
    let given = [ V3A, 0x7fffffff80000000UL; V3B, 0xffffffff00000001UL ]
    let wanted = [ R5, 0x800000000000000UL ]
    oracle only64 "10bf1e42" given wanted

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
