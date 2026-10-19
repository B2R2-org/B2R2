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

  /// The named calls the statements of one word make, in order.
  let namedCalls isa hex =
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
    lifted isa hex
    |> Array.toList
    |> List.collect (function
      | Put(Src = s) ->
        callsIn s
      | _ ->
        [])
    |> List.toArray

  /// Runs a decimal add or subtract over vA and vB holding the low doublewords
  /// given, their high ones zero, and asserts vD and CR6 as QEMU left them.
  let decimalCase hex a b result cr6 =
    let given = [ V2B, a; V3B, b ]
    let field =
      [ CR6_0, (cr6 >>> 3) &&& 1UL
        CR6_1, (cr6 >>> 2) &&& 1UL
        CR6_2, (cr6 >>> 1) &&& 1UL
        CR6_3, cr6 &&& 1UL ]
    oracle only64 hex given ([ V1A, 0UL; V1B, result ] @ field)

  /// Whether a RoundCtrl encloses arithmetic rounded to nearest, ties to
  /// even, rather than one of the conversions IRRunner runs inside a RoundCtrl.
  let isNearestArithmetic (mode: Expr) (body: Expr) =
    match mode, body with
    | _, Cast(Kind = BinIR.CastKind.FloatToSInt)
    | _, Cast(Kind = BinIR.CastKind.RoundToIntegral) ->
      false
    | Num(Value = m), _ ->
      m.ToUInt64() = uint64 (int BinIR.RoundingMode.ToNearestEven)
    | _ ->
      false

  /// An expression with each RoundCtrl that rounds arithmetic to nearest
  /// replaced by the arithmetic: IRRunner rounds that to nearest already.
  let rec toNearest (e: Expr) =
    match e with
    | RoundCtrl(Mode = m; Body = b) when isNearestArithmetic m b ->
      toNearest b
    | BinOp(Op = BinIR.BinOpType.APP) ->
      e
    | BinOp(Op = op; Left = l; Right = r) ->
      AST.binop op (toNearest l) (toNearest r)
    | UnOp(Op = op; Operand = x) ->
      AST.unop op (toNearest x)
    | RelOp(Op = op; Left = l; Right = r) ->
      AST.relop op (toNearest l) (toNearest r)
    | Cast(Kind = k; Type = t; Operand = x) ->
      AST.cast k t (toNearest x)
    | Extract(Operand = x; Type = t; StartPos = p) ->
      AST.extract (toNearest x) t p
    | Ite(Cond = c; TrueExpr = a; FalseExpr = b) ->
      AST.ite (toNearest c) (toNearest a) (toNearest b)
    | _ ->
      e

  /// oracle for the vector floating-point forms, whose arithmetic rounds to
  /// nearest whatever FPSCR[RN] holds and so is enclosed in a RoundCtrl.
  let oracleNearest isas hex given wanted =
    for isa in isas do
      let stmts =
        lifted isa hex
        |> Array.map (function
          | Put(Dst = d; Src = v) -> AST.put d (toNearest v)
          | s -> s)
      let read = IRRunner.run stmts (inputsOf isa given)
      for r, v in wanted do
        expect v ((read (var isa r)).ToUInt64()) $"{hex} {r} {nameOf isa}"

  /// Whether an expression, or any expression inside it, is one pred holds of.
  let rec occurs pred (e: Expr) =
    if pred e then
      true
    else
      match e with
      | BinOp(Left = l; Right = r) | RelOp(Left = l; Right = r) ->
        occurs pred l || occurs pred r
      | UnOp(Operand = x) | Cast(Operand = x) | Extract(Operand = x) ->
        occurs pred x
      | RoundCtrl(Body = x) ->
        occurs pred x
      | Ite(Cond = c; TrueExpr = a; FalseExpr = b) ->
        occurs pred c || occurs pred a || occurs pred b
      | _ ->
        false

  /// Whether any value one word puts somewhere holds an expression pred holds
  /// of.
  let liftedHas isa hex pred =
    lifted isa hex
    |> Array.exists (function
      | Put(Src = s) -> occurs pred s
      | _ -> false)

  /// Whether an expression is the binary operation op with 2.0 on its left,
  /// as 2 raised to a single and the base-2 logarithm of one are written.
  let ofTwo op = function
    | BinOp(Op = o; Left = Num(Value = v)) ->
      o = op && v.ToUInt64() = 0x40000000UL
    | _ ->
      false

  /// Eight bytes of memory in address order, given as the oracle writes them:
  /// one big-endian doubleword.
  let chunk (v: uint64) = Array.init 8 (fun i -> byte (v >>> (56 - 8 * i)))

  /// The eight bytes of memory from an address, read back as chunk writes
  /// them.
  let chunkAt (memory: Collections.Generic.IReadOnlyDictionary<_, _>) addr =
    Array.init 8 (fun i -> uint64 (memory[addr + uint64 i]: byte))
    |> Array.fold (fun acc b -> (acc <<< 8) ||| b) 0UL

  (* Lane X: VSX, MMA and quad precision. *)
  /// The bytes of memory eight-byte chunks stand for, each chunk being its
  /// bytes in address order read as one big-endian number, the way the QEMU
  /// oracle (optest-powerpc/oracle) prints a window of memory.
  let chunks (given: (uint64 * uint64) list) =
    given
    |> List.map (fun (addr, v) -> addr, BitConverter.GetBytes v |> Array.rev)

  /// <summary>
  /// Runs one word on the processor an ISA names over the registers and the
  /// eight-byte chunks of memory given, and asserts what each listed
  /// register and chunk holds afterwards: the values QEMU left, read from
  /// the oracle's results-ppc64.json and results-ppc64le.json. FPSCR is
  /// asserted only in its FPRF field, the only part of it the lifter writes.
  /// </summary>
  let oracleMem isa hex given memory regs mem =
    let after, outcome = exec isa hex given (chunks memory)
    for r, v in regs do
      let actual = if r = FPSCR then fprf (after r) else after r
      expect v actual $"{r} {hex} {nameOf isa}"
    for addr, v in mem do
      expect v (chunkAt outcome addr) $"{addr:x} {hex} {nameOf isa}"
  /// XER[OV], bit 33 of the Power ISA's XER, kept at bit 30 of XER here.
  let ov = 0x40000000UL

  /// XER's SO, OV and CA after a run, the status bits every processor has.
  let soOvCa after = after XER &&& (so ||| ov ||| ca)

  /// The 64-bit processors, in both byte orders.
  let ppc64s = [ ppc64; ppc64le ]

  /// Whether one word traps on the processor an ISA names, over the
  /// registers given. The runner refuses every side effect, so a run that
  /// reaches the trap's interrupt fails on it and one that does not
  /// completes.
  let traps isa hex given =
    try
      run isa hex given |> ignore
      false
    with e when e.Message.EndsWith "!!Int0" ->
      true

  /// Asserts whether one word trapped, naming the case.
  let expectTrap (trapped: bool) isa hex given =
    let case = $"{hex} {nameOf isa}"
    Assert.AreEqual(box trapped, box (traps isa hex given), case)

  /// Runs words one after another, each over what the one before left of the
  /// registers named and of memory, and gives what the last one left.
  let sequence isa hexes regs given memory =
    let step (given, memory) hex =
      let outcome = IRRunner.exec (lifted isa hex) (inputsOf isa given) memory
      let read r = r, (outcome.Read(var isa r)).ToUInt64()
      let bytes = outcome.Memory |> Seq.map (fun kv -> kv.Key, [| kv.Value |])
      List.map read regs, List.ofSeq bytes
    let regs, memory = List.fold step (given, memory) hexes
    let values = Map.ofList regs
    (fun r -> Map.find r values), Map.ofList memory

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
  /// vcipher vD, vA, vB runs one AES round -- SubBytes, ShiftRows, MixColumns,
  /// AddRoundKey -- on the state in vA with the round key in vB, which is the
  /// AESENC call the other front ends make. The calls number the state's bytes
  /// from the least significant end, so the operands go in laid out that way;
  /// IRRunner has no AES, so the call is what is asserted, its values having
  /// been checked against QEMU through the host's AES instructions.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCIPHER lifts to the named AES calls``() =
    (* vcipher v1, v2, v3 *)
    let calls = [| "AESENC" |]
    for isa in only64 do
      CollectionAssert.AreEqual(calls, namedCalls isa "10221d08")

  /// <summary>
  /// vcipherlast vD, vA, vB runs the last AES round, the one without
  /// MixColumns, which is the AESENCLAST call. The calls number the state's
  /// bytes from the least significant end, so the operands go in laid out that
  /// way; IRRunner has no AES, so the call is what is asserted, its values
  /// having been checked against QEMU through the host's AES instructions.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCIPHERLAST lifts to the named AES calls``() =
    (* vcipherlast v1, v2, v3 *)
    let calls = [| "AESENCLAST" |]
    for isa in only64 do
      CollectionAssert.AreEqual(calls, namedCalls isa "10221d09")

  /// <summary>
  /// vncipher vD, vA, vB runs one inverse round whose key is added before
  /// InvMixColumns, so it is the last inverse round (AESDECLAST) followed by
  /// InvMixColumns on its own (AESIMC). The calls number the state's bytes from
  /// the least significant end, so the operands go in laid out that way;
  /// IRRunner has no AES, so the call is what is asserted, its values having
  /// been checked against QEMU through the host's AES instructions.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VNCIPHER lifts to the named AES calls``() =
    (* vncipher v1, v2, v3 *)
    let calls = [| "AESDECLAST"; "AESIMC" |]
    for isa in only64 do
      CollectionAssert.AreEqual(calls, namedCalls isa "10221d48")

  /// <summary>
  /// vncipherlast vD, vA, vB runs the last inverse AES round, which is the
  /// AESDECLAST call. The calls number the state's bytes from the least
  /// significant end, so the operands go in laid out that way; IRRunner has no
  /// AES, so the call is what is asserted, its values having been checked
  /// against QEMU through the host's AES instructions.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VNCIPHERLAST lifts to the named AES calls``() =
    (* vncipherlast v1, v2, v3 *)
    let calls = [| "AESDECLAST" |]
    for isa in only64 do
      CollectionAssert.AreEqual(calls, namedCalls isa "10221d49")

  /// <summary>
  /// vsbox vD, vA applies SubBytes alone: the last AES round with a zero key
  /// (AESENCLAST), its ShiftRows undone by moving the bytes back. The calls
  /// number the state's bytes from the least significant end, so the operands
  /// go in laid out that way; IRRunner has no AES, so the call is what is
  /// asserted, its values having been checked against QEMU through the host's
  /// AES instructions.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSBOX lifts to the named AES calls``() =
    (* vsbox v1, v2 *)
    let calls = [| "AESENCLAST" |]
    for isa in only64 do
      CollectionAssert.AreEqual(calls, namedCalls isa "102205c8")

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
  /// bcdadd. vD, vA, vB, PS adds two signed packed decimals -- 31 digits and
  /// a sign code, 0b1011 and 0b1101 negative and the other four valid codes
  /// positive. The sum's sign code is 0b1101 when negative and otherwise
  /// 0b1100, or 0b1111 where PS is 1; CR6 says less than, greater than or
  /// equal to zero.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] BCDADDdot adds signed packed decimals``() =
    (* bcdadd. v1, v2, v3, 0 *)
    decimalCase "10221c01" 0x123cUL 0x456cUL 0x579cUL 0b0100UL
    decimalCase "10221c01" 0x5dUL 0x3cUL 0x2dUL 0b1000UL
    decimalCase "10221c01" 0x7aUL 0x7bUL 0xcUL 0b0010UL
    decimalCase "10221c01" 0x987654321fUL 0x123456789eUL 0x1111111110cUL 4UL
    (* bcdadd. v1, v2, v3, 1 *)
    decimalCase "10221e01" 0x123cUL 0x456cUL 0x579fUL 0b0100UL
    decimalCase "10221e01" 0x7aUL 0x7bUL 0xfUL 0b0010UL

  /// <summary>
  /// bcdsub. vD, vA, vB, PS writes vA - vB as bcdadd. writes a sum, the sign
  /// code and CR6 taken from the difference.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] BCDSUBdot subtracts signed packed decimals``() =
    (* bcdsub. v1, v2, v3, 0 *)
    decimalCase "10221c41" 0x123cUL 0x456cUL 0x333dUL 0b1000UL
    decimalCase "10221c41" 0x5dUL 0x3cUL 0x8dUL 0b1000UL
    decimalCase "10221c41" 0x42cUL 0x42cUL 0xcUL 0b0010UL
    (* bcdsub. v1, v2, v3, 1 *)
    decimalCase "10221e41" 0x7aUL 0x7bUL 0x14fUL 0b0100UL
    decimalCase "10221e41" 0x42cUL 0x42cUL 0xfUL 0b0010UL

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
  /// vstribl vD, vB copies the bytes of vB from the left up to and including
  /// the first zero one and clears the rest of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSTRIBL keeps bytes from the left up to a zero``() =
    (* vstribl v1, v3 *)
    let given = [ V3A, 0x5555555555555555UL; V3B, 0x5555555555555555UL ]
    let wanted = [ V1A, 0x5555555555555555UL; V1B, 0x5555555555555555UL ]
    oracle only64 "1020180d" given wanted

  /// <summary>
  /// vstribl. vD, vB writes vD as vstribl does and sets CR6 to 0b0010 where a
  /// zero element was found and to zero where none was.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSTRIBLdot isolates a byte string and records it``() =
    (* vstribl. v1, v3 *)
    let given = [ V3A, 0x5555555555555555UL; V3B, 0x5555555555555555UL ]
    let wanted =
      [ CR6_0, 0UL
        CR6_1, 0UL
        CR6_2, 0UL
        CR6_3, 0UL
        V1A, 0x5555555555555555UL
        V1B, 0x5555555555555555UL ]
    oracle only64 "10201c0d" given wanted

  /// <summary>
  /// vstribr vD, vB copies the bytes of vB from the right up to and including
  /// the first zero one and clears the rest of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSTRIBR keeps bytes from the right up to a zero``() =
    (* vstribr v1, v3 *)
    let given = [ V3A, 0x5555555555555555UL; V3B, 0x5555555555555555UL ]
    let wanted = [ V1A, 0x5555555555555555UL; V1B, 0x5555555555555555UL ]
    oracle only64 "1021180d" given wanted

  /// <summary>
  /// vstribr. vD, vB writes vD as vstribr does and sets CR6 to 0b0010 where a
  /// zero element was found and to zero where none was.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSTRIBRdot isolates a byte string and records it``() =
    (* vstribr. v1, v3 *)
    let given = [ V3A, 0x5555555555555555UL; V3B, 0x5555555555555555UL ]
    let wanted =
      [ CR6_0, 0UL
        CR6_1, 0UL
        CR6_2, 0UL
        CR6_3, 0UL
        V1A, 0x5555555555555555UL
        V1B, 0x5555555555555555UL ]
    oracle only64 "10211c0d" given wanted

  /// <summary>
  /// vstrihl vD, vB copies the halfwords of vB from the left up to and
  /// including the first zero one and clears the rest of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSTRIHL keeps halfwords from the left up to a zero``() =
    (* vstrihl v1, v3 *)
    let given = [ V3A, 0x7fff8000ffff0001UL; V3B, 0x7f80ff00017f80ffUL ]
    let wanted = [ V1A, 0x7fff8000ffff0001UL; V1B, 0x7f80ff00017f80ffUL ]
    oracle only64 "1022180d" given wanted

  /// <summary>
  /// vstrihl. vD, vB writes vD as vstrihl does and sets CR6 to 0b0010 where a
  /// zero element was found and to zero where none was.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSTRIHLdot isolates a halfword string and records it``() =
    (* vstrihl. v1, v3 *)
    let given = [ V3A, 0x7fff8000ffff0001UL; V3B, 0x7f80ff00017f80ffUL ]
    let wanted =
      [ CR6_0, 0UL
        CR6_1, 0UL
        CR6_2, 0UL
        CR6_3, 0UL
        V1A, 0x7fff8000ffff0001UL
        V1B, 0x7f80ff00017f80ffUL ]
    oracle only64 "10221c0d" given wanted

  /// <summary>
  /// vstrihr vD, vB copies the halfwords of vB from the right up to and
  /// including the first zero one and clears the rest of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSTRIHR keeps halfwords from the right up to a zero``() =
    (* vstrihr v1, v3 *)
    let given = [ V3A, 0x7fff8000ffff0001UL; V3B, 0x7f80ff00017f80ffUL ]
    let wanted = [ V1A, 0x7fff8000ffff0001UL; V1B, 0x7f80ff00017f80ffUL ]
    oracle only64 "1023180d" given wanted

  /// <summary>
  /// vstrihr. vD, vB writes vD as vstrihr does and sets CR6 to 0b0010 where a
  /// zero element was found and to zero where none was.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSTRIHRdot isolates a halfword string and records it``() =
    (* vstrihr. v1, v3 *)
    let given = [ V3A, 0x7fff8000ffff0001UL; V3B, 0x7f80ff00017f80ffUL ]
    let wanted =
      [ CR6_0, 0UL
        CR6_1, 0UL
        CR6_2, 0UL
        CR6_3, 0UL
        V1A, 0x7fff8000ffff0001UL
        V1B, 0x7f80ff00017f80ffUL ]
    oracle only64 "10231c0d" given wanted

  /// <summary>
  /// vpermr vD, vA, vB, vC writes into each byte of vD byte 31 - i of the 32
  /// bytes of vA || vB, i being the low five bits of the matching byte of vC.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VPERMR permutes bytes counted from the right``() =
    (* vpermr v1, v2, v3, v4 *)
    let given =
      [ V2A, 0x7fff8000ffff0001UL
        V2B, 0x7f80ff00017f80ffUL
        V3A, 0x0001ffff80007fffUL
        V3B, 0x7f7f808001010000UL
        V4A, 0x0003000500070009UL
        V4B, 0x000b000d000f0011UL ]
    let wanted = [ V1A, 0x00010080007f007fUL; V1B, 0x008000ff00000080UL ]
    oracle only64 "1022193b" given wanted

  /// <summary>
  /// vgnb rD, vB, N concatenates every Nth bit of vB, from bit 0 on, from the
  /// left of rD and clears the bits below them.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VGNB gathers every Nth bit``() =
    (* vgnb r5, v3, 2 *)
    let given = [ V3A, 0x7fffffff80000000UL; V3B, 0xffffffff00000001UL ]
    let wanted = [ R5, 0x7fff8000ffff0000UL ]
    oracle only64 "10a21ccc" given wanted

  /// <summary>
  /// vbpermd vD, vA, vB writes into the low byte of each doubleword of vD the
  /// bits of vA the eight bytes of the matching doubleword of vB index from
  /// the left, an index past 63 giving a zero, and clears the rest.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VBPERMD permutes bits of each doubleword``() =
    (* vbpermd v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x0000000000000010UL; V1B, 0x0000000000000007UL ]
    oracle only64 "10221dcc" given wanted

  /// <summary>
  /// vcfuged vD, vA, vB moves the bits of each doubleword of vA that the mask
  /// in vB selects to the right end and the others to the left, each group
  /// keeping its order.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCFUGED centrifuges each doubleword``() =
    (* vcfuged v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x7fffffff80000000UL; V1B, 0x80000001fffffffeUL ]
    oracle only64 "10221d4d" given wanted

  /// <summary>
  /// vpdepd vD, vA, vB spreads the low bits of each doubleword of vA to the
  /// set bits of the mask in vB, in order, and clears the rest.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VPDEPD deposits bits under a mask``() =
    (* vpdepd v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x0000000180000000UL; V1B, 0x0000000080000000UL ]
    oracle only64 "10221dcd" given wanted

  /// <summary>
  /// vpextd vD, vA, vB packs the bits of each doubleword of vA that the mask
  /// in vB selects into the low end, in order, and clears the rest.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VPEXTD extracts bits under a mask``() =
    (* vpextd v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x0000000180000000UL; V1B, 0x00000000fffffffeUL ]
    oracle only64 "10221d8d" given wanted

  /// <summary>
  /// vclzdm vD, vA, vB counts, from the left, the zero bits of each
  /// doubleword of vA at the set bits of the mask in vB before the first one.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCLZDM counts leading zeros under a mask``() =
    (* vclzdm v1, v2, v3 *)
    let given = [ V3A, 0xffffffffffffffffUL; V3B, 0xffffffffffffffffUL ]
    let wanted = [ V1A, 0x0000000000000040UL; V1B, 0x0000000000000040UL ]
    oracle only64 "10221f84" given wanted

  /// <summary>
  /// vctzdm vD, vA, vB counts, from the right, the zero bits of each
  /// doubleword of vA at the set bits of the mask in vB before the first one.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCTZDM counts trailing zeros under a mask``() =
    (* vctzdm v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x000000000000001fUL; V1B, 0x0000000000000001UL ]
    oracle only64 "10221fc4" given wanted

  /// <summary>
  /// The vector facility's floating-point arithmetic rounds to nearest
  /// whatever FPSCR[RN] holds (Book I 6.10, bfp32_ADD and its kin), so
  /// vaddfp encloses each sum in a RoundCtrl naming that direction.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VADDFP rounds to nearest whatever FPSCR says``() =
    let nearestSum = function
      | RoundCtrl(Mode = m; Body = BinOp(Op = BinIR.BinOpType.FADD) as b) ->
        isNearestArithmetic m b
      | _ ->
        false
    (* vaddfp v1, v2, v3 *)
    for isa in everyTarget do
      Assert.IsTrue(liftedHas isa "1022180a" nearestSum, nameOf isa)

  /// <summary>
  /// vexptefp vD, vB is 2 raised to each single, the FPOW of 2.0 rounded to
  /// nearest; IRRunner does not compute FPOW, so its shape is checked, the
  /// values having agreed with QEMU's on every vector run.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXPTEFP raises 2 to each single``() =
    (* vexptefp v1, v3 *)
    for isa in everyTarget do
      let pow = ofTwo BinIR.BinOpType.FPOW
      Assert.IsTrue(liftedHas isa "1020198a" pow, nameOf isa)

  /// <summary>
  /// vlogefp vD, vB is the base-2 logarithm of each single, the FLOG of it to
  /// base 2.0 rounded to nearest; IRRunner does not compute FLOG, so its
  /// shape is checked, the values having agreed with QEMU's on every vector
  /// run.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VLOGEFP takes the base-2 logarithm``() =
    (* vlogefp v1, v3 *)
    for isa in everyTarget do
      let log = ofTwo BinIR.BinOpType.FLOG
      Assert.IsTrue(liftedHas isa "102019ca" log, nameOf isa)

  /// <summary>
  /// With VSCR[NJ] clear, vaddfp adds denormal singles as IEEE 754 does; with
  /// it set, each denormal operand counts as a zero of its sign and a
  /// denormal sum is written as a zero (Book I 6.3.2, VSCR[NJ]), the other
  /// lanes -- an overflow to infinity among them -- unaffected.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VADDFP flushes denormals where VSCR[NJ] says``() =
    (* vaddfp v1, v2, v3 *)
    let given nj =
      [ V2A, 0x0040000080400000UL
        V2B, 0x008000017f7fffffUL
        V3A, 0x0000000100000000UL
        V3B, 0x808000007f7fffffUL
        VSCR, nj ]
    let wanted = [ V1A, 0x0040000180400000UL; V1B, 0x000000017f800000UL ]
    oracleNearest everyTarget "1022180a" (given 0UL) wanted
    let wanted = [ V1A, 0UL; V1B, 0x000000007f800000UL ]
    oracleNearest everyTarget "1022180a" (given 0x10000UL) wanted

  /// <summary>
  /// vaddfp vD, vA, vB adds each pair of singles, rounding to nearest
  /// whatever FPSCR[RN] holds; a NaN operand gives the first NaN quieted, an
  /// invalid operation 0x7FC00000. With VSCR[NJ] set, a denormal operand
  /// counts as a zero of its sign and a denormal result is written as one.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VADDFP adds singles rounding to nearest``() =
    (* vaddfp v1, v2, v3 *)
    let given =
      [ V2A, 0x3f8000003dcccccdUL
        V2B, 0x404000003f800000UL
        V3A, 0x3dcccccd40400000UL
        V3B, 0x3f8000003dcccccdUL ]
    let wanted = [ V1A, 0x3f8ccccd40466666UL; V1B, 0x408000003f8ccccdUL ]
    oracleNearest everyTarget "1022180a" given wanted

  /// <summary>
  /// vsubfp vD, vA, vB subtracts each pair of singles, rounding to nearest
  /// whatever FPSCR[RN] holds; a NaN operand gives the first NaN quieted, an
  /// invalid operation 0x7FC00000. With VSCR[NJ] set, a denormal operand
  /// counts as a zero of its sign and a denormal result is written as one.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VSUBFP subtracts singles rounding to nearest``() =
    (* vsubfp v1, v2, v3 *)
    let given =
      [ V2A, 0x3f8000003dcccccdUL
        V2B, 0x404000003f800000UL
        V3A, 0x3dcccccd40400000UL
        V3B, 0x3f8000003dcccccdUL ]
    let wanted = [ V1A, 0x3f666666c039999aUL; V1B, 0x400000003f666666UL ]
    oracleNearest everyTarget "1022184a" given wanted

  /// <summary>
  /// vmaddfp vD, vA, vC, vB writes vA times vC plus vB for each single,
  /// rounded once to nearest; the NaN taken is vA's, then vB's, then vC's.
  /// With VSCR[NJ] set, a denormal operand counts as a zero of its sign and a
  /// denormal result is written as one.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMADDFP fuses a multiply and an add``() =
    (* vmaddfp v1, v2, v4, v3 *)
    let given =
      [ V2A, 0x3f8000003dcccccdUL
        V2B, 0x404000003f800000UL
        V3A, 0x404000003f800000UL
        V3B, 0x3dcccccd40400000UL
        V4A, 0x3dcccccd40400000UL
        V4B, 0x3f8000003dcccccdUL ]
    let wanted = [ V1A, 0x404666663fa66666UL; V1B, 0x4046666640466666UL ]
    oracleNearest everyTarget "1022192e" given wanted

  /// <summary>
  /// vnmsubfp vD, vA, vC, vB writes the negation of vA times vC minus vB for
  /// each single, rounded once to nearest before the negation. With VSCR[NJ]
  /// set, a denormal operand counts as a zero of its sign and a denormal
  /// result is written as one.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VNMSUBFP fuses a negated multiply-subtract``() =
    (* vnmsubfp v1, v2, v4, v3 *)
    let given =
      [ V2A, 0x3f8000003dcccccdUL
        V2B, 0x404000003f800000UL
        V3A, 0x404000003f800000UL
        V3B, 0x3dcccccd40400000UL
        V4A, 0x3dcccccd40400000UL
        V4B, 0x3f8000003dcccccdUL ]
    let wanted = [ V1A, 0x4039999a3f333333UL; V1B, 0xc039999a4039999aUL ]
    oracleNearest everyTarget "1022192f" given wanted

  /// <summary>
  /// vmaxfp vD, vA, vB writes the larger of each pair of singles, +0 being
  /// the larger zero and a NaN operand giving a QNaN. With VSCR[NJ] set, a
  /// denormal operand counts as a zero of its sign and a denormal result is
  /// written as one.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMAXFP keeps the larger single``() =
    (* vmaxfp v1, v2, v3 *)
    let given =
      [ V2A, 0x3f8000003dcccccdUL
        V2B, 0x404000003f800000UL
        V3A, 0x3dcccccd40400000UL
        V3B, 0x3f8000003dcccccdUL ]
    let wanted = [ V1A, 0x3f80000040400000UL; V1B, 0x404000003f800000UL ]
    oracleNearest everyTarget "10221c0a" given wanted

  /// <summary>
  /// vminfp vD, vA, vB writes the smaller of each pair of singles, -0 being
  /// the smaller zero and a NaN operand giving a QNaN. With VSCR[NJ] set, a
  /// denormal operand counts as a zero of its sign and a denormal result is
  /// written as one.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMINFP keeps the smaller single``() =
    (* vminfp v1, v2, v3 *)
    let given =
      [ V2A, 0x3f8000003dcccccdUL
        V2B, 0x404000003f800000UL
        V3A, 0x3dcccccd40400000UL
        V3B, 0x3f8000003dcccccdUL ]
    let wanted = [ V1A, 0x3dcccccd3dcccccdUL; V1B, 0x3f8000003dcccccdUL ]
    oracleNearest everyTarget "10221c4a" given wanted

  /// <summary>
  /// vrefp vD, vB writes the reciprocal of each single, as QEMU computes the
  /// estimate the ISA allows: exactly, rounded to nearest. With VSCR[NJ] set,
  /// a denormal operand counts as a zero of its sign and a denormal result is
  /// written as one.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VREFP writes reciprocals of singles``() =
    (* vrefp v1, v3 *)
    let given = [ V3A, 0x3f8000003dcccccdUL; V3B, 0x404000003f800000UL ]
    let wanted = [ V1A, 0x3f80000041200000UL; V1B, 0x3eaaaaab3f800000UL ]
    oracleNearest everyTarget "1020190a" given wanted

  /// <summary>
  /// vrsqrtefp vD, vB writes the reciprocal of the square root of each
  /// single, the square root and the division each rounded to nearest. With
  /// VSCR[NJ] set, a denormal operand counts as a zero of its sign and a
  /// denormal result is written as one.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VRSQRTEFP writes reciprocal square roots``() =
    (* vrsqrtefp v1, v3 *)
    let given = [ V3A, 0x3f8000003dcccccdUL; V3B, 0x404000003f800000UL ]
    let wanted = [ V1A, 0x3f800000404a62c2UL; V1B, 0x3f13cd3a3f800000UL ]
    oracleNearest everyTarget "1020194a" given wanted

  /// <summary>
  /// vrfin vD, vB rounds each single to an integral value to nearest, ties to
  /// even, a NaN operand giving it quieted. With VSCR[NJ] set, a denormal
  /// operand counts as a zero of its sign and a denormal result is written as
  /// one.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VRFIN rounds singles to integral values``() =
    (* vrfin v1, v3 *)
    let given = [ V3A, 0x3f8000003dcccccdUL; V3B, 0x404000003f800000UL ]
    let wanted = [ V1A, 0x3f80000000000000UL; V1B, 0x404000003f800000UL ]
    oracleNearest everyTarget "10201a0a" given wanted

  /// <summary>
  /// vrfiz vD, vB rounds each single to an integral value toward zero, a NaN
  /// operand giving it quieted. With VSCR[NJ] set, a denormal operand counts
  /// as a zero of its sign and a denormal result is written as one.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VRFIZ rounds singles to integral values``() =
    (* vrfiz v1, v3 *)
    let given = [ V3A, 0x3f8000003dcccccdUL; V3B, 0x404000003f800000UL ]
    let wanted = [ V1A, 0x3f80000000000000UL; V1B, 0x404000003f800000UL ]
    oracleNearest everyTarget "10201a4a" given wanted

  /// <summary>
  /// vrfip vD, vB rounds each single to an integral value toward +infinity, a
  /// NaN operand giving it quieted. With VSCR[NJ] set, a denormal operand
  /// counts as a zero of its sign and a denormal result is written as one.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VRFIP rounds singles to integral values``() =
    (* vrfip v1, v3 *)
    let given = [ V3A, 0x3f8000003dcccccdUL; V3B, 0x404000003f800000UL ]
    let wanted = [ V1A, 0x3f8000003f800000UL; V1B, 0x404000003f800000UL ]
    oracleNearest everyTarget "10201a8a" given wanted

  /// <summary>
  /// vrfim vD, vB rounds each single to an integral value toward -infinity, a
  /// NaN operand giving it quieted. With VSCR[NJ] set, a denormal operand
  /// counts as a zero of its sign and a denormal result is written as one.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VRFIM rounds singles to integral values``() =
    (* vrfim v1, v3 *)
    let given = [ V3A, 0x3f8000003dcccccdUL; V3B, 0x404000003f800000UL ]
    let wanted = [ V1A, 0x3f80000000000000UL; V1B, 0x404000003f800000UL ]
    oracleNearest everyTarget "10201aca" given wanted

  /// <summary>
  /// vcfsx vD, vB, UIM converts each signed word of vB to the nearest single
  /// and divides it by 2^UIM.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCFSX converts signed words to singles``() =
    (* vcfsx v1, v3, 1 *)
    let given = [ V3A, 0x7fffffff80000000UL; V3B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0x4e800000ce800000UL; V1B, 0xbf0000003f000000UL ]
    oracleNearest everyTarget "10211b4a" given wanted

  /// <summary>
  /// vcfux vD, vB, UIM converts each unsigned word of vB to the nearest
  /// single and divides it by 2^UIM.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCFUX converts unsigned words to singles``() =
    (* vcfux v1, v3, 1 *)
    let given = [ V3A, 0x7fffffff80000000UL; V3B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0x4e8000004e800000UL; V1B, 0x4f0000003f000000UL ]
    oracleNearest everyTarget "10211b0a" given wanted

  /// <summary>
  /// vctsxs vD, vB, UIM multiplies each single by 2^UIM and converts it to a
  /// signed word toward zero; a value beyond the word, an infinity included,
  /// gives the nearer end and sets VSCR[SAT], a NaN gives 0.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCTSXS converts singles to signed words saturating``() =
    (* vctsxs v1, v3, 1 *)
    let given = [ V3A, 0x7f7fffff7f7fffffUL; V3B, 0x400000007f7fffffUL ]
    let wanted =
      [ V1A, 0x7fffffff7fffffffUL
        V1B, 0x000000047fffffffUL
        VSCR, 0x1UL ]
    oracle everyTarget "10211bca" given wanted
    let given =
      [ V3A, 0x3fc0000040100000UL
        V3B, 0xbf4000003fc00000UL
        VSCR, 0x10000UL ]
    let wanted =
      [ V1A, 0x0000000300000004UL
        V1B, 0xffffffff00000003UL
        VSCR, 0x10000UL ]
    oracle everyTarget "10211bca" given wanted

  /// <summary>
  /// vctuxs vD, vB, UIM multiplies each single by 2^UIM and converts it to an
  /// unsigned word toward zero; a value beyond the word or at most -1 gives
  /// the nearer end and sets VSCR[SAT], a NaN gives 0.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCTUXS converts singles to unsigned words saturating``() =
    (* vctuxs v1, v3, 1 *)
    let given =
      [ V3A, 0x3fc0000040100000UL
        V3B, 0xbf4000003fc00000UL
        VSCR, 0x10000UL ]
    let wanted =
      [ V1A, 0x0000000300000004UL
        V1B, 0x0000000000000003UL
        VSCR, 0x10001UL ]
    oracle everyTarget "10211b8a" given wanted
    let given = [ V3A, 0x3f8000003dcccccdUL; V3B, 0x404000003f800000UL ]
    let wanted =
      [ V1A, 0x0000000200000000UL
        V1B, 0x0000000600000002UL
        VSCR, 0x0UL ]
    oracle everyTarget "10211b8a" given wanted

  /// <summary>
  /// vcmpeqfp vD, vA, vB sets each word of vD to all ones where the single of
  /// vA is equal to that of vB and to all zeros where it is not or either is
  /// a NaN. With VSCR[NJ] set, a denormal operand counts as a zero of its
  /// sign and a denormal result is written as one.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCMPEQFP compares singles: equal to``() =
    (* vcmpeqfp v1, v2, v3 *)
    let given =
      [ V2A, 0x0000000080000000UL
        V2B, 0x3f80000000000000UL
        V3A, 0x800000003f800000UL
        V3B, 0x0000000080000000UL
        VSCR, 0x10000UL ]
    let wanted = [ V1A, 0xffffffff00000000UL; V1B, 0x00000000ffffffffUL ]
    oracleNearest everyTarget "102218c6" given wanted

  /// <summary>
  /// vcmpeqfp. vD, vA, vB writes vD as vcmpeqfp does and sets CR6: its first
  /// bit where every compare is true, its third where none is. With VSCR[NJ]
  /// set, a denormal operand counts as a zero of its sign and a denormal
  /// result is written as one.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCMPEQFPdot records the equal to compare in CR6``() =
    (* vcmpeqfp. v1, v2, v3 *)
    let given =
      [ V2A, 0x0000000080000000UL
        V2B, 0x3f80000000000000UL
        V3A, 0x800000003f800000UL
        V3B, 0x0000000080000000UL
        VSCR, 0x10000UL ]
    let wanted =
      [ CR6_0, 0UL
        CR6_1, 0UL
        CR6_2, 0UL
        CR6_3, 0UL
        V1A, 0xffffffff00000000UL
        V1B, 0x00000000ffffffffUL ]
    oracleNearest everyTarget "10221cc6" given wanted

  /// <summary>
  /// vcmpgefp vD, vA, vB sets each word of vD to all ones where the single of
  /// vA is at least that of vB and to all zeros where it is not or either is
  /// a NaN. With VSCR[NJ] set, a denormal operand counts as a zero of its
  /// sign and a denormal result is written as one.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCMPGEFP compares singles: at least``() =
    (* vcmpgefp v1, v2, v3 *)
    let given =
      [ V2A, 0x3f8000003dcccccdUL
        V2B, 0x404000003f800000UL
        V3A, 0x3dcccccd40400000UL
        V3B, 0x3f8000003dcccccdUL ]
    let wanted = [ V1A, 0xffffffff00000000UL; V1B, 0xffffffffffffffffUL ]
    oracleNearest everyTarget "102219c6" given wanted

  /// <summary>
  /// vcmpgefp. vD, vA, vB writes vD as vcmpgefp does and sets CR6: its first
  /// bit where every compare is true, its third where none is. With VSCR[NJ]
  /// set, a denormal operand counts as a zero of its sign and a denormal
  /// result is written as one.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCMPGEFPdot records the at least compare in CR6``() =
    (* vcmpgefp. v1, v2, v3 *)
    let given =
      [ V2A, 0x3f8000003dcccccdUL
        V2B, 0x404000003f800000UL
        V3A, 0x3dcccccd40400000UL
        V3B, 0x3f8000003dcccccdUL ]
    let wanted =
      [ CR6_0, 0UL
        CR6_1, 0UL
        CR6_2, 0UL
        CR6_3, 0UL
        V1A, 0xffffffff00000000UL
        V1B, 0xffffffffffffffffUL ]
    oracleNearest everyTarget "10221dc6" given wanted

  /// <summary>
  /// vcmpgtfp vD, vA, vB sets each word of vD to all ones where the single of
  /// vA is greater than that of vB and to all zeros where it is not or either
  /// is a NaN. With VSCR[NJ] set, a denormal operand counts as a zero of its
  /// sign and a denormal result is written as one.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCMPGTFP compares singles: greater than``() =
    (* vcmpgtfp v1, v2, v3 *)
    let given =
      [ V2A, 0x3f8000003dcccccdUL
        V2B, 0x404000003f800000UL
        V3A, 0x3dcccccd40400000UL
        V3B, 0x3f8000003dcccccdUL ]
    let wanted = [ V1A, 0xffffffff00000000UL; V1B, 0xffffffffffffffffUL ]
    oracleNearest everyTarget "10221ac6" given wanted

  /// <summary>
  /// vcmpgtfp. vD, vA, vB writes vD as vcmpgtfp does and sets CR6: its first
  /// bit where every compare is true, its third where none is. With VSCR[NJ]
  /// set, a denormal operand counts as a zero of its sign and a denormal
  /// result is written as one.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCMPGTFPdot records the greater than compare in CR6``() =
    (* vcmpgtfp. v1, v2, v3 *)
    let given =
      [ V2A, 0x3f8000003dcccccdUL
        V2B, 0x404000003f800000UL
        V3A, 0x3dcccccd40400000UL
        V3B, 0x3f8000003dcccccdUL ]
    let wanted =
      [ CR6_0, 0UL
        CR6_1, 0UL
        CR6_2, 0UL
        CR6_3, 0UL
        V1A, 0xffffffff00000000UL
        V1B, 0xffffffffffffffffUL ]
    oracleNearest everyTarget "10221ec6" given wanted

  /// <summary>
  /// vcmpbfp vD, vA, vB writes at the top of each word of vD two bits: the
  /// first set where the single of vA is not at most that of vB, the second
  /// where it is not at least its negation, both for a NaN. With VSCR[NJ]
  /// set, a denormal operand counts as a zero of its sign and a denormal
  /// result is written as one.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCMPBFP checks singles against bounds``() =
    (* vcmpbfp v1, v2, v3 *)
    let given =
      [ V2A, 0x3f8000003dcccccdUL
        V2B, 0x404000003f800000UL
        V3A, 0x3dcccccd40400000UL
        V3B, 0x3f8000003dcccccdUL ]
    let wanted = [ V1A, 0x8000000000000000UL; V1B, 0x8000000080000000UL ]
    oracleNearest everyTarget "10221bc6" given wanted

  /// <summary>
  /// vcmpbfp. vD, vA, vB writes vD as vcmpbfp does and sets CR6 to 0b0010
  /// where every single is within bounds and to zero where one is not. With
  /// VSCR[NJ] set, a denormal operand counts as a zero of its sign and a
  /// denormal result is written as one.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCMPBFPdot records the bounds check in CR6``() =
    (* vcmpbfp. v1, v2, v3 *)
    let given =
      [ V2A, 0x3f8000003dcccccdUL
        V2B, 0x404000003f800000UL
        V3A, 0x3dcccccd40400000UL
        V3B, 0x3f8000003dcccccdUL ]
    let wanted =
      [ CR6_0, 0UL
        CR6_1, 0UL
        CR6_2, 0UL
        CR6_3, 0UL
        V1A, 0x8000000000000000UL
        V1B, 0x8000000080000000UL ]
    oracleNearest everyTarget "10221fc6" given wanted

  /// <summary>
  /// bcdus. vD, vA, vB shifts the 32 unsigned digits of vB by the signed byte
  /// 7 of vA -- left by 2 here -- and sets CR6 from vB (Book I 6.15.4, p. 492):
  /// the first bit always clear, as an unsigned value is never negative,
  /// greater than for a nonzero vB. qemu-ppc64 -cpu power10 (8.2.2) sets the
  /// first bit instead and reports on the shifted value rather than on vB,
  /// which the manual rules out (deviations/ppc64/bcd_shift_cr.c), so these
  /// values are the manual's.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] BCDUSdot shifts unsigned decimal digits``() =
    (* bcdus. v1, v2, v3 *)
    let given = [ V2A, 2UL; V3B, 0x12345UL ]
    let wanted =
      [ V1A, 0UL
        V1B, 0x1234500UL
        CR6_0, 0UL
        CR6_1, 1UL
        CR6_2, 0UL
        CR6_3, 0UL ]
    oracle only64 "10221c81" given wanted

  /// <summary>
  /// bcdcpsgn. vD, vA, vB writes the digits of vA with the sign code of vB;
  /// CR6 compares the result with zero, 0b0001 where either operand is
  /// invalid.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] BCDCPSGNdot copies a decimal sign``() =
    (* bcdcpsgn. v1, v2, v3 *)
    let given = [ V2B, 0x000000987654321dUL; V3B, 0x000000000000000fUL ]
    let wanted =
      [ CR6_0, 0UL
        CR6_1, 1UL
        CR6_2, 0UL
        CR6_3, 0UL
        V1A, 0x0000000000000000UL
        V1B, 0x000000987654321fUL ]
    oracle only64 "10221b41" given wanted

  /// <summary>
  /// bcdsetsgn. vD, vB, PS writes vB with the sign code 0b1101 if it is
  /// negative, else 0b1100, or 0b1111 where PS is 1; CR6 compares it with
  /// zero.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] BCDSETSGNdot sets the preferred decimal sign``() =
    (* bcdsetsgn. v1, v3, 0 *)
    let given = [ V3B, 0x000000000000456aUL ]
    let wanted =
      [ CR6_0, 0UL
        CR6_1, 1UL
        CR6_2, 0UL
        CR6_3, 0UL
        V1A, 0x0000000000000000UL
        V1B, 0x000000000000456cUL ]
    oracle only64 "103f1d81" given wanted

  /// <summary>
  /// bcdcfsq. vD, vB, PS writes the signed quadword vB as a signed packed
  /// decimal; one beyond 31 digits sets the last bit of CR6 and leaves vD
  /// undefined.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] BCDCFSQdot converts a signed quadword to decimal``() =
    (* bcdcfsq. v1, v3, 0 *)
    let given = [ V3A, 0x0000007e37be2022UL; V3B, 0xc0914b267fffffffUL ]
    let wanted =
      [ CR6_0, 0UL
        CR6_1, 1UL
        CR6_2, 0UL
        CR6_3, 0UL
        V1A, 0x9999999999999999UL
        V1B, 0x999999999999999cUL ]
    oracle only64 "10221d81" given wanted

  /// <summary>
  /// bcdctsq. vD, vB writes the signed packed decimal vB as a signed
  /// quadword; CR6 compares it with zero.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] BCDCTSQdot converts a decimal to a signed quadword``() =
    (* bcdctsq. v1, v3 *)
    let given = [ V3B, 0x000000000098765dUL ]
    let wanted =
      [ CR6_0, 1UL
        CR6_1, 0UL
        CR6_2, 0UL
        CR6_3, 0UL
        V1A, 0xffffffffffffffffUL
        V1B, 0xfffffffffffe7e33UL ]
    oracle only64 "10201d81" given wanted

  /// <summary>
  /// bcds. vD, vA, vB, PS shifts the digits of vB left or right by the signed
  /// byte 7 of vA, a nonzero digit shifted out on the left setting the last
  /// bit of CR6.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] BCDSdot shifts decimal digits``() =
    (* bcds. v1, v2, v3, 0 *)
    let given = [ V2A, 0x0000000000000002UL; V3B, 0x000000000012345cUL ]
    let wanted =
      [ CR6_0, 0UL
        CR6_1, 1UL
        CR6_2, 0UL
        CR6_3, 0UL
        V1A, 0x0000000000000000UL
        V1B, 0x000000001234500cUL ]
    oracle only64 "10221cc1" given wanted

  /// <summary>
  /// bcdsr. vD, vA, vB, PS shifts as bcds. does and, shifting right, rounds
  /// the magnitude up where the last digit shifted out is 5 or more.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] BCDSRdot shifts and rounds decimal digits``() =
    (* bcdsr. v1, v2, v3, 0 *)
    let given = [ V2A, 0x00000000000000feUL; V3B, 0x000000000012355dUL ]
    let wanted =
      [ CR6_0, 1UL
        CR6_1, 0UL
        CR6_2, 0UL
        CR6_3, 0UL
        V1A, 0x0000000000000000UL
        V1B, 0x000000000000124dUL ]
    oracle only64 "10221dc1" given wanted

  /// <summary>
  /// bcdtrunc. vD, vA, vB, PS keeps the rightmost N digits of vB, N being
  /// bits 48:63 of vA, a nonzero digit cut off setting the last bit of CR6.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] BCDTRUNCdot truncates decimal digits``() =
    (* bcdtrunc. v1, v2, v3, 0 *)
    let given = [ V2A, 0x0000000000000003UL; V3B, 0x000000000012345cUL ]
    let wanted =
      [ CR6_0, 0UL
        CR6_1, 1UL
        CR6_2, 0UL
        CR6_3, 1UL
        V1A, 0x0000000000000000UL
        V1B, 0x000000000000345cUL ]
    oracle only64 "10221d01" given wanted

  /// <summary>
  /// bcdutrunc. vD, vA, vB keeps the rightmost N of the 32 unsigned digits of
  /// vB as bcdtrunc. does.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] BCDUTRUNCdot truncates unsigned decimal digits``() =
    (* bcdutrunc. v1, v2, v3 *)
    let given = [ V2A, 0x0000000000000003UL; V3B, 0x0000000000012345UL ]
    let wanted =
      [ CR6_0, 0UL
        CR6_1, 1UL
        CR6_2, 0UL
        CR6_3, 1UL
        V1A, 0x0000000000000000UL
        V1B, 0x0000000000000345UL ]
    oracle only64 "10221d41" given wanted

  /// <summary>
  /// bcdcfn. vD, vB, PS writes the national decimal vB -- seven digit
  /// halfwords and a sign halfword -- as a signed packed decimal.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] BCDCFNdot converts national decimal to packed``() =
    (* bcdcfn. v1, v3, 0 *)
    let given = [ V3A, 0x0030003000300030UL; V3B, 0x003000340032002dUL ]
    let wanted =
      [ CR6_0, 1UL
        CR6_1, 0UL
        CR6_2, 0UL
        CR6_3, 0UL
        V1A, 0x0000000000000000UL
        V1B, 0x000000000000042dUL ]
    oracle only64 "10271d81" given wanted

  /// <summary>
  /// bcdctn. vD, vB writes the low seven digits of the signed packed decimal
  /// vB as a national decimal, more digits setting the last bit of CR6.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] BCDCTNdot converts packed decimal to national``() =
    (* bcdctn. v1, v3 *)
    let given = [ V3B, 0x000000000000042dUL ]
    let wanted =
      [ CR6_0, 1UL
        CR6_1, 0UL
        CR6_2, 0UL
        CR6_3, 0UL
        V1A, 0x0030003000300030UL
        V1B, 0x003000340032002dUL ]
    oracle only64 "10251d81" given wanted

  /// <summary>
  /// bcdcfz. vD, vB, PS writes the zoned decimal vB -- a digit in the low
  /// nibble of each byte -- as a signed packed decimal.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] BCDCFZdot converts zoned decimal to packed``() =
    (* bcdcfz. v1, v3, 0 *)
    let given = [ V3A, 0x3132333435363738UL; V3B, 0x3930313233343536UL ]
    let wanted =
      [ CR6_0, 0UL
        CR6_1, 1UL
        CR6_2, 0UL
        CR6_3, 0UL
        V1A, 0x0000000000000001UL
        V1B, 0x234567890123456cUL ]
    oracle only64 "10261d81" given wanted

  /// <summary>
  /// bcdctz. vD, vB, PS writes the low sixteen digits of the signed packed
  /// decimal vB as a zoned decimal, more digits setting the last bit of CR6.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] BCDCTZdot converts packed decimal to zoned``() =
    (* bcdctz. v1, v3, 0 *)
    let given = [ V3B, 0x000000000000042dUL ]
    let wanted =
      [ CR6_0, 1UL
        CR6_1, 0UL
        CR6_2, 0UL
        CR6_3, 0UL
        V1A, 0x3030303030303030UL
        V1B, 0x3030303030303472UL ]
    oracle only64 "10241d81" given wanted

  /// <summary>
  /// vmul10uq vD, vA writes the low 128 bits of vA times ten.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMUL10UQ multiplies a quadword by ten``() =
    (* vmul10uq v1, v2 *)
    let given = [ V2A, 0x7fffffff80000000UL; V2B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0xfffffffb00000009UL; V1B, 0xfffffff60000000aUL ]
    oracle only64 "10220201" given wanted

  /// <summary>
  /// vmul10cuq vD, vA writes what vA times ten holds above 128 bits.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMUL10CUQ writes the carry of a times ten``() =
    (* vmul10cuq v1, v2 *)
    let given = [ V2A, 0x7fffffff80000000UL; V2B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0x0000000000000000UL; V1B, 0x0000000000000004UL ]
    oracle only64 "10220001" given wanted

  /// <summary>
  /// vmul10euq vD, vA, vB writes the low 128 bits of vA times ten plus the
  /// digit in the low nibble of vB.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMUL10EUQ multiplies a quadword by ten``() =
    (* vmul10euq v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0xfffffffb00000009UL; V1B, 0xfffffff60000000aUL ]
    oracle only64 "10221a41" given wanted

  /// <summary>
  /// vmul10ecuq vD, vA, vB writes what vA times ten plus the digit in the low
  /// nibble of vB holds above 128 bits.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VMUL10ECUQ writes the carry of a times ten``() =
    (* vmul10ecuq v1, v2, v3 *)
    let given =
      [ V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x0000000000000000UL; V1B, 0x0000000000000004UL ]
    oracle only64 "10221841" given wanted

  /// <summary>
  /// vextractub vD, vB, UIM writes the byte of vB that starts at byte UIM,
  /// zero-extended, into doubleword 0 of vD and clears doubleword 1.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXTRACTUB extracts the byte at a byte``() =
    (* vextractub v1, v3, 1 *)
    let given = [ V3A, 0x7fffffff80000000UL; V3B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0x00000000000000ffUL; V1B, 0x0000000000000000UL ]
    oracle only64 "10211a0d" given wanted

  /// <summary>
  /// vextractuh vD, vB, UIM writes the halfword of vB that starts at byte
  /// UIM, zero-extended, into doubleword 0 of vD and clears doubleword 1.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXTRACTUH extracts the halfword at a byte``() =
    (* vextractuh v1, v3, 1 *)
    let given = [ V3A, 0x7fffffff80000000UL; V3B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0x000000000000ffffUL; V1B, 0x0000000000000000UL ]
    oracle only64 "10211a4d" given wanted

  /// <summary>
  /// vextractuw vD, vB, UIM writes the word of vB that starts at byte UIM,
  /// zero-extended, into doubleword 0 of vD and clears doubleword 1.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXTRACTUW extracts the word at a byte``() =
    (* vextractuw v1, v3, 1 *)
    let given = [ V3A, 0x7fffffff80000000UL; V3B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0x00000000ffffff80UL; V1B, 0x0000000000000000UL ]
    oracle only64 "10211a8d" given wanted

  /// <summary>
  /// vextractd vD, vB, UIM writes the doubleword of vB that starts at byte
  /// UIM, zero-extended, into doubleword 0 of vD and clears doubleword 1.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXTRACTD extracts the doubleword at a byte``() =
    (* vextractd v1, v3, 1 *)
    let given = [ V3A, 0x7fffffff80000000UL; V3B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0xffffff80000000ffUL; V1B, 0x0000000000000000UL ]
    oracle only64 "10211acd" given wanted

  /// <summary>
  /// vinsertb vD, vB, UIM writes the low byte of doubleword 0 of vB over vD
  /// from byte UIM on, keeping the rest of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VINSERTB inserts a byte at a byte``() =
    (* vinsertb v1, v3, 1 *)
    let given =
      [ V1A, 0x0bad0bad0bad0badUL
        V1B, 0x0bad0bad0bad0badUL
        V3A, 0x7fffffff80000000UL
        V3B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0x0b000bad0bad0badUL ]
    oracle only64 "10211b0d" given wanted

  /// <summary>
  /// vinserth vD, vB, UIM writes the low halfword of doubleword 0 of vB over
  /// vD from byte UIM on, keeping the rest of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VINSERTH inserts a halfword at a byte``() =
    (* vinserth v1, v3, 1 *)
    let given =
      [ V1A, 0x0bad0bad0bad0badUL
        V1B, 0x0bad0bad0bad0badUL
        V3A, 0x7fffffff80000000UL
        V3B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0x0b0000ad0bad0badUL ]
    oracle only64 "10211b4d" given wanted

  /// <summary>
  /// vinsertw vD, vB, UIM writes the low word of doubleword 0 of vB over vD
  /// from byte UIM on, keeping the rest of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VINSERTW inserts a word at a byte``() =
    (* vinsertw v1, v3, 1 *)
    let given =
      [ V1A, 0x0bad0bad0bad0badUL
        V1B, 0x0bad0bad0bad0badUL
        V3A, 0x7fffffff80000000UL
        V3B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0x0b80000000ad0badUL ]
    oracle only64 "10211b8d" given wanted

  /// <summary>
  /// vinsertd vD, vB, UIM writes the low doubleword of doubleword 0 of vB
  /// over vD from byte UIM on, keeping the rest of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VINSERTD inserts a doubleword at a byte``() =
    (* vinsertd v1, v3, 1 *)
    let given =
      [ V1A, 0x0bad0bad0bad0badUL
        V1B, 0x0bad0bad0bad0badUL
        V3A, 0x7fffffff80000000UL
        V3B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0x0b7fffffff800000UL; V1B, 0x00ad0bad0bad0badUL ]
    oracle only64 "10211bcd" given wanted

  /// <summary>
  /// vinsw vD, rB, UIM writes the low word of rB over vD from byte UIM on,
  /// keeping the rest of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VINSW inserts a general word at a byte``() =
    (* vinsw v1, r7, 1 *)
    let given =
      [ R7, 0x7fffffffffffffffUL
        V1A, 0x0bad0bad0bad0badUL
        V1B, 0x0bad0bad0bad0badUL ]
    let wanted = [ V1A, 0x0bffffffffad0badUL ]
    oracle only64 "102138cf" given wanted

  /// <summary>
  /// vinsd vD, rB, UIM writes the low doubleword of rB over vD from byte UIM
  /// on, keeping the rest of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VINSD inserts a general doubleword at a byte``() =
    (* vinsd v1, r7, 1 *)
    let given =
      [ R7, 0x7fffffffffffffffUL
        V1A, 0x0bad0bad0bad0badUL
        V1B, 0x0bad0bad0bad0badUL ]
    let wanted = [ V1A, 0x0b7fffffffffffffUL; V1B, 0xffad0bad0bad0badUL ]
    oracle only64 "102139cf" given wanted

  /// <summary>
  /// vextublx rD, rA, vB writes into rD, zero-extended, the byte of vB at the
  /// byte the low four bits of rA count from the left.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXTUBLX extracts a byte indexed from the left``() =
    (* vextublx r5, r6, v3 *)
    let given =
      [ R6, 0x7fffffffffffffffUL
        V3A, 0x7fffffff80000000UL
        V3B, 0xffffffff00000001UL ]
    let wanted = [ R5, 0x1UL ]
    oracle only64 "10a61e0d" given wanted

  /// <summary>
  /// vextuhlx rD, rA, vB writes into rD, zero-extended, the halfword of vB at
  /// the byte the low four bits of rA count from the left.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXTUHLX extracts a halfword indexed from the left``() =
    (* vextuhlx r5, r6, v3 *)
    let given =
      [ R6, 0x8000000000000000UL
        V3A, 0x7fff8000ffff0001UL
        V3B, 0x7f80ff00017f80ffUL ]
    let wanted = [ R5, 0x7fffUL ]
    oracle only64 "10a61e4d" given wanted

  /// <summary>
  /// vextuwlx rD, rA, vB writes into rD, zero-extended, the word of vB at the
  /// byte the low four bits of rA count from the left.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXTUWLX extracts a word indexed from the left``() =
    (* vextuwlx r5, r6, v3 *)
    let given =
      [ R6, 0x8000000000000000UL
        V3A, 0x7fff8000ffff0001UL
        V3B, 0x7f80ff00017f80ffUL ]
    let wanted = [ R5, 0x7fff8000UL ]
    oracle only64 "10a61e8d" given wanted

  /// <summary>
  /// vextubrx rD, rA, vB writes into rD, zero-extended, the byte of vB at the
  /// byte the low four bits of rA count from the right.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXTUBRX extracts a byte indexed from the right``() =
    (* vextubrx r5, r6, v3 *)
    let given =
      [ R6, 0x7fffffffffffffffUL
        V3A, 0x7fffffff80000000UL
        V3B, 0xffffffff00000001UL ]
    let wanted = [ R5, 0x7fUL ]
    oracle only64 "10a61f0d" given wanted

  /// <summary>
  /// vextuhrx rD, rA, vB writes into rD, zero-extended, the halfword of vB at
  /// the byte the low four bits of rA count from the right.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXTUHRX extracts a halfword indexed from the right``() =
    (* vextuhrx r5, r6, v3 *)
    let given =
      [ R6, 0x8000000000000000UL
        V3A, 0x7fff8000ffff0001UL
        V3B, 0x7f80ff00017f80ffUL ]
    let wanted = [ R5, 0x80ffUL ]
    oracle only64 "10a61f4d" given wanted

  /// <summary>
  /// vextuwrx rD, rA, vB writes into rD, zero-extended, the word of vB at the
  /// byte the low four bits of rA count from the right.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXTUWRX extracts a word indexed from the right``() =
    (* vextuwrx r5, r6, v3 *)
    let given =
      [ R6, 0x8000000000000000UL
        V3A, 0x7fff8000ffff0001UL
        V3B, 0x7f80ff00017f80ffUL ]
    let wanted = [ R5, 0x17f80ffUL ]
    oracle only64 "10a61f8d" given wanted

  /// <summary>
  /// vextdubvlx vD, vA, vB, rC writes into doubleword 0 of vD, zero-extended,
  /// the byte of the 32-byte vA || vB at the byte the low five bits of rC
  /// count from the left, and clears doubleword 1.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXTDUBVLX extracts a pair byte from the left``() =
    (* vextdubvlx v1, v2, v3, r9 *)
    let given =
      [ R9, 0x8000000000000000UL
        V2A, 0x7fff8000ffff0001UL
        V2B, 0x7f80ff00017f80ffUL
        V3A, 0x0001ffff80007fffUL
        V3B, 0x7f7f808001010000UL ]
    let wanted = [ V1A, 0x000000000000007fUL; V1B, 0x0000000000000000UL ]
    oracle only64 "10221a58" given wanted

  /// <summary>
  /// vextdubvrx vD, vA, vB, rC writes into doubleword 0 of vD, zero-extended,
  /// the byte of the 32-byte vA || vB at the byte the low five bits of rC
  /// count from the right, and clears doubleword 1.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXTDUBVRX extracts a pair byte from the right``() =
    (* vextdubvrx v1, v2, v3, r9 *)
    let given =
      [ R9, 0x7fffffffffffffffUL
        V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL
        V3A, 0x00000001ffffffffUL
        V3B, 0x7fffffff80000000UL ]
    let wanted = [ V1A, 0x000000000000007fUL; V1B, 0x0000000000000000UL ]
    oracle only64 "10221a59" given wanted

  /// <summary>
  /// vextduhvlx vD, vA, vB, rC writes into doubleword 0 of vD, zero-extended,
  /// the halfword of the 32-byte vA || vB at the byte the low five bits of rC
  /// count from the left, and clears doubleword 1.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXTDUHVLX extracts a pair halfword from the left``() =
    (* vextduhvlx v1, v2, v3, r9 *)
    let given =
      [ R9, 0x8000000000000000UL
        V2A, 0x7fff8000ffff0001UL
        V2B, 0x7f80ff00017f80ffUL
        V3A, 0x0001ffff80007fffUL
        V3B, 0x7f7f808001010000UL ]
    let wanted = [ V1A, 0x0000000000007fffUL; V1B, 0x0000000000000000UL ]
    oracle only64 "10221a5a" given wanted

  /// <summary>
  /// vextduhvrx vD, vA, vB, rC writes into doubleword 0 of vD, zero-extended,
  /// the halfword of the 32-byte vA || vB at the byte the low five bits of rC
  /// count from the right, and clears doubleword 1.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXTDUHVRX extracts a pair halfword from the right``() =
    (* vextduhvrx v1, v2, v3, r9 *)
    let given = [ V3A, 0xffffffffffffffffUL; V3B, 0xffffffffffffffffUL ]
    let wanted = [ V1A, 0x000000000000ffffUL; V1B, 0x0000000000000000UL ]
    oracle only64 "10221a5b" given wanted

  /// <summary>
  /// vextduwvlx vD, vA, vB, rC writes into doubleword 0 of vD, zero-extended,
  /// the word of the 32-byte vA || vB at the byte the low five bits of rC
  /// count from the left, and clears doubleword 1.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXTDUWVLX extracts a pair word from the left``() =
    (* vextduwvlx v1, v2, v3, r9 *)
    let given =
      [ R9, 0x8000000000000000UL
        V2A, 0x7fff8000ffff0001UL
        V2B, 0x7f80ff00017f80ffUL
        V3A, 0x0001ffff80007fffUL
        V3B, 0x7f7f808001010000UL ]
    let wanted = [ V1A, 0x000000007fff8000UL; V1B, 0x0000000000000000UL ]
    oracle only64 "10221a5c" given wanted

  /// <summary>
  /// vextduwvrx vD, vA, vB, rC writes into doubleword 0 of vD, zero-extended,
  /// the word of the 32-byte vA || vB at the byte the low five bits of rC
  /// count from the right, and clears doubleword 1.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXTDUWVRX extracts a pair word from the right``() =
    (* vextduwvrx v1, v2, v3, r9 *)
    let given =
      [ R9, 0x8000000000000000UL
        V2A, 0x7fff8000ffff0001UL
        V2B, 0x7f80ff00017f80ffUL
        V3A, 0x0001ffff80007fffUL
        V3B, 0x7f7f808001010000UL ]
    let wanted = [ V1A, 0x0000000001010000UL; V1B, 0x0000000000000000UL ]
    oracle only64 "10221a5d" given wanted

  /// <summary>
  /// vextddvlx vD, vA, vB, rC writes into doubleword 0 of vD, zero-extended,
  /// the doubleword of the 32-byte vA || vB at the byte the low five bits of
  /// rC count from the left, and clears doubleword 1.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXTDDVLX extracts a pair doubleword from the left``() =
    (* vextddvlx v1, v2, v3, r9 *)
    let given =
      [ R9, 0x8000000000000000UL
        V2A, 0x7fff8000ffff0001UL
        V2B, 0x7f80ff00017f80ffUL
        V3A, 0x0001ffff80007fffUL
        V3B, 0x7f7f808001010000UL ]
    let wanted = [ V1A, 0x7fff8000ffff0001UL; V1B, 0x0000000000000000UL ]
    oracle only64 "10221a5e" given wanted

  /// <summary>
  /// vextddvrx vD, vA, vB, rC writes into doubleword 0 of vD, zero-extended,
  /// the doubleword of the 32-byte vA || vB at the byte the low five bits of
  /// rC count from the right, and clears doubleword 1.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VEXTDDVRX extracts a pair doubleword from the right``() =
    (* vextddvrx v1, v2, v3, r9 *)
    let given =
      [ R9, 0x8000000000000000UL
        V2A, 0x7fff8000ffff0001UL
        V2B, 0x7f80ff00017f80ffUL
        V3A, 0x0001ffff80007fffUL
        V3B, 0x7f7f808001010000UL ]
    let wanted = [ V1A, 0x7f7f808001010000UL; V1B, 0x0000000000000000UL ]
    oracle only64 "10221a5f" given wanted

  /// <summary>
  /// vinsblx vD, rA, rB writes the low byte of rB over vD at the byte the low
  /// four bits of rA count from the left, keeping the rest of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VINSBLX inserts a general byte from the left``() =
    (* vinsblx v1, r6, r7 *)
    let given =
      [ R6, 0x7fffffffffffffffUL
        R7, 0x1UL
        V1A, 0x0bad0bad0bad0badUL
        V1B, 0x0bad0bad0bad0badUL ]
    let wanted = [ V1B, 0x0bad0bad0bad0b01UL ]
    oracle only64 "10263a0f" given wanted

  /// <summary>
  /// vinshlx vD, rA, rB writes the low halfword of rB over vD at the byte the
  /// low four bits of rA count from the left, keeping the rest of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VINSHLX inserts a general halfword from the left``() =
    (* vinshlx v1, r6, r7 *)
    let given =
      [ R6, 0x8000000000000000UL
        R7, 0xffffffffffffffffUL
        V1A, 0x0bad0bad0bad0badUL
        V1B, 0x0bad0bad0bad0badUL ]
    let wanted = [ V1A, 0xffff0bad0bad0badUL ]
    oracle only64 "10263a4f" given wanted

  /// <summary>
  /// vinswlx vD, rA, rB writes the low word of rB over vD at the byte the low
  /// four bits of rA count from the left, keeping the rest of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VINSWLX inserts a general word from the left``() =
    (* vinswlx v1, r6, r7 *)
    let given =
      [ R6, 0x5555555555555555UL
        R7, 0xaaaaaaaaaaaaaaaaUL
        V1A, 0x0bad0bad0bad0badUL
        V1B, 0x0bad0bad0bad0badUL ]
    let wanted = [ V1A, 0x0bad0bad0baaaaaaUL; V1B, 0xaaad0bad0bad0badUL ]
    oracle only64 "10263a8f" given wanted

  /// <summary>
  /// vinsdlx vD, rA, rB writes the low doubleword of rB over vD at the byte
  /// the low four bits of rA count from the left, keeping the rest of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VINSDLX inserts a general doubleword from the left``() =
    (* vinsdlx v1, r6, r7 *)
    let given =
      [ R6, 0x5555555555555555UL
        R7, 0xaaaaaaaaaaaaaaaaUL
        V1A, 0x0bad0bad0bad0badUL
        V1B, 0x0bad0bad0bad0badUL ]
    let wanted = [ V1A, 0x0bad0bad0baaaaaaUL; V1B, 0xaaaaaaaaaaad0badUL ]
    oracle only64 "10263acf" given wanted

  /// <summary>
  /// vinsbrx vD, rA, rB writes the low byte of rB over vD at the byte the low
  /// four bits of rA count from the right, keeping the rest of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VINSBRX inserts a general byte from the right``() =
    (* vinsbrx v1, r6, r7 *)
    let given =
      [ R6, 0x7fffffffffffffffUL
        R7, 0x1UL
        V1A, 0x0bad0bad0bad0badUL
        V1B, 0x0bad0bad0bad0badUL ]
    let wanted = [ V1A, 0x01ad0bad0bad0badUL ]
    oracle only64 "10263b0f" given wanted

  /// <summary>
  /// vinshrx vD, rA, rB writes the low halfword of rB over vD at the byte the
  /// low four bits of rA count from the right, keeping the rest of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VINSHRX inserts a general halfword from the right``() =
    (* vinshrx v1, r6, r7 *)
    let given =
      [ R6, 0x8000000000000000UL
        R7, 0xffffffffffffffffUL
        V1A, 0x0bad0bad0bad0badUL
        V1B, 0x0bad0bad0bad0badUL ]
    let wanted = [ V1B, 0x0bad0bad0badffffUL ]
    oracle only64 "10263b4f" given wanted

  /// <summary>
  /// vinswrx vD, rA, rB writes the low word of rB over vD at the byte the low
  /// four bits of rA count from the right, keeping the rest of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VINSWRX inserts a general word from the right``() =
    (* vinswrx v1, r6, r7 *)
    let given =
      [ R6, 0x5555555555555555UL
        R7, 0xaaaaaaaaaaaaaaaaUL
        V1A, 0x0bad0bad0bad0badUL
        V1B, 0x0bad0bad0bad0badUL ]
    let wanted = [ V1A, 0x0bad0bad0bad0baaUL; V1B, 0xaaaaaaad0bad0badUL ]
    oracle only64 "10263b8f" given wanted

  /// <summary>
  /// vinsdrx vD, rA, rB writes the low doubleword of rB over vD at the byte
  /// the low four bits of rA count from the right, keeping the rest of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VINSDRX inserts a general doubleword from the right``() =
    (* vinsdrx v1, r6, r7 *)
    let given =
      [ R6, 0x5555555555555555UL
        R7, 0xaaaaaaaaaaaaaaaaUL
        V1A, 0x0bad0bad0bad0badUL
        V1B, 0x0bad0bad0bad0badUL ]
    let wanted = [ V1A, 0x0bad0baaaaaaaaaaUL; V1B, 0xaaaaaaad0bad0badUL ]
    oracle only64 "10263bcf" given wanted

  /// <summary>
  /// vinsbvlx vD, rA, vB writes the low byte of doubleword 0 of vB over vD at
  /// the byte the low four bits of rA count from the left, keeping the rest
  /// of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VINSBVLX inserts a vector byte from the left``() =
    (* vinsbvlx v1, r6, v3 *)
    let given =
      [ R6, 0x7fffffffffffffffUL
        V1A, 0x0bad0bad0bad0badUL
        V1B, 0x0bad0bad0bad0badUL
        V3A, 0x7fffffff80000000UL
        V3B, 0xffffffff00000001UL ]
    let wanted = [ V1B, 0x0bad0bad0bad0b00UL ]
    oracle only64 "1026180f" given wanted

  /// <summary>
  /// vinshvlx vD, rA, vB writes the low halfword of doubleword 0 of vB over
  /// vD at the byte the low four bits of rA count from the left, keeping the
  /// rest of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VINSHVLX inserts a vector halfword from the left``() =
    (* vinshvlx v1, r6, v3 *)
    let given =
      [ R6, 0x8000000000000000UL
        V1A, 0x0bad0bad0bad0badUL
        V1B, 0x0bad0bad0bad0badUL
        V3A, 0x7fff8000ffff0001UL
        V3B, 0x7f80ff00017f80ffUL ]
    let wanted = [ V1A, 0x00010bad0bad0badUL ]
    oracle only64 "1026184f" given wanted

  /// <summary>
  /// vinswvlx vD, rA, vB writes the low word of doubleword 0 of vB over vD at
  /// the byte the low four bits of rA count from the left, keeping the rest
  /// of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VINSWVLX inserts a vector word from the left``() =
    (* vinswvlx v1, r6, v3 *)
    let given =
      [ R6, 0x5555555555555555UL
        V1A, 0x0bad0bad0bad0badUL
        V1B, 0x0bad0bad0bad0badUL
        V3A, 0x5555555555555555UL
        V3B, 0x5555555555555555UL ]
    let wanted = [ V1A, 0x0bad0bad0b555555UL; V1B, 0x55ad0bad0bad0badUL ]
    oracle only64 "1026188f" given wanted

  /// <summary>
  /// vinsbvrx vD, rA, vB writes the low byte of doubleword 0 of vB over vD at
  /// the byte the low four bits of rA count from the right, keeping the rest
  /// of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VINSBVRX inserts a vector byte from the right``() =
    (* vinsbvrx v1, r6, v3 *)
    let given =
      [ R6, 0x7fffffffffffffffUL
        V1A, 0x0bad0bad0bad0badUL
        V1B, 0x0bad0bad0bad0badUL
        V3A, 0x7fffffff80000000UL
        V3B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0x00ad0bad0bad0badUL ]
    oracle only64 "1026190f" given wanted

  /// <summary>
  /// vinshvrx vD, rA, vB writes the low halfword of doubleword 0 of vB over
  /// vD at the byte the low four bits of rA count from the right, keeping the
  /// rest of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VINSHVRX inserts a vector halfword from the right``() =
    (* vinshvrx v1, r6, v3 *)
    let given =
      [ R6, 0x8000000000000000UL
        V1A, 0x0bad0bad0bad0badUL
        V1B, 0x0bad0bad0bad0badUL
        V3A, 0x7fff8000ffff0001UL
        V3B, 0x7f80ff00017f80ffUL ]
    let wanted = [ V1B, 0x0bad0bad0bad0001UL ]
    oracle only64 "1026194f" given wanted

  /// <summary>
  /// vinswvrx vD, rA, vB writes the low word of doubleword 0 of vB over vD at
  /// the byte the low four bits of rA count from the right, keeping the rest
  /// of vD.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VINSWVRX inserts a vector word from the right``() =
    (* vinswvrx v1, r6, v3 *)
    let given =
      [ R6, 0x5555555555555555UL
        V1A, 0x0bad0bad0bad0badUL
        V1B, 0x0bad0bad0bad0badUL
        V3A, 0x5555555555555555UL
        V3B, 0x5555555555555555UL ]
    let wanted = [ V1A, 0x0bad0bad0bad0b55UL; V1B, 0x555555ad0bad0badUL ]
    oracle only64 "1026198f" given wanted

  /// <summary>
  /// vclrlb vD, vA, rB writes vA with all but its rightmost N bytes cleared,
  /// N being rB or 16 where rB is above 15.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCLRLB clears all but the rightmost bytes``() =
    (* vclrlb v1, v2, r7 *)
    let given =
      [ R7, 0x7fffffffffffffffUL
        V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0x7fffffff80000000UL; V1B, 0xffffffff00000001UL ]
    oracle only64 "1022398d" given wanted

  /// <summary>
  /// vclrrb vD, vA, rB writes vA with all but its leftmost N bytes cleared, N
  /// being rB or 16 where rB is above 15.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] VCLRRB clears all but the leftmost bytes``() =
    (* vclrrb v1, v2, r7 *)
    let given =
      [ R7, 0x7fffffffffffffffUL
        V2A, 0x7fffffff80000000UL
        V2B, 0xffffffff00000001UL ]
    let wanted = [ V1A, 0x7fffffff80000000UL; V1B, 0xffffffff00000001UL ]
    oracle only64 "102239cd" given wanted

  (* Lane X: VSX, MMA and quad precision. *)
  /// <summary>
  /// lxsibzx xT, rA, rB loads the byte at (rA|0) + rB, zero-extended, into
  /// doubleword 0 of xT, and clears doubleword 1. QEMU 8.2.2 leaves doubleword
  /// 1 as it was; the manual sets it to zero, and that is what is asserted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] LXSIBZX zero-extends a byte into doubleword 0``() =
    (* lxsibzx vs1,r6,r7, under QEMU: oracle results *)
    let window0 =
      [ 0x20200080UL, 0xb5f4465092da97e1UL; 0x20200088UL, 0xd62ed088b9fb3d92UL ]
    oracleMem
      ppc64
      "7c263e1a"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window0
      [ F1, 0xb5UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "7c263e1a"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window0
      [ F1, 0xb5UL; VSRL1, 0x0UL ]
      []

  /// <summary>
  /// lxsihzx xT, rA, rB loads the halfword at (rA|0) + rB in the guest's byte
  /// order, zero-extended, into doubleword 0 of xT, and clears doubleword 1.
  /// QEMU 8.2.2 leaves doubleword 1 as it was; the manual sets it to zero, and
  /// that is what is asserted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] LXSIHZX zero-extends a halfword into doubleword 0``() =
    (* lxsihzx vs1,r6,r7, under QEMU: oracle results *)
    let window0 =
      [ 0x20200080UL, 0x306bbe1ecaee3665UL; 0x20200088UL, 0xb92904fb95b35bacUL ]
    oracleMem
      ppc64
      "7c263e5a"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window0
      [ F1, 0x306bUL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "7c263e5a"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window0
      [ F1, 0x6b30UL; VSRL1, 0x0UL ]
      []

  /// <summary>
  /// lxsiwax xT, rA, rB loads the word at (rA|0) + rB in the guest's byte
  /// order, sign-extended, into doubleword 0 of xT, and clears doubleword 1:
  /// the first vector's word is negative on both byte orders, the second's
  /// positive. QEMU 8.2.2 leaves doubleword 1 as it was; the manual sets it to
  /// zero, and that is what is asserted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] LXSIWAX sign-extends a word into doubleword 0``() =
    (* lxsiwax vs1,r6,r7, under QEMU: oracle results *)
    let window0 =
      [ 0x20200080UL, 0xad0df3e829ef4201UL; 0x20200088UL, 0x39bd67a2030c75eUL ]
    let window1 =
      [ 0x20200080UL, 0x5643ad8df3393989UL; 0x20200088UL, 0x661bdd15e838a07dUL ]
    oracleMem
      ppc64
      "7c263898"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window0
      [ F1, 0xffffffffad0df3e8UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "7c263898"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window0
      [ F1, 0xffffffffe8f30dadUL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "7c263898"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window1
      [ F1, 0x5643ad8dUL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "7c263898"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window1
      [ F1, 0xffffffff8dad4356UL; VSRL1, 0x0UL ]
      []

  /// <summary>
  /// lxsiwzx xT, rA, rB loads the word at (rA|0) + rB in the guest's byte
  /// order, zero-extended, into doubleword 0 of xT, and clears doubleword 1.
  /// QEMU 8.2.2 leaves doubleword 1 as it was; the manual sets it to zero, and
  /// that is what is asserted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] LXSIWZX zero-extends a word into doubleword 0``() =
    (* lxsiwzx vs1,r6,r7, under QEMU: oracle results *)
    let window0 =
      [ 0x20200080UL, 0xa52a66012bf5f0d7UL; 0x20200088UL, 0x8e463b62f1e64b96UL ]
    oracleMem
      ppc64
      "7c263818"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window0
      [ F1, 0xa52a6601UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "7c263818"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window0
      [ F1, 0x1662aa5UL; VSRL1, 0x0UL ]
      []

  /// <summary>
  /// lxssp vRT, DS(rA) loads the single at (rA|0) + DS and places it in double
  /// format in doubleword 0 of VSR[vRT+32]; doubleword 1 is cleared. 1.5, the
  /// smallest denormal, a signalling NaN -- which stays signalling, its payload
  /// moved up -- and -Inf are each exact in double format.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] LXSSP widens a loaded single into doubleword 0``() =
    (* lxssp v1,8(r6), under QEMU: lanes/x-oracle/loads, oracle results *)
    let window0 =
      [ 0x20200080UL, 0x3fc000007ec2bb6bUL; 0x20200088UL, 0x85f307d07b4cabf9UL ]
    let window0le =
      [ 0x20200080UL, 0xc03f7ec2bb6bUL; 0x20200088UL, 0x85f307d07b4cabf9UL ]
    let window1 =
      [ 0x20200080UL, 0x1645f28ecUL; 0x20200088UL, 0x71ff843b920d0cddUL ]
    let window1le =
      [ 0x20200080UL, 0x1000000645f28ecUL; 0x20200088UL, 0x71ff843b920d0cddUL ]
    let window2 =
      [ 0x20200080UL, 0x7f800001bc68cf7fUL; 0x20200088UL, 0x442c7c732f4bbdf8UL ]
    let window2le =
      [ 0x20200080UL, 0x100807fbc68cf7fUL; 0x20200088UL, 0x442c7c732f4bbdf8UL ]
    let window3 =
      [ 0x20200080UL, 0xff8000002c049d2fUL; 0x20200088UL, 0xe71b758877ec3210UL ]
    let window3le =
      [ 0x20200080UL, 0x80ff2c049d2fUL; 0x20200088UL, 0xe71b758877ec3210UL ]
    let window4 =
      [ 0x20200080UL, 0xfd615ab67ec2bb6bUL; 0x20200088UL, 0x85f307d07b4cabf9UL ]
    oracleMem
      ppc64
      "e426000b"
      [ R6, 0x20200078UL; V1A, 0xbad0bad0bad0badUL; V1B, 0xbad0bad0bad0badUL ]
      window0
      [ V1A, 0x3ff8000000000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "e426000b"
      [ R6, 0x20200078UL; V1A, 0xbad0bad0bad0badUL; V1B, 0xbad0bad0bad0badUL ]
      window0le
      [ V1A, 0x3ff8000000000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64
      "e426000b"
      [ R6, 0x20200078UL; V1A, 0xbad0bad0bad0badUL; V1B, 0xbad0bad0bad0badUL ]
      window1
      [ V1A, 0x36a0000000000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "e426000b"
      [ R6, 0x20200078UL; V1A, 0xbad0bad0bad0badUL; V1B, 0xbad0bad0bad0badUL ]
      window1le
      [ V1A, 0x36a0000000000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64
      "e426000b"
      [ R6, 0x20200078UL; V1A, 0xbad0bad0bad0badUL; V1B, 0xbad0bad0bad0badUL ]
      window2
      [ V1A, 0x7ff0000020000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "e426000b"
      [ R6, 0x20200078UL; V1A, 0xbad0bad0bad0badUL; V1B, 0xbad0bad0bad0badUL ]
      window2le
      [ V1A, 0x7ff0000020000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64
      "e426000b"
      [ R6, 0x20200078UL; V1A, 0xbad0bad0bad0badUL; V1B, 0xbad0bad0bad0badUL ]
      window3
      [ V1A, 0xfff0000000000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "e426000b"
      [ R6, 0x20200078UL; V1A, 0xbad0bad0bad0badUL; V1B, 0xbad0bad0bad0badUL ]
      window3le
      [ V1A, 0xfff0000000000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64
      "e426000b"
      [ R6, 0x20200078UL; V1A, 0xbad0bad0bad0badUL; V1B, 0xbad0bad0bad0badUL ]
      window4
      [ V1A, 0xc7ac2b56c0000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "e426000b"
      [ R6, 0x20200078UL; V1A, 0xbad0bad0bad0badUL; V1B, 0xbad0bad0bad0badUL ]
      window4
      [ V1A, 0xbecb4c3fa0000000UL; V1B, 0x0UL ]
      []

  /// <summary>
  /// lxsspx xT, rA, rB loads the single at (rA|0) + rB and places it in double
  /// format in doubleword 0 of xT, as lxssp does; doubleword 1 is cleared. QEMU
  /// 8.2.2 leaves doubleword 1 as it was; the manual sets it to zero, and that
  /// is what is asserted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] LXSSPX widens a loaded single into doubleword 0``() =
    (* lxsspx vs1,r6,r7, under QEMU: lanes/x-oracle/loads, oracle results *)
    let window0 =
      [ 0x20200080UL, 0x3fc0000047e8c26fUL; 0x20200088UL, 0xdd1f7b578b36893bUL ]
    let window0le =
      [ 0x20200080UL, 0xc03f47e8c26fUL; 0x20200088UL, 0xdd1f7b578b36893bUL ]
    let window1 =
      [ 0x20200080UL, 0x1d3f5b1d5UL; 0x20200088UL, 0x2094417605d1ea0eUL ]
    let window1le =
      [ 0x20200080UL, 0x1000000d3f5b1d5UL; 0x20200088UL, 0x2094417605d1ea0eUL ]
    let window2 =
      [ 0x20200080UL, 0x7f800001637811edUL; 0x20200088UL, 0x70783111ad441073UL ]
    let window2le =
      [ 0x20200080UL, 0x100807f637811edUL; 0x20200088UL, 0x70783111ad441073UL ]
    let window3 =
      [ 0x20200080UL, 0xff800000e558224dUL; 0x20200088UL, 0xd25af19b3ea16566UL ]
    let window3le =
      [ 0x20200080UL, 0x80ffe558224dUL; 0x20200088UL, 0xd25af19b3ea16566UL ]
    let window4 =
      [ 0x20200080UL, 0x973adcb347e8c26fUL; 0x20200088UL, 0xdd1f7b578b36893bUL ]
    oracleMem
      ppc64
      "7c263c18"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window0
      [ F1, 0x3ff8000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "7c263c18"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window0le
      [ F1, 0x3ff8000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "7c263c18"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window1
      [ F1, 0x36a0000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "7c263c18"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window1le
      [ F1, 0x36a0000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "7c263c18"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window2
      [ F1, 0x7ff0000020000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "7c263c18"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window2le
      [ F1, 0x7ff0000020000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "7c263c18"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window3
      [ F1, 0xfff0000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "7c263c18"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window3le
      [ F1, 0xfff0000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "7c263c18"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window4
      [ F1, 0xbae75b9660000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "7c263c18"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window4
      [ F1, 0xbe7b8752e0000000UL; VSRL1, 0x0UL ]
      []

  /// <summary>
  /// lxv xT, DQ(rA) loads the 16 bytes at (rA|0) + DQ into xT: byte element 0
  /// from the lowest address on a big-endian guest, from the highest on a
  /// little-endian one, where the whole quadword's byte order reverses.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] LXV loads a quadword in the guest's byte order``() =
    (* lxv vs1,16(r6), under QEMU: oracle results *)
    let window0 =
      [ 0x20200080UL, 0x35bcc3b73e493e1aUL; 0x20200088UL, 0x49f3bab35a85e6aUL ]
    oracleMem
      ppc64
      "f4260011"
      [ R6, 0x20200070UL; F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      window0
      [ F1, 0x35bcc3b73e493e1aUL; VSRL1, 0x49f3bab35a85e6aUL ]
      []
    oracleMem
      ppc64le
      "f4260011"
      [ R6, 0x20200070UL; F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      window0
      [ F1, 0x6a5ea835ab3b9f04UL; VSRL1, 0x1a3e493eb7c3bc35UL ]
      []

  /// <summary>
  /// lxvx xT, rA, rB loads the 16 bytes at (rA|0) + rB into xT as lxv does, the
  /// whole quadword's byte order following the guest's.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] LXVX loads a quadword in the guest's byte order``() =
    (* lxvx vs1,r6,r7, under QEMU: oracle results *)
    let window0 =
      [ 0x20200080UL, 0x24b691845c55adedUL; 0x20200088UL, 0xd68da397af749583UL ]
    oracleMem
      ppc64
      "7c263a18"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window0
      [ F1, 0x24b691845c55adedUL; VSRL1, 0xd68da397af749583UL ]
      []
    oracleMem
      ppc64le
      "7c263a18"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window0
      [ F1, 0x839574af97a38dd6UL; VSRL1, 0xedad555c8491b624UL ]
      []

  /// <summary>
  /// lxvb16x xT, rA, rB loads byte element i of xT from (rA|0) + rB + i, so a
  /// little-endian guest sees the same register as a big-endian one.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] LXVB16X loads bytes in address order``() =
    (* lxvb16x vs1,r6,r7, under QEMU: oracle results *)
    let window0 =
      [ 0x20200080UL, 0x88548c15dd98a4e4UL; 0x20200088UL, 0xcc54338e39091045UL ]
    oracleMem
      ppc64
      "7c263ed8"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window0
      [ F1, 0x88548c15dd98a4e4UL; VSRL1, 0xcc54338e39091045UL ]
      []
    oracleMem
      ppc64le
      "7c263ed8"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window0
      [ F1, 0x88548c15dd98a4e4UL; VSRL1, 0xcc54338e39091045UL ]
      []

  /// <summary>
  /// lxvh8x xT, rA, rB loads halfword element i of xT from (rA|0) + rB + 2i,
  /// each halfword in the guest's byte order but the elements in address order.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] LXVH8X loads eight halfwords in address order``() =
    (* lxvh8x vs1,r6,r7, under QEMU: oracle results *)
    let window0 =
      [ 0x20200080UL, 0xb6e52d821a62e7f8UL; 0x20200088UL, 0x2833ca77689ad46dUL ]
    oracleMem
      ppc64
      "7c263e58"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window0
      [ F1, 0xb6e52d821a62e7f8UL; VSRL1, 0x2833ca77689ad46dUL ]
      []
    oracleMem
      ppc64le
      "7c263e58"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window0
      [ F1, 0xe5b6822d621af8e7UL; VSRL1, 0x332877ca9a686dd4UL ]
      []

  /// <summary>
  /// lxvkq xT, UIM places the quad-precision constant UIM names in xT: 1.0 to
  /// 7.0, +Inf and the default quiet NaN for UIM 1 to 9, -0.0, -1.0 to -7.0 and
  /// -Inf for UIM 16 to 24.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] LXVKQ loads every quad-precision constant``() =
    (* lxvkq vs1,1, under QEMU: lanes/x-oracle/loads *)
    oracleMem
      ppc64
      "f03f0ad0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0x3fff000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f03f0ad0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0x3fff000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "f03f12d0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0x4000000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f03f12d0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0x4000000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "f03f1ad0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0x4000800000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f03f1ad0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0x4000800000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "f03f22d0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0x4001000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f03f22d0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0x4001000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "f03f2ad0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0x4001400000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f03f2ad0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0x4001400000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "f03f32d0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0x4001800000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f03f32d0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0x4001800000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "f03f3ad0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0x4001c00000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f03f3ad0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0x4001c00000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "f03f42d0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0x7fff000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f03f42d0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0x7fff000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "f03f4ad0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0x7fff800000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f03f4ad0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0x7fff800000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "f03f82d0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0x8000000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f03f82d0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0x8000000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "f03f8ad0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0xbfff000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f03f8ad0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0xbfff000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "f03f92d0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0xc000000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f03f92d0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0xc000000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "f03f9ad0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0xc000800000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f03f9ad0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0xc000800000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "f03fa2d0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0xc001000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f03fa2d0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0xc001000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "f03faad0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0xc001400000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f03faad0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0xc001400000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "f03fb2d0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0xc001800000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f03fb2d0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0xc001800000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "f03fbad0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0xc001c00000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f03fbad0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0xc001c00000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "f03fc2d0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0xffff000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f03fc2d0"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0xffff000000000000UL; VSRL1, 0x0UL ]
      []

  /// <summary>
  /// lxvl xT, rA, rB loads nb bytes at (rA|0), nb being the top byte of rB --
  /// 16, 5 and 0 here -- into the left of xT on a big-endian guest and, byte
  /// order reversed, into the right of it on a little-endian one, clearing the
  /// rest; with nb 0 nothing is read and xT is cleared.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] LXVL loads as many bytes as the top byte of rB says``() =
    (* lxvl vs1,r6,r7, under QEMU: oracle results *)
    let window0 =
      [ 0x20200080UL, 0x972d9a9234764059UL; 0x20200088UL, 0x8868c68b1f6b9211UL ]
    let window1 =
      [ 0x20200080UL, 0xf23ee32ab99d0d70UL; 0x20200088UL, 0xcfb04a4926ffef0fUL ]
    let window2 =
      [ 0x20200080UL, 0x13a574af0fe1fd2UL; 0x20200088UL, 0x60db17b53ab9a3b9UL ]
    oracleMem
      ppc64
      "7c263a1a"
      [ R6, 0x20200080UL
        R7, 0x1000000000000000UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window0
      [ F1, 0x972d9a9234764059UL; VSRL1, 0x8868c68b1f6b9211UL ]
      []
    oracleMem
      ppc64le
      "7c263a1a"
      [ R6, 0x20200080UL
        R7, 0x1000000000000000UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window0
      [ F1, 0x11926b1f8bc66888UL; VSRL1, 0x59407634929a2d97UL ]
      []
    oracleMem
      ppc64
      "7c263a1a"
      [ R6, 0x20200080UL
        R7, 0x500000000000000UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window1
      [ F1, 0xf23ee32ab9000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "7c263a1a"
      [ R6, 0x20200080UL
        R7, 0x500000000000000UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window1
      [ F1, 0x0UL; VSRL1, 0xb92ae33ef2UL ]
      []
    oracleMem
      ppc64
      "7c263a1a"
      [ R6, 0x20200080UL; F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      window2
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "7c263a1a"
      [ R6, 0x20200080UL; F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL ]
      window2
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []

  /// <summary>
  /// lxvll xT, rA, rB loads nb bytes at (rA|0), nb being the top byte of rB and
  /// at most 16 (16, 5 and 17 here), into byte elements 0 to nb-1 in address
  /// order whatever the guest's byte order, clearing the rest.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] LXVLL loads nb bytes left-justified on either guest``() =
    (* lxvll vs1,r6,r7, under QEMU: oracle results *)
    let window0 =
      [ 0x20200080UL, 0xfd1750a6f4c3e33dUL; 0x20200088UL, 0xeb87514450a9ef2fUL ]
    let window1 =
      [ 0x20200080UL, 0x1948c01cfb8a909fUL; 0x20200088UL, 0xe088f31510d06591UL ]
    let window2 =
      [ 0x20200080UL, 0x494ee7cd6905804bUL; 0x20200088UL, 0xf0b91d2ce1832eebUL ]
    oracleMem
      ppc64
      "7c263a5a"
      [ R6, 0x20200080UL
        R7, 0x1000000000000000UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window0
      [ F1, 0xfd1750a6f4c3e33dUL; VSRL1, 0xeb87514450a9ef2fUL ]
      []
    oracleMem
      ppc64le
      "7c263a5a"
      [ R6, 0x20200080UL
        R7, 0x1000000000000000UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window0
      [ F1, 0xfd1750a6f4c3e33dUL; VSRL1, 0xeb87514450a9ef2fUL ]
      []
    oracleMem
      ppc64
      "7c263a5a"
      [ R6, 0x20200080UL
        R7, 0x500000000000000UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window1
      [ F1, 0x1948c01cfb000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "7c263a5a"
      [ R6, 0x20200080UL
        R7, 0x500000000000000UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window1
      [ F1, 0x1948c01cfb000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "7c263a5a"
      [ R6, 0x20200080UL
        R7, 0x1100000000000000UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window2
      [ F1, 0x494ee7cd6905804bUL; VSRL1, 0xf0b91d2ce1832eebUL ]
      []
    oracleMem
      ppc64le
      "7c263a5a"
      [ R6, 0x20200080UL
        R7, 0x1100000000000000UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window2
      [ F1, 0x494ee7cd6905804bUL; VSRL1, 0xf0b91d2ce1832eebUL ]
      []

  /// <summary>
  /// lxvp xTp, DQ(rA) loads the 32 bytes at (rA|0) + DQ into xTp and xTp+1. The
  /// 32 bytes are one octword, so on a little-endian guest xTp takes the upper
  /// 16 bytes, byte-reversed, and xTp+1 the lower.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] LXVP loads a register pair``() =
    (* lxvp vs2,16(r6), under QEMU: oracle results *)
    let window0 =
      [ 0x20200080UL, 0x6d876f514fc010cfUL
        0x20200088UL, 0x847d288916f5b7d5UL
        0x20200090UL, 0xe78099546887fbe0UL
        0x20200098UL, 0x66b7f133b4d68f0UL ]
    oracleMem
      ppc64
      "18460010"
      [ R6, 0x20200070UL; F2, 0xbad0bad0bad0badUL; VSRL2, 0xbad0bad0bad0badUL ]
      window0
      [ F2, 0x6d876f514fc010cfUL
        F3, 0xe78099546887fbe0UL
        VSRL2, 0x847d288916f5b7d5UL
        VSRL3, 0x66b7f133b4d68f0UL ]
      []
    oracleMem
      ppc64le
      "18460010"
      [ R6, 0x20200070UL; F2, 0xbad0bad0bad0badUL; VSRL2, 0xbad0bad0bad0badUL ]
      window0
      [ F2, 0xf0684d3b137f6b06UL
        F3, 0xd5b7f51689287d84UL
        VSRL2, 0xe0fb8768549980e7UL
        VSRL3, 0xcf10c04f516f876dUL ]
      []

  /// <summary>
  /// lxvpx xTp, rA, rB loads the 32 bytes at (rA|0) + rB into xTp and xTp+1, as
  /// lxvp does.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] LXVPX loads a register pair``() =
    (* lxvpx vs2,r6,r7, under QEMU: oracle results *)
    let window0 =
      [ 0x20200080UL, 0x64bc7d77bae33378UL
        0x20200088UL, 0x4ae77049973271d6UL
        0x20200090UL, 0xe7bddfc3d0debac0UL
        0x20200098UL, 0xf8f8a0a3a15acfc2UL ]
    oracleMem
      ppc64
      "7c463a9a"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F2, 0xbad0bad0bad0badUL
        VSRL2, 0xbad0bad0bad0badUL ]
      window0
      [ F2, 0x64bc7d77bae33378UL
        F3, 0xe7bddfc3d0debac0UL
        VSRL2, 0x4ae77049973271d6UL
        VSRL3, 0xf8f8a0a3a15acfc2UL ]
      []
    oracleMem
      ppc64le
      "7c463a9a"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F2, 0xbad0bad0bad0badUL
        VSRL2, 0xbad0bad0bad0badUL ]
      window0
      [ F2, 0xc2cf5aa1a3a0f8f8UL
        F3, 0xd67132974970e74aUL
        VSRL2, 0xc0baded0c3dfbde7UL
        VSRL3, 0x7833e3ba777dbc64UL ]
      []

  /// <summary>
  /// lxvrbx xT, rA, rB loads the byte at (rA|0) + rB into byte element 15 of xT
  /// and clears the rest.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] LXVRBX loads a byte into the rightmost element``() =
    (* lxvrbx vs1,r6,r7, under QEMU: oracle results *)
    let window0 =
      [ 0x20200080UL, 0xa461fd807f299624UL; 0x20200088UL, 0x2c4263d2ba55889UL ]
    oracleMem
      ppc64
      "7c26381a"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window0
      [ F1, 0x0UL; VSRL1, 0xa4UL ]
      []
    oracleMem
      ppc64le
      "7c26381a"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window0
      [ F1, 0x0UL; VSRL1, 0xa4UL ]
      []

  /// <summary>
  /// lxvrhx xT, rA, rB loads the halfword at (rA|0) + rB, in the guest's byte
  /// order, into halfword element 7 of xT and clears the rest.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] LXVRHX loads a halfword into the rightmost element``() =
    (* lxvrhx vs1,r6,r7, under QEMU: oracle results *)
    let window0 =
      [ 0x20200080UL, 0x5d9125101fb99971UL; 0x20200088UL, 0xa714605a5a35f6cUL ]
    oracleMem
      ppc64
      "7c26385a"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window0
      [ F1, 0x0UL; VSRL1, 0x5d91UL ]
      []
    oracleMem
      ppc64le
      "7c26385a"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window0
      [ F1, 0x0UL; VSRL1, 0x915dUL ]
      []

  /// <summary>
  /// lxvrwx xT, rA, rB loads the word at (rA|0) + rB, in the guest's byte
  /// order, into word element 3 of xT and clears the rest.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] LXVRWX loads a word into the rightmost element``() =
    (* lxvrwx vs1,r6,r7, under QEMU: oracle results *)
    let window0 =
      [ 0x20200080UL, 0x54c388f4d3935752UL; 0x20200088UL, 0xb52f82be75a01116UL ]
    oracleMem
      ppc64
      "7c26389a"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window0
      [ F1, 0x0UL; VSRL1, 0x54c388f4UL ]
      []
    oracleMem
      ppc64le
      "7c26389a"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window0
      [ F1, 0x0UL; VSRL1, 0xf488c354UL ]
      []

  /// <summary>
  /// lxvrdx xT, rA, rB loads the doubleword at (rA|0) + rB, in the guest's byte
  /// order, into doubleword element 1 of xT and clears doubleword 0.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] LXVRDX loads a doubleword into the rightmost element``() =
    (* lxvrdx vs1,r6,r7, under QEMU: oracle results *)
    let window0 =
      [ 0x20200080UL, 0x1ec7bae3110e7a3eUL; 0x20200088UL, 0x51a78d4cf3f5d74UL ]
    oracleMem
      ppc64
      "7c2638da"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window0
      [ F1, 0x0UL; VSRL1, 0x1ec7bae3110e7a3eUL ]
      []
    oracleMem
      ppc64le
      "7c2638da"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window0
      [ F1, 0x0UL; VSRL1, 0x3e7a0e11e3bac71eUL ]
      []

  /// <summary>
  /// lxvwsx xT, rA, rB loads the word at (rA|0) + rB, in the guest's byte
  /// order, into all four word elements of xT.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] LXVWSX splats a loaded word``() =
    (* lxvwsx vs1,r6,r7, under QEMU: oracle results *)
    let window0 =
      [ 0x20200080UL, 0xbdaf0774cc2aa342UL; 0x20200088UL, 0x10d3f5c9d6997399UL ]
    oracleMem
      ppc64
      "7c263ad8"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window0
      [ F1, 0xbdaf0774bdaf0774UL; VSRL1, 0xbdaf0774bdaf0774UL ]
      []
    oracleMem
      ppc64le
      "7c263ad8"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      window0
      [ F1, 0x7407afbd7407afbdUL; VSRL1, 0x7407afbd7407afbdUL ]
      []

  /// <summary>
  /// mtvsrws xT, rA places the low word of rA in all four word elements of xT,
  /// whatever the high word holds.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] MTVSRWS splats the low word of a general register``() =
    (* mtvsrws vs1,r6, under QEMU: oracle results *)
    oracleMem
      ppc64
      "7c260326"
      [ R6, 0x3UL; F1, 0x1020304050607UL; VSRL1, 0x8090a0b0c0d0e0fUL ]
      []
      [ F1, 0x300000003UL; VSRL1, 0x300000003UL ]
      []
    oracleMem
      ppc64le
      "7c260326"
      [ R6, 0x3UL; F1, 0x1020304050607UL; VSRL1, 0x8090a0b0c0d0e0fUL ]
      []
      [ F1, 0x300000003UL; VSRL1, 0x300000003UL ]
      []
    oracleMem
      ppc64
      "7c260326"
      [ R6, 0x7fffffffffffffffUL
        F1, 0x7fffffff80000000UL
        VSRL1, 0xffffffff00000001UL ]
      []
      [ F1, 0xffffffffffffffffUL; VSRL1, 0xffffffffffffffffUL ]
      []
    oracleMem
      ppc64le
      "7c260326"
      [ R6, 0x7fffffffffffffffUL
        F1, 0x7fffffff80000000UL
        VSRL1, 0xffffffff00000001UL ]
      []
      [ F1, 0xffffffffffffffffUL; VSRL1, 0xffffffffffffffffUL ]
      []

  /// <summary>
  /// stxsibx xS, rA, rB stores byte element 7 of xS, the low byte of doubleword
  /// 0, at (rA|0) + rB, and nothing else.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] STXSIBX stores byte element 7``() =
    (* stxsibx vs1,r6,r7, under QEMU: oracle results *)
    let window0 =
      [ 0x20200080UL, 0x68989f228f3eec3dUL; 0x20200088UL, 0xead16be809902a38UL ]
    oracleMem
      ppc64
      "7c263f1a"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0x1020304050607UL
        VSRL1, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0x7989f228f3eec3dUL ]
    oracleMem
      ppc64le
      "7c263f1a"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0x1020304050607UL
        VSRL1, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0x7989f228f3eec3dUL ]

  /// <summary>
  /// stxsihx xS, rA, rB stores halfword element 3 of xS, the low halfword of
  /// doubleword 0, at (rA|0) + rB in the guest's byte order.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] STXSIHX stores halfword element 3``() =
    (* stxsihx vs1,r6,r7, under QEMU: oracle results *)
    let window0 =
      [ 0x20200080UL, 0xe0623307896f70c0UL; 0x20200088UL, 0xd0370f89ca05ca70UL ]
    oracleMem
      ppc64
      "7c263f5a"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0x1020304050607UL
        VSRL1, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0x6073307896f70c0UL ]
    oracleMem
      ppc64le
      "7c263f5a"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0x1020304050607UL
        VSRL1, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0x7063307896f70c0UL ]

  /// <summary>
  /// stxsiwx xS, rA, rB stores word element 1 of xS, the low word of doubleword
  /// 0, at (rA|0) + rB in the guest's byte order.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] STXSIWX stores word element 1``() =
    (* stxsiwx vs1,r6,r7, under QEMU: oracle results *)
    let window0 =
      [ 0x20200080UL, 0xbfc9a6692fb286dUL; 0x20200088UL, 0x4089a12626c46baeUL ]
    oracleMem
      ppc64
      "7c263918"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0x1020304050607UL
        VSRL1, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0x405060792fb286dUL ]
    oracleMem
      ppc64le
      "7c263918"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0x1020304050607UL
        VSRL1, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0x706050492fb286dUL ]

  /// <summary>
  /// stxssp vRS, DS(rA) stores the double in doubleword 0 of VSR[vRS+32] as a
  /// single at (rA|0) + DS, by the conversion that does not round: 1.5, the
  /// largest negative single, the smallest normal and the smallest denormal
  /// single, +Inf, a signalling and a quiet NaN (each keeping its payload's top
  /// bits) and -0. The conversion is undefined for a double no single
  /// represents, which no vector here holds.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] STXSSP stores doubleword 0 as a single``() =
    (* stxssp v1,8(r6), under QEMU: lanes/x-oracle/loads, oracle results *)
    let window0 =
      [ 0x20200080UL, 0xe5a5735e3a5695e5UL; 0x20200088UL, 0xa2cf6ece05b481bUL ]
    let window1 =
      [ 0x20200080UL, 0x9b9ac4b4dadd63e5UL; 0x20200088UL, 0x8bb0d6dfbf01d233UL ]
    let window2 =
      [ 0x20200080UL, 0x34774e899912ffe0UL; 0x20200088UL, 0xc33d8bc8462672abUL ]
    let window3 =
      [ 0x20200080UL, 0xe82106bbd067956cUL; 0x20200088UL, 0x1123cfe364027b07UL ]
    let window4 =
      [ 0x20200080UL, 0x870c0fe12dcbfa4UL; 0x20200088UL, 0xa2f4b0d4840d1d70UL ]
    let window5 =
      [ 0x20200080UL, 0xcbabe3dd103c736bUL; 0x20200088UL, 0x868e7c6eaf15d3f4UL ]
    let window6 =
      [ 0x20200080UL, 0x9b9ac4b4dadd63e5UL; 0x20200088UL, 0x8bb0d6dfbf01d233UL ]
    let window7 =
      [ 0x20200080UL, 0x903f351ed3aee222UL; 0x20200088UL, 0x8f27381507713064UL ]
    oracleMem
      ppc64
      "f426000b"
      [ R6, 0x20200078UL; V1A, 0x3ff8000000000000UL; V1B, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0x3fc000003a5695e5UL ]
    oracleMem
      ppc64le
      "f426000b"
      [ R6, 0x20200078UL; V1A, 0x3ff8000000000000UL; V1B, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0xc03f3a5695e5UL ]
    oracleMem
      ppc64
      "f426000b"
      [ R6, 0x20200078UL; V1A, 0xc7efffffe0000000UL; V1B, 0xffffffff00000001UL ]
      window1
      []
      [ 0x20200080UL, 0xff7fffffdadd63e5UL ]
    oracleMem
      ppc64le
      "f426000b"
      [ R6, 0x20200078UL; V1A, 0xc7efffffe0000000UL; V1B, 0xffffffff00000001UL ]
      window1
      []
      [ 0x20200080UL, 0xffff7fffdadd63e5UL ]
    oracleMem
      ppc64
      "f426000b"
      [ R6, 0x20200078UL; V1A, 0x3810000000000000UL; V1B, 0x7f80ff00017f80ffUL ]
      window2
      []
      [ 0x20200080UL, 0x8000009912ffe0UL ]
    oracleMem
      ppc64le
      "f426000b"
      [ R6, 0x20200078UL; V1A, 0x3810000000000000UL; V1B, 0x7f80ff00017f80ffUL ]
      window2
      []
      [ 0x20200080UL, 0x80009912ffe0UL ]
    oracleMem
      ppc64
      "f426000b"
      [ R6, 0x20200078UL; V1A, 0x36a0000000000000UL ]
      window3
      []
      [ 0x20200080UL, 0x1d067956cUL ]
    oracleMem
      ppc64le
      "f426000b"
      [ R6, 0x20200078UL; V1A, 0x36a0000000000000UL ]
      window3
      []
      [ 0x20200080UL, 0x1000000d067956cUL ]
    oracleMem
      ppc64
      "f426000b"
      [ R6, 0x20200078UL; V1A, 0x7ff0000000000000UL; V1B, 0x5555555555555555UL ]
      window4
      []
      [ 0x20200080UL, 0x7f80000012dcbfa4UL ]
    oracleMem
      ppc64le
      "f426000b"
      [ R6, 0x20200078UL; V1A, 0x7ff0000000000000UL; V1B, 0x5555555555555555UL ]
      window4
      []
      [ 0x20200080UL, 0x807f12dcbfa4UL ]
    oracleMem
      ppc64
      "f426000b"
      [ R6, 0x20200078UL; V1A, 0x7ff4000000000000UL; V1B, 0xfedcba9876543210UL ]
      window5
      []
      [ 0x20200080UL, 0x7fa00000103c736bUL ]
    oracleMem
      ppc64le
      "f426000b"
      [ R6, 0x20200078UL; V1A, 0x7ff4000000000000UL; V1B, 0xfedcba9876543210UL ]
      window5
      []
      [ 0x20200080UL, 0xa07f103c736bUL ]
    oracleMem
      ppc64
      "f426000b"
      [ R6, 0x20200078UL; V1A, 0x7fffffff80000000UL; V1B, 0xffffffff00000001UL ]
      window6
      []
      [ 0x20200080UL, 0x7ffffffcdadd63e5UL ]
    oracleMem
      ppc64le
      "f426000b"
      [ R6, 0x20200078UL; V1A, 0x7fffffff80000000UL; V1B, 0xffffffff00000001UL ]
      window6
      []
      [ 0x20200080UL, 0xfcffff7fdadd63e5UL ]
    oracleMem
      ppc64
      "f426000b"
      [ R6, 0x20200078UL; V1A, 0x8000000000000000UL ]
      window7
      []
      [ 0x20200080UL, 0x80000000d3aee222UL ]
    oracleMem
      ppc64le
      "f426000b"
      [ R6, 0x20200078UL; V1A, 0x8000000000000000UL ]
      window7
      []
      [ 0x20200080UL, 0x80d3aee222UL ]

  /// <summary>
  /// stxsspx xS, rA, rB stores the double in doubleword 0 of xS as a single at
  /// (rA|0) + rB, by the same conversion as stxssp, over the same values.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] STXSSPX stores doubleword 0 as a single``() =
    (* stxsspx vs1,r6,r7, under QEMU: lanes/x-oracle/loads, oracle results *)
    let window0 =
      [ 0x20200080UL, 0x3bd0532e3744dcbdUL; 0x20200088UL, 0x943f6551b210af78UL ]
    let window1 =
      [ 0x20200080UL, 0x8ba96a5167c8d38fUL; 0x20200088UL, 0xa83b3b0802c834c3UL ]
    let window2 =
      [ 0x20200080UL, 0xa16a35ffbdaad07eUL; 0x20200088UL, 0x21abc7c227e7f2f4UL ]
    let window3 =
      [ 0x20200080UL, 0xc947245ed88760e7UL; 0x20200088UL, 0x9517d63cf22f7e2bUL ]
    let window4 =
      [ 0x20200080UL, 0x45a84ba5fd500fadUL; 0x20200088UL, 0x212c603358a88f30UL ]
    let window5 =
      [ 0x20200080UL, 0x27302b952302735eUL; 0x20200088UL, 0xfa695644f158cb7bUL ]
    let window6 =
      [ 0x20200080UL, 0x8ba96a5167c8d38fUL; 0x20200088UL, 0xa83b3b0802c834c3UL ]
    let window7 =
      [ 0x20200080UL, 0x3234b914c6d5e977UL; 0x20200088UL, 0x20b5ec532bc78f4UL ]
    oracleMem
      ppc64
      "7c263d18"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0x3ff8000000000000UL
        VSRL1, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0x3fc000003744dcbdUL ]
    oracleMem
      ppc64le
      "7c263d18"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0x3ff8000000000000UL
        VSRL1, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0xc03f3744dcbdUL ]
    oracleMem
      ppc64
      "7c263d18"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xc7efffffe0000000UL
        VSRL1, 0xffffffff00000001UL ]
      window1
      []
      [ 0x20200080UL, 0xff7fffff67c8d38fUL ]
    oracleMem
      ppc64le
      "7c263d18"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0xc7efffffe0000000UL
        VSRL1, 0xffffffff00000001UL ]
      window1
      []
      [ 0x20200080UL, 0xffff7fff67c8d38fUL ]
    oracleMem
      ppc64
      "7c263d18"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0x3810000000000000UL
        VSRL1, 0x7f80ff00017f80ffUL ]
      window2
      []
      [ 0x20200080UL, 0x800000bdaad07eUL ]
    oracleMem
      ppc64le
      "7c263d18"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0x3810000000000000UL
        VSRL1, 0x7f80ff00017f80ffUL ]
      window2
      []
      [ 0x20200080UL, 0x8000bdaad07eUL ]
    oracleMem
      ppc64
      "7c263d18"
      [ R6, 0x20200078UL; R7, 0x8UL; F1, 0x36a0000000000000UL ]
      window3
      []
      [ 0x20200080UL, 0x1d88760e7UL ]
    oracleMem
      ppc64le
      "7c263d18"
      [ R6, 0x20200078UL; R7, 0x8UL; F1, 0x36a0000000000000UL ]
      window3
      []
      [ 0x20200080UL, 0x1000000d88760e7UL ]
    oracleMem
      ppc64
      "7c263d18"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0x7ff0000000000000UL
        VSRL1, 0x5555555555555555UL ]
      window4
      []
      [ 0x20200080UL, 0x7f800000fd500fadUL ]
    oracleMem
      ppc64le
      "7c263d18"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0x7ff0000000000000UL
        VSRL1, 0x5555555555555555UL ]
      window4
      []
      [ 0x20200080UL, 0x807ffd500fadUL ]
    oracleMem
      ppc64
      "7c263d18"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0x7ff4000000000000UL
        VSRL1, 0xfedcba9876543210UL ]
      window5
      []
      [ 0x20200080UL, 0x7fa000002302735eUL ]
    oracleMem
      ppc64le
      "7c263d18"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0x7ff4000000000000UL
        VSRL1, 0xfedcba9876543210UL ]
      window5
      []
      [ 0x20200080UL, 0xa07f2302735eUL ]
    oracleMem
      ppc64
      "7c263d18"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0x7fffffff80000000UL
        VSRL1, 0xffffffff00000001UL ]
      window6
      []
      [ 0x20200080UL, 0x7ffffffc67c8d38fUL ]
    oracleMem
      ppc64le
      "7c263d18"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0x7fffffff80000000UL
        VSRL1, 0xffffffff00000001UL ]
      window6
      []
      [ 0x20200080UL, 0xfcffff7f67c8d38fUL ]
    oracleMem
      ppc64
      "7c263d18"
      [ R6, 0x20200078UL; R7, 0x8UL; F1, 0x8000000000000000UL ]
      window7
      []
      [ 0x20200080UL, 0x80000000c6d5e977UL ]
    oracleMem
      ppc64le
      "7c263d18"
      [ R6, 0x20200078UL; R7, 0x8UL; F1, 0x8000000000000000UL ]
      window7
      []
      [ 0x20200080UL, 0x80c6d5e977UL ]

  /// <summary>
  /// stxv xS, DQ(rA) stores xS at (rA|0) + DQ, byte element 0 at the lowest
  /// address on a big-endian guest and at the highest on a little-endian one.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] STXV stores a quadword in the guest's byte order``() =
    (* stxv vs1,16(r6), under QEMU: oracle results *)
    let window0 =
      [ 0x20200080UL, 0x1387c1d05113f7a2UL; 0x20200088UL, 0x882813dcd4ff21fUL ]
    oracleMem
      ppc64
      "f4260015"
      [ R6, 0x20200070UL; F1, 0x1020304050607UL; VSRL1, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0x1020304050607UL; 0x20200088UL, 0x8090a0b0c0d0e0fUL ]
    oracleMem
      ppc64le
      "f4260015"
      [ R6, 0x20200070UL; F1, 0x1020304050607UL; VSRL1, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0xf0e0d0c0b0a0908UL; 0x20200088UL, 0x706050403020100UL ]

  /// <summary>
  /// stxvx xS, rA, rB stores xS at (rA|0) + rB as stxv does.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] STXVX stores a quadword in the guest's byte order``() =
    (* stxvx vs1,r6,r7, under QEMU: oracle results *)
    let window0 =
      [ 0x20200080UL, 0xbae6d1967f943d15UL; 0x20200088UL, 0x75a4488da907eb1aUL ]
    oracleMem
      ppc64
      "7c263b18"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0x1020304050607UL
        VSRL1, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0x1020304050607UL; 0x20200088UL, 0x8090a0b0c0d0e0fUL ]
    oracleMem
      ppc64le
      "7c263b18"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0x1020304050607UL
        VSRL1, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0xf0e0d0c0b0a0908UL; 0x20200088UL, 0x706050403020100UL ]

  /// <summary>
  /// stxvb16x xS, rA, rB stores byte element i of xS at (rA|0) + rB + i.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] STXVB16X stores bytes in address order``() =
    (* stxvb16x vs1,r6,r7, under QEMU: oracle results *)
    let window0 =
      [ 0x20200080UL, 0x40f83c3d18977259UL; 0x20200088UL, 0x446dc19f496c3751UL ]
    oracleMem
      ppc64
      "7c263fd8"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0x1020304050607UL
        VSRL1, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0x1020304050607UL; 0x20200088UL, 0x8090a0b0c0d0e0fUL ]
    oracleMem
      ppc64le
      "7c263fd8"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0x1020304050607UL
        VSRL1, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0x1020304050607UL; 0x20200088UL, 0x8090a0b0c0d0e0fUL ]

  /// <summary>
  /// stxvh8x xS, rA, rB stores halfword element i of xS at (rA|0) + rB + 2i,
  /// each in the guest's byte order.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] STXVH8X stores eight halfwords in address order``() =
    (* stxvh8x vs1,r6,r7, under QEMU: oracle results *)
    let window0 =
      [ 0x20200080UL, 0x42ab0656080b579dUL; 0x20200088UL, 0x645e20e9269f0393UL ]
    oracleMem
      ppc64
      "7c263f58"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0x1020304050607UL
        VSRL1, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0x1020304050607UL; 0x20200088UL, 0x8090a0b0c0d0e0fUL ]
    oracleMem
      ppc64le
      "7c263f58"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0x1020304050607UL
        VSRL1, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0x100030205040706UL; 0x20200088UL, 0x9080b0a0d0c0f0eUL ]

  /// <summary>
  /// stxvl xS, rA, rB stores nb bytes at (rA|0), nb being the top byte of rB --
  /// 16, 5 and 0 here: the leftmost bytes of xS on a big-endian guest, the
  /// rightmost, byte order reversed, on a little-endian one, and no other byte.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] STXVL stores as many bytes as the top byte of rB says``() =
    (* stxvl vs1,r6,r7, under QEMU: oracle results *)
    let window0 =
      [ 0x20200080UL, 0xe0299bb2455953b2UL; 0x20200088UL, 0x7870dea7881e0168UL ]
    let window1 =
      [ 0x20200080UL, 0xfc0387d02a2fd15UL; 0x20200088UL, 0x549ceb2638194eedUL ]
    let window2 =
      [ 0x20200080UL, 0x42ae0f396b38cecUL; 0x20200088UL, 0xe8be991b8eff2d42UL ]
    oracleMem
      ppc64
      "7c263b1a"
      [ R6, 0x20200080UL
        R7, 0x1000000000000000UL
        F1, 0x1020304050607UL
        VSRL1, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0x1020304050607UL; 0x20200088UL, 0x8090a0b0c0d0e0fUL ]
    oracleMem
      ppc64le
      "7c263b1a"
      [ R6, 0x20200080UL
        R7, 0x1000000000000000UL
        F1, 0x1020304050607UL
        VSRL1, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0xf0e0d0c0b0a0908UL; 0x20200088UL, 0x706050403020100UL ]
    oracleMem
      ppc64
      "7c263b1a"
      [ R6, 0x20200080UL
        R7, 0x500000000000000UL
        F1, 0x7fffffff80000000UL
        VSRL1, 0xffffffff00000001UL ]
      window1
      []
      [ 0x20200080UL, 0x7fffffff80a2fd15UL ]
    oracleMem
      ppc64le
      "7c263b1a"
      [ R6, 0x20200080UL
        R7, 0x500000000000000UL
        F1, 0x7fffffff80000000UL
        VSRL1, 0xffffffff00000001UL ]
      window1
      []
      [ 0x20200080UL, 0x1000000ffa2fd15UL ]
    oracleMem
      ppc64
      "7c263b1a"
      [ R6, 0x20200080UL
        F1, 0x7fff8000ffff0001UL
        VSRL1, 0x7f80ff00017f80ffUL ]
      window2
      []
      []
    oracleMem
      ppc64le
      "7c263b1a"
      [ R6, 0x20200080UL
        F1, 0x7fff8000ffff0001UL
        VSRL1, 0x7f80ff00017f80ffUL ]
      window2
      []
      []

  /// <summary>
  /// stxvll xS, rA, rB stores byte elements 0 to nb-1 of xS at (rA|0) upwards,
  /// nb being the top byte of rB and at most 16 (16, 5 and 17 here).
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] STXVLL stores nb bytes left-justified on either guest``() =
    (* stxvll vs1,r6,r7, under QEMU: oracle results *)
    let window0 =
      [ 0x20200080UL, 0x9f329fde0cfe007UL; 0x20200088UL, 0x565f4663f6b06214UL ]
    let window1 =
      [ 0x20200080UL, 0x6929ed1baef336a4UL; 0x20200088UL, 0x7f9c1e7de904818aUL ]
    let window2 =
      [ 0x20200080UL, 0xf735ac6afc02b27cUL; 0x20200088UL, 0x30b9956b8a113ca1UL ]
    oracleMem
      ppc64
      "7c263b5a"
      [ R6, 0x20200080UL
        R7, 0x1000000000000000UL
        F1, 0x1020304050607UL
        VSRL1, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0x1020304050607UL; 0x20200088UL, 0x8090a0b0c0d0e0fUL ]
    oracleMem
      ppc64le
      "7c263b5a"
      [ R6, 0x20200080UL
        R7, 0x1000000000000000UL
        F1, 0x1020304050607UL
        VSRL1, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0x1020304050607UL; 0x20200088UL, 0x8090a0b0c0d0e0fUL ]
    oracleMem
      ppc64
      "7c263b5a"
      [ R6, 0x20200080UL
        R7, 0x500000000000000UL
        F1, 0x7fffffff80000000UL
        VSRL1, 0xffffffff00000001UL ]
      window1
      []
      [ 0x20200080UL, 0x7fffffff80f336a4UL ]
    oracleMem
      ppc64le
      "7c263b5a"
      [ R6, 0x20200080UL
        R7, 0x500000000000000UL
        F1, 0x7fffffff80000000UL
        VSRL1, 0xffffffff00000001UL ]
      window1
      []
      [ 0x20200080UL, 0x7fffffff80f336a4UL ]
    oracleMem
      ppc64
      "7c263b5a"
      [ R6, 0x20200080UL; R7, 0x1100000000000000UL ]
      window2
      []
      [ 0x20200080UL, 0x0UL; 0x20200088UL, 0x0UL ]
    oracleMem
      ppc64le
      "7c263b5a"
      [ R6, 0x20200080UL; R7, 0x1100000000000000UL ]
      window2
      []
      [ 0x20200080UL, 0x0UL; 0x20200088UL, 0x0UL ]

  /// <summary>
  /// stxvp xSp, DQ(rA) stores xSp and xSp+1 as one octword at (rA|0) + DQ, so
  /// on a little-endian guest xSp goes to the upper 16 bytes, byte-reversed.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] STXVP stores a register pair``() =
    (* stxvp vs2,16(r6), under QEMU: oracle results *)
    let window0 =
      [ 0x20200080UL, 0x40043ba7907c4a19UL
        0x20200088UL, 0xa6f45e8d86b6242dUL
        0x20200090UL, 0x83b9402b4d89c479UL
        0x20200098UL, 0xe61f1158a6c702bUL ]
    oracleMem
      ppc64
      "18460011"
      [ R6, 0x20200070UL; F2, 0x1020304050607UL; VSRL2, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0x1020304050607UL
        0x20200088UL, 0x8090a0b0c0d0e0fUL
        0x20200090UL, 0x0UL
        0x20200098UL, 0x0UL ]
    oracleMem
      ppc64le
      "18460011"
      [ R6, 0x20200070UL; F2, 0x1020304050607UL; VSRL2, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0x0UL
        0x20200088UL, 0x0UL
        0x20200090UL, 0xf0e0d0c0b0a0908UL
        0x20200098UL, 0x706050403020100UL ]

  /// <summary>
  /// stxvpx xSp, rA, rB stores xSp and xSp+1 at (rA|0) + rB as stxvp does.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] STXVPX stores a register pair``() =
    (* stxvpx vs2,r6,r7, under QEMU: oracle results *)
    let window0 =
      [ 0x20200080UL, 0xf7ba2576aed13b03UL
        0x20200088UL, 0xfb4237e53847469cUL
        0x20200090UL, 0xa9d501e68fa6546eUL
        0x20200098UL, 0x363b06d4a8ca4245UL ]
    oracleMem
      ppc64
      "7c463b9a"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F2, 0x1020304050607UL
        VSRL2, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0x1020304050607UL
        0x20200088UL, 0x8090a0b0c0d0e0fUL
        0x20200090UL, 0x0UL
        0x20200098UL, 0x0UL ]
    oracleMem
      ppc64le
      "7c463b9a"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F2, 0x1020304050607UL
        VSRL2, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0x0UL
        0x20200088UL, 0x0UL
        0x20200090UL, 0xf0e0d0c0b0a0908UL
        0x20200098UL, 0x706050403020100UL ]

  /// <summary>
  /// stxvrbx xS, rA, rB stores byte element 15 of xS at (rA|0) + rB.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] STXVRBX stores the rightmost byte``() =
    (* stxvrbx vs1,r6,r7, under QEMU: oracle results *)
    let window0 =
      [ 0x20200080UL, 0x79258d516f425f65UL; 0x20200088UL, 0x8f3b1351fb2fee54UL ]
    oracleMem
      ppc64
      "7c26391a"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0x1020304050607UL
        VSRL1, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0xf258d516f425f65UL ]
    oracleMem
      ppc64le
      "7c26391a"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0x1020304050607UL
        VSRL1, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0xf258d516f425f65UL ]

  /// <summary>
  /// stxvrhx xS, rA, rB stores halfword element 7 of xS at (rA|0) + rB in the
  /// guest's byte order.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] STXVRHX stores the rightmost halfword``() =
    (* stxvrhx vs1,r6,r7, under QEMU: oracle results *)
    let window0 =
      [ 0x20200080UL, 0x8d3a488eab432aa1UL; 0x20200088UL, 0x19bfb4ccbf56f366UL ]
    oracleMem
      ppc64
      "7c26395a"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0x1020304050607UL
        VSRL1, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0xe0f488eab432aa1UL ]
    oracleMem
      ppc64le
      "7c26395a"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0x1020304050607UL
        VSRL1, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0xf0e488eab432aa1UL ]

  /// <summary>
  /// stxvrwx xS, rA, rB stores word element 3 of xS at (rA|0) + rB in the
  /// guest's byte order.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] STXVRWX stores the rightmost word``() =
    (* stxvrwx vs1,r6,r7, under QEMU: oracle results *)
    let window0 =
      [ 0x20200080UL, 0x5bdbaa4f381cb62dUL; 0x20200088UL, 0x3806ace9b918bfe0UL ]
    oracleMem
      ppc64
      "7c26399a"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0x1020304050607UL
        VSRL1, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0xc0d0e0f381cb62dUL ]
    oracleMem
      ppc64le
      "7c26399a"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0x1020304050607UL
        VSRL1, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0xf0e0d0c381cb62dUL ]

  /// <summary>
  /// stxvrdx xS, rA, rB stores doubleword element 1 of xS at (rA|0) + rB in the
  /// guest's byte order.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] STXVRDX stores the rightmost doubleword``() =
    (* stxvrdx vs1,r6,r7, under QEMU: oracle results *)
    let window0 =
      [ 0x20200080UL, 0xd4f552f32152b26dUL; 0x20200088UL, 0x42ee9c7755b771feUL ]
    oracleMem
      ppc64
      "7c2639da"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0x1020304050607UL
        VSRL1, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0x8090a0b0c0d0e0fUL ]
    oracleMem
      ppc64le
      "7c2639da"
      [ R6, 0x20200078UL
        R7, 0x8UL
        F1, 0x1020304050607UL
        VSRL1, 0x8090a0b0c0d0e0fUL ]
      window0
      []
      [ 0x20200080UL, 0xf0e0d0c0b0a0908UL ]

  /// <summary>
  /// xsresp xT, xB places in doubleword 0 of xT a single-precision estimate of
  /// the reciprocal of the double in doubleword 0 of xB, clears doubleword 1
  /// and sets FPRF to the class of the result. The estimate may stray by a part
  /// in 16384 except where the reciprocal is a zero, an infinity or a NaN,
  /// which are the vectors here: +0 and -0 give +Inf and -Inf, +Inf and -Inf
  /// give +0 and -0, a quiet NaN passes and a signalling one comes back quiet.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSRESP answers the special values exactly``() =
    (* xsresp vs1,vs3, under QEMU: lanes/x-oracle/est, oracle results *)
    oracleMem
      ppc64
      "f0201868"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL; FPSCR, 0x2UL ]
      []
      [ F1, 0x7ff0000000000000UL; VSRL1, 0x0UL; FPSCR, 0x5UL ]
      []
    oracleMem
      ppc64le
      "f0201868"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL; FPSCR, 0x2UL ]
      []
      [ F1, 0x7ff0000000000000UL; VSRL1, 0x0UL; FPSCR, 0x5UL ]
      []
    oracleMem
      ppc64
      "f0201868"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        FPSCR, 0x3UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "f0201868"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        FPSCR, 0x3UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64
      "f0201868"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff8000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        FPSCR, 0xbff80000UL ]
      []
      [ F1, 0x7ff8000000000000UL; VSRL1, 0x0UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64le
      "f0201868"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff8000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        FPSCR, 0xbff80000UL ]
      []
      [ F1, 0x7ff8000000000000UL; VSRL1, 0x0UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64
      "f0201868"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0xfff0000000000000UL; VSRL1, 0x0UL; FPSCR, 0x9UL ]
      []
    oracleMem
      ppc64le
      "f0201868"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0xfff0000000000000UL; VSRL1, 0x0UL; FPSCR, 0x9UL ]
      []
    oracleMem
      ppc64
      "f0201868"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0xfff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        FPSCR, 0x1UL ]
      []
      [ F1, 0x8000000000000000UL; VSRL1, 0x0UL; FPSCR, 0x12UL ]
      []
    oracleMem
      ppc64le
      "f0201868"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0xfff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        FPSCR, 0x1UL ]
      []
      [ F1, 0x8000000000000000UL; VSRL1, 0x0UL; FPSCR, 0x12UL ]
      []
    oracleMem
      ppc64
      "f0201868"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff4000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        FPSCR, 0x2UL ]
      []
      [ F1, 0x7ffc000000000000UL; VSRL1, 0x0UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64le
      "f0201868"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff4000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        FPSCR, 0x2UL ]
      []
      [ F1, 0x7ffc000000000000UL; VSRL1, 0x0UL; FPSCR, 0x11UL ]
      []

  /// <summary>
  /// xsrsqrtesp xT, xB places in doubleword 0 of xT a single-precision estimate
  /// of the reciprocal of the square root of the double in doubleword 0 of xB,
  /// clears doubleword 1 and sets FPRF. At the special values the answer is
  /// exact: +0 and -0 give +Inf and -Inf, +Inf gives +0, -Inf and any negative
  /// number are invalid and give the default quiet NaN, a quiet NaN passes and
  /// a signalling one comes back quiet.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSRSQRTESP answers the special values exactly``() =
    (* xsrsqrtesp vs1,vs3, under QEMU: lanes/x-oracle/est, oracle results *)
    oracleMem
      ppc64
      "f0201828"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL; FPSCR, 0x2UL ]
      []
      [ F1, 0x7ff0000000000000UL; VSRL1, 0x0UL; FPSCR, 0x5UL ]
      []
    oracleMem
      ppc64le
      "f0201828"
      [ F1, 0xbad0bad0bad0badUL; VSRL1, 0xbad0bad0bad0badUL; FPSCR, 0x2UL ]
      []
      [ F1, 0x7ff0000000000000UL; VSRL1, 0x0UL; FPSCR, 0x5UL ]
      []
    oracleMem
      ppc64
      "f0201828"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        FPSCR, 0x3UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "f0201828"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        FPSCR, 0x3UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64
      "f0201828"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff8000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        FPSCR, 0xbff80000UL ]
      []
      [ F1, 0x7ff8000000000000UL; VSRL1, 0x0UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64le
      "f0201828"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff8000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        FPSCR, 0xbff80000UL ]
      []
      [ F1, 0x7ff8000000000000UL; VSRL1, 0x0UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64
      "f0201828"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0xfff0000000000000UL; VSRL1, 0x0UL; FPSCR, 0x9UL ]
      []
    oracleMem
      ppc64le
      "f0201828"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0xfff0000000000000UL; VSRL1, 0x0UL; FPSCR, 0x9UL ]
      []
    oracleMem
      ppc64
      "f0201828"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0xfff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        FPSCR, 0x1UL ]
      []
      [ F1, 0x7ff8000000000000UL; VSRL1, 0x0UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64le
      "f0201828"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0xfff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        FPSCR, 0x1UL ]
      []
      [ F1, 0x7ff8000000000000UL; VSRL1, 0x0UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64
      "f0201828"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff4000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        FPSCR, 0x2UL ]
      []
      [ F1, 0x7ffc000000000000UL; VSRL1, 0x0UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64le
      "f0201828"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff4000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        FPSCR, 0x2UL ]
      []
      [ F1, 0x7ffc000000000000UL; VSRL1, 0x0UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64
      "f0201828"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0xc000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        FPSCR, 0x3UL ]
      []
      [ F1, 0x7ff8000000000000UL; VSRL1, 0x0UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64le
      "f0201828"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0xc000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        FPSCR, 0x3UL ]
      []
      [ F1, 0x7ff8000000000000UL; VSRL1, 0x0UL; FPSCR, 0x11UL ]
      []

  /// <summary>
  /// xxbrh xT, xB reverses the two bytes of every halfword element of xB, the
  /// elements staying where they are.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XXBRH reverses the bytes of each halfword``() =
    (* xxbrh vs1,vs3, under QEMU: oracle results *)
    oracleMem
      ppc64
      "f0271f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1020304050607UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8090a0b0c0d0e0fUL ]
      []
      [ F1, 0x100030205040706UL; VSRL1, 0x9080b0a0d0c0f0eUL ]
      []
    oracleMem
      ppc64le
      "f0271f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1020304050607UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8090a0b0c0d0e0fUL ]
      []
      [ F1, 0x100030205040706UL; VSRL1, 0x9080b0a0d0c0f0eUL ]
      []
    oracleMem
      ppc64
      "f0271f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7fffffff80000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xffffffff00000001UL ]
      []
      [ F1, 0xff7fffff00800000UL; VSRL1, 0xffffffff00000100UL ]
      []
    oracleMem
      ppc64le
      "f0271f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7fffffff80000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xffffffff00000001UL ]
      []
      [ F1, 0xff7fffff00800000UL; VSRL1, 0xffffffff00000100UL ]
      []

  /// <summary>
  /// xxbrw xT, xB reverses the four bytes of every word element of xB.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XXBRW reverses the bytes of each word``() =
    (* xxbrw vs1,vs3, under QEMU: oracle results *)
    oracleMem
      ppc64
      "f02f1f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1020304050607UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8090a0b0c0d0e0fUL ]
      []
      [ F1, 0x302010007060504UL; VSRL1, 0xb0a09080f0e0d0cUL ]
      []
    oracleMem
      ppc64le
      "f02f1f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1020304050607UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8090a0b0c0d0e0fUL ]
      []
      [ F1, 0x302010007060504UL; VSRL1, 0xb0a09080f0e0d0cUL ]
      []
    oracleMem
      ppc64
      "f02f1f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7fffffff80000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xffffffff00000001UL ]
      []
      [ F1, 0xffffff7f00000080UL; VSRL1, 0xffffffff01000000UL ]
      []
    oracleMem
      ppc64le
      "f02f1f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7fffffff80000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xffffffff00000001UL ]
      []
      [ F1, 0xffffff7f00000080UL; VSRL1, 0xffffffff01000000UL ]
      []

  /// <summary>
  /// xxbrd xT, xB reverses the eight bytes of each doubleword element of xB.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XXBRD reverses the bytes of each doubleword``() =
    (* xxbrd vs1,vs3, under QEMU: oracle results *)
    oracleMem
      ppc64
      "f0371f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1020304050607UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8090a0b0c0d0e0fUL ]
      []
      [ F1, 0x706050403020100UL; VSRL1, 0xf0e0d0c0b0a0908UL ]
      []
    oracleMem
      ppc64le
      "f0371f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1020304050607UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8090a0b0c0d0e0fUL ]
      []
      [ F1, 0x706050403020100UL; VSRL1, 0xf0e0d0c0b0a0908UL ]
      []
    oracleMem
      ppc64
      "f0371f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7fffffff80000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xffffffff00000001UL ]
      []
      [ F1, 0x80ffffff7fUL; VSRL1, 0x1000000ffffffffUL ]
      []
    oracleMem
      ppc64le
      "f0371f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7fffffff80000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xffffffff00000001UL ]
      []
      [ F1, 0x80ffffff7fUL; VSRL1, 0x1000000ffffffffUL ]
      []

  /// <summary>
  /// xxbrq xT, xB reverses the sixteen bytes of xB as one quadword.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XXBRQ reverses all sixteen bytes``() =
    (* xxbrq vs1,vs3, under QEMU: oracle results *)
    oracleMem
      ppc64
      "f03f1f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1020304050607UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8090a0b0c0d0e0fUL ]
      []
      [ F1, 0xf0e0d0c0b0a0908UL; VSRL1, 0x706050403020100UL ]
      []
    oracleMem
      ppc64le
      "f03f1f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1020304050607UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8090a0b0c0d0e0fUL ]
      []
      [ F1, 0xf0e0d0c0b0a0908UL; VSRL1, 0x706050403020100UL ]
      []
    oracleMem
      ppc64
      "f03f1f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7fffffff80000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xffffffff00000001UL ]
      []
      [ F1, 0x1000000ffffffffUL; VSRL1, 0x80ffffff7fUL ]
      []
    oracleMem
      ppc64le
      "f03f1f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7fffffff80000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xffffffff00000001UL ]
      []
      [ F1, 0x1000000ffffffffUL; VSRL1, 0x80ffffff7fUL ]
      []

  /// <summary>
  /// xxextractuw xT, xB, UIM places byte elements UIM to UIM+3 of xB, as a
  /// word, zero-extended into doubleword 0 of xT, and clears doubleword 1: UIM
  /// 1, 0, 5 and 12, the last the largest the manual defines.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XXEXTRACTUW takes the word at a byte offset``() =
    (* xxextractuw vs1,vs3,1, under QEMU: lanes/x-oracle/perm, oracle results *)
    oracleMem
      ppc64
      "f0211a94"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1020304050607UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8090a0b0c0d0e0fUL ]
      []
      [ F1, 0x1020304UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0211a94"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1020304050607UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8090a0b0c0d0e0fUL ]
      []
      [ F1, 0x1020304UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "f0201a94"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1020304050607UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8090a0b0c0d0e0fUL ]
      []
      [ F1, 0x10203UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0201a94"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1020304050607UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8090a0b0c0d0e0fUL ]
      []
      [ F1, 0x10203UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "f0251a94"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1020304050607UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8090a0b0c0d0e0fUL ]
      []
      [ F1, 0x5060708UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0251a94"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1020304050607UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8090a0b0c0d0e0fUL ]
      []
      [ F1, 0x5060708UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "f02c1a94"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1020304050607UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8090a0b0c0d0e0fUL ]
      []
      [ F1, 0xc0d0e0fUL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f02c1a94"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1020304050607UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8090a0b0c0d0e0fUL ]
      []
      [ F1, 0xc0d0e0fUL; VSRL1, 0x0UL ]
      []

  /// <summary>
  /// xxinsertw xT, xB, UIM writes word element 1 of xB into byte elements UIM
  /// to UIM+3 of xT and leaves the other bytes of xT as they were: UIM 1, 0, 7
  /// and 12.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XXINSERTW puts a word at a byte offset``() =
    (* xxinsertw vs1,vs3,1, under QEMU: lanes/x-oracle/perm, oracle results *)
    oracleMem
      ppc64
      "f0211ad4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1020304050607UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8090a0b0c0d0e0fUL ]
      []
      [ F1, 0xb04050607ad0badUL ]
      []
    oracleMem
      ppc64le
      "f0211ad4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1020304050607UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8090a0b0c0d0e0fUL ]
      []
      [ F1, 0xb04050607ad0badUL ]
      []
    oracleMem
      ppc64
      "f0201ad4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1020304050607UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8090a0b0c0d0e0fUL ]
      []
      [ F1, 0x40506070bad0badUL ]
      []
    oracleMem
      ppc64le
      "f0201ad4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1020304050607UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8090a0b0c0d0e0fUL ]
      []
      [ F1, 0x40506070bad0badUL ]
      []
    oracleMem
      ppc64
      "f0271ad4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1020304050607UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8090a0b0c0d0e0fUL ]
      []
      [ F1, 0xbad0bad0bad0b04UL; VSRL1, 0x50607ad0bad0badUL ]
      []
    oracleMem
      ppc64le
      "f0271ad4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1020304050607UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8090a0b0c0d0e0fUL ]
      []
      [ F1, 0xbad0bad0bad0b04UL; VSRL1, 0x50607ad0bad0badUL ]
      []
    oracleMem
      ppc64
      "f02c1ad4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1020304050607UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8090a0b0c0d0e0fUL ]
      []
      [ VSRL1, 0xbad0bad04050607UL ]
      []
    oracleMem
      ppc64le
      "f02c1ad4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1020304050607UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8090a0b0c0d0e0fUL ]
      []
      [ VSRL1, 0xbad0bad04050607UL ]
      []

  /// <summary>
  /// xxperm xT, xA, xB places in byte i of xT the byte of the 32-byte pair xA
  /// || xT that the low five bits of byte i of xB index from the left; xT is
  /// read whole before it is written.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XXPERM picks bytes of xA and xT by a left index``() =
    (* xxperm vs1,vs2,vs3, under QEMU: oracle results *)
    oracleMem
      ppc64
      "f02218d0"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x1020304050607UL
        F3, 0xf0e0d0c0b0a0908UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x8090a0b0c0d0e0fUL
        VSRL3, 0x706050403020100UL ]
      []
      [ F1, 0xf0e0d0c0b0a0908UL; VSRL1, 0x706050403020100UL ]
      []
    oracleMem
      ppc64le
      "f02218d0"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x1020304050607UL
        F3, 0xf0e0d0c0b0a0908UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x8090a0b0c0d0e0fUL
        VSRL3, 0x706050403020100UL ]
      []
      [ F1, 0xf0e0d0c0b0a0908UL; VSRL1, 0x706050403020100UL ]
      []
    oracleMem
      ppc64
      "f02218d0"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7fffffff80000000UL
        F3, 0x1ffffffffUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0xffffffff00000001UL
        VSRL3, 0x7fffffff80000000UL ]
      []
      [ F1, 0x7f7f7fffadadadadUL; VSRL1, 0xadadadad7f7f7f7fUL ]
      []
    oracleMem
      ppc64le
      "f02218d0"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7fffffff80000000UL
        F3, 0x1ffffffffUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0xffffffff00000001UL
        VSRL3, 0x7fffffff80000000UL ]
      []
      [ F1, 0x7f7f7fffadadadadUL; VSRL1, 0xadadadad7f7f7f7fUL ]
      []
    oracleMem
      ppc64
      "f02218d0"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7fff8000ffff0001UL
        F3, 0x1ffff80007fffUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7f80ff00017f80ffUL
        VSRL3, 0x7f7f808001010000UL ]
      []
      [ F1, 0x7fffadad7f7fadadUL; VSRL1, 0xadad7f7fffff7f7fUL ]
      []
    oracleMem
      ppc64le
      "f02218d0"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7fff8000ffff0001UL
        F3, 0x1ffff80007fffUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7f80ff00017f80ffUL
        VSRL3, 0x7f7f808001010000UL ]
      []
      [ F1, 0x7fffadad7f7fadadUL; VSRL1, 0xadad7f7fffff7f7fUL ]
      []

  /// <summary>
  /// xxpermr xT, xA, xB places in byte i of xT byte 31-k of the 32-byte pair xA
  /// || xT, k being the low five bits of byte i of xB.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XXPERMR picks bytes of xA and xT by a right index``() =
    (* xxpermr vs1,vs2,vs3, under QEMU: oracle results *)
    oracleMem
      ppc64
      "f02219d0"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x1020304050607UL
        F3, 0xf0e0d0c0b0a0908UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x8090a0b0c0d0e0fUL
        VSRL3, 0x706050403020100UL ]
      []
      []
      []
    oracleMem
      ppc64le
      "f02219d0"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x1020304050607UL
        F3, 0xf0e0d0c0b0a0908UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x8090a0b0c0d0e0fUL
        VSRL3, 0x706050403020100UL ]
      []
      []
      []
    oracleMem
      ppc64
      "f02219d0"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7fffffff80000000UL
        F3, 0x1ffffffffUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0xffffffff00000001UL
        VSRL3, 0x7fffffff80000000UL ]
      []
      [ F1, 0xadadad0b7f7f7f7fUL; VSRL1, 0x7f7f7f7fadadadadUL ]
      []
    oracleMem
      ppc64le
      "f02219d0"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7fffffff80000000UL
        F3, 0x1ffffffffUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0xffffffff00000001UL
        VSRL3, 0x7fffffff80000000UL ]
      []
      [ F1, 0xadadad0b7f7f7f7fUL; VSRL1, 0x7f7f7f7fadadadadUL ]
      []
    oracleMem
      ppc64
      "f02219d0"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7fff8000ffff0001UL
        F3, 0x1ffff80007fffUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7f80ff00017f80ffUL
        VSRL3, 0x7f7f808001010000UL ]
      []
      [ F1, 0xad0b7f7fadad7f7fUL; VSRL1, 0x7f7fadad0b0badadUL ]
      []
    oracleMem
      ppc64le
      "f02219d0"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7fff8000ffff0001UL
        F3, 0x1ffff80007fffUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7f80ff00017f80ffUL
        VSRL3, 0x7f7f808001010000UL ]
      []
      [ F1, 0xad0b7f7fadad7f7fUL; VSRL1, 0x7f7fadad0b0badadUL ]
      []

  /// <summary>
  /// xxgenpcvbm xT, vRB, IMM builds the permute control vector that expands
  /// (IMM 0 and 2) or compresses (1 and 3) the byte elements vRB's most
  /// significant bits select, for a left-indexed (0, 1) or right-indexed (2, 3)
  /// permute. Expansion is defined for every mask; compression leaves the
  /// elements past the selected ones undefined, so it runs here on the all-ones
  /// mask, where every element is defined.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XXGENPCVBM builds the byte permute controls``() =
    (* xxgenpcvbm vs1,v3,0, under QEMU: lanes/x-oracle/perm *)
    oracleMem
      ppc64
      "f0201f28"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0x80ff00ff7f800001UL
        V3B, 0x180ff8000ff8080UL ]
      []
      [ F1, 0x1120214031617UL; VSRL1, 0x180405061c070809UL ]
      []
    oracleMem
      ppc64le
      "f0201f28"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0x80ff00ff7f800001UL
        V3B, 0x180ff8000ff8080UL ]
      []
      [ F1, 0x1120214031617UL; VSRL1, 0x180405061c070809UL ]
      []
    oracleMem
      ppc64
      "f0201f28"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ F1, 0x1020304050607UL; VSRL1, 0x8090a0b0c0d0e0fUL ]
      []
    oracleMem
      ppc64le
      "f0201f28"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ F1, 0x1020304050607UL; VSRL1, 0x8090a0b0c0d0e0fUL ]
      []
    oracleMem
      ppc64
      "f0201f28"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0x7fffffff80000000UL
        V3B, 0xffffffff00000001UL ]
      []
      [ F1, 0x1000010203151617UL; VSRL1, 0x40506071c1d1e1fUL ]
      []
    oracleMem
      ppc64le
      "f0201f28"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0x7fffffff80000000UL
        V3B, 0xffffffff00000001UL ]
      []
      [ F1, 0x1000010203151617UL; VSRL1, 0x40506071c1d1e1fUL ]
      []
    oracleMem
      ppc64
      "f0221f28"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0x80ff00ff7f800001UL
        V3B, 0x180ff8000ff8080UL ]
      []
      [ F1, 0x9081d071b061918UL; VSRL1, 0x1705040313020100UL ]
      []
    oracleMem
      ppc64le
      "f0221f28"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0x80ff00ff7f800001UL
        V3B, 0x180ff8000ff8080UL ]
      []
      [ F1, 0x9081d071b061918UL; VSRL1, 0x1705040313020100UL ]
      []
    oracleMem
      ppc64
      "f0221f28"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ F1, 0xf0e0d0c0b0a0908UL; VSRL1, 0x706050403020100UL ]
      []
    oracleMem
      ppc64le
      "f0221f28"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ F1, 0xf0e0d0c0b0a0908UL; VSRL1, 0x706050403020100UL ]
      []
    oracleMem
      ppc64
      "f0221f28"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0x7fffffff80000000UL
        V3B, 0xffffffff00000001UL ]
      []
      [ F1, 0x1f070605041a1918UL; VSRL1, 0x302010013121110UL ]
      []
    oracleMem
      ppc64le
      "f0221f28"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0x7fffffff80000000UL
        V3B, 0xffffffff00000001UL ]
      []
      [ F1, 0x1f070605041a1918UL; VSRL1, 0x302010013121110UL ]
      []
    oracleMem
      ppc64
      "f0211f28"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ F1, 0x1020304050607UL; VSRL1, 0x8090a0b0c0d0e0fUL ]
      []
    oracleMem
      ppc64le
      "f0211f28"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ F1, 0x1020304050607UL; VSRL1, 0x8090a0b0c0d0e0fUL ]
      []
    oracleMem
      ppc64
      "f0231f28"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ F1, 0xf0e0d0c0b0a0908UL; VSRL1, 0x706050403020100UL ]
      []
    oracleMem
      ppc64le
      "f0231f28"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ F1, 0xf0e0d0c0b0a0908UL; VSRL1, 0x706050403020100UL ]
      []

  /// <summary>
  /// xxgenpcvhm xT, vRB, IMM builds the permute control vector over halfword
  /// elements, each element's two byte indices in the order the permute
  /// direction reads them, as xxgenpcvbm does over bytes.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XXGENPCVHM builds the halfword permute controls``() =
    (* xxgenpcvhm vs1,v3,0, under QEMU: lanes/x-oracle/perm *)
    oracleMem
      ppc64
      "f0201f2a"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0x80ff00ff7f800001UL
        V3B, 0x180ff8000ff8080UL ]
      []
      [ F1, 0x1121314151617UL; VSRL1, 0x181902031c1d0405UL ]
      []
    oracleMem
      ppc64le
      "f0201f2a"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0x80ff00ff7f800001UL
        V3B, 0x180ff8000ff8080UL ]
      []
      [ F1, 0x1121314151617UL; VSRL1, 0x181902031c1d0405UL ]
      []
    oracleMem
      ppc64
      "f0201f2a"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ F1, 0x1020304050607UL; VSRL1, 0x8090a0b0c0d0e0fUL ]
      []
    oracleMem
      ppc64le
      "f0201f2a"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ F1, 0x1020304050607UL; VSRL1, 0x8090a0b0c0d0e0fUL ]
      []
    oracleMem
      ppc64
      "f0201f2a"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0x7fffffff80000000UL
        V3B, 0xffffffff00000001UL ]
      []
      [ F1, 0x1011000102031617UL; VSRL1, 0x40506071c1d1e1fUL ]
      []
    oracleMem
      ppc64le
      "f0201f2a"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0x7fffffff80000000UL
        V3B, 0xffffffff00000001UL ]
      []
      [ F1, 0x1011000102031617UL; VSRL1, 0x40506071c1d1e1fUL ]
      []
    oracleMem
      ppc64
      "f0221f2a"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0x80ff00ff7f800001UL
        V3B, 0x180ff8000ff8080UL ]
      []
      [ F1, 0x5041d1c1b1a1918UL; VSRL1, 0x1716030213120100UL ]
      []
    oracleMem
      ppc64le
      "f0221f2a"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0x80ff00ff7f800001UL
        V3B, 0x180ff8000ff8080UL ]
      []
      [ F1, 0x5041d1c1b1a1918UL; VSRL1, 0x1716030213120100UL ]
      []
    oracleMem
      ppc64
      "f0221f2a"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ F1, 0xf0e0d0c0b0a0908UL; VSRL1, 0x706050403020100UL ]
      []
    oracleMem
      ppc64le
      "f0221f2a"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ F1, 0xf0e0d0c0b0a0908UL; VSRL1, 0x706050403020100UL ]
      []
    oracleMem
      ppc64
      "f0221f2a"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0x7fffffff80000000UL
        V3B, 0xffffffff00000001UL ]
      []
      [ F1, 0x1f1e070605041918UL; VSRL1, 0x302010013121110UL ]
      []
    oracleMem
      ppc64le
      "f0221f2a"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0x7fffffff80000000UL
        V3B, 0xffffffff00000001UL ]
      []
      [ F1, 0x1f1e070605041918UL; VSRL1, 0x302010013121110UL ]
      []
    oracleMem
      ppc64
      "f0211f2a"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ F1, 0x1020304050607UL; VSRL1, 0x8090a0b0c0d0e0fUL ]
      []
    oracleMem
      ppc64le
      "f0211f2a"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ F1, 0x1020304050607UL; VSRL1, 0x8090a0b0c0d0e0fUL ]
      []
    oracleMem
      ppc64
      "f0231f2a"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ F1, 0xf0e0d0c0b0a0908UL; VSRL1, 0x706050403020100UL ]
      []
    oracleMem
      ppc64le
      "f0231f2a"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ F1, 0xf0e0d0c0b0a0908UL; VSRL1, 0x706050403020100UL ]
      []

  /// <summary>
  /// xxgenpcvwm xT, vRB, IMM builds the permute control vector over word
  /// elements, as xxgenpcvbm does over bytes.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XXGENPCVWM builds the word permute controls``() =
    (* xxgenpcvwm vs1,v3,0, under QEMU: lanes/x-oracle/perm *)
    oracleMem
      ppc64
      "f0201f68"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0x80ff00ff7f800001UL
        V3B, 0x180ff8000ff8080UL ]
      []
      [ F1, 0x1020314151617UL; VSRL1, 0x18191a1b1c1d1e1fUL ]
      []
    oracleMem
      ppc64le
      "f0201f68"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0x80ff00ff7f800001UL
        V3B, 0x180ff8000ff8080UL ]
      []
      [ F1, 0x1020314151617UL; VSRL1, 0x18191a1b1c1d1e1fUL ]
      []
    oracleMem
      ppc64
      "f0201f68"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ F1, 0x1020304050607UL; VSRL1, 0x8090a0b0c0d0e0fUL ]
      []
    oracleMem
      ppc64le
      "f0201f68"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ F1, 0x1020304050607UL; VSRL1, 0x8090a0b0c0d0e0fUL ]
      []
    oracleMem
      ppc64
      "f0201f68"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0x7fffffff80000000UL
        V3B, 0xffffffff00000001UL ]
      []
      [ F1, 0x1011121300010203UL; VSRL1, 0x40506071c1d1e1fUL ]
      []
    oracleMem
      ppc64le
      "f0201f68"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0x7fffffff80000000UL
        V3B, 0xffffffff00000001UL ]
      []
      [ F1, 0x1011121300010203UL; VSRL1, 0x40506071c1d1e1fUL ]
      []
    oracleMem
      ppc64
      "f0221f68"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0x80ff00ff7f800001UL
        V3B, 0x180ff8000ff8080UL ]
      []
      [ F1, 0x30201001b1a1918UL; VSRL1, 0x1716151413121110UL ]
      []
    oracleMem
      ppc64le
      "f0221f68"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0x80ff00ff7f800001UL
        V3B, 0x180ff8000ff8080UL ]
      []
      [ F1, 0x30201001b1a1918UL; VSRL1, 0x1716151413121110UL ]
      []
    oracleMem
      ppc64
      "f0221f68"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ F1, 0xf0e0d0c0b0a0908UL; VSRL1, 0x706050403020100UL ]
      []
    oracleMem
      ppc64le
      "f0221f68"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ F1, 0xf0e0d0c0b0a0908UL; VSRL1, 0x706050403020100UL ]
      []
    oracleMem
      ppc64
      "f0221f68"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0x7fffffff80000000UL
        V3B, 0xffffffff00000001UL ]
      []
      [ F1, 0x1f1e1d1c07060504UL; VSRL1, 0x302010013121110UL ]
      []
    oracleMem
      ppc64le
      "f0221f68"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0x7fffffff80000000UL
        V3B, 0xffffffff00000001UL ]
      []
      [ F1, 0x1f1e1d1c07060504UL; VSRL1, 0x302010013121110UL ]
      []
    oracleMem
      ppc64
      "f0211f68"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ F1, 0x1020304050607UL; VSRL1, 0x8090a0b0c0d0e0fUL ]
      []
    oracleMem
      ppc64le
      "f0211f68"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ F1, 0x1020304050607UL; VSRL1, 0x8090a0b0c0d0e0fUL ]
      []
    oracleMem
      ppc64
      "f0231f68"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ F1, 0xf0e0d0c0b0a0908UL; VSRL1, 0x706050403020100UL ]
      []
    oracleMem
      ppc64le
      "f0231f68"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ F1, 0xf0e0d0c0b0a0908UL; VSRL1, 0x706050403020100UL ]
      []

  /// <summary>
  /// xxgenpcvdm xT, vRB, IMM builds the permute control vector over doubleword
  /// elements, as xxgenpcvbm does over bytes.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XXGENPCVDM builds the doubleword permute controls``() =
    (* xxgenpcvdm vs1,v3,0, under QEMU: lanes/x-oracle/perm *)
    oracleMem
      ppc64
      "f0201f6a"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0x80ff00ff7f800001UL
        V3B, 0x180ff8000ff8080UL ]
      []
      [ F1, 0x1020304050607UL; VSRL1, 0x18191a1b1c1d1e1fUL ]
      []
    oracleMem
      ppc64le
      "f0201f6a"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0x80ff00ff7f800001UL
        V3B, 0x180ff8000ff8080UL ]
      []
      [ F1, 0x1020304050607UL; VSRL1, 0x18191a1b1c1d1e1fUL ]
      []
    oracleMem
      ppc64
      "f0201f6a"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ F1, 0x1020304050607UL; VSRL1, 0x8090a0b0c0d0e0fUL ]
      []
    oracleMem
      ppc64le
      "f0201f6a"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ F1, 0x1020304050607UL; VSRL1, 0x8090a0b0c0d0e0fUL ]
      []
    oracleMem
      ppc64
      "f0201f6a"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0x7fffffff80000000UL
        V3B, 0xffffffff00000001UL ]
      []
      [ F1, 0x1011121314151617UL; VSRL1, 0x1020304050607UL ]
      []
    oracleMem
      ppc64le
      "f0201f6a"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0x7fffffff80000000UL
        V3B, 0xffffffff00000001UL ]
      []
      [ F1, 0x1011121314151617UL; VSRL1, 0x1020304050607UL ]
      []
    oracleMem
      ppc64
      "f0221f6a"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0x80ff00ff7f800001UL
        V3B, 0x180ff8000ff8080UL ]
      []
      [ F1, 0x706050403020100UL; VSRL1, 0x1716151413121110UL ]
      []
    oracleMem
      ppc64le
      "f0221f6a"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0x80ff00ff7f800001UL
        V3B, 0x180ff8000ff8080UL ]
      []
      [ F1, 0x706050403020100UL; VSRL1, 0x1716151413121110UL ]
      []
    oracleMem
      ppc64
      "f0221f6a"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ F1, 0xf0e0d0c0b0a0908UL; VSRL1, 0x706050403020100UL ]
      []
    oracleMem
      ppc64le
      "f0221f6a"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ F1, 0xf0e0d0c0b0a0908UL; VSRL1, 0x706050403020100UL ]
      []
    oracleMem
      ppc64
      "f0221f6a"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0x7fffffff80000000UL
        V3B, 0xffffffff00000001UL ]
      []
      [ F1, 0x1f1e1d1c1b1a1918UL; VSRL1, 0x706050403020100UL ]
      []
    oracleMem
      ppc64le
      "f0221f6a"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0x7fffffff80000000UL
        V3B, 0xffffffff00000001UL ]
      []
      [ F1, 0x1f1e1d1c1b1a1918UL; VSRL1, 0x706050403020100UL ]
      []
    oracleMem
      ppc64
      "f0211f6a"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ F1, 0x1020304050607UL; VSRL1, 0x8090a0b0c0d0e0fUL ]
      []
    oracleMem
      ppc64le
      "f0211f6a"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ F1, 0x1020304050607UL; VSRL1, 0x8090a0b0c0d0e0fUL ]
      []
    oracleMem
      ppc64
      "f0231f6a"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ F1, 0xf0e0d0c0b0a0908UL; VSRL1, 0x706050403020100UL ]
      []
    oracleMem
      ppc64le
      "f0231f6a"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ F1, 0xf0e0d0c0b0a0908UL; VSRL1, 0x706050403020100UL ]
      []

  /// <summary>
  /// xvtlsbb BF, xB sets bit 0 of CR field BF when the least significant bit of
  /// every byte of xB is one and bit 2 when every one is zero, and clears bits
  /// 1 and 3.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVTLSBB tests the lowest bit of every byte``() =
    (* xvtlsbb cr2,vs3, under QEMU: lanes/x-oracle/perm, oracle results *)
    oracleMem
      ppc64
      "f1021f6c"
      [ F3, 0x1020304050607UL; VSRL3, 0x8090a0b0c0d0e0fUL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1021f6c"
      [ F3, 0x1020304050607UL; VSRL3, 0x8090a0b0c0d0e0fUL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64
      "f1021f6c"
      [ F3, 0x7fffffff80000000UL
        VSRL3, 0xffffffff00000001UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1021f6c"
      [ F3, 0x7fffffff80000000UL
        VSRL3, 0xffffffff00000001UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64
      "f1021f6c"
      [ F3, 0x101010101010101UL; VSRL3, 0xffffffffffffffffUL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1021f6c"
      [ F3, 0x101010101010101UL; VSRL3, 0xffffffffffffffffUL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64
      "f1021f6c"
      [ F3, 0xfefefefefefefefeUL; CR2_1, 0x1UL; CR2_2, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1021f6c"
      [ F3, 0xfefefefefefefefeUL; CR2_1, 0x1UL; CR2_2, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64
      "f1021f6c"
      [ F3, 0x101010101010101UL
        VSRL3, 0x101010101010100UL
        CR2_0, 0x1UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1021f6c"
      [ F3, 0x101010101010101UL
        VSRL3, 0x101010101010100UL
        CR2_0, 0x1UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL ]
      []

  /// <summary>
  /// xvaddsp xT, xA, xB places in each word element of xT the sum of the
  /// matching single-precision elements, rounded once to single precision:
  /// signed zeroes, infinities, a quiet NaN that propagates, a signalling one
  /// that comes back quiet, an overflow and a denormal among the operands.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVADDSP adds four singles``() =
    (* xvaddsp vs1,vs2,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0221a00"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3fc00000c0100000UL
        F3, 0x404000003f000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7f8000007fc00001UL
        VSRL3, 0xff8000003f800000UL ]
      []
      [ F1, 0x40900000bfe00000UL; VSRL1, 0x7fc000007fc00001UL ]
      []
    oracleMem
      ppc64le
      "f0221a00"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3fc00000c0100000UL
        F3, 0x404000003f000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7f8000007fc00001UL
        VSRL3, 0xff8000003f800000UL ]
      []
      [ F1, 0x40900000bfe00000UL; VSRL1, 0x7fc000007fc00001UL ]
      []
    oracleMem
      ppc64
      "f0221a00"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x80000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7f8000017149f2caUL
        VSRL3, 0x400000007149f2caUL ]
      []
      [ F1, 0x0UL; VSRL1, 0x7fc0000171c9f2caUL ]
      []
    oracleMem
      ppc64le
      "f0221a00"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x80000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7f8000017149f2caUL
        VSRL3, 0x400000007149f2caUL ]
      []
      [ F1, 0x0UL; VSRL1, 0x7fc0000171c9f2caUL ]
      []
    oracleMem
      ppc64
      "f0221a00"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3eaaaaab7f7fffffUL
        F3, 0x4040000040000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x1bf800000UL
        VSRL3, 0x3f000000ffc00000UL ]
      []
      [ F1, 0x405555557f7fffffUL; VSRL1, 0x3f000000ffc00000UL ]
      []
    oracleMem
      ppc64le
      "f0221a00"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3eaaaaab7f7fffffUL
        F3, 0x4040000040000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x1bf800000UL
        VSRL3, 0x3f000000ffc00000UL ]
      []
      [ F1, 0x405555557f7fffffUL; VSRL1, 0x3f000000ffc00000UL ]
      []

  /// <summary>
  /// xvsubsp xT, xA, xB places in each word element of xT xA minus xB of the
  /// matching single-precision elements, rounded once to single precision:
  /// signed zeroes, infinities, a quiet NaN that propagates, a signalling one
  /// that comes back quiet, an overflow and a denormal among the operands.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVSUBSP subtracts four singles``() =
    (* xvsubsp vs1,vs2,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0221a40"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3fc00000c0100000UL
        F3, 0x404000003f000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7f8000007fc00001UL
        VSRL3, 0xff8000003f800000UL ]
      []
      [ F1, 0xbfc00000c0300000UL; VSRL1, 0x7f8000007fc00001UL ]
      []
    oracleMem
      ppc64le
      "f0221a40"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3fc00000c0100000UL
        F3, 0x404000003f000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7f8000007fc00001UL
        VSRL3, 0xff8000003f800000UL ]
      []
      [ F1, 0xbfc00000c0300000UL; VSRL1, 0x7f8000007fc00001UL ]
      []
    oracleMem
      ppc64
      "f0221a40"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x80000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7f8000017149f2caUL
        VSRL3, 0x400000007149f2caUL ]
      []
      [ F1, 0x80000000UL; VSRL1, 0x7fc0000100000000UL ]
      []
    oracleMem
      ppc64le
      "f0221a40"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x80000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7f8000017149f2caUL
        VSRL3, 0x400000007149f2caUL ]
      []
      [ F1, 0x80000000UL; VSRL1, 0x7fc0000100000000UL ]
      []
    oracleMem
      ppc64
      "f0221a40"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3eaaaaab7f7fffffUL
        F3, 0x4040000040000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x1bf800000UL
        VSRL3, 0x3f000000ffc00000UL ]
      []
      [ F1, 0xc02aaaab7f7fffffUL; VSRL1, 0xbf000000ffc00000UL ]
      []
    oracleMem
      ppc64le
      "f0221a40"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3eaaaaab7f7fffffUL
        F3, 0x4040000040000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x1bf800000UL
        VSRL3, 0x3f000000ffc00000UL ]
      []
      [ F1, 0xc02aaaab7f7fffffUL; VSRL1, 0xbf000000ffc00000UL ]
      []

  /// <summary>
  /// xvmulsp xT, xA, xB places in each word element of xT the product of the
  /// matching single-precision elements, rounded once to single precision:
  /// signed zeroes, infinities, a quiet NaN that propagates, a signalling one
  /// that comes back quiet, an overflow and a denormal among the operands.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVMULSP multiplies four singles``() =
    (* xvmulsp vs1,vs2,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0221a80"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3fc00000c0100000UL
        F3, 0x404000003f000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7f8000007fc00001UL
        VSRL3, 0xff8000003f800000UL ]
      []
      [ F1, 0x40900000bf900000UL; VSRL1, 0xff8000007fc00001UL ]
      []
    oracleMem
      ppc64le
      "f0221a80"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3fc00000c0100000UL
        F3, 0x404000003f000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7f8000007fc00001UL
        VSRL3, 0xff8000003f800000UL ]
      []
      [ F1, 0x40900000bf900000UL; VSRL1, 0xff8000007fc00001UL ]
      []
    oracleMem
      ppc64
      "f0221a80"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x80000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7f8000017149f2caUL
        VSRL3, 0x400000007149f2caUL ]
      []
      [ F1, 0x8000000080000000UL; VSRL1, 0x7fc000017f800000UL ]
      []
    oracleMem
      ppc64le
      "f0221a80"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x80000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7f8000017149f2caUL
        VSRL3, 0x400000007149f2caUL ]
      []
      [ F1, 0x8000000080000000UL; VSRL1, 0x7fc000017f800000UL ]
      []
    oracleMem
      ppc64
      "f0221a80"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3eaaaaab7f7fffffUL
        F3, 0x4040000040000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x1bf800000UL
        VSRL3, 0x3f000000ffc00000UL ]
      []
      [ F1, 0x3f8000007f800000UL; VSRL1, 0xffc00000UL ]
      []
    oracleMem
      ppc64le
      "f0221a80"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3eaaaaab7f7fffffUL
        F3, 0x4040000040000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x1bf800000UL
        VSRL3, 0x3f000000ffc00000UL ]
      []
      [ F1, 0x3f8000007f800000UL; VSRL1, 0xffc00000UL ]
      []

  /// <summary>
  /// xvdivsp xT, xA, xB places in each word element of xT xA divided by xB of
  /// the matching single-precision elements, rounded once to single precision:
  /// signed zeroes, infinities, a quiet NaN that propagates, a signalling one
  /// that comes back quiet, an overflow and a denormal among the operands.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVDIVSP divides four singles``() =
    (* xvdivsp vs1,vs2,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0221ac0"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3fc00000c0100000UL
        F3, 0x404000003f000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7f8000007fc00001UL
        VSRL3, 0xff8000003f800000UL ]
      []
      [ F1, 0x3f000000c0900000UL; VSRL1, 0x7fc000007fc00001UL ]
      []
    oracleMem
      ppc64le
      "f0221ac0"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3fc00000c0100000UL
        F3, 0x404000003f000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7f8000007fc00001UL
        VSRL3, 0xff8000003f800000UL ]
      []
      [ F1, 0x3f000000c0900000UL; VSRL1, 0x7fc000007fc00001UL ]
      []
    oracleMem
      ppc64
      "f0221ac0"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x80000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7f8000017149f2caUL
        VSRL3, 0x400000007149f2caUL ]
      []
      [ F1, 0x7fc000007fc00000UL; VSRL1, 0x7fc000013f800000UL ]
      []
    oracleMem
      ppc64le
      "f0221ac0"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x80000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7f8000017149f2caUL
        VSRL3, 0x400000007149f2caUL ]
      []
      [ F1, 0x7fc000007fc00000UL; VSRL1, 0x7fc000013f800000UL ]
      []
    oracleMem
      ppc64
      "f0221ac0"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3eaaaaab7f7fffffUL
        F3, 0x4040000040000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x1bf800000UL
        VSRL3, 0x3f000000ffc00000UL ]
      []
      [ F1, 0x3de38e397effffffUL; VSRL1, 0x2ffc00000UL ]
      []
    oracleMem
      ppc64le
      "f0221ac0"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3eaaaaab7f7fffffUL
        F3, 0x4040000040000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x1bf800000UL
        VSRL3, 0x3f000000ffc00000UL ]
      []
      [ F1, 0x3de38e397effffffUL; VSRL1, 0x2ffc00000UL ]
      []

  /// <summary>
  /// xvsqrtsp xT, xB places in each word element of xT the square root of the
  /// matching single, rounded once: the square root of a negative number is the
  /// default quiet NaN, that of -0 is -0.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVSQRTSP takes four square roots``() =
    (* xvsqrtsp vs1,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0201a2c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x40000000bf800000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7f8000007f800001UL ]
      []
      [ F1, 0x3fb504f37fc00000UL; VSRL1, 0x7f8000007fc00001UL ]
      []
    oracleMem
      ppc64le
      "f0201a2c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x40000000bf800000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7f8000007f800001UL ]
      []
      [ F1, 0x3fb504f37fc00000UL; VSRL1, 0x7f8000007fc00001UL ]
      []
    oracleMem
      ppc64
      "f0201a2c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3e80000080000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x40200000c0200000UL ]
      []
      [ F1, 0x3f00000080000000UL; VSRL1, 0x3fca62c27fc00000UL ]
      []
    oracleMem
      ppc64le
      "f0201a2c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3e80000080000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x40200000c0200000UL ]
      []
      [ F1, 0x3f00000080000000UL; VSRL1, 0x3fca62c27fc00000UL ]
      []
    oracleMem
      ppc64
      "f0201a2c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fc000003f000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbf000000bfc00000UL ]
      []
      [ F1, 0x3f9cc4713f3504f3UL; VSRL1, 0x7fc000007fc00000UL ]
      []
    oracleMem
      ppc64le
      "f0201a2c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fc000003f000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbf000000bfc00000UL ]
      []
      [ F1, 0x3f9cc4713f3504f3UL; VSRL1, 0x7fc000007fc00000UL ]
      []

  /// <summary>
  /// xvsqrtdp xT, xB places in each doubleword element of xT the square root of
  /// the matching double, rounded once, with the same special cases as
  /// xvsqrtsp.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVSQRTDP takes two square roots``() =
    (* xvsqrtdp vs1,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0201b2c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4010000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbff0000000000000UL ]
      []
      [ F1, 0x4000000000000000UL; VSRL1, 0x7ff8000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201b2c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4010000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbff0000000000000UL ]
      []
      [ F1, 0x4000000000000000UL; VSRL1, 0x7ff8000000000000UL ]
      []
    oracleMem
      ppc64
      "f0201b2c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4004000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc004000000000000UL ]
      []
      [ F1, 0x3ff94c583ada5b53UL; VSRL1, 0x7ff8000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201b2c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4004000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc004000000000000UL ]
      []
      [ F1, 0x3ff94c583ada5b53UL; VSRL1, 0x7ff8000000000000UL ]
      []
    oracleMem
      ppc64
      "f0201b2c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fe0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfff0000000000000UL ]
      []
      [ F1, 0x3fe6a09e667f3bcdUL; VSRL1, 0x7ff8000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201b2c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fe0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfff0000000000000UL ]
      []
      [ F1, 0x3fe6a09e667f3bcdUL; VSRL1, 0x7ff8000000000000UL ]
      []
    oracleMem
      ppc64
      "f0201b2c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff0000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff8000000000001UL; VSRL1, 0x8000000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201b2c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff0000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff8000000000001UL; VSRL1, 0x8000000000000000UL ]
      []

  /// <summary>
  /// xvabssp xT, xB clears the sign bit of each single element of xB, a NaN
  /// included, and raises nothing.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVABSSP clears the sign bits``() =
    (* xvabssp vs1,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0201e64"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x40000000bf800000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7f8000007f800001UL ]
      []
      [ F1, 0x400000003f800000UL; VSRL1, 0x7f8000007f800001UL ]
      []
    oracleMem
      ppc64le
      "f0201e64"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x40000000bf800000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7f8000007f800001UL ]
      []
      [ F1, 0x400000003f800000UL; VSRL1, 0x7f8000007f800001UL ]
      []
    oracleMem
      ppc64
      "f0201e64"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3e80000080000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x40200000c0200000UL ]
      []
      [ F1, 0x3e80000000000000UL; VSRL1, 0x4020000040200000UL ]
      []
    oracleMem
      ppc64le
      "f0201e64"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3e80000080000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x40200000c0200000UL ]
      []
      [ F1, 0x3e80000000000000UL; VSRL1, 0x4020000040200000UL ]
      []
    oracleMem
      ppc64
      "f0201e64"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fc000003f000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbf000000bfc00000UL ]
      []
      [ F1, 0x3fc000003f000000UL; VSRL1, 0x3f0000003fc00000UL ]
      []
    oracleMem
      ppc64le
      "f0201e64"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fc000003f000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbf000000bfc00000UL ]
      []
      [ F1, 0x3fc000003f000000UL; VSRL1, 0x3f0000003fc00000UL ]
      []

  /// <summary>
  /// xvabsdp xT, xB clears the sign bit of each double element of xB, a NaN
  /// included, and raises nothing.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVABSDP clears the sign bits``() =
    (* xvabsdp vs1,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0201f64"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4010000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbff0000000000000UL ]
      []
      [ F1, 0x4010000000000000UL; VSRL1, 0x3ff0000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201f64"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4010000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbff0000000000000UL ]
      []
      [ F1, 0x4010000000000000UL; VSRL1, 0x3ff0000000000000UL ]
      []
    oracleMem
      ppc64
      "f0201f64"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4004000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc004000000000000UL ]
      []
      [ F1, 0x4004000000000000UL; VSRL1, 0x4004000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201f64"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4004000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc004000000000000UL ]
      []
      [ F1, 0x4004000000000000UL; VSRL1, 0x4004000000000000UL ]
      []
    oracleMem
      ppc64
      "f0201f64"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fe0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfff0000000000000UL ]
      []
      [ F1, 0x3fe0000000000000UL; VSRL1, 0x7ff0000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201f64"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fe0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfff0000000000000UL ]
      []
      [ F1, 0x3fe0000000000000UL; VSRL1, 0x7ff0000000000000UL ]
      []

  /// <summary>
  /// xvnabssp xT, xB sets the sign bit of each single element of xB, a NaN
  /// included.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVNABSSP sets the sign bits``() =
    (* xvnabssp vs1,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0201ea4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x40000000bf800000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7f8000007f800001UL ]
      []
      [ F1, 0xc0000000bf800000UL; VSRL1, 0xff800000ff800001UL ]
      []
    oracleMem
      ppc64le
      "f0201ea4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x40000000bf800000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7f8000007f800001UL ]
      []
      [ F1, 0xc0000000bf800000UL; VSRL1, 0xff800000ff800001UL ]
      []
    oracleMem
      ppc64
      "f0201ea4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3e80000080000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x40200000c0200000UL ]
      []
      [ F1, 0xbe80000080000000UL; VSRL1, 0xc0200000c0200000UL ]
      []
    oracleMem
      ppc64le
      "f0201ea4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3e80000080000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x40200000c0200000UL ]
      []
      [ F1, 0xbe80000080000000UL; VSRL1, 0xc0200000c0200000UL ]
      []
    oracleMem
      ppc64
      "f0201ea4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fc000003f000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbf000000bfc00000UL ]
      []
      [ F1, 0xbfc00000bf000000UL; VSRL1, 0xbf000000bfc00000UL ]
      []
    oracleMem
      ppc64le
      "f0201ea4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fc000003f000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbf000000bfc00000UL ]
      []
      [ F1, 0xbfc00000bf000000UL; VSRL1, 0xbf000000bfc00000UL ]
      []

  /// <summary>
  /// xvnabsdp xT, xB sets the sign bit of each double element of xB, a NaN
  /// included.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVNABSDP sets the sign bits``() =
    (* xvnabsdp vs1,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0201fa4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4010000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbff0000000000000UL ]
      []
      [ F1, 0xc010000000000000UL; VSRL1, 0xbff0000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201fa4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4010000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbff0000000000000UL ]
      []
      [ F1, 0xc010000000000000UL; VSRL1, 0xbff0000000000000UL ]
      []
    oracleMem
      ppc64
      "f0201fa4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4004000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc004000000000000UL ]
      []
      [ F1, 0xc004000000000000UL; VSRL1, 0xc004000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201fa4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4004000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc004000000000000UL ]
      []
      [ F1, 0xc004000000000000UL; VSRL1, 0xc004000000000000UL ]
      []
    oracleMem
      ppc64
      "f0201fa4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fe0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfff0000000000000UL ]
      []
      [ F1, 0xbfe0000000000000UL; VSRL1, 0xfff0000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201fa4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fe0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfff0000000000000UL ]
      []
      [ F1, 0xbfe0000000000000UL; VSRL1, 0xfff0000000000000UL ]
      []

  /// <summary>
  /// xvnegsp xT, xB flips the sign bit of each single element of xB, a NaN
  /// included.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVNEGSP flips the sign bits``() =
    (* xvnegsp vs1,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0201ee4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x40000000bf800000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7f8000007f800001UL ]
      []
      [ F1, 0xc00000003f800000UL; VSRL1, 0xff800000ff800001UL ]
      []
    oracleMem
      ppc64le
      "f0201ee4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x40000000bf800000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7f8000007f800001UL ]
      []
      [ F1, 0xc00000003f800000UL; VSRL1, 0xff800000ff800001UL ]
      []
    oracleMem
      ppc64
      "f0201ee4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3e80000080000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x40200000c0200000UL ]
      []
      [ F1, 0xbe80000000000000UL; VSRL1, 0xc020000040200000UL ]
      []
    oracleMem
      ppc64le
      "f0201ee4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3e80000080000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x40200000c0200000UL ]
      []
      [ F1, 0xbe80000000000000UL; VSRL1, 0xc020000040200000UL ]
      []
    oracleMem
      ppc64
      "f0201ee4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fc000003f000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbf000000bfc00000UL ]
      []
      [ F1, 0xbfc00000bf000000UL; VSRL1, 0x3f0000003fc00000UL ]
      []
    oracleMem
      ppc64le
      "f0201ee4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fc000003f000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbf000000bfc00000UL ]
      []
      [ F1, 0xbfc00000bf000000UL; VSRL1, 0x3f0000003fc00000UL ]
      []

  /// <summary>
  /// xvcpsgnsp xT, xA, xB places in each single element of xT the magnitude of
  /// xB with the sign of xA, NaNs included.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVCPSGNSP copies the sign of xA``() =
    (* xvcpsgnsp vs1,vs2,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0221e80"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3fc00000c0100000UL
        F3, 0x404000003f000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7f8000007fc00001UL
        VSRL3, 0xff8000003f800000UL ]
      []
      [ F1, 0x40400000bf000000UL; VSRL1, 0x7f8000003f800000UL ]
      []
    oracleMem
      ppc64le
      "f0221e80"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3fc00000c0100000UL
        F3, 0x404000003f000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7f8000007fc00001UL
        VSRL3, 0xff8000003f800000UL ]
      []
      [ F1, 0x40400000bf000000UL; VSRL1, 0x7f8000003f800000UL ]
      []
    oracleMem
      ppc64
      "f0221e80"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x80000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7f8000017149f2caUL
        VSRL3, 0x400000007149f2caUL ]
      []
      [ F1, 0x80000000UL; VSRL1, 0x400000007149f2caUL ]
      []
    oracleMem
      ppc64le
      "f0221e80"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x80000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7f8000017149f2caUL
        VSRL3, 0x400000007149f2caUL ]
      []
      [ F1, 0x80000000UL; VSRL1, 0x400000007149f2caUL ]
      []
    oracleMem
      ppc64
      "f0221e80"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3eaaaaab7f7fffffUL
        F3, 0x4040000040000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x1bf800000UL
        VSRL3, 0x3f000000ffc00000UL ]
      []
      [ F1, 0x4040000040000000UL; VSRL1, 0x3f000000ffc00000UL ]
      []
    oracleMem
      ppc64le
      "f0221e80"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3eaaaaab7f7fffffUL
        F3, 0x4040000040000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x1bf800000UL
        VSRL3, 0x3f000000ffc00000UL ]
      []
      [ F1, 0x4040000040000000UL; VSRL1, 0x3f000000ffc00000UL ]
      []

  /// <summary>
  /// xvcpsgndp xT, xA, xB places in each double element of xT the magnitude of
  /// xB with the sign of xA, NaNs included.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVCPSGNDP copies the sign of xA``() =
    (* xvcpsgndp vs1,vs2,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0221f80"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3ff8000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x4000000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0221f80"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3ff8000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x4000000000000000UL ]
      []
    oracleMem
      ppc64
      "f0221f80"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff0000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x3ff0000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0221f80"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff0000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x3ff0000000000000UL ]
      []
    oracleMem
      ppc64
      "f0221f80"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7ff0000000000000UL
        F3, 0xfff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff0000000000000UL; VSRL1, 0x8000000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0221f80"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7ff0000000000000UL
        F3, 0xfff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff0000000000000UL; VSRL1, 0x8000000000000000UL ]
      []

  /// <summary>
  /// xvmaxsp xT, xA, xB places in each single element of xT the greater of the
  /// matching elements (bfp_MAXIMUM or bfp_MINIMUM): a quiet NaN loses to a
  /// number, a signalling NaN wins and comes back quiet, and +0 counts as
  /// greater than -0.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVMAXSP picks the greater of each pair``() =
    (* xvmaxsp vs1,vs2,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0221e00"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3fc00000c0100000UL
        F3, 0x404000003f000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7f8000007fc00001UL
        VSRL3, 0xff8000003f800000UL ]
      []
      [ F1, 0x404000003f000000UL; VSRL1, 0x7f8000003f800000UL ]
      []
    oracleMem
      ppc64le
      "f0221e00"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3fc00000c0100000UL
        F3, 0x404000003f000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7f8000007fc00001UL
        VSRL3, 0xff8000003f800000UL ]
      []
      [ F1, 0x404000003f000000UL; VSRL1, 0x7f8000003f800000UL ]
      []
    oracleMem
      ppc64
      "f0221e00"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x80000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7f8000017149f2caUL
        VSRL3, 0x400000007149f2caUL ]
      []
      [ F1, 0x0UL; VSRL1, 0x7fc000017149f2caUL ]
      []
    oracleMem
      ppc64le
      "f0221e00"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x80000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7f8000017149f2caUL
        VSRL3, 0x400000007149f2caUL ]
      []
      [ F1, 0x0UL; VSRL1, 0x7fc000017149f2caUL ]
      []
    oracleMem
      ppc64
      "f0221e00"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3eaaaaab7f7fffffUL
        F3, 0x4040000040000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x1bf800000UL
        VSRL3, 0x3f000000ffc00000UL ]
      []
      [ F1, 0x404000007f7fffffUL; VSRL1, 0x3f000000bf800000UL ]
      []
    oracleMem
      ppc64le
      "f0221e00"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3eaaaaab7f7fffffUL
        F3, 0x4040000040000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x1bf800000UL
        VSRL3, 0x3f000000ffc00000UL ]
      []
      [ F1, 0x404000007f7fffffUL; VSRL1, 0x3f000000bf800000UL ]
      []

  /// <summary>
  /// xvminsp xT, xA, xB places in each single element of xT the lesser of the
  /// matching elements (bfp_MAXIMUM or bfp_MINIMUM): a quiet NaN loses to a
  /// number, a signalling NaN wins and comes back quiet, and +0 counts as
  /// greater than -0.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVMINSP picks the lesser of each pair``() =
    (* xvminsp vs1,vs2,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0221e40"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3fc00000c0100000UL
        F3, 0x404000003f000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7f8000007fc00001UL
        VSRL3, 0xff8000003f800000UL ]
      []
      [ F1, 0x3fc00000c0100000UL; VSRL1, 0xff8000003f800000UL ]
      []
    oracleMem
      ppc64le
      "f0221e40"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3fc00000c0100000UL
        F3, 0x404000003f000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7f8000007fc00001UL
        VSRL3, 0xff8000003f800000UL ]
      []
      [ F1, 0x3fc00000c0100000UL; VSRL1, 0xff8000003f800000UL ]
      []
    oracleMem
      ppc64
      "f0221e40"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x80000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7f8000017149f2caUL
        VSRL3, 0x400000007149f2caUL ]
      []
      [ F1, 0x8000000080000000UL; VSRL1, 0x7fc000017149f2caUL ]
      []
    oracleMem
      ppc64le
      "f0221e40"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x80000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7f8000017149f2caUL
        VSRL3, 0x400000007149f2caUL ]
      []
      [ F1, 0x8000000080000000UL; VSRL1, 0x7fc000017149f2caUL ]
      []
    oracleMem
      ppc64
      "f0221e40"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3eaaaaab7f7fffffUL
        F3, 0x4040000040000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x1bf800000UL
        VSRL3, 0x3f000000ffc00000UL ]
      []
      [ F1, 0x3eaaaaab40000000UL; VSRL1, 0x1bf800000UL ]
      []
    oracleMem
      ppc64le
      "f0221e40"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3eaaaaab7f7fffffUL
        F3, 0x4040000040000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x1bf800000UL
        VSRL3, 0x3f000000ffc00000UL ]
      []
      [ F1, 0x3eaaaaab40000000UL; VSRL1, 0x1bf800000UL ]
      []

  /// <summary>
  /// xvmaxdp xT, xA, xB places in each double element of xT the greater of the
  /// matching elements (bfp_MAXIMUM or bfp_MINIMUM): a quiet NaN loses to a
  /// number, a signalling NaN wins and comes back quiet, and +0 counts as
  /// greater than -0.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVMAXDP picks the greater of each pair``() =
    (* xvmaxdp vs1,vs2,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0221f00"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3ff8000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ F1, 0x3ff8000000000000UL; VSRL1, 0x4000000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0221f00"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3ff8000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ F1, 0x3ff8000000000000UL; VSRL1, 0x4000000000000000UL ]
      []
    oracleMem
      ppc64
      "f0221f00"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff0000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x7ff8000000000001UL ]
      []
    oracleMem
      ppc64le
      "f0221f00"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff0000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x7ff8000000000001UL ]
      []
    oracleMem
      ppc64
      "f0221f00"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7ff0000000000000UL
        F3, 0xfff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff0000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221f00"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7ff0000000000000UL
        F3, 0xfff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff0000000000000UL; VSRL1, 0x0UL ]
      []

  /// <summary>
  /// xvmindp xT, xA, xB places in each double element of xT the lesser of the
  /// matching elements (bfp_MAXIMUM or bfp_MINIMUM): a quiet NaN loses to a
  /// number, a signalling NaN wins and comes back quiet, and +0 counts as
  /// greater than -0.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVMINDP picks the lesser of each pair``() =
    (* xvmindp vs1,vs2,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0221f40"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3ff8000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ F1, 0x8000000000000000UL; VSRL1, 0x4000000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0221f40"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3ff8000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ F1, 0x8000000000000000UL; VSRL1, 0x4000000000000000UL ]
      []
    oracleMem
      ppc64
      "f0221f40"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff0000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x8000000000000000UL; VSRL1, 0x7ff8000000000001UL ]
      []
    oracleMem
      ppc64le
      "f0221f40"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff0000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x8000000000000000UL; VSRL1, 0x7ff8000000000001UL ]
      []
    oracleMem
      ppc64
      "f0221f40"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7ff0000000000000UL
        F3, 0xfff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0xfff0000000000000UL; VSRL1, 0x8000000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0221f40"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7ff0000000000000UL
        F3, 0xfff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0xfff0000000000000UL; VSRL1, 0x8000000000000000UL ]
      []

  /// <summary>
  /// xsmaxcdp xT, xA, xB places in doubleword 0 of xT the greater of the
  /// doubles in doubleword 0 of xA and xB, or the one from xB, as it is, when
  /// either is a NaN or the two compare equal (+0 and -0 among them), and
  /// clears doubleword 1. For xA = +0 and xB = -0 the manual's Table 87 gives
  /// xB, -0; QEMU 8.2.2 gives +0, and the manual's -0 is asserted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSMAXCDP gives xB on a NaN or a tie``() =
    (* xsmaxcdp vs1,vs2,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0221c00"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3ff8000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ F1, 0x3ff8000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221c00"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3ff8000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ F1, 0x3ff8000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "f0221c00"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7ff0000000000000UL
        F3, 0xfff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff0000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221c00"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7ff0000000000000UL
        F3, 0xfff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff0000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "f0221c00"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff0000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ VSRL1, 0x0UL; F1, 0x8000000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0221c00"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff0000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ VSRL1, 0x0UL; F1, 0x8000000000000000UL ]
      []

  /// <summary>
  /// xsmincdp xT, xA, xB places in doubleword 0 of xT the lesser of the doubles
  /// in doubleword 0 of xA and xB, or the one from xB, as it is, when either is
  /// a NaN or the two compare equal (+0 and -0 among them), and clears
  /// doubleword 1.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSMINCDP gives xB on a NaN or a tie``() =
    (* xsmincdp vs1,vs2,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0221c40"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3ff8000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ F1, 0x8000000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221c40"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3ff8000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ F1, 0x8000000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "f0221c40"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff0000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x8000000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221c40"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff0000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x8000000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "f0221c40"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7ff0000000000000UL
        F3, 0xfff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0xfff0000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221c40"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7ff0000000000000UL
        F3, 0xfff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0xfff0000000000000UL; VSRL1, 0x0UL ]
      []

  /// <summary>
  /// xsmaxjdp xT, xA, xB places in doubleword 0 of xT the greater of the
  /// doubles in doubleword 0 of xA and xB; a NaN in xA, and then one in xB,
  /// passes as it is, unquieted; two zeroes give +0 if either is; doubleword 1
  /// is cleared.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSMAXJDP passes a NaN through``() =
    (* xsmaxjdp vs1,vs2,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0221c80"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3ff8000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ F1, 0x3ff8000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221c80"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3ff8000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ F1, 0x3ff8000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "f0221c80"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff0000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221c80"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff0000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "f0221c80"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7ff0000000000000UL
        F3, 0xfff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff0000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221c80"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7ff0000000000000UL
        F3, 0xfff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff0000000000000UL; VSRL1, 0x0UL ]
      []

  /// <summary>
  /// xsminjdp xT, xA, xB places in doubleword 0 of xT the lesser of the doubles
  /// in doubleword 0 of xA and xB; a NaN in xA, and then one in xB, passes as
  /// it is, unquieted; two zeroes give -0 if either is; doubleword 1 is
  /// cleared.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSMINJDP passes a NaN through``() =
    (* xsminjdp vs1,vs2,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0221cc0"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3ff8000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ F1, 0x8000000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221cc0"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3ff8000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ F1, 0x8000000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "f0221cc0"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff0000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x8000000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221cc0"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff0000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x8000000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64
      "f0221cc0"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7ff0000000000000UL
        F3, 0xfff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0xfff0000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221cc0"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7ff0000000000000UL
        F3, 0xfff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0xfff0000000000000UL; VSRL1, 0x0UL ]
      []

  /// <summary>
  /// xvrspi xT, xB rounds each single element of xB to an integral value to
  /// nearest, ties away from zero, a signalling NaN coming back quiet; the
  /// operands include the ties 2.5, -2.5, 0.5 and -1.5.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVRSPI rounds singles to integral values``() =
    (* xvrspi vs1,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0201a24"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3e80000080000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x40200000c0200000UL ]
      []
      [ F1, 0x80000000UL; VSRL1, 0x40400000c0400000UL ]
      []
    oracleMem
      ppc64le
      "f0201a24"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3e80000080000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x40200000c0200000UL ]
      []
      [ F1, 0x80000000UL; VSRL1, 0x40400000c0400000UL ]
      []
    oracleMem
      ppc64
      "f0201a24"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fc000003f000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbf000000bfc00000UL ]
      []
      [ F1, 0x400000003f800000UL; VSRL1, 0xbf800000c0000000UL ]
      []
    oracleMem
      ppc64le
      "f0201a24"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fc000003f000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbf000000bfc00000UL ]
      []
      [ F1, 0x400000003f800000UL; VSRL1, 0xbf800000c0000000UL ]
      []

  /// <summary>
  /// xvrspic xT, xB rounds each single element of xB to an integral value in
  /// the direction FPSCR[RN] names, to nearest here, a signalling NaN coming
  /// back quiet; the operands include the ties 2.5, -2.5, 0.5 and -1.5.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVRSPIC rounds singles to integral values``() =
    (* xvrspic vs1,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0201aac"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3e80000080000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x40200000c0200000UL ]
      []
      [ F1, 0x80000000UL; VSRL1, 0x40000000c0000000UL ]
      []
    oracleMem
      ppc64le
      "f0201aac"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3e80000080000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x40200000c0200000UL ]
      []
      [ F1, 0x80000000UL; VSRL1, 0x40000000c0000000UL ]
      []
    oracleMem
      ppc64
      "f0201aac"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fc000003f000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbf000000bfc00000UL ]
      []
      [ F1, 0x4000000000000000UL; VSRL1, 0x80000000c0000000UL ]
      []
    oracleMem
      ppc64le
      "f0201aac"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fc000003f000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbf000000bfc00000UL ]
      []
      [ F1, 0x4000000000000000UL; VSRL1, 0x80000000c0000000UL ]
      []

  /// <summary>
  /// xvrspim xT, xB rounds each single element of xB to an integral value
  /// toward -Inf, a signalling NaN coming back quiet; the operands include the
  /// ties 2.5, -2.5, 0.5 and -1.5.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVRSPIM rounds singles to integral values``() =
    (* xvrspim vs1,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0201ae4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3e80000080000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x40200000c0200000UL ]
      []
      [ F1, 0x80000000UL; VSRL1, 0x40000000c0400000UL ]
      []
    oracleMem
      ppc64le
      "f0201ae4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3e80000080000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x40200000c0200000UL ]
      []
      [ F1, 0x80000000UL; VSRL1, 0x40000000c0400000UL ]
      []
    oracleMem
      ppc64
      "f0201ae4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fc000003f000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbf000000bfc00000UL ]
      []
      [ F1, 0x3f80000000000000UL; VSRL1, 0xbf800000c0000000UL ]
      []
    oracleMem
      ppc64le
      "f0201ae4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fc000003f000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbf000000bfc00000UL ]
      []
      [ F1, 0x3f80000000000000UL; VSRL1, 0xbf800000c0000000UL ]
      []

  /// <summary>
  /// xvrspip xT, xB rounds each single element of xB to an integral value
  /// toward +Inf, a signalling NaN coming back quiet; the operands include the
  /// ties 2.5, -2.5, 0.5 and -1.5.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVRSPIP rounds singles to integral values``() =
    (* xvrspip vs1,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0201aa4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3e80000080000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x40200000c0200000UL ]
      []
      [ F1, 0x3f80000080000000UL; VSRL1, 0x40400000c0000000UL ]
      []
    oracleMem
      ppc64le
      "f0201aa4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3e80000080000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x40200000c0200000UL ]
      []
      [ F1, 0x3f80000080000000UL; VSRL1, 0x40400000c0000000UL ]
      []
    oracleMem
      ppc64
      "f0201aa4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fc000003f000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbf000000bfc00000UL ]
      []
      [ F1, 0x400000003f800000UL; VSRL1, 0x80000000bf800000UL ]
      []
    oracleMem
      ppc64le
      "f0201aa4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fc000003f000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbf000000bfc00000UL ]
      []
      [ F1, 0x400000003f800000UL; VSRL1, 0x80000000bf800000UL ]
      []

  /// <summary>
  /// xvrspiz xT, xB rounds each single element of xB to an integral value
  /// toward zero, a signalling NaN coming back quiet; the operands include the
  /// ties 2.5, -2.5, 0.5 and -1.5.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVRSPIZ rounds singles to integral values``() =
    (* xvrspiz vs1,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0201a64"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3e80000080000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x40200000c0200000UL ]
      []
      [ F1, 0x80000000UL; VSRL1, 0x40000000c0000000UL ]
      []
    oracleMem
      ppc64le
      "f0201a64"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3e80000080000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x40200000c0200000UL ]
      []
      [ F1, 0x80000000UL; VSRL1, 0x40000000c0000000UL ]
      []
    oracleMem
      ppc64
      "f0201a64"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fc000003f000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbf000000bfc00000UL ]
      []
      [ F1, 0x3f80000000000000UL; VSRL1, 0x80000000bf800000UL ]
      []
    oracleMem
      ppc64le
      "f0201a64"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fc000003f000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbf000000bfc00000UL ]
      []
      [ F1, 0x3f80000000000000UL; VSRL1, 0x80000000bf800000UL ]
      []

  /// <summary>
  /// xvrdpi xT, xB rounds each double element of xB to an integral value to
  /// nearest, ties away from zero, a signalling NaN coming back quiet.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVRDPI rounds doubles to integral values``() =
    (* xvrdpi vs1,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0201b24"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4010000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbff0000000000000UL ]
      []
      [ F1, 0x4010000000000000UL; VSRL1, 0xbff0000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201b24"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4010000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbff0000000000000UL ]
      []
      [ F1, 0x4010000000000000UL; VSRL1, 0xbff0000000000000UL ]
      []
    oracleMem
      ppc64
      "f0201b24"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4004000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc004000000000000UL ]
      []
      [ F1, 0x4008000000000000UL; VSRL1, 0xc008000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201b24"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4004000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc004000000000000UL ]
      []
      [ F1, 0x4008000000000000UL; VSRL1, 0xc008000000000000UL ]
      []
    oracleMem
      ppc64
      "f0201b24"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fe0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfff0000000000000UL ]
      []
      [ F1, 0x3ff0000000000000UL; VSRL1, 0xfff0000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201b24"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fe0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfff0000000000000UL ]
      []
      [ F1, 0x3ff0000000000000UL; VSRL1, 0xfff0000000000000UL ]
      []
    oracleMem
      ppc64
      "f0201b24"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff0000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff8000000000001UL; VSRL1, 0x8000000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201b24"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff0000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff8000000000001UL; VSRL1, 0x8000000000000000UL ]
      []

  /// <summary>
  /// xvrdpic xT, xB rounds each double element of xB to an integral value in
  /// the direction FPSCR[RN] names, to nearest here, a signalling NaN coming
  /// back quiet.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVRDPIC rounds doubles to integral values``() =
    (* xvrdpic vs1,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0201bac"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4010000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbff0000000000000UL ]
      []
      [ F1, 0x4010000000000000UL; VSRL1, 0xbff0000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201bac"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4010000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbff0000000000000UL ]
      []
      [ F1, 0x4010000000000000UL; VSRL1, 0xbff0000000000000UL ]
      []
    oracleMem
      ppc64
      "f0201bac"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4004000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc004000000000000UL ]
      []
      [ F1, 0x4000000000000000UL; VSRL1, 0xc000000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201bac"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4004000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc004000000000000UL ]
      []
      [ F1, 0x4000000000000000UL; VSRL1, 0xc000000000000000UL ]
      []
    oracleMem
      ppc64
      "f0201bac"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fe0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0xfff0000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201bac"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fe0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0xfff0000000000000UL ]
      []
    oracleMem
      ppc64
      "f0201bac"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff0000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff8000000000001UL; VSRL1, 0x8000000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201bac"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff0000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff8000000000001UL; VSRL1, 0x8000000000000000UL ]
      []

  /// <summary>
  /// xvrdpim xT, xB rounds each double element of xB to an integral value
  /// toward -Inf, a signalling NaN coming back quiet.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVRDPIM rounds doubles to integral values``() =
    (* xvrdpim vs1,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0201be4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4010000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbff0000000000000UL ]
      []
      [ F1, 0x4010000000000000UL; VSRL1, 0xbff0000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201be4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4010000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbff0000000000000UL ]
      []
      [ F1, 0x4010000000000000UL; VSRL1, 0xbff0000000000000UL ]
      []
    oracleMem
      ppc64
      "f0201be4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4004000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc004000000000000UL ]
      []
      [ F1, 0x4000000000000000UL; VSRL1, 0xc008000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201be4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4004000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc004000000000000UL ]
      []
      [ F1, 0x4000000000000000UL; VSRL1, 0xc008000000000000UL ]
      []
    oracleMem
      ppc64
      "f0201be4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fe0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0xfff0000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201be4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fe0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0xfff0000000000000UL ]
      []
    oracleMem
      ppc64
      "f0201be4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff0000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff8000000000001UL; VSRL1, 0x8000000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201be4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff0000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff8000000000001UL; VSRL1, 0x8000000000000000UL ]
      []

  /// <summary>
  /// xvrdpip xT, xB rounds each double element of xB to an integral value
  /// toward +Inf, a signalling NaN coming back quiet.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVRDPIP rounds doubles to integral values``() =
    (* xvrdpip vs1,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0201ba4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4010000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbff0000000000000UL ]
      []
      [ F1, 0x4010000000000000UL; VSRL1, 0xbff0000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201ba4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4010000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbff0000000000000UL ]
      []
      [ F1, 0x4010000000000000UL; VSRL1, 0xbff0000000000000UL ]
      []
    oracleMem
      ppc64
      "f0201ba4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4004000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc004000000000000UL ]
      []
      [ F1, 0x4008000000000000UL; VSRL1, 0xc000000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201ba4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4004000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc004000000000000UL ]
      []
      [ F1, 0x4008000000000000UL; VSRL1, 0xc000000000000000UL ]
      []
    oracleMem
      ppc64
      "f0201ba4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fe0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfff0000000000000UL ]
      []
      [ F1, 0x3ff0000000000000UL; VSRL1, 0xfff0000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201ba4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fe0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfff0000000000000UL ]
      []
      [ F1, 0x3ff0000000000000UL; VSRL1, 0xfff0000000000000UL ]
      []
    oracleMem
      ppc64
      "f0201ba4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff0000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff8000000000001UL; VSRL1, 0x8000000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201ba4"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff0000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff8000000000001UL; VSRL1, 0x8000000000000000UL ]
      []

  /// <summary>
  /// xvrdpiz xT, xB rounds each double element of xB to an integral value
  /// toward zero, a signalling NaN coming back quiet.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVRDPIZ rounds doubles to integral values``() =
    (* xvrdpiz vs1,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0201b64"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4010000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbff0000000000000UL ]
      []
      [ F1, 0x4010000000000000UL; VSRL1, 0xbff0000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201b64"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4010000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbff0000000000000UL ]
      []
      [ F1, 0x4010000000000000UL; VSRL1, 0xbff0000000000000UL ]
      []
    oracleMem
      ppc64
      "f0201b64"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4004000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc004000000000000UL ]
      []
      [ F1, 0x4000000000000000UL; VSRL1, 0xc000000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201b64"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4004000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc004000000000000UL ]
      []
      [ F1, 0x4000000000000000UL; VSRL1, 0xc000000000000000UL ]
      []
    oracleMem
      ppc64
      "f0201b64"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fe0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0xfff0000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201b64"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fe0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0xfff0000000000000UL ]
      []
    oracleMem
      ppc64
      "f0201b64"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff0000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff8000000000001UL; VSRL1, 0x8000000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201b64"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff0000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff8000000000001UL; VSRL1, 0x8000000000000000UL ]
      []

  /// <summary>
  /// xsrdpic xT, xB rounds the double in doubleword 0 of xB to an integral
  /// value in the direction FPSCR[RN] names (to nearest, ties to even, here),
  /// clears doubleword 1 and sets FPRF.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSRDPIC rounds in the FPSCR direction``() =
    (* xsrdpic vs1,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f02019ac"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4010000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbff0000000000000UL ]
      []
      [ F1, 0x4010000000000000UL; VSRL1, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "f02019ac"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4010000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbff0000000000000UL ]
      []
      [ F1, 0x4010000000000000UL; VSRL1, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64
      "f02019ac"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4004000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc004000000000000UL ]
      []
      [ F1, 0x4000000000000000UL; VSRL1, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "f02019ac"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4004000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc004000000000000UL ]
      []
      [ F1, 0x4000000000000000UL; VSRL1, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64
      "f02019ac"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fe0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "f02019ac"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3fe0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64
      "f02019ac"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff0000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff8000000000001UL; VSRL1, 0x0UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64le
      "f02019ac"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff0000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff8000000000001UL; VSRL1, 0x0UL; FPSCR, 0x11UL ]
      []

  /// <summary>
  /// xvresp xT, xB places in each single element of xT an estimate of the
  /// reciprocal of the matching element of xB. The vectors hold only operands
  /// whose answer the manual fixes exactly: signed zeroes and infinities, NaNs,
  /// and a negative number.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVRESP answers the special values exactly``() =
    (* xvresp vs1,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0201a68"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x80000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7f800000ff800000UL ]
      []
      [ F1, 0x7f800000ff800000UL; VSRL1, 0x80000000UL ]
      []
    oracleMem
      ppc64le
      "f0201a68"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x80000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7f800000ff800000UL ]
      []
      [ F1, 0x7f800000ff800000UL; VSRL1, 0x80000000UL ]
      []
    oracleMem
      ppc64
      "f0201a68"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7fc000017f800001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xffc00000bf800000UL ]
      []
      [ F1, 0x7fc000017fc00001UL; VSRL1, 0xffc00000bf800000UL ]
      []
    oracleMem
      ppc64le
      "f0201a68"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7fc000017f800001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xffc00000bf800000UL ]
      []
      [ F1, 0x7fc000017fc00001UL; VSRL1, 0xffc00000bf800000UL ]
      []

  /// <summary>
  /// xvrsqrtesp xT, xB places in each single element of xT an estimate of the
  /// reciprocal square root of the matching element of xB. The vectors hold
  /// only operands whose answer the manual fixes exactly: signed zeroes and
  /// infinities, NaNs, and a negative number.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVRSQRTESP answers the special values exactly``() =
    (* xvrsqrtesp vs1,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0201a28"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x80000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7f800000ff800000UL ]
      []
      [ F1, 0x7f800000ff800000UL; VSRL1, 0x7fc00000UL ]
      []
    oracleMem
      ppc64le
      "f0201a28"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x80000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7f800000ff800000UL ]
      []
      [ F1, 0x7f800000ff800000UL; VSRL1, 0x7fc00000UL ]
      []
    oracleMem
      ppc64
      "f0201a28"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7fc000017f800001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xffc00000bf800000UL ]
      []
      [ F1, 0x7fc000017fc00001UL; VSRL1, 0xffc000007fc00000UL ]
      []
    oracleMem
      ppc64le
      "f0201a28"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7fc000017f800001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xffc00000bf800000UL ]
      []
      [ F1, 0x7fc000017fc00001UL; VSRL1, 0xffc000007fc00000UL ]
      []

  /// <summary>
  /// xvredp xT, xB places in each double element of xT an estimate of the
  /// reciprocal of the matching element of xB, at operands whose answer the
  /// manual fixes exactly.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVREDP answers the special values exactly``() =
    (* xvredp vs1,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0201b68"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff0000000000000UL; VSRL1, 0xfff0000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201b68"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff0000000000000UL; VSRL1, 0xfff0000000000000UL ]
      []
    oracleMem
      ppc64
      "f0201b68"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x8000000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201b68"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x8000000000000000UL ]
      []
    oracleMem
      ppc64
      "f0201b68"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff8000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7ff0000000000001UL ]
      []
      [ F1, 0x7ff8000000000001UL; VSRL1, 0x7ff8000000000001UL ]
      []
    oracleMem
      ppc64le
      "f0201b68"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff8000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7ff0000000000001UL ]
      []
      [ F1, 0x7ff8000000000001UL; VSRL1, 0x7ff8000000000001UL ]
      []

  /// <summary>
  /// xvrsqrtedp xT, xB places in each double element of xT an estimate of the
  /// reciprocal square root of the matching element of xB, at operands whose
  /// answer the manual fixes exactly.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVRSQRTEDP answers the special values exactly``() =
    (* xvrsqrtedp vs1,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0201b28"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff0000000000000UL; VSRL1, 0xfff0000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201b28"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff0000000000000UL; VSRL1, 0xfff0000000000000UL ]
      []
    oracleMem
      ppc64
      "f0201b28"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x7ff8000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201b28"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x7ff8000000000000UL ]
      []
    oracleMem
      ppc64
      "f0201b28"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff8000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7ff0000000000001UL ]
      []
      [ F1, 0x7ff8000000000001UL; VSRL1, 0x7ff8000000000001UL ]
      []
    oracleMem
      ppc64le
      "f0201b28"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff8000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7ff0000000000001UL ]
      []
      [ F1, 0x7ff8000000000001UL; VSRL1, 0x7ff8000000000001UL ]
      []

  /// <summary>
  /// xsredp xT, xB places in doubleword 0 of xT an estimate of the reciprocal
  /// of the double in doubleword 0 of xB, clears doubleword 1 and sets FPRF, at
  /// operands whose answer the manual fixes exactly.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSREDP answers the special values exactly``() =
    (* xsredp vs1,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0201968"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff0000000000000UL; VSRL1, 0x0UL; FPSCR, 0x5UL ]
      []
    oracleMem
      ppc64le
      "f0201968"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff0000000000000UL; VSRL1, 0x0UL; FPSCR, 0x5UL ]
      []
    oracleMem
      ppc64
      "f0201968"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "f0201968"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64
      "f0201968"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff8000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7ff0000000000001UL ]
      []
      [ F1, 0x7ff8000000000001UL; VSRL1, 0x0UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64le
      "f0201968"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff8000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7ff0000000000001UL ]
      []
      [ F1, 0x7ff8000000000001UL; VSRL1, 0x0UL; FPSCR, 0x11UL ]
      []

  /// <summary>
  /// xsrsqrtedp xT, xB places in doubleword 0 of xT an estimate of the
  /// reciprocal square root of the double in doubleword 0 of xB, clears
  /// doubleword 1 and sets FPRF, at operands whose answer the manual fixes
  /// exactly.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSRSQRTEDP answers the special values exactly``() =
    (* xsrsqrtedp vs1,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0201928"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff0000000000000UL; VSRL1, 0x0UL; FPSCR, 0x5UL ]
      []
    oracleMem
      ppc64le
      "f0201928"
      [ F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff0000000000000UL; VSRL1, 0x0UL; FPSCR, 0x5UL ]
      []
    oracleMem
      ppc64
      "f0201928"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "f0201928"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64
      "f0201928"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff8000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7ff0000000000001UL ]
      []
      [ F1, 0x7ff8000000000001UL; VSRL1, 0x0UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64le
      "f0201928"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff8000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7ff0000000000001UL ]
      []
      [ F1, 0x7ff8000000000001UL; VSRL1, 0x0UL; FPSCR, 0x11UL ]
      []

  /// <summary>
  /// xvmaddadp xT, xA, xB places in each double element of xT xA times xB plus
  /// xT, the product exact and the sum rounded once. Which NaN comes back
  /// follows the order xA, then the addend, then the other factor, quieted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVMADDADP is fused``() =
    (* xvmaddadp vs1,vs2,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0221b08"
      [ F1, 0x4010000000000000UL
        F2, 0x3ff8000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbff0000000000000UL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ VSRL1, 0x7ff8000000000001UL; F1, 0x4010000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0221b08"
      [ F1, 0x4010000000000000UL
        F2, 0x3ff8000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbff0000000000000UL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ VSRL1, 0x7ff8000000000001UL; F1, 0x4010000000000000UL ]
      []
    oracleMem
      ppc64
      "f0221b08"
      [ F1, 0x4004000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xc004000000000000UL
        VSRL2, 0x7ff0000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ VSRL1, 0x7ff8000000000001UL; F1, 0x4004000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0221b08"
      [ F1, 0x4004000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xc004000000000000UL
        VSRL2, 0x7ff0000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ VSRL1, 0x7ff8000000000001UL; F1, 0x4004000000000000UL ]
      []
    oracleMem
      ppc64
      "f0221b08"
      [ F1, 0x3fe0000000000000UL
        F2, 0x7ff0000000000000UL
        F3, 0xfff0000000000000UL
        VSRL1, 0xfff0000000000000UL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0xfff0000000000000UL; VSRL1, 0xfff0000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0221b08"
      [ F1, 0x3fe0000000000000UL
        F2, 0x7ff0000000000000UL
        F3, 0xfff0000000000000UL
        VSRL1, 0xfff0000000000000UL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0xfff0000000000000UL; VSRL1, 0xfff0000000000000UL ]
      []

  /// <summary>
  /// xvmaddasp xT, xA, xB places in each single element of xT xA times xB plus
  /// xT, the product exact and the sum rounded once. Which NaN comes back
  /// follows the order xA, then the addend, then the other factor, quieted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVMADDASP is fused``() =
    (* xvmaddasp vs1,vs2,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0221a08"
      [ F1, 0x40000000bf800000UL
        F2, 0x3fc00000c0100000UL
        F3, 0x404000003f000000UL
        VSRL1, 0x7f8000007f800001UL
        VSRL2, 0x7f8000007fc00001UL
        VSRL3, 0xff8000003f800000UL ]
      []
      [ F1, 0x40d00000c0080000UL; VSRL1, 0x7fc000007fc00001UL ]
      []
    oracleMem
      ppc64le
      "f0221a08"
      [ F1, 0x40000000bf800000UL
        F2, 0x3fc00000c0100000UL
        F3, 0x404000003f000000UL
        VSRL1, 0x7f8000007f800001UL
        VSRL2, 0x7f8000007fc00001UL
        VSRL3, 0xff8000003f800000UL ]
      []
      [ F1, 0x40d00000c0080000UL; VSRL1, 0x7fc000007fc00001UL ]
      []
    oracleMem
      ppc64
      "f0221a08"
      [ F1, 0x3e80000080000000UL
        F2, 0x80000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0x40200000c0200000UL
        VSRL2, 0x7f8000017149f2caUL
        VSRL3, 0x400000007149f2caUL ]
      []
      [ VSRL1, 0x7fc000017f800000UL; F1, 0x3e80000080000000UL ]
      []
    oracleMem
      ppc64le
      "f0221a08"
      [ F1, 0x3e80000080000000UL
        F2, 0x80000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0x40200000c0200000UL
        VSRL2, 0x7f8000017149f2caUL
        VSRL3, 0x400000007149f2caUL ]
      []
      [ VSRL1, 0x7fc000017f800000UL; F1, 0x3e80000080000000UL ]
      []
    oracleMem
      ppc64
      "f0221a08"
      [ F1, 0x3fc000003f000000UL
        F2, 0x3eaaaaab7f7fffffUL
        F3, 0x4040000040000000UL
        VSRL1, 0xbf000000bfc00000UL
        VSRL2, 0x1bf800000UL
        VSRL3, 0x3f000000ffc00000UL ]
      []
      [ F1, 0x402000007f800000UL; VSRL1, 0xbf000000ffc00000UL ]
      []
    oracleMem
      ppc64le
      "f0221a08"
      [ F1, 0x3fc000003f000000UL
        F2, 0x3eaaaaab7f7fffffUL
        F3, 0x4040000040000000UL
        VSRL1, 0xbf000000bfc00000UL
        VSRL2, 0x1bf800000UL
        VSRL3, 0x3f000000ffc00000UL ]
      []
      [ F1, 0x402000007f800000UL; VSRL1, 0xbf000000ffc00000UL ]
      []

  /// <summary>
  /// xvmaddmdp xT, xA, xB places in each double element of xT xA times xT plus
  /// xB, the product exact and the sum rounded once. Which NaN comes back
  /// follows the order xA, then the addend, then the other factor, quieted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVMADDMDP is fused``() =
    (* xvmaddmdp vs1,vs2,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0221b48"
      [ F1, 0x4010000000000000UL
        F2, 0x3ff8000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbff0000000000000UL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ F1, 0x4018000000000000UL; VSRL1, 0x7ff8000000000001UL ]
      []
    oracleMem
      ppc64le
      "f0221b48"
      [ F1, 0x4010000000000000UL
        F2, 0x3ff8000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbff0000000000000UL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ F1, 0x4018000000000000UL; VSRL1, 0x7ff8000000000001UL ]
      []
    oracleMem
      ppc64
      "f0221b48"
      [ F1, 0x4004000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xc004000000000000UL
        VSRL2, 0x7ff0000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x7ff8000000000001UL ]
      []
    oracleMem
      ppc64le
      "f0221b48"
      [ F1, 0x4004000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xc004000000000000UL
        VSRL2, 0x7ff0000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x7ff8000000000001UL ]
      []
    oracleMem
      ppc64
      "f0221b48"
      [ F1, 0x3fe0000000000000UL
        F2, 0x7ff0000000000000UL
        F3, 0xfff0000000000000UL
        VSRL1, 0xfff0000000000000UL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff8000000000000UL; VSRL1, 0x7ff8000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0221b48"
      [ F1, 0x3fe0000000000000UL
        F2, 0x7ff0000000000000UL
        F3, 0xfff0000000000000UL
        VSRL1, 0xfff0000000000000UL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff8000000000000UL; VSRL1, 0x7ff8000000000000UL ]
      []

  /// <summary>
  /// xvmaddmsp xT, xA, xB places in each single element of xT xA times xT plus
  /// xB, the product exact and the sum rounded once. Which NaN comes back
  /// follows the order xA, then the addend, then the other factor, quieted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVMADDMSP is fused``() =
    (* xvmaddmsp vs1,vs2,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0221a48"
      [ F1, 0x40000000bf800000UL
        F2, 0x3fc00000c0100000UL
        F3, 0x404000003f000000UL
        VSRL1, 0x7f8000007f800001UL
        VSRL2, 0x7f8000007fc00001UL
        VSRL3, 0xff8000003f800000UL ]
      []
      [ F1, 0x40c0000040300000UL; VSRL1, 0x7fc000007fc00001UL ]
      []
    oracleMem
      ppc64le
      "f0221a48"
      [ F1, 0x40000000bf800000UL
        F2, 0x3fc00000c0100000UL
        F3, 0x404000003f000000UL
        VSRL1, 0x7f8000007f800001UL
        VSRL2, 0x7f8000007fc00001UL
        VSRL3, 0xff8000003f800000UL ]
      []
      [ F1, 0x40c0000040300000UL; VSRL1, 0x7fc000007fc00001UL ]
      []
    oracleMem
      ppc64
      "f0221a48"
      [ F1, 0x3e80000080000000UL
        F2, 0x80000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0x40200000c0200000UL
        VSRL2, 0x7f8000017149f2caUL
        VSRL3, 0x400000007149f2caUL ]
      []
      [ F1, 0x0UL; VSRL1, 0x7fc00001f1977618UL ]
      []
    oracleMem
      ppc64le
      "f0221a48"
      [ F1, 0x3e80000080000000UL
        F2, 0x80000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0x40200000c0200000UL
        VSRL2, 0x7f8000017149f2caUL
        VSRL3, 0x400000007149f2caUL ]
      []
      [ F1, 0x0UL; VSRL1, 0x7fc00001f1977618UL ]
      []
    oracleMem
      ppc64
      "f0221a48"
      [ F1, 0x3fc000003f000000UL
        F2, 0x3eaaaaab7f7fffffUL
        F3, 0x4040000040000000UL
        VSRL1, 0xbf000000bfc00000UL
        VSRL2, 0x1bf800000UL
        VSRL3, 0x3f000000ffc00000UL ]
      []
      [ F1, 0x406000007effffffUL; VSRL1, 0x3f000000ffc00000UL ]
      []
    oracleMem
      ppc64le
      "f0221a48"
      [ F1, 0x3fc000003f000000UL
        F2, 0x3eaaaaab7f7fffffUL
        F3, 0x4040000040000000UL
        VSRL1, 0xbf000000bfc00000UL
        VSRL2, 0x1bf800000UL
        VSRL3, 0x3f000000ffc00000UL ]
      []
      [ F1, 0x406000007effffffUL; VSRL1, 0x3f000000ffc00000UL ]
      []

  /// <summary>
  /// xvmsubadp xT, xA, xB places in each double element of xT xA times xB minus
  /// xT, the product exact and the sum rounded once. Which NaN comes back
  /// follows the order xA, then the addend, then the other factor, quieted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVMSUBADP is fused``() =
    (* xvmsubadp vs1,vs2,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0221b88"
      [ F1, 0x4010000000000000UL
        F2, 0x3ff8000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbff0000000000000UL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ F1, 0xc010000000000000UL; VSRL1, 0x7ff8000000000001UL ]
      []
    oracleMem
      ppc64le
      "f0221b88"
      [ F1, 0x4010000000000000UL
        F2, 0x3ff8000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbff0000000000000UL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ F1, 0xc010000000000000UL; VSRL1, 0x7ff8000000000001UL ]
      []
    oracleMem
      ppc64
      "f0221b88"
      [ F1, 0x4004000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xc004000000000000UL
        VSRL2, 0x7ff0000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0xc004000000000000UL; VSRL1, 0x7ff8000000000001UL ]
      []
    oracleMem
      ppc64le
      "f0221b88"
      [ F1, 0x4004000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xc004000000000000UL
        VSRL2, 0x7ff0000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0xc004000000000000UL; VSRL1, 0x7ff8000000000001UL ]
      []
    oracleMem
      ppc64
      "f0221b88"
      [ F1, 0x3fe0000000000000UL
        F2, 0x7ff0000000000000UL
        F3, 0xfff0000000000000UL
        VSRL1, 0xfff0000000000000UL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0xfff0000000000000UL; VSRL1, 0x7ff0000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0221b88"
      [ F1, 0x3fe0000000000000UL
        F2, 0x7ff0000000000000UL
        F3, 0xfff0000000000000UL
        VSRL1, 0xfff0000000000000UL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0xfff0000000000000UL; VSRL1, 0x7ff0000000000000UL ]
      []

  /// <summary>
  /// xvmsubasp xT, xA, xB places in each single element of xT xA times xB minus
  /// xT, the product exact and the sum rounded once. Which NaN comes back
  /// follows the order xA, then the addend, then the other factor, quieted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVMSUBASP is fused``() =
    (* xvmsubasp vs1,vs2,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0221a88"
      [ F1, 0x40000000bf800000UL
        F2, 0x3fc00000c0100000UL
        F3, 0x404000003f000000UL
        VSRL1, 0x7f8000007f800001UL
        VSRL2, 0x7f8000007fc00001UL
        VSRL3, 0xff8000003f800000UL ]
      []
      [ F1, 0x40200000be000000UL; VSRL1, 0xff8000007fc00001UL ]
      []
    oracleMem
      ppc64le
      "f0221a88"
      [ F1, 0x40000000bf800000UL
        F2, 0x3fc00000c0100000UL
        F3, 0x404000003f000000UL
        VSRL1, 0x7f8000007f800001UL
        VSRL2, 0x7f8000007fc00001UL
        VSRL3, 0xff8000003f800000UL ]
      []
      [ F1, 0x40200000be000000UL; VSRL1, 0xff8000007fc00001UL ]
      []
    oracleMem
      ppc64
      "f0221a88"
      [ F1, 0x3e80000080000000UL
        F2, 0x80000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0x40200000c0200000UL
        VSRL2, 0x7f8000017149f2caUL
        VSRL3, 0x400000007149f2caUL ]
      []
      [ F1, 0xbe80000000000000UL; VSRL1, 0x7fc000017f800000UL ]
      []
    oracleMem
      ppc64le
      "f0221a88"
      [ F1, 0x3e80000080000000UL
        F2, 0x80000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0x40200000c0200000UL
        VSRL2, 0x7f8000017149f2caUL
        VSRL3, 0x400000007149f2caUL ]
      []
      [ F1, 0xbe80000000000000UL; VSRL1, 0x7fc000017f800000UL ]
      []
    oracleMem
      ppc64
      "f0221a88"
      [ F1, 0x3fc000003f000000UL
        F2, 0x3eaaaaab7f7fffffUL
        F3, 0x4040000040000000UL
        VSRL1, 0xbf000000bfc00000UL
        VSRL2, 0x1bf800000UL
        VSRL3, 0x3f000000ffc00000UL ]
      []
      [ F1, 0xbeffffff7f800000UL; VSRL1, 0x3f000000ffc00000UL ]
      []
    oracleMem
      ppc64le
      "f0221a88"
      [ F1, 0x3fc000003f000000UL
        F2, 0x3eaaaaab7f7fffffUL
        F3, 0x4040000040000000UL
        VSRL1, 0xbf000000bfc00000UL
        VSRL2, 0x1bf800000UL
        VSRL3, 0x3f000000ffc00000UL ]
      []
      [ F1, 0xbeffffff7f800000UL; VSRL1, 0x3f000000ffc00000UL ]
      []

  /// <summary>
  /// xvmsubmdp xT, xA, xB places in each double element of xT xA times xT minus
  /// xB, the product exact and the sum rounded once. Which NaN comes back
  /// follows the order xA, then the addend, then the other factor, quieted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVMSUBMDP is fused``() =
    (* xvmsubmdp vs1,vs2,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0221bc8"
      [ F1, 0x4010000000000000UL
        F2, 0x3ff8000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbff0000000000000UL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ F1, 0x4018000000000000UL; VSRL1, 0x7ff8000000000001UL ]
      []
    oracleMem
      ppc64le
      "f0221bc8"
      [ F1, 0x4010000000000000UL
        F2, 0x3ff8000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbff0000000000000UL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ F1, 0x4018000000000000UL; VSRL1, 0x7ff8000000000001UL ]
      []
    oracleMem
      ppc64
      "f0221bc8"
      [ F1, 0x4004000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xc004000000000000UL
        VSRL2, 0x7ff0000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x7ff8000000000001UL ]
      []
    oracleMem
      ppc64le
      "f0221bc8"
      [ F1, 0x4004000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xc004000000000000UL
        VSRL2, 0x7ff0000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x7ff8000000000001UL ]
      []
    oracleMem
      ppc64
      "f0221bc8"
      [ F1, 0x3fe0000000000000UL
        F2, 0x7ff0000000000000UL
        F3, 0xfff0000000000000UL
        VSRL1, 0xfff0000000000000UL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff0000000000000UL; VSRL1, 0x7ff8000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0221bc8"
      [ F1, 0x3fe0000000000000UL
        F2, 0x7ff0000000000000UL
        F3, 0xfff0000000000000UL
        VSRL1, 0xfff0000000000000UL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff0000000000000UL; VSRL1, 0x7ff8000000000000UL ]
      []

  /// <summary>
  /// xvmsubmsp xT, xA, xB places in each single element of xT xA times xT minus
  /// xB, the product exact and the sum rounded once. Which NaN comes back
  /// follows the order xA, then the addend, then the other factor, quieted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVMSUBMSP is fused``() =
    (* xvmsubmsp vs1,vs2,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0221ac8"
      [ F1, 0x40000000bf800000UL
        F2, 0x3fc00000c0100000UL
        F3, 0x404000003f000000UL
        VSRL1, 0x7f8000007f800001UL
        VSRL2, 0x7f8000007fc00001UL
        VSRL3, 0xff8000003f800000UL ]
      []
      [ F1, 0x3fe00000UL; VSRL1, 0x7f8000007fc00001UL ]
      []
    oracleMem
      ppc64le
      "f0221ac8"
      [ F1, 0x40000000bf800000UL
        F2, 0x3fc00000c0100000UL
        F3, 0x404000003f000000UL
        VSRL1, 0x7f8000007f800001UL
        VSRL2, 0x7f8000007fc00001UL
        VSRL3, 0xff8000003f800000UL ]
      []
      [ F1, 0x3fe00000UL; VSRL1, 0x7f8000007fc00001UL ]
      []
    oracleMem
      ppc64
      "f0221ac8"
      [ F1, 0x3e80000080000000UL
        F2, 0x80000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0x40200000c0200000UL
        VSRL2, 0x7f8000017149f2caUL
        VSRL3, 0x400000007149f2caUL ]
      []
      [ F1, 0x0UL; VSRL1, 0x7fc00001f230b471UL ]
      []
    oracleMem
      ppc64le
      "f0221ac8"
      [ F1, 0x3e80000080000000UL
        F2, 0x80000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0x40200000c0200000UL
        VSRL2, 0x7f8000017149f2caUL
        VSRL3, 0x400000007149f2caUL ]
      []
      [ F1, 0x0UL; VSRL1, 0x7fc00001f230b471UL ]
      []
    oracleMem
      ppc64
      "f0221ac8"
      [ F1, 0x3fc000003f000000UL
        F2, 0x3eaaaaab7f7fffffUL
        F3, 0x4040000040000000UL
        VSRL1, 0xbf000000bfc00000UL
        VSRL2, 0x1bf800000UL
        VSRL3, 0x3f000000ffc00000UL ]
      []
      [ F1, 0xc02000007effffffUL; VSRL1, 0xbf000000ffc00000UL ]
      []
    oracleMem
      ppc64le
      "f0221ac8"
      [ F1, 0x3fc000003f000000UL
        F2, 0x3eaaaaab7f7fffffUL
        F3, 0x4040000040000000UL
        VSRL1, 0xbf000000bfc00000UL
        VSRL2, 0x1bf800000UL
        VSRL3, 0x3f000000ffc00000UL ]
      []
      [ F1, 0xc02000007effffffUL; VSRL1, 0xbf000000ffc00000UL ]
      []

  /// <summary>
  /// xvnmaddadp xT, xA, xB places in each double element of xT the negation of
  /// xA times xB plus xT, the product exact and the sum rounded once. Which NaN
  /// comes back follows the order xA, then the addend, then the other factor,
  /// quieted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVNMADDADP is fused``() =
    (* xvnmaddadp vs1,vs2,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0221f08"
      [ F1, 0x4010000000000000UL
        F2, 0x3ff8000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbff0000000000000UL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ F1, 0xc010000000000000UL; VSRL1, 0x7ff8000000000001UL ]
      []
    oracleMem
      ppc64le
      "f0221f08"
      [ F1, 0x4010000000000000UL
        F2, 0x3ff8000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbff0000000000000UL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ F1, 0xc010000000000000UL; VSRL1, 0x7ff8000000000001UL ]
      []
    oracleMem
      ppc64
      "f0221f08"
      [ F1, 0x4004000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xc004000000000000UL
        VSRL2, 0x7ff0000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0xc004000000000000UL; VSRL1, 0x7ff8000000000001UL ]
      []
    oracleMem
      ppc64le
      "f0221f08"
      [ F1, 0x4004000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xc004000000000000UL
        VSRL2, 0x7ff0000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0xc004000000000000UL; VSRL1, 0x7ff8000000000001UL ]
      []
    oracleMem
      ppc64
      "f0221f08"
      [ F1, 0x3fe0000000000000UL
        F2, 0x7ff0000000000000UL
        F3, 0xfff0000000000000UL
        VSRL1, 0xfff0000000000000UL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff0000000000000UL; VSRL1, 0x7ff0000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0221f08"
      [ F1, 0x3fe0000000000000UL
        F2, 0x7ff0000000000000UL
        F3, 0xfff0000000000000UL
        VSRL1, 0xfff0000000000000UL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff0000000000000UL; VSRL1, 0x7ff0000000000000UL ]
      []

  /// <summary>
  /// xvnmaddasp xT, xA, xB places in each single element of xT the negation of
  /// xA times xB plus xT, the product exact and the sum rounded once. Which NaN
  /// comes back follows the order xA, then the addend, then the other factor,
  /// quieted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVNMADDASP is fused``() =
    (* xvnmaddasp vs1,vs2,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0221e08"
      [ F1, 0x40000000bf800000UL
        F2, 0x3fc00000c0100000UL
        F3, 0x404000003f000000UL
        VSRL1, 0x7f8000007f800001UL
        VSRL2, 0x7f8000007fc00001UL
        VSRL3, 0xff8000003f800000UL ]
      []
      [ F1, 0xc0d0000040080000UL; VSRL1, 0x7fc000007fc00001UL ]
      []
    oracleMem
      ppc64le
      "f0221e08"
      [ F1, 0x40000000bf800000UL
        F2, 0x3fc00000c0100000UL
        F3, 0x404000003f000000UL
        VSRL1, 0x7f8000007f800001UL
        VSRL2, 0x7f8000007fc00001UL
        VSRL3, 0xff8000003f800000UL ]
      []
      [ F1, 0xc0d0000040080000UL; VSRL1, 0x7fc000007fc00001UL ]
      []
    oracleMem
      ppc64
      "f0221e08"
      [ F1, 0x3e80000080000000UL
        F2, 0x80000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0x40200000c0200000UL
        VSRL2, 0x7f8000017149f2caUL
        VSRL3, 0x400000007149f2caUL ]
      []
      [ F1, 0xbe80000000000000UL; VSRL1, 0x7fc00001ff800000UL ]
      []
    oracleMem
      ppc64le
      "f0221e08"
      [ F1, 0x3e80000080000000UL
        F2, 0x80000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0x40200000c0200000UL
        VSRL2, 0x7f8000017149f2caUL
        VSRL3, 0x400000007149f2caUL ]
      []
      [ F1, 0xbe80000000000000UL; VSRL1, 0x7fc00001ff800000UL ]
      []
    oracleMem
      ppc64
      "f0221e08"
      [ F1, 0x3fc000003f000000UL
        F2, 0x3eaaaaab7f7fffffUL
        F3, 0x4040000040000000UL
        VSRL1, 0xbf000000bfc00000UL
        VSRL2, 0x1bf800000UL
        VSRL3, 0x3f000000ffc00000UL ]
      []
      [ F1, 0xc0200000ff800000UL; VSRL1, 0x3f000000ffc00000UL ]
      []
    oracleMem
      ppc64le
      "f0221e08"
      [ F1, 0x3fc000003f000000UL
        F2, 0x3eaaaaab7f7fffffUL
        F3, 0x4040000040000000UL
        VSRL1, 0xbf000000bfc00000UL
        VSRL2, 0x1bf800000UL
        VSRL3, 0x3f000000ffc00000UL ]
      []
      [ F1, 0xc0200000ff800000UL; VSRL1, 0x3f000000ffc00000UL ]
      []

  /// <summary>
  /// xvnmaddmdp xT, xA, xB places in each double element of xT the negation of
  /// xA times xT plus xB, the product exact and the sum rounded once. Which NaN
  /// comes back follows the order xA, then the addend, then the other factor,
  /// quieted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVNMADDMDP is fused``() =
    (* xvnmaddmdp vs1,vs2,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0221f48"
      [ F1, 0x4010000000000000UL
        F2, 0x3ff8000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbff0000000000000UL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ F1, 0xc018000000000000UL; VSRL1, 0x7ff8000000000001UL ]
      []
    oracleMem
      ppc64le
      "f0221f48"
      [ F1, 0x4010000000000000UL
        F2, 0x3ff8000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbff0000000000000UL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ F1, 0xc018000000000000UL; VSRL1, 0x7ff8000000000001UL ]
      []
    oracleMem
      ppc64
      "f0221f48"
      [ F1, 0x4004000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xc004000000000000UL
        VSRL2, 0x7ff0000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x8000000000000000UL; VSRL1, 0x7ff8000000000001UL ]
      []
    oracleMem
      ppc64le
      "f0221f48"
      [ F1, 0x4004000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xc004000000000000UL
        VSRL2, 0x7ff0000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x8000000000000000UL; VSRL1, 0x7ff8000000000001UL ]
      []
    oracleMem
      ppc64
      "f0221f48"
      [ F1, 0x3fe0000000000000UL
        F2, 0x7ff0000000000000UL
        F3, 0xfff0000000000000UL
        VSRL1, 0xfff0000000000000UL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff8000000000000UL; VSRL1, 0x7ff8000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0221f48"
      [ F1, 0x3fe0000000000000UL
        F2, 0x7ff0000000000000UL
        F3, 0xfff0000000000000UL
        VSRL1, 0xfff0000000000000UL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff8000000000000UL; VSRL1, 0x7ff8000000000000UL ]
      []

  /// <summary>
  /// xvnmaddmsp xT, xA, xB places in each single element of xT the negation of
  /// xA times xT plus xB, the product exact and the sum rounded once. Which NaN
  /// comes back follows the order xA, then the addend, then the other factor,
  /// quieted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVNMADDMSP is fused``() =
    (* xvnmaddmsp vs1,vs2,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0221e48"
      [ F1, 0x40000000bf800000UL
        F2, 0x3fc00000c0100000UL
        F3, 0x404000003f000000UL
        VSRL1, 0x7f8000007f800001UL
        VSRL2, 0x7f8000007fc00001UL
        VSRL3, 0xff8000003f800000UL ]
      []
      [ F1, 0xc0c00000c0300000UL; VSRL1, 0x7fc000007fc00001UL ]
      []
    oracleMem
      ppc64le
      "f0221e48"
      [ F1, 0x40000000bf800000UL
        F2, 0x3fc00000c0100000UL
        F3, 0x404000003f000000UL
        VSRL1, 0x7f8000007f800001UL
        VSRL2, 0x7f8000007fc00001UL
        VSRL3, 0xff8000003f800000UL ]
      []
      [ F1, 0xc0c00000c0300000UL; VSRL1, 0x7fc000007fc00001UL ]
      []
    oracleMem
      ppc64
      "f0221e48"
      [ F1, 0x3e80000080000000UL
        F2, 0x80000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0x40200000c0200000UL
        VSRL2, 0x7f8000017149f2caUL
        VSRL3, 0x400000007149f2caUL ]
      []
      [ F1, 0x8000000080000000UL; VSRL1, 0x7fc0000171977618UL ]
      []
    oracleMem
      ppc64le
      "f0221e48"
      [ F1, 0x3e80000080000000UL
        F2, 0x80000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0x40200000c0200000UL
        VSRL2, 0x7f8000017149f2caUL
        VSRL3, 0x400000007149f2caUL ]
      []
      [ F1, 0x8000000080000000UL; VSRL1, 0x7fc0000171977618UL ]
      []
    oracleMem
      ppc64
      "f0221e48"
      [ F1, 0x3fc000003f000000UL
        F2, 0x3eaaaaab7f7fffffUL
        F3, 0x4040000040000000UL
        VSRL1, 0xbf000000bfc00000UL
        VSRL2, 0x1bf800000UL
        VSRL3, 0x3f000000ffc00000UL ]
      []
      [ F1, 0xc0600000feffffffUL; VSRL1, 0xbf000000ffc00000UL ]
      []
    oracleMem
      ppc64le
      "f0221e48"
      [ F1, 0x3fc000003f000000UL
        F2, 0x3eaaaaab7f7fffffUL
        F3, 0x4040000040000000UL
        VSRL1, 0xbf000000bfc00000UL
        VSRL2, 0x1bf800000UL
        VSRL3, 0x3f000000ffc00000UL ]
      []
      [ F1, 0xc0600000feffffffUL; VSRL1, 0xbf000000ffc00000UL ]
      []

  /// <summary>
  /// xvnmsubadp xT, xA, xB places in each double element of xT the negation of
  /// xA times xB minus xT, the product exact and the sum rounded once. Which
  /// NaN comes back follows the order xA, then the addend, then the other
  /// factor, quieted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVNMSUBADP is fused``() =
    (* xvnmsubadp vs1,vs2,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0221f88"
      [ F1, 0x4010000000000000UL
        F2, 0x3ff8000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbff0000000000000UL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ VSRL1, 0x7ff8000000000001UL; F1, 0x4010000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0221f88"
      [ F1, 0x4010000000000000UL
        F2, 0x3ff8000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbff0000000000000UL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ VSRL1, 0x7ff8000000000001UL; F1, 0x4010000000000000UL ]
      []
    oracleMem
      ppc64
      "f0221f88"
      [ F1, 0x4004000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xc004000000000000UL
        VSRL2, 0x7ff0000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ VSRL1, 0x7ff8000000000001UL; F1, 0x4004000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0221f88"
      [ F1, 0x4004000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xc004000000000000UL
        VSRL2, 0x7ff0000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ VSRL1, 0x7ff8000000000001UL; F1, 0x4004000000000000UL ]
      []
    oracleMem
      ppc64
      "f0221f88"
      [ F1, 0x3fe0000000000000UL
        F2, 0x7ff0000000000000UL
        F3, 0xfff0000000000000UL
        VSRL1, 0xfff0000000000000UL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff0000000000000UL; VSRL1, 0xfff0000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0221f88"
      [ F1, 0x3fe0000000000000UL
        F2, 0x7ff0000000000000UL
        F3, 0xfff0000000000000UL
        VSRL1, 0xfff0000000000000UL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0x7ff0000000000000UL; VSRL1, 0xfff0000000000000UL ]
      []

  /// <summary>
  /// xvnmsubasp xT, xA, xB places in each single element of xT the negation of
  /// xA times xB minus xT, the product exact and the sum rounded once. Which
  /// NaN comes back follows the order xA, then the addend, then the other
  /// factor, quieted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVNMSUBASP is fused``() =
    (* xvnmsubasp vs1,vs2,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0221e88"
      [ F1, 0x40000000bf800000UL
        F2, 0x3fc00000c0100000UL
        F3, 0x404000003f000000UL
        VSRL1, 0x7f8000007f800001UL
        VSRL2, 0x7f8000007fc00001UL
        VSRL3, 0xff8000003f800000UL ]
      []
      [ F1, 0xc02000003e000000UL; VSRL1, 0x7f8000007fc00001UL ]
      []
    oracleMem
      ppc64le
      "f0221e88"
      [ F1, 0x40000000bf800000UL
        F2, 0x3fc00000c0100000UL
        F3, 0x404000003f000000UL
        VSRL1, 0x7f8000007f800001UL
        VSRL2, 0x7f8000007fc00001UL
        VSRL3, 0xff8000003f800000UL ]
      []
      [ F1, 0xc02000003e000000UL; VSRL1, 0x7f8000007fc00001UL ]
      []
    oracleMem
      ppc64
      "f0221e88"
      [ F1, 0x3e80000080000000UL
        F2, 0x80000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0x40200000c0200000UL
        VSRL2, 0x7f8000017149f2caUL
        VSRL3, 0x400000007149f2caUL ]
      []
      [ VSRL1, 0x7fc00001ff800000UL; F1, 0x3e80000080000000UL ]
      []
    oracleMem
      ppc64le
      "f0221e88"
      [ F1, 0x3e80000080000000UL
        F2, 0x80000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0x40200000c0200000UL
        VSRL2, 0x7f8000017149f2caUL
        VSRL3, 0x400000007149f2caUL ]
      []
      [ VSRL1, 0x7fc00001ff800000UL; F1, 0x3e80000080000000UL ]
      []
    oracleMem
      ppc64
      "f0221e88"
      [ F1, 0x3fc000003f000000UL
        F2, 0x3eaaaaab7f7fffffUL
        F3, 0x4040000040000000UL
        VSRL1, 0xbf000000bfc00000UL
        VSRL2, 0x1bf800000UL
        VSRL3, 0x3f000000ffc00000UL ]
      []
      [ F1, 0x3effffffff800000UL; VSRL1, 0xbf000000ffc00000UL ]
      []
    oracleMem
      ppc64le
      "f0221e88"
      [ F1, 0x3fc000003f000000UL
        F2, 0x3eaaaaab7f7fffffUL
        F3, 0x4040000040000000UL
        VSRL1, 0xbf000000bfc00000UL
        VSRL2, 0x1bf800000UL
        VSRL3, 0x3f000000ffc00000UL ]
      []
      [ F1, 0x3effffffff800000UL; VSRL1, 0xbf000000ffc00000UL ]
      []

  /// <summary>
  /// xvnmsubmdp xT, xA, xB places in each double element of xT the negation of
  /// xA times xT minus xB, the product exact and the sum rounded once. Which
  /// NaN comes back follows the order xA, then the addend, then the other
  /// factor, quieted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVNMSUBMDP is fused``() =
    (* xvnmsubmdp vs1,vs2,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0221fc8"
      [ F1, 0x4010000000000000UL
        F2, 0x3ff8000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbff0000000000000UL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ F1, 0xc018000000000000UL; VSRL1, 0x7ff8000000000001UL ]
      []
    oracleMem
      ppc64le
      "f0221fc8"
      [ F1, 0x4010000000000000UL
        F2, 0x3ff8000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xbff0000000000000UL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ F1, 0xc018000000000000UL; VSRL1, 0x7ff8000000000001UL ]
      []
    oracleMem
      ppc64
      "f0221fc8"
      [ F1, 0x4004000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xc004000000000000UL
        VSRL2, 0x7ff0000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x8000000000000000UL; VSRL1, 0x7ff8000000000001UL ]
      []
    oracleMem
      ppc64le
      "f0221fc8"
      [ F1, 0x4004000000000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0xc004000000000000UL
        VSRL2, 0x7ff0000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x8000000000000000UL; VSRL1, 0x7ff8000000000001UL ]
      []
    oracleMem
      ppc64
      "f0221fc8"
      [ F1, 0x3fe0000000000000UL
        F2, 0x7ff0000000000000UL
        F3, 0xfff0000000000000UL
        VSRL1, 0xfff0000000000000UL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0xfff0000000000000UL; VSRL1, 0x7ff8000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0221fc8"
      [ F1, 0x3fe0000000000000UL
        F2, 0x7ff0000000000000UL
        F3, 0xfff0000000000000UL
        VSRL1, 0xfff0000000000000UL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0xfff0000000000000UL; VSRL1, 0x7ff8000000000000UL ]
      []

  /// <summary>
  /// xvnmsubmsp xT, xA, xB places in each single element of xT the negation of
  /// xA times xT minus xB, the product exact and the sum rounded once. Which
  /// NaN comes back follows the order xA, then the addend, then the other
  /// factor, quieted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVNMSUBMSP is fused``() =
    (* xvnmsubmsp vs1,vs2,vs3, under QEMU: lanes/x-oracle/arith *)
    oracleMem
      ppc64
      "f0221ec8"
      [ F1, 0x40000000bf800000UL
        F2, 0x3fc00000c0100000UL
        F3, 0x404000003f000000UL
        VSRL1, 0x7f8000007f800001UL
        VSRL2, 0x7f8000007fc00001UL
        VSRL3, 0xff8000003f800000UL ]
      []
      [ F1, 0x80000000bfe00000UL; VSRL1, 0xff8000007fc00001UL ]
      []
    oracleMem
      ppc64le
      "f0221ec8"
      [ F1, 0x40000000bf800000UL
        F2, 0x3fc00000c0100000UL
        F3, 0x404000003f000000UL
        VSRL1, 0x7f8000007f800001UL
        VSRL2, 0x7f8000007fc00001UL
        VSRL3, 0xff8000003f800000UL ]
      []
      [ F1, 0x80000000bfe00000UL; VSRL1, 0xff8000007fc00001UL ]
      []
    oracleMem
      ppc64
      "f0221ec8"
      [ F1, 0x3e80000080000000UL
        F2, 0x80000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0x40200000c0200000UL
        VSRL2, 0x7f8000017149f2caUL
        VSRL3, 0x400000007149f2caUL ]
      []
      [ F1, 0x8000000080000000UL; VSRL1, 0x7fc000017230b471UL ]
      []
    oracleMem
      ppc64le
      "f0221ec8"
      [ F1, 0x3e80000080000000UL
        F2, 0x80000000UL
        F3, 0x8000000000000000UL
        VSRL1, 0x40200000c0200000UL
        VSRL2, 0x7f8000017149f2caUL
        VSRL3, 0x400000007149f2caUL ]
      []
      [ F1, 0x8000000080000000UL; VSRL1, 0x7fc000017230b471UL ]
      []
    oracleMem
      ppc64
      "f0221ec8"
      [ F1, 0x3fc000003f000000UL
        F2, 0x3eaaaaab7f7fffffUL
        F3, 0x4040000040000000UL
        VSRL1, 0xbf000000bfc00000UL
        VSRL2, 0x1bf800000UL
        VSRL3, 0x3f000000ffc00000UL ]
      []
      [ F1, 0x40200000feffffffUL; VSRL1, 0x3f000000ffc00000UL ]
      []
    oracleMem
      ppc64le
      "f0221ec8"
      [ F1, 0x3fc000003f000000UL
        F2, 0x3eaaaaab7f7fffffUL
        F3, 0x4040000040000000UL
        VSRL1, 0xbf000000bfc00000UL
        VSRL2, 0x1bf800000UL
        VSRL3, 0x3f000000ffc00000UL ]
      []
      [ F1, 0x40200000feffffffUL; VSRL1, 0x3f000000ffc00000UL ]
      []

  /// <summary>
  /// xscmpeqdp xT, xA, xB sets doubleword 0 of xT to all ones where the doubles
  /// in doubleword 0 of xA and xB compare equal -- +0 and -0 do -- and to
  /// zeroes where not, a NaN comparing unequal; doubleword 1 is cleared.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSCMPEQDP writes a mask of equality``() =
    (* xscmpeqdp vs1,vs2,vs3, under QEMU: lanes/x-oracle/tests *)
    oracleMem
      ppc64le
      "f0221818"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3ff0000000000000UL
        F3, 0x3ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x3ff0000000000000UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0xffffffffffffffffUL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221818"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3ff0000000000000UL
        F3, 0x4000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x3ff0000000000000UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221818"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x4000000000000000UL
        F3, 0x3ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x4000000000000000UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221818"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0xffffffffffffffffUL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221818"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7ff8000000000001UL
        F3, 0x3ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221818"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3ff0000000000000UL
        F3, 0x7ff0000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x3ff0000000000000UL
        VSRL3, 0x7ff0000000000001UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221818"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7ff0000000000000UL
        F3, 0x7ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff0000000000000UL
        VSRL3, 0x7ff0000000000000UL ]
      []
      [ F1, 0xffffffffffffffffUL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221818"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0xfffffffffffffUL
        F3, 0x3ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0xfffffffffffffUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []

  /// <summary>
  /// xscmpgtdp xT, xA, xB sets doubleword 0 of xT to all ones where the double
  /// in xA is greater than the one in xB, a NaN comparing false; doubleword 1
  /// is cleared.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSCMPGTDP writes a mask of greater-than``() =
    (* xscmpgtdp vs1,vs2,vs3, under QEMU: lanes/x-oracle/tests *)
    oracleMem
      ppc64le
      "f0221858"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3ff0000000000000UL
        F3, 0x3ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x3ff0000000000000UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221858"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3ff0000000000000UL
        F3, 0x4000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x3ff0000000000000UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221858"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x4000000000000000UL
        F3, 0x3ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x4000000000000000UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0xffffffffffffffffUL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221858"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221858"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7ff8000000000001UL
        F3, 0x3ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221858"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3ff0000000000000UL
        F3, 0x7ff0000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x3ff0000000000000UL
        VSRL3, 0x7ff0000000000001UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221858"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7ff0000000000000UL
        F3, 0x7ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff0000000000000UL
        VSRL3, 0x7ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221858"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0xfffffffffffffUL
        F3, 0x3ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0xfffffffffffffUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []

  /// <summary>
  /// xscmpgedp xT, xA, xB sets doubleword 0 of xT to all ones where the double
  /// in xA is greater than or equal to the one in xB, a NaN comparing false;
  /// doubleword 1 is cleared.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSCMPGEDP writes a mask of greater-or-equal``() =
    (* xscmpgedp vs1,vs2,vs3, under QEMU: lanes/x-oracle/tests *)
    oracleMem
      ppc64le
      "f0221898"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3ff0000000000000UL
        F3, 0x3ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x3ff0000000000000UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0xffffffffffffffffUL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221898"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3ff0000000000000UL
        F3, 0x4000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x3ff0000000000000UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221898"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x4000000000000000UL
        F3, 0x3ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x4000000000000000UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0xffffffffffffffffUL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221898"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0xffffffffffffffffUL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221898"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7ff8000000000001UL
        F3, 0x3ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221898"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3ff0000000000000UL
        F3, 0x7ff0000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x3ff0000000000000UL
        VSRL3, 0x7ff0000000000001UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221898"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7ff0000000000000UL
        F3, 0x7ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff0000000000000UL
        VSRL3, 0x7ff0000000000000UL ]
      []
      [ F1, 0xffffffffffffffffUL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221898"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0xfffffffffffffUL
        F3, 0x3ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0xfffffffffffffUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []

  /// <summary>
  /// xscmpodp BF, xA, xB sets CR field BF and FPCC to less-than, greater-than,
  /// equal or unordered for the doubles in doubleword 0 of xA and xB; +0 and -0
  /// are equal, and a NaN is unordered.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSCMPODP orders two doubles into CR and FPCC``() =
    (* xscmpodp cr2,vs2,vs3, under QEMU: lanes/x-oracle/tests *)
    oracleMem
      ppc64le
      "f1021958"
      [ F2, 0x3ff0000000000000UL
        F3, 0x3ff0000000000000UL
        VSRL2, 0x3ff0000000000000UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "f1021958"
      [ F2, 0x3ff0000000000000UL
        F3, 0x4000000000000000UL
        VSRL2, 0x3ff0000000000000UL
        VSRL3, 0x4000000000000000UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "f1021958"
      [ F2, 0x4000000000000000UL
        F3, 0x3ff0000000000000UL
        VSRL2, 0x4000000000000000UL
        VSRL3, 0x3ff0000000000000UL
        CR2_0, 0x1UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x1UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "f1021958"
      [ F2, 0x8000000000000000UL
        VSRL2, 0x8000000000000000UL
        CR2_1, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "f1021958"
      [ F2, 0x7ff8000000000001UL
        F3, 0x3ff0000000000000UL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x1UL; FPSCR, 0x1UL ]
      []
    oracleMem
      ppc64le
      "f1021958"
      [ F2, 0x3ff0000000000000UL
        F3, 0x7ff0000000000001UL
        VSRL2, 0x3ff0000000000000UL
        VSRL3, 0x7ff0000000000001UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x1UL; FPSCR, 0x1UL ]
      []
    oracleMem
      ppc64le
      "f1021958"
      [ F2, 0x7ff0000000000000UL
        F3, 0x7ff0000000000000UL
        VSRL2, 0x7ff0000000000000UL
        VSRL3, 0x7ff0000000000000UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "f1021958"
      [ F2, 0xfffffffffffffUL
        F3, 0x3ff0000000000000UL
        VSRL2, 0xfffffffffffffUL
        VSRL3, 0x3ff0000000000000UL
        CR2_1, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x8UL ]
      []

  /// <summary>
  /// xscmpexpdp BF, xA, xB compares the biased exponent fields of the doubles
  /// in doubleword 0 of xA and xB as unsigned numbers into CR field BF and
  /// FPCC, unordered where either is a NaN.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSCMPEXPDP compares exponent fields``() =
    (* xscmpexpdp cr2,vs2,vs3, under QEMU: lanes/x-oracle/tests *)
    oracleMem
      ppc64le
      "f10219d8"
      [ F2, 0x3ff0000000000000UL
        F3, 0x3ff0000000000000UL
        VSRL2, 0x3ff0000000000000UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "f10219d8"
      [ F2, 0x3ff0000000000000UL
        F3, 0x4000000000000000UL
        VSRL2, 0x3ff0000000000000UL
        VSRL3, 0x4000000000000000UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "f10219d8"
      [ F2, 0x4000000000000000UL
        F3, 0x3ff0000000000000UL
        VSRL2, 0x4000000000000000UL
        VSRL3, 0x3ff0000000000000UL
        CR2_0, 0x1UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x1UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "f10219d8"
      [ F2, 0x8000000000000000UL
        VSRL2, 0x8000000000000000UL
        CR2_1, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "f10219d8"
      [ F2, 0x7ff8000000000001UL
        F3, 0x3ff0000000000000UL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x1UL; FPSCR, 0x1UL ]
      []
    oracleMem
      ppc64le
      "f10219d8"
      [ F2, 0x3ff0000000000000UL
        F3, 0x7ff0000000000001UL
        VSRL2, 0x3ff0000000000000UL
        VSRL3, 0x7ff0000000000001UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x1UL; FPSCR, 0x1UL ]
      []
    oracleMem
      ppc64le
      "f10219d8"
      [ F2, 0x7ff0000000000000UL
        F3, 0x7ff0000000000000UL
        VSRL2, 0x7ff0000000000000UL
        VSRL3, 0x7ff0000000000000UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "f10219d8"
      [ F2, 0xfffffffffffffUL
        F3, 0x3ff0000000000000UL
        VSRL2, 0xfffffffffffffUL
        VSRL3, 0x3ff0000000000000UL
        CR2_1, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x8UL ]
      []

  /// <summary>
  /// xvcmpeqdp xT, xA, xB sets each double element of xT to all ones where the
  /// matching element of xA is equal to that of xB, a NaN comparing false, and
  /// to zeroes where not.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVCMPEQDP writes lane masks``() =
    (* xvcmpeqdp vs1,vs2,vs3, under QEMU: lanes/x-oracle/tests *)
    oracleMem
      ppc64le
      "f0221b18"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3ff0000000000000UL
        F3, 0x3ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x3ff0000000000000UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0xffffffffffffffffUL; VSRL1, 0xffffffffffffffffUL ]
      []
    oracleMem
      ppc64le
      "f0221b18"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3ff0000000000000UL
        F3, 0x4000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x3ff0000000000000UL
        VSRL3, 0x4000000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221b18"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x4000000000000000UL
        F3, 0x3ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x4000000000000000UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221b18"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x8000000000000000UL ]
      []
      [ F1, 0xffffffffffffffffUL; VSRL1, 0xffffffffffffffffUL ]
      []
    oracleMem
      ppc64le
      "f0221b18"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7ff8000000000001UL
        F3, 0x3ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221b18"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3ff0000000000000UL
        F3, 0x7ff0000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x3ff0000000000000UL
        VSRL3, 0x7ff0000000000001UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []

  /// <summary>
  /// xvcmpeqdp. xT, xA, xB writes the masks xvcmpeqdp does and sets CR6 to all-
  /// true, 0, all-false, 0: bit 0 where every element compared true, bit 2
  /// where none did.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVCMPEQDP. also records in CR6``() =
    (* xvcmpeqdp. vs1,vs2,vs3, under QEMU: lanes/x-oracle/tests *)
    oracleMem
      ppc64le
      "f0221f18"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3ff0000000000000UL
        F3, 0x3ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x3ff0000000000000UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ CR6_0, 0x1UL
        CR6_1, 0x0UL
        CR6_2, 0x0UL
        CR6_3, 0x0UL
        F1, 0xffffffffffffffffUL
        VSRL1, 0xffffffffffffffffUL ]
      []
    oracleMem
      ppc64le
      "f0221f18"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3ff0000000000000UL
        F3, 0x4000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x3ff0000000000000UL
        VSRL3, 0x4000000000000000UL
        CR6_0, 0x1UL
        CR6_1, 0x1UL
        CR6_2, 0x1UL ]
      []
      [ CR6_0, 0x0UL
        CR6_1, 0x0UL
        CR6_2, 0x1UL
        CR6_3, 0x0UL
        F1, 0x0UL
        VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221f18"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x4000000000000000UL
        F3, 0x3ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x4000000000000000UL
        VSRL3, 0x3ff0000000000000UL
        CR6_0, 0x1UL
        CR6_1, 0x1UL
        CR6_2, 0x1UL
        CR6_3, 0x1UL ]
      []
      [ CR6_0, 0x0UL
        CR6_1, 0x0UL
        CR6_2, 0x1UL
        CR6_3, 0x0UL
        F1, 0x0UL
        VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221f18"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x8000000000000000UL
        CR6_0, 0x1UL
        CR6_1, 0x1UL
        CR6_3, 0x1UL ]
      []
      [ CR6_0, 0x1UL
        CR6_1, 0x0UL
        CR6_2, 0x0UL
        CR6_3, 0x0UL
        F1, 0xffffffffffffffffUL
        VSRL1, 0xffffffffffffffffUL ]
      []
    oracleMem
      ppc64le
      "f0221f18"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7ff8000000000001UL
        F3, 0x3ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7ff8000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ CR6_0, 0x0UL
        CR6_1, 0x0UL
        CR6_2, 0x1UL
        CR6_3, 0x0UL
        F1, 0x0UL
        VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221f18"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3ff0000000000000UL
        F3, 0x7ff0000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x3ff0000000000000UL
        VSRL3, 0x7ff0000000000001UL ]
      []
      [ CR6_0, 0x0UL
        CR6_1, 0x0UL
        CR6_2, 0x1UL
        CR6_3, 0x0UL
        F1, 0x0UL
        VSRL1, 0x0UL ]
      []

  /// <summary>
  /// xvcmpeqsp xT, xA, xB sets each single element of xT to all ones where the
  /// matching element of xA is equal to that of xB, a NaN comparing false, and
  /// to zeroes where not.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVCMPEQSP writes lane masks``() =
    (* xvcmpeqsp vs1,vs2,vs3, under QEMU: lanes/x-oracle/tests *)
    oracleMem
      ppc64le
      "f0221a18"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3f8000003f800000UL
        F3, 0x7f800000ff800000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x400000007fc00001UL
        VSRL3, 0x17f800001UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221a18"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3f80000040000000UL
        F3, 0x3f80000040000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x3f80000080000000UL
        VSRL3, 0x3f80000080000000UL ]
      []
      [ F1, 0xffffffffffffffffUL; VSRL1, 0xffffffffffffffffUL ]
      []
    oracleMem
      ppc64le
      "f0221a18"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7f800000ff800000UL
        F3, 0x3f8000003f800000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x17f800001UL
        VSRL3, 0x400000007fc00001UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221a18"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3f80000080000000UL
        F3, 0x3f80000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x40000000c0000000UL
        VSRL3, 0x40000000c0000000UL ]
      []
      [ F1, 0xffffffffffffffffUL; VSRL1, 0xffffffffffffffffUL ]
      []

  /// <summary>
  /// xvcmpeqsp. xT, xA, xB writes the masks xvcmpeqsp does and sets CR6 to all-
  /// true, 0, all-false, 0: bit 0 where every element compared true, bit 2
  /// where none did.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVCMPEQSP. also records in CR6``() =
    (* xvcmpeqsp. vs1,vs2,vs3, under QEMU: lanes/x-oracle/tests *)
    oracleMem
      ppc64le
      "f0221e18"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3f8000003f800000UL
        F3, 0x7f800000ff800000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x400000007fc00001UL
        VSRL3, 0x17f800001UL ]
      []
      [ CR6_0, 0x0UL
        CR6_1, 0x0UL
        CR6_2, 0x1UL
        CR6_3, 0x0UL
        F1, 0x0UL
        VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221e18"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3f80000040000000UL
        F3, 0x3f80000040000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x3f80000080000000UL
        VSRL3, 0x3f80000080000000UL
        CR6_0, 0x1UL
        CR6_1, 0x1UL
        CR6_2, 0x1UL ]
      []
      [ CR6_0, 0x1UL
        CR6_1, 0x0UL
        CR6_2, 0x0UL
        CR6_3, 0x0UL
        F1, 0xffffffffffffffffUL
        VSRL1, 0xffffffffffffffffUL ]
      []
    oracleMem
      ppc64le
      "f0221e18"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7f800000ff800000UL
        F3, 0x3f8000003f800000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x17f800001UL
        VSRL3, 0x400000007fc00001UL
        CR6_0, 0x1UL
        CR6_1, 0x1UL
        CR6_2, 0x1UL
        CR6_3, 0x1UL ]
      []
      [ CR6_0, 0x0UL
        CR6_1, 0x0UL
        CR6_2, 0x1UL
        CR6_3, 0x0UL
        F1, 0x0UL
        VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221e18"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3f80000080000000UL
        F3, 0x3f80000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x40000000c0000000UL
        VSRL3, 0x40000000c0000000UL
        CR6_0, 0x1UL
        CR6_1, 0x1UL
        CR6_3, 0x1UL ]
      []
      [ CR6_0, 0x1UL
        CR6_1, 0x0UL
        CR6_2, 0x0UL
        CR6_3, 0x0UL
        F1, 0xffffffffffffffffUL
        VSRL1, 0xffffffffffffffffUL ]
      []

  /// <summary>
  /// xvcmpgesp xT, xA, xB sets each single element of xT to all ones where the
  /// matching element of xA is greater than or equal to that of xB, a NaN
  /// comparing false, and to zeroes where not.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVCMPGESP writes lane masks``() =
    (* xvcmpgesp vs1,vs2,vs3, under QEMU: lanes/x-oracle/tests *)
    oracleMem
      ppc64le
      "f0221a98"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3f8000003f800000UL
        F3, 0x7f800000ff800000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x400000007fc00001UL
        VSRL3, 0x17f800001UL ]
      []
      [ F1, 0xffffffffUL; VSRL1, 0xffffffff00000000UL ]
      []
    oracleMem
      ppc64le
      "f0221a98"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3f80000040000000UL
        F3, 0x3f80000040000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x3f80000080000000UL
        VSRL3, 0x3f80000080000000UL ]
      []
      [ F1, 0xffffffffffffffffUL; VSRL1, 0xffffffffffffffffUL ]
      []
    oracleMem
      ppc64le
      "f0221a98"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7f800000ff800000UL
        F3, 0x3f8000003f800000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x17f800001UL
        VSRL3, 0x400000007fc00001UL ]
      []
      [ F1, 0xffffffff00000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221a98"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3f80000080000000UL
        F3, 0x3f80000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x40000000c0000000UL
        VSRL3, 0x40000000c0000000UL ]
      []
      [ F1, 0xffffffffffffffffUL; VSRL1, 0xffffffffffffffffUL ]
      []

  /// <summary>
  /// xvcmpgesp. xT, xA, xB writes the masks xvcmpgesp does and sets CR6 to all-
  /// true, 0, all-false, 0: bit 0 where every element compared true, bit 2
  /// where none did.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVCMPGESP. also records in CR6``() =
    (* xvcmpgesp. vs1,vs2,vs3, under QEMU: lanes/x-oracle/tests *)
    oracleMem
      ppc64le
      "f0221e98"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3f8000003f800000UL
        F3, 0x7f800000ff800000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x400000007fc00001UL
        VSRL3, 0x17f800001UL ]
      []
      [ CR6_0, 0x0UL
        CR6_1, 0x0UL
        CR6_2, 0x0UL
        CR6_3, 0x0UL
        F1, 0xffffffffUL
        VSRL1, 0xffffffff00000000UL ]
      []
    oracleMem
      ppc64le
      "f0221e98"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3f80000040000000UL
        F3, 0x3f80000040000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x3f80000080000000UL
        VSRL3, 0x3f80000080000000UL
        CR6_0, 0x1UL
        CR6_1, 0x1UL
        CR6_2, 0x1UL ]
      []
      [ CR6_0, 0x1UL
        CR6_1, 0x0UL
        CR6_2, 0x0UL
        CR6_3, 0x0UL
        F1, 0xffffffffffffffffUL
        VSRL1, 0xffffffffffffffffUL ]
      []
    oracleMem
      ppc64le
      "f0221e98"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7f800000ff800000UL
        F3, 0x3f8000003f800000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x17f800001UL
        VSRL3, 0x400000007fc00001UL
        CR6_0, 0x1UL
        CR6_1, 0x1UL
        CR6_2, 0x1UL
        CR6_3, 0x1UL ]
      []
      [ CR6_0, 0x0UL
        CR6_1, 0x0UL
        CR6_2, 0x0UL
        CR6_3, 0x0UL
        F1, 0xffffffff00000000UL
        VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221e98"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3f80000080000000UL
        F3, 0x3f80000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x40000000c0000000UL
        VSRL3, 0x40000000c0000000UL
        CR6_0, 0x1UL
        CR6_1, 0x1UL
        CR6_3, 0x1UL ]
      []
      [ CR6_0, 0x1UL
        CR6_1, 0x0UL
        CR6_2, 0x0UL
        CR6_3, 0x0UL
        F1, 0xffffffffffffffffUL
        VSRL1, 0xffffffffffffffffUL ]
      []

  /// <summary>
  /// xvcmpgtsp xT, xA, xB sets each single element of xT to all ones where the
  /// matching element of xA is greater than that of xB, a NaN comparing false,
  /// and to zeroes where not.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVCMPGTSP writes lane masks``() =
    (* xvcmpgtsp vs1,vs2,vs3, under QEMU: lanes/x-oracle/tests *)
    oracleMem
      ppc64le
      "f0221a58"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3f8000003f800000UL
        F3, 0x7f800000ff800000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x400000007fc00001UL
        VSRL3, 0x17f800001UL ]
      []
      [ F1, 0xffffffffUL; VSRL1, 0xffffffff00000000UL ]
      []
    oracleMem
      ppc64le
      "f0221a58"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3f80000040000000UL
        F3, 0x3f80000040000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x3f80000080000000UL
        VSRL3, 0x3f80000080000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221a58"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7f800000ff800000UL
        F3, 0x3f8000003f800000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x17f800001UL
        VSRL3, 0x400000007fc00001UL ]
      []
      [ F1, 0xffffffff00000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221a58"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3f80000080000000UL
        F3, 0x3f80000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x40000000c0000000UL
        VSRL3, 0x40000000c0000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []

  /// <summary>
  /// xvcmpgtsp. xT, xA, xB writes the masks xvcmpgtsp does and sets CR6 to all-
  /// true, 0, all-false, 0: bit 0 where every element compared true, bit 2
  /// where none did.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVCMPGTSP. also records in CR6``() =
    (* xvcmpgtsp. vs1,vs2,vs3, under QEMU: lanes/x-oracle/tests *)
    oracleMem
      ppc64le
      "f0221e58"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3f8000003f800000UL
        F3, 0x7f800000ff800000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x400000007fc00001UL
        VSRL3, 0x17f800001UL ]
      []
      [ CR6_0, 0x0UL
        CR6_1, 0x0UL
        CR6_2, 0x0UL
        CR6_3, 0x0UL
        F1, 0xffffffffUL
        VSRL1, 0xffffffff00000000UL ]
      []
    oracleMem
      ppc64le
      "f0221e58"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3f80000040000000UL
        F3, 0x3f80000040000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x3f80000080000000UL
        VSRL3, 0x3f80000080000000UL
        CR6_0, 0x1UL
        CR6_1, 0x1UL
        CR6_2, 0x1UL ]
      []
      [ CR6_0, 0x0UL
        CR6_1, 0x0UL
        CR6_2, 0x1UL
        CR6_3, 0x0UL
        F1, 0x0UL
        VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221e58"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x7f800000ff800000UL
        F3, 0x3f8000003f800000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x17f800001UL
        VSRL3, 0x400000007fc00001UL
        CR6_0, 0x1UL
        CR6_1, 0x1UL
        CR6_2, 0x1UL
        CR6_3, 0x1UL ]
      []
      [ CR6_0, 0x0UL
        CR6_1, 0x0UL
        CR6_2, 0x0UL
        CR6_3, 0x0UL
        F1, 0xffffffff00000000UL
        VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221e58"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x3f80000080000000UL
        F3, 0x3f80000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x40000000c0000000UL
        VSRL3, 0x40000000c0000000UL
        CR6_0, 0x1UL
        CR6_1, 0x1UL
        CR6_3, 0x1UL ]
      []
      [ CR6_0, 0x0UL
        CR6_1, 0x0UL
        CR6_2, 0x1UL
        CR6_3, 0x0UL
        F1, 0x0UL
        VSRL1, 0x0UL ]
      []

  /// <summary>
  /// xstdivdp BF, xA, xB sets CR field BF to 0b1 || fg || fe || 0b0 for the
  /// doubles in doubleword 0 of xA and xB: fe where a NaN, an infinity, a zero
  /// divisor or exponents past the thresholds of the double format need a
  /// software fix-up, fg where an operand is an infinity or the divisor a zero
  /// or a denormal.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSTDIVDP flags a divide that needs software``() =
    (* xstdivdp cr2,vs2,vs3, under QEMU: lanes/x-oracle/tests *)
    oracleMem
      ppc64le
      "f10219e8"
      [ F2, 0x3ff0000000000000UL
        F3, 0x3ff0000000000000UL
        VSRL2, 0x3ff0000000000000UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f10219e8"
      [ F2, 0x3ff0000000000000UL
        VSRL2, 0x3ff0000000000000UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x1UL; CR2_2, 0x1UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f10219e8"
      [ F2, 0x3ff0000000000000UL
        F3, 0xfffffffffffffUL
        VSRL2, 0x3ff0000000000000UL
        VSRL3, 0xfffffffffffffUL
        CR2_0, 0x1UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x1UL; CR2_2, 0x1UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f10219e8"
      [ F2, 0x7e70000000000000UL
        F3, 0x3e10000000000000UL
        VSRL2, 0x7e70000000000000UL
        VSRL3, 0x3e10000000000000UL
        CR2_1, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f10219e8"
      [ F2, 0x2b0000000000000UL
        F3, 0x3ff0000000000000UL
        VSRL2, 0x2b0000000000000UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f10219e8"
      [ F2, 0x3ff0000000000000UL
        F3, 0x7fc0000000000000UL
        VSRL2, 0x3ff0000000000000UL
        VSRL3, 0x7fc0000000000000UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f10219e8"
      [ F2, 0x7ff0000000000000UL
        F3, 0x3ff0000000000000UL
        VSRL2, 0x7ff0000000000000UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x1UL; CR2_2, 0x1UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f10219e8"
      [ F2, 0x20b0000000000000UL
        F3, 0x6070000000000000UL
        VSRL2, 0x20b0000000000000UL
        VSRL3, 0x6070000000000000UL
        CR2_1, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL ]
      []

  /// <summary>
  /// xvtdivdp BF, xA, xB sets CR field BF to 0b1 || fg || fe || 0b0, fe and fg
  /// gathered over both double lanes.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVTDIVDP flags a divide in either lane``() =
    (* xvtdivdp cr2,vs2,vs3, under QEMU: lanes/x-oracle/tests *)
    oracleMem
      ppc64le
      "f1021be8"
      [ F2, 0x3ff0000000000000UL
        F3, 0x3ff0000000000000UL
        VSRL2, 0x3ff0000000000000UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1021be8"
      [ F2, 0x3ff0000000000000UL
        VSRL2, 0x3ff0000000000000UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x1UL; CR2_2, 0x1UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1021be8"
      [ F2, 0x3ff0000000000000UL
        F3, 0xfffffffffffffUL
        VSRL2, 0x3ff0000000000000UL
        VSRL3, 0xfffffffffffffUL
        CR2_0, 0x1UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x1UL; CR2_2, 0x1UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1021be8"
      [ F2, 0x7e70000000000000UL
        F3, 0x3e10000000000000UL
        VSRL2, 0x7e70000000000000UL
        VSRL3, 0x3e10000000000000UL
        CR2_1, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1021be8"
      [ F2, 0x2b0000000000000UL
        F3, 0x3ff0000000000000UL
        VSRL2, 0x2b0000000000000UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1021be8"
      [ F2, 0x3ff0000000000000UL
        F3, 0x7fc0000000000000UL
        VSRL2, 0x3ff0000000000000UL
        VSRL3, 0x7fc0000000000000UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1021be8"
      [ F2, 0x7ff0000000000000UL
        F3, 0x3ff0000000000000UL
        VSRL2, 0x7ff0000000000000UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x1UL; CR2_2, 0x1UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1021be8"
      [ F2, 0x20b0000000000000UL
        F3, 0x6070000000000000UL
        VSRL2, 0x20b0000000000000UL
        VSRL3, 0x6070000000000000UL
        CR2_1, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL ]
      []

  /// <summary>
  /// xvtdivsp BF, xA, xB tests the four single lanes against the thresholds of
  /// the single format: e_b at most -126 or at least 125, e_a - e_b at least
  /// 127 or at most -125, e_a at most -103.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVTDIVSP uses the single thresholds``() =
    (* xvtdivsp cr2,vs2,vs3, under QEMU: lanes/x-oracle/tests *)
    oracleMem
      ppc64le
      "f1021ae8"
      [ F2, 0x3f8000003f800000UL
        F3, 0x3f8000003f800000UL
        VSRL2, 0x3f8000003f800000UL
        VSRL3, 0x3f8000003f800000UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1021ae8"
      [ F2, 0x3f80000071800000UL
        F3, 0x308000003f800000UL
        VSRL2, 0x3a80000008800000UL
        VSRL3, 0x448000003f800000UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1021ae8"
      [ F2, 0x3f80000000000000UL
        F3, 0x3f8000003f800000UL
        VSRL2, 0x17e000000UL
        VSRL3, 0x3f8000003f800000UL
        CR2_0, 0x1UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL ]
      []

  /// <summary>
  /// xstsqrtdp BF, xB sets CR field BF to 0b1 || fg || fe || 0b0 for the double
  /// in doubleword 0 of xB: fe for a zero, a NaN, an infinity, a negative
  /// number or an exponent at most -970, fg for a zero, an infinity or a
  /// denormal.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSTSQRTDP flags a square root that needs software``() =
    (* xstsqrtdp cr2,vs3, under QEMU: lanes/x-oracle/tests *)
    oracleMem
      ppc64le
      "f10019a8"
      [ F3, 0x3ff0000000000000UL; VSRL3, 0x3ff0000000000000UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f10019a8"
      [ VSRL3, 0x3ff0000000000000UL; CR2_1, 0x1UL; CR2_2, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x1UL; CR2_2, 0x1UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f10019a8"
      [ F3, 0xfffffffffffffUL
        VSRL3, 0x3ff0000000000000UL
        CR2_0, 0x1UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x1UL; CR2_2, 0x1UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f10019a8"
      [ F3, 0x300000000000000UL
        VSRL3, 0x3ff0000000000000UL
        CR2_1, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f10019a8"
      [ F3, 0x3f0000000000000UL; VSRL3, 0x3ff0000000000000UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f10019a8"
      [ F3, 0xbff0000000000000UL; VSRL3, 0x3ff0000000000000UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f10019a8"
      [ F3, 0x7ff0000000000000UL; VSRL3, 0x3ff0000000000000UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x1UL; CR2_2, 0x1UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f10019a8"
      [ F3, 0x7ff8000000000001UL; VSRL3, 0x3ff0000000000000UL; CR2_1, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL ]
      []

  /// <summary>
  /// xvtsqrtdp BF, xB gathers the xstsqrtdp flags over both double lanes.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVTSQRTDP flags a square root in either lane``() =
    (* xvtsqrtdp cr2,vs3, under QEMU: lanes/x-oracle/tests *)
    oracleMem
      ppc64le
      "f1001ba8"
      [ F3, 0x3ff0000000000000UL; VSRL3, 0x3ff0000000000000UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1001ba8"
      [ VSRL3, 0x3ff0000000000000UL; CR2_1, 0x1UL; CR2_2, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x1UL; CR2_2, 0x1UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1001ba8"
      [ F3, 0xfffffffffffffUL
        VSRL3, 0x3ff0000000000000UL
        CR2_0, 0x1UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x1UL; CR2_2, 0x1UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1001ba8"
      [ F3, 0x300000000000000UL
        VSRL3, 0x3ff0000000000000UL
        CR2_1, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1001ba8"
      [ F3, 0x3f0000000000000UL; VSRL3, 0x3ff0000000000000UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1001ba8"
      [ F3, 0xbff0000000000000UL; VSRL3, 0x3ff0000000000000UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1001ba8"
      [ F3, 0x7ff0000000000000UL; VSRL3, 0x3ff0000000000000UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x1UL; CR2_2, 0x1UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1001ba8"
      [ F3, 0x7ff8000000000001UL; VSRL3, 0x3ff0000000000000UL; CR2_1, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL ]
      []

  /// <summary>
  /// xvtsqrtsp BF, xB gathers the flags over four single lanes, an exponent at
  /// most -103 being the single format threshold.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVTSQRTSP uses the single thresholds``() =
    (* xvtsqrtsp cr2,vs3, under QEMU: lanes/x-oracle/tests *)
    oracleMem
      ppc64le
      "f1001aa8"
      [ F3, 0x3f80000040000000UL; VSRL3, 0x4080000041000000UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1001aa8"
      [ F3, 0x3f8000000b800000UL
        VSRL3, 0x3f8000003f800000UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1001aa8"
      [ F3, 0x3f80000080000001UL
        VSRL3, 0x3f800000bf800000UL
        CR2_0, 0x1UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x1UL; CR2_2, 0x1UL; CR2_3, 0x0UL ]
      []

  /// <summary>
  /// xststdcdp BF, xB, DCMX sets CR field BF and FPCC to the sign of the double
  /// in doubleword 0 of xB, 0, whether it is in a class DCMX selects, and 0;
  /// each of the seven classes is selected on its own over a value of every
  /// class, and then all of them.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSTSTDCDP tests each data class``() =
    (* xststdcdp cr2,vs3,64, under QEMU: lanes/x-oracle/tests *)
    oracleMem
      ppc64le
      "f1401da8"
      [ F3, 0x7ff8000000000001UL; VSRL3, 0x7ff8000000000001UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "f1401da8"
      [ F3, 0x7ff0000000000000UL
        VSRL3, 0x7ff0000000000000UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1401da8"
      [ F3, 0xfff0000000000000UL
        VSRL3, 0xfff0000000000000UL
        CR2_0, 0x1UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "f1401da8"
      [ CR2_1, 0x1UL; CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1401da8"
      [ F3, 0x8000000000000000UL; VSRL3, 0x8000000000000000UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "f1401da8"
      [ F3, 0xfffffffffffffUL; VSRL3, 0xfffffffffffffUL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1401da8"
      [ F3, 0x800fffffffffffffUL; VSRL3, 0x800fffffffffffffUL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "f1401da8"
      [ F3, 0x3ff0000000000000UL; VSRL3, 0x3ff0000000000000UL; CR2_1, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1201da8"
      [ F3, 0x7ff8000000000001UL; VSRL3, 0x7ff8000000000001UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1201da8"
      [ F3, 0x7ff0000000000000UL
        VSRL3, 0x7ff0000000000000UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "f1201da8"
      [ F3, 0xfff0000000000000UL
        VSRL3, 0xfff0000000000000UL
        CR2_0, 0x1UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "f1201da8"
      [ CR2_1, 0x1UL; CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1201da8"
      [ F3, 0x8000000000000000UL; VSRL3, 0x8000000000000000UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "f1201da8"
      [ F3, 0xfffffffffffffUL; VSRL3, 0xfffffffffffffUL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1201da8"
      [ F3, 0x800fffffffffffffUL; VSRL3, 0x800fffffffffffffUL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "f1201da8"
      [ F3, 0x3ff0000000000000UL; VSRL3, 0x3ff0000000000000UL; CR2_1, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1101da8"
      [ F3, 0x7ff8000000000001UL; VSRL3, 0x7ff8000000000001UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1101da8"
      [ F3, 0x7ff0000000000000UL
        VSRL3, 0x7ff0000000000000UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1101da8"
      [ F3, 0xfff0000000000000UL
        VSRL3, 0xfff0000000000000UL
        CR2_0, 0x1UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0xaUL ]
      []
    oracleMem
      ppc64le
      "f1101da8"
      [ CR2_1, 0x1UL; CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1101da8"
      [ F3, 0x8000000000000000UL; VSRL3, 0x8000000000000000UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "f1101da8"
      [ F3, 0xfffffffffffffUL; VSRL3, 0xfffffffffffffUL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1101da8"
      [ F3, 0x800fffffffffffffUL; VSRL3, 0x800fffffffffffffUL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "f1101da8"
      [ F3, 0x3ff0000000000000UL; VSRL3, 0x3ff0000000000000UL; CR2_1, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1081da8"
      [ F3, 0x7ff8000000000001UL; VSRL3, 0x7ff8000000000001UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1081da8"
      [ F3, 0x7ff0000000000000UL
        VSRL3, 0x7ff0000000000000UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1081da8"
      [ F3, 0xfff0000000000000UL
        VSRL3, 0xfff0000000000000UL
        CR2_0, 0x1UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "f1081da8"
      [ CR2_1, 0x1UL; CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "f1081da8"
      [ F3, 0x8000000000000000UL; VSRL3, 0x8000000000000000UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "f1081da8"
      [ F3, 0xfffffffffffffUL; VSRL3, 0xfffffffffffffUL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1081da8"
      [ F3, 0x800fffffffffffffUL; VSRL3, 0x800fffffffffffffUL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "f1081da8"
      [ F3, 0x3ff0000000000000UL; VSRL3, 0x3ff0000000000000UL; CR2_1, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1041da8"
      [ F3, 0x7ff8000000000001UL; VSRL3, 0x7ff8000000000001UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1041da8"
      [ F3, 0x7ff0000000000000UL
        VSRL3, 0x7ff0000000000000UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1041da8"
      [ F3, 0xfff0000000000000UL
        VSRL3, 0xfff0000000000000UL
        CR2_0, 0x1UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "f1041da8"
      [ CR2_1, 0x1UL; CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1041da8"
      [ F3, 0x8000000000000000UL; VSRL3, 0x8000000000000000UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0xaUL ]
      []
    oracleMem
      ppc64le
      "f1041da8"
      [ F3, 0xfffffffffffffUL; VSRL3, 0xfffffffffffffUL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1041da8"
      [ F3, 0x800fffffffffffffUL; VSRL3, 0x800fffffffffffffUL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "f1041da8"
      [ F3, 0x3ff0000000000000UL; VSRL3, 0x3ff0000000000000UL; CR2_1, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1021da8"
      [ F3, 0x7ff8000000000001UL; VSRL3, 0x7ff8000000000001UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1021da8"
      [ F3, 0x7ff0000000000000UL
        VSRL3, 0x7ff0000000000000UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1021da8"
      [ F3, 0xfff0000000000000UL
        VSRL3, 0xfff0000000000000UL
        CR2_0, 0x1UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "f1021da8"
      [ CR2_1, 0x1UL; CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1021da8"
      [ F3, 0x8000000000000000UL; VSRL3, 0x8000000000000000UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "f1021da8"
      [ F3, 0xfffffffffffffUL; VSRL3, 0xfffffffffffffUL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "f1021da8"
      [ F3, 0x800fffffffffffffUL; VSRL3, 0x800fffffffffffffUL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "f1021da8"
      [ F3, 0x3ff0000000000000UL; VSRL3, 0x3ff0000000000000UL; CR2_1, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1011da8"
      [ F3, 0x7ff8000000000001UL; VSRL3, 0x7ff8000000000001UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1011da8"
      [ F3, 0x7ff0000000000000UL
        VSRL3, 0x7ff0000000000000UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1011da8"
      [ F3, 0xfff0000000000000UL
        VSRL3, 0xfff0000000000000UL
        CR2_0, 0x1UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "f1011da8"
      [ CR2_1, 0x1UL; CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1011da8"
      [ F3, 0x8000000000000000UL; VSRL3, 0x8000000000000000UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "f1011da8"
      [ F3, 0xfffffffffffffUL; VSRL3, 0xfffffffffffffUL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1011da8"
      [ F3, 0x800fffffffffffffUL; VSRL3, 0x800fffffffffffffUL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0xaUL ]
      []
    oracleMem
      ppc64le
      "f1011da8"
      [ F3, 0x3ff0000000000000UL; VSRL3, 0x3ff0000000000000UL; CR2_1, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f17f1da8"
      [ F3, 0x7ff8000000000001UL; VSRL3, 0x7ff8000000000001UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "f17f1da8"
      [ F3, 0x7ff0000000000000UL
        VSRL3, 0x7ff0000000000000UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "f17f1da8"
      [ F3, 0xfff0000000000000UL
        VSRL3, 0xfff0000000000000UL
        CR2_0, 0x1UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0xaUL ]
      []
    oracleMem
      ppc64le
      "f17f1da8"
      [ CR2_1, 0x1UL; CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0x2UL ]
      []

  /// <summary>
  /// xststdcsp BF, xB, DCMX classifies the double in doubleword 0 of xB as it
  /// would be in single precision -- an exponent below the single range is a
  /// denormal there -- and sets bit 3 of CR field BF and FPCC where no single
  /// represents the value. Under a mask selecting NaN and +Inf only, QEMU 8.2.2
  /// still matches a value in the single denormal range; the manual does not,
  /// and that is asserted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSTSTDCSP reads the classes as a single``() =
    (* xststdcsp cr2,vs3,3, under QEMU: lanes/x-oracle/tests *)
    oracleMem
      ppc64le
      "f1031ca8"
      [ F3, 0x7ff8000000000001UL; VSRL3, 0x7ff8000000000001UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x1UL; FPSCR, 0x1UL ]
      []
    oracleMem
      ppc64le
      "f1031ca8"
      [ F3, 0x7ff0000000000000UL
        VSRL3, 0x7ff0000000000000UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1031ca8"
      [ F3, 0xfff0000000000000UL
        VSRL3, 0xfff0000000000000UL
        CR2_0, 0x1UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "f1031ca8"
      [ CR2_1, 0x1UL; CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1031ca8"
      [ F3, 0x8000000000000000UL; VSRL3, 0x8000000000000000UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "f1031ca8"
      [ F3, 0xfffffffffffffUL; VSRL3, 0xfffffffffffffUL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x1UL; FPSCR, 0x3UL ]
      []
    oracleMem
      ppc64le
      "f1031ca8"
      [ F3, 0x800fffffffffffffUL; VSRL3, 0x800fffffffffffffUL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x1UL; FPSCR, 0xbUL ]
      []
    oracleMem
      ppc64le
      "f1031ca8"
      [ F3, 0x3ff0000000000000UL; VSRL3, 0x3ff0000000000000UL; CR2_1, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1031ca8"
      [ F3, 0x3800000000000000UL; VSRL3, 0x3800000000000000UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "f1031ca8"
      [ F3, 0x36a0000000000000UL
        VSRL3, 0x36a0000000000000UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "f1031ca8"
      [ F3, 0x3810000000000000UL
        VSRL3, 0x3810000000000000UL
        CR2_0, 0x1UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1031ca8"
      [ F3, 0x3ff0000000000001UL
        VSRL3, 0x3ff0000000000001UL
        CR2_1, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x1UL; FPSCR, 0x1UL ]
      []
    oracleMem
      ppc64le
      "f1601ca8"
      [ F3, 0x7ff8000000000001UL; VSRL3, 0x7ff8000000000001UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x1UL; FPSCR, 0x3UL ]
      []
    oracleMem
      ppc64le
      "f1601ca8"
      [ F3, 0x7ff0000000000000UL
        VSRL3, 0x7ff0000000000000UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "f1601ca8"
      [ F3, 0xfff0000000000000UL
        VSRL3, 0xfff0000000000000UL
        CR2_0, 0x1UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "f1601ca8"
      [ CR2_1, 0x1UL; CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1601ca8"
      [ F3, 0x8000000000000000UL; VSRL3, 0x8000000000000000UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "f1601ca8"
      [ F3, 0xfffffffffffffUL; VSRL3, 0xfffffffffffffUL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x1UL; FPSCR, 0x1UL ]
      []
    oracleMem
      ppc64le
      "f1601ca8"
      [ F3, 0x800fffffffffffffUL; VSRL3, 0x800fffffffffffffUL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x1UL; FPSCR, 0x9UL ]
      []
    oracleMem
      ppc64le
      "f1601ca8"
      [ F3, 0x3ff0000000000000UL; VSRL3, 0x3ff0000000000000UL; CR2_1, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1601ca8"
      [ F3, 0x3810000000000000UL
        VSRL3, 0x3810000000000000UL
        CR2_0, 0x1UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1601ca8"
      [ F3, 0x3ff0000000000001UL
        VSRL3, 0x3ff0000000000001UL
        CR2_1, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x1UL; FPSCR, 0x1UL ]
      []
    oracleMem
      ppc64le
      "f1601ca8"
      [ F3, 0x3800000000000000UL; VSRL3, 0x3800000000000000UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_3, 0x0UL; CR2_2, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f1601ca8"
      [ F3, 0x36a0000000000000UL
        VSRL3, 0x36a0000000000000UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_3, 0x0UL; CR2_2, 0x0UL; FPSCR, 0x0UL ]
      []

  /// <summary>
  /// xvtstdcdp xT, xB, DCMX sets each double element of xT to all ones where
  /// the matching element of xB is in a class DCMX selects; each class selected
  /// on its own, over every class.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVTSTDCDP writes lane masks of data classes``() =
    (* xvtstdcdp vs1,vs3,64, under QEMU: lanes/x-oracle/tests *)
    oracleMem
      ppc64le
      "f0201fe8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff8000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7ff0000000000000UL ]
      []
      [ F1, 0xffffffffffffffffUL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0201fe8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0xfff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0201fe8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfffffffffffffUL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0201fe8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x800fffffffffffffUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0201fac"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff8000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0xffffffffffffffffUL ]
      []
    oracleMem
      ppc64le
      "f0201fac"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0xfff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0201fac"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfffffffffffffUL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0201fac"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x800fffffffffffffUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0301fa8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff8000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0301fa8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0xfff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0xffffffffffffffffUL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0301fa8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfffffffffffffUL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0301fa8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x800fffffffffffffUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0281fa8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff8000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0281fa8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0xfff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0x0UL; VSRL1, 0xffffffffffffffffUL ]
      []
    oracleMem
      ppc64le
      "f0281fa8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfffffffffffffUL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0281fa8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x800fffffffffffffUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0241fa8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff8000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0241fa8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0xfff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0241fa8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfffffffffffffUL ]
      []
      [ F1, 0xffffffffffffffffUL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0241fa8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x800fffffffffffffUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221fa8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff8000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221fa8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0xfff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221fa8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfffffffffffffUL ]
      []
      [ F1, 0x0UL; VSRL1, 0xffffffffffffffffUL ]
      []
    oracleMem
      ppc64le
      "f0221fa8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x800fffffffffffffUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0211fa8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff8000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0211fa8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0xfff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0211fa8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfffffffffffffUL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0211fa8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x800fffffffffffffUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0xffffffffffffffffUL; VSRL1, 0x0UL ]
      []

  /// <summary>
  /// xvtstdcsp xT, xB, DCMX does the same over four single elements.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVTSTDCSP writes lane masks of data classes``() =
    (* xvtstdcsp vs1,vs3,64, under QEMU: lanes/x-oracle/tests *)
    oracleMem
      ppc64le
      "f0201ee8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7fc000007f800000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xff80000000000000UL ]
      []
      [ F1, 0xffffffff00000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0201ee8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x800000013f800000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0201eac"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7fc000007f800000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xff80000000000000UL ]
      []
      [ F1, 0xffffffffUL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0201eac"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x800000013f800000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0301ea8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7fc000007f800000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xff80000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0xffffffff00000000UL ]
      []
    oracleMem
      ppc64le
      "f0301ea8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x800000013f800000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0281ea8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7fc000007f800000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xff80000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0xffffffffUL ]
      []
    oracleMem
      ppc64le
      "f0281ea8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x800000013f800000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0241ea8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7fc000007f800000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xff80000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0241ea8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x800000013f800000UL ]
      []
      [ F1, 0xffffffff00000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221ea8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7fc000007f800000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xff80000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0221ea8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x800000013f800000UL ]
      []
      [ F1, 0xffffffffUL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0211ea8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7fc000007f800000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xff80000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0211ea8"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x800000013f800000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0xffffffff00000000UL ]
      []

  /// <summary>
  /// xsiexpdp xT, rA, rB places in doubleword 0 of xT the sign and fraction of
  /// rA with the low eleven bits of rB as the exponent field, and clears
  /// doubleword 1.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSIEXPDP inserts an exponent from rB``() =
    (* xsiexpdp vs1,r6,r7, under QEMU: lanes/x-oracle/tests *)
    oracleMem
      ppc64le
      "f0263f2c"
      [ R6, 0x8123456789abcdefUL
        R7, 0x3ffUL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0xbff3456789abcdefUL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0263f2c"
      [ R6, 0xfffffffffffffUL
        R7, 0xfffffffffffff800UL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0xfffffffffffffUL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0263f2c"
      [ R6, 0x7fffffffffffffffUL
        R7, 0x7ffUL
        F1, 0xbad0bad0bad0badUL
        VSRL1, 0xbad0bad0bad0badUL ]
      []
      [ F1, 0x7fffffffffffffffUL; VSRL1, 0x0UL ]
      []

  /// <summary>
  /// xsxexpdp rT, xB places in rT the eleven-bit exponent field of the double
  /// in doubleword 0 of xB, zero-extended.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSXEXPDP extracts the exponent field``() =
    (* xsxexpdp r5,vs3, under QEMU: lanes/x-oracle/tests *)
    oracleMem
      ppc64le
      "f0a01d6c"
      [ R5, 0xbad0bad0bad0badUL
        F3, 0x3ff0000000000000UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ R5, 0x3ffUL ]
      []
    oracleMem
      ppc64le
      "f0a01d6c"
      [ R5, 0xbad0bad0bad0badUL
        F3, 0xfffffffffffffUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ R5, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0a01d6c"
      [ R5, 0xbad0bad0bad0badUL
        F3, 0x7ff0000000000000UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ R5, 0x7ffUL ]
      []
    oracleMem
      ppc64le
      "f0a01d6c"
      [ R5, 0xbad0bad0bad0badUL
        F3, 0x7ff8000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ R5, 0x7ffUL ]
      []
    oracleMem
      ppc64le
      "f0a01d6c"
      [ R5, 0xbad0bad0bad0badUL
        F3, 0x8000000000000000UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ R5, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0a01d6c"
      [ R5, 0xbad0bad0bad0badUL
        F3, 0xc123456789abcdefUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ R5, 0x412UL ]
      []

  /// <summary>
  /// xsxsigdp rT, xB places in rT the fraction of the double in doubleword 0 of
  /// xB with the implicit bit set where the value is normal, clear for a zero,
  /// a denormal, an infinity or a NaN.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSXSIGDP extracts the significand``() =
    (* xsxsigdp r5,vs3, under QEMU: lanes/x-oracle/tests *)
    oracleMem
      ppc64le
      "f0a11d6c"
      [ R5, 0xbad0bad0bad0badUL
        F3, 0x3ff0000000000000UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ R5, 0x10000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0a11d6c"
      [ R5, 0xbad0bad0bad0badUL
        F3, 0xfffffffffffffUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ R5, 0xfffffffffffffUL ]
      []
    oracleMem
      ppc64le
      "f0a11d6c"
      [ R5, 0xbad0bad0bad0badUL
        F3, 0x7ff0000000000000UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ R5, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0a11d6c"
      [ R5, 0xbad0bad0bad0badUL
        F3, 0x7ff8000000000001UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ R5, 0x8000000000001UL ]
      []
    oracleMem
      ppc64le
      "f0a11d6c"
      [ R5, 0xbad0bad0bad0badUL
        F3, 0x8000000000000000UL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ R5, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0a11d6c"
      [ R5, 0xbad0bad0bad0badUL
        F3, 0xc123456789abcdefUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ R5, 0x13456789abcdefUL ]
      []

  /// <summary>
  /// xviexpdp xT, xA, xB places in each double element of xT the sign and
  /// fraction of xA with the low eleven bits of xB as the exponent field.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVIEXPDP inserts the exponents of xB``() =
    (* xviexpdp vs1,vs2,vs3, under QEMU: lanes/x-oracle/tests *)
    oracleMem
      ppc64le
      "f0221fc0"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x8123456789abcdefUL
        F3, 0x3ffUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0xfffffffffffffUL
        VSRL3, 0xfffffffffffff801UL ]
      []
      [ F1, 0xbff3456789abcdefUL; VSRL1, 0x1fffffffffffffUL ]
      []

  /// <summary>
  /// xviexpsp xT, xA, xB places in each single element of xT the sign and
  /// fraction of xA with the low eight bits of xB as the exponent field.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVIEXPSP inserts the exponents of xB``() =
    (* xviexpsp vs1,vs2,vs3, under QEMU: lanes/x-oracle/tests *)
    oracleMem
      ppc64le
      "f0221ec0"
      [ F1, 0xbad0bad0bad0badUL
        F2, 0x80123456007fffffUL
        F3, 0x7fffffff01UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL2, 0x7fffffff00000000UL
        VSRL3, 0xff00000080UL ]
      []
      [ F1, 0xbf92345600ffffffUL; VSRL1, 0x7fffffff40000000UL ]
      []

  /// <summary>
  /// xvxexpdp xT, xB places in each double element of xT the exponent field of
  /// xB, zero-extended.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVXEXPDP extracts the exponent fields``() =
    (* xvxexpdp vs1,vs3, under QEMU: lanes/x-oracle/tests *)
    oracleMem
      ppc64le
      "f0201f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfffffffffffffUL ]
      []
      [ F1, 0x3ffUL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0201f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7ff8000000000001UL ]
      []
      [ F1, 0x7ffUL; VSRL1, 0x7ffUL ]
      []
    oracleMem
      ppc64le
      "f0201f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc123456789abcdefUL ]
      []
      [ F1, 0x0UL; VSRL1, 0x412UL ]
      []

  /// <summary>
  /// xvxexpsp xT, xB places in each single element of xT the exponent field of
  /// xB, zero-extended.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVXEXPSP extracts the exponent fields``() =
    (* xvxexpsp vs1,vs3, under QEMU: lanes/x-oracle/tests *)
    oracleMem
      ppc64le
      "f0281f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3f80000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7f800000c0123456UL ]
      []
      [ F1, 0x7f00000000UL; VSRL1, 0xff00000080UL ]
      []

  /// <summary>
  /// xvxsigdp xT, xB places in each double element of xT its fraction with the
  /// implicit bit where the value is normal.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVXSIGDP extracts the significands``() =
    (* xvxsigdp vs1,vs3, under QEMU: lanes/x-oracle/tests *)
    oracleMem
      ppc64le
      "f0211f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfffffffffffffUL ]
      []
      [ F1, 0x10000000000000UL; VSRL1, 0xfffffffffffffUL ]
      []
    oracleMem
      ppc64le
      "f0211f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7ff8000000000001UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x8000000000001UL ]
      []
    oracleMem
      ppc64le
      "f0211f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc123456789abcdefUL ]
      []
      [ F1, 0x0UL; VSRL1, 0x13456789abcdefUL ]
      []

  /// <summary>
  /// xvxsigsp xT, xB places in each single element of xT its fraction with the
  /// implicit bit where the value is normal.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVXSIGSP extracts the significands``() =
    (* xvxsigsp vs1,vs3, under QEMU: lanes/x-oracle/tests *)
    oracleMem
      ppc64le
      "f0291f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3f80000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7f800000c0123456UL ]
      []
      [ F1, 0x80000000000001UL; VSRL1, 0x923456UL ]
      []

  /// <summary>
  /// xscvdphp xT, xB rounds the double in doubleword 0 of xB to half precision
  /// in the direction FPSCR[RN] names, zero-extends it into doubleword 0 of xT,
  /// clears doubleword 1 and sets FPRF to the class of the half: the largest
  /// half, a value that overflows it in some directions only, ties at the
  /// denormal and the normal end, a value too small for any half, a signalling
  /// NaN (quieted), -0 and -Inf.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSCVDPHP rounds a double to a half``() =
    (* xscvdphp vs1,vs3, under QEMU: lanes/x-oracle/convs *)
    oracleMem
      ppc64le
      "f0311d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x40effc0000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x7bffUL; VSRL1, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "f0311d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x40effc0000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL
        FPSCR, 0x1UL ]
      []
      [ F1, 0x7bffUL; VSRL1, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "f0311d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x40effc0000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL
        FPSCR, 0x2UL ]
      []
      [ F1, 0x7bffUL; VSRL1, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "f0311d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x40effc0000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL
        FPSCR, 0x3UL ]
      []
      [ F1, 0x7bffUL; VSRL1, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "f0311d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x40effe0000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x7c00UL; VSRL1, 0x0UL; FPSCR, 0x5UL ]
      []
    oracleMem
      ppc64le
      "f0311d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x40effe0000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL
        FPSCR, 0x1UL ]
      []
      [ F1, 0x7bffUL; VSRL1, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "f0311d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x40effe0000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL
        FPSCR, 0x2UL ]
      []
      [ F1, 0x7c00UL; VSRL1, 0x0UL; FPSCR, 0x5UL ]
      []
    oracleMem
      ppc64le
      "f0311d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x40effe0000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL
        FPSCR, 0x3UL ]
      []
      [ F1, 0x7bffUL; VSRL1, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "f0311d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3e60000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "f0311d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3e60000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL
        FPSCR, 0x1UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "f0311d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3e60000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL
        FPSCR, 0x2UL ]
      []
      [ F1, 0x1UL; VSRL1, 0x0UL; FPSCR, 0x14UL ]
      []
    oracleMem
      ppc64le
      "f0311d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3e60000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL
        FPSCR, 0x3UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "f0311d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3ff0020000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x3c00UL; VSRL1, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "f0311d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3ff0020000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL
        FPSCR, 0x1UL ]
      []
      [ F1, 0x3c00UL; VSRL1, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "f0311d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3ff0020000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL
        FPSCR, 0x2UL ]
      []
      [ F1, 0x3c01UL; VSRL1, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "f0311d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3ff0020000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL
        FPSCR, 0x3UL ]
      []
      [ F1, 0x3c00UL; VSRL1, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "f0311d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3ff0010000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x3c00UL; VSRL1, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "f0311d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3ff0010000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL
        FPSCR, 0x1UL ]
      []
      [ F1, 0x3c00UL; VSRL1, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "f0311d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3ff0010000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL
        FPSCR, 0x2UL ]
      []
      [ F1, 0x3c01UL; VSRL1, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "f0311d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3ff0010000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL
        FPSCR, 0x3UL ]
      []
      [ F1, 0x3c00UL; VSRL1, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "f0311d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3ddb7cdfd9d7bdbbUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "f0311d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3ddb7cdfd9d7bdbbUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL
        FPSCR, 0x1UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "f0311d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3ddb7cdfd9d7bdbbUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL
        FPSCR, 0x2UL ]
      []
      [ F1, 0x1UL; VSRL1, 0x0UL; FPSCR, 0x14UL ]
      []
    oracleMem
      ppc64le
      "f0311d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3ddb7cdfd9d7bdbbUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL
        FPSCR, 0x3UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "f0311d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x3c00UL; VSRL1, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "f0311d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3e70000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x1UL; VSRL1, 0x0UL; FPSCR, 0x14UL ]
      []
    oracleMem
      ppc64le
      "f0311d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff4000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x7f00UL; VSRL1, 0x0UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64le
      "f0311d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x8000UL; VSRL1, 0x0UL; FPSCR, 0x12UL ]
      []
    oracleMem
      ppc64le
      "f0311d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0xfff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0xfc00UL; VSRL1, 0x0UL; FPSCR, 0x9UL ]
      []
    oracleMem
      ppc64le
      "f0311d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0xc0f0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0xfc00UL; VSRL1, 0x0UL; FPSCR, 0x9UL ]
      []

  /// <summary>
  /// xscvhpdp xT, xB widens the half in halfword 3 of xB to a double in
  /// doubleword 0 of xT, exactly, a denormal normalized and a signalling NaN
  /// quieted; doubleword 1 is cleared and FPRF set.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSCVHPDP widens a half to a double``() =
    (* xscvhpdp vs1,vs3, under QEMU: lanes/x-oracle/convs *)
    oracleMem
      ppc64le
      "f0301d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3c00UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x3ff0000000000000UL; VSRL1, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "f0301d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x3e70000000000000UL; VSRL1, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "f0301d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3ffUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x3f0ff80000000000UL; VSRL1, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "f0301d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7c00UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x7ff0000000000000UL; VSRL1, 0x0UL; FPSCR, 0x5UL ]
      []
    oracleMem
      ppc64le
      "f0301d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0xfc00UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0xfff0000000000000UL; VSRL1, 0x0UL; FPSCR, 0x9UL ]
      []
    oracleMem
      ppc64le
      "f0301d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7e01UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x7ff8040000000000UL; VSRL1, 0x0UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64le
      "f0301d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7d00UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x7ffc000000000000UL; VSRL1, 0x0UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64le
      "f0301d6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x8000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff0000000000000UL ]
      []
      [ F1, 0x8000000000000000UL; VSRL1, 0x0UL; FPSCR, 0x12UL ]
      []

  /// <summary>
  /// xvcvsphp xT, xB rounds each single of xB to half precision in the
  /// direction FPSCR[RN] names, into the low halfword of its word, the high
  /// halfword cleared; every direction over ties, the range edge, denormals and
  /// a NaN.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVCVSPHP rounds singles to halves``() =
    (* xvcvsphp vs1,vs3, under QEMU: lanes/x-oracle/convs *)
    oracleMem
      ppc64le
      "f0391f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3f800000477fe000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x477ff00033800000UL ]
      []
      [ F1, 0x3c0000007bffUL; VSRL1, 0x7c0000000001UL ]
      []
    oracleMem
      ppc64le
      "f0391f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3f800000477fe000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x477ff00033800000UL
        FPSCR, 0x1UL ]
      []
      [ F1, 0x3c0000007bffUL; VSRL1, 0x7bff00000001UL ]
      []
    oracleMem
      ppc64le
      "f0391f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3f800000477fe000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x477ff00033800000UL
        FPSCR, 0x2UL ]
      []
      [ F1, 0x3c0000007bffUL; VSRL1, 0x7c0000000001UL ]
      []
    oracleMem
      ppc64le
      "f0391f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3f800000477fe000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x477ff00033800000UL
        FPSCR, 0x3UL ]
      []
      [ F1, 0x3c0000007bffUL; VSRL1, 0x7bff00000001UL ]
      []
    oracleMem
      ppc64le
      "f0391f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x330000003f801000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3f8008007fa00000UL ]
      []
      [ F1, 0x3c00UL; VSRL1, 0x3c0000007f00UL ]
      []
    oracleMem
      ppc64le
      "f0391f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x330000003f801000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3f8008007fa00000UL
        FPSCR, 0x1UL ]
      []
      [ F1, 0x3c00UL; VSRL1, 0x3c0000007f00UL ]
      []
    oracleMem
      ppc64le
      "f0391f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x330000003f801000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3f8008007fa00000UL
        FPSCR, 0x2UL ]
      []
      [ F1, 0x100003c01UL; VSRL1, 0x3c0100007f00UL ]
      []
    oracleMem
      ppc64le
      "f0391f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x330000003f801000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3f8008007fa00000UL
        FPSCR, 0x3UL ]
      []
      [ F1, 0x3c00UL; VSRL1, 0x3c0000007f00UL ]
      []
    oracleMem
      ppc64le
      "f0391f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x80000000ff800000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x387fc000c7800000UL ]
      []
      [ F1, 0x80000000fc00UL; VSRL1, 0x3ff0000fc00UL ]
      []
    oracleMem
      ppc64le
      "f0391f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x80000000ff800000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x387fc000c7800000UL
        FPSCR, 0x1UL ]
      []
      [ F1, 0x80000000fc00UL; VSRL1, 0x3ff0000fbffUL ]
      []
    oracleMem
      ppc64le
      "f0391f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x80000000ff800000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x387fc000c7800000UL
        FPSCR, 0x2UL ]
      []
      [ F1, 0x80000000fc00UL; VSRL1, 0x3ff0000fbffUL ]
      []
    oracleMem
      ppc64le
      "f0391f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x80000000ff800000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x387fc000c7800000UL
        FPSCR, 0x3UL ]
      []
      [ F1, 0x80000000fc00UL; VSRL1, 0x3ff0000fc00UL ]
      []

  /// <summary>
  /// xvcvhpsp xT, xB widens the half in the low halfword of each word of xB to
  /// a single, exactly, a signalling NaN quieted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVCVHPSP widens halves to singles``() =
    (* xvcvhpsp vs1,vs3, under QEMU: lanes/x-oracle/convs *)
    oracleMem
      ppc64le
      "f0381f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3c0000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3ff00007c00UL ]
      []
      [ F1, 0x3f80000033800000UL; VSRL1, 0x387fc0007f800000UL ]
      []
    oracleMem
      ppc64le
      "f0381f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0xfc0000007e01UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7d0000008000UL ]
      []
      [ F1, 0xff8000007fc02000UL; VSRL1, 0x7fe0000080000000UL ]
      []

  /// <summary>
  /// xvcvspbf16 xT, xB rounds each single of xB to bfloat16 in the direction
  /// FPSCR[RN] names, into the low halfword of its word: ties to even and away,
  /// the largest single, a signalling NaN quieted, a denormal.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVCVSPBF16 rounds singles to bfloat16``() =
    (* xvcvspbf16 vs1,vs3, under QEMU: lanes/x-oracle/convs *)
    oracleMem
      ppc64le
      "f0311f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3f8000003f808000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3f8180007f7fffffUL ]
      []
      [ F1, 0x3f8000003f80UL; VSRL1, 0x3f8200007f80UL ]
      []
    oracleMem
      ppc64le
      "f0311f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3f8000003f808000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3f8180007f7fffffUL
        FPSCR, 0x1UL ]
      []
      [ F1, 0x3f8000003f80UL; VSRL1, 0x3f8100007f7fUL ]
      []
    oracleMem
      ppc64le
      "f0311f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3f8000003f808000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3f8180007f7fffffUL
        FPSCR, 0x2UL ]
      []
      [ F1, 0x3f8000003f81UL; VSRL1, 0x3f8200007f80UL ]
      []
    oracleMem
      ppc64le
      "f0311f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3f8000003f808000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x3f8180007f7fffffUL
        FPSCR, 0x3UL ]
      []
      [ F1, 0x3f8000003f80UL; VSRL1, 0x3f8100007f7fUL ]
      []
    oracleMem
      ppc64le
      "f0311f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7fa0000180000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x800000bf80c000UL ]
      []
      [ F1, 0x7fe000008000UL; VSRL1, 0x800000bf81UL ]
      []
    oracleMem
      ppc64le
      "f0311f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7fa0000180000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x800000bf80c000UL
        FPSCR, 0x1UL ]
      []
      [ F1, 0x7fe000008000UL; VSRL1, 0x800000bf80UL ]
      []
    oracleMem
      ppc64le
      "f0311f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7fa0000180000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x800000bf80c000UL
        FPSCR, 0x2UL ]
      []
      [ F1, 0x7fe000008000UL; VSRL1, 0x800000bf80UL ]
      []
    oracleMem
      ppc64le
      "f0311f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7fa0000180000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x800000bf80c000UL
        FPSCR, 0x3UL ]
      []
      [ F1, 0x7fe000008001UL; VSRL1, 0x800000bf81UL ]
      []

  /// <summary>
  /// xvcvbf16spn xT, xB places the bfloat16 in the low halfword of each word of
  /// xB in the high halfword of the word of xT and clears the low one: the
  /// single it stands for, NaNs left as they are.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVCVBF16SPN moves bfloat16 into singles``() =
    (* xvcvbf16spn vs1,vs3, under QEMU: lanes/x-oracle/convs *)
    oracleMem
      ppc64le
      "f0301f6c"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3f8000007fc1UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xff8000000001UL ]
      []
      [ F1, 0x3f8000007fc10000UL; VSRL1, 0xff80000000010000UL ]
      []

  /// <summary>
  /// xvcvdpsxds xT, xB converts each double of xB to signed doublewords of xT,
  /// truncating toward zero, saturating at the ends of the range and answering
  /// a NaN with the low end; the vectors sit on both sides of each end.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVCVDPSXDS saturates at the ends``() =
    (* xvcvdpsxds vs1,vs3, under QEMU: lanes/x-oracle/convs *)
    oracleMem
      ppc64le
      "f0201f60"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc1e0000000000000UL ]
      []
      [ F1, 0x1UL; VSRL1, 0xffffffff80000000UL ]
      []
    oracleMem
      ppc64le
      "f0201f60"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x41dfffffffc00000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc1e0000000100000UL ]
      []
      [ F1, 0x7fffffffUL; VSRL1, 0xffffffff80000000UL ]
      []
    oracleMem
      ppc64le
      "f0201f60"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x43e0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc3e0000000000000UL ]
      []
      [ F1, 0x7fffffffffffffffUL; VSRL1, 0x8000000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201f60"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff8000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfff0000000000000UL ]
      []
      [ F1, 0x8000000000000000UL; VSRL1, 0x8000000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201f60"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x41efffffffe00000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbfe0000000000000UL ]
      []
      [ F1, 0xffffffffUL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0201f60"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x43f0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x4330000000000001UL ]
      []
      [ F1, 0x7fffffffffffffffUL; VSRL1, 0x10000000000001UL ]
      []

  /// <summary>
  /// xvcvdpuxds xT, xB converts each double of xB to unsigned doublewords of
  /// xT, truncating toward zero, saturating at the ends of the range and
  /// answering a NaN with the low end; the vectors sit on both sides of each
  /// end.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVCVDPUXDS saturates at the ends``() =
    (* xvcvdpuxds vs1,vs3, under QEMU: lanes/x-oracle/convs *)
    oracleMem
      ppc64le
      "f0201f20"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc1e0000000000000UL ]
      []
      [ F1, 0x1UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0201f20"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x41dfffffffc00000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc1e0000000100000UL ]
      []
      [ F1, 0x7fffffffUL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0201f20"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x43e0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc3e0000000000000UL ]
      []
      [ F1, 0x8000000000000000UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0201f20"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff8000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0201f20"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x41efffffffe00000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbfe0000000000000UL ]
      []
      [ F1, 0xffffffffUL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0201f20"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x43f0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x4330000000000001UL ]
      []
      [ F1, 0xffffffffffffffffUL; VSRL1, 0x10000000000001UL ]
      []

  /// <summary>
  /// xvcvdpsxws xT, xB converts each double of xB to signed words, in both
  /// words of xT, truncating toward zero, saturating at the ends of the range
  /// and answering a NaN with the low end; the vectors sit on both sides of
  /// each end.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVCVDPSXWS saturates at the ends``() =
    (* xvcvdpsxws vs1,vs3, under QEMU: lanes/x-oracle/convs *)
    oracleMem
      ppc64le
      "f0201b60"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc1e0000000000000UL ]
      []
      [ F1, 0x100000001UL; VSRL1, 0x8000000080000000UL ]
      []
    oracleMem
      ppc64le
      "f0201b60"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x41dfffffffc00000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc1e0000000100000UL ]
      []
      [ F1, 0x7fffffff7fffffffUL; VSRL1, 0x8000000080000000UL ]
      []
    oracleMem
      ppc64le
      "f0201b60"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x43e0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc3e0000000000000UL ]
      []
      [ F1, 0x7fffffff7fffffffUL; VSRL1, 0x8000000080000000UL ]
      []
    oracleMem
      ppc64le
      "f0201b60"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff8000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfff0000000000000UL ]
      []
      [ F1, 0x8000000080000000UL; VSRL1, 0x8000000080000000UL ]
      []
    oracleMem
      ppc64le
      "f0201b60"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x41efffffffe00000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbfe0000000000000UL ]
      []
      [ F1, 0x7fffffff7fffffffUL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0201b60"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x43f0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x4330000000000001UL ]
      []
      [ F1, 0x7fffffff7fffffffUL; VSRL1, 0x7fffffff7fffffffUL ]
      []

  /// <summary>
  /// xvcvdpuxws xT, xB converts each double of xB to unsigned words, in both
  /// words of xT, truncating toward zero, saturating at the ends of the range
  /// and answering a NaN with the low end; the vectors sit on both sides of
  /// each end.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVCVDPUXWS saturates at the ends``() =
    (* xvcvdpuxws vs1,vs3, under QEMU: lanes/x-oracle/convs *)
    oracleMem
      ppc64le
      "f0201b20"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc1e0000000000000UL ]
      []
      [ F1, 0x100000001UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0201b20"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x41dfffffffc00000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc1e0000000100000UL ]
      []
      [ F1, 0x7fffffff7fffffffUL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0201b20"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x43e0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc3e0000000000000UL ]
      []
      [ F1, 0xffffffffffffffffUL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0201b20"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff8000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfff0000000000000UL ]
      []
      [ F1, 0x0UL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0201b20"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x41efffffffe00000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbfe0000000000000UL ]
      []
      [ F1, 0xffffffffffffffffUL; VSRL1, 0x0UL ]
      []
    oracleMem
      ppc64le
      "f0201b20"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x43f0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x4330000000000001UL ]
      []
      [ F1, 0xffffffffffffffffUL; VSRL1, 0xffffffffffffffffUL ]
      []

  /// <summary>
  /// xvcvdpsp xT, xB rounds each double of xB to a single, written into both
  /// words of the doubleword.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVCVDPSP rounds doubles to singles``() =
    (* xvcvdpsp vs1,vs3, under QEMU: lanes/x-oracle/convs *)
    oracleMem
      ppc64le
      "f0201e24"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3ff0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc1e0000000000000UL ]
      []
      [ F1, 0x3f8000003f800000UL; VSRL1, 0xcf000000cf000000UL ]
      []
    oracleMem
      ppc64le
      "f0201e24"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x41dfffffffc00000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc1e0000000100000UL ]
      []
      [ F1, 0x4f0000004f000000UL; VSRL1, 0xcf000000cf000000UL ]
      []
    oracleMem
      ppc64le
      "f0201e24"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x43e0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xc3e0000000000000UL ]
      []
      [ F1, 0x5f0000005f000000UL; VSRL1, 0xdf000000df000000UL ]
      []
    oracleMem
      ppc64le
      "f0201e24"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7ff8000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xfff0000000000000UL ]
      []
      [ F1, 0x7fc000007fc00000UL; VSRL1, 0xff800000ff800000UL ]
      []
    oracleMem
      ppc64le
      "f0201e24"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x41efffffffe00000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xbfe0000000000000UL ]
      []
      [ F1, 0x4f8000004f800000UL; VSRL1, 0xbf000000bf000000UL ]
      []
    oracleMem
      ppc64le
      "f0201e24"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x43f0000000000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x4330000000000001UL ]
      []
      [ F1, 0x5f8000005f800000UL; VSRL1, 0x5980000059800000UL ]
      []

  /// <summary>
  /// xvcvspsxds xT, xB converts the single in word 0 of each doubleword of xB
  /// to signed doublewords, truncating toward zero and saturating, a NaN giving
  /// the low end.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVCVSPSXDS saturates at the ends``() =
    (* xvcvspsxds vs1,vs3, under QEMU: lanes/x-oracle/convs *)
    oracleMem
      ppc64le
      "f0201e60"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3f800000cf000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x4f0000007fc00000UL ]
      []
      [ F1, 0x1UL; VSRL1, 0x80000000UL ]
      []
    oracleMem
      ppc64le
      "f0201e60"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4f800000bf000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x5f000000df000001UL ]
      []
      [ F1, 0x100000000UL; VSRL1, 0x7fffffffffffffffUL ]
      []

  /// <summary>
  /// xvcvspuxds xT, xB converts the single in word 0 of each doubleword of xB
  /// to unsigned doublewords, truncating toward zero and saturating, a NaN
  /// giving the low end.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVCVSPUXDS saturates at the ends``() =
    (* xvcvspuxds vs1,vs3, under QEMU: lanes/x-oracle/convs *)
    oracleMem
      ppc64le
      "f0201e20"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3f800000cf000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x4f0000007fc00000UL ]
      []
      [ F1, 0x1UL; VSRL1, 0x80000000UL ]
      []
    oracleMem
      ppc64le
      "f0201e20"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4f800000bf000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x5f000000df000001UL ]
      []
      [ F1, 0x100000000UL; VSRL1, 0x8000000000000000UL ]
      []

  /// <summary>
  /// xvcvspsxws xT, xB converts each single of xB to signed words, truncating
  /// toward zero and saturating, a NaN giving the low end.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVCVSPSXWS saturates at the ends``() =
    (* xvcvspsxws vs1,vs3, under QEMU: lanes/x-oracle/convs *)
    oracleMem
      ppc64le
      "f0201a60"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3f800000cf000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x4f0000007fc00000UL ]
      []
      [ F1, 0x180000000UL; VSRL1, 0x7fffffff80000000UL ]
      []
    oracleMem
      ppc64le
      "f0201a60"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4f800000bf000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x5f000000df000001UL ]
      []
      [ F1, 0x7fffffff00000000UL; VSRL1, 0x7fffffff80000000UL ]
      []

  /// <summary>
  /// xvcvspuxws xT, xB converts each single of xB to unsigned words, truncating
  /// toward zero and saturating, a NaN giving the low end.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVCVSPUXWS saturates at the ends``() =
    (* xvcvspuxws vs1,vs3, under QEMU: lanes/x-oracle/convs *)
    oracleMem
      ppc64le
      "f0201a20"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3f800000cf000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x4f0000007fc00000UL ]
      []
      [ F1, 0x100000000UL; VSRL1, 0x8000000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201a20"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4f800000bf000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x5f000000df000001UL ]
      []
      [ F1, 0xffffffff00000000UL; VSRL1, 0xffffffff00000000UL ]
      []

  /// <summary>
  /// xvcvspdp xT, xB widens the single in word 0 of each doubleword of xB to a
  /// double, a signalling NaN quieted.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVCVSPDP widens singles to doubles``() =
    (* xvcvspdp vs1,vs3, under QEMU: lanes/x-oracle/convs *)
    oracleMem
      ppc64le
      "f0201f24"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x3f800000cf000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x4f0000007fc00000UL ]
      []
      [ F1, 0x3ff0000000000000UL; VSRL1, 0x41e0000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201f24"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x4f800000bf000000UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x5f000000df000001UL ]
      []
      [ F1, 0x41f0000000000000UL; VSRL1, 0x43e0000000000000UL ]
      []

  /// <summary>
  /// xvcvsxddp xT, xB converts each signed doubleword to a double, rounded to
  /// nearest here.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVCVSXDDP rounds integers``() =
    (* xvcvsxddp vs1,vs3, under QEMU: lanes/x-oracle/convs *)
    oracleMem
      ppc64le
      "f0201fe0"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xffffffffffffffffUL ]
      []
      [ F1, 0x3ff0000000000000UL; VSRL1, 0xbff0000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201fe0"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7fffffffffffffffUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8000000000000000UL ]
      []
      [ F1, 0x43e0000000000000UL; VSRL1, 0xc3e0000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201fe0"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x20000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7fffffffUL ]
      []
      [ F1, 0x4340000000000000UL; VSRL1, 0x41dfffffffc00000UL ]
      []

  /// <summary>
  /// xvcvuxddp xT, xB converts each unsigned doubleword to a double, rounded to
  /// nearest here.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVCVUXDDP rounds integers``() =
    (* xvcvuxddp vs1,vs3, under QEMU: lanes/x-oracle/convs *)
    oracleMem
      ppc64le
      "f0201fa0"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xffffffffffffffffUL ]
      []
      [ F1, 0x3ff0000000000000UL; VSRL1, 0x43f0000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201fa0"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7fffffffffffffffUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8000000000000000UL ]
      []
      [ F1, 0x43e0000000000000UL; VSRL1, 0x43e0000000000000UL ]
      []
    oracleMem
      ppc64le
      "f0201fa0"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x20000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7fffffffUL ]
      []
      [ F1, 0x4340000000000000UL; VSRL1, 0x41dfffffffc00000UL ]
      []

  /// <summary>
  /// xvcvsxdsp xT, xB converts each signed doubleword to a single, in both
  /// words, rounded to nearest here.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVCVSXDSP rounds integers``() =
    (* xvcvsxdsp vs1,vs3, under QEMU: lanes/x-oracle/convs *)
    oracleMem
      ppc64le
      "f0201ee0"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xffffffffffffffffUL ]
      []
      [ F1, 0x3f8000003f800000UL; VSRL1, 0xbf800000bf800000UL ]
      []
    oracleMem
      ppc64le
      "f0201ee0"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7fffffffffffffffUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8000000000000000UL ]
      []
      [ F1, 0x5f0000005f000000UL; VSRL1, 0xdf000000df000000UL ]
      []
    oracleMem
      ppc64le
      "f0201ee0"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x20000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7fffffffUL ]
      []
      [ F1, 0x5a0000005a000000UL; VSRL1, 0x4f0000004f000000UL ]
      []

  /// <summary>
  /// xvcvuxdsp xT, xB converts each unsigned doubleword to a single, in both
  /// words, rounded to nearest here.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVCVUXDSP rounds integers``() =
    (* xvcvuxdsp vs1,vs3, under QEMU: lanes/x-oracle/convs *)
    oracleMem
      ppc64le
      "f0201ea0"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xffffffffffffffffUL ]
      []
      [ F1, 0x3f8000003f800000UL; VSRL1, 0x5f8000005f800000UL ]
      []
    oracleMem
      ppc64le
      "f0201ea0"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x7fffffffffffffffUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x8000000000000000UL ]
      []
      [ F1, 0x5f0000005f000000UL; VSRL1, 0x5f0000005f000000UL ]
      []
    oracleMem
      ppc64le
      "f0201ea0"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x20000000000001UL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7fffffffUL ]
      []
      [ F1, 0x5a0000005a000000UL; VSRL1, 0x4f0000004f000000UL ]
      []

  /// <summary>
  /// xvcvsxwsp xT, xB converts each signed word to a single.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVCVSXWSP converts words``() =
    (* xvcvsxwsp vs1,vs3, under QEMU: lanes/x-oracle/convs *)
    oracleMem
      ppc64le
      "f0201ae0"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1ffffffffUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7fffffff80000000UL ]
      []
      [ F1, 0x3f800000bf800000UL; VSRL1, 0x4f000000cf000000UL ]
      []
    oracleMem
      ppc64le
      "f0201ae0"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1000001fefffffeUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xffffffUL ]
      []
      [ F1, 0x4b800000cb800001UL; VSRL1, 0x4b7fffffUL ]
      []

  /// <summary>
  /// xvcvuxwsp xT, xB converts each unsigned word to a single.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVCVUXWSP converts words``() =
    (* xvcvuxwsp vs1,vs3, under QEMU: lanes/x-oracle/convs *)
    oracleMem
      ppc64le
      "f0201aa0"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1ffffffffUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7fffffff80000000UL ]
      []
      [ F1, 0x3f8000004f800000UL; VSRL1, 0x4f0000004f000000UL ]
      []
    oracleMem
      ppc64le
      "f0201aa0"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1000001fefffffeUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xffffffUL ]
      []
      [ F1, 0x4b8000004f7f0000UL; VSRL1, 0x4b7fffffUL ]
      []

  /// <summary>
  /// xvcvuxwdp xT, xB converts each unsigned word in word 0 of each doubleword
  /// to a double, exactly.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVCVUXWDP converts words``() =
    (* xvcvuxwdp vs1,vs3, under QEMU: lanes/x-oracle/convs *)
    oracleMem
      ppc64le
      "f0201ba0"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1ffffffffUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0x7fffffff80000000UL ]
      []
      [ F1, 0x3ff0000000000000UL; VSRL1, 0x41dfffffffc00000UL ]
      []
    oracleMem
      ppc64le
      "f0201ba0"
      [ F1, 0xbad0bad0bad0badUL
        F3, 0x1000001fefffffeUL
        VSRL1, 0xbad0bad0bad0badUL
        VSRL3, 0xffffffUL ]
      []
      [ F1, 0x4170000010000000UL; VSRL1, 0x0UL ]
      []

  /// <summary>
  /// xsaddqp vRT, vRA, vRB adds the quads in vRA and vRB, rounded in the
  /// direction FPSCR[RN] names: an inexact sum in every direction, an overflow
  /// to infinity or to the largest quad, opposite infinities and a NaN in
  /// either operand, exact zeroes and their signs.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSADDQP adds two quads``() =
    (* xsaddqp v1,v2,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc221808"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL
        V3A, 0x4000800000000000UL ]
      []
      [ V1A, 0x4001000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc221808"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL
        V3B, 0x1UL ]
      []
      [ V1A, 0x3fff000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc221808"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL
        V3B, 0x1UL
        FPSCR, 0x1UL ]
      []
      [ V1A, 0x3fff000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc221808"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL
        V3B, 0x1UL
        FPSCR, 0x2UL ]
      []
      [ V1A, 0x3fff000000000000UL; V1B, 0x1UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc221808"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL
        V3B, 0x1UL
        FPSCR, 0x3UL ]
      []
      [ V1A, 0x3fff000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc221808"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x7ffeffffffffffffUL
        V2B, 0xffffffffffffffffUL
        V3A, 0x7ffeffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ V1A, 0x7fff000000000000UL; V1B, 0x0UL; FPSCR, 0x5UL ]
      []
    oracleMem
      ppc64le
      "fc221808"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x7ffeffffffffffffUL
        V2B, 0xffffffffffffffffUL
        V3A, 0x7ffeffffffffffffUL
        V3B, 0xffffffffffffffffUL
        FPSCR, 0x1UL ]
      []
      [ V1A, 0x7ffeffffffffffffUL; V1B, 0xffffffffffffffffUL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc221808"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x7ffeffffffffffffUL
        V2B, 0xffffffffffffffffUL
        V3A, 0x7ffeffffffffffffUL
        V3B, 0xffffffffffffffffUL
        FPSCR, 0x3UL ]
      []
      [ V1A, 0x7ffeffffffffffffUL; V1B, 0xffffffffffffffffUL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc221808"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x7fff000000000000UL
        V3A, 0xffff000000000000UL ]
      []
      [ V1A, 0x7fff800000000000UL; V1B, 0x0UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64le
      "fc221808"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x7fff800000000000UL
        V2B, 0x1234UL
        V3A, 0x7fff400000000000UL
        V3B, 0x5678UL ]
      []
      [ V1A, 0x7fff800000000000UL; V1B, 0x1234UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64le
      "fc221808"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL
        V3A, 0x7fff400000000000UL
        V3B, 0x5678UL ]
      []
      [ V1A, 0x7fffc00000000000UL; V1B, 0x5678UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64le
      "fc221808"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x8000000000000000UL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "fc221808"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x8000000000000000UL
        FPSCR, 0x3UL ]
      []
      [ V1A, 0x8000000000000000UL; V1B, 0x0UL; FPSCR, 0x12UL ]
      []
    oracleMem
      ppc64le
      "fc221808"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL
        V3A, 0xbfff000000000000UL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "fc221808"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL
        V3A, 0xbfff000000000000UL
        FPSCR, 0x3UL ]
      []
      [ V1A, 0x8000000000000000UL; V1B, 0x0UL; FPSCR, 0x12UL ]
      []
    oracleMem
      ppc64le
      "fc221808"
      [ V1A, 0xbad0bad0bad0badUL; V1B, 0xbad0bad0bad0badUL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "fc221808"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL ]
      []
      [ V1A, 0x3fff000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc221808"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2B, 0x1UL
        V3A, 0x3ffe000000000000UL ]
      []
      [ V1A, 0x3ffe000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc221808"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0xbffd555555555555UL
        V2B, 0x5555555555555555UL
        V3A, 0xffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ V1A, 0xbffd555555555555UL; V1B, 0x5555555555555555UL; FPSCR, 0x8UL ]
      []

  /// <summary>
  /// xssubqp vRT, vRA, vRB subtracts vRB from vRA, rounded in the direction
  /// FPSCR[RN] names; a signalling NaN in vRB comes back quiet.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSSUBQP subtracts two quads``() =
    (* xssubqp v1,v2,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc221c08"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL
        V3A, 0x4000800000000000UL ]
      []
      [ V1A, 0xc000000000000000UL; V1B, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "fc221c08"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL
        V3B, 0x1UL ]
      []
      [ V1A, 0x3fff000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc221c08"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL
        V3B, 0x1UL
        FPSCR, 0x3UL ]
      []
      [ V1A, 0x3ffeffffffffffffUL; V1B, 0xffffffffffffffffUL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc221c08"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL
        V3A, 0x7fff400000000000UL
        V3B, 0x5678UL ]
      []
      [ V1A, 0x7fffc00000000000UL; V1B, 0x5678UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64le
      "fc221c08"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x8000000000000000UL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "fc221c08"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL
        V3A, 0xbfff000000000000UL ]
      []
      [ V1A, 0x4000000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []

  /// <summary>
  /// xsmulqp vRT, vRA, vRB multiplies the quads in vRA and vRB, rounded in the
  /// direction FPSCR[RN] names: an overflow, a NaN, zero times a number, a
  /// product that rounds into the denormals.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSMULQP multiplies two quads``() =
    (* xsmulqp v1,v2,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc221848"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL
        V3A, 0x4000800000000000UL ]
      []
      [ V1A, 0x4000800000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc221848"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x7ffeffffffffffffUL
        V2B, 0xffffffffffffffffUL
        V3A, 0x7ffeffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ V1A, 0x7fff000000000000UL; V1B, 0x0UL; FPSCR, 0x5UL ]
      []
    oracleMem
      ppc64le
      "fc221848"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x7ffeffffffffffffUL
        V2B, 0xffffffffffffffffUL
        V3A, 0x7ffeffffffffffffUL
        V3B, 0xffffffffffffffffUL
        FPSCR, 0x1UL ]
      []
      [ V1A, 0x7ffeffffffffffffUL; V1B, 0xffffffffffffffffUL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc221848"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x7fff000000000000UL
        V3A, 0xffff000000000000UL ]
      []
      [ V1A, 0xffff000000000000UL; V1B, 0x0UL; FPSCR, 0x9UL ]
      []
    oracleMem
      ppc64le
      "fc221848"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x7fff800000000000UL
        V2B, 0x1234UL
        V3A, 0x7fff400000000000UL
        V3B, 0x5678UL ]
      []
      [ V1A, 0x7fff800000000000UL; V1B, 0x1234UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64le
      "fc221848"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "fc221848"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2B, 0x1UL
        V3A, 0x3ffe000000000000UL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "fc221848"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2B, 0x1UL
        V3A, 0x3ffe000000000000UL
        FPSCR, 0x2UL ]
      []
      [ V1A, 0x0UL; V1B, 0x1UL; FPSCR, 0x14UL ]
      []
    oracleMem
      ppc64le
      "fc221848"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0xbffd555555555555UL
        V2B, 0x5555555555555555UL
        V3A, 0xffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ V1A, 0x8000555555555555UL; V1B, 0x5555555555555555UL; FPSCR, 0x18UL ]
      []
    oracleMem
      ppc64le
      "fc221848"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0xbffd555555555555UL
        V2B, 0x5555555555555555UL
        V3A, 0xffffffffffffUL
        V3B, 0xffffffffffffffffUL
        FPSCR, 0x1UL ]
      []
      [ V1A, 0x8000555555555555UL; V1B, 0x5555555555555554UL; FPSCR, 0x18UL ]
      []

  /// <summary>
  /// xsdivqp vRT, vRA, vRB divides vRA by vRB, rounded in the direction
  /// FPSCR[RN] names: one third in every direction, infinity by infinity, zero
  /// by zero, a number by zero, a quotient past the largest quad.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSDIVQP divides two quads``() =
    (* xsdivqp v1,v2,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc221c48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL
        V3A, 0x4000800000000000UL ]
      []
      [ V1A, 0x3ffd555555555555UL; V1B, 0x5555555555555555UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc221c48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL
        V3A, 0x4000800000000000UL
        FPSCR, 0x1UL ]
      []
      [ V1A, 0x3ffd555555555555UL; V1B, 0x5555555555555555UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc221c48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL
        V3A, 0x4000800000000000UL
        FPSCR, 0x2UL ]
      []
      [ V1A, 0x3ffd555555555555UL; V1B, 0x5555555555555556UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc221c48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL
        V3A, 0x4000800000000000UL
        FPSCR, 0x3UL ]
      []
      [ V1A, 0x3ffd555555555555UL; V1B, 0x5555555555555555UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc221c48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x7fff000000000000UL
        V3A, 0xffff000000000000UL ]
      []
      [ V1A, 0x7fff800000000000UL; V1B, 0x0UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64le
      "fc221c48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x7fff800000000000UL
        V2B, 0x1234UL
        V3A, 0x7fff400000000000UL
        V3B, 0x5678UL ]
      []
      [ V1A, 0x7fff800000000000UL; V1B, 0x1234UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64le
      "fc221c48"
      [ V1A, 0xbad0bad0bad0badUL; V1B, 0xbad0bad0bad0badUL ]
      []
      [ V1A, 0x7fff800000000000UL; V1B, 0x0UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64le
      "fc221c48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL ]
      []
      [ V1A, 0x7fff000000000000UL; V1B, 0x0UL; FPSCR, 0x5UL ]
      []
    oracleMem
      ppc64le
      "fc221c48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0xbffd555555555555UL
        V2B, 0x5555555555555555UL
        V3A, 0xffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ V1A, 0xfffb555555555555UL; V1B, 0x5555555555555556UL; FPSCR, 0x8UL ]
      []

  /// <summary>
  /// xsaddqpo, xssubqpo, xsmulqpo and xsdivqpo round to odd whatever FPSCR[RN]
  /// says: an inexact result keeps its truncated significand with the last bit
  /// set, and an overflow gives the largest quad.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSADDQPO and its kin round to odd``() =
    (* xsaddqpo v1,v2,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc221809"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL
        V3B, 0x1UL ]
      []
      [ V1A, 0x3fff000000000000UL; V1B, 0x1UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc221809"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x7ffeffffffffffffUL
        V2B, 0xffffffffffffffffUL
        V3A, 0x7ffeffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ V1A, 0x7ffeffffffffffffUL; V1B, 0xffffffffffffffffUL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc221809"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x8000000000000000UL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL; FPSCR, 0x2UL ]
      []

  /// <summary>
  /// xsaddqpo, xssubqpo, xsmulqpo and xsdivqpo round to odd whatever FPSCR[RN]
  /// says: an inexact result keeps its truncated significand with the last bit
  /// set, and an overflow gives the largest quad.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSSUBQPO beside XSADDQPO``() =
    (* xssubqpo v1,v2,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc221c09"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL
        V3B, 0x1UL ]
      []
      [ V1A, 0x3ffeffffffffffffUL; V1B, 0xffffffffffffffffUL; FPSCR, 0x4UL ]
      []

  /// <summary>
  /// xsaddqpo, xssubqpo, xsmulqpo and xsdivqpo round to odd whatever FPSCR[RN]
  /// says: an inexact result keeps its truncated significand with the last bit
  /// set, and an overflow gives the largest quad.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSMULQPO beside XSADDQPO``() =
    (* xsmulqpo v1,v2,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc221849"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL
        V3A, 0x4000800000000000UL ]
      []
      [ V1A, 0x4000800000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc221849"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2B, 0x1UL
        V3A, 0x3ffe000000000000UL ]
      []
      [ V1A, 0x0UL; V1B, 0x1UL; FPSCR, 0x14UL ]
      []

  /// <summary>
  /// xsaddqpo, xssubqpo, xsmulqpo and xsdivqpo round to odd whatever FPSCR[RN]
  /// says: an inexact result keeps its truncated significand with the last bit
  /// set, and an overflow gives the largest quad.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSDIVQPO beside XSADDQPO``() =
    (* xsdivqpo v1,v2,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc221c49"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL
        V3A, 0x4000800000000000UL ]
      []
      [ V1A, 0x3ffd555555555555UL; V1B, 0x5555555555555555UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc221c49"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0xbffd555555555555UL
        V2B, 0x5555555555555555UL
        V3A, 0xffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ V1A, 0xfffb555555555555UL; V1B, 0x5555555555555557UL; FPSCR, 0x8UL ]
      []

  /// <summary>
  /// xssqrtqp vRT, vRB takes the square root of vRB, rounded in the direction
  /// FPSCR[RN] names (xssqrtqpo to odd): an inexact root up and to nearest, an
  /// exact one, a negative number, -0, +Inf, a signalling NaN, the smallest
  /// denormal and the largest quad.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSSQRTQP takes the square root of a quad``() =
    (* xssqrtqp v1,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc3b1e48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x4000000000000000UL ]
      []
      [ V1A, 0x3fff6a09e667f3bcUL; V1B, 0xc908b2fb1366ea95UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc3b1e48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x4000000000000000UL
        FPSCR, 0x2UL ]
      []
      [ V1A, 0x3fff6a09e667f3bcUL; V1B, 0xc908b2fb1366ea96UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc3b1e48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x4001000000000000UL ]
      []
      [ V1A, 0x4000000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc3b1e48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0xbfff000000000000UL ]
      []
      [ V1A, 0x7fff800000000000UL; V1B, 0x0UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64le
      "fc3b1e48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x8000000000000000UL ]
      []
      [ V1A, 0x8000000000000000UL; V1B, 0x0UL; FPSCR, 0x12UL ]
      []
    oracleMem
      ppc64le
      "fc3b1e48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x7fff000000000000UL ]
      []
      [ V1A, 0x7fff000000000000UL; V1B, 0x0UL; FPSCR, 0x5UL ]
      []
    oracleMem
      ppc64le
      "fc3b1e48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x7fff400000000000UL
        V3B, 0x5678UL ]
      []
      [ V1A, 0x7fffc00000000000UL; V1B, 0x5678UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64le
      "fc3b1e48"
      [ V1A, 0xbad0bad0bad0badUL; V1B, 0xbad0bad0bad0badUL; V3B, 0x1UL ]
      []
      [ V1A, 0x1fc8000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc3b1e48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x7ffeffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ V1A, 0x5ffeffffffffffffUL; V1B, 0xffffffffffffffffUL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc3b1e48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x3ffd555555555555UL
        V3B, 0x5555555555555555UL ]
      []
      [ V1A, 0x3ffe279a74590331UL; V1B, 0xc4d218f81e4afb25UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc3b1e48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x3ffd555555555555UL
        V3B, 0x5555555555555555UL
        FPSCR, 0x2UL ]
      []
      [ V1A, 0x3ffe279a74590331UL; V1B, 0xc4d218f81e4afb26UL; FPSCR, 0x4UL ]
      []

  /// <summary>
  /// xssqrtqp vRT, vRB takes the square root of vRB, rounded in the direction
  /// FPSCR[RN] names (xssqrtqpo to odd): an inexact root up and to nearest, an
  /// exact one, a negative number, -0, +Inf, a signalling NaN, the smallest
  /// denormal and the largest quad.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSSQRTQPO beside XSSQRTQP``() =
    (* xssqrtqpo v1,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc3b1e49"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x4000000000000000UL ]
      []
      [ V1A, 0x3fff6a09e667f3bcUL; V1B, 0xc908b2fb1366ea95UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc3b1e49"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x3ffd555555555555UL
        V3B, 0x5555555555555555UL ]
      []
      [ V1A, 0x3ffe279a74590331UL; V1B, 0xc4d218f81e4afb25UL; FPSCR, 0x4UL ]
      []

  /// <summary>
  /// xsmaddqp vRT, vRA, vRB rounds vRA times vRB plus vRT once: a sum the
  /// product's lost bits decide, an exact zero, infinity times zero, NaNs in
  /// POWER's order (vRA, vRT, vRB), infinities of opposite signs, an overflow.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSMADDQP fuses a multiply and an add``() =
    (* xsmaddqp v1,v2,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc221b08"
      [ V1A, 0xbfff000000000000UL
        V2A, 0x3fff000000000000UL
        V2B, 0x1UL
        V3A, 0x3fff000000000000UL
        V3B, 0x1UL ]
      []
      [ V1A, 0x3f90000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc221b08"
      [ V1A, 0xbfff000000000000UL
        V2A, 0x3fff000000000000UL
        V2B, 0x1UL
        V3A, 0x3fff000000000000UL
        V3B, 0x1UL
        FPSCR, 0x2UL ]
      []
      [ V1A, 0x3f90000000000000UL; V1B, 0x1UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc221b08"
      [ V1A, 0xbfff000000000000UL
        V2A, 0x3fff000000000000UL
        V3A, 0x3fff000000000000UL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "fc221b08"
      [ V1A, 0x3fff000000000000UL; V2A, 0x7fff000000000000UL ]
      []
      [ V1A, 0x7fff800000000000UL; V1B, 0x0UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64le
      "fc221b08"
      [ V1A, 0x7fff400000000000UL
        V1B, 0x5678UL
        V2A, 0x7fff800000000000UL
        V2B, 0x1234UL
        V3A, 0x3fff000000000000UL ]
      []
      [ V1A, 0x7fff800000000000UL; V1B, 0x1234UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64le
      "fc221b08"
      [ V1A, 0x7fff800000000000UL
        V1B, 0x1234UL
        V2A, 0x3fff000000000000UL
        V3A, 0x7fff400000000000UL
        V3B, 0x5678UL ]
      []
      [ V1A, 0x7fff800000000000UL; V1B, 0x1234UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64le
      "fc221b08"
      [ V1A, 0x7fff400000000000UL
        V1B, 0x5678UL
        V2A, 0x3fff000000000000UL
        V3A, 0x3fff000000000000UL ]
      []
      [ V1A, 0x7fffc00000000000UL; V1B, 0x5678UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64le
      "fc221b08"
      [ V1A, 0xffff000000000000UL
        V2A, 0x7fff000000000000UL
        V3A, 0x3fff000000000000UL ]
      []
      [ V1A, 0x7fff800000000000UL; V1B, 0x0UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64le
      "fc221b08"
      [ V1A, 0xbfff000000000000UL
        V2A, 0x3ffd555555555555UL
        V2B, 0x5555555555555555UL
        V3A, 0x4000800000000000UL ]
      []
      [ V1A, 0xbf8d000000000000UL; V1B, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "fc221b08"
      [ V1A, 0xffff000000000000UL
        V2A, 0x7ffeffffffffffffUL
        V2B, 0xffffffffffffffffUL
        V3A, 0x4000000000000000UL ]
      []
      [ V1A, 0xffff000000000000UL; V1B, 0x0UL; FPSCR, 0x9UL ]
      []

  /// <summary>
  /// xsmaddqp vRT, vRA, vRB rounds vRA times vRB plus vRT once: a sum the
  /// product's lost bits decide, an exact zero, infinity times zero, NaNs in
  /// POWER's order (vRA, vRT, vRB), infinities of opposite signs, an overflow.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSMADDQPO beside XSMADDQP``() =
    (* xsmaddqpo v1,v2,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc221b09"
      [ V1A, 0xbfff000000000000UL
        V2A, 0x3fff000000000000UL
        V2B, 0x1UL
        V3A, 0x3fff000000000000UL
        V3B, 0x1UL ]
      []
      [ V1A, 0x3f90000000000000UL; V1B, 0x1UL; FPSCR, 0x4UL ]
      []

  /// <summary>
  /// xsmsubqp subtracts vRT from the product; xsnmaddqp and xsnmsubqp negate
  /// the result after it is rounded, so an exact zero takes the sign the
  /// direction gives and then flips; their "o" forms round to odd.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSNMADDQP negates the rounded result``() =
    (* xsmsubqp v1,v2,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc221b48"
      [ V1A, 0xbfff000000000000UL
        V2A, 0x3fff000000000000UL
        V2B, 0x1UL
        V3A, 0x3fff000000000000UL
        V3B, 0x1UL ]
      []
      [ V1A, 0x4000000000000000UL; V1B, 0x1UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc221b48"
      [ V1A, 0xbfff000000000000UL
        V2A, 0x3fff000000000000UL
        V3A, 0x3fff000000000000UL ]
      []
      [ V1A, 0x4000000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []

  /// <summary>
  /// xsmsubqp subtracts vRT from the product; xsnmaddqp and xsnmsubqp negate
  /// the result after it is rounded, so an exact zero takes the sign the
  /// direction gives and then flips; their "o" forms round to odd.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSNMADDQP beside XSMSUBQP``() =
    (* xsnmaddqp v1,v2,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc221b88"
      [ V1A, 0xbfff000000000000UL
        V2A, 0x3fff000000000000UL
        V2B, 0x1UL
        V3A, 0x3fff000000000000UL
        V3B, 0x1UL ]
      []
      [ V1A, 0xbf90000000000000UL; V1B, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "fc221b88"
      [ V1A, 0xbfff000000000000UL
        V2A, 0x3fff000000000000UL
        V3A, 0x3fff000000000000UL ]
      []
      [ V1A, 0x8000000000000000UL; V1B, 0x0UL; FPSCR, 0x12UL ]
      []
    oracleMem
      ppc64le
      "fc221b88"
      [ V1A, 0xbfff000000000000UL
        V2A, 0x3fff000000000000UL
        V3A, 0x3fff000000000000UL
        FPSCR, 0x2UL ]
      []
      [ V1A, 0x8000000000000000UL; V1B, 0x0UL; FPSCR, 0x12UL ]
      []
    oracleMem
      ppc64le
      "fc221b88"
      [ V1A, 0xbfff000000000000UL
        V2A, 0x3fff000000000000UL
        V2B, 0x1UL
        V3A, 0x3fff000000000000UL
        V3B, 0x1UL
        FPSCR, 0x2UL ]
      []
      [ V1A, 0xbf90000000000000UL; FPSCR, 0x8UL; V1B, 0x1UL ]
      []

  /// <summary>
  /// xsmsubqp subtracts vRT from the product; xsnmaddqp and xsnmsubqp negate
  /// the result after it is rounded, so an exact zero takes the sign the
  /// direction gives and then flips; their "o" forms round to odd.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSNMSUBQP beside XSMSUBQP``() =
    (* xsnmsubqp v1,v2,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc221bc8"
      [ V1A, 0xbfff000000000000UL
        V2A, 0x3fff000000000000UL
        V2B, 0x1UL
        V3A, 0x3fff000000000000UL
        V3B, 0x1UL ]
      []
      [ V1A, 0xc000000000000000UL; V1B, 0x1UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "fc221bc8"
      [ V1A, 0xbfff000000000000UL
        V2A, 0x3fff000000000000UL
        V2B, 0x1UL
        V3A, 0x3fff000000000000UL
        V3B, 0x1UL
        FPSCR, 0x2UL ]
      []
      [ V1A, 0xc000000000000000UL; FPSCR, 0x8UL; V1B, 0x2UL ]
      []

  /// <summary>
  /// xsmsubqp subtracts vRT from the product; xsnmaddqp and xsnmsubqp negate
  /// the result after it is rounded, so an exact zero takes the sign the
  /// direction gives and then flips; their "o" forms round to odd.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSMSUBQPO beside XSMSUBQP``() =
    (* xsmsubqpo v1,v2,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc221b49"
      [ V1A, 0xbfff000000000000UL
        V2A, 0x3fff000000000000UL
        V2B, 0x1UL
        V3A, 0x3fff000000000000UL
        V3B, 0x1UL ]
      []
      [ V1A, 0x4000000000000000UL; V1B, 0x1UL; FPSCR, 0x4UL ]
      []

  /// <summary>
  /// xsmsubqp subtracts vRT from the product; xsnmaddqp and xsnmsubqp negate
  /// the result after it is rounded, so an exact zero takes the sign the
  /// direction gives and then flips; their "o" forms round to odd.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSNMADDQPO beside XSMSUBQP``() =
    (* xsnmaddqpo v1,v2,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc221b89"
      [ V1A, 0xbfff000000000000UL
        V2A, 0x3fff000000000000UL
        V2B, 0x1UL
        V3A, 0x3fff000000000000UL
        V3B, 0x1UL ]
      []
      [ V1A, 0xbf90000000000000UL; V1B, 0x1UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "fc221b89"
      [ V1A, 0xbfff000000000000UL
        V2A, 0x3fff000000000000UL
        V3A, 0x3fff000000000000UL ]
      []
      [ V1A, 0x8000000000000000UL; V1B, 0x0UL; FPSCR, 0x12UL ]
      []

  /// <summary>
  /// xsmsubqp subtracts vRT from the product; xsnmaddqp and xsnmsubqp negate
  /// the result after it is rounded, so an exact zero takes the sign the
  /// direction gives and then flips; their "o" forms round to odd.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSNMSUBQPO beside XSMSUBQP``() =
    (* xsnmsubqpo v1,v2,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc221bc9"
      [ V1A, 0xbfff000000000000UL
        V2A, 0x3fff000000000000UL
        V2B, 0x1UL
        V3A, 0x3fff000000000000UL
        V3B, 0x1UL ]
      []
      [ V1A, 0xc000000000000000UL; V1B, 0x1UL; FPSCR, 0x8UL ]
      []

  /// <summary>
  /// xscmpuqp BF, vRA, vRB and xscmpoqp set CR field BF and FPCC to less-than,
  /// greater-than, equal or unordered: +0 equals -0, a NaN is unordered, a
  /// denormal is above -Inf.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSCMPUQP orders two quads into CR and FPCC``() =
    (* xscmpuqp cr2,v2,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fd021d08"
      [ V2A, 0x3fff000000000000UL; V3A, 0x4000000000000000UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "fd021d08"
      [ V2A, 0x4000000000000000UL
        V3A, 0x3fff000000000000UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x1UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fd021d08"
      [ V2A, 0x3fff000000000000UL
        V3A, 0x3fff000000000000UL
        CR2_0, 0x1UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "fd021d08"
      [ V3A, 0x8000000000000000UL; CR2_1, 0x1UL; CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "fd021d08"
      [ V2A, 0xbfff000000000000UL; V3A, 0x3fff000000000000UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "fd021d08"
      [ V2A, 0x7fff800000000000UL; V2B, 0x1234UL; V3A, 0x3fff000000000000UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x1UL; FPSCR, 0x1UL ]
      []
    oracleMem
      ppc64le
      "fd021d08"
      [ V2A, 0x3fff000000000000UL; V3A, 0x7fff400000000000UL; V3B, 0x5678UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x1UL; FPSCR, 0x1UL ]
      []
    oracleMem
      ppc64le
      "fd021d08"
      [ V2A, 0xffff000000000000UL; V3B, 0x1UL; CR2_1, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "fd021d08"
      [ V2A, 0xc000000000000000UL; V3A, 0xbfff000000000000UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "fd021d08"
      [ V2A, 0x7fff000000000000UL
        V3A, 0x7ffeffffffffffffUL
        V3B, 0xffffffffffffffffUL
        CR2_1, 0x1UL
        CR2_2, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x1UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x4UL ]
      []

  /// <summary>
  /// xscmpuqp BF, vRA, vRB and xscmpoqp set CR field BF and FPCC to less-than,
  /// greater-than, equal or unordered: +0 equals -0, a NaN is unordered, a
  /// denormal is above -Inf.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSCMPOQP beside XSCMPUQP``() =
    (* xscmpoqp cr2,v2,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fd021908"
      [ V2A, 0x7fff800000000000UL; V2B, 0x1234UL; V3A, 0x3fff000000000000UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x1UL; FPSCR, 0x1UL ]
      []
    oracleMem
      ppc64le
      "fd021908"
      [ V2A, 0x3fff000000000000UL; V3A, 0x7fff400000000000UL; V3B, 0x5678UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x1UL; FPSCR, 0x1UL ]
      []

  /// <summary>
  /// xscmpeqqp, xscmpgtqp and xscmpgeqp set vRT to all ones where vRA is equal
  /// to, greater than or not less than vRB, to all zeroes otherwise and where
  /// either is a NaN.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSCMPEQQP and its kin give a mask``() =
    (* xscmpeqqp v1,v2,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc221888"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL
        V3A, 0x3fff000000000000UL ]
      []
      [ V1A, 0xffffffffffffffffUL; V1B, 0xffffffffffffffffUL ]
      []
    oracleMem
      ppc64le
      "fc221888"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x8000000000000000UL ]
      []
      [ V1A, 0xffffffffffffffffUL; V1B, 0xffffffffffffffffUL ]
      []
    oracleMem
      ppc64le
      "fc221888"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x7fff800000000000UL
        V2B, 0x1234UL
        V3A, 0x3fff000000000000UL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL ]
      []

  /// <summary>
  /// xscmpeqqp, xscmpgtqp and xscmpgeqp set vRT to all ones where vRA is equal
  /// to, greater than or not less than vRB, to all zeroes otherwise and where
  /// either is a NaN.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSCMPGTQP beside XSCMPEQQP``() =
    (* xscmpgtqp v1,v2,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc2219c8"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL
        V3A, 0x4000000000000000UL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc2219c8"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x4000000000000000UL
        V3A, 0x3fff000000000000UL ]
      []
      [ V1A, 0xffffffffffffffffUL; V1B, 0xffffffffffffffffUL ]
      []
    oracleMem
      ppc64le
      "fc2219c8"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x8000000000000000UL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc2219c8"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x7fff800000000000UL
        V2B, 0x1234UL
        V3A, 0x3fff000000000000UL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc2219c8"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0xc000000000000000UL
        V3A, 0xbfff000000000000UL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL ]
      []

  /// <summary>
  /// xscmpeqqp, xscmpgtqp and xscmpgeqp set vRT to all ones where vRA is equal
  /// to, greater than or not less than vRB, to all zeroes otherwise and where
  /// either is a NaN.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSCMPGEQP beside XSCMPEQQP``() =
    (* xscmpgeqp v1,v2,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc221988"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL
        V3A, 0x4000000000000000UL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc221988"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL
        V3A, 0x3fff000000000000UL ]
      []
      [ V1A, 0xffffffffffffffffUL; V1B, 0xffffffffffffffffUL ]
      []
    oracleMem
      ppc64le
      "fc221988"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x8000000000000000UL ]
      []
      [ V1A, 0xffffffffffffffffUL; V1B, 0xffffffffffffffffUL ]
      []
    oracleMem
      ppc64le
      "fc221988"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x7fff800000000000UL
        V2B, 0x1234UL
        V3A, 0x3fff000000000000UL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL ]
      []

  /// <summary>
  /// xscmpexpqp BF, vRA, vRB compares the exponent fields of vRA and vRB as
  /// unsigned numbers into CR field BF and FPCC, unordered where either is a
  /// NaN.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSCMPEXPQP compares exponent fields``() =
    (* xscmpexpqp cr2,v2,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fd021948"
      [ V2A, 0x3fff000000000000UL; V3A, 0x4000000000000000UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "fd021948"
      [ V2A, 0x4000000000000000UL
        V3A, 0x3fff000000000000UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x1UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fd021948"
      [ V2A, 0x3fff000000000000UL
        V3A, 0x3fff000000000000UL
        CR2_0, 0x1UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "fd021948"
      [ V2A, 0x7fff800000000000UL; V2B, 0x1234UL; V3A, 0x3fff000000000000UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x1UL; FPSCR, 0x1UL ]
      []
    oracleMem
      ppc64le
      "fd021948"
      [ V2A, 0xffff000000000000UL; V3B, 0x1UL; CR2_1, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x1UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x4UL ]
      []

  /// <summary>
  /// xsmaxcqp vRT, vRA, vRB gives vRA where it is greater than vRB and vRB
  /// otherwise, so a NaN in either and a tie of +0 and -0 give vRB; xsmincqp
  /// gives the lesser in the same way.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSMAXCQP picks the C-style maximum``() =
    (* xsmaxcqp v1,v2,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc221d48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL
        V3A, 0x4000000000000000UL ]
      []
      [ V1A, 0x4000000000000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc221d48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x4000000000000000UL
        V3A, 0x3fff000000000000UL ]
      []
      [ V1A, 0x4000000000000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc221d48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x7fff800000000000UL
        V2B, 0x1234UL
        V3A, 0x3fff000000000000UL ]
      []
      [ V1A, 0x3fff000000000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc221d48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL
        V3A, 0x7fff400000000000UL
        V3B, 0x5678UL ]
      []
      [ V1A, 0x7fff400000000000UL; V1B, 0x5678UL ]
      []
    oracleMem
      ppc64le
      "fc221d48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0xc000000000000000UL
        V3A, 0xbfff000000000000UL ]
      []
      [ V1A, 0xbfff000000000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc221d48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x8000000000000000UL ]
      []
      [ V1B, 0x0UL; V1A, 0x8000000000000000UL ]
      []

  /// <summary>
  /// xsmaxcqp vRT, vRA, vRB gives vRA where it is greater than vRB and vRB
  /// otherwise, so a NaN in either and a tie of +0 and -0 give vRB; xsmincqp
  /// gives the lesser in the same way.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSMINCQP beside XSMAXCQP``() =
    (* xsmincqp v1,v2,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc221dc8"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL
        V3A, 0x4000000000000000UL ]
      []
      [ V1A, 0x3fff000000000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc221dc8"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x8000000000000000UL ]
      []
      [ V1A, 0x8000000000000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc221dc8"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x7fff800000000000UL
        V2B, 0x1234UL
        V3A, 0x3fff000000000000UL ]
      []
      [ V1A, 0x3fff000000000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc221dc8"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL
        V3A, 0x7fff400000000000UL
        V3B, 0x5678UL ]
      []
      [ V1A, 0x7fff400000000000UL; V1B, 0x5678UL ]
      []

  /// <summary>
  /// xscpsgnqp takes vRA's sign onto vRB; xsabsqp clears the sign, xsnabsqp
  /// sets it and xsnegqp flips it, a NaN included and left signalling.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSCPSGNQP and the sign forms touch only the sign``() =
    (* xscpsgnqp v1,v2,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc2218c8"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0xbfff000000000000UL
        V3A, 0x3fff000000000000UL ]
      []
      [ V1A, 0xbfff000000000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc2218c8"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x7fff800000000000UL
        V2B, 0x1234UL
        V3A, 0x3fff000000000000UL ]
      []
      [ V1A, 0x3fff000000000000UL; V1B, 0x0UL ]
      []

  /// <summary>
  /// xscpsgnqp takes vRA's sign onto vRB; xsabsqp clears the sign, xsnabsqp
  /// sets it and xsnegqp flips it, a NaN included and left signalling.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSABSQP beside XSCPSGNQP``() =
    (* xsabsqp v1,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc201e48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x3fff000000000000UL ]
      []
      [ V1A, 0x3fff000000000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc201e48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0xffff000000000000UL
        V3B, 0x1UL ]
      []
      [ V1A, 0x7fff000000000000UL; V1B, 0x1UL ]
      []

  /// <summary>
  /// xscpsgnqp takes vRA's sign onto vRB; xsabsqp clears the sign, xsnabsqp
  /// sets it and xsnegqp flips it, a NaN included and left signalling.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSNABSQP beside XSCPSGNQP``() =
    (* xsnabsqp v1,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc281e48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x3fff000000000000UL ]
      []
      [ V1A, 0xbfff000000000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc281e48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x7fff800000000000UL
        V3B, 0x1234UL ]
      []
      [ V1A, 0xffff800000000000UL; V1B, 0x1234UL ]
      []

  /// <summary>
  /// xscpsgnqp takes vRA's sign onto vRB; xsabsqp clears the sign, xsnabsqp
  /// sets it and xsnegqp flips it, a NaN included and left signalling.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSNEGQP beside XSCPSGNQP``() =
    (* xsnegqp v1,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc301e48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x3fff000000000000UL ]
      []
      [ V1A, 0xbfff000000000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc301e48"
      [ V1A, 0xbad0bad0bad0badUL; V1B, 0xbad0bad0bad0badUL ]
      []
      [ V1A, 0x8000000000000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc301e48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0xffff000000000000UL
        V3B, 0x1UL ]
      []
      [ V1A, 0x7fff000000000000UL; V1B, 0x1UL ]
      []

  /// <summary>
  /// xsxexpqp puts vRB's exponent field in doubleword 0; xsxsigqp gives the
  /// fraction with the implicit bit where vRB is normal; xsiexpqp puts the low
  /// 15 bits of vRB's doubleword 0 into vRA as its exponent field.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSXEXPQP and XSXSIGQP take a quad apart``() =
    (* xsxexpqp v1,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc221e48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x3fff000000000000UL ]
      []
      [ V1A, 0x3fffUL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc221e48"
      [ V1A, 0xbad0bad0bad0badUL; V1B, 0xbad0bad0bad0badUL; V3B, 0x1UL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc221e48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x7fff000000000000UL ]
      []
      [ V1A, 0x7fffUL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc221e48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x7ffeffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ V1A, 0x7ffeUL; V1B, 0x0UL ]
      []

  /// <summary>
  /// xsxexpqp puts vRB's exponent field in doubleword 0; xsxsigqp gives the
  /// fraction with the implicit bit where vRB is normal; xsiexpqp puts the low
  /// 15 bits of vRB's doubleword 0 into vRA as its exponent field.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSXSIGQP beside XSXEXPQP``() =
    (* xsxsigqp v1,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc321e48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x3fff000000000000UL ]
      []
      [ V1A, 0x1000000000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc321e48"
      [ V1A, 0xbad0bad0bad0badUL; V1B, 0xbad0bad0bad0badUL; V3B, 0x1UL ]
      []
      [ V1A, 0x0UL; V1B, 0x1UL ]
      []
    oracleMem
      ppc64le
      "fc321e48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x7fff000000000000UL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc321e48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x7fff800000000000UL
        V3B, 0x1234UL ]
      []
      [ V1A, 0x800000000000UL; V1B, 0x1234UL ]
      []
    oracleMem
      ppc64le
      "fc321e48"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x7ffeffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ V1A, 0x1ffffffffffffUL; V1B, 0xffffffffffffffffUL ]
      []

  /// <summary>
  /// xsxexpqp puts vRB's exponent field in doubleword 0; xsxsigqp gives the
  /// fraction with the implicit bit where vRB is normal; xsiexpqp puts the low
  /// 15 bits of vRB's doubleword 0 into vRA as its exponent field.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSIEXPQP beside XSXEXPQP``() =
    (* xsiexpqp v1,v2,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc221ec8"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x3fff000000000000UL
        V3A, 0x4000UL ]
      []
      [ V1A, 0x4000000000000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc221ec8"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0x7fff800000000000UL
        V2B, 0x1234UL
        V3A, 0x1234UL ]
      []
      [ V1A, 0x1234800000000000UL; V1B, 0x1234UL ]
      []
    oracleMem
      ppc64le
      "fc221ec8"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2A, 0xbfff000000000000UL
        V3A, 0xffffffffffff0000UL ]
      []
      [ V1A, 0x8000000000000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc221ec8"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V2B, 0x1UL
        V3A, 0x7fffUL ]
      []
      [ V1A, 0x7fff000000000000UL; V1B, 0x1UL ]
      []

  /// <summary>
  /// xststdcqp BF, vRB, DCMX sets the sign of vRB and whether it is in a class
  /// DCMX selects into CR field BF and FPCC: each DCMX bit on its own against
  /// its class and a normal number, and every bit together over every class.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSTSTDCQP tests a quad's data class``() =
    (* xststdcqp cr2,v3,1, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fd401d88"
      [ V3A, 0x7fff800000000000UL; V3B, 0x1234UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "fd401d88"
      [ V3A, 0x3fff000000000000UL; CR2_1, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fd201d88"
      [ V3A, 0x7fff000000000000UL; CR2_1, 0x1UL; CR2_2, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "fd201d88"
      [ V3A, 0x3fff000000000000UL; CR2_1, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fd101d88"
      [ V3A, 0xffff000000000000UL
        CR2_0, 0x1UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0xaUL ]
      []
    oracleMem
      ppc64le
      "fd101d88"
      [ V3A, 0x3fff000000000000UL; CR2_1, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fd081d88"
      [ CR2_1, 0x1UL; CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "fd081d88"
      [ V3A, 0x3fff000000000000UL; CR2_1, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fd041d88"
      [ V3A, 0x8000000000000000UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0xaUL ]
      []
    oracleMem
      ppc64le
      "fd041d88"
      [ V3A, 0x3fff000000000000UL; CR2_1, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fd021d88"
      [ V3B, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "fd021d88"
      [ V3A, 0x3fff000000000000UL; CR2_1, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fd011d88"
      [ V3A, 0x8000000000000000UL; V3B, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0xaUL ]
      []
    oracleMem
      ppc64le
      "fd011d88"
      [ V3A, 0x3fff000000000000UL; CR2_1, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fd7f1d88"
      [ V3A, 0x7fff800000000000UL; V3B, 0x1234UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "fd7f1d88"
      [ V3A, 0x7fff000000000000UL; CR2_1, 0x1UL; CR2_2, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "fd7f1d88"
      [ V3A, 0xffff000000000000UL
        CR2_0, 0x1UL
        CR2_1, 0x1UL
        CR2_2, 0x1UL
        CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0xaUL ]
      []
    oracleMem
      ppc64le
      "fd7f1d88"
      [ CR2_1, 0x1UL; CR2_3, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "fd7f1d88"
      [ V3A, 0x8000000000000000UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0xaUL ]
      []
    oracleMem
      ppc64le
      "fd7f1d88"
      [ V3B, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "fd7f1d88"
      [ V3A, 0x8000000000000000UL; V3B, 0x1UL ]
      []
      [ CR2_0, 0x1UL; CR2_1, 0x0UL; CR2_2, 0x1UL; CR2_3, 0x0UL; FPSCR, 0xaUL ]
      []
    oracleMem
      ppc64le
      "fd7f1d88"
      [ V3A, 0x3fff000000000000UL; CR2_1, 0x1UL ]
      []
      [ CR2_0, 0x0UL; CR2_1, 0x0UL; CR2_2, 0x0UL; CR2_3, 0x0UL; FPSCR, 0x0UL ]
      []

  /// <summary>
  /// xscvdpqp vRT, vRB widens the double in doubleword 0 of vRB to a quad
  /// exactly: denormals normalized, a signalling NaN quieted, infinities and
  /// the largest double; FPRF is set.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSCVDPQP widens a double to a quad``() =
    (* xscvdpqp v1,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc361e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x3ff0000000000000UL ]
      []
      [ V1A, 0x3fff000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc361e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x8000000000000000UL ]
      []
      [ V1A, 0x8000000000000000UL; V1B, 0x0UL; FPSCR, 0x12UL ]
      []
    oracleMem
      ppc64le
      "fc361e88"
      [ V1A, 0xbad0bad0bad0badUL; V1B, 0xbad0bad0bad0badUL; V3A, 0x1UL ]
      []
      [ V1A, 0x3bcd000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc361e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0xfffffffffffffUL ]
      []
      [ V1A, 0x3c00ffffffffffffUL; V1B, 0xe000000000000000UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc361e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x7ff0000000000000UL ]
      []
      [ V1A, 0x7fff000000000000UL; V1B, 0x0UL; FPSCR, 0x5UL ]
      []
    oracleMem
      ppc64le
      "fc361e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x7ff4000000000001UL ]
      []
      [ V1A, 0x7fffc00000000000UL; V1B, 0x1000000000000000UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64le
      "fc361e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0xfff8000000000000UL ]
      []
      [ V1A, 0xffff800000000000UL; V1B, 0x0UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64le
      "fc361e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x7fefffffffffffffUL ]
      []
      [ V1A, 0x43feffffffffffffUL; V1B, 0xf000000000000000UL; FPSCR, 0x4UL ]
      []

  /// <summary>
  /// xscvsdqp and xscvudqp convert the signed or unsigned doubleword in
  /// doubleword 0 of vRB to a quad, exactly; zero gives +0.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSCVSDQP converts a doubleword exactly``() =
    (* xscvsdqp v1,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc2a1e88"
      [ V1A, 0xbad0bad0bad0badUL; V1B, 0xbad0bad0bad0badUL; V3A, 0x1UL ]
      []
      [ V1A, 0x3fff000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc2a1e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL ]
      []
      [ V1A, 0xbfff000000000000UL; V1B, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "fc2a1e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x7fffffffffffffffUL ]
      []
      [ V1A, 0x403dffffffffffffUL; V1B, 0xfffc000000000000UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc2a1e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x8000000000000000UL ]
      []
      [ V1A, 0xc03e000000000000UL; V1B, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "fc2a1e88"
      [ V1A, 0xbad0bad0bad0badUL; V1B, 0xbad0bad0bad0badUL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL; FPSCR, 0x2UL ]
      []

  /// <summary>
  /// xscvsdqp and xscvudqp convert the signed or unsigned doubleword in
  /// doubleword 0 of vRB to a quad, exactly; zero gives +0.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSCVUDQP beside XSCVSDQP``() =
    (* xscvudqp v1,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc221e88"
      [ V1A, 0xbad0bad0bad0badUL; V1B, 0xbad0bad0bad0badUL; V3A, 0x1UL ]
      []
      [ V1A, 0x3fff000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc221e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL ]
      []
      [ V1A, 0x403effffffffffffUL; V1B, 0xfffe000000000000UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc221e88"
      [ V1A, 0xbad0bad0bad0badUL; V1B, 0xbad0bad0bad0badUL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL; FPSCR, 0x2UL ]
      []

  /// <summary>
  /// xscvsqqp and xscvuqqp convert the signed or unsigned quadword in vRB to a
  /// quad, rounded in the direction FPSCR[RN] names where it needs more than
  /// 113 bits.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSCVSQQP rounds a quadword to a quad``() =
    (* xscvsqqp v1,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc2b1e88"
      [ V1A, 0xbad0bad0bad0badUL; V1B, 0xbad0bad0bad0badUL; V3B, 0x1UL ]
      []
      [ V1A, 0x3fff000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc2b1e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ V1A, 0xbfff000000000000UL; V1B, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "fc2b1e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x8000000000000000UL ]
      []
      [ V1A, 0xc07e000000000000UL; V1B, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "fc2b1e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x2000000000000UL
        V3B, 0x1UL ]
      []
      [ V1A, 0x4070000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc2b1e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x2000000000000UL
        V3B, 0x1UL
        FPSCR, 0x1UL ]
      []
      [ V1A, 0x4070000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc2b1e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x2000000000000UL
        V3B, 0x1UL
        FPSCR, 0x2UL ]
      []
      [ V1A, 0x4070000000000000UL; V1B, 0x1UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc2b1e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x2000000000000UL
        V3B, 0x1UL
        FPSCR, 0x3UL ]
      []
      [ V1A, 0x4070000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc2b1e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x7fffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ V1A, 0x407e000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc2b1e88"
      [ V1A, 0xbad0bad0bad0badUL; V1B, 0xbad0bad0bad0badUL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL; FPSCR, 0x2UL ]
      []

  /// <summary>
  /// xscvsqqp and xscvuqqp convert the signed or unsigned quadword in vRB to a
  /// quad, rounded in the direction FPSCR[RN] names where it needs more than
  /// 113 bits.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSCVUQQP beside XSCVSQQP``() =
    (* xscvuqqp v1,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc231e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0xffffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ V1A, 0x407f000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc231e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x8000000000000000UL ]
      []
      [ V1A, 0x407e000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc231e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x2000000000000UL
        V3B, 0x1UL ]
      []
      [ V1A, 0x4070000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc231e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x2000000000000UL
        V3B, 0x1UL
        FPSCR, 0x2UL ]
      []
      [ V1A, 0x4070000000000000UL; V1B, 0x1UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc231e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x7fffffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ V1A, 0x407e000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []

  /// <summary>
  /// xscvqpdp vRT, vRB rounds vRB to a double in doubleword 0, in the direction
  /// FPSCR[RN] names (xscvqpdpo to odd), doubleword 1 cleared: overflow,
  /// underflow, a NaN keeping the top of its payload, one third.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSCVQPDP rounds a quad to a double``() =
    (* xscvqpdp v1,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc341e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x3fff000000000000UL
        V3B, 0x1UL ]
      []
      [ V1A, 0x3ff0000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc341e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x3fff000000000000UL
        V3B, 0x1UL
        FPSCR, 0x2UL ]
      []
      [ V1A, 0x3ff0000000000001UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc341e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x7ffeffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ V1A, 0x7ff0000000000000UL; V1B, 0x0UL; FPSCR, 0x5UL ]
      []
    oracleMem
      ppc64le
      "fc341e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x7ffeffffffffffffUL
        V3B, 0xffffffffffffffffUL
        FPSCR, 0x1UL ]
      []
      [ V1A, 0x7fefffffffffffffUL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc341e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x7ffeffffffffffffUL
        V3B, 0xffffffffffffffffUL
        FPSCR, 0x2UL ]
      []
      [ V1A, 0x7ff0000000000000UL; V1B, 0x0UL; FPSCR, 0x5UL ]
      []
    oracleMem
      ppc64le
      "fc341e88"
      [ V1A, 0xbad0bad0bad0badUL; V1B, 0xbad0bad0bad0badUL; V3B, 0x1UL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "fc341e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3B, 0x1UL
        FPSCR, 0x1UL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "fc341e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3B, 0x1UL
        FPSCR, 0x3UL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "fc341e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x7fff400000000000UL
        V3B, 0x5678UL ]
      []
      [ V1A, 0x7ffc000000000000UL; V1B, 0x0UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64le
      "fc341e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x7fff800000000000UL
        V3B, 0x1234UL ]
      []
      [ V1A, 0x7ff8000000000000UL; V1B, 0x0UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64le
      "fc341e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x3ffd555555555555UL
        V3B, 0x5555555555555555UL ]
      []
      [ V1A, 0x3fd5555555555555UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc341e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x3ffd555555555555UL
        V3B, 0x5555555555555555UL
        FPSCR, 0x1UL ]
      []
      [ V1A, 0x3fd5555555555555UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc341e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x3ffd555555555555UL
        V3B, 0x5555555555555555UL
        FPSCR, 0x2UL ]
      []
      [ V1A, 0x3fd5555555555556UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc341e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x3ffd555555555555UL
        V3B, 0x5555555555555555UL
        FPSCR, 0x3UL ]
      []
      [ V1A, 0x3fd5555555555555UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc341e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x3c00ffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ V1A, 0x10000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc341e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x3c00ffffffffffffUL
        V3B, 0xffffffffffffffffUL
        FPSCR, 0x2UL ]
      []
      [ V1A, 0x10000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []

  /// <summary>
  /// xscvqpdp vRT, vRB rounds vRB to a double in doubleword 0, in the direction
  /// FPSCR[RN] names (xscvqpdpo to odd), doubleword 1 cleared: overflow,
  /// underflow, a NaN keeping the top of its payload, one third.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSCVQPDPO beside XSCVQPDP``() =
    (* xscvqpdpo v1,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc341e89"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x3fff000000000000UL
        V3B, 0x1UL ]
      []
      [ V1A, 0x3ff0000000000001UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc341e89"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x7ffeffffffffffffUL
        V3B, 0xffffffffffffffffUL ]
      []
      [ V1A, 0x7fefffffffffffffUL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc341e89"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x3ffd555555555555UL
        V3B, 0x5555555555555555UL ]
      []
      [ V1A, 0x3fd5555555555555UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []

  /// <summary>
  /// xscvqpsdz and xscvqpudz truncate vRB toward zero to a signed or unsigned
  /// doubleword in doubleword 0, saturating: a NaN gives the smallest signed
  /// value or zero, a negative number zero to the unsigned one.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSCVQPSDZ truncates a quad to a doubleword``() =
    (* xscvqpsdz v1,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc391e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x3fff800000000000UL ]
      []
      [ V1A, 0x1UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc391e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0xbfff800000000000UL ]
      []
      [ V1A, 0xffffffffffffffffUL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc391e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x401e000000000000UL ]
      []
      [ V1A, 0x80000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc391e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0xc01e000000000000UL ]
      []
      [ V1A, 0xffffffff80000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc391e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x403e000000000000UL ]
      []
      [ V1A, 0x7fffffffffffffffUL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc391e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0xc03e000000000000UL ]
      []
      [ V1A, 0x8000000000000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc391e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x403f000000000000UL ]
      []
      [ V1A, 0x7fffffffffffffffUL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc391e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x407e000000000000UL ]
      []
      [ V1A, 0x7fffffffffffffffUL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc391e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x407f000000000000UL ]
      []
      [ V1A, 0x7fffffffffffffffUL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc391e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x7fff800000000000UL
        V3B, 0x1234UL ]
      []
      [ V1A, 0x8000000000000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc391e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0xbffe000000000000UL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc391e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0xffff000000000000UL ]
      []
      [ V1A, 0x8000000000000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc391e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x4070000000000000UL
        V3B, 0x8000000000000000UL ]
      []
      [ V1A, 0x7fffffffffffffffUL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc391e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x8000000000000000UL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL ]
      []

  /// <summary>
  /// xscvqpsdz and xscvqpudz truncate vRB toward zero to a signed or unsigned
  /// doubleword in doubleword 0, saturating: a NaN gives the smallest signed
  /// value or zero, a negative number zero to the unsigned one.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSCVQPUDZ beside XSCVQPSDZ``() =
    (* xscvqpudz v1,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc311e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x3fff800000000000UL ]
      []
      [ V1A, 0x1UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc311e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0xbfff800000000000UL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc311e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x403e000000000000UL ]
      []
      [ V1A, 0x8000000000000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc311e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x403f000000000000UL ]
      []
      [ V1A, 0xffffffffffffffffUL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc311e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x7fff800000000000UL
        V3B, 0x1234UL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc311e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0xbffe000000000000UL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc311e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0xffff000000000000UL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL ]
      []

  /// <summary>
  /// xscvqpswz and xscvqpuwz truncate vRB to a signed or unsigned word,
  /// extended to doubleword 0 as its signedness says, saturating at the word's
  /// ends.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSCVQPSWZ truncates a quad to a word``() =
    (* xscvqpswz v1,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc291e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x3fff800000000000UL ]
      []
      [ V1A, 0x1UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc291e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0xbfff800000000000UL ]
      []
      [ V1A, 0xffffffffffffffffUL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc291e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x401e000000000000UL ]
      []
      [ V1A, 0x7fffffffUL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc291e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0xc01e000000000000UL ]
      []
      [ V1A, 0xffffffff80000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc291e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x7fff800000000000UL
        V3B, 0x1234UL ]
      []
      [ V1A, 0xffffffff80000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc291e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0xffff000000000000UL ]
      []
      [ V1A, 0xffffffff80000000UL; V1B, 0x0UL ]
      []

  /// <summary>
  /// xscvqpswz and xscvqpuwz truncate vRB to a signed or unsigned word,
  /// extended to doubleword 0 as its signedness says, saturating at the word's
  /// ends.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSCVQPUWZ beside XSCVQPSWZ``() =
    (* xscvqpuwz v1,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc211e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x3fff800000000000UL ]
      []
      [ V1A, 0x1UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc211e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0xbfff800000000000UL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc211e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x401e000000000000UL ]
      []
      [ V1A, 0x80000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc211e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x403f000000000000UL ]
      []
      [ V1A, 0xffffffffUL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc211e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x7fff800000000000UL
        V3B, 0x1234UL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL ]
      []

  /// <summary>
  /// xscvqpsqz and xscvqpuqz truncate vRB to a signed or unsigned quadword,
  /// saturating at 2 to the 127 and 2 to the 128.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSCVQPSQZ truncates a quad to a quadword``() =
    (* xscvqpsqz v1,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc281e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x3fff800000000000UL ]
      []
      [ V1A, 0x0UL; V1B, 0x1UL ]
      []
    oracleMem
      ppc64le
      "fc281e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0xbfff800000000000UL ]
      []
      [ V1A, 0xffffffffffffffffUL; V1B, 0xffffffffffffffffUL ]
      []
    oracleMem
      ppc64le
      "fc281e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x407e000000000000UL ]
      []
      [ V1A, 0x7fffffffffffffffUL; V1B, 0xffffffffffffffffUL ]
      []
    oracleMem
      ppc64le
      "fc281e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x407f000000000000UL ]
      []
      [ V1A, 0x7fffffffffffffffUL; V1B, 0xffffffffffffffffUL ]
      []
    oracleMem
      ppc64le
      "fc281e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x7fff800000000000UL
        V3B, 0x1234UL ]
      []
      [ V1A, 0x8000000000000000UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc281e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x4070000000000000UL
        V3B, 0x8000000000000000UL ]
      []
      [ V1A, 0x2000000000001UL; V1B, 0x0UL ]
      []

  /// <summary>
  /// xscvqpsqz and xscvqpuqz truncate vRB to a signed or unsigned quadword,
  /// saturating at 2 to the 127 and 2 to the 128.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSCVQPUQZ beside XSCVQPSQZ``() =
    (* xscvqpuqz v1,v3, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc201e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x3fff800000000000UL ]
      []
      [ V1A, 0x0UL; V1B, 0x1UL ]
      []
    oracleMem
      ppc64le
      "fc201e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x407f000000000000UL ]
      []
      [ V1A, 0xffffffffffffffffUL; V1B, 0xffffffffffffffffUL ]
      []
    oracleMem
      ppc64le
      "fc201e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x7fff800000000000UL
        V3B, 0x1234UL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc201e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x4070000000000000UL
        V3B, 0x8000000000000000UL ]
      []
      [ V1A, 0x2000000000001UL; V1B, 0x0UL ]
      []
    oracleMem
      ppc64le
      "fc201e88"
      [ V1A, 0xbad0bad0bad0badUL
        V1B, 0xbad0bad0bad0badUL
        V3A, 0x8000000000000000UL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL ]
      []

  /// <summary>
  /// xsrqpi R, vRT, vRB, RMC rounds vRB to an integral value: R = 0 and RMC = 0
  /// to nearest with ties away, R = 0 and RMC = 3 by FPSCR[RN] (toward zero
  /// here), R = 1 by RMC; a signalling NaN comes back quiet, an infinity and -0
  /// as they are.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSRQPI rounds a quad to an integral value``() =
    (* xsrqpi 0,v1,v3,1, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc20180a"
      [ V1A, 0x3fff800000000000UL; V3A, 0x4000400000000000UL; FPSCR, 0x1UL ]
      []
      [ V1A, 0x4000800000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc20180a"
      [ V1A, 0x3fff000000000000UL; V3A, 0xc000400000000000UL; FPSCR, 0x1UL ]
      []
      [ V1A, 0xc000800000000000UL; V1B, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "fc20180a"
      [ V3A, 0x3fff800000000000UL; FPSCR, 0x1UL ]
      []
      [ V1A, 0x4000000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc20180a"
      [ V1A, 0x7fff000000000000UL; V3A, 0x3ffe000000000000UL; FPSCR, 0x1UL ]
      []
      [ V1A, 0x3fff000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc20180a"
      [ V1A, 0x7fff800000000000UL
        V3A, 0xbffd555555555555UL
        V3B, 0x5555555555555555UL
        FPSCR, 0x1UL ]
      []
      [ V1A, 0x8000000000000000UL; V1B, 0x0UL; FPSCR, 0x12UL ]
      []
    oracleMem
      ppc64le
      "fc20180a"
      [ V1A, 0x7ffeffffffffffffUL
        V1B, 0xffffffffffffffffUL
        V3A, 0x7fff400000000000UL
        V3B, 0x5678UL
        FPSCR, 0x1UL ]
      []
      [ V1A, 0x7fffc00000000000UL; V1B, 0x5678UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64le
      "fc20180a"
      [ V1A, 0x3fff000000000000UL; V3A, 0x7fff000000000000UL; FPSCR, 0x1UL ]
      []
      [ V1A, 0x7fff000000000000UL; V1B, 0x0UL; FPSCR, 0x5UL ]
      []
    oracleMem
      ppc64le
      "fc20180a"
      [ V1A, 0x3fff800000000000UL; V3A, 0x8000000000000000UL; FPSCR, 0x1UL ]
      []
      [ V1A, 0x8000000000000000UL; V1B, 0x0UL; FPSCR, 0x12UL ]
      []
    oracleMem
      ppc64le
      "fc20180a"
      [ V1A, 0x3fff000000000000UL
        V3A, 0x7ffeffffffffffffUL
        V3B, 0xffffffffffffffffUL
        FPSCR, 0x1UL ]
      []
      [ V1A, 0x7ffeffffffffffffUL; V1B, 0xffffffffffffffffUL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc201e0a"
      [ V1A, 0x3fff800000000000UL; V3A, 0x4000400000000000UL; FPSCR, 0x1UL ]
      []
      [ V1A, 0x4000000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc201e0a"
      [ V1A, 0x3fff000000000000UL; V3A, 0xc000400000000000UL; FPSCR, 0x1UL ]
      []
      [ V1B, 0x0UL; FPSCR, 0x8UL; V1A, 0xc000000000000000UL ]
      []
    oracleMem
      ppc64le
      "fc201e0a"
      [ V1A, 0x7fff800000000000UL
        V3A, 0xbffd555555555555UL
        V3B, 0x5555555555555555UL
        FPSCR, 0x1UL ]
      []
      [ V1B, 0x0UL; V1A, 0x8000000000000000UL; FPSCR, 0x12UL ]
      []
    oracleMem
      ppc64le
      "fc21180a"
      [ V1A, 0x3fff800000000000UL; V3A, 0x4000400000000000UL; FPSCR, 0x1UL ]
      []
      [ V1A, 0x4000000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc21180a"
      [ V1A, 0x3fff000000000000UL; V3A, 0xc000400000000000UL; FPSCR, 0x1UL ]
      []
      [ V1A, 0xc000000000000000UL; V1B, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "fc21180a"
      [ V3A, 0x3fff800000000000UL; FPSCR, 0x1UL ]
      []
      [ V1A, 0x4000000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc21180a"
      [ V1A, 0x7fff000000000000UL; V3A, 0x3ffe000000000000UL; FPSCR, 0x1UL ]
      []
      [ V1A, 0x0UL; V1B, 0x0UL; FPSCR, 0x2UL ]
      []
    oracleMem
      ppc64le
      "fc211a0a"
      [ V1A, 0x3fff800000000000UL; V3A, 0x4000400000000000UL; FPSCR, 0x1UL ]
      []
      [ V1A, 0x4000000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc211a0a"
      [ V1A, 0x7fff800000000000UL
        V3A, 0xbffd555555555555UL
        V3B, 0x5555555555555555UL
        FPSCR, 0x1UL ]
      []
      [ V1A, 0x8000000000000000UL; V1B, 0x0UL; FPSCR, 0x12UL ]
      []
    oracleMem
      ppc64le
      "fc211c0a"
      [ V1A, 0x3fff800000000000UL; V3A, 0x4000400000000000UL; FPSCR, 0x1UL ]
      []
      [ V1A, 0x4000800000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc211c0a"
      [ V1A, 0x7fff800000000000UL
        V3A, 0xbffd555555555555UL
        V3B, 0x5555555555555555UL
        FPSCR, 0x1UL ]
      []
      [ V1A, 0x8000000000000000UL; V1B, 0x0UL; FPSCR, 0x12UL ]
      []
    oracleMem
      ppc64le
      "fc211c0a"
      [ V1B, 0x1UL; V3A, 0x3fff000000000000UL; V3B, 0x1UL; FPSCR, 0x1UL ]
      []
      [ V1A, 0x4000000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc211e0a"
      [ V1A, 0x3fff800000000000UL; V3A, 0x4000400000000000UL; FPSCR, 0x1UL ]
      []
      [ V1A, 0x4000000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc211e0a"
      [ V1A, 0x7fff800000000000UL
        V3A, 0xbffd555555555555UL
        V3B, 0x5555555555555555UL
        FPSCR, 0x1UL ]
      []
      [ V1A, 0xbfff000000000000UL; V1B, 0x0UL; FPSCR, 0x8UL ]
      []
    oracleMem
      ppc64le
      "fc211e0a"
      [ V1A, 0x3fff800000000000UL; V3A, 0x8000000000000000UL; FPSCR, 0x1UL ]
      []
      [ V1A, 0x8000000000000000UL; V1B, 0x0UL; FPSCR, 0x12UL ]
      []

  /// <summary>
  /// xsrqpi R, vRT, vRB, RMC rounds vRB to an integral value: R = 0 and RMC = 0
  /// to nearest with ties away, R = 0 and RMC = 3 by FPSCR[RN] (toward zero
  /// here), R = 1 by RMC; a signalling NaN comes back quiet, an infinity and -0
  /// as they are.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSRQPIX beside XSRQPI``() =
    (* xsrqpix 0,v1,v3,1, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc21180b"
      [ V1A, 0x3fff800000000000UL; V3A, 0x4000400000000000UL; FPSCR, 0x1UL ]
      []
      [ V1A, 0x4000000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc21180b"
      [ V3A, 0x406f000000000000UL; V3B, 0x1UL; FPSCR, 0x1UL ]
      []
      [ V1A, 0x406f000000000000UL; V1B, 0x1UL; FPSCR, 0x4UL ]
      []

  /// <summary>
  /// xsrqpxp R, vRT, vRB, RMC rounds vRB to a 64-bit significand in the quad's
  /// exponent range: one ulp above one, a NaN cut to that precision, the
  /// largest quad overflowing or not by direction.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XSRQPXP rounds a quad to double-extended precision``() =
    (* xsrqpxp 0,v1,v3,1, under QEMU: lanes/x-oracle/quad *)
    oracleMem
      ppc64le
      "fc20184a"
      [ V1B, 0x1UL; V3A, 0x3fff000000000000UL; V3B, 0x1UL; FPSCR, 0x1UL ]
      []
      [ V1A, 0x3fff000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc20184a"
      [ V1A, 0x7ffeffffffffffffUL
        V1B, 0xffffffffffffffffUL
        V3A, 0x7fff400000000000UL
        V3B, 0x5678UL
        FPSCR, 0x1UL ]
      []
      [ V1A, 0x7fffc00000000000UL; V1B, 0x0UL; FPSCR, 0x11UL ]
      []
    oracleMem
      ppc64le
      "fc20184a"
      [ V1A, 0x3fff000000000000UL
        V3A, 0x7ffeffffffffffffUL
        V3B, 0xffffffffffffffffUL
        FPSCR, 0x1UL ]
      []
      [ V1A, 0x7fff000000000000UL; V1B, 0x0UL; FPSCR, 0x5UL ]
      []
    oracleMem
      ppc64le
      "fc20184a"
      [ V3A, 0x406f000000000000UL; V3B, 0x1UL; FPSCR, 0x1UL ]
      []
      [ V1A, 0x406f000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc211c4a"
      [ V1B, 0x1UL; V3A, 0x3fff000000000000UL; V3B, 0x1UL; FPSCR, 0x1UL ]
      []
      [ V1A, 0x3fff000000000000UL; V1B, 0x2000000000000UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc211c4a"
      [ V1A, 0x3fff000000000000UL
        V3A, 0x7ffeffffffffffffUL
        V3B, 0xffffffffffffffffUL
        FPSCR, 0x1UL ]
      []
      [ V1A, 0x7fff000000000000UL; V1B, 0x0UL; FPSCR, 0x5UL ]
      []
    oracleMem
      ppc64le
      "fc211e4a"
      [ V1A, 0x3fff000000000000UL
        V3A, 0x7ffeffffffffffffUL
        V3B, 0xffffffffffffffffUL
        FPSCR, 0x1UL ]
      []
      [ V1A, 0x7ffeffffffffffffUL; V1B, 0xfffe000000000000UL; FPSCR, 0x4UL ]
      []
    oracleMem
      ppc64le
      "fc21184a"
      [ V3A, 0x406f000000000000UL; V3B, 0x1UL; FPSCR, 0x1UL ]
      []
      [ V1A, 0x406f000000000000UL; V1B, 0x0UL; FPSCR, 0x4UL ]
      []

  /// <summary>
  /// xvf32ger AT, xA, xB sets element j of row i of accumulator AT (VSR 4AT +
  /// i) to word i of xA times word j of xB; the pp, pn, np and nn forms fuse
  /// the multiply with adding or subtracting the element and negate the rounded
  /// result for np and nn: exact sums, NaNs in every position in POWER's order,
  /// infinities, an inexact product and one past the range.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVF32GER updates a single accumulator``() =
    (* dmxvf32ger a4,vs2,vs3, under QEMU: lanes/x-oracle/mma *)
    oracleMem
      ppc64le
      "ee0218d8"
      [ F2, 0x3f800000c0000000UL
        F3, 0x3fc0000040000000UL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x3f00000040400000UL
        VSRL3, 0xbe80000040800000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x3fc0000040000000UL
        F17, 0xc0400000c0800000UL
        F18, 0x3f4000003f800000UL
        F19, 0x4090000040c00000UL
        VSRL16, 0xbe80000040800000UL
        VSRL17, 0x3f000000c1000000UL
        VSRL18, 0xbe00000040000000UL
        VSRL19, 0xbf40000041400000UL ]
      []
    oracleMem
      ppc64le
      "ee0218d8"
      [ F2, 0x7fc000017f800000UL
        F3, 0x3f80000000000000UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x7f800001UL
        VSRL3, 0xff8000007fc00002UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL ]
      []
      [ F16, 0x7fc000017fc00001UL
        F17, 0x7f8000007fc00000UL
        F18, 0x0UL
        F19, 0x7fc000017fc00001UL
        VSRL16, 0x7fc000017fc00001UL
        VSRL17, 0xff8000007fc00002UL
        VSRL18, 0x7fc000007fc00002UL
        VSRL19, 0x7fc000017fc00001UL ]
      []
    oracleMem
      ppc64le
      "ee0218d8"
      [ F2, 0x3eaaaaab3f8ccccdUL
        F3, 0x404000003f8ccccdUL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7149f2ca0da24260UL
        VSRL3, 0x7149f2ca0da24260UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x3f8000003ebbbbbcUL
        F17, 0x405333343f9ae148UL
        F18, 0x72177618715e24abUL
        F19, 0xe7363900db27c37UL
        VSRL16, 0x7086a1dc0cd85880UL
        VSRL17, 0x715e24ab0db27c37UL
        VSRL18, 0x7f8000003f800000UL
        VSRL19, 0x3f80000000000000UL ]
      []

  /// <summary>
  /// xvf32ger AT, xA, xB sets element j of row i of accumulator AT (VSR 4AT +
  /// i) to word i of xA times word j of xB; the pp, pn, np and nn forms fuse
  /// the multiply with adding or subtracting the element and negate the rounded
  /// result for np and nn: exact sums, NaNs in every position in POWER's order,
  /// infinities, an inexact product and one past the range.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVF32GERPP beside XVF32GER``() =
    (* dmxvf32gerpp a4,vs2,vs3, under QEMU: lanes/x-oracle/mma *)
    oracleMem
      ppc64le
      "ee0218d0"
      [ F2, 0x3f800000c0000000UL
        F3, 0x3fc0000040000000UL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x3f00000040400000UL
        VSRL3, 0xbe80000040800000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x4020000040800000UL
        F17, 0xc0200000c0c00000UL
        F18, 0x412c0000c1100000UL
        F19, 0x4090000040c00000UL
        VSRL16, 0x4030000041000000UL
        VSRL17, 0x3f000000c1000000UL
        VSRL18, 0x3f60000040400000UL
        VSRL19, 0xbf40000041400000UL ]
      []
    oracleMem
      ppc64le
      "ee0218d0"
      [ F2, 0x7fc000017f800000UL
        F3, 0x3f80000000000000UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x7f800001UL
        VSRL3, 0xff8000007fc00002UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL ]
      []
      [ F16, 0x7fc000017fc00001UL
        F17, 0x7f8000007fc00000UL
        F19, 0x7fc000017fc00001UL
        VSRL16, 0x7fc000017fc00001UL
        VSRL18, 0x7fc000007fc00002UL
        VSRL19, 0x7fc000017fc00001UL
        F18, 0x7fc0000200000000UL
        VSRL17, 0xff8000007fc00001UL ]
      []
    oracleMem
      ppc64le
      "ee0218d0"
      [ F2, 0x3eaaaaab3f8ccccdUL
        F3, 0x404000003f8ccccdUL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7149f2ca0da24260UL
        VSRL3, 0x7149f2ca0da24260UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x4000000040177778UL
        F17, 0x40733334bf4a3d70UL
        F18, 0x72177618715e24abUL
        F19, 0xe7363900db27c37UL
        VSRL16, 0x7086a1dc40800000UL
        VSRL17, 0x715e24ab0db27c37UL
        VSRL18, 0x7f80000040000000UL
        VSRL19, 0x3f80000000000000UL ]
      []

  /// <summary>
  /// xvf32ger AT, xA, xB sets element j of row i of accumulator AT (VSR 4AT +
  /// i) to word i of xA times word j of xB; the pp, pn, np and nn forms fuse
  /// the multiply with adding or subtracting the element and negate the rounded
  /// result for np and nn: exact sums, NaNs in every position in POWER's order,
  /// infinities, an inexact product and one past the range.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVF32GERPN beside XVF32GER``() =
    (* dmxvf32gerpn a4,vs2,vs3, under QEMU: lanes/x-oracle/mma *)
    oracleMem
      ppc64le
      "ee021cd0"
      [ F2, 0x3f800000c0000000UL
        F3, 0x3fc0000040000000UL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x3f00000040400000UL
        VSRL3, 0xbe80000040800000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x3f00000000000000UL
        F17, 0xc0600000c0000000UL
        F18, 0xc114000041300000UL
        F19, 0x4090000040c00000UL
        VSRL16, 0xc050000000000000UL
        VSRL17, 0x3f000000c1000000UL
        VSRL18, 0xbf9000003f800000UL
        VSRL19, 0xbf40000041400000UL ]
      []
    oracleMem
      ppc64le
      "ee021cd0"
      [ F2, 0x7fc000017f800000UL
        F3, 0x3f80000000000000UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x7f800001UL
        VSRL3, 0xff8000007fc00002UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL ]
      []
      [ F16, 0x7fc000017fc00001UL
        F17, 0x7fc000007fc00000UL
        F19, 0x7fc000017fc00001UL
        VSRL16, 0x7fc000017fc00001UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc000007fc00002UL
        VSRL19, 0x7fc000017fc00001UL
        F18, 0x7fc0000200000000UL ]
      []
    oracleMem
      ppc64le
      "ee021cd0"
      [ F2, 0x3eaaaaab3f8ccccdUL
        F3, 0x404000003f8ccccdUL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7149f2ca0da24260UL
        VSRL3, 0x7149f2ca0da24260UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x33000000bfd11111UL
        F17, 0x40333334404d70a4UL
        F18, 0x72177617715e24abUL
        F19, 0xe7363900db27c37UL
        VSRL16, 0x7086a1dcc0800000UL
        VSRL17, 0x715e24ab0db27c37UL
        VSRL18, 0x7f800000329c7f00UL
        VSRL19, 0x3f80000000000000UL ]
      []

  /// <summary>
  /// xvf32ger AT, xA, xB sets element j of row i of accumulator AT (VSR 4AT +
  /// i) to word i of xA times word j of xB; the pp, pn, np and nn forms fuse
  /// the multiply with adding or subtracting the element and negate the rounded
  /// result for np and nn: exact sums, NaNs in every position in POWER's order,
  /// infinities, an inexact product and one past the range.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVF32GERNP beside XVF32GER``() =
    (* dmxvf32gernp a4,vs2,vs3, under QEMU: lanes/x-oracle/mma *)
    oracleMem
      ppc64le
      "ee021ad0"
      [ F2, 0x3f800000c0000000UL
        F3, 0x3fc0000040000000UL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x3f00000040400000UL
        VSRL3, 0xbe80000040800000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0xbf00000080000000UL
        F17, 0x4060000040000000UL
        F18, 0x41140000c1300000UL
        F19, 0xc0900000c0c00000UL
        VSRL16, 0x4050000080000000UL
        VSRL17, 0xbf00000041000000UL
        VSRL18, 0x3f900000bf800000UL
        VSRL19, 0x3f400000c1400000UL ]
      []
    oracleMem
      ppc64le
      "ee021ad0"
      [ F2, 0x7fc000017f800000UL
        F3, 0x3f80000000000000UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x7f800001UL
        VSRL3, 0xff8000007fc00002UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL ]
      []
      [ F16, 0x7fc000017fc00001UL
        F17, 0x7fc000007fc00000UL
        F18, 0x7fc0000280000000UL
        F19, 0x7fc000017fc00001UL
        VSRL16, 0x7fc000017fc00001UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc000007fc00002UL
        VSRL19, 0x7fc000017fc00001UL ]
      []
    oracleMem
      ppc64le
      "ee021ad0"
      [ F2, 0x3eaaaaab3f8ccccdUL
        F3, 0x404000003f8ccccdUL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7149f2ca0da24260UL
        VSRL3, 0x7149f2ca0da24260UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0xb30000003fd11111UL
        F17, 0xc0333334c04d70a4UL
        F18, 0xf2177617f15e24abUL
        F19, 0x8e7363908db27c37UL
        VSRL16, 0xf086a1dc40800000UL
        VSRL17, 0xf15e24ab8db27c37UL
        VSRL18, 0xff800000b29c7f00UL
        VSRL19, 0xbf80000080000000UL ]
      []

  /// <summary>
  /// xvf32ger AT, xA, xB sets element j of row i of accumulator AT (VSR 4AT +
  /// i) to word i of xA times word j of xB; the pp, pn, np and nn forms fuse
  /// the multiply with adding or subtracting the element and negate the rounded
  /// result for np and nn: exact sums, NaNs in every position in POWER's order,
  /// infinities, an inexact product and one past the range.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVF32GERNN beside XVF32GER``() =
    (* dmxvf32gernn a4,vs2,vs3, under QEMU: lanes/x-oracle/mma *)
    oracleMem
      ppc64le
      "ee021ed0"
      [ F2, 0x3f800000c0000000UL
        F3, 0x3fc0000040000000UL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x3f00000040400000UL
        VSRL3, 0xbe80000040800000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0xc0200000c0800000UL
        F17, 0x4020000040c00000UL
        F18, 0xc12c000041100000UL
        F19, 0xc0900000c0c00000UL
        VSRL16, 0xc0300000c1000000UL
        VSRL17, 0xbf00000041000000UL
        VSRL18, 0xbf600000c0400000UL
        VSRL19, 0x3f400000c1400000UL ]
      []
    oracleMem
      ppc64le
      "ee021ed0"
      [ F2, 0x7fc000017f800000UL
        F3, 0x3f80000000000000UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x7f800001UL
        VSRL3, 0xff8000007fc00002UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL ]
      []
      [ F16, 0x7fc000017fc00001UL
        F17, 0xff8000007fc00000UL
        F18, 0x7fc0000280000000UL
        F19, 0x7fc000017fc00001UL
        VSRL16, 0x7fc000017fc00001UL
        VSRL17, 0x7f8000007fc00001UL
        VSRL18, 0x7fc000007fc00002UL
        VSRL19, 0x7fc000017fc00001UL ]
      []
    oracleMem
      ppc64le
      "ee021ed0"
      [ F2, 0x3eaaaaab3f8ccccdUL
        F3, 0x404000003f8ccccdUL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7149f2ca0da24260UL
        VSRL3, 0x7149f2ca0da24260UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0xc0000000c0177778UL
        F17, 0xc07333343f4a3d70UL
        F18, 0xf2177618f15e24abUL
        F19, 0x8e7363908db27c37UL
        VSRL16, 0xf086a1dcc0800000UL
        VSRL17, 0xf15e24ab8db27c37UL
        VSRL18, 0xff800000c0000000UL
        VSRL19, 0xbf80000080000000UL ]
      []

  /// <summary>
  /// xvf64ger AT, xAp, xB multiplies the four doubles of the pair starting at
  /// xAp by the two of xB into the 4 by 2 accumulator, each row two
  /// doublewords; the accumulating forms fuse as xvf32ger's do.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVF64GER updates a double accumulator``() =
    (* dmxvf64ger a4,vs6,vs3, under QEMU: lanes/x-oracle/mma *)
    oracleMem
      ppc64le
      "ee0619d8"
      [ F3, 0x4008000000000000UL
        F6, 0x3ff0000000000000UL
        F7, 0x3fe0000000000000UL
        F16, 0x3ff0000000000000UL
        F17, 0x3fe0000000000000UL
        F19, 0x4000000000000000UL
        VSRL3, 0x3fe0000000000000UL
        VSRL6, 0x4000000000000000UL
        VSRL7, 0xbff0000000000000UL
        VSRL16, 0x4000000000000000UL
        VSRL17, 0xc000000000000000UL
        VSRL18, 0x8000000000000000UL
        VSRL19, 0x3ff0000000000000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x4008000000000000UL
        F17, 0x4018000000000000UL
        F18, 0x3ff8000000000000UL
        F19, 0xc008000000000000UL
        VSRL16, 0x3fe0000000000000UL
        VSRL17, 0x3ff0000000000000UL
        VSRL18, 0x3fd0000000000000UL
        VSRL19, 0xbfe0000000000000UL ]
      []
    oracleMem
      ppc64le
      "ee0619d8"
      [ F3, 0x3ff0000000000000UL
        F6, 0x7ff8000000000001UL
        F16, 0x7ff0000000000000UL
        F17, 0x7ff8000000000002UL
        F18, 0xfff0000000000000UL
        F19, 0x7ff0000000000001UL
        VSRL6, 0x7ff0000000000000UL
        VSRL7, 0x7ff0000000000001UL
        VSRL16, 0x7ff8000000000001UL
        VSRL18, 0x3ff0000000000000UL
        VSRL19, 0x4000000000000000UL ]
      []
      [ F16, 0x7ff8000000000001UL
        F17, 0x7ff0000000000000UL
        F18, 0x0UL
        F19, 0x7ff8000000000001UL
        VSRL17, 0x7ff8000000000000UL
        VSRL18, 0x0UL
        VSRL19, 0x7ff8000000000001UL
        VSRL16, 0x7ff8000000000001UL ]
      []
    oracleMem
      ppc64le
      "ee0619d8"
      [ F3, 0x4008000000000000UL
        F6, 0x3fd5555555555555UL
        F7, 0x3ff0000000000000UL
        F16, 0x3ff0000000000000UL
        F17, 0x3fe0000000000000UL
        F19, 0x4000000000000000UL
        VSRL3, 0x3ff199999999999aUL
        VSRL6, 0x3ff199999999999aUL
        VSRL7, 0x4000000000000000UL
        VSRL16, 0x4000000000000000UL
        VSRL17, 0xc000000000000000UL
        VSRL18, 0x8000000000000000UL
        VSRL19, 0x3ff0000000000000UL
        VSCR, 0x10000UL ]
      []
      [ F17, 0x400a666666666667UL
        F18, 0x4008000000000000UL
        F19, 0x4018000000000000UL
        VSRL16, 0x3fd7777777777778UL
        VSRL17, 0x3ff35c28f5c28f5dUL
        VSRL18, 0x3ff199999999999aUL
        VSRL19, 0x400199999999999aUL
        F16, 0x3ff0000000000000UL ]
      []

  /// <summary>
  /// xvf64ger AT, xAp, xB multiplies the four doubles of the pair starting at
  /// xAp by the two of xB into the 4 by 2 accumulator, each row two
  /// doublewords; the accumulating forms fuse as xvf32ger's do.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVF64GERPP beside XVF64GER``() =
    (* dmxvf64gerpp a4,vs6,vs3, under QEMU: lanes/x-oracle/mma *)
    oracleMem
      ppc64le
      "ee0619d0"
      [ F3, 0x4008000000000000UL
        F6, 0x3ff0000000000000UL
        F7, 0x3fe0000000000000UL
        F16, 0x3ff0000000000000UL
        F17, 0x3fe0000000000000UL
        F19, 0x4000000000000000UL
        VSRL3, 0x3fe0000000000000UL
        VSRL6, 0x4000000000000000UL
        VSRL7, 0xbff0000000000000UL
        VSRL16, 0x4000000000000000UL
        VSRL17, 0xc000000000000000UL
        VSRL18, 0x8000000000000000UL
        VSRL19, 0x3ff0000000000000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x4010000000000000UL
        F17, 0x401a000000000000UL
        F18, 0x3ff8000000000000UL
        F19, 0xbff0000000000000UL
        VSRL16, 0x4004000000000000UL
        VSRL17, 0xbff0000000000000UL
        VSRL18, 0x3fd0000000000000UL
        VSRL19, 0x3fe0000000000000UL ]
      []
    oracleMem
      ppc64le
      "ee0619d0"
      [ F3, 0x3ff0000000000000UL
        F6, 0x7ff8000000000001UL
        F16, 0x7ff0000000000000UL
        F17, 0x7ff8000000000002UL
        F18, 0xfff0000000000000UL
        F19, 0x7ff0000000000001UL
        VSRL6, 0x7ff0000000000000UL
        VSRL7, 0x7ff0000000000001UL
        VSRL16, 0x7ff8000000000001UL
        VSRL18, 0x3ff0000000000000UL
        VSRL19, 0x4000000000000000UL ]
      []
      [ F16, 0x7ff8000000000001UL
        F19, 0x7ff8000000000001UL
        VSRL17, 0x7ff8000000000000UL
        VSRL19, 0x7ff8000000000001UL
        F17, 0x7ff8000000000002UL
        F18, 0xfff0000000000000UL
        VSRL16, 0x7ff8000000000001UL
        VSRL18, 0x3ff0000000000000UL ]
      []
    oracleMem
      ppc64le
      "ee0619d0"
      [ F3, 0x4008000000000000UL
        F6, 0x3fd5555555555555UL
        F7, 0x3ff0000000000000UL
        F16, 0x3ff0000000000000UL
        F17, 0x3fe0000000000000UL
        F19, 0x4000000000000000UL
        VSRL3, 0x3ff199999999999aUL
        VSRL6, 0x3ff199999999999aUL
        VSRL7, 0x4000000000000000UL
        VSRL16, 0x4000000000000000UL
        VSRL17, 0xc000000000000000UL
        VSRL18, 0x8000000000000000UL
        VSRL19, 0x3ff0000000000000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x4000000000000000UL
        F17, 0x400e666666666667UL
        F18, 0x4008000000000000UL
        F19, 0x4020000000000000UL
        VSRL16, 0x4002eeeeeeeeeeefUL
        VSRL17, 0xbfe947ae147ae146UL
        VSRL18, 0x3ff199999999999aUL
        VSRL19, 0x400999999999999aUL ]
      []

  /// <summary>
  /// xvf64ger AT, xAp, xB multiplies the four doubles of the pair starting at
  /// xAp by the two of xB into the 4 by 2 accumulator, each row two
  /// doublewords; the accumulating forms fuse as xvf32ger's do.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVF64GERPN beside XVF64GER``() =
    (* dmxvf64gerpn a4,vs6,vs3, under QEMU: lanes/x-oracle/mma *)
    oracleMem
      ppc64le
      "ee061dd0"
      [ F3, 0x4008000000000000UL
        F6, 0x3ff0000000000000UL
        F7, 0x3fe0000000000000UL
        F16, 0x3ff0000000000000UL
        F17, 0x3fe0000000000000UL
        F19, 0x4000000000000000UL
        VSRL3, 0x3fe0000000000000UL
        VSRL6, 0x4000000000000000UL
        VSRL7, 0xbff0000000000000UL
        VSRL16, 0x4000000000000000UL
        VSRL17, 0xc000000000000000UL
        VSRL18, 0x8000000000000000UL
        VSRL19, 0x3ff0000000000000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x4000000000000000UL
        F17, 0x4016000000000000UL
        F18, 0x3ff8000000000000UL
        F19, 0xc014000000000000UL
        VSRL16, 0xbff8000000000000UL
        VSRL17, 0x4008000000000000UL
        VSRL18, 0x3fd0000000000000UL
        VSRL19, 0xbff8000000000000UL ]
      []
    oracleMem
      ppc64le
      "ee061dd0"
      [ F3, 0x3ff0000000000000UL
        F6, 0x7ff8000000000001UL
        F16, 0x7ff0000000000000UL
        F17, 0x7ff8000000000002UL
        F18, 0xfff0000000000000UL
        F19, 0x7ff0000000000001UL
        VSRL6, 0x7ff0000000000000UL
        VSRL7, 0x7ff0000000000001UL
        VSRL16, 0x7ff8000000000001UL
        VSRL18, 0x3ff0000000000000UL
        VSRL19, 0x4000000000000000UL ]
      []
      [ F16, 0x7ff8000000000001UL
        F18, 0x7ff0000000000000UL
        F19, 0x7ff8000000000001UL
        VSRL17, 0x7ff8000000000000UL
        VSRL18, 0xbff0000000000000UL
        VSRL19, 0x7ff8000000000001UL
        F17, 0x7ff8000000000002UL
        VSRL16, 0x7ff8000000000001UL ]
      []
    oracleMem
      ppc64le
      "ee061dd0"
      [ F3, 0x4008000000000000UL
        F6, 0x3fd5555555555555UL
        F7, 0x3ff0000000000000UL
        F16, 0x3ff0000000000000UL
        F17, 0x3fe0000000000000UL
        F19, 0x4000000000000000UL
        VSRL3, 0x3ff199999999999aUL
        VSRL6, 0x3ff199999999999aUL
        VSRL7, 0x4000000000000000UL
        VSRL16, 0x4000000000000000UL
        VSRL17, 0xc000000000000000UL
        VSRL18, 0x8000000000000000UL
        VSRL19, 0x3ff0000000000000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0xbc90000000000000UL
        F17, 0x4006666666666667UL
        F18, 0x4008000000000000UL
        F19, 0x4010000000000000UL
        VSRL16, 0xbffa222222222222UL
        VSRL17, 0x4009ae147ae147afUL
        VSRL18, 0x3ff199999999999aUL
        VSRL19, 0x3ff3333333333334UL ]
      []

  /// <summary>
  /// xvf64ger AT, xAp, xB multiplies the four doubles of the pair starting at
  /// xAp by the two of xB into the 4 by 2 accumulator, each row two
  /// doublewords; the accumulating forms fuse as xvf32ger's do.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVF64GERNP beside XVF64GER``() =
    (* dmxvf64gernp a4,vs6,vs3, under QEMU: lanes/x-oracle/mma *)
    oracleMem
      ppc64le
      "ee061bd0"
      [ F3, 0x4008000000000000UL
        F6, 0x3ff0000000000000UL
        F7, 0x3fe0000000000000UL
        F16, 0x3ff0000000000000UL
        F17, 0x3fe0000000000000UL
        F19, 0x4000000000000000UL
        VSRL3, 0x3fe0000000000000UL
        VSRL6, 0x4000000000000000UL
        VSRL7, 0xbff0000000000000UL
        VSRL16, 0x4000000000000000UL
        VSRL17, 0xc000000000000000UL
        VSRL18, 0x8000000000000000UL
        VSRL19, 0x3ff0000000000000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0xc000000000000000UL
        F17, 0xc016000000000000UL
        F18, 0xbff8000000000000UL
        F19, 0x4014000000000000UL
        VSRL16, 0x3ff8000000000000UL
        VSRL17, 0xc008000000000000UL
        VSRL18, 0xbfd0000000000000UL
        VSRL19, 0x3ff8000000000000UL ]
      []
    oracleMem
      ppc64le
      "ee061bd0"
      [ F3, 0x3ff0000000000000UL
        F6, 0x7ff8000000000001UL
        F16, 0x7ff0000000000000UL
        F17, 0x7ff8000000000002UL
        F18, 0xfff0000000000000UL
        F19, 0x7ff0000000000001UL
        VSRL6, 0x7ff0000000000000UL
        VSRL7, 0x7ff0000000000001UL
        VSRL16, 0x7ff8000000000001UL
        VSRL18, 0x3ff0000000000000UL
        VSRL19, 0x4000000000000000UL ]
      []
      [ F16, 0x7ff8000000000001UL
        F19, 0x7ff8000000000001UL
        VSRL17, 0x7ff8000000000000UL
        VSRL19, 0x7ff8000000000001UL
        F17, 0x7ff8000000000002UL
        F18, 0xfff0000000000000UL
        VSRL16, 0x7ff8000000000001UL
        VSRL18, 0x3ff0000000000000UL ]
      []
    oracleMem
      ppc64le
      "ee061bd0"
      [ F3, 0x4008000000000000UL
        F6, 0x3fd5555555555555UL
        F7, 0x3ff0000000000000UL
        F16, 0x3ff0000000000000UL
        F17, 0x3fe0000000000000UL
        F19, 0x4000000000000000UL
        VSRL3, 0x3ff199999999999aUL
        VSRL6, 0x3ff199999999999aUL
        VSRL7, 0x4000000000000000UL
        VSRL16, 0x4000000000000000UL
        VSRL17, 0xc000000000000000UL
        VSRL18, 0x8000000000000000UL
        VSRL19, 0x3ff0000000000000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x3c90000000000000UL
        F17, 0xc006666666666667UL
        F18, 0xc008000000000000UL
        F19, 0xc010000000000000UL
        VSRL16, 0x3ffa222222222222UL
        VSRL17, 0xc009ae147ae147afUL
        VSRL18, 0xbff199999999999aUL
        VSRL19, 0xbff3333333333334UL ]
      []

  /// <summary>
  /// xvf64ger AT, xAp, xB multiplies the four doubles of the pair starting at
  /// xAp by the two of xB into the 4 by 2 accumulator, each row two
  /// doublewords; the accumulating forms fuse as xvf32ger's do.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVF64GERNN beside XVF64GER``() =
    (* dmxvf64gernn a4,vs6,vs3, under QEMU: lanes/x-oracle/mma *)
    oracleMem
      ppc64le
      "ee061fd0"
      [ F3, 0x4008000000000000UL
        F6, 0x3ff0000000000000UL
        F7, 0x3fe0000000000000UL
        F16, 0x3ff0000000000000UL
        F17, 0x3fe0000000000000UL
        F19, 0x4000000000000000UL
        VSRL3, 0x3fe0000000000000UL
        VSRL6, 0x4000000000000000UL
        VSRL7, 0xbff0000000000000UL
        VSRL16, 0x4000000000000000UL
        VSRL17, 0xc000000000000000UL
        VSRL18, 0x8000000000000000UL
        VSRL19, 0x3ff0000000000000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0xc010000000000000UL
        F17, 0xc01a000000000000UL
        F18, 0xbff8000000000000UL
        F19, 0x3ff0000000000000UL
        VSRL16, 0xc004000000000000UL
        VSRL17, 0x3ff0000000000000UL
        VSRL18, 0xbfd0000000000000UL
        VSRL19, 0xbfe0000000000000UL ]
      []
    oracleMem
      ppc64le
      "ee061fd0"
      [ F3, 0x3ff0000000000000UL
        F6, 0x7ff8000000000001UL
        F16, 0x7ff0000000000000UL
        F17, 0x7ff8000000000002UL
        F18, 0xfff0000000000000UL
        F19, 0x7ff0000000000001UL
        VSRL6, 0x7ff0000000000000UL
        VSRL7, 0x7ff0000000000001UL
        VSRL16, 0x7ff8000000000001UL
        VSRL18, 0x3ff0000000000000UL
        VSRL19, 0x4000000000000000UL ]
      []
      [ F16, 0x7ff8000000000001UL
        F18, 0x7ff0000000000000UL
        F19, 0x7ff8000000000001UL
        VSRL17, 0x7ff8000000000000UL
        VSRL18, 0xbff0000000000000UL
        VSRL19, 0x7ff8000000000001UL
        F17, 0x7ff8000000000002UL
        VSRL16, 0x7ff8000000000001UL ]
      []
    oracleMem
      ppc64le
      "ee061fd0"
      [ F3, 0x4008000000000000UL
        F6, 0x3fd5555555555555UL
        F7, 0x3ff0000000000000UL
        F16, 0x3ff0000000000000UL
        F17, 0x3fe0000000000000UL
        F19, 0x4000000000000000UL
        VSRL3, 0x3ff199999999999aUL
        VSRL6, 0x3ff199999999999aUL
        VSRL7, 0x4000000000000000UL
        VSRL16, 0x4000000000000000UL
        VSRL17, 0xc000000000000000UL
        VSRL18, 0x8000000000000000UL
        VSRL19, 0x3ff0000000000000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0xc000000000000000UL
        F17, 0xc00e666666666667UL
        F18, 0xc008000000000000UL
        F19, 0xc020000000000000UL
        VSRL16, 0xc002eeeeeeeeeeefUL
        VSRL17, 0x3fe947ae147ae146UL
        VSRL18, 0xbff199999999999aUL
        VSRL19, 0xc00999999999999aUL ]
      []

  /// <summary>
  /// xvf16ger2 AT, xA, xB sets each element to the two products of matching
  /// halves of word i of xA and word j of xB summed and rounded to a single in
  /// the direction FPSCR[RN] names, through FGER2HALF; the accumulating forms
  /// then add or subtract the element (negating the sum first for np and nn)
  /// with a second rounding.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVF16GER2 sums half products``() =
    (* dmxvf16ger2 a4,vs2,vs3, under QEMU: lanes/x-oracle/mma *)
    oracleMem
      ppc64le
      "ee021898"
      [ F2, 0x3c0040003800be00UL
        F3, 0x40003c0035553555UL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7bff7bff00013555UL
        VSRL3, 0x7bfffbff00014000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x408000003f7ff000UL
        F17, 0xbf000000beaaa000UL
        F18, 0x483fe800472a8aacUL
        F19, 0x3eaaa0043de371cbUL
        VSRL16, 0xc77fe00040800000UL
        VSRL17, 0x47ffe000c0400000UL
        VSRL18, 0x47ffe000UL
        VSRL19, 0xc6aa8aaa3f2aa000UL ]
      []
    oracleMem
      ppc64le
      "ee021898"
      [ F2, 0x3c0040003800be00UL
        F3, 0x40003c0035553555UL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7bff7bff00013555UL
        VSRL3, 0x7bfffbff00014000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        FPSCR, 0x1UL ]
      []
      [ F16, 0x408000003f7ff000UL
        F17, 0xbf000000beaaa000UL
        F18, 0x483fe800472a8aacUL
        F19, 0x3eaaa0043de371caUL
        VSRL16, 0xc77fe00040800000UL
        VSRL17, 0x47ffe000c03fffffUL
        VSRL18, 0x47ffe000UL
        VSRL19, 0xc6aa8aaa3f2aa000UL ]
      []
    oracleMem
      ppc64le
      "ee021898"
      [ F2, 0x3c0040003800be00UL
        F3, 0x40003c0035553555UL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7bff7bff00013555UL
        VSRL3, 0x7bfffbff00014000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x10000UL
        FPSCR, 0x2UL ]
      []
      [ F16, 0x408000003f7ff000UL
        F17, 0xbf000000beaaa000UL
        F18, 0x483fe800472a8aacUL
        F19, 0x3eaaa0043de371cbUL
        VSRL16, 0xc77fe00040800001UL
        VSRL17, 0x47ffe000c03fffffUL
        VSRL18, 0x47ffe001UL
        VSRL19, 0xc6aa8aaa3f2aa001UL ]
      []
    oracleMem
      ppc64le
      "ee021898"
      [ F2, 0x3c0040003800be00UL
        F3, 0x40003c0035553555UL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7bff7bff00013555UL
        VSRL3, 0x7bfffbff00014000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x1UL
        FPSCR, 0x3UL ]
      []
      [ F16, 0x408000003f7ff000UL
        F17, 0xbf000000beaaa000UL
        F18, 0x483fe800472a8aacUL
        F19, 0x3eaaa0043de371caUL
        VSRL16, 0xc77fe00040800000UL
        VSRL17, 0x47ffe000c0400000UL
        VSRL18, 0x8000000047ffe000UL
        VSRL19, 0xc6aa8aab3f2aa000UL ]
      []
    oracleMem
      ppc64le
      "ee021898"
      [ F2, 0x7e013c007c000000UL
        F3, 0x3c007e0200003c00UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3c007c013c003c00UL
        VSRL3, 0x7c00fc003c003c00UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL ]
      []
      [ F16, 0x7fc020007fc02000UL
        F17, 0x7fc040007fc00000UL
        F18, 0x7fc020007fc02000UL
        F19, 0x7fc040003f800000UL
        VSRL16, 0x7fc020007fc02000UL
        VSRL17, 0x7fc000007f800000UL
        VSRL18, 0x7fc020007fc02000UL
        VSRL19, 0x7fc0000040000000UL ]
      []
    oracleMem
      ppc64le
      "ee021898"
      [ F2, 0x7e013c007c000000UL
        F3, 0x3c007e0200003c00UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3c007c013c003c00UL
        VSRL3, 0x7c00fc003c003c00UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL
        VSCR, 0x10000UL
        FPSCR, 0x1UL ]
      []
      [ F16, 0x7fc020007fc02000UL
        F17, 0x7fc040007fc00000UL
        F18, 0x7fc020007fc02000UL
        F19, 0x7fc040003f800000UL
        VSRL16, 0x7fc020007fc02000UL
        VSRL17, 0x7fc000007f800000UL
        VSRL18, 0x7fc020007fc02000UL
        VSRL19, 0x7fc0000040000000UL ]
      []
    oracleMem
      ppc64le
      "ee021898"
      [ F2, 0x7e013c007c000000UL
        F3, 0x3c007e0200003c00UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3c007c013c003c00UL
        VSRL3, 0x7c00fc003c003c00UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL
        FPSCR, 0x2UL ]
      []
      [ F16, 0x7fc020007fc02000UL
        F17, 0x7fc040007fc00000UL
        F18, 0x7fc020007fc02000UL
        F19, 0x7fc040003f800000UL
        VSRL16, 0x7fc020007fc02000UL
        VSRL17, 0x7fc000007f800000UL
        VSRL18, 0x7fc020007fc02000UL
        VSRL19, 0x7fc0000040000000UL ]
      []
    oracleMem
      ppc64le
      "ee021898"
      [ F2, 0x7e013c007c000000UL
        F3, 0x3c007e0200003c00UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3c007c013c003c00UL
        VSRL3, 0x7c00fc003c003c00UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL
        VSCR, 0x10001UL
        FPSCR, 0x3UL ]
      []
      [ F16, 0x7fc020007fc02000UL
        F17, 0x7fc040007fc00000UL
        F18, 0x7fc020007fc02000UL
        F19, 0x7fc040003f800000UL
        VSRL16, 0x7fc020007fc02000UL
        VSRL17, 0x7fc000007f800000UL
        VSRL18, 0x7fc020007fc02000UL
        VSRL19, 0x7fc0000040000000UL ]
      []

  /// <summary>
  /// xvf16ger2 AT, xA, xB sets each element to the two products of matching
  /// halves of word i of xA and word j of xB summed and rounded to a single in
  /// the direction FPSCR[RN] names, through FGER2HALF; the accumulating forms
  /// then add or subtract the element (negating the sum first for np and nn)
  /// with a second rounding.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVF16GER2PP beside XVF16GER2``() =
    (* dmxvf16ger2pp a4,vs2,vs3, under QEMU: lanes/x-oracle/mma *)
    oracleMem
      ppc64le
      "ee021890"
      [ F2, 0x3c0040003800be00UL
        F3, 0x40003c0035553555UL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7bff7bff00013555UL
        VSRL3, 0x7bfffbff00014000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x40a00000403ffc00UL
        F17, 0xc0155400UL
        F18, 0x483fea80472a80acUL
        F19, 0x3eaaa0043de371cbUL
        VSRL16, 0xc77fdd0041000000UL
        VSRL17, 0x47ffe000c0400000UL
        VSRL18, 0x3f80000047ffe080UL
        VSRL19, 0xc6aa8aaa3f2aa000UL ]
      []
    oracleMem
      ppc64le
      "ee021890"
      [ F2, 0x3c0040003800be00UL
        F3, 0x40003c0035553555UL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7bff7bff00013555UL
        VSRL3, 0x7bfffbff00014000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        FPSCR, 0x1UL ]
      []
      [ F16, 0x40a00000403ffc00UL
        F17, 0xc0155400UL
        F18, 0x483fea80472a80acUL
        F19, 0x3eaaa0043de371caUL
        VSRL16, 0xc77fdd0041000000UL
        VSRL17, 0x47ffe000c03fffffUL
        VSRL18, 0x3f80000047ffe080UL
        VSRL19, 0xc6aa8aaa3f2aa000UL ]
      []
    oracleMem
      ppc64le
      "ee021890"
      [ F2, 0x3c0040003800be00UL
        F3, 0x40003c0035553555UL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7bff7bff00013555UL
        VSRL3, 0x7bfffbff00014000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x10000UL
        FPSCR, 0x2UL ]
      []
      [ F16, 0x40a00000403ffc00UL
        F17, 0xc0155400UL
        F18, 0x483fea80472a80acUL
        F19, 0x3eaaa0043de371cbUL
        VSRL16, 0xc77fdd0041000001UL
        VSRL17, 0x47ffe000c03fffffUL
        VSRL18, 0x3f80000047ffe081UL
        VSRL19, 0xc6aa8aaa3f2aa001UL ]
      []
    oracleMem
      ppc64le
      "ee021890"
      [ F2, 0x3c0040003800be00UL
        F3, 0x40003c0035553555UL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7bff7bff00013555UL
        VSRL3, 0x7bfffbff00014000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x1UL
        FPSCR, 0x3UL ]
      []
      [ F16, 0x40a00000403ffc00UL
        F17, 0x80000000c0155400UL
        F18, 0x483fea80472a80acUL
        F19, 0x3eaaa0043de371caUL
        VSRL16, 0xc77fdd0041000000UL
        VSRL17, 0x47ffe000c0400000UL
        VSRL18, 0x3f80000047ffe080UL
        VSRL19, 0xc6aa8aab3f2aa000UL ]
      []
    oracleMem
      ppc64le
      "ee021890"
      [ F2, 0x7e013c007c000000UL
        F3, 0x3c007e0200003c00UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3c007c013c003c00UL
        VSRL3, 0x7c00fc003c003c00UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL ]
      []
      [ F16, 0x7fc020007fc02000UL
        F17, 0x7fc040007fc00000UL
        F18, 0x7fc020007fc02000UL
        F19, 0x7fc0400040000000UL
        VSRL16, 0x7fc020007fc02000UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc020007fc02000UL
        VSRL19, 0x7fc0000040000000UL ]
      []
    oracleMem
      ppc64le
      "ee021890"
      [ F2, 0x7e013c007c000000UL
        F3, 0x3c007e0200003c00UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3c007c013c003c00UL
        VSRL3, 0x7c00fc003c003c00UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL
        VSCR, 0x10000UL
        FPSCR, 0x1UL ]
      []
      [ F16, 0x7fc020007fc02000UL
        F17, 0x7fc040007fc00000UL
        F18, 0x7fc020007fc02000UL
        F19, 0x7fc0400040000000UL
        VSRL16, 0x7fc020007fc02000UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc020007fc02000UL
        VSRL19, 0x7fc0000040000000UL ]
      []
    oracleMem
      ppc64le
      "ee021890"
      [ F2, 0x7e013c007c000000UL
        F3, 0x3c007e0200003c00UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3c007c013c003c00UL
        VSRL3, 0x7c00fc003c003c00UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL
        FPSCR, 0x2UL ]
      []
      [ F16, 0x7fc020007fc02000UL
        F17, 0x7fc040007fc00000UL
        F18, 0x7fc020007fc02000UL
        F19, 0x7fc0400040000000UL
        VSRL16, 0x7fc020007fc02000UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc020007fc02000UL
        VSRL19, 0x7fc0000040000000UL ]
      []
    oracleMem
      ppc64le
      "ee021890"
      [ F2, 0x7e013c007c000000UL
        F3, 0x3c007e0200003c00UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3c007c013c003c00UL
        VSRL3, 0x7c00fc003c003c00UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL
        VSCR, 0x10001UL
        FPSCR, 0x3UL ]
      []
      [ F16, 0x7fc020007fc02000UL
        F17, 0x7fc040007fc00000UL
        F18, 0x7fc020007fc02000UL
        F19, 0x7fc0400040000000UL
        VSRL16, 0x7fc020007fc02000UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc020007fc02000UL
        VSRL19, 0x7fc0000040000000UL ]
      []

  /// <summary>
  /// xvf16ger2 AT, xA, xB sets each element to the two products of matching
  /// halves of word i of xA and word j of xB summed and rounded to a single in
  /// the direction FPSCR[RN] names, through FGER2HALF; the accumulating forms
  /// then add or subtract the element (negating the sum first for np and nn)
  /// with a second rounding.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVF16GER2PN beside XVF16GER2``() =
    (* dmxvf16ger2pn a4,vs2,vs3, under QEMU: lanes/x-oracle/mma *)
    oracleMem
      ppc64le
      "ee021c90"
      [ F2, 0x3c0040003800be00UL
        F3, 0x40003c0035553555UL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7bff7bff00013555UL
        VSRL3, 0x7bfffbff00014000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x40400000bf800800UL
        F17, 0xbf8000003fd55800UL
        F18, 0x483fe580472a94acUL
        F19, 0x3eaaa0043de371cbUL
        VSRL16, 0xc77fe30000000000UL
        VSRL17, 0x47ffe000c0400000UL
        VSRL18, 0xbf80000047ffdf80UL
        VSRL19, 0xc6aa8aaa3f2aa000UL ]
      []
    oracleMem
      ppc64le
      "ee021c90"
      [ F2, 0x3c0040003800be00UL
        F3, 0x40003c0035553555UL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7bff7bff00013555UL
        VSRL3, 0x7bfffbff00014000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        FPSCR, 0x1UL ]
      []
      [ F16, 0x40400000bf800800UL
        F17, 0xbf8000003fd55800UL
        F18, 0x483fe580472a94acUL
        F19, 0x3eaaa0043de371caUL
        VSRL16, 0xc77fe30000000000UL
        VSRL17, 0x47ffe000c03fffffUL
        VSRL18, 0xbf80000047ffdf80UL
        VSRL19, 0xc6aa8aaa3f2aa000UL ]
      []
    oracleMem
      ppc64le
      "ee021c90"
      [ F2, 0x3c0040003800be00UL
        F3, 0x40003c0035553555UL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7bff7bff00013555UL
        VSRL3, 0x7bfffbff00014000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x10000UL
        FPSCR, 0x2UL ]
      []
      [ F16, 0x40400000bf800800UL
        F17, 0xbf8000003fd55800UL
        F18, 0x483fe580472a94acUL
        F19, 0x3eaaa0043de371cbUL
        VSRL16, 0xc77fe30035000000UL
        VSRL17, 0x47ffe000c03fffffUL
        VSRL18, 0xbf80000047ffdf81UL
        VSRL19, 0xc6aa8aaa3f2aa001UL ]
      []
    oracleMem
      ppc64le
      "ee021c90"
      [ F2, 0x3c0040003800be00UL
        F3, 0x40003c0035553555UL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7bff7bff00013555UL
        VSRL3, 0x7bfffbff00014000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x1UL
        FPSCR, 0x3UL ]
      []
      [ F16, 0x40400000bf800800UL
        F17, 0xbf8000003fd55800UL
        F18, 0x483fe580472a94acUL
        F19, 0x3eaaa0043de371caUL
        VSRL16, 0xc77fe30080000000UL
        VSRL17, 0x47ffe000c0400000UL
        VSRL18, 0xbf80000047ffdf80UL
        VSRL19, 0xc6aa8aab3f2aa000UL ]
      []
    oracleMem
      ppc64le
      "ee021c90"
      [ F2, 0x7e013c007c000000UL
        F3, 0x3c007e0200003c00UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3c007c013c003c00UL
        VSRL3, 0x7c00fc003c003c00UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL ]
      []
      [ F16, 0x7fc020007fc02000UL
        F17, 0x7fc040007fc00000UL
        F18, 0x7fc020007fc02000UL
        F19, 0x7fc0400000000000UL
        VSRL16, 0x7fc020007fc02000UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc020007fc02000UL
        VSRL19, 0x7fc0000040000000UL ]
      []
    oracleMem
      ppc64le
      "ee021c90"
      [ F2, 0x7e013c007c000000UL
        F3, 0x3c007e0200003c00UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3c007c013c003c00UL
        VSRL3, 0x7c00fc003c003c00UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL
        VSCR, 0x10000UL
        FPSCR, 0x1UL ]
      []
      [ F16, 0x7fc020007fc02000UL
        F17, 0x7fc040007fc00000UL
        F18, 0x7fc020007fc02000UL
        F19, 0x7fc0400000000000UL
        VSRL16, 0x7fc020007fc02000UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc020007fc02000UL
        VSRL19, 0x7fc0000040000000UL ]
      []
    oracleMem
      ppc64le
      "ee021c90"
      [ F2, 0x7e013c007c000000UL
        F3, 0x3c007e0200003c00UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3c007c013c003c00UL
        VSRL3, 0x7c00fc003c003c00UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL
        FPSCR, 0x2UL ]
      []
      [ F16, 0x7fc020007fc02000UL
        F17, 0x7fc040007fc00000UL
        F18, 0x7fc020007fc02000UL
        F19, 0x7fc0400000000000UL
        VSRL16, 0x7fc020007fc02000UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc020007fc02000UL
        VSRL19, 0x7fc0000040000000UL ]
      []
    oracleMem
      ppc64le
      "ee021c90"
      [ F2, 0x7e013c007c000000UL
        F3, 0x3c007e0200003c00UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3c007c013c003c00UL
        VSRL3, 0x7c00fc003c003c00UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL
        VSCR, 0x10001UL
        FPSCR, 0x3UL ]
      []
      [ F16, 0x7fc020007fc02000UL
        F17, 0x7fc040007fc00000UL
        F18, 0x7fc020007fc02000UL
        F19, 0x7fc0400080000000UL
        VSRL16, 0x7fc020007fc02000UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc020007fc02000UL
        VSRL19, 0x7fc0000040000000UL ]
      []

  /// <summary>
  /// xvf16ger2 AT, xA, xB sets each element to the two products of matching
  /// halves of word i of xA and word j of xB summed and rounded to a single in
  /// the direction FPSCR[RN] names, through FGER2HALF; the accumulating forms
  /// then add or subtract the element (negating the sum first for np and nn)
  /// with a second rounding.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVF16GER2NP beside XVF16GER2``() =
    (* dmxvf16ger2np a4,vs2,vs3, under QEMU: lanes/x-oracle/mma *)
    oracleMem
      ppc64le
      "ee021a90"
      [ F2, 0x3c0040003800be00UL
        F3, 0x40003c0035553555UL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7bff7bff00013555UL
        VSRL3, 0x7bfffbff00014000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0xc04000003f800800UL
        F17, 0x3f800000bfd55800UL
        F18, 0xc83fe580c72a94acUL
        F19, 0xbeaaa004bde371cbUL
        VSRL16, 0x477fe30000000000UL
        VSRL17, 0xc7ffe00040400000UL
        VSRL18, 0x3f800000c7ffdf80UL
        VSRL19, 0x46aa8aaabf2aa000UL ]
      []
    oracleMem
      ppc64le
      "ee021a90"
      [ F2, 0x3c0040003800be00UL
        F3, 0x40003c0035553555UL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7bff7bff00013555UL
        VSRL3, 0x7bfffbff00014000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        FPSCR, 0x1UL ]
      []
      [ F16, 0xc04000003f800800UL
        F17, 0x3f800000bfd55800UL
        F18, 0xc83fe580c72a94acUL
        F19, 0xbeaaa004bde371caUL
        VSRL16, 0x477fe30000000000UL
        VSRL17, 0xc7ffe000403fffffUL
        VSRL18, 0x3f800000c7ffdf80UL
        VSRL19, 0x46aa8aaabf2aa000UL ]
      []
    oracleMem
      ppc64le
      "ee021a90"
      [ F2, 0x3c0040003800be00UL
        F3, 0x40003c0035553555UL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7bff7bff00013555UL
        VSRL3, 0x7bfffbff00014000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x10000UL
        FPSCR, 0x2UL ]
      []
      [ F16, 0xc04000003f800800UL
        F17, 0x3f800000bfd55800UL
        F18, 0xc83fe580c72a94acUL
        F19, 0xbeaaa004bde371cbUL
        VSRL16, 0x477fe300b5000000UL
        VSRL17, 0xc7ffe000403fffffUL
        VSRL18, 0x3f800000c7ffdf81UL
        VSRL19, 0x46aa8aaabf2aa001UL ]
      []
    oracleMem
      ppc64le
      "ee021a90"
      [ F2, 0x3c0040003800be00UL
        F3, 0x40003c0035553555UL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7bff7bff00013555UL
        VSRL3, 0x7bfffbff00014000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x1UL
        FPSCR, 0x3UL ]
      []
      [ F16, 0xc04000003f800800UL
        F17, 0x3f800000bfd55800UL
        F18, 0xc83fe580c72a94acUL
        F19, 0xbeaaa004bde371caUL
        VSRL16, 0x477fe30080000000UL
        VSRL17, 0xc7ffe00040400000UL
        VSRL18, 0x3f800000c7ffdf80UL
        VSRL19, 0x46aa8aabbf2aa000UL ]
      []
    oracleMem
      ppc64le
      "ee021a90"
      [ F2, 0x7e013c007c000000UL
        F3, 0x3c007e0200003c00UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3c007c013c003c00UL
        VSRL3, 0x7c00fc003c003c00UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL ]
      []
      [ F16, 0x7fc020007fc02000UL
        F17, 0x7fc040007fc00000UL
        F18, 0x7fc020007fc02000UL
        F19, 0x7fc0400000000000UL
        VSRL16, 0x7fc020007fc02000UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc020007fc02000UL
        VSRL19, 0x7fc00000c0000000UL ]
      []
    oracleMem
      ppc64le
      "ee021a90"
      [ F2, 0x7e013c007c000000UL
        F3, 0x3c007e0200003c00UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3c007c013c003c00UL
        VSRL3, 0x7c00fc003c003c00UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL
        VSCR, 0x10000UL
        FPSCR, 0x1UL ]
      []
      [ F16, 0x7fc020007fc02000UL
        F17, 0x7fc040007fc00000UL
        F18, 0x7fc020007fc02000UL
        F19, 0x7fc0400000000000UL
        VSRL16, 0x7fc020007fc02000UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc020007fc02000UL
        VSRL19, 0x7fc00000c0000000UL ]
      []
    oracleMem
      ppc64le
      "ee021a90"
      [ F2, 0x7e013c007c000000UL
        F3, 0x3c007e0200003c00UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3c007c013c003c00UL
        VSRL3, 0x7c00fc003c003c00UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL
        FPSCR, 0x2UL ]
      []
      [ F16, 0x7fc020007fc02000UL
        F17, 0x7fc040007fc00000UL
        F18, 0x7fc020007fc02000UL
        F19, 0x7fc0400000000000UL
        VSRL16, 0x7fc020007fc02000UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc020007fc02000UL
        VSRL19, 0x7fc00000c0000000UL ]
      []
    oracleMem
      ppc64le
      "ee021a90"
      [ F2, 0x7e013c007c000000UL
        F3, 0x3c007e0200003c00UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3c007c013c003c00UL
        VSRL3, 0x7c00fc003c003c00UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL
        VSCR, 0x10001UL
        FPSCR, 0x3UL ]
      []
      [ F16, 0x7fc020007fc02000UL
        F17, 0x7fc040007fc00000UL
        F18, 0x7fc020007fc02000UL
        F19, 0x7fc0400080000000UL
        VSRL16, 0x7fc020007fc02000UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc020007fc02000UL
        VSRL19, 0x7fc00000c0000000UL ]
      []

  /// <summary>
  /// xvf16ger2 AT, xA, xB sets each element to the two products of matching
  /// halves of word i of xA and word j of xB summed and rounded to a single in
  /// the direction FPSCR[RN] names, through FGER2HALF; the accumulating forms
  /// then add or subtract the element (negating the sum first for np and nn)
  /// with a second rounding.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVF16GER2NN beside XVF16GER2``() =
    (* dmxvf16ger2nn a4,vs2,vs3, under QEMU: lanes/x-oracle/mma *)
    oracleMem
      ppc64le
      "ee021e90"
      [ F2, 0x3c0040003800be00UL
        F3, 0x40003c0035553555UL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7bff7bff00013555UL
        VSRL3, 0x7bfffbff00014000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0xc0a00000c03ffc00UL
        F17, 0x40155400UL
        F18, 0xc83fea80c72a80acUL
        F19, 0xbeaaa004bde371cbUL
        VSRL16, 0x477fdd00c1000000UL
        VSRL17, 0xc7ffe00040400000UL
        VSRL18, 0xbf800000c7ffe080UL
        VSRL19, 0x46aa8aaabf2aa000UL ]
      []
    oracleMem
      ppc64le
      "ee021e90"
      [ F2, 0x3c0040003800be00UL
        F3, 0x40003c0035553555UL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7bff7bff00013555UL
        VSRL3, 0x7bfffbff00014000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        FPSCR, 0x1UL ]
      []
      [ F16, 0xc0a00000c03ffc00UL
        F17, 0x40155400UL
        F18, 0xc83fea80c72a80acUL
        F19, 0xbeaaa004bde371caUL
        VSRL16, 0x477fdd00c1000000UL
        VSRL17, 0xc7ffe000403fffffUL
        VSRL18, 0xbf800000c7ffe080UL
        VSRL19, 0x46aa8aaabf2aa000UL ]
      []
    oracleMem
      ppc64le
      "ee021e90"
      [ F2, 0x3c0040003800be00UL
        F3, 0x40003c0035553555UL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7bff7bff00013555UL
        VSRL3, 0x7bfffbff00014000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x10000UL
        FPSCR, 0x2UL ]
      []
      [ F16, 0xc0a00000c03ffc00UL
        F17, 0x40155400UL
        F18, 0xc83fea80c72a80acUL
        F19, 0xbeaaa004bde371cbUL
        VSRL16, 0x477fdd00c1000000UL
        VSRL17, 0xc7ffe000403fffffUL
        VSRL18, 0xbf800000c7ffe081UL
        VSRL19, 0x46aa8aaabf2aa001UL ]
      []
    oracleMem
      ppc64le
      "ee021e90"
      [ F2, 0x3c0040003800be00UL
        F3, 0x40003c0035553555UL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7bff7bff00013555UL
        VSRL3, 0x7bfffbff00014000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x1UL
        FPSCR, 0x3UL ]
      []
      [ F16, 0xc0a00000c03ffc00UL
        F17, 0x8000000040155400UL
        F18, 0xc83fea80c72a80acUL
        F19, 0xbeaaa004bde371caUL
        VSRL16, 0x477fdd00c1000000UL
        VSRL17, 0xc7ffe00040400000UL
        VSRL18, 0xbf800000c7ffe080UL
        VSRL19, 0x46aa8aabbf2aa000UL ]
      []
    oracleMem
      ppc64le
      "ee021e90"
      [ F2, 0x7e013c007c000000UL
        F3, 0x3c007e0200003c00UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3c007c013c003c00UL
        VSRL3, 0x7c00fc003c003c00UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL ]
      []
      [ F16, 0x7fc020007fc02000UL
        F17, 0x7fc040007fc00000UL
        F18, 0x7fc020007fc02000UL
        F19, 0x7fc04000c0000000UL
        VSRL16, 0x7fc020007fc02000UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc020007fc02000UL
        VSRL19, 0x7fc00000c0000000UL ]
      []
    oracleMem
      ppc64le
      "ee021e90"
      [ F2, 0x7e013c007c000000UL
        F3, 0x3c007e0200003c00UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3c007c013c003c00UL
        VSRL3, 0x7c00fc003c003c00UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL
        VSCR, 0x10000UL
        FPSCR, 0x1UL ]
      []
      [ F16, 0x7fc020007fc02000UL
        F17, 0x7fc040007fc00000UL
        F18, 0x7fc020007fc02000UL
        F19, 0x7fc04000c0000000UL
        VSRL16, 0x7fc020007fc02000UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc020007fc02000UL
        VSRL19, 0x7fc00000c0000000UL ]
      []
    oracleMem
      ppc64le
      "ee021e90"
      [ F2, 0x7e013c007c000000UL
        F3, 0x3c007e0200003c00UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3c007c013c003c00UL
        VSRL3, 0x7c00fc003c003c00UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL
        FPSCR, 0x2UL ]
      []
      [ F16, 0x7fc020007fc02000UL
        F17, 0x7fc040007fc00000UL
        F18, 0x7fc020007fc02000UL
        F19, 0x7fc04000c0000000UL
        VSRL16, 0x7fc020007fc02000UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc020007fc02000UL
        VSRL19, 0x7fc00000c0000000UL ]
      []
    oracleMem
      ppc64le
      "ee021e90"
      [ F2, 0x7e013c007c000000UL
        F3, 0x3c007e0200003c00UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3c007c013c003c00UL
        VSRL3, 0x7c00fc003c003c00UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL
        VSCR, 0x10001UL
        FPSCR, 0x3UL ]
      []
      [ F16, 0x7fc020007fc02000UL
        F17, 0x7fc040007fc00000UL
        F18, 0x7fc020007fc02000UL
        F19, 0x7fc04000c0000000UL
        VSRL16, 0x7fc020007fc02000UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc020007fc02000UL
        VSRL19, 0x7fc00000c0000000UL ]
      []

  /// <summary>
  /// xvbf16ger2 AT, xA, xB is xvf16ger2 over bfloat16 halves, through
  /// FGER2BF16: the sum rounded to a single's significand with no bound on the
  /// exponent, then into a single; products of 2 to the 126 by 2 to the 126 and
  /// its negation, past the single range, cancel exactly.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVBF16GER2 sums bfloat16 products``() =
    (* dmxvbf16ger2 a4,vs2,vs3, under QEMU: lanes/x-oracle/mma *)
    oracleMem
      ppc64le
      "ee021998"
      [ F2, 0x3f8040003f00bfc0UL
        F3, 0x40003f803eab3eabUL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7e807e8000803eabUL
        VSRL3, 0x7e80fe8000804000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x408000003f804000UL
        F17, 0xbf000000beab0000UL
        F18, 0x7f4000007e2b0000UL
        F19, 0x3eab00003de47200UL
        VSRL16, 0xfe80000040800000UL
        VSRL17, 0x7f000000c0400000UL
        VSRL18, 0x7f000000UL
        VSRL19, 0xfdab00003f2b0000UL ]
      []
    oracleMem
      ppc64le
      "ee021998"
      [ F2, 0x3f8040003f00bfc0UL
        F3, 0x40003f803eab3eabUL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7e807e8000803eabUL
        VSRL3, 0x7e80fe8000804000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        FPSCR, 0x1UL ]
      []
      [ F16, 0x408000003f804000UL
        F17, 0xbf000000beab0000UL
        F18, 0x7f4000007e2b0000UL
        F19, 0x3eab00003de47200UL
        VSRL16, 0xfe80000040800000UL
        VSRL17, 0x7f000000c03fffffUL
        VSRL18, 0x7f000000UL
        VSRL19, 0xfdaaffff3f2b0000UL ]
      []
    oracleMem
      ppc64le
      "ee021998"
      [ F2, 0x3f8040003f00bfc0UL
        F3, 0x40003f803eab3eabUL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7e807e8000803eabUL
        VSRL3, 0x7e80fe8000804000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x10000UL
        FPSCR, 0x2UL ]
      []
      [ F16, 0x408000003f804000UL
        F17, 0xbf000000beab0000UL
        F18, 0x7f4000007e2b0000UL
        F19, 0x3eab00013de47201UL
        VSRL16, 0xfe80000040800001UL
        VSRL17, 0x7f000000c03fffffUL
        VSRL18, 0x7f000001UL
        VSRL19, 0xfdaaffff3f2b0001UL ]
      []
    oracleMem
      ppc64le
      "ee021998"
      [ F2, 0x3f8040003f00bfc0UL
        F3, 0x40003f803eab3eabUL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7e807e8000803eabUL
        VSRL3, 0x7e80fe8000804000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x1UL
        FPSCR, 0x3UL ]
      []
      [ F16, 0x408000003f804000UL
        F17, 0xbf000000beab0000UL
        F18, 0x7f4000007e2b0000UL
        F19, 0x3eab00003de47200UL
        VSRL16, 0xfe80000040800000UL
        VSRL17, 0x7f000000c0400000UL
        VSRL18, 0x800000007f000000UL
        VSRL19, 0xfdab00003f2b0000UL ]
      []
    oracleMem
      ppc64le
      "ee021998"
      [ F2, 0x7fc13f807f800000UL
        F3, 0x3f807fc200003f80UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3f807f813f803f80UL
        VSRL3, 0x7f80ff803f803f80UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL ]
      []
      [ F16, 0x7fc100007fc10000UL
        F17, 0x7fc200007fc00000UL
        F18, 0x7fc100007fc10000UL
        F19, 0x7fc200003f800000UL
        VSRL16, 0x7fc100007fc10000UL
        VSRL17, 0x7fc000007f800000UL
        VSRL18, 0x7fc100007fc10000UL
        VSRL19, 0x7fc0000040000000UL ]
      []
    oracleMem
      ppc64le
      "ee021998"
      [ F2, 0x7fc13f807f800000UL
        F3, 0x3f807fc200003f80UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3f807f813f803f80UL
        VSRL3, 0x7f80ff803f803f80UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL
        VSCR, 0x10000UL
        FPSCR, 0x1UL ]
      []
      [ F16, 0x7fc100007fc10000UL
        F17, 0x7fc200007fc00000UL
        F18, 0x7fc100007fc10000UL
        F19, 0x7fc200003f800000UL
        VSRL16, 0x7fc100007fc10000UL
        VSRL17, 0x7fc000007f800000UL
        VSRL18, 0x7fc100007fc10000UL
        VSRL19, 0x7fc0000040000000UL ]
      []
    oracleMem
      ppc64le
      "ee021998"
      [ F2, 0x7fc13f807f800000UL
        F3, 0x3f807fc200003f80UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3f807f813f803f80UL
        VSRL3, 0x7f80ff803f803f80UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL
        FPSCR, 0x2UL ]
      []
      [ F16, 0x7fc100007fc10000UL
        F17, 0x7fc200007fc00000UL
        F18, 0x7fc100007fc10000UL
        F19, 0x7fc200003f800000UL
        VSRL16, 0x7fc100007fc10000UL
        VSRL17, 0x7fc000007f800000UL
        VSRL18, 0x7fc100007fc10000UL
        VSRL19, 0x7fc0000040000000UL ]
      []
    oracleMem
      ppc64le
      "ee021998"
      [ F2, 0x7fc13f807f800000UL
        F3, 0x3f807fc200003f80UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3f807f813f803f80UL
        VSRL3, 0x7f80ff803f803f80UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL
        VSCR, 0x10001UL
        FPSCR, 0x3UL ]
      []
      [ F16, 0x7fc100007fc10000UL
        F17, 0x7fc200007fc00000UL
        F18, 0x7fc100007fc10000UL
        F19, 0x7fc200003f800000UL
        VSRL16, 0x7fc100007fc10000UL
        VSRL17, 0x7fc000007f800000UL
        VSRL18, 0x7fc100007fc10000UL
        VSRL19, 0x7fc0000040000000UL ]
      []

  /// <summary>
  /// xvbf16ger2 AT, xA, xB is xvf16ger2 over bfloat16 halves, through
  /// FGER2BF16: the sum rounded to a single's significand with no bound on the
  /// exponent, then into a single; products of 2 to the 126 by 2 to the 126 and
  /// its negation, past the single range, cancel exactly.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVBF16GER2PP beside XVBF16GER2``() =
    (* dmxvbf16ger2pp a4,vs2,vs3, under QEMU: lanes/x-oracle/mma *)
    oracleMem
      ppc64le
      "ee021990"
      [ F2, 0x3f8040003f00bfc0UL
        F3, 0x40003f803eab3eabUL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7e807e8000803eabUL
        VSRL3, 0x7e80fe8000804000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x40a0000040402000UL
        F17, 0xc0156000UL
        F18, 0x7f4000007e2b0000UL
        F19, 0x3eab00003de47200UL
        VSRL16, 0xfe80000041000000UL
        VSRL17, 0x7f000000c0400000UL
        VSRL18, 0x3f8000007f000000UL
        VSRL19, 0xfdab00003f2b0000UL ]
      []
    oracleMem
      ppc64le
      "ee021990"
      [ F2, 0x3f8040003f00bfc0UL
        F3, 0x40003f803eab3eabUL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7e807e8000803eabUL
        VSRL3, 0x7e80fe8000804000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        FPSCR, 0x1UL ]
      []
      [ F16, 0x40a0000040402000UL
        F17, 0xc0156000UL
        F18, 0x7f4000007e2affffUL
        F19, 0x3eab00003de47200UL
        VSRL16, 0xfe7fffff41000000UL
        VSRL17, 0x7f000000c03fffffUL
        VSRL18, 0x3f8000007f000000UL
        VSRL19, 0xfdaaffff3f2b0000UL ]
      []
    oracleMem
      ppc64le
      "ee021990"
      [ F2, 0x3f8040003f00bfc0UL
        F3, 0x40003f803eab3eabUL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7e807e8000803eabUL
        VSRL3, 0x7e80fe8000804000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x10000UL
        FPSCR, 0x2UL ]
      []
      [ F16, 0x40a0000040402000UL
        F17, 0xc0156000UL
        F18, 0x7f4000017e2b0000UL
        F19, 0x3eab00013de47201UL
        VSRL16, 0xfe7fffff41000001UL
        VSRL17, 0x7f000000c03fffffUL
        VSRL18, 0x3f8000007f000002UL
        VSRL19, 0xfdaaffff3f2b0001UL ]
      []
    oracleMem
      ppc64le
      "ee021990"
      [ F2, 0x3f8040003f00bfc0UL
        F3, 0x40003f803eab3eabUL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7e807e8000803eabUL
        VSRL3, 0x7e80fe8000804000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x1UL
        FPSCR, 0x3UL ]
      []
      [ F16, 0x40a0000040402000UL
        F17, 0x80000000c0156000UL
        F18, 0x7f4000007e2affffUL
        F19, 0x3eab00003de47200UL
        VSRL16, 0xfe80000041000000UL
        VSRL17, 0x7f000000c0400000UL
        VSRL18, 0x3f8000007f000000UL
        VSRL19, 0xfdab00003f2b0000UL ]
      []
    oracleMem
      ppc64le
      "ee021990"
      [ F2, 0x7fc13f807f800000UL
        F3, 0x3f807fc200003f80UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3f807f813f803f80UL
        VSRL3, 0x7f80ff803f803f80UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL ]
      []
      [ F16, 0x7fc100007fc10000UL
        F17, 0x7fc200007fc00000UL
        F18, 0x7fc100007fc10000UL
        F19, 0x7fc2000040000000UL
        VSRL16, 0x7fc100007fc10000UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc100007fc10000UL
        VSRL19, 0x7fc0000040000000UL ]
      []
    oracleMem
      ppc64le
      "ee021990"
      [ F2, 0x7fc13f807f800000UL
        F3, 0x3f807fc200003f80UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3f807f813f803f80UL
        VSRL3, 0x7f80ff803f803f80UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL
        VSCR, 0x10000UL
        FPSCR, 0x1UL ]
      []
      [ F16, 0x7fc100007fc10000UL
        F17, 0x7fc200007fc00000UL
        F18, 0x7fc100007fc10000UL
        F19, 0x7fc2000040000000UL
        VSRL16, 0x7fc100007fc10000UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc100007fc10000UL
        VSRL19, 0x7fc0000040000000UL ]
      []
    oracleMem
      ppc64le
      "ee021990"
      [ F2, 0x7fc13f807f800000UL
        F3, 0x3f807fc200003f80UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3f807f813f803f80UL
        VSRL3, 0x7f80ff803f803f80UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL
        FPSCR, 0x2UL ]
      []
      [ F16, 0x7fc100007fc10000UL
        F17, 0x7fc200007fc00000UL
        F18, 0x7fc100007fc10000UL
        F19, 0x7fc2000040000000UL
        VSRL16, 0x7fc100007fc10000UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc100007fc10000UL
        VSRL19, 0x7fc0000040000000UL ]
      []
    oracleMem
      ppc64le
      "ee021990"
      [ F2, 0x7fc13f807f800000UL
        F3, 0x3f807fc200003f80UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3f807f813f803f80UL
        VSRL3, 0x7f80ff803f803f80UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL
        VSCR, 0x10001UL
        FPSCR, 0x3UL ]
      []
      [ F16, 0x7fc100007fc10000UL
        F17, 0x7fc200007fc00000UL
        F18, 0x7fc100007fc10000UL
        F19, 0x7fc2000040000000UL
        VSRL16, 0x7fc100007fc10000UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc100007fc10000UL
        VSRL19, 0x7fc0000040000000UL ]
      []

  /// <summary>
  /// xvbf16ger2 AT, xA, xB is xvf16ger2 over bfloat16 halves, through
  /// FGER2BF16: the sum rounded to a single's significand with no bound on the
  /// exponent, then into a single; products of 2 to the 126 by 2 to the 126 and
  /// its negation, past the single range, cancel exactly.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVBF16GER2PN beside XVBF16GER2``() =
    (* dmxvbf16ger2pn a4,vs2,vs3, under QEMU: lanes/x-oracle/mma *)
    oracleMem
      ppc64le
      "ee021d90"
      [ F2, 0x3f8040003f00bfc0UL
        F3, 0x40003f803eab3eabUL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7e807e8000803eabUL
        VSRL3, 0x7e80fe8000804000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x40400000bf7f8000UL
        F17, 0xbf8000003fd54000UL
        F18, 0x7f4000007e2b0000UL
        F19, 0x3eab00003de47200UL
        VSRL16, 0xfe80000000000000UL
        VSRL17, 0x7f000000c0400000UL
        VSRL18, 0xbf8000007f000000UL
        VSRL19, 0xfdab00003f2b0000UL ]
      []
    oracleMem
      ppc64le
      "ee021d90"
      [ F2, 0x3f8040003f00bfc0UL
        F3, 0x40003f803eab3eabUL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7e807e8000803eabUL
        VSRL3, 0x7e80fe8000804000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        FPSCR, 0x1UL ]
      []
      [ F16, 0x40400000bf7f8000UL
        F17, 0xbf8000003fd54000UL
        F18, 0x7f3fffff7e2b0000UL
        F19, 0x3eab00003de47200UL
        VSRL16, 0xfe80000000000000UL
        VSRL17, 0x7f000000c03fffffUL
        VSRL18, 0xbf8000007effffffUL
        VSRL19, 0xfdaaffff3f2b0000UL ]
      []
    oracleMem
      ppc64le
      "ee021d90"
      [ F2, 0x3f8040003f00bfc0UL
        F3, 0x40003f803eab3eabUL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7e807e8000803eabUL
        VSRL3, 0x7e80fe8000804000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x10000UL
        FPSCR, 0x2UL ]
      []
      [ F16, 0x40400000bf7f8000UL
        F17, 0xbf8000003fd54000UL
        F18, 0x7f4000007e2b0001UL
        F19, 0x3eab00013de47201UL
        VSRL16, 0xfe80000035000000UL
        VSRL17, 0x7f000000c03fffffUL
        VSRL18, 0xbf8000007f000001UL
        VSRL19, 0xfdaaffff3f2b0001UL ]
      []
    oracleMem
      ppc64le
      "ee021d90"
      [ F2, 0x3f8040003f00bfc0UL
        F3, 0x40003f803eab3eabUL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7e807e8000803eabUL
        VSRL3, 0x7e80fe8000804000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x1UL
        FPSCR, 0x3UL ]
      []
      [ F16, 0x40400000bf7f8000UL
        F17, 0xbf8000003fd54000UL
        F18, 0x7f3fffff7e2b0000UL
        F19, 0x3eab00003de47200UL
        VSRL16, 0xfe80000180000000UL
        VSRL17, 0x7f000000c0400000UL
        VSRL18, 0xbf8000007effffffUL
        VSRL19, 0xfdab00003f2b0000UL ]
      []
    oracleMem
      ppc64le
      "ee021d90"
      [ F2, 0x7fc13f807f800000UL
        F3, 0x3f807fc200003f80UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3f807f813f803f80UL
        VSRL3, 0x7f80ff803f803f80UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL ]
      []
      [ F16, 0x7fc100007fc10000UL
        F17, 0x7fc200007fc00000UL
        F18, 0x7fc100007fc10000UL
        F19, 0x7fc2000000000000UL
        VSRL16, 0x7fc100007fc10000UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc100007fc10000UL
        VSRL19, 0x7fc0000040000000UL ]
      []
    oracleMem
      ppc64le
      "ee021d90"
      [ F2, 0x7fc13f807f800000UL
        F3, 0x3f807fc200003f80UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3f807f813f803f80UL
        VSRL3, 0x7f80ff803f803f80UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL
        VSCR, 0x10000UL
        FPSCR, 0x1UL ]
      []
      [ F16, 0x7fc100007fc10000UL
        F17, 0x7fc200007fc00000UL
        F18, 0x7fc100007fc10000UL
        F19, 0x7fc2000000000000UL
        VSRL16, 0x7fc100007fc10000UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc100007fc10000UL
        VSRL19, 0x7fc0000040000000UL ]
      []
    oracleMem
      ppc64le
      "ee021d90"
      [ F2, 0x7fc13f807f800000UL
        F3, 0x3f807fc200003f80UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3f807f813f803f80UL
        VSRL3, 0x7f80ff803f803f80UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL
        FPSCR, 0x2UL ]
      []
      [ F16, 0x7fc100007fc10000UL
        F17, 0x7fc200007fc00000UL
        F18, 0x7fc100007fc10000UL
        F19, 0x7fc2000000000000UL
        VSRL16, 0x7fc100007fc10000UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc100007fc10000UL
        VSRL19, 0x7fc0000040000000UL ]
      []
    oracleMem
      ppc64le
      "ee021d90"
      [ F2, 0x7fc13f807f800000UL
        F3, 0x3f807fc200003f80UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3f807f813f803f80UL
        VSRL3, 0x7f80ff803f803f80UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL
        VSCR, 0x10001UL
        FPSCR, 0x3UL ]
      []
      [ F16, 0x7fc100007fc10000UL
        F17, 0x7fc200007fc00000UL
        F18, 0x7fc100007fc10000UL
        F19, 0x7fc2000080000000UL
        VSRL16, 0x7fc100007fc10000UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc100007fc10000UL
        VSRL19, 0x7fc0000040000000UL ]
      []

  /// <summary>
  /// xvbf16ger2 AT, xA, xB is xvf16ger2 over bfloat16 halves, through
  /// FGER2BF16: the sum rounded to a single's significand with no bound on the
  /// exponent, then into a single; products of 2 to the 126 by 2 to the 126 and
  /// its negation, past the single range, cancel exactly.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVBF16GER2NP beside XVBF16GER2``() =
    (* dmxvbf16ger2np a4,vs2,vs3, under QEMU: lanes/x-oracle/mma *)
    oracleMem
      ppc64le
      "ee021b90"
      [ F2, 0x3f8040003f00bfc0UL
        F3, 0x40003f803eab3eabUL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7e807e8000803eabUL
        VSRL3, 0x7e80fe8000804000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0xc04000003f7f8000UL
        F17, 0x3f800000bfd54000UL
        F18, 0xff400000fe2b0000UL
        F19, 0xbeab0000bde47200UL
        VSRL16, 0x7e80000000000000UL
        VSRL17, 0xff00000040400000UL
        VSRL18, 0x3f800000ff000000UL
        VSRL19, 0x7dab0000bf2b0000UL ]
      []
    oracleMem
      ppc64le
      "ee021b90"
      [ F2, 0x3f8040003f00bfc0UL
        F3, 0x40003f803eab3eabUL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7e807e8000803eabUL
        VSRL3, 0x7e80fe8000804000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        FPSCR, 0x1UL ]
      []
      [ F16, 0xc04000003f7f8000UL
        F17, 0x3f800000bfd54000UL
        F18, 0xff3ffffffe2b0000UL
        F19, 0xbeab0000bde47200UL
        VSRL16, 0x7e80000000000000UL
        VSRL17, 0xff000000403fffffUL
        VSRL18, 0x3f800000feffffffUL
        VSRL19, 0x7daaffffbf2b0000UL ]
      []
    oracleMem
      ppc64le
      "ee021b90"
      [ F2, 0x3f8040003f00bfc0UL
        F3, 0x40003f803eab3eabUL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7e807e8000803eabUL
        VSRL3, 0x7e80fe8000804000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x10000UL
        FPSCR, 0x2UL ]
      []
      [ F16, 0xc04000003f7f8000UL
        F17, 0x3f800000bfd54000UL
        F18, 0xff3ffffffe2b0000UL
        F19, 0xbeab0001bde47201UL
        VSRL16, 0x7e800001b5000000UL
        VSRL17, 0xff000000403fffffUL
        VSRL18, 0x3f800000ff000000UL
        VSRL19, 0x7daaffffbf2b0001UL ]
      []
    oracleMem
      ppc64le
      "ee021b90"
      [ F2, 0x3f8040003f00bfc0UL
        F3, 0x40003f803eab3eabUL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7e807e8000803eabUL
        VSRL3, 0x7e80fe8000804000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x1UL
        FPSCR, 0x3UL ]
      []
      [ F16, 0xc04000003f7f8000UL
        F17, 0x3f800000bfd54000UL
        F18, 0xff400000fe2b0001UL
        F19, 0xbeab0000bde47200UL
        VSRL16, 0x7e80000080000000UL
        VSRL17, 0xff00000040400000UL
        VSRL18, 0x3f800000ff000000UL
        VSRL19, 0x7dab0000bf2b0000UL ]
      []
    oracleMem
      ppc64le
      "ee021b90"
      [ F2, 0x7fc13f807f800000UL
        F3, 0x3f807fc200003f80UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3f807f813f803f80UL
        VSRL3, 0x7f80ff803f803f80UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL ]
      []
      [ F16, 0x7fc100007fc10000UL
        F17, 0x7fc200007fc00000UL
        F18, 0x7fc100007fc10000UL
        F19, 0x7fc2000000000000UL
        VSRL16, 0x7fc100007fc10000UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc100007fc10000UL
        VSRL19, 0x7fc00000c0000000UL ]
      []
    oracleMem
      ppc64le
      "ee021b90"
      [ F2, 0x7fc13f807f800000UL
        F3, 0x3f807fc200003f80UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3f807f813f803f80UL
        VSRL3, 0x7f80ff803f803f80UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL
        VSCR, 0x10000UL
        FPSCR, 0x1UL ]
      []
      [ F16, 0x7fc100007fc10000UL
        F17, 0x7fc200007fc00000UL
        F18, 0x7fc100007fc10000UL
        F19, 0x7fc2000000000000UL
        VSRL16, 0x7fc100007fc10000UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc100007fc10000UL
        VSRL19, 0x7fc00000c0000000UL ]
      []
    oracleMem
      ppc64le
      "ee021b90"
      [ F2, 0x7fc13f807f800000UL
        F3, 0x3f807fc200003f80UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3f807f813f803f80UL
        VSRL3, 0x7f80ff803f803f80UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL
        FPSCR, 0x2UL ]
      []
      [ F16, 0x7fc100007fc10000UL
        F17, 0x7fc200007fc00000UL
        F18, 0x7fc100007fc10000UL
        F19, 0x7fc2000000000000UL
        VSRL16, 0x7fc100007fc10000UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc100007fc10000UL
        VSRL19, 0x7fc00000c0000000UL ]
      []
    oracleMem
      ppc64le
      "ee021b90"
      [ F2, 0x7fc13f807f800000UL
        F3, 0x3f807fc200003f80UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3f807f813f803f80UL
        VSRL3, 0x7f80ff803f803f80UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL
        VSCR, 0x10001UL
        FPSCR, 0x3UL ]
      []
      [ F16, 0x7fc100007fc10000UL
        F17, 0x7fc200007fc00000UL
        F18, 0x7fc100007fc10000UL
        F19, 0x7fc2000080000000UL
        VSRL16, 0x7fc100007fc10000UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc100007fc10000UL
        VSRL19, 0x7fc00000c0000000UL ]
      []

  /// <summary>
  /// xvbf16ger2 AT, xA, xB is xvf16ger2 over bfloat16 halves, through
  /// FGER2BF16: the sum rounded to a single's significand with no bound on the
  /// exponent, then into a single; products of 2 to the 126 by 2 to the 126 and
  /// its negation, past the single range, cancel exactly.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVBF16GER2NN beside XVBF16GER2``() =
    (* dmxvbf16ger2nn a4,vs2,vs3, under QEMU: lanes/x-oracle/mma *)
    oracleMem
      ppc64le
      "ee021f90"
      [ F2, 0x3f8040003f00bfc0UL
        F3, 0x40003f803eab3eabUL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7e807e8000803eabUL
        VSRL3, 0x7e80fe8000804000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0xc0a00000c0402000UL
        F17, 0x40156000UL
        F18, 0xff400000fe2b0000UL
        F19, 0xbeab0000bde47200UL
        VSRL16, 0x7e800000c1000000UL
        VSRL17, 0xff00000040400000UL
        VSRL18, 0xbf800000ff000000UL
        VSRL19, 0x7dab0000bf2b0000UL ]
      []
    oracleMem
      ppc64le
      "ee021f90"
      [ F2, 0x3f8040003f00bfc0UL
        F3, 0x40003f803eab3eabUL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7e807e8000803eabUL
        VSRL3, 0x7e80fe8000804000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        FPSCR, 0x1UL ]
      []
      [ F16, 0xc0a00000c0402000UL
        F17, 0x40156000UL
        F18, 0xff400000fe2affffUL
        F19, 0xbeab0000bde47200UL
        VSRL16, 0x7e7fffffc1000000UL
        VSRL17, 0xff000000403fffffUL
        VSRL18, 0xbf800000ff000000UL
        VSRL19, 0x7daaffffbf2b0000UL ]
      []
    oracleMem
      ppc64le
      "ee021f90"
      [ F2, 0x3f8040003f00bfc0UL
        F3, 0x40003f803eab3eabUL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7e807e8000803eabUL
        VSRL3, 0x7e80fe8000804000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x10000UL
        FPSCR, 0x2UL ]
      []
      [ F16, 0xc0a00000c0402000UL
        F17, 0x40156000UL
        F18, 0xff400000fe2affffUL
        F19, 0xbeab0001bde47201UL
        VSRL16, 0x7e800000c1000000UL
        VSRL17, 0xff000000403fffffUL
        VSRL18, 0xbf800000ff000001UL
        VSRL19, 0x7daaffffbf2b0001UL ]
      []
    oracleMem
      ppc64le
      "ee021f90"
      [ F2, 0x3f8040003f00bfc0UL
        F3, 0x40003f803eab3eabUL
        F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL2, 0x7e807e8000803eabUL
        VSRL3, 0x7e80fe8000804000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x1UL
        FPSCR, 0x3UL ]
      []
      [ F16, 0xc0a00000c0402000UL
        F17, 0x8000000040156000UL
        F18, 0xff400001fe2b0000UL
        F19, 0xbeab0000bde47200UL
        VSRL16, 0x7e7fffffc1000000UL
        VSRL17, 0xff00000040400000UL
        VSRL18, 0xbf800000ff000001UL
        VSRL19, 0x7dab0000bf2b0000UL ]
      []
    oracleMem
      ppc64le
      "ee021f90"
      [ F2, 0x7fc13f807f800000UL
        F3, 0x3f807fc200003f80UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3f807f813f803f80UL
        VSRL3, 0x7f80ff803f803f80UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL ]
      []
      [ F16, 0x7fc100007fc10000UL
        F17, 0x7fc200007fc00000UL
        F18, 0x7fc100007fc10000UL
        F19, 0x7fc20000c0000000UL
        VSRL16, 0x7fc100007fc10000UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc100007fc10000UL
        VSRL19, 0x7fc00000c0000000UL ]
      []
    oracleMem
      ppc64le
      "ee021f90"
      [ F2, 0x7fc13f807f800000UL
        F3, 0x3f807fc200003f80UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3f807f813f803f80UL
        VSRL3, 0x7f80ff803f803f80UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL
        VSCR, 0x10000UL
        FPSCR, 0x1UL ]
      []
      [ F16, 0x7fc100007fc10000UL
        F17, 0x7fc200007fc00000UL
        F18, 0x7fc100007fc10000UL
        F19, 0x7fc20000c0000000UL
        VSRL16, 0x7fc100007fc10000UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc100007fc10000UL
        VSRL19, 0x7fc00000c0000000UL ]
      []
    oracleMem
      ppc64le
      "ee021f90"
      [ F2, 0x7fc13f807f800000UL
        F3, 0x3f807fc200003f80UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3f807f813f803f80UL
        VSRL3, 0x7f80ff803f803f80UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL
        FPSCR, 0x2UL ]
      []
      [ F16, 0x7fc100007fc10000UL
        F17, 0x7fc200007fc00000UL
        F18, 0x7fc100007fc10000UL
        F19, 0x7fc20000c0000000UL
        VSRL16, 0x7fc100007fc10000UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc100007fc10000UL
        VSRL19, 0x7fc00000c0000000UL ]
      []
    oracleMem
      ppc64le
      "ee021f90"
      [ F2, 0x7fc13f807f800000UL
        F3, 0x3f807fc200003f80UL
        F16, 0xff8000003f800000UL
        F17, 0x7f8000007f800000UL
        F18, 0x7fc0000200000000UL
        F19, 0x13f800000UL
        VSRL2, 0x3f807f813f803f80UL
        VSRL3, 0x7f80ff803f803f80UL
        VSRL16, 0x7fa0000040000000UL
        VSRL17, 0xff8000007fc00001UL
        VSRL18, 0x800000003f800000UL
        VSCR, 0x10001UL
        FPSCR, 0x3UL ]
      []
      [ F16, 0x7fc100007fc10000UL
        F17, 0x7fc200007fc00000UL
        F18, 0x7fc100007fc10000UL
        F19, 0x7fc20000c0000000UL
        VSRL16, 0x7fc100007fc10000UL
        VSRL17, 0x7fc000007fc00001UL
        VSRL18, 0x7fc100007fc10000UL
        VSRL19, 0x7fc00000c0000000UL ]
      []

  /// <summary>
  /// xvi4ger8, xvi8ger4 and xvi16ger2 set each element to the sum of the
  /// products of matching signed nibbles, signed bytes of xA by unsigned bytes
  /// of xB, or signed halfwords, plus the element for the pp forms, modulo two
  /// to the 32.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVI8GER4 sums integer products``() =
    (* dmxvi4ger8 a4,vs2,vs3, under QEMU: lanes/x-oracle/mma *)
    oracleMem
      ppc64le
      "ee021918"
      [ F2, 0x102030480808080UL
        F3, 0x5060708ffffffffUL
        F16, 0x7fffffff80000000UL
        F17, 0x7ffffff080000010UL
        F19, 0x40000000c0000000UL
        VSRL2, 0x7f7f7f7ffffefdfcUL
        VSRL3, 0x808080807f7f7f7fUL
        VSRL16, 0x1ffffffffUL
        VSRL17, 0x12345678UL
        VSRL19, 0x7fffffff80000000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x6fffffff6UL
        F17, 0x20UL
        F18, 0xfffffff6ffffffe8UL
        F19, 0xfffffffa0000000eUL
        VSRL16, 0xfffffff6UL
        VSRL17, 0x100ffffff20UL
        VSRL18, 0xffffff20000000c8UL
        VSRL19, 0x20ffffffeeUL ]
      []
    oracleMem
      ppc64le
      "ee021918"
      [ F2, 0x800080007fff7fffUL
        F3, 0x8000800080008000UL
        F16, 0x7fffffff80000000UL
        F17, 0x7ffffff080000010UL
        F19, 0x40000000c0000000UL
        VSRL2, 0x12345678ffff0001UL
        VSRL3, 0x7fff7fff00020003UL
        VSRL16, 0x1ffffffffUL
        VSRL17, 0x12345678UL
        VSRL19, 0x7fffffff80000000UL ]
      []
      [ F16, 0x8000000080UL
        F17, 0xffffff90ffffff90UL
        F18, 0xffffffd0ffffffd0UL
        F19, 0x800000008UL
        VSRL16, 0xffffff9000000000UL
        VSRL17, 0x68fffffffbUL
        VSRL18, 0x1cfffffff0UL
        VSRL19, 0xfffffffb00000001UL ]
      []
    oracleMem
      ppc64le
      "ee021918"
      [ F2, 0x8888888877777777UL
        F3, 0x8888888888888888UL
        F16, 0x7fffffff80000000UL
        F17, 0x7ffffff080000010UL
        F19, 0x40000000c0000000UL
        VSRL2, 0x12345678fedcba98UL
        VSRL3, 0x777777770f0f0f0fUL
        VSRL16, 0x1ffffffffUL
        VSRL17, 0x12345678UL
        VSRL19, 0x7fffffff80000000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x20000000200UL
        F17, 0xfffffe40fffffe40UL
        F18, 0xffffff60ffffff60UL
        F19, 0x12000000120UL
        VSRL16, 0xfffffe4000000020UL
        VSRL17, 0x188ffffffe4UL
        VSRL18, 0x8cfffffffcUL
        VSRL19, 0xffffff0400000014UL ]
      []

  /// <summary>
  /// xvi4ger8, xvi8ger4 and xvi16ger2 set each element to the sum of the
  /// products of matching signed nibbles, signed bytes of xA by unsigned bytes
  /// of xB, or signed halfwords, plus the element for the pp forms, modulo two
  /// to the 32.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVI4GER8PP beside XVI4GER8``() =
    (* dmxvi4ger8pp a4,vs2,vs3, under QEMU: lanes/x-oracle/mma *)
    oracleMem
      ppc64le
      "ee021910"
      [ F2, 0x102030480808080UL
        F3, 0x5060708ffffffffUL
        F16, 0x7fffffff80000000UL
        F17, 0x7ffffff080000010UL
        F19, 0x40000000c0000000UL
        VSRL2, 0x7f7f7f7ffffefdfcUL
        VSRL3, 0x808080807f7f7f7fUL
        VSRL16, 0x1ffffffffUL
        VSRL17, 0x12345678UL
        VSRL19, 0x7fffffff80000000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x800000057ffffff6UL
        F17, 0x7ffffff080000030UL
        F18, 0xfffffff6ffffffe8UL
        F19, 0x3ffffffac000000eUL
        VSRL16, 0x1fffffff5UL
        VSRL17, 0x10012345598UL
        VSRL18, 0xffffff20000000c8UL
        VSRL19, 0x8000001f7fffffeeUL ]
      []
    oracleMem
      ppc64le
      "ee021910"
      [ F2, 0x800080007fff7fffUL
        F3, 0x8000800080008000UL
        F16, 0x7fffffff80000000UL
        F17, 0x7ffffff080000010UL
        F19, 0x40000000c0000000UL
        VSRL2, 0x12345678ffff0001UL
        VSRL3, 0x7fff7fff00020003UL
        VSRL16, 0x1ffffffffUL
        VSRL17, 0x12345678UL
        VSRL19, 0x7fffffff80000000UL ]
      []
      [ F16, 0x8000007f80000080UL
        F17, 0x7fffff807fffffa0UL
        F18, 0xffffffd0ffffffd0UL
        F19, 0x40000008c0000008UL
        VSRL16, 0xffffff91ffffffffUL
        VSRL17, 0x6812345673UL
        VSRL18, 0x1cfffffff0UL
        VSRL19, 0x7ffffffa80000001UL ]
      []
    oracleMem
      ppc64le
      "ee021910"
      [ F2, 0x8888888877777777UL
        F3, 0x8888888888888888UL
        F16, 0x7fffffff80000000UL
        F17, 0x7ffffff080000010UL
        F19, 0x40000000c0000000UL
        VSRL2, 0x12345678fedcba98UL
        VSRL3, 0x777777770f0f0f0fUL
        VSRL16, 0x1ffffffffUL
        VSRL17, 0x12345678UL
        VSRL19, 0x7fffffff80000000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x800001ff80000200UL
        F17, 0x7ffffe307ffffe50UL
        F18, 0xffffff60ffffff60UL
        F19, 0x40000120c0000120UL
        VSRL16, 0xfffffe410000001fUL
        VSRL17, 0x1881234565cUL
        VSRL18, 0x8cfffffffcUL
        VSRL19, 0x7fffff0380000014UL ]
      []

  /// <summary>
  /// xvi4ger8, xvi8ger4 and xvi16ger2 set each element to the sum of the
  /// products of matching signed nibbles, signed bytes of xA by unsigned bytes
  /// of xB, or signed halfwords, plus the element for the pp forms, modulo two
  /// to the 32.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVI8GER4 beside XVI4GER8``() =
    (* dmxvi8ger4 a4,vs2,vs3, under QEMU: lanes/x-oracle/mma *)
    oracleMem
      ppc64le
      "ee021818"
      [ F2, 0x102030480808080UL
        F3, 0x5060708ffffffffUL
        F16, 0x7fffffff80000000UL
        F17, 0x7ffffff080000010UL
        F19, 0x40000000c0000000UL
        VSRL2, 0x7f7f7f7ffffefdfcUL
        VSRL3, 0x808080807f7f7f7fUL
        VSRL16, 0x1ffffffffUL
        VSRL17, 0x12345678UL
        VSRL19, 0x7fffffff80000000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x46000009f6UL
        F17, 0xfffff300fffe0200UL
        F18, 0xce60001fa04UL
        F19, 0xffffffbafffff60aUL
        VSRL16, 0x500000004f6UL
        VSRL17, 0xffff0000ffff0200UL
        VSRL18, 0xfe000000fc04UL
        VSRL19, 0xfffffb00fffffb0aUL ]
      []
    oracleMem
      ppc64le
      "ee021818"
      [ F2, 0x800080007fff7fffUL
        F3, 0x8000800080008000UL
        F16, 0x7fffffff80000000UL
        F17, 0x7ffffff080000010UL
        F19, 0x40000000c0000000UL
        VSRL2, 0x12345678ffff0001UL
        VSRL3, 0x7fff7fff00020003UL
        VSRL16, 0x1ffffffffUL
        VSRL17, 0x12345678UL
        VSRL19, 0x7fffffff80000000UL ]
      []
      [ F16, 0xffff8000ffff8000UL
        F17, 0x7f0000007f00UL
        F18, 0x340000003400UL
        F19, 0xffffff80ffffff80UL
        VSRL16, 0xffff810000000000UL
        VSRL17, 0x7c04fffffffbUL
        VSRL18, 0xdeec000001d0UL
        VSRL19, 0xffffff8100000001UL ]
      []
    oracleMem
      ppc64le
      "ee021818"
      [ F2, 0x8888888877777777UL
        F3, 0x8888888888888888UL
        F16, 0x7fffffff80000000UL
        F17, 0x7ffffff080000010UL
        F19, 0x40000000c0000000UL
        VSRL2, 0x12345678fedcba98UL
        VSRL3, 0x777777770f0f0f0fUL
        VSRL16, 0x1ffffffffUL
        VSRL17, 0x12345678UL
        VSRL19, 0x7fffffff80000000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0xffff0100ffff0100UL
        F17, 0xfce00000fce0UL
        F18, 0x92a0000092a0UL
        F19, 0xffff8f60ffff8f60UL
        VSRL16, 0xffff20e0ffffe3e0UL
        VSRL17, 0xdd4400001be4UL
        VSRL18, 0x804c0000102cUL
        VSRL19, 0xffff9d74fffff394UL ]
      []

  /// <summary>
  /// xvi4ger8, xvi8ger4 and xvi16ger2 set each element to the sum of the
  /// products of matching signed nibbles, signed bytes of xA by unsigned bytes
  /// of xB, or signed halfwords, plus the element for the pp forms, modulo two
  /// to the 32.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVI8GER4PP beside XVI4GER8``() =
    (* dmxvi8ger4pp a4,vs2,vs3, under QEMU: lanes/x-oracle/mma *)
    oracleMem
      ppc64le
      "ee021810"
      [ F2, 0x102030480808080UL
        F3, 0x5060708ffffffffUL
        F16, 0x7fffffff80000000UL
        F17, 0x7ffffff080000010UL
        F19, 0x40000000c0000000UL
        VSRL2, 0x7f7f7f7ffffefdfcUL
        VSRL3, 0x808080807f7f7f7fUL
        VSRL16, 0x1ffffffffUL
        VSRL17, 0x12345678UL
        VSRL19, 0x7fffffff80000000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x80000045800009f6UL
        F17, 0x7ffff2f07ffe0210UL
        F18, 0xce60001fa04UL
        F19, 0x3fffffbabffff60aUL
        VSRL16, 0x501000004f5UL
        VSRL17, 0xffff000012335878UL
        VSRL18, 0xfe000000fc04UL
        VSRL19, 0x7ffffaff7ffffb0aUL ]
      []
    oracleMem
      ppc64le
      "ee021810"
      [ F2, 0x800080007fff7fffUL
        F3, 0x8000800080008000UL
        F16, 0x7fffffff80000000UL
        F17, 0x7ffffff080000010UL
        F19, 0x40000000c0000000UL
        VSRL2, 0x12345678ffff0001UL
        VSRL3, 0x7fff7fff00020003UL
        VSRL16, 0x1ffffffffUL
        VSRL17, 0x12345678UL
        VSRL19, 0x7fffffff80000000UL ]
      []
      [ F16, 0x7fff7fff7fff8000UL
        F17, 0x80007ef080007f10UL
        F18, 0x340000003400UL
        F19, 0x3fffff80bfffff80UL
        VSRL16, 0xffff8101ffffffffUL
        VSRL17, 0x7c0412345673UL
        VSRL18, 0xdeec000001d0UL
        VSRL19, 0x7fffff8080000001UL ]
      []
    oracleMem
      ppc64le
      "ee021810"
      [ F2, 0x8888888877777777UL
        F3, 0x8888888888888888UL
        F16, 0x7fffffff80000000UL
        F17, 0x7ffffff080000010UL
        F19, 0x40000000c0000000UL
        VSRL2, 0x12345678fedcba98UL
        VSRL3, 0x777777770f0f0f0fUL
        VSRL16, 0x1ffffffffUL
        VSRL17, 0x12345678UL
        VSRL19, 0x7fffffff80000000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x7fff00ff7fff0100UL
        F17, 0x8000fcd08000fcf0UL
        F18, 0x92a0000092a0UL
        F19, 0x3fff8f60bfff8f60UL
        VSRL16, 0xffff20e1ffffe3dfUL
        VSRL17, 0xdd441234725cUL
        VSRL18, 0x804c0000102cUL
        VSRL19, 0x7fff9d737ffff394UL ]
      []

  /// <summary>
  /// xvi4ger8, xvi8ger4 and xvi16ger2 set each element to the sum of the
  /// products of matching signed nibbles, signed bytes of xA by unsigned bytes
  /// of xB, or signed halfwords, plus the element for the pp forms, modulo two
  /// to the 32.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVI16GER2 beside XVI4GER8``() =
    (* dmxvi16ger2 a4,vs2,vs3, under QEMU: lanes/x-oracle/mma *)
    oracleMem
      ppc64le
      "ee021a58"
      [ F2, 0x102030480808080UL
        F3, 0x5060708ffffffffUL
        F16, 0x7fffffff80000000UL
        F17, 0x7ffffff080000010UL
        F19, 0x40000000c0000000UL
        VSRL2, 0x7f7f7f7ffffefdfcUL
        VSRL3, 0x808080807f7f7f7fUL
        VSRL16, 0x1ffffffffUL
        VSRL17, 0x12345678UL
        VSRL19, 0x7fffffff80000000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x1a442cfffffbfaUL
        F17, 0xf9ff07000000ff00UL
        F18, 0x600ecf2ffff0102UL
        F19, 0xfff1c9d400000206UL
        VSRL16, 0xfdff03000200f8faUL
        VSRL17, 0x7f00800081007f00UL
        VSRL18, 0x81007f007efe8202UL
        VSRL19, 0x101fd00fefe0506UL ]
      []
    oracleMem
      ppc64le
      "ee021a58"
      [ F2, 0x800080007fff7fffUL
        F3, 0x8000800080008000UL
        F16, 0x7fffffff80000000UL
        F17, 0x7ffffff080000010UL
        F19, 0x40000000c0000000UL
        VSRL2, 0x12345678ffff0001UL
        VSRL3, 0x7fff7fff00020003UL
        VSRL16, 0x1ffffffffUL
        VSRL17, 0x12345678UL
        VSRL19, 0x7fffffff80000000UL ]
      []
      [ F16, 0x8000000080000000UL
        F17, 0x8001000080010000UL
        F18, 0xcbaa0000cbaa0000UL
        F19, 0x0UL
        VSRL16, 0x80010000fffd8000UL
        VSRL17, 0x7ffe000200027ffbUL
        VSRL18, 0x34559754000127d0UL
        VSRL19, 0x1UL ]
      []
    oracleMem
      ppc64le
      "ee021a58"
      [ F2, 0x8888888877777777UL
        F3, 0x8888888888888888UL
        F16, 0x7fffffff80000000UL
        F17, 0x7ffffff080000010UL
        F19, 0x40000000c0000000UL
        VSRL2, 0x12345678fedcba98UL
        VSRL3, 0x777777770f0f0f0fUL
        VSRL16, 0x1ffffffffUL
        VSRL17, 0x12345678UL
        VSRL19, 0x7fffffff80000000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x6f8190806f819080UL
        F17, 0x907f5e70907f5e70UL
        F18, 0xcf26fb60cf26fb60UL
        F19, 0x20ec25a020ec25a0UL
        VSRL16, 0x907f5e70f1f1eff0UL
        VSRL17, 0x6f7fb2a20e0df1f2UL
        VSRL18, 0x30d89bf406283614UL
        VSRL19, 0xdf1420ecfbd9a9ccUL ]
      []

  /// <summary>
  /// xvi4ger8, xvi8ger4 and xvi16ger2 set each element to the sum of the
  /// products of matching signed nibbles, signed bytes of xA by unsigned bytes
  /// of xB, or signed halfwords, plus the element for the pp forms, modulo two
  /// to the 32.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVI16GER2PP beside XVI4GER8``() =
    (* dmxvi16ger2pp a4,vs2,vs3, under QEMU: lanes/x-oracle/mma *)
    oracleMem
      ppc64le
      "ee021b58"
      [ F2, 0x102030480808080UL
        F3, 0x5060708ffffffffUL
        F16, 0x7fffffff80000000UL
        F17, 0x7ffffff080000010UL
        F19, 0x40000000c0000000UL
        VSRL2, 0x7f7f7f7ffffefdfcUL
        VSRL3, 0x808080807f7f7f7fUL
        VSRL16, 0x1ffffffffUL
        VSRL17, 0x12345678UL
        VSRL19, 0x7fffffff80000000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x801a442b7ffffbfaUL
        F17, 0x79ff06f08000ff10UL
        F18, 0x600ecf2ffff0102UL
        F19, 0x3ff1c9d4c0000206UL
        VSRL16, 0xfdff03010200f8f9UL
        VSRL17, 0x7f0080009334d578UL
        VSRL18, 0x81007f007efe8202UL
        VSRL19, 0x8101fcff7efe0506UL ]
      []
    oracleMem
      ppc64le
      "ee021b58"
      [ F2, 0x800080007fff7fffUL
        F3, 0x8000800080008000UL
        F16, 0x7fffffff80000000UL
        F17, 0x7ffffff080000010UL
        F19, 0x40000000c0000000UL
        VSRL2, 0x12345678ffff0001UL
        VSRL3, 0x7fff7fff00020003UL
        VSRL16, 0x1ffffffffUL
        VSRL17, 0x12345678UL
        VSRL19, 0x7fffffff80000000UL ]
      []
      [ F16, 0xffffffff00000000UL
        F17, 0xfff000010010UL
        F18, 0xcbaa0000cbaa0000UL
        VSRL16, 0x80010001fffd7fffUL
        VSRL17, 0x7ffe00021236d673UL
        VSRL18, 0x34559754000127d0UL
        VSRL19, 0x7fffffff80000001UL
        F19, 0x40000000c0000000UL ]
      []
    oracleMem
      ppc64le
      "ee021b58"
      [ F2, 0x8888888877777777UL
        F3, 0x8888888888888888UL
        F16, 0x7fffffff80000000UL
        F17, 0x7ffffff080000010UL
        F19, 0x40000000c0000000UL
        VSRL2, 0x12345678fedcba98UL
        VSRL3, 0x777777770f0f0f0fUL
        VSRL16, 0x1ffffffffUL
        VSRL17, 0x12345678UL
        VSRL19, 0x7fffffff80000000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0xef81907fef819080UL
        F17, 0x107f5e60107f5e80UL
        F18, 0xcf26fb60cf26fb60UL
        F19, 0x60ec25a0e0ec25a0UL
        VSRL16, 0x907f5e71f1f1efefUL
        VSRL17, 0x6f7fb2a22042486aUL
        VSRL18, 0x30d89bf406283614UL
        VSRL19, 0x5f1420eb7bd9a9ccUL ]
      []

  /// <summary>
  /// xvi8ger4spp, xvi16ger2s and xvi16ger2spp saturate the sum (plus the
  /// element for spp) to a signed word, setting VSCR[SAT] where any element
  /// saturated.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVI16GER2S saturates to a word``() =
    (* dmxvi8ger4spp a4,vs2,vs3, under QEMU: lanes/x-oracle/mma *)
    oracleMem
      ppc64le
      "ee021b18"
      [ F2, 0x102030480808080UL
        F3, 0x5060708ffffffffUL
        F16, 0x7fffffff80000000UL
        F17, 0x7ffffff080000010UL
        F19, 0x40000000c0000000UL
        VSRL2, 0x7f7f7f7ffffefdfcUL
        VSRL3, 0x808080807f7f7f7fUL
        VSRL16, 0x1ffffffffUL
        VSRL17, 0x12345678UL
        VSRL19, 0x7fffffff80000000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x7fffffff800009f6UL
        F17, 0x7ffff2f080000000UL
        F18, 0xce60001fa04UL
        F19, 0x3fffffbabffff60aUL
        VSRL16, 0x501000004f5UL
        VSRL17, 0xffff000012335878UL
        VSRL18, 0xfe000000fc04UL
        VSRL19, 0x7ffffaff80000000UL ]
      []
    oracleMem
      ppc64le
      "ee021b18"
      [ F2, 0x800080007fff7fffUL
        F3, 0x8000800080008000UL
        F16, 0x7fffffff80000000UL
        F17, 0x7ffffff080000010UL
        F19, 0x40000000c0000000UL
        VSRL2, 0x12345678ffff0001UL
        VSRL3, 0x7fff7fff00020003UL
        VSRL16, 0x1ffffffffUL
        VSRL17, 0x12345678UL
        VSRL19, 0x7fffffff80000000UL ]
      []
      [ F16, 0x7fff7fff80000000UL
        F17, 0x7fffffff80007f10UL
        F18, 0x340000003400UL
        F19, 0x3fffff80bfffff80UL
        VSRL16, 0xffff8101ffffffffUL
        VSRL17, 0x7c0412345673UL
        VSRL18, 0xdeec000001d0UL
        VSRL19, 0x7fffff8080000001UL ]
      []
    oracleMem
      ppc64le
      "ee021b18"
      [ F2, 0x8888888877777777UL
        F3, 0x8888888888888888UL
        F16, 0x7fffffff80000000UL
        F17, 0x7ffffff080000010UL
        F19, 0x40000000c0000000UL
        VSRL2, 0x12345678fedcba98UL
        VSRL3, 0x777777770f0f0f0fUL
        VSRL16, 0x1ffffffffUL
        VSRL17, 0x12345678UL
        VSRL19, 0x7fffffff80000000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x7fff00ff80000000UL
        F17, 0x7fffffff8000fcf0UL
        F18, 0x92a0000092a0UL
        F19, 0x3fff8f60bfff8f60UL
        VSRL16, 0xffff20e1ffffe3dfUL
        VSRL17, 0xdd441234725cUL
        VSRL18, 0x804c0000102cUL
        VSRL19, 0x7fff9d7380000000UL ]
      []

  /// <summary>
  /// xvi8ger4spp, xvi16ger2s and xvi16ger2spp saturate the sum (plus the
  /// element for spp) to a signed word, setting VSCR[SAT] where any element
  /// saturated.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVI16GER2S beside XVI8GER4SPP``() =
    (* dmxvi16ger2s a4,vs2,vs3, under QEMU: lanes/x-oracle/mma *)
    oracleMem
      ppc64le
      "ee021958"
      [ F2, 0x102030480808080UL
        F3, 0x5060708ffffffffUL
        F16, 0x7fffffff80000000UL
        F17, 0x7ffffff080000010UL
        F19, 0x40000000c0000000UL
        VSRL2, 0x7f7f7f7ffffefdfcUL
        VSRL3, 0x808080807f7f7f7fUL
        VSRL16, 0x1ffffffffUL
        VSRL17, 0x12345678UL
        VSRL19, 0x7fffffff80000000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x1a442cfffffbfaUL
        F17, 0xf9ff07000000ff00UL
        F18, 0x600ecf2ffff0102UL
        F19, 0xfff1c9d400000206UL
        VSRL16, 0xfdff03000200f8faUL
        VSRL17, 0x7f00800081007f00UL
        VSRL18, 0x81007f007efe8202UL
        VSRL19, 0x101fd00fefe0506UL
        VSCR, 0x10000UL ]
      []
    oracleMem
      ppc64le
      "ee021958"
      [ F2, 0x800080007fff7fffUL
        F3, 0x8000800080008000UL
        F16, 0x7fffffff80000000UL
        F17, 0x7ffffff080000010UL
        F19, 0x40000000c0000000UL
        VSRL2, 0x12345678ffff0001UL
        VSRL3, 0x7fff7fff00020003UL
        VSRL16, 0x1ffffffffUL
        VSRL17, 0x12345678UL
        VSRL19, 0x7fffffff80000000UL ]
      []
      [ F16, 0x7fffffff7fffffffUL
        F17, 0x8001000080010000UL
        F18, 0xcbaa0000cbaa0000UL
        F19, 0x0UL
        VSRL16, 0x80010000fffd8000UL
        VSRL17, 0x7ffe000200027ffbUL
        VSRL18, 0x34559754000127d0UL
        VSRL19, 0x1UL ]
      []
    oracleMem
      ppc64le
      "ee021958"
      [ F2, 0x8888888877777777UL
        F3, 0x8888888888888888UL
        F16, 0x7fffffff80000000UL
        F17, 0x7ffffff080000010UL
        F19, 0x40000000c0000000UL
        VSRL2, 0x12345678fedcba98UL
        VSRL3, 0x777777770f0f0f0fUL
        VSRL16, 0x1ffffffffUL
        VSRL17, 0x12345678UL
        VSRL19, 0x7fffffff80000000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x6f8190806f819080UL
        F17, 0x907f5e70907f5e70UL
        F18, 0xcf26fb60cf26fb60UL
        F19, 0x20ec25a020ec25a0UL
        VSRL16, 0x907f5e70f1f1eff0UL
        VSRL17, 0x6f7fb2a20e0df1f2UL
        VSRL18, 0x30d89bf406283614UL
        VSRL19, 0xdf1420ecfbd9a9ccUL
        VSCR, 0x10000UL ]
      []

  /// <summary>
  /// xvi8ger4spp, xvi16ger2s and xvi16ger2spp saturate the sum (plus the
  /// element for spp) to a signed word, setting VSCR[SAT] where any element
  /// saturated.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XVI16GER2SPP beside XVI8GER4SPP``() =
    (* dmxvi16ger2spp a4,vs2,vs3, under QEMU: lanes/x-oracle/mma *)
    oracleMem
      ppc64le
      "ee021950"
      [ F2, 0x102030480808080UL
        F3, 0x5060708ffffffffUL
        F16, 0x7fffffff80000000UL
        F17, 0x7ffffff080000010UL
        F19, 0x40000000c0000000UL
        VSRL2, 0x7f7f7f7ffffefdfcUL
        VSRL3, 0x808080807f7f7f7fUL
        VSRL16, 0x1ffffffffUL
        VSRL17, 0x12345678UL
        VSRL19, 0x7fffffff80000000UL
        VSCR, 0x10000UL ]
      []
      [ F17, 0x79ff06f08000ff10UL
        F18, 0x600ecf2ffff0102UL
        F19, 0x3ff1c9d4c0000206UL
        VSRL16, 0xfdff03010200f8f9UL
        VSRL17, 0x7f0080009334d578UL
        VSRL18, 0x81007f007efe8202UL
        F16, 0x7fffffff80000000UL
        VSRL19, 0x7fffffff80000000UL ]
      []
    oracleMem
      ppc64le
      "ee021950"
      [ F2, 0x800080007fff7fffUL
        F3, 0x8000800080008000UL
        F16, 0x7fffffff80000000UL
        F17, 0x7ffffff080000010UL
        F19, 0x40000000c0000000UL
        VSRL2, 0x12345678ffff0001UL
        VSRL3, 0x7fff7fff00020003UL
        VSRL16, 0x1ffffffffUL
        VSRL17, 0x12345678UL
        VSRL19, 0x7fffffff80000000UL ]
      []
      [ F16, 0x7fffffff00000000UL
        F17, 0xfff080000000UL
        F18, 0xcbaa0000cbaa0000UL
        VSRL16, 0x80010001fffd7fffUL
        VSRL17, 0x7ffe00021236d673UL
        VSRL18, 0x34559754000127d0UL
        VSRL19, 0x7fffffff80000001UL
        F19, 0x40000000c0000000UL ]
      []
    oracleMem
      ppc64le
      "ee021950"
      [ F2, 0x8888888877777777UL
        F3, 0x8888888888888888UL
        F16, 0x7fffffff80000000UL
        F17, 0x7ffffff080000010UL
        F19, 0x40000000c0000000UL
        VSRL2, 0x12345678fedcba98UL
        VSRL3, 0x777777770f0f0f0fUL
        VSRL16, 0x1ffffffffUL
        VSRL17, 0x12345678UL
        VSRL19, 0x7fffffff80000000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x7fffffffef819080UL
        F17, 0x107f5e6080000000UL
        F18, 0xcf26fb60cf26fb60UL
        F19, 0x60ec25a0e0ec25a0UL
        VSRL16, 0x907f5e71f1f1efefUL
        VSRL17, 0x6f7fb2a22042486aUL
        VSRL18, 0x30d89bf406283614UL
        VSRL19, 0x5f1420eb80000000UL ]
      []

  /// <summary>
  /// xxsetaccz AT clears VSR 4AT to 4AT + 3; xxmfacc and xxmtacc move between
  /// an accumulator and the registers it overlays, which hold the same data, so
  /// nothing changes.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XXSETACCZ clears an accumulator``() =
    (* dmsetaccz a4, under QEMU: lanes/x-oracle/mma *)
    oracleMem
      ppc64le
      "7e030162"
      [ F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x0UL
        F17, 0x0UL
        F18, 0x0UL
        VSRL16, 0x0UL
        VSRL17, 0x0UL
        VSRL18, 0x0UL
        F19, 0x0UL
        VSRL19, 0x0UL ]
      []

  /// <summary>
  /// xxsetaccz AT clears VSR 4AT to 4AT + 3; xxmfacc and xxmtacc move between
  /// an accumulator and the registers it overlays, which hold the same data, so
  /// nothing changes.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XXMFACC beside XXSETACCZ``() =
    (* dmxxmfacc a4, under QEMU: lanes/x-oracle/mma *)
    oracleMem
      ppc64le
      "7e000162"
      [ F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        F19, 0x0UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSRL19, 0x0UL ]
      []

  /// <summary>
  /// xxsetaccz AT clears VSR 4AT to 4AT + 3; xxmfacc and xxmtacc move between
  /// an accumulator and the registers it overlays, which hold the same data, so
  /// nothing changes.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] XXMTACC beside XXSETACCZ``() =
    (* dmxxmtacc a4, under QEMU: lanes/x-oracle/mma *)
    oracleMem
      ppc64le
      "7e010162"
      [ F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSCR, 0x10000UL ]
      []
      [ F16, 0x3f80000040000000UL
        F17, 0x3f000000c0000000UL
        F18, 0x41200000c1200000UL
        F19, 0x0UL
        VSRL16, 0x4040000040800000UL
        VSRL17, 0x80000000UL
        VSRL18, 0x3f8000003f800000UL
        VSRL19, 0x0UL ]
      []

  /// <summary>
  /// divdo, divduo and mulldo set XER[OV] when the result cannot be
  /// represented in 64 bits -- the most negative doubleword over -1, a zero
  /// divisor, a product past the signed range -- and clear it when it can,
  /// OR it into XER[SO] and leave XER[CA] alone. The quotients the ISA
  /// leaves undefined are not checked. Values from qemu-ppc64 -cpu power10.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC64] DIVDO, DIVDUO and MULLDO record an overflow in OV``() =
    let max, min = 0x7fffffffffffffffUL, 0x8000000000000000UL
    let fives, tens = 0x5555555555555555UL, 0xaaaaaaaaaaaaaaaaUL
    (* divdo, divduo, mulldo r5, r6, r7 *)
    let divdo, divduo, mulldo = "7ca63fd2", "7ca63f92", "7ca63dd2"
    for isa in ppc64s do
      let after hex a b xer = run isa hex [ R6, a; R7, b; XER, xer ]
      let check hex a b xer status =
        expect status (soOvCa (after hex a b xer)) $"{hex} {nameOf isa}"
      let value hex a b xer = after hex a b xer R5
      expect max (value divdo max 1UL 0xe00c0000UL) (nameOf isa)
      check divdo max 1UL 0xe00c0000UL (so ||| ca)
      check divdo min UInt64.MaxValue 0x20040000UL (so ||| ov ||| ca)
      check divdo 0x1234UL 0UL 0UL (so ||| ov)
      expect 0UL (value divdo fives tens 0x40080000UL) (nameOf isa)
      check divdo fives tens 0x40080000UL 0UL
      expect max (value divduo max 1UL 0xe00c0000UL) (nameOf isa)
      check divduo max 1UL 0xe00c0000UL (so ||| ca)
      check divduo 0x1234UL 0UL 0x20040000UL (so ||| ov ||| ca)
      expect min (value mulldo min UInt64.MaxValue 0x20040000UL) (nameOf isa)
      check mulldo min UInt64.MaxValue 0x20040000UL (so ||| ov ||| ca)
      let product = 0x2236d88fe5618cf0UL
      let a, b = 0x123456789abcdefUL, 0xfedcba9876543210UL
      expect product (value mulldo a b 0UL) (nameOf isa)
      check mulldo a b 0UL (so ||| ov)
      check mulldo max 1UL 0xe00c0000UL (so ||| ca)

  /// <summary>
  /// The record forms of divdo, divduo and mulldo set CR0 from the result
  /// and copy XER[SO] into it after OV has been ORed in, so an overflow
  /// shows in CR0[SO] even when XER[SO] started clear. Values from
  /// qemu-ppc64 -cpu power10.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC64] DIVDO., DIVDUO. and MULLDO. record in CR0``() =
    let max, min = 0x7fffffffffffffffUL, 0x8000000000000000UL
    let fives, tens = 0x5555555555555555UL, 0xaaaaaaaaaaaaaaaaUL
    (* divdo., divduo., mulldo. r5, r6, r7 *)
    let divdo, divduo, mulldo = "7ca63fd3", "7ca63f93", "7ca63dd3"
    for isa in ppc64s do
      let field hex a b xer = cr0 (run isa hex [ R6, a; R7, b; XER, xer ])
      expect 0b0101UL (field divdo max 1UL 0xe00c0000UL) (nameOf isa)
      expect 0b0010UL (field divdo fives tens 0x40080000UL) (nameOf isa)
      expect 1UL (field divdo 0x1234UL 0UL 0UL &&& 1UL) (nameOf isa)
      expect 0b0101UL (field divduo max 1UL 0xe00c0000UL) (nameOf isa)
      expect 0b1001UL (field mulldo min UInt64.MaxValue 0x20040000UL) "mulldo."
      expect 0b0100UL (field mulldo 3UL 5UL 0UL) (nameOf isa)

  /// <summary>
  /// Every form that records an overflow sets XER[OV32] (bit 44, kept at bit
  /// 19 here) as OV would be set in 32-bit mode: from the low words for an
  /// add, a subtract and a negate, so 0x7fffffff + 1 sets OV32 alone and
  /// 0x7fffffffffffffff + 1 sets OV alone; the same as OV for a multiply or
  /// a divide. XER is compared whole. Values from qemu-ppc64 -cpu power10.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC64] The overflow forms set OV32 from the low word``() =
    let max, min = 0x7fffffffffffffffUL, 0x8000000000000000UL
    let lowMin = 0xffffffff80000000UL
    (* addo, subfo, addco, addeo, mullwo, divwo, divdo r5, r6, r7;
       nego r5, r6 *)
    let cases =
      [ "7ca63e14", max, 1UL, 0xe00c0000UL, 0xe0040000UL
        "7ca63e14", 0x7fffffffUL, 1UL, 0x20040000UL, 0x200c0000UL
        "7ca63c50", 0x123456789abcdefUL, 0xfedcba9876543210UL, 0UL, 0x80000UL
        "7ca63c14", 0x7fffffffUL, 1UL, 0x20040000UL, 0x80000UL
        "7ca63c14", min, UInt64.MaxValue, 0x20040000UL, 0xe0000000UL
        "7ca63d14", 0x7fffffffUL, 1UL, 0x20040000UL, 0x80000UL
        "7ca63dd6", lowMin, UInt64.MaxValue, 0xa0040000UL, 0xe00c0000UL
        "7ca63fd6", lowMin, UInt64.MaxValue, 0xa0040000UL, 0xe00c0000UL
        "7ca63fd2", min, UInt64.MaxValue, 0x20040000UL, 0xe00c0000UL
        "7ca604d0", lowMin, 0UL, 0xa0040000UL, 0xa00c0000UL
        "7ca604d0", min, 0UL, 0x20040000UL, 0xe0040000UL ]
    for isa in ppc64s do
      for hex, a, b, xer, expected in cases do
        let after = run isa hex [ R6, a; R7, b; XER, xer ]
        expect expected (after XER) $"{hex} {a:x} {nameOf isa}"

  /// <summary>
  /// Every form that sets XER[CA] sets XER[CA32] (bit 45, kept at bit 18
  /// here) as CA would be set in 32-bit mode: from the carry out of the low
  /// word for the carrying adds and subtracts, and the same as CA for the
  /// algebraic shifts. XER is compared whole. Values from qemu-ppc64 -cpu
  /// power10.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC64] The carrying forms set CA32 from the low word``() =
    let max, min = 0x7fffffffffffffffUL, 0x8000000000000000UL
    (* addc, subfze, addme r5, r6, r7; subfic r5, r6, 12;
       sraw, srad r6, r8, r7; srawi r6, r8, 5 *)
    let cases =
      [ "7ca63814", [ R6, max; R7, 1UL ], 0xe00c0000UL, 0xc00c0000UL
        "7ca63814", [ R6, min; R7, UInt64.MaxValue ], 0x20040000UL, ca
        "7ca60190", [ R6, min ], 0x20040000UL, 0x40000UL
        "20a6000c", [ R6, min ], 0x20040000UL, 0x40000UL
        "7ca601d4", [ R6, 0x5555555555555555UL ], 0x40080000UL, 0x600c0000UL
        "7d063e30", [ R8, 0x123456789abcdefUL; R7, 0x10UL ], 0UL, 0x20040000UL
        "7d063e30", [ R8, min; R7, UInt64.MaxValue ], 0x20040000UL, 0UL
        "7d063e34", [ R8, max; R7, 1UL ], 0xe00c0000UL, 0xc0080000UL
        "7d062e70", [ R8, 0x123456789abcdefUL ], 0UL, 0x20040000UL ]
    for isa in ppc64s do
      for hex, given, xer, expected in cases do
        let after = run isa hex ((XER, xer) :: given)
        expect expected (after XER) $"{hex} {nameOf isa}"

  /// <summary>
  /// A 32-bit processor predates OV32 and CA32: bits 44 and 45 of its XER
  /// are reserved, and no form writes them. The 7457 QEMU models drops them
  /// even from mtxer. XER is compared whole. Values from qemu-ppc -cpu 7457.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC32] No form writes OV32 or CA32``() =
    (* addco, addc r5, r6, r7; srawi r6, r8, 5 *)
    let cases =
      [ "7ca63c14", [ R6, 0x7fffffffUL; R7, 1UL ], 0xe0000000UL, 0xc0000000UL
        "7ca63c14", [ R6, 0x80000000UL; R7, 0xffffffffUL ], ca, 0xe0000000UL
        "7ca63814", [ R6, 0x7fffffffUL; R7, 1UL ], 0xe0000000UL, 0xc0000000UL
        "7d062e70", [ R8, 0x89abcdefUL ], 0UL, ca ]
    for hex, given, xer, expected in cases do
      let after = run ppc32 hex ((XER, xer) :: given)
      expect expected (after XER) hex

  /// <summary>
  /// twi and tw compare the low word of rA with the sign-extended SI or with
  /// the low word of rB, and trap when a comparison their TO field names
  /// holds: TO = 0 names none and never traps, and on a 64-bit processor the
  /// high words take no part, so 0xffffffff0000000c equals 12. The extended
  /// mnemonics (tweqi, twlti, tweq, twgt, twllt here) are the same words.
  /// Values from qemu-ppc64 -cpu power10 and qemu-ppc -cpu 7457.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] TWI and TW trap on the low words TO names``() =
    (* twi 4,r6,12; twi 0,r6,12; twi 16,r6,0; twi 31,r6,0; tw 4,r6,r7;
       tw 8,r6,r7; tw 2,r6,r7 *)
    let cases64 =
      [ "0c86000c", [ R6, 0xffffffff0000000cUL ], true
        "0c86000c", [ R6, 0x10000000dUL ], false
        "0c06000c", [ R6, 0xcUL ], false
        "0e060000", [ R6, 0x80000000UL ], true
        "0e060000", [ R6, 0xffffffff00000001UL ], false
        "0fe60000", [ R6, 7UL ], true
        "7c863808", [ R6, 0x100000005UL; R7, 5UL ], true
        "7c863808", [ R6, 5UL; R7, 6UL ], false
        "7d063808", [ R6, 1UL; R7, 0xffffffff00000002UL ], false
        "7d063808", [ R6, 3UL; R7, 0xffffffff00000002UL ], true
        "7c463808", [ R6, 0x1ffffffffUL; R7, 1UL ], false
        "7c463808", [ R6, 1UL; R7, 0x1ffffffffUL ], true ]
    for isa in ppc64s do
      for hex, given, trapped in cases64 do
        expectTrap trapped isa hex given
    for hex, given, trapped in
      [ "0c86000c", [ R6, 0xcUL ], true
        "0c86000c", [ R6, 0xdUL ], false
        "0c06000c", [ R6, 0xcUL ], false
        "0e060000", [ R6, 0x80000000UL ], true
        "0e060000", [ R6, 1UL ], false ] do
      expectTrap trapped ppc32 hex given

  /// <summary>
  /// lwarx reserves the word it loads, and stwcx. stores only while that
  /// reservation holds and says in CR0[EQ] whether it did; either way it
  /// clears the reservation, so a second stwcx. with no lwarx between fails
  /// and writes nothing -- even where the first stored the very value the
  /// reservation was made over, so that memory still holds it. Values from
  /// QEMU running lwarx r5,0,r6; stwcx. r7,0,r6 and then a second stwcx.
  /// r8,0,r6 in one go, in each byte order.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] STWCX. uses up the reservation LWARX made``() =
    let field = [ CR0_0; CR0_1; CR0_2; CR0_3 ]
    let state = [ R5; R6; R7; R8; ExMonAddr; ExMonVal; RES; XER ] @ field
    let ea = 0x20200080UL
    let reserved = [| 0x11uy; 0x22uy; 0x33uy; 0x44uy |]
    let big = [| 0xaauy; 0xbbuy; 0xccuy; 0xdduy |]
    let word (left: Map<uint64, byte[]>) =
      Array.init 4 (fun i -> left[ea + uint64 i][0])
    (* lwarx r5,0,r6; stwcx. r7,0,r6; stwcx. r8,0,r6 *)
    let lwarx, first, second = "7ca03028", "7ce0312d", "7d00312d"
    for isa, loaded, stored in
      [ ppc32, 0x11223344UL, big
        ppc64, 0x11223344UL, big
        ppc64le, 0x44332211UL, Array.rev big ] do
      let go hexes r7 =
        let given = [ R6, ea; R7, r7; R8, 0x55667788UL ]
        sequence isa hexes state given [ ea, reserved ]
      let after, left = go [ lwarx; first ] 0xaabbccddUL
      expect loaded (after R5) (nameOf isa)
      expect 0b0010UL (cr0 after) (nameOf isa)
      CollectionAssert.AreEqual(stored, word left, nameOf isa)
      let after, left = go [ lwarx; first; second ] loaded
      expect 0UL (cr0 after) (nameOf isa)
      CollectionAssert.AreEqual(reserved, word left, nameOf isa)

  /// <summary>
  /// stwcx. with no reservation fails without touching memory -- it neither
  /// stores nor reads the word it would have stored to -- and records the
  /// failure in CR0, with SO from XER[SO]. Values from QEMU running stwcx.
  /// r7,0,r6 alone.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] STWCX. with no reservation reads and writes nothing``() =
    let field = [ CR0_0, 1UL; CR0_1, 1UL; CR0_2, 1UL; CR0_3, 1UL ]
    (* stwcx. r7, 0, r6 *)
    for isa in [ ppc32; ppc64; ppc64le ] do
      let given = (R6, 0x20200080UL) :: (R7, 0xaabbccddUL) :: field
      let after, memory = exec isa "7ce0312d" given []
      expect 0UL (cr0 after) (nameOf isa)
      expect 0UL (uint64 memory.Count) (nameOf isa)

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
