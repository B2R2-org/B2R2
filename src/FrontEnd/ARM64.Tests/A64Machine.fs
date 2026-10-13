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

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.ARM64

/// A place an A64 instruction keeps a value, with the value.
type internal Loc =
  /// X0 to X30.
  | X of int * uint64
  /// V0 to V31, as the low and the high doubleword.
  | V of int * uint64 * uint64
  /// The stack pointer.
  | SP of uint64
  /// Where the instruction goes on: its own address unless it branches.
  | PC of uint64
  /// NZCV as MRS reads it: N, Z, C and V in bits 31 to 28.
  | NZCV of uint64
  /// FPSR, the exceptions an instruction raised: none before it runs.
  | FPSR of uint64
  /// The doubleword at a byte offset of the window, little-endian.
  | M of int * uint64
  /// Where the 64-byte window of memory is, where an input moves it.
  | Window of uint64

/// <summary>
/// A whole A64 register file and a window of memory: the state a test runs
/// one instruction over and reads back.
/// </summary>
type internal A64State =
  { Xs: uint64[]
    Sp: uint64
    Pc: uint64
    Vs: (uint64 * uint64)[]
    Flags: uint64
    Fpcr: uint64
    Fpsr: uint64
    Mem: uint64[]
    At: uint64 }

/// <summary>
/// <para>The register files a lifting test runs an instruction over, and the
/// comparison of what the lifted statements leave with what the processor
/// does. Each test's expected values are what QEMU's -cpu max computed for
/// the instruction over the same file, read back in full (the harness is
/// optest-arm/oracle/a64); the inputs are fixed here, value for value as
/// the harness has them.</para>
/// <para>Sets 0 and 1 draw every register, the flags and the window from
/// splitmix64 seeded 1 and 2, with FPCR 0. Set 2 has the integer corners in
/// X, single-precision corners in the lanes of V, NZCV 0110 and FPCR 0; set
/// 3 the integer corners rotated by seven, double-precision corners in the
/// lanes of V, NZCV 1001 and FPCR's FZ, DN and FZ16. The window holds X0 to
/// X7 in set 2, and in set 3 with the two pairs swapped, so that comparing
/// X2 and X3 against its first doublewords matches. SP is the window in
/// every set, and FPCR rounds to nearest in every set.</para>
/// <para>The instruction is at 0x1000000, and runs at EL0 of a Linux
/// process: SCTLR_EL1 has UCI, UCT and DZE, as Linux sets them.</para>
/// </summary>
module internal A64Machine =
  /// Where the instruction is.
  let code = 0x1000000UL

  /// Where the window of memory is, unless an input moves it.
  let window = 0x2008000UL

  let private intCorners =
    [| 0x0UL
       0x1UL
       0xffffffffffffffffUL
       0x8000000000000000UL
       0x7fffffffffffffffUL
       0x80000000UL
       0x7fffffffUL
       0xffffffffUL
       0x100000000UL
       0x5555555555555555UL
       0xaaaaaaaaaaaaaaaaUL
       0xff00ff00ff00ffUL
       0x8000UL
       0x7fffUL
       0xffffUL
       0x80UL
       0x7fUL
       0x2UL
       0x3UL
       0xfffffffffffffffeUL
       0x123456789abcdefUL
       0xfedcba9876543210UL
       0x1fUL
       0x3fUL
       0x40UL
       0x20UL
       0x10000UL
       0xff00000000000000UL
       0xffff0000UL
       0xffffffff00000000UL
       0x8000000080000000UL |]

  let private singleCorners =
    [| 0x3f800000UL
       0xbfc00000UL
       0x40400000UL
       0x3dcccccdUL
       0x80000000UL
       0x7f800000UL
       0x7fc00000UL
       0x7fa00000UL
       0x00000001UL
       0x807fffffUL
       0x7f7fffffUL
       0x00800000UL
       0x501502f9UL
       0xc0e80000UL
       0x3f000000UL
       0x42c80000UL
       0x4f000000UL
       0xcf000001UL
       0x477fe000UL
       0x3eaaaaabUL
       0xff800000UL
       0x00000000UL
       0x40200000UL
       0xc0600000UL
       0x4f800000UL
       0x3f400000UL
       0xe0ad78ecUL
       0x40e00000UL
       0x3f800001UL |]

  let private doubleCorners =
    [| 0x3ff0000000000000UL
       0xbff8000000000000UL
       0x4008000000000000UL
       0x3fb999999999999aUL
       0x8000000000000000UL
       0x7ff0000000000000UL
       0x7ff8000000000000UL
       0x7ff4000000000000UL
       0x0000000000000001UL
       0x800fffffffffffffUL
       0x7fefffffffffffffUL
       0x0010000000000000UL
       0x7e37e43c8800759cUL
       0xc01d000000000000UL
       0x3fe0000000000000UL
       0x43e0000000000000UL
       0xc3e0000000000000UL
       0x43f0000000000000UL
       0x3fd5555555555555UL
       0xfff0000000000000UL
       0x0000000000000000UL
       0x4004000000000000UL
       0xc00c000000000000UL
       0x41f0000000080000UL
       0x01a56e1fc2f8f359UL
       0xc415af1d78b58c40UL
       0x401c000000000000UL
       0x3ff0000000000001UL
       0x41e0000000000000UL |]

  /// The splitmix64 sequence from a seed.
  let private splitmix (seed: uint64) =
    Seq.unfold (fun (s: uint64) ->
      let s = s + 0x9e3779b97f4a7c15UL
      let z = (s ^^^ (s >>> 30)) * 0xbf58476d1ce4e5b9UL
      let z = (z ^^^ (z >>> 27)) * 0x94d049bb133111ebUL
      Some(z ^^^ (z >>> 31), s)) seed
    |> Seq.take (31 + 64 + 1 + 8)
    |> Array.ofSeq

  let private randomSet seed =
    let r = splitmix seed
    { Xs = r[0..30]
      Sp = window
      Pc = code
      Vs = Array.init 32 (fun i -> r[31 + 2 * i], r[32 + 2 * i])
      Flags = (r[95] >>> 60) <<< 28
      Fpcr = 0UL
      Fpsr = 0UL
      Mem = r[96..103]
      At = window }

  let private singleLanes i =
    let lane j = singleCorners[(4 * i + j) % singleCorners.Length]
    lane 0 ||| (lane 1 <<< 32), lane 2 ||| (lane 3 <<< 32)

  let private doubleLanes i =
    let n = doubleCorners.Length
    doubleCorners[(2 * i) % n], doubleCorners[(2 * i + 1) % n]

  let private singleSet () =
    { Xs = Array.copy intCorners
      Sp = window
      Pc = code
      Vs = Array.init 32 singleLanes
      Flags = 0x60000000UL
      Fpcr = 0UL
      Fpsr = 0UL
      Mem = intCorners[0..7]
      At = window }

  let private doubleSet () =
    let xs = Array.init 31 (fun i -> intCorners[(i + 7) % intCorners.Length])
    { Xs = xs
      Sp = window
      Pc = code
      Vs = Array.init 32 doubleLanes
      Flags = 0x90000000UL
      Fpcr = 0x03080000UL
      Fpsr = 0UL
      Mem = [| xs[2]; xs[3]; xs[0]; xs[1]; xs[4]; xs[5]; xs[6]; xs[7] |]
      At = window }

  /// Input set k, as the harness numbers them.
  let inputSet k =
    match k with
    | 0 -> randomSet 1UL
    | 1 -> randomSet 2UL
    | 2 -> singleSet ()
    | _ -> doubleSet ()

  /// The number of input sets.
  let sets = 4

  let private replace (arr: 'a[]) i v =
    Array.mapi (fun j x -> if j = i then v else x) arr

  /// A state with the given places holding the given values.
  let update state (locs: Loc list) =
    locs
    |> List.fold (fun s loc ->
      match loc with
      | X(i, v) -> { s with Xs = replace s.Xs i v }
      | V(i, lo, hi) -> { s with Vs = replace s.Vs i (lo, hi) }
      | SP v -> { s with Sp = v }
      | PC v -> { s with Pc = v }
      | NZCV v -> { s with Flags = v }
      | FPSR v -> { s with Fpsr = v }
      | M(off, v) -> { s with Mem = replace s.Mem (off / 8) v }
      | Window a -> { s with At = a }) state

  let private isa = ISA(Architecture.ARMv8, Endian.Big)

  let private regFactory = RegisterFactory isa :> IRegisterFactory

  let private reg r = regFactory.GetRegVar(Register.toRegID r)

  let private xReg i = reg (enum<Register> (int Register.X0 + i))

  let private vHalf i half =
    let q = enum<Register> (int Register.Q0 + i)
    regFactory.GetPseudoRegVar(Register.toRegID q, half)

  let private flagRegs =
    [ Register.N, 31
      Register.Z, 30
      Register.C, 29
      Register.V, 28 ]

  /// What the registers hold as inputs to the statements.
  let private inputsOf s =
    let bv64 (v: uint64) = BitVector(v, 64<rt>)
    [ for i in 0 .. 30 do yield xReg i, bv64 s.Xs[i]
      for i in 0 .. 31 do
        yield vHalf i 1, bv64 (fst s.Vs[i])
        yield vHalf i 2, bv64 (snd s.Vs[i])
      for r, bit in flagRegs do
        yield reg r, BitVector((s.Flags >>> bit) &&& 1UL, 1<rt>)
      yield reg Register.SP, bv64 s.Sp
      yield reg Register.FPCR, bv64 s.Fpcr
      yield reg Register.FPSR, bv64 s.Fpsr
      yield reg Register.PC, bv64 s.Pc
      yield reg Register.SCTLREL1, bv64 0x400c000UL ]

  /// The window's bytes.
  let private bytesOf s =
    s.Mem |> Array.collect (fun (q: uint64) -> System.BitConverter.GetBytes q)

  /// The statements a word lifts to, the word at the instruction's place.
  let lift (hex: string) =
    let parser = Parser(BinReader.Init Endian.Big) :> IInstructionParsable
    let builder = ILowUIRBuilder.Default(isa, regFactory, LowUIRStream())
    let ins = parser.Parse(ByteArray.ofHexString hex, code)
    ins.Translate builder

  /// What the window holds after the statements ran.
  let private windowAfter (o: IROutcome) at =
    Array.init 8 (fun q ->
      Array.init 8 (fun b ->
        match o.Byte(at + uint64 (8 * q + b)) with
        | Some v -> v
        | None -> 0uy)
      |> fun bs -> System.BitConverter.ToUInt64(bs, 0))

  /// The state the statements leave.
  let private stateAfter (o: IROutcome) s =
    let u (r: Expr) = (o.Read r).ToUInt64()
    let flags =
      flagRegs |> List.sumBy (fun (r, bit) -> u (reg r) <<< bit)
    { s with
        Xs = Array.init 31 (fun i -> u (xReg i))
        Sp = u (reg Register.SP)
        Pc = u (reg Register.PC)
        Vs = Array.init 32 (fun i -> u (vHalf i 1), u (vHalf i 2))
        Flags = flags
        Fpsr = u (reg Register.FPSR)
        Mem = windowAfter o s.At }

  /// Runs the statements over a state and gives the state they leave, and
  /// the side effects they reach.
  let runOver stmts s =
    let o = IRRunner.execute stmts (inputsOf s) [ (s.At, bytesOf s) ]
    stateAfter o s, o.Effects

  /// The state words leave, run one after another over input set k with
  /// the given places changed.
  let after hexes (inputs: Loc list) k =
    hexes
    |> List.fold (fun s hex -> fst (runOver (lift hex) s))
                 (update (inputSet k) inputs)

  /// The places two states differ, as text.
  let difference (expected: A64State) (actual: A64State) =
    let show name (e: uint64) (a: uint64) =
      if e = a then None else Some $"{name} is 0x{a:x}, expected 0x{e:x}"
    [ for i in 0 .. 30 do yield show $"X{i}" expected.Xs[i] actual.Xs[i]
      yield show "SP" expected.Sp actual.Sp
      yield show "PC" expected.Pc actual.Pc
      for i in 0 .. 31 do
        yield show $"V{i}.lo" (fst expected.Vs[i]) (fst actual.Vs[i])
        yield show $"V{i}.hi" (snd expected.Vs[i]) (snd actual.Vs[i])
      yield show "NZCV" expected.Flags actual.Flags
      yield show "FPSR" expected.Fpsr actual.Fpsr
      for q in 0 .. 7 do
        yield show $"M[{8 * q}]" expected.Mem[q] actual.Mem[q] ]
    |> List.choose id

  /// <summary>
  /// What a word's statements get wrong over each input set: the word runs
  /// over set k with the given places changed, and should leave the state
  /// those inputs make with the k-th list of places changed, and reach no
  /// side effect.
  /// </summary>
  let mismatches hex (inputs: Loc list) (expected: Loc list list) =
    let stmts = lift hex
    expected
    |> List.mapi (fun k changes ->
      let s = update (inputSet k) inputs
      let after, effects = runOver stmts s
      let want = update s changes
      let effects = effects |> List.map (fun e -> $"raises {e}")
      difference want after @ effects
      |> List.map (fun m -> $"{hex} set {k}: {m}"))
    |> List.concat

  /// The side effects a word's statements reach over input set k.
  let effectsOver hex (inputs: Loc list) k =
    let s = update (inputSet k) inputs
    snd (runOver (lift hex) s)
