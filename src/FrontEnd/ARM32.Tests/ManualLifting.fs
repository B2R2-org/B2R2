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

namespace B2R2.FrontEnd.ARM32.Tests

open System
open System.Collections.Generic
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.ARM32

/// A place a manual lifting test gives a value to or reads one from, with
/// the value.
type internal Cell =
  /// R0 to R12, by number.
  | Gpr of int * uint32
  /// D0 to D31, by number.
  | D of int * uint64
  /// CPSR as MRS reads it: the flags, Q, GE and the mode.
  | CPSR of uint32
  /// FPSCR.
  | FPSCR of uint32
  /// The eight bytes at an offset into the window, read little-endian.
  | M of int * uint64

/// What a run of one word's statements ended with: the value it left in a
/// cell's place and in a register, where the word jumped out to, if it did,
/// and the exception it took, if it took one.
type internal Run =
  { After: Cell -> Cell
    Reg: Register -> uint32
    Target: uint64 option
    Effect: SideEffect option }

/// <summary>
/// What the manual lifting tests share. A word is lifted where QEMU ran it,
/// at CodeAddr, for a little-endian ARMv7, which is the byte order QEMU's
/// user mode gave its data; the word itself is read from hex as the manual
/// writes it, a T32 one as its first halfword then its second.
/// </summary>
module internal ManualLifting =
  /// Where QEMU ran every word, which PC reads as.
  [<Literal>]
  let CodeAddr = 0x30000000UL

  /// Where the 64 bytes a load or a store reaches start: QEMU ran every
  /// access inside them.
  [<Literal>]
  let Window = 0x20000800UL

  let private isa = ISA(Architecture.ARMv7, Endian.Little)

  let private regFactory = RegisterFactory isa :> IRegisterFactory

  /// A register by name.
  let reg (r: Register) = Register.toRegID r |> regFactory.GetRegVar

  /// R0 to R12, by number: R0 to R8, SB, SL, FP and IP, numbered 0 to 12.
  let private gprs = Array.init 13 (fun n -> reg (enum<Register> n))

  /// Dn, the half n % 2 of Q(n / 2).
  let private dReg n =
    let q = enum<Register> (int Register.Q0 + n / 2)
    regFactory.GetPseudoRegVar(Register.toRegID q, n % 2 + 1)

  /// The statements a word lifts to at CodeAddr, without its marks.
  let lift isThumb (hex: string) =
    let reader = BinReader.Init Endian.Big
    let parser = Parser(isa, isThumb, reader) :> IInstructionParsable
    let builder = ILowUIRBuilder.Default(isa, regFactory, LowUIRStream())
    let ins = parser.Parse(ByteArray.ofHexString hex, CodeAddr)
    ins.Translate builder
    |> Array.filter (function
      | ISMark _ | IEMark _ -> false
      | _ -> true)

  /// The kinds of the jumps out of the instruction a word lifts to.
  let kindsOf isThumb hex =
    lift isThumb hex
    |> Array.choose (function
      | InterJmp(Kind = kind) -> Some kind
      | _ -> None)

  /// The window holding the doublewords the cells give, and nothing else.
  let private memoryOf cells =
    let mem = Dictionary<uint64, byte>()
    for cell in cells do
      match cell with
      | M(offset, v) ->
        BitConverter.GetBytes v
        |> Array.iteri (fun i b -> mem[Window + uint64 (offset + i)] <- b)
      | _ ->
        ()
    mem

  /// The register a cell names, with its value.
  let private regInput = function
    | Gpr(n, v) -> Some(gprs[n], BitVector(v, 32<rt>))
    | D(n, v) -> Some(dReg n, BitVector(v, 64<rt>))
    | CPSR v -> Some(reg Register.CPSR, BitVector(v, 32<rt>))
    | FPSCR v -> Some(reg Register.FPSCR, BitVector(v, 32<rt>))
    | M _ -> None

  /// <summary>
  /// The registers a run starts from: PC at CodeAddr, no exclusive
  /// reservation held, which is what QEMU's run had, then the cells, then
  /// the other registers given.
  /// </summary>
  let private inputsOf cells (others: (Register * uint32) list) =
    [ yield reg Register.PC, BitVector(uint32 CodeAddr, 32<rt>)
      yield reg Register.ExMonAddr, BitVector(0xffffffffu, 32<rt>)
      yield reg Register.ExMonVal, BitVector(0u, 32<rt>)
      yield! List.choose regInput cells
      for r, v in others -> reg r, BitVector(v, 32<rt>) ]

  /// The place a cell names, its value dropped.
  let private placeOf = function
    | Gpr(n, _) -> Gpr(n, 0u)
    | D(n, _) -> D(n, 0UL)
    | CPSR _ -> CPSR 0u
    | FPSCR _ -> FPSCR 0u
    | M(offset, _) -> M(offset, 0UL)

  /// The value a run left in a cell's place.
  let private valueAfter (read: Expr -> BitVector) mem cell =
    let value e = (read e).ToUInt64()
    match cell with
    | Gpr(n, _) ->
      Gpr(n, uint32 (value gprs[n]))
    | D(n, _) ->
      D(n, value (dReg n))
    | CPSR _ ->
      CPSR(uint32 (value (reg Register.CPSR)))
    | FPSCR _ ->
      FPSCR(uint32 (value (reg Register.FPSCR)))
    | M(offset, _) ->
      let byteAt i = (mem: Dictionary<uint64, byte>)[Window + uint64 i]
      let bytes = Array.init 8 (fun i -> byteAt (offset + i))
      M(offset, BitConverter.ToUInt64(bytes, 0))

  /// The registers of the exclusive monitor's model, which nothing outside
  /// B2R2 can read, so no test names.
  let private isMonitor r =
    r = Register.toRegID Register.ExMonAddr
    || r = Register.toRegID Register.ExMonVal

  /// The places of the registers a test may name, by register.
  let private places =
    let d = Dictionary<RegisterID, Cell>()
    let add (e: Expr) cell =
      match e with
      | Var(RegisterID = r) -> d[r] <- cell
      | _ -> ()
    gprs |> Array.iteri (fun n e -> add e (Gpr(n, 0u)))
    for n in 0 .. 31 do add (dReg n) (D(n, 0UL))
    add (reg Register.CPSR) (CPSR 0u)
    add (reg Register.FPSCR) (FPSCR 0u)
    d

  /// The register each statement writes, as a test would name it, or by its
  /// name where no test can.
  let private writtenBy stmts =
    stmts
    |> Array.choose (function
      | Put(Dst = Var(RegisterID = r; Name = name)) when not (isMonitor r) ->
        match places.TryGetValue r with
        | true, place -> Some(Choice1Of2 place)
        | false, _ -> Some(Choice2Of2 name)
      | _ ->
        None)

  /// Asserts that every register the statements write is one named.
  let private namesEveryWrite hex stmts (named: Set<Cell>) =
    for w in writtenBy stmts do
      match w with
      | Choice1Of2 place when named.Contains place -> ()
      | Choice1Of2 place -> Assert.Fail $"{hex} writes {place}"
      | Choice2Of2 name -> Assert.Fail $"{hex} writes {name}"

  /// One vector: what the outputs name holds what QEMU left, every input
  /// they do not name is as it was, and nothing else is written.
  let private checkOne (hex: string) stmts inputs outputs =
    let mem = memoryOf inputs
    let read = IRRunner.runOn stmts (inputsOf inputs []) mem
    let changed = outputs |> List.map placeOf |> Set.ofList
    let unchanged = inputs |> List.filter (placeOf >> changed.Contains >> not)
    for cell in outputs @ unchanged do
      Assert.AreEqual<Cell>(cell, valueAfter read mem cell, hex)
    inputs @ outputs |> List.map placeOf |> Set.ofList
    |> namesEveryWrite hex stmts

  /// <summary>
  /// Checks a word against what QEMU computed: the inputs and the outputs
  /// are paired by position, each pair a run QEMU made.
  /// </summary>
  let check isThumb hex (inputs: Cell list list) (outputs: Cell list list) =
    let stmts = lift isThumb hex
    Assert.AreEqual<int>(inputs.Length, outputs.Length, hex)
    List.iter2 (checkOne hex stmts) inputs outputs

  /// <summary>
  /// Runs a word's statements from cells and other registers given, PC at
  /// CodeAddr and no exclusive reservation held unless the others say so.
  /// </summary>
  let runWith isThumb hex cells (others: (Register * uint32) list) =
    let mem = memoryOf cells
    let stmts = lift isThumb hex
    let inputs = inputsOf cells others
    let struct (read, target, effect) = IRRunner.runToEnd stmts inputs mem
    { After = valueAfter read mem
      Reg = fun r -> uint32 ((read (reg r)).ToUInt64())
      Target = target |> Option.map (fun t -> t.ToUInt64())
      Effect = effect }

  /// <summary>
  /// The modes, of all CPSR.M names, in which a word takes the Undefined
  /// Instruction exception, run from the cells and other registers given.
  /// </summary>
  let refusedModes isThumb hex cells others =
    [| 0x10u; 0x11u; 0x12u; 0x13u; 0x16u; 0x17u; 0x1au; 0x1bu; 0x1fu |]
    |> Array.filter (fun mode ->
      let run = runWith isThumb hex (CPSR mode :: cells) others
      run.Effect = Some SideEffect.UndefinedInstruction)
