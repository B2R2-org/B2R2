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

open System.Collections.Generic
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.MIPS

/// A place a lifting test gives a value to or reads one from.
type Loc =
  /// A general register, by number.
  | G of int
  /// A floating-point register, by number.
  | F of int
  /// HI.
  | Hi
  /// LO.
  | Lo
  /// FCSR.
  | Fcsr
  /// The coprocessor 0 Status register.
  | Status
  /// The eight bytes of memory at an aligned address, read big-endian.
  | M of uint64

/// <summary>
/// What the tests of every instruction of the manuals run a word with, and
/// what they ask of the run.
///
/// <para>A word is lifted where the reference ran it, at 0x20100000, and run
/// over the values a test gives: every other register is zero, as it was
/// for the reference, and memory is the bytes the test gives and nothing
/// else. What a test expects is what CHANGED -- every general and
/// floating-point register, HI and LO where the processor has them, FCSR,
/// and every eight bytes of memory -- so a lifter that writes a register it
/// should not have written fails as surely as one that writes the wrong
/// value. A register the lifter gives a value the manual leaves
/// UNPREDICTABLE is not asked about.</para>
/// </summary>
module internal ManualLift =
  /// Where every word sits.
  let at = 0x20100000UL

  /// The register a register variable names.
  let private idOf = function
    | Var(RegisterID = r) -> r
    | PCVar _ -> Register.toRegID Register.PC
    | e -> failwith $"{e} is not a register"

  /// The register a place names.
  let private regOf (regs: IRegisterFactory) loc =
    let rid =
      match loc with
      | G n -> Register.toRegID (enum<Register> n)
      | F n -> Register.toRegID (enum<Register> (0x20 + n))
      | Hi -> Register.toRegID Register.HI
      | Lo -> Register.toRegID Register.LO
      | Fcsr -> Register.toRegID Register.FCSR
      | Status -> RegisterID.create (int CP0Register.Status)
      | M _ -> failwith "memory is not a register"
    regs.GetRegVar rid

  /// The statements words lift to, one after another from `at`, each read
  /// in the mode the ISA starts in.
  let lift (isa: ISA) (hexes: string list) =
    let builder = LowUIRBuilder(isa, RegisterFactory isa, LowUIRStream())
    let parser = Parser(isa, BinReader.Init isa.Endian) :> IInstructionParsable
    hexes
    |> List.fold (fun (addr, acc) (hex: string) ->
      let ins = parser.Parse(ByteArray.ofHexString hex, addr)
      addr + uint64 ins.Length, Array.append acc (ins.Translate builder))
      (at, [||])
    |> snd

  /// The bytes the places of memory among the given values hold.
  let private bytesOf given =
    given
    |> List.collect (function
      | M addr, (v: uint64) ->
        List.init 8 (fun i -> addr + uint64 i, byte (v >>> (56 - 8 * i)))
      | _ ->
        [])

  /// The places every run is asked about on a processor.
  let private places (isa: ISA) =
    let hiLo = if isa.MIPSRelease = MIPSRelease.R6 then [] else [ Hi; Lo ]
    [ for n in 1 .. 31 -> G n ] @ [ for n in 0 .. 31 -> F n ] @ hiLo @ [ Fcsr ]

  /// The eight-byte places of memory a run left different from how it was
  /// given, with what each holds after.
  let private changedMemory given (after: IReadOnlyDictionary<uint64, byte>) =
    let before = dict (bytesOf given)
    after.Keys
    |> Seq.filter (fun a ->
      match before.TryGetValue a with
      | true, b -> b <> after[a]
      | false, _ -> true)
    |> Seq.map (fun a -> a &&& ~~~7UL)
    |> Seq.distinct
    |> Seq.sort
    |> Seq.map (fun chunk ->
      let read i =
        match after.TryGetValue(chunk + uint64 i) with
        | true, b -> uint64 b
        | false, _ -> 0UL
      M chunk, List.fold (fun acc i -> (acc <<< 8) ||| read i) 0UL [ 0 .. 7 ])
    |> Seq.toList

  /// The outcome of running the words over the given values, and the
  /// register variable of each place.
  let private outcomeOf isa hexes (given: (Loc * uint64) list) =
    let regs = RegisterFactory isa :> IRegisterFactory
    let var loc = regOf regs loc
    let value loc (v: uint64) = var loc, BitVector(v, Expr.typeOf (var loc))
    let pc = regs.GetRegVar(Register.toRegID Register.PC)
    let inputs =
      (pc, BitVector(at, Expr.typeOf pc))
      :: (given |> List.filter (fst >> (function M _ -> false | _ -> true))
          |> List.map (fun (loc, v) -> value loc v))
    IRRunner.exec (lift isa hexes) inputs (bytesOf given), var

  /// What a run changed and what it raised, every register it gave a value
  /// the manual leaves UNPREDICTABLE left out.
  let run isa hexes (given: (Loc * uint64) list) =
    let outcome, var = outcomeOf isa hexes given
    let unpredictable loc =
      match loc with
      | M _ -> false
      | _ -> outcome.Unpredictable.Contains(idOf (var loc))
    let before loc =
      given |> List.tryFind (fst >> (=) loc) |> Option.map snd
      |> Option.defaultValue 0UL
    let after loc =
      match outcome.Registers.TryGetValue(idOf (var loc)) with
      | true, v -> v.ToUInt64()
      | false, _ -> 0UL
    let registers =
      places isa
      |> List.filter (fun loc -> not (unpredictable loc))
      |> List.filter (fun loc -> after loc <> before loc)
      |> List.map (fun loc -> loc, after loc)
    let changed = registers @ changedMemory given outcome.Memory
    changed, outcome.Effects, unpredictable

  /// The places and values in a fixed order, written out for a message.
  let private show (changes: (Loc * uint64) list) =
    changes
    |> List.sort
    |> List.map (fun (loc, v) -> $"{loc} = 0x{v:x}")
    |> String.concat "; "

  /// Asserts that a run raised the given side effects and changed exactly
  /// the given places to the given values.
  let raises effects expected (changed, raised: SideEffect list, skip) =
    let expected = expected |> List.filter (fst >> skip >> not)
    Assert.AreEqual<string>(show expected, show changed)
    CollectionAssert.AreEqual(List.toArray effects, List.toArray raised)

  /// Asserts that a run raised nothing and changed exactly the given places
  /// to the given values.
  let is expected outcome = raises [] expected outcome

  /// The jump control leaves the words by over the given values, as the
  /// address it goes to and the kind of the jump; the address after the last
  /// word, and no kind, where nothing leaves them.
  let private exitOf isa (hexes: string list) given =
    let outcome, _ = outcomeOf isa hexes given
    match outcome.Exit with
    | IRRunner.Left(target, kind) ->
      target, kind
    | IRRunner.Fallthrough ->
      let length = hexes |> List.sumBy (fun h -> uint64 h.Length / 2UL)
      at + length, InterJmpKind.NotAJmp

  /// Asserts that over the given values control goes to the target after
  /// the words: a branch, and a NOP in its delay slot where it has one.
  let goes isa hexes given (target: uint64) =
    Assert.AreEqual<uint64>(target, fst (exitOf isa hexes given))

  /// Asserts that over the given values the jump control leaves by switches
  /// to the encoding the kind names.
  let switches isa hexes given (kind: InterJmpKind) =
    let _, actual = exitOf isa hexes given
    Assert.AreEqual<InterJmpKind>(kind, actual &&& kind)

  /// Asserts whether a branch carries its own transfer, as a compact one
  /// does, rather than leaving it to the delay slot after it.
  let ownsJump isa hex expected =
    let owns =
      lift isa [ hex ]
      |> Array.exists (function
        | InterJmp _ | InterCJmp _ -> true
        | _ -> false)
    Assert.AreEqual<bool>(expected, owns)
