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

namespace B2R2.Assembly.Tests

open System
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.RISCV64
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.RISCV64

/// Represents what happened when a reference encoding was round-tripped.
type internal RISCV64Outcome =
  /// The re-encoded word disassembles back to the text we started from.
  | RISCV64Preserved
  /// The re-encoded word means something other than the text we started from.
  | RISCV64Altered of actual: string
  /// The assembler cannot encode this instruction yet.
  | RISCV64Unsupported

/// <summary>
/// Checks the RISCV64 assembler against B2R2's own RISCV64 decoder. For each
/// reference encoding we disassemble it into canonical RISCV64 syntax, hand
/// that text back to the assembler, and disassemble the result again. Comparing
/// the resulting *text* rather than the bytes means that picking a
/// valid-but-different encoding is not a failure, while emitting a word that
/// means something else is. A compressed instruction round-trips through the
/// full-width instruction the disassembler writes it as, which is what makes
/// this comparison the right one here.
///
/// Nothing here is a hand-written expectation, and nothing is a hand-written
/// input either: RISCV64Sweep walks the encoding space and the decoder says
/// what each word means, so the set of instructions under test is whatever the
/// decoder currently understands. Forms that canonical disassembly cannot
/// express - labels above all - are pinned by the hand-written tests below.
/// </summary>
[<TestClass>]
type RISCV64RoundTripTests() =

  static let isa = ISA(Architecture.RISCV, Endian.Little, WordSize.Bit64)

  /// One parser, reused across the whole sweep. The sweep asks for millions of
  /// decodings, so building one each time would dominate the run.
  static let parser =
    RISCV64Parser(isa, BinReader.Init Endian.Little) :> IInstructionParsable

  static let assembler = Assembler(isa, 0UL) :> ILowerable

  static let disasm (bytes: byte[]) = (parser.Parse(bytes, 0UL)).Disasm()

  static let encodeFirst (assembler: ILowerable) text =
    match assembler.Lower text with
    | Ok((_, bytes) :: _) -> Some bytes
    | Ok [] | Error _ -> None

  /// Encodes the given source and disassembles the result, so that a source
  /// text stands in for the word a probe was decoded from.
  static let roundTrip (source: string) =
    match (try encodeFirst assembler source with _ -> None) with
    | None -> RISCV64Unsupported
    | Some encoded ->
      let actual = try disasm encoded with _ -> "<undecodable>"
      if actual = source then RISCV64Preserved else RISCV64Altered actual

  /// Describes a source that does not encode to a word meaning the same.
  static let brokenSource source =
    match roundTrip source with
    | RISCV64Preserved -> None
    | RISCV64Altered actual -> Some $"'{source}' encoded as '{actual}'"
    | RISCV64Unsupported -> Some $"'{source}' is not encodable"

  /// Every probe the sweep produces. The sweep is the expensive part of this
  /// file, so it runs once for the class rather than once for each test that
  /// reads it.
  static let probes = lazy (RISCV64Sweep.probes ())

  /// The instruction a place is written into, over and over, so that a label
  /// can be put out of reach of the instruction naming it. What does nothing at
  /// all is written as a half-width instruction, so what is written here is an
  /// instruction of full width that changes nothing.
  let padding = String.replicate 200 "  add zero, zero, zero\n"

  /// <summary>
  /// The sources a branch to a label is tried in, each paired with the index of
  /// the instruction under test and the address its label sits at.
  ///
  /// A label is reached from below as well as from above, and from far enough
  /// away that an offset holding too few bits would not reach it.
  /// </summary>
  let branchCases source =
    [ $"L:\n  add zero, zero, zero\n  {source}\n  add zero, zero, zero",
      1, 0x0UL
      $"  {source}\n{padding}L:\n  add zero, zero, zero", 0, 0x324UL
      $"L:\n{padding}  {source}\n  add zero, zero, zero", 200, 0x0UL ]

  /// Every instruction that names a place, paired with how the disassembler
  /// writes it once it has resolved one.
  let branchSources =
    [ "beq a0, a1, L", "beq a0, a1,"
      "bne a0, a1, L", "bne a0, a1,"
      "blt a0, a1, L", "blt a0, a1,"
      "bge a0, a1, L", "bge a0, a1,"
      "bltu a0, a1, L", "bltu a0, a1,"
      "bgeu a0, a1, L", "bgeu a0, a1,"
      "jal ra, L", "jal ra,"
      "jal zero, L", "jal zero," ]

  /// Sources that name no instruction at all, either because a number does not
  /// fit where it is written or because a register cannot be named there.
  let unencodableSources =
    [ "addi a0, a1, 0x800"
      "addi a0, a1, -2049"
      "lui a0, 0x100000"
      "lw a0, 0x800(a1)"
      "sd a1, -2049(a0)"
      "slli a0, a1, 0x40"
      "srliw a0, a1, 0x20"
      "csrrw a0, 0x1000, a1"
      "csrrwi a0, 0x1, 0x20"
      "beq a0, a1, 0x1"
      "beq a0, a1, 0x2000"
      "jal ra, 0x1"
      "jal ra, 0x100000"
      "add fa0, a1, a2"
      "fadd.s a0, fa1, fa2"
      "flw a0, 0x0(a1)"
      "amoswap.w a0, a1, 0x8(a2)"
      "add a0, a1"
      "nop a0"
      "frobnicate a0, a1" ]

  /// Sources written the way a person writes one rather than the way the
  /// disassembler does, each paired with the instruction it names.
  let writtenSources =
    [ "  addi a0, a1, 1  # what a person writes", "addi a0, a1, 0x1"
      "addi x10, x11, 0x1 ; and the other way of saying so", "addi a0, a1, 0x1"
      "ADDI A0, A1, 0x1", "addi a0, a1, 0x1"
      "addi a0, a1, -1", "addi a0, a1, 0xffffffffffffffff"
      "lw a0, (a1)", "lw a0, 0(a1)"
      "lw a0, -8(a1)", "lw a0, -8(a1)"
      "jalr ra, -8(a0)", "jalr ra, 18446744073709551608(a0)"
      "lr.w a0, 0(a1)", "lr.w a0, (a1)"
      "amoswap.w a0, a1, (a2)aqrl", "amoswap.w a0, a1, (a2)aqrl"
      "fadd.s fa0, fa1, fa2", "fadd.s fa0, fa1, fa2"
      "fadd.s fa0, fa1, fa2, rtz", "fadd.s fa0, fa1, fa2, rtz"
      "fence iorw,iorw", "fence iorw,iorw"
      "fence ,w", "fence ,w" ]

  [<TestMethod>]
  [<TestCategory("Sweep")>]
  member _.``Every instruction the decoder decodes, the assembler encodes``() =
    let broken =
      probes.Force()
      |> List.choose (fun probe -> brokenSource probe.Text)
      |> List.distinct
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" broken,
      "These instructions decode but no longer encode, or encode to a word \
       that means something else.")

  [<TestMethod>]
  member _.``Branches to a label reach it in both directions``() =
    let wrong =
      [ for written, expected in branchSources do
          for source, index, target in branchCases written ->
            expected, source, index, target ]
      |> List.choose (fun (expected, source, index, target) ->
        match (try assembler.Lower source with _ -> Error "raised") with
        | Error _ | Ok [] -> Some $"'{expected} L' does not assemble"
        | Ok encoded ->
          let addr = uint64 (4 * index)
          let text =
            try (parser.Parse(snd (List.item index encoded), addr)).Disasm()
            with _ -> "<undecodable>"
          if text = $"{expected} 0x{target:x}" then None
          else Some $"'{expected} L' at 0x{addr:x} became '{text}'")
      |> List.distinct
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" wrong,
      "These branches no longer reach the instruction their label marks.")

  /// <summary>
  /// Checks that a source asking for what no encoding can say is refused rather
  /// than encoded.
  ///
  /// A field that silently drops what does not fit encodes an instruction the
  /// source did not ask for, which is worse than encoding nothing at all.
  /// </summary>
  [<TestMethod>]
  member _.``A source no encoding can say does not encode``() =
    let encoded =
      unencodableSources
      |> List.choose (fun source ->
        match (try encodeFirst assembler source with _ -> None) with
        | None -> None
        | Some bytes ->
          let text = try disasm bytes with _ -> "<undecodable>"
          Some $"'{source}' encoded as '{text}'")
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" encoded,
      "These ask for something no RISCV64 encoding can say.")

  /// Checks that a word comes out in the order the ISA stores its bytes in,
  /// which is the one thing about an encoding that the word itself cannot say.
  [<TestMethod>]
  member _.``The bytes come out in the order the ISA stores them``() =
    let isa = ISA(Architecture.RISCV, Endian.Big, WordSize.Bit64)
    let bigEndian = Assembler(isa, 0UL) :> ILowerable
    let source = "addi a0, a1, 0x1"
    let hex (bytes: byte[]) = Convert.ToHexString bytes
    match encodeFirst bigEndian source, encodeFirst assembler source with
    | Some big, Some little ->
      Assert.AreEqual<string>(hex (Array.rev little), hex big)
    | _ -> Assert.Fail $"'{source}' does not assemble"

  /// <summary>
  /// Checks that a source written the way a person writes one names the same
  /// instruction as the canonical text for it.
  ///
  /// What the disassembler writes is only part of what an assembler has to
  /// read: a source of its own writes a register by its number, writes a number
  /// below zero with a sign rather than as the bits it lands in, leaves out
  /// what it means to be zero, and says in a comment what it is doing.
  /// </summary>
  [<TestMethod>]
  member _.``A source may be written the way a person writes one``() =
    let wrong =
      writtenSources
      |> List.choose (fun (source, expected) ->
        match (try encodeFirst assembler source with _ -> None) with
        | None -> Some $"'{source}' does not assemble"
        | Some bytes ->
          let text = try disasm bytes with _ -> "<undecodable>"
          if text = expected then None
          else Some $"'{source}' encoded as '{text}'")
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" wrong,
      "These are no longer read as the instruction they name.")

  /// Checks that a source the assembler refuses leaves it able to read the next
  /// one, which a parser keeping state across a failure would not.
  [<TestMethod>]
  member _.``A refused source leaves the assembler usable``() =
    for bad in unencodableSources do
      (try encodeFirst assembler bad |> ignore with _ -> ())
      match assembler.Lower "  nop\n  addi a0, a1, 0x1" with
      | Ok [ _; _ ] -> ()
      | Ok _ | Error _ -> Assert.Fail $"'{bad}' left the assembler unusable"

// vim: set tw=80 sts=2 sw=2:
