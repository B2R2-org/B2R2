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
open B2R2.FrontEnd.BPF
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.BPF

/// Represents what happened when a reference encoding was round-tripped.
type internal BPFOutcome =
  /// The re-encoded word disassembles back to the text we started from.
  | BPFPreserved
  /// The re-encoded word means something other than the text we started from.
  | BPFAltered of actual: string
  /// The assembler cannot encode this instruction yet.
  | BPFUnsupported

/// <summary>
/// Checks the eBPF assembler against B2R2's own eBPF decoder. For each
/// reference encoding we disassemble it into canonical eBPF syntax, hand that
/// text back to the assembler, and disassemble the result again. Comparing the
/// resulting *text* rather than the bytes means that picking a
/// valid-but-different encoding is not a failure, while emitting a word that
/// means something else is.
///
/// Nothing here is a hand-written expectation, and nothing is a hand-written
/// input either: BPFSweep walks the encoding space and the decoder says what
/// each word means, so the set of instructions under test is whatever the
/// decoder currently understands. Forms that canonical disassembly cannot
/// express - labels above all - are pinned by the hand-written tests below.
/// </summary>
[<TestClass>]
type BPFRoundTripTests() =

  static let isa = ISA Architecture.BPF

  /// One parser, reused across the whole sweep. The sweep asks for hundreds of
  /// thousands of decodings, so building one each time would dominate the run.
  static let parser =
    BPFParser(BinReader.Init Endian.Little) :> IInstructionParsable

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
    | None ->
      BPFUnsupported
    | Some encoded ->
      let actual = try disasm encoded with _ -> "<undecodable>"
      if actual = source then BPFPreserved else BPFAltered actual

  /// Describes a source that does not encode to a word meaning the same.
  static let brokenSource source =
    match roundTrip source with
    | BPFPreserved -> None
    | BPFAltered actual -> Some $"'{source}' encoded as '{actual}'"
    | BPFUnsupported -> Some $"'{source}' is not encodable"

  /// Every probe the sweep produces. The sweep is the expensive part of this
  /// file, so it runs once for the class rather than once for each test that
  /// reads it.
  static let probes = lazy (BPFSweep.probes ())

  /// The instruction a place is written into, over and over, so that a label
  /// can be put out of reach of the instruction naming it. The machine spends
  /// no encoding on doing nothing, so this is a move of a register into itself.
  let filler = "mov r0, r0"

  let padding = String.replicate 200 $"  {filler}\n"

  /// <summary>
  /// The sources a jump to a label is tried in, each paired with the index of
  /// the instruction under test and how far away its label then is.
  ///
  /// A label is reached from below as well as from above, and from far enough
  /// away that the distance is more than a single instruction.
  /// </summary>
  let jumpCases source =
    [ $"L:\n  {filler}\n  {source}\n  {filler}", 1, -0x10L
      $"  {source}\n{padding}L:\n  {filler}", 0, 0x640L
      $"L:\n{padding}  {source}\n  {filler}", 200, -0x648L ]

  /// Every instruction that names a place, paired with how the disassembler
  /// writes it once it has worked out how far away that place is.
  let jumpSources =
    [ "ja L", "ja"
      "gotol L", "gotol"
      "jeq r1, r2, L", "jeq r1, r2,"
      "jne r1, 0x5, L", "jne r1, 0x5,"
      "jsle32 r1, r2, L", "jsle32 r1, r2,"
      "call_local L", "call_local" ]

  /// Sources that name no instruction at all, either because a number does not
  /// fit where it is written, because a register cannot be named there, or
  /// because the operands do not belong to the mnemonic.
  let unencodableSources =
    [ "ldxw r1, [r2+0x8000]"
      "ldxw r1, [r2+-32769]"
      (* A number the encoding reads as signed is written either with a sign or
         as the whole word it was widened to, never as the bits of the field it
         lands in, because those alone do not say how wide the field is. *)
      "ldxw r1, [r2+0xfff8]"
      "mov r1, 0x100000000"
      "ja 0x4"
      "ja 0x100000"
      "gotol 0x4"
      "call_local 0x4"
      "mov pc, r1"
      "mov r1, r2, r3"
      "add r1"
      "exit r1"
      "movsx r1, r2, 0x40"
      "movsx32 r1, r2, 0x20"
      "movsx r1, 0x8, 0x8"
      "le16 r1, r2"
      "lddw r1"
      "ldxw r1, r2"
      "stw [r1+0x0]"
      "stxw [r1+0x0], 0x5"
      "atomic_add_w r1, r2"
      "atomic_add_w [r1+0x0], 0x5"
      "ldabsw r1, 0x10"
      "frobnicate r1, r2" ]

  /// Sources written the way a person writes one rather than the way the
  /// disassembler does, each paired with the instruction it names.
  let writtenSources =
    [ "  add r1, r2  # what a person writes", "add r1, r2"
      "ADD R1, R2", "add r1, r2"
      "add r1,r2", "add r1, r2"
      "ldxw r1, [r2+16]", "ldxw r1, [r2+0x10]"
      "ldxw r1, [r2+-8]", "ldxw r1, [r2+0xfffffff8]"
      "ldxw r1, [ r2 + 0 ]", "ldxw r1, [r2+0x0]"
      "mov r1, 0b101", "mov r1, 0x5"
      "mov r1, fp", "mov r1, r10"
      "call 131", "call 0x83"
      "exit", "exit" ]

  [<TestMethod>]
  [<TestCategory("Sweep")>]
  member _.``Every instruction the decoder decodes, the assembler encodes``() =
    let broken =
      probes.Force()
      |> List.choose brokenSource
      |> List.distinct
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" broken,
      "These instructions decode but no longer encode, or encode to a word \
       that means something else."
    )

  /// <summary>
  /// Checks that the sweep reaches every instruction there is.
  ///
  /// What the sweep walks is the fields that name an instruction, and it keeps
  /// one probe per distinct operand shape; an instruction the walk never
  /// reaches is one the test above says nothing about, and it would say nothing
  /// silently. Every mnemonic the opcode enumeration spells therefore has to
  /// appear among the probes.
  /// </summary>
  [<TestMethod>]
  [<TestCategory("Sweep")>]
  member _.``The sweep reaches every instruction there is``() =
    let reached =
      probes.Force()
      |> List.map (fun text -> text.Split(' ')[0])
      |> Set.ofList
    let missing =
      Enum.GetValues typeof<Opcode>
      |> Seq.cast<Opcode>
      |> Seq.map Opcode.toString
      |> Seq.filter (fun name -> not (Set.contains name reached))
      |> Seq.toList
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" missing,
      "The sweep never reaches these, so nothing checks that they encode."
    )

  [<TestMethod>]
  member _.``Jumps to a label reach it in both directions``() =
    let wrong =
      [ for written, expected in jumpSources do
          for source, index, distance in jumpCases written ->
            expected, source, index, distance ]
      |> List.choose (fun (expected, source, index, distance) ->
        match (try assembler.Lower source with _ -> Error "raised") with
        | Error _ | Ok [] ->
          Some $"'{expected} L' does not assemble"
        | Ok encoded ->
          let addr = uint64 (8 * index)
          let text =
            try (parser.Parse(snd (List.item index encoded), addr)).Disasm()
            with _ -> "<undecodable>"
          if text = $"{expected} 0x{distance:x}" then None
          else Some $"'{expected} L' at 0x{addr:x} became '{text}'")
      |> List.distinct
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" wrong,
      "These jumps no longer reach the instruction their label marks."
    )

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
        | None ->
          None
        | Some bytes ->
          let text = try disasm bytes with _ -> "<undecodable>"
          Some $"'{source}' encoded as '{text}'")
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" encoded,
      "These ask for something no eBPF encoding can say."
    )

  /// <summary>
  /// Checks that a word comes out in the order the ISA stores its bytes in.
  ///
  /// This is the one thing about an eBPF encoding that the word itself cannot
  /// say, and the one architecture-level choice a loader makes: which nibble of
  /// the second byte names which register follows the order the bytes are
  /// stored in, so the two orders differ in more than the halfword and the word
  /// below that byte.
  /// </summary>
  [<TestMethod>]
  member _.``The bytes come out in the order the ISA stores them``() =
    let big = Assembler(ISA(Architecture.BPF, Endian.Big), 0UL) :> ILowerable
    let source = "ldxw r1, [r2+0x8]"
    match encodeFirst assembler source, encodeFirst big source with
    | Some little, Some big ->
      Assert.AreEqual<string>("6121080000000000", Convert.ToHexString(little)
                                                            .ToLowerInvariant())
      Assert.AreEqual<string>("6112000800000000", Convert.ToHexString(big)
                                                            .ToLowerInvariant())
    | _ ->
      Assert.Fail $"'{source}' does not assemble"

  /// <summary>
  /// Checks that a source written the way a person writes one names the same
  /// instruction as the canonical text for it.
  ///
  /// What the disassembler writes is only part of what an assembler has to
  /// read: a source of its own writes a number below zero with a sign rather
  /// than as the bits it lands in, leaves out the spaces the disassembler puts
  /// after a comma, and says in a comment what it is doing.
  /// </summary>
  [<TestMethod>]
  member _.``A source may be written the way a person writes one``() =
    let wrong =
      writtenSources
      |> List.choose (fun (source, expected) ->
        match (try encodeFirst assembler source with _ -> None) with
        | None ->
          Some $"'{source}' does not assemble"
        | Some bytes ->
          let text = try disasm bytes with _ -> "<undecodable>"
          if text = expected then None
          else Some $"'{source}' encoded as '{text}'")
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" wrong,
      "These are no longer read as the instruction they name."
    )

  /// Checks that a source the assembler refuses leaves it able to read the next
  /// one, which a parser keeping state across a failure would not.
  [<TestMethod>]
  member _.``A refused source leaves the assembler usable``() =
    for bad in unencodableSources do
      (try encodeFirst assembler bad |> ignore with _ -> ())
      match assembler.Lower $"  {filler}\n  add r1, r2" with
      | Ok [ _; _ ] -> ()
      | Ok _ | Error _ -> Assert.Fail $"'{bad}' left the assembler unusable"

// vim: set tw=80 sts=2 sw=2:
