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
open B2R2.FrontEnd.Alpha
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.Alpha

/// Represents what happened when a reference encoding was round-tripped.
type internal AlphaOutcome =
  /// The re-encoded word disassembles back to the text we started from.
  | AlphaPreserved
  /// The re-encoded word means something other than the text we started from.
  | AlphaAltered of actual: string
  /// The assembler cannot encode this instruction yet.
  | AlphaUnsupported

/// <summary>
/// Checks the Alpha assembler against B2R2's own Alpha decoder. For each
/// reference encoding we disassemble it into canonical Alpha syntax, hand that
/// text back to the assembler, and disassemble the result again. Comparing the
/// resulting *text* rather than the bytes means that picking a
/// valid-but-different encoding is not a failure, while emitting a word that
/// means something else is. The architecture leaves every register field an
/// instruction does not use free, and the disassembler writes nothing for one,
/// so text is also the only thing the two ends of this agree on.
///
/// Nothing here is a hand-written expectation, and nothing is a hand-written
/// input either: AlphaSweep walks the encoding space and the decoder says what
/// each word means, so the set of instructions under test is whatever the
/// decoder currently understands. Forms that canonical disassembly cannot
/// express - labels above all - are pinned by the hand-written tests below.
/// </summary>
[<TestClass>]
type AlphaRoundTripTests() =

  static let isa = ISA(Architecture.Alpha, Endian.Little, WordSize.Bit64)

  /// One parser, reused across the whole sweep. The sweep asks for hundreds of
  /// thousands of decodings, so building one each time would dominate the run.
  static let parser =
    AlphaParser(BinReader.Init Endian.Little) :> IInstructionParsable

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
      AlphaUnsupported
    | Some encoded ->
      let actual = try disasm encoded with _ -> "<undecodable>"
      if actual = source then AlphaPreserved else AlphaAltered actual

  /// Describes a source that does not encode to a word meaning the same.
  static let brokenSource source =
    match roundTrip source with
    | AlphaPreserved -> None
    | AlphaAltered actual -> Some $"'{source}' encoded as '{actual}'"
    | AlphaUnsupported -> Some $"'{source}' is not encodable"

  /// Every probe the sweep produces. The sweep is the expensive part of this
  /// file, so it runs once for the class rather than once for each test that
  /// reads it.
  static let probes = lazy (AlphaSweep.probes ())

  /// The instruction a place is written into, over and over, so that a label
  /// can be put out of reach of the instruction naming it. The architecture
  /// spends no encoding of its own on doing nothing, so this is the logical sum
  /// of the register that always reads as zero with itself.
  let filler = "bis r31, r31, r31"

  let padding = String.replicate 200 $"  {filler}\n"

  /// <summary>
  /// The sources a branch to a label is tried in, each paired with the index of
  /// the instruction under test and how far away its label then is.
  ///
  /// A label is reached from below as well as from above, and from far enough
  /// away that the distance is more than a single instruction.
  /// </summary>
  let branchCases source =
    [ $"L:\n  {filler}\n  {source}\n  {filler}", 1, -8
      $"  {source}\n{padding}L:\n  {filler}", 0, 0x320
      $"L:\n{padding}  {source}\n  {filler}", 200, -0x324 ]

  /// Every instruction that names a place, paired with how the disassembler
  /// writes it once it has worked out how far away that place is.
  let branchSources =
    [ "br r31, L", "br r31,"
      "bsr r26, L", "bsr r26,"
      "beq r1, L", "beq r1,"
      "bne r1, L", "bne r1,"
      "blbc r1, L", "blbc r1,"
      "fbeq f1, L", "fbeq f1,"
      "fblt f2, L", "fblt f2," ]

  /// Sources that name no instruction at all, either because a number does not
  /// fit where it is written, because a register cannot be named there, or
  /// because the instruction does not take the qualifier hung off its name.
  let unencodableSources =
    [ "lda r1, 0x8000(r30)"
      "lda r1, -32769(r30)"
      (* A number the encoding reads as signed is written either with a sign or
         as the whole word it was widened to, never as the bits of the field it
         lands in, because those alone do not say how wide the field is. *)
      "stq r1, 0xfff8(r30)"
      "addq r1, 0x100, r3"
      "br r31, 0x1"
      "br r31, 0x400000"
      "jsr r26, (r27), 0x4000"
      "call_pal 0x4000000"
      "adds r1, f2, f3"
      "addq f1, r2, r3"
      "mt_fpcr r1"
      "ftois r1, r3"
      "itofs f1, f3"
      "addq pc, r2, r3"
      "addq r1, r2"
      "ldq r1, r2"
      "ldq r1, (r30)"
      "prefetch (r16)"
      "fetch r16"
      "fetch 0x0(r16)"
      "rpcc (r16)"
      "mb r1"
      "implver r1, r2"
      "br r31, r1"
      "cvtst f1, f2, f3"
      "adds f1, f2"
      "and/v r1, r2, r3"
      "ldq/v r1, 0x0(r30)"
      "adds/v f1, f2, f3"
      "adds/xyz f1, f2, f3"
      "cmpteq/d f1, f2, f3"
      "cvtqs/u f2, f3"
      "cvttq/sui f2, f3"
      "cvtqf/m f2, f3"
      "frobnicate r1, r2" ]

  /// Sources written the way a person writes one rather than the way the
  /// disassembler does, each paired with the instruction it names.
  let writtenSources =
    [ "  addq r1, r2, r3  # what a person writes", "addq r1, r2, r3"
      "ADDQ R1, R2, R3", "addq r1, r2, r3"
      "addq r1,r2,r3", "addq r1, r2, r3"
      "lda r1, 16(r30)", "lda r1, 0x10(r30)"
      "lda r1, -8(r30)", "lda r1, 0xfffffff8(r30)"
      "lda r1, 0 ( r30 )", "lda r1, 0x0(r30)"
      "sll r1, 0b101, r3", "sll r1, 0x5, r3"
      "call_pal 131", "call_pal 0x83"
      "ADDS/SUID f1, f2, f3", "adds/suid f1, f2, f3"
      "jsr r26, ( r27 ), 0", "jsr r26, (r27), 0x0"
      "mb", "mb" ]

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
       that means something else."
    )

  [<TestMethod>]
  member _.``Branches to a label reach it in both directions``() =
    let wrong =
      [ for written, expected in branchSources do
          for source, index, distance in branchCases written ->
            expected, source, index, distance ]
      |> List.choose (fun (expected, source, index, distance) ->
        match (try assembler.Lower source with _ -> Error "raised") with
        | Error _ | Ok [] ->
          Some $"'{expected} L' does not assemble"
        | Ok encoded ->
          let addr = uint64 (4 * index)
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
      "These branches no longer reach the instruction their label marks."
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
      "These ask for something no Alpha encoding can say."
    )

  /// Checks that a word comes out in the order the ISA stores its bytes in,
  /// which is the one thing about an encoding that the word itself cannot say.
  /// Alpha is little-endian and has no other order to be read in, so what is
  /// pinned here is that order itself rather than a choice between two.
  [<TestMethod>]
  member _.``The bytes come out in the order the ISA stores them``() =
    let source = "addq r1, r2, r3"
    match encodeFirst assembler source with
    | Some bytes ->
      Assert.AreEqual<string>("03042240", Convert.ToHexString bytes)
    | None ->
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
      match assembler.Lower $"  {filler}\n  addq r1, r2, r3" with
      | Ok [ _; _ ] -> ()
      | Ok _ | Error _ -> Assert.Fail $"'{bad}' left the assembler unusable"

// vim: set tw=80 sts=2 sw=2:
