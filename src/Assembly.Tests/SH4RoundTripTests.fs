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
open B2R2.FrontEnd.SH4
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.SH4

/// Represents what happened when a reference encoding was round-tripped.
type internal SH4Outcome =
  /// The re-encoded word disassembles back to the text we started from.
  | SH4Preserved
  /// The re-encoded word means something other than the text we started from.
  | SH4Altered of actual: string
  /// The assembler cannot encode this instruction yet.
  | SH4Unsupported

/// <summary>
/// Checks the SH4 assembler against B2R2's own SH4 decoder. For each reference
/// encoding we disassemble it into canonical SH4 syntax, hand that text back to
/// the assembler, and disassemble the result again. Comparing the resulting
/// *text* rather than the bytes means that picking a valid-but-different
/// encoding is not a failure, while emitting a word that means something else
/// is.
///
/// Nothing here is a hand-written expectation, and nothing is a hand-written
/// input either: SH4Sweep walks every word there is and the decoder says what
/// each one means, so the set of instructions under test is whatever the
/// decoder currently understands. Forms that canonical disassembly cannot
/// express - labels above all - are pinned by the hand-written tests below.
/// </summary>
[<TestClass>]
type SH4RoundTripTests() =

  static let isa = ISA(Architecture.SH4, Endian.Little, WordSize.Bit32)

  /// One parser, reused across the whole sweep. The sweep asks for tens of
  /// thousands of decodings, so building one each time would dominate the run.
  static let parser =
    SH4Parser(BinReader.Init Endian.Little) :> IInstructionParsable

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
    | None -> SH4Unsupported
    | Some encoded ->
      let actual = try disasm encoded with _ -> "<undecodable>"
      if actual = source then SH4Preserved else SH4Altered actual

  /// Describes a probe whose text does not encode to a word meaning the same,
  /// naming the word it was decoded from so that a failure says where to look.
  static let brokenProbe (probe: SH4Probe) =
    let source = probe.Text
    match roundTrip source with
    | SH4Preserved -> None
    | SH4Altered actual ->
      Some $"0x{probe.Word:x4} '{source}' encoded as '{actual}'"
    | SH4Unsupported ->
      Some $"0x{probe.Word:x4} '{source}' is not encodable"

  /// Every probe the sweep produces. The sweep is the expensive part of this
  /// file, so it runs once for the class rather than once for each test that
  /// reads it.
  static let probes = lazy (SH4Sweep.probes ())

  /// The disassembler lines a mnemonic up in a column of its own, so what it
  /// writes between a name and the operands says nothing about the instruction.
  let squashed (text: string) =
    String.concat " " (text.Split(' ', StringSplitOptions.RemoveEmptyEntries))

  /// The instruction a place is written into, over and over, so that a label
  /// can be put far enough away to need most of the bits counting to it.
  let padding count = String.replicate count "  nop\n"

  /// <summary>
  /// The sources a branch to a label is tried in, each paired with the index of
  /// the instruction under test and the index its label marks.
  ///
  /// A label is reached from below as well as from above, and from far enough
  /// away that a distance one bit narrower would not reach it.
  /// </summary>
  let branchCases count source =
    let filler = padding count
    [ $"L:\n  nop\n  {source} L\n  nop", 1, 0
      $"  {source} L\n{filler}L:\n  nop", 0, count + 1
      $"L:\n{filler}  {source} L\n  nop", count, 0 ]

  /// Every instruction naming a place, paired with how many bits it says how
  /// far away that place is in and how far away the label is put.
  let branchSources =
    [ "bt", 8, 50
      "bts", 8, 50
      "bf", 8, 50
      "bfs", 8, 50
      "bra", 12, 900
      "bsr", 12, 900 ]

  /// Sources that name no instruction at all, either because a number does not
  /// fit where it is written or because a register cannot be named there.
  let unencodableSources =
    [ "add #256,r0"
      "add #-129,r0"
      "mov #256,r0"
      "movb r0,@(16,r1)"
      "movb r0,@(-1,r1)"
      "movb r1,@(3,r2)"
      "movl @(256,pc),r0"
      "mova @(3,r1),r0"
      "bf 256"
      "bf -129"
      "bra 4096"
      "bra -2049"
      "trapa r0"
      "trapa #256"
      "nop r0"
      "jmp r0"
      "jsr @r0+"
      "macl @r0,@r1"
      "stc sr,@r0"
      "stcl sr,r0"
      "stc mach,r0"
      "sts sr,r0"
      "ldc r0,sgr"
      "ldcl r0,gbr"
      "mov r0,fr1"
      "fadd r0,r1"
      "fmov dr0,dr2"
      "fcnvds fr0,fpul"
      "fmac fr1,fr2,fr3"
      "movcal r1,@r2"
      "frobnicate r0,r1"
      $"  bf L\n{padding 200}L:\n  nop" ]

  /// Sources written the way a person writes one rather than the way the
  /// disassembler does, each paired with the instruction it names.
  let writtenSources =
    [ "  mov.l @(4,r1),r2  ! what a person writes", "movl @(4,r1),r2"
      "MOV R1, R2", "mov r1,r2"
      "cmp/eq #-1,r0", "cmpeq #255,r0"
      "add #-1,r0", "add #255,r0"
      "add #0xf,r3", "add #15,r3"
      "bf/s 0x10", "bfs 16"
      "mov.b @( 3 , r4 ),r0", "movb @(3,r4),r0"
      "and.b #0b1010,@(r0,gbr)", "andb #10,@(r0,gbr)"
      "fmov.s @r1+,fr2", "fmovs @r1+,fr2"
      "mac.w @r1+,@r2+", "macw @r1+,@r2+"
      "ldc.l @r1+,r3_bank", "ldcl @r1+,r3_bank"
      "nop", "nop" ]

  /// <summary>
  /// Checks that the sweep reaches most of the encoding space.
  ///
  /// Every test below it says that nothing among the instructions it found is
  /// broken, which a sweep finding nothing at all would also say. Nine words in
  /// ten are an instruction, so a sweep that stops finding them has stopped
  /// working rather than found the truth.
  /// </summary>
  [<TestMethod>]
  [<TestCategory("Sweep")>]
  member _.``The sweep reaches most of the encoding space``() =
    Assert.IsGreaterThan(50000, List.length (probes.Force()))

  [<TestMethod>]
  [<TestCategory("Sweep")>]
  member _.``Every instruction the decoder decodes, the assembler encodes``() =
    let broken =
      probes.Force()
      |> List.choose brokenProbe
      |> List.distinct
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" broken,
      "These instructions decode but no longer encode, or encode to a word \
       that means something else.")

  /// <summary>
  /// Checks that a branch naming a label lands on the instruction that label
  /// marks, from either direction.
  ///
  /// What a branch holds is a distance counted from its own address plus four
  /// and measured in instructions, and what the disassembler writes there is
  /// that distance as the bits holding it. A branch written with a label is
  /// therefore checked against the same branch written with those bits, which
  /// the sweep above has already pinned.
  /// </summary>
  [<TestMethod>]
  member _.``Branches to a label reach it in both directions``() =
    let wrong =
      [ for name, width, count in branchSources do
          for source, index, marks in branchCases count name ->
            name, width, source, index, marks ]
      |> List.choose (fun (name, width, source, index, marks) ->
        let distance = 2L * int64 marks - 2L * int64 index - 4L
        let field = (distance / 2L) &&& ((1L <<< width) - 1L)
        let expected = encodeFirst assembler $"{name} {field}"
        match (try assembler.Lower source with _ -> Error "raised") with
        | Error _ | Ok [] -> Some $"'{name} L' does not assemble"
        | Ok encoded ->
          let actual = snd (List.item index encoded)
          if Some actual = expected then None
          else Some $"'{name} L' became '{disasm actual}'")
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
      "These ask for something no SH4 encoding can say.")

  /// Checks that a word comes out in the order the ISA stores its bytes in,
  /// which is the one thing about an encoding that the word itself cannot say.
  [<TestMethod>]
  member _.``The bytes come out in the order the ISA stores them``() =
    let isa = ISA(Architecture.SH4, Endian.Big, WordSize.Bit32)
    let bigEndian = Assembler(isa, 0UL) :> ILowerable
    let source = "add r1,r2"
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
  /// read: a source of its own separates the width an instruction works at from
  /// the rest of its name the way the manual does, writes a number below zero
  /// with a sign rather than as the bits it lands in, and says in a comment
  /// what it is doing.
  /// </summary>
  [<TestMethod>]
  member _.``A source may be written the way a person writes one``() =
    let wrong =
      writtenSources
      |> List.choose (fun (source, expected) ->
        match (try encodeFirst assembler source with _ -> None) with
        | None -> Some $"'{source}' does not assemble"
        | Some bytes ->
          let text = try squashed (disasm bytes) with _ -> "<undecodable>"
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
      match assembler.Lower "  nop\n  add r1,r2" with
      | Ok [ _; _ ] -> ()
      | Ok _ | Error _ -> Assert.Fail $"'{bad}' left the assembler unusable"

// vim: set tw=80 sts=2 sw=2:
