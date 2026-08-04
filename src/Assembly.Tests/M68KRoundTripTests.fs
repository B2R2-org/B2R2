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
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.M68K

/// Represents what happened when a reference encoding was round-tripped.
type internal M68KOutcome =
  /// The re-encoded instruction disassembles back to the text we started from.
  | M68KPreserved
  /// The re-encoded instruction means something other than that text.
  | M68KAltered of actual: string
  /// The assembler cannot encode this instruction yet.
  | M68KUnsupported

/// <summary>
/// Checks the m68k assembler against B2R2's own m68k decoder. For each
/// reference encoding we disassemble it into canonical m68k syntax, hand that
/// text back to the assembler, and disassemble the result again. Comparing the
/// resulting *text* rather than the bytes means that picking a
/// valid-but-different encoding is not a failure, while emitting an instruction
/// that means something else is.
///
/// Nothing here is a hand-written expectation, and nothing is a hand-written
/// input either: M68KSweep walks the encoding space and the decoder says what
/// each word means, so the set of instructions under test is whatever the
/// decoder currently understands. Three members of the family are checked,
/// because the family shares one encoding space and each model both added to it
/// and dropped from it, so which instructions exist is not one question but
/// several. Forms that canonical disassembly cannot express - labels above all
/// - are pinned by the hand-written tests below.
/// </summary>
[<TestClass>]
type M68KRoundTripTests() =

  static let isaOf (model: M68KModel) = ISA model

  static let assemblerOf model = Assembler(isaOf model, 0UL) :> ILowerable

  /// One parser per model, reused across the whole sweep. The sweep asks for
  /// millions of decodings, so building one each time would dominate the run.
  static let parser = M68KSweep.parserFor M68KModel.M68020

  static let parser40 = M68KSweep.parserFor M68KModel.M68040

  static let parser00 = M68KSweep.parserFor M68KModel.M68000

  static let assembler = assemblerOf M68KModel.M68020

  static let assembler40 = assemblerOf M68KModel.M68040

  static let assembler00 = assemblerOf M68KModel.M68000

  static let disasmWith (parser: IInstructionParsable) (bytes: byte[]) =
    (parser.Parse(bytes, 0UL)).Disasm()

  static let disasm bytes = disasmWith parser bytes

  static let encodeFirst (assembler: ILowerable) text =
    match assembler.Lower text with
    | Ok((_, bytes) :: _) -> Some bytes
    | Ok [] | Error _ -> None

  /// Encodes the given source and disassembles the result, so that a source
  /// text stands in for the word a probe was decoded from.
  static let roundTripWith assembler parser (source: string) =
    match (try encodeFirst assembler source with _ -> None) with
    | None -> M68KUnsupported
    | Some encoded ->
      let actual = try disasmWith parser encoded with _ -> "<undecodable>"
      if actual = source then M68KPreserved else M68KAltered actual

  /// Describes a source that does not encode to something meaning the same.
  static let brokenSource assembler parser source =
    match roundTripWith assembler parser source with
    | M68KPreserved -> None
    | M68KAltered actual -> Some $"'{source}' encoded as '{actual}'"
    | M68KUnsupported -> Some $"'{source}' is not encodable"

  /// Every probe the sweep produces for a 68020, which is the model that reads
  /// the most of the encoding space. The sweep is the expensive part of this
  /// file, so it runs once for the class rather than once for each test that
  /// reads it.
  static let probes = lazy (M68KSweep.probes M68KModel.M68020)

  /// The probes a 68040 reads, which is where the cache, translation, and block
  /// move instructions are and where the arithmetic rounding to a narrower
  /// precision is.
  static let probes40 = lazy (M68KSweep.probes M68KModel.M68040)

  /// The probes a 68000 reads, which is the part of the encoding space the
  /// whole of the family shares.
  static let probes00 =
    lazy (M68KSweep.readableBy M68KModel.M68000 (probes.Force()))

  /// Every instruction the assembler is handed, said in what a source hands it,
  /// having been sorted and thinned so that the failure names each broken
  /// instruction once.
  static let brokenSources assembler parser texts =
    texts
    |> List.choose (brokenSource assembler parser)
    |> List.distinct
    |> List.sort
    |> String.concat "\n"

  /// The instruction a place is written into, over and over, so that a label
  /// can be put out of reach of the instruction naming it. It is two bytes
  /// long, which is the shortest an m68k instruction gets.
  let padding = String.replicate 200 "  nop\n"

  /// <summary>
  /// The sources a branch to a label is tried in, each paired with the index of
  /// the instruction under test and the index of the one its label marks.
  ///
  /// A label is reached from below as well as from above, and from far enough
  /// away that a field holding too few bits would not reach it.
  /// </summary>
  let branchCases source =
    [ $"L:\n  nop\n  {source}\n  nop", 1, 0
      $"  {source}\n{padding}L:\n  nop", 0, 201
      $"L:\n{padding}  {source}\n  nop", 200, 0 ]

  /// Every instruction that names a place, as the source naming it with a label
  /// and what the disassembler writes for that instruction. The mark stands for
  /// how far away the place is and where it ends up, which the disassembler
  /// writes after the operands for a branch and in the middle of them for the
  /// one counting a register down.
  let branchSources =
    [ "bra.w L", "bra.w @"
      "bra.l L", "bra.l @"
      "bsr.w L", "bsr.w @"
      "beq.w L", "beq.w @"
      "bne.l L", "bne.l @"
      "dbf.w d0, L", "dbf.w d0, @"
      "dbeq.w d3, L", "dbeq.w d3, @"
      "fbeq.w L", "fbeq.w @"
      "fbne.l L", "fbne.l @"
      "fdbf.w d1, L", "fdbf.w d1, @" ]

  /// Sources that name no instruction at all, either because a number does not
  /// fit where it is written, because a register cannot be named there, or
  /// because the instruction is written with the wrong things after it.
  let unencodableSources =
    [ "move.b a0, d0"
      "move.b d0, a0"
      "move.l d0, a0"
      "movea.b (a0), a1"
      "moveq.w #0x1, d0"
      "moveq.l #0x100, d0"
      "addq.b #0x9, d0"
      "addq.b #0x0, d0"
      "addq.b #0x1, a0"
      "asr.w #0x9, d0"
      "asr.b (a0)"
      "bra.b +0x0"
      "bra.b +0x100"
      "bra.w +0x10000"
      "trap #0x10"
      "bkpt #0x8"
      "lea.l (a0)+, a1"
      "lea.l d0, a1"
      "pea.l -(a0)"
      "jmp (a0)+"
      "movem.w d0-d7, (a0)+"
      "movem.w (a0), -(a1)"
      "clr.b a0"
      "exg.l a0, d0"
      "cmpm.b (a0), (a1)+"
      "bfins d0, (a0){0x0:0x21}"
      "bftst (a0){0x20:0x1}"
      "bftst (a0)+{0x0:0x1}"
      "link.w a0, #0x10000"
      "stop #0x10000"
      "movec.l d0, d1"
      "fmove.x fp0, d0"
      "fmovem.l fpcr, (a0)"
      "fmove.l fpcr/fpsr, (a0)"
      "fmove.p fp0, (a0)"
      "cas.b d0, d1, d2"
      "move.l d0"
      "move.l d0, d1, d2"
      "add.l d0, #0x1"
      "frobnicate d0, d1" ]

  /// Sources written the way a person writes one rather than the way the
  /// disassembler does, each paired with the instruction it names.
  let writtenSources =
    [ "  move.l d0, d1  ; what a person writes", "move.l d0, d1"
      "MOVE.L D0, D1", "move.l d0, d1"
      "move.l 8(a0), d1", "move.l (0x8,a0), d1"
      "move.l -8(a0), d1", "move.l (-0x8,a0), d1"
      "move.l 8(a0,d1.w), d2", "move.l (0x8,a0,d1.w), d2"
      "move.l ( 0x8 , a0 ), d1", "move.l (0x8,a0), d1"
      "addi.l #-1, d0", "addi.l #0xffffffff, d0"
      "moveq.l #-1, d0", "moveq.l #-0x1, d0"
      "movem.w d0/d1/d2/d3/d4/d5/d6/d7, -(a0)", "movem.w d0-d7, -(a0)"
      "movem.l d0-a7, (a0)", "movem.l d0-a7, (a0)"
      "movem.l d3, (a0)", "movem.l d3, (a0)"
      "nop", "nop"
      "rts", "rts"
      "bra +0x10", "bra.w +0x10 ; 0x12"
      "bra 0x10", "bra.w +0xe ; 0x10"
      "jmp 0x1234", "jmp 0x1234"
      "jmp 0x12345678", "jmp 0x12345678"
      "fmove.x fp0, fp1", "fmove.x fp0, fp1" ]

  /// One instruction of each length an m68k instruction has, paired with how
  /// many bytes long it is. How long one is comes from the addressing modes its
  /// operands use and from nothing else, there being no field of the opcode
  /// word that says it.
  let lengths =
    [ "nop", 2
      "move.l d0, d1", 2
      "move.l (0x8,a0), d1", 4
      "move.l 0x12345678, d1", 6
      "move.l (0x8,a0), (0x4,a1)", 6
      "movem.l d0-d7, (0x8,a0)", 6
      "move.l ([0x12345678,a0],0x11223344), d1", 12
      "fmove.x #0x111122223333444455556666, fp0", 16 ]

  [<TestMethod>]
  [<TestCategory("Sweep")>]
  member _.``Every instruction the decoder decodes, the assembler encodes``() =
    let texts = probes.Force() |> List.map (fun probe -> probe.Text)
    Assert.AreEqual<string>(
      "",
      brokenSources assembler parser texts,
      "These instructions decode but no longer encode, or encode to an \
       instruction that means something else.")

  [<TestMethod>]
  [<TestCategory("Sweep")>]
  member _.``Every instruction a 68040 reads, it also writes``() =
    let texts = probes40.Force() |> List.map (fun probe -> probe.Text)
    Assert.AreEqual<string>(
      "",
      brokenSources assembler40 parser40 texts,
      "These instructions decode for a 68040 but no longer encode for one, or \
       encode to an instruction that means something else.")

  [<TestMethod>]
  [<TestCategory("Sweep")>]
  member _.``Every instruction a 68000 reads, it also writes``() =
    let texts = probes00.Force() |> List.map (fun probe -> probe.Text)
    Assert.AreEqual<string>(
      "",
      brokenSources assembler00 parser00 texts,
      "These instructions decode for a 68000 but no longer encode for one, or \
       encode to an instruction that means something else.")

  [<TestMethod>]
  member _.``Branches to a label reach it in both directions``() =
    let wrong =
      [ for written, expected in branchSources do
          for source, index, labelIndex in branchCases written ->
            expected, source, index, labelIndex ]
      |> List.choose (fun (expected, source, index, labelIndex) ->
        match (try assembler.Lower source with _ -> Error "raised") with
        | Error _ | Ok [] -> Some $"'{expected}' does not assemble"
        | Ok encoded ->
          let lengths = encoded |> List.map (fun (_, bytes) -> bytes.Length)
          let addrOf upto = List.take upto lengths |> List.sumBy uint64
          let addr = addrOf index
          let target = addrOf labelIndex
          let distance = int64 target - int64 addr - 2L
          let sign = if distance < 0L then "-" else "+"
          let bytes = snd (List.item index encoded)
          let text =
            try (parser.Parse(bytes, addr)).Disasm() with _ -> "<undecodable>"
          let want =
            expected.Replace("@", $"{sign}0x{abs distance:x} ; 0x{target:x}")
          if text = want then None
          else Some $"'{expected}' at 0x{addr:x} became '{text}'")
      |> List.distinct
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" wrong,
      "These no longer reach the instruction their label marks.")

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
      "These ask for something no m68k encoding can say.")

  /// Checks that an assembler for an earlier member of the family refuses what
  /// a later one added, because such a target could not read it back.
  [<TestMethod>]
  member _.``A 68000 is not given what a later model added``() =
    let encoded =
      [ "bkpt #0x1"
        "movec.l sfc, d0"
        "moves.b (a0), d0"
        "rtd #0x8"
        "extb.l d0"
        "bra.l +0x10"
        "link.l a0, #0x8"
        "chk.l (a0), d0"
        "bftst (a0){0x0:0x1}"
        "cas.b d0, d1, (a0)"
        "pack d0, d1, #0x0"
        "trapt"
        "callm #0x1, (a0)"
        "fmove.x fp0, fp1"
        "move16 (a0)+, (a1)+"
        "cinva bc"
        "move.l (0x0,a0,d1.w*2), d2"
        "move.l ([0x0,a0],0x0), d1" ]
      |> List.choose (fun source ->
        match (try encodeFirst assembler00 source with _ -> None) with
        | None -> None
        | Some _ -> Some source)
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" encoded,
      "A 68000 reads none of these, so it cannot be given them.")

  /// Checks that an assembler for a 68040 refuses the two instructions that the
  /// 68020 alone has, the family having dropped them again.
  [<TestMethod>]
  member _.``A 68040 is not given what only a 68020 reads``() =
    let encoded =
      [ "callm #0x1, (a0)"; "rtm d0"; "rtm a3" ]
      |> List.choose (fun source ->
        match (try encodeFirst assembler40 source with _ -> None) with
        | None -> None
        | Some _ -> Some source)
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" encoded,
      "A 68040 reads neither of these, so it cannot be given them.")

  /// <summary>
  /// Checks that a source written the way a person writes one names the same
  /// instruction as the canonical text for it.
  ///
  /// What the disassembler writes is only part of what an assembler has to
  /// read: a source of its own writes the distance of an address in front of
  /// the parentheses rather than inside them, writes a number below zero with a
  /// sign, names a register in upper case, leaves the width off where there is
  /// only one it could be, and says in a comment what it is doing.
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

  /// <summary>
  /// Checks that an instruction comes out as long as its encoding is.
  ///
  /// An m68k instruction says how long it is only through the addressing modes
  /// its operands use, and how far away a label is depends on how long every
  /// instruction before it was, so an encoder that got a length wrong would
  /// reach the wrong place.
  /// </summary>
  [<TestMethod>]
  member _.``An instruction is as long as its encoding is``() =
    let wrong =
      lengths
      |> List.choose (fun (source, expected) ->
        match (try encodeFirst assembler source with _ -> None) with
        | None -> Some $"'{source}' does not assemble"
        | Some bytes ->
          if bytes.Length = expected then None
          else Some $"'{source}' came out {bytes.Length} bytes long")
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" wrong,
      "These are no longer as long as their encoding is.")

  /// Checks that a source the assembler refuses leaves it able to read the next
  /// one, which a parser keeping state across a failure would not.
  [<TestMethod>]
  member _.``A refused source leaves the assembler usable``() =
    for bad in unencodableSources do
      (try encodeFirst assembler bad |> ignore with _ -> ())
      match assembler.Lower "  nop\n  move.l (0x8,a0), d1" with
      | Ok [ _; _ ] -> ()
      | Ok _ | Error _ -> Assert.Fail $"'{bad}' left the assembler unusable"

// vim: set tw=80 sts=2 sw=2:
