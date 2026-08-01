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
open B2R2.FrontEnd.MIPS
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.MIPS

/// Represents what happened when a reference encoding was round-tripped.
type internal MIPSOutcome =
  /// The re-encoded word disassembles back to the text we started from.
  | MIPSPreserved
  /// The re-encoded word means something other than the text we started from.
  | MIPSAltered of actual: string
  /// The assembler cannot encode this instruction yet.
  | MIPSUnsupported

/// <summary>
/// Checks the MIPS assembler against B2R2's own MIPS decoder, which is far
/// better tested (see B2R2.FrontEnd.MIPS.Tests). For each reference encoding
/// we disassemble it into canonical MIPS syntax, hand that text back to the
/// assembler, and disassemble the result again. Comparing the resulting *text*
/// rather than the bytes means that picking a valid-but-different encoding is
/// not a failure, while emitting a word that means something else is.
///
/// Nothing here is a hand-written expectation, and nothing is a hand-written
/// input either: MIPSSweep walks the encoding space and the decoder says what
/// each word means, so the set of instructions under test is whatever the
/// decoder currently understands. Forms that canonical disassembly cannot
/// express - labels above all - are pinned by the hand-written tests below.
/// </summary>
[<TestClass>]
type MIPSRoundTripTests() =

  static let isa32 = ISA(Architecture.MIPS, Endian.Little, WordSize.Bit32)

  static let isa64 = ISA(Architecture.MIPS, Endian.Little, WordSize.Bit64)

  /// One parser for each word size, reused across the whole sweep. The sweep
  /// asks for millions of decodings, so building one each time would dominate
  /// the run.
  static let parser32 =
    MIPSParser(isa32, BinReader.Init Endian.Little) :> IInstructionParsable

  static let parser64 =
    MIPSParser(isa64, BinReader.Init Endian.Little) :> IInstructionParsable

  static let assembler32 = Assembler(isa32, 0UL) :> ILowerable

  static let assembler64 = Assembler(isa64, 0UL) :> ILowerable

  static let disasm (parser: IInstructionParsable) (bytes: byte[]) =
    (parser.Parse(bytes, 0UL)).Disasm()

  static let encodeFirst (assembler: ILowerable) text =
    match assembler.Lower text with
    | Ok((_, bytes) :: _) -> Some bytes
    | Ok [] | Error _ -> None

  /// Encodes the given source and disassembles the result, so that a source
  /// text stands in for the word a probe was decoded from.
  static let roundTrip assembler parser (source: string) =
    match (try encodeFirst assembler source with _ -> None) with
    | None -> MIPSUnsupported
    | Some encoded ->
      let actual = try disasm parser encoded with _ -> "<undecodable>"
      if actual = source then MIPSPreserved else MIPSAltered actual

  /// Describes a source that does not encode to a word meaning the same.
  static let brokenSource assembler parser source =
    match roundTrip assembler parser source with
    | MIPSPreserved -> None
    | MIPSAltered actual -> Some $"'{source}' encoded as '{actual}'"
    | MIPSUnsupported -> Some $"'{source}' is not encodable"

  /// Every probe the sweep produces. The sweep is the expensive part of this
  /// file, so it runs once for the class rather than once for each test that
  /// reads it.
  static let sweepProbes = lazy (MIPSSweep.probes ())

  /// What the decoder of the other word size makes of a probe, which differs
  /// from what the sweep recorded only in how the registers are named.
  static let textAt (parser: IInstructionParsable) (word: uint32) =
    try Some((parser.Parse(BitConverter.GetBytes word, 0UL)).Disasm())
    with _ -> None

  /// The instruction a place is written into, over and over, so that a label
  /// can be put out of reach of the instruction naming it.
  let padding = String.replicate 200 "  nop\n"

  /// <summary>
  /// The sources a branch to a label is tried in, each paired with the index
  /// of the instruction under test and the address its label sits at.
  ///
  /// A label is reached from below as well as from above, and from far enough
  /// away that an offset holding too few bits would not reach it.
  /// </summary>
  let branchCases source =
    [ $"L:\n  nop\n  {source}\n  nop", 1, 0x0UL
      $"  {source}\n{padding}L:\n  nop", 0, 0x324UL
      $"L:\n{padding}  {source}\n  nop", 200, 0x0UL ]

  /// Every instruction that names a place, paired with how the disassembler
  /// writes it once it has resolved one.
  let branchSources =
    [ "b L", "b"
      "bal L", "bal"
      "beq v0, v1, L", "beq v0, v1,"
      "bne v0, v1, L", "bne v0, v1,"
      "beql v0, v1, L", "beql v0, v1,"
      "bnel v0, v1, L", "bnel v0, v1,"
      "bgez v0, L", "bgez v0,"
      "bgezal v0, L", "bgezal v0,"
      "bgtz v0, L", "bgtz v0,"
      "blez v0, L", "blez v0,"
      "bltz v0, L", "bltz v0,"
      "bltzal v0, L", "bltzal v0,"
      "bc1f L", "bc1f"
      "bc1t L", "bc1t"
      "bc1f 0x2, L", "bc1f 0x2,"
      "bc1t 0x2, L", "bc1t 0x2,"
      "j L", "j"
      "jal L", "jal" ]

  /// Sources that name no instruction at all, either because a number does not
  /// fit where it is written or because a register cannot be named there.
  let unencodableSources =
    [ "addiu v0, v1, 0x8000"
      "daddiu v0, v1, 0xffffffffffff7fff"
      "andi v0, v1, 0x10000"
      "lui v0, 0x10000"
      "sll v0, v1, 0x20"
      "sync 0x20"
      "lw v0, 0x8000(a0)"
      "sw v0, -32769(a0)"
      "rdhwr v0, v1, 0x8"
      "align v0, v1, v2, 0x4"
      "dalign v0, v1, v2, 0x8"
      "ext v0, v1, 0x0, 0x21"
      "ins v0, v1, 0x1f, 0x8"
      "add f0, f1, f2"
      "add.s v0, v1, v2"
      "add.w f0, f1, f2"
      "cvt.s.s f0, f1"
      "cvt.d.d f0, f1"
      "mfc1 v0, v1"
      "ldc1 v0, 0(a0)"
      "prefx 0x2, a1(a0)"
      "jr"
      "jr v0, v1"
      "frobnicate v0, v1" ]

  /// Sources written the way a person writes one rather than the way the
  /// disassembler does, each paired with the instruction it names.
  let writtenSources =
    [ "  addiu $v0, $v1, 1  # what a person writes", "addiu v0, v1, 0x1"
      "addiu r2, r3, 0x1 ; and the other way of saying so", "addiu v0, v1, 0x1"
      "ADDIU V0, V1, 0x1", "addiu v0, v1, 0x1"
      "addiu v0, v1, -1", "addiu v0, v1, 0xffffffffffffffff"
      "lw v0, (a0)", "lw v0, 0(a0)"
      "lw $2, -8($4)", "lw v0, -8(a0)"
      "c.eq.s $f4, $f2", "c.eq.s f4, f2"
      "sync", "sync 0x0" ]

  [<TestMethod>]
  member _.``Every instruction the decoder decodes, the assembler encodes``() =
    let broken =
      sweepProbes.Force()
      |> List.choose (fun probe ->
        brokenSource assembler32 parser32 probe.Text)
      |> List.distinct
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" broken,
      "These instructions decode but no longer encode, or encode to a word \
       that means something else.")

  /// <summary>
  /// Checks the same instructions where the source is sixty-four bits wide.
  ///
  /// Eight of the general registers are written by one name there and by
  /// another in a thirty-two bit source, and which of the two an instruction
  /// is written in follows from how wide what it works on is rather than from
  /// how wide the source is, so the two vocabularies meet within one source.
  /// </summary>
  [<TestMethod>]
  member _.``Every instruction encodes where the source is 64-bit``() =
    let broken =
      sweepProbes.Force()
      |> List.choose (fun probe ->
        textAt parser64 probe.Word
        |> Option.bind (brokenSource assembler64 parser64))
      |> List.distinct
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" broken,
      "These instructions no longer encode where the source is 64-bit.")

  [<TestMethod>]
  member _.``Branches and jumps to a label reach it in both directions``() =
    let wrong =
      [ for written, expected in branchSources do
          for source, index, target in branchCases written ->
            expected, source, index, target ]
      |> List.choose (fun (expected, source, index, target) ->
        match (try assembler32.Lower source with _ -> Error "raised") with
        | Error _ | Ok [] -> Some $"'{expected} L' does not assemble"
        | Ok encoded ->
          let addr = uint64 (4 * index)
          let text =
            try (parser32.Parse(snd (List.item index encoded), addr)).Disasm()
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
  /// Checks that a source asking for what no encoding can say is refused
  /// rather than encoded.
  ///
  /// A field that silently drops what does not fit encodes an instruction the
  /// source did not ask for, which is worse than encoding nothing at all.
  /// </summary>
  [<TestMethod>]
  member _.``A source no encoding can say does not encode``() =
    let encoded =
      unencodableSources
      |> List.choose (fun source ->
        match (try encodeFirst assembler32 source with _ -> None) with
        | None -> None
        | Some bytes ->
          let text = try disasm parser32 bytes with _ -> "<undecodable>"
          Some $"'{source}' encoded as '{text}'")
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" encoded,
      "These ask for something no MIPS encoding can say.")

  /// <summary>
  /// Checks that the registers of an instruction are read in the vocabulary
  /// the disassembler writes them in, which is the one the width of what the
  /// instruction works on belongs to rather than the one the source is in.
  /// </summary>
  [<TestMethod>]
  member _.``The registers are read in the vocabulary of the width``() =
    let wrong =
      [ isa32, "daddu t0, t1, t2", 0x012a402du
        isa64, "daddu a4, a5, a6", 0x012a402du
        isa32, "sd a4, 0(a5)", 0xfd280000u
        isa64, "sd a4, 0(a5)", 0xfd280000u
        isa32, "sw t0, 0(t1)", 0xad280000u
        isa64, "sw t0, 0(t1)", 0xad280000u ]
      |> List.choose (fun (isa, source, expected) ->
        let assembler = Assembler(isa, 0UL) :> ILowerable
        match (try encodeFirst assembler source with _ -> None) with
        | None -> Some $"'{source}' does not assemble"
        | Some bytes ->
          let word = BitConverter.ToUInt32(bytes, 0)
          if word = expected then None
          else Some $"'{source}' encoded as 0x{word:x8}")
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" wrong,
      "These name registers the disassembler writes other names for.")

  /// Checks that a word comes out in the order the ISA stores its bytes in,
  /// which is the one thing about an encoding that the word itself cannot say.
  [<TestMethod>]
  member _.``The bytes come out in the order the ISA stores them``() =
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit32)
    let assembler = Assembler(isa, 0UL) :> ILowerable
    let source = "addiu v0, v1, 0x1"
    let hex (bytes: byte[]) = Convert.ToHexString bytes
    match encodeFirst assembler source, encodeFirst assembler32 source with
    | Some big, Some little ->
      Assert.AreEqual<string>(hex (Array.rev little), hex big)
    | _ -> Assert.Fail $"'{source}' does not assemble"

  /// <summary>
  /// Checks that a source written the way a person writes one names the same
  /// instruction as the canonical text for it.
  ///
  /// What the disassembler writes is only part of what an assembler has to
  /// read: a source of its own writes a register with a dollar sign or by its
  /// number, writes a number below zero with a sign rather than as the bits it
  /// lands in, and says in a comment what it is doing.
  /// </summary>
  [<TestMethod>]
  member _.``A source may be written the way a person writes one``() =
    let wrong =
      writtenSources
      |> List.choose (fun (source, expected) ->
        match (try encodeFirst assembler32 source with _ -> None) with
        | None -> Some $"'{source}' does not assemble"
        | Some bytes ->
          let text = try disasm parser32 bytes with _ -> "<undecodable>"
          if text = expected then None
          else Some $"'{source}' encoded as '{text}'")
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" wrong,
      "These are no longer read as the instruction they name.")

  /// Checks that a source the assembler refuses leaves it able to read the
  /// next one, which a parser keeping state across a failure would not.
  [<TestMethod>]
  member _.``A refused source leaves the assembler usable``() =
    for bad in unencodableSources do
      (try encodeFirst assembler32 bad |> ignore with _ -> ())
      match assembler32.Lower "  nop\n  addiu v0, v1, 0x1" with
      | Ok [ _; _ ] -> ()
      | Ok _ | Error _ -> Assert.Fail $"'{bad}' left the assembler unusable"

// vim: set tw=80 sts=2 sw=2:
