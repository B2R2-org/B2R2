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
open B2R2.FrontEnd.PPC
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.PPC

/// Represents what happened when a reference encoding was round-tripped.
type internal PPCOutcome =
  /// The re-encoded word disassembles back to the text we started from.
  | PPCPreserved
  /// The re-encoded word means something other than the text we started from.
  | PPCAltered of actual: string
  /// The assembler cannot encode this instruction yet.
  | PPCUnsupported

/// <summary>
/// Checks the PPC assembler against B2R2's own PPC decoder, which is far better
/// tested (see B2R2.FrontEnd.PPC.Tests). For each reference encoding we
/// disassemble it into canonical PPC syntax, hand that text back to the
/// assembler, and disassemble the result again. Comparing the resulting *text*
/// rather than the bytes means that picking a valid-but-different encoding is
/// not a failure, while emitting a word that means something else is.
///
/// Nothing here is a hand-written expectation, and nothing is a hand-written
/// input either: PPCSweep walks the encoding space and the decoder says what
/// each word means, so the set of instructions under test is whatever the
/// decoder currently understands. Forms that canonical disassembly cannot
/// express - labels above all - are pinned by the hand-written tests below.
/// </summary>
[<TestClass>]
type PPCRoundTripTests() =

  static let isa32 = ISA(Architecture.PPC, Endian.Little, WordSize.Bit32)

  static let isa64 = ISA(Architecture.PPC, Endian.Little, WordSize.Bit64)

  /// One parser for each word size, reused across the whole sweep. The sweep
  /// asks for millions of decodings, so building one each time would dominate
  /// the run.
  static let parser32 =
    PPCParser(WordSize.Bit32, BinReader.Init Endian.Little)
    :> IInstructionParsable

  static let parser64 =
    PPCParser(WordSize.Bit64, BinReader.Init Endian.Little)
    :> IInstructionParsable

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
    | None ->
      PPCUnsupported
    | Some encoded ->
      let actual = try disasm parser encoded with _ -> "<undecodable>"
      if actual = source then PPCPreserved else PPCAltered actual

  /// Describes a source that does not encode to a word meaning the same.
  static let brokenSource assembler parser source =
    match roundTrip assembler parser source with
    | PPCPreserved -> None
    | PPCAltered actual -> Some $"'{source}' encoded as '{actual}'"
    | PPCUnsupported -> Some $"'{source}' is not encodable"

  /// Every probe the sweep produces at either word size. The sweep is the
  /// expensive part of this file, so it runs once for the class rather than
  /// once for each test that reads it.
  static let probes32 = lazy (PPCSweep.probes WordSize.Bit32)

  static let probes64 = lazy (PPCSweep.probes WordSize.Bit64)

  /// The instruction a place is written into, over and over, so that a label
  /// can be put out of reach of the instruction naming it.
  let padding = String.replicate 200 "  nop\n"

  /// <summary>
  /// The sources a branch to a label is tried in, each paired with the index of
  /// the instruction under test and the address its label sits at.
  ///
  /// A label is reached from below as well as from above, and from far enough
  /// away that an offset holding too few bits would not reach it.
  /// </summary>
  let branchCases source =
    [ $"L:\n  nop\n  {source}\n  nop", 1, 0x0UL
      $"  {source}\n{padding}L:\n  nop", 0, 0x324UL
      $"L:\n{padding}  {source}\n  nop", 200, 0x0UL ]

  /// <summary>
  /// Every instruction that names a place, paired with how the disassembler
  /// writes it once it has resolved one.
  ///
  /// A branch reaches its place either by counting the distance to it or by
  /// naming it outright, and both are written here, because what the two forms
  /// hold differs by exactly where the branch itself sits.
  /// </summary>
  let branchSources =
    [ "b L", "b"
      "bl L", "bl"
      "ba L", "ba"
      "bla L", "bla"
      "bc 0x1, 0x4 * cr0 + lt, L", "bc 0x1, 0x4 * cr0 + lt,"
      "bca 0x1, 0x4 * cr0 + lt, L", "bca 0x1, 0x4 * cr0 + lt,"
      "blt L", "blt cr0,"
      "blt cr3, L", "blt cr3,"
      "bgt cr1, L", "bgt cr1,"
      "beq cr2, L", "beq cr2,"
      "bne cr3, L", "bne cr3,"
      "bge cr4, L", "bge cr4,"
      "bdnz L", "bdnz"
      "bltl cr5, L", "bltl cr5,"
      "bnel cr6, L", "bnel cr6,"
      "blta cr7, L", "blta cr7,"
      "bgtla cr1, L", "bgtla cr1," ]

  /// Sources that name no instruction at all, either because a number does not
  /// fit where it is written or because a register cannot be named there.
  let unencodableSources =
    [ "addi r3, r4, 0x8000"
      "ori r3, r4, 0x10000"
      "lwz r3, 0x8000(r4)"
      "ld r3, 0x2(r4)"
      "b 0x2"
      "blt 0x2"
      "blta cr0, 0x2"
      "blta cr0, 0x8000"
      "sradi r3, r4, 0x40"
      "rlwinm r3, r4, 0x20, 0x0, 0x1f"
      "srwi r3, r4, 0x0"
      "mtcrf 0x100, r3"
      "vspltisb v1, 0x10"
      "xxspltib f1, 0x100"
      "add f0, f1, f2"
      "fadd r0, r1, r2"
      "lvx r1, r2, r3"
      "isel r1, r2, r3, 0x20"
      "add r1, r2"
      "nop r1"
      "frobnicate r1, r2" ]

  /// Sources written the way a person writes one rather than the way the
  /// disassembler does, each paired with the instruction it names.
  let writtenSources =
    [ "  addi r3, r4, 1  # what a person writes", "addi r3, r4, 0x1"
      "addi $r3, $r4, 0x1 ; and the other way of saying so", "addi r3, r4, 0x1"
      "ADDI R3, R4, 0x1", "addi r3, r4, 0x1"
      "addi r3, r4, -1", "addi r3, r4, 0xffffffff"
      "lwz r3, (r4)", "lwz r3, 0x0(r4)"
      "lwz r3, -8(r4)", "lwz r3, 0xfffffff8(r4)"
      "bc 0x1, 0x2, 0x8", "bc 0x1, 0x4 * cr0 + eq, 0x8"
      "blt 0x8", "blt cr0, 0x8"
      "bltlr", "bltlr cr0" ]

  [<TestMethod>]
  [<TestCategory("Sweep")>]
  member _.``Every instruction the decoder decodes, the assembler encodes``() =
    let broken =
      probes32.Force()
      |> List.choose (fun probe ->
        brokenSource assembler32 parser32 probe.Text)
      |> List.distinct
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" broken,
      "These instructions decode but no longer encode, or encode to a word \
       that means something else."
    )

  /// <summary>
  /// Checks the same against the decoder of the wider word size.
  ///
  /// The primary opcodes holding the instructions that work on a whole
  /// doubleword are ones a thirty-two bit source does not recognize at all, so
  /// the sweep above never reaches them; and a written number below zero is as
  /// wide as the source it was written in, so even the instructions both word
  /// sizes share are written differently here.
  /// </summary>
  [<TestMethod>]
  [<TestCategory("Sweep")>]
  member _.``Every instruction encodes where the source is 64-bit``() =
    let broken =
      probes64.Force()
      |> List.choose (fun probe ->
        brokenSource assembler64 parser64 probe.Text)
      |> List.distinct
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" broken,
      "These instructions no longer encode where the source is 64-bit."
    )

  [<TestMethod>]
  member _.``Branches to a label reach it in both directions``() =
    let wrong =
      [ for written, expected in branchSources do
          for source, index, target in branchCases written ->
            expected, source, index, target ]
      |> List.choose (fun (expected, source, index, target) ->
        match (try assembler32.Lower source with _ -> Error "raised") with
        | Error _ | Ok [] ->
          Some $"'{expected} L' does not assemble"
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
        match (try encodeFirst assembler32 source with _ -> None) with
        | None ->
          None
        | Some bytes ->
          let text = try disasm parser32 bytes with _ -> "<undecodable>"
          Some $"'{source}' encoded as '{text}'")
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" encoded,
      "These ask for something no PPC encoding can say."
    )

  /// Checks that a word comes out in the order the ISA stores its bytes in,
  /// which is the one thing about an encoding that the word itself cannot say.
  [<TestMethod>]
  member _.``The bytes come out in the order the ISA stores them``() =
    let isa = ISA(Architecture.PPC, Endian.Big, WordSize.Bit32)
    let assembler = Assembler(isa, 0UL) :> ILowerable
    let source = "addi r3, r4, 0x1"
    let hex (bytes: byte[]) = Convert.ToHexString bytes
    match encodeFirst assembler source, encodeFirst assembler32 source with
    | Some big, Some little ->
      Assert.AreEqual<string>(hex (Array.rev little), hex big)
    | _ ->
      Assert.Fail $"'{source}' does not assemble"

  /// <summary>
  /// Checks that a source written the way a person writes one names the same
  /// instruction as the canonical text for it.
  ///
  /// What the disassembler writes is only part of what an assembler has to
  /// read: a source of its own writes a register with a dollar sign, writes a
  /// number below zero with a sign rather than as the bits it lands in, leaves
  /// out what it means to be zero, and says in a comment what it is doing.
  /// </summary>
  [<TestMethod>]
  member _.``A source may be written the way a person writes one``() =
    let wrong =
      writtenSources
      |> List.choose (fun (source, expected) ->
        match (try encodeFirst assembler32 source with _ -> None) with
        | None ->
          Some $"'{source}' does not assemble"
        | Some bytes ->
          let text = try disasm parser32 bytes with _ -> "<undecodable>"
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
      (try encodeFirst assembler32 bad |> ignore with _ -> ())
      match assembler32.Lower "  nop\n  addi r3, r4, 0x1" with
      | Ok [ _; _ ] -> ()
      | Ok _ | Error _ -> Assert.Fail $"'{bad}' left the assembler unusable"

// vim: set tw=80 sts=2 sw=2:
