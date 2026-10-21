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
    Parser(WordSize.Bit32, BinReader.Init Endian.Little)
    :> IInstructionParsable

  static let parser64 =
    Parser(WordSize.Bit64, BinReader.Init Endian.Little)
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

  /// <summary>
  /// Checks the same of the encodings the categories of an embedded processor
  /// read differently from a server processor, such as primary opcode 4, which
  /// the Legacy Integer Multiply-Accumulate category takes from the vector
  /// facility. Each reading is a processor of its own, so each is swept with a
  /// parser reading its categories, at both word sizes. A category that
  /// another lane adds joins the list.
  /// </summary>
  [<TestMethod>]
  [<TestCategory("Sweep")>]
  member _.``Every instruction of the embedded categories encodes``() =
    let readings =
      [ Category.LegacyIntegerMultiplyAccumulate
        Category.LegacyMoveAssist
        Category.Embedded ]
    let reader = BinReader.Init Endian.Little
    let broken =
      [ for category in readings do
          for wordSize, assembler in
            [ WordSize.Bit32, assembler32; WordSize.Bit64, assembler64 ] do
            let parser =
              Parser(wordSize, category, reader) :> IInstructionParsable
            for probe in PPCSweep.categoryProbes wordSize category do
              yield brokenSource assembler parser probe.Text ]
      |> List.choose id
      |> List.distinct
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" broken,
      "These instructions of the embedded categories do not encode."
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
  /// Checks the same of the encodings a processor with the Signal Processing
  /// Engine reads in primary opcode 4, which every other processor gives to
  /// the vector facility. Each is disassembled again by a parser reading that
  /// category, at both word sizes.
  /// </summary>
  [<TestMethod>]
  [<TestCategory("Sweep")>]
  member _.``Every instruction of the signal processing engine encodes``() =
    let category = Category.SignalProcessing
    let reader = BinReader.Init Endian.Little
    let broken =
      [ for wordSize, assembler in
          [ WordSize.Bit32, assembler32; WordSize.Bit64, assembler64 ] do
          let parser =
            Parser(wordSize, category, reader) :> IInstructionParsable
          for probe in PPCSweep.categoryProbes wordSize category do
            yield brokenSource assembler parser probe.Text ]
      |> List.choose id
      |> List.distinct
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" broken,
      "These instructions of the signal processing engine do not encode."
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

  /// GNU as bytes cover every prefixed storage mnemonic and 34-bit edges.
  [<TestMethod>]
  member _.``Prefixed memory encodings match GNU bytes``() =
    let words =
      [ "0500000087e0ff8d"
        "0500000087ff07c7"
        "05000000841ff80b"
        "0500000087e0ff9d"
        "0500000087ff07d7"
        "05000000841ff81b"
        "0500000087e0ffad"
        "0500000087ff07e7"
        "05000000841ff82b"
        "0500000087e0ffbd"
        "0500000087ff07f7"
        "05000000841ff83b"
        "050000008be0ff9d"
        "050000018be0ff9d"
        "050000028be0ff9d"
        "050000038be0ff9d"
        "050000048be0ff9d"
        "050000058be0ff9d"
        "050000068be0ff9d"
        "050000078be0ff9d"
        "050000088be0ff9d"
        "050000098be0ff9d"
        "0500000a8be0ff9d"
        "0500000b8be0ff9d"
        "0500000c8be0ff9d"
        "0500000d8be0ff9d"
        "0500000e8be0ff9d"
        "0500000f8be0ff9d"
        "050000108be0ff9d"
        "050000118be0ff9d"
        "050000128be0ff9d"
        "050000138be0ff9d"
        "050000148be0ff9d"
        "050000158be0ff9d"
        "050000168be0ff9d"
        "050000178be0ff9d"
        "050000188be0ff9d"
        "050000198be0ff9d"
        "0500001a8be0ff9d"
        "0500001b8be0ff9d"
        "0500001c8be0ff9d"
        "0500001d8be0ff9d"
        "0500001e8be0ff9d"
        "0500001f8be0ff9d"
        "050000208be0ff9d"
        "050000218be0ff9d"
        "050000228be0ff9d"
        "050000238be0ff9d"
        "050000248be0ff9d"
        "050000258be0ff9d"
        "050000268be0ff9d"
        "050000278be0ff9d"
        "050000288be0ff9d"
        "050000298be0ff9d"
        "0500002a8be0ff9d"
        "0500002b8be0ff9d"
        "0500002c8be0ff9d"
        "0500002d8be0ff9d"
        "0500002e8be0ff9d"
        "0500002f8be0ff9d"
        "050000308be0ff9d"
        "050000318be0ff9d"
        "050000328be0ff9d"
        "050000338be0ff9d"
        "050000348be0ff9d"
        "050000358be0ff9d"
        "050000368be0ff9d"
        "050000378be0ff9d"
        "050000388be0ff9d"
        "050000398be0ff9d"
        "0500003a8be0ff9d"
        "0500003b8be0ff9d"
        "0500003c8be0ff9d"
        "0500003d8be0ff9d"
        "0500003e8be0ff9d"
        "0500003f8be0ff9d"
        "050000408be0ff9d"
        "050000418be0ff9d"
        "050000428be0ff9d"
        "050000438be0ff9d"
        "050000448be0ff9d"
        "050000458be0ff9d"
        "050000468be0ff9d"
        "050000478be0ff9d"
        "050000488be0ff9d"
        "050000498be0ff9d"
        "0500004a8be0ff9d"
        "0500004b8be0ff9d"
        "0500004c8be0ff9d"
        "0500004d8be0ff9d"
        "0500004e8be0ff9d"
        "0500004f8be0ff9d"
        "050000508be0ff9d"
        "050000518be0ff9d"
        "050000528be0ff9d"
        "050000538be0ff9d"
        "050000548be0ff9d"
        "050000558be0ff9d"
        "050000568be0ff9d"
        "050000578be0ff9d"
        "050000588be0ff9d"
        "050000598be0ff9d"
        "0500005a8be0ff9d"
        "0500005b8be0ff9d"
        "0500005c8be0ff9d"
        "0500005d8be0ff9d"
        "0500005e8be0ff9d"
        "0500005f8be0ff9d"
        "050000608be0ff9d"
        "050000618be0ff9d"
        "050000628be0ff9d"
        "050000638be0ff9d"
        "050000648be0ff9d"
        "050000658be0ff9d"
        "050000668be0ff9d"
        "050000678be0ff9d"
        "050000688be0ff9d"
        "050000698be0ff9d"
        "0500006a8be0ff9d"
        "0500006b8be0ff9d"
        "0500006c8be0ff9d"
        "0500006d8be0ff9d"
        "0500006e8be0ff9d"
        "0500006f8be0ff9d"
        "050000708be0ff9d"
        "050000718be0ff9d"
        "050000728be0ff9d"
        "050000738be0ff9d"
        "050000748be0ff9d"
        "050000758be0ff9d"
        "050000768be0ff9d"
        "050000778be0ff9d"
        "050000788be0ff9d"
        "050000798be0ff9d"
        "0500007a8be0ff9d"
        "0500007b8be0ff9d"
        "0500007c8be0ff9d"
        "0500007d8be0ff9d"
        "0500007e8be0ff9d"
        "0500007f8be0ff9d"
        "050000808be0ff9d"
        "050000818be0ff9d"
        "050000828be0ff9d"
        "050000838be0ff9d"
        "050000848be0ff9d"
        "050000858be0ff9d"
        "050000868be0ff9d"
        "050000878be0ff9d"
        "050000888be0ff9d"
        "050000898be0ff9d"
        "0500008a8be0ff9d"
        "0500008b8be0ff9d"
        "0500008c8be0ff9d"
        "0500008d8be0ff9d"
        "0500008e8be0ff9d"
        "0500008f8be0ff9d"
        "050000908be0ff9d"
        "050000918be0ff9d"
        "050000928be0ff9d"
        "050000938be0ff9d"
        "050000948be0ff9d"
        "050000958be0ff9d"
        "050000968be0ff9d"
        "050000978be0ff9d"
        "050000988be0ff9d"
        "050000998be0ff9d"
        "0500009a8be0ff9d"
        "0500009b8be0ff9d"
        "0500009c8be0ff9d"
        "0500009d8be0ff9d"
        "0500009e8be0ff9d"
        "0500009f8be0ff9d"
        "050000a08be0ff9d"
        "050000a18be0ff9d"
        "050000a28be0ff9d"
        "050000a38be0ff9d"
        "050000a48be0ff9d"
        "050000a58be0ff9d"
        "050000a68be0ff9d"
        "050000a78be0ff9d"
        "050000a88be0ff9d"
        "050000a98be0ff9d"
        "050000aa8be0ff9d"
        "050000ab8be0ff9d"
        "050000ac8be0ff9d"
        "050000ad8be0ff9d"
        "050000ae8be0ff9d"
        "050000af8be0ff9d"
        "050000b08be0ff9d"
        "050000b18be0ff9d"
        "050000b28be0ff9d"
        "050000b38be0ff9d"
        "050000b48be0ff9d"
        "050000b58be0ff9d"
        "050000b68be0ff9d"
        "050000b78be0ff9d"
        "050000b88be0ff9d"
        "050000b98be0ff9d"
        "050000ba8be0ff9d"
        "050000bb8be0ff9d"
        "050000bc8be0ff9d"
        "050000bd8be0ff9d"
        "050000be8be0ff9d"
        "050000bf8be0ff9d"
        "050000c08be0ff9d"
        "050000c18be0ff9d"
        "050000c28be0ff9d"
        "050000c38be0ff9d"
        "050000c48be0ff9d"
        "050000c58be0ff9d"
        "050000c68be0ff9d"
        "050000c78be0ff9d"
        "050000c88be0ff9d"
        "050000c98be0ff9d"
        "050000ca8be0ff9d"
        "050000cb8be0ff9d"
        "050000cc8be0ff9d"
        "050000cd8be0ff9d"
        "050000ce8be0ff9d"
        "050000cf8be0ff9d"
        "050000d08be0ff9d"
        "050000d18be0ff9d"
        "050000d28be0ff9d"
        "050000d38be0ff9d"
        "050000d48be0ff9d"
        "050000d58be0ff9d"
        "050000d68be0ff9d"
        "050000d78be0ff9d"
        "050000d88be0ff9d"
        "050000d98be0ff9d"
        "050000da8be0ff9d"
        "050000db8be0ff9d"
        "050000dc8be0ff9d"
        "050000dd8be0ff9d"
        "050000de8be0ff9d"
        "050000df8be0ff9d"
        "050000e08be0ff9d"
        "050000e18be0ff9d"
        "050000e28be0ff9d"
        "050000e38be0ff9d"
        "050000e48be0ff9d"
        "050000e58be0ff9d"
        "050000e68be0ff9d"
        "050000e78be0ff9d"
        "050000e88be0ff9d"
        "050000e98be0ff9d"
        "050000ea8be0ff9d"
        "050000eb8be0ff9d"
        "050000ec8be0ff9d"
        "050000ed8be0ff9d"
        "050000ee8be0ff9d"
        "050000ef8be0ff9d"
        "050000f08be0ff9d"
        "050000f18be0ff9d"
        "050000f28be0ff9d"
        "050000f38be0ff9d"
        "050000f48be0ff9d"
        "050000f58be0ff9d"
        "050000f68be0ff9d"
        "050000f78be0ff9d"
        "050000f88be0ff9d"
        "050000f98be0ff9d"
        "050000fa8be0ff9d"
        "050000fb8be0ff9d"
        "050000fc8be0ff9d"
        "050000fd8be0ff9d"
        "050000fe8be0ff9d"
        "050000ff8be0ff9d"
        "0500005a8bff07d7"
        "0500005a881ff81b"
        "050000008be0ff8d"
        "050000018be0ff8d"
        "050000028be0ff8d"
        "050000038be0ff8d"
        "050000048be0ff8d"
        "050000058be0ff8d"
        "050000068be0ff8d"
        "050000078be0ff8d"
        "050000008bff07c7"
        "050000018bff07c7"
        "050000028bff07c7"
        "050000038bff07c7"
        "050000048bff07c7"
        "050000058bff07c7"
        "050000068bff07c7"
        "050000078bff07c7"
        "05000000881ff80b"
        "05000001881ff80b"
        "05000002881ff80b"
        "05000003881ff80b"
        "05000004881ff80b"
        "05000005881ff80b"
        "05000006881ff80b"
        "05000007881ff80b"
        "0500000083e70000"
        "0500800083e70000"
        "05003f8083e70000"
        "05007f8083e70000"
        "05007fc183e72345"
        "05007f8183e72345"
        "0500ffff83e7ffff"
        "0500000083e50000"
        "0500800083e50000"
        "05003f8083e50000"
        "05007f8083e50000"
        "05007fc183e52345"
        "05007f8183e52345"
        "0500ffff83e5ffff"
        "0500000083e10000"
        "0500000083e30000"
        "0500800083e10000"
        "0500800083e30000"
        "05003f8083e10000"
        "05003f8083e30000"
        "05007f8083e10000"
        "05007f8083e30000"
        "05007fc183e12345"
        "05007fc183e32345"
        "05007f8183e12345"
        "05007f8183e32345"
        "0500ffff83e1ffff"
        "0500ffff83e3ffff"
        "07900000ee021998"
        "0790c0ffee021998"
        "0790005aee021998"
        "079080a5ee021998"
        "079040ffee021998"
        "07900000ee021f90"
        "0790c0ffee021f90"
        "0790005aee021f90"
        "079080a5ee021f90"
        "079040ffee021f90"
        "07900000ee021b90"
        "0790c0ffee021b90"
        "0790005aee021b90"
        "079080a5ee021b90"
        "079040ffee021b90"
        "07900000ee021d90"
        "0790c0ffee021d90"
        "0790005aee021d90"
        "079080a5ee021d90"
        "079040ffee021d90"
        "07900000ee021990"
        "0790c0ffee021990"
        "0790005aee021990"
        "079080a5ee021990"
        "079040ffee021990"
        "07900000ee021898"
        "0790c0ffee021898"
        "0790005aee021898"
        "079080a5ee021898"
        "079040ffee021898"
        "07900000ee021e90"
        "0790c0ffee021e90"
        "0790005aee021e90"
        "079080a5ee021e90"
        "079040ffee021e90"
        "07900000ee021a90"
        "0790c0ffee021a90"
        "0790005aee021a90"
        "079080a5ee021a90"
        "079040ffee021a90"
        "07900000ee021c90"
        "0790c0ffee021c90"
        "0790005aee021c90"
        "079080a5ee021c90"
        "079040ffee021c90"
        "07900000ee021890"
        "0790c0ffee021890"
        "0790005aee021890"
        "079080a5ee021890"
        "079040ffee021890"
        "07900000ee0218d8"
        "079000ffee0218d8"
        "0790005aee0218d8"
        "079000a5ee0218d8"
        "07900000ee021ed0"
        "079000ffee021ed0"
        "0790005aee021ed0"
        "079000a5ee021ed0"
        "07900000ee021ad0"
        "079000ffee021ad0"
        "0790005aee021ad0"
        "079000a5ee021ad0"
        "07900000ee021cd0"
        "079000ffee021cd0"
        "0790005aee021cd0"
        "079000a5ee021cd0"
        "07900000ee0218d0"
        "079000ffee0218d0"
        "0790005aee0218d0"
        "079000a5ee0218d0"
        "07900000ee0619d8"
        "079000fcee0619d8"
        "07900054ee0619d8"
        "079000a8ee0619d8"
        "07900000ee061fd0"
        "079000fcee061fd0"
        "07900054ee061fd0"
        "079000a8ee061fd0"
        "07900000ee061bd0"
        "079000fcee061bd0"
        "07900054ee061bd0"
        "079000a8ee061bd0"
        "07900000ee061dd0"
        "079000fcee061dd0"
        "07900054ee061dd0"
        "079000a8ee061dd0"
        "07900000ee0619d0"
        "079000fcee0619d0"
        "07900054ee0619d0"
        "079000a8ee0619d0"
        "07900000ee021a58"
        "0790c0ffee021a58"
        "0790005aee021a58"
        "079080a5ee021a58"
        "079040ffee021a58"
        "07900000ee021b58"
        "0790c0ffee021b58"
        "0790005aee021b58"
        "079080a5ee021b58"
        "079040ffee021b58"
        "07900000ee021958"
        "0790c0ffee021958"
        "0790005aee021958"
        "079080a5ee021958"
        "079040ffee021958"
        "07900000ee021950"
        "0790c0ffee021950"
        "0790005aee021950"
        "079080a5ee021950"
        "079040ffee021950"
        "07900000ee021918"
        "0790ffffee021918"
        "0790005aee021918"
        "079080a5ee021918"
        "079001ffee021918"
        "07900000ee021910"
        "0790ffffee021910"
        "0790005aee021910"
        "079080a5ee021910"
        "079001ffee021910"
        "07900000ee021818"
        "0790f0ffee021818"
        "0790005aee021818"
        "079080a5ee021818"
        "079010ffee021818"
        "07900000ee021810"
        "0790f0ffee021810"
        "0790005aee021810"
        "079080a5ee021810"
        "079010ffee021810"
        "07900000ee021b18"
        "0790f0ffee021b18"
        "0790005aee021b18"
        "079080a5ee021b18"
        "079010ffee021b18"
        "07904033ee021998"
        "07904033ee021f90"
        "07904033ee021b90"
        "07904033ee021d90"
        "07904033ee021990"
        "07904033ee021898"
        "07904033ee021e90"
        "07904033ee021a90"
        "07904033ee021c90"
        "07904033ee021890"
        "07900033ee0218d8"
        "07900033ee021ed0"
        "07900033ee021ad0"
        "07900033ee021cd0"
        "07900033ee0218d0"
        "0790003cee0619d8"
        "0790003cee061fd0"
        "0790003cee061bd0"
        "0790003cee061dd0"
        "0790003cee0619d0"
        "07904033ee021a58"
        "07904033ee021b58"
        "07904033ee021958"
        "07904033ee021950"
        "07900133ee021918"
        "07900133ee021910"
        "07901033ee021818"
        "07901033ee021810"
        "07901033ee021b18"
        "0500000084221900"
        "0500000084221930"
        "0500000084221910"
        "0500000084221920"
        "0500005a88221910"
        "0500000188221900"
        "0500123480225678"
        "0500123480245678"
        "0500123480265678"
        "0600000038a6000c"
        "0600000088a60008"
        "04000000e4a60008"
        "06000000c8260008"
        "06000000c0260008"
        "06000000a8a60008"
        "06000000a0a60008"
        "04000000e1460008"
        "04000000a4a60008"
        "0600000080a60008"
        "04000000a8260008"
        "04000000ac260008"
        "04000000c8260008"
        "04000000e8460008"
        "0700000000000000"
        "0600000099060008"
        "04000000f5060008"
        "06000000d8260008"
        "06000000d0260008"
        "06000000b1060008"
        "04000000f1460008"
        "0600000091060008"
        "04000000b8260008"
        "04000000bc260008"
        "04000000d8260008"
        "04000000f8460008"
        "0601ffff3860ffff"
        "0612000038600000"
        "0611ffff88a0ffff"
        "04020000f5060000"
        "04010000ebe60000" ]
    for endian in [ Endian.Big; Endian.Little ] do
      let isa = ISA(Architecture.PPC, endian, WordSize.Bit64)
      let parser = Parser(isa, BinReader.Init endian) :> IInstructionParsable
      let assembler = Assembler(isa, 0UL) :> ILowerable
      for hex in words do
        let bytes =
          Convert.FromHexString hex |> Array.chunkBySize 4
          |> Array.collect (fun w ->
            if endian = Endian.Big then w else Array.rev w)
        let ins = parser.Parse(bytes, 0UL)
        let source = ins.Disasm()
        match assembler.Lower source with
        | Ok [ _, encoded ] ->
          let expected = Convert.ToHexString bytes
          let actual = Convert.ToHexString encoded
          Assert.AreEqual<string>(expected, actual, source)
        | _ ->
          Assert.Fail source

  [<TestMethod>]
  member _.``Labels account for the prefix and suffix``() =
    let isa = ISA(Architecture.PPC, Endian.Big, WordSize.Bit64)
    let assembler = Assembler(isa, 0UL) :> ILowerable
    let source = "b target\npaddi r3, r0, 1, 0\ntarget: addi r4, r0, 2"
    match assembler.Lower source with
    | Ok [ _, branch; _, prefix; _, last ] ->
      Assert.AreEqual<string>("4800000C", Convert.ToHexString branch)
      Assert.AreEqual<int>(8, prefix.Length)
      Assert.AreEqual<string>("38800002", Convert.ToHexString last)
    | _ ->
      Assert.Fail source

// vim: set tw=80 sts=2 sw=2:
