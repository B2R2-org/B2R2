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
open B2R2.FrontEnd.AVR
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.AVR

/// Represents what happened when a reference encoding was round-tripped.
type internal AVROutcome =
  /// The re-encoded instruction disassembles back to the text we started from.
  | AVRPreserved
  /// The re-encoded instruction means something other than that text.
  | AVRAltered of actual: string
  /// The assembler cannot encode this instruction yet.
  | AVRUnsupported

/// <summary>
/// Checks the AVR assembler against B2R2's own AVR decoder. For each reference
/// encoding we disassemble it into canonical AVR syntax, hand that text back to
/// the assembler, and disassemble the result again. Comparing the resulting
/// *text* rather than the bytes means that picking a valid-but-different
/// encoding is not a failure, while emitting an instruction that means
/// something else is.
///
/// Nothing here is a hand-written expectation, and nothing is a hand-written
/// input either: AVRSweep walks every word there is and the decoder says what
/// each one means, so the set of instructions under test is whatever the
/// decoder currently understands. Forms that canonical disassembly cannot
/// express - labels above all - are pinned by the hand-written tests below.
/// </summary>
[<TestClass>]
type AVRRoundTripTests() =

  static let isa = ISA(Architecture.AVR, Endian.Little, WordSize.Bit8)

  /// One parser, reused across the whole sweep. The sweep asks for hundreds of
  /// thousands of decodings, so building one each time would dominate the run.
  static let parser =
    AVRParser(BinReader.Init Endian.Little) :> IInstructionParsable

  static let assembler = Assembler(isa, 0UL) :> ILowerable

  static let disasm (bytes: byte[]) = (parser.Parse(bytes, 0UL)).Disasm()

  static let encodeFirst (assembler: ILowerable) text =
    match assembler.Lower text with
    | Ok((_, bytes) :: _) -> Some bytes
    | Ok [] | Error _ -> None

  /// Encodes the given source and disassembles the result, so that a source
  /// text stands in for the words a probe was decoded from.
  static let roundTrip (source: string) =
    match (try encodeFirst assembler source with _ -> None) with
    | None -> AVRUnsupported
    | Some encoded ->
      let actual = try disasm encoded with _ -> "<undecodable>"
      if actual = source then AVRPreserved else AVRAltered actual

  /// <summary>
  /// Describes a probe whose text does not encode to an instruction meaning the
  /// same, naming the words it was decoded from so that a failure says where to
  /// look.
  ///
  /// How wide the instruction came out is checked as well as what it means,
  /// because an instruction of the wrong width leaves everything after it in a
  /// source at the wrong address, and the text of that one instruction says
  /// nothing about it.
  /// </summary>
  static let brokenProbe (probe: AVRProbe) =
    let source = probe.Text
    let where = $"0x{probe.Word:x4}{probe.Extra:x4}"
    match (try encodeFirst assembler source with _ -> None) with
    | None -> Some $"{where} '{source}' is not encodable"
    | Some encoded when encoded.Length <> probe.Length ->
      Some $"{where} '{source}' encoded {encoded.Length} bytes wide"
    | Some _ ->
      match roundTrip source with
      | AVRPreserved -> None
      | AVRAltered actual -> Some $"{where} '{source}' encoded as '{actual}'"
      | AVRUnsupported -> Some $"{where} '{source}' is not encodable"

  /// Every probe the sweep produces. The sweep is the expensive part of this
  /// file, so it runs once for the class rather than once for each test that
  /// reads it.
  static let probes = lazy (AVRSweep.probes ())

  /// The disassembler says in a comment what a written number comes to, and
  /// pads that comment out to a column of its own, so what it writes between
  /// one run of spaces and the next says nothing about the instruction.
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

  /// Every instruction naming a place, paired with how many bytes wide it is
  /// and how far away the label is put.
  let branchSources =
    [ "breq", 2, 50
      "brne", 2, 50
      "brcs", 2, 50
      "brid", 2, 50
      "rjmp", 2, 1500
      "rcall", 2, 1500
      "jmp", 4, 50
      "call", 4, 50 ]

  /// Sources that name no instruction at all, either because a number does not
  /// fit where it is written or because a register cannot be named there.
  let unencodableSources =
    [ "ldi r15, 0x1"
      "ldi r16, 0x100"
      "ldi r16, -129"
      "muls r15, r16"
      "fmul r24, r16"
      "movw r1, r2"
      "adiw r25, 0x1"
      "adiw r24, 0x40"
      "sbiw r22, 0x1"
      "des 0x10"
      "cbi 0x20, 0x0"
      "sbi 0x0, 0x8"
      "sbrc r0, 0x8"
      "in r0, 0x40"
      "out 0x40, r0"
      "brne .+1"
      "brne .+128"
      "brne .-130"
      "brbs 0x8, .+0"
      "rjmp .+4096"
      "rjmp .-4098"
      "jmp 0x1"
      "jmp 0x800000"
      "call -2"
      "lds r0, 0x10000"
      "sts 0x10000, r0"
      "ldd r0, X+1"
      "ldd r0, Y+64"
      "ld r0, Y+1"
      "ld r0, r1"
      "st X, X"
      "lpm r0, Y"
      "elpm r0, -Z"
      "xch Y, r0"
      "nop r0"
      "sec r0"
      "add r1"
      "add r32, r1"
      "push X"
      "frobnicate r0, r1"
      $"  breq L\n{padding 200}L:\n  nop" ]

  /// <summary>
  /// Sources written the way a person writes one rather than the way the
  /// disassembler does, each paired with the instruction it names.
  ///
  /// What the disassembler writes is only part of what an assembler has to
  /// read: a source of its own writes a number below zero with a sign rather
  /// than as the byte it lands in, names the several instructions that have no
  /// encoding of their own by the names the manual gives them, and says in a
  /// comment what it is doing.
  /// </summary>
  let writtenSources =
    [ "  add r1, r2  ; what a person writes", "add r1, r2"
      "ADD R1,R2", "add r1, r2"
      "ldi r16, -1", "ldi r16, 0xff ; 255"
      "ldi r16, 0b1010", "ldi r16, 0xa ; 10"
      "subi r16, 0o17", "subi r16, 0xf ; 15"
      "clr r5", "eor r5, r5"
      "lsl r5", "add r5, r5"
      "rol r5", "adc r5, r5"
      "tst r5", "and r5, r5"
      "ser r16", "ldi r16, 0xff ; 255"
      "sbr r16, 0x3", "ori r16, 0x3 ; 3"
      "cbr r16, 0x3", "andi r16, 0xfc ; 252"
      "brlo .+0", "brcs .+0 ; 0x2"
      "brsh .+0", "brcc .+0 ; 0x2"
      "brbs 0x1, .+0", "breq .+0 ; 0x2"
      "brbc 0x1, .+0", "brne .+0 ; 0x2"
      "bset 0x0", "sec"
      "bclr 0x7", "cli"
      "ldd r0, Z+0", "ld r0, Z"
      "std Y+0, r0", "st Y, r0"
      "rjmp 0x0", "rjmp .-2 ; 0x0"
      "lds r0, 4660", "lds r0, 0x1234"
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
    Assert.IsGreaterThan(380000, List.length (probes.Force()))

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
      "These instructions decode but no longer encode, or encode to an \
       instruction that means something else.")

  /// <summary>
  /// Checks that a branch naming a label lands on the instruction that label
  /// marks, from either direction.
  ///
  /// A branch written with a label is checked against the same branch written
  /// with the address it means to reach, assembled at the address the branch
  /// itself turned out to sit at. Both forms are then the same instruction, and
  /// the sweep above has already pinned what that instruction is. Two of the
  /// instructions under test are two words wide, so a source holding one of
  /// them also says that the lines below it were counted at the right
  /// addresses.
  /// </summary>
  [<TestMethod>]
  member _.``Branches to a label reach it in both directions``() =
    let wrong =
      [ for name, width, count in branchSources do
          for source, index, marks in branchCases count name ->
            name, width, source, index, marks ]
      |> List.choose (fun (name, width, source, index, marks) ->
        let addressOf i =
          uint64 (2 * i) + (if i > index then uint64 width - 2UL else 0UL)
        let reference = Assembler(isa, addressOf index) :> ILowerable
        let expected = encodeFirst reference $"{name} {addressOf marks}"
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
      "These ask for something no AVR encoding can say.")

  /// <summary>
  /// Checks that the words of an instruction come out in the order the machine
  /// reads them.
  ///
  /// AVR stores the two bytes of a word with the lower one first, and an
  /// instruction wide enough to need two words holds the one naming it first.
  /// Neither is something the words themselves can say.
  /// </summary>
  [<TestMethod>]
  member _.``The words come out in the order the machine reads them``() =
    let wrong =
      [ "0C943412", "jmp 0x2468"
        "0E943412", "call 0x2468"
        "00903412", "lds r0, 0x1234"
        "00923412", "sts 0x1234, r0"
        "120C", "add r1, r2" ]
      |> List.choose (fun (hex, source) ->
        match (try encodeFirst assembler source with _ -> None) with
        | None -> Some $"'{source}' does not assemble"
        | Some bytes when Convert.ToHexString bytes = hex -> None
        | Some bytes -> Some $"'{source}' came out {Convert.ToHexString bytes}")
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" wrong,
      "These no longer come out in the order the machine reads them.")

  /// <summary>
  /// Checks that a source written the way a person writes one names the same
  /// instruction as the canonical text for it.
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
      match assembler.Lower "  nop\n  add r1, r2" with
      | Ok [ _; _ ] -> ()
      | Ok _ | Error _ -> Assert.Fail $"'{bad}' left the assembler unusable"

// vim: set tw=80 sts=2 sw=2:
