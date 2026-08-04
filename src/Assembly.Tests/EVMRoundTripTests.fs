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
open B2R2.FrontEnd.EVM
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.EVM

/// Represents what happened when a reference encoding was round-tripped.
type internal EVMOutcome =
  /// The re-encoded instruction disassembles back to the text we started from.
  | EVMPreserved
  /// The re-encoded instruction means something other than that text.
  | EVMAltered of actual: string
  /// The assembler cannot encode this instruction yet.
  | EVMUnsupported

/// <summary>
/// Checks the EVM assembler against B2R2's own EVM decoder. For each reference
/// encoding we disassemble it into canonical EVM syntax, hand that text back to
/// the assembler, and disassemble the result again. Comparing the resulting
/// *text* rather than the bytes means that picking a valid-but-different
/// encoding is not a failure, while emitting an instruction that means
/// something else is.
///
/// Nothing here is a hand-written expectation, and nothing is a hand-written
/// input either: EVMSweep walks every byte there is and the decoder says what
/// each one means, so the set of instructions under test is whatever the
/// decoder currently understands. Forms that canonical disassembly cannot
/// express - labels above all - are pinned by the hand-written tests below.
/// </summary>
[<TestClass>]
type EVMRoundTripTests() =

  static let isa = ISA Architecture.EVM

  /// One parser, reused across the whole sweep.
  static let parser = EVMParser isa :> IInstructionParsable

  static let assembler = Assembler(isa, 0UL) :> ILowerable

  static let disasm (bytes: byte[]) = (parser.Parse(bytes, 0UL)).Disasm()

  static let encodeFirst (assembler: ILowerable) text =
    match assembler.Lower text with
    | Ok((_, bytes) :: _) -> Some bytes
    | Ok [] | Error _ -> None

  /// Encodes the given source and disassembles the result, so that a source
  /// text stands in for the bytes a probe was decoded from.
  static let roundTrip (source: string) =
    match (try encodeFirst assembler source with _ -> None) with
    | None -> EVMUnsupported
    | Some encoded ->
      let actual = try disasm encoded with _ -> "<undecodable>"
      if actual = source then EVMPreserved else EVMAltered actual

  /// <summary>
  /// Describes a probe whose text does not encode to an instruction meaning the
  /// same, naming the bytes it was decoded from so that a failure says where to
  /// look.
  ///
  /// How wide the instruction came out is checked as well as what it means,
  /// because an instruction of the wrong width leaves everything after it in a
  /// source at the wrong address, and the text of that one instruction says
  /// nothing about it. That matters here more than most: a push holds bytes a
  /// disassembler reads as instructions the moment the count is out by one.
  /// </summary>
  static let brokenProbe (probe: EVMProbe) =
    let source = probe.Text
    let where = Convert.ToHexString probe.Bytes
    match (try encodeFirst assembler source with _ -> None) with
    | None -> Some $"{where} '{source}' is not encodable"
    | Some encoded when encoded.Length <> probe.Length ->
      Some $"{where} '{source}' encoded {encoded.Length} bytes wide"
    | Some _ ->
      match roundTrip source with
      | EVMPreserved -> None
      | EVMAltered actual -> Some $"{where} '{source}' encoded as '{actual}'"
      | EVMUnsupported -> Some $"{where} '{source}' is not encodable"

  /// Every probe the sweep produces, run once for the class rather than once
  /// for each test that reads it.
  static let probes = lazy (EVMSweep.probes ())

  /// The instruction a place is written into, over and over, so that a label
  /// can be put far enough away to need more than one byte counting to it.
  let padding count = String.replicate count "  jumpdest\n"

  /// <summary>
  /// The sources a push naming a label is tried in, each paired with the index
  /// of the push and the index its label marks.
  ///
  /// A label is reached from below as well as from above, because a source is
  /// read once from top to bottom and a name used before it is defined is the
  /// harder of the two.
  /// </summary>
  let labelCases width count =
    let filler = padding count
    [ $"L:\n  jumpdest\n  push{width} L\n  jumpdest", 1, 0
      $"  push{width} L\n{filler}L:\n  jumpdest", 0, count + 1
      $"L:\n{filler}  push{width} L\n  jumpdest", count, 0 ]

  /// Every push a label is tried in, paired with how many instructions the
  /// label is put away from it. The narrow ones are given a label far enough
  /// off to fill the bytes they hold and no further, and the wide ones say that
  /// a number narrower than the push is written out to the width named anyway.
  let labelSources = [ 1, 50; 2, 400; 3, 400; 4, 100; 8, 100; 20, 60; 32, 60 ]

  /// Sources that name no instruction at all, either because a number does not
  /// fit where it is written, because the instruction takes nothing where
  /// something was written, or because nothing of that name exists.
  let unencodableSources =
    [ "push1 0x100"
      "push1 -129"
      "push1 256"
      "push2 0x10000"
      "push2 -32769"
      "push32 " + String.replicate 64 "f" + "0"
      "push0 0x1"
      "push1"
      "push1 0x1 0x2"
      "add 0x1"
      "jumpdest 0x1"
      "this.balance 0x1"
      "push"
      "push33 0x1"
      "dup0"
      "dup17"
      "swap0"
      "swap17"
      "log5"
      "frobnicate"
      "push2 L"
      "L:\n  jumpdest\nL:\n  jumpdest"
      $"  push1 L\n{padding 300}L:\n  jumpdest" ]

  /// <summary>
  /// Sources written the way a person writes one rather than the way the
  /// disassembler does, each paired with the instruction it names.
  ///
  /// What the disassembler writes is only part of what an assembler has to
  /// read: a source of its own writes a number below zero with a sign rather
  /// than as the bytes it lands in, writes one in whichever base suits what it
  /// means, and says in a comment what it is doing.
  /// </summary>
  let writtenSources =
    [ "  add  ; what a person writes", "add"
      "ADD", "add"
      "  PUSH1 0X0A", "push1 0xa"
      "This.Balance", "this.balance"
      "push1 -1", "push1 0xff"
      "push32 -1", "push32 0x" + String.replicate 64 "f"
      "push1 0b1010", "push1 0xa"
      "push1 0o17", "push1 0xf"
      "push2 4660", "push2 0x1234"
      "push4 +1", "push4 0x1"
      "push32 0", "push32 0x0"
      "jumpdest", "jumpdest" ]

  /// <summary>
  /// Checks that the sweep reaches the whole of the encoding space.
  ///
  /// Every test below it says that nothing among the instructions it found is
  /// broken, which a sweep finding nothing at all would also say. Rather more
  /// than half of the two hundred and fifty-six bytes name an instruction, and
  /// each push is tried holding several numbers besides.
  /// </summary>
  [<TestMethod>]
  [<TestCategory("Sweep")>]
  member _.``The sweep reaches the whole of the encoding space``() =
    Assert.IsGreaterThan(300, List.length (probes.Force()))

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
  /// Checks that a push naming a label holds the address of the instruction
  /// that label marks, whether the label is written above the push or below it.
  ///
  /// A push written with a label is checked against the same push written with
  /// the address it means to hold, and the sweep above has already pinned what
  /// that instruction is. The push itself is wider than everything around it,
  /// so a source holding one also says that the lines below it were counted at
  /// the right addresses.
  /// </summary>
  [<TestMethod>]
  member _.``A push naming a label holds where that label is``() =
    let wrong =
      [ for width, count in labelSources do
          for source, index, marks in labelCases width count ->
            width, source, index, marks ]
      |> List.choose (fun (width, source, index, marks) ->
        let addressOf i = i + (if i > index then width else 0)
        let expected = encodeFirst assembler $"push{width} {addressOf marks}"
        match (try assembler.Lower source with _ -> Error "raised") with
        | Error _ | Ok [] -> Some $"'push{width} L' does not assemble"
        | Ok encoded ->
          let actual = snd (List.item index encoded)
          if Some actual = expected then None
          else Some $"'push{width} L' became '{disasm actual}'")
      |> List.distinct
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" wrong,
      "These pushes no longer hold the address their label marks.")

  /// <summary>
  /// Checks that a label is counted from the address the source was assembled
  /// at rather than from nothing.
  ///
  /// A push holds where a label is outright, so where the source as a whole was
  /// put is part of every label in it, which a source assembled at zero cannot
  /// say anything about.
  /// </summary>
  [<TestMethod>]
  member _.``A label counts from where the source was assembled``() =
    let based = Assembler(isa, 0x1000UL) :> ILowerable
    match based.Lower "L:\n  jumpdest\n  push2 L" with
    | Ok [ _; (_, bytes) ] ->
      Assert.AreEqual<string>("611000", Convert.ToHexString bytes)
    | Ok _ | Error _ ->
      Assert.Fail "a source assembled elsewhere no longer assembles"

  /// <summary>
  /// Checks that a jump goes where the label it was pushed with marks.
  ///
  /// Nothing this architecture has holds where it goes, so a source names a
  /// place by pushing where it is and jumping to what was pushed. The whole of
  /// a small program is checked here rather than one instruction of it, because
  /// what the push holds is right only if every instruction between it and the
  /// place was counted at the width it really is.
  /// </summary>
  [<TestMethod>]
  member _.``A jump goes where the label it was pushed with marks``() =
    let source = "  push1 dest\n  jump\n  invalid\ndest:\n  jumpdest\n  stop"
    match assembler.Lower source with
    | Ok encoded ->
      let bytes = encoded |> List.map snd |> Array.concat
      Assert.AreEqual<string>("600456FE5B00", Convert.ToHexString bytes)
    | Error err ->
      Assert.Fail $"a program going by a label no longer assembles: {err}"

  /// <summary>
  /// Checks that a source asking for what no encoding can say is refused rather
  /// than encoded.
  ///
  /// A push that silently drops what does not fit encodes an instruction the
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
      "These ask for something no EVM encoding can say.")

  /// <summary>
  /// Checks that the bytes of an instruction come out in the order the machine
  /// reads them.
  ///
  /// A push holds the most telling byte of its number first and fills the bytes
  /// above that number in with zeroes, and neither is something the number
  /// itself can say. The instructions written with a mark in the middle are
  /// checked here too, because a name read as two words is a name read as none.
  /// </summary>
  [<TestMethod>]
  member _.``The bytes come out in the order the machine reads them``() =
    [ "6004", "push1 0x4"
      "60FF", "push1 0xff"
      "611234", "push2 0x1234"
      "6300000001", "push4 0x1"
      "7F" + String.replicate 62 "0" + "01", "push32 0x1"
      "01", "add"
      "5F", "push0"
      "80", "dup1"
      "9F", "swap16"
      "A4", "log4"
      "46", "chain_id"
      "47", "this.balance"
      "48", "block.basefee"
      "FF", "selfdestruct" ]
    |> List.choose (fun (hex, source) ->
      match (try encodeFirst assembler source with _ -> None) with
      | None -> Some $"'{source}' does not assemble"
      | Some bytes when Convert.ToHexString bytes = hex -> None
      | Some bytes -> Some $"'{source}' came out {Convert.ToHexString bytes}")
    |> List.sort
    |> String.concat "\n"
    |> fun wrong ->
      Assert.AreEqual<string>(
        "",
        wrong,
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
      match assembler.Lower "  add\n  push1 0x1" with
      | Ok [ _; _ ] -> ()
      | Ok _ | Error _ -> Assert.Fail $"'{bad}' left the assembler unusable"

// vim: set tw=80 sts=2 sw=2:
