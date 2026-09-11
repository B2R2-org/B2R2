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
open B2R2.FrontEnd.WASM
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.WASM

/// Represents what happened when a reference encoding was round-tripped.
type internal WASMOutcome =
  /// The re-encoded instruction disassembles back to the text we started from.
  | WASMPreserved
  /// The re-encoded instruction means something other than that text.
  | WASMAltered of actual: string
  /// The assembler cannot encode this instruction yet.
  | WASMUnsupported

/// <summary>
/// Checks the WASM assembler against B2R2's own WASM decoder. For each
/// reference encoding we disassemble it into canonical WASM syntax, hand that
/// text back to the assembler, and disassemble the result again. Comparing the
/// resulting *text* rather than the bytes means that picking a
/// valid-but-different encoding is not a failure, while emitting an
/// instruction that means something else is.
///
/// That leniency is not a convenience here, it is forced: the decoder reads a
/// LEB128 number however many bytes it was written in, and the encoder writes
/// it in as few as it needs, so an instruction padded out in the wild does not
/// come back the way it went in. Its width is checked all the same, against
/// the reference encoding, which the sweep writes at its narrowest.
///
/// The assembler derives its table from the decoder, so what the sweep says
/// about which bytes an instruction is, it says of one table twice. The
/// instructions written out by hand below are the independent word on that:
/// every one of them is an encoding read off the specification.
/// </summary>
[<TestClass>]
type WASMRoundTripTests() =

  static let isa = ISA Architecture.WASM

  /// One parser, reused across the whole sweep.
  static let parser =
    WASMParser(BinReader.Init Endian.Little) :> IInstructionParsable

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
    | None ->
      WASMUnsupported
    | Some encoded ->
      let actual = try disasm encoded with _ -> "<undecodable>"
      if actual = source then WASMPreserved else WASMAltered actual

  /// The name a line names, which is the first word of it.
  static let mnemonicOf (text: string) =
    match text.IndexOf ' ' with
    | -1 -> text
    | i -> text.Substring(0, i)

  /// <summary>
  /// Whether the width of what this text encodes to is worth checking.
  ///
  /// A name that two encodings share is one a source cannot pick between, so
  /// the assembler picks the narrower and a probe holding the wider comes out
  /// shorter than it went in. Only select is written that way: a select
  /// carrying no types at all means what the one-byte instruction means.
  /// </summary>
  static let widthIsPinned text =
    Tables.lookup (mnemonicOf text) |> List.length = 1

  /// <summary>
  /// Describes a probe whose text does not encode to an instruction meaning
  /// the same, naming the bytes it was decoded from so that a failure says
  /// where to look.
  ///
  /// How wide the instruction came out is checked as well as what it means,
  /// because an instruction of the wrong width leaves everything after it in a
  /// source at the wrong address, and the text of that one instruction says
  /// nothing about it.
  /// </summary>
  static let brokenProbe (probe: WASMProbe) =
    let source = probe.Text
    let where = Convert.ToHexString probe.Bytes
    match (try encodeFirst assembler source with _ -> None) with
    | None ->
      Some $"{where} '{source}' is not encodable"
    | Some encoded when
        encoded.Length <> probe.Length && widthIsPinned source ->
      Some $"{where} '{source}' encoded {encoded.Length} bytes wide"
    | Some _ ->
      match roundTrip source with
      | WASMPreserved -> None
      | WASMAltered actual -> Some $"{where} '{source}' encoded as '{actual}'"
      | WASMUnsupported -> Some $"{where} '{source}' is not encodable"

  /// Every probe the sweep produces, run once for the class rather than once
  /// for each test that reads it.
  static let probes = lazy (WASMSweep.probes ())

  /// <summary>
  /// Instructions written out from the specification rather than read back
  /// from the decoder, each paired with the bytes the specification gives it.
  ///
  /// This is the one test here the decoder has no hand in. Everything else
  /// derives what it expects from the decoder, and so would go on passing if
  /// the decoder itself came to read a byte as the wrong instruction; these
  /// would not.
  /// </summary>
  let specifiedEncodings =
    [ "unreachable", "00"
      "nop", "01"
      "block", "0240"
      "block i32", "027F"
      "loop", "0340"
      "if", "0440"
      "else", "05"
      "end", "0B"
      "br 1", "0C01"
      "br_if 2", "0D02"
      "br_table 0 1", "0E010001"
      "return", "0F"
      "call 3", "1003"
      "call_indirect 1 0", "110100"
      "drop", "1A"
      "select", "1B"
      "select i32", "1C017F"
      "local.get 0", "2000"
      "local.set 1", "2101"
      "local.tee 2", "2202"
      "global.get 3", "2303"
      "i32.load 2 0", "280200"
      "i32.store 2 4", "360204"
      "memory.size 0", "3F00"
      "memory.grow 0", "4000"
      "i32.const 1", "4101"
      "i32.const -1", "417F"
      "i64.const 1", "4201"
      "f32.const 1", "430000803F"
      "f64.const 1", "44000000000000F03F"
      "i32.eqz", "45"
      "i32.add", "6A"
      "i64.add", "7C"
      "f32.add", "92"
      "f64.add", "A0"
      "i32.wrap_i64", "A7"
      "i32.extend8_s", "C0"
      "ref.null func", "D070"
      "ref.null extern", "D06F"
      "ref.is_null", "D1"
      "ref.func 0", "D200"
      "i32.trunc_sat_f32_s", "FC00"
      "memory.copy 0 0", "FC0A0000"
      "memory.fill 0", "FC0B00"
      "v128.const 0x1 0x0 0x0 0x0",
      "FD0C01000000000000000000000000000000"
      "i8x16.splat", "FD0F"
      "i8x16.extract_lane_s 5", "FD1505"
      "i32x4.add", "FDAE01"
      "memory.atomic.notify 2 0", "FE000200"
      "atomic.fence 0", "FE0300"
      "i32.atomic.load 2 0", "FE100200" ]

  /// Sources that name no instruction at all, either because a number does not
  /// fit where it is written, because the instruction takes something other
  /// than what was written, or because nothing of that name exists.
  let unencodableSources =
    [ "i32.const 4294967296"
      "i32.const -2147483649"
      "i32.const"
      "f32.const abc"
      "call -1"
      "call 4294967296"
      "local.get 4294967296"
      "nop 1"
      "block i32 i32"
      "ref.null nothing"
      "br_table"
      "atomic.fence 256"
      "i8x16.extract_lane_s 256"
      "v128.const 0x1 0x2 0x3"
      "i32.load 2"
      "i32.load 2 0 0 0"
      "frobnicate"
      "i32.addd" ]

  /// <summary>
  /// Sources written the way a person writes one rather than the way the
  /// disassembler does, each paired with the instruction it names.
  ///
  /// What the disassembler writes is only part of what an assembler has to
  /// read: a source of its own writes a number in whichever base suits what it
  /// means, spells the values a decimal point cannot the way the text format
  /// does, and says in a comment what it is doing.
  /// </summary>
  let writtenSources =
    [ "  nop  ;; what a person writes", "nop"
      "I32.ADD", "i32.add"
      "Block I32", "block i32"
      "00000010: nop", "nop"
      "i32.const 0x2a", "i32.const 42"
      "i32.const 0b1010", "i32.const 10"
      "i32.const 0o17", "i32.const 15"
      "i32.const +1", "i32.const 1"
      "i64.const 0xffffffffffffffff", "i64.const -1"
      "f32.const inf", "f32.const Infinity"
      "f32.const -inf", "f32.const -Infinity"
      "f32.const nan", "f32.const NaN"
      "f64.const 1e10", "f64.const 10000000000"
      "ref.null FUNC", "ref.null func" ]

  /// <summary>
  /// Checks that the sweep reaches the whole of the encoding space.
  ///
  /// Every test below it says that nothing among the instructions it found is
  /// broken, which a sweep finding nothing at all would also say. There are
  /// upwards of five hundred instructions, each padded out three ways, so a
  /// sweep reaching what it should reaches a good many more probes than this.
  /// </summary>
  [<TestMethod>]
  [<TestCategory("Sweep")>]
  member _.``The sweep reaches the whole of the encoding space``() =
    Assert.IsGreaterThan(1000, List.length (probes.Force()))

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
       instruction that means something else."
    )

  /// <summary>
  /// Checks the instructions whose encoding is written out from the
  /// specification, which is the one word here the decoder has no hand in.
  /// </summary>
  [<TestMethod>]
  member _.``The bytes come out the way the specification says``() =
    let wrong =
      specifiedEncodings
      |> List.choose (fun (source, hex) ->
        match (try encodeFirst assembler source with _ -> None) with
        | None -> Some $"'{source}' does not assemble"
        | Some bytes when Convert.ToHexString bytes = hex -> None
        | Some bytes -> Some $"'{source}' came out {Convert.ToHexString bytes}")
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" wrong,
      "These no longer come out the way the specification says."
    )

  /// <summary>
  /// Checks that a source asking for what no encoding can say is refused
  /// rather than encoded.
  ///
  /// An instruction that silently drops what does not fit encodes something
  /// the source did not ask for, which is worse than encoding nothing at all.
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
      "These ask for something no WASM encoding can say."
    )

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

  /// <summary>
  /// Checks that a memarg names a memory only when a source writes one.
  ///
  /// The memory index is not a field of its own: bit 6 of the alignment is
  /// what says it is there. So an alignment carrying that bit names a memarg a
  /// source cannot mean, whichever of the two forms it was written in, and one
  /// carrying the bit above it is an ordinary alignment that has to survive
  /// being written out whole.
  /// </summary>
  [<TestMethod>]
  member _.``A memarg names a memory only when one is written``() =
    [ "i32.load 2 16", "280210"
      "i32.load 2 3 16", "28420310"
      "i32.load 0 0", "280000"
      "i32.load 0 1 0", "28400100"
      "i32.load 128 0", "28800100" ]
    |> List.choose (fun (source, hex) ->
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
        "These no longer say where the flag bit of a memarg belongs."
      )

  /// <summary>
  /// Checks that a source is read one line at a time, each line one
  /// instruction.
  ///
  /// A WASM branch says how many blocks out it goes rather than where it goes,
  /// so nothing in a source depends on where the lines before it landed. What
  /// a source of several lines has to say is only that each of them came out
  /// whole and in order.
  /// </summary>
  [<TestMethod>]
  member _.``A source is read one line at a time``() =
    let source = "  block i32\n  i32.const 1\n  br 0\n  end\n\n  drop"
    match assembler.Lower source with
    | Ok encoded ->
      let bytes = encoded |> List.map snd |> Array.concat
      Assert.AreEqual<int>(5, List.length encoded)
      Assert.AreEqual<string>("027F41010C000B1A", Convert.ToHexString bytes)
    | Error err ->
      Assert.Fail $"a source of several lines no longer assembles: {err}"

  /// Checks that a source the assembler refuses leaves it able to read the
  /// next one, which a parser keeping state across a failure would not.
  [<TestMethod>]
  member _.``A refused source leaves the assembler usable``() =
    for bad in unencodableSources do
      (try encodeFirst assembler bad |> ignore with _ -> ())
      match assembler.Lower "  nop\n  i32.const 1" with
      | Ok [ _; _ ] -> ()
      | Ok _ | Error _ -> Assert.Fail $"'{bad}' left the assembler unusable"

// vim: set tw=80 sts=2 sw=2:
