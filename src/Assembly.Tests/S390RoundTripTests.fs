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
open B2R2.Assembly.S390

/// Represents what happened when a reference encoding was round-tripped.
type internal S390Outcome =
  /// The re-encoded instruction disassembles back to the text we started from.
  | S390Preserved
  /// The re-encoded instruction means something other than that text.
  | S390Altered of actual: string
  /// The assembler cannot encode this instruction yet.
  | S390Unsupported

/// <summary>
/// Checks the S390 assemblers against B2R2's own S390 decoder. For each
/// reference encoding we disassemble it into canonical S390 syntax, hand that
/// text back to the assembler, and disassemble the result again. Comparing the
/// resulting *text* rather than the bytes means that picking a
/// valid-but-different encoding is not a failure, while emitting an instruction
/// that means something else is.
///
/// Nothing here is a hand-written expectation, and nothing is a hand-written
/// input either: S390Sweep walks the encoding space and the decoder says what
/// each word means, so the set of instructions under test is whatever the
/// decoder currently understands. Both targets are checked, because s390 runs
/// ESA/390 and s390x runs z/Architecture, and which instructions exist is not
/// the same question for the two of them. Forms that canonical disassembly
/// cannot express - labels above all - are pinned by the hand-written tests
/// below.
/// </summary>
[<TestClass>]
type S390RoundTripTests() =

  static let isa = ISA(Architecture.S390, Endian.Big, WordSize.Bit64)

  static let isa32 = ISA(Architecture.S390, Endian.Big, WordSize.Bit32)

  /// One parser per target, reused across the whole sweep. The sweep asks for
  /// hundreds of thousands of decodings, so building one each time would
  /// dominate the run.
  static let parser = S390Sweep.parserFor WordSize.Bit64

  static let parser32 = S390Sweep.parserFor WordSize.Bit32

  static let assembler = Assembler(isa, 0UL) :> ILowerable

  static let assembler32 = Assembler(isa32, 0UL) :> ILowerable

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
    | None -> S390Unsupported
    | Some encoded ->
      let actual = try disasmWith parser encoded with _ -> "<undecodable>"
      if actual = source then S390Preserved else S390Altered actual

  /// Describes a source that does not encode to something meaning the same.
  static let brokenSource assembler parser source =
    match roundTripWith assembler parser source with
    | S390Preserved -> None
    | S390Altered actual -> Some $"'{source}' encoded as '{actual}'"
    | S390Unsupported -> Some $"'{source}' is not encodable"

  /// Every probe the sweep produces. The sweep is the expensive part of this
  /// file, so it runs once for the class rather than once for each test that
  /// reads it.
  static let probes = lazy (S390Sweep.probes ())

  /// The probes a 32-bit target reads, which is the part of the instruction set
  /// ESA/390 already had.
  static let probes32 =
    lazy (S390Sweep.readableBy WordSize.Bit32 (probes.Force()))

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
  /// long, which is the shortest an S390 instruction gets.
  let padding = String.replicate 200 "  lr R0, R0\n"

  /// <summary>
  /// The sources a branch to a label is tried in, each paired with the index of
  /// the instruction under test and the index of the one its label marks.
  ///
  /// A label is reached from below as well as from above, and from far enough
  /// away that a field holding too few bits would not reach it.
  /// </summary>
  let branchCases source =
    [ $"L:\n  lr R0, R0\n  {source}\n  lr R0, R0", 1, 0
      $"  {source}\n{padding}L:\n  lr R0, R0", 0, 201
      $"L:\n{padding}  {source}\n  lr R0, R0", 200, 0 ]

  /// <summary>
  /// Every instruction that names a place, as the source naming it with a label
  /// and what the disassembler writes for that instruction.
  ///
  /// The mark stands for how far away the place is and where it ends up. The
  /// disassembler writes that in the middle of the operands rather than after
  /// all of them for the instructions counting a register down and for the one
  /// telling the machine what a branch further on will do.
  /// </summary>
  let branchSources =
    [ "brc B'1111', L", "brc B'1111', @"
      "brcl B'0011', L", "brcl B'0011', @"
      "bras R1, L", "bras R1, @"
      "brasl R1, L", "brasl R1, @"
      "brct R2, L", "brct R2, @"
      "brctg R3, L", "brctg R3, @"
      "brcth R4, L", "brcth R4, @"
      "brxh R1, L, R3", "brxh R1, @, R3"
      "brxle R1, L, R3", "brxle R1, @, R3"
      "brxhg R1, L, R3", "brxhg R1, @, R3"
      "crj R1, R2, B'0010', L", "crj R1, R2, B'0010', @"
      "clgrj R1, R2, B'0010', L", "clgrj R1, R2, B'0010', @"
      "cij R1, 0x5, B'0010', L", "cij R1, 0x5, B'0010', @"
      "larl R1, L", "larl R1, @"
      "lgrl R1, L", "lgrl R1, @"
      "strl R1, L", "strl R1, @"
      "exrl R1, L", "exrl R1, @"
      "pfdrl B'0001', L", "pfdrl B'0001', @"
      "bpp B'0001', L, 0x0(R0)", "bpp B'0001', @, 0x0(R0)" ]

  /// Sources that name no instruction at all, either because a number does not
  /// fit where it is written, because a register cannot be named there, or
  /// because the instruction is written with the wrong things after it.
  let unencodableSources =
    [ "a R1, 0x1000(R2, R3)"
      "lg R1, 0x80000(R2, R3)"
      "lg R1, -0x80001(R2, R3)"
      "ahi R1, 0x10000"
      "lgfi R1, 0x100000000"
      "svc 0x100"
      "niai 0x10, 0x0"
      "brc B'1111', 0x1"
      "brc B'1111', 0x10000"
      "brasl R1, 0x100000000"
      "brc B'11111', 0x10"
      "mvc 0x0(0, R1), 0x0(R2)"
      "mvc 0x0(257, R1), 0x0(R2)"
      "tp 0x0(17, R1)"
      "lr R1"
      "lr R1, R2, R3"
      "lr R1, 0x1"
      "lr FPR1, FPR2"
      "ler R1, R2"
      "lg VR1, 0x0(R2, R3)"
      "lgr R1, AR2"
      "lctl R1, R2, 0x0(R3)"
      "a R1, R2"
      "a R1, 0x0(R2)"
      "vl VR1, 0x0(R2, R3)"
      "fixbra FPR1, FPR2, B'0011', B'0000'"
      "ledbra FPR1, FPR2, B'0000', B'0000'"
      "frobnicate R1, R2" ]

  /// Sources written the way a person writes one rather than the way the
  /// disassembler does, each paired with the instruction it names.
  let writtenSources =
    [ "  lr R1, R2  # what a person writes", "lr R1, R2"
      "LR R1, R2", "lr R1, R2"
      "lr r1, r2", "lr R1, R2"
      "a R1, 8(R2,R3)", "a R1, 0x8(R2, R3)"
      "a R1, 8( R2 , R3 )", "a R1, 0x8(R2, R3)"
      "ahi R1, -1", "ahi R1, 0xffff"
      "lay R1, -8(R2, R3)", "lay R1, 0xfffffff8(R2, R3)"
      "mvc 0(16,R1), 0(R2)", "mvc 0x0(16, R1), 0x0(R2)"
      "brc b'1111', 0x10", "brc B'1111', +0x10 ; 0x10"
      "brc b'1111', -0x10", "brc B'1111', -0x10 ; 0xfffffffffffffff0"
      "bcr B'1111', R14", "bcr B'1111', R14"
      "vl VR19, 0x0(R2, R3), B'0000'", "vl VR19, 0x0(R2, R3), B'0000'"
      "pr", "pr" ]

  /// One instruction of each of the three lengths an S390 instruction has,
  /// paired with how many bytes long it is.
  let lengths =
    [ "lr R1, R2", 2
      "a R1, 0x8(R2, R3)", 4
      "lay R1, 0x8(R2, R3)", 6 ]

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
  member _.``Every instruction a 32-bit target reads, it also writes``() =
    let texts = probes32.Force() |> List.map (fun probe -> probe.Text)
    Assert.AreEqual<string>(
      "",
      brokenSources assembler32 parser32 texts,
      "These instructions decode for a 32-bit target but no longer encode for \
       one, or encode to an instruction that means something else.")

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
          let distance = int64 target - int64 addr
          let sign = if distance < 0L then "-" else "+"
          let bytes = snd (List.item index encoded)
          let text =
            try (parser.Parse(bytes, addr)).Disasm() with _ -> "<undecodable>"
          let want =
            expected.Replace("@",
              $"{sign}0x{abs distance:x} ; 0x{target:x}")
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
      "These ask for something no S390 encoding can say.")

  /// Checks that an assembler for a 32-bit target refuses what only
  /// z/Architecture has, because such a target could not read it back.
  [<TestMethod>]
  member _.``A 32-bit target is not given what z-Architecture added``() =
    let encoded =
      [ "lgr R1, R2"
        "lg R1, 0x0(R2, R3)"
        "lay R1, 0x0(R2, R3)"
        "vl VR1, 0x0(R2, R3), B'0000'"
        "sam64"
        "lgfi R1, 0x1" ]
      |> List.choose (fun source ->
        match (try encodeFirst assembler32 source with _ -> None) with
        | None -> None
        | Some _ -> Some source)
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" encoded,
      "These are not ESA/390 instructions, so a 32-bit target cannot read \
       them back.")

  /// <summary>
  /// Checks that a source written the way a person writes one names the same
  /// instruction as the canonical text for it.
  ///
  /// What the disassembler writes is only part of what an assembler has to
  /// read: a source of its own writes a number below zero with a sign rather
  /// than as the bits it lands in, leaves out the spaces the disassembler puts
  /// inside an address, names a register in lower case, and says in a comment
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
  /// An S390 instruction is two, four, or six bytes long, and how far away a
  /// label is depends on which of those every instruction before it was, so an
  /// encoder that got a length wrong would reach the wrong place.
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
      match assembler.Lower "  lr R1, R2\n  a R1, 0x8(R2, R3)" with
      | Ok [ _; _ ] -> ()
      | Ok _ | Error _ -> Assert.Fail $"'{bad}' left the assembler unusable"

// vim: set tw=80 sts=2 sw=2:
