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
open System.IO
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.ARM32
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.ARM32

/// Represents what happened when a reference encoding was round-tripped.
type internal ARM32Outcome =
  /// The re-encoded word disassembles back to the text we started from.
  | ARM32Preserved
  /// The re-encoded word means something other than the text we started from.
  | ARM32Altered of actual: string
  /// The assembler cannot encode this instruction yet.
  | ARM32Unsupported

/// <summary>
/// Checks the ARM32 assembler against B2R2's own ARM32 decoder, which is far
/// better tested (see B2R2.FrontEnd.ARM32.Tests). For each reference encoding
/// we disassemble it into canonical ARM syntax, hand that text back to the
/// assembler, and disassemble the result again. Comparing the resulting *text*
/// rather than the bytes means that picking a valid-but-different encoding is
/// not a failure, while emitting a word that means something else is.
///
/// Nothing here is a hand-written expectation, and nothing is a hand-written
/// input either: ARM32Sweep walks the encoding space and the decoder says what
/// each word means, so the set of instructions under test is whatever the
/// decoder currently understands. Forms that canonical disassembly cannot
/// express - labels, aliases, letter case - live in ARM32EncodingTests instead.
/// </summary>
[<TestClass>]
type ARM32RoundTripTests() =

  /// Runs the given action with stderr muted. Terminator.futureFeature writes a
  /// stack trace there for every unsupported opcode, which would bury the
  /// actual test output.
  static let mutingStderr action =
    let saved = Console.Error
    Console.SetError TextWriter.Null
    try action () finally Console.SetError saved

  static let isa = ISA(Architecture.ARMv7, WordSize.Bit32)

  /// One parser, reused across the whole sweep. Building one costs an array of
  /// operand parsers, and the sweep asks for tens of thousands of decodings.
  static let parser =
    ARM32Parser(isa, false, BinReader.Init Endian.Little)
    :> IInstructionParsable

  static let assembler = Assembler(isa, 0UL) :> ILowerable

  /// A Thumb parser and assembler of their own: which instruction set a line
  /// belongs to is settled when each is built, as nothing in the line says.
  static let thumbParser =
    ARM32Parser(isa, true, BinReader.Init Endian.Little)

  static let thumbAssembler =
    Assembler(ISA(Endian.Little, false, ARM32Mode.Thumb), 0UL) :> ILowerable

  static let disasm (bytes: byte[]) = (parser.Parse(bytes, 0UL)).Disasm()

  static let encodeFirst text =
    match assembler.Lower text with
    | Ok((_, bytes) :: _) -> Some bytes
    | Ok [] | Error _ -> None

  /// Encodes the given source and disassembles the result, so that a source
  /// text stands in for the word a probe was decoded from.
  static let sourceRoundTrip (source: string) =
    match (try encodeFirst source with _ -> None) with
    | None ->
      ARM32Unsupported
    | Some encoded ->
      let actual = try disasm encoded with _ -> "<undecodable>"
      if actual = source then ARM32Preserved else ARM32Altered actual

  static let thumbDisasm addr (bytes: byte[]) =
    (thumbParser :> IModeSwitchable).ITState <- 0uy
    let padded = Array.append bytes [| 0x00uy; 0xbfuy |]
    ((thumbParser :> IInstructionParsable).Parse(padded, addr)).Disasm()

  static let thumbRoundTrip (source: string) =
    match (try thumbAssembler.Lower source with _ -> Error "raised") with
    | Error _ | Ok [] ->
      ARM32Unsupported
    | Ok((_, bytes) :: _) ->
      let actual = try thumbDisasm 0UL bytes with _ -> "<undecodable>"
      if actual = source then ARM32Preserved else ARM32Altered actual

  /// <summary>
  /// Disassembles a whole sequence, letting the state of an IT block carry from
  /// one instruction to the next as it does when the processor runs them.
  /// </summary>
  static let thumbDisasmSequence (encoded: byte[] list) =
    (thumbParser :> IModeSwitchable).ITState <- 0uy
    let parser = thumbParser :> IInstructionParsable
    encoded
    |> List.fold (fun (addr, texts) (bytes: byte[]) ->
      let padded = Array.append bytes [| 0x00uy; 0xbfuy |]
      let text = (parser.Parse(padded, addr)).Disasm()
      addr + uint64 bytes.Length, text :: texts) (0UL, [])
    |> snd
    |> List.rev

  /// Round-trips every Thumb instruction the decoder reads.
  static let thumbOutcomes =
    lazy (mutingStderr (fun () ->
      [ for probe in ARM32Sweep.thumbProbes () ->
          probe, thumbRoundTrip probe.Text ]))

  /// Round-trips every probe the sweep produces. The sweep is the expensive
  /// part of this file, so it runs once for the class rather than once for each
  /// test that reads it.
  static let sweepOutcomes =
    lazy (mutingStderr (fun () ->
      [ for probe in ARM32Sweep.probes () ->
          probe, sourceRoundTrip probe.Text ]))

  /// Describes every source that does not encode to a word meaning the same.
  let brokenSources sources =
    mutingStderr (fun () ->
      sources
      |> List.choose (fun source ->
        match sourceRoundTrip source with
        | ARM32Preserved -> None
        | ARM32Altered actual -> Some $"'{source}' encoded as '{actual}'"
        | ARM32Unsupported -> Some $"'{source}' is not encodable"))
    |> List.sort

  /// Crosses a list of source templates with the opcodes that share them.
  let expand (opcodes: string list) (shapes: string list) =
    [ for shape in shapes do
        for opcode in opcodes -> shape.Replace("OP", opcode) ]

  /// The data-processing instructions that read two sources, which share one
  /// encoding path.
  let dataProcOpcodes =
    [ "and"; "eor"; "sub"; "rsb"; "add"; "adc"; "sbc"; "rsc"; "orr"; "bic" ]

  /// Every operand shape that path accepts, as a source template. Crossed with
  /// the opcodes below, so that collapsing them into one encoder cannot quietly
  /// change a single shape for a single opcode.
  let dataProcShapes =
    [ "OP r0, r1, r2"
      "OP r0, r1, #0x1"
      "OP r0, r1, #0xff000000"
      "OP r0, r1, r2, lsl #0x1"
      "OP r0, r1, r2, lsr #0x20"
      "OP r0, r1, r2, asr #0x20"
      "OP r0, r1, r2, ror #0x1f"
      "OP r0, r1, r2, rrx #0x1"
      "OP r0, r1, r2, lsl r3"
      "OP r0, r1, r2, ror r3"
      "OPs r0, r1, r2"
      "OPs r0, r1, #0x1"
      "OPs r0, r1, r2, lsl #0x1"
      "OPne sp, lr, pc"
      "OPeq fp, ip, sb, asr #0x3" ]

  /// The instructions that only set the flags, which name no destination.
  let testOpcodes = [ "tst"; "teq"; "cmp"; "cmn" ]

  let testShapes =
    [ "OP r1, r2"
      "OP r1, #0x1"
      "OP r1, r2, lsl #0x1"
      "OP r1, r2, lsl r3"
      "OPne sp, pc" ]

  /// The shifts, which the manual defines as aliases of MOV.
  let shiftOpcodes = [ "lsl"; "lsr"; "asr"; "ror" ]

  let shiftShapes =
    [ "OP r0, r1, #0x1"
      "OP r0, r1, r2"
      "OPs r0, r1, #0x1"
      "OPs r0, r1, r2"
      "OPne sp, lr, #0x1f" ]

  /// The loads and stores of a word or a byte, which share one encoding path
  /// with every way of naming a place.
  let loadStoreOpcodes = [ "ldr"; "str"; "ldrb"; "strb" ]

  let loadStoreShapes =
    [ "OP r0, [r1]"
      "OP r0, [r1, #0x4]"
      "OP r0, [r1, #-0x4]"
      "OP r0, [r1, #0xfff]"
      "OP r0, [r1, #0x4]!"
      "OP r0, [r1], #0x4"
      "OP r0, [r1], #-0x4"
      "OP r0, [r1, r2]"
      "OP r0, [r1, -r2]"
      "OP r0, [r1, r2, lsl #0x2]"
      "OP r0, [r1, r2, asr #0x20]"
      "OP r0, [r1, r2, rrx #0x1]"
      "OP r0, [r1, r2]!"
      "OP r0, [r1], r2"
      "OP r0, [r1], r2, lsl #0x2"
      (* A load whose base is the program counter is a literal one. The
         disassembler resolves it to an address rather than printing it as
         written, so ARM32EncodingTests pins that form instead. *)
      "OPne sp, [lr, #0x8]"
      "OPeq lr, [fp, -ip, ror #0x1f]" ]

  /// The loads and stores of a halfword or a signed byte, whose immediate
  /// offset is narrower and split in two.
  let extraLoadStoreOpcodes = [ "ldrh"; "strh"; "ldrsb"; "ldrsh" ]

  let extraLoadStoreShapes =
    [ "OP r0, [r1]"
      "OP r0, [r1, #0x4]"
      "OP r0, [r1, #-0xff]"
      "OP r0, [r1, #0x4]!"
      "OP r0, [r1], #0x4"
      "OP r0, [r1, r2]"
      "OP r0, [r1, -r2]"
      "OP r0, [r1, r2]!"
      "OP r0, [r1], r2"
      "OPne sp, [lr, #0x8]" ]

  /// The transfers of several registers at once, which name a list rather than
  /// a place.
  let blockOpcodes =
    [ "ldm"; "ldmda"; "ldmdb"; "ldmib"; "stm"; "stmda"; "stmdb"; "stmib" ]

  let blockShapes =
    [ "OP r1, {r0}"
      "OP r1, {r0, r2}"
      "OP r1, {r0, r1, r2, r3, r4, r5, r6, r7}"
      "OP r1!, {r0, r2}"
      "OP r1!, {r4, lr}"
      (* A caret moves the registers of another mode instead, which neither
         writes the base back nor reaches the program counter. *)
      "OP r1, {r0, r2}^"
      "OPne r1, {r0, sb, sl, fp, ip, sp, lr, pc}" ]

  /// The floating-point operations on three registers, which share one
  /// encoding path and differ only in an opcode split around a register field.
  let floatingPointOpcodes =
    [ "vmla"
      "vmls"
      "vnmls"
      "vnmla"
      "vmul"
      "vnmul"
      "vadd"
      "vsub"
      "vdiv"
      "vfnms"
      "vfnma"
      "vfma"
      "vfms" ]

  /// Both widths of every one of them, since which width an instruction is
  /// written for is read off its registers rather than out of its mnemonic.
  let floatingPointShapes =
    [ "OP.f64 d0, d1, d2"
      "OP.f64 d16, d17, d18"
      "OP.f32 s0, s1, s2"
      "OP.f32 s21, s22, s23"
      "OPne.f64 d10, d25, d12" ]

  /// The SIMD operations on three registers of the same length, which read the
  /// same number of elements as they write.
  let simdOpcodes = [ "vhadd"; "vqadd"; "vcgt"; "vcge" ]

  let simdShapes =
    [ "OP.s8 d0, d1, d2"
      "OP.s16 d0, d1, d2"
      "OP.s32 d16, d17, d18"
      "OP.u8 q0, q1, q2"
      "OP.u16 q0, q1, q2"
      "OP.u32 q13, q14, q15" ]

  /// <summary>
  /// Sources that open an IT block and fill it, which is the only way a narrow
  /// Thumb instruction runs conditionally.
  ///
  /// None of the condition is encoded in the instructions inside the block: the
  /// block is what says it, and the source writes it on each of them only so
  /// that the two can be seen to agree. What this checks is that the block
  /// still says what the source wrote, which it can only do by reading it back
  /// off every instruction the block covers.
  /// </summary>
  let ifThenSources =
    [ for first, second in
        [ "eq", "ne"
          "cs", "cc"
          "mi", "pl"
          "vs", "vc"
          "hi", "ls"
          "ge", "lt"
          "gt", "le" ] do
        (* A block holds four instructions at most, so it names three after
           the one its own condition covers. *)
        for letters in [ ""
                         "t"
                         "e"
                         "tt"
                         "te"
                         "et"
                         "ee"
                         "ttt"
                         "tte"
                         "tet"
                         "tee"
                         "ett"
                         "ete"
                         "eet"
                         "eee" ] do
          let conditions =
            first :: [ for letter in letters ->
                         if letter = 't' then first else second ]
          (* The instructions inside a block cover the ones whose narrow
             encoding sets the flags, which is written without the S that says
             so, and one that has nothing to say about them either way. *)
          let templates =
            [ (fun c -> $"add{c} r0, r0, r1")
              (fun c -> $"and{c} r2, r2, r3")
              (fun c -> $"mov{c} r4, #0x5")
              (fun c -> $"cmp{c} r6, r7") ]
          let body =
            conditions |> List.mapi (fun i cond -> (List.item i templates) cond)
          yield $"it{letters} {first}" :: body ]

  /// Padding long enough that the distance to the label is not a small number.
  /// Every A32 branch has the same reach, so what this checks is that a long
  /// distance is measured the same way as a short one.
  let padding = String.replicate 200 "  nop\n"

  /// A source that branches to a label, paired with which instruction the
  /// branch is and where the label ends up. Every instruction is four bytes
  /// long, so both follow from counting the instructions in the source.
  let branchCases opcode =
    [ $"  {opcode} L\n  nop\nL:\n  nop", 0, 0x8UL
      $"L:\n  nop\n  {opcode} L\n  nop", 1, 0x0UL
      $"  {opcode} L\n{padding}L:\n  nop", 0, 0x324UL
      $"L:\n{padding}  {opcode} L\n  nop", 200, 0x0UL ]

  let branchOpcodes = [ "b"; "bl"; "bne"; "bleq"; "blx" ]

  [<TestMethod>]
  [<TestCategory("Sweep")>]
  member _.``Every instruction the decoder decodes, the assembler encodes``() =
    let broken =
      sweepOutcomes.Force()
      |> List.choose (fun (probe, outcome) ->
        match outcome with
        | ARM32Preserved -> None
        | ARM32Altered actual -> Some $"'{probe.Text}' encoded as '{actual}'"
        | ARM32Unsupported -> Some $"'{probe.Text}' is not encodable")
      |> List.distinct
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" broken,
      "These instructions decode but no longer encode, or encode to a word \
       that means something else.")

  [<TestMethod>]
  member _.``Every data-processing shape encodes correctly``() =
    let wrong =
      expand dataProcOpcodes dataProcShapes
      @ expand testOpcodes testShapes
      @ expand shiftOpcodes shiftShapes
      |> brokenSources
    Assert.AreEqual<string>(
      "",
      String.concat "\n" wrong,
      "These data-processing operand shapes no longer encode correctly.")

  [<TestMethod>]
  member _.``Every load and store shape encodes correctly``() =
    let wrong =
      expand loadStoreOpcodes loadStoreShapes
      @ expand extraLoadStoreOpcodes extraLoadStoreShapes
      @ expand blockOpcodes blockShapes
      |> brokenSources
    Assert.AreEqual<string>(
      "",
      String.concat "\n" wrong,
      "These memory operand shapes no longer encode correctly.")

  [<TestMethod>]
  [<TestCategory("Sweep")>]
  member _.``Every Thumb instruction the decoder decodes encodes``() =
    let broken =
      thumbOutcomes.Force()
      |> List.choose (fun (probe, outcome) ->
        match outcome with
        | ARM32Preserved -> None
        | ARM32Altered actual -> Some $"'{probe.Text}' encoded as '{actual}'"
        | ARM32Unsupported -> Some $"'{probe.Text}' is not encodable")
      |> List.distinct
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" broken,
      "These Thumb instructions decode but no longer encode, or encode to a \
       halfword that means something else.")

  [<TestMethod>]
  member _.``Every SIMD and floating-point shape encodes correctly``() =
    let wrong =
      expand floatingPointOpcodes floatingPointShapes
      @ expand simdOpcodes simdShapes
      |> brokenSources
    Assert.AreEqual<string>(
      "",
      String.concat "\n" wrong,
      "These SIMD and floating-point operand shapes no longer encode \
       correctly.")

  [<TestMethod>]
  member _.``An IT block says what the instructions in it run under``() =
    let wrong =
      mutingStderr (fun () ->
        ifThenSources
        |> List.choose (fun lines ->
          let source = lines |> List.map (fun line -> "  " + line)
          let text = String.concat "\n" source
          match (try thumbAssembler.Lower text with _ -> Error "raised") with
          | Error _ ->
            Some $"'{List.head lines}' does not assemble"
          | Ok encoded ->
            let read =
              try thumbDisasmSequence (List.map snd encoded)
              with _ -> [ "<undecodable>" ]
            let written = String.concat "; " lines
            let readBack = String.concat "; " read
            if read = lines then None
            else Some $"'{written}' read back as '{readBack}'"))
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" wrong,
      "These blocks no longer say what the instructions in them run under.")

  [<TestMethod>]
  member _.``Branches to a label reach it in both directions``() =
    let wrong =
      mutingStderr (fun () ->
        [ for opcode in branchOpcodes do
            for source, index, target in branchCases opcode ->
              opcode, source, index, target ]
        |> List.choose (fun (opcode, source, index, target) ->
          match (try assembler.Lower source with _ -> Error "raised") with
          | Error _ ->
            Some $"'{opcode} L' does not assemble"
          | Ok encoded ->
            let addr = uint64 (4 * index)
            let text =
              try (parser.Parse(snd (List.item index encoded), addr)).Disasm()
              with _ -> "<undecodable>"
            if text.StartsWith $"{opcode} 0x{target:x} " then None
            else Some $"'{opcode} L' at 0x{addr:x} became '{text}'"))
      |> List.distinct
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" wrong,
      "These branches no longer reach the instruction their label marks.")
