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
open System.Text.RegularExpressions
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.ARM64
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.ARM64

/// Represents what happened when a reference encoding was round-tripped.
type internal ARM64Outcome =
  /// The re-encoded word disassembles back to the text we started from.
  | ARM64Preserved
  /// The re-encoded word means something other than the text we started from.
  | ARM64Altered of actual: string
  /// The assembler cannot encode this instruction yet.
  | ARM64Unsupported

/// <summary>
/// Checks the ARM64 assembler against B2R2's own ARM64 decoder, which is far
/// better tested (see B2R2.FrontEnd.ARM64.Tests). For each reference encoding
/// we disassemble it into canonical A64 syntax, hand that text back to the
/// assembler, and disassemble the result again. Comparing the resulting *text*
/// rather than the bytes means that picking a valid-but-different encoding is
/// not a failure, while emitting a word that means something else is.
///
/// Nothing here is a hand-written expectation, and nothing is a hand-written
/// input either: ARM64Sweep walks the encoding space and the decoder says what
/// each word means, so the set of instructions under test is whatever the
/// decoder currently understands. Forms that canonical disassembly cannot
/// express - labels above all - are pinned by the hand-written tests below.
/// </summary>
[<TestClass>]
type ARM64RoundTripTests() =

  /// Runs the given action with stderr muted. Terminator.futureFeature writes a
  /// stack trace there for every unsupported opcode, which would bury the
  /// actual test output.
  static let mutingStderr action =
    let saved = Console.Error
    Console.SetError TextWriter.Null
    try action () finally Console.SetError saved

  static let isa = ISA(Architecture.ARMv8, WordSize.Bit64)

  /// One parser, reused across the whole sweep. The sweep asks for hundreds of
  /// thousands of decodings, so building one each time would dominate the run.
  static let parser =
    ARM64Parser(BinReader.Init Endian.Little) :> IInstructionParsable

  static let assembler = Assembler(isa, 0UL) :> ILowerable

  static let disasm (bytes: byte[]) = (parser.Parse(bytes, 0UL)).Disasm()

  static let encodeFirst text =
    match assembler.Lower text with
    | Ok((_, bytes) :: _) -> Some bytes
    | Ok [] | Error _ -> None

  /// <summary>
  /// Whether two texts name one instruction under both of its names.
  ///
  /// An inclusive or that reads the zero register is what the manual writes as
  /// a move, and the disassembler writes the move, so a source that spells the
  /// or out cannot come back as itself. The word it assembles to is the one it
  /// asked for; only the name it comes back under is the other one.
  /// </summary>
  static let namesTheSame (expected: string) (actual: string) =
    match expected.Split ' ' |> Array.toList with
    | [ "orr"; rd; "wzr,"; rm ] | [ "orr"; rd; "xzr,"; rm ] ->
      actual = $"mov {rd} {rm}"
    | "mov" :: rest ->
      actual = "umov " + String.concat " " rest
    | "umov" :: rest ->
      actual = "mov " + String.concat " " rest
    | _ ->
      false

  /// Encodes the given source and disassembles the result, so that a source
  /// text stands in for the word a probe was decoded from.
  static let sourceRoundTrip (source: string) =
    match (try encodeFirst source with _ -> None) with
    | None ->
      ARM64Unsupported
    | Some encoded ->
      let actual = try disasm encoded with _ -> "<undecodable>"
      if actual = source || namesTheSame source actual then ARM64Preserved
      else ARM64Altered actual

  /// Round-trips every probe the sweep produces. The sweep is the expensive
  /// part of this file, so it runs once for the class rather than once for each
  /// test that reads it.
  static let sweepOutcomes =
    lazy (mutingStderr (fun () ->
      [ for probe in ARM64Sweep.probes () ->
          probe, sourceRoundTrip probe.Text ]))

  /// Every arrangement a vector is read in, so that a shape can be tried at
  /// each of them.
  static let arrangements =
    [ "8b"; "16b"; "4h"; "8h"; "2s"; "4s"; "1d"; "2d"; "1q" ]

  /// Every width one element is read at.
  static let widths = [ "b"; "h"; "s"; "d"; "q" ]

  /// <summary>
  /// Every text the given one becomes when the arrangement its registers are
  /// read in, or the width they are read at, is replaced by each of the others.
  ///
  /// Only a text whose registers are all read the same way is varied, because
  /// one that reads two widths at once relates them, and what that relation is
  /// belongs to the instruction rather than to this substitution.
  /// </summary>
  static let variants (text: string) =
    let replaceAll pattern (replacement: string) input =
      Regex.Replace(input, pattern, replacement)
    let distinct pattern =
      [ for m in Regex.Matches(text, pattern) -> m.Groups[1].Value ]
      |> List.distinct
    let arranged =
      match distinct @"\.(\d+[bhsdq])\b" with
      | [ one ] -> [ for a in arrangements -> text.Replace("." + one, "." + a) ]
      | _ -> []
    let scaled =
      match distinct @"\b([bhsdq])\d+\b" @ distinct @"\.([bhsdq])\[" with
      | one :: rest when List.forall ((=) one) rest ->
        [ for w in widths ->
            text
            |> replaceAll (@"\b" + one + @"(\d+)\b") (w + "$1")
            |> replaceAll (@"\." + one + @"\[") ("." + w + "[") ]
      | _ ->
        []
    arranged @ scaled

  /// The key one shape is kept once for, which is what the arrangements it is
  /// tried at do not depend on.
  static let shapeOf (text: string) =
    text
    |> fun t -> Regex.Replace(t, @"\.\d+[bhsdq]\b", ".T")
    |> fun t -> Regex.Replace(t, @"\b[bhsdq]\d+\b", "V")
    |> fun t -> Regex.Replace(t, @"\.[bhsdq]\[", ".E[")
    |> fun t -> Regex.Replace(t, @"\bv\d+", "v")
    |> fun t -> Regex.Replace(t, @"\b([wx]\d+|wzr|xzr|wsp|sp)\b", "R")
    |> fun t -> Regex.Replace(t, @"#[-\d.xa-f]+", "#i")
    |> fun t -> Regex.Replace(t, @"\[\d+\]", "[i]")
    |> fun t -> Regex.Replace(t, @"\b0x[0-9a-f]+\b", "A")

  /// Describes every source that does not encode to a word meaning the same.
  let brokenSources sources =
    mutingStderr (fun () ->
      sources
      |> List.choose (fun source ->
        match sourceRoundTrip source with
        | ARM64Preserved -> None
        | ARM64Altered actual -> Some $"'{source}' encoded as '{actual}'"
        | ARM64Unsupported -> Some $"'{source}' is not encodable"))
    |> List.sort

  /// Crosses a list of source templates with the opcodes that share them.
  let expand (opcodes: string list) (shapes: string list) =
    [ for shape in shapes do
        for opcode in opcodes -> shape.Replace("OP", opcode) ]

  /// The logical instructions on a shifted register, which share one encoding
  /// path. None of the shapes below reads the zero register where one of these
  /// would be written as a move or a test instead.
  let logicalOpcodes =
    [ "and"; "orr"; "eor"; "bic"; "orn"; "eon"; "ands"; "bics" ]

  let logicalShapes =
    [ "OP w0, w1, w2"
      "OP w0, w1, w2, lsl #0x1"
      "OP w0, w1, w2, lsr #0x1f"
      "OP w0, w1, w2, asr #0x1"
      "OP w0, w1, w2, ror #0x1f"
      "OP x0, x1, x2"
      "OP x0, x1, x2, lsl #0x3f"
      "OP x29, x30, x28, asr #0x2" ]

  /// The additions and subtractions, which read an immediate, a shifted
  /// register or an extended one under one name apiece.
  let addSubOpcodes = [ "add"; "adds"; "sub"; "subs" ]

  let addSubShapes =
    [ "OP w0, w1, #0x1"
      "OP w0, w1, #0xfff"
      "OP w0, w1, #0x1, lsl #0xc"
      "OP x0, x1, #0x20"
      "OP w0, w1, w2"
      "OP w0, w1, w2, lsl #0x1"
      "OP w0, w1, w2, lsr #0x2"
      "OP w0, w1, w2, asr #0x3"
      "OP x0, x1, x2, lsl #0x3f"
      "OP w0, w1, w2, uxtb"
      "OP w0, w1, w2, uxtb #2"
      "OP w0, w1, w2, sxth #3"
      "OP x0, x1, w2, uxtw"
      "OP x0, x1, x2, sxtx #4"
      "OP x0, x1, x2" ]

  /// The bitfield moves and the aliases the manual prefers to write them as,
  /// which say where a field starts and how wide it is rather than where it
  /// ends.
  let bitfieldSources =
    [ "sbfiz w0, w1, #0x1, #0x8"
      "sbfx w0, w1, #0x4, #0x8"
      "ubfiz x0, x1, #0x8, #0x10"
      "ubfx x0, x1, #0x8, #0x10"
      "bfi w0, w1, #0x2, #0x4"
      "bfxil x0, x1, #0x2, #0x4"
      "sxtb w0, w1"
      "sxth x0, w1"
      "sxtw x0, w1"
      "uxtb w0, w1"
      "uxth w0, w1"
      "asr w0, w1, #0x3"
      "asr x0, x1, #0x3f"
      "lsl w0, w1, #0x3"
      "lsl x0, x1, #0x3f"
      "lsr w0, w1, #0x3"
      "lsr x0, x1, #0x3f"
      "ror w0, w1, #3"
      "extr x0, x1, x2, #8" ]

  /// The moves of an immediate, which the manual writes as one of three
  /// instructions depending on what the value is.
  let moveSources =
    [ "mov w0, #0x1"
      "mov w0, #0x10000"
      "mov w0, #0xfffffffe"
      "mov x0, #0x1"
      "mov x0, #0x1000000000000"
      "mov x0, #0xfffffffffffffffe"
      "mov x0, #0x5555555555555555"
      "mov w0, w1"
      "mov x0, x1"
      "mov sp, x1"
      "mov x1, sp"
      "movk w0, #0x1234"
      "movk x0, #0x1234, lsl #0x30"
      "movn w0, #0xffff"
      "movz x0, #0x0, lsl #0x20" ]

  /// The loads and stores of one register, which share one encoding path with
  /// every way of naming a place.
  let loadStoreOpcodes = [ "ldr"; "str" ]

  let loadStoreShapes =
    [ "OP w0, [x1]"
      "OP w0, [x1, #0x4]"
      "OP w0, [x1, #0xffc]"
      "OP w0, [x1, #0x4]!"
      "OP w0, [x1], #0x4"
      "OP w0, [x1], #0x0"
      "OP w0, [x1, x2]"
      "OP w0, [x1, x2, lsl #0x2]"
      "OP w0, [x1, w2, uxtw]"
      "OP w0, [x1, w2, uxtw #2]"
      "OP w0, [x1, w2, sxtw]"
      "OP w0, [x1, x2, sxtx #2]"
      "OP x0, [x1, #0x8]"
      "OP x0, [sp, #0x8]"
      "OP x0, [x1, x2, lsl #0x3]"
      "OP b0, [x1]"
      "OP h0, [x1, #0x2]"
      "OP s0, [x1, #0x4]!"
      "OP d0, [x1], #0x8"
      "OP q0, [x1, #0x10]" ]

  /// The loads and stores whose mnemonic says how wide they are, which reach
  /// the same ways of naming a place with a narrower access.
  let narrowOpcodes = [ "ldrb"; "strb"; "ldrsb" ]

  let narrowShapes =
    [ "OP w0, [x1]"
      "OP w0, [x1, #0x1]"
      "OP w0, [x1, #0x1]!"
      "OP w0, [x1], #0x1"
      "OP w0, [x1, x2]"
      "OP w0, [x1, w2, uxtw]"
      "OP w0, [x1, x2, sxtx]" ]

  /// The transfers of a pair of registers, which name a place three ways.
  let pairOpcodes = [ "ldp"; "stp" ]

  let pairShapes =
    [ "OP w0, w1, [x2]"
      "OP w0, w1, [x2, #0x8]"
      "OP w0, w1, [x2, #0x8]!"
      "OP w0, w1, [x2], #0x8"
      "OP x0, x1, [sp, #0x10]"
      "OP x0, x1, [x2, #0xfffffffffffffff0]"
      "OP d0, d1, [x2, #0x10]"
      "OP q0, q1, [x2, #0x20]" ]

  /// The accesses that move whole vector registers, which name a run of them
  /// and step their base on by as much as they moved.
  let structureOpcodes = [ "ld1"; "st1" ]

  let structureShapes =
    [ "OP { v0.8b }, [x1]"
      "OP { v0.16b }, [x1]"
      "OP { v0.16b, v1.16b }, [x1]"
      "OP { v0.4h, v1.4h, v2.4h }, [x1]"
      "OP { v0.2s - v3.2s }, [x1]"
      "OP { v0.2d }, [x1], x2"
      "OP { v0.16b }, [x1], #0x10"
      "OP { v0.16b - v3.16b }, [sp], #0x40"
      "OP { v0.b }[3], [x1]"
      "OP { v0.h }[1], [x1], x2"
      "OP { v0.s }[2], [x1], #0x4"
      "OP { v0.d }[1], [x1]" ]

  /// The instructions that run under a condition, which name it as an operand
  /// rather than in their own name.
  let conditionalSources =
    [ for cond in [ "eq"
                    "ne"
                    "cs"
                    "cc"
                    "mi"
                    "pl"
                    "vs"
                    "vc"
                    "hi"
                    "ls"
                    "ge"
                    "lt"
                    "gt"
                    "le" ] do
        yield $"csel w0, w1, w2, {cond}"
        yield $"csinc x0, x1, x2, {cond}"
        yield $"csinv w0, w1, w2, {cond}"
        yield $"csneg x0, x1, x2, {cond}"
        yield $"cset w0, {cond}"
        yield $"csetm x0, {cond}"
        yield $"cinv w0, w1, {cond}"
        yield $"cneg x0, x1, {cond}"
        yield $"ccmp w0, w1, #0x3, {cond}"
        yield $"ccmn x0, #0x1f, #0x0, {cond}" ]

  /// The instructions the system space holds, which say what they are in a
  /// field of their own rather than in the fields the others use.
  let systemSources =
    [ "nop"
      "yield"
      "wfe"
      "wfi"
      "sev"
      "sevl"
      "hint #0x7"
      "clrex #0x5"
      "dsb sy"
      "dmb ish"
      "isb sy"
      "svc #0x1"
      "brk #0x0"
      "hlt #0xffff"
      "mrs x0, nzcv"
      "msr nzcv, x0"
      "msr spsel, #0x1"
      "msr daifset, #0x3"
      "sys #0x0, c8, c3, #0x1, x0"
      "sysl x0, #0x3, c7, c4, #0x1"
      "ret"
      "ret x1"
      "br x1"
      "blr x30"
      "eret"
      "drps" ]

  /// The operations on three vectors of one arrangement, which share one
  /// encoding path and differ only in a few bits.
  let vectorOpcodes =
    [ "add"; "sub"; "sqadd"; "uqsub"; "cmtst"; "sshl"; "srshl"; "uqrshl" ]

  let vectorShapes =
    [ "OP v0.8b, v1.8b, v2.8b"
      "OP v0.16b, v1.16b, v2.16b"
      "OP v0.4h, v1.4h, v2.4h"
      "OP v0.8h, v1.8h, v2.8h"
      "OP v0.2s, v1.2s, v2.2s"
      "OP v0.4s, v1.4s, v2.4s"
      "OP v31.2d, v30.2d, v29.2d" ]

  /// The ones that leave the widest arrangement reserved, and so are written
  /// with the narrower ones only.
  let narrowVectorOpcodes =
    [ "smax"; "umin"; "sabd"; "uaba"; "shadd"; "urhadd"; "smaxp"; "uminp" ]

  let narrowVectorShapes =
    [ "OP v0.8b, v1.8b, v2.8b"
      "OP v0.4h, v1.4h, v2.4h"
      "OP v0.4s, v1.4s, v2.4s" ]

  /// The ones on floating-point elements, of which there are three
  /// arrangements.
  let floatVectorOpcodes =
    [ "fadd"; "fsub"; "fmul"; "fdiv"; "fmax"; "fminnm"; "fabd"; "facge" ]

  let floatVectorShapes =
    [ "OP v0.2s, v1.2s, v2.2s"
      "OP v0.4s, v1.4s, v2.4s"
      "OP v0.2d, v1.2d, v2.2d" ]

  /// The ones that read whole registers rather than elements, which name the
  /// only two arrangements a register has as a whole.
  let logicalVectorOpcodes =
    [ "and"; "orr"; "eor"; "bic"; "orn"; "bsl"; "bit"; "bif" ]

  let logicalVectorShapes =
    [ "OP v0.8b, v1.8b, v2.8b"; "OP v0.16b, v1.16b, v2.16b" ]

  /// The ones that read one vector into another of the same arrangement.
  let oneVectorOpcodes =
    [ "abs"; "neg"; "cls"; "clz"; "sqabs"; "sqneg"; "rev64"; "suqadd" ]

  let oneVectorShapes =
    [ "OP v0.8b, v1.8b"
      "OP v0.16b, v1.16b"
      "OP v0.4h, v1.4h"
      "OP v0.4s, v1.4s" ]

  let floatOneVectorOpcodes =
    [ "fabs"; "fneg"; "fsqrt"; "frinta"; "frintz"; "fcvtzs"; "scvtf"; "frecpe" ]

  let floatOneVectorShapes =
    [ "OP v0.2s, v1.2s"; "OP v0.4s, v1.4s"; "OP v0.2d, v1.2d" ]

  /// The ones that write elements twice as wide as the ones they read, of which
  /// the second half reads the top of its source and says so in its name.
  let longVectorOpcodes =
    [ "saddl"; "ssubl"; "uaddl"; "usubl"; "sabal"; "uabdl"; "smlal"; "umull" ]

  let longVectorShapes =
    [ "OP v0.8h, v1.8b, v2.8b"; "OP v0.4s, v1.4h, v2.4h" ]

  let longVectorShapes2 =
    [ "OP2 v0.8h, v1.16b, v2.16b"; "OP2 v0.2d, v1.4s, v2.4s" ]

  /// The ones that shift every element by the same amount.
  let shiftVectorOpcodes =
    [ "sshr"; "ushr"; "srshr"; "ssra"; "usra"; "srsra"; "sri" ]

  let shiftVectorShapes =
    [ "OP v0.8b, v1.8b, #0x3"
      "OP v0.4h, v1.4h, #0x9"
      "OP v0.2d, v1.2d, #0x40" ]

  /// The ones that read one element of their second source, which name it as
  /// well as the register it is in.
  let indexedVectorOpcodes = [ "mul"; "mla"; "mls"; "sqdmulh"; "sqrdmulh" ]

  let indexedVectorShapes =
    [ "OP v0.4h, v1.4h, v2.h[3]"
      "OP v0.8h, v1.8h, v15.h[7]"
      "OP v0.2s, v1.2s, v2.s[1]"
      "OP v0.4s, v1.4s, v31.s[3]" ]

  /// Every other shape the vector space is written in, which no two
  /// instructions share enough of to be worth crossing.
  let otherVectorSources =
    [ "mvn v0.8b, v1.8b"
      "rbit v0.16b, v1.16b"
      "cnt v0.8b, v1.8b"
      "rev16 v0.16b, v1.16b"
      "cmgt v0.8b, v1.8b, #0x0"
      "cmge v0.2d, v1.2d, #0x0"
      "cmeq v0.4h, v1.4h, #0x0"
      "cmle v0.4s, v1.4s, #0x0"
      "cmlt v0.16b, v1.16b, #0x0"
      "fcmgt v0.4s, v1.4s, #0.00000000"
      "fcmge v0.2d, v1.2d, #0.00000000"
      "fcmeq v0.2s, v1.2s, #0.00000000"
      "fcmle v0.4s, v1.4s, #0.00000000"
      "fcmlt v0.2d, v1.2d, #0.00000000"
      "saddlp v0.4h, v1.8b"
      "uaddlp v0.1d, v1.2s"
      "sadalp v0.8h, v1.16b"
      "uadalp v0.2d, v1.4s"
      "xtn v0.8b, v1.8h"
      "sqxtn2 v0.4s, v1.2d"
      "uqxtn v0.2s, v1.2d"
      "sqxtun2 v0.16b, v1.8h"
      "fcvtn v0.4h, v1.4s"
      "fcvtn2 v0.4s, v1.2d"
      "fcvtl v0.2d, v1.2s"
      "fcvtl2 v0.4s, v1.8h"
      "fcvtxn v0.2s, v1.2d"
      "fcvtxn2 v0.4s, v1.2d"
      "shll v0.8h, v1.8b, lsl #0x8"
      "shll2 v0.2d, v1.4s, lsl #0x20"
      "addv b0, v1.8b"
      "smaxv h0, v1.8h"
      "uminv s0, v1.4s"
      "saddlv h0, v1.8b"
      "uaddlv d0, v1.4s"
      "fmaxv s0, v1.4s"
      "fminnmv s0, v1.4s"
      "saddw v0.8h, v1.8h, v2.8b"
      "usubw2 v0.2d, v1.2d, v2.4s"
      "addhn v0.8b, v1.8h, v2.8h"
      "rsubhn2 v0.4s, v1.2d, v2.2d"
      "pmull v0.8h, v1.8b, v2.8b"
      "pmull2 v0.8h, v1.16b, v2.16b"
      "pmul v0.8b, v1.8b, v2.8b"
      "sqdmull v0.4s, v1.4h, v2.4h"
      "shl v0.8b, v1.8b, #0x3"
      "sli v0.4s, v1.4s, #0x1f"
      "sqshl v0.2d, v1.2d, #0x0"
      "sqshlu v0.4h, v1.4h, #0x9"
      "shrn v0.8b, v1.8h, #0x3"
      "rshrn2 v0.4s, v1.2d, #0x20"
      "sqshrun v0.2s, v1.2d, #0x20"
      "uqrshrn2 v0.16b, v1.8h, #0x3"
      "sshll v0.2d, v1.2s, #0x1f"
      "ushll2 v0.8h, v1.16b, #0x3"
      "scvtf v0.2s, v1.2s, #32"
      "fcvtzu v0.2d, v1.2d, #64"
      "fmul v0.2d, v1.2d, v2.d[1]"
      "fmla v0.4s, v1.4s, v31.s[3]"
      "fmulx v0.2s, v1.2s, v2.s[1]"
      "smlal v0.4s, v1.4h, v2.h[3]"
      "umull2 v0.2d, v1.4s, v2.s[1]"
      "sqdmlal v0.2d, v1.2s, v2.s[1]"
      "uzp1 v0.8b, v1.8b, v2.8b"
      "trn2 v0.2d, v1.2d, v2.2d"
      "zip1 v0.4h, v1.4h, v2.4h"
      "ext v0.16b, v1.16b, v2.16b, #0xf"
      "tbl v0.8b, { v1.16b }, v2.8b"
      "tbl v0.16b, { v1.16b, v2.16b }, v3.16b"
      "tbx v0.16b, { v1.16b, v2.16b, v3.16b }, v4.16b"
      "tbx v0.8b, { v1.16b - v4.16b }, v5.8b"
      (* A table wraps round after the last register there is. *)
      "tbl v0.16b, { v29.16b - v0.16b }, v4.16b"
      "dup v0.8b, w1"
      "dup v0.2d, x1"
      "dup v0.4h, v1.h[7]"
      "dup v0.2d, v1.d[1]"
      "smov w0, v1.b[15]"
      "smov x0, v1.s[3]"
      "umov w0, v1.h[7]"
      "mov w0, v1.s[3]"
      "mov x0, v1.d[1]"
      "ins v0.b[15], w1"
      "ins v0.d[1], x1"
      "ins v0.h[7], v1.h[1]"
      "ins v0.s[3], v1.s[2]"
      "mov v0.16b, v1.16b"
      "movi v0.8b, #0x7f"
      "movi v0.4h, #0x12, lsl #0x8"
      "movi v0.4s, #0x12, lsl #0x18"
      "movi v0.2s, #0x12, msl #0x8"
      "mvni v0.4s, #0x12, lsl #0x18"
      "mvni v0.2s, #0x12, msl #0x8"
      "orr v0.4h, #0x12"
      "orr v0.4s, #0x12, lsl #0x10"
      "bic v0.8h, #0x12, lsl #0x8"
      "movi d0, #0xffff0000ffff0000"
      "movi v0.2d, #0xff00ff00ff00ff00"
      "fmov v0.2s, #7.50000000"
      "fmov v0.4s, #-10.50000000"
      "fmov v0.2d, #0.12500000"
      "aese v0.16b, v1.16b"
      "aesd v0.16b, v1.16b"
      "aesmc v0.16b, v1.16b"
      "aesimc v0.16b, v1.16b" ]

  /// The saturating operations on one element, which are the only ones of their
  /// family that reach every width an element has.
  let scalarOpcodes = [ "sqadd"; "uqsub"; "sqrshl" ]

  let scalarShapes =
    [ "OP b0, b1, b2"
      "OP h0, h1, h2"
      "OP s0, s1, s2"
      "OP d0, d1, d2" ]

  /// The operations on two floating-point registers, which share one encoding
  /// path.
  let floatOpcodes =
    [ "fadd"
      "fsub"
      "fmul"
      "fdiv"
      "fmax"
      "fmin"
      "fmaxnm"
      "fminnm"
      "fnmul" ]

  let floatShapes = [ "OP s0, s1, s2"; "OP d0, d1, d2" ]

  /// The operations on one floating-point register.
  let floatOneOpcodes =
    [ "fabs"
      "fneg"
      "fsqrt"
      "frinta"
      "frinti"
      "frintm"
      "frintn"
      "frintp"
      "frintx"
      "frintz"
      "fmov"
      "frecpe"
      "frecpx"
      "frsqrte" ]

  let floatOneShapes = [ "OP s0, s1"; "OP d0, d1" ]

  /// Every other shape the space of one element and of the floating-point
  /// registers is written in.
  let otherFloatSources =
    [ "urshl d0, d1, d2"
      "sshl d0, d1, d2"
      "cmtst d0, d1, d2"
      "cmhi d0, d1, d2"
      "add d0, d1, d2"
      "sub d0, d1, d2"
      "cmge d0, d1, d2"
      "cmhs d0, d1, d2"
      "cmeq d0, d1, d2"
      "srshl d0, d1, d2"
      "fabd s0, s1, s2"
      "facge s0, s1, s2"
      "facgt s0, s1, s2"
      "frecps s0, s1, s2"
      "frsqrts s0, s1, s2"
      "fabd d0, d1, d2"
      "facge d0, d1, d2"
      "facgt d0, d1, d2"
      "frecps d0, d1, d2"
      "frsqrts d0, d1, d2"
      "fmadd s0, s1, s2, s3"
      "fmsub s0, s1, s2, s3"
      "fnmadd s0, s1, s2, s3"
      "fnmsub s0, s1, s2, s3"
      "fmadd d0, d1, d2, d3"
      "fmsub d0, d1, d2, d3"
      "fnmadd d0, d1, d2, d3"
      "fnmsub d0, d1, d2, d3"
      "abs d0, d1"
      "neg d0, d1"
      "sqabs d0, d1"
      "sqneg d0, d1"
      "suqadd d0, d1"
      "usqadd d0, d1"
      "sqabs b0, b1"
      "sqneg b0, b1"
      "suqadd b0, b1"
      "usqadd b0, b1"
      "sqabs h0, h1"
      "sqneg h0, h1"
      "suqadd h0, h1"
      "usqadd h0, h1"
      "sqabs s0, s1"
      "sqneg s0, s1"
      "suqadd s0, s1"
      "usqadd s0, s1"
      "cmgt d0, d1, #0x0"
      "cmge d0, d1, #0x0"
      "cmeq d0, d1, #0x0"
      "cmle d0, d1, #0x0"
      "cmlt d0, d1, #0x0"
      "fcmgt s0, s1, #0.00000000"
      "fcmge s0, s1, #0.00000000"
      "fcmeq s0, s1, #0.00000000"
      "fcmle s0, s1, #0.00000000"
      "fcmlt s0, s1, #0.00000000"
      "fcmgt d0, d1, #0.00000000"
      "fcmge d0, d1, #0.00000000"
      "fcmeq d0, d1, #0.00000000"
      "fcmle d0, d1, #0.00000000"
      "fcmlt d0, d1, #0.00000000"
      "sqxtn b0, h1"
      "sqxtun b0, h1"
      "uqxtn b0, h1"
      "sqxtn h0, s1"
      "sqxtun h0, s1"
      "uqxtn h0, s1"
      "sqxtn s0, d1"
      "sqxtun s0, d1"
      "uqxtn s0, d1"
      "fcvtxn s0, d1"
      "addp d0, v1.2d"
      "faddp s0, v1.2s"
      "fmaxp s0, v1.2s"
      "fminp s0, v1.2s"
      "fmaxnmp s0, v1.2s"
      "fminnmp s0, v1.2s"
      "faddp d0, v1.2d"
      "fmaxp d0, v1.2d"
      "fminp d0, v1.2d"
      "fmaxnmp d0, v1.2d"
      "fminnmp d0, v1.2d"
      "sqdmlal s0, h1, h2"
      "sqdmlsl s0, h1, h2"
      "sqdmull s0, h1, h2"
      "sqdmlal d0, s1, s2"
      "sqdmlsl d0, s1, s2"
      "sqdmull d0, s1, s2"
      "sqdmulh h0, h1, h2"
      "sqrdmulh h0, h1, h2"
      "sqdmulh s0, s1, s2"
      "sqrdmulh s0, s1, s2"
      "sshr d0, d1, #0x3"
      "ssra d0, d1, #0x3"
      "srshr d0, d1, #0x3"
      "srsra d0, d1, #0x3"
      "ushr d0, d1, #0x3"
      "usra d0, d1, #0x3"
      "urshr d0, d1, #0x3"
      "ursra d0, d1, #0x3"
      "sri d0, d1, #0x3"
      "sshr d0, d1, #0x40"
      "ssra d0, d1, #0x40"
      "srshr d0, d1, #0x40"
      "srsra d0, d1, #0x40"
      "ushr d0, d1, #0x40"
      "usra d0, d1, #0x40"
      "urshr d0, d1, #0x40"
      "ursra d0, d1, #0x40"
      "sri d0, d1, #0x40"
      "shl d0, d1, #0x3"
      "sli d0, d1, #0x3"
      "shl d0, d1, #0x0"
      "sli d0, d1, #0x0"
      "sqshl b0, b1, #0x3"
      "uqshl b0, b1, #0x3"
      "sqshlu b0, b1, #0x3"
      "sqshl h0, h1, #0xf"
      "uqshl h0, h1, #0xf"
      "sqshlu h0, h1, #0xf"
      "sqshl s0, s1, #0x1f"
      "uqshl s0, s1, #0x1f"
      "sqshlu s0, s1, #0x1f"
      "sqshl d0, d1, #0x3f"
      "uqshl d0, d1, #0x3f"
      "sqshlu d0, d1, #0x3f"
      "sqshrn b0, h1, #0x3"
      "sqrshrn b0, h1, #0x3"
      "sqshrun b0, h1, #0x3"
      "sqrshrun b0, h1, #0x3"
      "uqshrn b0, h1, #0x3"
      "uqrshrn b0, h1, #0x3"
      "sqshrn h0, s1, #0x9"
      "sqrshrn h0, s1, #0x9"
      "sqshrun h0, s1, #0x9"
      "sqrshrun h0, s1, #0x9"
      "uqshrn h0, s1, #0x9"
      "uqrshrn h0, s1, #0x9"
      "sqshrn s0, d1, #0x20"
      "sqrshrn s0, d1, #0x20"
      "sqshrun s0, d1, #0x20"
      "sqrshrun s0, d1, #0x20"
      "uqshrn s0, d1, #0x20"
      "uqrshrn s0, d1, #0x20"
      "scvtf s0, s1"
      "ucvtf s0, s1"
      "scvtf d0, d1"
      "ucvtf d0, d1"
      "scvtf s0, w1"
      "ucvtf s0, w1"
      "scvtf d0, x1"
      "ucvtf d0, x1"
      "scvtf s0, x1"
      "ucvtf s0, x1"
      "scvtf d0, w1"
      "ucvtf d0, w1"
      "scvtf s0, s1, #3"
      "ucvtf s0, s1, #3"
      "scvtf d0, d1, #64"
      "ucvtf d0, d1, #64"
      "scvtf s0, w1, #3"
      "ucvtf s0, w1, #3"
      "scvtf d0, x1, #64"
      "ucvtf d0, x1, #64"
      "fcvtzs s0, s1"
      "fcvtzu s0, s1"
      "fcvtzs d0, d1"
      "fcvtzu d0, d1"
      "fcvtzs w0, s1"
      "fcvtzu w0, s1"
      "fcvtzs x0, d1"
      "fcvtzu x0, d1"
      "fcvtzs w0, d1"
      "fcvtzu w0, d1"
      "fcvtzs x0, s1"
      "fcvtzu x0, s1"
      "fcvtzs s0, s1, #3"
      "fcvtzu s0, s1, #3"
      "fcvtzs d0, d1, #64"
      "fcvtzu d0, d1, #64"
      "fcvtzs w0, s1, #3"
      "fcvtzu w0, s1, #3"
      "fcvtzs x0, d1, #64"
      "fcvtzu x0, d1, #64"
      "fcvtns s0, s1"
      "fcvtnu s0, s1"
      "fcvtas s0, s1"
      "fcvtau s0, s1"
      "fcvtms s0, s1"
      "fcvtmu s0, s1"
      "fcvtps s0, s1"
      "fcvtpu s0, s1"
      "fcvtns d0, d1"
      "fcvtnu d0, d1"
      "fcvtas d0, d1"
      "fcvtau d0, d1"
      "fcvtms d0, d1"
      "fcvtmu d0, d1"
      "fcvtps d0, d1"
      "fcvtpu d0, d1"
      "fcvtns w0, s1"
      "fcvtnu w0, s1"
      "fcvtas w0, s1"
      "fcvtau w0, s1"
      "fcvtms w0, s1"
      "fcvtmu w0, s1"
      "fcvtps w0, s1"
      "fcvtpu w0, s1"
      "fcvtns x0, d1"
      "fcvtnu x0, d1"
      "fcvtas x0, d1"
      "fcvtau x0, d1"
      "fcvtms x0, d1"
      "fcvtmu x0, d1"
      "fcvtps x0, d1"
      "fcvtpu x0, d1"
      "fcvt d0, s1"
      "fcvt h0, s1"
      "fcvt s0, d1"
      "fcvt h0, d1"
      "fcvt s0, h1"
      "fcvt d0, h1"
      "fmov w0, s1"
      "fmov s0, w1"
      "fmov x0, d1"
      "fmov d0, x1"
      "fmov x0, v1.d[1]"
      "fmov v0.d[1], x1"
      "fmov s0, #7.50000000"
      "fmov d0, #-10.50000000"
      "fcmp s0, s1"
      "fcmp d0, d1"
      "fcmp s0, #0.00000000"
      "fcmp d0, #0.00000000"
      "fcmpe s0, s1"
      "fcmpe d0, #0.00000000"
      "fccmp s0, s1, #0x3, eq"
      "fccmp s0, s1, #0x3, ne"
      "fccmp s0, s1, #0x3, cs"
      "fccmp s0, s1, #0x3, cc"
      "fccmp s0, s1, #0x3, mi"
      "fccmp s0, s1, #0x3, pl"
      "fccmp s0, s1, #0x3, vs"
      "fccmp s0, s1, #0x3, vc"
      "fccmp s0, s1, #0x3, hi"
      "fccmp s0, s1, #0x3, ls"
      "fccmp s0, s1, #0x3, ge"
      "fccmp s0, s1, #0x3, lt"
      "fccmp s0, s1, #0x3, gt"
      "fccmp s0, s1, #0x3, le"
      "fccmp s0, s1, #0x3, nv"
      "fccmpe d0, d1, #0xf, ne"
      "fcsel s0, s1, s2, eq"
      "fcsel d0, d1, d2, le"
      "fmul s0, s1, v2.s[3]"
      "fmulx s0, s1, v2.s[3]"
      "fmla s0, s1, v2.s[3]"
      "fmls s0, s1, v2.s[3]"
      "fmul d0, d1, v2.d[1]"
      "fmulx d0, d1, v2.d[1]"
      "fmla d0, d1, v2.d[1]"
      "fmls d0, d1, v2.d[1]"
      "sqdmulh h0, h1, v2.h[7]"
      "sqrdmulh h0, h1, v2.h[7]"
      "sqdmulh s0, s1, v2.s[3]"
      "sqrdmulh s0, s1, v2.s[3]"
      "sqdmlal s0, h1, v2.h[7]"
      "sqdmlsl s0, h1, v2.h[7]"
      "sqdmull s0, h1, v2.h[7]"
      "sqdmlal d0, s1, v2.s[3]"
      "sqdmlsl d0, s1, v2.s[3]"
      "sqdmull d0, s1, v2.s[3]"
      "mov b0, v1.b[15]"
      "mov h0, v1.h[7]"
      "mov s0, v1.s[3]"
      "mov d0, v1.d[1]"
      "sha1c q0, s1, v2.4s"
      "sha1p q0, s1, v2.4s"
      "sha1m q0, s1, v2.4s"
      "sha256h q0, q1, v2.4s"
      "sha256h2 q0, q1, v2.4s"
      "sha1su0 v0.4s, v1.4s, v2.4s"
      "sha256su1 v0.4s, v1.4s, v2.4s"
      "sha1h s0, s1"
      "sha1su1 v0.4s, v1.4s"
      "sha256su0 v0.4s, v1.4s"
      "sshl d0, d1, d2"
      "srshl d0, d1, d2"
      "urshl d0, d1, d2"
      "cmtst d0, d1, d2"
      "cmhi d0, d1, d2" ]

  /// Padding long enough that the distance to the label is not a small number.
  /// Every A64 branch of the same kind has the same reach, so what this checks
  /// is that a long distance is measured the same way as a short one.
  let padding = String.replicate 200 "  nop\n"

  /// A source that branches to a label, paired with which instruction the
  /// branch is and where the label ends up. Every instruction is four bytes
  /// long, so both follow from counting the instructions in the source.
  let branchCases source =
    [ $"  {source}\n  nop\nL:\n  nop", 0, 0x8UL
      $"L:\n  nop\n  {source}\n  nop", 1, 0x0UL
      $"  {source}\n{padding}L:\n  nop", 0, 0x324UL
      $"L:\n{padding}  {source}\n  nop", 200, 0x0UL ]

  /// Every instruction that names a place, paired with how the disassembler
  /// writes it once it has resolved one.
  let branchSources =
    [ "b L", "b"
      "bl L", "bl"
      "beq L", "beq"
      "bne L", "bne"
      "cbz x0, L", "cbz x0,"
      "cbnz w1, L", "cbnz w1,"
      "tbz w0, #0x3, L", "tbz w0, #0x3,"
      "tbnz x1, #0x21, L", "tbnz x1, #0x21,"
      "adr x0, L", "adr x0,"
      "ldr x0, L", "ldr x0,"
      "ldrsw x0, L", "ldrsw x0,"
      "prfm pldl1keep, L", "prfm pldl1keep," ]

  [<TestMethod>]
  [<TestCategory("Sweep")>]
  member _.``Every instruction the decoder decodes, the assembler encodes``() =
    let broken =
      sweepOutcomes.Force()
      |> List.choose (fun (probe, outcome) ->
        match outcome with
        | ARM64Preserved -> None
        | ARM64Altered actual -> Some $"'{probe.Text}' encoded as '{actual}'"
        | ARM64Unsupported -> Some $"'{probe.Text}' is not encodable")
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
      expand logicalOpcodes logicalShapes
      @ expand addSubOpcodes addSubShapes
      @ bitfieldSources
      @ moveSources
      |> brokenSources
    Assert.AreEqual<string>(
      "",
      String.concat "\n" wrong,
      "These data-processing operand shapes no longer encode correctly.")

  [<TestMethod>]
  member _.``Every load and store shape encodes correctly``() =
    let wrong =
      expand loadStoreOpcodes loadStoreShapes
      @ expand narrowOpcodes narrowShapes
      @ expand pairOpcodes pairShapes
      @ expand structureOpcodes structureShapes
      |> brokenSources
    Assert.AreEqual<string>(
      "",
      String.concat "\n" wrong,
      "These memory operand shapes no longer encode correctly.")

  [<TestMethod>]
  member _.``Every condition and system instruction encodes correctly``() =
    let wrong = conditionalSources @ systemSources |> brokenSources
    Assert.AreEqual<string>(
      "",
      String.concat "\n" wrong,
      "These conditions and system instructions no longer encode correctly.")

  [<TestMethod>]
  member _.``Every vector shape encodes correctly``() =
    let wrong =
      expand vectorOpcodes vectorShapes
      @ expand narrowVectorOpcodes narrowVectorShapes
      @ expand floatVectorOpcodes floatVectorShapes
      @ expand logicalVectorOpcodes logicalVectorShapes
      @ expand oneVectorOpcodes oneVectorShapes
      @ expand floatOneVectorOpcodes floatOneVectorShapes
      @ expand longVectorOpcodes longVectorShapes
      @ expand longVectorOpcodes longVectorShapes2
      @ expand shiftVectorOpcodes shiftVectorShapes
      @ expand indexedVectorOpcodes indexedVectorShapes
      @ otherVectorSources
      |> brokenSources
    Assert.AreEqual<string>(
      "",
      String.concat "\n" wrong,
      "These vector operand shapes no longer encode correctly.")

  [<TestMethod>]
  member _.``Every floating-point shape encodes correctly``() =
    let wrong =
      expand scalarOpcodes scalarShapes
      @ expand floatOpcodes floatShapes
      @ expand floatOneOpcodes floatOneShapes
      @ otherFloatSources
      |> brokenSources
    Assert.AreEqual<string>(
      "",
      String.concat "\n" wrong,
      "These floating-point operand shapes no longer encode correctly.")

  /// <summary>
  /// Checks that an arrangement the manual reserves is refused rather than
  /// encoded.
  ///
  /// Which arrangements a family leaves out differs for almost every member of
  /// it, and one it leaves out names no instruction at all, so a source writing
  /// one has to be refused. The decoder says which those are: every shape the
  /// sweep found is tried at every other arrangement here, and whatever comes
  /// out has to read back as itself.
  /// </summary>
  [<TestMethod>]
  [<TestCategory("Sweep")>]
  member _.``An arrangement no instruction reads does not encode``() =
    let broken =
      mutingStderr (fun () ->
        sweepOutcomes.Force()
        |> List.map (fun (probe, _) -> probe.Text)
        |> List.distinctBy shapeOf
        |> List.collect variants
        |> List.choose (fun variant ->
          match (try encodeFirst variant with _ -> None) with
          | None ->
            None
          | Some encoded ->
            let actual = try disasm encoded with _ -> "<undecodable>"
            if actual = variant || namesTheSame variant actual then None
            else Some $"'{variant}' encoded as '{actual}'"))
      |> List.distinct
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" broken,
      "These operand widths encode to a word that means something else, or to \
       one that is not an instruction at all.")

  [<TestMethod>]
  member _.``Branches to a label reach it in both directions``() =
    let wrong =
      mutingStderr (fun () ->
        [ for written, expected in branchSources do
            for source, index, target in branchCases written ->
              expected, source, index, target ]
        |> List.choose (fun (expected, source, index, target) ->
          match (try assembler.Lower source with _ -> Error "raised") with
          | Error _ | Ok [] ->
            Some $"'{expected} L' does not assemble"
          | Ok encoded ->
            let addr = uint64 (4 * index)
            let text =
              try (parser.Parse(snd (List.item index encoded), addr)).Disasm()
              with _ -> "<undecodable>"
            if text = $"{expected} 0x{target:x}" then None
            else Some $"'{expected} L' at 0x{addr:x} became '{text}'"))
      |> List.distinct
      |> List.sort
    Assert.AreEqual<string>(
      "",
      String.concat "\n" wrong,
      "These branches no longer reach the instruction their label marks.")
