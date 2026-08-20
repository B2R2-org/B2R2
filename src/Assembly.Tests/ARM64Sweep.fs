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
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.ARM64

/// Represents one instruction the decoder produced from a probe, paired with
/// the canonical text that gets handed back to the assembler.
type internal ARM64Probe =
  { /// Opcode the decoder settled on.
    Opcode: Opcode
    /// Canonical disassembly, which doubles as assembler input.
    Text: string }

/// <summary>
/// Enumerates the A64 encoding space by handing every combination of the fields
/// that name an instruction to B2R2's own decoder, so that the set of
/// instructions the assembler has to encode is derived from the decoder rather
/// than listed by hand.
///
/// The rule this encodes is that anything the decoder decodes, the assembler
/// encodes, and it holds outright: every one of the six encoding groups A64 has
/// is walked here, and every probe round-trips. What the assembler does not
/// reach is what this sweep does not reach either, which is only the words no
/// coordinate below arrives at.
/// </summary>
module internal ARM64Sweep =

  /// The register fields every probe carries where the sweep is not walking one
  /// of them. They are distinctive rather than zero, so that an encoder
  /// dropping one shows up as changed text, and the last four reach what the
  /// others cannot: a branch to a register, a return, a move of an empty
  /// immediate, and the conditional selects that read one register twice.
  let private payloads =
    [ 0x01u, 0x02u, 0x03u
      0x14u, 0x15u, 0x16u
      0x1fu, 0x1fu, 0x1fu
      0x00u, 0x1eu, 0x00u
      0x0au, 0x1fu, 0x09u
      0x03u, 0x08u, 0x0du
      0x1fu, 0x1eu, 0x00u
      0x1fu, 0x1fu, 0x00u
      0x00u, 0x00u, 0x00u
      0x05u, 0x05u, 0x06u ]

  /// One word, given what each of its five fields holds.
  let private word high rm mid rn rd =
    (high <<< 21) ||| (rm <<< 16) ||| (mid <<< 10) ||| (rn <<< 5) ||| rd

  /// <summary>
  /// Whether a word belongs to one of the four groups this sweep covers, which
  /// the four bits below the top byte say.
  /// </summary>
  let private isCovered (word: uint32) =
    let op0 = (word >>> 25) &&& 0b1111u
    op0 &&& 0b1110u = 0b1000u (* data processing, immediate *)
    || op0 &&& 0b1110u = 0b1010u (* branches, exceptions and the system space *)
    || op0 &&& 0b0101u = 0b0100u (* loads and stores *)
    || op0 &&& 0b0111u = 0b0101u (* data processing, register *)
    || op0 &&& 0b0111u = 0b0111u (* data processing, SIMD and floating point *)

  /// Whether a word is one of the ones on SIMD or floating-point registers,
  /// which name their instruction partly in the field above the one the others
  /// use.
  let private isSIMD (high: uint32) = (high >>> 4) &&& 0b0111u = 0b0111u

  /// <summary>
  /// Every word probed.
  ///
  /// The two fields that name an instruction outright are walked whole and
  /// crossed with one another. The three that name a register are walked one at
  /// a time on top of that, because what one of them holds decides which alias
  /// an instruction is written as, and because the lowest of them holds a
  /// condition rather than a register wherever a branch does.
  ///
  /// Two spaces are walked apart from the rest. What an instruction is in the
  /// system space is said by one field of sixteen bits rather than by the
  /// fields above, and sixteen bits is few enough to enumerate. The ones on
  /// SIMD and floating-point registers say what they are partly in the field
  /// the others keep a register in, so that field is crossed with the others
  /// for them; they are one eighth of the space, which leaves the crossing
  /// affordable.
  /// </summary>
  let private words =
    [ for high in 0u .. 2047u do
        for mid in 0u .. 63u do
          for (rm, rn, rd) in payloads do
            yield word high rm mid rn rd
      for high in 0u .. 2047u do
        for value in 0u .. 31u do
          yield word high value 0u 0x02u 0x03u
          yield word high 0x01u 0u value 0x03u
          yield word high 0x01u 0u 0x02u value
      for l in 0u .. 1u do
        for name in 0u .. 65535u do
          for rt in [ 0u; 31u ] do
            yield (0b1101010100u <<< 22) ||| (l <<< 21) ||| (name <<< 5) ||| rt
      for high in 0u .. 2047u do
        for mid in (if isSIMD high then [ 0u .. 63u ] else []) do
          for rm in 0u .. 31u do
            yield word high rm mid 0x02u 0x03u
            yield word high rm mid 0x1fu 0x1fu ]
    |> List.filter isCovered

  /// Reduces one operand to a deduplication key: an immediate keeps that it is
  /// one but not its value, a resolved address keeps only that it is one, and
  /// everything else stands for itself, because which register was named is
  /// exactly where an encoding mistake hides.
  let private operandShape (operand: string) =
    let operand = operand.Trim()
    if operand.StartsWith "#" then "imm"
    elif operand.StartsWith "0x" then "addr"
    else operand

  /// The key probes are deduplicated by, so that one operand shape is
  /// exercised once however many words reach it.
  let private shapeOf (text: string) =
    match text.Split(' ') |> Array.toList with
    | [] ->
      text
    | mnemonic :: rest ->
      let kinds = (String.concat " " rest).Split(',') |> Array.map operandShape
      mnemonic + " " + String.concat "," kinds

  let private decode (parser: IInstructionParsable) (word: uint32) =
    try
      let parsed = parser.Parse(BitConverter.GetBytes word, 0UL)
      let ins = parsed :?> Instruction
      Some(ins.Opcode, parsed.Disasm())
    with _ ->
      None

  /// Probes the whole space this sweep covers, keeping one instruction per
  /// distinct operand shape.
  let probes () =
    let parser =
      ARM64Parser(BinReader.Init Endian.Little) :> IInstructionParsable
    [ for word in words do
        match decode parser word with
        | Some(opcode, text) -> yield { Opcode = opcode; Text = text }
        | None -> () ]
    |> List.distinctBy (fun probe -> shapeOf probe.Text)

// vim: set tw=80 sts=2 sw=2:
