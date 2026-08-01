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
open B2R2.FrontEnd.MIPS

/// Represents one instruction the decoder produced from a probe, paired with
/// the word it came from and the canonical text that gets handed back to the
/// assembler.
type internal MIPSProbe =
  { /// Word the probe was decoded from, which one sweep stands for at either
    /// word size because only the register names differ between them.
    Word: uint32
    /// Canonical disassembly, which doubles as assembler input.
    Text: string }

/// <summary>
/// Enumerates the MIPS encoding space by handing every combination of the
/// fields that name an instruction to B2R2's own decoder, so that the set of
/// instructions the assembler has to encode is derived from the decoder rather
/// than listed by hand.
///
/// The rule this encodes is that anything the decoder decodes, the assembler
/// encodes, and it holds outright: every field a word divides into is walked
/// here, and every probe round-trips. Twenty million words drawn at random
/// reach no form this sweep does not.
/// </summary>
module internal MIPSSweep =

  /// The fields every probe carries where the sweep is not walking one of
  /// them. Zero reaches the instructions written only where a field holds it,
  /// and the other two are distinctive rather than zero, so that an encoder
  /// dropping a field shows up as changed text; the last of them fills the
  /// half of a word that an instruction taking a written number reads as one,
  /// so that such a number comes out below zero.
  let private backgrounds =
    [ 0x00u, 0x00u, 0x00u, 0x00u
      0x01u, 0x02u, 0x03u, 0x04u
      0x1fu, 0x1eu, 0x1du, 0x1cu ]

  /// <summary>
  /// The six opcodes that name a family of instructions rather than one
  /// instruction. Which member of the family a word is takes more than the
  /// function field at the bottom of it to say, and the rest of what says it
  /// lies in the fields that hold a register everywhere else.
  /// </summary>
  let private families =
    [ 0b000000u (* the instructions on registers *)
      0b000001u (* the branches that compare one register against zero *)
      0b010001u (* the floating-point unit *)
      0b010011u (* what the unit reaches memory and three numbers with *)
      0b011100u (* the multiplies that accumulate *)
      0b011111u (* the instructions on one field of a register *) ]

  /// One word, given what each of its six fields holds.
  let private word op rs rt rd sa func =
    (op <<< 26) ||| (rs <<< 21) ||| (rt <<< 16) ||| (rd <<< 11) ||| (sa <<< 6)
    ||| func

  /// <summary>
  /// Every word probed for the sake of the fields it holds.
  ///
  /// The function field is walked whole for every opcode there is, and each of
  /// the four fields that hold a register is walked on top of that one at a
  /// time, because which register a field names is exactly where a mistake in
  /// an encoder hides and because the lower half of a word is a written number
  /// wherever it is not those fields.
  /// </summary>
  let private fieldWords =
    [ for op in 0u .. 63u do
        for (rs, rt, rd, sa) in backgrounds do
          for func in 0u .. 63u do
            for value in 0u .. 31u do
              yield word op value rt rd sa func
              yield word op rs value rd sa func
              yield word op rs rt value sa func
              yield word op rs rt rd value func ]

  /// <summary>
  /// Every word probed for the sake of the forms it reaches.
  ///
  /// A family may take three fields at once to name one of its members, which
  /// walking one field at a time cannot reach: the move on a condition, for
  /// one, is named by the function field, by the field above the registers and
  /// by two bits of the field beside it together. So the two fields a family
  /// says what it is in are crossed with one another and with the function
  /// field, over the background that holds zero everywhere else.
  /// </summary>
  let private familyWords =
    [ for op in families do
        for rs in 0u .. 31u do
          for rt in 0u .. 31u do
            for func in 0u .. 63u do
              yield word op rs rt 0x03u 0x00u func ]

  /// Whether the text is a written number, which is what tells an operand that
  /// names a value from one that names a register.
  let private isNumber (text: string) =
    text.Length > 0 && (Char.IsDigit text[0] || text[0] = '-')

  /// What an operand names, keeping which register it was: an immediate keeps
  /// only that it is one, because its value is not what an encoder gets wrong.
  let private shapeOfOperand (operand: string) =
    if isNumber operand then "imm" else operand

  /// What an operand names and nothing else, which is the coarser of the two
  /// keys: one form is worth reaching once however many registers it is
  /// written with.
  let private kindOfOperand (operand: string) =
    if isNumber operand then "imm"
    elif operand.Length > 1 && operand[0] = 'f' && isNumber operand[1..] then
      "fpr"
    else "gpr"

  /// The key a probe is kept once for, given how much of an operand it keeps.
  let private keyOf describe (text: string) =
    let describeOne (operand: string) =
      let operand = operand.Trim()
      match operand.IndexOf '(' with
      | -1 -> describe operand
      | i ->
        let inner = operand[i + 1..operand.Length - 2]
        describe operand[..i - 1] + "(" + describe inner + ")"
    match text.Split ' ' |> Array.toList with
    | [] | [ _ ] -> text
    | mnemonic :: rest ->
      (String.concat " " rest).Split ','
      |> Array.map describeOne
      |> String.concat ","
      |> (+) (mnemonic + " ")

  let private decode (parser: IInstructionParsable) (probe: uint32) =
    try
      let parsed = parser.Parse(BitConverter.GetBytes probe, 0UL)
      Some { Word = probe; Text = parsed.Disasm() }
    with _ ->
      None

  /// Probes the whole space this sweep covers, keeping one instruction per
  /// distinct operand shape.
  let probes () =
    let isa = ISA(Architecture.MIPS, Endian.Little, WordSize.Bit32)
    let parser = MIPSParser(isa, BinReader.Init Endian.Little)
    let walk key words =
      List.choose (decode parser) words
      |> List.distinctBy (fun probe -> keyOf key probe.Text)
    walk shapeOfOperand fieldWords @ walk kindOfOperand familyWords
    |> List.distinctBy (fun probe -> keyOf shapeOfOperand probe.Text)

// vim: set tw=80 sts=2 sw=2:
