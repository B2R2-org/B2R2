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
open B2R2.FrontEnd.PPC

/// Represents one instruction the decoder produced from a probe, paired with
/// the word it came from and the canonical text that gets handed back to the
/// assembler.
type internal PPCProbe =
  { /// Word the probe was decoded from.
    Word: uint32
    /// Canonical disassembly, which doubles as assembler input.
    Text: string }

/// <summary>
/// Enumerates the PPC encoding space by handing every combination of the fields
/// that name an instruction to B2R2's own decoder, so that the set of
/// instructions the assembler has to encode is derived from the decoder rather
/// than listed by hand.
///
/// The rule this encodes is that anything the decoder decodes, the assembler
/// encodes. The eleven bits below the registers are what says which instruction
/// a word is, whichever form it takes, and they are walked whole for every
/// primary opcode there is; each of the three fields above them is then walked
/// over every form that reached, because which register a field names is
/// exactly where a mistake in an encoder hides.
/// </summary>
module internal PPCSweep =

  /// <summary>
  /// The three register fields every probe carries where the sweep is not
  /// walking one of them.
  ///
  /// Zero reaches the instructions written only where a field holds it, and the
  /// next two are distinctive rather than zero, so that an encoder dropping a
  /// field shows up as changed text; the last of those fills the half of a word
  /// that an instruction taking a written number reads as one, so that such a
  /// number comes out below zero. The fourth names a register the encoding
  /// knows only by a number, which is the one thing none of the others does and
  /// without which the forms reading such a register are never reached at all.
  /// </summary>
  let private backgrounds =
    [ 0x00u, 0x00u, 0x00u
      0x01u, 0x02u, 0x03u
      0x1fu, 0x1eu, 0x1du
      0x02u, 0x08u, 0x00u ]

  /// One word, given the primary opcode, what each of its three register fields
  /// holds, and what fills the eleven bits below them.
  let private word po d a b rest =
    (po <<< 26) ||| (d <<< 21) ||| (a <<< 16) ||| (b <<< 11) ||| rest

  /// Every word probed for the sake of the forms it reaches.
  let private formWords =
    [ for po in 0u .. 63u do
        for (d, a, b) in backgrounds do
          for rest in 0u .. 2047u do
            yield word po d a b rest ]

  /// Every word probed for the sake of the registers it names, given the forms
  /// the first pass reached.
  let private registerWords forms =
    [ for (po, rest) in forms do
        for value in 0u .. 31u do
          yield word po value 0x02u 0x03u rest
          yield word po 0x01u value 0x03u rest
          yield word po 0x01u 0x02u value rest ]

  /// <summary>
  /// The four primary opcodes in which more than one field above the low eleven
  /// bits says which instruction a word is.
  ///
  /// A conditional branch says what it does to the counter in one field and
  /// which bit it tests in the next; the branches to a register and the logic
  /// on the condition register say the same in the same two. An instruction
  /// naming a register the encoding knows only by a number keeps that number's
  /// two halves in the two fields the arithmetic keeps registers in, and one
  /// naming a field of the condition register or of the floating-point unit's
  /// status register says which by a mask lying across both.
  /// </summary>
  let private families = Set.ofList [ 16u; 19u; 31u; 63u ]

  /// Every word probed for the sake of the forms those four reach, which
  /// walking one field at a time cannot: the fields are crossed with one
  /// another rather than walked singly.
  let private familyWords forms =
    [ for (po, rest) in List.filter (fst >> families.Contains) forms do
        for value in 0u .. 31u do
          for other in 0u .. 31u do
            yield word po value other 0u rest
            yield word po 0u value other rest ]

  /// Whether the text is a written number, which is what tells an operand that
  /// names a value from one that names a register.
  let private isNumber (text: string) =
    text.Length > 0 && (Char.IsDigit text[0] || text[0] = '-')

  /// What an operand names, keeping which register it was: a number keeps only
  /// that it is one, because its value is not what an encoder gets wrong.
  let private shapeOfPart (part: string) =
    if isNumber part then "imm" else part

  /// What an operand names and nothing else, which is the coarser of the two
  /// keys: one form is worth reaching once however many registers it is
  /// written with.
  let private kindOfPart (part: string) =
    if isNumber part then "imm"
    elif part.StartsWith "cr" then "cr"
    elif part.StartsWith "f" then "fpr"
    elif part.StartsWith "v" then "vr"
    elif part.StartsWith "r" then "gpr"
    else part

  /// <summary>
  /// What one operand of a written instruction names.
  ///
  /// An operand may hold more than one thing: a distance is written beside the
  /// register it is counted from, and one bit of the condition register is
  /// written as which field of it that bit lies in and which of that field's
  /// bits it is. Both are read here as the things they hold.
  /// </summary>
  let private describe kind (operand: string) =
    operand.Split([| ' '; '('; ')'; '*'; '+' |],
                  StringSplitOptions.RemoveEmptyEntries)
    |> Array.map kind
    |> String.concat " "

  /// The key a probe is kept once for, given how much of an operand it keeps.
  let private keyOf kind (text: string) =
    match text.Split ' ' |> Array.toList with
    | [] | [ _ ] ->
      text
    | mnemonic :: rest ->
      (String.concat " " rest).Split ','
      |> Array.map (describe kind)
      |> String.concat ","
      |> (+) (mnemonic + " ")

  let private decode (parser: IInstructionParsable) (probe: uint32) =
    try
      let parsed = parser.Parse(BitConverter.GetBytes probe, 0UL)
      Some { Word = probe; Text = parsed.Disasm() }
    with _ ->
      None

  /// The primary opcode and the eleven bits below the registers of a word,
  /// which is what says which instruction it is.
  let private formOf (probe: uint32) = probe >>> 26, probe &&& 0x7FFu

  /// Probes the whole space this sweep covers at the given word size, keeping
  /// one instruction per distinct operand shape.
  let probes wordSize =
    let parser =
      PPCParser(wordSize, BinReader.Init Endian.Little)
      :> IInstructionParsable
    let byForm = List.choose (decode parser) formWords
    let forms =
      byForm
      |> List.distinctBy (fun probe -> keyOf kindOfPart probe.Text)
      |> List.map (fun probe -> formOf probe.Word)
      |> List.distinct
    byForm
    @ List.choose (decode parser) (registerWords forms)
    @ List.choose (decode parser) (familyWords forms)
    |> List.distinctBy (fun probe -> keyOf shapeOfPart probe.Text)

// vim: set tw=80 sts=2 sw=2:
