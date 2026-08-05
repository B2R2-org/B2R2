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
open B2R2.FrontEnd.PARISC

/// Represents one instruction the decoder produced from a probe, paired with
/// the word it came from and the canonical text that gets handed back to the
/// assembler.
type internal PARISCProbe =
  { /// Word the probe was decoded from.
    Word: uint32
    /// Canonical disassembly, which doubles as assembler input.
    Text: string }

/// <summary>
/// Enumerates the PA-RISC encoding space by handing words to B2R2's own
/// decoder, so that the set of instructions the assembler has to encode is
/// derived from the decoder rather than listed by hand.
///
/// The rule this encodes is that anything the decoder decodes, the assembler
/// encodes. Almost everything saying which instruction a PA-RISC word is lies
/// in the six bits it begins with and in the sixteen it ends with: the field
/// naming a family, the words hung off the name of an instruction, and the
/// condition it goes on. Those twenty-two bits are therefore walked whole,
/// with the two register fields between them held at something distinctive so
/// that an encoder dropping one shows up as changed text. Each register field
/// is then walked over every form that reached, and each form is tried again
/// with its lower bits stirred, because which register a field names and how
/// wide a number it holds are exactly where a mistake in an encoder hides.
/// </summary>
module internal PARISCSweep =

  /// One word, given the six bits it begins with and everything below them.
  let private word (op: uint32) rest = (op <<< 26) ||| rest

  /// <summary>
  /// Every word probed for the sake of the forms it reaches.
  ///
  /// The two register fields are held at something other than the first
  /// register, except in the pass over the branches that always go, where the
  /// whole of a word says which of them it is and two of them are written by
  /// naming the first register twice.
  /// </summary>
  let private formWords =
    seq {
      for op in 0u .. 63u do
        for low in 0u .. 65535u do
          yield word op ((5u <<< 21) ||| (3u <<< 16) ||| low)
        for high in 0u .. 1023u do
          for low in [ 0u; 0x1234u; 0xFFFFu; 0x8421u ] do
            yield word op ((high <<< 16) ||| low)
      for low in 0u .. 65535u do
        yield word 0b111010u low }

  /// <summary>
  /// Every word probed for the sake of the registers it names, given the forms
  /// the pass before this one reached.
  ///
  /// Five fields of five bits are walked, which is every place a PA-RISC word
  /// names a register: the two above everything else, the two an instruction
  /// doing a multiplication and an addition at once keeps its third and fourth
  /// registers in, and the one at the bottom of the word.
  /// </summary>
  let private registerWords forms =
    seq {
      for form in forms do
        for value in 0u .. 31u do
          for shift in [ 21; 16; 11; 6; 0 ] do
            yield (form &&& ~~~(0x1Fu <<< shift)) ||| (value <<< shift) }

  /// <summary>
  /// Every word probed for the sake of the numbers it holds.
  ///
  /// A number an instruction carries lies somewhere in the twenty-one bits
  /// below the field naming a register, and the passes above hold most of
  /// those still. Each form is therefore tried again with those bits stirred,
  /// so that a number is seen at more than one width and on both sides of
  /// zero.
  /// </summary>
  let private stirred =
    [ 0x1FFFFFu
      0xFFFFu
      0x1FFFu
      0x7FFu
      0x3FFu
      0x1Fu
      0x155555u
      0xAAAAAu
      0x8000u
      0x100u
      0x3u ]

  let private valueWords forms =
    seq {
      for form in forms do
        for mask in stirred do
          yield form ^^^ mask }

  /// The names the disassembler writes the registers under, of every kind:
  /// the general ones, the spaces, the ones the processor keeps for itself and
  /// the floating-point ones.
  let private registers =
    [ for i in 0 .. int Register.FPR31R ->
        Register.toString (enum<Register> i) ]
    |> Set.ofList

  /// Whether the text is a written number, which is what tells an operand that
  /// names a value from one that names a register.
  let private isNumber (text: string) = text.StartsWith "0x"

  /// Whether a written number is below zero, which the disassembler says by
  /// writing the whole doubleword the number was widened to.
  let private isNegative (text: string) =
    text.Length = 18 && text[2] >= '8'

  /// What an operand names, keeping which register it was: a number keeps
  /// whether it is below zero and how wide it is, because a field too narrow
  /// for what it was given is where an encoder goes wrong.
  let private shapeOfPart (part: string) =
    if isNumber part then
      (if isNegative part then "imm-" else "imm+") + string (part.Length - 2)
    else
      part

  /// What an operand names and nothing else, which is the coarser of the two
  /// keys: one form is worth reaching once however many registers it is
  /// written with.
  let private kindOfPart (part: string) =
    if isNumber part then "imm"
    elif Set.contains part registers then "reg"
    else part

  /// <summary>
  /// The name of an instruction with the numbers hung off it left unread.
  ///
  /// Which unit outside the processor an instruction is meant for and what it
  /// is to do are written after its name rather than beside it, and there are
  /// more of those than there is any point in reaching one at a time.
  /// </summary>
  let private nameOf (mnemonic: string) =
    mnemonic.Split ','
    |> Array.map (fun part ->
      if part.Length > 0 && Char.IsDigit part[0] then "#" else part)
    |> String.concat ","

  /// The key a probe is kept once for, given how much of an operand it keeps
  /// and whether the words hung off a name are kept as well. What is left of
  /// the text is taken apart at every mark the disassembler puts between the
  /// things an operand holds.
  let private keyOf whole kind (text: string) =
    let marks = [| ' '; ','; '('; ')' |]
    match text.Split ' ' |> Array.toList with
    | [] ->
      text
    | mnemonic :: rest ->
      let name = nameOf mnemonic
      let name = if whole then name else (name.Split ',')[0]
      (String.concat " " rest).Split(marks,
        StringSplitOptions.RemoveEmptyEntries)
      |> Array.map kind
      |> String.concat ","
      |> (+) (name + " ")

  let private decode (parser: IInstructionParsable) (probe: uint32) =
    try
      let parsed = parser.Parse(BitConverter.GetBytes probe |> Array.rev, 0UL)
      Some { Word = probe; Text = parsed.Disasm() }
    with _ ->
      None

  /// Probes the given words, keeping one instruction per distinct key. The
  /// words arrive as a sequence rather than a list because there are millions
  /// of them and only the ones kept are worth holding on to.
  let private survey parser key words =
    words |> Seq.choose (decode parser) |> Seq.distinctBy key |> Seq.toList

  /// Probes the whole space this sweep covers, keeping one instruction per
  /// distinct operand shape.
  let probes () =
    let isa = ISA(Architecture.PARISC, Endian.Big, WordSize.Bit64)
    let parser = PARISCParser(isa, BinReader.Init Endian.Big)
    let parser = parser :> IInstructionParsable
    let shape (probe: PARISCProbe) = keyOf true shapeOfPart probe.Text
    let byForm = survey parser (fun p -> keyOf true kindOfPart p.Text) formWords
    let forms = byForm |> List.map (fun probe -> probe.Word)
    let byName =
      byForm
      |> List.distinctBy (fun p -> keyOf false kindOfPart p.Text)
      |> List.map (fun probe -> probe.Word)
    byForm
    @ survey parser shape (registerWords byName)
    @ survey parser shape (valueWords forms)
    |> List.distinctBy shape

// vim: set tw=80 sts=2 sw=2:
