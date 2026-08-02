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
open B2R2.FrontEnd.SPARC

/// Represents one instruction the decoder produced from a probe, paired with
/// the word it came from and the canonical text that gets handed back to the
/// assembler.
type internal SPARCProbe =
  { /// Word the probe was decoded from.
    Word: uint32
    /// Canonical disassembly, which doubles as assembler input.
    Text: string }

/// <summary>
/// Enumerates the SPARC encoding space by handing every combination of the
/// fields that name an instruction to B2R2's own decoder, so that the set of
/// instructions the assembler has to encode is derived from the decoder rather
/// than listed by hand.
///
/// The rule this encodes is that anything the decoder decodes, the assembler
/// encodes. Which instruction a word is comes from the two bits it begins with,
/// the six naming a family below them, the five that name the register it
/// writes to - which a branch spends on its condition instead - the five that
/// name the register it reads from, which the moves on a condition spend the
/// same way, and the bit saying whether a number is written where a second
/// register would be. Those twenty-one bits are walked whole, and the nine that
/// say which floating-point instruction a word is are walked separately because
/// they overlap the ones above. Each register field is then walked over every
/// form that reached, because which register a field names is exactly where a
/// mistake in an encoder hides.
/// </summary>
module internal SPARCSweep =

  /// One word, given the two bits it begins with, the field naming the register
  /// it writes to, the six naming its family, the five naming the register it
  /// reads from, and everything below those.
  let private word op rd op3 rs1 rest =
    (op <<< 30) ||| (rd <<< 25) ||| (op3 <<< 19) ||| (rs1 <<< 14) ||| rest

  /// <summary>
  /// Every word probed for the sake of the forms it reaches.
  ///
  /// The two bits above the second register field are walked because the
  /// instructions naming a set of condition bits keep two of the three that
  /// name it there; everything else below the first register field holds
  /// something distinctive rather than zero, so that an encoder dropping it
  /// shows up as changed text.
  /// </summary>
  let private formWords =
    seq {
      for op in 0u .. 3u do
        for rd in 0u .. 31u do
          for op3 in 0u .. 63u do
            for rs1 in 0u .. 31u do
              for i in 0u .. 1u do
                for cc in 0u .. 3u do
                  yield word op rd op3 rs1 ((i <<< 13) ||| (cc <<< 11) ||| 5u) }

  /// <summary>
  /// Every word probed for the sake of the floating-point forms it reaches.
  ///
  /// Which floating-point instruction a word is comes from the nine bits
  /// between its two register fields, which the pass above holds at nothing
  /// because they overlap the bits it walks. The field naming the register such
  /// a word writes to is walked only as far as the four values a comparison
  /// keeps the set of condition bits it writes in.
  /// </summary>
  let private floatWords =
    seq {
      for op3 in [ 0x34u; 0x35u; 0x36u ] do
        for rd in 0u .. 3u do
          for rs1 in 0u .. 31u do
            for opf in 0u .. 511u do
              yield word 2u rd op3 rs1 ((opf <<< 5) ||| 5u) }

  /// <summary>
  /// Every word probed for the sake of the registers and the numbers it names,
  /// given the forms the pass before this one reached.
  ///
  /// Each of the three register fields is walked whole, and the number written
  /// where a second register would be is tried once below zero as well, because
  /// the disassembler writes such a number as the whole word it was widened to
  /// and a source reads it back from there.
  /// </summary>
  let private registerWords forms =
    seq {
      for form in forms do
        for value in 0u .. 31u do
          yield (form &&& ~~~(0x1Fu <<< 25)) ||| (value <<< 25)
          yield (form &&& ~~~(0x1Fu <<< 14)) ||| (value <<< 14)
          yield (form &&& ~~~0x1Fu) ||| value
        yield (form &&& ~~~0x7FFu) ||| 0x7FBu }

  /// Whether the text is a written number, which is what tells an operand that
  /// names a value from one that names a register.
  let private isNumber (text: string) =
    text.Length > 0 && Char.IsDigit text[0]

  /// Whether a written number is below zero, which the disassembler says by
  /// writing the whole thirty-two bit word the number was widened to.
  let private isNegative (text: string) =
    text.Length = 10 && text.StartsWith "0x" && text[2] >= '8'

  /// The names the disassembler writes the floating-point registers under.
  let private floatRegisters =
    [ for i in int Register.F0 .. int Register.F62 ->
        Register.toString (enum<Register> i) ]
    |> Set.ofList

  /// The names the disassembler writes the general registers under.
  let private intRegisters =
    [ for i in 0 .. 31 -> Register.toString (enum<Register> i) ] |> Set.ofList

  /// What an operand names, keeping which register it was: a number keeps only
  /// whether it is below zero, because its value beyond that is not what an
  /// encoder gets wrong.
  let private shapeOfPart (part: string) =
    if isNumber part then (if isNegative part then "imm-" else "imm+")
    else part

  /// What an operand names and nothing else, which is the coarser of the two
  /// keys: one form is worth reaching once however many registers it is written
  /// with.
  let private kindOfPart (part: string) =
    if isNumber part then "imm"
    elif Set.contains part floatRegisters then "fpr"
    elif Set.contains part intRegisters then "gpr"
    else part

  /// <summary>
  /// The key a probe is kept once for, given how much of an operand it keeps.
  ///
  /// What the disassembler writes after an instruction holding a number says
  /// that number over again in another base, so it is dropped here; what is
  /// left is taken apart at every mark the disassembler puts between the things
  /// an operand holds.
  /// </summary>
  let private keyOf kind (text: string) =
    let text = (text.Split '!')[0]
    let marks = [| ' '; ','; '+'; '['; ']'; '('; ')' |]
    match text.Split ' ' |> Array.toList with
    | [] | [ _ ] -> text.Trim()
    | mnemonic :: rest ->
      let operands = String.concat " " rest
      operands.Split(marks, StringSplitOptions.RemoveEmptyEntries)
      |> Array.map kind
      |> String.concat ","
      |> (+) (mnemonic + " ")

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
    let parser = SPARCParser(BinReader.Init Endian.Big) :> IInstructionParsable
    let walked = Seq.append formWords floatWords
    let shape (probe: SPARCProbe) = keyOf shapeOfPart probe.Text
    let byForm = survey parser (fun probe -> keyOf kindOfPart probe.Text) walked
    let forms = byForm |> List.map (fun probe -> probe.Word)
    byForm @ survey parser shape (registerWords forms) |> List.distinctBy shape

// vim: set tw=80 sts=2 sw=2:
