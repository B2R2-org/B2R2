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
open B2R2.FrontEnd.Alpha

/// Represents one instruction the decoder produced from a probe, paired with
/// the word it came from and the canonical text that gets handed back to the
/// assembler.
type internal AlphaProbe =
  { /// Word the probe was decoded from.
    Word: uint32
    /// Canonical disassembly, which doubles as assembler input.
    Text: string }

/// <summary>
/// Enumerates the Alpha encoding space by handing every combination of the
/// fields that name an instruction to B2R2's own decoder, so that the set of
/// instructions the assembler has to encode is derived from the decoder rather
/// than listed by hand.
///
/// The rule this encodes is that anything the decoder decodes, the assembler
/// encodes. Which instruction a word is comes from the six bits it begins with
/// and from a function code below them, and how wide that function code is
/// differs from one kind of instruction to the next: seven bits for the ones
/// computing from registers, eleven for the floating-point ones, and the whole
/// of the sixteen a displacement would sit in for the ones ordering memory and
/// for the branches to a computed address. Each width is walked whole, because
/// they overlap and no one walk reaches all of them. Each register field is
/// then walked over every form that reached, because which register a field
/// names is exactly where a mistake in an encoder hides.
/// </summary>
module internal AlphaSweep =

  /// One word, given the six bits it begins with and everything below them.
  let private word (major: uint32) rest = (major <<< 26) ||| rest

  /// <summary>
  /// Every word probed for the sake of the forms it reaches.
  ///
  /// The field naming the register a word writes to holds something other than
  /// zero wherever the walk leaves it free, so that an encoder dropping it
  /// shows up as changed text.
  /// </summary>
  let private formWords =
    seq {
      (* The instructions computing from registers, which the seven bits below
         the field naming the register they write to name, together with the bit
         saying whether a number stands where a second register would. *)
      for major in 0u .. 63u do
        for func in 0u .. 127u do
          for lit in 0u .. 1u do
            yield word major ((lit <<< 12) ||| (func <<< 5) ||| 0x3u)
      (* The floating-point instructions, which eleven bits name. They overlap
         the seven walked above, so they are walked on their own. *)
      for major in 0x14u .. 0x17u do
        for func in 0u .. 2047u do
          yield word major ((func <<< 5) ||| 0x3u)
      (* The instructions holding a function code where a displacement would
         sit, and the branches to a computed address, which say which of the
         four they are in the two bits at the top of that same field. *)
      for major in [ 0x18u; 0x1Au ] do
        for func in 0u .. 65535u do
          yield word major func
      (* A load whose result is thrown away is a prefetch instead, which a word
         says by naming the register that always reads as zero as the one it
         loads into. *)
      for major in 0u .. 63u do
        yield word major ((31u <<< 21) ||| 0x10u) }

  /// <summary>
  /// Every word probed for the sake of the registers and the numbers it names,
  /// given the forms the pass before this one reached.
  ///
  /// Each of the three register fields is walked whole. The displacement an
  /// instruction reaching memory holds and the distance a branch counts are
  /// both read as signed, and the disassembler writes one below zero as the
  /// whole word it was widened to, so each field is filled with ones once as
  /// well; so is the one holding a number in place of a register, because what
  /// an encoder gets wrong there is the widest value rather than any other.
  /// </summary>
  let private registerWords forms =
    seq {
      for form in forms do
        for value in 0u .. 31u do
          yield (form &&& ~~~(0x1Fu <<< 21)) ||| (value <<< 21)
          yield (form &&& ~~~(0x1Fu <<< 16)) ||| (value <<< 16)
          yield (form &&& ~~~0x1Fu) ||| value
        yield form ||| 0xFFFFu
        yield form ||| 0x1FFFFFu
        yield form ||| (0xFFu <<< 13) }

  /// The bytes of a word, in the order this architecture stores them.
  let private bytesOf (probe: uint32) =
    [| byte probe
       byte (probe >>> 8)
       byte (probe >>> 16)
       byte (probe >>> 24) |]

  /// Whether the text is a written number, which is what tells an operand that
  /// names a value from one that names a register.
  let private isNumber (text: string) = text.Length > 0 && Char.IsDigit text[0]

  /// Whether a written number is below zero, which the disassembler says by
  /// writing the whole thirty-two bit word the number was widened to.
  let private isNegative (text: string) =
    text.Length = 10 && text.StartsWith "0x" && text[2] >= '8'

  /// The names the disassembler writes the floating-point registers under.
  let private floatRegisters =
    [ for i in int Register.F0 .. int Register.F31 ->
        Register.toString (enum<Register> i) ]
    |> Set.ofList

  /// The names the disassembler writes the general registers under.
  let private intRegisters =
    [ for i in int Register.R0 .. int Register.R31 ->
        Register.toString (enum<Register> i) ]
    |> Set.ofList

  /// What an operand names, keeping which register it was: a number keeps only
  /// whether it is below zero, because its value beyond that is not what an
  /// encoder gets wrong.
  let private shapeOfPart (part: string) =
    if isNumber part then (if isNegative part then "imm-" else "imm+") else part

  /// What an operand names and nothing else, which is the coarser of the two
  /// keys: one form is worth reaching once however many registers it is written
  /// with.
  let private kindOfPart (part: string) =
    if isNumber part then "imm"
    elif Set.contains part floatRegisters then "fpr"
    elif Set.contains part intRegisters then "gpr"
    else part

  /// The key a probe is kept once for, given how much of an operand it keeps.
  /// The text is taken apart at every mark the disassembler puts between the
  /// things an operand holds.
  let private keyOf kind (text: string) =
    let marks = [| ' '; ','; '('; ')' |]
    match text.Split ' ' |> Array.toList with
    | [] | [ _ ] ->
      text.Trim()
    | mnemonic :: rest ->
      let operands = String.concat " " rest
      operands.Split(marks, StringSplitOptions.RemoveEmptyEntries)
      |> Array.map kind
      |> String.concat ","
      |> (+) (mnemonic + " ")

  let private decode (parser: IInstructionParsable) (probe: uint32) =
    try
      let parsed = parser.Parse(bytesOf probe, 0UL)
      Some { Word = probe; Text = parsed.Disasm() }
    with _ ->
      None

  /// Probes the given words, keeping one instruction per distinct key. The
  /// words arrive as a sequence rather than a list because there are hundreds
  /// of thousands of them and only the ones kept are worth holding on to.
  let private survey parser key words =
    words |> Seq.choose (decode parser) |> Seq.distinctBy key |> Seq.toList

  /// Probes the whole space this sweep covers, keeping one instruction per
  /// distinct operand shape.
  let probes () =
    let reader = BinReader.Init Endian.Little
    let parser = AlphaParser reader :> IInstructionParsable
    let shape (probe: AlphaProbe) = keyOf shapeOfPart probe.Text
    let byForm =
      survey parser (fun probe -> keyOf kindOfPart probe.Text) formWords
    let forms = byForm |> List.map (fun probe -> probe.Word)
    byForm @ survey parser shape (registerWords forms) |> List.distinctBy shape

// vim: set tw=80 sts=2 sw=2:
