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
/// the bytes it came from and the canonical text that gets handed back to the
/// assembler.
type internal PPCVLEProbe =
  { /// Bytes the probe was decoded from, as a page of VLE code holds them.
    Bytes: byte[]
    /// Canonical disassembly, which doubles as assembler input.
    Text: string }

/// <summary>
/// Enumerates the encoding space of Variable Length Encoding by handing it to
/// B2R2's own decoder, so that the set of instructions the assembler has to
/// encode is derived from the decoder rather than listed by hand.
///
/// The space has two halves. An instruction of a halfword is walked whole:
/// there are sixty-five thousand of them. An instruction of two takes its
/// primary opcode from the six bits of its first halfword, a register field or
/// the start of an immediate from each of the next three five-bit fields, and
/// the rest from the eleven bits below; those are walked as the base encoding's
/// are, with the field that holds the extended opcode of the scaled-immediate
/// and 16-bit-immediate forms walked whole as well.
/// </summary>
module internal PPCVLESweep =

  /// The three fields every probe carries where the sweep is not walking one
  /// of them: zero, two distinctive values so that an encoder dropping or
  /// exchanging a field shows up as changed text, and the pair that has the
  /// highest bit of the first set so that a signed immediate comes out below
  /// zero.
  let private backgrounds =
    [ 0x00u, 0x00u; 0x01u, 0x02u; 0x1fu, 0x1eu; 0x10u, 0x08u ]

  /// The primary opcodes of the instructions that fill two halfwords and are
  /// not instructions of the base encoding read as they are read there.
  let private longOpcodes =
    [ 6u; 7u; 12u; 13u; 14u; 20u; 21u; 22u; 23u; 28u; 29u; 30u; 31u ]

  /// One word, given the primary opcode, what each of its three five-bit fields
  /// holds, and what fills the eleven bits below them.
  let private word po d a b rest =
    (po <<< 26) ||| (d <<< 21) ||| (a <<< 16) ||| (b <<< 11) ||| rest

  /// Whether the text is a written number, which is what tells an operand that
  /// names a value from one that names a register.
  let private isNumber (text: string) =
    text.Length > 0 && (Char.IsDigit text[0] || text[0] = '-')

  /// What an operand names, keeping which register it was: a number keeps only
  /// that it is one, because its value is not what an encoder gets wrong.
  let private shapeOfPart (part: string) = if isNumber part then "imm" else part

  /// What an operand names and nothing else, which is the coarser of the two
  /// keys: one form is worth reaching once however many registers it is
  /// written with.
  let private kindOfPart (part: string) =
    if isNumber part then "imm"
    elif part.StartsWith "cr" then "cr"
    elif part.StartsWith "r" then "gpr"
    else part

  /// What one operand of a written instruction names. An operand may hold more
  /// than one thing: a distance is written beside the register it is counted
  /// from, and one bit of the condition register is written as which field of
  /// it that bit lies in and which of that field's bits it is.
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

  /// The bytes of a halfword as a page of VLE code holds them.
  let private halfwordBytes (half: uint32) = [| byte (half >>> 8); byte half |]

  /// The bytes of a word as a page of VLE code holds them.
  let private wordBytes (w: uint32) =
    [| byte (w >>> 24); byte (w >>> 16); byte (w >>> 8); byte w |]

  let private decode (parser: IInstructionParsable) (bytes: byte[]) =
    try
      let parsed = parser.Parse(bytes, 0UL)
      Some { Bytes = bytes[..int parsed.Length - 1]
             Text = parsed.Disasm() }
    with _ ->
      None

  /// Every word probed for the sake of the forms it reaches: the whole of
  /// the low eleven bits and of the field above them under each background,
  /// for every primary opcode of two halfwords.
  let private formWords =
    seq { for po in longOpcodes do
            for (d, a) in backgrounds do
              for b in 0u .. 31u do
                for rest in 0u .. 2047u do
                  yield word po d a b rest }

  /// Every word probed for the sake of the registers it names, given a word of
  /// each form the first pass reached.
  let private registerWords forms =
    seq { for w in forms do
            for value in 0u .. 31u do
              yield (w &&& ~~~(0x1fu <<< 21)) ||| (value <<< 21)
              yield (w &&& ~~~(0x1fu <<< 16)) ||| (value <<< 16)
              yield (w &&& ~~~(0x1fu <<< 11)) ||| (value <<< 11) }

  /// Probes the whole space this sweep covers at the given word size, keeping
  /// one instruction per distinct operand shape.
  let probes (wordSize: WordSize) =
    let parser =
      Parser(wordSize, Category.VLE, BinReader.Init Endian.Big)
      :> IInstructionParsable
    let distinct = Seq.distinctBy (fun probe -> keyOf shapeOfPart probe.Text)
    let short =
      seq { 0u .. 0xFFFFu }
      |> Seq.choose (halfwordBytes >> decode parser)
      |> distinct
      |> Seq.toList
    let long =
      formWords
      |> Seq.choose (wordBytes >> decode parser)
      |> distinct
      |> Seq.toList
    let forms =
      long
      |> List.distinctBy (fun probe -> keyOf kindOfPart probe.Text)
      |> List.map (fun probe ->
        Array.fold (fun acc b -> (acc <<< 8) ||| uint32 b) 0u probe.Bytes)
    registerWords forms
    |> Seq.choose (wordBytes >> decode parser)
    |> Seq.append (short @ long)
    |> distinct
    |> Seq.toList

// vim: set tw=80 sts=2 sw=2:
