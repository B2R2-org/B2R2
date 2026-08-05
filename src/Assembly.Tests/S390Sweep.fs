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
open B2R2.FrontEnd.S390

/// Represents one instruction the decoder produced from a probe, paired with
/// the word it came from and the canonical text that gets handed back to the
/// assembler.
type internal S390Probe =
  { /// The six bytes the probe was decoded from, the instruction first, held as
    /// one number so that a probe of any of the three lengths is one value.
    Word: uint64
    /// Canonical disassembly, which doubles as assembler input.
    Text: string }

/// <summary>
/// Enumerates the S390 encoding space by handing every combination of the bytes
/// that name an instruction to B2R2's own decoder, so that the set of
/// instructions the assembler has to encode is derived from the decoder rather
/// than listed by hand.
///
/// The rule this encodes is that anything the decoder decodes, the assembler
/// encodes. Which instruction a word is comes from bytes at four places, and
/// which of those places matter depends on how long the instruction is, which
/// its first two bits say. A two-byte instruction is named by the whole of
/// itself, so the whole of that space is walked. A four-byte one is named by
/// its first byte, by its first two together, or by its first byte and the
/// second half of its second, so those two bytes are walked whole. A six-byte
/// one is named by its first byte, by its first two, by its first byte and the
/// second half of its second, or by its first byte and its last, so those are
/// walked whole as well. Every four-bit run of every form so reached is then
/// walked over all sixteen of its values, because which register a run of bits
/// names, and how large a number it holds, is exactly where a mistake in an
/// encoder hides.
/// </summary>
module internal S390Sweep =

  /// The six bytes an S390 instruction is at most, most significant first. A
  /// shorter instruction sits in the first of them and the rest read as zero,
  /// which is what the decoder would find after it in a real program.
  let private bytesOf (word: uint64) =
    Array.init 6 (fun i -> uint8 (word >>> ((5 - i) * 8)))

  /// How many bytes long the instruction a word begins with is, which its first
  /// two bits say.
  let private lengthOf (word: uint64) =
    match word >>> 46 with
    | 0UL -> 2
    | 1UL | 2UL -> 4
    | _ -> 6

  /// Every word probed for the sake of the two-byte instructions it reaches,
  /// which is the whole of the space they are named in.
  let private shortWords =
    seq { for bin in 0u .. 0x3FFFu -> uint64 bin <<< 32 }

  /// <summary>
  /// Every word probed for the sake of the four-byte instructions it reaches.
  ///
  /// The two bytes naming such an instruction are walked whole, and what
  /// follows them is tried at nothing as well as at something, because a
  /// handful of these are told from another one written the same way by whether
  /// the bits between the two register fields hold anything.
  /// </summary>
  let private mediumWords =
    seq {
      for first in 0x40u .. 0xBFu do
        for second in 0u .. 0xFFu do
          for rest in [ 0u; 0x1234u ] do
            yield (uint64 first <<< 40)
                  ||| (uint64 second <<< 32)
                  ||| (uint64 rest <<< 16) }

  /// Every word probed for the sake of the six-byte instructions named by the
  /// whole of their first two bytes.
  let private pairWords =
    seq {
      for second in 0u .. 0xFFu ->
        0xE5UL <<< 40 ||| (uint64 second <<< 32) ||| 0x12345678UL }

  /// Every word probed for the sake of the six-byte instructions named by their
  /// first byte, by that byte and the second half of the one after it, or by
  /// that byte and the last one.
  let private longWords =
    seq {
      for first in 0xC0u .. 0xFFu do
        for half in 0u .. 0xFu do
          for last in 0u .. 0xFFu do
            yield (uint64 first <<< 40)
                  ||| (uint64 half <<< 32)
                  ||| 0x12345600UL
                  ||| uint64 last }

  /// Every word probed for the sake of the registers, the masks, and the
  /// numbers an instruction names, given the forms the passes before this one
  /// reached. Each four-bit run of the instruction is walked whole, which
  /// reaches every register a field can name and, because the highest of a
  /// number's bits is walked with the rest, a number below zero as well.
  let private fieldWords forms =
    seq {
      for form in forms do
        for index in 0 .. 2 * lengthOf form - 1 do
          let shift = 44 - 4 * index
          for value in 0UL .. 15UL do
            yield (form &&& ~~~(0xFUL <<< shift)) ||| (value <<< shift) }

  /// Whether the text is a written number, which is what tells an operand that
  /// names a value from one that names a register or a set of bits.
  let private isNumber (text: string) =
    text.Length > 0 && Char.IsDigit text[0]

  /// Whether the text is a set of bits selecting what an instruction does,
  /// which the disassembler writes out one bit at a time between quotes.
  let private isMask (text: string) = text.StartsWith "B'"

  /// What an operand names, keeping which register it was and how many digits a
  /// number was written with, because how large a number is is what tells one
  /// that fits its field from one that does not.
  let private shapeOfPart (part: string) =
    if isNumber part then $"imm{part.Length}" else part

  /// What an operand names and nothing else, which is the coarser of the two
  /// keys: one form is worth reaching once however many registers it is written
  /// with.
  let private kindOfPart (part: string) =
    if isNumber part then "imm"
    elif isMask part then "mask"
    else part.TrimEnd [| '0' .. '9' |]

  /// <summary>
  /// The key a probe is kept once for, given how much of an operand it keeps.
  ///
  /// What the disassembler writes is taken apart at every mark it puts between
  /// the things an operand holds, which leaves the comment saying where a
  /// branch ends up as one more written number; that says the same thing as
  /// the distance beside it, so keeping it costs a handful of probes and no
  /// coverage.
  /// </summary>
  let private keyOf kind (text: string) =
    let marks = [| ' '; ','; '('; ')'; '+'; '-'; ';' |]
    match text.Split ' ' |> Array.toList with
    | [] | [ _ ] ->
      text.Trim()
    | mnemonic :: rest ->
      let operands = String.concat " " rest
      operands.Split(marks, StringSplitOptions.RemoveEmptyEntries)
      |> Array.map kind
      |> String.concat ","
      |> (+) (mnemonic + " ")

  let private decode (parser: IInstructionParsable) (probe: uint64) =
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

  /// The decoder of a target of the given word size, which is what says whether
  /// a word is an instruction at all: a 32-bit target runs ESA/390 and so reads
  /// none of what z/Architecture added.
  let parserFor wordSize =
    let isa = ISA(Architecture.S390, Endian.Big, wordSize)
    S390Parser(isa, BinReader.Init Endian.Big) :> IInstructionParsable

  /// The instructions of the given probes that a target of the given word size
  /// reads. A 32-bit target reads only the part of the instruction set ESA/390
  /// already had, and writes a branch target that has come around within the
  /// first two gigabytes differently, so what it reads is decoded afresh rather
  /// than taken from what a 64-bit target read.
  let readableBy wordSize probes =
    let parser = parserFor wordSize
    probes |> List.choose (fun probe -> decode parser probe.Word)

  /// Probes the whole space this sweep covers, keeping one instruction per
  /// distinct operand shape.
  let probes () =
    let parser = parserFor WordSize.Bit64
    let walked =
      Seq.concat [ shortWords; mediumWords; pairWords; longWords ]
    let shape (probe: S390Probe) = keyOf shapeOfPart probe.Text
    let byForm = survey parser (fun probe -> keyOf kindOfPart probe.Text) walked
    let forms = byForm |> List.map (fun probe -> probe.Word)
    byForm @ survey parser shape (fieldWords forms) |> List.distinctBy shape

// vim: set tw=80 sts=2 sw=2:
