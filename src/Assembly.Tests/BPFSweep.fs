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
open B2R2.FrontEnd.BPF

/// Represents the fields one probed eBPF word holds. A probe is kept as fields
/// rather than as bytes so that a later pass can walk one field of a form the
/// pass before it reached while leaving the rest of that form alone.
type internal BPFWord =
  { Code: int
    Dst: int
    Src: int
    Off: int
    Imm: int }

/// <summary>
/// Enumerates the eBPF encoding space by handing every combination of the
/// fields that name an instruction to B2R2's own decoder, so that the set of
/// instructions the assembler has to encode is derived from the decoder rather
/// than listed by hand.
///
/// The rule this encodes is that anything the decoder decodes, the assembler
/// encodes. Which instruction a word is comes from the byte it begins with,
/// together with the halfword where a distance would sit -- that being what
/// tells a signed division from an unsigned one and a widening move from a
/// plain one -- the word where a number would sit, which says how much of a
/// register to reverse and which operation an atomic store performs, and the
/// field naming the second register, which says what the loader is to put where
/// a quadword is carried and what kind of thing a call calls. Each is walked
/// over the values that name something. Each register field is then walked over
/// every form that reached, because which register a field names is exactly
/// where a mistake in an encoder hides.
/// </summary>
module internal BPFSweep =

  /// The values the halfword where a distance would sit takes that name an
  /// instruction rather than merely saying how far away something is.
  let private namingOffsets = [ 0; 1; 8; 16; 32 ]

  /// The values the word where a number would sit takes that name an
  /// instruction: how much of a register to reverse, and which operation an
  /// atomic store performs.
  let private namingNumbers =
    [ 0; 1; 16; 32; 64; 0x40; 0x41; 0x50; 0x51; 0xA0; 0xA1; 0xE1; 0xF1 ]

  /// The values the field naming the register an instruction writes takes that
  /// name an instruction: the jumps, the calls, the return, and the reads of a
  /// packet name no destination at all, and are read as no instruction unless
  /// that field holds zero.
  let private namingDestinations = [ 0; 1 ]

  /// Every word probed for the sake of the forms it reaches.
  let private formWords =
    seq {
      for code in 0 .. 255 do
        for dst in namingDestinations do
          for src in 0 .. 6 do
            for off in namingOffsets do
              for imm in namingNumbers do
                yield { Code = code
                        Dst = dst
                        Src = src
                        Off = off
                        Imm = imm } }

  /// <summary>
  /// Every word probed for the sake of the registers and the numbers it names,
  /// given the forms the pass before this one reached.
  ///
  /// Each register field is walked over every register the machine has. The
  /// halfword a load or a store counts a distance in and the word an
  /// instruction carries a number in are both read as signed, and the
  /// disassembler writes one below zero as the whole word it was widened to, so
  /// each is filled with ones once as well.
  /// </summary>
  let private registerWords forms =
    seq {
      for form in forms do
        for value in 0 .. 10 do
          yield { form with Dst = value }
          yield { form with Src = value }
        yield { form with Off = 0xFFFF }
        yield { form with Imm = -1 } }

  /// <summary>
  /// The bytes of a probed word, in the order this architecture stores them.
  ///
  /// Eight bytes of zeroes follow every probe, so that the one instruction two
  /// words wide finds the word it reads past itself rather than running off the
  /// end of what it was handed.
  /// </summary>
  let private bytesOf w =
    Array.append
      [| byte w.Code
         byte ((w.Src <<< 4) ||| w.Dst)
         byte w.Off
         byte (w.Off >>> 8)
         byte w.Imm
         byte (w.Imm >>> 8)
         byte (w.Imm >>> 16)
         byte (w.Imm >>> 24) |]
      (Array.zeroCreate 8)

  /// Whether the text is a written number, which is what tells an operand that
  /// names a value from one that names a register.
  let private isNumber (text: string) = text.Length > 0 && Char.IsDigit text[0]

  /// Whether a written number is below zero, which the disassembler says by
  /// writing the whole word the number was widened to.
  let private isNegative (text: string) =
    text.Length >= 10 && text.StartsWith "0x" && text[2] >= '8'

  /// The names the disassembler writes the registers under.
  let private registers =
    [ for i in int Register.R0 .. int Register.R10 ->
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
    elif Set.contains part registers then "gpr"
    else part

  /// The key a probe is kept once for, given how much of an operand it keeps.
  /// The text is taken apart at every mark the disassembler puts between the
  /// things an operand holds.
  let private keyOf kind (text: string) =
    let marks = [| ' '; ','; '['; ']'; '+' |]
    match text.Split ' ' |> Array.toList with
    | [] | [ _ ] ->
      text.Trim()
    | mnemonic :: rest ->
      let operands = String.concat " " rest
      operands.Split(marks, StringSplitOptions.RemoveEmptyEntries)
      |> Array.map kind
      |> String.concat ","
      |> (+) (mnemonic + " ")

  let private decode (parser: IInstructionParsable) w =
    try Some(w, (parser.Parse(bytesOf w, 0UL)).Disasm()) with _ -> None

  /// Probes the given words, keeping one instruction per distinct key. The
  /// words arrive as a sequence rather than a list because there are hundreds
  /// of thousands of them and only the ones kept are worth holding on to.
  let private survey parser key words =
    words
    |> Seq.choose (decode parser)
    |> Seq.distinctBy (snd >> key)
    |> Seq.toList

  /// Probes the whole space this sweep covers, keeping one instruction per
  /// distinct operand shape, and returns the canonical text of each.
  let probes () =
    let parser = BPFParser(BinReader.Init Endian.Little) :> IInstructionParsable
    let byForm = survey parser (keyOf kindOfPart) formWords
    let forms = byForm |> List.map fst
    byForm @ survey parser (keyOf shapeOfPart) (registerWords forms)
    |> List.map snd
    |> List.distinctBy (keyOf shapeOfPart)

// vim: set tw=80 sts=2 sw=2:
