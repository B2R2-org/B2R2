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
open B2R2.FrontEnd.RISCV64

/// Represents one instruction the decoder produced from a probe, paired with
/// the word it came from and the canonical text that gets handed back to the
/// assembler.
type internal RISCV64Probe =
  { /// Word the probe was decoded from.
    Word: uint32
    /// Canonical disassembly, which doubles as assembler input.
    Text: string }

/// <summary>
/// Enumerates the RISCV64 encoding space by handing every combination of the
/// fields that name an instruction to B2R2's own decoder, so that the set of
/// instructions the assembler has to encode is derived from the decoder rather
/// than listed by hand.
///
/// The rule this encodes is that anything the decoder decodes, the assembler
/// encodes. A word of full width says which instruction it is in the seven bits
/// it ends in, the three above its registers, the seven at its very top, and -
/// in the instructions converting between one kind of number and another - the
/// five that would otherwise name a second register; those twenty-two bits are
/// walked whole, and each of the two register fields left is then walked over
/// every form that reached, because which register a field names is exactly
/// where a mistake in an encoder hides. A word of half width is only sixteen
/// bits wide altogether, so every one of them is simply tried.
/// </summary>
module internal RISCV64Sweep =

  /// One word of full width, given the seven bits it ends in, the three above
  /// its registers, the seven at its top, and what each of its three register
  /// fields holds.
  let private word opcode funct3 funct7 rd rs1 rs2 =
    (funct7 <<< 25) ||| (rs2 <<< 20) ||| (rs1 <<< 15) ||| (funct3 <<< 12)
    ||| (rd <<< 7) ||| opcode

  /// <summary>
  /// Every word probed for the sake of the forms it reaches.
  ///
  /// The two lowest bits of a word of full width are set in every one of them,
  /// which is what tells such a word from the half-width ones, so what is
  /// walked above them is the five bits that are left. The two register fields
  /// this pass does not walk hold something distinctive rather than zero, so
  /// that an encoder dropping one of them shows up as changed text; no
  /// instruction of full width is reached by what either of them holds, so
  /// walking them here would reach nothing walking them later does not.
  /// </summary>
  let private formWords =
    [ for family in 0u .. 31u do
        for funct3 in 0u .. 7u do
          for funct7 in 0u .. 127u do
            for rs2 in 0u .. 31u do
              yield word ((family <<< 2) ||| 3u) funct3 funct7 0x01u 0x02u rs2 ]

  /// Every word probed for the sake of the registers it names, given the forms
  /// the pass before this one reached.
  let private registerWords forms =
    [ for (opcode, funct3, funct7, rs2) in forms do
        for value in 0u .. 31u do
          yield word opcode funct3 funct7 value 0x02u rs2
          yield word opcode funct3 funct7 0x01u value rs2 ]

  /// Every word of half width there is, which is few enough to walk whole.
  let private compressedWords = [ for probe in 0u .. 0xFFFFu -> probe ]

  /// Whether the text is a written number, which is what tells an operand that
  /// names a value from one that names a register.
  let private isNumber (text: string) =
    text.Length > 0 && (Char.IsDigit text[0] || text[0] = '-')

  /// <summary>
  /// Whether a written number is one below zero.
  ///
  /// The disassembler prints a number the encoding reads as signed as the whole
  /// sixty-four bit register it lands in, so one below zero is written out to
  /// its full width whichever base it is written in; a sign is the other way a
  /// source says the same. Which of the two a number is decides how an encoder
  /// has to read it, so the two are worth probing separately.
  /// </summary>
  let private isNegative (text: string) =
    text.StartsWith "-" || text.Length > 10

  /// The names the disassembler writes the floating-point registers under.
  let private floatRegisters =
    [ for i in 0 .. 31 -> Register.toString (enum<Register>(0x20 + i)) ]
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
  /// What one operand of a written instruction names.
  ///
  /// An operand may hold more than one thing: a distance is written beside the
  /// register it is counted from, and whether an atomic instruction holds a
  /// lock across what it does is written glued to the memory it reaches. Both
  /// are read here as the things they hold.
  /// </summary>
  let private describe kind (operand: string) =
    operand.Split([| ' '; '('; ')' |], StringSplitOptions.RemoveEmptyEntries)
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

  /// The four fields of a word of full width that say which instruction it is.
  let private formOf (probe: uint32) =
    probe &&& 0x7Fu, (probe >>> 12) &&& 0x7u, probe >>> 25,
    (probe >>> 20) &&& 0x1Fu

  /// Probes the whole space this sweep covers, keeping one instruction per
  /// distinct operand shape.
  let probes () =
    let isa = ISA(Architecture.RISCV, Endian.Little, WordSize.Bit64)
    let parser =
      RISCV64Parser(isa, BinReader.Init Endian.Little) :> IInstructionParsable
    let byForm = List.choose (decode parser) formWords
    let forms =
      byForm
      |> List.distinctBy (fun probe -> keyOf kindOfPart probe.Text)
      |> List.map (fun probe -> formOf probe.Word)
      |> List.distinct
    byForm
    @ List.choose (decode parser) (registerWords forms)
    @ List.choose (decode parser) compressedWords
    |> List.distinctBy (fun probe -> keyOf shapeOfPart probe.Text)

// vim: set tw=80 sts=2 sw=2:
