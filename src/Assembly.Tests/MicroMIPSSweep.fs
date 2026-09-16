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

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.MIPS

/// Represents one microMIPS instruction the decoder produced from a probe,
/// paired with the word it came from and the canonical text that gets handed
/// back to the assembler.
type internal MicroMIPSProbe =
  { /// Word the probe was decoded from, which is one halfword in the low half
    /// where the instruction is a short one.
    Word: uint32
    /// How many bytes the instruction the probe decoded to takes.
    Length: uint32
    /// Canonical disassembly, which doubles as assembler input.
    Text: string }

/// <summary>
/// Enumerates the microMIPS encoding space by handing every combination of
/// the fields that name an instruction to B2R2's own decoder, so that the set
/// of instructions the assembler has to encode is derived from the decoder
/// rather than listed by hand.
///
/// The space is walked differently from the older encoding's. Six major
/// opcodes are pools whose sixteen low bits say which instruction a word is,
/// so the whole low half is walked for each of those; the rest name an
/// instruction on their own and take their operands from the two wide fields
/// and a number below them, so those are walked a field at a time.
/// </summary>
module internal MicroMIPSSweep =

  /// What the two wide fields hold where the sweep is not walking one of
  /// them. Zero reaches the instructions written only where a field holds it,
  /// and the other two are distinctive rather than zero so that an encoder
  /// dropping a field shows up as changed text.
  let private backgrounds = [ 0x00u, 0x00u; 0x01u, 0x02u; 0x1fu, 0x1eu ]

  /// The major opcodes whose sixteen low bits say which instruction a word
  /// is: POOL32A, POOL32B, POOL32I, POOL32C, POOL32F and POOL32S.
  let private pools =
    [ 0b000000u; 0b001000u; 0b010000u; 0b011000u; 0b010101u; 0b010110u ]

  /// The low halves a major opcode that is not a pool is probed with: zero,
  /// one, and the three that put a number at either end of its range.
  let private lows = [ 0x0000u; 0x0001u; 0x7fffu; 0x8000u; 0xffffu ]

  /// One word, given what each of its three fields holds.
  let private word (major: uint32) rt rs low =
    (major <<< 26) ||| (rt <<< 21) ||| (rs <<< 16) ||| low

  /// Every word probed for the sake of the pools, which is the whole of each
  /// pool's low half over each background.
  let private poolWords =
    [ for major in pools do
        for (rt, rs) in backgrounds do
          for low in 0u .. 0xffffu do
            yield word major rt rs low ]

  /// Every word probed for the sake of the majors that name an instruction on
  /// their own, which is each wide field walked over a distinctive background.
  let private majorWords =
    [ for major in 0u .. 63u do
        for value in 0u .. 31u do
          for low in lows do
            yield word major value 0x03u low
            yield word major 0x03u value low ]

  /// Every halfword, which is the whole of the short encoding.
  let private shortWords = [ for h in 0u .. 0xffffu -> h ]

  /// Whether the text is a written number, which is what tells an operand
  /// that names a value from one that names a register.
  let private isNumber (text: string) =
    text.Length > 0 && (System.Char.IsDigit text[0] || text[0] = '-')

  /// What an operand names, keeping which register it was: an immediate keeps
  /// only that it is one, because its value is not what an encoder gets
  /// wrong.
  let private shapeOfOperand (operand: string) =
    if isNumber operand then "imm" else operand

  /// The key a probe is kept once for.
  let private keyOf (text: string) =
    let describeOne (operand: string) =
      let operand = operand.Trim()
      match operand.IndexOf '(' with
      | -1 ->
        shapeOfOperand operand
      | i ->
        let inner = operand[i + 1..operand.Length - 2]
        shapeOfOperand operand[..i - 1] + "(" + shapeOfOperand inner + ")"
    match text.Split ' ' |> Array.toList with
    | [] | [ _ ] ->
      text
    | mnemonic :: rest ->
      (String.concat " " rest).Split ','
      |> Array.map describeOne
      |> String.concat ","
      |> (+) (mnemonic + " ")

  /// <summary>
  /// The bytes a word is stored as.
  ///
  /// A four-byte instruction is two halfwords and the one holding the major
  /// opcode is stored first, so a word cannot be written out in the
  /// endianness of the target the way a fixed four-byte encoding can.
  /// </summary>
  let bytesOf (word: uint32) =
    [| byte (word >>> 16); byte (word >>> 24); byte word; byte (word >>> 8) |]

  /// The bytes a HALFWORD is stored as, which is that halfword and then
  /// whatever follows it. A short instruction never reads the second one, and
  /// the parser is handed it only because it settles the length before it
  /// knows it will not need it.
  let private shortBytesOf (half: uint32) =
    [| byte half; byte (half >>> 8); 0uy; 0uy |]

  let private decodeWith (bytes: uint32 -> byte[]) parser (probe: uint32) =
    try
      let parsed = (parser: IInstructionParsable).Parse(bytes probe, 0UL)
      Some { Word = probe; Length = parsed.Length; Text = parsed.Disasm() }
    with _ ->
      None

  let private decode = decodeWith bytesOf

  let private decodeShort = decodeWith shortBytesOf

  /// Probes the whole space this sweep covers, keeping one instruction per
  /// distinct operand shape.
  let probesFor (release: MIPSRelease) =
    let flags = int release ||| int MIPSISAMode.MicroMIPS
    let isa = ISA(Architecture.MIPS, Endian.Little, WordSize.Bit64, flags)
    let parser = MIPSParser(isa, BinReader.Init Endian.Little)
    (* A halfword is a whole instruction only where the major opcode says so,
       and the rest of the space is the first half of a longer one, which this
       walk reaches through the words above rather than here. *)
    let short =
      List.choose (decodeShort (parser :> IInstructionParsable)) shortWords
      |> List.filter (fun probe -> probe.Length = 2u)
    let long =
      List.choose
        (decode (parser :> IInstructionParsable)) (poolWords @ majorWords)
      |> List.filter (fun probe -> probe.Length = 4u)
    short @ long |> List.distinctBy (fun probe -> keyOf probe.Text)

  /// The pre-Release-6 microMIPS encoding space.
  let probes () = probesFor MIPSRelease.PreR6

  /// The Release 6 microMIPS encoding space.
  let probesR6 () = probesFor MIPSRelease.R6

// vim: set tw=80 sts=2 sw=2:
