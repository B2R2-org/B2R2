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

/// Represents one MIPS16e instruction the decoder produced from a probe,
/// paired with the halfword it came from and the canonical text that gets
/// handed back to the assembler.
type internal MIPS16Probe =
  { /// The halfword the probe was decoded from.
    Word: uint32
    /// How many bytes the instruction the probe decoded to takes.
    Length: uint32
    /// Canonical disassembly, which doubles as assembler input.
    Text: string }

/// <summary>
/// Enumerates the MIPS16e encoding space by handing every halfword to B2R2's
/// own decoder, so that the set of instructions the assembler has to encode is
/// derived from the decoder rather than listed by hand.
///
/// The whole space is sixteen bits, so unlike the other two encodings it is
/// walked exhaustively rather than a field at a time. Each halfword is
/// followed by a NOP: a halfword in the EXTEND range prefixes the one after
/// it, so a run of them laid end to end would have every EXTEND swallow its
/// neighbour and the sweep would skip a value for each.
/// </summary>
module internal MIPS16Sweep =

  /// Whether the text of an operand is a number rather than a register.
  let private isNumber (operand: string) =
    operand.Length > 0
    && (System.Char.IsDigit operand[0] || operand[0] = '-')

  let private shapeOfOperand (operand: string) =
    if isNumber operand then "imm" else operand

  /// <summary>
  /// The key a probe is kept once for.
  ///
  /// Two encodings that differ only in which register or which number they
  /// name are the same instruction as far as an encoder is concerned, so one
  /// of each shape is enough -- and 65536 round trips through a parser
  /// combinator is not.
  /// </summary>
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
      let operands = String.concat " " rest
      let shapes = operands.Split ',' |> Array.map describeOne
      mnemonic + " " + String.concat "," shapes

  /// The halfword at its own slot, with the NOP that follows it.
  let private bytesOf (half: uint32) =
    [| byte half; byte (half >>> 8); 0x00uy; 0x65uy |]

  let private decode (parser: IInstructionParsable) (half: uint32) =
    try
      let parsed = parser.Parse(bytesOf half, 0UL)
      Some { Word = half; Length = parsed.Length; Text = parsed.Disasm() }
    with _ ->
      None

  /// <summary>
  /// Probes the whole space, keeping one instruction per distinct operand
  /// shape.
  ///
  /// The word size is asked for because it is not a detail of the text: the
  /// twenty MIPS64-only instructions decode on one and are refused on the
  /// other, and the registers are called different things.
  /// </summary>
  let probesFor (wordSize: WordSize) =
    let flags = int MIPSISAMode.MIPS16
    let isa = ISA(Architecture.MIPS, Endian.Little, wordSize, flags)
    let parser =
      MIPSParser(isa, BinReader.Init Endian.Little) :> IInstructionParsable
    [ 0u .. 0xFFFFu ]
    |> List.choose (decode parser)
    |> List.distinctBy (fun probe -> keyOf probe.Text)

  /// The MIPS32 half of the encoding space.
  let probes () = probesFor WordSize.Bit32

  /// The same with the doubleword instructions, which only MIPS64 has.
  let probes64 () = probesFor WordSize.Bit64
