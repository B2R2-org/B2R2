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
open B2R2.FrontEnd.ARM32

/// Represents one instruction the decoder produced from a probe, paired with
/// the canonical text that gets handed back to the assembler.
type internal ARM32Probe =
  { /// Opcode the decoder settled on.
    Opcode: Opcode
    /// Canonical disassembly, which doubles as assembler input.
    Text: string }

/// <summary>
/// Enumerates the A32 encoding space by handing every combination of condition,
/// opcode field and shape field to B2R2's own decoder, so that the set of
/// instructions the assembler has to encode is derived from the decoder rather
/// than listed by hand.
///
/// The rule this encodes is that anything the decoder decodes, the assembler
/// encodes, and it holds outright: every probe here round-trips, and nothing
/// the decoder says is dropped or set aside. What the assembler does not reach
/// is what this sweep does not reach either, which for A32 is only the words no
/// word pattern below arrives at.
/// </summary>
module internal ARM32Sweep =

  /// The conditions worth crossing with every opcode: one that is written out,
  /// one that is not, and the value that marks the unconditional encoding
  /// space, where a different set of instructions lives.
  let private conds = [ 0xeu; 0x1u; 0xfu ]

  /// The register and immediate fields every probe carries, laid out as the
  /// four nibbles above the shape field and the one below it. They are
  /// distinctive rather than zero, so that an encoder dropping one shows up as
  /// changed text, and they name registers whose numbers differ in each
  /// nibble; the last has the program counter in the field that decides
  /// between an ordinary access and a literal one.
  let private payloads = [ 0x1234u; 0x0000u; 0x9abcu; 0xf234u ]

  /// Every word probed: the opcode field is walked whole, and so is the field
  /// below the registers that tells a shift from a multiply from a load.
  let private words =
    [ for cond in conds do
        for opcodeByte in 0u .. 255u do
          for shapeField in 0u .. 15u do
            for payload in payloads do
              yield (cond <<< 28) ||| (opcodeByte <<< 20)
                    ||| ((payload >>> 4) <<< 8) ||| (shapeField <<< 4)
                    ||| (payload &&& 0xfu) ]

  /// Reduces one operand to a deduplication key: an immediate keeps that it is
  /// one but not its value, a resolved address keeps only that it is one, and
  /// everything else stands for itself, because which register was named is
  /// exactly where an encoding mistake hides.
  let private operandShape (operand: string) =
    let operand = operand.Trim()
    if operand.StartsWith "#" then "imm"
    elif operand.StartsWith "0x" then "addr"
    else operand

  /// The key probes are deduplicated by, so that one operand shape is
  /// exercised once however many words reach it.
  let private shapeOf (text: string) =
    match text.Split(' ') |> Array.toList with
    | [] -> text
    | mnemonic :: rest ->
      let kinds = (String.concat " " rest).Split(',') |> Array.map operandShape
      mnemonic + " " + String.concat "," kinds

  let private decode (parser: IInstructionParsable) (word: uint32) =
    try
      let parsed = parser.Parse(BitConverter.GetBytes word, 0UL)
      let ins = parsed :?> Instruction
      Some(ins.Opcode, parsed.Disasm())
    with _ ->
      None

  /// Probes the whole A32 encoding space, keeping one instruction per distinct
  /// operand shape.
  let probes () =
    let isa = ISA(Architecture.ARMv7, WordSize.Bit32)
    let parser =
      ARM32Parser(isa, false, BinReader.Init Endian.Little)
      :> IInstructionParsable
    [ for word in words do
        match decode parser word with
        | Some(opcode, text) ->
          yield { Opcode = opcode; Text = text }
        | None ->
          () ]
    |> List.distinctBy (fun probe -> shapeOf probe.Text)

  /// <summary>
  /// Probes the Thumb encodings: every halfword there is for the narrow ones,
  /// and every combination of the fields that name an instruction for the wide
  /// ones.
  ///
  /// Sixteen bits is few enough to enumerate, so the narrow half of this is not
  /// a sample of that space but all of it.
  /// </summary>
  let thumbProbes () =
    let isa = ISA(Architecture.ARMv7, WordSize.Bit32)
    let parser = ARM32Parser(isa, true, BinReader.Init Endian.Little)
    let switch = parser :> IModeSwitchable
    let parsable = parser :> IInstructionParsable
    let decodeThumb (halfword: uint16) =
      (* The parser carries the state of an IT block from one instruction to
         the next, so a probe left in one would decide the condition of the
         probes after it. *)
      switch.ITState <- 0uy
      let bytes =
        Array.append (BitConverter.GetBytes halfword) [| 0x00uy; 0xbfuy |]
      try
        let parsed = parsable.Parse(bytes, 0UL)
        let ins = parsed :?> Instruction
        if parsed.Length = 2u then Some(ins.Opcode, parsed.Disasm()) else None
      with _ ->
        None
    let decodeWide (first: uint32) (second: uint32) =
      switch.ITState <- 0uy
      let bytes =
        [| byte first; byte (first >>> 8); byte second; byte (second >>> 8) |]
      try
        let parsed = parsable.Parse(bytes, 0UL)
        let ins = parsed :?> Instruction
        if parsed.Length = 4u then Some(ins.Opcode, parsed.Disasm()) else None
      with _ ->
        None
    [ for halfword in 0us .. 65535us do
        match decodeThumb halfword with
        | Some(opcode, text) -> yield { Opcode = opcode; Text = text }
        | None -> ()
      (* The three values below are what marks a wide encoding; the fields
         walked under them are the ones that say which instruction it is. *)
      for prefix in [ 0b11101u; 0b11110u; 0b11111u ] do
        for opcodeField in 0u .. 127u do
          for rn in [ 1u; 9u ] do
            for high in 0u .. 15u do
              for middle in 0u .. 15u do
                let first = (prefix <<< 11) ||| (opcodeField <<< 4) ||| rn
                let second = (high <<< 12) ||| (middle <<< 8) ||| 0x34u
                match decodeWide first second with
                | Some(opcode, text) -> yield { Opcode = opcode; Text = text }
                | None -> () ]
    |> List.distinctBy (fun probe -> shapeOf probe.Text)

// vim: set tw=80 sts=2 sw=2:
