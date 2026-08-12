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
open B2R2.FrontEnd.Intel
open type Opcode

/// Identifies which opcode map a probe reaches into.
type internal OpcodeMap =
  | OneByte
  | TwoByte
  | ThreeByte38
  | ThreeByte3A

/// Represents one instruction the decoder produced from a probe, paired with
/// the canonical text that gets handed back to the assembler.
type internal Probe =
  { /// Opcode the decoder settled on.
    Opcode: Opcode
    /// Canonical disassembly, which doubles as assembler input.
    Text: string }

/// <summary>
/// Enumerates the Intel encoding space by handing every prefix, escape and
/// opcode byte combination to B2R2's own decoder, so that the set of
/// instructions the assembler has to encode is derived from the decoder rather
/// than listed by hand.
///
/// The rule this encodes is that anything the decoder decodes, the assembler
/// encodes. A form the manual leaves reserved never reaches the assembler,
/// because the decode tables carry the manual's own ModRM constraint and the
/// decoder refuses it; nothing here has to list those coordinates by hand. What
/// the two filters below drop is text no assembly syntax accepts, and a space
/// this sweep does not claim to cover. Each says which of the two it is.
/// </summary>
module internal IntelSweep =

  /// Bytes appended to every probe so that an instruction reading a
  /// displacement or an immediate still decodes. They are distinctive rather
  /// than zero, so that an encoder losing one shows up as changed text.
  let private padding = [| 0x11uy .. 0x11uy .. 0xeeuy |]

  let private escapeOf = function
    | OneByte -> [||]
    | TwoByte -> [| 0x0fuy |]
    | ThreeByte38 -> [| 0x0fuy; 0x38uy |]
    | ThreeByte3A -> [| 0x0fuy; 0x3auy |]

  /// The prefixes worth crossing with each opcode map. F2 and F3 are mandatory
  /// prefixes naming a distinct instruction only in the 0F maps; on a one-byte
  /// opcode they are a REP prefix, which means something on the string
  /// instructions alone, and IntelEncodingTests covers those by hand.
  let private prefixesOf = function
    | OneByte | ThreeByte3A ->
      [ [||]
        [| 0x66uy |] ]
    | TwoByte | ThreeByte38 ->
      [ [||]
        [| 0x66uy |]
        [| 0xf2uy |]
        [| 0xf3uy |] ]

  /// One ModRM byte per reg digit, in both the register-direct and the
  /// memory-operand form, so that opcodes told apart by that digit are reached.
  let private modRMs =
    [ for reg in 0 .. 7 do
        byte (0xc1 + reg * 8)
        byte (0x01 + reg * 8) ]

  let private rexesOf wordSize =
    if wordSize = WordSize.Bit64 then [ [||]; [| 0x48uy |] ] else [ [||] ]

  let private prefixMnemonics = [ "rep "; "repz "; "repnz "; "lock " ]

  /// A resolved branch target is rendered as a trailing comment, which no
  /// assembly syntax accepts, so relative branches cannot be round-tripped
  /// through text at all; the label-driven tests cover them instead. A REP or
  /// LOCK prefix on an instruction that does not take one is a decoder
  /// courtesy rather than an encoding worth supporting.
  let private isAssemblable (text: string) =
    not (text.Contains ";")
    && not (prefixMnemonics |> List.exists text.StartsWith)

  /// Reduces one operand to a deduplication key: a memory operand keeps its
  /// width but drops the address expression, an immediate keeps its width but
  /// drops the value, and a register stands for itself, because which register
  /// was named is exactly where encoding mistakes hide.
  let private operandShape (operand: string) =
    let operand = operand.Trim()
    if operand.Contains "ptr" then
      "m:" + operand.Substring(0, operand.IndexOf "ptr").Trim()
    elif operand.StartsWith "0x" then
      $"i{operand.Length - 2}"
    else
      operand

  /// The key probes are deduplicated by, so that one operand shape is
  /// exercised once however many byte patterns reach it.
  let private shapeOf (text: string) =
    match text.Split(' ') |> Array.toList with
    | [] ->
      text
    | mnemonic :: rest ->
      let kinds = (String.concat " " rest).Split(',') |> Array.map operandShape
      mnemonic + " " + String.concat "," kinds

  /// C4 and C5 are the three- and two-byte VEX prefixes as well as LES and LDS,
  /// so a probe there can decode an AVX instruction whose opcode comes out of
  /// the padding rather than out of the probe. The VEX and EVEX spaces want a
  /// sweep of their own; this one covers the legacy maps, so anything that
  /// arrived through a VEX prefix is out of scope.
  let private isVexEncoded (ins: Instruction) = ins.VEXInfo |> Option.isSome

  /// Every byte pattern probed for one opcode map under one word size.
  let private patterns map wordSize =
    [ for prefix in prefixesOf map do
        for rex in rexesOf wordSize do
          let head = Array.concat [ prefix; rex; escapeOf map ]
          for opcodeByte in 0 .. 255 do
            for modRM in modRMs do
              yield Array.append head [| byte opcodeByte; modRM |] ]

  let private decode (parser: IInstructionParsable) (bytes: byte[]) =
    try
      let parsed = parser.Parse(Array.append bytes padding, 0UL)
      let ins = parsed :?> Instruction
      if int parsed.Length > bytes.Length + padding.Length
         || isVexEncoded ins then
        None
      else
        Some(ins.Opcode, (parsed.Disasm()).ToLowerInvariant())
    with _ ->
      None

  /// Probes the whole encoding space under the given word size, keeping one
  /// instruction per distinct operand shape.
  let probes wordSize =
    let parser =
      IntelParser(wordSize, BinReader.Init Endian.Little)
      :> IInstructionParsable
    [ for map in [ OneByte; TwoByte; ThreeByte38; ThreeByte3A ] do
        for bytes in patterns map wordSize do
          match decode parser bytes with
          | Some(opcode, text) when isAssemblable text ->
            yield { Opcode = opcode; Text = text }
          | Some _ | None ->
            () ]
    |> List.distinctBy (fun probe -> shapeOf probe.Text)

// vim: set tw=80 sts=2 sw=2:
