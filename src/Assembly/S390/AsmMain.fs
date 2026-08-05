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

module internal B2R2.Assembly.S390.AsmMain

open B2R2
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.S390.ParserHelper
open B2R2.Assembly.S390.AsmField
open B2R2.Assembly.S390.AsmOpcode

type UserState =
  { /// Label string to the index of the instruction it marks. The index starts
    /// from zero, and a label does not take one of its own.
    LabelMap: Map<string, int>
    /// Index of the instruction being parsed, which a label does not change.
    CurIndex: int }

/// The four bits a handful of instructions are told from another one written
/// almost the same way by.
let private bits20 = { Pos = 20; Width = 4 }

let private bits16 = { Pos = 16; Width = 8 }

/// What an instruction of the given name encodes as. A name the table does not
/// hold is one the decoder does not read either.
let private rowOf (table: Map<string, Row>) name =
  match Map.tryFind name table with
  | Some row -> row
  | None -> raise <| EncodingFailureException $"{name} is not supported yet"

/// <summary>
/// Where each instruction of a source sits, and after the last of them the
/// place just past it, which is where a label written below everything marks.
///
/// An S390 instruction is two, four, or six bytes long, and which of those it
/// is comes from its name alone, so this can be worked out before anything is
/// encoded.
/// </summary>
let private addresses table baseAddr instrs =
  instrs
  |> List.scan (fun addr ins ->
    addr + uint64 (rowOf table ins.Mnemonic).Length) baseAddr
  |> List.toArray

/// Resolves a label to the address of the instruction it marks. A label that
/// was never defined is a mistake in the source, not a lookup that failed.
let private findLabel state (addrs: Addr[]) lbl =
  match Map.tryFind lbl state.LabelMap with
  | Some index when index < addrs.Length -> addrs[index]
  | Some _ | None ->
    raise <| EncodingFailureException $"Undefined label '{lbl}'"

/// <summary>
/// Rewrites the operand naming a label into how far away that label is, and
/// records where the instruction itself sits.
///
/// What the encoding holds where an instruction names a place is half the
/// distance to it, and what the disassembler writes there is the whole of that
/// distance, so a source writing a number writes the whole of it too; a source
/// writing a label says the same by naming where it wants to end up, and the
/// two are subtracted here.
/// </summary>
let private resolveLabels state addrs pc ins =
  let resolve = function
    | AsmLabel lbl -> AsmImm(findLabel state addrs lbl - pc)
    | operand -> operand
  { ins with Operands = List.map resolve ins.Operands; Address = pc }

/// <summary>
/// Settles the four bits a handful of instructions are told from another one
/// written almost the same way by.
///
/// Where the instruction does not name those bits itself, they are set to one,
/// which is what says which of the two instructions the word is. Where it does
/// name them, a source asking for the other instruction by what it writes there
/// is refused rather than quietly given that other instruction.
/// </summary>
let private settleBits20 row word =
  match row.Bits20 with
  | Bits20Free ->
    word
  | Bits20Filled ->
    place row.Length bits20 1UL word
  | Bits20Named ->
    if peek row.Length bits20 word = 0UL then
      raise <| EncodingFailureException "this instruction needs a mask here"
    else
      word
  | Bits16Named ->
    if peek row.Length bits16 word = 0UL then
      raise <| EncodingFailureException "this instruction needs a mask here"
    else
      word

/// Encodes one instruction, having refused a name the target cannot be given.
let private encodeInstruction table wordSize ins =
  let row = rowOf table ins.Mnemonic
  if wordSize = WordSize.Bit32 && not row.Esa390 then
    raise
    <| EncodingFailureException $"{ins.Mnemonic} is not an ESA/390 instruction"
  else
    row, encode row.Length row.Layout ins.Operands row.Bits |> settleBits20 row

/// The bytes of an encoded instruction, which S390 always stores with the most
/// significant of them first.
let private toBytes length (word: uint64) =
  Array.init length (fun i -> uint8 (word >>> ((length - 1 - i) * 8)))

/// Assembles a whole source.
let assemble (table: Lazy<_>) state wordSize baseAddr instrs =
  let table = table.Value
  let addrs = addresses table baseAddr instrs
  instrs
  |> List.mapi (fun index ins ->
    let row, word =
      resolveLabels state addrs addrs[index] ins
      |> encodeInstruction table wordSize
    toBytes row.Length word)

// vim: set tw=80 sts=2 sw=2:
