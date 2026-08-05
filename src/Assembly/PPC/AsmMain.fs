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

module internal B2R2.Assembly.PPC.AsmMain

open B2R2
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.PPC.ParserHelper
open B2R2.Assembly.PPC.AsmOpcode
open B2R2.Assembly.PPC.AsmFloat
open B2R2.Assembly.PPC.AsmVector

type UserState =
  { /// Label string to the index of the instruction it marks. The index starts
    /// from zero, and a label does not take one of its own.
    LabelMap: Map<string, int>
    /// Index of the instruction being parsed, which a label does not change.
    CurIndex: int }

/// <summary>
/// Builds the lookup from an opcode to the encoder for it. Each assembler
/// builds its own and lets it go when it goes, rather than the rows living for
/// as long as the process does.
///
/// How wide the source is decides what a written number below zero looks like,
/// because the disassembler prints such a number as the whole register it lands
/// in; so the rows that read one are built for the width they will be read at.
/// </summary>
let buildEncoderTable bitLen =
  [ arithmeticEncoders ()
    logicalEncoders ()
    rotateEncoders ()
    comparisonEncoders bitLen
    loadStoreEncoders bitLen
    branchEncoders bitLen
    systemEncoders ()
    floatEncoders ()
    vectorEncoders () ]
  |> List.concat
  |> Map.ofList

/// Resolves a label to the address of the instruction it marks. A label that
/// was never defined is a mistake in the source, not a lookup that failed.
let private findLabel state (baseAddr: Addr) lbl count =
  match Map.tryFind lbl state.LabelMap with
  | Some index when index <= count ->
    baseAddr + uint64 (index * 4)
  | Some _ | None ->
    raise <| EncodingFailureException $"Undefined label '{lbl}'"

/// <summary>
/// Rewrites the operand naming a label into the address that label sits at, and
/// records where the instruction itself sits.
///
/// What the encoding holds where a branch names a place is how far away that
/// place is, and what the disassembler prints there is the address it worked
/// out; so a source writes an address either way, and the two are subtracted
/// where the branch is encoded rather than here.
/// </summary>
let private resolveLabels state baseAddr count pc ins =
  let resolve = function
    | AsmLabel lbl -> AsmImm(findLabel state baseAddr lbl count)
    | operand -> operand
  { ins with Operands = List.map resolve ins.Operands; Address = pc }

let private encodeInstruction (encoders: Map<_, _>) ins =
  match Map.tryFind ins.Opcode encoders with
  | Some encode ->
    encode ins
  | None ->
    raise <| EncodingFailureException $"{ins.Opcode} is not supported yet"

/// The bytes of an encoded instruction, in the order the given endianness
/// stores them.
let private toBytes endian (word: uint32) =
  let bytes = System.BitConverter.GetBytes word
  if endian = Endian.Big then Array.rev bytes else bytes

/// <summary>
/// Assembles a whole source. Every PPC instruction is one word long, so where
/// each of them sits follows from counting the ones before it, and how far away
/// a label is can be worked out before anything is encoded.
/// </summary>
let assemble (encoders: Lazy<_>) state endian baseAddr instrs =
  let count = List.length instrs
  instrs
  |> List.mapi (fun index ins ->
    resolveLabels state baseAddr count (baseAddr + uint64 (index * 4)) ins
    |> encodeInstruction encoders.Value
    |> toBytes endian)
