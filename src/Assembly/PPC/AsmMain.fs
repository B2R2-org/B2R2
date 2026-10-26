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
open B2R2.Assembly.PPC.AsmVMX
open B2R2.Assembly.PPC.AsmVSX
open B2R2.Assembly.PPC.AsmLegacy
open B2R2.Assembly.PPC.AsmEmbedded
open B2R2.Assembly.PPC.AsmTransaction
open B2R2.Assembly.PPC.AsmSPE
open B2R2.Assembly.PPC.AsmVLE

type UserState =
  { /// Label string to the index of the instruction it marks. The index starts
    /// from zero, and a label does not take one of its own.
    LabelMap: Map<string, int>
    /// Index of the instruction being parsed, which a label does not change.
    CurIndex: int }

/// VLE shares primary opcodes 4 and 31, except for its own opcode 31 rows.
let private sharedVLE encode (ins: AsmInsInfo) =
  let bin = encode ins
  let overridden =
    match (bin >>> 1) &&& 0x3ffu with
    | 14u | 46u | 56u | 568u | 280u | 312u | 16u | 33u | 36u
    | 129u | 193u | 225u | 257u | 289u | 417u | 449u -> true
    | _ -> false
  if bin >>> 26 = 4u || (bin >>> 26 = 31u && not overridden) then
    bin
  else
    AsmField.fail $"{ins.Opcode} is not a shared VLE encoding"

/// <summary>
/// Builds the lookup from an opcode to the encoder for it. Each assembler
/// builds its own and lets it go when it goes, rather than the rows living for
/// as long as the process does.
///
/// How wide the source is decides what a written number below zero looks like,
/// because the disassembler prints such a number as the whole register it lands
/// in; so the rows that read one are built for the width they will be read at.
///
/// The instructions of Variable Length Encoding are rows of the table only
/// where the source is written in it, because they would otherwise be
/// halfwords in a stream of words.
/// </summary>
let buildEncoderTable bitLen vle =
  [ arithmeticEncoders ()
    logicalEncoders ()
    rotateEncoders ()
    comparisonEncoders bitLen
    loadStoreEncoders bitLen
    branchEncoders bitLen
    systemEncoders ()
    laneAEncoders bitLen
    floatEncoders ()
    vectorEncoders ()
    vmxEncoders ()
    vsxEncoders ()
    legacyEncoders ()
    embeddedEncoders ()
    transactionEncoders bitLen
    signalProcessingEncoders () ]
  |> List.concat
  |> fun rows ->
    if vle then
      (rows |> List.map (fun (op, encode) -> op, sharedVLE encode))
      @ vleEncoders bitLen
    else
      rows
  |> Map.ofList

/// Resolves a label to the address of the instruction it marks. A label that
/// was never defined is a mistake in the source, not a lookup that failed.
let private findLabel state (addresses: Addr[]) lbl count =
  match Map.tryFind lbl state.LabelMap with
  | Some index when index <= count ->
    addresses[index]
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
let private resolveLabels state (addresses: Addr[]) count index ins =
  let resolve = function
    | AsmLabel lbl -> AsmImm(findLabel state addresses lbl count)
    | operand -> operand
  { ins with
      Operands = List.map resolve ins.Operands
      Address = addresses[index] }

let private encodeInstruction (encoders: Map<_, _>) ins =
  match Map.tryFind ins.Opcode encoders with
  | Some encode ->
    encode ins
  | None ->
    raise <| EncodingFailureException $"{ins.Opcode} is not supported yet"

/// <summary>
/// The bytes of an encoded instruction, in the order the given endianness
/// stores them. The length is two for an instruction of Variable Length
/// Encoding that fills a halfword and four otherwise.
/// </summary>
let toBytes endian (length: int) (word: uint32) =
  let bytes =
    if length = 2 then System.BitConverter.GetBytes(uint16 word)
    else System.BitConverter.GetBytes word
  if endian = Endian.Big then Array.rev bytes else bytes

/// <summary>
/// Where each instruction of a source sits, and where the end of it is.
///
/// The array holds one address per instruction plus one for the place after
/// the last, which is the address a label written below everything marks. An
/// instruction is four bytes long, or two in Variable Length Encoding where it
/// can be either, so this is a running total rather than a multiplication.
/// </summary>
let private addressesOf sizeOf (baseAddr: Addr) instrs =
  let mutable next = baseAddr
  [| for ins in instrs do
       yield next
       next <- next + uint64 (sizeOf ins: int)
     yield next |]

/// <summary>
/// Assembles a whole source. How long an instruction is follows from what it
/// is rather than from what its operands turned out to be, so where each of
/// them sits is known before anything is encoded and a label can be resolved
/// in one pass.
/// </summary>
let assemble (encoders: Lazy<_>) state endian baseAddr sizeOf instrs =
  let count = List.length instrs
  let addresses = addressesOf sizeOf baseAddr instrs
  instrs
  |> List.mapi (fun index ins ->
    let ins = resolveLabels state addresses count index ins
    if AsmPrefixed.isPrefixed ins.Opcode then
      let struct (prefix, suffix) = AsmPrefixed.encode ins
      Array.append (toBytes endian 4 prefix) (toBytes endian 4 suffix)
    else
      encodeInstruction encoders.Value ins |> toBytes endian (sizeOf ins))
