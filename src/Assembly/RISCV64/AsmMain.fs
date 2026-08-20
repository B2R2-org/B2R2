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

module internal B2R2.Assembly.RISCV64.AsmMain

open B2R2
open B2R2.FrontEnd.RISCV64
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.RISCV64.ParserHelper
open B2R2.Assembly.RISCV64.AsmOpcode
open B2R2.Assembly.RISCV64.AsmFloat

type UserState =
  { /// Label string to the index of the instruction it marks. The index starts
    /// from zero, and a label does not take one of its own.
    LabelMap: Map<string, int>
    /// Index of the instruction being parsed, which a label does not change.
    CurIndex: int }

/// Builds the lookup from an opcode to the encoder for it. Each assembler
/// builds its own and lets it go when it goes, rather than the rows living for
/// as long as the process does.
let buildEncoderTable () =
  [ arithmeticEncoders ()
    immediateEncoders ()
    loadStoreEncoders ()
    branchEncoders ()
    atomicEncoders ()
    systemEncoders ()
    floatEncoders () ]
  |> List.concat
  |> Map.ofList

/// <summary>
/// How many bytes an instruction takes.
///
/// Every instruction this assembler writes is a word wide but one: the
/// instruction that does nothing, which the full-width instruction set has no
/// name of its own for, so what is written for it is the compressed form that
/// does have one.
/// </summary>
let private lengthOf ins = if ins.Opcode = Op.CdotNOP then 2 else 4

/// Where each instruction of a source sits, and after the last of them the
/// place just past it, which is where a label written below everything marks.
let private addresses baseAddr instrs =
  instrs
  |> List.scan (fun addr ins -> addr + uint64 (lengthOf ins)) baseAddr
  |> List.toArray

/// Resolves a label to the address of the instruction it marks. A label that
/// was never defined is a mistake in the source, not a lookup that failed.
let private findLabel state (addrs: Addr[]) lbl =
  match Map.tryFind lbl state.LabelMap with
  | Some index when index < addrs.Length ->
    addrs[index]
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
let private resolveLabels state addrs pc ins =
  let resolve = function
    | AsmLabel lbl -> AsmImm(findLabel state addrs lbl)
    | operand -> operand
  { ins with Operands = List.map resolve ins.Operands; Address = pc }

let private encodeInstruction (encoders: Map<_, _>) ins =
  match Map.tryFind ins.Opcode encoders with
  | Some encode ->
    encode ins
  | None ->
    raise <| EncodingFailureException $"{ins.Opcode} is not supported yet"

/// The bytes of an encoded instruction, in the order the given endianness
/// stores them and no more of them than the instruction is wide.
let private toBytes endian length (word: uint32) =
  let bytes = System.BitConverter.GetBytes word |> Array.truncate length
  if endian = Endian.Big then Array.rev bytes else bytes

/// <summary>
/// Assembles a whole source.
///
/// How far away a label is can be worked out before anything is encoded,
/// because how wide an instruction is follows from which instruction it is
/// rather than from anything the encoding of it decides.
/// </summary>
let assemble (encoders: Lazy<_>) state endian baseAddr instrs =
  let addrs = addresses baseAddr instrs
  instrs
  |> List.mapi (fun index ins ->
    resolveLabels state addrs addrs[index] ins
    |> encodeInstruction encoders.Value
    |> toBytes endian (lengthOf ins))
