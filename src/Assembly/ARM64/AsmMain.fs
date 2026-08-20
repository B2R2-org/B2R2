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

module internal B2R2.Assembly.ARM64.AsmMain

open B2R2
open B2R2.FrontEnd.ARM64
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.ARM64.ParserHelper
open B2R2.Assembly.ARM64.AsmOpcode
open B2R2.Assembly.ARM64.AsmSIMD
open B2R2.Assembly.ARM64.AsmFloat

type UserState =
  { /// Label string to the index of the instruction it marks. The index starts
    /// from zero, and a label does not take one of its own.
    LabelMap: Map<string, int>
    /// Index of the instruction being parsed, which a label does not change.
    CurIndex: int }

/// <summary>
/// Whether the instruction writes a whole vector, which is what tells one of
/// the instructions on whole vectors from the ones sharing its name elsewhere.
///
/// What an instruction writes says which space it belongs to, because a name
/// shared between two spaces is written with the registers of the space it
/// belongs to, and the first of those is the one it writes.
/// </summary>
let private writesVector ins =
  match getOperandsAsList ins.Operands with
  | OprSIMD(VecReg _) :: _ | OprSIMD(VecRegWithIdx _) :: _
  | OprSIMDList _ :: _ -> true
  | _ -> false

/// Whether the instruction names a SIMD register anywhere, which is what tells
/// the ones that read one into a general register from the ones that name no
/// SIMD register at all.
let private namesSIMD ins =
  getOperandsAsList ins.Operands
  |> List.exists (function
    | OprSIMD _ | OprSIMDList _ -> true
    | _ -> false)

/// <summary>
/// Adds a table of encoders to another, keeping what was already there for the
/// instructions the new rows do not claim.
///
/// A good many names belong to more than one of the spaces, and nothing but the
/// operands says which space an instruction written under one of them is in, so
/// where a name is in two the two encoders are put behind one that reads that.
/// </summary>
let private addEncoders claims table rows =
  rows
  |> List.fold (fun table (opcode, encode) ->
    match Map.tryFind opcode table with
    | Some other ->
      let choose ins = if claims ins then encode ins else other ins
      Map.add opcode choose table
    | None ->
      Map.add opcode encode table) table

/// Builds the lookup from an opcode to the encoder for it. Each assembler
/// builds its own and lets it go when it goes, rather than the rows living for
/// as long as the process does.
let buildEncoderTable () =
  let general =
    [ dataProcImmEncoders ()
      branchEncoders ()
      systemEncoders ()
      loadStoreEncoders ()
      dataProcRegEncoders () ]
    |> List.concat
    |> Map.ofList
  addEncoders writesVector general (vectorEncoders ())
  |> fun table ->
    addEncoders (fun ins -> namesSIMD ins && not (writesVector ins))
                table
                (floatEncoders ())

/// Resolves a label to the address of the instruction it marks. A label that
/// was never defined is a mistake in the source, not a lookup that failed.
let private findLabel state (baseAddr: Addr) lbl count =
  match Map.tryFind lbl state.LabelMap with
  | Some index when index <= count ->
    baseAddr + uint64 (index * 4)
  | Some _ | None ->
    raise <| EncodingFailureException $"Undefined label '{lbl}'"

/// <summary>
/// Where a place named by an instruction is measured from.
///
/// Every A64 instruction that names one measures it from its own address, save
/// the one that names a page: that one measures from the start of the page it
/// sits in, so that what it holds is a count of whole pages.
/// </summary>
let private origin opcode (addr: Addr) =
  match opcode with
  | Opcode.ADRP -> addr &&& ~~~0xfffUL
  | _ -> addr

/// <summary>
/// Rewrites the operand that names a place into the distance to it.
///
/// What the source writes is where to go, either as a label or as the address
/// the disassembler resolved one to; what an encoding holds is how far that is
/// from here, so the two are the same operand read at different times.
/// </summary>
let private resolvePlace state baseAddr count index ins =
  let pc = origin ins.Opcode (baseAddr + uint64 (index * 4))
  let resolve = function
    | OprMemory(LiteralMode(ImmOffset(Lbl target))) ->
      let target =
        match ins.Label with
        | Some lbl -> findLabel state baseAddr lbl count
        | None -> uint64 target
      OprMemory(LiteralMode(ImmOffset(Lbl(int64 (target - pc)))))
    | operand ->
      operand
  let operands = getOperandsAsList ins.Operands |> List.map resolve
  { ins with Operands = extractOperands operands }

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
/// Assembles a whole source. Every A64 instruction is one word long, so where
/// each of them sits follows from counting the ones before it, and a distance
/// to a label can be worked out before anything is encoded.
/// </summary>
let assemble (encoders: Lazy<_>) state endian baseAddr instrs =
  let count = List.length instrs
  instrs
  |> List.mapi (fun index ins ->
    resolvePlace state baseAddr count index ins
    |> encodeInstruction encoders.Value
    |> toBytes endian)
