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

module internal B2R2.Assembly.MIPS.AsmMain

open B2R2
open B2R2.FrontEnd.MIPS
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.MIPS.ParserHelper
open B2R2.Assembly.MIPS.AsmField
open B2R2.Assembly.MIPS.AsmOpcode
open B2R2.Assembly.MIPS.AsmFloat

type UserState =
  { /// Label string to the index of the instruction it marks. The index starts
    /// from zero, and a label does not take one of its own.
    LabelMap: Map<string, int>
    /// Index of the instruction being parsed, which a label does not change.
    CurIndex: int }

/// <summary>
/// Adds a table of encoders to another, keeping what was already there for the
/// instructions the new rows do not claim.
///
/// A dozen names belong both to the general registers and to the
/// floating-point ones, and what tells the two apart is the format written
/// into the mnemonic, so where a name is in both the two encoders are put
/// behind one that reads that.
/// </summary>
let private addEncoders claims table rows =
  rows
  |> List.fold (fun table (opcode, encode) ->
    match Map.tryFind opcode table with
    | Some other ->
      let choose ins = if claims ins then encode ins else other ins
      Map.add opcode choose table
    | None -> Map.add opcode encode table) table

/// Builds the lookup from an opcode to the encoder for it. Each assembler
/// builds its own and lets it go when it goes, rather than the rows living for
/// as long as the process does.
let buildEncoderTable () =
  let general =
    [ arithmeticEncoders (); branchEncoders (); loadStoreEncoders () ]
    |> List.concat
    |> Map.ofList
  addEncoders (fun ins -> Option.isSome ins.Fmt) general (floatEncoders ())

/// Resolves a label to the address of the instruction it marks. A label that
/// was never defined is a mistake in the source, not a lookup that failed.
let private findLabel state (baseAddr: Addr) lbl count =
  match Map.tryFind lbl state.LabelMap with
  | Some index when index <= count -> baseAddr + uint64 (index * 4)
  | Some _ | None ->
    raise <| EncodingFailureException $"Undefined label '{lbl}'"

/// <summary>
/// Rewrites the operand that names a label into what the encoding holds in its
/// place.
///
/// What the source writes is where to go; a branch holds how far that is from
/// here and a jump holds which word of the region it sits in the place is, so
/// the two are one operand read at different times.
/// </summary>
let private resolveLabels state baseAddr count index ins =
  let pc = baseAddr + uint64 (index * 4)
  let resolve = function
    | GoToLabel lbl ->
      let target = findLabel state baseAddr lbl count
      if namesRegion ins.Opcode then OpImm(region pc target)
      else OpAddr(Relative(int64 (target - pc)))
    | operand -> operand
  let operands = getOperandsAsList ins.Operands |> List.map resolve
  { ins with Operands = extractOperands operands }

let private encodeInstruction (encoders: Map<_, _>) ins =
  match Map.tryFind ins.Opcode encoders with
  | Some encode -> encode ins
  | None ->
    raise <| EncodingFailureException $"{ins.Opcode} is not supported yet"

/// The bytes of an encoded instruction, in the order the given endianness
/// stores them.
let private toBytes endian (word: uint32) =
  let bytes = System.BitConverter.GetBytes word
  if endian = Endian.Big then Array.rev bytes else bytes

/// <summary>
/// Assembles a whole source. Every MIPS instruction is one word long, so where
/// each of them sits follows from counting the ones before it, and how far
/// away a label is can be worked out before anything is encoded.
/// </summary>
let assemble (encoders: Lazy<_>) state endian baseAddr instrs =
  let count = List.length instrs
  instrs
  |> List.mapi (fun index ins ->
    resolveLabels state baseAddr count index ins
    |> encodeInstruction encoders.Value
    |> toBytes endian)
