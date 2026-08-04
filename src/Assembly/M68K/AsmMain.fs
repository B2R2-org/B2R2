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

module internal B2R2.Assembly.M68K.AsmMain

open B2R2
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.M68K.ParserHelper
open B2R2.Assembly.M68K.AsmField
open B2R2.Assembly.M68K.AsmOpcode
open B2R2.Assembly.M68K.AsmFloat

type UserState =
  { /// Label string to the index of the instruction it marks. The index starts
    /// from zero, and a label does not take one of its own.
    LabelMap: Map<string, int>
    /// Index of the instruction being parsed, which a label does not change.
    CurIndex: int }

/// Builds the lookup from a mnemonic to what it encodes as. Each assembler
/// builds its own and lets it go when it goes, rather than the rows living for
/// as long as the process does.
let buildTable () =
  integerEncoders () @ floatEncoders () |> Map.ofList

/// What the given instruction encodes as, having refused a name the member of
/// the family being written for could not read back.
let private rowOf (table: Map<string, Row>) ins =
  match Map.tryFind ins.Mnemonic table with
  | Some row when row.Since <= ins.Model && ins.Model <= row.Until -> row
  | Some _ ->
    raise
    <| EncodingFailureException $"{ins.Mnemonic} is not read by this model"
  | None ->
    raise <| EncodingFailureException $"{ins.Mnemonic} is not supported yet"

/// Encodes one instruction into the words it is made of.
let private encodeInstruction table ins = (rowOf table ins).Encode ins

/// Rewrites the operand naming a label into where that label turned out to be,
/// and records where the instruction itself sits.
let private resolveLabels resolve pc ins =
  let rewrite = function
    | AsmLabel lbl -> AsmTarget(resolve lbl)
    | operand -> operand
  { ins with Operands = List.map rewrite ins.Operands; Address = pc }

/// Resolves a label to the address of the instruction it marks. A label that
/// was never defined is a mistake in the source, not a lookup that failed.
let private findLabel state (addrs: Addr[]) lbl =
  match Map.tryFind lbl state.LabelMap with
  | Some index when index < addrs.Length -> Some addrs[index]
  | Some _ | None ->
    raise <| EncodingFailureException $"Undefined label '{lbl}'"

/// <summary>
/// Where each instruction of a source sits, and after the last of them the
/// place just past it, which is where a label written below everything marks.
///
/// An m68k instruction says how long it is only through the addressing modes
/// its operands use, so nothing can measure one without encoding it. Every
/// operand whose length turns on a value has that value in hand already, save
/// the one naming a place, and a place is reached by the widest form of the
/// field holding it, so encoding with the places left open measures every
/// instruction correctly.
/// </summary>
let private addresses table baseAddr instrs =
  instrs
  |> List.scan (fun addr ins ->
    let words = encodeInstruction table (resolveLabels (fun _ -> None) addr ins)
    addr + 2UL * uint64 (List.length words)) baseAddr
  |> List.toArray

/// The bytes of an encoded instruction, which m68k always stores with the most
/// significant of them first.
let private toBytes words =
  words
  |> List.collect (fun (word: uint16) -> [ uint8 (word >>> 8); uint8 word ])
  |> List.toArray

/// Assembles a whole source for the given member of the family.
let assemble (table: Lazy<_>) state model baseAddr instrs =
  let table = table.Value
  let instrs = instrs |> List.map (fun ins -> { ins with Model = model })
  let addrs = addresses table baseAddr instrs
  instrs
  |> List.mapi (fun index ins ->
    resolveLabels (findLabel state addrs) addrs[index] ins
    |> encodeInstruction table
    |> toBytes)

// vim: set tw=80 sts=2 sw=2:
