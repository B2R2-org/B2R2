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

module internal B2R2.Assembly.PPC.ParserHelper

open System
open B2R2
open B2R2.FrontEnd.PPC

/// The opcode enumeration under the short name the disassembler's own tables
/// go by, which the tables here are long enough to want too.
type Op = Opcode

/// <summary>
/// Represents one operand as the source wrote it.
///
/// There is only one operand a source writes that the disassembler does not:
/// the name of a place. What the disassembler prints there is the address it
/// resolved, and a source may write a label in its stead.
/// </summary>
type AsmOperand =
  /// A register, under the name the disassembler writes it by.
  | AsmReg of Register
  /// A written number, which is what stands wherever the encoding holds one.
  | AsmImm of uint64
  /// What lies at a written distance from what a register holds.
  | AsmMem of int32 * Register
  /// One bit of the condition register, written as the field it lies in and
  /// which of that field's four bits it is.
  | AsmBit of uint32
  /// The name of a place, which stands for the address it is defined at.
  | AsmLabel of string

/// Represents one instruction as the source wrote it.
type AsmInsInfo =
  { Opcode: Opcode
    Operands: AsmOperand list
    /// Where the instruction sits, which is what an instruction naming a place
    /// counts the distance to that place from.
    Address: Addr }

/// AssemblyLine is either a label definition or an instruction.
type AssemblyLine =
  | LabelDefLine
  | InstructionLine of AsmInsInfo

let checkIfInstructionLine = function
  | InstructionLine ins -> Some ins
  | LabelDefLine -> None

let filterInstructionLines lst = List.choose checkIfInstructionLine lst

/// Every register the enumeration holds, which is what the vocabulary below is
/// read off.
let private allRegisters =
  Enum.GetValues typeof<Register> |> Seq.cast<Register> |> Seq.toList

/// <summary>
/// The name the disassembler writes a register under, where it writes one at
/// all.
///
/// A vector register is kept as two halves and written as one register, so both
/// halves answer to the whole register's name. The registers no operand ever
/// names have no name here, because the disassembler never has to write one for
/// them.
/// </summary>
let private printableName (reg: Register) =
  if reg >= Register.V0A && reg <= Register.V31B then
    Some("v" + string ((int reg - int Register.V0A) / 2))
  elif reg <= Register.CR7_3 then
    Some(Register.toString reg)
  else
    None

/// Every register name the disassembler prints, paired with the register it
/// names. The names come from Register.toString rather than from a list written
/// out here, so that what the assembler reads cannot drift from what the
/// disassembler writes.
let registers =
  allRegisters
  |> List.choose (fun reg ->
    printableName reg |> Option.map (fun name -> name, reg))
  |> List.distinctBy fst
  |> Map.ofList

/// <summary>
/// The name the disassembler writes an opcode under.
///
/// A PPC mnemonic ending in a dot names the form that records what it did in
/// the condition register, and the enumeration spells that dot out because a
/// name cannot hold one; every other name is the enumeration's own, lowercased.
/// </summary>
let private nameOf (opcode: Opcode) =
  let name = string opcode
  if name.EndsWith "dot" then
    name[..name.Length - 4].ToLowerInvariant() + "."
  else
    name.ToLowerInvariant()

/// Every mnemonic, paired with the opcode it names. Each opcode has exactly one
/// name here, which is the one the disassembler writes it under.
let opcodes =
  Enum.GetValues typeof<Opcode>
  |> Seq.cast<Opcode>
  |> Seq.filter (fun opcode -> opcode <> Opcode.InvalOP)
  |> Seq.map (fun opcode -> nameOf opcode, opcode)
  |> Seq.distinctBy fst
  |> Map.ofSeq

/// <summary>
/// Which of a condition-register field's four bits a name stands for.
///
/// These are the only four the disassembler ever writes: the names for the
/// other tests are what a comparison against them is called, not bits of their
/// own.
/// </summary>
let conditionBits =
  [ "lt", 0u; "gt", 1u; "eq", 2u; "so", 3u ] |> Map.ofList

/// Builds one instruction as written. Where it sits is not known until the
/// lines before it have been counted, so it is filled in when they have been.
let newInfo opcode operands =
  { Opcode = opcode; Operands = operands; Address = 0UL }
