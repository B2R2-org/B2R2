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

module internal B2R2.Assembly.BPF.ParserHelper

open System
open B2R2.FrontEnd.BPF

/// <summary>
/// Represents one operand as the source wrote it.
///
/// There is only one operand a source writes that the disassembler does not:
/// the name of a place. What the disassembler writes where a jump names one is
/// how far away it is, and a source may write a label in its stead.
/// </summary>
type AsmOperand =
  /// A register, under the name the disassembler writes it by.
  | AsmReg of Register
  /// A written number, which is what stands wherever the encoding holds one.
  | AsmImm of uint64
  /// The memory an instruction reaches, written as the register holding where
  /// to start from and how far from there to reach.
  | AsmMem of Register * uint64
  /// The name of a place, which stands for how far away it is.
  | AsmLabel of string

/// <summary>
/// Represents one instruction as the source wrote it.
///
/// What the mnemonic names is kept as the text it was written as rather than as
/// an opcode, because which opcode a line names is settled where it is encoded,
/// once the operands are known.
/// </summary>
type AsmInsInfo =
  { /// The name of the instruction, lowercased.
    Mnemonic: string
    Operands: AsmOperand list }

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
/// Every register name a source may write, paired with the register it names.
///
/// The names come from Register.toString rather than from a list written out
/// here, so that what the assembler reads cannot drift from what the
/// disassembler writes. Beside them stands the one name a source writes that
/// the disassembler does not: what a program reaches its own frame through is
/// written as often by that as by its number.
/// </summary>
let registers =
  allRegisters
  |> List.map (fun reg -> Register.toString reg, reg)
  |> List.append [ "fp", Register.R10 ]
  |> List.distinctBy fst
  |> Map.ofList

/// <summary>
/// How many bytes each instruction of a source takes.
///
/// Every instruction is one word wide but the one carrying a whole quadword,
/// which is two, and that one is told from every other by its name alone. This
/// is what the addresses a label is resolved against are laid out with, so it
/// has to be known before anything is encoded.
/// </summary>
let lengthOf (ins: AsmInsInfo) =
  if ins.Mnemonic.StartsWith "lddw" then 16UL else 8UL

/// Builds one instruction as written.
let newInfo mnemonic operands = { Mnemonic = mnemonic; Operands = operands }

// vim: set tw=80 sts=2 sw=2:
