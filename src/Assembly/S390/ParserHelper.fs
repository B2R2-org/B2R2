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

module internal B2R2.Assembly.S390.ParserHelper

open System
open B2R2
open B2R2.FrontEnd.S390

/// <summary>
/// Represents one operand as the source wrote it.
///
/// There is only one operand a source writes that the disassembler does not:
/// the name of a place. What the disassembler writes where an instruction names
/// one is how far away it is, and a source may write a label in its stead.
/// </summary>
type AsmOperand =
  /// A register, under the name the disassembler writes it by.
  | AsmReg of Register
  /// A set of bits selecting what an instruction does, which the disassembler
  /// writes out one bit at a time between quotes.
  | AsmMask of uint16
  /// A written number, kept as the bits it stands for, because the
  /// disassembler writes one below zero as the bits it lands in rather than
  /// with a sign.
  | AsmImm of uint64
  /// The memory an instruction reaches, written as a number counted off a base
  /// register, with an index register added to it or without one.
  | AsmMem of Register option * Register * uint64
  /// The memory an instruction reaches, written with how many bytes of it the
  /// instruction touches where an index register would otherwise be named.
  | AsmMemLen of uint16 * Register * uint64
  /// The name of a place, which stands for how far away it is.
  | AsmLabel of string

/// <summary>
/// Represents one instruction as the source wrote it.
///
/// The mnemonic is kept as the text it was written as rather than as an opcode,
/// so that reading a line does not depend on the table the encoders are looked
/// up in.
/// </summary>
type AsmInsInfo =
  { /// The name of the instruction, lowercased.
    Mnemonic: string
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

/// Every register name a source may write, paired with the register it names.
/// The names come from Register.toString rather than from a list written out
/// here, so that what the assembler reads cannot drift from what the
/// disassembler writes.
let registers =
  allRegisters
  |> List.map (fun reg -> Register.toString reg, reg)
  |> List.distinctBy fst
  |> Map.ofList

/// Builds one instruction as written. Where it sits is not known until the
/// lines before it have been counted, so it is filled in when they have been.
let newInfo mnemonic operands =
  { Mnemonic = mnemonic; Operands = operands; Address = 0UL }

// vim: set tw=80 sts=2 sw=2:
