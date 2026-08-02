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

module internal B2R2.Assembly.SPARC.ParserHelper

open System
open B2R2
open B2R2.FrontEnd.SPARC

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
  /// One of the sets of bits an instruction reads a condition off.
  | AsmCC of ConditionCode
  /// A written number, which is what stands wherever the encoding holds one.
  | AsmImm of uint64
  /// The memory an instruction reaches, written as a register and what is
  /// added to it, which is another register, a number, or nothing at all.
  | AsmMem of Register * AsmOperand option
  /// The upper part of an address, which is all the one instruction building
  /// an address in a single word can hold.
  | AsmHi of uint64
  /// The name of a place, which stands for how far away it is.
  | AsmLabel of string

/// <summary>
/// Represents one instruction as the source wrote it.
///
/// What the mnemonic names is kept as the text it was written as rather than
/// as an opcode, because the disassembler writes several opcodes under one
/// name and tells them apart by what follows: the branch that always goes
/// somewhere is written the same whether it reads a set of condition bits or
/// not, and a load is written the same whether it lands in a general register
/// or a floating-point one. Which opcode a line names is therefore settled
/// where it is encoded, once the operands are known.
/// </summary>
type AsmInsInfo =
  { /// The name of the instruction, lowercased and without its suffixes.
    Mnemonic: string
    /// Whether the branch throws away the instruction after it when it does
    /// not go, which is written as a suffix.
    Annul: bool
    /// Whether the branch says it expects to go, which only the branches
    /// holding a set of condition bits say, and which they all say.
    Predict: bool option
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

/// Every set of condition bits a source may name, paired with the set it
/// names. These are read off ConditionCode.toString for the same reason.
let conditionCodes =
  [ ConditionCode.Fcc0
    ConditionCode.Fcc1
    ConditionCode.Fcc2
    ConditionCode.Fcc3
    ConditionCode.Icc
    ConditionCode.Xcc ]
  |> List.map (fun cc -> ConditionCode.toString cc, cc)
  |> Map.ofList

/// Builds one instruction as written. Where it sits is not known until the
/// lines before it have been counted, so it is filled in when they have been.
let newInfo mnemonic annul predict operands =
  { Mnemonic = mnemonic
    Annul = annul
    Predict = predict
    Operands = operands
    Address = 0UL }

// vim: set tw=80 sts=2 sw=2:
