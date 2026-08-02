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

module internal B2R2.Assembly.PARISC.ParserHelper

open System
open B2R2
open B2R2.FrontEnd.PARISC

/// <summary>
/// Represents one operand as the source wrote it.
///
/// There is only one operand a source writes that the disassembler does not:
/// the name of a place. What the disassembler writes where an instruction
/// reaches one is how far away it is, and a source may write a label instead.
/// </summary>
type AsmOperand =
  /// A register, under the name the disassembler writes it by.
  | AsmReg of Register
  /// A written number, which is what stands wherever the encoding holds one.
  | AsmImm of uint64
  /// The memory an instruction reaches, written as what is added to a register
  /// - which is another register, a number, or nothing at all - then the space
  /// it is reached in where that is written, and the register itself.
  | AsmMem of AsmOperand option * Register option * Register
  /// The name of a place, which stands for how far away it is.
  | AsmLabel of string

/// <summary>
/// Represents one instruction as the source wrote it.
///
/// What follows the name of an instruction is kept as the words it was written
/// as rather than as the things those words stand for, because one word says
/// different things after different names: after a comparison of
/// floating-point numbers a word names one of thirty-two conditions, after an
/// addition one of sixteen others, and after a load it says how the register
/// an address is counted from is left. Which is meant is therefore settled
/// where the instruction is encoded, once its name is known.
/// </summary>
type AsmInsInfo =
  { /// The name of the instruction, lowercased and without what follows it.
    Mnemonic: string
    /// The words written after the name, each glued on with a comma.
    Suffixes: string list
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
/// Every register name a source may write, paired with the register it names.
///
/// The names come from Register.toString rather than from a list written out
/// here, so that what the assembler reads cannot drift from what the
/// disassembler writes. They are held lowercased because a source may write a
/// name in any case, and one of them - the right half of a floating-point
/// register - is written with a capital where the disassembler writes it.
/// </summary>
let registers =
  allRegisters
  |> List.map (fun reg -> (Register.toString reg).ToLowerInvariant(), reg)
  |> List.distinctBy fst
  |> Map.ofList

/// Builds one instruction as written. Where it sits is not known until the
/// lines before it have been counted, so it is filled in when they have been.
let newInfo mnemonic suffixes operands =
  { Mnemonic = mnemonic
    Suffixes = suffixes
    Operands = operands
    Address = 0UL }

// vim: set tw=80 sts=2 sw=2:
