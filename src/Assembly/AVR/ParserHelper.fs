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

module internal B2R2.Assembly.AVR.ParserHelper

open B2R2
open B2R2.FrontEnd.AVR

/// <summary>
/// Represents one operand as the source wrote it.
///
/// There is only one operand a source writes that the disassembler does not:
/// the name of a place. What the disassembler writes where a branch names one
/// is the distance the encoding holds, and a source may write a label in its
/// stead.
/// </summary>
type AsmOperand =
  /// A register, under the name the disassembler writes it by.
  | AsmReg of Register
  /// A number written bare, which is what everything computing from one holds
  /// and what a jump reaching the whole of memory says where it goes with.
  | AsmNum of int32
  /// A distance from the address just past the instruction, written with the
  /// mark this architecture puts in front of one.
  | AsmRel of int32
  /// The memory a register names, where the register moves on past what was
  /// read through it.
  | AsmPostInc of Register
  /// The same, where the register moves back before anything is read.
  | AsmPreDec of Register
  /// The memory at a written distance from what one of the two index registers
  /// holds.
  | AsmDisp of Register * int32
  /// The name of a place, which stands for where that place is.
  | AsmLabel of string
  /// Where a named place turned out to be, which is what an instruction naming
  /// one counts the distance it holds from.
  | AsmTarget of Addr

/// Represents one instruction as the source wrote it.
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

/// <summary>
/// Every register an AVR instruction names.
///
/// The enumeration holds more than these: the single bits the status word is
/// made of, the stack pointer, and the register holding where the program is.
/// None of them is ever written as an operand, and leaving them out keeps a
/// label from being read as a register because it happens to be spelt like one.
/// </summary>
let private namedRegisters =
  [ for i in 0 .. 31 -> enum<Register>(int Register.R0 + i) ]
  @ [ Register.X; Register.Y; Register.Z ]

/// Every register name a source may write, paired with the register it names.
/// The names come from Register.toString rather than from a list written out
/// here, so that what the assembler reads cannot drift from what the
/// disassembler writes.
let registers =
  namedRegisters
  |> List.map (fun reg -> (Register.toString reg).ToLowerInvariant(), reg)
  |> Map.ofList

/// The name an instruction is looked up by, given the name a source wrote. An
/// AVR name is one word, so nothing but its case has to be settled here.
let canonicalName (name: string) = name.ToLowerInvariant()

/// Builds one instruction as written. Where it sits is not known until the
/// lines before it have been counted, so it is filled in when they have been.
let newInfo mnemonic operands =
  { Mnemonic = canonicalName mnemonic
    Operands = operands
    Address = 0UL }

// vim: set tw=80 sts=2 sw=2:
