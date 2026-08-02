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

module internal B2R2.Assembly.EVM.ParserHelper

open B2R2

/// <summary>
/// Represents one operand as the source wrote it.
///
/// An EVM instruction names no register and carries no field: the only thing
/// any of them writes is the number a push holds. A source may write that
/// number outright, which is what the disassembler does, or write the name of a
/// place and leave working out where it is to the assembler.
/// </summary>
type AsmOperand =
  /// A number written bare, which is what a push holds. The widest push reaches
  /// two hundred and fifty-six bits, so nothing narrower holds every one.
  | AsmNum of bigint
  /// The name of a place, which stands for where that place is.
  | AsmLabel of string
  /// Where a named place turned out to be, which is what a push naming one
  /// holds.
  | AsmTarget of Addr

/// Represents one instruction as the source wrote it.
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

/// The name an instruction is looked up by, given the name a source wrote. An
/// EVM name is one word, so nothing but its case has to be settled here.
let canonicalName (name: string) = name.ToLowerInvariant()

/// Builds one instruction as written. Where it sits does not come into what it
/// holds, because a push naming a place holds where that place is rather than
/// how far away it lies.
let newInfo mnemonic operands =
  { Mnemonic = canonicalName mnemonic; Operands = operands }

// vim: set tw=80 sts=2 sw=2:
