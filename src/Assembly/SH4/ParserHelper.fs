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

module internal B2R2.Assembly.SH4.ParserHelper

open B2R2
open B2R2.FrontEnd.SH4

/// <summary>
/// Represents one operand as the source wrote it.
///
/// There is only one operand a source writes that the disassembler does not:
/// the name of a place. What the disassembler writes where a branch names one
/// is the bits the encoding holds, and a source may write a label in its stead.
/// </summary>
type AsmOperand =
  /// A register, under the name the disassembler writes it by.
  | AsmReg of Register
  /// A number written with the mark an instruction computing from one puts in
  /// front of it.
  | AsmImm of int32
  /// A number written bare, which is what a branch holds and is the field
  /// itself rather than anything counted from where the branch sits.
  | AsmNum of int32
  /// The memory a register names.
  | AsmIndir of Register
  /// The same, where the register moves on past what was read.
  | AsmPostInc of Register
  /// The same, where the register moves back before anything is written.
  | AsmPreDec of Register
  /// The memory at a written distance from what a register holds, where the
  /// register is a general one, the global base, or the program counter.
  | AsmDispMem of int32 * Register
  /// The memory at the distance another register holds, which is always the
  /// first of the general registers.
  | AsmIdxMem of Register * Register
  /// The name of a place, which stands for where that place is.
  | AsmLabel of string
  /// Where a named place turned out to be, which is what a branch counts the
  /// bits it holds from.
  | AsmTarget of Addr

/// Represents one instruction as the source wrote it.
type AsmInsInfo =
  { /// The name of the instruction, lowercased and with the marks that only
    /// separate its parts taken out.
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

/// A run of registers the enumeration keeps one after another, given the first
/// of them and how many there are.
let private runFrom (first: Register) count =
  [ for i in 0 .. count - 1 -> enum<Register>(int first + i) ]

/// The registers that belong to no such run, which are the ones a program does
/// not compute with and the one holding where it is.
let private onTheirOwn =
  [ Register.XMTRX
    Register.SR
    Register.GBR
    Register.VBR
    Register.SSR
    Register.SPC
    Register.SGR
    Register.DBR
    Register.MACH
    Register.MACL
    Register.PR
    Register.FPUL
    Register.FPSCR
    Register.PC ]

/// <summary>
/// Every register an SH4 instruction names.
///
/// The enumeration holds more than these: the single bits a status word is
/// made of, and the registers only the machine itself reaches. None of them is
/// ever written as an operand, and leaving them out keeps a label from being
/// read as a register because it happens to be spelt like one.
/// </summary>
let private namedRegisters =
  [ runFrom Register.R0 16
    runFrom Register.R0_BANK 8
    runFrom Register.FR0 16
    runFrom Register.XF0 16
    runFrom Register.DR0 8
    runFrom Register.XD0 8
    runFrom Register.FV0 4
    onTheirOwn ]
  |> List.concat

/// Every register name a source may write, paired with the register it names.
/// The names come from Register.toString rather than from a list written out
/// here, so that what the assembler reads cannot drift from what the
/// disassembler writes.
let registers =
  namedRegisters
  |> List.map (fun reg -> Register.toString reg, reg)
  |> Map.ofList

/// <summary>
/// The name an instruction is looked up by, given the name a source wrote.
///
/// The disassembler writes a name as one word, while a person writing a source
/// separates the width or the condition an instruction works on from the rest
/// of the name, as the manual for this architecture does: mov.l, cmp/eq, bf/s.
/// Both are the same name once the marks that only separate the parts of it are
/// taken out.
/// </summary>
let canonicalName (name: string) =
  name.ToLowerInvariant().Replace(".", "").Replace("/", "")

/// Builds one instruction as written. Where it sits is not known until the
/// lines before it have been counted, so it is filled in when they have been.
let newInfo mnemonic operands =
  { Mnemonic = canonicalName mnemonic
    Operands = operands
    Address = 0UL }

// vim: set tw=80 sts=2 sw=2:
