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

module internal B2R2.Assembly.RISCV64.ParserHelper

open System
open B2R2
open B2R2.FrontEnd.RISCV64

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
  /// What lies at a written distance from what a register holds. The distance
  /// is kept as the whole sixty-four bits it was read as, because one below
  /// zero is written either with a sign or as the bits it stands for.
  | AsmMem of uint64 * Register
  /// How a floating-point instruction rounds what it computed, which is left
  /// unwritten where the instruction reads it from the rounding-mode register.
  | AsmRound of RoundMode
  /// What a fence keeps on either side of itself, written as the four kinds of
  /// access it may name.
  | AsmFence of uint32 * uint32
  /// Whether an atomic instruction takes the lock before it and gives it up
  /// after, which is written glued to the memory it reaches rather than beside
  /// it.
  | AsmOrder of bool * bool
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

/// The thirty-two general registers and the thirty-two floating-point ones,
/// which are the only registers an instruction ever names.
let private namedRegisters =
  [ for i in 0 .. 31 -> enum<Register> i
    for i in 0 .. 31 -> enum<Register>(int Register.F0 + i) ]

/// <summary>
/// Every register name a source may write, paired with the register it names.
///
/// The disassembler writes a register under the name its role in a calling
/// convention gives it, and the name comes from Register.toString rather than
/// from a list written out here, so that what the assembler reads cannot drift
/// from what the disassembler writes. A source of its own may write the number
/// of the register instead, which is the other name every one of them has.
/// </summary>
let registers =
  [ for reg in namedRegisters do
      yield Register.toString reg, reg
      let index = int reg
      if index < int Register.F0 then yield $"x{index}", reg
      else yield $"f{index - int Register.F0}", reg ]
  |> List.distinctBy fst
  |> Map.ofList

/// <summary>
/// The name the disassembler writes an opcode under.
///
/// A RISCV64 mnemonic is written in parts separated by dots, and the
/// enumeration spells each dot out because a name cannot hold one; what is left
/// is the enumeration's own name, lowercased.
/// </summary>
let private nameOf (opcode: Opcode) =
  (string opcode).Replace("dot", ".").ToLowerInvariant()

/// <summary>
/// Every mnemonic, paired with the opcode it names.
///
/// The compressed instructions are left out, because the disassembler writes
/// each of them under the name of the instruction of full width that does the
/// same thing, and that is the one this assembler encodes. The one exception is
/// the compressed instruction that does nothing at all, which has no such
/// counterpart: what the disassembler writes for it is a name the full-width
/// instruction set does not have.
/// </summary>
let opcodes =
  Enum.GetValues typeof<Opcode>
  |> Seq.cast<Opcode>
  |> Seq.filter (fun opcode ->
    let name = string opcode
    opcode <> Opcode.InvalOP && not (name.StartsWith "Cdot"))
  |> Seq.map (fun opcode -> nameOf opcode, opcode)
  |> Seq.append [ "nop", Opcode.CdotNOP ]
  |> Seq.distinctBy fst
  |> Map.ofSeq

/// Every rounding mode a source may write. The mode that reads the
/// rounding-mode register has no name here, because it is what an instruction
/// rounds by where the source writes no mode at all.
let roundModes =
  [ "rne", RoundMode.RNE
    "rtz", RoundMode.RTZ
    "rdn", RoundMode.RDN
    "rup", RoundMode.RUP
    "rmm", RoundMode.RMM ]
  |> Map.ofList

/// Which bit of a fence's mask each kind of access it may name stands for.
let fenceBits = [ 'i', 8u; 'o', 4u; 'r', 2u; 'w', 1u ] |> Map.ofList

/// Builds one instruction as written. Where it sits is not known until the
/// lines before it have been counted, so it is filled in when they have been.
let newInfo opcode operands =
  { Opcode = opcode; Operands = operands; Address = 0UL }
