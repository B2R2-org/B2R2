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

module internal B2R2.Assembly.M68K.ParserHelper

open System
open B2R2
open B2R2.FrontEnd.M68K

/// Shortcut for the size of the operation, which an m68k mnemonic carries as a
/// suffix of its own rather than spelling into the name.
type Sz = OperandSize

/// Represents the index register of an indexed memory operand, which a source
/// writes together with the width it is read at and the factor it is scaled by.
type AsmIndexReg =
  { Reg: Register
    /// Whether the whole long word is read rather than a sign-extended word.
    IsLong: bool
    /// The factor the index is scaled by, which is 1, 2, 4, or 8.
    Scale: int }

/// Represents the memory an instruction reaches, which is whichever of the
/// addressing modes its effective-address field names.
type AsmMemory =
  /// Address register indirect, written (An).
  | AsmDirect of Register
  /// The same, where the register moves on past what was read, written (An)+.
  | AsmPostInc of Register
  /// The same, where the register moves back before anything is written,
  /// written -(An).
  | AsmPreDec of Register
  /// A written distance from an address register or from where the instruction
  /// sits, written (d,An) or (d,PC).
  | AsmDisp of int64 * Register
  /// Any of the indexed modes, which are told apart by which of the parts of an
  /// address the source writes.
  | AsmIndexed of AsmIndex

/// <summary>
/// Represents an indexed memory operand, whose base register, index register,
/// base displacement, and outer displacement are each optional. Which of them
/// the source wrote is what tells the several indexed modes apart, just as it
/// is in what the disassembler writes.
/// </summary>
and AsmIndex =
  { /// The base register, or None where the source suppressed it. The program
    /// counter appears here for the modes counting from where the instruction
    /// sits.
    Base: Register option
    /// The index register, or None where the source named none.
    Index: AsmIndexReg option
    /// The base displacement, which is zero where the source wrote none.
    BaseDisp: int64
    /// The outer displacement, which is present only where the brackets of a
    /// memory indirect mode are.
    OuterDisp: int64 option
    /// Whether the index sits inside those brackets, which is what says that it
    /// is added before the indirect memory access rather than after it.
    IsPreIndexed: bool }

/// <summary>
/// Represents one operand as the source wrote it.
///
/// There is only one operand a source writes that the disassembler does not:
/// the name of a place. What the disassembler writes where a branch names one
/// is how far away it is, and a source may write a label in its stead.
/// </summary>
type AsmOperand =
  /// A register, under the name the disassembler writes it by.
  | AsmReg of Register
  /// A number written with the mark an instruction computing from one puts in
  /// front of it.
  | AsmImm of int64
  /// The same, where it is too wide for an integer to hold, which is how the
  /// wider of the real formats are written.
  | AsmWideImm of byte[]
  /// A number written bare, which is the whole of an address.
  | AsmAddr of uint64
  /// The memory an instruction reaches.
  | AsmMem of AsmMemory
  /// How far away a place is, written with the sign the disassembler writes it
  /// with so that it cannot be read as an address.
  | AsmRel of int64
  /// The name of a place, which stands for where that place is.
  | AsmLabel of string
  /// Where a named place turned out to be, which is None while the lengths of
  /// the instructions before it are still being counted.
  | AsmTarget of Addr option
  /// A list of registers, which is what a MOVEM or an FMOVEM moves.
  | AsmRegList of Register list
  /// The caches that a CINV or a CPUSH names.
  | AsmCaches of uint8
  /// A pair of registers written with a colon between them, which is how CAS2
  /// names each of its three operands and how a long divide names its two.
  | AsmRegPair of Register * Register
  /// A pair of memory locations that two registers point at, which is what CAS2
  /// compares and swaps.
  | AsmMemPair of Register * Register
  /// An effective address together with the bit field named within it, written
  /// "&lt;ea&gt;{offset:width}".
  | AsmBitField of AsmOperand * AsmOperand * AsmOperand

/// Represents one of the parts an address is written out of, which is how the
/// several indexed modes are told apart: which parts the source wrote is what
/// says which of them it meant.
type MemPart =
  /// The distance counted off whatever the address is built on.
  | PartDisp of int64
  /// The register the address is counted off.
  | PartBase of Register
  /// The register added to it, which is written with the width it is read at.
  | PartIndex of AsmIndexReg

/// Represents one instruction as the source wrote it.
type AsmInsInfo =
  { /// The name of the instruction, lowercased and without the suffix that
    /// said how wide the operation is.
    Mnemonic: string
    /// How wide the operation is, which the suffix of the name said.
    Size: Sz
    Operands: AsmOperand list
    /// Where the instruction sits, which is what an instruction naming a place
    /// counts the distance to that place from.
    Address: Addr
    /// The member of the family the instruction is being written for, which
    /// says which encodings it may use.
    Model: M68KModel }

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

/// The caches a source may name, paired with the bits saying which they are.
let caches = Map.ofList [ "nc", 0uy; "dc", 1uy; "ic", 2uy; "bc", 3uy ]

/// The size that a suffix of a mnemonic names, or nothing where the suffix
/// names no size at all and so is part of no mnemonic this assembler knows.
let sizeOfSuffix (suffix: string) =
  match suffix with
  | "b" -> Some Sz.Byte
  | "w" -> Some Sz.Word
  | "l" -> Some Sz.Long
  | "s" -> Some Sz.Single
  | "d" -> Some Sz.Double
  | "x" -> Some Sz.Extended
  | "p" -> Some Sz.Packed
  | _ -> None

/// The distance, the base register, and the index register that a run of parts
/// wrote, each of them where the run named one.
let private partsOf parts =
  let disp = parts |> List.tryPick (function PartDisp v -> Some v | _ -> None)
  let bse = parts |> List.tryPick (function PartBase r -> Some r | _ -> None)
  let idx = parts |> List.tryPick (function PartIndex i -> Some i | _ -> None)
  disp, bse, idx

/// The address a run of parts written between parentheses names, which is the
/// simplest mode that can say it: a register on its own where nothing else was
/// written, a distance from one where there is no index, and an indexed mode
/// otherwise.
let plainAddress parts =
  match partsOf parts with
  | None, Some reg, None ->
    AsmDirect reg
  | Some v, Some reg, None ->
    AsmDisp(v, reg)
  | disp, bse, index ->
    AsmIndexed
      { Base = bse
        Index = index
        BaseDisp = defaultArg disp 0L
        OuterDisp = None
        IsPreIndexed = false }

/// The address that a run of parts written inside the brackets of a memory
/// indirect mode names, together with whatever was written outside them. Where
/// the index sits relative to the closing bracket is what tells preindexing
/// from postindexing.
let indirectAddress inner outer =
  let disp, bse, innerIndex = partsOf inner
  let outerDisp, _, outerIndex = partsOf outer
  AsmIndexed
    { Base = bse
      Index = (if innerIndex.IsSome then innerIndex else outerIndex)
      BaseDisp = defaultArg disp 0L
      OuterDisp = Some(defaultArg outerDisp 0L)
      IsPreIndexed = innerIndex.IsSome }

/// The registers of a run written as its first and its last with a dash between
/// them, the two banks being consecutive so that a run may cross from one to
/// the other.
let runTo (first: Register) (last: Register) =
  [ for i in int first .. int last -> enum<Register> i ]

/// <summary>
/// Builds one instruction as written, taking the size of the operation out of
/// the name.
///
/// An m68k mnemonic names an operation and a size independently, so the two are
/// separated here and the encoders are looked up by the operation alone. A
/// suffix that names no size is left where it is, so that a name this assembler
/// does not know is reported as the name the source wrote.
/// </summary>
let newInfo (name: string) operands =
  let name = name.ToLowerInvariant()
  let mnemonic, size =
    match name.LastIndexOf '.' with
    | -1 ->
      name, Sz.NoSize
    | at ->
      match sizeOfSuffix name[at + 1..] with
      | Some size -> name[..at - 1], size
      | None -> name, Sz.NoSize
  { Mnemonic = mnemonic
    Size = size
    Operands = operands
    Address = 0UL
    Model = M68KModel.M68020 }

// vim: set tw=80 sts=2 sw=2:
