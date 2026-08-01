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

module internal B2R2.Assembly.ARM64.ParserHelper

open System
open B2R2.FrontEnd.ARM64
open B2R2.Assembly.BinLowerer

/// <summary>
/// Represents one instruction as the source wrote it.
///
/// A64 hangs nothing off a mnemonic: an instruction that runs under a condition
/// either spells the condition into its own name, as the branches do, or takes
/// it as an operand, and how wide an instruction is follows from the registers
/// it names rather than from a suffix. So an instruction is an opcode and its
/// operands, and nothing else.
/// </summary>
type AsmInsInfo =
  { Opcode: Opcode
    Operands: Operands
    /// The label a branch names, if the source wrote one where the
    /// disassembler prints the address it resolved. Only one operand of an
    /// instruction can name a place, so one name is enough for the line.
    Label: string option }

/// AssemblyLine is either a label definition or an instruction.
type AssemblyLine =
  | LabelDefLine
  | InstructionLine of AsmInsInfo

let checkIfInstructionLine = function
  | InstructionLine ins -> Some ins
  | LabelDefLine -> None

let filterInstructionLines lst = List.choose checkIfInstructionLine lst

let extractOperands = function
  | [] -> NoOperand
  | [ o1 ] -> OneOperand o1
  | [ o1; o2 ] -> TwoOperands(o1, o2)
  | [ o1; o2; o3 ] -> ThreeOperands(o1, o2, o3)
  | [ o1; o2; o3; o4 ] -> FourOperands(o1, o2, o3, o4)
  | [ o1; o2; o3; o4; o5 ] -> FiveOperands(o1, o2, o3, o4, o5)
  | _ -> raise <| EncodingFailureException "Too many operands"

let getOperandsAsList = function
  | NoOperand -> []
  | OneOperand o1 -> [ o1 ]
  | TwoOperands(o1, o2) -> [ o1; o2 ]
  | ThreeOperands(o1, o2, o3) -> [ o1; o2; o3 ]
  | FourOperands(o1, o2, o3, o4) -> [ o1; o2; o3; o4 ]
  | FiveOperands(o1, o2, o3, o4, o5) -> [ o1; o2; o3; o4; o5 ]

/// <summary>
/// Every register name the disassembler prints. The names come from
/// Register.toString rather than from a list written out here, so that the
/// vocabulary the assembler accepts cannot drift from the one the disassembler
/// emits.
/// </summary>
let registers =
  Enum.GetValues typeof<Register>
  |> Seq.cast<Register>
  |> Seq.map (fun reg -> Register.toString reg, reg)
  |> Seq.distinctBy fst
  |> Map.ofSeq

/// Every opcode name, lowercased. The disassembler spells a mnemonic as the
/// enumeration name in lower case, so this is that vocabulary; anything it
/// spells otherwise shows up as an instruction that does not assemble, which
/// the round-trip test reports.
let opcodes =
  Enum.GetNames typeof<Opcode>
  |> Array.map (fun name ->
    name.ToLowerInvariant(), Enum.Parse(typeof<Opcode>, name) :?> Opcode)
  |> Array.distinctBy fst
  |> Map.ofArray

/// Every condition name, including the two pairs that name one encoding twice.
let conditions =
  [ "eq", EQ
    "ne", NE
    "cs", CS
    "hs", HS
    "cc", CC
    "lo", LO
    "mi", MI
    "pl", PL
    "vs", VS
    "vc", VC
    "hi", HI
    "ls", LS
    "ge", GE
    "lt", LT
    "gt", GT
    "le", LE
    "al", AL
    "nv", NV ]
  |> Map.ofList

let shiftOps =
  [ "lsl", LSL
    "lsr", LSR
    "asr", ASR
    "ror", ROR
    "msl", MSL ]
  |> Map.ofList

let extendTypes =
  [ "uxtb", UXTB
    "uxth", UXTH
    "uxtw", UXTW
    "uxtx", UXTX
    "sxtb", SXTB
    "sxth", SXTH
    "sxtw", SXTW
    "sxtx", SXTX ]
  |> Map.ofList

let barrierOptions =
  [ "sy", SY
    "st", ST
    "ld", LD
    "ish", ISH
    "ishst", ISHST
    "ishld", ISHLD
    "nsh", NSH
    "nshst", NSHST
    "nshld", NSHLD
    "osh", OSH
    "oshst", OSHST
    "oshld", OSHLD ]
  |> Map.ofList

let prefetchOperations =
  [ "pldl1keep", PLDL1KEEP
    "pldl1strm", PLDL1STRM
    "pldl2keep", PLDL2KEEP
    "pldl2strm", PLDL2STRM
    "pldl3keep", PLDL3KEEP
    "pldl3strm", PLDL3STRM
    "pstl1keep", PSTL1KEEP
    "pstl1strm", PSTL1STRM
    "pstl2keep", PSTL2KEEP
    "pstl2strm", PSTL2STRM
    "pstl3keep", PSTL3KEEP
    "pstl3strm", PSTL3STRM
    "plil1keep", PLIL1KEEP
    "plil1strm", PLIL1STRM
    "plil2keep", PLIL2KEEP
    "plil2strm", PLIL2STRM
    "plil3keep", PLIL3KEEP
    "plil3strm", PLIL3STRM ]
  |> Map.ofList

let pstates =
  [ "spsel", SPSEL
    "daifset", DAIFSET
    "daifclr", DAIFCLR ]
  |> Map.ofList

/// Every arrangement a vector register may be written with, which says both how
/// wide one element is and how many of them the register holds.
let vectorArrangements =
  [ "b", VecB
    "h", VecH
    "s", VecS
    "d", VecD
    "8b", EightB
    "16b", SixteenB
    "4h", FourH
    "8h", EightH
    "2s", TwoS
    "4s", FourS
    "1d", OneD
    "2d", TwoD
    "1q", OneQ ]
  |> Map.ofList

/// Builds one instruction as written. A label travels beside the operands
/// rather than in them, because the operand it belongs to holds a distance and
/// how far away the label is cannot be known while the line is being read.
let newInfo opcode operands label =
  { Opcode = opcode; Operands = operands; Label = label }
