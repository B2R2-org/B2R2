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

module internal B2R2.Assembly.ARM32.ParserHelper

open System
open B2R2
open B2R2.FrontEnd.ARM32
open B2R2.Assembly.BinLowerer

/// <summary>
/// Represents one instruction as the source wrote it.
///
/// The condition is an option because A32 writes "always" by leaving the
/// suffix out, and the instructions living in the unconditional encoding space
/// take no condition at all. An encoder has to tell those two apart from a
/// condition that really was written, so an absent suffix cannot just become
/// AL here.
/// </summary>
type AsmInsInfo =
  { Opcode: Opcode
    Condition: Condition option
    Qualifier: Qualifier
    SIMDTyp: SIMDDataTypes option
    Operands: Operands
    /// Whether the base register carried a "!", which is how the source spells
    /// writeback for the forms that do not write it inside the brackets.
    WriteBack: bool
    /// Whether the register list carried a "^", which is how a block transfer
    /// says it names the registers of another mode or returns from an
    /// exception.
    Caret: bool
    /// Which instruction set this line belongs to. Nothing in a line says, so
    /// it is whatever the last directive before it said, or how the assembler
    /// was built if there was none.
    IsThumb: bool }

/// AssemblyLine is either a label definition or an instruction.
type AssemblyLine =
  | LabelDefLine
  | InstructionLine of AsmInsInfo

/// <summary>
/// One encoded instruction. An A32 instruction is always one word, but a Thumb
/// one is either a halfword or two of them, and which it is decides where the
/// instruction after it sits.
///
/// The two are told apart rather than counted alike because a word and two
/// halfwords do not hold their bytes in the same order.
/// </summary>
type Encoded =
  | Narrow of uint16
  | Wide of uint16 * uint16
  | Word of uint32

/// How many bytes an encoded instruction takes.
let encodedLength = function
  | Narrow _ -> 2
  | Wide _ | Word _ -> 4

/// What follows the closing bracket of a memory operand, which is what tells
/// the addressing modes apart. A post-indexed offset carries how to build
/// itself from the base register, because that register was written before the
/// bracket closed.
type MemorySuffix =
  | PlainSuffix
  | WriteBackSuffix
  | PostIndexedSuffix of (Register -> Offset)
  | UnindexedSuffix of Const

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
  | [ o1; o2; o3; o4; o5; o6 ] -> SixOperands(o1, o2, o3, o4, o5, o6)
  | _ -> raise <| EncodingFailureException "Too many operands"

let getOperandsAsList = function
  | NoOperand -> []
  | OneOperand o1 -> [ o1 ]
  | TwoOperands(o1, o2) -> [ o1; o2 ]
  | ThreeOperands(o1, o2, o3) -> [ o1; o2; o3 ]
  | FourOperands(o1, o2, o3, o4) -> [ o1; o2; o3; o4 ]
  | FiveOperands(o1, o2, o3, o4, o5) -> [ o1; o2; o3; o4; o5 ]
  | SixOperands(o1, o2, o3, o4, o5, o6) -> [ o1; o2; o3; o4; o5; o6 ]

/// Whether the opcode is one of the IT instructions, whose operand is the
/// condition the block it opens runs under.
let isITInstruction = function
  | Opcode.IT | Opcode.ITT | Opcode.ITE | Opcode.ITTT | Opcode.ITET
  | Opcode.ITTE | Opcode.ITEE | Opcode.ITTTT | Opcode.ITETT
  | Opcode.ITTET | Opcode.ITEET | Opcode.ITTTE | Opcode.ITETE
  | Opcode.ITTEE | Opcode.ITEEE -> true
  | _ -> false

/// The SIMD operand a braced list of registers stands for.
let makeSIMDOperand = function
  | [ reg ] -> OneReg reg
  | [ reg1; reg2 ] -> TwoRegs(reg1, reg2)
  | [ reg1; reg2; reg3 ] -> ThreeRegs(reg1, reg2, reg3)
  | [ reg1; reg2; reg3; reg4 ] -> FourRegs(reg1, reg2, reg3, reg4)
  | _ -> raise <| EncodingFailureException "Bad SIMD register list"

/// The barrier option a bare number names. The disassembler writes an option it
/// has no name for as its number, so reading one back means taking the number
/// for the option it stands for.
let barrierOptionOfValue (value: int64): BarrierOption =
  LanguagePrimitives.EnumOfValue(int value)

/// <summary>
/// Every register name the disassembler prints. The names come from
/// Register.toString rather than from a list written out here, so that the
/// vocabulary the assembler accepts cannot drift from the one the disassembler
/// emits.
///
/// The numbered names of the registers it prints by their role are added: the
/// disassembler writes the ninth register as sb, but a source may write it
/// either way, and only one of the two spellings comes back.
/// </summary>
let registers =
  let byRole =
    [ "r9", Register.SB
      "r10", Register.SL
      "r11", Register.FP
      "r12", Register.IP
      "r13", Register.SP
      "r14", Register.LR
      "r15", Register.PC ]
  Enum.GetValues typeof<Register>
  |> Seq.cast<Register>
  |> Seq.map (fun reg -> Register.toString reg, reg)
  |> Seq.append byRole
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

/// Every condition suffix, plus the synonyms other assemblers accept. AL and
/// NV are here because a source may write them even though the disassembler
/// does not print AL.
let conditions =
  [ "eq", Condition.EQ
    "ne", Condition.NE
    "cs", Condition.CS
    "hs", Condition.HS
    "cc", Condition.CC
    "lo", Condition.LO
    "mi", Condition.MI
    "pl", Condition.PL
    "vs", Condition.VS
    "vc", Condition.VC
    "hi", Condition.HI
    "ls", Condition.LS
    "ge", Condition.GE
    "lt", Condition.LT
    "gt", Condition.GT
    "le", Condition.LE
    "al", Condition.AL
    "nv", Condition.NV ]
  |> Map.ofList

let psrFlags =
  [ "c", PSRc
    "x", PSRx
    "xc", PSRxc
    "s", PSRs
    "sc", PSRsc
    "sx", PSRsx
    "sxc", PSRsxc
    "f", PSRf
    "fc", PSRfc
    "fx", PSRfx
    "fxc", PSRfxc
    "fs", PSRfs
    "fsc", PSRfsc
    "fsx", PSRfsx
    "fsxc", PSRfsxc
    "nzcv", PSRnzcv
    "nzcvq", PSRnzcvq
    "g", PSRg
    "nzcvqg", PSRnzcvqg ]
  |> Map.ofList

let simdDataTypes =
  [ "8", SIMDTyp8
    "16", SIMDTyp16
    "32", SIMDTyp32
    "64", SIMDTyp64
    "f16", SIMDTypF16
    "f32", SIMDTypF32
    "f64", SIMDTypF64
    "i8", SIMDTypI8
    "i16", SIMDTypI16
    "i32", SIMDTypI32
    "i64", SIMDTypI64
    "p8", SIMDTypP8
    "p64", SIMDTypP64
    "s8", SIMDTypS8
    "s16", SIMDTypS16
    "s32", SIMDTypS32
    "s64", SIMDTypS64
    "u8", SIMDTypU8
    "u16", SIMDTypU16
    "u32", SIMDTypU32
    "u64", SIMDTypU64
    "bf16", BF16 ]
  |> Map.ofList

let shiftOps =
  [ "lsl", ShiftOp.LSL
    "lsr", ShiftOp.LSR
    "asr", ShiftOp.ASR
    "ror", ShiftOp.ROR
    "rrx", ShiftOp.RRX ]
  |> Map.ofList

let barrierOptions =
  [ "sy", BarrierOption.SY
    "st", BarrierOption.ST
    "ld", BarrierOption.LD
    "ish", BarrierOption.ISH
    "ishst", BarrierOption.ISHST
    "ishld", BarrierOption.ISHLD
    "nsh", BarrierOption.NSH
    "nshst", BarrierOption.NSHST
    "nshld", BarrierOption.NSHLD
    "osh", BarrierOption.OSH
    "oshst", BarrierOption.OSHST
    "oshld", BarrierOption.OSHLD ]
  |> Map.ofList

let iflags =
  [ "a", A
    "i", I
    "f", F
    "ai", AI
    "af", AF
    "if", IF
    "aif", AIF ]
  |> Map.ofList

/// Splits the part of a mnemonic before any dot into an opcode and a condition
/// suffix. The longest opcode name wins, so that VCGT reads as one opcode
/// rather than as a VC with a GT condition; a shorter name is only taken when
/// what follows it really is a condition.
let private splitOpcodeAndCondition (text: string) =
  let rec tryLength len =
    if len = 0 then
      None
    else
      match Map.tryFind text[0..len - 1] opcodes with
      | Some opcode when len = text.Length ->
        Some(opcode, None)
      | Some opcode ->
        match Map.tryFind text[len..] conditions with
        | Some cond -> Some(opcode, Some cond)
        | None -> tryLength (len - 1)
      | _ ->
        tryLength (len - 1)
  tryLength text.Length

/// Reads the dot-separated suffixes the disassembler appends to a mnemonic: a
/// width qualifier first, then up to two SIMD data types.
let private splitSuffixes suffixes =
  let qualifier, types =
    match suffixes with
    | "w" :: rest -> W, rest
    | "n" :: rest -> N, rest
    | rest -> N, rest
  let dataTypes =
    types |> List.map (fun s -> Map.tryFind s simdDataTypes) |> List.toArray
  match dataTypes with
  | [||] -> Some(qualifier, None)
  | [| Some dt |] -> Some(qualifier, Some(OneDT dt))
  | [| Some dt1; Some dt2 |] -> Some(qualifier, Some(TwoDT(dt1, dt2)))
  | _ -> None

/// Takes a mnemonic apart into the pieces the disassembler joined together:
/// an opcode, a condition suffix, a width qualifier and any SIMD data types.
let decomposeMnemonic (mnemonic: string) =
  match mnemonic.ToLowerInvariant().Split '.' |> Array.toList with
  | [] ->
    None
  | head :: suffixes ->
    match splitOpcodeAndCondition head, splitSuffixes suffixes with
    | Some(opcode, cond), Some(qualifier, dataTypes) ->
      Some(opcode, cond, qualifier, dataTypes)
    | _ ->
      None

/// Builds one instruction as written, in the A32 instruction set: which set a
/// line belongs to is settled by the directives around it rather than by the
/// line, so the caller fills that in. The marks a register may carry travel
/// beside the operands rather than in them, because what they change is the
/// instruction rather than the register.
let newInfo opcode cond qualifier dataTypes operands marks =
  let writeBack, caret = marks
  { Opcode = opcode
    Condition = cond
    Qualifier = qualifier
    SIMDTyp = dataTypes
    Operands = operands
    WriteBack = writeBack
    Caret = caret
    IsThumb = false }
