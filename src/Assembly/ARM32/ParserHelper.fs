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

open B2R2
open B2R2.FrontEnd.ARM32
open FParsec

type AsmInsInfo =
  { Address: Addr
    NumBytes: uint32
    Condition: Condition
    Opcode: Opcode
    Operands: Operands
    ITState: byte
    WriteBack: bool
    Qualifier: Qualifier
    SIMDTyp: SIMDDataTypes option
    IsThumb: bool
    Cflag: bool option }

type AssemblyLine =
  | LabelDefLine
  | InstructionLine of AsmInsInfo

/// Updates the dummy offset value by substituing the reg field of the dummy
/// offset value by the register given.
let substituteParsedRegister (reg, dummyOffset) =
  match dummyOffset with
  | ImmOffset(_, signOpt, constOpt) -> ImmOffset(reg, signOpt, constOpt)
  | RegOffset(_, signOpt, shiftReg, shiftOpt) ->
    RegOffset(reg, signOpt, shiftReg, shiftOpt)
  | AlignOffset(_, alignOpt, regOpt) -> AlignOffset(reg, alignOpt, regOpt)

let parseShiftOperation opcode imm =
  let srType =
    match opcode with
    | Opcode.LSL -> Some LSL
    | Opcode.LSR -> Some LSR
    | Opcode.ASR -> Some ASR
    | Opcode.ROR -> Some ROR
    | Opcode.RRX -> Some RRX
    | _ -> None
  if srType.IsNone then fail "not a shift opcode"
  else preturn (srType.Value, imm)

let getSRType (str: string) =
  match str.ToLowerInvariant() with
  | "lsl" -> LSL
  | "lsr" -> LSR
  | "asr" -> ASR
  | "ror" -> ROR
  | "rrx" -> RRX
  | _ -> failwith "unknown SRType"

let parseOprRegShiftOperand opcode reg =
  let srType =
    match opcode with
    | Opcode.LSL -> Some LSL
    | Opcode.LSR -> Some LSR
    | Opcode.ASR -> Some ASR
    | Opcode.ROR -> Some ROR
    | Opcode.RRX -> Some RRX
    | _ -> None
  if srType.IsNone then fail "not a shift opcode"
  else preturn (OprRegShift(srType.Value, reg))

let extractOperands = function
  | [] -> NoOperand
  | [ op1 ] -> OneOperand op1
  | [ op1; op2 ] -> TwoOperands(op1, op2)
  | [ op1; op2; op3 ] -> ThreeOperands(op1, op2, op3)
  | [ op1; op2; op3; op4 ] -> FourOperands(op1, op2, op3, op4)
  | [ op1; op2; op3; op4; op5 ] -> FiveOperands(op1, op2, op3, op4, op5)
  | [ op1; op2; op3; op4; op5; op6 ] ->
    SixOperands(op1, op2, op3, op4, op5, op6)
  | _ -> failwith "Operand overload"

let getOperandsAsList operands =
  match operands with
  | NoOperand -> []
  | OneOperand(op1) -> [ op1 ]
  | TwoOperands(op1, op2) -> [ op1; op2 ]
  | ThreeOperands(op1, op2, op3) -> [ op1; op2; op3 ]
  | FourOperands(op1, op2, op3, op4) -> [ op1; op2; op3; op4 ]
  | FiveOperands(op1, op2, op3, op4, op5) -> [ op1; op2; op3; op4; op5 ]
  | SixOperands(op1, op2, op3, op4, op5, op6) ->
    [ op1; op2; op3; op4; op5; op6 ]

let getSIMDTypFromStr (str: string) =
  match str.ToLowerInvariant() with
  | "8" -> SIMDTyp8
  | "16" -> SIMDTyp16
  | "32" -> SIMDTyp32
  | "64" -> SIMDTyp64
  | "s8" -> SIMDTypS8
  | "s16" -> SIMDTypS16
  | "s32" -> SIMDTypS32
  | "s64" -> SIMDTypS64
  | "u8" -> SIMDTypU8
  | "u16" -> SIMDTypU16
  | "u32" -> SIMDTypU32
  | "u64" -> SIMDTypU64
  | "i8" -> SIMDTypI8
  | "i16" -> SIMDTypI16
  | "i32" -> SIMDTypI32
  | "i64" -> SIMDTypI64
  | "f16" -> SIMDTypF16
  | "f32" -> SIMDTypF32
  | "f64" -> SIMDTypF64
  | "p8" -> SIMDTypP8
  | _ -> failwith "unknown SIMD Type"

let getPSRFlagFromStr (str: string) =
  match str.ToLowerInvariant() with
  | "c" -> PSRc
  | "x" -> PSRx
  | "xc" -> PSRxc
  | "s" -> PSRs
  | "sc" -> PSRsc
  | "sx" -> PSRsx
  | "sxc" -> PSRsxc
  | "f" -> PSRf
  | "fc" -> PSRfc
  | "fx" -> PSRfx
  | "fxc" -> PSRfxc
  | "fs" -> PSRfs
  | "fsc" -> PSRfsc
  | "fsx" -> PSRfsx
  | "fsxc" -> PSRfsxc
  | "nzcv" -> PSRnzcv
  | "nzcvq" -> PSRnzcvq
  | "g" -> PSRg
  | "nzcvqg" -> PSRnzcvqg
  | _ -> failwith "unknown PSRFlag"

let optionOprFromStr (str: string) =
  match str.ToLowerInvariant() with
  | "sy" -> BarrierOption.SY
  | "st" -> BarrierOption.ST
  | "ld" -> BarrierOption.LD
  | "ish" -> BarrierOption.ISH
  | "ishst" -> BarrierOption.ISHST
  | "ishld" -> BarrierOption.ISHLD
  | "nsh" -> BarrierOption.NSH
  | "nshst" -> BarrierOption.NSHST
  | "nshld" -> BarrierOption.NSHLD
  | "osh" -> BarrierOption.OSH
  | "oshst" -> BarrierOption.OSHST
  | "oshld" -> BarrierOption.OSHLD
  | _ -> failwith "unknown OptionOperand"

let iFlagFromStr (str: string) =
  match str.ToLowerInvariant() with
  | "a" -> A
  | "i" -> I
  | "f" -> F
  | "ai" -> AI
  | "af" -> AF
  | "if" -> IF
  | "aif" -> AIF
  | _ -> failwith "unknown iflag"

let isITInstruction = function
  | Opcode.IT | Opcode.ITT | Opcode.ITE | Opcode.ITTT | Opcode.ITET
  | Opcode.ITTE | Opcode.ITEE | Opcode.ITTTT | Opcode.ITETT
  | Opcode.ITTET | Opcode.ITEET | Opcode.ITTTE | Opcode.ITETE
  | Opcode.ITTEE | Opcode.ITEEE -> true
  | _ -> false

let isSIMDOpcode (opcode: Opcode) = opcode.ToString() |> Seq.head = 'V'

let makeSIMDOperand = function
  | [ reg ] -> OneReg reg
  | [ reg1; reg2 ] -> TwoRegs(reg1, reg2)
  | [ reg1; reg2; reg3 ] -> ThreeRegs(reg1, reg2, reg3)
  | [ reg1; reg2; reg3; reg4 ] -> FourRegs(reg1, reg2, reg3, reg4)
  | _ -> failwith "Incorrect number of SIMDFPRegisters in the list"

let getOpCode fourTuple = fst (fst (fst fourTuple))

let newInsInfo addr opcode c it w q simd oprs iLen isThumb cflag =
  { Address = addr
    NumBytes = iLen
    Condition = c
    Opcode = opcode
    Operands = oprs
    ITState = it
    WriteBack = w
    Qualifier = q
    SIMDTyp = simd
    IsThumb = isThumb
    Cflag = cflag }

let checkIfInstructionLine = function
  | InstructionLine ins -> Some ins
  | LabelDefLine -> None

let filterInstructionLines lst = List.choose checkIfInstructionLine lst
