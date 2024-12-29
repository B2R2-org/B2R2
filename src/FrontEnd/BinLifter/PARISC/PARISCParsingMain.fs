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

module internal B2R2.FrontEnd.BinLifter.PARISC.ParsingMain

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.BitData

let getRegister = function
  | 0x0u -> R.GR0
  | 0x1u -> R.GR1
  | 0x2u -> R.GR2
  | 0x3u -> R.GR3
  | 0x4u -> R.GR4
  | 0x5u -> R.GR5
  | 0x6u -> R.GR6
  | 0x7u -> R.GR7
  | 0x8u -> R.GR8
  | 0x9u -> R.GR9
  | 0xAu -> R.GR10
  | 0xBu -> R.GR11
  | 0xCu -> R.GR12
  | 0xDu -> R.GR13
  | 0xEu -> R.GR14
  | 0xFu -> R.GR15
  | 0x10u -> R.GR16
  | 0x11u -> R.GR17
  | 0x12u -> R.GR18
  | 0x13u -> R.GR19
  | 0x14u -> R.GR20
  | 0x15u -> R.GR21
  | 0x16u -> R.GR22
  | 0x17u -> R.GR23
  | 0x18u -> R.GR24
  | 0x19u -> R.GR25
  | 0x1Au -> R.GR26
  | 0x1Bu -> R.GR27
  | 0x1Cu -> R.GR28
  | 0x1Du -> R.GR29
  | 0x1Eu -> R.GR30
  | 0x1Fu -> R.GR31
  | _ -> raise InvalidRegisterException

let getFRegister = function
  | 0x0u -> R.FPR0
  | 0x1u -> R.FPR1
  | 0x2u -> R.FPR2
  | 0x3u -> R.FPR3
  | 0x4u -> R.FPR4
  | 0x5u -> R.FPR5
  | 0x6u -> R.FPR6
  | 0x7u -> R.FPR7
  | 0x8u -> R.FPR8
  | 0x9u -> R.FPR9
  | 0xAu -> R.FPR10
  | 0xBu -> R.FPR11
  | 0xCu -> R.FPR12
  | 0xDu -> R.FPR13
  | 0xEu -> R.FPR14
  | 0xFu -> R.FPR15
  | _ -> raise InvalidRegisterException

let getRegFromRange bin low high =
  extract bin high low |> uint32 |> getRegister

let getFRegFromRange bin low high =
  extract bin high low |> uint32 |> getFRegister

let getImmediate bin low high wordSize =
  let imm = extract bin high low |> uint64
  signExtend (int (high - low + 1u)) wordSize imm

let getRelativeAddress pc bin low high wordSize =
  let offset = getImmediate bin low high wordSize
  pc + uint64 offset

let parseArithmeticInstruction bin wordSz =
  let rd = getRegFromRange bin 4u 0u
  let rs1 = getRegFromRange bin 20u 16u
  let rs2 = getRegFromRange bin 25u 21u
  let ext6 =
    match extract bin 11u 6u with
    | 0b011000u -> Op.ADD
    | 0b101000u -> Op.ADDL
    | 0b011100u -> Op.ADDC
    | 0b010000u -> Op.SUB
    | 0b010100u -> Op.SUBB
    | 0b001001u -> Op.OR
    | 0b001000u -> Op.AND
    | 0b011001u | 0b011010u | 0b011011u -> Op.SHLADD
    | 0b101001u | 0b101010u | 0b101011u -> Op.SHLADDL
    | 0b001010u -> Op.XOR
    | 0b000000u -> Op.ANDCM
    | 0b100110u -> Op.UADDCM
    | 0b001110u -> Op.UXOR
    | 0b010001u -> Op.DS
    | 0b100010u -> Op.CMPCLR
    | 0b101110u -> Op.DCOR
    | 0b001111u -> Op.HADD
    | 0b000111u -> Op.HSUB
    | 0b001011u -> Op.HAVG
    | 0b011101u | 0b011110u | 0b011111u -> Op.HSHLADD
    | 0b010101u | 0b010110u | 0b010111u -> Op.HSHRADD
    | _ -> raise ParsingFailureException
  let operands = ThreeOperands (OpReg rd, OpReg rs1, OpReg rs2)
  struct (ext6, operands)

let parseImmediateArithmeticInstruction bin wordSz =
  let rd = getRegFromRange bin 20u 16u
  let rs1 = getRegFromRange bin 25u 21u
  let imm = extract bin 10u 0u |> uint64 |> OpImm
  let opcode =
    match extract bin 31u 26u with
    | 0b101101u | 0b101100u -> Op.ADDI
    | 0b100101u -> Op.SUBI
    | 0b100100u -> Op.CMPICLR
    | _ -> raise ParsingFailureException
  let operands = ThreeOperands (OpReg rd, OpReg rs1, imm)
  struct (opcode, operands)

let parseShiftExtractDepositInstruction bin wordSz =
  let bit20 = extract bin 11u 11u
  let bit19 = extract bin 12u 12u
  let bit19to21 = extract bin 12u 10u
  let opcode =
    match extract bin 31u 26u with
    | 0b110100u ->
      match bit19 with
      | 0b0u -> Op.SHRPW
      | _ -> Op.EXTRW
    | 0b110101u ->
      match bit19 with
      | 0b0u -> Op.DEPW
      | _ -> Op.DEPWI
    | _ -> raise ParsingFailureException
  let operands =
    match opcode with
    | Op.SHRPW ->
      match bit20 with
      | 0b0u ->
        let r1 = getRegFromRange bin 20u 16u
        let r2 = getRegFromRange bin 25u 21u
        let rd = getRegFromRange bin 4u 0u
        let shftamtsar = OpSARSHIFT (SHIFTST.SARSHFT)
        FourOperands (OpReg r1, OpReg r2, shftamtsar, OpReg rd)
      | 0b1u ->
        let r1 = getRegFromRange bin 20u 16u
        let r2 = getRegFromRange bin 25u 21u
        let rd = getRegFromRange bin 4u 0u
        let shiftamtfixedcpos = extract bin 9u 5u |> uint64 |> OpImm
        FourOperands (OpReg r1, OpReg r2, shiftamtfixedcpos, OpReg rd)
      | _ -> raise ParsingFailureException
    | Op.EXTRW ->
      match bit20 with
      | 0b0u ->
        let shftamtsar = OpSARSHIFT (SHIFTST.SARSHFT)
        let rd = getRegFromRange bin 20u 16u
        let r = getRegFromRange bin 25u 21u
        let immlen = extract bin 4u 0u |> uint64 |> OpImm
        let condbit =
          match extract bin 15u 13u with
          | 0b000u -> OpCond (PARISCCondition.NV)
          | 0b001u -> OpCond (PARISCCondition.EQ)
          | 0b010u -> OpCond (PARISCCondition.LT)
          | 0b100u -> OpCond (PARISCCondition.TR)
          | 0b101u -> OpCond (PARISCCondition.NEQ)
          | 0b110u -> OpCond (PARISCCondition.GTE)
          | _ -> raise ParsingFailureException
        FiveOperands (condbit, OpReg r, shftamtsar, immlen, OpReg rd)
      | 0b1u ->
        let shiftamtfixedpos = extract bin 9u 5u |> uint64 |> OpImm
        let immlen = extract bin 4u 0u |> uint64 |> OpImm
        let rd = getRegFromRange bin 20u 16u
        let r = getRegFromRange bin 25u 21u
        let condbit =
          match extract bin 15u 13u with
          | 0b000u -> OpCond (PARISCCondition.NV)
          | 0b001u -> OpCond (PARISCCondition.EQ)
          | 0b010u -> OpCond (PARISCCondition.LT)
          | 0b100u -> OpCond (PARISCCondition.TR)
          | 0b101u -> OpCond (PARISCCondition.NEQ)
          | 0b110u -> OpCond (PARISCCondition.GTE)
          | _ -> raise ParsingFailureException
        FiveOperands (condbit, OpReg r, shiftamtfixedpos, immlen, OpReg rd)
      | _ -> raise ParsingFailureException
    | Op.DEPW ->
      match bit20 with
      | 0b0u ->
        let shftamtsar = OpSARSHIFT (SHIFTST.SARSHFT)
        let r = getRegFromRange bin 20u 16u
        let rd = getRegFromRange bin 25u 21u
        let immlen = extract bin 4u 0u |> uint64 |> OpImm
        FourOperands (OpReg r, shftamtsar, immlen, OpReg rd)
      | 0b1u ->
        let shiftamtfixedcpos = extract bin 9u 5u |> uint64 |> OpImm
        let immlen = extract bin 4u 0u |> uint64 |> OpImm
        let r = getRegFromRange bin 20u 16u
        let rd = getRegFromRange bin 25u 21u
        FourOperands (OpReg r, shiftamtfixedcpos, immlen, OpReg rd)
      | _ -> raise ParsingFailureException
    | Op.DEPWI ->
      match bit20 with
      | 0b0u ->
        let shftamtsar = OpSARSHIFT (SHIFTST.SARSHFT)
        let im5 = extract bin 20u 16u |> uint64 |> OpImm
        let rd = getRegFromRange bin 25u 21u
        let immlen = extract bin 4u 0u |> uint64 |> OpImm
        FourOperands (im5, shftamtsar, immlen, OpReg rd)
      | 0b1u ->
        let shiftamtfixedcpos = extract bin 9u 5u |> uint64 |> OpImm
        let immlen = extract bin 4u 0u |> uint64 |> OpImm
        let im5 = extract bin 20u 16u |> uint64 |> OpImm
        let rd = getRegFromRange bin 25u 21u
        FourOperands (im5, shiftamtfixedcpos, immlen, OpReg rd)
      | _ -> raise ParsingFailureException
    | _ -> raise ParsingFailureException
  struct (opcode, operands)

let parseRearrangementInstruction bin wordSz =
  let rd = getRegFromRange bin 4u 0u
  let rs1 = getRegFromRange bin 20u 16u
  let rs2 = getRegFromRange bin 25u 21u
  let ea = extract bin 14u 13u
  let eb = extract bin 11u 10u
  let opcode =
    match extract bin 15u 15u with
    | 0b1u ->
      match (ea, eb) with
      | (0b00u, 0b10u) -> Op.HSHL
      | (0b10u, 0b10u) -> Op.HSHR
      | (0b00u, 0b00u) -> Op.MIXW
      | (0b00u, 0b01u) -> Op.MIXH
      | _ -> raise ParsingFailureException
    | 0b0u -> Op.PERMH
    | _ -> raise ParsingFailureException
  let operands = ThreeOperands (OpReg rd, OpReg rs1, OpReg rs2)
  struct (opcode, operands)

let parseLoadStoreBWHAloneInstruction bin wordSz =
  let baseReg = getRegFromRange bin 25u 21u
  let rd = getRegFromRange bin 20u 16u
  let offset = getImmediate bin 13u 0u wordSz
  let memAddr = OpMem (baseReg, Some (Imm (int64 offset)), wordSz)
  let opcode =
    match extract bin 31u 26u with
    | 0b010000u -> Op.LDB
    | 0b010001u -> Op.LDH
    | 0b010010u | 0b010011u -> Op.LDW
    | 0b011000u -> Op.STB
    | 0b011001u -> Op.STH
    | 0b011010u | 0b011011u  -> Op.STW
    | _ -> raise ParsingFailureException
  let operands = TwoOperands (OpReg rd, memAddr)
  struct (opcode, operands)

let parseFLsAloneInstruction bin wordSz =
  let baseReg = getRegFromRange bin 25u 21u
  let offset = getImmediate bin 20u 16u wordSz
  let rd = getRegFromRange bin 4u 0u
  let memAddr = OpMem (baseReg, Some (Imm (int64 offset)), wordSz)
  let operands = TwoOperands (OpReg rd, memAddr)
  let opcode =
    match extract bin 9u 9u with
    | 0b0u -> Op.FLDW
    | 0b1u -> Op.FSTW
    | _ -> raise ParsingFailureException
  struct (opcode, operands)

let parseLoadStoreShortInstruction bin wordSz =
  let baseReg = getRegFromRange bin 25u 21u
  let bt = extract bin 9u 6u
  let firstopc = extract bin 31u 26u
  let bt30 = extract bin 1u 1u
  let bt29 = extract bin 2u 2u
  let opcode =
    match extract bin 31u 26u with
    | 0b000011u ->
      match extract bin 9u 6u with
      | 0b0000u -> Op.LDB
      | 0b0001u -> Op.LDH
      | 0b0010u -> Op.LDW
      | 0b0011u -> Op.LDD
      | 0b0100u -> Op.LDDA
      | 0b0101u -> Op.LDCD
      | 0b0111u -> Op.LDCW
      | 0b1000u -> Op.STB
      | 0b1001u -> Op.STH
      | 0b1010u -> Op.STW
      | 0b1011u -> Op.STD
      | 0b1100u -> Op.STBY
      | 0b1101u -> Op.STDBY
      | 0b1110u -> Op.STWA
      | 0b1111u -> Op.STDA
      | _ -> raise ParsingFailureException
    | 0b001011u ->
      match extract bin 9u 9u with
      | 0b0u -> Op.FLDD
      | 0b1u -> Op.FSTD
      | _ -> raise ParsingFailureException
    | _ -> raise ParsingFailureException
  let operands =
    match opcode with
    | Op.STB | Op.STH | Op.STW | Op.STD
    | Op.STDA | Op.STBY | Op.STDBY
    | Op.STWA | Op.FSTW | Op.FSTD ->
      let offset = getImmediate bin 4u 0u wordSz
      let rs = getRegFromRange bin 20u 16u
      let memAddr = OpMem (baseReg, Some (Imm (int64 offset)), wordSz)
      TwoOperands (OpReg rs, memAddr)
    | Op.LDB | Op.LDH | Op.LDW | Op.LDD
    | Op.LDDA | Op.LDCD | Op.LDCW
    | Op.FLDW | Op.FLDD ->
      let rd = getRegFromRange bin 4u 0u
      let offset = getImmediate bin 20u 16u wordSz
      let memAddr = OpMem (baseReg, Some (Imm (int64 offset)), wordSz)
      TwoOperands (OpReg rd, memAddr)
    | _ -> raise ParsingFailureException
  struct (opcode, operands)

let parseLoadStoredwInstruction bin wordSz =
  let baseReg = getRegFromRange bin 25u 21u
  let bit30 = extract bin 1u 1u
  let bit29 = extract bin 2u 2u
  let opcode =
    match extract bin 31u 26u with
    | 0b010110u -> Op.FLDW
    | 0b011110u -> Op.FSTW
    | 0b010100u ->
      match bit30 with
      | 0b0u -> Op.LDD
      | 0b1u -> Op.FLDD
      | _ -> raise ParsingFailureException
    | 0b011100u ->
      match bit30 with
      | 0b0u -> Op.STD
      | 0b1u -> Op.FSTD
      | _ -> raise ParsingFailureException
    | 0b010111u ->
      match bit29 with
      | 0b0u -> Op.FLDW
      | 0b1u -> Op.LDW
      | _ -> raise ParsingFailureException
    | 0b011111u ->
      match bit29 with
      | 0b0u -> Op.FSTW
      | 0b1u -> Op.STW
      | _ -> raise ParsingFailureException
    | _ -> raise ParsingFailureException
  let operands =
    match opcode with
    | Op.LDD | Op.FLDD | Op.STD | Op.FSTD ->
      let rd = getRegFromRange bin 20u 16u
      let offset = getImmediate bin 13u 4u wordSz
      let memAddr = OpMem (baseReg, Some (Imm (int64 offset)), wordSz)
      TwoOperands (OpReg rd, memAddr)
    | Op.LDW | Op.FLDW | Op.STW | Op.FSTW ->
      let rd = getRegFromRange bin 20u 16u
      let offset = getImmediate bin 13u 3u wordSz
      let memAddr = OpMem (baseReg, Some (Imm (int64 offset)), wordSz)
      TwoOperands (OpReg rd, memAddr)
    | _ -> raise ParsingFailureException
  struct (opcode, operands)

let parseBranchC3Instruction bin wordSz =
  let ext16to18 = extract bin 15u 13u
  let opcode =
    match ext16to18 with
    | 0b000u | 0b101u | 0b100u -> Op.BL
    | 0b010u -> Op.BLR
    | 0b110u -> Op.BV
    | _ -> raise ParsingFailureException
  let operands =
    match opcode with
    | Op.BL ->
      let rd = getRegFromRange bin 25u 21u
      let br = getRegFromRange bin 20u 16u
      let w1bit = extract bin 20u 16u
      let w2bit = extract bin 12u 2u
      let wbit = extract bin 0u 0u
      let combinedbit = (w2bit <<< 5) ||| (w1bit <<< 1) ||| wbit
      let offset = getImmediate combinedbit 0u 20u wordSz
      let memAddr = OpMem (br, Some (Imm (int64 offset)), wordSz)
      TwoOperands (memAddr, OpReg rd)
    | Op.BV ->
      let br = getRegFromRange bin 25u 21u
      let offset = getImmediate bin 20u 16u wordSz
      let memAddr = OpMem (br, Some (Imm (int64 offset)), wordSz)
      OneOperand (memAddr)
    | Op.BLR ->
      let regx = getRegFromRange bin 20u 16u
      let rd = getRegFromRange bin 25u 21u
      TwoOperands (OpReg regx, OpReg rd)
    | _ -> raise ParsingFailureException
  struct (opcode, operands)

let parseBranchAlonesInstruction bin wordSz =
  let brg = getRegFromRange bin 25u 21u
  let w1bit = extract bin 12u 2u
  let wbit = extract bin 0u 0u
  let combinedbit = (w1bit <<< 1) ||| wbit
  let offset = getImmediate combinedbit 0u 12u wordSz
  let memAddr = OpMem (brg , Some (Imm (int64 offset)), wordSz)
  let opcode =
    match extract bin 31u 26u with
    | 0b110010u -> Op.MOVB
    | 0b110000u | 0b110001u -> Op.BB
    | 0b100000u | 0b100010u | 0b100111u | 0b101111u -> Op.CMPB
    | 0b101000u | 0b101010u -> Op.ADDB
    | _ -> raise ParsingFailureException
  let fbit =
    match extract bin 31u 26u with
    | 0b100000u | 0b100111u | 0b101000u -> 0b0u
    | 0b100010u | 0b101111u | 0b101010u -> 0b1u
    | _ -> 0b00u
  let operands =
    match opcode with
    | Op.BB ->
      let p = extract bin 25u 21u |> uint64 |> OpImm
      let reg = getRegFromRange bin 20u 16u
      let condc = extract bin 15u 15u
      let condbit =
        match condc with
        | 0b0u -> OpCond (PARISCCondition.LT)
        | 0b1u -> OpCond (PARISCCondition.GTE)
        | _ -> raise ParsingFailureException
      FourOperands (condbit, OpReg reg, p, memAddr)
    | Op.MOVB ->
      let r2 = getRegFromRange bin 25u 21u
      let r1 = getRegFromRange bin 20u 16u
      let condc = extract bin 15u 13u
      let condbit =
        match condc with
        | 0b000u -> OpCond (PARISCCondition.NV)
        | 0b001u -> OpCond (PARISCCondition.EQ)
        | 0b010u -> OpCond (PARISCCondition.LT)
        | 0b100u -> OpCond (PARISCCondition.TR)
        | 0b101u -> OpCond (PARISCCondition.NEQ)
        | 0b110u -> OpCond (PARISCCondition.GTE)
        | _ -> raise ParsingFailureException
      FourOperands (condbit, OpReg r1, OpReg r2, memAddr)
    | Op.CMPB | Op.ADDB ->
      let r2 = getRegFromRange bin 25u 21u
      let r1 = getRegFromRange bin 20u 16u
      let condc = extract bin 15u 13u
      let condbit =
        match (condc, fbit) with
        | (0b000u, 0b0u) -> OpCond (PARISCCondition.NV)
        | (0b001u, 0b0u) -> OpCond (PARISCCondition.EQ)
        | (0b010u, 0b0u) -> OpCond (PARISCCondition.LT)
        | (0b011u, 0b0u) -> OpCond (PARISCCondition.LTE)
        | (0b100u, 0b0u) -> OpCond (PARISCCondition.LTU)
        | (0b101u, 0b0u) -> OpCond (PARISCCondition.LTEU)
        | (0b000u, 0b1u) -> OpCond (PARISCCondition.TR)
        | (0b001u, 0b1u) -> OpCond (PARISCCondition.NEQ)
        | (0b010u, 0b1u) -> OpCond (PARISCCondition.GTE)
        | (0b011u, 0b1u) -> OpCond (PARISCCondition.GT)
        | (0b100u, 0b1u) -> OpCond (PARISCCondition.GTEU)
        | (0b101u, 0b1u) -> OpCond (PARISCCondition.GTU)
        | _ -> raise ParsingFailureException
      FourOperands (condbit, OpReg r1, OpReg r2, memAddr)
    | _ -> raise ParsingFailureException
  struct (opcode, operands)

let parseBranchImmediateInstruction bin wordSz =
  let opcode =
    match extract bin 31u 26u with
    | 0b110011u -> Op.MOVIB
    | 0b100001u | 0b100011u | 0b111011u -> Op.CMPIB
    | 0b101001u | 0b101011u -> Op.ADDIB
    | _ -> raise ParsingFailureException
  let fbit =
    match extract bin 31u 26u with
    | 0b101001u | 0b100001u -> 0b0u
    | 0b100011u | 0b101011u -> 0b1u
    | _ -> raise ParsingFailureException
  let condc = extract bin 15u 13u
  let reg = getRegFromRange bin 25u 21u
  let imm5 = extract bin 20u 16u |> uint64 |> OpImm
  let brg = getRegFromRange bin 20u 16u
  let w1bit = extract bin 12u 2u
  let wbit = extract bin 0u 0u
  let combinedbit = (w1bit <<< 1) ||| wbit
  let offset = getImmediate combinedbit 0u 12u wordSz
  let memAddr = OpMem (brg , Some (Imm (int64 offset)), wordSz)
  let condbit =
    match opcode with
    | Op.MOVIB ->
      match condc with
      | 0b000u -> OpCond (PARISCCondition.NV)
      | 0b001u -> OpCond (PARISCCondition.EQ)
      | 0b010u -> OpCond (PARISCCondition.LT)
      | 0b100u -> OpCond (PARISCCondition.TR)
      | 0b101u -> OpCond (PARISCCondition.NEQ)
      | 0b110u -> OpCond (PARISCCondition.GTE)
      | _ -> raise ParsingFailureException
    | Op.ADDIB | Op.CMPIB ->
        match (condc, fbit) with
        | (0b000u, 0b0u) -> OpCond (PARISCCondition.NV)
        | (0b001u, 0b0u) -> OpCond (PARISCCondition.EQ)
        | (0b010u, 0b0u) -> OpCond (PARISCCondition.LT)
        | (0b011u, 0b0u) -> OpCond (PARISCCondition.LTE)
        | (0b100u, 0b0u) -> OpCond (PARISCCondition.LTU)
        | (0b101u, 0b0u) -> OpCond (PARISCCondition.LTEU)
        | (0b000u, 0b1u) -> OpCond (PARISCCondition.TR)
        | (0b001u, 0b1u) -> OpCond (PARISCCondition.NEQ)
        | (0b010u, 0b1u) -> OpCond (PARISCCondition.GTE)
        | (0b011u, 0b1u) -> OpCond (PARISCCondition.GT)
        | (0b100u, 0b1u) -> OpCond (PARISCCondition.GTEU)
        | (0b101u, 0b1u) -> OpCond (PARISCCondition.GTU)
        | _ -> raise ParsingFailureException
    | _ -> raise ParsingFailureException
  let operands = FourOperands (condbit, imm5, OpReg reg, memAddr)
  struct (opcode, operands)

let parseSpecialRegisterInstruction bin wordSz =
  let ext19to26 = extract bin 12u 5u
  let opcode =
    match ext19to26 with
    | 0b01100000u -> Op.RFI
    | 0b00000000u -> Op.BREAK
    | 0b00100000u ->
      match extract bin 20u 16u with
      | 0b00000u -> Op.SYNC
      | 0b10000u -> Op.SYNCDMA
      | _ -> raise ParsingFailureException
    | 0b01101011u -> Op.SSM
    | 0b01110011u -> Op.RSM
    | 0b11000011u -> Op.MTSM
    | 0b10000101u -> Op.LDSID
    | 0b11000001u -> Op.MTSP
    | 0b00100101u -> Op.MFSP
    | 0b11000010u -> Op.MTCTL
    | 0b01000101u -> Op.MFCTL
    | 0b11000110u -> Op.MTSARCM
    | 0b10100101u -> Op.MFIA
    | _ -> raise ParsingFailureException
  let operands =
    match opcode with
    | Op.LDSID ->
      let baseReg = getRegFromRange bin 25u 21u
      let sbit = extract bin 15u 14u
      let desReg = getRegFromRange bin 4u 0u
      match sbit with
      | 0b00u ->
        TwoOperands (OpMem (baseReg, Some (Imm (int64 sbit)), wordSz),
        OpReg desReg)
      | _ ->
        let spaceReg = getRegFromRange bin 15u 14u
        TwoOperands (OpReg spaceReg, OpReg desReg)
    | Op.MTSP ->
      let spaceReg = getRegFromRange bin 15u 13u
      let srcReg = getRegFromRange bin 19u 15u
      TwoOperands (OpReg srcReg, OpReg spaceReg)
    | Op.MTCTL ->
      let destReg = getRegFromRange bin 25u 21u
      let srcReg = getRegFromRange bin 19u 15u
      TwoOperands (OpReg srcReg, OpReg destReg)
    | Op.MTSARCM ->
      let srcReg = getRegFromRange bin 19u 15u
      OneOperand (OpReg srcReg)
    | Op.MFSP ->
      let spaceReg = getRegFromRange bin 15u 13u
      let destReg = getRegFromRange bin 4u 0u
      TwoOperands (OpReg spaceReg, OpReg destReg)
    | Op.MFCTL ->
      let spaceReg = getRegFromRange bin 25u 21u
      let destReg = getRegFromRange bin 4u 0u
      TwoOperands (OpReg spaceReg, OpReg destReg)
    | Op.MFIA ->
      let destReg = getRegFromRange bin 4u 0u
      OneOperand (OpReg destReg)
    | Op.SSM | Op.RSM ->
      let destReg = getRegFromRange bin 4u 0u
      let immi = extract bin 15u 6u |> uint64 |> OpImm
      TwoOperands (immi, OpReg destReg)
    | Op.MTSM ->
      let reg = getRegFromRange bin 20u 16u
      OneOperand (OpReg reg)
    | Op.RFI ->
      let e1 = getRegFromRange bin 8u 5u
      OneOperand (OpReg e1)
    | Op.SYNC | Op.SYNCDMA -> NoOperand
    | Op.BREAK ->
      let im5 = extract bin 4u 0u |> uint64 |> OpImm
      let im13 = extract bin 25u 13u |> uint64 |> OpImm
      TwoOperands (im5, im13)
    | _ -> NoOperand
  struct (opcode, operands)

let parseMemoryManagementInstruction bin wordSz =
  let ext20to25 = extract bin 11u 6u
  let bit19 = extract bin 12u 12u
  let bit18 = extract bin 13u 13u
  let opcode =
    match ext20to25 with
    | 0b000110u ->
      match bit18 with
      | 0b0u -> Op.PROBE
      | 0b1u -> Op.PROBEI
      | _ -> raise ParsingFailureException
    | 0b001101u -> Op.LPA
    | 0b001100u -> Op.LCI
    | 0b001000u ->
      match bit19 with
      | 0b1u -> Op.PDTLB
      | 0b0u -> Op.PITLB
      | _ -> raise ParsingFailureException
    | 0b001001u ->
      match bit19 with
      | 0b1u -> Op.PDTLBE
      | 0b0u -> Op.PITLBE
      | _ -> raise ParsingFailureException
    | 0b100000u ->
      match bit19 with
      | 0b1u -> Op.IITLBT
      | 0b0u -> Op.IDTLBT
      | _ -> raise ParsingFailureException
    | 0b001110u -> Op.PDC
    | 0b001010u -> Op.FDC
    | 0b001111u -> Op.FIC
    | 0b110001u -> Op.PUSHBTS
    | 0b110010u -> Op.PUSHNOM
    | 0b001011u ->
      match bit19 with
      | 0b1u -> Op.FDCE
      | 0b0u -> Op.FICE
      | _ -> raise ParsingFailureException
    | _ -> raise ParsingFailureException
  let operands =
    match opcode with
    | Op.IITLBT ->
      let srcReg1 = getRegFromRange bin 20u 16u
      let srcReg2 = getRegFromRange bin 25u 21u
      TwoOperands (OpReg srcReg1, OpReg srcReg2)
    | Op.PUSHBTS | Op.PUSHNOM -> NoOperand
    | Op.PROBE | Op.PROBEI | Op.LPA | Op.LCI | Op.PDTLB | Op.PITLB
    | Op.PDTLBE | Op.PITLBE | Op.IDTLBT | Op.IITLBT | Op.PDC | Op.FDC
    | Op.FIC | Op.FDCE | Op.FICE ->
      let reg = getRegFromRange bin 11u 7u
      OneOperand (OpReg reg)
    | _ -> NoOperand
  struct (opcode, operands)

let parseFCPYInstruction bin wordSz =
  let rs = getRegFromRange bin 25u 21u
  let rd = getRegFromRange bin 4u 0u
  let fmt = extract bin 12u 11u
  let opcode =
    match fmt with
    | 0b01u -> Op.FCPYDBL
    | 0b00u -> Op.FCPYSGL
    | _ -> raise ParsingFailureException
  let operands = TwoOperands (OpReg rs, OpReg rd)
  struct (opcode, operands)

let parseSpecialFunctionInstruction bin wordSz =
  let opcode =
    match extract bin 10u 9u with
    | 0b00u -> Op.SPOP0
    | 0b01u -> Op.SPOP1
    | 0b10u -> Op.SPOP2
    | 0b11u -> Op.SPOP3
    | _ -> raise ParsingFailureException
  let operands = NoOperand
  struct (opcode, operands)

let parseImplementationDependentInstruction bin wordSz =
  let imm = extract bin 25u 0u |> uint64 |> OpImm
  match extract bin 31u 26u with
  | 0b000101u ->
    let opcode = Op.DIAG
    let operands = OneOperand (imm)
    struct (opcode, operands)
  | _ -> raise ParsingFailureException

let parseLongimmInstruction bin wordSz =
  match extract bin 31u 26u with
  | 0b001101u ->
    let opcode = Op.LDO
    let baseReg = getRegFromRange bin 25u 21u
    let destReg = getRegFromRange bin 20u 16u
    let offset = getImmediate bin 13u 0u wordSz
    let memAddr = OpMem (baseReg, Some (Imm (int64 offset)), wordSz)
    let operands = TwoOperands (OpReg destReg, memAddr)
    struct (opcode, operands)
  | 0b001000u ->
    let opcode = Op.LDIL
    let destReg = getRegFromRange bin 25u 21u
    let immi = extract bin 20u 0u |> uint64 |> OpImm
    let operands = TwoOperands (immi, OpReg destReg)
    struct (opcode, operands)
  | 0b001010u ->
    let opcode = Op.ADDIL
    let destReg = getRegFromRange bin 25u 21u
    let immi = extract bin 20u 0u |> uint64 |> OpImm
    let operands = ThreeOperands (immi, OpReg destReg, OpReg destReg)
    struct (opcode, operands)
  | _ -> raise ParsingFailureException

let parseCoprocessorandFLsInstruction bin wordSz =
  match extract bin 31u 26u with
  | 0b001100u ->
    let opcode = Op.COPR
    let reg = getRegFromRange bin 11u 7u
    let operands = OneOperand (OpReg reg)
    struct (opcode, operands)
  | 0b000010u ->
    let opcode = Op.CLDD
    let reg = getRegFromRange bin 11u 7u
    let operands = OneOperand (OpReg reg)
    struct (opcode, operands)
  | 0b000011u ->
    let opcode = Op.CLDW
    let reg = getRegFromRange bin 11u 7u
    let operands = OneOperand (OpReg reg)
    struct (opcode, operands)
  | 0b000100u ->
    let opcode = Op.CSTD
    let reg = getRegFromRange bin 11u 7u
    let operands = OneOperand (OpReg reg)
    struct (opcode, operands)
  | 0b000101u ->
    let opcode = Op.CSTW
    let reg = getRegFromRange bin 11u 7u
    let operands = OneOperand (OpReg reg)
    struct (opcode, operands)
  | _ -> raise ParsingFailureException

let private parseInstruction bin wordSz =
  let opc = extract bin 31u 26u
  match opc with
  | 0b000010u -> parseArithmeticInstruction bin wordSz
  | 0b101101u | 0b100101u -> parseImmediateArithmeticInstruction bin wordSz
  | 0b110100u | 0b110101u -> parseShiftExtractDepositInstruction bin wordSz
  | 0b111110u -> parseRearrangementInstruction bin wordSz
  | 0b000011u | 0b001011u -> parseLoadStoreShortInstruction bin wordSz
  | 0b001001u -> parseFLsAloneInstruction bin wordSz
  | 0b001101u | 0b001000u | 0b001010u -> parseLongimmInstruction bin wordSz
  | 0b010100u | 0b011100u | 0b010111u
  | 0b011111u | 0b010110u | 0b011110u -> parseLoadStoredwInstruction bin wordSz
  | 0b010000u | 0b010001u | 0b010010u
  | 0b010011u | 0b011000u | 0b011001u
  | 0b011010u | 0b011011u-> parseLoadStoreBWHAloneInstruction bin wordSz
  | 0b111010u -> parseBranchC3Instruction bin wordSz
  | 0b110010u | 0b110000u | 0b110001u
  | 0b100000u | 0b100010u | 0b100111u
  | 0b101111u | 0b101000u | 0b101010u -> parseBranchAlonesInstruction bin wordSz
  | 0b110011u | 0b100001u | 0b100011u
  | 0b111011u | 0b101001u
  | 0b101011u -> parseBranchImmediateInstruction bin wordSz
  | 0b000000u -> parseSpecialRegisterInstruction bin wordSz
  | 0b000001u -> parseMemoryManagementInstruction bin wordSz
  | 0b001100u -> parseFCPYInstruction bin wordSz
  | 0b000100u -> parseSpecialFunctionInstruction bin wordSz
  | 0b000101u -> parseImplementationDependentInstruction bin wordSz
  | _ -> raise ParsingFailureException

let parse (span: ByteSpan) (reader: IBinReader) wordSize addr =
  let bin = reader.ReadUInt32(span, 0)
  let wordSz = int wordSize
  let struct (op, operands) = parseInstruction bin wordSz
  let insInfo =
    { Address = addr
      NumBytes = 4u
      Opcode = op
      Operands = operands
      OperationSize = 32<rt> }
  PARISCInstruction (addr, 4u, insInfo)

// vim: set tw=80 sts=2 sw=2:
