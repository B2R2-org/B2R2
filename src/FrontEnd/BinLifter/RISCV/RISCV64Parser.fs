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

module B2R2.FrontEnd.BinLifter.RISCV.Parser

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.BitData
open B2R2.FrontEnd.BinLifter.RISCV.Helper

let getRegister = function
  | _ -> raise ParsingFailureException

let parseLUI bin =
  struct (Op.LUI, getRdImm20 bin)

let parseAUIPC bin =
  struct (Op.AUIPC, getPCRdImm20 bin)

let parseBranch bin =
  let opcode =
    match getFunc3 bin with
    | 0b000u -> Op.BEQ
    | 0b001u -> Op.BNE
    | 0b100u -> Op.BLT
    | 0b101u -> Op.BGE
    | 0b110u -> Op.BLTU
    | 0b111u -> Op.BGEU
    | _ -> raise ParsingFailureException
  struct (opcode, getPCBImm bin)

let parseLoad bin =
  let opcode =
    match getFunc3 bin with
    | 0b000u -> Op.LB
    | 0b001u -> Op.LH
    | 0b010u -> Op.LW
    | 0b011u -> Op.LD
    | 0b100u -> Op.LBU
    | 0b110u -> Op.LWU
    | 0b101u -> Op.LHU
    | _ -> raise ParsingFailureException
  struct (opcode, getRdRs1IImm bin)

let parseStore bin =
  let opcode =
    match getFunc3 bin with
    | 0b000u -> Op.SB
    | 0b001u -> Op.SH
    | 0b010u -> Op.SW
    | 0b011u -> Op.SD
    | _ -> raise ParsingFailureException
  struct (opcode, getRs2Rs1SImm bin)

let parseOpImm bin =
  let opcode =
    match getFunc3 bin with
    | 0b000u -> Op.ADDI
    | 0b010u -> Op.SLTI
    | 0b011u -> Op.SLTIU
    | 0b100u -> Op.XORI
    | 0b110u -> Op.ORI
    | 0b111u -> Op.ANDI
    (* Shifts *)
    | 0b001u -> Op.SLLI
    | 0b101u ->
      if extract bin 31u 26u = 0b000000u then
        Op.SRLI
      elif extract bin 31u 26u = 0b010000u then
        Op.SRAI
      else
        raise ParsingFailureException
    | _ -> raise ParsingFailureException
  match opcode with
  | Op.ADDI | Op.SLTI | Op.SLTIU | Op.XORI
  | Op.ORI | Op.ANDI -> struct (opcode, getRdRs1IImm bin)
  | _ -> struct (opcode, getRdRs1Shamt bin)

let parseOp bin =
  let opcode =
    match getFunc3 bin with
    | 0b000u ->
      match getFunc7 bin with
      | 0b0000001u -> Op.MUL
      | 0b0000000u -> Op.ADD
      | 0b0100000u -> Op.SUB
      | _ -> raise ParsingFailureException
    | 0b001u ->
      match getFunc7 bin with
      | 0b0000001u -> Op.MULH
      | 0b0000000u -> Op.SLL
      | _ -> raise ParsingFailureException
    | 0b010u ->
      match getFunc7 bin with
      | 0b0000001u -> Op.MULHSU
      | 0b0000000u -> Op.SLT
      | _ -> raise ParsingFailureException
    | 0b011u ->
      match getFunc7 bin with
      | 0b0000001u -> Op.MULHU
      | 0b0000000u -> Op.SLTU
      | _ -> raise ParsingFailureException
    | 0b101u ->
      match getFunc7 bin with
      | 0b0000001u -> Op.DIVU
      | 0b0000000u -> Op.SRL
      | 0b0100000u -> Op.SRA
      | _ -> raise ParsingFailureException
    | 0b110u ->
      match getFunc7 bin with
      | 0b0000001u -> Op.REM
      | 0b0000000u -> Op.OR
      | _ -> raise ParsingFailureException
    | 0b111u ->
      match getFunc7 bin with
      | 0b0000001u -> Op.REMU
      | 0b0000000u -> Op.AND
      | _ -> raise ParsingFailureException
    | 0b100u ->
      if getFunc7 bin = 0b0000000u then Op.XOR
      else raise ParsingFailureException
    | _ -> raise ParsingFailureException
  struct (opcode, getRdRs1Rs2 bin)

let parseEnvCall bin =
  let opcode= if pickBit bin 20u = 1u then Op.ECALL else Op.EBREAK
  struct (opcode, NoOperand)

let parseFence bin =
  let opcode = if pickBit bin 12u = 0u then Op.FENCE else Op.FENCEdotI
  if opcode = Op.FENCEdotI then
    struct (opcode, NoOperand)
  else
    struct (opcode, getPredSucc bin)

let parseFloatArith bin =
  match extract bin 31u 25u with
  | 0b0000000u -> struct (Op.FADDdotS, getRdRs1Rs2Rm bin)
  | 0b0000100u -> struct (Op.FSUBdotS, getRdRs1Rs2Rm bin)
  | 0b0001000u -> struct (Op.FMULdotS, getRdRs1Rs2Rm bin)
  | 0b0001100u -> struct (Op.FDIVdotS, getRdRs1Rs2Rm bin)
  | 0b0101100u ->
    if extract bin 24u 20u = 0u then struct (Op.FSQRTdotS, getRdRs1Rm bin)
    else raise ParsingFailureException
  | 0b0010000u ->
    match getFunc3 bin with
    | 0b000u -> struct (Op.FSGNJdotS, getRdRs1Rs2Rm bin)
    | 0b001u -> struct (Op.FSGNJNdotS, getRdRs1Rs2 bin)
    | 0b010u -> struct (Op.FSGNJXdotS, getRdRs1Rs2 bin)
    | _ -> raise ParsingFailureException
  | 0b0010100u ->
    match getFunc3 bin with
    | 0b000u -> struct (Op.FMINdotS, getRdRs1Rs2 bin)
    | 0b001u -> struct (Op.FMAXdotS, getRdRs1Rs2 bin)
    | _ -> raise ParsingFailureException
  | 0b1100000u ->
    match getRs2 bin with
    | 0b00000u -> struct (Op.FCVTdotWdotS, getRdRs1Rm bin)
    | 0b00001u -> struct (Op.FCVTdotWUdotS, getRdRs1 bin)
    | 0b00010u -> struct (Op.FCVTdotLdotS, getRdRs1Rm bin)
    | 0b00011u -> struct (Op.FCVTdotLUdotS, getRdRs1Rm bin)
    | _ -> raise ParsingFailureException
  | 0b1110000u ->
    if getFunc3 bin = 0b000u && getRs2 bin = 0b00000u then
      struct (Op.FMVdotXdotW, getRdRs1 bin)
    elif getFunc3 bin = 0b001u && getRs2 bin = 0b00000u then
      struct (Op.FCLASSdotS, getRdRs1 bin)
    else
      raise ParsingFailureException
  | 0b1010000u ->
    match getFunc3 bin with
    | 0b010u -> struct (Op.FEQdotS, getRdRs1Rs2 bin)
    | 0b001u -> struct (Op.FLTdotS, getRdRs1Rs2 bin)
    | 0b000u -> struct (Op.FLEdotS, getRdRs1Rs2 bin)
    | _ -> raise ParsingFailureException
  | 0b1101000u ->
    match getRs2 bin with
    | 0b00000u -> struct (Op.FCVTdotSdotW, getRdRs1Rm bin)
    | 0b00001u -> struct (Op.FCVTdotSdotWU, getRdRs1Rm bin)
    | 0b00010u -> struct (Op.FCVTdotSdotL, getRdRs1Rm bin)
    | 0b00011u -> struct (Op.FCVTdotSdotLU, getRdRs1Rm bin)
    | _ -> raise ParsingFailureException
  | 0b1111000u ->
    if getRs2 bin = 0b00000u && getFunc3 bin = 0b000u then
      struct (Op.FMVdotWdotX, getRdRs1 bin)
    else
      raise ParsingFailureException
  | 0b0000001u -> struct (Op.FADDdotD, getRdRs1Rs2Rm bin)
  | 0b0000101u -> struct (Op.FSUBdotD, getRdRs1Rs2Rm bin)
  | 0b0001001u -> struct (Op.FMULdotD, getRdRs1Rs2Rm bin)
  | 0b0001101u -> struct (Op.FDIVdotD, getRdRs1Rs2Rm bin)
  | 0b0101101u ->
    if getRs2 bin = 0u then struct (Op.FSQRTdotD, getRdRs1Rm bin)
    else raise ParsingFailureException
  | 0b0010001u ->
    match getFunc3 bin with
    | 0b000u -> struct (Op.FSGNJdotD, getRdRs1Rs2 bin)
    | 0b001u -> struct (Op.FSGNJNdotD, getRdRs1Rs2 bin)
    | 0b010u -> struct (Op.FSGNJXdotD, getRdRs1Rs2 bin)
    | _ -> raise ParsingFailureException
  | 0b0010101u ->
    if getFunc3 bin = 0b000u then struct (Op.FMINdotD, getRdRs1Rs2 bin)
    elif getFunc3 bin = 0b001u then struct (Op.FMAXdotD, getRdRs1Rs2 bin)
    else raise ParsingFailureException
  | 0b0100000u ->
    if getRs2 bin = 0b00001u then struct (Op.FCVTdotSdotD, getRdRs1Rm bin)
    else raise ParsingFailureException
  | 0b0100001u ->
    if getRs2 bin = 0b00000u then struct (Op.FCVTdotDdotS, getRdRs1Rm bin)
    else raise ParsingFailureException
  | 0b1010001u ->
    match getFunc3 bin with
    | 0b010u -> struct (Op.FEQdotD, getRdRs1Rs2 bin)
    | 0b000u -> struct (Op.FLTdotD, getRdRs1Rs2 bin)
    | 0b001u -> struct (Op.FLEdotD, getRdRs1Rs2 bin)
    | _ -> raise ParsingFailureException
  | 0b1110001u ->
    if getRs2 bin = 0b00000u && getFunc3 bin = 0b001u then
      struct (Op.FCLASSdotD, getRdRs1 bin)
    elif getRs2 bin = 0b00000u && getFunc3 bin = 0b000u then
      struct (Op.FMVdotXdotD, getRdRs1 bin)
    else
      raise ParsingFailureException
  | 0b1100001u ->
    match getRs2 bin with
    | 0b00000u -> struct (Op.FCVTdotWdotD, getRdRs1 bin)
    | 0b00001u -> struct (Op.FCVTdotWUdotD, getRdRs1 bin)
    | 0b00010u -> struct (Op.FCVTdotLdotD, getRdRs1Rm bin)
    | 0b00011u -> struct (Op.FCVTdotLUdotD, getRdRs1Rm bin)
    | _ -> raise ParsingFailureException
  | 0b1101001u ->
    match getRs2 bin with
    | 0b00000u -> struct (Op.FCVTdotDdotW, getRdRs1Rm bin)
    | 0b00001u -> struct (Op.FCVTdotDdotWU, getRdRs1Rm bin)
    | 0b00010u -> struct (Op.FCVTdotDdotL, getRdRs1Rm bin)
    | 0b00011u -> struct (Op.FCVTdotDdotLU, getRdRs1Rm bin)
    | _ -> raise ParsingFailureException
  | 0b1111001u ->
    if getRs2 bin = 0b00000u && getFunc3 bin = 0b000u then
      struct (Op.FMVdotDdotX, getRdRs1 bin)
    else
      raise ParsingFailureException
  | _ -> raise ParsingFailureException

let parseAtomic bin =
  if extract bin 14u 12u = 0b010u then
    match extract bin 31u 27u with
    | 0b00010u -> struct (Op.LRdotW, getRdRs1AqRlAcc bin 32<rt>)
    | 0b00011u -> struct (Op.SCdotW, getRdRs1Rs2AqRlAcc bin 32<rt>)
    | 0b00001u -> struct (Op.AMOSWAPdotW, getRdRs1Rs2AqRlAcc bin 32<rt>)
    | 0b00000u -> struct (Op.AMOADDdotW, getRdRs1Rs2AqRlAcc bin 32<rt>)
    | 0b00100u -> struct (Op.AMOXORdotW, getRdRs1Rs2AqRlAcc bin 32<rt>)
    | 0b01100u -> struct (Op.AMOANDdotW, getRdRs1Rs2AqRlAcc bin 32<rt>)
    | 0b01000u -> struct (Op.AMOORdotW, getRdRs1Rs2AqRlAcc bin 32<rt>)
    | 0b10000u -> struct (Op.AMOMINdotW, getRdRs1Rs2AqRlAcc bin 32<rt>)
    | 0b10100u -> struct (Op.AMOMAXdotW, getRdRs1Rs2AqRlAcc bin 32<rt>)
    | 0b11000u -> struct (Op.AMOMINUdotW, getRdRs1Rs2AqRlAcc bin 32<rt>)
    | 0b11100u -> struct (Op.AMOMAXUdotW, getRdRs1Rs2AqRlAcc bin 32<rt>)
    | _ -> raise ParsingFailureException
  elif extract bin 14u 12u = 0b011u then
    match extract bin 31u 27u with
    | 0b00010u -> struct (Op.LRdotD, getRdRs1AqRlAcc bin 64<rt>)
    | 0b00011u -> struct (Op.SCdotD, getRdRs1Rs2AqRlAcc bin 64<rt>)
    | 0b00001u -> struct (Op.AMOSWAPdotD, getRdRs1Rs2AqRlAcc bin 64<rt>)
    | 0b00000u -> struct (Op.AMOADDdotD, getRdRs1Rs2AqRlAcc bin 64<rt>)
    | 0b00100u -> struct (Op.AMOXORdotD, getRdRs1Rs2AqRlAcc bin 64<rt>)
    | 0b01100u -> struct (Op.AMOANDdotD, getRdRs1Rs2AqRlAcc bin 64<rt>)
    | 0b01000u -> struct (Op.AMOORdotD, getRdRs1Rs2AqRlAcc bin 64<rt>)
    | 0b10000u -> struct (Op.AMOMINdotD, getRdRs1Rs2AqRlAcc bin 64<rt>)
    | 0b10100u -> struct (Op.AMOMAXdotD, getRdRs1Rs2AqRlAcc bin 64<rt>)
    | 0b11000u -> struct (Op.AMOMINUdotD, getRdRs1Rs2AqRlAcc bin 64<rt>)
    | 0b11100u -> struct (Op.AMOMAXUdotD, getRdRs1Rs2AqRlAcc bin 64<rt>)
    | _ -> raise ParsingFailureException
  else
    raise ParsingFailureException

let parseJAL bin = struct (Op.JAL, getRdJImm bin)

let parseJALR bin = struct (Op.JALR, getRdRs1JImm bin)

let parseFused bin =
  if extract bin 26u 25u = 0b00u then
    match extract bin 6u 0u with
    | 0b1000011u -> struct (Op.FMADDdotS, getRdRs1Rs2Rs3 bin)
    | 0b1000111u -> struct (Op.FMSUBdotS, getRdRs1Rs2Rs3 bin)
    | 0b1001011u -> struct (Op.FNMSUBdotS, getRdRs1Rs2Rs3 bin)
    | 0b1001111u -> struct (Op.FNMADDdotS, getRdRs1Rs2Rs3 bin)
    | _ -> raise ParsingFailureException
  elif extract bin 26u 25u = 0b01u then
    match extract bin 6u 0u with
    | 0b1000011u -> struct (Op.FMADDdotD, getRdRs1Rs2Rs3 bin)
    | 0b1000111u -> struct (Op.FMSUBdotD, getRdRs1Rs2Rs3 bin)
    | 0b1001011u -> struct (Op.FNMSUBdotD, getRdRs1Rs2Rs3 bin)
    | 0b1001111u -> struct (Op.FNMADDdotD, getRdRs1Rs2Rs3 bin)
    | _ -> raise ParsingFailureException
  else
    raise ParsingFailureException

let parseFloatLoad bin =
  match extract bin 14u 12u with
  | 0b011u -> struct (Op.FLD, getRdRs1IImm bin)
  | 0b010u -> struct (Op.FLW, getRdRs1IImm bin)
  | _ -> raise ParsingFailureException

let parseFloatStore bin =
  match extract bin 14u 12u with
  | 0b011u -> struct (Op.FSD, getRs2Rs1SImm bin)
  | 0b010u -> struct (Op.FSW, getRs2Rs1SImm bin)
  | _ -> raise ParsingFailureException

let parseOp32 bin =
  match extract bin 31u 25u with
  | 0b0000000u ->
    match getFunc3 bin with
    | 0b000u -> struct (Op.ADDW, getRdRs1Rs2 bin)
    | 0b001u -> struct (Op.SLLW, getRdRs1Rs2 bin)
    | 0b101u -> struct (Op.SRLW, getRdRs1Rs2 bin)
    | _ -> raise ParsingFailureException
  | 0b0100000u ->
    if getFunc3 bin = 0b000u then struct (Op.SUBW, getRdRs1Rs2 bin)
    elif getFunc3 bin = 0b101u then struct (Op.SRAW, getRdRs1Rs2 bin)
    else raise ParsingFailureException
  | 0b0000001u ->
    match getFunc3 bin with
    | 0b000u -> struct (Op.MULW, getRdRs1Rs2 bin)
    | 0b100u -> struct (Op.DIVW, getRdRs1Rs2 bin)
    | 0b101u -> struct (Op.DIVUW, getRdRs1Rs2 bin)
    | 0b110u -> struct (Op.REMW, getRdRs1Rs2 bin)
    | 0b111u -> struct (Op.REMUW, getRdRs1Rs2 bin)
    | _ -> raise ParsingFailureException
  | _ -> raise ParsingFailureException

let parseOpImm32 bin =
  match getFunc3 bin with
  | 0b000u -> struct (Op.ADDIW, getRdRs1IImm bin)
  | 0b001u -> struct (Op.SLLIW, getRdRs1Shamt bin)
  | 0b101u ->
    if extract bin 31u 25u = 0b0000000u then
      struct (Op.SRLIW, getRdRs1Shamt bin)
    elif extract bin 31u 25u = 0b0100000u then
      struct (Op.SRAIW, getRdRs1Shamt bin)
    else
      raise ParsingFailureException
  | _ -> raise ParsingFailureException

let parseCSR bin =
  match getFunc3 bin with
  | 0b001u -> struct (Op.CSRRW, getRdRs1CSR bin)
  | 0b010u -> struct (Op.CSRRS, getRdRs1CSR bin)
  | 0b011u -> struct (Op.CSRRC, getRdRs1CSR bin)
  | 0b101u -> struct (Op.CSRRWI, getRdUImmCSR bin)
  | 0b110u -> struct (Op.CSRRSI, getRdUImmCSR bin)
  | 0b111u -> struct (Op.CSRRCI, getRdUImmCSR bin)
  | _ -> raise ParsingFailureException

let private parseInstruction bin =
  match extract bin 6u 0u with
  | 0b0110111u -> parseLUI bin
  | 0b0010111u -> parseAUIPC bin
  | 0b1101111u -> parseJAL bin
  | 0b1100111u -> parseJALR bin
  | 0b1100011u -> parseBranch bin
  | 0b0000011u -> parseLoad bin
  | 0b0100011u -> parseStore bin
  | 0b0010011u -> parseOpImm bin
  | 0b0110011u -> parseOp bin
  | 0b0001111u -> parseFence bin
  | 0b1110011u ->
    if getFunc3 bin = 0u then parseEnvCall bin
    else parseCSR bin
  | 0b0011011u -> parseOpImm32 bin
  | 0b0111011u -> parseOp32 bin
  | 0b0101111u -> parseAtomic bin
  | 0b0000111u -> parseFloatLoad bin
  | 0b0100111u -> parseFloatStore bin
  | 0b1000011u
  | 0b1000111u
  | 0b1001011u
  | 0b1001111u -> parseFused bin
  | 0b1010011u -> parseFloatArith bin
  | _ -> raise ParsingFailureException

let parse (span: ByteSpan) (reader: IBinReader) addr =
  let bin = reader.ReadUInt32 (span, 0)
  let struct (opcode, operands) = parseInstruction bin
  let insInfo =
    { Address = addr
      NumBytes = 4u
      Opcode = opcode
      Operands = operands
      OperationSize = 32<rt> }
  RISCV64Instruction (addr, 4u, insInfo)

// vim: set tw=80 sts=2 sw=2:
