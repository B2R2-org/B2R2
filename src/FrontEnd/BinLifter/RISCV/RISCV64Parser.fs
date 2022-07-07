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
  Op.LUI, getRdImm20 bin

let parseAUIPC bin = 
  Op.AUIPC, getPCRdImm20 bin 

let parseBranch bin = 
  let opcode = 
    match getFunc3 bin with
    | 0b000u -> Op.BEQ
    | 0b001u -> Op.BNE
    | 0b100u -> Op.BLT
    | 0b101u -> Op.BGE
    | 0b110u -> Op.BLTU
    | 0b111u -> Op.BGEU
    | _ -> failwith "invalid opcode"
  opcode, getPCBImm bin

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
    | _ -> failwith "invalid opcode"
  opcode, getRdRs1IImm bin

let parseStore bin = 
  let opcode =
    match getFunc3 bin with 
    | 0b000u -> Op.SB
    | 0b001u -> Op.SH
    | 0b010u -> Op.SW
    | 0b011u -> Op.SD
    | _ -> failwith "invalid opcode"
  opcode, getRs2Rs1SImm bin

let parseArithImmOper bin =
  let opcode =
    match getFunc3 bin with
    | 0b000u -> Op.ADDI
    | 0b010u -> Op.SLTI
    | 0b011u -> Op.SLTIU
    | 0b100u -> Op.XORI
    | 0b110u -> Op.ORI
    | 0b111u -> Op.ANDI
    /// Shifts
    | 0b001u -> Op.SLLI
    | 0b101u when pickBit bin 30u = 0u -> Op.SRLI
    | 0b101u when pickBit bin 30u = 1u -> Op.SRAI
    | _ -> failwith "invalid opcode"
  match opcode with
  | Op.ADDI | Op.SLTI | Op.SLTIU | Op.XORI 
  | Op.ORI | Op.ANDI -> opcode, getRdRs1IImm bin
  | _ -> opcode, getRdRs1Shamt bin

let parseArithOper bin = 
  let opcode =
    match getFunc3 bin with
    | 0b000u when pickBit bin 25u = 1u -> Op.MUL
    | 0b001u when pickBit bin 25u = 1u -> Op.MULH
    | 0b010u when pickBit bin 25u = 1u -> Op.MULHSU
    | 0b011u when pickBit bin 25u = 1u -> Op.MULHU
    | 0b101u when pickBit bin 25u = 1u -> Op.DIVU
    | 0b110u when pickBit bin 25u = 1u -> Op.REM
    | 0b111u when pickBit bin 25u = 1u -> Op.REMU
    | 0b000u when pickBit bin 30u = 0u -> Op.ADD
    | 0b000u when pickBit bin 30u = 1u -> Op.SUB
    | 0b001u -> Op.SLL
    | 0b010u -> Op.SLT
    | 0b011u -> Op.SLTU
    | 0b100u -> Op.XOR
    | 0b101u when pickBit bin 30u = 0u -> Op.SRL
    | 0b101u when pickBit bin 30u = 1u -> Op.SRA
    | 0b110u -> Op.OR
    | 0b111u -> Op.AND
    | _ -> failwith "invalid opcode"
  opcode, getRdRs1Rs2 bin

let parseEnvCall bin =
  let opcode= if pickBit bin 20u = 1u then Op.ECALL else Op.EBREAK
  opcode, NoOperand

let parseFence bin = 
  let opcode = if pickBit bin 12u = 0u then Op.FENCE else Op.FENCEdotI
  if opcode = Op.FENCEdotI then 
    opcode, NoOperand
  else 
    opcode, getPredSucc bin

let parseFloatArith bin = 
  match extract bin 31u 25u with
  | 0b0000000u -> Op.FADDdotS, getRdRs1Rs2Rm bin
  | 0b0000100u -> Op.FSUBdotS, getRdRs1Rs2Rm bin
  | 0b0001000u -> Op.FMULdotS, getRdRs1Rs2Rm bin
  | 0b0001100u -> Op.FDIVdotS, getRdRs1Rs2Rm bin
  | 0b0101100u when extract bin 24u 20u = 0u -> Op.FSQRTdotS, getRdRs1Rm bin
  | 0b0010000u when getFunc3 bin = 0b000u -> Op.FSGNJdotS, getRdRs1Rs2Rm bin
  | 0b0010000u when getFunc3 bin = 0b001u -> Op.FSGNJNdotS, getRdRs1Rs2 bin
  | 0b0010000u when getFunc3 bin = 0b010u -> Op.FSGNJXdotS, getRdRs1Rs2 bin
  | 0b0010100u when getFunc3 bin = 0b000u -> Op.FMINdotS, getRdRs1Rs2 bin
  | 0b0010100u when getFunc3 bin = 0b001u -> Op.FMAXdotS, getRdRs1Rs2 bin
  | 0b1100000u when getRs2 bin = 0b00000u -> Op.FCVTdotWdotS, getRdRs1Rm bin
  | 0b1100000u when getRs2 bin = 0b00001u -> Op.FCVTdotWUdotS, getRdRs1 bin
  | 0b1100000u when getRs2 bin = 0b00010u -> Op.FCVTdotLdotS, getRdRs1Rm bin
  | 0b1100000u when getRs2 bin = 0b00011u -> Op.FCVTdotLUdotS, getRdRs1Rm bin
  | 0b1110000u when getFunc3 bin = 0b000u && getRs2 bin = 0b00000u -> Op.FMVdotXdotW, getRdRs1 bin
  | 0b1110000u when getFunc3 bin = 0b001u && getRs2 bin = 0b00000u -> Op.FCLASSdotS, getRdRs1 bin
  | 0b1010000u when getFunc3 bin = 0b010u -> Op.FEQdotS, getRdRs1Rs2 bin
  | 0b1010000u when getFunc3 bin = 0b001u -> Op.FLTdotS, getRdRs1Rs2 bin
  | 0b1010000u when getFunc3 bin = 0b000u -> Op.FLEdotS, getRdRs1Rs2 bin
  | 0b1101000u when getRs2 bin = 0b00000u -> Op.FCVTdotSdotW, getRdRs1Rm bin
  | 0b1101000u when getRs2 bin = 0b00001u -> Op.FCVTdotSdotWU, getRdRs1Rm bin
  | 0b1101000u when getRs2 bin = 0b00010u -> Op.FCVTdotSdotL, getRdRs1Rm bin
  | 0b1101000u when getRs2 bin = 0b00011u -> Op.FCVTdotSdotLU, getRdRs1Rm bin
  | 0b1111000u when getRs2 bin = 0b00000u && getFunc3 bin = 0b000u -> Op.FMVdotWdotX, getRdRs1 bin
  | 0b0000001u -> Op.FADDdotD, getRdRs1Rs2Rm bin
  | 0b0000101u -> Op.FSUBdotD, getRdRs1Rs2Rm bin
  | 0b0001001u -> Op.FMULdotD, getRdRs1Rs2Rm bin
  | 0b0001101u -> Op.FDIVdotD, getRdRs1Rs2Rm bin
  | 0b0101101u when getRs2 bin = 0u -> Op.FSQRTdotD, getRdRs1Rm bin
  | 0b0010001u when getFunc3 bin = 0b000u -> Op.FSGNJdotD, getRdRs1Rs2 bin
  | 0b0010001u when getFunc3 bin = 0b001u -> Op.FSGNJNdotD, getRdRs1Rs2 bin
  | 0b0010001u when getFunc3 bin = 0b001u -> Op.FSGNJXdotD, getRdRs1Rs2 bin
  | 0b0010101u when getFunc3 bin = 0b000u -> Op.FMINdotD, getRdRs1Rs2 bin
  | 0b0010101u when getFunc3 bin = 0b001u -> Op.FMAXdotD, getRdRs1Rs2 bin
  | 0b0100000u when getRs2 bin = 0b00001u -> Op.FCVTdotSdotD, getRdRs1Rm bin
  | 0b0100001u when getRs2 bin = 0b00000u -> Op.FCVTdotDdotS, getRdRs1Rm bin
  | 0b1010001u when getFunc3 bin = 0b010u -> Op.FEQdotD, getRdRs1Rs2 bin
  | 0b1010001u when getFunc3 bin = 0b000u -> Op.FLTdotD, getRdRs1Rs2 bin
  | 0b1010001u when getFunc3 bin = 0b001u -> Op.FLEdotD, getRdRs1Rs2 bin
  | 0b1110001u when getRs2 bin = 0b00000u && getFunc3 bin = 0b001u -> Op.FCLASSdotD, getRdRs1 bin
  | 0b1110001u when getRs2 bin = 0b00000u && getFunc3 bin = 0b000u -> Op.FMVdotXdotD, getRdRs1 bin
  | 0b1100001u when getRs2 bin = 0b00000u -> Op.FCVTdotWdotD, getRdRs1 bin 
  | 0b1100001u when getRs2 bin = 0b00001u -> Op.FCVTdotWUdotD, getRdRs1 bin 
  | 0b1100001u when getRs2 bin = 0b00010u -> Op.FCVTdotLdotD, getRdRs1Rm bin
  | 0b1100001u when getRs2 bin = 0b00011u -> Op.FCVTdotLUdotD, getRdRs1Rm bin
  | 0b1101001u when getRs2 bin = 0b00000u -> Op.FCVTdotDdotW, getRdRs1Rm bin
  | 0b1101001u when getRs2 bin = 0b00001u -> Op.FCVTdotDdotWU, getRdRs1Rm bin
  | 0b1101001u when getRs2 bin = 0b00010u -> Op.FCVTdotDdotL, getRdRs1Rm bin
  | 0b1101001u when getRs2 bin = 0b00011u -> Op.FCVTdotDdotLU, getRdRs1Rm bin
  | 0b1111001u when getRs2 bin = 0b00000u && getFunc3 bin = 0b000u -> Op.FMVdotDdotX, getRdRs1 bin
  | _ -> failwith "invalid op"
    
    
let parseAtomic bin = 
  if extract bin 14u 12u = 0b010u then
    match extract bin 31u 27u with
    | 0b00010u -> Op.LRdotW, getRdRs1AqRlAcc bin 32<rt>
    | 0b00011u -> Op.SCdotW, getRdRs1Rs2AqRlAcc bin 32<rt>
    | 0b00001u -> Op.AMOSWAPdotW, getRdRs1Rs2AqRlAcc bin 32<rt>
    | 0b00000u -> Op.AMOADDdotW, getRdRs1Rs2AqRlAcc bin 32<rt>
    | 0b00100u -> Op.AMOXORdotW, getRdRs1Rs2AqRlAcc bin 32<rt>
    | 0b01100u -> Op.AMOANDdotW, getRdRs1Rs2AqRlAcc bin 32<rt>
    | 0b01000u -> Op.AMOORdotW, getRdRs1Rs2AqRlAcc bin 32<rt>
    | 0b10000u -> Op.AMOMINdotW, getRdRs1Rs2AqRlAcc bin 32<rt>
    | 0b10100u -> Op.AMOMAXdotW, getRdRs1Rs2AqRlAcc bin 32<rt>
    | 0b11000u -> Op.AMOMINUdotW, getRdRs1Rs2AqRlAcc bin 32<rt>
    | 0b11100u -> Op.AMOMAXUdotW, getRdRs1Rs2AqRlAcc bin 32<rt>
    | _ -> failwith "invalid opcode"
  elif extract bin 14u 12u = 0b011u then
    match extract bin 31u 27u with
    | 0b00010u -> Op.LRdotD, getRdRs1AqRlAcc bin 64<rt>
    | 0b00011u -> Op.SCdotD, getRdRs1Rs2AqRlAcc bin 64<rt>
    | 0b00001u -> Op.AMOSWAPdotD, getRdRs1Rs2AqRlAcc bin 64<rt>
    | 0b00000u -> Op.AMOADDdotD, getRdRs1Rs2AqRlAcc bin 64<rt>
    | 0b00100u -> Op.AMOXORdotD, getRdRs1Rs2AqRlAcc bin 64<rt>
    | 0b01100u -> Op.AMOANDdotD, getRdRs1Rs2AqRlAcc bin 64<rt>
    | 0b01000u -> Op.AMOORdotD, getRdRs1Rs2AqRlAcc bin 64<rt>
    | 0b10000u -> Op.AMOMINdotD, getRdRs1Rs2AqRlAcc bin 64<rt>
    | 0b10100u -> Op.AMOMAXdotD, getRdRs1Rs2AqRlAcc bin 64<rt>
    | 0b11000u -> Op.AMOMINUdotD, getRdRs1Rs2AqRlAcc bin 64<rt>
    | 0b11100u -> Op.AMOMAXUdotD, getRdRs1Rs2AqRlAcc bin 64<rt>
    | _ -> failwith "invalid opcode"
  else
    failwith "invalid opcode"

let parseJAL bin = Op.JAL, getRdJImm bin

let parseJALR bin = Op.JALR, getRdRs1JImm bin

let parseFused bin =
  if extract bin 26u 25u = 0b00u then
    match extract bin 6u 0u with
    | 0b1000011u -> Op.FMADDdotS, getRdRs1Rs2Rs3 bin
    | 0b1000111u -> Op.FMSUBdotS, getRdRs1Rs2Rs3 bin
    | 0b1001011u -> Op.FNMSUBdotS, getRdRs1Rs2Rs3 bin
    | 0b1001111u -> Op.FNMADDdotS, getRdRs1Rs2Rs3 bin
    | _ -> failwith "invalid opcode"
  elif extract bin 26u 25u = 0b01u then 
    match extract bin 6u 0u with
    | 0b1000011u -> Op.FMADDdotD, getRdRs1Rs2Rs3 bin
    | 0b1000111u -> Op.FMSUBdotD, getRdRs1Rs2Rs3 bin
    | 0b1001011u -> Op.FNMSUBdotD, getRdRs1Rs2Rs3 bin
    | 0b1001111u -> Op.FNMADDdotD, getRdRs1Rs2Rs3 bin
    | _ -> failwith "invalid opcode"
  else
    failwith "invalid opcode"  

let parseFloatLoad bin = 
  match extract bin 14u 12u with 
  | 0b011u -> Op.FLD, getRdRs1IImm bin
  | 0b010u -> Op.FLW, getRdRs1IImm bin
  | _ -> failwith "invalid"

let parseFloatStore bin =
  match extract bin 14u 12u with
  | 0b011u -> Op.FSD, getRs2Rs1SImm bin 
  | 0b010u -> Op.FSW, getRs2Rs1SImm bin
  | _ -> failwith "invalid"

let parseArithLow32Oper bin = 
  match extract bin 31u 25u with
  | 0b0000000u when getFunc3 bin = 0b000u -> Op.ADDW, getRdRs1Rs2 bin
  | 0b0100000u when getFunc3 bin = 0b000u -> Op.SUBW, getRdRs1Rs2 bin
  | 0b0000000u when getFunc3 bin = 0b001u -> Op.SLLW, getRdRs1Rs2 bin
  | 0b0000000u when getFunc3 bin = 0b101u -> Op.SRLW, getRdRs1Rs2 bin
  | 0b0100000u when getFunc3 bin = 0b101u -> Op.SRAW, getRdRs1Rs2 bin
  | 0b0000001u when getFunc3 bin = 0b000u -> Op.MULW, getRdRs1Rs2 bin
  | 0b0000001u when getFunc3 bin = 0b100u -> Op.DIVW, getRdRs1Rs2 bin
  | 0b0000001u when getFunc3 bin = 0b101u -> Op.DIVUW, getRdRs1Rs2 bin
  | 0b0000001u when getFunc3 bin = 0b110u -> Op.REMW, getRdRs1Rs2 bin
  | 0b0000001u when getFunc3 bin = 0b111u -> Op.REMUW, getRdRs1Rs2 bin
  | _ -> failwith "invalid opcode"

let parseArithImmLow32Oper bin = 
  match getFunc3 bin with
  | 0b000u -> Op.ADDIW, getRdRs1IImm bin
  | 0b001u -> Op.SLLIW, getRdRs1Shamt bin
  | 0b101u when extract bin 31u 25u = 0b0000000u -> Op.SRLIW, getRdRs1Shamt bin 
  | 0b101u when extract bin 31u 25u = 0b0100000u -> Op.SRAIW, getRdRs1Shamt bin 
  | _ -> failwith "invalid opcode"

let parseCSR bin = 
  match getFunc3 bin with
  | 0b001u -> Op.CSRRW, getRdRs1CSR bin 
  | 0b010u -> Op.CSRRS, getRdRs1CSR bin
  | 0b011u -> Op.CSRRC, getRdRs1CSR bin
  | 0b101u -> Op.CSRRWI, getRdUImmCSR bin
  | 0b110u -> Op.CSRRSI, getRdUImmCSR bin
  | 0b111u -> Op.CSRRCI, getRdUImmCSR bin
  | _ -> failwith "invalid opcode"

let private parseInstruction bin =
  match extract bin 6u 0u with
  | 0b0110111u -> parseLUI bin
  | 0b0010111u -> parseAUIPC bin
  | 0b1101111u -> parseJAL bin
  | 0b1100111u -> parseJALR bin
  | 0b1100011u -> parseBranch bin
  | 0b0000011u -> parseLoad bin
  | 0b0100011u -> parseStore bin
  | 0b0010011u -> parseArithImmOper bin
  | 0b0110011u -> parseArithOper bin
  | 0b0001111u -> parseFence bin
  | 0b1110011u when getFunc3 bin = 0u -> parseEnvCall bin
  | 0b1110011u -> parseCSR bin
  | 0b0011011u -> parseArithImmLow32Oper bin
  | 0b0111011u -> parseArithLow32Oper bin
  | 0b0101111u -> parseAtomic bin
  | 0b0000111u -> parseFloatLoad bin
  | 0b0100111u -> parseFloatStore bin
  | 0b1000011u -> parseFused bin
  | 0b1000111u -> parseFused bin
  | 0b1001011u -> parseFused bin
  | 0b1001111u -> parseFused bin
  | 0b1010011u -> parseFloatArith bin
  | _ -> raise ParsingFailureException

let parse (span: ByteSpan) (reader: IBinReader) addr =
  let bin = reader.ReadUInt32 (span, 0)
  let opcode, operands = parseInstruction bin
  let insInfo =
    { Address = addr
      NumBytes = 4u
      Opcode = opcode
      Operands = operands
      OperationSize = 32<rt> }
  RISCV64Instruction (addr, 4u, insInfo)

// vim: set tw=80 sts=2 sw=2:
