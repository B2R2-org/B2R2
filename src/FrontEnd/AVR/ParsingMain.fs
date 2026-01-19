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

module internal B2R2.FrontEnd.AVR.ParsingMain

open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.AVR.OperandHelper
open type Register

let isTwoBytes b1 =
  let b32 = b1 |> uint32
  match concat (b32 >>> 9) (b32 &&& 0b1111u) 4 with
  | 0b10010101110u | 0b1001010111u -> false
  | 0b10010101100u | 0b10010101101u -> false
  | 0b10010000000u -> false
  | 0b10010010000u -> false
  | _ -> true

/// 1001 000- ---- ----
let parse1001000 b32 =
  match b32 &&& 0b1111u with
  | 0b1100u  | 0b1101u | 0b1110u | 0b1001u | 0b1010u | 0b0001u | 0b0010u ->
    Opcode.LD, parseTwoOpr b32 getRegD getMemLDD
  | 0b1111u -> Opcode.POP, parseOneOpr b32 getRegD
  | 0b0101u | 0b0100u -> Opcode.LPM, parseTwoOpr b32 getRegD getMemLDD
  | 0b0110u | 0b0111u -> Opcode.ELPM, parseTwoOpr b32 getRegD getMemLDD
  | _ -> Opcode.InvalidOp, NoOperand

/// 1001 001- ---- ----
let parse1001001 b32 =
  match b32 &&& 0b1111u with
  | 0b1100u | 0b1101u | 0b1110u | 0b1001u | 0b1010u | 0b0001u | 0b0010u ->
    Opcode.ST, parseTwoOpr b32 getMemST getRegD
  | 0b1111u -> Opcode.PUSH, parseOneOpr b32 getRegD
  | 0b0110u -> Opcode.LAC, TwoOperands(OprReg Z, getRegD b32)
  | 0b0101u -> Opcode.LAS, TwoOperands(OprReg Z, getRegD b32)
  | 0b0111u -> Opcode.LAT, TwoOperands(OprReg Z, getRegD b32)
  | 0b0100u -> Opcode.XCH, TwoOperands(OprReg Z, getRegD b32)
  | _ -> Opcode.InvalidOp, NoOperand

/// 0000 00-- ---- ----
let parse000000 b32 =
  match extract b32 9u 8u with
  | 0b01u -> Opcode.MOVW, parseTwoOpr b32 getRegEven4D getRegEvenEnd4D
  | 0b10u -> Opcode.MULS, parseTwoOpr b32 getRegEven4D getRegEvenEnd4D
  | 0b11u ->
    match concat (pickBit b32 7u) (pickBit b32 3u) 1 with
    | 0b01u -> Opcode.FMUL, parseTwoOpr b32 getReg3D getReg3DLast
    | 0b10u -> Opcode.FMULS, parseTwoOpr b32 getReg3D getReg3DLast
    | 0b11u -> Opcode.FMULSU, parseTwoOpr b32 getReg3D getReg3DLast
    | 0b00u -> Opcode.MULSU, parseTwoOpr b32 getReg3D getReg3DLast
    | _ -> Opcode.InvalidOp, NoOperand
  | 0b0u when b32 = 0u -> Opcode.NOP, NoOperand
  | _ -> Opcode.InvalidOp, NoOperand

/// 1001 010- ---- 1000 with no operands
let parseNoOp1000 b32 =
  match extract b32 8u 4u with
  | 0b11001u -> Opcode.BREAK, NoOperand
  | 0b01000u -> Opcode.CLC, NoOperand
  | 0b01101u -> Opcode.CLH, NoOperand
  | 0b01111u -> Opcode.CLI, NoOperand
  | 0b01010u -> Opcode.CLN, NoOperand
  | 0b01100u -> Opcode.CLS, NoOperand
  | 0b01110u -> Opcode.CLT, NoOperand
  | 0b01011u -> Opcode.CLV, NoOperand
  | 0b01001u -> Opcode.CLZ, NoOperand
  | 0b10000u -> Opcode.RET, NoOperand
  | 0b10001u -> Opcode.RETI, NoOperand
  | 0b00000u -> Opcode.SEC, NoOperand
  | 0b00101u -> Opcode.SEH, NoOperand
  | 0b00111u -> Opcode.SEI, NoOperand
  | 0b00010u -> Opcode.SEN, NoOperand
  | 0b00100u -> Opcode.SES, NoOperand
  | 0b00110u -> Opcode.SET, NoOperand
  | 0b00011u -> Opcode.SEV, NoOperand
  | 0b00001u -> Opcode.SEZ, NoOperand
  | 0b11000u -> Opcode.SLEEP, NoOperand
  | 0b11110u -> Opcode.SPM, NoOperand
  | 0b11010u -> Opcode.WDR, NoOperand
  | 0b11100u -> Opcode.LPM, NoOperand
  | 0b11101u -> Opcode.ELPM, NoOperand
  | _ -> Opcode.InvalidOp, NoOperand

/// 1001 010- ---- 1001 with no operands
let parseNoOp1001 b32 =
  match extract b32 8u 4u with
  | 0b10001u -> Opcode.EICALL, NoOperand
  | 0b00001u -> Opcode.EIJMP, NoOperand
  | 0b10000u -> Opcode.ICALL, NoOperand
  | 0b00000u -> Opcode.IJMP, NoOperand
  | _ -> Opcode.InvalidOp, NoOperand

/// 1001 010- ---- ----
let parse1001010 b32 =
  match b32 >>> 9 with
  | 0b1001010u ->
    match b32 &&& 0b1111u with
    | 0b0101u -> Opcode.ASR, parseOneOpr b32 getRegD
    | 0b0000u -> Opcode.COM, parseOneOpr b32 getRegD
    | 0b1010u -> Opcode.DEC, parseOneOpr b32 getRegD
    | 0b0011u -> Opcode.INC, parseOneOpr b32 getRegD
    | 0b0110u -> Opcode.LSR, parseOneOpr b32 getRegD
    | 0b0001u -> Opcode.NEG, parseOneOpr b32 getRegD
    | 0b0111u -> Opcode.ROR, parseOneOpr b32 getRegD
    | 0b0010u -> Opcode.SWAP, parseOneOpr b32 getRegD
    | 0b1011u when pickBit b32 8u = 0b0u ->
      Opcode.DES, parseOneOpr b32 getConst4K
    (* | 0b1000u when extract b32 8u 7u = 0b01u ->
      Opcode.BCLR, parseOneOpr b32 getConst3bs
    | 0b1000u when extract b32 8u 7u = 0b00u ->
      Opcode.BSET, parseOneOpr b32 getConst3bs *)
    | 0b1000u -> parseNoOp1000 b32
    | 0b1001u -> parseNoOp1001 b32
    | _ -> Opcode.InvalidOp, NoOperand
  | _ -> Opcode.InvalidOp, NoOperand

/// 1111 1--d dddd 0bbb
let parse11111 b32 =
  match concat (extract b32 10u 9u) (pickBit b32 3u) 1 with
  | 0b000u -> Opcode.BLD, parseTwoOpr b32 getRegD getConst3b
  | 0b010u -> Opcode.BST, parseTwoOpr b32 getRegD getConst3b
  | 0b100u -> Opcode.SBRC, parseTwoOpr b32 getRegD getConst3b
  | 0b110u -> Opcode.SBRS, parseTwoOpr b32 getRegD getConst3b
  | _ -> Opcode.InvalidOp, NoOperand

/// 1111 0- kk kkkk k---
let parse11110 b32 =
  match pickBit b32 10u with
  | 0b0u ->
    match b32 &&& 0b111u with
    | 0b000u -> Opcode.BRCS, parseOneOpr b32 getAddr7K
    | 0b001u -> Opcode.BREQ, parseOneOpr b32 getAddr7K
    | 0b101u -> Opcode.BRHS, parseOneOpr b32 getAddr7K
    | 0b111u -> Opcode.BRIE, parseOneOpr b32 getAddr7K
    (* | 0b000u -> Opcode.BRLO, parseOneOpr b getAddr7K *)
    | 0b100u -> Opcode.BRLT, parseOneOpr b32 getAddr7K
    | 0b010u -> Opcode.BRMI, parseOneOpr b32 getAddr7K
    | 0b110u -> Opcode.BRTS, parseOneOpr b32 getAddr7K
    | 0b011u -> Opcode.BRVS, parseOneOpr b32 getAddr7K
    | _ -> Opcode.InvalidOp, NoOperand
  | 0b1u ->
    match b32 &&& 0b111u with
    | 0b000u -> Opcode.BRCC, parseOneOpr b32 getAddr7K
    | 0b001u -> Opcode.BRNE, parseOneOpr b32 getAddr7K
    | 0b101u -> Opcode.BRHC, parseOneOpr b32 getAddr7K
    | 0b111u -> Opcode.BRID, parseOneOpr b32 getAddr7K
    (* | 0b000u -> Opcode.BRSH, parseOneOpr b getAddr7K *)
    | 0b100u -> Opcode.BRGE, parseOneOpr b32 getAddr7K
    | 0b010u -> Opcode.BRPL, parseOneOpr b32 getAddr7K
    | 0b110u -> Opcode.BRTC, parseOneOpr b32 getAddr7K
    | 0b011u -> Opcode.BRVC, parseOneOpr b32 getAddr7K
    | _ -> Opcode.InvalidOp, NoOperand
  | _ -> Opcode.InvalidOp, NoOperand

let parse1111 b32 =
  match pickBit b32 11u with
  | 0b0u -> parse11110 b32
  | 0b1u -> parse11111 b32
  | _ -> Opcode.InvalidOp, NoOperand

let parse1001 b32 =
  match extract b32 11u 8u with
  | 0b0100u | 0b0101u -> parse1001010 b32
  | 0b0010u | 0b0011u -> parse1001001 b32
  | 0b0000u | 0b0001u -> parse1001000 b32
  | 0b0110u -> Opcode.ADIW, parseTwoOpr b32 getReg2D getConst6K
  | 0b1000u -> Opcode.CBI, parseTwoOpr b32 getIO5 getConst3b
  | 0b1010u -> Opcode.SBI, parseTwoOpr b32 getIO5 getConst3b
  | 0b1001u -> Opcode.SBIC, parseTwoOpr b32 getIO5 getConst3b
  | 0b1011u -> Opcode.SBIS, parseTwoOpr b32 getIO5 getConst3b
  | 0b0111u -> Opcode.SBIW, parseTwoOpr b32 getReg2D getConst6K
  | op when op &&& 0b1100u = 0b1100u ->
    Opcode.MUL, parseTwoOpr b32 getRegD getRegR
  | _ -> Opcode.InvalidOp, NoOperand

let parse1000 b32 =
  let isDispZero = getDisp b32 = 0
  match concat (pickBit b32 9u)(pickBit b32 3u) 1 with
  | 0b11u ->
    if isDispZero then Opcode.ST, parseTwoOpr b32 getMemST getRegD
    else Opcode.STD, parseTwoOpr b32 getMemDispY getRegD
  | 0b10u ->
    if isDispZero then Opcode.ST, parseTwoOpr b32 getMemST getRegD
    else Opcode.STD, parseTwoOpr b32 getMemDispZ getRegD
  | 0b01u ->
    if isDispZero then Opcode.LD, parseTwoOpr b32 getRegD getMemLDD
    else Opcode.LDD, parseTwoOpr b32 getRegD getMemDispY
  | 0b00u ->
    if isDispZero then Opcode.LD, parseTwoOpr b32 getRegD getMemLDD
    else Opcode.LDD, parseTwoOpr b32 getRegD getMemDispZ
  | _ -> Opcode.InvalidOp, NoOperand

let parse1010 b32 =
  match concat (pickBit b32 9u)(pickBit b32 3u) 1 with
  | 0b00u -> Opcode.LDD, parseTwoOpr b32 getRegD getMemDispZ
  | 0b01u -> Opcode.LDD, parseTwoOpr b32 getRegD getMemDispY
  | 0b10u -> Opcode.STD, parseTwoOpr b32 getMemDispZ getRegD
  | 0b11u -> Opcode.STD, parseTwoOpr b32 getMemDispY getRegD
  | _ -> Opcode.InvalidOp, NoOperand

/// Parse the instruction using only the first 6 bits
let parseSixBits b32 =
  match b32 >>> 10 with
  | 0b000111u -> Opcode.ADC, parseTwoOpr b32 getRegD getRegR
  | 0b000011u -> Opcode.ADD, parseTwoOpr b32 getRegD getRegR
  | 0b001000u -> Opcode.AND, parseTwoOpr b32 getRegD getRegR
  (* | 0b111101u -> Opcode.BRBC
     | 0b111100u -> Opcode.BRBS
     | 0b001001u -> Opcode.CLR // Same with EOR *)
  | 0b000101u -> Opcode.CP, parseTwoOpr b32 getRegD getRegR
  | 0b000001u -> Opcode.CPC, parseTwoOpr b32 getRegD getRegR
  | 0b000100u -> Opcode.CPSE, parseTwoOpr b32 getRegD getRegR
  | 0b001001u -> Opcode.EOR, parseTwoOpr b32 getRegD getRegR
  (* | 0b000011u -> Opcode.LSL // Logical shift left *)
  | 0b001011u -> Opcode.MOV, parseTwoOpr b32 getRegD getRegR
  | 0b000110u -> Opcode.SUB, parseTwoOpr b32 getRegD getRegR
  | 0b100111u -> Opcode.MUL, parseTwoOpr b32 getRegD getRegR
  | 0b001010u -> Opcode.OR, parseTwoOpr b32 getRegD getRegR
  (* | 0b000111u -> Opcode.ROL // Rotate Left through Carry *)
  | 0b000010u -> Opcode.SBC, parseTwoOpr b32 getRegD getRegR
  (* | 0b001000u -> Opcode.TST *)
  | _ -> Opcode.InvalidOp, NoOperand

/// Parse the instruction using only the first 4 bits
let parseFourBits b32 =
  match b32 >>> 12 with
  | 0b0111u -> Opcode.ANDI, parseTwoOpr b32 getReg4D getConst8K
  | 0b0011u -> Opcode.CPI, parseTwoOpr b32 getReg4D getConst8K
  | 0b1110u -> Opcode.LDI, parseTwoOpr b32 getReg4D getConst8K
  | 0b0110u -> Opcode.ORI, parseTwoOpr b32 getReg4D getConst8K
  | 0b1101u -> Opcode.RCALL, parseOneOpr b32 getAddr12
  | 0b1100u -> Opcode.RJMP, parseOneOpr b32 getAddr12
  | 0b0100u -> Opcode.SBCI, parseTwoOpr b32 getReg4D getConst8K
  (* | 0x0110u -> Opcode.SBR, parseTwoOpr b32 getReg4D getConst8K *)
  | 0b0101u -> Opcode.SUBI, parseTwoOpr b32 getReg4D getConst8K
  | 0b1011u when (pickBit b32 11u) = 0b0u ->
    Opcode.IN, parseTwoOpr b32 getRegD getIO6
  | 0b1011u when (pickBit b32 11u) = 0b1u ->
    Opcode.OUT, parseTwoOpr b32 getIO6 getRegD
  | _ -> parseSixBits b32

let parseTwoBytes bin =
  match bin >>> 12 with
  | 0b0000u when extract bin 11u 10u = 0b0u -> parse000000 bin
  | 0b1001u -> parse1001 bin
  | 0b1111u -> parse1111 bin
  | 0b1000u -> parse1000 bin
  | 0b1010u -> parse1010 bin
  | _ -> parseFourBits bin

let parseFourBytes b1 =
  match concat (b1 >>> 25) ((b1 >>> 16) &&& 0b1111u) 4 with
  | 0b10010101110u | 0b10010101111u -> Opcode.CALL, parseOneOpr b1 getConst22
  | 0b10010101100u | 0b10010101101u -> Opcode.JMP, parseOneOpr b1 getConst22
  | 0b10010000000u -> Opcode.LDS, parseTwoOpr b1 getRegD32 getConst16
  | 0b10010010000u -> Opcode.STS, parseTwoOpr b1 getConst16 getRegD32
  | _ -> Opcode.InvalidOp, NoOperand

let parse lifter (span: ByteSpan) (reader: IBinReader) addr =
  let bin = reader.ReadUInt16(span, 0)
  let struct ((op, operands), instrLen) =
    match isTwoBytes bin with
    | true ->
      let bin = uint32 bin
      struct (bin |> parseTwoBytes, 2u)
    | false ->
      let b2 = reader.ReadUInt16(span, 2)
      let bin = ((uint32 bin) <<< 16) + (uint32 b2)
      struct (bin |> parseFourBytes, 4u)
  Instruction(addr, instrLen, op, operands, lifter)
