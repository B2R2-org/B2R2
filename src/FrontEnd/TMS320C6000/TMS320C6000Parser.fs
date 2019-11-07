(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Seung Il Jung <sijung@kaist.ac.kr>
          Sang Kil Cha <sangkilc@kaist.ac.kr>

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

module B2R2.FrontEnd.TMS320C6000.Parser

open B2R2
open B2R2.FrontEnd.BitData

/// Appendix C-5. Fig. C-1
let parseDUnitSrcs bin = Op.InvalOP, NoOperand
let parseDUnitSrcsExt bin = Op.InvalOP, NoOperand
let parseDUnitLSBasic bin = Op.InvalOP, NoOperand
let parseDUnitLSLongImm bin = Op.InvalOP, NoOperand

let parseLUnitSrcs bin = Op.InvalOP, NoOperand
let parseLUnitNonCond bin = Op.InvalOP, NoOperand
let parseLUnitUnary bin = Op.InvalOP, NoOperand

let parseMUnitCompound bin = Op.InvalOP, NoOperand
let parseMUnitNonCond bin = Op.InvalOP, NoOperand
let parseMUnitUnaryExt bin = Op.InvalOP, NoOperand

let parseSUnitSrcs bin = Op.InvalOP, NoOperand
let parseSUnitSrcsExt bin = Op.InvalOP, NoOperand
let parseSUnitNonCond bin = Op.InvalOP, NoOperand
let parseSUnitUnary bin = Op.InvalOP, NoOperand
let parseSUnitBrImm bin = Op.InvalOP, NoOperand
let parseSUnitUncondImm bin = Op.InvalOP, NoOperand
let parseSUnitBrNOPConst bin = Op.InvalOP, NoOperand
let parseSUnitBrNOPReg bin = Op.InvalOP, NoOperand
let parseSUnitBr bin = Op.InvalOP, NoOperand
let parseSUnitMVK bin = Op.InvalOP, NoOperand
let parseSUnitFieldOps bin = Op.InvalOP, NoOperand

let parseNoUnitLoop bin = Op.InvalOP, NoOperand
let parseNoUnitNOPIdle bin = Op.InvalOP, NoOperand
let parseNoUnitEmuControl bin = Op.InvalOP, NoOperand

let parseCase1111 bin =
  match extract bin 31u 29u with
  | 0b0000u -> parseSUnitNonCond bin
  | _ -> parseSUnitSrcsExt bin

let parseMUnit bin =
  match extract bin 10u 6u with
  | 0b00011u -> parseMUnitUnaryExt bin
  | _ ->
    match extract bin 31u 28u with
    | 0b0001u -> parseMUnitNonCond bin
    | _ -> parseMUnitCompound bin

let parseNoUnit bin =
  match extract bin 31u 28u, pickBit bin 17u with
  | 0b0001u, _ -> parseNoUnitNOPIdle bin
  | _, 0b1u -> parseNoUnitLoop bin
  | _, _ (* 0b0u *) -> parseNoUnitEmuControl bin

let parseCase0000 bin =
  match pickBit bin 6u with
  | 0b0u -> parseNoUnit bin
  | _ -> parseDUnitSrcs bin

let parseCase0100 bin =
  match extract bin 31u 29u with
  | 0b000u -> parseSUnitUncondImm bin
  | _ -> parseSUnitBrImm bin

let parseCase1000 bin =
  match extract bin 27u 23u, extract bin 11u 6u with
  | 0b00000u, 0b001101u -> parseSUnitBr bin
  | 0b00001u, 0b001101u -> parseSUnitBrNOPReg bin
  | _, 0b000100u -> parseSUnitBrNOPConst bin
  | _, 0b111100u -> parseSUnitUnary bin
  | _, _ -> parseSUnitSrcs bin

let parseCase00 bin =
  match extract bin 11u 10u, extract bin 5u 4u with
  | 0b10u, 0b11u -> parseDUnitSrcsExt bin
  | 0b11u, 0b11u -> parseCase1111 bin
  | _, 0b11u -> parseMUnit bin
  | _, 0b00u -> parseCase0000 bin
  | _, 0b01u -> parseCase0100 bin
  | _, _ (* 0b10u *) -> parseCase1000 bin

let parseLUnit bin =
  match extract bin 31u 28u with
  | 0b0001u -> parseLUnitNonCond bin
  | _ -> parseLUnitSrcs bin

let parseCase10 bin =
  match extract bin 5u 4u with
  | 0b11u -> parseLUnit bin
  | 0b01u -> parseLUnitUnary bin
  | 0b10u -> parseSUnitMVK bin
  | _ (* 0b00u *) -> parseSUnitFieldOps bin

let parseInstruction bin =
  match extract bin 3u 2u with
  | 0b00u -> parseCase00 bin
  | 0b01u -> parseDUnitLSBasic bin
  | 0b10u -> parseCase10 bin
  | _ (* 11u *) -> parseDUnitLSLongImm bin

let parse (reader: BinReader) addr pos =
  let struct (bin, nextPos) = reader.ReadUInt32 pos
  let instrLen = nextPos - pos |> uint32
  let opcode, operands = parseInstruction bin
  let insInfo =
    { Address = addr
      NumBytes = instrLen
      Opcode = opcode
      Operands = operands
      OperationSize = 32<rt> // FIXME
      PacketIndex = 0 // FIXME
      EffectiveAddress = 0UL }
  TMS320C6000Instruction (addr, instrLen, insInfo, WordSize.Bit32)

// vim: set tw=80 sts=2 sw=2:
