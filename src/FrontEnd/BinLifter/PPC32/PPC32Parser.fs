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

module B2R2.FrontEnd.BinLifter.PPC32.Parser

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.BitData

let getRegister = function
  | 0b00000u -> R.R0
  | 0b00001u -> R.R1
  | 0b00010u -> R.R2
  | 0b00011u -> R.R3
  | 0b00100u -> R.R4
  | 0b00101u -> R.R5
  | 0b00110u -> R.R6
  | 0b00111u -> R.R7
  | 0b01000u -> R.R8
  | 0b01001u -> R.R9
  | 0b01010u -> R.R10
  | 0b01011u -> R.R11
  | 0b01100u -> R.R12
  | 0b01101u -> R.R13
  | 0b01110u -> R.R14
  | 0b01111u -> R.R15
  | 0b10000u -> R.R16
  | 0b10001u -> R.R17
  | 0b10010u -> R.R18
  | 0b10011u -> R.R19
  | 0b10100u -> R.R20
  | 0b10101u -> R.R21
  | 0b10110u -> R.R22
  | 0b10111u -> R.R23
  | 0b11000u -> R.R24
  | 0b11001u -> R.R25
  | 0b11010u -> R.R26
  | 0b11011u -> R.R27
  | 0b11100u -> R.R28
  | 0b11101u -> R.R29
  | 0b11110u -> R.R30
  | 0b11111u -> R.R31
  | _ -> Utils.futureFeature ()

let parseADDx bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE : RC *) with
  (* FIMXE *)
  | 0b00u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.ADD, ThreeOperands (rd, ra, rb))
  | 0b01u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.ADDdot, ThreeOperands (rd, ra, rb))
  | 0b10u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.ADDO, ThreeOperands (rd, ra, rb))
  | _ (* 11 *) ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.ADDOdot, ThreeOperands (rd, ra, rb))

let parseADDCx bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE : RC *) with
  | 0b00u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.ADDC, ThreeOperands (rd, ra, rb))
  | 0b01u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.ADDCdot, ThreeOperands (rd, ra, rb))
  | 0b10u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.ADDCO, ThreeOperands (rd, ra, rb))
  | _ (* 11 *) ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.ADDCOdot, ThreeOperands (rd, ra, rb))

let paserADDEx bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE : RC *) with
  | 0b00u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.ADDE, ThreeOperands (rd, ra, rb))
  | 0b01u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.ADDEdot, ThreeOperands (rd, ra, rb))
  | 0b10u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.ADDEO, ThreeOperands (rd, ra, rb))
  | _ (* 11 *) ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.ADDEOdot, ThreeOperands (rd, ra, rb))

let paserADDMEx bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE : RC *) with
  | 0b00u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.ADDME, TwoOperands (rd, ra))
  | 0b01u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.ADDMEdot, TwoOperands (rd, ra))
  | 0b10u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.ADDMEO, TwoOperands (rd, ra))
  | _ (* 11 *) ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.ADDMEOdot, TwoOperands (rd, ra))

let paserADDZEx bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE : RC *) with
  | 0b00u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.ADDZE, TwoOperands (rd, ra))
  | 0b01u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.ADDZEdot, TwoOperands (rd, ra))
  | 0b10u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.ADDZEO, TwoOperands (rd, ra))
  | _ (* 11 *) ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.ADDZEOdot, TwoOperands (rd, ra))

let parse1F bin =
  match extract bin 9u 1u with
  | 0x10Au -> parseADDx bin
  | 0x0Au -> parseADDCx bin
  | 0x8Au -> paserADDEx bin
  | 0xEAu -> paserADDMEx bin
  | 0xCAu -> paserADDZEx bin
  | _ -> Utils.futureFeature ()

let private parseInstruction bin =
  match extract bin 31u 26u with
  | 0x1Fu -> parse1F bin
  | _ -> Utils.futureFeature ()

let parse (reader: BinReader) addr pos =
  let struct (bin, nextPos) = reader.ReadUInt32 pos
  let instrLen = nextPos - pos |> uint32
  let struct (opcode, operands) = parseInstruction bin
  let insInfo =
    { Address = addr
      NumBytes = instrLen
      Opcode = opcode
      Operands = operands
      OperationSize = 32<rt> // FIXME
      EffectiveAddress = 0UL }
  PPC32Instruction (addr, instrLen, insInfo)

// vim: set tw=80 sts=2 sw=2:
