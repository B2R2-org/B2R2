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

let getFPRegister = function
  | 0b00000u -> F.F0
  | 0b00001u -> F.F1
  | 0b00010u -> F.F2
  | 0b00011u -> F.F3
  | 0b00100u -> F.F4
  | 0b00101u -> F.F5
  | 0b00110u -> F.F6
  | 0b00111u -> F.F7
  | 0b01000u -> F.F8
  | 0b01001u -> F.F9
  | 0b01010u -> F.F10
  | 0b01011u -> F.F11
  | 0b01100u -> F.F12
  | 0b01101u -> F.F13
  | 0b01110u -> F.F14
  | 0b01111u -> F.F15
  | 0b10000u -> F.F16
  | 0b10001u -> F.F17
  | 0b10010u -> F.F18
  | 0b10011u -> F.F19
  | 0b10100u -> F.F20
  | 0b10101u -> F.F21
  | 0b10110u -> F.F22
  | 0b10111u -> F.F23
  | 0b11000u -> F.F24
  | 0b11001u -> F.F25
  | 0b11010u -> F.F26
  | 0b11011u -> F.F27
  | 0b11100u -> F.F28
  | 0b11101u -> F.F29
  | 0b11110u -> F.F30
  | 0b11111u -> F.F31
  | _ -> Utils.futureFeature ()

let getCondRegister = function
  | 0b000u -> CR.CR0
  | 0b001u -> CR.CR1
  | 0b010u -> CR.CR2
  | 0b011u -> CR.CR3
  | 0b100u -> CR.CR4
  | 0b101u -> CR.CR5
  | 0b110u -> CR.CR6
  | 0b111u -> CR.CR7
  | _ -> Utils.futureFeature ()

let getCRM bin = bin |> uint64 |> Immediate

let getSegRegister bin = bin |> uint64 |> Immediate

let getSpecialRegister bin =  bin |> uint64 |> Immediate

let getTBRRegister bin = bin |> uint64 |> Immediate

let getFPSCRegister bin = bin |> uint64 |> Immediate

let getFM bin = bin |> uint64 |> Immediate

let parseADDx bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
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
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
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

let parseADDEx bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
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

let parseADDMEx bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  | 0b00u when extract bin 15u 11u = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.ADDME, TwoOperands (rd, ra))
  | 0b01u when extract bin 15u 11u = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.ADDMEdot, TwoOperands (rd, ra))
  | 0b10u when extract bin 15u 11u = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.ADDMEO, TwoOperands (rd, ra))
  | 0b11u when extract bin 15u 11u = 0u  ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.ADDMEOdot, TwoOperands (rd, ra))
  | _ -> Utils.impossible ()

let parseADDZEx bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  | 0b00u when extract bin 15u 11u = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.ADDZE, TwoOperands (rd, ra))
  | 0b01u when extract bin 15u 11u = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.ADDZEdot, TwoOperands (rd, ra))
  | 0b10u when extract bin 15u 11u = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.ADDZEO, TwoOperands (rd, ra))
  | 0b11u when extract bin 15u 11u = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.ADDZEOdot, TwoOperands (rd, ra))
  | _ -> Utils.impossible ()

let parseDIVWx bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  | 0b00u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.DIVW, ThreeOperands (rd, ra, rb))
  | 0b01u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.DIVWdot, ThreeOperands (rd, ra, rb))
  | 0b10u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.DIVWO, ThreeOperands (rd, ra, rb))
  | _ (* 11 *) ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.DIVWOdot, ThreeOperands (rd, ra, rb))

let parseDIVWUx bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  | 0b00u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.DIVWU, ThreeOperands (rd, ra, rb))
  | 0b01u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.DIVWUdot, ThreeOperands (rd, ra, rb))
  | 0b10u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.DIVWUO, ThreeOperands (rd, ra, rb))
  | _ (* 11 *) ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.DIVWUOdot, ThreeOperands (rd, ra, rb))

let parseMULLWx bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  | 0b00u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.MULLW, ThreeOperands (rd, ra, rb))
  | 0b01u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.MULLWdot, ThreeOperands (rd, ra, rb))
  | 0b10u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.MULLWO, ThreeOperands (rd, ra, rb))
  | _ (* 11 *) ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.MULLWOdot, ThreeOperands (rd, ra, rb))

let parseNEGx bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  | 0b00u when extract bin 15u 11u = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.NEG, TwoOperands (rd, ra))
  | 0b01u when extract bin 15u 11u = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.NEGdot, TwoOperands (rd, ra))
  | 0b10u when extract bin 15u 11u = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.NEGO, TwoOperands (rd, ra))
  | 0b11u when extract bin 15u 11u = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.NEGOdot, TwoOperands (rd, ra))
  | _ -> Utils.impossible ()

let parseSUBFx bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  /// sub rd,rb,ra = subf rd,ra,rb
  | 0b00u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.SUBF, ThreeOperands (rd, ra, rb))
  | 0b01u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.SUBFdot, ThreeOperands (rd, ra, rb))
  | 0b10u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.SUBFO, ThreeOperands (rd, ra, rb))
  | _ (* 11 *) ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.SUBFOdot, ThreeOperands (rd, ra, rb))

let parseSUBFCx bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  /// subfc rd,ra,rb = subc rd,rb,ra
  | 0b00u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.SUBFC, ThreeOperands (rd, ra, rb))
  | 0b01u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.SUBFCdot, ThreeOperands (rd, ra, rb))
  | 0b10u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.SUBFCO, ThreeOperands (rd, ra, rb))
  | _ (* 11 *) ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.SUBFCOdot, ThreeOperands (rd, ra, rb))

let parseSUBFEx bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  | 0b00u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.SUBFE, ThreeOperands (rd, ra, rb))
  | 0b01u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.SUBFEdot, ThreeOperands (rd, ra, rb))
  | 0b10u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.SUBFEO, ThreeOperands (rd, ra, rb))
  | _ (* 11 *) ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.SUBFEOdot, ThreeOperands (rd, ra, rb))

let parseSUBFMEx bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  | 0b00u when extract bin 15u 11u = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.SUBFME, TwoOperands (rd, ra))
  | 0b01u when extract bin 15u 11u = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.SUBFMEdot, TwoOperands (rd, ra))
  | 0b10u when extract bin 15u 11u = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.SUBFMEO, TwoOperands (rd, ra))
  | 0b11u when extract bin 15u 11u = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.SUBFMEOdot, TwoOperands (rd, ra))
  | _ -> Utils.impossible ()

let parseSUBFZEx bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  | 0b00u when extract bin 15u 11u = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.SUBFZE, TwoOperands (rd, ra))
  | 0b01u when extract bin 15u 11u = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.SUBFZEdot, TwoOperands (rd, ra))
  | 0b10u when extract bin 15u 11u = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.SUBFZEO, TwoOperands (rd, ra))
  | 0b11u when extract bin 15u 11u = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.SUBFZEOdot, TwoOperands (rd, ra))
  | _ -> Utils.impossible ()

let parseMULHWx bin =
  match pickBit bin 0u with
  | 0b0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.MULHW, ThreeOperands (rd, ra, rb))
  | _ (* 1 *) ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.MULHWdot, ThreeOperands (rd, ra, rb))

let parseMULHWUx bin =
  match pickBit bin 0u with
  | 0b0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.MULHWU, ThreeOperands (rd, ra, rb))
  | _ (* 1 *) ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.MULHWUdot, ThreeOperands (rd, ra, rb))

let parseANDx bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 0:RC *) with
  | 0b00u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.AND, ThreeOperands (ra, rs, rb))
  | 0b01u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.ANDdot, ThreeOperands (ra, rs, rb))
  | _ (* 1x *) -> Utils.impossible ()

let parseANDCx bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 0:RC *) with
  | 0b00u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.ANDC, ThreeOperands (ra, rs, rb))
  | 0b01u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.ANDCdot, ThreeOperands (ra, rs, rb))
  | _ (* 1x *) -> Utils.impossible ()

let parseCNTLZWx bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 0:RC *) with
  | 0b00u when extract bin 15u 11u = 0u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.CNTLZW, TwoOperands (ra, rs))
  | 0b01u when extract bin 15u 11u = 0u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.CNTLZWdot, TwoOperands (ra, rs))
  | _ (* 1x *) -> Utils.impossible ()

let parseDCBTSTandDCBA bin =
  match pickBit bin 10u with
  | 0b0u when extract bin 25u 21u = 0u ->
    (* CT = 0u *)
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.DCBTST, TwoOperands (ra, rb))
  | 0b1u when extract bin 25u 21u = 0u ->
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.DCBA, TwoOperands (ra, rb))
  | _ -> Utils.impossible ()

let parseDCBFandSYNC bin =
  match pickBit bin 10u with
  | 0b0u when extract bin 25u 21u = 0u ->
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.DCBF, TwoOperands (ra, rb))
  | 0b1u when extract bin 25u 11u = 0u ->
    struct (Op.SYNC, NoOperand)
  | _ -> Utils.impossible ()

let parseDCBIandICBI bin =
  match pickBit bin 10u with
  | 0b0u when extract bin 25u 21u = 0u ->
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.DCBI, TwoOperands (ra, rb))
  | 0b1u when extract bin 25u 21u = 0u ->
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.ICBI, TwoOperands (ra, rb))
  | _ -> Utils.impossible ()

let parseDCBSTandTLBSYNC bin =
  match pickBit bin 10u with
  | 0b0u when extract bin 25u 21u = 0u ->
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.DCBST, TwoOperands (ra, rb))
  | 0b1u when extract bin 25u 11u = 0u ->
    struct (Op.TLBSYNC, NoOperand)
  | _ -> Utils.impossible ()

let parseDCBTandLHBRX bin =
  match pickBit bin 10u with
  | 0b0u when extract bin 25u 21u = 0u ->
    (* CT = 0u *)
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.DCBT, TwoOperands (ra, rb))
  | 0b1u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.LHBRX, ThreeOperands (rd, ra, rb))
  | _ -> Utils.impossible ()

let parseDCBZ bin =
  match pickBit bin 10u with
  | 0b1u when extract bin 25u 21u = 0u ->
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.DCBZ, TwoOperands (ra, rb))
  | _ (* 0 *) -> Utils.impossible ()

let parseECIWX bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 with
  | 0b00u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.ECIWX, ThreeOperands (rd, ra, rb))
  | _ (* 01, 1x *) -> Utils.impossible ()

let parseECOWX bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 with
  | 0b00u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.ECOWX, ThreeOperands (rs, ra, rb))
  | _ (* 01, 1x *) -> Utils.impossible ()

let parseEIEIO bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 with
  | 0b10u when extract bin 25u 11u = 0u ->
    struct (Op.EIEIO, NoOperand)
  | _ (* 11, 0x *) -> Utils.impossible ()

let parseEQVx bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 0:Rc *) with
  | 0b00u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.EQV, ThreeOperands (rd, ra, rb))
  | 0b01u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.EQVdot, ThreeOperands (rd, ra, rb))
  | _ (* 1x *) -> Utils.impossible ()

let parseEXTSBx bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 1:Rc *) with
  | 0b10u when extract bin 15u 11u = 0u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.EXTSB, TwoOperands (rs, ra))
  | 0b11u when extract bin 15u 11u = 0u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.EXTSBdot, TwoOperands (rs, ra))
  | _ (* 0x *) -> Utils.impossible ()

let parseEXTSHx bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 1:Rc *) with
  | 0b10u when extract bin 15u 11u = 0u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.EXTSH, TwoOperands (rs, ra))
  | 0b11u when extract bin 15u 11u = 0u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.EXTSHdot, TwoOperands (rs, ra))
  | _ (* 0x *) -> Utils.impossible ()

let parseLBZUXandLFDUX bin =
  match pickBit bin 10u with
  | 0b0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.LBZUX, ThreeOperands (rd, ra, rb))
  | 0b1u ->
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  struct (Op.LFDUX, ThreeOperands (frd, ra, rb))
  | _ -> Utils.impossible ()

let parseLBZXandLFDX bin =
  match pickBit bin 10u with
  | 0b0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.LBZX, ThreeOperands (rd, ra, rb))
  | _ (* 1 *) ->
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  struct (Op.LFDX, ThreeOperands (frd, ra, rb))

let parseLWZUXandLFSUX bin =
  match pickBit bin 10u with
  | 0b0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.LWZUX, ThreeOperands (rd, ra, rb))
  | _ (* 1 *) ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.LFSUX, ThreeOperands (frd, ra, rb))

let parseLWZXandLFSX bin =
  match pickBit bin 10u with
  | 0b0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.LWZX, ThreeOperands (rd, ra, rb))
  | _ (* 1 *) ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.LFSX, ThreeOperands (frd, ra, rb))

let parseLHAUX bin =
  match pickBit bin 10u with
  | 0b0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.LHAUX, ThreeOperands (rd, ra, rb))
  | _ (* 1 *) -> Utils.impossible ()

let parseLHAX bin =
  match pickBit bin 10u with
  | 0b0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.LHAX, ThreeOperands (rd, ra, rb))
  | _ (* 1 *) -> Utils.impossible ()

let parseLHZUX bin =
  match pickBit bin 10u with
  | 0b0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.LHZUX, ThreeOperands (rd, ra, rb))
  | _ (* 1 *) -> Utils.impossible ()

let parseLHZX bin =
  match pickBit bin 10u with
  | 0b0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.LHZX, ThreeOperands (rd, ra, rb))
  | _ (* 1 *) -> Utils.impossible ()

let parseLSWI bin =
  match pickBit bin 10u with
  | 0b1u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let nb = extract bin 15u 11u |> uint64 |> Immediate
    struct (Op.LSWI, ThreeOperands(rd, ra, nb))
  | _ (* 0 *) -> Utils.impossible ()

let parseLSWX bin =
  match pickBit bin 10u with
  | 0b1u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.LSWX, ThreeOperands (rd, ra, rb))
  | _ (* 0 *) -> Utils.impossible ()

let parseLWARX bin =
  match pickBit bin 10u with
  | 0b0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.LWARX, ThreeOperands (rd, ra, rb))
  | _ (* 1 *) -> Utils.impossible ()

let parseLWBRX bin =
  match pickBit bin 10u with
  | 0b1u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.LWBRX, ThreeOperands (rd, ra, rb))
  | _ (* 0 *) -> Utils.impossible ()

let parseCMPandMCRXR bin =
  match pickBit bin 10u with
  | 0b0u when pickBit bin 22u = 0u ->
    let crfd = getCondRegister (extract bin 25u 23u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    if pickBit bin 21u = 0u then
    /// cmpw crfd,ra,rb = cmp crfd,0,ra,rb
      struct (Op.CMPW, ThreeOperands (crfd, ra, rb))
    else
      struct (Op.CMP, FourOperands (crfd, Immediate 1UL, ra, rb))
  | 0b1u when extract bin 22u 11u = 0u ->
    let crfd = getCondRegister (extract bin 25u 23u) |> OpReg
    struct (Op.MCRXR, OneOperand (crfd))
  | _ -> Utils.impossible ()

let parseMFCR bin =
  match pickBit bin 10u with
  | 0b0u when extract bin 20u 11u = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    struct (Op.MFCR, OneOperand (rd))
  | _ (* 1 *) -> Utils.impossible ()

let parseMFMSRandMFSR bin =
  match pickBit bin 10u with
  | 0b0u when extract bin 20u 11u = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    struct (Op.MFMSR, OneOperand (rd))
  | 0b1u when (concat (pickBit bin 20u) (extract bin 15u 11u) 1) = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    /// (* FIX SegRegister *)
    let sr = getSegRegister (extract bin 19u 16u)
    struct (Op.MFSR, TwoOperands (sr, rd))
  | _ -> Utils.impossible ()

let parseMFSRIN bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 with
  | 0b10u when extract bin 20u 16u = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.MFSRIN, TwoOperands (rd, rb))
  | _ (* 11, 0x *) -> Utils.impossible ()

let parseMTMSR bin =
  match pickBit bin 10u with
  | 0b0u when extract bin 20u 11u = 0u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    struct (Op.MFMSR, OneOperand (rs))
  | _ (* 1 *) -> Utils.impossible ()

let parseMTSRIN bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 with
  | 0b10u when extract bin 20u 16u = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.MTSRIN, TwoOperands (rd, rb))
  | _ (* 11, 0x *) -> Utils.impossible ()

let parseNANDx bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 0:RC *) with
  | 0b00u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.NAND, ThreeOperands (ra, rs, rb))
  | 0b01u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.NANDdot, ThreeOperands (ra, rs, rb))
  | _ (* 1x *) -> Utils.impossible ()

let parseNORx bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 0:RC *) with
  /// not rd,rs = nor ra,rs,rs
  | 0b00u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.NOR, ThreeOperands (ra, rs, rb))
  | 0b01u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.NORdot, ThreeOperands (ra, rs, rb))
  | _ (* 1x *) -> Utils.impossible ()

let parseORx bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 0:RC *) with
  /// mr ra,rs = or ra,rs,rs
  | 0b00u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.OR, ThreeOperands (ra, rs, rb))
  | 0b01u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.ORdot, ThreeOperands (ra, rs, rb))
  | _ (* 1x *) -> Utils.impossible ()

let parseORCx bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 0:RC *) with
  | 0b00u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.ORC, ThreeOperands (ra, rs, rb))
  | 0b01u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.ORCdot, ThreeOperands (ra, rs, rb))
  | _ (* 1x *) -> Utils.impossible ()

let parseSLWxandSRWx bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 0:RC *) with
  | 0b00u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.SLW, ThreeOperands (ra, rs, rb))
  | 0b01u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.SLWdot, ThreeOperands (ra, rs, rb))
  | 0b10u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.SRW, ThreeOperands (ra, rs, rb))
  | _ (* 11 *) ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.SRWdot, ThreeOperands (ra, rs, rb))

let parseSRAWx bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 1:RC *) with
  | 0b10u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.SRAW, ThreeOperands (ra, rs, rb))
  | 0b11u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.SRAWdot, ThreeOperands (ra, rs, rb))
  | _ (* 0x *) -> Utils.impossible ()

let parseSTBUXandSTFDUX bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 with
  | 0b00u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.STBUX, ThreeOperands (rs, ra, rb))
  | 0b10u ->
    let frs = getFPRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.STFDUX, ThreeOperands (frs, ra, rb))
  | _ (* 01, 11 *) -> Utils.impossible ()

let parseSTBXandSTFDX bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 with
  | 0b00u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.STBX, ThreeOperands (rs, ra, rb))
  | 0b10u ->
    let frs = getFPRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.STFDX, ThreeOperands (frs, ra, rb))
  | _ (* 01, 11 *) -> Utils.impossible ()

let parseSTFIWX bin =
  match pickBit bin 10u with
  | 0b1u ->
    let frs = getFPRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.STFIWX, ThreeOperands (frs, ra, rb))
  | _ (* 0 *) -> Utils.impossible ()

let parseSTWUXandSTFSUX bin =
  match pickBit bin 10u with
  | 0b0u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.STWUX, ThreeOperands (rs, ra, rb))
  | _ (* 1 *) ->
    let frs = getFPRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.STFSUX, ThreeOperands (frs, ra, rb))

let parseSTWXandSTFSX bin =
  match pickBit bin 10u with
  | 0b0u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.STWX, ThreeOperands (rs, ra, rb))
  | _ (* 1 *) ->
    let frs = getFPRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.STFSX, ThreeOperands (frs, ra, rb))

let parseSTHBRX bin =
  match pickBit bin 10u with
  | 0b1u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.STHBRX, ThreeOperands (rs, ra, rb))
  | _ (* 0 *) -> Utils.impossible ()

let parseSTHUX bin =
  match pickBit bin 10u with
  | 0b0u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.STHUX, ThreeOperands (rs, ra, rb))
  | _ (* 1 *) -> Utils.impossible ()

let parseSTHX bin =
  match pickBit bin 10u with
  | 0b0u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.STHX, ThreeOperands (rs, ra, rb))
  | _ (* 1 *) -> Utils.impossible ()

let parseSTWCXdotandSTWBRX bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 with
  | 0b01u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.STWCXdot, ThreeOperands (rs, ra, rb))
  | 0b10u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.STWBRX, ThreeOperands (rs, ra, rb))
  | _ (* 00, 11 *) -> Utils.impossible ()

let parseTLBIA bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 with
  | 0b00u ->
    struct (Op.TLBIA, NoOperand)
  | _ (* 01, 1x *)-> Utils.impossible ()

let parseTLBIE bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 with
  | 0b00u ->
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.TLBIE, OneOperand(rb))
  | _ (* 01, 1x *)-> Utils.impossible ()

let parseXORx bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 0:RC *) with
  | 0b00u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.XOR, ThreeOperands (ra, rs, rb))
  | 0b01u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.XORdot, ThreeOperands (ra, rs, rb))
  | _ (* 1x *) -> Utils.impossible ()

let parseSTSWX bin =
  match pickBit bin 10u with
  | 0b1u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.STSWX, ThreeOperands (rs, ra, rb))
  | _ (* 0 *) -> Utils.impossible ()

let parseCMPL bin =
  match pickBit bin 10u with
  | 0b0u when pickBit bin 22u = 0u ->
    let crfd = getCondRegister (extract bin 25u 23u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    if pickBit bin 21u = 0u then
    /// cmplw crfd,ra,rb = cmpl crfd,0,ra,rb
      struct (Op.CMPLW, ThreeOperands (crfd, ra, rb))
    else
      struct (Op.CMPL, FourOperands (crfd, Immediate 1UL, ra, rb))
  | _ (* 1 *) -> Utils.impossible ()

let parseTW bin =
  match pickBit bin 10u with
  /// twlge ra,rb = tw 5,ra,rb
  | 0b0u ->
    let TO = extract bin 25u 21u |> uint64 |> Immediate
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    if extract bin 25u 21u = 0x4u then
    /// tweq ra,rb = tw 4,ra,rb
      struct (Op.TWEQ, TwoOperands (ra, rb))
    elif extract bin 25u 21u = 0x1fu then
      if extract bin 20u 11u = 0x0u then
        struct (Op.TRAP, NoOperand)
      else
        struct (Op.TW, NoOperand)
    else
      struct (Op.TW, ThreeOperands (TO, ra, rb))
  | _ (* 1 *) -> Utils.impossible ()

let parseMTCRF bin =
  match pickBit bin 10u with
  /// mtcr rs = mtcrf 0xff,rs
  | 0b0u when concat (pickBit bin 20u) (pickBit bin 11u) 1 = 00u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    /// (* FIX CRM *)
    let crm = getCRM (extract bin 19u 12u)
    struct (Op.MTCRF, TwoOperands (crm, rs))
  | _ (* 1 *) -> Utils.impossible ()

let parseMTSR bin =
  match pickBit bin 10u with
  | 0b0u when (concat (pickBit bin 20u) (extract bin 15u 11u) 1) = 0u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    /// (* FIX SegRegister *)
    let sr = getSegRegister (extract bin 19u 16u)
    struct (Op.MTSR, TwoOperands (sr, rs))
  | _ (* 1 *) -> Utils.impossible ()

let parseMFSPR bin =
  match pickBit bin 10u with
  | 0b0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    /// (* FIX SpecialRegister *)
    let spr =
      getSpecialRegister (concat (extract bin 15u 11u) (extract bin 20u 16u) 5)
    /// mfxer rd = mfspr rd,1
    if concat (extract bin 15u 11u) (extract bin 20u 16u) 5 = 0x1u then
      struct (Op.MFXER, OneOperand rd)
    /// mflr rd = mfspr rd,8
    elif concat (extract bin 15u 11u) (extract bin 20u 16u) 5 = 0x8u then
      struct (Op.MFLR, OneOperand rd)
    /// mfctr rd = mfspr rd,9
    elif concat (extract bin 15u 11u) (extract bin 20u 16u) 5 = 0x9u then
      struct (Op.MFCTR, OneOperand rd)
    else
    struct (Op.MFSPR, TwoOperands (rd, spr))
  | _ (* 1 *) -> Utils.impossible ()

let parseMFTB bin =
  match pickBit bin 10u with
  | 0b0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    /// (* FIX TBRRegister *)
    let tbr =
      getTBRRegister (concat (extract bin 15u 11u) (extract bin 20u 16u) 5)
    /// mftbu rd = mftb rd,269
    if concat (extract bin 15u 11u) (extract bin 20u 16u) 5 = 0x10du then
      struct (Op.MFTBU, OneOperand rd)
    /// mftb rd = mftb rd,268
    else
    struct (Op.MFTB, TwoOperands (rd, tbr))
  | _ (* 1 *) -> Utils.impossible ()

let parseMTSPR bin =
  match pickBit bin 10u with
  | 0b0u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    /// (* FIX SpecialRegister *)
    let spr =
      getSpecialRegister (concat (extract bin 15u 11u) (extract bin 20u 16u) 5)
    /// mtxer rd = mtspr rd,1
    if concat (extract bin 15u 11u) (extract bin 20u 16u) 5 = 0x1u then
      struct (Op.MTXER, OneOperand rs)
    /// mtlr rd = mtspr rd,8
    elif concat (extract bin 15u 11u) (extract bin 20u 16u) 5 = 0x8u then
      struct (Op.MTLR, OneOperand rs)
    /// mtctr rd = mtspr rd,9
    elif concat (extract bin 15u 11u) (extract bin 20u 16u) 5 = 0x9u then
      struct (Op.MTCTR, OneOperand rs)
    else
    struct (Op.MTSPR, TwoOperands (rs, spr))
  | _ (* 1 *) -> Utils.impossible ()

let parseSTSWI bin =
  match pickBit bin 10u with
  | 0b1u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let nb = extract bin 15u 11u |> uint64 |> Immediate
    struct (Op.STSWI, ThreeOperands (rs, ra, nb))
  | _ (* 0 *) -> Utils.impossible ()

let parseSRAWIx bin =
  match pickBit bin 0u with
  | 0b0u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let sh = extract bin 15u 11u |> uint64 |> Immediate
    struct (Op.SRAWI, ThreeOperands (rs, ra, sh))
  | _ (* 1 *) ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let sh = extract bin 15u 11u |> uint64 |> Immediate
    struct (Op.SRAWIdot, ThreeOperands (rs, ra, sh))

let parse1F bin =
  match extract bin 9u 1u with
  | 0x10Au -> parseADDx bin
  | 0xAu -> parseADDCx bin
  | 0x8Au -> parseADDEx bin
  | 0xEAu -> parseADDMEx bin
  | 0xCAu -> parseADDZEx bin
  | 0x1EBu -> parseDIVWx bin
  | 0x1CBu -> parseDIVWUx bin
  | 0xEBu -> parseMULLWx bin
  | 0x68u -> parseNEGx bin
  | 0x28u -> parseSUBFx bin
  | 0x8u -> parseSUBFCx bin
  | 0x88u -> parseSUBFEx bin
  | 0xE8u -> parseSUBFMEx bin
  | 0xC8u -> parseSUBFZEx bin
  | 0x4Bu when pickBit bin 10u = 0u -> parseMULHWx bin
  | 0xBu when pickBit bin 10u = 0u -> parseMULHWUx bin
  | 0x1Cu -> parseANDx bin
  | 0x3Cu -> parseANDCx bin
  | 0x1Au -> parseCNTLZWx bin
  (* FIX DCBTST / DCBA RegA = 0 *)
  | 0xF6u when pickBit bin 0u = 0u -> parseDCBTSTandDCBA bin
  (* FIX DCBF RegA = 0 / SYNC 0 *)
  | 0x56u when pickBit bin 0u = 0u -> parseDCBFandSYNC bin
  (* FIX DCBI / ICBI RegA = 0 *)
  | 0x1D6u when pickBit bin 0u = 0u -> parseDCBIandICBI bin
  (* FIX DCBST RegA = 0 *)
  | 0x36u when pickBit bin 0u = 0u -> parseDCBSTandTLBSYNC bin
  (* FIX DCBT / LHBRX RegA = 0 *)
  | 0x116u when pickBit bin 0u = 0u -> parseDCBTandLHBRX bin
  (* FIX DCBZ RegA = 0 *)
  | 0x1F6u when pickBit bin 0u = 0u -> parseDCBZ bin
  | 0x136u when pickBit bin 0u = 0u -> parseECIWX bin
  | 0x1B6u when pickBit bin 0u = 0u -> parseECOWX bin
  | 0x156u when pickBit bin 0u = 0u -> parseEIEIO bin
  | 0x11Cu -> parseEQVx bin
  | 0x1BAu -> parseEXTSBx bin
  | 0x19Au -> parseEXTSHx bin
  (* FIX LBZUX / LFDUX RegA = 0 *)
  | 0x77u when pickBit bin 0u = 0u -> parseLBZUXandLFDUX bin
  (* FIX LBZX / LFDX RegA = 0 *)
  | 0x57u when pickBit bin 0u = 0u -> parseLBZXandLFDX bin
  (* FIX LWZUX / LFSUX RegA = 0 *)
  | 0x37u when pickBit bin 0u = 0u -> parseLWZUXandLFSUX bin
  (* FIX LWZX / LFSX RegA = 0 *)
  | 0x17u when pickBit bin 0u = 0u -> parseLWZXandLFSX bin
  (* FIX LHAUX RegA = 0 *)
  | 0x177u when pickBit bin 0u = 0u -> parseLHAUX bin
  (* FIX LHAX RegA = 0 *)
  | 0x157u when pickBit bin 0u = 0u -> parseLHAX bin
  (* FIX LHZUX RegA = 0 *)
  | 0x137u when pickBit bin 0u = 0u -> parseLHZUX bin
  (* FIX LHZX RegA = 0 *)
  | 0x117u when pickBit bin 0u = 0u -> parseLHZX bin
  | 0x55u when pickBit bin 0u = 0u -> parseLSWI bin
  | 0x15u when pickBit bin 0u = 0u -> parseLSWX bin
  (* FIX LWARX RegA = 0 *)
  | 0x14u when pickBit bin 0u = 0u -> parseLWARX bin
  (* FIX LWBRX RegA = 0 *)
  | 0x16u when pickBit bin 0u = 0u -> parseLWBRX bin
  | 0x0u when pickBit bin 0u = 0u -> parseCMPandMCRXR bin
  | 0x13u when pickBit bin 0u = 0u -> parseMFCR bin
  /// (* FIX SegRegister *)
  | 0x53u when pickBit bin 0u = 0u -> parseMFMSRandMFSR bin
  | 0x93u -> parseMFSRIN bin
  | 0x92u when pickBit bin 0u = 0u -> parseMTMSR bin
  | 0xF2u -> parseMTSRIN bin
  | 0x1DCu -> parseNANDx bin
  | 0x7Cu -> parseNORx bin
  | 0x1BCu -> parseORx bin
  | 0x19Cu -> parseORCx bin
  | 0x18u -> parseSLWxandSRWx bin
  | 0x118u -> parseSRAWx bin
  (* FIX STBUX / STFDUX RegA = 0 *)
  | 0xF7u -> parseSTBUXandSTFDUX bin
  (* FIX STBX / STFDX RegA = 0 *)
  | 0xD7u -> parseSTBXandSTFDX bin
  (* FIX STFIWX RegA = 0 *)
  | 0x1D7u when pickBit bin 0u = 0u -> parseSTFIWX bin
  (* FIX STWUX / STFSUX RegA = 0 *)
  | 0xB7u when pickBit bin 0u = 0u -> parseSTWUXandSTFSUX bin
  (* FIX STWX / STFSX RegA = 0 *)
  | 0x97u when pickBit bin 0u = 0u -> parseSTWXandSTFSX bin
  (* FIX STHBRX RegA = 0 *)
  | 0x196u when pickBit bin 0u = 0u -> parseSTHBRX bin
  (* FIX STHUX RegA = 0 *)
  | 0x1B7u when pickBit bin 0u = 0u -> parseSTHUX bin
  (* FIX STHX RegA = 0 *)
  | 0x197u when pickBit bin 0u = 0u -> parseSTHX bin
  | 0x95u when pickBit bin 0u = 0u -> parseSTSWX bin
  (* FIX STWCXdot / STWBRX RegA = 0 *)
  | 0x96u -> parseSTWCXdotandSTWBRX bin
  | 0x172u -> parseTLBIA bin
  | 0x132u -> parseTLBIE bin
  | 0x13Cu -> parseXORx bin
  | 0x20u when pickBit bin 0u = 0u -> parseCMPL bin
  | 0x4u when pickBit bin 0u = 0u -> parseTW bin
  /// (* FIX CRM *)
  | 0x90u when pickBit bin 0u = 0u -> parseMTCRF bin
  /// (* FIX SegRegister *)
  | 0xD2u when pickBit bin 0u = 0u -> parseMTSR bin
  /// (* FIX SpecialRegister *)
  | 0x153u when pickBit bin 0u = 0u -> parseMFSPR bin
  /// (* FIX TBRRegister *)
  | 0x173u when pickBit bin 0u = 0u -> parseMFTB bin
  /// (* FIX SpecialRegister *)
  | 0x1D3u when pickBit bin 0u = 0u -> parseMTSPR bin
  | 0xD5u when pickBit bin 0u = 0u -> parseSTSWI bin
  | 0x138u when pickBit bin 10u = 1u -> parseSRAWIx bin
  | _ -> Utils.futureFeature ()

let parseFCMPU bin =
  match pickBit bin 0u with
  | 0b0u when extract bin 22u 21u = 0u ->
    let crfd = getCondRegister (extract bin 25u 23u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FCMPU, ThreeOperands (crfd, fra, frb))
  | _ (* 1 *)-> Utils.impossible ()

let parseFRSPx bin =
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 16u = 0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FRSP, TwoOperands (frd, frb))
  | 0b1u when extract bin 20u 16u = 0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FRSPdot, TwoOperands (frd, frb))
  | _ -> Utils.impossible ()

let parseFCTIWx bin =
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 16u = 0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FCTIW, TwoOperands (frd, frb))
  | 0b1u when extract bin 20u 16u = 0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FCTIWdot, TwoOperands (frd, frb))
  | _ -> Utils.impossible ()

let parseFCTIWZx bin =
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 16u = 0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FCTIWZ, TwoOperands (frd, frb))
  | 0b1u when extract bin 20u 16u = 0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FCTIWZdot, TwoOperands (frd, frb))
  | _ -> Utils.impossible ()

let parseFDIVx bin =
  match pickBit bin 0u with
  | 0b0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FDIV, ThreeOperands (frd, fra, frb))
  | _ (* 1 *)->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FDIVdot, ThreeOperands (frd, fra, frb))

let parseFSUBx bin =
  match pickBit bin 0u with
  | 0b0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FSUB, ThreeOperands (frd, fra, frb))
  | _ (* 1 *) ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FSUBdot, ThreeOperands (frd, fra, frb))

let parseFADDx bin =
  match pickBit bin 0u with
  | 0b0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FADD, ThreeOperands (frd, fra, frb))
  | _ (* 1 *) ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FADDdot, ThreeOperands (frd, fra, frb))

let parseFSQRTx bin =
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 16u = 0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FSQRT, TwoOperands (frd, frb))
  | 0b1u when extract bin 20u 16u = 0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FSQRTdot, TwoOperands (frd, frb))
  | _ -> Utils.impossible ()

let parseFSELx bin =
  match pickBit bin 0u with
  | 0b0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    let frc = getFPRegister (extract bin 10u 6u) |> OpReg
    struct (Op.FSEL, FourOperands (frd, fra, frc, frb))
  | _ (* 1 *) ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    let frc = getFPRegister (extract bin 10u 6u) |> OpReg
    struct (Op.FSELdot, FourOperands (frd, fra, frc, frb))

let parseFMULx bin =
  match pickBit bin 0u with
  | 0b0u when extract bin 15u 11u = 0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frc = getFPRegister (extract bin 10u 6u) |> OpReg
    struct (Op.FMUL, ThreeOperands (frd, fra, frc))
  | 0b1u when extract bin 15u 11u = 0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frc = getFPRegister (extract bin 10u 6u) |> OpReg
    struct (Op.FMULdot, ThreeOperands (frd, fra, frc))
  | _ -> Utils.impossible ()

let parseFRSQRTEx bin =
  match pickBit bin 0u with
  | 0b0u when concat (extract bin 20u 16u) (extract bin 10u 6u) 5 = 0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FRSQRTE, TwoOperands (frd, frb))
  | 0b1u when extract bin 15u 11u = 0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FRSQRTEdot, TwoOperands (frd, frb))
  | _ -> Utils.impossible ()

let parseFMSUBx bin =
  match pickBit bin 0u with
  | 0b0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    let frc = getFPRegister (extract bin 10u 6u) |> OpReg
    struct (Op.FMSUB, FourOperands (frd, fra, frc, frb))
  | _ (* 1 *) ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    let frc = getFPRegister (extract bin 10u 6u) |> OpReg
    struct (Op.FMSUBdot, FourOperands (frd, fra, frc, frb))

let parseFMADDx bin =
  match pickBit bin 0u with
  | 0b0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    let frc = getFPRegister (extract bin 10u 6u) |> OpReg
    struct (Op.FMADD, FourOperands (frd, fra, frc, frb))
  | _ (* 1 *) ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    let frc = getFPRegister (extract bin 10u 6u) |> OpReg
    struct (Op.FMADDdot, FourOperands (frd, fra, frc, frb))

let parseFNMSUBx bin =
  match pickBit bin 0u with
  | 0b0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    let frc = getFPRegister (extract bin 10u 6u) |> OpReg
    struct (Op.FNMSUB, FourOperands (frd, fra, frc, frb))
  | _ (* 1 *) ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    let frc = getFPRegister (extract bin 10u 6u) |> OpReg
    struct (Op.FNMSUBdot, FourOperands (frd, fra, frc, frb))

let parseFNMADDx bin =
  match pickBit bin 0u with
  | 0b0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    let frc = getFPRegister (extract bin 10u 6u) |> OpReg
    struct (Op.FNMADD, FourOperands (frd, fra, frc, frb))
  | _ (* 1 *) ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    let frc = getFPRegister (extract bin 10u 6u) |> OpReg
    struct (Op.FNMADDdot, FourOperands (frd, fra, frc, frb))

let parseFCMPO bin =
  match pickBit bin 0u with
  | 0b0u when extract bin 22u 21u = 0u ->
    let crfd = getCondRegister (extract bin 25u 23u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FCMPO, ThreeOperands (crfd, fra, frb))
  | _ (* 1 *)-> Utils.impossible ()

let parseMTFSB1x bin =
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 11u = 0u ->
  /// (* FIX FPSCRegister *)
    let crbd = getFPSCRegister (extract bin 25u 21u)
    struct (Op.MTFSB1, OneOperand crbd)
  | 0b1u when extract bin 20u 11u = 0u ->
  /// (* FIX FPSCRegister *)
    let crbd = getFPSCRegister (extract bin 25u 21u)
    struct (Op.MTFSB1dot, OneOperand crbd)
  | _ -> Utils.impossible ()

let parseFNEGx bin =
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 11u = 0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FNEG, TwoOperands (frd, frb))
  | 0b1u when extract bin 20u 11u = 0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FNEGdot, TwoOperands (frd, frb))
  | _ -> Utils.impossible ()

let parseMCRFS bin =
  match pickBit bin 0u with
  | 0b0u when concat (extract bin 22u 21u) (extract bin 17u 11u) 2 = 0u ->
    let crfd = getCondRegister (extract bin 25u 23u) |> OpReg
    let crfs = getCondRegister (extract bin 20u 18u) |> OpReg
    struct (Op.MCRFS, TwoOperands (crfd, crfs))
  | _ (* 1 *)-> Utils.impossible ()

let parseMTFSB0x bin =
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 11u = 0u ->
  /// (* FIX FPSCRegister *)
    let crbd = getFPSCRegister (extract bin 25u 21u)
    struct (Op.MTFSB0, OneOperand crbd)
  | 0b1u when extract bin 20u 11u = 0u ->
  /// (* FIX FPSCRegister *)
    let crbd = getFPSCRegister (extract bin 25u 21u)
    struct (Op.MTFSB0dot, OneOperand crbd)
  | _ -> Utils.impossible ()

let parseFMRx bin =
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 16u = 0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FMR, TwoOperands (frd, frb))
  | 0b1u when extract bin 20u 16u = 0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FMRdot, TwoOperands (frd, frb))
  | _ -> Utils.impossible ()

let parseMTFSFIx bin =
  match pickBit bin 0u with
  | 0b0u when concat (extract bin 22u 16u) (pickBit bin 11u) 7 = 0u ->
    let crfd = getCondRegister (extract bin 25u 23u) |> OpReg
    let IMM = extract bin 15u 12u |> uint64 |> Immediate
    struct (Op.MTFSFI, TwoOperands (crfd, IMM))
  | 0b1u when concat (extract bin 22u 16u) (pickBit bin 11u) 7 = 0u ->
    let crfd = getCondRegister (extract bin 25u 23u) |> OpReg
    let IMM = extract bin 15u 12u |> uint64 |> Immediate
    struct (Op.MTFSFIdot, TwoOperands (crfd, IMM))
  | _ -> Utils.impossible ()

let parseFNABSx bin =
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 16u = 0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FNABS, TwoOperands (frd, frb))
  | 0b1u when extract bin 20u 16u = 0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FNABSdot, TwoOperands (frd, frb))
  | _ -> Utils.impossible ()

let parseFABSx bin =
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 16u = 0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FABS, TwoOperands (frd, frb))
  | 0b1u when extract bin 20u 16u = 0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FABSdot, TwoOperands (frd, frb))
  | _ -> Utils.impossible ()

let parseMFFSx bin =
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 11u = 0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    struct (Op.MFFS, OneOperand frd)
  | 0b1u when extract bin 20u 11u = 0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    struct (Op.MFFSdot, OneOperand frd)
  | _ -> Utils.impossible ()

let parseMTFSFx bin =
  match pickBit bin 0u with
  | 0b0u when concat (pickBit bin 25u) (pickBit bin 16u) 1 = 0u ->
    let fm = getFM (extract bin 24u 17u)
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.MTFSF, TwoOperands (fm, frb))
  | 0b1u when concat (pickBit bin 25u) (pickBit bin 16u) 1 = 0u ->
    let fm = getFM (extract bin 24u 17u)
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.MTFSFdot, TwoOperands (fm, frb))
  | _ -> Utils.impossible ()

let parse3F bin =
  match extract bin 5u 1u with
  | 0x0u ->
    if extract bin 10u 6u = 0u then parseFCMPU bin
    elif extract bin 10u 6u = 1u then parseFCMPO bin
    elif extract bin 10u 6u = 2u then parseMCRFS bin
    else Utils.impossible ()
  | 0x6u ->
    /// (* FIX FPSCRegister *)
    if extract bin 10u 6u = 1u then parseMTFSB1x bin
    /// (* FIX FPSCRegister *)
    elif extract bin 10u 6u = 2u then parseMTFSB0x bin
    elif extract bin 10u 6u = 4u then parseMTFSFIx bin
    else Utils.impossible ()
  | 0x7u ->
    if extract bin 10u 6u = 0x12u then parseMFFSx bin
    elif extract bin 10u 6u = 0x16u then parseMTFSFx bin
    else Utils.impossible ()
  | 0x8u ->
    if extract bin 10u 6u = 1u then parseFNEGx bin
    elif extract bin 10u 6u = 2u then parseFMRx bin
    elif extract bin 10u 6u = 4u then parseFNABSx bin
    elif extract bin 10u 6u = 8u then parseFABSx bin
    else Utils.impossible ()
  | 0xCu when extract bin 10u 6u = 0u -> parseFRSPx bin
  | 0xEu when extract bin 10u 6u = 0u -> parseFCTIWx bin
  | 0xFu when extract bin 10u 6u = 0u -> parseFCTIWZx bin
  | 0x12u when extract bin 10u 6u = 0u -> parseFDIVx bin
  | 0x14u when extract bin 10u 6u = 0u -> parseFSUBx bin
  | 0x15u when extract bin 10u 6u = 0u -> parseFADDx bin
  | 0x16u when extract bin 10u 6u = 0u -> parseFSQRTx bin
  | 0x17u -> parseFSELx bin
  | 0x19u -> parseFMULx bin
  | 0x1Au -> parseFRSQRTEx bin
  | 0x1Cu -> parseFMSUBx bin
  | 0x1Du -> parseFMADDx bin
  | 0x1Eu -> parseFNMSUBx bin
  | 0x1Fu -> parseFNMADDx bin
  | 0x20u when extract bin 10u 6u = 0u -> parseFCMPO bin
  | _ -> Utils.futureFeature ()

let parseFDIVSx bin =
  match pickBit bin 0u with
  | 0b0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FDIVS, ThreeOperands (frd, fra, frb))
  | _ (* 1 *)->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FDIVSdot, ThreeOperands (frd, fra, frb))

let parseFSUBSx bin =
  match pickBit bin 0u with
  | 0b0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FSUBS, ThreeOperands (frd, fra, frb))
  | _ (* 1 *) ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FSUBSdot, ThreeOperands (frd, fra, frb))

let parseFADDSx bin =
  match pickBit bin 0u with
  | 0b0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FADDS, ThreeOperands (frd, fra, frb))
  | _ (* 1 *) ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FADDSdot, ThreeOperands (frd, fra, frb))

let parseFSQRTSx bin =
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 16u = 0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FSQRTS, TwoOperands (frd, frb))
  | 0b1u when extract bin 20u 16u = 0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FSQRTSdot, TwoOperands (frd, frb))
  | _ -> Utils.impossible ()

let parseFRESx bin =
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 16u = 0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FRES, TwoOperands (frd, frb))
  | 0b1u when extract bin 20u 16u = 0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FRESdot, TwoOperands (frd, frb))
  | _ -> Utils.impossible ()

let parseFMULSx bin =
  match pickBit bin 0u with
  | 0b0u when extract bin 15u 11u = 0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frc = getFPRegister (extract bin 10u 6u) |> OpReg
    struct (Op.FMULS, ThreeOperands (frd, fra, frc))
  | 0b1u when extract bin 15u 11u = 0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frc = getFPRegister (extract bin 10u 6u) |> OpReg
    struct (Op.FMULSdot, ThreeOperands (frd, fra, frc))
  | _ -> Utils.impossible ()

let parseFMSUBSx bin =
  match pickBit bin 0u with
  | 0b0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    let frc = getFPRegister (extract bin 10u 6u) |> OpReg
    struct (Op.FMSUBS, FourOperands (frd, fra, frc, frb))
  | _ (* 1 *) ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    let frc = getFPRegister (extract bin 10u 6u) |> OpReg
    struct (Op.FMSUBSdot, FourOperands (frd, fra, frc, frb))

let parseFMADDSx bin =
  match pickBit bin 0u with
  | 0b0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    let frc = getFPRegister (extract bin 10u 6u) |> OpReg
    struct (Op.FMADDS, FourOperands (frd, fra, frc, frb))
  | _ (* 1 *) ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    let frc = getFPRegister (extract bin 10u 6u) |> OpReg
    struct (Op.FMADDSdot, FourOperands (frd, fra, frc, frb))

let parseFNMSUBSx bin =
  match pickBit bin 0u with
  | 0b0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    let frc = getFPRegister (extract bin 10u 6u) |> OpReg
    struct (Op.FNMSUBS, FourOperands (frd, fra, frc, frb))
  | _ (* 1 *) ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    let frc = getFPRegister (extract bin 10u 6u) |> OpReg
    struct (Op.FNMSUBSdot, FourOperands (frd, fra, frc, frb))

let parseFNMADDSx bin =
  match pickBit bin 0u with
  | 0b0u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    let frc = getFPRegister (extract bin 10u 6u) |> OpReg
    struct (Op.FNMADDS, FourOperands (frd, fra, frc, frb))
  | _ (* 1 *) ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    let frc = getFPRegister (extract bin 10u 6u) |> OpReg
    struct (Op.FNMADDSdot, FourOperands (frd, fra, frc, frb))

let parse3B bin =
  match extract bin 5u 1u with
  | 0x12u when extract bin 10u 6u = 0u -> parseFDIVSx bin
  | 0x14u when extract bin 10u 6u = 0u -> parseFSUBSx bin
  | 0x15u when extract bin 10u 6u = 0u -> parseFADDSx bin
  | 0x16u when extract bin 10u 6u = 0u -> parseFSQRTSx bin
  | 0x18u when extract bin 10u 6u = 0u -> parseFRESx bin
  | 0x19u -> parseFMULSx bin
  | 0x1Cu -> parseFMSUBSx bin
  | 0x1Du -> parseFMADDSx bin
  | 0x1Eu -> parseFNMSUBSx bin
  | 0x1Fu -> parseFNMADDSx bin
  | _ -> Utils.futureFeature ()

let private parseInstruction bin =
  match extract bin 31u 26u with
  | 0x1Fu -> parse1F bin
  | 0x3Fu -> parse3F bin
  | 0x3Bu -> parse3B bin
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
