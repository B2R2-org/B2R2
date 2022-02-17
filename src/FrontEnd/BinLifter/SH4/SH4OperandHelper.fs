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

module B2R2.FrontEnd.BinLifter.SH4.OperandHelper

open B2R2

let getReg = function
  | 0x0us -> R.R0
  | 0x1us -> R.R1
  | 0x2us -> R.R2
  | 0x3us -> R.R3
  | 0x4us -> R.R4
  | 0x5us -> R.R5
  | 0x6us -> R.R6
  | 0x7us -> R.R7
  | 0x8us -> R.R8
  | 0x9us -> R.R9
  | 0xAus -> R.R10
  | 0xBus -> R.R11
  | 0xCus -> R.R12
  | 0xDus -> R.R13
  | 0xEus -> R.R14
  | 0xFus -> R.R15
  | _ -> raise InvalidRegTypeException

let getRegBank = function
  | 0x0us -> R.R0_BANK
  | 0x1us -> R.R1_BANK
  | 0x2us -> R.R2_BANK
  | 0x3us -> R.R3_BANK
  | 0x4us -> R.R4_BANK
  | 0x5us -> R.R5_BANK
  | 0x6us -> R.R6_BANK
  | 0x7us -> R.R7_BANK
  | _ -> raise InvalidRegTypeException

let getRegFR = function
  | 0x0us -> R.FR0
  | 0x1us -> R.FR1
  | 0x2us -> R.FR2
  | 0x3us -> R.FR3
  | 0x4us -> R.FR4
  | 0x5us -> R.FR5
  | 0x6us -> R.FR6
  | 0x7us -> R.FR7
  | 0x8us -> R.FR8
  | 0x9us -> R.FR9
  | 0xAus -> R.FR10
  | 0xBus -> R.FR11
  | 0xCus -> R.FR12
  | 0xDus -> R.FR13
  | 0xEus -> R.FR14
  | 0xFus -> R.FR15
  | _ -> raise InvalidRegTypeException

let getRegXF = function
  | 0x0us -> R.XF0
  | 0x1us -> R.XF1
  | 0x2us -> R.XF2
  | 0x3us -> R.XF3
  | 0x4us -> R.XF4
  | 0x5us -> R.XF5
  | 0x6us -> R.XF6
  | 0x7us -> R.XF7
  | 0x8us -> R.XF8
  | 0x9us -> R.XF9
  | 0xAus -> R.XF10
  | 0xBus -> R.XF11
  | 0xCus -> R.XF12
  | 0xDus -> R.XF13
  | 0xEus -> R.XF14
  | 0xFus -> R.XF15
  | _ -> raise InvalidRegTypeException

let getRegDR = function
  | 0x0us -> R.DR0
  | 0x2us -> R.DR2
  | 0x4us -> R.DR4
  | 0x6us -> R.DR6
  | 0x8us -> R.DR8
  | 0xAus -> R.DR10
  | 0xCus -> R.DR12
  | 0xEus -> R.DR14
  | _ -> raise InvalidRegTypeException

let getRegXD = function
  | 0x0us -> R.XD0
  | 0x2us -> R.XD2
  | 0x4us -> R.XD4
  | 0x6us -> R.XD6
  | 0x8us -> R.XD8
  | 0xAus -> R.XD10
  | 0xCus -> R.XD12
  | 0xEus -> R.XD14
  | _ -> raise InvalidRegTypeException

let getRegFV = function
  | 0x0us -> R.FV0
  | 0x4us -> R.FV4
  | 0x8us -> R.FV8
  | 0xCus -> R.FV12
  | _ -> raise InvalidRegTypeException

let getBits (binary: uint16) (start: int)  (fin: int) =
  let s, e = if ((max start fin) = start) then start, fin else fin, start
  if (s - e + 1) > 15 then failwith "Bits outside range" else ()
  let mask = (pown 2 ((int) (s-e+1))) - 1 |> uint16
  (binary >>> (e - 1)) &&& mask

let get1Bit (binary: uint16) (pos: int) =
  ((binary >>> (pos - 1)) &&& 1us) = 1us

// Register-Fetching Functions:

let getReg1d b = getReg (getBits b 12 9)

let getReg1dBank b = getRegBank (getBits b 7 5)

let getReg1dFR b = getRegFR (getBits b 12 9)

let getReg1dXF b = getRegXF (getBits b 12 9)

let getReg1dDR b = getRegDR (getBits b 12 10 * 2us)

let getReg1dXD b = getRegXD (getBits b 12 10 * 2us)

let getReg1dFV b = getRegFV (getBits b 12 11 * 4us)

let getReg1s b = getReg (getBits b 8 5)

let getReg1sFR b = getRegFR (getBits b 8 5)

let getReg1sXF b = getRegXF (getBits b 8 5)

let getReg1sDR b = getRegDR (getBits b 8 6 * 2us)

let getReg1sXD b = getRegXD (getBits b 8 6 * 2us)

let getReg1sFV b = getRegFV (getBits b 10 9 * 4us)

let getDisp4b b = int32 (getBits b 4 1)

let getDisp8b b = int32 (getBits b 8 1)

let getDisp12b b = int32 (getBits b 12 1)