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

module internal B2R2.FrontEnd.PARISC.Helper

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
  | 0x10u -> R.FPR16
  | 0x11u -> R.FPR17
  | 0x12u -> R.FPR18
  | 0x13u -> R.FPR19
  | 0x14u -> R.FPR20
  | 0x15u -> R.FPR21
  | 0x16u -> R.FPR22
  | 0x17u -> R.FPR23
  | 0x18u -> R.FPR24
  | 0x19u -> R.FPR25
  | 0x1Au -> R.FPR26
  | 0x1Bu -> R.FPR27
  | 0x1Cu -> R.FPR28
  | 0x1Du -> R.FPR29
  | 0x1Eu -> R.FPR30
  | 0x1Fu -> R.FPR31
  | _ -> raise InvalidRegisterException

let getSRegister = function
  | 0x0u -> R.SR0
  | 0x1u -> R.SR1
  | 0x2u -> R.SR2
  | 0x3u -> R.SR3
  | 0x4u -> R.SR4
  | 0x5u -> R.SR5
  | 0x6u -> R.SR6
  | 0x7u -> R.SR7
  | _ -> raise InvalidRegisterException

let getCRegister = function
  | 0x0u -> R.CR0
  | 0x1u -> R.CR1
  | 0x2u -> R.CR2
  | 0x3u -> R.CR3
  | 0x4u -> R.CR4
  | 0x5u -> R.CR5
  | 0x6u -> R.CR6
  | 0x7u -> R.CR7
  | 0x8u -> R.CR8
  | 0x9u -> R.CR9
  | 0xAu -> R.CR10
  | 0xBu -> R.CR11
  | 0xCu -> R.CR12
  | 0xDu -> R.CR13
  | 0xEu -> R.CR14
  | 0xFu -> R.CR15
  | 0x10u -> R.CR16
  | 0x11u -> R.CR17
  | 0x12u -> R.CR18
  | 0x13u -> R.CR19
  | 0x14u -> R.CR20
  | 0x15u -> R.CR21
  | 0x16u -> R.CR22
  | 0x17u -> R.CR23
  | 0x18u -> R.CR24
  | 0x19u -> R.CR25
  | 0x1Au -> R.CR26
  | 0x1Bu -> R.CR27
  | 0x1Cu -> R.CR28
  | 0x1Du -> R.CR29
  | 0x1Eu -> R.CR30
  | 0x1Fu -> R.CR31
  | _ -> raise InvalidRegisterException

let getAddCondition = function
  | 0b00000u -> Some Completer.NEVER
  | 0b00100u -> Some Completer.EQ
  | 0b01000u -> Some Completer.LT
  | 0b01100u -> Some Completer.LE
  | 0b10000u -> Some Completer.NUV
  | 0b10100u -> Some Completer.ZNV
  | 0b11000u -> Some Completer.SV
  | 0b11100u -> Some Completer.OD
  | 0b00010u -> Some Completer.TR
  | 0b00110u -> Some Completer.NEQ
  | 0b01010u -> Some Completer.GE
  | 0b01110u -> Some Completer.GT
  | 0b10010u -> Some Completer.UV
  | 0b10110u -> Some Completer.VNZ
  | 0b11010u -> Some Completer.NSV
  | 0b11110u -> Some Completer.EV
  | 0b00001u -> Some Completer.DNEVER
  | 0b00101u -> Some Completer.DEQ
  | 0b01001u -> Some Completer.DLT
  | 0b01101u -> Some Completer.DLE
  | 0b10001u -> Some Completer.DNUV
  | 0b10101u -> Some Completer.DZNV
  | 0b11001u -> Some Completer.DSV
  | 0b11101u -> Some Completer.DOD
  | 0b00011u -> Some Completer.DTR
  | 0b00111u -> Some Completer.DNEQ
  | 0b01011u -> Some Completer.DGE
  | 0b01111u -> Some Completer.DGT
  | 0b10011u -> Some Completer.DUV
  | 0b10111u -> Some Completer.DVNZ
  | 0b11011u -> Some Completer.DNSV
  | 0b11111u -> Some Completer.DEV
  | _ -> None

let getCompSubCondition = function
  | 0b00000u -> Some Completer.NEVER
  | 0b00100u -> Some Completer.EQ
  | 0b01000u -> Some Completer.LT
  | 0b01100u -> Some Completer.LE
  | 0b10000u -> Some Completer.LTU
  | 0b10100u -> Some Completer.LEU
  | 0b11000u -> Some Completer.SV
  | 0b11100u -> Some Completer.OD
  | 0b00010u -> Some Completer.TR
  | 0b00110u -> Some Completer.NEQ
  | 0b01010u -> Some Completer.GE
  | 0b01110u -> Some Completer.GT
  | 0b10010u -> Some Completer.GEU
  | 0b10110u -> Some Completer.GTU
  | 0b11010u -> Some Completer.NSV
  | 0b11110u -> Some Completer.EV
  | 0b00001u -> Some Completer.DNEVER
  | 0b00101u -> Some Completer.DEQ
  | 0b01001u -> Some Completer.DLT
  | 0b01101u -> Some Completer.DLE
  | 0b10001u -> Some Completer.DLTU
  | 0b10101u -> Some Completer.DLEU
  | 0b11001u -> Some Completer.DSV
  | 0b11101u -> Some Completer.DOD
  | 0b00011u -> Some Completer.DTR
  | 0b00111u -> Some Completer.DNEQ
  | 0b01011u -> Some Completer.DGE
  | 0b01111u -> Some Completer.DGT
  | 0b10011u -> Some Completer.DGEU
  | 0b10111u -> Some Completer.DGTU
  | 0b11011u -> Some Completer.DNSV
  | 0b11111u -> Some Completer.DEV
  | _ -> None

let getCmpibCondition = function
  | 0b000u -> Some Completer.DLTU
  | 0b001u -> Some Completer.DEQ
  | 0b010u -> Some Completer.DLT
  | 0b011u -> Some Completer.DLE
  | 0b100u -> Some Completer.DGEU
  | 0b101u -> Some Completer.DNEQ
  | 0b110u -> Some Completer.DGE
  | 0b111u -> Some Completer.DGT
  | _ -> None

let getLogicalCondition = function
  | 0b00000u -> Some Completer.NEVER
  | 0b00100u -> Some Completer.EQ
  | 0b01000u -> Some Completer.LT
  | 0b11100u -> Some Completer.OD
  | 0b00010u -> Some Completer.TR
  | 0b00110u -> Some Completer.NEQ
  | 0b01010u -> Some Completer.GE
  | 0b01110u -> Some Completer.GT
  | 0b11110u -> Some Completer.EV
  | 0b00001u -> Some Completer.DNEVER
  | 0b00101u -> Some Completer.DEQ
  | 0b01001u -> Some Completer.DLT
  | 0b11101u -> Some Completer.DOD
  | 0b00011u -> Some Completer.DTR
  | 0b00111u -> Some Completer.DNEQ
  | 0b01011u -> Some Completer.DGE
  | 0b01111u -> Some Completer.DGT
  | 0b11111u -> Some Completer.DEV
  | _ -> None

let getUnitCondition = function
  | 0b00000u -> Some Completer.NEVER
  | 0b00100u -> Some Completer.SWZ
  | 0b01000u -> Some Completer.SBZ
  | 0b01100u -> Some Completer.SHZ
  | 0b10000u -> Some Completer.SDC
  | 0b10100u -> Some Completer.SWC
  | 0b11000u -> Some Completer.SBC
  | 0b11100u -> Some Completer.SHC
  | 0b00010u -> Some Completer.TR
  | 0b00110u -> Some Completer.NWZ
  | 0b01010u -> Some Completer.NBZ
  | 0b01110u -> Some Completer.NHZ
  | 0b10010u -> Some Completer.NDC
  | 0b10110u -> Some Completer.NWC
  | 0b11010u -> Some Completer.NBC
  | 0b11110u -> Some Completer.NHC
  | 0b00001u -> Some Completer.DNEVER
  | 0b00101u -> Some Completer.DSWZ
  | 0b01001u -> Some Completer.DSBZ
  | 0b01101u -> Some Completer.DSHZ
  | 0b10001u -> Some Completer.DSDC
  | 0b10101u -> Some Completer.DSWC
  | 0b11001u -> Some Completer.DSBC
  | 0b11101u -> Some Completer.DSHC
  | 0b00011u -> Some Completer.DTR
  | 0b00111u -> Some Completer.DNWZ
  | 0b01011u -> Some Completer.DNBZ
  | 0b01111u -> Some Completer.DNHZ
  | 0b10011u -> Some Completer.DNDC
  | 0b10111u -> Some Completer.DNWC
  | 0b11011u -> Some Completer.DNBC
  | 0b11111u -> Some Completer.DNHC
  | _ -> None

let getShfExtDepCondition = function
  | 0b0000u -> Some Completer.NEVER
  | 0b0010u -> Some Completer.EQ
  | 0b0100u -> Some Completer.LT
  | 0b0110u -> Some Completer.OD
  | 0b1000u -> Some Completer.TR
  | 0b1010u -> Some Completer.NEQ
  | 0b1100u -> Some Completer.GE
  | 0b1110u -> Some Completer.EV
  | 0b0001u -> Some Completer.DNEVER
  | 0b0011u -> Some Completer.DEQ
  | 0b0101u -> Some Completer.DLT
  | 0b0111u -> Some Completer.DOD
  | 0b1001u -> Some Completer.DTR
  | 0b1011u -> Some Completer.DNEQ
  | 0b1101u -> Some Completer.DGE
  | 0b1111u -> Some Completer.DEV
  | _ -> None

let getBranchOnBitCondition = function
  | 0b00u -> Some Completer.LT
  | 0b10u -> Some Completer.GE
  | 0b01u -> Some Completer.DLT
  | 0b11u -> Some Completer.DGE
  | _ -> None

let getIndexedCompleter = function
  | 0b00u -> None
  | 0b01u -> Some [| Completer.M |]
  | 0b10u -> Some [| Completer.S |]
  | _ -> Some [| Completer.SM |]

let getStoreBytesCmplt a m =
  match a, m with
  | 0u, 1u -> Some [| Completer.B; Completer.M |]
  | 1u, 0u -> Some [| Completer.E |]
  | 1u, 1u -> Some [| Completer.E; Completer.M |]
  | _ -> None

let getShortLoadStoreCmplt a m im5 =
  match a, m, im5 with
  | _, 0u, _ -> None
  | 0u, _, 0u -> Some [| Completer.O |]
  | 0u, _, _ -> Some [| Completer.MA |]
  | _ -> Some [| Completer.MB |]

let getLoadCacheHints cc = if cc = 2u then Some Completer.SL else None

let getLoadCWordCacheHints cc =
  if cc = 1u then Some Completer.CO else None

let getStoreCacheHints cc =
  match cc with
  | 1u -> Some Completer.BC
  | 2u -> Some Completer.SL
  | _ -> None

let getExtractCmplt se =
  Some [| if se = 0b1u then Completer.S else Completer.U |]

let getDepositCmplt nz = if nz = 0b1u then None else Some [| Completer.Z |]

let  getFloatFormat = function
  | 0b00u -> Some [| Completer.SGL |]
  | 0b01u -> Some [| Completer.DBL |]
  | 0b11u -> Some [| Completer.QUAD |]
  | _ -> None

let getFloatFloatFormat = function
  | 0b0000u -> Some [| Completer.SGL; Completer.SGL |]
  | 0b0001u -> Some [| Completer.SGL; Completer.DBL |]
  | 0b0011u -> Some [| Completer.SGL; Completer.QUAD |]
  | 0b0100u -> Some [| Completer.DBL; Completer.SGL |]
  | 0b0101u -> Some [| Completer.DBL; Completer.DBL |]
  | 0b0111u -> Some [| Completer.DBL; Completer.QUAD |]
  | 0b1100u -> Some [| Completer.QUAD; Completer.SGL |]
  | 0b1101u -> Some [| Completer.QUAD; Completer.DBL |]
  | 0b1111u -> Some [| Completer.QUAD; Completer.QUAD |]
  | 0b0010u | 0b1000u -> Some [| Completer.SGL |]
  | 0b0110u | 0b1001u -> Some [| Completer.DBL |]
  | 0b1011u | 0b1110u -> Some [| Completer.QUAD |]
  | _ -> None

let getFixedFloatFormat = function
  | 0b0000u -> Some [| Completer.W; Completer.SGL |]
  | 0b0001u -> Some [| Completer.W; Completer.DBL |]
  | 0b0011u -> Some [| Completer.W; Completer.QUAD |]
  | 0b0100u -> Some [| Completer.DW; Completer.SGL |]
  | 0b0101u -> Some [| Completer.DW; Completer.DBL |]
  | 0b0111u -> Some [| Completer.DW; Completer.QUAD |]
  | 0b1100u -> Some [| Completer.QW; Completer.SGL |]
  | 0b1101u -> Some [| Completer.QW; Completer.DBL |]
  | 0b1111u -> Some [| Completer.QW; Completer.QUAD |]
  | 0b0010u -> Some [| Completer.W |]
  | 0b0110u -> Some [| Completer.DW |]
  | 0b1110u -> Some [| Completer.QW |]
  | 0b1000u -> Some [| Completer.SGL |]
  | 0b1001u -> Some [| Completer.DBL |]
  | 0b1011u -> Some [| Completer.QUAD |]
  | _ -> None

let getFloatFixedFormat isT bit =
  let completer =
    match bit with
    | 0b0000u -> Some [| Completer.SGL; Completer.W |]
    | 0b0001u -> Some [| Completer.SGL; Completer.DW |]
    | 0b0011u -> Some [| Completer.SGL; Completer.QW |]
    | 0b0100u -> Some [| Completer.DBL; Completer.W |]
    | 0b0101u -> Some [| Completer.DBL; Completer.DW |]
    | 0b0111u -> Some [| Completer.DBL; Completer.QW |]
    | 0b1100u -> Some [| Completer.QUAD; Completer.W |]
    | 0b1101u -> Some [| Completer.QUAD; Completer.DW |]
    | 0b1111u -> Some [| Completer.QUAD; Completer.QW |]
    | 0b1000u -> Some [| Completer.W |]
    | 0b1001u -> Some [| Completer.DW |]
    | 0b1011u -> Some [| Completer.QW |]
    | 0b0010u -> Some [| Completer.SGL |]
    | 0b0110u -> Some [| Completer.DBL |]
    | 0b1110u -> Some [| Completer.QUAD |]
    | _ -> None
  if isT then Option.map2 Array.append (Some [| Completer.T |]) completer
  else completer

let getUFixedFloatFormat = function
  | 0b0000u -> Some [| Completer.UW; Completer.SGL |]
  | 0b0001u -> Some [| Completer.UW; Completer.DBL |]
  | 0b0011u -> Some [| Completer.UW; Completer.QUAD |]
  | 0b0100u -> Some [| Completer.UDW; Completer.SGL |]
  | 0b0101u -> Some [| Completer.UDW; Completer.DBL |]
  | 0b0111u -> Some [| Completer.UDW; Completer.QUAD |]
  | 0b1100u -> Some [| Completer.UQW; Completer.SGL |]
  | 0b1101u -> Some [| Completer.UQW; Completer.DBL |]
  | 0b1111u -> Some [| Completer.UQW; Completer.QUAD |]
  | 0b0010u -> Some [| Completer.UW |]
  | 0b0110u -> Some [| Completer.UDW |]
  | 0b1110u -> Some [| Completer.UQW |]
  | 0b1000u -> Some [| Completer.SGL |]
  | 0b1001u -> Some [| Completer.DBL |]
  | 0b1011u -> Some [| Completer.QUAD |]
  | _ -> None

let getFloatUFixedFormat isT bit =
  let completer =
    match bit with
    | 0b0000u -> Some [| Completer.SGL; Completer.UW |]
    | 0b0001u -> Some [| Completer.SGL; Completer.UDW |]
    | 0b0011u -> Some [| Completer.SGL; Completer.UQW |]
    | 0b0100u -> Some [| Completer.DBL; Completer.UW |]
    | 0b0101u -> Some [| Completer.DBL; Completer.UDW |]
    | 0b0111u -> Some [| Completer.DBL; Completer.UQW |]
    | 0b1100u -> Some [| Completer.QUAD; Completer.UW |]
    | 0b1101u -> Some [| Completer.QUAD; Completer.UDW |]
    | 0b1111u -> Some [| Completer.QUAD; Completer.UQW |]
    | 0b0010u -> Some [| Completer.SGL |]
    | 0b0110u -> Some [| Completer.DBL |]
    | 0b1110u -> Some [| Completer.QUAD |]
    | 0b1000u -> Some [| Completer.UW |]
    | 0b1001u -> Some [| Completer.UDW |]
    | 0b1011u -> Some [| Completer.UQW |]
    | _ -> None
  if isT then Option.map2 Array.append (Some [| Completer.T |]) completer
  else completer
let getFloatCompareCondition = function
  | 0b00000u -> Some Completer.FALSEQ
  | 0b00001u -> Some Completer.FALSE
  | 0b00010u -> Some Completer.FQ
  | 0b00011u -> Some Completer.FBGTLE
  | 0b00100u -> Some Completer.FEQ
  | 0b00101u -> Some Completer.FEQT
  | 0b00110u -> Some Completer.FQEQ
  | 0b00111u -> Some Completer.FBNEQ
  | 0b01000u -> Some Completer.FBQGE
  | 0b01001u -> Some Completer.FLT
  | 0b01010u -> Some Completer.FQLT
  | 0b01011u -> Some Completer.FBGE
  | 0b01100u -> Some Completer.FBQGT
  | 0b01101u -> Some Completer.FLE
  | 0b01110u -> Some Completer.FQLE
  | 0b01111u -> Some Completer.FBGT
  | 0b10000u -> Some Completer.FBQLE
  | 0b10001u -> Some Completer.FGT
  | 0b10010u -> Some Completer.FQGT
  | 0b10011u -> Some Completer.FBLE
  | 0b10100u -> Some Completer.FBQLT
  | 0b10101u -> Some Completer.FGE
  | 0b10110u -> Some Completer.FQGE
  | 0b10111u -> Some Completer.FBLT
  | 0b11000u -> Some Completer.FBQEQ
  | 0b11001u -> Some Completer.FNEQ
  | 0b11010u -> Some Completer.FBEQ
  | 0b11011u -> Some Completer.FBEQT
  | 0b11100u -> Some Completer.FBQ
  | 0b11101u -> Some Completer.FGTLE
  | 0b11110u -> Some Completer.TRUEQ
  | 0b11111u -> Some Completer.TRUE
  | _ -> None

let getFloatTestCondition = function
  | 0b00001u -> Some Completer.ACC
  | 0b00010u -> Some Completer.REJ
  | 0b00101u -> Some Completer.ACC8
  | 0b00110u -> Some Completer.REJ8
  | 0b01001u -> Some Completer.ACC6
  | 0b01101u -> Some Completer.ACC4
  | 0b10001u -> Some Completer.ACC2
  | _ -> None

let getRegFromRange bin high low =
  extract bin high low |> uint32 |> getRegister

let getSRegFromRange bin high low =
  extract bin high low |> uint32 |> getSRegister

let getCRegFromRange bin high low =
  extract bin high low |> uint32 |> getCRegister

let getFRegFromRange bin high low =
  extract bin high low |> uint32 |> getFRegister

let br b = getRegFromRange b 25u 21u

let sr b = getSRegFromRange b 15u 14u

let rd b = getRegFromRange b 4u 0u |> OpReg

let rs1 b = getRegFromRange b 20u 16u |> OpReg

let rs2 b = getRegFromRange b 25u 21u |> OpReg

let frd b = getFRegFromRange b 4u 0u |> OpReg

let frs1 b = getFRegFromRange b 20u 16u |> OpReg

let frs2 b = getFRegFromRange b 25u 21u |> OpReg

let cr b = getCRegFromRange b 25u 21u |> OpReg

let sa b spos size = extract b (spos + size) spos |> uint64 |> OpShiftAmount

let cCpos cp cpos = 63u - (cp <<< 5 ||| cpos) |> uint64 |> OpShiftAmount

let pos0to4 b = extract b 4u 0u |> uint64 |> OpImm

let pos5to9 b = extract b 9u 5u |> uint64 |> OpImm

let posP5to9 b = pickBit b 11u <<< 5 ||| extract b 9u 5u |> uint64 |> OpImm

let pos13to25 b = extract b 25u 13u |> uint64 |> OpImm

let pos16to20 b = extract b 20u 16u |> uint64 |> OpImm

let pos16to25 b = extract b 25u 16u |> uint64 |> OpImm

let pos21to25 b = extract b 25u 21u |> uint64 |> OpImm

let getRs1 b = OneOperand (rs1 b)

let getRs2 b = OneOperand (rs2 b)

let getRd b = OneOperand (rd b)

let getImm imm = OneOperand (OpImm imm)

let getRs2Rd b = TwoOperands (rs2 b, rd b)

let getFrs2Frd b = TwoOperands (frs2 b, frd b)

let getFrs2Frs1 b = TwoOperands (frs2 b, frs1 b)

let getFrs2Frs1Frd b = ThreeOperands (frs2 b, frs1 b, frd b)

let getRs1Rs2Imm b imm = ThreeOperands (rs1 b, rs2 b, OpImm imm)

let getRs1Rs2Rd b = ThreeOperands (rs1 b, rs2 b, rd b)

let getRs1Rs2 b = TwoOperands (rs1 b, rs2 b)

let getRs1Cr b = TwoOperands (rs1 b, cr b)

let getCrRd b = TwoOperands (cr b, rd b)

let getImmediate bin high low =
  extract bin high low |> uint64

let getImmLowSignExt bin high low wordSz =
  let imm = extract bin high low |> uint64
  let extended = (imm >>> 1) - (imm &&& 1UL <<< int (high - low))
  signExtend (int (high - low + 1u)) (RegType.toBitWidth wordSz) extended
  |> int64

let internal signExtend32 originalSize targetSize value =
  let originalMask = (1UL <<< originalSize) - 1UL
  let valueMasked = value &&& originalMask
  let signBit = valueMasked >>> originalSize - 1 &&& 1UL
  if signBit = 0UL then
    valueMasked
  else
    ~~~((1UL <<< targetSize) - 1UL) ||| ~~~((1UL <<< originalSize) - 1UL)
    ||| valueMasked

let getImmAssemble3 bin = pickBit bin 13u <<< 2 ||| extract bin 15u 14u

let srImm3 b = getImmAssemble3 b |> getSRegister

let getImmAssemble6 (x: uint32) (clen: uint32) =
  x <<< 5 ||| 32u - clen &&& 0x3fu |> uint64

let getImmAssembleExtDWord cl clen = (cl + 1u) * 32u - clen |> uint64

let getImmAssemble12 bin =
  let w1 = extract bin 12u 3u
  let bit10 = pickBit bin 2u
  let imm = w1 ||| (bit10 <<< 10) ||| (bin &&& 0x1u <<< 11) |> uint64
  signExtend32 12 32 imm <<< 2

let getImmAssemble16 bin =
  let bit0 = pickBit bin 0u
  let bit13to1 = extract bin 13u 1u
  let imm =
    bit13to1 ||| (bit0 <<< 15) ||| (bit0 <<< 14) ||| (bit0 <<< 13) |> uint64
  signExtend32 16 32 imm |> int64

let getImmAssemble17 bin =
  let w = extract bin 12u 3u
  let w2 = pickBit bin 2u <<< 10
  let w3 = extract bin 20u 16u <<< 11
  let w4 = bin &&& 1u <<< 16
  let v = w ||| w2 ||| w3 ||| w4
  signExtend32 17 32 (uint64 v) <<< 2

let getImmAssemble21 bin =
  let word = bin &&& 0x1FFFFFu
  let word = word <<< 11
  let w1 = pickBit word 11u
  let w2 = extract word 22u 12u
  let w3 = extract word 26u 25u
  let w4 = extract word 31u 27u
  let w5 = extract word 24u 23u
  let assemble21 =
    w1 <<< 20 ||| (w2 <<< 9) ||| (w3 <<< 7) ||| (w4 <<< 2) ||| w5 |> uint64
  signExtend32 21 32 assemble21 <<< 11

let getImmAssemble22 bin =
  let imm =
    extract bin 12u 3u |||
    (pickBit bin 2u <<< 10) |||
    (extract bin 20u 16u <<< 11) |||
    (extract bin 25u 21u <<< 16) |||
    (pickBit bin 0u <<< 21)
    |> uint64
  signExtend32 22 32 imm <<< 2

let getExtRs1Rs2Imm b imm wordSz =
  let sign = getImmLowSignExt b 20u 16u wordSz |> uint64
  ThreeOperands (OpImm sign, rs2 b, OpImm imm)

let getFrs2Frs1Imm b imm = ThreeOperands (frs2 b, frs1 b, OpImm imm)

let getRs1Rs2SarRd b = FourOperands (rs1 b, rs2 b, OpReg R.CR11, rd b)

let getRs1SarImm b imm = ThreeOperands (rs1 b, OpReg R.CR11, OpImm imm)

let getRs2SarLenRs1 b clen =
  FourOperands (rs2 b, OpReg R.CR11, OpImm clen, rs1 b)

let getRs1SarLenRs2 b clen =
  FourOperands (rs1 b, OpReg R.CR11, OpImm clen, rs2 b)

let getImmSarLenRs2 b imm clen =
  FourOperands (OpImm imm, OpReg R.CR11, OpImm clen, rs2 b)

let getImmCCposLenRs2 b imm cp cpos len =
  FourOperands (OpImm imm, cCpos cp cpos, OpImm len, rs2 b)

let getImmRs2 b imm = TwoOperands (OpImm imm, rs2 b)

let getImmRs2Rs1 b imm = ThreeOperands (OpImm imm, rs2 b, rs1 b)

let getRs1SaRd b spos size = ThreeOperands (rs1 b, sa b spos size, rd b)

let getRs2SaRd b spos size = ThreeOperands (rs2 b, sa b spos size, rd b)

let getRs1SaRs2Rd b spos size =
  FourOperands (rs1 b, sa b spos size, rs2 b, rd b)

let getRs1Rs2cCposRd b cp cpos =
  FourOperands (rs1 b, rs2 b, cCpos cp cpos, rd b)

let getRs1CCposLenRs2 b cp cpos len =
  FourOperands (rs1 b, cCpos cp cpos, OpImm len, rs2 b)

let getRs2Pos5to9LenRs1 b len =
  FourOperands (rs2 b, pos5to9 b, OpImm len, rs1 b)

let getRs2PosP5to9LenRs1 b len =
  FourOperands (rs2 b, posP5to9 b, OpImm len, rs1 b)

let getMemBase b wordSz =
  OneOperand (OpMem (br b, None, None, wordSz))

let getMemBaseRP b wordSz =
  TwoOperands (OpMem (br b, None, None, wordSz), OpReg R.GR2)

let getMemBaseOffRs1 b offset wordSz =
  TwoOperands (OpMem (br b, None, Some (Imm offset), wordSz), rs1 b)

let getMemBaseRegOff b offset wordSz =
  OneOperand (OpMem (br b, None, Some (Reg offset), wordSz))

let getMemSpaceOff b space offset wordSz =
  OneOperand (OpMem (br b, Some space, Some (Imm offset), wordSz))

let getMemSpaceOffSr0R31 b space offset wordSz =
  ThreeOperands (OpMem (br b, Some space, Some (Imm offset), wordSz),
    OpReg R.SR0, OpReg R.GR31)

let getMemSpaceRegOff b space offset wordSz =
  OneOperand (OpMem (br b, Some space, Some (Reg offset), wordSz))

let getMemSpaceRd b space wordSz =
  TwoOperands (OpMem (br b, Some space, None, wordSz), rd b)

let getMemSpaceOffRs1 b space offset wordSz =
  TwoOperands (OpMem (br b, Some space, Some (Imm offset), wordSz), rs1 b)

let getMemOffRd b offset wordSz =
  TwoOperands (OpMem (br b, None, Some (Imm offset), wordSz), rd b)

let getMemSpaceOffRd b space offset wordSz =
  TwoOperands (OpMem (br b, Some space, Some (Imm offset), wordSz), rd b)

let getRdMemSpaceOff b space offset wordSz =
  TwoOperands (rd b, OpMem (br b, Some space, Some (Imm offset), wordSz))

let getFrdMemSpaceOff b space offset wordSz =
  TwoOperands (frd b, OpMem (br b, Some space, Some (Imm offset), wordSz))

let getMemSpaceOffFrd b space offset wordSz =
  TwoOperands (OpMem (br b, Some space, Some (Imm offset), wordSz), frd b)

let getRs1MemOff b offset wordSz =
  TwoOperands (rs1 b, OpMem (br b, None, Some (Imm offset), wordSz))

let getRs1MemSpaceOff b space offset wordSz =
  TwoOperands (rs1 b, OpMem (br b, Some space, Some (Imm offset), wordSz))

let getMemSpaceOffFrs1 b space offset wordSz =
  TwoOperands (OpMem (br b, Some space, Some (Imm offset), wordSz), frs1 b)

let getFrs1MemSpaceOff b space offset wordSz =
  TwoOperands (frs1 b, OpMem (br b, Some space, Some (Imm offset), wordSz))

let getMemRegOffRd b offset wordSz =
  TwoOperands (OpMem (br b, None, Some (Reg offset), wordSz), rd b)

let getMemSpaceRegOffRd b space offset wordSz =
  TwoOperands (OpMem (br b, Some space, Some (Reg offset), wordSz), rd b)

let getRdMemSpaceRegOff b space offset wordSz =
  TwoOperands (rd b, OpMem (br b, Some space, Some (Reg offset), wordSz))

let getFrdMemSpaceRegOff b space offset wordSz =
  TwoOperands (frd b, OpMem (br b, Some space, Some (Reg offset), wordSz))

let getMemSpaceRegOffFrd b space offset wordSz =
  TwoOperands (OpMem (br b, Some space, Some (Reg offset), wordSz), frd b)

let getMemSpaceRs1Rd b space wordSz =
  ThreeOperands (OpMem (br b, Some space, None, wordSz), rs1 b, rd b)

let getMemSpaceIRs1Rd b space wordSz =
  ThreeOperands (OpMem (br b, Some space, None, wordSz), pos16to20 b, rd b)

let getPos0Pos13 b = TwoOperands (pos0to4 b, pos13to25 b)

let getPos16to25Rd b = TwoOperands (pos16to25 b, rd b)

let getRs1Pos21to25Imm b imm = ThreeOperands (rs1 b, pos21to25 b, OpImm imm)

let getRegRd b reg = TwoOperands (OpReg reg, rd b)

let getRs1Sr b sReg = TwoOperands (rs1 b, OpReg sReg)

let getSrRd b sReg = TwoOperands (OpReg sReg, rd b)

let getFe2Fe1Cbit b cbit =
  ThreeOperands (frs2 b, frs1 b, OpImm cbit)

let getFrs2Frs1FraFrd b =
  let ra = extract b 15u 13u <<< 2 ||| extract b 10u 9u
  let fra = ra |> getFRegister |> OpReg
  FourOperands (frs2 b, frs1 b, fra, frd b)
