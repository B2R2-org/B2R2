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

let isTwoBytes b =
  b &&& 3us <> 3us

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
  struct (opcode, getRs1Rs2BImm bin)

let parseLoad bin =
  match getFunc3 bin with
  | 0b000u -> struct (Op.LB, getRdRs1IImmAcc bin 8<rt>)
  | 0b001u -> struct (Op.LH, getRdRs1IImmAcc bin 16<rt>)
  | 0b010u -> struct (Op.LW, getRdRs1IImmAcc bin 32<rt>)
  | 0b011u -> struct (Op.LD, getRdRs1IImmAcc bin 64<rt>)
  | 0b100u -> struct (Op.LBU, getRdRs1IImmAcc bin 8<rt>)
  | 0b110u -> struct (Op.LWU, getRdRs1IImmAcc bin 32<rt>)
  | 0b101u -> struct (Op.LHU, getRdRs1IImmAcc bin 16<rt>)
  | _ -> raise ParsingFailureException

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
      if extract bin 31u 26u = 0b000000u then Op.SRLI
      elif extract bin 31u 26u = 0b010000u then Op.SRAI
      else raise ParsingFailureException
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
  let opcode = if pickBit bin 20u = 1u then Op.ECALL else Op.EBREAK
  struct (opcode, NoOperand)

let parseFence bin =
  let opcode = if pickBit bin 12u = 0u then Op.FENCE else Op.FENCEdotI
  if opcode = Op.FENCEdotI then
    struct (opcode, NoOperand)
  else
    if getPred bin = 0b0011uy && getSucc bin = 0b0011uy then
      struct (Op.FENCEdotTSO, NoOperand)
    else
      struct (opcode, getPredSucc bin)

let parseFloatArith bin =
  match extract bin 31u 25u with
  | 0b0000000u -> struct (Op.FADDdotS, getFRdRs1Rs2Rm bin)
  | 0b0000100u -> struct (Op.FSUBdotS, getFRdRs1Rs2Rm bin)
  | 0b0001000u -> struct (Op.FMULdotS, getFRdRs1Rs2Rm bin)
  | 0b0001100u -> struct (Op.FDIVdotS, getFRdRs1Rs2Rm bin)
  | 0b0101100u ->
    if extract bin 24u 20u = 0u then struct (Op.FSQRTdotS, getFRdRs1Rm bin)
    else raise ParsingFailureException
  | 0b0010000u ->
    match getFunc3 bin with
    | 0b000u -> struct (Op.FSGNJdotS, getFRdRs1Rs2Rm bin)
    | 0b001u -> struct (Op.FSGNJNdotS, getFRdRs1Rs2 bin)
    | 0b010u -> struct (Op.FSGNJXdotS, getFRdRs1Rs2 bin)
    | _ -> raise ParsingFailureException
  | 0b0010100u ->
    match getFunc3 bin with
    | 0b000u -> struct (Op.FMINdotS, getFRdRs1Rs2 bin)
    | 0b001u -> struct (Op.FMAXdotS, getFRdRs1Rs2 bin)
    | _ -> raise ParsingFailureException
  | 0b1100000u ->
    match getRs2 bin with
    | 0b00000u -> struct (Op.FCVTdotWdotS, getFRdRs1Rm bin)
    | 0b00001u -> struct (Op.FCVTdotWUdotS, getFRdRs1 bin)
    | 0b00010u -> struct (Op.FCVTdotLdotS, getFRdRs1Rm bin)
    | 0b00011u -> struct (Op.FCVTdotLUdotS, getFRdRs1Rm bin)
    | _ -> raise ParsingFailureException
  | 0b1110000u ->
    if getFunc3 bin = 0b000u && getRs2 bin = 0b00000u then
      struct (Op.FMVdotXdotW, getFRdRs1 bin)
    elif getFunc3 bin = 0b001u && getRs2 bin = 0b00000u then
      struct (Op.FCLASSdotS, getFRdRs1 bin)
    else
      raise ParsingFailureException
  | 0b1010000u ->
    match getFunc3 bin with
    | 0b010u -> struct (Op.FEQdotS, getFRdRs1Rs2 bin)
    | 0b001u -> struct (Op.FLTdotS, getFRdRs1Rs2 bin)
    | 0b000u -> struct (Op.FLEdotS, getFRdRs1Rs2 bin)
    | _ -> raise ParsingFailureException
  | 0b1101000u ->
    match getRs2 bin with
    | 0b00000u -> struct (Op.FCVTdotSdotW, getFRdRs1Rm bin)
    | 0b00001u -> struct (Op.FCVTdotSdotWU, getFRdRs1Rm bin)
    | 0b00010u -> struct (Op.FCVTdotSdotL, getFRdRs1Rm bin)
    | 0b00011u -> struct (Op.FCVTdotSdotLU, getFRdRs1Rm bin)
    | _ -> raise ParsingFailureException
  | 0b1111000u ->
    if getRs2 bin = 0b00000u && getFunc3 bin = 0b000u then
      struct (Op.FMVdotWdotX, getFRdRs1 bin)
    else
      raise ParsingFailureException
  | 0b0000001u -> struct (Op.FADDdotD, getFRdRs1Rs2Rm bin)
  | 0b0000101u -> struct (Op.FSUBdotD, getFRdRs1Rs2Rm bin)
  | 0b0001001u -> struct (Op.FMULdotD, getFRdRs1Rs2Rm bin)
  | 0b0001101u -> struct (Op.FDIVdotD, getFRdRs1Rs2Rm bin)
  | 0b0101101u ->
    if getRs2 bin = 0u then struct (Op.FSQRTdotD, getFRdRs1Rm bin)
    else raise ParsingFailureException
  | 0b0010001u ->
    match getFunc3 bin with
    | 0b000u -> struct (Op.FSGNJdotD, getFRdRs1Rs2 bin)
    | 0b001u -> struct (Op.FSGNJNdotD, getFRdRs1Rs2 bin)
    | 0b010u -> struct (Op.FSGNJXdotD, getFRdRs1Rs2 bin)
    | _ -> raise ParsingFailureException
  | 0b0010101u ->
    if getFunc3 bin = 0b000u then struct (Op.FMINdotD, getFRdRs1Rs2 bin)
    elif getFunc3 bin = 0b001u then struct (Op.FMAXdotD, getFRdRs1Rs2 bin)
    else raise ParsingFailureException
  | 0b0100000u ->
    if getRs2 bin = 0b00001u then struct (Op.FCVTdotSdotD, getFRdRs1Rm bin)
    else raise ParsingFailureException
  | 0b0100001u ->
    if getRs2 bin = 0b00000u then struct (Op.FCVTdotDdotS, getFRdRs1Rm bin)
    else raise ParsingFailureException
  | 0b1010001u ->
    match getFunc3 bin with
    | 0b010u -> struct (Op.FEQdotD, getFRdRs1Rs2 bin)
    | 0b000u -> struct (Op.FLTdotD, getFRdRs1Rs2 bin)
    | 0b001u -> struct (Op.FLEdotD, getFRdRs1Rs2 bin)
    | _ -> raise ParsingFailureException
  | 0b1110001u ->
    if getRs2 bin = 0b00000u && getFunc3 bin = 0b001u then
      struct (Op.FCLASSdotD, getFRdRs1 bin)
    elif getRs2 bin = 0b00000u && getFunc3 bin = 0b000u then
      struct (Op.FMVdotXdotD, getFRdRs1 bin)
    else
      raise ParsingFailureException
  | 0b1100001u ->
    match getRs2 bin with
    | 0b00000u -> struct (Op.FCVTdotWdotD, getFRdRs1 bin)
    | 0b00001u -> struct (Op.FCVTdotWUdotD, getFRdRs1 bin)
    | 0b00010u -> struct (Op.FCVTdotLdotD, getFRdRs1Rm bin)
    | 0b00011u -> struct (Op.FCVTdotLUdotD, getFRdRs1Rm bin)
    | _ -> raise ParsingFailureException
  | 0b1101001u ->
    match getRs2 bin with
    | 0b00000u -> struct (Op.FCVTdotDdotW, getFRdRs1Rm bin)
    | 0b00001u -> struct (Op.FCVTdotDdotWU, getFRdRs1Rm bin)
    | 0b00010u -> struct (Op.FCVTdotDdotL, getFRdRs1Rm bin)
    | 0b00011u -> struct (Op.FCVTdotDdotLU, getFRdRs1Rm bin)
    | _ -> raise ParsingFailureException
  | 0b1111001u ->
    if getRs2 bin = 0b00000u && getFunc3 bin = 0b000u then
      struct (Op.FMVdotDdotX, getFRdRs1 bin)
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
    | 0b1000011u -> struct (Op.FMADDdotS, getFRdRs1Rs2Rs3Rm bin)
    | 0b1000111u -> struct (Op.FMSUBdotS, getFRdRs1Rs2Rs3Rm bin)
    | 0b1001011u -> struct (Op.FNMSUBdotS, getFRdRs1Rs2Rs3Rm bin)
    | 0b1001111u -> struct (Op.FNMADDdotS, getFRdRs1Rs2Rs3Rm bin)
    | _ -> raise ParsingFailureException
  elif extract bin 26u 25u = 0b01u then
    match extract bin 6u 0u with
    | 0b1000011u -> struct (Op.FMADDdotD, getFRdRs1Rs2Rs3Rm bin)
    | 0b1000111u -> struct (Op.FMSUBdotD, getFRdRs1Rs2Rs3Rm bin)
    | 0b1001011u -> struct (Op.FNMSUBdotD, getFRdRs1Rs2Rs3Rm bin)
    | 0b1001111u -> struct (Op.FNMADDdotD, getFRdRs1Rs2Rs3Rm bin)
    | _ -> raise ParsingFailureException
  else
    raise ParsingFailureException

let parseFloatLoad bin =
  match extract bin 14u 12u with
  | 0b011u -> struct (Op.FLD, getFRdRs1Addr bin 64<rt>)
  | 0b010u -> struct (Op.FLW, getFRdRs1Addr bin 32<rt>)
  | _ -> raise ParsingFailureException

let parseFloatStore bin =
  match extract bin 14u 12u with
  | 0b011u -> struct (Op.FSD, getFRs2Rs1Addr bin 64<rt>)
  | 0b010u -> struct (Op.FSW, getFRs2Rs1Addr bin 32<rt>)
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
  | 0b001u -> struct (Op.CSRRW, getRdCSRRs1 bin)
  | 0b010u -> struct (Op.CSRRS, getRdCSRRs1 bin)
  | 0b011u -> struct (Op.CSRRC, getRdCSRRs1 bin)
  | 0b101u -> struct (Op.CSRRWI, getRdCSRUImm bin)
  | 0b110u -> struct (Op.CSRRSI, getRdCSRUImm bin)
  | 0b111u -> struct (Op.CSRRCI, getRdCSRUImm bin)
  | _ -> raise ParsingFailureException

let parseRegisterBasedLoadStore bin =
  match extract bin 15u 13u with
  | 0b010u ->
    let dest = crdComp bin
    let from2to2 = pickBit bin 6u <<< 2
    let from3to5 = extract bin 12u 10u <<< 3
    let from6to6 = pickBit bin 5u <<< 6
    let imm = from2to2 ||| from3to5 ||| from6to6 |> int64 |> Imm |> Some
    let b = getCompRegFrom97 bin
    struct (Op.CdotLW, TwoOperands (dest, OpMem (b, imm, 32<rt>)))
  | 0b011u ->
    let dest = crdComp bin
    let from3to5 = extract bin 12u 10u
    let from6to7 = extract bin 6u 5u
    let imm = from3to5 ||| from6to7 |> int64 |> Imm |> Some
    let b = getCompRegFrom97 bin
    struct (Op.CdotLD, TwoOperands (dest, OpMem (b, imm, 64<rt>)))
  | 0b001u ->
    let dest = cfrdComp bin
    let from3to5 = extract bin 12u 10u <<< 3
    let from6to7 = extract bin 6u 5u <<< 6
    let imm = from3to5 ||| from6to7 |> int64 |> Imm |> Some
    let b = getCompRegFrom97 bin
    struct (Op.CdotFLD, TwoOperands (dest, OpMem (b, imm, 64<rt>)))
  | 0b110u ->
    let src = csrc2Comp bin
    let b = getCompRegFrom97 bin
    let from2to2 = pickBit bin 6u <<< 2
    let from3to5 = extract bin 10u 12u <<< 3
    let from6to6 = pickBit bin 5u <<< 6
    let imm = from2to2 ||| from3to5 ||| from6to6 |> int64 |> Imm |> Some
    struct (Op.CdotSW, TwoOperands (src, OpMem (b, imm, 32<rt>)))
  | 0b111u ->
    let src = csrc2Comp bin
    let b = getCompRegFrom97 bin
    let from3to5 = extract bin 10u 12u <<< 3
    let from6to7 = extract bin 6u 5u <<< 6
    let imm = from3to5 ||| from6to7 |> int64 |> Imm |> Some
    struct (Op.CdotSD, TwoOperands (src, OpMem (b, imm, 64<rt>)))
  | 0b101u ->
    let src = cfrs2Comp bin
    let b = getCompRegFrom97 bin
    let from3to5 = extract bin 10u 12u <<< 3
    let from6to7 = extract bin 6u 5u <<< 6
    let imm = from3to5 ||| from6to7 |> int64 |> Imm |> Some
    struct (Op.CdotFSD, TwoOperands (src, OpMem (b, imm, 64<rt>)))
  | _ -> Utils.impossible ()

let parseStackBasedLoadStore bin =
  match extract bin 15u 13u with
  | 0b010u ->
    let from2to4 = extract bin 4u 6u <<< 2
    let from5to5 = pickBit bin 12u <<< 5
    let from6to7 = extract bin 2u 3u <<< 6
    let imm = from2to4 ||| from5to5 ||| from6to7 |> int64 |> Imm |> Some
    let dest = crd bin
    if extract bin 11u 7u = 0u then raise ParsingFailureException
    else ()
    struct (Op.CdotLWSP, TwoOperands (dest, OpMem (R.X2, imm, 32<rt>)))
  | 0b011u ->
    let from3to4 = extract bin 6u 5u <<< 3
    let from5to5 = pickBit bin 12u <<< 5
    let from6to8 = extract bin 2u 4u <<< 6
    let imm = from3to4 ||| from5to5 ||| from6to8 |> int64 |> Imm |> Some
    let dest = crd bin
    if extract bin 11u 7u = 0u then raise ParsingFailureException
    else ()
    struct (Op.CdotLDSP, TwoOperands (dest, OpMem (R.X2, imm, 64<rt>)))
  | 0b001u ->
    let from3to4 = extract bin 6u 5u <<< 3
    let from5to5 = pickBit bin 12u <<< 5
    let from6to8 = extract bin 2u 4u <<< 6
    let imm = from3to4 ||| from5to5 ||| from6to8 |> int64 |> Imm |> Some
    let dest = cfrd bin
    struct (Op.CdotFLDSP, TwoOperands (dest, OpMem (R.X2, imm, 64<rt>)))
  | 0b110u ->
    let rs2 = crs2 bin
    let from2to5 = extract bin 12u 9u <<< 2
    let from6to7 = extract bin 8u 7u <<< 6
    let imm = from2to5 ||| from6to7 |> int64 |> Imm |> Some
    struct (Op.CdotSWSP, TwoOperands (rs2, OpMem (R.X2, imm, 32<rt>)))
  | 0b111u ->
    let rs2 = crs2 bin
    let from3to5 = extract bin 12u 10u <<< 3
    let from6to8 = extract bin 9u 7u <<< 6
    let imm = from3to5 ||| from6to8 |> int64 |> Imm |> Some
    struct (Op.CdotSDSP, TwoOperands (rs2, OpMem (R.X2, imm, 64<rt>)))
  | 0b101u ->
    let rs2 = cfrs2 bin
    let from3to5 = extract bin 12u 10u <<< 2
    let from6to8 = extract bin 9u 7u <<< 6
    let imm = from3to5 ||| from6to8 |> int64 |> Imm |> Some
    struct (Op.CdotFSDSP, TwoOperands (rs2, OpMem (R.X2, imm, 64<rt>)))
  | _ -> Utils.impossible ()

let parseCdotADDI4SPN bin =
  let from2to2 = pickBit bin 6u <<< 2
  let from3to3 = pickBit bin 5u <<< 3
  let from4to5 = extract bin 12u 11u <<< 4
  let from6to9 = extract bin 10u 7u <<< 6
  let imm = from2to2 ||| from3to3 ||| from4to5 ||| from6to9 |> uint64
  let dest = csrc2Comp bin
  if imm = 0uL then raise ParsingFailureException
  else ()
  struct (Op.CdotADDI4SPN, ThreeOperands (dest, R.X2 |> OpReg, imm |> OpImm))

let parseCdotJ bin =
  let from1to3 = extract bin 5u 3u <<< 1
  let from5to5 = pickBit bin 2u <<< 5
  let from7to7 = pickBit bin 6u <<< 7
  let from6to6 = pickBit bin 7u <<< 6
  let from10to10 = pickBit bin 8u <<< 10
  let from8to9 = extract bin 10u 9u <<< 8
  let from4to4 = pickBit bin 11u <<< 4
  let from11to11 = pickBit bin 12u <<< 11
  let imm = from1to3 ||| from4to4 ||| from5to5 ||| from6to6 ||| from7to7
                ||| from8to9 ||| from10to10 ||| from11to11 |> int64
  struct (Op.CdotJ, TwoOperands (R.X0 |> OpReg, imm |> Relative |> OpAddr))

let parseCdotBranch bin =
  let opcode = if extract bin 15u 13u = 0b111u then Op.CdotBEQZ
                else Op.CdotBNEZ
  let src = csrc1Comp bin
  let from1to2 = extract bin 3u 4u <<< 1
  let from3to4 = extract bin 10u 11u <<< 3
  let from5to5 = pickBit bin 2u <<< 5
  let from6to7 = extract bin 6u 5u <<< 6
  let from8to8 = pickBit bin 12u <<< 8
  let imm = from1to2 ||| from3to4 ||| from5to5 ||| from6to7 ||| from8to8
            |> int64 |> Relative |> OpAddr
  struct (opcode, ThreeOperands (src, R.X0 |> OpReg, imm))

let parseCdotADDIW bin =
  if extract bin 11u 7u = 0u then raise ParsingFailureException
  else ()
  let imm = (extract bin 6u 2u) ||| (pickBit bin 12u <<< 5) |> uint64
  let signExtended = signExtend 6 32 imm |> OpImm
  let dest = crd bin
  struct (Op.CdotADDIW, ThreeOperands (dest, dest, signExtended))

let parseCdotLI bin =
  let dest = crd bin
  let imm = (extract bin 6u 2u) ||| (pickBit bin 12u <<< 5) |> uint64
  let signExtended = signExtend 6 32 imm
  struct (Op.CdotLI, ThreeOperands (dest, R.X0 |> OpReg, signExtended |> OpImm))

let parseCdotANDI bin =
  let dest = csrc1Comp bin
  let from0to4 = extract bin 6u 2u
  let from5to5 = pickBit bin 12u <<< 5
  let imm = from0to4 ||| from5to5 |> uint64
  let signExtended = signExtend 6 32 imm
  struct (Op.CdotANDI, ThreeOperands (dest, dest, signExtended |> OpImm))

let parseCdotSLLI bin =
  let from0to4 = extract bin 6u 2u
  let from5to5 = pickBit bin 12u <<< 5
  let imm = from0to4 ||| from5to5 |> uint64
  let dest = crd bin
  struct (Op.CdotSLLI, ThreeOperands (dest, dest, imm |> OpShiftAmount))

let parseCdotSR bin =
  let dest = csrc1Comp bin
  let from0to4 = extract bin 6u 2u
  let from5to5 = pickBit bin 12u <<< 5
  let imm = from0to4 ||| from5to5 |> uint64
  let opcode = if extract bin 11u 10u = 0u then Op.CdotSRLI else Op.CdotSRAI
  struct (opcode, ThreeOperands (dest, dest, imm |> OpShiftAmount))

let parseCdotLUIADDI16SP bin =
  if extract bin 11u 7u = 2u then
    let from4to4 = pickBit bin 4u <<< 4
    let from5to5 = pickBit bin 2u <<< 5
    let from6to6 = pickBit bin 5u <<< 6
    let from7to8 = extract bin 4u 3u <<< 7
    let from9to9 = pickBit bin 12u
    let imm = from4to4 ||| from5to5 ||| from6to6 ||| from7to8 ||| from9to9
              |> uint64
    if imm = 0uL then raise ParsingFailureException
    else ()
    let signExtended = signExtend 10 32 imm |> OpImm
    struct (Op.CdotADDI16SP,
            ThreeOperands (R.X2 |> OpReg, R.X2 |> OpReg, signExtended))
  else
    let imm = (extract bin 6u 2u <<< 12) ||| (pickBit bin 12u <<< 17)
    if imm = 0u then raise ParsingFailureException
    else ()
    let dest = crd bin
    struct (Op.CdotLUI, TwoOperands (dest, imm |> uint64 |> OpImm))

let parseCdotArith bin =
  let opcode =
    match (pickBit bin 12u) <<< 2 ||| extract bin 6u 5u with
    | 0b000u -> Op.CdotSUB
    | 0b001u -> Op.CdotXOR
    | 0b010u -> Op.CdotOR
    | 0b011u -> Op.CdotAND
    | 0b100u -> Op.CdotSUBW
    | 0b101u -> Op.CdotADDW
    | _ -> raise ParsingFailureException
  let dest = csrc1Comp bin
  let src = crdComp bin
  struct (opcode, ThreeOperands (dest, dest, src))

let parseCdotJrMvEBREAKJalrAdd bin =
  if pickBit bin 12u = 0u then
    if extract bin 6u 2u = 0u then
      if extract bin 11u 7u = 0u then raise ParsingFailureException
      else struct (Op.CdotJR, TwoOperands (R.X1 |> OpReg,
                  RelativeBase (getRegFrom62 bin, 0uL) |> OpAddr))
    else
      let dest = crd bin
      let src = crs2 bin
      struct (Op.CdotMV, ThreeOperands (dest, R.X0 |> OpReg, src))
  else
    if extract bin 6u 2u = 0u then
      if extract bin 11u 7u = 0u then
        struct (Op.CdotEBREAK, NoOperand)
      else
        struct (Op.CdotJALR, TwoOperands (R.X1 |> OpReg,
                RelativeBase (getRegFrom117 bin, 0uL) |> OpAddr))
    else
      let dest = crd bin
      let src = crs2 bin
      struct (Op.CdotADD, ThreeOperands (dest, dest, src))

let parseCdotNOPADDI bin =
  if extract bin 11u 7u = 0u then
    struct (Op.CdotNOP, NoOperand)
  else
    let imm = (extract bin 6u 2u) ||| (pickBit bin 12u <<< 5) |> uint64
    let signExtended = signExtend 6 32 imm |> OpImm
    let dest = crd bin
    struct (Op.CdotADDI, ThreeOperands (dest, dest, signExtended))

let parseQuadrant0 bin =
  match extract bin 15u 13u with
  | 0b000u -> parseCdotADDI4SPN bin
  | 0b001u
  | 0b010u
  | 0b011u
  | 0b101u
  | 0b110u
  | 0b111u -> parseRegisterBasedLoadStore bin
  | _ -> raise ParsingFailureException

let parseQuadrant1 bin =
  match extract bin 15u 13u with
  | 0b000u -> parseCdotNOPADDI bin
  | 0b001u -> parseCdotADDIW bin
  | 0b010u -> parseCdotLI bin
  | 0b011u -> parseCdotLUIADDI16SP bin
  | 0b100u ->
    match extract bin 11u 10u with
    | 0b00u
    | 0b01u -> parseCdotSR bin
    | 0b10u -> parseCdotANDI bin
    | 0b11u -> parseCdotArith bin
    | _ -> Utils.impossible ()
  | 0b101u -> parseCdotJ bin
  | 0b110u
  | 0b111u -> parseCdotBranch bin
  | _ -> raise ParsingFailureException

let parseQuadrant2 bin =
  match extract bin 15u 13u with
  | 0b000u -> parseCdotSLLI bin
  | 0b001u
  | 0b010u
  | 0b011u
  | 0b101u
  | 0b110u
  | 0b111u -> parseStackBasedLoadStore bin
  | 0b100u -> parseCdotJrMvEBREAKJalrAdd bin
  | _ -> Utils.impossible ()

let private parseCompressedInstruction bin =
  match extract bin 0u 1u with
  | 0b00u -> parseQuadrant0 bin
  | 0b01u -> parseQuadrant1 bin
  | 0b10u -> parseQuadrant2 bin
  | _ -> Utils.impossible ()

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
  let bin = reader.ReadUInt16 (span, 0)
  let struct (op, operands, instrLen) =
    match isTwoBytes bin with
    | true ->
      let bin = uint32 bin
      let struct (op, operands) = bin |> parseCompressedInstruction
      struct (op, operands, 2u)
    | false ->
      let b2 = reader.ReadUInt16 (span, 2)
      let bin = ((uint32 b2) <<< 16) + (uint32 bin)
      let struct (op, operands) = bin |> parseInstruction
      struct (op, operands, 4u)
  let insInfo =
    { Address = addr
      NumBytes = instrLen
      Opcode = op
      Operands = operands
      OperationSize = 32<rt> }
  RISCV64Instruction (addr, instrLen, insInfo)

// vim: set tw=80 sts=2 sw=2:
