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

module internal B2R2.FrontEnd.RISCV.ParsingMain

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.ParsingUtils
open B2R2.FrontEnd.RISCV.Helper

let isTwoBytes b = b &&& 3us <> 3us

let getRegister = function
  | _ -> raise ParsingFailureException

let parseLUI bin wordSize = struct (Op.LUI, getRdImm20 bin wordSize)

let parseAUIPC bin wordSize = struct (Op.AUIPC, getPCRdImm20 bin wordSize)

let parseBranch bin wordSize =
  let opcode =
    match getFunc3 bin with
    | 0b000u -> Op.BEQ
    | 0b001u -> Op.BNE
    | 0b100u -> Op.BLT
    | 0b101u -> Op.BGE
    | 0b110u -> Op.BLTU
    | 0b111u -> Op.BGEU
    | _ -> raise ParsingFailureException
  struct (opcode, getRs1Rs2BImm bin wordSize)

let parseLoad bin wordSize =
  let struct (opcode, acc) =
    match getFunc3 bin with
    | 0b000u -> struct (Op.LB, 8<rt>)
    | 0b001u -> struct (Op.LH, 16<rt>)
    | 0b010u -> struct (Op.LW, 32<rt>)
    | 0b011u -> struct (rv64Only wordSize Op.LD, 64<rt>)
    | 0b100u -> struct (Op.LBU, 8<rt>)
    | 0b110u -> struct (rv64Only wordSize Op.LWU, 32<rt>)
    | 0b101u -> struct (Op.LHU, 16<rt>)
    | _ -> raise ParsingFailureException
  struct (opcode, getRdRs1IImmAcc bin acc wordSize)

let parseStore bin wordSize =
  let struct (opcode, acc) =
    match getFunc3 bin with
    | 0b000u -> struct (Op.SB, 8<rt>)
    | 0b001u -> struct (Op.SH, 16<rt>)
    | 0b010u -> struct (Op.SW, 32<rt>)
    | 0b011u -> struct (rv64Only wordSize Op.SD, 64<rt>)
    | _ -> raise ParsingFailureException
  struct (opcode, getRs2Rs1SImm bin acc wordSize)

let parseOpImm bin wordSize =
  let opcode =
    match getFunc3 bin with
    | 0b000u ->
      Op.ADDI
    | 0b010u ->
      Op.SLTI
    | 0b011u ->
      Op.SLTIU
    | 0b100u ->
      Op.XORI
    | 0b110u ->
      Op.ORI
    | 0b111u ->
      Op.ANDI
    (* Shifts *)
    | 0b001u ->
      if Bits.extract bin 31u 26u = 0b000000u then Op.SLLI
      else raise ParsingFailureException
    | 0b101u ->
      if Bits.extract bin 31u 26u = 0b000000u then Op.SRLI
      elif Bits.extract bin 31u 26u = 0b010000u then Op.SRAI
      else raise ParsingFailureException
    | _ ->
      raise ParsingFailureException
  match opcode with
  | Op.ADDI | Op.SLTI | Op.SLTIU | Op.XORI
  | Op.ORI | Op.ANDI -> struct (opcode, getRdRs1IImm bin wordSize)
  | _ -> struct (opcode, getRdRs1Shamt bin wordSize)

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
      match getFunc7 bin with
      | 0b0000001u -> Op.DIV
      | 0b0000000u -> Op.XOR
      | _ -> raise ParsingFailureException
    | _ ->
      raise ParsingFailureException
  struct (opcode, getRdRs1Rs2 bin)

let parseEnvCall bin =
  let opcode = if Bits.pick bin 20u = 1u then Op.EBREAK else Op.ECALL
  struct (opcode, NoOperand)

let parseFence bin =
  let opcode = if Bits.pick bin 12u = 0u then Op.FENCE else Op.FENCEdotI
  if opcode = Op.FENCEdotI then
    struct (opcode, NoOperand)
  else
    if getPred bin = 0b0011uy && getSucc bin = 0b0011uy then
      struct (Op.FENCEdotTSO, NoOperand)
    else
      struct (opcode, getPredSucc bin)

let parseFloatArith bin wordSize =
  match Bits.extract bin 31u 25u with
  | 0b0000000u ->
    struct (Op.FADDdotS, getFRdRs1Rs2Rm bin)
  | 0b0000100u ->
    struct (Op.FSUBdotS, getFRdRs1Rs2Rm bin)
  | 0b0001000u ->
    struct (Op.FMULdotS, getFRdRs1Rs2Rm bin)
  | 0b0001100u ->
    struct (Op.FDIVdotS, getFRdRs1Rs2Rm bin)
  | 0b0101100u ->
    if Bits.extract bin 24u 20u = 0u then
      struct (Op.FSQRTdotS, getFRdFRs1Rm bin)
    else
      raise ParsingFailureException
  | 0b0010000u ->
    match getFunc3 bin with
    | 0b000u -> struct (Op.FSGNJdotS, getFRdRs1Rs2 bin)
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
    | 0b00000u -> struct (Op.FCVTdotWdotS, getRdFRs1Rm bin)
    | 0b00001u -> struct (Op.FCVTdotWUdotS, getRdFRs1Rm bin)
    | 0b00010u -> struct (rv64Only wordSize Op.FCVTdotLdotS, getRdFRs1Rm bin)
    | 0b00011u -> struct (rv64Only wordSize Op.FCVTdotLUdotS, getRdFRs1Rm bin)
    | _ -> raise ParsingFailureException
  | 0b1110000u ->
    if getFunc3 bin = 0b000u && getRs2 bin = 0b00000u then
      struct (Op.FMVdotXdotW, getRdFRs1 bin)
    elif getFunc3 bin = 0b001u && getRs2 bin = 0b00000u then
      struct (Op.FCLASSdotS, getRdFRs1 bin)
    else
      raise ParsingFailureException
  | 0b1010000u ->
    match getFunc3 bin with
    | 0b010u -> struct (Op.FEQdotS, getFNRdRs1Rs2 bin)
    | 0b001u -> struct (Op.FLTdotS, getFNRdRs1Rs2 bin)
    | 0b000u -> struct (Op.FLEdotS, getFNRdRs1Rs2 bin)
    | _ -> raise ParsingFailureException
  | 0b1101000u ->
    match getRs2 bin with
    | 0b00000u -> struct (Op.FCVTdotSdotW, getFRdRs1Rm bin)
    | 0b00001u -> struct (Op.FCVTdotSdotWU, getFRdRs1Rm bin)
    | 0b00010u -> struct (rv64Only wordSize Op.FCVTdotSdotL, getFRdRs1Rm bin)
    | 0b00011u -> struct (rv64Only wordSize Op.FCVTdotSdotLU, getFRdRs1Rm bin)
    | _ -> raise ParsingFailureException
  | 0b1111000u ->
    if getRs2 bin = 0b00000u && getFunc3 bin = 0b000u then
      struct (Op.FMVdotWdotX, getFRdRs1 bin)
    else
      raise ParsingFailureException
  | 0b0000001u ->
    struct (Op.FADDdotD, getFRdRs1Rs2Rm bin)
  | 0b0000101u ->
    struct (Op.FSUBdotD, getFRdRs1Rs2Rm bin)
  | 0b0001001u ->
    struct (Op.FMULdotD, getFRdRs1Rs2Rm bin)
  | 0b0001101u ->
    struct (Op.FDIVdotD, getFRdRs1Rs2Rm bin)
  | 0b0101101u ->
    if getRs2 bin = 0u then struct (Op.FSQRTdotD, getFRdFRs1Rm bin)
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
    if getRs2 bin = 0b00001u then struct (Op.FCVTdotSdotD, getFRdFRs1Rm bin)
    else raise ParsingFailureException
  | 0b0100001u ->
    if getRs2 bin = 0b00000u then struct (Op.FCVTdotDdotS, getFRdFRs1Rm bin)
    else raise ParsingFailureException
  | 0b1010001u ->
    match getFunc3 bin with
    | 0b010u -> struct (Op.FEQdotD, getFNRdRs1Rs2 bin)
    | 0b000u -> struct (Op.FLEdotD, getFNRdRs1Rs2 bin)
    | 0b001u -> struct (Op.FLTdotD, getFNRdRs1Rs2 bin)
    | _ -> raise ParsingFailureException
  | 0b1110001u ->
    if getRs2 bin = 0b00000u && getFunc3 bin = 0b001u then
      struct (Op.FCLASSdotD, getRdFRs1 bin)
    elif getRs2 bin = 0b00000u && getFunc3 bin = 0b000u then
      struct (rv64Only wordSize Op.FMVdotXdotD, getRdFRs1 bin)
    else
      raise ParsingFailureException
  | 0b1100001u ->
    match getRs2 bin with
    | 0b00000u -> struct (Op.FCVTdotWdotD, getRdFRs1Rm bin)
    | 0b00001u -> struct (Op.FCVTdotWUdotD, getRdFRs1Rm bin)
    | 0b00010u -> struct (rv64Only wordSize Op.FCVTdotLdotD, getRdFRs1Rm bin)
    | 0b00011u -> struct (rv64Only wordSize Op.FCVTdotLUdotD, getRdFRs1Rm bin)
    | _ -> raise ParsingFailureException
  | 0b1101001u ->
    match getRs2 bin with
    | 0b00000u -> struct (Op.FCVTdotDdotW, getFRdRs1 bin)
    | 0b00001u -> struct (Op.FCVTdotDdotWU, getFRdRs1 bin)
    | 0b00010u -> struct (rv64Only wordSize Op.FCVTdotDdotL, getFRdRs1Rm bin)
    | 0b00011u -> struct (rv64Only wordSize Op.FCVTdotDdotLU, getFRdRs1Rm bin)
    | _ -> raise ParsingFailureException
  | 0b1111001u ->
    if getRs2 bin = 0b00000u && getFunc3 bin = 0b000u then
      struct (rv64Only wordSize Op.FMVdotDdotX, getFRdRs1 bin)
    else
      raise ParsingFailureException
  | _ ->
    raise ParsingFailureException

let parseAtomic bin wordSize =
  if Bits.extract bin 14u 12u = 0b010u then
    match Bits.extract bin 31u 27u with
    | 0b00010u -> struct (Op.LRdotW, getRdRs1AqRlAcc bin 32<rt>)
    | 0b00011u -> struct (Op.SCdotW, getRdRs2Rs1AqRlAcc bin 32<rt>)
    | 0b00001u -> struct (Op.AMOSWAPdotW, getRdRs2Rs1AqRlAcc bin 32<rt>)
    | 0b00000u -> struct (Op.AMOADDdotW, getRdRs2Rs1AqRlAcc bin 32<rt>)
    | 0b00100u -> struct (Op.AMOXORdotW, getRdRs2Rs1AqRlAcc bin 32<rt>)
    | 0b01100u -> struct (Op.AMOANDdotW, getRdRs2Rs1AqRlAcc bin 32<rt>)
    | 0b01000u -> struct (Op.AMOORdotW, getRdRs2Rs1AqRlAcc bin 32<rt>)
    | 0b10000u -> struct (Op.AMOMINdotW, getRdRs2Rs1AqRlAcc bin 32<rt>)
    | 0b10100u -> struct (Op.AMOMAXdotW, getRdRs2Rs1AqRlAcc bin 32<rt>)
    | 0b11000u -> struct (Op.AMOMINUdotW, getRdRs2Rs1AqRlAcc bin 32<rt>)
    | 0b11100u -> struct (Op.AMOMAXUdotW, getRdRs2Rs1AqRlAcc bin 32<rt>)
    | _ -> raise ParsingFailureException
  elif Bits.extract bin 14u 12u = 0b011u then
    match rv64Only wordSize (Bits.extract bin 31u 27u) with
    | 0b00010u -> struct (Op.LRdotD, getRdRs1AqRlAcc bin 64<rt>)
    | 0b00011u -> struct (Op.SCdotD, getRdRs2Rs1AqRlAcc bin 64<rt>)
    | 0b00001u -> struct (Op.AMOSWAPdotD, getRdRs2Rs1AqRlAcc bin 64<rt>)
    | 0b00000u -> struct (Op.AMOADDdotD, getRdRs2Rs1AqRlAcc bin 64<rt>)
    | 0b00100u -> struct (Op.AMOXORdotD, getRdRs2Rs1AqRlAcc bin 64<rt>)
    | 0b01100u -> struct (Op.AMOANDdotD, getRdRs2Rs1AqRlAcc bin 64<rt>)
    | 0b01000u -> struct (Op.AMOORdotD, getRdRs2Rs1AqRlAcc bin 64<rt>)
    | 0b10000u -> struct (Op.AMOMINdotD, getRdRs2Rs1AqRlAcc bin 64<rt>)
    | 0b10100u -> struct (Op.AMOMAXdotD, getRdRs2Rs1AqRlAcc bin 64<rt>)
    | 0b11000u -> struct (Op.AMOMINUdotD, getRdRs2Rs1AqRlAcc bin 64<rt>)
    | 0b11100u -> struct (Op.AMOMAXUdotD, getRdRs2Rs1AqRlAcc bin 64<rt>)
    | _ -> raise ParsingFailureException
  else
    raise ParsingFailureException

let parseJAL bin wordSize = struct (Op.JAL, getRdJImm bin wordSize)

let parseJALR bin wordSize = struct (Op.JALR, getRdRs1JImm bin wordSize)

let parseFused bin =
  if Bits.extract bin 26u 25u = 0b00u then
    match Bits.extract bin 6u 0u with
    | 0b1000011u -> struct (Op.FMADDdotS, getFRdRs1Rs2Rs3Rm bin)
    | 0b1000111u -> struct (Op.FMSUBdotS, getFRdRs1Rs2Rs3Rm bin)
    | 0b1001011u -> struct (Op.FNMSUBdotS, getFRdRs1Rs2Rs3Rm bin)
    | 0b1001111u -> struct (Op.FNMADDdotS, getFRdRs1Rs2Rs3Rm bin)
    | _ -> raise ParsingFailureException
  elif Bits.extract bin 26u 25u = 0b01u then
    match Bits.extract bin 6u 0u with
    | 0b1000011u -> struct (Op.FMADDdotD, getFRdRs1Rs2Rs3Rm bin)
    | 0b1000111u -> struct (Op.FMSUBdotD, getFRdRs1Rs2Rs3Rm bin)
    | 0b1001011u -> struct (Op.FNMSUBdotD, getFRdRs1Rs2Rs3Rm bin)
    | 0b1001111u -> struct (Op.FNMADDdotD, getFRdRs1Rs2Rs3Rm bin)
    | _ -> raise ParsingFailureException
  else
    raise ParsingFailureException

let parseFloatLoad bin wordSize =
  match Bits.extract bin 14u 12u with
  | 0b011u -> struct (Op.FLD, getFRdRs1Addr bin 64<rt> wordSize)
  | 0b010u -> struct (Op.FLW, getFRdRs1Addr bin 32<rt> wordSize)
  | _ -> raise ParsingFailureException

let parseFloatStore bin wordSize =
  match Bits.extract bin 14u 12u with
  | 0b011u -> struct (Op.FSD, getFRs2Rs1Addr bin 64<rt> wordSize)
  | 0b010u -> struct (Op.FSW, getFRs2Rs1Addr bin 32<rt> wordSize)
  | _ -> raise ParsingFailureException

let parseOp32 bin wordSize =
  match rv64Only wordSize (Bits.extract bin 31u 25u) with
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
  | _ ->
    raise ParsingFailureException

let parseOpImm32 bin wordSize =
  match rv64Only wordSize (getFunc3 bin) with
  | 0b000u ->
    struct (Op.ADDIW, getRdRs1IImm bin wordSize)
  | 0b001u ->
    if Bits.extract bin 31u 25u = 0b0000000u then
      struct (Op.SLLIW, getRdRs1Shamt bin wordSize)
    else
      raise ParsingFailureException
  | 0b101u ->
    if Bits.extract bin 31u 25u = 0b0000000u then
      struct (Op.SRLIW, getRdRs1Shamt bin wordSize)
    elif Bits.extract bin 31u 25u = 0b0100000u then
      struct (Op.SRAIW, getRdRs1Shamt bin wordSize)
    else
      raise ParsingFailureException
  | _ ->
    raise ParsingFailureException

let parseCSR bin =
  match getFunc3 bin with
  | 0b001u -> struct (Op.CSRRW, getRdCSRRs1 bin)
  | 0b010u -> struct (Op.CSRRS, getRdCSRRs1 bin)
  | 0b011u -> struct (Op.CSRRC, getRdCSRRs1 bin)
  | 0b101u -> struct (Op.CSRRWI, getRdCSRUImm bin)
  | 0b110u -> struct (Op.CSRRSI, getRdCSRUImm bin)
  | 0b111u -> struct (Op.CSRRCI, getRdCSRUImm bin)
  | _ -> raise ParsingFailureException

/// The offset a compressed instruction reaching a word holds, which counts in
/// the four bytes such a word takes.
let compWordOffset bin =
  let from2to2 = Bits.pick bin 6u <<< 2
  let from3to5 = Bits.extract bin 12u 10u <<< 3
  let from6to6 = Bits.pick bin 5u <<< 6
  from2to2 ||| from3to5 ||| from6to6 |> int64 |> Imm |> Some

/// The offset a compressed instruction reaching a doubleword holds, which
/// counts in the eight bytes such a doubleword takes.
let compDoubleOffset bin =
  let from3to5 = Bits.extract bin 12u 10u <<< 3
  let from6to7 = Bits.extract bin 6u 5u <<< 6
  from3to5 ||| from6to7 |> int64 |> Imm |> Some

/// <summary>
/// Reads what a compressed instruction reaching memory through a register of
/// its own says.
///
/// The two encodings naming a doubleword are the ones RV32 has no doubleword
/// for, and what it puts in their stead reaches a word of floating point; the
/// offset such a word is found at counts in four bytes rather than eight, so
/// which instruction it is decides how the offset is read as well.
/// </summary>
let parseRegisterBasedLoadStore bin wordSize =
  let b = getCompRegFrom97 bin
  match Bits.extract bin 15u 13u with
  | 0b001u ->
    let mem = OpMem(b, compDoubleOffset bin, 64<rt>)
    struct (Op.CdotFLD, TwoOperands(cfrdComp bin, mem))
  | 0b010u ->
    let mem = OpMem(b, compWordOffset bin, 32<rt>)
    struct (Op.CdotLW, TwoOperands(crdComp bin, mem))
  | 0b011u when wordSize = 64 ->
    let mem = OpMem(b, compDoubleOffset bin, 64<rt>)
    struct (Op.CdotLD, TwoOperands(crdComp bin, mem))
  | 0b011u ->
    let mem = OpMem(b, compWordOffset bin, 32<rt>)
    struct (Op.CdotFLW, TwoOperands(cfrdComp bin, mem))
  | 0b101u ->
    let mem = OpMem(b, compDoubleOffset bin, 64<rt>)
    struct (Op.CdotFSD, TwoOperands(cfrs2Comp bin, mem))
  | 0b110u ->
    let mem = OpMem(b, compWordOffset bin, 32<rt>)
    struct (Op.CdotSW, TwoOperands(crs2Comp bin, mem))
  | 0b111u when wordSize = 64 ->
    let mem = OpMem(b, compDoubleOffset bin, 64<rt>)
    struct (Op.CdotSD, TwoOperands(crs2Comp bin, mem))
  | 0b111u ->
    let mem = OpMem(b, compWordOffset bin, 32<rt>)
    struct (Op.CdotFSW, TwoOperands(cfrs2Comp bin, mem))
  | _ ->
    Terminator.impossible ()

/// The offset a compressed instruction loading a word through the stack
/// pointer holds.
let stackLoadWordOffset bin =
  let from2to4 = Bits.extract bin 4u 6u <<< 2
  let from5to5 = Bits.pick bin 12u <<< 5
  let from6to7 = Bits.extract bin 2u 3u <<< 6
  from2to4 ||| from5to5 ||| from6to7 |> int64 |> Imm |> Some

/// The offset a compressed instruction loading a doubleword through the stack
/// pointer holds.
let stackLoadDoubleOffset bin =
  let from3to4 = Bits.extract bin 6u 5u <<< 3
  let from5to5 = Bits.pick bin 12u <<< 5
  let from6to8 = Bits.extract bin 2u 4u <<< 6
  from3to4 ||| from5to5 ||| from6to8 |> int64 |> Imm |> Some

/// The offset a compressed instruction storing a word through the stack
/// pointer holds, which sits elsewhere in the word than a load keeps it.
let stackStoreWordOffset bin =
  let from2to5 = Bits.extract bin 12u 9u <<< 2
  let from6to7 = Bits.extract bin 8u 7u <<< 6
  from2to5 ||| from6to7 |> int64 |> Imm |> Some

/// The offset a compressed instruction storing a doubleword through the stack
/// pointer holds, which sits elsewhere in the word than a load keeps it.
let stackStoreDoubleOffset bin =
  let from3to5 = Bits.extract bin 12u 10u <<< 3
  let from6to8 = Bits.extract bin 9u 7u <<< 6
  from3to5 ||| from6to8 |> int64 |> Imm |> Some

/// <summary>
/// Reads what a compressed instruction reaching memory through the stack
/// pointer says.
///
/// As with the instructions reaching memory through a register of their own,
/// the two encodings naming a doubleword are what RV32 gives to a word of
/// floating point instead. Only the instructions naming a general register may
/// not name the one hard-wired to zero, there being nothing for such an
/// instruction to do.
/// </summary>
let parseStackBasedLoadStore bin wordSize =
  match Bits.extract bin 15u 13u with
  | 0b001u ->
    let mem = OpMem(R.X2, stackLoadDoubleOffset bin, 64<rt>)
    struct (Op.CdotFLDSP, TwoOperands(cfrd bin, mem))
  | 0b010u ->
    if Bits.extract bin 11u 7u = 0u then raise ParsingFailureException else ()
    let mem = OpMem(R.X2, stackLoadWordOffset bin, 32<rt>)
    struct (Op.CdotLWSP, TwoOperands(crd bin, mem))
  | 0b011u when wordSize = 64 ->
    if Bits.extract bin 11u 7u = 0u then raise ParsingFailureException else ()
    let mem = OpMem(R.X2, stackLoadDoubleOffset bin, 64<rt>)
    struct (Op.CdotLDSP, TwoOperands(crd bin, mem))
  | 0b011u ->
    let mem = OpMem(R.X2, stackLoadWordOffset bin, 32<rt>)
    struct (Op.CdotFLWSP, TwoOperands(cfrd bin, mem))
  | 0b101u ->
    let mem = OpMem(R.X2, stackStoreDoubleOffset bin, 64<rt>)
    struct (Op.CdotFSDSP, TwoOperands(cfrs2 bin, mem))
  | 0b110u ->
    let mem = OpMem(R.X2, stackStoreWordOffset bin, 32<rt>)
    struct (Op.CdotSWSP, TwoOperands(crs2 bin, mem))
  | 0b111u when wordSize = 64 ->
    let mem = OpMem(R.X2, stackStoreDoubleOffset bin, 64<rt>)
    struct (Op.CdotSDSP, TwoOperands(crs2 bin, mem))
  | 0b111u ->
    let mem = OpMem(R.X2, stackStoreWordOffset bin, 32<rt>)
    struct (Op.CdotFSWSP, TwoOperands(cfrs2 bin, mem))
  | _ ->
    Terminator.impossible ()

let parseCdotADDI4SPN bin =
  let from2to2 = Bits.pick bin 6u <<< 2
  let from3to3 = Bits.pick bin 5u <<< 3
  let from4to5 = Bits.extract bin 12u 11u <<< 4
  let from6to9 = Bits.extract bin 10u 7u <<< 6
  let imm = from2to2 ||| from3to3 ||| from4to5 ||| from6to9 |> uint64
  let dest = crs2Comp bin
  if imm = 0UL then raise ParsingFailureException else ()
  struct (Op.CdotADDI4SPN, ThreeOperands(dest, R.X2 |> OpReg, imm |> OpImm))

/// The place a compressed jump names, which is written as how far that place
/// lies from the jump itself.
let cdotJOffset bin wordSize =
  let from1to3 = Bits.extract bin 5u 3u <<< 1
  let from5to5 = Bits.pick bin 2u <<< 5
  let from7to7 = Bits.pick bin 6u <<< 7
  let from6to6 = Bits.pick bin 7u <<< 6
  let from10to10 = Bits.pick bin 8u <<< 10
  let from8to9 = Bits.extract bin 10u 9u <<< 8
  let from4to4 = Bits.pick bin 11u <<< 4
  let from11to11 = Bits.pick bin 12u <<< 11
  0b0u ||| from1to3 ||| from4to4 ||| from5to5 ||| from6to6
  ||| from7to7 ||| from8to9 ||| from10to10 ||| from11to11 |> uint64
  |> Bits.signExtend 12 wordSize |> int64 |> Relative |> OpAddr

let parseCdotJ bin wordSize =
  let imm = cdotJOffset bin wordSize
  struct (Op.CdotJ, TwoOperands(R.X0 |> OpReg, imm))

/// Reads a compressed jump keeping the place it came from, which only RV32
/// has an encoding for, RV64 giving that encoding to the addition on a word.
let parseCdotJAL bin wordSize =
  let imm = cdotJOffset bin wordSize
  struct (Op.CdotJAL, TwoOperands(R.X1 |> OpReg, imm))

let parseCdotBranch bin wordSize =
  let opcode = if Bits.extract bin 15u 13u = 0b111u then Op.CdotBNEZ
               else Op.CdotBEQZ
  let src = crs1Comp bin
  let from1to2 = Bits.extract bin 3u 4u <<< 1
  let from3to4 = Bits.extract bin 10u 11u <<< 3
  let from5to5 = Bits.pick bin 2u <<< 5
  let from6to7 = Bits.extract bin 6u 5u <<< 6
  let from8to8 = Bits.pick bin 12u <<< 8
  let imm =
    0b0u ||| from1to2 ||| from3to4 ||| from5to5 ||| from6to7
    ||| from8to8 |> uint64 |> Bits.signExtend 9 wordSize
    |> int64 |> Relative |> OpAddr
  struct (opcode, ThreeOperands(src, R.X0 |> OpReg, imm))

let parseCdotADDIW bin wordSize =
  if Bits.extract bin 11u 7u = 0u then raise ParsingFailureException else ()
  let imm = (Bits.extract bin 6u 2u) ||| (Bits.pick bin 12u <<< 5) |> uint64
  let signExtended = Bits.signExtend 6 wordSize imm |> uint64 |> OpImm
  let dest = crd bin
  struct (Op.CdotADDIW, ThreeOperands(dest, dest, signExtended))

let parseCdotLI bin wordSize =
  let dest = crd bin
  let imm = (Bits.extract bin 6u 2u) ||| (Bits.pick bin 12u <<< 5) |> uint64
  let signExtended = Bits.signExtend 6 wordSize imm |> uint64
  struct (Op.CdotLI, ThreeOperands(dest, R.X0 |> OpReg, signExtended |> OpImm))

let parseCdotANDI bin wordSize =
  let dest = crs1Comp bin
  let from0to4 = Bits.extract bin 6u 2u
  let from5to5 = Bits.pick bin 12u <<< 5
  let imm = from0to4 ||| from5to5 |> uint64
  let signExtended = Bits.signExtend 6 wordSize imm |> uint64
  struct (Op.CdotANDI, ThreeOperands(dest, dest, signExtended |> OpImm))

/// The amount a compressed shift shifts by, whose highest bit RV32 has no
/// places left to shift across and so leaves clear.
let cdotShamt bin wordSize =
  let from0to4 = Bits.extract bin 6u 2u
  let from5to5 = Bits.pick bin 12u <<< 5
  if wordSize = 64 || from5to5 = 0u then
    from0to4 ||| from5to5 |> uint64 |> OpShiftAmount
  else
    raise ParsingFailureException

let parseCdotSLLI bin wordSize =
  let imm = cdotShamt bin wordSize
  let dest = crd bin
  struct (Op.CdotSLLI, ThreeOperands(dest, dest, imm))

let parseCdotSR bin wordSize =
  let dest = crs1Comp bin
  let imm = cdotShamt bin wordSize
  let opcode =
    if Bits.extract bin 11u 10u = 0u then Op.CdotSRLI else Op.CdotSRAI
  struct (opcode, ThreeOperands(dest, dest, imm))

let parseCdotLUIADDI16SP bin wordSize =
  if Bits.extract bin 11u 7u = 2u then
    let from4to4 = Bits.pick bin 6u <<< 4
    let from5to5 = Bits.pick bin 2u <<< 5
    let from6to6 = Bits.pick bin 5u <<< 6
    let from7to8 = Bits.extract bin 4u 3u <<< 7
    let from9to9 = Bits.pick bin 12u <<< 9
    let imm = from4to4 ||| from5to5 ||| from6to6 ||| from7to8 ||| from9to9
              |> uint64
#if DEBUG
    if imm = 0uL then raise ParsingFailureException else ()
#endif
    let signExtended = Bits.signExtend 10 wordSize imm |> uint64 |> OpImm
    let opr = ThreeOperands(R.X2 |> OpReg, R.X2 |> OpReg, signExtended)
    struct (Op.CdotADDI16SP, opr)
  else
    let imm = (Bits.extract bin 6u 2u) ||| (Bits.pick bin 12u <<< 5) |> uint64
    let signExtended = Bits.signExtend 6 wordSize imm |> uint64
    if imm = 0uL then raise ParsingFailureException else ()
    let dest = crd bin
    struct (Op.CdotLUI, TwoOperands(dest, signExtended |> OpImm))

let parseCdotArith bin wordSize =
  let opcode =
    match (Bits.pick bin 12u) <<< 2 ||| Bits.extract bin 6u 5u with
    | 0b000u -> Op.CdotSUB
    | 0b001u -> Op.CdotXOR
    | 0b010u -> Op.CdotOR
    | 0b011u -> Op.CdotAND
    | 0b100u -> rv64Only wordSize Op.CdotSUBW
    | 0b101u -> rv64Only wordSize Op.CdotADDW
    | _ -> raise ParsingFailureException
  let dest = crs1Comp bin
  let src = crdComp bin
  struct (opcode, ThreeOperands(dest, dest, src))

let parseCdotJrMvEBREAKJalrAdd bin =
  if Bits.pick bin 12u = 0u then
    if Bits.extract bin 6u 2u = 0u then
      if Bits.extract bin 11u 7u = 0u then raise ParsingFailureException
      else struct (Op.CdotJR, TwoOperands(R.X0 |> OpReg,
                   RelativeBase(getRegFrom117 bin, 0UL) |> OpAddr))
    else
      let dest = crd bin
      let src = crs2 bin
      struct (Op.CdotMV, ThreeOperands(dest, R.X0 |> OpReg, src))
  else
    if Bits.extract bin 6u 2u = 0u then
      if Bits.extract bin 11u 7u = 0u then
        struct (Op.CdotEBREAK, NoOperand)
      else
        struct (Op.CdotJALR, TwoOperands(R.X1 |> OpReg,
                RelativeBase(getRegFrom117 bin, 0UL) |> OpAddr))
    else
      let dest = crd bin
      let src = crs2 bin
      struct (Op.CdotADD, ThreeOperands(dest, dest, src))

let parseCdotNOPADDI bin wordSize =
  if Bits.extract bin 11u 7u = 0u then
    struct (Op.CdotNOP, NoOperand)
  else
    let imm = (Bits.extract bin 6u 2u) ||| (Bits.pick bin 12u <<< 5) |> uint64
    let signExtended = Bits.signExtend 6 wordSize imm |> uint64 |> OpImm
    let dest = crd bin
    struct (Op.CdotADDI, ThreeOperands(dest, dest, signExtended))

let parseQuadrant0 bin wordSize =
  match Bits.extract bin 15u 13u with
  | 0b000u -> parseCdotADDI4SPN bin
  | 0b001u
  | 0b010u
  | 0b011u
  | 0b101u
  | 0b110u
  | 0b111u -> parseRegisterBasedLoadStore bin wordSize
  | _ -> raise ParsingFailureException

let parseQuadrant1 bin wordSize =
  match Bits.extract bin 15u 13u with
  | 0b000u ->
    parseCdotNOPADDI bin wordSize
  | 0b001u ->
    if wordSize = 64 then
      parseCdotADDIW bin wordSize
    else
      parseCdotJAL bin wordSize
  | 0b010u ->
    parseCdotLI bin wordSize
  | 0b011u ->
    parseCdotLUIADDI16SP bin wordSize
  | 0b100u ->
    match Bits.extract bin 11u 10u with
    | 0b00u
    | 0b01u -> parseCdotSR bin wordSize
    | 0b10u -> parseCdotANDI bin wordSize
    | 0b11u -> parseCdotArith bin wordSize
    | _ -> Terminator.impossible ()
  | 0b101u ->
    parseCdotJ bin wordSize
  | 0b110u
  | 0b111u ->
    parseCdotBranch bin wordSize
  | _ ->
    raise ParsingFailureException

let parseQuadrant2 bin wordSize =
  match Bits.extract bin 15u 13u with
  | 0b000u -> parseCdotSLLI bin wordSize
  | 0b001u
  | 0b010u
  | 0b011u
  | 0b101u
  | 0b110u
  | 0b111u -> parseStackBasedLoadStore bin wordSize
  | 0b100u -> parseCdotJrMvEBREAKJalrAdd bin
  | _ -> Terminator.impossible ()

let private parseCompressedInstruction wordSize bin =
  match Bits.extract bin 0u 1u with
  | 0b00u -> parseQuadrant0 bin wordSize
  | 0b01u -> parseQuadrant1 bin wordSize
  | 0b10u -> parseQuadrant2 bin wordSize
  | _ -> Terminator.impossible ()

let private parseInstruction wordSize bin =
  match Bits.extract bin 6u 0u with
  | 0b0110111u -> parseLUI bin wordSize
  | 0b0010111u -> parseAUIPC bin wordSize
  | 0b1101111u -> parseJAL bin wordSize
  | 0b1100111u -> parseJALR bin wordSize
  | 0b1100011u -> parseBranch bin wordSize
  | 0b0000011u -> parseLoad bin wordSize
  | 0b0100011u -> parseStore bin wordSize
  | 0b0010011u -> parseOpImm bin wordSize
  | 0b0110011u -> parseOp bin
  | 0b0001111u -> parseFence bin
  | 0b1110011u -> if getFunc3 bin = 0u then parseEnvCall bin else parseCSR bin
  | 0b0011011u -> parseOpImm32 bin wordSize
  | 0b0111011u -> parseOp32 bin wordSize
  | 0b0101111u -> parseAtomic bin wordSize
  | 0b0000111u -> parseFloatLoad bin wordSize
  | 0b0100111u -> parseFloatStore bin wordSize
  | 0b1000011u
  | 0b1000111u
  | 0b1001011u
  | 0b1001111u -> parseFused bin
  | 0b1010011u -> parseFloatArith bin wordSize
  | _ -> raise ParsingFailureException

let parse lifter (span: ByteSpan) (reader: IBinReader) wordSize addr =
  let bin = reader.ReadUInt16(span, 0)
  let wordSz = int wordSize
  let struct (op, operands, instrLen) =
    match isTwoBytes bin with
    | true ->
      let bin = uint32 bin
      let struct (op, operands) = bin |> parseCompressedInstruction wordSz
      struct (op, operands, 2u)
    | false ->
      let b2 = reader.ReadUInt16(span, 2)
      let bin = ((uint32 b2) <<< 16) + (uint32 bin)
      let struct (op, operands) = bin |> parseInstruction wordSz
      struct (op, operands, 4u)
  Instruction(addr, instrLen, op, operands, 32<rt>, wordSize, lifter)
