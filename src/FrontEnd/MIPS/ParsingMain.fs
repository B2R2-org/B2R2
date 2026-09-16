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

module internal B2R2.FrontEnd.MIPS.ParsingMain

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.ParsingUtils
open B2R2.FrontEnd.MIPS.Helper

let private parseNOP binary =
  match Bits.extract binary 10u 6u with
  | 0u -> Op.NOP, None, None, NoOperand
  | 1u -> Op.SSNOP, None, None, NoOperand
  | 3u -> Op.EHB, None, None, NoOperand
  | 5u -> Op.PAUSE, None, None, NoOperand
  | _ -> raise ParsingFailureException

let private parseSLL binary =
  match Bits.extract binary 25u 11u with
  | 0u ->
    parseNOP binary
  | _ when Bits.extract binary 25u 21u = 0u ->
    Op.SLL, None, None, getRdRtSa binary
  | _ ->
    raise ParsingFailureException

let private parseJALR binary =
  match Bits.extract binary 15u 11u, Bits.pick binary 10u with
  | 0u, 0u -> Op.JR, None, None, getRs binary
  | 31u, 0u -> Op.JALR, None, None, getRs binary
  | 31u, 1u -> Op.JALRHB, None, None, getRs binary
  | _, 0u -> Op.JALR, None, None, getRdRs binary
  | _, 1u -> Op.JALRHB, None, None, getRdRs binary
  | _ -> raise ParsingFailureException

let private parseJR binary =
  match Bits.pick binary 10u with
  | 0u -> Op.JR, None, None, getRs binary
  | _ -> Op.JRHB, None, None, getRs binary

let private parseDIVU binary =
  match Bits.extract binary 15u 11u, Bits.extract binary 10u 6u with
  | 0u, 0u -> Op.DIVU, None, None, getRsRt binary
  | _, 0b00010u -> Op.DIVU, None, None, getRdRsRt binary
  | _ -> raise ParsingFailureException

let private parseR2CLZ binary =
  match Bits.extract binary 10u 6u with
  | 0u -> Op.CLZ, None, None, getRdRs binary
  | _ -> raise ParsingFailureException

let private parseR2CLO binary =
  match Bits.extract binary 10u 6u with
  | 0u -> Op.CLO, None, None, getRdRs binary
  | _ -> raise ParsingFailureException

let private parseR6CLZ binary =
  match Bits.extract binary 20u 16u with
  | 0u -> Op.CLZ, None, None, getRdRs binary
  | _ -> raise ParsingFailureException

let private parseR6CLO binary =
  match Bits.extract binary 20u 16u with
  | 0u -> Op.CLO, None, None, getRdRs binary
  | _ -> raise ParsingFailureException

let private parseMFHI binary =
  match Bits.extract binary 25u 16u, Bits.extract binary 10u 6u with
  | 0u, 0u -> Op.MFHI, None, None, getRd binary
  | _, 1u -> parseR6CLZ binary
  | _ -> raise ParsingFailureException

let private parseR2DCLZ binary =
  match Bits.extract binary 10u 6u with
  | 0u -> Op.DCLZ, None, None, getRdRs binary
  | _ -> raise ParsingFailureException

let private parseR2DCLO binary =
  match Bits.extract binary 10u 6u with
  | 0u -> Op.DCLO, None, None, getRdRs binary
  | _ -> raise ParsingFailureException

let private parseR6DCLZ binary =
  match Bits.extract binary 20u 16u with
  | 0u -> Op.DCLZ, None, None, getRdRs binary
  | _ -> raise ParsingFailureException

let private parseR6DCLO binary =
  match Bits.extract binary 20u 16u with
  | 0u -> Op.DCLO, None, None, getRdRs binary
  | _ -> raise ParsingFailureException

let private parseMFLO binary =
  match Bits.extract binary 25u 16u, Bits.extract binary 10u 6u with
  | 0u, 0u -> Op.MFLO, None, None, getRd binary
  | _, 1u -> parseR6DCLZ binary
  | _ -> raise ParsingFailureException

/// Table A.3 MIPS64 SEPCIAL Opcode Encoding of Function Field
let private parseSPECIAL release bin =
  let b25to21 = Bits.extract bin 25u 21u
  let b20to6 = Bits.extract bin 20u 6u
  let b15to6 = Bits.extract bin 15u 6u
  let b10to6 = Bits.extract bin 10u 6u
  match Bits.extract bin 5u 0u with
  | 0b000000u ->
    parseSLL bin
  | 0b000001u ->
    if b10to6 = 0u then
      let ztf = Bits.extract bin 17u 16u
      if ztf = 0b00u then Op.MOVF, None, None, getRdRsCc bin
      elif ztf = 0b01u then Op.MOVT, None, None, getRdRsCc bin
      else raise ParsingFailureException
    else
      raise ParsingFailureException
  | 0b000010u ->
    if b25to21 = 0u then Op.SRL, None, None, getRdRtSa bin
    elif b25to21 = 1u then Op.ROTR, None, None, getRdRtSa bin
    else raise ParsingFailureException
  | 0b000011u ->
    if b25to21 = 0u then Op.SRA, None, None, getRdRtSa bin
    else raise ParsingFailureException
  | 0b000100u ->
    if b10to6 = 0u then Op.SLLV, None, None, getRdRtRs bin
    else raise ParsingFailureException
  | 0b000101u ->
    (* LSA rd, rs, rt, sa2 -- bits 10..8 are zero and 7..6 hold sa2, which
       the operation uses as sa2+1. Release 6 only. *)
    if release = MIPSRelease.R6 && Bits.extract bin 10u 8u = 0u then
      Op.LSA, None, None, getRdRsRtSa2 bin
    else
      raise ParsingFailureException
  | 0b000110u ->
    if b10to6 = 0u then Op.SRLV, None, None, getRdRtRs bin
    elif b10to6 = 1u then Op.ROTRV, None, None, getRdRtRs bin
    else raise ParsingFailureException
  | 0b000111u ->
    if b10to6 = 0u then Op.SRAV, None, None, getRdRtRs bin
    else raise ParsingFailureException
  | 0b001000u ->
    parseJR bin
  | 0b001001u ->
    parseJALR bin
  | 0b001010u ->
    if b10to6 = 0u then Op.MOVZ, None, None, getRdRsRt bin
    else raise ParsingFailureException
  | 0b001011u ->
    if b10to6 = 0u then Op.MOVN, None, None, getRdRsRt bin
    else raise ParsingFailureException
  | 0b001100u ->
    Op.SYSCALL, None, None, NoOperand
  | 0b001101u ->
    Op.BREAK, None, None, NoOperand
  | 0b001111u ->
    if Bits.extract bin 25u 11u = 0u then Op.SYNC, None, None, getStype bin
    else raise ParsingFailureException
  | 0b010000u ->
    parseMFHI bin
  | 0b010001u ->
    if b20to6 = 0u then Op.MTHI, None, None, getRs bin
    elif Bits.extract bin 10u 6u = 1u then parseR6CLO bin
    else raise ParsingFailureException
  | 0b010010u ->
    parseMFLO bin
  | 0b010011u ->
    if b20to6 = 0u then Op.MTLO, None, None, getRs bin
    elif Bits.extract bin 10u 6u = 1u then parseR6DCLO bin
    else raise ParsingFailureException
  | 0b010100u ->
    if b10to6 = 0u then Op.DSLLV, None, None, getRdRtRs bin
    else raise ParsingFailureException
  | 0b110101u ->
    (* SELEQZ rd, rs, rt -- rd gets rs when rt is zero and zero
       otherwise. Release 6 put it where nothing stood before, so the
       encoding is free on earlier releases rather than reassigned. *)
    if release = MIPSRelease.R6 && b10to6 = 0u then
      Op.SELEQZ, None, None, getRdRsRt bin
    else
      raise ParsingFailureException
  | 0b110111u ->
    if release = MIPSRelease.R6 && b10to6 = 0u then
      Op.SELNEZ, None, None, getRdRsRt bin
    else
      raise ParsingFailureException
  | 0b010101u ->
    (* DLSA, the doubleword LSA. Release 6 only. *)
    if release = MIPSRelease.R6 && Bits.extract bin 10u 8u = 0u then
      Op.DLSA, None, None, getRdRsRtSa2 bin
    else
      raise ParsingFailureException
  | 0b010110u ->
    if b10to6 = 0u then Op.DSRLV, None, None, getRdRtRs bin
    elif b10to6 = 1u then Op.DROTRV, None, None, getRdRtRs bin
    else raise ParsingFailureException
  | 0b010111u ->
    if b10to6 = 0u then Op.DSRAV, None, None, getRdRtRs bin
    else raise ParsingFailureException
  | 0b011000u ->
    if release = MIPSRelease.R6 then
      match b10to6 with
      | 0b00010u ->
        Op.MUL, None, None, getRdRsRt bin
      | 0b00011u ->
        Op.MUH, None, None, getRdRsRt bin
      | _ ->
        raise ParsingFailureException
    elif b15to6 = 0u then
      Op.MULT, None, None, getRsRt bin
    else
      raise ParsingFailureException
  | 0b011001u ->
    if release = MIPSRelease.R6 then
      match b10to6 with
      | 0b00010u ->
        Op.MULU, None, None, getRdRsRt bin
      | 0b00011u ->
        Op.MUHU, None, None, getRdRsRt bin
      | _ ->
        raise ParsingFailureException
    elif b15to6 = 0u then
      Op.MULTU, None, None, getRsRt bin
    else
      raise ParsingFailureException
  | 0b011010u ->
    if release = MIPSRelease.R6 then
      match b10to6 with
      | 0b00010u ->
        Op.DIV, None, None, getRdRsRt bin
      | 0b00011u ->
        Op.MOD, None, None, getRdRsRt bin
      | _ ->
        raise ParsingFailureException
    elif b15to6 = 0u then
      Op.DIV, None, None, getRsRt bin
    else
      raise ParsingFailureException
  | 0b011011u ->
    if release = MIPSRelease.R6 then
      match b10to6 with
      | 0b00010u ->
        Op.DIVU, None, None, getRdRsRt bin
      | 0b00011u ->
        Op.MODU, None, None, getRdRsRt bin
      | _ ->
        raise ParsingFailureException
    else
      parseDIVU bin
  | 0b011100u ->
    if release = MIPSRelease.R6 then
      match b10to6 with
      | 0b00010u ->
        Op.DMUL, None, None, getRdRsRt bin
      | 0b00011u ->
        Op.DMUH, None, None, getRdRsRt bin
      | _ ->
        raise ParsingFailureException
    elif b15to6 = 0u then
      Op.DMULT, None, None, getRsRt bin
    else
      raise ParsingFailureException
  | 0b011101u ->
    if release = MIPSRelease.R6 then
      match b10to6 with
      | 0b00010u ->
        Op.DMULU, None, None, getRdRsRt bin
      | 0b00011u ->
        Op.DMUHU, None, None, getRdRsRt bin
      | _ ->
        raise ParsingFailureException
    elif b15to6 = 0u then
      Op.DMULTU, None, None, getRsRt bin
    else
      raise ParsingFailureException
  | 0b011110u ->
    if release = MIPSRelease.R6 then
      match b10to6 with
      | 0b00010u ->
        Op.DDIV, None, None, getRdRsRt bin
      | 0b00011u ->
        Op.DMOD, None, None, getRdRsRt bin
      | _ ->
        raise ParsingFailureException
    elif b15to6 = 0u then
      Op.DDIV, None, None, getRsRt bin
    else
      raise ParsingFailureException
  | 0b011111u ->
    if release = MIPSRelease.R6 then
      match b10to6 with
      | 0b00010u ->
        Op.DDIVU, None, None, getRdRsRt bin
      | 0b00011u ->
        Op.DMODU, None, None, getRdRsRt bin
      | _ ->
        raise ParsingFailureException
    elif b15to6 = 0u then
      Op.DDIVU, None, None, getRsRt bin
    else
      raise ParsingFailureException
  | 0b100000u ->
    if b10to6 = 0u then Op.ADD, None, None, getRdRsRt bin
    else raise ParsingFailureException
  | 0b101100u ->
    if b10to6 = 0u then Op.DADD, None, None, getRdRsRt bin
    else raise ParsingFailureException
  | 0b100001u ->
    if b10to6 = 0u then Op.ADDU, None, None, getRdRsRt bin
    else raise ParsingFailureException
  | 0b100010u ->
    if b10to6 = 0u then Op.SUB, None, None, getRdRsRt bin
    else raise ParsingFailureException
  | 0b100011u ->
    if b10to6 = 0u then Op.SUBU, None, None, getRdRsRt bin
    else raise ParsingFailureException
  | 0b100100u ->
    if b10to6 = 0u then Op.AND, None, None, getRdRsRt bin
    else raise ParsingFailureException
  | 0b100101u ->
    if b10to6 = 0u then Op.OR, None, None, getRdRsRt bin
    else raise ParsingFailureException
  | 0b100110u ->
    if b10to6 = 0u then Op.XOR, None, None, getRdRsRt bin
    else raise ParsingFailureException
  | 0b100111u ->
    if b10to6 = 0u then Op.NOR, None, None, getRdRsRt bin
    else raise ParsingFailureException
  | 0b101010u ->
    if b10to6 = 0u then Op.SLT, None, None, getRdRsRt bin
    else raise ParsingFailureException
  | 0b101011u ->
    if b10to6 = 0u then Op.SLTU, None, None, getRdRsRt bin
    else raise ParsingFailureException
  | 0b101101u ->
    if b10to6 = 0u then Op.DADDU, None, None, getRdRsRt bin
    else raise ParsingFailureException
  | 0b101110u ->
    if b10to6 = 0u then Op.DSUB, None, None, getRdRsRt bin
    else raise ParsingFailureException
  | 0b101111u ->
    if b10to6 = 0u then Op.DSUBU, None, None, getRdRsRt bin
    else raise ParsingFailureException
  (* The conditional traps. Table A.3 gives the six of them one row,
     110000 through 110110, with 110101 unassigned; only TEQ was decoded.
     The ten bits above the registers are a code the hardware ignores and
     software reads out of the word, so nothing here is held to zero. *)
  | 0b110000u ->
    Op.TGE, None, None, getRsRt bin
  | 0b110001u ->
    Op.TGEU, None, None, getRsRt bin
  | 0b110010u ->
    Op.TLT, None, None, getRsRt bin
  | 0b110011u ->
    Op.TLTU, None, None, getRsRt bin
  | 0b110100u ->
    Op.TEQ, None, None, getRsRt bin
  | 0b110110u ->
    Op.TNE, None, None, getRsRt bin
  | 0b111000u ->
    if b25to21 = 0u then Op.DSLL, None, None, getRdRtSa bin
    else raise ParsingFailureException
  | 0b111010u ->
    if b25to21 = 0u then Op.DSRL, None, None, getRdRtSa bin
    elif b25to21 = 1u then Op.DROTR, None, None, getRdRtSa bin
    else raise ParsingFailureException
  | 0b111011u ->
    if b25to21 = 0u then Op.DSRA, None, None, getRdRtSa bin
    else raise ParsingFailureException
  | 0b111100u ->
    if b25to21 = 0u then Op.DSLL32, None, None, getRdRtSa bin
    else raise ParsingFailureException
  | 0b111110u ->
    if b25to21 = 0u then Op.DSRL32, None, None, getRdRtSa bin
    elif b25to21 = 1u then Op.DROTR32, None, None, getRdRtSa bin
    else raise ParsingFailureException
  | 0b111111u ->
    if b25to21 = 0u then Op.DSRA32, None, None, getRdRtSa bin
    else raise ParsingFailureException
  | _ ->
    raise ParsingFailureException

let private parseBAL binary =
  match Bits.extract binary 25u 21u with
  | 0u -> Op.BAL, None, None, getRel16 binary
  | _ -> Op.BGEZAL, None, None, getRsRel16 binary

/// Table A.4 MIPS64 REGIMM Encoding of rt Field
let private parseREGIMM release binary =
  let r6 = release = MIPSRelease.R6
  match Bits.extract binary 20u 16u with
  (* Release 6 put DAHI and DATI in two of REGIMM's free rt slots. They
     add an immediate to the upper halves of a register, which is how a
     64-bit constant is built without a load. *)
  | 0b00110u when r6 -> Op.DAHI, None, None, getRsImm16u binary
  | 0b11110u when r6 -> Op.DATI, None, None, getRsImm16u binary
  | 0b00000u -> Op.BLTZ, None, None, getRsRel16 binary
  | 0b00001u -> Op.BGEZ, None, None, getRsRel16 binary
  (* The branch-likely forms. Release 6 removed the whole family, so
     these are pre-Release-6 only -- the same reason BLEZL and BGTZL
     share their opcodes with Release 6's compact-branch pools. *)
  | 0b00010u when not r6 -> Op.BLTZL, None, None, getRsRel16 binary
  | 0b00011u when not r6 -> Op.BGEZL, None, None, getRsRel16 binary
  | 0b10010u when not r6 -> Op.BLTZALL, None, None, getRsRel16 binary
  | 0b10011u when not r6 -> Op.BGEZALL, None, None, getRsRel16 binary
  (* The traps that take a written number. Release 6 removed all six, which
     is why they are guarded where the register forms above are not: a
     Release 6 word in one of these slots is not one of these
     instructions. *)
  | 0b01000u when not r6 -> Op.TGEI, None, None, getRsImm16s binary
  | 0b01001u when not r6 -> Op.TGEIU, None, None, getRsImm16s binary
  | 0b01010u when not r6 -> Op.TLTI, None, None, getRsImm16s binary
  | 0b01011u when not r6 -> Op.TLTIU, None, None, getRsImm16s binary
  | 0b01100u when not r6 -> Op.TEQI, None, None, getRsImm16s binary
  | 0b01110u when not r6 -> Op.TNEI, None, None, getRsImm16s binary
  (* SIGRIE is what Release 6 put in the pool the traps left: an instruction
     whose whole effect is to raise a Reserved Instruction exception, with a
     sixteen-bit code for the handler to read. *)
  | 0b10111u when r6 -> Op.SIGRIE, None, None, getImm16 binary
  | 0b10000u -> Op.BLTZAL, None, None, getRsRel16 binary
  | 0b10001u -> parseBAL binary
  | _ -> raise ParsingFailureException

/// Table A.5 MIPS64 SEPCIAL2 Encoding of Function Field
let private parseSPECIAL2 bin =
  let b15to6 = Bits.extract bin 15u 6u
  let b10to6 = Bits.extract bin 10u 6u
  match Bits.extract bin 5u 0u with
  | 0b000000u ->
    if b15to6 = 0u then Op.MADD, None, None, getRsRt bin
    else raise ParsingFailureException
  | 0b000001u ->
    if b15to6 = 0u then Op.MADDU, None, None, getRsRt bin
    else raise ParsingFailureException
  | 0b000010u ->
    if b10to6 = 0u then Op.MUL, None, None, getRdRsRt bin
    else raise ParsingFailureException
  | 0b000100u ->
    if b15to6 = 0u then Op.MSUB, None, None, getRsRt bin
    else raise ParsingFailureException
  | 0b000101u ->
    if b15to6 = 0u then Op.MSUBU, None, None, getRsRt bin
    else raise ParsingFailureException
  | 0b100000u ->
    parseR2CLZ bin
  | 0b100001u ->
    parseR2CLO bin
  (* SDBBP enters the EJTAG debug exception handler. The twenty bits above
     the function field are a code for that handler and are not held to
     zero. *)
  | 0b111111u ->
    Op.SDBBP, None, None, getCode20 bin
  | 0b100100u ->
    parseR2DCLZ bin
  | 0b100101u ->
    parseR2DCLO bin
  | _ ->
    raise ParsingFailureException

/// Table A.13 MIPS64 BSHFL and DBSHFL Encoding of sa Field
let private parseBSHFL binary =
  let b25to21 = Bits.extract binary 25u 21u
  match Bits.extract binary 10u 6u with
  | 0b000000u ->
    if b25to21 = 0u then Op.BITSWAP, None, None, getRdRt binary
    else raise ParsingFailureException
  | 0b00010u ->
    if b25to21 = 0u then Op.WSBH, None, None, getRdRt binary
    else raise ParsingFailureException
  | b when b &&& 0b11100u = 0b01000u (* 0b010xx *) ->
    Op.ALIGN, None, None, getRdRsRtBp binary
  | 0b10000u ->
    if b25to21 = 0u then Op.SEB, None, None, getRdRt binary
    else raise ParsingFailureException
  | 0b11000u ->
    if b25to21 = 0u then Op.SEH, None, None, getRdRt binary
    else raise ParsingFailureException
  | _ ->
    raise ParsingFailureException

let private parseDBSHFL binary =
  let b25to21 = Bits.extract binary 25u 21u
  match Bits.extract binary 10u 6u with
  | 0b000000u ->
    if b25to21 = 0u then Op.DBITSWAP, None, None, getRdRt binary
    else raise ParsingFailureException
  | 0b00010u ->
    if b25to21 = 0u then Op.DSBH, None, None, getRdRt binary
    else raise ParsingFailureException
  | b when b &&& 0b11000u = 0b01000u (* 0b01xxx *) ->
    Op.DALIGN, None, None, getRdRsRtBp64 binary
  | 0b00101u ->
    if b25to21 = 0u then Op.DSHD, None, None, getRdRt binary
    else raise ParsingFailureException
  | _ ->
    raise ParsingFailureException

/// Table A.6 MIPS64 SEPCIAL3 Encoding of Function Field for Release of the
/// Architecture
let private parseSPECIAL3 release binary =
  let b6 = Bits.pick binary 6u
  match Bits.extract binary 5u 0u with
  | 0b000000u ->
    Op.EXT, None, None, getRtRsPosSize2 binary
  | 0b000001u ->
    Op.DEXTM, None, None, getRtRsPosSize5 binary
  | 0b000010u ->
    Op.DEXTU, None, None, getRtRsPosSize6 binary
  | 0b000011u ->
    Op.DEXT, None, None, getRtRsPosSize2 binary
  | 0b000100u ->
    Op.INS, None, None, getRtRsPosSize binary
  | 0b000101u ->
    Op.DINSM, None, None, getRtRsPosSize3 binary
  | 0b000110u ->
    Op.DINSU, None, None, getRtRsPosSize4 binary
  | 0b000111u ->
    Op.DINS, None, None, getRtRsPosSize binary
  (* The CRC family. Three bits above the size say which polynomial -- 000
     the one IEEE 802 uses and 001 Castagnoli -- and two below them say how
     wide the message element is. The doubleword forms are MIPS64 only, which
     isMIPS64Only carries; the rest are Release 6 whatever the width. *)
  | 0b001111u when release = MIPSRelease.R6 ->
    if Bits.extract binary 15u 11u <> 0u then raise ParsingFailureException
    else ()
    let opcode =
      match Bits.extract binary 10u 8u, Bits.extract binary 7u 6u with
      | 0b000u, 0b00u -> Op.CRC32B
      | 0b000u, 0b01u -> Op.CRC32H
      | 0b000u, 0b10u -> Op.CRC32W
      | 0b000u, 0b11u -> Op.CRC32D
      | 0b001u, 0b00u -> Op.CRC32CB
      | 0b001u, 0b01u -> Op.CRC32CH
      | 0b001u, 0b10u -> Op.CRC32CW
      | 0b001u, 0b11u -> Op.CRC32CD
      | _ -> raise ParsingFailureException
    opcode, None, None, getRtRsRt binary
  (* The EVA loads and stores, which name the OTHER address space: a kernel
     running with Enhanced Virtual Addressing reaches a user mapping through
     these rather than through the ordinary forms. What they do to the value
     is what their non-EVA twins do; the offset is nine bits rather than
     sixteen, which is the only difference a decoder sees. *)
  | 0b011001u ->
    Op.LWLE, None, None, getRtMemBaseOff9 binary 32<rt>
  | 0b011010u ->
    Op.LWRE, None, None, getRtMemBaseOff9 binary 32<rt>
  | 0b011011u ->
    Op.CACHEE, None, None, getHintMemBaseOff9 binary 32<rt>
  | 0b011100u ->
    Op.SBE, None, None, getRtMemBaseOff9 binary 8<rt>
  | 0b011101u ->
    Op.SHE, None, None, getRtMemBaseOff9 binary 16<rt>
  | 0b011110u ->
    if b6 = 0u then
      Op.SCE, None, None, getRtMemBaseOff9 binary 32<rt>
    elif release = MIPSRelease.R6 then
      Op.SCWPE, None, None, getRtRdBase binary 32<rt>
    else
      raise ParsingFailureException
  | 0b011111u ->
    Op.SWE, None, None, getRtMemBaseOff9 binary 32<rt>
  | 0b100001u ->
    Op.SWLE, None, None, getRtMemBaseOff9 binary 32<rt>
  | 0b100010u ->
    Op.SWRE, None, None, getRtMemBaseOff9 binary 32<rt>
  | 0b100011u ->
    Op.PREFE, None, None, getHintMemBaseOff9 binary 32<rt>
  | 0b100101u when release = MIPSRelease.R6 ->
    Op.CACHE, None, None, getHintMemBaseOff9 binary 32<rt>
  | 0b101000u ->
    Op.LBUE, None, None, getRtMemBaseOff9 binary 8<rt>
  | 0b101001u ->
    Op.LHUE, None, None, getRtMemBaseOff9 binary 16<rt>
  | 0b101100u ->
    Op.LBE, None, None, getRtMemBaseOff9 binary 8<rt>
  | 0b101101u ->
    Op.LHE, None, None, getRtMemBaseOff9 binary 16<rt>
  | 0b101110u ->
    if b6 = 0u then
      Op.LLE, None, None, getRtMemBaseOff9 binary 32<rt>
    elif release = MIPSRelease.R6 then
      Op.LLWPE, None, None, getRtRdBase binary 32<rt>
    else
      raise ParsingFailureException
  | 0b101111u ->
    Op.LWE, None, None, getRtMemBaseOff9 binary 32<rt>
  (* The Release 6 global invalidates, which reach the caches and TLBs of the
     OTHER processors in a multiprocessor. Bits 7..6 say which of the two it
     is; GINVT names what kind of translation to drop as well. *)
  | 0b111101u when release = MIPSRelease.R6 ->
    if Bits.extract binary 7u 6u = 0b00u && Bits.extract binary 20u 8u = 0u then
      Op.GINVI, None, None, getRs binary
    elif Bits.extract binary 7u 6u = 0b10u
         && Bits.extract binary 20u 10u = 0u then
      Op.GINVT, None, None, getRsType binary
    else
      raise ParsingFailureException
  | 0b100000u (* BSHFL *) ->
    parseBSHFL binary
  | 0b100100u (* DBSHFL *) ->
    parseDBSHFL binary
  | 0b100110u ->
    if b6 = 0u then
      Op.SC, None, None, getRtMemBaseOff9 binary 32<rt>
    elif release = MIPSRelease.R6 then
      Op.SCWP, None, None, getRtRdBase binary 32<rt>
    else
      raise ParsingFailureException
  | 0b100111u ->
    if b6 = 0u then
      Op.SCD, None, None, getRtMemBaseOff9 binary 64<rt>
    elif release = MIPSRelease.R6 then
      Op.SCDP, None, None, getRtRdBase binary 64<rt>
    else
      raise ParsingFailureException
  | 0b110101u ->
    if b6 = 0u then Op.PREF, None, None, getHintMemBaseOff9 binary 32<rt>
    else raise ParsingFailureException
  | 0b110110u ->
    (* Bit 6 selects the PAIRED form, which Release 6 added so that two
       adjacent words can be read under one watch. *)
    if b6 = 0u then
      Op.LL, None, None, getRtMemBaseOff9 binary 32<rt>
    elif release = MIPSRelease.R6 then
      Op.LLWP, None, None, getRtRdBase binary 32<rt>
    else
      raise ParsingFailureException
  | 0b110111u ->
    if b6 = 0u then
      Op.LLD, None, None, getRtMemBaseOff9 binary 64<rt>
    elif release = MIPSRelease.R6 then
      Op.LLDP, None, None, getRtRdBase binary 64<rt>
    else
      raise ParsingFailureException
  | 0b111011u ->
    if Bits.extract binary 10u 9u = 0u then
      Op.RDHWR, None, None, getRtRdSel binary
    else
      raise ParsingFailureException
  | _ ->
    raise ParsingFailureException

/// The MIPS64 Instruction Set Reference Manual, Revision 6.06
/// on page 70, 93
let private parseBEQ binary =
  match Bits.extract binary 25u 16u with
  | 0u -> Op.B, None, None, getRel16 binary
  | _ -> Op.BEQ, None, None, getRsRtRel16 binary

/// The MIPS64 Instruction Set Reference Manual, Revision 6.06
/// on page 58, 295
let private parseLUIAUI binary =
  match Bits.extract binary 25u 21u with
  | 0u -> Op.LUI, None, None, getRtImm16 binary
  | _ -> Op.AUI, None, None, getRtRsImm16s binary

/// The MIPS64 Instruction Set Reference Manual, Revision 6.06
/// on page 89, 94, 105
let private parsePOP06 binary =
  match Bits.extract binary 20u 16u with
  | 0u -> Op.BLEZ, None, None, getRsRel16 binary
  | _ -> raise ParsingFailureException

/// The MIPS64 Instruction Set Reference Manual, Revision 6.06
/// on page 89, 94, 105
let private parsePOP07 binary =
  match Bits.extract binary 20u 16u with
  | 0u -> Op.BGTZ, None, None, getRsRel16 binary
  | _ -> raise ParsingFailureException

/// PCREL, the major opcode Release 6 gave to the PC-relative family. Which
/// instruction a word means is settled by a variable-length field starting at
/// bit 20, so the wider selectors have to be tested after the narrower ones
/// fail rather than alongside them:
///
///     rs 00   <off19>   ADDIUPC      rs 110   <off18>   LDPC
///     rs 01   <off19>   LWPC         rs 11110 <imm16>   AUIPC
///     rs 10   <off19>   LWUPC        rs 11111 <imm16>   ALUIPC
let private parsePCREL release bin =
  if release <> MIPSRelease.R6 then
    raise ParsingFailureException
  else
    match Bits.extract bin 20u 19u with
    | 0b00u ->
      Op.ADDIUPC, None, None, getRsOff19 bin
    | 0b01u ->
      Op.LWPC, None, None, getRsOff19 bin
    | 0b10u ->
      Op.LWUPC, None, None, getRsOff19 bin
    | _ ->
      match Bits.extract bin 20u 16u with
      | 0b11110u ->
        Op.AUIPC, None, None, getRsImm16u bin
      | 0b11111u ->
        Op.ALUIPC, None, None, getRsImm16u bin
      | _ when Bits.extract bin 20u 18u = 0b110u ->
        Op.LDPC, None, None, getRsOff18 bin
      | _ ->
        raise ParsingFailureException

/// Release 6 put a pool of compact branches on each of the opcodes that used
/// to hold BLEZ, BGTZ, BLEZL, BGTZL, ADDI and DADDI. Which instruction a word
/// means is settled by rs and rt, and the rules below are the manual's own
/// ("Compact Compare-and-Branch Instructions", MD00087 Revision 6.06).
///
/// The pools are only reachable on Release 6. On every earlier release the
/// same opcodes mean what they always did, which is why the caller tests the
/// release before coming here rather than after.
let private parsePOP06R6 bin =
  let rs = Bits.extract bin 25u 21u
  let rt = Bits.extract bin 20u 16u
  if rt = 0u then Op.BLEZ, None, None, getRsRel16 bin
  elif rs = 0u then Op.BLEZALC, None, None, getRtRel16 bin
  elif rs = rt then Op.BGEZALC, None, None, getRtRel16 bin
  else Op.BGEUC, None, None, getRsRtRel16 bin

let private parsePOP07R6 bin =
  let rs = Bits.extract bin 25u 21u
  let rt = Bits.extract bin 20u 16u
  if rt = 0u then Op.BGTZ, None, None, getRsRel16 bin
  elif rs = 0u then Op.BGTZALC, None, None, getRtRel16 bin
  elif rs = rt then Op.BLTZALC, None, None, getRtRel16 bin
  else Op.BLTUC, None, None, getRsRtRel16 bin

let private parsePOP26R6 bin =
  let rs = Bits.extract bin 25u 21u
  let rt = Bits.extract bin 20u 16u
  if rt = 0u then raise ParsingFailureException
  elif rs = 0u then Op.BLEZC, None, None, getRtRel16 bin
  elif rs = rt then Op.BGEZC, None, None, getRtRel16 bin
  else Op.BGEC, None, None, getRsRtRel16 bin

let private parsePOP27R6 bin =
  let rs = Bits.extract bin 25u 21u
  let rt = Bits.extract bin 20u 16u
  if rt = 0u then raise ParsingFailureException
  elif rs = 0u then Op.BGTZC, None, None, getRtRel16 bin
  elif rs = rt then Op.BLTZC, None, None, getRtRel16 bin
  else Op.BLTC, None, None, getRsRtRel16 bin

/// BOVC and BNVC take rs >= rt, which is what separates them from the
/// equality branches sharing their opcode.
let private parsePOP10R6 bin =
  let rs = Bits.extract bin 25u 21u
  let rt = Bits.extract bin 20u 16u
  if rs >= rt then Op.BOVC, None, None, getRsRtRel16 bin
  elif rs = 0u then Op.BEQZALC, None, None, getRtRel16 bin
  else Op.BEQC, None, None, getRsRtRel16 bin

let private parsePOP30R6 bin =
  let rs = Bits.extract bin 25u 21u
  let rt = Bits.extract bin 20u 16u
  if rs >= rt then Op.BNVC, None, None, getRsRtRel16 bin
  elif rs = 0u then Op.BNEZALC, None, None, getRtRel16 bin
  else Op.BNEC, None, None, getRsRtRel16 bin

/// POP66 and POP76 hold an indexed jump when rs is zero and a compact
/// compare-with-zero branch otherwise. The branch's offset is 21 bits, not
/// 16 -- it uses the register field the jump needs for its base.
let private parsePOP66R6 bin =
  if Bits.extract bin 25u 21u = 0u then Op.JIC, None, None, getRtOff16 bin
  else Op.BEQZC, None, None, getRsRel21 bin

let private parsePOP76R6 bin =
  if Bits.extract bin 25u 21u = 0u then Op.JIALC, None, None, getRtOff16 bin
  else Op.BNEZC, None, None, getRsRel21 bin

/// CMP.cond.fmt's condition is the low five bits of the function field.
/// Conditions 0 to 7 mean what the same numbers mean for C.cond.fmt, so
/// they share the Condition type. From 8 up they do NOT: Release 6 puts
/// the signalling forms of 0 to 7 there, where the older encoding has
/// SF, NGLE, SEQ, NGL, LT, NGE, LE and NGT. Those need their own names
/// before they can be decoded, so they are refused rather than silently
/// given the older meaning.
let private parseCMPR6 fmt binary =
  let cond = Bits.extract binary 4u 0u
  if cond > 7u then raise ParsingFailureException
  else Op.CMP, Some(getCondition cond), Some fmt, getFdFsFt binary
/// Table A.18 MIPS64 COP1 Encoding of Function Field When rs=S, Revision 6.06
let private parseCOP1WhenRsS release binary =
  let b20to16 = Bits.extract binary 20u 16u
  let b17to16 = Bits.extract binary 17u 16u (* 0:tf *)
  match Bits.extract binary 5u 0u with
  | 0b010000u when release = MIPSRelease.R6 ->
    Op.SEL, None, Some Fmt.S, getFdFsFt binary
  | 0b010100u when release = MIPSRelease.R6 ->
    Op.SELEQZ, None, Some Fmt.S, getFdFsFt binary
  | 0b010111u when release = MIPSRelease.R6 ->
    Op.SELNEZ, None, Some Fmt.S, getFdFsFt binary
  | 0b011000u when release = MIPSRelease.R6 ->
    Op.MADDF, None, Some Fmt.S, getFdFsFt binary
  | 0b011001u when release = MIPSRelease.R6 ->
    Op.MSUBF, None, Some Fmt.S, getFdFsFt binary
  | 0b011010u when release = MIPSRelease.R6 ->
    Op.RINT, None, Some Fmt.S, getFdFs binary
  | 0b011011u when release = MIPSRelease.R6 ->
    Op.CLASS, None, Some Fmt.S, getFdFs binary
  | 0b011100u when release = MIPSRelease.R6 ->
    Op.MIN, None, Some Fmt.S, getFdFsFt binary
  | 0b011101u when release = MIPSRelease.R6 ->
    Op.MINA, None, Some Fmt.S, getFdFsFt binary
  | 0b011110u when release = MIPSRelease.R6 ->
    Op.MAX, None, Some Fmt.S, getFdFsFt binary
  | 0b011111u when release = MIPSRelease.R6 ->
    Op.MAXA, None, Some Fmt.S, getFdFsFt binary
  | 0b000000u ->
    Op.ADD, None, Some Fmt.S, getFdFsFt binary
  | 0b000001u ->
    Op.SUB, None, Some Fmt.S, getFdFsFt binary
  | 0b000010u ->
    Op.MUL, None, Some Fmt.S, getFdFsFt binary
  | 0b000011u ->
    Op.DIV, None, Some Fmt.S, getFdFsFt binary
  | 0b000100u ->
    Op.SQRT, None, Some Fmt.S, getFdFs binary
  | 0b000101u ->
    Op.ABS, None, Some Fmt.S, getFdFs binary
  | 0b000110u ->
    if b20to16 = 0u then Op.MOV, None, Some Fmt.S, getFdFs binary
    else raise ParsingFailureException
  | 0b000111u ->
    if b20to16 = 0u then Op.NEG, None, Some Fmt.S, getFdFs binary
    else raise ParsingFailureException
  | 0b001000u ->
    if b20to16 = 0u then Op.ROUNDL, None, Some Fmt.S, getFdFs binary
    else raise ParsingFailureException
  | 0b001010u ->
    if b20to16 = 0u then Op.CEILL, None, Some Fmt.S, getFdFs binary
    else raise ParsingFailureException
  | 0b001011u ->
    if b20to16 = 0u then Op.FLOORL, None, Some Fmt.S, getFdFs binary
    else raise ParsingFailureException
  | 0b001100u ->
    if b20to16 = 0u then Op.ROUNDW, None, Some Fmt.S, getFdFs binary
    else raise ParsingFailureException
  | 0b001110u ->
    if b20to16 = 0u then Op.CEILW, None, Some Fmt.S, getFdFs binary
    else raise ParsingFailureException
  | 0b001111u ->
    if b20to16 = 0u then Op.FLOORW, None, Some Fmt.S, getFdFs binary
    else raise ParsingFailureException
  | 0b001001u ->
    if b20to16 = 0u then Op.TRUNCL, None, Some Fmt.S, getFdFs binary
    else raise ParsingFailureException
  | 0b001101u ->
    if b20to16 = 0u then Op.TRUNCW, None, Some Fmt.S, getFdFs binary
    else raise ParsingFailureException
  | 0b010001u ->
    if b17to16 = 0b00u then Op.MOVF, None, Some Fmt.S, getFdFsCc binary
    elif b17to16 = 0b01u then Op.MOVT, None, Some Fmt.S, getFdFsCc binary
    else raise ParsingFailureException
  | 0b010010u ->
    Op.MOVZ, None, Some Fmt.S, getFdFsRt binary
  | 0b010011u ->
    Op.MOVN, None, Some Fmt.S, getFdFsRt binary
  | 0b010101u ->
    Op.RECIP, None, Some Fmt.S, getFdFs binary
  | 0b010110u ->
    Op.RSQRT, None, Some Fmt.S, getFdFs binary
  | 0b100001u ->
    if b20to16 = 0u then Op.CVTD, None, Some Fmt.S, getFdFs binary
    else raise ParsingFailureException
  | 0b100100u ->
    if b20to16 = 0u then Op.CVTW, None, Some Fmt.S, getFdFs binary
    else raise ParsingFailureException
  | 0b100101u ->
    if b20to16 = 0u then Op.CVTL, None, Some Fmt.S, getFdFs binary
    else raise ParsingFailureException
  (* CVT.PS.S reads two singles and writes a pair, so it is the one member of
     the paired-single family whose operands are in the S format and whose
     encoding is therefore in this table rather than in A.21. Release 6
     removed the format. *)
  | 0b100110u when release <> MIPSRelease.R6 ->
    Op.CVTPSS, None, None, getFdFsFt binary
  | b when b &&& 0b110000u = 0b110000u ->
    let cc = Bits.extract binary 10u 8u
    let oprFn = if cc = 0u then getFsFt else getCcFsFt
    let cond = getCondition (Bits.extract binary 3u 0u) |> Some
    Op.C, cond, Some Fmt.S, oprFn binary
  | _ ->
    raise ParsingFailureException

/// Table A.19 MIPS64 COP1 Encoding of Function Field When rs=D, Revision 6.06
let private parseCOP1WhenRsD release binary =
  let b20to16 = Bits.extract binary 20u 16u
  let b17to16 = Bits.extract binary 17u 16u (* 0:tf *)
  match Bits.extract binary 5u 0u with
  | 0b010000u when release = MIPSRelease.R6 ->
    Op.SEL, None, Some Fmt.D, getFdFsFt binary
  | 0b010100u when release = MIPSRelease.R6 ->
    Op.SELEQZ, None, Some Fmt.D, getFdFsFt binary
  | 0b010111u when release = MIPSRelease.R6 ->
    Op.SELNEZ, None, Some Fmt.D, getFdFsFt binary
  | 0b011000u when release = MIPSRelease.R6 ->
    Op.MADDF, None, Some Fmt.D, getFdFsFt binary
  | 0b011001u when release = MIPSRelease.R6 ->
    Op.MSUBF, None, Some Fmt.D, getFdFsFt binary
  | 0b011010u when release = MIPSRelease.R6 ->
    Op.RINT, None, Some Fmt.D, getFdFs binary
  | 0b011011u when release = MIPSRelease.R6 ->
    Op.CLASS, None, Some Fmt.D, getFdFs binary
  | 0b011100u when release = MIPSRelease.R6 ->
    Op.MIN, None, Some Fmt.D, getFdFsFt binary
  | 0b011101u when release = MIPSRelease.R6 ->
    Op.MINA, None, Some Fmt.D, getFdFsFt binary
  | 0b011110u when release = MIPSRelease.R6 ->
    Op.MAX, None, Some Fmt.D, getFdFsFt binary
  | 0b011111u when release = MIPSRelease.R6 ->
    Op.MAXA, None, Some Fmt.D, getFdFsFt binary
  | 0b000000u ->
    Op.ADD, None, Some Fmt.D, getFdFsFt binary
  | 0b000001u ->
    Op.SUB, None, Some Fmt.D, getFdFsFt binary
  | 0b000010u ->
    Op.MUL, None, Some Fmt.D, getFdFsFt binary
  | 0b000011u ->
    Op.DIV, None, Some Fmt.D, getFdFsFt binary
  | 0b000100u ->
    Op.SQRT, None, Some Fmt.D, getFdFs binary
  | 0b000101u ->
    Op.ABS, None, Some Fmt.D, getFdFs binary
  | 0b000110u ->
    if b20to16 = 0u then Op.MOV, None, Some Fmt.D, getFdFs binary
    else raise ParsingFailureException
  | 0b000111u ->
    if b20to16 = 0u then Op.NEG, None, Some Fmt.D, getFdFs binary
    else raise ParsingFailureException
  | 0b001000u ->
    if b20to16 = 0u then Op.ROUNDL, None, Some Fmt.D, getFdFs binary
    else raise ParsingFailureException
  | 0b001010u ->
    if b20to16 = 0u then Op.CEILL, None, Some Fmt.D, getFdFs binary
    else raise ParsingFailureException
  | 0b001011u ->
    if b20to16 = 0u then Op.FLOORL, None, Some Fmt.D, getFdFs binary
    else raise ParsingFailureException
  | 0b001100u ->
    if b20to16 = 0u then Op.ROUNDW, None, Some Fmt.D, getFdFs binary
    else raise ParsingFailureException
  | 0b001110u ->
    if b20to16 = 0u then Op.CEILW, None, Some Fmt.D, getFdFs binary
    else raise ParsingFailureException
  | 0b001111u ->
    if b20to16 = 0u then Op.FLOORW, None, Some Fmt.D, getFdFs binary
    else raise ParsingFailureException
  | 0b001001u ->
    if b20to16 = 0u then Op.TRUNCL, None, Some Fmt.D, getFdFs binary
    else raise ParsingFailureException
  | 0b001101u ->
    if b20to16 = 0u then Op.TRUNCW, None, Some Fmt.D, getFdFs binary
    else raise ParsingFailureException
  | 0b010001u ->
    if b17to16 = 0b00u then Op.MOVF, None, Some Fmt.D, getFdFsCc binary
    elif b17to16 = 0b01u then Op.MOVT, None, Some Fmt.D, getFdFsCc binary
    else raise ParsingFailureException
  | 0b010010u ->
    Op.MOVZ, None, Some Fmt.D, getFdFsRt binary
  | 0b010011u ->
    Op.MOVN, None, Some Fmt.D, getFdFsRt binary
  | 0b010101u ->
    Op.RECIP, None, Some Fmt.D, getFdFs binary
  | 0b010110u ->
    Op.RSQRT, None, Some Fmt.D, getFdFs binary
  | 0b100000u ->
    if b20to16 = 0u then Op.CVTS, None, Some Fmt.D, getFdFs binary
    else raise ParsingFailureException
  | 0b100100u ->
    if b20to16 = 0u then Op.CVTW, None, Some Fmt.D, getFdFs binary
    else raise ParsingFailureException
  | 0b100101u ->
    if b20to16 = 0u then Op.CVTL, None, Some Fmt.D, getFdFs binary
    else raise ParsingFailureException
  | b when b &&& 0b110000u = 0b110000u ->
    let cc = Bits.extract binary 10u 8u
    let oprFn = if cc = 0u then getFsFt else getCcFsFt
    let cond = getCondition (Bits.extract binary 3u 0u) |> Some
    Op.C, cond, Some Fmt.D, oprFn binary
  | _ ->
    raise ParsingFailureException

/// Table A.20 MIPS64 COP1 Encoding of Function Field When rs=W or L,
/// Revision 6.06
let private parseCOP1WhenRsW binary =
  let b20to16 = Bits.extract binary 20u 16u
  match Bits.extract binary 5u 0u with
  | 0b100000u ->
    if b20to16 = 0u then Op.CVTS, None, Some Fmt.W, getFdFs binary
    else raise ParsingFailureException
  | 0b100001u ->
    if b20to16 = 0u then Op.CVTD, None, Some Fmt.W, getFdFs binary
    else raise ParsingFailureException
  | _ ->
    raise ParsingFailureException

/// Table A.20 MIPS64 COP1 Encoding of Function Field When rs=W or L,
/// Revision 6.06
let private parseCOP1WhenRsL binary =
  let b20to16 = Bits.extract binary 20u 16u
  match Bits.extract binary 5u 0u with
  | 0b100000u ->
    if b20to16 = 0u then Op.CVTS, None, Some Fmt.L, getFdFs binary
    else raise ParsingFailureException
  | 0b100001u ->
    if b20to16 = 0u then Op.CVTD, None, Some Fmt.L, getFdFs binary
    else raise ParsingFailureException
  | _ ->
    raise ParsingFailureException

/// <summary>
/// Table A.21 MIPS64 COP1 Encoding of Function Field When rs=PS, Revision
/// 6.06.
///
/// What is decoded here is the part of the format that MOVES halves about:
/// taking one out as a single, and the four ways two pairs can be re-paired.
/// The arithmetic the table also carries -- ADD.PS and its neighbours --
/// applies one operation to both halves at once, and this file's
/// floating-point lifters each name a single number; decoding those without
/// lifting them that way would hand the evaluator a pair to compute on as
/// though it were one double, which is a wrong answer rather than a missing
/// one.
/// </summary>
let private parseCOP1WhenRsPS binary =
  let b20to16 = Bits.extract binary 20u 16u
  match Bits.extract binary 5u 0u with
  | 0b100000u ->
    if b20to16 = 0u then Op.CVTSPU, None, None, getFdFs binary
    else raise ParsingFailureException
  | 0b101000u ->
    if b20to16 = 0u then Op.CVTSPL, None, None, getFdFs binary
    else raise ParsingFailureException
  | 0b101100u ->
    Op.PLLPS, None, None, getFdFsFt binary
  | 0b101101u ->
    Op.PLUPS, None, None, getFdFsFt binary
  | 0b101110u ->
    Op.PULPS, None, None, getFdFsFt binary
  | 0b101111u ->
    Op.PUUPS, None, None, getFdFsFt binary
  | _ ->
    raise ParsingFailureException

let private parseCOP1 arch release binary =
  let b10to0 = Bits.extract binary 10u 0u
  let b17to16 = Bits.extract binary 17u 16u (* nd:tf *)
  match Bits.extract binary 25u 21u with
  | 0b00000u ->
    if b10to0 = 0u then Op.MFC1, None, None, getRtFs binary
    else raise ParsingFailureException
  | 0b00001u ->
    if b10to0 = 0u then Op.DMFC1, None, None, getRtFs binary
    else raise ParsingFailureException
  | 0b00010u ->
    if b10to0 = 0u then Op.CFC1, None, None, getRtFs binary
    else raise ParsingFailureException
  | 0b00011u ->
    if b10to0 = 0u then Op.MFHC1, None, None, getRtFs binary
    else raise ParsingFailureException
  | 0b00100u ->
    if b10to0 = 0u then Op.MTC1, None, None, getRtFs binary
    else raise ParsingFailureException
  | 0b00101u ->
    if b10to0 = 0u then Op.DMTC1, None, None, getRtFs binary
    else raise ParsingFailureException
  | 0b00110u ->
    if b10to0 = 0u then Op.CTC1, None, None, getRtFs binary
    else raise ParsingFailureException
  | 0b00111u ->
    if b10to0 = 0u then Op.MTHC1, None, None, getRtFs binary
    else raise ParsingFailureException
  (* Release 6 replaced the condition-code machinery: a comparison writes
     a whole-register mask into an FPR and these branches test that
     register, so the condition travels in a register rather than in
     FCSR. The conditions themselves are in the low five bits of the
     function field. *)
  | 0b01001u when release = MIPSRelease.R6 ->
    Op.BC1EQZ, None, None, getFtRel16 binary
  | 0b01101u when release = MIPSRelease.R6 ->
    Op.BC1NEZ, None, None, getFtRel16 binary
  | 0b10100u when release = MIPSRelease.R6 ->
    parseCMPR6 Fmt.S binary
  | 0b10101u when release = MIPSRelease.R6 ->
    parseCMPR6 Fmt.D binary
  | 0b01000u ->
    (* bit 17 is nd, the nullify bit, and bit 16 is tf. The two likely
       forms are the same branch with nd set, and nullifying the delay
       slot on the not-taken path is the whole of what nd means. *)
    if b17to16 = 0b00u then Op.BC1F, None, None, getCcOff binary
    elif b17to16 = 0b01u then Op.BC1T, None, None, getCcOff binary
    elif b17to16 = 0b10u then Op.BC1FL, None, None, getCcOff binary
    else Op.BC1TL, None, None, getCcOff binary
  | 0b10000u ->
    parseCOP1WhenRsS release binary
  | 0b10001u ->
    parseCOP1WhenRsD release binary
  | 0b10100u ->
    parseCOP1WhenRsW binary
  | 0b10101u ->
    parseCOP1WhenRsL binary
  | 0b10110u when release <> MIPSRelease.R6 ->
    parseCOP1WhenRsPS binary
  | _ ->
    raise ParsingFailureException

/// Table A.24 MIPS64 COP1X6R1 Encoding of Function Field on page 588,
/// Revision 6.06.
let private parseCOP1X binary =
  let b15to11 = Bits.extract binary 15u 11u
  let b10to6 = Bits.extract binary 10u 6u
  match Bits.extract binary 5u 0u with
  | 0b000000u ->
    if b15to11 = 0u then Op.LWXC1, None, None, getFdMemBaseIdx binary 32<rt>
    else raise ParsingFailureException
  | 0b000001u ->
    let b15to11 = Bits.extract binary 15u 11u
    if b15to11 = 0u then Op.LDXC1, None, None, getFdMemBaseIdx binary 64<rt>
    else raise ParsingFailureException
  (* LUXC1 and SUXC1 name a doubleword and IGNORE the low three bits of the
     address rather than faulting on them, which is what makes them usable
     for the unaligned array of pairs that ALNV.PS exists to read. *)
  | 0b000101u ->
    if b15to11 = 0u then Op.LUXC1, None, None, getFdMemBaseIdx binary 64<rt>
    else raise ParsingFailureException
  | 0b001000u ->
    if b10to6 = 0u then Op.SWXC1, None, None, getFsMemBaseIdx binary 32<rt>
    else raise ParsingFailureException
  | 0b001001u ->
    if b10to6 = 0u then Op.SDXC1, None, None, getFsMemBaseIdx binary 64<rt>
    else raise ParsingFailureException
  | 0b001101u ->
    if b10to6 = 0u then Op.SUXC1, None, None, getFsMemBaseIdx binary 64<rt>
    else raise ParsingFailureException
  | 0b001111u ->
    if b10to6 = 0u then Op.PREFX, None, None, getHintMemBaseIdx binary 32<rt>
    else raise ParsingFailureException
  | 0b011110u ->
    Op.ALNVPS, None, None, getFdFsFtRs binary
  | 0b100000u ->
    Op.MADD, None, Some Fmt.S, getFdFrFsFt binary
  | 0b100001u ->
    Op.MADD, None, Some Fmt.D, getFdFrFsFt binary
  | 0b100110u ->
    Op.MADD, None, Some Fmt.PS, getFdFrFsFt binary
  | 0b101000u ->
    Op.MSUB, None, Some Fmt.S, getFdFrFsFt binary
  | 0b101001u ->
    Op.MSUB, None, Some Fmt.D, getFdFrFsFt binary
  | 0b101110u ->
    Op.MSUB, None, Some Fmt.PS, getFdFrFsFt binary
  | 0b110000u ->
    Op.NMADD, None, Some Fmt.S, getFdFrFsFt binary
  | 0b110001u ->
    Op.NMADD, None, Some Fmt.D, getFdFrFsFt binary
  | 0b110110u ->
    Op.NMADD, None, Some Fmt.PS, getFdFrFsFt binary
  | 0b111000u ->
    Op.NMSUB, None, Some Fmt.S, getFdFrFsFt binary
  | 0b111001u ->
    Op.NMSUB, None, Some Fmt.D, getFdFrFsFt binary
  | 0b111110u ->
    Op.NMSUB, None, Some Fmt.PS, getFdFrFsFt binary
  | _ ->
    raise ParsingFailureException

/// <summary>
/// Table A.14 MIPS64 COP0 Encoding of rs Field, Revision 6.06, when rs names
/// the MFMC0 function: the two interrupt-control instructions and, in
/// Release 6, the two virtual-processor ones.
///
/// Which of the four a word is takes the rd field and the low three bits as
/// well as the rs field, because MFMC0 is one encoding covering all of them:
/// rd = 12 with 000 below is DI and EI, rd = 0 with 100 below is DVP and EVP,
/// and bit 5 chooses within each pair.
/// </summary>
let private parseMFMC0 release binary =
  let sc = Bits.pick binary 5u
  match Bits.extract binary 15u 11u, Bits.extract binary 2u 0u with
  | 0b01100u, 0b000u ->
    if sc = 0u then
      Op.DI, None, None, getRt binary
    else
      Op.EI, None, None, getRt binary
  | 0b00000u, 0b100u when release = MIPSRelease.R6 ->
    if sc = 0u then
      Op.EVP, None, None, getRt binary
    else
      Op.DVP, None, None, getRt binary
  | _ ->
    raise ParsingFailureException

/// <summary>
/// Table A.15 MIPS64 COP0 Encoding of Function Field When rs=CO, Revision
/// 6.06: the TLB instructions, the three exception returns and WAIT.
///
/// ERET and ERETNC share a function field and differ in bit 6 alone, which is
/// the whole of what "no clear" means -- ERETNC leaves the LLbit an LL had
/// set where ERET clears it.
/// </summary>
let private parseCOP0WhenCO binary =
  match Bits.extract binary 5u 0u with
  | 0b000001u ->
    Op.TLBR, None, None, NoOperand
  | 0b000010u ->
    Op.TLBWI, None, None, NoOperand
  | 0b000011u ->
    Op.TLBINV, None, None, NoOperand
  | 0b000100u ->
    Op.TLBINVF, None, None, NoOperand
  | 0b000110u ->
    Op.TLBWR, None, None, NoOperand
  | 0b001000u ->
    Op.TLBP, None, None, NoOperand
  | 0b011000u ->
    if Bits.pick binary 6u = 0u then
      Op.ERET, None, None, NoOperand
    else
      Op.ERETNC, None, None, NoOperand
  | 0b011111u ->
    Op.DERET, None, None, NoOperand
  | 0b100000u ->
    Op.WAIT, None, None, NoOperand
  | _ ->
    raise ParsingFailureException

/// <summary>
/// Table A.14 MIPS64 COP0 Encoding of rs Field, Revision 6.06.
///
/// The six register moves differ only in how wide a move they make and which
/// half of the register they name, and each names its CP0 register by a
/// (rd, sel) PAIR -- sel being the low three bits of the word, not the three
/// that RDHWR puts its own sel in.
///
/// Checked against binutils: MFC0 of register 12 into GPR 8 assembles to
/// 0x40086000, which objdump renders as a read of c0_status.
/// </summary>
let private parseCOP0 release binary =
  if Bits.pick binary 25u = 1u then
    parseCOP0WhenCO binary
  else
    let oprs = getRtRdSel0 binary
    (* Bits 10..3 are zero in every one of the moves. RDPGPR and WRPGPR read
       the same fields as a register pair instead, so they are not held to
       it. *)
    let reserved = Bits.extract binary 10u 3u
    match Bits.extract binary 25u 21u with
    | 0b00000u when reserved = 0u ->
      Op.MFC0, None, None, oprs
    | 0b00001u when reserved = 0u ->
      Op.DMFC0, None, None, oprs
    | 0b00010u when reserved = 0u ->
      Op.MFHC0, None, None, oprs
    | 0b00100u when reserved = 0u ->
      Op.MTC0, None, None, oprs
    | 0b00101u when reserved = 0u ->
      Op.DMTC0, None, None, oprs
    | 0b00110u when reserved = 0u ->
      Op.MTHC0, None, None, oprs
    | 0b01010u ->
      Op.RDPGPR, None, None, getRdRt binary
    | 0b01011u ->
      parseMFMC0 release binary
    | 0b01110u ->
      Op.WRPGPR, None, None, getRdRt binary
    | _ ->
      raise ParsingFailureException

/// The MIPS64 Instrecutin Set Reference Manual, MD00087, Revision 6.06
/// Table A.2 MIPS64 Encoding of the Opcode Field
let private parseOpcodeField arch binary wordSize release =
  match Bits.extract binary 31u 26u with
  | 0b000000u ->
    parseSPECIAL release binary
  | 0b000001u ->
    parseREGIMM release binary
  | 0b000010u ->
    Op.J, None, None, getTarget binary
  | 0b000011u ->
    Op.JAL, None, None, getTarget binary
  | 0b000100u ->
    parseBEQ binary
  | 0b000101u ->
    Op.BNE, None, None, getRsRtRel16 binary
  | 0b000110u ->
    if release = MIPSRelease.R6 then parsePOP06R6 binary
    else parsePOP06 binary
  | 0b000111u ->
    if release = MIPSRelease.R6 then parsePOP07R6 binary
    else parsePOP07 binary
  | 0b001000u ->
    (* ADDI before Release 6; Release 6 reassigned this primary opcode to
       POP10 (BOVC/BEQZALC/BEQC). *)
    if release = MIPSRelease.R6 then parsePOP10R6 binary
    else Op.ADDI, None, None, getRtRsImm16s binary
  | 0b001001u ->
    Op.ADDIU, None, None, getRtRsImm16s binary
  | 0b001010u ->
    Op.SLTI, None, None, getRtRsImm16s binary
  | 0b001011u ->
    Op.SLTIU, None, None, getRtRsImm16s binary
  | 0b001100u ->
    Op.ANDI, None, None, getRtRsImm16 binary
  | 0b001101u ->
    Op.ORI, None, None, getRtRsImm16 binary
  | 0b001110u ->
    Op.XORI, None, None, getRtRsImm16 binary
  | 0b001111u ->
    parseLUIAUI binary
  | 0b010000u ->
    parseCOP0 release binary
  | 0b010001u ->
    parseCOP1 arch release binary
  | 0b010010u ->
    raise ParsingFailureException (* COP2 *)
  | 0b010011u ->
    parseCOP1X binary
  | 0b010100u ->
    Op.BEQL, None, None, getRsRtRel16 binary
  | 0b010101u ->
    Op.BNEL, None, None, getRsRtRel16 binary
  | 0b010110u ->
    if release = MIPSRelease.R6 then
      parsePOP26R6 binary
    elif Bits.extract binary 20u 16u = 0u then
      Op.BLEZL, None, None, getRsRel16 binary
    else
      raise ParsingFailureException
  | 0b010111u ->
    if release = MIPSRelease.R6 then
      parsePOP27R6 binary
    elif Bits.extract binary 20u 16u = 0u then
      Op.BGTZL, None, None, getRsRel16 binary
    else
      raise ParsingFailureException
  | 0b011000u ->
    (* DADDI before Release 6; Release 6 reassigned it to POP30. *)
    if release = MIPSRelease.R6 then parsePOP30R6 binary
    else Op.DADDI, None, None, getRtRsImm16s binary
  | 0b011001u ->
    Op.DADDIU, None, None, getRtRsImm16s binary
  | 0b011010u ->
    Op.LDL, None, None, getRtMemBaseOff binary 64<rt>
  | 0b011011u ->
    Op.LDR, None, None, getRtMemBaseOff binary 64<rt>
  | 0b011100u ->
    parseSPECIAL2 binary
  | 0b011101u ->
    (* Release 6 has no other encoding to cross into, so it took JALX away
       and gave the primary opcode to DAUI. *)
    if release = MIPSRelease.R6 then
      Op.DAUI, None, None, getRtRsImm16u binary
    else
      Op.JALX, None, None, getTarget binary
  | 0b011110u ->
    raise ParsingFailureException (* MSA *)
  | 0b011111u ->
    parseSPECIAL3 release binary
  | 0b100000u ->
    Op.LB, None, None, getRtMemBaseOff binary 8<rt>
  | 0b100001u ->
    Op.LH, None, None, getRtMemBaseOff binary 16<rt>
  | 0b100010u ->
    Op.LWL, None, None, getRtMemBaseOff binary 32<rt>
  | 0b100011u ->
    Op.LW, None, None, getRtMemBaseOff binary 32<rt>
  | 0b100100u ->
    Op.LBU, None, None, getRtMemBaseOff binary 8<rt>
  | 0b100101u ->
    Op.LHU, None, None, getRtMemBaseOff binary 16<rt>
  | 0b100110u ->
    Op.LWR, None, None, getRtMemBaseOff binary 32<rt>
  | 0b100111u ->
    Op.LWU, None, None, getRtMemBaseOff binary 32<rt>
  | 0b101000u ->
    Op.SB, None, None, getRtMemBaseOff binary 8<rt>
  | 0b101001u ->
    Op.SH, None, None, getRtMemBaseOff binary 16<rt>
  | 0b101010u ->
    Op.SWL, None, None, getRtMemBaseOff binary 32<rt>
  | 0b101011u ->
    Op.SW, None, None, getRtMemBaseOff binary 32<rt>
  | 0b101100u ->
    Op.SDL, None, None, getRtMemBaseOff binary 64<rt>
  | 0b101101u ->
    Op.SDR, None, None, getRtMemBaseOff binary 64<rt>
  | 0b101110u ->
    Op.SWR, None, None, getRtMemBaseOff binary 32<rt>
  | 0b101111u ->
    (* Release 6 moved CACHE into SPECIAL3, where its offset is nine bits
       rather than sixteen, and left this opcode unused. *)
    if release = MIPSRelease.R6 then raise ParsingFailureException
    else Op.CACHE, None, None, getHintMemBaseOff binary 32<rt>
  | 0b110000u (* pre-Release 6 *) ->
    Op.LL, None, None, getRtMemBaseOff binary 32<rt>
  | 0b110001u ->
    Op.LWC1, None, None, getFtMemBaseOff binary 32<rt>
  | 0b110010u ->
    if release = MIPSRelease.R6 then Op.BC, None, None, getRel26 binary
    else raise ParsingFailureException (* LWC2 *)
  | 0b110011u (* pre-Release 6 *) ->
    Op.PREF, None, None, getHintMemBaseOff binary 32<rt>
  | 0b110100u (* MIPS64 pre-Release 6 *) ->
    Op.LLD, None, None, getRtMemBaseOff binary 64<rt>
  | 0b110101u ->
    Op.LDC1, None, None, getFtMemBaseOff binary (WordSize.toRegType wordSize)
  | 0b110110u ->
    if release = MIPSRelease.R6 then parsePOP66R6 binary
    else raise ParsingFailureException (* LDC2 *)
  | 0b110111u ->
    Op.LD, None, None, getRtMemBaseOff binary 64<rt>
  | 0b111000u (* pre-Release 6 *) ->
    Op.SC, None, None, getRtMemBaseOff binary 32<rt>
  | 0b111001u ->
    Op.SWC1, None, None, getFtMemBaseOff binary 32<rt>
  | 0b111010u ->
    if release = MIPSRelease.R6 then
      Op.BALC, None, None, getRel26 binary
    else
      raise ParsingFailureException (* SWC2 *)
  | 0b111011u ->
    parsePCREL release binary
  | 0b111100u (* pre-Release 6 *) ->
    Op.SCD, None, None, getRtMemBaseOff binary 64<rt>
  | 0b111101u ->
    Op.SDC1, None, None, getFtMemBaseOff binary (WordSize.toRegType wordSize)
  | 0b111110u ->
    if release = MIPSRelease.R6 then parsePOP76R6 binary
    else raise ParsingFailureException (* SDC2 *)
  | 0b111111u ->
    Op.SD, None, None, getRtMemBaseOff binary 64<rt>
  | _ ->
    raise ParsingFailureException

/// How wide the value an instruction moves is, which the stores settle for
/// themselves and everything else takes from the word size.
let getOperationSize opcode wordSz =
  match opcode with
  | Op.SB -> 8<rt>
  | Op.SH -> 16<rt>
  | Op.SW -> 32<rt>
  | Op.SD -> 64<rt>
  | _ -> WordSize.toRegType wordSz

/// <summary>
/// Whether an opcode is one only a 64-bit CPU has. MD00087 says so on
/// each instruction's own page, to the right of its Format line: the
/// field reads MIPS64 where the 32-bit architecture has no such
/// instruction at all. A word holding one of these encodings is a
/// Reserved Instruction on MIPS32, so it is not an instruction there.
///
/// Which encoding the word was read from makes no difference: microMIPS32
/// has no 64-bit instructions either, and its own opcode map leaves the
/// major opcodes theirs would need empty.
/// </summary>
let isMIPS64Only = function
  | Op.DADD | Op.DADDI | Op.DADDIU | Op.DADDU | Op.DAHI | Op.DALIGN
  | Op.DATI | Op.DAUI | Op.DBITSWAP | Op.DCLZ | Op.DDIV | Op.DDIVU
  | Op.DEXT | Op.DEXTM | Op.DEXTU | Op.DINS | Op.DINSM | Op.DINSU
  | Op.DLSA | Op.DMFC1 | Op.DMOD | Op.DMODU | Op.DMTC1 | Op.DMUH
  | Op.DMUHU | Op.DMUL | Op.DMULT | Op.DMULTU | Op.DMULU | Op.DROTR
  | Op.DROTR32 | Op.DROTRV | Op.DSBH | Op.DSHD | Op.DSLL | Op.DSLL32
  | Op.DSLLV | Op.DSRA | Op.DSRA32 | Op.DSRAV | Op.DSRL | Op.DSRL32
  | Op.DSRLV | Op.DSUB | Op.DSUBU | Op.LD | Op.LDL | Op.LDPC | Op.LDR
  | Op.LLD | Op.LLDP | Op.LWU | Op.LWUPC | Op.SCD | Op.SCDP | Op.SD
  | Op.SDL | Op.SDR
  (* The two CRC forms over a doubleword. The byte, halfword and word forms
     are MIPS32 as well, and only the element they read is wider here. *)
  | Op.CRC32D | Op.CRC32CD -> true
  | _ -> false

let parse lifter span (reader: IBinReader) arch wordSize release addr =
  let bin = reader.ReadUInt32(span = span, offset = 0)
  let opcode, cond, fmt, oprs = parseOpcodeField arch bin wordSize release
  if wordSize = WordSize.Bit32 && isMIPS64Only opcode then
    raise ParsingFailureException
  else
    ()
  let sz = getOperationSize opcode wordSize
  Instruction(addr, 4u, cond, fmt, opcode, oprs, sz, wordSize, false, lifter)
