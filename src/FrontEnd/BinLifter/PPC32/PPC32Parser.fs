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
  | _ -> raise ParsingFailureException

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
  | _ -> raise ParsingFailureException

let getCondRegister = function
  | 0b000u -> CR.CR0
  | 0b001u -> CR.CR1
  | 0b010u -> CR.CR2
  | 0b011u -> CR.CR3
  | 0b100u -> CR.CR4
  | 0b101u -> CR.CR5
  | 0b110u -> CR.CR6
  | 0b111u -> CR.CR7
  | _ -> raise ParsingFailureException

let getCRM bin = bin |> uint64 |> Immediate

let getSegRegister bin = bin |> uint64 |> Immediate

let getSPRegister bin =  bin |> uint64 |> Immediate

let getTBRRegister bin = bin |> uint64 |> Immediate

let getFPSCRegister bin = bin |> uint64 |> Immediate

let getFM bin = bin |> uint64 |> Immediate

let parseTWI bin =
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let value = extract bin 15u 0u |> uint64 |> Immediate
  match extract bin 25u 21u with
  (* twlgti ra,value = twi 1,ra,value *)
  | 0x1u -> struct (Op.TWLGTI, TwoOperands (ra, value))
  (* twllti ra,value = twi 2,ra,value *)
  | 0x2u -> struct (Op.TWLLTI, TwoOperands (ra, value))
  (* tweqi ra,value = twi 4,ra,value *)
  | 0x4u -> struct (Op.TWEQI, TwoOperands (ra, value))
  (* twlnli ra,value = twi 5,ra,value *)
  | 0x5u -> struct (Op.TWLNLI, TwoOperands (ra, value))
  (* twgti ra,value = twi 8,ra,value *)
  | 0x8u -> struct (Op.TWGTI, TwoOperands (ra, value))
  (* twlti ra,value = twi 16,ra,value *)
  | 0x10u -> struct (Op.TWLTI, TwoOperands (ra, value))
  (*  twnei ra,value = twi 24,ra,value *)
  | 0x18u -> struct (Op.TWNEI, TwoOperands (ra, value))
  (* twllei ra,value = twlngi ra, value = twi 6,ra,value
     twgei ra,value = twlgei ra, value = twnli ra, value = twi 12,ra,value
     twlei ra,value = twngi ra, value = twi 20,ra,value *)
  | _ ->
    let tO = extract bin 25u 21u |> uint64 |> Immediate
    struct (Op.TWI, ThreeOperands (tO, ra, value))

let parseMULLI bin =
  let rd = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let simm = extract bin 15u 0u |> uint64 |> Immediate
  struct (Op.MULLI, ThreeOperands (rd, ra, simm))

let parseSUBFIC bin =
  let rd = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let simm = extract bin 15u 0u |> uint64 |> Immediate
  struct (Op.SUBFIC, ThreeOperands (rd, ra, simm))

let parseCMPLI bin =
  match pickBit bin 22u with
  | 0b0u ->
    let crfd = getCondRegister (extract bin 25u 23u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let uimm = extract bin 15u 0u |> uint64 |> Immediate
    match pickBit bin 21u with
    (* cmplwi crfd,ra,uimm = cmpli crfd,0,ra,uimm *)
    | 0b0u -> struct (Op.CMPLWI, ThreeOperands (crfd, ra, uimm))
    | _ -> struct (Op.CMPLI, FourOperands (crfd, Immediate 1UL, ra, uimm))
  | _ (* 1 *) -> raise ParsingFailureException

let parseCMPI bin =
  match pickBit bin 22u with
  | 0b0u ->
    let crfd = getCondRegister (extract bin 25u 23u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let simm = extract bin 15u 0u |> uint64 |> Immediate
    match pickBit bin 21u with
    (* cmpwl crfd,ra,uimm = cmpl crfd,0,ra,uimm *)
    | 0b0u -> struct (Op.CMPWI, ThreeOperands (crfd, ra, simm))
    | _ -> struct (Op.CMPI, FourOperands (crfd, Immediate 1UL, ra, simm))
  | _ (* 1 *) -> raise ParsingFailureException

let parseADDIC bin =
  let rd = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let value = extract bin 15u 0u |> uint64 |> Immediate
  (* subic rd,ra,value = addic rd,ra,-value *)
  struct (Op.ADDIC, ThreeOperands (rd, ra, value))

let parseADDICdot bin =
  let rd = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let value = extract bin 15u 0u |> uint64 |> Immediate
  (* subic. rd,ra,value = addic. rd,ra,-value *)
  struct (Op.ADDICdot, ThreeOperands (rd, ra, value))

let parseADDI bin =
  let rd = getRegister (extract bin 25u 21u) |> OpReg
  let value = extract bin 15u 0u |> uint64 |> Immediate
  match extract bin 20u 16u with
  | 0b0u -> struct (Op.LI, TwoOperands (rd, value))
  (* subi rd,ra,value = addi rd,ra,-value *)
  | _ ->
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.ADDI, ThreeOperands (rd, ra, value))

let parseADDIS bin =
  let rd = getRegister (extract bin 25u 21u) |> OpReg
  let value = extract bin 15u 0u |> uint64 |> Immediate
  match extract bin 20u 16u with
  | 0b0u -> struct (Op.LIS, TwoOperands (rd, value))
  (* subis rd,ra,value = addis rd,ra,-value *)
  | _ ->
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    struct (Op.ADDIS, ThreeOperands (rd, ra, value))

let parseBCx bin =
  let bd = extract bin 15u 2u |> uint64 |> Immediate
  match extract bin 1u 0u (* AA:LK *) with
  | 0b00u ->
    match extract bin 25u 21u with
    (* bdnzf bi,target = bc 0,bi,target *)
    | 0x0u ->
      let bi = extract bin 20u 16u |> uint64 |> Branch
      struct (Op.BDNZF, TwoOperands (bi, bd))
    (* bdzf bi,target = bc 2,bi,target *)
    | 0x2u ->
      let bi = extract bin 20u 16u |> uint64 |> Branch
      struct (Op.BDZF, TwoOperands (bi, bd))
    | 0x4u ->
      match extract bin 20u 18u with
      | 0b0u ->
        match extract bin 17u 16u with
        (* bf 0,target = bnl 0,target = bge target = bc 4,0,target *)
        | 0b00u -> struct (Op.BGE, OneOperand bd)
        (* bf 1,target = bng 0,target = ble target = bc 4,1,target *)
        | 0b01u -> struct (Op.BLE, OneOperand bd)
        (* bf 2,target = bne target = bc 4,2,target *)
        | 0b10u -> struct (Op.BNE, OneOperand bd)
        (* bf 3,target = bnu 0,target = bns target = bc 4,3,target *)
        | _ (* 1 *) -> struct (Op.BNS, OneOperand bd)
      | _ ->
        let crs = getCondRegister (extract bin 20u 18u) |> OpReg
        match extract bin 17u 16u with
        (* bf 4*crs,target = bnl crs,target = bge crs,target
        = bc 4,4*crs,target *)
        | 0b00u -> struct (Op.BGE, TwoOperands (crs, bd))
        (* bf 4*crs+1,target = bng crs,target = ble crs,target
        = bc 4,4*crs+1,target *)
        | 0b01u -> struct (Op.BLE, TwoOperands (crs, bd))
        (* bf 4*crs+2,target = bne crs,target = bc 4,4*crs+2,target *)
        | 0b10u -> struct (Op.BNE, TwoOperands (crs, bd))
        (* bf 4*crs+3,target = bnu crs,target = bns crs,target
        = bc 4,4*crs+3,target *)
        | _ (* 1 *) -> struct (Op.BNS, TwoOperands (crs, bd))
    (* bdnzt bi,target = bc 8,bi,target *)
    | 0x8u ->
      let bi = extract bin 20u 16u |> uint64 |> Branch
      struct (Op.BDNZT, TwoOperands (bi, bd))
    (* bdzt bi,target = bc 10,bi,target *)
    | 0xAu ->
      let bi = extract bin 20u 16u |> uint64 |> Branch
      struct (Op.BDZT, TwoOperands (bi, bd))
    | 0xCu ->
      match extract bin 20u 18u with
      | 0b0u ->
        match extract bin 17u 16u with
        (* bt 0,target = blt target = bc 12,0,target *)
        | 0b00u -> struct (Op.BLT, OneOperand bd)
        (* bt 1,0 = bgt target = bc 12,1,target *)
        | 0b01u -> struct (Op.BGT, OneOperand bd)
        (* bt 2,0 = beq target = bc 12,2,target *)
        | 0b10u -> struct (Op.BEQ, OneOperand bd)
        (* bt 3,0 = bun 0,target = bso target = bc 12,3,target *)
        | _ (* 1 *) -> struct (Op.BSO, OneOperand bd)
      | _ ->
        let crs = getCondRegister (extract bin 20u 18u) |> OpReg
        match extract bin 17u 16u with
        (* bt 4*crs,target = blt crs,target = bc 12,4*crs,target *)
        | 0b00u -> struct (Op.BLT, TwoOperands (crs, bd))
        (* bt 4*crs+1,target = bgt crs,target = bc 12,4*crs+1,target *)
        | 0b01u -> struct (Op.BGT, TwoOperands (crs, bd))
        (* bt 4*crs+2,target = beq crs,target = bc 12,4*crs+2,target *)
        | 0b10u -> struct (Op.BEQ, TwoOperands (crs, bd))
        (* bt 4*crs+3,target = bun crs,target = bso crs,target
        = bc 12,4*crs+3,target *)
        | _ (* 1 *) -> struct (Op.BSO, TwoOperands (crs, bd))
    | 0x10u ->
      match extract bin 20u 16u with
      (* bdnz target = bc 16,0,target *)
      | 0b0u -> struct (Op.BDNZ, OneOperand bd)
      | _ ->
        let bo = extract bin 25u 21u |> uint64 |> Immediate
        let bi = extract bin 20u 16u |> uint64 |> Branch
        struct (Op.BC, ThreeOperands (bo, bi, bd))
    | 0x12u ->
      match extract bin 20u 16u with
      (* bdz target = bc 18,0,target *)
      | 0b0u -> struct (Op.BDZ, OneOperand bd)
      | _ ->
        let bo = extract bin 25u 21u |> uint64 |> Immediate
        let bi = extract bin 20u 16u |> uint64 |> Branch
        struct (Op.BC, ThreeOperands (bo, bi, bd))
    | _ ->
      let bo = extract bin 25u 21u |> uint64 |> Immediate
      let bi = extract bin 20u 16u |> uint64 |> Branch
      struct (Op.BC, ThreeOperands (bo, bi, bd))
  | 0b01u ->
    match extract bin 25u 21u with
    (* bdnzfl bi,target = bcl 0,bi,target *)
    | 0x0u ->
      let bi = extract bin 20u 16u |> uint64 |> Branch
      struct (Op.BDNZFL, TwoOperands (bi, bd))
    (* bdzfl bi,target = bcl 2,bi,target *)
    | 0x2u ->
      let bi = extract bin 20u 16u |> uint64 |> Branch
      struct (Op.BDZFL, TwoOperands (bi, bd))
    | 0x4u ->
      match extract bin 20u 18u with
      | 0b0u ->
        match extract bin 17u 16u with
        (* bfl 0,target = bnll 0,target = bgel target = bcl 4,0,target *)
        | 0b00u -> struct (Op.BGEL, OneOperand bd)
        (* bfl 1,0 = bngl 0,target = blel target = bcl 4,1,target *)
        | 0b01u -> struct (Op.BLEL, OneOperand bd)
        (* bfl 2,0 = bnel target = bcl 4,2,target *)
        | 0b10u -> struct (Op.BNEL, OneOperand bd)
        (* bfl 3,0 = bnul 0,target = bnsl target = bcl 4,3,target *)
        | _ (* 1 *) -> struct (Op.BNSL, OneOperand bd)
      | _ ->
        let crs = getCondRegister (extract bin 20u 18u) |> OpReg
        match extract bin 17u 16u with
        (* bfl 4*crs,target = bnll crs,target = bgel crs,target
        = bcl 4,4*crs,target *)
        | 0b00u -> struct (Op.BGEL, TwoOperands (crs, bd))
        (* bfl 4*crs+1,target = bngl crs,target = blel crs,target
        = bcl 4,4*crs+1,target *)
        | 0b01u -> struct (Op.BLEL, TwoOperands (crs, bd))
        (* bfl 4*crs+2,target = bnel crs,target = bcl 4,4*crs+2,target *)
        | 0b10u -> struct (Op.BNEL, TwoOperands (crs, bd))
        (*bfl 4*crs+3,target = bnul crs,target = bnsl crs,target
        = bcl 4,4*crs+3,target *)
        | _ (* 1 *) -> struct (Op.BNSL, TwoOperands (crs, bd))
    (* bdnztl bi,target = bc 8,bi,target *)
    | 0x8u ->
      let bi = extract bin 20u 16u |> uint64 |> Branch
      struct (Op.BDNZTL, TwoOperands (bi, bd))
    (* bdztl bi,target = bc 10,bi,target *)
    | 0xAu ->
      let bi = extract bin 20u 16u |> uint64 |> Branch
      struct (Op.BDZTL, TwoOperands (bi, bd))
    | 0xCu ->
      match extract bin 20u 18u with
      | 0b0u ->
        match extract bin 17u 16u with
        (* btl 0,target = bltl target = bcl 12,0,target *)
        | 0b00u -> struct (Op.BLTL, OneOperand bd)
        (* btl 1,target = bgtl target = bcl 12,1,target *)
        | 0b01u -> struct (Op.BGTL, OneOperand bd)
        (* btl 2,target = beql target = bcl 12,2,target *)
        | 0b10u -> struct (Op.BEQL, OneOperand bd)
        (* btl 3,target = bunl 0,target = bsol target = bcl 12,3,target *)
        | _ (* 1 *) -> struct (Op.BSOL, OneOperand bd)
      | _ ->
        let crs = getCondRegister (extract bin 20u 18u) |> OpReg
        match extract bin 17u 16u with
        (* btl 4*crs,target = bltl crs,target = bcl 12,4*crs,target *)
        | 0b00u -> struct (Op.BLTL, TwoOperands (crs, bd))
        (* btl 4*crs+1,target = bgtl crs,target = bcl 12,4*crs+1,target *)
        | 0b01u -> struct (Op.BGTL, TwoOperands (crs, bd))
        (* btl 4*crs+2,target = beql crs,target = bcl 12,4*crs+2,target *)
        | 0b10u -> struct (Op.BEQL, TwoOperands (crs, bd))
        (* btl 4*crs+3,target = bunl crs,target = bsol crs,target
        = bcl 12,4*crs+3,target *)
        | _ (* 1 *) -> struct (Op.BSOL, TwoOperands (crs, bd))
    | 0x10u ->
      match extract bin 20u 16u with
      (* bdnzl target = bcl 16,0,target *)
      | 0b0u -> struct (Op.BDNZL, OneOperand bd)
      | _ ->
        let bo = extract bin 25u 21u |> uint64 |> Immediate
        let bi = extract bin 20u 16u |> uint64 |> Branch
        struct (Op.BCL, ThreeOperands (bo, bi, bd))
    | 0x12u ->
      match extract bin 20u 16u with
      (* bdzl target = bcl 18,0,target *)
      | 0b0u -> struct (Op.BDZL, OneOperand bd)
      | _ ->
        let bo = extract bin 25u 21u |> uint64 |> Immediate
        let bi = extract bin 20u 16u |> uint64 |> Branch
        struct (Op.BCL, ThreeOperands (bo, bi, bd))
    | _ ->
      let bo = extract bin 25u 21u |> uint64 |> Immediate
      let bi = extract bin 20u 16u |> uint64 |> Branch
      struct (Op.BCL, ThreeOperands (bo, bi, bd))
  | 0b10u ->
    match extract bin 25u 21u with
    (* bdnzfa bi,target = bca 0,bi,target0 *)
    | 0x0u ->
      let bi = extract bin 20u 16u |> uint64 |> Branch
      struct (Op.BDNZFA, TwoOperands (bi, bd))
    (* bdzfa bi,target = bca 2,bi,target *)
    | 0x2u ->
      let bi = extract bin 20u 16u |> uint64 |> Branch
      struct (Op.BDZFA, TwoOperands (bi, bd))
    | 0x4u ->
      match extract bin 20u 18u with
      | 0b0u ->
        match extract bin 17u 16u with
        (* bfa 0,target = bnla 0,target = bgea target = bca 4,0,target *)
        | 0b00u -> struct (Op.BGEA, OneOperand bd)
        (* bfa 1,target = bnga 0,target = blea target = bca 4,1,target *)
        | 0b01u -> struct (Op.BLEA, OneOperand bd)
        (* bfa 2,target = bnea target = bca 4,2,target *)
        | 0b10u -> struct (Op.BNEA, OneOperand bd)
        (* bfa 3,target = bnua 0,target = bnsa target = bca 4,3,target *)
        | _ (* 1 *) -> struct (Op.BNSA, OneOperand bd)
      | _ ->
        let crs = getCondRegister (extract bin 20u 18u) |> OpReg
        match extract bin 17u 16u with
        (* bfa 4*crs,target = bnla crs,target = bgea crs,target
        = bca 4,4*crs,target *)
        | 0b00u -> struct (Op.BGEA, TwoOperands (crs, bd))
        (* bfa 4*crs+1,target = bnga crs,target = blea crs,target
        = bca 4,4*crs+1,target *)
        | 0b01u -> struct (Op.BLEA, TwoOperands (crs, bd))
        (* bfa 4*crs+2,target = bnea crs,target = bca 4,4*crs+2,target *)
        | 0b10u -> struct (Op.BNEA, TwoOperands (crs, bd))
        (* bfa 4*crs+3,target = bnua crs,target = bnsa crs,target
        = bca 4,4*crs+3,target *)
        | _ (* 1 *) -> struct (Op.BNSA, TwoOperands (crs, bd))
    (* bdnzta bi,target = bc 8,bi,target *)
    | 0x8u ->
      let bi = extract bin 20u 16u |> uint64 |> Branch
      struct (Op.BDNZTA, TwoOperands (bi, bd))
    (* bdzta bi,target = bc 10,bi,target *)
    | 0xAu ->
      let bi = extract bin 20u 16u |> uint64 |> Branch
      struct (Op.BDZTA, TwoOperands (bi, bd))
    | 0xCu ->
      match extract bin 20u 18u with
      | 0b0u ->
        match extract bin 17u 16u with
        (* bta 0,target = blta target = bca 12,0,target *)
        | 0b00u -> struct (Op.BLTA, OneOperand bd)
        (* bta 1,target = bgta target = bca 12,1,target *)
        | 0b01u -> struct (Op.BGTA, OneOperand bd)
        (* bta 2,target = beqa target = bca 12,2,target *)
        | 0b10u -> struct (Op.BEQA, OneOperand bd)
        (* bta 3,target = buna 0,target = bsoa target = bca 12,3,target *)
        | _ (* 1 *) -> struct (Op.BSOA, OneOperand bd)
      | _ ->
        let crs = getCondRegister (extract bin 20u 18u) |> OpReg
        match extract bin 17u 16u with
        (* bta 4*crs,target = blta crs,target = bca 12,4*crs,target *)
        | 0b00u -> struct (Op.BLTA, TwoOperands (crs, bd))
        (* bta 4*crs+1,target = bgta crs,target = bca 12,4*crs+1,target *)
        | 0b01u -> struct (Op.BGTA, TwoOperands (crs, bd))
        (* bta 4*crs+2,target = beqa crs,target = bca 12,4*crs+2,target *)
        | 0b10u -> struct (Op.BEQA, TwoOperands (crs, bd))
        (* bta 4*crs+3,target = buna crs,target = bsoa crs,target
        = bca 12,4*crs+3,target *)
        | _ (* 1 *) -> struct (Op.BSOA, TwoOperands (crs, bd))
    | 0x10u ->
      match extract bin 20u 16u with
      (* bdnza target = bca 16,0,target *)
      | 0b0u -> struct (Op.BDNZA, OneOperand bd)
      | _ ->
        let bo = extract bin 25u 21u |> uint64 |> Immediate
        let bi = extract bin 20u 16u |> uint64 |> Branch
        struct (Op.BCA, ThreeOperands (bo, bi, bd))
    | 0x12u ->
      match extract bin 20u 16u with
      (* bdza target = bca 18,0,target *)
      | 0b0u -> struct (Op.BDZA, OneOperand bd)
      | _ ->
        let bo = extract bin 25u 21u |> uint64 |> Immediate
        let bi = extract bin 20u 16u |> uint64 |> Branch
        struct (Op.BCA, ThreeOperands (bo, bi, bd))
    | _ ->
      let bo = extract bin 25u 21u |> uint64 |> Immediate
      let bi = extract bin 20u 16u |> uint64 |> Branch
      struct (Op.BCA, ThreeOperands (bo, bi, bd))
  | _ (* 11 *) ->
    match extract bin 25u 21u with
    (* bdnzfla bi,target = bcla 0,bi,target *)
    | 0x0u ->
      let bi = extract bin 20u 16u |> uint64 |> Branch
      struct (Op.BDNZFLA, TwoOperands (bi, bd))
    (* bdzfla bi,target = bcla 2,bi,target *)
    | 0x2u ->
      let bi = extract bin 20u 16u |> uint64 |> Branch
      struct (Op.BDZFLA, TwoOperands (bi, bd))
    | 0x4u ->
      match extract bin 20u 18u with
      | 0b0u ->
        match extract bin 17u 16u with
        (* bfla 0,target = bnlla 0,target = bgela target = bcla 4,0,target *)
        | 0b00u -> struct (Op.BGELA, OneOperand bd)
        (* bfla 1,target = bngla 0,target = blela target = bcla 4,1,target *)
        | 0b01u -> struct (Op.BLELA, OneOperand bd)
        (* bfla 2,target = bnela target = bcla 4,2,target *)
        | 0b10u -> struct (Op.BNELA, OneOperand bd)
        (* bfla 3,target = bnula 0,target = bnsla target = bcla 4,3,target *)
        | _ (* 1 *) -> struct (Op.BNSLA, OneOperand bd)
      | _ ->
        let crs = getCondRegister (extract bin 20u 18u) |> OpReg
        match extract bin 17u 16u with
        (* bfla 4*crs,target = bnlla crs,target = bgela crs,target
        = bcla 4,4*crs,target *)
        | 0b00u -> struct (Op.BGELA, TwoOperands (crs, bd))
        (* bfla 4*crs+1,target = bngla crs,target = blela crs,target
        = bcla 4,4*crs+1,target *)
        | 0b01u -> struct (Op.BLELA, TwoOperands (crs, bd))
        (* bfla 4*crs+2,target = bnela crs,target = bcla 4,4*crs+2,target *)
        | 0b10u -> struct (Op.BNELA, TwoOperands (crs, bd))
        (* bfla 4*crs+3,target = bnula crs,target = bnsla crs,target
        = bcla 4,4*crs+3,target *)
        | _ (* 1 *) -> struct (Op.BNSLA, TwoOperands (crs, bd))
    (* bdnztla bi,target = bc 8,bi,target *)
    | 0x8u ->
      let bi = extract bin 20u 16u |> uint64 |> Branch
      struct (Op.BDNZTLA, TwoOperands (bi, bd))
    (* bdztla bi,target = bc 10,bi,target *)
    | 0xAu ->
      let bi = extract bin 20u 16u |> uint64 |> Branch
      struct (Op.BDZTLA, TwoOperands (bi, bd))
    | 0xCu ->
      match extract bin 20u 18u with
      | 0b0u ->
        match extract bin 17u 16u with
        (* btla 0,target = bltla target = bcla 12,0,target *)
        | 0b00u -> struct (Op.BLTLA, OneOperand bd)
        (* btla 1,target = bgtla target = bcla 12,1,target *)
        | 0b01u -> struct (Op.BGTLA, OneOperand bd)
        (* btla 2,target = beqla target = bcla 12,2,target *)
        | 0b10u -> struct (Op.BEQLA, OneOperand bd)
        (* btla 3,target = bunla crs,target = bsola target = bcla 12,3,target *)
        | _ (* 1 *) -> struct (Op.BSOLA, OneOperand bd)
      | _ ->
        let crs = getCondRegister (extract bin 20u 18u) |> OpReg
        match extract bin 17u 16u with
        (* btla 4*crs,target = bltla crs,target = bcla 12,4*crs,target *)
        | 0b00u -> struct (Op.BLTLA, TwoOperands (crs, bd))
        (* btla 4*crs+1,target = bgtla crs,target = bcla 12,4*crs+1,target *)
        | 0b01u -> struct (Op.BGTLA, TwoOperands (crs, bd))
        (* btla 4*crs+2,target = beqla crs,target = bcla 12,4*crs+2,target *)
        | 0b10u -> struct (Op.BEQLA, TwoOperands (crs, bd))
        (* btla 4*crs+3,target = bunla crs,target = bsola crs,target
        = bcla 12,4*crs+3,target *)
        | _ (* 1 *) -> struct (Op.BSOLA, TwoOperands (crs, bd))
    | 0x10u ->
      match extract bin 20u 16u with
      (* bdnzla target = bcLA 16,0,target *)
      | 0b0u -> struct (Op.BDNZLA, OneOperand bd)
      | _ ->
        let bo = extract bin 25u 21u |> uint64 |> Immediate
        let bi = extract bin 20u 16u |> uint64 |> Branch
        struct (Op.BCLA, ThreeOperands (bo, bi, bd))
    | 0x12u ->
      match extract bin 20u 16u with
      (* bdzla target = bcLA 18,0,target *)
      | 0b0u -> struct (Op.BDZLA, OneOperand bd)
      | _ ->
        let bo = extract bin 25u 21u |> uint64 |> Immediate
        let bi = extract bin 20u 16u |> uint64 |> Branch
        struct (Op.BCLA, ThreeOperands (bo, bi, bd))
    | _ ->
      let bo = extract bin 25u 21u |> uint64 |> Immediate
      let bi = extract bin 20u 16u |> uint64 |> Branch
      struct (Op.BCLA, ThreeOperands (bo, bi, bd))

let parseSC bin =
  match pickBit bin 1u with
  | 0b1u -> struct (Op.SC, NoOperand)
  | _ -> raise ParsingFailureException

let parseBx bin =
  let li = extract bin 25u 2u |> uint64 |> Immediate
  match extract bin 1u 0u (* AA:LK *) with
  | 0b00u -> struct (Op.B, OneOperand li)
  | 0b01u -> struct (Op.BL, OneOperand li)
  | 0b10u -> struct (Op.BA, OneOperand li)
  | _ (* 11 *) -> struct (Op.BLA, OneOperand li)

let parseMCRF bin =
  match pickBit bin 0u with
  | 0b0u when concat (extract bin 22u 21u) (extract bin 17u 11u) 2 = 0u ->
    let crfd = getCondRegister (extract bin 25u 23u) |> OpReg
    let crfs = getCondRegister (extract bin 20u 18u) |> OpReg
    struct (Op.MCRF, TwoOperands (crfd, crfs))
  | _ (* 1 *) -> raise ParsingFailureException

let parseBCLRx bin =
  match pickBit bin 0u with
  | 0b0u when extract bin 15u 11u = 0u ->
    match extract bin 25u 21u with
    (* bdnzflr bi = bclr 0,bi *)
    | 0x0u ->
      let bi = extract bin 20u 16u |> uint64 |> Branch
      struct (Op.BDNZFLR, OneOperand bi)
    (* bdzflr bi = bclr 2,bi *)
    | 0x2u ->
      let bi = extract bin 20u 16u |> uint64 |> Branch
      struct (Op.BDZFLR, OneOperand bi)
    | 0x4u ->
      match extract bin 20u 18u with
      | 0b0u ->
        match extract bin 17u 16u with
        (* bflr 0 = bnllr 0 = bgelr = bclr 4,0 *)
        | 0b00u -> struct (Op.BGELR, NoOperand)
        (* bflr 1 = bnglr 0 = blelr = bclr 4,1 *)
        | 0b01u -> struct (Op.BLELR, NoOperand)
        (* bflr 2 = bnelr = bclr 4,2 *)
        | 0b10u -> struct (Op.BNELR, NoOperand)
        (* bflr 3 = bnulr 0 = bnslr = bclr 4,3 *)
        | _ (* 1 *) -> struct (Op.BNSLR, NoOperand)
      | _ ->
        let crs = getCondRegister (extract bin 20u 18u) |> OpReg
        match extract bin 17u 16u with
        (* bflr 4*crs = bnllr crs = bgelr crs = bclr 4,4*crs *)
        | 0b00u -> struct (Op.BGELR, OneOperand crs)
        (* bflr 4*crs+1 = bnglr crs = blelr crs = bclr 4,4*crs+1 *)
        | 0b01u -> struct (Op.BLELR, OneOperand crs)
        (* bflr 4*crs+2 = bnelr crs = bclr 4,4*crs+2 *)
        | 0b10u -> struct (Op.BNELR, OneOperand crs)
        (* bflr 4*crs+3 = bnulr crs = bnslr crs = bclr 4,4*crs+3 *)
        | _ (* 1 *) -> struct (Op.BNSLR, OneOperand crs)
    (* bdnztlr bi = bclr 8,bi *)
    | 0x8u ->
      let bi = extract bin 20u 16u |> uint64 |> Branch
      struct (Op.BDNZTLR, OneOperand bi)
    (* bdztlr bi = bclr 10,bi *)
    | 0xAu ->
      let bi = extract bin 20u 16u |> uint64 |> Branch
      struct (Op.BDZTLR, OneOperand bi)
    | 0xCu ->
      match extract bin 20u 18u with
      | 0b0u ->
        match extract bin 17u 16u with
        (* btlr 0 = bltlr = bclr 12,0 *)
        | 0b00u -> struct (Op.BLTLR, NoOperand)
        (* btlr 1 = bgtlr = bclr 12,1 *)
        | 0b01u -> struct (Op.BGTLR, NoOperand)
        (* btlr 2 = beqlr = bclr 12,2 *)
        | 0b10u -> struct (Op.BEQLR, NoOperand)
        (* btlr 3 = bunlr 0 = bsolr = bclr 12,3 *)
        | _ (* 1 *) -> struct (Op.BSOLR, NoOperand)
      | _ ->
        let crs = getCondRegister (extract bin 20u 18u) |> OpReg
        match extract bin 17u 16u with
        (* btlr 4*crs = bltlr crs = bclr 12,4*crs *)
        | 0b00u -> struct (Op.BLTLR, OneOperand crs)
        (* btlr 4*crs+1,0 = bgtlr crs = bclr 12,4*crs+1 *)
        | 0b01u -> struct (Op.BGTLR, OneOperand crs)
        (* btlr 4*crs+2,0 = beqlr crs = bclr 12,4*crs+2 *)
        | 0b10u -> struct (Op.BEQLR, OneOperand crs)
        (* btlr 4*crs+3,0 = bunlr crs = bsolr crs = bclr 12,4*crs+3 *)
        | _ (* 1 *) -> struct (Op.BSOLR, OneOperand crs)
    | 0x10u ->
      match extract bin 20u 16u with
      (* bdnzlr = bclr 16,0 *)
      | 0b0u -> struct (Op.BDNZLR, NoOperand)
      | _ ->
        let bo = extract bin 25u 21u |> uint64 |> Immediate
        let bi = extract bin 20u 16u |> uint64 |> Branch
        struct (Op.BCLR, TwoOperands (bo, bi))
    | 0x12u ->
      match extract bin 20u 16u with
      (* bdzlr = bclr 18,0 *)
      | 0b0u -> struct (Op.BDZLR, NoOperand)
      | _ ->
        let bo = extract bin 25u 21u |> uint64 |> Immediate
        let bi = extract bin 20u 16u |> uint64 |> Branch
        struct (Op.BCLR, TwoOperands (bo, bi))
    | 0x14u ->
      match extract bin 20u 16u with
      (* blr = bclr 20,0 *)
      | 0b0u -> struct (Op.BLR, NoOperand)
      | _ ->
        let bo = extract bin 25u 21u |> uint64 |> Immediate
        let bi = extract bin 20u 16u |> uint64 |> Branch
        struct (Op.BCLR, TwoOperands (bo, bi))
    | _ ->
      let bo = extract bin 25u 21u |> uint64 |> Immediate
      let bi = extract bin 20u 16u |> uint64 |> Branch
      struct (Op.BCLR, TwoOperands (bo, bi))
  | 0b1u when extract bin 15u 11u = 0u ->
    match extract bin 25u 21u with
    (* bdnzflrl bi = bclrl 0,bi *)
    | 0x0u ->
      let bi = extract bin 20u 16u |> uint64 |> Branch
      struct (Op.BDNZFLRL, OneOperand bi)
    (* bdzflrl bi = bclrl 2,bi *)
    | 0x2u ->
      let bi = extract bin 20u 16u |> uint64 |> Branch
      struct (Op.BDZFLRL, OneOperand bi)
    | 0x4u ->
      match extract bin 20u 18u with
      | 0b0u ->
        match extract bin 17u 16u with
        (* bflrl 0 = bnllrl 0 = bgelrl = bclrl 4,0 *)
        | 0b00u -> struct (Op.BGELRL, NoOperand)
        (* bflrl 1 = bnglrl 0 = blelrl = bclrl 4,1 *)
        | 0b01u -> struct (Op.BLELRL, NoOperand)
        (* bflrl 2 = bnelrl = bclrl 4,2 *)
        | 0b10u -> struct (Op.BNELRL, NoOperand)
        (* bflrl 3 = bnulrl 0 = bnslrl = bclrl 4,3 *)
        | _ (* 1 *) -> struct (Op.BNSLRL, NoOperand)
      | _ ->
        let crs = getCondRegister (extract bin 20u 18u) |> OpReg
        match extract bin 17u 16u with
        (* bflrl 4*crs = bnllrl crs = bgelrl crs = bclrl 4,4*crs *)
        | 0b00u -> struct (Op.BGELRL, OneOperand crs)
        (* bflrl 4*crs+1 = bnglrl crs = blelrl crs = bclrl 4,4*crs+1 *)
        | 0b01u -> struct (Op.BLELRL, OneOperand crs)
        (* bflrl 4*crs+2 = bnelrl crs = bclrl 4,4*crs+2 *)
        | 0b10u -> struct (Op.BNELRL, OneOperand crs)
        (* bflrl 4*crs+3 = bnulrl crs = bnslrl crs = bclrl 4,4*crs+3 *)
        | _ (* 1 *) -> struct (Op.BNSLRL, OneOperand crs)
    (* bdnztlrl bi = bclrl 8,bi *)
    | 0x8u ->
      let bi = extract bin 20u 16u |> uint64 |> Branch
      struct (Op.BDNZTLRL, OneOperand bi)
    (* bdztlrl bi = bclr 10,bi *)
    | 0xAu ->
      let bi = extract bin 20u 16u |> uint64 |> Branch
      struct (Op.BDZTLRL, OneOperand bi)
    | 0xCu ->
      match extract bin 20u 18u with
      | 0b0u ->
        match extract bin 17u 16u with
        (* btlrl 0 = bltlrl = bclrl 12,0 *)
        | 0b00u -> struct (Op.BLTLRL, NoOperand)
        (* btlrl 1 = bgtlrl = bclrl 12,1 *)
        | 0b01u -> struct (Op.BGTLRL, NoOperand)
        (* btlrl 2 = beqlrl = bclrl 12,2 *)
        | 0b10u -> struct (Op.BEQLRL, NoOperand)
        (* btlrl 3 = bunlrl 0 = bsolrl = bclrl 12,3 *)
        | _ (* 1 *) -> struct (Op.BSOLRL, NoOperand)
      | _ ->
        let crs = getCondRegister (extract bin 20u 18u) |> OpReg
        match extract bin 17u 16u with
        (* btlrl 4*crs = bltlrl crs = bclrl 12,4*crs *)
        | 0b00u -> struct (Op.BLTLRL, OneOperand crs)
        (* btlrl 4*crs+1,0 = bgtlrl crs = bclrl 12,4*crs+1 *)
        | 0b01u -> struct (Op.BGTLRL, OneOperand crs)
        (* btlrl 4*crs+2,0 = beqlrl crs = bclrl 12,4*crs+2 *)
        | 0b10u -> struct (Op.BEQLRL, OneOperand crs)
        (* btlrl 4*crs+3,0 = bunlrl crs = bsolrl crs = bclrl 12,4*crs+3 *)
        | _ (* 1 *) -> struct (Op.BSOLRL, OneOperand crs)
    | 0x10u ->
      match extract bin 20u 16u with
      (* bdnzlrl = bclrl 16,0 *)
      | 0b0u -> struct (Op.BDNZLRL, NoOperand)
      | _ ->
        let bo = extract bin 25u 21u |> uint64 |> Immediate
        let bi = extract bin 20u 16u |> uint64 |> Branch
        struct (Op.BCLRL, TwoOperands (bo, bi))
    | 0x12u ->
      match extract bin 20u 16u with
      (* bdzlrl = bclrl 18,0 *)
      | 0b0u -> struct (Op.BDZLRL, NoOperand)
      | _ ->
        let bo = extract bin 25u 21u |> uint64 |> Immediate
        let bi = extract bin 20u 16u |> uint64 |> Branch
        struct (Op.BCLRL, TwoOperands (bo, bi))
    | 0x14u ->
      match extract bin 20u 16u with
      (* blrl = bclrl 20,0 *)
      | 0b0u -> struct (Op.BLRL, NoOperand)
      | _ ->
        let bo = extract bin 25u 21u |> uint64 |> Immediate
        let bi = extract bin 20u 16u |> uint64 |> Branch
        struct (Op.BCLRL, TwoOperands (bo, bi))
    | _ ->
      let bo = extract bin 25u 21u |> uint64 |> Immediate
      let bi = extract bin 20u 16u |> uint64 |> Branch
      struct (Op.BCLRL, TwoOperands (bo, bi))
  | _ -> raise ParsingFailureException

let parseCRNOR bin =
  match pickBit bin 0u with
  | 0b0u ->
    let crbd = getFPSCRegister (extract bin 25u 21u)
    let crba = getFPSCRegister (extract bin 20u 16u)
    (* crnot crbd,crba = crnor crbd,crba,crba *)
    if extract bin 20u 16u = extract bin 15u 11u then
      struct (Op.CRNOT, TwoOperands (crbd, crba))
    else
      let crbb = getFPSCRegister (extract bin 15u 11u)
      struct (Op.CRNOR, ThreeOperands (crbd, crba, crbb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseRFI bin =
  match pickBit bin 0u with
  | 0b0u when extract bin 25u 11u = 0u ->
    struct (Op.RFI, NoOperand)
  | _ (* 1 *) -> raise ParsingFailureException

let parseCRANDC bin =
  match pickBit bin 0u with
  | 0b0u ->
    let crbd = getFPSCRegister (extract bin 25u 21u)
    let crba = getFPSCRegister (extract bin 20u 16u)
    let crbb = getFPSCRegister (extract bin 15u 11u)
    struct (Op.CRANDC, ThreeOperands (crbd, crba, crbb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseISYNC bin =
  match pickBit bin 0u with
  | 0b0u when extract bin 25u 11u = 0u ->
    struct (Op.ISYNC, NoOperand)
  | _ (* 1 *) -> raise ParsingFailureException

let parseCRXOR bin =
  match pickBit bin 0u with
  | 0b0u ->
    let crbd = getFPSCRegister (extract bin 25u 21u)
    (* crclr crbd = crxor crbd,crbd,crbd *)
    if extract bin 25u 21u = extract bin 20u 16u then
      if extract bin 20u 16u = extract bin 15u 11u then
        struct (Op.CRCLR, OneOperand crbd)
      else
        let crba = getFPSCRegister (extract bin 20u 16u)
        let crbb = getFPSCRegister (extract bin 15u 11u)
        struct (Op.CRXOR, ThreeOperands (crbd, crba, crbb))
    else
      let crba = getFPSCRegister (extract bin 20u 16u)
      let crbb = getFPSCRegister (extract bin 15u 11u)
      struct (Op.CRXOR, ThreeOperands (crbd, crba, crbb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseCRNAND bin =
  match pickBit bin 0u with
  | 0b0u ->
    let crbd = getFPSCRegister (extract bin 25u 21u)
    let crba = getFPSCRegister (extract bin 20u 16u)
    let crbb = getFPSCRegister (extract bin 15u 11u)
    struct (Op.CRNAND, ThreeOperands (crbd, crba, crbb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseCRAND bin =
  match pickBit bin 0u with
  | 0b0u ->
    let crbd = getFPSCRegister (extract bin 25u 21u)
    let crba = getFPSCRegister (extract bin 20u 16u)
    let crbb = getFPSCRegister (extract bin 15u 11u)
    struct (Op.CRAND, ThreeOperands (crbd, crba, crbb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseCREQV bin =
  match pickBit bin 0u with
  | 0b0u ->
    let crbd = getFPSCRegister (extract bin 25u 21u)
    (* crset crbd = creqv crbd,crbd,crbd *)
    if extract bin 25u 21u = extract bin 20u 16u then
      if extract bin 20u 16u = extract bin 15u 11u then
        struct (Op.CRSET, OneOperand crbd)
      else
        let crba = getFPSCRegister (extract bin 20u 16u)
        let crbb = getFPSCRegister (extract bin 15u 11u)
        struct (Op.CREQV, ThreeOperands (crbd, crba, crbb))
    else
      let crba = getFPSCRegister (extract bin 20u 16u)
      let crbb = getFPSCRegister (extract bin 15u 11u)
      struct (Op.CREQV, ThreeOperands (crbd, crba, crbb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseCRORC bin =
  match pickBit bin 0u with
  | 0b0u ->
    let crbd = getFPSCRegister (extract bin 25u 21u)
    let crba = getFPSCRegister (extract bin 20u 16u)
    let crbb = getFPSCRegister (extract bin 15u 11u)
    struct (Op.CRORC, ThreeOperands (crbd, crba, crbb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseCROR bin =
  match pickBit bin 0u with
  | 0b0u ->
    let crbd = getFPSCRegister (extract bin 25u 21u)
    let crba = getFPSCRegister (extract bin 20u 16u)
    (* crmove crbd,crba = cror crbd,crba,crba *)
    if extract bin 20u 16u = extract bin 15u 11u then
      struct (Op.CRMOVE, TwoOperands (crbd, crba))
    else
      let crbb = getFPSCRegister (extract bin 15u 11u)
      struct (Op.CROR, ThreeOperands (crbd, crba, crbb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseBCCTRx bin =
  match pickBit bin 0u with
  | 0b0u when extract bin 15u 11u = 0u ->
    match extract bin 25u 21u with
    | 0x4u ->
      match extract bin 20u 18u with
      | 0b0u ->
        match extract bin 17u 16u with
        (* bfctr 0 = bnctr 0 = bgectr = bcctr 4,0 *)
        | 0b00u -> struct (Op.BGECTR, NoOperand)
        (* bfctr 1 = bngctr 0 = blectr = bcctr 4,1 *)
        | 0b01u -> struct (Op.BLECTR, NoOperand)
        (* bfctr 2 = bnectr = bcctr 4,2 *)
        | 0b10u -> struct (Op.BNECTR, NoOperand)
        (* bfctr 3 = bnuctr 0 = bnsctr = bcctr 4,3 *)
        | _ (* 1 *) -> struct (Op.BNSCTR, NoOperand)
      | _ ->
        let crs = getCondRegister (extract bin 20u 18u) |> OpReg
        match extract bin 17u 16u with
        (* bfctr 4*crs = bnlctr crs = bgectr crs = bcctr 4,4*crs *)
        | 0b00u -> struct (Op.BGECTR, OneOperand crs)
        (* bfctr 4*crs+1 = bngctr crs = blectr crs = bcctr 4,4*crs+1 *)
        | 0b01u -> struct (Op.BLECTR, OneOperand crs)
        (* bfctr 4*crs+2 = bnectr crs = bcctr 4,4*crs+2 *)
        | 0b10u -> struct (Op.BNECTR, OneOperand crs)
        (* bfctr 4*crs+3 = bnuctr crs = bnsctr crs = bcctr 4,4*crs+3 *)
        | _ (* 1 *) -> struct (Op.BNSCTR, OneOperand crs)
    | 0xCu ->
      match extract bin 20u 18u with
      | 0b0u ->
        match extract bin 17u 16u with
        (* btctr 0 = bltctr = bcctr 12,0 *)
        | 0b00u -> struct (Op.BLTCTR, NoOperand)
        (* btctr 1 = bgtctr = bcctr 12,1 *)
        | 0b01u -> struct (Op.BGTCTR, NoOperand)
        (* btctr 2 = beqctr = bcctr 12,2 *)
        | 0b10u -> struct (Op.BEQCTR, NoOperand)
        (* btctr 3 = bunctr 0 = bsoctr = bcctr 12,3 *)
        | _ (* 1 *) -> struct (Op.BSOCTR, NoOperand)
      | _ ->
        let crs = getCondRegister (extract bin 20u 18u) |> OpReg
        match extract bin 17u 16u with
        (* btctr 4*crs = bltctr crs = bcctr 12,4*crs *)
        | 0b00u -> struct (Op.BLTCTR, OneOperand crs)
        (* btctr 4*crs+1,0 = bgtctr crs = bcctr 12,4*crs+1 *)
        | 0b01u -> struct (Op.BGTCTR, OneOperand crs)
        (* btctr 4*crs+2,0 = beqctr crs = bcctr 12,4*crs+2 *)
        | 0b10u -> struct (Op.BEQCTR, OneOperand crs)
        (* btctr 4*crs+3,0 = bunctr crs = bsoctr crs = bcctr 12,4*crs+3 *)
        | _ (* 1 *) -> struct (Op.BSOCTR, OneOperand crs)
    | 0x14u ->
      match extract bin 20u 16u with
      (* bctr = bcctr 20,0 *)
      | 0b0u -> struct (Op.BCTR, NoOperand)
      | _ ->
        let bo = extract bin 25u 21u |> uint64 |> Immediate
        let bi = extract bin 20u 16u |> uint64 |> Branch
        struct (Op.BCCTR, TwoOperands (bo, bi))
    | _ ->
      let bo = extract bin 25u 21u |> uint64 |> Immediate
      let bi = extract bin 20u 16u |> uint64 |> Branch
      struct (Op.BCCTR, TwoOperands (bo, bi))
  | 0b1u when extract bin 15u 11u = 0u ->
    match extract bin 25u 21u with
    | 0x4u ->
      match extract bin 20u 18u with
      | 0b0u ->
        match extract bin 17u 16u with
        (* bfctrl 0 = bnctrl 0 = bgectrl = bcctrl 4,0 *)
        | 0b00u -> struct (Op.BGECTRL, NoOperand)
        (* bfctrl 1 = bngctrl 0 = blectrl = bcctrl 4,1 *)
        | 0b01u -> struct (Op.BLECTRL, NoOperand)
        (* bfctrl 2 = bnectrl = bcctrl 4,2 *)
        | 0b10u -> struct (Op.BNECTRL, NoOperand)
        (* bfctrl 3 = bnuctrl 0 = bnsctrl = bcctrl 4,3 *)
        | _ (* 1 *) -> struct (Op.BNSCTRL, NoOperand)
      | _ ->
        let crs = getCondRegister (extract bin 20u 18u) |> OpReg
        match extract bin 17u 16u with
        (* bfctrl 4*crs = bnlctrl crs = bgectrl crs = bcctrl 4,4*crs *)
        | 0b00u -> struct (Op.BGECTRL, OneOperand crs)
        (* bfctrl 4*crs+1 = bngctrl crs = blectrl crs = bcctrl 4,4*crs+1 *)
        | 0b01u -> struct (Op.BLECTRL, OneOperand crs)
        (* bfctrl 4*crs+2 = bnectrl crs = bcctrl 4,4*crs+2 *)
        | 0b10u -> struct (Op.BNECTRL, OneOperand crs)
        (* bfctrl 4*crs+3 = bnuctrl crs = bnsctrl crs = bcctrl 4,4*crs+3 *)
        | _ (* 1 *) -> struct (Op.BNSCTRL, OneOperand crs)
    | 0xCu ->
      match extract bin 20u 18u with
      | 0b0u ->
        match extract bin 17u 16u with
        (* btctrl 0 = bltctrl = bcctrl 12,0 *)
        | 0b00u -> struct (Op.BLTCTRL, NoOperand)
        (* btctrl 1 = bgtctrl = bcctrl 12,1 *)
        | 0b01u -> struct (Op.BGTCTRL, NoOperand)
        (* btctrl 2 = beqctrl = bcctrl 12,2 *)
        | 0b10u -> struct (Op.BEQCTRL, NoOperand)
        (* btctrl 3 = bunctrl 0 = bsoctrl = bcctrl 12,3 *)
        | _ (* 1 *) -> struct (Op.BSOCTRL, NoOperand)
      | _ ->
        let crs = getCondRegister (extract bin 20u 18u) |> OpReg
        match extract bin 17u 16u with
        (* btctrl 4*crs = bltctrl crs = bcctrl 12,4*crs *)
        | 0b00u -> struct (Op.BLTCTRL, OneOperand crs)
        (* btctrl 4*crs+1,0 = bgtctrl crs = bcctrl 12,4*crs+1 *)
        | 0b01u -> struct (Op.BGTCTRL, OneOperand crs)
        (* btctrl 4*crs+2,0 = beqctrl crs = bcctrl 12,4*crs+2 *)
        | 0b10u -> struct (Op.BEQCTRL, OneOperand crs)
        (* btctrl 4*crs+3,0 = bunctrl crs = bsoctrl crs = bcctrl 12,4*crs+3 *)
        | _ (* 1 *) -> struct (Op.BSOCTRL, OneOperand crs)
    | 0x14u ->
      match extract bin 20u 16u with
      (* bctrl = bcctrl 20,0 *)
      | 0b0u -> struct (Op.BCTRL, NoOperand)
      | _ ->
        let bo = extract bin 25u 21u |> uint64 |> Immediate
        let bi = extract bin 20u 16u |> uint64 |> Branch
        struct (Op.BCCTRL, TwoOperands (bo, bi))
    | _ ->
      let bo = extract bin 25u 21u |> uint64 |> Immediate
      let bi = extract bin 20u 16u |> uint64 |> Branch
      struct (Op.BCCTRL, TwoOperands (bo, bi))
  | _ -> raise ParsingFailureException

let parse13 bin =
  match extract bin 10u 1u with
  | 0x0u -> parseMCRF bin
  | 0x10u -> parseBCLRx bin
  | 0x21u -> parseCRNOR bin
  | 0x32u -> parseRFI bin
  | 0x81u -> parseCRANDC bin
  | 0x96u -> parseISYNC bin
  | 0xC1u -> parseCRXOR bin
  | 0xE1u -> parseCRNAND bin
  | 0x101u -> parseCRAND bin
  | 0x121u -> parseCREQV bin
  | 0x1A1u -> parseCRORC bin
  | 0x1C1u -> parseCROR bin
  | 0x210u -> parseBCCTRx bin
  | _ -> raise ParsingFailureException

let parseRLWIMIx bin =
  let rs = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let sh = extract bin 15u 11u |> uint64 |> Immediate
  let mb = extract bin 10u 6u |> uint64 |> Immediate
  let me = extract bin 5u 1u |> uint64 |> Immediate
  match pickBit bin 0u with
  (* inslwi ra,rs,n,b = rlwimi ra,rs,32-b,b,b+n-1
     insrwi ra,rs,n,b (n>0) = rlwimi ra,rs,32-(b+n),b,(b+n)-1 *)
  | 0b0u -> struct (Op.RLWIMI, FiveOperands(ra, rs, sh, mb, me))
  | _ (* 1 *) -> struct (Op.RLWIMIdot, FiveOperands(ra, rs, sh, mb, me))

let parseRLWINMx bin =
  let rs = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  match pickBit bin 0u with
  | 0b0u ->
    match extract bin 15u 11u with
    | 0b0u when extract bin 5u 1u = 0x1Fu ->
      let n = extract bin 15u 11u |> uint64 |> Immediate
      match extract bin 10u 6u with
      (* slwi ra,rs,0 = rlwinm ra,rs,0,0,31 *)
      | 0x0u ->
        struct (Op.SLWI, ThreeOperands(ra, rs, n))
      (* clrlwi ra,rs,n = rlwinm ra,rs,0,n,31 *)
      | _ ->
        struct (Op.CLRLWI, ThreeOperands(ra, rs, n))
    | _ ->
      match extract bin 10u 6u with
      | 0x0u ->
        let n = extract bin 15u 11u
        (* rotlwi ra,rs,n = rotrwi ra,rs,n = rlwinm ra,rs,n,0,31 *)
        if extract bin 5u 1u = 0x1Fu then
          let n = extract bin 15u 11u |> uint64 |> Immediate
          struct (Op.ROTLWI, ThreeOperands(ra, rs, n))
        (* slwi ra,rs,n = rlwinm ra,rs,n,0,31-n *)
        elif extract bin 5u 1u = 0x1Fu - n then
          let n = extract bin 15u 11u |> uint64 |> Immediate
          struct (Op.SLWI, ThreeOperands(ra, rs, n))
        else
          let sh = extract bin 15u 11u |> uint64 |> Immediate
          let mb = extract bin 10u 6u |> uint64 |> Immediate
          let me = extract bin 5u 1u |> uint64 |> Immediate
          struct (Op.RLWINM, FiveOperands(ra, rs, sh, mb, me))
      | _ ->
        let n = extract bin 10u 6u
        if extract bin 15u 11u = 0x20u - n then
          match extract bin 5u 1u with
          (* srwi ra,rs,n = rlwinm ra,rs,32-n,n,31 *)
          | 0x1Fu ->
            let n = extract bin 10u 6u |> uint64 |> Immediate
            struct (Op.SRWI, ThreeOperands(ra, rs, n))
          | _ ->
            let sh = extract bin 15u 11u |> uint64 |> Immediate
            let mb = extract bin 10u 6u |> uint64 |> Immediate
            let me = extract bin 5u 1u |> uint64 |> Immediate
            struct (Op.RLWINM, FiveOperands(ra, rs, sh, mb, me))
        (* extlwi ra,rs,n,b = rlwinm ra,rs,b,0,n-1,
           extrwi ra,rs,n,b = rlwinm ra,rs,b+n,32-n,31
           clrrwi ra,rs,n = rlwinm ra,rs,0,0,31-n
           clrlslwi ra,rs,b,n = rlwinm ra,rs,n,b-n,31-n *)
        else
          let sh = extract bin 15u 11u |> uint64 |> Immediate
          let mb = extract bin 10u 6u |> uint64 |> Immediate
          let me = extract bin 5u 1u |> uint64 |> Immediate
          struct (Op.RLWINM, FiveOperands(ra, rs, sh, mb, me))
  | _ (* 1 *) ->
    let sh = extract bin 15u 11u |> uint64 |> Immediate
    let mb = extract bin 10u 6u |> uint64 |> Immediate
    let me = extract bin 5u 1u |> uint64 |> Immediate
    struct (Op.RLWINMdot, FiveOperands(ra, rs, sh, mb, me))

let parseRLWNMx bin =
  let rs = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  match pickBit bin 0u with
  | 0b0u ->
    match extract bin 10u 1u with
    (* rotlw ra,rs,rb = rlwnm ra,rs,rb,mb,me *)
    | 0x1Fu -> struct (Op.ROTLW, ThreeOperands(ra, rs, rb))
    | _ ->
      let mb = extract bin 10u 6u |> uint64 |> Immediate
      let me = extract bin 5u 1u |> uint64 |> Immediate
      struct (Op.RLWNM, FiveOperands(ra, rs, rb, mb, me))
  | _ (* 1 *) ->
    let mb = extract bin 10u 6u |> uint64 |> Immediate
    let me = extract bin 5u 1u |> uint64 |> Immediate
    struct (Op.RLWNMdot, FiveOperands(ra, rs, rb, mb, me))

let parseORI bin =
  match extract bin 25u 0u with
  (* nop = ori 0,0,0 *)
  | 0b0u -> struct (Op.NOP, NoOperand)
  | _ ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let uimm = extract bin 15u 0u |> uint64 |> Immediate
    struct (Op.ORI, ThreeOperands(rs, ra, uimm))

let parseORIS bin =
  let rs = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let uimm = extract bin 15u 0u |> uint64 |> Immediate
  struct (Op.ORIS, ThreeOperands(rs, ra, uimm))

let parseXORI bin =
  let rs = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let uimm = extract bin 15u 0u |> uint64 |> Immediate
  struct (Op.XORI, ThreeOperands(rs, ra, uimm))

let parseXORIS bin =
  let rs = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let uimm = extract bin 15u 0u |> uint64 |> Immediate
  struct (Op.XORIS, ThreeOperands(rs, ra, uimm))

let parseANDIdot bin =
  let rs = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let uimm = extract bin 15u 0u |> uint64 |> Immediate
  struct (Op.ANDIdot, ThreeOperands(rs, ra, uimm))

let parseANDISdot bin =
  let rs = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let uimm = extract bin 15u 0u |> uint64 |> Immediate
  struct (Op.ANDISdot, ThreeOperands(rs, ra, uimm))

let parseCMPandMCRXR bin =
  match pickBit bin 10u with
  | 0b0u when pickBit bin 22u = 0u ->
    let crfd = getCondRegister (extract bin 25u 23u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    match pickBit bin 21u with
    (* cmpw crfd,ra,rb = cmp crfd,0,ra,rb *)
    | 0b0u -> struct (Op.CMPW, ThreeOperands (crfd, ra, rb))
    | _ (* 1 *) -> struct (Op.CMP, FourOperands (crfd, Immediate 1UL, ra, rb))
  | 0b1u when extract bin 22u 11u = 0u ->
    let crfd = getCondRegister (extract bin 25u 23u) |> OpReg
    struct (Op.MCRXR, OneOperand (crfd))
  | _ -> raise ParsingFailureException

let parseTW bin =
  match pickBit bin 10u with
  | 0b0u ->
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    match extract bin 25u 21u with
    (* twlgt ra,rb = tw 1,ra,rb *)
    | 0x1u -> struct (Op.TWLGT, TwoOperands (ra, rb))
    (* twllt ra,rb = tw 2,ra,rb *)
    | 0x2u -> struct (Op.TWLLT, TwoOperands (ra, rb))
    (* tweq ra,rb = tw 4,ra,rb *)
    | 0x4u -> struct (Op.TWEQ, TwoOperands (ra, rb))
    (* twlnl ra,rb = tw 5,ra,rb *)
    | 0x5u -> struct (Op.TWLNL, TwoOperands (ra, rb))
    (* twgt ra,rb = tw 8,ra,rb *)
    | 0x8u -> struct (Op.TWGT, TwoOperands (ra, rb))
    (* twlt ra,rb = tw 16,ra,rb *)
    | 0x10u -> struct (Op.TWLT, TwoOperands (ra, rb))
    (* twne ra,rb = tw 24,ra,rb *)
    | 0x18u -> struct (Op.TWNE, TwoOperands (ra, rb))
    | 0x1Fu ->
      match extract bin 20u 11u with
      | 0x0u -> struct (Op.TRAP, NoOperand)
      (* twlle ra,rb = twlng ra, rb = tw 6,ra,rb
         twge ra,rb = twlge ra, rb = twnl ra, rb = tw 12,ra,rb
         twle ra,rb = twng ra, rb = tw 20,ra,rb *)
      | _ ->
        let tO = extract bin 25u 21u |> uint64 |> Immediate
        struct (Op.TW, ThreeOperands (tO, ra, rb))
    | _ ->
      let tO = extract bin 25u 21u |> uint64 |> Immediate
      struct (Op.TW, ThreeOperands (tO, ra, rb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseSUBFCx bin =
  let rd = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  (* subc rd,ra,rb = subfc rd,rb,ra *)
  | 0b00u -> struct (Op.SUBFC, ThreeOperands (rd, ra, rb))
  | 0b01u -> struct (Op.SUBFCdot, ThreeOperands (rd, ra, rb))
  | 0b10u -> struct (Op.SUBFCO, ThreeOperands (rd, ra, rb))
  | _ (* 11 *) -> struct (Op.SUBFCOdot, ThreeOperands (rd, ra, rb))

let parseADDCx bin =
  let rd = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  | 0b00u -> struct (Op.ADDC, ThreeOperands (rd, ra, rb))
  | 0b01u -> struct (Op.ADDCdot, ThreeOperands (rd, ra, rb))
  | 0b10u -> struct (Op.ADDCO, ThreeOperands (rd, ra, rb))
  | _ (* 11 *) ->  struct (Op.ADDCOdot, ThreeOperands (rd, ra, rb))

let parseMULHWUx bin =
  let rd = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  match pickBit bin 0u with
  | 0b0u ->  struct (Op.MULHWU, ThreeOperands (rd, ra, rb))
  | _ (* 1 *) -> struct (Op.MULHWUdot, ThreeOperands (rd, ra, rb))

let parseMFCR bin =
  match pickBit bin 10u with
  | 0b0u when extract bin 20u 11u = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    struct (Op.MFCR, OneOperand (rd))
  | _ (* 1 *) -> raise ParsingFailureException

let parseLWARX bin =
  match pickBit bin 10u with
  | 0b0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.LWARX, ThreeOperands (rd, ra, rb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseLSWX bin =
  match pickBit bin 10u with
  | 0b1u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.LSWX, ThreeOperands (rd, ra, rb))
  | _ (* 0 *) -> raise ParsingFailureException

let parseLWBRX bin =
  match pickBit bin 10u with
  | 0b1u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.LWBRX, ThreeOperands (rd, ra, rb))
  | _ (* 0 *) -> raise ParsingFailureException

let parseLWZXandLFSX bin =
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  match pickBit bin 10u with
  | 0b0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    struct (Op.LWZX, ThreeOperands (rd, ra, rb))
  | _ (* 1 *) ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    struct (Op.LFSX, ThreeOperands (frd, ra, rb))

let parseSLWxandSRWx bin =
  let rs = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 0:RC *) with
  | 0b00u -> struct (Op.SLW, ThreeOperands (ra, rs, rb))
  | 0b01u -> struct (Op.SLWdot, ThreeOperands (ra, rs, rb))
  | 0b10u -> struct (Op.SRW, ThreeOperands (ra, rs, rb))
  | _ (* 11 *) -> struct (Op.SRWdot, ThreeOperands (ra, rs, rb))

let parseCNTLZWx bin =
  let rs = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 0:RC *) with
  | 0b00u when extract bin 15u 11u = 0u ->
    struct (Op.CNTLZW, TwoOperands (ra, rs))
  | 0b01u when extract bin 15u 11u = 0u ->
    struct (Op.CNTLZWdot, TwoOperands (ra, rs))
  | _ (* 1x *) -> raise ParsingFailureException

let parseANDx bin =
  let rs = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 0:RC *) with
  | 0b00u -> struct (Op.AND, ThreeOperands (ra, rs, rb))
  | 0b01u -> struct (Op.ANDdot, ThreeOperands (ra, rs, rb))
  | _ (* 1x *) -> raise ParsingFailureException

let parseCMPL bin =
  match pickBit bin 10u with
  | 0b0u when pickBit bin 22u = 0u ->
    let crfd = getCondRegister (extract bin 25u 23u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    match pickBit bin 21u with
    (* cmplw crfd,ra,rb = cmpl crfd,0,ra,rb *)
    | 0b0u -> struct (Op.CMPLW, ThreeOperands (crfd, ra, rb))
    | _ (* 1 *)-> struct (Op.CMPL, FourOperands (crfd, Immediate 1UL, ra, rb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseSUBFx bin =
  let rd = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  (* sub rd,rb,ra = subf rd,ra,rb *)
  | 0b00u -> struct (Op.SUBF, ThreeOperands (rd, ra, rb))
  | 0b01u -> struct (Op.SUBFdot, ThreeOperands (rd, ra, rb))
  | 0b10u -> struct (Op.SUBFO, ThreeOperands (rd, ra, rb))
  | _ (* 11 *) ->  struct (Op.SUBFOdot, ThreeOperands (rd, ra, rb))

let parseDCBSTandTLBSYNC bin =
  match pickBit bin 10u with
  | 0b0u when extract bin 25u 21u = 0u ->
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.DCBST, TwoOperands (ra, rb))
  | 0b1u when extract bin 25u 11u = 0u ->
    struct (Op.TLBSYNC, NoOperand)
  | _ -> raise ParsingFailureException

let parseLWZUXandLFSUX bin =
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  match pickBit bin 10u with
  | 0b0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    struct (Op.LWZUX, ThreeOperands (rd, ra, rb))
  | _ (* 1 *) ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    struct (Op.LFSUX, ThreeOperands (frd, ra, rb))

let parseANDCx bin =
  let rs = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 0:RC *) with
  | 0b00u -> struct (Op.ANDC, ThreeOperands (ra, rs, rb))
  | 0b01u -> struct (Op.ANDCdot, ThreeOperands (ra, rs, rb))
  | _ (* 1x *) -> raise ParsingFailureException

let parseMULHWx bin =
  let rd = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  match pickBit bin 0u with
  | 0b0u -> struct (Op.MULHW, ThreeOperands (rd, ra, rb))
  | _ (* 1 *) -> struct (Op.MULHWdot, ThreeOperands (rd, ra, rb))

let parseMFMSRandMFSR bin =
  match pickBit bin 10u with
  | 0b0u when extract bin 20u 11u = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    struct (Op.MFMSR, OneOperand (rd))
  | 0b1u when (concat (pickBit bin 20u) (extract bin 15u 11u) 1) = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    (* FIXME : SegRegister *)
    let sr = getSegRegister (extract bin 19u 16u)
    struct (Op.MFSR, TwoOperands (sr, rd))
  | _ -> raise ParsingFailureException

let parseLSWI bin =
  match pickBit bin 10u with
  | 0b1u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let nb = extract bin 15u 11u |> uint64 |> Immediate
    struct (Op.LSWI, ThreeOperands(rd, ra, nb))
  | _ (* 0 *) -> raise ParsingFailureException

let parseDCBFandSYNC bin =
  match pickBit bin 10u with
  | 0b0u when extract bin 25u 21u = 0u ->
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.DCBF, TwoOperands (ra, rb))
  | 0b1u when extract bin 25u 11u = 0u ->
    struct (Op.SYNC, NoOperand)
  | _ -> raise ParsingFailureException

let parseLBZXandLFDX bin =
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  match pickBit bin 10u with
  | 0b0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    struct (Op.LBZX, ThreeOperands (rd, ra, rb))
  | _ (* 1 *) ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.LFDX, ThreeOperands (frd, ra, rb))

let parseNEGx bin =
  let rd = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  | 0b00u when extract bin 15u 11u = 0u ->
    struct (Op.NEG, TwoOperands (rd, ra))
  | 0b01u when extract bin 15u 11u = 0u ->
    struct (Op.NEGdot, TwoOperands (rd, ra))
  | 0b10u when extract bin 15u 11u = 0u ->
    struct (Op.NEGO, TwoOperands (rd, ra))
  | 0b11u when extract bin 15u 11u = 0u ->
    struct (Op.NEGOdot, TwoOperands (rd, ra))
  | _ -> raise ParsingFailureException

let parseLBZUXandLFDUX bin =
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  match pickBit bin 10u with
  | 0b0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    struct (Op.LBZUX, ThreeOperands (rd, ra, rb))
  | 0b1u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OpReg
    struct (Op.LFDUX, ThreeOperands (frd, ra, rb))
  | _ -> raise ParsingFailureException

let parseNORx bin =
  let rs = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 0:RC *) with
  (* not rd,rs = nor ra,rs,rs *)
  | 0b00u -> struct (Op.NOR, ThreeOperands (ra, rs, rb))
  | 0b01u -> struct (Op.NORdot, ThreeOperands (ra, rs, rb))
  | _ (* 1x *) -> raise ParsingFailureException

let parseSUBFEx bin =
  let rd = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  | 0b00u -> struct (Op.SUBFE, ThreeOperands (rd, ra, rb))
  | 0b01u -> struct (Op.SUBFEdot, ThreeOperands (rd, ra, rb))
  | 0b10u -> struct (Op.SUBFEO, ThreeOperands (rd, ra, rb))
  | _ (* 11 *) -> struct (Op.SUBFEOdot, ThreeOperands (rd, ra, rb))

let parseADDEx bin =
  let rd = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  | 0b00u -> struct (Op.ADDE, ThreeOperands (rd, ra, rb))
  | 0b01u -> struct (Op.ADDEdot, ThreeOperands (rd, ra, rb))
  | 0b10u -> struct (Op.ADDEO, ThreeOperands (rd, ra, rb))
  | _ (* 11 *) -> struct (Op.ADDEOdot, ThreeOperands (rd, ra, rb))

let parseMTCRF bin =
  match pickBit bin 10u with
  (* mtcr rs = mtcrf 0xff,rs *)
  | 0b0u when concat (pickBit bin 20u) (pickBit bin 11u) 1 = 00u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    (* FIXME : CRM *)
    let crm = getCRM (extract bin 19u 12u)
    struct (Op.MTCRF, TwoOperands (crm, rs))
  | _ (* 1 *) -> raise ParsingFailureException

let parseMTMSR bin =
  match pickBit bin 10u with
  | 0b0u when extract bin 20u 11u = 0u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    struct (Op.MFMSR, OneOperand (rs))
  | _ (* 1 *) -> raise ParsingFailureException

let parseMFSRIN bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 with
  | 0b10u when extract bin 20u 16u = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.MFSRIN, TwoOperands (rd, rb))
  | _ (* 11, 0x *) -> raise ParsingFailureException

let parseSTSWX bin =
  match pickBit bin 10u with
  | 0b1u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.STSWX, ThreeOperands (rs, ra, rb))
  | _ (* 0 *) -> raise ParsingFailureException

let parseSTWCXdotandSTWBRX bin =
  let rs = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 with
  | 0b01u -> struct (Op.STWCXdot, ThreeOperands (rs, ra, rb))
  | 0b10u -> struct (Op.STWBRX, ThreeOperands (rs, ra, rb))
  | _ (* 00, 11 *) -> raise ParsingFailureException

let parseSTWXandSTFSX bin =
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  match pickBit bin 10u with
  | 0b0u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    struct (Op.STWX, ThreeOperands (rs, ra, rb))
  | _ (* 1 *) ->
    let frs = getFPRegister (extract bin 25u 21u) |> OpReg
    struct (Op.STFSX, ThreeOperands (frs, ra, rb))

let parseSTWUXandSTFSUX bin =
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  match pickBit bin 10u with
  | 0b0u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    struct (Op.STWUX, ThreeOperands (rs, ra, rb))
  | _ (* 1 *) ->
    let frs = getFPRegister (extract bin 25u 21u) |> OpReg
    struct (Op.STFSUX, ThreeOperands (frs, ra, rb))

let parseSUBFZEx bin =
  let rd = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  | 0b00u when extract bin 15u 11u = 0u ->
    struct (Op.SUBFZE, TwoOperands (rd, ra))
  | 0b01u when extract bin 15u 11u = 0u ->
    struct (Op.SUBFZEdot, TwoOperands (rd, ra))
  | 0b10u when extract bin 15u 11u = 0u ->
    struct (Op.SUBFZEO, TwoOperands (rd, ra))
  | 0b11u when extract bin 15u 11u = 0u ->
    struct (Op.SUBFZEOdot, TwoOperands (rd, ra))
  | _ -> raise ParsingFailureException

let parseADDZEx bin =
  let rd = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  | 0b00u when extract bin 15u 11u = 0u ->
    struct (Op.ADDZE, TwoOperands (rd, ra))
  | 0b01u when extract bin 15u 11u = 0u ->
    struct (Op.ADDZEdot, TwoOperands (rd, ra))
  | 0b10u when extract bin 15u 11u = 0u ->
    struct (Op.ADDZEO, TwoOperands (rd, ra))
  | 0b11u when extract bin 15u 11u = 0u ->
    struct (Op.ADDZEOdot, TwoOperands (rd, ra))
  | _ -> raise ParsingFailureException

let parseMTSR bin =
  match pickBit bin 10u with
  | 0b0u when (concat (pickBit bin 20u) (extract bin 15u 11u) 1) = 0u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    (* FIXME : SegRegister *)
    let sr = getSegRegister (extract bin 19u 16u)
    struct (Op.MTSR, TwoOperands (sr, rs))
  | _ (* 1 *) -> raise ParsingFailureException

let parseSTSWI bin =
  match pickBit bin 10u with
  | 0b1u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let nb = extract bin 15u 11u |> uint64 |> Immediate
    struct (Op.STSWI, ThreeOperands (rs, ra, nb))
  | _ (* 0 *) -> raise ParsingFailureException

let parseSTBXandSTFDX bin =
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 with
  | 0b00u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    struct (Op.STBX, ThreeOperands (rs, ra, rb))
  | 0b10u ->
    let frs = getFPRegister (extract bin 25u 21u) |> OpReg
    struct (Op.STFDX, ThreeOperands (frs, ra, rb))
  | _ (* 01, 11 *) -> raise ParsingFailureException

let parseSUBFMEx bin =
  let rd = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  | 0b00u when extract bin 15u 11u = 0u ->
    struct (Op.SUBFME, TwoOperands (rd, ra))
  | 0b01u when extract bin 15u 11u = 0u ->
    struct (Op.SUBFMEdot, TwoOperands (rd, ra))
  | 0b10u when extract bin 15u 11u = 0u ->
    struct (Op.SUBFMEO, TwoOperands (rd, ra))
  | 0b11u when extract bin 15u 11u = 0u ->
    struct (Op.SUBFMEOdot, TwoOperands (rd, ra))
  | _ -> raise ParsingFailureException

let parseADDMEx bin =
  let rd = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  | 0b00u when extract bin 15u 11u = 0u ->
    struct (Op.ADDME, TwoOperands (rd, ra))
  | 0b01u when extract bin 15u 11u = 0u ->
    struct (Op.ADDMEdot, TwoOperands (rd, ra))
  | 0b10u when extract bin 15u 11u = 0u ->
    struct (Op.ADDMEO, TwoOperands (rd, ra))
  | 0b11u when extract bin 15u 11u = 0u  ->
    struct (Op.ADDMEOdot, TwoOperands (rd, ra))
  | _ -> raise ParsingFailureException

let parseMULLWx bin =
  let rd = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  | 0b00u -> struct (Op.MULLW, ThreeOperands (rd, ra, rb))
  | 0b01u -> struct (Op.MULLWdot, ThreeOperands (rd, ra, rb))
  | 0b10u -> struct (Op.MULLWO, ThreeOperands (rd, ra, rb))
  | _ (* 11 *) -> struct (Op.MULLWOdot, ThreeOperands (rd, ra, rb))

let parseMTSRIN bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 with
  | 0b10u when extract bin 20u 16u = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.MTSRIN, TwoOperands (rd, rb))
  | _ (* 11, 0x *) -> raise ParsingFailureException

let parseDCBTSTandDCBA bin =
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  match pickBit bin 10u with
  | 0b0u when extract bin 25u 21u = 0u ->
    (* CT = 0u *)
    struct (Op.DCBTST, TwoOperands (ra, rb))
  | 0b1u when extract bin 25u 21u = 0u ->
    struct (Op.DCBA, TwoOperands (ra, rb))
  | _ -> raise ParsingFailureException

let parseSTBUXandSTFDUX bin =
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 with
  | 0b00u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    struct (Op.STBUX, ThreeOperands (rs, ra, rb))
  | 0b10u ->
    let frs = getFPRegister (extract bin 25u 21u) |> OpReg
    struct (Op.STFDUX, ThreeOperands (frs, ra, rb))
  | _ (* 01, 11 *) -> raise ParsingFailureException

let parseADDx bin =
  let rd = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  | 0b00u -> struct (Op.ADD, ThreeOperands (rd, ra, rb))
  | 0b01u -> struct (Op.ADDdot, ThreeOperands (rd, ra, rb))
  | 0b10u -> struct (Op.ADDO, ThreeOperands (rd, ra, rb))
  | _ (* 11 *) -> struct (Op.ADDOdot, ThreeOperands (rd, ra, rb))

let parseDCBTandLHBRX bin =
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  match pickBit bin 10u with
  | 0b0u when extract bin 25u 21u = 0u ->
    (* CT = 0u *)
     struct (Op.DCBT, TwoOperands (ra, rb))
  | 0b1u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    struct (Op.LHBRX, ThreeOperands (rd, ra, rb))
  | _ -> raise ParsingFailureException

let parseLHZX bin =
  match pickBit bin 10u with
  | 0b0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.LHZX, ThreeOperands (rd, ra, rb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseSRAWx bin =
  let rs = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 1:RC *) with
  | 0b10u -> struct (Op.SRAW, ThreeOperands (ra, rs, rb))
  | 0b11u -> struct (Op.SRAWdot, ThreeOperands (ra, rs, rb))
  | _ (* 0x *) -> raise ParsingFailureException

let parseEQVx bin =
  let rd = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 0:Rc *) with
  | 0b00u -> struct (Op.EQV, ThreeOperands (rd, ra, rb))
  | 0b01u -> struct (Op.EQVdot, ThreeOperands (rd, ra, rb))
  | _ (* 1x *) -> raise ParsingFailureException

let parseTLBIE bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 with
  | 0b00u ->
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.TLBIE, OneOperand(rb))
  | _ (* 01, 1x *) -> raise ParsingFailureException

let parseECIWX bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 with
  | 0b00u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.ECIWX, ThreeOperands (rd, ra, rb))
  | _ (* 01, 1x *) -> raise ParsingFailureException

let parseLHZUX bin =
  match pickBit bin 10u with
  | 0b0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.LHZUX, ThreeOperands (rd, ra, rb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseSRAWIx bin =
  let rs = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let sh = extract bin 15u 11u |> uint64 |> Immediate
  match pickBit bin 0u with
  | 0b0u -> struct (Op.SRAWI, ThreeOperands (rs, ra, sh))
  | _ (* 1 *) -> struct (Op.SRAWIdot, ThreeOperands (rs, ra, sh))

let parseXORx bin =
  let rs = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 0:RC *) with
  | 0b00u -> struct (Op.XOR, ThreeOperands (ra, rs, rb))
  | 0b01u -> struct (Op.XORdot, ThreeOperands (ra, rs, rb))
  | _ (* 1x *) -> raise ParsingFailureException

let parseMFSPR bin =
  match pickBit bin 10u with
  | 0b0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    match concat (extract bin 15u 11u) (extract bin 20u 16u) 5 with
    (* mfxer rd = mfspr rd,1 *)
    | 0x1u -> struct (Op.MFXER, OneOperand rd)
    (* mflr rd = mfspr rd,8 *)
    | 0x8u -> struct (Op.MFLR, OneOperand rd)
    (* mfctr rd = mfspr rd,9 *)
    | 0x9u -> struct (Op.MFCTR, OneOperand rd)
    | _ ->
      (* FIXME : SPRegister *)
      let spr =
        getSPRegister (concat (extract bin 15u 11u) (extract bin 20u 16u) 5)
      struct (Op.MFSPR, TwoOperands (rd, spr))
  | _ (* 1 *) -> raise ParsingFailureException

let parseEIEIO bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 with
  | 0b10u when extract bin 25u 11u = 0u ->
    struct (Op.EIEIO, NoOperand)
  | _ (* 11, 0x *) -> raise ParsingFailureException

let parseLHAX bin =
  match pickBit bin 10u with
  | 0b0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.LHAX, ThreeOperands (rd, ra, rb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseTLBIA bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 with
  | 0b00u ->
    struct (Op.TLBIA, NoOperand)
  | _ (* 01, 1x *) -> raise ParsingFailureException

let parseMFTB bin =
  match pickBit bin 10u with
  | 0b0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    (* FIXME : TBRRegister *)
    let tbr =
      getTBRRegister (concat (extract bin 15u 11u) (extract bin 20u 16u) 5)
    match concat (extract bin 15u 11u) (extract bin 20u 16u) 5 with
    (* mftbu rd = mftb rd,269 *)
    | 0x10du -> struct (Op.MFTBU, OneOperand rd)
    (* mftb rd = mftb rd,268 *)
    | _ -> struct (Op.MFTB, TwoOperands (rd, tbr))
  | _ (* 1 *) -> raise ParsingFailureException

let parseLHAUX bin =
  match pickBit bin 10u with
  | 0b0u ->
    let rd = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.LHAUX, ThreeOperands (rd, ra, rb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseSTHBRX bin =
  match pickBit bin 10u with
  | 0b1u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.STHBRX, ThreeOperands (rs, ra, rb))
  | _ (* 0 *) -> raise ParsingFailureException

let parseSTHX bin =
  match pickBit bin 10u with
  | 0b0u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.STHX, ThreeOperands (rs, ra, rb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseEXTSHx bin =
  let rs = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 1:Rc *) with
  | 0b10u when extract bin 15u 11u = 0u ->
    struct (Op.EXTSH, TwoOperands (rs, ra))
  | 0b11u when extract bin 15u 11u = 0u ->
    struct (Op.EXTSHdot, TwoOperands (rs, ra))
  | _ (* 0x *) -> raise ParsingFailureException

let parseORCx bin =
  let rs = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 0:RC *) with
  | 0b00u -> struct (Op.ORC, ThreeOperands (ra, rs, rb))
  | 0b01u -> struct (Op.ORCdot, ThreeOperands (ra, rs, rb))
  | _ (* 1x *) -> raise ParsingFailureException

let parseECOWX bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 with
  | 0b00u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.ECOWX, ThreeOperands (rs, ra, rb))
  | _ (* 01, 1x *) -> raise ParsingFailureException

let parseSTHUX bin =
  match pickBit bin 10u with
  | 0b0u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.STHUX, ThreeOperands (rs, ra, rb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseEXTSBx bin =
  let rs = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 1:Rc *) with
  | 0b10u when extract bin 15u 11u = 0u ->
    struct (Op.EXTSB, TwoOperands (rs, ra))
  | 0b11u when extract bin 15u 11u = 0u ->
    struct (Op.EXTSBdot, TwoOperands (rs, ra))
  | _ (* 0x *) -> raise ParsingFailureException

let parseORx bin =
  let rs = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 0:RC *) with
  (* mr ra,rs = or ra,rs,rs *)
  | 0b00u ->
    if extract bin 25u 21u = extract bin 15u 11u then
      struct (Op.MR, TwoOperands (ra, rs))
    else
      let rb = getRegister (extract bin 15u 11u) |> OpReg
      struct (Op.OR, ThreeOperands (ra, rs, rb))
  | 0b01u ->
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.ORdot, ThreeOperands (ra, rs, rb))
  | _ (* 1x *) -> raise ParsingFailureException

let parseDIVWUx bin =
  let rd = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  | 0b00u -> struct (Op.DIVWU, ThreeOperands (rd, ra, rb))
  | 0b01u -> struct (Op.DIVWUdot, ThreeOperands (rd, ra, rb))
  | 0b10u -> struct (Op.DIVWUO, ThreeOperands (rd, ra, rb))
  | _ (* 11 *) -> struct (Op.DIVWUOdot, ThreeOperands (rd, ra, rb))

let parseMTSPR bin =
  match pickBit bin 10u with
  | 0b0u ->
    let rs = getRegister (extract bin 25u 21u) |> OpReg
    match concat (extract bin 15u 11u) (extract bin 20u 16u) 5 with
    (* mtxer rd = mtspr rd,1 *)
    | 0x1u -> struct (Op.MTXER, OneOperand rs)
    (* mtlr rd = mtspr rd,8 *)
    | 0x8u -> struct (Op.MTLR, OneOperand rs)
    (* mtctr rd = mtspr rd,9 *)
    | 0x9u -> struct (Op.MTCTR, OneOperand rs)
    | _ ->
      (* FIXME : SPRegister *)
      let spr =
        getSPRegister (concat (extract bin 15u 11u) (extract bin 20u 16u) 5)
      struct (Op.MTSPR, TwoOperands (rs, spr))
  | _ (* 1 *) -> raise ParsingFailureException

let parseDCBIandICBI bin =
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  match pickBit bin 10u with
  | 0b0u when extract bin 25u 21u = 0u ->
    struct (Op.DCBI, TwoOperands (ra, rb))
  | 0b1u when extract bin 25u 21u = 0u ->
    struct (Op.ICBI, TwoOperands (ra, rb))
  | _ -> raise ParsingFailureException

let parseSTFIWX bin =
  match pickBit bin 10u with
  | 0b1u ->
    let frs = getFPRegister (extract bin 25u 21u) |> OpReg
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.STFIWX, ThreeOperands (frs, ra, rb))
  | _ (* 0 *) -> raise ParsingFailureException

let parseNANDx bin =
  let rs = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 0:RC *) with
  | 0b00u -> struct (Op.NAND, ThreeOperands (ra, rs, rb))
  | 0b01u -> struct (Op.NANDdot, ThreeOperands (ra, rs, rb))
  | _ (* 1x *) -> raise ParsingFailureException

let parseDIVWx bin =
  let rd = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u) |> OpReg
  let rb = getRegister (extract bin 15u 11u) |> OpReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  | 0b00u -> struct (Op.DIVW, ThreeOperands (rd, ra, rb))
  | 0b01u -> struct (Op.DIVWdot, ThreeOperands (rd, ra, rb))
  | 0b10u -> struct (Op.DIVWO, ThreeOperands (rd, ra, rb))
  | _ (* 11 *) -> struct (Op.DIVWOdot, ThreeOperands (rd, ra, rb))

let parseDCBZ bin =
  match pickBit bin 10u with
  | 0b1u when extract bin 25u 21u = 0u ->
    let ra = getRegister (extract bin 20u 16u) |> OpReg
    let rb = getRegister (extract bin 15u 11u) |> OpReg
    struct (Op.DCBZ, TwoOperands (ra, rb))
  | _ (* 0 *) -> raise ParsingFailureException

let parse1F bin =
  match extract bin 9u 1u with
  | 0x0u when pickBit bin 0u = 0u -> parseCMPandMCRXR bin
  | 0x4u when pickBit bin 0u = 0u -> parseTW bin
  | 0x8u -> parseSUBFCx bin
  | 0xAu -> parseADDCx bin
  | 0xBu when pickBit bin 10u = 0u -> parseMULHWUx bin
  | 0x13u when pickBit bin 0u = 0u -> parseMFCR bin
  (* FIXME : LWARX RegA = 0 *)
  | 0x14u when pickBit bin 0u = 0u -> parseLWARX bin
  | 0x15u when pickBit bin 0u = 0u -> parseLSWX bin
  (* FIXME : LWBRX RegA = 0 *)
  | 0x16u when pickBit bin 0u = 0u -> parseLWBRX bin
  (* FIXME : LWZX / LFSX RegA = 0 *)
  | 0x17u when pickBit bin 0u = 0u -> parseLWZXandLFSX bin
  | 0x18u -> parseSLWxandSRWx bin
  | 0x1Au -> parseCNTLZWx bin
  | 0x1Cu -> parseANDx bin
  | 0x20u when pickBit bin 0u = 0u -> parseCMPL bin
  | 0x28u -> parseSUBFx bin
  (* FIXME : DCBST RegA = 0 *)
  | 0x36u when pickBit bin 0u = 0u -> parseDCBSTandTLBSYNC bin
  (* FIXME : LWZUX / LFSUX RegA = 0 *)
  | 0x37u when pickBit bin 0u = 0u -> parseLWZUXandLFSUX bin
  | 0x3Cu -> parseANDCx bin
  | 0x4Bu when pickBit bin 10u = 0u -> parseMULHWx bin
  (* FIXME : SegRegister *)
  | 0x53u when pickBit bin 0u = 0u -> parseMFMSRandMFSR bin
  | 0x55u when pickBit bin 0u = 0u -> parseLSWI bin
  (* FIXME : DCBF RegA = 0 / SYNC 0 *)
  | 0x56u when pickBit bin 0u = 0u -> parseDCBFandSYNC bin
  (* FIXME : LBZX / LFDX RegA = 0 *)
  | 0x57u when pickBit bin 0u = 0u -> parseLBZXandLFDX bin
  | 0x68u -> parseNEGx bin
  (* FIXME : LBZUX / LFDUX RegA = 0 *)
  | 0x77u when pickBit bin 0u = 0u -> parseLBZUXandLFDUX bin
  | 0x7Cu -> parseNORx bin
  | 0x88u -> parseSUBFEx bin
  | 0x8Au -> parseADDEx bin
  (* FIXME : CRM *)
  | 0x90u when pickBit bin 0u = 0u -> parseMTCRF bin
  | 0x92u when pickBit bin 0u = 0u -> parseMTMSR bin
  | 0x93u -> parseMFSRIN bin
  | 0x95u when pickBit bin 0u = 0u -> parseSTSWX bin
  (* FIXME : STWCXdot / STWBRX RegA = 0 *)
  | 0x96u -> parseSTWCXdotandSTWBRX bin
  (* FIXME : STWX / STFSX RegA = 0 *)
  | 0x97u when pickBit bin 0u = 0u -> parseSTWXandSTFSX bin
  (* FIXME : STWUX / STFSUX RegA = 0 *)
  | 0xB7u when pickBit bin 0u = 0u -> parseSTWUXandSTFSUX bin
  | 0xC8u -> parseSUBFZEx bin
  | 0xCAu -> parseADDZEx bin
  (* FIXME : SegRegister *)
  | 0xD2u when pickBit bin 0u = 0u -> parseMTSR bin
  (* FIXME : SpecialRegister *)
  | 0xD5u when pickBit bin 0u = 0u -> parseSTSWI bin
  (* FIXME : STBX / STFDX RegA = 0 *)
  | 0xD7u -> parseSTBXandSTFDX bin
  | 0xE8u -> parseSUBFMEx bin
  | 0xEAu -> parseADDMEx bin
  | 0xEBu -> parseMULLWx bin
  | 0xF2u -> parseMTSRIN bin
  (* FIXME : DCBTST / DCBA RegA = 0 *)
  | 0xF6u when pickBit bin 0u = 0u -> parseDCBTSTandDCBA bin
  (* FIXME : STBUX / STFDUX RegA = 0 *)
  | 0xF7u -> parseSTBUXandSTFDUX bin
  | 0x10Au -> parseADDx bin
  (* FIXME : DCBT / LHBRX RegA = 0 *)
  | 0x116u when pickBit bin 0u = 0u -> parseDCBTandLHBRX bin
  (* FIXME : LHZX RegA = 0 *)
  | 0x117u when pickBit bin 0u = 0u -> parseLHZX bin
  | 0x118u -> parseSRAWx bin
  | 0x11Cu -> parseEQVx bin
  | 0x132u -> parseTLBIE bin
  | 0x136u when pickBit bin 0u = 0u -> parseECIWX bin
  (* FIXME : LHZUX RegA = 0 *)
  | 0x137u when pickBit bin 0u = 0u -> parseLHZUX bin
  | 0x138u when pickBit bin 10u = 1u -> parseSRAWIx bin
  | 0x13Cu -> parseXORx bin
  (* FIXME : SpecialRegister *)
  | 0x153u when pickBit bin 0u = 0u -> parseMFSPR bin
  | 0x156u when pickBit bin 0u = 0u -> parseEIEIO bin
  (* FIXME : LHAX RegA = 0 *)
  | 0x157u when pickBit bin 0u = 0u -> parseLHAX bin
  | 0x172u -> parseTLBIA bin
  (* FIXME : TBRRegister *)
  | 0x173u when pickBit bin 0u = 0u -> parseMFTB bin
  (* FIXME : LHAUX RegA = 0 *)
  | 0x177u when pickBit bin 0u = 0u -> parseLHAUX bin
  (* FIXME : STHBRX RegA = 0 *)
  | 0x196u when pickBit bin 0u = 0u -> parseSTHBRX bin
  (* FIXME : STHX RegA = 0 *)
  | 0x197u when pickBit bin 0u = 0u -> parseSTHX bin
  | 0x19Au -> parseEXTSHx bin
  | 0x19Cu -> parseORCx bin
  | 0x1B6u when pickBit bin 0u = 0u -> parseECOWX bin
  (* FIXME : STHUX RegA = 0 *)
  | 0x1B7u when pickBit bin 0u = 0u -> parseSTHUX bin
  | 0x1BAu -> parseEXTSBx bin
  | 0x1BCu -> parseORx bin
  | 0x1CBu -> parseDIVWUx bin
  | 0x1D3u when pickBit bin 0u = 0u -> parseMTSPR bin
  (* FIXME : DCBI / ICBI RegA = 0 *)
  | 0x1D6u when pickBit bin 0u = 0u -> parseDCBIandICBI bin
  (* FIXME : STFIWX RegA = 0 *)
  | 0x1D7u when pickBit bin 0u = 0u -> parseSTFIWX bin
  | 0x1DCu -> parseNANDx bin
  | 0x1EBu -> parseDIVWx bin
  (* FIXME : DCBZ RegA = 0 *)
  | 0x1F6u when pickBit bin 0u = 0u -> parseDCBZ bin
  | _ -> raise ParsingFailureException

let parseLWZ bin =
  let rd = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let d(ra) = (d, ra) |> ImmOp
  struct (Op.LWZ, TwoOperands(rd, d(ra)))

let parseLWZU bin =
  let rd = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let d(ra) = (d, ra) |> ImmOp
  struct (Op.LWZU, TwoOperands(rd, d(ra)))

let parseLBZ bin =
  let rd = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let d(ra) = (d, ra) |> ImmOp
  struct (Op.LBZ, TwoOperands(rd, d(ra)))

let parseLBZU bin =
  let rd = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let d(ra) = (d, ra) |> ImmOp
  struct (Op.LBZU, TwoOperands(rd, d(ra)))

let parseSTW bin =
  let rs = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let d(ra) = (d, ra) |> ImmOp
  struct (Op.STW, TwoOperands(rs, d(ra)))

let parseSTWU bin =
  let rs = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let d(ra) = (d, ra) |> ImmOp
  struct (Op.STWU, TwoOperands(rs, d(ra)))

let parseSTB bin =
  let rs = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let d(ra) = (d, ra) |> ImmOp
  struct (Op.STB, TwoOperands(rs, d(ra)))

let parseSTBU bin =
  let rs = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let d(ra) = (d, ra) |> ImmOp
  struct (Op.STBU, TwoOperands(rs, d(ra)))

let parseLHZ bin =
  let rd = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let d(ra) = (d, ra) |> ImmOp
  struct (Op.LHZ, TwoOperands(rd, d(ra)))

let parseLHZU bin =
  let rd = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let d(ra) = (d, ra) |> ImmOp
  struct (Op.LHZU, TwoOperands(rd, d(ra)))

let parseLHA bin =
  let rd = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let d(ra) = (d, ra) |> ImmOp
  struct (Op.LHA, TwoOperands(rd, d(ra)))

let parseLHAU bin =
  let rd = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let d(ra) = (d, ra) |> ImmOp
  struct (Op.LHAU, TwoOperands(rd, d(ra)))

let parseSTH bin =
  let rs = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let d(ra) = (d, ra) |> ImmOp
  struct (Op.STH, TwoOperands(rs, d(ra)))

let parseSTHU bin =
  let rs = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let d(ra) = (d, ra) |> ImmOp
  struct (Op.STHU, TwoOperands(rs, d(ra)))

let parseLMW bin =
  let rd = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let d(ra) = (d, ra) |> ImmOp
  struct (Op.LMW, TwoOperands(rd, d(ra)))

let parseSTMW bin =
  let rs = getRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let d(ra) = (d, ra) |> ImmOp
  struct (Op.STMW, TwoOperands(rs, d(ra)))

let parseLFS bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let d(ra) = (d, ra) |> ImmOp
  struct (Op.LFS, TwoOperands(frd, d(ra)))

let parseLFSU bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let d(ra) = (d, ra) |> ImmOp
  struct (Op.LFSU, TwoOperands(frd, d(ra)))

let parseLFD bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let d(ra) = (d, ra) |> ImmOp
  struct (Op.LFD, TwoOperands(frd, d(ra)))

let parseLFDU bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let d(ra) = (d, ra) |> ImmOp
  struct (Op.LFDU, TwoOperands(frd, d(ra)))

let parseSTFS bin =
  let frs = getFPRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let d(ra) = (d,ra) |> ImmOp
  struct (Op.STFS, TwoOperands(frs, d(ra)))

let parseSTFSU bin =
  let frs = getFPRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let d(ra) = (d,ra) |> ImmOp
  struct (Op.STFSU, TwoOperands(frs, d(ra)))

let parseSTFD bin =
  let frs = getFPRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let d(ra) = (d,ra) |> ImmOp
  struct (Op.STFD, TwoOperands(frs, d(ra)))

let parseSTFDU bin =
  let frs = getFPRegister (extract bin 25u 21u) |> OpReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let d(ra) = (d,ra) |> ImmOp
  struct (Op.STFDU, TwoOperands(frs, d(ra)))

let parseFDIVSx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let fra = getFPRegister (extract bin 20u 16u) |> OpReg
  let frb = getFPRegister (extract bin 15u 11u) |> OpReg
  match pickBit bin 0u with
  | 0b0u -> struct (Op.FDIVS, ThreeOperands (frd, fra, frb))
  | _ (* 1 *) -> struct (Op.FDIVSdot, ThreeOperands (frd, fra, frb))

let parseFSUBSx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let fra = getFPRegister (extract bin 20u 16u) |> OpReg
  let frb = getFPRegister (extract bin 15u 11u) |> OpReg
  match pickBit bin 0u with
  | 0b0u -> struct (Op.FSUBS, ThreeOperands (frd, fra, frb))
  | _ (* 1 *) -> struct (Op.FSUBSdot, ThreeOperands (frd, fra, frb))

let parseFADDSx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let fra = getFPRegister (extract bin 20u 16u) |> OpReg
  let frb = getFPRegister (extract bin 15u 11u) |> OpReg
  match pickBit bin 0u with
  | 0b0u -> struct (Op.FADDS, ThreeOperands (frd, fra, frb))
  | _ (* 1 *) -> struct (Op.FADDSdot, ThreeOperands (frd, fra, frb))

let parseFSQRTSx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let frb = getFPRegister (extract bin 15u 11u) |> OpReg
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 16u = 0u ->
    struct (Op.FSQRTS, TwoOperands (frd, frb))
  | 0b1u when extract bin 20u 16u = 0u ->
    struct (Op.FSQRTSdot, TwoOperands (frd, frb))
  | _ -> raise ParsingFailureException

let parseFRESx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let frb = getFPRegister (extract bin 15u 11u) |> OpReg
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 16u = 0u ->
    struct (Op.FRES, TwoOperands (frd, frb))
  | 0b1u when extract bin 20u 16u = 0u ->
    struct (Op.FRESdot, TwoOperands (frd, frb))
  | _ -> raise ParsingFailureException

let parseFMULSx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let fra = getFPRegister (extract bin 20u 16u) |> OpReg
  let frc = getFPRegister (extract bin 10u 6u) |> OpReg
  match pickBit bin 0u with
  | 0b0u when extract bin 15u 11u = 0u ->
    struct (Op.FMULS, ThreeOperands (frd, fra, frc))
  | 0b1u when extract bin 15u 11u = 0u ->
    struct (Op.FMULSdot, ThreeOperands (frd, fra, frc))
  | _ -> raise ParsingFailureException

let parseFMSUBSx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let fra = getFPRegister (extract bin 20u 16u) |> OpReg
  let frb = getFPRegister (extract bin 15u 11u) |> OpReg
  let frc = getFPRegister (extract bin 10u 6u) |> OpReg
  match pickBit bin 0u with
  | 0b0u -> struct (Op.FMSUBS, FourOperands (frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FMSUBSdot, FourOperands (frd, fra, frc, frb))

let parseFMADDSx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let fra = getFPRegister (extract bin 20u 16u) |> OpReg
  let frb = getFPRegister (extract bin 15u 11u) |> OpReg
  let frc = getFPRegister (extract bin 10u 6u) |> OpReg
  match pickBit bin 0u with
  | 0b0u -> struct (Op.FMADDS, FourOperands (frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FMADDSdot, FourOperands (frd, fra, frc, frb))

let parseFNMSUBSx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let fra = getFPRegister (extract bin 20u 16u) |> OpReg
  let frb = getFPRegister (extract bin 15u 11u) |> OpReg
  let frc = getFPRegister (extract bin 10u 6u) |> OpReg
  match pickBit bin 0u with
  | 0b0u -> struct (Op.FNMSUBS, FourOperands (frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FNMSUBSdot, FourOperands (frd, fra, frc, frb))

let parseFNMADDSx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let fra = getFPRegister (extract bin 20u 16u) |> OpReg
  let frb = getFPRegister (extract bin 15u 11u) |> OpReg
  let frc = getFPRegister (extract bin 10u 6u) |> OpReg
  match pickBit bin 0u with
  | 0b0u -> struct (Op.FNMADDS, FourOperands (frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FNMADDSdot, FourOperands (frd, fra, frc, frb))

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
  | _ -> raise ParsingFailureException

let parseFCMPU bin =
  match pickBit bin 0u with
  | 0b0u when extract bin 22u 21u = 0u ->
    let crfd = getCondRegister (extract bin 25u 23u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FCMPU, ThreeOperands (crfd, fra, frb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseFRSPx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let frb = getFPRegister (extract bin 15u 11u) |> OpReg
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 16u = 0u ->
    struct (Op.FRSP, TwoOperands (frd, frb))
  | 0b1u when extract bin 20u 16u = 0u ->
    struct (Op.FRSPdot, TwoOperands (frd, frb))
  | _ -> raise ParsingFailureException

let parseFCTIWx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let frb = getFPRegister (extract bin 15u 11u) |> OpReg
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 16u = 0u ->
    struct (Op.FCTIW, TwoOperands (frd, frb))
  | 0b1u when extract bin 20u 16u = 0u ->
    struct (Op.FCTIWdot, TwoOperands (frd, frb))
  | _ -> raise ParsingFailureException

let parseFCTIWZx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let frb = getFPRegister (extract bin 15u 11u) |> OpReg
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 16u = 0u ->
    struct (Op.FCTIWZ, TwoOperands (frd, frb))
  | 0b1u when extract bin 20u 16u = 0u ->
    struct (Op.FCTIWZdot, TwoOperands (frd, frb))
  | _ -> raise ParsingFailureException

let parseFDIVx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let fra = getFPRegister (extract bin 20u 16u) |> OpReg
  let frb = getFPRegister (extract bin 15u 11u) |> OpReg
  match pickBit bin 0u with
  | 0b0u -> struct (Op.FDIV, ThreeOperands (frd, fra, frb))
  | _ (* 1 *) -> struct (Op.FDIVdot, ThreeOperands (frd, fra, frb))

let parseFSUBx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let fra = getFPRegister (extract bin 20u 16u) |> OpReg
  let frb = getFPRegister (extract bin 15u 11u) |> OpReg
  match pickBit bin 0u with
  | 0b0u -> struct (Op.FSUB, ThreeOperands (frd, fra, frb))
  | _ (* 1 *) -> struct (Op.FSUBdot, ThreeOperands (frd, fra, frb))

let parseFADDx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let fra = getFPRegister (extract bin 20u 16u) |> OpReg
  let frb = getFPRegister (extract bin 15u 11u) |> OpReg
  match pickBit bin 0u with
  | 0b0u -> struct (Op.FADD, ThreeOperands (frd, fra, frb))
  | _ (* 1 *) -> struct (Op.FADDdot, ThreeOperands (frd, fra, frb))

let parseFSQRTx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let frb = getFPRegister (extract bin 15u 11u) |> OpReg
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 16u = 0u ->
    struct (Op.FSQRT, TwoOperands (frd, frb))
  | 0b1u when extract bin 20u 16u = 0u ->
    struct (Op.FSQRTdot, TwoOperands (frd, frb))
  | _ -> raise ParsingFailureException

let parseFSELx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let fra = getFPRegister (extract bin 20u 16u) |> OpReg
  let frb = getFPRegister (extract bin 15u 11u) |> OpReg
  let frc = getFPRegister (extract bin 10u 6u) |> OpReg
  match pickBit bin 0u with
  | 0b0u -> struct (Op.FSEL, FourOperands (frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FSELdot, FourOperands (frd, fra, frc, frb))

let parseFMULx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let fra = getFPRegister (extract bin 20u 16u) |> OpReg
  let frc = getFPRegister (extract bin 10u 6u) |> OpReg
  match pickBit bin 0u with
  | 0b0u when extract bin 15u 11u = 0u ->
    struct (Op.FMUL, ThreeOperands (frd, fra, frc))
  | 0b1u when extract bin 15u 11u = 0u ->
    struct (Op.FMULdot, ThreeOperands (frd, fra, frc))
  | _ -> raise ParsingFailureException

let parseFRSQRTEx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let frb = getFPRegister (extract bin 15u 11u) |> OpReg
  match pickBit bin 0u with
  | 0b0u when concat (extract bin 20u 16u) (extract bin 10u 6u) 5 = 0u ->
    struct (Op.FRSQRTE, TwoOperands (frd, frb))
  | 0b1u when extract bin 15u 11u = 0u ->
    struct (Op.FRSQRTEdot, TwoOperands (frd, frb))
  | _ -> raise ParsingFailureException

let parseFMSUBx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let fra = getFPRegister (extract bin 20u 16u) |> OpReg
  let frb = getFPRegister (extract bin 15u 11u) |> OpReg
  let frc = getFPRegister (extract bin 10u 6u) |> OpReg
  match pickBit bin 0u with
  | 0b0u -> struct (Op.FMSUB, FourOperands (frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FMSUBdot, FourOperands (frd, fra, frc, frb))

let parseFMADDx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let fra = getFPRegister (extract bin 20u 16u) |> OpReg
  let frb = getFPRegister (extract bin 15u 11u) |> OpReg
  let frc = getFPRegister (extract bin 10u 6u) |> OpReg
  match pickBit bin 0u with
  | 0b0u -> struct (Op.FMADD, FourOperands (frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FMADDdot, FourOperands (frd, fra, frc, frb))

let parseFNMSUBx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let fra = getFPRegister (extract bin 20u 16u) |> OpReg
  let frb = getFPRegister (extract bin 15u 11u) |> OpReg
  let frc = getFPRegister (extract bin 10u 6u) |> OpReg
  match pickBit bin 0u with
  | 0b0u -> struct (Op.FNMSUB, FourOperands (frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FNMSUBdot, FourOperands (frd, fra, frc, frb))

let parseFNMADDx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let fra = getFPRegister (extract bin 20u 16u) |> OpReg
  let frb = getFPRegister (extract bin 15u 11u) |> OpReg
  let frc = getFPRegister (extract bin 10u 6u) |> OpReg
  match pickBit bin 0u with
  | 0b0u -> struct (Op.FNMADD, FourOperands (frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FNMADDdot, FourOperands (frd, fra, frc, frb))

let parseFCMPO bin =
  match pickBit bin 0u with
  | 0b0u when extract bin 22u 21u = 0u ->
    let crfd = getCondRegister (extract bin 25u 23u) |> OpReg
    let fra = getFPRegister (extract bin 20u 16u) |> OpReg
    let frb = getFPRegister (extract bin 15u 11u) |> OpReg
    struct (Op.FCMPO, ThreeOperands (crfd, fra, frb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseMTFSB1x bin =
  let crbd = getFPSCRegister (extract bin 25u 21u)
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 11u = 0u ->
    (* FIXME : FPSCRegister *)
    struct (Op.MTFSB1, OneOperand crbd)
  | 0b1u when extract bin 20u 11u = 0u ->
    (* FIXME : FPSCRegister *)
    struct (Op.MTFSB1dot, OneOperand crbd)
  | _ -> raise ParsingFailureException

let parseFNEGx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let frb = getFPRegister (extract bin 15u 11u) |> OpReg
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 11u = 0u ->
    struct (Op.FNEG, TwoOperands (frd, frb))
  | 0b1u when extract bin 20u 11u = 0u ->
    struct (Op.FNEGdot, TwoOperands (frd, frb))
  | _ -> raise ParsingFailureException

let parseMCRFS bin =
  match pickBit bin 0u with
  | 0b0u when concat (extract bin 22u 21u) (extract bin 17u 11u) 2 = 0u ->
    let crfd = getCondRegister (extract bin 25u 23u) |> OpReg
    let crfs = getCondRegister (extract bin 20u 18u) |> OpReg
    struct (Op.MCRFS, TwoOperands (crfd, crfs))
  | _ (* 1 *) -> raise ParsingFailureException

let parseMTFSB0x bin =
  let crbd = getFPSCRegister (extract bin 25u 21u)
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 11u = 0u ->
    (* FIXME : FPSCRegister *)
    struct (Op.MTFSB0, OneOperand crbd)
  | 0b1u when extract bin 20u 11u = 0u ->
    (* FIXME : FPSCRegister *)
    struct (Op.MTFSB0dot, OneOperand crbd)
  | _ -> raise ParsingFailureException

let parseFMRx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let frb = getFPRegister (extract bin 15u 11u) |> OpReg
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 16u = 0u ->
    struct (Op.FMR, TwoOperands (frd, frb))
  | 0b1u when extract bin 20u 16u = 0u ->
    struct (Op.FMRdot, TwoOperands (frd, frb))
  | _ -> raise ParsingFailureException

let parseMTFSFIx bin =
  let crfd = getCondRegister (extract bin 25u 23u) |> OpReg
  let imm = extract bin 15u 12u |> uint64 |> Immediate
  match pickBit bin 0u with
  | 0b0u when concat (extract bin 22u 16u) (pickBit bin 11u) 7 = 0u ->
    struct (Op.MTFSFI, TwoOperands (crfd, imm))
  | 0b1u when concat (extract bin 22u 16u) (pickBit bin 11u) 7 = 0u ->
    struct (Op.MTFSFIdot, TwoOperands (crfd, imm))
  | _ -> raise ParsingFailureException

let parseFNABSx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let frb = getFPRegister (extract bin 15u 11u) |> OpReg
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 16u = 0u ->
    struct (Op.FNABS, TwoOperands (frd, frb))
  | 0b1u when extract bin 20u 16u = 0u ->
    struct (Op.FNABSdot, TwoOperands (frd, frb))
  | _ -> raise ParsingFailureException

let parseFABSx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  let frb = getFPRegister (extract bin 15u 11u) |> OpReg
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 16u = 0u ->
    struct (Op.FABS, TwoOperands (frd, frb))
  | 0b1u when extract bin 20u 16u = 0u ->
    struct (Op.FABSdot, TwoOperands (frd, frb))
  | _ -> raise ParsingFailureException

let parseMFFSx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OpReg
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 11u = 0u ->
    struct (Op.MFFS, OneOperand frd)
  | 0b1u when extract bin 20u 11u = 0u ->
    struct (Op.MFFSdot, OneOperand frd)
  | _ -> raise ParsingFailureException

let parseMTFSFx bin =
  let fm = getFM (extract bin 24u 17u)
  let frb = getFPRegister (extract bin 15u 11u) |> OpReg
  match pickBit bin 0u with
  | 0b0u when concat (pickBit bin 25u) (pickBit bin 16u) 1 = 0u ->
    struct (Op.MTFSF, TwoOperands (fm, frb))
  | 0b1u when concat (pickBit bin 25u) (pickBit bin 16u) 1 = 0u ->
    struct (Op.MTFSFdot, TwoOperands (fm, frb))
  | _ -> raise ParsingFailureException

let parse3F bin =
  match extract bin 5u 1u with
  | 0x0u ->
    match extract bin 10u 6u with
    | 0x0u -> parseFCMPU bin
    | 0x1u -> parseFCMPO bin
    | 0x2u -> parseMCRFS bin
    | _ -> raise ParsingFailureException
  | 0x6u ->
    (* FIXME : FPSCRegister *)
    match extract bin 10u 6u with
    | 0x1u -> parseMTFSB1x bin
    (* FIXME : FPSCRegister *)
    | 0x2u -> parseMTFSB0x bin
    | 0x4u -> parseMTFSFIx bin
    | _ -> raise ParsingFailureException
  | 0x7u ->
    match extract bin 10u 6u with
    | 0x12u -> parseMFFSx bin
    | 0x16u -> parseMTFSFx bin
    | _ -> raise ParsingFailureException
  | 0x8u ->
    match extract bin 10u 6u with
    | 0x1u -> parseFNEGx bin
    | 0x2u -> parseFMRx bin
    | 0x4u -> parseFNABSx bin
    | 0x8u -> parseFABSx bin
    | _ -> raise ParsingFailureException
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
  | _ -> raise ParsingFailureException

let private parseInstruction bin =
  match extract bin 31u 26u with
  | 0x3u -> parseTWI bin
  | 0x7u -> parseMULLI bin
  | 0x8u -> parseSUBFIC bin
  | 0xAu -> parseCMPLI bin
  | 0xBu -> parseCMPI bin
  | 0xCu -> parseADDIC bin
  | 0xDu -> parseADDICdot bin
  | 0xEu -> parseADDI bin
  | 0xFu -> parseADDIS bin
  | 0x10u -> parseBCx bin
  | 0x11u when pickBit bin 0u = 0u -> parseSC bin
  | 0x12u -> parseBx bin
  | 0x13u -> parse13 bin
  | 0x14u -> parseRLWIMIx bin
  | 0x15u -> parseRLWINMx bin
  | 0x17u -> parseRLWNMx bin
  | 0x18u -> parseORI bin
  | 0x19u -> parseORIS bin
  | 0x1Au -> parseXORI bin
  | 0x1Bu -> parseXORIS bin
  | 0x1Cu -> parseANDIdot bin
  | 0x1Du -> parseANDISdot bin
  | 0x1Fu -> parse1F bin
  | 0x20u -> parseLWZ bin
  | 0x21u -> parseLWZU bin
  | 0x22u -> parseLBZ bin
  | 0x23u -> parseLBZU bin
  | 0x24u -> parseSTW bin
  | 0x25u -> parseSTWU bin
  | 0x26u -> parseSTB bin
  | 0x27u -> parseSTBU bin
  | 0x28u -> parseLHZ bin
  | 0x29u -> parseLHZU bin
  | 0x2Au -> parseLHA bin
  | 0x2Bu -> parseLHAU bin
  | 0x2Cu -> parseSTH bin
  | 0x2Du -> parseSTHU bin
  | 0x2Eu -> parseLMW bin
  | 0x2Fu -> parseSTMW bin
  | 0x30u -> parseLFS bin
  | 0x31u -> parseLFSU bin
  | 0x32u -> parseLFD bin
  | 0x33u -> parseLFDU bin
  | 0x34u -> parseSTFS bin
  | 0x35u -> parseSTFSU bin
  | 0x36u -> parseSTFD bin
  | 0x37u -> parseSTFDU bin
  | 0x3Bu -> parse3B bin
  | 0x3Fu -> parse3F bin
  | _ -> raise ParsingFailureException

let parse (span: ByteSpan) (reader: IBinReader) addr =
  let bin = reader.ReadUInt32 (span, 0)
  let struct (opcode, operands) = parseInstruction bin
  let insInfo =
    { Address = addr
      NumBytes = 4u
      Opcode = opcode
      Operands = operands
      OperationSize = 32<rt>
      EffectiveAddress = 0UL }
  PPC32Instruction (addr, 4u, insInfo)

// vim: set tw=80 sts=2 sw=2:
