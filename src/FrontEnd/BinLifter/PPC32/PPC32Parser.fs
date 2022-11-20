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
open B2R2.FrontEnd.BinLifter.PPC32.OperandHelper

let parseTWI bin =
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let simm = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 simm |> uint64 |> OprImm
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
  (* twnei ra,value = twi 24,ra,value *)
  | 0x18u -> struct (Op.TWNEI, TwoOperands (ra, value))
  (* twllei ra,value = twlngi ra, value = twi 6,ra,value
     twgei ra,value = twlgei ra, value = twnli ra, value = twi 12,ra,value
     twlei ra,value = twngi ra, value = twi 20,ra,value *)
  | _ ->
    let tO = extract bin 25u 21u |> uint64 |> OprImm
    struct (Op.TWI, ThreeOperands (tO, ra, value))

let parseMULLI bin =
  let rd = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let simm = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 simm |> uint64 |> OprImm
  struct (Op.MULLI, ThreeOperands (rd, ra, value))

let parseSUBFIC bin =
  let rd = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let simm = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 simm |> uint64 |> OprImm
  struct (Op.SUBFIC, ThreeOperands (rd, ra, value))

let parseCMPLI bin =
  match pickBit bin 22u with
  | 0b0u ->
    let crfd = getCondRegister (extract bin 25u 23u) |> OprReg
    let ra = getRegister (extract bin 20u 16u) |> OprReg
    let uimm = extract bin 15u 0u |> uint64
    let value = signExtend 16 32 uimm |> uint64 |> OprImm
    match pickBit bin 21u with
    (* cmplwi crfd,ra,uimm = cmpli crfd,0,ra,uimm *)
    | 0b0u -> struct (Op.CMPLWI, ThreeOperands (crfd, ra, value))
    | _ -> struct (Op.CMPLI, FourOperands (crfd, OprImm 1UL, ra, value))
  | _ (* 1 *) -> raise ParsingFailureException

let parseCMPI bin =
  match pickBit bin 22u with
  | 0b0u ->
    let crfd = getCondRegister (extract bin 25u 23u) |> OprReg
    let ra = getRegister (extract bin 20u 16u) |> OprReg
    let simm = extract bin 15u 0u |> uint64
    let value = signExtend 16 32 simm |> uint64 |> OprImm
    match pickBit bin 21u with
    (* cmpwl crfd,ra,uimm = cmpl crfd,0,ra,uimm *)
    | 0b0u -> struct (Op.CMPWI, ThreeOperands (crfd, ra, value))
    | _ -> struct (Op.CMPI, FourOperands (crfd, OprImm 1UL, ra, value))
  | _ (* 1 *) -> raise ParsingFailureException

let parseADDIC bin =
  let rd = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let simm = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 simm |> uint64 |> OprImm
  (* subic rd,ra,value = addic rd,ra,-value *)
  struct (Op.ADDIC, ThreeOperands (rd, ra, value))

let parseADDICdot bin =
  let rd = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let simm = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 simm |> uint64 |> OprImm
  (* subic. rd,ra,value = addic. rd,ra,-value *)
  struct (Op.ADDICdot, ThreeOperands (rd, ra, value))

let parseADDI bin =
  let rd = getRegister (extract bin 25u 21u) |> OprReg
  let simm = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 simm |> uint64 |> OprImm
  match extract bin 20u 16u with
  | 0b0u -> struct (Op.LI, TwoOperands (rd, value))
  (* subi rd,ra,value = addi rd,ra,-value *)
  | _ ->
    let ra = getRegister (extract bin 20u 16u) |> OprReg
    struct (Op.ADDI, ThreeOperands (rd, ra, value))

let parseADDIS bin =
  let rd = getRegister (extract bin 25u 21u) |> OprReg
  let simm = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 simm |> uint64 |> OprImm
  match extract bin 20u 16u with
  | 0b0u -> struct (Op.LIS, TwoOperands (rd, value))
  (* subis rd,ra,value = addis rd,ra,-value *)
  | _ ->
    let ra = getRegister (extract bin 20u 16u) |> OprReg
    struct (Op.ADDIS, ThreeOperands (rd, ra, value))

let parseBCx bin =
  let idx = (extract bin 1u 0u |> int) (* opcode *)
  let bd = extract bin 15u 2u <<< 2 |> uint64
  let value = signExtend 16 32 bd |> uint64 |> OprAddr (* TargetAddress *)
  let op = [| Op.BC; Op.BCL; Op.BCA; Op.BCLA |].[idx]
  let bo = extract bin 25u 21u |> uint64 |> OprImm
  struct (op, ThreeOperands (bo, OprBI (extract bin 20u 16u), value))

let parseSC bin =
  match pickBit bin 1u with
  | 0b1u -> struct (Op.SC, NoOperand)
  | _ -> raise ParsingFailureException

let parseBx bin addr =
  let li = extract bin 25u 2u |> uint64
  let signExtended = signExtend 25 32 (li <<< 2)
  match extract bin 1u 0u (* AA:LK *) with
  | 0b00u ->
    let value = uint32 addr + uint32 signExtended |> uint64 |> OprImm
    struct (Op.B, OneOperand value)
  | 0b01u ->
    let value = uint32 addr + uint32 signExtended |> uint64 |> OprImm
    struct (Op.BL, OneOperand value)
  | 0b10u ->
    let value = signExtended |> OprImm
    struct (Op.BA, OneOperand value)
  | _ (* 11 *) ->
    let value = signExtended |> OprImm
    struct (Op.BLA, OneOperand value)

let parseMCRF bin =
  match pickBit bin 0u with
  | 0b0u when concat (extract bin 22u 21u) (extract bin 17u 11u) 2 = 0u ->
    let crfd = getCondRegister (extract bin 25u 23u) |> OprReg
    let crfs = getCondRegister (extract bin 20u 18u) |> OprReg
    struct (Op.MCRF, TwoOperands (crfd, crfs))
  | _ (* 1 *) -> raise ParsingFailureException

let parseBCLRx bin =
  if extract bin 15u 11u <> 0u then raise ParsingFailureException
  else
    let idx = pickBit bin 0u |> int (* opcode *)
    let op = [| Op.BCLR; Op.BCLRL |].[idx]
    let bo = extract bin 25u 21u |> uint64 |> OprImm
    struct (op, TwoOperands (bo, OprBI (extract bin 20u 16u)))

let parseCRNOR bin =
  match pickBit bin 0u with
  | 0b0u ->
    let crbd = getCRBit (extract bin 25u 21u)
    let crba = getCRBit (extract bin 20u 16u)
    (* crnot crbd,crba = crnor crbd,crba,crba *)
    if extract bin 20u 16u = extract bin 15u 11u then
      struct (Op.CRNOT, TwoOperands (crbd, crba))
    else
      let crbb = getCRBit (extract bin 15u 11u)
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
    let crbd = getCRBit (extract bin 25u 21u)
    let crba = getCRBit (extract bin 20u 16u)
    let crbb = getCRBit (extract bin 15u 11u)
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
    let crbd = getCRBit (extract bin 25u 21u)
    (* crclr crbd = crxor crbd,crbd,crbd *)
    if extract bin 25u 21u = extract bin 20u 16u then
      if extract bin 20u 16u = extract bin 15u 11u then
        struct (Op.CRCLR, OneOperand crbd)
      else
        let crba = getCRBit (extract bin 20u 16u)
        let crbb = getCRBit (extract bin 15u 11u)
        struct (Op.CRXOR, ThreeOperands (crbd, crba, crbb))
    else
      let crba = getCRBit (extract bin 20u 16u)
      let crbb = getCRBit (extract bin 15u 11u)
      struct (Op.CRXOR, ThreeOperands (crbd, crba, crbb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseCRNAND bin =
  match pickBit bin 0u with
  | 0b0u ->
    let crbd = getCRBit (extract bin 25u 21u)
    let crba = getCRBit (extract bin 20u 16u)
    let crbb = getCRBit (extract bin 15u 11u)
    struct (Op.CRNAND, ThreeOperands (crbd, crba, crbb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseCRAND bin =
  match pickBit bin 0u with
  | 0b0u ->
    let crbd = getCRBit (extract bin 25u 21u)
    let crba = getCRBit (extract bin 20u 16u)
    let crbb = getCRBit (extract bin 15u 11u)
    struct (Op.CRAND, ThreeOperands (crbd, crba, crbb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseCREQV bin =
  match pickBit bin 0u with
  | 0b0u ->
    let crbd = getCRBit (extract bin 25u 21u)
    (* crset crbd = creqv crbd,crbd,crbd *)
    if extract bin 25u 21u = extract bin 20u 16u then
      if extract bin 20u 16u = extract bin 15u 11u then
        struct (Op.CRSET, OneOperand crbd)
      else
        let crba = getCRBit (extract bin 20u 16u)
        let crbb = getCRBit (extract bin 15u 11u)
        struct (Op.CREQV, ThreeOperands (crbd, crba, crbb))
    else
      let crba = getCRBit (extract bin 20u 16u)
      let crbb = getCRBit (extract bin 15u 11u)
      struct (Op.CREQV, ThreeOperands (crbd, crba, crbb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseCRORC bin =
  match pickBit bin 0u with
  | 0b0u ->
    let crbd = getCRBit (extract bin 25u 21u)
    let crba = getCRBit (extract bin 20u 16u)
    let crbb = getCRBit (extract bin 15u 11u)
    struct (Op.CRORC, ThreeOperands (crbd, crba, crbb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseCROR bin =
  match pickBit bin 0u with
  | 0b0u ->
    let crbd = getCRBit (extract bin 25u 21u)
    let crba = getCRBit (extract bin 20u 16u)
    (* crmove crbd,crba = cror crbd,crba,crba *)
    if extract bin 20u 16u = extract bin 15u 11u then
      struct (Op.CRMOVE, TwoOperands (crbd, crba))
    else
      let crbb = getCRBit (extract bin 15u 11u)
      struct (Op.CROR, ThreeOperands (crbd, crba, crbb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseBCCTRx bin =
  match pickBit bin 0u with
  | 0b0u when extract bin 15u 11u = 0u ->
    let bo = extract bin 25u 21u |> uint64 |> OprImm
    struct (Op.BCCTR, TwoOperands (bo, OprBI (extract bin 20u 16u)))
  | 0b1u when extract bin 15u 11u = 0u ->
    let bo = extract bin 25u 21u |> uint64 |> OprImm
    struct (Op.BCCTRL, TwoOperands (bo, OprBI (extract bin 20u 16u)))
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
  let rs = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let sh = extract bin 15u 11u |> uint64 |> OprImm
  let mb = extract bin 10u 6u |> uint64 |> OprImm
  let me = extract bin 5u 1u |> uint64 |> OprImm
  match pickBit bin 0u with
  (* inslwi ra,rs,n,b = rlwimi ra,rs,32-b,b,b+n-1
     insrwi ra,rs,n,b (n>0) = rlwimi ra,rs,32-(b+n),b,(b+n)-1 *)
  | 0b0u -> struct (Op.RLWIMI, FiveOperands(ra, rs, sh, mb, me))
  | _ (* 1 *) -> struct (Op.RLWIMIdot, FiveOperands(ra, rs, sh, mb, me))

let parseRLWINMx bin =
  let rs = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  match pickBit bin 0u with
  | 0b0u ->
    match extract bin 15u 11u with
    | 0b0u when extract bin 5u 1u = 0x1Fu ->
      let n = extract bin 15u 11u |> uint64 |> OprImm
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
          let n = extract bin 15u 11u |> uint64 |> OprImm
          struct (Op.ROTLWI, ThreeOperands(ra, rs, n))
        (* slwi ra,rs,n = rlwinm ra,rs,n,0,31-n *)
        elif extract bin 5u 1u = 0x1Fu - n then
          let n = extract bin 15u 11u |> uint64 |> OprImm
          struct (Op.SLWI, ThreeOperands(ra, rs, n))
        else
          let sh = extract bin 15u 11u |> uint64 |> OprImm
          let mb = extract bin 10u 6u |> uint64 |> OprImm
          let me = extract bin 5u 1u |> uint64 |> OprImm
          struct (Op.RLWINM, FiveOperands(ra, rs, sh, mb, me))
      | _ ->
        let n = extract bin 10u 6u
        if extract bin 15u 11u = 0x20u - n then
          match extract bin 5u 1u with
          (* srwi ra,rs,n = rlwinm ra,rs,32-n,n,31 *)
          | 0x1Fu ->
            let n = extract bin 10u 6u |> uint64 |> OprImm
            struct (Op.SRWI, ThreeOperands(ra, rs, n))
          | _ ->
            let sh = extract bin 15u 11u |> uint64 |> OprImm
            let mb = extract bin 10u 6u |> uint64 |> OprImm
            let me = extract bin 5u 1u |> uint64 |> OprImm
            struct (Op.RLWINM, FiveOperands(ra, rs, sh, mb, me))
        (* extlwi ra,rs,n,b = rlwinm ra,rs,b,0,n-1,
           extrwi ra,rs,n,b = rlwinm ra,rs,b+n,32-n,31
           clrrwi ra,rs,n = rlwinm ra,rs,0,0,31-n
           clrlslwi ra,rs,b,n = rlwinm ra,rs,n,b-n,31-n *)
        else
          let sh = extract bin 15u 11u |> uint64 |> OprImm
          let mb = extract bin 10u 6u |> uint64 |> OprImm
          let me = extract bin 5u 1u |> uint64 |> OprImm
          struct (Op.RLWINM, FiveOperands(ra, rs, sh, mb, me))
  | _ (* 1 *) ->
    let sh = extract bin 15u 11u |> uint64 |> OprImm
    let mb = extract bin 10u 6u |> uint64 |> OprImm
    let me = extract bin 5u 1u |> uint64 |> OprImm
    struct (Op.RLWINMdot, FiveOperands(ra, rs, sh, mb, me))

let parseRLWNMx bin =
  let rs = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let rb = getRegister (extract bin 15u 11u) |> OprReg
  match pickBit bin 0u with
  | 0b0u ->
    match extract bin 10u 1u with
    (* rotlw ra,rs,rb = rlwnm ra,rs,rb,mb,me *)
    | 0x1Fu -> struct (Op.ROTLW, ThreeOperands(ra, rs, rb))
    | _ ->
      let mb = extract bin 10u 6u |> uint64 |> OprImm
      let me = extract bin 5u 1u |> uint64 |> OprImm
      struct (Op.RLWNM, FiveOperands(ra, rs, rb, mb, me))
  | _ (* 1 *) ->
    let mb = extract bin 10u 6u |> uint64 |> OprImm
    let me = extract bin 5u 1u |> uint64 |> OprImm
    struct (Op.RLWNMdot, FiveOperands(ra, rs, rb, mb, me))

let parseORI bin =
  match extract bin 25u 0u with
  (* nop = ori 0,0,0 *)
  | 0b0u -> struct (Op.NOP, NoOperand)
  | _ ->
    let rs = getRegister (extract bin 25u 21u) |> OprReg
    let ra = getRegister (extract bin 20u 16u) |> OprReg
    let uimm = extract bin 15u 0u |> uint64
    let value = signExtend 16 32 uimm |> uint64 |> OprImm
    struct (Op.ORI, ThreeOperands(rs, ra, value))

let parseORIS bin =
  let rs = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let uimm = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 uimm |> uint64 |> OprImm
  struct (Op.ORIS, ThreeOperands(rs, ra, value))

let parseXORI bin =
  let rs = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let uimm = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 uimm |> uint64 |> OprImm
  struct (Op.XORI, ThreeOperands(rs, ra, value))

let parseXORIS bin =
  let rs = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let uimm = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 uimm |> uint64 |> OprImm
  struct (Op.XORIS, ThreeOperands(rs, ra, value))

let parseANDIdot bin =
  let rs = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let uimm = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 uimm |> uint64 |> OprImm
  struct (Op.ANDIdot, ThreeOperands(rs, ra, value))

let parseANDISdot bin =
  let rs = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let uimm = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 uimm |> uint64 |> OprImm
  struct (Op.ANDISdot, ThreeOperands(rs, ra, value))

let parseCMPandMCRXR bin =
  match pickBit bin 10u with
  | 0b0u when pickBit bin 22u = 0u ->
    let crfd = getCondRegister (extract bin 25u 23u) |> OprReg
    let ra = getRegister (extract bin 20u 16u) |> OprReg
    let rb = getRegister (extract bin 15u 11u) |> OprReg
    match pickBit bin 21u with
    (* cmpw crfd,ra,rb = cmp crfd,0,ra,rb *)
    | 0b0u -> struct (Op.CMPW, ThreeOperands (crfd, ra, rb))
    | _ (* 1 *) -> struct (Op.CMP, FourOperands (crfd, OprImm 1UL, ra, rb))
  | 0b1u when extract bin 22u 11u = 0u ->
    let crfd = getCondRegister (extract bin 25u 23u) |> OprReg
    struct (Op.MCRXR, OneOperand (crfd))
  | _ -> raise ParsingFailureException

let parseTW bin =
  match pickBit bin 10u with
  | 0b0u ->
    let ra = getRegister (extract bin 20u 16u) |> OprReg
    let rb = getRegister (extract bin 15u 11u) |> OprReg
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
        let tO = extract bin 25u 21u |> uint64 |> OprImm
        struct (Op.TW, ThreeOperands (tO, ra, rb))
    | _ ->
      let tO = extract bin 25u 21u |> uint64 |> OprImm
      struct (Op.TW, ThreeOperands (tO, ra, rb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseSUBFCx bin =
  let rd = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let rb = getRegister (extract bin 15u 11u) |> OprReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  (* subc rd,ra,rb = subfc rd,rb,ra *)
  | 0b00u -> struct (Op.SUBFC, ThreeOperands (rd, ra, rb))
  | 0b01u -> struct (Op.SUBFCdot, ThreeOperands (rd, ra, rb))
  | 0b10u -> struct (Op.SUBFCO, ThreeOperands (rd, ra, rb))
  | _ (* 11 *) -> struct (Op.SUBFCOdot, ThreeOperands (rd, ra, rb))

let parseADDCx bin =
  let rd = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let rb = getRegister (extract bin 15u 11u) |> OprReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  | 0b00u -> struct (Op.ADDC, ThreeOperands (rd, ra, rb))
  | 0b01u -> struct (Op.ADDCdot, ThreeOperands (rd, ra, rb))
  | 0b10u -> struct (Op.ADDCO, ThreeOperands (rd, ra, rb))
  | _ (* 11 *) ->  struct (Op.ADDCOdot, ThreeOperands (rd, ra, rb))

let parseMULHWUx bin =
  let rd = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let rb = getRegister (extract bin 15u 11u) |> OprReg
  match pickBit bin 0u with
  | 0b0u ->  struct (Op.MULHWU, ThreeOperands (rd, ra, rb))
  | _ (* 1 *) -> struct (Op.MULHWUdot, ThreeOperands (rd, ra, rb))

let parseMFCR bin =
  match pickBit bin 10u with
  | 0b0u when extract bin 20u 11u = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OprReg
    struct (Op.MFCR, OneOperand (rd))
  | _ (* 1 *) -> raise ParsingFailureException

let parseLWARX bin =
  match pickBit bin 10u with
  | 0b0u ->
    let rd = getRegister (extract bin 25u 21u) |> OprReg
    let ra = getRegister (extract bin 20u 16u) |> OprReg
    let rb = getRegister (extract bin 15u 11u) |> OprReg
    struct (Op.LWARX, ThreeOperands (rd, ra, rb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseLSWX bin =
  match pickBit bin 10u with
  | 0b1u ->
    let rd = getRegister (extract bin 25u 21u) |> OprReg
    let ra = getRegister (extract bin 20u 16u) |> OprReg
    let rb = getRegister (extract bin 15u 11u) |> OprReg
    struct (Op.LSWX, ThreeOperands (rd, ra, rb))
  | _ (* 0 *) -> raise ParsingFailureException

let parseLWBRX bin =
  match pickBit bin 10u with
  | 0b1u ->
    let rd = getRegister (extract bin 25u 21u) |> OprReg
    let ra = getRegister (extract bin 20u 16u) |> OprReg
    let rb = getRegister (extract bin 15u 11u) |> OprReg
    struct (Op.LWBRX, ThreeOperands (rd, ra, rb))
  | _ (* 0 *) -> raise ParsingFailureException

let parseLWZXandLFSX bin =
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let rb = getRegister (extract bin 15u 11u) |> OprReg
  match pickBit bin 10u with
  | 0b0u ->
    let rd = getRegister (extract bin 25u 21u) |> OprReg
    struct (Op.LWZX, ThreeOperands (rd, ra, rb))
  | _ (* 1 *) ->
    let frd = getFPRegister (extract bin 25u 21u) |> OprReg
    struct (Op.LFSX, ThreeOperands (frd, ra, rb))

let parseSLWxandSRWx bin =
  let rs = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let rb = getRegister (extract bin 15u 11u) |> OprReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 0:RC *) with
  | 0b00u -> struct (Op.SLW, ThreeOperands (ra, rs, rb))
  | 0b01u -> struct (Op.SLWdot, ThreeOperands (ra, rs, rb))
  | 0b10u -> struct (Op.SRW, ThreeOperands (ra, rs, rb))
  | _ (* 11 *) -> struct (Op.SRWdot, ThreeOperands (ra, rs, rb))

let parseCNTLZWx bin =
  let rs = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 0:RC *) with
  | 0b00u when extract bin 15u 11u = 0u ->
    struct (Op.CNTLZW, TwoOperands (ra, rs))
  | 0b01u when extract bin 15u 11u = 0u ->
    struct (Op.CNTLZWdot, TwoOperands (ra, rs))
  | _ (* 1x *) -> raise ParsingFailureException

let parseANDx bin =
  let rs = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let rb = getRegister (extract bin 15u 11u) |> OprReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 0:RC *) with
  | 0b00u -> struct (Op.AND, ThreeOperands (ra, rs, rb))
  | 0b01u -> struct (Op.ANDdot, ThreeOperands (ra, rs, rb))
  | _ (* 1x *) -> raise ParsingFailureException

let parseCMPL bin =
  match pickBit bin 10u with
  | 0b0u when pickBit bin 22u = 0u ->
    let crfd = getCondRegister (extract bin 25u 23u) |> OprReg
    let ra = getRegister (extract bin 20u 16u) |> OprReg
    let rb = getRegister (extract bin 15u 11u) |> OprReg
    match pickBit bin 21u with
    (* cmplw crfd,ra,rb = cmpl crfd,0,ra,rb *)
    | 0b0u -> struct (Op.CMPLW, ThreeOperands (crfd, ra, rb))
    | _ (* 1 *)-> struct (Op.CMPL, FourOperands (crfd, OprImm 1UL, ra, rb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseSUBFx bin =
  let rd = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let rb = getRegister (extract bin 15u 11u) |> OprReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  (* sub rd,rb,ra = subf rd,ra,rb *)
  | 0b00u -> struct (Op.SUBF, ThreeOperands (rd, ra, rb))
  | 0b01u -> struct (Op.SUBFdot, ThreeOperands (rd, ra, rb))
  | 0b10u -> struct (Op.SUBFO, ThreeOperands (rd, ra, rb))
  | _ (* 11 *) ->  struct (Op.SUBFOdot, ThreeOperands (rd, ra, rb))

let parseDCBSTandTLBSYNC bin =
  match pickBit bin 10u with
  | 0b0u when extract bin 25u 21u = 0u ->
    let ra = getRegister (extract bin 20u 16u) |> OprReg
    let rb = getRegister (extract bin 15u 11u) |> OprReg
    struct (Op.DCBST, TwoOperands (ra, rb))
  | 0b1u when extract bin 25u 11u = 0u ->
    struct (Op.TLBSYNC, NoOperand)
  | _ -> raise ParsingFailureException

let parseLWZUXandLFSUX bin =
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let rb = getRegister (extract bin 15u 11u) |> OprReg
  match pickBit bin 10u with
  | 0b0u ->
    let rd = getRegister (extract bin 25u 21u) |> OprReg
    struct (Op.LWZUX, ThreeOperands (rd, ra, rb))
  | _ (* 1 *) ->
    let frd = getFPRegister (extract bin 25u 21u) |> OprReg
    struct (Op.LFSUX, ThreeOperands (frd, ra, rb))

let parseANDCx bin =
  let rs = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let rb = getRegister (extract bin 15u 11u) |> OprReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 0:RC *) with
  | 0b00u -> struct (Op.ANDC, ThreeOperands (ra, rs, rb))
  | 0b01u -> struct (Op.ANDCdot, ThreeOperands (ra, rs, rb))
  | _ (* 1x *) -> raise ParsingFailureException

let parseMULHWx bin =
  let rd = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let rb = getRegister (extract bin 15u 11u) |> OprReg
  match pickBit bin 0u with
  | 0b0u -> struct (Op.MULHW, ThreeOperands (rd, ra, rb))
  | _ (* 1 *) -> struct (Op.MULHWdot, ThreeOperands (rd, ra, rb))

let parseMFMSRandMFSR bin =
  match pickBit bin 10u with
  | 0b0u when extract bin 20u 11u = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OprReg
    struct (Op.MFMSR, OneOperand (rd))
  | 0b1u when (concat (pickBit bin 20u) (extract bin 15u 11u) 1) = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OprReg
    (* FIXME: SegRegister *)
    let sr = getSegRegister (extract bin 19u 16u)
    struct (Op.MFSR, TwoOperands (sr, rd))
  | _ -> raise ParsingFailureException

let parseLSWI bin =
  match pickBit bin 10u with
  | 0b1u ->
    let rd = getRegister (extract bin 25u 21u) |> OprReg
    let ra = getRegister (extract bin 20u 16u) |> OprReg
    let nb = extract bin 15u 11u |> uint64 |> OprImm
    struct (Op.LSWI, ThreeOperands(rd, ra, nb))
  | _ (* 0 *) -> raise ParsingFailureException

let parseDCBFandSYNC bin =
  match pickBit bin 10u with
  | 0b0u when extract bin 25u 21u = 0u ->
    let ra = getRegister (extract bin 20u 16u) |> OprReg
    let rb = getRegister (extract bin 15u 11u) |> OprReg
    struct (Op.DCBF, TwoOperands (ra, rb))
  | 0b1u when extract bin 25u 11u = 0u ->
    struct (Op.SYNC, NoOperand)
  | _ -> raise ParsingFailureException

let parseLBZXandLFDX bin =
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let rb = getRegister (extract bin 15u 11u) |> OprReg
  match pickBit bin 10u with
  | 0b0u ->
    let rd = getRegister (extract bin 25u 21u) |> OprReg
    struct (Op.LBZX, ThreeOperands (rd, ra, rb))
  | _ (* 1 *) ->
    let frd = getFPRegister (extract bin 25u 21u) |> OprReg
    let ra = getRegister (extract bin 20u 16u) |> OprReg
    let rb = getRegister (extract bin 15u 11u) |> OprReg
    struct (Op.LFDX, ThreeOperands (frd, ra, rb))

let parseNEGx bin =
  let rd = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
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
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let rb = getRegister (extract bin 15u 11u) |> OprReg
  match pickBit bin 10u with
  | 0b0u ->
    let rd = getRegister (extract bin 25u 21u) |> OprReg
    struct (Op.LBZUX, ThreeOperands (rd, ra, rb))
  | 0b1u ->
    let frd = getFPRegister (extract bin 25u 21u) |> OprReg
    struct (Op.LFDUX, ThreeOperands (frd, ra, rb))
  | _ -> raise ParsingFailureException

let parseNORx bin =
  let rs = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let rb = getRegister (extract bin 15u 11u) |> OprReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 0:RC *) with
  (* not rd,rs = nor ra,rs,rs *)
  | 0b00u -> struct (Op.NOR, ThreeOperands (ra, rs, rb))
  | 0b01u -> struct (Op.NORdot, ThreeOperands (ra, rs, rb))
  | _ (* 1x *) -> raise ParsingFailureException

let parseSUBFEx bin =
  let rd = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let rb = getRegister (extract bin 15u 11u) |> OprReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  | 0b00u -> struct (Op.SUBFE, ThreeOperands (rd, ra, rb))
  | 0b01u -> struct (Op.SUBFEdot, ThreeOperands (rd, ra, rb))
  | 0b10u -> struct (Op.SUBFEO, ThreeOperands (rd, ra, rb))
  | _ (* 11 *) -> struct (Op.SUBFEOdot, ThreeOperands (rd, ra, rb))

let parseADDEx bin =
  let rd = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let rb = getRegister (extract bin 15u 11u) |> OprReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  | 0b00u -> struct (Op.ADDE, ThreeOperands (rd, ra, rb))
  | 0b01u -> struct (Op.ADDEdot, ThreeOperands (rd, ra, rb))
  | 0b10u -> struct (Op.ADDEO, ThreeOperands (rd, ra, rb))
  | _ (* 11 *) -> struct (Op.ADDEOdot, ThreeOperands (rd, ra, rb))

let parseMTCRF bin =
  match pickBit bin 10u with
  (* mtcr rs = mtcrf 0xff,rs *)
  | 0b0u when concat (pickBit bin 20u) (pickBit bin 11u) 1 = 00u ->
    let rs = getRegister (extract bin 25u 21u) |> OprReg
    let crm = extract bin 19u 12u |> uint64 |> OprImm
    struct (Op.MTCRF, TwoOperands (crm, rs))
  | _ (* 1 *) -> raise ParsingFailureException

let parseMTMSR bin =
  match pickBit bin 10u with
  | 0b0u when extract bin 20u 11u = 0u ->
    let rs = getRegister (extract bin 25u 21u) |> OprReg
    struct (Op.MFMSR, OneOperand rs)
  | _ (* 1 *) -> raise ParsingFailureException

let parseMFSRIN bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 with
  | 0b10u when extract bin 20u 16u = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OprReg
    let rb = getRegister (extract bin 15u 11u) |> OprReg
    struct (Op.MFSRIN, TwoOperands (rd, rb))
  | _ (* 11, 0x *) -> raise ParsingFailureException

let parseSTSWX bin =
  match pickBit bin 10u with
  | 0b1u ->
    let rs = getRegister (extract bin 25u 21u) |> OprReg
    let ra = getRegister (extract bin 20u 16u) |> OprReg
    let rb = getRegister (extract bin 15u 11u) |> OprReg
    struct (Op.STSWX, ThreeOperands (rs, ra, rb))
  | _ (* 0 *) -> raise ParsingFailureException

let parseSTWCXdotandSTWBRX bin =
  let rs = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let rb = getRegister (extract bin 15u 11u) |> OprReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 with
  | 0b01u -> struct (Op.STWCXdot, ThreeOperands (rs, ra, rb))
  | 0b10u -> struct (Op.STWBRX, ThreeOperands (rs, ra, rb))
  | _ (* 00, 11 *) -> raise ParsingFailureException

let parseSTWXandSTFSX bin =
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let rb = getRegister (extract bin 15u 11u) |> OprReg
  match pickBit bin 10u with
  | 0b0u ->
    let rs = getRegister (extract bin 25u 21u) |> OprReg
    struct (Op.STWX, ThreeOperands (rs, ra, rb))
  | _ (* 1 *) ->
    let frs = getFPRegister (extract bin 25u 21u) |> OprReg
    struct (Op.STFSX, ThreeOperands (frs, ra, rb))

let parseSTWUXandSTFSUX bin =
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let rb = getRegister (extract bin 15u 11u) |> OprReg
  match pickBit bin 10u with
  | 0b0u ->
    let rs = getRegister (extract bin 25u 21u) |> OprReg
    struct (Op.STWUX, ThreeOperands (rs, ra, rb))
  | _ (* 1 *) ->
    let frs = getFPRegister (extract bin 25u 21u) |> OprReg
    struct (Op.STFSUX, ThreeOperands (frs, ra, rb))

let parseSUBFZEx bin =
  let rd = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
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
  let rd = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
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
    let rs = getRegister (extract bin 25u 21u) |> OprReg
    (* FIXME: SegRegister *)
    let sr = getSegRegister (extract bin 19u 16u)
    struct (Op.MTSR, TwoOperands (rs, sr))
  | _ (* 1 *) -> raise ParsingFailureException

let parseSTSWI bin =
  match pickBit bin 10u with
  | 0b1u ->
    let rs = getRegister (extract bin 25u 21u) |> OprReg
    let ra = getRegister (extract bin 20u 16u) |> OprReg
    let nb = extract bin 15u 11u |> uint64 |> OprImm
    struct (Op.STSWI, ThreeOperands (rs, ra, nb))
  | _ (* 0 *) -> raise ParsingFailureException

let parseSTBXandSTFDX bin =
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let rb = getRegister (extract bin 15u 11u) |> OprReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 with
  | 0b00u ->
    let rs = getRegister (extract bin 25u 21u) |> OprReg
    struct (Op.STBX, ThreeOperands (rs, ra, rb))
  | 0b10u ->
    let frs = getFPRegister (extract bin 25u 21u) |> OprReg
    struct (Op.STFDX, ThreeOperands (frs, ra, rb))
  | _ (* 01, 11 *) -> raise ParsingFailureException

let parseSUBFMEx bin =
  let rd = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
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
  let rd = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
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
  let rd = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let rb = getRegister (extract bin 15u 11u) |> OprReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  | 0b00u -> struct (Op.MULLW, ThreeOperands (rd, ra, rb))
  | 0b01u -> struct (Op.MULLWdot, ThreeOperands (rd, ra, rb))
  | 0b10u -> struct (Op.MULLWO, ThreeOperands (rd, ra, rb))
  | _ (* 11 *) -> struct (Op.MULLWOdot, ThreeOperands (rd, ra, rb))

let parseMTSRIN bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 with
  | 0b10u when extract bin 20u 16u = 0u ->
    let rd = getRegister (extract bin 25u 21u) |> OprReg
    let rb = getRegister (extract bin 15u 11u) |> OprReg
    struct (Op.MTSRIN, TwoOperands (rd, rb))
  | _ (* 11, 0x *) -> raise ParsingFailureException

let parseDCBTSTandDCBA bin =
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let rb = getRegister (extract bin 15u 11u) |> OprReg
  match pickBit bin 10u with
  | 0b0u when extract bin 25u 21u = 0u ->
    (* CT = 0u *)
    struct (Op.DCBTST, TwoOperands (ra, rb))
  | 0b1u when extract bin 25u 21u = 0u ->
    struct (Op.DCBA, TwoOperands (ra, rb))
  | _ -> raise ParsingFailureException

let parseSTBUXandSTFDUX bin =
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let rb = getRegister (extract bin 15u 11u) |> OprReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 with
  | 0b00u ->
    let rs = getRegister (extract bin 25u 21u) |> OprReg
    struct (Op.STBUX, ThreeOperands (rs, ra, rb))
  | 0b10u ->
    let frs = getFPRegister (extract bin 25u 21u) |> OprReg
    struct (Op.STFDUX, ThreeOperands (frs, ra, rb))
  | _ (* 01, 11 *) -> raise ParsingFailureException

let parseADDx bin =
  let rd = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let rb = getRegister (extract bin 15u 11u) |> OprReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  | 0b00u -> struct (Op.ADD, ThreeOperands (rd, ra, rb))
  | 0b01u -> struct (Op.ADDdot, ThreeOperands (rd, ra, rb))
  | 0b10u -> struct (Op.ADDO, ThreeOperands (rd, ra, rb))
  | _ (* 11 *) -> struct (Op.ADDOdot, ThreeOperands (rd, ra, rb))

let parseDCBTandLHBRX bin =
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let rb = getRegister (extract bin 15u 11u) |> OprReg
  match pickBit bin 10u with
  | 0b0u when extract bin 25u 21u = 0u ->
    (* CT = 0u *)
     struct (Op.DCBT, TwoOperands (ra, rb))
  | 0b1u ->
    let rd = getRegister (extract bin 25u 21u) |> OprReg
    struct (Op.LHBRX, ThreeOperands (rd, ra, rb))
  | _ -> raise ParsingFailureException

let parseLHZX bin =
  match pickBit bin 10u with
  | 0b0u ->
    let rd = getRegister (extract bin 25u 21u) |> OprReg
    let ra = getRegister (extract bin 20u 16u) |> OprReg
    let rb = getRegister (extract bin 15u 11u) |> OprReg
    struct (Op.LHZX, ThreeOperands (rd, ra, rb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseSRAWx bin =
  let rs = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let rb = getRegister (extract bin 15u 11u) |> OprReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 1:RC *) with
  | 0b10u -> struct (Op.SRAW, ThreeOperands (ra, rs, rb))
  | 0b11u -> struct (Op.SRAWdot, ThreeOperands (ra, rs, rb))
  | _ (* 0x *) -> raise ParsingFailureException

let parseEQVx bin =
  let rd = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let rb = getRegister (extract bin 15u 11u) |> OprReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 0:Rc *) with
  | 0b00u -> struct (Op.EQV, ThreeOperands (rd, ra, rb))
  | 0b01u -> struct (Op.EQVdot, ThreeOperands (rd, ra, rb))
  | _ (* 1x *) -> raise ParsingFailureException

let parseTLBIE bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 with
  | 0b00u ->
    let rb = getRegister (extract bin 15u 11u) |> OprReg
    struct (Op.TLBIE, OneOperand rb)
  | _ (* 01, 1x *) -> raise ParsingFailureException

let parseECIWX bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 with
  | 0b00u ->
    let rd = getRegister (extract bin 25u 21u) |> OprReg
    let ra = getRegister (extract bin 20u 16u) |> OprReg
    let rb = getRegister (extract bin 15u 11u) |> OprReg
    struct (Op.ECIWX, ThreeOperands (rd, ra, rb))
  | _ (* 01, 1x *) -> raise ParsingFailureException

let parseLHZUX bin =
  match pickBit bin 10u with
  | 0b0u ->
    let rd = getRegister (extract bin 25u 21u) |> OprReg
    let ra = getRegister (extract bin 20u 16u) |> OprReg
    let rb = getRegister (extract bin 15u 11u) |> OprReg
    struct (Op.LHZUX, ThreeOperands (rd, ra, rb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseSRAWIx bin =
  let rs = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let sh = extract bin 15u 11u |> uint64 |> OprImm
  match pickBit bin 0u with
  | 0b0u -> struct (Op.SRAWI, ThreeOperands (rs, ra, sh))
  | _ (* 1 *) -> struct (Op.SRAWIdot, ThreeOperands (rs, ra, sh))

let parseXORx bin =
  let rs = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let rb = getRegister (extract bin 15u 11u) |> OprReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 0:RC *) with
  | 0b00u -> struct (Op.XOR, ThreeOperands (ra, rs, rb))
  | 0b01u -> struct (Op.XORdot, ThreeOperands (ra, rs, rb))
  | _ (* 1x *) -> raise ParsingFailureException

let parseMFSPR bin =
  match pickBit bin 10u with
  | 0b0u ->
    let rd = getRegister (extract bin 25u 21u) |> OprReg
    match concat (extract bin 15u 11u) (extract bin 20u 16u) 5 with
    (* mfxer rd = mfspr rd,1 *)
    | 0x1u -> struct (Op.MFXER, OneOperand rd)
    (* mflr rd = mfspr rd,8 *)
    | 0x8u -> struct (Op.MFLR, OneOperand rd)
    (* mfctr rd = mfspr rd,9 *)
    | 0x9u -> struct (Op.MFCTR, OneOperand rd)
    | _ ->
      (* FIXME: SPRegister *)
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
    let rd = getRegister (extract bin 25u 21u) |> OprReg
    let ra = getRegister (extract bin 20u 16u) |> OprReg
    let rb = getRegister (extract bin 15u 11u) |> OprReg
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
    let rd = getRegister (extract bin 25u 21u) |> OprReg
    (* FIXME: TBRRegister *)
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
    let rd = getRegister (extract bin 25u 21u) |> OprReg
    let ra = getRegister (extract bin 20u 16u) |> OprReg
    let rb = getRegister (extract bin 15u 11u) |> OprReg
    struct (Op.LHAUX, ThreeOperands (rd, ra, rb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseSTHBRX bin =
  match pickBit bin 10u with
  | 0b1u ->
    let rs = getRegister (extract bin 25u 21u) |> OprReg
    let ra = getRegister (extract bin 20u 16u) |> OprReg
    let rb = getRegister (extract bin 15u 11u) |> OprReg
    struct (Op.STHBRX, ThreeOperands (rs, ra, rb))
  | _ (* 0 *) -> raise ParsingFailureException

let parseSTHX bin =
  match pickBit bin 10u with
  | 0b0u ->
    let rs = getRegister (extract bin 25u 21u) |> OprReg
    let ra = getRegister (extract bin 20u 16u) |> OprReg
    let rb = getRegister (extract bin 15u 11u) |> OprReg
    struct (Op.STHX, ThreeOperands (rs, ra, rb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseEXTSHx bin =
  let rs = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 1:Rc *) with
  | 0b10u when extract bin 15u 11u = 0u ->
    struct (Op.EXTSH, TwoOperands (rs, ra))
  | 0b11u when extract bin 15u 11u = 0u ->
    struct (Op.EXTSHdot, TwoOperands (rs, ra))
  | _ (* 0x *) -> raise ParsingFailureException

let parseORCx bin =
  let rs = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let rb = getRegister (extract bin 15u 11u) |> OprReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 0:RC *) with
  | 0b00u -> struct (Op.ORC, ThreeOperands (ra, rs, rb))
  | 0b01u -> struct (Op.ORCdot, ThreeOperands (ra, rs, rb))
  | _ (* 1x *) -> raise ParsingFailureException

let parseECOWX bin =
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 with
  | 0b00u ->
    let rs = getRegister (extract bin 25u 21u) |> OprReg
    let ra = getRegister (extract bin 20u 16u) |> OprReg
    let rb = getRegister (extract bin 15u 11u) |> OprReg
    struct (Op.ECOWX, ThreeOperands (rs, ra, rb))
  | _ (* 01, 1x *) -> raise ParsingFailureException

let parseSTHUX bin =
  match pickBit bin 10u with
  | 0b0u ->
    let rs = getRegister (extract bin 25u 21u) |> OprReg
    let ra = getRegister (extract bin 20u 16u) |> OprReg
    let rb = getRegister (extract bin 15u 11u) |> OprReg
    struct (Op.STHUX, ThreeOperands (rs, ra, rb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseEXTSBx bin =
  let rs = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 1:Rc *) with
  | 0b10u when extract bin 15u 11u = 0u ->
    struct (Op.EXTSB, TwoOperands (rs, ra))
  | 0b11u when extract bin 15u 11u = 0u ->
    struct (Op.EXTSBdot, TwoOperands (rs, ra))
  | _ (* 0x *) -> raise ParsingFailureException

let parseORx bin =
  let rs = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 0:RC *) with
  (* mr ra,rs = or ra,rs,rs *)
  | 0b00u ->
    if extract bin 25u 21u = extract bin 15u 11u then
      struct (Op.MR, TwoOperands (ra, rs))
    else
      let rb = getRegister (extract bin 15u 11u) |> OprReg
      struct (Op.OR, ThreeOperands (ra, rs, rb))
  | 0b01u ->
    let rb = getRegister (extract bin 15u 11u) |> OprReg
    struct (Op.ORdot, ThreeOperands (ra, rs, rb))
  | _ (* 1x *) -> raise ParsingFailureException

let parseDIVWUx bin =
  let rd = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let rb = getRegister (extract bin 15u 11u) |> OprReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  | 0b00u -> struct (Op.DIVWU, ThreeOperands (rd, ra, rb))
  | 0b01u -> struct (Op.DIVWUdot, ThreeOperands (rd, ra, rb))
  | 0b10u -> struct (Op.DIVWUO, ThreeOperands (rd, ra, rb))
  | _ (* 11 *) -> struct (Op.DIVWUOdot, ThreeOperands (rd, ra, rb))

let parseMTSPR bin =
  match pickBit bin 10u with
  | 0b0u ->
    let rs = getRegister (extract bin 25u 21u) |> OprReg
    match concat (extract bin 15u 11u) (extract bin 20u 16u) 5 with
    (* mtxer rd = mtspr rd,1 *)
    | 0x1u -> struct (Op.MTXER, OneOperand rs)
    (* mtlr rd = mtspr rd,8 *)
    | 0x8u -> struct (Op.MTLR, OneOperand rs)
    (* mtctr rd = mtspr rd,9 *)
    | 0x9u -> struct (Op.MTCTR, OneOperand rs)
    | _ ->
      (* FIXME: SPRegister *)
      let spr =
        getSPRegister (concat (extract bin 15u 11u) (extract bin 20u 16u) 5)
      struct (Op.MTSPR, TwoOperands (rs, spr))
  | _ (* 1 *) -> raise ParsingFailureException

let parseDCBIandICBI bin =
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let rb = getRegister (extract bin 15u 11u) |> OprReg
  match pickBit bin 10u with
  | 0b0u when extract bin 25u 21u = 0u ->
    struct (Op.DCBI, TwoOperands (ra, rb))
  | 0b1u when extract bin 25u 21u = 0u ->
    struct (Op.ICBI, TwoOperands (ra, rb))
  | _ -> raise ParsingFailureException

let parseSTFIWX bin =
  match pickBit bin 10u with
  | 0b1u ->
    let frs = getFPRegister (extract bin 25u 21u) |> OprReg
    let ra = getRegister (extract bin 20u 16u) |> OprReg
    let rb = getRegister (extract bin 15u 11u) |> OprReg
    struct (Op.STFIWX, ThreeOperands (frs, ra, rb))
  | _ (* 0 *) -> raise ParsingFailureException

let parseNANDx bin =
  let rs = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let rb = getRegister (extract bin 15u 11u) |> OprReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* 0:RC *) with
  | 0b00u -> struct (Op.NAND, ThreeOperands (ra, rs, rb))
  | 0b01u -> struct (Op.NANDdot, ThreeOperands (ra, rs, rb))
  | _ (* 1x *) -> raise ParsingFailureException

let parseDIVWx bin =
  let rd = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u) |> OprReg
  let rb = getRegister (extract bin 15u 11u) |> OprReg
  match concat (pickBit bin 10u) (pickBit bin 0u) 1 (* OE:RC *) with
  | 0b00u -> struct (Op.DIVW, ThreeOperands (rd, ra, rb))
  | 0b01u -> struct (Op.DIVWdot, ThreeOperands (rd, ra, rb))
  | 0b10u -> struct (Op.DIVWO, ThreeOperands (rd, ra, rb))
  | _ (* 11 *) -> struct (Op.DIVWOdot, ThreeOperands (rd, ra, rb))

let parseDCBZ bin =
  match pickBit bin 10u with
  | 0b1u when extract bin 25u 21u = 0u ->
    let ra = getRegister (extract bin 20u 16u) |> OprReg
    let rb = getRegister (extract bin 15u 11u) |> OprReg
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
  (* FIXME: LWARX RegA = 0 *)
  | 0x14u when pickBit bin 0u = 0u -> parseLWARX bin
  | 0x15u when pickBit bin 0u = 0u -> parseLSWX bin
  (* FIXME: LWBRX RegA = 0 *)
  | 0x16u when pickBit bin 0u = 0u -> parseLWBRX bin
  (* FIXME: LWZX / LFSX RegA = 0 *)
  | 0x17u when pickBit bin 0u = 0u -> parseLWZXandLFSX bin
  | 0x18u -> parseSLWxandSRWx bin
  | 0x1Au -> parseCNTLZWx bin
  | 0x1Cu -> parseANDx bin
  | 0x20u when pickBit bin 0u = 0u -> parseCMPL bin
  | 0x28u -> parseSUBFx bin
  (* FIXME: DCBST RegA = 0 *)
  | 0x36u when pickBit bin 0u = 0u -> parseDCBSTandTLBSYNC bin
  (* FIXME: LWZUX / LFSUX RegA = 0 *)
  | 0x37u when pickBit bin 0u = 0u -> parseLWZUXandLFSUX bin
  | 0x3Cu -> parseANDCx bin
  | 0x4Bu when pickBit bin 10u = 0u -> parseMULHWx bin
  (* FIXME: SegRegister *)
  | 0x53u when pickBit bin 0u = 0u -> parseMFMSRandMFSR bin
  | 0x55u when pickBit bin 0u = 0u -> parseLSWI bin
  (* FIXME: DCBF RegA = 0 / SYNC 0 *)
  | 0x56u when pickBit bin 0u = 0u -> parseDCBFandSYNC bin
  (* FIXME: LBZX / LFDX RegA = 0 *)
  | 0x57u when pickBit bin 0u = 0u -> parseLBZXandLFDX bin
  | 0x68u -> parseNEGx bin
  (* FIXME: LBZUX / LFDUX RegA = 0 *)
  | 0x77u when pickBit bin 0u = 0u -> parseLBZUXandLFDUX bin
  | 0x7Cu -> parseNORx bin
  | 0x88u -> parseSUBFEx bin
  | 0x8Au -> parseADDEx bin
  (* FIXME: CRM *)
  | 0x90u when pickBit bin 0u = 0u -> parseMTCRF bin
  | 0x92u when pickBit bin 0u = 0u -> parseMTMSR bin
  | 0x93u -> parseMFSRIN bin
  | 0x95u when pickBit bin 0u = 0u -> parseSTSWX bin
  (* FIXME: STWCXdot / STWBRX RegA = 0 *)
  | 0x96u -> parseSTWCXdotandSTWBRX bin
  (* FIXME: STWX / STFSX RegA = 0 *)
  | 0x97u when pickBit bin 0u = 0u -> parseSTWXandSTFSX bin
  (* FIXME: STWUX / STFSUX RegA = 0 *)
  | 0xB7u when pickBit bin 0u = 0u -> parseSTWUXandSTFSUX bin
  | 0xC8u -> parseSUBFZEx bin
  | 0xCAu -> parseADDZEx bin
  (* FIXME: SegRegister *)
  | 0xD2u when pickBit bin 0u = 0u -> parseMTSR bin
  (* FIXME: SpecialRegister *)
  | 0xD5u when pickBit bin 0u = 0u -> parseSTSWI bin
  (* FIXME: STBX / STFDX RegA = 0 *)
  | 0xD7u -> parseSTBXandSTFDX bin
  | 0xE8u -> parseSUBFMEx bin
  | 0xEAu -> parseADDMEx bin
  | 0xEBu -> parseMULLWx bin
  | 0xF2u -> parseMTSRIN bin
  (* FIXME: DCBTST / DCBA RegA = 0 *)
  | 0xF6u when pickBit bin 0u = 0u -> parseDCBTSTandDCBA bin
  (* FIXME: STBUX / STFDUX RegA = 0 *)
  | 0xF7u -> parseSTBUXandSTFDUX bin
  | 0x10Au -> parseADDx bin
  (* FIXME: DCBT / LHBRX RegA = 0 *)
  | 0x116u when pickBit bin 0u = 0u -> parseDCBTandLHBRX bin
  (* FIXME: LHZX RegA = 0 *)
  | 0x117u when pickBit bin 0u = 0u -> parseLHZX bin
  | 0x118u -> parseSRAWx bin
  | 0x11Cu -> parseEQVx bin
  | 0x132u -> parseTLBIE bin
  | 0x136u when pickBit bin 0u = 0u -> parseECIWX bin
  (* FIXME: LHZUX RegA = 0 *)
  | 0x137u when pickBit bin 0u = 0u -> parseLHZUX bin
  | 0x138u when pickBit bin 10u = 1u -> parseSRAWIx bin
  | 0x13Cu -> parseXORx bin
  (* FIXME: SpecialRegister *)
  | 0x153u when pickBit bin 0u = 0u -> parseMFSPR bin
  | 0x156u when pickBit bin 0u = 0u -> parseEIEIO bin
  (* FIXME: LHAX RegA = 0 *)
  | 0x157u when pickBit bin 0u = 0u -> parseLHAX bin
  | 0x172u -> parseTLBIA bin
  (* FIXME: TBRRegister *)
  | 0x173u when pickBit bin 0u = 0u -> parseMFTB bin
  (* FIXME: LHAUX RegA = 0 *)
  | 0x177u when pickBit bin 0u = 0u -> parseLHAUX bin
  (* FIXME: STHBRX RegA = 0 *)
  | 0x196u when pickBit bin 0u = 0u -> parseSTHBRX bin
  (* FIXME: STHX RegA = 0 *)
  | 0x197u when pickBit bin 0u = 0u -> parseSTHX bin
  | 0x19Au -> parseEXTSHx bin
  | 0x19Cu -> parseORCx bin
  | 0x1B6u when pickBit bin 0u = 0u -> parseECOWX bin
  (* FIXME: STHUX RegA = 0 *)
  | 0x1B7u when pickBit bin 0u = 0u -> parseSTHUX bin
  | 0x1BAu -> parseEXTSBx bin
  | 0x1BCu -> parseORx bin
  | 0x1CBu -> parseDIVWUx bin
  | 0x1D3u when pickBit bin 0u = 0u -> parseMTSPR bin
  (* FIXME: DCBI / ICBI RegA = 0 *)
  | 0x1D6u when pickBit bin 0u = 0u -> parseDCBIandICBI bin
  (* FIXME: STFIWX RegA = 0 *)
  | 0x1D7u when pickBit bin 0u = 0u -> parseSTFIWX bin
  | 0x1DCu -> parseNANDx bin
  | 0x1EBu -> parseDIVWx bin
  (* FIXME: DCBZ RegA = 0 *)
  | 0x1F6u when pickBit bin 0u = 0u -> parseDCBZ bin
  | _ -> raise ParsingFailureException

let parseLWZ bin =
  let rd = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LWZ, TwoOperands(rd, mem))

let parseLWZU bin =
  let rd = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LWZU, TwoOperands(rd, mem))

let parseLBZ bin =
  let rd = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LBZ, TwoOperands(rd, mem))

let parseLBZU bin =
  let rd = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LBZU, TwoOperands(rd, mem))

let parseSTW bin =
  let rs = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.STW, TwoOperands(rs, mem))

let parseSTWU bin =
  let rs = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.STWU, TwoOperands(rs, mem))

let parseSTB bin =
  let rs = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.STB, TwoOperands(rs, mem))

let parseSTBU bin =
  let rs = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.STBU, TwoOperands(rs, mem))

let parseLHZ bin =
  let rd = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LHZ, TwoOperands(rd, mem))

let parseLHZU bin =
  let rd = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LHZU, TwoOperands(rd, mem))

let parseLHA bin =
  let rd = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LHA, TwoOperands(rd, mem))

let parseLHAU bin =
  let rd = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LHAU, TwoOperands(rd, mem))

let parseSTH bin =
  let rs = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.STH, TwoOperands(rs, mem))

let parseSTHU bin =
  let rs = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.STHU, TwoOperands(rs, mem))

let parseLMW bin =
  let rd = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LMW, TwoOperands(rd, mem))

let parseSTMW bin =
  let rs = getRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.STMW, TwoOperands(rs, mem))

let parseLFS bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LFS, TwoOperands(frd, mem))

let parseLFSU bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LFSU, TwoOperands(frd, mem))

let parseLFD bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LFD, TwoOperands(frd, mem))

let parseLFDU bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LFDU, TwoOperands(frd, mem))

let parseSTFS bin =
  let frs = getFPRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.STFS, TwoOperands(frs, mem))

let parseSTFSU bin =
  let frs = getFPRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.STFSU, TwoOperands(frs, mem))

let parseSTFD bin =
  let frs = getFPRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.STFD, TwoOperands(frs, mem))

let parseSTFDU bin =
  let frs = getFPRegister (extract bin 25u 21u) |> OprReg
  let ra = getRegister (extract bin 20u 16u)
  let d = extract bin 15u 0u |> uint64
  let value = signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.STFDU, TwoOperands(frs, mem))

let parseFDIVSx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (extract bin 15u 11u) |> OprReg
  match pickBit bin 0u with
  | 0b0u -> struct (Op.FDIVS, ThreeOperands (frd, fra, frb))
  | _ (* 1 *) -> struct (Op.FDIVSdot, ThreeOperands (frd, fra, frb))

let parseFSUBSx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (extract bin 15u 11u) |> OprReg
  match pickBit bin 0u with
  | 0b0u -> struct (Op.FSUBS, ThreeOperands (frd, fra, frb))
  | _ (* 1 *) -> struct (Op.FSUBSdot, ThreeOperands (frd, fra, frb))

let parseFADDSx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (extract bin 15u 11u) |> OprReg
  match pickBit bin 0u with
  | 0b0u -> struct (Op.FADDS, ThreeOperands (frd, fra, frb))
  | _ (* 1 *) -> struct (Op.FADDSdot, ThreeOperands (frd, fra, frb))

let parseFSQRTSx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (extract bin 15u 11u) |> OprReg
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 16u = 0u ->
    struct (Op.FSQRTS, TwoOperands (frd, frb))
  | 0b1u when extract bin 20u 16u = 0u ->
    struct (Op.FSQRTSdot, TwoOperands (frd, frb))
  | _ -> raise ParsingFailureException

let parseFRESx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (extract bin 15u 11u) |> OprReg
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 16u = 0u ->
    struct (Op.FRES, TwoOperands (frd, frb))
  | 0b1u when extract bin 20u 16u = 0u ->
    struct (Op.FRESdot, TwoOperands (frd, frb))
  | _ -> raise ParsingFailureException

let parseFMULSx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (extract bin 20u 16u) |> OprReg
  let frc = getFPRegister (extract bin 10u 6u) |> OprReg
  match pickBit bin 0u with
  | 0b0u when extract bin 15u 11u = 0u ->
    struct (Op.FMULS, ThreeOperands (frd, fra, frc))
  | 0b1u when extract bin 15u 11u = 0u ->
    struct (Op.FMULSdot, ThreeOperands (frd, fra, frc))
  | _ -> raise ParsingFailureException

let parseFMSUBSx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (extract bin 15u 11u) |> OprReg
  let frc = getFPRegister (extract bin 10u 6u) |> OprReg
  match pickBit bin 0u with
  | 0b0u -> struct (Op.FMSUBS, FourOperands (frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FMSUBSdot, FourOperands (frd, fra, frc, frb))

let parseFMADDSx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (extract bin 15u 11u) |> OprReg
  let frc = getFPRegister (extract bin 10u 6u) |> OprReg
  match pickBit bin 0u with
  | 0b0u -> struct (Op.FMADDS, FourOperands (frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FMADDSdot, FourOperands (frd, fra, frc, frb))

let parseFNMSUBSx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (extract bin 15u 11u) |> OprReg
  let frc = getFPRegister (extract bin 10u 6u) |> OprReg
  match pickBit bin 0u with
  | 0b0u -> struct (Op.FNMSUBS, FourOperands (frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FNMSUBSdot, FourOperands (frd, fra, frc, frb))

let parseFNMADDSx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (extract bin 15u 11u) |> OprReg
  let frc = getFPRegister (extract bin 10u 6u) |> OprReg
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
    let crfd = getCondRegister (extract bin 25u 23u) |> OprReg
    let fra = getFPRegister (extract bin 20u 16u) |> OprReg
    let frb = getFPRegister (extract bin 15u 11u) |> OprReg
    struct (Op.FCMPU, ThreeOperands (crfd, fra, frb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseFRSPx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (extract bin 15u 11u) |> OprReg
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 16u = 0u ->
    struct (Op.FRSP, TwoOperands (frd, frb))
  | 0b1u when extract bin 20u 16u = 0u ->
    struct (Op.FRSPdot, TwoOperands (frd, frb))
  | _ -> raise ParsingFailureException

let parseFCTIWx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (extract bin 15u 11u) |> OprReg
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 16u = 0u ->
    struct (Op.FCTIW, TwoOperands (frd, frb))
  | 0b1u when extract bin 20u 16u = 0u ->
    struct (Op.FCTIWdot, TwoOperands (frd, frb))
  | _ -> raise ParsingFailureException

let parseFCTIWZx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (extract bin 15u 11u) |> OprReg
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 16u = 0u ->
    struct (Op.FCTIWZ, TwoOperands (frd, frb))
  | 0b1u when extract bin 20u 16u = 0u ->
    struct (Op.FCTIWZdot, TwoOperands (frd, frb))
  | _ -> raise ParsingFailureException

let parseFDIVx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (extract bin 15u 11u) |> OprReg
  match pickBit bin 0u with
  | 0b0u -> struct (Op.FDIV, ThreeOperands (frd, fra, frb))
  | _ (* 1 *) -> struct (Op.FDIVdot, ThreeOperands (frd, fra, frb))

let parseFSUBx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (extract bin 15u 11u) |> OprReg
  match pickBit bin 0u with
  | 0b0u -> struct (Op.FSUB, ThreeOperands (frd, fra, frb))
  | _ (* 1 *) -> struct (Op.FSUBdot, ThreeOperands (frd, fra, frb))

let parseFADDx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (extract bin 15u 11u) |> OprReg
  match pickBit bin 0u with
  | 0b0u -> struct (Op.FADD, ThreeOperands (frd, fra, frb))
  | _ (* 1 *) -> struct (Op.FADDdot, ThreeOperands (frd, fra, frb))

let parseFSQRTx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (extract bin 15u 11u) |> OprReg
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 16u = 0u ->
    struct (Op.FSQRT, TwoOperands (frd, frb))
  | 0b1u when extract bin 20u 16u = 0u ->
    struct (Op.FSQRTdot, TwoOperands (frd, frb))
  | _ -> raise ParsingFailureException

let parseFSELx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (extract bin 15u 11u) |> OprReg
  let frc = getFPRegister (extract bin 10u 6u) |> OprReg
  match pickBit bin 0u with
  | 0b0u -> struct (Op.FSEL, FourOperands (frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FSELdot, FourOperands (frd, fra, frc, frb))

let parseFMULx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (extract bin 20u 16u) |> OprReg
  let frc = getFPRegister (extract bin 10u 6u) |> OprReg
  match pickBit bin 0u with
  | 0b0u when extract bin 15u 11u = 0u ->
    struct (Op.FMUL, ThreeOperands (frd, fra, frc))
  | 0b1u when extract bin 15u 11u = 0u ->
    struct (Op.FMULdot, ThreeOperands (frd, fra, frc))
  | _ -> raise ParsingFailureException

let parseFRSQRTEx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (extract bin 15u 11u) |> OprReg
  match pickBit bin 0u with
  | 0b0u when concat (extract bin 20u 16u) (extract bin 10u 6u) 5 = 0u ->
    struct (Op.FRSQRTE, TwoOperands (frd, frb))
  | 0b1u when extract bin 15u 11u = 0u ->
    struct (Op.FRSQRTEdot, TwoOperands (frd, frb))
  | _ -> raise ParsingFailureException

let parseFMSUBx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (extract bin 15u 11u) |> OprReg
  let frc = getFPRegister (extract bin 10u 6u) |> OprReg
  match pickBit bin 0u with
  | 0b0u -> struct (Op.FMSUB, FourOperands (frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FMSUBdot, FourOperands (frd, fra, frc, frb))

let parseFMADDx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (extract bin 15u 11u) |> OprReg
  let frc = getFPRegister (extract bin 10u 6u) |> OprReg
  match pickBit bin 0u with
  | 0b0u -> struct (Op.FMADD, FourOperands (frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FMADDdot, FourOperands (frd, fra, frc, frb))

let parseFNMSUBx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (extract bin 15u 11u) |> OprReg
  let frc = getFPRegister (extract bin 10u 6u) |> OprReg
  match pickBit bin 0u with
  | 0b0u -> struct (Op.FNMSUB, FourOperands (frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FNMSUBdot, FourOperands (frd, fra, frc, frb))

let parseFNMADDx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (extract bin 15u 11u) |> OprReg
  let frc = getFPRegister (extract bin 10u 6u) |> OprReg
  match pickBit bin 0u with
  | 0b0u -> struct (Op.FNMADD, FourOperands (frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FNMADDdot, FourOperands (frd, fra, frc, frb))

let parseFCMPO bin =
  match pickBit bin 0u with
  | 0b0u when extract bin 22u 21u = 0u ->
    let crfd = getCondRegister (extract bin 25u 23u) |> OprReg
    let fra = getFPRegister (extract bin 20u 16u) |> OprReg
    let frb = getFPRegister (extract bin 15u 11u) |> OprReg
    struct (Op.FCMPO, ThreeOperands (crfd, fra, frb))
  | _ (* 1 *) -> raise ParsingFailureException

let parseMTFSB1x bin =
  let crbd = getFPSCRBit (extract bin 25u 21u)
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 11u = 0u ->
    (* FIXME: FPSCRegister *)
    struct (Op.MTFSB1, OneOperand crbd)
  | 0b1u when extract bin 20u 11u = 0u ->
    (* FIXME: FPSCRegister *)
    struct (Op.MTFSB1dot, OneOperand crbd)
  | _ -> raise ParsingFailureException

let parseFNEGx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (extract bin 15u 11u) |> OprReg
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 11u = 0u ->
    struct (Op.FNEG, TwoOperands (frd, frb))
  | 0b1u when extract bin 20u 11u = 0u ->
    struct (Op.FNEGdot, TwoOperands (frd, frb))
  | _ -> raise ParsingFailureException

let parseMCRFS bin =
  match pickBit bin 0u with
  | 0b0u when concat (extract bin 22u 21u) (extract bin 17u 11u) 2 = 0u ->
    let crfd = getCondRegister (extract bin 25u 23u) |> OprReg
    let crfs = getCondRegister (extract bin 20u 18u) |> OprReg
    struct (Op.MCRFS, TwoOperands (crfd, crfs))
  | _ (* 1 *) -> raise ParsingFailureException

let parseMTFSB0x bin =
  let crbd = getFPSCRBit (extract bin 25u 21u)
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 11u = 0u ->
    (* FIXME: FPSCRegister *)
    struct (Op.MTFSB0, OneOperand crbd)
  | 0b1u when extract bin 20u 11u = 0u ->
    (* FIXME: FPSCRegister *)
    struct (Op.MTFSB0dot, OneOperand crbd)
  | _ -> raise ParsingFailureException

let parseFMRx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (extract bin 15u 11u) |> OprReg
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 16u = 0u ->
    struct (Op.FMR, TwoOperands (frd, frb))
  | 0b1u when extract bin 20u 16u = 0u ->
    struct (Op.FMRdot, TwoOperands (frd, frb))
  | _ -> raise ParsingFailureException

let parseMTFSFIx bin =
  let crfd = getCondRegister (extract bin 25u 23u) |> OprReg
  let imm = extract bin 15u 12u |> uint64 |> OprImm
  match pickBit bin 0u with
  | 0b0u when concat (extract bin 22u 16u) (pickBit bin 11u) 7 = 0u ->
    struct (Op.MTFSFI, TwoOperands (crfd, imm))
  | 0b1u when concat (extract bin 22u 16u) (pickBit bin 11u) 7 = 0u ->
    struct (Op.MTFSFIdot, TwoOperands (crfd, imm))
  | _ -> raise ParsingFailureException

let parseFNABSx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (extract bin 15u 11u) |> OprReg
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 16u = 0u ->
    struct (Op.FNABS, TwoOperands (frd, frb))
  | 0b1u when extract bin 20u 16u = 0u ->
    struct (Op.FNABSdot, TwoOperands (frd, frb))
  | _ -> raise ParsingFailureException

let parseFABSx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (extract bin 15u 11u) |> OprReg
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 16u = 0u ->
    struct (Op.FABS, TwoOperands (frd, frb))
  | 0b1u when extract bin 20u 16u = 0u ->
    struct (Op.FABSdot, TwoOperands (frd, frb))
  | _ -> raise ParsingFailureException

let parseMFFSx bin =
  let frd = getFPRegister (extract bin 25u 21u) |> OprReg
  match pickBit bin 0u with
  | 0b0u when extract bin 20u 11u = 0u ->
    struct (Op.MFFS, OneOperand frd)
  | 0b1u when extract bin 20u 11u = 0u ->
    struct (Op.MFFSdot, OneOperand frd)
  | _ -> raise ParsingFailureException

let parseMTFSFx bin =
  let fm = getFM (extract bin 24u 17u)
  let frb = getFPRegister (extract bin 15u 11u) |> OprReg
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
    (* FIXME: FPSCRegister *)
    match extract bin 10u 6u with
    | 0x1u -> parseMTFSB1x bin
    (* FIXME: FPSCRegister *)
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

let private parseInstruction bin addr =
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
  | 0x12u -> parseBx bin addr
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
  let struct (opcode, operands) = parseInstruction bin addr
  let insInfo =
    { Address = addr
      NumBytes = 4u
      Opcode = opcode
      Operands = operands
      OperationSize = 32<rt>
      EffectiveAddress = 0UL }
  PPC32Instruction (addr, 4u, insInfo)

// vim: set tw=80 sts=2 sw=2:
