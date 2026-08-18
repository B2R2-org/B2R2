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

module internal B2R2.FrontEnd.PPC.ParsingMain

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.ParsingUtils
open B2R2.FrontEnd.PPC.OperandHelper

/// Sign-extends a 16-bit signed-immediate field to the guest's register width,
/// so a negative immediate reads as one on either word size.
let private simm16 bitLen bin =
  Bits.extract bin 15u 0u |> uint64 |> Bits.signExtend 16 bitLen |> uint64

let parseTWI bitLen bin =
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let value = simm16 bitLen bin |> OprImm
  match Bits.extract bin 25u 21u with
  (* twlgti ra,value = twi 1,ra,value *)
  | 1u ->
    struct (Op.TWLGTI, TwoOperands(ra, value))
  (* twllti ra,value = twi 2,ra,value *)
  | 2u ->
    struct (Op.TWLLTI, TwoOperands(ra, value))
  (* tweqi ra,value = twi 4,ra,value *)
  | 4u ->
    struct (Op.TWEQI, TwoOperands(ra, value))
  (* twlnli ra,value = twi 5,ra,value *)
  | 5u ->
    struct (Op.TWLNLI, TwoOperands(ra, value))
  (* twllei ra,value = twi 6,ra,value *)
  | 6u ->
    struct (Op.TWLLEI, TwoOperands(ra, value))
  (* twgti ra,value = twi 8,ra,value *)
  | 8u ->
    struct (Op.TWGTI, TwoOperands(ra, value))
  (* twgei ra,value = twi 12,ra,value *)
  | 12u ->
    struct (Op.TWGEI, TwoOperands(ra, value))
  (* twlti ra,value = twi 16,ra,value *)
  | 16u ->
    struct (Op.TWLTI, TwoOperands(ra, value))
  (* twlei ra,value = twi 20,ra,value *)
  | 20u ->
    struct (Op.TWLEI, TwoOperands(ra, value))
  (* twnei ra,value = twi 24,ra,value *)
  | 24u ->
    struct (Op.TWNEI, TwoOperands(ra, value))
  (* twllei ra,value = twlngi ra, value = twi 6,ra,value
     twgei ra,value = twlgei ra, value = twnli ra, value = twi 12,ra,value
     twlei ra,value = twngi ra, value = twi 20,ra,value *)
  | _ ->
    let tO = Bits.extract bin 25u 21u |> uint64 |> OprImm
    struct (Op.TWI, ThreeOperands(tO, ra, value))

let parseMULLI bitLen bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let value = simm16 bitLen bin |> OprImm
  struct (Op.MULLI, ThreeOperands(rd, ra, value))

let parseSUBFIC bitLen bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let value = simm16 bitLen bin |> OprImm
  struct (Op.SUBFIC, ThreeOperands(rd, ra, value))

let parseCMPLI bin =
  match Bits.pick bin 22u with
  | 0b0u ->
    let crfd = getCondRegister (Bits.extract bin 25u 23u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let uimm = Bits.extract bin 15u 0u |> uint64 |> OprImm
    match Bits.pick bin 21u with
    (* cmplwi crfd,ra,uimm = cmpli crfd,0,ra,uimm *)
    | 0b0u -> struct (Op.CMPLWI, ThreeOperands(crfd, ra, uimm))
    (* cmpldi crfd,ra,uimm = cmpli crfd,1,ra,uimm *)
    | _ -> struct (Op.CMPLDI, ThreeOperands(crfd, ra, uimm))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseCMPI bitLen bin =
  match Bits.pick bin 22u with
  | 0b0u ->
    let crfd = getCondRegister (Bits.extract bin 25u 23u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let value = simm16 bitLen bin |> OprImm
    match Bits.pick bin 21u with
    (* cmpwi crfd,ra,simm = cmpi crfd,0,ra,simm *)
    | 0b0u -> struct (Op.CMPWI, ThreeOperands(crfd, ra, value))
    (* cmpdi crfd,ra,simm = cmpi crfd,1,ra,simm *)
    | _ -> struct (Op.CMPDI, ThreeOperands(crfd, ra, value))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseADDIC bitLen bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let value = simm16 bitLen bin |> OprImm
  (* subic rd,ra,value = addic rd,ra,-value *)
  struct (Op.ADDIC, ThreeOperands(rd, ra, value))

let parseADDICdot bitLen bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let value = simm16 bitLen bin |> OprImm
  (* subic. rd,ra,value = addic. rd,ra,-value *)
  struct (Op.ADDICdot, ThreeOperands(rd, ra, value))

let parseADDI bitLen bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let value = simm16 bitLen bin |> OprImm
  match Bits.extract bin 20u 16u with
  | 0b0u ->
    struct (Op.LI, TwoOperands(rd, value))
  (* subi rd,ra,value = addi rd,ra,-value *)
  | _ ->
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    struct (Op.ADDI, ThreeOperands(rd, ra, value))

let parseADDIS bitLen bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let value = simm16 bitLen bin |> OprImm
  match Bits.extract bin 20u 16u with
  | 0b0u ->
    struct (Op.LIS, TwoOperands(rd, value))
  (* subis rd,ra,value = addis rd,ra,-value *)
  | _ ->
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    struct (Op.ADDIS, ThreeOperands(rd, ra, value))

let parseBCx bitLen bin =
  let idx = (Bits.extract bin 1u 0u |> int) (* opcode *)
  let bd = Bits.extract bin 15u 2u <<< 2 |> uint64
  let value = Bits.signExtend 16 bitLen bd |> uint64 |> OprAddr
  let op = [| Op.BC; Op.BCL; Op.BCA; Op.BCLA |].[idx]
  let bo = Bits.extract bin 25u 21u |> uint64 |> OprImm
  struct (op, ThreeOperands(bo, OprBI(Bits.extract bin 20u 16u), value))

let parseSC bin =
  match Bits.pick bin 1u with
  | 0b1u -> struct (Op.SC, NoOperand)
  | _ -> raise ParsingFailureException

let parseBx bitLen bin addr =
  let li = Bits.extract bin 25u 2u |> uint64
  let signExtended = Bits.signExtend 26 bitLen (li <<< 2) |> uint64
  let mask = System.UInt64.MaxValue >>> (64 - bitLen)
  match Bits.extract bin 1u 0u (* AA:LK *) with
  | 0b00u ->
    let value = (addr + signExtended) &&& mask |> OprImm
    struct (Op.B, OneOperand value)
  | 0b01u ->
    let value = (addr + signExtended) &&& mask |> OprImm
    struct (Op.BL, OneOperand value)
  | 0b10u ->
    let value = signExtended |> OprImm
    struct (Op.BA, OneOperand value)
  | _ (* 11 *) ->
    let value = signExtended |> OprImm
    struct (Op.BLA, OneOperand value)

let parseMCRF bin =
  match Bits.pick bin 0u with
  | 0b0u when Bits.concat (Bits.extract bin 22u 21u)
                          (Bits.extract bin 17u 11u)
                          2 = 0u ->
    let crfd = getCondRegister (Bits.extract bin 25u 23u) |> OprReg
    let crfs = getCondRegister (Bits.extract bin 20u 18u) |> OprReg
    struct (Op.MCRF, TwoOperands(crfd, crfs))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseBCLRx bin =
  if Bits.extract bin 15u 11u <> 0u then
    raise ParsingFailureException
  else
    let idx = Bits.pick bin 0u |> int (* opcode *)
    let op = [| Op.BCLR; Op.BCLRL |].[idx]
    let bo = Bits.extract bin 25u 21u |> uint64 |> OprImm
    struct (op, TwoOperands(bo, OprBI(Bits.extract bin 20u 16u)))

let parseCRNOR bin =
  match Bits.pick bin 0u with
  | 0b0u ->
    let crbd = Bits.extract bin 25u 21u |> OprBI
    let crba = Bits.extract bin 20u 16u |> OprBI
    (* crnot crbd,crba = crnor crbd,crba,crba *)
    if Bits.extract bin 20u 16u = Bits.extract bin 15u 11u then
      struct (Op.CRNOT, TwoOperands(crbd, crba))
    else
      let crbb = Bits.extract bin 15u 11u |> OprBI
      struct (Op.CRNOR, ThreeOperands(crbd, crba, crbb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseRFI bin =
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 25u 11u = 0u -> struct (Op.RFI, NoOperand)
  | _ (* 1 *) -> raise ParsingFailureException

let parseCRANDC bin =
  match Bits.pick bin 0u with
  | 0b0u ->
    let crbd = Bits.extract bin 25u 21u |> OprBI
    let crba = Bits.extract bin 20u 16u |> OprBI
    let crbb = Bits.extract bin 15u 11u |> OprBI
    struct (Op.CRANDC, ThreeOperands(crbd, crba, crbb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseISYNC bin =
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 25u 11u = 0u -> struct (Op.ISYNC, NoOperand)
  | _ (* 1 *) -> raise ParsingFailureException

let parseCRXOR bin =
  match Bits.pick bin 0u with
  | 0b0u ->
    let crbd = Bits.extract bin 25u 21u |> OprBI
    let crba = Bits.extract bin 20u 16u |> OprBI
    let crbb = Bits.extract bin 15u 11u |> OprBI
    if (crbd = crba) && (crbd = crbb) then struct (Op.CRCLR, OneOperand crbd)
    else struct (Op.CRXOR, ThreeOperands(crbd, crba, crbb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseCRNAND bin =
  match Bits.pick bin 0u with
  | 0b0u ->
    let crbd = Bits.extract bin 25u 21u |> OprBI
    let crba = Bits.extract bin 20u 16u |> OprBI
    let crbb = Bits.extract bin 15u 11u |> OprBI
    struct (Op.CRNAND, ThreeOperands(crbd, crba, crbb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseCRAND bin =
  match Bits.pick bin 0u with
  | 0b0u ->
    let crbd = Bits.extract bin 25u 21u |> OprBI
    let crba = Bits.extract bin 20u 16u |> OprBI
    let crbb = Bits.extract bin 15u 11u |> OprBI
    struct (Op.CRAND, ThreeOperands(crbd, crba, crbb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseCREQV bin =
  match Bits.pick bin 0u with
  | 0b0u ->
    let crbd = Bits.extract bin 25u 21u |> OprBI
    (* crset crbd = creqv crbd,crbd,crbd *)
    if Bits.extract bin 25u 21u = Bits.extract bin 20u 16u then
      if Bits.extract bin 20u 16u = Bits.extract bin 15u 11u then
        struct (Op.CRSET, OneOperand crbd)
      else
        let crba = Bits.extract bin 20u 16u |> OprBI
        let crbb = Bits.extract bin 15u 11u |> OprBI
        struct (Op.CREQV, ThreeOperands(crbd, crba, crbb))
    else
      let crba = Bits.extract bin 20u 16u |> OprBI
      let crbb = Bits.extract bin 15u 11u |> OprBI
      struct (Op.CREQV, ThreeOperands(crbd, crba, crbb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseCRORC bin =
  match Bits.pick bin 0u with
  | 0b0u ->
    let crbd = Bits.extract bin 25u 21u |> OprBI
    let crba = Bits.extract bin 20u 16u |> OprBI
    let crbb = Bits.extract bin 15u 11u |> OprBI
    struct (Op.CRORC, ThreeOperands(crbd, crba, crbb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseCROR bin =
  match Bits.pick bin 0u with
  | 0b0u ->
    let crbd = Bits.extract bin 25u 21u |> OprBI
    let crba = Bits.extract bin 20u 16u |> OprBI
    (* crmove crbd,crba = cror crbd,crba,crba *)
    if Bits.extract bin 20u 16u = Bits.extract bin 15u 11u then
      struct (Op.CRMOVE, TwoOperands(crbd, crba))
    else
      let crbb = Bits.extract bin 15u 11u |> OprBI
      struct (Op.CROR, ThreeOperands(crbd, crba, crbb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseBCCTRx bin =
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 15u 11u = 0u ->
    let bo = Bits.extract bin 25u 21u |> uint64 |> OprImm
    struct (Op.BCCTR, TwoOperands(bo, OprBI(Bits.extract bin 20u 16u)))
  | 0b1u when Bits.extract bin 15u 11u = 0u ->
    let bo = Bits.extract bin 25u 21u |> uint64 |> OprImm
    struct (Op.BCCTRL, TwoOperands(bo, OprBI(Bits.extract bin 20u 16u)))
  | _ ->
    raise ParsingFailureException

let parse13 bin =
  match Bits.extract bin 10u 1u with
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
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let sh = Bits.extract bin 15u 11u |> uint64 |> OprImm
  let mb = Bits.extract bin 10u 6u |> uint64 |> OprImm
  let me = Bits.extract bin 5u 1u |> uint64 |> OprImm
  match Bits.pick bin 0u with
  (* inslwi ra,rs,n,b = rlwimi ra,rs,32-b,b,b+n-1
     insrwi ra,rs,n,b (n>0) = rlwimi ra,rs,32-(b+n),b,(b+n)-1 *)
  | 0b0u -> struct (Op.RLWIMI, FiveOperands(ra, rs, sh, mb, me))
  | _ (* 1 *) -> struct (Op.RLWIMIdot, FiveOperands(ra, rs, sh, mb, me))

let parseRLWINMx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u ->
    let sh = Bits.extract bin 15u 11u |> uint64 |> OprImm
    let mb = Bits.extract bin 10u 6u |> uint64 |> OprImm
    let me = Bits.extract bin 5u 1u |> uint64 |> OprImm
    struct (Op.RLWINM, FiveOperands(ra, rs, sh, mb, me))
  | _ (* 1 *) ->
    let sh = Bits.extract bin 15u 11u |> uint64 |> OprImm
    let mb = Bits.extract bin 10u 6u |> uint64 |> OprImm
    let me = Bits.extract bin 5u 1u |> uint64 |> OprImm
    struct (Op.RLWINMdot, FiveOperands(ra, rs, sh, mb, me))

let parseRLWNMx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u ->
    match Bits.extract bin 10u 1u with
    (* rotlw ra,rs,rb = rlwnm ra,rs,rb,mb,me *)
    | 0x1Fu ->
      struct (Op.ROTLW, ThreeOperands(ra, rs, rb))
    | _ ->
      let mb = Bits.extract bin 10u 6u |> uint64 |> OprImm
      let me = Bits.extract bin 5u 1u |> uint64 |> OprImm
      struct (Op.RLWNM, FiveOperands(ra, rs, rb, mb, me))
  | _ (* 1 *) ->
    let mb = Bits.extract bin 10u 6u |> uint64 |> OprImm
    let me = Bits.extract bin 5u 1u |> uint64 |> OprImm
    struct (Op.RLWNMdot, FiveOperands(ra, rs, rb, mb, me))

let parseORI bin =
  match Bits.extract bin 25u 0u with
  (* nop = ori 0,0,0 *)
  | 0b0u ->
    struct (Op.NOP, NoOperand)
  | _ ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let uimm = Bits.extract bin 15u 0u |> uint64 |> OprImm
    struct (Op.ORI, ThreeOperands(ra, rs, uimm))

let parseORIS bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let uimm = Bits.extract bin 15u 0u |> uint64 |> OprImm
  struct (Op.ORIS, ThreeOperands(ra, rs, uimm))

let parseXORI bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let uimm = Bits.extract bin 15u 0u |> uint64 |> OprImm
  struct (Op.XORI, ThreeOperands(ra, rs, uimm))

let parseXORIS bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let uimm = Bits.extract bin 15u 0u |> uint64 |> OprImm
  struct (Op.XORIS, ThreeOperands(ra, rs, uimm))

let parseANDIdot bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let uimm = Bits.extract bin 15u 0u |> uint64 |> OprImm
  struct (Op.ANDIdot, ThreeOperands(ra, rs, uimm))

let parseANDISdot bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let uimm = Bits.extract bin 15u 0u |> uint64 |> OprImm
  struct (Op.ANDISdot, ThreeOperands(ra, rs, uimm))

let parseCMPandMCRXR bin =
  match Bits.pick bin 10u with
  | 0b0u when Bits.pick bin 22u = 0u ->
    let crfd = getCondRegister (Bits.extract bin 25u 23u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    match Bits.pick bin 21u with
    (* cmpw crfd,ra,rb = cmp crfd,0,ra,rb *)
    | 0b0u -> struct (Op.CMPW, ThreeOperands(crfd, ra, rb))
    (* cmpd crfd,ra,rb = cmp crfd,1,ra,rb *)
    | _ (* 1 *) -> struct (Op.CMPD, ThreeOperands(crfd, ra, rb))
  | 0b1u when Bits.extract bin 22u 11u = 0u ->
    let crfd = getCondRegister (Bits.extract bin 25u 23u) |> OprReg
    struct (Op.MCRXR, OneOperand(crfd))
  | _ ->
    raise ParsingFailureException

let parseTW bin =
  match Bits.pick bin 10u with
  | 0b0u ->
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    match Bits.extract bin 25u 21u with
    (* twlgt ra,rb = tw 1,ra,rb *)
    | 1u ->
      struct (Op.TWLGT, TwoOperands(ra, rb))
    (* twllt ra,rb = tw 2,ra,rb *)
    | 2u ->
      struct (Op.TWLLT, TwoOperands(ra, rb))
    (* tweq ra,rb = tw 4,ra,rb *)
    | 4u ->
      struct (Op.TWEQ, TwoOperands(ra, rb))
    (* twlnl ra,rb = tw 5,ra,rb *)
    | 5u ->
      struct (Op.TWLNL, TwoOperands(ra, rb))
    (* twllel ra,rb = tw 6,ra,rb *)
    | 6u ->
      struct (Op.TWLLE, TwoOperands(ra, rb))
    (* twgt ra,rb = tw 8,ra,rb *)
    | 8u ->
      struct (Op.TWGT, TwoOperands(ra, rb))
    (* twge ra,rb = tw 12,ra,rb *)
    | 12u ->
      struct (Op.TWGE, TwoOperands(ra, rb))
    (* twlt ra,rb = tw 16,ra,rb *)
    | 16u ->
      struct (Op.TWLT, TwoOperands(ra, rb))
    (* twle ra,rb = tw 20,ra,rb *)
    | 20u ->
      struct (Op.TWLE, TwoOperands(ra, rb))
    (* twne ra,rb = tw 24,ra,rb *)
    | 24u ->
      struct (Op.TWNE, TwoOperands(ra, rb))
    | 31u when Bits.extract bin 20u 11u = 0u ->
      struct (Op.TRAP, NoOperand)
    | _ ->
      let tO = Bits.extract bin 25u 21u |> uint64 |> OprImm
      struct (Op.TW, ThreeOperands(tO, ra, rb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseSUBFCx bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* OE:RC *) with
  (* subc rd,ra,rb = subfc rd,rb,ra *)
  | 0b00u -> struct (Op.SUBFC, ThreeOperands(rd, ra, rb))
  | 0b01u -> struct (Op.SUBFCdot, ThreeOperands(rd, ra, rb))
  | 0b10u -> struct (Op.SUBFCO, ThreeOperands(rd, ra, rb))
  | _ (* 11 *) -> struct (Op.SUBFCOdot, ThreeOperands(rd, ra, rb))

let parseADDCx bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* OE:RC *) with
  | 0b00u -> struct (Op.ADDC, ThreeOperands(rd, ra, rb))
  | 0b01u -> struct (Op.ADDCdot, ThreeOperands(rd, ra, rb))
  | 0b10u -> struct (Op.ADDCO, ThreeOperands(rd, ra, rb))
  | _ (* 11 *) -> struct (Op.ADDCOdot, ThreeOperands(rd, ra, rb))

let parseMULHWUx bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.MULHWU, ThreeOperands(rd, ra, rb))
  | _ (* 1 *) -> struct (Op.MULHWUdot, ThreeOperands(rd, ra, rb))

let parseMFCR bin =
  match Bits.pick bin 10u with
  | 0b0u when Bits.extract bin 20u 11u = 0u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.MFCR, OneOperand(rd))
  (* mfocrf rd,crm names one CR field with a one-hot mask; every other field of
     rd is left undefined, so reading the whole CR satisfies it. *)
  | 0b0u when Bits.pick bin 20u = 1u && Bits.pick bin 11u = 0u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.MFOCRF, OneOperand(rd))
  | _ ->
    raise ParsingFailureException

/// lwarx, whose last bit is the EH hint rather than a reserved bit: it only
/// tells the processor how the reservation is expected to be used, so both
/// values lift the same way.
let parseLWARX bin =
  match Bits.pick bin 10u with
  | 0b0u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.LWARX, ThreeOperands(rd, ra, rb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseLSWX bin =
  match Bits.pick bin 10u with
  | 0b1u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.LSWX, ThreeOperands(rd, ra, rb))
  | _ (* 0 *) ->
    raise ParsingFailureException

let parseLWBRX bin =
  match Bits.pick bin 10u with
  | 0b1u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.LWBRX, ThreeOperands(rd, ra, rb))
  | _ (* 0 *) ->
    raise ParsingFailureException

let parseLWZXandLFSX bin =
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 10u with
  | 0b0u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.LWZX, ThreeOperands(rd, ra, rb))
  | _ (* 1 *) ->
    let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.LFSX, ThreeOperands(frd, ra, rb))

let parseSLWxandSRWx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* 0:RC *) with
  | 0b00u -> struct (Op.SLW, ThreeOperands(ra, rs, rb))
  | 0b01u -> struct (Op.SLWdot, ThreeOperands(ra, rs, rb))
  | 0b10u -> struct (Op.SRW, ThreeOperands(ra, rs, rb))
  | _ (* 11 *) -> struct (Op.SRWdot, ThreeOperands(ra, rs, rb))

let parseCNTLZWx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* 0:RC *) with
  | 0b00u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.CNTLZW, TwoOperands(ra, rs))
  | 0b01u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.CNTLZWdot, TwoOperands(ra, rs))
  | _ (* 1x *) ->
    raise ParsingFailureException

let parseANDx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* 0:RC *) with
  | 0b00u -> struct (Op.AND, ThreeOperands(ra, rs, rb))
  | 0b01u -> struct (Op.ANDdot, ThreeOperands(ra, rs, rb))
  | _ (* 1x *) -> raise ParsingFailureException

let parseCMPL bin =
  match Bits.pick bin 10u with
  | 0b0u when Bits.pick bin 22u = 0u ->
    let crfd = getCondRegister (Bits.extract bin 25u 23u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    match Bits.pick bin 21u with
    (* cmplw crfd,ra,rb = cmpl crfd,0,ra,rb *)
    | 0b0u -> struct (Op.CMPLW, ThreeOperands(crfd, ra, rb))
    (* cmpld crfd,ra,rb = cmpl crfd,1,ra,rb *)
    | _ (* 1 *) -> struct (Op.CMPLD, ThreeOperands(crfd, ra, rb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseSUBFx bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* OE:RC *) with
  (* sub rd,rb,ra = subf rd,ra,rb *)
  | 0b00u -> struct (Op.SUBF, ThreeOperands(rd, ra, rb))
  | 0b01u -> struct (Op.SUBFdot, ThreeOperands(rd, ra, rb))
  | 0b10u -> struct (Op.SUBFO, ThreeOperands(rd, ra, rb))
  | _ (* 11 *) -> struct (Op.SUBFOdot, ThreeOperands(rd, ra, rb))

let parseDCBSTandTLBSYNC bin =
  match Bits.pick bin 10u with
  | 0b0u when Bits.extract bin 25u 21u = 0u ->
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.DCBST, TwoOperands(ra, rb))
  | 0b1u when Bits.extract bin 25u 11u = 0u ->
    struct (Op.TLBSYNC, NoOperand)
  | _ ->
    raise ParsingFailureException

let parseLWZUXandLFSUX bin =
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 10u with
  | 0b0u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.LWZUX, ThreeOperands(rd, ra, rb))
  | _ (* 1 *) ->
    let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.LFSUX, ThreeOperands(frd, ra, rb))

let parseANDCx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* 0:RC *) with
  | 0b00u -> struct (Op.ANDC, ThreeOperands(ra, rs, rb))
  | 0b01u -> struct (Op.ANDCdot, ThreeOperands(ra, rs, rb))
  | _ (* 1x *) -> raise ParsingFailureException

let parseMULHWx bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.MULHW, ThreeOperands(rd, ra, rb))
  | _ (* 1 *) -> struct (Op.MULHWdot, ThreeOperands(rd, ra, rb))

let parseMFMSRandMFSR bin =
  match Bits.pick bin 10u with
  | 0b0u when Bits.extract bin 20u 11u = 0u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.MFMSR, OneOperand(rd))
  | 0b1u when (Bits.concat (Bits.pick bin 20u)
                           (Bits.extract bin 15u 11u)
                           1) = 0u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    (* FIXME: SegRegister *)
    let sr = getSegRegister (Bits.extract bin 19u 16u)
    struct (Op.MFSR, TwoOperands(rd, sr))
  | _ ->
    raise ParsingFailureException

let parseLSWI bin =
  match Bits.pick bin 10u with
  | 0b1u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let nb = Bits.extract bin 15u 11u |> uint64 |> OprImm
    struct (Op.LSWI, ThreeOperands(rd, ra, nb))
  | _ (* 0 *) ->
    raise ParsingFailureException

let parseDCBFandSYNC bin =
  match Bits.pick bin 10u with
  | 0b0u when Bits.extract bin 25u 21u = 0u ->
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.DCBF, TwoOperands(ra, rb))
  | 0b1u when Bits.extract bin 25u 11u = 0u ->
    struct (Op.SYNC, NoOperand)
  | 0b1u when Bits.extract bin 25u 21u = 1u ->
    struct (Op.LWSYNC, NoOperand)
  | _ ->
    raise ParsingFailureException

let parseLBZXandLFDX bin =
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 10u with
  | 0b0u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.LBZX, ThreeOperands(rd, ra, rb))
  | _ (* 1 *) ->
    let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.LFDX, ThreeOperands(frd, ra, rb))

let parseNEGx bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* OE:RC *) with
  | 0b00u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.NEG, TwoOperands(rd, ra))
  | 0b01u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.NEGdot, TwoOperands(rd, ra))
  | 0b10u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.NEGO, TwoOperands(rd, ra))
  | 0b11u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.NEGOdot, TwoOperands(rd, ra))
  | _ ->
    raise ParsingFailureException

let parseLBZUXandLFDUX bin =
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 10u with
  | 0b0u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.LBZUX, ThreeOperands(rd, ra, rb))
  | 0b1u ->
    let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.LFDUX, ThreeOperands(frd, ra, rb))
  | _ ->
    raise ParsingFailureException

let parseNORx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* 0:RC *) with
  (* not rd,rs = nor ra,rs,rs *)
  | 0b00u -> struct (Op.NOR, ThreeOperands(ra, rs, rb))
  | 0b01u -> struct (Op.NORdot, ThreeOperands(ra, rs, rb))
  | _ (* 1x *) -> raise ParsingFailureException

let parseSUBFEx bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* OE:RC *) with
  | 0b00u -> struct (Op.SUBFE, ThreeOperands(rd, ra, rb))
  | 0b01u -> struct (Op.SUBFEdot, ThreeOperands(rd, ra, rb))
  | 0b10u -> struct (Op.SUBFEO, ThreeOperands(rd, ra, rb))
  | _ (* 11 *) -> struct (Op.SUBFEOdot, ThreeOperands(rd, ra, rb))

let parseADDEx bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* OE:RC *) with
  | 0b00u -> struct (Op.ADDE, ThreeOperands(rd, ra, rb))
  | 0b01u -> struct (Op.ADDEdot, ThreeOperands(rd, ra, rb))
  | 0b10u -> struct (Op.ADDEO, ThreeOperands(rd, ra, rb))
  | _ (* 11 *) -> struct (Op.ADDEOdot, ThreeOperands(rd, ra, rb))

let parseMTCRF bin =
  match Bits.pick bin 10u with
  (* mtcr rs = mtcrf 0xff,rs *)
  | 0b0u when Bits.concat (Bits.pick bin 20u) (Bits.pick bin 11u) 1 = 00u ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let crm = Bits.extract bin 19u 12u |> uint64 |> OprImm
    struct (Op.MTCRF, TwoOperands(crm, rs))
  (* mtocrf crm,rs writes the single CR field its one-hot mask names, which is
     what mtcrf with that same mask does. *)
  | 0b0u when Bits.pick bin 20u = 1u && Bits.pick bin 11u = 0u ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let crm = Bits.extract bin 19u 12u |> uint64 |> OprImm
    struct (Op.MTOCRF, TwoOperands(crm, rs))
  | _ ->
    raise ParsingFailureException

let parseMTMSR bin =
  match Bits.pick bin 10u with
  | 0b0u when Bits.extract bin 20u 11u = 0u ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.MFMSR, OneOperand rs)
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseMFSRIN bin =
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 with
  | 0b10u when Bits.extract bin 20u 16u = 0u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.MFSRIN, TwoOperands(rd, rb))
  | _ (* 11, 0x *) ->
    raise ParsingFailureException

let parseSTSWX bin =
  match Bits.pick bin 10u with
  | 0b1u ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.STSWX, ThreeOperands(rs, ra, rb))
  | _ (* 0 *) ->
    raise ParsingFailureException

let parseSTWCXdotandSTWBRX bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 with
  | 0b01u -> struct (Op.STWCXdot, ThreeOperands(rs, ra, rb))
  | 0b10u -> struct (Op.STWBRX, ThreeOperands(rs, ra, rb))
  | _ (* 00, 11 *) -> raise ParsingFailureException

let parseSTWXandSTFSX bin =
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 10u with
  | 0b0u ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.STWX, ThreeOperands(rs, ra, rb))
  | _ (* 1 *) ->
    let frs = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.STFSX, ThreeOperands(frs, ra, rb))

let parseSTWUXandSTFSUX bin =
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 10u with
  | 0b0u ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.STWUX, ThreeOperands(rs, ra, rb))
  | _ (* 1 *) ->
    let frs = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.STFSUX, ThreeOperands(frs, ra, rb))

let parseSUBFZEx bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* OE:RC *) with
  | 0b00u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.SUBFZE, TwoOperands(rd, ra))
  | 0b01u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.SUBFZEdot, TwoOperands(rd, ra))
  | 0b10u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.SUBFZEO, TwoOperands(rd, ra))
  | 0b11u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.SUBFZEOdot, TwoOperands(rd, ra))
  | _ ->
    raise ParsingFailureException

let parseADDZEx bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* OE:RC *) with
  | 0b00u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.ADDZE, TwoOperands(rd, ra))
  | 0b01u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.ADDZEdot, TwoOperands(rd, ra))
  | 0b10u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.ADDZEO, TwoOperands(rd, ra))
  | 0b11u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.ADDZEOdot, TwoOperands(rd, ra))
  | _ ->
    raise ParsingFailureException

let parseMTSR bin =
  match Bits.pick bin 10u with
  | 0b0u when (Bits.concat (Bits.pick bin 20u)
                           (Bits.extract bin 15u 11u)
                           1) = 0u ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    (* FIXME: SegRegister *)
    let sr = getSegRegister (Bits.extract bin 19u 16u)
    struct (Op.MTSR, TwoOperands(sr, rs))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseSTSWI bin =
  match Bits.pick bin 10u with
  | 0b1u ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let nb = Bits.extract bin 15u 11u |> uint64 |> OprImm
    struct (Op.STSWI, ThreeOperands(rs, ra, nb))
  | _ (* 0 *) ->
    raise ParsingFailureException

let parseSTBXandSTFDX bin =
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 with
  | 0b00u ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.STBX, ThreeOperands(rs, ra, rb))
  | 0b10u ->
    let frs = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.STFDX, ThreeOperands(frs, ra, rb))
  | _ (* 01, 11 *) ->
    raise ParsingFailureException

let parseSUBFMEx bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* OE:RC *) with
  | 0b00u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.SUBFME, TwoOperands(rd, ra))
  | 0b01u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.SUBFMEdot, TwoOperands(rd, ra))
  | 0b10u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.SUBFMEO, TwoOperands(rd, ra))
  | 0b11u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.SUBFMEOdot, TwoOperands(rd, ra))
  | _ ->
    raise ParsingFailureException

let parseADDMEx bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* OE:RC *) with
  | 0b00u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.ADDME, TwoOperands(rd, ra))
  | 0b01u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.ADDMEdot, TwoOperands(rd, ra))
  | 0b10u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.ADDMEO, TwoOperands(rd, ra))
  | 0b11u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.ADDMEOdot, TwoOperands(rd, ra))
  | _ ->
    raise ParsingFailureException

let parseMULLWx bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* OE:RC *) with
  | 0b00u -> struct (Op.MULLW, ThreeOperands(rd, ra, rb))
  | 0b01u -> struct (Op.MULLWdot, ThreeOperands(rd, ra, rb))
  | 0b10u -> struct (Op.MULLWO, ThreeOperands(rd, ra, rb))
  | _ (* 11 *) -> struct (Op.MULLWOdot, ThreeOperands(rd, ra, rb))

let parseMTSRIN bin =
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 with
  | 0b10u when Bits.extract bin 20u 16u = 0u ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.MTSRIN, TwoOperands(rs, rb))
  | _ (* 11, 0x *) ->
    raise ParsingFailureException

let parseDCBTSTandDCBA bin =
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 10u with
  | 0b0u when Bits.extract bin 25u 21u = 0u ->
    (* CT = 0u *)
    struct (Op.DCBTST, TwoOperands(ra, rb))
  | 0b1u when Bits.extract bin 25u 21u = 0u ->
    struct (Op.DCBA, TwoOperands(ra, rb))
  | _ ->
    raise ParsingFailureException

let parseSTBUXandSTFDUX bin =
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 with
  | 0b00u ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.STBUX, ThreeOperands(rs, ra, rb))
  | 0b10u ->
    let frs = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.STFDUX, ThreeOperands(frs, ra, rb))
  | _ (* 01, 11 *) ->
    raise ParsingFailureException

let parseADDx bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* OE:RC *) with
  | 0b00u -> struct (Op.ADD, ThreeOperands(rd, ra, rb))
  | 0b01u -> struct (Op.ADDdot, ThreeOperands(rd, ra, rb))
  | 0b10u -> struct (Op.ADDO, ThreeOperands(rd, ra, rb))
  | _ (* 11 *) -> struct (Op.ADDOdot, ThreeOperands(rd, ra, rb))

let parseDCBTandLHBRX bin =
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 10u with
  | 0b0u when Bits.extract bin 25u 21u = 0u ->
    (* CT = 0u *)
     struct (Op.DCBT, TwoOperands(ra, rb))
  | 0b1u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.LHBRX, ThreeOperands(rd, ra, rb))
  | _ ->
    raise ParsingFailureException

let parseLHZX bin =
  match Bits.pick bin 10u with
  | 0b0u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.LHZX, ThreeOperands(rd, ra, rb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseSRAWx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* 1:RC *) with
  | 0b10u -> struct (Op.SRAW, ThreeOperands(ra, rs, rb))
  | 0b11u -> struct (Op.SRAWdot, ThreeOperands(ra, rs, rb))
  | _ (* 0x *) -> raise ParsingFailureException

let parseEQVx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* 0:Rc *) with
  | 0b00u -> struct (Op.EQV, ThreeOperands(ra, rs, rb))
  | 0b01u -> struct (Op.EQVdot, ThreeOperands(ra, rs, rb))
  | _ (* 1x *) -> raise ParsingFailureException

let parseTLBIE bin =
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 with
  | 0b00u ->
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.TLBIE, OneOperand rb)
  | _ (* 01, 1x *) ->
    raise ParsingFailureException

let parseECIWX bin =
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 with
  | 0b00u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.ECIWX, ThreeOperands(rd, ra, rb))
  | _ (* 01, 1x *) ->
    raise ParsingFailureException

let parseLHZUX bin =
  match Bits.pick bin 10u with
  | 0b0u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.LHZUX, ThreeOperands(rd, ra, rb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseSRAWIx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let sh = Bits.extract bin 15u 11u |> uint64 |> OprImm
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.SRAWI, ThreeOperands(ra, rs, sh))
  | _ (* 1 *) -> struct (Op.SRAWIdot, ThreeOperands(ra, rs, sh))

let parseXORx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* 0:RC *) with
  | 0b00u -> struct (Op.XOR, ThreeOperands(ra, rs, rb))
  | 0b01u -> struct (Op.XORdot, ThreeOperands(ra, rs, rb))
  | _ (* 1x *) -> raise ParsingFailureException

let parseMFSPR bin =
  match Bits.pick bin 10u with
  | 0b0u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    match Bits.concat (Bits.extract bin 15u 11u)
                      (Bits.extract bin 20u 16u)
                      5 with
    (* mfxer rd = mfspr rd,1 *)
    | 1u ->
      struct (Op.MFXER, OneOperand rd)
    (* mflr rd = mfspr rd,8 *)
    | 8u ->
      struct (Op.MFLR, OneOperand rd)
    (* mfctr rd = mfspr rd,9 *)
    | 9u ->
      struct (Op.MFCTR, OneOperand rd)
    (* On a 64-bit part the time base is read through mfspr, not mftb: SPR 268
       is the whole 64-bit counter and 269 its upper half. *)
    | 268u ->
      struct (Op.MFTB, TwoOperands(rd, OprImm 268UL))
    | 269u ->
      struct (Op.MFTBU, OneOperand rd)
    (* mfvrsave rd = mfspr rd,256 *)
    | 256u ->
      struct (Op.MFSPR, TwoOperands(rd, OprImm 256UL))
    | 18u | 19u | 22u | 25u | 26u | 27u | 272u | 273u | 274u | 275u | 282u
    | 287u | 528u | 529u | 530u | 531u | 532u | 533u | 534u | 535u | 536u
    | 537u | 538u | 539u | 540u | 541u | 542u | 543u | 1013u ->
      let spr =
        getSPRegister (Bits.concat (Bits.extract bin 15u 11u)
                                   (Bits.extract bin 20u 16u)
                                   5)
      struct (Op.MFSPR, TwoOperands(rd, spr))
    | _ ->
      raise ParsingFailureException
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseEIEIO bin =
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 with
  | 0b10u when Bits.extract bin 25u 11u = 0u -> struct (Op.EIEIO, NoOperand)
  | _ (* 11, 0x *) -> raise ParsingFailureException

let parseLHAX bin =
  match Bits.pick bin 10u with
  | 0b0u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.LHAX, ThreeOperands(rd, ra, rb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseTLBIA bin =
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 with
  | 0b00u -> struct (Op.TLBIA, NoOperand)
  | _ (* 01, 1x *) -> raise ParsingFailureException

let parseMFTB bin =
  match Bits.pick bin 10u with
  | 0b0u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    (* FIXME: TBRRegister *)
    let tbr =
      getTBRRegister (Bits.concat (Bits.extract bin 15u 11u)
                                  (Bits.extract bin 20u 16u)
                                  5)
    match Bits.concat (Bits.extract bin 15u 11u)
                      (Bits.extract bin 20u 16u)
                      5 with
    (* mftbu rd = mftb rd,269 *)
    | 0x10du -> struct (Op.MFTBU, OneOperand rd)
    (* mftb rd = mftb rd,268 *)
    | _ -> struct (Op.MFTB, TwoOperands(rd, tbr))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseLHAUX bin =
  match Bits.pick bin 10u with
  | 0b0u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.LHAUX, ThreeOperands(rd, ra, rb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseSTHBRX bin =
  match Bits.pick bin 10u with
  | 0b1u ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.STHBRX, ThreeOperands(rs, ra, rb))
  | _ (* 0 *) ->
    raise ParsingFailureException

let parseSTHX bin =
  match Bits.pick bin 10u with
  | 0b0u ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.STHX, ThreeOperands(rs, ra, rb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseEXTSHx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* 1:Rc *) with
  | 0b10u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.EXTSH, TwoOperands(ra, rs))
  | 0b11u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.EXTSHdot, TwoOperands(ra, rs))
  | _ (* 0x *) ->
    raise ParsingFailureException

let parseORCx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* 0:RC *) with
  | 0b00u -> struct (Op.ORC, ThreeOperands(ra, rs, rb))
  | 0b01u -> struct (Op.ORCdot, ThreeOperands(ra, rs, rb))
  | _ (* 1x *) -> raise ParsingFailureException

let parseECOWX bin =
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 with
  | 0b00u ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.ECOWX, ThreeOperands(rs, ra, rb))
  | _ (* 01, 1x *) ->
    raise ParsingFailureException

let parseSTHUX bin =
  match Bits.pick bin 10u with
  | 0b0u ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.STHUX, ThreeOperands(rs, ra, rb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseEXTSBx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* 1:Rc *) with
  | 0b10u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.EXTSB, TwoOperands(ra, rs))
  | 0b11u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.EXTSBdot, TwoOperands(ra, rs))
  | _ (* 0x *) ->
    raise ParsingFailureException

let parseORx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* 0:RC *) with
  (* mr ra,rs = or ra,rs,rs *)
  | 0b00u ->
    if Bits.extract bin 25u 21u = Bits.extract bin 15u 11u then
      struct (Op.MR, TwoOperands(ra, rs))
    else
      let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
      struct (Op.OR, ThreeOperands(ra, rs, rb))
  | 0b01u ->
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.ORdot, ThreeOperands(ra, rs, rb))
  | _ (* 1x *) ->
    raise ParsingFailureException

let parseDIVWUx bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* OE:RC *) with
  | 0b00u -> struct (Op.DIVWU, ThreeOperands(rd, ra, rb))
  | 0b01u -> struct (Op.DIVWUdot, ThreeOperands(rd, ra, rb))
  | 0b10u -> struct (Op.DIVWUO, ThreeOperands(rd, ra, rb))
  | _ (* 11 *) -> struct (Op.DIVWUOdot, ThreeOperands(rd, ra, rb))

let parseMTSPR bin =
  match Bits.pick bin 10u with
  | 0b0u ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    match Bits.concat (Bits.extract bin 15u 11u)
                      (Bits.extract bin 20u 16u)
                      5 with
    (* mtxer rd = mtspr rd,1 *)
    | 0x1u ->
      struct (Op.MTXER, OneOperand rs)
    (* mtlr rd = mtspr rd,8 *)
    | 0x8u ->
      struct (Op.MTLR, OneOperand rs)
    (* mtctr rd = mtspr rd,9 *)
    | 0x9u ->
      struct (Op.MTCTR, OneOperand rs)
    | _ ->
      (* FIXME: SPRegister *)
      let spr =
        getSPRegister (Bits.concat (Bits.extract bin 15u 11u)
                                   (Bits.extract bin 20u 16u)
                                   5)
      struct (Op.MTSPR, TwoOperands(spr, rs))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseDCBIandICBI bin =
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 10u with
  | 0b0u when Bits.extract bin 25u 21u = 0u ->
    struct (Op.DCBI, TwoOperands(ra, rb))
  | 0b1u when Bits.extract bin 25u 21u = 0u ->
    struct (Op.ICBI, TwoOperands(ra, rb))
  | _ ->
    raise ParsingFailureException

let parseSTFIWX bin =
  match Bits.pick bin 10u with
  | 0b1u ->
    let frs = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.STFIWX, ThreeOperands(frs, ra, rb))
  | _ (* 0 *) ->
    raise ParsingFailureException

let parseNANDx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* 0:RC *) with
  | 0b00u -> struct (Op.NAND, ThreeOperands(ra, rs, rb))
  | 0b01u -> struct (Op.NANDdot, ThreeOperands(ra, rs, rb))
  | _ (* 1x *) -> raise ParsingFailureException

let parseDIVWx bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* OE:RC *) with
  | 0b00u -> struct (Op.DIVW, ThreeOperands(rd, ra, rb))
  | 0b01u -> struct (Op.DIVWdot, ThreeOperands(rd, ra, rb))
  | 0b10u -> struct (Op.DIVWO, ThreeOperands(rd, ra, rb))
  | _ (* 11 *) -> struct (Op.DIVWOdot, ThreeOperands(rd, ra, rb))

let parseDCBZ bin =
  match Bits.pick bin 10u with
  | 0b1u when Bits.extract bin 25u 21u = 0u ->
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.DCBZ, TwoOperands(ra, rb))
  | _ (* 0 *) ->
    raise ParsingFailureException

(* The 64-bit forms all live in the same primary opcodes as their 32-bit
   siblings; only the extended opcode tells them apart. Because the word forms
   below are dispatched on nine of the extended opcode's ten bits, the 64-bit
   ones are picked out first (parse1F) on the full ten. *)
/// The three registers of an X-form "rD, rA, rB", in that order.
let private xFormRegs bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  struct (rd, ra, rb)

/// An X-form load or store indexed, whose operands are "rD, rA, rB".
let private parseXFormIndexed op bin =
  let struct (rd, ra, rb) = xFormRegs bin
  if Bits.pick bin 0u <> 0u then raise ParsingFailureException
  else struct (op, ThreeOperands(rd, ra, rb))

/// A load-and-reserve indexed, whose last bit is the EH hint rather than a
/// reserved bit: it only says how the reservation is expected to be used, so
/// both values lift the same way.
let private parseReserveIndexed op bin =
  let struct (rd, ra, rb) = xFormRegs bin
  struct (op, ThreeOperands(rd, ra, rb))

/// A store-conditional indexed, whose record bit is not optional -- the store
/// always reports in CR0 whether the reservation still held.
let private parseStoreConditional op bin =
  let struct (rs, ra, rb) = xFormRegs bin
  if Bits.pick bin 0u <> 1u then raise ParsingFailureException
  else struct (op, ThreeOperands(rs, ra, rb))

/// An XO-form "rD, rA, rB" whose OE:Rc pair names four opcodes, given in the
/// order plain, dot, overflow, overflow-dot.
let private parseXOForm (ops: Opcode[]) bin =
  let struct (rd, ra, rb) = xFormRegs bin
  let idx = Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 |> int
  struct (ops[idx], ThreeOperands(rd, ra, rb))

/// An X-form "rD, rA, rB" whose Rc bit names two opcodes.
let private parseXFormArith op opDot bin =
  let struct (rd, ra, rb) = xFormRegs bin
  if Bits.pick bin 0u = 0u then struct (op, ThreeOperands(rd, ra, rb))
  else struct (opDot, ThreeOperands(rd, ra, rb))

/// An X-form "rA, rS" with no third register, whose Rc bit names two opcodes.
let private parseXFormUnary op opDot bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  if Bits.extract bin 15u 11u <> 0u then raise ParsingFailureException
  elif Bits.pick bin 0u = 0u then struct (op, TwoOperands(ra, rs))
  else struct (opDot, TwoOperands(ra, rs))

/// An X-form "rA, rS" with neither a third register nor an Rc bit.
let private parseXFormCount op bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  if Bits.extract bin 15u 11u <> 0u || Bits.pick bin 0u <> 0u then
    raise ParsingFailureException
  else
    struct (op, TwoOperands(ra, rs))

/// An X-form "rA, rS, rB" whose Rc bit names two opcodes.
let private parseXFormLogical op opDot bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  if Bits.pick bin 0u = 0u then struct (op, ThreeOperands(ra, rs, rb))
  else struct (opDot, ThreeOperands(ra, rs, rb))

/// An X-form "rA, rS, rB" with no Rc bit.
let private parseXFormPerm op bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  if Bits.pick bin 0u <> 0u then raise ParsingFailureException
  else struct (op, ThreeOperands(ra, rs, rb))

/// sradi/sradi., whose shift amount spans the extended-opcode field: the low
/// five bits sit where an X-form rB would, and the sixth is bit 1.
let private parseSRADIx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let sh = (Bits.pick bin 1u <<< 5) ||| Bits.extract bin 15u 11u
  let sh = sh |> uint64 |> OprImm
  if Bits.pick bin 0u = 0u then struct (Op.SRADI, ThreeOperands(ra, rs, sh))
  else struct (Op.SRADIdot, ThreeOperands(ra, rs, sh))

/// td, whose TO field selects the comparison the same way tw's does; the
/// generic three-operand form carries TO to the lifter.
let private parseTD bin =
  let struct (_, ra, rb) = xFormRegs bin
  let tO = Bits.extract bin 25u 21u |> uint64 |> OprImm
  if Bits.pick bin 0u <> 0u then raise ParsingFailureException
  else struct (Op.TD, ThreeOperands(tO, ra, rb))

/// isel rD, rA, rB, crb: the condition bit sits where an X-form keeps the
/// extended opcode's high bits, so the whole "bits 26-30 = 15" space is isel.
let private parseISEL bin =
  let struct (rd, ra, rb) = xFormRegs bin
  let crb = Bits.extract bin 10u 6u |> OprBI
  struct (Op.ISEL, FourOperands(rd, ra, rb, crb))

/// mtvsrdd, which fills both halves of a vector-scalar register from two
/// general ones.
let private parseMTVSRDD bin =
  let xt = (Bits.pick bin 0u <<< 5) ||| Bits.extract bin 25u 21u
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  struct (Op.MTVSRDD, ThreeOperands(getVsxRegister xt |> OprReg, ra, rb))

/// mfvsrld, which reads a vector-scalar register's low doubleword.
let private parseMFVSRLD bin =
  let xs = (Bits.pick bin 0u <<< 5) ||| Bits.extract bin 25u 21u
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  struct (Op.MFVSRLD, TwoOperands(getVsxRegister xs |> OprReg, ra))

/// A VSX direct move between a vector-scalar register and a general one. The
/// operand names the VSX register's high doubleword, which is a floating-point
/// register for VSR0-31 and a vector register for VSR32-63.
let private parseVsrMove op bin =
  let n = (Bits.pick bin 0u <<< 5) ||| Bits.extract bin 25u 21u
  let xs = getVsxRegister n |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  struct (op, TwoOperands(xs, ra))

(* The vector forms. A vector operand names a register by its high half; the
   lifter reaches its low half from there. A VSX operand's register number is
   six bits: five in the usual field plus a low-order bit at the very end of the
   instruction, which is why the forms below do not treat that bit as reserved
   the way an integer X-form does. *)
/// A VMX load or store indexed: "vD, rA, rB" in primary opcode 31.
let private parseVmxIndexed op bin =
  let vd = getVecRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  if Bits.pick bin 0u <> 0u then raise ParsingFailureException
  else struct (op, ThreeOperands(vd, ra, rb))

/// A VSX load or store indexed: "xT, rA, rB", the register number's high bit
/// being the instruction's last bit.
let private parseVsxIndexed op bin =
  let n = (Bits.pick bin 0u <<< 5) ||| Bits.extract bin 25u 21u
  let xt = getVsxRegister n |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  struct (op, ThreeOperands(xt, ra, rb))

/// A VX-form "vD, vA, vB".
let private parseVX op bin =
  let vd = getVecRegister (Bits.extract bin 25u 21u) |> OprReg
  let va = getVecRegister (Bits.extract bin 20u 16u) |> OprReg
  let vb = getVecRegister (Bits.extract bin 15u 11u) |> OprReg
  struct (op, ThreeOperands(vd, va, vb))

/// A VX-form "vD, vB" whose middle field is unused.
let private parseVX2 op bin =
  let vd = getVecRegister (Bits.extract bin 25u 21u) |> OprReg
  let vb = getVecRegister (Bits.extract bin 15u 11u) |> OprReg
  if Bits.extract bin 20u 16u <> 0u then raise ParsingFailureException
  else struct (op, TwoOperands(vd, vb))

/// A VX-form "vD, SIM" carrying a five-bit signed immediate to splat.
let private parseVXImm op bin =
  let vd = getVecRegister (Bits.extract bin 25u 21u) |> OprReg
  let sim = Bits.extract bin 20u 16u |> uint64 |> Bits.signExtend 5 64 |> uint64
  struct (op, TwoOperands(vd, OprImm sim))

/// A VX-form "vD, vB, UIM" whose immediate picks an element to splat.
let private parseVXUimm op bin =
  let vd = getVecRegister (Bits.extract bin 25u 21u) |> OprReg
  let uim = Bits.extract bin 20u 16u |> uint64 |> OprImm
  let vb = getVecRegister (Bits.extract bin 15u 11u) |> OprReg
  struct (op, ThreeOperands(vd, vb, uim))

/// A VX-form naming just one vector register, for mfvscr and mtvscr.
let private parseVXOne op bin =
  let v = getVecRegister (Bits.extract bin 25u 21u) |> OprReg
  struct (op, OneOperand v)

/// A VA-form "vD, vA, vB, vC".
let private parseVA op bin =
  let vd = getVecRegister (Bits.extract bin 25u 21u) |> OprReg
  let va = getVecRegister (Bits.extract bin 20u 16u) |> OprReg
  let vb = getVecRegister (Bits.extract bin 15u 11u) |> OprReg
  let vc = getVecRegister (Bits.extract bin 10u 6u) |> OprReg
  struct (op, FourOperands(vd, va, vb, vc))

/// vsldoi, a VA-form whose fourth operand is the shift its rC field holds.
let private parseVSLDOI bin =
  let vd = getVecRegister (Bits.extract bin 25u 21u) |> OprReg
  let va = getVecRegister (Bits.extract bin 20u 16u) |> OprReg
  let vb = getVecRegister (Bits.extract bin 15u 11u) |> OprReg
  let sh = Bits.extract bin 9u 6u |> uint64 |> OprImm
  struct (Op.VSLDOI, FourOperands(vd, va, vb, sh))

/// A VC-form compare, whose Rc bit chooses between the two record forms.
let private parseVC op opDot bin =
  let vd = getVecRegister (Bits.extract bin 25u 21u) |> OprReg
  let va = getVecRegister (Bits.extract bin 20u 16u) |> OprReg
  let vb = getVecRegister (Bits.extract bin 15u 11u) |> OprReg
  let op = if Bits.pick bin 10u = 0u then op else opDot
  struct (op, ThreeOperands(vd, va, vb))

/// An XX3-form "xT, xA, xB", each register number extended by one of the three
/// bits at the end of the instruction.
let private parseXX3 op bin =
  let xt = (Bits.pick bin 0u <<< 5) ||| Bits.extract bin 25u 21u
  let xa = (Bits.pick bin 2u <<< 5) ||| Bits.extract bin 20u 16u
  let xb = (Bits.pick bin 1u <<< 5) ||| Bits.extract bin 15u 11u
  struct (op, ThreeOperands(getVsxRegister xt |> OprReg,
                            getVsxRegister xa |> OprReg,
                            getVsxRegister xb |> OprReg))

/// The vector instructions in primary opcode 4, whose extended opcode is a
/// plain eleven-bit field except in the VA and VC forms.
let private parse04 bin =
  match Bits.extract bin 5u 0u with
  | 42u ->
    parseVA Op.VSEL bin
  | 43u ->
    parseVA Op.VPERM bin
  | 44u ->
    parseVSLDOI bin
  | _ ->
    match Bits.extract bin 9u 0u with
    | 6u ->
      parseVC Op.VCMPEQUB Op.VCMPEQUBdot bin
    | 70u ->
      parseVC Op.VCMPEQUH Op.VCMPEQUHdot bin
    | 134u ->
      parseVC Op.VCMPEQUW Op.VCMPEQUWdot bin
    | 199u ->
      parseVC Op.VCMPEQUD Op.VCMPEQUDdot bin
    | 518u ->
      parseVC Op.VCMPGTUB Op.VCMPGTUBdot bin
    | 582u ->
      parseVC Op.VCMPGTUH Op.VCMPGTUHdot bin
    | 646u ->
      parseVC Op.VCMPGTUW Op.VCMPGTUWdot bin
    | 711u ->
      parseVC Op.VCMPGTUD Op.VCMPGTUDdot bin
    | 774u ->
      parseVC Op.VCMPGTSB Op.VCMPGTSBdot bin
    | 838u ->
      parseVC Op.VCMPGTSH Op.VCMPGTSHdot bin
    | 902u ->
      parseVC Op.VCMPGTSW Op.VCMPGTSWdot bin
    | 967u ->
      parseVC Op.VCMPGTSD Op.VCMPGTSDdot bin
    | _ ->
      match Bits.extract bin 10u 0u with
      | 0u -> parseVX Op.VADDUBM bin
      | 2u -> parseVX Op.VMAXUB bin
      | 4u -> parseVX Op.VRLB bin
      | 12u -> parseVX Op.VMRGHB bin
      | 14u -> parseVX Op.VPKUHUM bin
      | 64u -> parseVX Op.VADDUHM bin
      | 66u -> parseVX Op.VMAXUH bin
      | 68u -> parseVX Op.VRLH bin
      | 76u -> parseVX Op.VMRGHH bin
      | 78u -> parseVX Op.VPKUWUM bin
      | 128u -> parseVX Op.VADDUWM bin
      | 130u -> parseVX Op.VMAXUW bin
      | 132u -> parseVX Op.VRLW bin
      | 140u -> parseVX Op.VMRGHW bin
      | 192u -> parseVX Op.VADDUDM bin
      | 194u -> parseVX Op.VMAXUD bin
      | 196u -> parseVX Op.VRLD bin
      | 258u -> parseVX Op.VMAXSB bin
      | 260u -> parseVX Op.VSLB bin
      | 268u -> parseVX Op.VMRGLB bin
      | 322u -> parseVX Op.VMAXSH bin
      | 324u -> parseVX Op.VSLH bin
      | 332u -> parseVX Op.VMRGLH bin
      | 386u -> parseVX Op.VMAXSW bin
      | 388u -> parseVX Op.VSLW bin
      | 396u -> parseVX Op.VMRGLW bin
      | 450u -> parseVX Op.VMAXSD bin
      | 452u -> parseVX Op.VSL bin
      | 514u -> parseVX Op.VMINUB bin
      | 516u -> parseVX Op.VSRB bin
      | 524u -> parseVXUimm Op.VSPLTB bin
      | 526u -> parseVX2 Op.VUPKHSB bin
      | 578u -> parseVX Op.VMINUH bin
      | 580u -> parseVX Op.VSRH bin
      | 588u -> parseVXUimm Op.VSPLTH bin
      | 590u -> parseVX2 Op.VUPKHSH bin
      | 642u -> parseVX Op.VMINUW bin
      | 644u -> parseVX Op.VSRW bin
      | 652u -> parseVXUimm Op.VSPLTW bin
      | 654u -> parseVX2 Op.VUPKLSB bin
      | 706u -> parseVX Op.VMINUD bin
      | 708u -> parseVX Op.VSR bin
      | 718u -> parseVX2 Op.VUPKLSH bin
      | 770u -> parseVX Op.VMINSB bin
      | 772u -> parseVX Op.VSRAB bin
      | 780u -> parseVXImm Op.VSPLTISB bin
      | 834u -> parseVX Op.VMINSH bin
      | 836u -> parseVX Op.VSRAH bin
      | 844u -> parseVXImm Op.VSPLTISH bin
      | 898u -> parseVX Op.VMINSW bin
      | 900u -> parseVX Op.VSRAW bin
      | 908u -> parseVXImm Op.VSPLTISW bin
      | 962u -> parseVX Op.VMINSD bin
      | 964u -> parseVX Op.VSRAD bin
      | 1024u -> parseVX Op.VSUBUBM bin
      | 1028u -> parseVX Op.VAND bin
      | 1036u -> parseVX Op.VSLO bin
      | 1088u -> parseVX Op.VSUBUHM bin
      | 1092u -> parseVX Op.VANDC bin
      | 1100u -> parseVX Op.VSRO bin
      | 1152u -> parseVX Op.VSUBUWM bin
      | 1156u -> parseVX Op.VOR bin
      | 1216u -> parseVX Op.VSUBUDM bin
      | 1220u -> parseVX Op.VXOR bin
      | 1284u -> parseVX Op.VNOR bin
      | 1292u -> parseVX2 Op.VGBBD bin
      | 1348u -> parseVX Op.VORC bin
      | 1356u -> parseVX Op.VBPERMQ bin
      | 1412u -> parseVX Op.VNAND bin
      | 1476u -> parseVX Op.VSLD bin
      | 1540u -> parseVXOne Op.MFVSCR bin
      | 1604u -> parseVXOne Op.MTVSCR bin
      | 1668u -> parseVX Op.VEQV bin
      | 1676u -> parseVX Op.VMRGOW bin
      | 1732u -> parseVX Op.VSRD bin
      | 1794u -> parseVX2 Op.VCLZB bin
      | 1795u -> parseVX2 Op.VPOPCNTB bin
      | 1858u -> parseVX2 Op.VCLZH bin
      | 1859u -> parseVX2 Op.VPOPCNTH bin
      | 1922u -> parseVX2 Op.VCLZW bin
      | 1923u -> parseVX2 Op.VPOPCNTW bin
      | 1932u -> parseVX Op.VMRGEW bin
      | 1986u -> parseVX2 Op.VCLZD bin
      | 1987u -> parseVX2 Op.VPOPCNTD bin
      | _ -> raise ParsingFailureException

/// xxpermdi, whose two-bit DM field picks one doubleword of each source. Its
/// six-bit extended opcode sits below DM, so the whole instruction shares the
/// eight bits the logical forms use as one field; the logical opcodes are
/// xxpermdi and xxsldwi, whose two-bit DM or SHW field sits inside the eight
/// bits the logical forms use as one extended opcode: bit 10 is clear, bits 9
/// and 8 hold the field, and bits 7 down to 3 identify the instruction. The
/// logical opcodes all have bit 10 set, so the two groups never overlap.
let private parseXXPERMDIx op bin =
  let struct (op, oprs) = parseXX3 op bin
  let dm = Bits.extract bin 9u 8u |> uint64 |> OprImm
  match oprs with
  | ThreeOperands(xt, xa, xb) -> struct (op, FourOperands(xt, xa, xb, dm))
  | _ -> raise ParsingFailureException

/// An XX2-form "xT, xB", whose extended opcode is nine bits wide because only
/// two register-extension bits follow it.
let private parseXX2 op bin =
  let xt = (Bits.pick bin 0u <<< 5) ||| Bits.extract bin 25u 21u
  let xb = (Bits.pick bin 1u <<< 5) ||| Bits.extract bin 15u 11u
  struct (op, TwoOperands(getVsxRegister xt |> OprReg,
                          getVsxRegister xb |> OprReg))

/// xxspltw, an XX2 form whose spare field selects the word to splat.
let private parseXXSPLTW bin =
  let struct (op, oprs) = parseXX2 Op.XXSPLTW bin
  let uim = Bits.extract bin 17u 16u |> uint64 |> OprImm
  match oprs with
  | TwoOperands(xt, xb) -> struct (op, ThreeOperands(xt, xb, uim))
  | _ -> raise ParsingFailureException

/// xxspltib, which carries the byte to splat as an eight-bit immediate.
let private parseXXSPLTIB bin =
  let xt = (Bits.pick bin 0u <<< 5) ||| Bits.extract bin 25u 21u
  let imm = Bits.extract bin 20u 13u |> uint64 |> OprImm
  struct (Op.XXSPLTIB, TwoOperands(getVsxRegister xt |> OprReg, imm))

/// An XX3-form scalar compare, which reports in a condition-register field
/// rather than in a vector-scalar register.
let private parseXX3Compare op bin =
  let crfd = getCondRegister (Bits.extract bin 25u 23u) |> OprReg
  let xa = (Bits.pick bin 2u <<< 5) ||| Bits.extract bin 20u 16u
  let xb = (Bits.pick bin 1u <<< 5) ||| Bits.extract bin 15u 11u
  struct (op, ThreeOperands(crfd,
                            getVsxRegister xa |> OprReg,
                            getVsxRegister xb |> OprReg))

/// The VSX instructions in primary opcode 60: the logical forms, the ones that
/// shuffle doublewords and words, and the scalar double-precision arithmetic.
/// The quad-precision and vector floating-point forms share the space and fail
/// to parse. An XX3 form's extended opcode is eight bits and an XX2 form's is
/// nine, so the wider ones are matched first.
let private parse3C bin =
  match Bits.extract bin 10u 3u with
  | 32u ->
    parseXX3 Op.XSADDDP bin
  | 35u ->
    parseXX3Compare Op.XSCMPUDP bin
  | 40u ->
    parseXX3 Op.XSSUBDP bin
  | 56u ->
    parseXX3 Op.XSDIVDP bin
  | 130u ->
    parseXX3 Op.XXLAND bin
  | 138u ->
    parseXX3 Op.XXLANDC bin
  | 146u ->
    parseXX3 Op.XXLOR bin
  | 154u ->
    parseXX3 Op.XXLXOR bin
  | 162u ->
    parseXX3 Op.XXLNOR bin
  | 170u ->
    parseXX3 Op.XXLORC bin
  | 176u ->
    parseXX3 Op.XSCPSGNDP bin
  | 178u ->
    parseXX3 Op.XXLNAND bin
  | 186u ->
    parseXX3 Op.XXLEQV bin
  | xo when xo &&& 0x9Fu = 0x0Au ->
    parseXXPERMDIx Op.XXPERMDI bin
  | xo when xo &&& 0x9Fu = 0x02u ->
    parseXXPERMDIx Op.XXSLDWI bin
  | _ ->
    match Bits.extract bin 10u 2u with
    | 164u -> parseXXSPLTW bin
    | 180u -> parseXXSPLTIB bin
    | 267u -> parseXX2 Op.XSCVDPSPN bin
    | 281u -> parseXX2 Op.XSRSP bin
    | 331u -> parseXX2 Op.XSCVSPDPN bin
    | 345u -> parseXX2 Op.XSABSDP bin
    | _ -> raise ParsingFailureException

/// The VMX and VSX memory accesses that live in primary opcode 31.
let private parse1FVector fallback bin =
  match Bits.extract bin 10u 1u with
  | 6u -> parseVmxIndexed Op.LVSL bin
  | 7u -> parseVmxIndexed Op.LVEBX bin
  | 38u -> parseVmxIndexed Op.LVSR bin
  | 39u -> parseVmxIndexed Op.LVEHX bin
  | 71u -> parseVmxIndexed Op.LVEWX bin
  | 103u -> parseVmxIndexed Op.LVX bin
  | 135u -> parseVmxIndexed Op.STVEBX bin
  | 167u -> parseVmxIndexed Op.STVEHX bin
  | 199u -> parseVmxIndexed Op.STVEWX bin
  | 231u -> parseVmxIndexed Op.STVX bin
  | 359u -> parseVmxIndexed Op.LVXL bin
  | 487u -> parseVmxIndexed Op.STVXL bin
  | 332u -> parseVsxIndexed Op.LXVDSX bin
  | 588u -> parseVsxIndexed Op.LXSDX bin
  | 716u -> parseVsxIndexed Op.STXSDX bin
  | 780u -> parseVsxIndexed Op.LXVW4X bin
  | 844u -> parseVsxIndexed Op.LXVD2X bin
  | 908u -> parseVsxIndexed Op.STXVW4X bin
  | 972u -> parseVsxIndexed Op.STXVD2X bin
  | _ -> fallback bin

let private parse1FDouble fallback bin =
  match Bits.extract bin 10u 1u with
  | 0x009u -> parseXFormArith Op.MULHDU Op.MULHDUdot bin
  | 0x015u -> parseXFormIndexed Op.LDX bin
  | 0x01Bu -> parseXFormLogical Op.SLD Op.SLDdot bin
  | 0x033u -> parseVsrMove Op.MFVSRD bin
  | 0x035u -> parseXFormIndexed Op.LDUX bin
  | 0x03Au -> parseXFormUnary Op.CNTLZD Op.CNTLZDdot bin
  | 0x044u -> parseTD bin
  | 0x049u -> parseXFormArith Op.MULHD Op.MULHDdot bin
  (* The byte and halfword reservation pairs came with the doubleword ones'
     generation of the architecture, so they sit alongside them here. *)
  | 0x034u -> parseReserveIndexed Op.LBARX bin
  | 0x054u -> parseReserveIndexed Op.LDARX bin
  | 0x074u -> parseReserveIndexed Op.LHARX bin
  | 0x2B6u -> parseStoreConditional Op.STBCXdot bin
  | 0x2D6u -> parseStoreConditional Op.STHCXdot bin
  | 0x073u -> parseVsrMove Op.MFVSRWZ bin
  | 0x07Au -> parseXFormCount Op.POPCNTB bin
  | 0x095u -> parseXFormIndexed Op.STDX bin
  | 0x09Au -> parseXFormCount Op.PRTYW bin
  | 0x0B3u -> parseVsrMove Op.MTVSRD bin
  | 0x0B5u -> parseXFormIndexed Op.STDUX bin
  | 0x0BAu -> parseXFormCount Op.PRTYD bin
  | 0x0D3u -> parseVsrMove Op.MTVSRWA bin
  | 0x0D6u -> parseStoreConditional Op.STDCXdot bin
  | 0x0E9u -> parseXOForm [| Op.MULLD
                             Op.MULLDdot
                             Op.MULLDO
                             Op.MULLDOdot |] bin
  | 0x0F3u -> parseVsrMove Op.MTVSRWZ bin
  | 0x133u -> parseMFVSRLD bin
  | 0x1B3u -> parseMTVSRDD bin
  | 0x0FCu -> parseXFormPerm Op.BPERMD bin
  | 0x155u -> parseXFormIndexed Op.LWAX bin
  | 0x175u -> parseXFormIndexed Op.LWAUX bin
  | 0x17Au -> parseXFormCount Op.POPCNTW bin
  | 0x1C9u -> parseXOForm [| Op.DIVDU
                             Op.DIVDUdot
                             Op.DIVDUO
                             Op.DIVDUOdot |] bin
  | 0x1E9u -> parseXOForm [| Op.DIVD; Op.DIVDdot; Op.DIVDO; Op.DIVDOdot |] bin
  | 0x1FAu -> parseXFormCount Op.POPCNTD bin
  | 0x1FCu -> parseXFormPerm Op.CMPB bin
  | 0x214u -> parseXFormIndexed Op.LDBRX bin
  | 0x21Bu -> parseXFormLogical Op.SRD Op.SRDdot bin
  | 0x294u -> parseXFormIndexed Op.STDBRX bin
  | 0x31Au -> parseXFormLogical Op.SRAD Op.SRADdot bin
  | 0x33Au | 0x33Bu -> parseSRADIx bin
  | 0x3DAu -> parseXFormUnary Op.EXTSW Op.EXTSWdot bin
  | _ -> fallback bin

let private parse1FWord bin =
  match Bits.extract bin 9u 1u with
  | 0x0u when Bits.pick bin 0u = 0u -> parseCMPandMCRXR bin
  | 0x4u when Bits.pick bin 0u = 0u -> parseTW bin
  | 0x8u -> parseSUBFCx bin
  | 0xAu -> parseADDCx bin
  | 0xBu when Bits.pick bin 10u = 0u -> parseMULHWUx bin
  | 0x13u when Bits.pick bin 0u = 0u -> parseMFCR bin
  (* FIXME: LWARX RegA = 0 *)
  | 0x14u when Bits.pick bin 10u = 0u -> parseLWARX bin
  | 0x15u when Bits.pick bin 0u = 0u -> parseLSWX bin
  (* FIXME: LWBRX RegA = 0 *)
  | 0x16u when Bits.pick bin 0u = 0u -> parseLWBRX bin
  (* FIXME: LWZX / LFSX RegA = 0 *)
  | 0x17u when Bits.pick bin 0u = 0u -> parseLWZXandLFSX bin
  | 0x18u -> parseSLWxandSRWx bin
  | 0x1Au -> parseCNTLZWx bin
  | 0x1Cu -> parseANDx bin
  | 0x20u when Bits.pick bin 0u = 0u -> parseCMPL bin
  | 0x28u -> parseSUBFx bin
  (* FIXME: DCBST RegA = 0 *)
  | 0x36u when Bits.pick bin 0u = 0u -> parseDCBSTandTLBSYNC bin
  (* FIXME: LWZUX / LFSUX RegA = 0 *)
  | 0x37u when Bits.pick bin 0u = 0u -> parseLWZUXandLFSUX bin
  | 0x3Cu -> parseANDCx bin
  | 0x4Bu when Bits.pick bin 10u = 0u -> parseMULHWx bin
  (* FIXME: SegRegister *)
  | 0x53u when Bits.pick bin 0u = 0u -> parseMFMSRandMFSR bin
  | 0x55u when Bits.pick bin 0u = 0u -> parseLSWI bin
  (* FIXME: DCBF RegA = 0 / SYNC 0 *)
  | 0x56u when Bits.pick bin 0u = 0u -> parseDCBFandSYNC bin
  (* FIXME: LBZX / LFDX RegA = 0 *)
  | 0x57u when Bits.pick bin 0u = 0u -> parseLBZXandLFDX bin
  | 0x68u -> parseNEGx bin
  (* FIXME: LBZUX / LFDUX RegA = 0 *)
  | 0x77u when Bits.pick bin 0u = 0u -> parseLBZUXandLFDUX bin
  | 0x7Cu -> parseNORx bin
  | 0x88u -> parseSUBFEx bin
  | 0x8Au -> parseADDEx bin
  (* FIXME: CRM *)
  | 0x90u when Bits.pick bin 0u = 0u -> parseMTCRF bin
  | 0x92u when Bits.pick bin 0u = 0u -> parseMTMSR bin
  | 0x93u -> parseMFSRIN bin
  | 0x95u when Bits.pick bin 0u = 0u -> parseSTSWX bin
  (* FIXME: STWCXdot / STWBRX RegA = 0 *)
  | 0x96u -> parseSTWCXdotandSTWBRX bin
  (* FIXME: STWX / STFSX RegA = 0 *)
  | 0x97u when Bits.pick bin 0u = 0u -> parseSTWXandSTFSX bin
  (* FIXME: STWUX / STFSUX RegA = 0 *)
  | 0xB7u when Bits.pick bin 0u = 0u -> parseSTWUXandSTFSUX bin
  | 0xC8u -> parseSUBFZEx bin
  | 0xCAu -> parseADDZEx bin
  (* FIXME: SegRegister *)
  | 0xD2u when Bits.pick bin 0u = 0u -> parseMTSR bin
  (* FIXME: SpecialRegister *)
  | 0xD5u when Bits.pick bin 0u = 0u -> parseSTSWI bin
  (* FIXME: STBX / STFDX RegA = 0 *)
  | 0xD7u -> parseSTBXandSTFDX bin
  | 0xE8u -> parseSUBFMEx bin
  | 0xEAu -> parseADDMEx bin
  | 0xEBu -> parseMULLWx bin
  | 0xF2u -> parseMTSRIN bin
  (* FIXME: DCBTST / DCBA RegA = 0 *)
  | 0xF6u when Bits.pick bin 0u = 0u -> parseDCBTSTandDCBA bin
  (* FIXME: STBUX / STFDUX RegA = 0 *)
  | 0xF7u -> parseSTBUXandSTFDUX bin
  | 0x10Au -> parseADDx bin
  (* FIXME: DCBT / LHBRX RegA = 0 *)
  | 0x116u when Bits.pick bin 0u = 0u -> parseDCBTandLHBRX bin
  (* FIXME: LHZX RegA = 0 *)
  | 0x117u when Bits.pick bin 0u = 0u -> parseLHZX bin
  | 0x118u -> parseSRAWx bin
  | 0x11Cu -> parseEQVx bin
  | 0x132u -> parseTLBIE bin
  | 0x136u when Bits.pick bin 0u = 0u -> parseECIWX bin
  (* FIXME: LHZUX RegA = 0 *)
  | 0x137u when Bits.pick bin 0u = 0u -> parseLHZUX bin
  | 0x138u when Bits.pick bin 10u = 1u -> parseSRAWIx bin
  | 0x13Cu -> parseXORx bin
  (* FIXME: SpecialRegister *)
  | 0x153u when Bits.pick bin 0u = 0u -> parseMFSPR bin
  | 0x156u when Bits.pick bin 0u = 0u -> parseEIEIO bin
  (* FIXME: LHAX RegA = 0 *)
  | 0x157u when Bits.pick bin 0u = 0u -> parseLHAX bin
  | 0x172u -> parseTLBIA bin
  (* FIXME: TBRRegister *)
  | 0x173u when Bits.pick bin 0u = 0u -> parseMFTB bin
  (* FIXME: LHAUX RegA = 0 *)
  | 0x177u when Bits.pick bin 0u = 0u -> parseLHAUX bin
  (* FIXME: STHBRX RegA = 0 *)
  | 0x196u when Bits.pick bin 0u = 0u -> parseSTHBRX bin
  (* FIXME: STHX RegA = 0 *)
  | 0x197u when Bits.pick bin 0u = 0u -> parseSTHX bin
  | 0x19Au -> parseEXTSHx bin
  | 0x19Cu -> parseORCx bin
  | 0x1B6u when Bits.pick bin 0u = 0u -> parseECOWX bin
  (* FIXME: STHUX RegA = 0 *)
  | 0x1B7u when Bits.pick bin 0u = 0u -> parseSTHUX bin
  | 0x1BAu -> parseEXTSBx bin
  | 0x1BCu -> parseORx bin
  | 0x1CBu -> parseDIVWUx bin
  | 0x1D3u when Bits.pick bin 0u = 0u -> parseMTSPR bin
  (* FIXME: DCBI / ICBI RegA = 0 *)
  | 0x1D6u when Bits.pick bin 0u = 0u -> parseDCBIandICBI bin
  (* FIXME: STFIWX RegA = 0 *)
  | 0x1D7u when Bits.pick bin 0u = 0u -> parseSTFIWX bin
  | 0x1DCu -> parseNANDx bin
  | 0x1EBu -> parseDIVWx bin
  (* FIXME: DCBZ RegA = 0 *)
  | 0x1F6u when Bits.pick bin 0u = 0u -> parseDCBZ bin
  | _ -> raise ParsingFailureException

let parse1F is64 bin =
  if Bits.extract bin 5u 1u = 0xFu then parseISEL bin
  elif is64 then parse1FVector (parse1FDouble parse1FWord) bin
  else parse1FVector parse1FWord bin

let parseLWZ bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LWZ, TwoOperands(rd, mem))

let parseLWZU bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LWZU, TwoOperands(rd, mem))

let parseLBZ bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LBZ, TwoOperands(rd, mem))

let parseLBZU bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LBZU, TwoOperands(rd, mem))

let parseSTW bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.STW, TwoOperands(rs, mem))

let parseSTWU bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.STWU, TwoOperands(rs, mem))

let parseSTB bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.STB, TwoOperands(rs, mem))

let parseSTBU bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.STBU, TwoOperands(rs, mem))

let parseLHZ bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LHZ, TwoOperands(rd, mem))

let parseLHZU bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LHZU, TwoOperands(rd, mem))

let parseLHA bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LHA, TwoOperands(rd, mem))

let parseLHAU bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LHAU, TwoOperands(rd, mem))

let parseSTH bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.STH, TwoOperands(rs, mem))

let parseSTHU bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.STHU, TwoOperands(rs, mem))

let parseLMW bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LMW, TwoOperands(rd, mem))

let parseSTMW bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.STMW, TwoOperands(rs, mem))

let parseLFS bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LFS, TwoOperands(frd, mem))

let parseLFSU bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LFSU, TwoOperands(frd, mem))

let parseLFD bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LFD, TwoOperands(frd, mem))

let parseLFDU bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LFDU, TwoOperands(frd, mem))

let parseSTFS bin =
  let frs = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.STFS, TwoOperands(frs, mem))

let parseSTFSU bin =
  let frs = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.STFSU, TwoOperands(frs, mem))

let parseSTFD bin =
  let frs = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.STFD, TwoOperands(frs, mem))

let parseSTFDU bin =
  let frs = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.STFDU, TwoOperands(frs, mem))

let parseFDIVSx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.FDIVS, ThreeOperands(frd, fra, frb))
  | _ (* 1 *) -> struct (Op.FDIVSdot, ThreeOperands(frd, fra, frb))

let parseFSUBSx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.FSUBS, ThreeOperands(frd, fra, frb))
  | _ (* 1 *) -> struct (Op.FSUBSdot, ThreeOperands(frd, fra, frb))

let parseFADDSx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.FADDS, ThreeOperands(frd, fra, frb))
  | _ (* 1 *) -> struct (Op.FADDSdot, ThreeOperands(frd, fra, frb))

let parseFSQRTSx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FSQRTS, TwoOperands(frd, frb))
  | 0b1u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FSQRTSdot, TwoOperands(frd, frb))
  | _ ->
    raise ParsingFailureException

let parseFRESx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FRES, TwoOperands(frd, frb))
  | 0b1u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FRESdot, TwoOperands(frd, frb))
  | _ ->
    raise ParsingFailureException

let parseFMULSx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frc = getFPRegister (Bits.extract bin 10u 6u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.FMULS, ThreeOperands(frd, fra, frc))
  | 0b1u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.FMULSdot, ThreeOperands(frd, fra, frc))
  | _ ->
    raise ParsingFailureException

let parseFMSUBSx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  let frc = getFPRegister (Bits.extract bin 10u 6u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.FMSUBS, FourOperands(frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FMSUBSdot, FourOperands(frd, fra, frc, frb))

let parseFMADDSx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  let frc = getFPRegister (Bits.extract bin 10u 6u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.FMADDS, FourOperands(frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FMADDSdot, FourOperands(frd, fra, frc, frb))

let parseFNMSUBSx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  let frc = getFPRegister (Bits.extract bin 10u 6u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.FNMSUBS, FourOperands(frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FNMSUBSdot, FourOperands(frd, fra, frc, frb))

let parseFNMADDSx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  let frc = getFPRegister (Bits.extract bin 10u 6u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.FNMADDS, FourOperands(frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FNMADDSdot, FourOperands(frd, fra, frc, frb))

/// fcpsgn, which takes a sign from one operand and a magnitude from the other.
let private parseFCPSGN bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  if Bits.pick bin 0u <> 0u then raise ParsingFailureException
  else struct (Op.FCPSGN, ThreeOperands(frd, fra, frb))

/// An X-form floating-point "frD, frB" whose Rc bit names two opcodes.
let private parseFPUnary op opDot bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  if Bits.extract bin 20u 16u <> 0u then raise ParsingFailureException
  elif Bits.pick bin 0u = 0u then struct (op, TwoOperands(frd, frb))
  else struct (opDot, TwoOperands(frd, frb))

let parse3B bin =
  match Bits.extract bin 5u 1u with
  | 0xEu ->
    match Bits.extract bin 10u 6u with
    | 0x1Au -> parseFPUnary Op.FCFIDS Op.FCFIDSdot bin
    | 0x1Eu -> parseFPUnary Op.FCFIDUS Op.FCFIDUSdot bin
    | _ -> raise ParsingFailureException
  | 0x12u when Bits.extract bin 10u 6u = 0u ->
    parseFDIVSx bin
  | 0x14u when Bits.extract bin 10u 6u = 0u ->
    parseFSUBSx bin
  | 0x15u when Bits.extract bin 10u 6u = 0u ->
    parseFADDSx bin
  | 0x16u when Bits.extract bin 10u 6u = 0u ->
    parseFSQRTSx bin
  | 0x18u when Bits.extract bin 10u 6u = 0u ->
    parseFRESx bin
  | 0x19u ->
    parseFMULSx bin
  | 0x1Cu ->
    parseFMSUBSx bin
  | 0x1Du ->
    parseFMADDSx bin
  | 0x1Eu ->
    parseFNMSUBSx bin
  | 0x1Fu ->
    parseFNMADDSx bin
  | _ ->
    raise ParsingFailureException

let parseFCMPU bin =
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 22u 21u = 0u ->
    let crfd = getCondRegister (Bits.extract bin 25u 23u) |> OprReg
    let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
    let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.FCMPU, ThreeOperands(crfd, fra, frb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseFRSPx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FRSP, TwoOperands(frd, frb))
  | 0b1u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FRSPdot, TwoOperands(frd, frb))
  | _ ->
    raise ParsingFailureException

let parseFCTIWx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FCTIW, TwoOperands(frd, frb))
  | 0b1u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FCTIWdot, TwoOperands(frd, frb))
  | _ ->
    raise ParsingFailureException

let parseFCTIWZx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FCTIWZ, TwoOperands(frd, frb))
  | 0b1u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FCTIWZdot, TwoOperands(frd, frb))
  | _ ->
    raise ParsingFailureException

let parseFDIVx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.FDIV, ThreeOperands(frd, fra, frb))
  | _ (* 1 *) -> struct (Op.FDIVdot, ThreeOperands(frd, fra, frb))

let parseFSUBx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.FSUB, ThreeOperands(frd, fra, frb))
  | _ (* 1 *) -> struct (Op.FSUBdot, ThreeOperands(frd, fra, frb))

let parseFADDx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.FADD, ThreeOperands(frd, fra, frb))
  | _ (* 1 *) -> struct (Op.FADDdot, ThreeOperands(frd, fra, frb))

let parseFSQRTx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FSQRT, TwoOperands(frd, frb))
  | 0b1u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FSQRTdot, TwoOperands(frd, frb))
  | _ ->
    raise ParsingFailureException

let parseFSELx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  let frc = getFPRegister (Bits.extract bin 10u 6u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.FSEL, FourOperands(frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FSELdot, FourOperands(frd, fra, frc, frb))

let parseFMULx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frc = getFPRegister (Bits.extract bin 10u 6u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.FMUL, ThreeOperands(frd, fra, frc))
  | 0b1u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.FMULdot, ThreeOperands(frd, fra, frc))
  | _ ->
    raise ParsingFailureException

let parseFRSQRTEx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u when Bits.concat (Bits.extract bin 20u 16u)
                          (Bits.extract bin 10u 6u)
                          5 = 0u ->
    struct (Op.FRSQRTE, TwoOperands(frd, frb))
  | 0b1u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.FRSQRTEdot, TwoOperands(frd, frb))
  | _ ->
    raise ParsingFailureException

let parseFMSUBx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  let frc = getFPRegister (Bits.extract bin 10u 6u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.FMSUB, FourOperands(frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FMSUBdot, FourOperands(frd, fra, frc, frb))

let parseFMADDx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  let frc = getFPRegister (Bits.extract bin 10u 6u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.FMADD, FourOperands(frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FMADDdot, FourOperands(frd, fra, frc, frb))

let parseFNMSUBx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  let frc = getFPRegister (Bits.extract bin 10u 6u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.FNMSUB, FourOperands(frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FNMSUBdot, FourOperands(frd, fra, frc, frb))

let parseFNMADDx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  let frc = getFPRegister (Bits.extract bin 10u 6u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.FNMADD, FourOperands(frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FNMADDdot, FourOperands(frd, fra, frc, frb))

let parseFCMPO bin =
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 22u 21u = 0u ->
    let crfd = getCondRegister (Bits.extract bin 25u 23u) |> OprReg
    let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
    let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.FCMPO, ThreeOperands(crfd, fra, frb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseMTFSB1x bin =
  let crbd = getFPSCRBit (Bits.extract bin 25u 21u)
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 20u 11u = 0u ->
    (* FIXME: FPSCRegister *)
    struct (Op.MTFSB1, OneOperand crbd)
  | 0b1u when Bits.extract bin 20u 11u = 0u ->
    (* FIXME: FPSCRegister *)
    struct (Op.MTFSB1dot, OneOperand crbd)
  | _ ->
    raise ParsingFailureException

let parseFNEGx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FNEG, TwoOperands(frd, frb))
  | 0b1u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FNEGdot, TwoOperands(frd, frb))
  | _ ->
    raise ParsingFailureException

let parseMCRFS bin =
  match Bits.pick bin 0u with
  | 0b0u when Bits.concat (Bits.extract bin 22u 21u)
                          (Bits.extract bin 17u 11u)
                          2 = 0u ->
    let crfd = getCondRegister (Bits.extract bin 25u 23u) |> OprReg
    let crfs = getCondRegister (Bits.extract bin 20u 18u) |> OprReg
    struct (Op.MCRFS, TwoOperands(crfd, crfs))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseMTFSB0x bin =
  let crbd = getFPSCRBit (Bits.extract bin 25u 21u)
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 20u 11u = 0u ->
    (* FIXME: FPSCRegister *)
    struct (Op.MTFSB0, OneOperand crbd)
  | 0b1u when Bits.extract bin 20u 11u = 0u ->
    (* FIXME: FPSCRegister *)
    struct (Op.MTFSB0dot, OneOperand crbd)
  | _ ->
    raise ParsingFailureException

let parseFMRx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FMR, TwoOperands(frd, frb))
  | 0b1u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FMRdot, TwoOperands(frd, frb))
  | _ ->
    raise ParsingFailureException

let parseMTFSFIx bin =
  let crfd = Bits.extract bin 25u 23u |> uint64 |> OprImm
  let imm = Bits.extract bin 15u 12u |> uint64 |> OprImm
  match Bits.pick bin 0u with
  | 0b0u when Bits.concat (Bits.extract bin 22u 16u)
                          (Bits.pick bin 11u)
                          7 = 0u ->
    struct (Op.MTFSFI, TwoOperands(crfd, imm))
  | 0b1u when Bits.concat (Bits.extract bin 22u 16u)
                          (Bits.pick bin 11u)
                          7 = 0u ->
    struct (Op.MTFSFIdot, TwoOperands(crfd, imm))
  | _ ->
    raise ParsingFailureException

let parseFNABSx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FNABS, TwoOperands(frd, frb))
  | 0b1u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FNABSdot, TwoOperands(frd, frb))
  | _ ->
    raise ParsingFailureException

let parseFABSx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FABS, TwoOperands(frd, frb))
  | 0b1u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FABSdot, TwoOperands(frd, frb))
  | _ ->
    raise ParsingFailureException

let parseMFFSx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 20u 11u = 0u ->
    struct (Op.MFFS, OneOperand frd)
  | 0b1u when Bits.extract bin 20u 11u = 0u ->
    struct (Op.MFFSdot, OneOperand frd)
  (* mffsl reads the FPSCR's control and status bits and leaves the rest zero;
     reading the whole register covers what it asks for. *)
  | 0b0u when Bits.extract bin 20u 16u = 24u && Bits.extract bin 15u 11u = 0u ->
    struct (Op.MFFSL, OneOperand frd)
  | _ ->
    raise ParsingFailureException

let parseMTFSFx bin =
  let fm = Bits.extract bin 24u 17u |> uint64 |> OprImm
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  (* FIXME: PowerISA v3.1 *)
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.MTFSF, TwoOperands(fm, frb))
  | 0b1u -> struct (Op.MTFSFdot, TwoOperands(fm, frb))
  | _ -> raise ParsingFailureException

let parse3F bin =
  match Bits.extract bin 5u 1u with
  | 0x0u ->
    match Bits.extract bin 10u 6u with
    | 0x0u -> parseFCMPU bin
    | 0x1u -> parseFCMPO bin
    | 0x2u -> parseMCRFS bin
    | _ -> raise ParsingFailureException
  | 0x6u ->
    (* FIXME: FPSCRegister *)
    match Bits.extract bin 10u 6u with
    | 0x1u -> parseMTFSB1x bin
    (* FIXME: FPSCRegister *)
    | 0x2u -> parseMTFSB0x bin
    | 0x4u -> parseMTFSFIx bin
    | _ -> raise ParsingFailureException
  | 0x7u ->
    match Bits.extract bin 10u 6u with
    | 0x12u -> parseMFFSx bin
    | 0x16u -> parseMTFSFx bin
    | _ -> raise ParsingFailureException
  | 0x8u ->
    match Bits.extract bin 10u 6u with
    | 0x0u -> parseFCPSGN bin
    | 0x1u -> parseFNEGx bin
    | 0x2u -> parseFMRx bin
    | 0x4u -> parseFNABSx bin
    | 0x8u -> parseFABSx bin
    | 0xCu -> parseFPUnary Op.FRIN Op.FRINdot bin
    | 0xDu -> parseFPUnary Op.FRIZ Op.FRIZdot bin
    | 0xEu -> parseFPUnary Op.FRIP Op.FRIPdot bin
    | 0xFu -> parseFPUnary Op.FRIM Op.FRIMdot bin
    | _ -> raise ParsingFailureException
  | 0xCu when Bits.extract bin 10u 6u = 0u ->
    parseFRSPx bin
  | 0xEu ->
    match Bits.extract bin 10u 6u with
    | 0x0u -> parseFCTIWx bin
    | 0x4u -> parseFPUnary Op.FCTIWU Op.FCTIWUdot bin
    | 0x19u -> parseFPUnary Op.FCTID Op.FCTIDdot bin
    | 0x1Au -> parseFPUnary Op.FCFID Op.FCFIDdot bin
    | 0x1Du -> parseFPUnary Op.FCTIDU Op.FCTIDUdot bin
    | 0x1Eu -> parseFPUnary Op.FCFIDU Op.FCFIDUdot bin
    | _ -> raise ParsingFailureException
  | 0xFu ->
    match Bits.extract bin 10u 6u with
    | 0x0u -> parseFCTIWZx bin
    | 0x4u -> parseFPUnary Op.FCTIWUZ Op.FCTIWUZdot bin
    | 0x19u -> parseFPUnary Op.FCTIDZ Op.FCTIDZdot bin
    | 0x1Du -> parseFPUnary Op.FCTIDUZ Op.FCTIDUZdot bin
    | _ -> raise ParsingFailureException
  | 0x12u when Bits.extract bin 10u 6u = 0u ->
    parseFDIVx bin
  | 0x14u when Bits.extract bin 10u 6u = 0u ->
    parseFSUBx bin
  | 0x15u when Bits.extract bin 10u 6u = 0u ->
    parseFADDx bin
  | 0x16u when Bits.extract bin 10u 6u = 0u ->
    parseFSQRTx bin
  | 0x17u ->
    parseFSELx bin
  | 0x19u ->
    parseFMULx bin
  | 0x1Au ->
    parseFRSQRTEx bin
  | 0x1Cu ->
    parseFMSUBx bin
  | 0x1Du ->
    parseFMADDx bin
  | 0x1Eu ->
    parseFNMSUBx bin
  | 0x1Fu ->
    parseFNMADDx bin
  | _ ->
    raise ParsingFailureException

/// tdi, whose TO field selects the comparison the same way twi's does.
let private parseTDI bitLen bin =
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let value = simm16 bitLen bin |> OprImm
  let tO = Bits.extract bin 25u 21u |> uint64 |> OprImm
  struct (Op.TDI, ThreeOperands(tO, ra, value))

/// The displacement of a DS-form load or store: a 14-bit signed field that the
/// encoding leaves scaled by four.
let private dsDisp bin =
  Bits.extract bin 15u 2u <<< 2 |> uint64 |> Bits.signExtend 16 64
  |> int64 |> int32

/// The DS-form loads: ld, ldu and lwa, told apart by the low two bits.
let private parse3A bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let mem = (dsDisp bin, ra) |> OprMem (* ds (rA) *)
  match Bits.extract bin 1u 0u with
  | 0b00u -> struct (Op.LD, TwoOperands(rd, mem))
  | 0b01u -> struct (Op.LDU, TwoOperands(rd, mem))
  | 0b10u -> struct (Op.LWA, TwoOperands(rd, mem))
  | _ (* 11 *) -> raise ParsingFailureException

/// The DS-form stores: std and stdu. The remaining encoding is stq, which is
/// not modeled.
let private parse3E bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let mem = (dsDisp bin, ra) |> OprMem (* ds (rA) *)
  match Bits.extract bin 1u 0u with
  | 0b00u -> struct (Op.STD, TwoOperands(rs, mem))
  | 0b01u -> struct (Op.STDU, TwoOperands(rs, mem))
  | _ -> raise ParsingFailureException

/// The rotate-left-doubleword forms. In an MD form the six-bit mask bound and
/// shift amount are both split: the bound keeps its high bit in bit 5, and the
/// shift its sixth bit in bit 1. An MDS form takes the shift from rB instead,
/// so only the bound is split.
let private parse1E bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let bound = (Bits.pick bin 5u <<< 5) ||| Bits.extract bin 10u 6u
  let bound = bound |> uint64 |> OprImm
  let sh = (Bits.pick bin 1u <<< 5) ||| Bits.extract bin 15u 11u
  let sh = sh |> uint64 |> OprImm
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  let dot = Bits.pick bin 0u = 1u
  match Bits.extract bin 4u 2u with
  | 0b000u ->
    let op = if dot then Op.RLDICLdot else Op.RLDICL
    struct (op, FourOperands(ra, rs, sh, bound))
  | 0b001u ->
    let op = if dot then Op.RLDICRdot else Op.RLDICR
    struct (op, FourOperands(ra, rs, sh, bound))
  | 0b010u ->
    let op = if dot then Op.RLDICdot else Op.RLDIC
    struct (op, FourOperands(ra, rs, sh, bound))
  | 0b011u ->
    let op = if dot then Op.RLDIMIdot else Op.RLDIMI
    struct (op, FourOperands(ra, rs, sh, bound))
  | 0b100u when Bits.pick bin 1u = 0u ->
    let op = if dot then Op.RLDCLdot else Op.RLDCL
    struct (op, FourOperands(ra, rs, rb, bound))
  | 0b100u ->
    let op = if dot then Op.RLDCRdot else Op.RLDCR
    struct (op, FourOperands(ra, rs, rb, bound))
  | _ ->
    raise ParsingFailureException

(* The primary opcodes below hold only 64-bit forms, so a 32-bit guest must not
   recognize them; the extended-opcode space of 0x1F is shared, and parse1F
   takes the word size to decide how much of it to look at. *)
let private parseInstruction bitLen bin addr =
  match Bits.extract bin 31u 26u with
  | 0x2u when bitLen = 64 -> parseTDI bitLen bin
  | 0x3u -> parseTWI bitLen bin
  | 0x4u -> parse04 bin
  | 0x7u -> parseMULLI bitLen bin
  | 0x8u -> parseSUBFIC bitLen bin
  | 0xAu -> parseCMPLI bin
  | 0xBu -> parseCMPI bitLen bin
  | 0xCu -> parseADDIC bitLen bin
  | 0xDu -> parseADDICdot bitLen bin
  | 0xEu -> parseADDI bitLen bin
  | 0xFu -> parseADDIS bitLen bin
  | 0x10u -> parseBCx bitLen bin
  | 0x11u when Bits.pick bin 0u = 0u -> parseSC bin
  | 0x12u -> parseBx bitLen bin addr
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
  | 0x1Eu when bitLen = 64 -> parse1E bin
  | 0x1Fu -> parse1F (bitLen = 64) bin
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
  | 0x3Au when bitLen = 64 -> parse3A bin
  | 0x3Bu -> parse3B bin
  | 0x3Cu -> parse3C bin
  | 0x3Eu when bitLen = 64 -> parse3E bin
  | 0x3Fu -> parse3F bin
  | _ -> raise ParsingFailureException

let parse lifter (span: ByteSpan) (reader: IBinReader) addr rt =
  let bin = reader.ReadUInt32(span, 0)
  let struct (opcode, operands) = parseInstruction (int rt) bin addr
  Instruction(addr, 4u, opcode, operands, rt, 0UL, lifter)

// vim: set tw=80 sts=2 sw=2:
