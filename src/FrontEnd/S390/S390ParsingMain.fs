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

module internal B2R2.FrontEnd.S390.ParsingMain

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.S390
open B2R2.FrontEnd.S390.Helper

let parseInstLenOne (bin: uint16) =
  match bin with
  | 0x0101us -> Op.PR, NoOperand, Fmt.E
  | 0x0102us -> Op.UPT, NoOperand, Fmt.E
  | 0x0104us -> Op.PTFF, NoOperand, Fmt.E
  | 0x0107us -> Op.SCKPF, NoOperand, Fmt.E
  | 0x010Aus -> Op.PFPO, NoOperand, Fmt.E
  | 0x010Bus -> Op.TAM, NoOperand, Fmt.E
  | 0x010Cus -> Op.SAM24, NoOperand, Fmt.E
  | 0x010Dus -> Op.SAM31, NoOperand, Fmt.E
  | 0x010Eus -> Op.SAM64, NoOperand, Fmt.E
  | 0x01FFus -> Op.TRAP2, NoOperand, Fmt.E
  | _ ->
    match extract16 bin 0 7 with
    | 0x0Aus -> Op.SVC, getUImm8to15 bin, Fmt.I
    | 0x04us -> Op.SPM, getGR8to11 bin, Fmt.RR
    | 0x05us -> Op.BALR, getGR8GR12 bin, Fmt.RR
    | 0x06us -> Op.BCTR, getGR8GR12 bin, Fmt.RR
    | 0x07us -> Op.BCR, getMGR8GR12 bin, Fmt.RR
    | 0x0Bus -> Op.BSM, getGR8GR12 bin, Fmt.RR
    | 0x0Cus -> Op.BASSM, getGR8GR12 bin, Fmt.RR
    | 0x0Dus -> Op.BASR, getGR8GR12 bin, Fmt.RR
    | 0x0Eus -> Op.MVCL, getGR8GR12 bin, Fmt.RR
    | 0x0Fus -> Op.CLCL, getGR8GR12 bin, Fmt.RR
    | 0x10us -> Op.LPR, getGR8GR12 bin, Fmt.RR
    | 0x11us -> Op.LNR, getGR8GR12 bin, Fmt.RR
    | 0x12us -> Op.LTR, getGR8GR12 bin, Fmt.RR
    | 0x13us -> Op.LCR, getGR8GR12 bin, Fmt.RR
    | 0x14us -> Op.NR, getGR8GR12 bin, Fmt.RR
    | 0x15us -> Op.CLR, getGR8GR12 bin, Fmt.RR
    | 0x16us -> Op.OR, getGR8GR12 bin, Fmt.RR
    | 0x17us -> Op.XR, getGR8GR12 bin, Fmt.RR
    | 0x18us -> Op.LR, getGR8GR12 bin, Fmt.RR
    | 0x19us -> Op.CR, getGR8GR12 bin, Fmt.RR
    | 0x1Aus -> Op.AR, getGR8GR12 bin, Fmt.RR
    | 0x1Bus -> Op.SR, getGR8GR12 bin, Fmt.RR
    | 0x1Cus -> Op.MR, getGR8GR12 bin, Fmt.RR
    | 0x1Dus -> Op.DR, getGR8GR12 bin, Fmt.RR
    | 0x1Eus -> Op.ALR, getGR8GR12 bin, Fmt.RR
    | 0x1Fus -> Op.SLR, getGR8GR12 bin, Fmt.RR
    | 0x20us -> Op.LPDR, getFPR8FPR12 bin, Fmt.RR
    | 0x21us -> Op.LNDR, getFPR8FPR12 bin, Fmt.RR
    | 0x22us -> Op.LTDR, getFPR8FPR12 bin, Fmt.RR
    | 0x23us -> Op.LCDR, getFPR8FPR12 bin, Fmt.RR
    | 0x24us -> Op.HDR, getFPR8FPR12 bin, Fmt.RR
    | 0x25us -> Op.LDXR, getFPR8FPR12 bin, Fmt.RR
    | 0x26us -> Op.MXR, getFPR8FPR12 bin, Fmt.RR
    | 0x27us -> Op.MXDR, getFPR8FPR12 bin, Fmt.RR
    | 0x28us -> Op.LDR, getFPR8FPR12 bin, Fmt.RR
    | 0x29us -> Op.CDR, getFPR8FPR12 bin, Fmt.RR
    | 0x2Aus -> Op.ADR, getFPR8FPR12 bin, Fmt.RR
    | 0x2Bus -> Op.SDR, getFPR8FPR12 bin, Fmt.RR
    | 0x2Cus -> Op.MDR, getFPR8FPR12 bin, Fmt.RR
    | 0x2Dus -> Op.DDR, getFPR8FPR12 bin, Fmt.RR
    | 0x2Eus -> Op.AWR, getFPR8FPR12 bin, Fmt.RR
    | 0x2Fus -> Op.SWR, getFPR8FPR12 bin, Fmt.RR
    | 0x30us -> Op.LPER, getFPR8FPR12 bin, Fmt.RR
    | 0x31us -> Op.LNER, getFPR8FPR12 bin, Fmt.RR
    | 0x32us -> Op.LTER, getFPR8FPR12 bin, Fmt.RR
    | 0x33us -> Op.LCER, getFPR8FPR12 bin, Fmt.RR
    | 0x34us -> Op.HER, getFPR8FPR12 bin, Fmt.RR
    | 0x35us -> Op.LEDR, getFPR8FPR12 bin, Fmt.RR
    | 0x36us -> Op.AXR, getFPR8FPR12 bin, Fmt.RR
    | 0x37us -> Op.SXR, getFPR8FPR12 bin, Fmt.RR
    | 0x38us -> Op.LER, getFPR8FPR12 bin, Fmt.RR
    | 0x39us -> Op.CER, getFPR8FPR12 bin, Fmt.RR
    | 0x3Aus -> Op.AER, getFPR8FPR12 bin, Fmt.RR
    | 0x3Bus -> Op.SER, getFPR8FPR12 bin, Fmt.RR
    | 0x3Cus -> Op.MDER, getFPR8FPR12 bin, Fmt.RR
    | 0x3Dus -> Op.DER, getFPR8FPR12 bin, Fmt.RR
    | 0x3Eus -> Op.AUR, getFPR8FPR12 bin, Fmt.RR
    | 0x3Fus -> Op.SUR, getFPR8FPR12 bin, Fmt.RR
    | _ -> Op.InvalOp, NoOperand, Fmt.Invalid

let parseInstLenTwo (bin: uint32) =
  let opcode1 = extract32 bin 0 7 |> uint16
  match opcode1 with
  | 0x40us -> Op.STH, getGR8WIdx12M16D20 bin, Fmt.RX
  | 0x41us -> Op.LA, getGR8WIdx12M16D20 bin, Fmt.RX
  | 0x42us -> Op.STC, getGR8WIdx12M16D20 bin, Fmt.RX
  | 0x43us -> Op.IC, getGR8WIdx12M16D20 bin, Fmt.RX
  | 0x44us -> Op.EX, getGR8WIdx12M16D20 bin, Fmt.RX
  | 0x45us -> Op.BAL, getGR8WIdx12M16D20 bin, Fmt.RX
  | 0x46us -> Op.BCT, getGR8WIdx12M16D20 bin, Fmt.RX
  | 0x47us -> Op.BC, getMask8WIdx12M16D20 bin, Fmt.RX
  | 0x48us -> Op.LH, getGR8WIdx12M16D20 bin, Fmt.RX
  | 0x49us -> Op.CH, getGR8WIdx12M16D20 bin, Fmt.RX
  | 0x4Aus -> Op.AH, getGR8WIdx12M16D20 bin, Fmt.RX
  | 0x4Bus -> Op.SH, getGR8WIdx12M16D20 bin, Fmt.RX
  | 0x4Cus -> Op.MH, getGR8WIdx12M16D20 bin, Fmt.RX
  | 0x4Dus -> Op.BAS, getGR8WIdx12M16D20 bin, Fmt.RX
  | 0x4Eus -> Op.CVD, getGR8WIdx12M16D20 bin, Fmt.RX
  | 0x4Fus -> Op.CVB, getGR8WIdx12M16D20 bin, Fmt.RX
  | 0x50us -> Op.ST, getGR8WIdx12M16D20 bin, Fmt.RX
  | 0x51us -> Op.LAE, getAR8WIdx12M16D20 bin, Fmt.RX
  | 0x54us -> Op.N, getGR8WIdx12M16D20 bin, Fmt.RX
  | 0x55us -> Op.CL, getGR8WIdx12M16D20 bin, Fmt.RX
  | 0x56us -> Op.O, getGR8WIdx12M16D20 bin, Fmt.RX
  | 0x57us -> Op.X, getGR8WIdx12M16D20 bin, Fmt.RX
  | 0x58us -> Op.L, getGR8WIdx12M16D20 bin, Fmt.RX
  | 0x59us -> Op.C, getGR8WIdx12M16D20 bin, Fmt.RX
  | 0x5Aus -> Op.A, getGR8WIdx12M16D20 bin, Fmt.RX
  | 0x5Bus -> Op.S, getGR8WIdx12M16D20 bin, Fmt.RX
  | 0x5Cus -> Op.M, getGR8WIdx12M16D20 bin, Fmt.RX
  | 0x5Dus -> Op.D, getGR8WIdx12M16D20 bin, Fmt.RX
  | 0x5Eus -> Op.AL, getGR8WIdx12M16D20 bin, Fmt.RX
  | 0x5Fus -> Op.SL, getGR8WIdx12M16D20 bin, Fmt.RX
  | 0x60us -> Op.STD, getFPR8WIdx12M16D20 bin, Fmt.RX
  | 0x67us -> Op.MXD, getFPR8WIdx12M16D20 bin, Fmt.RX
  | 0x68us -> Op.LD, getFPR8WIdx12M16D20 bin, Fmt.RX
  | 0x69us -> Op.CD, getFPR8WIdx12M16D20 bin, Fmt.RX
  | 0x6Aus -> Op.AD, getFPR8WIdx12M16D20 bin, Fmt.RX
  | 0x6Bus -> Op.SD, getFPR8WIdx12M16D20 bin, Fmt.RX
  | 0x6Cus -> Op.MD, getFPR8WIdx12M16D20 bin, Fmt.RX
  | 0x6Dus -> Op.DD, getFPR8WIdx12M16D20 bin, Fmt.RX
  | 0x6Eus -> Op.AW, getFPR8WIdx12M16D20 bin, Fmt.RX
  | 0x6Fus -> Op.SW, getFPR8WIdx12M16D20 bin, Fmt.RX
  | 0x70us -> Op.STE, getGR8WIdx12M16D20 bin, Fmt.RX
  | 0x71us -> Op.MS, getGR8WIdx12M16D20 bin, Fmt.RX
  | 0x78us -> Op.LE, getFPR8WIdx12M16D20 bin, Fmt.RX
  | 0x79us -> Op.CE, getFPR8WIdx12M16D20 bin, Fmt.RX
  | 0x7Aus -> Op.AE, getFPR8WIdx12M16D20 bin, Fmt.RX
  | 0x7Bus -> Op.SE, getFPR8WIdx12M16D20 bin, Fmt.RX
  | 0x7Cus -> Op.MDE, getFPR8WIdx12M16D20 bin, Fmt.RX
  | 0x7Dus -> Op.DE, getFPR8WIdx12M16D20 bin, Fmt.RX
  | 0x7Eus -> Op.AU, getFPR8WIdx12M16D20 bin, Fmt.RX
  | 0x7Fus -> Op.SU, getFPR8WIdx12M16D20 bin, Fmt.RX
  | 0xB1us -> Op.LRA, getGR8WIdx12M16D20 bin, Fmt.RX
  | 0x84us -> Op.BRXH, getGR8SImmRUpperGR12 bin, Fmt.RSI
  | 0x85us -> Op.BRXLE, getGR8SImmRUpperGR12 bin, Fmt.RSI
  | 0x86us -> Op.BXH, getGR8WNoneM16D20GR12 bin, Fmt.RS
  | 0x87us -> Op.BXLE, getGR8WNoneM16D20GR12 bin, Fmt.RS
  | 0x88us -> Op.SRL, getGR8WNoneM16D20 bin, Fmt.RS
  | 0x89us -> Op.SLL, getGR8WNoneM16D20 bin, Fmt.RS
  | 0x8Aus -> Op.SRA, getGR8WNoneM16D20 bin, Fmt.RS
  | 0x8Bus -> Op.SLA, getGR8WNoneM16D20 bin, Fmt.RS
  | 0x8Cus -> Op.SRDL, getGR8WNoneM16D20 bin, Fmt.RS
  | 0x8Dus -> Op.SLDL, getGR8WNoneM16D20 bin, Fmt.RS
  | 0x8Eus -> Op.SRDA, getGR8WNoneM16D20 bin, Fmt.RS
  | 0x8Fus -> Op.SLDA, getGR8WNoneM16D20 bin, Fmt.RS
  | 0x90us -> Op.STM, getGR8WNoneM16D20GR12 bin, Fmt.RS
  | 0x98us -> Op.LM, getGR8WNoneM16D20GR12 bin, Fmt.RS
  | 0x99us -> Op.TRACE, getGR8WNoneM16D20GR12 bin, Fmt.RS
  | 0x9Aus -> Op.LAM, getAR8WNoneM16D20AR12 bin, Fmt.RS
  | 0x9Bus -> Op.STAM, getAR8WNoneM16D20AR12 bin, Fmt.RS
  | 0xA8us -> Op.MVCLE, getGR8WNoneM16D20GR12 bin, Fmt.RS
  | 0xA9us -> Op.CLCLE, getGR8WNoneM16D20GR12 bin, Fmt.RS
  | 0xAEus -> Op.SIGP, getGR8WNoneM16D20GR12 bin, Fmt.RS
  | 0xB6us -> Op.STCTL, getCR8WNoneM16D20CR12 bin, Fmt.RS
  | 0xB7us -> Op.LCTL, getCR8WNoneM16D20CR12 bin, Fmt.RS
  | 0xBAus -> Op.CS, getGR8WNoneM16D20GR12 bin, Fmt.RS
  | 0xBBus -> Op.CDS, getGR8WNoneM16D20GR12 bin, Fmt.RS
  | 0xBDus -> Op.CLM, getGR8WNoneM16D20Mask12 bin, Fmt.RS
  | 0xBEus -> Op.STCM, getGR8WNoneM16D20Mask12 bin, Fmt.RS
  | 0xBFus -> Op.ICM, getGR8WNoneM16D20Mask12 bin, Fmt.RS
  | 0x80us -> Op.SSM, getNoneM16D20 bin, Fmt.SI
  | 0x82us -> Op.LPSW, getNoneM16D20 bin, Fmt.SI
  | 0x91us -> Op.TM, getNoneM16D20UImm8 bin, Fmt.SI
  | 0x92us -> Op.MVI, getNoneM16D20UImm8 bin, Fmt.SI
  | 0x93us -> Op.TS, getNoneM16D20 bin, Fmt.SI
  | 0x94us -> Op.NI, getNoneM16D20UImm8 bin, Fmt.SI
  | 0x95us -> Op.CLI, getNoneM16D20UImm8 bin, Fmt.SI
  | 0x96us -> Op.OI, getNoneM16D20UImm8 bin, Fmt.SI
  | 0x97us -> Op.XI, getNoneM16D20UImm8 bin, Fmt.SI
  | 0xACus -> Op.STNSM, getNoneM16D20UImm8 bin, Fmt.SI
  | 0xADus -> Op.STOSM, getNoneM16D20UImm8 bin, Fmt.SI
  | 0xAFus -> Op.MC, getNoneM16D20UImm8 bin, Fmt.SI
  | _ ->
    match extract32 bin 0 15 |> uint16 with
    | 0xB2FAus ->
      let op1 = BitVector.OfUInt32 (extract32 bin 24 27) 4<rt> |> ImmU4
      let op2 = BitVector.OfUInt32 (extract32 bin 28 31) 4<rt> |> ImmU4
      Op.NIAI, TwoOperands (OpImm op1, OpImm op2), Fmt.IE
    | 0xB30Eus -> Op.MAEBR, getFPR16FPR28FPR24 bin, Fmt.RRD
    | 0xB30Fus -> Op.MSEBR, getFPR16FPR28FPR24 bin, Fmt.RRD
    | 0xB31Eus -> Op.MADBR, getFPR16FPR28FPR24 bin, Fmt.RRD
    | 0xB31Fus -> Op.MSDBR, getFPR16FPR28FPR24 bin, Fmt.RRD
    | 0xB32Eus -> Op.MAER, getFPR16FPR28FPR24 bin, Fmt.RRD
    | 0xB32Fus -> Op.MSER, getFPR16FPR28FPR24 bin, Fmt.RRD
    | 0xB338us -> Op.MAYLR, getFPR16FPR28FPR24 bin, Fmt.RRD
    | 0xB339us -> Op.MYLR, getFPR16FPR28FPR24 bin, Fmt.RRD
    | 0xB33Aus -> Op.MAYR, getFPR16FPR28FPR24 bin, Fmt.RRD
    | 0xB33Bus -> Op.MYR, getFPR16FPR28FPR24 bin, Fmt.RRD
    | 0xB33Cus -> Op.MAYHR, getFPR16FPR28FPR24 bin, Fmt.RRD
    | 0xB33Dus -> Op.MYHR, getFPR16FPR28FPR24 bin, Fmt.RRD
    | 0xB33Eus -> Op.MADR, getFPR16FPR28FPR24 bin, Fmt.RRD
    | 0xB33Fus -> Op.MSDR, getFPR16FPR28FPR24 bin, Fmt.RRD
    | 0xB200us -> Op.LBEAR, getNoneM16D20 bin, Fmt.S
    | 0xB201us -> Op.STBEAR, getNoneM16D20 bin, Fmt.S
    | 0xB202us -> Op.STIDP, getNoneM16D20 bin, Fmt.S
    | 0xB204us -> Op.SCK, getNoneM16D20 bin, Fmt.S
    | 0xB205us -> Op.STCK, getNoneM16D20 bin, Fmt.S
    | 0xB206us -> Op.SCKC, getNoneM16D20 bin, Fmt.S
    | 0xB207us -> Op.STCKC, getNoneM16D20 bin, Fmt.S
    | 0xB208us -> Op.SPT, getNoneM16D20 bin, Fmt.S
    | 0xB209us -> Op.STPT, getNoneM16D20 bin, Fmt.S
    | 0xB20Aus -> Op.SPKA, getNoneM16D20 bin, Fmt.S
    | 0xB20Bus -> Op.IPK, NoOperand, Fmt.S
    | 0xB20Dus -> Op.PTLB, NoOperand, Fmt.S
    | 0xB210us -> Op.SPX, getNoneM16D20 bin, Fmt.S
    | 0xB211us -> Op.STPX, getNoneM16D20 bin, Fmt.S
    | 0xB212us -> Op.STAP, getNoneM16D20 bin, Fmt.S
    | 0xB218us -> Op.PC, getNoneM16D20 bin, Fmt.S
    | 0xB219us -> Op.SAC, getNoneM16D20 bin, Fmt.S
    | 0xB21Aus -> Op.CFC, getNoneM16D20 bin, Fmt.S
    | 0xB230us -> Op.CSCH, NoOperand, Fmt.S
    | 0xB231us -> Op.HSCH, NoOperand, Fmt.S
    | 0xB232us -> Op.MSCH, getNoneM16D20 bin, Fmt.S
    | 0xB233us -> Op.SSCH, getNoneM16D20 bin, Fmt.S
    | 0xB234us -> Op.STSCH, getNoneM16D20 bin, Fmt.S
    | 0xB235us -> Op.TSCH, getNoneM16D20 bin, Fmt.S
    | 0xB236us -> Op.TPI, getNoneM16D20 bin, Fmt.S
    | 0xB237us -> Op.SAL, NoOperand, Fmt.S
    | 0xB238us -> Op.RSCH, NoOperand, Fmt.S
    | 0xB239us -> Op.STCRW, getNoneM16D20 bin, Fmt.S
    | 0xB23Aus -> Op.STCPS, getNoneM16D20 bin, Fmt.S
    | 0xB23Bus -> Op.RCHP, NoOperand, Fmt.S
    | 0xB23Cus -> Op.SCHM, NoOperand, Fmt.S
    | 0xB276us -> Op.XSCH, NoOperand, Fmt.S
    | 0xB277us -> Op.RP, getNoneM16D20 bin, Fmt.S
    | 0xB278us -> Op.STCKE, getNoneM16D20 bin, Fmt.S
    | 0xB279us -> Op.SACF, getNoneM16D20 bin, Fmt.S
    | 0xB27Cus -> Op.STCKF, getNoneM16D20 bin, Fmt.S
    | 0xB27Dus -> Op.STSI, getNoneM16D20 bin, Fmt.S
    | 0xB28Fus -> Op.QPACI, getNoneM16D20 bin, Fmt.S
    | 0xB299us -> Op.SRNM, getNoneM16D20 bin, Fmt.S
    | 0xB29Cus -> Op.STFPC, getNoneM16D20 bin, Fmt.S
    | 0xB29Dus -> Op.LFPC, getNoneM16D20 bin, Fmt.S
    | 0xB2B0us -> Op.STFLE, getNoneM16D20 bin, Fmt.S
    | 0xB2B1us -> Op.STFL, getNoneM16D20 bin, Fmt.S
    | 0xB2B2us -> Op.LPSWE, getNoneM16D20 bin, Fmt.S
    | 0xB2B8us -> Op.SRNMB, getNoneM16D20 bin, Fmt.S
    | 0xB2B9us -> Op.SRNMT, getNoneM16D20 bin, Fmt.S
    | 0xB2BDus -> Op.LFAS, getNoneM16D20 bin, Fmt.S
    | 0xB2F8us -> Op.TEND, NoOperand, Fmt.S
    | 0xB2FCus -> Op.TABORT,getNoneM16D20 bin, Fmt.S
    | 0xB2FFus -> Op.TRAP4, getNoneM16D20 bin, Fmt.S
    | 0xB222us -> Op.IPM, getGR24to27 bin, Fmt.RRE
    | 0xB223us -> Op.IVSK, getGR24GR28 bin, Fmt.RRE
    | 0xB224us -> Op.IAC, getGR24to27 bin, Fmt.RRE
    | 0xB225us -> Op.SSAR, getGR24to27 bin, Fmt.RRE
    | 0xB226us -> Op.EPAR, getGR24to27 bin, Fmt.RRE
    | 0xB227us -> Op.ESAR, getGR24to27 bin, Fmt.RRE
    | 0xB228us -> Op.PT, getGR24GR28 bin, Fmt.RRE
    | 0xB229us -> Op.ISKE, getGR24GR28 bin, Fmt.RRE
    | 0xB22Aus -> Op.RRBE, getGR24GR28 bin, Fmt.RRE
    | 0xB22Cus -> Op.TB, getGR24GR28 bin, Fmt.RRE
    | 0xB22Dus -> Op.DXR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB22Eus -> Op.PGIN, getGR24GR28 bin, Fmt.RRE
    | 0xB22Fus -> Op.PGOUT, getGR24GR28 bin, Fmt.RRE
    | 0xB240us -> Op.BAKR, getGR24GR28 bin, Fmt.RRE
    | 0xB241us -> Op.CKSM, getGR24GR28 bin, Fmt.RRE
    | 0xB244us -> Op.SQDR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB245us -> Op.SQER, getFPR24FPR28 bin, Fmt.RRE
    | 0xB246us -> Op.STURA, getGR24GR28 bin, Fmt.RRE
    | 0xB247us -> Op.MSTA, getGR24to27 bin, Fmt.RRE
    | 0xB248us -> Op.PALB, NoOperand, Fmt.RRE
    | 0xB249us -> Op.EREG, getAR24AR28 bin, Fmt.RRE
    | 0xB24Aus -> Op.ESTA, getGR24GR28 bin, Fmt.RRE
    | 0xB24Bus -> Op.LURA, getGR24GR28 bin, Fmt.RRE
    | 0xB24Cus -> Op.TAR, getAR24GR28 bin, Fmt.RRE
    | 0xB24Dus -> Op.CPYA, getAR24AR28 bin, Fmt.RRE
    | 0xB24Eus -> Op.SAR, getAR24GR28 bin, Fmt.RRE
    | 0xB24Fus -> Op.EAR, getGR24AR28 bin, Fmt.RRE
    | 0xB250us -> Op.CSP, getGR24GR28 bin, Fmt.RRE
    | 0xB252us -> Op.MSR, getGR24GR28 bin, Fmt.RRE
    | 0xB254us -> Op.MVPG, getGR24GR28 bin, Fmt.RRE
    | 0xB255us -> Op.MVST, getGR24GR28 bin, Fmt.RRE
    | 0xB257us -> Op.CUSE, getGR24GR28 bin, Fmt.RRE
    | 0xB258us -> Op.BSG, getGR24GR28 bin, Fmt.RRE
    | 0xB25Aus -> Op.BSA, getGR24GR28 bin, Fmt.RRE
    | 0xB25Dus -> Op.CLST, getGR24GR28 bin, Fmt.RRE
    | 0xB25Eus -> Op.SRST, getGR24GR28 bin, Fmt.RRE
    | 0xB263us -> Op.CMPSC, getGR24GR28 bin, Fmt.RRE
    | 0xB2A5us -> Op.TRE, getGR24GR28 bin, Fmt.RRE
    | 0xB2A6us when extract32 bin 16 23 = 0u ->
      Op.CUUTF, getGR24GR28 bin, Fmt.RRE
    | 0xB2A7us when extract32 bin 16 23 = 0u ->
      Op.CUTFU, getGR24GR28 bin, Fmt.RRE
    | 0xB2ECus -> Op.ETND, getGR24to27 bin, Fmt.RRE
    | 0xB300us -> Op.LPEBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB301us -> Op.LNEBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB302us -> Op.LTEBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB303us -> Op.LCEBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB304us -> Op.LDEBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB305us -> Op.LXDBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB306us -> Op.LXEBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB307us -> Op.MXDBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB308us -> Op.KEBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB309us -> Op.CEBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB30Aus -> Op.AEBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB30Bus -> Op.SEBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB30Cus -> Op.MDEBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB30Dus -> Op.DEBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB310us -> Op.LPDBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB311us -> Op.LNDBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB312us -> Op.LTDBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB313us -> Op.LCDBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB314us -> Op.SQEBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB315us -> Op.SQDBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB316us -> Op.SQXBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB317us -> Op.MEEBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB318us -> Op.KDBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB319us -> Op.CDBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB31Aus -> Op.ADBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB31Bus -> Op.SDBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB31Cus -> Op.MDBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB31Dus -> Op.DDBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB324us -> Op.LDER, getFPR24FPR28 bin, Fmt.RRE
    | 0xB325us -> Op.LXDR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB326us -> Op.LXER, getFPR24FPR28 bin, Fmt.RRE
    | 0xB336us -> Op.SQXR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB337us -> Op.MEER, getFPR24FPR28 bin, Fmt.RRE
    | 0xB340us -> Op.LPXBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB341us -> Op.LNXBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB342us -> Op.LTXBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB343us -> Op.LCXBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB344us when extract32 bin 16 23 = 0u ->
      Op.LEDBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB345us when extract32 bin 16 23 = 0u ->
      Op.LDXBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB346us when extract32 bin 16 23 = 0u ->
      Op.LEXBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB348us -> Op.KXBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB349us -> Op.CXBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB34Aus -> Op.AXBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB34Bus -> Op.SXBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB34Cus -> Op.MXBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB34Dus -> Op.DXBR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB358us -> Op.THDER, getFPR24FPR28 bin, Fmt.RRE
    | 0xB359us -> Op.THDR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB360us -> Op.LPXR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB361us -> Op.LNXR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB362us -> Op.LTXR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB363us -> Op.LCXR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB365us -> Op.LXR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB366us -> Op.LEXR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB367us -> Op.FIXR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB369us -> Op.CXR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB370us -> Op.LPDFR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB371us -> Op.LNDFR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB373us -> Op.LCDFR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB374us -> Op.LZER, getFPR24FPR28 bin, Fmt.RRE
    | 0xB375us -> Op.LZDR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB376us -> Op.LZXR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB377us -> Op.FIER, getFPR24FPR28 bin, Fmt.RRE
    | 0xB37Fus -> Op.FIDR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB384us -> Op.SFPC, getGR24to27 bin, Fmt.RRE
    | 0xB385us -> Op.SFASR, getGR24to27 bin, Fmt.RRE
    | 0xB38Cus -> Op.EFPC, getGR24to27 bin, Fmt.RRE
    | 0xB394us when extract32 bin 16 23 = 0u ->
      Op.CEFBR, getFPR24GR28 bin, Fmt.RRE
    | 0xB395us when extract32 bin 16 23 = 0u ->
      Op.CDFBR, getFPR24GR28 bin, Fmt.RRE
    | 0xB396us when extract32 bin 16 23 = 0u ->
      Op.CXFBR, getFPR24GR28 bin, Fmt.RRE
    | 0xB3A4us when extract32 bin 16 23 = 0u ->
      Op.CEGBR, getFPR24GR28 bin, Fmt.RRE
    | 0xB3A5us when extract32 bin 16 23 = 0u ->
      Op.CDGBR, getFPR24GR28 bin, Fmt.RRE
    | 0xB3A6us when extract32 bin 16 23 = 0u ->
      Op.CXGBR, getFPR24GR28 bin, Fmt.RRE
    | 0xB3B4us -> Op.CEFR, getFPR24GR28 bin, Fmt.RRE
    | 0xB3B5us -> Op.CDFR, getFPR24GR28 bin, Fmt.RRE
    | 0xB3B6us -> Op.CXFR, getFPR24GR28 bin, Fmt.RRE
    | 0xB3C1us -> Op.LDGR, getFPR24GR28 bin, Fmt.RRE
    | 0xB3C4us -> Op.CEGR, getFPR24GR28 bin, Fmt.RRE
    | 0xB3C5us -> Op.CDGR, getFPR24GR28 bin, Fmt.RRE
    | 0xB3C6us -> Op.CXGR, getFPR24GR28 bin, Fmt.RRE
    | 0xB3CDus -> Op.LGDR, getGR24FPR28 bin, Fmt.RRE
    | 0xB3D6us -> Op.LTDTR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB3DEus -> Op.LTXTR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB3E0us -> Op.KDTR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB3E2us -> Op.CUDTR, getGR24FPR28 bin, Fmt.RRE
    | 0xB3E4us -> Op.CDTR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB3E5us -> Op.EEDTR, getGR24FPR28 bin, Fmt.RRE
    | 0xB3E7us -> Op.ESDTR, getGR24FPR28 bin, Fmt.RRE
    | 0xB3E8us -> Op.KXTR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB3EAus -> Op.CUXTR, getGR24FPR28 bin, Fmt.RRE
    | 0xB3ECus -> Op.CXTR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB3EDus -> Op.EEXTR, getGR24FPR28 bin, Fmt.RRE
    | 0xB3EFus -> Op.ESXTR, getGR24FPR28 bin, Fmt.RRE
    | 0xB3F1us when extract32 bin 16 23 = 0u ->
      Op.CDGTR, getFPR24GR28 bin, Fmt.RRE
    | 0xB3F2us -> Op.CDUTR, getFPR24GR28 bin, Fmt.RRE
    | 0xB3F3us -> Op.CDSTR, getFPR24GR28 bin, Fmt.RRE
    | 0xB3F4us -> Op.CEDTR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB3F9us when extract32 bin 16 23 = 0u ->
      Op.CXGTR, getFPR24GR28 bin, Fmt.RRE
    | 0xB3FAus -> Op.CXUTR, getFPR24GR28 bin, Fmt.RRE
    | 0xB3FBus -> Op.CXSTR, getFPR24GR28 bin, Fmt.RRE
    | 0xB3FCus -> Op.CEXTR, getFPR24FPR28 bin, Fmt.RRE
    | 0xB900us -> Op.LPGR, getGR24GR28 bin, Fmt.RRE
    | 0xB901us -> Op.LNGR, getGR24GR28 bin, Fmt.RRE
    | 0xB902us -> Op.LTGR, getGR24GR28 bin, Fmt.RRE
    | 0xB903us -> Op.LCGR, getGR24GR28 bin, Fmt.RRE
    | 0xB904us -> Op.LGR, getGR24GR28 bin, Fmt.RRE
    | 0xB905us -> Op.LURAG, getGR24GR28 bin, Fmt.RRE
    | 0xB906us -> Op.LGBR, getGR24GR28 bin, Fmt.RRE
    | 0xB907us -> Op.LGHR, getGR24GR28 bin, Fmt.RRE
    | 0xB908us -> Op.AGR, getGR24GR28 bin, Fmt.RRE
    | 0xB909us -> Op.SGR, getGR24GR28 bin, Fmt.RRE
    | 0xB90Aus -> Op.ALGR, getGR24GR28 bin, Fmt.RRE
    | 0xB90Bus -> Op.SLGR, getGR24GR28 bin, Fmt.RRE
    | 0xB90Cus -> Op.MSGR, getGR24GR28 bin, Fmt.RRE
    | 0xB90Dus -> Op.DSGR, getGR24GR28 bin, Fmt.RRE
    | 0xB90Eus -> Op.EREGG, getAR24AR28 bin, Fmt.RRE
    | 0xB90Fus -> Op.LRVGR, getGR24GR28 bin, Fmt.RRE
    | 0xB910us -> Op.LPGFR, getGR24GR28 bin, Fmt.RRE
    | 0xB911us -> Op.LNGFR, getGR24GR28 bin, Fmt.RRE
    | 0xB912us -> Op.LTGFR, getGR24GR28 bin, Fmt.RRE
    | 0xB913us -> Op.LCGFR, getGR24GR28 bin, Fmt.RRE
    | 0xB914us -> Op.LGFR, getGR24GR28 bin, Fmt.RRE
    | 0xB916us -> Op.LLGFR, getGR24GR28 bin, Fmt.RRE
    | 0xB917us -> Op.LLGTR, getGR24GR28 bin, Fmt.RRE
    | 0xB918us -> Op.AGFR, getGR24GR28 bin, Fmt.RRE
    | 0xB919us -> Op.SGFR, getGR24GR28 bin, Fmt.RRE
    | 0xB91Aus -> Op.ALGFR, getGR24GR28 bin, Fmt.RRE
    | 0xB91Bus -> Op.SLGFR, getGR24GR28 bin, Fmt.RRE
    | 0xB91Cus -> Op.MSGFR, getGR24GR28 bin, Fmt.RRE
    | 0xB91Dus -> Op.DSGFR, getGR24GR28 bin, Fmt.RRE
    | 0xB91Eus -> Op.KMAC, getGR24GR28 bin, Fmt.RRE
    | 0xB91Fus -> Op.LRVR, getGR24GR28 bin, Fmt.RRE
    | 0xB920us -> Op.CGR, getGR24GR28 bin, Fmt.RRE
    | 0xB921us -> Op.CLGR, getGR24GR28 bin, Fmt.RRE
    | 0xB925us -> Op.STURG, getGR24GR28 bin, Fmt.RRE
    | 0xB926us -> Op.LBR, getGR24GR28 bin, Fmt.RRE
    | 0xB927us -> Op.LHR, getGR24GR28 bin, Fmt.RRE
    | 0xB928us -> Op.PCKMO, NoOperand, Fmt.RRE
    | 0xB92Aus -> Op.KMF, getGR24GR28 bin, Fmt.RRE
    | 0xB92Bus -> Op.KMO, getGR24GR28 bin, Fmt.RRE
    | 0xB92Cus -> Op.PCC, NoOperand, Fmt.RRE
    | 0xB92Eus -> Op.KM, getGR24GR28 bin, Fmt.RRE
    | 0xB92Fus -> Op.KMC, getGR24GR28 bin, Fmt.RRE
    | 0xB930us -> Op.CGFR, getGR24GR28 bin, Fmt.RRE
    | 0xB931us -> Op.CLGFR, getGR24GR28 bin, Fmt.RRE
    | 0xB938us -> Op.SORTL, getGR24GR28 bin, Fmt.RRE
    | 0xB93Aus -> Op.KDSA, getGR24GR28 bin, Fmt.RRE
    | 0xB93Bus -> Op.NNPA, NoOperand, Fmt.RRE
    | 0xB93Cus -> Op.PRNO, getGR24GR28 bin, Fmt.RRE
    | 0xB93Eus -> Op.KIMD, getGR24GR28 bin, Fmt.RRE
    | 0xB93Fus -> Op.KLMD, getGR24GR28 bin, Fmt.RRE
    | 0xB946us -> Op.BCTGR, getGR24GR28 bin, Fmt.RRE
    | 0xB980us -> Op.NGR, getGR24GR28 bin, Fmt.RRE
    | 0xB981us -> Op.OGR, getGR24GR28 bin, Fmt.RRE
    | 0xB982us -> Op.XGR, getGR24GR28 bin, Fmt.RRE
    | 0xB983us -> Op.FLOGR, getGR24GR28 bin, Fmt.RRE
    | 0xB984us -> Op.LLGCR, getGR24GR28 bin, Fmt.RRE
    | 0xB985us -> Op.LLGHR, getGR24GR28 bin, Fmt.RRE
    | 0xB986us -> Op.MLGR, getGR24GR28 bin, Fmt.RRE
    | 0xB987us -> Op.DLGR, getGR24GR28 bin, Fmt.RRE
    | 0xB988us -> Op.ALCGR, getGR24GR28 bin, Fmt.RRE
    | 0xB989us -> Op.SLBGR, getGR24GR28 bin, Fmt.RRE
    | 0xB98Aus -> Op.CSPG, getGR24GR28 bin, Fmt.RRE
    | 0xB98Dus -> Op.EPSW, getGR24GR28 bin, Fmt.RRE
    | 0xB994us -> Op.LLCR, getGR24GR28 bin, Fmt.RRE
    | 0xB995us -> Op.LLHR, getGR24GR28 bin, Fmt.RRE
    | 0xB996us -> Op.MLR, getGR24GR28 bin, Fmt.RRE
    | 0xB997us -> Op.DLR, getGR24GR28 bin, Fmt.RRE
    | 0xB998us -> Op.ALCR, getGR24GR28 bin, Fmt.RRE
    | 0xB999us -> Op.SLBR, getGR24GR28 bin, Fmt.RRE
    | 0xB99Aus -> Op.EPAIR, getGR24to27 bin, Fmt.RRE
    | 0xB99Bus -> Op.ESAIR, getGR24to27 bin, Fmt.RRE
    | 0xB99Dus -> Op.ESEA, getGR24to27 bin, Fmt.RRE
    | 0xB99Eus -> Op.PTI, getGR24GR28 bin, Fmt.RRE
    | 0xB99Fus -> Op.SSAIR, getGR24to27 bin, Fmt.RRE
    | 0xB9A1us -> Op.TPEI, getGR24GR28 bin, Fmt.RRE
    | 0xB9A2us -> Op.PTF, getGR24to27 bin, Fmt.RRE
    | 0xB9ACus -> Op.IRBM, getGR24GR28 bin, Fmt.RRE
    | 0xB9AEus -> Op.RRBM, getGR24GR28 bin, Fmt.RRE
    | 0xB9AFus -> Op.PFMF, getGR24GR28 bin, Fmt.RRE
    | 0xB9B2us -> Op.CU41, getGR24GR28 bin, Fmt.RRE
    | 0xB9B3us -> Op.CU42, getGR24GR28 bin, Fmt.RRE
    | 0xB9BEus -> Op.SRSTU, getGR24GR28 bin, Fmt.RRE
    | 0xB9CDus -> Op.CHHR, getGR24GR28 bin, Fmt.RRE
    | 0xB9CFus -> Op.CLHHR, getGR24GR28 bin, Fmt.RRE
    | 0xB9DDus -> Op.CHLR, getGR24GR28 bin, Fmt.RRE
    | 0xB9DFus -> Op.CLHLR, getGR24GR28 bin, Fmt.RRE
    | 0xB9E1us -> Op.POPCNT, getGR24GR28 bin, Fmt.RRE
    | 0xB221us -> Op.IPTE, getGR24GR28GR16Mask20 bin, Fmt.RRF
    | 0xB22Bus -> Op.SSKE, getGR24GR28Mask16 bin, Fmt.RRF
    | 0xB2A6us -> Op.CU21, getGR24GR28Mask16 bin, Fmt.RRF
    | 0xB2A7us -> Op.CU12, getGR24GR28Mask16 bin, Fmt.RRF
    | 0xB2E8us -> Op.PPA, getGR24GR28Mask16 bin, Fmt.RRF
    | 0xB344us when extract32 bin 20 23 <> 0u ->
      Op.LEDBRA, getFPR24FPR28Mask16Mask20 bin, Fmt.RRF
    | 0xB345us when extract32 bin 20 23 <> 0u ->
      Op.LDXBRA, getFPR24FPR28Mask16Mask20 bin, Fmt.RRF
    | 0xB346us when extract32 bin 20 23 <> 0u ->
      Op.LEXBRA, getFPR24FPR28Mask16Mask20 bin, Fmt.RRF
    | 0xB347us when extract32 bin 20 23 <> 0u ->
      Op.FIXBR, getFPR24FPR28Mask16 bin, Fmt.RRF
    | 0xB347us -> Op.FIXBRA, getFPR24FPR28Mask16Mask20 bin, Fmt.RRF
    | 0xB350us -> Op.TBEDR, getFPR24FPR28Mask16 bin, Fmt.RRF
    | 0xB351us -> Op.TBDR, getFPR24FPR28Mask16 bin, Fmt.RRF
    | 0xB353us -> Op.DIEBR, getFPR24FPR28FPR16Mask20 bin, Fmt.RRF
    | 0xB357us when extract32 bin 20 23 <> 0u ->
      Op.FIEBR, getFPR24FPR28Mask16 bin, Fmt.RRF
    | 0xB357us -> Op.FIEBRA, getFPR24FPR28Mask16Mask20 bin, Fmt.RRF
    | 0xB35Bus -> Op.DIDBR, getFPR24FPR28FPR16Mask20 bin, Fmt.RRF
    | 0xB35Fus when extract32 bin 20 23 <> 0u ->
      Op.FIDBR, getFPR24FPR28Mask16 bin, Fmt.RRF
    | 0xB35Fus -> Op.FIDBRA, getFPR24FPR28Mask16Mask20 bin, Fmt.RRF
    | 0xB372us -> Op.CPSDR, getFPR24FPR28FPR16 bin, Fmt.RRF
    | 0xB390us -> Op.CELFBR, getFPR24GR28Mask16Mask20 bin, Fmt.RRF
    | 0xB391us -> Op.CDLFBR, getFPR24GR28Mask16Mask20 bin, Fmt.RRF
    | 0xB392us -> Op.CXLFBR, getFPR24GR28Mask16Mask20 bin, Fmt.RRF
    | 0xB394us when extract32 bin 20 23 <> 0u ->
      Op.CEFBRA, getFPR24GR28Mask16Mask20 bin, Fmt.RRF
    | 0xB395us when extract32 bin 20 23 <> 0u ->
      Op.CDFBRA, getFPR24GR28Mask16Mask20 bin, Fmt.RRF
    | 0xB396us when extract32 bin 20 23 <> 0u ->
      Op.CXFBRA, getFPR24GR28Mask16Mask20 bin, Fmt.RRF
    | 0xB398us when extract32 bin 20 23 <> 0u ->
      Op.CFEBR, getGR24FPR28Mask16 bin, Fmt.RRF
    | 0xB398us -> Op.CFEBRA, getGR24FPR28Mask16Mask20 bin, Fmt.RRF
    | 0xB399us when extract32 bin 20 23 <> 0u ->
      Op.CFDBR, getGR24FPR28Mask16 bin, Fmt.RRF
    | 0xB399us -> Op.CFDBRA, getGR24FPR28Mask16Mask20 bin, Fmt.RRF
    | 0xB39Aus when extract32 bin 20 23 <> 0u ->
      Op.CFXBR, getGR24FPR28Mask16 bin, Fmt.RRF
    | 0xB39Aus -> Op.CFXBRA, getGR24FPR28Mask16Mask20 bin, Fmt.RRF
    | 0xB39Cus -> Op.CLFEBR, getGR24FPR28Mask16Mask20 bin, Fmt.RRF
    | 0xB39Dus -> Op.CLFDBR, getGR24FPR28Mask16Mask20 bin, Fmt.RRF
    | 0xB39Eus -> Op.CLFXBR, getGR24FPR28Mask16Mask20 bin, Fmt.RRF
    | 0xB3A0us -> Op.CELGBR, getFPR24GR28Mask16Mask20 bin, Fmt.RRF
    | 0xB3A1us -> Op.CDLGBR, getFPR24GR28Mask16Mask20 bin, Fmt.RRF
    | 0xB3A2us -> Op.CXLGBR, getFPR24GR28Mask16Mask20 bin, Fmt.RRF
    | 0xB3A4us when extract32 bin 20 23 <> 0u ->
      Op.CEGBRA, getFPR24GR28Mask16Mask20 bin, Fmt.RRF
    | 0xB3A5us when extract32 bin 20 23 <> 0u ->
      Op.CDGBRA, getFPR24GR28Mask16Mask20 bin, Fmt.RRF
    | 0xB3A6us when extract32 bin 20 23 <> 0u ->
      Op.CXGBRA, getFPR24GR28Mask16Mask20 bin, Fmt.RRF
    | 0xB3A8us when extract32 bin 20 23 <> 0u ->
      Op.CGEBR, getGR24FPR28Mask16 bin, Fmt.RRF
    | 0xB3A8us -> Op.CGEBRA, getGR24FPR28Mask16Mask20 bin, Fmt.RRF
    | 0xB3A9us when extract32 bin 20 23 <> 0u ->
      Op.CGDBR, getGR24FPR28Mask16 bin, Fmt.RRF
    | 0xB3A9us -> Op.CGDBRA, getGR24FPR28Mask16Mask20 bin, Fmt.RRF
    | 0xB3AAus when extract32 bin 20 23 <> 0u ->
      Op.CGXBR, getGR24FPR28Mask16 bin, Fmt.RRF
    | 0xB3AAus -> Op.CGXBRA, getGR24FPR28Mask16Mask20 bin, Fmt.RRF
    | 0xB3ACus -> Op.CLGEBR, getGR24FPR28Mask16Mask20 bin, Fmt.RRF
    | 0xB3ADus -> Op.CLGDBR, getGR24FPR28Mask16Mask20 bin, Fmt.RRF
    | 0xB3AEus -> Op.CLGXBR, getGR24FPR28Mask16Mask20 bin, Fmt.RRF
    | 0xB3B8us -> Op.CFER, getGR24FPR28Mask16 bin, Fmt.RRF
    | 0xB3B9us -> Op.CFDR, getGR24FPR28Mask16 bin, Fmt.RRF
    | 0xB3BAus -> Op.CFXR, getGR24FPR28Mask16 bin, Fmt.RRF
    | 0xB3C8us -> Op.CGER, getGR24FPR28Mask16 bin, Fmt.RRF
    | 0xB3C9us -> Op.CGDR, getGR24FPR28Mask16 bin, Fmt.RRF
    | 0xB3CAus -> Op.CGXR, getGR24FPR28Mask16 bin, Fmt.RRF
    | 0xB3D0us when extract32 bin 20 23 <> 0u ->
      Op.MDTR, getFPR24FPR28FPR16 bin, Fmt.RRF
    | 0xB3D0us -> Op.MDTRA, getFPR24FPR28FPR16Mask20 bin, Fmt.RRF
    | 0xB3D1us when extract32 bin 20 23 <> 0u ->
      Op.DDTR, getFPR24FPR28FPR16 bin, Fmt.RRF
    | 0xB3D1us -> Op.DDTRA, getFPR24FPR28FPR16Mask20 bin, Fmt.RRF
    | 0xB3D2us when extract32 bin 20 23 <> 0u ->
      Op.ADTR, getFPR24FPR28FPR16 bin, Fmt.RRF
    | 0xB3D2us -> Op.ADTRA, getFPR24FPR28FPR16Mask20 bin, Fmt.RRF
    | 0xB3D3us when extract32 bin 20 23 <> 0u ->
      Op.SDTR, getFPR24FPR28FPR16 bin, Fmt.RRF
    | 0xB3D3us -> Op.SDTRA, getFPR24FPR28FPR16Mask20 bin, Fmt.RRF
    | 0xB3D4us -> Op.LDETR, getFPR24FPR28Mask20 bin, Fmt.RRF
    | 0xB3D5us -> Op.LEDTR, getFPR24FPR28Mask16Mask20 bin, Fmt.RRF
    | 0xB3D7us -> Op.FIDTR, getFPR24FPR28Mask16Mask20 bin, Fmt.RRF
    | 0xB3D8us when extract32 bin 20 23 <> 0u ->
      Op.MXTR, getFPR24FPR28FPR16 bin, Fmt.RRF
    | 0xB3D8us -> Op.MXTRA, getFPR24FPR28FPR16Mask20 bin, Fmt.RRF
    | 0xB3D9us when extract32 bin 20 23 <> 0u ->
      Op.DXTR, getFPR24FPR28FPR16 bin, Fmt.RRF
    | 0xB3D9us -> Op.DXTRA, getFPR24FPR28FPR16Mask20 bin, Fmt.RRF
    | 0xB3DAus when extract32 bin 20 23 <> 0u ->
      Op.AXTR, getFPR24FPR28FPR16 bin, Fmt.RRF
    | 0xB3DAus -> Op.AXTRA, getFPR24FPR28FPR16Mask20 bin, Fmt.RRF
    | 0xB3DBus when extract32 bin 20 23 <> 0u ->
      Op.SXTR, getFPR24FPR28FPR16 bin, Fmt.RRF
    | 0xB3DBus -> Op.SXTRA, getFPR24FPR28FPR16Mask20 bin, Fmt.RRF
    | 0xB3DCus -> Op.LXDTR, getFPR24FPR28Mask20 bin, Fmt.RRF
    | 0xB3DDus -> Op.LDXTR, getFPR24FPR28Mask16Mask20 bin, Fmt.RRF
    | 0xB3DFus -> Op.FIXTR, getFPR24FPR28Mask16Mask20 bin, Fmt.RRF
    | 0xB3E1us when extract32 bin 20 23 <> 0u ->
      Op.CGDTR, getGR24FPR28Mask16 bin, Fmt.RRF
    | 0xB3E1us -> Op.CGDTRA, getGR24FPR28Mask16Mask20 bin, Fmt.RRF
    | 0xB3E3us -> Op.CSDTR, getGR24FPR28Mask20 bin, Fmt.RRF
    | 0xB3E9us when extract32 bin 20 23 <> 0u ->
      Op.CGXTR, getGR24FPR28Mask16 bin, Fmt.RRF
    | 0xB3E9us -> Op.CGXTRA, getGR24FPR28Mask16Mask20 bin, Fmt.RRF
    | 0xB3EBus when extract32 bin 20 23 <> 0u ->
      Op.CSXTR, getGR24FPR28Mask20 bin, Fmt.RRF
    | 0xB3F1us when extract32 bin 20 23 <> 0u ->
      Op.CDGTRA, getFPR24GR28Mask16Mask20 bin, Fmt.RRF
    | 0xB3F5us -> Op.QADTR, getFPR24FPR28FPR16Mask20 bin, Fmt.RRF
    | 0xB3F6us -> Op.IEDTR, getFPR24GR28FPR16 bin, Fmt.RRF
    | 0xB3F7us -> Op.RRDTR, getFPR24GR28FPR16Mask20 bin, Fmt.RRF
    | 0xB3F9us when extract32 bin 20 23 <> 0u ->
      Op.CXGTRA, getFPR24GR28Mask16Mask20 bin, Fmt.RRF
    | 0xB3FDus -> Op.QAXTR, getFPR24FPR28FPR16Mask20 bin, Fmt.RRF
    | 0xB3FEus -> Op.IEXTR, getFPR24GR28FPR16 bin, Fmt.RRF
    | 0xB3FFus -> Op.RRXTR, getFPR24GR28FPR16Mask20 bin, Fmt.RRF
    | 0xB929us -> Op.KMA, getGR24GR28GR16 bin, Fmt.RRF
    | 0xB92Dus -> Op.KMCTR, getGR24GR28GR16 bin, Fmt.RRF
    | 0xB939us -> Op.DFLTCC, getGR24GR28GR16 bin, Fmt.RRF
    | 0xB941us -> Op.CFDTR, getGR24FPR28Mask16Mask20 bin, Fmt.RRF
    | 0xB942us -> Op.CLGDTR, getGR24FPR28Mask16Mask20 bin, Fmt.RRF
    | 0xB943us -> Op.CLFDTR, getGR24FPR28Mask16Mask20 bin, Fmt.RRF
    | 0xB949us -> Op.CFXTR, getGR24FPR28Mask16Mask20 bin, Fmt.RRF
    | 0xB94Aus -> Op.CLGXTR, getGR24FPR28Mask16Mask20 bin, Fmt.RRF
    | 0xB94Bus -> Op.CLFXTR, getGR24FPR28Mask16Mask20 bin, Fmt.RRF
    | 0xB951us -> Op.CDFTR, getFPR24GR28Mask16Mask20 bin, Fmt.RRF
    | 0xB952us -> Op.CDLGTR, getFPR24GR28Mask16Mask20 bin, Fmt.RRF
    | 0xB953us -> Op.CDLFTR, getFPR24GR28Mask16Mask20 bin, Fmt.RRF
    | 0xB959us -> Op.CXFTR, getFPR24GR28Mask16Mask20 bin, Fmt.RRF
    | 0xB95Aus -> Op.CXLGTR, getFPR24GR28Mask16Mask20 bin, Fmt.RRF
    | 0xB95Bus -> Op.CXLFTR, getFPR24GR28Mask16Mask20 bin, Fmt.RRF
    | 0xB960us -> Op.CGRT, getGR24GR28Mask16 bin, Fmt.RRF
    | 0xB961us -> Op.CLGRT, getGR24GR28Mask16 bin, Fmt.RRF
    | 0xB972us -> Op.CRT, getGR24GR28Mask16 bin, Fmt.RRF
    | 0xB973us -> Op.CLRT, getGR24GR28Mask16 bin, Fmt.RRF
    | 0xB98Eus -> Op.IDTE, getGR24GR28GR16Mask20 bin, Fmt.RRF
    | 0xB98Fus -> Op.CRDTE, getGR24GR28GR16Mask20 bin, Fmt.RRF
    | 0xB990us -> Op.TRTT, getGR24GR28Mask16 bin, Fmt.RRF
    | 0xB991us -> Op.TRTO, getGR24GR28Mask16 bin, Fmt.RRF
    | 0xB992us -> Op.TROT, getGR24GR28Mask16 bin, Fmt.RRF
    | 0xB993us -> Op.TROO, getGR24GR28Mask16 bin, Fmt.RRF
    | 0xB9AAus -> Op.LPTEA, getGR24GR28GR16Mask20 bin, Fmt.RRF
    | 0xB9B0us -> Op.CU14, getGR24GR28Mask16 bin, Fmt.RRF
    | 0xB9B1us -> Op.CU24, getGR24GR28Mask16 bin, Fmt.RRF
    | 0xB9BDus -> Op.TRTRE, getGR24GR28Mask16 bin, Fmt.RRF
    | 0xB9BFus -> Op.TRTE, getGR24GR28Mask16 bin, Fmt.RRF
    | 0xB9C8us -> Op.AHHHR, getGR24GR28GR16 bin, Fmt.RRF
    | 0xB9C9us -> Op.SHHHR, getGR24GR28GR16 bin, Fmt.RRF
    | 0xB9CAus -> Op.ALHHHR, getGR24GR28GR16 bin, Fmt.RRF
    | 0xB9CBus -> Op.SLHHHR, getGR24GR28GR16 bin, Fmt.RRF
    | 0xB9D8us -> Op.AHHLR, getGR24GR28GR16 bin, Fmt.RRF
    | 0xB9D9us -> Op.SHHLR, getGR24GR28GR16 bin, Fmt.RRF
    | 0xB9DAus -> Op.ALHHLR, getGR24GR28GR16 bin, Fmt.RRF
    | 0xB9DBus -> Op.SLHHLR, getGR24GR28GR16 bin, Fmt.RRF
    | 0xB9E0us -> Op.LOCFHR, getGR24GR28Mask16 bin, Fmt.RRF
    | 0xB9E2us -> Op.LOCGR, getGR24GR28Mask16 bin, Fmt.RRF
    | 0xB9E4us -> Op.NGRK, getGR24GR28GR16 bin, Fmt.RRF
    | 0xB9E6us -> Op.OGRK, getGR24GR28GR16 bin, Fmt.RRF
    | 0xB9E7us -> Op.XGRK, getGR24GR28GR16 bin, Fmt.RRF
    | 0xB9E8us -> Op.AGRK, getGR24GR28GR16 bin, Fmt.RRF
    | 0xB9E9us -> Op.SGRK, getGR24GR28GR16 bin, Fmt.RRF
    | 0xB9EAus -> Op.ALGRK, getGR24GR28GR16 bin, Fmt.RRF
    | 0xB9EBus -> Op.SLGRK, getGR24GR28GR16 bin, Fmt.RRF
    | 0xB9ECus -> Op.MGRK, getGR24GR28GR16 bin, Fmt.RRF
    | 0xB9EDus -> Op.MSGRKC, getGR24GR28GR16 bin, Fmt.RRF
    | 0xB9F2us -> Op.LOCR, getGR24GR28Mask16 bin, Fmt.RRF
    | 0xB9F4us -> Op.NRK, getGR24GR28GR16 bin, Fmt.RRF
    | 0xB9F6us -> Op.ORK, getGR24GR28GR16 bin, Fmt.RRF
    | 0xB9F7us -> Op.XRK, getGR24GR28GR16 bin, Fmt.RRF
    | 0xB9F8us -> Op.ARK, getGR24GR28GR16 bin, Fmt.RRF
    | 0xB9F9us -> Op.SRK, getGR24GR28GR16 bin, Fmt.RRF
    | 0xB9FAus -> Op.ALRK, getGR24GR28GR16 bin, Fmt.RRF
    | 0xB9FBus -> Op.SLRK, getGR24GR28GR16 bin, Fmt.RRF
    | 0xB9FDus -> Op.MSRKC, getGR24GR28GR16 bin, Fmt.RRF
    | _ ->
      match opcode1 <<< 4 ||| (extract32 bin 12 15 |> uint16) with
      | 0xA50us -> Op.IIHH, getGR8HWImm bin, Fmt.RI
      | 0xA51us -> Op.IIHL, getGR8HWImm bin, Fmt.RI
      | 0xA52us -> Op.IILH, getGR8HWImm bin, Fmt.RI
      | 0xA53us -> Op.IILL, getGR8HWImm bin, Fmt.RI
      | 0xA54us -> Op.NIHH, getGR8HWImm bin, Fmt.RI
      | 0xA55us -> Op.NIHL, getGR8HWImm bin, Fmt.RI
      | 0xA56us -> Op.NILH, getGR8HWImm bin, Fmt.RI
      | 0xA57us -> Op.NILL, getGR8HWImm bin, Fmt.RI
      | 0xA58us -> Op.OIHH, getGR8HWImm bin, Fmt.RI
      | 0xA59us -> Op.OIHL, getGR8HWImm bin, Fmt.RI
      | 0xA5Aus -> Op.OILH, getGR8HWImm bin, Fmt.RI
      | 0xA5Bus -> Op.OILL, getGR8HWImm bin, Fmt.RI
      | 0xA5Cus -> Op.LLIHH, getGR8HWImm bin, Fmt.RI
      | 0xA5Dus -> Op.LLIHL, getGR8HWImm bin, Fmt.RI
      | 0xA5Eus -> Op.LLILH, getGR8HWImm bin, Fmt.RI
      | 0xA5Fus -> Op.LLILL, getGR8HWImm bin, Fmt.RI
      | 0xA70us -> Op.TMLH, getGR8HWImmM bin, Fmt.RI
      | 0xA71us -> Op.TMLL, getGR8HWImmM bin, Fmt.RI
      | 0xA72us -> Op.TMHH, getGR8HWImmM bin, Fmt.RI
      | 0xA73us -> Op.TMHL, getGR8HWImmM bin, Fmt.RI
      | 0xA74us -> Op.BRC, getBit8MaskSImmRUpper bin, Fmt.RI
      | 0xA75us -> Op.BRAS, getGR8SImmRUpper bin, Fmt.RI
      | 0xA76us -> Op.BRCT, getGR8SImmRUpper bin, Fmt.RI
      | 0xA77us -> Op.BRCTG, getGR8SImmRUpper bin, Fmt.RI
      | 0xA78us -> Op.LHI, getGR8SImmUpper bin, Fmt.RI
      | 0xA79us -> Op.LGHI, getGR8SImmUpper bin, Fmt.RI
      | 0xA7Aus -> Op.AHI, getGR8SImmUpper bin, Fmt.RI
      | 0xA7Bus -> Op.AGHI, getGR8SImmUpper bin, Fmt.RI
      | 0xA7Cus -> Op.MHI, getGR8SImmUpper bin, Fmt.RI
      | 0xA7Dus -> Op.MGHI, getGR8SImmUpper bin, Fmt.RI
      | 0xA7Eus -> Op.CHI, getGR8SImmUpper bin, Fmt.RI
      | 0xA7Fus -> Op.CGHI, getGR8SImmUpper bin, Fmt.RI
      | _ -> Op.InvalOp, NoOperand, Fmt.Invalid

let parseInstLenThree (bin: uint64) =
  match extract48 bin 0 15 |> uint16 with
  | 0xE500us -> Op.LASP, getM16D20M32D36 bin, Fmt.SSE
  | 0xE501us -> Op.TPROT, getM16D20M32D36 bin, Fmt.SSE
  | 0xE502us -> Op.STRAG, getM16D20M32D36 bin, Fmt.SSE
  | 0xE50Aus -> Op.MVCRL, getM16D20M32D36 bin, Fmt.SSE
  | 0xE50Eus -> Op.MVCSK, getM16D20M32D36 bin, Fmt.SSE
  | 0xE50Fus -> Op.MVCDK, getM16D20M32D36 bin, Fmt.SSE
  | 0xE544us -> Op.MVHHI, getM16D20SImm32to47CQ bin, Fmt.SIL
  | 0xE548us -> Op.MVGHI, getM16D20SImm32to47CQ bin, Fmt.SIL
  | 0xE54Cus -> Op.MVHI, getM16D20SImm32to47CQ bin, Fmt.SIL
  | 0xE554us -> Op.CHHSI, getM16D20SImm32to47CQ bin, Fmt.SIL
  | 0xE555us -> Op.CLHHSI, getM16D20UImm32to47Q bin, Fmt.SIL
  | 0xE558us -> Op.CGHSI, getM16D20SImm32to47CQ bin, Fmt.SIL
  | 0xE559us -> Op.CLGHSI, getM16D20UImm32to47Q bin, Fmt.SIL
  | 0xE55Cus -> Op.CHSI, getM16D20SImm32to47CQ bin, Fmt.SIL
  | 0xE55Dus -> Op.CLFHSI, getM16D20UImm32to47Q bin, Fmt.SIL
  | 0xE560us -> Op.TBEGIN, getM16D20UImm32to47Q bin, Fmt.SIL
  | 0xE561us -> Op.TBEGINC, getM16D20UImm32to47Q bin, Fmt.SIL
  | _ ->
    let opcode1 = extract48 bin 0 7 |> uint16
    match opcode1 with
    | 0xC7us -> Op.BPP, getMask8QSImm32RM16D20 bin, Fmt.SMI
    | 0xC5us ->
      let opr1 = extract48 bin 8 11 |> uint16
      let opr2 =
        BitVector.OfInt32 (extract48 bin 12 23 |> int32) 12<rt> |> ImmS12
      let opr3 =
        BitVector.OfInt32 (extract48 bin 24 47 |> int32) 24<rt> |> ImmS24
      Op.BPRP, ThreeOperands (OpMask opr1, OpImm opr2, OpImm opr3), Fmt.MII
    | 0xD0us -> Op.TRTR, getGRL8QM32D36 bin, Fmt.SS
    | 0xD1us -> Op.MVN, getGRL8QM32D36 bin, Fmt.SS
    | 0xD2us -> Op.MVC, getGRL8QM32D36 bin, Fmt.SS
    | 0xD3us -> Op.MVZ, getGRL8QM32D36 bin, Fmt.SS
    | 0xD4us -> Op.NC, getGRL8QM32D36 bin, Fmt.SS
    | 0xD5us -> Op.CLC, getGRL8QM32D36 bin, Fmt.SS
    | 0xD6us -> Op.OC, getGRL8QM32D36 bin, Fmt.SS
    | 0xD7us -> Op.XC, getGRL8QM32D36 bin, Fmt.SS
    | 0xD9us -> Op.MVCK, getR9MemBase16to35Disp20to47GR12Q bin, Fmt.SS
    | 0xDAus -> Op.MVCP, getR9MemBase16to35Disp20to47GR12Q bin, Fmt.SS
    | 0xDBus -> Op.MVCS, getR9MemBase16to35Disp20to47GR12Q bin, Fmt.SS
    | 0xDCus -> Op.TR, getGRL8QM32D36 bin, Fmt.SS
    | 0xDDus -> Op.TRT, getGRL8QM32D36 bin, Fmt.SS
    | 0xDEus -> Op.ED, getGRL8QM32D36 bin, Fmt.SS
    | 0xDFus -> Op.EDMK, getGRL8QM32D36 bin, Fmt.SS
    | 0xE1us -> Op.PKU, getM16D20GRL8Q bin, Fmt.SS
    | 0xE2us -> Op.UNPKU, getGRL8QM32D36 bin, Fmt.SS
    | 0xE8us -> Op.MVCIN, getGRL8QM32D36 bin, Fmt.SS
    | 0xE9us -> Op.PKA, getM16D20GRL8Q bin, Fmt.SS
    | 0xEAus -> Op.UNPKA, getGRL8QM32D36 bin, Fmt.SS
    | 0xEEus -> Op.PLO, getGR9QM16D20GR12QM32D36 bin, Fmt.SS
    | 0xEFus -> Op.LMD, getGR9QM16D20GR12QM32D36 bin, Fmt.SS
    | 0xF0us -> Op.SRP, getGRL9QM32D36UImm4 bin, Fmt.SS
    | 0xF1us -> Op.MVO, grl9QGRL12Q bin, Fmt.SS
    | 0xF2us -> Op.PACK, grl9QGRL12Q bin, Fmt.SS
    | 0xF3us -> Op.UNPK, grl9QGRL12Q bin, Fmt.SS
    | 0xF8us -> Op.ZAP, grl9QGRL12Q bin, Fmt.SS
    | 0xF9us -> Op.CP, grl9QGRL12Q bin, Fmt.SS
    | 0xFAus -> Op.AP, grl9QGRL12Q bin, Fmt.SS
    | 0xFBus -> Op.SP, grl9QGRL12Q bin, Fmt.SS
    | 0xFCus -> Op.MP, grl9QGRL12Q bin, Fmt.SS
    | 0xFDus -> Op.DP, grl9QGRL12Q bin, Fmt.SS
    | _ ->
      match opcode1 <<< 4 ||| (extract48 bin 12 15 |> uint16) with
      | 0xC80us -> Op.MVCOS, getM16D20M32D36GR8Q bin, Fmt.SSF
      | 0xC81us -> Op.ECTG, getM16D20M32D36GR8Q bin, Fmt.SSF
      | 0xC82us -> Op.CSST, getM16D20M32D36GR8Q bin, Fmt.SSF
      | 0xC84us -> Op.LPD, getM16D20M32D36GR8Q bin, Fmt.SSF
      | 0xC85us -> Op.LPDG, getM16D20M32D36GR8Q bin, Fmt.SSF
      | 0xC00us -> Op.LARL, getGR8QSImm16to47RQ bin, Fmt.RIL
      | 0xC01us -> Op.LGFI, getGR8QSImm16to47Q bin, Fmt.RIL
      | 0xC04us -> Op.BRCL, getMask8QSImm16to47RQ bin, Fmt.RIL
      | 0xC05us -> Op.BRASL, getGR8QSImm16to47RQ bin, Fmt.RIL
      | 0xC06us -> Op.XIHF, getGR8QUImm16to47CQ bin, Fmt.RIL
      | 0xC07us -> Op.XILF, getGR8QUImm16to47CQ bin, Fmt.RIL
      | 0xC08us -> Op.IIHF, getGR8QUImm16to47CQ bin, Fmt.RIL
      | 0xC09us -> Op.IILF, getGR8QUImm16to47CQ bin, Fmt.RIL
      | 0xC0Aus -> Op.NIHF, getGR8QUImm16to47CQ bin, Fmt.RIL
      | 0xC0Bus -> Op.NILF, getGR8QUImm16to47CQ bin, Fmt.RIL
      | 0xC0Cus -> Op.OIHF, getGR8QUImm16to47CQ bin, Fmt.RIL
      | 0xC0Dus -> Op.OILF, getGR8QUImm16to47CQ bin, Fmt.RIL
      | 0xC0Eus -> Op.LLIHF, getGR8QUImm16to47CQ bin, Fmt.RIL
      | 0xC0Fus -> Op.LLILF, getGR8QUImm16to47CQ bin, Fmt.RIL
      | 0xC20us -> Op.MSGFI, getGR8QSImm16to47Q bin, Fmt.RIL
      | 0xC21us -> Op.MSFI, getGR8QSImm16to47Q bin, Fmt.RIL
      | 0xC24us -> Op.SLGFI, getGR8QUImm16to47CQ bin, Fmt.RIL
      | 0xC25us -> Op.SLFI, getGR8QUImm16to47CQ bin, Fmt.RIL
      | 0xC28us -> Op.AGFI, getGR8QSImm16to47Q bin, Fmt.RIL
      | 0xC29us -> Op.AFI, getGR8QSImm16to47Q bin, Fmt.RIL
      | 0xC2Aus -> Op.ALGFI, getGR8QUImm16to47CQ bin, Fmt.RIL
      | 0xC2Bus -> Op.ALFI, getGR8QUImm16to47CQ bin, Fmt.RIL
      | 0xC2Cus -> Op.CGFI, getGR8QSImm16to47Q bin, Fmt.RIL
      | 0xC2Dus -> Op.CFI, getGR8QSImm16to47Q bin, Fmt.RIL
      | 0xC2Eus -> Op.CLGFI, getGR8QUImm16to47CQ bin, Fmt.RIL
      | 0xC2Fus -> Op.CLFI, getGR8QUImm16to47CQ bin, Fmt.RIL
      | 0xC42us -> Op.LLHRL, getGR8QSImm16to47RQ bin, Fmt.RIL
      | 0xC44us -> Op.LGHRL, getGR8QSImm16to47RQ bin, Fmt.RIL
      | 0xC45us -> Op.LHRL, getGR8QSImm16to47RQ bin, Fmt.RIL
      | 0xC46us -> Op.LLGHRL, getGR8QSImm16to47RQ bin, Fmt.RIL
      | 0xC47us -> Op.STHRL, getGR8QSImm16to47RQ bin, Fmt.RIL
      | 0xC48us -> Op.LGRL, getGR8QSImm16to47RQ bin, Fmt.RIL
      | 0xC4Bus -> Op.STGRL, getGR8QSImm16to47RQ bin, Fmt.RIL
      | 0xC4Cus -> Op.LGFRL, getGR8QSImm16to47RQ bin, Fmt.RIL
      | 0xC4Dus -> Op.LRL, getGR8QSImm16to47RQ bin, Fmt.RIL
      | 0xC4Eus -> Op.LLGFRL, getGR8QSImm16to47RQ bin, Fmt.RIL
      | 0xC4Fus -> Op.STRL, getGR8QSImm16to47RQ bin, Fmt.RIL
      | 0xC60us -> Op.EXRL, getGR8QSImm16to47RQ bin, Fmt.RIL
      | 0xC62us -> Op.PFDRL, getMask8QSImm16to47RQ bin, Fmt.RIL
      | 0xC64us -> Op.CGHRL, getGR8QSImm16to47RQ bin, Fmt.RIL
      | 0xC65us -> Op.CHRL, getGR8QSImm16to47RQ bin, Fmt.RIL
      | 0xC66us -> Op.CLGHRL, getGR8QSImm16to47RQ bin, Fmt.RIL
      | 0xC67us -> Op.CLHRL, getGR8QSImm16to47RQ bin, Fmt.RIL
      | 0xC68us -> Op.CGRL, getGR8QSImm16to47RQ bin, Fmt.RIL
      | 0xC6Aus -> Op.CLGRL, getGR8QSImm16to47RQ bin, Fmt.RIL
      | 0xC6Cus -> Op.CGFRL, getGR8QSImm16to47RQ bin, Fmt.RIL
      | 0xC6Dus -> Op.CRL, getGR8QSImm16to47RQ bin, Fmt.RIL
      | 0xC6Eus -> Op.CLGFRL, getGR8QSImm16to47RQ bin, Fmt.RIL
      | 0xC6Fus -> Op.CLRL, getGR8QSImm16to47RQ bin, Fmt.RIL
      | 0xCC6us -> Op.BRCTH, getGR8QSImm16to47RQ bin, Fmt.RIL
      | 0xCC8us -> Op.AIH, getGR8QSImm16to47Q bin, Fmt.RIL
      | 0xCCAus -> Op.ALSIH, getGR8QSImm16to47Q bin, Fmt.RIL
      | 0xCCBus -> Op.ALSIHN, getGR8QSImm16to47Q bin, Fmt.RIL
      | 0xCCDus -> Op.CIH, getGR8QSImm16to47Q bin, Fmt.RIL
      | 0xCCFus -> Op.CLIH, getGR8QUImm16to47CQ bin, Fmt.RIL
      | _ ->
        match opcode1 <<< 8 ||| (extract48 bin 40 47 |> uint16) with
        | 0xEC42us -> Op.LOCHI, getGR8QSImmUpperQMask12Q bin, Fmt.RIE
        | 0xEC44us -> Op.BRXHG, getGR8QSImmUpperQGR12Q bin, Fmt.RIE
        | 0xEC45us -> Op.BRXLG, getGR8QSImmUpperQGR12Q bin, Fmt.RIE
        | 0xEC46us -> Op.LOCGHI, getGR8QSImmUpperQMask12Q bin, Fmt.RIE
        | 0xEC4Eus -> Op.LOCHHI, getGR8QSImmUpperQMask12Q bin, Fmt.RIE
        | 0xEC51us -> Op.RISBLG, getGR8QGR12QUImmUpper24to32Q bin, Fmt.RIE
        | 0xEC54us -> Op.RNSBG, getGR8QGR12QUImmUpper24to32Q bin, Fmt.RIE
        | 0xEC55us -> Op.RISBG, getGR8QGR12QUImmUpper24to32Q bin, Fmt.RIE
        | 0xEC56us -> Op.ROSBG, getGR8QGR12QUImmUpper24to32Q bin, Fmt.RIE
        | 0xEC57us -> Op.RXSBG, getGR8QGR12QUImmUpper24to32Q bin, Fmt.RIE
        | 0xEC59us -> Op.RISBGN, getGR8QGR12QUImmUpper24to32Q bin, Fmt.RIE
        | 0xEC5Dus -> Op.RISBHG, getGR8QGR12QUImmUpper24to32Q bin, Fmt.RIE
        | 0xEC64us -> Op.CGRJ, getGR8QGR12QMask32SImmUpperRQ bin, Fmt.RIE
        | 0xEC65us -> Op.CLGRJ, getGR8QGR12QMask32SImmUpperRQ bin, Fmt.RIE
        | 0xEC70us -> Op.CGIT, getGR8QSImmUpperBQMask32Q bin, Fmt.RIE
        | 0xEC71us -> Op.CLGIT, getGR8QUImmUpperCQMask32Q bin, Fmt.RIE
        | 0xEC72us -> Op.CIT, getGR8QSImmUpperBQMask32Q bin, Fmt.RIE
        | 0xEC73us -> Op.CLFIT, getGR8QUImmUpperCQMask32Q bin, Fmt.RIE
        | 0xEC76us -> Op.CRJ, getGR8QGR12QMask32SImmUpperRQ bin, Fmt.RIE
        | 0xEC77us -> Op.CLRJ, getGR8QGR12QMask32SImmUpperRQ bin, Fmt.RIE
        | 0xEC7Cus -> Op.CGIJ, getGR8QSImm32BQMask12SImmUpperRQ bin, Fmt.RIE
        | 0xEC7Dus ->
          Op.CLGIJ, getGR8QUImm32CQMask12SImmUpperRQ bin, Fmt.RIE
        | 0xEC7Eus -> Op.CIJ, getGR8QSImm32BQMask12SImmUpperRQ bin, Fmt.RIE
        | 0xEC7Fus -> Op.CLIJ, getGR8QUImm32CQMask12SImmUpperRQ bin, Fmt.RIE
        | 0xECD8us -> Op.AHIK, getGR8QSImmUpperQGR12Q bin, Fmt.RIE
        | 0xECD9us -> Op.AGHIK, getGR8QSImmUpperQGR12Q bin, Fmt.RIE
        | 0xECDAus -> Op.ALHSIK, getGR8QUImmUpperCQGR12Q bin, Fmt.RIE
        | 0xECDBus -> Op.ALGHSIK, getGR8QUImmUpperCQGR12Q bin, Fmt.RIE
        | 0xECFCus ->
          Op.CGIB, getGR8QSImm32BQMask12NBase16Disp20 bin, Fmt.RIS
        | 0xECFDus ->
          Op.CLGIB, getGR8QUImm32CQMask12NBase16Disp20 bin, Fmt.RIS
        | 0xECFEus ->
          Op.CIB, getGR8QSImm32BQMask12NBase16Disp20 bin, Fmt.RIS
        | 0xECFFus ->
          Op.CLIB, getGR8QUImm32CQMask12NBase16Disp20 bin, Fmt.RIS
        | 0xECE4us -> Op.CGRB, getGR8QGR12QMask32NBase16Disp20 bin, Fmt.RRS
        | 0xECE5us -> Op.CLGRB, getGR8QGR12QMask32NBase16Disp20 bin, Fmt.RRS
        | 0xECF6us -> Op.CRB, getGR8QGR12QMask32NBase16Disp20 bin, Fmt.RRS
        | 0xECF7us -> Op.CLRB, getGR8QGR12QMask32NBase16Disp20 bin, Fmt.RRS
        | 0xEBC0us -> Op.TP, getGRL8Q bin, Fmt.RSL
        | 0xEDA8us -> Op.CZDT, getFPR32QGRL8QMask36 bin, Fmt.RSL
        | 0xEDA9us -> Op.CZXT, getFPR32QGRL8QMask36 bin, Fmt.RSL
        | 0xEDAAus -> Op.CDZT, getFPR32QGRL8QMask36 bin, Fmt.RSL
        | 0xEDABus -> Op.CXZT, getFPR32QGRL8QMask36 bin, Fmt.RSL
        | 0xEDACus -> Op.CPDT, getFPR32QGRL8QMask36 bin, Fmt.RSL
        | 0xEDADus -> Op.CPXT, getFPR32QGRL8QMask36 bin, Fmt.RSL
        | 0xEDAEus -> Op.CDPT, getFPR32QGRL8QMask36 bin, Fmt.RSL
        | 0xEDAFus -> Op.CXPT, getFPR32QGRL8QMask36 bin, Fmt.RSL
        | 0xEB04us -> Op.LMG, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEB0Aus -> Op.SRAG, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEB0Bus -> Op.SLAG, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEB0Cus -> Op.SRLG, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEB0Dus -> Op.SLLG, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEB0Fus -> Op.TRACG, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEB14us -> Op.CSY, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEB1Cus -> Op.RLLG, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEB1Dus -> Op.RLL, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEB20us -> Op.CLMH, getGR8QM16D20Mask12Q bin, Fmt.RSY
        | 0xEB21us -> Op.CLMY, getGR8QM16D20Mask12Q bin, Fmt.RSY
        | 0xEB23us -> Op.CLT, getGR8QM16D20Mask12Q bin, Fmt.RSY
        | 0xEB24us -> Op.STMG, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEB25us -> Op.STCTG, getCR8QM16D20CR12Q bin, Fmt.RSY
        | 0xEB26us -> Op.STMH, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEB2Bus -> Op.CLGT, getGR8QM16D20Mask12Q bin, Fmt.RSY
        | 0xEB2Cus -> Op.STCMH, getGR8QM16D20Mask12Q bin, Fmt.RSY
        | 0xEB2Dus -> Op.STCMY, getGR8QM16D20Mask12Q bin, Fmt.RSY
        | 0xEB2Fus -> Op.LCTLG, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEB30us -> Op.CSG, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEB31us -> Op.CDSY, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEB3Eus -> Op.CDSG, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEB44us -> Op.BXHG, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEB45us -> Op.BXLEG, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEB4Cus -> Op.ECAG, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEB80us -> Op.ICMH, getGR8QM16D20Mask12Q bin, Fmt.RSY
        | 0xEB81us -> Op.ICMY, getGR8QM16D20Mask12Q bin, Fmt.RSY
        | 0xEB8Eus -> Op.MVCLU, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEB8Fus -> Op.CLCLU, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEB90us -> Op.STMY, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEB96us -> Op.LMH, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEB98us -> Op.LMY, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEB9Aus -> Op.LAMY, getAR8QM16D20AR12Q bin, Fmt.RSY
        | 0xEB9Bus -> Op.STAMY, getAR8QM16D20AR12Q bin, Fmt.RSY
        | 0xEBDCus -> Op.SRAK, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEBDDus -> Op.SLAK, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEBDEus -> Op.SRLK, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEBDFus -> Op.SLLK, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEBE0us -> Op.LOCFH, getGR8QM16D20Mask12Q bin, Fmt.RSY
        | 0xEBE1us -> Op.STOCFH, getGR8QM16D20Mask12Q bin, Fmt.RSY
        | 0xEBE2us -> Op.LOCG, getGR8QM16D20Mask12Q bin, Fmt.RSY
        | 0xEBE3us -> Op.STOCG, getGR8QM16D20Mask12Q bin, Fmt.RSY
        | 0xEBE4us -> Op.LANG, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEBE6us -> Op.LAOG, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEBE7us -> Op.LAXG, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEBE8us -> Op.LAAG, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEBEAus -> Op.LAALG, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEBF2us -> Op.LOC, getGR8QM16D20Mask12Q bin, Fmt.RSY
        | 0xEBF3us -> Op.STOC, getGR8QM16D20Mask12Q bin, Fmt.RSY
        | 0xEBF4us -> Op.LAN, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEBF6us -> Op.LAO, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEBF7us -> Op.LAX, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEBF8us -> Op.LAA, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xEBFAus -> Op.LAAL, getGR8QM16D20GR12Q bin, Fmt.RSY
        | 0xE727us -> Op.LCBB, getGR8QIdx12M16D20Mask32Q bin, Fmt.RXE
        | 0xED04us -> Op.LDEB, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xED05us -> Op.LXDB, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xED06us -> Op.LXEB, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xED07us -> Op.MXDB, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xED08us -> Op.KEB, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xED09us -> Op.CEB, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xED0Aus -> Op.AEB, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xED0Bus -> Op.SEB, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xED0Cus -> Op.MDEB, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xED0Dus -> Op.DEB, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xED10us -> Op.TCEB, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xED11us -> Op.TCDB, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xED12us -> Op.TCXB, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xED14us -> Op.SQEB, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xED15us -> Op.SQDB, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xED17us -> Op.MEEB, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xED18us -> Op.KDB, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xED19us -> Op.CDB, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xED1Aus -> Op.ADB, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xED1Bus -> Op.SDB, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xED1Cus -> Op.MDB, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xED1Dus -> Op.DDB, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xED24us -> Op.LDE, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xED25us -> Op.LXD, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xED26us -> Op.LXE, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xED34us -> Op.SQE, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xED35us -> Op.SQD, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xED37us -> Op.MEE, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xED50us -> Op.TDCET, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xED51us -> Op.TDGET, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xED54us -> Op.TDCDT, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xED55us -> Op.TDGDT, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xED58us -> Op.TDCXT, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xED59us -> Op.TDGXT, getFPR8QIdx12M16D20 bin, Fmt.RXE
        | 0xE302us -> Op.LTG, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE303us -> Op.LRAG, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE304us -> Op.LG, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE306us -> Op.CVBY, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE308us -> Op.AG, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE309us -> Op.SG, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE30Aus -> Op.ALG, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE30Bus -> Op.SLG, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE30Cus -> Op.MSG, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE30Dus -> Op.DSG, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE30Eus -> Op.CVBG, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE30Fus -> Op.LRVG, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE312us -> Op.LT, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE313us -> Op.LRAY, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE314us -> Op.LGF, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE315us -> Op.LGH, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE316us -> Op.LLGF, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE317us -> Op.LLGT, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE318us -> Op.AGF, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE319us -> Op.SGF, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE31Aus -> Op.ALGF, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE31Bus -> Op.SLGF, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE31Cus -> Op.MSGF, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE31Dus -> Op.DSGF, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE31Eus -> Op.LRV, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE31Fus -> Op.LRVH, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE320us -> Op.CG, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE321us -> Op.CLG, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE324us -> Op.STG, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE325us -> Op.NTSTG, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE326us -> Op.CVDY, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE32Aus -> Op.LZRG, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE32Eus -> Op.CVDG, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE32Fus -> Op.STRVG, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE330us -> Op.CGF, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE331us -> Op.CLGF, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE332us -> Op.LTGF, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE334us -> Op.CGH, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE336us -> Op.PFD, getMask8QIdx12M16D20 bin, Fmt.RXY
        | 0xE338us -> Op.AGH, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE339us -> Op.SGH, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE33Aus -> Op.LLZRGF, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE33Bus -> Op.LZRF, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE33Cus -> Op.MGH, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE33Eus -> Op.STRV, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE33Fus -> Op.STRVH, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE346us -> Op.BCTG, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE347us -> Op.BIC, getMask8QIdx12M16D20 bin, Fmt.RXY
        | 0xE348us -> Op.LLGFSG, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE349us -> Op.STGSC, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE34Cus -> Op.LGG, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE34Dus -> Op.LGSC, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE350us -> Op.STY, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE351us -> Op.MSY, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE353us -> Op.MSC, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE354us -> Op.NY, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE355us -> Op.CLY, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE356us -> Op.OY, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE357us -> Op.XY, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE358us -> Op.LY, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE359us -> Op.CY, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE35Aus -> Op.AY, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE35Bus -> Op.SY, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE35Cus -> Op.MFY, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE35Eus -> Op.ALY, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE35Fus -> Op.SLY, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE370us -> Op.STHY, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE371us -> Op.LAY, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE372us -> Op.STCY, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE373us -> Op.ICY, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE375us -> Op.LAEY, getAR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE376us -> Op.LB, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE377us -> Op.LGB, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE378us -> Op.LHY, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE379us -> Op.CHY, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE37Aus -> Op.AHY, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE37Bus -> Op.SHY, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE37Cus -> Op.MHY, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE380us -> Op.NG, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE381us -> Op.OG, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE382us -> Op.XG, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE383us -> Op.MSGC, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE384us -> Op.MG, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE385us -> Op.LGAT, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE386us -> Op.MLG, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE387us -> Op.DLG, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE388us -> Op.ALCG, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE389us -> Op.SLBG, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE38Eus -> Op.STPQ, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE38Fus -> Op.LPQ, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE390us -> Op.LLGC, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE391us -> Op.LLGH, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE394us -> Op.LLC, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE395us -> Op.LLH, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE396us -> Op.ML, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE397us -> Op.DL, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE398us -> Op.ALC, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE399us -> Op.SLB, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE39Cus -> Op.LLGTAT, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE39Dus -> Op.LLGFAT, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE39Fus -> Op.LAT, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE3C0us -> Op.LBH, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE3C2us -> Op.LLCH, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE3C3us -> Op.STCH, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE3C4us -> Op.LHH, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE3C6us -> Op.LLHH, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE3C7us -> Op.STHH, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE3C8us -> Op.LFHAT, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE3CAus -> Op.LFH, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE3CBus -> Op.STFH, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE3CDus -> Op.CHF, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xE3CFus -> Op.CLHF, getGR8QIdx12M16D20 bin, Fmt.RXY
        | 0xED64us -> Op.LEY, getFPR8QIdx12MemBase16DispL20 bin, Fmt.RXY
        | 0xED65us -> Op.LDY, getFPR8QIdx12MemBase16DispL20 bin, Fmt.RXY
        | 0xED66us -> Op.STEY, getFPR8QIdx12MemBase16DispL20 bin, Fmt.RXY
        | 0xED67us -> Op.STDY, getFPR8QIdx12MemBase16DispL20 bin, Fmt.RXY
        | 0xED0Eus -> Op.MAEB, getFPR32QIdx12M16D20FPR8Q bin, Fmt.RXF
        | 0xED0Fus -> Op.MSEB, getFPR32QIdx12M16D20FPR8Q bin, Fmt.RXF
        | 0xED1Eus -> Op.MADB, getFPR32QIdx12M16D20FPR8Q bin, Fmt.RXF
        | 0xED1Fus -> Op.MSDB, getFPR32QIdx12M16D20FPR8Q bin, Fmt.RXF
        | 0xED2Eus -> Op.MAE, getFPR32QIdx12M16D20FPR8Q bin, Fmt.RXF
        | 0xED2Fus -> Op.MSE, getFPR32QIdx12M16D20FPR8Q bin, Fmt.RXF
        | 0xED38us -> Op.MAYL, getFPR32QIdx12M16D20FPR8Q bin, Fmt.RXF
        | 0xED39us -> Op.MYL, getFPR32QIdx12M16D20FPR8Q bin, Fmt.RXF
        | 0xED3Aus -> Op.MAY, getFPR32QIdx12M16D20FPR8Q bin, Fmt.RXF
        | 0xED3Bus -> Op.MY, getFPR32QIdx12M16D20FPR8Q bin, Fmt.RXF
        | 0xED3Cus -> Op.MAYH, getFPR32QIdx12M16D20FPR8Q bin, Fmt.RXF
        | 0xED3Dus -> Op.MYH, getFPR32QIdx12M16D20FPR8Q bin, Fmt.RXF
        | 0xED3Eus -> Op.MAD, getFPR32QIdx12M16D20FPR8Q bin, Fmt.RXF
        | 0xED3Fus -> Op.MSD, getFPR32QIdx12M16D20FPR8Q bin, Fmt.RXF
        | 0xED40us -> Op.SLDT, getFPR32QIdx12M16D20FPR8Q bin, Fmt.RXF
        | 0xED41us -> Op.SRDT, getFPR32QIdx12M16D20FPR8Q bin, Fmt.RXF
        | 0xED48us -> Op.SLXT, getFPR32QIdx12M16D20FPR8Q bin, Fmt.RXF
        | 0xED49us -> Op.SRXT, getFPR32QIdx12M16D20FPR8Q bin, Fmt.RXF
        | 0xEB51us -> Op.TMY, getM16D20LUImm8to15Q bin, Fmt.SIY
        | 0xEB52us -> Op.MVIY, getM16D20LUImm8to15Q bin, Fmt.SIY
        | 0xEB54us -> Op.NIY, getM16D20LUImm8to15Q bin, Fmt.SIY
        | 0xEB55us -> Op.CLIY, getM16D20LUImm8to15Q bin, Fmt.SIY
        | 0xEB56us -> Op.OIY, getM16D20LUImm8to15Q bin, Fmt.SIY
        | 0xEB57us -> Op.XIY, getM16D20LUImm8to15Q bin, Fmt.SIY
        | 0xEB6Aus -> Op.ASI, getM16D20LSImm8to15Q bin, Fmt.SIY
        | 0xEB6Eus -> Op.ALSI, getM16D20LUImm8to15Q bin, Fmt.SIY
        | 0xEB71us -> Op.LPSWEY, getM16D20L bin, Fmt.SIY
        | 0xEB7Aus -> Op.AGSI, getM16D20LSImm8to15Q bin, Fmt.SIY
        | 0xEB7Eus -> Op.ALGSI, getM16D20LUImm8to15Q bin, Fmt.SIY
        | 0xE649us -> Op.VLIP, getVR8QUImmUpperQUImm4 bin, Fmt.VRI
        | 0xE658us -> Op.VCVD, getVR8QGR12QUImm8Mask24 bin, Fmt.VRI
        | 0xE659us -> Op.VSRP, getVR8QVR12QUImm8sMask24 bin, Fmt.VRI
        | 0xE65Aus -> Op.VCVDG, getVR8QGR12QUImm8Mask24 bin, Fmt.VRI
        | 0xE65Bus -> Op.VPSOP, getVR8QVR12QUImm8sMask24 bin, Fmt.VRI
        | 0xE670us -> Op.VPKZR, getVR8QVR12QVR16QUImm8Mask24 bin, Fmt.VRI
        | 0xE671us -> Op.VAP, getVR8QVR12QVR16QUImm8Mask24 bin, Fmt.VRI
        | 0xE672us -> Op.VSRPR, getVR8QVR12QVR16QUImm8Mask24 bin, Fmt.VRI
        | 0xE673us -> Op.VSP, getVR8QVR12QVR16QUImm8Mask24 bin, Fmt.VRI
        | 0xE678us -> Op.VMP, getVR8QVR12QVR16QUImm8Mask24 bin, Fmt.VRI
        | 0xE679us -> Op.VMSP, getVR8QVR12QVR16QUImm8Mask24 bin, Fmt.VRI
        | 0xE67Aus -> Op.VDP, getVR8QVR12QVR16QUImm8Mask24 bin, Fmt.VRI
        | 0xE67Bus -> Op.VRP, getVR8QVR12QVR16QUImm8Mask24 bin, Fmt.VRI
        | 0xE67Eus -> Op.VSDP, getVR8QVR12QVR16QUImm8Mask24 bin, Fmt.VRI
        | 0xE740us -> Op.VLEIB, getVR8QUImm16Mask32 bin, Fmt.VRI
        | 0xE741us -> Op.VLEIH, getVR8QUImm16Mask32 bin, Fmt.VRI
        | 0xE742us -> Op.VLEIG, getVR8QUImm16Mask32 bin, Fmt.VRI
        | 0xE743us -> Op.VLEIF, getVR8QUImm16Mask32 bin, Fmt.VRI
        | 0xE744us -> Op.VGBM, getVR8QUImm16 bin, Fmt.VRI
        | 0xE745us -> Op.VREPI, getVR8QUImm16Mask32 bin, Fmt.VRI
        | 0xE746us -> Op.VGM, getVR8QUImm8sMask32 bin, Fmt.VRI
        | 0xE74Aus -> Op.VFTCI, getVR8QVR12QUImm12Mask32Mask28 bin, Fmt.VRI
        | 0xE74Dus -> Op.VREP, getVR8QUImmUpperVR12QMask32 bin, Fmt.VRI
        | 0xE772us -> Op.VERIM, getVR8QVR12QVR16QUImm8Mask32 bin, Fmt.VRI
        | 0xE777us -> Op.VSLDB, getVR8QVR12QVR16QUImm8 bin, Fmt.VRI
        | 0xE786us -> Op.VSLD, getVR8QVR12QVR16QUImm8 bin, Fmt.VRI
        | 0xE787us -> Op.VSRD, getVR8QVR12QVR16QUImm8 bin, Fmt.VRI
        | 0xE650us -> Op.VCVB, getGR8QVR12QMask24Mask28 bin, Fmt.VRR
        | 0xE651us -> Op.VCLZDP, getVR8QVR12QMask24 bin, Fmt.VRR
        | 0xE652us -> Op.VCVBG, getGR8QVR12QMask24Mask28 bin, Fmt.VRR
        | 0xE654us -> Op.VUPKZH, getVR8QVR12QMask24 bin, Fmt.VRR
        | 0xE655us -> Op.VCNF, getVR8QVR12QMask32Mask28 bin, Fmt.VRR
        | 0xE656us -> Op.VCLFNH, getVR8QVR12QMask32Mask28 bin, Fmt.VRR
        | 0xE65Cus -> Op.VUPKZL,  getVR8QVR12QMask24 bin, Fmt.VRR
        | 0xE65Dus -> Op.VCFN, getVR8QVR12QMask32Mask28 bin, Fmt.VRR
        | 0xE65Eus -> Op.VCLFNL, getVR8QVR12QMask32Mask28 bin, Fmt.VRR
        | 0xE65Fus -> Op.VTP, getVR12Q bin, Fmt.VRR
        | 0xE674us -> Op.VSCHP, getVR8QVR12QVR16QMask32Mask24 bin, Fmt.VRR
        | 0xE675us -> Op.VCRNF, getVR8QVR12QVR16QMask32Mask28 bin, Fmt.VRR
        | 0xE677us -> Op.VCP, getVR12QVR16QMask24 bin, Fmt.VRR
        | 0xE67Cus -> Op.VSCSHP, getVR8QVR12QVR16Q bin, Fmt.VRR
        | 0xE67Dus -> Op.VCSPH, getVR8QVR12QVR16QMask24 bin, Fmt.VRR
        | 0xE750us -> Op.VPOPCT, getVR8QVR12QMask32 bin, Fmt.VRR
        | 0xE752us -> Op.VCTZ, getVR8QVR12QMask32 bin, Fmt.VRR
        | 0xE753us -> Op.VCLZ, getVR8QVR12QMask32 bin, Fmt.VRR
        | 0xE756us -> Op.VLR, getVR8QVR12Q bin, Fmt.VRR
        | 0xE75Cus -> Op.VISTR, getVR8QVR12QMask32Mask24 bin, Fmt.VRR
        | 0xE75Fus -> Op.VSEG, getVR8QVR12QMask32 bin, Fmt.VRR
        | 0xE760us -> Op.VMRL, getVR8QVR12QVR16QMask32 bin, Fmt.VRR
        | 0xE761us -> Op.VMRH, getVR8QVR12QVR16QMask32 bin, Fmt.VRR
        | 0xE762us -> Op.VLVGP, getVR8QGR12QGR16Q bin, Fmt.VRR
        | 0xE764us -> Op.VSUM, getVR8QVR12QVR16QMask32 bin, Fmt.VRR
        | 0xE765us -> Op.VSUMG, getVR8QVR12QVR16QMask32 bin, Fmt.VRR
        | 0xE766us -> Op.VCKSM, getVR8QVR12QVR16Q bin, Fmt.VRR
        | 0xE767us -> Op.VSUMQ, getVR8QVR12QVR16QMask32 bin, Fmt.VRR
        | 0xE768us -> Op.VN, getVR8QVR12QVR16Q bin, Fmt.VRR
        | 0xE769us -> Op.VNC, getVR8QVR12QVR16Q bin, Fmt.VRR
        | 0xE76Aus -> Op.VO, getVR8QVR12QVR16Q bin, Fmt.VRR
        | 0xE76Bus -> Op.VNO, getVR8QVR12QVR16Q bin, Fmt.VRR
        | 0xE76Cus -> Op.VNX, getVR8QVR12QVR16Q bin, Fmt.VRR
        | 0xE76Dus -> Op.VX, getVR8QVR12QVR16Q bin, Fmt.VRR
        | 0xE76Eus -> Op.VNN, getVR8QVR12QVR16Q bin, Fmt.VRR
        | 0xE76Fus -> Op.VOC, getVR8QVR12QVR16Q bin, Fmt.VRR
        | 0xE770us -> Op.VESLV, getVR8QVR12QVR16QMask32 bin, Fmt.VRR
        | 0xE773us -> Op.VERLLV, getVR8QVR12QVR16QMask32 bin, Fmt.VRR
        | 0xE774us -> Op.VSL, getVR8QVR12QVR16Q bin, Fmt.VRR
        | 0xE775us -> Op.VSLB, getVR8QVR12QVR16Q bin, Fmt.VRR
        | 0xE778us -> Op.VESRLV, getVR8QVR12QVR16QMask32 bin, Fmt.VRR
        | 0xE77Aus -> Op.VESRAV, getVR8QVR12QVR16QMask32 bin, Fmt.VRR
        | 0xE77Cus -> Op.VSRL, getVR8QVR12QVR16Q bin, Fmt.VRR
        | 0xE77Dus -> Op.VSRLB, getVR8QVR12QVR16Q bin, Fmt.VRR
        | 0xE77Eus -> Op.VSRA, getVR8QVR12QVR16Q bin, Fmt.VRR
        | 0xE77Fus -> Op.VSRAB, getVR8QVR12QVR16Q bin, Fmt.VRR
        | 0xE780us -> Op.VFEE, getVR8QVR12QVR16QMask32Mask24 bin, Fmt.VRR
        | 0xE781us -> Op.VFENE, getVR8QVR12QVR16QMask32Mask24 bin, Fmt.VRR
        | 0xE782us -> Op.VFAE, getVR8QVR12QVR16QMask32Mask24 bin, Fmt.VRR
        | 0xE784us -> Op.VPDI, getVR8QVR12QVR16QMask32 bin, Fmt.VRR
        | 0xE785us -> Op.VBPERM, getVR8QVR12QVR16Q bin, Fmt.VRR
        | 0xE78Aus ->
          Op.VSTRC, getVR8QVR12QVR16QVR32QMask20Mask24 bin, Fmt.VRR
        | 0xE78Bus ->
          Op.VSTRS, getVR8QVR12QVR16QVR32QMask20Mask24 bin, Fmt.VRR
        | 0xE78Cus -> Op.VPERM, getVR8QVR12QVR16QVR32Q bin, Fmt.VRR
        | 0xE78Dus -> Op.VSEL, getVR8QVR12QVR16QVR32Q bin, Fmt.VRR
        | 0xE78Eus ->
          Op.VFMS, getVR8QVR12QVR16QVR32QMask28Mask20 bin, Fmt.VRR
        | 0xE78Fus ->
          Op.VFMA, getVR8QVR12QVR16QVR32QMask28Mask20 bin, Fmt.VRR
        | 0xE794us -> Op.VPK, getVR8QVR12QVR16QMask32 bin, Fmt.VRR
        | 0xE795us -> Op.VPKLS, getVR8QVR12QVR16QMask32Mask24 bin, Fmt.VRR
        | 0xE797us -> Op.VPKS, getVR8QVR12QVR16QMask32Mask24 bin, Fmt.VRR
        | 0xE79Eus ->
          Op.VFNMS, getVR8QVR12QVR16QVR32QMask28Mask20 bin, Fmt.VRR
        | 0xE79Fus ->
          Op.VFNMA, getVR8QVR12QVR16QVR32QMask28Mask20 bin, Fmt.VRR
        | 0xE7A1us -> Op.VMLH, getVR8QVR12QVR16QMask32 bin, Fmt.VRR
        | 0xE7A2us -> Op.VML, getVR8QVR12QVR16QMask32 bin, Fmt.VRR
        | 0xE7A3us -> Op.VMH, getVR8QVR12QVR16QMask32 bin, Fmt.VRR
        | 0xE7A4us -> Op.VMLE, getVR8QVR12QVR16QMask32 bin, Fmt.VRR
        | 0xE7A5us -> Op.VMLO, getVR8QVR12QVR16QMask32 bin, Fmt.VRR
        | 0xE7A6us -> Op.VME, getVR8QVR12QVR16QMask32 bin, Fmt.VRR
        | 0xE7A7us -> Op.VMO, getVR8QVR12QVR16QMask32 bin, Fmt.VRR
        | 0xE7A9us -> Op.VMALH, getVR8QVR12QVR16QVR32QMask20 bin, Fmt.VRR
        | 0xE7AAus -> Op.VMAL, getVR8QVR12QVR16QVR32QMask20 bin, Fmt.VRR
        | 0xE7ABus -> Op.VMAH, getVR8QVR12QVR16QVR32QMask20 bin, Fmt.VRR
        | 0xE7ACus -> Op.VMALE, getVR8QVR12QVR16QVR32QMask20 bin, Fmt.VRR
        | 0xE7ADus -> Op.VMALO, getVR8QVR12QVR16QVR32QMask20 bin, Fmt.VRR
        | 0xE7AEus -> Op.VMAE, getVR8QVR12QVR16QVR32QMask20 bin, Fmt.VRR
        | 0xE7AFus -> Op.VMAO, getVR8QVR12QVR16QVR32QMask20 bin, Fmt.VRR
        | 0xE7B4us -> Op.VGFM, getVR8QVR12QVR16QMask32 bin, Fmt.VRR
        | 0xE7B8us ->
          Op.VMSL, getVR8QVR12QVR16QVR32QMask20Mask24 bin, Fmt.VRR
        | 0xE7B9us -> Op.VACCC, getVR8QVR12QVR16QVR32Q bin, Fmt.VRR
        | 0xE7BBus -> Op.VAC, getVR8QVR12QVR16QVR32QMask20 bin, Fmt.VRR
        | 0xE7BCus -> Op.VGFMA, getVR8QVR12QVR16QVR32QMask20 bin, Fmt.VRR
        | 0xE7BDus -> Op.VSBCBI, getVR8QVR12QVR16QVR32QMask20 bin, Fmt.VRR
        | 0xE7BFus -> Op.VSBI, getVR8QVR12QVR16QVR32QMask20 bin, Fmt.VRR
        | 0xE7C0us -> Op.VCLFP, getVR8QVR12QMask32Mask28Mask24 bin, Fmt.VRR
        | 0xE7C1us -> Op.VCFPL, getVR8QVR12QMask32Mask28Mask24 bin, Fmt.VRR
        | 0xE7C2us -> Op.VCSFP, getVR8QVR12QMask32Mask28Mask24 bin, Fmt.VRR
        | 0xE7C3us -> Op.VCFPS, getVR8QVR12QMask32Mask28Mask24 bin, Fmt.VRR
        | 0xE7C4us -> Op.VFLL, getVR8QVR12QMask32Mask28 bin, Fmt.VRR
        | 0xE7C5us -> Op.VFLR, getVR8QVR12QMask32Mask28Mask24 bin, Fmt.VRR
        | 0xE7C7us -> Op.VFI, getVR8QVR12QMask32Mask28Mask24 bin, Fmt.VRR
        | 0xE7CAus -> Op.WFK, getVR8QVR12QMask32Mask28 bin, Fmt.VRR
        | 0xE7CBus -> Op.WFC, getVR8QVR12QMask32Mask28 bin, Fmt.VRR
        | 0xE7CCus -> Op.VFPSO, getVR8QVR12QMask32Mask28Mask24 bin, Fmt.VRR
        | 0xE7CEus -> Op.VFSQ, getVR8QVR12QMask32Mask28 bin, Fmt.VRR
        | 0xE7D4us -> Op.VUPLL, getVR8QVR12QMask32 bin, Fmt.VRR
        | 0xE7D5us -> Op.VUPLH, getVR8QVR12QMask32 bin, Fmt.VRR
        | 0xE7D6us -> Op.VUPL, getVR8QVR12QMask32 bin, Fmt.VRR
        | 0xE7D7us -> Op.VUPH, getVR8QVR12Q bin, Fmt.VRR
        | 0xE7D8us -> Op.VTM, getVR8QVR12QMask32 bin, Fmt.VRR
        | 0xE7D9us -> Op.VECL, getVR8QVR12QMask32 bin, Fmt.VRR
        | 0xE7DBus -> Op.VEC, getVR8QVR12QMask32 bin, Fmt.VRR
        | 0xE7DEus -> Op.VLC, getVR8QVR12QMask32 bin, Fmt.VRR
        | 0xE7DFus -> Op.VLP, getVR8QVR12QMask32 bin, Fmt.VRR
        | 0xE7E2us -> Op.VFS, getVR8QVR12QMask32 bin, Fmt.VRR
        | 0xE7E3us -> Op.VFA, getVR8QVR12QVR16QMask32Mask28 bin, Fmt.VRR
        | 0xE7E5us -> Op.VFD, getVR8QVR12QVR16QMask32Mask28 bin, Fmt.VRR
        | 0xE7E7us -> Op.VFM, getVR8QVR12QVR16QMask32Mask28 bin, Fmt.VRR
        | 0xE7E8us ->
          Op.VFCE, getVR8QVR12QVR16QMask32Mask28Mask24 bin, Fmt.VRR
        | 0xE7EAus ->
          Op.VFCHE, getVR8QVR12QVR16QMask32Mask28Mask24 bin, Fmt.VRR
        | 0xE7EBus ->
          Op.VFCH, getVR8QVR12QVR16QMask32Mask28Mask24 bin, Fmt.VRR
        | 0xE7EEus ->
          Op.VFMIN, getVR8QVR12QVR16QMask32Mask28Mask24 bin, Fmt.VRR
        | 0xE7EFus ->
          Op.VFMAX, getVR8QVR12QVR16QMask32Mask28Mask24 bin, Fmt.VRR
        | 0xE7F0us -> Op.VAVGL, getVR8QVR12QVR16QMask32 bin, Fmt.VRR
        | 0xE7F1us -> Op.VACC, getVR8QVR12QVR16QMask32 bin, Fmt.VRR
        | 0xE7F2us -> Op.VAVG, getVR8QVR12QVR16QMask32 bin, Fmt.VRR
        | 0xE7F3us -> Op.VA, getVR8QVR12QVR16QMask32 bin, Fmt.VRR
        | 0xE7F5us -> Op.VSCBI, getVR8QVR12QVR16QMask32 bin, Fmt.VRR
        | 0xE7F7us -> Op.VS, getVR8QVR12QVR16QMask32 bin, Fmt.VRR
        | 0xE7F8us -> Op.VCEQ, getVR8QVR12QVR16QMask32Mask24 bin, Fmt.VRR
        | 0xE7F9us -> Op.VCHL, getVR8QVR12QVR16QMask32Mask24 bin, Fmt.VRR
        | 0xE7FBus -> Op.VCH, getVR8QVR12QVR16QMask32Mask24 bin, Fmt.VRR
        | 0xE7FCus -> Op.VMNL, getVR8QVR12QVR16QMask32 bin, Fmt.VRR
        | 0xE7FDus -> Op.VMXL, getVR8QVR12QVR16QMask32 bin, Fmt.VRR
        | 0xE7FEus -> Op.VMN, getVR8QVR12QVR16QMask32 bin, Fmt.VRR
        | 0xE7FFus -> Op.VMX, getVR8QVR12QVR16QMask32 bin, Fmt.VRR
        | 0xE637us -> Op.VLRLR, getVR32QM16D20GR12Q bin, Fmt.VRS
        | 0xE63Fus -> Op.VSTRLR, getVR32QM16D20GR12Q bin, Fmt.VRS
        | 0xE721us -> Op.VLGV, getGR8QM16D20VR12QMask32 bin, Fmt.VRS
        | 0xE722us -> Op.VLVG, getVR8QM16D20GR12QMask32 bin, Fmt.VRS
        | 0xE730us -> Op.VESL, getVR8QM16D20VR12QMask32 bin, Fmt.VRS
        | 0xE733us -> Op.VERLL, getVR8QM16D20VR12QMask32 bin, Fmt.VRS
        | 0xE736us -> Op.VLM, getVR8QM16D20VR12QMask32 bin, Fmt.VRS
        | 0xE737us -> Op.VLL, getVR8QM16D20GR12Q bin, Fmt.VRS
        | 0xE738us -> Op.VESRL, getVR8QM16D20VR12QMask32 bin, Fmt.VRS
        | 0xE73Aus -> Op.VESRA, getVR8QM16D20VR12QMask32 bin, Fmt.VRS
        | 0xE73Eus -> Op.VSTM, getVR8QM16D20VR12QMask32 bin, Fmt.VRS
        | 0xE73Fus -> Op.VSTL, getVR8QM16D20GR12Q bin, Fmt.VRS
        | 0xE712us -> Op.VGEG, getVR8QVIdxM16D20Mask32 bin, Fmt.VRV
        | 0xE713us -> Op.VGEF, getVR8QVIdxM16D20Mask32 bin, Fmt.VRV
        | 0xE71Aus -> Op.VSCEG, getVR8QVIdxM16D20Mask32 bin, Fmt.VRV
        | 0xE71Bus -> Op.VSCEF, getVR8QVIdxM16D20Mask32 bin, Fmt.VRV
        | 0xE601us -> Op.VLEBRH, getVR8QIdxM16D20Mask32 bin, Fmt.VRX
        | 0xE602us -> Op.VLEBRG, getVR8QIdxM16D20Mask32 bin, Fmt.VRX
        | 0xE603us -> Op.VLEBRF, getVR8QIdxM16D20Mask32 bin, Fmt.VRX
        | 0xE604us -> Op.VLLEBRZ, getVR8QIdxM16D20Mask32 bin, Fmt.VRX
        | 0xE605us -> Op.VLBRREP, getVR8QIdxM16D20Mask32 bin, Fmt.VRX
        | 0xE606us -> Op.VLBR, getVR8QIdxM16D20Mask32 bin, Fmt.VRX
        | 0xE607us -> Op.VLER, getVR8QIdxM16D20Mask32 bin, Fmt.VRX
        | 0xE609us -> Op.VSTEBRH, getVR8QIdxM16D20Mask32 bin, Fmt.VRX
        | 0xE60Aus -> Op.VSTEBRG, getVR8QIdxM16D20Mask32 bin, Fmt.VRX
        | 0xE60Bus -> Op.VSTEBRF, getVR8QIdxM16D20Mask32 bin, Fmt.VRX
        | 0xE60Fus -> Op.VSTER, getVR8QIdxM16D20Mask32 bin, Fmt.VRX
        | 0xE700us -> Op.VLEB, getVR8QIdxM16D20Mask32 bin, Fmt.VRX
        | 0xE701us -> Op.VLEH, getVR8QIdxM16D20Mask32 bin, Fmt.VRX
        | 0xE702us -> Op.VLEG, getVR8QIdxM16D20Mask32 bin, Fmt.VRX
        | 0xE703us -> Op.VLEF, getVR8QIdxM16D20Mask32 bin, Fmt.VRX
        | 0xE704us -> Op.VLLEZ, getVR8QIdxM16D20Mask32 bin, Fmt.VRX
        | 0xE705us -> Op.VLREP, getVR8QIdxM16D20Mask32 bin, Fmt.VRX
        | 0xE706us -> Op.VL, getVR8QIdxM16D20Mask32 bin, Fmt.VRX
        | 0xE707us -> Op.VLBB, getVR8QIdxM16D20Mask32 bin, Fmt.VRX
        | 0xE708us -> Op.VSTEB, getVR8QIdxM16D20Mask32 bin, Fmt.VRX
        | 0xE709us -> Op.VSTEH, getVR8QIdxM16D20Mask32 bin, Fmt.VRX
        | 0xE70Aus -> Op.VSTEG, getVR8QIdxM16D20Mask32 bin, Fmt.VRX
        | 0xE70Bus -> Op.VSTEF, getVR8QIdxM16D20Mask32 bin, Fmt.VRX
        | 0xE70Eus -> Op.VST, getVR8QIdxM16D20Mask32 bin, Fmt.VRX
        | 0xE634us -> Op.VPKZ, getVR32QM16D20UImm8 bin, Fmt.VSI
        | 0xE635us -> Op.VLRL, getVR32QM16D20UImm8 bin, Fmt.VSI
        | 0xE63Cus -> Op.VUPKZ, getVR32QM16D20UImm8 bin, Fmt.VSI
        | 0xE63Dus -> Op.VSTRL, getVR32QM16D20UImm8 bin, Fmt.VSI
        | _ -> Op.InvalOp, NoOperand, Fmt.Invalid

let parseByFmt (span: ByteSpan) (reader: IBinReader) bin =
  match extract16 bin 0 1 with
  | 0b00us -> parseInstLenOne (reader.ReadUInt16 (span, 0)), 2u
  | 0b01us | 0b10us -> parseInstLenTwo (reader.ReadUInt32 (span, 0)), 4u
  | 0b11us ->
    span.Slice(0, 6).ToArray ()
    |> Array.rev
    |> BitVector.OfArr
    |> BitVector.ToUInt64
    |> parseInstLenThree, 6u
  | _ -> Terminator.impossible ()

let parse lifter (span: ByteSpan) (reader: IBinReader) wordSize addr =
  let bin = reader.ReadUInt16 (span, 0)
  let (opcode, operand, fmt), numBytes = parseByFmt span reader bin
  Instruction (addr, numBytes, fmt, opcode, operand, wordSize, lifter)

// vim: set tw=80 sts=2 sw=2:
