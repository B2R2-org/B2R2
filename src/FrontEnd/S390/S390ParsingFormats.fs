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
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*)

module internal B2R2.FrontEnd.S390.ParsingFormats

open System
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.BitData
open B2R2.FrontEnd.S390.Helper

let fillFmt op opr fmt =
  match op with
  | Op.InvalOp -> struct (op, opr, Fmt.Invalid)
  | _ -> struct (op, opr, fmt)

let parseE (bin: uint16) (state: State) =
  let opcode = bin
  let struct (op, opr) =
    match opcode with
    | 0x0101us -> struct (Op.PR, NoOperand)
    | 0x0102us -> struct (Op.UPT, NoOperand)
    | 0x0104us -> struct (Op.PTFF, NoOperand)
    | 0x0107us -> struct (Op.SCKPF, NoOperand)
    | 0x010Aus -> struct (Op.PFPO, NoOperand)
    | 0x010Bus -> struct (Op.TAM, NoOperand)
    | 0x010Cus -> struct (Op.SAM24, NoOperand)
    | 0x010Dus -> struct (Op.SAM31, NoOperand)
    | 0x010Eus -> struct (Op.SAM64, NoOperand)
    | 0x01FFus -> struct (Op.TRAP2, NoOperand)
    | _ -> struct (Op.InvalOp, NoOperand)
  fillFmt op opr Fmt.E

let parseI (bin: uint16) (state: State) =
  let opcode = extract16 bin 0 7
  let imm = extract16 bin 8 15 |> uint8 |> ImmU8

  match opcode with
  | 0x0Aus -> struct (Op.SVC, OneOperand (OpImm imm), Fmt.E)
  | _ -> struct (Op.InvalOp, NoOperand, Fmt.Invalid)

let parseRR (bin: uint16) (state: State) =
  let opcode = extract16 bin 0 7
  let op1 = extract16 bin 8 11
  let op2 = extract16 bin 12 15
  let pick = modeSelect state.Tm
  let r1op1 = pick (getR op1) (getAR op2)
  let r2op2 = pick (getR op2) (getAR op2)

  let struct (op, opr) =
    match opcode with
    | 0x04us -> struct (Op.SPM, OneOperand (OpReg (getR op1)))
    | 0x05us ->
      struct (Op.BALR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0x06us ->
      struct (Op.BCTR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0x07us -> struct (Op.BCR, TwoOperands (OpMask op1, OpReg (getR op2)))
    | 0x0Bus ->
      struct (Op.BSM, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0x0Cus ->
      struct (Op.BASSM, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0x0Dus ->
      struct (Op.BASR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0x0Eus ->
      struct (Op.MVCL, TwoOperands (OpReg r1op1, OpReg r2op2))
    | 0x0Fus ->
      struct (Op.CLCL, TwoOperands (OpReg r1op1, OpReg r2op2))
    | 0x10us ->
      struct (Op.LPR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0x11us ->
      struct (Op.LNR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0x12us ->
      struct (Op.LTR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0x13us ->
      struct (Op.LCR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0x14us ->
      struct (Op.NR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0x15us ->
      struct (Op.CLR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0x16us ->
      struct (Op.OR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0x17us ->
      struct (Op.XR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0x18us ->
      struct (Op.LR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0x19us ->
      struct (Op.CR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0x1Aus ->
      struct (Op.AR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0x1Bus ->
      struct (Op.SR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0x1Cus ->
      struct (Op.MR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0x1Dus ->
      struct (Op.DR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0x1Eus ->
      struct (Op.ALR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0x1Fus ->
      struct (Op.SLR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0x20us ->
      struct (Op.LPDR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0x21us ->
      struct (Op.LNDR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0x22us ->
      struct (Op.LTDR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0x23us ->
      struct (Op.LCDR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0x24us ->
      struct (Op.HDR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0x25us ->
      struct (Op.LDXR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0x26us ->
      struct (Op.MXR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0x27us ->
      struct (Op.MXDR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0x28us ->
      struct (Op.LDR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0x29us ->
      struct (Op.CDR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0x2Aus ->
      struct (Op.ADR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0x2Bus ->
      struct (Op.SDR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0x2Cus ->
      struct (Op.MDR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0x2Dus ->
      struct (Op.DDR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0x2Eus ->
      struct (Op.AWR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0x2Fus ->
      struct (Op.SWR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0x30us ->
      struct (Op.LPER, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0x31us ->
      struct (Op.LNER, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0x32us ->
      struct (Op.LTER, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0x33us ->
      struct (Op.LCER, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0x34us ->
      struct (Op.HER, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0x35us ->
      struct (Op.LEDR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0x36us ->
      struct (Op.AXR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0x37us ->
      struct (Op.SXR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0x38us ->
      struct (Op.LER, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0x39us ->
      struct (Op.CER, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0x3Aus ->
      struct (Op.AER, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0x3Bus ->
      struct (Op.SER, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0x3Cus ->
      struct (Op.MDER, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0x3Dus ->
      struct (Op.DER, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0x3Eus ->
      struct (Op.AUR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0x3Fus ->
      struct (Op.SUR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | _ -> struct(Op.InvalOp, NoOperand)
  fillFmt op opr Fmt.RR

let parseRX (bin: uint32) (state: State) =
  let opcode = extract32 bin 0 7 |> uint16
  let op1 = extract32 bin 8 11 |> uint16
  let idx2 = extract32 bin 12 15 |> uint16 |> getR |> Some
  let base2 = extract32 bin 16 19 |> uint16
  let disp2 = extract32 bin 20 31 |> uint32 |> DispU
  let op2 = OpStore (idx2, getR base2, disp2)

  /// for access-register mode addressing
  let op2a = OpStore (idx2, getAR base2, disp2)
  let b2op2 = modeSelect state.Tm op2 op2a
  let bpop2 = modeSelectBP state.Bp op2 op2a

  let struct (op, opr) =
    match opcode with
    | 0x40us -> struct (Op.STH, TwoOperands (OpReg (getR op1), b2op2))
    | 0x41us -> struct (Op.LA, TwoOperands (OpReg (getR op1), op2))
    | 0x42us -> struct (Op.STC, TwoOperands (OpReg (getR op1), b2op2))
    | 0x43us -> struct (Op.IC, TwoOperands (OpReg (getR op1), b2op2))
    | 0x44us -> struct (Op.EX, TwoOperands (OpReg (getR op1), op2))
    | 0x45us -> struct (Op.BAL, TwoOperands (OpReg (getR op1), op2))
    | 0x46us -> struct (Op.BCT, TwoOperands (OpReg (getR op1), op2))
    | 0x47us -> struct (Op.BC, TwoOperands (OpMask op1, op2))
    | 0x48us -> struct (Op.LH, TwoOperands (OpReg (getR op1), b2op2))
    | 0x49us -> struct (Op.CH, TwoOperands (OpReg (getR op1), b2op2))
    | 0x4Aus -> struct (Op.AH, TwoOperands (OpReg (getR op1), b2op2))
    | 0x4Bus -> struct (Op.SH, TwoOperands (OpReg (getR op1), b2op2))
    | 0x4Cus -> struct (Op.MH, TwoOperands (OpReg (getR op1), b2op2))
    | 0x4Dus -> struct (Op.BAS, TwoOperands (OpReg (getR op1), op2))
    | 0x4Eus -> struct (Op.CVD, TwoOperands (OpReg (getR op1), b2op2))
    | 0x4Fus -> struct (Op.CVB, TwoOperands (OpReg (getR op1), b2op2))
    | 0x50us -> struct (Op.ST, TwoOperands (OpReg (getR op1), b2op2))
    | 0x51us -> struct (Op.LAE, TwoOperands (OpReg (getAR op1), bpop2))
    | 0x54us -> struct (Op.N, TwoOperands (OpReg (getR op1), b2op2))
    | 0x55us -> struct (Op.CL, TwoOperands (OpReg (getR op1), b2op2))
    | 0x56us -> struct (Op.O, TwoOperands (OpReg (getR op1), b2op2))
    | 0x57us -> struct (Op.X, TwoOperands (OpReg (getR op1), b2op2))
    | 0x58us -> struct (Op.L, TwoOperands (OpReg (getR op1), b2op2))
    | 0x59us -> struct (Op.C, TwoOperands (OpReg (getR op1), b2op2))
    | 0x5Aus -> struct (Op.A, TwoOperands (OpReg (getR op1), b2op2))
    | 0x5Bus -> struct (Op.S, TwoOperands (OpReg (getR op1), b2op2))
    | 0x5Cus -> struct (Op.M, TwoOperands (OpReg (getR op1), b2op2))
    | 0x5Dus -> struct (Op.D, TwoOperands (OpReg (getR op1), b2op2))
    | 0x5Eus -> struct (Op.AL, TwoOperands (OpReg (getR op1), b2op2))
    | 0x5Fus -> struct (Op.SL, TwoOperands (OpReg (getR op1), b2op2))
    | 0x60us -> struct (Op.STD, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0x67us -> struct (Op.MXD, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0x68us -> struct (Op.LD, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0x69us -> struct (Op.CD, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0x6Aus -> struct (Op.AD, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0x6Bus -> struct (Op.SD, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0x6Cus -> struct (Op.MD, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0x6Dus -> struct (Op.DD, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0x6Eus -> struct (Op.AW, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0x6Fus -> struct (Op.SW, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0x70us -> struct (Op.STE, TwoOperands (OpReg (getR op1), b2op2))
    | 0x71us -> struct (Op.MS, TwoOperands (OpReg (getR op1), b2op2))
    | 0x78us -> struct (Op.LE, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0x79us -> struct (Op.CE, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0x7Aus -> struct (Op.AE, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0x7Bus -> struct (Op.SE, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0x7Cus -> struct (Op.MDE, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0x7Dus -> struct (Op.DE, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0x7Eus -> struct (Op.AU, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0x7Fus -> struct (Op.SU, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0xB1us -> struct (Op.LRA, TwoOperands (OpReg (getR op1), bpop2))
    | _ -> struct (Op.InvalOp, NoOperand)

  fillFmt op opr Fmt.RX

let parseRI (bin: uint32) (state: State) =
  let opcode1 = extract32 bin 0 7 |> uint16
  let opcode2 = extract32 bin 12 15 |> uint16
  let opcode = opcode1  <<< 4 ||| opcode2
  let op1 = extract32 bin 8 11 |> uint16
  let op2 = extract32 bin 16 31 |> int16

  let struct (op, opr) =
    match opcode with
    | 0xA50us ->
      struct (Op.IIHH,
        TwoOperands (OpReg (getR op1), OpImm (ImmU16 (uint16 op2))))
    | 0xA51us ->
      struct (Op.IIHL,
        TwoOperands (OpReg (getR op1), OpImm (ImmU16 (uint16 op2))))
    | 0xA52us ->
      struct (Op.IILH,
        TwoOperands (OpReg (getR op1), OpImm (ImmU16 (uint16 op2))))
    | 0xA53us ->
      struct (Op.IILL,
        TwoOperands (OpReg (getR op1), OpImm (ImmU16 (uint16 op2))))
    | 0xA54us ->
      struct (Op.NIHH,
        TwoOperands (OpReg (getR op1), OpImm (ImmU16 (uint16 op2))))
    | 0xA55us ->
      struct (Op.NIHL,
        TwoOperands (OpReg (getR op1), OpImm (ImmU16 (uint16 op2))))
    | 0xA56us ->
      struct (Op.NILH,
        TwoOperands (OpReg (getR op1), OpImm (ImmU16 (uint16 op2))))
    | 0xA57us ->
      struct (Op.NILL,
        TwoOperands (OpReg (getR op1), OpImm (ImmU16 (uint16 op2))))
    | 0xA58us ->
      struct (Op.OIHH,
        TwoOperands (OpReg (getR op1), OpImm (ImmU16 (uint16 op2))))
    | 0xA59us ->
      struct (Op.OIHL,
        TwoOperands (OpReg (getR op1), OpImm (ImmU16 (uint16 op2))))
    | 0xA5Aus ->
      struct (Op.OILH,
        TwoOperands (OpReg (getR op1), OpImm (ImmU16 (uint16 op2))))
    | 0xA5Bus ->
      struct (Op.OILL,
        TwoOperands (OpReg (getR op1), OpImm (ImmU16 (uint16 op2))))
    | 0xA5Cus ->
      struct (Op.LLIHH,
        TwoOperands (OpReg (getR op1), OpImm (ImmU16 (uint16 op2))))
    | 0xA5Dus ->
      struct (Op.LLIHL,
        TwoOperands (OpReg (getR op1), OpImm (ImmU16 (uint16 op2))))
    | 0xA5Eus ->
      struct (Op.LLILH,
        TwoOperands (OpReg (getR op1), OpImm (ImmU16 (uint16 op2))))
    | 0xA5Fus ->
      struct (Op.LLILL,
        TwoOperands (OpReg (getR op1), OpImm (ImmU16 (uint16 op2))))
    | 0xA70us ->
      struct(Op.TMLH, TwoOperands (OpReg (getR op1), OpMask (uint16 op2)))
    | 0xA71us ->
      struct(Op.TMLL, TwoOperands (OpReg (getR op1), OpMask (uint16 op2)))
    | 0xA72us ->
      struct(Op.TMHH, TwoOperands (OpReg (getR op1), OpMask (uint16 op2)))
    | 0xA73us ->
      struct(Op.TMHL, TwoOperands (OpReg (getR op1), OpMask (uint16 op2)))
    | 0xA74us ->
      struct(Op.BRC, TwoOperands (OpMask (uint16 op1), OpRImm (ImmS16 op2)))
    | 0xA75us ->
      struct(Op.BRAS, TwoOperands (OpReg (getR op1), OpRImm (ImmS16 op2)))
    | 0xA76us ->
      struct(Op.BRCT, TwoOperands (OpReg (getR op1), OpRImm (ImmS16 op2)))
    | 0xA77us ->
      struct(Op.BRCTG, TwoOperands (OpReg (getR op1), OpRImm (ImmS16 op2)))
    | 0xA78us ->
      struct(Op.LHI, TwoOperands (OpReg (getR op1), OpImm (ImmS16 op2)))
    | 0xA79us ->
      struct(Op.LGHI, TwoOperands (OpReg (getR op1), OpImm (ImmS16 op2)))
    | 0xA7Aus ->
      struct(Op.AHI, TwoOperands (OpReg (getR op1), OpImm (ImmS16 op2)))
    | 0xA7Bus ->
      struct(Op.AGHI, TwoOperands (OpReg (getR op1), OpImm (ImmS16 op2)))
    | 0xA7Cus ->
      struct(Op.MHI, TwoOperands (OpReg (getR op1), OpImm (ImmS16 op2)))
    | 0xA7Dus ->
      struct(Op.MGHI, TwoOperands (OpReg (getR op1), OpImm (ImmS16 op2)))
    | 0xA7Eus ->
      struct(Op.CHI, TwoOperands (OpReg (getR op1), OpImm (ImmS16 op2)))
    | 0xA7Fus ->
      struct(Op.CGHI, TwoOperands (OpReg (getR op1), OpImm (ImmS16 op2)))
    | _ -> struct (Op.InvalOp, NoOperand)
  fillFmt op opr Fmt.RI

let parseRS (bin: uint32) (state: State) =
  let opcode = extract32 bin 0 7 |> uint16
  let op1 = extract32 bin 8 11 |> uint16
  let op3 = extract32 bin 12 15 |> uint16
  let base2 = extract32 bin 16 19 |> uint16
  let disp2 = extract32 bin 20 31 |> uint32 |> DispU
  let op2 = OpStore (None, getR base2, disp2)
  let op2a = OpStore (None, getAR base2, disp2)
  let inline pick gen acc = modeSelect state.Tm gen acc
  let r1op1 = pick (getR op1) (getAR op1)
  let b2op2 = pick op2 op2a
  let r3op3 = pick (getR op3) (getAR op3)

  let struct (op, opr) =
    match opcode with
    | 0x86us ->
      struct (Op.BXH, ThreeOperands (OpReg (getR op1), op2, OpReg (getR op3)))
    | 0x87us ->
      struct (Op.BXLE, ThreeOperands (OpReg (getR op1), op2, OpReg (getR op3)))
    | 0x88us -> struct (Op.SRL, TwoOperands (OpReg (getR op1), op2))
    | 0x89us -> struct (Op.SLL, TwoOperands (OpReg (getR op1), op2))
    | 0x8Aus -> struct (Op.SRA, TwoOperands (OpReg (getR op1), op2))
    | 0x8Bus -> struct (Op.SLA, TwoOperands (OpReg (getR op1), op2))
    | 0x8Cus -> struct (Op.SRDL, TwoOperands (OpReg (getR op1), op2))
    | 0x8Dus -> struct (Op.SLDL, TwoOperands (OpReg (getR op1), op2))
    | 0x8Eus -> struct (Op.SRDA, TwoOperands (OpReg (getR op1), op2))
    | 0x8Fus -> struct (Op.SLDA, TwoOperands (OpReg (getR op1), op2))
    | 0x90us ->
      struct (Op.STM, ThreeOperands (OpReg (getR op1), b2op2, OpReg (getR op3)))
    | 0x98us ->
      struct (Op.LM, ThreeOperands (OpReg (getR op1), b2op2, OpReg (getR op3)))
    | 0x99us ->
      struct (Op.TRACE,
        ThreeOperands (OpReg (getR op1), b2op2, OpReg (getR op3)))
    | 0x9Aus ->
      struct (Op.LAM, ThreeOperands (OpReg (getAR op1), op2, OpReg (getAR op3)))
    | 0x9Bus ->
      struct (Op.STAM,
        ThreeOperands (OpReg (getAR op1), op2, OpReg (getAR op3)))
    | 0xA8us ->
      struct (Op.MVCLE, ThreeOperands (OpReg r1op1, op2, OpReg r3op3))
    | 0xA9us ->
      struct (Op.CLCLE, ThreeOperands (OpReg r1op1, op2, OpReg r3op3))
    | 0xAEus ->
      struct (Op.SIGP, ThreeOperands (OpReg (getR op1), op2, OpReg (getR op3)))
    | 0xB6us ->
      struct (Op.STCTL,
        ThreeOperands (OpReg (getCR op1), b2op2, OpReg (getCR op3)))
    | 0xB7us ->
      struct (Op.LCTL,
        ThreeOperands (OpReg (getCR op1), b2op2, OpReg (getCR op3)))
    | 0xBAus ->
      struct (Op.CS, ThreeOperands (OpReg (getR op1), b2op2, OpReg (getR op3)))
    | 0xBBus ->
      struct (Op.CDS, ThreeOperands (OpReg (getR op1), b2op2, OpReg (getR op3)))
    | 0xBDus ->
      struct (Op.CLM, ThreeOperands (OpReg (getR op1), b2op2, OpMask op3))
    | 0xBEus ->
      struct (Op.STCM, ThreeOperands (OpReg (getR op1), b2op2, OpMask op3))
    | 0xBFus ->
      struct (Op.ICM, ThreeOperands (OpReg (getR op1), b2op2, OpMask op3))
    | _ -> struct (Op.InvalOp, NoOperand)
  fillFmt op opr Fmt.RS

let parseRRD (bin: uint32) (state: State) =
  let opcode = extract32 bin 0 15 |> uint16
  let op1 = extract32 bin 16 19 |> uint16 |> getFPR |> OpReg
  let op3 = extract32 bin 24 27 |> uint16 |> getFPR |> OpReg
  let op2 = extract32 bin 28 31 |> uint16 |> getFPR |> OpReg

  let struct (op, opr) =
    match opcode with
      | 0xB30Eus -> struct (Op.MAEBR, ThreeOperands (op1, op2, op3))
      | 0xB30Fus -> struct (Op.MSEBR, ThreeOperands (op1, op2, op3))
      | 0xB31Eus -> struct (Op.MADBR, ThreeOperands (op1, op2, op3))
      | 0xB31Fus -> struct (Op.MSDBR, ThreeOperands (op1, op2, op3))
      | 0xB32Eus -> struct (Op.MAER, ThreeOperands (op1, op2, op3))
      | 0xB32Fus -> struct (Op.MSER, ThreeOperands (op1, op2, op3))
      | 0xB338us -> struct (Op.MAYLR, ThreeOperands (op1, op2, op3))
      | 0xB339us -> struct (Op.MYLR, ThreeOperands (op1, op2, op3))
      | 0xB33Aus -> struct (Op.MAYR, ThreeOperands (op1, op2, op3))
      | 0xB33Bus -> struct (Op.MYR, ThreeOperands (op1, op2, op3))
      | 0xB33Cus -> struct (Op.MAYHR, ThreeOperands (op1, op2, op3))
      | 0xB33Dus -> struct (Op.MYHR, ThreeOperands (op1, op2, op3))
      | 0xB33Eus -> struct (Op.MADR, ThreeOperands (op1, op2, op3))
      | 0xB33Fus -> struct (Op.MSDR, ThreeOperands (op1, op2, op3))
      | _ -> struct (Op.InvalOp, NoOperand)
  fillFmt op opr Fmt.RRD

let parseSI (bin: uint32) (state: State) =
  let opcode = extract32 bin 0 7 |> uint16
  let op2 = extract32 bin 8 15 |> uint8 |> ImmU8 |> OpImm
  let base1 = extract32 bin 16 19 |> uint16
  let disp1 = extract32 bin 20 31 |> uint32 |> DispU
  let op1 = (None, getR base1, disp1) |> OpStore
  let op1a = (None, getAR base1, disp1) |> OpStore
  let b1op1 = modeSelect state.Tm op1 op1a

  let struct (op, opr) =
    match opcode with
    | 0x80us -> struct (Op.SSM, OneOperand b1op1)
    | 0x82us -> struct (Op.LPSW, OneOperand b1op1)
    | 0x91us -> struct (Op.TM, TwoOperands (b1op1, op2))
    | 0x92us -> struct (Op.MVI, TwoOperands (b1op1, op2))
    | 0x93us -> struct (Op.TS, OneOperand b1op1)
    | 0x94us -> struct (Op.NI, TwoOperands (b1op1, op2))
    | 0x95us -> struct (Op.CLI, TwoOperands (b1op1, op2))
    | 0x96us -> struct (Op.OI, TwoOperands (b1op1, op2))
    | 0x97us -> struct (Op.XI, TwoOperands (b1op1, op2))
    | 0xACus -> struct (Op.STNSM, TwoOperands (b1op1, op2))
    | 0xADus -> struct (Op.STOSM, TwoOperands (b1op1, op2))
    | 0xAFus -> struct (Op.MC, TwoOperands (op1, op2))
    | _ -> struct (Op.InvalOp, NoOperand)
  fillFmt op opr Fmt.SI

let parseS (bin: uint32) (state: State) =
  let opcode = extract32 bin 0 15 |> uint16
  let base2 = extract32 bin 16 19 |> uint16
  let disp2 = extract32 bin 20 31 |> uint32 |> DispU
  let op2 = OpStore (None, getR base2, disp2)
  let op2a = OpStore (None, getAR base2, disp2)
  let b2op2 = modeSelect state.Tm op2 op2a

  let struct (op, opr) =
    match opcode with
      | 0xB200us -> struct (Op.LBEAR, OneOperand b2op2)
      | 0xB201us -> struct (Op.STBEAR, OneOperand b2op2)
      | 0xB202us -> struct (Op.STIDP, OneOperand b2op2)
      | 0xB204us -> struct (Op.SCK, OneOperand b2op2)
      | 0xB205us -> struct (Op.STCK, OneOperand b2op2)
      | 0xB206us -> struct (Op.SCKC, OneOperand b2op2)
      | 0xB207us -> struct (Op.STCKC, OneOperand b2op2)
      | 0xB208us -> struct (Op.SPT, OneOperand b2op2)
      | 0xB209us -> struct (Op.STPT, OneOperand b2op2)
      | 0xB20Aus -> struct (Op.SPKA, OneOperand op2)
      | 0xB20Bus -> struct (Op.IPK, NoOperand)
      | 0xB20Dus -> struct (Op.PTLB, NoOperand)
      | 0xB210us -> struct (Op.SPX, OneOperand b2op2)
      | 0xB211us -> struct (Op.STPX, OneOperand b2op2)
      | 0xB212us -> struct (Op.STAP, OneOperand b2op2)
      | 0xB218us -> struct (Op.PC, OneOperand op2)
      | 0xB219us -> struct (Op.SAC, OneOperand op2)
      | 0xB21Aus -> struct (Op.CFC, OneOperand op2)
      | 0xB230us -> struct (Op.CSCH, NoOperand)
      | 0xB231us -> struct (Op.HSCH, NoOperand)
      | 0xB232us -> struct (Op.MSCH, OneOperand b2op2)
      | 0xB233us -> struct (Op.SSCH, OneOperand b2op2)
      | 0xB234us -> struct (Op.STSCH, OneOperand b2op2)
      | 0xB235us -> struct (Op.TSCH, OneOperand b2op2)
      | 0xB236us -> struct (Op.TPI, OneOperand b2op2)
      | 0xB237us -> struct (Op.SAL, NoOperand)
      | 0xB238us -> struct (Op.RSCH, NoOperand)
      | 0xB239us -> struct (Op.STCRW, OneOperand b2op2)
      | 0xB23Aus -> struct (Op.STCPS, OneOperand b2op2)
      | 0xB23Bus -> struct (Op.RCHP, NoOperand)
      | 0xB23Cus -> struct (Op.SCHM, NoOperand)
      | 0xB276us -> struct (Op.XSCH, NoOperand)
      | 0xB277us -> struct (Op.RP, OneOperand b2op2)
      | 0xB278us -> struct (Op.STCKE, OneOperand b2op2)
      | 0xB279us -> struct (Op.SACF, OneOperand op2)
      | 0xB27Cus -> struct (Op.STCKF, OneOperand b2op2)
      | 0xB27Dus -> struct (Op.STSI, OneOperand b2op2)
      | 0xB28Fus -> struct (Op.QPACI, OneOperand b2op2)
      | 0xB299us -> struct (Op.SRNM, OneOperand op2)
      | 0xB29Cus -> struct (Op.STFPC, OneOperand b2op2)
      | 0xB29Dus -> struct (Op.LFPC, OneOperand b2op2)
      | 0xB2B0us -> struct (Op.STFLE, OneOperand b2op2)
      | 0xB2B1us -> struct (Op.STFL, OneOperand op2)
      | 0xB2B2us -> struct (Op.LPSWE, OneOperand b2op2)
      | 0xB2B8us -> struct (Op.SRNMB, OneOperand op2)
      | 0xB2B9us -> struct (Op.SRNMT, OneOperand op2)
      | 0xB2BDus -> struct (Op.LFAS, OneOperand b2op2)
      | 0xB2F8us -> struct (Op.TEND, NoOperand)
      | 0xB2FCus -> struct (Op.TABORT,OneOperand op2)
      | 0xB2FFus -> struct (Op.TRAP4, OneOperand op2)
      | _ -> struct (Op.InvalOp, NoOperand)
  fillFmt op opr Fmt.S

let parseRRE (bin: uint32) (state: State) =
  let opcode = extract32 bin 0 15 |> uint16
  let op1 = extract32 bin 24 27 |> uint16
  let op2 = extract32 bin 28 31 |> uint16
  let isRRF = (extract32 bin 16 23 |> uint16) <> uint16 0
  let pick = modeSelect state.Tm
  let r1op1 = pick (getR op1) (getAR op1)
  let r2op2 = pick (getR op2) (getAR op2)

  let struct (op, opr) =
    match opcode with
    | 0xB222us -> struct (Op.IPM, OneOperand (OpReg (getR op1)))
    | 0xB223us ->
      struct (Op.IVSK, TwoOperands (OpReg (getR op1), OpReg r2op2))
    | 0xB224us -> struct (Op.IAC, OneOperand (OpReg (getR op1)))
    | 0xB225us -> struct (Op.SSAR, OneOperand (OpReg (getR op1)))
    | 0xB226us -> struct (Op.EPAR, OneOperand (OpReg (getR op1)))
    | 0xB227us -> struct (Op.ESAR, OneOperand (OpReg (getR op1)))
    | 0xB228us ->
      struct (Op.PT, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB229us ->
      struct (Op.ISKE, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB22Aus ->
      struct (Op.RRBE, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB22Cus ->
      struct (Op.TB, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB22Dus ->
      struct (Op.DXR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB22Eus ->
      struct (Op.PGIN, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB22Fus ->
      struct (Op.PGOUT, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB240us ->
      struct (Op.BAKR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB241us ->
      struct (Op.CKSM, TwoOperands (OpReg (getR op1), OpReg r2op2))
    | 0xB244us ->
      struct (Op.SQDR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB245us ->
      struct (Op.SQER, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB246us ->
      struct (Op.STURA, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB247us -> struct (Op.MSTA, OneOperand (OpReg (getR op1)))
    | 0xB248us -> struct (Op.PALB, NoOperand)
    | 0xB249us ->
      struct (Op.EREG, TwoOperands (OpReg (getAR op1), OpReg (getAR op2)))
    | 0xB24Aus ->
      struct (Op.ESTA, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB24Bus ->
      struct (Op.LURA, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB24Cus ->
      struct (Op.TAR, TwoOperands (OpReg (getAR op1), OpReg (getR op2)))
    | 0xB24Dus ->
      struct (Op.CPYA, TwoOperands (OpReg (getAR op1), OpReg (getAR op2)))
    | 0xB24Eus ->
      struct (Op.SAR, TwoOperands (OpReg (getAR op1), OpReg (getR op2)))
    | 0xB24Fus ->
      struct (Op.EAR, TwoOperands (OpReg (getR op1), OpReg (getAR op2)))
    | 0xB250us ->
      struct (Op.CSP, TwoOperands (OpReg (getR op1), OpReg r2op2))
    | 0xB252us ->
      struct (Op.MSR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB254us ->
      struct (Op.MVPG, TwoOperands (OpReg r1op1, OpReg r2op2))
    | 0xB255us ->
      struct (Op.MVST, TwoOperands (OpReg r1op1, OpReg r2op2))
    | 0xB257us ->
      struct (Op.CUSE, TwoOperands (OpReg r1op1, OpReg r2op2))
    | 0xB258us ->
      struct (Op.BSG, TwoOperands (OpReg (getR op1), OpReg r2op2))
    | 0xB25Aus ->
      struct (Op.BSA, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB25Dus ->
      struct (Op.CLST, TwoOperands (OpReg r1op1, OpReg r2op2))
    | 0xB25Eus ->
      struct (Op.SRST, TwoOperands (OpReg (getR op1), OpReg r2op2))
    | 0xB263us ->
      struct (Op.CMPSC, TwoOperands (OpReg r1op1, OpReg r2op2))
    | 0xB2A5us ->
      struct (Op.TRE, TwoOperands (OpReg r1op1, OpReg r2op2))
    | 0xB2A6us when not isRRF ->
      struct (Op.CUUTF, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB2A7us when not isRRF ->
      struct (Op.CUTFU, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB2ECus -> struct (Op.ETND, OneOperand (OpReg (getR op1)))
    | 0xB300us ->
      struct (Op.LPEBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB301us ->
      struct (Op.LNEBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB302us ->
      struct (Op.LTEBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB303us ->
      struct (Op.LCEBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB304us ->
      struct (Op.LDEBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB305us ->
      struct (Op.LXDBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB306us ->
      struct (Op.LXEBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB307us ->
      struct (Op.MXDBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB308us ->
      struct (Op.KEBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB309us ->
      struct (Op.CEBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB30Aus ->
      struct (Op.AEBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB30Bus ->
      struct (Op.SEBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB30Cus ->
      struct (Op.MDEBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB30Dus ->
      struct (Op.DEBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB310us ->
      struct (Op.LPDBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB311us ->
      struct (Op.LNDBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB312us ->
      struct (Op.LTDBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB313us ->
      struct (Op.LCDBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB314us ->
      struct (Op.SQEBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB315us ->
      struct (Op.SQDBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB316us ->
      struct (Op.SQXBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB317us ->
      struct (Op.MEEBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB318us ->
      struct (Op.KDBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB319us ->
      struct (Op.CDBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB31Aus ->
      struct (Op.ADBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB31Bus ->
      struct (Op.SDBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB31Cus ->
      struct (Op.MDBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB31Dus ->
      struct (Op.DDBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB324us ->
      struct (Op.LDER, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB325us ->
      struct (Op.LXDR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB326us ->
      struct (Op.LXER, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB336us ->
      struct (Op.SQXR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB337us ->
      struct (Op.MEER, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB340us ->
      struct (Op.LPXBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB341us ->
      struct (Op.LNXBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB342us ->
      struct (Op.LTXBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB343us ->
      struct (Op.LCXBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB344us when not isRRF ->
      struct (Op.LEDBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB345us when not isRRF ->
      struct (Op.LDXBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB346us when not isRRF ->
      struct (Op.LEXBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB348us ->
      struct (Op.KXBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB349us ->
      struct (Op.CXBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB34Aus ->
      struct (Op.AXBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB34Bus ->
      struct (Op.SXBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB34Cus ->
      struct (Op.MXBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB34Dus ->
      struct (Op.DXBR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB358us ->
      struct (Op.THDER, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB359us ->
      struct (Op.THDR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB360us ->
      struct (Op.LPXR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB361us ->
      struct (Op.LNXR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB362us ->
      struct (Op.LTXR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB363us ->
      struct (Op.LCXR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB365us ->
      struct (Op.LXR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB366us ->
      struct (Op.LEXR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB367us ->
      struct (Op.FIXR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB369us ->
      struct (Op.CXR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB370us ->
      struct (Op.LPDFR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB371us ->
      struct (Op.LNDFR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB373us ->
      struct (Op.LCDFR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB374us ->
      struct (Op.LZER, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB375us ->
      struct (Op.LZDR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB376us ->
      struct (Op.LZXR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB377us ->
      struct (Op.FIER, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB37Fus ->
      struct (Op.FIDR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB384us -> struct (Op.SFPC, OneOperand (OpReg (getR op1)))
    | 0xB385us -> struct (Op.SFASR, OneOperand (OpReg (getR op1)))
    | 0xB38Cus -> struct (Op.EFPC, OneOperand (OpReg (getR op1)))
    | 0xB394us when not isRRF ->
      struct (Op.CEFBR, TwoOperands (OpReg (getFPR op1), OpReg (getR op2)))
    | 0xB395us when not isRRF ->
      struct (Op.CDFBR, TwoOperands (OpReg (getFPR op1), OpReg (getR op2)))
    | 0xB396us when not isRRF ->
      struct (Op.CXFBR, TwoOperands (OpReg (getFPR op1), OpReg (getR op2)))
    | 0xB3A4us when not isRRF ->
      struct (Op.CEGBR, TwoOperands (OpReg (getFPR op1), OpReg (getR op2)))
    | 0xB3A5us when not isRRF ->
      struct (Op.CDGBR, TwoOperands (OpReg (getFPR op1), OpReg (getR op2)))
    | 0xB3A6us when not isRRF ->
      struct (Op.CXGBR, TwoOperands (OpReg (getFPR op1), OpReg (getR op2)))
    | 0xB3B4us ->
      struct (Op.CEFR, TwoOperands (OpReg (getFPR op1), OpReg (getR op2)))
    | 0xB3B5us ->
      struct (Op.CDFR, TwoOperands (OpReg (getFPR op1), OpReg (getR op2)))
    | 0xB3B6us ->
      struct (Op.CXFR, TwoOperands (OpReg (getFPR op1), OpReg (getR op2)))
    | 0xB3C1us ->
      struct (Op.LDGR, TwoOperands (OpReg (getFPR op1), OpReg (getR op2)))
    | 0xB3C4us ->
      struct (Op.CEGR, TwoOperands (OpReg (getFPR op1), OpReg (getR op2)))
    | 0xB3C5us ->
      struct (Op.CDGR, TwoOperands (OpReg (getFPR op1), OpReg (getR op2)))
    | 0xB3C6us ->
      struct (Op.CXGR, TwoOperands (OpReg (getFPR op1), OpReg (getR op2)))
    | 0xB3CDus ->
      struct (Op.LGDR, TwoOperands (OpReg (getR op1), OpReg (getFPR op2)))
    | 0xB3D6us ->
      struct (Op.LTDTR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB3DEus ->
      struct (Op.LTXTR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB3E0us ->
      struct (Op.KDTR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB3E2us ->
      struct (Op.CUDTR, TwoOperands (OpReg (getR op1), OpReg (getFPR op2)))
    | 0xB3E4us ->
      struct (Op.CDTR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB3E5us ->
      struct (Op.EEDTR, TwoOperands (OpReg (getR op1), OpReg (getFPR op2)))
    | 0xB3E7us ->
      struct (Op.ESDTR, TwoOperands (OpReg (getR op1), OpReg (getFPR op2)))
    | 0xB3E8us ->
      struct (Op.KXTR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB3EAus ->
      struct (Op.CUXTR, TwoOperands (OpReg (getR op1), OpReg (getFPR op2)))
    | 0xB3ECus ->
      struct (Op.CXTR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB3EDus ->
      struct (Op.EEXTR, TwoOperands (OpReg (getR op1), OpReg (getFPR op2)))
    | 0xB3EFus ->
      struct (Op.ESXTR, TwoOperands (OpReg (getR op1), OpReg (getFPR op2)))
    | 0xB3F1us when not isRRF ->
      struct (Op.CDGTR, TwoOperands (OpReg (getFPR op1), OpReg (getR op2)))
    | 0xB3F2us ->
      struct (Op.CDUTR, TwoOperands (OpReg (getFPR op1), OpReg (getR op2)))
    | 0xB3F3us ->
      struct (Op.CDSTR, TwoOperands (OpReg (getFPR op1), OpReg (getR op2)))
    | 0xB3F4us ->
      struct (Op.CEDTR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB3F9us when not isRRF ->
      struct (Op.CXGTR, TwoOperands (OpReg (getFPR op1), OpReg (getR op2)))
    | 0xB3FAus ->
      struct (Op.CXUTR, TwoOperands (OpReg (getFPR op1), OpReg (getR op2)))
    | 0xB3FBus ->
      struct (Op.CXSTR, TwoOperands (OpReg (getFPR op1), OpReg (getR op2)))
    | 0xB3FCus ->
      struct (Op.CEXTR, TwoOperands (OpReg (getFPR op1), OpReg (getFPR op2)))
    | 0xB900us ->
      struct (Op.LPGR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB901us ->
      struct (Op.LNGR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB902us ->
      struct (Op.LTGR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB903us ->
      struct (Op.LCGR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB904us ->
      struct (Op.LGR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB905us ->
      struct (Op.LURAG, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB906us ->
      struct (Op.LGBR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB907us ->
      struct (Op.LGHR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB908us ->
      struct (Op.AGR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB909us ->
      struct (Op.SGR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB90Aus ->
      struct (Op.ALGR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB90Bus ->
      struct (Op.SLGR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB90Cus ->
      struct (Op.MSGR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB90Dus ->
      struct (Op.DSGR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB90Eus ->
      struct (Op.EREGG, TwoOperands (OpReg (getAR op1), OpReg (getAR op2)))
    | 0xB90Fus ->
      struct (Op.LRVGR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB910us ->
      struct (Op.LPGFR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB911us ->
      struct (Op.LNGFR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB912us ->
      struct (Op.LTGFR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB913us ->
      struct (Op.LCGFR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB914us ->
      struct (Op.LGFR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB916us ->
      struct (Op.LLGFR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB917us ->
      struct (Op.LLGTR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB918us ->
      struct (Op.AGFR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB919us ->
      struct (Op.SGFR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB91Aus ->
      struct (Op.ALGFR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB91Bus ->
      struct (Op.SLGFR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB91Cus ->
      struct (Op.MSGFR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB91Dus ->
      struct (Op.DSGFR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB91Eus ->
      struct (Op.KMAC, TwoOperands (OpReg (getR op1), OpReg r2op2))
    | 0xB91Fus ->
      struct (Op.LRVR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB920us ->
      struct (Op.CGR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB921us ->
      struct (Op.CLGR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB925us ->
      struct (Op.STURG, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB926us ->
      struct (Op.LBR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB927us ->
      struct (Op.LHR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB928us -> struct (Op.PCKMO, NoOperand)
    | 0xB92Aus ->
      struct (Op.KMF, TwoOperands (OpReg r1op1, OpReg r2op2))
    | 0xB92Bus ->
      struct (Op.KMO, TwoOperands (OpReg r1op1, OpReg r2op2))
    | 0xB92Cus -> struct (Op.PCC, NoOperand)
    | 0xB92Eus ->
      struct (Op.KM, TwoOperands (OpReg r1op1, OpReg r2op2))
    | 0xB92Fus ->
      struct (Op.KMC, TwoOperands (OpReg r1op1, OpReg r2op2))
    | 0xB930us ->
      struct (Op.CGFR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB931us ->
      struct (Op.CLGFR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB938us ->
      struct (Op.SORTL, TwoOperands (OpReg r1op1, OpReg r2op2))
    | 0xB93Aus ->
      struct (Op.KDSA, TwoOperands (OpReg r1op1, OpReg r2op2))
    | 0xB93Bus ->
      struct (Op.NNPA, NoOperand)
    | 0xB93Cus ->
      struct (Op.PRNO, TwoOperands (OpReg r1op1, OpReg r2op2))
    | 0xB93Eus ->
      struct (Op.KIMD, TwoOperands (OpReg (getR op1), OpReg r2op2))
    | 0xB93Fus ->
      struct (Op.KLMD, TwoOperands (OpReg (getR op1), OpReg r2op2))
    | 0xB946us ->
      struct (Op.BCTGR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB980us ->
      struct (Op.NGR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB981us ->
      struct (Op.OGR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB982us ->
      struct (Op.XGR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB983us ->
      struct (Op.FLOGR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB984us ->
      struct (Op.LLGCR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB985us ->
      struct (Op.LLGHR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB986us ->
      struct (Op.MLGR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB987us ->
      struct (Op.DLGR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB988us ->
      struct (Op.ALCGR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB989us ->
      struct (Op.SLBGR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB98Aus ->
      struct (Op.CSPG, TwoOperands (OpReg (getR op1), OpReg r2op2))
    | 0xB98Dus ->
      struct (Op.EPSW, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB994us ->
      struct (Op.LLCR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB995us ->
      struct (Op.LLHR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB996us ->
      struct (Op.MLR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB997us ->
      struct (Op.DLR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB998us ->
      struct (Op.ALCR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB999us ->
      struct (Op.SLBR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB99Aus -> struct (Op.EPAIR, OneOperand (OpReg (getR op1)))
    | 0xB99Bus -> struct (Op.ESAIR, OneOperand (OpReg (getR op1)))
    | 0xB99Dus -> struct (Op.ESEA, OneOperand (OpReg (getR op1)))
    | 0xB99Eus ->
      struct (Op.PTI, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB99Fus -> struct (Op.SSAIR, OneOperand (OpReg (getR op1)))
    | 0xB9A1us ->
      struct (Op.TPEI, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB9A2us -> struct (Op.PTF, OneOperand (OpReg (getR op1)))
    | 0xB9ACus ->
      struct (Op.IRBM, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB9AEus ->
      struct (Op.RRBM, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB9AFus ->
      struct (Op.PFMF, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB9B2us ->
      struct (Op.CU41, TwoOperands (OpReg r1op1, OpReg r2op2))
    | 0xB9B3us ->
      struct (Op.CU42, TwoOperands (OpReg r1op1, OpReg r2op2))
    | 0xB9BEus ->
      struct (Op.SRSTU, TwoOperands (OpReg r1op1, OpReg r2op2))
    | 0xB9CDus ->
      struct (Op.CHHR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB9CFus ->
      struct (Op.CLHHR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB9DDus ->
      struct (Op.CHLR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB9DFus ->
      struct (Op.CLHLR, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | 0xB9E1us ->
      struct (Op.POPCNT, TwoOperands (OpReg (getR op1), OpReg (getR op2)))
    | _ -> struct (Op.InvalOp, NoOperand)
  fillFmt op opr Fmt.RRE

let parseRRF (bin: uint32) (state: State) =
  let opcode = extract32 bin 0 15 |> uint16
  let op1 = extract32 bin 24 27 |> uint16
  let op2 = extract32 bin 28 31 |> uint16
  let op3 = extract32 bin 16 19 |> uint16
  let op4 = extract32 bin 20 23 |> uint16
  let pick = modeSelect state.Tm
  let r1op1 = pick (getR op1) (getAR op1)
  let r2op2 = pick (getR op2) (getAR op2)
  let r3op3 = pick (getR op3) (getAR op3)
  let isRRE = op4 = (0 |> uint16)

  let struct (op, opr) =
    match opcode with
    | 0xB221us ->
      struct (Op.IPTE, FourOperands (OpReg (getR op1), OpReg (getR op2),
        OpReg (getR op3), OpMask op4))
    | 0xB22Bus ->
      struct (Op.SSKE,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpMask op3))
    | 0xB2A6us ->
      struct (Op.CU21,
        ThreeOperands (OpReg r1op1, OpReg r2op2, OpMask op3))
    | 0xB2A7us ->
      struct (Op.CU12,
        ThreeOperands (OpReg r1op1, OpReg r2op2, OpMask op3))
    | 0xB2E8us ->
      struct (Op.PPA,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpMask op3))
    | 0xB344us when not isRRE ->
      struct (Op.LEDBRA, FourOperands (OpReg (getFPR op1), OpReg (getFPR op2),
        OpMask op3, OpMask op4)) // also RRE done
    | 0xB345us when not isRRE ->
      struct (Op.LDXBRA, FourOperands (OpReg (getFPR op1), OpReg (getFPR op2),
        OpMask op3, OpMask op4)) // RRE done
    | 0xB346us when not isRRE ->
      struct (Op.LEXBRA,
        FourOperands (OpReg (getFPR op1), OpReg (getFPR op2),
          OpMask op3, OpMask op4)) // RRE done
    | 0xB347us when not isRRE ->
      struct (Op.FIXBR,
        ThreeOperands (OpReg (getFPR op1), OpReg (getFPR op2), OpMask op3))
    | 0xB347us ->
      struct (Op.FIXBRA, FourOperands (OpReg (getFPR op1), OpReg (getFPR op2),
        OpMask op3, OpMask op4))
    | 0xB350us ->
      struct (Op.TBEDR,
        ThreeOperands (OpReg (getFPR op1), OpReg (getFPR op2), OpMask op3))
    | 0xB351us ->
      struct (Op.TBDR,
        ThreeOperands (OpReg (getFPR op1), OpReg (getFPR op2), OpMask op3))
    | 0xB353us ->
      struct (Op.DIEBR, FourOperands (OpReg (getFPR op1), OpReg (getFPR op2),
        OpReg (getFPR op3), OpMask op4))
    | 0xB357us when not isRRE ->
      struct (Op.FIEBR,
        ThreeOperands (OpReg (getFPR op1), OpReg (getFPR op2), OpMask op3))
    | 0xB357us ->
      struct (Op.FIEBRA, FourOperands (OpReg (getFPR op1), OpReg (getFPR op2),
        OpMask op3, OpMask op4))
    | 0xB35Bus ->
      struct (Op.DIDBR, FourOperands (OpReg (getFPR op1), OpReg (getFPR op2),
        OpReg (getFPR op3), OpMask op4))
    | 0xB35Fus when not isRRE ->
      struct (Op.FIDBR,
        ThreeOperands (OpReg (getFPR op1), OpReg (getFPR op2), OpMask op3))
    | 0xB35Fus ->
      struct (Op.FIDBRA, FourOperands (OpReg (getFPR op1), OpReg (getFPR op2),
        OpMask op3, OpMask op4))
    | 0xB372us ->
      struct (Op.CPSDR, ThreeOperands (OpReg (getFPR op1), OpReg (getFPR op2),
        OpReg (getFPR op3)))
    | 0xB390us ->
      struct (Op.CELFBR, FourOperands (OpReg (getFPR op1), OpReg (getR op2),
        OpMask op3, OpMask op4))
    | 0xB391us ->
      struct (Op.CDLFBR, FourOperands (OpReg (getFPR op1), OpReg (getR op2),
        OpMask op3, OpMask op4))
    | 0xB392us ->
      struct (Op.CXLFBR, FourOperands (OpReg (getFPR op1), OpReg (getR op2),
        OpMask op3, OpMask op4))
    | 0xB394us when not isRRE ->
      struct (Op.CEFBRA, FourOperands (OpReg (getFPR op1), OpReg (getR op2),
        OpMask op3, OpMask op4)) // RRE done
    | 0xB395us when not isRRE ->
      struct (Op.CDFBRA, FourOperands (OpReg (getFPR op1), OpReg (getR op2),
        OpMask op3, OpMask op4)) // RRE done
    | 0xB396us when not isRRE ->
      struct (Op.CXFBRA, FourOperands (OpReg (getFPR op1), OpReg (getR op2),
        OpMask op3, OpMask op4)) // RRE done
    | 0xB398us when not isRRE ->
      struct (Op.CFEBR,
        ThreeOperands (OpReg (getR op1), OpReg (getFPR op2), OpMask op3))
    | 0xB398us ->
      struct (Op.CFEBRA, FourOperands (OpReg (getR op1), OpReg (getFPR op2),
        OpMask op3, OpMask op4))
    | 0xB399us when not isRRE ->
      struct (Op.CFDBR,
        ThreeOperands (OpReg (getR op1), OpReg (getFPR op2), OpMask op3))
    | 0xB399us ->
      struct (Op.CFDBRA, FourOperands (OpReg (getR op1), OpReg (getFPR op2),
        OpMask op3, OpMask op4))
    | 0xB39Aus when not isRRE ->
      struct (Op.CFXBR,
        ThreeOperands (OpReg (getR op1), OpReg (getFPR op2), OpMask op3))
    | 0xB39Aus ->
      struct (Op.CFXBRA, FourOperands (OpReg (getR op1), OpReg (getFPR op2),
        OpMask op3, OpMask op4))
    | 0xB39Cus ->
      struct (Op.CLFEBR, FourOperands (OpReg (getR op1), OpReg (getFPR op2),
        OpMask op3, OpMask op4))
    | 0xB39Dus ->
      struct (Op.CLFDBR, FourOperands (OpReg (getR op1), OpReg (getFPR op2),
        OpMask op3, OpMask op4))
    | 0xB39Eus ->
      struct (Op.CLFXBR, FourOperands (OpReg (getR op1), OpReg (getFPR op2),
        OpMask op3, OpMask op4))
    | 0xB3A0us ->
      struct (Op.CELGBR, FourOperands (OpReg (getFPR op1), OpReg (getR op2),
        OpMask op3, OpMask op4))
    | 0xB3A1us ->
      struct (Op.CDLGBR, FourOperands (OpReg (getFPR op1), OpReg (getR op2),
        OpMask op3, OpMask op4))
    | 0xB3A2us ->
      struct (Op.CXLGBR, FourOperands (OpReg (getFPR op1), OpReg (getR op2),
        OpMask op3, OpMask op4))
    | 0xB3A4us when not isRRE ->
      struct (Op.CEGBRA, FourOperands (OpReg (getFPR op1), OpReg (getR op2),
        OpMask op3, OpMask op4)) // RRE done
    | 0xB3A5us when not isRRE ->
      struct (Op.CDGBRA, FourOperands (OpReg (getFPR op1), OpReg (getR op2),
        OpMask op3, OpMask op4)) // RRE done
    | 0xB3A6us when not isRRE ->
      struct (Op.CXGBRA, FourOperands (OpReg (getFPR op1), OpReg (getR op2),
        OpMask op3, OpMask op4)) // RRE done
    | 0xB3A8us when not isRRE ->
      struct (Op.CGEBR,
        ThreeOperands (OpReg (getR op1), OpReg (getFPR op2), OpMask op3))
    | 0xB3A8us ->
      struct (Op.CGEBRA, FourOperands (OpReg (getR op1), OpReg (getFPR op2),
        OpMask op3, OpMask op4))
    | 0xB3A9us when not isRRE ->
      struct (Op.CGDBR,
        ThreeOperands (OpReg (getR op1), OpReg (getFPR op2), OpMask op3))
    | 0xB3A9us ->
      struct (Op.CGDBRA, FourOperands (OpReg (getR op1), OpReg (getFPR op2),
        OpMask op3, OpMask op4))
    | 0xB3AAus when not isRRE ->
      struct (Op.CGXBR,
        ThreeOperands (OpReg (getR op1), OpReg (getFPR op2), OpMask op3))
    | 0xB3AAus ->
      struct (Op.CGXBRA, FourOperands (OpReg (getR op1), OpReg (getFPR op2),
        OpMask op3, OpMask op4))
    | 0xB3ACus ->
      struct (Op.CLGEBR, FourOperands (OpReg (getR op1), OpReg (getFPR op2),
        OpMask op3, OpMask op4))
    | 0xB3ADus ->
      struct (Op.CLGDBR, FourOperands (OpReg (getR op1), OpReg (getFPR op2),
        OpMask op3, OpMask op4))
    | 0xB3AEus ->
      struct (Op.CLGXBR, FourOperands (OpReg (getR op1), OpReg (getFPR op2),
        OpMask op3, OpMask op4))
    | 0xB3B8us ->
      struct (Op.CFER,
        ThreeOperands (OpReg (getR op1), OpReg (getFPR op2), OpMask op3))
    | 0xB3B9us ->
      struct (Op.CFDR,
        ThreeOperands (OpReg (getR op1), OpReg (getFPR op2), OpMask op3))
    | 0xB3BAus ->
      struct (Op.CFXR,
        ThreeOperands (OpReg (getR op1), OpReg (getFPR op2), OpMask op3))
    | 0xB3C8us ->
      struct (Op.CGER,
        ThreeOperands (OpReg (getR op1), OpReg (getFPR op2), OpMask op3))
    | 0xB3C9us ->
      struct (Op.CGDR,
        ThreeOperands (OpReg (getR op1), OpReg (getFPR op2), OpMask op3))
    | 0xB3CAus ->
      struct (Op.CGXR,
        ThreeOperands (OpReg (getR op1), OpReg (getFPR op2), OpMask op3))
    | 0xB3D0us when not isRRE ->
      struct (Op.MDTR, ThreeOperands (OpReg (getFPR op1), OpReg (getFPR op2),
        OpReg (getFPR op3)))
    | 0xB3D0us ->
      struct (Op.MDTRA, FourOperands (OpReg (getFPR op1), OpReg (getFPR op2),
        OpReg (getFPR op3), OpMask op4))
    | 0xB3D1us when not isRRE ->
      struct (Op.DDTR, ThreeOperands (OpReg (getFPR op1), OpReg (getFPR op2),
        OpReg (getFPR op3)))
    | 0xB3D1us ->
      struct (Op.DDTRA, FourOperands (OpReg (getFPR op1), OpReg (getFPR op2),
        OpReg (getFPR op3), OpMask op4))
    | 0xB3D2us when not isRRE ->
      struct (Op.ADTR, ThreeOperands (OpReg (getFPR op1), OpReg (getFPR op2),
        OpReg (getFPR op3)))
    | 0xB3D2us ->
      struct (Op.ADTRA, FourOperands (OpReg (getFPR op1), OpReg (getFPR op2),
        OpReg (getFPR op3), OpMask op4))
    | 0xB3D3us when not isRRE ->
      struct (Op.SDTR, ThreeOperands (OpReg (getFPR op1), OpReg (getFPR op2),
        OpReg (getFPR op3)))
    | 0xB3D3us ->
      struct (Op.SDTRA, FourOperands (OpReg (getFPR op1), OpReg (getFPR op2),
        OpReg (getFPR op3), OpMask op4))
    | 0xB3D4us ->
      struct (Op.LDETR,
        ThreeOperands (OpReg (getFPR op1), OpReg (getFPR op2), OpMask op4))
    | 0xB3D5us ->
      struct (Op.LEDTR, FourOperands (OpReg (getFPR op1), OpReg (getFPR op2),
        OpMask op3, OpMask op4))
    | 0xB3D7us ->
      struct (Op.FIDTR, FourOperands (OpReg (getFPR op1), OpReg (getFPR op2),
        OpMask op3, OpMask op4))
    | 0xB3D8us when not isRRE ->
      struct (Op.MXTR, ThreeOperands (OpReg (getFPR op1), OpReg (getFPR op2),
        OpReg (getFPR op3)))
    | 0xB3D8us ->
      struct (Op.MXTRA, FourOperands (OpReg (getFPR op1), OpReg (getFPR op2),
        OpReg (getFPR op3), OpMask op4))
    | 0xB3D9us when not isRRE ->
      struct (Op.DXTR, ThreeOperands (OpReg (getFPR op1), OpReg (getFPR op2),
        OpReg (getFPR op3)))
    | 0xB3D9us ->
      struct (Op.DXTRA, FourOperands (OpReg (getFPR op1), OpReg (getFPR op2),
        OpReg (getFPR op3), OpMask op4))
    | 0xB3DAus when not isRRE ->
      struct (Op.AXTR, ThreeOperands (OpReg (getFPR op1), OpReg (getFPR op2),
        OpReg (getFPR op3)))
    | 0xB3DAus ->
      struct (Op.AXTRA, FourOperands (OpReg (getFPR op1), OpReg (getFPR op2),
        OpReg (getFPR op3), OpMask op4))
    | 0xB3DBus when not isRRE ->
      struct (Op.SXTR, ThreeOperands (OpReg (getFPR op1), OpReg (getFPR op2),
        OpReg (getFPR op3)))
    | 0xB3DBus ->
      struct (Op.SXTRA, FourOperands (OpReg (getFPR op1), OpReg (getFPR op2),
        OpReg (getFPR op3), OpMask op4))
    | 0xB3DCus ->
      struct (Op.LXDTR,
        ThreeOperands (OpReg (getFPR op1), OpReg (getFPR op2), OpMask op4))
    | 0xB3DDus ->
      struct (Op.LDXTR, FourOperands (OpReg (getFPR op1), OpReg (getFPR op2),
        OpMask op3, OpMask op4))
    | 0xB3DFus ->
      struct (Op.FIXTR, FourOperands (OpReg (getFPR op1), OpReg (getFPR op2),
        OpMask op3, OpMask op4))
    | 0xB3E1us when not isRRE ->
      struct (Op.CGDTR,
        ThreeOperands (OpReg (getR op1), OpReg (getFPR op2), OpMask op3))
    | 0xB3E1us ->
      struct (Op.CGDTRA, FourOperands (OpReg (getR op1), OpReg (getFPR op2),
        OpMask op3, OpMask op4))
    | 0xB3E3us ->
      struct (Op.CSDTR,
        ThreeOperands (OpReg (getR op1), OpReg (getFPR op2), OpMask op4))
    | 0xB3E9us when not isRRE ->
      struct (Op.CGXTR,
        ThreeOperands (OpReg (getR op1), OpReg (getFPR op2), OpMask op3))
    | 0xB3E9us ->
      struct (Op.CGXTRA, FourOperands (OpReg (getR op1), OpReg (getFPR op2),
        OpMask op3, OpMask op4))
    | 0xB3EBus when not isRRE ->
      struct (Op.CSXTR,
        ThreeOperands (OpReg (getR op1), OpReg (getFPR op2), OpMask op4))
    | 0xB3F1us when not isRRE ->
      struct (Op.CDGTRA, FourOperands (OpReg (getFPR op1), OpReg (getR op2),
        OpMask op3, OpMask op4)) // RRE done
    | 0xB3F5us ->
      struct (Op.QADTR, FourOperands (OpReg (getFPR op1), OpReg (getFPR op2),
        OpReg (getFPR op3), OpMask op4))
    | 0xB3F6us ->
      struct (Op.IEDTR, ThreeOperands (OpReg (getFPR op1), OpReg (getR op2),
        OpReg (getFPR op3)))
    | 0xB3F7us ->
      struct (Op.RRDTR, FourOperands (OpReg (getFPR op1), OpReg (getR op2),
        OpReg (getFPR op3), OpMask op4))
    | 0xB3F9us when not isRRE ->
      struct (Op.CXGTRA, FourOperands (OpReg (getFPR op1), OpReg (getR op2),
        OpMask op3, OpMask op4)) // RRE done
    | 0xB3FDus ->
      struct (Op.QAXTR, FourOperands (OpReg (getFPR op1), OpReg (getFPR op2),
        OpReg (getFPR op3), OpMask op4))
    | 0xB3FEus ->
      struct (Op.IEXTR, ThreeOperands (OpReg (getFPR op1), OpReg (getR op2),
        OpReg (getFPR op3)))
    | 0xB3FFus ->
      struct (Op.RRXTR, FourOperands (OpReg (getFPR op1), OpReg (getR op2),
        OpReg (getFPR op3), OpMask op4))
    | 0xB929us ->
      struct (Op.KMA, ThreeOperands (OpReg r1op1, OpReg r2op2, OpReg r3op3))
    | 0xB92Dus ->
      struct (Op.KMCTR, ThreeOperands (OpReg (getR op1), OpReg (getR op2),
        OpReg (getR op3)))
    | 0xB939us ->
      struct (Op.DFLTCC, ThreeOperands (OpReg r1op1, OpReg r2op2, OpReg r3op3))
    | 0xB941us ->
      struct (Op.CFDTR, FourOperands (OpReg (getR op1), OpReg (getFPR op2),
        OpMask op3, OpMask op4))
    | 0xB942us ->
      struct (Op.CLGDTR, FourOperands (OpReg (getR op1), OpReg (getFPR op2),
        OpMask op3, OpMask op4))
    | 0xB943us ->
      struct (Op.CLFDTR, FourOperands (OpReg (getR op1), OpReg (getFPR op2),
        OpMask op3, OpMask op4))
    | 0xB949us ->
      struct (Op.CFXTR, FourOperands (OpReg (getR op1), OpReg (getFPR op2),
        OpMask op3, OpMask op4))
    | 0xB94Aus ->
      struct (Op.CLGXTR, FourOperands (OpReg (getR op1), OpReg (getFPR op2),
        OpMask op3, OpMask op4))
    | 0xB94Bus ->
      struct (Op.CLFXTR, FourOperands (OpReg (getR op1), OpReg (getFPR op2),
        OpMask op3, OpMask op4))
    | 0xB951us ->
      struct (Op.CDFTR, FourOperands (OpReg (getFPR op1), OpReg (getR op2),
        OpMask op3, OpMask op4))
    | 0xB952us ->
      struct (Op.CDLGTR, FourOperands (OpReg (getFPR op1), OpReg (getR op2),
        OpMask op3, OpMask op3))
    | 0xB953us ->
      struct (Op.CDLFTR, FourOperands (OpReg (getFPR op1), OpReg (getR op2),
        OpMask op3, OpMask op3))
    | 0xB959us ->
      struct (Op.CXFTR, FourOperands (OpReg (getFPR op1), OpReg (getR op2),
        OpMask op3, OpMask op4))
    | 0xB95Aus ->
      struct (Op.CXLGTR, FourOperands (OpReg (getFPR op1), OpReg (getR op2),
        OpMask op3, OpMask op3))
    | 0xB95Bus ->
      struct (Op.CXLFTR, FourOperands (OpReg (getFPR op1), OpReg (getR op2),
        OpMask op3, OpMask op3))
    | 0xB960us ->
      struct (Op.CGRT,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpMask op3))
    | 0xB961us ->
      struct (Op.CLGRT,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpMask op3))
    | 0xB972us ->
      struct (Op.CRT,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpMask op3))
    | 0xB973us ->
      struct (Op.CLRT,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpMask op3))
    | 0xB98Eus ->
      struct (Op.IDTE, FourOperands (OpReg (getR op1), OpReg (getR op2),
        OpReg (getR op3), OpMask op4))
    | 0xB98Fus ->
      struct (Op.CRDTE, FourOperands (OpReg (getR op1), OpReg (getR op2),
        OpReg (getR op3), OpMask op4))
    | 0xB990us ->
      struct (Op.TRTT, ThreeOperands (OpReg r1op1, OpReg r2op2, OpMask op3))
    | 0xB991us ->
      struct (Op.TRTO, ThreeOperands (OpReg r1op1, OpReg r2op2, OpMask op3))
    | 0xB992us ->
      struct (Op.TROT, ThreeOperands (OpReg r1op1, OpReg r2op2, OpMask op3))
    | 0xB993us ->
      struct (Op.TROO, ThreeOperands (OpReg r1op1, OpReg r2op2, OpMask op3))
    | 0xB9AAus ->
      struct (Op.LPTEA, FourOperands (OpReg (getR op1), OpReg r2op2,
        OpReg (getR op3), OpMask op4))
    | 0xB9B0us ->
      struct (Op.CU14, ThreeOperands (OpReg r1op1, OpReg r2op2, OpMask op3))
    | 0xB9B1us ->
      struct (Op.CU24, ThreeOperands (OpReg r1op1, OpReg r2op2, OpMask op3))
    | 0xB9BDus ->
      struct (Op.TRTRE,
        ThreeOperands (OpReg r1op1, OpReg (getR op2), OpMask op3))
    | 0xB9BFus ->
      struct (Op.TRTE,
        ThreeOperands (OpReg r1op1, OpReg (getR op2), OpMask op3))
    | 0xB9C8us ->
      struct (Op.AHHHR,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpReg (getR op3)))
    | 0xB9C9us ->
      struct (Op.SHHHR,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpReg (getR op3)))
    | 0xB9CAus ->
      struct (Op.ALHHHR,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpReg (getR op3)))
    | 0xB9CBus ->
      struct (Op.SLHHHR,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpReg (getR op3)))
    | 0xB9D8us ->
      struct (Op.AHHLR,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpReg (getR op3)))
    | 0xB9D9us ->
      struct (Op.SHHLR,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpReg (getR op3)))
    | 0xB9DAus ->
      struct (Op.ALHHLR,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpReg (getR op3)))
    | 0xB9DBus ->
      struct (Op.SLHHLR,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpReg (getR op3)))
    | 0xB9E0us ->
      struct (Op.LOCFHR,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpMask op3))
    | 0xB9E2us ->
      struct (Op.LOCGR,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpMask op3))
    | 0xB9E4us ->
      struct (Op.NGRK,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpReg (getR op3)))
    | 0xB9E6us ->
      struct (Op.OGRK,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpReg (getR op3)))
    | 0xB9E7us ->
      struct (Op.XGRK,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpReg (getR op3)))
    | 0xB9E8us ->
      struct (Op.AGRK,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpReg (getR op3)))
    | 0xB9E9us ->
      struct (Op.SGRK,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpReg (getR op3)))
    | 0xB9EAus ->
      struct (Op.ALGRK,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpReg (getR op3)))
    | 0xB9EBus ->
      struct (Op.SLGRK,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpReg (getR op3)))
    | 0xB9ECus ->
      struct (Op.MGRK,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpReg (getR op3)))
    | 0xB9EDus ->
      struct (Op.MSGRKC,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpReg (getR op3)))
    | 0xB9F2us ->
      struct (Op.LOCR,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpMask op3))
    | 0xB9F4us ->
      struct (Op.NRK,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpReg (getR op3)))
    | 0xB9F6us ->
      struct (Op.ORK,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpReg (getR op3)))
    | 0xB9F7us ->
      struct (Op.XRK,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpReg (getR op3)))
    | 0xB9F8us ->
      struct (Op.ARK,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpReg (getR op3)))
    | 0xB9F9us ->
      struct (Op.SRK,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpReg (getR op3)))
    | 0xB9FAus ->
      struct (Op.ALRK,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpReg (getR op3)))
    | 0xB9FBus ->
      struct (Op.SLRK,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpReg (getR op3)))
    | 0xB9FDus ->
      struct (Op.MSRKC,
        ThreeOperands (OpReg (getR op1), OpReg (getR op2), OpReg (getR op3)))
    | _ -> struct (Op.InvalOp, NoOperand)

  fillFmt op opr Fmt.RRF

let parseRSI (bin: uint32) (state: State) =
  let opcode = extract32 bin 0 7 |> uint16
  let op1 = extract32 bin 8 11 |> uint16
  let op2 = extract32 bin 16 31 |> int16 |> ImmS16
  let op3 = extract32 bin 12 15 |> uint16

  let struct (op, opr) =
    match opcode with
    | 0x84us ->
      struct (Op.BRXH,
        ThreeOperands (OpReg (getR op1), OpRImm op2, OpReg (getR op3)))
    | 0x85us ->
      struct (Op.BRXLE,
        ThreeOperands (OpReg (getR op1), OpRImm op2, OpReg (getR op3)))
    | _ -> struct (Op.InvalOp, NoOperand)

  fillFmt op opr Fmt.RSI

let parseMII (bin: uint64) (state: State) =
  let opcode = extract48 bin  0 7 |> uint16
  let op1 = extract48 bin 8 11 |> uint16
  let op2 = BitVector.OfInt32 (extract48 bin 12 23 |> int32) 12<rt> |> ImmS12
  let op3 = BitVector.OfInt32 (extract48 bin 24 47 |> int32) 24<rt> |> ImmS24

  match opcode with
  | 0xC5us ->
      struct (Op.BPRP,
        ThreeOperands (OpMask op1, OpImm op2, OpImm op3), Fmt.MII)
  | _ -> struct (Op.InvalOp, NoOperand, Fmt.Invalid)

let parseRIE (bin: uint64) (state: State) =
  let opcode1 = extract48 bin 0 7 |> uint16
  let opcode2 = extract48 bin 40 47 |> uint16
  let opcode = opcode1 <<< 8 ||| opcode2
  let op1 = extract48 bin 8 11 |> uint16
  let op2a = extract48 bin 16 31 |> int8
  let op3a = extract48 bin 32 35 |> uint16
  let op2b = extract48 bin 12 15 |> uint16
  let op3b = extract48 bin 32 35 |> uint16
  let op4b = extract48 bin 16 31 |> int16
  let op2c = extract48 bin 32 39 |> int8
  let op3c = extract48 bin 12 15 |> uint16
  let op4c = extract48 bin 16 31 |> int16
  let op2d = extract48 bin 16 31 |> int16
  let op3d = extract48 bin 12 15 |> uint16
  let op2e = extract48 bin 16 31 |> int16
  let op3e = extract48 bin 12 15 |> uint16
  let op2f = extract48 bin 12 15 |> uint16
  let op3f = extract48 bin 16 23 |> uint8
  let op4f = extract48 bin 24 31 |> uint8
  let op5f = extract48 bin 32 39 |> uint8
  let op2g = extract48 bin 16 31 |> int16
  let op3g = extract48 bin 12 15 |> uint16

  let struct (op, opr) =
    match opcode with
    | 0xEC42us ->
      struct (Op.LOCHI,
        ThreeOperands (OpReg (getR op1), OpImm (ImmS16 op2g), OpMask op3g))
    | 0xEC44us ->
      struct (Op.BRXHG, ThreeOperands (OpReg (getR op1), OpRImm (ImmS16 op2e),
        OpReg (getR op3e)))
    | 0xEC45us ->
      struct (Op.BRXLG, ThreeOperands (OpReg (getR op1), OpRImm (ImmS16 op2e),
        OpReg (getR op3e)))
    | 0xEC46us ->
      struct (Op.LOCGHI,
        ThreeOperands (OpReg (getR op1), OpImm (ImmS16 op2g), OpMask op3g))
    | 0xEC4Eus ->
      struct (Op.LOCHHI,
        ThreeOperands (OpReg (getR op1), OpImm (ImmS16 op2g), OpMask op3g))
    | 0xEC51us ->
      struct (Op.RISBLG, FiveOperands (OpReg (getR op1), OpReg (getR op2f),
        OpImm (ImmU8 op3f), OpImm (ImmU8 op4f), OpImm (ImmU8 op5f)))
    | 0xEC54us ->
      struct (Op.RNSBG, FiveOperands (OpReg (getR op1), OpReg (getR op2f),
        OpImm (ImmU8 op3f), OpImm (ImmU8 op4f), OpImm (ImmU8 op5f)))
    | 0xEC55us ->
      struct (Op.RISBG, FiveOperands (OpReg (getR op1), OpReg (getR op2f),
        OpImm (ImmU8 op3f), OpImm (ImmU8 op4f), OpImm (ImmU8 op5f)))
    | 0xEC56us ->
      struct (Op.ROSBG, FiveOperands (OpReg (getR op1), OpReg (getR op2f),
        OpImm (ImmU8 op3f), OpImm (ImmU8 op4f), OpImm (ImmU8 op5f)))
    | 0xEC57us ->
      struct (Op.RXSBG, FiveOperands (OpReg (getR op1), OpReg (getR op2f),
        OpImm (ImmU8 op3f), OpImm (ImmU8 op4f), OpImm (ImmU8 op5f)))
    | 0xEC59us ->
      struct (Op.RISBGN, FiveOperands (OpReg (getR op1), OpReg (getR op2f),
        OpImm (ImmU8 op3f), OpImm (ImmU8 op4f), OpImm (ImmU8 op5f)))
    | 0xEC5Dus ->
      struct (Op.RISBHG, FiveOperands (OpReg (getR op1), OpReg (getR op2f),
        OpImm (ImmU8 op3f), OpImm (ImmU8 op4f), OpImm (ImmU8 op5f)))
    | 0xEC64us ->
      struct (Op.CGRJ, FourOperands (OpReg (getR op1), OpReg (getR op2b),
        OpMask op3b, OpRImm (ImmS16 op4b)))
    | 0xEC65us ->
      struct (Op.CLGRJ, FourOperands (OpReg (getR op1), OpReg (getR op2b),
        OpMask op3b, OpRImm (ImmS16 op4b)))
    | 0xEC70us ->
      struct (Op.CGIT,
        ThreeOperands (OpReg (getR op1), OpImm (ImmS8 op2a), OpMask op3a))
    | 0xEC71us ->
      struct (Op.CLGIT, ThreeOperands (OpReg (getR op1),
        OpImm (ImmU8 (uint8 op2a)), OpMask op3a))
    | 0xEC72us ->
      struct (Op.CIT,
        ThreeOperands (OpReg (getR op1), OpImm (ImmS8 op2a), OpMask op3a))
    | 0xEC73us ->
      struct (Op.CLFIT, ThreeOperands (OpReg (getR op1),
        OpImm (ImmU8 (uint8 op2a)), OpMask op3a))
    | 0xEC76us ->
      struct (Op.CRJ, FourOperands (OpReg (getR op1), OpReg (getR op2b),
        OpMask op3b, OpRImm (ImmS16 op4b)))
    | 0xEC77us ->
      struct (Op.CLRJ, FourOperands (OpReg (getR op1), OpReg (getR op2b),
        OpMask op3b, OpRImm (ImmS16 op4b)))
    | 0xEC7Cus ->
      struct (Op.CGIJ, FourOperands (OpReg (getR op1), OpImm (ImmS8 op2c),
        OpMask op3c, OpRImm (ImmS16 op4c)))
    | 0xEC7Dus ->
      struct (Op.CLGIJ, FourOperands (OpReg (getR op1),
        OpImm (ImmU8 (uint8 op2c)), OpMask op3c, OpRImm (ImmS16 op4c)))
    | 0xEC7Eus ->
      struct (Op.CIJ, FourOperands (OpReg (getR op1), OpImm (ImmS8 op2c),
        OpMask op3c, OpRImm (ImmS16 op4c)))
    | 0xEC7Fus ->
      struct (Op.CLIJ, FourOperands (OpReg (getR op1),
        OpImm (ImmU8 (uint8 op2c)), OpMask op3c, OpRImm (ImmS16 op4c)))
    | 0xECD8us ->
      struct (Op.AHIK, ThreeOperands (OpReg (getR op1), OpImm (ImmS16 op2d),
        OpReg (getR op3d)))
    | 0xECD9us ->
      struct (Op.AGHIK, ThreeOperands (OpReg (getR op1), OpImm (ImmS16 op2d),
        OpReg (getR op3d)))
    | 0xECDAus ->
      struct (Op.ALHSIK, ThreeOperands (OpReg (getR op1),
        OpImm (ImmU8 (uint8 op2d)), OpReg (getR op3d)))
    | 0xECDBus ->
      struct (Op.ALGHSIK, ThreeOperands (OpReg (getR op1),
        OpImm (ImmU8 (uint8 op2d)), OpReg (getR op3d)))
    | _ -> struct (Op.InvalOp, NoOperand)

  fillFmt op opr Fmt.RIE

let parseRIL (bin: uint64) (state: State) =
  let opcode1 = extract48 bin 0 7 |> uint16
  let opcode2 = extract48 bin 12 15 |> uint16
  let opcode = opcode1 <<< 4 ||| opcode2

  let op1 = extract48 bin 8 11 |> uint16
  let op2 = extract48 bin 16 47 |> int32

  let struct (op, opr) =
    match opcode with
    | 0xC00us ->
      struct (Op.LARL, TwoOperands (OpReg (getR op1), OpRImm (ImmS32 op2)))
    | 0xC01us ->
      struct (Op.LGFI, TwoOperands (OpReg (getR op1), OpImm (ImmS32 op2)))
    | 0xC04us ->
      struct (Op.BRCL, TwoOperands (OpMask op1, OpRImm (ImmS32 op2)))
    | 0xC05us ->
      struct (Op.BRASL, TwoOperands (OpReg (getR op1), OpRImm (ImmS32 op2)))
    | 0xC06us ->
      struct (Op.XIHF,
        TwoOperands (OpReg (getR op1), OpImm (ImmU32 (uint32 op2))))
    | 0xC07us ->
      struct (Op.XILF,
        TwoOperands (OpReg (getR op1), OpImm (ImmU32 (uint32 op2))))
    | 0xC08us ->
      struct (Op.IIHF,
        TwoOperands (OpReg (getR op1), OpImm (ImmU32 (uint32 op2))))
    | 0xC09us ->
      struct (Op.IILF,
        TwoOperands (OpReg (getR op1), OpImm (ImmU32 (uint32 op2))))
    | 0xC0Aus ->
      struct (Op.NIHF,
        TwoOperands (OpReg (getR op1), OpImm (ImmU32 (uint32 op2))))
    | 0xC0Bus ->
      struct (Op.NILF,
        TwoOperands (OpReg (getR op1), OpImm (ImmU32 (uint32 op2))))
    | 0xC0Cus ->
      struct (Op.OIHF,
        TwoOperands (OpReg (getR op1), OpImm (ImmU32 (uint32 op2))))
    | 0xC0Dus ->
      struct (Op.OILF,
        TwoOperands (OpReg (getR op1), OpImm (ImmU32 (uint32 op2))))
    | 0xC0Eus ->
      struct (Op.LLIHF,
        TwoOperands (OpReg (getR op1), OpImm (ImmU32 (uint32 op2))))
    | 0xC0Fus ->
      struct (Op.LLILF,
        TwoOperands (OpReg (getR op1), OpImm (ImmU32 (uint32 op2))))
    | 0xC20us ->
      struct (Op.MSGFI, TwoOperands (OpReg (getR op1), OpImm (ImmS32 op2)))
    | 0xC21us ->
      struct (Op.MSFI, TwoOperands (OpReg (getR op1), OpImm (ImmS32 op2)))
    | 0xC24us ->
      struct (Op.SLGFI,
        TwoOperands (OpReg (getR op1), OpImm (ImmU32 (uint32 op2))))
    | 0xC25us ->
      struct (Op.SLFI,
        TwoOperands (OpReg (getR op1), OpImm (ImmU32 (uint32 op2))))
    | 0xC28us ->
      struct (Op.AGFI, TwoOperands (OpReg (getR op1), OpImm (ImmS32 op2)))
    | 0xC29us ->
      struct (Op.AFI, TwoOperands (OpReg (getR op1), OpImm (ImmS32 op2)))
    | 0xC2Aus ->
      struct (Op.ALGFI,
        TwoOperands (OpReg (getR op1), OpImm (ImmU32 (uint32 op2))))
    | 0xC2Bus ->
      struct (Op.ALFI,
        TwoOperands (OpReg (getR op1), OpImm (ImmU32 (uint32 op2))))
    | 0xC2Cus ->
      struct (Op.CGFI, TwoOperands (OpReg (getR op1), OpImm (ImmS32 op2)))
    | 0xC2Dus ->
      struct (Op.CFI, TwoOperands (OpReg (getR op1), OpImm (ImmS32 op2)))
    | 0xC2Eus ->
      struct (Op.CLGFI,
        TwoOperands (OpReg (getR op1), OpImm (ImmU32 (uint32 op2))))
    | 0xC2Fus ->
      struct (Op.CLFI,
        TwoOperands (OpReg (getR op1), OpImm (ImmU32 (uint32 op2))))
    | 0xC42us ->
      struct (Op.LLHRL, TwoOperands (OpReg (getR op1), OpRImm (ImmS32 op2)))
    | 0xC44us ->
      struct (Op.LGHRL, TwoOperands (OpReg (getR op1), OpRImm (ImmS32 op2)))
    | 0xC45us ->
      struct (Op.LHRL, TwoOperands (OpReg (getR op1), OpRImm (ImmS32 op2)))
    | 0xC46us ->
      struct (Op.LLGHRL, TwoOperands (OpReg (getR op1), OpRImm (ImmS32 op2)))
    | 0xC47us ->
      struct (Op.STHRL, TwoOperands (OpReg (getR op1), OpRImm (ImmS32 op2)))
    | 0xC48us ->
      struct (Op.LGRL, TwoOperands (OpReg (getR op1), OpRImm (ImmS32 op2)))
    | 0xC4Bus ->
      struct (Op.STGRL, TwoOperands (OpReg (getR op1), OpRImm (ImmS32 op2)))
    | 0xC4Cus ->
      struct (Op.LGFRL, TwoOperands (OpReg (getR op1), OpRImm (ImmS32 op2)))
    | 0xC4Dus ->
      struct (Op.LRL, TwoOperands (OpReg (getR op1), OpRImm (ImmS32 op2)))
    | 0xC4Eus ->
      struct (Op.LLGFRL, TwoOperands (OpReg (getR op1), OpRImm (ImmS32 op2)))
    | 0xC4Fus ->
      struct (Op.STRL, TwoOperands (OpReg (getR op1), OpRImm (ImmS32 op2)))
    | 0xC60us ->
      struct (Op.EXRL, TwoOperands (OpReg (getR op1), OpRImm (ImmS32 op2)))
    | 0xC62us ->
      struct (Op.PFDRL, TwoOperands (OpMask op1, OpRImm (ImmS32 op2)))
    | 0xC64us ->
      struct (Op.CGHRL, TwoOperands (OpReg (getR op1), OpRImm (ImmS32 op2)))
    | 0xC65us ->
      struct (Op.CHRL, TwoOperands (OpReg (getR op1), OpRImm (ImmS32 op2)))
    | 0xC66us ->
      struct (Op.CLGHRL, TwoOperands (OpReg (getR op1), OpRImm (ImmS32 op2)))
    | 0xC67us ->
      struct (Op.CLHRL, TwoOperands (OpReg (getR op1), OpRImm (ImmS32 op2)))
    | 0xC68us ->
      struct (Op.CGRL, TwoOperands (OpReg (getR op1), OpRImm (ImmS32 op2)))
    | 0xC6Aus ->
      struct (Op.CLGRL, TwoOperands (OpReg (getR op1), OpRImm (ImmS32 op2)))
    | 0xC6Cus ->
      struct (Op.CGFRL, TwoOperands (OpReg (getR op1), OpRImm (ImmS32 op2)))
    | 0xC6Dus ->
      struct (Op.CRL, TwoOperands (OpReg (getR op1), OpRImm (ImmS32 op2)))
    | 0xC6Eus ->
      struct (Op.CLGFRL, TwoOperands (OpReg (getR op1), OpRImm (ImmS32 op2)))
    | 0xC6Fus ->
      struct (Op.CLRL, TwoOperands (OpReg (getR op1), OpRImm (ImmS32 op2)))
    | 0xCC6us ->
      struct (Op.BRCTH, TwoOperands (OpReg (getR op1), OpRImm (ImmS32 op2)))
    | 0xCC8us ->
      struct (Op.AIH, TwoOperands (OpReg (getR op1), OpImm (ImmS32 op2)))
    | 0xCCAus ->
      struct (Op.ALSIH, TwoOperands (OpReg (getR op1), OpImm (ImmS32 op2)))
    | 0xCCBus ->
      struct (Op.ALSIHN, TwoOperands (OpReg (getR op1), OpImm (ImmS32 op2)))
    | 0xCCDus ->
      struct (Op.CIH, TwoOperands (OpReg (getR op1), OpImm (ImmS32 op2)))
    | 0xCCFus ->
      struct (Op.CLIH,
        TwoOperands (OpReg (getR op1), OpImm (ImmU32 (uint32 op2))))
    | _ -> struct (Op.InvalOp, NoOperand)
  fillFmt op opr Fmt.RIL

let parseRIS (bin: uint64) (state: State) =
  let opcode1 = extract48 bin 0 7 |> uint16
  let opcode2 = extract48 bin 40 47 |> uint16
  let opcode = opcode1 <<< 8 ||| opcode2
  let op1 = extract48 bin 8 11 |> uint16 |> getR |> OpReg
  let op2 = extract48 bin 32 39 |> int8
  let op3 = extract48 bin 12 15 |> uint16 |> OpMask
  let base4 = extract48 bin 16 19 |> uint16 |> getR
  let disp4 = extract48 bin 20 31 |> uint32 |> DispU
  let op4 = (None, base4, disp4) |> OpStore

  let struct (op, opr) =
    match opcode with
    | 0xECFCus ->
      struct (Op.CGIB, FourOperands (op1, OpImm (ImmS8  op2), op3, op4))
    | 0xECFDus ->
      struct (Op.CLGIB, FourOperands (op1, OpImm (ImmU8 (uint8 op2)), op3, op4))
    | 0xECFEus ->
      struct (Op.CIB, FourOperands (op1, OpImm (ImmS8 op2), op3, op4))
    | 0xECFFus ->
      struct (Op.CLIB, FourOperands (op1, OpImm (ImmU8 (uint8 op2)), op3, op4))
    | _ -> struct (Op.InvalOp, NoOperand)
  fillFmt op opr Fmt.RIS

let parseRRS (bin: uint64) (state: State) =
  let opcode1 = extract48 bin 0 7 |> uint16
  let opcode2 = extract48 bin 40 47 |> uint16
  let opcode = opcode1 <<< 8 ||| opcode2
  let op1 = extract48 bin 8 11 |> uint16 |> getR |> OpReg
  let op2 = extract48 bin 12 15 |> uint16 |> getR |> OpReg
  let op3 = extract48 bin 32 35 |> uint16 |> OpMask
  let base4 = extract48 bin 16 19 |> uint16 |> getR
  let disp4 = extract48 bin 20 31 |> uint32 |> DispU
  let op4 = (None, base4, disp4) |> OpStore

  let struct (op, opr) =
    match opcode with
    | 0xECE4us -> struct (Op.CGRB, FourOperands (op1, op2, op3, op4))
    | 0xECE5us -> struct (Op.CLGRB, FourOperands (op1, op2, op3, op4))
    | 0xECF6us -> struct (Op.CRB, FourOperands (op1, op2, op3, op4))
    | 0xECF7us -> struct (Op.CLRB, FourOperands (op1, op2, op3, op4))
    | _ -> struct (Op.InvalOp, NoOperand)
  fillFmt op opr Fmt.RRS

let parseRSL (bin: uint64) (state: State) =
  let opcode1 = extract48 bin 0 7 |> uint16
  let opcode2 = extract48 bin 40 47 |> uint16
  let opcode = opcode1 <<< 8 ||| opcode2
  let len1a = (extract48 bin 8 11 |> uint16) + 1us
  let base1a = extract48 bin 16 19 |> uint16
  let disp1a = extract48 bin 20 31 |> uint32 |> DispU
  let op1a = OpStoreLen (len1a + 1us, base1a |> getR, disp1a)
  let op1aa = OpStoreLen (len1a + 1us, base1a |> getAR, disp1a)
  let b1op1a = modeSelect state.Tm op1a op1aa
  let op1b = extract48 bin 32 35 |> uint16 |> getFPR |> OpReg
  let len2b = (extract48 bin 8 15 |> uint16) + 1us
  let base2b = extract48 bin 16 19 |> uint16
  let disp2b = extract48 bin 20 31 |> uint32 |> DispU
  let op2b = OpStoreLen (len2b + 1us, getR base2b, disp2b)
  let op2ba = OpStoreLen (len2b + 1us, getAR base2b, disp2b)
  let b2op2b = modeSelect state.Tm op2b op2ba
  let op3b = extract48 bin 36 39 |> uint16 |> OpMask

  let struct (op, opr) =
    match opcode with
    | 0xEBC0us -> struct (Op.TP, OneOperand b1op1a)
    | 0xEDA8us -> struct (Op.CZDT, ThreeOperands (op1b, b2op2b, op3b))
    | 0xEDA9us -> struct (Op.CZXT, ThreeOperands (op1b, b2op2b, op3b))
    | 0xEDAAus -> struct (Op.CDZT, ThreeOperands (op1b, b2op2b, op3b))
    | 0xEDABus -> struct (Op.CXZT, ThreeOperands (op1b, b2op2b, op3b))
    | 0xEDACus -> struct (Op.CPDT, ThreeOperands (op1b, b2op2b, op3b))
    | 0xEDADus -> struct (Op.CPXT, ThreeOperands (op1b, b2op2b, op3b))
    | 0xEDAEus -> struct (Op.CDPT, ThreeOperands (op1b, b2op2b, op3b))
    | 0xEDAFus -> struct (Op.CXPT, ThreeOperands (op1b, b2op2b, op3b))
    | _ -> struct (Op.InvalOp, NoOperand)
  fillFmt op opr Fmt.RSL

let parseRSY (bin: uint64) (state: State) =
  let opcode1 = extract48 bin 0 7 |> uint16
  let opcode2 = extract48 bin 40 47 |> uint16
  let opcode = opcode1 <<< 8 ||| opcode2
  let op1 = extract48 bin 8 11 |> uint16
  let base2 = extract48 bin 16 19 |> uint16
  let displ2 = extract48 bin 20 31 |> uint16
  let disph2 = extract48 bin 32 39 |> int8
  let disp2 = (getLongDisp disph2 displ2) |> DispS
  let op2 = OpStore (None, getR base2, disp2)
  let op2a = OpStore (None, getAR base2, disp2)
  let op3 = extract48 bin 12 15 |> uint16
  let inline pick gen acc= modeSelect state.Tm gen acc
  let r1op1 = pick (getR op1) (getAR op1)
  let b2op2: Operand = pick op2 op2a
  let r3op3 = pick (getR op3) (getAR op3)

  let struct (op, opr) =
    match opcode with
    | 0xEB04us ->
      struct (Op.LMG, ThreeOperands (OpReg (getR op1), b2op2, OpReg (getR op3)))
    | 0xEB0Aus ->
      struct (Op.SRAG, ThreeOperands (OpReg (getR op1), op2, OpReg (getR op3)))
    | 0xEB0Bus ->
      struct (Op.SLAG, ThreeOperands (OpReg (getR op1), op2, OpReg (getR op3)))
    | 0xEB0Cus ->
      struct (Op.SRLG, ThreeOperands (OpReg (getR op1), op2, OpReg (getR op3)))
    | 0xEB0Dus ->
      struct (Op.SLLG, ThreeOperands (OpReg (getR op1), op2, OpReg (getR op3)))
    | 0xEB0Fus ->
      struct (Op.TRACG,
        ThreeOperands (OpReg (getR op1), b2op2, OpReg (getR op3)))
    | 0xEB14us ->
      struct (Op.CSY, ThreeOperands (OpReg (getR op1), b2op2, OpReg (getR op3)))
    | 0xEB1Cus ->
      struct (Op.RLLG, ThreeOperands (OpReg (getR op1), op2, OpReg (getR op3)))
    | 0xEB1Dus ->
      struct (Op.RLL, ThreeOperands (OpReg (getR op1), op2, OpReg (getR op3)))
    | 0xEB20us ->
      struct (Op.CLMH, ThreeOperands (OpReg (getR op1), b2op2, OpMask op3))
    | 0xEB21us ->
      struct (Op.CLMY, ThreeOperands (OpReg (getR op1), b2op2, OpMask op3))
    | 0xEB23us ->
      struct (Op.CLT, ThreeOperands (OpReg (getR op1), b2op2, OpMask op3))
    | 0xEB24us ->
      struct (Op.STMG,
        ThreeOperands (OpReg (getR op1), b2op2, OpReg (getR op3)))
    | 0xEB25us ->
      struct (Op.STCTG,
        ThreeOperands (OpReg (getCR op1), b2op2, OpReg (getCR op3)))
    | 0xEB26us ->
      struct (Op.STMH,
        ThreeOperands (OpReg (getR op1), b2op2, OpReg (getR op3)))
    | 0xEB2Bus ->
      struct (Op.CLGT, ThreeOperands (OpReg (getR op1), b2op2, OpMask op3))
    | 0xEB2Cus ->
      struct (Op.STCMH, ThreeOperands (OpReg (getR op1), b2op2, OpMask op3))
    | 0xEB2Dus ->
      struct (Op.STCMY, ThreeOperands (OpReg (getR op1), b2op2, OpMask op3))
    | 0xEB2Fus ->
      struct (Op.LCTLG,
        ThreeOperands (OpReg (getR op1), b2op2, OpReg (getR op3)))
    | 0xEB30us ->
      struct (Op.CSG, ThreeOperands (OpReg (getR op1), b2op2, OpReg (getR op3)))
    | 0xEB31us ->
      struct (Op.CDSY,
         ThreeOperands (OpReg (getR op1), b2op2, OpReg (getR op3)))
    | 0xEB3Eus ->
      struct (Op.CDSG,
        ThreeOperands (OpReg (getR op1), b2op2, OpReg (getR op3)))
    | 0xEB44us ->
      struct (Op.BXHG, ThreeOperands (OpReg (getR op1), op2, OpReg (getR op3)))
    | 0xEB45us ->
      struct (Op.BXLEG, ThreeOperands (OpReg (getR op1), op2, OpReg (getR op3)))
    | 0xEB4Cus ->
      struct (Op.ECAG, ThreeOperands (OpReg (getR op1), op2, OpReg (getR op3)))
    | 0xEB80us ->
      struct (Op.ICMH, ThreeOperands (OpReg (getR op1), b2op2, OpMask op3))
    | 0xEB81us ->
      struct (Op.ICMY, ThreeOperands (OpReg (getR op1), b2op2, OpMask op3))
    | 0xEB8Eus ->
      struct (Op.MVCLU, ThreeOperands (OpReg r1op1, op2, OpReg r3op3))
    | 0xEB8Fus ->
      struct (Op.CLCLU, ThreeOperands (OpReg r1op1, op2, OpReg (getR op3)))
    | 0xEB90us ->
      struct (Op.STMY,
        ThreeOperands (OpReg (getR op1), b2op2, OpReg (getR op3)))
    | 0xEB96us ->
      struct (Op.LMH, ThreeOperands (OpReg (getR op1), b2op2, OpReg (getR op3)))
    | 0xEB98us ->
      struct (Op.LMY, ThreeOperands (OpReg (getR op1), b2op2, OpReg (getR op3)))
    | 0xEB9Aus ->
      struct (Op.LAMY,
        ThreeOperands (OpReg (getAR op1), op2, OpReg (getAR op3)))
    | 0xEB9Bus ->
      struct (Op.STAMY,
        ThreeOperands (OpReg (getAR op1), b2op2, OpReg (getAR op3)))
    | 0xEBDCus ->
      struct (Op.SRAK, ThreeOperands (OpReg (getR op1), op2, OpReg (getR op3)))
    | 0xEBDDus ->
      struct (Op.SLAK, ThreeOperands (OpReg (getR op1), op2, OpReg (getR op3)))
    | 0xEBDEus ->
      struct (Op.SRLK, ThreeOperands (OpReg (getR op1), op2, OpReg (getR op3)))
    | 0xEBDFus ->
      struct (Op.SLLK, ThreeOperands (OpReg (getR op1), op2, OpReg (getR op3)))
    | 0xEBE0us ->
      struct (Op.LOCFH, ThreeOperands (OpReg (getR op1), b2op2, OpMask op3))
    | 0xEBE1us ->
      struct (Op.STOCFH, ThreeOperands (OpReg (getR op1), b2op2, OpMask op3))
    | 0xEBE2us ->
      struct (Op.LOCG, ThreeOperands (OpReg (getR op1), b2op2, OpMask op3))
    | 0xEBE3us ->
      struct (Op.STOCG, ThreeOperands (OpReg (getR op1), b2op2, OpMask op3))
    | 0xEBE4us ->
      struct (Op.LANG,
        ThreeOperands (OpReg (getR op1), b2op2, OpReg (getR op3)))
    | 0xEBE6us ->
      struct (Op.LAOG,
        ThreeOperands (OpReg (getR op1), b2op2, OpReg (getR op3)))
    | 0xEBE7us ->
      struct (Op.LAXG,
        ThreeOperands (OpReg (getR op1), b2op2, OpReg (getR op3)))
    | 0xEBE8us ->
      struct (Op.LAAG,
        ThreeOperands (OpReg (getR op1), b2op2, OpReg (getR op3)))
    | 0xEBEAus ->
      struct (Op.LAALG,
        ThreeOperands (OpReg (getR op1), b2op2, OpReg (getR op3)))
    | 0xEBF2us ->
      struct (Op.LOC, ThreeOperands (OpReg (getR op1), b2op2, OpMask op3))
    | 0xEBF3us ->
      struct (Op.STOC, ThreeOperands (OpReg (getR op1), b2op2, OpMask op3))
    | 0xEBF4us ->
      struct (Op.LAN, ThreeOperands (OpReg (getR op1), b2op2, OpReg (getR op3)))
    | 0xEBF6us ->
      struct (Op.LAO, ThreeOperands (OpReg (getR op1), b2op2, OpReg (getR op3)))
    | 0xEBF7us ->
      struct (Op.LAX, ThreeOperands (OpReg (getR op1), b2op2, OpReg (getR op3)))
    | 0xEBF8us ->
      struct (Op.LAA, ThreeOperands (OpReg (getR op1), b2op2, OpReg (getR op3)))
    | 0xEBFAus ->
      struct (Op.LAAL,
        ThreeOperands (OpReg (getR op1), b2op2, OpReg (getR op3)))
    | _ -> struct (Op.InvalOp, NoOperand)
  fillFmt op opr Fmt.RSY

let parseRXE (bin: uint64) (state: State) =
  let opcode1 = extract48 bin 0 7 |> uint16
  let opcode2 = extract48 bin 40 47 |> uint16
  let opcode = opcode1 <<< 8 ||| opcode2
  let op1 = extract48 bin 8 11 |> uint16
  let idx2 = extract48 bin 12 15 |> uint16 |> getR |> Some
  let base2 = extract48 bin  16 19 |> uint16
  let disp2 = extract48 bin 20 31 |> uint32 |> DispU
  let op2 = OpStore (idx2, getR base2, disp2)
  let op2a = OpStore (idx2, getAR base2, disp2)
  let op3 = extract48 bin 32 35 |> uint16 |> OpMask
  let pick = modeSelect state.Tm
  let b2op2 = pick op2 op2a

  let struct (op, opr) =
    match opcode with
    | 0xE727us -> struct (Op.LCBB, ThreeOperands (OpReg (getR op1), op2, op3))
    | 0xED04us -> struct (Op.LDEB, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0xED05us -> struct (Op.LXDB, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0xED06us -> struct (Op.LXEB,TwoOperands (OpReg (getFPR op1), b2op2))
    | 0xED07us -> struct (Op.MXDB, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0xED08us -> struct (Op.KEB, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0xED09us -> struct (Op.CEB, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0xED0Aus -> struct (Op.AEB, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0xED0Bus -> struct (Op.SEB, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0xED0Cus -> struct (Op.MDEB, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0xED0Dus -> struct (Op.DEB, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0xED10us -> struct (Op.TCEB, TwoOperands (OpReg (getFPR op1), op2))
    | 0xED11us -> struct (Op.TCDB, TwoOperands (OpReg (getFPR op1), op2))
    | 0xED12us -> struct (Op.TCXB, TwoOperands (OpReg (getFPR op1), op2))
    | 0xED14us -> struct (Op.SQEB, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0xED15us -> struct (Op.SQDB, TwoOperands (OpReg (getFPR op1), op2))
    | 0xED17us -> struct (Op.MEEB, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0xED18us -> struct (Op.KDB, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0xED19us -> struct (Op.CDB, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0xED1Aus -> struct (Op.ADB, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0xED1Bus -> struct (Op.SDB, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0xED1Cus -> struct (Op.MDB, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0xED1Dus -> struct (Op.DDB, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0xED24us -> struct (Op.LDE, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0xED25us -> struct (Op.LXD, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0xED26us -> struct (Op.LXE, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0xED34us -> struct (Op.SQE, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0xED35us -> struct (Op.SQD, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0xED37us -> struct (Op.MEE, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0xED50us -> struct (Op.TDCET,TwoOperands (OpReg (getFPR op1), op2))
    | 0xED51us -> struct (Op.TDGET, TwoOperands (OpReg (getFPR op1), op2))
    | 0xED54us -> struct (Op.TDCDT, TwoOperands (OpReg (getFPR op1), op2))
    | 0xED55us -> struct (Op.TDGDT, TwoOperands (OpReg (getFPR op1), op2))
    | 0xED58us -> struct (Op.TDCXT, TwoOperands (OpReg (getFPR op1), op2))
    | 0xED59us -> struct (Op.TDGXT, TwoOperands (OpReg (getFPR op1), op2))
    | _ -> struct (Op.InvalOp, NoOperand)
  fillFmt op opr Fmt.RXE

let parseRXY (bin: uint64) (state: State) =
  let opcode1 = extract48 bin 0 7 |> uint16
  let opcode2 = extract48 bin 40 47 |> uint16
  let opcode = opcode1 <<< 8 ||| opcode2
  let op1 = extract48 bin  8 11 |> uint16
  let idx2 = extract48 bin 12 15 |> uint16 |> getR |> Some
  let base2 = extract48 bin 16 19 |> uint16
  let displ2 = extract48 bin 20 31 |> uint16
  let disph2 = extract48 bin 32 39 |> int8
  let disp2 = getLongDisp disph2 displ2 |> DispS
  let op2 = OpStore (idx2, getR base2, disp2)
  let op2a = OpStore (idx2, getAR base2, disp2)
  let b2op2 = modeSelect state.Tm op2 op2a
  let bpop2 = modeSelectBP state.Bp op2 op2a

  let struct (op, opr) =
    match opcode with
    | 0xE302us -> struct (Op.LTG, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE303us -> struct (Op.LRAG, TwoOperands (OpReg (getR op1), bpop2))
    | 0xE304us -> struct (Op.LG, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE306us -> struct (Op.CVBY, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE308us -> struct (Op.AG, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE309us -> struct (Op.SG, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE30Aus -> struct (Op.ALG, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE30Bus -> struct (Op.SLG, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE30Cus -> struct (Op.MSG, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE30Dus -> struct (Op.DSG, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE30Eus -> struct (Op.CVBG, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE30Fus -> struct (Op.LRVG, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE312us -> struct (Op.LT, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE313us -> struct (Op.LRAY, TwoOperands (OpReg (getR op1), bpop2))
    | 0xE314us -> struct (Op.LGF, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE315us -> struct (Op.LGH, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE316us -> struct (Op.LLGF, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE317us -> struct (Op.LLGT, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE318us -> struct (Op.AGF, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE319us -> struct (Op.SGF, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE31Aus -> struct (Op.ALGF, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE31Bus -> struct (Op.SLGF, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE31Cus -> struct (Op.MSGF, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE31Dus -> struct (Op.DSGF, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE31Eus -> struct (Op.LRV, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE31Fus -> struct (Op.LRVH, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE320us -> struct (Op.CG, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE321us -> struct (Op.CLG, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE324us -> struct (Op.STG, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE325us -> struct (Op.NTSTG, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE326us -> struct (Op.CVDY, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE32Aus -> struct (Op.LZRG, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE32Eus -> struct (Op.CVDG, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE32Fus -> struct (Op.STRVG, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE330us -> struct (Op.CGF, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE331us -> struct (Op.CLGF, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE332us -> struct (Op.LTGF, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE334us -> struct (Op.CGH, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE336us -> struct (Op.PFD, TwoOperands (OpMask op1, b2op2))
    | 0xE338us -> struct (Op.AGH, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE339us -> struct (Op.SGH, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE33Aus -> struct (Op.LLZRGF, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE33Bus -> struct (Op.LZRF, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE33Cus -> struct (Op.MGH, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE33Eus -> struct (Op.STRV, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE33Fus -> struct (Op.STRVH, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE346us -> struct (Op.BCTG, TwoOperands (OpReg (getR op1), op2))
    | 0xE347us -> struct (Op.BIC, TwoOperands (OpMask op1, b2op2))
    | 0xE348us -> struct (Op.LLGFSG, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE349us -> struct (Op.STGSC, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE34Cus -> struct (Op.LGG, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE34Dus -> struct (Op.LGSC, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE350us -> struct (Op.STY, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE351us -> struct (Op.MSY, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE353us -> struct (Op.MSC, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE354us -> struct (Op.NY, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE355us -> struct (Op.CLY, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE356us -> struct (Op.OY, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE357us -> struct (Op.XY, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE358us -> struct (Op.LY, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE359us -> struct (Op.CY, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE35Aus -> struct (Op.AY, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE35Bus -> struct (Op.SY, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE35Cus -> struct (Op.MFY, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE35Eus -> struct (Op.ALY, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE35Fus -> struct (Op.SLY, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE370us -> struct (Op.STHY, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE371us -> struct (Op.LAY, TwoOperands (OpReg (getR op1), op2))
    | 0xE372us -> struct (Op.STCY, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE373us -> struct (Op.ICY, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE375us -> struct (Op.LAEY, TwoOperands (OpReg (getAR op1), bpop2))
    | 0xE376us -> struct (Op.LB, TwoOperands (OpReg (getR op1), op2))
    | 0xE377us -> struct (Op.LGB, TwoOperands (OpReg (getR op1), op2))
    | 0xE378us -> struct (Op.LHY, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE379us -> struct (Op.CHY, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE37Aus -> struct (Op.AHY, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE37Bus -> struct (Op.SHY, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE37Cus -> struct (Op.MHY, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE380us -> struct (Op.NG, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE381us -> struct (Op.OG, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE382us -> struct (Op.XG, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE383us -> struct (Op.MSGC, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE384us -> struct (Op.MG, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE385us -> struct (Op.LGAT, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE386us -> struct (Op.MLG, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE387us -> struct (Op.DLG, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE388us -> struct (Op.ALCG, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE389us -> struct (Op.SLBG, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE38Eus -> struct (Op.STPQ, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE38Fus -> struct (Op.LPQ, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE390us -> struct (Op.LLGC, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE391us -> struct (Op.LLGH, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE394us -> struct (Op.LLC, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE395us -> struct (Op.LLH, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE396us -> struct (Op.ML, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE397us -> struct (Op.DL, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE398us -> struct (Op.ALC, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE399us -> struct (Op.SLB, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE39Cus -> struct (Op.LLGTAT, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE39Dus -> struct (Op.LLGFAT, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE39Fus -> struct (Op.LAT, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE3C0us -> struct (Op.LBH, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE3C2us -> struct (Op.LLCH, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE3C3us -> struct (Op.STCH, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE3C4us -> struct (Op.LHH, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE3C6us -> struct (Op.LLHH, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE3C7us -> struct (Op.STHH, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE3C8us -> struct (Op.LFHAT, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE3CAus -> struct (Op.LFH, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE3CBus -> struct (Op.STFH, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE3CDus -> struct (Op.CHF, TwoOperands (OpReg (getR op1), b2op2))
    | 0xE3CFus -> struct (Op.CLHF, TwoOperands (OpReg (getR op1), b2op2))
    | 0xED64us -> struct (Op.LEY, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0xED65us -> struct (Op.LDY, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0xED66us -> struct (Op.STEY, TwoOperands (OpReg (getFPR op1), b2op2))
    | 0xED67us -> struct (Op.STDY, TwoOperands (OpReg (getFPR op1), b2op2))
    | _ -> struct (Op.InvalOp, NoOperand)
  fillFmt op opr Fmt.RXY

let parseRXF (bin: uint64) (state: State) =
  let opcode1 = extract48 bin 0 7 |> uint16
  let opcode2 = extract48 bin 40 47 |> uint16
  let opcode = opcode1 <<< 8 ||| opcode2
  let op1 = extract48 bin 32 35 |> uint16
  let idx2 = extract48 bin 12 15 |> uint16 |> getR |> Some
  let base2 = extract48 bin 16 19 |> uint16
  let disp2 = extract48 bin 20 31 |> uint32 |> DispU
  let op2 = OpStore (idx2, base2 |> getR, disp2)
  let op2a = OpStore (idx2, base2 |> getAR, disp2)
  let b2op2 = modeSelect state.Tm op2 op2a
  let op3 = extract48 bin 8 11 |> uint16

  let struct (op, opr) =
    match opcode with
    | 0xED0Eus ->
      struct (Op.MAEB,
        ThreeOperands (OpReg (getFPR op1), op2, OpReg (getFPR op3)))
    | 0xED0Fus ->
      struct (Op.MSEB,
        ThreeOperands (OpReg (getFPR op1), op2, OpReg (getFPR op3)))
    | 0xED1Eus ->
      struct (Op.MADB,
        ThreeOperands (OpReg (getFPR op1), b2op2, OpReg (getFPR op3)))
    | 0xED1Fus ->
      struct (Op.MSDB,
        ThreeOperands (OpReg (getFPR op1), b2op2, OpReg (getFPR op3)))
    | 0xED2Eus ->
      struct (Op.MAE,
        ThreeOperands (OpReg (getFPR op1), b2op2, OpReg (getFPR op3)))
    | 0xED2Fus ->
      struct (Op.MSE,
        ThreeOperands (OpReg (getFPR op1), b2op2, OpReg (getFPR op3)))
    | 0xED38us ->
      struct (Op.MAYL,
        ThreeOperands (OpReg (getFPR op1), b2op2, OpReg (getFPR op3)))
    | 0xED39us ->
      struct (Op.MYL,
        ThreeOperands (OpReg (getFPR op1), b2op2, OpReg (getFPR op3)))
    | 0xED3Aus ->
      struct (Op.MAY,
        ThreeOperands (OpReg (getFPR op1), b2op2, OpReg (getFPR op3)))
    | 0xED3Bus ->
      struct (Op.MY,
        ThreeOperands (OpReg (getFPR op1), b2op2, OpReg (getFPR op3)))
    | 0xED3Cus ->
      struct (Op.MAYH,
        ThreeOperands (OpReg (getFPR op1), b2op2, OpReg (getFPR op3)))
    | 0xED3Dus ->
      struct (Op.MYH,
        ThreeOperands (OpReg (getFPR op1), b2op2, OpReg (getFPR op3)))
    | 0xED3Eus ->
      struct (Op.MAD,
        ThreeOperands (OpReg (getFPR op1), b2op2, OpReg (getFPR op3)))
    | 0xED3Fus ->
      struct (Op.MSD,
        ThreeOperands (OpReg (getFPR op1), b2op2, OpReg (getFPR op3)))
    | 0xED40us ->
      struct (Op.SLDT,
        ThreeOperands (OpReg (getFPR op1), op2, OpReg (getFPR op3)))
    | 0xED41us ->
      struct (Op.SRDT,
        ThreeOperands (OpReg (getFPR op1), op2, OpReg (getFPR op3)))
    | 0xED48us ->
      struct (Op.SLXT,
        ThreeOperands (OpReg (getFPR op1), op2, OpReg (getFPR op3)))
    | 0xED49us ->
      struct (Op.SRXT,
        ThreeOperands (OpReg (getFPR op1), op2, OpReg (getFPR op3)))
    | _ -> struct (Op.InvalOp, NoOperand)
  fillFmt op opr Fmt.RXF

let parseSIL (bin: uint64) (state: State) =
  let opcode = extract48 bin 0 15 |> uint16
  let base1  = extract48 bin 16 19 |> uint16
  let disp1 = extract48 bin 20 31 |> uint32 |> DispU
  let op1 = OpStore (None, getR base1, disp1)
  let op1a = OpStore (None, getAR base1, disp1)
  let b1op1 = modeSelect state.Tm op1 op1a
  let op2 = extract48 bin 32 47 |> uint16

  let struct (op, opr) =
    match opcode with
    | 0xE544us ->
      struct (Op.MVHHI, TwoOperands (b1op1, OpImm (ImmS16 (int16 op2))))
    | 0xE548us ->
      struct (Op.MVGHI, TwoOperands (b1op1, OpImm (ImmS16 (int16 op2))))
    | 0xE54Cus ->
      struct (Op.MVHI, TwoOperands (b1op1, OpImm (ImmS16 (int16 op2))))
    | 0xE554us ->
      struct (Op.CHHSI, TwoOperands (b1op1, OpImm (ImmS16 (int16 op2))))
    | 0xE555us -> struct (Op.CLHHSI, TwoOperands (b1op1, OpImm (ImmU16 op2)))
    | 0xE558us ->
      struct (Op.CGHSI, TwoOperands (b1op1, OpImm (ImmS16 (int16 op2))))
    | 0xE559us -> struct (Op.CLGHSI, TwoOperands (b1op1, OpImm (ImmU16 op2)))
    | 0xE55Cus ->
      struct (Op.CHSI, TwoOperands (b1op1, OpImm (ImmS16 (int16 op2))))
    | 0xE55Dus -> struct (Op.CLFHSI, TwoOperands (b1op1, OpImm (ImmU16 op2)))
    | 0xE560us -> struct (Op.TBEGIN, TwoOperands (op1, OpImm (ImmU16 op2)))
    | 0xE561us -> struct (Op.TBEGINC, TwoOperands (op1, OpImm (ImmU16 op2)))
    | _ -> struct (Op.InvalOp, NoOperand)
  fillFmt op opr Fmt.SIL

let parseSIY (bin: uint64) (state: State) =
  let opcode1 = extract48 bin 0 7 |> uint16
  let opcode2 = extract48 bin 40 47 |> uint16
  let opcode = opcode1  <<< 8 ||| opcode2
  let base1 = extract48 bin 16 19 |> uint16
  let displ1 = extract48 bin 20 31 |> uint16
  let disph1 = extract48 bin 32 39 |> int8
  let disp1 = getLongDisp disph1 displ1 |> DispS
  let op1 = OpStore (None, getR base1, disp1)
  let op1a = OpStore (None, getAR base1, disp1)
  let b1op1 = modeSelect state.Tm op1 op1a
  let op2 = extract48 bin 8 15 |> uint8

  let struct (op, opr) =
    match opcode with
    | 0xEB51us ->
      struct (Op.TMY, TwoOperands (b1op1, OpImm (ImmU8 op2)))
    | 0xEB52us ->
      struct (Op.MVIY, TwoOperands (b1op1, OpImm (ImmU8 op2)))
    | 0xEB54us ->
      struct (Op.NIY, TwoOperands (b1op1, OpImm (ImmU8 op2)))
    | 0xEB55us ->
      struct (Op.CLIY, TwoOperands (b1op1, OpImm (ImmU8 op2)))
    | 0xEB56us ->
      struct (Op.OIY, TwoOperands (b1op1, OpImm (ImmU8 op2)))
    | 0xEB57us ->
      struct (Op.XIY, TwoOperands (b1op1, OpImm (ImmU8 op2)))
    | 0xEB6Aus ->
      struct (Op.ASI, TwoOperands (b1op1, OpImm (ImmS8 (int8 op2))))
    | 0xEB6Eus ->
      struct (Op.ALSI, TwoOperands (b1op1, OpImm (ImmU8 op2)))
    | 0xEB71us ->
      struct (Op.LPSWEY, OneOperand b1op1)
    | 0xEB7Aus ->
      struct (Op.AGSI, TwoOperands (b1op1, OpImm (ImmS8 (int8 op2))))
    | 0xEB7Eus ->
      struct (Op.ALGSI, TwoOperands (b1op1, OpImm (ImmU8 op2)))
    | _ -> struct (Op.InvalOp, NoOperand)
  fillFmt op opr Fmt.SIY

let parseSMI (bin: uint64) (state: State) =
  let opcode = extract48 bin 0 7 |> uint16
  let op1 = extract48 bin 8 11 |> uint16 |> OpMask
  let op2 = extract48 bin 32 47 |> int8 |> ImmS8 |> OpRImm
  let base3 = extract48 bin 16 19 |> uint16
  let disp3 = extract48 bin 20 31 |> uint32 |> DispU
  let op3 = OpStore (None, getR base3, disp3)

  match opcode with
  | 0xC7us -> struct (Op.BPP, ThreeOperands (op1, op2, op3), Fmt.SMI)
  | _ -> struct (Op.InvalOp, NoOperand, Fmt.Invalid)

let parseSS (bin: uint64) (state: State) =
  let opcode = extract48 bin 0 7 |> uint16
  let pick = modeSelect state.Tm

  /// opr fragments
  let frag1 = extract48 bin 9 11 |> uint16
  let frag2 = extract48 bin 12 15 |> uint16
  let frag12 = extract48 bin 8 15 |> uint16
  let base1 = extract48 bin 16 19 |> uint16
  let disp1 = extract48 bin 20 31 |> uint32 |> DispU
  let base2 = extract48 bin 32 35 |> uint16
  let disp2 = extract48 bin 36 47 |> uint32 |> DispU

  // SS-a format
  let op1a = OpStoreLen (frag12 + 1us, getR base1, disp1)
  let op1aa = OpStoreLen (frag12 + 1us, getAR base1, disp1)
  let b1op1a = pick op1a op1aa
  let op2a = OpStore (None, getR base2, disp2)
  let op2aa = OpStore (None, getAR base2, disp2)
  let b2op2a = pick op2a op2aa

  // SS-b format
  let op1b = OpStoreLen (frag1 + 1us, getR base1, disp1)
  let op1ba = OpStoreLen (frag1 + 1us, getAR base1, disp1)
  let b1op1b = pick op1b op1ba
  let op2b = OpStoreLen (frag2 + 1us, getR base2, disp2)
  let op2ba = OpStoreLen (frag2 + 1us, getAR base2, disp2)
  let b2op2b = pick op2b op2ba

  // SS-c format
  let op1c = OpStoreLen (frag1 + 1us, getR base1, disp1)
  let op1ca = OpStoreLen (frag1 + 1us, getAR base1, disp1)
  let b1op1c = pick op1c op1ca
  let op2c = OpStore (None, getR base2, disp2)
  let op2ca = OpStore (None, getAR base2, disp2)
  let b2op2c = pick op2c op2ca
  let op3c = BitVector.OfUInt32 (uint32 frag2) 4<rt> |> ImmU4

  // SS-d format
  let op1d = OpStore (Some (getR frag1), getR base1, disp1)
  let op1da = OpStore (Some (getR frag1), getAR base1, disp1)
  let b1op1d = pick op1d op1da
  let op2d = OpStore (None, getR base2, disp2)
  let op2da = OpStore (None, getAR base2, disp2)
  let b2op2d = pick op2d op2da
  let op3d = frag2

  // SS-e format
  let op1e = frag1
  let op2e = OpStore (None, getR base1, disp1)
  let op2ea = OpStore (None, getAR base1, disp1)
  let b2op2e = pick op2e op2ea
  let op3e = frag2
  let op4e = OpStore (None, getR base2, disp2)
  let op4ea = OpStore (None, getAR base2, disp2)
  let b4op4e = pick op4e op4ea

  // SS-f format
  let op1f = OpStore (None, getR base1, disp1)
  let op1fa = OpStore (None, getAR base1, disp1)
  let b1op1f = pick op1f op1fa
  let op2f = OpStoreLen (frag12 + 1us, getR base2, disp2)
  let op2fa = OpStoreLen (frag12 + 1us, getAR base2, disp2)
  let b2op2f = pick op2f op2fa

  let struct (op, opr) =
    match opcode with
    | 0xD0us -> struct (Op.TRTR, TwoOperands (b1op1a, b2op2a))
    | 0xD1us -> struct (Op.MVN, TwoOperands (b1op1a, b2op2a))
    | 0xD2us -> struct (Op.MVC, TwoOperands (b1op1a, b2op2a))
    | 0xD3us -> struct (Op.MVZ, TwoOperands (b1op1a, b2op2a))
    | 0xD4us -> struct (Op.NC, TwoOperands (b1op1a, b2op2a))
    | 0xD5us -> struct (Op.CLC, TwoOperands (b1op1a, b2op2a))
    | 0xD6us -> struct (Op.OC, TwoOperands (b1op1a, b2op2a))
    | 0xD7us -> struct (Op.XC, TwoOperands (b1op1a, b2op2a))
    | 0xD9us ->
      struct (Op.MVCK, ThreeOperands (b1op1d, b2op2d, OpReg (getR op3d)))
    | 0xDAus -> struct (Op.MVCP, ThreeOperands (op1d, op2d, OpReg (getR op3d)))
    | 0xDBus -> struct (Op.MVCS, ThreeOperands (op1d, op2d, OpReg (getR op3d)))
    | 0xDCus -> struct (Op.TR, TwoOperands (b1op1a, b2op2a))
    | 0xDDus -> struct (Op.TRT, TwoOperands (b1op1a, b2op2a))
    | 0xDEus -> struct (Op.ED, TwoOperands (b1op1a, b2op2a))
    | 0xDFus -> struct (Op.EDMK, TwoOperands (b1op1a, b2op2a))
    | 0xE1us -> struct (Op.PKU, TwoOperands (b1op1f, b2op2f))
    | 0xE2us -> struct (Op.UNPKU, TwoOperands (b1op1a, b2op2a))
    | 0xE8us -> struct (Op.MVCIN, TwoOperands (b1op1a, b2op2a))
    | 0xE9us -> struct (Op.PKA, TwoOperands (b1op1f, b2op2f))
    | 0xEAus -> struct (Op.UNPKA, TwoOperands (b1op1a, b2op2a))
    | 0xEEus ->
      struct (Op.PLO,
        FourOperands (OpReg (getR op1e), op2e, OpReg (getR op3e), op4e))
    | 0xEFus ->
      struct (Op.LMD,
        FourOperands (OpReg (getR op1e), b2op2e, OpReg (getR op3e), b4op4e))
    | 0xF0us -> struct (Op.SRP, ThreeOperands (b1op1c, b2op2c, OpImm op3c))
    | 0xF1us -> struct (Op.MVO, TwoOperands (b1op1b, b2op2b))
    | 0xF2us -> struct (Op.PACK, TwoOperands (b1op1b, b2op2b))
    | 0xF3us -> struct (Op.UNPK, TwoOperands (b1op1b, b2op2b))
    | 0xF8us -> struct (Op.ZAP, TwoOperands (b1op1b, b2op2b))
    | 0xF9us -> struct (Op.CP, TwoOperands (b1op1b, b2op2b))
    | 0xFAus -> struct (Op.AP, TwoOperands (b1op1b, b2op2b))
    | 0xFBus -> struct (Op.SP, TwoOperands (b1op1b, b2op2b))
    | 0xFCus -> struct (Op.MP, TwoOperands (b1op1b, b2op2b))
    | 0xFDus -> struct (Op.DP, TwoOperands (b1op1b, b2op2b))
    | _ -> struct (Op.InvalOp, NoOperand)
  fillFmt op opr Fmt.SS

let parseSSE (bin: uint64) (state: State) =
  let opcode = extract48 bin 0 16 |> uint16
  let pick = modeSelect state.Tm
  let base1 = extract48 bin 16 19 |> uint16
  let disp1 = extract48 bin 20 31 |> uint32 |> DispU
  let op1 = OpStore (None, getR base1, disp1)
  let op1a = OpStore (None, getAR base1, disp1)
  let b1op1 = pick op1 op1a
  let base2 = extract48 bin 32 35 |> uint16
  let disp2 = extract48 bin 36 47 |> uint32 |> DispU
  let op2 = OpStore (None, getR base2, disp2)
  let op2a = OpStore (None, getAR base2, disp2)
  let b2op2 = pick op2 op2a
  let bpop2 = modeSelectBP state.Bp op2 op2a

  let struct (op, opr) =
    match opcode with
    | 0xE500us -> struct (Op.LASP, TwoOperands (b1op1, op2))
    | 0xE501us -> struct (Op.TPROT, TwoOperands (b1op1, op2))
    | 0xE502us -> struct (Op.STRAG, TwoOperands (b1op1, bpop2))
    | 0xE50Aus -> struct (Op.MVCRL, TwoOperands (b1op1, b2op2))
    | 0xE50Eus -> struct (Op.MVCSK, TwoOperands (b1op1, b2op2))
    | 0xE50Fus -> struct (Op.MVCDK, TwoOperands (b1op1, b2op2))
    | _ -> struct (Op.InvalOp, NoOperand)
  fillFmt op opr Fmt.SSE

let parseSSF (bin: uint64) (state: State) =
  let opcode1 = extract48 bin 0 7 |> uint16
  let opcode2 = extract48 bin 12 15 |> uint16
  let opcode = opcode1 <<< 4 ||| opcode2
  let pick gen acc = modeSelect state.Tm gen acc
  let base1 = extract48 bin 16 19 |> uint16
  let disp1 = extract48 bin 20 31 |> uint32 |> DispU
  let op1 = OpStore (None, getR base1, disp1)
  let op1a = OpStore (None, getAR base1, disp1)
  let b1op1 = pick op1 op1a
  let base2 = extract48 bin 32 35 |> uint16
  let disp2 = extract48 bin 36 47 |> uint32 |> DispU
  let op2 = OpStore (None, getR base2, disp2)
  let op2a = OpStore (None, getAR base2, disp2)
  let b2op2 = pick op2 op2a
  let op3 = extract48 bin 8 11 |> uint16
  let r3op3 = pick (getR op3) (getAR op3)

  let struct (op, opr) =
    match opcode with
    | 0xC80us -> struct (Op.MVCOS, ThreeOperands (op1, op2, OpReg (getR op3)))
    | 0xC81us -> struct (Op.ECTG, ThreeOperands (b1op1, b2op2, OpReg r3op3))
    | 0xC82us ->
      struct (Op.CSST, ThreeOperands (b1op1, b2op2, OpReg (getR op3)))
    | 0xC84us ->
      struct (Op.LPD, ThreeOperands (b1op1, b2op2, OpReg (getR op3)))
    | 0xC85us ->
      struct (Op.LPDG, ThreeOperands (b1op1, b2op2, OpReg (getR op3)))
    | _ -> struct (Op.InvalOp, NoOperand)

  fillFmt op opr Fmt.SSF

let parseVRI (bin: uint64) (state: State) =
  let opcode1 = extract48 bin 0 7 |> uint16
  let opcode2 = extract48 bin 40 47 |> uint16
  let opcode = opcode1 <<< 8 ||| opcode2
  let rxb = extract48 bin 36 39 |> uint16
  let toVR = getVR rxb
  let op1 = OpReg (toVR (extract48 bin 8 11 |> uint16) 1us)

  // opr fragments
  let frag1 = extract48 bin 12 15 |> uint16
  let frag2 =  extract48 bin 16 19 |> uint16
  let frag23 = extract48 bin 16 23 |> uint8
  let frag24 = BitVector.OfUInt32 (extract48 bin 16 27 |> uint32) 12<rt>
  let frag25 = extract48 bin 16 31 |> uint16
  let frag4 = extract48 bin 24 27 |> uint16
  let frag45 = extract48 bin 24 31 |> uint8
  let frag5 = extract48 bin 28 31 |> uint16
  let frag56 = extract48 bin 28 35 |> uint8
  let frag6 = extract48 bin 32 35 |> uint16

  // VRI-a operands
  let op2a = OpImm (ImmU16 frag25)
  let op3a = OpMask frag6

  // VRI-b operands
  let op2b = OpImm (ImmU8 frag23)
  let op3b = OpImm (ImmU8 frag45)
  let op4b = OpMask frag6

  // VRI-c operands
  let op2c = OpImm (ImmU16 frag25)
  let op3c = OpReg (toVR frag1 2us)
  let op4c = OpMask frag6

  // VRI-d operands
  let op2d = OpReg (toVR frag1 2us)
  let op3d = OpReg (toVR frag2 3us)
  let op4d = OpImm (ImmU8 frag45)
  let op5d = OpMask frag6

  // VRI-e operands
  let op2e = OpReg (toVR frag1 2us)
  let op3e = OpImm (ImmU12 frag24)
  let op4e = OpMask frag6
  let op5e = OpMask frag5

  // VRI-f operands
  let op2f = OpReg (toVR frag1 2us)
  let op3f = OpReg (toVR frag2 3us)
  let op4f = OpImm (ImmU8 frag56)
  let op5f = OpMask frag4

  // VRI-g operands
  let op2g = OpReg (toVR frag1 2us)
  let op3g = OpImm (ImmU8 frag56)
  let op4g = OpImm (ImmU8 frag23)
  let op5g = OpMask frag4

  // VRI-h operands
  let op2h = OpImm (ImmU16 frag25)
  let op3h = OpImm (ImmU4 (BitVector.OfUInt32 (uint32 frag6) 4<rt>))

  // VRI-i operands
  let op2i = OpReg (getR frag1)
  let op3i = OpImm (ImmU8 frag56)
  let op4i = OpMask frag4

  let struct (op, opr) =
    match opcode with
    | 0xE649us -> struct (Op.VLIP, ThreeOperands (op1, op2h, op3h))
    | 0xE658us -> struct (Op.VCVD, FourOperands (op1, op2i, op3i, op4i))
    | 0xE659us -> struct (Op.VSRP, FiveOperands (op1, op2g, op3g, op4g, op5g))
    | 0xE65Aus -> struct (Op.VCVDG, FourOperands (op1, op2i, op3i, op4i))
    | 0xE65Bus -> struct (Op.VPSOP, FiveOperands (op1, op2g, op3g, op4g, op5g))
    | 0xE670us -> struct (Op.VPKZR, FiveOperands (op1, op2f, op3f, op4f, op5f))
    | 0xE671us -> struct (Op.VAP, FiveOperands (op1, op2f, op3f, op4f, op5f))
    | 0xE672us -> struct (Op.VSRPR, FiveOperands (op1, op2f, op3f, op4f, op5f))
    | 0xE673us -> struct (Op.VSP, FiveOperands (op1, op2f, op3f, op4f, op5f))
    | 0xE678us -> struct (Op.VMP, FiveOperands (op1, op2f, op3f, op4f, op5f))
    | 0xE679us -> struct (Op.VMSP, FiveOperands (op1, op2f, op3f, op4f, op5f))
    | 0xE67Aus -> struct (Op.VDP, FiveOperands (op1, op2f, op3f, op4f, op5f))
    | 0xE67Bus -> struct (Op.VRP, FiveOperands (op1, op2f, op3f, op4f, op5f))
    | 0xE67Eus -> struct (Op.VSDP, FiveOperands (op1, op2f, op3f, op4f, op5f))
    | 0xE740us -> struct (Op.VLEIB, ThreeOperands (op1, op2a, op3a))
    | 0xE741us -> struct (Op.VLEIH, ThreeOperands (op1, op2a, op3a))
    | 0xE742us -> struct (Op.VLEIG, ThreeOperands (op1, op2a, op3a))
    | 0xE743us -> struct (Op.VLEIF, ThreeOperands (op1, op2a, op3a))
    | 0xE744us -> struct (Op.VGBM, TwoOperands (op1, op2a))
    | 0xE745us -> struct (Op.VREPI, ThreeOperands (op1, op2a, op3a))
    | 0xE746us -> struct (Op.VGM, FourOperands (op1, op2b, op3b, op4b))
    | 0xE74Aus -> struct (Op.VFTCI, FiveOperands (op1, op2e, op3e, op4e, op5e))
    | 0xE74Dus -> struct (Op.VREP, FourOperands (op1, op2c, op3c, op4c))
    | 0xE772us -> struct (Op.VERIM, FiveOperands (op1, op2d, op3d, op4d, op5d))
    | 0xE777us -> struct (Op.VSLDB, FourOperands (op1, op2d, op3d, op4d))
    | 0xE786us -> struct (Op.VSLD, FourOperands (op1, op2d, op3d, op4d))
    | 0xE787us -> struct (Op.VSRD, FourOperands (op1, op2d, op3d, op4d))
    | _ -> struct (Op.InvalOp, NoOperand)

  fillFmt op opr Fmt.VRI

let parseVRR (bin: uint64) (state: State) =
  let opcode1 = extract48 bin 0 7 |> uint16
  let opcode2 = extract48 bin 40 47 |> uint16
  let opcode = opcode1 <<< 8 ||| opcode2
  let rxb = extract48 bin 36 39 |> uint16
  let toVR = getVR rxb
  let frag1 = extract48 bin 8 11 |> uint16
  let frag2 = extract48 bin 12 15 |> uint16
  let frag3 = extract48 bin 16 19 |> uint16
  let frag4 = extract48 bin 20 23 |> uint16
  let frag5 = extract48 bin 24 27 |> uint16
  let frag6 = extract48 bin 28 31 |> uint16
  let frag7 = extract48 bin 32 35 |> uint16
  let op1a = OpReg (toVR frag1 1us)
  let op2a = OpReg (toVR frag2 2us)
  let op3a = OpMask frag7
  let op4a = OpMask frag6
  let op5a = OpMask frag5
  let op1b = OpReg (toVR frag1 1us)
  let op2b = OpReg (toVR frag2 2us)
  let op3b = OpReg (toVR frag3 3us)
  let op4b = OpMask frag7
  let op5b = OpMask  frag5
  let op1c = OpReg (toVR frag1 1us)
  let op2c = OpReg (toVR frag2 2us)
  let op3c = OpReg (toVR frag3 3us)
  let op4c = OpMask frag7
  let op5c = OpMask frag6
  let op6c = OpMask frag5
  let op1d = OpReg (toVR frag1 1us)
  let op2d = OpReg (toVR frag2 2us)
  let op3d = OpReg (toVR frag3 3us)
  let op4d = OpReg (toVR frag7 4us)
  let op5d = OpMask frag4
  let op6d = OpMask frag5
  let op1e = OpReg (toVR frag1 1us)
  let op2e = OpReg (toVR frag2 2us)
  let op3e = OpReg (toVR frag3 3us)
  let op4e = OpReg (toVR frag7 4us)
  let op5e = OpMask frag6
  let op6e = OpMask frag4
  let op1f = OpReg (toVR frag1 1us)
  let op2f = OpReg (getR frag2)
  let op3f = OpReg (getR frag3)
  let op1g = OpReg (toVR frag2 2us)
  let op1h = OpReg (toVR frag2 2us)
  let op2h = OpReg (toVR frag3 3us)
  let op3h = OpMask frag5
  let op1i = OpReg (getR frag1)
  let op2i = OpReg (toVR frag2 2us)
  let op3i = OpMask frag5
  let op4i = OpMask frag6
  let op1j = OpReg (toVR frag1 1us)
  let op2j = OpReg (toVR frag2 2us)
  let op3j = OpReg (toVR frag3 3us)
  let op4j = OpMask frag5
  let op1k = OpReg (toVR frag1 1us)
  let op2k = OpReg (toVR frag2 2us)
  let op3k = OpMask frag5

  let struct (op, opr) =
    match opcode with
    | 0xE650us ->
      struct (Op.VCVB, FourOperands (op1i, op2i, op3i, op4i))
    | 0xE651us -> struct (Op.VCLZDP, ThreeOperands (op1k, op2k, op3k))
    | 0xE652us ->
      struct (Op.VCVBG,FourOperands (op1i, op2i, op3i, op4i))
    | 0xE654us -> struct (Op.VUPKZH, ThreeOperands (op1k, op2k, op3k))
    | 0xE655us -> struct (Op.VCNF, FourOperands (op1a, op2a, op3a, op4a))
    | 0xE656us -> struct (Op.VCLFNH, FourOperands (op1a, op2a, op3a, op4a))
    | 0xE65Cus -> struct (Op.VUPKZL,  ThreeOperands (op1k, op2k, op3k))
    | 0xE65Dus -> struct (Op.VCFN, FourOperands (op1a, op2a, op3a, op4a))
    | 0xE65Eus -> struct (Op.VCLFNL, FourOperands (op1a, op2a, op3a, op4a))
    | 0xE65Fus -> struct (Op.VTP, OneOperand op1g)
    | 0xE674us ->
      struct (Op.VSCHP, FiveOperands (op1b, op2b, op3b, op4b, op5b))
    | 0xE675us ->
      struct (Op.VCRNF, FiveOperands (op1c, op2c, op3c, op4c, op5c))
    | 0xE677us -> struct (Op.VCP, ThreeOperands (op1h, op2h, op3h))
    | 0xE67Cus -> struct (Op.VSCSHP, ThreeOperands (op1b, op2b, op3b))
    | 0xE67Dus -> struct (Op.VCSPH, FourOperands (op1j, op2j, op3j, op4j))
    | 0xE750us -> struct (Op.VPOPCT, ThreeOperands (op1a, op2a, op3a))
    | 0xE752us -> struct (Op.VCTZ, ThreeOperands (op1a, op2a, op3a))
    | 0xE753us -> struct (Op.VCLZ, ThreeOperands (op1a, op2a, op3a))
    | 0xE756us -> struct (Op.VLR, TwoOperands (op1a, op2a))
    | 0xE75Cus -> struct (Op.VISTR, FourOperands (op1a, op2a, op3a, op5a))
    | 0xE75Fus -> struct (Op.VSEG, ThreeOperands (op1a, op2a, op3a))
    | 0xE760us -> struct (Op.VMRL, FourOperands (op1c, op2c, op3c, op4c))
    | 0xE761us -> struct (Op.VMRH, FourOperands (op1c, op2c, op3c, op4c))
    | 0xE762us ->
      struct (Op.VLVGP, ThreeOperands (op1f, op2f, op3f))
    | 0xE764us -> struct (Op.VSUM, FourOperands (op1c, op2c, op3c, op4c))
    | 0xE765us -> struct (Op.VSUMG, FourOperands (op1c, op2c, op3c, op4c))
    | 0xE766us -> struct (Op.VCKSM, ThreeOperands (op1c, op2c, op3c))
    | 0xE767us -> struct (Op.VSUMQ, FourOperands (op1c, op2c, op3c, op4c))
    | 0xE768us -> struct (Op.VN, ThreeOperands (op1c, op2c, op3c))
    | 0xE769us -> struct (Op.VNC, ThreeOperands (op1c, op2c, op3c))
    | 0xE76Aus -> struct (Op.VO, ThreeOperands (op1c, op2c, op3c))
    | 0xE76Bus -> struct (Op.VNO, ThreeOperands (op1c, op2c, op3c))
    | 0xE76Cus -> struct (Op.VNX, ThreeOperands (op1c, op2c, op3c))
    | 0xE76Dus -> struct (Op.VX, ThreeOperands (op1c, op2c, op3c))
    | 0xE76Eus -> struct (Op.VNN, ThreeOperands (op1c, op2c, op3c))
    | 0xE76Fus -> struct (Op.VOC, ThreeOperands (op1c, op2c, op3c))
    | 0xE770us -> struct (Op.VESLV, FourOperands (op1c, op2c, op3c, op4c))
    | 0xE773us -> struct (Op.VERLLV, FourOperands (op1c, op2c, op3c, op4c))
    | 0xE774us -> struct (Op.VSL, ThreeOperands (op1c, op2c, op3c))
    | 0xE775us -> struct (Op.VSLB, ThreeOperands (op1c, op2c, op3c))
    | 0xE778us -> struct (Op.VESRLV, FourOperands (op1c, op2c, op3c, op4c))
    | 0xE77Aus -> struct (Op.VESRAV, FourOperands (op1c, op2c, op3c, op4c))
    | 0xE77Cus -> struct (Op.VSRL, ThreeOperands (op1c, op2c, op3c))
    | 0xE77Dus -> struct (Op.VSRLB, ThreeOperands (op1c, op2c, op3c))
    | 0xE77Eus -> struct (Op.VSRA, ThreeOperands (op1c, op2c, op3c))
    | 0xE77Fus -> struct (Op.VSRAB, ThreeOperands (op1c, op2c, op3c))
    | 0xE780us ->
      struct (Op.VFEE, FiveOperands (op1b, op2b, op3b, op4b, op5b))
    | 0xE781us ->
      struct (Op.VFENE, FiveOperands (op1b, op2b, op3b, op4b, op5b))
    | 0xE782us ->
      struct (Op.VFAE, FiveOperands (op1b, op2b, op3b, op4b, op5b))
    | 0xE784us -> struct (Op.VPDI, FourOperands (op1c, op2c, op3c, op4c))
    | 0xE785us -> struct (Op.VBPERM, ThreeOperands (op1c, op2c, op3c))
    | 0xE78Aus ->
      struct (Op.VSTRC, SixOperands (op1d, op2d, op3d, op4d, op5d, op6d))
    | 0xE78Bus ->
      struct (Op.VSTRS, SixOperands (op1d, op2d, op3d, op4d, op5d, op6d))
    | 0xE78Cus -> struct (Op.VPERM, FourOperands (op1e, op2e, op3e, op4e))
    | 0xE78Dus -> struct (Op.VSEL, FourOperands (op1e, op2e, op3e, op4e))
    | 0xE78Eus ->
      struct (Op.VFMS, SixOperands (op1e, op2e, op3e, op4e, op5e, op6e))
    | 0xE78Fus ->
      struct (Op.VFMA, SixOperands (op1e, op2e, op3e, op4e, op5e, op6e))
    | 0xE794us ->
      struct (Op.VPK, FourOperands (op1c, op2c, op3c, op4c))
    | 0xE795us ->
      struct (Op.VPKLS, FiveOperands (op1b, op2b, op3b, op4b, op5b))
    | 0xE797us ->
      struct (Op.VPKS, FiveOperands (op1b, op2b, op3b, op4b, op5b))
    | 0xE79Eus ->
      struct (Op.VFNMS, SixOperands (op1e, op2e, op3e, op4e, op5e, op6e))
    | 0xE79Fus ->
      struct (Op.VFNMA, SixOperands (op1e, op2e, op3e, op4e, op5e, op6e))
    | 0xE7A1us -> struct (Op.VMLH, FourOperands (op1c, op2c, op3c, op4c))
    | 0xE7A2us -> struct (Op.VML, FourOperands (op1c, op2c, op3c, op4c))
    | 0xE7A3us -> struct (Op.VMH, FourOperands (op1c, op2c, op3c, op4c))
    | 0xE7A4us -> struct (Op.VMLE, FourOperands (op1c, op2c, op3c, op4c))
    | 0xE7A5us -> struct (Op.VMLO, FourOperands (op1c, op2c, op3c, op4c))
    | 0xE7A6us -> struct (Op.VME, FourOperands (op1c, op2c, op3c, op4c))
    | 0xE7A7us -> struct (Op.VMO, FourOperands (op1c, op2c, op3c, op4c))
    | 0xE7A9us ->
      struct (Op.VMALH, FiveOperands (op1d, op2d, op3d, op4d, op5d))
    | 0xE7AAus ->
      struct (Op.VMAL, FiveOperands (op1d, op2d, op3d, op4d, op5d))
    | 0xE7ABus ->
      struct (Op.VMAH, FiveOperands (op1d, op2d, op3d, op4d, op5d))
    | 0xE7ACus ->
      struct (Op.VMALE, FiveOperands (op1d, op2d, op3d, op4d, op5d))
    | 0xE7ADus ->
      struct (Op.VMALO, FiveOperands (op1d, op2d, op3d, op4d, op5d))
    | 0xE7AEus ->
      struct (Op.VMAE, FiveOperands (op1d, op2d, op3d, op4d, op5d))
    | 0xE7AFus ->
      struct (Op.VMAO, FiveOperands (op1d, op2d, op3d, op4d, op5d))
    | 0xE7B4us -> struct (Op.VGFM, FourOperands (op1c, op2c, op3c, op4c))
    | 0xE7B8us ->
      struct (Op.VMSL, SixOperands (op1d, op2d, op3d, op4d, op5d, op6d))
    | 0xE7B9us -> struct (Op.VACCC, FourOperands (op1d, op2d, op3d, op4d))
    | 0xE7BBus ->
      struct (Op.VAC, FiveOperands (op1d, op2d, op3d, op4d, op5d))
    | 0xE7BCus ->
      struct (Op.VGFMA, FiveOperands (op1d, op2d, op3d, op4d, op5d))
    | 0xE7BDus ->
      struct (Op.VSBCBI, FiveOperands (op1d, op2d, op3d, op4d, op5d))
    | 0xE7BFus ->
      struct (Op.VSBI, FiveOperands (op1d, op2d, op3d, op4d, op5d))
    | 0xE7C0us ->
      struct (Op.VCLFP, FiveOperands (op1a, op2a, op3a, op4a, op5a))
    | 0xE7C1us ->
      struct (Op.VCFPL, FiveOperands (op1a, op2a, op3a, op4a, op5a))
    | 0xE7C2us ->
      struct (Op.VCSFP, FiveOperands (op1a, op2a, op3a, op4a, op5a))
    | 0xE7C3us ->
      struct (Op.VCFPS, FiveOperands (op1a, op2a, op3a, op4a, op5a))
    | 0xE7C4us -> struct (Op.VFLL, FourOperands (op1a, op2a, op3a, op4a))
    | 0xE7C5us ->
      struct (Op.VFLR, FiveOperands (op1a, op2a, op3a, op4a, op5a))
    | 0xE7C7us ->
      struct (Op.VFI, FiveOperands (op1a, op2a, op3a, op4a, op5a))
    | 0xE7CAus -> struct (Op.WFK, FourOperands (op1a, op2a, op3a, op4a))
    | 0xE7CBus -> struct (Op.WFC, FourOperands (op1a, op2a, op3a, op4a))
    | 0xE7CCus ->
      struct (Op.VFPSO, FiveOperands (op1a, op2a, op3a, op4a, op5a))
    | 0xE7CEus -> struct (Op.VFSQ, FourOperands (op1a, op2a, op3a, op4a))
    | 0xE7D4us -> struct (Op.VUPLL, ThreeOperands (op1a, op2a, op3a))
    | 0xE7D5us -> struct (Op.VUPLH, ThreeOperands (op1a, op2a, op3a))
    | 0xE7D6us -> struct (Op.VUPL, ThreeOperands (op1a, op2a, op3a))
    | 0xE7D7us -> struct (Op.VUPH, TwoOperands (op1a, op2a))
    | 0xE7D8us -> struct (Op.VTM, ThreeOperands (op1a, op2a, op3a))
    | 0xE7D9us -> struct (Op.VECL, ThreeOperands (op1a, op2a, op3a))
    | 0xE7DBus -> struct (Op.VEC, ThreeOperands (op1a, op2a, op3a))
    | 0xE7DEus -> struct (Op.VLC, ThreeOperands (op1a, op2a, op3a))
    | 0xE7DFus -> struct (Op.VLP, ThreeOperands (op1a, op2a, op3a))
    | 0xE7E2us -> struct (Op.VFS, ThreeOperands (op1a, op2a, op3a))
    | 0xE7E3us ->
      struct (Op.VFA, FiveOperands (op1c, op2c, op3c, op4c, op5c))
    | 0xE7E5us ->
      struct (Op.VFD, FiveOperands (op1c, op2c, op3c, op4c, op5c))
    | 0xE7E7us ->
      struct (Op.VFM, FiveOperands (op1c, op2c, op3c, op4c, op5c))
    | 0xE7E8us ->
      struct (Op.VFCE, SixOperands (op1c, op2c, op3c, op4c, op5c, op6c))
    | 0xE7EAus ->
      struct (Op.VFCHE, SixOperands (op1c, op2c, op3c, op4c, op5c, op6c))
    | 0xE7EBus ->
      struct (Op.VFCH, SixOperands (op1c, op2c, op3c, op4c, op5c, op6c))
    | 0xE7EEus ->
      struct (Op.VFMIN, SixOperands (op1c, op2c, op3c, op4c, op5c, op6c))
    | 0xE7EFus ->
      struct (Op.VFMAX, SixOperands (op1c, op2c, op3c, op4c, op5c, op6c))
    | 0xE7F0us -> struct (Op.VAVGL, FourOperands (op1c, op2c, op3c, op4c))
    | 0xE7F1us -> struct (Op.VACC, FourOperands (op1c, op2c, op3c, op4c))
    | 0xE7F2us -> struct (Op.VAVG, FourOperands (op1c, op2c, op3c, op4c))
    | 0xE7F3us -> struct (Op.VA, FourOperands (op1c, op2c, op3c, op4c))
    | 0xE7F5us -> struct (Op.VSCBI, FourOperands (op1c, op2c, op3c, op4c))
    | 0xE7F7us -> struct (Op.VS, FourOperands (op1c, op2c, op3c, op4c))
    | 0xE7F8us ->
      struct (Op.VCEQ, FiveOperands (op1b, op2b, op3b, op4b, op5b))
    | 0xE7F9us ->
      struct (Op.VCHL, FiveOperands (op1b, op2b, op3b, op4b, op5b))
    | 0xE7FBus ->
      struct (Op.VCH, FiveOperands (op1b, op2b, op3b, op4b, op5b))
    | 0xE7FCus -> struct (Op.VMNL, FourOperands (op1c, op2c, op3c, op4c))
    | 0xE7FDus -> struct (Op.VMXL, FourOperands (op1c, op2c, op3c, op4c))
    | 0xE7FEus -> struct (Op.VMN, FourOperands (op1c, op2c, op3c, op4c))
    | 0xE7FFus -> struct (Op.VMX, FourOperands (op1c, op2c, op3c, op4c))
    | _ -> struct (Op.InvalOp, NoOperand)

  fillFmt op opr Fmt.VRR

let parseVRS (bin: uint64) (state: State) =
  let opcode1 = extract48 bin 0 7 |> uint16
  let opcode2 = extract48 bin 40 47 |> uint16
  let opcode = opcode1 <<< 8 ||| opcode2

  let rxb = extract48 bin 36 39 |> uint16
  let toVR = getVR rxb

  let base2 = extract48 bin 16 19 |> uint16
  let disp2 = extract48 bin 20 31 |> uint32 |> DispU
  let op2 = OpStore (None, getR base2, disp2)
  let op2a=  OpStore (None, getAR base2, disp2)
  let b2op2 = modeSelect (state.Tm) op2 op2a

  let frag1 = extract48 bin 8 11 |> uint16
  let frag2 = extract48 bin 12 15 |> uint16
  let frag3 = extract48 bin 16 19 |> uint16
  let frag4 = extract48 bin 32 35 |> uint16

  let op1a = OpReg (toVR frag1 1us)
  let op3a = OpReg (toVR frag2 2us)
  let op4a = OpMask frag4

  let op1b = OpReg (toVR frag1 1us)
  let op3b = OpReg (getR frag2)
  let op4b = OpMask frag4

  let op1c = OpReg (getR frag1)
  let op3c = OpReg (toVR frag2 2us)
  let op4c = OpMask frag4

  let op1d = OpReg (toVR frag4 4us)
  let op3d = OpReg (getR frag2)

  let struct (op, opr) =
    match opcode with
    | 0xE637us -> struct (Op.VLRLR, ThreeOperands (op1d, b2op2, op3d))
    | 0xE63Fus -> struct (Op.VSTRLR, ThreeOperands (op1d, b2op2, op3d))
    | 0xE721us -> struct (Op.VLGV, FourOperands (op1c, op2, op3c, op4c))
    | 0xE722us -> struct (Op.VLVG, FourOperands (op1b, op2, op3b, op4b))
    | 0xE730us -> struct (Op.VESL, FourOperands (op1a, op2, op3a, op4a))
    | 0xE733us -> struct (Op.VERLL, FourOperands (op1a, op2, op3a, op4a))
    | 0xE736us -> struct (Op.VLM, FourOperands (op1a, b2op2, op3a, op4a))
    | 0xE737us -> struct (Op.VLL, ThreeOperands (op1b, b2op2, op3b))
    | 0xE738us -> struct (Op.VESRL, FourOperands (op1a, op2, op3a, op4a))
    | 0xE73Aus -> struct (Op.VESRA, FourOperands (op1a, op2, op3a, op4a))
    | 0xE73Eus -> struct (Op.VSTM, FourOperands (op1a, b2op2, op3a, op4a))
    | 0xE73Fus -> struct (Op.VSTL, ThreeOperands (op1b, b2op2, op3b))
    | _ -> struct (Op.InvalOp, NoOperand)

  fillFmt op opr Fmt.VRS

let parseVRV (bin: uint64) (state: State) =
  let opcode1 = extract48 bin 0 7 |> uint16
  let opcode2 = extract48 bin 40 47 |> uint16
  let opcode = opcode1 <<< 8 ||| opcode2

  let rxb = extract48 bin 36 39 |> uint16
  let toVR = getVR rxb

  let op1 = toVR (extract48 bin 8 11 |> uint16) 1us |> OpReg

  let vidx2 = toVR (extract48 bin 12 15 |> uint16) 2us
  let base2 = extract48 bin 16 19 |> uint16
  let disp2 = extract48 bin 20 31 |> uint32 |> DispU
  let op2 = OpStore (Some vidx2, getR base2, disp2)
  let op2a = OpStore (Some vidx2, getAR base2, disp2)
  let b2op2 = modeSelect state.Tm op2 op2a

  let op3 = extract48 bin 32 35 |> uint16 |> OpMask

  let struct (op, opr) =
    match opcode with
    | 0xE712us -> struct (Op.VGEG, ThreeOperands (op1, b2op2, op3))
    | 0xE713us -> struct (Op.VGEF, ThreeOperands (op1, b2op2, op3))
    | 0xE71Aus -> struct (Op.VSCEG, ThreeOperands (op1, b2op2, op3))
    | 0xE71Bus -> struct (Op.VSCEF, ThreeOperands (op1, b2op2, op3))
    | _ -> struct (Op.InvalOp, NoOperand)

  fillFmt op opr Fmt.VRV

let parseVRX (bin: uint64) (state: State) =
  let opcode1 = extract48 bin 0 7 |> uint16
  let opcode2 = extract48 bin 40 47 |> uint16
  let opcode = opcode1 <<< 8 ||| opcode2

  let rxb = extract48 bin 36 39 |> uint16
  let toVR = getVR rxb

  let op1 = OpReg (toVR (extract48 bin 8 11 |> uint16) 1us)
  let idx2 = Some (getR (extract48 bin 12 15 |> uint16))
  let base2 = extract48 bin 16 19 |> uint16
  let disp2 = extract48 bin 20 31 |> uint32 |> DispU
  let op2 = OpStore (idx2, getR base2, disp2)
  let op2a = OpStore (idx2, getAR base2, disp2)
  let b2op2 = modeSelect state.Tm op2 op2a

  let op3 = OpMask (extract48 bin 32 35 |> uint16)

  let struct (op, opr) =
    match opcode with
    | 0xE601us -> struct (Op.VLEBRH, ThreeOperands (op1, b2op2, op3))
    | 0xE602us -> struct (Op.VLEBRG, ThreeOperands (op1, b2op2, op3))
    | 0xE603us -> struct (Op.VLEBRF, ThreeOperands (op1, b2op2, op3))
    | 0xE604us -> struct (Op.VLLEBRZ, ThreeOperands (op1, b2op2, op3))
    | 0xE605us -> struct (Op.VLBRREP, ThreeOperands (op1, b2op2, op3))
    | 0xE606us -> struct (Op.VLBR, ThreeOperands (op1, b2op2, op3))
    | 0xE607us -> struct (Op.VLER, ThreeOperands (op1, b2op2, op3))
    | 0xE609us -> struct (Op.VSTEBRH, ThreeOperands (op1, b2op2, op3))
    | 0xE60Aus -> struct (Op.VSTEBRG, ThreeOperands (op1, b2op2, op3))
    | 0xE60Bus -> struct (Op.VSTEBRF, ThreeOperands (op1, b2op2, op3))
    | 0xE60Fus -> struct (Op.VSTER, ThreeOperands (op1, b2op2, op3))
    | 0xE700us -> struct (Op.VLEB, ThreeOperands (op1, b2op2, op3))
    | 0xE701us -> struct (Op.VLEH, ThreeOperands (op1, b2op2, op3))
    | 0xE702us -> struct (Op.VLEG, ThreeOperands (op1, b2op2, op3))
    | 0xE703us -> struct (Op.VLEF, ThreeOperands (op1, b2op2, op3))
    | 0xE704us -> struct (Op.VLLEZ, ThreeOperands (op1, b2op2, op3))
    | 0xE705us -> struct (Op.VLREP, ThreeOperands (op1, b2op2, op3))
    | 0xE706us -> struct (Op.VL, ThreeOperands (op1, b2op2, op3))
    | 0xE707us -> struct (Op.VLBB, ThreeOperands (op1, b2op2, op3))
    | 0xE708us -> struct (Op.VSTEB, ThreeOperands (op1, b2op2, op3))
    | 0xE709us -> struct (Op.VSTEH, ThreeOperands (op1, b2op2, op3))
    | 0xE70Aus -> struct (Op.VSTEG, ThreeOperands (op1, b2op2, op3))
    | 0xE70Bus -> struct (Op.VSTEF, ThreeOperands (op1, b2op2, op3))
    | 0xE70Eus -> struct (Op.VST, ThreeOperands (op1, b2op2, op3))
    | _ -> struct (Op.InvalOp, NoOperand)

  fillFmt op opr Fmt.VRX

let parseVSI (bin: uint64) (state: State) =
  let opcode1 = extract48 bin 0 7 |> uint16
  let opcode2 = extract48 bin 40 47 |> uint16
  let opcode = opcode1 <<< 8 ||| opcode2

  let rxb = extract48 bin 36 39 |> uint16
  let toVR = getVR rxb

  let op1 = OpReg (toVR (extract48 bin 32 35 |> uint16) 4us)
  let base2 = extract48 bin 16 19 |> uint16
  let disp2 = extract48 bin 20 31 |> uint32 |> DispU
  let op2 = OpStore (None, getR base2, disp2)
  let op2a = OpStore (None, getAR base2, disp2)
  let b2op2 = modeSelect state.Tm op2 op2a
  let op3 = OpImm (ImmU8 (extract48 bin 8 15 |> uint8))

  let struct (op, opr) =
    match opcode with
    | 0xE634us -> struct (Op.VPKZ, ThreeOperands (op1, b2op2, op3))
    | 0xE635us -> struct (Op.VLRL, ThreeOperands (op1, b2op2, op3))
    | 0xE63Cus -> struct (Op.VUPKZ, ThreeOperands (op1, b2op2, op3))
    | 0xE63Dus -> struct (Op.VSTRL, ThreeOperands (op1, b2op2, op3))
    | _ -> struct (Op.InvalOp, NoOperand)

  fillFmt op opr Fmt.VSI

let parseIE (bin: uint32) (state: State) =
  let opcode = extract32 bin 0 15 |> uint16

  let op1 = BitVector.OfUInt32 (extract32 bin 24 27 |> uint32) 4<rt> |> ImmU4
  let op2 = BitVector.OfUInt32 (extract32 bin 28 31 |> uint32) 4<rt> |> ImmU4

  match opcode with
  | 0xB2FAus -> struct (Op.NIAI, TwoOperands (OpImm op1, OpImm op2), Fmt.IE)
  | _ -> struct (Op.InvalOp, NoOperand, Fmt.IE)