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

module internal B2R2.FrontEnd.S390.Helper

open System
open B2R2
open B2R2.FrontEnd.BinLifter

let extract16 (bin: uint16) (ofs1: int) (ofs2: int) =
  let m, n = if max ofs1 ofs2 = ofs1 then ofs1, ofs2 else ofs2, ofs1
  if m - n > 15 then invalidOp "Invalid range of offsets given."
  [ n .. m ]
  |> List.fold (fun acc i -> acc <<< 1 ||| (bin >>> 15 - i &&& 0b1us)) 0us

let extract32 (bin: uint32) ofs1 ofs2 =
  let m, n = if max ofs1 ofs2 = ofs1 then ofs1, ofs2 else ofs2, ofs1
  if m - n > 31 then invalidOp "Invalid range of offsets given."
  [ n .. m ]
  |> List.fold (fun acc i -> acc <<< 1 ||| (bin >>> 31 - i &&& 0b1u)) 0u

let extract48 (bin: uint64) ofs1 ofs2 =
  let m, n = if max ofs1 ofs2 = ofs1 then ofs1, ofs2 else ofs2, ofs1
  if m - n > 47 then invalidOp "Invalid range of offsets given."
  [ n .. m ]
  |> List.fold (fun acc i -> acc <<< 1 ||| (bin >>> 47 - i &&& 0b1UL)) 0UL

let extract64 (bin: uint64) ofs1 ofs2 =
  let m, n = if max ofs1 ofs2 = ofs1 then ofs1, ofs2 else ofs2, ofs1
  if m - n > 63 then invalidOp "Invalid range of offsets given."
  [ n .. m ]
  |> List.fold (fun acc i -> acc <<< 1 ||| (bin >>> 63 - i &&& 0b1UL)) 0UL

let extract128 (bin: UInt128) ofs1 ofs2 =
  let m, n = if max ofs1 ofs2 = ofs1 then ofs1, ofs2 else ofs2, ofs1
  if m - n > 127 then invalidOp "Invalid range of offsets given."
  [ n .. m ]
  |> List.fold (fun acc i -> acc <<< 1 ||| (bin >>> 127 - i &&& UInt128.One))
    UInt128.Zero

let getR (bin: uint16) =
  match bin with
  | 0us -> Register.R0
  | 1us -> Register.R1
  | 2us -> Register.R2
  | 3us -> Register.R3
  | 4us -> Register.R4
  | 5us -> Register.R5
  | 6us -> Register.R6
  | 7us -> Register.R7
  | 8us -> Register.R8
  | 9us -> Register.R9
  | 10us -> Register.R10
  | 11us -> Register.R11
  | 12us -> Register.R12
  | 13us -> Register.R13
  | 14us -> Register.R14
  | 15us -> Register.R15
  | _ -> raise InvalidOperandException

let getFPR (bin: uint16) =
  match bin with
  | 0us -> Register.FPR0
  | 1us -> Register.FPR1
  | 2us -> Register.FPR2
  | 3us -> Register.FPR3
  | 4us -> Register.FPR4
  | 5us -> Register.FPR5
  | 6us -> Register.FPR6
  | 7us -> Register.FPR7
  | 8us -> Register.FPR8
  | 9us -> Register.FPR9
  | 10us -> Register.FPR10
  | 11us -> Register.FPR11
  | 12us -> Register.FPR12
  | 13us -> Register.FPR13
  | 14us -> Register.FPR14
  | 15us -> Register.FPR15
  | _ -> raise InvalidOperandException

let getVR (rxb: uint16) (bin: uint16) (pos: uint16) =
  match bin ||| (rxb <<< (uint32 pos |> int32) &&& 0b10000us) with
  | 0x00us -> Register.VR0
  | 0x01us -> Register.VR1
  | 0x02us -> Register.VR2
  | 0x03us -> Register.VR3
  | 0x04us -> Register.VR4
  | 0x05us -> Register.VR5
  | 0x06us -> Register.VR6
  | 0x07us -> Register.VR7
  | 0x08us -> Register.VR8
  | 0x09us -> Register.VR9
  | 0x0Aus -> Register.VR10
  | 0x0Bus -> Register.VR11
  | 0x0Cus -> Register.VR12
  | 0x0Dus -> Register.VR13
  | 0x0Eus -> Register.VR14
  | 0x0Fus -> Register.VR15
  | 0x10us -> Register.VR16
  | 0x11us -> Register.VR17
  | 0x12us -> Register.VR18
  | 0x13us -> Register.VR19
  | 0x14us -> Register.VR20
  | 0x15us -> Register.VR21
  | 0x16us -> Register.VR22
  | 0x17us -> Register.VR23
  | 0x18us -> Register.VR24
  | 0x19us -> Register.VR25
  | 0x1Aus -> Register.VR26
  | 0x1Bus -> Register.VR27
  | 0x1Cus -> Register.VR28
  | 0x1Dus -> Register.VR29
  | 0x1Eus -> Register.VR30
  | 0x1Fus -> Register.VR31
  | _ -> raise InvalidOperandException

let getFPC (bin: uint16) =
  match bin with
  | 0us -> Register.FPC
  | _ -> raise InvalidOperandException

let getCR (bin: uint16) =
  match bin with
  | 0us -> Register.CR0
  | 1us -> Register.CR1
  | 2us -> Register.CR2
  | 3us -> Register.CR3
  | 4us -> Register.CR4
  | 5us -> Register.CR5
  | 6us -> Register.CR6
  | 7us -> Register.CR7
  | 8us -> Register.CR8
  | 9us -> Register.CR9
  | 10us -> Register.CR10
  | 11us -> Register.CR11
  | 12us -> Register.CR12
  | 13us -> Register.CR13
  | 14us -> Register.CR14
  | 15us -> Register.CR15
  | _ -> raise InvalidOperandException

let getAR (bin: uint16) =
  match bin with
  | 0us -> Register.AR0
  | 1us -> Register.AR1
  | 2us -> Register.AR2
  | 3us -> Register.AR3
  | 4us -> Register.AR4
  | 5us -> Register.AR5
  | 6us -> Register.AR6
  | 7us -> Register.AR7
  | 8us -> Register.AR8
  | 9us -> Register.AR9
  | 10us -> Register.AR10
  | 11us -> Register.AR11
  | 12us -> Register.AR12
  | 13us -> Register.AR13
  | 14us -> Register.AR14
  | 15us -> Register.AR15
  | _ -> raise InvalidOperandException

let gr8to11UHWQ b = extract48 b 8 11 |> uint16

let gr9to11UHWQ b = extract48 b 9 11 |> uint16

let gr12to15UHWQ b = extract48 b 12 15 |> uint16

let gr12to15UWQ b = extract48 b 12 15 |> uint32

let gr16to27UWQ b = extract48 b 16 27 |> uint32

let gr32to35UWQ b = extract48 b 32 35 |> uint32

let gr8to15UHWQ b = extract48 b 8 15 |> uint16

let gr36to39UHWQ b = extract48 b 36 39 |> uint16

let gr16to19UQ b = extract48 b 16 19 |> uint16 |> getR

let gr9to11UQ b = extract48 b 9 11 |> uint16 |> getR

let gr16to19Q b = extract48 b 16 19 |> uint16 |> getR |> OpReg

let gr9to11Q b = extract48 b 9 11 |> uint16 |> getR |> OpReg

let gr8to11 b = extract16 b 8 11 |> getR |> OpReg

let fpr8to11 b = extract16 b 8 11 |> getFPR |> OpReg

let fpr12to15 b = extract16 b 12 15 |> getFPR |> OpReg

let gr12to15 b = extract16 b 12 15 |> getR |> OpReg

let gr8Maskto11 b = extract16 b 8 11 |> OpMask

let gr8to11W b = extract32 b 8 11 |> uint16 |> getR |> OpReg

let fpr8to11W b = extract32 b 8 11 |> uint16 |> getFPR |> OpReg

let ar8to11W b = extract32 b 8 11 |> uint16 |> getAR |> OpReg

let cr8to11W b = extract32 b 8 11 |> uint16 |> getCR |> OpReg

let mask8to11W b = extract32 b 8 11 |> uint16 |> OpMask

let mask8to11Q b = extract48 b 8 11 |> uint16 |> OpMask

let mask12to15W b = extract32 b 12 15 |> uint16 |> OpMask

let mask16to19W b = extract32 b 16 19 |> uint16 |> OpMask

let mask20to23W b = extract32 b 20 23 |> uint16 |> OpMask

let mask20to23Q b = extract48 b 20 23 |> uint16 |> OpMask

let gr12to15W b = extract32 b 12 15 |> uint16 |> getR |> OpReg

let ar12to15W b = extract32 b 12 15 |> uint16 |> getAR |> OpReg

let cr12to15W b = extract32 b 12 15 |> uint16 |> getCR |> OpReg

let gr24to27W b = extract32 b 24 27 |> uint16 |> getR |> OpReg

let gr28to31W b = extract32 b 28 31 |> uint16 |> getR |> OpReg

let fpr16to19W b = extract32 b 16 19 |> uint16 |> getFPR |> OpReg

let fpr24to27W b = extract32 b 24 27 |> uint16 |> getFPR |> OpReg

let fpr28to31W b = extract32 b 28 31 |> uint16 |> getFPR |> OpReg

let fpr32to35Q b = extract48 b 32 35 |> uint16 |> getFPR |> OpReg

let ar24to27W b = extract32 b 24 27 |> uint16 |> getAR |> OpReg

let ar28to31W b = extract32 b 28 31 |> uint16 |> getAR |> OpReg

let idx12 b = extract32 b 12 15 |> uint16 |> getR |> Some

let idx12Q b = extract48 b 12 15 |> uint16 |> getR |> Some

let gr16to19W b = extract32 b 16 19 |> uint16 |> getR |> OpReg

let base16 b = extract32 b 16 19 |> uint16 |> getR

let base16Q b = extract48 b 16 19 |> uint16 |> getR

let base32Q b = extract48 b 32 35 |> uint16 |> getR

let disp20 b = extract32 b 20 31 |> uint32 |> DispU

let disp20Q b = extract48 b 20 31 |> uint32 |> DispU

let disp36Q b = extract48 b 36 47 |> uint32 |> DispU

let disp20to39SQ b =
  extract48 b 32 39 |> int8 |> int32 <<< 12
  ||| (extract48 b 20 31 |> uint16 |> uint32 |> int32)
  |> DispS

let hWUpperImm b = extract32 b 16 31 |> int16 |> uint16 |> ImmU16 |> OpImm

let hWUpperSImm b = extract32 b 16 31 |> int16 |> ImmS16 |> OpImm

let hWUpperSImmR b = extract32 b 16 31 |> int16 |> ImmS16 |> OpRImm

let hWUpperImmM b = extract32 b 16 31 |> int16 |> uint16 |> OpMask

let bit8to15UImm8 b = extract32 b 8 15 |> uint8 |> ImmU8 |> OpImm

let bit8to11ImmM b = extract32 b 8 11 |> uint16 |> OpMask

let gr8to11Q b = extract48 b 8 11 |> uint16 |> getR |> OpReg

let vr8Q b = getVR (gr36to39UHWQ b) (extract48 b 8 11 |> uint16) 1us |> OpReg

let vr12Q b pos =
  getVR (gr36to39UHWQ b) (extract48 b 12 15 |> uint16) pos |> OpReg

let vr16Q b pos =
  getVR (gr36to39UHWQ b) (extract48 b 16 19 |> uint16) pos |> OpReg

let vr32Q b pos =
  getVR (gr36to39UHWQ b) (extract48 b 32 35 |> uint16) pos |> OpReg

let fpr8to11Q b = extract48 b 8 11 |> uint16 |> getFPR |> OpReg

let cr8to11Q b = extract48 b 8 11 |> uint16 |> getCR |> OpReg

let ar8to11Q b = extract48 b 8 11 |> uint16 |> getAR |> OpReg

let gr12to15Q b = extract48 b 12 15 |> uint16 |> getR |> OpReg

let cr12to15Q b = extract48 b 12 15 |> uint16 |> getCR |> OpReg

let ar12to15Q b = extract48 b 12 15 |> uint16 |> getAR |> OpReg

let gr16to47SImmQ b = extract48 b 16 47 |> int32 |> ImmS32 |> OpImm

let gr16to47SImmRQ b = extract48 b 16 47 |> int32 |> ImmS32 |> OpRImm

let gr16to47UImmCQ b = extract48 b 16 47 |> int32 |> uint32 |> ImmU32 |> OpImm

let gr16to23UImmBQ b = extract48 b 16 23 |> uint8 |> ImmU8 |> OpImm

let gr24to31UImmBQ b = extract48 b 24 31 |> uint8 |> ImmU8 |> OpImm

let gr32to39UImmBQ b = extract48 b 32 39 |> uint8 |> ImmU8 |> OpImm

let gr32to39SImm b = extract48 b 32 39 |> int8 |> ImmS8 |> OpImm

let mask12to15Q b = extract48 b 12 15 |> uint16 |> OpMask

let mask24to27Q b = extract48 b 24 27 |> uint16 |> OpMask

let mask28to31Q b = extract48 b 28 31 |> uint16 |> OpMask

let mask32to35Q b = extract48 b 32 35 |> uint16 |> OpMask

let mask36to39Q b = extract48 b 36 39 |> uint16 |> OpMask

let gr16to31SImmBQ b = extract48 b 16 31 |> int8 |> ImmS8 |> OpImm

let gr16to31SImmCQ b = extract48 b 16 31 |> int8 |> uint8 |> ImmU8 |> OpImm

let gr16to31UImmCQ b = extract48 b 16 31 |> int16 |> uint8 |> ImmU8 |> OpImm

let gr32to39UImmCQ b = extract48 b 32 39 |> int8 |> uint8 |> ImmU8 |> OpImm

let gr8to15UImmB b = extract16 b 8 15 |> uint8 |> ImmU8 |> OpImm

let gr8to15UImmBQ b = extract48 b 8 15 |> uint8 |> ImmU8 |> OpImm

let gr8to15SImmCBQ b = extract48 b 8 15 |> uint8 |> int8 |> ImmS8 |> OpImm

let gr16to31SImmQ b = extract48 b 16 31 |> int16 |> ImmS16 |> OpImm

let gr16to31UImmQ b = extract48 b 16 31 |> uint16 |> ImmU16 |> OpImm

let gr28to35UImmBQ b = extract48 b 28 35 |> uint8 |> ImmU8 |> OpImm

let gr16to31SImmRQ b = extract48 b 16 31 |> int16 |> ImmS16 |> OpRImm

let gr32to47UImmQ b = extract48 b 32 47 |> uint16 |> ImmU16 |> OpImm

let gr32to47SImmBRQ b = extract48 b 32 47 |> int8 |> ImmS8 |> OpRImm

let gr32to47SImmCQ b = extract48 b 32 47 |> uint16 |> int16 |> ImmS16 |> OpImm

let getUImm8to15 b = OneOperand(gr8to15UImmB b)

let getGR8to11 b = OneOperand(gr8to11 b)

let getGR24to27 b = OneOperand(gr24to27W b)

let getNoneM16D20 b = OneOperand(OpStore(None, base16 b, disp20 b))

let getVR12Q b = OneOperand(vr12Q b 2us)

let getM16D20L b = OneOperand(OpStore(None, base16Q b, disp20to39SQ b))

let getGRL8Q b =
  OneOperand(OpStoreLen(gr8to11UHWQ b + 2us, gr16to19UQ b, disp20Q b))

let getGR8GR12 b = TwoOperands(gr8to11 b, gr12to15 b)

let getGR24GR28 b = TwoOperands(gr24to27W b, gr28to31W b)

let getFPR24GR28 b = TwoOperands(fpr24to27W b, gr28to31W b)

let getGR24FPR28 b = TwoOperands(gr24to27W b, fpr28to31W b)

let getFPR24FPR28 b = TwoOperands(fpr24to27W b, fpr28to31W b)

let getAR24AR28 b = TwoOperands(ar24to27W b, ar28to31W b)

let getAR24GR28 b = TwoOperands(ar24to27W b, gr28to31W b)

let getGR24AR28 b = TwoOperands(gr24to27W b, ar28to31W b)

let getFPR8FPR12 b = TwoOperands(fpr8to11 b, fpr12to15 b)

let getMGR8GR12 b = TwoOperands(gr8Maskto11 b, gr12to15 b)

let getGR8WIdx12M16D20 b =
  TwoOperands(gr8to11W b, OpStore(idx12 b, base16 b, disp20 b))

let getMask8WIdx12M16D20 b =
  TwoOperands(mask8to11W b, OpStore(idx12 b, base16 b, disp20 b))

let getAR8WIdx12M16D20 b =
  TwoOperands(ar8to11W b, OpStore(idx12 b, base16 b, disp20 b))

let getGR8WNoneM16D20 b =
  TwoOperands(gr8to11W b, OpStore(None, base16 b, disp20 b))

let getFPR8WIdx12M16D20 b =
  TwoOperands(fpr8to11W b, OpStore(idx12 b, base16 b, disp20 b))

let getNoneM16D20UImm8 b =
  TwoOperands(OpStore(None, base16 b, disp20 b), bit8to15UImm8 b)

let getGR8HWImm b = TwoOperands(gr8to11W b, hWUpperImm b)

let getGR8HWImmM b = TwoOperands(gr8to11W b, hWUpperImmM b)

let getGR8SImmUpper b = TwoOperands(gr8to11W b, hWUpperSImm b)

let getGR8SImmRUpper b = TwoOperands(gr8to11W b, hWUpperSImmR b)

let getBit8MaskSImmRUpper b = TwoOperands(bit8to11ImmM b, hWUpperSImmR b)

let getMask8QSImm16to47RQ b = TwoOperands(mask8to11Q b, gr16to47SImmRQ b)

let getGR8QSImm16to47Q b = TwoOperands(gr8to11Q b, gr16to47SImmQ b)

let getGR8QUImm16to47CQ b = TwoOperands(gr8to11Q b, gr16to47UImmCQ b)

let getGR8QSImm16to47RQ b = TwoOperands(gr8to11Q b, gr16to47SImmRQ b)

let getGR8QIdx12M16D20 b =
  TwoOperands(gr8to11Q b, OpStore(idx12Q b, base16Q b, disp20to39SQ b))

let getAR8QIdx12M16D20 b =
  TwoOperands(ar8to11Q b, OpStore(idx12Q b, base16Q b, disp20to39SQ b))

let getFPR8QIdx12MemBase16DispL20 b =
  TwoOperands(fpr8to11Q b, OpStore(idx12Q b, base16Q b, disp20to39SQ b))

let getMask8QIdx12M16D20 b =
  TwoOperands(mask8to11Q b, OpStore(idx12Q b, base16Q b, disp20to39SQ b))

let getFPR8QIdx12M16D20 b =
  TwoOperands(fpr8to11Q b, OpStore(idx12Q b, base16Q b, disp20Q b))

let getM16D20UImm32to47Q b =
  TwoOperands(OpStore(None, base16Q b, disp20Q b), gr32to47UImmQ b)

let getM16D20SImm32to47CQ b =
  TwoOperands(OpStore(None, base16Q b, disp20Q b), gr32to47SImmCQ b)

let getM16D20LUImm8to15Q b =
  TwoOperands(OpStore(None, base16Q b, disp20to39SQ b), gr8to15UImmBQ b)

let getM16D20LSImm8to15Q b =
  TwoOperands(OpStore(None, base16Q b, disp20to39SQ b), gr8to15SImmCBQ b)

let getGRL8QM32D36 b =
  TwoOperands(OpStoreLen(gr8to15UHWQ b + 1us, base16Q b, disp20Q b),
  OpStore(None, base32Q b, disp36Q b))

let getM16D20GRL8Q b =
  TwoOperands(OpStore(None, base16Q b, disp20Q b),
  OpStoreLen(gr8to15UHWQ b + 1us, base32Q b, disp36Q b))

let getM16D20M32D36 b =
  TwoOperands(OpStore(None, base16Q b, disp20Q b),
  OpStore(None, base32Q b, disp36Q b))

let getVR8QUImm16 b = TwoOperands(vr8Q b, gr16to31UImmQ b)

let grl9QGRL12Q b =
  TwoOperands(OpStoreLen(gr9to11UHWQ b + 1us, base16Q b, disp20Q b),
  OpStoreLen(gr12to15UHWQ b + 1us, base32Q b, disp36Q b))

let getVR8QVR12Q b = TwoOperands(vr8Q b, vr12Q b 2us)

let getGR8WNoneM16D20GR12 b =
  ThreeOperands(gr8to11W b, OpStore(None, base16 b, disp20 b), gr12to15W b)

let getGR8WNoneM16D20Mask12 b =
  ThreeOperands(gr8to11W b, OpStore(None, base16 b, disp20 b), mask12to15W b)

let getAR8WNoneM16D20AR12 b =
  ThreeOperands(ar8to11W b, OpStore(None, base16 b, disp20 b), ar12to15W b)

let getCR8WNoneM16D20CR12 b =
  ThreeOperands(cr8to11W b, OpStore(None, base16 b, disp20 b), cr12to15W b)

let getGR8SImmRUpperGR12 b =
  ThreeOperands(gr8to11W b, hWUpperSImmR b, gr12to15W b)

let getFPR16FPR28FPR24 b =
  ThreeOperands(fpr16to19W b, fpr28to31W b, fpr24to27W b)

let getFPR24GR28FPR16 b =
  ThreeOperands(fpr16to19W b, gr28to31W b, fpr16to19W b)

let getGR24GR28Mask16 b =
  ThreeOperands(gr24to27W b, gr28to31W b, mask16to19W b)

let getFPR24FPR28Mask16 b =
  ThreeOperands(fpr24to27W b, fpr28to31W b, mask16to19W b)

let getGR24FPR28Mask16 b =
  ThreeOperands(gr24to27W b, fpr28to31W b, mask16to19W b)

let getGR24FPR28Mask20 b =
  ThreeOperands(gr24to27W b, fpr28to31W b, mask20to23W b)

let getFPR24FPR28Mask20 b =
  ThreeOperands(fpr24to27W b, fpr28to31W b, mask20to23W b)

let getGR24GR28GR16 b = ThreeOperands(gr24to27W b, gr28to31W b, gr16to19W b)

let getFPR24FPR28FPR16 b =
  ThreeOperands(fpr24to27W b, fpr28to31W b, fpr16to19W b)

let getGR8QSImmUpperQGR12Q b =
  ThreeOperands(gr8to11Q b, gr16to31SImmQ b, gr12to15Q b)

let getGR8QSImmUpperQMask12Q b =
  ThreeOperands(gr8to11Q b, gr16to31SImmQ b, mask12to15Q b)

let getGR8QUImmUpperCQGR12Q b =
  ThreeOperands(gr8to11Q b, gr16to31UImmCQ b, gr12to15Q b)

let getGR8QUImmUpperCQMask32Q b =
  ThreeOperands(gr8to11Q b, gr16to31SImmCQ b, mask32to35Q b)

let getGR8QSImmUpperBQMask32Q b =
  ThreeOperands(gr8to11Q b, gr16to31SImmBQ b, mask32to35Q b)

let getGR8QM16D20GR12Q b =
  ThreeOperands(gr8to11Q b, OpStore(None, base16Q b, disp20to39SQ b),
    gr12to15Q b)

let getCR8QM16D20CR12Q b =
  ThreeOperands(cr8to11Q b, OpStore(None, base16Q b, disp20to39SQ b),
    cr12to15Q b)

let getAR8QM16D20AR12Q b =
  ThreeOperands(ar8to11Q b, OpStore(None, base16Q b, disp20to39SQ b),
    ar12to15Q b)

let getGR8QM16D20Mask12Q b =
  ThreeOperands(gr8to11Q b, OpStore(None, base16Q b, disp20to39SQ b),
    mask12to15Q b)

let getGR8QIdx12M16D20Mask32Q b =
  ThreeOperands(gr8to11Q b, OpStore(idx12Q b, base16Q b, disp20Q b),
    mask32to35Q b)

let getMask8QSImm32RM16D20 b =
  ThreeOperands(mask8to11Q b, gr32to47SImmBRQ b,
    OpStore(None, base16Q b, disp20Q b))

let getFPR32QIdx12M16D20FPR8Q b =
  ThreeOperands(fpr32to35Q b, OpStore(idx12Q b, base16Q b, disp20Q b),
    fpr8to11Q b)

let getM16D20M32D36GR8Q b =
  ThreeOperands(OpStore(None, base16Q b, disp20Q b),
    OpStore(None, base32Q b, disp36Q b), gr8to11Q b)

let getVR8QUImmUpperQUImm4 b =
  ThreeOperands(vr8Q b, gr16to31UImmQ b,
    OpImm(BitVector.OfUInt32(gr32to35UWQ b, 4<rt>) |> ImmU4))

let getVR8QUImm16Mask32 b =
  ThreeOperands(vr8Q b, gr16to31UImmQ b, mask32to35Q b)

let getVR8QIdxM16D20Mask32 b =
  ThreeOperands(vr8Q b, OpStore(idx12Q b, base16Q b, disp20Q b), mask32to35Q b)

let getVR8QVIdxM16D20Mask32 b =
  ThreeOperands(vr8Q b,
    OpStore(Some(getVR (gr36to39UHWQ b) (extract48 b 12 15 |> uint16) 2us),
      base16Q b, disp20Q b), mask32to35Q b)

let getVR32QM16D20UImm8 b =
  ThreeOperands(vr32Q b 4us, OpStore(None, base16Q b, disp20Q b),
    gr8to15UImmBQ b)

let getVR8QVR12QMask24 b = ThreeOperands(vr8Q b, vr12Q b 2us, mask24to27Q b)

let getVR8QVR12QMask32 b = ThreeOperands(vr8Q b, vr12Q b 2us, mask32to35Q b)

let getVR8QGR12QGR16Q b = ThreeOperands(vr8Q b, gr12to15Q b, gr16to19Q b)

let getVR8QVR12QVR16Q b = ThreeOperands(vr8Q b, vr12Q b 2us, vr16Q b 3us)

let getVR12QVR16QMask24 b =
  ThreeOperands(vr12Q b 2us, vr16Q b 3us, mask24to27Q b)

let getVR32QM16D20GR12Q b =
  ThreeOperands(vr32Q b 4us, OpStore(None, base16Q b, disp20Q b),
    gr12to15Q b)

let getVR8QM16D20GR12Q b =
  ThreeOperands(vr8Q b, OpStore(None, base16Q b, disp20Q b), gr12to15Q b)

let getFPR32QGRL8QMask36 b =
  ThreeOperands(fpr32to35Q b,
    OpStoreLen(gr8to15UHWQ b + 2us, gr16to19UQ b, disp20Q b), mask36to39Q b)

let getGRL9QM32D36UImm4 b =
  ThreeOperands(OpStoreLen(gr9to11UHWQ b + 1us, base16Q b, disp20Q b),
    OpStore(None, base32Q b, disp36Q b),
    OpImm(BitVector.OfUInt32(gr12to15UWQ b, 4<rt>) |> ImmU4))

let getR9MemBase16to35Disp20to47GR12Q b =
  ThreeOperands(OpStore(Some(gr9to11UQ b), base16Q b, disp20Q b),
    OpStore(None, base32Q b, disp36Q b), gr12to15Q b)

let getGR24GR28GR16Mask20 b =
  FourOperands(gr24to27W b, gr28to31W b, gr16to19W b, mask20to23W b)

let getGR24FPR28Mask16Mask20 b =
  FourOperands(gr24to27W b, fpr28to31W b, mask16to19W b, mask20to23W b)

let getFPR24GR28FPR16Mask20 b =
  FourOperands(fpr24to27W b, gr28to31W b, fpr16to19W b, mask20to23W b)

let getFPR24FPR28FPR16Mask20 b =
  FourOperands(fpr24to27W b, fpr28to31W b, fpr16to19W b, mask20to23W b)

let getFPR24GR28Mask16Mask20 b =
  FourOperands(fpr24to27W b, gr28to31W b, mask16to19W b, mask20to23W b)

let getFPR24FPR28Mask16Mask20 b =
  FourOperands(fpr24to27W b, fpr28to31W b, mask16to19W b, mask20to23W b)

let getGR8QGR12QMask32SImmUpperRQ b =
  FourOperands(gr8to11Q b, gr12to15Q b, mask32to35Q b, gr16to31SImmRQ b)

let getGR8QSImm32BQMask12SImmUpperRQ b =
  FourOperands(gr8to11Q b, gr32to39SImm b, mask12to15Q b, gr16to31SImmRQ b)

let getGR8QUImm32CQMask12SImmUpperRQ b =
  FourOperands(gr8to11Q b, gr32to39UImmCQ b, mask12to15Q b, gr16to31SImmRQ b)

let getGR8QUImm32CQMask12NBase16Disp20 b =
  FourOperands(gr8to11Q b, gr32to39UImmCQ b, mask12to15Q b,
    OpStore(None, base16Q b, disp20Q b))

let getGR8QSImm32BQMask12NBase16Disp20 b =
  FourOperands(gr8to11Q b, gr32to39SImm b, mask12to15Q b,
    OpStore(None, base16Q b, disp20Q b))

let getGR8QGR12QMask32NBase16Disp20 b =
  FourOperands(gr8to11Q b, gr12to15Q b, mask32to35Q b,
    OpStore(None, base16Q b, disp20Q b))

let getGR9QM16D20GR12QM32D36 b =
  FourOperands(gr9to11Q b, OpStore(None, base16Q b, disp20Q b), gr12to15Q b,
    OpStore(None, base32Q b, disp36Q b))

let getGR8QM16D20VR12QMask32 b =
  FourOperands(gr8to11Q b, OpStore(None, base16Q b, disp20Q b), vr12Q b 2us,
    mask32to35Q b)

let getVR8QM16D20VR12QMask32 b =
  FourOperands(vr8Q b, OpStore(None, base16Q b, disp20Q b), vr12Q b 2us,
    mask32to35Q b)

let getVR8QM16D20GR12QMask32 b =
  FourOperands(vr8Q b, OpStore(None, base16Q b, disp20Q b), gr12to15Q b,
    mask32to35Q b)

let getVR8QGR12QUImm8Mask24 b =
  FourOperands(vr8Q b, gr12to15Q b, gr28to35UImmBQ b, mask24to27Q b)

let getVR8QUImm8sMask32 b =
  FourOperands(vr8Q b, gr16to23UImmBQ b, gr24to31UImmBQ b, mask32to35Q b)

let getVR8QUImmUpperVR12QMask32 b =
  FourOperands(vr8Q b, gr16to31UImmQ b, vr12Q b 2us, mask32to35Q b)

let getVR8QVR12QVR16QUImm8 b =
  FourOperands(vr8Q b, vr12Q b 2us, vr16Q b 3us, gr24to31UImmBQ b)

let getGR8QVR12QMask24Mask28 b =
  FourOperands(gr8to11Q b, vr12Q b 2us, mask24to27Q b, mask28to31Q b)

let getVR8QVR12QMask32Mask28 b =
  FourOperands(vr8Q b, vr12Q b 2us, mask32to35Q b, mask28to31Q b)

let getVR8QVR12QMask32Mask24 b =
  FourOperands(vr8Q b, vr12Q b 2us, mask32to35Q b, mask24to27Q b)

let getVR8QVR12QVR16QMask24 b =
  FourOperands(vr8Q b, vr12Q b 2us, vr16Q b 3us, mask24to27Q b)

let getVR8QVR12QVR16QMask32 b =
  FourOperands(vr8Q b, vr12Q b 2us, vr16Q b 3us, mask32to35Q b)

let getVR8QVR12QVR16QVR32Q b =
  FourOperands(vr8Q b, vr12Q b 2us, vr16Q b 3us, vr32Q b 4us)

let getGR8QGR12QUImmUpper24to32Q b =
  FiveOperands(gr8to11Q b, gr12to15Q b, gr16to23UImmBQ b, gr24to31UImmBQ b,
    gr32to39UImmBQ b)

let getVR8QVR12QUImm8sMask24 b =
  FiveOperands(vr8Q b, vr12Q b 2us, gr28to35UImmBQ b, gr16to23UImmBQ b,
    mask24to27Q b)

let getVR8QVR12QVR16QUImm8Mask32 b =
  FiveOperands(vr8Q b, vr12Q b 2us, vr16Q b 3us, gr24to31UImmBQ b,
    mask32to35Q b)

let getVR8QVR12QMask32Mask28Mask24 b =
  FiveOperands(vr8Q b, vr12Q b 2us, mask32to35Q b, mask28to31Q b,
    mask24to27Q b)

let getVR8QVR12QUImm12Mask32Mask28 b =
  FiveOperands(vr8Q b, vr12Q b 2us,
    OpImm(BitVector.OfUInt32(gr16to27UWQ b, 12<rt>) |> ImmU12), mask32to35Q b,
    mask28to31Q b)

let getVR8QVR12QVR16QMask32Mask24 b =
  FiveOperands(vr8Q b, vr12Q b 2us, vr16Q b 3us, mask32to35Q b, mask24to27Q b)

let getVR8QVR12QVR16QMask32Mask28 b =
  FiveOperands(vr8Q b, vr12Q b 2us, vr16Q b 3us, mask32to35Q b, mask28to31Q b)

let getVR8QVR12QVR16QUImm8Mask24 b =
  FiveOperands(vr8Q b, vr12Q b 2us, vr16Q b 3us, gr28to35UImmBQ b,
    mask24to27Q b)

let getVR8QVR12QVR16QVR32QMask20 b =
  FiveOperands(vr8Q b, vr12Q b 2us, vr16Q b 3us, vr32Q b 4us, mask20to23Q b)

let getVR8QVR12QVR16QVR32QMask20Mask24 b =
  SixOperands(vr8Q b, vr12Q b 2us, vr16Q b 3us, vr32Q b 4us, mask20to23Q b,
    mask24to27Q b)

let getVR8QVR12QVR16QVR32QMask28Mask20 b =
  SixOperands(vr8Q b, vr12Q b 2us, vr16Q b 3us, vr32Q b 4us, mask28to31Q b,
    mask20to23Q b)

let getVR8QVR12QVR16QMask32Mask28Mask24 b =
  SixOperands(vr8Q b, vr12Q b 2us, vr16Q b 3us, mask32to35Q b, mask28to31Q b,
    mask24to27Q b)
