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

module internal B2R2.Assembly.S390.AsmLayout

open B2R2.Assembly.S390.AsmField

(* Every value below says where the operands of one shape of instruction go, and
   is read off the matching function of B2R2's own S390 decoder, so that what
   the assembler writes into a field is what the decoder reads back out of it.
   Each is named after that function, and they are kept in the order the table
   of instructions first reaches them. Every bit position is counted from the
   first bit of the instruction, the way the architecture counts them. *)

/// A run of the given number of bits, beginning at the given one.
let private fld pos width = { Pos = pos; Width = width }

/// A general register named by the four bits beginning at the given one.
let private gpr pos = RegField(Gpr, fld pos 4)

/// A floating-point register named by the four bits beginning at the given one.
let private fpr pos = RegField(Fpr, fld pos 4)

/// An access register named by the four bits beginning at the given one.
let private apr pos = RegField(Apr, fld pos 4)

/// A control register named by the four bits beginning at the given one.
let private cpr pos = RegField(Cpr, fld pos 4)

/// A vector register named by the four bits beginning at the first given one,
/// together with the bit holding the fifth bit of its number.
let private vpr pos bit = RegField(Vpr bit, fld pos 4)

/// A set of four bits selecting what an instruction does.
let private mask pos = MaskField(fld pos 4)

/// A set of sixteen such bits, which only the instructions testing a quarter of
/// a register against a pattern hold.
let private maskWide pos = MaskField(fld pos 16)

/// A written number of the given width, which is written out as the bits it
/// holds and nothing more.
let private uimm pos width = ImmField(fld pos width, Unsigned)

/// A written number of eight bits, which is widened to sixteen before being
/// written out, so that one below zero is written as the bits it lands in.
let private simm pos = ImmField(fld pos 8, Signed 16)

/// How far away a place is, said in the given number of bits.
let private rel pos width = RelField(fld pos width)

/// The memory an instruction reaches, as the base register it is counted off
/// and the twelve bits holding the number added to that register.
let private mem bse pos = MemField(None, fld bse 4, Short(fld pos 12))

/// The same, with a general register added to the base one as well.
let private memIdx idx bse pos =
  MemField(Some(Gpr, fld idx 4), fld bse 4, Short(fld pos 12))

/// The same, where what is added to the base register is a vector register,
/// which is how the instructions gathering and scattering elements reach.
let private memVecIdx idx bse pos =
  MemField(Some(Vpr 37, fld idx 4), fld bse 4, Short(fld pos 12))

/// The memory an instruction reaches, where the number counted off the base
/// register is held in eight more bits above the twelve, and reads as signed.
let private memLong bse pos =
  MemField(None, fld bse 4, Long(fld pos 12, fld 32 8))

/// The same, with a general register added to the base one as well.
let private memIdxLong idx bse pos =
  MemField(Some(Gpr, fld idx 4), fld bse 4, Long(fld pos 12, fld 32 8))

/// The memory an instruction reaches, together with how many bytes of it the
/// instruction touches, whose field holds one less than that.
let private memLen pos width bse dsp =
  LenMemField(fld pos width, 1us, fld bse 4, Short(fld dsp 12))

/// An instruction working on nothing it names.
let noOperand: Slot list = []

let uImm8to15 = [ uimm 8 8 ]

let gr8to11 = [ gpr 8 ]

let gr8GR12 = [ gpr 8; gpr 12 ]

let mgr8GR12 = [ mask 8; gpr 12 ]

let fpr8FPR12 = [ fpr 8; fpr 12 ]

let gr8WIdx12M16D20 = [ gpr 8; memIdx 12 16 20 ]

let mask8WIdx12M16D20 = [ mask 8; memIdx 12 16 20 ]

let fpr8WIdx12M16D20 = [ fpr 8; memIdx 12 16 20 ]

let gr8SImmRUpperGR12 = [ gpr 8; rel 16 16; gpr 12 ]

let gr8WGR12M16D20 = [ gpr 8; gpr 12; mem 16 20 ]

let gr8WNoneM16D20 = [ gpr 8; mem 16 20 ]

let ar8WAR12M16D20 = [ apr 8; apr 12; mem 16 20 ]

let cr8WCR12M16D20 = [ cpr 8; cpr 12; mem 16 20 ]

let gr8WMask12M16D20 = [ gpr 8; mask 12; mem 16 20 ]

let noneM16D20 = [ mem 16 20 ]

let noneM16D20UImm8 = [ mem 16 20; uimm 8 8 ]

let uImm24UImm28 = [ uimm 24 4; uimm 28 4 ]

let fpr16FPR28FPR24 = [ fpr 16; fpr 28; fpr 24 ]

let gr24to27 = [ gpr 24 ]

let gr24GR28 = [ gpr 24; gpr 28 ]

let fpr24FPR28 = [ fpr 24; fpr 28 ]

let ar24GR28 = [ apr 24; gpr 28 ]

let ar24AR28 = [ apr 24; apr 28 ]

let gr24AR28 = [ gpr 24; apr 28 ]

let fpr24GR28 = [ fpr 24; gpr 28 ]

let gr24FPR28 = [ gpr 24; fpr 28 ]

let gr24GR28GR16Mask20 = [ gpr 24; gpr 28; gpr 16; mask 20 ]

let gr24GR28Mask16 = [ gpr 24; gpr 28; mask 16 ]

let fpr24FPR28Mask16Mask20 = [ fpr 24; fpr 28; mask 16; mask 20 ]

let fpr24FPR28Mask16 = [ fpr 24; fpr 28; mask 16 ]

let fpr24FPR28FPR16Mask20 = [ fpr 24; fpr 28; fpr 16; mask 20 ]

let fpr24FPR28FPR16 = [ fpr 24; fpr 28; fpr 16 ]

let fpr24GR28Mask16Mask20 = [ fpr 24; gpr 28; mask 16; mask 20 ]

let gr24FPR28Mask16 = [ gpr 24; fpr 28; mask 16 ]

let gr24FPR28Mask16Mask20 = [ gpr 24; fpr 28; mask 16; mask 20 ]

let fpr24FPR28Mask20 = [ fpr 24; fpr 28; mask 20 ]

let gr24FPR28Mask20 = [ gpr 24; fpr 28; mask 20 ]

let fpr24GR28FPR16 = [ fpr 24; gpr 28; fpr 16 ]

let fpr24GR28FPR16Mask20 = [ fpr 24; gpr 28; fpr 16; mask 20 ]

let gr24GR28GR16 = [ gpr 24; gpr 28; gpr 16 ]

let gr8HWImm = [ gpr 8; uimm 16 16 ]

let gr8HWImmM = [ gpr 8; maskWide 16 ]

let bit8MaskSImmRUpper = [ mask 8; rel 16 16 ]

let gr8SImmRUpper = [ gpr 8; rel 16 16 ]

let gr8SImmUpper = [ gpr 8; uimm 16 16 ]

let m16D20M32D36 = [ mem 16 20; mem 32 36 ]

let m16D20SImm32to47CQ = [ mem 16 20; uimm 32 16 ]

let m16D20UImm32to47Q = [ mem 16 20; uimm 32 16 ]

let mask8QSImmRQM32D36 = [ mask 8; rel 16 16; mem 32 36 ]

let mask8Imm12Imm24 = [ mask 8; uimm 12 12; uimm 24 24 ]

let grl8QM32D36 = [ memLen 8 8 16 20; mem 32 36 ]

let idx8M16D20M32D36GR12Q = [ memIdx 8 16 20; mem 32 36; gpr 12 ]

let m16D20GRL8Q = [ mem 16 20; memLen 8 8 32 36 ]

let gr8QM16D20GR12QM32D36 = [ gpr 8; mem 16 20; gpr 12; mem 32 36 ]

let grl8QM32D36UImm4 = [ memLen 8 4 16 20; mem 32 36; uimm 12 4 ]

let grl8QGRL12Q = [ memLen 8 4 16 20; memLen 12 4 32 36 ]

let m16D20M32D36GR8Q = [ mem 16 20; mem 32 36; gpr 8 ]

let gr8QSImm16to47RQ = [ gpr 8; rel 16 32 ]

let gr8QSImm16to47Q = [ gpr 8; uimm 16 32 ]

let mask8QSImm16to47RQ = [ mask 8; rel 16 32 ]

let gr8QUImm16to47CQ = [ gpr 8; uimm 16 32 ]

let gr8QSImmUpperQMask12Q = [ gpr 8; uimm 16 16; mask 12 ]

let gr8QSImmUpperRQGR12Q = [ gpr 8; rel 16 16; gpr 12 ]

let gr8QGR12QUImmUpper24to32Q =
  [ gpr 8; gpr 12; uimm 16 8; uimm 24 8; uimm 32 8 ]

let gr8QGR12QMask32SImmUpperRQ = [ gpr 8; gpr 12; mask 32; rel 16 16 ]

let gr8QSImmUpperQMask32Q = [ gpr 8; uimm 16 16; mask 32 ]

let gr8QUImmUpperQMask32Q = [ gpr 8; uimm 16 16; mask 32 ]

let gr8QSImm32BQMask12SImmUpperRQ = [ gpr 8; simm 32; mask 12; rel 16 16 ]

let gr8QUImm32CQMask12SImmUpperRQ = [ gpr 8; uimm 32 8; mask 12; rel 16 16 ]

let gr8QSImmUpperQGR12Q = [ gpr 8; uimm 16 16; gpr 12 ]

let gr8QSImm32BQMask12NBase16Disp20 = [ gpr 8; simm 32; mask 12; mem 16 20 ]

let gr8QUImm32CQMask12NBase16Disp20 = [ gpr 8; uimm 32 8; mask 12; mem 16 20 ]

let gr8QGR12QMask32NBase16Disp20 = [ gpr 8; gpr 12; mask 32; mem 16 20 ]

let grl8Q = [ memLen 8 4 16 20 ]

let fpr32QGRL8QMask36 = [ fpr 32; memLen 8 8 16 20; mask 36 ]

let gr8QM16D20GR12Q = [ gpr 8; memLong 16 20; gpr 12 ]

let gr8QM16D20Mask12Q = [ gpr 8; memLong 16 20; mask 12 ]

let cr8QM16D20CR12Q = [ cpr 8; memLong 16 20; cpr 12 ]

let ar8QM16D20AR12Q = [ apr 8; memLong 16 20; apr 12 ]

let gr8QIdx12M16D20Mask32Q = [ gpr 8; memIdx 12 16 20; mask 32 ]

let fpr8QIdx12M16D20 = [ fpr 8; memIdx 12 16 20 ]

let gr8QIdx12M16D20 = [ gpr 8; memIdxLong 12 16 20 ]

let mask8QIdx12M16D20 = [ mask 8; memIdxLong 12 16 20 ]

let fpr8QIdx12MemBase16DispL20 = [ fpr 8; memIdxLong 12 16 20 ]

let fpr32QIdx12M16D20FPR8Q = [ fpr 32; memIdx 12 16 20; fpr 8 ]

let m16D20LUImm8to15Q = [ memLong 16 20; uimm 8 8 ]

let m16D20LSImm8to15Q = [ memLong 16 20; simm 8 ]

let m16D20L = [ memLong 16 20 ]

let vr8QUImmUpperQUImm4 = [ vpr 8 36; uimm 16 16; uimm 32 4 ]

let vr8QGR12QUImm8Mask24 = [ vpr 8 36; gpr 12; uimm 28 8; mask 24 ]

let vr8QVR12QUImm8sMask24 =
  [ vpr 8 36; vpr 12 37; uimm 28 8; uimm 16 8; mask 24 ]

let vr8QVR12QVR16QUImm8Mask24 =
  [ vpr 8 36; vpr 12 37; vpr 16 38; uimm 28 8; mask 24 ]

let vr8QUImm16Mask32 = [ vpr 8 36; uimm 16 16; mask 32 ]

let vr8QUImm16 = [ vpr 8 36; uimm 16 16 ]

let vr8QUImm8sMask32 = [ vpr 8 36; uimm 16 8; uimm 24 8; mask 32 ]

let vr8QVR12QUImm12Mask32Mask28 =
  [ vpr 8 36; vpr 12 37; uimm 16 12; mask 32; mask 28 ]

let vr8QUImmUpperVR12QMask32 = [ vpr 8 36; uimm 16 16; vpr 12 37; mask 32 ]

let vr8QVR12QVR16QUImm8Mask32 =
  [ vpr 8 36; vpr 12 37; vpr 16 38; uimm 24 8; mask 32 ]

let vr8QVR12QVR16QUImm8 = [ vpr 8 36; vpr 12 37; vpr 16 38; uimm 24 8 ]

let gr8QVR12QMask24Mask28 = [ gpr 8; vpr 12 37; mask 24; mask 28 ]

let vr8QVR12QMask24 = [ vpr 8 36; vpr 12 37; mask 24 ]

let vr8QVR12QMask32Mask28 = [ vpr 8 36; vpr 12 37; mask 32; mask 28 ]

let vr12Q = [ vpr 12 37 ]

let vr8QVR12QVR16QMask32Mask24 =
  [ vpr 8 36; vpr 12 37; vpr 16 38; mask 32; mask 24 ]

let vr8QVR12QVR16QMask32Mask28 =
  [ vpr 8 36; vpr 12 37; vpr 16 38; mask 32; mask 28 ]

let vr12QVR16QMask24 = [ vpr 12 37; vpr 16 38; mask 24 ]

let vr8QVR12QVR16Q = [ vpr 8 36; vpr 12 37; vpr 16 38 ]

let vr8QVR12QVR16QMask24 = [ vpr 8 36; vpr 12 37; vpr 16 38; mask 24 ]

let vr8QVR12QMask32 = [ vpr 8 36; vpr 12 37; mask 32 ]

let vr8QVR12Q = [ vpr 8 36; vpr 12 37 ]

let vr8QVR12QMask32Mask24 = [ vpr 8 36; vpr 12 37; mask 32; mask 24 ]

let vr8QVR12QVR16QMask32 = [ vpr 8 36; vpr 12 37; vpr 16 38; mask 32 ]

let vr8QGR12QGR16Q = [ vpr 8 36; gpr 12; gpr 16 ]

let vr8QVR12QVR16QVR32QMask20Mask24 =
  [ vpr 8 36; vpr 12 37; vpr 16 38; vpr 32 39; mask 20; mask 24 ]

let vr8QVR12QVR16QVR32Q = [ vpr 8 36; vpr 12 37; vpr 16 38; vpr 32 39 ]

let vr8QVR12QVR16QVR32QMask28Mask20 =
  [ vpr 8 36; vpr 12 37; vpr 16 38; vpr 32 39; mask 28; mask 20 ]

let vr8QVR12QVR16QVR32QMask20 =
  [ vpr 8 36; vpr 12 37; vpr 16 38; vpr 32 39; mask 20 ]

let vr8QVR12QMask32Mask28Mask24 =
  [ vpr 8 36; vpr 12 37; mask 32; mask 28; mask 24 ]

let vr8QVR12QVR16QMask32Mask28Mask24 =
  [ vpr 8 36; vpr 12 37; vpr 16 38; mask 32; mask 28; mask 24 ]

let vr32QM16D20GR12Q = [ vpr 32 39; mem 16 20; gpr 12 ]

let gr8QM16D20VR12QMask32 = [ gpr 8; mem 16 20; vpr 12 37; mask 32 ]

let vr8QM16D20GR12QMask32 = [ vpr 8 36; mem 16 20; gpr 12; mask 32 ]

let vr8QM16D20VR12QMask32 = [ vpr 8 36; mem 16 20; vpr 12 37; mask 32 ]

let vr8QM16D20GR12Q = [ vpr 8 36; mem 16 20; gpr 12 ]

let vr8QVIdxM16D20Mask32 = [ vpr 8 36; memVecIdx 12 16 20; mask 32 ]

let vr8QIdxM16D20Mask32 = [ vpr 8 36; memIdx 12 16 20; mask 32 ]

let vr32QM16D20UImm8 = [ vpr 32 39; mem 16 20; uimm 8 8 ]

// vim: set tw=80 sts=2 sw=2:
