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

module internal B2R2.FrontEnd.BinLifter.MIPS.Helper

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.MIPS.Utils

let isRel2 arch = arch = Arch.MIPS32R2 || arch = Arch.MIPS64R2
let isRel6 arch = arch = Arch.MIPS32R6 || arch = Arch.MIPS64R6
let isMIPS32 arch = arch = Arch.MIPS32R2 || arch = Arch.MIPS32R6
let isMIPS64 arch = arch = Arch.MIPS64R2 || arch = Arch.MIPS64R6
let isMIPS32R2 arch = arch = Arch.MIPS32R2
let isMIPS64R2 arch = arch = Arch.MIPS64R2
let isMIPS32R6 arch = arch = Arch.MIPS32R6
let isMIPS64R6 arch = arch = Arch.MIPS64R6

let getRegister = function
  | 0x0uy -> R.R0
  | 0x1uy -> R.R1
  | 0x2uy -> R.R2
  | 0x3uy -> R.R3
  | 0x4uy -> R.R4
  | 0x5uy -> R.R5
  | 0x6uy -> R.R6
  | 0x7uy -> R.R7
  | 0x8uy -> R.R8
  | 0x9uy -> R.R9
  | 0xAuy -> R.R10
  | 0xBuy -> R.R11
  | 0xCuy -> R.R12
  | 0xDuy -> R.R13
  | 0xEuy -> R.R14
  | 0xFuy -> R.R15
  | 0x10uy -> R.R16
  | 0x11uy -> R.R17
  | 0x12uy -> R.R18
  | 0x13uy -> R.R19
  | 0x14uy -> R.R20
  | 0x15uy -> R.R21
  | 0x16uy -> R.R22
  | 0x17uy -> R.R23
  | 0x18uy -> R.R24
  | 0x19uy -> R.R25
  | 0x1Auy -> R.R26
  | 0x1Buy -> R.R27
  | 0x1Cuy -> R.R28
  | 0x1Duy -> R.R29
  | 0x1Euy -> R.R30
  | 0x1Fuy -> R.R31
  | _ -> raise InvalidRegisterException

let getFRegister = function
  | 0x0uy -> R.F0
  | 0x1uy -> R.F1
  | 0x2uy -> R.F2
  | 0x3uy -> R.F3
  | 0x4uy -> R.F4
  | 0x5uy -> R.F5
  | 0x6uy -> R.F6
  | 0x7uy -> R.F7
  | 0x8uy -> R.F8
  | 0x9uy -> R.F9
  | 0xAuy -> R.F10
  | 0xBuy -> R.F11
  | 0xCuy -> R.F12
  | 0xDuy -> R.F13
  | 0xEuy -> R.F14
  | 0xFuy -> R.F15
  | 0x10uy -> R.F16
  | 0x11uy -> R.F17
  | 0x12uy -> R.F18
  | 0x13uy -> R.F19
  | 0x14uy -> R.F20
  | 0x15uy -> R.F21
  | 0x16uy -> R.F22
  | 0x17uy -> R.F23
  | 0x18uy -> R.F24
  | 0x19uy -> R.F25
  | 0x1Auy -> R.F26
  | 0x1Buy -> R.F27
  | 0x1Cuy -> R.F28
  | 0x1Duy -> R.F29
  | 0x1Euy -> R.F30
  | 0x1Fuy -> R.F31
  | _ -> raise InvalidRegisterException

let getCondition = function
  | 0x0u -> Condition.F
  | 0x1u -> Condition.UN
  | 0x2u -> Condition.EQ
  | 0x3u -> Condition.UEQ
  | 0x4u -> Condition.OLT
  | 0x5u -> Condition.ULT
  | 0x6u -> Condition.OLE
  | 0x7u -> Condition.ULE
  | 0x8u -> Condition.SF
  | 0x9u -> Condition.NGLE
  | 0xAu -> Condition.SEQ
  | 0xBu -> Condition.NGL
  | 0xCu -> Condition.LT
  | 0xDu -> Condition.NGE
  | 0xEu -> Condition.LE
  | 0xFu -> Condition.NGT
  | _ -> raise InvalidConditionException

let gprLen = function
  | Arch.MIPS32R2 | Arch.MIPS32R6 -> 32
  | Arch.MIPS64R2 | Arch.MIPS64R6 -> 64
  | _ -> failwith "Not Implemented."

let num9 b = extract b 15u 7u
let num16 b = extract b 15u 0u
let num26 b = extract b 25u 0u
let getRegFrom2521 b = getRegister (extract b 25u 21u |> byte)
let getRegFrom2016 b = getRegister (extract b 20u 16u |> byte)
let getRegFrom1511 b = getRegister (extract b 15u 11u |> byte)
let getFRegFrom2521 b = getFRegister (extract b 25u 21u |> byte)
let getFRegFrom2016 b = getFRegister (extract b 20u 16u |> byte)
let getFRegFrom2018 b = getFRegister (extract b 20u 18u |> byte)
let getFRegFrom1511 b = getFRegister (extract b 15u 11u |> byte)
let getFRegFrom106 b = getFRegister (extract b 10u 6u |> byte)
let getFRegFrom108 b = getFRegister (extract b 10u 8u |> byte)

let rs b = getRegFrom2521 b |> OpReg
let rt b = getRegFrom2016 b |> OpReg
let rd b = getRegFrom1511 b |> OpReg

let fs b = getFRegFrom1511 b |> OpReg
let ft b = getFRegFrom2016 b |> OpReg
let fd b = getFRegFrom106 b |> OpReg
let fr b = getFRegFrom2521 b |> OpReg
let cc10 b = getFRegFrom108 b |> OpReg // FIXME: Floating Point cond code CC.
let cc20 b = getFRegFrom2018 b |> OpReg // FIXME: Floating Point cond code CC.

let sa b = extract b 10u 6u |> uint64 |> OpShiftAmount
let bp b = extract b 7u 6u |> uint64 |> OpImm

let hint b = extract b 20u 16u |> uint64 |> OpImm (* FIMXE: hint on page 420 *)
let sel b = extract b 8u 6u |> uint64 |> OpImm (* FIXME: sel on page 432 *)

let rel16 b =
  let off = num16 b |> uint64 <<< 2 |> signExtend 18 64 |> int64
  off + 4L |> Relative |> OpAddr
let region b =
  num26 b <<< 2 |> uint64 |> OpImm (* FIXME: PC-region on page 268 *)
let stype b =
  extract b 10u 6u |> uint64 |> OpImm (* FIXME: SType Field on page 533 *)
let imm16 b = num16 b |> uint64 |> OpImm
let imm16SignExt b = num16 b |> uint64 |> signExtend 16 64 |> OpImm
let memBaseOff b num accLength =
  let offset = num b |> uint64 |> signExtend 16 64 |> int64
  OpMem (getRegFrom2521 b, Imm offset, accLength)
let memBaseIdx b accLength =
  OpMem (getRegFrom2521 b, Reg (getRegFrom2016 b), accLength)

let posSize b =
  let msb = extract b 15u 11u
  let lsb = extract b 10u 6u
  lsb |> uint64 |> OpImm, msb + 1u - lsb |> uint64 |> OpImm
let posSize2 b =
  let msbd = extract b 15u 11u
  let lsb = extract b 10u 6u
  lsb |> uint64 |> OpImm, msbd + 1u |> uint64 |> OpImm
let posSize3 b =
  let msbminus32 = extract b 15u 11u
  let lsb = extract b 10u 6u
  lsb |> uint64 |> OpImm, msbminus32 + 33u - lsb |> uint64 |> OpImm
let posSize4 b =
  let msbminus32 = extract b 15u 11u
  let lsbminus32 = extract b 10u 6u
  let pos = lsbminus32 + 32u
  pos |> uint64 |> OpImm, msbminus32 + 33u - pos |> uint64 |> OpImm
let posSize5 b =
  let msbdminus32 = extract b 15u 11u
  let lsb = extract b 10u 6u
  lsb |> uint64 |> OpImm, msbdminus32 + 33u |> uint64 |> OpImm
let posSize6 b =
  let msbd = extract b 15u 11u
  let lsbminus32 = extract b 10u 6u
  lsbminus32 + 32u |> uint64 |> OpImm, msbd + 1u |> uint64 |> OpImm

let getRel16 b = OneOperand (rel16 b)
let getRs b = OneOperand (rs b)
let getRd b = OneOperand (rd b)
let getTarget b = OneOperand (region b)
let getStype b = OneOperand (stype b)
let getRdRs b = TwoOperands (rd b, rs b)
let getRdRtRs b = ThreeOperands (rd b, rt b, rs b)
let getRdRsRt b = ThreeOperands (rd b, rs b, rt b)
let getRsRt b = TwoOperands (rs b, rt b)
let getRdRt b = TwoOperands (rd b, rt b)
let getRtRdSel b = ThreeOperands (rt b, rd b, sel b)
let getRsRtRel16 b = ThreeOperands (rs b, rt b, rel16 b)
let getRsRel16 b = TwoOperands (rs b, rel16 b)
let getRtImm16 b = TwoOperands (rt b, imm16 b)
let getRtRsImm16s b = ThreeOperands (rt b, rs b, imm16SignExt b)
let getRtRsImm16 b = ThreeOperands (rt b, rs b, imm16 b)
let getRtMemBaseOff b accLen = TwoOperands (rt b, memBaseOff b num16 accLen)
let getRtMemBaseOff9 b accLen = TwoOperands (rt b, memBaseOff b num9 accLen)
let getFtMemBaseOff b accLen = TwoOperands (ft b, memBaseOff b num16 accLen)
let getHintMemBaseOff b accLen = TwoOperands (hint b, memBaseOff b num16 accLen)
let getHintMemBaseOff9 b accLen = TwoOperands (hint b, memBaseOff b num9 accLen)
let getFdMemBaseIdx b accLen = TwoOperands (fd b, memBaseIdx b accLen)
let getFsMemBaseIdx b accLen = TwoOperands (fs b, memBaseIdx b accLen)
let getHintMemBaseIdx b accLen = TwoOperands (hint b, memBaseIdx b accLen)
let getRdRtSa b = ThreeOperands (rd b, rt b, sa b)
let getRdRsCc b = ThreeOperands (rd b, rs b, cc20 b)
let getRdRsRtBp b = FourOperands (rd b, rs b, rt b, bp b)
let getRtRsPosSize b = let p, s = posSize b in FourOperands (rt b, rs b, p, s)
let getRtRsPosSize2 b = let p, s = posSize2 b in FourOperands (rt b, rs b, p, s)
let getRtRsPosSize3 b = let p, s = posSize3 b in FourOperands (rt b, rs b, p, s)
let getRtRsPosSize4 b = let p, s = posSize4 b in FourOperands (rt b, rs b, p, s)
let getRtRsPosSize5 b = let p, s = posSize5 b in FourOperands (rt b, rs b, p, s)
let getRtRsPosSize6 b = let p, s = posSize6 b in FourOperands (rt b, rs b, p, s)
let getRtFs b = TwoOperands (rt b, fs b)
let getCcOff b =
  match extract b 20u 18u with
  | 0u -> OneOperand (rel16 b)
  | a -> TwoOperands (a |> uint64 |> OpImm, rel16 b)
let getFsFt b = TwoOperands (fs b, ft b)
let getFdFs b = TwoOperands (fd b, fs b)
let getFdFsRt b = ThreeOperands (fd b, fs b, rt b)
let getFdFsCc b = ThreeOperands (fd b, fs b, cc20 b)
let getCcFsFt b = ThreeOperands (cc10 b, fs b, ft b)
let getFdFsFt b = ThreeOperands (fd b, fs b, ft b)
let getFdFrFsFt b = FourOperands (fd b, fr b, fs b, ft b)

// vim: set tw=80 sts=2 sw=2:
