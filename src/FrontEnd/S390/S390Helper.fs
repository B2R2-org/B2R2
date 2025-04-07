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

/// extracting bit values located in between the given two offsets from uint16
let extract16 (bin: uint16) (ofs1: int) (ofs2: int) =
  let m, n = if max ofs1 ofs2 = ofs1 then ofs1, ofs2 else ofs2, ofs1
  let range = m - n + 1

  if range > 16 then invalidOp "Invalid range of offsets given."
  let mutable res = 0us
  for i in n..m do
    res <- (res <<< 1) ||| (bin >>> (15 - i) &&& 0b1us)
  res

/// extracting bit values located in between the given two offsets from uint32
let extract32 (bin: uint32) ofs1 ofs2 =
  let m, n = if max ofs1 ofs2 = ofs1 then ofs1, ofs2 else ofs2, ofs1
  let range = m - n + 1

  if range > 32 then invalidOp "Invalid range of offsets given."
  let mutable res = 0u
  for i in n..m do
    res <- (res <<< 1) ||| (bin >>> (31 - i) &&& 0b1u)
  res

/// extracting bit values located in between the given two offsets from uint64
let extract48 (bin: uint64) ofs1 ofs2 =
  let m, n = if max ofs1 ofs2 = ofs1 then ofs1, ofs2 else ofs2, ofs1
  let range = m - n + 1

  if range > 48 then invalidOp "Invalid range of offsets given."
  let mutable res = 0UL
  for i in n..m do
    res <- (res <<< 1) ||| (bin >>> (47 - i) &&& 0b1UL)
  res

/// extracting bit values located in between the given two offsets from uint64
let extract64 (bin: uint64) ofs1 ofs2 =
  let m, n = if max ofs1 ofs2 = ofs1 then ofs1, ofs2 else ofs2, ofs1
  let range = m - n + 1

  if range > 64 then invalidOp "Invalid range of offsets given."
  let mutable res = 0UL
  for i in n..m do
    res <- (res <<< 1) ||| (bin >>> (63 - i) &&& 0b1UL)
  res

let extract128 (bin: UInt128) ofs1 ofs2 =
  let m, n = if max ofs1 ofs2 = ofs1 then ofs1, ofs2 else ofs2, ofs1
  let range = m - n + 1

  if range > 128 then invalidOp "Invalid range of offsets given."
  let mutable res = UInt128.Zero
  for i in n..m do
        res <- (res <<< 1) ||| (bin >>> (127 - i) &&& UInt128.One)
  res

/// construct long-displacement from DH, DL field
let getLongDisp (disph: int8) (displ: uint16) =
  ((disph |> int32) <<< 12) ||| ((displ |> uint32) |> int32)

let private extractMask (opr: Operand)=
  match opr with
  | OpMask op -> Some op
  | _ -> None

let getMaskVal (opr: Operands) =
  match opr with
  | NoOperand -> None
  | OneOperand op1 -> extractMask op1
  | TwoOperands (op1, op2) ->
      extractMask op1 |> Option.orElse (extractMask op2)
  | ThreeOperands (op1, op2, op3) ->
      [| op1; op2; op3 |] |> Array.tryPick extractMask
  | FourOperands (op1, op2, op3, op4) ->
      [| op1; op2; op3; op4 |] |> Array.tryPick extractMask
  | FiveOperands (op1, op2, op3, op4, op5) ->
      [| op1; op2; op3; op4; op5 |] |> Array.tryPick extractMask
  | SixOperands (op1, op2, op3, op4, op5, op6) ->
    [| op1; op2; op3; op4; op5; op6 |] |> Array.tryPick extractMask

let matchTransModeBit = function
  | 0b00us -> TranslationMode.PrimarySpaceMode
  | 0b01us -> TranslationMode.AccessRegisterMode
  | 0b10us -> TranslationMode.SecondarySpaceMode
  | 0b11us -> TranslationMode.HomeSpaceMode
  | _ -> TranslationMode.RealMode

/// getting Address Translation Mode from Program-Status Word.
let getTransMode (psw: obj) =
  let mutable dataModeBit = 0us
  let mutable transModeBit = 0us
  let mutable transMode = TranslationMode.RealMode

  match psw with
  | :? UInt128 as p ->
    dataModeBit <- extract128 p 5 5 |> uint16
    if (dataModeBit &&& 0b1us) = 0b1us then
      transModeBit <- extract128 p 16 17 |> uint16
      transMode <- matchTransModeBit transModeBit
  | :? uint64 as p ->
    dataModeBit <- extract64 p 5 5 |> uint16
    if (dataModeBit &&& 0b1us) = 0b1us then
      transModeBit <- extract64 p 16 17 |> uint16
      transMode <- matchTransModeBit transModeBit
  | _ -> Terminator.impossible ()
  transMode

/// check PSW if the condition for BP characteristic is set.
/// BP B2 field designates an access register when PSW bits 16
/// and 17 have the value 01 binary.
let checkBP (psw: obj) =
  let mutable value = 0us
  match psw with
  | :? UInt128 as p ->
    value <- extract128 p 16 17 |> uint16
  | :? uint64 as p ->
    value <- extract64 p 16 17 |> uint16
  | _ -> Terminator.impossible ()

  match value with
  | 0b01us -> true
  | _ -> false

/// sign extend 12-bit int into int32
let sext12 (bin: uint32) =
  if bin &&& 0x800u <> 0u then (bin ||| 0xFFFFF000u) |> int32
  else bin |> int32

/// return proper argument based on translation mode.
let inline modeSelect (mode: TranslationMode) generalOpr accessOpr=
  match mode with
  | TranslationMode.AccessRegisterMode -> accessOpr
  | _ -> generalOpr

let inline modeSelectBP (mode: ASC) generalOpr bpOpr =
  match mode with
  | ASC.BPEnabled -> bpOpr
  | _ -> generalOpr

/// getting the general register operand from the binary
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

/// getting the floating point register operand from the binary
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

/// getting the vector register operand from the binary
let getVR (rxb: uint16) (bin: uint16) (pos: uint16) =
  // pos = 1 (VR at bit 8-11), 2 (VR at bit 12-15), ... 4
  let reg = bin ||| ((rxb <<< (uint32 pos |> int32)) &&& 0b10000us)

  match reg with
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

/// getting the floating point control register operand from the binary
let getFPC (bin: uint16) =
  match bin with
  | 0us -> Register.FPC
  | _ -> raise InvalidOperandException

/// getting the control register operand from the binary
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

/// getting the access register operand from the binary
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
