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

module internal B2R2.Assembler.Intel.AsmOperands

open System
open B2R2
open B2R2.FrontEnd.Intel

let private regTo3Bit = function
  | Register.AL | Register.AX | Register.EAX | Register.RAX | Register.BND0
  | Register.MM0 | Register.XMM0 | Register.YMM0 | Register.ES
  | Register.R8L | Register.R8W | Register.R8D | Register.R8
  | Register.XMM8 | Register.YMM8 -> 0b000uy
  | Register.CL | Register.CX | Register.ECX | Register.RCX | Register.BND1
  | Register.MM1 | Register.XMM1 | Register.YMM1 | Register.CS
  | Register.R9L | Register.R9W | Register.R9D | Register.R9
  | Register.XMM9 | Register.YMM9 -> 0b001uy
  | Register.DL | Register.DX | Register.EDX | Register.RDX | Register.BND2
  | Register.MM2 | Register.XMM2 | Register.YMM2 | Register.SS
  | Register.R10L | Register.R10W | Register.R10D | Register.R10
  | Register.XMM10 | Register.YMM10 -> 0b010uy
  | Register.BL | Register.BX | Register.EBX | Register.RBX | Register.BND3
  | Register.MM3 | Register.XMM3 | Register.YMM3 | Register.DS
  | Register.R11L | Register.R11W | Register.R11D | Register.R11
  | Register.XMM11 | Register.YMM11 -> 0b011uy
  | Register.AH | Register.SP | Register.ESP | Register.RSP
  | Register.MM4 | Register.XMM4 | Register.YMM4 | Register.FS
  | Register.SPL | Register.R12L | Register.R12W | Register.R12D | Register.R12
  | Register.XMM12 | Register.YMM12 -> 0b100uy
  | Register.CH | Register.BP | Register.EBP | Register.RBP
  | Register.MM5 | Register.XMM5 | Register.YMM5 | Register.GS
  | Register.BPL | Register.R13L | Register.R13W | Register.R13D | Register.R13
  | Register.XMM13 | Register.YMM13  -> 0b101uy
  | Register.DH | Register.SI | Register.ESI | Register.RSI
  | Register.MM6 | Register.XMM6 | Register.YMM6
  | Register.SIL | Register.R14L | Register.R14W | Register.R14D | Register.R14
  | Register.XMM14 | Register.YMM14  -> 0b110uy
  | Register.BH | Register.DI | Register.EDI | Register.RDI
  | Register.MM7 | Register.XMM7 | Register.YMM7
  | Register.DIL | Register.R15L | Register.R15W | Register.R15D | Register.R15
  | Register.XMM15 | Register.YMM15 -> 0b111uy
  | _ -> Utils.impossible ()

let getModRMByte md reg rm = (md <<< 6) + (reg <<< 3) + rm |> Normal

let private getRMBySIB baseReg = function
  | Some _ -> 0b100uy
  | None ->
    match baseReg with
    | Some baseReg -> regTo3Bit baseReg
    | None -> 0b101uy

let encodeRR reg1 reg2 =
  getModRMByte 0b11uy (regTo3Bit reg1) (regTo3Bit reg2)

let private getMod = function
  | None -> 0b00uy
  | Some disp -> if disp > 0xffL then 0b10uy else 0b01uy

let encodeMR baseReg sib disp reg =
  getModRMByte (getMod disp) (regTo3Bit reg) (getRMBySIB baseReg sib)

let encodeRM baseReg sib disp reg =
  getModRMByte (getMod disp) (regTo3Bit reg) (getRMBySIB baseReg sib)

let encodeRI reg regConstr =
  getModRMByte 0b11uy regConstr (regTo3Bit reg)

let encodeRIWithoutModRM reg baseHex = baseHex + (regTo3Bit reg) |> Normal

let encodeMI baseReg sib disp regConstr =
  getModRMByte (getMod disp) regConstr (getRMBySIB baseReg sib)

let encodeM baseReg disp sib regConstr =
  getModRMByte (getMod disp) regConstr (getRMBySIB baseReg sib)

let encodeR reg regConstr =
  getModRMByte 0b11uy regConstr (regTo3Bit reg)

let encodeRRR r1 r2 =
  getModRMByte 0b11uy (regTo3Bit r1) (regTo3Bit r2)

let encodeRRM r1 baseReg sib disp =
  getModRMByte (getMod disp) (regTo3Bit r1) (getRMBySIB baseReg sib)

let encodeRRIWithConstr reg regConstr =
  getModRMByte 0b11uy regConstr (regTo3Bit reg)

let encodeRRI reg1 reg2 =
  getModRMByte 0b11uy (regTo3Bit reg1) (regTo3Bit reg2)

let encodeRMI baseReg disp reg sib =
  getModRMByte (getMod disp) (regTo3Bit reg) (getRMBySIB baseReg sib)

let encodeMRI baseReg disp reg sib =
  getModRMByte (getMod disp) (regTo3Bit reg) (getRMBySIB baseReg sib)

let encodeRRRI r1 r2 r3 =
  getModRMByte 0b11uy (regTo3Bit r1) (regTo3Bit r3)

let encodeRRMI baseReg disp reg2 sib =
  getModRMByte (getMod disp) (regTo3Bit reg2) (getRMBySIB baseReg sib)

let private getScaleBit = function
  | Scale.X1 -> 0b00uy
  | Scale.X2 -> 0b01uy
  | Scale.X4 -> 0b10uy
  | _ (* Scale.X8 *) -> 0b11uy

let private encodeScaledIdx baseReg (reg, scale) =
  let idxBit, sBit = regTo3Bit reg, getScaleBit scale
  let baseBit =
    match baseReg with
    | Some baseReg -> regTo3Bit baseReg
    | None -> 0b101uy
  (sBit <<< 6) + (idxBit <<< 3) + baseBit |> Normal

/// Scale(2):Index(3):Base(3)
let encodeSIB baseReg si =
  match si with
  | Some si -> [| encodeScaledIdx baseReg si |]
  | _ -> [||]

let private adjustDisp = function
  | None -> [||]
  | Some disp ->
    if disp > 0xffL then BitConverter.GetBytes (int32 disp) |> Array.map Normal
    else [| Normal <| byte disp |]

let encodeDisp ins disp =
  match ins.Operands with
  | OneOperand (GoToLabel _lbl) -> [| Label; Label; Label; Label |] // FIXME
  | _ -> adjustDisp disp

let encodeImm (imm: int64) = function
  | 8<rt> -> [| Normal <| byte imm |]
  | 16<rt> -> BitConverter.GetBytes (int16 imm) |> Array.map Normal
  | 32<rt> -> BitConverter.GetBytes (int32 imm) |> Array.map Normal
  | 64<rt> -> BitConverter.GetBytes (imm) |> Array.map Normal
  | _ -> Utils.impossible ()

// vim: set tw=80 sts=2 sw=2:
