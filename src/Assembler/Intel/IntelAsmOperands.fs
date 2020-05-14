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

let regTo3Bit = function
  | Register.AL | Register.AX | Register.EAX | Register.RAX | Register.BND0
  | Register.MM0 | Register.XMM0 | Register.YMM0 | Register.ES
  | Register.R8L | Register.R8W | Register.R8D | Register.R8
  | Register.XMM8 | Register.YMM8 | Register.ST0 -> 0b000uy
  | Register.CL | Register.CX | Register.ECX | Register.RCX | Register.BND1
  | Register.MM1 | Register.XMM1 | Register.YMM1 | Register.CS
  | Register.R9L | Register.R9W | Register.R9D | Register.R9
  | Register.XMM9 | Register.YMM9 | Register.ST1 -> 0b001uy
  | Register.DL | Register.DX | Register.EDX | Register.RDX | Register.BND2
  | Register.MM2 | Register.XMM2 | Register.YMM2 | Register.SS
  | Register.R10L | Register.R10W | Register.R10D | Register.R10
  | Register.XMM10 | Register.YMM10 | Register.ST2 -> 0b010uy
  | Register.BL | Register.BX | Register.EBX | Register.RBX | Register.BND3
  | Register.MM3 | Register.XMM3 | Register.YMM3 | Register.DS
  | Register.R11L | Register.R11W | Register.R11D | Register.R11
  | Register.XMM11 | Register.YMM11 | Register.ST3 -> 0b011uy
  | Register.AH | Register.SP | Register.ESP | Register.RSP
  | Register.MM4 | Register.XMM4 | Register.YMM4 | Register.FS
  | Register.SPL | Register.R12L | Register.R12W | Register.R12D | Register.R12
  | Register.XMM12 | Register.YMM12 | Register.ST4 -> 0b100uy
  | Register.CH | Register.BP | Register.EBP | Register.RBP
  | Register.MM5 | Register.XMM5 | Register.YMM5 | Register.GS
  | Register.BPL | Register.R13L | Register.R13W | Register.R13D | Register.R13
  | Register.XMM13 | Register.YMM13 | Register.ST5 | Register.RIP -> 0b101uy
  | Register.DH | Register.SI | Register.ESI | Register.RSI
  | Register.MM6 | Register.XMM6 | Register.YMM6
  | Register.SIL | Register.R14L | Register.R14W | Register.R14D | Register.R14
  | Register.XMM14 | Register.YMM14 | Register.ST6 -> 0b110uy
  | Register.BH | Register.DI | Register.EDI | Register.RDI
  | Register.MM7 | Register.XMM7 | Register.YMM7
  | Register.DIL | Register.R15L | Register.R15W | Register.R15D | Register.R15
  | Register.XMM15 | Register.YMM15 | Register.ST7 -> 0b111uy
  | _ -> Utils.impossible ()

let private getModRMByte md reg rm =
  (md <<< 6) + (reg <<< 3) + rm |> Normal

let private getRMBySIB baseReg si =
  match si, baseReg with
  | Some _, _ -> 0b100uy
  | None, Some baseReg -> regTo3Bit baseReg
  | None, None -> 0b101uy

let private isDisp8 disp = 0xFFFFFFFFFFFFFF80L <= disp && disp <= 0x7FL

let private getMod baseReg = function
  | None -> 0b00uy
  | Some disp ->
    match baseReg with
    | Some (Register.RIP) | None -> 0b00uy
    | _ -> if isDisp8 disp then 0b01uy else 0b10uy

let modrmRR reg1 reg2 =
  getModRMByte 0b11uy (regTo3Bit reg1) (regTo3Bit reg2)

let modrmMR baseReg si disp reg =
  getModRMByte (getMod baseReg disp) (regTo3Bit reg) (getRMBySIB baseReg si)

let modrmRM reg baseReg si disp =
  getModRMByte (getMod baseReg disp) (regTo3Bit reg) (getRMBySIB baseReg si)

let modrmRL reg =
  getModRMByte 0b00uy (regTo3Bit reg) 0b101uy

let modrmLI regConstr =
  getModRMByte 0b00uy regConstr 0b101uy

let modrmRI reg regConstr =
  getModRMByte 0b11uy regConstr (regTo3Bit reg)

let modrmMI baseReg si disp regConstr =
  getModRMByte (getMod baseReg disp) regConstr (getRMBySIB baseReg si)

let modrmRC reg regConstr =
  getModRMByte 0b11uy regConstr (regTo3Bit reg)

let modrmMC baseReg si disp regConstr =
  getModRMByte (getMod baseReg disp) regConstr (getRMBySIB baseReg si)

let modrmM baseReg si disp regConstr =
  getModRMByte (getMod baseReg disp) regConstr (getRMBySIB baseReg si)

let modrmR reg regConstr =
  getModRMByte 0b11uy regConstr (regTo3Bit reg)

let private getScaleBit = function
  | Scale.X1 -> 0b00uy
  | Scale.X2 -> 0b01uy
  | Scale.X4 -> 0b10uy
  | _ (* Scale.X8 *) -> 0b11uy

let private encSIB sBit idxBit baseBit =
  (sBit <<< 6) + (idxBit <<< 3) + baseBit |> Normal

let modrmRel (rel: int64) = function // FIXME
  | 8<rt> -> [| Normal <| byte rel |]
  | 16<rt> -> BitConverter.GetBytes (int16 rel) |> Array.map Normal
  | 32<rt> -> BitConverter.GetBytes (int32 rel) |> Array.map Normal
  | _ -> Utils.impossible ()

let private encDisp disp = function
  | 8<rt> -> [| byte disp |> Normal |]
  | 32<rt> -> BitConverter.GetBytes (int32 disp) |> Array.map Normal
  | _ -> failwith "Invalid displacement"

let private getDispSz disp = if isDisp8 disp then 8<rt> else 32<rt>

let private isRegFld4 = function
  | Register.RSP | Register.ESP | Register.SP | Register.AH
  | Register.R12 | Register.R12D | Register.R12W | Register.R12L | Register.SPL
    -> true
  | _ -> false

/// SIB and Displacement.
let mem b si d =
  match b, si, d with
  | Some b, None, None -> if isRegFld4 b then [| Normal 0x24uy |] else [||]
  | Some b, Some (i, s), None ->
    [| yield encSIB (getScaleBit s) (regTo3Bit i) (regTo3Bit b) |]
  | Some b, Some (i, s), Some d ->
    [| yield encSIB (getScaleBit s) (regTo3Bit i) (regTo3Bit b)
       yield! encDisp d (getDispSz d) |]
  | None, Some (i, s), None -> (* Vol.2A 2-7 NOTES *)
    [| yield encSIB (getScaleBit s) (regTo3Bit i) 0b101uy
       yield! encDisp 0L 32<rt> |]
  | None, Some (i, s), Some d ->
    [| yield encSIB (getScaleBit s) (regTo3Bit i) 0b101uy
       yield! encDisp d 32<rt> |]
  | None, None, Some d -> [| yield! encDisp d 32<rt> |]
  | Some b, None, Some d ->
    [| yield! if isRegFld4 b then [| Normal 0x24uy |] else [||]
       yield! encDisp d (getDispSz d) |]
  | _ -> [||]

let immediate (imm: int64) = function
  | 8<rt> -> [| Normal <| byte imm |]
  | 16<rt> -> BitConverter.GetBytes (int16 imm) |> Array.map Normal
  | 32<rt> -> BitConverter.GetBytes (int32 imm) |> Array.map Normal
  | 64<rt> -> BitConverter.GetBytes (imm) |> Array.map Normal
  | _ -> Utils.impossible ()

// vim: set tw=80 sts=2 sw=2:
