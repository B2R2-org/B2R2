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

module internal B2R2.Peripheral.Assembly.Intel.AsmOperands

open System
open B2R2
open B2R2.FrontEnd.Register
open B2R2.FrontEnd.BinLifter.Intel

let regTo3Bit = function
  | Intel.AL | Intel.AX | Intel.EAX | Intel.RAX | Intel.BND0
  | Intel.MM0 | Intel.XMM0 | Intel.YMM0 | Intel.ES
  | Intel.R8B | Intel.R8W | Intel.R8D | Intel.R8
  | Intel.XMM8 | Intel.YMM8 | Intel.ST0 -> 0b000uy
  | Intel.CL | Intel.CX | Intel.ECX | Intel.RCX | Intel.BND1
  | Intel.MM1 | Intel.XMM1 | Intel.YMM1 | Intel.CS
  | Intel.R9B | Intel.R9W | Intel.R9D | Intel.R9
  | Intel.XMM9 | Intel.YMM9 | Intel.ST1 -> 0b001uy
  | Intel.DL | Intel.DX | Intel.EDX | Intel.RDX | Intel.BND2
  | Intel.MM2 | Intel.XMM2 | Intel.YMM2 | Intel.SS
  | Intel.R10B | Intel.R10W | Intel.R10D | Intel.R10
  | Intel.XMM10 | Intel.YMM10 | Intel.ST2 -> 0b010uy
  | Intel.BL | Intel.BX | Intel.EBX | Intel.RBX | Intel.BND3
  | Intel.MM3 | Intel.XMM3 | Intel.YMM3 | Intel.DS
  | Intel.R11B | Intel.R11W | Intel.R11D | Intel.R11
  | Intel.XMM11 | Intel.YMM11 | Intel.ST3 -> 0b011uy
  | Intel.AH | Intel.SP | Intel.ESP | Intel.RSP
  | Intel.MM4 | Intel.XMM4 | Intel.YMM4 | Intel.FS
  | Intel.SPL | Intel.R12B | Intel.R12W | Intel.R12D | Intel.R12
  | Intel.XMM12 | Intel.YMM12 | Intel.ST4 -> 0b100uy
  | Intel.CH | Intel.BP | Intel.EBP | Intel.RBP
  | Intel.MM5 | Intel.XMM5 | Intel.YMM5 | Intel.GS
  | Intel.BPL | Intel.R13B | Intel.R13W | Intel.R13D | Intel.R13
  | Intel.XMM13 | Intel.YMM13 | Intel.ST5 | Intel.RIP -> 0b101uy
  | Intel.DH | Intel.SI | Intel.ESI | Intel.RSI
  | Intel.MM6 | Intel.XMM6 | Intel.YMM6
  | Intel.SIL | Intel.R14B | Intel.R14W | Intel.R14D | Intel.R14
  | Intel.XMM14 | Intel.YMM14 | Intel.ST6 -> 0b110uy
  | Intel.BH | Intel.DI | Intel.EDI | Intel.RDI
  | Intel.MM7 | Intel.XMM7 | Intel.YMM7
  | Intel.DIL | Intel.R15B | Intel.R15W | Intel.R15D | Intel.R15
  | Intel.XMM15 | Intel.YMM15 | Intel.ST7 -> 0b111uy
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
    | Some (Intel.RIP) | None -> 0b00uy
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

let modrmRel byteLen (rel: int64) relSz = // FIXME
  let comRel rel = rel - (byteLen + RegType.toByteWidth relSz |> int64)
  match relSz with
  | 8<rt> -> [| Normal <| byte (comRel rel) |]
  | 16<rt> -> BitConverter.GetBytes (comRel rel |> int16) |> Array.map Normal
  | 32<rt> -> BitConverter.GetBytes (comRel rel |> int32) |> Array.map Normal
  | _ -> Utils.impossible ()

let private encDisp disp = function
  | 8<rt> -> [| byte disp |> Normal |]
  | 32<rt> -> BitConverter.GetBytes (int32 disp) |> Array.map Normal
  | _ -> failwith "Invalid displacement"

let private getDispSz disp = if isDisp8 disp then 8<rt> else 32<rt>

let private isRegFld4 = function
  | Intel.RSP | Intel.ESP | Intel.SP | Intel.AH
  | Intel.R12 | Intel.R12D | Intel.R12W | Intel.R12B | Intel.SPL -> true
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
