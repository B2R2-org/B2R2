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
open B2R2.Assembler.Intel.EncodingType

let private regTo3Bit = function
  | Register.AL | Register.AX | Register.EAX | Register.RAX | Register.BND0
  | Register.MM0 | Register.XMM0 | Register.YMM0 | Register.ES -> 0b000uy
  | Register.CL | Register.CX | Register.ECX | Register.RCX | Register.BND1
  | Register.MM1 | Register.XMM1 | Register.YMM1 | Register.CS -> 0b001uy
  | Register.DL | Register.DX | Register.EDX | Register.RDX | Register.BND2
  | Register.MM2 | Register.XMM2 | Register.YMM2 | Register.SS -> 0b010uy
  | Register.BL | Register.BX | Register.EBX | Register.RBX | Register.BND3
  | Register.MM3 | Register.XMM3 | Register.YMM3 | Register.DS -> 0b011uy
  | Register.AH | Register.SP | Register.ESP | Register.RSP
  | Register.MM4 | Register.XMM4 | Register.YMM4 | Register.FS -> 0b100uy
  | Register.CH | Register.BP | Register.EBP | Register.RBP
  | Register.MM5 | Register.XMM5 | Register.YMM5 | Register.GS -> 0b101uy
  | Register.DH | Register.SI | Register.ESI | Register.RSI
  | Register.MM6 | Register.XMM6 | Register.YMM6 -> 0b110uy
  | Register.BH | Register.DI | Register.EDI | Register.RDI
  | Register.MM7 | Register.XMM7 | Register.YMM7 -> 0b111uy
  | _ -> Utils.impossible ()

let private getModRMByte md reg rm =
  (md <<< 6) + (reg <<< 3) + rm |> Normal

let private getRMBySIB baseReg = function // FIXME: baseReg option
  | Some _ -> 0b100uy
  | None -> regTo3Bit baseReg

let private isMR encType = function // ModRM:r/m(r, w), ModRM:reg(r)
  | Opcode.BT -> true
  | Opcode.MOVD when encType = EnR32Mx || encType = EnR32Xm -> true
  | Opcode.MOVQ when encType = EnR64Mx || encType = EnR64Xm -> true
  | Opcode.VMOVD when encType = EnR32Xm -> true
  | Opcode.VMOVQ when encType = EnR64Xm -> true
  | _ -> false // ModRM:reg(r, w), ModRM:r/m(r)

let private encodeRR reg1 reg2 encType op =
  if isMR encType op then getModRMByte 0b11uy (regTo3Bit reg2) (regTo3Bit reg1)
  else getModRMByte 0b11uy (regTo3Bit reg1) (regTo3Bit reg2)

let private getMod = function
  | None -> 0b00uy
  | Some disp -> if disp > 0xffL then 0b10uy else 0b01uy

let private encodeMR baseReg disp reg2 sib = // FIXME: same encodeRM
  getModRMByte (getMod disp) (regTo3Bit reg2) (getRMBySIB baseReg sib)

let private encodeRM baseReg disp reg2 sib =
  getModRMByte (getMod disp) (regTo3Bit reg2) (getRMBySIB baseReg sib)

let private encodeRI reg regConstr =
  getModRMByte 0b11uy regConstr (regTo3Bit reg)

let private encodeMI baseReg disp sib regConstr =
  getModRMByte (getMod disp) regConstr (getRMBySIB baseReg sib)

let private encodeM baseReg disp sib regConstr =
  getModRMByte (getMod disp) regConstr (getRMBySIB baseReg sib)

let private encodeR reg regConstr =
  getModRMByte 0b11uy regConstr (regTo3Bit reg)

let private encodeRRR r1 r2 r3 =
  match Register.getKind r1, Register.getKind r2, Register.getKind r3 with
  | RK.XMM, RK.XMM, RK.GP | RK.GP, RK.GP, RK.GP
  | RK.XMM, RK.XMM, RK.XMM | RK.YMM, RK.YMM, RK.XMM
  | RK.YMM, RK.YMM, RK.YMM  ->
    getModRMByte 0b11uy (regTo3Bit r1) (regTo3Bit r3)
  | _ -> Utils.impossible ()

let private encodeRRM r1 r2 baseReg sib disp =
  match Register.getKind r1, Register.getKind r2 with
  | RK.XMM, RK.XMM | RK.YMM, RK.YMM | RK.GP, RK.GP ->
    getModRMByte (getMod disp) (regTo3Bit r1) (getRMBySIB baseReg sib)
  | _ -> Utils.impossible ()

let private encodeRRIWithConstr reg regConstr =
  getModRMByte 0b11uy regConstr (regTo3Bit reg)

let private encodeRRI reg1 reg2 =
  getModRMByte 0b11uy (regTo3Bit reg1) (regTo3Bit reg2)

let private encodeRMI baseReg disp reg sib =
  getModRMByte (getMod disp) (regTo3Bit reg) (getRMBySIB baseReg sib)

let private encodeMRI baseReg disp reg sib =
  getModRMByte (getMod disp) (regTo3Bit reg) (getRMBySIB baseReg sib)

let private encodeRRRI r1 r2 r3 =
  match Register.getKind r1, Register.getKind r2, Register.getKind r3 with
  | RK.XMM, RK.XMM, RK.GP
  | RK.XMM, RK.XMM, RK.XMM | RK.YMM, RK.YMM, RK.YMM ->
    getModRMByte 0b11uy (regTo3Bit r1) (regTo3Bit r3)
  | _ -> Utils.impossible ()

let private encodeRRMI baseReg disp reg2 sib =
  getModRMByte (getMod disp) (regTo3Bit reg2) (getRMBySIB baseReg sib)

let private computeRegConstraint (ins: InsInfo) =
  match ins.Opcode with
  | Opcode.ADD | Opcode.MOV -> 0b000uy
  | Opcode.CMPXCHG8B | Opcode.CMPXCHG16B | Opcode.DEC -> 0b001uy
  | Opcode.LDMXCSR -> 0b010uy
  | Opcode.BT | Opcode.JMPNear -> 0b100uy
  | Opcode.IMUL -> 0b101uy
  | Opcode.PSLLD | Opcode.VPSLLD -> 0b110uy
  | Opcode.CLFLUSH | Opcode.IDIV | Opcode.PSLLDQ | Opcode.VPSLLDQ -> 0b111uy
  | _ -> Utils.impossible ()

/// Mod(2):Reg/Opcode(3):R/M(3)
let encodeModRM ins eType =
  match ins.Operands with
  (* One Operand *)
  | OneOperand (OprReg reg) -> [| encodeR reg (computeRegConstraint ins) |]
  | OneOperand (OprMem (Some b, s, d, _)) ->
    [| encodeM b d s (computeRegConstraint ins) |]
  (* Two Operands *)
  | TwoOperands (OprReg _, OprReg _)
    when ins.Opcode = Opcode.IN || ins.Opcode = Opcode.OUT  -> [||]
  | TwoOperands (OprReg r1, OprReg r2) -> [| encodeRR r1 r2 eType ins.Opcode |]
  | TwoOperands (OprReg r, OprMem (Some b, s, d, _)) -> [| encodeRM b d r s |]
  | TwoOperands (OprMem (Some b, s, d, _), OprReg r) -> [| encodeMR b d r s |]
  | TwoOperands (OprReg _, OprImm _) when ins.Opcode = Opcode.IN -> [||]
  | TwoOperands (OprReg r, OprImm _) ->
    [| encodeRI r (computeRegConstraint ins) |]
  | TwoOperands (OprMem (Some b, s, d, _), OprImm _) ->
    [| encodeMI b d s (computeRegConstraint ins) |]
  (* Three Operands *)
  | ThreeOperands (OprReg r1, OprReg r2, OprReg r3) -> [| encodeRRR r1 r2 r3 |]
  | ThreeOperands (OprReg r1, OprReg r2, OprMem (Some b, s, d, _)) ->
    [| encodeRRM r1 r2 b s d |]
  | ThreeOperands (OprReg _, OprReg r, OprImm _)
    when ins.Opcode = Opcode.VPSLLDQ || ins.Opcode = Opcode.VPSLLD ->
    [| encodeRRIWithConstr r (computeRegConstraint ins) |]
  | ThreeOperands (OprReg r1, OprReg r2, OprImm _) -> [| encodeRRI r1 r2 |]
  | ThreeOperands (OprReg r, OprMem (Some b, s, d, _), OprImm _) ->
    [| encodeRMI b d r s |]
  | ThreeOperands (OprMem (Some b, s, d, _), OprReg r, OprImm _) ->
    [| encodeMRI b d r s |]
  (* Four Operands *)
  | FourOperands (OprReg r1, OprReg r2, OprReg r3, OprImm _) ->
    [| encodeRRRI r1 r2 r3 |]
  | FourOperands (OprReg r1, OprReg _, OprMem (Some b, s, d, _), OprImm _) ->
    [| encodeRRMI b d r1 s |]
  (* more cases *)
  | _ -> [||]

let private getScaleBit = function
  | Scale.X1 -> 0b00uy
  | Scale.X2 -> 0b01uy
  | Scale.X4 -> 0b10uy
  | _ (* Scale.X8 *) -> 0b11uy

let private encodeScaledIdx baseReg (reg, scale) =
  let idxBit, sBit = regTo3Bit reg, getScaleBit scale
  let baseBit = regTo3Bit baseReg
  (sBit <<< 6) + (idxBit <<< 3) + baseBit |> Normal

/// Scale(2):Index(3):Base(3)
let encodeSIB ins =
  match ins.Operands with
  | TwoOperands (OprMem (Some b, Some sib, _, _), _)
  | TwoOperands (_, OprMem (Some b, Some sib, _, _)) ->
    [| encodeScaledIdx b sib |]
  (* more cases *)
  | _ -> [||]

let private adjustDisp = function
  | None -> [||]
  | Some disp ->
    if disp > 0xffL then BitConverter.GetBytes (int32 disp) |> Array.map Normal
    else [| Normal <| byte disp |]

let encodeDisp ins =
  match ins.Operands with
  | OneOperand (GoToLabel _lbl) -> [| Label; Label; Label; Label |] // FIXME
  | TwoOperands (OprMem (_, _, disp, _), _)
  | TwoOperands (_, OprMem (_, _, disp, _)) -> adjustDisp disp
  (* more cases *)
  | _ -> [||]

let private uncondImm8Opcode = function
  | Opcode.BT | Opcode.CMPPD | Opcode.CMPPS | Opcode.IN | Opcode.PALIGNR
  | Opcode.PEXTRW | Opcode.PINSRW | Opcode.PSLLD | Opcode.PSLLDQ
  | Opcode.ROUNDSD -> true
  | _ -> false

let private adjustImm op (imm: int64) = function
  | _ when uncondImm8Opcode op -> [| byte imm |]
  | 8<rt> -> [| byte imm |]
  | 16<rt> -> BitConverter.GetBytes (int16 imm)
  | 32<rt> -> BitConverter.GetBytes (int32 imm)
  | 64<rt> when op = Opcode.IMUL -> BitConverter.GetBytes (int32 imm)
  | 64<rt> -> BitConverter.GetBytes (imm)
  | _ -> Utils.impossible ()

let private encTwoOprImm op opr1 opr2 =
  match opr1, opr2 with
  | OprReg r, OprImm imm ->
    adjustImm op imm (Register.toRegType r) |> Array.map Normal
  | OprMem (_, _, _, sz), OprImm imm ->
    adjustImm op imm sz |> Array.map Normal
  | OprImm imm1, OprImm imm2 -> // ENTER
    Array.append (adjustImm op imm1 16<rt> |> Array.map Normal)
      (adjustImm op imm2 8<rt> |> Array.map Normal)
  | OprImm imm, OprReg _ -> adjustImm op imm 8<rt> |> Array.map Normal // OUT
  | _ -> [||]

let private encThreeOprImm op opr1 opr2 opr3 =
  match opr1, opr2, opr3 with
  | OprReg r1, OprReg r2, OprImm imm ->
    match regKindAndSize r1, regKindAndSize r2 with
    | (RK.GP, 32<rt>), (RK.MMX, _)
    | (RK.GP, 32<rt>), (RK.XMM, _)
    | (RK.GP, 64<rt>), (RK.MMX, _)
    | (RK.GP, 64<rt>), (RK.XMM, _)
    | (RK.MMX, _), (RK.GP, 32<rt>)
    | (RK.XMM, _), (RK.GP, 32<rt>)
    | (RK.XMM, _), (RK.GP, 64<rt>)
    | (RK.MMX, _), (RK.MMX, _) | (RK.XMM, _), (RK.XMM, _)
    | (RK.YMM, _), (RK.YMM, _) ->
      adjustImm op imm 8<rt> |> Array.map Normal
    | (RK.GP, 16<rt>), (RK.GP, 16<rt>) ->
      adjustImm op imm 16<rt> |> Array.map Normal
    | (RK.GP, 32<rt>), (RK.GP, 32<rt>)
    | (RK.GP, 64<rt>), (RK.GP, 64<rt>) ->
      adjustImm op imm 32<rt> |> Array.map Normal
    | _ -> [||]
  | OprReg _, OprMem (_, _, _, sz), OprImm imm
  | OprMem (_, _, _, sz), OprReg _, OprImm imm ->
    adjustImm op imm sz |> Array.map Normal
  | _ -> [||]

let private encFourOprImm op opr1 opr2 opr3 opr4 =
  match opr1, opr2, opr3, opr4 with
  | OprReg _, OprReg _, OprReg _, OprImm imm ->
    adjustImm op imm 8<rt> |> Array.map Normal
  | OprReg _, OprReg _, OprMem (_, _, _, sz), OprImm imm ->
    match sz with
    | 8<rt> | 16<rt> | 128<rt> | 256<rt> ->
      adjustImm op imm 8<rt> |> Array.map Normal
    | _ -> [||]
  | _ -> [||]

let encodeImm ins =
  match ins.Operands with
  | OneOperand (OprImm imm) ->
    adjustImm ins.Opcode imm 8<rt> |> Array.map Normal
  | TwoOperands (opr1, opr2) -> encTwoOprImm (ins.Opcode) opr1 opr2
  | ThreeOperands (o1, o2, o3) -> encThreeOprImm (ins.Opcode) o1 o2 o3
  | FourOperands (o1, o2, o3, o4) -> encFourOprImm (ins.Opcode) o1 o2 o3 o4
  | _ -> [||]

// vim: set tw=80 sts=2 sw=2:
