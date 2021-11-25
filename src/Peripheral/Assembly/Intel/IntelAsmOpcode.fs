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

module internal B2R2.Peripheral.Assembly.Intel.AsmOpcode

open B2R2
open B2R2.FrontEnd.BinLifter.Intel
open B2R2.Peripheral.Assembly.Intel.ParserHelper
open B2R2.Peripheral.Assembly.Intel.AsmPrefix
open B2R2.Peripheral.Assembly.Intel.AsmOperands

let no32Arch arch =
  if arch = Arch.IntelX86 then raise InvalidISAException else ()

let no64Arch arch =
  if arch = Arch.IntelX64 then raise InvalidISAException else ()

let isInt8 i = 0xFFFFFFFFFFFFFF80L <= i && i <= 0x7FL
let isInt16 i = 0xFFFFFFFFFFFF8000L <= i && i <= 0x7FFFL
let isInt32 i = 0xFFFFFFFF80000000L <= i && i <= 0x7FFFFFFFL

let isUInt8 (i: int64) = uint64 i <= 0xFFUL
let isUInt16 (i: int64) = uint64 i <= 0xFFFFUL
let isUInt32 (i: int64) = uint64 i <= 0xFFFFFFFFUL

let inline prxRexOp ins arch pref rex op =
  [| yield! encodePrefix ins arch pref
     yield! encodeREXPref ins arch rex
     yield! Array.map Normal op |]

let inline encLbl ins =
  [| IncompleteOp (ins.Opcode, ins.Operands) |]

let inline encI ins arch pref rex op i immSz =
  [| yield! prxRexOp ins arch pref rex op
     yield! immediate i immSz |]

let inline encR ins arch pref rex op r c =
  [| yield! prxRexOp ins arch pref rex op
     modrmR r c |]

let inline encD ins arch pref rex op rel sz =
  let prxRexOp = prxRexOp ins arch pref rex op
  [| yield! prxRexOp
     yield! modrmRel (Array.length prxRexOp) rel sz |]

let inline encM ins arch pref rex op b s d c =
  [| yield! prxRexOp ins arch pref rex op
     modrmM b s d c
     yield! mem b s d |]

let inline encRR ins arch pref rex op r1 r2 =
  [| yield! prxRexOp ins arch pref rex op
     modrmRR r1 r2 |]

let normalToByte = function
  | Normal b -> b
  | _ -> Utils.impossible ()

let getCtxtByOprSz (ctxt: EncContext) op8Byte opByte = function
  | 8<rt> -> ctxt.PrefNormal, ctxt.RexNormal, op8Byte
  | 16<rt> -> ctxt.Pref66, ctxt.RexNormal, opByte
  | 32<rt> -> ctxt.PrefNormal, ctxt.RexNormal, opByte
  | 64<rt> -> ctxt.PrefNormal, ctxt.RexW, opByte
  | _ -> Utils.impossible ()

let inline encRL (ctxt: EncContext) ins r op8Byte opByte =
  let pref, rex, opByte =
    getCtxtByOprSz ctxt op8Byte opByte (Register.toRegType r)
  [| yield! prxRexOp ins ctxt.Arch pref rex opByte
     yield modrmRL r |]
  |> Array.map normalToByte
  |> fun bytes ->
    [| CompOp (ins.Opcode, ins.Operands, bytes, None); IncompLabel 32<rt> |]

let inline encLI (ctxt: EncContext) ins regConstr i immSz op8Byte opByte =
  let pref, rex, opByte = getCtxtByOprSz ctxt op8Byte opByte 32<rt> // FIXME
  let op = [| yield! prxRexOp ins ctxt.Arch pref rex opByte
              yield modrmLI regConstr |] |> Array.map normalToByte
  let imm = immediate i immSz |> Array.map normalToByte |> Some
  [| CompOp (ins.Opcode, ins.Operands, op, imm); IncompLabel 32<rt> |]

let inline encRLI (ctxt: EncContext) ins r op i immSz =
  let pref, rex, opByte =
    getCtxtByOprSz ctxt [||] op (Register.toRegType r)
  let op = [| yield! prxRexOp ins ctxt.Arch pref rex opByte
              yield modrmRL r |] |> Array.map normalToByte
  let imm = immediate i immSz |> Array.map normalToByte |> Some
  [| CompOp (ins.Opcode, ins.Operands, op, imm); IncompLabel 32<rt> |]

let inline encFR (op: byte []) r =
  let op = [| op.[0]; op.[1] + (regTo3Bit r) |]
  [| yield! Array.map Normal op |]

let inline encO ins arch pref rex op r =
  let op = [| op + (regTo3Bit r) |]
  [| yield! prxRexOp ins arch pref rex op |]

let inline encRI ins arch pref rex op r c i immSz =
  [| yield! prxRexOp ins arch pref rex op
     yield modrmRI r c
     yield! immediate i immSz |]

let inline encOI ins arch pref rex op r i immSz =
  let op = [| op + (regTo3Bit r) |]
  [| yield! prxRexOp ins arch pref rex op
     yield! immediate i immSz |]

let inline encRM ins arch pref rex op r b s d =
  [| yield! prxRexOp ins arch pref rex op
     modrmRM r b s d
     yield! mem b s d |]

let inline encMR ins arch pref rex op b s d r =
  [| yield! prxRexOp ins arch pref rex op
     modrmMR b s d r
     yield! mem b s d |]

let inline encMI ins arch pref rex op b s d c i immSz =
  [| yield! prxRexOp ins arch pref rex op
     modrmMI b s d c
     yield! mem b s d
     yield! immediate i immSz |]

let inline encRC ins arch pref rex op r c =
  [| yield! prxRexOp ins arch pref rex op
     modrmRC r c |]

let inline encMC ins arch pref rex op b s d c =
  [| yield! prxRexOp ins arch pref rex op
     modrmMC b s d c |]

let inline encNP ins arch pref rex op =
  [| yield! prxRexOp ins arch pref rex op |]

let inline encRRI ins arch pref rex op r1 r2 i immSz =
  [| yield! prxRexOp ins arch pref rex op
     modrmRR r1 r2
     yield! immediate i immSz |]

let inline encRMI ins arch pref rex op r b s d i immSz =
  [| yield! prxRexOp ins arch pref rex op
     modrmRM r b s d
     yield! mem b s d
     yield! immediate i immSz |]

let inline encMRI ins arch pref rex op b s d r i immSz =
  [| yield! prxRexOp ins arch pref rex op
     modrmMR b s d r
     yield! mem b s d
     yield! immediate i immSz |]

let inline encVexRRR ins arch vvvv vex op r1 r3 =
  let rexRXB = encodeVEXRexRB arch r1 r3
  [| yield! encodeVEXPref rexRXB vvvv vex
     yield! Array.map Normal op
     modrmRR r1 r3 |]

let inline encVexRRM ins arch vvvv vex op r b s d =
  let rexRXB = encodeVEXRexRXB arch r b s
  [| yield! encodeVEXPref rexRXB vvvv vex
     yield! Array.map Normal op
     modrmRM r b s d
     yield! mem b s d |]

let inline encVexRRRI ins arch vvvv vex op r1 r3 i immSz =
  let rexRXB = encodeVEXRexRB arch r1 r3
  [| yield! encodeVEXPref rexRXB vvvv vex
     yield! Array.map Normal op
     modrmRR r1 r3
     yield! immediate i immSz |]

let inline encVexRRMI ins arch vvvv vex op r b s d i immSz =
  let rexRXB = encodeVEXRexRXB arch r b s
  [| yield! encodeVEXPref rexRXB vvvv vex
     yield! Array.map Normal op
     modrmRM r b s d
     yield! mem b s d
     yield! immediate i immSz |]

let aaa (ctxt: EncContext) = function
  | NoOperand -> no64Arch ctxt.Arch; [| Normal 0x37uy |]
  | _ -> raise NotEncodableException

let aad (ctxt: EncContext) = function
  | NoOperand -> no64Arch ctxt.Arch; [| Normal 0xD5uy; Normal 0x0Auy |]
  | OneOperand (OprImm (imm, _)) ->
    no64Arch ctxt.Arch; [| Normal 0xD5uy; yield! immediate imm 8<rt> |]
  | _ -> raise NotEncodableException

let aam (ctxt: EncContext) = function
  | NoOperand -> no64Arch ctxt.Arch; [| Normal 0xD4uy; Normal 0x0Auy |]
  | OneOperand (OprImm (imm, _)) ->
    no64Arch ctxt.Arch; [| Normal 0xD4uy; yield! immediate imm 8<rt> |]
  | _ -> raise NotEncodableException

let aas (ctxt: EncContext) = function
  | NoOperand -> no64Arch ctxt.Arch; [| Normal 0x3Fuy |]
  | _ -> raise NotEncodableException

let adc (ctxt: EncContext) ins =
  match ins.Operands with
  (* Reg (fixed) - Imm (Priority 1) *)
  | TwoOperands (OprReg Register.AL, OprImm (imm, _)) ->
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x14uy |] imm 8<rt>
  | TwoOperands (OprReg Register.AX, OprImm (imm, _)) ->
    encI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x15uy |] imm 16<rt>
  | TwoOperands (OprReg Register.EAX, OprImm (imm, _)) ->
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x15uy |] imm 32<rt>
  | TwoOperands (OprReg Register.RAX, OprImm (imm, _)) ->
    no32Arch ctxt.Arch
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x15uy |] imm 32<rt>
  (* Reg - Imm (Priority 0) *)
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg16 r && isInt8 imm ->
    encRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x83uy |] r 0b010uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg32 r && isInt8 imm ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x83uy |] r 0b010uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg64 r && isInt8 imm ->
    no32Arch ctxt.Arch
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x83uy |] r 0b010uy imm 8<rt>
  (* Mem - Imm (Priority 0) *)
  | TwoOperands (Label _, OprImm (imm, _)) when isInt8 imm ->
    encLI ctxt ins 0b010uy imm 8<rt> [||] [| 0x83uy |]
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprImm (imm, _)) when isInt8 imm ->
    encMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x83uy |] b s d 0b010uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprImm (imm, _)) when isInt8 imm ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x83uy |] b s d 0b010uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprImm (imm, _)) when isInt8 imm ->
    no32Arch ctxt.Arch
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x83uy |] b s d 0b010uy imm 8<rt>
  (* Reg - Imm (Priority 1) *)
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg8 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x80uy |] r 0b010uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg16 r ->
    encRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x81uy |] r 0b010uy imm 16<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg32 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x81uy |] r 0b010uy imm 32<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg64 r ->
    no32Arch ctxt.Arch
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x81uy |] r 0b010uy imm 32<rt>
  (* Mem - Imm (Priority 1) *)
  | TwoOperands (Label _, OprImm (imm, _)) ->
    encLI ctxt ins 0b010uy imm 32<rt> [| 0x80uy |] [| 0x81uy |] // FIXME
  | TwoOperands (OprMem (b, s, d, 8<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x80uy |] b s d 0b010uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x81uy |] b s d 0b010uy imm 16<rt>
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x81uy |] b s d 0b010uy imm 32<rt>
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprImm (imm, _)) ->
    no32Arch ctxt.Arch;
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x81uy |] b s d 0b010uy imm 32<rt>
  (* Mem - Reg *)
  | TwoOperands (Label _, OprReg r) ->
    encRL ctxt ins r [| 0x10uy |] [| 0x11uy |]
  | TwoOperands (OprMem (b, s, d, 8<rt>), OprReg r) when isReg8 r ->
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x10uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprReg r) when isReg16 r ->
    encMR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x11uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprReg r) when isReg32 r ->
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x11uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprReg r) when isReg64 r ->
    no32Arch ctxt.Arch
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x11uy |] b s d r
  (* Reg - Reg *)
  | TwoOperands (OprReg r1, OprReg r2) when isReg8 r1 && isReg8 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x12uy |] r1 r2
  | TwoOperands (OprReg r1, OprReg r2) when isReg16 r1 && isReg16 r2 ->
    encRR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x13uy |] r1 r2
  | TwoOperands (OprReg r1, OprReg r2) when isReg32 r1 && isReg32 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x13uy |] r1 r2
  | TwoOperands (OprReg r1, OprReg r2) when isReg64 r1 && isReg64 r2 ->
    no32Arch ctxt.Arch
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x13uy |] r1 r2
  (* Reg - Mem *)
  | TwoOperands (OprReg r, Label _) ->
    encRL ctxt ins r [| 0x12uy |] [| 0x13uy |]
  | TwoOperands (OprReg r, OprMem (b, s, d, 8<rt>)) when isReg8 r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x12uy |] r b s d
  | TwoOperands (OprReg r, OprMem (b, s, d, 16<rt>)) when isReg16 r ->
    encRM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x13uy |] r b s d
  | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isReg32 r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x13uy |] r b s d
  | TwoOperands (OprReg r, OprMem (b, s, d, 64<rt>)) when isReg64 r ->
    no32Arch ctxt.Arch
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x13uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let add (ctxt: EncContext) ins =
  match ins.Operands with
  (* Reg (fixed) - Imm (Priority 1) *)
  | TwoOperands (OprReg Register.AL, OprImm (imm, _)) ->
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x04uy |] imm 8<rt>
  | TwoOperands (OprReg Register.AX, OprImm (imm, _)) ->
    encI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x05uy |] imm 16<rt>
  | TwoOperands (OprReg Register.EAX, OprImm (imm, _)) ->
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x05uy |] imm 32<rt>
  | TwoOperands (OprReg Register.RAX, OprImm (imm, _)) ->
    no32Arch ctxt.Arch
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x05uy |] imm 32<rt>
  (* Reg - Imm (Priority 0) *)
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg16 r && isInt8 imm ->
    encRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x83uy |] r 0b000uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg32 r && isInt8 imm ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x83uy |] r 0b000uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg64 r && isInt8 imm ->
    no32Arch ctxt.Arch
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x83uy |] r 0b000uy imm 8<rt>
  (* Mem - Imm (Priority 0) *)
  | TwoOperands (Label _, OprImm (imm, _)) when isInt8 imm ->
    encLI ctxt ins 0b000uy imm 8<rt> [||] [| 0x83uy |]
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprImm (imm, _)) when isInt8 imm ->
    encMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x83uy |] b s d 0b000uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprImm (imm, _)) when isInt8 imm ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x83uy |] b s d 0b000uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprImm (imm, _)) when isInt8 imm ->
    no32Arch ctxt.Arch
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x83uy |] b s d 0b000uy imm 8<rt>
  (* Reg - Imm (Priority 1) *)
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg8 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x80uy |] r 0b000uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg16 r ->
    encRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x81uy |] r 0b000uy imm 16<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg32 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x81uy |] r 0b000uy imm 32<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg64 r ->
    no32Arch ctxt.Arch
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x81uy |] r 0b000uy imm 32<rt>
  (* Mem - Imm (Priority 1) *)
  | TwoOperands (Label _, OprImm (imm, _)) ->
    encLI ctxt ins 0b000uy imm 32<rt> [| 0x80uy |] [| 0x81uy |] // FIXME
  | TwoOperands (OprMem (b, s, d, 8<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x80uy |] b s d 0b000uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x81uy |] b s d 0b000uy imm 16<rt>
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x81uy |] b s d 0b000uy imm 32<rt>
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprImm (imm, _)) ->
    no32Arch ctxt.Arch;
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x81uy |] b s d 0b000uy imm 32<rt>
  (* Mem - Reg *)
  | TwoOperands (Label _, OprReg r) ->
    encRL ctxt ins r [| 0x00uy |] [| 0x01uy |]
  | TwoOperands (OprMem (b, s, d, 8<rt>), OprReg r) when isReg8 r ->
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x00uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprReg r) when isReg16 r ->
    encMR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x01uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprReg r) when isReg32 r ->
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x01uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprReg r) when isReg64 r ->
    no32Arch ctxt.Arch
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x01uy |] b s d r
  (* Reg - Reg *)
  | TwoOperands (OprReg r1, OprReg r2) when isReg8 r1 && isReg8 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x02uy |] r1 r2
  | TwoOperands (OprReg r1, OprReg r2) when isReg16 r1 && isReg16 r2 ->
    encRR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x03uy |] r1 r2
  | TwoOperands (OprReg r1, OprReg r2) when isReg32 r1 && isReg32 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x03uy |] r1 r2
  | TwoOperands (OprReg r1, OprReg r2) when isReg64 r1 && isReg64 r2 ->
    no32Arch ctxt.Arch
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x03uy |] r1 r2
  (* Reg - Mem *)
  | TwoOperands (OprReg r, Label _) ->
    encRL ctxt ins r [| 0x02uy |] [| 0x03uy |]
  | TwoOperands (OprReg r, OprMem (b, s, d, 8<rt>)) when isReg8 r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x02uy |] r b s d
  | TwoOperands (OprReg r, OprMem (b, s, d, 16<rt>)) when isReg16 r ->
    encRM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x03uy |] r b s d
  | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isReg32 r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x03uy |] r b s d
  | TwoOperands (OprReg r, OprMem (b, s, d, 64<rt>)) when isReg64 r ->
    no32Arch ctxt.Arch
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x03uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let addpd (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0x58uy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 128<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0x58uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let addps (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0x58uy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 128<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0x58uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let addsd (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefF2 ctxt.RexNormal [| 0x0Fuy; 0x58uy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 64<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefF2 ctxt.RexNormal [| 0x0Fuy; 0x58uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let addss (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefF3 ctxt.RexNormal [| 0x0Fuy; 0x58uy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefF3 ctxt.RexNormal [| 0x0Fuy; 0x58uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let logAnd (ctxt: EncContext) ins =
  match ins.Operands with
  (* Reg (fixed) - Imm *)
  | TwoOperands (OprReg Register.AL, OprImm (imm, _)) ->
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x24uy |] imm 8<rt>
  | TwoOperands (OprReg Register.AX, OprImm (imm, _)) ->
    encI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x25uy |] imm 16<rt>
  | TwoOperands (OprReg Register.EAX, OprImm (imm, _)) ->
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x25uy |] imm 32<rt>
  | TwoOperands (OprReg Register.RAX, OprImm (imm, _)) ->
    no32Arch ctxt.Arch
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x25uy |] imm 32<rt>
  (* Reg - Imm (Priority 0) *)
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg16 r && isInt8 imm ->
    encRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x83uy |] r 0b100uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg32 r && isInt8 imm ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x83uy |] r 0b100uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg64 r && isInt8 imm ->
    no32Arch ctxt.Arch
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x83uy |] r 0b100uy imm 8<rt>
  (* Mem - Imm (Priority 0) *)
  | TwoOperands (Label _, OprImm (imm, _)) when isInt8 imm ->
    encLI ctxt ins 0b100uy imm 8<rt> [||] [| 0x83uy |]
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprImm (imm, _)) when isInt8 imm ->
    encMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x83uy |] b s d 0b100uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprImm (imm, _)) when isInt8 imm ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x83uy |] b s d 0b100uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprImm (imm, _)) when isInt8 imm ->
    no32Arch ctxt.Arch
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x83uy |] b s d 0b100uy imm 8<rt>
  (* Reg - Imm (Priority 1) *)
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg8 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x80uy |] r 0b100uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg16 r ->
    encRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x81uy |] r 0b100uy imm 16<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg32 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x81uy |] r 0b100uy imm 32<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg64 r ->
    no32Arch ctxt.Arch
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x81uy |] r 0b100uy imm 32<rt>
  (* Mem - Imm (Priority 1) *)
  | TwoOperands (Label _, OprImm (imm, _)) ->
    encLI ctxt ins 0b100uy imm 32<rt> [| 0x80uy |] [| 0x81uy |] // FIXME
  | TwoOperands (OprMem (b, s, d, 8<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x80uy |] b s d 0b100uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x81uy |] b s d 0b100uy imm 16<rt>
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x81uy |] b s d 0b100uy imm 32<rt>
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprImm (imm, _)) ->
    no32Arch ctxt.Arch;
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x81uy |] b s d 0b100uy imm 32<rt>
  (* Mem - Reg *)
  | TwoOperands (Label _, OprReg r) ->
    encRL ctxt ins r [| 0x20uy |] [| 0x21uy |]
  | TwoOperands (OprMem (b, s, d, 8<rt>), OprReg r) when isReg8 r ->
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x20uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprReg r) when isReg16 r ->
    encMR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x21uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprReg r) when isReg32 r ->
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x21uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprReg r) when isReg64 r ->
    no32Arch ctxt.Arch
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x21uy |] b s d r
  (* Reg - Reg *)
  | TwoOperands (OprReg r1, OprReg r2) when isReg8 r1 && isReg8 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x22uy |] r1 r2
  | TwoOperands (OprReg r1, OprReg r2) when isReg16 r1 && isReg16 r2 ->
    encRR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x23uy |] r1 r2
  | TwoOperands (OprReg r1, OprReg r2) when isReg32 r1 && isReg32 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x23uy |] r1 r2
  | TwoOperands (OprReg r1, OprReg r2) when isReg64 r1 && isReg64 r2 ->
    no32Arch ctxt.Arch
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x23uy |] r1 r2
  (* Reg - Mem *)
  | TwoOperands (Label _, OprReg r) ->
    encRL ctxt ins r [| 0x22uy |] [| 0x23uy |]
  | TwoOperands (OprReg r, OprMem (b, s, d, 8<rt>)) when isReg8 r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x22uy |] r b s d
  | TwoOperands (OprReg r, OprMem (b, s, d, 16<rt>)) when isReg16 r ->
    encRM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x23uy |] r b s d
  | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isReg32 r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x23uy |] r b s d
  | TwoOperands (OprReg r, OprMem (b, s, d, 64<rt>)) when isReg64 r ->
    no32Arch ctxt.Arch
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x23uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let andpd (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0x54uy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 128<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0x54uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let andps (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0x54uy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 128<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0x54uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let bsr (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isReg16 r1 && isReg16 r2 ->
    encRR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0xBDuy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 16<rt>)) when isReg16 r ->
    encRM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0xBDuy |] r b s d
  | TwoOperands (OprReg r1, OprReg r2) when isReg32 r1 && isReg32 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0xBDuy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isReg32 r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0xBDuy |] r b s d
  | TwoOperands (OprReg r1, OprReg r2) when isReg64 r1 && isReg64 r2 ->
    no32Arch ctxt.Arch
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x0Fuy; 0xBDuy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 64<rt>)) when isReg64 r ->
    no32Arch ctxt.Arch
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x0Fuy; 0xBDuy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let bt (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isReg16 r1 && isReg16 r2 ->
    encRR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexMR [| 0x0Fuy; 0xA3uy |] r2 r1
  | TwoOperands (OprReg r1, OprReg r2) when isReg32 r1 && isReg32 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexMR [| 0x0Fuy; 0xA3uy |] r2 r1
  | TwoOperands (OprReg r1, OprReg r2) when isReg64 r1 && isReg64 r2 ->
    no32Arch ctxt.Arch
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexWAndMR [| 0x0Fuy; 0xA3uy |] r2 r1
  | TwoOperands (Label _, OprReg r) ->
    encRL ctxt ins r [||] [| 0x0Fuy; 0xA3uy |]
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprReg r) when isReg16 r ->
    encMR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexMR [| 0x0Fuy; 0xA3uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprReg r) when isReg32 r ->
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexMR [| 0x0Fuy; 0xA3uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprReg r) when isReg64 r ->
    no32Arch ctxt.Arch
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexWAndMR [| 0x0Fuy; 0xA3uy |] b s d r
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg16 r ->
    encRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0xBAuy |] r 0b100uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg32 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0xBAuy |] r 0b100uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg64 r ->
    no32Arch ctxt.Arch
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x0Fuy; 0xBAuy |] r 0b100uy imm 8<rt>
  | TwoOperands (Label _, OprImm (imm, _)) ->
    encLI ctxt ins 0b100uy imm 32<rt> [||] [| 0x0Fuy; 0xBAuy |] // FIXME
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0xBAuy |] b s d 0b100uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprImm (i, _)) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0xBAuy |] b s d 0b100uy i 8<rt>
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprImm (imm, _)) ->
    no32Arch ctxt.Arch
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x0Fuy; 0xBAuy |] b s d 0b100uy imm 8<rt>
  | o -> printfn "%A" o; raise NotEncodableException

let call (ctxt: EncContext) ins =
  match ins.Operands with
  | OneOperand (OprDirAddr (Relative rel))
    when isInt16 rel && ctxt.Arch = Arch.IntelX86 ->
    encD ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0xE8uy |] rel 16<rt>
  | OneOperand (OprDirAddr (Relative rel))
    when isInt32 rel ->
    encD ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xE8uy |] rel 32<rt>
  | OneOperand (Label _) ->
    encLbl ins // FIXME
  | OneOperand (OprMem (b, s, d, 16<rt>)) ->
    no64Arch ctxt.Arch
    encM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0xFFuy |] b s d 0b010uy
  | OneOperand (OprMem (b, s, d, 32<rt>)) ->
    no64Arch ctxt.Arch
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xFFuy |] b s d 0b010uy
  | OneOperand (OprMem (b, s, d, 64<rt>)) ->
    no32Arch ctxt.Arch
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xFFuy |] b s d 0b010uy
  | OneOperand (OprReg r) when isReg16 r ->
    no64Arch ctxt.Arch
    encR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0xFFuy |] r 0b010uy
  | OneOperand (OprReg r) when isReg32 r ->
    no64Arch ctxt.Arch
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xFFuy |] r 0b010uy
  | OneOperand (OprReg r) when isReg64 r ->
    no32Arch ctxt.Arch
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xFFuy |] r 0b010uy
  | o -> printfn "%A" o; raise NotEncodableException

let cbw _ctxt = function
  | NoOperand -> [| Normal 0x66uy; Normal 0x98uy |]
  | _ -> raise NotEncodableException

let cdq _ctxt = function
  | NoOperand -> [| Normal 0x99uy |]
  | _ -> raise NotEncodableException

let cdqe (ctxt: EncContext) = function
  | NoOperand -> no32Arch ctxt.Arch; [| Normal 0x48uy; Normal 0x98uy |]
  | _ -> raise NotEncodableException

let cmovcc (ctxt: EncContext) ins opcode =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isReg16 r1 && isReg16 r2 ->
    encRR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal opcode r1 r2
  | TwoOperands (OprReg r1, OprReg r2) when isReg32 r1 && isReg32 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal opcode r1 r2
  | TwoOperands (OprReg r1, OprReg r2) when isReg64 r1 && isReg64 r2 ->
    no32Arch ctxt.Arch
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW opcode r1 r2
  | TwoOperands (Label _, OprReg r) ->
    encRL ctxt ins r [||] opcode
  | TwoOperands (OprReg r, OprMem (b, s, d, 16<rt>)) when isReg16 r ->
    encMR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal opcode b s d r
  | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isReg32 r ->
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal opcode b s d r
  | TwoOperands (OprReg r, OprMem (b, s, d, 64<rt>)) when isReg64 r ->
    no32Arch ctxt.Arch
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW opcode b s d r
  | o -> printfn "%A" o; raise NotEncodableException

let cmova ctxt ins = cmovcc ctxt ins [| 0x0Fuy; 0x47uy |]
let cmovae ctxt ins = cmovcc ctxt ins [| 0x0Fuy; 0x43uy |]
let cmovb ctxt ins = cmovcc ctxt ins [| 0x0Fuy; 0x42uy |]
let cmovbe ctxt ins = cmovcc ctxt ins [| 0x0Fuy; 0x46uy |]
let cmovg ctxt ins = cmovcc ctxt ins [| 0x0Fuy; 0x4Fuy |]
let cmovge ctxt ins = cmovcc ctxt ins [| 0x0Fuy; 0x4Duy |]
let cmovl ctxt ins = cmovcc ctxt ins [| 0x0Fuy; 0x4Cuy |]
let cmovle ctxt ins = cmovcc ctxt ins [| 0x0Fuy; 0x4Euy |]
let cmovno ctxt ins = cmovcc ctxt ins [| 0x0Fuy; 0x41uy |]
let cmovnp ctxt ins = cmovcc ctxt ins [| 0x0Fuy; 0x4Buy |]
let cmovns ctxt ins = cmovcc ctxt ins [| 0x0Fuy; 0x49uy |]
let cmovnz ctxt ins = cmovcc ctxt ins [| 0x0Fuy; 0x45uy |]
let cmovo ctxt ins = cmovcc ctxt ins [| 0x0Fuy; 0x40uy |]
let cmovp ctxt ins = cmovcc ctxt ins [| 0x0Fuy; 0x4Auy |]
let cmovs ctxt ins = cmovcc ctxt ins [| 0x0Fuy; 0x48uy |]
let cmovz ctxt ins = cmovcc ctxt ins [| 0x0Fuy; 0x44uy |]

let cmp (ctxt: EncContext) ins =
  match ins.Operands with
  (* Reg (fixed) - Imm (Priority 1) *)
  | TwoOperands (OprReg Register.AL, OprImm (imm, _)) ->
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x3Cuy |] imm 8<rt>
  | TwoOperands (OprReg Register.AX, OprImm (imm, _)) ->
    encI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x3Duy |] imm 16<rt>
  | TwoOperands (OprReg Register.EAX, OprImm (imm, _)) ->
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x3Duy |] imm 32<rt>
  | TwoOperands (OprReg Register.RAX, OprImm (imm, _)) ->
    no32Arch ctxt.Arch
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x3Duy |] imm 32<rt>
  (* Reg - Imm (Priority 0) *)
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg16 r && isInt8 imm ->
    encRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x83uy |] r 0b111uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg32 r && isInt8 imm ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x83uy |] r 0b111uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg64 r && isInt8 imm ->
    no32Arch ctxt.Arch
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x83uy |] r 0b111uy imm 8<rt>
  (* Mem - Imm (Priority 0) *)
  | TwoOperands (Label _, OprImm (imm, _)) when isInt8 imm ->
    encLI ctxt ins 0b111uy imm 8<rt> [||] [| 0x83uy |]
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprImm (imm, _)) when isInt8 imm ->
    encMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x83uy |] b s d 0b111uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprImm (imm, _)) when isInt8 imm ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x83uy |] b s d 0b111uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprImm (imm, _)) when isInt8 imm ->
    no32Arch ctxt.Arch
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x83uy |] b s d 0b111uy imm 8<rt>
  (* Reg - Imm (Priority 1) *)
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg8 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x80uy |] r 0b111uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg16 r ->
    encRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x81uy |] r 0b111uy imm 16<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg32 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x81uy |] r 0b111uy imm 32<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg64 r ->
    no32Arch ctxt.Arch
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x81uy |] r 0b111uy imm 32<rt>
  (* Mem - Imm (Priority 1) *)
  | TwoOperands (Label _, OprImm (imm, _)) ->
    encLI ctxt ins 0b111uy imm 32<rt> [| 0x80uy |] [| 0x81uy |] // FIXME
  | TwoOperands (OprMem (b, s, d, 8<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x80uy |] b s d 0b111uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x81uy |] b s d 0b111uy imm 16<rt>
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x81uy |] b s d 0b111uy imm 32<rt>
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprImm (imm, _)) ->
    no32Arch ctxt.Arch;
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x81uy |] b s d 0b111uy imm 32<rt>
  (* Mem - Reg *)
  | TwoOperands (Label _, OprReg r) ->
    encRL ctxt ins r [| 0x38uy |] [| 0x39uy |]
  | TwoOperands (OprMem (b, s, d, 8<rt>), OprReg r) when isReg8 r ->
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x38uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprReg r) when isReg16 r ->
    encMR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x39uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprReg r) when isReg32 r ->
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x39uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprReg r) when isReg64 r ->
    no32Arch ctxt.Arch
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x39uy |] b s d r
  (* Reg - Reg *)
  | TwoOperands (OprReg r1, OprReg r2) when isReg8 r1 && isReg8 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x3Auy |] r1 r2
  | TwoOperands (OprReg r1, OprReg r2) when isReg16 r1 && isReg16 r2 ->
    encRR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x3Buy |] r1 r2
  | TwoOperands (OprReg r1, OprReg r2) when isReg32 r1 && isReg32 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x3Buy |] r1 r2
  | TwoOperands (OprReg r1, OprReg r2) when isReg64 r1 && isReg64 r2 ->
    no32Arch ctxt.Arch
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x3Buy |] r1 r2
  (* Reg - Mem *)
  | TwoOperands (OprReg r, Label _) ->
    encRL ctxt ins r [| 0x3Auy |] [| 0x3Buy |]
  | TwoOperands (OprReg r, OprMem (b, s, d, 8<rt>)) when isReg8 r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x3Auy |] r b s d
  | TwoOperands (OprReg r, OprMem (b, s, d, 16<rt>)) when isReg16 r ->
    encRM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x3Buy |] r b s d
  | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isReg32 r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x3Buy |] r b s d
  | TwoOperands (OprReg r, OprMem (b, s, d, 64<rt>)) when isReg64 r ->
    no32Arch ctxt.Arch
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x3Buy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let cmpsb (ctxt: EncContext) ins =
  match ins.Operands with
  | NoOperand ->
    encNP ins ctxt.Arch
      ctxt.PrefREP ctxt.RexNormal [| 0xA6uy |]
  | o -> printfn "%A" o; raise NotEncodableException

let cmpxchg (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isReg8 r1 && isReg8 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexMR [| 0x0Fuy; 0xB0uy |] r2 r1
  | TwoOperands (OprReg r1, OprReg r2) when isReg16 r1 && isReg16 r2 ->
    encRR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexMR [| 0x0Fuy; 0xB1uy |] r2 r1
  | TwoOperands (OprReg r1, OprReg r2) when isReg32 r1 && isReg32 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexMR [| 0x0Fuy; 0xB1uy |] r2 r1
  | TwoOperands (OprReg r1, OprReg r2) when isReg64 r1 && isReg64 r2 ->
    no32Arch ctxt.Arch
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexWAndMR [| 0x0Fuy; 0xB1uy |] r2 r1
  | TwoOperands (Label _, OprReg r) ->
    encRL ctxt ins r [| 0x0Fuy; 0xB0uy |] [| 0x0Fuy; 0xB1uy |]
  | TwoOperands (OprMem (b, s, d, 8<rt>), OprReg r) when isReg8 r ->
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0xB0uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprReg r) when isReg16 r ->
    encMR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0xB1uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprReg r) when isReg32 r ->
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0xB1uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprReg r) when isReg64 r ->
    no32Arch ctxt.Arch
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x0Fuy; 0xB1uy |] b s d r
  | o -> printfn "%A" o; raise NotEncodableException

let cmpxchg8b (ctxt: EncContext) ins =
  match ins.Operands with
  | OneOperand (OprMem (b, s, d, 64<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0xC7uy |] b s d 0b001uy
  | o -> printfn "%A" o; raise NotEncodableException

let cmpxchg16b (ctxt: EncContext) ins =
  match ins.Operands with
  | OneOperand (OprMem (b, s, d, 128<rt>)) ->
    no32Arch ctxt.Arch
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x0Fuy; 0xC7uy |] b s d 0b001uy
  | o -> printfn "%A" o; raise NotEncodableException

let cvtsd2ss (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefF2 ctxt.RexNormal [| 0x0Fuy; 0x5Auy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 64<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefF2 ctxt.RexNormal [| 0x0Fuy; 0x5Auy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let cvtsi2sd (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isReg32 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefF2 ctxt.RexNormal [| 0x0Fuy; 0x2Auy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefF2 ctxt.RexNormal [| 0x0Fuy; 0x2Auy |] r b s d
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isReg64 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefF2 ctxt.RexW [| 0x0Fuy; 0x2Auy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 64<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefF2 ctxt.RexW [| 0x0Fuy; 0x2Auy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let cvtsi2ss (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isReg32 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefF3 ctxt.RexNormal [| 0x0Fuy; 0x2Auy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefF3 ctxt.RexNormal [| 0x0Fuy; 0x2Auy |] r b s d
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isReg64 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefF3 ctxt.RexW [| 0x0Fuy; 0x2Auy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 64<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefF3 ctxt.RexW [| 0x0Fuy; 0x2Auy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let cvtss2si (ctxt: EncContext) ins =
   match ins.Operands with
   | TwoOperands (OprReg r1, OprReg r2) when isReg32 r1 && isXMMReg r2 ->
     encRR ins ctxt.Arch
       ctxt.PrefF3 ctxt.RexNormal [| 0x0Fuy; 0x2Duy |] r1 r2
   | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isReg32 r ->
     encRM ins ctxt.Arch
       ctxt.PrefF3 ctxt.RexNormal [| 0x0Fuy; 0x2Duy |] r b s d
   | TwoOperands (OprReg r1, OprReg r2) when isReg64 r1 && isXMMReg r2 ->
     encRR ins ctxt.Arch
       ctxt.PrefF3 ctxt.RexW [| 0x0Fuy; 0x2Duy |] r1 r2
   | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isReg64 r ->
     encRM ins ctxt.Arch
       ctxt.PrefF3 ctxt.RexW [| 0x0Fuy; 0x2Duy |] r b s d
   | o -> printfn "%A" o; raise NotEncodableException

let cvttss2si (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isReg32 r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefF3 ctxt.RexNormal [| 0x0Fuy; 0x2Cuy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isReg32 r ->
    encRM ins ctxt.Arch
      ctxt.PrefF3 ctxt.RexNormal [| 0x0Fuy; 0x2Cuy |] r b s d
  | TwoOperands (OprReg r1, OprReg r2) when isReg64 r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefF3 ctxt.RexW [| 0x0Fuy; 0x2Cuy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 64<rt>)) when isReg64 r ->
    encRM ins ctxt.Arch
      ctxt.PrefF3 ctxt.RexW [| 0x0Fuy; 0x2Cuy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let cwde _ctxt = function
  | NoOperand -> [| Normal 0x98uy |]
  | _ -> raise NotEncodableException

let dec (ctxt: EncContext) ins =
  match ins.Operands with
  | OneOperand (OprReg r) when isReg8 r ->
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xFEuy |] r 0b001uy
  | OneOperand (OprMem (b, s, d, 8<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xFEuy |] b s d 0b001uy
  | OneOperand (OprReg r) when isReg16 r && ctxt.Arch = Arch.IntelX86 ->
    encO ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal 0x48uy r
  | OneOperand (OprReg r) when isReg16 r ->
    encR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0xFFuy |] r 0b001uy
  | OneOperand (OprMem (b, s, d, 16<rt>)) ->
    encM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0xFFuy |] b s d 0b001uy
  | OneOperand (OprReg r) when isReg32 r && ctxt.Arch = Arch.IntelX86 ->
    encO ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal 0x48uy r
  | OneOperand (OprReg r) when isReg32 r ->
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xFFuy |] r 0b001uy
  | OneOperand (OprMem (b, s, d, 32<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xFFuy |] b s d 0b001uy
  | OneOperand (OprReg r) when isReg64 r ->
    no32Arch ctxt.Arch
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0xFFuy |] r 0b001uy
  | OneOperand (OprMem (b, s, d, 64<rt>)) ->
    no32Arch ctxt.Arch
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0xFFuy |] b s d 0b001uy
  | o -> printfn "%A" o; raise NotEncodableException

let div (ctxt: EncContext) ins =
  match ins.Operands with
  | OneOperand (OprReg r) when isReg8 r ->
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xF6uy |] r 0b110uy
  | OneOperand (OprMem (b, s, d, 8<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xF6uy |] b s d 0b110uy
  | OneOperand (OprReg r) when isReg16 r ->
    encR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0xF7uy |] r 0b110uy
  | OneOperand (OprMem (b, s, d, 16<rt>)) ->
    encM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0xF7uy |] b s d 0b110uy
  | OneOperand (OprReg r) when isReg32 r ->
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xF7uy |] r 0b110uy
  | OneOperand (OprMem (b, s, d, 32<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xF7uy |] b s d 0b110uy
  | OneOperand (OprReg r) when isReg64 r ->
    no32Arch ctxt.Arch
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0xF7uy |] r 0b110uy
  | OneOperand (OprMem (b, s, d, 64<rt>)) ->
    no32Arch ctxt.Arch
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0xF7uy |] b s d 0b110uy
  | o -> printfn "%A" o; raise NotEncodableException

let divsd (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefF2 ctxt.RexNormal [| 0x0Fuy; 0x5Euy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 64<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefF2 ctxt.RexNormal [| 0x0Fuy; 0x5Euy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let divss (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefF3 ctxt.RexNormal [| 0x0Fuy; 0x5Euy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefF3 ctxt.RexNormal [| 0x0Fuy; 0x5Euy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let fadd (ctxt: EncContext) ins =
  match ins.Operands with
  | OneOperand (OprMem (b, s, d, 32<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xD8uy |] b s d 0b000uy
  | OneOperand (OprMem (b, s, d, 64<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xDCuy |] b s d 0b000uy
  | TwoOperands (OprReg Register.ST0, OprReg r) when isFPUReg r ->
    encFR [| 0xD8uy; 0xC0uy |] r
  | TwoOperands (OprReg r, OprReg Register.ST0) when isFPUReg r ->
    encFR [| 0xDCuy; 0xC0uy |] r
  | o -> printfn "%A" o; raise NotEncodableException

let fcmovb _ctxt ins =
  match ins.Operands with
  | TwoOperands (OprReg Register.ST0, OprReg r) when isFPUReg r ->
    encFR [| 0xDAuy; 0xC0uy |] r
  | o -> printfn "%A" o; raise NotEncodableException

let fdiv (ctxt: EncContext) ins =
  match ins.Operands with
  | OneOperand (OprMem (b, s, d, 32<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xD8uy |] b s d 0b110uy
  | OneOperand (OprMem (b, s, d, 64<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xDCuy |] b s d 0b110uy
  | TwoOperands (OprReg Register.ST0, OprReg r) when isFPUReg r ->
    encFR [| 0xD8uy; 0xF0uy |] r
  | TwoOperands (OprReg r, OprReg Register.ST0) when isFPUReg r ->
    encFR [| 0xDCuy; 0xF8uy |] r
  | o -> printfn "%A" o; raise NotEncodableException

let fdivp _ctxt = function
  | NoOperand -> [| Normal 0xDEuy; Normal 0xF9uy |]
  | TwoOperands (OprReg r, OprReg Register.ST0) when isFPUReg r ->
    encFR [| 0xDEuy; 0xF8uy |] r
  | o -> printfn "%A" o; raise NotEncodableException

let fdivrp _ctxt = function
  | NoOperand -> [| Normal 0xDEuy; Normal 0xF1uy |]
  | TwoOperands (OprReg r, OprReg Register.ST0) when isFPUReg r ->
    encFR [| 0xDEuy; 0xF0uy |] r
  | o -> printfn "%A" o; raise NotEncodableException

let fild (ctxt: EncContext) ins =
  match ins.Operands with
  | OneOperand (OprMem (b, s, d, 16<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xDFuy |] b s d 0b000uy
  | OneOperand (OprMem (b, s, d, 32<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xDBuy |] b s d 0b000uy
  | OneOperand (OprMem (b, s, d, 64<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xDFuy |] b s d 0b101uy
  | o -> printfn "%A" o; raise NotEncodableException

let fistp (ctxt: EncContext) ins =
  match ins.Operands with
  | OneOperand (OprMem (b, s, d, 16<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xDFuy |] b s d 0b011uy
  | OneOperand (OprMem (b, s, d, 32<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xDBuy |] b s d 0b011uy
  | OneOperand (OprMem (b, s, d, 64<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xDFuy |] b s d 0b111uy
  | o -> printfn "%A" o; raise NotEncodableException

let fld (ctxt: EncContext) ins =
  match ins.Operands with
  | OneOperand (OprMem (b, s, d, 32<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xD9uy |] b s d 0b000uy
  | OneOperand (OprMem (b, s, d, 64<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xDDuy |] b s d 0b000uy
  | OneOperand (OprMem (b, s, d, 80<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xDBuy |] b s d 0b101uy
  | OneOperand (OprReg r) when isFPUReg r -> encFR [| 0xD9uy; 0xC0uy |] r
  | o -> printfn "%A" o; raise NotEncodableException

let fld1 _ctxt = function
  | NoOperand -> [| Normal 0xD9uy; Normal 0xE8uy |]
  | o -> printfn "%A" o; raise NotEncodableException

let fldcw (ctxt: EncContext) ins =
  match ins.Operands with
  | OneOperand (OprMem (b, s, d, 16<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xD9uy |] b s d 0b101uy
  | o -> printfn "%A" o; raise NotEncodableException

let fldz _ctxt = function
  | NoOperand -> [| Normal 0xD9uy; Normal 0xEEuy |]
  | o -> printfn "%A" o; raise NotEncodableException

let fmul (ctxt: EncContext) ins =
  match ins.Operands with
  | OneOperand (OprMem (b, s, d, 32<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xD8uy |] b s d 0b001uy
  | OneOperand (OprMem (b, s, d, 64<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xDCuy |] b s d 0b001uy
  | TwoOperands (OprReg Register.ST0, OprReg r) when isFPUReg r ->
    encFR [| 0xD8uy; 0xC8uy |] r
  | TwoOperands (OprReg r, OprReg Register.ST0) when isFPUReg r ->
    encFR [| 0xDCuy; 0xC8uy |] r
  | o -> printfn "%A" o; raise NotEncodableException

let fmulp _ctxt = function
  | NoOperand -> [| Normal 0xDEuy; Normal 0xC9uy |]
  | TwoOperands (OprReg r, OprReg Register.ST0) when isFPUReg r ->
    encFR [| 0xDEuy; 0xC8uy |] r
  | o -> printfn "%A" o; raise NotEncodableException

let fnstcw (ctxt: EncContext) ins =
  match ins.Operands with
  | OneOperand (OprMem (b, s, d, 16<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xD9uy |] b s d 0b111uy
  | o -> printfn "%A" o; raise NotEncodableException

let fstp (ctxt: EncContext) ins =
  match ins.Operands with
  | OneOperand (OprMem (b, s, d, 32<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xD9uy |] b s d 0b011uy
  | OneOperand (OprMem (b, s, d, 64<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xDDuy |] b s d 0b011uy
  | OneOperand (OprMem (b, s, d, 80<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xDBuy |] b s d 0b111uy
  | OneOperand (OprReg r) when isFPUReg r -> encFR [| 0xDDuy; 0xD8uy |] r
  | o -> printfn "%A" o; raise NotEncodableException

let fsub (ctxt: EncContext) ins =
  match ins.Operands with
  | OneOperand (OprMem (b, s, d, 32<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xD8uy |] b s d 0b100uy
  | OneOperand (OprMem (b, s, d, 64<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xDCuy |] b s d 0b100uy
  | TwoOperands (OprReg Register.ST0, OprReg r) when isFPUReg r ->
    encFR [| 0xD8uy; 0xE0uy |] r
  | TwoOperands (OprReg r, OprReg Register.ST0) when isFPUReg r ->
    encFR [| 0xDCuy; 0xE8uy |] r
  | o -> printfn "%A" o; raise NotEncodableException

let fsubr (ctxt: EncContext) ins =
  match ins.Operands with
  | OneOperand (OprMem (b, s, d, 32<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xD8uy |] b s d 0b101uy
  | OneOperand (OprMem (b, s, d, 64<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xDCuy |] b s d 0b101uy
  | TwoOperands (OprReg Register.ST0, OprReg r) when isFPUReg r ->
    encFR [| 0xD8uy; 0xE8uy |] r
  | TwoOperands (OprReg r, OprReg Register.ST0) when isFPUReg r ->
    encFR [| 0xDCuy; 0xE0uy |] r
  | o -> printfn "%A" o; raise NotEncodableException

let fucomi _ctxt = function
  | TwoOperands (OprReg Register.ST0, OprReg r) when isFPUReg r ->
    encFR [| 0xDBuy; 0xE8uy |] r
  | o -> printfn "%A" o; raise NotEncodableException

let fucomip _ctxt = function
  | TwoOperands (OprReg Register.ST0, OprReg r) when isFPUReg r ->
    encFR [| 0xDFuy; 0xE8uy |] r
  | o -> printfn "%A" o; raise NotEncodableException

let fxch _ctxt = function
  | NoOperand -> [| Normal 0xD9uy; Normal 0xC9uy |]
  | OneOperand (OprReg r) when isFPUReg r -> encFR [| 0xD9uy; 0xC8uy |] r
  | o -> printfn "%A" o; raise NotEncodableException

let hlt _ctxt = function
  | NoOperand -> [| Normal 0xF4uy |]
  | _ -> raise NotEncodableException

let idiv (ctxt: EncContext) ins =
  match ins.Operands with
  | OneOperand (OprReg r) when isReg8 r ->
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xF6uy |] r 0b111uy
  | OneOperand (OprMem (b, s, d, 8<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xF6uy |] b s d 0b111uy
  | OneOperand (OprReg r) when isReg16 r ->
    encR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0xF7uy |] r 0b111uy
  | OneOperand (OprMem (b, s, d, 16<rt>)) ->
    encM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0xF7uy |] b s d 0b111uy
  | OneOperand (OprReg r) when isReg32 r ->
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xF7uy |] r 0b111uy
  | OneOperand (OprMem (b, s, d, 32<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xF7uy |] b s d 0b111uy
  | OneOperand (OprReg r) when isReg64 r ->
    no32Arch ctxt.Arch
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0xF7uy |] r 0b111uy
  | OneOperand (OprMem (b, s, d, 64<rt>)) ->
    no32Arch ctxt.Arch
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0xF7uy |] b s d 0b111uy
  | o -> printfn "%A" o; raise NotEncodableException

let imul (ctxt: EncContext) ins =
  match ins.Operands with
  | OneOperand (OprReg r) when isReg8 r ->
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xF6uy |] r 0b101uy
  | OneOperand (OprMem (b, s, d, 8<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xF6uy |] b s d 0b101uy
  | OneOperand (OprReg r) when isReg16 r ->
    encR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0xF7uy |] r 0b101uy
  | OneOperand (OprMem (b, s, d, 16<rt>)) ->
    encM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0xF7uy |] b s d 0b101uy
  | OneOperand (OprReg r) when isReg32 r ->
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xF7uy |] r 0b101uy
  | OneOperand (OprMem (b, s, d, 32<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xF7uy |] b s d 0b101uy
  | OneOperand (OprReg r) when isReg64 r ->
    no32Arch ctxt.Arch
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0xF7uy |] r 0b101uy
  | OneOperand (OprMem (b, s, d, 64<rt>)) ->
    no32Arch ctxt.Arch
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0xF7uy |] b s d 0b101uy
  | TwoOperands (OprReg r1, OprReg r2) when isReg16 r1 && isReg16 r2 ->
    encRR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0xAFuy |] r1 r2
  | TwoOperands (OprReg r, Label _) ->
    encRL ctxt ins r [||] [| 0x0Fuy; 0xAFuy |]
  | TwoOperands (OprReg r, OprMem (b, s, d, 16<rt>)) when isReg16 r ->
    encRM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0xAFuy |] r b s d
  | TwoOperands (OprReg r1, OprReg r2) when isReg32 r1 && isReg32 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0xAFuy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isReg32 r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0xAFuy |] r b s d
  | TwoOperands (OprReg r1, OprReg r2) when isReg64 r1 && isReg64 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x0Fuy; 0xAFuy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 64<rt>)) when isReg64 r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x0Fuy; 0xAFuy |] r b s d
  | ThreeOperands (OprReg r1, OprReg r2, OprImm (imm, _))
    when isReg16 r1 && isReg16 r2 && isInt8 imm ->
    encRRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x6Buy |] r1 r2 imm 8<rt>
  | ThreeOperands (OprReg r, Label _, OprImm (imm, _)) when isInt8 imm ->
    encRLI ctxt ins r [| 0x6Buy |] imm 8<rt>
  | ThreeOperands (OprReg r, OprMem (b, s, d, 16<rt>), OprImm (imm, _))
    when isReg16 r && isInt8 imm ->
    encRMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x6Buy |] r b s d imm 8<rt>
  | ThreeOperands (OprReg r1, OprReg r2, OprImm (imm, _))
    when isReg32 r1 && isReg32 r2 && isInt8 imm ->
    encRRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x6Buy |] r1 r2 imm 8<rt>
  | ThreeOperands (OprReg r, OprMem (b, s, d, 32<rt>), OprImm (imm, _))
    when isReg32 r && isInt8 imm ->
    encRMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x6Buy |] r b s d imm 8<rt>
  | ThreeOperands (OprReg r1, OprReg r2, OprImm (imm, _))
    when isReg64 r1 && isReg64 r2 && isInt8 imm ->
    no32Arch ctxt.Arch
    encRRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x6Buy |] r1 r2 imm 8<rt>
  | ThreeOperands (OprReg r, OprMem (b, s, d, 64<rt>), OprImm (imm, _))
    when isReg64 r && isInt8 imm ->
    no32Arch ctxt.Arch
    encRMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x6Buy |] r b s d imm 8<rt>
  | ThreeOperands (OprReg r1, OprReg r2, OprImm (imm, _))
    when isReg16 r1 && isReg16 r2 ->
    encRRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x69uy |] r1 r2 imm 16<rt>
  | ThreeOperands (OprReg r, Label _, OprImm (imm, _)) ->
    encRLI ctxt ins r [| 0x69uy |] imm 32<rt> // FIXME
  | ThreeOperands (OprReg r, OprMem (b, s, d, 16<rt>), OprImm (imm, _))
    when isReg16 r ->
    encRMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x69uy |] r b s d imm 16<rt>
  | ThreeOperands (OprReg r1, OprReg r2, OprImm (imm, _))
    when isReg32 r1 && isReg32 r2 ->
    encRRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x69uy |] r1 r2 imm 32<rt>
  | ThreeOperands (OprReg r, OprMem (b, s, d, 32<rt>), OprImm (imm, _))
    when isReg32 r ->
    encRMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x69uy |] r b s d imm 32<rt>
  | ThreeOperands (OprReg r1, OprReg r2, OprImm (imm, _))
    when isReg64 r1 && isReg64 r2 ->
    no32Arch ctxt.Arch
    encRRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x69uy |] r1 r2 imm 32<rt>
  | ThreeOperands (OprReg r, OprMem (b, s, d, 64<rt>), OprImm (imm, _))
    when isReg64 r ->
    no32Arch ctxt.Arch
    encRMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x69uy |] r b s d imm 32<rt>
  | o -> printfn "%A" o; raise NotEncodableException

let inc (ctxt: EncContext) ins =
  match ins.Operands with
  | OneOperand (OprReg r) when isReg8 r ->
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xFEuy |] r 0b000uy
  | OneOperand (OprMem (b, s, d, 8<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xFEuy |] b s d 0b000uy
  | OneOperand (OprReg r) when isReg16 r && ctxt.Arch = Arch.IntelX86 ->
    encO ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal 0x40uy r
  | OneOperand (OprReg r) when isReg16 r ->
    encR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0xFFuy |] r 0b000uy
  | OneOperand (OprMem (b, s, d, 16<rt>)) ->
    encM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0xFFuy |] b s d 0b000uy
  | OneOperand (OprReg r) when isReg32 r && ctxt.Arch = Arch.IntelX86 ->
    encO ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal 0x40uy r
  | OneOperand (OprReg r) when isReg32 r ->
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xFFuy |] r 0b000uy
  | OneOperand (OprMem (b, s, d, 32<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xFFuy |] b s d 0b000uy
  | OneOperand (OprReg r) when isReg64 r ->
    no32Arch ctxt.Arch
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0xFFuy |] r 0b000uy
  | OneOperand (OprMem (b, s, d, 64<rt>)) ->
    no32Arch ctxt.Arch
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0xFFuy |] b s d 0b000uy
  | o -> printfn "%A" o; raise NotEncodableException

let interrupt ins =
  match ins.Operands with
  | OneOperand (OprImm (n, _)) when isUInt8 n ->
    [| Normal 0xcduy; Normal (byte n) |]
  | o -> printfn "%A" o; raise NotEncodableException

let interrupt3 () = [| Normal 0xccuy |]

let jcc (ctxt: EncContext) ins op8Byte opByte op =
  match ins.Operands with
  | OneOperand (Label _) ->
    encLbl ins // FIXME
  | OneOperand (OprDirAddr (Relative rel)) when isInt8 rel ->
    encD ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| op8Byte |] rel 8<rt>
  | OneOperand (OprDirAddr (Relative rel))
    when isInt16 rel && ctxt.Arch = Arch.IntelX86 ->
    encD ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal opByte rel 16<rt>
  | OneOperand (OprDirAddr (Relative rel)) when isInt32 rel ->
    encD ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal opByte rel 32<rt>
  | o -> printfn "%A" o; raise NotEncodableException

let ja ctxt ins = jcc ctxt ins 0x77uy [| 0x0Fuy; 0x87uy |] Opcode.JA
let jb ctxt ins = jcc ctxt ins 0x72uy [| 0x0Fuy; 0x82uy |] Opcode.JB
let jbe ctxt ins = jcc ctxt ins 0x76uy [| 0x0Fuy; 0x86uy |] Opcode.JBE
let jg ctxt ins = jcc ctxt ins 0x7Fuy [| 0x0Fuy; 0x8Fuy |] Opcode.JG
let jl ctxt ins = jcc ctxt ins 0x7Cuy [| 0x0Fuy; 0x8Cuy |] Opcode.JL
let jle ctxt ins = jcc ctxt ins 0x7Euy [| 0x0Fuy; 0x8Euy |] Opcode.JLE
let jnb ctxt ins = jcc ctxt ins 0x73uy [| 0x0Fuy; 0x83uy |] Opcode.JNB
let jnl ctxt ins = jcc ctxt ins 0x7Duy [| 0x0Fuy; 0x8Duy |] Opcode.JNL
let jno ctxt ins = jcc ctxt ins 0x71uy [| 0x0Fuy; 0x81uy |] Opcode.JNO
let jnp ctxt ins = jcc ctxt ins 0x7Buy [| 0x0Fuy; 0x8Buy |] Opcode.JNP
let jns ctxt ins = jcc ctxt ins 0x79uy [| 0x0Fuy; 0x89uy |] Opcode.JNS
let jnz ctxt ins = jcc ctxt ins 0x75uy [| 0x0Fuy; 0x85uy |] Opcode.JNZ
let jo ctxt ins = jcc ctxt ins 0x70uy [| 0x0Fuy; 0x80uy |] Opcode.JO
let jp ctxt ins = jcc ctxt ins 0x7auy [| 0x0Fuy; 0x8Auy |] Opcode.JP
let js ctxt ins = jcc ctxt ins 0x78uy [| 0x0Fuy; 0x88uy |] Opcode.JS
let jz ctxt ins = jcc ctxt ins 0x74uy [| 0x0Fuy; 0x84uy |] Opcode.JZ

let jmp (ctxt: EncContext) ins =
  match ins.Operands with
  | OneOperand (Label _) ->
    encLbl ins // FIXME
  | OneOperand (OprDirAddr (Relative rel)) when isInt8 rel ->
    encD ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xEBuy |] rel 8<rt>
  | OneOperand (OprDirAddr (Relative rel)) when isInt32 rel ->
    encD ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xE9uy |] rel 32<rt>
  | OneOperand (OprReg r) when isReg32 r ->
    no64Arch ctxt.Arch (* N.S. *)
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xFFuy |] r 0b100uy
  | OneOperand (OprMem (b, s, d, 32<rt>)) ->
    no64Arch ctxt.Arch (* N.S. *)
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xFFuy |] b s d 0b100uy
  | OneOperand (OprReg r) when isReg64 r ->
    no32Arch ctxt.Arch
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xFFuy |] r 0b100uy
  | OneOperand (OprMem (b, s, d, 64<rt>)) ->
    no32Arch ctxt.Arch
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xFFuy |] b s d 0b100uy
  | o -> printfn "%A" o; raise NotEncodableException

let lahf (ctxt: EncContext) = function
  | NoOperand -> no64Arch ctxt.Arch; [| Normal 0x9Fuy |]
  | _ -> raise NotEncodableException

let lea (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r, Label _) ->
    encRL ctxt ins r [||] [| 0x8Duy |]
  | TwoOperands (OprReg r, OprMem (b, s, d, 16<rt>)) when isReg16 r ->
    encRM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x8Duy |] r b s d
  | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isReg32 r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x8Duy |] r b s d
  | TwoOperands (OprReg r, OprMem (b, s, d, 64<rt>)) when isReg64 r ->
    no32Arch ctxt.Arch
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x8Duy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let leave (ctxt: EncContext) = function
  | NoOperand -> no64Arch ctxt.Arch; [| Normal 0xC9uy |]
  | _ -> raise NotEncodableException

let mov (ctxt: EncContext) ins =
  match ins.Operands with
  (* Reg - Sreg *)
  | TwoOperands (OprReg r1, OprReg r2) when isReg16 r1 && isSegReg r2 ->
    encRR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexMR [| 0x8Cuy |] r2 r1
  | TwoOperands (OprReg r1, OprReg r2) when isReg64 r1 && isSegReg r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexWAndMR [| 0x8Cuy |] r2 r1
  (* Mem - Sreg *)
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprReg r) when isSegReg r ->
    encMR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x8Cuy |] b s d r
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprReg r) when isSegReg r ->
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexWAndMR [| 0x8Cuy |] b s d r
  (* Mem - Reg *)
  | TwoOperands (Label _, OprReg r) ->
    encRL ctxt ins r [| 0x88uy |] [| 0x89uy |]
  | TwoOperands (OprMem (b, s, d, 8<rt>), OprReg r) when isReg8 r ->
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x88uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprReg r) when isReg16 r ->
    encMR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x89uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprReg r) when isReg32 r ->
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x89uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprReg r) when isReg64 r ->
    no32Arch ctxt.Arch
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x89uy |] b s d r
  (* Reg - Reg *)
  | TwoOperands (OprReg r1, OprReg r2) when isReg8 r1 && isReg8 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x8Auy |] r1 r2
  | TwoOperands (OprReg r1, OprReg r2) when isReg16 r1 && isReg16 r2 ->
    encRR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x8Buy |] r1 r2
  | TwoOperands (OprReg r1, OprReg r2) when isReg32 r1 && isReg32 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x8Buy |] r1 r2
  | TwoOperands (OprReg r1, OprReg r2) when isReg64 r1 && isReg64 r2 ->
    no32Arch ctxt.Arch
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x8Buy |] r1 r2
  (* Reg - Mem *)
  | TwoOperands (OprReg r, Label _) ->
    encRL ctxt ins r [| 0x8Auy |] [| 0x8Buy |]
  | TwoOperands (OprReg r, OprMem (b, s, d, 8<rt>)) when isReg8 r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x8Auy |] r b s d
  | TwoOperands (OprReg r, OprMem (b, s, d, 16<rt>)) when isReg16 r ->
    encRM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x8Buy |] r b s d
  | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isReg32 r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x8Buy |] r b s d
  | TwoOperands (OprReg r, OprMem (b, s, d, 64<rt>)) when isReg64 r ->
    no32Arch ctxt.Arch
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x8Buy |] r b s d
  (* Reg - Imm (Opcode reg field) *)
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg8 r ->
    encOI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal 0xB0uy r imm 8<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg16 r ->
    encOI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal 0xB8uy r imm 16<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg32 r ->
    encOI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal 0xB8uy r imm 32<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg64 r && isInt32 imm ->
    no32Arch ctxt.Arch
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0xC7uy |] r 0b000uy imm 32<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg64 r ->
    no32Arch ctxt.Arch
    encOI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW 0xB8uy r imm 64<rt>
  (* Mem - Imm *)
  | TwoOperands (Label _, OprImm (imm, _)) ->
    encLI ctxt ins 0b000uy imm 32<rt> [| 0xC6uy |] [| 0xC7uy |] // FIXME
  | TwoOperands (OprMem (b, s, d, 8<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xC6uy |] b s d 0b000uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0xC7uy |] b s d 0b000uy imm 16<rt>
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xC7uy |] b s d 0b000uy imm 32<rt>
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprImm (imm, _)) ->
    no32Arch ctxt.Arch;
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0xC7uy |] b s d 0b000uy imm 32<rt>
  | o -> printfn "%A" o; raise NotEncodableException

let movaps (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0x28uy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 128<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0x28uy |] r b s d
  | TwoOperands (OprMem (b, s, d, 128<rt>), OprReg r) when isXMMReg r ->
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0x29uy |] b s d r
  | o -> printfn "%A" o; raise NotEncodableException

let movd (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isMMXReg r1 && isReg32 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0x6Euy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isMMXReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0x6Euy |] r b s d
  | TwoOperands (OprReg r1, OprReg r2) when isReg32 r1 && isMMXReg r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexMR [| 0x0Fuy; 0x7Euy |] r2 r1
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprReg r) when isMMXReg r ->
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0x7Euy |] b s d r
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isReg32 r2 ->
    encRR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0x6Euy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0x6Euy |] r b s d
  | TwoOperands (OprReg r1, OprReg r2) when isReg32 r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexMR [| 0x0Fuy; 0x7Euy |] r2 r1
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprReg r) when isXMMReg r ->
    encMR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0x7Euy |] b s d r
  | o -> printfn "%A" o; raise NotEncodableException

let movdqa (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0x6Fuy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 128<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0x6Fuy |] r b s d
  | TwoOperands (OprMem (b, s, d, 128<rt>), OprReg r) when isXMMReg r ->
    encMR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0x7Fuy |] b s d r
  | o -> printfn "%A" o; raise NotEncodableException

let movdqu (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefF3 ctxt.RexNormal [| 0x0Fuy; 0x6Fuy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 128<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefF3 ctxt.RexNormal [| 0x0Fuy; 0x6Fuy |] r b s d
  | TwoOperands (OprMem (b, s, d, 128<rt>), OprReg r) when isXMMReg r ->
    encMR ins ctxt.Arch
      ctxt.PrefF3 ctxt.RexNormal [| 0x0Fuy; 0x7Fuy |] b s d r
  | o -> printfn "%A" o; raise NotEncodableException

let movsd (ctxt: EncContext) ins =
  match ins.Operands with
  | NoOperand -> [| Normal 0xA5uy |]
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefF2 ctxt.RexNormal [| 0x0Fuy; 0x10uy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 64<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefF2 ctxt.RexNormal [| 0x0Fuy; 0x10uy |] r b s d
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprReg r) when isXMMReg r ->
    encMR ins ctxt.Arch
      ctxt.PrefF2 ctxt.RexNormal [| 0x0Fuy; 0x11uy |] b s d r
  | o -> printfn "%A" o; raise NotEncodableException

let movss (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefF3 ctxt.RexNormal [| 0x0Fuy; 0x10uy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefF3 ctxt.RexNormal [| 0x0Fuy; 0x10uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let movsx (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isReg16 r1 && isReg8 r2 ->
    encRR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0xBEuy |] r1 r2
  | TwoOperands (OprReg r, Label _) ->
    encRL ctxt ins r [||] [| 0x0Fuy; 0xBEuy |]
  | TwoOperands (OprReg r, OprMem (b, s, d, 8<rt>)) when isReg16 r ->
    encRM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0xBEuy |] r b s d
  | TwoOperands (OprReg r1, OprReg r2) when isReg32 r1 && isReg8 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0xBEuy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 8<rt>)) when isReg32 r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0xBEuy |] r b s d
  | TwoOperands (OprReg r1, OprReg r2) when isReg64 r1 && isReg8 r2 ->
    no32Arch ctxt.Arch
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x0Fuy; 0xBEuy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 8<rt>)) when isReg64 r ->
    no32Arch ctxt.Arch
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x0Fuy; 0xBEuy |] r b s d
  | TwoOperands (OprReg r1, OprReg r2) when isReg32 r1 && isReg16 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0xBFuy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 16<rt>)) when isReg32 r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0xBFuy |] r b s d
  | TwoOperands (OprReg r1, OprReg r2) when isReg64 r1 && isReg16 r2 ->
    no32Arch ctxt.Arch
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x0Fuy; 0xBFuy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 16<rt>)) when isReg64 r ->
    no32Arch ctxt.Arch
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x0Fuy; 0xBFuy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let movsxd (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isReg64 r1 && isReg32 r2 ->
    no32Arch ctxt.Arch
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x63uy |] r1 r2
  | TwoOperands (OprReg r, Label _) ->
    encRL ctxt ins r [||] [| 0x63uy |]
  | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isReg64 r ->
    no32Arch ctxt.Arch
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x63uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let movups (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0x10uy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 128<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0x10uy |] r b s d
  | TwoOperands (OprMem (b, s, d, 128<rt>), OprReg r) when isXMMReg r ->
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0x11uy |] b s d r
  | o -> printfn "%A" o; raise NotEncodableException

let movzx (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isReg16 r1 && isReg8 r2 ->
    encRR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0xB6uy |] r1 r2
  | TwoOperands (OprReg r, Label _) ->
    encRL ctxt ins r [||] [| 0x0Fuy; 0xB6uy |]
  | TwoOperands (OprReg r, OprMem (b, s, d, 8<rt>)) when isReg16 r ->
    encRM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0xB6uy |] r b s d
  | TwoOperands (OprReg r1, OprReg r2) when isReg32 r1 && isReg8 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0xB6uy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 8<rt>)) when isReg32 r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0xB6uy |] r b s d
  | TwoOperands (OprReg r1, OprReg r2) when isReg64 r1 && isReg8 r2 ->
    no32Arch ctxt.Arch
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x0Fuy; 0xB6uy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 8<rt>)) when isReg64 r ->
    no32Arch ctxt.Arch
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x0Fuy; 0xB6uy |] r b s d
  | TwoOperands (OprReg r1, OprReg r2) when isReg32 r1 && isReg16 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0xB7uy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 16<rt>)) when isReg32 r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0xB7uy |] r b s d
  | TwoOperands (OprReg r1, OprReg r2) when isReg64 r1 && isReg16 r2 ->
    no32Arch ctxt.Arch
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x0Fuy; 0xB7uy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 16<rt>)) when isReg64 r ->
    no32Arch ctxt.Arch
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x0Fuy; 0xB7uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let mul (ctxt: EncContext) ins =
  match ins.Operands with
  | OneOperand (OprReg r) when isReg8 r ->
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xF6uy |] r 0b100uy
  | OneOperand (OprMem (b, s, d, 8<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xF6uy |] b s d 0b100uy
  | OneOperand (OprReg r) when isReg16 r ->
    encR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0xF7uy |] r 0b100uy
  | OneOperand (OprMem (b, s, d, 16<rt>)) ->
    encM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0xF7uy |] b s d 0b100uy
  | OneOperand (OprReg r) when isReg32 r ->
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xF7uy |] r 0b100uy
  | OneOperand (OprMem (b, s, d, 32<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xF7uy |] b s d 0b100uy
  | OneOperand (OprReg r) when isReg64 r ->
    no32Arch ctxt.Arch
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0xF7uy |] r 0b100uy
  | OneOperand (OprMem (b, s, d, 64<rt>)) ->
    no32Arch ctxt.Arch
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0xF7uy |] b s d 0b100uy
  | o -> printfn "%A" o; raise NotEncodableException

let mulsd (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefF2 ctxt.RexNormal [| 0x0Fuy; 0x59uy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 64<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefF2 ctxt.RexNormal [| 0x0Fuy; 0x59uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let mulss (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefF3 ctxt.RexNormal [| 0x0Fuy; 0x59uy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefF3 ctxt.RexNormal [| 0x0Fuy; 0x59uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let neg (ctxt: EncContext) ins =
  match ins.Operands with
  | OneOperand (OprReg r) when isReg8 r ->
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xF6uy |] r 0b011uy
  | OneOperand (OprMem (b, s, d, 8<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xF6uy |] b s d 0b011uy
  | OneOperand (OprReg r) when isReg16 r ->
    encR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0xF7uy |] r 0b011uy
  | OneOperand (OprMem (b, s, d, 16<rt>)) ->
    encM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0xF7uy |] b s d 0b011uy
  | OneOperand (OprReg r) when isReg32 r ->
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xF7uy |] r 0b011uy
  | OneOperand (OprMem (b, s, d, 32<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xF7uy |] b s d 0b011uy
  | OneOperand (OprReg r) when isReg64 r ->
    no32Arch ctxt.Arch
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0xF7uy |] r 0b011uy
  | OneOperand (OprMem (b, s, d, 64<rt>)) ->
    no32Arch ctxt.Arch
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0xF7uy |] b s d 0b011uy
  | o -> printfn "%A" o; raise NotEncodableException

let nop (ctxt: EncContext) ins =
  match ins.Operands with
  | NoOperand -> [| Normal 0x90uy |]
  | OneOperand (OprReg r) when isReg16 r ->
    encR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0x1Fuy |] r 0b000uy
  | OneOperand (OprMem (b, s, d, 16<rt>)) ->
    encM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0x1Fuy |] b s d 0b000uy
  | OneOperand (OprReg r) when isReg32 r ->
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0x1Fuy |] r 0b000uy
  | OneOperand (OprMem (b, s, d, 32<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0x1Fuy |] b s d 0b000uy
  | o -> printfn "%A" o; raise NotEncodableException

let not (ctxt: EncContext) ins =
  match ins.Operands with
  | OneOperand (OprReg r) when isReg8 r ->
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xF6uy |] r 0b010uy
  | OneOperand (OprMem (b, s, d, 8<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xF6uy |] b s d 0b010uy
  | OneOperand (OprReg r) when isReg16 r ->
    encR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0xF7uy |] r 0b010uy
  | OneOperand (OprMem (b, s, d, 16<rt>)) ->
    encM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0xF7uy |] b s d 0b010uy
  | OneOperand (OprReg r) when isReg32 r ->
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xF7uy |] r 0b010uy
  | OneOperand (OprMem (b, s, d, 32<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xF7uy |] b s d 0b010uy
  | OneOperand (OprReg r) when isReg64 r ->
    no32Arch ctxt.Arch
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0xF7uy |] r 0b010uy
  | OneOperand (OprMem (b, s, d, 64<rt>)) ->
    no32Arch ctxt.Arch
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0xF7uy |] b s d 0b010uy
  | o -> printfn "%A" o; raise NotEncodableException

let logOr (ctxt: EncContext) ins =
  match ins.Operands with
  (* Reg (fixed) - Imm *)
  | TwoOperands (OprReg Register.AL, OprImm (imm, _)) ->
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Cuy |] imm 8<rt>
  | TwoOperands (OprReg Register.AX, OprImm (imm, _)) ->
    encI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Duy |] imm 16<rt>
  | TwoOperands (OprReg Register.EAX, OprImm (imm, _)) ->
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Duy |] imm 32<rt>
  | TwoOperands (OprReg Register.RAX, OprImm (imm, _)) ->
    no32Arch ctxt.Arch
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x0Duy |] imm 32<rt>
  (* Reg - Imm (Priority 0) *)
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg16 r && isInt8 imm ->
    encRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x83uy |] r 0b001uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg32 r && isInt8 imm ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x83uy |] r 0b001uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg64 r && isInt8 imm ->
    no32Arch ctxt.Arch
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x83uy |] r 0b001uy imm 8<rt>
  (* Mem - Imm (Priority 0) *)
  | TwoOperands (Label _, OprImm (imm, _)) when isInt8 imm ->
    encLI ctxt ins 0b001uy imm 8<rt> [||] [| 0x83uy |]
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprImm (imm, _)) when isInt8 imm ->
    encMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x83uy |] b s d 0b001uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprImm (imm, _)) when isInt8 imm ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x83uy |] b s d 0b001uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprImm (imm, _)) when isInt8 imm ->
    no32Arch ctxt.Arch
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x83uy |] b s d 0b001uy imm 8<rt>
  (* Reg - Imm (Priority 1) *)
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg8 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x80uy |] r 0b001uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg16 r ->
    encRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x81uy |] r 0b001uy imm 16<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg32 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x81uy |] r 0b001uy imm 32<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg64 r ->
    no32Arch ctxt.Arch
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x81uy |] r 0b001uy imm 32<rt>
  (* Mem - Imm (Priority 1) *)
  | TwoOperands (Label _, OprImm (imm, _)) ->
    encLI ctxt ins 0b001uy imm 32<rt> [| 0x80uy |] [| 0x81uy |] // FIXME
  | TwoOperands (OprMem (b, s, d, 8<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x80uy |] b s d 0b001uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x81uy |] b s d 0b001uy imm 16<rt>
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x81uy |] b s d 0b001uy imm 32<rt>
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprImm (imm, _)) ->
    no32Arch ctxt.Arch;
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x81uy |] b s d 0b001uy imm 32<rt>
  (* Mem - Reg *)
  | TwoOperands (Label _, OprReg r) ->
    encRL ctxt ins r [| 0x08uy |] [| 0x09uy |]
  | TwoOperands (OprMem (b, s, d, 8<rt>), OprReg r) when isReg8 r ->
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x08uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprReg r) when isReg16 r ->
    encMR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x09uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprReg r) when isReg32 r ->
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x09uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprReg r) when isReg64 r ->
    no32Arch ctxt.Arch
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x09uy |] b s d r
  (* Reg - Reg *)
  | TwoOperands (OprReg r1, OprReg r2) when isReg8 r1 && isReg8 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Auy |] r1 r2
  | TwoOperands (OprReg r1, OprReg r2) when isReg16 r1 && isReg16 r2 ->
    encRR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Buy |] r1 r2
  | TwoOperands (OprReg r1, OprReg r2) when isReg32 r1 && isReg32 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Buy |] r1 r2
  | TwoOperands (OprReg r1, OprReg r2) when isReg64 r1 && isReg64 r2 ->
    no32Arch ctxt.Arch
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x0Buy |] r1 r2
  (* Reg - Mem *)
  | TwoOperands (OprReg r, Label _) ->
    encRL ctxt ins r [| 0x0Auy |] [| 0x0Buy |]
  | TwoOperands (OprReg r, OprMem (b, s, d, 8<rt>)) when isReg8 r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Auy |] r b s d
  | TwoOperands (OprReg r, OprMem (b, s, d, 16<rt>)) when isReg16 r ->
    encRM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Buy |] r b s d
  | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isReg32 r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Buy |] r b s d
  | TwoOperands (OprReg r, OprMem (b, s, d, 64<rt>)) when isReg64 r ->
    no32Arch ctxt.Arch
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x0Buy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let orpd (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0x56uy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0x56uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let paddd (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0xFEuy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 128<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0xFEuy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let palignr (ctxt: EncContext) ins =
  match ins.Operands with
  (* Reg - Reg - Imm8 *)
  | ThreeOperands (OprReg r1, OprReg r2, OprImm (imm, _))
    when isMMXReg r1 && isMMXReg r2 ->
    encRRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0x3Auy; 0x0Fuy |]
      r1 r2 imm 8<rt>
  | ThreeOperands (OprReg r1, OprReg r2, OprImm (imm, _))
    when isXMMReg r1 && isXMMReg r2 ->
    encRRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0x3Auy; 0x0Fuy |] r1 r2 imm 8<rt>
  (* Reg - Mem - Imm8 *)
  | ThreeOperands (OprReg r, OprMem (b, s, d, 64<rt>), OprImm (imm, _))
    when isMMXReg r ->
    encRMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0x3Auy; 0x0Fuy |]
      r b s d imm 8<rt>
  | ThreeOperands (OprReg r, OprMem (b, s, d, 128<rt>), OprImm (imm, _))
    when isXMMReg r ->
    encRMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0x3Auy; 0x0Fuy |] r b s d imm 8<rt>
  | o -> printfn "%A" o; raise NotEncodableException

let pop (ctxt: EncContext) ins =
  match ins.Operands with
  | OneOperand (OprReg Register.DS) -> no64Arch ctxt.Arch; [| Normal 0x1Fuy |]
  | OneOperand (OprReg Register.ES) -> no64Arch ctxt.Arch; [| Normal 0x07uy |]
  | OneOperand (OprReg Register.SS) -> no64Arch ctxt.Arch; [| Normal 0x17uy |]
  | OneOperand (OprReg Register.FS) -> [| Normal 0x0Fuy; Normal 0xA1uy |]
  | OneOperand (OprReg Register.GS) -> [| Normal 0x0Fuy; Normal 0xA9uy |]
  | OneOperand (OprReg r) when isReg16 r ->
    encR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x8Fuy |] r 0b000uy
  | OneOperand (OprMem (b, s, d, 16<rt>)) ->
    encM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x8Fuy |] b s d 0b000uy
  | OneOperand (OprReg r) when isReg32 r ->
    no64Arch ctxt.Arch
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x8Fuy |] r 0b000uy
  | OneOperand (OprMem (b, s, d, 32<rt>)) ->
    no64Arch ctxt.Arch
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x8Fuy |] b s d 0b000uy
  | OneOperand (OprReg r) when isReg64 r ->
    no32Arch ctxt.Arch
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x8Fuy |] r 0b000uy
  | OneOperand (OprMem (b, s, d, 64<rt>)) ->
    no32Arch ctxt.Arch
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x8Fuy |] b s d 0b000uy
  | o -> printfn "%A" o; raise NotEncodableException

let pshufd (ctxt: EncContext) ins =
  match ins.Operands with
  | ThreeOperands (OprReg r1, OprReg r2, OprImm (imm, _))
    when isXMMReg r1 && isXMMReg r2 ->
    encRRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0x70uy |] r1 r2 imm 8<rt>
  | ThreeOperands (OprReg r, OprMem (b, s, d, 128<rt>), OprImm (imm, _))
    when isXMMReg r ->
    encRMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0x70uy |] r b s d imm 8<rt>
  | o -> printfn "%A" o; raise NotEncodableException

let punpckldq (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isMMXReg r1 && isMMXReg r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0x62uy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isMMXReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0x62uy |] r b s d
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0x62uy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 128<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0x62uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let push (ctxt: EncContext) ins =
  match ins.Operands with
  | OneOperand (OprReg Register.CS) -> no64Arch ctxt.Arch; [| Normal 0x0Euy |]
  | OneOperand (OprReg Register.SS) -> no64Arch ctxt.Arch; [| Normal 0x16uy |]
  | OneOperand (OprReg Register.DS) -> no64Arch ctxt.Arch; [| Normal 0x1Euy |]
  | OneOperand (OprReg Register.ES) -> no64Arch ctxt.Arch; [| Normal 0x06uy |]
  | OneOperand (OprReg Register.FS) -> [| Normal 0x0Fuy; Normal 0xA0uy |]
  | OneOperand (OprReg Register.GS) -> [| Normal 0x0Fuy; Normal 0xA8uy |]
  | OneOperand (OprReg r) when isReg16 r ->
    encR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0xFFuy |] r 0b110uy
  | OneOperand (OprMem (b, s, d, 16<rt>)) ->
    encM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0xFFuy |] b s d 0b110uy
  | OneOperand (OprReg r) when isReg32 r ->
    no64Arch ctxt.Arch
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xFFuy |] r 0b110uy
  | OneOperand (OprMem (b, s, d, 32<rt>)) ->
    no64Arch ctxt.Arch
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xFFuy |] b s d 0b110uy
  | OneOperand (OprReg r) when isReg64 r ->
    no32Arch ctxt.Arch
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xFFuy |] r 0b110uy
  | OneOperand (OprMem (b, s, d, 64<rt>)) ->
    no32Arch ctxt.Arch
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xFFuy |] b s d 0b110uy
  | OneOperand (OprImm (imm, _)) when isInt8 imm ->
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x6Auy |] imm 8<rt>
  | OneOperand (OprImm (imm, _)) when isInt16 imm ->
    encI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x68uy |] imm 16<rt>
  | OneOperand (OprImm (imm, _)) when isUInt32 imm -> // FIXME
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x68uy |] imm 32<rt>
  | o -> printfn "%A" o; raise NotEncodableException

let pxor (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isMMXReg r1 && isMMXReg r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0xEFuy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 64<rt>)) when isMMXReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0xEFuy |] r b s d
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0xEFuy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 128<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0xEFuy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let rotateOrShift (ctxt: EncContext) ins regConstr =
  match ins.Operands with
  | TwoOperands (OprReg r, OprImm (1L as imm, _)) when isReg8 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xD0uy |] r regConstr imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 8<rt>), OprImm (1L as imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xD0uy |] b s d regConstr imm 8<rt>
  | TwoOperands (OprReg r, OprReg Register.CL) when isReg8 r ->
    encRC ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexMR [| 0xD2uy |] r regConstr
  | TwoOperands (OprMem (b, s, d, 8<rt>), OprReg Register.CL) ->
    encMC ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xD2uy |] b s d regConstr
  | TwoOperands (OprReg r, OprImm (imm, _))  when isReg8 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xC0uy |] r regConstr imm 8<rt>
  | TwoOperands (Label _, OprImm (imm, _)) ->
    encLI ctxt ins regConstr imm 8<rt> [| 0xC0uy |] [| 0xC1uy |]
  | TwoOperands (OprMem (b, s, d, 8<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xC0uy |] b s d regConstr imm 8<rt>
  | TwoOperands (OprReg r, OprImm (1L as imm, _)) when isReg16 r ->
    encRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0xD1uy |] r regConstr imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprImm (1L as imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0xD1uy |] b s d regConstr imm 8<rt>
  | TwoOperands (OprReg r, OprReg Register.CL) when isReg16 r ->
    encRC ins ctxt.Arch
      ctxt.Pref66 ctxt.RexMR [| 0xD3uy |] r regConstr
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprReg Register.CL) ->
    encMC ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0xD3uy |] b s d regConstr
  | TwoOperands (OprReg r, OprImm (imm, _))  when isReg16 r ->
    encRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0xC1uy |] r regConstr imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0xC1uy |] b s d regConstr imm 8<rt>
  | TwoOperands (OprReg r, OprImm (1L as imm, _)) when isReg32 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xD1uy |] r regConstr imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprImm (1L as imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xD1uy |] b s d regConstr imm 8<rt>
  | TwoOperands (OprReg r, OprReg Register.CL) when isReg32 r ->
    encRC ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexMR [| 0xD3uy |] r regConstr
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprReg Register.CL) ->
    encMC ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xD3uy |] b s d regConstr
  | TwoOperands (OprReg r, OprImm (imm, _))  when isReg32 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xC1uy |] r regConstr imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xC1uy |] b s d regConstr imm 8<rt>
  | TwoOperands (OprReg r, OprImm (1L as imm, _)) when isReg64 r ->
    no32Arch ctxt.Arch
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0xD1uy |] r regConstr imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprImm (1L as imm, _)) ->
    no32Arch ctxt.Arch
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0xD1uy |] b s d regConstr imm 8<rt>
  | TwoOperands (OprReg r, OprReg Register.CL) when isReg64 r ->
    no32Arch ctxt.Arch
    encRC ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexWAndMR [| 0xD3uy |] r regConstr
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprReg Register.CL) ->
    no32Arch ctxt.Arch
    encMC ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0xD3uy |] b s d regConstr
  | TwoOperands (OprReg r, OprImm (imm, _))  when isReg64 r ->
    no32Arch ctxt.Arch
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0xC1uy |] r regConstr imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprImm (imm, _)) ->
    no32Arch ctxt.Arch
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0xC1uy |] b s d regConstr imm 8<rt>
  | o -> printfn "%A" o; raise NotEncodableException

let rcl ctxt ins = rotateOrShift ctxt ins 0b010uy
let rcr ctxt ins = rotateOrShift ctxt ins 0b011uy
let rol ctxt ins = rotateOrShift ctxt ins 0b000uy
let ror ctxt ins = rotateOrShift ctxt ins 0b001uy

let ret (ctxt: EncContext) ins =
  match ins.Operands with
  | NoOperand -> [| Normal 0xC3uy |]
  | OneOperand (OprDirAddr (Relative rel)) -> // FIXME
    encD ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xC2uy |] rel 16<rt>
  | OneOperand (OprImm (imm, _)) ->
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xC2uy |] imm 16<rt>
  | o -> printfn "%A" o; raise NotEncodableException

let sar ctxt ins = rotateOrShift ctxt ins 0b111uy
let shl ctxt ins = rotateOrShift ctxt ins 0b100uy
let shr ctxt ins = rotateOrShift ctxt ins 0b101uy

let sahf (ctxt: EncContext) = function
  | NoOperand -> no64Arch ctxt.Arch; [| Normal 0x9Euy |]
  | _ -> raise NotEncodableException

let sbb (ctxt: EncContext) ins =
  match ins.Operands with
  (* Reg (fixed) - Imm (Priority 1) *)
  | TwoOperands (OprReg Register.AL, OprImm (imm, _)) ->
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x1Cuy |] imm 8<rt>
  | TwoOperands (OprReg Register.AX, OprImm (imm, _)) ->
    encI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x1Duy |] imm 16<rt>
  | TwoOperands (OprReg Register.EAX, OprImm (imm, _)) ->
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x1Duy |] imm 32<rt>
  | TwoOperands (OprReg Register.RAX, OprImm (imm, _)) ->
    no32Arch ctxt.Arch
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x1Duy |] imm 32<rt>
  (* Reg - Imm (Priority 0) *)
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg16 r && isInt8 imm ->
    encRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x83uy |] r 0b011uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg32 r && isInt8 imm ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x83uy |] r 0b011uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg64 r && isInt8 imm ->
    no32Arch ctxt.Arch
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x83uy |] r 0b011uy imm 8<rt>
  (* Mem - Imm (Priority 0) *)
  | TwoOperands (Label _, OprImm (imm, _)) when isInt8 imm ->
    encLI ctxt ins 0b011uy imm 8<rt> [||] [| 0x83uy |]
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprImm (imm, _)) when isInt8 imm ->
    encMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x83uy |] b s d 0b011uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprImm (imm, _)) when isInt8 imm ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x83uy |] b s d 0b011uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprImm (imm, _)) when isInt8 imm ->
    no32Arch ctxt.Arch
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x83uy |] b s d 0b011uy imm 8<rt>
  (* Reg - Imm (Priority 1) *)
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg8 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x80uy |] r 0b011uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg16 r ->
    encRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x81uy |] r 0b011uy imm 16<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg32 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x81uy |] r 0b011uy imm 32<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg64 r ->
    no32Arch ctxt.Arch
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x81uy |] r 0b011uy imm 32<rt>
  (* Mem - Imm (Priority 1) *)
  | TwoOperands (Label _, OprImm (imm, _)) ->
    encLI ctxt ins 0b011uy imm 32<rt> [| 0x80uy |] [| 0x81uy |] // FIXME
  | TwoOperands (OprMem (b, s, d, 8<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x80uy |] b s d 0b011uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x81uy |] b s d 0b011uy imm 16<rt>
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x81uy |] b s d 0b011uy imm 32<rt>
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprImm (imm, _)) ->
    no32Arch ctxt.Arch;
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x81uy |] b s d 0b011uy imm 32<rt>
  (* Mem - Reg *)
  | TwoOperands (Label _, OprReg r) ->
    encRL ctxt ins r [| 0x18uy |] [| 0x19uy |]
  | TwoOperands (OprMem (b, s, d, 8<rt>), OprReg r) when isReg8 r ->
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x18uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprReg r) when isReg16 r ->
    encMR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x19uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprReg r) when isReg32 r ->
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x19uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprReg r) when isReg64 r ->
    no32Arch ctxt.Arch
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x19uy |] b s d r
  (* Reg - Reg *)
  | TwoOperands (OprReg r1, OprReg r2) when isReg8 r1 && isReg8 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x1Auy |] r1 r2
  | TwoOperands (OprReg r1, OprReg r2) when isReg16 r1 && isReg16 r2 ->
    encRR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x1Buy |] r1 r2
  | TwoOperands (OprReg r1, OprReg r2) when isReg32 r1 && isReg32 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x1Buy |] r1 r2
  | TwoOperands (OprReg r1, OprReg r2) when isReg64 r1 && isReg64 r2 ->
    no32Arch ctxt.Arch
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x1Buy |] r1 r2
  (* Reg - Mem *)
  | TwoOperands (OprReg r, Label _) ->
    encRL ctxt ins r [| 0x1Auy |] [| 0x1Buy |]
  | TwoOperands (OprReg r, OprMem (b, s, d, 8<rt>)) when isReg8 r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x1Auy |] r b s d
  | TwoOperands (OprReg r, OprMem (b, s, d, 16<rt>)) when isReg16 r ->
    encRM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x1Buy |] r b s d
  | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isReg32 r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x1Buy |] r b s d
  | TwoOperands (OprReg r, OprMem (b, s, d, 64<rt>)) when isReg64 r ->
    no32Arch ctxt.Arch
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x1Buy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let scasb (ctxt: EncContext) ins =
  match ins.Operands with
  | NoOperand ->
    encNP ins ctxt.Arch
      ctxt.PrefREP ctxt.RexNormal [| 0xAEuy |]
  | o -> printfn "%A" o; raise NotEncodableException

let scasd (ctxt: EncContext) ins =
  match ins.Operands with
  | NoOperand ->
    encNP ins ctxt.Arch
      ctxt.PrefREP ctxt.RexNormal [| 0xAFuy |]
  | o -> printfn "%A" o; raise NotEncodableException

let scasq (ctxt: EncContext) ins =
  match ins.Operands with
  | NoOperand ->
    no32Arch ctxt.Arch
    encNP ins ctxt.Arch
      ctxt.PrefREP ctxt.RexW [| 0xAFuy |]
  | o -> printfn "%A" o; raise NotEncodableException

let scasw (ctxt: EncContext) ins =
  match ins.Operands with
  | NoOperand ->
    encNP ins ctxt.Arch
      ctxt.PrefREP66 ctxt.RexNormal [| 0xAFuy |]
  | o -> printfn "%A" o; raise NotEncodableException

let setcc (ctxt: EncContext) ins op =
  match ins.Operands with
  | OneOperand (OprReg r) when isReg8 r ->
    encR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; op |] r 0b000uy
  | OneOperand (OprMem (b, s, d, 8<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; op |] b s d 0b000uy
  | o -> printfn "%A" o; raise NotEncodableException

let seta ctxt ins = setcc ctxt ins 0x97uy
let setb ctxt ins = setcc ctxt ins 0x92uy
let setbe ctxt ins = setcc ctxt ins 0x96uy
let setg ctxt ins = setcc ctxt ins 0x9Fuy
let setl ctxt ins = setcc ctxt ins 0x9Cuy
let setle ctxt ins = setcc ctxt ins 0x9Euy
let setnb ctxt ins = setcc ctxt ins 0x93uy
let setnl ctxt ins = setcc ctxt ins 0x9Duy
let setno ctxt ins = setcc ctxt ins 0x91uy
let setnp ctxt ins = setcc ctxt ins 0x9Buy
let setns ctxt ins = setcc ctxt ins 0x99uy
let setnz ctxt ins = setcc ctxt ins 0x95uy
let seto ctxt ins = setcc ctxt ins 0x90uy
let setp ctxt ins = setcc ctxt ins 0x9Auy
let sets ctxt ins = setcc ctxt ins 0x98uy
let setz ctxt ins = setcc ctxt ins 0x94uy

let shld (ctxt: EncContext) ins =
  match ins.Operands with
  | ThreeOperands (OprReg r1, OprReg r2, OprImm (imm, _))
    when isReg16 r1 && isReg16 r2 ->
    encRRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0xA4uy |] r1 r2 imm 8<rt>
  | ThreeOperands (OprMem (b, s, d, 16<rt>), OprReg r, OprImm (imm, _))
    when isReg16 r ->
    encMRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0xA4uy |] b s d r imm 8<rt>
  | ThreeOperands (OprReg r1, OprReg r2, OprReg Register.CL)
    when isReg16 r1 && isReg16 r2 ->
    encRR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0xA5uy |] r1 r2
  | ThreeOperands (OprMem (b, s, d, 16<rt>), OprReg r, OprReg Register.CL)
    when isReg16 r ->
    encMR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0xA5uy |] b s d r
  | ThreeOperands (OprReg r1, OprReg r2, OprImm (imm, _))
    when isReg32 r1 && isReg32 r2 ->
    encRRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexMR [| 0x0Fuy; 0xA4uy |] r2 r1 imm 8<rt>
  | ThreeOperands (OprMem (b, s, d, 32<rt>), OprReg r, OprImm (imm, _))
    when isReg32 r ->
    encMRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0xA4uy |] b s d r imm 8<rt>
  | ThreeOperands (OprReg r1, OprReg r2, OprReg Register.CL)
    when isReg32 r1 && isReg32 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0xA5uy |] r1 r2
  | ThreeOperands (OprMem (b, s, d, 32<rt>), OprReg r, OprReg Register.CL)
    when isReg32 r ->
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0xA5uy |] b s d r
  | ThreeOperands (OprReg r1, OprReg r2, OprImm (imm, _))
    when isReg64 r1 && isReg64 r2 ->
    no32Arch ctxt.Arch
    encRRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x0Fuy; 0xA4uy |] r1 r2 imm 8<rt>
  | ThreeOperands (OprMem (b, s, d, 64<rt>), OprReg r, OprImm (imm, _))
    when isReg64 r ->
    no32Arch ctxt.Arch
    encMRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x0Fuy; 0xA4uy |] b s d r imm 8<rt>
  | ThreeOperands (OprReg r1, OprReg r2, OprReg Register.CL)
    when isReg64 r1 && isReg64 r2 ->
    no32Arch ctxt.Arch
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x0Fuy; 0xA5uy |] r1 r2
  | ThreeOperands (OprMem (b, s, d, 64<rt>), OprReg r, OprReg Register.CL)
    when isReg64 r ->
    no32Arch ctxt.Arch
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x0Fuy; 0xA5uy |] b s d r
  | o -> printfn "%A" o; raise NotEncodableException

let stosb (ctxt: EncContext) ins =
  match ins.Operands with
  | NoOperand ->
    encNP ins ctxt.Arch
      ctxt.PrefREP ctxt.RexNormal [| 0xAAuy |]
  | o -> printfn "%A" o; raise NotEncodableException

let stosd (ctxt: EncContext) ins =
  match ins.Operands with
  | NoOperand ->
    encNP ins ctxt.Arch
      ctxt.PrefREP ctxt.RexNormal [| 0xABuy |]
  | o -> printfn "%A" o; raise NotEncodableException

let stosq (ctxt: EncContext) ins =
  match ins.Operands with
  | NoOperand ->
    no32Arch ctxt.Arch
    encNP ins ctxt.Arch
      ctxt.PrefREP ctxt.RexW [| 0xABuy |]
  | o -> printfn "%A" o; raise NotEncodableException

let stosw (ctxt: EncContext) ins =
  match ins.Operands with
  | NoOperand ->
    encNP ins ctxt.Arch
      ctxt.PrefREP66 ctxt.RexNormal [| 0xABuy |]
  | o -> printfn "%A" o; raise NotEncodableException

let sub (ctxt: EncContext) ins =
  match ins.Operands with
  (* Reg (fixed) - Imm (Priority 1) *)
  | TwoOperands (OprReg Register.AL, OprImm (imm, _)) ->
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x2Cuy |] imm 8<rt>
  | TwoOperands (OprReg Register.AX, OprImm (imm, _)) ->
    encI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x2Duy |] imm 16<rt>
  | TwoOperands (OprReg Register.EAX, OprImm (imm, _)) ->
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x2Duy |] imm 32<rt>
  | TwoOperands (OprReg Register.RAX, OprImm (imm, _)) ->
    no32Arch ctxt.Arch
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x2Duy |] imm 32<rt>
  (* Reg - Imm (Priority 0) *)
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg16 r && isInt8 imm ->
    encRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x83uy |] r 0b101uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg32 r && isInt8 imm ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x83uy |] r 0b101uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg64 r && isInt8 imm ->
    no32Arch ctxt.Arch
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x83uy |] r 0b101uy imm 8<rt>
  (* Mem - Imm (Priority 0) *)
  | TwoOperands (Label _, OprImm (imm, _)) when isInt8 imm ->
    encLI ctxt ins 0b101uy imm 8<rt> [||] [| 0x83uy |]
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprImm (imm, _)) when isInt8 imm ->
    encMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x83uy |] b s d 0b101uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprImm (imm, _)) when isInt8 imm ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x83uy |] b s d 0b101uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprImm (imm, _)) when isInt8 imm ->
    no32Arch ctxt.Arch
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x83uy |] b s d 0b101uy imm 8<rt>
  (* Reg - Imm (Priority 1) *)
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg8 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x80uy |] r 0b101uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg16 r ->
    encRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x81uy |] r 0b101uy imm 16<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg32 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x81uy |] r 0b101uy imm 32<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg64 r ->
    no32Arch ctxt.Arch
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x81uy |] r 0b101uy imm 32<rt>
  (* Mem - Imm (Priority 1) *)
  | TwoOperands (Label _, OprImm (imm, _)) ->
     encLI ctxt ins 0b101uy imm 32<rt> [| 0x80uy |] [| 0x81uy |] // FIXME
  | TwoOperands (OprMem (b, s, d, 8<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x80uy |] b s d 0b101uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x81uy |] b s d 0b101uy imm 16<rt>
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x81uy |] b s d 0b101uy imm 32<rt>
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprImm (imm, _)) ->
    no32Arch ctxt.Arch;
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x81uy |] b s d 0b011uy imm 32<rt>
  (* Mem - Reg *)
  | TwoOperands (Label _, OprReg r) ->
    encRL ctxt ins r [| 0x28uy |] [| 0x29uy |]
  | TwoOperands (OprMem (b, s, d, 8<rt>), OprReg r) when isReg8 r ->
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x28uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprReg r) when isReg16 r ->
    encMR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x29uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprReg r) when isReg32 r ->
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x29uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprReg r) when isReg64 r ->
    no32Arch ctxt.Arch
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x29uy |] b s d r
  (* Reg - Reg *)
  | TwoOperands (OprReg r1, OprReg r2) when isReg8 r1 && isReg8 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x2Auy |] r1 r2
  | TwoOperands (OprReg r1, OprReg r2) when isReg16 r1 && isReg16 r2 ->
    encRR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x2Buy |] r1 r2
  | TwoOperands (OprReg r1, OprReg r2) when isReg32 r1 && isReg32 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x2Buy |] r1 r2
  | TwoOperands (OprReg r1, OprReg r2) when isReg64 r1 && isReg64 r2 ->
    no32Arch ctxt.Arch
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x2Buy |] r1 r2
  (* Reg - Mem *)
  | TwoOperands (OprReg r, Label _) ->
    encRL ctxt ins r [| 0x2Auy |] [| 0x2Buy |]
  | TwoOperands (OprReg r, OprMem (b, s, d, 8<rt>)) when isReg8 r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x2Auy |] r b s d
  | TwoOperands (OprReg r, OprMem (b, s, d, 16<rt>)) when isReg16 r ->
    encRM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x2Buy |] r b s d
  | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isReg32 r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x2Buy |] r b s d
  | TwoOperands (OprReg r, OprMem (b, s, d, 64<rt>)) when isReg64 r ->
    no32Arch ctxt.Arch
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x2Buy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let subsd (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefF2 ctxt.RexNormal [| 0x0Fuy; 0x5Cuy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 64<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefF2 ctxt.RexNormal [| 0x0Fuy; 0x5Cuy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let subss (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefF3 ctxt.RexNormal [| 0x0Fuy; 0x5Cuy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefF3 ctxt.RexNormal [| 0x0Fuy; 0x5Cuy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let test (ctxt: EncContext) ins =
  match ins.Operands with
  (* Reg (fixed) - Imm *)
  | TwoOperands (OprReg Register.AL, OprImm (imm, _)) ->
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xA8uy |] imm 8<rt>
  | TwoOperands (OprReg Register.AX, OprImm (imm, _)) ->
    encI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0xA9uy |] imm 16<rt>
  | TwoOperands (OprReg Register.EAX, OprImm (imm, _)) ->
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xA9uy |] imm 32<rt>
  | TwoOperands (OprReg Register.RAX, OprImm (imm, _)) ->
    no32Arch ctxt.Arch
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0xA9uy |] imm 32<rt>
  (* Reg - Imm *)
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg8 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xF6uy |] r 0b000uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg16 r ->
    encRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0xF7uy |] r 0b000uy imm 16<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg32 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xF7uy |] r 0b000uy imm 32<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg64 r ->
    no32Arch ctxt.Arch
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0xF7uy |] r 0b000uy imm 32<rt>
  (* Mem - Imm *)
  | TwoOperands (Label _, OprImm (imm, _)) ->
    encLI ctxt ins 0b000uy imm 32<rt> [| 0xF6uy |] [| 0xF7uy |] // FIXME
  | TwoOperands (OprMem (b, s, d, 8<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xF6uy |] b s d 0b000uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0xF7uy |] b s d 0b000uy imm 16<rt>
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xF7uy |] b s d 0b000uy imm 32<rt>
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprImm (imm, _)) ->
    no32Arch ctxt.Arch;
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0xF7uy |] b s d 0b000uy imm 32<rt>
  (* Reg - Reg *)
  | TwoOperands (OprReg r1, OprReg r2) when isReg8 r1 && isReg8 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexMR [| 0x84uy |] r2 r1
  | TwoOperands (OprReg r1, OprReg r2) when isReg16 r1 && isReg16 r2 ->
    encRR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexMR [| 0x85uy |] r2 r1
  | TwoOperands (OprReg r1, OprReg r2) when isReg32 r1 && isReg32 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexMR [| 0x85uy |] r2 r1
  | TwoOperands (OprReg r1, OprReg r2) when isReg64 r1 && isReg64 r2 ->
    no32Arch ctxt.Arch
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexWAndMR [| 0x85uy |] r2 r1
  (* Mem - Reg *)
  | TwoOperands (OprReg r, Label _) ->
    encRL ctxt ins r [| 0x84uy |] [| 0x85uy |]
  | TwoOperands (OprMem (b, s, d, 8<rt>), OprReg r) when isReg8 r ->
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x84uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprReg r) when isReg16 r ->
    encMR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x85uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprReg r) when isReg32 r ->
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x85uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprReg r) when isReg64 r ->
    no32Arch ctxt.Arch
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x85uy |] b s d r
  | o -> printfn "%A" o; raise NotEncodableException

let ucomiss (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0x2Euy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0x2Euy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let vaddpd (ctxt: EncContext) ins =
  match ins.Operands with
  | ThreeOperands (OprReg r1, OprReg r2, OprReg r3)
    when isXMMReg r1 && isXMMReg r2 && isXMMReg r3 ->
    encVexRRR ins ctxt.Arch (Some r2) ctxt.VEX128n66n0F [| 0x58uy |] r1 r3
  | ThreeOperands (OprReg r1, OprReg r2, OprReg r3)
    when isYMMReg r1 && isYMMReg r2 && isYMMReg r3 ->
    encVexRRR ins ctxt.Arch (Some r2) ctxt.VEX256n66n0F [| 0x58uy |] r1 r3
  | ThreeOperands (OprReg r1, OprReg r2, OprMem (b, s, d, 128<rt>))
    when isXMMReg r1 && isXMMReg r2 ->
    encVexRRM ins ctxt.Arch (Some r2) ctxt.VEX128n66n0F [| 0x58uy |] r1 b s d
  | ThreeOperands (OprReg r1, OprReg r2, OprMem (b, s, d, 256<rt>))
    when isYMMReg r1 && isYMMReg r2 ->
    encVexRRM ins ctxt.Arch (Some r2) ctxt.VEX256n66n0F [| 0x58uy |] r1 b s d
  | o -> printfn "%A" o; raise NotEncodableException

let vaddps (ctxt: EncContext) ins =
  match ins.Operands with
  | ThreeOperands (OprReg r1, OprReg r2, OprReg r3)
    when isXMMReg r1 && isXMMReg r2 && isXMMReg r3 ->
    encVexRRR ins ctxt.Arch (Some r2) ctxt.VEX128n0F [| 0x58uy |] r1 r3
  | ThreeOperands (OprReg r1, OprReg r2, OprReg r3)
    when isYMMReg r1 && isYMMReg r2 && isYMMReg r3 ->
    encVexRRR ins ctxt.Arch (Some r2) ctxt.VEX256n0F [| 0x58uy |] r1 r3
  | ThreeOperands (OprReg r1, OprReg r2, OprMem (b, s, d, 128<rt>))
    when isXMMReg r1 && isXMMReg r2 ->
    encVexRRM ins ctxt.Arch (Some r2) ctxt.VEX128n0F [| 0x58uy |] r1 b s d
  | ThreeOperands (OprReg r1, OprReg r2, OprMem (b, s, d, 256<rt>))
    when isYMMReg r1 && isYMMReg r2 ->
    encVexRRM ins ctxt.Arch (Some r2) ctxt.VEX256n0F [| 0x58uy |] r1 b s d
  | o -> printfn "%A" o; raise NotEncodableException

let vaddsd (ctxt: EncContext) ins =
  match ins.Operands with
  | ThreeOperands (OprReg r1, OprReg r2, OprReg r3)
    when isXMMReg r1 && isXMMReg r2 && isXMMReg r3 ->
    encVexRRR ins ctxt.Arch (Some r2) ctxt.VEX128nF2n0F [| 0x58uy |] r1 r3
  | ThreeOperands (OprReg r1, OprReg r2, OprMem (b, s, d, 64<rt>))
    when isXMMReg r1 && isXMMReg r2 ->
    encVexRRM ins ctxt.Arch (Some r2) ctxt.VEX128nF2n0F [| 0x58uy |] r1 b s d
  | o -> printfn "%A" o; raise NotEncodableException

let vaddss (ctxt: EncContext) ins =
  match ins.Operands with
  | ThreeOperands (OprReg r1, OprReg r2, OprReg r3)
    when isXMMReg r1 && isXMMReg r2 && isXMMReg r3 ->
    encVexRRR ins ctxt.Arch (Some r2) ctxt.VEX128nF3n0F [| 0x58uy |] r1 r3
  | ThreeOperands (OprReg r1, OprReg r2, OprMem (b, s, d, 32<rt>))
    when isXMMReg r1 && isXMMReg r2 ->
    encVexRRM ins ctxt.Arch (Some r2) ctxt.VEX128nF3n0F [| 0x58uy |] r1 b s d
  | o -> printfn "%A" o; raise NotEncodableException

let vpalignr (ctxt: EncContext) ins =
  match ins.Operands with
  (* Reg - Reg - Reg - Imm8 *)
  | FourOperands (OprReg r1, OprReg r2, OprReg r3, OprImm (imm, _))
    when isXMMReg r1 && isXMMReg r2 && isXMMReg r3 ->
    encVexRRRI ins ctxt.Arch
      (Some r2) ctxt.VEX128n66n0F3A [| 0x0Fuy |] r1 r3 imm 8<rt>
  | FourOperands (OprReg r1, OprReg r2, OprReg r3, OprImm (imm, _))
    when isYMMReg r1 && isYMMReg r2 && isYMMReg r3 ->
    encVexRRRI ins ctxt.Arch
      (Some r2) ctxt.VEX256n66n0F3A [| 0x0Fuy |] r1 r3 imm 8<rt>
  (* Reg - Reg - Mem - Imm8 *)
  | FourOperands (OprReg r1, OprReg r2, OprMem (b, s, d, 128<rt>), OprImm (imm, _))
    when isXMMReg r1 && isXMMReg r2 ->
    encVexRRMI ins ctxt.Arch
      (Some r2) ctxt.VEX128n66n0F3A [| 0x0Fuy |] r1 b s d imm 8<rt>
  | FourOperands (OprReg r1, OprReg r2, OprMem (b, s, d, 256<rt>), OprImm (imm, _))
    when isYMMReg r1 && isYMMReg r2 ->
    encVexRRMI ins ctxt.Arch
      (Some r2) ctxt.VEX256n66n0F3A [| 0x0Fuy |] r1 b s d imm 8<rt>
  | o -> printfn "%A" o; raise NotEncodableException

let xchg (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg Register.AX, OprReg r)
  | TwoOperands (OprReg r, OprReg Register.AX) when isReg16 r ->
    encO ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal 0x90uy r
  | TwoOperands (OprReg Register.EAX, OprReg r)
  | TwoOperands (OprReg r, OprReg Register.EAX) when isReg32 r ->
    encO ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal 0x90uy r
  | TwoOperands (OprReg Register.RAX, OprReg r)
  | TwoOperands (OprReg r, OprReg Register.RAX) when isReg64 r ->
    no32Arch ctxt.Arch
    encO ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW 0x90uy r
  | o -> printfn "%A" o; raise NotEncodableException

let xor (ctxt: EncContext) ins =
  match ins.Operands with
  (* Reg (fixed) - Imm (Priority 1). *)
  | TwoOperands (OprReg Register.AL, OprImm (imm, _)) ->
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x34uy |] imm 8<rt>
  | TwoOperands (OprReg Register.AX, OprImm (imm, _)) ->
    encI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x35uy |] imm 16<rt>
  | TwoOperands (OprReg Register.EAX, OprImm (imm, _)) ->
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x35uy |] imm 32<rt>
  | TwoOperands (OprReg Register.RAX, OprImm (imm, _)) ->
    no32Arch ctxt.Arch
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x35uy |] imm 32<rt>
  (* Reg - Imm (Priority 0) *)
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg16 r && isInt8 imm ->
    encRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x83uy |] r 0b110uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg32 r && isInt8 imm ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x83uy |] r 0b110uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg64 r && isInt8 imm ->
    no32Arch ctxt.Arch
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x83uy |] r 0b110uy imm 8<rt>
  (* Mem - Imm (Priority 0) *)
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprImm (imm, _)) when isInt8 imm ->
    encMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x83uy |] b s d 0b110uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprImm (imm, _)) when isInt8 imm ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x83uy |] b s d 0b110uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprImm (imm, _)) when isInt8 imm ->
    no32Arch ctxt.Arch
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x83uy |] b s d 0b110uy imm 8<rt>
  (* Reg - Imm (Priority 1) *)
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg8 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x80uy |] r 0b110uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg16 r ->
    encRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x81uy |] r 0b110uy imm 16<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg32 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x81uy |] r 0b110uy imm 32<rt>
  | TwoOperands (OprReg r, OprImm (imm, _)) when isReg64 r ->
    no32Arch ctxt.Arch
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x81uy |] r 0b110uy imm 32<rt>
  (* Mem - Imm (Priority 1) *)
  | TwoOperands (OprMem (b, s, d, 8<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x80uy |] b s d 0b110uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x81uy |] b s d 0b110uy imm 16<rt>
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprImm (imm, _)) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x81uy |] b s d 0b110uy imm 32<rt>
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprImm (imm, _)) ->
    no32Arch ctxt.Arch;
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x81uy |] b s d 0b110uy imm 32<rt>
  (* Mem - Reg *)
  | TwoOperands (OprMem (b, s, d, 8<rt>), OprReg r) when isReg8 r ->
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x30uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprReg r) when isReg16 r ->
    encMR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x31uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprReg r) when isReg32 r ->
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x31uy |] b s d r
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprReg r) when isReg64 r ->
    no32Arch ctxt.Arch
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x31uy |] b s d r
  (* Reg - Reg *)
  | TwoOperands (OprReg r1, OprReg r2) when isReg8 r1 && isReg8 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x32uy |] r1 r2
  | TwoOperands (OprReg r1, OprReg r2) when isReg16 r1 && isReg16 r2 ->
    encRR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x33uy |] r1 r2
  | TwoOperands (OprReg r1, OprReg r2) when isReg32 r1 && isReg32 r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x33uy |] r1 r2
  | TwoOperands (OprReg r1, OprReg r2) when isReg64 r1 && isReg64 r2 ->
    no32Arch ctxt.Arch
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x33uy |] r1 r2
  (* Reg - Mem *)
  | TwoOperands (OprReg r, OprMem (b, s, d, 8<rt>)) when isReg8 r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x32uy |] r b s d
  | TwoOperands (OprReg r, OprMem (b, s, d, 16<rt>)) when isReg16 r ->
    encRM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x33uy |] r b s d
  | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isReg32 r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x33uy |] r b s d
  | TwoOperands (OprReg r, OprMem (b, s, d, 64<rt>)) when isReg64 r ->
    no32Arch ctxt.Arch
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x33uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let xorps (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0x57uy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 128<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0x57uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let syscall () =
  [| Normal 0x0Fuy; Normal 0x05uy |]

// vim: set tw=80 sts=2 sw=2:
