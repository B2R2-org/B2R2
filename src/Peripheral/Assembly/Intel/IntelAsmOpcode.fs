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
open B2R2.FrontEnd.Intel
open B2R2.Peripheral.Assembly.Intel.ParserHelper
open B2R2.Peripheral.Assembly.Intel.AsmPrefix
open B2R2.Peripheral.Assembly.Intel.AsmOperands

let no32Arch wordSz =
  if wordSz = WordSize.Bit32 then raise InvalidISAException else ()

let no64Arch wordSz =
  if wordSz = WordSize.Bit64 then raise InvalidISAException else ()

let isInt8 i = 0xFFFFFFFFFFFFFF80L <= i && i <= 0x7FL

let isInt16 i = 0xFFFFFFFFFFFF8000L <= i && i <= 0x7FFFL

let isInt32 i = 0xFFFFFFFF80000000L <= i && i <= 0x7FFFFFFFL

let isUInt8 (i: int64) = uint64 i <= 0xFFUL

let isUInt16 (i: int64) = uint64 i <= 0xFFFFUL

let isUInt32 (i: int64) = uint64 i <= 0xFFFFFFFFUL

let isClassicGPReg = function
  | Register.RAX | Register.EAX | Register.AX
  | Register.RCX | Register.ECX | Register.CX
  | Register.RDX | Register.EDX | Register.DX
  | Register.RBX | Register.EBX | Register.BX
  | Register.RSP | Register.ESP | Register.SP
  | Register.RBP | Register.EBP | Register.BP
  | Register.RSI | Register.ESI | Register.SI
  | Register.RDI | Register.EDI | Register.DI -> true
  | _ -> false

let inline prxRexOp ins ctx pref rex op =
  [| yield! encodePrefix ins ctx pref
     yield! encodeREXPref ins ctx rex
     yield! Array.map Normal op |]

let inline encLbl ins =
  [| IncompleteOp(ins.Opcode, ins.Operands) |]

let inline encImm ins ctx pref rex op i immSz =
  [| yield! prxRexOp ins ctx pref rex op
     yield! immediate i immSz |]

let inline encR ins ctx pref rex op r c =
  [| yield! prxRexOp ins ctx pref rex op
     modrmR r c |]

let inline encClassicR opSizePref opValue diff =
  [| if opSizePref then Normal 0x66uy else ()
     Normal(opValue + diff) |]

let inline encD ins ctx pref rex op rel sz =
  let prxRexOp = prxRexOp ins ctx pref rex op
  [| yield! prxRexOp
     yield! modrmRel (Array.length prxRexOp) rel sz |]

let inline encM ins ctx pref rex op b s d c =
  [| yield! prxRexOp ins ctx pref rex op
     modrmM b s d c
     yield! mem b s d |]

let inline encRR ins ctx pref rex op r1 r2 =
  [| yield! prxRexOp ins ctx pref rex op
     modrmRR r1 r2 |]

let normalToByte = function
  | Normal b -> b
  | _ -> Terminator.impossible ()

let getCtxtByOprSz (ctx: EncContext) op8Byte opByte = function
  | 8<rt> -> ctx.PrefNormal, ctx.RexNormal, op8Byte
  | 16<rt> -> ctx.Pref66, ctx.RexNormal, opByte
  | 32<rt> -> ctx.PrefNormal, ctx.RexNormal, opByte
  | 64<rt> -> ctx.PrefNormal, ctx.RexW, opByte
  | _ -> Terminator.impossible ()

let inline encRL (ctx: EncContext) ins r op8Byte opByte =
  let pref, rex, opByte =
    getCtxtByOprSz ctx op8Byte opByte (Register.toRegType ctx.WordSize r)
  [| yield! prxRexOp ins ctx pref rex opByte
     yield modrmRL r |]
  |> Array.map normalToByte
  |> fun bytes ->
    [| CompOp(ins.Opcode, ins.Operands, bytes, None); IncompLabel 32<rt> |]

let inline encLI (ctx: EncContext) ins regConstr i immSz op8Byte opByte =
  let pref, rex, opByte = getCtxtByOprSz ctx op8Byte opByte 32<rt>
  let op =
    [| yield! prxRexOp ins ctx pref rex opByte
       yield modrmLI regConstr |] |> Array.map normalToByte
  let imm = immediate i immSz |> Array.map normalToByte |> Some
  [| CompOp(ins.Opcode, ins.Operands, op, imm); IncompLabel 32<rt> |]

let inline encRLI (ctx: EncContext) ins r op i immSz =
  let pref, rex, opByte =
    getCtxtByOprSz ctx [||] op (Register.toRegType ctx.WordSize r)
  let op =
    [| yield! prxRexOp ins ctx pref rex opByte
       yield modrmRL r |] |> Array.map normalToByte
  let imm = immediate i immSz |> Array.map normalToByte |> Some
  [| CompOp(ins.Opcode, ins.Operands, op, imm); IncompLabel 32<rt> |]

let inline encFR (op: byte[]) r =
  let op = [| op[0]; op[1] + (regTo3Bit r) |]
  [| yield! Array.map Normal op |]

let inline encO ins ctx pref rex op r =
  let op = [| op + (regTo3Bit r) |]
  [| yield! prxRexOp ins ctx pref rex op |]

let inline encRI ins ctx pref rex op r c i immSz =
  [| yield! prxRexOp ins ctx pref rex op
     yield modrmRI r c
     yield! immediate i immSz |]

let inline encOI ins ctx pref rex op r i immSz =
  let op = [| op + (regTo3Bit r) |]
  [| yield! prxRexOp ins ctx pref rex op
     yield! immediate i immSz |]

let inline encRM ins ctx pref rex op r b s d =
  [| yield! prxRexOp ins ctx pref rex op
     modrmRM r b s d
     yield! mem b s d |]

let inline encMR ins ctx pref rex op b s d r =
  [| yield! prxRexOp ins ctx pref rex op
     modrmMR b s d r
     yield! mem b s d |]

let inline encMI ins ctx pref rex op b s d c i immSz =
  [| yield! prxRexOp ins ctx pref rex op
     modrmMI b s d c
     yield! mem b s d
     yield! immediate i immSz |]

let inline encRC ins ctx pref rex op r c =
  [| yield! prxRexOp ins ctx pref rex op
     modrmRC r c |]

let inline encMC ins ctx pref rex op b s d c =
  [| yield! prxRexOp ins ctx pref rex op
     modrmMC b s d c |]

let inline encNP ins ctx pref rex op =
  [| yield! prxRexOp ins ctx pref rex op |]

let inline encRRI ins ctx pref rex op r1 r2 i immSz =
  [| yield! prxRexOp ins ctx pref rex op
     modrmRR r1 r2
     yield! immediate i immSz |]

let inline encRMI ins ctx pref rex op r b s d i immSz =
  [| yield! prxRexOp ins ctx pref rex op
     modrmRM r b s d
     yield! mem b s d
     yield! immediate i immSz |]

let inline encMRI ins ctx pref rex op b s d r i immSz =
  [| yield! prxRexOp ins ctx pref rex op
     modrmMR b s d r
     yield! mem b s d
     yield! immediate i immSz |]

let inline encVexRRR ins wordSz vvvv vex op r1 r3 =
  let rexRXB = encodeVEXRexRB wordSz r1 r3
  [| yield! encodeVEXPref rexRXB vvvv vex
     yield! Array.map Normal op
     modrmRR r1 r3 |]

let inline encVexRRM ins wordSz vvvv vex op r b s d =
  let rexRXB = encodeVEXRexRXB wordSz r b s
  [| yield! encodeVEXPref rexRXB vvvv vex
     yield! Array.map Normal op
     modrmRM r b s d
     yield! mem b s d |]

let inline encVexRRRI ins wordSz vvvv vex op r1 r3 i immSz =
  let rexRXB = encodeVEXRexRB wordSz r1 r3
  [| yield! encodeVEXPref rexRXB vvvv vex
     yield! Array.map Normal op
     modrmRR r1 r3
     yield! immediate i immSz |]

let inline encVexRRMI ins wordSz vvvv vex op r b s d i immSz =
  let rexRXB = encodeVEXRexRXB wordSz r b s
  [| yield! encodeVEXPref rexRXB vvvv vex
     yield! Array.map Normal op
     modrmRM r b s d
     yield! mem b s d
     yield! immediate i immSz |]

let aaa (ctx: EncContext) = function
  | NoOperand -> no64Arch ctx.WordSize; [| Normal 0x37uy |]
  | _ -> raise NotEncodableException

let aad (ctx: EncContext) = function
  | NoOperand -> no64Arch ctx.WordSize; [| Normal 0xD5uy; Normal 0x0Auy |]
  | OneOperand(OprImm(imm, _)) ->
    no64Arch ctx.WordSize; [| Normal 0xD5uy; yield! immediate imm 8<rt> |]
  | _ -> raise NotEncodableException

let aam (ctx: EncContext) = function
  | NoOperand -> no64Arch ctx.WordSize; [| Normal 0xD4uy; Normal 0x0Auy |]
  | OneOperand(OprImm(imm, _)) ->
    no64Arch ctx.WordSize; [| Normal 0xD4uy; yield! immediate imm 8<rt> |]
  | _ -> raise NotEncodableException

let aas (ctx: EncContext) = function
  | NoOperand -> no64Arch ctx.WordSize; [| Normal 0x3Fuy |]
  | _ -> raise NotEncodableException

let adc (ctx: EncContext) ins =
  match ins.Operands with
  (* Reg (fixed) - Imm (Priority 1) *)
  | TwoOperands(OprReg Register.AL, OprImm(imm, _)) ->
    encImm ins ctx ctx.PrefNormal ctx.RexNormal [| 0x14uy |] imm 8<rt>
  | TwoOperands(OprReg Register.AX, OprImm(imm, _)) ->
    encImm ins ctx ctx.Pref66 ctx.RexNormal [| 0x15uy |] imm 16<rt>
  | TwoOperands(OprReg Register.EAX, OprImm(imm, _)) ->
    encImm ins ctx ctx.PrefNormal ctx.RexNormal [| 0x15uy |] imm 32<rt>
  | TwoOperands(OprReg Register.RAX, OprImm(imm, _)) ->
    no32Arch ctx.WordSize
    encImm ins ctx ctx.PrefNormal ctx.RexW [| 0x15uy |] imm 32<rt>
  (* Reg - Imm (Priority 0) *)
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg16 ctx r && isInt8 imm ->
    encRI ins ctx ctx.Pref66 ctx.RexNormal [| 0x83uy |] r 0b010uy imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg32 ctx r && isInt8 imm ->
    encRI ins ctx ctx.PrefNormal ctx.RexNormal [| 0x83uy |] r 0b010uy imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg64 ctx r && isInt8 imm ->
    no32Arch ctx.WordSize
    encRI ins ctx ctx.PrefNormal ctx.RexW [| 0x83uy |] r 0b010uy imm 8<rt>
  (* Mem - Imm (Priority 0) *)
  | TwoOperands(Label _, OprImm(imm, _)) when isInt8 imm ->
    encLI ctx ins 0b010uy imm 8<rt> [||] [| 0x83uy |]
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprImm(imm, _)) when isInt8 imm ->
    encMI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x83uy |] b s d 0b010uy imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprImm(imm, _)) when isInt8 imm ->
    encMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x83uy |] b s d 0b010uy imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprImm(imm, _)) when isInt8 imm ->
    no32Arch ctx.WordSize
    encMI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x83uy |] b s d 0b010uy imm 8<rt>
  (* Reg - Imm (Priority 1) *)
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg8 ctx r ->
    encRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x80uy |] r 0b010uy imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg16 ctx r ->
    encRI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x81uy |] r 0b010uy imm 16<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg32 ctx r ->
    encRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x81uy |] r 0b010uy imm 32<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encRI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x81uy |] r 0b010uy imm 32<rt>
  (* Mem - Imm (Priority 1) *)
  | TwoOperands(Label _, OprImm(imm, _)) ->
    encLI ctx ins 0b010uy imm 32<rt> [| 0x80uy |] [| 0x81uy |]
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x80uy |] b s d 0b010uy imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x81uy |] b s d 0b010uy imm 16<rt>
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x81uy |] b s d 0b010uy imm 32<rt>
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprImm(imm, _)) ->
    no32Arch ctx.WordSize;
    encMI ins ctx ctx.PrefNormal ctx.RexW [| 0x81uy |] b s d 0b010uy imm 32<rt>
  (* Mem - Reg *)
  | TwoOperands(Label _, OprReg r) ->
    encRL ctx ins r [| 0x10uy |] [| 0x11uy |]
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprReg r) when isReg8 ctx r ->
    encMR ins ctx ctx.PrefNormal ctx.RexNormal [| 0x10uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprReg r) when isReg16 ctx r ->
    encMR ins ctx ctx.Pref66 ctx.RexNormal [| 0x11uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprReg r) when isReg32 ctx r ->
    encMR ins ctx ctx.PrefNormal ctx.RexNormal [| 0x11uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprReg r) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encMR ins ctx ctx.PrefNormal ctx.RexW [| 0x11uy |] b s d r
  (* Reg - Reg *)
  | TwoOperands(OprReg r1, OprReg r2) when isReg8 ctx r1 && isReg8 ctx r2 ->
    encRR ins ctx ctx.PrefNormal ctx.RexNormal [| 0x12uy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isReg16 ctx r1 && isReg16 ctx r2 ->
    encRR ins ctx ctx.Pref66 ctx.RexNormal [| 0x13uy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isReg32 ctx r1 && isReg32 ctx r2 ->
    encRR ins ctx ctx.PrefNormal ctx.RexNormal [| 0x13uy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isReg64 ctx r1 && isReg64 ctx r2 ->
    no32Arch ctx.WordSize
    encRR ins ctx ctx.PrefNormal ctx.RexW [| 0x13uy |] r1 r2
  (* Reg - Mem *)
  | TwoOperands(OprReg r, Label _) ->
    encRL ctx ins r [| 0x12uy |] [| 0x13uy |]
  | TwoOperands(OprReg r, OprMem(b, s, d, 8<rt>)) when isReg8 ctx r ->
    encRM ins ctx ctx.PrefNormal ctx.RexNormal [| 0x12uy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 16<rt>)) when isReg16 ctx r ->
    encRM ins ctx ctx.Pref66 ctx.RexNormal [| 0x13uy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg32 ctx r ->
    encRM ins ctx ctx.PrefNormal ctx.RexNormal [| 0x13uy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encRM ins ctx ctx.PrefNormal ctx.RexW [| 0x13uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let add (ctx: EncContext) ins =
  match ins.Operands with
  (* Reg (fixed) - Imm (Priority 1) *)
  | TwoOperands(OprReg Register.AL, OprImm(imm, _)) ->
    encImm ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x04uy |] imm 8<rt>
  | TwoOperands(OprReg Register.AX, OprImm(imm, _)) ->
    encImm ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x05uy |] imm 16<rt>
  | TwoOperands(OprReg Register.EAX, OprImm(imm, _)) ->
    encImm ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x05uy |] imm 32<rt>
  | TwoOperands(OprReg Register.RAX, OprImm(imm, _)) ->
    no32Arch ctx.WordSize
    encImm ins ctx
      ctx.PrefNormal ctx.RexW [| 0x05uy |] imm 32<rt>
  (* Reg - Imm (Priority 0) *)
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg16 ctx r && isInt8 imm ->
    encRI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x83uy |] r 0b000uy imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg32 ctx r && isInt8 imm ->
    encRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x83uy |] r 0b000uy imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg64 ctx r && isInt8 imm ->
    no32Arch ctx.WordSize
    encRI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x83uy |] r 0b000uy imm 8<rt>
  (* Mem - Imm (Priority 0) *)
  | TwoOperands(Label _, OprImm(imm, _)) when isInt8 imm ->
    encLI ctx ins 0b000uy imm 8<rt> [||] [| 0x83uy |]
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprImm(imm, _)) when isInt8 imm ->
    encMI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x83uy |] b s d 0b000uy imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprImm(imm, _)) when isInt8 imm ->
    encMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x83uy |] b s d 0b000uy imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprImm(imm, _)) when isInt8 imm ->
    no32Arch ctx.WordSize
    encMI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x83uy |] b s d 0b000uy imm 8<rt>
  (* Reg - Imm (Priority 1) *)
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg8 ctx r ->
    encRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x80uy |] r 0b000uy imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg16 ctx r ->
    encRI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x81uy |] r 0b000uy imm 16<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg32 ctx r ->
    encRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x81uy |] r 0b000uy imm 32<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encRI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x81uy |] r 0b000uy imm 32<rt>
  (* Mem - Imm (Priority 1) *)
  | TwoOperands(Label _, OprImm(imm, _)) ->
    encLI ctx ins 0b000uy imm 32<rt> [| 0x80uy |] [| 0x81uy |]
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x80uy |] b s d 0b000uy imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x81uy |] b s d 0b000uy imm 16<rt>
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x81uy |] b s d 0b000uy imm 32<rt>
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprImm(imm, _)) ->
    no32Arch ctx.WordSize;
    encMI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x81uy |] b s d 0b000uy imm 32<rt>
  (* Mem - Reg *)
  | TwoOperands(Label _, OprReg r) ->
    encRL ctx ins r [| 0x00uy |] [| 0x01uy |]
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprReg r) when isReg8 ctx r ->
    encMR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x00uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprReg r) when isReg16 ctx r ->
    encMR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x01uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprReg r) when isReg32 ctx r ->
    encMR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x01uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprReg r) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encMR ins ctx
      ctx.PrefNormal ctx.RexW [| 0x01uy |] b s d r
  (* Reg - Reg *)
  | TwoOperands(OprReg r1, OprReg r2) when isReg8 ctx r1 && isReg8 ctx r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x02uy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isReg16 ctx r1 && isReg16 ctx r2 ->
    encRR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x03uy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isReg32 ctx r1 && isReg32 ctx r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x03uy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isReg64 ctx r1 && isReg64 ctx r2 ->
    no32Arch ctx.WordSize
    encRR ins ctx
      ctx.PrefNormal ctx.RexW [| 0x03uy |] r1 r2
  (* Reg - Mem *)
  | TwoOperands(OprReg r, Label _) ->
    encRL ctx ins r [| 0x02uy |] [| 0x03uy |]
  | TwoOperands(OprReg r, OprMem(b, s, d, 8<rt>)) when isReg8 ctx r ->
    encRM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x02uy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 16<rt>)) when isReg16 ctx r ->
    encRM ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x03uy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg32 ctx r ->
    encRM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x03uy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encRM ins ctx
      ctx.PrefNormal ctx.RexW [| 0x03uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let addpd (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0x58uy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 128<rt>)) when isXMMReg r ->
    encRM ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0x58uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let addps (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0x58uy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 128<rt>)) when isXMMReg r ->
    encRM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0x58uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let addsd (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctx
      ctx.PrefF2 ctx.RexNormal [| 0x0Fuy; 0x58uy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isXMMReg r ->
    encRM ins ctx
      ctx.PrefF2 ctx.RexNormal [| 0x0Fuy; 0x58uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let addss (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctx
      ctx.PrefF3 ctx.RexNormal [| 0x0Fuy; 0x58uy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isXMMReg r ->
    encRM ins ctx
      ctx.PrefF3 ctx.RexNormal [| 0x0Fuy; 0x58uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let logAnd (ctx: EncContext) ins =
  match ins.Operands with
  (* Reg (fixed) - Imm *)
  | TwoOperands(OprReg Register.AL, OprImm(imm, _)) ->
    encImm ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x24uy |] imm 8<rt>
  | TwoOperands(OprReg Register.AX, OprImm(imm, _)) ->
    encImm ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x25uy |] imm 16<rt>
  | TwoOperands(OprReg Register.EAX, OprImm(imm, _)) ->
    encImm ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x25uy |] imm 32<rt>
  | TwoOperands(OprReg Register.RAX, OprImm(imm, _)) ->
    no32Arch ctx.WordSize
    encImm ins ctx
      ctx.PrefNormal ctx.RexW [| 0x25uy |] imm 32<rt>
  (* Reg - Imm (Priority 0) *)
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg16 ctx r && isInt8 imm ->
    encRI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x83uy |] r 0b100uy imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg32 ctx r && isInt8 imm ->
    encRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x83uy |] r 0b100uy imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg64 ctx r && isInt8 imm ->
    no32Arch ctx.WordSize
    encRI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x83uy |] r 0b100uy imm 8<rt>
  (* Mem - Imm (Priority 0) *)
  | TwoOperands(Label _, OprImm(imm, _)) when isInt8 imm ->
    encLI ctx ins 0b100uy imm 8<rt> [||] [| 0x83uy |]
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprImm(imm, _)) when isInt8 imm ->
    encMI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x83uy |] b s d 0b100uy imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprImm(imm, _)) when isInt8 imm ->
    encMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x83uy |] b s d 0b100uy imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprImm(imm, _)) when isInt8 imm ->
    no32Arch ctx.WordSize
    encMI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x83uy |] b s d 0b100uy imm 8<rt>
  (* Reg - Imm (Priority 1) *)
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg8 ctx r ->
    encRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x80uy |] r 0b100uy imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg16 ctx r ->
    encRI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x81uy |] r 0b100uy imm 16<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg32 ctx r ->
    encRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x81uy |] r 0b100uy imm 32<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encRI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x81uy |] r 0b100uy imm 32<rt>
  (* Mem - Imm (Priority 1) *)
  | TwoOperands(Label _, OprImm(imm, _)) ->
    encLI ctx ins 0b100uy imm 32<rt> [| 0x80uy |] [| 0x81uy |]
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x80uy |] b s d 0b100uy imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x81uy |] b s d 0b100uy imm 16<rt>
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x81uy |] b s d 0b100uy imm 32<rt>
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprImm(imm, _)) ->
    no32Arch ctx.WordSize;
    encMI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x81uy |] b s d 0b100uy imm 32<rt>
  (* Mem - Reg *)
  | TwoOperands(Label _, OprReg r) ->
    encRL ctx ins r [| 0x20uy |] [| 0x21uy |]
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprReg r) when isReg8 ctx r ->
    encMR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x20uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprReg r) when isReg16 ctx r ->
    encMR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x21uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprReg r) when isReg32 ctx r ->
    encMR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x21uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprReg r) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encMR ins ctx
      ctx.PrefNormal ctx.RexW [| 0x21uy |] b s d r
  (* Reg - Reg *)
  | TwoOperands(OprReg r1, OprReg r2) when isReg8 ctx r1 && isReg8 ctx r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x22uy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isReg16 ctx r1 && isReg16 ctx r2 ->
    encRR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x23uy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isReg32 ctx r1 && isReg32 ctx r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x23uy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isReg64 ctx r1 && isReg64 ctx r2 ->
    no32Arch ctx.WordSize
    encRR ins ctx
      ctx.PrefNormal ctx.RexW [| 0x23uy |] r1 r2
  (* Reg - Mem *)
  | TwoOperands(OprReg r, Label _) ->
    encRL ctx ins r [| 0x22uy |] [| 0x23uy |]
  | TwoOperands(OprReg r, OprMem(b, s, d, 8<rt>)) when isReg8 ctx r ->
    encRM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x22uy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 16<rt>)) when isReg16 ctx r ->
    encRM ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x23uy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg32 ctx r ->
    encRM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x23uy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encRM ins ctx
      ctx.PrefNormal ctx.RexW [| 0x23uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let andpd (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0x54uy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 128<rt>)) when isXMMReg r ->
    encRM ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0x54uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let andps (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0x54uy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 128<rt>)) when isXMMReg r ->
    encRM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0x54uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let bsr (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isReg16 ctx r1 && isReg16 ctx r2 ->
    encRR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0xBDuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 16<rt>)) when isReg16 ctx r ->
    encRM ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0xBDuy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2) when isReg32 ctx r1 && isReg32 ctx r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0xBDuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg32 ctx r ->
    encRM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0xBDuy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2) when isReg64 ctx r1 && isReg64 ctx r2 ->
    no32Arch ctx.WordSize
    encRR ins ctx
      ctx.PrefNormal ctx.RexW [| 0x0Fuy; 0xBDuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encRM ins ctx
      ctx.PrefNormal ctx.RexW [| 0x0Fuy; 0xBDuy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let bt (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isReg16 ctx r1 && isReg16 ctx r2 ->
    encRR ins ctx
      ctx.Pref66 ctx.RexMR [| 0x0Fuy; 0xA3uy |] r2 r1
  | TwoOperands(OprReg r1, OprReg r2) when isReg32 ctx r1 && isReg32 ctx r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexMR [| 0x0Fuy; 0xA3uy |] r2 r1
  | TwoOperands(OprReg r1, OprReg r2) when isReg64 ctx r1 && isReg64 ctx r2 ->
    no32Arch ctx.WordSize
    encRR ins ctx
      ctx.PrefNormal ctx.RexWAndMR [| 0x0Fuy; 0xA3uy |] r2 r1
  | TwoOperands(Label _, OprReg r) ->
    encRL ctx ins r [||] [| 0x0Fuy; 0xA3uy |]
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprReg r) when isReg16 ctx r ->
    encMR ins ctx
      ctx.Pref66 ctx.RexMR [| 0x0Fuy; 0xA3uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprReg r) when isReg32 ctx r ->
    encMR ins ctx
      ctx.PrefNormal ctx.RexMR [| 0x0Fuy; 0xA3uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprReg r) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encMR ins ctx
      ctx.PrefNormal ctx.RexWAndMR [| 0x0Fuy; 0xA3uy |] b s d r
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg16 ctx r ->
    encRI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0xBAuy |] r 0b100uy imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg32 ctx r ->
    encRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0xBAuy |] r 0b100uy imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encRI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x0Fuy; 0xBAuy |] r 0b100uy imm 8<rt>
  | TwoOperands(Label _, OprImm(imm, _)) ->
    encLI ctx ins 0b100uy imm 32<rt> [||] [| 0x0Fuy; 0xBAuy |]
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0xBAuy |] b s d 0b100uy imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprImm(i, _)) ->
    encMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0xBAuy |] b s d 0b100uy i 8<rt>
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprImm(imm, _)) ->
    no32Arch ctx.WordSize
    encMI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x0Fuy; 0xBAuy |] b s d 0b100uy imm 8<rt>
  | o -> printfn "%A" o; raise NotEncodableException

let call (ctx: EncContext) ins =
  match ins.Operands with
  | OneOperand(OprDirAddr(Relative rel))
    when isInt16 rel && ctx.WordSize = WordSize.Bit32 ->
    encD ins ctx
      ctx.Pref66 ctx.RexNormal [| 0xE8uy |] rel 16<rt>
  | OneOperand(OprDirAddr(Relative rel))
    when isInt32 rel ->
    encD ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xE8uy |] rel 32<rt>
  | OneOperand(Label _) ->
    encLbl ins
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    no64Arch ctx.WordSize
    encM ins ctx
      ctx.Pref66 ctx.RexNormal [| 0xFFuy |] b s d 0b010uy
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    no64Arch ctx.WordSize
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xFFuy |] b s d 0b010uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    no32Arch ctx.WordSize
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xFFuy |] b s d 0b010uy
  | OneOperand(OprReg r) when isReg16 ctx r ->
    no64Arch ctx.WordSize
    encR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0xFFuy |] r 0b010uy
  | OneOperand(OprReg r) when isReg32 ctx r ->
    no64Arch ctx.WordSize
    encR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xFFuy |] r 0b010uy
  | OneOperand(OprReg r) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xFFuy |] r 0b010uy
  | o -> printfn "%A" o; raise NotEncodableException

let cbw _ctx = function
  | NoOperand -> [| Normal 0x66uy; Normal 0x98uy |]
  | _ -> raise NotEncodableException

let cdq _ctx = function
  | NoOperand -> [| Normal 0x99uy |]
  | _ -> raise NotEncodableException

let cdqe (ctx: EncContext) = function
  | NoOperand -> no32Arch ctx.WordSize; [| Normal 0x48uy; Normal 0x98uy |]
  | _ -> raise NotEncodableException

let cmovcc (ctx: EncContext) ins opcode =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isReg16 ctx r1 && isReg16 ctx r2 ->
    encRR ins ctx
      ctx.Pref66 ctx.RexNormal opcode r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isReg32 ctx r1 && isReg32 ctx r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexNormal opcode r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isReg64 ctx r1 && isReg64 ctx r2 ->
    no32Arch ctx.WordSize
    encRR ins ctx
      ctx.PrefNormal ctx.RexW opcode r1 r2
  | TwoOperands(Label _, OprReg r) ->
    encRL ctx ins r [||] opcode
  | TwoOperands(OprReg r, OprMem(b, s, d, 16<rt>)) when isReg16 ctx r ->
    encMR ins ctx
      ctx.Pref66 ctx.RexNormal opcode b s d r
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg32 ctx r ->
    encMR ins ctx
      ctx.PrefNormal ctx.RexNormal opcode b s d r
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encMR ins ctx
      ctx.PrefNormal ctx.RexW opcode b s d r
  | o -> printfn "%A" o; raise NotEncodableException

let cmova ctx ins = cmovcc ctx ins [| 0x0Fuy; 0x47uy |]

let cmovae ctx ins = cmovcc ctx ins [| 0x0Fuy; 0x43uy |]

let cmovb ctx ins = cmovcc ctx ins [| 0x0Fuy; 0x42uy |]

let cmovbe ctx ins = cmovcc ctx ins [| 0x0Fuy; 0x46uy |]

let cmovg ctx ins = cmovcc ctx ins [| 0x0Fuy; 0x4Fuy |]

let cmovge ctx ins = cmovcc ctx ins [| 0x0Fuy; 0x4Duy |]

let cmovl ctx ins = cmovcc ctx ins [| 0x0Fuy; 0x4Cuy |]

let cmovle ctx ins = cmovcc ctx ins [| 0x0Fuy; 0x4Euy |]

let cmovno ctx ins = cmovcc ctx ins [| 0x0Fuy; 0x41uy |]

let cmovnp ctx ins = cmovcc ctx ins [| 0x0Fuy; 0x4Buy |]

let cmovns ctx ins = cmovcc ctx ins [| 0x0Fuy; 0x49uy |]

let cmovnz ctx ins = cmovcc ctx ins [| 0x0Fuy; 0x45uy |]

let cmovo ctx ins = cmovcc ctx ins [| 0x0Fuy; 0x40uy |]

let cmovp ctx ins = cmovcc ctx ins [| 0x0Fuy; 0x4Auy |]

let cmovs ctx ins = cmovcc ctx ins [| 0x0Fuy; 0x48uy |]

let cmovz ctx ins = cmovcc ctx ins [| 0x0Fuy; 0x44uy |]

let cmp (ctx: EncContext) ins =
  match ins.Operands with
  (* Reg (fixed) - Imm (Priority 1) *)
  | TwoOperands(OprReg Register.AL, OprImm(imm, _)) ->
    encImm ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x3Cuy |] imm 8<rt>
  | TwoOperands(OprReg Register.AX, OprImm(imm, _)) ->
    encImm ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x3Duy |] imm 16<rt>
  | TwoOperands(OprReg Register.EAX, OprImm(imm, _)) ->
    encImm ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x3Duy |] imm 32<rt>
  | TwoOperands(OprReg Register.RAX, OprImm(imm, _)) ->
    no32Arch ctx.WordSize
    encImm ins ctx
      ctx.PrefNormal ctx.RexW [| 0x3Duy |] imm 32<rt>
  (* Reg - Imm (Priority 0) *)
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg16 ctx r && isInt8 imm ->
    encRI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x83uy |] r 0b111uy imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg32 ctx r && isInt8 imm ->
    encRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x83uy |] r 0b111uy imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg64 ctx r && isInt8 imm ->
    no32Arch ctx.WordSize
    encRI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x83uy |] r 0b111uy imm 8<rt>
  (* Mem - Imm (Priority 0) *)
  | TwoOperands(Label _, OprImm(imm, _)) when isInt8 imm ->
    encLI ctx ins 0b111uy imm 8<rt> [||] [| 0x83uy |]
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprImm(imm, _)) when isInt8 imm ->
    encMI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x83uy |] b s d 0b111uy imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprImm(imm, _)) when isInt8 imm ->
    encMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x83uy |] b s d 0b111uy imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprImm(imm, _)) when isInt8 imm ->
    no32Arch ctx.WordSize
    encMI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x83uy |] b s d 0b111uy imm 8<rt>
  (* Reg - Imm (Priority 1) *)
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg8 ctx r ->
    encRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x80uy |] r 0b111uy imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg16 ctx r ->
    encRI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x81uy |] r 0b111uy imm 16<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg32 ctx r ->
    encRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x81uy |] r 0b111uy imm 32<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encRI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x81uy |] r 0b111uy imm 32<rt>
  (* Mem - Imm (Priority 1) *)
  | TwoOperands(Label _, OprImm(imm, _)) ->
    encLI ctx ins 0b111uy imm 32<rt> [| 0x80uy |] [| 0x81uy |]
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x80uy |] b s d 0b111uy imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x81uy |] b s d 0b111uy imm 16<rt>
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x81uy |] b s d 0b111uy imm 32<rt>
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprImm(imm, _)) ->
    no32Arch ctx.WordSize;
    encMI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x81uy |] b s d 0b111uy imm 32<rt>
  (* Mem - Reg *)
  | TwoOperands(Label _, OprReg r) ->
    encRL ctx ins r [| 0x38uy |] [| 0x39uy |]
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprReg r) when isReg8 ctx r ->
    encMR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x38uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprReg r) when isReg16 ctx r ->
    encMR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x39uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprReg r) when isReg32 ctx r ->
    encMR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x39uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprReg r) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encMR ins ctx
      ctx.PrefNormal ctx.RexW [| 0x39uy |] b s d r
  (* Reg - Reg *)
  | TwoOperands(OprReg r1, OprReg r2) when isReg8 ctx r1 && isReg8 ctx r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x3Auy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isReg16 ctx r1 && isReg16 ctx r2 ->
    encRR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x3Buy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isReg32 ctx r1 && isReg32 ctx r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x3Buy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isReg64 ctx r1 && isReg64 ctx r2 ->
    no32Arch ctx.WordSize
    encRR ins ctx
      ctx.PrefNormal ctx.RexW [| 0x3Buy |] r1 r2
  (* Reg - Mem *)
  | TwoOperands(OprReg r, Label _) ->
    encRL ctx ins r [| 0x3Auy |] [| 0x3Buy |]
  | TwoOperands(OprReg r, OprMem(b, s, d, 8<rt>)) when isReg8 ctx r ->
    encRM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x3Auy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 16<rt>)) when isReg16 ctx r ->
    encRM ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x3Buy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg32 ctx r ->
    encRM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x3Buy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encRM ins ctx
      ctx.PrefNormal ctx.RexW [| 0x3Buy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let cmpsb (ctx: EncContext) ins =
  match ins.Operands with
  | NoOperand ->
    encNP ins ctx
      ctx.PrefREP ctx.RexNormal [| 0xA6uy |]
  | o -> printfn "%A" o; raise NotEncodableException

let cmpxchg (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isReg8 ctx r1 && isReg8 ctx r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexMR [| 0x0Fuy; 0xB0uy |] r2 r1
  | TwoOperands(OprReg r1, OprReg r2) when isReg16 ctx r1 && isReg16 ctx r2 ->
    encRR ins ctx
      ctx.Pref66 ctx.RexMR [| 0x0Fuy; 0xB1uy |] r2 r1
  | TwoOperands(OprReg r1, OprReg r2) when isReg32 ctx r1 && isReg32 ctx r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexMR [| 0x0Fuy; 0xB1uy |] r2 r1
  | TwoOperands(OprReg r1, OprReg r2) when isReg64 ctx r1 && isReg64 ctx r2 ->
    no32Arch ctx.WordSize
    encRR ins ctx
      ctx.PrefNormal ctx.RexWAndMR [| 0x0Fuy; 0xB1uy |] r2 r1
  | TwoOperands(Label _, OprReg r) ->
    encRL ctx ins r [| 0x0Fuy; 0xB0uy |] [| 0x0Fuy; 0xB1uy |]
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprReg r) when isReg8 ctx r ->
    encMR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0xB0uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprReg r) when isReg16 ctx r ->
    encMR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0xB1uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprReg r) when isReg32 ctx r ->
    encMR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0xB1uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprReg r) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encMR ins ctx
      ctx.PrefNormal ctx.RexW [| 0x0Fuy; 0xB1uy |] b s d r
  | o -> printfn "%A" o; raise NotEncodableException

let cmpxchg8b (ctx: EncContext) ins =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0xC7uy |] b s d 0b001uy
  | o -> printfn "%A" o; raise NotEncodableException

let cmpxchg16b (ctx: EncContext) ins =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, 128<rt>)) ->
    no32Arch ctx.WordSize
    encM ins ctx
      ctx.PrefNormal ctx.RexW [| 0x0Fuy; 0xC7uy |] b s d 0b001uy
  | o -> printfn "%A" o; raise NotEncodableException

let cvtsd2ss (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctx
      ctx.PrefF2 ctx.RexNormal [| 0x0Fuy; 0x5Auy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isXMMReg r ->
    encRM ins ctx
      ctx.PrefF2 ctx.RexNormal [| 0x0Fuy; 0x5Auy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let cvtsi2sd (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isReg32 ctx r2 ->
    encRR ins ctx
      ctx.PrefF2 ctx.RexNormal [| 0x0Fuy; 0x2Auy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isXMMReg r ->
    encRM ins ctx
      ctx.PrefF2 ctx.RexNormal [| 0x0Fuy; 0x2Auy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isReg64 ctx r2 ->
    encRR ins ctx
      ctx.PrefF2 ctx.RexW [| 0x0Fuy; 0x2Auy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isXMMReg r ->
    encRM ins ctx
      ctx.PrefF2 ctx.RexW [| 0x0Fuy; 0x2Auy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let cvtsi2ss (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isReg32 ctx r2 ->
    encRR ins ctx
      ctx.PrefF3 ctx.RexNormal [| 0x0Fuy; 0x2Auy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isXMMReg r ->
    encRM ins ctx
      ctx.PrefF3 ctx.RexNormal [| 0x0Fuy; 0x2Auy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isReg64 ctx r2 ->
    encRR ins ctx
      ctx.PrefF3 ctx.RexW [| 0x0Fuy; 0x2Auy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isXMMReg r ->
    encRM ins ctx
      ctx.PrefF3 ctx.RexW [| 0x0Fuy; 0x2Auy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let cvtss2si (ctx: EncContext) ins =
   match ins.Operands with
   | TwoOperands(OprReg r1, OprReg r2) when isReg32 ctx r1 && isXMMReg r2 ->
     encRR ins ctx
       ctx.PrefF3 ctx.RexNormal [| 0x0Fuy; 0x2Duy |] r1 r2
   | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg32 ctx r ->
     encRM ins ctx
       ctx.PrefF3 ctx.RexNormal [| 0x0Fuy; 0x2Duy |] r b s d
   | TwoOperands(OprReg r1, OprReg r2) when isReg64 ctx r1 && isXMMReg r2 ->
     encRR ins ctx
       ctx.PrefF3 ctx.RexW [| 0x0Fuy; 0x2Duy |] r1 r2
   | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg64 ctx r ->
     encRM ins ctx
       ctx.PrefF3 ctx.RexW [| 0x0Fuy; 0x2Duy |] r b s d
   | o -> printfn "%A" o; raise NotEncodableException

let cvttss2si (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isReg32 ctx r1 && isXMMReg r2 ->
    encRR ins ctx
      ctx.PrefF3 ctx.RexNormal [| 0x0Fuy; 0x2Cuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg32 ctx r ->
    encRM ins ctx
      ctx.PrefF3 ctx.RexNormal [| 0x0Fuy; 0x2Cuy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2) when isReg64 ctx r1 && isXMMReg r2 ->
    encRR ins ctx
      ctx.PrefF3 ctx.RexW [| 0x0Fuy; 0x2Cuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isReg64 ctx r ->
    encRM ins ctx
      ctx.PrefF3 ctx.RexW [| 0x0Fuy; 0x2Cuy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let cwde _ctx = function
  | NoOperand -> [| Normal 0x98uy |]
  | _ -> raise NotEncodableException

let dec (ctx: EncContext) ins =
  match ins.Operands with
  | OneOperand(OprReg r) when isReg8 ctx r ->
    encR ins ctx ctx.PrefNormal ctx.RexNormal [| 0xFEuy |] r 1uy
  | OneOperand(OprMem(b, s, d, 8<rt>)) ->
    encM ins ctx ctx.PrefNormal ctx.RexNormal [| 0xFEuy |] b s d 1uy
  | OneOperand(OprReg r) when isReg16 ctx r ->
    if isClassicGPReg r && ctx.WordSize = WordSize.Bit32 then
      encClassicR true 0x48uy (regTo3Bit r)
    else encR ins ctx ctx.Pref66 ctx.RexNormal [| 0xFFuy |] r 1uy
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins ctx ctx.Pref66 ctx.RexNormal [| 0xFFuy |] b s d 1uy
  | OneOperand(OprReg r) when isReg32 ctx r ->
    if isClassicGPReg r && ctx.WordSize = WordSize.Bit32 then
      encClassicR false 0x48uy (regTo3Bit r)
    else encR ins ctx ctx.PrefNormal ctx.RexNormal [| 0xFFuy |] r 1uy
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins ctx ctx.PrefNormal ctx.RexNormal [| 0xFFuy |] b s d 1uy
  | OneOperand(OprReg r) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encR ins ctx ctx.PrefNormal ctx.RexW [| 0xFFuy |] r 1uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    no32Arch ctx.WordSize
    encM ins ctx ctx.PrefNormal ctx.RexW [| 0xFFuy |] b s d 1uy
  | o -> printfn "%A" o; raise NotEncodableException

let div (ctx: EncContext) ins =
  match ins.Operands with
  | OneOperand(OprReg r) when isReg8 ctx r ->
    encR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xF6uy |] r 0b110uy
  | OneOperand(OprMem(b, s, d, 8<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xF6uy |] b s d 0b110uy
  | OneOperand(OprReg r) when isReg16 ctx r ->
    encR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0xF7uy |] r 0b110uy
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins ctx
      ctx.Pref66 ctx.RexNormal [| 0xF7uy |] b s d 0b110uy
  | OneOperand(OprReg r) when isReg32 ctx r ->
    encR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xF7uy |] r 0b110uy
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xF7uy |] b s d 0b110uy
  | OneOperand(OprReg r) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encR ins ctx
      ctx.PrefNormal ctx.RexW [| 0xF7uy |] r 0b110uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    no32Arch ctx.WordSize
    encM ins ctx
      ctx.PrefNormal ctx.RexW [| 0xF7uy |] b s d 0b110uy
  | o -> printfn "%A" o; raise NotEncodableException

let divsd (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctx
      ctx.PrefF2 ctx.RexNormal [| 0x0Fuy; 0x5Euy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isXMMReg r ->
    encRM ins ctx
      ctx.PrefF2 ctx.RexNormal [| 0x0Fuy; 0x5Euy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let divss (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctx
      ctx.PrefF3 ctx.RexNormal [| 0x0Fuy; 0x5Euy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isXMMReg r ->
    encRM ins ctx
      ctx.PrefF3 ctx.RexNormal [| 0x0Fuy; 0x5Euy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let fadd (ctx: EncContext) ins =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xD8uy |] b s d 0b000uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xDCuy |] b s d 0b000uy
  | TwoOperands(OprReg Register.ST0, OprReg r) when isFPUReg r ->
    encFR [| 0xD8uy; 0xC0uy |] r
  | TwoOperands(OprReg r, OprReg Register.ST0) when isFPUReg r ->
    encFR [| 0xDCuy; 0xC0uy |] r
  | o -> printfn "%A" o; raise NotEncodableException

let fcmovb _ctx ins =
  match ins.Operands with
  | TwoOperands(OprReg Register.ST0, OprReg r) when isFPUReg r ->
    encFR [| 0xDAuy; 0xC0uy |] r
  | o -> printfn "%A" o; raise NotEncodableException

let fdiv (ctx: EncContext) ins =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xD8uy |] b s d 0b110uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xDCuy |] b s d 0b110uy
  | TwoOperands(OprReg Register.ST0, OprReg r) when isFPUReg r ->
    encFR [| 0xD8uy; 0xF0uy |] r
  | TwoOperands(OprReg r, OprReg Register.ST0) when isFPUReg r ->
    encFR [| 0xDCuy; 0xF8uy |] r
  | o -> printfn "%A" o; raise NotEncodableException

let fdivp _ctx = function
  | NoOperand -> [| Normal 0xDEuy; Normal 0xF9uy |]
  | TwoOperands(OprReg r, OprReg Register.ST0) when isFPUReg r ->
    encFR [| 0xDEuy; 0xF8uy |] r
  | o -> printfn "%A" o; raise NotEncodableException

let fdivrp _ctx = function
  | NoOperand -> [| Normal 0xDEuy; Normal 0xF1uy |]
  | TwoOperands(OprReg r, OprReg Register.ST0) when isFPUReg r ->
    encFR [| 0xDEuy; 0xF0uy |] r
  | o -> printfn "%A" o; raise NotEncodableException

let fild (ctx: EncContext) ins =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xDFuy |] b s d 0b000uy
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xDBuy |] b s d 0b000uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xDFuy |] b s d 0b101uy
  | o -> printfn "%A" o; raise NotEncodableException

let fistp (ctx: EncContext) ins =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xDFuy |] b s d 0b011uy
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xDBuy |] b s d 0b011uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xDFuy |] b s d 0b111uy
  | o -> printfn "%A" o; raise NotEncodableException

let fld (ctx: EncContext) ins =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xD9uy |] b s d 0b000uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xDDuy |] b s d 0b000uy
  | OneOperand(OprMem(b, s, d, 80<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xDBuy |] b s d 0b101uy
  | OneOperand(OprReg r) when isFPUReg r -> encFR [| 0xD9uy; 0xC0uy |] r
  | o -> printfn "%A" o; raise NotEncodableException

let fld1 _ctx = function
  | NoOperand -> [| Normal 0xD9uy; Normal 0xE8uy |]
  | o -> printfn "%A" o; raise NotEncodableException

let fldcw (ctx: EncContext) ins =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xD9uy |] b s d 0b101uy
  | o -> printfn "%A" o; raise NotEncodableException

let fldz _ctx = function
  | NoOperand -> [| Normal 0xD9uy; Normal 0xEEuy |]
  | o -> printfn "%A" o; raise NotEncodableException

let fmul (ctx: EncContext) ins =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xD8uy |] b s d 0b001uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xDCuy |] b s d 0b001uy
  | TwoOperands(OprReg Register.ST0, OprReg r) when isFPUReg r ->
    encFR [| 0xD8uy; 0xC8uy |] r
  | TwoOperands(OprReg r, OprReg Register.ST0) when isFPUReg r ->
    encFR [| 0xDCuy; 0xC8uy |] r
  | o -> printfn "%A" o; raise NotEncodableException

let fmulp _ctx = function
  | NoOperand -> [| Normal 0xDEuy; Normal 0xC9uy |]
  | TwoOperands(OprReg r, OprReg Register.ST0) when isFPUReg r ->
    encFR [| 0xDEuy; 0xC8uy |] r
  | o -> printfn "%A" o; raise NotEncodableException

let fnstcw (ctx: EncContext) ins =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xD9uy |] b s d 0b111uy
  | o -> printfn "%A" o; raise NotEncodableException

let fstp (ctx: EncContext) ins =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xD9uy |] b s d 0b011uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xDDuy |] b s d 0b011uy
  | OneOperand(OprMem(b, s, d, 80<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xDBuy |] b s d 0b111uy
  | OneOperand(OprReg r) when isFPUReg r -> encFR [| 0xDDuy; 0xD8uy |] r
  | o -> printfn "%A" o; raise NotEncodableException

let fsub (ctx: EncContext) ins =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xD8uy |] b s d 0b100uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xDCuy |] b s d 0b100uy
  | TwoOperands(OprReg Register.ST0, OprReg r) when isFPUReg r ->
    encFR [| 0xD8uy; 0xE0uy |] r
  | TwoOperands(OprReg r, OprReg Register.ST0) when isFPUReg r ->
    encFR [| 0xDCuy; 0xE8uy |] r
  | o -> printfn "%A" o; raise NotEncodableException

let fsubr (ctx: EncContext) ins =
  match ins.Operands with
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xD8uy |] b s d 0b101uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xDCuy |] b s d 0b101uy
  | TwoOperands(OprReg Register.ST0, OprReg r) when isFPUReg r ->
    encFR [| 0xD8uy; 0xE8uy |] r
  | TwoOperands(OprReg r, OprReg Register.ST0) when isFPUReg r ->
    encFR [| 0xDCuy; 0xE0uy |] r
  | o -> printfn "%A" o; raise NotEncodableException

let fucomi _ctx = function
  | TwoOperands(OprReg Register.ST0, OprReg r) when isFPUReg r ->
    encFR [| 0xDBuy; 0xE8uy |] r
  | o -> printfn "%A" o; raise NotEncodableException

let fucomip _ctx = function
  | TwoOperands(OprReg Register.ST0, OprReg r) when isFPUReg r ->
    encFR [| 0xDFuy; 0xE8uy |] r
  | o -> printfn "%A" o; raise NotEncodableException

let fxch _ctx = function
  | NoOperand -> [| Normal 0xD9uy; Normal 0xC9uy |]
  | OneOperand(OprReg r) when isFPUReg r -> encFR [| 0xD9uy; 0xC8uy |] r
  | o -> printfn "%A" o; raise NotEncodableException

let hlt _ctx = function
  | NoOperand -> [| Normal 0xF4uy |]
  | _ -> raise NotEncodableException

let idiv (ctx: EncContext) ins =
  match ins.Operands with
  | OneOperand(OprReg r) when isReg8 ctx r ->
    encR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xF6uy |] r 0b111uy
  | OneOperand(OprMem(b, s, d, 8<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xF6uy |] b s d 0b111uy
  | OneOperand(OprReg r) when isReg16 ctx r ->
    encR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0xF7uy |] r 0b111uy
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins ctx
      ctx.Pref66 ctx.RexNormal [| 0xF7uy |] b s d 0b111uy
  | OneOperand(OprReg r) when isReg32 ctx r ->
    encR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xF7uy |] r 0b111uy
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xF7uy |] b s d 0b111uy
  | OneOperand(OprReg r) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encR ins ctx
      ctx.PrefNormal ctx.RexW [| 0xF7uy |] r 0b111uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    no32Arch ctx.WordSize
    encM ins ctx
      ctx.PrefNormal ctx.RexW [| 0xF7uy |] b s d 0b111uy
  | o -> printfn "%A" o; raise NotEncodableException

let imul (ctx: EncContext) ins =
  match ins.Operands with
  | OneOperand(OprReg r) when isReg8 ctx r ->
    encR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xF6uy |] r 0b101uy
  | OneOperand(OprMem(b, s, d, 8<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xF6uy |] b s d 0b101uy
  | OneOperand(OprReg r) when isReg16 ctx r ->
    encR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0xF7uy |] r 0b101uy
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins ctx
      ctx.Pref66 ctx.RexNormal [| 0xF7uy |] b s d 0b101uy
  | OneOperand(OprReg r) when isReg32 ctx r ->
    encR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xF7uy |] r 0b101uy
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xF7uy |] b s d 0b101uy
  | OneOperand(OprReg r) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encR ins ctx
      ctx.PrefNormal ctx.RexW [| 0xF7uy |] r 0b101uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    no32Arch ctx.WordSize
    encM ins ctx
      ctx.PrefNormal ctx.RexW [| 0xF7uy |] b s d 0b101uy
  | TwoOperands(OprReg r1, OprReg r2) when isReg16 ctx r1 && isReg16 ctx r2 ->
    encRR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0xAFuy |] r1 r2
  | TwoOperands(OprReg r, Label _) ->
    encRL ctx ins r [||] [| 0x0Fuy; 0xAFuy |]
  | TwoOperands(OprReg r, OprMem(b, s, d, 16<rt>)) when isReg16 ctx r ->
    encRM ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0xAFuy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2) when isReg32 ctx r1 && isReg32 ctx r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0xAFuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg32 ctx r ->
    encRM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0xAFuy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2) when isReg64 ctx r1 && isReg64 ctx r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexW [| 0x0Fuy; 0xAFuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isReg64 ctx r ->
    encRM ins ctx
      ctx.PrefNormal ctx.RexW [| 0x0Fuy; 0xAFuy |] r b s d
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _))
    when isReg16 ctx r1 && isReg16 ctx r2 && isInt8 imm ->
    encRRI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x6Buy |] r1 r2 imm 8<rt>
  | ThreeOperands(OprReg r, Label _, OprImm(imm, _)) when isInt8 imm ->
    encRLI ctx ins r [| 0x6Buy |] imm 8<rt>
  | ThreeOperands(OprReg r, OprMem(b, s, d, 16<rt>), OprImm(imm, _))
    when isReg16 ctx r && isInt8 imm ->
    encRMI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x6Buy |] r b s d imm 8<rt>
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _))
    when isReg32 ctx r1 && isReg32 ctx r2 && isInt8 imm ->
    encRRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x6Buy |] r1 r2 imm 8<rt>
  | ThreeOperands(OprReg r, OprMem(b, s, d, 32<rt>), OprImm(imm, _))
    when isReg32 ctx r && isInt8 imm ->
    encRMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x6Buy |] r b s d imm 8<rt>
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _))
    when isReg64 ctx r1 && isReg64 ctx r2 && isInt8 imm ->
    no32Arch ctx.WordSize
    encRRI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x6Buy |] r1 r2 imm 8<rt>
  | ThreeOperands(OprReg r, OprMem(b, s, d, 64<rt>), OprImm(imm, _))
    when isReg64 ctx r && isInt8 imm ->
    no32Arch ctx.WordSize
    encRMI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x6Buy |] r b s d imm 8<rt>
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _))
    when isReg16 ctx r1 && isReg16 ctx r2 ->
    encRRI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x69uy |] r1 r2 imm 16<rt>
  | ThreeOperands(OprReg r, Label _, OprImm(imm, _)) ->
    encRLI ctx ins r [| 0x69uy |] imm 32<rt>
  | ThreeOperands(OprReg r, OprMem(b, s, d, 16<rt>), OprImm(imm, _))
    when isReg16 ctx r ->
    encRMI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x69uy |] r b s d imm 16<rt>
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _))
    when isReg32 ctx r1 && isReg32 ctx r2 ->
    encRRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x69uy |] r1 r2 imm 32<rt>
  | ThreeOperands(OprReg r, OprMem(b, s, d, 32<rt>), OprImm(imm, _))
    when isReg32 ctx r ->
    encRMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x69uy |] r b s d imm 32<rt>
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _))
    when isReg64 ctx r1 && isReg64 ctx r2 ->
    no32Arch ctx.WordSize
    encRRI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x69uy |] r1 r2 imm 32<rt>
  | ThreeOperands(OprReg r, OprMem(b, s, d, 64<rt>), OprImm(imm, _))
    when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encRMI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x69uy |] r b s d imm 32<rt>
  | o -> printfn "%A" o; raise NotEncodableException

let inc (ctx: EncContext) ins =
  match ins.Operands with
  | OneOperand(OprReg r) when isReg8 ctx r ->
    encR ins ctx ctx.PrefNormal ctx.RexNormal [| 0xFEuy |] r 0uy
  | OneOperand(OprMem(b, s, d, 8<rt>)) ->
    encM ins ctx ctx.PrefNormal ctx.RexNormal [| 0xFEuy |] b s d 0uy
  | OneOperand(OprReg r) when isReg16 ctx r ->
    if isClassicGPReg r && ctx.WordSize = WordSize.Bit32 then
      encClassicR true 0x40uy (regTo3Bit r)
    else encR ins ctx ctx.Pref66 ctx.RexNormal [| 0xFFuy |] r 0uy
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins ctx ctx.Pref66 ctx.RexNormal [| 0xFFuy |] b s d 0uy
  | OneOperand(OprReg r) when isReg32 ctx r ->
    if isClassicGPReg r && ctx.WordSize = WordSize.Bit32 then
      encClassicR false 0x40uy (regTo3Bit r)
    else encR ins ctx ctx.PrefNormal ctx.RexNormal [| 0xFFuy |] r 0uy
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins ctx ctx.PrefNormal ctx.RexNormal [| 0xFFuy |] b s d 0uy
  | OneOperand(OprReg r) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encR ins ctx ctx.PrefNormal ctx.RexW [| 0xFFuy |] r 0uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    no32Arch ctx.WordSize
    encM ins ctx ctx.PrefNormal ctx.RexW [| 0xFFuy |] b s d 0uy
  | o -> printfn "%A" o; raise NotEncodableException

let interrupt ins =
  match ins.Operands with
  | OneOperand(OprImm(n, _)) when isUInt8 n ->
    [| Normal 0xcduy; Normal(byte n) |]
  | o -> printfn "%A" o; raise NotEncodableException

let interrupt3 () = [| Normal 0xccuy |]

let jcc (ctx: EncContext) ins op8Byte opByte op =
  match ins.Operands with
  | OneOperand(Label _) ->
    encLbl ins
  | OneOperand(OprDirAddr(Relative rel)) when isInt8 rel ->
    encD ins ctx
      ctx.PrefNormal ctx.RexNormal [| op8Byte |] rel 8<rt>
  | OneOperand(OprDirAddr(Relative rel))
    when isInt16 rel && ctx.WordSize = WordSize.Bit32 ->
    encD ins ctx
      ctx.Pref66 ctx.RexNormal opByte rel 16<rt>
  | OneOperand(OprDirAddr(Relative rel)) when isInt32 rel ->
    encD ins ctx
      ctx.PrefNormal ctx.RexNormal opByte rel 32<rt>
  | o -> printfn "%A" o; raise NotEncodableException

let ja ctx ins = jcc ctx ins 0x77uy [| 0x0Fuy; 0x87uy |] Opcode.JA

let jb ctx ins = jcc ctx ins 0x72uy [| 0x0Fuy; 0x82uy |] Opcode.JB

let jbe ctx ins = jcc ctx ins 0x76uy [| 0x0Fuy; 0x86uy |] Opcode.JBE

let jg ctx ins = jcc ctx ins 0x7Fuy [| 0x0Fuy; 0x8Fuy |] Opcode.JG

let jl ctx ins = jcc ctx ins 0x7Cuy [| 0x0Fuy; 0x8Cuy |] Opcode.JL

let jle ctx ins = jcc ctx ins 0x7Euy [| 0x0Fuy; 0x8Euy |] Opcode.JLE

let jnb ctx ins = jcc ctx ins 0x73uy [| 0x0Fuy; 0x83uy |] Opcode.JNB

let jnl ctx ins = jcc ctx ins 0x7Duy [| 0x0Fuy; 0x8Duy |] Opcode.JNL

let jno ctx ins = jcc ctx ins 0x71uy [| 0x0Fuy; 0x81uy |] Opcode.JNO

let jnp ctx ins = jcc ctx ins 0x7Buy [| 0x0Fuy; 0x8Buy |] Opcode.JNP

let jns ctx ins = jcc ctx ins 0x79uy [| 0x0Fuy; 0x89uy |] Opcode.JNS

let jnz ctx ins = jcc ctx ins 0x75uy [| 0x0Fuy; 0x85uy |] Opcode.JNZ

let jo ctx ins = jcc ctx ins 0x70uy [| 0x0Fuy; 0x80uy |] Opcode.JO

let jp ctx ins = jcc ctx ins 0x7auy [| 0x0Fuy; 0x8Auy |] Opcode.JP

let js ctx ins = jcc ctx ins 0x78uy [| 0x0Fuy; 0x88uy |] Opcode.JS

let jz ctx ins = jcc ctx ins 0x74uy [| 0x0Fuy; 0x84uy |] Opcode.JZ

let jmp (ctx: EncContext) ins =
  match ins.Operands with
  | OneOperand(Label _) ->
    encLbl ins
  | OneOperand(OprDirAddr(Relative rel)) when isInt8 rel ->
    encD ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xEBuy |] rel 8<rt>
  | OneOperand(OprDirAddr(Relative rel)) when isInt32 rel ->
    encD ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xE9uy |] rel 32<rt>
  | OneOperand(OprReg r) when isReg32 ctx r ->
    no64Arch ctx.WordSize (* N.S. *)
    encR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xFFuy |] r 0b100uy
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    no64Arch ctx.WordSize (* N.S. *)
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xFFuy |] b s d 0b100uy
  | OneOperand(OprReg r) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xFFuy |] r 0b100uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    no32Arch ctx.WordSize
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xFFuy |] b s d 0b100uy
  | o -> printfn "%A" o; raise NotEncodableException

let lahf (ctx: EncContext) = function
  | NoOperand -> no64Arch ctx.WordSize; [| Normal 0x9Fuy |]
  | _ -> raise NotEncodableException

let lea (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r, Label _) ->
    encRL ctx ins r [||] [| 0x8Duy |]
  | TwoOperands(OprReg r, OprMem(b, s, d, 16<rt>)) when isReg16 ctx r ->
    encRM ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x8Duy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg32 ctx r ->
    encRM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x8Duy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encRM ins ctx
      ctx.PrefNormal ctx.RexW [| 0x8Duy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let leave (ctx: EncContext) = function
  | NoOperand -> no64Arch ctx.WordSize; [| Normal 0xC9uy |]
  | _ -> raise NotEncodableException

let mov (ctx: EncContext) ins =
  match ins.Operands with
  (* Reg - Sreg *)
  | TwoOperands(OprReg r1, OprReg r2) when isReg16 ctx r1 && isSegReg r2 ->
    encRR ins ctx
      ctx.Pref66 ctx.RexMR [| 0x8Cuy |] r2 r1
  | TwoOperands(OprReg r1, OprReg r2) when isReg64 ctx r1 && isSegReg r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexWAndMR [| 0x8Cuy |] r2 r1
  (* Mem - Sreg *)
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprReg r) when isSegReg r ->
    encMR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x8Cuy |] b s d r
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprReg r) when isSegReg r ->
    encMR ins ctx
      ctx.PrefNormal ctx.RexWAndMR [| 0x8Cuy |] b s d r
  (* Mem - Reg *)
  | TwoOperands(Label _, OprReg r) ->
    encRL ctx ins r [| 0x88uy |] [| 0x89uy |]
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprReg r) when isReg8 ctx r ->
    encMR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x88uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprReg r) when isReg16 ctx r ->
    encMR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x89uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprReg r) when isReg32 ctx r ->
    encMR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x89uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprReg r) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encMR ins ctx
      ctx.PrefNormal ctx.RexW [| 0x89uy |] b s d r
  (* Reg - Reg *)
  | TwoOperands(OprReg r1, OprReg r2) when isReg8 ctx r1 && isReg8 ctx r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x8Auy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isReg16 ctx r1 && isReg16 ctx r2 ->
    encRR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x8Buy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isReg32 ctx r1 && isReg32 ctx r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x8Buy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isReg64 ctx r1 && isReg64 ctx r2 ->
    no32Arch ctx.WordSize
    encRR ins ctx
      ctx.PrefNormal ctx.RexW [| 0x8Buy |] r1 r2
  (* Reg - Mem *)
  | TwoOperands(OprReg r, Label _) ->
    encRL ctx ins r [| 0x8Auy |] [| 0x8Buy |]
  | TwoOperands(OprReg r, OprMem(b, s, d, 8<rt>)) when isReg8 ctx r ->
    encRM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x8Auy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 16<rt>)) when isReg16 ctx r ->
    encRM ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x8Buy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg32 ctx r ->
    encRM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x8Buy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encRM ins ctx
      ctx.PrefNormal ctx.RexW [| 0x8Buy |] r b s d
  (* Reg - Imm (Opcode reg field) *)
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg8 ctx r ->
    encOI ins ctx
      ctx.PrefNormal ctx.RexNormal 0xB0uy r imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg16 ctx r ->
    encOI ins ctx
      ctx.Pref66 ctx.RexNormal 0xB8uy r imm 16<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg32 ctx r ->
    encOI ins ctx
      ctx.PrefNormal ctx.RexNormal 0xB8uy r imm 32<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg64 ctx r && isInt32 imm ->
    no32Arch ctx.WordSize
    encRI ins ctx
      ctx.PrefNormal ctx.RexW [| 0xC7uy |] r 0b000uy imm 32<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encOI ins ctx
      ctx.PrefNormal ctx.RexW 0xB8uy r imm 64<rt>
  (* Mem - Imm *)
  | TwoOperands(Label _, OprImm(imm, _)) ->
    encLI ctx ins 0b000uy imm 32<rt> [| 0xC6uy |] [| 0xC7uy |]
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xC6uy |] b s d 0b000uy imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0xC7uy |] b s d 0b000uy imm 16<rt>
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xC7uy |] b s d 0b000uy imm 32<rt>
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprImm(imm, _)) ->
    no32Arch ctx.WordSize;
    encMI ins ctx
      ctx.PrefNormal ctx.RexW [| 0xC7uy |] b s d 0b000uy imm 32<rt>
  | o -> printfn "%A" o; raise NotEncodableException

let movaps (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0x28uy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 128<rt>)) when isXMMReg r ->
    encRM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0x28uy |] r b s d
  | TwoOperands(OprMem(b, s, d, 128<rt>), OprReg r) when isXMMReg r ->
    encMR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0x29uy |] b s d r
  | o -> printfn "%A" o; raise NotEncodableException

let movd (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isMMXReg r1 && isReg32 ctx r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0x6Euy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isMMXReg r ->
    encRM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0x6Euy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2) when isReg32 ctx r1 && isMMXReg r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexMR [| 0x0Fuy; 0x7Euy |] r2 r1
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprReg r) when isMMXReg r ->
    encMR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0x7Euy |] b s d r
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isReg32 ctx r2 ->
    encRR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0x6Euy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isXMMReg r ->
    encRM ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0x6Euy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2) when isReg32 ctx r1 && isXMMReg r2 ->
    encRR ins ctx
      ctx.Pref66 ctx.RexMR [| 0x0Fuy; 0x7Euy |] r2 r1
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprReg r) when isXMMReg r ->
    encMR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0x7Euy |] b s d r
  | o -> printfn "%A" o; raise NotEncodableException

let movdqa (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0x6Fuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 128<rt>)) when isXMMReg r ->
    encRM ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0x6Fuy |] r b s d
  | TwoOperands(OprMem(b, s, d, 128<rt>), OprReg r) when isXMMReg r ->
    encMR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0x7Fuy |] b s d r
  | o -> printfn "%A" o; raise NotEncodableException

let movdqu (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctx
      ctx.PrefF3 ctx.RexNormal [| 0x0Fuy; 0x6Fuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 128<rt>)) when isXMMReg r ->
    encRM ins ctx
      ctx.PrefF3 ctx.RexNormal [| 0x0Fuy; 0x6Fuy |] r b s d
  | TwoOperands(OprMem(b, s, d, 128<rt>), OprReg r) when isXMMReg r ->
    encMR ins ctx
      ctx.PrefF3 ctx.RexNormal [| 0x0Fuy; 0x7Fuy |] b s d r
  | o -> printfn "%A" o; raise NotEncodableException

let movsd (ctx: EncContext) ins =
  match ins.Operands with
  | NoOperand -> [| Normal 0xA5uy |]
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctx
      ctx.PrefF2 ctx.RexNormal [| 0x0Fuy; 0x10uy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isXMMReg r ->
    encRM ins ctx
      ctx.PrefF2 ctx.RexNormal [| 0x0Fuy; 0x10uy |] r b s d
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprReg r) when isXMMReg r ->
    encMR ins ctx
      ctx.PrefF2 ctx.RexNormal [| 0x0Fuy; 0x11uy |] b s d r
  | o -> printfn "%A" o; raise NotEncodableException

let movss (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctx
      ctx.PrefF3 ctx.RexNormal [| 0x0Fuy; 0x10uy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isXMMReg r ->
    encRM ins ctx
      ctx.PrefF3 ctx.RexNormal [| 0x0Fuy; 0x10uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let movsx (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isReg16 ctx r1 && isReg8 ctx r2 ->
    encRR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0xBEuy |] r1 r2
  | TwoOperands(OprReg r, Label _) ->
    encRL ctx ins r [||] [| 0x0Fuy; 0xBEuy |]
  | TwoOperands(OprReg r, OprMem(b, s, d, 8<rt>)) when isReg16 ctx r ->
    encRM ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0xBEuy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2) when isReg32 ctx r1 && isReg8 ctx r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0xBEuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 8<rt>)) when isReg32 ctx r ->
    encRM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0xBEuy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2) when isReg64 ctx r1 && isReg8 ctx r2 ->
    no32Arch ctx.WordSize
    encRR ins ctx
      ctx.PrefNormal ctx.RexW [| 0x0Fuy; 0xBEuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 8<rt>)) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encRM ins ctx
      ctx.PrefNormal ctx.RexW [| 0x0Fuy; 0xBEuy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2) when isReg32 ctx r1 && isReg16 ctx r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0xBFuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 16<rt>)) when isReg32 ctx r ->
    encRM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0xBFuy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2) when isReg64 ctx r1 && isReg16 ctx r2 ->
    no32Arch ctx.WordSize
    encRR ins ctx
      ctx.PrefNormal ctx.RexW [| 0x0Fuy; 0xBFuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 16<rt>)) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encRM ins ctx
      ctx.PrefNormal ctx.RexW [| 0x0Fuy; 0xBFuy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let movsxd (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isReg64 ctx r1 && isReg32 ctx r2 ->
    no32Arch ctx.WordSize
    encRR ins ctx
      ctx.PrefNormal ctx.RexW [| 0x63uy |] r1 r2
  | TwoOperands(OprReg r, Label _) ->
    encRL ctx ins r [||] [| 0x63uy |]
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encRM ins ctx
      ctx.PrefNormal ctx.RexW [| 0x63uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let movups (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0x10uy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 128<rt>)) when isXMMReg r ->
    encRM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0x10uy |] r b s d
  | TwoOperands(OprMem(b, s, d, 128<rt>), OprReg r) when isXMMReg r ->
    encMR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0x11uy |] b s d r
  | o -> printfn "%A" o; raise NotEncodableException

let movzx (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isReg16 ctx r1 && isReg8 ctx r2 ->
    encRR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0xB6uy |] r1 r2
  | TwoOperands(OprReg r, Label _) ->
    encRL ctx ins r [||] [| 0x0Fuy; 0xB6uy |]
  | TwoOperands(OprReg r, OprMem(b, s, d, 8<rt>)) when isReg16 ctx r ->
    encRM ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0xB6uy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2) when isReg32 ctx r1 && isReg8 ctx r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0xB6uy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 8<rt>)) when isReg32 ctx r ->
    encRM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0xB6uy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2) when isReg64 ctx r1 && isReg8 ctx r2 ->
    no32Arch ctx.WordSize
    encRR ins ctx
      ctx.PrefNormal ctx.RexW [| 0x0Fuy; 0xB6uy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 8<rt>)) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encRM ins ctx
      ctx.PrefNormal ctx.RexW [| 0x0Fuy; 0xB6uy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2) when isReg32 ctx r1 && isReg16 ctx r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0xB7uy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 16<rt>)) when isReg32 ctx r ->
    encRM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0xB7uy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2) when isReg64 ctx r1 && isReg16 ctx r2 ->
    no32Arch ctx.WordSize
    encRR ins ctx
      ctx.PrefNormal ctx.RexW [| 0x0Fuy; 0xB7uy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 16<rt>)) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encRM ins ctx
      ctx.PrefNormal ctx.RexW [| 0x0Fuy; 0xB7uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let mul (ctx: EncContext) ins =
  match ins.Operands with
  | OneOperand(OprReg r) when isReg8 ctx r ->
    encR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xF6uy |] r 0b100uy
  | OneOperand(OprMem(b, s, d, 8<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xF6uy |] b s d 0b100uy
  | OneOperand(OprReg r) when isReg16 ctx r ->
    encR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0xF7uy |] r 0b100uy
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins ctx
      ctx.Pref66 ctx.RexNormal [| 0xF7uy |] b s d 0b100uy
  | OneOperand(OprReg r) when isReg32 ctx r ->
    encR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xF7uy |] r 0b100uy
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xF7uy |] b s d 0b100uy
  | OneOperand(OprReg r) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encR ins ctx
      ctx.PrefNormal ctx.RexW [| 0xF7uy |] r 0b100uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    no32Arch ctx.WordSize
    encM ins ctx
      ctx.PrefNormal ctx.RexW [| 0xF7uy |] b s d 0b100uy
  | o -> printfn "%A" o; raise NotEncodableException

let mulsd (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctx
      ctx.PrefF2 ctx.RexNormal [| 0x0Fuy; 0x59uy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isXMMReg r ->
    encRM ins ctx
      ctx.PrefF2 ctx.RexNormal [| 0x0Fuy; 0x59uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let mulss (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctx
      ctx.PrefF3 ctx.RexNormal [| 0x0Fuy; 0x59uy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isXMMReg r ->
    encRM ins ctx
      ctx.PrefF3 ctx.RexNormal [| 0x0Fuy; 0x59uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let neg (ctx: EncContext) ins =
  match ins.Operands with
  | OneOperand(OprReg r) when isReg8 ctx r ->
    encR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xF6uy |] r 0b011uy
  | OneOperand(OprMem(b, s, d, 8<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xF6uy |] b s d 0b011uy
  | OneOperand(OprReg r) when isReg16 ctx r ->
    encR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0xF7uy |] r 0b011uy
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins ctx
      ctx.Pref66 ctx.RexNormal [| 0xF7uy |] b s d 0b011uy
  | OneOperand(OprReg r) when isReg32 ctx r ->
    encR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xF7uy |] r 0b011uy
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xF7uy |] b s d 0b011uy
  | OneOperand(OprReg r) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encR ins ctx
      ctx.PrefNormal ctx.RexW [| 0xF7uy |] r 0b011uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    no32Arch ctx.WordSize
    encM ins ctx
      ctx.PrefNormal ctx.RexW [| 0xF7uy |] b s d 0b011uy
  | o -> printfn "%A" o; raise NotEncodableException

let nop (ctx: EncContext) ins =
  match ins.Operands with
  | NoOperand -> [| Normal 0x90uy |]
  | OneOperand(OprReg r) when isReg16 ctx r ->
    encR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0x1Fuy |] r 0b000uy
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0x1Fuy |] b s d 0b000uy
  | OneOperand(OprReg r) when isReg32 ctx r ->
    encR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0x1Fuy |] r 0b000uy
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0x1Fuy |] b s d 0b000uy
  | o -> printfn "%A" o; raise NotEncodableException

let not (ctx: EncContext) ins =
  match ins.Operands with
  | OneOperand(OprReg r) when isReg8 ctx r ->
    encR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xF6uy |] r 0b010uy
  | OneOperand(OprMem(b, s, d, 8<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xF6uy |] b s d 0b010uy
  | OneOperand(OprReg r) when isReg16 ctx r ->
    encR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0xF7uy |] r 0b010uy
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins ctx
      ctx.Pref66 ctx.RexNormal [| 0xF7uy |] b s d 0b010uy
  | OneOperand(OprReg r) when isReg32 ctx r ->
    encR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xF7uy |] r 0b010uy
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xF7uy |] b s d 0b010uy
  | OneOperand(OprReg r) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encR ins ctx
      ctx.PrefNormal ctx.RexW [| 0xF7uy |] r 0b010uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    no32Arch ctx.WordSize
    encM ins ctx
      ctx.PrefNormal ctx.RexW [| 0xF7uy |] b s d 0b010uy
  | o -> printfn "%A" o; raise NotEncodableException

let logOr (ctx: EncContext) ins =
  match ins.Operands with
  (* Reg (fixed) - Imm *)
  | TwoOperands(OprReg Register.AL, OprImm(imm, _)) ->
    encImm ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Cuy |] imm 8<rt>
  | TwoOperands(OprReg Register.AX, OprImm(imm, _)) ->
    encImm ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Duy |] imm 16<rt>
  | TwoOperands(OprReg Register.EAX, OprImm(imm, _)) ->
    encImm ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Duy |] imm 32<rt>
  | TwoOperands(OprReg Register.RAX, OprImm(imm, _)) ->
    no32Arch ctx.WordSize
    encImm ins ctx
      ctx.PrefNormal ctx.RexW [| 0x0Duy |] imm 32<rt>
  (* Reg - Imm (Priority 0) *)
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg16 ctx r && isInt8 imm ->
    encRI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x83uy |] r 0b001uy imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg32 ctx r && isInt8 imm ->
    encRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x83uy |] r 0b001uy imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg64 ctx r && isInt8 imm ->
    no32Arch ctx.WordSize
    encRI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x83uy |] r 0b001uy imm 8<rt>
  (* Mem - Imm (Priority 0) *)
  | TwoOperands(Label _, OprImm(imm, _)) when isInt8 imm ->
    encLI ctx ins 0b001uy imm 8<rt> [||] [| 0x83uy |]
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprImm(imm, _)) when isInt8 imm ->
    encMI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x83uy |] b s d 0b001uy imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprImm(imm, _)) when isInt8 imm ->
    encMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x83uy |] b s d 0b001uy imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprImm(imm, _)) when isInt8 imm ->
    no32Arch ctx.WordSize
    encMI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x83uy |] b s d 0b001uy imm 8<rt>
  (* Reg - Imm (Priority 1) *)
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg8 ctx r ->
    encRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x80uy |] r 0b001uy imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg16 ctx r ->
    encRI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x81uy |] r 0b001uy imm 16<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg32 ctx r ->
    encRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x81uy |] r 0b001uy imm 32<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encRI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x81uy |] r 0b001uy imm 32<rt>
  (* Mem - Imm (Priority 1) *)
  | TwoOperands(Label _, OprImm(imm, _)) ->
    encLI ctx ins 0b001uy imm 32<rt> [| 0x80uy |] [| 0x81uy |]
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x80uy |] b s d 0b001uy imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x81uy |] b s d 0b001uy imm 16<rt>
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x81uy |] b s d 0b001uy imm 32<rt>
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprImm(imm, _)) ->
    no32Arch ctx.WordSize;
    encMI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x81uy |] b s d 0b001uy imm 32<rt>
  (* Mem - Reg *)
  | TwoOperands(Label _, OprReg r) ->
    encRL ctx ins r [| 0x08uy |] [| 0x09uy |]
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprReg r) when isReg8 ctx r ->
    encMR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x08uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprReg r) when isReg16 ctx r ->
    encMR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x09uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprReg r) when isReg32 ctx r ->
    encMR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x09uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprReg r) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encMR ins ctx
      ctx.PrefNormal ctx.RexW [| 0x09uy |] b s d r
  (* Reg - Reg *)
  | TwoOperands(OprReg r1, OprReg r2) when isReg8 ctx r1 && isReg8 ctx r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Auy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isReg16 ctx r1 && isReg16 ctx r2 ->
    encRR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Buy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isReg32 ctx r1 && isReg32 ctx r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Buy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isReg64 ctx r1 && isReg64 ctx r2 ->
    no32Arch ctx.WordSize
    encRR ins ctx
      ctx.PrefNormal ctx.RexW [| 0x0Buy |] r1 r2
  (* Reg - Mem *)
  | TwoOperands(OprReg r, Label _) ->
    encRL ctx ins r [| 0x0Auy |] [| 0x0Buy |]
  | TwoOperands(OprReg r, OprMem(b, s, d, 8<rt>)) when isReg8 ctx r ->
    encRM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Auy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 16<rt>)) when isReg16 ctx r ->
    encRM ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Buy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg32 ctx r ->
    encRM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Buy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encRM ins ctx
      ctx.PrefNormal ctx.RexW [| 0x0Buy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let orpd (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0x56uy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isXMMReg r ->
    encRM ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0x56uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let paddd (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0xFEuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 128<rt>)) when isXMMReg r ->
    encRM ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0xFEuy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let palignr (ctx: EncContext) ins =
  match ins.Operands with
  (* Reg - Reg - Imm8 *)
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _))
    when isMMXReg r1 && isMMXReg r2 ->
    encRRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0x3Auy; 0x0Fuy |]
      r1 r2 imm 8<rt>
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _))
    when isXMMReg r1 && isXMMReg r2 ->
    encRRI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0x3Auy; 0x0Fuy |] r1 r2 imm 8<rt>
  (* Reg - Mem - Imm8 *)
  | ThreeOperands(OprReg r, OprMem(b, s, d, 64<rt>), OprImm(imm, _))
    when isMMXReg r ->
    encRMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0x3Auy; 0x0Fuy |]
      r b s d imm 8<rt>
  | ThreeOperands(OprReg r, OprMem(b, s, d, 128<rt>), OprImm(imm, _))
    when isXMMReg r ->
    encRMI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0x3Auy; 0x0Fuy |] r b s d imm 8<rt>
  | o -> printfn "%A" o; raise NotEncodableException

let pop (ctx: EncContext) ins =
  match ins.Operands with
  | OneOperand(OprReg Register.DS) ->
    no64Arch ctx.WordSize; [| Normal 0x1Fuy |]
  | OneOperand(OprReg Register.ES) ->
    no64Arch ctx.WordSize; [| Normal 0x07uy |]
  | OneOperand(OprReg Register.SS) ->
    no64Arch ctx.WordSize; [| Normal 0x17uy |]
  | OneOperand(OprReg Register.FS) -> [| Normal 0x0Fuy; Normal 0xA1uy |]
  | OneOperand(OprReg Register.GS) -> [| Normal 0x0Fuy; Normal 0xA9uy |]
  | OneOperand(OprReg r) when isReg16 ctx r ->
    if isClassicGPReg r then encClassicR true 0x58uy (regTo3Bit r)
    else encR ins ctx ctx.Pref66 ctx.RexNormal [| 0x8Fuy |] r 0uy
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins ctx ctx.Pref66 ctx.RexNormal [| 0x8Fuy |] b s d 0uy
  | OneOperand(OprReg r) when isReg32 ctx r ->
    no64Arch ctx.WordSize
    if isClassicGPReg r then encClassicR false 0x58uy (regTo3Bit r)
    else encR ins ctx ctx.PrefNormal ctx.RexNormal [| 0x8Fuy |] r 0uy
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    no64Arch ctx.WordSize
    encM ins ctx ctx.PrefNormal ctx.RexNormal [| 0x8Fuy |] b s d 0uy
  | OneOperand(OprReg r) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    if isClassicGPReg r then encClassicR false 0x58uy (regTo3Bit r)
    else encR ins ctx ctx.PrefNormal ctx.RexW [| 0x8Fuy |] r 0uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    no32Arch ctx.WordSize
    encM ins ctx ctx.PrefNormal ctx.RexW [| 0x8Fuy |] b s d 0uy
  | o -> printfn "%A" o; raise NotEncodableException

let pshufd (ctx: EncContext) ins =
  match ins.Operands with
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _))
    when isXMMReg r1 && isXMMReg r2 ->
    encRRI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0x70uy |] r1 r2 imm 8<rt>
  | ThreeOperands(OprReg r, OprMem(b, s, d, 128<rt>), OprImm(imm, _))
    when isXMMReg r ->
    encRMI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0x70uy |] r b s d imm 8<rt>
  | o -> printfn "%A" o; raise NotEncodableException

let punpckldq (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isMMXReg r1 && isMMXReg r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0x62uy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isMMXReg r ->
    encRM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0x62uy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0x62uy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 128<rt>)) when isXMMReg r ->
    encRM ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0x62uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let push (ctx: EncContext) ins =
  match ins.Operands with
  | OneOperand(OprReg Register.CS) ->
    no64Arch ctx.WordSize; [| Normal 0x0Euy |]
  | OneOperand(OprReg Register.SS) ->
    no64Arch ctx.WordSize; [| Normal 0x16uy |]
  | OneOperand(OprReg Register.DS) ->
    no64Arch ctx.WordSize; [| Normal 0x1Euy |]
  | OneOperand(OprReg Register.ES) ->
    no64Arch ctx.WordSize; [| Normal 0x06uy |]
  | OneOperand(OprReg Register.FS) -> [| Normal 0x0Fuy; Normal 0xA0uy |]
  | OneOperand(OprReg Register.GS) -> [| Normal 0x0Fuy; Normal 0xA8uy |]
  | OneOperand(OprReg r) when isReg16 ctx r ->
    if isClassicGPReg r then encClassicR true 0x50uy (regTo3Bit r)
    else encR ins ctx ctx.Pref66 ctx.RexNormal [| 0xFFuy |] r 0b110uy
  | OneOperand(OprMem(b, s, d, 16<rt>)) ->
    encM ins ctx ctx.Pref66 ctx.RexNormal [| 0xFFuy |] b s d 0b110uy
  | OneOperand(OprReg r) when isReg32 ctx r ->
    no64Arch ctx.WordSize
    if isClassicGPReg r then encClassicR false 0x50uy (regTo3Bit r)
    else
      encR ins ctx ctx.PrefNormal ctx.RexNormal [| 0xFFuy |] r 0b110uy
  | OneOperand(OprMem(b, s, d, 32<rt>)) ->
    no64Arch ctx.WordSize
    encM ins ctx ctx.PrefNormal ctx.RexNormal [| 0xFFuy |] b s d 0b110uy
  | OneOperand(OprReg r) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    if isClassicGPReg r then encClassicR false 0x50uy (regTo3Bit r)
    else
      encR ins ctx ctx.PrefNormal ctx.RexNormal [| 0xFFuy |] r 0b110uy
  | OneOperand(OprMem(b, s, d, 64<rt>)) ->
    no32Arch ctx.WordSize
    encM ins ctx ctx.PrefNormal ctx.RexNormal [| 0xFFuy |] b s d 0b110uy
  | OneOperand(OprImm(imm, _)) when isInt8 imm ->
    encImm ins ctx ctx.PrefNormal ctx.RexNormal [| 0x6Auy |] imm 8<rt>
  | OneOperand(OprImm(imm, _)) when isInt16 imm ->
    encImm ins ctx ctx.Pref66 ctx.RexNormal [| 0x68uy |] imm 16<rt>
  | OneOperand(OprImm(imm, _)) when isUInt32 imm ->
    encImm ins ctx ctx.PrefNormal ctx.RexNormal [| 0x68uy |] imm 32<rt>
  | o -> printfn "%A" o; raise NotEncodableException

let pxor (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isMMXReg r1 && isMMXReg r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0xEFuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isMMXReg r ->
    encRM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0xEFuy |] r b s d
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0xEFuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 128<rt>)) when isXMMReg r ->
    encRM ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0xEFuy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let rotateOrShift (ctx: EncContext) ins regConstr =
  match ins.Operands with
  | TwoOperands(OprReg r, OprImm(1L as imm, _)) when isReg8 ctx r ->
    encRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xD0uy |] r regConstr imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprImm(1L as imm, _)) ->
    encMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xD0uy |] b s d regConstr imm 8<rt>
  | TwoOperands(OprReg r, OprReg Register.CL) when isReg8 ctx r ->
    encRC ins ctx
      ctx.PrefNormal ctx.RexMR [| 0xD2uy |] r regConstr
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprReg Register.CL) ->
    encMC ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xD2uy |] b s d regConstr
  | TwoOperands(OprReg r, OprImm(imm, _))  when isReg8 ctx r ->
    encRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xC0uy |] r regConstr imm 8<rt>
  | TwoOperands(Label _, OprImm(imm, _)) ->
    encLI ctx ins regConstr imm 8<rt> [| 0xC0uy |] [| 0xC1uy |]
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xC0uy |] b s d regConstr imm 8<rt>
  | TwoOperands(OprReg r, OprImm(1L as imm, _)) when isReg16 ctx r ->
    encRI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0xD1uy |] r regConstr imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprImm(1L as imm, _)) ->
    encMI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0xD1uy |] b s d regConstr imm 8<rt>
  | TwoOperands(OprReg r, OprReg Register.CL) when isReg16 ctx r ->
    encRC ins ctx
      ctx.Pref66 ctx.RexMR [| 0xD3uy |] r regConstr
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprReg Register.CL) ->
    encMC ins ctx
      ctx.Pref66 ctx.RexNormal [| 0xD3uy |] b s d regConstr
  | TwoOperands(OprReg r, OprImm(imm, _))  when isReg16 ctx r ->
    encRI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0xC1uy |] r regConstr imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0xC1uy |] b s d regConstr imm 8<rt>
  | TwoOperands(OprReg r, OprImm(1L as imm, _)) when isReg32 ctx r ->
    encRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xD1uy |] r regConstr imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprImm(1L as imm, _)) ->
    encMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xD1uy |] b s d regConstr imm 8<rt>
  | TwoOperands(OprReg r, OprReg Register.CL) when isReg32 ctx r ->
    encRC ins ctx
      ctx.PrefNormal ctx.RexMR [| 0xD3uy |] r regConstr
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprReg Register.CL) ->
    encMC ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xD3uy |] b s d regConstr
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg32 ctx r ->
    encRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xC1uy |] r regConstr imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xC1uy |] b s d regConstr imm 8<rt>
  | TwoOperands(OprReg r, OprImm(1L as imm, _)) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encRI ins ctx
      ctx.PrefNormal ctx.RexW [| 0xD1uy |] r regConstr imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprImm(1L as imm, _)) ->
    no32Arch ctx.WordSize
    encMI ins ctx
      ctx.PrefNormal ctx.RexW [| 0xD1uy |] b s d regConstr imm 8<rt>
  | TwoOperands(OprReg r, OprReg Register.CL) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encRC ins ctx
      ctx.PrefNormal ctx.RexWAndMR [| 0xD3uy |] r regConstr
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprReg Register.CL) ->
    no32Arch ctx.WordSize
    encMC ins ctx
      ctx.PrefNormal ctx.RexW [| 0xD3uy |] b s d regConstr
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encRI ins ctx
      ctx.PrefNormal ctx.RexW [| 0xC1uy |] r regConstr imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprImm(imm, _)) ->
    no32Arch ctx.WordSize
    encMI ins ctx
      ctx.PrefNormal ctx.RexW [| 0xC1uy |] b s d regConstr imm 8<rt>
  | o -> printfn "%A" o; raise NotEncodableException

let rcl ctx ins = rotateOrShift ctx ins 0b010uy

let rcr ctx ins = rotateOrShift ctx ins 0b011uy

let rol ctx ins = rotateOrShift ctx ins 0b000uy

let ror ctx ins = rotateOrShift ctx ins 0b001uy

let ret (ctx: EncContext) ins =
  match ins.Operands with
  | NoOperand -> [| Normal 0xC3uy |]
  | OneOperand(OprDirAddr(Relative rel)) ->
    encD ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xC2uy |] rel 16<rt>
  | OneOperand(OprImm(imm, _)) ->
    encImm ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xC2uy |] imm 16<rt>
  | o -> printfn "%A" o; raise NotEncodableException

let sar ctx ins = rotateOrShift ctx ins 0b111uy

let shl ctx ins = rotateOrShift ctx ins 0b100uy

let shr ctx ins = rotateOrShift ctx ins 0b101uy

let sahf (ctx: EncContext) = function
  | NoOperand -> no64Arch ctx.WordSize; [| Normal 0x9Euy |]
  | _ -> raise NotEncodableException

let sbb (ctx: EncContext) ins =
  match ins.Operands with
  (* Reg (fixed) - Imm (Priority 1) *)
  | TwoOperands(OprReg Register.AL, OprImm(imm, _)) ->
    encImm ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x1Cuy |] imm 8<rt>
  | TwoOperands(OprReg Register.AX, OprImm(imm, _)) ->
    encImm ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x1Duy |] imm 16<rt>
  | TwoOperands(OprReg Register.EAX, OprImm(imm, _)) ->
    encImm ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x1Duy |] imm 32<rt>
  | TwoOperands(OprReg Register.RAX, OprImm(imm, _)) ->
    no32Arch ctx.WordSize
    encImm ins ctx
      ctx.PrefNormal ctx.RexW [| 0x1Duy |] imm 32<rt>
  (* Reg - Imm (Priority 0) *)
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg16 ctx r && isInt8 imm ->
    encRI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x83uy |] r 0b011uy imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg32 ctx r && isInt8 imm ->
    encRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x83uy |] r 0b011uy imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg64 ctx r && isInt8 imm ->
    no32Arch ctx.WordSize
    encRI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x83uy |] r 0b011uy imm 8<rt>
  (* Mem - Imm (Priority 0) *)
  | TwoOperands(Label _, OprImm(imm, _)) when isInt8 imm ->
    encLI ctx ins 0b011uy imm 8<rt> [||] [| 0x83uy |]
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprImm(imm, _)) when isInt8 imm ->
    encMI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x83uy |] b s d 0b011uy imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprImm(imm, _)) when isInt8 imm ->
    encMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x83uy |] b s d 0b011uy imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprImm(imm, _)) when isInt8 imm ->
    no32Arch ctx.WordSize
    encMI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x83uy |] b s d 0b011uy imm 8<rt>
  (* Reg - Imm (Priority 1) *)
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg8 ctx r ->
    encRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x80uy |] r 0b011uy imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg16 ctx r ->
    encRI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x81uy |] r 0b011uy imm 16<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg32 ctx r ->
    encRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x81uy |] r 0b011uy imm 32<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encRI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x81uy |] r 0b011uy imm 32<rt>
  (* Mem - Imm (Priority 1) *)
  | TwoOperands(Label _, OprImm(imm, _)) ->
    encLI ctx ins 0b011uy imm 32<rt> [| 0x80uy |] [| 0x81uy |]
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x80uy |] b s d 0b011uy imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x81uy |] b s d 0b011uy imm 16<rt>
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x81uy |] b s d 0b011uy imm 32<rt>
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprImm(imm, _)) ->
    no32Arch ctx.WordSize;
    encMI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x81uy |] b s d 0b011uy imm 32<rt>
  (* Mem - Reg *)
  | TwoOperands(Label _, OprReg r) ->
    encRL ctx ins r [| 0x18uy |] [| 0x19uy |]
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprReg r) when isReg8 ctx r ->
    encMR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x18uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprReg r) when isReg16 ctx r ->
    encMR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x19uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprReg r) when isReg32 ctx r ->
    encMR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x19uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprReg r) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encMR ins ctx
      ctx.PrefNormal ctx.RexW [| 0x19uy |] b s d r
  (* Reg - Reg *)
  | TwoOperands(OprReg r1, OprReg r2) when isReg8 ctx r1 && isReg8 ctx r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x1Auy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isReg16 ctx r1 && isReg16 ctx r2 ->
    encRR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x1Buy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isReg32 ctx r1 && isReg32 ctx r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x1Buy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isReg64 ctx r1 && isReg64 ctx r2 ->
    no32Arch ctx.WordSize
    encRR ins ctx
      ctx.PrefNormal ctx.RexW [| 0x1Buy |] r1 r2
  (* Reg - Mem *)
  | TwoOperands(OprReg r, Label _) ->
    encRL ctx ins r [| 0x1Auy |] [| 0x1Buy |]
  | TwoOperands(OprReg r, OprMem(b, s, d, 8<rt>)) when isReg8 ctx r ->
    encRM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x1Auy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 16<rt>)) when isReg16 ctx r ->
    encRM ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x1Buy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg32 ctx r ->
    encRM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x1Buy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encRM ins ctx
      ctx.PrefNormal ctx.RexW [| 0x1Buy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let scasb (ctx: EncContext) ins =
  match ins.Operands with
  | NoOperand ->
    encNP ins ctx
      ctx.PrefREP ctx.RexNormal [| 0xAEuy |]
  | o -> printfn "%A" o; raise NotEncodableException

let scasd (ctx: EncContext) ins =
  match ins.Operands with
  | NoOperand ->
    encNP ins ctx
      ctx.PrefREP ctx.RexNormal [| 0xAFuy |]
  | o -> printfn "%A" o; raise NotEncodableException

let scasq (ctx: EncContext) ins =
  match ins.Operands with
  | NoOperand ->
    no32Arch ctx.WordSize
    encNP ins ctx
      ctx.PrefREP ctx.RexW [| 0xAFuy |]
  | o -> printfn "%A" o; raise NotEncodableException

let scasw (ctx: EncContext) ins =
  match ins.Operands with
  | NoOperand ->
    encNP ins ctx
      ctx.PrefREP66 ctx.RexNormal [| 0xAFuy |]
  | o -> printfn "%A" o; raise NotEncodableException

let setcc (ctx: EncContext) ins op =
  match ins.Operands with
  | OneOperand(OprReg r) when isReg8 ctx r ->
    encR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; op |] r 0b000uy
  | OneOperand(OprMem(b, s, d, 8<rt>)) ->
    encM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; op |] b s d 0b000uy
  | o -> printfn "%A" o; raise NotEncodableException

let seta ctx ins = setcc ctx ins 0x97uy

let setb ctx ins = setcc ctx ins 0x92uy

let setbe ctx ins = setcc ctx ins 0x96uy

let setg ctx ins = setcc ctx ins 0x9Fuy

let setl ctx ins = setcc ctx ins 0x9Cuy

let setle ctx ins = setcc ctx ins 0x9Euy

let setnb ctx ins = setcc ctx ins 0x93uy

let setnl ctx ins = setcc ctx ins 0x9Duy

let setno ctx ins = setcc ctx ins 0x91uy

let setnp ctx ins = setcc ctx ins 0x9Buy

let setns ctx ins = setcc ctx ins 0x99uy

let setnz ctx ins = setcc ctx ins 0x95uy

let seto ctx ins = setcc ctx ins 0x90uy

let setp ctx ins = setcc ctx ins 0x9Auy

let sets ctx ins = setcc ctx ins 0x98uy

let setz ctx ins = setcc ctx ins 0x94uy

let shld (ctx: EncContext) ins =
  match ins.Operands with
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _))
    when isReg16 ctx r1 && isReg16 ctx r2 ->
    encRRI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0xA4uy |] r1 r2 imm 8<rt>
  | ThreeOperands(OprMem(b, s, d, 16<rt>), OprReg r, OprImm(imm, _))
    when isReg16 ctx r ->
    encMRI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0xA4uy |] b s d r imm 8<rt>
  | ThreeOperands(OprReg r1, OprReg r2, OprReg Register.CL)
    when isReg16 ctx r1 && isReg16 ctx r2 ->
    encRR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0xA5uy |] r1 r2
  | ThreeOperands(OprMem(b, s, d, 16<rt>), OprReg r, OprReg Register.CL)
    when isReg16 ctx r ->
    encMR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x0Fuy; 0xA5uy |] b s d r
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _))
    when isReg32 ctx r1 && isReg32 ctx r2 ->
    encRRI ins ctx
      ctx.PrefNormal ctx.RexMR [| 0x0Fuy; 0xA4uy |] r2 r1 imm 8<rt>
  | ThreeOperands(OprMem(b, s, d, 32<rt>), OprReg r, OprImm(imm, _))
    when isReg32 ctx r ->
    encMRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0xA4uy |] b s d r imm 8<rt>
  | ThreeOperands(OprReg r1, OprReg r2, OprReg Register.CL)
    when isReg32 ctx r1 && isReg32 ctx r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0xA5uy |] r1 r2
  | ThreeOperands(OprMem(b, s, d, 32<rt>), OprReg r, OprReg Register.CL)
    when isReg32 ctx r ->
    encMR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0xA5uy |] b s d r
  | ThreeOperands(OprReg r1, OprReg r2, OprImm(imm, _))
    when isReg64 ctx r1 && isReg64 ctx r2 ->
    no32Arch ctx.WordSize
    encRRI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x0Fuy; 0xA4uy |] r1 r2 imm 8<rt>
  | ThreeOperands(OprMem(b, s, d, 64<rt>), OprReg r, OprImm(imm, _))
    when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encMRI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x0Fuy; 0xA4uy |] b s d r imm 8<rt>
  | ThreeOperands(OprReg r1, OprReg r2, OprReg Register.CL)
    when isReg64 ctx r1 && isReg64 ctx r2 ->
    no32Arch ctx.WordSize
    encRR ins ctx
      ctx.PrefNormal ctx.RexW [| 0x0Fuy; 0xA5uy |] r1 r2
  | ThreeOperands(OprMem(b, s, d, 64<rt>), OprReg r, OprReg Register.CL)
    when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encMR ins ctx
      ctx.PrefNormal ctx.RexW [| 0x0Fuy; 0xA5uy |] b s d r
  | o -> printfn "%A" o; raise NotEncodableException

let stosb (ctx: EncContext) ins =
  match ins.Operands with
  | NoOperand ->
    encNP ins ctx
      ctx.PrefREP ctx.RexNormal [| 0xAAuy |]
  | o -> printfn "%A" o; raise NotEncodableException

let stosd (ctx: EncContext) ins =
  match ins.Operands with
  | NoOperand ->
    encNP ins ctx
      ctx.PrefREP ctx.RexNormal [| 0xABuy |]
  | o -> printfn "%A" o; raise NotEncodableException

let stosq (ctx: EncContext) ins =
  match ins.Operands with
  | NoOperand ->
    no32Arch ctx.WordSize
    encNP ins ctx
      ctx.PrefREP ctx.RexW [| 0xABuy |]
  | o -> printfn "%A" o; raise NotEncodableException

let stosw (ctx: EncContext) ins =
  match ins.Operands with
  | NoOperand ->
    encNP ins ctx
      ctx.PrefREP66 ctx.RexNormal [| 0xABuy |]
  | o -> printfn "%A" o; raise NotEncodableException

let sub (ctx: EncContext) ins =
  match ins.Operands with
  (* Reg (fixed) - Imm (Priority 1) *)
  | TwoOperands(OprReg Register.AL, OprImm(imm, _)) ->
    encImm ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x2Cuy |] imm 8<rt>
  | TwoOperands(OprReg Register.AX, OprImm(imm, _)) ->
    encImm ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x2Duy |] imm 16<rt>
  | TwoOperands(OprReg Register.EAX, OprImm(imm, _)) ->
    encImm ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x2Duy |] imm 32<rt>
  | TwoOperands(OprReg Register.RAX, OprImm(imm, _)) ->
    no32Arch ctx.WordSize
    encImm ins ctx
      ctx.PrefNormal ctx.RexW [| 0x2Duy |] imm 32<rt>
  (* Reg - Imm (Priority 0) *)
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg16 ctx r && isInt8 imm ->
    encRI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x83uy |] r 0b101uy imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg32 ctx r && isInt8 imm ->
    encRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x83uy |] r 0b101uy imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg64 ctx r && isInt8 imm ->
    no32Arch ctx.WordSize
    encRI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x83uy |] r 0b101uy imm 8<rt>
  (* Mem - Imm (Priority 0) *)
  | TwoOperands(Label _, OprImm(imm, _)) when isInt8 imm ->
    encLI ctx ins 0b101uy imm 8<rt> [||] [| 0x83uy |]
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprImm(imm, _)) when isInt8 imm ->
    encMI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x83uy |] b s d 0b101uy imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprImm(imm, _)) when isInt8 imm ->
    encMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x83uy |] b s d 0b101uy imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprImm(imm, _)) when isInt8 imm ->
    no32Arch ctx.WordSize
    encMI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x83uy |] b s d 0b101uy imm 8<rt>
  (* Reg - Imm (Priority 1) *)
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg8 ctx r ->
    encRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x80uy |] r 0b101uy imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg16 ctx r ->
    encRI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x81uy |] r 0b101uy imm 16<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg32 ctx r ->
    encRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x81uy |] r 0b101uy imm 32<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encRI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x81uy |] r 0b101uy imm 32<rt>
  (* Mem - Imm (Priority 1) *)
  | TwoOperands(Label _, OprImm(imm, _)) ->
     encLI ctx ins 0b101uy imm 32<rt> [| 0x80uy |] [| 0x81uy |]
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x80uy |] b s d 0b101uy imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x81uy |] b s d 0b101uy imm 16<rt>
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x81uy |] b s d 0b101uy imm 32<rt>
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprImm(imm, _)) ->
    no32Arch ctx.WordSize;
    encMI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x81uy |] b s d 0b011uy imm 32<rt>
  (* Mem - Reg *)
  | TwoOperands(Label _, OprReg r) ->
    encRL ctx ins r [| 0x28uy |] [| 0x29uy |]
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprReg r) when isReg8 ctx r ->
    encMR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x28uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprReg r) when isReg16 ctx r ->
    encMR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x29uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprReg r) when isReg32 ctx r ->
    encMR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x29uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprReg r) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encMR ins ctx
      ctx.PrefNormal ctx.RexW [| 0x29uy |] b s d r
  (* Reg - Reg *)
  | TwoOperands(OprReg r1, OprReg r2) when isReg8 ctx r1 && isReg8 ctx r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x2Auy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isReg16 ctx r1 && isReg16 ctx r2 ->
    encRR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x2Buy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isReg32 ctx r1 && isReg32 ctx r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x2Buy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isReg64 ctx r1 && isReg64 ctx r2 ->
    no32Arch ctx.WordSize
    encRR ins ctx
      ctx.PrefNormal ctx.RexW [| 0x2Buy |] r1 r2
  (* Reg - Mem *)
  | TwoOperands(OprReg r, Label _) ->
    encRL ctx ins r [| 0x2Auy |] [| 0x2Buy |]
  | TwoOperands(OprReg r, OprMem(b, s, d, 8<rt>)) when isReg8 ctx r ->
    encRM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x2Auy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 16<rt>)) when isReg16 ctx r ->
    encRM ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x2Buy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg32 ctx r ->
    encRM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x2Buy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encRM ins ctx
      ctx.PrefNormal ctx.RexW [| 0x2Buy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let subsd (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctx
      ctx.PrefF2 ctx.RexNormal [| 0x0Fuy; 0x5Cuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isXMMReg r ->
    encRM ins ctx
      ctx.PrefF2 ctx.RexNormal [| 0x0Fuy; 0x5Cuy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let subss (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctx
      ctx.PrefF3 ctx.RexNormal [| 0x0Fuy; 0x5Cuy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isXMMReg r ->
    encRM ins ctx
      ctx.PrefF3 ctx.RexNormal [| 0x0Fuy; 0x5Cuy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let test (ctx: EncContext) ins =
  match ins.Operands with
  (* Reg (fixed) - Imm *)
  | TwoOperands(OprReg Register.AL, OprImm(imm, _)) ->
    encImm ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xA8uy |] imm 8<rt>
  | TwoOperands(OprReg Register.AX, OprImm(imm, _)) ->
    encImm ins ctx
      ctx.Pref66 ctx.RexNormal [| 0xA9uy |] imm 16<rt>
  | TwoOperands(OprReg Register.EAX, OprImm(imm, _)) ->
    encImm ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xA9uy |] imm 32<rt>
  | TwoOperands(OprReg Register.RAX, OprImm(imm, _)) ->
    no32Arch ctx.WordSize
    encImm ins ctx
      ctx.PrefNormal ctx.RexW [| 0xA9uy |] imm 32<rt>
  (* Reg - Imm *)
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg8 ctx r ->
    encRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xF6uy |] r 0b000uy imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg16 ctx r ->
    encRI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0xF7uy |] r 0b000uy imm 16<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg32 ctx r ->
    encRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xF7uy |] r 0b000uy imm 32<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encRI ins ctx
      ctx.PrefNormal ctx.RexW [| 0xF7uy |] r 0b000uy imm 32<rt>
  (* Mem - Imm *)
  | TwoOperands(Label _, OprImm(imm, _)) ->
    encLI ctx ins 0b000uy imm 32<rt> [| 0xF6uy |] [| 0xF7uy |]
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xF6uy |] b s d 0b000uy imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0xF7uy |] b s d 0b000uy imm 16<rt>
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0xF7uy |] b s d 0b000uy imm 32<rt>
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprImm(imm, _)) ->
    no32Arch ctx.WordSize;
    encMI ins ctx
      ctx.PrefNormal ctx.RexW [| 0xF7uy |] b s d 0b000uy imm 32<rt>
  (* Reg - Reg *)
  | TwoOperands(OprReg r1, OprReg r2) when isReg8 ctx r1 && isReg8 ctx r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexMR [| 0x84uy |] r2 r1
  | TwoOperands(OprReg r1, OprReg r2) when isReg16 ctx r1 && isReg16 ctx r2 ->
    encRR ins ctx
      ctx.Pref66 ctx.RexMR [| 0x85uy |] r2 r1
  | TwoOperands(OprReg r1, OprReg r2) when isReg32 ctx r1 && isReg32 ctx r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexMR [| 0x85uy |] r2 r1
  | TwoOperands(OprReg r1, OprReg r2) when isReg64 ctx r1 && isReg64 ctx r2 ->
    no32Arch ctx.WordSize
    encRR ins ctx
      ctx.PrefNormal ctx.RexWAndMR [| 0x85uy |] r2 r1
  (* Mem - Reg *)
  | TwoOperands(OprReg r, Label _) ->
    encRL ctx ins r [| 0x84uy |] [| 0x85uy |]
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprReg r) when isReg8 ctx r ->
    encMR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x84uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprReg r) when isReg16 ctx r ->
    encMR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x85uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprReg r) when isReg32 ctx r ->
    encMR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x85uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprReg r) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encMR ins ctx
      ctx.PrefNormal ctx.RexW [| 0x85uy |] b s d r
  | o -> printfn "%A" o; raise NotEncodableException

let ucomiss (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0x2Euy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isXMMReg r ->
    encRM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0x2Euy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let vaddpd (ctx: EncContext) ins =
  match ins.Operands with
  | ThreeOperands(OprReg r1, OprReg r2, OprReg r3)
    when isXMMReg r1 && isXMMReg r2 && isXMMReg r3 ->
    encVexRRR ins ctx.WordSize (Some r2) ctx.VEX128n66n0F [| 0x58uy |] r1 r3
  | ThreeOperands(OprReg r1, OprReg r2, OprReg r3)
    when isYMMReg r1 && isYMMReg r2 && isYMMReg r3 ->
    encVexRRR ins ctx.WordSize (Some r2) ctx.VEX256n66n0F [| 0x58uy |] r1 r3
  | ThreeOperands(OprReg r1, OprReg r2, OprMem(b, s, d, 128<rt>))
    when isXMMReg r1 && isXMMReg r2 ->
    encVexRRM ins ctx.WordSize (Some r2) ctx.VEX128n66n0F [| 0x58uy |] r1 b s d
  | ThreeOperands(OprReg r1, OprReg r2, OprMem(b, s, d, 256<rt>))
    when isYMMReg r1 && isYMMReg r2 ->
    encVexRRM ins ctx.WordSize (Some r2) ctx.VEX256n66n0F [| 0x58uy |] r1 b s d
  | o -> printfn "%A" o; raise NotEncodableException

let vaddps (ctx: EncContext) ins =
  match ins.Operands with
  | ThreeOperands(OprReg r1, OprReg r2, OprReg r3)
    when isXMMReg r1 && isXMMReg r2 && isXMMReg r3 ->
    encVexRRR ins ctx.WordSize (Some r2) ctx.VEX128n0F [| 0x58uy |] r1 r3
  | ThreeOperands(OprReg r1, OprReg r2, OprReg r3)
    when isYMMReg r1 && isYMMReg r2 && isYMMReg r3 ->
    encVexRRR ins ctx.WordSize (Some r2) ctx.VEX256n0F [| 0x58uy |] r1 r3
  | ThreeOperands(OprReg r1, OprReg r2, OprMem(b, s, d, 128<rt>))
    when isXMMReg r1 && isXMMReg r2 ->
    encVexRRM ins ctx.WordSize (Some r2) ctx.VEX128n0F [| 0x58uy |] r1 b s d
  | ThreeOperands(OprReg r1, OprReg r2, OprMem(b, s, d, 256<rt>))
    when isYMMReg r1 && isYMMReg r2 ->
    encVexRRM ins ctx.WordSize (Some r2) ctx.VEX256n0F [| 0x58uy |] r1 b s d
  | o -> printfn "%A" o; raise NotEncodableException

let vaddsd (ctx: EncContext) ins =
  match ins.Operands with
  | ThreeOperands(OprReg r1, OprReg r2, OprReg r3)
    when isXMMReg r1 && isXMMReg r2 && isXMMReg r3 ->
    encVexRRR ins ctx.WordSize (Some r2) ctx.VEX128nF2n0F [| 0x58uy |] r1 r3
  | ThreeOperands(OprReg r1, OprReg r2, OprMem(b, s, d, 64<rt>))
    when isXMMReg r1 && isXMMReg r2 ->
    encVexRRM ins ctx.WordSize (Some r2) ctx.VEX128nF2n0F [| 0x58uy |] r1 b s d
  | o -> printfn "%A" o; raise NotEncodableException

let vaddss (ctx: EncContext) ins =
  match ins.Operands with
  | ThreeOperands(OprReg r1, OprReg r2, OprReg r3)
    when isXMMReg r1 && isXMMReg r2 && isXMMReg r3 ->
    encVexRRR ins ctx.WordSize (Some r2) ctx.VEX128nF3n0F [| 0x58uy |] r1 r3
  | ThreeOperands(OprReg r1, OprReg r2, OprMem(b, s, d, 32<rt>))
    when isXMMReg r1 && isXMMReg r2 ->
    encVexRRM ins ctx.WordSize (Some r2) ctx.VEX128nF3n0F [| 0x58uy |] r1 b s d
  | o -> printfn "%A" o; raise NotEncodableException

let vpalignr (ctx: EncContext) ins =
  match ins.Operands with
  (* Reg - Reg - Reg - Imm8 *)
  | FourOperands(OprReg r1, OprReg r2, OprReg r3, OprImm(imm, _))
    when isXMMReg r1 && isXMMReg r2 && isXMMReg r3 ->
    encVexRRRI ins ctx.WordSize
      (Some r2) ctx.VEX128n66n0F3A [| 0x0Fuy |] r1 r3 imm 8<rt>
  | FourOperands(OprReg r1, OprReg r2, OprReg r3, OprImm(imm, _))
    when isYMMReg r1 && isYMMReg r2 && isYMMReg r3 ->
    encVexRRRI ins ctx.WordSize
      (Some r2) ctx.VEX256n66n0F3A [| 0x0Fuy |] r1 r3 imm 8<rt>
  (* Reg - Reg - Mem - Imm8 *)
  | FourOperands(OprReg r1, OprReg r2, OprMem(b, s, d, 128<rt>), OprImm(imm, _))
    when isXMMReg r1 && isXMMReg r2 ->
    encVexRRMI ins ctx.WordSize
      (Some r2) ctx.VEX128n66n0F3A [| 0x0Fuy |] r1 b s d imm 8<rt>
  | FourOperands(OprReg r1, OprReg r2, OprMem(b, s, d, 256<rt>), OprImm(imm, _))
    when isYMMReg r1 && isYMMReg r2 ->
    encVexRRMI ins ctx.WordSize
      (Some r2) ctx.VEX256n66n0F3A [| 0x0Fuy |] r1 b s d imm 8<rt>
  | o -> printfn "%A" o; raise NotEncodableException

let xchg (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg Register.AX, OprReg r)
  | TwoOperands(OprReg r, OprReg Register.AX) when isReg16 ctx r ->
    encO ins ctx ctx.Pref66 ctx.RexNormal 0x90uy r
  | TwoOperands(OprReg Register.EAX, OprReg r)
  | TwoOperands(OprReg r, OprReg Register.EAX) when isReg32 ctx r ->
    encO ins ctx ctx.PrefNormal ctx.RexNormal 0x90uy r
  | TwoOperands(OprReg Register.RAX, OprReg r)
  | TwoOperands(OprReg r, OprReg Register.RAX) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encO ins ctx ctx.PrefNormal ctx.RexW 0x90uy r
  | o -> printfn "%A" o; raise NotEncodableException

let xor (ctx: EncContext) ins =
  match ins.Operands with
  (* Reg (fixed) - Imm (Priority 1). *)
  | TwoOperands(OprReg Register.AL, OprImm(imm, _)) ->
    encImm ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x34uy |] imm 8<rt>
  | TwoOperands(OprReg Register.AX, OprImm(imm, _)) ->
    encImm ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x35uy |] imm 16<rt>
  | TwoOperands(OprReg Register.EAX, OprImm(imm, _)) ->
    encImm ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x35uy |] imm 32<rt>
  | TwoOperands(OprReg Register.RAX, OprImm(imm, _)) ->
    no32Arch ctx.WordSize
    encImm ins ctx
      ctx.PrefNormal ctx.RexW [| 0x35uy |] imm 32<rt>
  (* Reg - Imm (Priority 0) *)
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg16 ctx r && isInt8 imm ->
    encRI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x83uy |] r 0b110uy imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg32 ctx r && isInt8 imm ->
    encRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x83uy |] r 0b110uy imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg64 ctx r && isInt8 imm ->
    no32Arch ctx.WordSize
    encRI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x83uy |] r 0b110uy imm 8<rt>
  (* Mem - Imm (Priority 0) *)
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprImm(imm, _)) when isInt8 imm ->
    encMI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x83uy |] b s d 0b110uy imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprImm(imm, _)) when isInt8 imm ->
    encMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x83uy |] b s d 0b110uy imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprImm(imm, _)) when isInt8 imm ->
    no32Arch ctx.WordSize
    encMI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x83uy |] b s d 0b110uy imm 8<rt>
  (* Reg - Imm (Priority 1) *)
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg8 ctx r ->
    encRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x80uy |] r 0b110uy imm 8<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg16 ctx r ->
    encRI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x81uy |] r 0b110uy imm 16<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg32 ctx r ->
    encRI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x81uy |] r 0b110uy imm 32<rt>
  | TwoOperands(OprReg r, OprImm(imm, _)) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encRI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x81uy |] r 0b110uy imm 32<rt>
  (* Mem - Imm (Priority 1) *)
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x80uy |] b s d 0b110uy imm 8<rt>
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x81uy |] b s d 0b110uy imm 16<rt>
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprImm(imm, _)) ->
    encMI ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x81uy |] b s d 0b110uy imm 32<rt>
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprImm(imm, _)) ->
    no32Arch ctx.WordSize;
    encMI ins ctx
      ctx.PrefNormal ctx.RexW [| 0x81uy |] b s d 0b110uy imm 32<rt>
  (* Mem - Reg *)
  | TwoOperands(OprMem(b, s, d, 8<rt>), OprReg r) when isReg8 ctx r ->
    encMR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x30uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 16<rt>), OprReg r) when isReg16 ctx r ->
    encMR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x31uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 32<rt>), OprReg r) when isReg32 ctx r ->
    encMR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x31uy |] b s d r
  | TwoOperands(OprMem(b, s, d, 64<rt>), OprReg r) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encMR ins ctx
      ctx.PrefNormal ctx.RexW [| 0x31uy |] b s d r
  (* Reg - Reg *)
  | TwoOperands(OprReg r1, OprReg r2) when isReg8 ctx r1 && isReg8 ctx r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x32uy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isReg16 ctx r1 && isReg16 ctx r2 ->
    encRR ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x33uy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isReg32 ctx r1 && isReg32 ctx r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x33uy |] r1 r2
  | TwoOperands(OprReg r1, OprReg r2) when isReg64 ctx r1 && isReg64 ctx r2 ->
    no32Arch ctx.WordSize
    encRR ins ctx
      ctx.PrefNormal ctx.RexW [| 0x33uy |] r1 r2
  (* Reg - Mem *)
  | TwoOperands(OprReg r, OprMem(b, s, d, 8<rt>)) when isReg8 ctx r ->
    encRM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x32uy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 16<rt>)) when isReg16 ctx r ->
    encRM ins ctx
      ctx.Pref66 ctx.RexNormal [| 0x33uy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 32<rt>)) when isReg32 ctx r ->
    encRM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x33uy |] r b s d
  | TwoOperands(OprReg r, OprMem(b, s, d, 64<rt>)) when isReg64 ctx r ->
    no32Arch ctx.WordSize
    encRM ins ctx
      ctx.PrefNormal ctx.RexW [| 0x33uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let xorps (ctx: EncContext) ins =
  match ins.Operands with
  | TwoOperands(OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0x57uy |] r1 r2
  | TwoOperands(OprReg r, OprMem(b, s, d, 128<rt>)) when isXMMReg r ->
    encRM ins ctx
      ctx.PrefNormal ctx.RexNormal [| 0x0Fuy; 0x57uy |] r b s d
  | o -> printfn "%A" o; raise NotEncodableException

let syscall () =
  [| Normal 0x0Fuy; Normal 0x05uy |]

// vim: set tw=80 sts=2 sw=2:
