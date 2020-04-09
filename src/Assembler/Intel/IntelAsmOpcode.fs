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

module internal B2R2.Assembler.Intel.AsmOpcode

open B2R2
open B2R2.FrontEnd.Intel
open B2R2.Assembler.Intel.AsmPrefix
open B2R2.Assembler.Intel.AsmOperands

let no32Arch arch =
  if arch = Arch.IntelX86 then raise NotEncodableException else ()

let no64Arch arch =
  if arch = Arch.IntelX64 then raise NotEncodableException else ()

let encPrxRexOp ins arch pref rex op =
  [| yield! encodePrefix ins arch pref
     yield! encodeREXPref ins arch rex
     yield! Array.map Normal op |]

let inline encLbl ins arch pref rex op =
  [| yield! encPrxRexOp ins arch pref rex op
     yield! encodeDisp ins None |]

let inline encI ins arch pref rex op i immSz =
  [| yield! encPrxRexOp ins arch pref rex op
     yield! encodeImm i immSz |]

let inline encR ins arch pref rex op r c =
  [| yield! encPrxRexOp ins arch pref rex op
     encodeR r c |]

let inline encM ins arch pref rex op b s d c =
  [| yield! encPrxRexOp ins arch pref rex op
     encodeM b s d c
     yield! encodeSIB b s
     yield! encodeDisp ins d |]

let inline encRR ins arch pref rex op r1 r2 =
  [| yield! encPrxRexOp ins arch pref rex op
     encodeRR r1 r2 |]

let inline encRI ins arch pref rex op r c i immSz =
  [| yield! encPrxRexOp ins arch pref rex op
     encodeRI r c
     yield! encodeImm i immSz |]

let inline encRM ins arch pref rex op r b s d =
  [| yield! encPrxRexOp ins arch pref rex op
     encodeRM r b s d
     yield! encodeSIB b s
     yield! encodeDisp ins d |]

let inline encMR ins arch pref rex op b s d r =
  [| yield! encPrxRexOp ins arch pref rex op
     encodeMR b s d r
     yield! encodeSIB b s
     yield! encodeDisp ins d |]

let inline encMI ins arch pref rex op b s d c i immSz =
  [| yield! encPrxRexOp ins arch pref rex op
     encodeMI b s d c
     yield! encodeSIB b s
     yield! encodeDisp ins d
     yield! encodeImm i immSz |]

let inline encRIWithOpFld ins arch pref rex op r i immSz =
  let op = [| op + (regTo3Bit r) |]
  [| yield! encPrxRexOp ins arch pref rex op
     yield! encodeImm i immSz |]

let inline encRRI ins arch pref rex op r1 r2 i immSz =
  [| yield! encPrxRexOp ins arch pref rex op
     encodeRR r1 r2
     yield! encodeImm i immSz |]

let inline encRMI ins arch pref rex op r b s d i immSz =
  [| yield! encPrxRexOp ins arch pref rex op
     encodeRM r b s d
     yield! encodeSIB b s
     yield! encodeDisp ins d
     yield! encodeImm i immSz |]

let inline encVexRRR ins arch vvvv vex op r1 r3 =
  let rexRXB = encodeVEXRexRB arch r1 r3
  [| yield! encodeVEXPref rexRXB vvvv vex
     yield! Array.map Normal op
     encodeRR r1 r3 |]

let inline encVexRRM ins arch vvvv vex op r b s d =
  let rexRXB = encodeVEXRexRXB arch r b s
  [| yield! encodeVEXPref rexRXB vvvv vex
     yield! Array.map Normal op
     encodeRM r b s d
     yield! encodeSIB b s
     yield! encodeDisp ins d |]

let inline encVexRRRI ins arch vvvv vex op r1 r3 i immSz =
  let rexRXB = encodeVEXRexRB arch r1 r3
  [| yield! encodeVEXPref rexRXB vvvv vex
     yield! Array.map Normal op
     encodeRR r1 r3
     yield! encodeImm i immSz |]

let inline encVexRRMI ins arch vvvv vex op r b s d i immSz =
  let rexRXB = encodeVEXRexRXB arch r b s
  [| yield! encodeVEXPref rexRXB vvvv vex
     yield! Array.map Normal op
     encodeRM r b s d
     yield! encodeSIB b s
     yield! encodeDisp ins d
     yield! encodeImm i immSz |]

let aaa (ctxt: EncContext) = function
  | NoOperand -> no64Arch ctxt.Arch; [| Normal 0x37uy |]
  | _ -> raise OperandTypeMismatchException

let aad (ctxt: EncContext) = function
  | NoOperand -> no64Arch ctxt.Arch; [| Normal 0xD5uy; Normal 0x0Auy |]
  | OneOperand (OprImm imm) ->
    no64Arch ctxt.Arch; [| Normal 0xD5uy; yield! encodeImm imm 8<rt> |]
  | _ -> raise OperandTypeMismatchException

let aam (ctxt: EncContext) = function
  | NoOperand -> no64Arch ctxt.Arch; [| Normal 0xD4uy; Normal 0x0Auy |]
  | OneOperand (OprImm imm) ->
    no64Arch ctxt.Arch; [| Normal 0xD4uy; yield! encodeImm imm 8<rt> |]
  | _ -> raise OperandTypeMismatchException

let aas (ctxt: EncContext) = function
  | NoOperand -> no64Arch ctxt.Arch; [| Normal 0x3Fuy |]
  | _ -> raise OperandTypeMismatchException

let adc (ctxt: EncContext) ins =
  match ins.Operands with
  (* Reg (fixed) - Imm (Priority 1). *)
  | TwoOperands (OprReg Register.AL, OprImm imm) ->
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x14uy |] imm 8<rt>
  | TwoOperands (OprReg Register.AX, OprImm imm) ->
    encI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x15uy |] imm 16<rt>
  | TwoOperands (OprReg Register.EAX, OprImm imm) ->
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x15uy |] imm 32<rt>
  | TwoOperands (OprReg Register.RAX, OprImm imm) ->
    no32Arch ctxt.Arch
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x15uy |] imm 32<rt>
  (* Reg - Imm (Priority 0) *)
  | TwoOperands (OprReg r, OprImm imm) when isReg16 r && imm <= 0xFFL ->
    encRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x83uy |] r 0b010uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm imm) when isReg32 r && imm <= 0xFFL ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x83uy |] r 0b010uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm imm) when isReg64 r && imm <= 0xFFL ->
    no32Arch ctxt.Arch
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x83uy |] r 0b010uy imm 8<rt>
  (* Mem - Imm (Priority 0) *)
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprImm imm) when imm <= 0xFFL ->
    encMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x83uy |] b s d 0b010uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprImm imm) when imm <= 0xFFL ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x83uy |] b s d 0b010uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprImm imm) when imm <= 0xFFL ->
    no32Arch ctxt.Arch
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x83uy |] b s d 0b010uy imm 8<rt>
  (* Reg - Imm (Priority 1) *)
  | TwoOperands (OprReg r, OprImm imm) when isReg8 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x80uy |] r 0b010uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm imm) when isReg16 r ->
    encRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x81uy |] r 0b010uy imm 16<rt>
  | TwoOperands (OprReg r, OprImm imm) when isReg32 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x81uy |] r 0b010uy imm 32<rt>
  | TwoOperands (OprReg r, OprImm imm) when isReg64 r ->
    no32Arch ctxt.Arch
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x81uy |] r 0b010uy imm 32<rt>
  (* Mem - Imm (Priority 1) *)
  | TwoOperands (OprMem (b, s, d, 8<rt>), OprImm imm) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x80uy |] b s d 0b010uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprImm imm) ->
    encMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x81uy |] b s d 0b010uy imm 16<rt>
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprImm imm) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x81uy |] b s d 0b010uy imm 32<rt>
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprImm imm) ->
    no32Arch ctxt.Arch;
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x81uy |] b s d 0b010uy imm 32<rt>
  (* Mem - Reg *)
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
  | o -> printfn "%A" o; raise OperandTypeMismatchException

let add (ctxt: EncContext) ins =
  match ins.Operands with
  (* Reg (fixed) - Imm (Priority 1) *)
  | TwoOperands (OprReg Register.AL, OprImm imm) ->
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x04uy |] imm 8<rt>
  | TwoOperands (OprReg Register.AX, OprImm imm) ->
    encI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x05uy |] imm 16<rt>
  | TwoOperands (OprReg Register.EAX, OprImm imm) ->
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x05uy |] imm 32<rt>
  | TwoOperands (OprReg Register.RAX, OprImm imm) ->
    no32Arch ctxt.Arch
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x05uy |] imm 32<rt>
  (* Reg - Imm (Priority 0) *)
  | TwoOperands (OprReg r, OprImm imm) when isReg16 r && imm <= 0xFFL ->
    encRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x83uy |] r 0b000uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm imm) when isReg32 r && imm <= 0xFFL ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x83uy |] r 0b000uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm imm) when isReg64 r && imm <= 0xFFL ->
    no32Arch ctxt.Arch
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x83uy |] r 0b000uy imm 8<rt>
  (* Mem - Imm (Priority 0) *)
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprImm imm) when imm <= 0xFFL ->
    encMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x83uy |] b s d 0b000uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprImm imm) when imm <= 0xFFL ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x83uy |] b s d 0b000uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprImm imm) when imm <= 0xFFL ->
    no32Arch ctxt.Arch
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x83uy |] b s d 0b000uy imm 8<rt>
  (* Reg - Imm (Priority 1) *)
  | TwoOperands (OprReg r, OprImm imm) when isReg8 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x80uy |] r 0b000uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm imm) when isReg16 r ->
    encRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x81uy |] r 0b000uy imm 16<rt>
  | TwoOperands (OprReg r, OprImm imm) when isReg32 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x81uy |] r 0b000uy imm 32<rt>
  | TwoOperands (OprReg r, OprImm imm) when isReg64 r ->
    no32Arch ctxt.Arch
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x81uy |] r 0b000uy imm 32<rt>
  (* Mem - Imm (Priority 1) *)
  | TwoOperands (OprMem (b, s, d, 8<rt>), OprImm imm) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x80uy |] b s d 0b000uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprImm imm) ->
    encMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x81uy |] b s d 0b000uy imm 16<rt>
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprImm imm) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x81uy |] b s d 0b000uy imm 32<rt>
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprImm imm) ->
    no32Arch ctxt.Arch;
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x81uy |] b s d 0b000uy imm 32<rt>
  (* Mem - Reg *)
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
  | o -> printfn "%A" o; raise OperandTypeMismatchException

let addpd (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0x58uy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 128<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.Pref66  ctxt.RexNormal [| 0x0Fuy; 0x58uy |] r b s d
  | o -> printfn "%A" o; raise OperandTypeMismatchException

let addps (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0x58uy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 128<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0x58uy |] r b s d
  | o -> printfn "%A" o; raise OperandTypeMismatchException

let addsd (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefF2 ctxt.RexNormal [| 0x0Fuy; 0x58uy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 64<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefF2 ctxt.RexNormal [| 0x0Fuy; 0x58uy |] r b s d
  | o -> printfn "%A" o; raise OperandTypeMismatchException

let addss (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefF3 ctxt.RexNormal [| 0x0Fuy; 0x58uy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefF3 ctxt.RexNormal [| 0x0Fuy; 0x58uy |] r b s d
  | o -> printfn "%A" o; raise OperandTypeMismatchException

let logAnd (ctxt: EncContext) ins =
  match ins.Operands with
  (* Reg (fixed) - Imm *)
  | TwoOperands (OprReg Register.AL, OprImm imm) ->
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x24uy |] imm 8<rt>
  | TwoOperands (OprReg Register.AX, OprImm imm) ->
    encI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x25uy |] imm 16<rt>
  | TwoOperands (OprReg Register.EAX, OprImm imm) ->
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x25uy |] imm 32<rt>
  | TwoOperands (OprReg Register.RAX, OprImm imm) ->
    no32Arch ctxt.Arch
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x25uy |] imm 32<rt>
  (* Reg - Imm (Priority 0) *)
  | TwoOperands (OprReg r, OprImm imm) when isReg16 r && imm <= 0xFFL ->
    encRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x83uy |] r 0b100uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm imm) when isReg32 r && imm <= 0xFFL ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x83uy |] r 0b100uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm imm) when isReg64 r && imm <= 0xFFL ->
    no32Arch ctxt.Arch
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x83uy |] r 0b100uy imm 8<rt>
  (* Mem - Imm (Priority 0) *)
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprImm imm) when imm <= 0xFFL ->
    encMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x83uy |] b s d 0b100uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprImm imm) when imm <= 0xFFL ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x83uy |] b s d 0b100uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprImm imm) when imm <= 0xFFL ->
    no32Arch ctxt.Arch
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x83uy |] b s d 0b100uy imm 8<rt>
  (* Reg - Imm (Priority 1) *)
  | TwoOperands (OprReg r, OprImm imm) when isReg8 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x80uy |] r 0b100uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm imm) when isReg16 r ->
    encRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x81uy |] r 0b100uy imm 16<rt>
  | TwoOperands (OprReg r, OprImm imm) when isReg32 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x81uy |] r 0b100uy imm 32<rt>
  | TwoOperands (OprReg r, OprImm imm) when isReg64 r ->
    no32Arch ctxt.Arch
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x81uy |] r 0b100uy imm 32<rt>
  (* Mem - Imm (Priority 1) *)
  | TwoOperands (OprMem (b, s, d, 8<rt>), OprImm imm) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x80uy |] b s d 0b100uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprImm imm) ->
    encMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x81uy |] b s d 0b100uy imm 16<rt>
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprImm imm) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x81uy |] b s d 0b100uy imm 32<rt>
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprImm imm) ->
    no32Arch ctxt.Arch;
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x81uy |] b s d 0b100uy imm 32<rt>
  (* Mem - Reg *)
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
  | o -> printfn "%A" o; raise OperandTypeMismatchException

let andpd (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0x54uy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 128<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0x54uy |] r b s d
  | o -> printfn "%A" o; raise OperandTypeMismatchException

let andps (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0x54uy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 128<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0x54uy |] r b s d
  | o -> printfn "%A" o; raise OperandTypeMismatchException

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
  | TwoOperands (OprReg r, OprImm imm) when isReg16 r ->
    encRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0xBAuy |] r 0b100uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm imm) when isReg32 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0xBAuy |] r 0b100uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm imm) when isReg64 r ->
    no32Arch ctxt.Arch
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x0Fuy; 0xBAuy |] r 0b100uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprImm imm) ->
    encMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0xBAuy |] b s d 0b100uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprImm i) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0xBAuy |] b s d 0b100uy i 8<rt>
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprImm imm) ->
    no32Arch ctxt.Arch
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x0Fuy; 0xBAuy |] b s d 0b100uy imm 8<rt>
  | o -> printfn "%A" o; raise OperandTypeMismatchException

let call (ctxt: EncContext) ins =
  match ins.Operands with
  | OneOperand (GoToLabel _) -> // FIXME: rel32
    encLbl ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xE8uy |]
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
  | o -> printfn "%A" o; raise OperandTypeMismatchException

let cbw _ctxt = function
  | NoOperand -> [| Normal 0x66uy; Normal 0x98uy |]
  | _ -> raise OperandTypeMismatchException

let cdqe (ctxt: EncContext) = function
  | NoOperand -> no32Arch ctxt.Arch; [| Normal 0x48uy; Normal 0x98uy |]
  | _ -> raise OperandTypeMismatchException

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
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprReg r) when isReg16 r ->
    encMR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal opcode b s d r
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprReg r) when isReg32 r ->
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal opcode b s d r
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprReg r) when isReg64 r ->
    no32Arch ctxt.Arch
    encMR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW opcode b s d r
  | o -> printfn "%A" o; raise OperandTypeMismatchException

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
  | TwoOperands (OprReg Register.AL, OprImm imm) ->
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x3Cuy |] imm 8<rt>
  | TwoOperands (OprReg Register.AX, OprImm imm) ->
    encI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x3Duy |] imm 16<rt>
  | TwoOperands (OprReg Register.EAX, OprImm imm) ->
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x3Duy |] imm 32<rt>
  | TwoOperands (OprReg Register.RAX, OprImm imm) ->
    no32Arch ctxt.Arch
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x3Duy |] imm 32<rt>
  (* Reg - Imm (Priority 0) *)
  | TwoOperands (OprReg r, OprImm imm) when isReg16 r && imm <= 0xFFL ->
    encRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x83uy |] r 0b111uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm imm) when isReg32 r && imm <= 0xFFL ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x83uy |] r 0b111uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm imm) when isReg64 r && imm <= 0xFFL ->
    no32Arch ctxt.Arch
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x83uy |] r 0b111uy imm 8<rt>
  (* Mem - Imm (Priority 0) *)
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprImm imm) when imm <= 0xFFL ->
    encMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x83uy |] b s d 0b111uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprImm imm) when imm <= 0xFFL ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x83uy |] b s d 0b111uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprImm imm) when imm <= 0xFFL ->
    no32Arch ctxt.Arch
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x83uy |] b s d 0b111uy imm 8<rt>
  (* Reg - Imm (Priority 1) *)
  | TwoOperands (OprReg r, OprImm imm) when isReg8 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x80uy |] r 0b111uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm imm) when isReg16 r ->
    encRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x81uy |] r 0b111uy imm 16<rt>
  | TwoOperands (OprReg r, OprImm imm) when isReg32 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x81uy |] r 0b111uy imm 32<rt>
  | TwoOperands (OprReg r, OprImm imm) when isReg64 r ->
    no32Arch ctxt.Arch
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x81uy |] r 0b111uy imm 32<rt>
  (* Mem - Imm (Priority 1) *)
  | TwoOperands (OprMem (b, s, d, 8<rt>), OprImm imm) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x80uy |] b s d 0b111uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprImm imm) ->
    encMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x81uy |] b s d 0b111uy imm 16<rt>
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprImm imm) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x81uy |] b s d 0b111uy imm 32<rt>
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprImm imm) ->
    no32Arch ctxt.Arch;
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x81uy |] b s d 0b111uy imm 32<rt>
  (* Mem - Reg *)
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
  | o -> printfn "%A" o; raise OperandTypeMismatchException

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
  | o -> printfn "%A" o; raise OperandTypeMismatchException

let cmpxchg8b (ctxt: EncContext) ins =
  match ins.Operands with
  | OneOperand (OprMem (b, s, d, 64<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0xC7uy |] b s d 0b001uy
  | o -> printfn "%A" o; raise OperandTypeMismatchException

let cmpxchg16b (ctxt: EncContext) ins =
  match ins.Operands with
  | OneOperand (OprMem (b, s, d, 128<rt>)) ->
    no32Arch ctxt.Arch
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x0Fuy; 0xC7uy |] b s d 0b001uy
  | o -> printfn "%A" o; raise OperandTypeMismatchException

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
  | o -> printfn "%A" o; raise OperandTypeMismatchException

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
  | o -> printfn "%A" o; raise OperandTypeMismatchException

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
  | o -> printfn "%A" o; raise OperandTypeMismatchException

let cwde _ctxt = function
  | NoOperand -> [| Normal 0x98uy |]
  | _ -> raise OperandTypeMismatchException

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
  | o -> printfn "%A" o; raise OperandTypeMismatchException

let divsd (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefF2 ctxt.RexNormal [| 0x0Fuy; 0x5Euy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 64<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefF2 ctxt.RexNormal [| 0x0Fuy; 0x5Euy |] r b s d
  | o -> printfn "%A" o; raise OperandTypeMismatchException

let divss (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefF3 ctxt.RexNormal [| 0x0Fuy; 0x5Euy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefF3 ctxt.RexNormal [| 0x0Fuy; 0x5Euy |] r b s d
  | o -> printfn "%A" o; raise OperandTypeMismatchException

let fadd (ctxt: EncContext) ins =
  match ins.Operands with
  | OneOperand (OprMem (b, s, d, 32<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xD8uy |] b s d 0b000uy
  | OneOperand (OprMem (b, s, d, 64<rt>)) ->
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xDCuy |] b s d 0b000uy
  // FIXME: ST(0), ST(i)
  | o -> printfn "%A" o; raise OperandTypeMismatchException

let hlt _ctxt = function
  | NoOperand -> [| Normal 0x3Fuy |]
  | _ -> raise OperandTypeMismatchException

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
  | ThreeOperands (OprReg r1, OprReg r2, OprImm imm)
    when isReg16 r1 && isReg16 r2 && imm <= 0xFFL ->
    encRRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x6Buy |] r1 r2 imm 8<rt>
  | ThreeOperands (OprReg r, OprMem (b, s, d, 16<rt>), OprImm imm)
    when isReg16 r && imm <= 0xFFL ->
    encRMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x6Buy |] r b s d imm 8<rt>
  | ThreeOperands (OprReg r1, OprReg r2, OprImm imm)
    when isReg32 r1 && isReg32 r2 && imm <= 0xFFL ->
    encRRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x6Buy |] r1 r2 imm 8<rt>
  | ThreeOperands (OprReg r, OprMem (b, s, d, 32<rt>), OprImm imm)
    when isReg32 r && imm <= 0xFFL ->
    encRMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x6Buy |] r b s d imm 8<rt>
  | ThreeOperands (OprReg r1, OprReg r2, OprImm imm)
    when isReg64 r1 && isReg64 r2 && imm <= 0xFFL ->
    no32Arch ctxt.Arch
    encRRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x6Buy |] r1 r2 imm 8<rt>
  | ThreeOperands (OprReg r, OprMem (b, s, d, 64<rt>), OprImm imm)
    when isReg64 r && imm <= 0xFFL ->
    no32Arch ctxt.Arch
    encRMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x6Buy |] r b s d imm 8<rt>
  | ThreeOperands (OprReg r1, OprReg r2, OprImm imm)
    when isReg16 r1 && isReg16 r2 ->
    encRRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x69uy |] r1 r2 imm 16<rt>
  | ThreeOperands (OprReg r, OprMem (b, s, d, 16<rt>), OprImm imm)
    when isReg16 r ->
    encRMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x69uy |] r b s d imm 16<rt>
  | ThreeOperands (OprReg r1, OprReg r2, OprImm imm)
    when isReg32 r1 && isReg32 r2 ->
    encRRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x69uy |] r1 r2 imm 32<rt>
  | ThreeOperands (OprReg r, OprMem (b, s, d, 32<rt>), OprImm imm)
    when isReg32 r ->
    encRMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x69uy |] r b s d imm 32<rt>
  | ThreeOperands (OprReg r1, OprReg r2, OprImm imm)
    when isReg64 r1 && isReg64 r2 ->
    no32Arch ctxt.Arch
    encRRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x69uy |] r1 r2 imm 32<rt>
  | ThreeOperands (OprReg r, OprMem (b, s, d, 64<rt>), OprImm imm)
    when isReg64 r ->
    no32Arch ctxt.Arch
    encRMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x69uy |] r b s d imm 32<rt>
  | o -> printfn "%A" o; raise OperandTypeMismatchException

let jmp (ctxt: EncContext) ins =
  match ins.Operands with
  | o -> printfn "%A" o; raise OperandTypeMismatchException

let lea (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r, OprMem (b, s, d, 16<rt>)) when isReg16 r ->
    encRM ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x8Duy |] r b s d
  | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isReg32 r ->
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x8Duy |] r b s d
  | TwoOperands (OprReg r, OprMem (b, s, d, 16<rt>)) when isReg16 r ->
    no32Arch ctxt.Arch
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x8Duy |] r b s d
  | o -> printfn "%A" o; raise OperandTypeMismatchException

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
  (* Reg - Imm  *)
  | TwoOperands (OprReg r, OprImm imm) when isReg8 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xC6uy |] r 0b000uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm imm) when isReg16 r ->
    encRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0xC7uy |] r 0b000uy imm 16<rt>
  | TwoOperands (OprReg r, OprImm imm) when isReg32 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xC7uy |] r 0b000uy imm 32<rt>
  | TwoOperands (OprReg r, OprImm imm) when isReg64 r && imm <= 0xFFFFFFFFL ->
    no32Arch ctxt.Arch
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0xC7uy |] r 0b000uy imm 32<rt>
  (* Mem - Imm *)
  | TwoOperands (OprMem (b, s, d, 8<rt>), OprImm imm) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xC6uy |] b s d 0b000uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprImm imm) ->
    encMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0xC7uy |] b s d 0b000uy imm 16<rt>
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprImm imm) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0xC7uy |] b s d 0b000uy imm 32<rt>
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprImm imm) ->
    no32Arch ctxt.Arch;
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0xC7uy |] b s d 0b000uy imm 32<rt>
  (* Reg - Imm (Opcode reg field) *)
  | TwoOperands (OprReg r, OprImm imm) when isReg64 r ->
    no32Arch ctxt.Arch
    encRIWithOpFld ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexWAndOpFld 0xB8uy r imm 64<rt>
  | o -> printfn "%A" o; raise OperandTypeMismatchException

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
  | o -> printfn "%A" o; raise OperandTypeMismatchException

let movss (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefF3 ctxt.RexNormal [| 0x0Fuy; 0x10uy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefF3 ctxt.RexNormal [| 0x0Fuy; 0x10uy |] r b s d
  | o -> printfn "%A" o; raise OperandTypeMismatchException

let movsx (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isReg16 r1 && isReg8 r2 ->
    encRR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0xBEuy |] r1 r2
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
  | o -> printfn "%A" o; raise OperandTypeMismatchException

let movsxd (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isReg64 r1 && isReg32 r2 ->
    no32Arch ctxt.Arch
    encRR ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x63uy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isReg64 r ->
    no32Arch ctxt.Arch
    encRM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x63uy |] r b s d
  | o -> printfn "%A" o; raise OperandTypeMismatchException

let movzx (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isReg16 r1 && isReg8 r2 ->
    encRR ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0xB6uy |] r1 r2
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
  | o -> printfn "%A" o; raise OperandTypeMismatchException

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
  | o -> printfn "%A" o; raise OperandTypeMismatchException

let mulsd (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefF2 ctxt.RexNormal [| 0x0Fuy; 0x59uy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 64<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefF2 ctxt.RexNormal [| 0x0Fuy; 0x59uy |] r b s d
  | o -> printfn "%A" o; raise OperandTypeMismatchException

let mulss (ctxt: EncContext) ins =
  match ins.Operands with
  | TwoOperands (OprReg r1, OprReg r2) when isXMMReg r1 && isXMMReg r2 ->
    encRR ins ctxt.Arch
      ctxt.PrefF3 ctxt.RexNormal [| 0x0Fuy; 0x59uy |] r1 r2
  | TwoOperands (OprReg r, OprMem (b, s, d, 32<rt>)) when isXMMReg r ->
    encRM ins ctxt.Arch
      ctxt.PrefF3 ctxt.RexNormal [| 0x0Fuy; 0x59uy |] r b s d
  | o -> printfn "%A" o; raise OperandTypeMismatchException

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
  | o -> printfn "%A" o; raise OperandTypeMismatchException

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
  | o -> printfn "%A" o; raise OperandTypeMismatchException

let logOr (ctxt: EncContext) ins =
  match ins.Operands with
  (* Reg (fixed) - Imm *)
  | TwoOperands (OprReg Register.AL, OprImm imm) ->
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Cuy |] imm 8<rt>
  | TwoOperands (OprReg Register.AX, OprImm imm) ->
    encI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Duy |] imm 16<rt>
  | TwoOperands (OprReg Register.EAX, OprImm imm) ->
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Duy |] imm 32<rt>
  | TwoOperands (OprReg Register.RAX, OprImm imm) ->
    no32Arch ctxt.Arch
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x0Duy |] imm 32<rt>
  (* Reg - Imm (Priority 0) *)
  | TwoOperands (OprReg r, OprImm imm) when isReg16 r && imm <= 0xFFL ->
    encRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x83uy |] r 0b001uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm imm) when isReg32 r && imm <= 0xFFL ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x83uy |] r 0b001uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm imm) when isReg64 r && imm <= 0xFFL ->
    no32Arch ctxt.Arch
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x83uy |] r 0b001uy imm 8<rt>
  (* Mem - Imm (Priority 0) *)
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprImm imm) when imm <= 0xFFL ->
    encMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x83uy |] b s d 0b001uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprImm imm) when imm <= 0xFFL ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x83uy |] b s d 0b001uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprImm imm) when imm <= 0xFFL ->
    no32Arch ctxt.Arch
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x83uy |] b s d 0b001uy imm 8<rt>
  (* Reg - Imm (Priority 1) *)
  | TwoOperands (OprReg r, OprImm imm) when isReg8 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x80uy |] r 0b001uy imm 8<rt>
  | TwoOperands (OprReg r, OprImm imm) when isReg16 r ->
    encRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x81uy |] r 0b001uy imm 16<rt>
  | TwoOperands (OprReg r, OprImm imm) when isReg32 r ->
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x81uy |] r 0b001uy imm 32<rt>
  | TwoOperands (OprReg r, OprImm imm) when isReg64 r ->
    no32Arch ctxt.Arch
    encRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x81uy |] r 0b001uy imm 32<rt>
  (* Mem - Imm (Priority 1) *)
  | TwoOperands (OprMem (b, s, d, 8<rt>), OprImm imm) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x80uy |] b s d 0b001uy imm 8<rt>
  | TwoOperands (OprMem (b, s, d, 16<rt>), OprImm imm) ->
    encMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x81uy |] b s d 0b001uy imm 16<rt>
  | TwoOperands (OprMem (b, s, d, 32<rt>), OprImm imm) ->
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x81uy |] b s d 0b001uy imm 32<rt>
  | TwoOperands (OprMem (b, s, d, 64<rt>), OprImm imm) ->
    no32Arch ctxt.Arch;
    encMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0x81uy |] b s d 0b001uy imm 32<rt>
  (* Mem - Reg *)
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
  | o -> printfn "%A" o; raise OperandTypeMismatchException

let palignr (ctxt: EncContext) ins =
  match ins.Operands with
  (* Reg - Reg - Imm8 *)
  | ThreeOperands (OprReg r1, OprReg r2, OprImm imm)
    when isMMXReg r1 && isMMXReg r2 ->
    encRRI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0x3Auy; 0x0Fuy |]
      r1 r2 imm 8<rt>
  | ThreeOperands (OprReg r1, OprReg r2, OprImm imm)
    when isXMMReg r1 && isXMMReg r2 ->
    encRRI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0x3Auy; 0x0Fuy |] r1 r2 imm 8<rt>
  (* Reg - Mem - Imm8 *)
  | ThreeOperands (OprReg r, OprMem (b, s, d, 64<rt>), OprImm imm)
    when isMMXReg r ->
    encRMI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x0Fuy; 0x3Auy; 0x0Fuy |]
      r b s d imm 8<rt>
  | ThreeOperands (OprReg r, OprMem (b, s, d, 128<rt>), OprImm imm)
    when isXMMReg r ->
    encRMI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x0Fuy; 0x3Auy; 0x0Fuy |] r b s d imm 8<rt>
  | o -> printfn "%A" o; raise OperandTypeMismatchException

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
  | o -> printfn "%A" o; raise OperandTypeMismatchException

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
      ctxt.PrefNormal ctxt.RexW [| 0xFFuy |] r 0b110uy
  | OneOperand (OprMem (b, s, d, 64<rt>)) ->
    no32Arch ctxt.Arch
    encM ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexW [| 0xFFuy |] b s d 0b110uy
  | OneOperand (OprImm imm) when imm <= 0xFFL ->
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x6Auy |] imm 8<rt>
  | OneOperand (OprImm imm) when imm <= 0xFFFFL ->
    encI ins ctxt.Arch
      ctxt.Pref66 ctxt.RexNormal [| 0x68uy |] imm 16<rt>
  | OneOperand (OprImm imm) when imm <= 0xFFFFFFFFL ->
    encI ins ctxt.Arch
      ctxt.PrefNormal ctxt.RexNormal [| 0x68uy |] imm 32<rt>
  | o -> printfn "%A" o; raise OperandTypeMismatchException

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
  | o -> printfn "%A" o; raise OperandTypeMismatchException

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
  | o -> printfn "%A" o; raise OperandTypeMismatchException

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
  | o -> printfn "%A" o; raise OperandTypeMismatchException

let vaddsd (ctxt: EncContext) ins =
  match ins.Operands with
  | ThreeOperands (OprReg r1, OprReg r2, OprReg r3)
    when isXMMReg r1 && isXMMReg r2 && isXMMReg r3 ->
    encVexRRR ins ctxt.Arch (Some r2) ctxt.VEX128nF2n0F [| 0x58uy |] r1 r3
  | ThreeOperands (OprReg r1, OprReg r2, OprMem (b, s, d, 64<rt>))
    when isXMMReg r1 && isXMMReg r2 ->
    encVexRRM ins ctxt.Arch (Some r2) ctxt.VEX128nF2n0F [| 0x58uy |] r1 b s d
  | o -> printfn "%A" o; raise OperandTypeMismatchException

let vaddss (ctxt: EncContext) ins =
  match ins.Operands with
  | ThreeOperands (OprReg r1, OprReg r2, OprReg r3)
    when isXMMReg r1 && isXMMReg r2 && isXMMReg r3 ->
    encVexRRR ins ctxt.Arch (Some r2) ctxt.VEX128nF3n0F [| 0x58uy |] r1 r3
  | ThreeOperands (OprReg r1, OprReg r2, OprMem (b, s, d, 32<rt>))
    when isXMMReg r1 && isXMMReg r2 ->
    encVexRRM ins ctxt.Arch (Some r2) ctxt.VEX128nF3n0F [| 0x58uy |] r1 b s d
  | o -> printfn "%A" o; raise OperandTypeMismatchException

let vpalignr (ctxt: EncContext) ins =
  match ins.Operands with
  (* Reg - Reg - Reg - Imm8 *)
  | FourOperands (OprReg r1, OprReg r2, OprReg r3, OprImm imm)
    when isXMMReg r1 && isXMMReg r2 && isXMMReg r3 ->
    encVexRRRI ins ctxt.Arch
      (Some r2) ctxt.VEX128n66n0F3A [| 0x0Fuy |] r1 r3 imm 8<rt>
  | FourOperands (OprReg r1, OprReg r2, OprReg r3, OprImm imm)
    when isYMMReg r1 && isYMMReg r2 && isYMMReg r3 ->
    encVexRRRI ins ctxt.Arch
      (Some r2) ctxt.VEX256n66n0F3A [| 0x0Fuy |] r1 r3 imm 8<rt>
  (* Reg - Reg - Mem - Imm8 *)
  | FourOperands (OprReg r1, OprReg r2, OprMem (b, s, d, 128<rt>), OprImm imm)
    when isXMMReg r1 && isXMMReg r2 ->
    encVexRRMI ins ctxt.Arch
      (Some r2) ctxt.VEX128n66n0F3A [| 0x0Fuy |] r1 b s d imm 8<rt>
  | FourOperands (OprReg r1, OprReg r2, OprMem (b, s, d, 256<rt>), OprImm imm)
    when isYMMReg r1 && isYMMReg r2 ->
    encVexRRMI ins ctxt.Arch
      (Some r2) ctxt.VEX256n66n0F3A [| 0x0Fuy |] r1 b s d imm 8<rt>
  | o -> printfn "%A" o; raise OperandTypeMismatchException
// vim: set tw=80 sts=2 sw=2:
