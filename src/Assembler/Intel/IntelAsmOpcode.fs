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

let oSzPref = Some 0x66uy
let rexW = Some 0x48uy

let no32Arch arch =
  if arch = Arch.IntelX86 then raise NotEncodableException else ()

let no64Arch arch =
  if arch = Arch.IntelX64 then raise NotEncodableException else ()

let aaa arch = function
  | NoOperand -> no64Arch arch; [| Normal 0x37uy |]
  | _ -> raise OperandTypeMismatchException

let aad arch = function
  | NoOperand -> no64Arch arch; [| Normal 0xD5uy; Normal 0x0Auy |]
  | OneOperand (OprImm imm) ->
    no64Arch arch; [| Normal 0xD5uy; yield! encodeImm imm 8<rt> |]
  | _ -> raise OperandTypeMismatchException

let aam arch = function
  | NoOperand -> no64Arch arch; [| Normal 0xD4uy; Normal 0x0Auy |]
  | OneOperand (OprImm imm) ->
    no64Arch arch; [| Normal 0xD4uy; yield! encodeImm imm 8<rt> |]
  | _ -> raise OperandTypeMismatchException

let aas arch = function
  | NoOperand -> no64Arch arch; [| Normal 0x3Fuy |]
  | _ -> raise OperandTypeMismatchException

let adc arch ins =
  match ins.Operands with
  // Reg (fixed) - Imm (Priority 1)
  | TwoOperands (OprReg Register.AL, OprImm imm) ->
    [| Normal 0x14uy
       yield! encodeImm imm 8<rt> |]
  | TwoOperands (OprReg Register.AX as o1, OprImm imm) ->
    [| Normal 0x66uy
       Normal 0x15uy
       yield! encodeImm imm 16<rt> |]
  | TwoOperands (OprReg Register.EAX, OprImm imm) ->
    [| Normal 0x15uy
       yield! encodeImm imm 32<rt> |]
  | TwoOperands (OprReg Register.RAX, OprImm imm) ->
    no32Arch arch
    [| Normal 0x48uy
       Normal 0x15uy
       yield! encodeImm imm 32<rt> |]

  // Reg - Imm (Priority 1)
  | TwoOperands (OprReg r, OprImm imm) when isReg8 r ->
    [| yield! encodeREXPref arch ins None
       Normal 0x80uy
       encodeRI r 0b010uy
       yield! encodeImm imm 8<rt> |]

  // Mem - Imm (Priority 1)
  | TwoOperands (OprMem (Some b, s, d, 8<rt>), OprImm imm) ->
    [| yield! encodePrefix arch ins None
       yield! encodeREXPref arch ins None
       Normal 0x80uy
       encodeMI b s d 0b010uy
       yield! encodeSIB ins
       yield! encodeDisp ins
       yield! encodeImm imm 8<rt> |]
  | TwoOperands (OprReg r, OprImm imm) when isReg16 r ->
    [| yield! encodePrefix arch ins oSzPref
       yield! encodeREXPref arch ins None
       Normal 0x81uy
       encodeRI r 0b010uy
       yield! encodeImm imm 16<rt> |]
  | TwoOperands (OprMem (Some b, s, d, 16<rt>), OprImm imm) ->
    [| yield! encodePrefix arch ins oSzPref
       yield! encodeREXPref arch ins None
       Normal 0x81uy
       encodeMI b s d 0b010uy
       yield! encodeSIB ins
       yield! encodeDisp ins
       yield! encodeImm imm 16<rt> |]
  | TwoOperands (OprReg r, OprImm imm) when isReg32 r ->
    [| yield! encodeREXPref arch ins None
       Normal 0x81uy
       encodeRI r 0b010uy
       yield! encodeImm imm 32<rt> |]
  | TwoOperands (OprMem (Some b, s, d, 32<rt>), OprImm imm) ->
    [| yield! encodePrefix arch ins None
       yield! encodeREXPref arch ins None
       Normal 0x81uy
       encodeMI b s d 0b010uy
       yield! encodeSIB ins
       yield! encodeDisp ins
       yield! encodeImm imm 32<rt> |]
  | TwoOperands (OprReg r, OprImm imm) when isReg64 r ->
    no32Arch arch
    [| yield! encodeREXPref arch ins rexW
       Normal 0x81uy
       encodeRI r 0b010uy
       yield! encodeImm imm 32<rt> |]

  // Mem - Imm (Priority 1)
  | TwoOperands (OprMem (Some b, s, d, 64<rt>), OprImm imm) ->
    no32Arch arch;
    [| yield! encodePrefix arch ins None
       yield! encodeREXPref arch ins rexW
       Normal 0x81uy
       encodeMI b s d 0b010uy
       yield! encodeSIB ins
       yield! encodeDisp ins
       yield! encodeImm imm 32<rt> |]

  // Reg - Imm (Priority 0)
  | TwoOperands (OprReg r, OprImm imm) when isReg16 r ->
    [| yield! encodePrefix arch ins oSzPref
       yield! encodeREXPref arch ins None
       Normal 0x83uy
       encodeRI r 0b010uy
       yield! encodeImm imm 8<rt> |]
  | TwoOperands (OprReg r, OprImm imm) when isReg32 r ->
    [| yield! encodeREXPref arch ins None
       Normal 0x83uy
       encodeRI r 0b010uy
       yield! encodeImm imm 8<rt> |]
  | TwoOperands (OprReg r, OprImm imm) when isReg64 r ->
    no32Arch arch
    [| yield! encodeREXPref arch ins rexW
       Normal 0x83uy
       encodeRI r 0b010uy
       yield! encodeImm imm 8<rt> |]

  // Mem - Imm (Priority 0)
  | TwoOperands (OprMem (Some b, s, d, 16<rt>), OprImm imm) ->
    [| yield! encodePrefix arch ins oSzPref
       yield! encodeREXPref arch ins None
       Normal 0x83uy
       encodeMI b s d 0b010uy
       yield! encodeSIB ins
       yield! encodeDisp ins
       yield! encodeImm imm 8<rt> |]
  | TwoOperands (OprMem (Some b, s, d, 32<rt>), OprImm imm) ->
    [| yield! encodePrefix arch ins None
       yield! encodeREXPref arch ins None
       Normal 0x83uy
       encodeMI b s d 0b010uy
       yield! encodeSIB ins
       yield! encodeDisp ins
       yield! encodeImm imm 8<rt> |]
  | TwoOperands (OprMem (Some b, s, d, 64<rt>), OprImm imm) ->
    no32Arch arch
    [| yield! encodePrefix arch ins None
       yield! encodeREXPref arch ins rexW
       Normal 0x83uy
       encodeMI b s d 0b010uy
       yield! encodeSIB ins
       yield! encodeDisp ins
       yield! encodeImm imm 8<rt> |]

  // Mem - Reg
  | TwoOperands (OprMem (Some b, s, d, 8<rt>), OprReg r) when isReg8 r ->
    [| yield! encodePrefix arch ins None
       yield! encodeREXPref arch ins None
       Normal 0x10uy
       encodeMR b s d r
       yield! encodeSIB ins
       yield! encodeDisp ins |]
  | TwoOperands (OprMem (Some b, s, d, 16<rt>), OprReg r) when isReg16 r ->
    [| yield! encodePrefix arch ins oSzPref
       yield! encodeREXPref arch ins None
       Normal 0x11uy
       encodeMR b s d r
       yield! encodeSIB ins
       yield! encodeDisp ins |]
  | TwoOperands (OprMem (Some b, s, d, 32<rt>), OprReg r) when isReg32 r ->
    [| yield! encodePrefix arch ins None
       yield! encodeREXPref arch ins None
       Normal 0x11uy
       encodeMR b s d r
       yield! encodeSIB ins
       yield! encodeDisp ins |]
  | TwoOperands (OprMem (Some b, s, d, 64<rt>), OprReg r) when isReg64 r ->
    no32Arch arch
    [| yield! encodePrefix arch ins None
       yield! encodeREXPref arch ins rexW
       Normal 0x11uy
       encodeMR b s d r
       yield! encodeSIB ins
       yield! encodeDisp ins |]

  // Reg - Reg
  | TwoOperands (OprReg r1, OprReg r2) when isReg8 r1 && isReg8 r2 ->
    [| yield! encodeREXPref arch ins None
       Normal 0x12uy
       encodeRR r1 r2 |]
  | TwoOperands (OprReg r1, OprReg r2) when isReg16 r1 && isReg16 r2 ->
    [| Normal 0x66uy
       yield! encodeREXPref arch ins None
       Normal 0x13uy
       encodeRR r1 r2 |]
  | TwoOperands (OprReg r1, OprReg r2) when isReg32 r1 && isReg32 r2 ->
    [| yield! encodeREXPref arch ins None
       Normal 0x13uy
       encodeRR r1 r2 |]
  | TwoOperands (OprReg r1, OprReg r2) when isReg64 r1 && isReg64 r2 ->
    no32Arch arch
    [| yield! encodeREXPref arch ins rexW
       Normal 0x13uy
       encodeRR r1 r2 |]

  // Reg - Mem
  | TwoOperands (OprReg r, OprMem (Some b, s, d, 8<rt>)) when isReg8 r ->
    [| yield! encodePrefix arch ins None
       yield! encodeREXPref arch ins None
       Normal 0x12uy
       encodeRM b s d r
       yield! encodeSIB ins
       yield! encodeDisp ins |]
  | TwoOperands (OprReg r, OprMem (Some b, s, d, 16<rt>)) when isReg16 r ->
    [| yield! encodePrefix arch ins oSzPref
       yield! encodeREXPref arch ins None
       Normal 0x13uy
       encodeRM b s d r
       yield! encodeSIB ins
       yield! encodeDisp ins |]
  | TwoOperands (OprReg r, OprMem (Some b, s, d, 32<rt>)) when isReg32 r ->
    [| yield! encodePrefix arch ins None
       yield! encodeREXPref arch ins None
       Normal 0x13uy
       encodeRM b s d r
       yield! encodeSIB ins
       yield! encodeDisp ins |]
  | TwoOperands (OprReg r, OprMem (Some b, s, d, 64<rt>)) when isReg64 r ->
    no32Arch arch
    [| yield! encodePrefix arch ins None
       yield! encodeREXPref arch ins rexW
       Normal 0x13uy
       encodeRM b s d r
       yield! encodeSIB ins
       yield! encodeDisp ins |]
  | o -> printfn "%A" o; raise OperandTypeMismatchException

let add arch = function
  | TwoOperands (OprReg Register.AL, OprImm imm) ->
    [| Normal 0x04uy; yield! encodeImm imm 8<rt> |]
  | TwoOperands (OprReg Register.AX, OprImm imm) ->
    [| Normal 0x66uy; Normal 0x05uy; yield! encodeImm imm 16<rt> |]
  | TwoOperands (OprReg Register.EAX, OprImm imm) ->
    [| Normal 0x15uy; yield! encodeImm imm 32<rt> |]
  | TwoOperands (OprReg Register.RAX, OprImm imm) ->
    no32Arch arch
    [| Normal 0x48uy; Normal 0x05uy; yield! encodeImm imm 32<rt> |]
  | TwoOperands (OprReg r, OprImm imm) when isReg8 r ->
    [| Normal 0x80uy; encodeRI r 0b000uy; yield! encodeImm imm 8<rt> |]

  // Check here
  | TwoOperands (OprMem (Some b, s, d, 8<rt>), OprImm imm) ->
    [| Normal 0x80uy; encodeMI b s d 0b010uy; yield! encodeImm imm 8<rt> |]
  | TwoOperands (OprReg r, OprImm imm) when isReg16 r ->
    [| Normal 0x66uy; Normal 0x81uy; encodeRI r 0b010uy
       yield! encodeImm imm 16<rt> |]
  | TwoOperands (OprMem (Some b, s, d, 16<rt>), OprImm imm) ->
    [| Normal 0x66uy; Normal 0x81uy; encodeMI b s d 0b010uy
       yield! encodeImm imm 16<rt> |]
  | TwoOperands (OprReg r, OprImm imm) when isReg32 r ->
    [| Normal 0x81uy; encodeRI r 0b010uy; yield! encodeImm imm 32<rt> |]
  | TwoOperands (OprMem (Some b, s, d, 32<rt>), OprImm imm) ->
    [| Normal 0x81uy; encodeMI b s d 0b010uy; yield! encodeImm imm 32<rt> |]
  | TwoOperands (OprReg r, OprImm imm) when isReg64 r ->
    no32Arch arch
    [| Normal 0x48uy; Normal 0x81uy; encodeRI r 0b010uy
       yield! encodeImm imm 32<rt> |]
  | TwoOperands (OprMem (Some b, s, d, 64<rt>), OprImm imm) ->
    no32Arch arch;
    [| Normal 0x48uy; Normal 0x81uy; encodeMI b s d 0b010uy
       yield! encodeImm imm 32<rt> |]
  | TwoOperands (OprReg r, OprImm imm) when isReg16 r ->
    [| Normal 0x66uy; Normal 0x83uy; encodeRI r 0b010uy
       yield! encodeImm imm 8<rt> |]
  | TwoOperands (OprReg r, OprImm imm) when isReg32 r ->
    [| Normal 0x83uy; encodeRI r 0b010uy; yield! encodeImm imm 8<rt> |]
  | TwoOperands (OprReg r, OprImm imm) when isReg64 r ->
    no32Arch arch
    [| Normal 0x48uy; Normal 0x83uy; encodeRI r 0b010uy
       yield! encodeImm imm 8<rt> |]
  | TwoOperands (OprMem (Some b, s, d, 16<rt>), OprImm imm) ->
    [| Normal 0x66uy; Normal 0x83uy; encodeMI b s d 0b010uy
       yield! encodeImm imm 8<rt> |]
  | TwoOperands (OprMem (Some b, s, d, 32<rt>), OprImm imm) ->
    [| Normal 0x83uy; encodeMI b s d 0b010uy; yield! encodeImm imm 8<rt> |]
  | TwoOperands (OprMem (Some b, s, d, 64<rt>), OprImm imm) ->
    no32Arch arch
    [| Normal 0x48uy; Normal 0x83uy; encodeMI b s d 0b010uy
       yield! encodeImm imm 8<rt> |]
  | TwoOperands (OprMem (Some b, s, d, 8<rt>), OprReg r) when isReg8 r ->
    [| Normal 0x10uy; encodeMR b s d r |]
  | TwoOperands (OprMem (Some b, s, d, 16<rt>), OprReg r) when isReg16 r ->
    [| Normal 0x66uy; Normal 0x11uy; encodeMR b s d r |]
  | TwoOperands (OprMem (Some b, s, d, 32<rt>), OprReg r) when isReg32 r ->
    [| Normal 0x11uy; encodeMR b s d r |]
  | TwoOperands (OprMem (Some b, s, d, 64<rt>), OprReg r) when isReg64 r ->
    no32Arch arch
    [| Normal 0x48uy; Normal 0x11uy; encodeMR b s d r |]
  | TwoOperands (OprReg r1, OprReg r2) when isReg8 r1 && isReg8 r2 ->
    [| Normal 0x12uy; encodeRR r1 r2 |]
  | TwoOperands (OprReg r1, OprReg r2) when isReg16 r1 && isReg16 r2 ->
    [| Normal 0x66uy; Normal 0x13uy; encodeRR r1 r2 |]
  | TwoOperands (OprReg r1, OprReg r2) when isReg32 r1 && isReg32 r2 ->
    [| Normal 0x13uy; encodeRR r1 r2 |]
  | TwoOperands (OprReg r1, OprReg r2) when isReg64 r1 && isReg64 r2 ->
    no32Arch arch
    [| Normal 0x48uy; Normal 0x13uy; encodeRR r1 r2 |]
  | TwoOperands (OprReg r, OprMem (Some b, s, d, 8<rt>)) when isReg8 r ->
    [| Normal 0x12uy; encodeRM b s d r |]
  | TwoOperands (OprReg r, OprMem (Some b, s, d, 16<rt>)) when isReg16 r ->
    [| Normal 0x66uy; Normal 0x13uy; encodeRM b s d r |]
  | TwoOperands (OprReg r, OprMem (Some b, s, d, 32<rt>)) when isReg32 r ->
    [| Normal 0x13uy; encodeRM b s d r |]
  | TwoOperands (OprReg r, OprMem (Some b, s, d, 64<rt>)) when isReg64 r ->
    no32Arch arch
    [| Normal 0x48uy; Normal 0x13uy; encodeRM b s d r |]
  | _ -> raise OperandTypeMismatchException

// vim: set tw=80 sts=2 sw=2:
