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

module B2R2.Assembler.Intel.EncodingType

open B2R2
open B2R2.FrontEnd.Intel

type RK = Register.Kind

type EncodingType =
  (** One Operand **)
  | EnR8
  | EnR16
  | EnR32
  | EnR64
  | EnM8
  | EnM16
  | EnM32
  | EnM64
  | EnM128
  | EnLbl
  | EnI8
  (** Two Operands **)
  (* Register - Register *)
  | EnR8R8
  | EnR8R16 // Opcode.IN
  | EnR16R8
  | EnR16R16
  | EnR16R32 // Opcode.OUT
  | EnR32R32
  | EnR64R16
  | EnR64R32 // Opcode.LSL
  | EnR64R64
  | EnR32R8
  | EnR32R16
  | EnR64R8
  | EnR32Mx
  | EnR64Mx
  | EnR32Xm
  | EnR64Xm
  | EnMxR32
  | EnMxR64
  | EnMxMx
  | EnMxXm
  | EnXmR32
  | EnXmR64
  | EnXmMx
  | EnXmXm
  | EnYmYm
  (* Register - Memory *)
  | EnR8M8
  | EnR16M8
  | EnR16M16
  | EnR32M32
  | EnR64M16
  | EnR64M64
  | EnR32M8
  | EnR32M16
  | EnR64M8
  | EnR64M32
  | EnMxM32
  | EnMxM64
  | EnMxM128
  | EnXmM16
  | EnXmM32
  | EnXmM64
  | EnXmM128
  | EnYmM256
  (* Memory - Register *)
  | EnM8R8
  | EnM16R16
  | EnM32R32
  | EnM64R64
  | EnM32Mx
  | EnM64Mx
  | EnM32Xm
  | EnM64Xm
  | EnM128Xm
  | EnM256Ym
  (* Regiser - Immediate *)
  | EnR8I8
  | EnR16I16
  | EnR32I32
  | EnR64I64
  | EnR16I8
  | EnR32I8
  | EnR64I8
  | EnMxI8
  | EnXmI8
  (* Memory - Immediate *)
  | EnM8I8
  | EnM16I16
  | EnM32I32
  | EnM64I64
  | EnM16I8
  | EnM32I8
  | EnM64I8
  (* Special Case *)
  | EnI8AL
  | EnI8AX
  | EnI8EAX
  | EnI16I8
  | EnSgRM16
  | EnSgRM64
  | EnRM16Sg
  | EnRM64Sg
  | EnBnBM64
  | EnBnBM128
  | EnBM64Bn
  | EnBM128Bn
  (** Three Operands **)
  (* Register - Register - Register/Memory *)
  | EnR32R32RM32 of Register
  | EnR64R64RM64 of Register
  (* Register - Register - Register *)
  | EnXmXmR32 of Register
  | EnXmXmR64 of Register
  | EnXmXmXm of Register
  | EnYmYmXm of Register
  | EnYmYmYm of Register
  (* Register - Register - Memory *)
  | EnXmXmM32 of Register
  | EnXmXmM64 of Register
  | EnXmXmM128 of Register
  | EnYmYmM128 of Register
  | EnYmYmM256 of Register
  (* Register - Register - Immediate *)
  | EnR32MxI8
  | EnR64MxI8
  | EnR32XmI8
  | EnR64XmI8
  | EnMxR32I8
  | EnXmR32I8
  | EnXmR64I8
  | EnXmXmI8 of Register // Register uses only VEX
  | EnYmYmI8 of Register
  (* Register - Memory - Immediate *)
  | EnMxM16I8
  | EnXmM8I8
  | EnXmM16I8
  | EnXmM32I8
  | EnXmM64I8
  | EnXmM128I8
  (* Memory - Register - Immediate *)
  | EnM16XmI8
  (* Register - Register/Memory - Immediate *)
  | EnR16RM16I8
  | EnR16RM16I16
  | EnR32RM32I8
  | EnR32RM32I32
  | EnR64RM64I8
  | EnR64RM64I32
  | EnMxMM64I8
  (** Four Operands **)
  (* Register - Register - Resgier - Immediate *)
  | EnXmXmR32I8 of Register
  (* Register - Register - Memory - Immediate *)
  | EnXmXmM8I8 of Register
  | EnXmXmM16I8 of Register
  (* Register - Register - Resgier/Memory - Immediate *)
  | EnXmXmXM128I8 of Register
  | EnYmYmYM256I8 of Register

let private getOneOprRegEncType = function
  | 8<rt> -> EnR8
  | 16<rt> -> EnR16
  | 32<rt> -> EnR32
  | 64<rt> -> EnR64
  | _ -> Utils.impossible ()

let private getOneOprMemEncType = function
  | 8<rt> -> EnM8
  | 16<rt> -> EnM16
  | 32<rt> -> EnM32
  | 64<rt> -> EnM64
  | 128<rt> -> EnM128
  | _ -> Utils.impossible ()

let private getOneOprEncType _op = function
  | OprReg reg -> Register.toRegType reg |> getOneOprRegEncType
  | OprMem (Some _, _, _, sz) -> getOneOprMemEncType sz
  | OprImm _ -> EnI8
  | GoToLabel _ -> EnLbl
  | opr -> printfn "%A" opr; Utils.impossible ()

let regKindAndSize reg = struct (Register.getKind reg, Register.toRegType reg)

let private getRegRegEncType arch r1 r2 =
  match regKindAndSize r1, regKindAndSize r2 with
  | (RK.Segment, 16<rt>), (RK.GP, 16<rt>) -> EnSgRM16
  | (RK.Segment, 16<rt>), (RK.GP, 64<rt>) -> EnSgRM64
  | (RK.GP, 16<rt>), (RK.Segment, 16<rt>) -> EnRM16Sg
  | (RK.GP, 64<rt>), (RK.Segment, 16<rt>) -> EnRM64Sg
  | (RK.GP, 8<rt>), (RK.GP, 8<rt>) -> EnR8R8
  | (RK.GP, 16<rt>), (RK.GP, 16<rt>) -> EnR16R16
  | (RK.GP, 32<rt>), (RK.GP, 32<rt>) -> EnR32R32
  | (RK.GP, 64<rt>), (RK.GP, 64<rt>) -> EnR64R64
  | (RK.GP, 8<rt>), (RK.GP, 16<rt>) -> EnR8R16
  | (RK.GP, 16<rt>), (RK.GP, 8<rt>) -> EnR16R8
  | (RK.GP, 16<rt>), (RK.GP, 32<rt>) -> EnR16R32
  | (RK.GP, 32<rt>), (RK.GP, 8<rt>) -> EnR32R8
  | (RK.GP, 32<rt>), (RK.GP, 16<rt>) -> EnR32R16
  | (RK.GP, 64<rt>), (RK.GP, 8<rt>) -> EnR64R8
  | (RK.GP, 64<rt>), (RK.GP, 16<rt>) -> EnR64R16
  | (RK.GP, 64<rt>), (RK.GP, 32<rt>) -> EnR64R32
  | (RK.GP, 32<rt>), (RK.MMX, _) -> EnR32Mx
  | (RK.GP, 32<rt>), (RK.XMM, _) -> EnR32Xm
  | (RK.GP, 64<rt>), (RK.MMX, _) -> EnR64Mx
  | (RK.GP, 64<rt>), (RK.XMM, _) -> EnR64Xm
  | (RK.MMX, _), (RK.GP, 32<rt>) -> EnMxR32
  | (RK.MMX, _), (RK.GP, 64<rt>) -> EnMxR64
  | (RK.MMX, _), (RK.MMX, _) -> EnMxMx
  | (RK.MMX, _), (RK.XMM, _) -> EnMxXm
  | (RK.XMM, _), (RK.GP, 32<rt>) -> EnXmR32
  | (RK.XMM, _), (RK.GP, 64<rt>) -> EnXmR64
  | (RK.XMM, _), (RK.MMX, _) -> EnXmMx
  | (RK.XMM, _), (RK.XMM, _) -> EnXmXm
  | (RK.YMM, 256<rt>), (RK.YMM, 256<rt>) -> EnYmYm
  | (RK.Bound, 128<rt>), (RK.Bound, 128<rt>) ->
    if arch = Arch.IntelX86 then EnBnBM64 else EnBnBM128
  | _ -> Utils.impossible ()

let private getRegMemEncType r sz =
  match regKindAndSize r, sz with
  | (RK.Segment, 16<rt>), 16<rt> -> EnSgRM16
  | (RK.Segment, 16<rt>), 64<rt> -> EnSgRM64
  | (RK.GP, 8<rt>), 8<rt> -> EnR8M8
  | (RK.GP, 16<rt>), 8<rt> -> EnR16M8
  | (RK.GP, 16<rt>), 16<rt> -> EnR16M16
  | (RK.GP, 32<rt>), 8<rt> -> EnR32M8
  | (RK.GP, 32<rt>), 16<rt> -> EnR32M16
  | (RK.GP, 32<rt>), 32<rt> -> EnR32M32
  | (RK.GP, 64<rt>), 8<rt> -> EnR64M8
  | (RK.GP, 64<rt>), 16<rt> -> EnR64M16
  | (RK.GP, 64<rt>), 32<rt> -> EnR64M32
  | (RK.GP, 64<rt>), 64<rt> -> EnR64M64
  | (RK.MMX, _), 32<rt> -> EnMxM32 // check
  | (RK.MMX, _), 64<rt> -> EnMxM64 // check
  | (RK.MMX, _), 128<rt> -> EnMxM128
  | (RK.XMM, _), 16<rt> -> EnXmM16
  | (RK.XMM, _), 32<rt> -> EnXmM32
  | (RK.XMM, _), 64<rt> -> EnXmM64
  | (RK.XMM, _), 128<rt> -> EnXmM128
  | (RK.YMM, _), 256<rt> -> EnYmM256
  | (RK.Bound, _), 64<rt> -> EnBnBM64
  | (RK.Bound, _), 128<rt> -> EnBnBM128
  | _ -> Utils.impossible ()

let private getMemRegEncType sz r =
  match sz, regKindAndSize r with
  | 16<rt>, (RK.Segment, _) -> EnRM16Sg
  | 64<rt>, (RK.Segment, _) -> EnRM64Sg
  | 32<rt>, (RK.MMX, _) -> EnM32Mx
  | 64<rt>, (RK.MMX, _) -> EnM64Mx
  | 32<rt>, (RK.XMM, _) -> EnM32Xm
  | 64<rt>, (RK.XMM, _) -> EnM64Xm
  | 128<rt>, (RK.XMM, _) -> EnM128Xm
  | 256<rt>, (RK.YMM, _) -> EnM256Ym
  | 8<rt>, (RK.GP, 8<rt>) -> EnM8R8
  | 16<rt>, (RK.GP, 16<rt>) -> EnM16R16
  | 32<rt>, (RK.GP, 32<rt>) -> EnM32R32
  | 64<rt>, (RK.GP, 64<rt>) -> EnM64R64
  | 64<rt>, (RK.Bound, _) -> EnBM64Bn
  | 128<rt>, (RK.Bound, _) -> EnBM128Bn
  | _ -> Utils.impossible ()

let private getMemImmEncType opcode sz =
  match opcode, sz with
  | _, 8<rt> -> EnM8I8
  | Opcode.BT, 16<rt> -> EnM16I8
  | _, 16<rt> -> EnM16I16
  | Opcode.BT, 32<rt> -> EnM32I8
  | _, 32<rt> -> EnM32I32
  | Opcode.BT, 64<rt> -> EnM64I8
  | _, 64<rt> -> EnM64I64
  | _ -> Utils.impossible ()

let private getRegImmEncType opcode sz =
  match opcode, sz with
  | _, 8<rt> -> EnR8I8
  | Opcode.BT, 16<rt> | Opcode.IN, 16<rt> -> EnR16I8
  | _, 16<rt> -> EnR16I16
  | Opcode.BT, 32<rt> | Opcode.IN, 32<rt> -> EnR32I8
  | _, 32<rt> -> EnR32I32
  | Opcode.BT, 64<rt> -> EnR64I8
  | Opcode.PSLLD, 64<rt> -> EnMxI8
  | _, 64<rt> -> EnR64I64
  | _, 128<rt> -> EnXmI8
  | _ -> Utils.impossible ()

let private getTwoOprEncType isa op opr1 opr2 =
  match opr1, opr2 with
  | OprReg r1, OprReg r2 -> getRegRegEncType isa.Arch r1 r2
  | OprReg r, OprMem (_, _, _, sz) -> getRegMemEncType r sz
  | OprMem (_, _, _, sz), OprReg r -> getMemRegEncType sz r
  | OprMem (_, _, _, sz), OprImm _ -> getMemImmEncType op sz
  | OprReg r, OprImm _ -> getRegImmEncType op (Register.toRegType r)
  | OprImm _, OprImm _ -> EnI16I8 (* Opcode.ENTER *)
  | OprImm _, OprReg Register.AL -> EnI8AL (* Opcode.OUT *)
  | OprImm _, OprReg Register.AX -> EnI8AX (* Opcode.OUT *)
  | OprImm _, OprReg Register.EAX -> EnI8EAX (* Opcode.OUT *)
  | opr -> printfn "%A" opr; Utils.impossible ()

let private getRegRegRegEncType r1 r2 r3 =
  match regKindAndSize r1, regKindAndSize r2, regKindAndSize r3 with
  | (RK.GP, 32<rt>), (RK.GP, 32<rt>), (RK.GP, 32<rt>) ->
    EnR32R32RM32 r2
  | (RK.GP, 64<rt>), (RK.GP, 64<rt>), (RK.GP, 64<rt>) ->
    EnR64R64RM64 r2
  | (RK.XMM, _), (RK.XMM, _), (RK.XMM, _) -> EnXmXmXm r2
  | (RK.YMM, _), (RK.YMM, _), (RK.XMM, _) -> EnYmYmXm r2
  | (RK.YMM, _), (RK.YMM, _), (RK.YMM, _) -> EnYmYmYm r2
  | (RK.XMM, _), (RK.XMM, _), (RK.GP, 32<rt>) -> EnXmXmR32 r2
  | (RK.XMM, _), (RK.XMM, _), (RK.GP, 64<rt>) -> EnXmXmR64 r2
  | _ -> Utils.impossible ()

let private getRegRegMemEncType r1 r2 sz =
  match regKindAndSize r1, regKindAndSize r2, sz with
  | (RK.GP, 32<rt>), (RK.GP, 32<rt>), 32<rt> -> EnR32R32RM32 r2
  | (RK.GP, 64<rt>), (RK.GP, 64<rt>), 64<rt> -> EnR64R64RM64 r2
  | (RK.XMM, _), (RK.XMM, _), 32<rt> -> EnXmXmM32 r2
  | (RK.XMM, _), (RK.XMM, _), 64<rt> -> EnXmXmM64 r2
  | (RK.XMM, _), (RK.XMM, _), 128<rt> -> EnXmXmM128 r2
  | (RK.YMM, _), (RK.YMM, _), 128<rt> -> EnYmYmM128 r2
  | (RK.YMM, _), (RK.YMM, _), 256<rt> -> EnYmYmM256 r2
  | _ -> Utils.impossible ()

let private getRegRegImmEncType r1 r2 =
  match regKindAndSize r1, regKindAndSize r2 with
  | (RK.GP, 16<rt>), (RK.GP, 16<rt>) -> EnR16RM16I16
  | (RK.GP, 32<rt>), (RK.GP, 32<rt>) -> EnR32RM32I32
  | (RK.GP, 64<rt>), (RK.GP, 64<rt>) -> EnR64RM64I32
  | (RK.GP, 32<rt>), (RK.MMX, _) -> EnR32MxI8
  | (RK.GP, 32<rt>), (RK.XMM, _) -> EnR32XmI8
  | (RK.GP, 64<rt>), (RK.MMX, _) -> EnR64MxI8
  | (RK.GP, 64<rt>), (RK.XMM, _) -> EnR64XmI8
  | (RK.MMX, _), (RK.GP, 32<rt>) -> EnMxR32I8
  | (RK.MMX, _), (RK.MMX, _) -> EnMxMM64I8
  | (RK.XMM, _), (RK.GP, 32<rt>) -> EnXmR32I8
  | (RK.XMM, _), (RK.GP, 64<rt>) -> EnXmR64I8
  | (RK.XMM, _), (RK.XMM, _) -> EnXmXmI8 r1
  | (RK.YMM, _), (RK.YMM, _) -> EnYmYmI8 r1
  | _ -> Utils.impossible ()

let private getRegMemImmEncType r sz =
  match regKindAndSize r, sz with
  | (RK.GP, 16<rt>), 16<rt> -> EnR16RM16I16
  | (RK.GP, 32<rt>), 32<rt> -> EnR32RM32I32
  | (RK.GP, 64<rt>), 64<rt> -> EnR64RM64I32
  | (RK.MMX, _), 16<rt> -> EnMxM16I8
  | (RK.MMX, _), 64<rt> -> EnMxMM64I8
  | (RK.XMM, _), 8<rt> -> EnXmM8I8
  | (RK.XMM, _), 16<rt> -> EnXmM16I8
  | (RK.XMM, _), 32<rt> -> EnXmM32I8
  | (RK.XMM, _), 64<rt> -> EnXmM64I8
  | (RK.XMM, _), 128<rt> -> EnXmM128I8
  | _ -> Utils.impossible ()

let private getMemRegImmEncType sz r =
  match sz, regKindAndSize r with
  | 16<rt>, (RK.XMM, _) -> EnM16XmI8
  | _ -> Utils.impossible ()

let private getThreeOprEncType opr1 opr2 opr3 =
  match opr1, opr2, opr3 with
  | OprReg r1, OprReg r2, OprReg r3 -> getRegRegRegEncType r1 r2 r3
  | OprReg r1, OprReg r2, OprMem (_, _, _, sz) -> getRegRegMemEncType r1 r2 sz
  | OprReg r1, OprReg r2, OprImm _ -> getRegRegImmEncType r1 r2
  | OprReg r, OprMem (_, _, _, sz), OprImm _ -> getRegMemImmEncType r sz
  | OprMem (_, _, _, sz), OprReg r, OprImm _ -> getMemRegImmEncType sz r
  | opr -> printfn "%A" opr; Utils.impossible ()

let private getRegRegRegImmEncType r1 r2 r3 =
  match regKindAndSize r1, regKindAndSize r2, regKindAndSize r3 with
  | (RK.XMM, _), (RK.XMM, _), (RK.GP, 32<rt>) -> EnXmXmR32I8 r2
  | (RK.XMM, _), (RK.XMM, _), (RK.XMM, _) -> EnXmXmXM128I8 r2
  | (RK.YMM, _), (RK.YMM, _), (RK.YMM, _) -> EnYmYmYM256I8 r2
  | _ -> Utils.impossible ()

let private getRegRegMemImmEncType r1 r2 sz =
  match regKindAndSize r1, regKindAndSize r2, sz with
  | (RK.XMM, _), (RK.XMM, _), 8<rt> -> EnXmXmM8I8 r2
  | (RK.XMM, _), (RK.XMM, _), 16<rt> -> EnXmXmM16I8 r2
  | (RK.XMM, _), (RK.XMM, _), 128<rt> -> EnXmXmXM128I8 r2
  | (RK.YMM, _), (RK.YMM, _), 256<rt> -> EnYmYmYM256I8 r2
  | _ -> Utils.impossible ()

let private getFourOprEncType opr1 opr2 opr3 opr4 =
  match opr1, opr2, opr3, opr4 with
  | OprReg r1, OprReg r2, OprReg r3, OprImm _ -> getRegRegRegImmEncType r1 r2 r3
  | OprReg r1, OprReg r2, OprMem (_, _, _, sz), OprImm _ ->
    getRegRegMemImmEncType r1 r2 sz
  | opr -> printfn "%A" opr; Utils.impossible ()

let compute isa op = function
  | OneOperand opr -> getOneOprEncType op opr
  | TwoOperands (opr1, opr2) -> getTwoOprEncType isa op opr1 opr2
  | ThreeOperands (opr1, opr2, opr3) -> getThreeOprEncType opr1 opr2 opr3
  | FourOperands (o1, o2, o3, o4) -> getFourOprEncType o1 o2 o3 o4
  | opr -> printfn "%A" opr; Utils.impossible ()

// vim: set tw=80 sts=2 sw=2:
