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

module B2R2.Assembler.Intel.FixInsInfo

open System
open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.Intel

// FixMe
let vexInfoFromOpcode opcode: VEXInfo option = None

let asmError () =
  let trace = Diagnostics.StackTrace (true)
  printfn "ASSEMBLY ERROR: THIS IS OPERAND TYPE MISMATCH."
  trace.ToString () |> printfn "%s"
  raise <| InvalidOperationException ()

type LabeledByte =
  | Normal of byte
  | Label

type EncodedByteCode = {
  Prefix        : LabeledByte []
  REXPrefix     : LabeledByte [] // 1 byte option
  Opcode        : LabeledByte []
  ModRM         : LabeledByte [] // 1 byte option
  SIB           : LabeledByte [] // 1 byte option
  Displacement  : LabeledByte []
  Immediate     : LabeledByte []
}

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

let getRegOrMem isReg eReg eMem = if isReg then eReg else eMem

// FIMXE: Refactoring
let getEncRegMemImm opcode sz isReg =
  match opcode, sz with
  | _, 8<rt> -> if isReg then EnR8I8 else EnM8I8
  | Opcode.BT, 16<rt> -> if isReg then EnR16I8 else EnM16I8
  | Opcode.IN, 16<rt> -> EnR16I8
  | _, 16<rt> -> if isReg then EnR16I16 else EnM16I16
  | Opcode.BT, 32<rt> -> if isReg then EnR32I8 else EnM32I8
  | Opcode.IN, 32<rt> -> EnR32I8
  | _, 32<rt> -> if isReg then EnR32I32 else EnM32I32
  | Opcode.BT, 64<rt> -> if isReg then EnR64I8 else EnM64I8
  | Opcode.PSLLD, 64<rt> -> EnMxI8
  | _, 64<rt> -> if isReg then EnR64I64 else EnM64I64
  | _, 128<rt> -> EnXmI8
  | _ -> Utils.impossible ()

let getEncRegMem isReg = function
  | 8<rt> -> if isReg then EnR8 else EnM8
  | 16<rt> -> if isReg then EnR16 else EnM16
  | 32<rt> -> if isReg then EnR32 else EnM32
  | 64<rt> -> if isReg then EnR64 else EnM64
  | 128<rt> -> EnM128
  | _ -> Utils.futureFeature ()

let getOneOprEncType _op = function
  | OprReg reg -> getEncRegMem true (Register.toRegType reg)
  | OprMem (Some _, _, _, sz) -> getEncRegMem false sz
  | OprImm _ -> EnI8
  | GoToLabel _ -> EnLbl
  | opr -> printfn "%A" opr; Utils.futureFeature ()

let getKindAndSize reg = struct (Register.getKind reg, Register.toRegType reg)

type internal RegKnd = Register.Kind

let getTwoOprEncType isa op opr1 opr2 =
  match opr1, opr2 with
  | OprReg r1, OprReg r2 ->
    match getKindAndSize r1, getKindAndSize r2 with
    | (RegKnd.Segment, 16<rt>), (RegKnd.GP, 16<rt>) -> EnSgRM16
    | (RegKnd.Segment, 16<rt>), (RegKnd.GP, 64<rt>) -> EnSgRM64
    | (RegKnd.GP, 16<rt>), (RegKnd.Segment, 16<rt>) -> EnRM16Sg
    | (RegKnd.GP, 64<rt>), (RegKnd.Segment, 16<rt>) -> EnRM64Sg
    | (RegKnd.GP, 8<rt>), (RegKnd.GP, 8<rt>) -> EnR8R8
    | (RegKnd.GP, 16<rt>), (RegKnd.GP, 16<rt>) -> EnR16R16
    | (RegKnd.GP, 32<rt>), (RegKnd.GP, 32<rt>) -> EnR32R32
    | (RegKnd.GP, 64<rt>), (RegKnd.GP, 64<rt>) -> EnR64R64
    | (RegKnd.GP, 8<rt>), (RegKnd.GP, 16<rt>) -> EnR8R16
    | (RegKnd.GP, 16<rt>), (RegKnd.GP, 8<rt>) -> EnR16R8
    | (RegKnd.GP, 16<rt>), (RegKnd.GP, 32<rt>) -> EnR16R32
    | (RegKnd.GP, 32<rt>), (RegKnd.GP, 8<rt>) -> EnR32R8
    | (RegKnd.GP, 32<rt>), (RegKnd.GP, 16<rt>) -> EnR32R16
    | (RegKnd.GP, 64<rt>), (RegKnd.GP, 8<rt>) -> EnR64R8
    | (RegKnd.GP, 64<rt>), (RegKnd.GP, 16<rt>) -> EnR64R16
    | (RegKnd.GP, 64<rt>), (RegKnd.GP, 32<rt>) -> EnR64R32
    | (RegKnd.GP, 32<rt>), (RegKnd.MMX, _) -> EnR32Mx
    | (RegKnd.GP, 32<rt>), (RegKnd.XMM, _) -> EnR32Xm
    | (RegKnd.GP, 64<rt>), (RegKnd.MMX, _) -> EnR64Mx
    | (RegKnd.GP, 64<rt>), (RegKnd.XMM, _) -> EnR64Xm
    | (RegKnd.MMX, _), (RegKnd.GP, 32<rt>) -> EnMxR32
    | (RegKnd.MMX, _), (RegKnd.GP, 64<rt>) -> EnMxR64
    | (RegKnd.MMX, _), (RegKnd.MMX, _) -> EnMxMx
    | (RegKnd.MMX, _), (RegKnd.XMM, _) -> EnMxXm
    | (RegKnd.XMM, _), (RegKnd.GP, 32<rt>) -> EnXmR32
    | (RegKnd.XMM, _), (RegKnd.GP, 64<rt>) -> EnXmR64
    | (RegKnd.XMM, _), (RegKnd.MMX, _) -> EnXmMx
    | (RegKnd.XMM, _), (RegKnd.XMM, _) -> EnXmXm
    | (RegKnd.YMM, 256<rt>), (RegKnd.YMM, 256<rt>) -> EnYmYm
    | (RegKnd.Bound, 128<rt>), (RegKnd.Bound, 128<rt>)
      when isa.Arch = Arch.IntelX86 -> EnBnBM64
    | (RegKnd.Bound, 128<rt>), (RegKnd.Bound, 128<rt>)
      when isa.Arch = Arch.IntelX64 -> EnBnBM128
    | _ -> Utils.futureFeature ()
  | OprReg r, OprMem (_, _, _, sz) ->
    match getKindAndSize r, sz with
    | (RegKnd.Segment, 16<rt>), 16<rt> -> EnSgRM16
    | (RegKnd.Segment, 16<rt>), 64<rt> -> EnSgRM64
    | (RegKnd.GP, 8<rt>), 8<rt> -> EnR8M8
    | (RegKnd.GP, 16<rt>), 8<rt> -> EnR16M8
    | (RegKnd.GP, 16<rt>), 16<rt> -> EnR16M16
    | (RegKnd.GP, 32<rt>), 8<rt> -> EnR32M8
    | (RegKnd.GP, 32<rt>), 16<rt> -> EnR32M16
    | (RegKnd.GP, 32<rt>), 32<rt> -> EnR32M32
    | (RegKnd.GP, 64<rt>), 8<rt> -> EnR64M8
    | (RegKnd.GP, 64<rt>), 16<rt> -> EnR64M16
    | (RegKnd.GP, 64<rt>), 32<rt> -> EnR64M32
    | (RegKnd.GP, 64<rt>), 64<rt> -> EnR64M64
    | (RegKnd.MMX, _), 32<rt> -> EnMxM32 // check
    | (RegKnd.MMX, _), 64<rt> -> EnMxM64 // check
    | (RegKnd.MMX, _), 128<rt> -> EnMxM128
    | (RegKnd.XMM, _), 16<rt> -> EnXmM16
    | (RegKnd.XMM, _), 32<rt> -> EnXmM32
    | (RegKnd.XMM, _), 64<rt> -> EnXmM64
    | (RegKnd.XMM, _), 128<rt> -> EnXmM128
    | (RegKnd.YMM, _), 256<rt> -> EnYmM256
    | (RegKnd.Bound, _), 64<rt> -> EnBnBM64
    | (RegKnd.Bound, _), 128<rt> -> EnBnBM128
    | _ -> Utils.futureFeature ()
  | OprMem (_, _, _, sz), OprReg r ->
    match sz, getKindAndSize r with
    | 16<rt>, (RegKnd.Segment, _) -> EnRM16Sg
    | 64<rt>, (RegKnd.Segment, _) -> EnRM64Sg
    | 32<rt>, (RegKnd.MMX, _) -> EnM32Mx
    | 64<rt>, (RegKnd.MMX, _) -> EnM64Mx
    | 32<rt>, (RegKnd.XMM, _) -> EnM32Xm
    | 64<rt>, (RegKnd.XMM, _) -> EnM64Xm
    | 128<rt>, (RegKnd.XMM, _) -> EnM128Xm
    | 256<rt>, (RegKnd.YMM, _) -> EnM256Ym
    | 8<rt>, (RegKnd.GP, 8<rt>) -> EnM8R8
    | 16<rt>, (RegKnd.GP, 16<rt>) -> EnM16R16
    | 32<rt>, (RegKnd.GP, 32<rt>) -> EnM32R32
    | 64<rt>, (RegKnd.GP, 64<rt>) -> EnM64R64
    | 64<rt>, (RegKnd.Bound, _) -> EnBM64Bn
    | 128<rt>, (RegKnd.Bound, _) -> EnBM128Bn
    | _ -> Utils.futureFeature ()
  | OprMem (_, _, _, sz), OprImm _ -> getEncRegMemImm op sz false
  | OprReg r, OprImm _ -> getEncRegMemImm op (Register.toRegType r) true
  | OprImm _, OprImm _ -> EnI16I8 // Opcode.ENTER
  | OprImm _, OprReg Register.AL -> EnI8AL // Opcode.OUT
  | OprImm _, OprReg Register.AX -> EnI8AX // Opcode.OUT
  | OprImm _, OprReg Register.EAX -> EnI8EAX // Opcode.OUT
  | opr -> printfn "%A" opr; Utils.futureFeature ()

let getThreeOprEncType opr1 opr2 opr3 =
  match opr1, opr2, opr3 with
  | OprReg r1, OprReg r2, OprReg r3 ->
    match getKindAndSize r1, getKindAndSize r2, getKindAndSize r3 with
    | (RegKnd.GP, 32<rt>), (RegKnd.GP, 32<rt>),
      (RegKnd.GP, 32<rt>) -> EnR32R32RM32 r2
    | (RegKnd.GP, 64<rt>), (RegKnd.GP, 64<rt>),
      (RegKnd.GP, 64<rt>) -> EnR64R64RM64 r2
    | (RegKnd.XMM, _), (RegKnd.XMM, _), (RegKnd.XMM, _) -> EnXmXmXm r2
    | (RegKnd.YMM, _), (RegKnd.YMM, _), (RegKnd.XMM, _) -> EnYmYmXm r2
    | (RegKnd.YMM, _), (RegKnd.YMM, _), (RegKnd.YMM, _) -> EnYmYmYm r2
    | (RegKnd.XMM, _), (RegKnd.XMM, _), (RegKnd.GP, 32<rt>) -> EnXmXmR32 r2
    | (RegKnd.XMM, _), (RegKnd.XMM, _), (RegKnd.GP, 64<rt>) -> EnXmXmR64 r2
    | _ -> Utils.futureFeature ()
  | OprReg r1, OprReg r2, OprMem (_, _, _, sz) ->
    match getKindAndSize r1, getKindAndSize r2, sz with
    | (RegKnd.GP, 32<rt>), (RegKnd.GP, 32<rt>), 32<rt> -> EnR32R32RM32 r2
    | (RegKnd.GP, 64<rt>), (RegKnd.GP, 64<rt>), 64<rt> -> EnR64R64RM64 r2
    | (RegKnd.XMM, _), (RegKnd.XMM, _), 32<rt> -> EnXmXmM32 r2
    | (RegKnd.XMM, _), (RegKnd.XMM, _), 64<rt> -> EnXmXmM64 r2
    | (RegKnd.XMM, _), (RegKnd.XMM, _), 128<rt> -> EnXmXmM128 r2
    | (RegKnd.YMM, _), (RegKnd.YMM, _), 128<rt> -> EnYmYmM128 r2
    | (RegKnd.YMM, _), (RegKnd.YMM, _), 256<rt> -> EnYmYmM256 r2
    | _ -> Utils.futureFeature ()
  | OprReg r1, OprReg r2, OprImm _ ->
    match getKindAndSize r1, getKindAndSize r2 with
    | (RegKnd.GP, 16<rt>), (RegKnd.GP, 16<rt>) -> EnR16RM16I16
    | (RegKnd.GP, 32<rt>), (RegKnd.GP, 32<rt>) -> EnR32RM32I32
    | (RegKnd.GP, 64<rt>), (RegKnd.GP, 64<rt>) -> EnR64RM64I32
    | (RegKnd.GP, 32<rt>), (RegKnd.MMX, _) -> EnR32MxI8
    | (RegKnd.GP, 32<rt>), (RegKnd.XMM, _) -> EnR32XmI8
    | (RegKnd.GP, 64<rt>), (RegKnd.MMX, _) -> EnR64MxI8
    | (RegKnd.GP, 64<rt>), (RegKnd.XMM, _) -> EnR64XmI8
    | (RegKnd.MMX, _), (RegKnd.GP, 32<rt>) -> EnMxR32I8
    | (RegKnd.MMX, _), (RegKnd.MMX, _) -> EnMxMM64I8
    | (RegKnd.XMM, _), (RegKnd.GP, 32<rt>) -> EnXmR32I8
    | (RegKnd.XMM, _), (RegKnd.GP, 64<rt>) -> EnXmR64I8
    | (RegKnd.XMM, _), (RegKnd.XMM, _) -> EnXmXmI8 r1
    | (RegKnd.YMM, _), (RegKnd.YMM, _) -> EnYmYmI8 r1
    | _ -> Utils.futureFeature ()
  | OprReg r, OprMem (_, _, _, sz), OprImm _ ->
    match getKindAndSize r, sz with
    | (RegKnd.GP, 16<rt>), 16<rt> -> EnR16RM16I16
    | (RegKnd.GP, 32<rt>), 32<rt> -> EnR32RM32I32
    | (RegKnd.GP, 64<rt>), 64<rt> -> EnR64RM64I32
    | (RegKnd.MMX, _), 16<rt> -> EnMxM16I8
    | (RegKnd.MMX, _), 64<rt> -> EnMxMM64I8
    | (RegKnd.XMM, _), 8<rt> -> EnXmM8I8
    | (RegKnd.XMM, _), 16<rt> -> EnXmM16I8
    | (RegKnd.XMM, _), 32<rt> -> EnXmM32I8
    | (RegKnd.XMM, _), 64<rt> -> EnXmM64I8
    | (RegKnd.XMM, _), 128<rt> -> EnXmM128I8
    | _ -> Utils.futureFeature ()
  | OprMem (_, _, _, sz), OprReg r, OprImm _ ->
    match sz, getKindAndSize r with
    | 16<rt>, (RegKnd.XMM, _) -> EnM16XmI8
    | _ -> Utils.futureFeature ()
  | opr -> printfn "%A" opr; Utils.futureFeature ()

let getFourOprEncType opr1 opr2 opr3 opr4 =
  match opr1, opr2, opr3, opr4 with
  | OprReg r1, OprReg r2, OprReg r3, OprImm _ ->
    match getKindAndSize r1, getKindAndSize r2, getKindAndSize r3 with
    | (RegKnd.XMM, _), (RegKnd.XMM, _), (RegKnd.GP, 32<rt>) -> EnXmXmR32I8 r2
    | (RegKnd.XMM, _), (RegKnd.XMM, _), (RegKnd.XMM, _) -> EnXmXmXM128I8 r2
    | (RegKnd.YMM, _), (RegKnd.YMM, _), (RegKnd.YMM, _) -> EnYmYmYM256I8 r2
    | _ -> Utils.futureFeature ()
  | OprReg r1, OprReg r2, OprMem (_, _, _, sz), OprImm _ ->
    match getKindAndSize r1, getKindAndSize r2, sz with
    | (RegKnd.XMM, _), (RegKnd.XMM, _), 8<rt> -> EnXmXmM8I8 r2
    | (RegKnd.XMM, _), (RegKnd.XMM, _), 16<rt> -> EnXmXmM16I8 r2
    | (RegKnd.XMM, _), (RegKnd.XMM, _), 128<rt> -> EnXmXmXM128I8 r2
    | (RegKnd.YMM, _), (RegKnd.YMM, _), 256<rt> -> EnYmYmYM256I8 r2
    | _ -> Utils.futureFeature ()
  | opr -> printfn "%A" opr; Utils.futureFeature ()

let getEncodingType isa op = function
  | OneOperand opr -> getOneOprEncType op opr
  | TwoOperands (opr1, opr2) -> getTwoOprEncType isa op opr1 opr2
  | ThreeOperands (opr1, opr2, opr3) -> getThreeOprEncType opr1 opr2 opr3
  | FourOperands (o1, o2, o3, o4) -> getFourOprEncType o1 o2 o3 o4
  | opr -> printfn "%A" opr; Utils.futureFeature ()

let exceptOprSzPrefOp encType op =
  match encType, op with
  | EnR32R16, Opcode.IN
  | EnR32R16, Opcode.MOVZX
  | EnR32M16, Opcode.MOVZX
  | EnR16R8, Opcode.OUT -> true
  | _ -> false

let isOprReg16 op = function
  | encType when exceptOprSzPrefOp encType op -> false
  | EnR16 | EnM16
  | EnR16R16 | EnR32R16 | EnR16R8
  | EnR16M16 | EnR32M16 | EnR16M8
  | EnM16I8 | EnM16R16
  | EnR16I8 | EnR16I16
  | EnI8AX
  | EnR16RM16I16 -> true
  | _ -> false

let isAddrSz (isa: ISA) reg =
  match isa.Arch, Register.toRegType reg with
  | Arch.IntelX64, 32<rt> -> true
  | Arch.IntelX86, 16<rt> -> true
  | _ -> false

let isAddrSize isa = function
  | OneOperand (OprMem (Some bReg, _, _, _))
  | TwoOperands (_, OprMem (Some bReg, _, _, _))
  | TwoOperands (OprMem (Some bReg, _, _, _), _) -> isAddrSz isa bReg
  | _ -> false

let encodePrefix isa (ins: InsInfo) encType =
  // 64-bit mode : register -> 16bit => 66
  //               memory base register -> 32bit => 67
  // 32-bit mode : register -> 16bit => 66
  //               memory base register -> 16bit => 67

  // Prefix group3: Operand-size override
  let prxGrp3 =
    if isOprReg16 ins.Opcode encType then [| Normal 0x66uy |] else [||]

  // Prefix group4: Address-size override
  let prxGrp4 =
    if isAddrSize isa ins.Operands then [| Normal 0x67uy |] else [||]

  Array.append prxGrp3 prxGrp4

let exceptREXPrefOp = function
  | Opcode.CRC32 -> true
  | _ -> false

let encodeREXPref isa (ins: InsInfo) encType =
  // only 64-bit
  // 0x40 - 0x4f
  // 64-bit mode : register 64bit => 48 ~
  if isa.Arch = Arch.IntelX86 then [||]
  else match encType with (* Arch.IntelX64 *)
       | _ when exceptREXPrefOp ins.Opcode -> [||]
       | EnR64 | EnM64
       | EnR64R64 | EnR64R32 | EnR64R16 | EnR64R8
       | EnR64M64 | EnR64M16 | EnR64M8
       | EnR64I8 | EnR64I64
       | EnM64R64 | EnM64I8
       | EnR64RM64I32 -> [| Normal 0x48uy |]
       (* more cases *)
       | _ -> [||]

let aad = function
  | EnI8 -> [| Normal 0xD5uy |]
  | _ -> Utils.futureFeature ()

let add = function
  | EnR8I8 | EnM8I8 -> [| Normal 0x80uy |]
  | EnR16I16 | EnR32I32 | EnR64I64
  | EnM16I16 | EnM32I32 | EnM64I64 -> [| Normal 0x81uy |]
  | EnM8R8 -> [| Normal 0x00uy |]
  | EnM16R16 | EnM32R32 | EnM64R64 -> [| Normal 0x01uy |]
  | EnR8R8 | EnR8M8 -> [| Normal 0x02uy |]
  | EnR16R16 | EnR32R32 | EnR64R64
  | EnR16M16 | EnR32M32 | EnR64M64 -> [| Normal 0x03uy |]
  | _ -> Utils.futureFeature ()

let addps = function
  | EnXmXm | EnXmM128 -> [| Normal 0x0Fuy; Normal 0x58uy |]
  | _ -> asmError ()

let addss = function
  | EnXmXm | EnXmM32 -> [| Normal 0xF3uy; Normal 0x0Fuy; Normal 0x58uy |]
  | _ -> asmError ()

let bndmov = function
  | EnBnBM64 | EnBnBM128 ->
    [| Normal 0x66uy; Normal 0x0Fuy; Normal 0x1Auy |]
  | EnBM64Bn | EnBM128Bn ->
    [| Normal 0x66uy; Normal 0x0Fuy; Normal 0x1Buy |]
  | _ -> asmError ()

let bt = function
  | EnR16R16 | EnR32R32 | EnR64R64
  | EnM16R16 | EnM32R32 | EnM64R64 -> [| Normal 0x0Fuy; Normal 0xA3uy |]
  | EnR16I8 | EnR32I8 | EnR64I8
  | EnM16I8 | EnM32I8 | EnM64I8 -> [| Normal 0x0Fuy; Normal 0xBAuy |]
  | _ -> asmError ()

let clflush = function
  | EnM8 -> [| Normal 0x0Fuy; Normal 0xAEuy |]
  | _ -> asmError ()

let cmppd = function
  | EnXmXmI8 _ | EnXmM128I8 -> [| Normal 0x66uy; Normal 0x0Fuy; Normal 0xC2uy |]
  | _ -> asmError ()

let cmpss = function
  | EnXmXmI8 _ | EnXmM32I8 -> [| Normal 0xF3uy; Normal 0x0Fuy; Normal 0xC2uy |]
  | _ -> asmError ()

let cmpxchgByte = function
  | EnM64 -> [| Normal 0x0Fuy; Normal 0xC7uy |]
  | EnM128 -> [| Normal 0x48uy; Normal 0x0Fuy; Normal 0xC7uy |] // REX prefix
  | _ -> asmError ()

let comiss = function
  | EnXmXm | EnXmM32 -> [| Normal 0x0Fuy; Normal 0x2Fuy |]
  | _ -> asmError ()

let crc32 = function
  | EnR32R8 | EnR32M8 ->
    [| Normal 0xF2uy; Normal 0x0Fuy; Normal 0x38uy; Normal 0xF0uy |]
  | EnR32R16 | EnR32M16 | EnR32R32 | EnR32M32 ->
    [| Normal 0xF2uy; Normal 0x0Fuy; Normal 0x38uy; Normal 0xF1uy |]
  | EnR64R8 | EnR64M8 ->
    [| Normal 0xF2uy; Normal 0x48uy; Normal 0x0Fuy; Normal 0x38uy;
       Normal 0xF0uy |]
  | EnR64R64 | EnR64M64 ->
    [| Normal 0xF2uy; Normal 0x48uy; Normal 0x0Fuy; Normal 0x38uy;
       Normal 0xF1uy |]
  | _ -> asmError ()

let cvtpd2pi = function
  | EnMxXm | EnMxM128 -> [| Normal 0x66uy; Normal 0x0Fuy; Normal 0x2Duy |]
  | _ -> asmError ()

let cvtpi2pd = function
  | EnXmMx | EnXmM64 -> [| Normal 0x66uy; Normal 0x0Fuy; Normal 0x2Auy |]
  | _ -> asmError ()

let cvtsi2sd = function
  | EnXmR32 | EnXmM32 -> [| Normal 0xF2uy; Normal 0x0Fuy; Normal 0x2Auy |]
  | EnXmR64 | EnXmM64 ->
    [| Normal 0xF2uy; Normal 0x48uy; Normal 0x0Fuy; Normal 0x2Auy |]
  | _ -> asmError ()

let cvttss2si = function
  | EnR32Xm | EnR32M32 -> [| Normal 0xF3uy; Normal 0x0Fuy; Normal 0x2Cuy |]
  | EnR64Xm | EnR64M32 ->
    [| Normal 0xF3uy; Normal 0x48uy; Normal 0x0Fuy; Normal 0x2Cuy |]
  | _ -> asmError ()

let dec = function
  | EnR8 | EnM8 -> [| Normal 0xFEuy |]
  | EnR16 | EnM16 | EnR32 | EnM32 | EnR64 | EnM64 -> [| Normal 0xFFuy |]
  | _ -> asmError ()

let enter = function
  | EnI16I8 -> [| Normal 0xC8uy |]
  | _ -> asmError ()

let idiv = function
  | EnR8 | EnM8 -> [| Normal 0xF6uy |]
  | EnR16 | EnM16 | EnR32 | EnM32 | EnR64 | EnM64 -> [| Normal 0xF7uy |]
  | _ -> asmError ()

let imul = function
  | EnR8 | EnM8 -> [| Normal 0xF6uy |]
  | EnR16 | EnM16 | EnR32 | EnM32 | EnR64 | EnM64 -> [| Normal 0xF7uy |]
  | EnR16R16 | EnR32R32 | EnR64R64
  | EnR16M16 | EnR32M32 | EnR64M64 -> [| Normal 0x0Fuy; Normal 0xAFuy |]
  | EnR16RM16I8 | EnR32RM32I8 | EnR64RM64I8 -> [| Normal 0x6Buy |]
  | EnR16RM16I16 | EnR32RM32I32 | EnR64RM64I32 -> [| Normal 0x69uy |]
  | _ -> asmError ()

let input encType operands = // FIXME: Special Case
  match encType, operands with
  | EnR8I8, TwoOperands (OprReg Register.AL, OprImm _) -> [| Normal 0xE4uy |]
  | EnR16I8, TwoOperands (OprReg Register.AX, OprImm _)
  | EnR32I8, TwoOperands (OprReg Register.EAX, OprImm _) -> [| Normal 0xE5uy |]
  | EnR8R16, TwoOperands (OprReg Register.AL, OprReg Register.DX) ->
    [| Normal 0xECuy |]
  | EnR16R16, TwoOperands (OprReg Register.AX, OprReg Register.DX)
  | EnR32R16, TwoOperands (OprReg Register.EAX, OprReg Register.DX) ->
    [| Normal 0xEDuy |]
  | _ -> asmError ()

let ldmxcsr = function
  | EnM32 -> [| Normal 0x0Fuy; Normal 0xAEuy |]
  | _ -> asmError ()

let loadSegLimit = function
  | EnR16R16 | EnR16M16 | EnR32R32 | EnR32M16 | EnR64R32 | EnR64M16 ->
    [| Normal 0x0Fuy; Normal 0x03uy |]
  | _ -> asmError ()

let jmp = function
  | EnR16 | EnM16 | EnR32 | EnM32 | EnR64 | EnM64 -> [| Normal 0xFFuy |]
  | EnLbl -> [| Normal 0xE9uy |] // FIXME: 0xEB(8bit) or 0xE9(32bit)
  | _ -> Utils.futureFeature ()

let mov = function
  | EnM8R8 -> [| Normal 0x88uy |]
  | EnM16R16 | EnM32R32 | EnM64R64 -> [| Normal 0x89uy |]
  | EnR8R8 | EnR8M8 -> [| Normal 0x8Auy |]
  | EnR16R16 | EnR32R32 | EnR64R64
  | EnR16M16 | EnR32M32 | EnR64M64 -> [| Normal 0x8Buy |]
  | EnRM16Sg | EnRM64Sg -> [| Normal 0x8Cuy |]
  | EnSgRM16 | EnSgRM64 -> [| Normal 0x8Euy |]
  //| EnR8I8 -> [| Normal 0xB0uy |]
  //| EnR16I16 | EnR32I32 | EnR64I64 -> [| Normal 0xB8uy |]
  | EnR8I8 | EnM8I8 -> [| Normal 0xC6uy |]
  | EnR16I16 | EnR32I32 | EnR64I64
  | EnM16I16 | EnM32I32 | EnM64I64 -> [| Normal 0xC7uy |]
  | _ -> Utils.futureFeature ()

let movapd = function
  | EnXmXm | EnXmM128 -> [| Normal 0x66uy; Normal 0x0Fuy; Normal 0x28uy |]
  | EnM128Xm -> [| Normal 0x66uy; Normal 0x0Fuy; Normal 0x29uy |]
  | _ -> asmError ()

let movd = function
  | EnMxR32 | EnMxM32-> [| Normal 0x0Fuy; Normal 0x6Euy |]
  | EnR32Mx | EnM32Mx-> [| Normal 0x0Fuy; Normal 0x7Euy |]
  | EnXmR32 | EnXmM32-> [| Normal 0x66uy; Normal 0x0Fuy; Normal 0x6Euy |]
  | EnR32Xm | EnM32Xm-> [| Normal 0x66uy; Normal 0x0Fuy; Normal 0x7Euy |]
  | _ -> Utils.impossible ()

let movq = function
  | EnMxR64 -> [| Normal 0x48uy; Normal 0x0Fuy; Normal 0x6Euy |]
  | EnR64Mx -> [| Normal 0x48uy; Normal 0x0Fuy; Normal 0x7Euy |]
  | EnXmR64 -> [| Normal 0x66uy; Normal 0x48uy; Normal 0x0Fuy; Normal 0x6Euy |]
  | EnR64Xm -> [| Normal 0x66uy; Normal 0x48uy; Normal 0x0Fuy; Normal 0x7Euy |]
  | EnMxMx | EnMxM64 -> [| Normal 0x0Fuy; Normal 0x6Fuy |]
  | EnM64Mx -> [| Normal 0x0Fuy; Normal 0x7Fuy |]
  | EnXmXm | EnXmM64 -> [| Normal 0xF3uy; Normal 0x0Fuy; Normal 0x7Euy |]
  | EnM64Xm -> [| Normal 0x66uy; Normal 0x0Fuy; Normal 0xD6uy |]
  | _ -> Utils.impossible ()

let movzx = function
  | EnR16R8 | EnR16M8 -> [| Normal 0x0Fuy; Normal 0xB6uy |]
  | EnR32R8 | EnR32M8 -> [| Normal 0x0Fuy; Normal 0xB6uy |]
  | EnR64R8 | EnR64M8 -> [| Normal 0x0Fuy; Normal 0xB6uy |]
  | EnR32R16 | EnR32M16 -> [| Normal 0x0Fuy; Normal 0xB7uy |]
  | EnR64R16 | EnR64M16 -> [| Normal 0x0Fuy; Normal 0xB7uy |]
  | _ -> asmError ()

let out encType operands = // FIXME: Special Case
  match encType, operands with
  | EnI8AL, _ -> [| Normal 0xE6uy |]
  | EnI8AX, _ | EnI8EAX, _ -> [| Normal 0xE7uy |]
  | EnR16R8, TwoOperands (OprReg Register.DX, OprReg Register.AL) ->
    [| Normal 0xEEuy |]
  | EnR16R16, TwoOperands (OprReg Register.DX, OprReg Register.AX)
  | EnR16R32, TwoOperands (OprReg Register.DX, OprReg Register.EAX) ->
    [| Normal 0xEFuy |]
  | _ -> asmError ()

let palignr = function
  | EnMxMM64I8 -> [| Normal 0x0Fuy; Normal 0x3Auy; Normal 0x0Fuy |]
  | EnXmXmI8 _ | EnXmM128I8 ->
    [| Normal 0x66uy; Normal 0x0Fuy; Normal 0x3Auy; Normal 0x0Fuy |]
  | _ -> asmError ()

let pextrw = function
  | EnR32MxI8 | EnR64MxI8 -> [| Normal 0x0Fuy; Normal 0xC5uy |]
  | EnR32XmI8 | EnR64XmI8 -> [| Normal 0x66uy; Normal 0x0Fuy; Normal 0xC5uy |]
  | EnM16XmI8 ->
    [| Normal 0x66uy; Normal 0x0Fuy; Normal 0x3Auy; Normal 0x15uy |]
  | o -> printfn "%A" o; asmError ()

let pinsrb = function
  | EnXmR32I8 | EnXmM8I8 ->
    [| Normal 0x66uy; Normal 0x0Fuy; Normal 0x3Auy; Normal 0x20uy |]
  | _ -> asmError ()

let pinsrd = function
  | EnXmR32I8 | EnXmM32I8 ->
    [| Normal 0x66uy; Normal 0x0Fuy; Normal 0x3Auy; Normal 0x22uy |]
  | _ -> asmError ()

let pinsrq = function
  | EnXmR64I8 | EnXmM64I8 -> [| Normal 0x66uy; Normal 0x48uy; Normal 0x0Fuy;
                                Normal 0x3Auy; Normal 0x22uy |]
  | _ -> asmError ()

let pinsrw = function
  | EnMxR32I8 | EnMxM16I8 -> [| Normal 0x0Fuy; Normal 0xC4uy |]
  | EnXmR32I8 | EnXmM16I8 ->
    [| Normal 0x66uy; Normal 0x0Fuy; Normal 0xC4uy |]
  | _ -> asmError ()

let pmovsxbq = function
  | EnXmXm | EnXmM16 ->
    [| Normal 0x66uy; Normal 0x0Fuy; Normal 0x38uy; Normal 0x22uy |]
  | _ -> asmError ()

let pslld = function
  | EnMxMx | EnMxM64 -> [| Normal 0x0Fuy; Normal 0xF2uy |]
  | EnXmXm | EnXmM128-> [| Normal 0x66uy; Normal 0x0Fuy; Normal 0xF2uy |]
  | EnMxI8 -> [| Normal 0x0Fuy; Normal 0x72uy |]
  | EnXmI8 -> [| Normal 0x66uy; Normal 0x0Fuy; Normal 0x72uy |]
  | _ -> asmError ()

let pslldq = function
  | EnXmI8 -> [| Normal 0x66uy; Normal 0x0Fuy; Normal 0x73uy |]
  | _ -> asmError ()

let roundsd = function
  | EnXmXmI8 _ | EnXmM64I8 ->
    [| Normal 0x66uy; Normal 0x0Fuy; Normal 0x3Auy; Normal 0x0Buy |]
  | _ -> asmError ()

let getRexRXB = function
  | REXPrefix.REXR -> 0b011uy
  | REXPrefix.REXX -> 0b101uy
  | REXPrefix.REXB -> 0b110uy
  | REXPrefix.REXRX -> 0b001uy
  | REXPrefix.REXRB -> 0b010uy
  | REXPrefix.REXXB -> 0b100uy
  | REXPrefix.REXRXB -> 0b000uy
  | REXPrefix.NOREX -> 0b111uy
  | _ -> Utils.impossible ()

let getLeadingOpcodeByte = function (* m-mmmm *)
  | VEXType.VEXTwoByteOp -> 0b00001uy
  | VEXType.VEXThreeByteOpOne -> 0b00010uy
  | VEXType.VEXThreeByteOpTwo -> 0b00011uy
  | _ -> Utils.impossible ()

let getVVVVByte = function
  | Some Register.XMM0 | Some Register.YMM0
  | Some Register.EAX | Some Register.RAX -> 0b1111uy
  | Some Register.XMM1 | Some Register.YMM1
  | Some Register.ECX | Some Register.RCX -> 0b1110uy
  | Some Register.XMM2 | Some Register.YMM2
  | Some Register.EDX | Some Register.RDX -> 0b1101uy
  | Some Register.XMM3 | Some Register.YMM3
  | Some Register.EBX | Some Register.RBX -> 0b1100uy
  | Some Register.XMM4 | Some Register.YMM4
  | Some Register.ESP | Some Register.RSP -> 0b1011uy
  | Some Register.XMM5 | Some Register.YMM5
  | Some Register.EBP | Some Register.RBP -> 0b1010uy
  | Some Register.XMM6 | Some Register.YMM6
  | Some Register.ESI | Some Register.RSI -> 0b1001uy
  | Some Register.XMM7 | Some Register.YMM7
  | Some Register.EDI | Some Register.RDI -> 0b1000uy
  | Some Register.XMM8 | Some Register.YMM8 -> 0b0111uy
  | Some Register.XMM9 | Some Register.YMM9 -> 0b0110uy
  | Some Register.XMM10 | Some Register.YMM10 -> 0b0101uy
  | Some Register.XMM11 | Some Register.YMM11 -> 0b0100uy
  | Some Register.XMM12 | Some Register.YMM12 -> 0b0011uy
  | Some Register.XMM13 | Some Register.YMM13 -> 0b0010uy
  | Some Register.XMM14 | Some Register.YMM14 -> 0b0001uy
  | Some Register.XMM15 | Some Register.YMM15 -> 0b0000uy
  | None -> 0b1111uy
  | _ -> Utils.impossible ()

let getVLen = function
  | 128<rt> -> 0b0uy
  | 256<rt> -> 0b1uy
  | 32<rt> | 64<rt> -> 0b0uy // Scalar
  | _ -> Utils.impossible ()

let getSIMDPref = function
  | Prefix.PrxNone -> 0b00uy
  | Prefix.PrxOPSIZE (* 0x66 *) -> 0b01uy
  | Prefix.PrxREPZ   (* 0xF3 *) -> 0b10uy
  | Prefix.PrxREPNZ  (* 0xF2 *) -> 0b11uy
  | _ -> Utils.impossible ()

let getTwoByteVEX rexPref vvvv len pp op =
  let rexR = if rexPref = REXPrefix.REXR then 0b0uy else 0b1uy
  let vvvv = getVVVVByte vvvv
  let vectorLen = getVLen len
  let pp = getSIMDPref pp
  let sndVByte = (rexR <<< 7) + (vvvv <<< 3) + (vectorLen <<< 2) + pp
  [| Normal 0b11000101uy; Normal sndVByte; Normal op |]

let getThreeByteVEX rexPref mmmmm rexW vvvv len pp op =
  let rexRXB = getRexRXB rexPref
  let mmmmm = getLeadingOpcodeByte mmmmm
  let rexW = if rexW = REXPrefix.REXW then 0b1uy else 0b0uy
  let vvvv = getVVVVByte vvvv
  let vectorLen = getVLen len
  let pp = getSIMDPref pp
  let sndVByte = (rexRXB <<< 5) + mmmmm
  let trdVByte = (rexW <<< 7) + (vvvv <<< 3) + (vectorLen <<< 2) + pp
  [| Normal 0b11000100uy; Normal sndVByte; Normal trdVByte; Normal op |]

let mulx = function // FIXME: REX prefix
  | EnR32R32RM32 r -> getThreeByteVEX REXPrefix.NOREX VEXType.VEXThreeByteOpOne
                        REXPrefix.NOREX (Some r) 32<rt> Prefix.PrxREPNZ 0xF6uy
  | EnR64R64RM64 r -> getThreeByteVEX REXPrefix.NOREX VEXType.VEXThreeByteOpOne
                        REXPrefix.REXW (Some r) 64<rt> Prefix.PrxREPNZ 0xF6uy
  | _ -> asmError ()

let vaddps = function // FIXME: REX prefix
  | EnXmXmXm vvvv | EnXmXmM128 vvvv ->
    getTwoByteVEX REXPrefix.NOREX (Some vvvv) 128<rt> Prefix.PrxNone 0x58uy
  | EnYmYmYm vvvv | EnYmYmM256 vvvv ->
    getTwoByteVEX REXPrefix.NOREX (Some vvvv) 256<rt> Prefix.PrxNone 0x58uy
  | _ -> Utils.futureFeature ()

let vaddss = function // FIXME: REX prefix
  | EnXmXmXm vvvv | EnXmXmM32 vvvv ->
    getTwoByteVEX REXPrefix.NOREX (Some vvvv) 128<rt> Prefix.PrxREPZ 0x58uy
  | _ -> Utils.futureFeature ()

let vcvtsi2sd = function // FIXME: REX prefix
  | EnXmXmR32 vvvv | EnXmXmM32 vvvv ->
    getThreeByteVEX REXPrefix.NOREX VEXType.VEXTwoByteOp
      REXPrefix.NOREX (Some vvvv) 128<rt> Prefix.PrxREPNZ 0x2Auy
  | EnXmXmR64 vvvv | EnXmXmM64 vvvv ->
    getThreeByteVEX REXPrefix.NOREX VEXType.VEXTwoByteOp
      REXPrefix.REXW (Some vvvv) 128<rt> Prefix.PrxREPNZ 0x2Auy
  | _ -> Utils.futureFeature ()

let vcvttss2si = function // FIXME: REX prefix
  | EnR32Xm | EnR32M32 -> getThreeByteVEX REXPrefix.NOREX VEXType.VEXTwoByteOp
                            REXPrefix.NOREX None 128<rt> Prefix.PrxREPZ 0x2Cuy
  | EnR64Xm | EnR64M32 -> getThreeByteVEX REXPrefix.NOREX VEXType.VEXTwoByteOp
                            REXPrefix.REXW None 128<rt> Prefix.PrxREPZ 0x2Cuy
  | _ -> Utils.futureFeature ()

let vmovapd = function // FIXME: REX prefix
  | EnXmXm | EnXmM128 ->
    getTwoByteVEX REXPrefix.NOREX None 128<rt> Prefix.PrxOPSIZE 0x28uy
  | EnM128Xm ->
    getTwoByteVEX REXPrefix.NOREX None 128<rt> Prefix.PrxOPSIZE 0x29uy
  | EnYmYm | EnYmM256 ->
    getTwoByteVEX REXPrefix.NOREX None 256<rt> Prefix.PrxOPSIZE 0x28uy
  | EnM256Ym ->
    getTwoByteVEX REXPrefix.NOREX None 256<rt> Prefix.PrxOPSIZE 0x29uy
  | _ -> Utils.futureFeature ()

let vmovd = function // FIXME: REX prefix
  | EnXmR32 | EnXmM32 ->
    getTwoByteVEX REXPrefix.NOREX None 128<rt> Prefix.PrxOPSIZE 0x6Euy
  | EnR32Xm | EnM32Xm ->
    getTwoByteVEX REXPrefix.NOREX None 128<rt> Prefix.PrxOPSIZE 0x7Euy
  | _ -> Utils.futureFeature ()

let vmovq = function // FIXME: REX prefix
  | EnXmR64 | EnXmM64 -> getThreeByteVEX REXPrefix.NOREX VEXType.VEXTwoByteOp
                           REXPrefix.REXW None 128<rt> Prefix.PrxOPSIZE 0x6Euy
  | EnR64Xm -> getThreeByteVEX REXPrefix.NOREX VEXType.VEXTwoByteOp
                 REXPrefix.REXW None 128<rt> Prefix.PrxOPSIZE 0x7Euy
  | EnXmXm | EnXmM64 ->
    getTwoByteVEX REXPrefix.NOREX None 128<rt> Prefix.PrxREPZ 0x7Euy
  | EnM64Xm ->
    getTwoByteVEX REXPrefix.NOREX None 128<rt> Prefix.PrxOPSIZE 0xD6uy
  | _ -> Utils.futureFeature ()

let vpalignr = function // FIXME: REX prefix
  | EnXmXmXM128I8 vvvv ->
    getThreeByteVEX REXPrefix.NOREX VEXType.VEXThreeByteOpTwo
      REXPrefix.NOREX (Some vvvv) 128<rt> Prefix.PrxOPSIZE 0x0Fuy
  | EnYmYmYM256I8 vvvv ->
    getThreeByteVEX REXPrefix.NOREX VEXType.VEXThreeByteOpTwo
      REXPrefix.NOREX (Some vvvv) 256<rt> Prefix.PrxOPSIZE 0x0Fuy
  | _ -> Utils.futureFeature ()

let vpextrw = function // FIXME: REX prefix
  | EnR32XmI8 | EnR64XmI8 ->
    getThreeByteVEX REXPrefix.NOREX VEXType.VEXTwoByteOp
      REXPrefix.NOREX None 128<rt> Prefix.PrxOPSIZE 0xC5uy
  | EnM16XmI8 ->
    getThreeByteVEX REXPrefix.NOREX VEXType.VEXThreeByteOpTwo
      REXPrefix.NOREX None 128<rt> Prefix.PrxOPSIZE 0x15uy
  | _ -> Utils.futureFeature ()

let vpinsrb = function // FIXME: REX prefix
  | EnXmXmR32I8 vvvv | EnXmXmM8I8 vvvv ->
    getThreeByteVEX REXPrefix.NOREX VEXType.VEXThreeByteOpTwo
      REXPrefix.NOREX (Some vvvv) 128<rt> Prefix.PrxOPSIZE 0x20uy
  | _ -> Utils.futureFeature ()

let vpinsrw = function // FIXME: REX prefix
  | EnXmXmR32I8 vvvv | EnXmXmM16I8 vvvv ->
    getThreeByteVEX REXPrefix.NOREX VEXType.VEXTwoByteOp
      REXPrefix.NOREX (Some vvvv) 128<rt> Prefix.PrxOPSIZE 0xC4uy
  | _ -> Utils.futureFeature ()

let vpmovsxbq = function // FIXME: REX prefix
  | EnXmXm | EnXmM16 ->
    getThreeByteVEX REXPrefix.NOREX VEXType.VEXThreeByteOpOne
      REXPrefix.NOREX None 128<rt> Prefix.PrxOPSIZE 0x22uy
  | _ -> Utils.futureFeature ()

let vpslld = function // FIXME: REX prefix
  | EnXmXmXm vvvv | EnXmXmM128 vvvv ->
    getTwoByteVEX REXPrefix.NOREX (Some vvvv) 128<rt> Prefix.PrxOPSIZE 0xF2uy
  | EnYmYmXm vvvv | EnYmYmM128 vvvv ->
    getTwoByteVEX REXPrefix.NOREX (Some vvvv) 256<rt> Prefix.PrxOPSIZE 0xF2uy
  | EnXmXmI8 vvvv ->
    getTwoByteVEX REXPrefix.NOREX (Some vvvv) 128<rt> Prefix.PrxOPSIZE 0x72uy
  | EnYmYmI8 vvvv ->
    getTwoByteVEX REXPrefix.NOREX (Some vvvv) 256<rt> Prefix.PrxOPSIZE 0x72uy
  | _ -> Utils.futureFeature ()

let vpslldq = function // FIXME: REX prefix
  | EnXmXmI8 reg ->
    getTwoByteVEX REXPrefix.NOREX (Some reg) 128<rt> Prefix.PrxOPSIZE 0x73uy
  | EnYmYmI8 reg ->
    getTwoByteVEX REXPrefix.NOREX (Some reg) 256<rt> Prefix.PrxOPSIZE 0x73uy
  | _ -> Utils.futureFeature ()

let encodeOpcode (ins: InsInfo) eTyp =
  match ins.Opcode with
  | Opcode.AAD -> aad eTyp // 64-bit mode: invalid
  | Opcode.ADD -> add eTyp
  | Opcode.ADDPS -> addps eTyp
  | Opcode.ADDSS -> addss eTyp
  | Opcode.BNDMOV -> bndmov eTyp
  | Opcode.BT -> bt eTyp
  | Opcode.CLFLUSH -> clflush eTyp
  | Opcode.CMPPD -> cmppd eTyp
  | Opcode.CMPSS -> cmpss eTyp
  | Opcode.CMPXCHG8B | Opcode.CMPXCHG16B -> cmpxchgByte eTyp
  | Opcode.COMISS -> comiss eTyp
  | Opcode.CPUID -> [| Normal 0x0Fuy; Normal 0xA2uy |]
  | Opcode.CRC32 -> crc32 eTyp
  | Opcode.CVTPD2PI -> cvtpd2pi eTyp
  | Opcode.CVTPI2PD -> cvtpi2pd eTyp
  | Opcode.CVTSI2SD -> cvtsi2sd eTyp
  | Opcode.CVTTSS2SI -> cvttss2si eTyp
  | Opcode.DEC -> dec eTyp
  | Opcode.ENTER -> enter eTyp
  | Opcode.IDIV -> idiv eTyp
  | Opcode.IMUL -> imul eTyp
  | Opcode.IN -> input eTyp ins.Operands
  | Opcode.LDMXCSR -> ldmxcsr eTyp
  | Opcode.LSL -> loadSegLimit eTyp
  | Opcode.JMPNear -> jmp eTyp
  | Opcode.MOV -> mov eTyp
  | Opcode.MOVAPD -> movapd eTyp
  | Opcode.MOVD -> movd eTyp
  | Opcode.MOVQ -> movq eTyp
  | Opcode.MOVZX -> movzx eTyp
  | Opcode.MULX -> mulx eTyp
  | Opcode.OUT -> out eTyp ins.Operands
  | Opcode.PALIGNR -> palignr eTyp
  | Opcode.PEXTRW -> pextrw eTyp
  | Opcode.PINSRB -> pinsrb eTyp
  | Opcode.PINSRD -> pinsrd eTyp // Parsing not supported
  | Opcode.PINSRQ -> pinsrq eTyp // Parsing not supported
  | Opcode.PINSRW -> pinsrw eTyp
  | Opcode.PMOVSXBQ -> pmovsxbq eTyp
  | Opcode.PSLLD -> pslld eTyp
  | Opcode.PSLLDQ -> pslldq eTyp
  | Opcode.ROUNDSD -> roundsd eTyp
  | Opcode.VADDPS -> vaddps eTyp
  | Opcode.VADDSS -> vaddss eTyp
  | Opcode.VCVTSI2SD -> vcvtsi2sd eTyp
  | Opcode.VCVTTSS2SI -> vcvttss2si eTyp
  | Opcode.VMOVAPD -> vmovapd eTyp
  | Opcode.VMOVD -> vmovd eTyp
  | Opcode.VMOVQ -> vmovq eTyp
  | Opcode.VPALIGNR -> vpalignr eTyp
  | Opcode.VPEXTRW -> vpextrw eTyp
  | Opcode.VPINSRB -> vpinsrb eTyp
  | Opcode.VPINSRW -> vpinsrw eTyp
  | Opcode.VPMOVSXBQ -> vpmovsxbq eTyp
  | Opcode.VPSLLD -> vpslld eTyp
  | Opcode.VPSLLDQ -> vpslldq eTyp
  | op -> printfn "%A" op;Utils.futureFeature ()

let getRegBit = function
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
  | _ -> Utils.futureFeature ()

let getModRMByte md reg rm = (md <<< 6) + (reg <<< 3) + rm |> Normal

let getRMBySIB baseReg = function // FIXME: baseReg option
  | Some _ -> 0b100uy
  | None -> getRegBit baseReg

let isMR encType = function // ModRM:r/m(r, w), ModRM:reg(r)
  | Opcode.BT -> true
  | Opcode.MOVD when encType = EnR32Mx || encType = EnR32Xm -> true
  | Opcode.MOVQ when encType = EnR64Mx || encType = EnR64Xm -> true
  | Opcode.VMOVD when encType = EnR32Xm -> true
  | Opcode.VMOVQ when encType = EnR64Xm -> true
  | _ -> false // ModRM:reg(r, w), ModRM:r/m(r)

let encodeRR reg1 reg2 encType op =
  if isMR encType op then getModRMByte 0b11uy (getRegBit reg2) (getRegBit reg1)
  else getModRMByte 0b11uy (getRegBit reg1) (getRegBit reg2)

let getMod = function
  | None -> 0b00uy
  | Some disp -> if disp > 0xffL then 0b10uy else 0b01uy

let encodeMR baseReg disp reg2 sib = // FIXME: same encodeRM
  getModRMByte (getMod disp) (getRegBit reg2) (getRMBySIB baseReg sib)

let encodeRM baseReg disp reg2 sib =
  getModRMByte (getMod disp) (getRegBit reg2) (getRMBySIB baseReg sib)

let encodeRI reg regConstr =
  getModRMByte 0b11uy regConstr (getRegBit reg)

let encodeMI baseReg disp sib regConstr =
  getModRMByte (getMod disp) regConstr (getRMBySIB baseReg sib)

let encodeM baseReg disp sib regConstr =
  getModRMByte (getMod disp) regConstr (getRMBySIB baseReg sib)

let encodeR reg regConstr =
  getModRMByte 0b11uy regConstr (getRegBit reg)

let encodeRRR r1 r2 r3 =
  match Register.getKind r1, Register.getKind r2, Register.getKind r3 with
  | RegKnd.XMM, RegKnd.XMM, RegKnd.XMM
  | RegKnd.YMM, RegKnd.YMM, RegKnd.XMM
  | RegKnd.YMM, RegKnd.YMM, RegKnd.YMM
  | RegKnd.XMM, RegKnd.XMM, RegKnd.GP
  | RegKnd.GP, RegKnd.GP, RegKnd.GP ->
    getModRMByte 0b11uy (getRegBit r1) (getRegBit r3)
  | _ -> Utils.futureFeature ()

let encodeRRM r1 r2 baseReg sib disp =
  match Register.getKind r1, Register.getKind r2 with
  | RegKnd.XMM, RegKnd.XMM | RegKnd.YMM, RegKnd.YMM
  | RegKnd.GP, RegKnd.GP ->
    getModRMByte (getMod disp) (getRegBit r1) (getRMBySIB baseReg sib)
  | _ -> Utils.futureFeature ()

let encodeRRIWithConstr reg regConstr =
  getModRMByte 0b11uy regConstr (getRegBit reg)

let encodeRRI reg1 reg2 =
  getModRMByte 0b11uy (getRegBit reg1) (getRegBit reg2)

let encodeRMI baseReg disp reg sib =
  getModRMByte (getMod disp) (getRegBit reg) (getRMBySIB baseReg sib)

let encodeMRI baseReg disp reg sib =
  getModRMByte (getMod disp) (getRegBit reg) (getRMBySIB baseReg sib)

let encodeRRRI r1 r2 r3 =
  match Register.getKind r1, Register.getKind r2, Register.getKind r3 with
  | RegKnd.XMM, RegKnd.XMM, RegKnd.XMM
  | RegKnd.YMM, RegKnd.YMM, RegKnd.YMM
  | RegKnd.XMM, RegKnd.XMM, RegKnd.GP ->
    getModRMByte 0b11uy (getRegBit r1) (getRegBit r3)
  | _ -> Utils.futureFeature ()

let encodeRRMI baseReg disp reg2 sib =
  getModRMByte (getMod disp) (getRegBit reg2) (getRMBySIB baseReg sib)

let computeRegConstraint (ins: InsInfo) =
  match ins.Opcode with
  | Opcode.ADD | Opcode.MOV -> 0b000uy
  | Opcode.CMPXCHG8B | Opcode.CMPXCHG16B | Opcode.DEC -> 0b001uy
  | Opcode.LDMXCSR -> 0b010uy
  | Opcode.BT | Opcode.JMPNear -> 0b100uy
  | Opcode.IMUL -> 0b101uy
  | Opcode.PSLLD | Opcode.VPSLLD -> 0b110uy
  | Opcode.CLFLUSH | Opcode.IDIV | Opcode.PSLLDQ | Opcode.VPSLLDQ -> 0b111uy
  | _ -> Utils.futureFeature ()

let encodeModRM ins eType =
  (* Mod(2):Reg/Opcode(3):R/M(3) *)
  match ins.Operands with
  (* One Operand *)
  | OneOperand (OprReg reg ) -> [| encodeR reg (computeRegConstraint ins) |]
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

let getScaleBit = function
  | Scale.X1 -> 0b00uy
  | Scale.X2 -> 0b01uy
  | Scale.X4 -> 0b10uy
  | _ (* Scale.X8 *) -> 0b11uy

let encodeScaledIdx baseReg (reg, scale) =
  let idxBit, sBit = getRegBit reg, getScaleBit scale
  let baseBit = getRegBit baseReg
  (sBit <<< 6) + (idxBit <<< 3) + baseBit |> Normal

let encodeSIB ins =
  (* Scale(2):Index(3):Base(3) *)
  match ins.Operands with
  | TwoOperands (OprMem (Some b, Some sib, _, _), _)
  | TwoOperands (_, OprMem (Some b, Some sib, _, _)) ->
    [| encodeScaledIdx b sib |]
  (* more cases *)
  | _ -> [||]

let adjustDisp = function
  | None -> [||]
  | Some disp ->
    if disp > 0xffL then BitConverter.GetBytes (int32 disp)
                         |> Array.map Normal
    else [| Normal <| byte disp |]

let encodeDisp ins =
  match ins.Operands with
  | OneOperand (GoToLabel _lbl) -> [| Label; Label; Label; Label |] // FIXME
  | TwoOperands (OprMem (_, _, disp, _), _)
  | TwoOperands (_, OprMem (_, _, disp, _)) -> adjustDisp disp
  (* more cases *)
  | _ -> [||]

let uncondImm8Opcode = function
  | Opcode.BT | Opcode.CMPPD | Opcode.CMPPS | Opcode.IN | Opcode.PALIGNR
  | Opcode.PEXTRW | Opcode.PINSRW | Opcode.PSLLD | Opcode.PSLLDQ
  | Opcode.ROUNDSD -> true
  | _ -> false

let adjustImm op (imm: int64) = function
  | _ when uncondImm8Opcode op -> [| byte imm |]
  | 8<rt> -> [| byte imm |]
  | 16<rt> -> BitConverter.GetBytes (int16 imm)
  | 32<rt> -> BitConverter.GetBytes (int32 imm)
  | 64<rt> when op = Opcode.IMUL -> BitConverter.GetBytes (int32 imm)
  | 64<rt> -> BitConverter.GetBytes (imm)
  | _ -> Utils.impossible ()

let encTwoOprImm op opr1 opr2 =
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

let encThreeOprImm op opr1 opr2 opr3 =
  match opr1, opr2, opr3 with
  | OprReg r1, OprReg r2, OprImm imm ->
    match getKindAndSize r1, getKindAndSize r2 with
    | (RegKnd.GP, 32<rt>), (RegKnd.MMX, _)
    | (RegKnd.GP, 32<rt>), (RegKnd.XMM, _)
    | (RegKnd.GP, 64<rt>), (RegKnd.MMX, _)
    | (RegKnd.GP, 64<rt>), (RegKnd.XMM, _)
    | (RegKnd.MMX, _), (RegKnd.GP, 32<rt>)
    | (RegKnd.XMM, _), (RegKnd.GP, 32<rt>)
    | (RegKnd.XMM, _), (RegKnd.GP, 64<rt>)
    | (RegKnd.MMX, _), (RegKnd.MMX, _) | (RegKnd.XMM, _), (RegKnd.XMM, _)
    | (RegKnd.YMM, _), (RegKnd.YMM, _) ->
      adjustImm op imm 8<rt> |> Array.map Normal
    | (RegKnd.GP, 16<rt>), (RegKnd.GP, 16<rt>) ->
      adjustImm op imm 16<rt> |> Array.map Normal
    | (RegKnd.GP, 32<rt>), (RegKnd.GP, 32<rt>)
    | (RegKnd.GP, 64<rt>), (RegKnd.GP, 64<rt>) ->
      adjustImm op imm 32<rt> |> Array.map Normal
    | _ -> [||]
  | OprReg _, OprMem (_, _, _, sz), OprImm imm
  | OprMem (_, _, _, sz), OprReg _, OprImm imm ->
    adjustImm op imm sz |> Array.map Normal
  | _ -> [||]

let encFourOprImm op opr1 opr2 opr3 opr4 =
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

let encodingByteCode isa (ins: InsInfo) =
  let encType = getEncodingType isa ins.Opcode ins.Operands
  let prefix = encodePrefix isa ins encType
  let rexPref = encodeREXPref isa ins encType
  let opcode = encodeOpcode ins encType
  let modrm = encodeModRM ins encType
  let sib = encodeSIB ins
  let disp = encodeDisp ins
  let imm = encodeImm ins
  {
    Prefix = prefix
    REXPrefix = rexPref
    Opcode = opcode
    ModRM = modrm
    SIB = sib
    Displacement = disp
    Immediate = imm
  }

/// Temp code for testing

open System.Text

let getValue enBytes (sb: StringBuilder) =
  Array.rev enBytes
  |> Array.fold (fun acc byte ->
    match byte with
    | Normal b -> b.ToString("X2") + acc
    | Label -> "00" + acc)"" // FIXME: assumed (32bit)
  |> sb.Append

let eByteCodeToStr (eIns: EncodedByteCode) =
  let sb = StringBuilder ()
  getValue eIns.Prefix sb
  |> getValue eIns.REXPrefix
  |> getValue eIns.Opcode
  |> getValue eIns.ModRM
  |> getValue eIns.SIB
  |> getValue eIns.Displacement
  |> getValue eIns.Immediate
  |> (fun sb -> sb.ToString ())

let rec updatePC acc addr = function
  | [] -> acc |> List.rev
  | (i, len, b, e) :: t -> updatePC ((i, addr, b, e) :: acc) (addr + len) t

let findPC idx pcMap =
  match Map.tryFind idx pcMap with
  | Some pc -> pc
  | None -> 0xffffffffUL // -1

let disassembly (isa: ISA) addr bCode =
  let handler = BinHandler.Init (isa, ByteArray.ofHexString bCode)
  let ins = BinHandler.ParseInstr handler 0UL
  printfn "%-4x: %-20s     %s" addr bCode (ins.Disasm ())

type AssemblyInfo = {
  Index         : int
  PC            : Addr
  ByteStr       : string
  LabeledBytes  : LabeledByte []
  Label         : string option
}

let parseEncInfoToLblBytes (eInfo: EncodedByteCode) =
  Array.append eInfo.Displacement eInfo.Immediate
  |> Array.append eInfo.SIB
  |> Array.append eInfo.ModRM
  |> Array.append eInfo.Opcode
  |> Array.append eInfo.REXPrefix
  |> Array.append eInfo.Prefix

let parseAsmInfo idx pc byteStr encInfo operands =
  let lblBytes = parseEncInfoToLblBytes encInfo
  let label =
    match operands with
    | OneOperand (GoToLabel str) -> Some str
    | _ -> None
  {
    Index = idx
    PC = pc
    ByteStr = byteStr
    LabeledBytes = lblBytes
    Label = label
  }

let getDispBytes addr (asmInfo: AssemblyInfo) =
  let opByte = [| asmInfo.LabeledBytes.[0] |]
  let dispBytes =
    (int32 addr) - (int32 asmInfo.PC + (String.length asmInfo.ByteStr / 2))
    |> BitConverter.GetBytes |> Array.map Normal // FIXME: assumed (int32)
  Array.append opByte dispBytes

let getLabeledBytes str asmInfo lbls =
  match Map.tryFind str lbls with
  | Some addr -> getDispBytes addr asmInfo
  | None -> Utils.impossible ()

let updateByteStr lblBytes =
  Array.fold (fun acc lblByte ->
    match lblByte with
    | Normal byte -> byte.ToString ("X2") + acc
    | _ -> Utils.impossible ()) "" (lblBytes |> Array.rev)

let updateByteCodeAndStr str lbls asmInfo =
  let lblBytes = getLabeledBytes str asmInfo lbls
  let byteStr = updateByteStr lblBytes
  { asmInfo with LabeledBytes = lblBytes; ByteStr = byteStr }

let updateLabeledByte lbls (asmInfo: AssemblyInfo) =
  match asmInfo.Label with
  | Some str -> updateByteCodeAndStr str lbls asmInfo
  | None -> asmInfo

let updateLabeledInstr ins encodedInfo lbls =
  List.map2 (fun (idx, pc, bStr, eInfo) ins ->
    parseAsmInfo idx pc bStr eInfo ins.Operands
    |> updateLabeledByte lbls) encodedInfo ins

let prettyPrint isa asmInfos lbls =
  printfn ""
  printfn "<Assembly>"
  List.fold (fun acc asmInfo -> asmInfo.ByteStr + acc) "" (asmInfos |> List.rev)
  |> printfn "%s"
  printfn ""
  printfn "<Disassembly>"
  List.iter (fun asmInfo -> disassembly isa asmInfo.PC asmInfo.ByteStr) asmInfos
  printfn ""
  printfn "<Label>"
  Map.iter (fun lbl addr -> printfn "%04x <%s>:" addr lbl) lbls

// FixMe: Should complete the fields of InsInfo. Should call vexInfoFromOpcode
// for every insInfo and complete the InsInfo size. It should also look for and
// substitue label operands.
let updateInsInfos (ins: InsInfo list) (lbls: Map<string, int>) isa =
  let encodedInfo =
    List.map (fun ins -> let eByteCode = encodingByteCode isa ins
                         eByteCode, eByteCodeToStr eByteCode) ins
    |> List.mapi (fun i (e, str) -> i, String.length str / 2 |> uint64, str, e)
    |> updatePC [] 0UL

  let pcMap =
    List.map (fun (i, pc, _, _) -> i, pc) encodedInfo |> Map.ofList
  let lbls = Map.map (fun _ idx -> findPC idx pcMap) lbls

  let asmInfos = updateLabeledInstr ins encodedInfo lbls

  prettyPrint isa asmInfos lbls

  asmInfos