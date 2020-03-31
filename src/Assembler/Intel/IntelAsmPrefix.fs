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

module internal B2R2.Assembler.Intel.AsmPrefix

open B2R2
open B2R2.FrontEnd.Intel
open B2R2.Assembler.Intel.EncodingType

let private exceptOprSzPrefOp encType op =
  match encType, op with
  | EnR32R16, Opcode.IN
  | EnR32R16, Opcode.MOVZX
  | EnR32M16, Opcode.MOVZX
  | EnR16R8, Opcode.OUT -> true
  | _ -> false

let private isOprReg16 op = function
  | encType when exceptOprSzPrefOp encType op -> false
  | EnR16 | EnM16
  | EnR16R16 | EnR32R16 | EnR16R8
  | EnR16M16 | EnR32M16 | EnR16M8
  | EnM16I8 | EnM16R16
  | EnR16I8 | EnR16I16
  | EnI8AX
  | EnR16RM16I16 -> true
  | _ -> false

let private isAddrSz (isa: ISA) reg =
  match isa.Arch, Register.toRegType reg with
  | Arch.IntelX64, 32<rt> -> true
  | Arch.IntelX86, 16<rt> -> true
  | _ -> false

let private isAddrSize isa = function
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

let private exceptREXPrefOp = function
  | Opcode.CRC32 | Opcode.CMPXCHG8B -> true
  | _ -> false

let encodeREXPref isa (ins: InsInfo) encType =
  // only 64-bit
  // 0x40 - 0x4f
  // 64-bit mode : register 64bit => 48 ~
  if isa.Arch = Arch.IntelX86 then [||]
  else
    match encType with (* Arch.IntelX64 *)
    | _ when exceptREXPrefOp ins.Opcode -> [||]
    | EnR64 | EnM64
    | EnR64R64 | EnR64R32 | EnR64R16 | EnR64R8
    | EnR64M64 | EnR64M16 | EnR64M8
    | EnR64I8 | EnR64I64
    | EnM64R64 | EnM64I8
    | EnR64RM64I32 -> [| Normal 0x48uy |]
    (* More cases *)
    | _ -> [||]

let private getRexRXB = function
  | REXPrefix.REXR -> 0b011uy
  | REXPrefix.REXX -> 0b101uy
  | REXPrefix.REXB -> 0b110uy
  | REXPrefix.REXRX -> 0b001uy
  | REXPrefix.REXRB -> 0b010uy
  | REXPrefix.REXXB -> 0b100uy
  | REXPrefix.REXRXB -> 0b000uy
  | REXPrefix.NOREX -> 0b111uy
  | _ -> Utils.impossible ()

let private getLeadingOpcodeByte = function (* m-mmmm *)
  | VEXType.VEXTwoByteOp -> 0b00001uy
  | VEXType.VEXThreeByteOpOne -> 0b00010uy
  | VEXType.VEXThreeByteOpTwo -> 0b00011uy
  | _ -> Utils.impossible ()

let private getVVVVByte = function
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

let private getVLen = function
  | 128<rt> -> 0b0uy
  | 256<rt> -> 0b1uy
  | 32<rt> | 64<rt> -> 0b0uy // Scalar
  | _ -> Utils.impossible ()

let private getSIMDPref = function
  | Prefix.PrxNone -> 0b00uy
  | Prefix.PrxOPSIZE (* 0x66 *) -> 0b01uy
  | Prefix.PrxREPZ   (* 0xF3 *) -> 0b10uy
  | Prefix.PrxREPNZ  (* 0xF2 *) -> 0b11uy
  | _ -> Utils.impossible ()

let getTwoByteVEX rexPref vvvv len pp op =
  let  rexR = if rexPref = REXPrefix.REXR then 0b0uy else 0b1uy
  let  vvvv = getVVVVByte vvvv
  let  vectorLen = getVLen len
  let  pp = getSIMDPref pp
  let  sndVByte = (rexR <<< 7) + (vvvv <<< 3) + (vectorLen <<< 2) + pp
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

// vim: set tw=80 sts=2 sw=2:
