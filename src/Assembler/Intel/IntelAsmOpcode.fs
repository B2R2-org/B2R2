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
open B2R2.Assembler.Intel.EncodingType
open B2R2.Assembler.Intel.AsmPrefix

let private aad = function
  | EnI8 -> [| Normal 0xD5uy |]
  | _ -> Utils.impossible ()

let private add = function
  | EnR8I8 | EnM8I8 -> [| Normal 0x80uy |]
  | EnR16I16 | EnR32I32 | EnR64I64
  | EnM16I16 | EnM32I32 | EnM64I64 -> [| Normal 0x81uy |]
  | EnM8R8 -> [| Normal 0x00uy |]
  | EnM16R16 | EnM32R32 | EnM64R64 -> [| Normal 0x01uy |]
  | EnR8R8 | EnR8M8 -> [| Normal 0x02uy |]
  | EnR16R16 | EnR32R32 | EnR64R64
  | EnR16M16 | EnR32M32 | EnR64M64 -> [| Normal 0x03uy |]
  | _ -> raise OperandTypeMismatchException

let private addps = function
  | EnXmXm | EnXmM128 -> [| Normal 0x0Fuy; Normal 0x58uy |]
  | _ -> raise OperandTypeMismatchException

let private addss = function
  | EnXmXm | EnXmM32 -> [| Normal 0xF3uy; Normal 0x0Fuy; Normal 0x58uy |]
  | _ -> raise OperandTypeMismatchException

let private bndmov = function
  | EnBnBM64 | EnBnBM128 ->
    [| Normal 0x66uy; Normal 0x0Fuy; Normal 0x1Auy |]
  | EnBM64Bn | EnBM128Bn ->
    [| Normal 0x66uy; Normal 0x0Fuy; Normal 0x1Buy |]
  | _ -> raise OperandTypeMismatchException

let private bt = function
  | EnR16R16 | EnR32R32 | EnR64R64
  | EnM16R16 | EnM32R32 | EnM64R64 -> [| Normal 0x0Fuy; Normal 0xA3uy |]
  | EnR16I8 | EnR32I8 | EnR64I8
  | EnM16I8 | EnM32I8 | EnM64I8 -> [| Normal 0x0Fuy; Normal 0xBAuy |]
  | _ -> raise OperandTypeMismatchException

let private clflush = function
  | EnM8 -> [| Normal 0x0Fuy; Normal 0xAEuy |]
  | _ -> raise OperandTypeMismatchException

let private cmppd = function
  | EnXmXmI8 _ | EnXmM128I8 -> [| Normal 0x66uy; Normal 0x0Fuy; Normal 0xC2uy |]
  | _ -> raise OperandTypeMismatchException

let private cmpss = function
  | EnXmXmI8 _ | EnXmM32I8 -> [| Normal 0xF3uy; Normal 0x0Fuy; Normal 0xC2uy |]
  | _ -> raise OperandTypeMismatchException

let private cmpxchgByte = function
  | EnM64 -> [| Normal 0x0Fuy; Normal 0xC7uy |]
  | EnM128 -> [| Normal 0x48uy; Normal 0x0Fuy; Normal 0xC7uy |]
  | _ -> raise OperandTypeMismatchException

let private comiss = function
  | EnXmXm | EnXmM32 -> [| Normal 0x0Fuy; Normal 0x2Fuy |]
  | _ -> raise OperandTypeMismatchException

let private crc32 = function
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
  | _ -> raise OperandTypeMismatchException

let private cvtpd2pi = function
  | EnMxXm | EnMxM128 -> [| Normal 0x66uy; Normal 0x0Fuy; Normal 0x2Duy |]
  | _ -> raise OperandTypeMismatchException

let private cvtpi2pd = function
  | EnXmMx | EnXmM64 -> [| Normal 0x66uy; Normal 0x0Fuy; Normal 0x2Auy |]
  | _ -> raise OperandTypeMismatchException

let private cvtsi2sd = function
  | EnXmR32 | EnXmM32 -> [| Normal 0xF2uy; Normal 0x0Fuy; Normal 0x2Auy |]
  | EnXmR64 | EnXmM64 ->
    [| Normal 0xF2uy; Normal 0x48uy; Normal 0x0Fuy; Normal 0x2Auy |]
  | _ -> raise OperandTypeMismatchException

let private cvttss2si = function
  | EnR32Xm | EnR32M32 -> [| Normal 0xF3uy; Normal 0x0Fuy; Normal 0x2Cuy |]
  | EnR64Xm | EnR64M32 ->
    [| Normal 0xF3uy; Normal 0x48uy; Normal 0x0Fuy; Normal 0x2Cuy |]
  | _ -> raise OperandTypeMismatchException

let private dec = function
  | EnR8 | EnM8 -> [| Normal 0xFEuy |]
  | EnR16 | EnM16 | EnR32 | EnM32 | EnR64 | EnM64 -> [| Normal 0xFFuy |]
  | _ -> raise OperandTypeMismatchException

let private enter = function
  | EnI16I8 -> [| Normal 0xC8uy |]
  | _ -> raise OperandTypeMismatchException

let private idiv = function
  | EnR8 | EnM8 -> [| Normal 0xF6uy |]
  | EnR16 | EnM16 | EnR32 | EnM32 | EnR64 | EnM64 -> [| Normal 0xF7uy |]
  | _ -> raise OperandTypeMismatchException

let private imul = function
  | EnR8 | EnM8 -> [| Normal 0xF6uy |]
  | EnR16 | EnM16 | EnR32 | EnM32 | EnR64 | EnM64 -> [| Normal 0xF7uy |]
  | EnR16R16 | EnR32R32 | EnR64R64
  | EnR16M16 | EnR32M32 | EnR64M64 -> [| Normal 0x0Fuy; Normal 0xAFuy |]
  | EnR16RM16I8 | EnR32RM32I8 | EnR64RM64I8 -> [| Normal 0x6Buy |]
  | EnR16RM16I16 | EnR32RM32I32 | EnR64RM64I32 -> [| Normal 0x69uy |]
  | _ -> raise OperandTypeMismatchException

let private input encType operands = // FIXME: Special Case
  match encType, operands with
  | EnR8I8, TwoOperands (OprReg Register.AL, OprImm _) -> [| Normal 0xE4uy |]
  | EnR16I8, TwoOperands (OprReg Register.AX, OprImm _)
  | EnR32I8, TwoOperands (OprReg Register.EAX, OprImm _) -> [| Normal 0xE5uy |]
  | EnR8R16, TwoOperands (OprReg Register.AL, OprReg Register.DX) ->
    [| Normal 0xECuy |]
  | EnR16R16, TwoOperands (OprReg Register.AX, OprReg Register.DX)
  | EnR32R16, TwoOperands (OprReg Register.EAX, OprReg Register.DX) ->
    [| Normal 0xEDuy |]
  | _ -> raise OperandTypeMismatchException

let private ldmxcsr = function
  | EnM32 -> [| Normal 0x0Fuy; Normal 0xAEuy |]
  | _ -> raise OperandTypeMismatchException

let private loadSegLimit = function
  | EnR16R16 | EnR16M16 | EnR32R32 | EnR32M16 | EnR64R32 | EnR64M16 ->
    [| Normal 0x0Fuy; Normal 0x03uy |]
  | _ -> raise OperandTypeMismatchException

let private jmp = function
  | EnR16 | EnM16 | EnR32 | EnM32 | EnR64 | EnM64 -> [| Normal 0xFFuy |]
  | EnLbl -> [| Normal 0xE9uy |] // FIXME: 0xEB(8bit) or 0xE9(32bit)
  | _ -> raise OperandTypeMismatchException

let private mov = function
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
  | _ -> raise OperandTypeMismatchException

let private movapd = function
  | EnXmXm | EnXmM128 -> [| Normal 0x66uy; Normal 0x0Fuy; Normal 0x28uy |]
  | EnM128Xm -> [| Normal 0x66uy; Normal 0x0Fuy; Normal 0x29uy |]
  | _ -> raise OperandTypeMismatchException

let private movd = function
  | EnMxR32 | EnMxM32-> [| Normal 0x0Fuy; Normal 0x6Euy |]
  | EnR32Mx | EnM32Mx-> [| Normal 0x0Fuy; Normal 0x7Euy |]
  | EnXmR32 | EnXmM32-> [| Normal 0x66uy; Normal 0x0Fuy; Normal 0x6Euy |]
  | EnR32Xm | EnM32Xm-> [| Normal 0x66uy; Normal 0x0Fuy; Normal 0x7Euy |]
  | _ -> Utils.impossible ()

let private movq = function
  | EnMxR64 -> [| Normal 0x48uy; Normal 0x0Fuy; Normal 0x6Euy |]
  | EnR64Mx -> [| Normal 0x48uy; Normal 0x0Fuy; Normal 0x7Euy |]
  | EnXmR64 -> [| Normal 0x66uy; Normal 0x48uy; Normal 0x0Fuy; Normal 0x6Euy |]
  | EnR64Xm -> [| Normal 0x66uy; Normal 0x48uy; Normal 0x0Fuy; Normal 0x7Euy |]
  | EnMxMx | EnMxM64 -> [| Normal 0x0Fuy; Normal 0x6Fuy |]
  | EnM64Mx -> [| Normal 0x0Fuy; Normal 0x7Fuy |]
  | EnXmXm | EnXmM64 -> [| Normal 0xF3uy; Normal 0x0Fuy; Normal 0x7Euy |]
  | EnM64Xm -> [| Normal 0x66uy; Normal 0x0Fuy; Normal 0xD6uy |]
  | _ -> Utils.impossible ()

let private movzx = function
  | EnR16R8 | EnR16M8 -> [| Normal 0x0Fuy; Normal 0xB6uy |]
  | EnR32R8 | EnR32M8 -> [| Normal 0x0Fuy; Normal 0xB6uy |]
  | EnR64R8 | EnR64M8 -> [| Normal 0x0Fuy; Normal 0xB6uy |]
  | EnR32R16 | EnR32M16 -> [| Normal 0x0Fuy; Normal 0xB7uy |]
  | EnR64R16 | EnR64M16 -> [| Normal 0x0Fuy; Normal 0xB7uy |]
  | _ -> raise OperandTypeMismatchException

let private out encType operands = // FIXME: Special Case
  match encType, operands with
  | EnI8AL, _ -> [| Normal 0xE6uy |]
  | EnI8AX, _ | EnI8EAX, _ -> [| Normal 0xE7uy |]
  | EnR16R8, TwoOperands (OprReg Register.DX, OprReg Register.AL) ->
    [| Normal 0xEEuy |]
  | EnR16R16, TwoOperands (OprReg Register.DX, OprReg Register.AX)
  | EnR16R32, TwoOperands (OprReg Register.DX, OprReg Register.EAX) ->
    [| Normal 0xEFuy |]
  | _ -> raise OperandTypeMismatchException

let private palignr = function
  | EnMxMM64I8 -> [| Normal 0x0Fuy; Normal 0x3Auy; Normal 0x0Fuy |]
  | EnXmXmI8 _ | EnXmM128I8 ->
    [| Normal 0x66uy; Normal 0x0Fuy; Normal 0x3Auy; Normal 0x0Fuy |]
  | _ -> raise OperandTypeMismatchException

let private pextrw = function
  | EnR32MxI8 | EnR64MxI8 -> [| Normal 0x0Fuy; Normal 0xC5uy |]
  | EnR32XmI8 | EnR64XmI8 -> [| Normal 0x66uy; Normal 0x0Fuy; Normal 0xC5uy |]
  | EnM16XmI8 ->
    [| Normal 0x66uy; Normal 0x0Fuy; Normal 0x3Auy; Normal 0x15uy |]
  | o -> printfn "%A" o; raise OperandTypeMismatchException

let private pinsrb = function
  | EnXmR32I8 | EnXmM8I8 ->
    [| Normal 0x66uy; Normal 0x0Fuy; Normal 0x3Auy; Normal 0x20uy |]
  | _ -> raise OperandTypeMismatchException

let private pinsrd = function
  | EnXmR32I8 | EnXmM32I8 ->
    [| Normal 0x66uy; Normal 0x0Fuy; Normal 0x3Auy; Normal 0x22uy |]
  | _ -> raise OperandTypeMismatchException

let private pinsrq = function
  | EnXmR64I8 | EnXmM64I8 -> [| Normal 0x66uy; Normal 0x48uy; Normal 0x0Fuy;
                                Normal 0x3Auy; Normal 0x22uy |]
  | _ -> raise OperandTypeMismatchException

let private pinsrw = function
  | EnMxR32I8 | EnMxM16I8 -> [| Normal 0x0Fuy; Normal 0xC4uy |]
  | EnXmR32I8 | EnXmM16I8 ->
    [| Normal 0x66uy; Normal 0x0Fuy; Normal 0xC4uy |]
  | _ -> raise OperandTypeMismatchException

let private pmovsxbq = function
  | EnXmXm | EnXmM16 ->
    [| Normal 0x66uy; Normal 0x0Fuy; Normal 0x38uy; Normal 0x22uy |]
  | _ -> raise OperandTypeMismatchException

let private pslld = function
  | EnMxMx | EnMxM64 -> [| Normal 0x0Fuy; Normal 0xF2uy |]
  | EnXmXm | EnXmM128-> [| Normal 0x66uy; Normal 0x0Fuy; Normal 0xF2uy |]
  | EnMxI8 -> [| Normal 0x0Fuy; Normal 0x72uy |]
  | EnXmI8 -> [| Normal 0x66uy; Normal 0x0Fuy; Normal 0x72uy |]
  | _ -> raise OperandTypeMismatchException

let private pslldq = function
  | EnXmI8 -> [| Normal 0x66uy; Normal 0x0Fuy; Normal 0x73uy |]
  | _ -> raise OperandTypeMismatchException

let private roundsd = function
  | EnXmXmI8 _ | EnXmM64I8 ->
    [| Normal 0x66uy; Normal 0x0Fuy; Normal 0x3Auy; Normal 0x0Buy |]
  | _ -> raise OperandTypeMismatchException

let private mulx = function // FIXME: REX prefix
  | EnR32R32RM32 r -> getThreeByteVEX REXPrefix.NOREX VEXType.VEXThreeByteOpOne
                        REXPrefix.NOREX (Some r) 32<rt> Prefix.PrxREPNZ 0xF6uy
  | EnR64R64RM64 r -> getThreeByteVEX REXPrefix.NOREX VEXType.VEXThreeByteOpOne
                        REXPrefix.REXW (Some r) 64<rt> Prefix.PrxREPNZ 0xF6uy
  | _ -> raise OperandTypeMismatchException

let private vaddps = function // FIXME: REX prefix
  | EnXmXmXm vvvv | EnXmXmM128 vvvv ->
    getTwoByteVEX REXPrefix.NOREX (Some vvvv) 128<rt> Prefix.PrxNone 0x58uy
  | EnYmYmYm vvvv | EnYmYmM256 vvvv ->
    getTwoByteVEX REXPrefix.NOREX (Some vvvv) 256<rt> Prefix.PrxNone 0x58uy
  | _ -> raise OperandTypeMismatchException

let private vaddss = function // FIXME: REX prefix
  | EnXmXmXm vvvv | EnXmXmM32 vvvv ->
    getTwoByteVEX REXPrefix.NOREX (Some vvvv) 128<rt> Prefix.PrxREPZ 0x58uy
  | _ -> raise OperandTypeMismatchException

let private vcvtsi2sd = function // FIXME: REX prefix
  | EnXmXmR32 vvvv | EnXmXmM32 vvvv ->
    getThreeByteVEX REXPrefix.NOREX VEXType.VEXTwoByteOp
      REXPrefix.NOREX (Some vvvv) 128<rt> Prefix.PrxREPNZ 0x2Auy
  | EnXmXmR64 vvvv | EnXmXmM64 vvvv ->
    getThreeByteVEX REXPrefix.NOREX VEXType.VEXTwoByteOp
      REXPrefix.REXW (Some vvvv) 128<rt> Prefix.PrxREPNZ 0x2Auy
  | _ -> raise OperandTypeMismatchException

let private vcvttss2si = function // FIXME: REX prefix
  | EnR32Xm | EnR32M32 -> getThreeByteVEX REXPrefix.NOREX VEXType.VEXTwoByteOp
                            REXPrefix.NOREX None 128<rt> Prefix.PrxREPZ 0x2Cuy
  | EnR64Xm | EnR64M32 -> getThreeByteVEX REXPrefix.NOREX VEXType.VEXTwoByteOp
                            REXPrefix.REXW None 128<rt> Prefix.PrxREPZ 0x2Cuy
  | _ -> raise OperandTypeMismatchException

let private vmovapd = function // FIXME: REX prefix
  | EnXmXm | EnXmM128 ->
    getTwoByteVEX REXPrefix.NOREX None 128<rt> Prefix.PrxOPSIZE 0x28uy
  | EnM128Xm ->
    getTwoByteVEX REXPrefix.NOREX None 128<rt> Prefix.PrxOPSIZE 0x29uy
  | EnYmYm | EnYmM256 ->
    getTwoByteVEX REXPrefix.NOREX None 256<rt> Prefix.PrxOPSIZE 0x28uy
  | EnM256Ym ->
    getTwoByteVEX REXPrefix.NOREX None 256<rt> Prefix.PrxOPSIZE 0x29uy
  | _ -> raise OperandTypeMismatchException

let private vmovd = function // FIXME: REX prefix
  | EnXmR32 | EnXmM32 ->
    getTwoByteVEX REXPrefix.NOREX None 128<rt> Prefix.PrxOPSIZE 0x6Euy
  | EnR32Xm | EnM32Xm ->
    getTwoByteVEX REXPrefix.NOREX None 128<rt> Prefix.PrxOPSIZE 0x7Euy
  | _ -> raise OperandTypeMismatchException

let private vmovq = function // FIXME: REX prefix
  | EnXmR64 | EnXmM64 -> getThreeByteVEX REXPrefix.NOREX VEXType.VEXTwoByteOp
                           REXPrefix.REXW None 128<rt> Prefix.PrxOPSIZE 0x6Euy
  | EnR64Xm -> getThreeByteVEX REXPrefix.NOREX VEXType.VEXTwoByteOp
                 REXPrefix.REXW None 128<rt> Prefix.PrxOPSIZE 0x7Euy
  | EnXmXm | EnXmM64 ->
    getTwoByteVEX REXPrefix.NOREX None 128<rt> Prefix.PrxREPZ 0x7Euy
  | EnM64Xm ->
    getTwoByteVEX REXPrefix.NOREX None 128<rt> Prefix.PrxOPSIZE 0xD6uy
  | _ -> raise OperandTypeMismatchException

let private vpalignr = function // FIXME: REX prefix
  | EnXmXmXM128I8 vvvv ->
    getThreeByteVEX REXPrefix.NOREX VEXType.VEXThreeByteOpTwo
      REXPrefix.NOREX (Some vvvv) 128<rt> Prefix.PrxOPSIZE 0x0Fuy
  | EnYmYmYM256I8 vvvv ->
    getThreeByteVEX REXPrefix.NOREX VEXType.VEXThreeByteOpTwo
      REXPrefix.NOREX (Some vvvv) 256<rt> Prefix.PrxOPSIZE 0x0Fuy
  | _ -> raise OperandTypeMismatchException

let private vpextrw = function // FIXME: REX prefix
  | EnR32XmI8 | EnR64XmI8 ->
    getThreeByteVEX REXPrefix.NOREX VEXType.VEXTwoByteOp
      REXPrefix.NOREX None 128<rt> Prefix.PrxOPSIZE 0xC5uy
  | EnM16XmI8 ->
    getThreeByteVEX REXPrefix.NOREX VEXType.VEXThreeByteOpTwo
      REXPrefix.NOREX None 128<rt> Prefix.PrxOPSIZE 0x15uy
  | _ -> raise OperandTypeMismatchException

let private vpinsrb = function // FIXME: REX prefix
  | EnXmXmR32I8 vvvv | EnXmXmM8I8 vvvv ->
    getThreeByteVEX REXPrefix.NOREX VEXType.VEXThreeByteOpTwo
      REXPrefix.NOREX (Some vvvv) 128<rt> Prefix.PrxOPSIZE 0x20uy
  | _ -> raise OperandTypeMismatchException

let private vpinsrw = function // FIXME: REX prefix
  | EnXmXmR32I8 vvvv | EnXmXmM16I8 vvvv ->
    getThreeByteVEX REXPrefix.NOREX VEXType.VEXTwoByteOp
      REXPrefix.NOREX (Some vvvv) 128<rt> Prefix.PrxOPSIZE 0xC4uy
  | _ -> raise OperandTypeMismatchException

let private vpmovsxbq = function // FIXME: REX prefix
  | EnXmXm | EnXmM16 ->
    getThreeByteVEX REXPrefix.NOREX VEXType.VEXThreeByteOpOne
      REXPrefix.NOREX None 128<rt> Prefix.PrxOPSIZE 0x22uy
  | _ -> raise OperandTypeMismatchException

let private vpslld = function // FIXME: REX prefix
  | EnXmXmXm vvvv | EnXmXmM128 vvvv ->
    getTwoByteVEX REXPrefix.NOREX (Some vvvv) 128<rt> Prefix.PrxOPSIZE 0xF2uy
  | EnYmYmXm vvvv | EnYmYmM128 vvvv ->
    getTwoByteVEX REXPrefix.NOREX (Some vvvv) 256<rt> Prefix.PrxOPSIZE 0xF2uy
  | EnXmXmI8 vvvv ->
    getTwoByteVEX REXPrefix.NOREX (Some vvvv) 128<rt> Prefix.PrxOPSIZE 0x72uy
  | EnYmYmI8 vvvv ->
    getTwoByteVEX REXPrefix.NOREX (Some vvvv) 256<rt> Prefix.PrxOPSIZE 0x72uy
  | _ -> raise OperandTypeMismatchException

let private vpslldq = function // FIXME: REX prefix
  | EnXmXmI8 reg ->
    getTwoByteVEX REXPrefix.NOREX (Some reg) 128<rt> Prefix.PrxOPSIZE 0x73uy
  | EnYmYmI8 reg ->
    getTwoByteVEX REXPrefix.NOREX (Some reg) 256<rt> Prefix.PrxOPSIZE 0x73uy
  | _ -> raise OperandTypeMismatchException

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

// vim: set tw=80 sts=2 sw=2:
