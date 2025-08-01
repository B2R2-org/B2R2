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

module internal B2R2.FrontEnd.AVR.OperandHelper

open B2R2.FrontEnd.BinLifter
open type Register

let getRegister = function
  | 0x0uy -> R0
  | 0x1uy -> R1
  | 0x2uy -> R2
  | 0x3uy -> R3
  | 0x4uy -> R4
  | 0x5uy -> R5
  | 0x6uy -> R6
  | 0x7uy -> R7
  | 0x8uy -> R8
  | 0x9uy -> R9
  | 0xAuy -> R10
  | 0xBuy -> R11
  | 0xCuy -> R12
  | 0xDuy -> R13
  | 0xEuy -> R14
  | 0xFuy -> R15
  | 0x10uy -> R16
  | 0x11uy -> R17
  | 0x12uy -> R18
  | 0x13uy -> R19
  | 0x14uy -> R20
  | 0x15uy -> R21
  | 0x16uy -> R22
  | 0x17uy -> R23
  | 0x18uy -> R24
  | 0x19uy -> R25
  | 0x1Auy -> R26
  | 0x1Buy -> R27
  | 0x1Cuy -> R28
  | 0x1Duy -> R29
  | 0x1Euy -> R30
  | 0x1Fuy -> R31
  | 0x20uy -> X
  | 0x21uy -> Y
  | 0x22uy -> Z
  | _ -> raise InvalidRegisterException

let memPreIdx offset = OprMemory(PreIdxMode(offset))

let memPostIdx offset = OprMemory(PostIdxMode(offset))

let memDisp offset = OprMemory(DispMode(offset))

let memUnch offset = OprMemory(UnchMode(offset))

let extract binary n1 n2 =
  let m, n = if max n1 n2 = n1 then n1, n2 else n2, n1
  let range = m - n + 1u
  assert (range <= 31u)
  let mask = pown 2 (int range) - 1 |> uint32
  binary >>> int n &&& mask

let extract16 binary n1 n2 =
  let m, n = if max n1 n2 = n1 then n1, n2 else n2, n1
  let range = m - n + 1us
  assert (range <= 31us)
  let mask = pown 2 (int range) - 1 |> uint16
  binary >>> int n &&& mask

let pickBit binary (pos: uint32) = binary >>> int pos &&& 0b1u

let concat (n1: uint32) (n2: uint32) shift = (n1 <<< shift) + n2

let parseOneOpr b op1 = OneOperand(op1 b)

let parseTwoOpr b op1 op2 = TwoOperands(op1 b, op2 b)

let getReg b s e = getRegister (extract b s e |> byte)

let getRegD b = getReg b 8u 4u |> OprReg

let getReg2D b = getRegister (24u + 2u * (extract b 5u 4u) |> byte) |> OprReg

let getReg3D b = getRegister (16u + (extract b 6u 4u) |> byte) |> OprReg

let getReg3DLast b = getRegister (16u + (extract b 2u 0u) |> byte) |> OprReg

let getReg4D b = getRegister (extract b 7u 4u + 16u |> byte) |> OprReg

let getRegEven4D b = getRegister (2u * (extract b 7u 4u) |> byte) |> OprReg

let getRegEvenEnd4D b = getRegister (2u * (extract b 3u 0u) |> byte) |> OprReg

let getRegR b =
  getRegister (concat (pickBit b 9u) (b &&& 0b1111u) 4 |> byte) |> OprReg

let getRegD32 b = getReg b 24u 20u |> OprReg

let getConst4K b = extract b 7u 4u |> int32 |> OprImm

let getConst6K b = concat (extract b 7u 6u) (b &&& 0b1111u) 4 |> int32 |> OprImm

let getConst8K b =
  concat (extract b 11u 8u) (b &&& 0b1111u) 4 |> int32 |> OprImm

let getConst3b b = b &&& 0b111u |> int32 |> OprImm

let getConst3bs b = extract b 6u 4u |> int32 |> OprImm

let getConst22 b =
  (2u * concat (extract b 24u 20u) (extract b 16u 0u) (17)) |> int32 |> OprAddr

let getConst16 b = extract b 15u 0u |> int32 |> OprAddr

let getIO5 b = extract b 7u 3u |> int32 |> OprImm

let getIO6 b = concat (extract b 10u 9u) (b &&& 0b1111u) 4 |> int32 |> OprImm

let getAddr7K b = ((extract b 9u 3u) <<< 25 |> int32 >>> 25) * 2 |> OprAddr

let getAddr12 b = ((extract b 11u 0u) <<< 20 |> int32 >>> 20) * 2 |> OprAddr

let getDisp b =
  concat (concat (pickBit b 13u) (extract b 11u 10u) (2)) (b &&& 0b111u) 3
  |> int32

let getMemDispY b =
  let disp = getDisp b
  memDisp (Y, disp)

let getMemDispZ b =
  let disp = getDisp b
  memDisp (Z, disp)

let getMemLDD b =
  match b &&& 0b1111u with
  | 0b1100u -> memUnch X
  | 0b1101u -> memPostIdx X
  | 0b1110u -> memPreIdx X
  | 0b1000u -> memUnch Y
  | 0b1001u -> memPostIdx Y
  | 0b1010u -> memPreIdx Y
  | 0b0000u -> memUnch Z
  | 0b0001u -> memPostIdx Z
  | 0b0010u -> memPreIdx Z
  | 0b0110u -> memUnch Z
  | 0b0111u -> memPostIdx Z
  | 0b0100u -> memUnch Z
  | _ -> memPostIdx Z // 0101

let getMemST b =
  match b &&& 0b1111u with
  | 0b1100u -> memUnch X
  | 0b1101u -> memPostIdx X
  | 0b1110u -> memPreIdx X
  | 0b1000u -> memUnch Y
  | 0b1001u -> memPostIdx Y
  | 0b1010u -> memPreIdx Y
  | 0b0000u -> memUnch Z
  | 0b0001u -> memPostIdx Z
  | _ -> memPreIdx Z //0010
