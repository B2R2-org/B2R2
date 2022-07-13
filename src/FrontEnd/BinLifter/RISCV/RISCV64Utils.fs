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
module internal B2R2.FrontEnd.BinLifter.RISCV.Utils

open B2R2

let extract binary n1 n2 =
  let m, n = if max n1 n2 = n1 then n1, n2 else n2, n1
  let range = m - n + 1u
  if range > 31u then failwith "invaild range" else ()
  let mask = pown 2 (int range) - 1 |> uint32
  binary >>> int n &&& mask

let pickBit8 (binary: uint8) (pos: uint32) = binary >>> int pos &&& 0b1uy

let pickBit binary (pos: uint32) = binary >>> int pos &&& 0b1u

let signExtend bitSize extSize (imm: uint64) =
  assert (bitSize <= extSize)
  if imm >>> (bitSize - 1) = 0b0UL then imm
  else BigInteger.getMask extSize - BigInteger.getMask bitSize ||| (bigint imm)
       |> uint64
