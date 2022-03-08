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

module internal B2R2.FrontEnd.BinLifter.ARM32.ParseUtils

open B2R2
open B2R2.FrontEnd.BinLifter.ARM32

let inline extract (binary: uint32) m n =
  (binary >>> n) &&& ((1u <<< (m - n + 1)) - 1u)

let inline pickTwo (binary: uint32) n =
  (binary >>> n) &&& 0b11u

let inline pickThree (binary: uint32) n =
  (binary >>> n) &&& 0b111u

let inline pickFour (binary: uint32) n =
  (binary >>> n) &&& 0b1111u

let inline pickFive (binary: uint32) n =
  (binary >>> n) &&& 0b11111u

let inline pickBit (binary: uint32) pos =
  (binary >>> pos) &&& 0b1u

let inline concat (n1: uint32) (n2: uint32) shift =
  (n1 <<< shift) + n2

let halve bin = struct (bin &&& 0x0000ffffu, bin >>> 16)

let align (x: uint64) (y: uint64) = y * (x / y)

/// The DecodeImmShift() function in the manual.
let decodeImmShift typ imm5 =
  match typ with
  | 0b00u -> struct (SRTypeLSL, imm5)
  | 0b01u -> struct (SRTypeLSR, if imm5 = 0ul then 32ul else imm5)
  | 0b10u -> struct (SRTypeASR, if imm5 = 0ul then 32ul else imm5)
  | 0b11u when imm5 = 0ul -> struct (SRTypeRRX, 1ul)
  | _ (* 0b11u *) -> struct (SRTypeROR, imm5)

/// The DecodeRegShift() function in the manual.
let decodeRegShift = function
  | 0b00u -> SRTypeLSL
  | 0b01u -> SRTypeLSR
  | 0b10u -> SRTypeASR
  | 0b11u -> SRTypeROR
  | _ -> Utils.impossible ()

/// Test if the current instruction is in an IT block.
let inITBlock itstate = List.isEmpty itstate |> not

/// Test if the current instruction is the last instruction of an IT block.
let lastInITBlock itstate = List.length itstate = 1

let parseCond = function
  | 0x0uy -> Condition.EQ
  | 0x1uy -> Condition.NE
  | 0x2uy -> Condition.CS
  | 0x3uy -> Condition.CC
  | 0x4uy -> Condition.MI
  | 0x5uy -> Condition.PL
  | 0x6uy -> Condition.VS
  | 0x7uy -> Condition.VC
  | 0x8uy -> Condition.HI
  | 0x9uy -> Condition.LS
  | 0xauy -> Condition.GE
  | 0xbuy -> Condition.LT
  | 0xcuy -> Condition.GT
  | 0xduy -> Condition.LE
  | 0xeuy -> Condition.AL
  | 0xfuy -> Condition.UN
  | _ -> failwith "Invalid condition"

/// The function SignExtend() in the manual.
let signExtend bitSize extSize (imm: uint64) =
  assert (bitSize <= extSize)
  if imm >>> (bitSize - 1) = 0b0UL then imm
  else
    BigInteger.getMask extSize - BigInteger.getMask bitSize ||| (bigint imm)
    |> uint64

let isUnconditional cond =
  match cond with
  | Condition.AL | Condition.UN -> true
  | _ -> false

// vim: set tw=80 sts=2 sw=2:
