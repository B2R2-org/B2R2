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

module internal B2R2.FrontEnd.ARM32.ParseUtils

open B2R2
open B2R2.FrontEnd.ARM32
open B2R2.FrontEnd

let extract binary n1 n2 =
  let m, n = if max n1 n2 = n1 then n1, n2 else n2, n1
  let range = m - n + 1u
  if range > 31u then failwith "invaild range" else ()
  let mask = pown 2 (int range) - 1 |> uint32
  binary >>> int n &&& mask

let pickBit binary (pos: uint32) = binary >>> int pos &&& 0b1u

let concat (n1: uint32) (n2: uint32) shift = (n1 <<< shift) + n2

let halve bin = bin &&& 0x0000ffffu, bin >>> 16

let align (x: uint64) (y: uint64) = y * (x / y)

/// The DecodeImmShift() function in the manual.
let decodeImmShift typ imm5 =
  match typ with
  | 0b00u -> SRTypeLSL, imm5
  | 0b01u -> SRTypeLSR, if imm5 = 0ul then 32ul else imm5
  | 0b10u -> SRTypeASR, if imm5 = 0ul then 32ul else imm5
  | 0b11u when imm5 = 0ul -> SRTypeRRX, 1ul
  | 0b11u -> SRTypeROR, imm5
  | _ -> raise InvalidTypeException

/// The DecodeRegShift() function in the manual.
let decodeRegShift = function
  | 0b00u -> SRTypeLSL
  | 0b01u -> SRTypeLSR
  | 0b10u -> SRTypeASR
  | 0b11u -> SRTypeROR
  | _ -> raise InvalidTypeException

/// Test if the current instruction is in an IT block.
let inITBlock (ctxt: ParsingContext) = List.isEmpty ctxt.ITState |> not

/// Test if the current instruction is the last instruction of an IT block.
let lastInITBlock (ctxt: ParsingContext) = List.length ctxt.ITState = 1

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

let private getThumbLen (reader: BinReader) pos =
  let b = reader.PeekUInt16 pos
  match b >>> 11 with
  | 0x1dus | 0x1eus | 0x1fus -> 4
  | _ -> 2

let getInstrLen reader offset = function
  | ArchOperationMode.ThumbMode -> getThumbLen reader offset |> uint64
  | ArchOperationMode.ARMMode -> 4UL
  | _ -> raise InvalidTargetArchModeException

let isUnconditional cond =
  match cond with
  | None
  | Some Condition.AL
  | Some Condition.UN -> true
  | _ -> false

// vim: set tw=80 sts=2 sw=2:
