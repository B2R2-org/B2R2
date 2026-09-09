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

/// <summary>
/// Turns the pieces of an instruction into the fields an eBPF encoding is built
/// from. Every function here rejects what does not fit rather than truncating
/// it, because a field that silently drops a bit encodes an instruction the
/// source did not ask for.
/// </summary>
module internal B2R2.Assembly.BPF.AsmField

open B2R2.FrontEnd.BPF
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.BPF.ParserHelper

/// <summary>
/// Represents one encoded eBPF word.
///
/// What is kept is the fields it is built from rather than the bytes it
/// becomes, because which nibble of the second byte names which register
/// follows the order the bytes are stored in, and that is not known here.
/// </summary>
type Word =
  { Code: uint32
    Dst: uint32
    Src: uint32
    Off: uint32
    Imm: uint32 }

/// Reports a source this assembler cannot encode.
let fail msg = raise <| EncodingFailureException msg

/// Reports operands that do not belong to the given mnemonic.
let wrongOperands (ins: AsmInsInfo) =
  fail $"{ins.Mnemonic} does not take these operands"

/// The four bits naming one of the registers a program computes with.
let gpr (reg: Register) =
  if reg >= Register.R0 && reg <= Register.R10 then uint32 (int reg)
  else fail $"{Register.toString reg} is not a register a program computes with"

/// <summary>
/// The bits a field reads as a signed number.
///
/// The disassembler writes such a number as the bits of the word it was widened
/// to rather than with a sign, so one below zero arrives here as its thirty-two
/// bit form whether the source wrote it that way or with a sign.
/// </summary>
let private signed width (value: uint64) =
  let v = int64 (int32 (uint32 value))
  let bound = 1L <<< (width - 1)
  if v >= -bound && v < bound then uint32 (uint64 v &&& ((1UL <<< width) - 1UL))
  else fail $"{v} does not fit in {width} signed bits"

/// The thirty-two bits an instruction holds where it carries a number.
let imm32 (value: uint64) =
  let truncated = uint32 value
  if uint64 truncated = value then truncated
  elif int64 (int32 truncated) = int64 value then truncated
  else fail $"0x{value:x} does not fit in thirty-two bits"

/// The sixteen bits a load or a store counts how far from what a register holds
/// to reach by.
let memDisp value = signed 16 value

/// <summary>
/// The sixteen bits a jump counts how far away the place it goes to is in.
///
/// What the encoding holds is that distance in instructions and what the
/// disassembler writes is the same distance in bytes, so a source writes bytes
/// either way and an instruction is eight of them.
/// </summary>
let jumpDisp (value: uint64) =
  let v = int64 value
  if v % 8L = 0L then signed 16 (uint64 (v / 8L))
  else fail "a jump reaches only a whole instruction away"

/// The thirty-two bits the two jumps reaching furthest count how far away the
/// place they go to is in, which they hold where every other instruction holds
/// a number.
let longJumpDisp (value: uint64) =
  let v = int64 value
  if v % 8L <> 0L then
    fail "a jump reaches only a whole instruction away"
  elif v / 8L < -2147483648L || v / 8L > 2147483647L then
    fail $"0x{value:x} is further away than a jump reaches"
  else
    uint32 (int32 (v / 8L))

/// The number a widening move reads to say how much of its source it reads,
/// which the encoding holds where a distance would sit.
let widenWidth allowWord (value: uint64) =
  match value with
  | 8UL | 16UL -> uint32 value
  | 32UL when allowWord -> uint32 value
  | _ -> fail $"nothing widens {value} bits"

/// A register operand.
let (|Rg|_|) = function
  | AsmReg reg -> Some reg
  | _ -> None

/// An operand that stands for a number.
let (|Im|_|) = function
  | AsmImm value -> Some value
  | _ -> None

/// The memory an instruction reaches, written as the register holding where to
/// start from and how far from there to reach.
let (|Mem|_|) = function
  | AsmMem(baseReg, disp) -> Some(baseReg, disp)
  | _ -> None

/// One word, given the byte naming the instruction and every field below it.
let word code dst src off imm =
  { Code = code; Dst = dst; Src = src; Off = off; Imm = imm }

/// One word naming nothing at all, every field an instruction does not use
/// being required to hold zero.
let bare code = word code 0u 0u 0u 0u

// vim: set tw=80 sts=2 sw=2:
