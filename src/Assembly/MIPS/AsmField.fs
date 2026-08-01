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
/// Turns the pieces of an instruction into the bit fields a MIPS encoding is
/// built from. Every function here rejects what does not fit rather than
/// truncating it, because a field that silently drops a bit encodes an
/// instruction the source did not ask for.
/// </summary>
module internal B2R2.Assembly.MIPS.AsmField

open B2R2
open B2R2.FrontEnd.MIPS
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.MIPS.ParserHelper

/// Reports a source this assembler cannot encode.
let fail msg = raise <| EncodingFailureException msg

/// Reports operands that do not belong to the given opcode.
let wrongOperands (ins: AsmInsInfo) =
  fail $"{ins.Opcode} does not take these operands"

/// The five bits that name one of the general registers.
let gpr (reg: Register) =
  if reg >= Register.R0 && reg <= Register.R31 then uint32 (int reg)
  else fail $"{reg} is not a general register"

/// The five bits that name one of the floating-point registers.
let fpr (reg: Register) =
  if reg >= Register.F0 && reg <= Register.F31 then
    uint32 (int reg - int Register.F0)
  else
    fail $"{reg} is not a floating-point register"

/// The bits a value takes where the field reads it as a count, which is every
/// field but the ones holding a distance or an offset.
let unsigned width (value: uint64) =
  if value < (1UL <<< width) then uint32 value
  else fail $"0x{value:x} does not fit in {width} bits"

/// The bits a value takes where the field reads it as a signed number.
let signed width (value: int64) =
  let bound = 1L <<< (width - 1)
  if value >= -bound && value < bound then
    uint32 (uint64 value &&& ((1UL <<< width) - 1UL))
  else
    fail $"{value} does not fit in {width} signed bits"

/// <summary>
/// The thirty-two bits a value takes where what the encoding holds is not the
/// value itself but what it and another one add up to.
///
/// A pair of fields saying where something starts and where it ends is read
/// back as where it starts and how long it is, and that reading is done in
/// thirty-two bits; so a length only makes sense once it has wrapped wherever
/// the pair of fields held an end below its own start, and a source writing
/// one asks for exactly the pair of fields that was read that way.
/// </summary>
let narrowed (value: uint64) =
  if value < 0x100000000UL then uint32 value
  else fail $"0x{value:x} does not fit in 32 bits"

/// <summary>
/// The sixteen bits an instruction taking a signed immediate holds.
///
/// The disassembler prints such an immediate as the whole register it lands
/// in, which is the sixteen bits of it spread over sixty-four, so what arrives
/// here is that number rather than the field.
/// </summary>
let immediate16 (value: uint64) = signed 16 (int64 value)

/// <summary>
/// The sixteen bits a branch holds: how far the place it names is from the
/// instruction after it, counted in instructions.
/// </summary>
let branchOffset (distance: int64) =
  if distance % 4L = 0L then signed 16 ((distance - 4L) / 4L)
  else fail "a branch cannot reach a place that is not a whole word away"

/// <summary>
/// The twenty-six bits a jump holds, which name one word of the region the
/// jump sits in. What lies above those bits is taken from the address the
/// jump itself is at, so a jump cannot leave its own region.
/// </summary>
let jumpTarget (target: uint64) =
  if target % 4UL <> 0UL then
    fail "a jump cannot reach a place that is not a whole word away"
  elif target >= 0x10000000UL then
    fail $"0x{target:x} lies outside the region a jump can name"
  else
    uint32 (target >>> 2)

/// The word of the region a place lies in, which is what a jump to it holds.
/// A place in another region is one no jump reaches.
let region (pc: Addr) (target: Addr) =
  if (pc >>> 28) = (target >>> 28) then target &&& 0x0fffffffUL
  else fail $"0x{target:x} lies outside the region 0x{pc:x} sits in"

/// A register operand.
let (|Rg|_|) = function
  | OpReg reg -> Some reg
  | _ -> None

/// An operand that stands for a number, whichever kind of number it is. The
/// disassembler tells a shift distance from an immediate, but a source writes
/// the two the same way.
let (|Im|_|) = function
  | OpImm value | OpShiftAmount value -> Some value
  | _ -> None

/// Memory read at a written distance from a register.
let (|Mem|_|) = function
  | OpMem(baseReg, Imm offset, _) -> Some(baseReg, offset)
  | _ -> None

/// Memory read at a distance another register holds.
let (|MemIdx|_|) = function
  | OpMem(baseReg, Reg index, _) -> Some(baseReg, index)
  | _ -> None

/// A place the instruction names, which arrives here as the distance to it.
let (|Place|_|) = function
  | OpAddr(Relative distance) -> Some distance
  | _ -> None

/// One word, given what each of its six fields holds.
let word (op: uint32) rs rt rd sa func =
  (op <<< 26) ||| (rs <<< 21) ||| (rt <<< 16) ||| (rd <<< 11) ||| (sa <<< 6)
  ||| func

/// One word of the kind whose lower half is a single number rather than the
/// four fields the other kinds divide it into.
let immWord (op: uint32) rs rt imm =
  (op <<< 26) ||| (rs <<< 21) ||| (rt <<< 16) ||| imm
