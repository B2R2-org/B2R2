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
/// Turns the pieces of an instruction into the bit fields a PPC encoding is
/// built from. Every function here rejects what does not fit rather than
/// truncating it, because a field that silently drops a bit encodes an
/// instruction the source did not ask for.
/// </summary>
module internal B2R2.Assembly.PPC.AsmField

open B2R2
open B2R2.FrontEnd.PPC
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.PPC.ParserHelper

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

/// The five bits that name one of the vector registers.
let vr (reg: Register) =
  if reg >= Register.V0A && reg <= Register.V31B then
    uint32 ((int reg - int Register.V0A) / 2)
  else
    fail $"{reg} is not a vector register"

/// <summary>
/// The six bits that name one of the vector-scalar registers.
///
/// The lower half of that space is the floating-point registers widened and the
/// upper half is the vector registers outright, so which register a source
/// wrote says which half of the space it meant.
/// </summary>
let vsr (reg: Register) =
  if reg >= Register.F0 && reg <= Register.F31 then
    uint32 (int reg - int Register.F0)
  elif reg >= Register.V0A && reg <= Register.V31B then
    uint32 ((int reg - int Register.V0A) / 2) + 32u
  else
    fail $"{reg} is not a vector-scalar register"

/// The three bits that name one field of the condition register.
let crf (reg: Register) =
  if reg >= Register.CR0 && reg <= Register.CR7 then
    uint32 (int reg - int Register.CR0)
  else
    fail $"{reg} is not a condition register field"

/// The bits a value takes where the field reads it as a count, which is every
/// field but the ones holding a distance or a signed number.
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
/// What a written number stands for where the field it lands in reads it as
/// signed.
///
/// The disassembler prints such a number as the whole register it lands in,
/// which is as wide as the source; a source of its own may write it with a sign
/// instead, and that reaches here as its sixty-four bit form. Both are read
/// here, because a number wider than the source is one only a sign could have
/// written.
/// </summary>
let signedValue bitLen (value: uint64) =
  if bitLen >= 64 then
    int64 value
  else
    let mask = (1UL <<< bitLen) - 1UL
    if (value &&& ~~~mask) <> 0UL then int64 value
    elif (value &&& (1UL <<< (bitLen - 1))) = 0UL then int64 value
    else int64 (value ||| ~~~mask)

/// The sixteen bits an instruction taking a signed immediate holds.
let immediate16 bitLen value = signed 16 (signedValue bitLen value)

/// The sixteen bits an instruction taking an unsigned immediate holds.
let uimmediate16 (value: uint64) = unsigned 16 value

/// The sixteen bits a memory operand holds, which is how far from what the base
/// register holds the access is.
let displacement (disp: int32) = signed 16 (int64 disp)

/// The same, where the encoding leaves out the two lowest bits of the distance
/// because what it reaches is always a whole word.
let wordDisplacement (disp: int32) =
  if disp % 4 = 0 then signed 16 (int64 disp)
  else fail "this access cannot reach a place that is not a whole word away"

/// The bits a branch holds where it counts how far away the place it names is.
/// The two bits below that distance belong to the branch rather than to it, so
/// they come out zero and whatever the branch keeps there may be laid over
/// them.
let relativeTarget width bitLen (pc: Addr) (target: uint64) =
  let distance = signedValue bitLen (target - pc)
  if distance % 4L = 0L then signed width distance
  else fail "a branch cannot reach a place that is not a whole word away"

/// The bits a branch holds where it names its place outright, which is where to
/// go rather than how far away it is.
let absoluteTarget width bitLen target =
  let value = signedValue bitLen target
  if value % 4L = 0L then signed width value
  else fail "a branch cannot reach a place that is not a whole word away"

/// <summary>
/// The two halves the field naming a special register is written in.
///
/// The encoding keeps that field the other way round from how it is read: the
/// five bits above the register number hold the low half of the name and the
/// five below it the high half.
/// </summary>
let specialRegister (value: uint64) =
  let spr = unsigned 10 value
  ((spr &&& 0x1Fu) <<< 16) ||| ((spr >>> 5) <<< 11)

/// A register operand.
let (|Rg|_|) = function
  | AsmReg reg -> Some reg
  | _ -> None

/// An operand that stands for a number.
let (|Im|_|) = function
  | AsmImm value -> Some value
  | _ -> None

/// Memory read at a written distance from a register.
let (|Mem|_|) = function
  | AsmMem(disp, baseReg) -> Some(disp, baseReg)
  | _ -> None

/// <summary>
/// One bit of the condition register.
///
/// The disassembler writes such a bit as the field it lies in and which of that
/// field's bits it is, and a source may write the number those two add up to
/// instead, so both are read here.
/// </summary>
let (|Bit|_|) = function
  | AsmBit value -> Some value
  | AsmImm value -> Some(unsigned 5 value)
  | _ -> None

/// One word, given the primary opcode, what each of its three register fields
/// holds, and what fills the eleven bits below them.
let word (po: uint32) d a b rest =
  (po <<< 26) ||| (d <<< 21) ||| (a <<< 16) ||| (b <<< 11) ||| rest

/// One word of the kind whose lower half is a single number rather than a
/// register and the fields below it.
let dForm (po: uint32) d a (imm: uint32) =
  (po <<< 26) ||| (d <<< 21) ||| (a <<< 16) ||| imm

/// One word of the kind whose eleven lowest bits are an extended opcode and the
/// bit saying whether the instruction records what it did.
let xForm po d a b xo rc = word po d a b ((xo <<< 1) ||| rc)

/// One word of the kind that names a fourth register where an X-form keeps the
/// top of its extended opcode.
let aForm po d a b c xo rc = word po d a b ((c <<< 6) ||| (xo <<< 1) ||| rc)

/// The two names an instruction whose record bit is written into its name goes
/// by, given the form it takes and its extended opcode.
let recording form xo plain dot = [ plain, form xo 0u; dot, form xo 1u ]
