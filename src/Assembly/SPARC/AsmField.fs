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
/// Turns the pieces of an instruction into the bit fields a SPARC encoding is
/// built from. Every function here rejects what does not fit rather than
/// truncating it, because a field that silently drops a bit encodes an
/// instruction the source did not ask for.
/// </summary>
module internal B2R2.Assembly.SPARC.AsmField

open B2R2.FrontEnd.SPARC
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.SPARC.ParserHelper

/// Reports a source this assembler cannot encode.
let fail msg = raise <| EncodingFailureException msg

/// Reports operands that do not belong to the given mnemonic.
let wrongOperands (ins: AsmInsInfo) =
  fail $"{ins.Mnemonic} does not take these operands"

/// <summary>
/// Tries one encoding and falls back on another where the first does not fit.
///
/// The disassembler writes several instructions under one name, so a name on
/// its own does not say which instruction a line is; the forms that share a
/// name are tried in turn, and the one whose operands fit is the one meant.
/// </summary>
let orTry first second ins =
  try first ins with EncodingFailureException _ -> second ins

/// <summary>
/// The number a floating-point register is known by, which is not the number
/// its name holds.
///
/// The registers past the thirty-second are only ever named in pairs, so the
/// enumeration keeps every other one of them and their names count by twos.
/// </summary>
let private numberOf (reg: Register) =
  if reg >= Register.F0 && reg <= Register.F31 then
    int reg - int Register.F0
  elif reg >= Register.F32 && reg <= Register.F62 then
    32 + 2 * (int reg - int Register.F32)
  else
    -1

/// The five bits that name one of the general registers.
let gpr (reg: Register) =
  if reg >= Register.G0 && reg <= Register.I7 then uint32 (int reg)
  else fail $"{Register.toString reg} is not a general register"

/// The five bits naming the register a single-precision number lands in, which
/// is one of the first thirty-two.
let single (reg: Register) =
  let n = numberOf reg
  if n >= 0 && n <= 31 then uint32 n
  else fail $"{Register.toString reg} holds no single-precision number"

/// <summary>
/// The five bits naming the pair a double-precision number lands in.
///
/// A pair is named by the first register of it, so only the even ones name
/// one; the pairs above the thirty-second are named by the bit that would say
/// which half of a pair a register is, which is free because no pair starts at
/// an odd register.
/// </summary>
let double (reg: Register) =
  let n = numberOf reg
  if n < 0 || n % 2 <> 0 then
    fail $"{Register.toString reg} holds no double-precision number"
  elif n <= 30 then
    uint32 n
  else
    uint32 (n - 31)

/// The five bits naming the four registers a quad-precision number lands in,
/// which are named the way a pair is and start every fourth register.
let quad (reg: Register) =
  let n = numberOf reg
  if n < 0 || n % 4 <> 0 then
    fail $"{Register.toString reg} holds no quad-precision number"
  elif n <= 28 then
    uint32 n
  else
    uint32 (n - 31)

/// <summary>
/// The bits a field reads as a signed number.
///
/// The disassembler writes such a number as the whole word it was widened to
/// rather than with a sign, so one below zero arrives as its thirty-two bit
/// form whether the source wrote it that way or with a sign.
/// </summary>
let private signed width (value: uint64) =
  let v = int64 (int32 (uint32 value))
  let bound = 1L <<< (width - 1)
  if v >= -bound && v < bound then uint32 (uint64 v &&& ((1UL <<< width) - 1UL))
  else fail $"{v} does not fit in {width} signed bits"

/// The bits a field reads as a count, which is every field but the ones
/// holding a distance or a signed number.
let private unsigned width (value: uint64) =
  if value < (1UL <<< width) then uint32 value
  else fail $"0x{value:x} does not fit in {width} bits"

/// The thirteen bits an instruction computing from a written number holds.
let simm13 (value: uint64) = signed 13 value

/// The eleven bits the move on a condition holds where it moves a number.
let simm11 (value: uint64) = signed 11 value

/// The ten bits the move on what a register holds holds where it moves a
/// number.
let simm10 (value: uint64) = signed 10 value

/// How far a shift of a word goes, which is never further than a word is wide.
let shcnt32 (value: uint64) = unsigned 5 value

/// How far a shift of a doubleword goes.
let shcnt64 (value: uint64) = unsigned 6 value

/// The number a trap carries, which the machine adds to where it traps to.
let trapNumber (value: uint64) = unsigned 8 value

/// Which of the address spaces an instruction naming one reaches.
let immAsi (value: uint64) = unsigned 8 value

/// What a memory barrier keeps on either side of itself, which is written as
/// one number holding both of the masks the encoding keeps apart.
let membarMask (value: uint64) = unsigned 4 value

/// The whole of what the instruction reserved for the machine to trap on
/// carries.
let const22 (value: uint64) = unsigned 22 value

/// <summary>
/// The twenty-two bits the instruction building an address holds.
///
/// What it builds is the upper part of an address and the lower ten bits of
/// what it writes are zero, so the disassembler writes the address itself
/// rather than the field, and the field is read back out of it here.
/// </summary>
let hi22 (value: uint64) =
  if value < 0x100000000UL && value % 0x400UL = 0UL then uint32 (value >>> 10)
  else fail $"0x{value:x} is not the upper part of an address"

/// <summary>
/// The bits an instruction left to the machine it runs on carries.
///
/// They lie on either side of the field naming a register, and the
/// disassembler writes the two pieces as the one number they stand for.
/// </summary>
let implDep (value: uint64) =
  if value < 0x1000000UL then
    (uint32 (value >>> 19) <<< 25) ||| uint32 (value &&& 0x7FFFFUL)
  else
    fail $"0x{value:x} is more than an implementation-dependent word holds"

/// <summary>
/// The bits an instruction holds where it counts how far away the place it
/// names is.
///
/// What the encoding holds is that distance in words and what the disassembler
/// writes is the same distance in bytes, so a source writes bytes either way.
/// </summary>
let private distance width (value: uint64) =
  let v = int32 (uint32 value)
  if v % 4 = 0 then signed width (uint64 (uint32 (v / 4)))
  else fail "a branch reaches only a whole word away"

/// How far the branch reading no condition bits goes.
let disp22 (value: uint64) = distance 22 value

/// How far the branch reading a set of condition bits goes.
let disp19 (value: uint64) = distance 19 value

/// How far the branch on what a register holds goes.
let disp16 (value: uint64) = distance 16 value

/// How far the call goes, which reaches further than any branch.
let disp30 (value: uint64) = distance 30 value

/// <summary>
/// The three bits naming which set of condition bits an instruction reads.
///
/// The uppermost of them says whether the set holds what a comparison of
/// integers left or what a comparison of floating-point numbers left, and the
/// two below it say which set of that kind it is.
/// </summary>
let ccThree = function
  | ConditionCode.Fcc0 -> 0u
  | ConditionCode.Fcc1 -> 1u
  | ConditionCode.Fcc2 -> 2u
  | ConditionCode.Fcc3 -> 3u
  | ConditionCode.Icc -> 4u
  | ConditionCode.Xcc -> 6u
  | cc -> fail $"{cc} is not a set of condition bits"

/// Whether the set of condition bits holds what a comparison of integers left,
/// which is what says which of the two tables a condition is named out of.
let isIntegerCC cc = cc = ConditionCode.Icc || cc = ConditionCode.Xcc

/// The two bits naming one of the two sets of condition bits a comparison of
/// integers leaves.
let integerCC = function
  | ConditionCode.Icc -> 0u
  | ConditionCode.Xcc -> 2u
  | cc -> fail $"{cc} holds nothing a comparison of integers left"

/// The two bits naming one of the four sets of condition bits a comparison of
/// floating-point numbers leaves.
let floatCC = function
  | ConditionCode.Fcc0 -> 0u
  | ConditionCode.Fcc1 -> 1u
  | ConditionCode.Fcc2 -> 2u
  | ConditionCode.Fcc3 -> 3u
  | cc -> fail $"{cc} holds nothing a comparison of floating-point numbers left"

/// A register operand.
let (|Rg|_|) = function
  | AsmReg reg -> Some reg
  | _ -> None

/// An operand that stands for a number.
let (|Im|_|) = function
  | AsmImm value -> Some value
  | _ -> None

/// An operand naming a set of condition bits.
let (|Cc|_|) = function
  | AsmCC cc -> Some cc
  | _ -> None

/// The memory an instruction reaches.
let (|Mem|_|) = function
  | AsmMem(baseReg, index) -> Some(baseReg, index)
  | _ -> None

/// The upper part of an address.
let (|Hi|_|) = function
  | AsmHi value -> Some value
  | _ -> None

/// One word of the kind whose lower twenty-two bits are a single number, which
/// is how the branches, the call and the instruction building an address are
/// written. The two bits such a word begins with are zero, so nothing sets
/// them.
let format2 (rd: uint32) op2 (imm22: uint32) =
  (rd <<< 25) ||| (op2 <<< 22) ||| imm22

/// One word of the kind computing from what registers hold, which is how
/// everything else is written. What lies below the field naming the first
/// register differs from one instruction to the next and is built by the
/// caller.
let format3 (op: uint32) op3 rd rs1 (rest: uint32) =
  (op <<< 30) ||| (rd <<< 25) ||| (op3 <<< 19) ||| (rs1 <<< 14) ||| rest

/// <summary>
/// The fourteen bits below the field naming the first register, where what
/// they hold is either a second register or a written number.
///
/// Which of the two it is, is what the bit above them says, so the bit is part
/// of what is built here rather than of the instruction that asks for it.
/// </summary>
let rs2OrImm = function
  | AsmReg reg -> gpr reg
  | AsmImm value -> (1u <<< 13) ||| simm13 value
  | _ -> fail "this is neither a register nor a number"

/// The same, where the number an instruction moving on a condition holds is
/// two bits narrower because the condition itself lies above it.
let rs2OrSimm11 = function
  | AsmReg reg -> gpr reg
  | AsmImm value -> (1u <<< 13) ||| simm11 value
  | _ -> fail "this is neither a register nor a number"

/// The same, where the number an instruction moving on what a register holds
/// holds is narrower again.
let rs2OrSimm10 = function
  | AsmReg reg -> gpr reg
  | AsmImm value -> (1u <<< 13) ||| simm10 value
  | _ -> fail "this is neither a register nor a number"

/// <summary>
/// The register the memory an instruction reaches is counted from, and the
/// bits saying what is added to it.
///
/// What is added is either a second register or a written number, and where a
/// source writes neither, nothing is added.
/// </summary>
let address = function
  | AsmMem(baseReg, Some index) -> gpr baseReg, rs2OrImm index
  | AsmMem(baseReg, None) -> gpr baseReg, 0u
  | _ -> fail "this does not name memory"

/// <summary>
/// The same, for the instructions naming which address space they reach.
///
/// The space is written as a number where the memory is reached at a distance
/// held in a register, and as the register holding the space where it is
/// reached at a written distance, because the one field holds the distance and
/// the space both.
/// </summary>
let alternateAddress mem asi =
  match mem, asi with
  | AsmMem(baseReg, Some(AsmReg index)), AsmImm space ->
    gpr baseReg, (immAsi space <<< 5) ||| gpr index
  | AsmMem(baseReg, Some(AsmImm offset)), AsmReg Register.ASI ->
    gpr baseReg, (1u <<< 13) ||| simm13 offset
  | AsmMem(baseReg, None), AsmImm space ->
    gpr baseReg, immAsi space <<< 5
  | AsmMem(baseReg, None), AsmReg Register.ASI ->
    gpr baseReg, 1u <<< 13
  | _ ->
    fail "this does not name memory in an address space"

// vim: set tw=80 sts=2 sw=2:
