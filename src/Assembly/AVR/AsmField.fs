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
/// Turns the pieces of an instruction into the bit fields an AVR encoding is
/// built from. Every function here rejects what does not fit rather than
/// truncating it, because a field that silently drops a bit encodes an
/// instruction the source did not ask for.
/// </summary>
module internal B2R2.Assembly.AVR.AsmField

open B2R2
open B2R2.FrontEnd.AVR
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.AVR.ParserHelper

/// Reports a source this assembler cannot encode.
let fail msg = raise <| EncodingFailureException msg

/// Reports operands that do not belong to the given mnemonic.
let wrongOperands (ins: AsmInsInfo) =
  fail $"{ins.Mnemonic} does not take these operands"

/// The number one of a run of registers is known by, given the first and the
/// last of the run, or nothing where the register lies outside it.
let private indexIn first last (reg: Register) =
  if reg >= first && reg <= last then Some(int reg - int first) else None

/// The five bits naming one of the thirty-two registers a program computes
/// with.
let gpr (reg: Register) =
  match indexIn Register.R0 Register.R31 reg with
  | Some n -> uint16 n
  | None -> fail $"{Register.toString reg} is not a general register"

/// <summary>
/// The four bits naming one of the upper half of the file.
///
/// An instruction computing from a written number spends eight of its bits on
/// that number, which leaves it four for the register and so only half the file
/// to reach.
/// </summary>
let upperReg (reg: Register) =
  match indexIn Register.R16 Register.R31 reg with
  | Some n -> uint16 n
  | None -> fail $"{Register.toString reg} is not one of r16 to r31"

/// The three bits naming one of the first eight of that upper half, which is as
/// far as the multiplications keeping their arguments narrow reach.
let mulReg (reg: Register) =
  match indexIn Register.R16 Register.R23 reg with
  | Some n -> uint16 n
  | None -> fail $"{Register.toString reg} is not one of r16 to r23"

/// <summary>
/// The four bits naming the pair a whole word lands in.
///
/// A pair is named by the first register of it, so the names count by twos and
/// the field counts by ones, and a register at an odd number begins no pair.
/// </summary>
let evenReg (reg: Register) =
  match indexIn Register.R0 Register.R31 reg with
  | Some n when n % 2 = 0 -> uint16 (n / 2)
  | Some _ | None -> fail $"{Register.toString reg} begins no register pair"

/// The two bits naming one of the four pairs an instruction adding a written
/// number to a whole word reaches, which are the last four pairs of the file.
let wordReg (reg: Register) =
  match indexIn Register.R24 Register.R31 reg with
  | Some n when n % 2 = 0 -> uint16 (n / 2)
  | Some _ | None -> fail $"{Register.toString reg} begins no upper word"

/// The bits a field holding a count of something holds, which is never below
/// zero.
let private unsigned width (value: int32) =
  if value >= 0 && value < (1 <<< width) then uint16 value
  else fail $"{value} does not fit in {width} bits"

/// <summary>
/// The bits a field holds where what it holds may be written either way.
///
/// The disassembler writes a byte-wide number as the byte itself, which is
/// never below zero; a source of its own may write what that byte stands for
/// where an instruction reads it as signed, which is. Both are read here.
/// </summary>
let private either width (value: int32) =
  let bound = 1 <<< (width - 1)
  if value >= -bound && value < bound * 2 then
    uint16 (value &&& ((1 <<< width) - 1))
  else
    fail $"{value} does not fit in {width} bits"

/// The byte an instruction computing from a written number holds.
let imm8 value = either 8 value

/// A number six bits wide: what is added to a whole word, where in the space of
/// the peripherals an instruction reaches, and how far from an index register
/// the memory a load or a store reaches lies.
let imm6 value = unsigned 6 value

/// The same, five bits wide, which is as far into the space of the peripherals
/// as the instructions working on a single bit of it reach.
let imm5 value = unsigned 5 value

/// The same, four bits wide, which is what the one instruction encrypting a
/// block holds to say which round of it to run.
let imm4 value = unsigned 4 value

/// Which bit of a byte or of a status word an instruction works on.
let imm3 value = unsigned 3 value

/// <summary>
/// How many words away the place a branch names lies, given how many bits the
/// branch has to say it in.
///
/// AVR counts from the address just past the branch, and in words rather than
/// in bytes, so a place at an odd address is one no branch can name.
/// </summary>
let private wordsAway width (ins: AsmInsInfo) (distance: int64) =
  let bound = 1L <<< (width - 1)
  if distance % 2L <> 0L then
    fail "a branch reaches only an even address"
  elif distance / 2L >= -bound && distance / 2L < bound then
    uint16 ((distance / 2L) &&& ((1L <<< width) - 1L))
  else
    fail $"a place {distance} bytes away is out of reach of {ins.Mnemonic}"

/// <summary>
/// The bits a relative branch holds, however the source said where it goes.
///
/// What the disassembler writes there is the distance itself, because a word on
/// its own does not say where it sits. A source naming a place, or writing out
/// the address of one, says where it wants to end up instead, and the three are
/// the same thing once the distance between them has been worked out.
/// </summary>
let branchField width ins operand =
  let awayFrom (target: int64) = target - int64 ins.Address - 2L
  match operand with
  | AsmRel value -> wordsAway width ins (int64 value)
  | AsmTarget target -> wordsAway width ins (awayFrom (int64 target))
  | AsmNum value -> wordsAway width ins (awayFrom (int64 value))
  | _ -> wrongOperands ins

/// <summary>
/// The word address a jump reaching the whole of the code space holds.
///
/// Such a jump says where it goes rather than how far away it is, and it says
/// it in words, so a place at an odd address is one it cannot name.
/// </summary>
let jumpTarget (ins: AsmInsInfo) operand =
  let addressOf (target: int64) =
    if target % 2L <> 0L then fail "a jump reaches only an even address"
    elif target >= 0L && target < (1L <<< 23) then uint32 (target / 2L)
    else fail $"0x{target:x} is out of reach of {ins.Mnemonic}"
  match operand with
  | AsmNum value -> addressOf (int64 value)
  | AsmTarget target -> addressOf (int64 target)
  | _ -> wrongOperands ins

/// The byte of memory a load or a store naming one outright reaches, which is
/// written out in full and reaches every byte the data space holds.
let dataAddress ins operand =
  match operand with
  | AsmNum value -> unsigned 16 value
  | _ -> wrongOperands ins

/// <summary>
/// One word holding a field split in two.
///
/// The lower four bits of such a field sit at the bottom of the word and the
/// rest just above the field naming the register, which is how the register an
/// instruction reads is written and how the peripheral a move to or from one
/// names it.
/// </summary>
let splitWord (head: uint16) (d: uint16) (value: uint16) =
  head ||| ((value >>> 4) <<< 9) ||| (d <<< 4) ||| (value &&& 0xFus)

/// One word holding a byte, whose upper half sits above the field naming the
/// register and whose lower half sits at the bottom of the word.
let byteWord (head: uint16) (d: uint16) (value: uint16) =
  head ||| ((value >>> 4) <<< 8) ||| (d <<< 4) ||| (value &&& 0xFus)

/// One word holding a single field just above its lowest four bits, which is
/// where the register an instruction names sits and where the few instructions
/// naming a number in place of one put that number.
let regWord (head: uint16) (value: uint16) = head ||| (value <<< 4)

/// One word naming two registers whose fields sit next to each other, which is
/// how the instructions reaching only part of the file are written.
let pairWord (head: uint16) (d: uint16) (r: uint16) = head ||| (d <<< 4) ||| r

/// One word holding a number six bits wide whose upper two bits sit just above
/// the field naming the register, which is how a number added to a whole word
/// is written.
let wordImmWord (head: uint16) (d: uint16) (value: uint16) =
  head ||| ((value >>> 4) <<< 6) ||| (d <<< 4) ||| (value &&& 0xFus)

/// One word naming a place in the space of the peripherals and a bit of it.
let ioBitWord (head: uint16) (a: uint16) (b: uint16) =
  head ||| (a <<< 3) ||| b

/// <summary>
/// One word holding how far from an index register the memory it reaches lies.
///
/// The six bits saying that are scattered over the whole word: the highest of
/// them is the second bit of it, the two below that sit above the bit saying
/// whether memory is read or written, and the three lowest sit at the bottom.
/// </summary>
let dispWord (head: uint16) (d: uint16) (q: uint16) =
  head ||| ((q >>> 5) <<< 13) ||| (((q >>> 3) &&& 0x3us) <<< 10)
  ||| (d <<< 4) ||| (q &&& 0x7us)

/// A register operand.
let (|Rg|_|) = function
  | AsmReg reg -> Some reg
  | _ -> None

/// A number written bare.
let (|Nm|_|) = function
  | AsmNum value -> Some value
  | _ -> None

/// The memory a register names, where the register moves on past what was read.
let (|Post|_|) = function
  | AsmPostInc reg -> Some reg
  | _ -> None

/// The same, where the register moves back before anything is read.
let (|Pre|_|) = function
  | AsmPreDec reg -> Some reg
  | _ -> None

/// The memory at a written distance from what an index register holds.
let (|Disp|_|) = function
  | AsmDisp(reg, value) -> Some(reg, value)
  | _ -> None

// vim: set tw=80 sts=2 sw=2:
