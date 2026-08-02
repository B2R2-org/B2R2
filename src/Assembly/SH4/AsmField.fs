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
/// Turns the pieces of an instruction into the bit fields an SH4 encoding is
/// built from. Every function here rejects what does not fit rather than
/// truncating it, because a field that silently drops a bit encodes an
/// instruction the source did not ask for.
/// </summary>
module internal B2R2.Assembly.SH4.AsmField

open B2R2
open B2R2.FrontEnd.SH4
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.SH4.ParserHelper

/// Reports a source this assembler cannot encode.
let fail msg = raise <| EncodingFailureException msg

/// Reports operands that do not belong to the given mnemonic.
let wrongOperands (ins: AsmInsInfo) =
  fail $"{ins.Mnemonic} does not take these operands"

/// The number one of a run of registers is known by, given the first of the
/// run, or nothing where the register does not belong to that run.
let private indexIn first last (reg: Register) =
  if reg >= first && reg <= last then Some(int reg - int first) else None

/// <summary>
/// Whether a register is one of the general sixteen.
///
/// This is what tells the memory an instruction reaches from what a register
/// holds apart from the memory it reaches from the global base or from where
/// the instruction itself sits, which are written the same way.
/// </summary>
let isGeneral (reg: Register) = reg >= Register.R0 && reg <= Register.R15

/// The four bits naming one of the sixteen general registers.
let gpr (reg: Register) =
  match indexIn Register.R0 Register.R15 reg with
  | Some n -> uint16 n
  | None -> fail $"{Register.toString reg} is not a general register"

/// <summary>
/// The three bits naming one of the eight registers a bank holds.
///
/// A fourth bit above them says that a bank is what is named at all, and it
/// belongs to the instruction rather than to the register, so it is set where
/// the instruction is built.
/// </summary>
let bank (reg: Register) =
  match indexIn Register.R0_BANK Register.R7_BANK reg with
  | Some n -> uint16 n
  | None -> fail $"{Register.toString reg} is not a banked register"

/// The four bits naming one of the sixteen floating-point registers.
let fpr (reg: Register) =
  match indexIn Register.FR0 Register.FR15 reg with
  | Some n -> uint16 n
  | None -> fail $"{Register.toString reg} holds no single-precision number"

/// <summary>
/// The three bits naming the pair a double-precision number lands in.
///
/// A pair is named by the first register of it, so the names count by twos and
/// the field counts by ones; the bit below the field is what the name's last
/// bit would be, and it is zero because no pair starts at an odd register.
/// </summary>
let dpr (reg: Register) =
  match indexIn Register.DR0 Register.DR14 reg with
  | Some n -> uint16 n
  | None -> fail $"{Register.toString reg} holds no double-precision number"

/// The two bits naming one of the four vectors, which are named by the first of
/// the four registers each is made of.
let fvr (reg: Register) =
  match indexIn Register.FV0 Register.FV12 reg with
  | Some n -> uint16 n
  | None -> fail $"{Register.toString reg} is not a vector"

/// The bits a field holding a distance from a register holds, which is a count
/// of steps and is never below zero.
let private unsigned width (value: int32) =
  if value >= 0 && value < (1 <<< width) then uint16 value
  else fail $"{value} does not fit in {width} bits"

/// <summary>
/// The bits a field holds where what it holds may be written either way.
///
/// The disassembler writes such a field as the count it holds, while a source
/// of its own writes what that count stands for, which for the fields an
/// instruction reads as signed is a number below zero.
/// </summary>
let private either width (value: int32) =
  let bound = 1 <<< (width - 1)
  if value >= -bound && value < bound * 2 then
    uint16 (value &&& ((1 <<< width) - 1))
  else
    fail $"{value} does not fit in {width} bits"

/// How far from a register the memory an instruction reaches lies, in steps of
/// the width it reaches by.
let disp4 value = unsigned 4 value

/// The same, for the instructions counting from the global base or from the
/// program counter, which reach further.
let disp8 value = unsigned 8 value

/// The number an instruction computing from one holds.
let imm8 value = either 8 value

/// The bits the branches reading a condition hold.
let bdisp8 value = either 8 value

/// The bits the branches reading none hold, which reach further.
let bdisp12 value = either 12 value

/// <summary>
/// The bits a branch holds, given where it wants to end up.
///
/// SH4 counts from the branch's own address plus four, which is what the
/// pipeline's program counter holds while the branch runs, and in instructions
/// rather than in bytes.
/// </summary>
let branchTo width (ins: AsmInsInfo) (target: Addr) =
  let distance = int64 target - int64 ins.Address - 4L
  let bound = 1L <<< (width - 1)
  if distance % 2L <> 0L then
    fail "a branch reaches only an even address"
  elif distance >= -bound && distance < bound then
    uint16 ((distance / 2L) &&& ((1L <<< width) - 1L))
  else
    fail $"a place 0x{target:x} away is out of reach of {ins.Mnemonic}"

/// One word naming two registers, which is how most of the instruction set is
/// written: four bits saying what family the instruction belongs to, four
/// naming the register it writes, four naming the one it reads, and four saying
/// which member of the family it is.
let nmWord (family: uint16) (n: uint16) (m: uint16) (rest: uint16) =
  (family <<< 12) ||| (n <<< 8) ||| (m <<< 4) ||| rest

/// One word naming one register, where everything below the register is spelt
/// out.
let nWord (family: uint16) (n: uint16) (rest: uint16) =
  (family <<< 12) ||| (n <<< 8) ||| rest

/// One word whose lower half is a single number, which is how the branches
/// reading a condition and everything computing from a written number are
/// written.
let immWord (head: uint16) (value: uint16) = (head <<< 8) ||| value

/// One word whose lower three quarters are a single number, which is how the
/// two branches reading no condition are written.
let dispWord (family: uint16) (value: uint16) = (family <<< 12) ||| value

/// A register operand.
let (|Rg|_|) = function
  | AsmReg reg -> Some reg
  | _ -> None

/// A number written with the mark that says it is one.
let (|Im|_|) = function
  | AsmImm value -> Some value
  | _ -> None

/// A number written bare, which stands for the bits the encoding holds.
let (|Nm|_|) = function
  | AsmNum value -> Some value
  | _ -> None

/// Where a named place turned out to be.
let (|Tgt|_|) = function
  | AsmTarget addr -> Some addr
  | _ -> None

/// The memory a register names.
let (|Ind|_|) = function
  | AsmIndir reg -> Some reg
  | _ -> None

/// The same, where the register moves on past what was read.
let (|Post|_|) = function
  | AsmPostInc reg -> Some reg
  | _ -> None

/// The same, where the register moves back before anything is written.
let (|Pre|_|) = function
  | AsmPreDec reg -> Some reg
  | _ -> None

/// The memory at a written distance from what a register holds.
let (|Disp|_|) = function
  | AsmDispMem(value, reg) -> Some(value, reg)
  | _ -> None

/// <summary>
/// The memory at the distance a register holds.
///
/// Only the first of the general registers ever holds that distance, so the
/// register naming it says nothing and what is kept is what it is added to.
/// </summary>
let (|Idx|_|) = function
  | AsmIdxMem(Register.R0, reg) -> Some reg
  | _ -> None

// vim: set tw=80 sts=2 sw=2:
