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
/// Turns the pieces of an instruction into the bit fields an Alpha encoding is
/// built from. Every function here rejects what does not fit rather than
/// truncating it, because a field that silently drops a bit encodes an
/// instruction the source did not ask for.
/// </summary>
module internal B2R2.Assembly.Alpha.AsmField

open B2R2.FrontEnd.Alpha
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.Alpha.ParserHelper

/// The value the architecture asks every register field an instruction does
/// not use to hold, which is the register that always reads as zero.
let [<Literal>] Unused = 31u

/// Reports a source this assembler cannot encode.
let fail msg = raise <| EncodingFailureException msg

/// Reports operands that do not belong to the given mnemonic.
let wrongOperands (ins: AsmInsInfo) =
  fail $"{ins.Mnemonic} does not take these operands"

/// The five bits naming one of the general registers.
let gpr (reg: Register) =
  if reg >= Register.R0 && reg <= Register.R31 then uint32 (int reg)
  else fail $"{Register.toString reg} is not a general register"

/// The five bits naming one of the floating-point registers.
let fpr (reg: Register) =
  if reg >= Register.F0 && reg <= Register.F31 then
    uint32 (int reg - int Register.F0)
  else
    fail $"{Register.toString reg} is not a floating-point register"

/// <summary>
/// The bits a field reads as a signed number.
///
/// The disassembler writes such a number as the bits of the word it was
/// widened to rather than with a sign, so one below zero arrives here as its
/// thirty-two bit form whether the source wrote it that way or with a sign.
/// </summary>
let private signed width (value: uint64) =
  let v = int64 (int32 (uint32 value))
  let bound = 1L <<< (width - 1)
  if v >= -bound && v < bound then uint32 (uint64 v &&& ((1UL <<< width) - 1UL))
  else fail $"{v} does not fit in {width} signed bits"

/// The bits a field reads as a count, which is every field but the ones
/// holding a distance or a displacement.
let private unsigned width (value: uint64) =
  if value < (1UL <<< width) then uint32 value
  else fail $"0x{value:x} does not fit in {width} bits"

/// The sixteen bits an instruction reaching memory counts an address from a
/// register by.
let memDisp value = signed 16 value

/// The number an Operate instruction computes from in place of a second
/// register, which is a count between nothing and two hundred fifty-five.
let literal value = unsigned 8 value

/// The guess a branch to a computed address carries at where it ends up, which
/// the machine reads to fill its pipeline and is free to be wrong.
let hint value = unsigned 14 value

/// The routine a trap to PALcode names.
let palFunction value = unsigned 26 value

/// <summary>
/// The twenty-one bits a branch holds where it counts how far away the place it
/// names is.
///
/// What the encoding holds is that distance in words and what the disassembler
/// writes is the same distance in bytes, so a source writes bytes either way.
/// </summary>
let branchDisp (value: uint64) =
  let v = int32 (uint32 value)
  if v % 4 = 0 then signed 21 (uint64 (uint32 (v / 4)))
  else fail "a branch reaches only a whole word away"

/// A register operand.
let (|Rg|_|) = function
  | AsmReg reg -> Some reg
  | _ -> None

/// An operand that stands for a number.
let (|Im|_|) = function
  | AsmImm value -> Some value
  | _ -> None

/// The memory an instruction reaches, written as a displacement and the
/// register it is counted from.
let (|Mem|_|) = function
  | AsmMem(baseReg, disp) -> Some(baseReg, disp)
  | _ -> None

/// The memory an instruction reaches, named by a register alone.
let (|Base|_|) = function
  | AsmBase baseReg -> Some baseReg
  | _ -> None

/// One word of the kind reaching memory, which names a register, a second one
/// the address is counted from, and how far from it to reach.
let memWord (op: uint32) ra rb (disp: uint32) =
  (op <<< 26) ||| (ra <<< 21) ||| (rb <<< 16) ||| disp

/// One word of the kind computing from what registers hold. What lies below
/// the field naming the first register is either a second register or a number
/// written in its place, so the caller builds it.
let oprWord (op: uint32) (func: uint32) ra (source: uint32) rc =
  (op <<< 26) ||| (ra <<< 21) ||| source ||| (func <<< 5) ||| rc

/// One word of the kind branching to a place it counts the distance to.
let braWord (op: uint32) ra (disp: uint32) =
  (op <<< 26) ||| (ra <<< 21) ||| disp

/// One word of the kind computing from what floating-point registers hold,
/// which never holds a number in place of a register.
let fltWord (op: uint32) (func: uint32) fa fb fc =
  (op <<< 26) ||| (fa <<< 21) ||| (fb <<< 16) ||| (func <<< 5) ||| fc

/// <summary>
/// The bits below the field naming the first register, where what they hold is
/// either a second register or a number written in its place.
///
/// Which of the two it is, is what the bit above them says, so the bit is part
/// of what is built here rather than of the instruction that asks for it.
/// </summary>
let operateSource = function
  | AsmReg reg -> gpr reg <<< 16
  | AsmImm value -> (1u <<< 12) ||| (literal value <<< 13)
  | _ -> fail "this is neither a register nor a number"

// vim: set tw=80 sts=2 sw=2:
