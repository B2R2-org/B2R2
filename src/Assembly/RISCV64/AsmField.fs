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
/// Turns the pieces of an instruction into the bit fields a RISCV64 encoding is
/// built from. Every function here rejects what does not fit rather than
/// truncating it, because a field that silently drops a bit encodes an
/// instruction the source did not ask for.
/// </summary>
module internal B2R2.Assembly.RISCV64.AsmField

open B2R2
open B2R2.FrontEnd.RISCV64
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.RISCV64.ParserHelper

/// Reports a source this assembler cannot encode.
let fail msg = raise <| EncodingFailureException msg

/// Reports operands that do not belong to the given opcode.
let wrongOperands (ins: AsmInsInfo) =
  fail $"{ins.Opcode} does not take these operands"

/// The five bits that name one of the general registers.
let gpr (reg: Register) =
  if reg >= Register.X0 && reg <= Register.X31 then uint32 (int reg)
  else fail $"{reg} is not a general register"

/// The five bits that name one of the floating-point registers.
let fpr (reg: Register) =
  if reg >= Register.F0 && reg <= Register.F31 then
    uint32 (int reg - int Register.F0)
  else
    fail $"{reg} is not a floating-point register"

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
/// The twelve bits an instruction taking a signed number holds.
///
/// The disassembler prints such a number as the whole register it lands in,
/// which is sixty-four bits wide, so one below zero arrives as its sixty-four
/// bit form whether the source wrote it with a sign or as the bits it stands
/// for.
/// </summary>
let immediate12 (value: uint64) = signed 12 (int64 value)

/// <summary>
/// The twenty bits an instruction naming the upper part of an address holds.
///
/// What the disassembler prints there is the field itself widened to the whole
/// register rather than the address the instruction builds, so what is read
/// back here is that same field.
/// </summary>
let immediate20 (value: uint64) = signed 20 (int64 value)

/// The bits a shift holds, which say how far to shift and are never below zero.
let shiftAmount width (value: uint64) = unsigned width value

/// The twelve bits naming one of the control and status registers.
let csr (value: uint64) = unsigned 12 value

/// <summary>
/// The bits a branch holds where it counts how far away the place it names is.
///
/// What the encoding holds is that distance and what the disassembler prints is
/// the address it worked out, so a source writes an address either way and the
/// two are subtracted here. The lowest bit of the distance is not kept, because
/// no instruction begins halfway through a halfword.
/// </summary>
let relativeTarget width (pc: Addr) (target: uint64) =
  let distance = int64 (target - pc)
  if distance % 2L = 0L then signed width distance
  else fail "a branch cannot reach a place that is not a halfword away"

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
  | AsmMem(offset, baseReg) -> Some(offset, baseReg)
  | _ -> None

/// The register an atomic instruction reaches memory through. Such an
/// instruction reaches exactly what that register holds, so no distance from it
/// can be written.
let atomicBase (offset: uint64, baseReg) =
  if offset = 0UL then gpr baseReg
  else fail "an atomic instruction reaches no distance from what it names"

/// <summary>
/// How an instruction rounds what it computed.
///
/// The disassembler leaves the mode unwritten where the instruction reads it
/// from the rounding-mode register, so an instruction that takes a mode and is
/// written without one takes that one.
/// </summary>
let roundingOf = function
  | [ AsmRound mode ] -> uint32 (int mode)
  | [] -> uint32 (int RoundMode.DYN)
  | _ -> fail "this is not a rounding mode"

/// Whether an atomic instruction takes the lock before it and gives it up
/// after, which is written after the memory it reaches or not at all.
let orderingOf = function
  | [ AsmOrder(aq, rl) ] ->
    ((if aq then 1u else 0u) <<< 1) ||| (if rl then 1u else 0u)
  | [] -> 0u
  | _ -> fail "this does not say how an atomic instruction is ordered"

(* The seven bits every RISCV64 word ends in, which are the coarsest thing
   saying what an instruction is. Every one of them stands for a whole family,
   and which member of that family a word is comes from the three bits above the
   registers and, where those do not say enough, from the seven at the very
   top. *)
let [<Literal>] OpLoad = 0x03u
let [<Literal>] OpLoadFp = 0x07u
let [<Literal>] OpFence = 0x0Fu
let [<Literal>] OpImm = 0x13u
let [<Literal>] OpAuipc = 0x17u
let [<Literal>] OpImm32 = 0x1Bu
let [<Literal>] OpStore = 0x23u
let [<Literal>] OpStoreFp = 0x27u
let [<Literal>] OpAtomic = 0x2Fu
let [<Literal>] OpArith = 0x33u
let [<Literal>] OpLui = 0x37u
let [<Literal>] OpArith32 = 0x3Bu
let [<Literal>] OpFloat = 0x53u
let [<Literal>] OpBranch = 0x63u
let [<Literal>] OpJalr = 0x67u
let [<Literal>] OpJal = 0x6Fu
let [<Literal>] OpSystem = 0x73u

/// One word of the kind naming three registers, which is how the instructions
/// computing from two registers into a third are written.
let rType (opcode: uint32) funct3 funct7 rd rs1 rs2 =
  (funct7 <<< 25) ||| (rs2 <<< 20) ||| (rs1 <<< 15) ||| (funct3 <<< 12)
  ||| (rd <<< 7) ||| opcode

/// One word of the kind whose upper twelve bits are a single number.
let iType (opcode: uint32) funct3 rd rs1 (imm: uint32) =
  ((imm &&& 0xFFFu) <<< 20) ||| (rs1 <<< 15) ||| (funct3 <<< 12)
  ||| (rd <<< 7) ||| opcode

/// One word of the kind a store takes, whose number is split so that the two
/// registers it names lie where every other instruction keeps them.
let sType (opcode: uint32) funct3 rs1 rs2 (imm: uint32) =
  (((imm >>> 5) &&& 0x7Fu) <<< 25) ||| (rs2 <<< 20) ||| (rs1 <<< 15)
  ||| (funct3 <<< 12) ||| ((imm &&& 0x1Fu) <<< 7) ||| opcode

/// One word of the kind a conditional branch takes, whose distance is kept
/// without its lowest bit and with the two bits above the rest swapped.
let bType (opcode: uint32) funct3 rs1 rs2 (imm: uint32) =
  (((imm >>> 12) &&& 1u) <<< 31) ||| (((imm >>> 5) &&& 0x3Fu) <<< 25)
  ||| (rs2 <<< 20) ||| (rs1 <<< 15) ||| (funct3 <<< 12)
  ||| (((imm >>> 1) &&& 0xFu) <<< 8) ||| (((imm >>> 11) &&& 1u) <<< 7)
  ||| opcode

/// One word of the kind whose upper twenty bits are a single number.
let uType (opcode: uint32) rd (imm: uint32) =
  ((imm &&& 0xFFFFFu) <<< 12) ||| (rd <<< 7) ||| opcode

/// One word of the kind the unconditional jump takes, whose distance is kept in
/// four pieces so that the eight bits it shares with every other form stay
/// where they are.
let jType (opcode: uint32) rd (imm: uint32) =
  (((imm >>> 20) &&& 1u) <<< 31) ||| (((imm >>> 1) &&& 0x3FFu) <<< 21)
  ||| (((imm >>> 11) &&& 1u) <<< 20) ||| (((imm >>> 12) &&& 0xFFu) <<< 12)
  ||| (rd <<< 7) ||| opcode
