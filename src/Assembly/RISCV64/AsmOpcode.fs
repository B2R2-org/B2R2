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
/// Encodes the instructions that work on the general registers: the arithmetic
/// and the logic, the shifts, the multiplication and the division, the loads
/// and the stores, the jumps and the branches, the atomic instructions, and
/// what a program says to the machine it runs on.
/// </summary>
module internal B2R2.Assembly.RISCV64.AsmOpcode

open B2R2.FrontEnd.RISCV64
open B2R2.Assembly.RISCV64.ParserHelper
open B2R2.Assembly.RISCV64.AsmField

/// An instruction computing from two registers into a third.
let private regForm opcode funct3 funct7 ins =
  match ins.Operands with
  | [ Rg d; Rg s1; Rg s2 ] ->
    rType opcode funct3 funct7 (gpr d) (gpr s1) (gpr s2)
  | _ -> wrongOperands ins

/// The instructions computing from two registers into a third, both the ones
/// that work on a whole doubleword and the ones that keep only a word of what
/// they computed and widen it back.
let arithmeticEncoders () =
  [ Op.ADD, regForm OpArith 0u 0u
    Op.SUB, regForm OpArith 0u 0x20u
    Op.SLL, regForm OpArith 1u 0u
    Op.SLT, regForm OpArith 2u 0u
    Op.SLTU, regForm OpArith 3u 0u
    Op.XOR, regForm OpArith 4u 0u
    Op.SRL, regForm OpArith 5u 0u
    Op.SRA, regForm OpArith 5u 0x20u
    Op.OR, regForm OpArith 6u 0u
    Op.AND, regForm OpArith 7u 0u
    Op.MUL, regForm OpArith 0u 1u
    Op.MULH, regForm OpArith 1u 1u
    Op.MULHSU, regForm OpArith 2u 1u
    Op.MULHU, regForm OpArith 3u 1u
    Op.DIV, regForm OpArith 4u 1u
    Op.DIVU, regForm OpArith 5u 1u
    Op.REM, regForm OpArith 6u 1u
    Op.REMU, regForm OpArith 7u 1u
    Op.ADDW, regForm OpArith32 0u 0u
    Op.SUBW, regForm OpArith32 0u 0x20u
    Op.SLLW, regForm OpArith32 1u 0u
    Op.SRLW, regForm OpArith32 5u 0u
    Op.SRAW, regForm OpArith32 5u 0x20u
    Op.MULW, regForm OpArith32 0u 1u
    Op.DIVW, regForm OpArith32 4u 1u
    Op.DIVUW, regForm OpArith32 5u 1u
    Op.REMW, regForm OpArith32 6u 1u
    Op.REMUW, regForm OpArith32 7u 1u ]

/// An instruction computing from a register and a written number.
let private immForm opcode funct3 ins =
  match ins.Operands with
  | [ Rg d; Rg s; Im value ] ->
    iType opcode funct3 (gpr d) (gpr s) (immediate12 value)
  | _ -> wrongOperands ins

/// <summary>
/// A shift by a written amount.
///
/// What is written is only how far to shift, and the bits above it in the same
/// field say which shift it is; how many of them there are depends on how wide
/// the amount may be, which is the whole register for a shift of a doubleword
/// and half of one for a shift keeping only a word.
/// </summary>
let private shiftForm opcode funct3 upper width ins =
  match ins.Operands with
  | [ Rg d; Rg s; Im amount ] ->
    let field = (upper <<< width) ||| shiftAmount width amount
    iType opcode funct3 (gpr d) (gpr s) field
  | _ -> wrongOperands ins

/// An instruction whose whole operand is the upper twenty bits of a number.
let private upperForm opcode ins =
  match ins.Operands with
  | [ Rg d; Im value ] -> uType opcode (gpr d) (immediate20 value)
  | _ -> wrongOperands ins

/// The instructions that take a written number rather than a second register.
let immediateEncoders () =
  [ Op.ADDI, immForm OpImm 0u
    Op.SLTI, immForm OpImm 2u
    Op.SLTIU, immForm OpImm 3u
    Op.XORI, immForm OpImm 4u
    Op.ORI, immForm OpImm 6u
    Op.ANDI, immForm OpImm 7u
    Op.SLLI, shiftForm OpImm 1u 0u 6
    Op.SRLI, shiftForm OpImm 5u 0u 6
    Op.SRAI, shiftForm OpImm 5u 0x10u 6
    Op.ADDIW, immForm OpImm32 0u
    Op.SLLIW, shiftForm OpImm32 1u 0u 6
    Op.SRLIW, shiftForm OpImm32 5u 0u 5
    Op.SRAIW, shiftForm OpImm32 5u 0x20u 5
    Op.LUI, upperForm OpLui
    Op.AUIPC, upperForm OpAuipc ]

/// A load, which names where it reads as a distance from what a register holds.
let private loadForm opcode funct3 ins =
  match ins.Operands with
  | [ Rg d; Mem(offset, b) ] ->
    iType opcode funct3 (gpr d) (gpr b) (immediate12 offset)
  | _ -> wrongOperands ins

/// A store, which names where it writes the same way and keeps the register it
/// writes from where a load keeps the one it writes to.
let private storeForm opcode funct3 ins =
  match ins.Operands with
  | [ Rg s; Mem(offset, b) ] ->
    sType opcode funct3 (gpr b) (gpr s) (immediate12 offset)
  | _ -> wrongOperands ins

/// The instructions that read and write memory, one word size at a time.
let loadStoreEncoders () =
  [ Op.LB, loadForm OpLoad 0u
    Op.LH, loadForm OpLoad 1u
    Op.LW, loadForm OpLoad 2u
    Op.LD, loadForm OpLoad 3u
    Op.LBU, loadForm OpLoad 4u
    Op.LHU, loadForm OpLoad 5u
    Op.LWU, loadForm OpLoad 6u
    Op.SB, storeForm OpStore 0u
    Op.SH, storeForm OpStore 1u
    Op.SW, storeForm OpStore 2u
    Op.SD, storeForm OpStore 3u ]

/// A conditional branch, which goes to the place it names when what two
/// registers hold compare as its name says.
let private branchForm funct3 ins =
  match ins.Operands with
  | [ Rg s1; Rg s2; Im target ] ->
    let distance = relativeTarget 13 ins.Address target
    bType OpBranch funct3 (gpr s1) (gpr s2) distance
  | _ -> wrongOperands ins

/// The jump that counts how far away the place it goes to is.
let private jumpForm ins =
  match ins.Operands with
  | [ Rg d; Im target ] ->
    jType OpJal (gpr d) (relativeTarget 21 ins.Address target)
  | _ -> wrongOperands ins

/// The jump that goes to a distance from what a register holds, which is
/// written the way a load names where it reads.
let private jumpRegForm ins =
  match ins.Operands with
  | [ Rg d; Mem(offset, b) ] ->
    iType OpJalr 0u (gpr d) (gpr b) (immediate12 offset)
  | _ -> wrongOperands ins

/// The instructions that go somewhere other than the next word.
let branchEncoders () =
  [ Op.BEQ, branchForm 0u
    Op.BNE, branchForm 1u
    Op.BLT, branchForm 4u
    Op.BGE, branchForm 5u
    Op.BLTU, branchForm 6u
    Op.BGEU, branchForm 7u
    Op.JAL, jumpForm
    Op.JALR, jumpRegForm ]

/// An atomic instruction reading memory, changing what it read, and writing it
/// back, all without anything else reaching that memory in between.
let private atomicForm funct5 funct3 ins =
  match ins.Operands with
  | Rg d :: Rg s :: Mem mem :: rest ->
    let funct7 = (funct5 <<< 2) ||| orderingOf rest
    rType OpAtomic funct3 funct7 (gpr d) (atomicBase mem) (gpr s)
  | _ -> wrongOperands ins

/// The load that reserves the memory it read, which names no second register
/// because it changes nothing.
let private reserveForm funct3 ins =
  match ins.Operands with
  | Rg d :: Mem mem :: rest ->
    let funct7 = (0b00010u <<< 2) ||| orderingOf rest
    rType OpAtomic funct3 funct7 (gpr d) (atomicBase mem) 0u
  | _ -> wrongOperands ins

/// The instructions that reach memory without anything else reaching it in
/// between, in both the width of a word and the width of a doubleword. Which of
/// the two widths one reaches is the only thing the three bits above the
/// registers say here, so the two sets differ in nothing else.
let atomicEncoders () =
  [ Op.LRdotW, reserveForm 2u
    Op.SCdotW, atomicForm 0b00011u 2u
    Op.AMOSWAPdotW, atomicForm 0b00001u 2u
    Op.AMOADDdotW, atomicForm 0b00000u 2u
    Op.AMOXORdotW, atomicForm 0b00100u 2u
    Op.AMOANDdotW, atomicForm 0b01100u 2u
    Op.AMOORdotW, atomicForm 0b01000u 2u
    Op.AMOMINdotW, atomicForm 0b10000u 2u
    Op.AMOMAXdotW, atomicForm 0b10100u 2u
    Op.AMOMINUdotW, atomicForm 0b11000u 2u
    Op.AMOMAXUdotW, atomicForm 0b11100u 2u
    Op.LRdotD, reserveForm 3u
    Op.SCdotD, atomicForm 0b00011u 3u
    Op.AMOSWAPdotD, atomicForm 0b00001u 3u
    Op.AMOADDdotD, atomicForm 0b00000u 3u
    Op.AMOXORdotD, atomicForm 0b00100u 3u
    Op.AMOANDdotD, atomicForm 0b01100u 3u
    Op.AMOORdotD, atomicForm 0b01000u 3u
    Op.AMOMINdotD, atomicForm 0b10000u 3u
    Op.AMOMAXdotD, atomicForm 0b10100u 3u
    Op.AMOMINUdotD, atomicForm 0b11000u 3u
    Op.AMOMAXUdotD, atomicForm 0b11100u 3u ]

/// An instruction that reads one of the control and status registers and writes
/// what a general register holds into it.
let private csrRegForm funct3 ins =
  match ins.Operands with
  | [ Rg d; Im number; Rg s ] ->
    iType OpSystem funct3 (gpr d) (gpr s) (csr number)
  | _ -> wrongOperands ins

/// The same, where what is written is a number rather than a register.
let private csrImmForm funct3 ins =
  match ins.Operands with
  | [ Rg d; Im number; Im value ] ->
    iType OpSystem funct3 (gpr d) (unsigned 5 value) (csr number)
  | _ -> wrongOperands ins

/// An instruction whose name is the whole of it.
let private wordForm word ins =
  match ins.Operands with
  | [] -> word
  | _ -> wrongOperands ins

/// <summary>
/// The fence, which says what may not cross it.
///
/// A source names on either side of it which of the four kinds of access it
/// keeps there, and each of the two names is four bits of one field.
/// </summary>
let private fenceForm ins =
  match ins.Operands with
  | [ AsmFence(pred, succ) ] ->
    iType OpFence 0u 0u 0u ((pred <<< 4) ||| succ)
  | _ -> wrongOperands ins

/// <summary>
/// What a program says to the machine it runs on.
///
/// The fence that keeps every access in the order it was written is written
/// under a name of its own rather than as the two names it would otherwise
/// take, and so is the one that reaches the instructions rather than the data.
/// The instruction that does nothing has no full-width form the disassembler
/// writes under that name, so what is encoded for it is the compressed one.
/// </summary>
let systemEncoders () =
  [ Op.FENCE, fenceForm
    Op.FENCEdotTSO, wordForm (iType OpFence 0u 0u 0u 0x833u)
    Op.FENCEdotI, wordForm (iType OpFence 1u 0u 0u 0u)
    Op.ECALL, wordForm (iType OpSystem 0u 0u 0u 0u)
    Op.EBREAK, wordForm (iType OpSystem 0u 0u 0u 1u)
    Op.CdotNOP, wordForm 1u
    Op.CSRRW, csrRegForm 1u
    Op.CSRRS, csrRegForm 2u
    Op.CSRRC, csrRegForm 3u
    Op.CSRRWI, csrImmForm 5u
    Op.CSRRSI, csrImmForm 6u
    Op.CSRRCI, csrImmForm 7u ]
