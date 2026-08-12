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
/// Encodes one instruction on the general registers into the word that means
/// it. Every encoder here takes the instruction as the source wrote it and
/// returns that word, so the families whose members differ only in a few bits
/// are one function applied to different bits rather than one function each.
/// </summary>
module internal B2R2.Assembly.MIPS.AsmOpcode

open B2R2.FrontEnd.MIPS
open B2R2.Assembly.MIPS.ParserHelper
open B2R2.Assembly.MIPS.AsmField

(* The instructions on the general registers. Their opcode field says only
   which of the four families they belong to; a function field of six bits at
   the bottom of the word says which member of it they are. *)
/// The instructions that take no operand at all, which the two fields left
/// over tell apart.
let private noOperand sa func ins =
  match ins.Operands with
  | NoOperand -> word 0u 0u 0u 0u sa func
  | _ -> wrongOperands ins

/// <rd>, <rt>, <sa>: a shift by a written distance. Which shift it is, the
/// field above the registers says as well as the function field.
let private shiftImm rs func ins =
  match ins.Operands with
  | ThreeOperands(Rg rd, Rg rt, Im sa) ->
    word 0u rs (gpr rt) (gpr rd) (unsigned 5 sa) func
  | _ ->
    wrongOperands ins

/// <rd>, <rt>, <rs>: a shift by a distance a register holds.
let private shiftReg sa func ins =
  match ins.Operands with
  | ThreeOperands(Rg rd, Rg rt, Rg rs) ->
    word 0u (gpr rs) (gpr rt) (gpr rd) sa func
  | _ ->
    wrongOperands ins

/// <rd>, <rs>, <rt>: the arithmetic and the logic on two registers.
let private threeReg func ins =
  match ins.Operands with
  | ThreeOperands(Rg rd, Rg rs, Rg rt) ->
    word 0u (gpr rs) (gpr rt) (gpr rd) 0u func
  | _ ->
    wrongOperands ins

/// <rs>, <rt>: the multiplies and the divides that write the pair of registers
/// a product too wide for one of them needs, and the trap that compares two.
/// The number a trap leaves behind for whatever handles it is not printed by
/// the disassembler, so nothing written here can say one and it comes out as
/// zero.
let private twoReg func ins =
  match ins.Operands with
  | TwoOperands(Rg rs, Rg rt) -> word 0u (gpr rs) (gpr rt) 0u 0u func
  | _ -> wrongOperands ins

/// <rs>, <rt> and <rd>, <rs>, <rt>: the unsigned divide, which is written both
/// ways and is a different instruction under each.
let private divideUnsigned ins =
  match ins.Operands with
  | TwoOperands(Rg rs, Rg rt) ->
    word 0u (gpr rs) (gpr rt) 0u 0u 0b011011u
  | ThreeOperands(Rg rd, Rg rs, Rg rt) ->
    word 0u (gpr rs) (gpr rt) (gpr rd) 0b00010u 0b011011u
  | _ ->
    wrongOperands ins

/// <rd>: the reads of the pair of registers a multiply writes.
let private readReg func ins =
  match ins.Operands with
  | OneOperand(Rg rd) -> word 0u 0u 0u (gpr rd) 0u func
  | _ -> wrongOperands ins

/// <rs>: the writes of that pair, and the jumps to a place a register holds.
let private oneReg sa func ins =
  match ins.Operands with
  | OneOperand(Rg rs) -> word 0u (gpr rs) 0u 0u sa func
  | _ -> wrongOperands ins

/// <rd>, <rs>, <cc>: a move that happens only where the condition the
/// floating-point unit last tested holds, or only where it does not.
let private moveOnCondition tf ins =
  match ins.Operands with
  | ThreeOperands(Rg rd, Rg rs, Im cc) ->
    let rt = (unsigned 3 cc <<< 2) ||| tf
    word 0u (gpr rs) rt (gpr rd) 0u 0b000001u
  | _ ->
    wrongOperands ins

/// {<stype>}: how much of what came before has to have been seen before what
/// comes after may run. A source leaving it out asks for all of it, which is
/// the same as writing zero and is what the disassembler prints.
let private sync ins =
  match ins.Operands with
  | NoOperand -> word 0u 0u 0u 0u 0u 0b001111u
  | OneOperand(Im stype) -> word 0u 0u 0u 0u (unsigned 5 stype) 0b001111u
  | _ -> wrongOperands ins

/// <rs>, <rt>: the multiplies that add what they yield to the pair of
/// registers a multiply writes rather than replacing it.
let private multiplyAccumulate func ins =
  match ins.Operands with
  | TwoOperands(Rg rs, Rg rt) -> word 0b011100u (gpr rs) (gpr rt) 0u 0u func
  | _ -> wrongOperands ins

/// <rd>, <rs>, <rt>: the multiply that writes one register rather than two.
let private multiplyToReg ins =
  match ins.Operands with
  | ThreeOperands(Rg rd, Rg rs, Rg rt) ->
    word 0b011100u (gpr rs) (gpr rt) (gpr rd) 0u 0b000010u
  | _ ->
    wrongOperands ins

/// <rd>, <rs>: counting the zeroes a word or a doubleword starts with. The
/// manual writes the destination into both of the fields the instructions
/// beside this one keep a register in.
let private countLeadingZeros func ins =
  match ins.Operands with
  | TwoOperands(Rg rd, Rg rs) ->
    word 0b011100u (gpr rs) (gpr rd) (gpr rd) 0u func
  | _ ->
    wrongOperands ins

/// The last bit of the field an extract reads, which follows from how long the
/// field is alone. What a doubleword adds to it is not kept in the encoding.
let private extractEnd bias _pos (size: uint32) = size - 1u - bias

/// The last bit of the field an insert writes, which follows from where the
/// field starts as well.
let private insertEnd bias pos (size: uint32) = pos + size - 1u - bias

/// <rt>, <rs>, <pos>, <size>: the instructions that read or write one field of
/// a register. What they hold is where the field starts and where it ends,
/// and every member of the family works the end out differently, so the caller
/// says how.
let private bitfield func lsbBias endOf ins =
  match ins.Operands with
  | FourOperands(Rg rt, Rg rs, Im pos, Im size) ->
    let pos, size = narrowed pos, narrowed size
    let msb = unsigned 5 (uint64 (endOf pos size))
    let lsb = unsigned 5 (uint64 (pos - lsbBias))
    word 0b011111u (gpr rs) (gpr rt) msb lsb func
  | _ ->
    wrongOperands ins

/// <rd>, <rt>: the instructions that shuffle the bytes or the bits of a
/// register, which the field a shift keeps its distance in tells apart.
let private shuffle func sa ins =
  match ins.Operands with
  | TwoOperands(Rg rd, Rg rt) -> word 0b011111u 0u (gpr rt) (gpr rd) sa func
  | _ -> wrongOperands ins

/// <rd>, <rs>, <rt>, <bp>: taking a run of bytes that straddles two registers,
/// which starts at the byte the last operand names.
let private align func width ins =
  match ins.Operands with
  | FourOperands(Rg rd, Rg rs, Rg rt, Im bp) ->
    let sa = 0b01000u ||| unsigned width bp
    word 0b011111u (gpr rs) (gpr rt) (gpr rd) sa func
  | _ ->
    wrongOperands ins

/// <rt>, <rd>, <sel>: reading one of the registers the hardware shows to a
/// program that cannot reach the ones the system keeps.
let private readHardware ins =
  match ins.Operands with
  | ThreeOperands(Rg rt, Rg rd, Im sel) ->
    word 0b011111u 0u (gpr rt) (gpr rd) (unsigned 3 sel) 0b111011u
  | _ ->
    wrongOperands ins

/// <rt>, <rs>, <imm>: the arithmetic that takes a written number, which it
/// reads as a signed one.
let private arithImm op ins =
  match ins.Operands with
  | ThreeOperands(Rg rt, Rg rs, Im value) ->
    immWord op (gpr rs) (gpr rt) (immediate16 value)
  | _ ->
    wrongOperands ins

/// <rt>, <rs>, <imm>: the logic that takes one, which it reads as a count of
/// bits set rather than as a number that may be below zero.
let private logicImm op ins =
  match ins.Operands with
  | ThreeOperands(Rg rt, Rg rs, Im value) ->
    immWord op (gpr rs) (gpr rt) (unsigned 16 value)
  | _ ->
    wrongOperands ins

/// <rt>, <imm>: writing a number into the upper half of a register, which is
/// how the halves of a whole word are written one after the other.
let private loadUpper ins =
  match ins.Operands with
  | TwoOperands(Rg rt, Im value) ->
    immWord 0b001111u 0u (gpr rt) (unsigned 16 value)
  | _ ->
    wrongOperands ins

let arithmeticEncoders () =
  [ Opcode.NOP, noOperand 0b00000u 0b000000u
    Opcode.SSNOP, noOperand 0b00001u 0b000000u
    Opcode.EHB, noOperand 0b00011u 0b000000u
    Opcode.PAUSE, noOperand 0b00101u 0b000000u
    Opcode.SLL, shiftImm 0u 0b000000u
    Opcode.SRL, shiftImm 0u 0b000010u
    Opcode.ROTR, shiftImm 1u 0b000010u
    Opcode.SRA, shiftImm 0u 0b000011u
    Opcode.DSLL, shiftImm 0u 0b111000u
    Opcode.DSRL, shiftImm 0u 0b111010u
    Opcode.DROTR, shiftImm 1u 0b111010u
    Opcode.DSRA, shiftImm 0u 0b111011u
    Opcode.DSLL32, shiftImm 0u 0b111100u
    Opcode.DSRL32, shiftImm 0u 0b111110u
    Opcode.DROTR32, shiftImm 1u 0b111110u
    Opcode.DSRA32, shiftImm 0u 0b111111u
    Opcode.SLLV, shiftReg 0u 0b000100u
    Opcode.SRLV, shiftReg 0u 0b000110u
    Opcode.ROTRV, shiftReg 1u 0b000110u
    Opcode.SRAV, shiftReg 0u 0b000111u
    Opcode.DSLLV, shiftReg 0u 0b010100u
    Opcode.DSRLV, shiftReg 0u 0b010110u
    Opcode.DROTRV, shiftReg 1u 0b010110u
    Opcode.DSRAV, shiftReg 0u 0b010111u
    Opcode.ADD, threeReg 0b100000u
    Opcode.ADDU, threeReg 0b100001u
    Opcode.SUBU, threeReg 0b100011u
    Opcode.AND, threeReg 0b100100u
    Opcode.OR, threeReg 0b100101u
    Opcode.XOR, threeReg 0b100110u
    Opcode.NOR, threeReg 0b100111u
    Opcode.SLT, threeReg 0b101010u
    Opcode.SLTU, threeReg 0b101011u
    Opcode.DADD, threeReg 0b101100u
    Opcode.DADDU, threeReg 0b101101u
    Opcode.DSUBU, threeReg 0b101111u
    Opcode.MOVZ, threeReg 0b001010u
    Opcode.MOVN, threeReg 0b001011u
    Opcode.MULT, twoReg 0b011000u
    Opcode.MULTU, twoReg 0b011001u
    Opcode.DIV, twoReg 0b011010u
    Opcode.DMULT, twoReg 0b011100u
    Opcode.DMULTU, twoReg 0b011101u
    Opcode.DDIV, twoReg 0b011110u
    Opcode.DDIVU, twoReg 0b011111u
    Opcode.DIVU, divideUnsigned
    Opcode.MFHI, readReg 0b010000u
    Opcode.MFLO, readReg 0b010010u
    Opcode.MTHI, oneReg 0u 0b010001u
    Opcode.MTLO, oneReg 0u 0b010011u
    Opcode.MOVF, moveOnCondition 0u
    Opcode.MOVT, moveOnCondition 1u
    Opcode.SYNC, sync
    Opcode.MADD, multiplyAccumulate 0b000000u
    Opcode.MADDU, multiplyAccumulate 0b000001u
    Opcode.MSUB, multiplyAccumulate 0b000100u
    Opcode.MSUBU, multiplyAccumulate 0b000101u
    Opcode.MUL, multiplyToReg
    Opcode.CLZ, countLeadingZeros 0b100000u
    Opcode.DCLZ, countLeadingZeros 0b100100u
    Opcode.EXT, bitfield 0b000000u 0u (extractEnd 0u)
    Opcode.DEXTM, bitfield 0b000001u 0u (extractEnd 32u)
    Opcode.DEXTU, bitfield 0b000010u 32u (extractEnd 0u)
    Opcode.DEXT, bitfield 0b000011u 0u (extractEnd 0u)
    Opcode.INS, bitfield 0b000100u 0u (insertEnd 0u)
    Opcode.DINSM, bitfield 0b000101u 0u (insertEnd 32u)
    Opcode.DINSU, bitfield 0b000110u 32u (insertEnd 32u)
    Opcode.DINS, bitfield 0b000111u 0u (insertEnd 0u)
    Opcode.BITSWAP, shuffle 0b100000u 0b00000u
    Opcode.WSBH, shuffle 0b100000u 0b00010u
    Opcode.SEB, shuffle 0b100000u 0b10000u
    Opcode.SEH, shuffle 0b100000u 0b11000u
    Opcode.DBITSWAP, shuffle 0b100100u 0b00000u
    Opcode.DSBH, shuffle 0b100100u 0b00010u
    Opcode.DSHD, shuffle 0b100100u 0b00101u
    Opcode.ALIGN, align 0b100000u 2
    Opcode.DALIGN, align 0b100100u 3
    Opcode.RDHWR, readHardware
    Opcode.ADDIU, arithImm 0b001001u
    Opcode.SLTI, arithImm 0b001010u
    Opcode.SLTIU, arithImm 0b001011u
    Opcode.DADDIU, arithImm 0b011001u
    Opcode.AUI, arithImm 0b001111u
    Opcode.ANDI, logicImm 0b001100u
    Opcode.ORI, logicImm 0b001101u
    Opcode.XORI, logicImm 0b001110u
    Opcode.LUI, loadUpper ]

(* The branches and the jumps. A branch holds how far the place it names is
   from the instruction after it; a jump holds one word of the region it sits
   in, which is as far as it reaches. *)
/// <place>: the branches that name a place and nothing else.
let private branchAlways op rs rt ins =
  match ins.Operands with
  | OneOperand(Place distance) -> immWord op rs rt (branchOffset distance)
  | _ -> wrongOperands ins

/// <rs>, <rt>, <place>: the branches that compare two registers.
let private branchOnPair op ins =
  match ins.Operands with
  | ThreeOperands(Rg rs, Rg rt, Place distance) ->
    immWord op (gpr rs) (gpr rt) (branchOffset distance)
  | _ ->
    wrongOperands ins

/// <rs>, <place>: a branch that compares one register against zero. Which one
/// it is lies partly in the opcode and partly in the field a branch on two
/// registers keeps the other of them in.
let private branchOnZero op rt ins =
  match ins.Operands with
  | TwoOperands(Rg rs, Place distance) ->
    immWord op (gpr rs) rt (branchOffset distance)
  | _ ->
    wrongOperands ins

/// <target>: a jump to a place in the region it sits in.
let private jump op ins =
  match ins.Operands with
  | OneOperand(Im target) -> immWord op 0u 0u (jumpTarget target)
  | _ -> wrongOperands ins

/// <rs> and <rd>, <rs>: a jump that keeps where it came from, which names the
/// register it keeps it in only where that is not the usual one.
let private jumpAndLink hint ins =
  match ins.Operands with
  | OneOperand(Rg rs) -> word 0u (gpr rs) 0u 31u hint 0b001001u
  | TwoOperands(Rg rd, Rg rs) -> word 0u (gpr rs) 0u (gpr rd) hint 0b001001u
  | _ -> wrongOperands ins

/// <rs>, <imm>: the trap that compares a register against a written number.
let private trapImm rt ins =
  match ins.Operands with
  | TwoOperands(Rg rs, Im value) ->
    immWord 0b000001u (gpr rs) rt (immediate16 value)
  | _ ->
    wrongOperands ins

let branchEncoders () =
  [ Opcode.B, branchAlways 0b000100u 0u 0u
    Opcode.BAL, branchAlways 0b000001u 0u 0b10001u
    Opcode.BEQ, branchOnPair 0b000100u
    Opcode.BNE, branchOnPair 0b000101u
    Opcode.BEQL, branchOnPair 0b010100u
    Opcode.BNEL, branchOnPair 0b010101u
    Opcode.BLTZ, branchOnZero 0b000001u 0b00000u
    Opcode.BGEZ, branchOnZero 0b000001u 0b00001u
    Opcode.BLTZAL, branchOnZero 0b000001u 0b10000u
    Opcode.BGEZAL, branchOnZero 0b000001u 0b10001u
    Opcode.BLEZ, branchOnZero 0b000110u 0b00000u
    Opcode.BGTZ, branchOnZero 0b000111u 0b00000u
    Opcode.J, jump 0b000010u
    Opcode.JAL, jump 0b000011u
    Opcode.JR, oneReg 0b00000u 0b001000u
    Opcode.JRHB, oneReg 0b10000u 0b001000u
    Opcode.JALR, jumpAndLink 0b00000u
    Opcode.JALRHB, jumpAndLink 0b10000u
    Opcode.SYSCALL, noOperand 0b00000u 0b001100u
    Opcode.BREAK, noOperand 0b00000u 0b001101u
    Opcode.TEQ, twoReg 0b110100u
    Opcode.TEQI, trapImm 0b01100u ]

(* The loads and the stores. Every one of them reads memory at a distance from
   a register, and what says how wide the access is is the instruction rather
   than anything the source writes. *)
/// <rt>, <offset>(<base>): the loads and the stores of a general register.
let private memory op ins =
  match ins.Operands with
  | TwoOperands(Rg rt, Mem(baseReg, offset)) ->
    immWord op (gpr baseReg) (gpr rt) (signed 16 offset)
  | _ ->
    wrongOperands ins

/// <ft>, <offset>(<base>): the loads and the stores of a floating-point
/// register, which name one where the others name a general register.
let private memoryFP op ins =
  match ins.Operands with
  | TwoOperands(Rg ft, Mem(baseReg, offset)) ->
    immWord op (gpr baseReg) (fpr ft) (signed 16 offset)
  | _ ->
    wrongOperands ins

/// <hint>, <offset>(<base>): the word that a place is about to be read or
/// written, which says what to do with it where the others name a register.
let private prefetch ins =
  match ins.Operands with
  | TwoOperands(Im hint, Mem(baseReg, offset)) ->
    immWord 0b110011u (gpr baseReg) (unsigned 5 hint) (signed 16 offset)
  | _ ->
    wrongOperands ins

let loadStoreEncoders () =
  [ Opcode.LB, memory 0b100000u
    Opcode.LH, memory 0b100001u
    Opcode.LWL, memory 0b100010u
    Opcode.LW, memory 0b100011u
    Opcode.LBU, memory 0b100100u
    Opcode.LHU, memory 0b100101u
    Opcode.LWR, memory 0b100110u
    Opcode.LWU, memory 0b100111u
    Opcode.SB, memory 0b101000u
    Opcode.SH, memory 0b101001u
    Opcode.SWL, memory 0b101010u
    Opcode.SW, memory 0b101011u
    Opcode.SDL, memory 0b101100u
    Opcode.SDR, memory 0b101101u
    Opcode.SWR, memory 0b101110u
    Opcode.LDL, memory 0b011010u
    Opcode.LDR, memory 0b011011u
    Opcode.LD, memory 0b110111u
    Opcode.SD, memory 0b111111u
    Opcode.LL, memory 0b110000u
    Opcode.LLD, memory 0b110100u
    Opcode.SC, memory 0b111000u
    Opcode.SCD, memory 0b111100u
    Opcode.LWC1, memoryFP 0b110001u
    Opcode.LDC1, memoryFP 0b110101u
    Opcode.SWC1, memoryFP 0b111001u
    Opcode.SDC1, memoryFP 0b111101u
    Opcode.PREF, prefetch ]
