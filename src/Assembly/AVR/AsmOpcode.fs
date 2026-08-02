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
/// Encodes what a program computes with: the arithmetic and the logic over two
/// registers, the same over a register and a written number, the instructions
/// working on one register alone, the multiplications, and the instructions
/// working on a single bit of a register or of a peripheral.
/// </summary>
module internal B2R2.Assembly.AVR.AsmOpcode

open B2R2.Assembly.AVR.ParserHelper
open B2R2.Assembly.AVR.AsmField

/// An instruction naming the register it writes and the register it reads,
/// which is the shape most of the arithmetic and the logic has.
let private twoReg head ins =
  match ins.Operands with
  | [ Rg d; Rg r ] -> [ splitWord head (gpr d) (gpr r) ]
  | _ -> wrongOperands ins

/// <summary>
/// One of those instructions written the way a source names a single register.
///
/// Several of the things a program most often does have no encoding of their
/// own, because naming the same register twice already does them: shifting a
/// register up is adding it to itself, clearing it is an exclusive or of it
/// with itself, and testing it is an and of it with itself.
/// </summary>
let private sameReg head ins =
  match ins.Operands with
  | [ Rg d ] -> [ splitWord head (gpr d) (gpr d) ]
  | _ -> wrongOperands ins

let arithmeticEncoders () =
  [ "add", twoReg 0x0C00us
    "adc", twoReg 0x1C00us
    "sub", twoReg 0x1800us
    "sbc", twoReg 0x0800us
    "cp", twoReg 0x1400us
    "cpc", twoReg 0x0400us
    "cpse", twoReg 0x1000us
    "and", twoReg 0x2000us
    "or", twoReg 0x2800us
    "eor", twoReg 0x2400us
    "mov", twoReg 0x2C00us
    "mul", twoReg 0x9C00us
    "lsl", sameReg 0x0C00us
    "rol", sameReg 0x1C00us
    "clr", sameReg 0x2400us
    "tst", sameReg 0x2000us ]

/// An instruction computing from a written byte, which reaches only the upper
/// half of the register file because the byte takes the bits that would name
/// the rest of it.
let private immReg head ins =
  match ins.Operands with
  | [ Rg d; Nm value ] -> [ byteWord head (upperReg d) (imm8 value) ]
  | _ -> wrongOperands ins

/// Clearing the bits a written byte names, which is an and with every bit but
/// those and so has no encoding of its own.
let private clearBits ins =
  match ins.Operands with
  | [ Rg d; Nm value ] ->
    [ byteWord 0x7000us (upperReg d) (0xFFus - imm8 value) ]
  | _ ->
    wrongOperands ins

/// Setting every bit of a register, which is loading the byte that has them all
/// set.
let private setAll ins =
  match ins.Operands with
  | [ Rg d ] -> [ byteWord 0xE000us (upperReg d) 0xFFus ]
  | _ -> wrongOperands ins

/// An instruction adding a written number to one of the four upper pairs, which
/// names the pair in two bits and the number in six.
let private wordImm head ins =
  match ins.Operands with
  | [ Rg d; Nm value ] -> [ wordImmWord head (wordReg d) (imm6 value) ]
  | _ -> wrongOperands ins

let immediateEncoders () =
  [ "subi", immReg 0x5000us
    "sbci", immReg 0x4000us
    "andi", immReg 0x7000us
    "ori", immReg 0x6000us
    "cpi", immReg 0x3000us
    "ldi", immReg 0xE000us
    "sbr", immReg 0x6000us
    "cbr", clearBits
    "ser", setAll
    "adiw", wordImm 0x9600us
    "sbiw", wordImm 0x9700us ]

/// An instruction naming one register and nothing else, where every bit below
/// the field naming it is spelt out.
let private oneReg head ins =
  match ins.Operands with
  | [ Rg d ] -> [ regWord head (gpr d) ]
  | _ -> wrongOperands ins

let singleEncoders () =
  [ "com", oneReg 0x9400us
    "neg", oneReg 0x9401us
    "swap", oneReg 0x9402us
    "inc", oneReg 0x9403us
    "asr", oneReg 0x9405us
    "lsr", oneReg 0x9406us
    "ror", oneReg 0x9407us
    "dec", oneReg 0x940Aus
    "pop", oneReg 0x900Fus
    "push", oneReg 0x920Fus ]

/// A multiplication keeping a signed result, which reaches only the upper half
/// of the file because it names each of its two registers in four bits.
let private upperPair head ins =
  match ins.Operands with
  | [ Rg d; Rg r ] -> [ pairWord head (upperReg d) (upperReg r) ]
  | _ -> wrongOperands ins

/// A multiplication naming each of its registers in three bits, which reaches
/// only the first eight of that upper half.
let private narrowPair head ins =
  match ins.Operands with
  | [ Rg d; Rg r ] -> [ pairWord head (mulReg d) (mulReg r) ]
  | _ -> wrongOperands ins

/// The instruction copying a whole word, which names each of the two pairs by
/// the register it begins at.
let private evenPair head ins =
  match ins.Operands with
  | [ Rg d; Rg r ] -> [ pairWord head (evenReg d) (evenReg r) ]
  | _ -> wrongOperands ins

let multiplyEncoders () =
  [ "movw", evenPair 0x0100us
    "muls", upperPair 0x0200us
    "mulsu", narrowPair 0x0300us
    "fmul", narrowPair 0x0308us
    "fmuls", narrowPair 0x0380us
    "fmulsu", narrowPair 0x0388us ]

/// An instruction working on a single bit of a register, which names the bit in
/// the three lowest bits of the word.
let private regBit head ins =
  match ins.Operands with
  | [ Rg d; Nm value ] -> [ pairWord head (gpr d) (imm3 value) ]
  | _ -> wrongOperands ins

/// The same, for a bit of one of the peripherals, which is named outright
/// rather than through a register.
let private ioBit head ins =
  match ins.Operands with
  | [ Nm a; Nm b ] -> [ ioBitWord head (imm5 a) (imm3 b) ]
  | _ -> wrongOperands ins

let bitEncoders () =
  [ "bld", regBit 0xF800us
    "bst", regBit 0xFA00us
    "sbrc", regBit 0xFC00us
    "sbrs", regBit 0xFE00us
    "cbi", ioBit 0x9800us
    "sbic", ioBit 0x9900us
    "sbi", ioBit 0x9A00us
    "sbis", ioBit 0x9B00us ]

// vim: set tw=80 sts=2 sw=2:
