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
/// Encodes everything that moves a byte about: the loads and the stores through
/// each of the three index registers, the ones reaching a written distance from
/// two of them, the ones naming the byte they reach outright, the reads of the
/// code space, the moves to and from a peripheral, and the four instructions
/// reading and writing the same byte at once.
/// </summary>
module internal B2R2.Assembly.AVR.AsmTransfer

open B2R2.FrontEnd.AVR
open B2R2.Assembly.AVR.ParserHelper
open B2R2.Assembly.AVR.AsmField

/// <summary>
/// The head one word of a load begins with, given how it names the memory it
/// reads.
///
/// Which index register is named and how it moves are spelt out to the last bit
/// rather than held in a field, because the three registers were added to the
/// architecture one at a time and the encodings left over for each of them were
/// whichever ones were still free. The two forms that reach memory without
/// moving the register are the two the same word reaches a written distance
/// with, so they sit in a family of their own.
/// </summary>
let private loadHead ins operand =
  match operand with
  | Rg Register.X -> 0x900Cus
  | Post Register.X -> 0x900Dus
  | Pre Register.X -> 0x900Eus
  | Rg Register.Y -> 0x8008us
  | Post Register.Y -> 0x9009us
  | Pre Register.Y -> 0x900Aus
  | Rg Register.Z -> 0x8000us
  | Post Register.Z -> 0x9001us
  | Pre Register.Z -> 0x9002us
  | _ -> wrongOperands ins

/// A load through an index register.
let private load ins =
  match ins.Operands with
  | [ Rg d; memory ] -> [ regWord (loadHead ins memory) (gpr d) ]
  | _ -> wrongOperands ins

/// A store through one, which is written the same way with the register and the
/// memory the other way about, and encoded the same way with the one bit that
/// says which way the byte goes set.
let private store ins =
  match ins.Operands with
  | [ memory; Rg r ] -> [ regWord (loadHead ins memory ||| 0x200us) (gpr r) ]
  | _ -> wrongOperands ins

/// Which of the two index registers that reach a written distance is named, as
/// the bit that says so. The first of the three reaches no such distance,
/// because the encodings that would say how far were spent on the other two.
let private indexBit reg =
  match reg with
  | Register.Z -> 0x0us
  | Register.Y -> 0x8us
  | _ -> fail $"{Register.toString reg} reaches no written distance"

/// A load of the byte lying a written distance from what an index register
/// holds.
let private loadDisp ins =
  match ins.Operands with
  | [ Rg d; Disp(reg, q) ] ->
    [ dispWord (0x8000us ||| indexBit reg) (gpr d) (imm6 q) ]
  | _ ->
    wrongOperands ins

/// A store of one, the other way about.
let private storeDisp ins =
  match ins.Operands with
  | [ Disp(reg, q); Rg r ] ->
    [ dispWord (0x8200us ||| indexBit reg) (gpr r) (imm6 q) ]
  | _ ->
    wrongOperands ins

/// A load naming the byte it reads outright, which is why it takes a second
/// word: the first has no room left for an address reaching the whole of the
/// data space.
let private loadDirect ins =
  match ins.Operands with
  | [ Rg d; operand ] -> [ regWord 0x9000us (gpr d); dataAddress ins operand ]
  | _ -> wrongOperands ins

/// A store naming the byte it writes outright.
let private storeDirect ins =
  match ins.Operands with
  | [ operand; Rg r ] -> [ regWord 0x9200us (gpr r); dataAddress ins operand ]
  | _ -> wrongOperands ins

/// <summary>
/// A read of the code space.
///
/// It is written either as a name on its own, which reads through the last
/// index register into the first register of the file, or with both of them
/// written out. The two are different instructions rather than one written two
/// ways, because the shorter of them says nothing at all in the bits the longer
/// one names its register in.
/// </summary>
let private loadProgram bare head ins =
  match ins.Operands with
  | [] -> [ bare ]
  | [ Rg d; Rg Register.Z ] -> [ regWord head (gpr d) ]
  | [ Rg d; Post Register.Z ] -> [ regWord (head ||| 0x1us) (gpr d) ]
  | _ -> wrongOperands ins

/// A read of one of the peripherals into a register.
let private readIo ins =
  match ins.Operands with
  | [ Rg d; Nm a ] -> [ splitWord 0xB000us (gpr d) (imm6 a) ]
  | _ -> wrongOperands ins

/// A write of a register out to one, which is written the other way about.
let private writeIo ins =
  match ins.Operands with
  | [ Nm a; Rg r ] -> [ splitWord 0xB800us (gpr r) (imm6 a) ]
  | _ -> wrongOperands ins

/// One of the four instructions reading the byte the last index register names
/// and writing it in the same breath, which name that register first though
/// they write both of them.
let private throughZ head ins =
  match ins.Operands with
  | [ Rg Register.Z; Rg d ] -> [ regWord head (gpr d) ]
  | _ -> wrongOperands ins

let transferEncoders () =
  [ "ld", load
    "st", store
    "ldd", loadDisp
    "std", storeDisp
    "lds", loadDirect
    "sts", storeDirect
    "lpm", loadProgram 0x95C8us 0x9004us
    "elpm", loadProgram 0x95D8us 0x9006us
    "in", readIo
    "out", writeIo
    "xch", throughZ 0x9204us
    "las", throughZ 0x9205us
    "lac", throughZ 0x9206us
    "lat", throughZ 0x9207us ]

// vim: set tw=80 sts=2 sw=2:
