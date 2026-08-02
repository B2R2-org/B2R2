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
/// Encodes the instructions going somewhere other than the next word, together
/// with the ones that say something to the machine rather than compute: the
/// branches reading one bit of the status word, the jumps and calls reaching
/// either a little way or the whole of the code space, and the instructions
/// naming nothing at all.
/// </summary>
module internal B2R2.Assembly.AVR.AsmBranch

open B2R2.Assembly.AVR.ParserHelper
open B2R2.Assembly.AVR.AsmField

/// <summary>
/// A branch reading one bit of the status word.
///
/// Every one of them is the same instruction: the bit it reads and whether it
/// goes when that bit is set or when it is clear are fields, and the sixteen
/// names are the sixteen ways of filling those two in. The distance such a
/// branch holds is seven bits wide, which reaches sixty-three words either way.
/// </summary>
let private branch head ins =
  match ins.Operands with
  | [ operand ] -> [ head ||| (branchField 7 ins operand <<< 3) ]
  | _ -> wrongOperands ins

/// The same, written out as the one instruction it is, with the bit it reads
/// written rather than said by the name.
let private branchOnBit head ins =
  match ins.Operands with
  | [ Nm value; operand ] ->
    [ head ||| (branchField 7 ins operand <<< 3) ||| imm3 value ]
  | _ ->
    wrongOperands ins

/// A jump or a call reaching a little way, which spends every bit below its
/// name on how far it goes and so reaches two thousand words either way.
let private relativeJump head ins =
  match ins.Operands with
  | [ operand ] -> [ head ||| branchField 12 ins operand ]
  | _ -> wrongOperands ins

/// <summary>
/// A jump or a call reaching the whole of the code space.
///
/// Where it goes is a word address twenty-two bits wide, which no single word
/// holds: the six highest bits of it are scattered over the word naming the
/// instruction and the sixteen below them make up a second word of their own.
/// </summary>
let private longJump rest ins =
  match ins.Operands with
  | [ operand ] ->
    let target = jumpTarget ins operand
    let high = uint16 ((target >>> 17) &&& 0x1Fu)
    let low = uint16 ((target >>> 16) &&& 0x1u)
    [ regWord (0x9400us ||| rest ||| low) high; uint16 (target &&& 0xFFFFu) ]
  | _ ->
    wrongOperands ins

let branchEncoders () =
  [ "brcs", branch 0xF000us
    "brlo", branch 0xF000us
    "breq", branch 0xF001us
    "brmi", branch 0xF002us
    "brvs", branch 0xF003us
    "brlt", branch 0xF004us
    "brhs", branch 0xF005us
    "brts", branch 0xF006us
    "brie", branch 0xF007us
    "brcc", branch 0xF400us
    "brsh", branch 0xF400us
    "brne", branch 0xF401us
    "brpl", branch 0xF402us
    "brvc", branch 0xF403us
    "brge", branch 0xF404us
    "brhc", branch 0xF405us
    "brtc", branch 0xF406us
    "brid", branch 0xF407us
    "brbs", branchOnBit 0xF000us
    "brbc", branchOnBit 0xF400us
    "rjmp", relativeJump 0xC000us
    "rcall", relativeJump 0xD000us
    "jmp", longJump 0xCus
    "call", longJump 0xEus ]

/// An instruction setting or clearing one bit of the status word, with the bit
/// written rather than said by the name.
let private statusBit head ins =
  match ins.Operands with
  | [ Nm value ] -> [ regWord head (imm3 value) ]
  | _ -> wrongOperands ins

/// The one instruction encrypting a block, which holds nothing but which round
/// of the cipher to run.
let private encrypt ins =
  match ins.Operands with
  | [ Nm value ] -> [ regWord 0x940Bus (imm4 value) ]
  | _ -> wrongOperands ins

/// An instruction naming nothing at all, and therefore one word spelt out to
/// the last bit.
let private noOperand word ins =
  match ins.Operands with
  | [] -> [ word ]
  | _ -> wrongOperands ins

/// <summary>
/// The instructions naming nothing, together with the two naming a single bit
/// of the status word.
///
/// The eight instructions setting a bit of that word and the eight clearing one
/// are the two instructions naming such a bit with every value it may hold
/// written out, and they are listed as their own names because that is what the
/// disassembler writes.
/// </summary>
let controlEncoders () =
  [ "bset", statusBit 0x9408us
    "bclr", statusBit 0x9488us
    "des", encrypt
    "sec", noOperand 0x9408us
    "sez", noOperand 0x9418us
    "sen", noOperand 0x9428us
    "sev", noOperand 0x9438us
    "ses", noOperand 0x9448us
    "seh", noOperand 0x9458us
    "set", noOperand 0x9468us
    "sei", noOperand 0x9478us
    "clc", noOperand 0x9488us
    "clz", noOperand 0x9498us
    "cln", noOperand 0x94A8us
    "clv", noOperand 0x94B8us
    "cls", noOperand 0x94C8us
    "clh", noOperand 0x94D8us
    "clt", noOperand 0x94E8us
    "cli", noOperand 0x94F8us
    "nop", noOperand 0x0000us
    "ret", noOperand 0x9508us
    "reti", noOperand 0x9518us
    "sleep", noOperand 0x9588us
    "break", noOperand 0x9598us
    "wdr", noOperand 0x95A8us
    "spm", noOperand 0x95E8us
    "ijmp", noOperand 0x9409us
    "eijmp", noOperand 0x9419us
    "icall", noOperand 0x9509us
    "eicall", noOperand 0x9519us ]

// vim: set tw=80 sts=2 sw=2:
