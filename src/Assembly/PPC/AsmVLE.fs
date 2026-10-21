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
/// Encodes the instructions of Variable Length Encoding (VLE), the second
/// encoding of the Power ISA. Its instructions are named e_ where they fill
/// two halfwords and se_ where they fill one, and what the Book of the
/// category calls a form is drawn with the bits numbered from the most
/// significant, which is how the fields below are placed.
/// </summary>
module internal B2R2.Assembly.PPC.AsmVLE

open B2R2
open B2R2.FrontEnd.PPC
open B2R2.Assembly.PPC.ParserHelper
open B2R2.Assembly.PPC.AsmField

/// Every opcode that fills one halfword, which are the ones the category names
/// with the prefix se_.
let private halfwords =
  lazy (System.Enum.GetValues typeof<Opcode>
        |> Seq.cast<Opcode>
        |> Seq.filter (fun opcode -> (string opcode).StartsWith "SE_")
        |> Set.ofSeq)

/// How many bytes an instruction takes: two where it is one of the short forms
/// of the category and four otherwise.
let size (ins: AsmInsInfo) =
  if halfwords.Value.Contains ins.Opcode then 2 else 4

/// An instruction that names nothing and fills a halfword, which is the whole
/// of its encoding.
let private cForm value ins =
  match ins.Operands with
  | [] -> value
  | _ -> wrongOperands ins

/// The four bits that name a general register in the 16-bit forms, which reach
/// r0 to r7 and r24 to r31 only.
let private gpr4 (reg: Register) =
  if reg >= Register.R0 && reg <= Register.R7 then uint32 (int reg)
  elif reg >= Register.R24 && reg <= Register.R31 then uint32 (int reg - 16)
  else fail $"{reg} is not a register a 16-bit instruction can name"

/// The four bits that name one of the registers r8 to r23, which the two
/// instructions that move to or from the "alternate" ones reach.
let private alternate4 (reg: Register) =
  if reg >= Register.R8 && reg <= Register.R23 then uint32 (int reg - 8)
  else fail $"{reg} is not an alternate register"

/// An instruction of one register, which sits in the low four bits.
let private rForm value ins =
  match ins.Operands with
  | [ Rg x ] -> value ||| gpr4 x
  | _ -> wrongOperands ins

/// An instruction of two registers: RX in the low four bits and RY above it.
let private rrForm value ins =
  match ins.Operands with
  | [ Rg x; Rg y ] -> value ||| (gpr4 y <<< 4) ||| gpr4 x
  | _ -> wrongOperands ins

/// se_mtar, which moves RY to an alternate register named in the low bits.
let private moveToAlternate ins =
  match ins.Operands with
  | [ Rg x; Rg y ] -> 0x0200u ||| (gpr4 y <<< 4) ||| alternate4 x
  | _ -> wrongOperands ins

/// se_mfar, which moves an alternate register named above RX to RX.
let private moveFromAlternate ins =
  match ins.Operands with
  | [ Rg x; Rg y ] -> 0x0300u ||| (alternate4 y <<< 4) ||| gpr4 x
  | _ -> wrongOperands ins

/// An instruction of one register and a five-bit number above it.
let private riForm value ins =
  match ins.Operands with
  | [ Rg x; Im n ] -> value ||| (unsigned 5 n <<< 4) ||| gpr4 x
  | _ -> wrongOperands ins

/// An instruction of one register and a number from 1 to 32, which the
/// encoding keeps as one less.
let private roForm value ins =
  match ins.Operands with
  | [ Rg x; Im n ] when n >= 1UL && n <= 32UL ->
    value ||| (unsigned 5 (n - 1UL) <<< 4) ||| gpr4 x
  | _ ->
    wrongOperands ins

/// se_li, whose seven-bit number sits above the register.
let private loadImmediate ins =
  match ins.Operands with
  | [ Rg x; Im n ] -> 0x4800u ||| (unsigned 7 n <<< 4) ||| gpr4 x
  | _ -> wrongOperands ins

/// The eight bits a 16-bit branch holds where it counts how far away the place
/// it names is, in halfwords.
let private distance8 bitLen (ins: AsmInsInfo) target =
  let distance = signedValue bitLen (target - ins.Address)
  if distance % 2L = 0L then signed 8 (distance / 2L)
  else fail "a branch cannot reach a place that is not a halfword away"

/// se_b and se_bl, which differ only in the bit that says they link.
let private branch16 bitLen value ins =
  match ins.Operands with
  | [ Im target ] -> value ||| distance8 bitLen ins target
  | _ -> wrongOperands ins

/// se_bc, whose condition is one bit of CR0 and a value for it.
let private branchOnBit bitLen ins =
  match ins.Operands with
  | [ Im bo; Bit bi; Im target ] when bo <= 1UL && bi < 4u ->
    0xE000u ||| (uint32 bo <<< 10) ||| (bi <<< 8)
    ||| distance8 bitLen ins target
  | _ ->
    wrongOperands ins

/// A load or store of a register at a base register and a displacement that is
/// a multiple of the size of what it moves, which the encoding keeps in four
/// bits as that many sizes.
let private accessForm value size ins =
  match ins.Operands with
  | [ Rg z; Mem(disp, x) ] when disp >= 0 && disp % size = 0 ->
    value ||| (unsigned 4 (uint64 (disp / size)) <<< 8)
    ||| (gpr4 z <<< 4) ||| gpr4 x
  | _ ->
    wrongOperands ins

/// The instructions of Variable Length Encoding, by what they are called.
let vleEncoders bitLen =
  [ Op.SE_ILLEGAL, cForm 0x0000u
    Op.SE_ISYNC, cForm 0x0001u
    Op.SE_SC, cForm 0x0002u
    Op.SE_BLR, cForm 0x0004u
    Op.SE_BLRL, cForm 0x0005u
    Op.SE_BCTR, cForm 0x0006u
    Op.SE_BCTRL, cForm 0x0007u
    Op.SE_NOT, rForm 0x0020u
    Op.SE_NEG, rForm 0x0030u
    Op.SE_MFLR, rForm 0x0080u
    Op.SE_MTLR, rForm 0x0090u
    Op.SE_MFCTR, rForm 0x00A0u
    Op.SE_MTCTR, rForm 0x00B0u
    Op.SE_EXTZB, rForm 0x00C0u
    Op.SE_EXTSB, rForm 0x00D0u
    Op.SE_EXTZH, rForm 0x00E0u
    Op.SE_EXTSH, rForm 0x00F0u
    Op.SE_MR, rrForm 0x0100u
    Op.SE_MTAR, moveToAlternate
    Op.SE_MFAR, moveFromAlternate
    Op.SE_ADD, rrForm 0x0400u
    Op.SE_MULLW, rrForm 0x0500u
    Op.SE_SUB, rrForm 0x0600u
    Op.SE_SUBF, rrForm 0x0700u
    Op.SE_OR, rrForm 0x4400u
    Op.SE_ANDC, rrForm 0x4500u
    Op.SE_AND, rrForm 0x4600u
    Op.SE_ANDdot, rrForm 0x4700u
    Op.SE_CMP, rrForm 0x0C00u
    Op.SE_CMPL, rrForm 0x0D00u
    Op.SE_CMPH, rrForm 0x0E00u
    Op.SE_CMPHL, rrForm 0x0F00u
    Op.SE_SRW, rrForm 0x4000u
    Op.SE_SRAW, rrForm 0x4100u
    Op.SE_SLW, rrForm 0x4200u
    Op.SE_ADDI, roForm 0x2000u
    Op.SE_CMPLI, roForm 0x2200u
    Op.SE_SUBI, roForm 0x2400u
    Op.SE_SUBIdot, roForm 0x2600u
    Op.SE_CMPI, riForm 0x2A00u
    Op.SE_BMASKI, riForm 0x2C00u
    Op.SE_ANDI, riForm 0x2E00u
    Op.SE_BCLRI, riForm 0x6000u
    Op.SE_BGENI, riForm 0x6200u
    Op.SE_BSETI, riForm 0x6400u
    Op.SE_BTSTI, riForm 0x6600u
    Op.SE_SRWI, riForm 0x6800u
    Op.SE_SRAWI, riForm 0x6A00u
    Op.SE_SLWI, riForm 0x6C00u
    Op.SE_B, branch16 bitLen 0xE800u
    Op.SE_BL, branch16 bitLen 0xE900u
    Op.SE_BC, branchOnBit bitLen
    Op.SE_LBZ, accessForm 0x8000u 1
    Op.SE_STB, accessForm 0x9000u 1
    Op.SE_LHZ, accessForm 0xA000u 2
    Op.SE_STH, accessForm 0xB000u 2
    Op.SE_LWZ, accessForm 0xC000u 4
    Op.SE_STW, accessForm 0xD000u 4
    Op.SE_LI, loadImmediate ]
