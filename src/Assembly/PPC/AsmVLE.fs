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

/// The bits a branch holds where it counts how far away the place it names is,
/// in halfwords.
let private distanceIn width bitLen (ins: AsmInsInfo) target =
  let distance = signedValue bitLen (target - ins.Address)
  if distance % 2L = 0L then signed width (distance / 2L)
  else fail "a branch cannot reach a place that is not a halfword away"

/// The eight bits of a 16-bit branch.
let private distance8 bitLen ins target = distanceIn 8 bitLen ins target

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

/// A load or a store of the D-form: a register and a base register with a
/// displacement of sixteen bits.
let private dForm po ins =
  match ins.Operands with
  | [ Rg t; Mem(disp, a) ] ->
    (po <<< 26) ||| (gpr t <<< 21) ||| (gpr a <<< 16) ||| displacement disp
  | _ ->
    wrongOperands ins

/// A load or a store of the D8-form: the same with a displacement of eight bits
/// and a byte that says which instruction it is.
let private d8Form xo ins =
  match ins.Operands with
  | [ Rg t; Mem(disp, a) ] ->
    (6u <<< 26) ||| (gpr t <<< 21) ||| (gpr a <<< 16) ||| (xo <<< 8)
    ||| signed 8 (int64 disp)
  | _ ->
    wrongOperands ins

/// e_b and e_bl, whose distance is 24 bits of halfwords with the bit that says
/// they link below it.
let private branch32 bitLen link ins =
  match ins.Operands with
  | [ Im target ] ->
    0x78000000u ||| (distanceIn 24 bitLen ins target <<< 1) ||| link
  | _ ->
    wrongOperands ins

/// e_bc and e_bcl, which name the counter and the bit to test in two bits, the
/// bit in four, and a distance of 15 bits of halfwords.
let private conditionalBranch32 bitLen link ins =
  match ins.Operands with
  | [ Im bo; Bit bi; Im target ] when bo <= 3UL && bi < 16u ->
    0x7A000000u ||| (uint32 bo <<< 20) ||| (bi <<< 16) ||| link
    ||| (distanceIn 15 bitLen ins target <<< 1)
  | _ ->
    wrongOperands ins

/// The instructions that combine two bits of the condition register into a
/// third.
let private crLogic xo ins =
  match ins.Operands with
  | [ Bit d; Bit a; Bit b ] ->
    0x7C000000u ||| (d <<< 21) ||| (a <<< 16) ||| (b <<< 11) ||| (xo <<< 1)
  | _ ->
    wrongOperands ins

/// e_mcrf, which moves one field of the condition register to another.
let private moveField ins =
  match ins.Operands with
  | [ Rg d; Rg s ] -> 0x7C000020u ||| (crf d <<< 23) ||| (crf s <<< 18)
  | _ -> wrongOperands ins

/// e_sc, which says the level of its call after its name unless it is zero.
let private systemCall ins =
  match ins.Operands with
  | [] -> 0x7C000048u
  | [ Im level ] -> 0x7C000048u ||| (unsigned 5 level <<< 11)
  | _ -> wrongOperands ins

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
    Op.E_LBZ, dForm 12u
    Op.E_STB, dForm 13u
    Op.E_LHA, dForm 14u
    Op.E_LWZ, dForm 20u
    Op.E_STW, dForm 21u
    Op.E_LHZ, dForm 22u
    Op.E_STH, dForm 23u
    Op.E_LBZU, d8Form 0x00u
    Op.E_LHZU, d8Form 0x01u
    Op.E_LWZU, d8Form 0x02u
    Op.E_LHAU, d8Form 0x03u
    Op.E_STBU, d8Form 0x04u
    Op.E_STHU, d8Form 0x05u
    Op.E_STWU, d8Form 0x06u
    Op.E_LMW, d8Form 0x08u
    Op.E_STMW, d8Form 0x09u
    Op.E_B, branch32 bitLen 0u
    Op.E_BL, branch32 bitLen 1u
    Op.E_BC, conditionalBranch32 bitLen 0u
    Op.E_BCL, conditionalBranch32 bitLen 1u
    Op.E_CRNOR, crLogic 33u
    Op.E_CRANDC, crLogic 129u
    Op.E_CRXOR, crLogic 193u
    Op.E_CRNAND, crLogic 225u
    Op.E_CRAND, crLogic 257u
    Op.E_CREQV, crLogic 289u
    Op.E_CRORC, crLogic 417u
    Op.E_CROR, crLogic 449u
    Op.E_MCRF, moveField
    Op.E_SC, systemCall
    Op.SE_LI, loadImmediate ]
