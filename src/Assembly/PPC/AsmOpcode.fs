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
/// and the logic, the rotates, the comparisons and the traps, the loads and the
/// stores, the branches, and what a program says to the machine it runs on.
/// </summary>
module internal B2R2.Assembly.PPC.AsmOpcode

open B2R2.FrontEnd.PPC
open B2R2.Assembly.PPC.ParserHelper
open B2R2.Assembly.PPC.AsmField

(* The forms of primary opcode 31, which is where every instruction naming
   three registers lives. Which of the three fields holds which register is not
   the same throughout: what an instruction computes goes in the first field
   where the answer is a new value and in the second where it is a register
   being written through, and the arithmetic and the logic differ in exactly
   that way. *)
/// An X-form "rD, rA, rB".
let private xDab xo rc ins =
  match ins.Operands with
  | [ Rg d; Rg a; Rg b ] -> xForm 31u (gpr d) (gpr a) (gpr b) xo rc
  | _ -> wrongOperands ins

/// An X-form "rA, rS, rB", which is how the logic is written.
let private xAsb xo rc ins =
  match ins.Operands with
  | [ Rg a; Rg s; Rg b ] -> xForm 31u (gpr s) (gpr a) (gpr b) xo rc
  | _ -> wrongOperands ins

/// An X-form "rD, rA" with no third register.
let private xDa xo rc ins =
  match ins.Operands with
  | [ Rg d; Rg a ] -> xForm 31u (gpr d) (gpr a) 0u xo rc
  | _ -> wrongOperands ins

/// An X-form "rA, rS" with no third register.
let private xAs xo rc ins =
  match ins.Operands with
  | [ Rg a; Rg s ] -> xForm 31u (gpr s) (gpr a) 0u xo rc
  | _ -> wrongOperands ins

/// An X-form "rA, rB", which is how the instructions that reach the caches say
/// what they reach.
let private xAb xo ins =
  match ins.Operands with
  | [ Rg a; Rg b ] -> xForm 31u 0u (gpr a) (gpr b) xo 0u
  | _ -> wrongOperands ins

/// An X-form naming one general register, where the first field holds it.
let private xD xo ins =
  match ins.Operands with
  | [ Rg d ] -> xForm 31u (gpr d) 0u 0u xo 0u
  | _ -> wrongOperands ins

/// An X-form naming one general register, where the third field holds it.
let private xB xo ins =
  match ins.Operands with
  | [ Rg b ] -> xForm 31u 0u 0u (gpr b) xo 0u
  | _ -> wrongOperands ins

/// An X-form with nothing written after its name.
let private xNone xo ins =
  match ins.Operands with
  | [] -> xForm 31u 0u 0u 0u xo 0u
  | _ -> wrongOperands ins

/// <summary>
/// The four names an instruction goes by where both whether it reports an
/// overflow and whether it records what it did are written into its name.
///
/// The bit saying that it reports an overflow sits at the top of the extended
/// opcode, so the two names that carry it are the two the opcode reads five
/// hundred and twelve higher.
/// </summary>
let private overflowing form xo (plain, dot) (ovf, ovfDot) =
  [ plain, form xo 0u
    dot, form xo 1u
    ovf, form (xo + 512u) 0u
    ovfDot, form (xo + 512u) 1u ]

/// or under the name that says the two registers it reads are one, which is
/// what moving a register to another asks for.
let private xMove ins =
  match ins.Operands with
  | [ Rg a; Rg s ] -> xForm 31u (gpr s) (gpr a) (gpr s) 444u 0u
  | _ -> wrongOperands ins

/// The instructions on the general registers that write one of them.
let arithmeticEncoders () =
  List.concat
    [ overflowing xDab 8u (Op.SUBFC, Op.SUBFCdot) (Op.SUBFCO, Op.SUBFCOdot)
      overflowing xDab 10u (Op.ADDC, Op.ADDCdot) (Op.ADDCO, Op.ADDCOdot)
      overflowing xDab 40u (Op.SUBF, Op.SUBFdot) (Op.SUBFO, Op.SUBFOdot)
      overflowing xDa 104u (Op.NEG, Op.NEGdot) (Op.NEGO, Op.NEGOdot)
      overflowing xDab 136u (Op.SUBFE, Op.SUBFEdot) (Op.SUBFEO, Op.SUBFEOdot)
      overflowing xDab 138u (Op.ADDE, Op.ADDEdot) (Op.ADDEO, Op.ADDEOdot)
      overflowing xDa 200u (Op.SUBFZE, Op.SUBFZEdot)
                           (Op.SUBFZEO, Op.SUBFZEOdot)
      overflowing xDa 202u (Op.ADDZE, Op.ADDZEdot) (Op.ADDZEO, Op.ADDZEOdot)
      overflowing xDa 232u (Op.SUBFME, Op.SUBFMEdot)
                           (Op.SUBFMEO, Op.SUBFMEOdot)
      overflowing xDa 234u (Op.ADDME, Op.ADDMEdot) (Op.ADDMEO, Op.ADDMEOdot)
      overflowing xDab 235u (Op.MULLW, Op.MULLWdot) (Op.MULLWO, Op.MULLWOdot)
      overflowing xDab 266u (Op.ADD, Op.ADDdot) (Op.ADDO, Op.ADDOdot)
      overflowing xDab 459u (Op.DIVWU, Op.DIVWUdot) (Op.DIVWUO, Op.DIVWUOdot)
      overflowing xDab 491u (Op.DIVW, Op.DIVWdot) (Op.DIVWO, Op.DIVWOdot)
      recording xDab 11u Op.MULHWU Op.MULHWUdot
      recording xDab 75u Op.MULHW Op.MULHWdot
      (* The instructions on a whole doubleword, which a source that is only
         thirty-two bits wide has no register to keep the answer of. *)
      overflowing xDab 233u (Op.MULLD, Op.MULLDdot) (Op.MULLDO, Op.MULLDOdot)
      overflowing xDab 457u (Op.DIVDU, Op.DIVDUdot) (Op.DIVDUO, Op.DIVDUOdot)
      overflowing xDab 489u (Op.DIVD, Op.DIVDdot) (Op.DIVDO, Op.DIVDOdot)
      recording xDab 9u Op.MULHDU Op.MULHDUdot
      recording xDab 73u Op.MULHD Op.MULHDdot ]

/// The instructions that work a bit at a time: the logic, the shifts, and the
/// ones that count or gather what the bits of a register say.
let logicalEncoders () =
  List.concat
    [ recording xAsb 24u Op.SLW Op.SLWdot
      recording xAsb 28u Op.AND Op.ANDdot
      recording xAsb 60u Op.ANDC Op.ANDCdot
      recording xAsb 124u Op.NOR Op.NORdot
      recording xAsb 284u Op.EQV Op.EQVdot
      recording xAsb 316u Op.XOR Op.XORdot
      recording xAsb 412u Op.ORC Op.ORCdot
      recording xAsb 444u Op.OR Op.ORdot
      recording xAsb 476u Op.NAND Op.NANDdot
      recording xAsb 536u Op.SRW Op.SRWdot
      recording xAsb 792u Op.SRAW Op.SRAWdot
      recording xAs 26u Op.CNTLZW Op.CNTLZWdot
      recording xAs 922u Op.EXTSH Op.EXTSHdot
      recording xAs 954u Op.EXTSB Op.EXTSBdot
      recording xAsb 27u Op.SLD Op.SLDdot
      recording xAsb 539u Op.SRD Op.SRDdot
      recording xAsb 794u Op.SRAD Op.SRADdot
      recording xAs 58u Op.CNTLZD Op.CNTLZDdot
      recording xAs 986u Op.EXTSW Op.EXTSWdot
      [ Op.MR, xMove
        Op.POPCNTB, xAs 122u 0u
        Op.POPCNTW, xAs 378u 0u
        Op.POPCNTD, xAs 506u 0u
        Op.PRTYW, xAs 154u 0u
        Op.PRTYD, xAs 186u 0u
        Op.CMPB, xAsb 508u 0u
        Op.BPERMD, xAsb 252u 0u ] ]

(* The rotates. What a rotate keeps of what it rotated is a run of bits, and
   the encoding names that run by where it starts and where it ends; a name of
   its own is what a source writes where the two say something simpler than a
   run, such as a shift or a clearing of one end. *)
/// An M-form "rA, rS, SH, MB, ME", which is a rotate by a written amount.
let private mForm po rc ins =
  match ins.Operands with
  | [ Rg a; Rg s; Im sh; Im mb; Im me ] ->
    let rest = ((unsigned 5 mb) <<< 6) ||| ((unsigned 5 me) <<< 1) ||| rc
    word po (gpr s) (gpr a) (unsigned 5 sh) rest
  | _ -> wrongOperands ins

/// An M-form "rA, rS, rB, MB, ME", which is a rotate by what a register holds.
let private mFormReg rc ins =
  match ins.Operands with
  | [ Rg a; Rg s; Rg b; Im mb; Im me ] ->
    let rest = ((unsigned 5 mb) <<< 6) ||| ((unsigned 5 me) <<< 1) ||| rc
    word 23u (gpr s) (gpr a) (gpr b) rest
  | _ -> wrongOperands ins

/// rotlw, which is the rotate by a register that keeps everything it rotated.
let private xRotate ins =
  match ins.Operands with
  | [ Rg a; Rg s; Rg b ] -> word 23u (gpr s) (gpr a) (gpr b) (31u <<< 1)
  | _ -> wrongOperands ins

/// <summary>
/// A rotate written under a name that says what it and its mask together do.
///
/// One number is what the source writes, and the name says which three fields
/// of the encoding that number stands for.
/// </summary>
let private shorthandRotate fields ins =
  match ins.Operands with
  | [ Rg a; Rg s; Im n ] ->
    let struct (sh, mb, me) = fields (unsigned 5 n)
    word 21u (gpr s) (gpr a) sh ((mb <<< 6) ||| (me <<< 1))
  | _ -> wrongOperands ins

/// rotlwi, which keeps all of what it rotated.
let private rotateBy n = struct (n, 0u, 31u)

/// slwi, which is a rotate keeping only what did not fall off the top.
let private shiftLeftBy n = struct (n, 0u, 31u - n)

/// srwi, whose rotate is the other way round from the shift it stands for; a
/// shift by nothing is therefore a rotate by a whole register, which the field
/// holding the amount cannot say.
let private shiftRightBy n =
  if n = 0u then fail "a shift right by nothing has no encoding"
  else struct (32u - n, n, 31u)

/// clrlwi, which keeps everything below the bit it is given.
let private clearLeftAt n = struct (0u, n, 31u)

/// clrrwi, which keeps everything above the bit it is given.
let private clearRightAt n = struct (0u, 0u, 31u - n)

/// srawi, whose amount is written where a rotate keeps a register.
let private xShiftImm xo rc ins =
  match ins.Operands with
  | [ Rg a; Rg s; Im sh ] ->
    xForm 31u (gpr s) (gpr a) (unsigned 5 sh) xo rc
  | _ -> wrongOperands ins

/// sradi, whose amount is six bits wide and keeps its highest one below the
/// extended opcode.
let private xShiftImm64 rc ins =
  match ins.Operands with
  | [ Rg a; Rg s; Im shift ] ->
    let sh = unsigned 6 shift
    let rest = (413u <<< 2) ||| ((sh >>> 5) <<< 1) ||| rc
    word 31u (gpr s) (gpr a) (sh &&& 0x1Fu) rest
  | _ -> wrongOperands ins

/// <summary>
/// An MD-form "rA, rS, SH, MB", which rotates a whole doubleword.
///
/// Both the amount and the bit the mask is bounded at are six bits wide, and
/// the encoding keeps the highest bit of each away from the rest of its field.
/// </summary>
let private mdForm xo rc ins =
  match ins.Operands with
  | [ Rg a; Rg s; Im shift; Im bound ] ->
    let sh = unsigned 6 shift
    let mb = unsigned 6 bound
    let rest =
      ((mb &&& 0x1Fu) <<< 6) ||| ((mb >>> 5) <<< 5) ||| (xo <<< 2)
      ||| ((sh >>> 5) <<< 1) ||| rc
    word 30u (gpr s) (gpr a) (sh &&& 0x1Fu) rest
  | _ -> wrongOperands ins

/// An MDS-form "rA, rS, rB, MB", which takes its amount from a register and so
/// splits only the bound of its mask.
let private mdsForm which rc ins =
  match ins.Operands with
  | [ Rg a; Rg s; Rg b; Im bound ] ->
    let mb = unsigned 6 bound
    let rest =
      ((mb &&& 0x1Fu) <<< 6) ||| ((mb >>> 5) <<< 5) ||| (4u <<< 2)
      ||| (which <<< 1) ||| rc
    word 30u (gpr s) (gpr a) (gpr b) rest
  | _ -> wrongOperands ins

/// The rotates, and the shifts and maskings that are rotates under another
/// name.
let rotateEncoders () =
  List.concat
    [ recording mForm 20u Op.RLWIMI Op.RLWIMIdot
      recording mForm 21u Op.RLWINM Op.RLWINMdot
      recording xShiftImm 824u Op.SRAWI Op.SRAWIdot
      recording mdForm 0u Op.RLDICL Op.RLDICLdot
      recording mdForm 1u Op.RLDICR Op.RLDICRdot
      recording mdForm 2u Op.RLDIC Op.RLDICdot
      recording mdForm 3u Op.RLDIMI Op.RLDIMIdot
      recording mdsForm 0u Op.RLDCL Op.RLDCLdot
      recording mdsForm 1u Op.RLDCR Op.RLDCRdot
      [ Op.RLWNM, mFormReg 0u
        Op.RLWNMdot, mFormReg 1u
        Op.ROTLW, xRotate
        Op.ROTLWI, shorthandRotate rotateBy
        Op.SLWI, shorthandRotate shiftLeftBy
        Op.SRWI, shorthandRotate shiftRightBy
        Op.CLRLWI, shorthandRotate clearLeftAt
        Op.CLRRWI, shorthandRotate clearRightAt
        Op.SRADI, xShiftImm64 0u
        Op.SRADIdot, xShiftImm64 1u ] ]

(* The comparisons and the traps. A comparison says which field of the
   condition register it answers in, and whether it reads a whole doubleword or
   only half of one is in its name rather than beside it. A trap says which
   comparisons are the ones it fires on, and the ten it fires on singly have
   names of their own. *)
/// An X-form comparison "crfD, rA, rB".
let private xCompare xo width ins =
  match ins.Operands with
  | [ Rg f; Rg a; Rg b ] ->
    xForm 31u (((crf f) <<< 2) ||| width) (gpr a) (gpr b) xo 0u
  | _ -> wrongOperands ins

/// A D-form comparison "crfD, rA, value", read as signed.
let private dCompare bitLen po width ins =
  match ins.Operands with
  | [ Rg f; Rg a; Im v ] ->
    dForm po (((crf f) <<< 2) ||| width) (gpr a) (immediate16 bitLen v)
  | _ -> wrongOperands ins

/// A D-form comparison "crfD, rA, value", read as a count.
let private dCompareUnsigned po width ins =
  match ins.Operands with
  | [ Rg f; Rg a; Im v ] ->
    dForm po (((crf f) <<< 2) ||| width) (gpr a) (uimmediate16 v)
  | _ -> wrongOperands ins

/// A trap whose name says which comparisons fire it.
let private xTrapNamed xo cond ins =
  match ins.Operands with
  | [ Rg a; Rg b ] -> xForm 31u cond (gpr a) (gpr b) xo 0u
  | _ -> wrongOperands ins

/// A trap that says beside its name which comparisons fire it.
let private xTrap xo ins =
  match ins.Operands with
  | [ Im cond; Rg a; Rg b ] ->
    xForm 31u (unsigned 5 cond) (gpr a) (gpr b) xo 0u
  | _ -> wrongOperands ins

/// A trap against a written number whose name says which comparisons fire it.
let private dTrapNamed bitLen po cond ins =
  match ins.Operands with
  | [ Rg a; Im v ] -> dForm po cond (gpr a) (immediate16 bitLen v)
  | _ -> wrongOperands ins

/// A trap against a written number that says beside its name which comparisons
/// fire it.
let private dTrap bitLen po ins =
  match ins.Operands with
  | [ Im cond; Rg a; Im v ] ->
    dForm po (unsigned 5 cond) (gpr a) (immediate16 bitLen v)
  | _ -> wrongOperands ins

/// trap, which is the trap that fires on every comparison at once.
let private xTrapAlways ins =
  match ins.Operands with
  | [] -> xForm 31u 31u 0u 0u 4u 0u
  | _ -> wrongOperands ins

/// Which comparisons each of the traps that name theirs fires on, paired with
/// the name it goes by against a register and the one against a number.
let private trapConditions =
  [ Op.TWLGT, Op.TWLGTI, 1u
    Op.TWLLT, Op.TWLLTI, 2u
    Op.TWEQ, Op.TWEQI, 4u
    Op.TWLNL, Op.TWLNLI, 5u
    Op.TWLLE, Op.TWLLEI, 6u
    Op.TWGT, Op.TWGTI, 8u
    Op.TWGE, Op.TWGEI, 12u
    Op.TWLT, Op.TWLTI, 16u
    Op.TWLE, Op.TWLEI, 20u
    Op.TWNE, Op.TWNEI, 24u ]

/// The comparisons and the traps.
let comparisonEncoders bitLen =
  let named (reg, imm, cond) =
    [ reg, xTrapNamed 4u cond; imm, dTrapNamed bitLen 3u cond ]
  [ Op.CMPW, xCompare 0u 0u
    Op.CMPD, xCompare 0u 1u
    Op.CMPLW, xCompare 32u 0u
    Op.CMPLD, xCompare 32u 1u
    Op.CMPWI, dCompare bitLen 11u 0u
    Op.CMPDI, dCompare bitLen 11u 1u
    Op.CMPLWI, dCompareUnsigned 10u 0u
    Op.CMPLDI, dCompareUnsigned 10u 1u
    Op.TW, xTrap 4u
    Op.TD, xTrap 68u
    Op.TWI, dTrap bitLen 3u
    Op.TDI, dTrap bitLen 2u
    Op.TRAP, xTrapAlways ]
  @ List.collect named trapConditions

(* The instructions taking a written number, and the ones reaching memory. What
   a source writes as a distance from a register is the same operand
   throughout; how wide the access it makes is belongs to the instruction. *)
/// A D-form "rD, rA, value", read as signed.
let private dSigned bitLen po ins =
  match ins.Operands with
  | [ Rg d; Rg a; Im v ] ->
    dForm po (gpr d) (gpr a) (immediate16 bitLen v)
  | _ -> wrongOperands ins

/// A D-form "rD, value", which is what an instruction adding to nothing at all
/// is written as.
let private dLoadImm bitLen po ins =
  match ins.Operands with
  | [ Rg d; Im v ] -> dForm po (gpr d) 0u (immediate16 bitLen v)
  | _ -> wrongOperands ins

/// A D-form "rA, rS, value", read as a count, which is how the logic against a
/// written number is written.
let private dUnsigned po ins =
  match ins.Operands with
  | [ Rg a; Rg s; Im v ] -> dForm po (gpr s) (gpr a) (uimmediate16 v)
  | _ -> wrongOperands ins

/// nop, which is the instruction that ors nothing into nothing.
let private dNop ins =
  match ins.Operands with
  | [] -> dForm 24u 0u 0u 0u
  | _ -> wrongOperands ins

/// A D-form access to memory, whose distance from the base register is written
/// whole.
let private dMemory po ins =
  match ins.Operands with
  | [ Rg r; Mem(disp, b) ] -> dForm po (gpr r) (gpr b) (displacement disp)
  | _ -> wrongOperands ins

/// A DS-form access to memory, which reaches only a whole word and so keeps
/// two bits of its own where the distance would end.
let private dsMemory po which ins =
  match ins.Operands with
  | [ Rg r; Mem(disp, b) ] ->
    dForm po (gpr r) (gpr b) ((wordDisplacement disp) ||| which)
  | _ -> wrongOperands ins

/// An X-form access to memory at a distance another register holds.
let private xMemory xo rc ins =
  match ins.Operands with
  | [ Rg r; Rg a; Rg b ] -> xForm 31u (gpr r) (gpr a) (gpr b) xo rc
  | _ -> wrongOperands ins

/// An X-form access to as many bytes as are written beside it.
let private xString xo ins =
  match ins.Operands with
  | [ Rg r; Rg a; Im n ] ->
    xForm 31u (gpr r) (gpr a) (unsigned 5 n) xo 0u
  | _ -> wrongOperands ins

/// The instructions taking a written number and the ones reaching memory.
let loadStoreEncoders bitLen =
  [ Op.MULLI, dSigned bitLen 7u
    Op.SUBFIC, dSigned bitLen 8u
    Op.ADDIC, dSigned bitLen 12u
    Op.ADDICdot, dSigned bitLen 13u
    Op.ADDI, dSigned bitLen 14u
    Op.ADDIS, dSigned bitLen 15u
    Op.LI, dLoadImm bitLen 14u
    Op.LIS, dLoadImm bitLen 15u
    Op.ORI, dUnsigned 24u
    Op.ORIS, dUnsigned 25u
    Op.XORI, dUnsigned 26u
    Op.XORIS, dUnsigned 27u
    Op.ANDIdot, dUnsigned 28u
    Op.ANDISdot, dUnsigned 29u
    Op.NOP, dNop
    Op.LWZ, dMemory 32u
    Op.LWZU, dMemory 33u
    Op.LBZ, dMemory 34u
    Op.LBZU, dMemory 35u
    Op.STW, dMemory 36u
    Op.STWU, dMemory 37u
    Op.STB, dMemory 38u
    Op.STBU, dMemory 39u
    Op.LHZ, dMemory 40u
    Op.LHZU, dMemory 41u
    Op.LHA, dMemory 42u
    Op.LHAU, dMemory 43u
    Op.STH, dMemory 44u
    Op.STHU, dMemory 45u
    Op.LMW, dMemory 46u
    Op.STMW, dMemory 47u
    Op.LD, dsMemory 58u 0u
    Op.LDU, dsMemory 58u 1u
    Op.LWA, dsMemory 58u 2u
    Op.STD, dsMemory 62u 0u
    Op.STDU, dsMemory 62u 1u
    Op.LWARX, xMemory 20u 0u
    Op.LWZX, xMemory 23u 0u
    Op.LWZUX, xMemory 55u 0u
    Op.LBZX, xMemory 87u 0u
    Op.LBZUX, xMemory 119u 0u
    Op.STWCXdot, xMemory 150u 1u
    Op.STWX, xMemory 151u 0u
    Op.STWUX, xMemory 183u 0u
    Op.STBX, xMemory 215u 0u
    Op.STBUX, xMemory 247u 0u
    Op.LHZX, xMemory 279u 0u
    Op.ECIWX, xMemory 310u 0u
    Op.LHZUX, xMemory 311u 0u
    Op.LHAX, xMemory 343u 0u
    Op.LHAUX, xMemory 375u 0u
    Op.STHX, xMemory 407u 0u
    Op.ECOWX, xMemory 438u 0u
    Op.STHUX, xMemory 439u 0u
    Op.LSWX, xMemory 533u 0u
    Op.LWBRX, xMemory 534u 0u
    Op.STSWX, xMemory 661u 0u
    Op.STWBRX, xMemory 662u 0u
    Op.LHBRX, xMemory 790u 0u
    Op.STHBRX, xMemory 918u 0u
    Op.LSWI, xString 597u
    Op.STSWI, xString 725u
    Op.LDX, xMemory 21u 0u
    Op.LBARX, xMemory 52u 0u
    Op.LDUX, xMemory 53u 0u
    Op.LDARX, xMemory 84u 0u
    Op.LHARX, xMemory 116u 0u
    Op.STDX, xMemory 149u 0u
    Op.STDUX, xMemory 181u 0u
    Op.STDCXdot, xMemory 214u 1u
    Op.LWAX, xMemory 341u 0u
    Op.LWAUX, xMemory 373u 0u
    Op.LDBRX, xMemory 532u 0u
    Op.STDBRX, xMemory 660u 0u
    Op.STBCXdot, xMemory 694u 1u
    Op.STHCXdot, xMemory 726u 1u ]

(* The branches. What the disassembler prints where a branch names a place is
   the address it resolved, so what a source writes there is an address too;
   what the encoding holds is how far away that address is, save in the forms
   that name a place outright. *)
/// An I-form branch, which is the branch that names its place and nothing
/// else.
let private iBranch bitLen absolute link ins =
  match ins.Operands with
  | [ Im target ] ->
    let li =
      if absolute = 0u then relativeTarget 26 bitLen ins.Address target
      else absoluteTarget 26 bitLen target
    (18u <<< 26) ||| (li &&& 0x03FFFFFCu) ||| (absolute <<< 1) ||| link
  | _ -> wrongOperands ins

/// The sixteen bits a conditional branch holds, given the two bits below them
/// that say whether it names its place outright and whether it leaves behind
/// where it came from.
let private branchField bitLen aalk pc target =
  if (aalk &&& 2u) = 0u then relativeTarget 16 bitLen pc target
  else absoluteTarget 16 bitLen target

/// A B-form branch, which says beside its name what it does to the counter and
/// which bit of the condition register it tests.
let private bBranch bitLen aalk ins =
  match ins.Operands with
  | [ Im bo; Bit bi; Im target ] ->
    let bd = branchField bitLen aalk ins.Address target
    dForm 16u (unsigned 5 bo) bi ((bd &&& 0xFFFCu) ||| aalk)
  | _ -> wrongOperands ins

/// <summary>
/// A conditional branch written under a simplified name.
///
/// What the branch does to the counter and which of a condition-register
/// field's four bits it tests are both in the name, so what is left to write is
/// the field that bit lies in and where to go. A source may leave the field out
/// and mean the first one, or write the whole bit as one number.
/// </summary>
let private namedBranch bitLen (bo, bit) aalk ins =
  let go bi target =
    let bd = branchField bitLen aalk ins.Address target
    dForm 16u bo bi ((bd &&& 0xFFFCu) ||| aalk)
  match ins.Operands with
  | [ Im target ] -> go bit target
  | [ Rg field; Im target ] -> go (((crf field) <<< 2) ||| bit) target
  | [ Bit bi; Im target ] -> go bi target
  | _ -> wrongOperands ins

/// A branch to what one of the two registers a branch may read holds, written
/// under a simplified name.
let private namedRegisterBranch xo (bo, bit) link ins =
  let go bi = word 19u bo bi 0u ((xo <<< 1) ||| link)
  match ins.Operands with
  | [] -> go bit
  | [ Rg field ] -> go (((crf field) <<< 2) ||| bit)
  | [ Bit bi ] -> go bi
  | _ -> wrongOperands ins

/// A branch to what one of the two registers a branch may read holds, saying
/// beside its name what it tests.
let private registerBranch xo link ins =
  match ins.Operands with
  | [ Im bo; Bit bi ] -> word 19u (unsigned 5 bo) bi 0u ((xo <<< 1) ||| link)
  | _ -> wrongOperands ins

/// sc, which is how a program asks the machine it runs on for something.
let private systemCall ins =
  match ins.Operands with
  | [] -> (17u <<< 26) ||| 2u
  | _ -> wrongOperands ins

/// <summary>
/// The four names each conditional branch goes by, given what it does to the
/// counter and which bit it tests.
///
/// The two lowest bits of a branch say whether the place it names is where to
/// go outright and whether it leaves behind where it came from, and both are
/// written into the name rather than beside it.
/// </summary>
let private branchForms bitLen test (plain, link) (abs, absLink) =
  [ plain, namedBranch bitLen test 0u
    link, namedBranch bitLen test 1u
    abs, namedBranch bitLen test 2u
    absLink, namedBranch bitLen test 3u ]

/// The same, for the branches that go to what the link register or the counter
/// holds; those name no place, so only whether they link is left to say.
let private returnForms xo test (plain, link) =
  [ plain, namedRegisterBranch xo test 0u
    link, namedRegisterBranch xo test 1u ]

/// The branches whose name says which bit of a condition-register field they
/// test, paired with that bit and with what they do to the counter.
let private conditionalBranchNames =
  [ (12u, 0u), (Op.BLT, Op.BLTL), (Op.BLTA, Op.BLTLA)
    (12u, 1u), (Op.BGT, Op.BGTL), (Op.BGTA, Op.BGTLA)
    (12u, 2u), (Op.BEQ, Op.BEQL), (Op.BEQA, Op.BEQLA)
    (12u, 3u), (Op.BSO, Op.BSOL), (Op.BSOA, Op.BSOLA)
    (4u, 0u), (Op.BGE, Op.BGEL), (Op.BGEA, Op.BGELA)
    (4u, 1u), (Op.BLE, Op.BLEL), (Op.BLEA, Op.BLELA)
    (4u, 2u), (Op.BNE, Op.BNEL), (Op.BNEA, Op.BNELA)
    (4u, 3u), (Op.BNS, Op.BNSL), (Op.BNSA, Op.BNSLA) ]

/// The branches whose name says what they do to the counter, whether they also
/// test a bit of the condition register, and how.
let private counterBranchNames =
  [ (16u, 0u), (Op.BDNZ, Op.BDNZL), (Op.BDNZA, Op.BDNZLA)
    (18u, 0u), (Op.BDZ, Op.BDZL), (Op.BDZA, Op.BDZLA)
    (8u, 0u), (Op.BDNZT, Op.BDNZTL), (Op.BDNZTA, Op.BDNZTLA)
    (0u, 0u), (Op.BDNZF, Op.BDNZFL), (Op.BDNZFA, Op.BDNZFLA)
    (10u, 0u), (Op.BDZT, Op.BDZTL), (Op.BDZTA, Op.BDZTLA)
    (2u, 0u), (Op.BDZF, Op.BDZFL), (Op.BDZFA, Op.BDZFLA) ]

/// The same names, for the branches that go to what the link register holds.
let private linkBranchNames =
  [ (20u, 0u), (Op.BLR, Op.BLRL)
    (12u, 0u), (Op.BLTLR, Op.BLTLRL)
    (12u, 1u), (Op.BGTLR, Op.BGTLRL)
    (12u, 2u), (Op.BEQLR, Op.BEQLRL)
    (12u, 3u), (Op.BSOLR, Op.BSOLRL)
    (4u, 0u), (Op.BGELR, Op.BGELRL)
    (4u, 1u), (Op.BLELR, Op.BLELRL)
    (4u, 2u), (Op.BNELR, Op.BNELRL)
    (4u, 3u), (Op.BNSLR, Op.BNSLRL)
    (16u, 0u), (Op.BDNZLR, Op.BDNZLRL)
    (18u, 0u), (Op.BDZLR, Op.BDZLRL)
    (8u, 0u), (Op.BDNZTLR, Op.BDNZTLRL)
    (0u, 0u), (Op.BDNZFLR, Op.BDNZFLRL)
    (10u, 0u), (Op.BDZTLR, Op.BDZTLRL)
    (2u, 0u), (Op.BDZFLR, Op.BDZFLRL) ]

/// The same names, for the branches that go to what the counter holds.
let private counterTargetNames =
  [ (20u, 0u), (Op.BCTR, Op.BCTRL)
    (12u, 0u), (Op.BLTCTR, Op.BLTCTRL)
    (12u, 1u), (Op.BGTCTR, Op.BGTCTRL)
    (12u, 2u), (Op.BEQCTR, Op.BEQCTRL)
    (12u, 3u), (Op.BSOCTR, Op.BSOCTRL)
    (4u, 0u), (Op.BGECTR, Op.BGECTRL)
    (4u, 1u), (Op.BLECTR, Op.BLECTRL)
    (4u, 2u), (Op.BNECTR, Op.BNECTRL)
    (4u, 3u), (Op.BNSCTR, Op.BNSCTRL) ]

/// The branches, and the one instruction that leaves the program for the
/// machine under it.
let branchEncoders bitLen =
  let places (test, plain, absolute) = branchForms bitLen test plain absolute
  let returns xo (test, names) = returnForms xo test names
  [ Op.B, iBranch bitLen 0u 0u
    Op.BL, iBranch bitLen 0u 1u
    Op.BA, iBranch bitLen 1u 0u
    Op.BLA, iBranch bitLen 1u 1u
    Op.BC, bBranch bitLen 0u
    Op.BCL, bBranch bitLen 1u
    Op.BCA, bBranch bitLen 2u
    Op.BCLA, bBranch bitLen 3u
    Op.BCLR, registerBranch 16u 0u
    Op.BCLRL, registerBranch 16u 1u
    Op.BCCTR, registerBranch 528u 0u
    Op.BCCTRL, registerBranch 528u 1u
    Op.SC, systemCall ]
  @ List.collect places conditionalBranchNames
  @ List.collect places counterBranchNames
  @ List.collect (returns 16u) linkBranchNames
  @ List.collect (returns 528u) counterTargetNames

(* What a program says to the machine it runs on: the moves between a general
   register and one of the registers that is not written by name, the barriers,
   and the instructions that reach the tables the machine translates addresses
   through. *)
/// An X-form that reads or writes a register the encoding names by a number
/// the source writes.
let private xSpecial xo ins =
  match ins.Operands with
  | [ Rg r; Im spr ] ->
    word 31u (gpr r) 0u 0u ((specialRegister spr) ||| (xo <<< 1))
  | [ Im spr; Rg r ] ->
    word 31u (gpr r) 0u 0u ((specialRegister spr) ||| (xo <<< 1))
  | _ -> wrongOperands ins

/// The same, where which register it is is in the name rather than beside it.
let private xSpecialNamed xo spr ins =
  match ins.Operands with
  | [ Rg r ] ->
    word 31u (gpr r) 0u 0u ((specialRegister spr) ||| (xo <<< 1))
  | _ -> wrongOperands ins

/// An X-form that reads or writes one of the registers naming a segment, which
/// the encoding names by four bits the source writes.
let private xSegment xo ins =
  match ins.Operands with
  | [ Rg r; Im sr ] -> xForm 31u (gpr r) (unsigned 4 sr) 0u xo 0u
  | [ Im sr; Rg r ] -> xForm 31u (gpr r) (unsigned 4 sr) 0u xo 0u
  | _ -> wrongOperands ins

/// An X-form that reads or writes the segment register another register names.
let private xSegmentIndirect xo ins =
  match ins.Operands with
  | [ Rg r; Rg b ] -> xForm 31u (gpr r) 0u (gpr b) xo 0u
  | _ -> wrongOperands ins

/// <summary>
/// mfocrf, which reads the one field of the condition register its mask names.
///
/// Every other field of what it writes is left undefined, so which field the
/// mask names is not something the disassembler has to print; the mask written
/// here therefore names the first field, and any other would say the same
/// thing.
/// </summary>
let private xReadOneCondField ins =
  match ins.Operands with
  | [ Rg d ] -> word 31u (gpr d) 0x18u 0u (19u <<< 1)
  | _ -> wrongOperands ins

/// mtcrf and mtocrf, which write the fields of the condition register their
/// mask names. The mask straddles the two fields an X-form keeps registers in.
let private xWriteCondFields one ins =
  match ins.Operands with
  | [ Im crm; Rg s ] ->
    let mask = unsigned 8 crm
    let high = (one <<< 4) ||| (mask >>> 4)
    word 31u (gpr s) high ((mask &&& 0xFu) <<< 1) (144u <<< 1)
  | _ -> wrongOperands ins

/// mcrxr, which moves the summary of what the arithmetic overflowed into one
/// field of the condition register.
let private xReadSummary ins =
  match ins.Operands with
  | [ Rg f ] -> xForm 31u ((crf f) <<< 2) 0u 0u 512u 0u
  | _ -> wrongOperands ins

/// mcrf, which moves one field of the condition register to another.
let private xMoveCondField ins =
  match ins.Operands with
  | [ Rg d; Rg s ] -> word 19u ((crf d) <<< 2) ((crf s) <<< 2) 0u 0u
  | _ -> wrongOperands ins

/// isel, which picks one of two registers by a bit of the condition register.
let private xSelect ins =
  match ins.Operands with
  | [ Rg d; Rg a; Rg b; Bit bi ] ->
    word 31u (gpr d) (gpr a) (gpr b) ((bi <<< 6) ||| (15u <<< 1))
  | _ -> wrongOperands ins

/// One of the instructions that combines two bits of the condition register
/// into a third.
let private xCondLogical xo ins =
  match ins.Operands with
  | [ Bit d; Bit a; Bit b ] -> word 19u d a b (xo <<< 1)
  | _ -> wrongOperands ins

/// The same, under a name that says the two bits it reads are one.
let private xCondUnary xo ins =
  match ins.Operands with
  | [ Bit d; Bit a ] -> word 19u d a a (xo <<< 1)
  | _ -> wrongOperands ins

/// The same, under a name that says all three of its bits are one, which is
/// what setting or clearing a bit outright asks for.
let private xCondConstant xo ins =
  match ins.Operands with
  | [ Bit d ] -> word 19u d d d (xo <<< 1)
  | _ -> wrongOperands ins

/// A barrier or a table instruction, which says nothing beside its name.
let private xBare po xo ins =
  match ins.Operands with
  | [] -> xForm po 0u 0u 0u xo 0u
  | _ -> wrongOperands ins

/// lwsync, which is the barrier the field above it tells from the whole one.
let private xLightBarrier ins =
  match ins.Operands with
  | [] -> xForm 31u 1u 0u 0u 598u 0u
  | _ -> wrongOperands ins

/// The instructions that move what no name reaches, the barriers, and the
/// instructions on the condition register.
let systemEncoders () =
  [ Op.MFCR, xD 19u
    Op.MFOCRF, xReadOneCondField
    Op.MTCRF, xWriteCondFields 0u
    Op.MTOCRF, xWriteCondFields 1u
    Op.MFMSR, xD 83u
    Op.MFSPR, xSpecial 339u
    Op.MTSPR, xSpecial 467u
    Op.MFTB, xSpecial 371u
    Op.MFXER, xSpecialNamed 339u 1UL
    Op.MFLR, xSpecialNamed 339u 8UL
    Op.MFCTR, xSpecialNamed 339u 9UL
    Op.MFTBU, xSpecialNamed 371u 269UL
    Op.MTXER, xSpecialNamed 467u 1UL
    Op.MTLR, xSpecialNamed 467u 8UL
    Op.MTCTR, xSpecialNamed 467u 9UL
    Op.MFSR, xSegment 595u
    Op.MTSR, xSegment 210u
    Op.MFSRIN, xSegmentIndirect 659u
    Op.MTSRIN, xSegmentIndirect 754u
    Op.MCRXR, xReadSummary
    Op.MCRF, xMoveCondField
    Op.ISEL, xSelect
    Op.CRNOR, xCondLogical 33u
    Op.CRANDC, xCondLogical 129u
    Op.CRXOR, xCondLogical 193u
    Op.CRNAND, xCondLogical 225u
    Op.CRAND, xCondLogical 257u
    Op.CREQV, xCondLogical 289u
    Op.CRORC, xCondLogical 417u
    Op.CROR, xCondLogical 449u
    Op.CRNOT, xCondUnary 33u
    Op.CRMOVE, xCondUnary 449u
    Op.CRCLR, xCondConstant 193u
    Op.CRSET, xCondConstant 289u
    Op.DCBST, xAb 54u
    Op.DCBF, xAb 86u
    Op.DCBTST, xAb 246u
    Op.DCBT, xAb 278u
    Op.DCBI, xAb 470u
    Op.DCBA, xAb 758u
    Op.ICBI, xAb 982u
    Op.DCBZ, xAb 1014u
    Op.TLBIE, xB 306u
    Op.TLBIA, xNone 370u
    Op.TLBSYNC, xNone 566u
    Op.SYNC, xNone 598u
    Op.LWSYNC, xLightBarrier
    Op.EIEIO, xNone 854u
    Op.ISYNC, xBare 19u 150u
    Op.RFI, xBare 19u 50u ]
