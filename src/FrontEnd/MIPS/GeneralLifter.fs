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

module internal B2R2.FrontEnd.MIPS.GeneralLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.MIPS
open B2R2.FrontEnd.MIPS.LiftingUtils

let abs ins bld =
  lift bld ins {
    let fd, fs = getTwoOprs ins
    let is32Bit = is32Bit bld
    match ins.Fmt with
    | Some Fmt.D when is32Bit ->
      let fdB, fdA = transOprToFPPair bld fd
      let fsB, fsA = transOprToFPPair bld fs
      let mask = numU64 0x7FFFFFFFFFFFFFFFUL 64<rt>
      let res = (AST.concat fsB fsA) .& mask
      writeFPResult fdB fdA res bld
    | Some Fmt.PS when is32Bit ->
      let fdB, fdA = transOprToFPPair bld fd
      let fsB, fsA = transOprToFPPair bld fs
      let mask = numU64 0x7FFFFFFFUL 32<rt>
      let resA = fsA .& mask
      let resB = fsB .& mask
      writeFPResult fdB fdA (AST.concat resB resA) bld
    | Some Fmt.PS ->
      let fd, fs = transOpr ins bld fd, transOpr ins bld fs
      let mask = numU64 0x7FFFFFFFUL 32<rt>
      let resA = (AST.xtlo 32<rt> fs) .& mask
      let resB = (AST.xthi 32<rt> fs) .& mask
      fd := AST.concat resB resA
    | Some Fmt.S ->
      let fd, fs = transTwoSingleFP bld (fd, fs)
      fd := fs .& numU64 0x7FFFFFFFUL 32<rt>
    | _ ->
      let fd, fs = transOpr ins bld fd, transOpr ins bld fs
      let mask =
        if is32Bit then numU64 0x7FFFFFFFUL 32<rt>
        else numU64 0x7FFFFFFFFFFFFFFFUL 64<rt>
      fd := fs .& mask
  }

let private reDupSrc opr1 opr2 expr1 expr2 tmp1 tmp2 bld =
  append bld {
    if opr1 = opr2 then
      tmp1 := expr1
      tmp2 := tmp1
    else
      tmp1 := expr1
      tmp2 := expr2
  }

let private reDupSrc3 opr1 opr2 opr3 expr1 expr2 expr3 tmp1 tmp2 tmp3 bld =
  append bld {
    if opr1 = opr2 && opr2 = opr3 then
      tmp1 := expr1
      tmp2 := tmp1
      tmp3 := tmp1
    elif opr1 = opr2 then
      tmp1 := expr1
      tmp2 := tmp1
      tmp3 := expr3
    elif opr1 = opr3 then
      tmp1 := expr1
      tmp3 := tmp1
      tmp2 := expr2
    elif opr2 = opr3 then
      tmp2 := expr2
      tmp3 := tmp2
      tmp1 := expr1
    else
      tmp1 := expr1
      tmp2 := expr2
      tmp3 := expr3
  }

/// <summary>
/// The paired-single form of an arithmetic instruction on two registers.
///
/// A pair is two single-precision numbers side by side, so this is two
/// single-precision operations and not one on the whole width: each half
/// rounds on its own and is normalised on its own. Computing it at
/// sixty-four bits produces a number out of bits that were never one number,
/// which is what grouping the format with D did.
/// </summary>
let private pairedArith op arith (dst, src1, src2) bld =
  append bld {
    let fdB, fdA = transOprToFPPair bld dst
    let fs = transOprToFPPairConcat bld src1
    let ft = transOprToFPPairConcat bld src2
    let struct (hi, lo) = tmpVars2 bld 32<rt>
    let struct (sHi, sLo, tHi, tLo) = tmpVars4 bld 32<rt>
    sHi := AST.xthi 32<rt> fs
    sLo := AST.xtlo 32<rt> fs
    tHi := AST.xthi 32<rt> ft
    tLo := AST.xtlo 32<rt> ft
    hi := op sHi tHi
    lo := op sLo tLo
    normalizeNaN 32<rt> hi bld
    normalizeNaN 32<rt> lo bld
    (* One record for the pair, not one each: the two halves are two
       operations and the register that holds what was raised is one. Cause
       is rewritten whole by every instruction, so recording each half in
       turn would leave only the second half's answer there. *)
    let raisedHi = fpRaised bld 32<rt> arith sHi tHi hi
    let raisedLo = fpRaised bld 32<rt> arith sLo tLo lo
    fpRecord bld (raisedHi .| raisedLo)
    writeFPResult fdB fdA (AST.concat hi lo) bld
  }

let add (ins: Instruction) bld =
  lift bld ins {
    let dst, src1, src2 = getThreeOprs ins
    match ins.Fmt with
    | None ->
      let lblL0 = label bld "L0"
      let lblL1 = label bld "L1"
      let lblEnd = label bld "End"
      let rd = transOpr ins bld dst
      let rs = transOpr ins bld src1
      let rt = transOpr ins bld src2
      let result = if is32Bit bld then rs .+ rt else signExtLo64 (rs .+ rt)
      let cond = checkOverflowOnAdd rs rt result
      AST.cjmp cond (AST.jmpDest lblL0) (AST.jmpDest lblL1)
      AST.lmark lblL0
      AST.sideEffect (Exception IntegerOverflow)
      AST.jmp (AST.jmpDest lblEnd)
      AST.lmark lblL1
      rd := result
      AST.lmark lblEnd
    | Some Fmt.S ->
      let fd, fs, ft = transThreeSingleFP bld (dst, src1, src2)
      let struct (tSrc1, tSrc2, result) = tmpVars3 bld 32<rt>
      reDupSrc src1 src2 fs ft tSrc1 tSrc2 bld
      result := AST.fadd tSrc1 tSrc2
      normalizeNaN 32<rt> result bld
      fpExceptions bld 32<rt> FPAdd tSrc1 tSrc2 result
      fd := result
    | Some Fmt.PS ->
      pairedArith AST.fadd FPAdd (dst, src1, src2) bld
    | _ ->
      let fdB, fdA = transOprToFPPair bld dst
      let fs, ft = transFPConcatTwoOprs bld (src1, src2)
      let struct (tSrc1, tSrc2, result) = tmpVars3 bld 64<rt>
      reDupSrc src1 src2 fs ft tSrc1 tSrc2 bld
      result := AST.fadd tSrc1 tSrc2
      normalizeNaN 64<rt> result bld
      fpExceptions bld 64<rt> FPAdd tSrc1 tSrc2 result
      writeFPResult fdB fdA result bld
  }

/// ADDI is ADDIU plus a trap: a signed overflow raises Integer Overflow
/// and leaves the destination alone. Its non-trapping counterpart was
/// modelled and it was not, which is the whole of the difference.
let addi ins bld =
  lift bld ins {
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    let rt, rs, imm = transThreeOprs ins bld
    let result = if is32Bit bld then rs .+ imm else signExtLo64 (rs .+ imm)
    let cond = checkOverflowOnAdd rs imm result
    AST.cjmp cond (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    AST.sideEffect (Exception IntegerOverflow)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rt := result
    AST.lmark lblEnd
  }

let addiu ins bld =
  lift bld ins {
    let rt, rs, imm = transThreeOprs ins bld
    let result = if is32Bit bld then rs .+ imm else signExtLo64 (rs .+ imm)
    rt := result
  }

let addu ins bld =
  lift bld ins {
    let rd, rs, rt = transThreeOprs ins bld
    let result = if is32Bit bld then rs .+ rt else signExtLo64 (rs .+ rt)
    rd := result
  }

let logAnd ins bld =
  lift bld ins {
    let rd, rs, rt = transThreeOprs ins bld
    rd := rs .& rt
  }

let andi ins bld =
  lift bld ins {
    let rt, rs, imm = transThreeOprs ins bld
    rt := rs .& imm
  }

let aui ins bld =
  lift bld ins {
    let rt, rs, imm = transThreeOprs ins bld
    let imm = imm << numI32 16 bld.RegType
    let result = if is32Bit bld then rs .+ imm else signExtLo64 (rs .+ imm)
    rt := result
  }

/// <summary>
/// B, which has a delay slot in one encoding and not in the other.
///
/// MD00076 3.13: a MIPS16e branch does not have one, and "if a branch or jump
/// is taken, the instruction immediately following the branch or jump is
/// never executed". The base architecture's B is BEQ against the zero
/// register and does have one. Same name, same effect on the program counter,
/// and a different instruction after it -- so the encoding decides.
/// </summary>
let b (ins: Instruction) (bld: LowUIRBuilder) =
  if ins.ISAMode = MIPSISAMode.MIPS16 then
    lift bld ins {
      let offset = transOneOpr ins bld
      AST.interjmp offset InterJmpKind.Base
    }
  else
    liftTransfer bld ins {
      let nPC = regVar bld R.NPC
      let offset = transOneOpr ins bld
      bld.DelayedBranch <- InterJmpKind.Base
      nPC := offset
    }

let bal ins (bld: LowUIRBuilder) =
  liftTransfer bld ins {
    let offset = transOneOpr ins bld
    let pc = regVar bld R.PC
    let nPC = regVar bld R.NPC
    bld.DelayedBranch <- InterJmpKind.IsCall
    regVar bld R.R31 := pc .+ numI32 8 bld.RegType
    nPC := offset
  }

/// <summary>
/// NAL links and does not branch, which is BLTZAL's condition read on the
/// register that is always zero.
///
/// A program uses it to find out where it is: the architecture gives it no
/// other way to read the PC, and the return address a link leaves behind is
/// the address after the delay slot. The slot still runs, and what follows it
/// is what would have followed anyway -- so the only thing this writes is
/// r31.
/// </summary>
let nal ins (bld: LowUIRBuilder) =
  liftTransfer bld ins {
    let pc = regVar bld R.PC
    let nPC = regVar bld R.NPC
    bld.DelayedBranch <- InterJmpKind.Base
    regVar bld R.R31 := pc .+ numI32 8 bld.RegType
    nPC := pc .+ numI32 8 bld.RegType
  }

let private fpConditionCode cc bld =
  let fcsr = regVar bld R.FCSR
  if cc = 0 then
    (fcsr .& numU32 0x800000u 32<rt>) == numU32 0x800000u 32<rt>
  else
    let num = numU32 0x1000000u 32<rt> << numI32 cc 32<rt>
    (fcsr .& num) == num

let bc1f (ins: Instruction) bld =
  liftTransfer bld ins {
    match ins.Operands with
    | OneOperand off ->
      let offset = transOpr ins bld off
      let cond = AST.not (fpConditionCode 0 bld)
      updatePCCond ins bld offset cond InterJmpKind.Base
    | _ ->
      let cc, offset = getTwoOprs ins
      let offset = transOpr ins bld offset
      let cc = transOprToImmToInt cc
      let cond = AST.not (fpConditionCode cc bld)
      updatePCCond ins bld offset cond InterJmpKind.Base
  }

let bc1t (ins: Instruction) bld =
  liftTransfer bld ins {
    match ins.Operands with
    | OneOperand off ->
      let offset = transOpr ins bld off
      let cond = fpConditionCode 0 bld
      updatePCCond ins bld offset cond InterJmpKind.Base
    | _ ->
      let cc, offset = getTwoOprs ins
      let offset = transOpr ins bld offset
      let cc = transOprToImmToInt cc
      let cond = fpConditionCode cc bld
      updatePCCond ins bld offset cond InterJmpKind.Base
  }

let beq ins bld =
  liftTransfer bld ins {
    let rs, rt, offset = transThreeOprs ins bld
    let cond = rs == rt
    updatePCCond ins bld offset cond InterJmpKind.Base
  }

/// BEQL and BNEL. See updatePCCondLikely for why the delay slot is skipped
/// rather than predicated: the slot is a separate instruction and the lifter
/// cannot reach into it, so the not-taken path steps over it instead.
let beql ins bld =
  liftTransfer bld ins {
    let rs, rt, offset = transThreeOprs ins bld
    let cond = rs == rt
    updatePCCondLikely bld offset cond InterJmpKind.Base
  }

/// BC1FL and BC1TL: the floating-point branches with the nullify bit set.
/// The condition is a bit of FCSR rather than a register, which is the
/// only way they differ from the branch-likelies above.
let bc1condl (ins: Instruction) bld tf =
  liftTransfer bld ins {
    (* The condition code is optional in the assembly -- an omitted one
       means cc 0 -- so the operand shape is read the same way bc1f and
       bc1t read it. *)
    let cc, offset =
      match ins.Operands with
      | OneOperand off ->
        0, transOpr ins bld off
      | _ ->
        let cc, off = getTwoOprs ins
        transOprToImmToInt cc, transOpr ins bld off
    let bit = fpConditionCode cc bld
    let cond = if tf then bit else AST.not bit
    updatePCCondLikely bld offset cond InterJmpKind.Base
  }

/// The compare-with-zero branch-likelies. They nullify the delay slot on
/// the not-taken path exactly as BEQL and BNEL do, so they share the
/// helper; only the condition differs.
let bcondzl ins bld cmp =
  liftTransfer bld ins {
    let rs, offset = transTwoOprs ins bld
    let cond = cmp rs (AST.num0 bld.RegType)
    updatePCCondLikely bld offset cond InterJmpKind.Base
  }

/// The and-link branch-likelies. The link is written unconditionally, as
/// it is for BLTZAL and BGEZAL.
let bcondzall ins bld cmp =
  liftTransfer bld ins {
    let rs, offset = transTwoOprs ins bld
    let cond = cmp rs (AST.num0 bld.RegType)
    regVar bld R.R31 := regVar bld R.PC .+ numI32 8 bld.RegType
    updatePCCondLikely bld offset cond InterJmpKind.IsCall
  }

let bnel ins bld =
  liftTransfer bld ins {
    let rs, rt, offset = transThreeOprs ins bld
    let cond = rs != rt
    updatePCCondLikely bld offset cond InterJmpKind.Base
  }

let blez ins bld =
  liftTransfer bld ins {
    let rs, offset = transTwoOprs ins bld
    let cond = AST.sle rs (AST.num0 bld.RegType)
    updatePCCond ins bld offset cond InterJmpKind.Base
  }

let bltz ins bld =
  liftTransfer bld ins {
    let rs, offset = transTwoOprs ins bld
    let cond = AST.slt rs (AST.num0 bld.RegType)
    updatePCCond ins bld offset cond InterJmpKind.Base
  }

let bltzal ins bld =
  liftTransfer bld ins {
    let rs, offset = transTwoOprs ins bld
    let pc = regVar bld R.PC
    let nAddr = tmpVar bld bld.RegType
    let cond = AST.slt rs (AST.num0 bld.RegType)
    nAddr := pc .+ numI32 8 bld.RegType
    regVar bld R.R31 := nAddr
    updatePCCond ins bld offset cond InterJmpKind.IsCall
  }

let bgez ins bld =
  liftTransfer bld ins {
    let rs, offset = transTwoOprs ins bld
    let cond = AST.sge rs (AST.num0 bld.RegType)
    updatePCCond ins bld offset cond InterJmpKind.Base
  }

let bgezal ins bld =
  liftTransfer bld ins {
    let rs, offset = transTwoOprs ins bld
    let pc = regVar bld R.PC
    let nAddr = tmpVar bld bld.RegType
    let cond = AST.sge rs (AST.num0 bld.RegType)
    nAddr := pc .+ numI32 8 bld.RegType
    regVar bld R.R31 := nAddr
    updatePCCond ins bld offset cond InterJmpKind.IsCall
  }

let bgtz ins bld =
  liftTransfer bld ins {
    let rs, offset = transTwoOprs ins bld
    let cond = AST.sgt rs (AST.num0 bld.RegType)
    updatePCCond ins bld offset cond InterJmpKind.Base
  }

let bne ins bld =
  liftTransfer bld ins {
    let rs, rt, offset = transThreeOprs ins bld
    let cond = rs != rt
    updatePCCond ins bld offset cond InterJmpKind.Base
  }

let setFPConditionCode bld cc tf =
  append bld {
    let insertBit = AST.xtlo 32<rt> tf
    let fcsr = regVar bld R.FCSR
    if cc = 0 then
      let shf1 = numI32 23 32<rt>
      let mask1 = numU32 0xFF000000u 32<rt>
      let mask2 = numU32 0x7FFFFFu 32<rt>
      let insertBit = AST.xtlo 32<rt> tf
      fcsr := (fcsr .& mask1) .| (insertBit << shf1) .| (fcsr .& mask2)
    else
      let shf2 = numI32 (24 + cc) 32<rt>
      let mask1 = numU32 0xFE000000u 32<rt> << numI32 cc 32<rt>
      let mask2 =
        (numU32 0xFFFFFFu 32<rt> << numI32 cc 32<rt>) .| numU32 0xFFu 32<rt>
      fcsr := (fcsr .& mask1) .| (insertBit << shf2) .| (fcsr .& mask2)
  }

let private getCCondOpr (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(fs, ft) ->
    let sameReg = fs = ft
    match ins.Fmt with
    | Some Fmt.PS | Some Fmt.D ->
      let fs, ft = transFPConcatTwoOprs bld (fs, ft)
      64<rt>, 0, fs, ft, sameReg
    | _ ->
      let fs, ft = transTwoSingleFP bld (fs, ft)
      32<rt>, 0, fs, ft, sameReg
  | ThreeOperands(cc, fs, ft) ->
    let sameReg = fs = ft
    match ins.Fmt with
    | Some Fmt.PS | Some Fmt.D ->
      let cc = transOprToImmToInt cc
      let fs, ft = transFPConcatTwoOprs bld (fs, ft)
      64<rt>, cc, fs, ft, sameReg
    | _ ->
      let cc = transOprToImmToInt cc
      let fs, ft = transTwoSingleFP bld (fs, ft)
      32<rt>, cc, fs, ft, sameReg
  | _ ->
    raise InvalidOperandException

/// Which of the three comparison outcomes the condition asks about: unordered,
/// equal and less, one bit each. A signalling form asks the same question as
/// the quiet form beside it, and differs only in the trap it would raise.
let private conditionBitsOf condition num0 num1 =
  match condition with
  | Some Condition.F | Some Condition.SF -> num0, num0, num0
  | Some Condition.UN | Some Condition.NGLE -> num1, num0, num0
  | Some Condition.EQ | Some Condition.SEQ -> num0, num1, num0
  | Some Condition.UEQ | Some Condition.NGL -> num1, num1, num0
  | Some Condition.OLT | Some Condition.LT -> num0, num0, num1
  | Some Condition.ULT | Some Condition.NGE -> num1, num0, num1
  | Some Condition.OLE | Some Condition.LE -> num0, num1, num1
  | Some Condition.ULE | Some Condition.NGT -> num1, num1, num1
  | _ -> raise InvalidOperandException

/// A NaN is a full exponent with a non-zero mantissa, and either operand
/// being one makes the comparison unordered. When both operands are the same
/// register it is only worth testing once, and the two temporaries hold that
/// one test's halves.
let private condNaNOf bld oprSz (mantissa, exponent) sameReg tFs tFt =
  if sameReg then
    append bld {
      mantissa := getMantissa tFt oprSz
      exponent := getExponentFull tFt oprSz
    }
    AST.xtlo 1<rt> (exponent .& (mantissa != AST.num0 oprSz))
  else
    let src1Mantissa = getMantissa tFs oprSz
    let src2Mantissa = getMantissa tFt oprSz
    let src1Exponent = getExponentFull tFs oprSz
    let src2Exponent = getExponentFull tFt oprSz
    AST.xtlo 1<rt> (src1Exponent .& (src1Mantissa != AST.num0 oprSz)) .|
    AST.xtlo 1<rt> (src2Exponent .& (src2Mantissa != AST.num0 oprSz))

/// Whether the predicate is one of the signalling half. The manual's
/// condition field is four bits and the top one is what separates the two
/// spellings of each comparison: the signalling one raises Invalid for a
/// quiet NaN as well, which is how a program asks to be told about an
/// unordered comparison it did not expect.
let private conditionSignals (condition: Condition option) =
  match condition with
  | Some c -> int c >= 8
  | None -> false

/// Writes the answer of one comparison into one condition code, and hands
/// back whether the comparison raised Invalid.
let private compareIntoCC (ins: Instruction) bld oprSz cc (fs, ft) sameReg =
  let invalid = tmpVar bld 1<rt>
  append bld {
    let num0 = AST.num0 oprSz
    let num1 = AST.num1 oprSz
    let struct (tFs, tFt, mantissa) = tmpVars3 bld oprSz
    let struct (less, equal, unordered, condition) = tmpVars4 bld oprSz
    let struct (condNaN, exponent) = tmpVars2 bld 1<rt>
    let bit0, bit1, bit2 = conditionBitsOf ins.Condition num0 num1
    if sameReg then
      tFs := fs
      tFt := tFs
    else
      tFs := fs
      tFt := ft
    (* Equality is a floating-point question, not a comparison of the two bit
       patterns with the sign masked off: that answers "equal" for every value
       against its own negation -- which is what a range check like
       `d >= LONG_MAX` tests against `-LONG_MAX` -- while getting +0 and -0
       right by accident. AST.feq gets both. *)
    let isEqual = if sameReg then AST.b1 else AST.feq tFs tFt
    condNaN := condNaNOf bld oprSz (mantissa, exponent) sameReg tFs tFt
    less := AST.ite condNaN num0 (AST.ite (AST.flt tFs tFt) num1 num0)
    equal :=
      AST.ite condNaN num0 (AST.ite isEqual num1 num0)
    unordered := AST.ite condNaN num1 num0
    condition := (bit2 .& less) .| (bit1 .& equal) .| (bit0 .& unordered)
    setFPConditionCode bld cc condition
    invalid :=
      fpCompareInvalid bld oprSz (conditionSignals ins.Condition) tFs tFt
  }
  invalid

/// <summary>
/// A comparison, whose answer goes to a condition code rather than to a
/// register.
///
/// A pair answers TWO of them: the upper half's comparison goes to cc + 1 and
/// the lower half's to cc. Comparing the two pairs as one sixty-four bit
/// number answers one code, out of bits that were never one number.
/// </summary>
let cCond ins bld =
  lift bld ins {
    let oprSz, cc, fs, ft, sameReg = getCCondOpr ins bld
    match ins.Fmt with
    | Some Fmt.PS ->
      let lower = AST.xtlo 32<rt> fs, AST.xtlo 32<rt> ft
      let upper = AST.xthi 32<rt> fs, AST.xthi 32<rt> ft
      let invLo = compareIntoCC ins bld 32<rt> cc lower sameReg
      let invHi = compareIntoCC ins bld 32<rt> (cc + 1) upper sameReg
      (* Two comparisons and one register to record them in, so the record is
         their union: see the note in pairedArith. *)
      fpExceptionsInvalidOnly bld (invLo .| invHi)
    | _ ->
      let invalid = compareIntoCC ins bld oprSz cc (fs, ft) sameReg
      fpExceptionsInvalidOnly bld invalid
  }

/// FCCR, FEXR and FENR are windows onto FCSR rather than registers of their
/// own: each exposes a subset of the same state, and CTC1 and CFC1 name which
/// window they mean. Ignoring the name and reading or writing the whole of
/// FCSR is wrong twice over -- a write through a window changes fields the
/// window does not contain, and a read through one returns fields it does not
/// expose.
///
/// The layouts, from MD00087 Vol. III. Only FCCR repacks: the condition codes
/// are contiguous there and split in FCSR, where FCC0 sits at 23 and FCC7..1
/// at 31..25. FEXR keeps Cause and Flags where FCSR has them. FENR keeps the
/// Enables and RM where FCSR has them and moves FS from 24 down to 2.
let private fccrOfFcsr fcsr =
  ((fcsr >> numI32 25 32<rt>) .& numU32 0x7Fu 32<rt> << AST.num1 32<rt>)
  .| ((fcsr >> numI32 23 32<rt>) .& AST.num1 32<rt>)

let private fcsrWithFccr fcsr v =
  let cleared = fcsr .& numU32 0x017FFFFFu 32<rt>
  cleared
  .| ((v .& numU32 0xFEu 32<rt>) >> AST.num1 32<rt> << numI32 25 32<rt>)
  .| ((v .& AST.num1 32<rt>) << numI32 23 32<rt>)

let private fexrMask = 0x0003F07Cu          // Cause 17..12, Flags 6..2
let private fenrFcsrMask = 0x01000F83u      // Enables 11..7, FS 24, RM 1..0

let private fenrOfFcsr fcsr =
  (fcsr .& numU32 0xF83u 32<rt>)
  .| (((fcsr >> numI32 24 32<rt>) .& AST.num1 32<rt>) << numI32 2 32<rt>)

let private fcsrWithFenr fcsr v =
  (fcsr .& AST.not (numU32 fenrFcsrMask 32<rt>))
  .| (v .& numU32 0xF83u 32<rt>)
  .| (((v >> numI32 2 32<rt>) .& AST.num1 32<rt>) << numI32 24 32<rt>)

let ctc1 ins bld =
  lift bld ins {
    let rt, fsOpr = getTwoOprs ins
    let rt = transOpr ins bld rt
    let fcsr = regVar bld R.FCSR
    let v = AST.xtlo 32<rt> rt
    match fsOpr with
    | OpReg R.F25 ->
      fcsr := fcsrWithFccr fcsr v
    | OpReg R.F26 ->
      fcsr := (fcsr .& AST.not (numU32 fexrMask 32<rt>))
              .| (v .& numU32 fexrMask 32<rt>)
    | OpReg R.F28 ->
      fcsr := fcsrWithFenr fcsr v
    | OpReg R.F0 ->
      ()                                    // FIR is read-only
    | _ ->
      (* fs = 31, the whole register. MD00087 CTC1: writing bits 22..18 when
         the implementation-defined field is absent is UNPREDICTABLE, not
         masked -- so there is nothing here to clamp. A difference against
         another implementation on those bits says nothing about either. *)
      fcsr := v
  }

let cfc1 ins bld =
  lift bld ins {
    let rt, fsOpr = getTwoOprs ins
    let rt = transOpr ins bld rt
    let fcsr = regVar bld R.FCSR
    let v =
      match fsOpr with
      | OpReg R.F25 -> fccrOfFcsr fcsr
      | OpReg R.F26 -> fcsr .& numU32 fexrMask 32<rt>
      | OpReg R.F28 -> fenrOfFcsr fcsr
      | OpReg R.F0 -> AST.num0 32<rt>       // FIR: no implementation named
      | _ -> fcsr
    rt := AST.sext bld.RegType v
  }

let private countLeading ones ins bld =
  lift bld ins {
    let lblLoop = label bld "Loop"
    let lblContinue = label bld "Continue"
    let lblEnd = label bld "End"
    let wordSz = bld.RegType
    let rd, rs = transTwoOprs ins bld
    (* CLZ counts leading zeros of the 32-bit word, so on a 64-bit machine it
       must look at the low 32 bits only -- zero-extend them so upper bits (e.g.
       a sign-extended negative word) do not skew the scan. *)
    let rs = if is32Bit bld then rs else AST.zext wordSz (AST.xtlo 32<rt> rs)
    (* Leading ones are the complement's leading zeros. The complement is
       taken of the 32-bit word alone, for the same reason the scan is. *)
    let rs =
      if not ones then rs
      elif is32Bit bld then AST.not rs
      else AST.zext wordSz (AST.not (AST.xtlo 32<rt> rs))
    let t = tmpVar bld wordSz
    let n31 = numI32 31 wordSz
    t := n31
    AST.lmark lblLoop
    let cond1 = rs >> t == AST.num1 wordSz
    AST.cjmp cond1 (AST.jmpDest lblEnd) (AST.jmpDest lblContinue)
    AST.lmark lblContinue
    t := t .- AST.num1 wordSz
    let cond2 = t == numI32 -1 wordSz
    AST.cjmp cond2 (AST.jmpDest lblEnd) (AST.jmpDest lblLoop)
    AST.lmark lblEnd
    rd := n31 .- t
  }

/// CLZ: how many zeros the word begins with.
let clz ins bld = countLeading false ins bld

/// CLO: how many ones it begins with, which is CLZ of the complement.
let clo ins bld = countLeading true ins bld

/// <summary>
/// The CRC family, which folds one message element into a running
/// thirty-two bit value.
///
/// The polynomial is written reversed and the value is shifted DOWN, because
/// the least significant bit of a message element is the most significant
/// coefficient of the polynomial that element stands for. One step per bit:
/// the bit that falls off the value is exclusive-ored with the next bit of
/// the message, and where that comes out set the polynomial is
/// exclusive-ored back in.
///
/// The running value is thirty-two bits wide whatever the element is, and it
/// arrives in the register it leaves in -- which is why the manual writes
/// these with three operands of which the first and the last are the same
/// one.
/// </summary>
let crc32 ins bld poly width =
  lift bld ins {
    let rt, rs, _ = getThreeOprs ins
    let dst = transOpr ins bld rt
    let msg = transOpr ins bld rs
    let sz = bld.RegType
    let crc = tmpVar bld 32<rt>
    crc := AST.xtlo 32<rt> dst
    for i in 0 .. width - 1 do
      let feedback = AST.xtlo 1<rt> crc <+> AST.xtlo 1<rt> (msg >> numI32 i sz)
      crc := (crc >> AST.num1 32<rt>)
             <+> AST.ite feedback (numU32 poly 32<rt>) (AST.num0 32<rt>)
    dst := if is32Bit bld then crc else AST.sext 64<rt> crc
  }

let cvtd ins bld =
  lift bld ins {
    let fd, fs = getTwoOprs ins
    let fdB, fdA = transOprToFPPair bld fd
    let result = tmpVar bld 64<rt>
    let struct (src, srcSz, fromInt) =
      match ins.Fmt with
      | Some Fmt.W -> struct (transOprToFPConvert ins bld fs, 32<rt>, true)
      | Some Fmt.S -> struct (transOprToFPConvert ins bld fs, 32<rt>, false)
      | _ -> struct (transOprToFPPairConcat bld fs, 64<rt>, true)
    result :=
      if fromInt then AST.cast CastKind.SIntToFloat 64<rt> src
      else AST.cast CastKind.FloatCast 64<rt> src
    normalizeNaN 64<rt> result bld
    if fromInt then
      let back = AST.floatToSInt RoundingMode.TowardZero srcSz result
      fpExceptionsFromInt bld src back
    else
      let back = AST.cast CastKind.FloatCast srcSz result
      fpExceptionsConvert bld srcSz 64<rt> back src result
    writeFPResult fdB fdA result bld
  }

/// The word a floating-point value converts to. MD00087 names one default
/// result for an operand that cannot be represented -- the largest positive
/// value, on a core with FCSR_NAN2008=0, whatever the operand's sign -- and
/// the range has to be decided BEFORE the result is narrowed. A value already
/// narrowed to the destination width is never outside that width's range, so
/// a comparison made after the narrowing is constant false and the default is
/// never chosen.
let private wordOfFP bld convert src inf nan =
  let wide = tmpVar bld 64<rt>
  append bld {
    wide := convert bld 64<rt> src
  }
  let outOfRange =
    AST.sgt wide (numI64 0x7fffffffL 64<rt>)
    .| AST.slt wide (numI64 -0x80000000L 64<rt>)
  let narrowed = AST.xtlo 32<rt> wide
  let noInteger = outOfRange .| inf .| nan
  struct (AST.ite noInteger (numI32 0x7fffffff 32<rt>) narrowed, noInteger)

/// The doubleword one converts to. There is no wider integer to convert into,
/// so the range is decided on the operand itself: a magnitude of 2^63 or more
/// cannot be represented, and -2^63 exactly can, which is why the lower bound
/// is the strict comparison and the upper one is not.
let private longOfFP bld convert srcSz src inf nan =
  let eval = tmpVar bld 64<rt>
  let upper, lower =
    if srcSz = 32<rt> then
      numU32 0x5f000000u 32<rt>, numU32 0xdf000000u 32<rt>
    else
      numU64 0x43e0000000000000UL 64<rt>, numU64 0xc3e0000000000000UL 64<rt>
  append bld {
    eval := convert bld 64<rt> src
  }
  let outOfRange = AST.fge src upper .| AST.flt src lower
  let noInteger = outOfRange .| inf .| nan
  struct (AST.ite noInteger (numI64 0x7fffffffffffffffL 64<rt>) eval,
          noInteger)

/// Rounds the way the instruction's own name says, which is what every
/// conversion but CVT does.
let private roundingOf mode =
  fun _ oprSz src -> AST.floatToSInt mode oprSz src

/// Rounds the way FCSR says, which is what CVT does -- and which a conversion
/// no RoundCtrl encloses does on its own.
let private roundingOfFCSR = fun _ oprSz src -> roundToInt src oprSz

let cvtw ins bld =
  lift bld ins {
    let fd, fs = getTwoOprs ins
    let exponent = tmpVar bld 1<rt>
    let struct (dst, src, inf, nan) =
      match ins.Fmt with
      | Some Fmt.S ->
        let dst, src = transTwoOprFPConvert ins bld (fd, fs)
        append bld {
          exponent := getExponentFull src 32<rt>
        }
        let mantissa = tmpVar bld 32<rt>
        append bld {
          mantissa := getMantissa src 32<rt>
        }
        let inf = isInfinity 32<rt> exponent mantissa
        let nan = isNaN 32<rt> exponent mantissa
        dst, src, inf, nan
      | _ ->
        let dst = transOprToFPConvert ins bld fd
        let src = transOprToFPPairConcat bld fs
        append bld {
          exponent := getExponentFull src 64<rt>
        }
        let mantissa = tmpVar bld 64<rt>
        append bld {
          mantissa := getMantissa src 64<rt>
        }
        let inf = isInfinity 64<rt> exponent mantissa
        let nan = isNaN 64<rt> exponent mantissa
        dst, src, inf, nan
    let srcSz = if ins.Fmt = Some Fmt.S then 32<rt> else 64<rt>
    let struct (value, noInteger) = wordOfFP bld roundingOfFCSR src inf nan
    dst := value
    fpExceptionsToInt bld srcSz src noInteger
  }

let cvtl ins bld =
  lift bld ins {
    let fd, fs = getTwoOprs ins
    let fdB, fdA = transOprToFPPair bld fd
    let eval = tmpVar bld 64<rt>
    let exponent = tmpVar bld 1<rt>
    let srcSz = if ins.Fmt = Some Fmt.S then 32<rt> else 64<rt>
    let struct (src, inf, nan) =
      match ins.Fmt with
      | Some Fmt.S ->
        let src = transOprToFPConvert ins bld fs
        append bld {
          exponent := getExponentFull src 32<rt>
        }
        let mantissa = tmpVar bld 32<rt>
        append bld {
          mantissa := getMantissa src 32<rt>
        }
        let inf = isInfinity 32<rt> exponent mantissa
        let nan = isNaN 32<rt> exponent mantissa
        src, inf, nan
      | _ ->
        let src = transOprToFPPairConcat bld fs
        append bld {
          exponent := getExponentFull src 64<rt>
        }
        let mantissa = tmpVar bld 64<rt>
        append bld {
          mantissa := getMantissa src 64<rt>
        }
        let inf = isInfinity 64<rt> exponent mantissa
        let nan = isNaN 64<rt> exponent mantissa
        src, inf, nan
    let struct (value, noInteger) =
      longOfFP bld roundingOfFCSR srcSz src inf nan
    eval := value
    fpExceptionsToInt bld srcSz src noInteger
    writeFPResult fdB fdA eval bld
  }

let cvts ins bld =
  lift bld ins {
    let fd, fs = getTwoOprs ins
    let fd = transOprToFPConvert ins bld fd
    let dst = if is32Bit bld then fd else AST.xtlo 32<rt> fd
    let result = tmpVar bld 32<rt>
    let struct (src, srcSz, fromInt) =
      match ins.Fmt with
      | Some Fmt.L -> struct (transOprToFPPairConcat bld fs, 64<rt>, true)
      | Some Fmt.D -> struct (transOprToFPPairConcat bld fs, 64<rt>, false)
      | _ -> struct (transOprToFPConvert ins bld fs, 32<rt>, true)
    result :=
      if fromInt then AST.cast CastKind.SIntToFloat 32<rt> src
      else AST.cast CastKind.FloatCast 32<rt> src
    normalizeNaN 32<rt> result bld
    if fromInt then
      let back = AST.floatToSInt RoundingMode.TowardZero srcSz result
      fpExceptionsFromInt bld src back
    else
      let back = AST.cast CastKind.FloatCast srcSz result
      fpExceptionsConvert bld srcSz 32<rt> back src result
    dst := result
  }

let dadd ins bld =
  lift bld ins {
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    let rd, rs, rt = transThreeOprs ins bld
    let cond = checkOverflowOnDadd rs rt (rs .+ rt)
    AST.cjmp cond (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    AST.sideEffect (Exception IntegerOverflow)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rd := rs .+ rt
    AST.lmark lblEnd
  }

let dsub ins bld =
  lift bld ins {
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    let rd, rs, rt = transThreeOprs ins bld
    let cond = checkOverflowOnDsub rs rt (rs .- rt)
    AST.cjmp cond (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    AST.sideEffect (Exception IntegerOverflow)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rd := rs .- rt
    AST.lmark lblEnd
  }

let daddu ins bld =
  lift bld ins {
    let rd, rs, rt = transThreeOprs ins bld
    let result = tmpVar bld 64<rt>
    result := rs .+ rt
    rd := result
  }

let daddi ins bld =
  lift bld ins {
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    let rt, rs, imm = transThreeOprs ins bld
    let cond = checkOverflowOnDadd rs imm (rs .+ imm)
    AST.cjmp cond (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    AST.sideEffect (Exception IntegerOverflow)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rt := rs .+ imm
    AST.lmark lblEnd
  }

let daddiu ins bld =
  lift bld ins {
    let rt, rs, imm = transThreeOprs ins bld
    let result = tmpVar bld 64<rt>
    result := rs .+ imm
    rt := result
  }

let private countLeadingD ones ins bld =
  lift bld ins {
    let lblLoop = label bld "Loop"
    let lblContinue = label bld "Continue"
    let lblEnd = label bld "End"
    let wordSz = bld.RegType
    let rd, rs = transTwoOprs ins bld
    let rs = if ones then AST.not rs else rs
    let t = tmpVar bld wordSz
    let n63 = numI32 63 wordSz
    t := n63
    AST.lmark lblLoop
    AST.cjmp (rs >> t == AST.num1 wordSz)
             (AST.jmpDest lblEnd)
             (AST.jmpDest lblContinue)
    AST.lmark lblContinue
    t := t .- AST.num1 wordSz
    AST.cjmp (t == numI64 -1L wordSz)
             (AST.jmpDest lblEnd)
             (AST.jmpDest lblLoop)
    AST.lmark lblEnd
    rd := n63 .- t
  }

/// Selects a defined value in place of a division MIPS never performs. A zero
/// divisor raises no arithmetic exception under any circumstances and leaves
/// both HI and LO UNPREDICTABLE (MD00087 Vol. II, DIV and DDIV), so the IR has
/// to select for either register rather than reach a division that would trap
/// on evaluation.
let private divGuard (bld: ILowUIRBuilder) cond expr =
  AST.ite cond (AST.num0 bld.RegType) expr

/// DCLZ: how many zeros the doubleword begins with.
let dclz ins bld = countLeadingD false ins bld

/// DCLO: how many ones it begins with, which is DCLZ of the complement.
let dclo ins bld = countLeadingD true ins bld

let ddiv ins bld =
  lift bld ins {
    let rs, rt = transTwoOprs ins bld
    let hi = regVar bld R.HI
    let lo = regVar bld R.LO
    let num0 = AST.num0 bld.RegType
    let intMin = AST.num (BitVector.SignedMin bld.RegType)
    (* The quotient of -2^63 by -1 is not representable; truncated it is -2^63
       again, and DDIV raises no exception for that pair either. *)
    let isOverflow = (rs == intMin) .& (rt == numI64 -1L bld.RegType)
    let guard = divGuard bld (rt == num0)
    lo := guard (AST.ite isOverflow intMin (AST.sdiv rs rt))
    hi := guard (AST.ite isOverflow num0 (AST.smod rs rt))
  }

let dmfc1 ins bld =
  lift bld ins {
    let rt, fs = getTwoOprs ins
    let rt = transOpr ins bld rt
    let fs = transOprToFPPairConcat bld fs
    rt := fs
  }

let dmtc1 ins bld =
  lift bld ins {
    let rt, fs = getTwoOprs ins
    let rt = transOpr ins bld rt
    let fsB, fsA = transOprToFPPair bld fs
    writeFPResult fsB fsA rt bld
  }

let ddivu ins bld =
  lift bld ins {
    let rs, rt = transTwoOprs ins bld
    let hi = regVar bld R.HI
    let lo = regVar bld R.LO
    let guard = divGuard bld (rt == AST.num0 bld.RegType)
    lo := guard (AST.div rs rt)
    hi := guard (AST.(mod) rs rt)
  }

let checkDEXTPosSize pos size =
  let posSize = pos + size
  if 0 <= pos
    && pos < 32
    && 0 < size
    && size <= 32
    && 0 < posSize
    && posSize <= 63 then ()
  else raise InvalidOperandException

let dext ins bld =
  lift bld ins {
    let rt, rs, pos, size = getFourOprs ins
    let rt = transOpr ins bld rt
    let rs = transOpr ins bld rs
    let pos = transOprToImm pos |> int
    let size = transOprToImm size |> int
    checkDEXTPosSize pos size
    let mask = numI64 (getMask size) bld.RegType
    let rs = if pos = 0 then rs else rs >> numI32 pos bld.RegType
    rt := mask .& rs |> AST.zext 64<rt>
  }

let checkDEXTMPosSize pos size =
  let posSize = pos + size
  if 0 <= pos
    && pos < 32
    && 32 < size
    && size <= 64
    && 32 < posSize
    && posSize <= 64 then ()
  else raise InvalidOperandException

let checkDEXTUPosSize pos size =
  let posSize = pos + size
  if 32 <= pos
    && pos < 64
    && 0 < size
    && size <= 32
    && 32 < posSize
    && posSize <= 64 then ()
  else raise InvalidOperandException

let dextx ins posSizeCheckFn bld =
  lift bld ins {
    let rt, rs, pos, size = getFourOprs ins
    let rt = transOpr ins bld rt
    let rs = transOpr ins bld rs
    let pos = transOprToImm pos |> int
    let sz = transOprToImm size |> int
    posSizeCheckFn pos sz
    if sz = 64 then
      if rt = rs then () else append bld { rt := rs }
    else
      let rs = if pos = 0 then rs else rs >> numI32 pos bld.RegType
      let result = rs .& numI64 (getMask sz) bld.RegType
      rt := result
  }

let checkINSorExtPosSize pos size =
  let posSize = pos + size
  if 0 <= pos
    && pos < 32
    && 0 < size
    && size <= 32
    && 0 < posSize
    && posSize <= 32 then ()
  else raise InvalidOperandException

let dins ins bld =
  lift bld ins {
    let rt, rs, pos, size = getFourOprs ins
    let rt = transOpr ins bld rt
    let rs = transOpr ins bld rs
    let pos = int32 (transOprToImm pos)
    let size = int32 (transOprToImm size)
    checkINSorExtPosSize pos size
    if pos = 0 && rt = rs then
      ()
    else
      let posExpr = numI32 pos bld.RegType
      let mask = numI64 (getMask size) bld.RegType
      let rs', rt' =
        if pos = 0 then rs .& mask, rt .& (AST.not mask)
        else (rs .& mask) << posExpr, rt .& (AST.not (mask << posExpr))
      rt := rt' .| rs'
  }

let checkDINSMPosSize pos size =
  let posSize = pos + size
  (* MD00087 DINSM: 0 <= pos < 32, 2 <= size <= 64, 32 < pos+size <= 64. The
     size bound is INCLUSIVE, and this read it as strict -- so pos=31,size=2,
     which the other two relations allow, was rejected outright. DEXTM's
     sibling guard is `32 < size`, which is correct for DEXTM, and the strict
     form was carried across to where an inclusive one was needed. *)
  if 0 <= pos
    && pos < 32
    && 2 <= size
    && size <= 64
    && 32 < posSize
    && posSize <= 64 then ()
  else raise InvalidOperandException

let checkDINSUPosSize pos size =
  let posSize = pos + size
  if 32 <= pos
    && pos < 64
    && 1 <= size
    && size <= 32
    && 32 < posSize
    && posSize <= 64 then ()
  else raise InvalidOperandException

let dinsx ins posSizeCheckFn bld =
  lift bld ins {
    let rt, rs, pos, size = getFourOprs ins
    let rt = transOpr ins bld rt
    let rs = transOpr ins bld rs
    let pos = int32 (transOprToImm pos)
    let size = int32 (transOprToImm size)
    posSizeCheckFn pos size
    if size = 64 then
      if rt = rs then () else append bld { rt := rs }
    else
      let posExpr = numI32 pos bld.RegType
      let mask = numI64 (getMask size) bld.RegType
      let rs', rt' =
        if pos = 0 then rs .& mask, rt .& (AST.not mask)
        else (rs .& mask) << posExpr, rt .& (AST.not (mask << posExpr))
      rt := rt' .| rs'
  }

let div (ins: Instruction) bld =
  lift bld ins {
    match ins.Fmt with
    | None ->
      let rs, rt = transTwoOprs ins bld
      let hi = regVar bld R.HI
      let lo = regVar bld R.LO
      let guard = divGuard bld (rt == AST.num0 bld.RegType)
      if is32Bit bld then
        lo :=
          (AST.sext 64<rt> rs ?/ AST.sext 64<rt> rt)
          |> AST.xtlo 32<rt> |> guard
        hi :=
          (AST.sext 64<rt> rs ?% AST.sext 64<rt> rt)
          |> AST.xtlo 32<rt> |> guard
      else
        lo := guard (signExtLo64 (signExtLo64 rs ?/ signExtLo64 rt))
        hi := guard (signExtLo64 (signExtLo64 rs ?% signExtLo64 rt))
    | Some Fmt.D ->
      let fd, fs, ft = getThreeOprs ins
      let fdB, fdA = transOprToFPPair bld fd
      let src1, src2 = transFPConcatTwoOprs bld (fs, ft)
      let struct (tSrc1, tSrc2, result) = tmpVars3 bld 64<rt>
      reDupSrc fs ft src1 src2 tSrc1 tSrc2 bld
      result := AST.fdiv tSrc1 tSrc2
      normalizeNaN 64<rt> result bld
      fpExceptions bld 64<rt> FPDiv tSrc1 tSrc2 result
      writeFPResult fdB fdA result bld
    | _ ->
      let fd, fs, ft = getThreeOprs ins
      let dst, src1, src2 = transThreeSingleFP bld (fd, fs, ft)
      let struct (tSrc1, tSrc2, result) = tmpVars3 bld 32<rt>
      reDupSrc fs ft src1 src2 tSrc1 tSrc2 bld
      result := AST.fdiv tSrc1 tSrc2
      normalizeNaN 32<rt> result bld
      fpExceptions bld 32<rt> FPDiv tSrc1 tSrc2 result
      dst := result
  }

let divu ins bld =
  lift bld ins {
    let rs, rt = transTwoOprs ins bld
    let hi = regVar bld R.HI
    let lo = regVar bld R.LO
    let guard = divGuard bld (rt == AST.num0 bld.RegType)
    if is32Bit bld then
      let struct (extendRs, extendRt) = tmpVars2 bld 64<rt>
      extendRs := AST.zext 64<rt> rs
      extendRt := AST.zext 64<rt> rt
      lo := (extendRs ./ extendRt) |> AST.xtlo 32<rt> |> guard
      hi := (extendRs .% extendRt) |> AST.xtlo 32<rt> |> guard
    else
      let struct (maskRs, maskRt) = tmpVars2 bld 64<rt>
      let mask = numI64 0xFFFFFFFFL 64<rt>
      maskRs := rs .& mask
      maskRt := rt .& mask
      lo := signExtLo64 (maskRs ./ maskRt) |> guard
      hi := signExtLo64 (maskRs .% maskRt) |> guard
  }

let dmul ins bld isSign =
  lift bld ins {
    let rs, rt = transTwoOprs ins bld
    let struct (high, low) = mul64BitReg rs rt bld isSign
    let hi = regVar bld R.HI
    let lo = regVar bld R.LO
    lo := low
    hi := high
  }

let drotr ins bld =
  lift bld ins {
    let rd, rt, sa = getThreeOprs ins
    let rd, rt = transOpr ins bld rd, transOpr ins bld rt
    let sa = numU64 (transOprToImm sa) 64<rt>
    let size = numI32 64 64<rt>
    rd := (rt << (size .- sa)) .| (rt >> sa)
  }

let drotr32 ins bld =
  lift bld ins {
    let rd, rt, sa = getThreeOprs ins
    let rd, rt = transOpr ins bld rd, transOpr ins bld rt
    let sa = numU64 (transOprToImm sa) 64<rt> .+ numI32 32 64<rt>
    let size = numI32 64 64<rt>
    rd := (rt << (size .- sa)) .| (rt >> sa)
  }

let drotrv ins bld =
  lift bld ins {
    let rd, rt, rs = transThreeOprs ins bld
    let sa = tmpVar bld 64<rt>
    let size = numI32 64 64<rt>
    sa := rs .& numI32 0x3F 64<rt>
    rd := (rt << (size .- sa)) .| (rt >> sa)
  }

let dsra ins bld =
  lift bld ins {
    let rd, rt, sa = transThreeOprs ins bld
    rd := rt ?>> sa |> AST.sext 64<rt>
  }

let dsrav ins bld =
  lift bld ins {
    let rd, rt, rs = transThreeOprs ins bld
    rd := rt ?>> (rs .& numI32 63 64<rt>) |> AST.sext 64<rt>
  }

let dsra32 ins bld =
  lift bld ins {
    let rd, rt, sa = transThreeOprs ins bld
    let sa = sa .+ numI32 32 64<rt>
    rd := rt ?>> sa |> AST.sext 64<rt>
  }

let dShiftLeftRight32 ins bld shf =
  lift bld ins {
    let rd, rt, sa = transThreeOprs ins bld
    let sa = sa .+ numI32 32 64<rt>
    rd := shf rt sa |> AST.zext 64<rt>
  }

let dShiftLeftRight ins bld shf =
  lift bld ins {
    let rd, rt, sa = transThreeOprs ins bld
    rd := shf rt sa |> AST.zext 64<rt>
  }

let dShiftLeftRightVar ins bld shf =
  lift bld ins {
    let rd, rt, rs = transThreeOprs ins bld
    rd := shf rt (rs .& numI32 63 64<rt>) |> AST.zext 64<rt>
  }

let dsubu ins bld =
  lift bld ins {
    let rd, rs, rt = transThreeOprs ins bld
    let result = tmpVar bld 64<rt>
    result := rs .- rt
    rd := result
  }

let insert ins bld =
  lift bld ins {
    let rt, rs, pos, size = getFourOprs ins
    let rt = transOpr ins bld rt
    let rs = transOpr ins bld rs
    let pos = transOprToImm pos |> int
    let size = transOprToImm size |> int
    let msb = pos + size - 1
    let lsb = pos
    checkINSorExtPosSize pos size
    if lsb > msb then raise InvalidOperandException else ()
    let mask = numI64 (getMask size) bld.RegType
    let posExpr = numI32 pos bld.RegType
    let rs', rt' =
      if pos = 0 then rs .& mask, rt .& (AST.not mask)
      else (rs .& mask) << posExpr, rt .& (AST.not (mask << posExpr))
    let merged = rt' .| rs'
    (* MD00087 INS: GPR[rt] <- sign_extend(GPR[rt]31..msb+1 || ... ). The
       merge happens in 32 bits and the WORD is then sign-extended, so an
       insert that reaches bit 31 changes the sign of the whole register.
       Merging straight into the 64-bit rt keeps its old upper half, which
       is right for DINS and wrong here. *)
    rt := if is32Bit bld then merged else signExtLo64 merged
  }

let getJALROprs (ins: Instruction) bld =
  match ins.Operands with
  | OneOperand opr ->
    struct (regVar bld R.R31, transOpr ins bld opr)
  | TwoOperands(o1, o2) ->
    struct (transOpr ins bld o1, transOpr ins bld o2)
  | _ ->
    raise InvalidOperandException

let j ins (bld: LowUIRBuilder) =
  liftTransfer bld ins {
    let nPC = regVar bld R.NPC
    let dest = getOneOpr ins |> transOpr ins bld
    bld.DelayedBranch <- InterJmpKind.Base
    nPC := dest
  }

/// <summary>
/// Whether a jump through a register carries the encoding to read at its
/// target, which is a property of the PROCESSOR rather than of the
/// instruction.
///
/// MD00076 3.8 says so outright: JR and JALR "load the ISA Mode bit from bit
/// 0 of the source register" on a processor that implements MIPS16e, and
/// "cause an Address exception" on one that does not. Which kind this is is
/// what the image says it was built for, and that does not change as the
/// program moves between encodings -- so it is asked of the ISA and not of
/// the instruction, whose own encoding is whatever the last jump left.
///
/// The test is against the ordinary encoding rather than against MIPS16e
/// because microMIPS carries the SAME bit in the same place, which is the
/// half that was missing: MD00594's JALR reads "Set the ISA Mode bit to the
/// value in GPR rs bit 0. Set bit 0 of the target address to zero", word for
/// word what MIPS16e says. A jump left unmasked lands one byte inside the
/// instruction it was aimed at.
/// </summary>
let private carriesMode (bld: ILowUIRBuilder) =
  bld.ISA.MIPSISAMode <> MIPSISAMode.MIPS

/// <summary>
/// The return address a call leaves behind, which carries the encoding it was
/// made from.
///
/// MD00076 writes it as <c>(PC + n)[GPRLEN-1..1] || ISAMode</c>: the low bit
/// is not part of the address but the mode to come back to, and a JR through
/// this register reads it there. So a call made from the compressed encoding
/// leaves an ODD address behind, and the return finds its way back.
///
/// Which mode that is belongs to the CALL and not to the processor. A
/// -mips16 program is 32-bit code with MIPS16e functions in it and both
/// encodings make calls; a link from the 32-bit side that carried the bit
/// anyway would send its own return into the halfword decoder.
/// </summary>
let private linkFrom (ins: Instruction) (bld: LowUIRBuilder) ahead =
  let pc = regVar bld R.PC
  let raw = pc .+ numI32 ahead bld.RegType
  if ins.IsCompressed then raw .| AST.num1 bld.RegType else raw

/// <summary>
/// How far past a call the instruction it returns to sits.
///
/// The call's own length plus its delay slot's, and the slot is not always a
/// word: a MIPS16e one is a halfword, which is why MD00076 writes the link of
/// JAL as <c>PC + 6</c> where the base architecture writes <c>PC + 8</c>, and
/// the link of JALR as <c>PC + 4</c>. A call that left the wrong address
/// behind returns two bytes late, and in an encoding of halfwords that is
/// another instruction rather than a misalignment -- so nothing faults and
/// the program simply goes somewhere else.
/// </summary>
let private afterSlot (ins: Instruction) =
  let slot = if ins.ISAMode = MIPSISAMode.MIPS16 then 2 else 4
  int ins.Length + slot

/// <summary>
/// The same for the microMIPS calls that name a halfword slot in the
/// mnemonic -- JALS, JALRS, BLTZALS and BGEZALS.
///
/// microMIPS does not make the slot's width follow the encoding the way
/// MIPS16e does; it gives the short slot its own instructions, and MD00594
/// writes their link as <c>PC + 6</c> against JALR's <c>PC + 8</c>.
/// </summary>
let private afterShortSlot (ins: Instruction) =
  int ins.Length + 2

let jal (ins: Instruction) (bld: LowUIRBuilder) =
  liftTransfer bld ins {
    let nPC = regVar bld R.NPC
    let lr = regVar bld R.R31
    let dest = getOneOpr ins |> transOpr ins bld
    bld.DelayedBranch <- InterJmpKind.IsCall
    lr := linkFrom ins bld (afterSlot ins)
    nPC := dest
  }

/// <summary>
/// JALX, which calls into the OTHER encoding of the instruction set.
///
/// That is the whole of what sets it apart from JAL, and the jump carries
/// it: the processor holds the encoding it is reading in a bit that is not
/// in any register a program can name, so which encoding the words at the
/// target belong to cannot be read off the target. Which way this one
/// crosses is settled by the side it starts on, there being only two.
/// </summary>
let jalx (ins: Instruction) (bld: LowUIRBuilder) =
  liftTransfer bld ins {
    let nPC = regVar bld R.NPC
    let dest = getOneOpr ins |> transOpr ins bld
    let toward =
      if ins.IsCompressed then InterJmpKind.SwitchToMIPS
      else InterJmpKind.SwitchToMicroMIPS
    bld.DelayedBranch <- InterJmpKind.IsCall ||| toward
    regVar bld R.R31 := linkFrom ins bld (afterSlot ins)
    nPC := dest
  }

let jalr (ins: Instruction) (bld: LowUIRBuilder) =
  liftTransfer bld ins {
    let nPC = regVar bld R.NPC
    let struct (lr, rs) = getJALROprs ins bld
    bld.DelayedBranch <- InterJmpKind.IsCall
    bld.BranchCarriesMode <- carriesMode bld
    lr := linkFrom ins bld (afterSlot ins)
    nPC := rs
  }

let jr ins (bld: LowUIRBuilder) =
  liftTransfer bld ins {
    let nPC = regVar bld R.NPC
    let rs = transOneOpr ins bld
    bld.DelayedBranch <- InterJmpKind.Base
    bld.BranchCarriesMode <- carriesMode bld
    nPC := rs
  }

/// <summary>
/// JRC, which is JR without the delay slot.
///
/// A compact jump is not a faster JR but a different instruction: the word
/// after it is not executed before the jump takes effect, so a delay slot
/// written for JR would run where JRC would not run it.
/// </summary>
let jumpRegCompact ins (bld: LowUIRBuilder) =
  lift bld ins {
    let rs = transOneOpr ins bld
    if carriesMode bld then interJmpByMode bld rs InterJmpKind.Base
    else append bld { AST.interjmp rs InterJmpKind.Base }
  }

/// <summary>
/// JALS, which is JAL with a delay slot of one halfword.
///
/// The link is where the difference shows: the call returns to the
/// instruction after the slot, two bytes past the end of this one.
/// </summary>
let jalShortSlot ins (bld: LowUIRBuilder) =
  liftTransfer bld ins {
    let nPC = regVar bld R.NPC
    let dest = getOneOpr ins |> transOpr ins bld
    bld.DelayedBranch <- InterJmpKind.IsCall
    regVar bld R.R31 := linkFrom ins bld (afterShortSlot ins)
    nPC := dest
  }

/// BLTZALS and BGEZALS, which are BLTZAL and BGEZAL with a delay slot of one
/// halfword.
let branchLinkShortSlot ins (bld: LowUIRBuilder) cmp =
  liftTransfer bld ins {
    let rs, offset = transTwoOprs ins bld
    let nAddr = tmpVar bld bld.RegType
    let cond = cmp rs (AST.num0 bld.RegType)
    nAddr := linkFrom ins bld (afterShortSlot ins)
    regVar bld R.R31 := nAddr
    updatePCCond ins bld offset cond InterJmpKind.IsCall
  }

/// <summary>
/// JALRS, whose delay slot holds one halfword rather than one word.
///
/// That is the whole of what sets it apart from JALR, and the link is where
/// it shows: MD00594 writes it as <c>PC + 6</c> against JALR's <c>PC + 8</c>,
/// the call returning to the instruction after a slot two bytes long.
/// </summary>
let jalrShortSlot ins (bld: LowUIRBuilder) =
  liftTransfer bld ins {
    let nPC = regVar bld R.NPC
    let struct (lr, rs) = getJALROprs ins bld
    bld.DelayedBranch <- InterJmpKind.IsCall
    bld.BranchCarriesMode <- carriesMode bld
    lr := linkFrom ins bld (afterShortSlot ins)
    nPC := rs
  }

/// <summary>
/// JALRC, which is JALR without the delay slot.
///
/// The target is read into a temporary before the link is written, because
/// nothing stops the call from jumping through the register it links into.
/// </summary>
let jalrCompact (ins: Instruction) (bld: LowUIRBuilder) =
  lift bld ins {
    let struct (lr, rs) = getJALROprs ins bld
    let target = tmpVar bld bld.RegType
    target := rs
    lr := linkFrom ins bld (int ins.Length)
    if carriesMode bld then interJmpByMode bld target InterJmpKind.IsCall
    else append bld { AST.interjmp target InterJmpKind.IsCall }
  }

/// <summary>
/// JRADDIUSP and JRCADDIUSP, which return and give the frame back in one
/// instruction.
///
/// Neither register is named: the jump is to the return address and the
/// adjustment is to the stack pointer, and an epilogue never wants any
/// others. The adjustment is unsigned because a return only ever unwinds.
///
/// NEITHER has a delay slot, despite only one of them saying so in its name.
/// MD00594 writes JRADDIUSP's operation across I and I+1 the way it writes a
/// delayed branch, but the halves are the other way round -- the PC
/// assignment is in I and the stack adjustment in I+1 -- so the notation is
/// about the order of the two writes and not about a slot. A processor
/// settles it: an instruction written after one does not execute. Lifting it
/// as delayed leaves the return armed while the halfword after it runs, and a
/// compiler puts a branch TARGET there.
/// </summary>
let jumpRegAdjust ins (bld: LowUIRBuilder) =
  lift bld ins {
    let sp = regVar bld R.R29
    let imm = transOneOpr ins bld
    let ra = regVar bld R.R31
    sp := sp .+ imm
    if carriesMode bld then interJmpByMode bld ra InterJmpKind.Base
    else append bld { AST.interjmp ra InterJmpKind.Base }
  }

/// <summary>
/// MOVEP, which is two register moves in one instruction.
///
/// It is there because a call sets up two argument registers more often than
/// one. The two destinations are not any two registers but one of eight
/// pairs, which is what lets the encoding name them in three bits.
/// </summary>
let movePair ins bld =
  lift bld ins {
    let rdOpr, reOpr, rsOpr, rtOpr = getFourOprs ins
    let rd = transOpr ins bld rdOpr
    let re = transOpr ins bld reOpr
    rd := transOpr ins bld rsOpr
    re := transOpr ins bld rtOpr
  }

/// <summary>
/// LWM and SWM, which move a set of registers to or from consecutive words.
///
/// The set is the one a prologue saves and an epilogue restores, and the
/// words are ascending from the named address in the order the set lists.
/// Each register takes a word however wide it is, so a 64-bit machine writes
/// the low half and reads a sign-extended one back.
/// </summary>
let loadStoreMultiple ins bld isLoad width =
  lift bld ins {
    let regsOpr, memOpr = getTwoOprs ins
    let regs =
      match regsOpr with
      | OpRegList regs -> List.toArray regs
      | _ -> raise InvalidOperandException
    let addr = transOprToBaseOffset bld memOpr
    let step = RegType.toByteWidth width
    for i = 0 to regs.Length - 1 do
      let reg = regVar bld regs[i]
      let at = addr .+ numI32 (i * step) bld.RegType
      if isLoad then reg := AST.sext bld.RegType (loadNative bld width at)
      else storeNative bld at (AST.xtlo width reg)
  }

/// <summary>
/// LWP, SWP, LDP and SDP, which move two registers rather than a list.
///
/// The second register is the one after the first and the encoding does not
/// name it, so it is written out here to keep the lifter from having to know
/// how a register number is put together.
/// </summary>
let loadStorePair ins bld isLoad width =
  lift bld ins {
    let firstOpr, secondOpr, memOpr = getThreeOprs ins
    let first = transOpr ins bld firstOpr
    let second = transOpr ins bld secondOpr
    let addr = transOprToBaseOffset bld memOpr
    let step = numI32 (RegType.toByteWidth width) bld.RegType
    if isLoad then
      first := AST.sext bld.RegType (loadNative bld width addr)
      second := AST.sext bld.RegType (loadNative bld width (addr .+ step))
    else
      storeNative bld addr (AST.xtlo width first)
      storeNative bld (addr .+ step) (AST.xtlo width second)
  }

/// <summary>
/// LWXS, whose index is a word count rather than a byte count.
///
/// That is the whole of what sets it apart from LWX, and reading it as a
/// byte count would load from a quarter of the way along the array.
/// </summary>
let loadWordScaled ins bld =
  lift bld ins {
    let rdOpr, memOpr = getTwoOprs ins
    let rd = transOpr ins bld rdOpr
    match memOpr with
    | OpMem(b, Reg idx, _) ->
      let addr = regVar bld b .+ (regVar bld idx << numI32 2 bld.RegType)
      rd := AST.sext bld.RegType (loadNative bld 32<rt> addr)
    | _ ->
      raise InvalidOperandException
  }

/// <summary>
/// What a load reads, which is not always a memory operand.
///
/// MIPS16e reads a constant out of the instruction stream -- a word at a
/// distance from the program counter -- and the disassembler prints that as
/// the ADDRESS it resolved rather than as a base and an offset, there being
/// no base register to print. So the operand arrives as a place, and taking
/// it for the value would load the address into the register instead of what
/// is at it. The compiler puts every literal a MIPS16e function needs in a
/// pool it reads this way, so getting it wrong is not a corner: the first
/// such load faults.
/// </summary>
let private loadedValue (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(_, OpAddr _) ->
    (* Only LW and LD are written this way -- a doubleword and a word are the
       only literals a pool holds -- so the width is the opcode's and there is
       no operand to read it off. *)
    let width = if ins.Opcode = Op.LD then 64<rt> else 32<rt>
    let _, target = transTwoOprs ins bld
    loadNative bld width target
  | _ ->
    let _, mem = transTwoOprs ins bld
    mem

let loadSigned (ins: Instruction) bld =
  lift bld ins {
    let rt, _ = transTwoOprs ins bld
    rt := AST.sext bld.RegType (loadedValue ins bld)
  }

let loadUnsigned (ins: Instruction) bld =
  lift bld ins {
    let rt, _ = transTwoOprs ins bld
    rt := AST.zext bld.RegType (loadedValue ins bld)
  }

let readHWR ins bld =
  lift bld ins {
    let rtOpr, rdOpr, _ = getThreeOprs ins
    let rt = transOpr ins bld rtOpr
    let value =
      match rdOpr with
      | OpReg R.R29 -> regVar bld R.ULR      (* HWR 29: TLS pointer *)
      | OpReg R.R3 -> numI32 1 bld.RegType   (* CCRes: nonzero resolution *)
      | _ -> numI32 0 bld.RegType            (* CPUNum, SYNCI_Step, CC *)
    rt := value
  }

/// The Release 6 compact compare-and-branch family.
///
/// Release 6 dropped the branch delay slot, and these are what replaced
/// the delayed branches. Every member differs from the others only in its
/// condition, so the condition is a parameter and the transfer is shared:
/// twenty instructions, one lifter, which is also how the manual presents
/// them.
let compactBranchRR ins bld cmp =
  lift bld ins {
    let rs, rt, offset = transThreeOprs ins bld
    updatePCCondCompact ins bld offset (cmp rs rt)
  }

/// A compact compare-with-zero branch.
let compactBranchZ ins bld cmp =
  lift bld ins {
    let r, offset = transTwoOprs ins bld
    updatePCCondCompact ins bld offset (cmp r (AST.num0 bld.RegType))
  }

/// The and-link forms. MD00087 says the return address link is updated
/// UNCONDITIONALLY, so the write sits outside the branch rather than on its
/// taken path.
let compactBranchLinkZ ins bld cmp =
  lift bld ins {
    let r, offset = transTwoOprs ins bld
    let cond = cmp r (AST.num0 bld.RegType)
    regVar bld R.R31 := regVar bld R.PC .+ numI32 4 bld.RegType
    updatePCCondCompact ins bld offset cond
  }

/// BOVC and BNVC branch on whether the 32-bit signed sum of their operands
/// overflows. They compute no sum -- the test is the whole instruction.
let branchOverflowCompact ins bld taken =
  lift bld ins {
    let rs, rt, offset = transThreeOprs ins bld
    let t = tmpVar bld bld.RegType
    t := rs .+ rt
    let ovf = checkOverflowOnAdd rs rt t
    updatePCCondCompact ins bld offset (if taken then ovf else AST.not ovf)
  }

let bcCompact ins bld =
  lift bld ins {
    let offset = transOneOpr ins bld
    AST.interjmp offset InterJmpKind.Base
  }

let balc ins bld =
  lift bld ins {
    let offset = transOneOpr ins bld
    regVar bld R.R31 := regVar bld R.PC .+ numI32 4 bld.RegType
    AST.interjmp offset InterJmpKind.IsCall
  }

/// JIC and JIALC jump to a register plus a signed offset. The target is read
/// into a temporary before the link is written, because the register the jump
/// reads may be the one the link overwrites.
let jicCompact ins bld link =
  lift bld ins {
    let rt, off = transTwoOprs ins bld
    let target = tmpVar bld bld.RegType
    target := rt .+ off
    if link then
      regVar bld R.R31 := regVar bld R.PC .+ numI32 4 bld.RegType
      AST.interjmp target InterJmpKind.IsCall
    else
      AST.interjmp target InterJmpKind.Base
  }

/// The Release 6 multiply family: the product's low or high half into rd.
///
/// These exist because Release 6 dropped HI and LO. Each computes the
/// same product the older instructions did and keeps ONE half of it in a
/// general register, so the opcode says which half rather than which
/// register pair.
///
/// The width comes from the OPCODE, not from the register file. MUL, MUH,
/// MULU and MUHU are 32-bit operations on a 64-bit machine too -- only the
/// D-prefixed members are 64-bit -- so keying the width on `is32Bit bld`
/// would make every one of them 64 bits wide on a MIPS64 target.
let mulR6 ins bld half signed wide =
  lift bld ins {
    let rd, rs, rt = transThreeOprs ins bld
    if wide then
      (* A 64x64 product needs 128 bits, and the high half is what DMUH
         wants, so the multiply is done there and then narrowed. *)
      let ext e = if signed then AST.sext 128<rt> e else AST.zext 128<rt> e
      let prod = tmpVar bld 128<rt>
      prod := ext rs .* ext rt
      rd := if half then AST.xthi 64<rt> prod else AST.xtlo 64<rt> prod
    else
      let lo e = AST.xtlo 32<rt> e
      let ext e = if signed then AST.sext 64<rt> (lo e)
                  else AST.zext 64<rt> (lo e)
      let prod = tmpVar bld 64<rt>
      prod := ext rs .* ext rt
      let res = if half then AST.xthi 32<rt> prod else AST.xtlo 32<rt> prod
      rd := if is32Bit bld then res else AST.sext 64<rt> res
  }

/// The Release 6 divide family: the quotient or the remainder into rd. A zero
/// divisor is UNPREDICTABLE, exactly as it is before Release 6, so the guard
/// is here to keep the evaluator from trapping rather than to satisfy the
/// architecture.
/// The width is the opcode's, for the same reason it is in mulR6: DIV and
/// MOD stay 32-bit on a MIPS64 target and only DDIV and DMOD are 64.
let divR6 ins bld wantRem signed wide =
  lift bld ins {
    let rd, rs, rt = transThreeOprs ins bld
    let sz = if wide then 64<rt> else 32<rt>
    let narrow e = if wide then e else AST.xtlo 32<rt> e
    let rs, rt = narrow rs, narrow rt
    let num0 = AST.num0 sz
    let guard e = AST.ite (rt == num0) num0 e
    let res =
      if signed then
        let intMin = AST.num (BitVector.SignedMin sz)
        let isOverflow = (rs == intMin) .& (rt == numI64 -1L sz)
        if wantRem then
          guard (AST.ite isOverflow num0 (AST.smod rs rt))
        else
          guard (AST.ite isOverflow intMin (AST.sdiv rs rt))
      elif wantRem then
        guard (rs .% rt)
      else
        guard (rs ./ rt)
    rd := if wide || is32Bit bld then res else AST.sext 64<rt> res
  }

/// AUI, DAUI, DAHI and DATI: add an immediate shifted into one of the upper
/// halves of a register. Release 6 has them because it dropped the
/// branch-delay-slot tricks that used to build a 64-bit constant, and four of
/// them together cover a full doubleword.
let addUpperImm ins bld shift twoOperand =
  lift bld ins {
    if twoOperand then
      let rs, imm = transTwoOprs ins bld
      rs := rs .+ (imm << numI32 shift bld.RegType)
    else
      let rt, rs, imm = transThreeOprs ins bld
      rt := rs .+ (imm << numI32 shift bld.RegType)
  }

/// BITSWAP and DBITSWAP reverse the bits WITHIN each byte and leave the bytes
/// where they are. Doing it with three masked swaps costs no loop: each pass
/// exchanges neighbouring fields of half the previous width, and because the
/// masks never cross a byte boundary all the bytes are done at once.
let bitswap ins bld wide =
  lift bld ins {
    let rd, rt = transTwoOprs ins bld
    let sz = if wide then 64<rt> else 32<rt>
    let src = if wide then rt else AST.xtlo 32<rt> rt
    let t = tmpVar bld sz
    let mask (byteValue: uint64) =
      let mutable v = 0UL
      for _ in 1 .. (if wide then 8 else 4) do
        v <- (v <<< 8) ||| byteValue
      numU64 v sz
    t := src
    t := ((t .& mask 0xF0UL) >> numI32 4 sz)
         .| ((t .& mask 0x0FUL) << numI32 4 sz)
    t := ((t .& mask 0xCCUL) >> numI32 2 sz)
         .| ((t .& mask 0x33UL) << numI32 2 sz)
    t := ((t .& mask 0xAAUL) >> numI32 1 sz)
         .| ((t .& mask 0x55UL) << numI32 1 sz)
    rd := if wide || is32Bit bld then t else AST.sext 64<rt> t
  }

/// ALIGN and DALIGN concatenate two registers and take a register-wide window
/// starting bp bytes in: rd = (rt << 8*bp) | (rs >> (GPRLEN - 8*bp)).
let align ins bld wide =
  lift bld ins {
    let rd, rs, rt, bp = transFourOprs ins bld
    let sz = if wide then 64<rt> else 32<rt>
    let narrow e = if wide then e else AST.xtlo 32<rt> e
    let bits = numI32 8 sz .* narrow bp
    let width = numI32 (if wide then 64 else 32) sz
    let res = (narrow rt << bits) .| (narrow rs >> (width .- bits))
    rd := if wide || is32Bit bld then res else AST.sext 64<rt> res
  }

/// The operand plumbing every scalar Release 6 float instruction shares.
///
/// A single is one register. A double is one register on a 64-bit FPU and an
/// even-odd PAIR on a 32-bit one, and `writeFPResult` is what knows the
/// difference -- which is why the destination cannot simply be assigned. An
/// earlier version of these lifters read all three operands with
/// `transThreeOprs`, the INTEGER path, and every double came back as garbage.
///
/// `compute` is handed the width and the two source values and returns the
/// result; `readDst` says whether the destination is also an input, which it
/// is for SEL.fmt and nothing else.
let private fpR6BinaryWith ins bld readDst compute record =
  lift bld ins {
    let dst, src1, src2 = getThreeOprs ins
    match ins.Fmt with
    | Some Fmt.S ->
      let fd, fs, ft = transThreeSingleFP bld (dst, src1, src2)
      let struct (a, b, result) = tmpVars3 bld 32<rt>
      a := fs
      b := ft
      let d = if readDst then fd else a
      result := compute 32<rt> d a b
      (* Before the destination is written, so a record that reads it sees
         what the instruction read. *)
      record 32<rt> d a b result
      fd := result
    | _ ->
      let fdB, fdA = transOprToFPPair bld dst
      let fs, ft = transFPConcatTwoOprs bld (src1, src2)
      let struct (a, b, result) = tmpVars3 bld 64<rt>
      let d = tmpVar bld 64<rt>
      a := fs
      b := ft
      if readDst then d := transOprToFPPairConcat bld dst else d := a
      result := compute 64<rt> d a b
      record 64<rt> d a b result
      writeFPResult fdB fdA result bld
  }

let private fpR6Binary ins bld readDst compute =
  fpR6BinaryWith ins bld readDst compute (fun _ _ _ _ _ -> ())

let private fpR6UnaryWith ins bld compute record =
  lift bld ins {
    let dst, src = getTwoOprs ins
    match ins.Fmt with
    | Some Fmt.S ->
      let fd, fs = transTwoSingleFP bld (dst, src)
      let struct (a, result) = tmpVars2 bld 32<rt>
      a := fs
      result := compute 32<rt> a
      record 32<rt> a result
      fd := result
    | _ ->
      let fdB, fdA = transOprToFPPair bld dst
      let struct (a, result) = tmpVars2 bld 64<rt>
      a := transOprToFPPairConcat bld src
      result := compute 64<rt> a
      record 64<rt> a result
      writeFPResult fdB fdA result bld
  }

let private fpR6Unary ins bld compute =
  fpR6UnaryWith ins bld compute (fun _ _ _ -> ())

let private signBitOf sz =
  if sz = 32<rt> then numU64 0x80000000UL sz
  else numU64 0x8000000000000000UL sz

/// SEL.fmt, SELEQZ.fmt and SELNEZ.fmt: a branchless choice driven by bit 0 of
/// a floating-point register. SEL reads that bit from the DESTINATION, which
/// is therefore an input as well as an output; the other two read it from ft
/// and write zero when the test fails, exactly as their integer namesakes do.
let fpSelect ins bld kind =
  fpR6Binary ins bld (kind = 0) (fun sz d a b ->
    let bit e = AST.xtlo 1<rt> e
    let zero = AST.num0 sz
    match kind with
    | 0 -> AST.ite (bit d) b a
    | 1 -> AST.ite (bit b) zero a
    | _ -> AST.ite (bit b) a zero)

/// MIN.fmt, MAX.fmt, MINA.fmt and MAXA.fmt -- IEEE-754 minNum and maxNum, and
/// the two that compare MAGNITUDES.
///
/// They are not `a < b ? a : b`. Two cases separate them from a comparison,
/// and both are why the instructions exist:
///
///   - A NaN operand is IGNORED rather than propagated: maxNum(x, NaN) is x.
///     Only when both are NaN is the result a NaN.
///   - Zeroes are ordered by SIGN, where a comparison calls them equal:
///     MAX(+0, -0) is +0 and MIN(+0, -0) is -0. An `fgt` sees no difference
///     between the two and would return whichever operand came second.
/// The one thing a choice between two numbers, or a comparison of them, can
/// raise: a quiet NaN is part of what those answer and a signalling one is
/// not.
let private recordSignalling bld sz a b =
  fpExceptionsInvalidOnly bld (fpEitherSignalling bld sz a b)

let fpMinMax ins bld wantMax absolute =
  fpR6BinaryWith ins bld false (fun sz _ a b ->
    let signMask = signBitOf sz
    let ca = if absolute then a .& AST.not signMask else a
    let cb = if absolute then b .& AST.not signMask else b
    (* A NaN is the one value not equal to itself, which is the cheapest
       test the IR can express and needs no exponent picking. A SIGNALLING
       one is a NaN whose leading mantissa bit is clear, and it is not
       ignored the way a quiet one is: IEEE-754 maxNum and minNum return a
       QUIETED copy of it rather than the other operand. Treating every NaN
       alike returned the other operand and lost the signal. *)
    let mantMSB =
      if sz = 32<rt> then numU64 0x400000UL sz
      else numU64 0x8000000000000UL sz
    let aNaN = AST.not (AST.feq a a)
    let bNaN = AST.not (AST.feq b b)
    let aSNaN = aNaN .& ((a .& mantMSB) == AST.num0 sz)
    let bSNaN = bNaN .& ((b .& mantMSB) == AST.num0 sz)
    let isZero e = (e .& AST.not signMask) == AST.num0 sz
    let bothZero = isZero a .& isZero b
    let aNeg = (a .& signMask) != AST.num0 sz
    let byValue =
      if wantMax then AST.ite (AST.fgt a b) a b
      else AST.ite (AST.flt a b) a b
    (* MAXA and MINA are IEEE-754's maxNumMag and minNumMag, which fall
       back to maxNum and minNum when the two MAGNITUDES are equal: MINA
       of +1.0 and -1.0 is -1.0, not whichever operand came second. *)
    let byOrder =
      if not absolute then
        byValue
      else
        let bigger = if wantMax then AST.fgt ca cb else AST.flt ca cb
        AST.ite (ca == cb) byValue (AST.ite bigger a b)
    let byZeroSign =
      if wantMax then AST.ite aNeg b a
      else AST.ite aNeg a b
    let ordered = AST.ite bothZero byZeroSign byOrder
    let oneNaN = AST.ite aNaN b (AST.ite bNaN a ordered)
    let quiet = AST.ite (aNaN .& bNaN) a oneNaN
    let signalling = AST.ite bSNaN (b .| mantMSB) quiet
    AST.ite aSNaN (a .| mantMSB) signalling)
    (fun sz _ a b _ -> recordSignalling bld sz a b)

/// RINT.fmt rounds to an integral value in the operand's own format, in the
/// direction FCSR names -- which is what a conversion no RoundCtrl encloses
/// rounds by. So the field is not read here and the four directions are not
/// spelled out: the cast that keeps the value a float is the whole of it.
let rint ins bld =
  fpR6UnaryWith ins bld (fun sz v -> AST.cast CastKind.RoundToIntegral sz v)
    (fun sz a result ->
      (* Rounding to an integer loses whatever the operand had below the
         point, and nothing else: the answer is always representable, so
         there is no overflow and no underflow to have. *)
      let struct (invalid, inexact) = tmpVars2 bld 1<rt>
      append bld {
        invalid := fpEitherSignalling bld sz a a
        inexact := AST.not invalid .& fpRoundChanged bld sz a result
      }
      fpExceptionsRounded bld invalid inexact)

/// CLASS.fmt -- a ten-bit mask naming the IEEE class of its operand.
///
/// MD00087: "Bits 0 and 1 indicate NaN values: signaling NaN (bit 0) and quiet
/// NaN (bit 1). Bits 2, 3, 4, 5 classify negative values: infinity (bit 2),
/// normal (bit 3), subnormal (bit 4), and zero (bit 5). Bits 6, 7, 8, 9
/// classify positive values" in the same order. The mask is exact and total,
/// which makes this the one float instruction in the suite that is comparable
/// for every input, NaNs included.
let fpClass ins bld =
  fpR6Unary ins bld (fun sz v ->
    let expBits = if sz = 32<rt> then 8 else 11
    let mantBits = if sz = 32<rt> then 23 else 52
    let signMask = signBitOf sz
    let expMask = numU64 ((((1UL <<< expBits) - 1UL) <<< mantBits)) sz
    let mantMask = numU64 ((1UL <<< mantBits) - 1UL) sz
    let zero = AST.num0 sz
    let expo = v .& expMask
    let mant = v .& mantMask
    let neg = (v .& signMask) != zero
    let pos = AST.not neg
    let expAllOnes = expo == expMask
    let expZero = expo == zero
    let mantZero = mant == zero
    let isInf = expAllOnes .& mantZero
    let isNaN = expAllOnes .& AST.not mantZero
    (* A quiet NaN is one whose most significant mantissa bit is set. *)
    let quietBit = numU64 (1UL <<< (mantBits - 1)) sz
    let isQNaN = isNaN .& ((v .& quietBit) != zero)
    let isSNaN = isNaN .& ((v .& quietBit) == zero)
    let isZero = expZero .& mantZero
    let isSub = expZero .& AST.not mantZero
    let isNorm = AST.not expAllOnes .& AST.not expZero
    let bit b cond = AST.ite cond (numU64 (1UL <<< b) sz) zero
    bit 0 isSNaN .| bit 1 isQNaN
    .| bit 2 (neg .& isInf) .| bit 3 (neg .& isNorm)
    .| bit 4 (neg .& isSub) .| bit 5 (neg .& isZero)
    .| bit 6 (pos .& isInf) .| bit 7 (pos .& isNorm)
    .| bit 8 (pos .& isSub) .| bit 9 (pos .& isZero))

/// <summary>
/// MADDF.fmt and MSUBF.fmt, which add the product to the destination or take
/// it away with a SINGLE rounding.
///
/// That is the whole of what separates them from the MADD.fmt of the earlier
/// releases, which rounds the product and then the sum. Release 6 dropped
/// that one and put these in its place, so writing these as a multiply and an
/// add would lift the instruction the release removed.
///
/// Subtracting the product is asked for as a flag rather than done here by
/// flipping the multiplicand's sign: a NaN's sign is not the arithmetic's to
/// change, so a sign flip would have needed a guard, and the guard would have
/// been wrong for a NaN whose sign the operation is supposed to keep.
/// </summary>
let private fusedMultiplyAdd add ins bld =
  fpR6BinaryWith ins bld true (fun sz d a b ->
    let mantBits = if sz = 32<rt> then 23 else 52
    let expMask = numU64 ((((1UL <<< (int sz - mantBits - 1)) - 1UL))
                          <<< mantBits) sz
    let mantMask = numU64 ((1UL <<< mantBits) - 1UL) sz
    let isNaN v =
      ((v .& expMask) == expMask) .& ((v .& mantMask) != AST.num0 sz)
    let result = fma sz (not add) false a b d
    (* Which NaN comes out is the architecture's to say, not the host's. A
       SIGNALLING operand wins over a quiet one wherever it sits -- that is
       what the reference does when one operand is a quiet NaN and a later one
       is signalling -- and it comes out quieted. Failing that a quiet operand
       propagates as it is, and a NaN no operand carried is one this operation
       manufactured, which Release 6 gives the IEEE-2008 default: the quiet bit
       set, the rest of the mantissa clear, and positive whatever the operands
       were. *)
    let quietBit = numU64 (1UL <<< (mantBits - 1)) sz
    let defaultNaN = quietBit .| expMask
    let isSNaN v = isNaN v .& ((v .& quietBit) == AST.num0 sz)
    let isQNaN v = isNaN v .& ((v .& quietBit) != AST.num0 sz)
    let manufactured = AST.ite (isNaN result) defaultNaN result
    let quietD = AST.ite (isQNaN d) d manufactured
    let quietB = AST.ite (isQNaN b) b quietD
    let quietA = AST.ite (isQNaN a) a quietB
    let signalD = AST.ite (isSNaN d) (d .| quietBit) quietA
    let signalB = AST.ite (isSNaN b) (b .| quietBit) signalD
    AST.ite (isSNaN a) (a .| quietBit) signalB)
    (fun sz d a b result ->
      fpExceptionsFused bld sz (not add) a b d result)

/// MADDF.fmt: the destination plus the product.
let maddf ins bld = fusedMultiplyAdd true ins bld

/// MSUBF.fmt: the destination less the product.
let msubf ins bld = fusedMultiplyAdd false ins bld

/// CMP.cond.fmt -- the comparison Release 6 replaced C.cond.fmt with. The
/// answer goes into an FPR as all-ones or all-zeros rather than into a
/// condition-code bit, which is why BC1EQZ and BC1NEZ test a register.
let fpCmpR6 (ins: Instruction) bld =
  fpR6BinaryWith ins bld false (fun sz _ a b ->
    (* Unordered is "neither less, nor equal, nor greater", which is what a
       NaN operand makes true. *)
    let unordered =
      AST.not (AST.flt a b) .& AST.not (AST.feq a b) .& AST.not (AST.fgt a b)
    let cond =
      match ins.Condition with
      | Some Condition.F -> AST.b0
      | Some Condition.UN -> unordered
      | Some Condition.EQ -> AST.feq a b
      | Some Condition.UEQ -> unordered .| AST.feq a b
      | Some Condition.OLT -> AST.flt a b
      | Some Condition.ULT -> unordered .| AST.flt a b
      | Some Condition.OLE -> AST.flt a b .| AST.feq a b
      | Some Condition.ULE -> unordered .| AST.flt a b .| AST.feq a b
      (* The signalling eight test the same thing as the quiet eight; what
         they differ in is what an unordered comparison does to FCSR, which
         is recorded below and not decided here. *)
      | Some Condition.SF -> AST.b0
      | Some Condition.NGLE -> unordered
      | Some Condition.SEQ -> AST.feq a b
      | Some Condition.NGL -> unordered .| AST.feq a b
      | Some Condition.LT -> AST.flt a b
      | Some Condition.NGE -> unordered .| AST.flt a b
      | Some Condition.LE -> AST.flt a b .| AST.feq a b
      | Some Condition.NGT -> unordered .| AST.flt a b .| AST.feq a b
      | _ -> raise InvalidOperandException
    let ones =
      if sz = 32<rt> then numU64 0xFFFFFFFFUL sz
      else numU64 0xFFFFFFFFFFFFFFFFUL sz
    AST.ite cond ones (AST.num0 sz))
    (fun sz _ a b _ ->
      (* A signalling operand always raises; a QUIET one raises only where
         the predicate is one of the signalling eight, which is the whole of
         what separates them from the eight below. *)
      let signals = conditionSignals ins.Condition
      fpExceptionsInvalidOnly bld (fpCompareInvalid bld sz signals a b))

/// BC1EQZ and BC1NEZ branch on bit 0 of an FPR. They are compact -- Release 6
/// has no delay slot -- so the transfer is the compact one.
let bc1z ins bld nonZero =
  lift bld ins {
    let ft, offset = transTwoOprs ins bld
    let bit = AST.xtlo 1<rt> ft
    updatePCCondCompact ins bld offset (if nonZero then bit else AST.not bit)
  }

/// The Release 6 PC-relative family.
///
/// `transOpr` turns an OpAddr(Relative off) into the absolute address the
/// instruction's own address plus off, which is what five of these six want:
/// the manual forms every one of them from "the address of the instruction"
/// rather than from the one after it, because Release 6 has no delay slot for
/// a `+ 4` to account for.
///
/// LDPC is the exception: its base is `PC & ~0x7`, the aligned doubleword
/// CONTAINING the instruction, so an LDPC at an address ending in 4 forms a
/// different address from the same encoding four bytes earlier. That is why
/// the alignment is applied here to the whole sum rather than folded into the
/// operand.
let addiupc ins bld =
  lift bld ins {
    let rs, target = transTwoOprs ins bld
    rs := target
  }

/// AUIPC and ALUIPC add an immediate shifted into the upper half. ALUIPC then
/// clears the low 16 bits of the RESULT, which is not the same as shifting a
/// cleared immediate: the carry out of the addition is kept.
let auipc ins bld aligned =
  lift bld ins {
    let rs, imm = transTwoOprs ins bld
    let pc = numU64 ins.Address bld.RegType
    let sum = pc .+ (AST.sext bld.RegType (AST.xtlo 16<rt> imm)
                     << numI32 16 bld.RegType)
    rs := if aligned then sum .& numI64 -65536L bld.RegType else sum
  }

/// LWPC, LWUPC and LDPC load from the address the offset forms. The loaded
/// word is sign-extended for LWPC and zero-extended for LWUPC; LDPC loads a
/// whole doubleword and needs neither.
let loadPC ins bld size signed =
  lift bld ins {
    let rs, target = transTwoOprs ins bld
    let addr =
      if size = 64<rt> then
        (* LDPC's base is the aligned doubleword containing the instruction,
           so the alignment applies to the address the operand already
           formed minus the instruction's own address, and back again. *)
        let pc = numU64 ins.Address bld.RegType
        let aligned = pc .& numI64 -8L bld.RegType
        aligned .+ (target .- pc)
      else
        target
    let v = AST.loadLE size addr
    rs :=
      if size = 64<rt> then v
      elif signed then AST.sext bld.RegType v
      else AST.zext bld.RegType v
  }

/// SELEQZ and SELNEZ: the conditional move Release 6 replaced MOVZ and
/// MOVN with. They differ from those in leaving ZERO behind when the
/// condition fails rather than leaving the destination alone, which is
/// what lets a pair of them build a branchless select.
let selectZ ins bld wantZero =
  lift bld ins {
    let rd, rs, rt = transThreeOprs ins bld
    let num0 = AST.num0 bld.RegType
    let cond = if wantZero then rt == num0 else rt != num0
    rd := AST.ite cond rs num0
  }

/// LSA and DLSA: GPR[rd] = (GPR[rs] << (sa2+1)) + GPR[rt].
///
/// LSA is a 32-bit operation whose result is SIGN-EXTENDED into the
/// register, even on a 64-bit machine; only DLSA works at 64. Computing LSA
/// at the register width instead leaves the real upper half of the sum
/// there, which is a different number whenever the shift carries past bit 31.
let lsa ins bld wide =
  lift bld ins {
    let rd, rs, rt, sa = transFourOprs ins bld
    let sz = if wide then 64<rt> else 32<rt>
    let narrow e = if wide then e else AST.xtlo 32<rt> e
    let sum =
      (narrow rs << (narrow sa .+ AST.num1 sz)) .+ narrow rt
    rd := if wide || is32Bit bld then sum else AST.sext 64<rt> sum
  }

/// LLWP and LLDP: two adjacent values read under ONE watch, which is what
/// lets a program swap a pointer and its counter together. The manual
/// describes the pair as the halves of one wider value at the base --
/// "GPR[rd] <- memory[GPR[base]]63..32, GPR[rt] <- memory[GPR[base]]31..0"
/// -- so loading it that wide and splitting it is what puts each half in
/// the right register at either endianness.
let loadLinkedPair ins bld half =
  lift bld ins {
    let rtOpr, rdOpr, memOpr = getThreeOprs ins
    let rt = transOpr ins bld rtOpr
    let rd = transOpr ins bld rdOpr
    let addr = transOprToBaseOffset bld memOpr
    let wide = if half = 32<rt> then 64<rt> else 128<rt>
    let v = tmpVar bld wide
    v := AST.loadLE wide addr
    regVar bld R.ExMonAddr := addr
    regVar bld R.ExMonVal := AST.zext bld.RegType (AST.xtlo half v)
    rd := AST.sext bld.RegType (AST.xthi half v)
    rt := AST.sext bld.RegType (AST.xtlo half v)
  }

/// SCWP and SCDP: both halves are written or neither, and rt reports
/// which. A single-threaded guest cannot make the watch fail, so the
/// store always succeeds here -- the same shape the unpaired SC has.
let storeConditionalPair ins bld half =
  lift bld ins {
    let rtOpr, rdOpr, memOpr = getThreeOprs ins
    let rt = transOpr ins bld rtOpr
    let rd = transOpr ins bld rdOpr
    let addr = transOprToBaseOffset bld memOpr
    let wide = if half = 32<rt> then 64<rt> else 128<rt>
    let ok = regVar bld R.ExMonAddr == addr
    let paired =
      AST.concat (AST.xtlo half rd) (AST.xtlo half rt)
    AST.loadLE wide addr := AST.ite ok paired (AST.loadLE wide addr)
    rt := AST.zext bld.RegType (AST.ite ok (AST.num1 1<rt>) (AST.num0 1<rt>))
  }

let loadLinked ins bld =
  lift bld ins {
    let rtOpr, memOpr = getTwoOprs ins
    let rt = transOpr ins bld rtOpr
    let mem = transOpr ins bld memOpr
    let addr = transOprToBaseOffset bld memOpr
    let sz = match memOpr with
             | OpMem(_, _, sz) -> sz
             | _ -> raise InvalidOperandException
    let v = tmpVar bld sz
    v := mem
    regVar bld R.ExMonAddr := addr
    regVar bld R.ExMonVal := AST.zext bld.RegType v
    rt := AST.sext bld.RegType v
  }

let sldc1 ins bld stORld unaligned =
  lift bld ins {
    let ft, mem = getTwoOprs ins
    let ftB, ftA = transOprToFPPair bld ft
    let baseOffset = transOprToBaseOffset bld mem
    let bOff = tmpVar bld bld.RegType
    let memory = tmpVar bld 64<rt>
    (* LUXC1 and SUXC1 clear the low three bits of the address instead of
       taking an Address Error on them, which is the whole of what separates
       them from LDC1 and SDC1. It is what lets an array of pairs be read at
       an offset that is not a multiple of eight, which is the case ALNV.PS
       exists to finish. *)
    let address =
      if unaligned then baseOffset .& numI64 -8L bld.RegType else baseOffset
    bOff := address
    let loadMem =
      loadNative bld 64<rt> bOff
    memory := loadMem
    if stORld then
      loadMem := if is32Bit bld then AST.concat ftB ftA else ftA
    else
      writeFPResult ftB ftA memory bld
  }

/// Which half of a pair a name asks for. The pair is two fields of one
/// register rather than two values in memory, so the upper half is at the
/// high end of it whichever way round the bytes go.
let private pairHalf upper value =
  if upper then AST.xthi 32<rt> value else AST.xtlo 32<rt> value

/// CVT.PS.S builds a pair out of two singles: the first source becomes the
/// upper half and the second the lower, in the order the manual names them.
let cvtpss ins bld =
  lift bld ins {
    let fd, fs, ft = getThreeOprs ins
    let fdB, fdA = transOprToFPPair bld fd
    let fs, ft = transTwoSingleFP bld (fs, ft)
    writeFPResult fdB fdA (AST.concat fs ft) bld
  }

/// CVT.S.PU and CVT.S.PL take one half of a pair back out. What comes out is
/// already a single -- the format packs two of them rather than encoding
/// either differently -- so this moves thirty-two bits and converts nothing,
/// which is why no rounding and no NaN handling belong here.
let cvtsFromPair ins bld upper =
  lift bld ins {
    let fd, fs = getTwoOprs ins
    let fd = transOprToSingleFP bld fd
    let fs = transOprToFPPairConcat bld fs
    fd := pairHalf upper fs
  }

/// The four re-pairings. Each name says which half of the first source
/// becomes the UPPER half of the result and which half of the second becomes
/// the lower, in that order: PLL takes the lower of each, PUL the upper of
/// the first and the lower of the second.
let pairHalves ins bld upperOfFs upperOfFt =
  lift bld ins {
    let fd, fs, ft = getThreeOprs ins
    let fdB, fdA = transOprToFPPair bld fd
    let fs, ft = transFPConcatTwoOprs bld (fs, ft)
    let result =
      AST.concat (pairHalf upperOfFs fs) (pairHalf upperOfFt ft)
    writeFPResult fdB fdA result bld
  }

/// ALNV.PS splices two pairs by the low three bits of a general-purpose
/// register, which is how an array of pairs is read at an offset that is not
/// a multiple of eight.
///
/// The manual gives the instruction two defined alignments: zero copies the
/// first source unchanged and four splices the two, with every other value
/// UNPREDICTABLE. Those others leave the destination alone, which is the one
/// answer that invents nothing -- a byte count that is not a multiple of four
/// asks for a shift no paired-single register can hold, and writing anything
/// at all would be a value this instruction was never told to produce.
///
/// Which half comes from which source depends on the byte order here, unlike
/// everywhere else in this format, because the two registers came out of
/// consecutive memory and it is the memory order being undone.
let alnvps ins bld =
  lift bld ins {
    let fd, fs, ft, rs = getFourOprs ins
    let fdB, fdA = transOprToFPPair bld fd
    let fs, ft = transFPConcatTwoOprs bld (fs, ft)
    let rs = transOpr ins bld rs
    let spliced =
      if bld.Endianness = Endian.Big then
        AST.concat (pairHalf false fs) (pairHalf true ft)
      else
        AST.concat (pairHalf false ft) (pairHalf true fs)
    let offset = rs .& numI32 0b111 bld.RegType
    let kept = if is32Bit bld then AST.concat fdB fdA else fdA
    let defined = AST.ite (offset == numI32 0b100 bld.RegType) spliced kept
    let result = AST.ite (offset == AST.num0 bld.RegType) fs defined
    writeFPResult fdB fdA result bld
  }

let slwc1 ins bld stORld =
  lift bld ins {
    let ft, mem = getTwoOprs ins
    let ft = transOprToSingleFP bld ft
    let mem = transOpr ins bld mem
    let ft = if is32Bit bld then ft else AST.xtlo 32<rt> ft
    if stORld then append bld { mem := ft } else append bld { ft := mem }
  }

let ext ins bld =
  lift bld ins {
    let rt, rs, pos, size = getFourOprs ins
    let rt = transOpr ins bld rt
    let rs = transOpr ins bld rs
    let pos = transOprToImm pos |> int
    let size = transOprToImm size |> int
    let msbd = size - 1
    let lsb = pos
    checkINSorExtPosSize pos size
    if lsb + msbd > 31 then raise InvalidOperandException else ()
    let rs = if pos = 0 then rs else rs >> numI32 pos bld.RegType
    let field = rs .& numI64 (getMask size) bld.RegType
    (* MD00087 EXT: temp <- sign_extend(0^(32-(msbd+1)) || GPR[rs]...),
       so the 32-bit assembled value is SIGN-extended into the register.
       Below size 32 the zero fill puts a 0 at bit 31 and the extension is
       a no-op; at size 32 the field's own bit 31 is the sign of the word
       and has to propagate. DEXT produces a 64-bit result and needs no
       such step -- which is the difference this arm lost by copying it. *)
    rt := if is32Bit bld then field else signExtLo64 field
  }

let lui ins bld =
  lift bld ins {
    let rt, imm = transTwoOprs ins bld
    if is32Bit bld then
      rt := AST.concat (AST.xtlo 16<rt> imm) (AST.num0 16<rt>)
    else
      rt := AST.sext 64<rt>
            (AST.concat (AST.xtlo 16<rt> imm) (AST.num0 16<rt>))
  }

/// <summary>
/// The paired-single form of a multiply-add.
///
/// Two single-precision multiply-adds, one per half, each normalised on its
/// own. <c>combine</c> is given the product and the addend in that order, so
/// that the four members keep the operand order each of them is written with.
/// <c>signMask</c> is the bit the negated pair flip AFTER normalising, since
/// the negation applies to the default NaN an invalid operation produces as
/// much as to a number; it is zero for the two that do not negate, which
/// makes the flip a no-op rather than a branch.
/// </summary>
let private pairedFused combine arith addendFirst signMask oprs bld =
  let fd, fr, fs, ft = oprs
  append bld {
    let fdB, fdA = transOprToFPPair bld fd
    let fr = transOprToFPPairConcat bld fr
    let fs = transOprToFPPairConcat bld fs
    let ft = transOprToFPPairConcat bld ft
    let struct (hi, lo) = tmpVars2 bld 32<rt>
    let struct (sHi, tHi, rHi, pHi) = tmpVars4 bld 32<rt>
    let struct (sLo, tLo, rLo, pLo) = tmpVars4 bld 32<rt>
    let upper = AST.xthi 32<rt>
    let lower = AST.xtlo 32<rt>
    sHi := upper fs
    tHi := upper ft
    rHi := upper fr
    sLo := lower fs
    tLo := lower ft
    rLo := lower fr
    pHi := AST.fmul sHi tHi
    pLo := AST.fmul sLo tLo
    hi := combine pHi rHi
    lo := combine pLo rLo
    normalizeNaN 32<rt> hi bld
    normalizeNaN 32<rt> lo bld
    (* Four roundings and one register: two halves, each a product and then a
       sum. Recorded before the sign is flipped, which raises nothing. *)
    let addOf p r result =
      if addendFirst then fpRaised bld 32<rt> arith r p result
      else fpRaised bld 32<rt> arith p r result
    let mulHi = fpRaised bld 32<rt> FPMul sHi tHi pHi
    let mulLo = fpRaised bld 32<rt> FPMul sLo tLo pLo
    let addHi = addOf pHi rHi hi
    let addLo = addOf pLo rLo lo
    fpRecord bld (mulHi .| mulLo .| addHi .| addLo)
    hi := numU64 signMask 32<rt> <+> hi
    lo := numU64 signMask 32<rt> <+> lo
    writeFPResult fdB fdA (AST.concat hi lo) bld
  }

/// <summary>
/// What an UNFUSED multiply-add raised, which is what its multiply raised and
/// what its add raised, together.
///
/// It rounds twice -- MD00087 spells the operation out as a product and then
/// a sum -- so an intermediate product that overflows raises the overflow
/// even where the addend would have brought the answer back. Cause holds what
/// the INSTRUCTION raised, and that is both roundings; recording them one
/// after the other would leave only the second there.
/// </summary>
let private mAddSubRecord bld oprSz opFn a b c product result =
  let rMul = fpRaised bld oprSz FPMul a b product
  let rAdd =
    if opFn then fpRaised bld oprSz FPAdd product c result
    else fpRaised bld oprSz FPSub product c result
  fpRecord bld (rMul .| rAdd)

/// The integer MADD and MSUB, which accumulate into the HI/LO pair rather
/// than into a register, and have nothing in common with the floating-point
/// forms but the name.
let private mAddSubInteger ins (bld: LowUIRBuilder) opFn =
  let rs, rt = transTwoOprs ins bld
  let op = if opFn then AST.add else AST.sub
  let result = tmpVar bld 64<rt>
  let hi = regVar bld R.HI
  let lo = regVar bld R.LO
  append bld {
    if is32Bit bld then
      result :=
        op (AST.concat hi lo) (AST.sext 64<rt> rs .* AST.sext 64<rt> rt)
      hi := AST.xthi 32<rt> result
      lo := AST.xtlo 32<rt> result
    else
      let hilo = AST.concat (AST.xtlo 32<rt> hi) (AST.xtlo 32<rt> lo)
      let rs = AST.sext 64<rt> (AST.xtlo 32<rt> rs)
      let rt = AST.sext 64<rt> (AST.xtlo 32<rt> rt)
      result := op hilo (rs .* rt)
      hi := signExtHi64 result
      lo := signExtLo64 result
  }

let mAddSub (ins: Instruction) bld opFn =
  lift bld ins {
    match ins.Fmt with
    | None ->
      mAddSubInteger ins bld opFn
    | Some Fmt.PS ->
      let combine p r = if opFn then AST.fadd p r else AST.fsub p r
      let arith = if opFn then FPAdd else FPSub
      pairedFused combine arith false 0UL (getFourOprs ins) bld
    | Some Fmt.D ->
      let op = if opFn then AST.fadd else AST.fsub
      let fd, fr, fs, ft = getFourOprs ins
      let fdB, fdA = transOprToFPPair bld fd
      let fr, fs, ft = transFPConcatThreeOprs bld (fr, fs, ft)
      let struct (a, b, c) = tmpVars3 bld 64<rt>
      let struct (product, result) = tmpVars2 bld 64<rt>
      a := fs
      b := ft
      c := fr
      product := AST.fmul a b
      result := op product c
      normalizeNaN 64<rt> result bld
      mAddSubRecord bld 64<rt> opFn a b c product result
      writeFPResult fdB fdA result bld
    | _ ->
      let op = if opFn then AST.fadd else AST.fsub
      let fd, fr, fs, ft = getFourOprs ins |> transFourSingleFP bld
      let struct (a, b, c) = tmpVars3 bld 32<rt>
      let struct (product, result) = tmpVars2 bld 32<rt>
      a := fs
      b := ft
      c := fr
      product := AST.fmul a b
      result := op product c
      normalizeNaN 32<rt> result bld
      mAddSubRecord bld 32<rt> opFn a b c product result
      fd := result
  }

let mAdduSubu ins bld opFn =
  lift bld ins {
    let rs, rt = transTwoOprs ins bld
    let result = tmpVar bld 64<rt>
    let hi = regVar bld R.HI
    let lo = regVar bld R.LO
    let op = if opFn then AST.add else AST.sub
    if is32Bit bld then
      result :=
        op (AST.concat hi lo) (AST.zext 64<rt> rs .* AST.zext 64<rt> rt)
      hi := AST.xthi 32<rt> result
      lo := AST.xtlo 32<rt> result
    else
      let hilo = AST.concat (AST.xtlo 32<rt> hi) (AST.xtlo 32<rt> lo)
      let rs = AST.zext 64<rt> (AST.xtlo 32<rt> rs)
      let rt = AST.zext 64<rt> (AST.xtlo 32<rt> rt)
      result := op hilo (rs .* rt)
      (* The write-back is SIGN-extended, exactly as MADD's and MSUB's is.
         MD00087, MADDU: "the most significant 32 bits of the result are
         sign-extended and written into HI and the least significant 32 bits
         are sign-extended and written into LO". The `u' governs the
         multiplicands -- which is why rs and rt above are zero-extended --
         and not the halves of the product. MULTU two functions away already
         gets this right; this arm was written separately and zero-extended
         both halves. *)
      hi := signExtHi64 result
      lo := signExtLo64 result
  }

let mfhi ins bld =
  lift bld ins {
    let rd = transOneOpr ins bld
    rd := regVar bld R.HI
  }

let mflo ins bld =
  lift bld ins {
    let rd = transOneOpr ins bld
    rd := regVar bld R.LO
  }

let mfhc1 ins bld =
  lift bld ins {
    let rt, fs = getTwoOprs ins
    let rt = transOpr ins bld rt
    let fsB, _ = transOprToFPPair bld fs
    rt := AST.sext bld.RegType fsB
  }

let mthc1 ins bld =
  lift bld ins {
    let rt, fs = getTwoOprs ins
    let rt = transOpr ins bld rt
    let fsB, _ = transOprToFPPair bld fs
    fsB := AST.xtlo 32<rt> rt
  }

let mthi ins bld =
  lift bld ins {
    let rs = transOneOpr ins bld
    let hi = regVar bld R.HI
    hi := rs
  }

let mtlo ins bld =
  lift bld ins {
    let rs = transOneOpr ins bld
    let lo = regVar bld R.LO
    lo := rs
  }

let mfc1 ins bld =
  lift bld ins {
    let rt, fs = getTwoOprs ins
    let rt = transOpr ins bld rt
    let fs = transOprToSingleFP bld fs
    rt := AST.sext bld.RegType fs
  }

let mov ins bld =
  lift bld ins {
    let fd, fs = getTwoOprs ins
    match ins.Fmt with
    | Some Fmt.S ->
      let fd, fs = transTwoSingleFP bld (fd, fs)
      fd := fs
    (* A pair is copied whole: both halves move and neither is read as a
       number, so the width is all this needs to know. *)
    | Some Fmt.D | Some Fmt.PS ->
      let fdB, fdA = transOprToFPPair bld fd
      let fs = transOprToFPPairConcat bld fs
      let result = tmpVar bld 64<rt>
      result := fs
      writeFPResult fdB fdA result bld
    | _ ->
      raise InvalidOperandException
  }

/// <summary>
/// The paired-single form of a move on a condition the floating-point unit
/// last tested.
///
/// Each half moves on a condition code of its OWN: the upper on cc + 1 and
/// the lower on cc, which is the pair of codes C.cond.PS writes. Moving both
/// on one code is the same instruction only where the two happen to agree.
/// </summary>
let private pairedMoveOnCC negate cc (dst, src) bld =
  append bld {
    let dstB, dstA = transOprToFPPair bld dst
    let dstVal = transOprToFPPairConcat bld dst
    let srcVal = transOprToFPPairConcat bld src
    let lower = fpConditionCode cc bld
    let upper = fpConditionCode (cc + 1) bld
    let lower = if negate then AST.not lower else lower
    let upper = if negate then AST.not upper else upper
    let struct (hi, lo) = tmpVars2 bld 32<rt>
    hi := AST.ite upper (AST.xthi 32<rt> srcVal) (AST.xthi 32<rt> dstVal)
    lo := AST.ite lower (AST.xtlo 32<rt> srcVal) (AST.xtlo 32<rt> dstVal)
    writeFPResult dstB dstA (AST.concat hi lo) bld
  }

let movt ins bld =
  lift bld ins {
    let dst, src, cc = getThreeOprs ins
    let cc = transOprToImmToInt cc
    let cond = fpConditionCode cc bld
    match ins.Fmt with
    | Some Fmt.S ->
      let dst, src = transTwoSingleFP bld (dst, src)
      dst := AST.ite cond src dst
    | Some Fmt.D when is32Bit bld ->
      let dstB, dstA = transOprToFPPair bld dst
      let srcB, srcA = transOprToFPPair bld src
      dstB := AST.ite cond srcB dstB
      dstA := AST.ite cond srcA dstA
    | Some Fmt.PS ->
      pairedMoveOnCC false cc (dst, src) bld
    | _ ->
      let dst, src = transOpr ins bld dst, transOpr ins bld src
      dst := AST.ite cond src dst
  }

let movf ins bld =
  lift bld ins {
    let dst, src, cc = getThreeOprs ins
    let cc = transOprToImmToInt cc
    let cond = AST.not (fpConditionCode cc bld)
    match ins.Fmt with
    | Some Fmt.S ->
      let dst, src = transTwoSingleFP bld (dst, src)
      dst := AST.ite cond src dst
    | Some Fmt.D when is32Bit bld ->
      let dstB, dstA = transOprToFPPair bld dst
      let srcB, srcA = transOprToFPPair bld src
      dstB := AST.ite cond srcB dstB
      dstA := AST.ite cond srcA dstA
    | Some Fmt.PS ->
      pairedMoveOnCC true cc (dst, src) bld
    | _ ->
      let dst, src = transOpr ins bld dst, transOpr ins bld src
      dst := AST.ite cond src dst
  }

let movzOrn ins bld opFn =
  lift bld ins {
    let dst, src, compare = getThreeOprs ins
    let compare = transOpr ins bld compare
    let cond = opFn compare (AST.num0 bld.RegType)
    match ins.Fmt with
    | Some Fmt.S ->
      let dst, src = transTwoSingleFP bld (dst, src)
      dst := AST.ite cond src dst
    | Some Fmt.D when is32Bit bld ->
      let dstB, dstA = transOprToFPPair bld dst
      let src = transOprToFPPairConcat bld src
      dstB := AST.ite cond (AST.xthi 32<rt> src) dstB
      dstA := AST.ite cond (AST.xtlo 32<rt> src) dstA
    | _ ->
      let dst, src = transOpr ins bld dst, transOpr ins bld src
      dst := AST.ite cond src dst
  }

let mtc1 ins bld =
  lift bld ins {
    let rt, fs = getTwoOprs ins
    let rt = transOpr ins bld rt
    let fs = transOprToSingleFP bld fs
    fs := AST.xtlo 32<rt> rt
  }

let mul ins bld =
  lift bld ins {
    let dst, src1, src2 = getThreeOprs ins
    match ins.Fmt with
    | None ->
      let dst = transOpr ins bld dst
      let src1 = transOpr ins bld src1
      let src2 = transOpr ins bld src2
      let hi = regVar bld R.HI
      let lo = regVar bld R.LO
      let result =
        if is32Bit bld then
          (AST.sext 64<rt> src1 .* AST.sext 64<rt> src2) |> AST.xtlo 32<rt>
        else
          signExtLo64 (src1 .* src2)
      dst := result
      hi := AST.undef bld.RegType "UNPREDICTABLE"
      lo := AST.undef bld.RegType "UNPREDICTABLE"
    | Some Fmt.S ->
      let dst, fs, ft = transThreeSingleFP bld (dst, src1, src2)
      let struct (tSrc1, tSrc2, result) = tmpVars3 bld 32<rt>
      reDupSrc src1 src2 fs ft tSrc1 tSrc2 bld
      result := AST.fmul tSrc1 tSrc2
      normalizeNaN 32<rt> result bld
      fpExceptions bld 32<rt> FPMul tSrc1 tSrc2 result
      dst := result
    | Some Fmt.D ->
      let dstB, dstA = transOprToFPPair bld dst
      let fs, ft = transFPConcatTwoOprs bld (src1, src2)
      let struct (tSrc1, tSrc2, result) = tmpVars3 bld 64<rt>
      reDupSrc src1 src2 fs ft tSrc1 tSrc2 bld
      result := AST.fmul tSrc1 tSrc2
      normalizeNaN 64<rt> result bld
      fpExceptions bld 64<rt> FPMul tSrc1 tSrc2 result
      writeFPResult dstB dstA result bld
    | Some Fmt.PS ->
      pairedArith AST.fmul FPMul (dst, src1, src2) bld
    | _ ->
      raise InvalidOperandException
  }

let mult ins bld =
  lift bld ins {
    let rs, rt = transTwoOprs ins bld
    let hi = regVar bld R.HI
    let lo = regVar bld R.LO
    let result = tmpVar bld 64<rt>
    let struct (low, high) =
      if is32Bit bld then
        append bld {
          result := AST.sext 64<rt> rs .* AST.sext 64<rt> rt
        }
        result |> AST.xtlo 32<rt>, result |> AST.xthi 32<rt>
      else
        append bld {
          result := signExtLo64 rs .* signExtLo64 rt
        }
        signExtLo64 result, signExtHi64 result
    lo := low
    hi := high
  }

let multu ins bld =
  lift bld ins {
    let rs, rt = getTwoOprs ins
    let src1, src2 = transOpr ins bld rs, transOpr ins bld rt
    let struct (tRs, tRt) = tmpVars2 bld bld.RegType
    let hi = regVar bld R.HI
    let lo = regVar bld R.LO
    let mask = numI64 0xFFFFFFFFL 64<rt>
    let result = tmpVar bld 64<rt>
    reDupSrc rs rt src1 src2 tRs tRt bld
    let struct (low, high) =
      if is32Bit bld then
        append bld {
          result := AST.zext 64<rt> tRs .* AST.zext 64<rt> tRt
        }
        result |> AST.xtlo 32<rt>, result |> AST.xthi 32<rt>
      else
        append bld {
          result := (tRs .& mask) .* (tRt .& mask)
        }
        signExtLo64 result, signExtHi64 result
    lo := low
    hi := high
  }

let neg ins bld =
  lift bld ins {
    let fd, fs = getTwoOprs ins
    let is32Bit = is32Bit bld
    match ins.Fmt with
    | Some Fmt.D when is32Bit ->
      let fdB, fdA = transOprToFPPair bld fd
      let fsB, fsA = transOprToFPPair bld fs
      let mask = numU64 0x8000000000000000UL 64<rt>
      let res = (AST.concat fsB fsA) <+> mask
      writeFPResult fdB fdA res bld
    | Some Fmt.PS when is32Bit ->
      let fdB, fdA = transOprToFPPair bld fd
      let fsB, fsA = transOprToFPPair bld fs
      let mask = numU64 0x80000000UL 32<rt>
      let resA = fsA <+> mask
      let resB = fsB <+> mask
      writeFPResult fdB fdA (AST.concat resB resA) bld
    | Some Fmt.PS ->
      let fd, fs = transOpr ins bld fd, transOpr ins bld fs
      let mask = numU64 0x80000000UL 32<rt>
      let resA = (AST.xtlo 32<rt> fs) <+> mask
      let resB = (AST.xthi 32<rt> fs) <+> mask
      fd := AST.concat resB resA
    | Some Fmt.S ->
      let fd, fs = transTwoSingleFP bld (fd, fs)
      fd := fs <+> numU64 0x80000000UL 32<rt>
    | _ ->
      let fd, fs = transOpr ins bld fd, transOpr ins bld fs
      let mask =
        if bld.RegType = 32<rt> then numU64 0x80000000UL bld.RegType
        else numU64 0x8000000000000000UL bld.RegType
      fd := fs <+> mask
  }

/// The same two roundings as MADD's, at the operand order the negated forms
/// use: NMADD adds the addend to the product and NMSUB takes the addend off
/// it, and a subtraction is not commutative.
let private nmAddSubRecord bld oprSz add a b c product result =
  let rMul = fpRaised bld oprSz FPMul a b product
  let rAdd =
    if add then fpRaised bld oprSz FPAdd c product result
    else fpRaised bld oprSz FPSub product c result
  fpRecord bld (rMul .| rAdd)

let private negatedMultiplyAdd add ins bld =
  lift bld ins {
    let fd, src1, src2, src3 = getFourOprs ins
    match ins.Fmt with
    | Some Fmt.S ->
      let dst, fr, fs, ft = transFourSingleFP bld (fd, src1, src2, src3)
      let struct (tSrc1, tSrc2, tSrc3, result) = tmpVars4 bld 32<rt>
      reDupSrc3 src1 src2 src3 fr fs ft tSrc1 tSrc2 tSrc3 bld
      let product = tmpVar bld 32<rt>
      product := AST.fmul tSrc2 tSrc3
      let sum =
        if add then AST.fadd tSrc1 product else AST.fsub product tSrc1
      (* The negation is of the RESULT, so it applies to the default NaN an
         invalid operation produces as much as to a number: normalise first,
         then flip the sign, or the canonicalisation undoes the negation. *)
      result := sum
      normalizeNaN 32<rt> result bld
      (* Recorded before the negation: flipping a sign raises nothing, and the
         value the add produced is what the two roundings are asked about. *)
      nmAddSubRecord bld 32<rt> add tSrc2 tSrc3 tSrc1 product result
      result := numU64 0x80000000UL 32<rt> <+> result
      dst := result
    | Some Fmt.D ->
      let fdB, fdA = transOprToFPPair bld fd
      let fr, fs, ft = transFPConcatThreeOprs bld (src1, src2, src3)
      let struct (tSrc1, tSrc2, tSrc3, result) = tmpVars4 bld 64<rt>
      reDupSrc3 src1 src2 src3 fr fs ft tSrc1 tSrc2 tSrc3 bld
      let product = tmpVar bld 64<rt>
      product := AST.fmul tSrc2 tSrc3
      let sum =
        if add then AST.fadd tSrc1 product else AST.fsub product tSrc1
      result := sum
      normalizeNaN 64<rt> result bld
      nmAddSubRecord bld 64<rt> add tSrc2 tSrc3 tSrc1 product result
      result := numU64 0x8000000000000000UL 64<rt> <+> result
      writeFPResult fdB fdA result bld
    | Some Fmt.PS ->
      let combine p r = if add then AST.fadd r p else AST.fsub p r
      let arith = if add then FPAdd else FPSub
      pairedFused combine arith add 0x80000000UL (fd, src1, src2, src3) bld
    | _ ->
      raise InvalidOperandException
  }

/// NMADD.fmt: the negation of the operand plus the product.
let nmadd ins bld = negatedMultiplyAdd true ins bld

/// NMSUB.fmt: the negation of the product less the operand.
let nmsub ins bld = negatedMultiplyAdd false ins bld

/// The CP0 register a decoded (rd, sel) pair names, where it is one this
/// front end models. A CP0 register is named by the PAIR rather than by a
/// number, which is why these instructions carry two written values and not
/// one.
let private cp0Of rdOpr selOpr =
  match rdOpr, selOpr with
  | OpImm rd, OpImm sel -> CP0.tryOfRdSel (int rd) (int sel)
  | _ -> raise InvalidOperandException

/// <summary>
/// How wide a coprocessor 0 register is, which is NOT how wide the machine
/// is.
///
/// It is the architecture's width and not the word size's: a processor with
/// the extended physical addressing holds more page frame number in EntryLo
/// than a thirty-two bit move reaches, which is the whole reason MFHC0 and
/// MTHC0 exist. Holding the register at the machine width leaves that half
/// nowhere to live, and the two moves then read and write nothing.
/// </summary>
let [<Literal>] private CP0Size = 64<rt>

/// One half of a CP0 register as a general register sees it: the machine's
/// width, sign-extended into it where the machine is the wider of the two.
let private cp0Half (bld: LowUIRBuilder) upper e =
  let half = if upper then AST.xthi 32<rt> e else AST.xtlo 32<rt> e
  if bld.RegType = 32<rt> then half else AST.sext 64<rt> half

/// <summary>
/// Which bits a write to this register changes.
///
/// A constant for all but one of them. EntryLo is the exception, and on a
/// processor with the extended physical addressing it is not a constant at
/// all: PageGrain carries the bit that switches the feature on, and until it
/// is set the top of the register is not there to be written and the two
/// inhibit bits at the top of the low half are not either.
/// </summary>
let private cp0WriteMask (bld: ILowUIRBuilder) reg =
  let wordSize = bld.ISA.WordSize
  let fixedMask = numU64 (CP0.writeMask wordSize reg) CP0Size
  match reg with
  | CP0Register.EntryLo0 | CP0Register.EntryLo1
        when wordSize = WordSize.Bit32 ->
    let grain = regVar bld CP0Register.PageGrain
    let extended =
      (grain .& numU64 CP0.ExtendedPhysical CP0Size) != AST.num0 CP0Size
    AST.ite extended (numU64 CP0.ExtendedEntryLo CP0Size) fixedMask
  | _ ->
    fixedMask

/// <summary>
/// MFC0, DMFC0 and MFHC0: a CP0 register, or one half of one, into a general
/// register.
///
/// A register this front end does not model reads as zero. That is Release
/// 6's rule -- "Reading a reserved register or a register that is not
/// implemented for the current core configuration returns 0" -- and it is
/// applied on every release, because the earlier ones call the same case
/// UNDEFINED and an undefined answer tells a caller nothing.
/// </summary>
let moveFromCP0 ins bld wide upper =
  lift bld ins {
    let rtOpr, rdOpr, selOpr = getThreeOprs ins
    let rt = transOpr ins bld rtOpr
    match cp0Of rdOpr selOpr with
    | ValueSome reg ->
      let src = regVar bld reg
      let read =
        if not wide then cp0Half bld upper src
        elif CP0.isWord reg then AST.sext CP0Size (AST.xtlo 32<rt> src)
        else src
      (* DMFC0 is a Reserved Instruction where the machine is thirty-two bits
         wide, so nothing reaches here; what it would carry if it did is the
         low half, which is what MFC0 carries. *)
      rt := if wide && is32Bit bld then AST.xtlo 32<rt> read else read
    | ValueNone ->
      rt := AST.num0 bld.RegType
  }

/// <summary>
/// MTC0, DMTC0 and MTHC0: a general register into a CP0 register, or into one
/// half of one.
///
/// The write goes through the register's write mask rather than straight in,
/// because hardware keeps the read-only and reserved fields at their old
/// value -- BadVAddr and PRId are written by nothing at all -- and a
/// write-then-read has to see the same masking. A register this front end
/// does not model is not written: Release 6 says "Writes to a register that
/// is reserved or not defined for the current core configuration are
/// ignored".
/// </summary>
let moveToCP0 ins bld wide upper =
  lift bld ins {
    let rtOpr, rdOpr, selOpr = getThreeOprs ins
    let rt = transOpr ins bld rtOpr
    match cp0Of rdOpr selOpr with
    | ValueSome reg ->
      let dst = regVar bld reg
      let low = numU64 0xFFFFFFFFUL CP0Size
      let all = numU64 0xFFFFFFFFFFFFFFFFUL CP0Size
      let src = if is32Bit bld then AST.zext CP0Size rt else rt
      (* The narrow move carries thirty-two bits and writes the whole
         register with them, widened the way the machine widens a word: by
         its sign where the machine is wider than the move, and by zero where
         it is not and the register is. Both were measured -- the first is
         what a 5KEf leaves in EPC, the second what a P5600 leaves above
         EntryLo. So a write of a page frame number clears the four bits the
         extended physical addressing put above it, and a kernel that means
         to keep them writes MTHC0 after MTC0 and not before. *)
      let narrow =
        if is32Bit bld then src else AST.sext CP0Size (AST.xtlo 32<rt> src)
      let high = (src .& low) << numI32 32 CP0Size
      (* MTHC0 is the one that reaches a half and only a half, on top of the
         register's own mask. *)
      let struct (value, reach) =
        if wide then struct (src, all)
        elif upper then struct (high, AST.not low)
        else struct (narrow, all)
      let mask = cp0WriteMask bld reg .& reach
      dst := (dst .& AST.not mask) .| (value .& mask)
    | ValueNone ->
      ()
  }

/// <summary>
/// RDPGPR and WRPGPR move between the current general registers and the
/// PREVIOUS shadow set.
///
/// With one shadow set -- which is what a core without the feature has, and
/// what SRSCtl reads out of reset -- the previous set IS the current one, so
/// both are a move between two general registers. A second register file
/// would be state no other instruction in the architecture can reach.
/// </summary>
let movePrevGPR ins bld =
  lift bld ins {
    let rd, rt = transTwoOprs ins bld
    rd := rt
  }

/// <summary>
/// DI and EI hand back what Status held and then clear or set its interrupt
/// enable, which is bit 0.
///
/// The old value is latched before the change, because entering a critical
/// section is written as DI into the register the caller will later restore
/// from -- so the two must not be the same read.
/// </summary>
let interruptEnable ins bld enable =
  lift bld ins {
    let rt = transOneOpr ins bld
    let status = regVar bld CP0Register.Status
    let bit = AST.num1 CP0Size
    let old = tmpVar bld CP0Size
    old := status
    rt := if is32Bit bld then AST.xtlo 32<rt> old else old
    status := if enable then old .| bit else old .& AST.not bit
  }

/// <summary>
/// DVP and EVP do to VPControl's DIS bit what DI and EI do to Status, and
/// hand back what it held in the same way.
///
/// Disabling a virtual processor stops the OTHER processors of a core, so
/// what the bit means on a machine with one of them is nothing; what the
/// instruction reads back still has to be what it wrote.
/// </summary>
let virtualProcessorEnable ins bld enable =
  lift bld ins {
    let rt = transOneOpr ins bld
    let control = regVar bld CP0Register.VPControl
    let bit = AST.num1 CP0Size
    let old = tmpVar bld CP0Size
    old := control
    rt := if is32Bit bld then AST.xtlo 32<rt> old else old
    control := if enable then old .& AST.not bit else old .| bit
  }

/// The four registers a TLB entry is written from and read into.
let private tlbRegisters bld =
  let hi = regVar bld CP0Register.EntryHi
  let lo0 = regVar bld CP0Register.EntryLo0
  let lo1 = regVar bld CP0Register.EntryLo1
  hi, lo0, lo1, regVar bld CP0Register.PageMask

/// One field of one entry, as a variable.
let private tlbSlot bld index field = regVar bld (CP0.tlbReg index field)

/// <summary>
/// Which entry Index names.
///
/// Only the field at the bottom of the register, and not the register: bit 31
/// is the P bit a failed probe sets, and it stays set until something clears
/// it. Reading the whole register would make every instruction after one
/// failed probe name no entry at all.
/// </summary>
let private tlbIndex (bld: ILowUIRBuilder) =
  let count = CP0.entryCount bld.ISA.WordSize
  regVar bld CP0Register.Index .& numI32 (count - 1) CP0Size

/// How many entries this processor's TLB has, which Config1 publishes and a
/// TLB instruction indexes by.
let private tlbCount (bld: ILowUIRBuilder) = CP0.entryCount bld.ISA.WordSize

/// <summary>
/// TLBWI writes the entry Index names from the four registers that describe
/// one.
///
/// What it stores is not what the registers hold. An entry keeps the virtual
/// page number with the bits its own size covers cleared, and it keeps ONE
/// global bit for the pair -- the two halves are global together or not at
/// all -- so a read of the entry afterwards answers something else than was
/// written, and has to.
///
/// There is no branch here. Every entry is assigned on every write, taking
/// its own old value wherever Index does not name it, which is the same
/// state as writing only the one and is straight-line code rather than
/// thirty-two jumps.
/// </summary>
let private tlbStore (bld: ILowUIRBuilder) index =
  let sz = CP0Size
  let hi, lo0, lo1, mask = tlbRegisters bld
  let pageBits = mask .| numU64 0x1FFFUL sz
  let storedHi = (hi .& AST.not pageBits) .| (hi .& numU64 0xFFUL sz)
  let shared = lo0 .& lo1 .& AST.num1 sz
  let storedLo0 = (lo0 .& AST.not (AST.num1 sz)) .| shared
  let storedLo1 = (lo1 .& AST.not (AST.num1 sz)) .| shared
  append bld {
    for i in 0 .. tlbCount bld - 1 do
      let chosen = index == numI32 i sz
      let keep field source =
        tlbSlot bld i field := AST.ite chosen source (tlbSlot bld i field)
      keep CP0.TLBField.Hi storedHi
      keep CP0.TLBField.Lo0 storedLo0
      keep CP0.TLBField.Lo1 storedLo1
      keep CP0.TLBField.Mask mask
  }

let tlbWriteIndexed ins bld =
  lift bld ins {
    tlbStore bld (tlbIndex bld)
  }

/// <summary>
/// TLBWR writes the entry RANDOM names, which is the same write TLBWI makes
/// at an index the program did not choose.
///
/// That is the whole of the difference, and it is what a refill handler
/// wants: it has an entry to install and no reason to care which slot takes
/// it. The architecture keeps Random between Wired -- below which a kernel's
/// own permanent entries live and a random replacement must not reach -- and
/// the last entry, and decrements it as the processor runs.
///
/// The RATE is the one thing a lifter cannot have, having no clock. What it
/// can have is the range and the direction, so the register is stepped here,
/// by the instruction that reads it, wrapping back to the top when it reaches
/// Wired. Software is forbidden from depending on any particular sequence, so
/// this one is as conforming as a clock's; what it buys over leaving the
/// register alone is that consecutive writes land in different entries, which
/// is the property the instruction exists for.
/// </summary>
let tlbWriteRandom ins bld =
  lift bld ins {
    let sz = CP0Size
    let last = numI32 (tlbCount bld - 1) sz
    let random = regVar bld CP0Register.Random
    let wired = regVar bld CP0Register.Wired .& last
    let index = tmpVar bld sz
    (* Kept inside the range rather than trusted to be in it: Wired is a
       register a program writes, and one written above where Random already
       stands would otherwise name an entry the replacement must not touch. *)
    index := AST.ite (random .< wired) last (random .& last)
    tlbStore bld index
    random := AST.ite (index == wired) last (index .- AST.num1 sz)
  }

/// The bit an invalidated entry carries. EntryHi names it EHINV, and a
/// processor that has the invalidate instructions exposes it there; here it
/// lives in the entry alone, which is the only place the instructions below
/// need it.
let private tlbInvalidBit sz = numU64 0x400UL sz

/// <summary>
/// TLBINV and TLBINVF mark entries invalid without writing one.
///
/// A kernel that has just torn down an address space has to stop its
/// translations being found, and doing that one entry at a time is thirty-two
/// writes it has no values for. TLBINVF invalidates every entry; TLBINV
/// invalidates the ones whose address space id matches EntryHi's, leaving the
/// global ones -- which belong to every address space and are the kernel's
/// own -- alone.
///
/// What they change is the entry, not the registers that describe one, and a
/// probe afterwards must not find what they marked. An entry written by TLBWI
/// or TLBWR comes back valid, because the bit is below the page size and the
/// address space id that a write keeps.
/// </summary>
let tlbInvalidate ins bld byASID =
  lift bld ins {
    let sz = CP0Size
    let target = regVar bld CP0Register.EntryHi
    let asid = numU64 0xFFUL sz
    for i in 0 .. tlbCount bld - 1 do
      let entry = tlbSlot bld i CP0.TLBField.Hi
      if byASID then
        let global0 = tlbSlot bld i CP0.TLBField.Lo0 .& AST.num1 sz
        let global1 = tlbSlot bld i CP0.TLBField.Lo1 .& AST.num1 sz
        let sameASID = ((entry <+> target) .& asid) == AST.num0 sz
        let hit = sameASID .& ((global0 .& global1) != AST.num1 sz)
        entry := AST.ite hit (entry .| tlbInvalidBit sz) entry
      else
        entry := entry .| tlbInvalidBit sz
  }

/// <summary>
/// TLBR reads the entry Index names into those same four registers.
///
/// What is read is what TLBWI wrote, so the pair round-trips: a case can
/// write an entry and read it back without any address ever being
/// translated, which is what makes these two comparable against a processor
/// while the translation they exist for is not modelled.
/// </summary>
let tlbRead ins bld =
  lift bld ins {
    let sz = CP0Size
    let index = tlbIndex bld
    let hi, lo0, lo1, mask = tlbRegisters bld
    let pick field =
      List.fold (fun acc i ->
        AST.ite (index == numI32 i sz) (tlbSlot bld i field) acc)
        (tlbSlot bld 0 field) [ 1 .. tlbCount bld - 1 ]
    hi := pick CP0.TLBField.Hi
    lo0 := pick CP0.TLBField.Lo0
    lo1 := pick CP0.TLBField.Lo1
    mask := pick CP0.TLBField.Mask
  }

/// <summary>
/// TLBP searches for the entry EntryHi names and writes where it found it
/// into Index, or sets Index's top bit where it found none.
///
/// An entry matches on the virtual page number above the size its own
/// PageMask gives it, and on the address space id -- unless both halves of
/// the entry are global, which is what the G bit of each EntryLo says and is
/// how a kernel maps a page into every address space at once.
///
/// Where more than one entry matches, a processor is allowed to do anything
/// at all; this answers the lowest, and a case that made two entries match
/// would be measuring the choice rather than the instruction.
/// </summary>
let tlbProbe ins bld =
  lift bld ins {
    let sz = CP0Size
    let index = regVar bld CP0Register.Index
    let target = regVar bld CP0Register.EntryHi
    let asid = numU64 0xFFUL sz
    let matches i =
      let entry = tlbSlot bld i CP0.TLBField.Hi
      let mask = tlbSlot bld i CP0.TLBField.Mask
      let global0 = tlbSlot bld i CP0.TLBField.Lo0 .& AST.num1 sz
      let global1 = tlbSlot bld i CP0.TLBField.Lo1 .& AST.num1 sz
      let pageBits = mask .| numU64 0x1FFFUL sz
      let differs = entry <+> target
      let sameVPN = (differs .& AST.not pageBits) == AST.num0 sz
      let sameASID = (differs .& asid) == AST.num0 sz
      let bothGlobal = (global0 .& global1) == AST.num1 sz
      let valid = (entry .& tlbInvalidBit sz) == AST.num0 sz
      valid .& sameVPN .& (bothGlobal .| sameASID)
    (* The P bit alone. What the other thirty-one hold after a probe that
       found nothing is UNPREDICTABLE; they are left at zero here, and nothing
       may be compared against them. Index is a thirty-two bit register, so a
       sixty-four bit read of it carries the sign of that very bit -- but that
       is the READ's to do, not the store's. *)
    let noMatch = numU64 0x80000000UL sz
    index :=
      List.fold (fun acc i -> AST.ite (matches i) (numI32 i sz) acc)
        noMatch (List.rev [ 0 .. tlbCount bld - 1 ])
  }

/// <summary>
/// ERET and ERETNC return from an exception, to ErrorEPC where Status.ERL
/// says the last one was an error and to EPC otherwise, clearing whichever of
/// the two bits said so. Neither has a delay slot.
///
/// ERETNC differs in exactly one thing: it leaves the LLbit that an LL had
/// set, where ERET clears it, which is what its name says. The bit is the
/// exclusive monitor here, and clearing it means leaving an address behind
/// that no store-conditional can match -- an all-ones one is not a word
/// address, so no aligned access reaches it.
/// </summary>
let exceptionReturn ins bld clearLL =
  lift bld ins {
    let status = regVar bld CP0Register.Status
    let erl = numI32 0b100 CP0Size
    let exl = numI32 0b010 CP0Size
    let isError = (status .& erl) != AST.num0 CP0Size
    let resume = tmpVar bld CP0Size
    let target = tmpVar bld bld.RegType
    resume := AST.ite isError (regVar bld CP0Register.ErrorEPC)
                              (regVar bld CP0Register.EPC)
    target := if is32Bit bld then AST.xtlo 32<rt> resume else resume
    status := AST.ite isError (status .& AST.not erl) (status .& AST.not exl)
    let monitor = regVar bld R.ExMonAddr
    monitor := if clearLL then numI64 -1L bld.RegType else monitor
    AST.interjmp target InterJmpKind.Base
  }

/// DERET returns from a debug exception to the address DEPC holds, and has no
/// delay slot either. The debug-mode bit it also clears is not modelled:
/// nothing here can enter debug mode, so there is no state for it to leave.
let debugReturn ins bld =
  lift bld ins {
    let depc = regVar bld CP0Register.DEPC
    let target = tmpVar bld bld.RegType
    target := if is32Bit bld then AST.xtlo 32<rt> depc else depc
    AST.interjmp target InterJmpKind.Base
  }

let nop (ins: Instruction) bld =
  lift bld ins {
  }

let nor ins bld =
  lift bld ins {
    let rd, rs, rt = transThreeOprs ins bld
    rd := AST.not (rs .| rt)
  }

let logOr ins bld =
  lift bld ins {
    let rd, rs, rt = transThreeOprs ins bld
    rd := rs .| rt
  }

let ori ins bld =
  lift bld ins {
    let rt, rs, imm = transThreeOprs ins bld
    rt := rs .| imm
  }

let rotr ins bld =
  lift bld ins {
    let rd, rt, sa = getThreeOprs ins
    let rd, rt = transOpr ins bld rd, transOpr ins bld rt
    let sa = numU64 (transOprToImm sa) 32<rt>
    let size = numI32 32 32<rt>
    if is32Bit bld then
      rd := (rt << (size .- sa)) .| (rt >> sa)
    else
      rd := ((AST.xtlo 32<rt> rt << (size .- sa)) .|
            (AST.xtlo 32<rt> rt >> sa)) |> AST.sext 64<rt>
  }

let rotrv ins bld =
  lift bld ins {
    let rd, rt, rs = transThreeOprs ins bld
    let sa = tmpVar bld 32<rt>
    let size = numI32 32 32<rt>
    sa := AST.xtlo 32<rt> rs .& numI32 0x1F 32<rt>
    if is32Bit bld then
      rd := (rt << (size .- sa)) .| (rt >> sa)
    else
      rd := ((AST.xtlo 32<rt> rt << (size .- sa)) .|
            (AST.xtlo 32<rt> rt >> sa)) |> AST.sext 64<rt>
  }

let store ins width bld =
  lift bld ins {
    let rt, mem = transTwoOprs ins bld
    mem := AST.xtlo width rt
  }

let sqrt ins bld =
  lift bld ins {
    let fd, fs = getTwoOprs ins
    match ins.Fmt with
    | Some Fmt.S ->
      let fd, fs = transTwoSingleFP bld (fd, fs)
      let cond = fs == numU32 0x80000000u 32<rt>
      let result = tmpVar bld 32<rt>
      result := AST.ite cond (numU32 0x80000000u 32<rt>) (AST.fsqrt fs)
      normalizeNaN 32<rt> result bld
      fpExceptions bld 32<rt> FPSqrt fs fs result
      fd := result
    | _ ->
      let fdB, fdA = transOprToFPPair bld fd
      let struct (src, result) = tmpVars2 bld 64<rt>
      src := transOprToFPPairConcat bld fs
      let cond = src == numU64 0x8000000000000000UL 64<rt>
      result :=
        AST.ite cond (numU64 0x8000000000000000UL 64<rt>) (AST.fsqrt src)
      normalizeNaN 64<rt> result bld
      fpExceptions bld 64<rt> FPSqrt src src result
      writeFPResult fdB fdA result bld
  }

let storeConditional ins width bld =
  lift bld ins {
    let rtOpr, memOpr = getTwoOprs ins
    let rt = transOpr ins bld rtOpr
    let mem = transOpr ins bld memOpr
    let addr = transOprToBaseOffset bld memOpr
    let cur = tmpVar bld width
    let matched = tmpVar bld 1<rt>
    cur := mem
    matched := (addr == regVar bld R.ExMonAddr)
               .& (cur == AST.xtlo width (regVar bld R.ExMonVal))
    mem := AST.ite matched (AST.xtlo width rt) cur
    rt := AST.zext bld.RegType matched
  }

let storeLeftRight ins bld memShf regShf amtOp oprSz =
  lift bld ins {
    let rt, mem = getTwoOprs ins
    let baseOffset = transOprToBaseOffset bld mem
    let rt = transOpr ins bld rt
    let rRt, baseOffset =
      if oprSz = 32<rt> then
        if is32Bit bld then rt, baseOffset else AST.xtlo 32<rt> rt, baseOffset
      else
        rt, baseOffset
    let baseOff = tmpVar bld bld.RegType
    let maskLd = if oprSz = 64<rt> then 0xFFFFFFF8 else 0xFFFFFFFC
    let struct (t1, t2, t3) = tmpVars3 bld oprSz
    let baseMask = tmpVar bld bld.RegType
    let mask = numI32 (((int oprSz) >>> 3) - 1) bld.RegType
    let mask32 = numI32 (((int oprSz) >>> 3) - 1) oprSz
    (* BigEndianCPU is keyed on the ACCESS width, not the register width.
       MD00087, LWL on MIPS64: `byte <- 0 || (vAddr1..0 xor BigEndianCPU^2)`
       -- two bits, with a literal zero above them; LDL is the one that uses
       BigEndianCPU^3. Asking the helper for bld.RegType gave 0b111 on a
       64-bit CPU, so the word forms XORed with 7. LWL and SWL survived by
       accident, since masking with 3 after XORing with 7 is the same as
       XORing with 3; LWR and SWR add the offset instead and produced shift
       amounts of 40 to 64 on a 32-bit value. `mask` below is already
       (accessBytes - 1) at register width, which is the constant wanted. *)
    let bigEndianCPU =
      if bld.Endianness = Endian.Big then mask else AST.num0 bld.RegType
    let vaddr0To2 = (baseOff .& mask) <+> bigEndianCPU
    let baseAddress =
      loadNative bld oprSz baseMask
    baseOff := baseOffset
    baseMask := baseOff .& numI32 maskLd bld.RegType
    t1 := if is32Bit bld then vaddr0To2 else AST.xtlo oprSz vaddr0To2
    t2 := (amtOp (mask32 .- t1) mask32) .* numI32 8 oprSz
    t3 := ((amtOp t1 mask32) .+ AST.num1 oprSz) .* numI32 8 oprSz
    baseAddress := shifterStore memShf regShf rRt t2 t3 baseAddress
  }

let syscall (ins: Instruction) bld =
  lift bld ins {
    AST.sideEffect SysCall
  }

let seb ins bld =
  lift bld ins {
    let rd, rt = transTwoOprs ins bld
    rd := AST.sext bld.RegType (AST.extract rt 8<rt> 0)
  }

let seh ins bld =
  lift bld ins {
    let rd, rt = transTwoOprs ins bld
    rd := AST.sext bld.RegType (AST.extract rt 16<rt> 0)
  }

let shiftLeftRight ins bld shf =
  lift bld ins {
    let rd, rt, sa = transThreeOprs ins bld
    if is32Bit bld then
      rd := shf rt sa
    else
      let struct (rt, sa) = AST.xtlo 32<rt> rt, AST.xtlo 32<rt> sa
      rd := shf rt sa |> AST.sext 64<rt>
  }

let sra ins bld =
  lift bld ins {
    let rd, rt, sa = transThreeOprs ins bld
    if is32Bit bld then
      rd := rt ?>> sa |> AST.sext 32<rt>
    else
      let struct (rt, sa) = AST.xtlo 32<rt> rt, AST.xtlo 32<rt> sa
      rd := rt ?>> sa |> AST.sext 64<rt>
  }

let srav ins bld =
  lift bld ins {
    let rd, rt, rs = transThreeOprs ins bld
    let mask = numI32 31 32<rt>
    if is32Bit bld then
      rd := rt ?>> (rs .& mask) |> AST.sext 32<rt>
    else
      let struct (rt, rs) = AST.xtlo 32<rt> rt, AST.xtlo 32<rt> rs
      rd := rt ?>> (rs .& mask) |> AST.sext 64<rt>
  }

let shiftLeftRightVar ins bld shf =
  lift bld ins {
    let rd, rt, rs = transThreeOprs ins bld
    let mask = numI32 31 32<rt>
    if is32Bit bld then
      rd := shf rt (rs .& mask)
    else
      let struct (rt, rs) = AST.xtlo 32<rt> rt, AST.xtlo 32<rt> rs
      rd := shf rt (rs .& mask) |> AST.sext 64<rt>
  }

let sltAndU ins bld amtOp =
  lift bld ins {
    let rd, rs, rt = transThreeOprs ins bld
    let cond = amtOp rs rt
    let rtVal = AST.ite cond (AST.num1 bld.RegType) (AST.num0 bld.RegType)
    rd := rtVal
  }

let sltiAndU ins bld amtOp =
  lift bld ins {
    let rt, rs, imm = transThreeOprs ins bld
    let cond = amtOp rs imm
    let rtVal = AST.ite cond (AST.num1 bld.RegType) (AST.num0 bld.RegType)
    rt := rtVal
  }

/// The paired-single form of the subtract, which carries its own treatment
/// of a result that has gone subnormal and so needs both operands kept.
let private pairedSub (dst, src1, src2) bld =
  append bld {
    let fdB, fdA = transOprToFPPair bld dst
    let fs = transOprToFPPairConcat bld src1
    let ft = transOprToFPPairConcat bld src2
    let struct (hiA, hiB, hi) = tmpVars3 bld 32<rt>
    let struct (loA, loB, lo) = tmpVars3 bld 32<rt>
    hiA := AST.xthi 32<rt> fs
    hiB := AST.xthi 32<rt> ft
    loA := AST.xtlo 32<rt> fs
    loB := AST.xtlo 32<rt> ft
    hi := AST.fsub hiA hiB
    lo := AST.fsub loA loB
    normalizeNaN 32<rt> hi bld
    normalizeNaN 32<rt> lo bld
    (* One record for the pair: see the note in pairedArith. *)
    let raisedHi = fpRaised bld 32<rt> FPSub hiA hiB hi
    let raisedLo = fpRaised bld 32<rt> FPSub loA loB lo
    fpRecord bld (raisedHi .| raisedLo)
    writeFPResult fdB fdA (AST.concat hi lo) bld
  }

/// SUB is SUBU plus a trap: a signed overflow raises Integer Overflow and
/// leaves the destination alone, rather than writing the truncated result.
/// This arm used to be a plain subtract, which is SUBU.
let private subTrapping ins bld (dst, src1, src2) =
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblEnd = label bld "End"
  let rd = transOpr ins bld dst
  let rs = transOpr ins bld src1
  let rt = transOpr ins bld src2
  let result = if is32Bit bld then rs .- rt else signExtLo64 (rs .- rt)
  let cond = checkOverflowOnSub rs rt result
  append bld {
    AST.cjmp cond (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    AST.sideEffect (Exception IntegerOverflow)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rd := result
    AST.lmark lblEnd
  }

let sub ins bld =
  lift bld ins {
    let dst, src1, src2 = getThreeOprs ins
    match ins.Fmt with
    | None ->
      subTrapping ins bld (dst, src1, src2)
    | Some Fmt.S ->
      let dst, fs, ft = transThreeSingleFP bld (dst, src1, src2)
      let struct (tSrc1, tSrc2, result) = tmpVars3 bld 32<rt>
      reDupSrc src1 src2 fs ft tSrc1 tSrc2 bld
      result := AST.fsub tSrc1 tSrc2
      normalizeNaN 32<rt> result bld
      fpExceptions bld 32<rt> FPSub tSrc1 tSrc2 result
      dst := result
    | Some Fmt.D ->
      let dstB, dstA = transOprToFPPair bld dst
      let fs, ft = transFPConcatTwoOprs bld (src1, src2)
      let struct (tSrc1, tSrc2, result) = tmpVars3 bld 64<rt>
      reDupSrc src1 src2 fs ft tSrc1 tSrc2 bld
      result := AST.fsub tSrc1 tSrc2
      normalizeNaN 64<rt> result bld
      fpExceptions bld 64<rt> FPSub tSrc1 tSrc2 result
      writeFPResult dstB dstA result bld
    | Some Fmt.PS ->
      pairedSub (dst, src1, src2) bld
    | _ ->
      raise InvalidOperandException
  }

let subu ins bld =
  lift bld ins {
    let rd, rs, rt = transThreeOprs ins bld
    let result = if is32Bit bld then rs .- rt else signExtLo64 (rs .- rt)
    rd := result
  }

/// <summary>
/// The conditional traps: each compares two values and takes a Trap exception
/// where the comparison holds, which is how a bounds check is written without
/// a branch around it.
///
/// The comparison is the only thing that separates the twelve of them, and
/// the six that take a written number differ from the six that take a second
/// register in nothing else, so all twelve share this.
///
/// The exception is a trap and not an undefined instruction. MD00087 gives it
/// a code of its own -- Tr, 13 -- which is what identifies it to a handler,
/// and that is the number carried here. The ten-bit field the encoding also
/// holds is for software to read out of the instruction word; the hardware
/// does nothing with it.
/// </summary>
let trapIf ins bld cmp =
  lift bld ins {
    let lblTrap = label bld "Trap"
    let lblEnd = label bld "End"
    let lhs, rhs = transTwoOprs ins bld
    AST.cjmp (cmp lhs rhs) (AST.jmpDest lblTrap) (AST.jmpDest lblEnd)
    AST.lmark lblTrap
    AST.sideEffect (Interrupt 13)
    AST.lmark lblEnd
  }

let private convertToWord mode ins bld =
  lift bld ins {
    let fd, fs = getTwoOprs ins
    let exponent = tmpVar bld 1<rt>
    let struct (dst, src, inf, nan) =
      match ins.Fmt with
      | Some Fmt.S ->
        let dst, src = transTwoSingleFP bld (fd, fs)
        append bld {
          exponent := getExponentFull src 32<rt>
        }
        let mantissa = tmpVar bld 32<rt>
        append bld {
          mantissa := getMantissa src 32<rt>
        }
        let inf = isInfinity 32<rt> exponent mantissa
        let nan = isNaN 32<rt> exponent mantissa
        dst, src, inf, nan
      | _ ->
        let dst = transOprToSingleFP bld fd
        let src = transOprToFPPairConcat bld fs
        let tSrc = tmpVar bld 64<rt>
        append bld {
          tSrc := src
          exponent := getExponentFull tSrc 64<rt>
        }
        let mantissa = tmpVar bld 64<rt>
        append bld {
          mantissa := getMantissa tSrc 64<rt>
        }
        let inf = isInfinity 64<rt> exponent mantissa
        let nan = isNaN 64<rt> exponent mantissa
        dst, tSrc, inf, nan
    let srcSz = if ins.Fmt = Some Fmt.S then 32<rt> else 64<rt>
    let struct (value, noInteger) =
      wordOfFP bld (roundingOf mode) src inf nan
    dst := value
    fpExceptionsToInt bld srcSz src noInteger
  }

/// TRUNC.W.fmt: the word nearest the operand towards zero.
let truncw ins bld = convertToWord RoundingMode.TowardZero ins bld

/// ROUND.W.fmt: the nearest word, ties to even.
let roundw ins bld = convertToWord RoundingMode.ToNearestEven ins bld

/// CEIL.W.fmt: the word nearest the operand towards plus infinity.
let ceilw ins bld = convertToWord RoundingMode.TowardPositive ins bld

/// FLOOR.W.fmt: the word nearest the operand towards minus infinity.
let floorw ins bld = convertToWord RoundingMode.TowardNegative ins bld

let private convertToLong mode ins bld =
  lift bld ins {
    let fd, fs = getTwoOprs ins
    let fdB, fdA = transOprToFPPair bld fd
    let eval = tmpVar bld 64<rt>
    let exponent = tmpVar bld 1<rt>
    let srcSz = if ins.Fmt = Some Fmt.S then 32<rt> else 64<rt>
    let struct (src, inf, nan) =
      match ins.Fmt with
      | Some Fmt.S ->
        let src = transOprToSingleFP bld fs
        append bld {
          exponent := getExponentFull src 32<rt>
        }
        let mantissa = tmpVar bld 32<rt>
        append bld {
          mantissa := getMantissa src 32<rt>
        }
        let inf = isInfinity 32<rt> exponent mantissa
        let nan = isNaN 32<rt> exponent mantissa
        src, inf, nan
      | _ ->
        let src = transOprToFPPairConcat bld fs
        append bld {
          exponent := getExponentFull src 64<rt>
        }
        let mantissa = tmpVar bld 64<rt>
        append bld {
          mantissa := getMantissa src 64<rt>
        }
        let inf = isInfinity 64<rt> exponent mantissa
        let nan = isNaN 64<rt> exponent mantissa
        src, inf, nan
    let struct (value, noInteger) =
      longOfFP bld (roundingOf mode) srcSz src inf nan
    eval := value
    fpExceptionsToInt bld srcSz src noInteger
    writeFPResult fdB fdA eval bld
  }

/// TRUNC.L.fmt: the doubleword nearest the operand towards zero.
let truncl ins bld = convertToLong RoundingMode.TowardZero ins bld

/// ROUND.L.fmt: the nearest doubleword, ties to even.
let roundl ins bld = convertToLong RoundingMode.ToNearestEven ins bld

/// CEIL.L.fmt: the doubleword nearest the operand towards plus infinity.
let ceill ins bld = convertToLong RoundingMode.TowardPositive ins bld

/// FLOOR.L.fmt: the doubleword nearest the operand towards minus infinity.
let floorl ins bld = convertToLong RoundingMode.TowardNegative ins bld

let logXor ins bld =
  lift bld ins {
    let rd, rs, rt = transThreeOprs ins bld
    rd := rs <+> rt
  }

let wsbh ins bld =
  lift bld ins {
    let dst, src = transTwoOprs ins bld
    let rt = AST.xtlo 32<rt> src
    let elements =
      Array.init 4 (fun x -> AST.extract rt 8<rt> ((2 + x) % 4 * 8))
      |> Array.rev
    dst := AST.sext bld.RegType (AST.revConcat elements)
  }

let dsbh ins bld =
  lift bld ins {
    let dst, src = transTwoOprs ins bld
    let lo = AST.xtlo 32<rt> src
    let hi = AST.xthi 32<rt> src
    let hiResult =
      Array.init 4 (fun x -> AST.extract hi 8<rt> ((2 + x) % 4 * 8))
      |> Array.rev
    let lowResult =
      Array.init 4 (fun x -> AST.extract lo 8<rt> ((2 + x) % 4 * 8))
      |> Array.rev
    dst := AST.revConcat (Array.append lowResult hiResult)
  }

let dshd ins bld =
  lift bld ins {
    let dst, src = transTwoOprs ins bld
    let result =
      Array.init 4 (fun idx -> AST.extract src 16<rt> (idx * 16)) |> Array.rev
    dst := AST.revConcat result
  }

let xori ins bld =
  lift bld ins {
    let rt, rs, imm = transThreeOprs ins bld
    rt := rs <+> imm
  }

let loadLeftRight ins bld memShf regShf amtOp oprSz =
  lift bld ins {
    let rt, mem = getTwoOprs ins
    let baseOffset = transOprToBaseOffset bld mem
    let rt = transOpr ins bld rt
    let rRt =
      if oprSz = 32<rt> && not (is32Bit bld) then AST.xtlo 32<rt> rt else rt
    let baseOff = tmpVar bld bld.RegType
    let maskLd = if oprSz = 64<rt> then 0xFFFFFFF8 else 0xFFFFFFFC
    let struct (t1, t2, t3) = tmpVars3 bld oprSz
    let baseMask = tmpVar bld bld.RegType
    let mask = numI32 (((int oprSz) >>> 3) - 1) bld.RegType
    let mask32 = numI32 (((int oprSz) >>> 3) - 1) oprSz
    (* BigEndianCPU is keyed on the ACCESS width, not the register width.
       MD00087, LWL on MIPS64: `byte <- 0 || (vAddr1..0 xor BigEndianCPU^2)`
       -- two bits, with a literal zero above them; LDL is the one that uses
       BigEndianCPU^3. Asking the helper for bld.RegType gave 0b111 on a
       64-bit CPU, so the word forms XORed with 7. LWL and SWL survived by
       accident, since masking with 3 after XORing with 7 is the same as
       XORing with 3; LWR and SWR add the offset instead and produced shift
       amounts of 40 to 64 on a 32-bit value. `mask` below is already
       (accessBytes - 1) at register width, which is the constant wanted. *)
    let bigEndianCPU =
      if bld.Endianness = Endian.Big then mask else AST.num0 bld.RegType
    let vaddr0To2 = (baseOff .& mask) <+> bigEndianCPU
    let baseAddress =
      loadNative bld oprSz baseMask
    baseOff := baseOffset
    baseMask := baseOff .& numI32 maskLd bld.RegType
    t1 := if is32Bit bld then vaddr0To2 else AST.xtlo oprSz vaddr0To2
    t2 := ((amtOp t1 mask32) .+ AST.num1 oprSz) .* numI32 8 oprSz
    t3 := (amtOp (mask32 .- t1) mask32) .* numI32 8 oprSz
    let result = shifterLoad memShf regShf rRt t2 t3 baseAddress
    rt := if is32Bit bld then result else result |> AST.sext 64<rt>
  }

let recip ins bld =
  lift bld ins {
    let fd, fs = getTwoOprs ins
    match ins.Fmt with
    | Some Fmt.S ->
      let fd, fs = transTwoSingleFP bld (fd, fs)
      let fnum = AST.cast CastKind.SIntToFloat 32<rt> (AST.num1 32<rt>)
      fd := AST.fdiv fnum fs
    | _ ->
      let fdB, fdA = transOprToFPPair bld fd
      let fs = transOprToFPPairConcat bld fs
      let fnum = AST.cast CastKind.SIntToFloat 64<rt> (AST.num1 64<rt>)
      writeFPResult fdB fdA (AST.fdiv fnum fs) bld
  }

let rsqrt ins bld =
  lift bld ins {
    let fd, fs = getTwoOprs ins
    match ins.Fmt with
    | Some Fmt.S ->
      let fd, fs = transTwoSingleFP bld (fd, fs)
      let fnum = AST.cast CastKind.SIntToFloat 32<rt> (AST.num1 32<rt>)
      fd := AST.fdiv fnum (AST.fsqrt fs)
    | _ ->
      let fdB, fdA = transOprToFPPair bld fd
      let fs = transOprToFPPairConcat bld fs
      let fnum = AST.cast CastKind.SIntToFloat 64<rt> (AST.num1 64<rt>)
      let result = AST.fdiv fnum (AST.fsqrt fs)
      writeFPResult fdB fdA result bld
  }

/// <summary>
/// The register MIPS16e compares into, which MD00076 calls T.
///
/// A halfword has no room for a destination as well as two operands and a
/// function code, so CMP and CMPI write a register the encoding does not
/// name. It is $24, and BTEQZ and BTNEZ are the only instructions that read
/// it.
/// </summary>
let private tReg bld = regVar bld R.R24

/// <summary>
/// The address the instruction after a MIPS16e one sits at.
///
/// Not four bytes on. A MIPS16e instruction is two bytes, or four where an
/// EXTEND widens it, so the fall-through of a branch is the instruction's own
/// length away and not a constant.
/// </summary>
let private m16Next (ins: Instruction) bld =
  regVar bld R.PC .+ numI32 (int ins.Length) bld.RegType

/// <summary>
/// A MIPS16e branch, which has NO DELAY SLOT.
///
/// MD00076 3.13: "Branch instructions and the JALRC and JRC jump instructions
/// do not have a delay slot. If a branch or jump is taken, the instruction
/// immediately following the branch or jump is never executed." That is the
/// opposite of the base architecture, where every branch has one -- so the
/// same opcode cannot take the same lifter in both encodings.
/// </summary>
let private m16Branch ins bld cond target =
  append bld { AST.intercjmp cond target (m16Next ins bld) }

/// BEQZ and BNEZ, which the base architecture writes as BEQ and BNE against
/// the zero register and this encoding cannot, a three-bit field having no
/// way to name it.
let m16BranchZero ins bld cmp =
  lift bld ins {
    let rx, target = transTwoOprs ins bld
    m16Branch ins bld (cmp rx (AST.num0 bld.RegType)) target
  }

/// BTEQZ and BTNEZ, which read what CMP and CMPI left in T.
let m16BranchT ins bld cmp =
  lift bld ins {
    let target = transOneOpr ins bld
    m16Branch ins bld (cmp (tReg bld) (AST.num0 bld.RegType)) target
  }

/// CMP and CMPI, whose answer is the exclusive-or rather than a comparison:
/// what the branches then ask is whether it is zero, which is whether the two
/// were equal.
let m16Compare ins bld =
  lift bld ins {
    let a, b = transTwoOprs ins bld
    tReg bld := a <+> b
  }

/// <summary>
/// SLT, SLTU, SLTI and SLTIU, whose answer goes to T in this encoding.
///
/// MD00076 writes all four as "T ← (GPR[rx] &lt; ...)". The base architecture
/// names a destination and a halfword has no room for one, so the comparison
/// is the same instruction and where it lands is not -- which is why these
/// keep the base architecture's opcode and take a lifter arm of their own.
/// </summary>
let m16SetLessThan ins bld cmp =
  lift bld ins {
    let a, b = transTwoOprs ins bld
    tReg bld := AST.zext bld.RegType (cmp a b)
  }

/// NEG, which is the integer one this encoding has and not the
/// floating-point NEG the base architecture's lifter answers to.
let m16Neg ins bld =
  lift bld ins {
    let rx, ry = transTwoOprs ins bld
    rx := AST.num0 bld.RegType .- ry
  }

/// NOT, which the base architecture writes as NOR against the zero register.
let m16Not ins bld =
  lift bld ins {
    let rx, ry = transTwoOprs ins bld
    rx := AST.not ry
  }

/// LI and MOVE, which both put one value in one register: LI a zero-extended
/// immediate, MOVE the contents of the register the five-bit field names.
let m16Move ins bld =
  lift bld ins {
    let dst, src = transTwoOprs ins bld
    dst := src
  }

/// <summary>
/// The width conversions: ZEB, ZEH, ZEW, SEB, SEH and SEW.
///
/// Three of the six are the base architecture's own and lift through its
/// arms; these are the ones it has no instruction for. Each takes the low
/// part of a register and fills the rest, which is a cast and not a shift
/// pair.
/// </summary>
let m16Extend ins bld width signed =
  lift bld ins {
    let rx, ry = transTwoOprs ins bld
    let part = AST.extract ry width 0
    let widened =
      if signed then AST.sext bld.RegType part
      else AST.zext bld.RegType part
    rx := widened
  }

/// <summary>
/// The order SAVE and RESTORE touch the registers in, which is not the order
/// they are named in.
///
/// MD00076 writes the sequence as nested conditions and it descends: the
/// return address first, then the static registers from $30 back to $18,
/// then $17 and $16, and last the argument registers kept as static, from $7
/// back. Each takes the next word DOWN from the stack pointer, so a lifter
/// that walked the printed list -- which ascends, because that is how an
/// assembly programmer writes a set -- would put every one of them at another
/// one's address.
/// </summary>
let private svrsOrder =
  [ R.R31
    R.R30
    R.R23
    R.R22
    R.R21
    R.R20
    R.R19
    R.R18
    R.R17
    R.R16
    R.R7
    R.R6
    R.R5
    R.R4 ]

/// <summary>
/// SAVE and RESTORE.
///
/// One instruction that is a whole function prologue or epilogue: the
/// arguments stored UP from a base, the saved registers stored DOWN from it,
/// and the stack pointer then moved by the frame size.
///
/// The base is not the same one. MD00076 gives SAVE as <c>temp ← GPR[29]</c>
/// and RESTORE as <c>temp ← GPR[29] + framesize</c>, which is the same
/// address both times: the registers sit just below where the pointer was
/// before the frame was taken, and by the time RESTORE runs the pointer is a
/// frame lower. Reading them from the pointer as it stands would read a frame
/// too low, and the first thing to come back wrong is the return address --
/// so the function returns to nowhere rather than computing anything
/// incorrectly.
///
/// Every set is known when the instruction is decoded, so what comes out is a
/// straight line of loads or stores and not a loop.
/// </summary>
let private svrsPlaces args saved =
  let down =
    svrsOrder
    |> List.filter (fun r -> List.contains r saved)
    |> List.mapi (fun i r -> r, -4L * int64 (i + 1))
  let up = args |> List.mapi (fun i r -> r, 4L * int64 i)
  up, down

let private saveRestore ins bld isSave =
  lift bld ins {
    let frame, args, saved =
      match getThreeOprs ins with
      | OpImm f, OpRegList a, OpRegList s -> f, a, s
      | _ -> raise InvalidOperandException
    let sp = regVar bld R.R29
    let frameSize = numU64 frame bld.RegType
    let entry = tmpVar bld bld.RegType
    entry := if isSave then sp else sp .+ frameSize
    let word = 32<rt>
    let at off = loadNative bld word (entry .+ numI64 off bld.RegType)
    let up, down = svrsPlaces args saved
    if isSave then
      append bld {
        (* The arguments, upwards from where the pointer arrived. RESTORE
           writes none: the aregs field names them as arguments only on the
           way in. *)
        for (r, off) in up do
          at off := AST.xtlo word (regVar bld r)
        for (r, off) in down do
          at off := AST.xtlo word (regVar bld r)
      }
    else
      append bld {
        for (r, off) in down do
          regVar bld r := AST.sext bld.RegType (at off)
      }
    (* RESTORE's new pointer is the base it just read from, which is where
       the pointer stood before the frame was taken. *)
    sp := if isSave then entry .- frameSize else entry
  }

/// SAVE: the prologue.
let save ins bld = saveRestore ins bld true

/// RESTORE: the epilogue.
let restore ins bld = saveRestore ins bld false
