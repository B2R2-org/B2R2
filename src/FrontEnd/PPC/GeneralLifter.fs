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

module internal B2R2.FrontEnd.PPC.GeneralLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC
open B2R2.FrontEnd.PPC.OperandHelper
open B2R2.FrontEnd.PPC.LiftingUtils

let add ins insLen updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    t1 := src1
    t2 := src2
    dst := t1 .+ t2
    if ovCond then isAddSubOV bld t1 t2 dst else ()
    if updateCond then setCR0Reg bld dst else ()
  }

let addc ins insLen updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    t1 := src1
    t2 := src2
    addWithCarryOut bld dst t1 t2 (AST.num0 bld.RegType)
    if ovCond then isAddSubOV bld t1 t2 dst else ()
    if updateCond then setCR0Reg bld dst else ()
  }

let adde ins insLen updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    let ca = carryIn bld
    t1 := src1
    t2 := src2
    addWithCarryOut bld dst t1 t2 ca
    if ovCond then isAddSubOV bld t1 t2 dst else ()
    if updateCond then setCR0Reg bld dst else ()
  }

let addi ins insLen (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (dst, src1, simm) = transThreeOprs ins bld
    let cond = src1 == AST.num0 bld.RegType
    dst := (AST.ite cond simm (src1 .+ simm))
  }

let addic ins insLen updateCond (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (dst, src1, simm) = transThreeOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    t1 := src1
    t2 := simm
    addWithCarryOut bld dst t1 t2 (AST.num0 bld.RegType)
    if updateCond then setCR0Reg bld dst else ()
  }

/// The 16-bit immediate of an addis/lis/oris/xoris shifted into the upper half
/// of a word and sign- or zero-extended to a register, as that form's shifted
/// operand.
let shiftedImm (bld: ILowUIRBuilder) signed simm =
  let hi = AST.concat (AST.xtlo 16<rt> simm) (AST.num0 16<rt>)
  if bld.RegType = 32<rt> then hi
  elif signed then AST.sext bld.RegType hi
  else AST.zext bld.RegType hi

let addis ins insLen (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (dst, src1, simm) = transThreeOprs ins bld
    let cond = src1 == AST.num0 bld.RegType
    let simm = shiftedImm bld true simm
    dst := (AST.ite cond simm (src1 .+ simm))
  }

let addme ins insLen updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (dst, src) = transTwoOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    let ca = carryIn bld
    t1 := src
    t2 := AST.not (AST.num0 bld.RegType)
    addWithCarryOut bld dst t1 t2 ca
    if ovCond then isAddSubOV bld t1 t2 dst else ()
    if updateCond then setCR0Reg bld dst else ()
  }

let addze ins insLen updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (dst, src) = transTwoOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    let ca = carryIn bld
    t1 := src
    t2 := AST.num0 bld.RegType
    addWithCarryOut bld dst t1 t2 ca
    if ovCond then isAddSubOV bld t1 t2 dst else ()
    if updateCond then setCR0Reg bld dst else ()
  }

let andx ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    dst := src1 .& src2
    if updateCond then setCR0Reg bld dst else ()
  }

let andc ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    dst := src1 .& AST.not (src2)
    if updateCond then setCR0Reg bld dst else ()
  }

let andidot ins insLen bld =
  lift bld ins insLen {
    let struct (dst, src, uimm) = transThreeOprs ins bld
    dst := src .& uimm
    setCR0Reg bld dst
  }

let andisdot ins insLen bld =
  lift bld ins insLen {
    let struct (dst, src, uimm) = transThreeOprs ins bld
    let uimm = shiftedImm bld false uimm
    dst := src .& uimm
    setCR0Reg bld dst
  }

let b ins insLen (bld: ILowUIRBuilder) lk =
  lift bld ins insLen {
    let addr = transOneOpr ins bld
    let lr = regVar bld Register.LR
    if lk then
      lr := numU64 (ins.Address + 4UL) bld.RegType
      AST.interjmp addr InterJmpKind.IsCall
    else
      AST.interjmp addr InterJmpKind.Base
  }

let bc ins insLen (bld: ILowUIRBuilder) aa lk =
  lift bld ins insLen {
    let struct (bo, cr, addr) = transBranchThreeOprs ins bld
    let rt = bld.RegType
    let lr = regVar bld Register.LR
    let ctr = regVar bld Register.CTR
    let bo0 = numU32 ((bo >>> 4) &&& 1u) 1<rt>
    let bo1 = numU32 ((bo >>> 3) &&& 1u) 1<rt>
    let bo2 = numU32 ((bo >>> 2) &&& 1u) 1<rt>
    let bo3 = numU32 ((bo >>> 1) &&& 1u) 1<rt>
    let ctrOk = tmpVar bld 1<rt>
    let condOk = tmpVar bld 1<rt>
    let cia = numU64 ins.Address rt
    let nia = numU64 (ins.Address + 4UL) rt
    let temp = tmpVar bld rt
    if lk then append bld { lr := nia } else ()
    ctr :=
            if ((bo >>> 2) &&& 1u = 1u) then ctr else (ctr .- AST.num1 rt)
    ctrOk := bo2 .| ((ctr != AST.num0 rt) <+> bo3)
    condOk := bo0 .| (cr <+> AST.not bo1)
    if aa then append bld { temp := AST.ite (ctrOk .& condOk) addr nia }
    else append bld { temp := AST.ite (ctrOk .& condOk) (cia .+ addr) nia }
    let kind = if lk then InterJmpKind.IsCall else InterJmpKind.Base
    AST.interjmp temp kind
  }

/// The low two bits an indirect branch clears out of LR or CTR before jumping.
let private branchTargetMask (bld: ILowUIRBuilder) =
  AST.not (numI32 3 bld.RegType)

let bclr ins insLen (bld: ILowUIRBuilder) lk =
  lift bld ins insLen {
    let struct (bo, cr) = transBranchTwoOprs ins bld
    let rt = bld.RegType
    let lr = regVar bld Register.LR
    let ctr = regVar bld Register.CTR
    let bo0 = numU32 ((bo >>> 4) &&& 1u) 1<rt>
    let bo1 = numU32 ((bo >>> 3) &&& 1u) 1<rt>
    let bo2 = numU32 ((bo >>> 2) &&& 1u) 1<rt>
    let bo3 = numU32 ((bo >>> 1) &&& 1u) 1<rt>
    let ctrOk = tmpVar bld 1<rt>
    let condOk = tmpVar bld 1<rt>
    let nia = numU64 (ins.Address + 4UL) rt
    let temp = tmpVar bld rt
    ctr :=
            if ((bo >>> 2) &&& 1u = 1u) then ctr else (ctr .- AST.num1 rt)
    ctrOk := bo2 .| ((ctr != AST.num0 rt) <+> bo3)
    condOk := bo0 .| (cr <+> AST.not bo1)
    temp := AST.ite (ctrOk .& condOk) (lr .& branchTargetMask bld) nia
    if lk then append bld { lr := AST.ite (ctrOk .& condOk) nia lr } else ()
    let kind = if lk then InterJmpKind.IsCall else InterJmpKind.IsRet
    AST.interjmp temp kind
  }

let bcctr ins insLen (bld: ILowUIRBuilder) lk =
  lift bld ins insLen {
    let struct (bo, cr) = transBranchTwoOprs ins bld
    let rt = bld.RegType
    let lr = regVar bld Register.LR
    let ctr = regVar bld Register.CTR
    let bo0 = numU32 ((bo >>> 4) &&& 1u) 1<rt>
    let bo1 = numU32 ((bo >>> 3) &&& 1u) 1<rt>
    let condOk = tmpVar bld 1<rt>
    let nia = numU64 (ins.Address + 4UL) rt
    let temp = tmpVar bld rt
    condOk := bo0 .| (cr <+> AST.not bo1)
    temp := AST.ite condOk (ctr .& branchTargetMask bld) nia
    if lk then append bld { lr := AST.ite condOk nia lr } else ()
    let kind = if lk then InterJmpKind.IsCall else InterJmpKind.Base
    AST.interjmp temp kind
  }

/// Records the outcome of a comparison in a CR field. cmpOp gives the "less
/// than" and "greater than" tests, which differ between the signed and the
/// unsigned forms; equality is whatever neither of those is.
let private compare ins insLen bld ltOp gtOp narrow =
  lift bld ins insLen {
    let struct ((crf0, crf1, crf2, crf3), ra, rb) = transCmpOprs ins bld
    let ra, rb =
      if narrow then AST.xtlo 32<rt> ra, AST.xtlo 32<rt> rb else ra, rb
    let cond1 = ltOp ra rb
    let cond2 = gtOp ra rb
    let xer = regVar bld Register.XER
    crf0 := cond1
    crf1 := cond2
    crf2 := AST.ite cond1 AST.b0 (AST.not cond2)
    crf3 := AST.xthi 1<rt> xer
  }

/// A signed compare of the given width: cmpw/cmpwi narrow to a word, cmpd and
/// cmpdi take the whole register.
let cmp ins insLen bld narrow = compare ins insLen bld AST.slt AST.sgt narrow

/// An unsigned compare, narrowing as cmp does.
let cmpl ins insLen bld narrow = compare ins insLen bld AST.lt AST.gt narrow

/// Counts the leading zeroes of the low `width` bits of rs, by folding the
/// value down to a mask of the bits at or below the highest set one and then
/// counting the ones in it. The result is a register-wide count.
let private countLeadingZeros (bld: ILowUIRBuilder) ra rs width =
  append bld {
    let rt = bld.RegType
    let x = tmpVar bld width
    let n i = numI32 i width
    let mask1 = numU64 0x5555555555555555UL width
    let mask2 = numU64 0x3333333333333333UL width
    let mask3 = numU64 0x0f0f0f0f0f0f0f0fUL width
    x := AST.xtlo width rs
    x := x .| (x >> n 1)
    x := x .| (x >> n 2)
    x := x .| (x >> n 4)
    x := x .| (x >> n 8)
    x := x .| (x >> n 16)
    if width = 64<rt> then append bld { x := x .| (x >> n 32) } else ()
    x := x .- ((x >> n 1) .& mask1)
    x := ((x >> n 2) .& mask2) .+ (x .& mask2)
    x := ((x >> n 4) .+ x) .& mask3
    x := x .+ (x >> n 8)
    x := x .+ (x >> n 16)
    if width = 64<rt> then append bld { x := x .+ (x >> n 32) } else ()
    let ones = AST.zext rt (x .& n 127)
    ra := numI32 (int width) rt .- ones
  }

let cntlzw ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (ra, rs) = transTwoOprs ins bld
    countLeadingZeros bld ra rs 32<rt>
    if updateCond then setCR0Reg bld ra else ()
  }

let cntlzd ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (ra, rs) = transTwoOprs ins bld
    countLeadingZeros bld ra rs 64<rt>
    if updateCond then setCR0Reg bld ra else ()
  }

let crclr ins insLen bld =
  lift bld ins insLen {
    let crbd = transOneOpr ins bld
    crbd := AST.b0
  }

let cror ins insLen bld =
  lift bld ins insLen {
    let struct (crbD, crbA, crbB) = transThreeOprs ins bld
    crbD := crbA .| crbB
  }

let crorc ins insLen bld =
  lift bld ins insLen {
    let struct (crbD, crbA, crbB) = transThreeOprs ins bld
    crbD := crbA .| (AST.not crbB)
  }

let creqv ins insLen bld =
  lift bld ins insLen {
    let struct (crbD, crbA, crbB) = transThreeOprs ins bld
    crbD := crbA <+> AST.not (crbB)
  }

let crset ins insLen bld =
  lift bld ins insLen {
    let crbD = transOneOpr ins bld
    crbD := crbD <+> AST.not (crbD)
  }

let crnand ins insLen bld =
  lift bld ins insLen {
    let struct (crbD, crbA, crbB) = transThreeOprs ins bld
    crbD := AST.not (crbA .& crbB)
  }

let crnor ins insLen bld =
  lift bld ins insLen {
    let struct (crbD, crbA, crbB) = transThreeOprs ins bld
    crbD := AST.not (crbA .| crbB)
  }

let crnot ins insLen bld =
  lift bld ins insLen {
    let struct (crbD, crbA) = transTwoOprs ins bld
    crbD := AST.not crbA
  }

let crxor ins insLen bld =
  lift bld ins insLen {
    let struct (crbD, crbA, crbB) = transThreeOprs ins bld
    crbD := crbA <+> crbB
  }

let crand ins insLen bld =
  lift bld ins insLen {
    let struct (crbD, crbA, crbB) = transThreeOprs ins bld
    crbD := crbA .& crbB
  }

let crandc ins insLen bld =
  lift bld ins insLen {
    let struct (crbD, crbA, crbB) = transThreeOprs ins bld
    crbD := crbA .& (AST.not crbB)
  }

(* crmove crbD, crbA = cror crbD, crbA, crbA: copies one CR bit to another. *)
let crmove ins insLen bld =
  lift bld ins insLen {
    let struct (crbD, crbA) = transTwoOprs ins bld
    crbD := crbA
  }

/// A divide of the given width. A zero divisor (and the signed overflow case)
/// leaves the destination alone, as the architecture leaves it undefined.
let private divide ins
                   insLen
                   updateCond
                   ovCond
                   (bld: ILowUIRBuilder)
                   width
                   signed =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let a = AST.xtlo width src1
    let b = AST.xtlo width src2
    if ovCond && signed then isSignedDivOV bld width a b
    elif ovCond then isUnsignedDivOV bld width b
    else ()
    let q = if signed then a ?/ b else a ./ b
    let q = if signed then AST.sext bld.RegType q else AST.zext bld.RegType q
    dst := AST.ite (b == AST.num0 width) dst q
    if updateCond then setCR0Reg bld dst else ()
  }

let divw ins insLen updateCond ovCond bld =
  divide ins insLen updateCond ovCond bld 32<rt> true

let divwu ins insLen updateCond ovCond bld =
  divide ins insLen updateCond ovCond bld 32<rt> false

let divd ins insLen updateCond ovCond bld =
  divide ins insLen updateCond ovCond bld 64<rt> true

let divdu ins insLen updateCond ovCond bld =
  divide ins insLen updateCond ovCond bld 64<rt> false

/// Sign-extends the low `width` bits of rs into a whole register.
let private signExtend ins insLen updateCond (bld: ILowUIRBuilder) width =
  lift bld ins insLen {
    let struct (ra, rs) = transTwoOprs ins bld
    let tmp = tmpVar bld width
    tmp := AST.xtlo width rs
    ra := AST.sext bld.RegType tmp
    if updateCond then setCR0Reg bld ra else ()
  }

let extsb ins insLen updateCond bld = signExtend ins insLen updateCond bld 8<rt>

let extsh ins insLen updateCond bld =
  signExtend ins insLen updateCond bld 16<rt>

let extsw ins insLen updateCond bld =
  signExtend ins insLen updateCond bld 32<rt>

let eqvx ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (ra, rs, rb) = transThreeOprs ins bld
    ra := AST.not (rs <+> rb)
    if updateCond then setCR0Reg bld ra else ()
  }

let fabs ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (frd, frb) = transTwoOprs ins bld
    frd := frb .& numU64 0x7fffffffffffffffUL 64<rt>
    if updateCond then setCR1Reg bld else ()
  }

let fAddOrSub ins insLen updateCond isDouble fnOp bld =
  lift bld ins insLen {
    let struct (frd, fra, frb) = transThreeOprs ins bld
    if isDouble then
      frd := fnOp fra frb
    else
      let fra = AST.cast CastKind.FloatCast 32<rt> fra
      let frb = AST.cast CastKind.FloatCast 32<rt> frb
      frd := AST.cast CastKind.FloatCast 64<rt> (fnOp fra frb)
    setFPRF bld frd
    if updateCond then setCR1Reg bld else ()
  }

let fadd ins insLen updateCond isDouble bld =
  fAddOrSub ins insLen updateCond isDouble AST.fadd bld

let fcmp ins insLen bld isOrdered =
  lift bld ins insLen {
    let struct ((crf0, crf1, crf2, crf3), fra, frb) = transCmpOprs ins bld
    let fpscr = regVar bld Register.FPSCR
    let vxsnan = AST.extract fpscr 1<rt> 24
    let vxvc = AST.extract fpscr 1<rt> 19
    let fl = AST.extract fpscr 1<rt> 15
    let fg = AST.extract fpscr 1<rt> 14
    let fe = AST.extract fpscr 1<rt> 13
    let fu = AST.extract fpscr 1<rt> 12
    let ve = AST.extract fpscr 1<rt> 7
    let cond1 = AST.flt fra frb
    let cond2 = AST.fgt fra frb
    let cond3 = (IEEE754Double.isSNaN fra) .| (IEEE754Double.isSNaN frb)
    let cond4 = (IEEE754Double.isQNaN fra) .| (IEEE754Double.isQNaN frb)
    let nanFlag = tmpVar bld 1<rt>
    let lblNan = label bld "NaN"
    let lblRegular = label bld "Regular"
    let lblEnd = label bld "End"
    fl := cond1
    fg := cond2
    fe := AST.ite cond1 AST.b0 (AST.not cond2)
    nanFlag := (IEEE754Double.isNaN fra) .| (IEEE754Double.isNaN frb)
    fu := nanFlag
    AST.cjmp nanFlag (AST.jmpDest lblNan) (AST.jmpDest lblRegular)
    AST.lmark lblNan
    crf0 := AST.b0
    crf1 := AST.b0
    crf2 := AST.b0
    crf3 := AST.b1
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblRegular
    crf0 := fl
    crf1 := fg
    crf2 := fe
    crf3 := fu
    AST.lmark lblEnd
    vxsnan := cond3
    if isOrdered then
      vxvc := AST.ite cond3 (AST.ite ve AST.b0 AST.b1) cond4
    else
      ()
  }

let fcmpo ins insLen bld = fcmp ins insLen bld true

let fcmpu ins insLen bld = fcmp ins insLen bld false

let fdiv ins insLen updateCond isDouble bld =
  lift bld ins insLen {
    let struct (frd, fra, frb) = transThreeOprs ins bld
    let tmp = tmpVar bld 32<rt>
    if isDouble then
      frd := AST.fdiv fra frb
    else
      let fraS = AST.cast CastKind.FloatCast 32<rt> fra
      let frbS = AST.cast CastKind.FloatCast 32<rt> frb
      tmp := AST.fdiv fraS frbS
      frd := AST.cast CastKind.FloatCast 64<rt> tmp
    setFPRF bld frd
    if updateCond then setCR1Reg bld else ()
  }

let frsp ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (frd, frb) = transTwoOprs ins bld
    let single = AST.cast CastKind.FloatCast 32<rt> frb
    frd := AST.cast CastKind.FloatCast 64<rt> single
    setFPRF bld frd
    if updateCond then setCR1Reg bld else ()
  }

let fsub ins insLen updateCond isDouble bld =
  fAddOrSub ins insLen updateCond isDouble AST.fsub bld

let fsqrt ins insLen updateCond isDouble bld =
  lift bld ins insLen {
    let struct (frd, frb) = transTwoOprs ins bld
    let tmp = tmpVar bld 32<rt>
    if isDouble then
      frd := AST.fsqrt frb
    else
      let frbS = AST.cast CastKind.FloatCast 32<rt> frb
      tmp := AST.fsqrt frbS
      frd := AST.cast CastKind.FloatCast 64<rt> tmp
    setFPRF bld frd
    if updateCond then setCR1Reg bld else ()
  }

let fctiw ins insLen updateCond bld =
  lift bld ins insLen {
    let tmp = tmpVar bld 64<rt>
    let struct (frd, frb) = transTwoOprs ins bld
    roundingToCastInt bld frd frb
    setFPRF bld frd
    if updateCond then setCR1Reg bld else ()
  }

let fctiwz ins insLen updateCond bld =
  lift bld ins insLen {
    let intMaxInFloat = numU64 0x41dfffffffc00000uL 64<rt>
    let intMinInFloat = numU64 0xc1e0000000000000uL 64<rt>
    let intMax = numU64 0x7fffffffUL 64<rt>
    let intMin = numU64 0x80000000UL 64<rt>
    let struct (frd, frb) = transTwoOprs ins bld
    frd := AST.cast CastKind.FtoITrunc 64<rt> frb
    frd := AST.ite (IEEE754Double.isNaN frb) intMin frd
    frd := AST.ite (AST.fle frb intMinInFloat) intMin frd
    frd := AST.ite (AST.fge frb intMaxInFloat) intMax frd
    setFPRF bld frd
    if updateCond then setCR1Reg bld else ()
  }

let fmadd ins insLen updateCond isDouble bld =
  lift bld ins insLen {
    let struct (frd, fra, frc, frb) = transFourOprs ins bld
    let tmp = tmpVar bld 32<rt>
    if isDouble then
      frd := AST.fadd (AST.fmul fra frc) frb
    else
      let fraS = AST.cast CastKind.FloatCast 32<rt> fra
      let frbS = AST.cast CastKind.FloatCast 32<rt> frb
      let frcS = AST.cast CastKind.FloatCast 32<rt> frc
      tmp := AST.fadd (AST.fmul fraS frcS) frbS
      frd := AST.cast CastKind.FloatCast 64<rt> tmp
    setFPRF bld frd
    if updateCond then setCR1Reg bld else ()
  }

let fmr ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (dst, src) = transTwoOprs ins bld
    dst := src
    if updateCond then setCR1Reg bld else ()
  }

let fmsub ins insLen updateCond isDouble bld =
  lift bld ins insLen {
    let struct (frd, fra, frc, frb) = transFourOprs ins bld
    let tmp = tmpVar bld 32<rt>
    if isDouble then
      frd := AST.fsub (AST.fmul fra frc) frb
    else
      let fraS = AST.cast CastKind.FloatCast 32<rt> fra
      let frbS = AST.cast CastKind.FloatCast 32<rt> frb
      let frcS = AST.cast CastKind.FloatCast 32<rt> frc
      tmp := AST.fsub (AST.fmul fraS frcS) frbS
      frd := AST.cast CastKind.FloatCast 64<rt> tmp
    setFPRF bld frd
    if updateCond then setCR1Reg bld else ()
  }

let fmul ins insLen updateCond isDouble bld =
  lift bld ins insLen {
    let struct (frd, fra, frb) = transThreeOprs ins bld
    let tmp = tmpVar bld 32<rt>
    if isDouble then
      frd := AST.fmul fra frb
    else
      let fraS = AST.cast CastKind.FloatCast 32<rt> fra
      let frbS = AST.cast CastKind.FloatCast 32<rt> frb
      tmp := AST.fmul fraS frbS
      frd := AST.cast CastKind.FloatCast 64<rt> tmp
    setFPRF bld frd
    if updateCond then setCR1Reg bld else ()
  }

let fnabs ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (frd, frb) = transTwoOprs ins bld
    frd := frb .| numU64 0x8000000000000000UL 64<rt>
    if updateCond then setCR1Reg bld else ()
  }

let fneg ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (frd, frb) = transTwoOprs ins bld
    floatingNeg bld frd frb 64<rt>
    if updateCond then setCR1Reg bld else ()
  }

let fnmadd ins insLen updateCond isDouble bld =
  lift bld ins insLen {
    let struct (frd, fra, frc, frb) = transFourOprs ins bld
    if isDouble then
      let res = tmpVar bld 64<rt>
      res := (AST.fadd (AST.fmul fra frc) frb)
      floatingNeg bld frd res 64<rt>
    else
      let res = tmpVar bld 32<rt>
      let nres = tmpVar bld 32<rt>
      let fraS = AST.cast CastKind.FloatCast 32<rt> fra
      let frcS = AST.cast CastKind.FloatCast 32<rt> frc
      let frbS = AST.cast CastKind.FloatCast 32<rt> frb
      res := (AST.fadd (AST.fmul fraS frcS) frbS)
      floatingNeg bld nres res 32<rt>
      frd := AST.cast CastKind.FloatCast 64<rt> nres
    if updateCond then setCR1Reg bld else ()
  }

let fnmsub ins insLen updateCond isDouble bld =
  lift bld ins insLen {
    let struct (frd, fra, frc, frb) = transFourOprs ins bld
    if isDouble then
      let res = tmpVar bld 64<rt>
      res := (AST.fsub (AST.fmul fra frc) frb)
      floatingNeg bld frd res 64<rt>
    else
      let res = tmpVar bld 32<rt>
      let nres = tmpVar bld 32<rt>
      let fraS = AST.cast CastKind.FloatCast 32<rt> fra
      let frcS = AST.cast CastKind.FloatCast 32<rt> frc
      let frbS = AST.cast CastKind.FloatCast 32<rt> frb
      res := (AST.fsub (AST.fmul fraS frcS) frbS)
      floatingNeg bld nres res 32<rt>
      frd := AST.cast CastKind.FloatCast 64<rt> nres
    if updateCond then setCR1Reg bld else ()
  }

let fsel ins insLen updateCond bld =
  lift bld ins insLen {
    let struct(frd, fra, frc, frb) = transFourOprs ins bld
    let cond = AST.fge fra (AST.num0 64<rt>)
    frd := AST.ite cond frc frb
    if updateCond then setCR1Reg bld else ()
  }

let lbz ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let ea = transEAWithOffset o2 bld
    let dst = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    dst := AST.zext bld.RegType (loadNative bld 8<rt> tmpEA)
  }

let lbzu ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
    let rd = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    rd := AST.zext bld.RegType (loadNative bld 8<rt> tmpEA)
    ra := tmpEA
  }

let lbzux ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rd = transOpr bld o1
    let struct (ea, ra) = transEAWithIndexRegForUpdate o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    rd := AST.zext bld.RegType (loadNative bld 8<rt> tmpEA)
    ra := tmpEA
  }

let lbzx ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rd = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    rd := AST.zext bld.RegType (loadNative bld 8<rt> tmpEA)
  }

let lfd ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let ea = transEAWithOffset o2 bld
    let dst = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    dst := loadNative bld 64<rt> tmpEA
  }

let lfdu ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
    let dst = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    dst := loadNative bld 64<rt> tmpEA
    ra := tmpEA
  }

let lfdux ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let dst = transOpr bld o1
    let struct (ea, ra) = transEAWithIndexRegForUpdate o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    dst := loadNative bld 64<rt> tmpEA
    ra := tmpEA
  }

let lfdx ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let dst = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    dst := loadNative bld 64<rt> tmpEA
  }

let lfs ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let ea = transEAWithOffset o2 bld
    let dst = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    let v = loadNative bld 32<rt> tmpEA
    tmpEA := ea
    dst := AST.cast CastKind.FloatCast 64<rt> v
  }

let lfsu ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
    let frd = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    let v = loadNative bld 32<rt> tmpEA
    tmpEA := ea
    frd := AST.cast CastKind.FloatCast 64<rt> v
    ra := tmpEA
  }

let lfsux ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let frd = transOpr bld o1
    let struct (ea, ra) = transEAWithIndexRegForUpdate o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    let v = loadNative bld 32<rt> tmpEA
    tmpEA := ea
    frd := AST.cast CastKind.FloatCast 64<rt> v
    ra := tmpEA
  }

let lfsx ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let frd = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    let v = loadNative bld 32<rt> tmpEA
    tmpEA := ea
    frd := AST.cast CastKind.FloatCast 64<rt> v
  }

let lha ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let ea = transEAWithOffset o2 bld
    let rd = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    rd := AST.sext bld.RegType (loadNative bld 16<rt> tmpEA)
  }

let lhau ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
    let rd = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    rd := AST.sext bld.RegType (loadNative bld 16<rt> tmpEA)
    ra := tmpEA
  }

let lhaux ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rd = transOpr bld o1
    let struct (ea, ra) = transEAWithIndexRegForUpdate o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    rd := AST.sext bld.RegType (loadNative bld 16<rt> tmpEA)
    ra := tmpEA
  }

let lhax ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rd = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    rd := AST.sext bld.RegType (loadNative bld 16<rt> tmpEA)
  }

let lhbrx ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rd = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    let tmpMem = tmpVar bld 16<rt>
    let revtmp = tmpVar bld 16<rt>
    tmpEA := ea
    tmpMem := loadNative bld 16<rt> tmpEA
    AST.xthi 8<rt> revtmp := AST.xtlo 8<rt> tmpMem
    AST.xtlo 8<rt> revtmp := AST.xthi 8<rt> tmpMem
    rd := AST.zext bld.RegType revtmp
  }

let lhz ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let ea = transEAWithOffset o2 bld
    let rd = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    rd := AST.zext bld.RegType (loadNative bld 16<rt> tmpEA)
  }

let lhzu ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
    let rd = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    rd := AST.zext bld.RegType (loadNative bld 16<rt> tmpEA)
    ra := ea
  }

let lhzux ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rd = transOpr bld o1
    let struct (ea, rA) = transEAWithIndexRegForUpdate o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    rd := AST.zext bld.RegType (loadNative bld 16<rt> tmpEA)
    rA := tmpEA
  }

let lhzx ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rd = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    rd := AST.zext bld.RegType (loadNative bld 16<rt> tmpEA)
  }

let li ins insLen bld =
  lift bld ins insLen {
    let struct (dst, simm) = transTwoOprs ins bld
    dst := simm
  }

let lis ins insLen bld =
  lift bld ins insLen {
    let struct (dst, simm) = transTwoOprs ins bld
    let simm = shiftedImm bld true simm
    dst := simm
  }

/// lwarx/ldarx: a load that arms the reservation a following store-conditional
/// checks. The reserved value is kept register-wide whatever the access size.
let private loadReserve ins insLen (bld: ILowUIRBuilder) size =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rd = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    let tmpVal = tmpVar bld bld.RegType
    tmpEA := ea
    tmpVal := AST.zext bld.RegType (loadNative bld size tmpEA)
    regVar bld Register.ExMonAddr := tmpEA
    regVar bld Register.ExMonVal := tmpVal
    rd := tmpVal
  }

let lwarx ins insLen bld = loadReserve ins insLen bld 32<rt>

let ldarx ins insLen bld = loadReserve ins insLen bld 64<rt>

let lbarx ins insLen bld = loadReserve ins insLen bld 8<rt>

let lharx ins insLen bld = loadReserve ins insLen bld 16<rt>

/// The bytes of a value of the given width, in reverse order. revConcat places
/// the array's first element in the result's least significant byte, so taking
/// the value's most significant byte first is what turns the order around.
let private reversedBytes value width =
  let n = int width / 8
  Array.init n (fun i -> AST.extract value 8<rt> ((n - 1 - i) * 8))
  |> AST.revConcat

/// lwbrx/ldbrx: a load whose bytes come back in the opposite order.
let private loadByteReverse ins insLen (bld: ILowUIRBuilder) size =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rd = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    let tmpMem = tmpVar bld size
    tmpEA := ea
    tmpMem := loadNative bld size tmpEA
    rd := AST.zext bld.RegType (reversedBytes tmpMem size)
  }

let lwbrx ins insLen bld = loadByteReverse ins insLen bld 32<rt>

let ldbrx ins insLen bld = loadByteReverse ins insLen bld 64<rt>

/// A d(rA) load of `size` bits, widened into rD by ext; when update is set the
/// effective address is also written back to rA.
let private loadOffset ins insLen (bld: ILowUIRBuilder) size ext update =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let dst = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    if update then
      let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
      tmpEA := ea
      dst := ext bld.RegType (loadNative bld size tmpEA)
      ra := tmpEA
    else
      tmpEA := transEAWithOffset o2 bld
      dst := ext bld.RegType (loadNative bld size tmpEA)
  }

/// An rA + rB load of `size` bits, widened into rD by ext, updating rA when
/// update is set.
let private loadIndexed ins insLen (bld: ILowUIRBuilder) size ext update =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let dst = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    if update then
      let struct (ea, ra) = transEAWithIndexRegForUpdate o2 o3 bld
      tmpEA := ea
      dst := ext bld.RegType (loadNative bld size tmpEA)
      ra := tmpEA
    else
      tmpEA := transEAWithIndexReg o2 o3 bld
      dst := ext bld.RegType (loadNative bld size tmpEA)
  }

let lwz ins insLen bld = loadOffset ins insLen bld 32<rt> AST.zext false

let lwzu ins insLen bld = loadOffset ins insLen bld 32<rt> AST.zext true

let lwzux ins insLen bld = loadIndexed ins insLen bld 32<rt> AST.zext true

let lwzx ins insLen bld = loadIndexed ins insLen bld 32<rt> AST.zext false

let lwa ins insLen bld = loadOffset ins insLen bld 32<rt> AST.sext false

let lwax ins insLen bld = loadIndexed ins insLen bld 32<rt> AST.sext false

let lwaux ins insLen bld = loadIndexed ins insLen bld 32<rt> AST.sext true

let ld ins insLen bld = loadOffset ins insLen bld 64<rt> AST.zext false

let ldu ins insLen bld = loadOffset ins insLen bld 64<rt> AST.zext true

let ldx ins insLen bld = loadIndexed ins insLen bld 64<rt> AST.zext false

let ldux ins insLen bld = loadIndexed ins insLen bld 64<rt> AST.zext true

let mcrf ins insLen bld =
  lift bld ins insLen {
    let struct ((crd0, crd1, crd2, crd3),
                (crs0, crs1, crs2, crs3)) = transCondTwoOprs ins bld
    crd0 := crs0
    crd1 := crs1
    crd2 := crs2
    crd3 := crs3
  }

let mcrxr ins insLen bld =
  lift bld ins insLen {
    let crd0, crd1, crd2, crd3 = transCondOneOpr ins bld
    let xer = regVar bld Register.XER
    crd0 := AST.extract xer 1<rt> 31
    crd1 := AST.extract xer 1<rt> 30
    crd2 := AST.extract xer 1<rt> 29
    crd3 := AST.extract xer 1<rt> 28
    xer := xer .& numI32 0x0fffffff 32<rt>
  }

let mfcr ins insLen (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let dst = transOneOpr ins bld
    let cr = tmpVar bld 32<rt>
    getCRRegValue bld cr
    dst := AST.zext bld.RegType cr
  }

let mfctr ins insLen bld =
  lift bld ins insLen {
    let dst = transOneOpr ins bld
    let ctr = regVar bld Register.CTR
    dst := ctr
  }

let mffs ins insLen bld =
  lift bld ins insLen {
    let dst = transOneOpr ins bld
    let fpscr = regVar bld Register.FPSCR
    dst := AST.zext 64<rt> fpscr
  }

let mflr ins insLen bld =
  lift bld ins insLen {
    let dst = transOneOpr ins bld
    let lr = regVar bld Register.LR
    dst := lr
  }

let mfspr (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, spr) =
      match ins.Operands with
      | TwoOperands(o1, OprImm o2) -> transOpr bld o1, getSPRReg bld o2
      | _ -> raise InvalidOperandException
    dst := spr
  }

(* mftb/mftbu read the 64-bit Time Base into rD. There is no real time base to
   read, so the value is left to the emulator via a ClockCounterRead side effect
   carrying the destination register and which 32-bit half (lower for mftb,
   upper for mftbu). *)
let mftb (ins: Instruction) insLen bld =
  let rid =
    match ins.Operands with
    | TwoOperands(OprReg rd, _) -> Register.toRegID rd
    | _ -> raise InvalidOperandException
  sideEffects ins insLen bld (ClockCounterRead(Some(rid, false)))

let mftbu (ins: Instruction) insLen bld =
  let rid =
    match ins.Operands with
    | OneOperand(OprReg rd) -> Register.toRegID rd
    | _ -> raise InvalidOperandException
  sideEffects ins insLen bld (ClockCounterRead(Some(rid, true)))

let mfxer ins insLen bld =
  lift bld ins insLen {
    let dst = transOneOpr ins bld
    let xer = regVar bld Register.XER
    dst := xer
  }

let mr ins insLen bld =
  lift bld ins insLen {
    let struct (dst, src) = transTwoOprs ins bld
    dst := src .| src
  }

let mtctr ins insLen bld =
  lift bld ins insLen {
    let src = transOneOpr ins bld
    let ctr = regVar bld Register.CTR
    ctr := src
  }

let mtfsfi ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (crfd, imm) = getTwoOprs ins
    let crfd = crfd |> getImmValue |> int
    let pos = 4 * (7 - crfd)
    let imm = transOpr bld imm
    let fpscr = regVar bld Register.FPSCR
    if crfd = 0 then
      AST.extract fpscr 1<rt> 31 := AST.extract imm 1<rt> 3
      AST.extract fpscr 1<rt> 28 := AST.extract imm 1<rt> 0
    else
      AST.extract fpscr 1<rt> (pos + 3) := AST.extract imm 1<rt> 3
      AST.extract fpscr 1<rt> (pos + 2) := AST.extract imm 1<rt> 2
      AST.extract fpscr 1<rt> (pos + 1) := AST.extract imm 1<rt> 1
      AST.extract fpscr 1<rt> pos := AST.extract imm 1<rt> 0
  }

let mtspr (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (spr, rs) =
      match ins.Operands with
      | TwoOperands(OprImm o1, o2) -> getSPRReg bld o1, transOpr bld o2
      | _ -> raise InvalidOperandException
    spr := rs
  }

let private crmMask bld crm =
  let tCrm = Array.init 4 (fun _ -> tmpVar bld 8<rt>)
  for i in 0..3 do
    let cond1 = AST.extract crm 1<rt> (i * 2)
    let cond2 = AST.extract crm 1<rt> (i * 2 + 1)
    append bld {
      tCrm[i] :=
        AST.ite cond1
                (AST.ite cond2 (numI32 0xff 8<rt>) (numI32 0xf 8<rt>))
                (AST.ite cond2 (numI32 0xf0 8<rt>) (AST.num0 8<rt>))
    }
  tCrm |> AST.revConcat

let mtcrf ins insLen bld =
  lift bld ins insLen {
    let struct (crm, rs) = transTwoOprs ins bld
    let mask = tmpVar bld 32<rt>
    let cr = tmpVar bld 32<rt>
    mask := crmMask bld crm
    getCRRegValue bld cr
    cr := (AST.xtlo 32<rt> rs .& mask) .| (cr .& AST.not mask)
    setCRRegValue bld cr
  }

let mtlr ins insLen bld =
  lift bld ins insLen {
    let src = transOneOpr ins bld
    let lr = regVar bld Register.LR
    lr := src
  }

let mtfsb0 ins insLen updateCond bld =
  lift bld ins insLen {
    let crbD = getOneOpr ins |> getImmValue |> int
    let fpscr = regVar bld Register.FPSCR
    if crbD <> 1 && crbD <> 2 then
      AST.extract fpscr 1<rt> (31 - crbD) := AST.b0
    else
      ()
    if updateCond then setCR1Reg bld else ()
    (* Affected: FX *)
  }

let mtfsb1 ins insLen updateCond bld =
  lift bld ins insLen {
    let crbD = getOneOpr ins |> getImmValue |> int
    let fpscr = regVar bld Register.FPSCR
    if crbD <> 1 && crbD <> 2 then
      AST.extract fpscr 1<rt> (31 - crbD) := AST.b1
    else
      ()
    if updateCond then setCR1Reg bld else ()
    (* Affected: FX *)
  }

let mtfsf ins insLen bld =
  lift bld ins insLen {
    let struct (fm, frB) = getTwoOprs ins
    let frB = transOpr bld frB
    let fm = BitVector(getImmValue fm, 32<rt>) |> AST.num
    let fpscr = regVar bld Register.FPSCR
    let mask = tmpVar bld 32<rt>
    mask := crmMask bld fm
    fpscr := (AST.xtlo 32<rt> frB .& mask) .| (fpscr .& AST.not mask)
  }

let mtxer ins insLen bld =
  lift bld ins insLen {
    let src = transOneOpr ins bld
    let xer = regVar bld Register.XER
    xer := src
  }

/// The high half of a product of two `width`-bit operands, taken in a double-
/// width temporary and placed in a whole register. A 64-bit guest leaves the
/// upper half of a mulhw's result undefined, so widening it either way is
/// allowed; sign- or zero-extending matches the operands' signedness.
let private mulHigh ins
                    insLen
                    updateCond
                    (bld: ILowUIRBuilder)
                    (width: RegType)
                    signed =
  lift bld ins insLen {
    let struct (dst, ra, rb) = transThreeOprs ins bld
    let wide = width + width
    let tmp = tmpVar bld wide
    let ext e = if signed then AST.sext wide e else AST.zext wide e
    tmp := ext (AST.xtlo width ra) .* ext (AST.xtlo width rb)
    let hi = AST.xthi width tmp
    dst := if signed then AST.sext bld.RegType hi
           else AST.zext bld.RegType hi
    if updateCond then setCR0Reg bld dst else ()
  }

let mulhw ins insLen updateCond bld =
  mulHigh ins insLen updateCond bld 32<rt> true

let mulhwu ins insLen updateCond bld =
  mulHigh ins insLen updateCond bld 32<rt> false

let mulhd ins insLen updateCond bld =
  mulHigh ins insLen updateCond bld 64<rt> true

let mulhdu ins insLen updateCond bld =
  mulHigh ins insLen updateCond bld 64<rt> false

let mulli ins insLen bld =
  lift bld ins insLen {
    let struct (dst, ra, simm) = transThreeOprs ins bld
    dst := ra .* simm
  }

/// mullw takes two word operands and, on a 64-bit part, keeps the whole
/// doubleword product; on a 32-bit one only the low word exists.
let mullw ins insLen updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let tmp = tmpVar bld 64<rt>
    if ovCond then isMulwOV bld src1 src2 else ()
    let a = AST.sext 64<rt> (AST.xtlo 32<rt> src1)
    let b = AST.sext 64<rt> (AST.xtlo 32<rt> src2)
    tmp := a .* b
    dst := AST.xtlo bld.RegType tmp
    if updateCond then setCR0Reg bld dst else ()
  }

let mulld ins insLen updateCond ovCond bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    if ovCond then isMuldOV bld src1 src2 else ()
    dst := src1 .* src2
    if updateCond then setCR0Reg bld dst else ()
  }

let nand ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    dst := AST.not (src1 .& src2)
    if updateCond then setCR0Reg bld dst else ()
  }

let neg ins insLen updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (dst, src) = transTwoOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    t1 := AST.not src
    t2 := AST.num1 bld.RegType
    dst := t1 .+ t2
    if ovCond then isAddSubOV bld t1 t2 dst else ()
    if updateCond then setCR0Reg bld dst else ()
  }

let nor ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    dst := AST.not (src1 .| src2)
    if updateCond then setCR0Reg bld dst else ()
  }

let nop (ins: Instruction) insLen bld =
  lift bld ins insLen {
  }

/// The number of bytes dcbz clears. The architecture leaves the size to the
/// implementation and has software discover it from AT_DCACHEBSIZE; this is
/// the size every 64-bit Power part uses.
let [<Literal>] private CacheBlockSize = 128

/// dcbz, the one cache-management form with an effect on storage: it clears the
/// block the address falls in. Modeled as clearing that many bytes, in
/// doublewords, from the block-aligned address.
let dcbz ins insLen (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let ea = transEAWithIndexReg o1 o2 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea .& AST.not (numI32 (CacheBlockSize - 1) bld.RegType)
    for i in 0 .. (CacheBlockSize / 8) - 1 do
      let addr = tmpEA .+ numI32 (i * 8) bld.RegType
      loadNative bld 64<rt> addr := AST.num0 64<rt>
  }

let orx ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    dst := src1 .| src2
    if updateCond then setCR0Reg bld dst else ()
  }

let orc ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    dst := src1 .| AST.not (src2)
    if updateCond then setCR0Reg bld dst else ()
  }

let ori ins insLen bld =
  lift bld ins insLen {
    let struct (dst, src, uimm) = transThreeOprs ins bld
    let uimm = AST.zext bld.RegType (AST.xtlo 16<rt> uimm)
    dst := src .| uimm
  }

let oris ins insLen bld =
  lift bld ins insLen {
    let struct (dst, src, uimm) = transThreeOprs ins bld
    let uimm = shiftedImm bld false uimm
    dst := src .| uimm
  }

(* The rotate-word forms all work on the low word of rS and, on a 64-bit part,
   leave the result's upper word zero -- so the whole thing is a word operation
   whose result is zero-extended back into a register. *)
let rlwinm ins insLen updateCond (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (ra, rs, sh, mb, me) = transFiveOprs ins bld
    let rol = tmpVar bld 32<rt>
    rol := rotateLeft (AST.xtlo 32<rt> rs) (AST.xtlo 32<rt> sh)
    ra := AST.zext bld.RegType (rol .& (getExtMask mb me))
    if updateCond then setCR0Reg bld ra else ()
  }

/// rlwimi merges a rotated word into rA under a mask that covers only the low
/// word, so unlike the other rotate-word forms it leaves rA's upper word alone
/// rather than clearing it -- which is what makes it the instruction a compiler
/// reaches for when it inserts a bit field.
let rlwimi ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (ra, rs, sh, mb, me) = transFiveOprs ins bld
    let m = getExtMask mb me
    let rol = rotateLeft (AST.xtlo 32<rt> rs) (AST.xtlo 32<rt> sh)
    let merged = tmpVar bld 32<rt>
    merged := (rol .& m) .| (AST.xtlo 32<rt> ra .& AST.not m)
    AST.xtlo 32<rt> ra := merged
    if updateCond then setCR0Reg bld ra else ()
  }

let rlwnm ins insLen updateCond (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (ra, rs, rb, mb, me) = transFiveOprs ins bld
    let n = AST.xtlo 32<rt> rb .& numI32 0x1f 32<rt>
    let rol = tmpVar bld 32<rt>
    rol := rotateLeft (AST.xtlo 32<rt> rs) n
    ra := AST.zext bld.RegType (rol .& (getExtMask mb me))
    if updateCond then setCR0Reg bld ra else ()
  }

let rotlw ins insLen (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (ra, rs, rb) = transThreeOprs ins bld
    let n = AST.xtlo 32<rt> rb .& numI32 0x1f 32<rt>
    let rol = rotateLeft (AST.xtlo 32<rt> rs) n
    ra := AST.zext bld.RegType rol (* no mask *)
  }

(* The rotate-doubleword forms take a six-bit shift and a six-bit mask bound,
   and the mask is a constant of the immediate forms. *)
let rldicl ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (ra, rs, sh, mb) = transFourOprs ins bld
    let rol = tmpVar bld 64<rt>
    rol := rotateLeft64 rs sh
    ra := rol .& getExtMask64 mb (numI32 63 64<rt>)
    if updateCond then setCR0Reg bld ra else ()
  }

let rldicr ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (ra, rs, sh, me) = transFourOprs ins bld
    let rol = tmpVar bld 64<rt>
    rol := rotateLeft64 rs sh
    ra := rol .& getExtMask64 (AST.num0 64<rt>) me
    if updateCond then setCR0Reg bld ra else ()
  }

/// The end of an rldic/rldimi mask, which the shift amount fixes at 63 - sh.
let private maskEndOfShift sh =
  match sh with
  | Num(n, _) -> numI32 (63 - int (n.ToUInt64())) 64<rt>
  | _ -> raise InvalidExprException

let rldic ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (ra, rs, sh, mb) = transFourOprs ins bld
    let rol = tmpVar bld 64<rt>
    rol := rotateLeft64 rs sh
    ra := rol .& getExtMask64 mb (maskEndOfShift sh)
    if updateCond then setCR0Reg bld ra else ()
  }

let rldimi ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (ra, rs, sh, mb) = transFourOprs ins bld
    let m = getExtMask64 mb (maskEndOfShift sh)
    let rol = tmpVar bld 64<rt>
    rol := rotateLeft64 rs sh
    ra := (rol .& m) .| (ra .& AST.not m)
    if updateCond then setCR0Reg bld ra else ()
  }

let rldcl ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (ra, rs, rb, mb) = transFourOprs ins bld
    let rol = tmpVar bld 64<rt>
    rol := rotateLeft64 rs (rb .& numI32 0x3f 64<rt>)
    ra := rol .& getExtMask64 mb (numI32 63 64<rt>)
    if updateCond then setCR0Reg bld ra else ()
  }

let rldcr ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (ra, rs, rb, me) = transFourOprs ins bld
    let rol = tmpVar bld 64<rt>
    rol := rotateLeft64 rs (rb .& numI32 0x3f 64<rt>)
    ra := rol .& getExtMask64 (AST.num0 64<rt>) me
    if updateCond then setCR0Reg bld ra else ()
  }

(* A shift's count comes from the low six bits of rB, and the bit above them
   makes the result all sign (arithmetic) or all zero (logical). *)
/// A logical shift of `width` bits, left when shiftLeft is set. The count's
/// high bit -- bit 5 for a word form, bit 6 for a doubleword one -- shifts the
/// whole operand out, which the architecture defines as a zero result.
let private logicalShift ins
                         insLen
                         updateCond
                         (bld: ILowUIRBuilder)
                         width
                         shiftLeft =
  lift bld ins insLen {
    let struct (dst, rs, rb) = transThreeOprs ins bld
    let bits = int width
    let value = AST.xtlo width rs
    let count = AST.xtlo width rb
    let n = tmpVar bld width
    n := count .& numI32 (bits - 1) width
    let shifted = if shiftLeft then value << n else value >> n
    let tooFar = (count .& numI32 bits width) != AST.num0 width
    let res = AST.ite tooFar (AST.num0 width) shifted
    dst := AST.zext bld.RegType res
    if updateCond then setCR0Reg bld dst else ()
  }

let slw ins insLen updateCond bld =
  logicalShift ins insLen updateCond bld 32<rt> true

let srw ins insLen updateCond bld =
  logicalShift ins insLen updateCond bld 32<rt> false

let sld ins insLen updateCond bld =
  logicalShift ins insLen updateCond bld 64<rt> true

let srd ins insLen updateCond bld =
  logicalShift ins insLen updateCond bld 64<rt> false

/// An arithmetic right shift of `width` bits by a register count, which also
/// leaves XER[CA] set when a one was shifted out of a negative value. A count
/// past the operand's width shifts in nothing but sign.
let private arithShift ins insLen updateCond (bld: ILowUIRBuilder) width =
  lift bld ins insLen {
    let struct (ra, rs, rb) = transThreeOprs ins bld
    let bits = int width
    let z = AST.num0 width
    let value = tmpVar bld width
    let count = AST.xtlo width rb
    let inRange = (count .& numI32 bits width) == z
    let n = tmpVar bld width
    let res = tmpVar bld width
    value := AST.xtlo width rs
    n := count .& numI32 (bits - 1) width
    res := AST.ite inRange (value ?>> n)
                           (value ?>> numI32 (bits - 1) width)
    ra := AST.sext bld.RegType res
    let dropped =
      AST.ite inRange ((AST.num1 width << n) .- AST.num1 width) (AST.not z)
    let lost = (value .& dropped) != z
    AST.extract (regVar bld Register.XER) 1<rt> 29 :=
      AST.ite (res ?< z) lost AST.b0
    if updateCond then setCR0Reg bld ra else ()
  }

let sraw ins insLen updateCond bld = arithShift ins insLen updateCond bld 32<rt>

let srad ins insLen updateCond bld = arithShift ins insLen updateCond bld 64<rt>

/// An arithmetic right shift of `width` bits by an immediate count, setting
/// XER[CA] as the register-count form does.
let private arithShiftImm ins insLen updateCond (bld: ILowUIRBuilder) width =
  lift bld ins insLen {
    let struct (ra, rs, sh) = transThreeOprs ins bld
    let z = AST.num0 width
    let value = tmpVar bld width
    let n = AST.xtlo width sh
    let res = tmpVar bld width
    value := AST.xtlo width rs
    res := value ?>> n
    ra := AST.sext bld.RegType res
    let dropped = (AST.num1 width << n) .- AST.num1 width
    let lost = (value .& dropped) != z
    AST.extract (regVar bld Register.XER) 1<rt> 29 :=
      AST.ite (res ?< z) lost AST.b0
    if updateCond then setCR0Reg bld ra else ()
  }

let srawi ins insLen updateCond bld =
  arithShiftImm ins insLen updateCond bld 32<rt>

let sradi ins insLen updateCond bld =
  arithShiftImm ins insLen updateCond bld 64<rt>

let stb ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let ea = transEAWithOffset o2 bld
    let src = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 8<rt> tmpEA := AST.xtlo 8<rt> src
  }

let stbx ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rs = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 8<rt> tmpEA := AST.xtlo 8<rt> rs
  }

let stbu ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
    let src = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 8<rt> tmpEA := AST.xtlo 8<rt> src
    ra := tmpEA
  }

let stbux ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rs = transOpr bld o1
    let struct (ea, rA) = transEAWithIndexRegForUpdate o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 8<rt> tmpEA := AST.xtlo 8<rt> rs
    rA := tmpEA
  }

let stfd ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let ea = transEAWithOffset o2 bld
    let frs = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 64<rt> tmpEA := frs
  }

let stfdx ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let ea = transEAWithIndexReg o2 o3 bld
    let frs = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 64<rt> tmpEA := frs
  }

let stfdu ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
    let frs = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 64<rt> tmpEA := frs
    ra := tmpEA
  }

let stfdux ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let frs = transOpr bld o1
    let struct (ea, rA) = transEAWithIndexRegForUpdate o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 64<rt> tmpEA := frs
    rA := tmpEA
  }

let stfiwx ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let frs = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 32<rt> tmpEA := AST.xtlo 32<rt> frs
  }

let stfs ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let ea = transEAWithOffset o2 bld
    let frs = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 32<rt> tmpEA := AST.cast CastKind.FloatCast 32<rt> frs
  }

let stfsx ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let ea = transEAWithIndexReg o2 o3 bld
    let frs = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 32<rt> tmpEA := AST.cast CastKind.FloatCast 32<rt> frs
  }

let stfsu ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
    let frs = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 32<rt> tmpEA := AST.cast CastKind.FloatCast 32<rt> frs
    ra := tmpEA
  }

let stfsux ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let frs = transOpr bld o1
    let struct (ea, rA) = transEAWithIndexRegForUpdate o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 32<rt> tmpEA := AST.cast CastKind.FloatCast 32<rt> frs
    rA := tmpEA
  }

let sth ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let ea = transEAWithOffset o2 bld
    let src = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 16<rt> tmpEA := AST.xtlo 16<rt> src
  }

let sthbrx ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rs = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let revtmp = tmpVar bld 16<rt>
    revtmp := AST.concat (AST.extract rs 8<rt> 0)
                         (AST.extract rs 8<rt> 8)
    loadNative bld 16<rt> ea := revtmp
  }

let sthx ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rs = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 16<rt> tmpEA := AST.xtlo 16<rt> rs
  }

let sthu ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
    let rs = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 16<rt> tmpEA := AST.xtlo 16<rt> rs
    ra := tmpEA
  }

let sthux ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rs = transOpr bld o1
    let struct (ea, rA) = transEAWithIndexRegForUpdate o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 16<rt> tmpEA := AST.xtlo 16<rt> rs
    rA := tmpEA
  }

/// A d(rA) store of the low `size` bits of rS, updating rA when update is set.
let private storeOffset ins insLen (bld: ILowUIRBuilder) size update =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let src = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    if update then
      let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
      tmpEA := ea
      loadNative bld size tmpEA := AST.xtlo size src
      ra := tmpEA
    else
      tmpEA := transEAWithOffset o2 bld
      loadNative bld size tmpEA := AST.xtlo size src
  }

/// An rA + rB store of the low `size` bits of rS, updating rA when update is
/// set.
let private storeIndexed ins insLen (bld: ILowUIRBuilder) size update =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let src = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    if update then
      let struct (ea, ra) = transEAWithIndexRegForUpdate o2 o3 bld
      tmpEA := ea
      loadNative bld size tmpEA := AST.xtlo size src
      ra := tmpEA
    else
      tmpEA := transEAWithIndexReg o2 o3 bld
      loadNative bld size tmpEA := AST.xtlo size src
  }

let stw ins insLen bld = storeOffset ins insLen bld 32<rt> false

let stwu ins insLen bld = storeOffset ins insLen bld 32<rt> true

let stwx ins insLen bld = storeIndexed ins insLen bld 32<rt> false

let stwux ins insLen bld = storeIndexed ins insLen bld 32<rt> true

let std ins insLen bld = storeOffset ins insLen bld 64<rt> false

let stdu ins insLen bld = storeOffset ins insLen bld 64<rt> true

let stdx ins insLen bld = storeIndexed ins insLen bld 64<rt> false

let stdux ins insLen bld = storeIndexed ins insLen bld 64<rt> true

let lmw ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let rd =
      match o1 with
      | OprReg r -> int r
      | _ -> raise InvalidOperandException
    let ea = transEAWithOffset o2 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    for r = rd to 31 do
      let dst = regVar bld (getRegister (uint32 r))
      let addr = tmpEA .+ numI32 ((r - rd) * 4) bld.RegType
      dst := AST.zext bld.RegType (loadNative bld 32<rt> addr)
  }

let stmw ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let rs =
      match o1 with
      | OprReg r -> int r
      | _ -> raise InvalidOperandException
    let ea = transEAWithOffset o2 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    for r = rs to 31 do
      let src = regVar bld (getRegister (uint32 r))
      let addr = tmpEA .+ numI32 ((r - rs) * 4) bld.RegType
      loadNative bld 32<rt> addr := AST.xtlo 32<rt> src
  }

/// stwbrx/stdbrx: a store whose bytes go out in the opposite order.
let private storeByteReverse ins insLen (bld: ILowUIRBuilder) size =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rs = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld size tmpEA := reversedBytes (AST.xtlo size rs) size
  }

let stwbrx ins insLen bld = storeByteReverse ins insLen bld 32<rt>

let stdbrx ins insLen bld = storeByteReverse ins insLen bld 64<rt>

/// stwcx./stdcx.: the store half of a reservation pair. It succeeds only when
/// the address and the value both still match what the paired load reserved,
/// and reports that in CR0[EQ].
let private storeConditional ins insLen (bld: ILowUIRBuilder) size =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rs = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let xerSO = AST.xthi 1<rt> (regVar bld Register.XER)
    let cr0LT = regVar bld Register.CR0_0
    let cr0GT = regVar bld Register.CR0_1
    let cr0EQ = regVar bld Register.CR0_2
    let cr0SO = regVar bld Register.CR0_3
    let tmpEA = tmpVar bld bld.RegType
    let cur = tmpVar bld size
    let matched = tmpVar bld 1<rt>
    tmpEA := ea
    cur := loadNative bld size tmpEA
    matched := (tmpEA == regVar bld Register.ExMonAddr)
               .& (AST.zext bld.RegType cur
                   == regVar bld Register.ExMonVal)
    loadNative bld size tmpEA :=
      AST.ite matched (AST.xtlo size rs) cur
    cr0EQ := matched
    cr0LT := AST.b0
    cr0GT := AST.b0
    cr0SO := xerSO
  }

let stwcxdot ins insLen bld = storeConditional ins insLen bld 32<rt>

let stdcxdot ins insLen bld = storeConditional ins insLen bld 64<rt>

let stbcxdot ins insLen bld = storeConditional ins insLen bld 8<rt>

let sthcxdot ins insLen bld = storeConditional ins insLen bld 16<rt>

let subf ins insLen updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let one = AST.num1 bld.RegType
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    t1 := AST.not src1
    t2 := src2
    dst := t1 .+ t2 .+ one
    if ovCond then isAddSubOV bld t1 t2 dst else ()
    if updateCond then setCR0Reg bld dst else ()
  }

let subfc ins insLen updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    t1 := AST.not src1
    t2 := src2
    addWithCarryOut bld dst t1 t2 (AST.num1 bld.RegType)
    if ovCond then isAddSubOV bld t1 t2 dst else ()
    if updateCond then setCR0Reg bld dst else ()
  }

let subfe ins insLen updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    let ca = carryIn bld
    t1 := AST.not src1
    t2 := src2
    addWithCarryOut bld dst t1 t2 ca
    if ovCond then isAddSubOV bld t1 t2 dst else ()
    if updateCond then setCR0Reg bld dst else ()
  }

let subfic ins insLen (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (dst, src1, simm) = transThreeOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    t1 := AST.not src1
    t2 := simm
    addWithCarryOut bld dst t1 t2 (AST.num1 bld.RegType)
  }

let subfme ins insLen updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (dst, src) = transTwoOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    let ca = carryIn bld
    t1 := AST.not src
    t2 := AST.not (AST.num0 bld.RegType)
    addWithCarryOut bld dst t1 t2 ca
    if ovCond then isAddSubOV bld t1 t2 dst else ()
    if updateCond then setCR0Reg bld dst else ()
  }

let subfze ins insLen updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (dst, src) = transTwoOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    let ca = carryIn bld
    t1 := AST.not src
    t2 := AST.num0 bld.RegType
    addWithCarryOut bld dst t1 t2 ca
    if ovCond then isAddSubOV bld t1 t2 dst else ()
    if updateCond then setCR0Reg bld dst else ()
  }

let trap (ins: Instruction) insLen bld =
  lift bld ins insLen {
    AST.sideEffect (Interrupt 0)
  }

let trapCond ins insLen cmpOp bld =
  lift bld ins insLen {
    let struct (ra, rb) = transTwoOprs ins bld
    let lblTrap = label bld "Trap"
    let lblEnd = label bld "End"
    AST.cjmp (cmpOp ra rb) (AST.jmpDest lblTrap) (AST.jmpDest lblEnd)
    AST.lmark lblTrap
    AST.sideEffect (Interrupt 0)
    AST.lmark lblEnd
  }

/// The five TO bits of a tw/td, each naming one comparison that traps: from
/// bit 0, signed less-than, signed greater-than, equal, unsigned less-than and
/// unsigned greater-than.
let private trapTests = [| AST.slt; AST.sgt; AST.eq; AST.lt; AST.gt |]

/// A generic tw/td/twi/tdi, which traps when any comparison its TO field names
/// holds. The word forms compare only the low word of each operand.
let trapGeneric ins insLen (bld: ILowUIRBuilder) narrow =
  lift bld ins insLen {
    let struct (tO, ra, rb) = transThreeOprs ins bld
    let tO = match tO with
             | Num(n, _) -> int (n.ToUInt64())
             | _ -> raise InvalidExprException
    let ra, rb =
      if narrow then AST.xtlo 32<rt> ra, AST.xtlo 32<rt> rb else ra, rb
    let lblTrap = label bld "Trap"
    let lblEnd = label bld "End"
    let cond =
      Array.mapi (fun i test -> if tO &&& (1 <<< (4 - i)) <> 0 then test ra rb
                                else AST.b0) trapTests
      |> Array.reduce (.|)
    AST.cjmp cond (AST.jmpDest lblTrap) (AST.jmpDest lblEnd)
    AST.lmark lblTrap
    AST.sideEffect (Interrupt 0)
    AST.lmark lblEnd
  }

let xor ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    dst := (src1 <+> src2)
    if updateCond then setCR0Reg bld dst else ()
  }

let xori ins insLen bld =
  lift bld ins insLen {
    let struct (dst, src, uimm) = transThreeOprs ins bld
    let uimm = AST.zext bld.RegType (AST.xtlo 16<rt> uimm)
    dst := src <+> uimm
  }

let xoris ins insLen bld =
  lift bld ins insLen {
    let struct (dst, src, uimm) = transThreeOprs ins bld
    let uimm = shiftedImm bld false uimm
    dst := src <+> uimm
  }

/// Sums the set bits of each `chunk`-wide field of rs, in place, by the usual
/// halving fold: pairs, then nibbles, then bytes, and so on up to the field.
let private popCountInto (bld: ILowUIRBuilder) ra rs chunk =
  append bld {
    let rt = bld.RegType
    let x = tmpVar bld rt
    let n i = numI32 i rt
    let mask v = numU64 v rt
    x := rs
    x := (x .& mask 0x5555555555555555UL)
         .+ ((x >> n 1) .& mask 0x5555555555555555UL)
    x := (x .& mask 0x3333333333333333UL)
         .+ ((x >> n 2) .& mask 0x3333333333333333UL)
    x := (x .& mask 0x0f0f0f0f0f0f0f0fUL)
         .+ ((x >> n 4) .& mask 0x0f0f0f0f0f0f0f0fUL)
    if chunk > 8 then
      x := (x .& mask 0x00ff00ff00ff00ffUL)
           .+ ((x >> n 8) .& mask 0x00ff00ff00ff00ffUL)
    else
      ()
    if chunk > 16 then
      x := (x .& mask 0x0000ffff0000ffffUL)
           .+ ((x >> n 16) .& mask 0x0000ffff0000ffffUL)
    else
      ()
    if chunk > 32 then
      x := (x .& mask 0x00000000ffffffffUL)
           .+ ((x >> n 32) .& mask 0x00000000ffffffffUL)
    else
      ()
    ra := x
  }

/// popcntb/popcntw/popcntd, which count the set bits of every byte, word or
/// doubleword of rS into the same field of rA.
let popcnt ins insLen bld chunk =
  lift bld ins insLen {
    let struct (ra, rs) = transTwoOprs ins bld
    popCountInto bld ra rs chunk
  }

/// prtyw/prtyd, which put the parity of rS's bytes -- one per word, or one for
/// the whole doubleword -- in the low bit of that field of rA. Only each byte's
/// low bit takes part, so summing those and keeping the sum's low bit gives it.
let prty ins insLen (bld: ILowUIRBuilder) chunk =
  lift bld ins insLen {
    let rt = bld.RegType
    let struct (ra, rs) = transTwoOprs ins bld
    let lowBitOfField =
      if chunk > 32 then AST.num1 rt else numU64 0x0000000100000001UL rt
    let x = tmpVar bld rt
    x := rs .& numU64 0x0101010101010101UL rt
    popCountInto bld x x chunk
    ra := x .& lowBitOfField
  }

/// bpermd, which gathers the eight bits of rB that the eight byte indices in rS
/// name into the low byte of rA; an index past 63 contributes a zero. Index i
/// counts from rS's most significant byte and lands in rA's bit 7 - i.
let bpermd ins insLen (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let rt = bld.RegType
    let struct (ra, rs, rb) = transThreeOprs ins bld
    let res = tmpVar bld rt
    res := AST.num0 rt
    for i in 0 .. 7 do
      let idx = AST.zext rt (AST.extract rs 8<rt> ((7 - i) * 8))
      let bit = (rb >> (numI32 63 rt .- idx)) .& AST.num1 rt
      let inRange = idx .< numI32 64 rt
      let picked = AST.ite inRange bit (AST.num0 rt)
      res := res .| (picked << numI32 (7 - i) rt)
    ra := res
  }

/// cmpb, which sets each byte of rA to all ones where the matching bytes of rS
/// and rB are equal and to zero where they are not.
let cmpb ins insLen (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let rt = bld.RegType
    let struct (ra, rs, rb) = transThreeOprs ins bld
    let res = tmpVar bld rt
    res := AST.num0 rt
    for i in 0 .. (int rt / 8) - 1 do
      let eq = AST.extract rs 8<rt> (i * 8) == AST.extract rb 8<rt> (i * 8)
      AST.extract res 8<rt> (i * 8) :=
        AST.ite eq (numI32 0xff 8<rt>) (AST.num0 8<rt>)
    ra := res
  }

/// isel, which picks rA (or zero when rA is r0) or rB by a CR bit.
let isel (ins: Instruction) insLen (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (rd, ra, rb, crb) =
      match ins.Operands with
      | FourOperands(o1, OprReg Register.R0, o3, o4) ->
        let o1 = transOpr bld o1
        let o3 = transOpr bld o3
        let o4 = transOpr bld o4
        struct (o1, AST.num0 bld.RegType, o3, o4)
      | FourOperands(o1, o2, o3, o4) ->
        let o1 = transOpr bld o1
        let o2 = transOpr bld o2
        let o3 = transOpr bld o3
        let o4 = transOpr bld o4
        struct (o1, o2, o3, o4)
      | _ ->
        raise InvalidOperandException
    rd := AST.ite crb ra rb
  }

/// mfvsrd/mfvsrwz, which move the bits of a vector-scalar register's high
/// doubleword into a general register without converting them. The operand
/// names that doubleword, whichever kind of register holds it.
let mfvsr ins insLen (bld: ILowUIRBuilder) size =
  lift bld ins insLen {
    let struct (frs, ra) = transTwoOprs ins bld
    ra := AST.zext bld.RegType (AST.xtlo size frs)
  }

/// mtvsrd, which moves a general register's bits into a vector-scalar
/// register's high doubleword, leaving the low one undefined.
let mtvsrd ins insLen bld =
  lift bld ins insLen {
    let struct (frs, ra) = transTwoOprs ins bld
    frs := AST.zext 64<rt> ra
  }

/// mtvsrwa/mtvsrwz, which move the low word of a general register into a
/// vector-scalar register's high doubleword, sign- or zero-extended.
let mtvsrw ins insLen bld signed =
  lift bld ins insLen {
    let struct (frs, ra) = transTwoOprs ins bld
    let w = AST.xtlo 32<rt> ra
    frs := if signed then AST.sext 64<rt> w else AST.zext 64<rt> w
  }

/// fctid/fctidz/fctidu/fctiduz and fctiwu/fctiwuz: a conversion from a double
/// to an integer of `width` bits, left in the target's low bits. A "z" form
/// always truncates; the others follow FPSCR[RN].
let fcti ins insLen updateCond bld width truncate =
  lift bld ins insLen {
    let struct (frd, frb) = transTwoOprs ins bld
    if truncate then
      frd := AST.zext 64<rt> (AST.cast CastKind.FtoITrunc width frb)
    else
      let rounded = tmpVar bld 64<rt>
      roundingToCastInt bld rounded frb
      frd := AST.zext 64<rt> (AST.xtlo width rounded)
    if updateCond then setCR1Reg bld else ()
  }

/// fcfid/fcfidu/fcfids/fcfidus: a conversion from the integer in frB's whole
/// doubleword to a double, rounded to single precision by the "s" forms.
let fcfid ins insLen updateCond bld signed single =
  lift bld ins insLen {
    let struct (frd, frb) = transTwoOprs ins bld
    let kind = if signed then CastKind.SIntToFloat else CastKind.UIntToFloat
    let converted = AST.cast kind 64<rt> frb
    if single then
      let narrowed = AST.cast CastKind.FloatCast 32<rt> converted
      frd := AST.cast CastKind.FloatCast 64<rt> narrowed
    else
      frd := converted
    setFPRF bld frd
    if updateCond then setCR1Reg bld else ()
  }

/// frin/friz/frip/frim, which round a double to an integral value in place,
/// respectively to nearest, toward zero, up, and down.
let frnd ins insLen updateCond bld kind =
  lift bld ins insLen {
    let struct (frd, frb) = transTwoOprs ins bld
    frd := AST.cast kind 64<rt> frb
    setFPRF bld frd
    if updateCond then setCR1Reg bld else ()
  }

(* The vector unit. A 128-bit vector register is modeled as two 64-bit halves
   (see the Register type), and every operation below works on those halves
   rather than on a 128-bit value, so nothing needs an intermediate wider than a
   register. "hi" always holds the vector's most significant doubleword, which
   is the half PowerPC numbers first. *)
/// The high and low halves of the 128-bit register an operand names: a vector
/// register keeps its low half in the register that follows, while a VSX
/// operand naming a floating-point register keeps it in that register's
/// companion (VSR0-31 hold their high doubleword in an FPR).
