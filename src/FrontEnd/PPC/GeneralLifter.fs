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

let add ins updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    t1 := src1
    t2 := src2
    dst := t1 .+ t2
    if ovCond then isAddSubOV bld t1 t2 dst else ()
    if updateCond then setCR0Reg bld dst else ()
  }

let addc ins updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    t1 := src1
    t2 := src2
    addWithCarryOut bld dst t1 t2 (AST.num0 bld.RegType)
    if ovCond then isAddSubOV bld t1 t2 dst else ()
    if updateCond then setCR0Reg bld dst else ()
  }

let adde ins updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    let ca = carryIn bld
    t1 := src1
    t2 := src2
    addWithCarryOut bld dst t1 t2 ca
    if ovCond then isAddSubOV bld t1 t2 dst else ()
    if updateCond then setCR0Reg bld dst else ()
  }

let addi ins (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (dst, src1, simm) = transThreeOprs ins bld
    let cond = src1 == AST.num0 bld.RegType
    dst := (AST.ite cond simm (src1 .+ simm))
  }

let addic ins updateCond (bld: ILowUIRBuilder) =
  lift bld ins {
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

let addis ins (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (dst, src1, simm) = transThreeOprs ins bld
    let cond = src1 == AST.num0 bld.RegType
    let simm = shiftedImm bld true simm
    dst := (AST.ite cond simm (src1 .+ simm))
  }

let addme ins updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (dst, src) = transTwoOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    let ca = carryIn bld
    t1 := src
    t2 := AST.not (AST.num0 bld.RegType)
    addWithCarryOut bld dst t1 t2 ca
    if ovCond then isAddSubOV bld t1 t2 dst else ()
    if updateCond then setCR0Reg bld dst else ()
  }

let addze ins updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (dst, src) = transTwoOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    let ca = carryIn bld
    t1 := src
    t2 := AST.num0 bld.RegType
    addWithCarryOut bld dst t1 t2 ca
    if ovCond then isAddSubOV bld t1 t2 dst else ()
    if updateCond then setCR0Reg bld dst else ()
  }

let andx ins updateCond bld =
  lift bld ins {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    dst := src1 .& src2
    if updateCond then setCR0Reg bld dst else ()
  }

let andc ins updateCond bld =
  lift bld ins {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    dst := src1 .& AST.not (src2)
    if updateCond then setCR0Reg bld dst else ()
  }

let andidot ins bld =
  lift bld ins {
    let struct (dst, src, uimm) = transThreeOprs ins bld
    dst := src .& uimm
    setCR0Reg bld dst
  }

let andisdot ins bld =
  lift bld ins {
    let struct (dst, src, uimm) = transThreeOprs ins bld
    let uimm = shiftedImm bld false uimm
    dst := src .& uimm
    setCR0Reg bld dst
  }

let b ins (bld: ILowUIRBuilder) lk =
  lift bld ins {
    let addr = transOneOpr ins bld
    let lr = regVar bld Register.LR
    if lk then
      lr := numU64 (ins.Address + 4UL) bld.RegType
      AST.interjmp addr InterJmpKind.IsCall
    else
      AST.interjmp addr InterJmpKind.Base
  }

let bc ins (bld: ILowUIRBuilder) aa lk =
  lift bld ins {
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

/// bclr/bclrl, which go to LR with its low two bits cleared where BO says the
/// counter and the CR bit allow it. bclrl reads LR before it writes the next
/// instruction's address there, which it does whether it branches or not.
let bclr ins (bld: ILowUIRBuilder) lk =
  lift bld ins {
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
    if lk then append bld { lr := nia } else ()
    let kind = if lk then InterJmpKind.IsCall else InterJmpKind.IsRet
    AST.interjmp temp kind
  }

/// bcctr/bcctrl, which go to CTR with its low two bits cleared where the CR
/// bit BO names allows it; bcctrl, like bclrl, links either way.
let bcctr ins (bld: ILowUIRBuilder) lk =
  lift bld ins {
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
    if lk then append bld { lr := nia } else ()
    let kind = if lk then InterJmpKind.IsCall else InterJmpKind.Base
    AST.interjmp temp kind
  }

/// Records the outcome of a comparison in a CR field. cmpOp gives the "less
/// than" and "greater than" tests, which differ between the signed and the
/// unsigned forms; equality is whatever neither of those is.
let private compare ins bld ltOp gtOp narrow =
  lift bld ins {
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
let cmp ins bld narrow = compare ins bld AST.slt AST.sgt narrow

/// An unsigned compare, narrowing as cmp does.
let cmpl ins bld narrow = compare ins bld AST.lt AST.gt narrow

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

let cntlzw ins updateCond bld =
  lift bld ins {
    let struct (ra, rs) = transTwoOprs ins bld
    countLeadingZeros bld ra rs 32<rt>
    if updateCond then setCR0Reg bld ra else ()
  }

let cntlzd ins updateCond bld =
  lift bld ins {
    let struct (ra, rs) = transTwoOprs ins bld
    countLeadingZeros bld ra rs 64<rt>
    if updateCond then setCR0Reg bld ra else ()
  }

let crclr ins bld =
  lift bld ins {
    let crbd = transOneOpr ins bld
    crbd := AST.b0
  }

let cror ins bld =
  lift bld ins {
    let struct (crbD, crbA, crbB) = transThreeOprs ins bld
    crbD := crbA .| crbB
  }

let crorc ins bld =
  lift bld ins {
    let struct (crbD, crbA, crbB) = transThreeOprs ins bld
    crbD := crbA .| (AST.not crbB)
  }

let creqv ins bld =
  lift bld ins {
    let struct (crbD, crbA, crbB) = transThreeOprs ins bld
    crbD := crbA <+> AST.not (crbB)
  }

let crset ins bld =
  lift bld ins {
    let crbD = transOneOpr ins bld
    crbD := crbD <+> AST.not (crbD)
  }

let crnand ins bld =
  lift bld ins {
    let struct (crbD, crbA, crbB) = transThreeOprs ins bld
    crbD := AST.not (crbA .& crbB)
  }

let crnor ins bld =
  lift bld ins {
    let struct (crbD, crbA, crbB) = transThreeOprs ins bld
    crbD := AST.not (crbA .| crbB)
  }

let crnot ins bld =
  lift bld ins {
    let struct (crbD, crbA) = transTwoOprs ins bld
    crbD := AST.not crbA
  }

let crxor ins bld =
  lift bld ins {
    let struct (crbD, crbA, crbB) = transThreeOprs ins bld
    crbD := crbA <+> crbB
  }

let crand ins bld =
  lift bld ins {
    let struct (crbD, crbA, crbB) = transThreeOprs ins bld
    crbD := crbA .& crbB
  }

let crandc ins bld =
  lift bld ins {
    let struct (crbD, crbA, crbB) = transThreeOprs ins bld
    crbD := crbA .& (AST.not crbB)
  }

(* crmove crbD, crbA = cror crbD, crbA, crbA: copies one CR bit to another. *)
let crmove ins bld =
  lift bld ins {
    let struct (crbD, crbA) = transTwoOprs ins bld
    crbD := crbA
  }

/// A divide of the given width. A zero divisor (and the signed overflow case)
/// leaves the destination alone, as the architecture leaves it undefined.
let private divide ins updateCond ovCond (bld: ILowUIRBuilder) width signed =
  lift bld ins {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let a = AST.xtlo width src1
    let b = AST.xtlo width src2
    let zero = b == AST.num0 width
    let invalid =
      if signed then
        let min = AST.num1 width << numI32 (int width - 1) width
        zero .| ((a == min) .& (b == AST.not (AST.num0 width)))
      else
        zero
    if ovCond && signed then isSignedDivOV bld width a b
    elif ovCond then isUnsignedDivOV bld width b
    else ()
    let q = if signed then a ?/ b else a ./ b
    let q = if signed then AST.sext bld.RegType q else AST.zext bld.RegType q
    dst := AST.ite invalid dst q
    if updateCond then setCR0Reg bld dst else ()
  }

let divw ins updateCond ovCond bld =
  divide ins updateCond ovCond bld 32<rt> true

let divwu ins updateCond ovCond bld =
  divide ins updateCond ovCond bld 32<rt> false

let divd ins updateCond ovCond bld =
  divide ins updateCond ovCond bld 64<rt> true

let divdu ins updateCond ovCond bld =
  divide ins updateCond ovCond bld 64<rt> false

/// Sign-extends the low `width` bits of rs into a whole register.
let private signExtend ins updateCond (bld: ILowUIRBuilder) width =
  lift bld ins {
    let struct (ra, rs) = transTwoOprs ins bld
    let tmp = tmpVar bld width
    tmp := AST.xtlo width rs
    ra := AST.sext bld.RegType tmp
    if updateCond then setCR0Reg bld ra else ()
  }

let extsb ins updateCond bld = signExtend ins updateCond bld 8<rt>

let extsh ins updateCond bld =
  signExtend ins updateCond bld 16<rt>

let extsw ins updateCond bld =
  signExtend ins updateCond bld 32<rt>

let eqvx ins updateCond bld =
  lift bld ins {
    let struct (ra, rs, rb) = transThreeOprs ins bld
    ra := AST.not (rs <+> rb)
    if updateCond then setCR0Reg bld ra else ()
  }

let fabs ins updateCond bld =
  lift bld ins {
    let struct (frd, frb) = transTwoOprs ins bld
    frd := frb .& numU64 0x7fffffffffffffffUL 64<rt>
    if updateCond then setCR1Reg bld else ()
  }

/// The quiet NaN an invalid operation answers with. It is positive here, where
/// the FMA primitive -- written for a machine whose indefinite is negative --
/// hands back the other one, so a result that turned into a NaN on its own has
/// to be rewritten. A NaN that arrived in an operand is not: that one
/// propagates, quieted, which the primitive already does.
let internal defaultQNaN = numU64 0x7ff8000000000000UL 64<rt>

let internal noNaNOperand a b c =
  AST.not (IEEE754Double.isNaN a .| IEEE754Double.isNaN b
           .| IEEE754Double.isNaN c)

let fmr ins updateCond bld =
  lift bld ins {
    let struct (dst, src) = transTwoOprs ins bld
    dst := src
    if updateCond then setCR1Reg bld else ()
  }

let fnabs ins updateCond bld =
  lift bld ins {
    let struct (frd, frb) = transTwoOprs ins bld
    frd := frb .| numU64 0x8000000000000000UL 64<rt>
    if updateCond then setCR1Reg bld else ()
  }

let fneg ins updateCond bld =
  lift bld ins {
    let struct (frd, frb) = transTwoOprs ins bld
    floatingNeg bld frd frb 64<rt>
    if updateCond then setCR1Reg bld else ()
  }

let fsel ins updateCond bld =
  lift bld ins {
    let struct(frd, fra, frc, frb) = transFourOprs ins bld
    let cond = AST.fge fra (AST.num0 64<rt>)
    frd := AST.ite cond frc frb
    if updateCond then setCR1Reg bld else ()
  }

let lbz ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let ea = transEAWithOffset o2 bld
    let dst = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    dst := AST.zext bld.RegType (loadNative bld 8<rt> tmpEA)
  }

let lbzu ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
    let rd = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    rd := AST.zext bld.RegType (loadNative bld 8<rt> tmpEA)
    ra := tmpEA
  }

let lbzux ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rd = transOpr bld o1
    let struct (ea, ra) = transEAWithIndexRegForUpdate o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    rd := AST.zext bld.RegType (loadNative bld 8<rt> tmpEA)
    ra := tmpEA
  }

let lbzx ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rd = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    rd := AST.zext bld.RegType (loadNative bld 8<rt> tmpEA)
  }

let lfd ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let ea = transEAWithOffset o2 bld
    let dst = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    dst := loadNative bld 64<rt> tmpEA
  }

let lfdu ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
    let dst = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    dst := loadNative bld 64<rt> tmpEA
    ra := tmpEA
  }

let lfdux ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let dst = transOpr bld o1
    let struct (ea, ra) = transEAWithIndexRegForUpdate o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    dst := loadNative bld 64<rt> tmpEA
    ra := tmpEA
  }

let lfdx ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let dst = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    dst := loadNative bld 64<rt> tmpEA
  }

/// LFIWAX and LFIWZX move a word of memory into a floating register as the
/// integer it is -- no conversion, the destination holding a bit pattern the
/// convert instructions read afterwards. The two differ only in how the word
/// reaches sixty-four bits: signed for LFIWAX, zero-filled for LFIWZX.
let private lfiwx ins bld ext =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let frd = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    frd := ext 64<rt> (loadNative bld 32<rt> tmpEA)
  }

let lfiwax ins bld = lfiwx ins bld AST.sext

let lfiwzx ins bld = lfiwx ins bld AST.zext

/// A load widens a single exactly, preserving an SNaN as signaling.
let doubleOfSingle bld word =
  let w = tmpVar bld 32<rt>
  let res = tmpVar bld 64<rt>
  append bld {
    w := word
    let isNaN =
      (w .& numU32 0x7f800000u 32<rt> == numU32 0x7f800000u 32<rt>)
      .& (w .& numU32 0x007fffffu 32<rt> != AST.num0 32<rt>)
    let w64 = AST.zext 64<rt> w
    let nan =
      ((w64 .& numU64 0x80000000UL 64<rt>) << numI32 32 64<rt>)
      .| numU64 0x7ff0000000000000UL 64<rt>
      .| ((w64 .& numU64 0x007fffffUL 64<rt>) << numI32 29 64<rt>)
    res := AST.ite isNaN nan (AST.cast CastKind.FloatCast 64<rt> w)
  }
  res

let lfs ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let ea = transEAWithOffset o2 bld
    let dst = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    let v = loadNative bld 32<rt> tmpEA
    tmpEA := ea
    dst := doubleOfSingle bld v
  }

let lfsu ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
    let frd = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    let v = loadNative bld 32<rt> tmpEA
    tmpEA := ea
    frd := doubleOfSingle bld v
    ra := tmpEA
  }

let lfsux ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let frd = transOpr bld o1
    let struct (ea, ra) = transEAWithIndexRegForUpdate o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    let v = loadNative bld 32<rt> tmpEA
    tmpEA := ea
    frd := doubleOfSingle bld v
    ra := tmpEA
  }

let lfsx ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let frd = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    let v = loadNative bld 32<rt> tmpEA
    tmpEA := ea
    frd := doubleOfSingle bld v
  }

let lha ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let ea = transEAWithOffset o2 bld
    let rd = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    rd := AST.sext bld.RegType (loadNative bld 16<rt> tmpEA)
  }

let lhau ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
    let rd = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    rd := AST.sext bld.RegType (loadNative bld 16<rt> tmpEA)
    ra := tmpEA
  }

let lhaux ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rd = transOpr bld o1
    let struct (ea, ra) = transEAWithIndexRegForUpdate o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    rd := AST.sext bld.RegType (loadNative bld 16<rt> tmpEA)
    ra := tmpEA
  }

let lhax ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rd = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    rd := AST.sext bld.RegType (loadNative bld 16<rt> tmpEA)
  }

let lhbrx ins bld =
  lift bld ins {
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

let lhz ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let ea = transEAWithOffset o2 bld
    let rd = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    rd := AST.zext bld.RegType (loadNative bld 16<rt> tmpEA)
  }

let lhzu ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
    let rd = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    rd := AST.zext bld.RegType (loadNative bld 16<rt> tmpEA)
    ra := ea
  }

let lhzux ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rd = transOpr bld o1
    let struct (ea, rA) = transEAWithIndexRegForUpdate o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    rd := AST.zext bld.RegType (loadNative bld 16<rt> tmpEA)
    rA := tmpEA
  }

let lhzx ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rd = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    rd := AST.zext bld.RegType (loadNative bld 16<rt> tmpEA)
  }

let li ins bld =
  lift bld ins {
    let struct (dst, simm) = transTwoOprs ins bld
    dst := simm
  }

let lis ins bld =
  lift bld ins {
    let struct (dst, simm) = transTwoOprs ins bld
    let simm = shiftedImm bld true simm
    dst := simm
  }

/// lwarx/ldarx: a load that arms the reservation a following store-conditional
/// checks. RES says that one is held, ExMonAddr where and ExMonVal over what
/// value, which is kept register-wide whatever the access size.
let private loadReserve ins (bld: ILowUIRBuilder) size =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rd = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    let tmpVal = tmpVar bld bld.RegType
    tmpEA := ea
    tmpVal := AST.zext bld.RegType (loadNative bld size tmpEA)
    regVar bld Register.RES := AST.b1
    regVar bld Register.ExMonAddr := tmpEA
    regVar bld Register.ExMonVal := tmpVal
    rd := tmpVal
  }

let lwarx ins bld = loadReserve ins bld 32<rt>

let ldarx ins bld = loadReserve ins bld 64<rt>

let lbarx ins bld = loadReserve ins bld 8<rt>

let lharx ins bld = loadReserve ins bld 16<rt>

/// The bytes of a value of the given width, in reverse order. revConcat places
/// the array's first element in the result's least significant byte, so taking
/// the value's most significant byte first is what turns the order around.
let private reversedBytes value width =
  let n = int width / 8
  Array.init n (fun i -> AST.extract value 8<rt> ((n - 1 - i) * 8))
  |> AST.revConcat

/// lwbrx/ldbrx: a load whose bytes come back in the opposite order.
let private loadByteReverse ins (bld: ILowUIRBuilder) size =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rd = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    let tmpMem = tmpVar bld size
    tmpEA := ea
    tmpMem := loadNative bld size tmpEA
    rd := AST.zext bld.RegType (reversedBytes tmpMem size)
  }

let lwbrx ins bld = loadByteReverse ins bld 32<rt>

let ldbrx ins bld = loadByteReverse ins bld 64<rt>

/// A d(rA) load of `size` bits, widened into rD by ext; when update is set the
/// effective address is also written back to rA.
let private loadOffset ins (bld: ILowUIRBuilder) size ext update =
  lift bld ins {
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
let private loadIndexed ins (bld: ILowUIRBuilder) size ext update =
  lift bld ins {
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

let lwz ins bld = loadOffset ins bld 32<rt> AST.zext false

let lwzu ins bld = loadOffset ins bld 32<rt> AST.zext true

let lwzux ins bld = loadIndexed ins bld 32<rt> AST.zext true

let lwzx ins bld = loadIndexed ins bld 32<rt> AST.zext false

/// eciwx, the external control word read, which fetches a word from the device
/// the EAR names at (rA|0)+rB. With no device to model, the storage at that
/// address stands in for it.
let eciwx ins bld = loadIndexed ins bld 32<rt> AST.zext false

/// The base of a string operation: rA, or zero when the field names r0.
let private stringBase (bld: ILowUIRBuilder) ra =
  if ra = Register.R0 then AST.num0 bld.RegType else regVar bld ra

/// The word a string load of a known count leaves in one register: its first n
/// bytes come from ea on, most significant first, and the rest are zero. The
/// concatenation takes its bytes least significant first, so byte i of the
/// word is built from position 3 - i.
let private stringWordN (bld: ILowUIRBuilder) ea n =
  if n = 4 then
    loadNative bld 32<rt> ea
  else
    Array.init 4 (fun k ->
      let i = 3 - k
      if i < n then loadNative bld 8<rt> (ea .+ numI32 i bld.RegType)
      else AST.num0 8<rt>)
    |> AST.revConcat

/// The register n places after r, wrapping from r31 around to r0, which is how
/// the string operations run through the register file.
let private gprAfter (r: Register) n =
  getRegister (uint32 ((int r + n) % 32))

/// The same word when the count is known only at run time: a byte the count
/// does not reach is zero.
let private stringWord (bld: ILowUIRBuilder) ea cnt =
  Array.init 4 (fun k ->
    let i = 3 - k
    let inRange = cnt .> numI32 i bld.RegType
    let byte = loadNative bld 8<rt> (ea .+ numI32 i bld.RegType)
    AST.ite inRange byte (AST.num0 8<rt>))
  |> AST.revConcat

/// lswi, which loads NB bytes (32 when NB is zero) from (rA|0) into the low
/// words of the registers from rD on, wrapping from r31 to r0, and zeroes what
/// is left of the last word.
let lswi (ins: Instruction) (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (rd, ra, nb) =
      match ins.Operands with
      | ThreeOperands(OprReg rd, OprReg ra, OprImm nb) ->
        struct (rd, ra, int nb)
      | _ ->
        raise InvalidOperandException
    let n = if nb = 0 then 32 else nb
    let rt = bld.RegType
    let ea = tmpVar bld rt
    ea := stringBase bld ra
    for i in 0 .. (n + 3) / 4 - 1 do
      let word = stringWordN bld (ea .+ numI32 (4 * i) rt) (min 4 (n - 4 * i))
      regVar bld (gprAfter rd i) := AST.zext rt word
  }

/// lswx, whose byte count is XER[57:63] and so is known only at run time: each
/// register in turn is loaded once the count reaches it, and a count of zero
/// loads nothing.
let lswx (ins: Instruction) (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (rd, ra, rb) =
      match ins.Operands with
      | ThreeOperands(OprReg rd, ra, rb) -> struct (rd, ra, rb)
      | _ -> raise InvalidOperandException
    let rt = bld.RegType
    let ea = tmpVar bld rt
    let cnt = tmpVar bld rt
    ea := transEAWithIndexReg ra rb bld
    cnt := AST.zext rt (AST.xtlo 7<rt> (regVar bld Register.XER))
    for i in 0 .. 31 do
      let off = numI32 (4 * i) rt
      let word = stringWord bld (ea .+ off) (cnt .- off)
      let reg = regVar bld (gprAfter rd i)
      _when bld "Lswx" (cnt .> off) (block { reg := AST.zext rt word })
  }

let lwa ins bld = loadOffset ins bld 32<rt> AST.sext false

let lwax ins bld = loadIndexed ins bld 32<rt> AST.sext false

let lwaux ins bld = loadIndexed ins bld 32<rt> AST.sext true

let ld ins bld = loadOffset ins bld 64<rt> AST.zext false

let ldu ins bld = loadOffset ins bld 64<rt> AST.zext true

let ldx ins bld = loadIndexed ins bld 64<rt> AST.zext false

let ldux ins bld = loadIndexed ins bld 64<rt> AST.zext true

let mcrf ins bld =
  lift bld ins {
    let struct ((crd0, crd1, crd2, crd3),
                (crs0, crs1, crs2, crs3)) = transCondTwoOprs ins bld
    crd0 := crs0
    crd1 := crs1
    crd2 := crs2
    crd3 := crs3
  }

/// Whether an FPSCR bit, numbered from the least significant, is one of the
/// exception bits: FX and OX through VXVC (bits 0 and 3 to 12 as the
/// architecture counts them) and VXSOFT, VXSQRT, and VXCVI (bits 21 to 23).
/// FEX and VX are summaries the hardware recomputes, and the rest are status
/// and control.
let private isFPSCRExceptionBit pos =
  match pos with
  | 31 | 28 | 27 | 26 | 25 | 24 | 23 | 22 | 21 | 20 | 19 | 10 | 9 | 8 -> true
  | _ -> false

/// Recomputes the two summary bits of the FPSCR after its other bits have
/// changed: VX, whether any invalid-operation exception bit is set, and FEX,
/// whether any exception bit is set together with its enable.
let private setFPSCRSummary bld =
  let fpscr = regVar bld Register.FPSCR
  let bit pos = AST.extract fpscr 1<rt> pos
  let anyOf ps = List.reduce (.|) (List.map bit ps)
  let enabled (e, en) = bit e .& bit en
  append bld {
    let vx = tmpVar bld 1<rt>
    vx := anyOf [ 24; 23; 22; 21; 20; 19; 10; 9; 8 ]
    AST.extract fpscr 1<rt> 29 := vx
    let others = List.map enabled [ 28, 6; 27, 5; 26, 4; 25, 3 ]
    AST.extract fpscr 1<rt> 30 := List.reduce (.|) ((vx .& bit 7) :: others)
  }

/// mcrfs, which copies a four-bit field of the FPSCR into a CR field and then
/// clears the exception bits it copied, which may clear the VX summary too.
/// The parser names the FPSCR field as if it were a CR field, so its number is
/// read off that register.
let mcrfs (ins: Instruction) bld =
  lift bld ins {
    let struct (crd, fld) =
      match ins.Operands with
      | TwoOperands(OprReg d, OprReg s) ->
        struct (transCRxToExpr bld d, int s - int Register.CR0)
      | _ ->
        raise InvalidOperandException
    let crd0, crd1, crd2, crd3 = crd
    let fpscr = regVar bld Register.FPSCR
    let hi = 31 - 4 * fld
    crd0 := AST.extract fpscr 1<rt> hi
    crd1 := AST.extract fpscr 1<rt> (hi - 1)
    crd2 := AST.extract fpscr 1<rt> (hi - 2)
    crd3 := AST.extract fpscr 1<rt> (hi - 3)
    for pos in List.filter isFPSCRExceptionBit [ hi - 3 .. hi ] do
      AST.extract fpscr 1<rt> pos := AST.b0
    setFPSCRSummary bld
  }

let mcrxr ins bld =
  lift bld ins {
    let crd0, crd1, crd2, crd3 = transCondOneOpr ins bld
    let xer = regVar bld Register.XER
    crd0 := AST.extract xer 1<rt> 31
    crd1 := AST.extract xer 1<rt> 30
    crd2 := AST.extract xer 1<rt> 29
    crd3 := AST.extract xer 1<rt> 28
    xer := xer .& numI32 0x0fffffff 32<rt>
  }

let mfcr ins (bld: ILowUIRBuilder) =
  lift bld ins {
    let dst = transOneOpr ins bld
    let cr = tmpVar bld 32<rt>
    getCRRegValue bld cr
    dst := AST.zext bld.RegType cr
  }

let mfctr ins bld =
  lift bld ins {
    let dst = transOneOpr ins bld
    let ctr = regVar bld Register.CTR
    dst := ctr
  }

let mflr ins bld =
  lift bld ins {
    let dst = transOneOpr ins bld
    let lr = regVar bld Register.LR
    dst := lr
  }

/// A special register read into a general one: one narrower than a register
/// fills the low bits and zeroes the rest, as mfspr does with a 32-bit SPR.
let private widened (bld: ILowUIRBuilder) spr =
  if Expr.typeOf spr = bld.RegType then spr else AST.zext bld.RegType spr

/// A general register written into a special one, which takes as many of its
/// low bits as it is wide, as mtspr does with a 32-bit SPR.
let private narrowed spr rs =
  let width = Expr.typeOf spr
  if Expr.typeOf rs = width then rs else AST.xtlo width rs

let nop (ins: Instruction) bld =
  lift bld ins {
  }

/// <summary>
/// Whether an SPR number names one of the server registers a program may
/// reach -- DSCR, AMR, CTRL, SPRG3, PPR and PPR32, those of the event-based
/// branch and target address facilities, and the reserved 808 to 811 --
/// which only a 64-bit processor has: on a 32-bit one, an mfspr or mtspr
/// naming one names no register at all.
/// </summary>
let private isServerSPR (spr: Imm) =
  match spr with
  | 3UL | 13UL | 136UL | 259UL | 815UL | 896UL | 898UL -> true
  | _ -> spr >= 800UL && spr <= 811UL

/// SPRs 808 to 811, which are reserved and whose accesses are no-ops.
let private isNoOpSPR (spr: Imm) = spr >= 808UL && spr <= 811UL

/// What mfspr reads through an SPR number: BESCR whole through 800, 802 and
/// 806, its upper word through 801 and 803 -- the numbers that set and reset
/// its bits read it as it is -- and otherwise the register the number names.
let private sprToRead bld spr =
  let bescr = regVar bld Register.BESCR
  match spr with
  | 800UL | 802UL | 806UL -> bescr
  | 801UL | 803UL -> AST.xthi 32<rt> bescr
  | 804UL -> regVar bld Register.EBBHR
  | 805UL -> regVar bld Register.EBBRR
  | 815UL -> regVar bld Register.TAR
  | 3UL -> regVar bld Register.DSCR
  | 13UL -> regVar bld Register.AMR
  | 136UL -> regVar bld Register.CTRL
  | 259UL -> regVar bld Register.SPRG3
  | 896UL -> regVar bld Register.PPR
  | 898UL -> AST.xthi 32<rt> (regVar bld Register.PPR)
  | _ -> getSPRReg bld spr

let mfspr (ins: Instruction) (bld: ILowUIRBuilder) =
  match ins.Operands with
  | TwoOperands(_, OprImm spr) when isServerSPR spr && bld.RegType = 32<rt> ->
    sideEffects ins bld UndefinedInstruction
  | TwoOperands(_, OprImm spr) when isNoOpSPR spr ->
    nop ins bld
  | TwoOperands(o1, OprImm spr) ->
    lift bld ins {
      let dst = transOpr bld o1
      dst := widened bld (sprToRead bld spr)
    }
  | _ ->
    raise InvalidOperandException

(* mftb/mftbu read the 64-bit Time Base into rD. There is no real time base to
   read, so the value is left to the emulator via a ClockCounterRead side effect
   carrying the destination register and which 32-bit half (lower for mftb,
   upper for mftbu). *)
let mftb (ins: Instruction) bld =
  let rid =
    match ins.Operands with
    | TwoOperands(OprReg rd, _) -> Register.toRegID rd
    | _ -> raise InvalidOperandException
  sideEffects ins bld (ClockCounterRead(Some(rid, false)))

let mftbu (ins: Instruction) bld =
  let rid =
    match ins.Operands with
    | OneOperand(OprReg rd) -> Register.toRegID rd
    | _ -> raise InvalidOperandException
  sideEffects ins bld (ClockCounterRead(Some(rid, true)))

let mfxer ins bld =
  lift bld ins {
    let dst = transOneOpr ins bld
    let xer = regVar bld Register.XER
    dst := widened bld xer
  }

let mr ins bld =
  lift bld ins {
    let struct (dst, src) = transTwoOprs ins bld
    dst := src .| src
  }

let mtctr ins bld =
  lift bld ins {
    let src = transOneOpr ins bld
    let ctr = regVar bld Register.CTR
    ctr := src
  }

/// An SPR number that names a register of its own, and rS sized to it.
let private namedSPR bld spr rs =
  let reg = getSPRReg bld spr
  struct (reg, narrowed reg rs)

/// <summary>
/// What mtspr writes through an SPR number, and the value: rS into the
/// register the number names, but through the numbers that set (800, 801)
/// and reset (802, 803) bits of BESCR, the ones of rS turn on or off the bits
/// of the whole register or, from rS's low word, of its upper word.
/// </summary>
let private sprToWrite bld spr rs =
  let bescr = regVar bld Register.BESCR
  let ppr = regVar bld Register.PPR
  let upper () = rs << numI32 32 64<rt>
  match spr with
  | 800UL -> struct (bescr, bescr .| rs)
  | 801UL -> struct (bescr, bescr .| upper ())
  | 802UL -> struct (bescr, bescr .& AST.not rs)
  | 803UL -> struct (bescr, bescr .& AST.not (upper ()))
  | 804UL -> struct (regVar bld Register.EBBHR, rs)
  | 805UL -> struct (regVar bld Register.EBBRR, rs)
  | 806UL -> struct (bescr, rs)
  | 815UL -> struct (regVar bld Register.TAR, rs)
  | 3UL -> struct (regVar bld Register.DSCR, rs)
  | 13UL -> struct (regVar bld Register.AMR, rs)
  | 896UL -> struct (ppr, rs)
  | 898UL -> struct (ppr, (upper ()) .| (ppr .& numU64 0xffffffffUL 64<rt>))
  | _ -> namedSPR bld spr rs

/// mtspr. PVR (287) cannot be written at all: an mtspr naming it is a
/// privileged instruction, which no register file here can stand for.
let mtspr (ins: Instruction) (bld: ILowUIRBuilder) =
  match ins.Operands with
  | TwoOperands(OprImm 287UL, _) ->
    sideEffects ins bld UnsupportedInstruction
  | TwoOperands(OprImm spr, _) when isServerSPR spr && bld.RegType = 32<rt> ->
    sideEffects ins bld UndefinedInstruction
  | TwoOperands(OprImm 136UL, _) | TwoOperands(OprImm 259UL, _) ->
    sideEffects ins bld UndefinedInstruction
  | TwoOperands(OprImm spr, _) when isNoOpSPR spr ->
    nop ins bld
  | TwoOperands(OprImm spr, o2) ->
    lift bld ins {
      let struct (dst, value) = sprToWrite bld spr (transOpr bld o2)
      dst := value
    }
  | _ ->
    raise InvalidOperandException

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

let mtcrf ins bld =
  lift bld ins {
    let struct (crm, rs) = transTwoOprs ins bld
    let mask = tmpVar bld 32<rt>
    let cr = tmpVar bld 32<rt>
    mask := crmMask bld crm
    getCRRegValue bld cr
    cr := (AST.xtlo 32<rt> rs .& mask) .| (cr .& AST.not mask)
    setCRRegValue bld cr
  }

let mtlr ins bld =
  lift bld ins {
    let src = transOneOpr ins bld
    let lr = regVar bld Register.LR
    lr := src
  }

/// mtxer, which writes the low word of rS into XER. A 32-bit processor has
/// no OV32 or CA32 (bits 19 and 18 here) to write.
let mtxer ins (bld: ILowUIRBuilder) =
  lift bld ins {
    let src = transOneOpr ins bld
    let xer = regVar bld Register.XER
    let word = narrowed xer src
    if bld.RegType = 64<rt> then xer := word
    else xer := word .& numU32 0xfff3ffffu 32<rt>
  }

/// The high half of a product of two `width`-bit operands, taken in a double-
/// width temporary and placed in a whole register. A 64-bit guest leaves the
/// upper half of a mulhw's result undefined, so widening it either way is
/// allowed; sign- or zero-extending matches the operands' signedness.
let private mulHigh ins updateCond (bld: ILowUIRBuilder) width signed =
  lift bld ins {
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

let mulhw ins updateCond bld =
  mulHigh ins updateCond bld 32<rt> true

let mulhwu ins updateCond bld =
  mulHigh ins updateCond bld 32<rt> false

let mulhd ins updateCond bld =
  mulHigh ins updateCond bld 64<rt> true

let mulhdu ins updateCond bld =
  mulHigh ins updateCond bld 64<rt> false

let mulli ins bld =
  lift bld ins {
    let struct (dst, ra, simm) = transThreeOprs ins bld
    dst := ra .* simm
  }

/// mullw takes two word operands and, on a 64-bit part, keeps the whole
/// doubleword product; on a 32-bit one only the low word exists.
let mullw ins updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let tmp = tmpVar bld 64<rt>
    if ovCond then isMulwOV bld src1 src2 else ()
    let a = AST.sext 64<rt> (AST.xtlo 32<rt> src1)
    let b = AST.sext 64<rt> (AST.xtlo 32<rt> src2)
    tmp := a .* b
    dst := AST.xtlo bld.RegType tmp
    if updateCond then setCR0Reg bld dst else ()
  }

let mulld ins updateCond ovCond bld =
  lift bld ins {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    if ovCond then isMuldOV bld src1 src2 else ()
    dst := src1 .* src2
    if updateCond then setCR0Reg bld dst else ()
  }

let nand ins updateCond bld =
  lift bld ins {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    dst := AST.not (src1 .& src2)
    if updateCond then setCR0Reg bld dst else ()
  }

let neg ins updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (dst, src) = transTwoOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    t1 := AST.not src
    t2 := AST.num1 bld.RegType
    dst := t1 .+ t2
    if ovCond then isAddSubOV bld t1 t2 dst else ()
    if updateCond then setCR0Reg bld dst else ()
  }

let nor ins updateCond bld =
  lift bld ins {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    dst := AST.not (src1 .| src2)
    if updateCond then setCR0Reg bld dst else ()
  }

/// The number of bytes dcbz clears. The architecture leaves the size to the
/// implementation and has software discover it from AT_DCACHEBSIZE; this is
/// the size every 64-bit Power part uses.
let [<Literal>] private CacheBlockSize = 128

/// dcbz, the one cache-management form with an effect on storage: it clears the
/// block the address falls in. Modeled as clearing that many bytes, in
/// doublewords, from the block-aligned address.
let dcbz ins (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let ea = transEAWithIndexReg o1 o2 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea .& AST.not (numI32 (CacheBlockSize - 1) bld.RegType)
    for i in 0 .. (CacheBlockSize / 8) - 1 do
      let addr = tmpEA .+ numI32 (i * 8) bld.RegType
      loadNative bld 64<rt> addr := AST.num0 64<rt>
  }

let orx ins updateCond bld =
  lift bld ins {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    dst := src1 .| src2
    if updateCond then setCR0Reg bld dst else ()
  }

let orc ins updateCond bld =
  lift bld ins {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    dst := src1 .| AST.not (src2)
    if updateCond then setCR0Reg bld dst else ()
  }

let ori ins bld =
  lift bld ins {
    let struct (dst, src, uimm) = transThreeOprs ins bld
    let uimm = AST.zext bld.RegType (AST.xtlo 16<rt> uimm)
    dst := src .| uimm
  }

let oris ins bld =
  lift bld ins {
    let struct (dst, src, uimm) = transThreeOprs ins bld
    let uimm = shiftedImm bld false uimm
    dst := src .| uimm
  }

(* The rotate-word forms rotate the low word of rS. On a 64-bit part the
   rotated word is doubled up into both halves before MASK(mb+32, me+32) is
   applied, so a wrapping mask (mb > me) lets rotated bits into the high word;
   on a 32-bit part it is a plain word operation. *)
let private rotatedWord (bld: ILowUIRBuilder) rs n =
  let rol = tmpVar bld 32<rt>
  append bld { rol := rotateLeft (AST.xtlo 32<rt> rs) n }
  if bld.RegType = 64<rt> then AST.concat rol rol else rol

let private wordMask (bld: ILowUIRBuilder) mb me =
  if bld.RegType = 64<rt> then getWordMaskIn64 mb me else getExtMask mb me

let rlwinm ins updateCond (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (ra, rs, sh, mb, me) = transFiveOprs ins bld
    let rol = rotatedWord bld rs (AST.xtlo 32<rt> sh)
    ra := rol .& wordMask bld mb me
    if updateCond then setCR0Reg bld ra else ()
  }

/// rlwimi merges the rotated word into rA under the mask, which is what makes
/// it the instruction a compiler reaches for when it inserts a bit field.
let rlwimi ins updateCond (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (ra, rs, sh, mb, me) = transFiveOprs ins bld
    let m = wordMask bld mb me
    let rol = rotatedWord bld rs (AST.xtlo 32<rt> sh)
    let merged = tmpVar bld bld.RegType
    merged := (rol .& m) .| (ra .& AST.not m)
    ra := merged
    if updateCond then setCR0Reg bld ra else ()
  }

let rlwnm ins updateCond (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (ra, rs, rb, mb, me) = transFiveOprs ins bld
    let n = AST.xtlo 32<rt> rb .& numI32 0x1f 32<rt>
    let rol = rotatedWord bld rs n
    ra := rol .& wordMask bld mb me
    if updateCond then setCR0Reg bld ra else ()
  }

let rotlw ins (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (ra, rs, rb) = transThreeOprs ins bld
    let n = AST.xtlo 32<rt> rb .& numI32 0x1f 32<rt>
    let rol = rotateLeft (AST.xtlo 32<rt> rs) n
    ra := AST.zext bld.RegType rol (* no mask *)
  }

(* The rotate-doubleword forms take a six-bit shift and a six-bit mask bound,
   and the mask is a constant of the immediate forms. *)
let rldicl ins updateCond bld =
  lift bld ins {
    let struct (ra, rs, sh, mb) = transFourOprs ins bld
    let rol = tmpVar bld 64<rt>
    rol := rotateLeft64 rs sh
    ra := rol .& getExtMask64 mb (numI32 63 64<rt>)
    if updateCond then setCR0Reg bld ra else ()
  }

let rldicr ins updateCond bld =
  lift bld ins {
    let struct (ra, rs, sh, me) = transFourOprs ins bld
    let rol = tmpVar bld 64<rt>
    rol := rotateLeft64 rs sh
    ra := rol .& getExtMask64 (AST.num0 64<rt>) me
    if updateCond then setCR0Reg bld ra else ()
  }

/// The end of an rldic/rldimi mask, which the shift amount fixes at 63 - sh.
let private maskEndOfShift sh =
  match sh with
  | Num(Value = n) -> numI32 (63 - int (n.ToUInt64())) 64<rt>
  | _ -> raise InvalidExprException

let rldic ins updateCond bld =
  lift bld ins {
    let struct (ra, rs, sh, mb) = transFourOprs ins bld
    let rol = tmpVar bld 64<rt>
    rol := rotateLeft64 rs sh
    ra := rol .& getExtMask64 mb (maskEndOfShift sh)
    if updateCond then setCR0Reg bld ra else ()
  }

let rldimi ins updateCond bld =
  lift bld ins {
    let struct (ra, rs, sh, mb) = transFourOprs ins bld
    let m = getExtMask64 mb (maskEndOfShift sh)
    let rol = tmpVar bld 64<rt>
    rol := rotateLeft64 rs sh
    ra := (rol .& m) .| (ra .& AST.not m)
    if updateCond then setCR0Reg bld ra else ()
  }

let rldcl ins updateCond bld =
  lift bld ins {
    let struct (ra, rs, rb, mb) = transFourOprs ins bld
    let rol = tmpVar bld 64<rt>
    rol := rotateLeft64 rs (rb .& numI32 0x3f 64<rt>)
    ra := rol .& getExtMask64 mb (numI32 63 64<rt>)
    if updateCond then setCR0Reg bld ra else ()
  }

let rldcr ins updateCond bld =
  lift bld ins {
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
let private logicalShift ins updateCond (bld: ILowUIRBuilder) width shiftLeft =
  lift bld ins {
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

let slw ins updateCond bld =
  logicalShift ins updateCond bld 32<rt> true

let srw ins updateCond bld =
  logicalShift ins updateCond bld 32<rt> false

let sld ins updateCond bld =
  logicalShift ins updateCond bld 64<rt> true

let srd ins updateCond bld =
  logicalShift ins updateCond bld 64<rt> false

/// An arithmetic right shift of `width` bits by a register count, which also
/// leaves XER[CA] set when a one was shifted out of a negative value. A count
/// past the operand's width shifts in nothing but sign.
let private arithShift ins updateCond (bld: ILowUIRBuilder) width =
  lift bld ins {
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
    let carry = tmpVar bld 1<rt>
    carry := AST.ite (res ?< z) lost AST.b0
    setCarry bld carry carry
    if updateCond then setCR0Reg bld ra else ()
  }

let sraw ins updateCond bld = arithShift ins updateCond bld 32<rt>

let srad ins updateCond bld = arithShift ins updateCond bld 64<rt>

/// An arithmetic right shift of `width` bits by an immediate count, setting
/// XER[CA] as the register-count form does.
let private arithShiftImm ins updateCond (bld: ILowUIRBuilder) width =
  lift bld ins {
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
    let carry = tmpVar bld 1<rt>
    carry := AST.ite (res ?< z) lost AST.b0
    setCarry bld carry carry
    if updateCond then setCR0Reg bld ra else ()
  }

let srawi ins updateCond bld =
  arithShiftImm ins updateCond bld 32<rt>

let sradi ins updateCond bld =
  arithShiftImm ins updateCond bld 64<rt>

let stb ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let ea = transEAWithOffset o2 bld
    let src = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 8<rt> tmpEA := AST.xtlo 8<rt> src
  }

let stbx ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rs = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 8<rt> tmpEA := AST.xtlo 8<rt> rs
  }

let stbu ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
    let src = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 8<rt> tmpEA := AST.xtlo 8<rt> src
    ra := tmpEA
  }

let stbux ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rs = transOpr bld o1
    let struct (ea, rA) = transEAWithIndexRegForUpdate o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 8<rt> tmpEA := AST.xtlo 8<rt> rs
    rA := tmpEA
  }

let stfd ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let ea = transEAWithOffset o2 bld
    let frs = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 64<rt> tmpEA := frs
  }

let stfdx ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let ea = transEAWithIndexReg o2 o3 bld
    let frs = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 64<rt> tmpEA := frs
  }

let stfdu ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
    let frs = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 64<rt> tmpEA := frs
    ra := tmpEA
  }

let stfdux ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let frs = transOpr bld o1
    let struct (ea, rA) = transEAWithIndexRegForUpdate o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 64<rt> tmpEA := frs
    rA := tmpEA
  }

let stfiwx ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let frs = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 32<rt> tmpEA := AST.xtlo 32<rt> frs
  }

/// The word stfs stores. The architecture splices bits rather than rounding:
/// a normal double keeps its sign, the top exponent bit with the seven low
/// ones, and the top 23 fraction bits; one that only fits a single-precision
/// denormal is denormalized with truncation; anything smaller becomes a signed
/// zero.
let singleBits bld frs =
  let word = tmpVar bld 32<rt>
  append bld {
    let exp = (frs >> numI32 52 64<rt>) .& numI32 0x7ff 64<rt>
    let spliced =
      ((frs >> numI32 32 64<rt>) .& numU64 0xc0000000UL 64<rt>)
      .| ((frs >> numI32 29 64<rt>) .& numU64 0x3fffffffUL 64<rt>)
    let sign = (frs >> numI32 32 64<rt>) .& numU64 0x80000000UL 64<rt>
    let frac =
      (frs .& numU64 0xfffffffffffffUL 64<rt>) .| numU64 (1UL <<< 52) 64<rt>
    let denorm = frac >> (numI32 926 64<rt> .- exp)
    let small = AST.ite (exp .>= numI32 874 64<rt>) (sign .| denorm) sign
    word := AST.xtlo 32<rt> (AST.ite (exp .> numI32 896 64<rt>) spliced small)
  }
  word

let stfs ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let ea = transEAWithOffset o2 bld
    let frs = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 32<rt> tmpEA := singleBits bld frs
  }

let stfsx ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let ea = transEAWithIndexReg o2 o3 bld
    let frs = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 32<rt> tmpEA := singleBits bld frs
  }

let stfsu ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
    let frs = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 32<rt> tmpEA := singleBits bld frs
    ra := tmpEA
  }

let stfsux ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let frs = transOpr bld o1
    let struct (ea, rA) = transEAWithIndexRegForUpdate o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 32<rt> tmpEA := singleBits bld frs
    rA := tmpEA
  }

let sth ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let ea = transEAWithOffset o2 bld
    let src = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 16<rt> tmpEA := AST.xtlo 16<rt> src
  }

let sthbrx ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rs = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let revtmp = tmpVar bld 16<rt>
    revtmp := AST.concat (AST.extract rs 8<rt> 0)
                         (AST.extract rs 8<rt> 8)
    loadNative bld 16<rt> ea := revtmp
  }

let sthx ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rs = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 16<rt> tmpEA := AST.xtlo 16<rt> rs
  }

let sthu ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
    let rs = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 16<rt> tmpEA := AST.xtlo 16<rt> rs
    ra := tmpEA
  }

let sthux ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rs = transOpr bld o1
    let struct (ea, rA) = transEAWithIndexRegForUpdate o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 16<rt> tmpEA := AST.xtlo 16<rt> rs
    rA := tmpEA
  }

/// A d(rA) store of the low `size` bits of rS, updating rA when update is set.
let private storeOffset ins (bld: ILowUIRBuilder) size update =
  lift bld ins {
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
let private storeIndexed ins (bld: ILowUIRBuilder) size update =
  lift bld ins {
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

let stw ins bld = storeOffset ins bld 32<rt> false

let stwu ins bld = storeOffset ins bld 32<rt> true

let stwx ins bld = storeIndexed ins bld 32<rt> false

/// ecowx, the external control word write, the counterpart of eciwx.
let ecowx ins bld = storeIndexed ins bld 32<rt> false

/// Byte i of the string a store spells out of the low words of the registers
/// from rS on: the most significant byte of each word comes first.
let private stringByte bld rs i =
  let reg = regVar bld (gprAfter rs (i / 4))
  AST.extract reg 8<rt> (24 - 8 * (i % 4))

/// stswi, which stores NB bytes (32 when NB is zero) to (rA|0) out of the low
/// words of the registers from rS on, wrapping from r31 to r0.
let stswi (ins: Instruction) (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (rs, ra, nb) =
      match ins.Operands with
      | ThreeOperands(OprReg rs, OprReg ra, OprImm nb) ->
        struct (rs, ra, int nb)
      | _ ->
        raise InvalidOperandException
    let n = if nb = 0 then 32 else nb
    let rt = bld.RegType
    let ea = tmpVar bld rt
    ea := stringBase bld ra
    for i in 0 .. n - 1 do
      loadNative bld 8<rt> (ea .+ numI32 i rt) := stringByte bld rs i
  }

/// stswx, whose byte count is XER[57:63]: each byte is stored once the count
/// reaches it, up to the 127 bytes the field can name.
let stswx (ins: Instruction) (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (rs, ra, rb) =
      match ins.Operands with
      | ThreeOperands(OprReg rs, ra, rb) -> struct (rs, ra, rb)
      | _ -> raise InvalidOperandException
    let rt = bld.RegType
    let ea = tmpVar bld rt
    let cnt = tmpVar bld rt
    ea := transEAWithIndexReg ra rb bld
    cnt := AST.zext rt (AST.xtlo 7<rt> (regVar bld Register.XER))
    for i in 0 .. 126 do
      let off = numI32 i rt
      let dst = loadNative bld 8<rt> (ea .+ off)
      _when bld "Stswx" (cnt .> off) (block { dst := stringByte bld rs i })
  }

let stwux ins bld = storeIndexed ins bld 32<rt> true

let std ins bld = storeOffset ins bld 64<rt> false

let stdu ins bld = storeOffset ins bld 64<rt> true

let stdx ins bld = storeIndexed ins bld 64<rt> false

let stdux ins bld = storeIndexed ins bld 64<rt> true

let lmw ins bld =
  lift bld ins {
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

let stmw ins bld =
  lift bld ins {
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
let private storeByteReverse ins (bld: ILowUIRBuilder) size =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rs = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld size tmpEA := reversedBytes (AST.xtlo size rs) size
  }

let stwbrx ins bld = storeByteReverse ins bld 32<rt>

let stdbrx ins bld = storeByteReverse ins bld 64<rt>

/// <summary>
/// The skeleton of a store-conditional. Memory is read, by check, only while
/// the reservation is held at ea, and written, by stores, only where check
/// finds the reserved value still there. The reservation is cleared either
/// way, and CR0 says whether the store happened, with SO from XER[SO].
/// </summary>
let private conditionalStore (bld: ILowUIRBuilder) ea check stores =
  let res = regVar bld Register.RES
  let stored = tmpVar bld 1<rt>
  let held = res .& (ea == regVar bld Register.ExMonAddr)
  let lblCheck = label bld "Check"
  let lblStore = label bld "Store"
  let lblEnd = label bld "End"
  append bld {
    stored := AST.b0
    AST.cjmp held (AST.jmpDest lblCheck) (AST.jmpDest lblEnd)
    AST.lmark lblCheck
    stored := check
    AST.cjmp stored (AST.jmpDest lblStore) (AST.jmpDest lblEnd)
    AST.lmark lblStore
    for dst, value in stores do
      dst := value
    AST.lmark lblEnd
    res := AST.b0
    regVar bld Register.CR0_0 := AST.b0
    regVar bld Register.CR0_1 := AST.b0
    regVar bld Register.CR0_2 := stored
    regVar bld Register.CR0_3 := AST.xthi 1<rt> (regVar bld Register.XER)
  }

/// <summary>
/// stwcx./stdcx.: the store half of a reservation pair. It stores only while
/// the reservation is held, at the address it stores to, over a value memory
/// still holds; it reports in CR0[EQ] whether it did, and clears the
/// reservation either way. Where no reservation is held at that address,
/// memory is neither read nor written.
/// </summary>
let private storeConditional ins (bld: ILowUIRBuilder) size =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rs = transOpr bld o1
    let ea = tmpVar bld bld.RegType
    let current = AST.zext bld.RegType (loadNative bld size ea)
    let check = current == regVar bld Register.ExMonVal
    ea := transEAWithIndexReg o2 o3 bld
    conditionalStore bld ea check [ loadNative bld size ea, AST.xtlo size rs ]
  }

let stwcxdot ins bld = storeConditional ins bld 32<rt>

let stdcxdot ins bld = storeConditional ins bld 64<rt>

let stbcxdot ins bld = storeConditional ins bld 8<rt>

let sthcxdot ins bld = storeConditional ins bld 16<rt>

let subf ins updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let one = AST.num1 bld.RegType
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    t1 := AST.not src1
    t2 := src2
    dst := t1 .+ t2 .+ one
    if ovCond then isAddSubOV bld t1 t2 dst else ()
    if updateCond then setCR0Reg bld dst else ()
  }

let subfc ins updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    t1 := AST.not src1
    t2 := src2
    addWithCarryOut bld dst t1 t2 (AST.num1 bld.RegType)
    if ovCond then isAddSubOV bld t1 t2 dst else ()
    if updateCond then setCR0Reg bld dst else ()
  }

let subfe ins updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    let ca = carryIn bld
    t1 := AST.not src1
    t2 := src2
    addWithCarryOut bld dst t1 t2 ca
    if ovCond then isAddSubOV bld t1 t2 dst else ()
    if updateCond then setCR0Reg bld dst else ()
  }

let subfic ins (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (dst, src1, simm) = transThreeOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    t1 := AST.not src1
    t2 := simm
    addWithCarryOut bld dst t1 t2 (AST.num1 bld.RegType)
  }

let subfme ins updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (dst, src) = transTwoOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    let ca = carryIn bld
    t1 := AST.not src
    t2 := AST.not (AST.num0 bld.RegType)
    addWithCarryOut bld dst t1 t2 ca
    if ovCond then isAddSubOV bld t1 t2 dst else ()
    if updateCond then setCR0Reg bld dst else ()
  }

let subfze ins updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (dst, src) = transTwoOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    let ca = carryIn bld
    t1 := AST.not src
    t2 := AST.num0 bld.RegType
    addWithCarryOut bld dst t1 t2 ca
    if ovCond then isAddSubOV bld t1 t2 dst else ()
    if updateCond then setCR0Reg bld dst else ()
  }

let trap (ins: Instruction) bld =
  lift bld ins {
    AST.sideEffect (Interrupt 0)
  }

/// One of the extended mnemonics of tw and twi, whose name gives the one
/// comparison that traps. They are word forms, so only the low words of the
/// operands take part, whatever the width of a register.
let trapCond ins cmpOp bld =
  lift bld ins {
    let struct (ra, rb) = transTwoOprs ins bld
    let ra, rb = AST.xtlo 32<rt> ra, AST.xtlo 32<rt> rb
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
let trapGeneric ins (bld: ILowUIRBuilder) narrow =
  lift bld ins {
    let struct (tO, ra, rb) = transThreeOprs ins bld
    let tO = match tO with
             | Num(Value = n) -> int (n.ToUInt64())
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

let xor ins updateCond bld =
  lift bld ins {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    dst := (src1 <+> src2)
    if updateCond then setCR0Reg bld dst else ()
  }

let xori ins bld =
  lift bld ins {
    let struct (dst, src, uimm) = transThreeOprs ins bld
    let uimm = AST.zext bld.RegType (AST.xtlo 16<rt> uimm)
    dst := src <+> uimm
  }

let xoris ins bld =
  lift bld ins {
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
let popcnt ins bld chunk =
  lift bld ins {
    let struct (ra, rs) = transTwoOprs ins bld
    popCountInto bld ra rs chunk
  }

/// prtyw/prtyd, which put the parity of rS's bytes -- one per word, or one for
/// the whole doubleword -- in the low bit of that field of rA. Only each byte's
/// low bit takes part, so summing those and keeping the sum's low bit gives it.
let prty ins (bld: ILowUIRBuilder) chunk =
  lift bld ins {
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
let bpermd ins (bld: ILowUIRBuilder) =
  lift bld ins {
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
let cmpb ins (bld: ILowUIRBuilder) =
  lift bld ins {
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
let isel (ins: Instruction) (bld: ILowUIRBuilder) =
  lift bld ins {
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
let mfvsr ins (bld: ILowUIRBuilder) size =
  lift bld ins {
    let struct (frs, ra) = transTwoOprs ins bld
    ra := AST.zext bld.RegType (AST.xtlo size frs)
  }

/// mtvsrd, which moves a general register's bits into a vector-scalar
/// register's high doubleword, leaving the low one undefined.
let mtvsrd ins bld =
  lift bld ins {
    let struct (frs, ra) = transTwoOprs ins bld
    frs := AST.zext 64<rt> ra
  }

/// mtvsrwa/mtvsrwz, which move the low word of a general register into a
/// vector-scalar register's high doubleword, sign- or zero-extended.
let mtvsrw ins bld signed =
  lift bld ins {
    let struct (frs, ra) = transTwoOprs ins bld
    let w = AST.xtlo 32<rt> ra
    frs := if signed then AST.sext 64<rt> w else AST.zext 64<rt> w
  }

/// An unsigned doubleword conversion has to reach past the signed range: values
/// of 2^63 and up are converted with 2^63 taken off and put back afterwards.
(* Lane A: the branch and storage instructions of ISA 2.07 and later. *)
/// <summary>
/// addex rT, rA, rB, 0, which adds rA, rB and OV, and keeps the carry out in
/// OV -- out of the register -- and OV32 -- out of the low word -- the way
/// adde keeps it in CA and CA32. SO is left alone, as it is by nothing else
/// that writes OV.
/// </summary>
let addex ins (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (dst, src1, src2, _) = transFourOprs ins bld
    let rt = bld.RegType
    let struct (a, b) = tmpVars2 bld rt
    let struct (partial, sum) = tmpVars2 bld rt
    let struct (c1, c2) = tmpVars2 bld 1<rt>
    a := src1
    b := src2
    partial := a .+ b
    c1 := partial .< a
    sum := partial .+ AST.zext rt (xerBit bld 30)
    c2 := sum .< partial
    xerBit bld 30 := c1 .| c2
    if rt = 64<rt> then
      xerBit bld 19 := AST.extract (a <+> b <+> sum) 1<rt> 32
    else
      ()
    dst := sum
  }

/// addpcis rT, D, which adds D shifted up sixteen bits to the address of the
/// next instruction.
let addpcis (ins: Instruction) (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (dst, d) = transTwoOprs ins bld
    let nia = numU64 (ins.Address + 4UL) bld.RegType
    dst := nia .+ (d << numI32 16 bld.RegType)
  }

/// <summary>
/// cnttzw/cnttzd, which count the zeros below the lowest one of rS's low word
/// or of all of it, up to the whole width where it is zero: the ones of
/// (x &amp; -x) - 1 are exactly those zeros.
/// </summary>
let private countTrailingZeros ins updateCond (bld: ILowUIRBuilder) width =
  lift bld ins {
    let struct (ra, rs) = transTwoOprs ins bld
    let x = tmpVar bld width
    let below = tmpVar bld bld.RegType
    x := AST.xtlo width rs
    x := (x .& AST.neg x) .- AST.num1 width
    below := AST.zext bld.RegType x
    popCountInto bld ra below (int bld.RegType)
    if updateCond then setCR0Reg bld ra else ()
  }

let cnttzw ins updateCond bld = countTrailingZeros ins updateCond bld 32<rt>

let cnttzd ins updateCond bld = countTrailingZeros ins updateCond bld 64<rt>

/// <summary>
/// cmpeqb BF, rA, rB, which sets CR field BF to 0b0100 where the low byte of
/// rA equals any byte of rB and to zero where it equals none.
/// </summary>
let cmpeqb ins (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct ((lt, gt, eq, so), ra, rb) = transCmpOprs ins bld
    let c = AST.xtlo 8<rt> ra
    let matches = [ for i in 0 .. 7 -> AST.extract rb 8<rt> (8 * i) == c ]
    lt := AST.b0
    gt := List.reduce (.|) matches
    eq := AST.b0
    so := AST.b0
  }

/// <summary>
/// cmprb BF, L, rA, rB, which sets CR field BF to 0b0100 where the low byte
/// of rA lies in the range rB's bytes 7:6 bound (and, for L = 1, also where
/// it lies in the one its bytes 5:4 bound) and to zero where it does not.
/// </summary>
let cmprb (ins: Instruction) (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (field, l, ra, rb) =
      match ins.Operands with
      | FourOperands(OprReg f, OprImm l, ra, rb) ->
        struct (transCRxToExpr bld f, l, transOpr bld ra, transOpr bld rb)
      | _ ->
        raise InvalidOperandException
    let lt, gt, eq, so = field
    let c = AST.xtlo 8<rt> ra
    let byte n = AST.extract rb 8<rt> (8 * n)
    let within lo hi = (byte lo .<= c) .& (c .<= byte hi)
    lt := AST.b0
    gt := if l = 0UL then within 0 1 else within 0 1 .| within 2 3
    eq := AST.b0
    so := AST.b0
  }

/// darn rT, L. The random number generator may fail, and says so by giving
/// all ones (Book I 3.3.9); this one has no source of randomness to read, so
/// it always reports that, which software is expected to handle by retrying
/// and then falling back on a generator of its own.
let darn ins (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (rt, _) = transTwoOprs ins bld
    rt := AST.not (AST.num0 bld.RegType)
  }

/// extswsli rA, rS, SH, which sign-extends rS's low word and shifts it left.
let extswsli ins updateCond (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (ra, rs, sh) = transThreeOprs ins bld
    ra := AST.sext 64<rt> (AST.xtlo 32<rt> rs) << sh
    if updateCond then setCR0Reg bld ra else ()
  }

/// mcrxrx BF, which copies OV, OV32, CA and CA32 into CR field BF.
let mcrxrx ins bld =
  lift bld ins {
    let lt, gt, eq, so = transCondOneOpr ins bld
    lt := xerBit bld 30
    gt := xerBit bld 19
    eq := xerBit bld 29
    so := xerBit bld 18
  }

/// <summary>
/// The modulos, which give the remainder of a word (doubleword) division
/// with the sign of the dividend. The remainder is undefined for a zero
/// divisor and for the most negative dividend over -1; it is zero here, as
/// QEMU leaves it. A word remainder fills a 64-bit register by sign or zero
/// extension, as QEMU leaves it (the ISA leaves the high word undefined).
/// </summary>
let private modulo ins (bld: ILowUIRBuilder) width signed =
  lift bld ins {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let struct (a, b) = tmpVars2 bld width
    let extend = if signed then AST.sext else AST.zext
    let zero = b == AST.num0 width
    let minValue = AST.num1 width << numI32 (int width - 1) width
    let overflow = (a == minValue) .& (b == AST.not (AST.num0 width))
    let undefined = if signed then zero .| overflow else zero
    let safe = AST.ite undefined (AST.num1 width) b
    let r = if signed then a ?% safe else a .% safe
    a := AST.xtlo width src1
    b := AST.xtlo width src2
    dst := AST.ite undefined (AST.num0 bld.RegType) (extend bld.RegType r)
  }

let modsw ins bld = modulo ins bld 32<rt> true

let moduw ins bld = modulo ins bld 32<rt> false

let modsd ins bld = modulo ins bld 64<rt> true

let modud ins bld = modulo ins bld 64<rt> false

/// setb rT, BFA, which gives -1 where CR field BFA says LT, else 1 where it
/// says GT, and 0 otherwise.
let setb (ins: Instruction) (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (rt, field) =
      match ins.Operands with
      | TwoOperands(rt, OprReg f) -> struct (transOpr bld rt, f)
      | _ -> raise InvalidOperandException
    let lt, gt, _, _ = transCRxToExpr bld field
    let one = AST.num1 bld.RegType
    let gtValue = AST.ite gt one (AST.num0 bld.RegType)
    rt := AST.ite lt (AST.not (AST.num0 bld.RegType)) gtValue
  }

/// <summary>
/// addg6s, which adds rA and rB and, for each four-bit digit, puts 6 in the
/// result where the binary sum did not carry out of that digit and 0 where it
/// did. The carry into bit 4k of a sum is bit 4k of a ^ b ^ sum; the carry out
/// of the top digit is the sum's own carry.
/// </summary>
let addg6s ins (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (rt, ra, rb) = transThreeOprs ins bld
    let width = int bld.RegType
    let struct (sum, carries) = tmpVars2 bld bld.RegType
    let num v = numU64 (v >>> (64 - width)) bld.RegType
    let ones = num 0x1111111111111111UL
    let top = AST.zext bld.RegType (sum .< ra)
    sum := ra .+ rb
    carries := ((ra <+> rb <+> sum) >> numI32 4 bld.RegType) .& ones
    carries := carries .| (top << numI32 (width - 4) bld.RegType)
    rt := (carries <+> ones) .* numU64 6UL bld.RegType
  }

/// <summary>
/// The twelve bits of three BCD digits from the ten of a declet, pqr stu v
/// wxy, by the Boolean equations of Book I Appendix B.2: abcd efgh ijkm.
/// </summary>
let private dpdToBCD (dpd: Expr) =
  let bit n = AST.extract dpd 1<rt> (9 - n)
  let p, q, r, s, t = bit 0, bit 1, bit 2, bit 3, bit 4
  let u, v, w, x, y = bit 5, bit 6, bit 7, bit 8, bit 9
  let n = AST.not
  let a = (n s .& v .& w) .| (t .& v .& w .& s) .| (v .& w .& n x)
  let b = (p .& s .& x .& n t) .| (p .& n w) .| (p .& n v)
  let c = (q .& s .& x .& n t) .| (q .& n w) .| (q .& n v)
  let e = (v .& n w .& x) .| (s .& v .& w .& x) .| (n t .& v .& x .& w)
  let f = (p .& t .& v .& w .& x .& n s) .| (s .& n x .& v) .| (s .& n v)
  let g = (q .& t .& w .& v .& x .& n s) .| (t .& n x .& v) .| (t .& n v)
  let i = (t .& v .& w .& x) .| (s .& v .& w .& x) .| (v .& n w .& n x)
  let j =
    (p .& n s .& n t .& w .& v) .| (s .& v .& n w .& x)
    .| (p .& w .& n x .& v) .| (w .& n v)
  let k =
    (q .& n s .& n t .& v .& w) .| (t .& v .& n w .& x)
    .| (q .& v .& w .& n x) .| (x .& n v)
  AST.revConcat [| y; k; j; i; u; g; f; e; r; c; b; a |]

/// <summary>
/// The ten bits of a declet from the twelve of three BCD digits, abcd efgh
/// ijkm, by the Boolean equations of Book I Appendix B.1: pqr stu v wxy.
/// </summary>
let private bcdToDPD (bcd: Expr) =
  let bit n = AST.extract bcd 1<rt> (11 - n)
  let a, b, c, d, e, f = bit 0, bit 1, bit 2, bit 3, bit 4, bit 5
  let g, h, i, j, k, m = bit 6, bit 7, bit 8, bit 9, bit 10, bit 11
  let n = AST.not
  let p = (f .& a .& i .& n e) .| (j .& a .& n i) .| (b .& n a)
  let q = (g .& a .& i .& n e) .| (k .& a .& n i) .| (c .& n a)
  let s =
    (j .& n a .& e .& n i) .| (f .& n i .& n e) .| (f .& n a .& n e)
    .| (e .& i)
  let t =
    (k .& n a .& e .& n i) .| (g .& n i .& n e) .| (g .& n a .& n e)
    .| (a .& i)
  let v = a .| e .| i
  let w = (n e .& j .& n i) .| (e .& i) .| a
  let x = (n a .& k .& n i) .| (a .& i) .| e
  AST.revConcat [| m; x; w; v; h; t; s; d; q; p |]

/// <summary>
/// cdtbcd and cbcdtd, which convert the low bits of each word of rS on their
/// own -- two declets to six BCD digits, or back -- and zero the rest of the
/// word. convert takes a word held in a temporary and gives its result.
/// </summary>
let private perWord ins (bld: ILowUIRBuilder) convert =
  lift bld ins {
    let struct (ra, rs) = transTwoOprs ins bld
    let words = int bld.RegType / 32
    let word = tmpVar bld 32<rt>
    let result = tmpVar bld bld.RegType
    result := AST.num0 bld.RegType
    for n in 0 .. words - 1 do
      word := AST.extract rs 32<rt> (32 * n)
      AST.extract result 32<rt> (32 * n) := convert word
    ra := result
  }

/// A word converted by cdtbcd: the declets in bits 19:10 and 9:0, as BCD in
/// bits 23:12 and 11:0.
let private declets word =
  let high = dpdToBCD (AST.extract word 10<rt> 10)
  AST.zext 32<rt> (AST.concat high (dpdToBCD (AST.extract word 10<rt> 0)))

let cdtbcd ins bld = perWord ins bld declets

/// A word converted by cbcdtd: the BCD digits in bits 23:12 and 11:0, as
/// declets in bits 19:10 and 9:0.
let private digits word =
  let high = bcdToDPD (AST.extract word 12<rt> 12)
  AST.zext 32<rt> (AST.concat high (bcdToDPD (AST.extract word 12<rt> 0)))

let cbcdtd ins bld = perWord ins bld digits

/// <summary>
/// The extended divides, which divide the low word (doubleword) of rA with a
/// word (doubleword) of zeros below it by the low word (doubleword) of rB, in
/// a type twice that wide. The quotient is defined only where it fits in a
/// word (doubleword) and the divisor is not zero; otherwise it is zero here,
/// as QEMU leaves it, and the OE forms set OV and OV32. A word quotient fills
/// a 64-bit register by sign or zero extension, as divw and divwu do.
/// </summary>
let private divideExtended ins updateCond ovCond bld width signed =
  lift bld ins {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let wide = width + width
    let extend = if signed then AST.sext else AST.zext
    let dividend = AST.concat (AST.xtlo width src1) (AST.num0 width)
    let struct (divisor, quotient) = tmpVars2 bld wide
    let ok = tmpVar bld 1<rt>
    let zero = divisor == AST.num0 wide
    let safe = AST.ite zero (AST.num1 wide) divisor
    let result = extend bld.RegType (AST.xtlo width quotient)
    divisor := extend wide (AST.xtlo width src2)
    quotient := if signed then dividend ?/ safe else dividend ./ safe
    ok := AST.not zero .& (quotient == extend wide (AST.xtlo width quotient))
    if ovCond then setWholeOverflow bld (AST.not ok) else ()
    dst := AST.ite ok result (AST.num0 bld.RegType)
    if updateCond then setCR0Reg bld dst else ()
  }

let divwe ins updateCond ovCond bld =
  divideExtended ins updateCond ovCond bld 32<rt> true

let divweu ins updateCond ovCond bld =
  divideExtended ins updateCond ovCond bld 32<rt> false

let divde ins updateCond ovCond bld =
  divideExtended ins updateCond ovCond bld 64<rt> true

let divdeu ins updateCond ovCond bld =
  divideExtended ins updateCond ovCond bld 64<rt> false

/// <summary>
/// bctar/bctarl, which go to TAR with its low two bits cleared where the
/// counter and a CR bit say so, testing them as bc does -- CTR is counted down
/// unless BO2 says not to, which bcctr may not do. bctarl leaves the address
/// of the next instruction in LR whether the branch is taken or not.
/// </summary>
let bctar (ins: Instruction) (bld: ILowUIRBuilder) lk =
  lift bld ins {
    let struct (bo, bi) =
      match ins.Operands with
      | TwoOperands(OprImm bo, OprBI bi)
      | ThreeOperands(OprImm bo, OprBI bi, _) -> struct (uint32 bo, bi)
      | _ -> raise InvalidOperandException
    let rt = bld.RegType
    let ctr = regVar bld Register.CTR
    let cr = getCRbitRegister bi |> regVar bld
    let boBit n = numU32 ((bo >>> (4 - n)) &&& 1u) 1<rt>
    let taken = tmpVar bld 1<rt>
    let target = tmpVar bld rt
    let nia = numU64 (ins.Address + 4UL) rt
    if bo &&& 4u = 0u then append bld { ctr := ctr .- AST.num1 rt } else ()
    let ctrOk = boBit 2 .| ((ctr != AST.num0 rt) <+> boBit 3)
    let condOk = boBit 0 .| (cr <+> AST.not (boBit 1))
    let tar = regVar bld Register.TAR .& branchTargetMask bld
    taken := ctrOk .& condOk
    target := AST.ite taken tar nia
    if lk then append bld { regVar bld Register.LR := nia } else ()
    let kind = if lk then InterJmpKind.IsCall else InterJmpKind.Base
    AST.interjmp target kind
  }

/// <summary>
/// rfebb S, which sets BESCR[GE], its most significant bit, to S and goes to
/// EBBRR with its low two bits cleared. No event-based exception is ever
/// pending here, so none is taken on the way; the transactional state BESCR
/// carries belongs to a facility ISA 3.1 no longer has.
/// </summary>
let rfebb (ins: Instruction) (bld: ILowUIRBuilder) =
  lift bld ins {
    let s =
      match ins.Operands with
      | OneOperand(OprImm s) -> s
      | _ -> raise InvalidOperandException
    let target = tmpVar bld bld.RegType
    target := regVar bld Register.EBBRR .& branchTargetMask bld
    AST.xthi 1<rt> (regVar bld Register.BESCR) := numU64 s 1<rt>
    AST.interjmp target InterJmpKind.IsRet
  }

/// <summary>
/// mfbhrbe, which reads an entry of the branch history rolling buffer. How
/// many entries there are is the implementation's to choose, and this one has
/// none -- nothing here records the branches taken -- so every entry reads as
/// zero, which is what the ISA gives for an entry past the last one, and what
/// it allows any entry to read as after the buffer is cleared at any time.
/// </summary>
let mfbhrbe (ins: Instruction) (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (rt, _) = transTwoOprs ins bld
    rt := AST.num0 bld.RegType
  }

/// The even register of the pair an lq-family instruction names, and the odd
/// one after it.
let private registerPair = function
  | OprReg r -> struct (r, int r + 1 |> enum<Register>)
  | _ -> raise InvalidOperandException

/// <summary>
/// The addresses of the doublewords a quadword access moves to or from the
/// even register of the pair and the odd one: a big-endian processor keeps
/// the even register's first, and a little-endian one byte-reverses the whole
/// quadword, which puts it second.
/// </summary>
let private pairAddresses (bld: ILowUIRBuilder) ea =
  let next = ea .+ numI32 8 bld.RegType
  if bld.Endianness = Endian.Big then struct (ea, next) else struct (next, ea)

/// <summary>
/// lqarx rTp, rA, rB, which loads a quadword into an even-odd register pair
/// and reserves it: ExMonVal and ExMonVal2 keep the value of the two
/// doublewords, as ExMonVal alone does for the narrower forms.
/// </summary>
let lqarx (ins: Instruction) (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (even, odd) = registerPair o1
    let ea = tmpVar bld 64<rt>
    let struct (hi, lo) = tmpVars2 bld 64<rt>
    ea := transEAWithIndexReg o2 o3 bld
    let struct (evenAddr, oddAddr) = pairAddresses bld ea
    hi := loadNative bld 64<rt> evenAddr
    lo := loadNative bld 64<rt> oddAddr
    regVar bld Register.RES := AST.b1
    regVar bld Register.ExMonAddr := ea
    regVar bld Register.ExMonVal := hi
    regVar bld Register.ExMonVal2 := lo
    regVar bld even := hi
    regVar bld odd := lo
  }

/// <summary>
/// stqcx. rSp, rA, rB, which stores an even-odd register pair as one
/// quadword while the reservation lqarx made is held over a quadword memory
/// still holds, and otherwise neither stores nor, without a reservation at
/// that address, reads.
/// </summary>
let stqcxdot (ins: Instruction) (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (even, odd) = registerPair o1
    let ea = tmpVar bld 64<rt>
    ea := transEAWithIndexReg o2 o3 bld
    let struct (evenAddr, oddAddr) = pairAddresses bld ea
    let evenMem = loadNative bld 64<rt> evenAddr
    let oddMem = loadNative bld 64<rt> oddAddr
    let check =
      (evenMem == regVar bld Register.ExMonVal)
      .& (oddMem == regVar bld Register.ExMonVal2)
    let pair = [ evenMem, regVar bld even; oddMem, regVar bld odd ]
    conditionalStore bld ea check pair
  }

/// <summary>
/// lq rTp, DQ(rA), which loads a quadword into an even-odd register pair. rA
/// may name the odd register, which the load then overwrites.
/// </summary>
let lq (ins: Instruction) (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (even, odd) = registerPair o1
    let ea = tmpVar bld 64<rt>
    let struct (hi, lo) = tmpVars2 bld 64<rt>
    ea := transEAWithOffset o2 bld
    let struct (evenAddr, oddAddr) = pairAddresses bld ea
    hi := loadNative bld 64<rt> evenAddr
    lo := loadNative bld 64<rt> oddAddr
    regVar bld even := hi
    regVar bld odd := lo
  }

/// stq rSp, DS(rA), which stores an even-odd register pair as one quadword.
let stq (ins: Instruction) (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (even, odd) = registerPair o1
    let ea = tmpVar bld 64<rt>
    ea := transEAWithOffset o2 bld
    let struct (evenAddr, oddAddr) = pairAddresses bld ea
    loadNative bld 64<rt> evenAddr := regVar bld even
    loadNative bld 64<rt> oddAddr := regVar bld odd
  }

/// brd, brw and brh, which reverse the bytes of each doubleword, word or
/// halfword of rS.
let byteReverse ins (bld: ILowUIRBuilder) chunk =
  lift bld ins {
    let struct (ra, rs) = transTwoOprs ins bld
    let piece k = reversedBytes (AST.extract rs chunk (k * int chunk)) chunk
    ra := Array.init (int bld.RegType / int chunk) piece |> AST.revConcat
  }

/// Packs the bits of src under the ones of mask into the low bits of packed,
/// keeping their order, and leaves in count how many there were.
let private packUnder (bld: ILowUIRBuilder) packed count src mask =
  append bld {
    let cond = tmpVar bld 1<rt>
    packed := AST.num0 64<rt>
    count := AST.num0 64<rt>
    for i in 0 .. 63 do
      cond := AST.extract mask 1<rt> i
      let bit = AST.zext 64<rt> (AST.extract src 1<rt> i)
      packed := packed .| AST.ite cond (bit << count) (AST.num0 64<rt>)
      count := count .+ AST.zext 64<rt> cond
  }

/// pextd rA, rS, rB, which packs the bits of rS under the ones of rB into the
/// low bits of rA, keeping their order.
let pextd ins (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (ra, rs, rb) = transThreeOprs ins bld
    let struct (packed, count) = tmpVars2 bld 64<rt>
    packUnder bld packed count rs rb
    ra := packed
  }

/// pdepd rA, rS, rB, which spreads the low bits of rS over the positions of
/// the ones of rB, lowest first, and clears the rest.
let pdepd ins (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (ra, rs, rb) = transThreeOprs ins bld
    let struct (spread, count) = tmpVars2 bld 64<rt>
    let cond = tmpVar bld 1<rt>
    spread := AST.num0 64<rt>
    count := AST.num0 64<rt>
    for i in 0 .. 63 do
      cond := AST.extract rb 1<rt> i
      let bit = ((rs >> count) .& AST.num1 64<rt>) << numI32 i 64<rt>
      spread := spread .| AST.ite cond bit (AST.num0 64<rt>)
      count := count .+ AST.zext 64<rt> cond
    ra := spread
  }

/// <summary>
/// cfuged rA, rS, rB, which packs the bits of rS under the ones of rB to the
/// right of rA and the others to the left, each keeping their order. Where
/// rB is all ones, nothing goes to the left, and the left part shifted out
/// of the register is zero however far it goes.
/// </summary>
let cfuged ins (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (ra, rs, rb) = transThreeOprs ins bld
    let struct (right, ones) = tmpVars2 bld 64<rt>
    let struct (left, zeros) = tmpVars2 bld 64<rt>
    packUnder bld right ones rs rb
    packUnder bld left zeros rs (AST.not rb)
    ra := (left << ones) .| right
  }

/// <summary>
/// cntlzdm rA, rS, rB, which counts the zeros of rS under the ones of rB from
/// the most significant end to the first one there: the ones of rB above the
/// highest one of rS &amp; rB, which smearing that one down to the bottom
/// marks.
/// </summary>
let cntlzdm ins (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (ra, rs, rb) = transThreeOprs ins bld
    let x = tmpVar bld 64<rt>
    x := rs .& rb
    for shift in [ 1; 2; 4; 8; 16; 32 ] do
      x := x .| (x >> numI32 shift 64<rt>)
    x := rb .& AST.not x
    popCountInto bld ra x 64
  }

/// <summary>
/// cnttzdm rA, rS, rB, which counts the zeros of rS under the ones of rB from
/// the least significant end to the first one there: the ones of rB below
/// the lowest one of rS &amp; rB.
/// </summary>
let cnttzdm ins (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (ra, rs, rb) = transThreeOprs ins bld
    let x = tmpVar bld 64<rt>
    x := rs .& rb
    x := rb .& ((x .& AST.neg x) .- AST.num1 64<rt>)
    popCountInto bld ra x 64
  }

/// setbc, setbcr, setnbc and setnbcr rT, BI, which give 1 -- or -1 for the
/// negative forms -- where the CR bit BI is set, or clear for the reverse
/// forms, and 0 otherwise.
let setbc ins (bld: ILowUIRBuilder) negative reverse =
  lift bld ins {
    let struct (rt, bi) = transTwoOprs ins bld
    let zero = AST.num0 bld.RegType
    let value = if negative then AST.not zero else AST.num1 bld.RegType
    let cond = if reverse then AST.not bi else bi
    rt := AST.ite cond value zero
  }

/// Whether a function code is one Figure 3 of Book II lists for the atomic
/// loads.
let private isLoadFC fc =
  fc <= 8UL || fc = 16UL || fc = 24UL || fc = 25UL || fc = 28UL

/// The address an atomic memory operation reaches: (rA|0).
let private atomicAddress bld = function
  | OprReg Register.R0 -> AST.num0 64<rt>
  | OprReg r -> regVar bld r
  | _ -> raise InvalidOperandException

/// <summary>
/// The offsets from EA of the first and the last byte an atomic memory
/// operation of s bytes reaches for a function code: the bounded and equal
/// increments and store twin reach the operand above as well, and the
/// bounded decrement the one below.
/// </summary>
let private atomicReach isLoad fc (s: int64) =
  match fc with
  | 24UL | 25UL -> struct (0L, 2L * s - 1L)
  | 28UL when isLoad -> struct (-s, s - 1L)
  | _ -> struct (0L, s - 1L)

/// <summary>
/// Raises an alignment interrupt, and goes on to the end label, where EA is
/// not a multiple of the operand's s bytes or the bytes the operation
/// reaches leave the aligned 32-byte block; and otherwise goes on.
/// </summary>
let private alignmentGuard (bld: ILowUIRBuilder) ea s reach lblEnd =
  let struct (lo, hi) = reach
  let block (off: int64) = (ea .+ numI64 off 64<rt>) >> numI32 5 64<rt>
  let odd = (ea .& numI64 (s - 1L) 64<rt>) != AST.num0 64<rt>
  let faulty = odd .| (block lo != block hi)
  let lblFault = label bld "Fault"
  let lblGo = label bld "Go"
  append bld {
    AST.cjmp faulty (AST.jmpDest lblFault) (AST.jmpDest lblGo)
    AST.lmark lblFault
    AST.sideEffect (Exception MisalignedAccess)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblGo
  }

/// <summary>
/// What an atomic memory operation that reads only the operand at EA leaves
/// there, for a function code, the old value t and the operands a and b
/// (Book II 4.5, Figures 3 and 4).
/// </summary>
let private atomicResult fc t a b =
  match fc with
  | 0UL -> t .+ a
  | 1UL -> t <+> a
  | 2UL -> t .| a
  | 3UL -> t .& a
  | 4UL -> AST.ite (a .> t) a t
  | 5UL -> AST.ite (a ?> t) a t
  | 6UL -> AST.ite (a .< t) a t
  | 7UL -> AST.ite (a ?< t) a t
  | 8UL -> a
  | _ -> AST.ite (t != a) b t

/// <summary>
/// The body of lwat and ldat: the old value t at EA, and for the bounded
/// and equal codes the neighbour t2, decide what memory and rT get; a
/// bounded operation that may not go on gives 1 &lt;&lt; (width - 1).
/// </summary>
let private fetchAtomic (bld: ILowUIRBuilder) rt fc size ea =
  let s = numI32 (int size / 8) 64<rt>
  let operand n = AST.xtlo size (regVar bld (gprAfter rt n))
  let struct (t, t2) = tmpVars2 bld size
  let struct (stored, result) = tmpVars2 bld size
  let one = AST.num1 size
  let top = numU64 (1UL <<< (int size - 1)) size
  let neighbour = if fc = 28UL then ea .- s else ea .+ s
  let bounded cond next = struct (AST.ite cond next t, AST.ite cond t top)
  let struct (value, back) =
    match fc with
    | 24UL -> bounded (t != t2) (t .+ one)
    | 25UL -> bounded (t == t2) (t .+ one)
    | 28UL -> bounded (t != t2) (t .- one)
    | _ -> struct (atomicResult fc t (operand 1) (operand 2), t)
  append bld {
    t := loadNative bld size ea
    if fc >= 24UL then append bld { t2 := loadNative bld size neighbour }
    else ()
    stored := value
    result := back
    loadNative bld size ea := stored
    regVar bld rt := widened bld result
  }

/// <summary>
/// lwat and ldat rT, rA, FC, which update the word or doubleword at (rA)
/// atomically as the function code says and return the old value in rT
/// (Book II 4.5.1). A code Figure 3 does not list invokes the data storage
/// error handler; an address not a multiple of the size, or operands that
/// leave the aligned 32-byte block, the alignment error handler.
/// </summary>
let loadAtomic (ins: Instruction) (bld: ILowUIRBuilder) size =
  match ins.Operands with
  | ThreeOperands(OprReg rt, ra, OprImm fc) when isLoadFC fc ->
    lift bld ins {
      let s = int64 size / 8L
      let ea = tmpVar bld 64<rt>
      let lblEnd = label bld "End"
      ea := atomicAddress bld ra
      alignmentGuard bld ea s (atomicReach true fc s) lblEnd
      fetchAtomic bld rt fc size ea
      AST.lmark lblEnd
    }
  | ThreeOperands(_, _, OprImm _) ->
    sideEffects ins bld (Exception ProtectionFault)
  | _ ->
    raise InvalidOperandException

/// Whether a function code is one Figure 4 of Book II lists for the atomic
/// stores.
let private isStoreFC fc = fc <= 7UL || fc = 24UL

/// <summary>
/// The body of stwat and stdat: store twin (24) writes rS to both operands
/// where they are equal, and the other codes update the one at EA.
/// </summary>
let private storeAtomicBody (bld: ILowUIRBuilder) rs fc size ea =
  let next = ea .+ numI32 (int size / 8) 64<rt>
  let value = AST.xtlo size (regVar bld rs)
  let struct (t, t2) = tmpVars2 bld size
  let same = t == t2
  if fc = 24UL then
    append bld {
      t := loadNative bld size ea
      t2 := loadNative bld size next
      loadNative bld size ea := AST.ite same value t
      loadNative bld size next := AST.ite same value t2
    }
  else
    append bld {
      t := loadNative bld size ea
      loadNative bld size ea := atomicResult fc t value value
    }

/// <summary>
/// stwat and stdat rS, rA, FC, which update the word or doubleword at (rA)
/// atomically with rS as the function code says (Book II 4.5.2), faulting
/// as lwat and ldat do.
/// </summary>
let storeAtomic (ins: Instruction) (bld: ILowUIRBuilder) size =
  match ins.Operands with
  | ThreeOperands(OprReg rs, ra, OprImm fc) when isStoreFC fc ->
    lift bld ins {
      let s = int64 size / 8L
      let ea = tmpVar bld 64<rt>
      let lblEnd = label bld "End"
      ea := atomicAddress bld ra
      alignmentGuard bld ea s (atomicReach false fc s) lblEnd
      storeAtomicBody bld rs fc size ea
      AST.lmark lblEnd
    }
  | ThreeOperands(_, _, OprImm _) ->
    sideEffects ins bld (Exception ProtectionFault)
  | _ ->
    raise InvalidOperandException

(* The vector unit. A 128-bit vector register is modeled as two 64-bit halves
   (see the Register type), and every operation below works on those halves
   rather than on a 128-bit value, so nothing needs an intermediate wider than a
   register. "hi" always holds the vector's most significant doubleword, which
   is the half PowerPC numbers first. *)
/// The high and low halves of the 128-bit register an operand names: a vector
/// register keeps its low half in the register that follows, while a VSX
/// operand naming a floating-point register keeps it in that register's
/// companion (VSR0-31 hold their high doubleword in an FPR).
