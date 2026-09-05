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

/// A module for the AArch64 general-purpose IR translation functions
module internal B2R2.FrontEnd.ARM64.GeneralLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.ARM64
open B2R2.FrontEnd.ARM64.LiftingUtils

let sideEffects insAddr insLen bld name =
  liftAt bld insAddr insLen {
    AST.sideEffect name
  }

let adc ins insLen bld addr =
  lift bld ins insLen {
    let dst, src1, src2 = transThreeOprs ins bld addr
    let c = AST.zext ins.OprSize (regVar bld R.C)
    let result, _ = addWithCarry src1 src2 c ins.OprSize
    sized ins.OprSize dst := result
  }

let adcs ins insLen bld addr =
  lift bld ins insLen {
    let dst, src1, src2 = transThreeOprs ins bld addr
    let c = tmpVar bld ins.OprSize
    direct c := AST.zext ins.OprSize (regVar bld R.C)
    let result, (n, z, c, v) = addWithCarry src1 src2 c ins.OprSize
    direct (regVar bld R.N) := n
    direct (regVar bld R.Z) := z
    direct (regVar bld R.C) := c
    direct (regVar bld R.V) := v
    sized ins.OprSize dst := result
  }

let adds ins insLen bld addr =
  lift bld ins insLen {
    let dst, src1, src2 = transFourOprsWithBarrelShift ins bld addr
    let oSz = ins.OprSize
    let result, (n, z, c, v) = addWithCarry src1 src2 (AST.num0 oSz) oSz
    direct (regVar bld R.N) := n
    direct (regVar bld R.Z) := z
    direct (regVar bld R.C) := c
    direct (regVar bld R.V) := v
    sized ins.OprSize dst := result
  }

let adr ins insLen bld addr =
  lift bld ins insLen {
    let dst, label = transTwoOprs ins bld addr
    direct dst := getPC bld .+ label
  }

let adrp ins insLen bld addr =
  lift bld ins insLen {
    let dst, lbl = transTwoOprs ins bld addr
    direct dst := (getPC bld .& numI64 0xfffffffffffff000L 64<rt>) .+ lbl
  }

let asrv ins insLen bld addr =
  lift bld ins insLen {
    let dst, src1, src2 = transThreeOprs ins bld addr
    let amount = src2 .% oprSzToExpr ins.OprSize
    sized ins.OprSize dst := shiftReg src1 amount ins.OprSize ASR
  }

let ands ins insLen bld addr =
  lift bld ins insLen {
    let dst, src1, src2 = transOprToExprOfAND ins bld addr
    let result = tmpVar bld ins.OprSize
    direct result := src1 .& src2
    direct (regVar bld R.N) := AST.xthi 1<rt> result
    direct (regVar bld R.Z) := (result == AST.num0 ins.OprSize)
    direct (regVar bld R.C) := AST.b0
    direct (regVar bld R.V) := AST.b0
    sized ins.OprSize dst := result
  }

let b ins insLen bld addr =
  lift bld ins insLen {
    let label = transOneOpr ins bld addr
    let pc = numU64 (ins:Instruction).Address bld.RegType
    AST.interjmp (pc .+ label) InterJmpKind.Base
    return NoEndMark
  }

let bCond ins insLen bld addr cond =
  lift bld ins insLen {
    let label = transOneOpr ins bld addr
    let pc = numU64 (ins:Instruction).Address bld.RegType
    let fall = pc .+ numU32 insLen 64<rt>
    AST.intercjmp (conditionHolds bld cond) (pc .+ label) fall
    return NoEndMark
  }

let bfm (ins: Instruction) insLen bld addr dst src immr imms =
  lift bld ins insLen {
    let oSz = ins.OprSize
    let width = oprSzToExpr ins.OprSize
    let struct (wmask, tmask) = decodeBitMasks immr imms (int oSz)
    let dst = transOprToExpr ins bld addr dst
    let src = transOprToExpr ins bld addr src
    let immr = transOprToExpr ins bld addr immr
    let struct (wMask, tMask) = tmpVars2 bld oSz
    let bot = tmpVar bld ins.OprSize
    direct wMask := numI64 wmask oSz
    direct tMask := numI64 tmask oSz
    direct bot := (dst .& AST.not wMask) .| (rorForIR src immr width .& wMask)
    sized ins.OprSize dst := (dst .& AST.not tMask) .| (bot .& tMask)
  }

let bfi ins insLen bld addr =
  let struct (dst, src, lsb, width) = getFourOprs ins
  let immr = ((getImmValue lsb * -1L) &&& 0x3FL) % int64 ins.OprSize |> OprImm
  let imms = getImmValue width - 1L |> OprImm
  bfm ins insLen bld addr dst src immr imms

let bfxil ins insLen bld addr =
  let struct (dst, src, lsb, width) = getFourOprs ins
  let imms = (getImmValue lsb) + (getImmValue width) - 1L |> OprImm
  bfm ins insLen bld addr dst src lsb imms

let bics ins insLen bld addr =
  lift bld ins insLen {
    let dst, src1, src2 = transFourOprsWithBarrelShift ins bld addr
    let result = tmpVar bld ins.OprSize
    direct result := src1 .& AST.not src2
    direct (regVar bld R.N) := AST.xthi 1<rt> result
    direct (regVar bld R.Z) := result == AST.num0 ins.OprSize
    direct (regVar bld R.C) := AST.b0
    direct (regVar bld R.V) := AST.b0
    sized ins.OprSize dst := result
  }

let bl ins insLen bld addr =
  lift bld ins insLen {
    let label = transOneOpr ins bld addr
    let pc = numU64 (ins:Instruction).Address bld.RegType
    direct (regVar bld R.X30) := pc .+ numI64 4L ins.OprSize
    (* FIXME: BranchTo (BranchType_DIRCALL) *)
    AST.interjmp (pc .+ label) InterJmpKind.IsCall
    return NoEndMark
  }

let blr ins insLen bld addr =
  lift bld ins insLen {
    let src = transOneOpr ins bld addr
    let pc = numU64 (ins:Instruction).Address bld.RegType
    direct (regVar bld R.X30) := pc .+ numI64 4L ins.OprSize
    (* FIXME: BranchTo (BranchType_INDCALL) *)
    AST.interjmp src InterJmpKind.IsCall
    return NoEndMark
  }

let br ins insLen bld addr =
  lift bld ins insLen {
    let dst = transOneOpr ins bld addr
    (* FIXME: BranchTo (BranchType_INDIR) *)
    AST.interjmp dst InterJmpKind.Base
    return NoEndMark
  }

let inline private compareBranch ins insLen bld addr cmp =
  lift bld ins insLen {
    let test, label = transTwoOprs ins bld addr
    let pc = numU64 (ins: Instruction).Address bld.RegType
    let fall = pc .+ numU32 insLen 64<rt>
    AST.intercjmp (cmp test (AST.num0 ins.OprSize)) (pc .+ label) fall
    return NoEndMark
  }

let compareAndSwap ins insLen bld addr =
  lift bld ins insLen {
    let dst, src, mem = transThreeOprs ins bld addr
    let struct (compareVal, newVal, oldVal) = tmpVars3 bld ins.OprSize
    let memVal = tmpVar bld 64<rt>
    let cond = oldVal == compareVal
    direct compareVal := dst
    direct newVal := src
    direct memVal := mem
    direct oldVal := memVal |> AST.xtlo ins.OprSize
    direct mem := AST.ite cond (newVal |> AST.sext 64<rt>) memVal
    direct dst := oldVal |> AST.zext ins.OprSize
  }

let cbnz ins insLen bld addr = compareBranch ins insLen bld addr (!=)

let cbz ins insLen bld addr = compareBranch ins insLen bld addr (==)

let ccmn ins insLen bld addr =
  lift bld ins insLen {
    let src, imm, nzcv, cond = transOprToExprOfCCMN ins bld addr
    let oSz = ins.OprSize
    let tCond = tmpVar bld 1<rt>
    direct tCond := conditionHolds bld cond
    let _, (n, z, c, v) = addWithCarry src imm (AST.num0 oSz) oSz
    direct (regVar bld R.N) := (AST.ite tCond n (AST.extract nzcv 1<rt> 3))
    direct (regVar bld R.Z) := (AST.ite tCond z (AST.extract nzcv 1<rt> 2))
    direct (regVar bld R.C) := (AST.ite tCond c (AST.extract nzcv 1<rt> 1))
    direct (regVar bld R.V) := (AST.ite tCond v (AST.xtlo 1<rt> nzcv))
  }

let ccmp ins insLen bld addr =
  lift bld ins insLen {
    let src, imm, nzcv, cond = transOprToExprOfCCMP ins bld addr
    let oSz = ins.OprSize
    let tCond = tmpVar bld 1<rt>
    direct tCond := conditionHolds bld cond
    let _, (n, z, c, v) = addWithCarry src (AST.not imm) (AST.num1 oSz) oSz
    direct (regVar bld R.N) := (AST.ite tCond n (AST.extract nzcv 1<rt> 3))
    direct (regVar bld R.Z) := (AST.ite tCond z (AST.extract nzcv 1<rt> 2))
    direct (regVar bld R.C) := (AST.ite tCond c (AST.extract nzcv 1<rt> 1))
    direct (regVar bld R.V) := (AST.ite tCond v (AST.xtlo 1<rt> nzcv))
  }

let clzBits src bitSize oprSize bld =
  let x = tmpVar bld oprSize
  match oprSize with
  | 8<rt> ->
    let mask1 = numI32 0x55 8<rt>
    let mask2 = numI32 0x33 8<rt>
    let mask3 = numI32 0x0f 8<rt>
    append bld {
      direct x := src
      direct x := x .| (x >> numI32 1 8<rt>)
      direct x := x .| (x >> numI32 2 8<rt>)
      direct x := x .| (x >> numI32 4 8<rt>)
      direct x := x .- ((x >> numI32 1 8<rt>) .& mask1)
      direct x := ((x >> numI32 2 8<rt>) .& mask2) .+ (x .& mask2)
      direct x := ((x >> numI32 4 8<rt>) .+ x) .& mask3
    }
    numI32 bitSize 8<rt> .- (x .& numI32 15 8<rt>)
  | 16<rt> ->
    let mask1 = numI32 0x5555 16<rt>
    let mask2 = numI32 0x3333 16<rt>
    let mask3 = numI32 0x0f0f 16<rt>
    append bld {
      direct x := src
      direct x := x .| (x >> numI32 1 16<rt>)
      direct x := x .| (x >> numI32 2 16<rt>)
      direct x := x .| (x >> numI32 4 16<rt>)
      direct x := x .| (x >> numI32 8 16<rt>)
      direct x := x .- ((x >> numI32 1 16<rt>) .& mask1)
      direct x := ((x >> numI32 2 16<rt>) .& mask2) .+ (x .& mask2)
      direct x := ((x >> numI32 4 16<rt>) .+ x) .& mask3
      direct x := x .+ (x >> numI32 8 16<rt>)
    }
    numI32 bitSize 16<rt> .- (x .& numI32 31 16<rt>)
  | 32<rt> ->
    let mask1 = numI32 0x55555555 32<rt>
    let mask2 = numI32 0x33333333 32<rt>
    let mask3 = numI32 0x0f0f0f0f 32<rt>
    append bld {
      direct x := src
      direct x := x .| (x >> numI32 1 32<rt>)
      direct x := x .| (x >> numI32 2 32<rt>)
      direct x := x .| (x >> numI32 4 32<rt>)
      direct x := x .| (x >> numI32 8 32<rt>)
      direct x := x .| (x >> numI32 16 32<rt>)
      direct x := x .- ((x >> numI32 1 32<rt>) .& mask1)
      direct x := ((x >> numI32 2 32<rt>) .& mask2) .+ (x .& mask2)
      direct x := ((x >> numI32 4 32<rt>) .+ x) .& mask3
      direct x := x .+ (x >> numI32 8 32<rt>)
      direct x := x .+ (x >> numI32 16 32<rt>)
    }
    numI32 bitSize 32<rt> .- (x .& numI32 63 32<rt>)
  | 64<rt> ->
    let mask1 = numU64 0x5555555555555555UL 64<rt>
    let mask2 = numU64 0x3333333333333333UL 64<rt>
    let mask3 = numU64 0x0f0f0f0f0f0f0f0fUL 64<rt>
    append bld {
      direct x := src
      direct x := x .| (x >> numI32 1 64<rt>)
      direct x := x .| (x >> numI32 2 64<rt>)
      direct x := x .| (x >> numI32 4 64<rt>)
      direct x := x .| (x >> numI32 8 64<rt>)
      direct x := x .| (x >> numI32 16 64<rt>)
      direct x := x .| (x >> numI32 32 64<rt>)
      direct x := x .- ((x >> numI32 1 64<rt>) .& mask1)
      direct x := ((x >> numI32 2 64<rt>) .& mask2) .+ (x .& mask2)
      direct x := ((x >> numI32 4 64<rt>) .+ x) .& mask3
      direct x := x .+ (x >> numI32 8 64<rt>)
      direct x := x .+ (x >> numI32 16 64<rt>)
      direct x := x .+ (x >> numI32 32 64<rt>)
    }
    numI32 bitSize 64<rt> .- (x .& numI32 127 64<rt>)
  | _ ->
    raise InvalidOperandSizeException

let cmn ins insLen bld addr =
  lift bld ins insLen {
    let src1, src2 = transThreeOprsWithBarrelShift ins bld addr
    let oSz = ins.OprSize
    let _, (n, z, c, v) = addWithCarry src1 src2 (AST.num0 oSz) oSz
    direct (regVar bld R.N) := n
    direct (regVar bld R.Z) := z
    direct (regVar bld R.C) := c
    direct (regVar bld R.V) := v
  }

let cmp ins insLen bld addr =
  lift bld ins insLen {
    let src1, src2 = transOprToExprOfCMP ins bld addr
    let oSz = ins.OprSize
    let _, (n, z, c, v) = addWithCarry src1 (AST.not src2) (AST.num1 oSz) oSz
    direct (regVar bld R.N) := n
    direct (regVar bld R.Z) := z
    direct (regVar bld R.C) := c
    direct (regVar bld R.V) := v
  }

let csel ins insLen bld addr =
  lift bld ins insLen {
    let dst, s1, s2, cond = transOprToExprOfCSEL ins bld addr
    sized ins.OprSize dst := AST.ite (conditionHolds bld cond) s1 s2
  }

let csinc ins insLen bld addr =
  lift bld ins insLen {
    let dst, s1, s2, cond = transOprToExprOfCSINC ins bld addr
    let oprSize = ins.OprSize
    let cond = conditionHolds bld cond
    sized oprSize dst := AST.ite cond s1 (s2 .+ AST.num1 oprSize)
  }

let csinv ins insLen bld addr =
  lift bld ins insLen {
    let dst, src1, src2, cond = transOprToExprOfCSINV ins bld addr
    let cond = conditionHolds bld cond
    sized ins.OprSize dst := AST.ite cond src1 (AST.not src2)
  }

let csneg ins insLen bld addr =
  lift bld ins insLen {
    let dst, s1, s2, cond = transOprToExprOfCSNEG ins bld addr
    let s2 = AST.not s2 .+ AST.num1 ins.OprSize
    sized ins.OprSize dst := AST.ite (conditionHolds bld cond) s1 s2
  }

let ctz ins insLen bld addr =
  lift bld ins insLen {
    let dst, src = transTwoOprs ins bld addr
    let revSrc = tmpVar bld ins.OprSize
    direct revSrc := bitReverse src ins.OprSize
    let res = countLeadingZeroBitsForIR revSrc (int ins.OprSize) ins.OprSize bld
    sized ins.OprSize dst := res
  }

let dczva ins insLen bld addr =
  lift bld ins insLen {
    let src = transOneOpr ins bld addr
    let dczid = regVar bld R.DCZIDEL0
    let struct (idx, n4, len) = tmpVars3 bld 64<rt>
    let lblLoop = label bld "Loop"
    let lblLoopCont = label bld "LoopContinue"
    let lblEnd = label bld "End"
    direct idx := AST.num0 64<rt>
    direct n4 := numI32 4 64<rt>
    direct len := (numI32 2 64<rt> << (dczid .+ numI32 1 64<rt>))
    direct len := len ./ n4
    AST.lmark lblLoop
    AST.cjmp (idx == len) (AST.jmpDest lblEnd) (AST.jmpDest lblLoopCont)
    AST.lmark lblLoopCont
    direct (AST.loadLE 32<rt> (src .+ (idx .* n4))) := AST.num0 32<rt>
    direct idx := idx .+ AST.num1 64<rt>
    AST.jmp (AST.jmpDest lblLoop)
    AST.lmark lblEnd
  }

let checkZero bld dataSize fpVal =
  let isFZ = (regVar bld R.FPCR >> numI32 24 64<rt>) |> AST.xtlo 1<rt>
  let struct (n0, f0) = tmpVars2 bld dataSize
  append bld {
    direct n0 := AST.num0 dataSize
    direct f0 := fpZero fpVal dataSize
  }
  let inline isOnes exp =
    match dataSize with
    | 32<rt> -> exp == numI32 0xFF 32<rt>
    | 64<rt> -> exp == numI32 0x7FF 64<rt>
    | _ -> raise InvalidOperandSizeException
  let struct (exp, frac) = tmpVars2 bld dataSize
  match dataSize with
  | 32<rt> ->
    append bld {
      direct exp := (fpVal >> numI32 23 32<rt>) .& numI32 0xff 32<rt>
      direct frac := fpVal .& numU32 0x7fffffu 32<rt>
    }
  | 64<rt> ->
    append bld {
      direct exp := (fpVal >> numI64 52L 64<rt>) .& numI64 0x7ffL 64<rt>
      direct frac := fpVal .& numU64 0xfffffffffffffUL 64<rt>
    }
  | _ ->
    raise InvalidOperandSizeException
  AST.ite ((exp == n0) .& (frac == n0 .| isFZ))
    f0
    (AST.ite ((isOnes exp) .& (frac != n0)) f0 fpVal)

let private fpCompare bld oprSz src1 src2 =
  let struct (v1, v2) = tmpVars2 bld oprSz
  let isOpNaN = tmpVar bld 1<rt>
  let result = tmpVar bld 8<rt>
  append bld {
    direct v1 := checkZero bld oprSz src1
    direct v2 := checkZero bld oprSz src2
  }
  let lblOpNaN = label bld "OpNaN"
  let lblCmp = label bld "Cmp"
  let lblEq = label bld "Eq"
  let lblNeq = label bld "Neq"
  let lblEnd = label bld "End"
  append bld {
    direct isOpNaN := isNaN oprSz src1 .| isNaN oprSz src2
    AST.cjmp isOpNaN (AST.jmpDest lblOpNaN) (AST.jmpDest lblCmp)
    AST.lmark lblOpNaN
    direct result := numI32 0b0011 8<rt>
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblCmp
    AST.cjmp (AST.feq v1 v2) (AST.jmpDest lblEq) (AST.jmpDest lblNeq)
    AST.lmark lblEq
    direct result := numI32 0b110 8<rt>
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblNeq
  }
  let cond = AST.flt v1 v2
  append bld {
    direct result := AST.ite cond (numI32 0b1000 8<rt>) (numI32 0b0010 8<rt>)
    AST.lmark lblEnd
  }
  result

let fcmp (ins: Instruction) insLen bld addr =
  lift bld ins insLen {
    let src1, src2 = transTwoOprs ins bld addr
    let flags = tmpVar bld 8<rt>
    direct flags := fpCompare bld ins.OprSize src1 src2
    direct (regVar bld R.N) := AST.extract flags 1<rt> 3
    direct (regVar bld R.Z) := AST.extract flags 1<rt> 2
    direct (regVar bld R.C) := AST.extract flags 1<rt> 1
    direct (regVar bld R.V) := AST.extract flags 1<rt> 0
  }

let fccmp (ins: Instruction) insLen bld addr =
  lift bld ins insLen {
    let src1, src2, nzcv, cond = transOprToExprOfCCMP ins bld addr
    let flags = tmpVar bld 8<rt>
    let comp = fpCompare bld ins.OprSize src1 src2
    direct flags := AST.ite (conditionHolds bld cond) comp (AST.xtlo 8<rt> nzcv)
    direct (regVar bld R.N) := AST.extract flags 1<rt> 3
    direct (regVar bld R.Z) := AST.extract flags 1<rt> 2
    direct (regVar bld R.C) := AST.extract flags 1<rt> 1
    direct (regVar bld R.V) := AST.extract flags 1<rt> 0
  }

let ldar ins insLen bld addr =
  lift bld ins insLen {
    let dst, (bReg, offset) = transTwoOprsSepMem ins bld addr
    let address = tmpVar bld 64<rt>
    direct address := bReg .+ offset
    sized ins.OprSize dst := AST.loadLE ins.OprSize address
  }

let ldarb ins insLen bld addr =
  lift bld ins insLen {
    let dst, (bReg, offset) = transTwoOprsSepMem ins bld addr
    let address = tmpVar bld 64<rt>
    direct address := bReg .+ offset
    sized ins.OprSize dst := AST.loadLE 8<rt> address
  }

let ldax ins insLen bld addr size =
  lift bld ins insLen {
    let dst, (bReg, offset) = transTwoOprsSepMem ins bld addr
    let address = tmpVar bld 64<rt>
    let value = tmpVar bld size
    direct address := bReg .+ offset
    direct value := AST.loadLE size address
    reserveExclusive bld address value
    sized ins.OprSize dst := value
  }

let ldaxr ins insLen bld addr =
  lift bld ins insLen {
    let dst, (bReg, offset) = transTwoOprsSepMem ins bld addr
    let address = tmpVar bld 64<rt>
    let value = tmpVar bld ins.OprSize
    direct address := bReg .+ offset
    direct value := AST.loadLE ins.OprSize address
    reserveExclusive bld address value
    sized ins.OprSize dst := value
  }

let ldaxp ins insLen bld addr =
  lift bld ins insLen {
    let dst1, dst2, (bReg, offset) = transThreeOprsSepMem ins bld addr
    let address = tmpVar bld 64<rt>
    direct address := bReg .+ offset
    reserveExclusive bld address (AST.loadLE 64<rt> address)
    if ins.OprSize = 32<rt> then
      let src = AST.loadLE 64<rt> address
      sized ins.OprSize dst1 := AST.xtlo 32<rt> src
      sized ins.OprSize dst2 := AST.xthi 32<rt> src
    else
      direct dst1 := (AST.loadLE 64<rt> address)
      direct dst2 := (AST.loadLE 64<rt> (address .+ numI32 8 64<rt>))
  }

let ldpsw ins insLen bld addr =
  lift bld ins insLen {
    let src1, src2, (bReg, offset) = transThreeOprsSepMem ins bld addr
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    let address = tmpVar bld 64<rt>
    let data1 = tmpVar bld 32<rt>
    let data2 = tmpVar bld 32<rt>
    direct address := bReg
    direct address := if isPostIndex then address else address .+ offset
    direct data1 := AST.loadLE 32<rt> address
    direct data2 := AST.loadLE 32<rt> (address .+ numI32 4 64<rt>)
    direct src1 := AST.sext 64<rt> data1
    direct src2 := AST.sext 64<rt> data2
    writeBack bld isWBack isPostIndex bReg address offset
  }

let ldrb ins insLen bld addr =
  lift bld ins insLen {
    let dst, (bReg, offset) = transTwoOprsSepMem ins bld addr
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld 8<rt>
    direct address := bReg
    direct address := if isPostIndex then address else address .+ offset
    direct data := AST.loadLE 8<rt> address
    sized ins.OprSize dst := AST.zext 32<rt> data
    writeBack bld isWBack isPostIndex bReg address offset
  }

let ldrh ins insLen bld addr =
  lift bld ins insLen {
    let dst, (bReg, offset) = transTwoOprsSepMem ins bld addr
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld 16<rt>
    direct address := bReg
    direct address := if isPostIndex then address else address .+ offset
    direct data := AST.loadLE 16<rt> address
    sized ins.OprSize dst := AST.zext 32<rt> data
    writeBack bld isWBack isPostIndex bReg address offset
  }

let ldrsb ins insLen bld addr =
  lift bld ins insLen {
    let dst, (bReg, offset) = transTwoOprsSepMem ins bld addr
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld 8<rt>
    direct address := bReg
    direct address := if isPostIndex then address else address .+ offset
    direct data := AST.loadLE 8<rt> address
    sized ins.OprSize dst := AST.sext ins.OprSize data
    writeBack bld isWBack isPostIndex bReg address offset
  }

let ldrsh ins insLen bld addr =
  lift bld ins insLen {
    let dst, (bReg, offset) = transTwoOprsSepMem ins bld addr
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld 16<rt>
    direct address := bReg
    direct address := if isPostIndex then address else address .+ offset
    direct data := AST.loadLE 16<rt> address
    sized ins.OprSize dst := AST.sext ins.OprSize data
    writeBack bld isWBack isPostIndex bReg address offset
  }

let ldrsw (ins: Instruction) insLen bld addr =
  lift bld ins insLen {
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld 32<rt>
    match ins.Operands with
    | TwoOperands(o1, OprMemory(LiteralMode o2)) ->
      let dst = transOprToExpr ins bld addr o1
      let offset = transOprToExpr ins bld addr (OprMemory(LiteralMode o2))
      direct address := getPC bld .+ offset
      direct data := AST.loadLE 32<rt> address
      direct dst := AST.sext 64<rt> data
    | TwoOperands(o1, o2) ->
      let dst = transOprToExpr ins bld addr o1
      let bReg, offset = transOprToExpr ins bld addr o2 |> separateMemExpr
      let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
      direct address := bReg
      direct address := if isPostIndex then address else address .+ offset
      direct data := AST.loadLE 32<rt> address
      direct dst := AST.sext 64<rt> data
      writeBack bld isWBack isPostIndex bReg address offset
    | _ ->
      raise InvalidOperandException
  }

let ldtr ins insLen bld addr =
  lift bld ins insLen {
    let dst, (bReg, offset) = transTwoOprsSepMem ins bld addr
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld ins.OprSize
    direct address := bReg .+ offset
    direct data := AST.loadLE ins.OprSize address
    sized ins.OprSize dst := AST.zext ins.OprSize data
  }

let ldurb ins insLen bld addr =
  lift bld ins insLen {
    let src, (bReg, offset) = transTwoOprsSepMem ins bld addr
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld 8<rt>
    direct address := bReg
    direct address := address .+ offset
    direct data := AST.loadLE 8<rt> address
    sized ins.OprSize src := AST.zext 32<rt> data
  }

let ldurh ins insLen bld addr =
  lift bld ins insLen {
    let src, (bReg, offset) = transTwoOprsSepMem ins bld addr
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld 16<rt>
    direct address := bReg
    direct address := address .+ offset
    direct data := AST.loadLE 16<rt> address
    sized ins.OprSize src := AST.zext 32<rt> data
  }

let ldursb ins insLen bld addr =
  lift bld ins insLen {
    let dst, (bReg, offset) = transTwoOprsSepMem ins bld addr
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld 8<rt>
    direct address := bReg .+ offset
    direct data := AST.loadLE 8<rt> address
    sized ins.OprSize dst := AST.sext ins.OprSize data
  }

let ldursh ins insLen bld addr =
  lift bld ins insLen {
    let dst, (bReg, offset) = transTwoOprsSepMem ins bld addr
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld 16<rt>
    direct address := bReg .+ offset
    direct data := AST.loadLE 16<rt> address
    sized ins.OprSize dst := AST.sext ins.OprSize data
  }

let ldursw ins insLen bld addr =
  lift bld ins insLen {
    let dst, (bReg, offset) = transTwoOprsSepMem ins bld addr
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld 32<rt>
    direct address := bReg
    direct address := address .+ offset
    direct data := AST.loadLE 32<rt> address
    sized ins.OprSize dst := AST.sext 64<rt> data
  }

let lslv ins insLen bld addr =
  lift bld ins insLen {
    let dst, src1, src2 = transThreeOprs ins bld addr
    let oprSz = ins.OprSize
    let dataSize = numI32 (RegType.toBitWidth ins.OprSize) oprSz
    let result = shiftReg src1 (src2 .% dataSize) oprSz LSL
    sized ins.OprSize dst := result
  }

let lsrv ins insLen bld addr =
  lift bld ins insLen {
    let dst, src1, src2 = transThreeOprs ins bld addr
    let oprSz = ins.OprSize
    let dataSize = numI32 (RegType.toBitWidth oprSz) oprSz
    let result = shiftReg src1 (src2 .% dataSize) oprSz LSR
    sized ins.OprSize dst := result
  }

let movn (ins: Instruction) insLen bld addr =
  lift bld ins insLen {
    let dst, src = transThreeOprsWithBarrelShift ins bld addr
    sized ins.OprSize dst := AST.not src
  }

let movz (ins: Instruction) insLen bld addr =
  lift bld ins insLen {
    let dst, src = transThreeOprsWithBarrelShift ins bld addr
    sized ins.OprSize dst := src
  }

let msr (ins: Instruction) insLen bld addr =
  lift bld ins insLen {
    let struct (dst, src) = getTwoOprs ins
    match dst with
    | OprRegister R.NZCV ->
      let src = transOprToExpr ins bld addr src
      direct (regVar bld R.N) := AST.extract src 1<rt> 31
      direct (regVar bld R.Z) := AST.extract src 1<rt> 30
      direct (regVar bld R.C) := AST.extract src 1<rt> 29
      direct (regVar bld R.V) := AST.extract src 1<rt> 28
    | _ ->
      let dst = transOprToExpr ins bld addr dst
      let src = transOprToExpr ins bld addr src
      direct dst := src
  }

let msub ins insLen bld addr =
  lift bld ins insLen {
    let dst, src1, src2, src3 = transOprToExprOfMSUB ins bld addr
    sized ins.OprSize dst := src3 .- (src1 .* src2)
  }

let nop insAddr insLen bld =
  liftAt bld insAddr insLen { }

let ret ins insLen bld addr =
  lift bld ins insLen {
    let src = transOneOpr ins bld addr
    let target = tmpVar bld 64<rt>
    direct target := src
    branchTo ins bld target BrTypeRET InterJmpKind.IsRet
    return NoEndMark
  }

let rorv ins insLen bld addr =
  lift bld ins insLen {
    let dst, src1, src2 = transThreeOprs ins bld addr
    let amount = src2 .% oprSzToExpr ins.OprSize
    sized ins.OprSize dst := shiftReg src1 amount ins.OprSize ROR
  }

let sbc ins insLen bld addr =
  lift bld ins insLen {
    let dst, src1, src2 = transThreeOprs ins bld addr
    let c = AST.zext ins.OprSize (regVar bld R.C)
    let result, _ = addWithCarry src1 (AST.not src2) c ins.OprSize
    sized ins.OprSize dst := result
  }

let sbcs ins insLen bld addr =
  lift bld ins insLen {
    let dst, src1, src2 = transThreeOprs ins bld addr
    let c = tmpVar bld ins.OprSize
    direct c := AST.zext ins.OprSize (regVar bld R.C)
    let result, (n, z, c, v) = addWithCarry src1 (AST.not src2) c ins.OprSize
    direct (regVar bld R.N) := n
    direct (regVar bld R.Z) := z
    direct (regVar bld R.C) := c
    direct (regVar bld R.V) := v
    sized ins.OprSize dst := result
  }

let sbfm (ins: Instruction) insLen bld addr dst src immr imms =
  lift bld ins insLen {
    let oprSz = ins.OprSize
    let width = oprSzToExpr oprSz
    let struct (wmask, tmask) = decodeBitMasks immr imms (int oprSz)
    let immr = transOprToExpr ins bld addr immr
    let imms = transOprToExpr ins bld addr imms
    let n0 = AST.num0 oprSz
    let struct (bot, srcS, top, tMask) = tmpVars4 bld oprSz
    direct bot := rorForIR src immr width .& (numI64 wmask oprSz)
    direct srcS := (src >> imms) .& (AST.num1 oprSz)
    direct top := AST.ite (srcS == n0) n0 (numI32 -1 oprSz)
    direct tMask := numI64 tmask oprSz
    sized ins.OprSize dst := (top .& AST.not tMask) .| (bot .& tMask)
  }

let sbfiz ins insLen bld addr =
  let struct (dst, src, lsb, width) = getFourOprs ins
  let dst = transOprToExpr ins bld addr dst
  let src = transOprToExpr ins bld addr src
  let immr = ((getImmValue lsb * -1L) &&& 0x3FL) % int64 ins.OprSize |> OprImm
  let imms = getImmValue width - 1L |> OprImm
  sbfm ins insLen bld addr dst src immr imms

let sbfx ins insLen bld addr =
  let struct (dst, src, lsb, width) = getFourOprs ins
  let dst = transOprToExpr ins bld addr dst
  let src = transOprToExpr ins bld addr src
  let imms = (getImmValue lsb) + (getImmValue width) - 1L |> OprImm
  sbfm ins insLen bld addr dst src lsb imms

let sdiv ins insLen bld addr =
  lift bld ins insLen {
    let dst, src1, src2 = transThreeOprs ins bld addr
    let num0 = AST.num0 ins.OprSize
    let cond1 = AST.eq src2 num0
    let divSrc = src1 ?/ src2
    let result = AST.ite cond1 num0 divSrc
    sized ins.OprSize dst := result
  }

let smaddl ins insLen bld addr =
  lift bld ins insLen {
    let dst, src1, src2, src3 = transFourOprs ins bld addr
    direct dst := src3 .+ (AST.sext 64<rt> src1 .* AST.sext 64<rt> src2)
  }

let smov (ins: Instruction) insLen bld addr =
  lift bld ins insLen {
    let result = tmpVar bld ins.OprSize
    let dst, src = transTwoOprs ins bld addr
    direct result := AST.sext ins.OprSize src
    sized ins.OprSize dst := result
  }

let smsubl ins insLen bld addr =
  lift bld ins insLen {
    let dst, src1, src2, src3 = transOprToExprOfSMSUBL ins bld addr
    direct dst := src3 .- (AST.sext 64<rt> src1 .* AST.sext 64<rt> src2)
  }

let stlr ins insLen bld addr =
  lift bld ins insLen {
    let src, (bReg, offset) = transTwoOprsSepMem ins bld addr
    let address = tmpVar bld 64<rt>
    direct address := bReg .+ offset
    sized ins.OprSize (AST.loadLE ins.OprSize address) := src
  }

let stlrb ins insLen bld addr =
  lift bld ins insLen {
    let src, (bReg, offset) = transTwoOprsSepMem ins bld addr
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld 8<rt>
    direct address := bReg .+ offset
    direct data := AST.xtlo 8<rt> src
    direct (AST.loadLE 8<rt> address) := data
  }

let stlx ins insLen bld addr size =
  lift bld ins insLen {
    let src1, src2, (bReg, offset) = transThreeOprsSepMem ins bld addr
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld size
    direct address := bReg .+ offset
    direct data := AST.xtlo size src2
    let status = storeExclusive bld address size data
    sized 32<rt> src1 := status
  }

let stlxr ins insLen bld addr =
  lift bld ins insLen {
    let src1, src2, (bReg, offset) = transThreeOprsSepMem ins bld addr
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld ins.OprSize
    direct address := bReg .+ offset
    direct data := AST.zext ins.OprSize src2
    let status = storeExclusive bld address ins.OprSize data
    sized 32<rt> src1 := status
  }

let stlxp ins insLen bld addr =
  lift bld ins insLen {
    let src1, src2, src3, (bReg, offset) = transFourOprsSepMem ins bld addr
    let address = tmpVar bld 64<rt>
    direct address := bReg .+ offset
    if ins.OprSize = 32<rt> then
      let data = tmpVar bld 64<rt>
      direct data := AST.concat (AST.xtlo 32<rt> src3) (AST.xtlo 32<rt> src2)
      let status = storeExclusive bld address 64<rt> data
      sized 32<rt> src1 := status
    else
      let status = storeExclusivePair bld address 64<rt> src2 src3
      sized 32<rt> src1 := status
  }

let strb ins insLen bld addr =
  lift bld ins insLen {
    let src, (bReg, offset) = transTwoOprsSepMem ins bld addr
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld 8<rt>
    direct address := bReg
    direct address := if isPostIndex then address else address .+ offset
    direct data := AST.xtlo 8<rt> src
    direct (AST.loadLE 8<rt> address) := data
    writeBack bld isWBack isPostIndex bReg address offset
  }

let strh ins insLen bld addr =
  lift bld ins insLen {
    let src, (bReg, offset) = transTwoOprsSepMem ins bld addr
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld 16<rt>
    direct address := bReg
    direct address := if isPostIndex then address else address .+ offset
    direct data := AST.xtlo 16<rt> src
    direct (AST.loadLE 16<rt> address) := data
    writeBack bld isWBack isPostIndex bReg address offset
  }

let sttrb ins insLen bld addr =
  lift bld ins insLen {
    let src, (bReg, offset) = transTwoOprsSepMem ins bld addr
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld 8<rt>
    direct address := bReg
    direct address := address .+ offset
    direct data := AST.xtlo 8<rt> src
    direct (AST.loadLE 8<rt> address) := data
  }

let sturb ins insLen bld addr =
  lift bld ins insLen {
    let src, (bReg, offset) = transTwoOprsSepMem ins bld addr
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld 8<rt>
    direct address := bReg
    direct address := address .+ offset
    direct data := AST.xtlo 8<rt> src
    direct (AST.loadLE 8<rt> address) := data
  }

let sturh ins insLen bld addr =
  lift bld ins insLen {
    let src, (bReg, offset) = transTwoOprsSepMem ins bld addr
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld 16<rt>
    direct address := bReg
    direct address := address .+ offset
    direct data := AST.xtlo 16<rt> src
    direct (AST.loadLE 16<rt> address) := data
  }

let subs (ins: Instruction) insLen bld addr =
  lift bld ins insLen {
    let dst, src1, src2 = transOprToExprOfSUBS ins bld addr
    let result, (n, z, c, v) =
      addWithCarry src1 src2 (AST.num1 ins.OprSize) ins.OprSize
    direct (regVar bld R.N) := n
    direct (regVar bld R.Z) := z
    direct (regVar bld R.C) := c
    direct (regVar bld R.V) := v
    sized ins.OprSize dst := result
  }

let svc (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let n =
      match ins.Operands with
      | OneOperand(OprImm n) -> int n
      | _ -> raise InvalidOperandException
    AST.sideEffect (Interrupt n)
  }

let sxtb ins insLen bld addr =
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr ins bld addr dst
  let src = transOprToExpr ins bld addr src
  let src = if ins.OprSize = 64<rt> then unwrapReg src else src
  sbfm ins insLen bld addr dst src (OprImm 0L) (OprImm 7L)

let sxth ins insLen bld addr =
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr ins bld addr dst
  let src = transOprToExpr ins bld addr src
  let src = if ins.OprSize = 64<rt> then unwrapReg src else src
  sbfm ins insLen bld addr dst src (OprImm 0L) (OprImm 15L)

let sxtw ins insLen bld addr =
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr ins bld addr dst
  let src = transOprToExpr ins bld addr src |> unwrapReg
  sbfm ins insLen bld addr dst src (OprImm 0L) (OprImm 31L)

let tbnz ins insLen bld addr =
  lift bld ins insLen {
    let test, imm, label = transThreeOprs ins bld addr
    let pc = numU64 (ins:Instruction).Address bld.RegType
    let fall = pc .+ numU32 insLen 64<rt>
    let cond = (test >> imm .& AST.num1 ins.OprSize) == AST.num1 ins.OprSize
    AST.intercjmp cond (pc .+ label) fall
    return NoEndMark
  }

let tbz ins insLen bld addr =
  lift bld ins insLen {
    let test, imm, label = transThreeOprs ins bld addr
    let pc = numU64 (ins:Instruction).Address bld.RegType
    let fall = pc .+ numU32 insLen 64<rt>
    let cond = (test >> imm .& AST.num1 ins.OprSize) == AST.num0 ins.OprSize
    AST.intercjmp cond (pc .+ label) fall
    return NoEndMark
  }

let tst ins insLen bld addr =
  lift bld ins insLen {
    let src1, src2 = transOprToExprOfTST ins bld addr
    let result = tmpVar bld ins.OprSize
    direct result := src1 .& src2
    direct (regVar bld R.N) := AST.xthi 1<rt> result
    direct (regVar bld R.Z) := result == AST.num0 ins.OprSize
    direct (regVar bld R.C) := AST.b0
    direct (regVar bld R.V) := AST.b0
  }

let ubfm (ins: Instruction) insLen bld addr dst src immr imms =
  lift bld ins insLen {
    let oSz = ins.OprSize
    let width = oprSzToExpr oSz
    let struct (wmask, tmask) = decodeBitMasks immr imms (int oSz)
    let dst = transOprToExpr ins bld addr dst
    let src = transOprToExpr ins bld addr src
    let immr = transOprToExpr ins bld addr immr
    let bot = tmpVar bld oSz
    direct bot := rorForIR src immr width .& (numI64 wmask oSz)
    sized ins.OprSize dst := bot .& (numI64 tmask oSz)
  }

let ubfiz ins insLen bld addr =
  let struct (dst, src, lsb, width) = getFourOprs ins
  let immr = ((getImmValue lsb * -1L) &&& 0x3FL) % int64 ins.OprSize |> OprImm
  let imms = getImmValue width - 1L |> OprImm
  ubfm ins insLen bld addr dst src immr imms

let ubfx ins insLen bld addr =
  let struct (dst, src, lsb, width) = getFourOprs ins
  let imms = (getImmValue lsb) + (getImmValue width) - 1L |> OprImm
  ubfm ins insLen bld addr dst src lsb imms

let udiv ins insLen bld addr =
  lift bld ins insLen {
    let dst, src1, src2 = transThreeOprs ins bld addr
    let num0 = AST.num0 ins.OprSize
    let cond1 = AST.eq src2 num0
    let divSrc = src1 ./ src2
    let result = AST.ite cond1 num0 divSrc
    sized ins.OprSize dst := result
  }

let umaddl ins insLen bld addr =
  lift bld ins insLen {
    let dst, src1, src2, src3 = transFourOprs ins bld addr
    direct dst := src3 .+ (AST.zext 64<rt> src1 .* AST.zext 64<rt> src2)
  }

let umov (ins: Instruction) insLen bld addr =
  lift bld ins insLen {
    let dst, src = transTwoOprs ins bld addr
    sized ins.OprSize dst := src
  }

let umsubl ins insLen bld addr =
  lift bld ins insLen {
    let dst, src1, src2, src3 = transOprToExprOfUMADDL ins bld addr
    direct dst := src3 .- (AST.zext 64<rt> src1 .* AST.zext 64<rt> src2)
  }

let uxtb ins insLen bld addr =
  let struct (dst, src) = getTwoOprs ins
  ubfm ins insLen bld addr dst src (OprImm 0L) (OprImm 7L)

let uxth ins insLen bld addr =
  let struct (dst, src) = getTwoOprs ins
  ubfm ins insLen bld addr dst src (OprImm 0L) (OprImm 15L)
