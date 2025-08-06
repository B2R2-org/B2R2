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

module internal B2R2.FrontEnd.Intel.X87Lifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.Intel
open B2R2.FrontEnd.Intel.LiftingUtils

#if !EMULATION
let private undefC0 = AST.undef 1<rt> "C0 is undefined."

let private undefC1 = AST.undef 1<rt> "C1 is undefined."

let private undefC2 = AST.undef 1<rt> "C2 is undefined."

let private undefC3 = AST.undef 1<rt> "C3 is undefined."

let private allCFlagsUndefined bld =
  bld <+ (regVar bld R.FSWC0 := undefC0)
  bld <+ (regVar bld R.FSWC1 := undefC1)
  bld <+ (regVar bld R.FSWC2 := undefC2)
  bld <+ (regVar bld R.FSWC3 := undefC3)

let private cflagsUndefined023 bld =
  bld <+ (regVar bld R.FSWC0 := undefC0)
  bld <+ (regVar bld R.FSWC2 := undefC2)
  bld <+ (regVar bld R.FSWC3 := undefC3)
#endif

let inline private getFPUPseudoRegVars bld r =
  struct (pseudoRegVar bld r 2, pseudoRegVar bld r 1)

let private updateC1OnLoad bld =
  let top = regVar bld R.FTOP
  let c1Flag = regVar bld R.FSWC1
  (* Top value has been wrapped around, which means stack overflow in B2R2. *)
  bld <+ (c1Flag := (top == AST.num0 8<rt>))
#if !EMULATION
  bld <+ (regVar bld R.FSWC0 := undefC0)
  bld <+ (regVar bld R.FSWC2 := undefC2)
  bld <+ (regVar bld R.FSWC3 := undefC3)
#endif

let private updateC1OnStore bld =
  let top = regVar bld R.FTOP
  let c1Flag = regVar bld R.FSWC1
  (* Top value has been wrapped around, which means stack underflow in B2R2. *)
  bld <+ (c1Flag := (top != numI32 7 8<rt>))
#if !EMULATION
  bld <+ (regVar bld R.FSWC0 := undefC0)
  bld <+ (regVar bld R.FSWC2 := undefC2)
  bld <+ (regVar bld R.FSWC3 := undefC3)
#endif

let private moveFPRegtoFPReg regdst regsrc bld =
  let struct (dstB, dstA) = getFPUPseudoRegVars bld regdst
  let struct (srcB, srcA) = getFPUPseudoRegVars bld regsrc
  bld <+ (dstA := srcA)
  bld <+ (dstB := srcB)

let private moveFPRegtoTemp src bld =
  let tmpA = tmpVar bld 64<rt>
  let tmpB = tmpVar bld 16<rt>
  let struct (srcB, srcA) = getFPUPseudoRegVars bld src
  bld <+ (tmpA := srcA)
  bld <+ (tmpB := srcB)
  struct (tmpB, tmpA)

let private moveTemptoFPReg dst tmpA tmpB bld =
  let struct (dstB, dstA) = getFPUPseudoRegVars bld dst
  bld <+ (dstA := tmpA)
  bld <+ (dstB := tmpB)

let private clearFPReg reg bld =
  let struct (stB, stA) = getFPUPseudoRegVars bld reg
  bld <+ (stB := AST.num0 16<rt>)
  bld <+ (stA := AST.num0 64<rt>)

let private pushFPUStack bld =
  let top = regVar bld R.FTOP
  (* We increment TOP here (which is the opposite way of what the manual says),
     because it is more intuitive to consider it as a counter. *)
  bld <+ (extractDstAssign top (top .+ AST.num1 8<rt>))
  moveFPRegtoFPReg R.ST7 R.ST6 bld
  moveFPRegtoFPReg R.ST6 R.ST5 bld
  moveFPRegtoFPReg R.ST5 R.ST4 bld
  moveFPRegtoFPReg R.ST4 R.ST3 bld
  moveFPRegtoFPReg R.ST3 R.ST2 bld
  moveFPRegtoFPReg R.ST2 R.ST1 bld
  moveFPRegtoFPReg R.ST1 R.ST0 bld

let private popFPUStack bld =
  let top = regVar bld R.FTOP
  (* We decrement TOP here (the opposite way compared to the manual) because it
     is more intuitive, because it is more intuitive to consider it as a
     counter. *)
  bld <+ (extractDstAssign top (top .- AST.num1 8<rt>))
  moveFPRegtoFPReg R.ST0 R.ST1 bld
  moveFPRegtoFPReg R.ST1 R.ST2 bld
  moveFPRegtoFPReg R.ST2 R.ST3 bld
  moveFPRegtoFPReg R.ST3 R.ST4 bld
  moveFPRegtoFPReg R.ST4 R.ST5 bld
  moveFPRegtoFPReg R.ST5 R.ST6 bld
  moveFPRegtoFPReg R.ST6 R.ST7 bld
  clearFPReg R.ST7 bld

let inline private getLoadAddressExpr (src: Expr) =
  match src with
  | Load(_, _, addr, _) -> struct (addr, Expr.TypeOf addr)
  | _ -> Terminator.impossible ()

let private castTo80Bit bld tmpB tmpA srcExpr =
  let oprSize = Expr.TypeOf srcExpr
  let zero = AST.num0 oprSize
  match oprSize with
  | 32<rt> ->
    let tmpSrc = tmpVar bld oprSize
    let biasedExponent = tmpVar bld 16<rt>
    let n31 = numI32 31 32<rt>
    let n15 = numI32 15 16<rt>
    let n23 = numI32 23 32<rt>
    let one = numI32 1 32<rt>
    let biasDiff = numI32 0x3f80 16<rt>
    let sign = (AST.xtlo 16<rt> ((tmpSrc >> n31) .& one)) << n15
    let integerpart = numI64 0x8000000000000000L 64<rt>
    let significand = (AST.zext 64<rt> (tmpSrc .& numI32 0x7fffff 32<rt>))
    bld <+ (tmpSrc := srcExpr)
    bld <+ (biasedExponent :=
      AST.xtlo 16<rt> ((tmpSrc >> n23) .& (numI32 0xff 32<rt>)))
    let exponent =
      AST.ite (biasedExponent == numI32 0 16<rt>) (numI32 0 16<rt>)
        (AST.ite (biasedExponent == numI32 0xff 16<rt>)
          (numI32 0x7fff 16<rt>)
          (biasedExponent .+ biasDiff))
    bld <+ (tmpB := sign .| exponent)
    bld <+ (tmpA :=
      AST.ite
        (AST.eq tmpSrc zero)
        (AST.num0 64<rt>)
        (integerpart .| (significand << numI32 40 64<rt>)))
  | 64<rt> ->
    let tmpSrc = tmpVar bld oprSize
    let biasedExponent = tmpVar bld 16<rt>
    let n63 = numI32 63 64<rt>
    let n15 = numI32 15 16<rt>
    let n52 = numI32 52 64<rt>
    let one = numI32 1 64<rt>
    let biasDiff = numI32 0x3c00 16<rt>
    let sign = (AST.xtlo 16<rt> (((tmpSrc >> n63) .& one))) << n15
    let integerpart = numI64 0x8000000000000000L 64<rt>
    let significand = tmpSrc .& numI64 0xFFFFFFFFFFFFFL 64<rt>
    bld <+ (tmpSrc := srcExpr)
    bld <+ (biasedExponent :=
      AST.xtlo 16<rt> ((tmpSrc >> n52) .& (numI32 0x7ff 64<rt>)))
    let exponent =
      AST.ite (biasedExponent == numI32 0 16<rt>) (numI32 0 16<rt>)
        (AST.ite (biasedExponent == numI32 0x7ff 16<rt>)
          (numI32 0x7fff 16<rt>)
          (biasedExponent .+ biasDiff))
    bld <+ (tmpB := sign .| exponent)
    bld <+ (tmpA :=
      AST.ite
        (AST.eq tmpSrc zero)
        (AST.num0 64<rt>)
        (integerpart .| (significand << numI32 11 64<rt>)))
  | 80<rt> ->
    match srcExpr with
    | Load(_, _, addrExpr, _) ->
      let addrSize = Expr.TypeOf addrExpr
      bld <+ (tmpB := AST.loadLE 16<rt> (addrExpr .+ numI32 8 addrSize))
      bld <+ (tmpA := AST.loadLE 64<rt> addrExpr)
    | BinOp(_, _, Var(_, r, _, _), Var _, _) ->
      let reg = Register.pseudoRegToReg (Register.ofRegID r)
      let struct (srcB, srcA) = getFPUPseudoRegVars bld reg
      bld <+ (tmpB := srcB)
      bld <+ (tmpA := srcA)
    | _ -> raise InvalidOperandException
  | _ -> Terminator.impossible ()

let private fpuLoad (ins: Instruction) insLen bld oprExpr =
  let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
  let tmpB, tmpA = tmpVar bld 16<rt>, bld.Stream.NewTempVar 64<rt>
  bld <!-- (ins.Address, insLen)
  castTo80Bit bld tmpB tmpA oprExpr
  pushFPUStack bld
  bld <+ (st0b := tmpB)
  bld <+ (st0a := tmpA)
  updateC1OnLoad bld
  bld --!> insLen

let fld (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprExpr = transOneOpr bld ins insLen
  let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
  let tmpB, tmpA = tmpVar bld 16<rt>, bld.Stream.NewTempVar 64<rt>
  castTo80Bit bld tmpB tmpA oprExpr
  pushFPUStack bld
  bld <+ (st0b := tmpB)
  bld <+ (st0a := tmpA)
  updateC1OnLoad bld
  bld --!> insLen

let private castFrom80Bit dstExpr dstSize srcB srcA bld =
  match dstSize with
  | 16<rt> ->
    let sign = srcB .& (numI32 0x8000 16<rt>)
    let biasDiff = numI32 0x3ff0 16<rt>
    let tmpExp = tmpVar bld 16<rt>
    let exp = srcB .& numI32 0x7fff 16<rt>
    let computedExp = exp .- biasDiff
    let maxExp = numI32 0x1f 16<rt>
    let exponent =
      AST.ite (exp == AST.num0 16<rt>) (AST.num0 16<rt>)
        (AST.ite (exp == numI32 0x7fff 16<rt>) (numI32 0x1f 16<rt>)
          (AST.ite (computedExp .> maxExp) maxExp computedExp))
      << numI32 10 dstSize
    let n53 = numI32 53 64<rt>
    let significand =
      AST.xtlo 16<rt> ((srcA .& numI64 0x7FFFFFFFFFFFFFFFL 64<rt>) >> n53)
    bld <+ (tmpExp := computedExp)
    bld <+ (dstExpr := (sign .| exponent .| significand))
  | 32<rt> ->
    let n48 = numI32 48 64<rt>
    let sign = (AST.zext 64<rt> srcB .& (numI32 0x8000 64<rt>)) << n48
    let biasDiff = numI32 0x3c00 64<rt>
    let tmpExp = tmpVar bld 64<rt>
    let tmpExp2 = tmpVar bld 64<rt>
    let exp = srcB .& numI32 0x7fff 16<rt>
    let computedExp = AST.zext 64<rt> exp .- biasDiff
    let maxExp = numI32 0x7ff 64<rt>
    let exponent =
      AST.ite (exp == AST.num0 16<rt>) (AST.num0 64<rt>)
        (AST.ite (exp == numI32 0x7fff 16<rt>) (numI32 0x7ff 64<rt>)
          (AST.ite (computedExp .> maxExp) maxExp computedExp))
      << numI32 52 64<rt>
    let n11 = numI32 11 64<rt>
    let significand = (srcA .& numI64 0x7FFFFFFFFFFFFFFFL 64<rt>) >> n11
    bld <+ (tmpExp := computedExp)
    bld <+ (tmpExp2 := (sign .| exponent .| significand))
    bld <+ (dstExpr := AST.cast CastKind.FloatCast 32<rt> tmpExp2)
  | 64<rt> ->
    let n48 = numI32 48 64<rt>
    let sign = (AST.zext 64<rt> srcB .& (numI32 0x8000 64<rt>)) << n48
    let biasDiff = numI32 0x3c00 64<rt>
    let tmpExp = tmpVar bld 64<rt>
    let exp = srcB .& numI32 0x7fff 16<rt>
    let computedExp = AST.zext 64<rt> exp .- biasDiff
    let maxExp = numI32 0x7ff 64<rt>
    let exponent =
      AST.ite (exp == AST.num0 16<rt>) (AST.num0 64<rt>)
        (AST.ite (exp == numI32 0x7fff 16<rt>) (numI32 0x7ff 64<rt>)
          (AST.ite (computedExp .> maxExp) maxExp computedExp))
      << numI32 52 64<rt>
    let n11 = numI32 11 64<rt>
    let significand = (srcA .& numI64 0x7FFFFFFFFFFFFFFFL 64<rt>) >> n11
    bld <+ (tmpExp := computedExp)
    bld <+ (dstExpr := (sign .| exponent .| significand))
  | 80<rt> ->
    let struct (addrExpr, addrSize) = getLoadAddressExpr dstExpr
    bld <+ (AST.store Endian.Little (addrExpr) srcA)
    bld <+ (AST.store Endian.Little (addrExpr .+ numI32 8 addrSize) srcB)
  | _ -> Terminator.impossible ()

let ffst (ins: Instruction) insLen bld doPop =
  let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | OneOperand(OprReg r) ->
    let struct (dstB, dstA) = getFPUPseudoRegVars bld r
    bld <+ (dstB := st0b)
    bld <+ (dstA := st0a)
  | OneOperand(opr) ->
    let oprExpr = transOprToExpr bld false ins insLen opr
    let oprSize = Expr.TypeOf oprExpr
    castFrom80Bit oprExpr oprSize st0b st0a bld
  | _ -> raise InvalidOperandException
  if doPop then popFPUStack bld else ()
  updateC1OnStore bld
  bld --!> insLen

let fild (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
  let oprExpr = transOneOpr bld ins insLen
  let tmpB, tmpA = tmpVar bld 16<rt>, bld.Stream.NewTempVar 64<rt>
  castTo80Bit bld tmpB tmpA (AST.cast CastKind.SIntToFloat 64<rt> oprExpr)
  pushFPUStack bld
  bld <+ (st0b := tmpB)
  bld <+ (st0a := tmpA)
  updateC1OnLoad bld
  bld --!> insLen

let fist (ins: Instruction) insLen bld doPop =
  bld <!-- (ins.Address, insLen)
  let oprExpr = transOneOpr bld ins insLen
  let oprSize = Expr.TypeOf oprExpr
  let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
  let tmp0 = tmpVar bld oprSize
  let rcField = tmpVar bld 8<rt> (* Rounding Control *)
  let num2 = numI32 2 8<rt>
  let cst00 = AST.cast CastKind.FtoIRound oprSize tmp0
  let cst01 = AST.cast CastKind.FtoIFloor oprSize tmp0
  let cst10 = AST.cast CastKind.FtoICeil oprSize tmp0
  let cst11 = AST.cast CastKind.FtoITrunc oprSize tmp0
  castFrom80Bit tmp0 oprSize st0b st0a bld
  bld <+ (rcField := (AST.zext 8<rt> (AST.extract (regVar bld R.FCW) 1<rt> 10)))
  bld <+ (rcField := (rcField << AST.num1 8<rt>))
  bld <+ (rcField :=
    (rcField .| (AST.zext 8<rt> (AST.extract (regVar bld R.FCW) 1<rt> 11))))
  bld <+ (tmp0 := AST.ite (rcField == AST.num0 8<rt>) cst00 cst11)
  bld <+ (tmp0 := AST.ite (rcField == AST.num1 8<rt>) cst01 tmp0)
  bld <+ (tmp0 := AST.ite (rcField == num2) cst10 tmp0)
  bld <+ (oprExpr := tmp0)
  if doPop then popFPUStack bld else ()
  updateC1OnStore bld
  bld --!> insLen

let fisttp (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprExpr = transOneOpr bld ins insLen
  let oprSize = Expr.TypeOf oprExpr
  let tmp1 = tmpVar bld 64<rt>
  let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
  castFrom80Bit tmp1 64<rt> st0b st0a bld
  bld <+ (oprExpr := AST.cast CastKind.FtoITrunc oprSize tmp1)
  popFPUStack bld
  bld <+ (regVar bld R.FSWC1 := AST.b0)
#if !EMULATION
  bld <+ (regVar bld R.FSWC0 := undefC0)
  bld <+ (regVar bld R.FSWC2 := undefC2)
  bld <+ (regVar bld R.FSWC3 := undefC3)
#endif
  bld --!> insLen

let private getTwoBCDDigits addrExpr addrSize startPos =
  let byteValue = AST.loadLE 8<rt> (addrExpr .+ numI32 startPos addrSize)
  let d1 =
    let msb = AST.extract byteValue 1<rt> 3
    (byteValue .& (AST.sext 8<rt> msb .| numI32 0xF0 8<rt>)) |> AST.sext 64<rt>
  let d2 =
    let msb = AST.extract byteValue 1<rt> 7
    ((byteValue >> numI32 4 8<rt>) .& (AST.sext 8<rt> msb .| numI32 0xF0 8<rt>))
    |> AST.sext 64<rt>
  struct (d1, d2)

let private bcdToInt intgr addrExpr addrSize bld =
  let struct (d1, d2) = getTwoBCDDigits addrExpr addrSize 0
  let struct (d3, d4) = getTwoBCDDigits addrExpr addrSize 1
  let struct (d5, d6) = getTwoBCDDigits addrExpr addrSize 2
  let struct (d7, d8) = getTwoBCDDigits addrExpr addrSize 3
  let struct (d9, d10) = getTwoBCDDigits addrExpr addrSize 4
  let struct (d11, d12) = getTwoBCDDigits addrExpr addrSize 5
  let struct (d13, d14) = getTwoBCDDigits addrExpr addrSize 6
  let struct (d15, d16) = getTwoBCDDigits addrExpr addrSize 7
  let struct (d17, d18) = getTwoBCDDigits addrExpr addrSize 8
  let signByte = AST.loadLE 8<rt> (addrExpr .+ numI32 9 addrSize)
  let signBit = AST.xthi 1<rt> signByte
  bld <+ (intgr := d1)
  bld <+ (intgr := intgr .+ d2 .* numI64 10L 64<rt>)
  bld <+ (intgr := intgr .+ d3 .* numI64 100L 64<rt>)
  bld <+ (intgr := intgr .+ d4 .* numI64 1000L 64<rt>)
  bld <+ (intgr := intgr .+ d5 .* numI64 10000L 64<rt>)
  bld <+ (intgr := intgr .+ d6 .* numI64 100000L 64<rt>)
  bld <+ (intgr := intgr .+ d7 .* numI64 1000000L 64<rt>)
  bld <+ (intgr := intgr .+ d8 .* numI64 10000000L 64<rt>)
  bld <+ (intgr := intgr .+ d9 .* numI64 100000000L 64<rt>)
  bld <+ (intgr := intgr .+ d10 .* numI64 1000000000L 64<rt>)
  bld <+ (intgr := intgr .+ d11 .* numI64 10000000000L 64<rt>)
  bld <+ (intgr := intgr .+ d12 .* numI64 100000000000L 64<rt>)
  bld <+ (intgr := intgr .+ d13 .* numI64 1000000000000L 64<rt>)
  bld <+ (intgr := intgr .+ d14 .* numI64 10000000000000L 64<rt>)
  bld <+ (intgr := intgr .+ d15 .* numI64 100000000000000L 64<rt>)
  bld <+ (intgr := intgr .+ d16 .* numI64 1000000000000000L 64<rt>)
  bld <+ (intgr := intgr .+ d17 .* numI64 10000000000000000L 64<rt>)
  bld <+ (intgr := intgr .+ d18 .* numI64 100000000000000000L 64<rt>)
  bld <+ (AST.xthi 1<rt> intgr := signBit)

let fbld (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
  let src = transOneOpr bld ins insLen
  let struct (addrExpr, addrSize) = getLoadAddressExpr src
  let intgr = tmpVar bld 64<rt>
  let tmpB, tmpA = tmpVar bld 16<rt>, bld.Stream.NewTempVar 64<rt>
  bcdToInt intgr addrExpr addrSize bld
  castTo80Bit bld tmpB tmpA (AST.cast CastKind.SIntToFloat 64<rt> intgr)
  pushFPUStack bld
  bld <+ (st0b := tmpB)
  bld <+ (st0a := tmpA)
  updateC1OnLoad bld
  bld --!> insLen

let private storeTwoDigitBCD n10 addrExpr addrSize intgr pos bld =
  let d1 = (AST.xtlo 8<rt> (intgr .% n10)) .& (numI32 0xF 8<rt>)
  let d2 = (AST.xtlo 8<rt> ((intgr ./ n10) .% n10)) .& (numI32 0xF 8<rt>)
  let ds = (d2 << (numI32 4 8<rt>)) .| d1
  bld <+ (AST.store Endian.Little (addrExpr .+ numI32 pos addrSize) ds)

let private storeBCD addrExpr addrSize intgr bld =
  let n10 = numI32 10 64<rt>
  let n100 = numI32 100 64<rt>
  let sign = tmpVar bld 1<rt>
  let signByte = (AST.zext 8<rt> sign) << numI32 7 8<rt>
  bld <+ (sign := AST.xthi 1<rt> intgr)
  storeTwoDigitBCD n10 addrExpr addrSize intgr 0 bld
  bld <+ (intgr := intgr ./ n100)
  storeTwoDigitBCD n10 addrExpr addrSize intgr 1 bld
  bld <+ (intgr := intgr ./ n100)
  storeTwoDigitBCD n10 addrExpr addrSize intgr 2 bld
  bld <+ (intgr := intgr ./ n100)
  storeTwoDigitBCD n10 addrExpr addrSize intgr 3 bld
  bld <+ (intgr := intgr ./ n100)
  storeTwoDigitBCD n10 addrExpr addrSize intgr 4 bld
  bld <+ (intgr := intgr ./ n100)
  storeTwoDigitBCD n10 addrExpr addrSize intgr 5 bld
  bld <+ (intgr := intgr ./ n100)
  storeTwoDigitBCD n10 addrExpr addrSize intgr 6 bld
  bld <+ (intgr := intgr ./ n100)
  storeTwoDigitBCD n10 addrExpr addrSize intgr 7 bld
  bld <+ (intgr := intgr ./ n100)
  storeTwoDigitBCD n10 addrExpr addrSize intgr 8 bld
  bld <+ (AST.store Endian.Little (addrExpr .+ numI32 9 addrSize) signByte)

let fbstp (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let dst = transOneOpr bld ins insLen
  let struct (addrExpr, addrSize) = getLoadAddressExpr dst
  let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
  let tmp = tmpVar bld 64<rt>
  let intgr = tmpVar bld 64<rt>
  castFrom80Bit tmp 64<rt> st0b st0a bld
  bld <+ (intgr := AST.cast CastKind.FtoIRound 64<rt> tmp)
  storeBCD addrExpr addrSize intgr bld
  popFPUStack bld
  updateC1OnStore bld
  bld --!> insLen

let fxch (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
  let tmpB, tmpA = tmpVar bld 16<rt>, bld.Stream.NewTempVar 64<rt>
  bld <+ (tmpB := st0b)
  bld <+ (tmpA := st0a)
  let struct (srcB, srcA) =
    match ins.Operands with
    | OneOperand(OprReg reg) -> getFPUPseudoRegVars bld reg
    | NoOperand -> getFPUPseudoRegVars bld R.ST1
    | _ -> raise InvalidOperandException
  bld <+ (st0b := srcB)
  bld <+ (st0a := srcA)
  bld <+ (srcB := tmpB)
  bld <+ (srcA := tmpA)
  bld <+ (regVar bld R.FSWC1 := AST.b0)
#if !EMULATION
  cflagsUndefined023 bld
#endif
  bld --!> insLen

let private fcmov (ins: Instruction) insLen bld cond =
  let srcReg =
    match ins.Operands with
    | TwoOperands(_, OprReg reg) -> reg
    | _ -> raise InvalidOperandException
  let struct (srcB, srcA) = getFPUPseudoRegVars bld srcReg
  let struct (dstB, dstA) = getFPUPseudoRegVars bld R.ST0
  bld <+ (dstB := AST.ite cond srcB dstB)
  bld <+ (dstA := AST.ite cond srcA dstA)
#if !EMULATION
  bld <+ (regVar bld R.FSWC0 := undefC0)
  bld <+ (regVar bld R.FSWC2 := undefC2)
  bld <+ (regVar bld R.FSWC3 := undefC3)
#endif

let fcmove (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
#if EMULATION
  getZFLazy bld |> fcmov ins insLen bld
#else
  regVar bld R.ZF |> fcmov ins insLen bld
#endif
  bld --!> insLen

let fcmovne (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
#if EMULATION
  getZFLazy bld |> AST.not |> fcmov ins insLen bld
#else
  regVar bld R.ZF |> AST.not |> fcmov ins insLen bld
#endif
  bld --!> insLen

let fcmovb (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
#if EMULATION
  getCFLazy bld |> fcmov ins insLen bld
#else
  regVar bld R.CF |> fcmov ins insLen bld
#endif
  bld --!> insLen

let fcmovbe (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
#if EMULATION
  (getCFLazy bld .| getZFLazy bld) |> fcmov ins insLen bld
#else
  (regVar bld R.CF .| regVar bld R.ZF) |> fcmov ins insLen bld
#endif
  bld --!> insLen

let fcmovnb (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
#if EMULATION
  getCFLazy bld |> AST.not |> fcmov ins insLen bld
#else
  regVar bld R.CF |> AST.not |> fcmov ins insLen bld
#endif
  bld --!> insLen

let fcmovnbe (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
#if EMULATION
  let cond1 = getCFLazy bld |> AST.not
  let cond2 = getZFLazy bld |> AST.not
#else
  let cond1 = regVar bld R.CF |> AST.not
  let cond2 = regVar bld R.ZF |> AST.not
#endif
  cond1 .& cond2 |> fcmov ins insLen bld
  bld --!> insLen

let fcmovu (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
#if EMULATION
  getPFLazy bld |> fcmov ins insLen bld
#else
  regVar bld R.PF |> fcmov ins insLen bld
#endif
  bld --!> insLen

let fcmovnu (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
#if EMULATION
  getPFLazy bld |> AST.not |> fcmov ins insLen bld
#else
  regVar bld R.PF |> AST.not |> fcmov ins insLen bld
#endif
  bld --!> insLen

let private fpuFBinOp (ins: Instruction) insLen bld binOp doPop leftToRight =
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | NoOperand ->
    let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
    let struct (st1b, st1a) = getFPUPseudoRegVars bld R.ST1
    let struct (tmp0, tmp1) = tmpVars2 bld 64<rt>
    let res = tmpVar bld 64<rt>
    castFrom80Bit tmp0 64<rt> st0b st0a bld
    castFrom80Bit tmp1 64<rt> st1b st1a bld
    if leftToRight then bld <+ (res := binOp tmp0 tmp1)
    else bld <+ (res := binOp tmp1 tmp0)
    castTo80Bit bld st1b st1a res
  | OneOperand _ ->
    let oprExpr = transOneOpr bld ins insLen
    let oprSize = Expr.TypeOf oprExpr
    let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
    let struct (tmp0, tmp1) = tmpVars2 bld 64<rt>
    let res = tmpVar bld 64<rt>
    castFrom80Bit tmp0 64<rt> st0b st0a bld
    if oprSize = 64<rt> then bld <+ (tmp1 := oprExpr)
    else bld <+ (tmp1 := AST.cast CastKind.FloatCast 64<rt> oprExpr)
    if leftToRight then bld <+ (res := binOp tmp0 tmp1)
    else bld <+ (res := binOp tmp1 tmp0)
    castTo80Bit bld st0b st0a res
  | TwoOperands(OprReg reg0, OprReg reg1) ->
    let struct (r0B, r0A) = getFPUPseudoRegVars bld reg0
    let struct (r1B, r1A) = getFPUPseudoRegVars bld reg1
    let struct (tmp0, tmp1) = tmpVars2 bld 64<rt>
    let res = tmpVar bld 64<rt>
    castFrom80Bit tmp0 64<rt> r0B r0A bld
    castFrom80Bit tmp1 64<rt> r1B r1A bld
    if leftToRight then bld <+ (res := binOp tmp0 tmp1)
    else bld <+ (res := binOp tmp1 tmp0)
    castTo80Bit bld r0B r0A res
  | _ -> raise InvalidOperandException
  if doPop then popFPUStack bld else ()
  updateC1OnStore bld
  bld --!> insLen

let private fpuIntOp (ins: Instruction) insLen bld binOp leftToRight =
  bld <!-- (ins.Address, insLen)
  let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
  let oprExpr = transOneOpr bld ins insLen
  let struct (tmp, dst) = tmpVars2 bld 64<rt>
  let res = tmpVar bld 64<rt>
  bld <+ (tmp := AST.cast CastKind.SIntToFloat 64<rt> oprExpr)
  castFrom80Bit dst 64<rt> st0b st0a bld
  if leftToRight then bld <+ (res := binOp dst tmp)
  else bld <+ (res := binOp tmp dst)
  castTo80Bit bld st0b st0a res
  bld --!> insLen

let fpuadd ins insLen bld doPop =
  fpuFBinOp ins insLen bld AST.fadd doPop true

let fiadd ins insLen bld =
  fpuIntOp ins insLen bld AST.fadd true

let fpusub ins insLen bld doPop =
  fpuFBinOp ins insLen bld AST.fsub doPop true

let fisub ins insLen bld =
  fpuIntOp ins insLen bld AST.fsub true

let fsubr ins insLen bld doPop =
  fpuFBinOp ins insLen bld AST.fsub doPop false

let fisubr ins insLen bld =
  fpuIntOp ins insLen bld AST.fsub false

let fpumul ins insLen bld doPop =
  fpuFBinOp ins insLen bld AST.fmul doPop true

let fimul ins insLen bld =
  fpuIntOp ins insLen bld AST.fmul true

let fpudiv ins insLen bld doPop =
  fpuFBinOp ins insLen bld AST.fdiv doPop true

let fidiv ins insLen bld =
  fpuIntOp ins insLen bld AST.fdiv true

let private isZero exponent significand =
  (exponent == (AST.num0 16<rt>)) .& (significand == (AST.num0 64<rt>))

let fdivr (ins: Instruction) insLen bld doPop =
  bld <!-- (ins.Address, insLen)
  let lblChk = label bld "Check"
  let lblErr = label bld "DivErr"
  let struct (tmp0, tmp1) = tmpVars2 bld 64<rt>
  let res = tmpVar bld 64<rt>
  match ins.Operands with
  | NoOperand ->
    let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
    let struct (st1b, st1a) = getFPUPseudoRegVars bld R.ST1
    bld <+ (AST.cjmp (isZero st0b st0a)
                     (AST.jmpDest lblErr) (AST.jmpDest lblChk))
    bld <+ (AST.lmark lblErr)
    bld <+ (AST.sideEffect (Exception "DivErr"))
    bld <+ (AST.lmark lblChk)
    castFrom80Bit tmp0 64<rt> st0b st0a bld
    castFrom80Bit tmp1 64<rt> st1b st1a bld
    bld <+ (res := AST.fdiv tmp1 tmp0)
    castTo80Bit bld st1b st1a res
  | OneOperand _ ->
    let oprExpr = transOneOpr bld ins insLen
    let oprSize = Expr.TypeOf oprExpr
    let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
    bld <+ (AST.cjmp (isZero st0b st0a)
                     (AST.jmpDest lblErr) (AST.jmpDest lblChk))
    bld <+ (AST.lmark lblErr)
    bld <+ (AST.sideEffect (Exception "DivErr"))
    bld <+ (AST.lmark lblChk)
    castFrom80Bit tmp0 64<rt> st0b st0a bld
    if oprSize = 64<rt> then bld <+ (tmp1 := oprExpr)
    else bld <+ (tmp1 := AST.cast CastKind.FloatCast 64<rt> oprExpr)
    bld <+ (res := AST.fdiv tmp1 tmp0)
    castTo80Bit bld st0b st0a res
  | TwoOperands(OprReg reg0, OprReg reg1) ->
    let struct (r0B, r0A) = getFPUPseudoRegVars bld reg0
    let struct (r1B, r1A) = getFPUPseudoRegVars bld reg1
    bld <+ (AST.cjmp (isZero r0B r0A) (AST.jmpDest lblErr) (AST.jmpDest lblChk))
    bld <+ (AST.lmark lblErr)
    bld <+ (AST.sideEffect (Exception "DivErr"))
    bld <+ (AST.lmark lblChk)
    castFrom80Bit tmp0 64<rt> r0B r0A bld
    castFrom80Bit tmp1 64<rt> r1B r1A bld
    bld <+ (res := AST.fdiv tmp1 tmp0)
    castTo80Bit bld r0B r0A res
  | _ -> raise InvalidOperandException
  if doPop then popFPUStack bld else ()
  updateC1OnStore bld
  bld --!> insLen

let fidivr ins insLen bld =
  fpuIntOp ins insLen bld AST.fdiv false

let inline private castToF64 intexp =
  AST.cast CastKind.SIntToFloat 64<rt> intexp

let getExponent isDouble src =
  if isDouble then
    let numMantissa =  numI32 52 64<rt>
    let mask = numI32 0x7FF 64<rt>
    AST.xtlo 32<rt> ((src >> numMantissa) .& mask)
  else
    let numMantissa = numI32 23 32<rt>
    let mask = numI32 0xff 32<rt>
    (src >> numMantissa) .& mask

let getMantissa isDouble src =
  let mask =
    if isDouble then numU64 0xfffff_ffffffffUL 64<rt>
    else numU64 0x7fffffUL 32<rt>
  src .& mask

let isNan isDouble expr =
  let exponent = getExponent isDouble expr
  let mantissa = getMantissa isDouble expr
  let e = if isDouble then numI32 0x7ff 32<rt> else numI32 0xff 32<rt>
  let zero = if isDouble then AST.num0 64<rt> else AST.num0 32<rt>
  (exponent == e) .& (mantissa != zero)

let isInf isDouble expr =
  let exponent = getExponent isDouble expr
  let mantissa = getMantissa isDouble expr
  let e = if isDouble then numI32 0x7ff 32<rt> else numI32 0xff 32<rt>
  let zero = if isDouble then AST.num0 64<rt> else AST.num0 32<rt>
  (exponent == e) .& (mantissa == zero)

let isUnordered isDouble expr = isNan isDouble expr .| isInf isDouble expr

let fprem (ins: Instruction) insLen bld round =
  let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
  let struct (st1b, st1a) = getFPUPseudoRegVars bld R.ST1
  let caster = if round then CastKind.FtoIRound else CastKind.FtoITrunc
  let lblUnordered = label bld "Unordered"
  let lblOrdered = label bld "Ordered"
  let lblLT64 = label bld "ExpDiffInRange"
  let lblGE64 = label bld "ExpDiffOutOfRange"
  let lblExit = label bld "Exit"
  let struct (tmp0, tmp1) = tmpVars2 bld 64<rt>
  let expDiff = tmpVar bld 16<rt>
  let expMask = numI32 0x7fff 16<rt>
  let n64 = numI32 64 16<rt>
  let n2 = numI32 2 64<rt> |> castToF64
  let struct (divres, intres, tmpres, divider) = tmpVars4 bld 64<rt>
  bld <!-- (ins.Address, insLen)
  castFrom80Bit tmp0 64<rt> st0b st0a bld
  castFrom80Bit tmp1 64<rt> st1b st1a bld
  bld <+ (expDiff := (st0b .& expMask) .- (st1b .& expMask))
  bld <+ (AST.cjmp
    (isUnordered true tmp0 .| isUnordered true tmp1)
    (AST.jmpDest lblUnordered) (AST.jmpDest lblOrdered))
  bld <+ (AST.lmark lblUnordered)
  castTo80Bit bld st0b st0a (AST.ite (isUnordered true tmp0) tmp0 tmp1)
  bld <+ (regVar bld R.FSWC2 := AST.b0)
  bld <+ (AST.jmp (AST.jmpDest lblExit))
  bld <+ (AST.lmark lblOrdered)
  bld <+ (AST.cjmp (AST.slt expDiff n64)
                   (AST.jmpDest lblLT64) (AST.jmpDest lblGE64))
  bld <+ (AST.lmark lblLT64) (* D < 64 *)
  bld <+ (divres := AST.fdiv tmp0 tmp1)
  bld <+ (intres := AST.cast caster 64<rt> divres)
  bld <+ (tmpres := AST.fsub tmp0 (AST.fmul tmp1 (castToF64 intres)))
  castTo80Bit bld st0b st0a tmpres
  bld <+ (regVar bld R.FSWC2 := AST.b0)
  bld <+ (regVar bld R.FSWC1 := AST.xtlo 1<rt> intres)
  bld <+ (regVar bld R.FSWC3 := AST.extract intres 1<rt> 1)
  bld <+ (regVar bld R.FSWC0 := AST.extract intres 1<rt> 2)
  bld <+ (AST.jmp (AST.jmpDest lblExit))
  bld <+ (AST.lmark lblGE64) (* ELSE *)
  bld <+ (regVar bld R.FSWC2 := AST.b1)
  bld <+ (tmpres := AST.fsub (castToF64 expDiff) (castToF64 (numI32 63 64<rt>)))
  bld <+ (divider := AST.fpow n2 tmpres)
  bld <+ (divres := AST.fdiv (AST.fdiv tmp0 tmp1) divider)
  bld <+ (intres := AST.cast CastKind.FtoITrunc 64<rt> divres)
  bld <+ (tmpres :=
    AST.fsub tmp0 (AST.fmul tmp1 (AST.fmul (castToF64 intres) divider)))
  castTo80Bit bld st0b st0a tmpres
  bld <+ (AST.lmark lblExit)
  bld --!> insLen

let fabs (ins: Instruction) insLen bld =
  let struct (st0b, _st0a) = getFPUPseudoRegVars bld R.ST0
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.extract st0b 1<rt> 15 := AST.b0)
  bld <+ (regVar bld R.FSWC1 := AST.b0)
#if !EMULATION
  bld <+ (regVar bld R.FSWC0 := undefC0)
  bld <+ (regVar bld R.FSWC2 := undefC2)
  bld <+ (regVar bld R.FSWC3 := undefC3)
#endif
  bld --!> insLen

let fchs (ins: Instruction) insLen bld =
  let struct (st0b, _st0a) = getFPUPseudoRegVars bld R.ST0
  let tmp = tmpVar bld 1<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmp := AST.xthi 1<rt> st0b)
  bld <+ (AST.xthi 1<rt> st0b := AST.not tmp)
  bld <+ (regVar bld R.FSWC1 := AST.b0)
#if !EMULATION
  bld <+ (regVar bld R.FSWC0 := undefC0)
  bld <+ (regVar bld R.FSWC2 := undefC2)
  bld <+ (regVar bld R.FSWC3 := undefC3)
#endif
  bld --!> insLen

let frndint (ins: Instruction) insLen bld =
  let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
  let lblOrdered = label bld "Ordered"
  let lblExit = label bld "Exit"
  let tmp0 = tmpVar bld 64<rt>
  let rcField = tmpVar bld 8<rt> (* Rounding Control *)
  let cst00 = AST.cast CastKind.FtoIRound 64<rt> tmp0
  let cst01 = AST.cast CastKind.FtoIFloor 64<rt> tmp0
  let cst10 = AST.cast CastKind.FtoICeil 64<rt> tmp0
  let cst11 = AST.cast CastKind.FtoITrunc 64<rt> tmp0
  bld <!-- (ins.Address, insLen)
  castFrom80Bit tmp0 64<rt> st0b st0a bld
  bld <+ (AST.cjmp
    (isUnordered true tmp0)
    (AST.jmpDest lblExit) (AST.jmpDest lblOrdered))
  bld <+ (AST.lmark lblOrdered)
  bld <+ (rcField := (AST.zext 8<rt> (AST.extract (regVar bld R.FCW) 1<rt> 11)))
  bld <+ (rcField := (rcField << AST.num1 8<rt>))
  bld <+ (rcField :=
    (rcField .| (AST.zext 8<rt> (AST.extract (regVar bld R.FCW) 1<rt> 10))))
  bld <+ (tmp0 := AST.ite (rcField == AST.num0 8<rt>) cst00 tmp0)
  bld <+ (tmp0 := AST.ite (rcField == AST.num1 8<rt>) cst01 tmp0)
  bld <+ (tmp0 := AST.ite (rcField == numI32 2 8<rt>) cst10 tmp0)
  bld <+ (tmp0 := AST.ite (rcField == numI32 3 8<rt>) cst11 tmp0)
  castTo80Bit bld st0b st0a (castToF64 tmp0)
  bld <+ (AST.lmark lblExit)
  updateC1OnStore bld
  bld --!> insLen

let fscale (ins: Instruction) insLen bld =
  let struct (tmp0, tmp1, tmp2, tmp3) = tmpVars4 bld 64<rt>
  let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
  let struct (st1b, st1a) = getFPUPseudoRegVars bld R.ST1
  let f2 = numI32 2 64<rt> |> castToF64
  bld <!-- (ins.Address, insLen)
  castFrom80Bit tmp0 64<rt> st0b st0a bld
  castFrom80Bit tmp1 64<rt> st1b st1a bld
  bld <+ (tmp2 := AST.cast CastKind.FtoITrunc 64<rt> tmp1)
  let exp = AST.ite (tmp2 ?>= numI64 0L 64<rt>) tmp2 (AST.neg tmp2)
  bld <+ (tmp3 := AST.fpow f2 (castToF64 exp))
  let v =
    AST.ite
      (tmp2 ?>= numI64 0L 64<rt>) (AST.fmul tmp0 tmp3) (AST.fdiv tmp0 tmp3)
  castTo80Bit bld st0b st0a v
  updateC1OnStore bld
  bld --!> insLen

let fsqrt (ins: Instruction) insLen bld =
  let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
  let tmp0 = tmpVar bld 64<rt>
  bld <!-- (ins.Address, insLen)
  castFrom80Bit tmp0 64<rt> st0b st0a bld
  castTo80Bit bld st0b st0a (AST.unop UnOpType.FSQRT tmp0)
  updateC1OnStore bld
  bld --!> insLen

let fxtract (ins: Instruction) insLen bld =
  let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
  let n3fff = numI32 0x3FFF 16<rt>
  let tmpB, tmpA = tmpVar bld 16<rt>, bld.Stream.NewTempVar 64<rt>
  let tmpF = tmpVar bld 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpB := (st0b .& numI32 0x8000 16<rt>) .| n3fff)
  bld <+ (tmpA := st0a)
  bld <+ (tmpF := castToF64 ((st0b .& numI32 0x7fff 16<rt>) .- n3fff))
  castTo80Bit bld st0b st0a tmpF
  pushFPUStack bld
  bld <+ (st0b := tmpB)
  bld <+ (st0a := tmpA)
  bld --!> insLen

let private prepareTwoOprsForComparison (ins: Instruction) insLen bld =
  let struct (tmp0, tmp1) = tmpVars2 bld 64<rt>
  match ins.Operands with
  | NoOperand ->
    let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
    let struct (st1b, st1a) = getFPUPseudoRegVars bld R.ST1
    castFrom80Bit tmp0 64<rt> st0b st0a bld
    castFrom80Bit tmp1 64<rt> st1b st1a bld
  | OneOperand(OprReg r) ->
    let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
    let struct (st1b, st1a) = getFPUPseudoRegVars bld r
    castFrom80Bit tmp0 64<rt> st0b st0a bld
    castFrom80Bit tmp1 64<rt> st1b st1a bld
  | OneOperand(opr) ->
    let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
    let oprExpr = transOprToExpr bld false ins insLen opr
    castFrom80Bit tmp0 64<rt> st0b st0a bld
    bld <+ (tmp1 := AST.cast CastKind.FloatCast 64<rt> oprExpr)
  | TwoOperands(OprReg r1, OprReg r2) ->
    let struct (st0b, st0a) = getFPUPseudoRegVars bld r1
    let struct (st1b, st1a) = getFPUPseudoRegVars bld r2
    castFrom80Bit tmp0 64<rt> st0b st0a bld
    castFrom80Bit tmp1 64<rt> st1b st1a bld
  | _ -> raise InvalidOperandException
  if ins.Opcode = Opcode.FUCOM then struct (tmp1, tmp0) else struct (tmp0, tmp1)

let fcom (ins: Instruction) insLen bld nPop unordered =
  let c0 = regVar bld R.FSWC0
  let c2 = regVar bld R.FSWC2
  let c3 = regVar bld R.FSWC3
  bld <!-- (ins.Address, insLen)
  let struct (tmp0, tmp1) = prepareTwoOprsForComparison ins insLen bld
  let isNan = isNan true tmp0 .| isNan true tmp1
  bld <+ (c0 := isNan .| AST.flt tmp0 tmp1)
  bld <+ (c2 := isNan .| AST.b0)
  bld <+ (c3 := isNan .| (tmp0 == tmp1))
  bld <+ (regVar bld R.FSWC1 := AST.b0)
  if nPop > 0 then popFPUStack bld else ()
  if nPop = 2 then popFPUStack bld else ()
  bld --!> insLen

let ficom (ins: Instruction) insLen bld doPop =
  bld <!-- (ins.Address, insLen)
  let oprExpr = transOneOpr bld ins insLen
  let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
  let struct (tmp0, tmp1) = tmpVars2 bld 64<rt>
  castFrom80Bit tmp0 64<rt> st0b st0a bld
  bld <+ (tmp1 := AST.cast CastKind.SIntToFloat 64<rt> oprExpr)
  let isNan = isNan true tmp0 .| isNan true tmp1
  bld <+ (regVar bld R.FSWC0 := isNan .| AST.flt tmp0 tmp1)
  bld <+ (regVar bld R.FSWC2 := isNan .| AST.b0)
  bld <+ (regVar bld R.FSWC3 := isNan .| (tmp0 == tmp1))
  bld <+ (regVar bld R.FSWC1 := AST.b0)
  if doPop then popFPUStack bld else ()
  bld --!> insLen

let fcomi (ins: Instruction) insLen bld doPop =
  let zf = regVar bld R.ZF
  let pf = regVar bld R.PF
  let cf = regVar bld R.CF
  bld <!-- (ins.Address, insLen)
  let struct (tmp0, tmp1) = prepareTwoOprsForComparison ins insLen bld
  let isNan = isNan true tmp0 .| isNan true tmp1
  bld <+ (cf := isNan .| AST.flt tmp0 tmp1)
  bld <+ (pf := isNan .| AST.b0)
  bld <+ (zf := isNan .| (tmp0 == tmp1))
  bld <+ (regVar bld R.FSWC1 := AST.b0)
  if doPop then popFPUStack bld else ()
#if EMULATION
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let ftst (ins: Instruction) insLen bld =
  let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
  let num0V = AST.num0 64<rt>
  let c0 = regVar bld R.FSWC0
  let c2 = regVar bld R.FSWC2
  let c3 = regVar bld R.FSWC3
  let tmp = tmpVar bld 64<rt>
  bld <!-- (ins.Address, insLen)
  castFrom80Bit tmp 64<rt> st0b st0a bld
  bld <+ (c0 := AST.flt tmp num0V)
  bld <+ (c2 := AST.b0)
  bld <+ (c3 := tmp == num0V)
  bld <+ (regVar bld R.FSWC1 := AST.b0)
  bld --!> insLen

let fxam (ins: Instruction) insLen bld =
  let top = regVar bld R.FTOP
  let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
  let n7fff = numI32 0x7fff 16<rt>
  let exponent = st0b .& n7fff
  let num = numI64 0x7FFFFFFF_FFFFFFFFL 64<rt>
  let isNaN = (exponent == n7fff) .& ((st0a .& num) != AST.num0 64<rt>)
  let isInf = (exponent == n7fff) .& ((st0a .& num) == AST.num0 64<rt>)
  let isZero = (st0a == AST.num0 64<rt>) .& (exponent == AST.num0 16<rt>)
  let isEmpty = top == numI32 0 8<rt>
  let c3Cond = isZero .| isEmpty
  let c2Cond = AST.not (isNaN .| isZero .| isEmpty)
  let c0Cond = isNaN .| isInf .| isEmpty
  bld <!-- (ins.Address, insLen)
  bld <+ (regVar bld R.FSWC1 := AST.xthi 1<rt> st0b)
  bld <+ (regVar bld R.FSWC3 := c3Cond)
  bld <+ (regVar bld R.FSWC2 := c2Cond)
  bld <+ (regVar bld R.FSWC0 := c0Cond)
  bld --!> insLen

let private checkForTrigFunction unsigned lin lout bld =
  let maxLimit = numI64 (1L <<< 63) 64<rt>
  let maxFloat = AST.cast CastKind.UIntToFloat 64<rt> maxLimit
  bld <+ (AST.cjmp (AST.flt unsigned maxFloat)
                 (AST.jmpDest lin) (AST.jmpDest lout))

let private ftrig (ins: Instruction) insLen bld trigFunc =
  let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
  let n7fff = numI32 0x7fff 16<rt>
  let c0 = regVar bld R.FSWC0
  let c1 = regVar bld R.FSWC1
  let c2 = regVar bld R.FSWC2
  let c3 = regVar bld R.FSWC3
  let lin = label bld "IsInRange"
  let lout = label bld "IsOutOfRange"
  let lexit = label bld "Exit"
  let struct (unsigned, signed, tmp) = tmpVars3 bld 64<rt>
  bld <!-- (ins.Address, insLen)
  castFrom80Bit unsigned 64<rt> (st0b .& n7fff) st0a bld
  castFrom80Bit signed 64<rt> st0b st0a bld
  checkForTrigFunction unsigned lin lout bld
  bld <+ (AST.lmark lin)
  bld <+ (tmp := trigFunc signed)
  castTo80Bit bld st0b st0a tmp
  bld <+ (c2 := AST.b0)
  bld <+ (AST.jmp (AST.jmpDest lexit))
  bld <+ (AST.lmark lout)
  bld <+ (c2 := AST.b1)
  bld <+ (AST.lmark lexit)
#if !EMULATION
  bld <+ (c0 := undefC0)
  bld <+ (c3 := undefC3)
#endif
  bld <+ (c1 := AST.b0)
  bld --!> insLen

let fsin ins insLen bld =
  ftrig ins insLen bld AST.fsin

let fcos ins insLen bld =
  ftrig ins insLen bld AST.fcos

let fsincos (ins: Instruction) insLen bld =
  let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
  let n7fff = numI32 0x7fff 16<rt>
  let c0 = regVar bld R.FSWC0
  let c2 = regVar bld R.FSWC2
  let c3 = regVar bld R.FSWC3
  let lin = label bld "IsInRange"
  let lout = label bld "IsOutOfRange"
  let lexit = label bld "Exit"
  let struct (unsigned, signed, tmpsin, tmpcos) = tmpVars4 bld 64<rt>
  bld <!-- (ins.Address, insLen)
  castFrom80Bit unsigned 64<rt> (st0b .& n7fff) st0a bld
  castFrom80Bit signed 64<rt> st0b st0a bld
  checkForTrigFunction unsigned lin lout bld
  bld <+ (AST.lmark lin)
  bld <+ (tmpcos := AST.fcos signed)
  bld <+ (tmpsin := AST.fsin signed)
  castTo80Bit bld st0b st0a tmpsin
  pushFPUStack bld
  castTo80Bit bld st0b st0a tmpcos
  bld <+ (c2 := AST.b0)
  bld <+ (AST.jmp (AST.jmpDest lexit))
  bld <+ (AST.lmark lout)
  bld <+ (c2 := AST.b1)
  bld <+ (AST.lmark lexit)
#if !EMULATION
  bld <+ (c0 := undefC0)
  bld <+ (c3 := undefC3)
#endif
  updateC1OnLoad bld
  bld --!> insLen

let fptan (ins: Instruction) insLen bld =
  let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
  let n7fff = numI32 0x7fff 16<rt>
  let c0 = regVar bld R.FSWC0
  let c2 = regVar bld R.FSWC2
  let c3 = regVar bld R.FSWC3
  let lin = label bld "IsInRange"
  let lout = label bld "IsOutOfRange"
  let lexit = label bld "Exit"
  let fone = numI64 0x3ff0000000000000L 64<rt> (* 1.0 *)
  let struct (unsigned, signed, tmp) = tmpVars3 bld 64<rt>
  bld <!-- (ins.Address, insLen)
  castFrom80Bit unsigned 64<rt> (st0b .& n7fff) st0a bld
  castFrom80Bit signed 64<rt> st0b st0a bld
  checkForTrigFunction unsigned lin lout bld
  bld <+ (AST.lmark lin)
  bld <+ (tmp := AST.ftan signed)
  castTo80Bit bld st0b st0a tmp
  bld <+ (c2 := AST.b0)
  pushFPUStack bld
  castTo80Bit bld st0b st0a fone
  bld <+ (c2 := AST.b0)
  bld <+ (AST.jmp (AST.jmpDest lexit))
  bld <+ (AST.lmark lout)
  bld <+ (c2 := AST.b1)
  bld <+ (AST.lmark lexit)
#if !EMULATION
  bld <+ (c0 := undefC0)
  bld <+ (c3 := undefC3)
#endif
  updateC1OnLoad bld
  bld --!> insLen

let fpatan (ins: Instruction) insLen bld =
  let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
  let struct (st1b, st1a) = getFPUPseudoRegVars bld R.ST1
  let struct (tmp0, tmp1, res) = tmpVars3 bld 64<rt>
  bld <!-- (ins.Address, insLen)
  castFrom80Bit tmp0 64<rt> st0b st0a bld
  castFrom80Bit tmp1 64<rt> st1b st1a bld
  bld <+ (res := AST.fatan (AST.fdiv tmp1 tmp0))
  castTo80Bit bld st1b st1a res
  popFPUStack bld
  updateC1OnStore bld
#if !EMULATION
  cflagsUndefined023 bld
#endif
  bld --!> insLen

let f2xm1 (ins: Instruction) insLen bld =
  let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
  let f1 = numI32 1 64<rt> |> castToF64
  let f2 = numI32 2 64<rt> |> castToF64
  let c1 = regVar bld R.FSWC1
  let struct (tmp, res) = tmpVars2 bld 64<rt>
  bld <!-- (ins.Address, insLen)
  castFrom80Bit tmp 64<rt> st0b st0a bld
  bld <+ (res := AST.fsub (AST.fpow f2 tmp) f1)
  castTo80Bit bld st0b st0a res
  bld <+ (c1 := AST.b0)
#if !EMULATION
  cflagsUndefined023 bld
#endif
  bld --!> insLen

let fyl2x (ins: Instruction) insLen bld =
  let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
  let struct (st1b, st1a) = getFPUPseudoRegVars bld R.ST1
  let struct (tmp0, tmp1, res) = tmpVars3 bld 64<rt>
  let f2 = numI32 2 64<rt> |> castToF64
  bld <!-- (ins.Address, insLen)
  castFrom80Bit tmp0 64<rt> st0b st0a bld
  castFrom80Bit tmp1 64<rt> st1b st1a bld
  bld <+ (res := AST.fmul tmp1 (AST.flog f2 tmp0))
  castTo80Bit bld st1b st1a res
  popFPUStack bld
  updateC1OnStore bld
#if !EMULATION
  cflagsUndefined023 bld
#endif
  bld --!> insLen

let fyl2xp1 (ins: Instruction) insLen bld =
  let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
  let struct (st1b, st1a) = getFPUPseudoRegVars bld R.ST1
  let struct (tmp0, tmp1, res) = tmpVars3 bld 64<rt>
  let f1 = numI32 1 64<rt> |> castToF64
  let f2 = numI32 2 64<rt> |> castToF64
  bld <!-- (ins.Address, insLen)
  castFrom80Bit tmp0 64<rt> st0b st0a bld
  castFrom80Bit tmp1 64<rt> st1b st1a bld
  bld <+ (res := AST.fmul tmp1 (AST.flog f2 (AST.fadd tmp0 f1)))
  castTo80Bit bld st1b st1a res
  popFPUStack bld
  updateC1OnStore bld
#if !EMULATION
  cflagsUndefined023 bld
#endif
  bld --!> insLen

let fld1 ins insLen bld =
  let oprExpr = numU64 0x3FF0000000000000UL 64<rt>
  fpuLoad ins insLen bld oprExpr

let fldz (ins: Instruction) insLen bld =
  let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
  bld <!-- (ins.Address, insLen)
  pushFPUStack bld
  bld <+ (st0b := AST.num0 16<rt>)
  bld <+ (st0a := AST.num0 64<rt>)
  updateC1OnLoad bld
  bld --!> insLen

let fldpi ins insLen bld =
  let oprExpr = numU64 4614256656552045848UL 64<rt>
  fpuLoad ins insLen bld oprExpr

let fldl2e ins insLen bld =
  let oprExpr = numU64 4609176140021203710UL 64<rt>
  fpuLoad ins insLen bld oprExpr

let fldln2 ins insLen bld =
  let oprExpr = numU64 4604418534313441775UL 64<rt>
  fpuLoad ins insLen bld oprExpr

let fldl2t ins insLen bld =
  let oprExpr = numU64 4614662735865160561UL 64<rt>
  fpuLoad ins insLen bld oprExpr

let fldlg2 ins insLen bld =
  let oprExpr = numU64 4599094494223104511UL 64<rt>
  fpuLoad ins insLen bld oprExpr

let fincstp (ins: Instruction) insLen bld =
  let top = regVar bld R.FTOP
  bld <!-- (ins.Address, insLen)
  (* TOP in B2R2 is really a counter, so we decrement TOP here (same as pop). *)
  let cond = top == numI32 0 8<rt>
  let updatedTOP = AST.ite cond (numI32 7 8<rt>) (top .- AST.num1 8<rt>)
  bld <+ (extractDstAssign top updatedTOP)
  let struct (tmpB, tmpA) = moveFPRegtoTemp R.ST0 bld
  moveFPRegtoFPReg R.ST0 R.ST1 bld
  moveFPRegtoFPReg R.ST1 R.ST2 bld
  moveFPRegtoFPReg R.ST2 R.ST3 bld
  moveFPRegtoFPReg R.ST3 R.ST4 bld
  moveFPRegtoFPReg R.ST4 R.ST5 bld
  moveFPRegtoFPReg R.ST5 R.ST6 bld
  moveFPRegtoFPReg R.ST6 R.ST7 bld
  moveTemptoFPReg R.ST7 tmpA tmpB bld
  bld <+ (regVar bld R.FSWC1 := AST.b0)
#if !EMULATION
  bld <+ (regVar bld R.FSWC0 := undefC0)
  bld <+ (regVar bld R.FSWC2 := undefC2)
  bld <+ (regVar bld R.FSWC3 := undefC3)
#endif
  bld --!> insLen

let fdecstp (ins: Instruction) insLen bld =
  let top = regVar bld R.FTOP
  bld <!-- (ins.Address, insLen)
  (* TOP in B2R2 is really a counter, so we increment TOP here. *)
  let cond = top == numI32 7 8<rt>
  let updatedTOP = AST.ite cond (AST.num0 8<rt>) (top .+ AST.num1 8<rt>)
  bld <+ (extractDstAssign top updatedTOP)
  let struct (tmpB, tmpA) = moveFPRegtoTemp R.ST7 bld
  moveFPRegtoFPReg R.ST7 R.ST6 bld
  moveFPRegtoFPReg R.ST6 R.ST5 bld
  moveFPRegtoFPReg R.ST5 R.ST4 bld
  moveFPRegtoFPReg R.ST4 R.ST3 bld
  moveFPRegtoFPReg R.ST3 R.ST2 bld
  moveFPRegtoFPReg R.ST2 R.ST1 bld
  moveFPRegtoFPReg R.ST1 R.ST0 bld
  moveTemptoFPReg R.ST0 tmpA tmpB bld
  bld <+ (regVar bld R.FSWC1 := AST.b0)
#if !EMULATION
  bld <+ (regVar bld R.FSWC0 := undefC0)
  bld <+ (regVar bld R.FSWC2 := undefC2)
  bld <+ (regVar bld R.FSWC3 := undefC3)
#endif
  bld --!> insLen

let ffree (ins: Instruction) insLen bld =
  let top = regVar bld R.FTOP
  let tagWord = regVar bld R.FTW
  let struct (top16, shifter, tagValue) = tmpVars3 bld 16<rt>
  let value3 = numI32 3 16<rt>
  let offset =
    match ins.Operands with
    | OneOperand(OprReg R.ST0) -> numI32 0 16<rt>
    | OneOperand(OprReg R.ST1) -> numI32 1 16<rt>
    | OneOperand(OprReg R.ST2) -> numI32 2 16<rt>
    | OneOperand(OprReg R.ST3) -> numI32 3 16<rt>
    | OneOperand(OprReg R.ST4) -> numI32 4 16<rt>
    | OneOperand(OprReg R.ST5) -> numI32 5 16<rt>
    | OneOperand(OprReg R.ST6) -> numI32 6 16<rt>
    | OneOperand(OprReg R.ST7) -> numI32 7 16<rt>
    | _ -> raise InvalidOperandException
  bld <!-- (ins.Address, insLen)
  bld <+ (top16 := AST.cast CastKind.ZeroExt 16<rt> top)
  bld <+ (top16 := top16 .+ offset)
  bld <+ (shifter := (numI32 2 16<rt>) .* top16)
  bld <+ (tagValue := (value3 << shifter))
  bld <+ (tagWord := tagWord .| tagValue)
  bld --!> insLen

(* FIXME: check all unmasked pending floating point exceptions. *)
let private checkFPUExceptions bld = ()

let private clearFPU bld =
  let cw = numI32 895 16<rt>
  let tw = BitVector.MaxUInt16 |> AST.num
  bld <+ (regVar bld R.FCW := cw)
  bld <+ (regVar bld R.FSW := AST.num0 16<rt>)
  bld <+ (regVar bld R.FTW := tw)

let finit (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  checkFPUExceptions bld
  clearFPU bld
  bld --!> insLen

let fninit (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  clearFPU bld
  bld --!> insLen

let fclex (ins: Instruction) insLen bld =
  let stsWrd = regVar bld R.FSW
  bld <!-- (ins.Address, insLen)
  bld <+ (stsWrd := stsWrd .& (numI32 0xFF80 16<rt>))
  bld <+ (AST.xthi 1<rt> stsWrd := AST.b0)
#if !EMULATION
  bld <+ (regVar bld R.FSWC0 := undefC0)
  bld <+ (regVar bld R.FSWC1 := undefC1)
  bld <+ (regVar bld R.FSWC2 := undefC2)
  bld <+ (regVar bld R.FSWC3 := undefC3)
#endif
  bld --!> insLen

let fstcw (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprExpr = transOneOpr bld ins insLen
  checkFPUExceptions bld
  bld <+ (oprExpr := regVar bld R.FCW)
#if !EMULATION
  allCFlagsUndefined bld
#endif
  bld --!> insLen

let fnstcw (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprExpr = transOneOpr bld ins insLen
  bld <+ (oprExpr := regVar bld R.FCW)
#if !EMULATION
  allCFlagsUndefined bld
#endif
  bld --!> insLen

let fldcw (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprExpr = transOneOpr bld ins insLen
  bld <+ (regVar bld R.FCW := oprExpr)
#if !EMULATION
  bld <+ (regVar bld R.FSWC0 := undefC0)
  bld <+ (regVar bld R.FSWC1 := undefC1)
  bld <+ (regVar bld R.FSWC2 := undefC2)
  bld <+ (regVar bld R.FSWC3 := undefC3)
#endif
  bld --!> insLen

let inline private storeLE addr v =
  AST.store Endian.Little addr v

let private m14fstenv dstAddr addrSize bld =
  let fiplo = AST.xtlo 16<rt> (regVar bld R.FIP)
  let fdplo = AST.xtlo 16<rt> (regVar bld R.FDP)
  bld <+ (storeLE (dstAddr) (regVar bld R.FCW))
  bld <+ (storeLE (dstAddr .+ numI32 2 addrSize) (regVar bld R.FSW))
  bld <+ (storeLE (dstAddr .+ numI32 4 addrSize) (regVar bld R.FTW))
  bld <+ (storeLE (dstAddr .+ numI32 6 addrSize) fiplo)
  bld <+ (storeLE (dstAddr .+ numI32 8 addrSize) (regVar bld R.FCS))
  bld <+ (storeLE (dstAddr .+ numI32 10 addrSize) fdplo)
  bld <+ (storeLE (dstAddr .+ numI32 12 addrSize) (regVar bld R.FDS))

let private m28fstenv dstAddr addrSize bld =
  let n0 = numI32 0 16<rt>
  bld <+ (storeLE (dstAddr) (regVar bld R.FCW))
  bld <+ (storeLE (dstAddr .+ numI32 2 addrSize) n0)
  bld <+ (storeLE (dstAddr .+ numI32 4 addrSize) (regVar bld R.FSW))
  bld <+ (storeLE (dstAddr .+ numI32 6 addrSize) n0)
  bld <+ (storeLE (dstAddr .+ numI32 8 addrSize) (regVar bld R.FTW))
  bld <+ (storeLE (dstAddr .+ numI32 10 addrSize) n0)
  bld <+ (storeLE (dstAddr .+ numI32 12 addrSize) (regVar bld R.FIP))
  bld <+ (storeLE (dstAddr .+ numI32 20 addrSize) (regVar bld R.FDP))

let fnstenv (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let dst = transOneOpr bld ins insLen
  let struct (addrExpr, addrSize) = getLoadAddressExpr dst
  match Expr.TypeOf dst with
  | 112<rt> -> m14fstenv addrExpr addrSize bld
  | 224<rt> -> m28fstenv addrExpr addrSize bld
  | _ -> raise InvalidOperandSizeException
  bld --!> insLen

let private m14fldenv srcAddr addrSize bld =
  bld <+ (regVar bld R.FCW := AST.loadLE 16<rt> (srcAddr))
  bld <+ (regVar bld R.FSW := AST.loadLE 16<rt> (srcAddr .+ numI32 2 addrSize))
  bld <+ (regVar bld R.FTW := AST.loadLE 16<rt> (srcAddr .+ numI32 4 addrSize))
  bld <+ (AST.xtlo 16<rt> (regVar bld R.FIP) :=
    AST.loadLE 16<rt> (srcAddr .+ numI32 6 addrSize))
  bld <+ (regVar bld R.FCS := AST.loadLE 16<rt> (srcAddr .+ numI32 8 addrSize))
  bld <+ (AST.xtlo 16<rt> (regVar bld R.FDP) :=
    AST.loadLE 16<rt> (srcAddr .+ numI32 10 addrSize))
  bld <+ (regVar bld R.FDS := AST.loadLE 16<rt> (srcAddr .+ numI32 12 addrSize))

let private m28fldenv srcAddr addrSize bld =
  bld <+ (regVar bld R.FCW := AST.loadLE 16<rt> (srcAddr))
  bld <+ (regVar bld R.FSW := AST.loadLE 16<rt> (srcAddr .+ numI32 4 addrSize))
  bld <+ (regVar bld R.FTW := AST.loadLE 16<rt> (srcAddr .+ numI32 8 addrSize))
  bld <+ (regVar bld R.FIP := AST.loadLE 64<rt> (srcAddr .+ numI32 12 addrSize))
  bld <+ (regVar bld R.FDP := AST.loadLE 64<rt> (srcAddr .+ numI32 20 addrSize))

let fldenv (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let src = transOneOpr bld ins insLen
  let struct (addrExpr, addrSize) = getLoadAddressExpr src
  match Expr.TypeOf src with
  | 112<rt> -> m14fldenv addrExpr addrSize bld
  | 224<rt> -> m28fldenv addrExpr addrSize bld
  | _ -> raise InvalidOperandSizeException
  bld --!> insLen

let private stSts dstAddr addrSize offset bld =
  let struct (stb, sta) = getFPUPseudoRegVars bld R.ST0
  bld <+ (storeLE (dstAddr .+ numI32 (offset) addrSize) sta)
  bld <+ (storeLE (dstAddr .+ numI32 (offset + 8) addrSize) stb)
  let struct (stb, sta) = getFPUPseudoRegVars bld R.ST1
  bld <+ (storeLE (dstAddr .+ numI32 (offset + 10) addrSize) sta)
  bld <+ (storeLE (dstAddr .+ numI32 (offset + 18) addrSize) stb)
  let struct (stb, sta) = getFPUPseudoRegVars bld R.ST2
  bld <+ (storeLE (dstAddr .+ numI32 (offset + 20) addrSize) sta)
  bld <+ (storeLE (dstAddr .+ numI32 (offset + 28) addrSize) stb)
  let struct (stb, sta) = getFPUPseudoRegVars bld R.ST3
  bld <+ (storeLE (dstAddr .+ numI32 (offset + 30) addrSize) sta)
  bld <+ (storeLE (dstAddr .+ numI32 (offset + 38) addrSize) stb)
  let struct (stb, sta) = getFPUPseudoRegVars bld R.ST4
  bld <+ (storeLE (dstAddr .+ numI32 (offset + 40) addrSize) sta)
  bld <+ (storeLE (dstAddr .+ numI32 (offset + 48) addrSize) stb)
  let struct (stb, sta) = getFPUPseudoRegVars bld R.ST5
  bld <+ (storeLE (dstAddr .+ numI32 (offset + 50) addrSize) sta)
  bld <+ (storeLE (dstAddr .+ numI32 (offset + 58) addrSize) stb)
  let struct (stb, sta) = getFPUPseudoRegVars bld R.ST6
  bld <+ (storeLE (dstAddr .+ numI32 (offset + 60) addrSize) sta)
  bld <+ (storeLE (dstAddr .+ numI32 (offset + 68) addrSize) stb)
  let struct (stb, sta) = getFPUPseudoRegVars bld R.ST7
  bld <+ (storeLE (dstAddr .+ numI32 (offset + 70) addrSize) sta)
  bld <+ (storeLE (dstAddr .+ numI32 (offset + 78) addrSize) stb)

let fnsave (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let dst = transOneOpr bld ins insLen
  let struct (addrExpr, addrSize) = getLoadAddressExpr dst
  match Expr.TypeOf dst with
  | 752<rt> ->
    m14fstenv addrExpr addrSize bld
    stSts addrExpr addrSize 14 bld
  | 864<rt> ->
    m28fstenv addrExpr addrSize bld
    stSts addrExpr addrSize 28 bld
  | _ -> raise InvalidOperandSizeException
  bld <+ (regVar bld R.FCW := numI32 0x037F 16<rt>)
  bld <+ (regVar bld R.FSW := AST.num0 16<rt>)
  bld <+ (regVar bld R.FTW := numI32 0xFFFF 16<rt>)
  bld <+ (regVar bld R.FDP := AST.num0 64<rt>)
  bld <+ (regVar bld R.FIP := AST.num0 64<rt>)
  bld <+ (regVar bld R.FOP := AST.num0 16<rt>)
  bld --!> insLen

let private ldSts srcAddr addrSize offset bld =
  let struct (stb, sta) = getFPUPseudoRegVars bld R.ST0
  bld <+ (sta := AST.loadLE 64<rt> (srcAddr .+ numI32 (offset) addrSize))
  bld <+ (stb := AST.loadLE 16<rt> (srcAddr .+ numI32 (offset + 8) addrSize))
  let struct (stb, sta) = getFPUPseudoRegVars bld R.ST1
  bld <+ (sta := AST.loadLE 64<rt> (srcAddr .+ numI32 (offset + 10) addrSize))
  bld <+ (stb := AST.loadLE 16<rt> (srcAddr .+ numI32 (offset + 18) addrSize))
  let struct (stb, sta) = getFPUPseudoRegVars bld R.ST2
  bld <+ (sta := AST.loadLE 64<rt> (srcAddr .+ numI32 (offset + 20) addrSize))
  bld <+ (stb := AST.loadLE 16<rt> (srcAddr .+ numI32 (offset + 28) addrSize))
  let struct (stb, sta) = getFPUPseudoRegVars bld R.ST3
  bld <+ (sta := AST.loadLE 64<rt> (srcAddr .+ numI32 (offset + 30) addrSize))
  bld <+ (stb := AST.loadLE 16<rt> (srcAddr .+ numI32 (offset + 38) addrSize))
  let struct (stb, sta) = getFPUPseudoRegVars bld R.ST4
  bld <+ (sta := AST.loadLE 64<rt> (srcAddr .+ numI32 (offset + 40) addrSize))
  bld <+ (stb := AST.loadLE 16<rt> (srcAddr .+ numI32 (offset + 48) addrSize))
  let struct (stb, sta) = getFPUPseudoRegVars bld R.ST5
  bld <+ (sta := AST.loadLE 64<rt> (srcAddr .+ numI32 (offset + 50) addrSize))
  bld <+ (stb := AST.loadLE 16<rt> (srcAddr .+ numI32 (offset + 58) addrSize))
  let struct (stb, sta) = getFPUPseudoRegVars bld R.ST6
  bld <+ (sta := AST.loadLE 64<rt> (srcAddr .+ numI32 (offset + 60) addrSize))
  bld <+ (stb := AST.loadLE 16<rt> (srcAddr .+ numI32 (offset + 68) addrSize))
  let struct (stb, sta) = getFPUPseudoRegVars bld R.ST7
  bld <+ (sta := AST.loadLE 64<rt> (srcAddr .+ numI32 (offset + 70) addrSize))
  bld <+ (stb := AST.loadLE 16<rt> (srcAddr .+ numI32 (offset + 78) addrSize))

let frstor (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let src = transOneOpr bld ins insLen
  let struct (addrExpr, addrSize) = getLoadAddressExpr src
  match Expr.TypeOf src with
  | 752<rt> ->
    m14fldenv addrExpr addrSize bld
    ldSts addrExpr addrSize 14 bld
  | 864<rt> ->
    m28fldenv addrExpr addrSize bld
    ldSts addrExpr addrSize 28 bld
  | _ -> raise InvalidOperandSizeException
  bld --!> insLen

let fnstsw (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprExpr = transOneOpr bld ins insLen
  bld <+ (oprExpr := regVar bld R.FSW)
#if !EMULATION
  allCFlagsUndefined bld
#endif
  bld --!> insLen

let wait (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  checkFPUExceptions bld
  bld --!> insLen

let fnop (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
#if !EMULATION
  allCFlagsUndefined bld
#endif
  bld --!> insLen

let private fxsaveInternal bld dstAddr addrSize is64bit =
  bld <+ (storeLE (dstAddr) (regVar bld R.FCW))
  bld <+ (storeLE (dstAddr .+ (numI32 2 addrSize)) (regVar bld R.FSW))
  bld <+ (storeLE (dstAddr .+ (numI32 4 addrSize)) (regVar bld R.FTW))
  bld <+ (storeLE (dstAddr .+ (numI32 6 addrSize)) (regVar bld R.FOP))
  bld <+ (storeLE (dstAddr .+ (numI32 8 addrSize)) (regVar bld R.FIP))
  bld <+ (storeLE (dstAddr .+ (numI32 16 addrSize)) (regVar bld R.FDP))
  bld <+ (storeLE (dstAddr .+ (numI32 24 addrSize)) (regVar bld R.MXCSR))
  bld <+ (storeLE (dstAddr .+ (numI32 28 addrSize)) (regVar bld R.MXCSRMASK))
  let struct (stb, sta) = getFPUPseudoRegVars bld R.ST0
  bld <+ (storeLE (dstAddr .+ (numI32 32 addrSize)) sta)
  bld <+ (storeLE (dstAddr .+ (numI32 40 addrSize)) stb)
  let struct (stb, sta) = getFPUPseudoRegVars bld R.ST1
  bld <+ (storeLE (dstAddr .+ (numI32 48 addrSize)) sta)
  bld <+ (storeLE (dstAddr .+ (numI32 56 addrSize)) stb)
  let struct (stb, sta) = getFPUPseudoRegVars bld R.ST2
  bld <+ (storeLE (dstAddr .+ (numI32 64 addrSize)) sta)
  bld <+ (storeLE (dstAddr .+ (numI32 72 addrSize)) stb)
  let struct (stb, sta) = getFPUPseudoRegVars bld R.ST3
  bld <+ (storeLE (dstAddr .+ (numI32 80 addrSize)) sta)
  bld <+ (storeLE (dstAddr .+ (numI32 88 addrSize)) stb)
  let struct (stb, sta) = getFPUPseudoRegVars bld R.ST4
  bld <+ (storeLE (dstAddr .+ (numI32 96 addrSize)) sta)
  bld <+ (storeLE (dstAddr .+ (numI32 104 addrSize)) stb)
  let struct (stb, sta) = getFPUPseudoRegVars bld R.ST5
  bld <+ (storeLE (dstAddr .+ (numI32 112 addrSize)) sta)
  bld <+ (storeLE (dstAddr .+ (numI32 120 addrSize)) stb)
  let struct (stb, sta) = getFPUPseudoRegVars bld R.ST6
  bld <+ (storeLE (dstAddr .+ (numI32 128 addrSize)) sta)
  bld <+ (storeLE (dstAddr .+ (numI32 136 addrSize)) stb)
  let struct (stb, sta) = getFPUPseudoRegVars bld R.ST7
  bld <+ (storeLE (dstAddr .+ (numI32 144 addrSize)) sta)
  bld <+ (storeLE (dstAddr .+ (numI32 152 addrSize)) stb)
  let struct (xmmb, xmma) = pseudoRegVar128 bld R.XMM0
  bld <+ (storeLE (dstAddr .+ (numI32 160 addrSize)) xmma)
  bld <+ (storeLE (dstAddr .+ (numI32 168 addrSize)) xmmb)
  let struct (xmmb, xmma) = pseudoRegVar128 bld R.XMM1
  bld <+ (storeLE (dstAddr .+ (numI32 176 addrSize)) xmma)
  bld <+ (storeLE (dstAddr .+ (numI32 184 addrSize)) xmmb)
  let struct (xmmb, xmma) = pseudoRegVar128 bld R.XMM2
  bld <+ (storeLE (dstAddr .+ (numI32 192 addrSize)) xmma)
  bld <+ (storeLE (dstAddr .+ (numI32 200 addrSize)) xmmb)
  let struct (xmmb, xmma) = pseudoRegVar128 bld R.XMM3
  bld <+ (storeLE (dstAddr .+ (numI32 208 addrSize)) xmma)
  bld <+ (storeLE (dstAddr .+ (numI32 216 addrSize)) xmmb)
  let struct (xmmb, xmma) = pseudoRegVar128 bld R.XMM4
  bld <+ (storeLE (dstAddr .+ (numI32 224 addrSize)) xmma)
  bld <+ (storeLE (dstAddr .+ (numI32 232 addrSize)) xmmb)
  let struct (xmmb, xmma) = pseudoRegVar128 bld R.XMM5
  bld <+ (storeLE (dstAddr .+ (numI32 240 addrSize)) xmma)
  bld <+ (storeLE (dstAddr .+ (numI32 248 addrSize)) xmmb)
  let struct (xmmb, xmma) = pseudoRegVar128 bld R.XMM6
  bld <+ (storeLE (dstAddr .+ (numI32 256 addrSize)) xmma)
  bld <+ (storeLE (dstAddr .+ (numI32 264 addrSize)) xmmb)
  let struct (xmmb, xmma) = pseudoRegVar128 bld R.XMM7
  bld <+ (storeLE (dstAddr .+ (numI32 272 addrSize)) xmma)
  bld <+ (storeLE (dstAddr .+ (numI32 280 addrSize)) xmmb)
  if is64bit then
    let struct (xmmb, xmma) = pseudoRegVar128 bld R.XMM8
    bld <+ (storeLE (dstAddr .+ (numI32 288 addrSize)) xmma)
    bld <+ (storeLE (dstAddr .+ (numI32 296 addrSize)) xmmb)
    let struct (xmmb, xmma) = pseudoRegVar128 bld R.XMM9
    bld <+ (storeLE (dstAddr .+ (numI32 304 addrSize)) xmma)
    bld <+ (storeLE (dstAddr .+ (numI32 312 addrSize)) xmmb)
    let struct (xmmb, xmma) = pseudoRegVar128 bld R.XMM10
    bld <+ (storeLE (dstAddr .+ (numI32 320 addrSize)) xmma)
    bld <+ (storeLE (dstAddr .+ (numI32 328 addrSize)) xmmb)
    let struct (xmmb, xmma) = pseudoRegVar128 bld R.XMM11
    bld <+ (storeLE (dstAddr .+ (numI32 336 addrSize)) xmma)
    bld <+ (storeLE (dstAddr .+ (numI32 344 addrSize)) xmmb)
    let struct (xmmb, xmma) = pseudoRegVar128 bld R.XMM12
    bld <+ (storeLE (dstAddr .+ (numI32 352 addrSize)) xmma)
    bld <+ (storeLE (dstAddr .+ (numI32 360 addrSize)) xmmb)
    let struct (xmmb, xmma) = pseudoRegVar128 bld R.XMM13
    bld <+ (storeLE (dstAddr .+ (numI32 368 addrSize)) xmma)
    bld <+ (storeLE (dstAddr .+ (numI32 376 addrSize)) xmmb)
    let struct (xmmb, xmma) = pseudoRegVar128 bld R.XMM14
    bld <+ (storeLE (dstAddr .+ (numI32 384 addrSize)) xmma)
    bld <+ (storeLE (dstAddr .+ (numI32 392 addrSize)) xmmb)
    let struct (xmmb, xmma) = pseudoRegVar128 bld R.XMM15
    bld <+ (storeLE (dstAddr .+ (numI32 400 addrSize)) xmma)
    bld <+ (storeLE (dstAddr .+ (numI32 408 addrSize)) xmmb)
  else ()

let fxsave (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let dst = transOneOpr bld ins insLen
  let struct (addrExpr, addrSize) = getLoadAddressExpr dst
  fxsaveInternal bld addrExpr addrSize (bld.RegType = 64<rt>)
  bld --!> insLen

let private fxrstoreInternal bld srcAddr addrSz is64bit =
  bld <+ (regVar bld R.FCW := AST.loadLE 16<rt> (srcAddr))
  bld <+ (regVar bld R.FSW := AST.loadLE 16<rt> (srcAddr .+ (numI32 2 addrSz)))
  bld <+ (regVar bld R.FTW := AST.loadLE 16<rt> (srcAddr .+ (numI32 4 addrSz)))
  bld <+ (regVar bld R.FOP := AST.loadLE 16<rt> (srcAddr .+ (numI32 6 addrSz)))
  bld <+ (regVar bld R.FIP := AST.loadLE 64<rt> (srcAddr .+ (numI32 8 addrSz)))
  bld <+ (regVar bld R.FDP := AST.loadLE 64<rt> (srcAddr .+ (numI32 16 addrSz)))
  bld <+ (regVar bld R.MXCSR :=
            AST.loadLE 32<rt> (srcAddr .+ (numI32 24 addrSz)))
  bld <+ (regVar bld R.MXCSRMASK :=
            AST.loadLE 32<rt> (srcAddr .+ (numI32 28 addrSz)))
  let struct (stb, sta) = getFPUPseudoRegVars bld R.ST0
  bld <+ (sta := AST.loadLE 64<rt> (srcAddr .+ (numI32 32 addrSz)))
  bld <+ (stb := AST.loadLE 16<rt> (srcAddr .+ (numI32 40 addrSz)))
  let struct (stb, sta) = getFPUPseudoRegVars bld R.ST1
  bld <+ (sta := AST.loadLE 64<rt> (srcAddr .+ (numI32 48 addrSz)))
  bld <+ (stb := AST.loadLE 16<rt> (srcAddr .+ (numI32 56 addrSz)))
  let struct (stb, sta) = getFPUPseudoRegVars bld R.ST2
  bld <+ (sta := AST.loadLE 64<rt> (srcAddr .+ (numI32 64 addrSz)))
  bld <+ (stb := AST.loadLE 16<rt> (srcAddr .+ (numI32 72 addrSz)))
  let struct (stb, sta) = getFPUPseudoRegVars bld R.ST3
  bld <+ (sta := AST.loadLE 64<rt> (srcAddr .+ (numI32 80 addrSz)))
  bld <+ (stb := AST.loadLE 16<rt> (srcAddr .+ (numI32 88 addrSz)))
  let struct (stb, sta) = getFPUPseudoRegVars bld R.ST4
  bld <+ (sta := AST.loadLE 64<rt> (srcAddr .+ (numI32 96 addrSz)))
  bld <+ (stb := AST.loadLE 16<rt> (srcAddr .+ (numI32 104 addrSz)))
  let struct (stb, sta) = getFPUPseudoRegVars bld R.ST5
  bld <+ (sta := AST.loadLE 64<rt> (srcAddr .+ (numI32 112 addrSz)))
  bld <+ (stb := AST.loadLE 16<rt> (srcAddr .+ (numI32 120 addrSz)))
  let struct (stb, sta) = getFPUPseudoRegVars bld R.ST6
  bld <+ (sta := AST.loadLE 64<rt> (srcAddr .+ (numI32 128 addrSz)))
  bld <+ (stb := AST.loadLE 16<rt> (srcAddr .+ (numI32 136 addrSz)))
  let struct (stb, sta) = getFPUPseudoRegVars bld R.ST7
  bld <+ (sta := AST.loadLE 64<rt> (srcAddr .+ (numI32 144 addrSz)))
  bld <+ (stb := AST.loadLE 16<rt> (srcAddr .+ (numI32 152 addrSz)))
  let struct (xmmb, xmma) = pseudoRegVar128 bld R.XMM0
  bld <+ (xmma := AST.loadLE 64<rt> (srcAddr .+ (numI32 160 addrSz)))
  bld <+ (xmmb := AST.loadLE 64<rt> (srcAddr .+ (numI32 168 addrSz)))
  let struct (xmmb, xmma) = pseudoRegVar128 bld R.XMM1
  bld <+ (xmma := AST.loadLE 64<rt> (srcAddr .+ (numI32 176 addrSz)))
  bld <+ (xmmb := AST.loadLE 64<rt> (srcAddr .+ (numI32 184 addrSz)))
  let struct (xmmb, xmma) = pseudoRegVar128 bld R.XMM2
  bld <+ (xmma := AST.loadLE 64<rt> (srcAddr .+ (numI32 192 addrSz)))
  bld <+ (xmmb := AST.loadLE 64<rt> (srcAddr .+ (numI32 200 addrSz)))
  let struct (xmmb, xmma) = pseudoRegVar128 bld R.XMM3
  bld <+ (xmma := AST.loadLE 64<rt> (srcAddr .+ (numI32 208 addrSz)))
  bld <+ (xmmb := AST.loadLE 64<rt> (srcAddr .+ (numI32 216 addrSz)))
  let struct (xmmb, xmma) = pseudoRegVar128 bld R.XMM4
  bld <+ (xmma := AST.loadLE 64<rt> (srcAddr .+ (numI32 224 addrSz)))
  bld <+ (xmmb := AST.loadLE 64<rt> (srcAddr .+ (numI32 232 addrSz)))
  let struct (xmmb, xmma) = pseudoRegVar128 bld R.XMM5
  bld <+ (xmma := AST.loadLE 64<rt> (srcAddr .+ (numI32 240 addrSz)))
  bld <+ (xmmb := AST.loadLE 64<rt> (srcAddr .+ (numI32 248 addrSz)))
  let struct (xmmb, xmma) = pseudoRegVar128 bld R.XMM6
  bld <+ (xmma := AST.loadLE 64<rt> (srcAddr .+ (numI32 256 addrSz)))
  bld <+ (xmmb := AST.loadLE 64<rt> (srcAddr .+ (numI32 264 addrSz)))
  let struct (xmmb, xmma) = pseudoRegVar128 bld R.XMM7
  bld <+ (xmma := AST.loadLE 64<rt> (srcAddr .+ (numI32 272 addrSz)))
  bld <+ (xmmb := AST.loadLE 64<rt> (srcAddr .+ (numI32 280 addrSz)))
  if is64bit then
    let struct (xmmb, xmma) = pseudoRegVar128 bld R.XMM8
    bld <+ (xmma := AST.loadLE 64<rt> (srcAddr .+ (numI32 288 addrSz)))
    bld <+ (xmmb := AST.loadLE 64<rt> (srcAddr .+ (numI32 296 addrSz)))
    let struct (xmmb, xmma) = pseudoRegVar128 bld R.XMM9
    bld <+ (xmma := AST.loadLE 64<rt> (srcAddr .+ (numI32 304 addrSz)))
    bld <+ (xmmb := AST.loadLE 64<rt> (srcAddr .+ (numI32 312 addrSz)))
    let struct (xmmb, xmma) = pseudoRegVar128 bld R.XMM10
    bld <+ (xmma := AST.loadLE 64<rt> (srcAddr .+ (numI32 320 addrSz)))
    bld <+ (xmmb := AST.loadLE 64<rt> (srcAddr .+ (numI32 328 addrSz)))
    let struct (xmmb, xmma) = pseudoRegVar128 bld R.XMM11
    bld <+ (xmma := AST.loadLE 64<rt> (srcAddr .+ (numI32 336 addrSz)))
    bld <+ (xmmb := AST.loadLE 64<rt> (srcAddr .+ (numI32 344 addrSz)))
    let struct (xmmb, xmma) = pseudoRegVar128 bld R.XMM12
    bld <+ (xmma := AST.loadLE 64<rt> (srcAddr .+ (numI32 352 addrSz)))
    bld <+ (xmmb := AST.loadLE 64<rt> (srcAddr .+ (numI32 360 addrSz)))
    let struct (xmmb, xmma) = pseudoRegVar128 bld R.XMM13
    bld <+ (xmma := AST.loadLE 64<rt> (srcAddr .+ (numI32 368 addrSz)))
    bld <+ (xmmb := AST.loadLE 64<rt> (srcAddr .+ (numI32 376 addrSz)))
    let struct (xmmb, xmma) = pseudoRegVar128 bld R.XMM14
    bld <+ (xmma := AST.loadLE 64<rt> (srcAddr .+ (numI32 384 addrSz)))
    bld <+ (xmmb := AST.loadLE 64<rt> (srcAddr .+ (numI32 392 addrSz)))
    let struct (xmmb, xmma) = pseudoRegVar128 bld R.XMM15
    bld <+ (xmma := AST.loadLE 64<rt> (srcAddr .+ (numI32 400 addrSz)))
    bld <+ (xmmb := AST.loadLE 64<rt> (srcAddr .+ (numI32 408 addrSz)))
  else ()

let fxrstor (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let src = transOneOpr bld ins insLen
  let struct (addrExpr, addrSize) = getLoadAddressExpr src
  fxrstoreInternal bld addrExpr addrSize (bld.RegType = 64<rt>)
  bld --!> insLen
