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
  append bld {
    direct (regVar bld R.FSWC0) := undefC0
    direct (regVar bld R.FSWC1) := undefC1
    direct (regVar bld R.FSWC2) := undefC2
    direct (regVar bld R.FSWC3) := undefC3
  }

let private cflagsUndefined023 bld =
  append bld {
    direct (regVar bld R.FSWC0) := undefC0
    direct (regVar bld R.FSWC2) := undefC2
    direct (regVar bld R.FSWC3) := undefC3
  }
#endif

let inline private getFPUPseudoRegVars bld r =
  struct (pseudoRegVar bld r 2, pseudoRegVar bld r 1)

let private updateC1OnLoad bld =
  append bld {
    let top = regVar bld R.FTOP
    let c1Flag = regVar bld R.FSWC1
    (* Top value has been wrapped around, which means stack overflow in B2R2. *)
    direct c1Flag := (top == AST.num0 8<rt>)
#if !EMULATION
    direct (regVar bld R.FSWC0) := undefC0
    direct (regVar bld R.FSWC2) := undefC2
    direct (regVar bld R.FSWC3) := undefC3
#endif
  }

let private updateC1OnStore bld =
  append bld {
    let top = regVar bld R.FTOP
    let c1Flag = regVar bld R.FSWC1
    (* Top value has been wrapped around, which means stack underflow in
       B2R2. *)
    direct c1Flag := (top != numI32 7 8<rt>)
#if !EMULATION
    direct (regVar bld R.FSWC0) := undefC0
    direct (regVar bld R.FSWC2) := undefC2
    direct (regVar bld R.FSWC3) := undefC3
#endif
  }

let private moveFPRegtoFPReg regdst regsrc bld =
  append bld {
    let struct (dstB, dstA) = getFPUPseudoRegVars bld regdst
    let struct (srcB, srcA) = getFPUPseudoRegVars bld regsrc
    direct dstA := srcA
    direct dstB := srcB
  }

let private moveFPRegtoTemp src bld =
  let tmpA = tmpVar bld 64<rt>
  let tmpB = tmpVar bld 16<rt>
  let struct (srcB, srcA) = getFPUPseudoRegVars bld src
  append bld {
    direct tmpA := srcA
    direct tmpB := srcB
  }
  struct (tmpB, tmpA)

let private moveTemptoFPReg dst tmpA tmpB bld =
  append bld {
    let struct (dstB, dstA) = getFPUPseudoRegVars bld dst
    direct dstA := tmpA
    direct dstB := tmpB
  }

let private clearFPReg reg bld =
  append bld {
    let struct (stB, stA) = getFPUPseudoRegVars bld reg
    direct stB := AST.num0 16<rt>
    direct stA := AST.num0 64<rt>
  }

let private pushFPUStack bld =
  let top = regVar bld R.FTOP
  (* We increment TOP here (which is the opposite way of what the manual says),
     because it is more intuitive to consider it as a counter. *)
  append bld {
    extractDstAssign top (top .+ AST.num1 8<rt>)
  }
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
  append bld {
    extractDstAssign top (top .- AST.num1 8<rt>)
  }
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
  | Load(_, _, addr, _) -> struct (addr, Expr.typeOf addr)
  | _ -> Terminator.impossible ()

let private castTo80Bit bld tmpB tmpA srcExpr =
  let oprSize = Expr.typeOf srcExpr
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
    append bld {
      direct tmpSrc := srcExpr
      direct biasedExponent :=
        AST.xtlo 16<rt> ((tmpSrc >> n23) .& (numI32 0xff 32<rt>))
    }
    let exponent =
      AST.ite (biasedExponent == numI32 0 16<rt>)
        (numI32 0 16<rt>)
        (AST.ite (biasedExponent == numI32 0xff 16<rt>)
          (numI32 0x7fff 16<rt>)
          (biasedExponent .+ biasDiff))
    append bld {
      direct tmpB := sign .| exponent
      direct tmpA :=
        AST.ite
          (AST.eq tmpSrc zero)
          (AST.num0 64<rt>)
          (integerpart .| (significand << numI32 40 64<rt>))
    }
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
    append bld {
      direct tmpSrc := srcExpr
      direct biasedExponent :=
        AST.xtlo 16<rt> ((tmpSrc >> n52) .& (numI32 0x7ff 64<rt>))
    }
    let exponent =
      AST.ite (biasedExponent == numI32 0 16<rt>)
        (numI32 0 16<rt>)
        (AST.ite (biasedExponent == numI32 0x7ff 16<rt>)
          (numI32 0x7fff 16<rt>)
          (biasedExponent .+ biasDiff))
    append bld {
      direct tmpB := sign .| exponent
      direct tmpA :=
        AST.ite
          (AST.eq tmpSrc zero)
          (AST.num0 64<rt>)
          (integerpart .| (significand << numI32 11 64<rt>))
    }
  | 80<rt> ->
    match srcExpr with
    | Load(_, _, addrExpr, _) ->
      let addrSize = Expr.typeOf addrExpr
      append bld {
        direct tmpB := AST.loadLE 16<rt> (addrExpr .+ numI32 8 addrSize)
        direct tmpA := AST.loadLE 64<rt> addrExpr
      }
    | BinOp(_, _, Var(_, r, _, _), Var _, _) ->
      let reg = RegisterHelper.pseudoRegToReg (Register.ofRegID r)
      let struct (srcB, srcA) = getFPUPseudoRegVars bld reg
      append bld {
        direct tmpB := srcB
        direct tmpA := srcA
      }
    | _ ->
      raise InvalidOperandException
  | _ ->
    Terminator.impossible ()

let private fpuLoad (ins: Instruction) bld oprExpr =
  lift bld ins {
    let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
    let tmpB, tmpA = tmpVar bld 16<rt>, bld.Stream.NewTempVar 64<rt>
    castTo80Bit bld tmpB tmpA oprExpr
    pushFPUStack bld
    direct st0b := tmpB
    direct st0a := tmpA
    updateC1OnLoad bld
  }

let fld (ins: Instruction) bld =
  lift bld ins {
    let oprExpr = transOneOpr bld ins
    let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
    let tmpB, tmpA = tmpVar bld 16<rt>, bld.Stream.NewTempVar 64<rt>
    castTo80Bit bld tmpB tmpA oprExpr
    pushFPUStack bld
    direct st0b := tmpB
    direct st0a := tmpA
    updateC1OnLoad bld
  }

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
      AST.ite (exp == AST.num0 16<rt>)
        (AST.num0 16<rt>)
        (AST.ite (exp == numI32 0x7fff 16<rt>)
          (numI32 0x1f 16<rt>)
          (AST.ite (computedExp .> maxExp) maxExp computedExp))
      << numI32 10 dstSize
    let n53 = numI32 53 64<rt>
    let significand =
      AST.xtlo 16<rt> ((srcA .& numI64 0x7FFFFFFFFFFFFFFFL 64<rt>) >> n53)
    append bld {
      direct tmpExp := computedExp
      direct dstExpr := (sign .| exponent .| significand)
    }
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
      AST.ite (exp == AST.num0 16<rt>)
        (AST.num0 64<rt>)
        (AST.ite (exp == numI32 0x7fff 16<rt>)
          (numI32 0x7ff 64<rt>)
          (AST.ite (computedExp .> maxExp) maxExp computedExp))
      << numI32 52 64<rt>
    let n11 = numI32 11 64<rt>
    let significand = (srcA .& numI64 0x7FFFFFFFFFFFFFFFL 64<rt>) >> n11
    append bld {
      direct tmpExp := computedExp
      direct tmpExp2 := (sign .| exponent .| significand)
      direct dstExpr := AST.cast CastKind.FloatCast 32<rt> tmpExp2
    }
  | 64<rt> ->
    let n48 = numI32 48 64<rt>
    let sign = (AST.zext 64<rt> srcB .& (numI32 0x8000 64<rt>)) << n48
    let biasDiff = numI32 0x3c00 64<rt>
    let tmpExp = tmpVar bld 64<rt>
    let exp = srcB .& numI32 0x7fff 16<rt>
    let computedExp = AST.zext 64<rt> exp .- biasDiff
    let maxExp = numI32 0x7ff 64<rt>
    let exponent =
      AST.ite (exp == AST.num0 16<rt>)
        (AST.num0 64<rt>)
        (AST.ite (exp == numI32 0x7fff 16<rt>)
          (numI32 0x7ff 64<rt>)
          (AST.ite (computedExp .> maxExp) maxExp computedExp))
      << numI32 52 64<rt>
    let n11 = numI32 11 64<rt>
    let significand = (srcA .& numI64 0x7FFFFFFFFFFFFFFFL 64<rt>) >> n11
    append bld {
      direct tmpExp := computedExp
      direct dstExpr := (sign .| exponent .| significand)
    }
  | 80<rt> ->
    let struct (addrExpr, addrSize) = getLoadAddressExpr dstExpr
    append bld {
      AST.store Endian.Little (addrExpr) srcA
      AST.store Endian.Little (addrExpr .+ numI32 8 addrSize) srcB
    }
  | _ ->
    Terminator.impossible ()

let ffst (ins: Instruction) bld doPop =
  lift bld ins {
    let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
    match ins.Operands with
    | OneOperand(OprReg r) ->
      let struct (dstB, dstA) = getFPUPseudoRegVars bld r
      direct dstB := st0b
      direct dstA := st0a
    | OneOperand(opr) ->
      let oprExpr = transOprToExpr bld false ins opr
      let oprSize = Expr.typeOf oprExpr
      castFrom80Bit oprExpr oprSize st0b st0a bld
    | _ ->
      raise InvalidOperandException
    if doPop then popFPUStack bld else ()
    updateC1OnStore bld
  }

let fild (ins: Instruction) bld =
  lift bld ins {
    let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
    let oprExpr = transOneOpr bld ins
    let tmpB, tmpA = tmpVar bld 16<rt>, bld.Stream.NewTempVar 64<rt>
    castTo80Bit bld tmpB tmpA (AST.cast CastKind.SIntToFloat 64<rt> oprExpr)
    pushFPUStack bld
    direct st0b := tmpB
    direct st0a := tmpA
    updateC1OnLoad bld
  }

let fist (ins: Instruction) bld doPop =
  lift bld ins {
    let oprExpr = transOneOpr bld ins
    let oprSize = Expr.typeOf oprExpr
    let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
    let tmp0 = tmpVar bld oprSize
    let rcField = tmpVar bld 8<rt> (* Rounding Control *)
    let num2 = numI32 2 8<rt>
    let cst00 = AST.cast CastKind.FtoIRound oprSize tmp0
    let cst01 = AST.cast CastKind.FtoIFloor oprSize tmp0
    let cst10 = AST.cast CastKind.FtoICeil oprSize tmp0
    let cst11 = AST.cast CastKind.FtoITrunc oprSize tmp0
    castFrom80Bit tmp0 oprSize st0b st0a bld
    direct rcField := (AST.zext 8<rt> (AST.extract (regVar bld R.FCW) 1<rt> 10))
    direct rcField := (rcField << AST.num1 8<rt>)
    direct rcField :=
      (rcField .| (AST.zext 8<rt> (AST.extract (regVar bld R.FCW) 1<rt> 11)))
    direct tmp0 := AST.ite (rcField == AST.num0 8<rt>) cst00 cst11
    direct tmp0 := AST.ite (rcField == AST.num1 8<rt>) cst01 tmp0
    direct tmp0 := AST.ite (rcField == num2) cst10 tmp0
    direct oprExpr := tmp0
    if doPop then popFPUStack bld else ()
    updateC1OnStore bld
  }

let fisttp (ins: Instruction) bld =
  lift bld ins {
    let oprExpr = transOneOpr bld ins
    let oprSize = Expr.typeOf oprExpr
    let tmp1 = tmpVar bld 64<rt>
    let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
    castFrom80Bit tmp1 64<rt> st0b st0a bld
    direct oprExpr := AST.cast CastKind.FtoITrunc oprSize tmp1
    popFPUStack bld
    direct (regVar bld R.FSWC1) := AST.b0
#if !EMULATION
    direct (regVar bld R.FSWC0) := undefC0
    direct (regVar bld R.FSWC2) := undefC2
    direct (regVar bld R.FSWC3) := undefC3
#endif
  }

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
  append bld {
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
    direct intgr := d1
    direct intgr := intgr .+ d2 .* numI64 10L 64<rt>
    direct intgr := intgr .+ d3 .* numI64 100L 64<rt>
    direct intgr := intgr .+ d4 .* numI64 1000L 64<rt>
    direct intgr := intgr .+ d5 .* numI64 10000L 64<rt>
    direct intgr := intgr .+ d6 .* numI64 100000L 64<rt>
    direct intgr := intgr .+ d7 .* numI64 1000000L 64<rt>
    direct intgr := intgr .+ d8 .* numI64 10000000L 64<rt>
    direct intgr := intgr .+ d9 .* numI64 100000000L 64<rt>
    direct intgr := intgr .+ d10 .* numI64 1000000000L 64<rt>
    direct intgr := intgr .+ d11 .* numI64 10000000000L 64<rt>
    direct intgr := intgr .+ d12 .* numI64 100000000000L 64<rt>
    direct intgr := intgr .+ d13 .* numI64 1000000000000L 64<rt>
    direct intgr := intgr .+ d14 .* numI64 10000000000000L 64<rt>
    direct intgr := intgr .+ d15 .* numI64 100000000000000L 64<rt>
    direct intgr := intgr .+ d16 .* numI64 1000000000000000L 64<rt>
    direct intgr := intgr .+ d17 .* numI64 10000000000000000L 64<rt>
    direct intgr := intgr .+ d18 .* numI64 100000000000000000L 64<rt>
    direct (AST.xthi 1<rt> intgr) := signBit
  }

let fbld (ins: Instruction) bld =
  lift bld ins {
    let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
    let src = transOneOpr bld ins
    let struct (addrExpr, addrSize) = getLoadAddressExpr src
    let intgr = tmpVar bld 64<rt>
    let tmpB, tmpA = tmpVar bld 16<rt>, bld.Stream.NewTempVar 64<rt>
    bcdToInt intgr addrExpr addrSize bld
    castTo80Bit bld tmpB tmpA (AST.cast CastKind.SIntToFloat 64<rt> intgr)
    pushFPUStack bld
    direct st0b := tmpB
    direct st0a := tmpA
    updateC1OnLoad bld
  }

let private storeTwoDigitBCD n10 addrExpr addrSize intgr pos bld =
  append bld {
    let d1 = (AST.xtlo 8<rt> (intgr .% n10)) .& (numI32 0xF 8<rt>)
    let d2 = (AST.xtlo 8<rt> ((intgr ./ n10) .% n10)) .& (numI32 0xF 8<rt>)
    let ds = (d2 << (numI32 4 8<rt>)) .| d1
    AST.store Endian.Little (addrExpr .+ numI32 pos addrSize) ds
  }

let private storeBCD addrExpr addrSize intgr bld =
  append bld {
    let n10 = numI32 10 64<rt>
    let n100 = numI32 100 64<rt>
    let sign = tmpVar bld 1<rt>
    let signByte = (AST.zext 8<rt> sign) << numI32 7 8<rt>
    direct sign := AST.xthi 1<rt> intgr
    storeTwoDigitBCD n10 addrExpr addrSize intgr 0 bld
    direct intgr := intgr ./ n100
    storeTwoDigitBCD n10 addrExpr addrSize intgr 1 bld
    direct intgr := intgr ./ n100
    storeTwoDigitBCD n10 addrExpr addrSize intgr 2 bld
    direct intgr := intgr ./ n100
    storeTwoDigitBCD n10 addrExpr addrSize intgr 3 bld
    direct intgr := intgr ./ n100
    storeTwoDigitBCD n10 addrExpr addrSize intgr 4 bld
    direct intgr := intgr ./ n100
    storeTwoDigitBCD n10 addrExpr addrSize intgr 5 bld
    direct intgr := intgr ./ n100
    storeTwoDigitBCD n10 addrExpr addrSize intgr 6 bld
    direct intgr := intgr ./ n100
    storeTwoDigitBCD n10 addrExpr addrSize intgr 7 bld
    direct intgr := intgr ./ n100
    storeTwoDigitBCD n10 addrExpr addrSize intgr 8 bld
    AST.store Endian.Little (addrExpr .+ numI32 9 addrSize) signByte
  }

let fbstp (ins: Instruction) bld =
  lift bld ins {
    let dst = transOneOpr bld ins
    let struct (addrExpr, addrSize) = getLoadAddressExpr dst
    let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
    let tmp = tmpVar bld 64<rt>
    let intgr = tmpVar bld 64<rt>
    castFrom80Bit tmp 64<rt> st0b st0a bld
    direct intgr := AST.cast CastKind.FtoIRound 64<rt> tmp
    storeBCD addrExpr addrSize intgr bld
    popFPUStack bld
    updateC1OnStore bld
  }

let fxch (ins: Instruction) bld =
  lift bld ins {
    let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
    let tmpB, tmpA = tmpVar bld 16<rt>, bld.Stream.NewTempVar 64<rt>
    direct tmpB := st0b
    direct tmpA := st0a
    let struct (srcB, srcA) =
      match ins.Operands with
      | OneOperand(OprReg reg) -> getFPUPseudoRegVars bld reg
      | NoOperand -> getFPUPseudoRegVars bld R.ST1
      | _ -> raise InvalidOperandException
    direct st0b := srcB
    direct st0a := srcA
    direct srcB := tmpB
    direct srcA := tmpA
    direct (regVar bld R.FSWC1) := AST.b0
#if !EMULATION
    cflagsUndefined023 bld
#endif
  }

let private fcmov (ins: Instruction) bld cond =
  append bld {
    let srcReg =
      match ins.Operands with
      | TwoOperands(_, OprReg reg) -> reg
      | _ -> raise InvalidOperandException
    let struct (srcB, srcA) = getFPUPseudoRegVars bld srcReg
    let struct (dstB, dstA) = getFPUPseudoRegVars bld R.ST0
    direct dstB := AST.ite cond srcB dstB
    direct dstA := AST.ite cond srcA dstA
#if !EMULATION
    direct (regVar bld R.FSWC0) := undefC0
    direct (regVar bld R.FSWC2) := undefC2
    direct (regVar bld R.FSWC3) := undefC3
#endif
  }

let fcmove (ins: Instruction) bld =
  lift bld ins {
#if EMULATION
    getZFLazy bld |> fcmov ins bld
#else
    regVar bld R.ZF |> fcmov ins bld
#endif
  }

let fcmovne (ins: Instruction) bld =
  lift bld ins {
#if EMULATION
    getZFLazy bld |> AST.not |> fcmov ins bld
#else
    regVar bld R.ZF |> AST.not |> fcmov ins bld
#endif
  }

let fcmovb (ins: Instruction) bld =
  lift bld ins {
#if EMULATION
    getCFLazy bld |> fcmov ins bld
#else
    regVar bld R.CF |> fcmov ins bld
#endif
  }

let fcmovbe (ins: Instruction) bld =
  lift bld ins {
#if EMULATION
    (getCFLazy bld .| getZFLazy bld) |> fcmov ins bld
#else
    (regVar bld R.CF .| regVar bld R.ZF) |> fcmov ins bld
#endif
  }

let fcmovnb (ins: Instruction) bld =
  lift bld ins {
#if EMULATION
    getCFLazy bld |> AST.not |> fcmov ins bld
#else
    regVar bld R.CF |> AST.not |> fcmov ins bld
#endif
  }

let fcmovnbe (ins: Instruction) bld =
  lift bld ins {
#if EMULATION
    let cond1 = getCFLazy bld |> AST.not
    let cond2 = getZFLazy bld |> AST.not
#else
    let cond1 = regVar bld R.CF |> AST.not
    let cond2 = regVar bld R.ZF |> AST.not
#endif
    cond1 .& cond2 |> fcmov ins bld
  }

let fcmovu (ins: Instruction) bld =
  lift bld ins {
#if EMULATION
    getPFLazy bld |> fcmov ins bld
#else
    regVar bld R.PF |> fcmov ins bld
#endif
  }

let fcmovnu (ins: Instruction) bld =
  lift bld ins {
#if EMULATION
    getPFLazy bld |> AST.not |> fcmov ins bld
#else
    regVar bld R.PF |> AST.not |> fcmov ins bld
#endif
  }

let private fpuFBinOp (ins: Instruction) bld binOp doPop leftToRight =
  lift bld ins {
    match ins.Operands with
    | NoOperand ->
      let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
      let struct (st1b, st1a) = getFPUPseudoRegVars bld R.ST1
      let struct (tmp0, tmp1) = tmpVars2 bld 64<rt>
      let res = tmpVar bld 64<rt>
      castFrom80Bit tmp0 64<rt> st0b st0a bld
      castFrom80Bit tmp1 64<rt> st1b st1a bld
      if leftToRight then append bld { direct res := binOp tmp0 tmp1 }
      else append bld { direct res := binOp tmp1 tmp0 }
      castTo80Bit bld st1b st1a res
    | OneOperand _ ->
      let oprExpr = transOneOpr bld ins
      let oprSize = Expr.typeOf oprExpr
      let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
      let struct (tmp0, tmp1) = tmpVars2 bld 64<rt>
      let res = tmpVar bld 64<rt>
      castFrom80Bit tmp0 64<rt> st0b st0a bld
      if oprSize = 64<rt> then
        append bld { direct tmp1 := oprExpr }
      else
        append bld { direct tmp1 := AST.cast CastKind.FloatCast 64<rt> oprExpr }
      if leftToRight then append bld { direct res := binOp tmp0 tmp1 }
      else append bld { direct res := binOp tmp1 tmp0 }
      castTo80Bit bld st0b st0a res
    | TwoOperands(OprReg reg0, OprReg reg1) ->
      let struct (r0B, r0A) = getFPUPseudoRegVars bld reg0
      let struct (r1B, r1A) = getFPUPseudoRegVars bld reg1
      let struct (tmp0, tmp1) = tmpVars2 bld 64<rt>
      let res = tmpVar bld 64<rt>
      castFrom80Bit tmp0 64<rt> r0B r0A bld
      castFrom80Bit tmp1 64<rt> r1B r1A bld
      if leftToRight then append bld { direct res := binOp tmp0 tmp1 }
      else append bld { direct res := binOp tmp1 tmp0 }
      castTo80Bit bld r0B r0A res
    | _ ->
      raise InvalidOperandException
    if doPop then popFPUStack bld else ()
    updateC1OnStore bld
  }

let private fpuIntOp (ins: Instruction) bld binOp leftToRight =
  lift bld ins {
    let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
    let oprExpr = transOneOpr bld ins
    let struct (tmp, dst) = tmpVars2 bld 64<rt>
    let res = tmpVar bld 64<rt>
    direct tmp := AST.cast CastKind.SIntToFloat 64<rt> oprExpr
    castFrom80Bit dst 64<rt> st0b st0a bld
    if leftToRight then append bld { direct res := binOp dst tmp }
    else append bld { direct res := binOp tmp dst }
    castTo80Bit bld st0b st0a res
  }

let fpuadd ins bld doPop = fpuFBinOp ins bld AST.fadd doPop true

let fiadd ins bld = fpuIntOp ins bld AST.fadd true

let fpusub ins bld doPop = fpuFBinOp ins bld AST.fsub doPop true

let fisub ins bld = fpuIntOp ins bld AST.fsub true

let fsubr ins bld doPop = fpuFBinOp ins bld AST.fsub doPop false

let fisubr ins bld = fpuIntOp ins bld AST.fsub false

let fpumul ins bld doPop = fpuFBinOp ins bld AST.fmul doPop true

let fimul ins bld = fpuIntOp ins bld AST.fmul true

let fpudiv ins bld doPop = fpuFBinOp ins bld AST.fdiv doPop true

let fidiv ins bld = fpuIntOp ins bld AST.fdiv true

let private isZero exponent significand =
  (exponent == (AST.num0 16<rt>)) .& (significand == (AST.num0 64<rt>))

/// Raises a divide error when the 80-bit value is zero, which is what the
/// reversed divide checks before it touches the operands.
let private raiseIfZero bld lblErr lblChk hi lo =
  append bld {
    AST.cjmp (isZero hi lo) (AST.jmpDest lblErr) (AST.jmpDest lblChk)
    AST.lmark lblErr
    AST.sideEffect (Exception DivideError)
    AST.lmark lblChk
  }

let fdivr (ins: Instruction) bld doPop =
  lift bld ins {
    let lblChk = label bld "Check"
    let lblErr = label bld "DivErr"
    let struct (tmp0, tmp1) = tmpVars2 bld 64<rt>
    let res = tmpVar bld 64<rt>
    match ins.Operands with
    | NoOperand ->
      let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
      let struct (st1b, st1a) = getFPUPseudoRegVars bld R.ST1
      raiseIfZero bld lblErr lblChk st0b st0a
      castFrom80Bit tmp0 64<rt> st0b st0a bld
      castFrom80Bit tmp1 64<rt> st1b st1a bld
      direct res := AST.fdiv tmp1 tmp0
      castTo80Bit bld st1b st1a res
    | OneOperand _ ->
      let oprExpr = transOneOpr bld ins
      let oprSize = Expr.typeOf oprExpr
      let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
      raiseIfZero bld lblErr lblChk st0b st0a
      castFrom80Bit tmp0 64<rt> st0b st0a bld
      if oprSize = 64<rt> then
        direct tmp1 := oprExpr
      else
        direct tmp1 := AST.cast CastKind.FloatCast 64<rt> oprExpr
      direct res := AST.fdiv tmp1 tmp0
      castTo80Bit bld st0b st0a res
    | TwoOperands(OprReg reg0, OprReg reg1) ->
      let struct (r0B, r0A) = getFPUPseudoRegVars bld reg0
      let struct (r1B, r1A) = getFPUPseudoRegVars bld reg1
      raiseIfZero bld lblErr lblChk r0B r0A
      castFrom80Bit tmp0 64<rt> r0B r0A bld
      castFrom80Bit tmp1 64<rt> r1B r1A bld
      direct res := AST.fdiv tmp1 tmp0
      castTo80Bit bld r0B r0A res
    | _ ->
      raise InvalidOperandException
    if doPop then popFPUStack bld else ()
    updateC1OnStore bld
  }

let fidivr ins bld = fpuIntOp ins bld AST.fdiv false

let inline private castToF64 intexp =
  AST.cast CastKind.SIntToFloat 64<rt> intexp

let getExponent isDouble src =
  if isDouble then
    let numMantissa = numI32 52 64<rt>
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

/// The remainder where one step of the division reaches it: divide, take the
/// quotient down to a whole number, and subtract that many divisors. The
/// quotient's low three bits come back in C1, C3 and C0, and C2 says the
/// reduction is finished. `caster` is what rounds the quotient, and is the
/// only thing telling `fprem` from `fprem1`.
let private fpremWholeQuotient bld caster sts srcs tmps =
  append bld {
    let st0b, st0a = sts
    let tmp0, tmp1 = srcs
    let divres, intres, tmpres, _ = tmps
    direct divres := AST.fdiv tmp0 tmp1
    direct intres := AST.cast caster 64<rt> divres
    direct tmpres := AST.fsub tmp0 (AST.fmul tmp1 (castToF64 intres))
    castTo80Bit bld st0b st0a tmpres
    direct (regVar bld R.FSWC2) := AST.b0
    direct (regVar bld R.FSWC1) := AST.xtlo 1<rt> intres
    direct (regVar bld R.FSWC3) := AST.extract intres 1<rt> 1
    direct (regVar bld R.FSWC0) := AST.extract intres 1<rt> 2
  }

/// The partial remainder where the exponents stand sixty-four or more apart,
/// which is further than one step reaches. The divisor is scaled up by two to
/// the difference less sixty-three, and what comes back is the remainder of
/// that scaled divide. C2 is set to say the reduction is unfinished, and the
/// instruction is meant to be run again on what is left.
let private fpremScaledQuotient bld sts srcs expDiff tmps =
  let st0b, st0a = sts
  let tmp0, tmp1 = srcs
  let divres, intres, tmpres, divider = tmps
  let n2 = numI32 2 64<rt> |> castToF64
  append bld {
    direct (regVar bld R.FSWC2) := AST.b1
    direct tmpres := AST.fsub (castToF64 expDiff) (castToF64 (numI32 63 64<rt>))
    direct divider := AST.fpow n2 tmpres
    direct divres := AST.fdiv (AST.fdiv tmp0 tmp1) divider
    direct intres := AST.cast CastKind.FtoITrunc 64<rt> divres
    direct tmpres :=
      AST.fsub tmp0 (AST.fmul tmp1 (AST.fmul (castToF64 intres) divider))
  }
  castTo80Bit bld st0b st0a tmpres

let fprem (ins: Instruction) bld round =
  lift bld ins {
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
    let struct (divres, intres, tmpres, divider) = tmpVars4 bld 64<rt>
    let sts = st0b, st0a
    let srcs = tmp0, tmp1
    let tmps = divres, intres, tmpres, divider
    castFrom80Bit tmp0 64<rt> st0b st0a bld
    castFrom80Bit tmp1 64<rt> st1b st1a bld
    direct expDiff := (st0b .& expMask) .- (st1b .& expMask)
    AST.cjmp
      (isUnordered true tmp0 .| isUnordered true tmp1)
      (AST.jmpDest lblUnordered)
      (AST.jmpDest lblOrdered)
    AST.lmark lblUnordered
    castTo80Bit bld st0b st0a (AST.ite (isUnordered true tmp0) tmp0 tmp1)
    direct (regVar bld R.FSWC2) := AST.b0
    AST.jmp (AST.jmpDest lblExit)
    AST.lmark lblOrdered
    AST.cjmp (AST.slt expDiff n64)
             (AST.jmpDest lblLT64)
             (AST.jmpDest lblGE64)
    AST.lmark lblLT64 (* D < 64 *)
    fpremWholeQuotient bld caster sts srcs tmps
    AST.jmp (AST.jmpDest lblExit)
    AST.lmark lblGE64 (* ELSE *)
    fpremScaledQuotient bld sts srcs expDiff tmps
    AST.lmark lblExit
  }

let fabs (ins: Instruction) bld =
  lift bld ins {
    let struct (st0b, _st0a) = getFPUPseudoRegVars bld R.ST0
    direct (AST.extract st0b 1<rt> 15) := AST.b0
    direct (regVar bld R.FSWC1) := AST.b0
#if !EMULATION
    direct (regVar bld R.FSWC0) := undefC0
    direct (regVar bld R.FSWC2) := undefC2
    direct (regVar bld R.FSWC3) := undefC3
#endif
  }

let fchs (ins: Instruction) bld =
  lift bld ins {
    let struct (st0b, _st0a) = getFPUPseudoRegVars bld R.ST0
    let tmp = tmpVar bld 1<rt>
    direct tmp := AST.xthi 1<rt> st0b
    direct (AST.xthi 1<rt> st0b) := AST.not tmp
    direct (regVar bld R.FSWC1) := AST.b0
#if !EMULATION
    direct (regVar bld R.FSWC0) := undefC0
    direct (regVar bld R.FSWC2) := undefC2
    direct (regVar bld R.FSWC3) := undefC3
#endif
  }

let frndint (ins: Instruction) bld =
  lift bld ins {
    let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
    let lblOrdered = label bld "Ordered"
    let lblExit = label bld "Exit"
    let tmp0 = tmpVar bld 64<rt>
    let rcField = tmpVar bld 8<rt> (* Rounding Control *)
    let cst00 = AST.cast CastKind.FtoIRound 64<rt> tmp0
    let cst01 = AST.cast CastKind.FtoIFloor 64<rt> tmp0
    let cst10 = AST.cast CastKind.FtoICeil 64<rt> tmp0
    let cst11 = AST.cast CastKind.FtoITrunc 64<rt> tmp0
    castFrom80Bit tmp0 64<rt> st0b st0a bld
    AST.cjmp
      (isUnordered true tmp0) (AST.jmpDest lblExit) (AST.jmpDest lblOrdered)
    AST.lmark lblOrdered
    direct rcField := (AST.zext 8<rt> (AST.extract (regVar bld R.FCW) 1<rt> 11))
    direct rcField := (rcField << AST.num1 8<rt>)
    direct rcField :=
      (rcField .| (AST.zext 8<rt> (AST.extract (regVar bld R.FCW) 1<rt> 10)))
    direct tmp0 := AST.ite (rcField == AST.num0 8<rt>) cst00 tmp0
    direct tmp0 := AST.ite (rcField == AST.num1 8<rt>) cst01 tmp0
    direct tmp0 := AST.ite (rcField == numI32 2 8<rt>) cst10 tmp0
    direct tmp0 := AST.ite (rcField == numI32 3 8<rt>) cst11 tmp0
    castTo80Bit bld st0b st0a (castToF64 tmp0)
    AST.lmark lblExit
    updateC1OnStore bld
  }

let fscale (ins: Instruction) bld =
  lift bld ins {
    let struct (tmp0, tmp1, tmp2, tmp3) = tmpVars4 bld 64<rt>
    let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
    let struct (st1b, st1a) = getFPUPseudoRegVars bld R.ST1
    let f2 = numI32 2 64<rt> |> castToF64
    castFrom80Bit tmp0 64<rt> st0b st0a bld
    castFrom80Bit tmp1 64<rt> st1b st1a bld
    direct tmp2 := AST.cast CastKind.FtoITrunc 64<rt> tmp1
    let exp = AST.ite (tmp2 ?>= numI64 0L 64<rt>) tmp2 (AST.neg tmp2)
    direct tmp3 := AST.fpow f2 (castToF64 exp)
    let v =
      AST.ite
        (tmp2 ?>= numI64 0L 64<rt>) (AST.fmul tmp0 tmp3) (AST.fdiv tmp0 tmp3)
    castTo80Bit bld st0b st0a v
    updateC1OnStore bld
  }

let fsqrt (ins: Instruction) bld =
  lift bld ins {
    let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
    let tmp0 = tmpVar bld 64<rt>
    castFrom80Bit tmp0 64<rt> st0b st0a bld
    castTo80Bit bld st0b st0a (AST.unop UnOpType.FSQRT tmp0)
    updateC1OnStore bld
  }

let fxtract (ins: Instruction) bld =
  lift bld ins {
    let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
    let n3fff = numI32 0x3FFF 16<rt>
    let tmpB, tmpA = tmpVar bld 16<rt>, bld.Stream.NewTempVar 64<rt>
    let tmpF = tmpVar bld 64<rt>
    direct tmpB := (st0b .& numI32 0x8000 16<rt>) .| n3fff
    direct tmpA := st0a
    direct tmpF := castToF64 ((st0b .& numI32 0x7fff 16<rt>) .- n3fff)
    castTo80Bit bld st0b st0a tmpF
    pushFPUStack bld
    direct st0b := tmpB
    direct st0a := tmpA
  }

let private prepareTwoOprsForComparison (ins: Instruction) bld =
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
    let oprExpr = transOprToExpr bld false ins opr
    castFrom80Bit tmp0 64<rt> st0b st0a bld
    append bld {
      direct tmp1 := AST.cast CastKind.FloatCast 64<rt> oprExpr
    }
  | TwoOperands(OprReg r1, OprReg r2) ->
    let struct (st0b, st0a) = getFPUPseudoRegVars bld r1
    let struct (st1b, st1a) = getFPUPseudoRegVars bld r2
    castFrom80Bit tmp0 64<rt> st0b st0a bld
    castFrom80Bit tmp1 64<rt> st1b st1a bld
  | _ ->
    raise InvalidOperandException
  if ins.Opcode = Opcode.FUCOM then struct (tmp1, tmp0) else struct (tmp0, tmp1)

let fcom (ins: Instruction) bld nPop unordered =
  lift bld ins {
    let c0 = regVar bld R.FSWC0
    let c2 = regVar bld R.FSWC2
    let c3 = regVar bld R.FSWC3
    let struct (tmp0, tmp1) = prepareTwoOprsForComparison ins bld
    let isNan = isNan true tmp0 .| isNan true tmp1
    direct c0 := isNan .| AST.flt tmp0 tmp1
    direct c2 := isNan .| AST.b0
    direct c3 := isNan .| (tmp0 == tmp1)
    direct (regVar bld R.FSWC1) := AST.b0
    if nPop > 0 then popFPUStack bld else ()
    if nPop = 2 then popFPUStack bld else ()
  }

let ficom (ins: Instruction) bld doPop =
  lift bld ins {
    let oprExpr = transOneOpr bld ins
    let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
    let struct (tmp0, tmp1) = tmpVars2 bld 64<rt>
    castFrom80Bit tmp0 64<rt> st0b st0a bld
    direct tmp1 := AST.cast CastKind.SIntToFloat 64<rt> oprExpr
    let isNan = isNan true tmp0 .| isNan true tmp1
    direct (regVar bld R.FSWC0) := isNan .| AST.flt tmp0 tmp1
    direct (regVar bld R.FSWC2) := isNan .| AST.b0
    direct (regVar bld R.FSWC3) := isNan .| (tmp0 == tmp1)
    direct (regVar bld R.FSWC1) := AST.b0
    if doPop then popFPUStack bld else ()
  }

let fcomi (ins: Instruction) bld doPop =
  lift bld ins {
    let zf = regVar bld R.ZF
    let pf = regVar bld R.PF
    let cf = regVar bld R.CF
    let struct (tmp0, tmp1) = prepareTwoOprsForComparison ins bld
    let isNan = isNan true tmp0 .| isNan true tmp1
    direct cf := isNan .| AST.flt tmp0 tmp1
    direct pf := isNan .| AST.b0
    direct zf := isNan .| (tmp0 == tmp1)
    direct (regVar bld R.FSWC1) := AST.b0
    if doPop then popFPUStack bld else ()
#if EMULATION
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let ftst (ins: Instruction) bld =
  lift bld ins {
    let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
    let num0V = AST.num0 64<rt>
    let c0 = regVar bld R.FSWC0
    let c2 = regVar bld R.FSWC2
    let c3 = regVar bld R.FSWC3
    let tmp = tmpVar bld 64<rt>
    castFrom80Bit tmp 64<rt> st0b st0a bld
    direct c0 := AST.flt tmp num0V
    direct c2 := AST.b0
    direct c3 := tmp == num0V
    direct (regVar bld R.FSWC1) := AST.b0
  }

let fxam (ins: Instruction) bld =
  lift bld ins {
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
    direct (regVar bld R.FSWC1) := AST.xthi 1<rt> st0b
    direct (regVar bld R.FSWC3) := c3Cond
    direct (regVar bld R.FSWC2) := c2Cond
    direct (regVar bld R.FSWC0) := c0Cond
  }

let private checkForTrigFunction unsigned lin lout bld =
  append bld {
    let maxLimit = numI64 (1L <<< 63) 64<rt>
    let maxFloat = AST.cast CastKind.UIntToFloat 64<rt> maxLimit
    AST.cjmp (AST.flt unsigned maxFloat)
             (AST.jmpDest lin)
             (AST.jmpDest lout)
  }

let private ftrig (ins: Instruction) bld trigFunc =
  lift bld ins {
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
    castFrom80Bit unsigned 64<rt> (st0b .& n7fff) st0a bld
    castFrom80Bit signed 64<rt> st0b st0a bld
    checkForTrigFunction unsigned lin lout bld
    AST.lmark lin
    direct tmp := trigFunc signed
    castTo80Bit bld st0b st0a tmp
    direct c2 := AST.b0
    AST.jmp (AST.jmpDest lexit)
    AST.lmark lout
    direct c2 := AST.b1
    AST.lmark lexit
#if !EMULATION
    direct c0 := undefC0
    direct c3 := undefC3
#endif
    direct c1 := AST.b0
  }

let fsin ins bld = ftrig ins bld AST.fsin

let fcos ins bld = ftrig ins bld AST.fcos

let fsincos (ins: Instruction) bld =
  lift bld ins {
    let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
    let n7fff = numI32 0x7fff 16<rt>
    let c0 = regVar bld R.FSWC0
    let c2 = regVar bld R.FSWC2
    let c3 = regVar bld R.FSWC3
    let lin = label bld "IsInRange"
    let lout = label bld "IsOutOfRange"
    let lexit = label bld "Exit"
    let struct (unsigned, signed, tmpsin, tmpcos) = tmpVars4 bld 64<rt>
    castFrom80Bit unsigned 64<rt> (st0b .& n7fff) st0a bld
    castFrom80Bit signed 64<rt> st0b st0a bld
    checkForTrigFunction unsigned lin lout bld
    AST.lmark lin
    direct tmpcos := AST.fcos signed
    direct tmpsin := AST.fsin signed
    castTo80Bit bld st0b st0a tmpsin
    pushFPUStack bld
    castTo80Bit bld st0b st0a tmpcos
    direct c2 := AST.b0
    AST.jmp (AST.jmpDest lexit)
    AST.lmark lout
    direct c2 := AST.b1
    AST.lmark lexit
#if !EMULATION
    direct c0 := undefC0
    direct c3 := undefC3
#endif
    updateC1OnLoad bld
  }

let fptan (ins: Instruction) bld =
  lift bld ins {
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
    castFrom80Bit unsigned 64<rt> (st0b .& n7fff) st0a bld
    castFrom80Bit signed 64<rt> st0b st0a bld
    checkForTrigFunction unsigned lin lout bld
    AST.lmark lin
    direct tmp := AST.ftan signed
    castTo80Bit bld st0b st0a tmp
    direct c2 := AST.b0
    pushFPUStack bld
    castTo80Bit bld st0b st0a fone
    direct c2 := AST.b0
    AST.jmp (AST.jmpDest lexit)
    AST.lmark lout
    direct c2 := AST.b1
    AST.lmark lexit
#if !EMULATION
    direct c0 := undefC0
    direct c3 := undefC3
#endif
    updateC1OnLoad bld
  }

let fpatan (ins: Instruction) bld =
  lift bld ins {
    let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
    let struct (st1b, st1a) = getFPUPseudoRegVars bld R.ST1
    let struct (tmp0, tmp1, res) = tmpVars3 bld 64<rt>
    castFrom80Bit tmp0 64<rt> st0b st0a bld
    castFrom80Bit tmp1 64<rt> st1b st1a bld
    direct res := AST.fatan (AST.fdiv tmp1 tmp0)
    castTo80Bit bld st1b st1a res
    popFPUStack bld
    updateC1OnStore bld
#if !EMULATION
    cflagsUndefined023 bld
#endif
  }

let f2xm1 (ins: Instruction) bld =
  lift bld ins {
    let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
    let f1 = numI32 1 64<rt> |> castToF64
    let f2 = numI32 2 64<rt> |> castToF64
    let c1 = regVar bld R.FSWC1
    let struct (tmp, res) = tmpVars2 bld 64<rt>
    castFrom80Bit tmp 64<rt> st0b st0a bld
    direct res := AST.fsub (AST.fpow f2 tmp) f1
    castTo80Bit bld st0b st0a res
    direct c1 := AST.b0
#if !EMULATION
    cflagsUndefined023 bld
#endif
  }

let fyl2x (ins: Instruction) bld =
  lift bld ins {
    let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
    let struct (st1b, st1a) = getFPUPseudoRegVars bld R.ST1
    let struct (tmp0, tmp1, res) = tmpVars3 bld 64<rt>
    let f2 = numI32 2 64<rt> |> castToF64
    castFrom80Bit tmp0 64<rt> st0b st0a bld
    castFrom80Bit tmp1 64<rt> st1b st1a bld
    direct res := AST.fmul tmp1 (AST.flog f2 tmp0)
    castTo80Bit bld st1b st1a res
    popFPUStack bld
    updateC1OnStore bld
#if !EMULATION
    cflagsUndefined023 bld
#endif
  }

let fyl2xp1 (ins: Instruction) bld =
  lift bld ins {
    let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
    let struct (st1b, st1a) = getFPUPseudoRegVars bld R.ST1
    let struct (tmp0, tmp1, res) = tmpVars3 bld 64<rt>
    let f1 = numI32 1 64<rt> |> castToF64
    let f2 = numI32 2 64<rt> |> castToF64
    castFrom80Bit tmp0 64<rt> st0b st0a bld
    castFrom80Bit tmp1 64<rt> st1b st1a bld
    direct res := AST.fmul tmp1 (AST.flog f2 (AST.fadd tmp0 f1))
    castTo80Bit bld st1b st1a res
    popFPUStack bld
    updateC1OnStore bld
#if !EMULATION
    cflagsUndefined023 bld
#endif
  }

let fld1 ins bld =
  let oprExpr = numU64 0x3FF0000000000000UL 64<rt>
  fpuLoad ins bld oprExpr

let fldz (ins: Instruction) bld =
  lift bld ins {
    let struct (st0b, st0a) = getFPUPseudoRegVars bld R.ST0
    pushFPUStack bld
    direct st0b := AST.num0 16<rt>
    direct st0a := AST.num0 64<rt>
    updateC1OnLoad bld
  }

let fldpi ins bld =
  let oprExpr = numU64 4614256656552045848UL 64<rt>
  fpuLoad ins bld oprExpr

let fldl2e ins bld =
  let oprExpr = numU64 4609176140021203710UL 64<rt>
  fpuLoad ins bld oprExpr

let fldln2 ins bld =
  let oprExpr = numU64 4604418534313441775UL 64<rt>
  fpuLoad ins bld oprExpr

let fldl2t ins bld =
  let oprExpr = numU64 4614662735865160561UL 64<rt>
  fpuLoad ins bld oprExpr

let fldlg2 ins bld =
  let oprExpr = numU64 4599094494223104511UL 64<rt>
  fpuLoad ins bld oprExpr

let fincstp (ins: Instruction) bld =
  lift bld ins {
    let top = regVar bld R.FTOP
    (* TOP in B2R2 is really a counter, so we decrement TOP here (same as
       pop). *)
    let cond = top == numI32 0 8<rt>
    let updatedTOP = AST.ite cond (numI32 7 8<rt>) (top .- AST.num1 8<rt>)
    extractDstAssign top updatedTOP
    let struct (tmpB, tmpA) = moveFPRegtoTemp R.ST0 bld
    moveFPRegtoFPReg R.ST0 R.ST1 bld
    moveFPRegtoFPReg R.ST1 R.ST2 bld
    moveFPRegtoFPReg R.ST2 R.ST3 bld
    moveFPRegtoFPReg R.ST3 R.ST4 bld
    moveFPRegtoFPReg R.ST4 R.ST5 bld
    moveFPRegtoFPReg R.ST5 R.ST6 bld
    moveFPRegtoFPReg R.ST6 R.ST7 bld
    moveTemptoFPReg R.ST7 tmpA tmpB bld
    direct (regVar bld R.FSWC1) := AST.b0
#if !EMULATION
    direct (regVar bld R.FSWC0) := undefC0
    direct (regVar bld R.FSWC2) := undefC2
    direct (regVar bld R.FSWC3) := undefC3
#endif
  }

let fdecstp (ins: Instruction) bld =
  lift bld ins {
    let top = regVar bld R.FTOP
    (* TOP in B2R2 is really a counter, so we increment TOP here. *)
    let cond = top == numI32 7 8<rt>
    let updatedTOP = AST.ite cond (AST.num0 8<rt>) (top .+ AST.num1 8<rt>)
    extractDstAssign top updatedTOP
    let struct (tmpB, tmpA) = moveFPRegtoTemp R.ST7 bld
    moveFPRegtoFPReg R.ST7 R.ST6 bld
    moveFPRegtoFPReg R.ST6 R.ST5 bld
    moveFPRegtoFPReg R.ST5 R.ST4 bld
    moveFPRegtoFPReg R.ST4 R.ST3 bld
    moveFPRegtoFPReg R.ST3 R.ST2 bld
    moveFPRegtoFPReg R.ST2 R.ST1 bld
    moveFPRegtoFPReg R.ST1 R.ST0 bld
    moveTemptoFPReg R.ST0 tmpA tmpB bld
    direct (regVar bld R.FSWC1) := AST.b0
#if !EMULATION
    direct (regVar bld R.FSWC0) := undefC0
    direct (regVar bld R.FSWC2) := undefC2
    direct (regVar bld R.FSWC3) := undefC3
#endif
  }

let ffree (ins: Instruction) bld =
  lift bld ins {
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
    direct top16 := AST.cast CastKind.ZeroExt 16<rt> top
    direct top16 := top16 .+ offset
    direct shifter := (numI32 2 16<rt>) .* top16
    direct tagValue := (value3 << shifter)
    direct tagWord := tagWord .| tagValue
  }

(* FIXME: check all unmasked pending floating point exceptions. *)
let private checkFPUExceptions bld = ()

let private clearFPU bld =
  append bld {
    let cw = numI32 895 16<rt>
    let tw = BitVector.MaxUInt16 |> AST.num
    direct (regVar bld R.FCW) := cw
    direct (regVar bld R.FSW) := AST.num0 16<rt>
    direct (regVar bld R.FTW) := tw
  }

let finit (ins: Instruction) bld =
  lift bld ins {
    checkFPUExceptions bld
    clearFPU bld
  }

let fninit (ins: Instruction) bld =
  lift bld ins {
    clearFPU bld
  }

let fclex (ins: Instruction) bld =
  lift bld ins {
    let stsWrd = regVar bld R.FSW
    direct stsWrd := stsWrd .& (numI32 0xFF80 16<rt>)
    direct (AST.xthi 1<rt> stsWrd) := AST.b0
#if !EMULATION
    direct (regVar bld R.FSWC0) := undefC0
    direct (regVar bld R.FSWC1) := undefC1
    direct (regVar bld R.FSWC2) := undefC2
    direct (regVar bld R.FSWC3) := undefC3
#endif
  }

let fstcw (ins: Instruction) bld =
  lift bld ins {
    let oprExpr = transOneOpr bld ins
    checkFPUExceptions bld
    direct oprExpr := regVar bld R.FCW
#if !EMULATION
    allCFlagsUndefined bld
#endif
  }

let fnstcw (ins: Instruction) bld =
  lift bld ins {
    let oprExpr = transOneOpr bld ins
    direct oprExpr := regVar bld R.FCW
#if !EMULATION
    allCFlagsUndefined bld
#endif
  }

let fldcw (ins: Instruction) bld =
  lift bld ins {
    let oprExpr = transOneOpr bld ins
    direct (regVar bld R.FCW) := oprExpr
#if !EMULATION
    direct (regVar bld R.FSWC0) := undefC0
    direct (regVar bld R.FSWC1) := undefC1
    direct (regVar bld R.FSWC2) := undefC2
    direct (regVar bld R.FSWC3) := undefC3
#endif
  }

let inline private storeLE addr v = AST.store Endian.Little addr v

let private m14fstenv dstAddr addrSize bld =
  append bld {
    let fiplo = AST.xtlo 16<rt> (regVar bld R.FIP)
    let fdplo = AST.xtlo 16<rt> (regVar bld R.FDP)
    storeLE (dstAddr) (regVar bld R.FCW)
    storeLE (dstAddr .+ numI32 2 addrSize) (regVar bld R.FSW)
    storeLE (dstAddr .+ numI32 4 addrSize) (regVar bld R.FTW)
    storeLE (dstAddr .+ numI32 6 addrSize) fiplo
    storeLE (dstAddr .+ numI32 8 addrSize) (regVar bld R.FCS)
    storeLE (dstAddr .+ numI32 10 addrSize) fdplo
    storeLE (dstAddr .+ numI32 12 addrSize) (regVar bld R.FDS)
  }

let private m28fstenv dstAddr addrSize bld =
  append bld {
    let n0 = numI32 0 16<rt>
    storeLE (dstAddr) (regVar bld R.FCW)
    storeLE (dstAddr .+ numI32 2 addrSize) n0
    storeLE (dstAddr .+ numI32 4 addrSize) (regVar bld R.FSW)
    storeLE (dstAddr .+ numI32 6 addrSize) n0
    storeLE (dstAddr .+ numI32 8 addrSize) (regVar bld R.FTW)
    storeLE (dstAddr .+ numI32 10 addrSize) n0
    storeLE (dstAddr .+ numI32 12 addrSize) (regVar bld R.FIP)
    storeLE (dstAddr .+ numI32 20 addrSize) (regVar bld R.FDP)
  }

let fnstenv (ins: Instruction) bld =
  lift bld ins {
    let dst = transOneOpr bld ins
    let struct (addrExpr, addrSize) = getLoadAddressExpr dst
    match Expr.typeOf dst with
    | 112<rt> -> m14fstenv addrExpr addrSize bld
    | 224<rt> -> m28fstenv addrExpr addrSize bld
    | _ -> raise InvalidOperandSizeException
  }

let private m14fldenv srcAddr addrSize bld =
  append bld {
    direct (regVar bld R.FCW) := AST.loadLE 16<rt> (srcAddr)
    direct (regVar bld R.FSW) :=
      AST.loadLE 16<rt> (srcAddr .+ numI32 2 addrSize)
    direct (regVar bld R.FTW) :=
      AST.loadLE 16<rt> (srcAddr .+ numI32 4 addrSize)
    direct (AST.xtlo 16<rt> (regVar bld R.FIP)) :=
      AST.loadLE 16<rt> (srcAddr .+ numI32 6 addrSize)
    direct (regVar bld R.FCS) :=
      AST.loadLE 16<rt> (srcAddr .+ numI32 8 addrSize)
    direct (AST.xtlo 16<rt> (regVar bld R.FDP)) :=
      AST.loadLE 16<rt> (srcAddr .+ numI32 10 addrSize)
    direct (regVar bld R.FDS) :=
      AST.loadLE 16<rt> (srcAddr .+ numI32 12 addrSize)
  }

let private m28fldenv srcAddr addrSize bld =
  append bld {
    direct (regVar bld R.FCW) := AST.loadLE 16<rt> (srcAddr)
    direct (regVar bld R.FSW) :=
      AST.loadLE 16<rt> (srcAddr .+ numI32 4 addrSize)
    direct (regVar bld R.FTW) :=
      AST.loadLE 16<rt> (srcAddr .+ numI32 8 addrSize)
    direct (regVar bld R.FIP) :=
      AST.loadLE 64<rt> (srcAddr .+ numI32 12 addrSize)
    direct (regVar bld R.FDP) :=
      AST.loadLE 64<rt> (srcAddr .+ numI32 20 addrSize)
  }

let fldenv (ins: Instruction) bld =
  lift bld ins {
    let src = transOneOpr bld ins
    let struct (addrExpr, addrSize) = getLoadAddressExpr src
    match Expr.typeOf src with
    | 112<rt> -> m14fldenv addrExpr addrSize bld
    | 224<rt> -> m28fldenv addrExpr addrSize bld
    | _ -> raise InvalidOperandSizeException
  }

let private stSts dstAddr addrSize offset bld =
  append bld {
    let struct (stb, sta) = getFPUPseudoRegVars bld R.ST0
    storeLE (dstAddr .+ numI32 (offset) addrSize) sta
    storeLE (dstAddr .+ numI32 (offset + 8) addrSize) stb
    let struct (stb, sta) = getFPUPseudoRegVars bld R.ST1
    storeLE (dstAddr .+ numI32 (offset + 10) addrSize) sta
    storeLE (dstAddr .+ numI32 (offset + 18) addrSize) stb
    let struct (stb, sta) = getFPUPseudoRegVars bld R.ST2
    storeLE (dstAddr .+ numI32 (offset + 20) addrSize) sta
    storeLE (dstAddr .+ numI32 (offset + 28) addrSize) stb
    let struct (stb, sta) = getFPUPseudoRegVars bld R.ST3
    storeLE (dstAddr .+ numI32 (offset + 30) addrSize) sta
    storeLE (dstAddr .+ numI32 (offset + 38) addrSize) stb
    let struct (stb, sta) = getFPUPseudoRegVars bld R.ST4
    storeLE (dstAddr .+ numI32 (offset + 40) addrSize) sta
    storeLE (dstAddr .+ numI32 (offset + 48) addrSize) stb
    let struct (stb, sta) = getFPUPseudoRegVars bld R.ST5
    storeLE (dstAddr .+ numI32 (offset + 50) addrSize) sta
    storeLE (dstAddr .+ numI32 (offset + 58) addrSize) stb
    let struct (stb, sta) = getFPUPseudoRegVars bld R.ST6
    storeLE (dstAddr .+ numI32 (offset + 60) addrSize) sta
    storeLE (dstAddr .+ numI32 (offset + 68) addrSize) stb
    let struct (stb, sta) = getFPUPseudoRegVars bld R.ST7
    storeLE (dstAddr .+ numI32 (offset + 70) addrSize) sta
    storeLE (dstAddr .+ numI32 (offset + 78) addrSize) stb
  }

let fnsave (ins: Instruction) bld =
  lift bld ins {
    let dst = transOneOpr bld ins
    let struct (addrExpr, addrSize) = getLoadAddressExpr dst
    match Expr.typeOf dst with
    | 752<rt> ->
      m14fstenv addrExpr addrSize bld
      stSts addrExpr addrSize 14 bld
    | 864<rt> ->
      m28fstenv addrExpr addrSize bld
      stSts addrExpr addrSize 28 bld
    | _ ->
      raise InvalidOperandSizeException
    direct (regVar bld R.FCW) := numI32 0x037F 16<rt>
    direct (regVar bld R.FSW) := AST.num0 16<rt>
    direct (regVar bld R.FTW) := numI32 0xFFFF 16<rt>
    direct (regVar bld R.FDP) := AST.num0 64<rt>
    direct (regVar bld R.FIP) := AST.num0 64<rt>
    direct (regVar bld R.FOP) := AST.num0 16<rt>
  }

let private ldSts srcAddr addrSize offset bld =
  append bld {
    let struct (stb, sta) = getFPUPseudoRegVars bld R.ST0
    direct sta := AST.loadLE 64<rt> (srcAddr .+ numI32 (offset) addrSize)
    direct stb := AST.loadLE 16<rt> (srcAddr .+ numI32 (offset + 8) addrSize)
    let struct (stb, sta) = getFPUPseudoRegVars bld R.ST1
    direct sta := AST.loadLE 64<rt> (srcAddr .+ numI32 (offset + 10) addrSize)
    direct stb := AST.loadLE 16<rt> (srcAddr .+ numI32 (offset + 18) addrSize)
    let struct (stb, sta) = getFPUPseudoRegVars bld R.ST2
    direct sta := AST.loadLE 64<rt> (srcAddr .+ numI32 (offset + 20) addrSize)
    direct stb := AST.loadLE 16<rt> (srcAddr .+ numI32 (offset + 28) addrSize)
    let struct (stb, sta) = getFPUPseudoRegVars bld R.ST3
    direct sta := AST.loadLE 64<rt> (srcAddr .+ numI32 (offset + 30) addrSize)
    direct stb := AST.loadLE 16<rt> (srcAddr .+ numI32 (offset + 38) addrSize)
    let struct (stb, sta) = getFPUPseudoRegVars bld R.ST4
    direct sta := AST.loadLE 64<rt> (srcAddr .+ numI32 (offset + 40) addrSize)
    direct stb := AST.loadLE 16<rt> (srcAddr .+ numI32 (offset + 48) addrSize)
    let struct (stb, sta) = getFPUPseudoRegVars bld R.ST5
    direct sta := AST.loadLE 64<rt> (srcAddr .+ numI32 (offset + 50) addrSize)
    direct stb := AST.loadLE 16<rt> (srcAddr .+ numI32 (offset + 58) addrSize)
    let struct (stb, sta) = getFPUPseudoRegVars bld R.ST6
    direct sta := AST.loadLE 64<rt> (srcAddr .+ numI32 (offset + 60) addrSize)
    direct stb := AST.loadLE 16<rt> (srcAddr .+ numI32 (offset + 68) addrSize)
    let struct (stb, sta) = getFPUPseudoRegVars bld R.ST7
    direct sta := AST.loadLE 64<rt> (srcAddr .+ numI32 (offset + 70) addrSize)
    direct stb := AST.loadLE 16<rt> (srcAddr .+ numI32 (offset + 78) addrSize)
  }

let frstor (ins: Instruction) bld =
  lift bld ins {
    let src = transOneOpr bld ins
    let struct (addrExpr, addrSize) = getLoadAddressExpr src
    match Expr.typeOf src with
    | 752<rt> ->
      m14fldenv addrExpr addrSize bld
      ldSts addrExpr addrSize 14 bld
    | 864<rt> ->
      m28fldenv addrExpr addrSize bld
      ldSts addrExpr addrSize 28 bld
    | _ ->
      raise InvalidOperandSizeException
  }

let fnstsw (ins: Instruction) bld =
  lift bld ins {
    let oprExpr = transOneOpr bld ins
    direct oprExpr := regVar bld R.FSW
#if !EMULATION
    allCFlagsUndefined bld
#endif
  }

let wait (ins: Instruction) bld =
  lift bld ins {
    checkFPUExceptions bld
  }

let fnop (ins: Instruction) bld =
  lift bld ins {
#if !EMULATION
    allCFlagsUndefined bld
#endif
  }

/// The x87 stack registers, in the order FXSAVE lays them out: eighty bits
/// each, on a sixteen-byte stride, starting thirty-two bytes in.
let private fxsaveStackRegs =
  [ R.ST0; R.ST1; R.ST2; R.ST3; R.ST4; R.ST5; R.ST6; R.ST7 ]

/// The SSE registers FXSAVE always lays out, on the same stride from one
/// hundred and sixty bytes in.
let private fxsaveXmmRegs =
  [ R.XMM0; R.XMM1; R.XMM2; R.XMM3; R.XMM4; R.XMM5; R.XMM6; R.XMM7 ]

/// The eight more it lays out in 64-bit mode, carrying on from there.
let private fxsaveXmmRegs64 =
  [ R.XMM8; R.XMM9; R.XMM10; R.XMM11; R.XMM12; R.XMM13; R.XMM14; R.XMM15 ]

let private fxsaveInternal bld dstAddr addrSize is64bit =
  let storeAt off e =
    append bld { storeLE (dstAddr .+ (numI32 off addrSize)) e }
  append bld {
    storeLE (dstAddr) (regVar bld R.FCW)
  }
  storeAt 2 (regVar bld R.FSW)
  storeAt 4 (regVar bld R.FTW)
  storeAt 6 (regVar bld R.FOP)
  storeAt 8 (regVar bld R.FIP)
  storeAt 16 (regVar bld R.FDP)
  storeAt 24 (regVar bld R.MXCSR)
  storeAt 28 (regVar bld R.MXCSRMASK)
  fxsaveStackRegs
  |> List.iteri (fun i st ->
    let struct (stb, sta) = getFPUPseudoRegVars bld st
    storeAt (32 + 16 * i) sta
    storeAt (40 + 16 * i) stb
  )
  fxsaveXmmRegs
  |> List.iteri (fun i xmm ->
    let struct (xmmb, xmma) = pseudoRegVar128 bld xmm
    storeAt (160 + 16 * i) xmma
    storeAt (168 + 16 * i) xmmb
  )
  if is64bit then
    fxsaveXmmRegs64
    |> List.iteri (fun i xmm ->
      let struct (xmmb, xmma) = pseudoRegVar128 bld xmm
      storeAt (288 + 16 * i) xmma
      storeAt (296 + 16 * i) xmmb
    )
  else
    ()

let fxsave (ins: Instruction) bld =
  lift bld ins {
    let dst = transOneOpr bld ins
    let struct (addrExpr, addrSize) = getLoadAddressExpr dst
    fxsaveInternal bld addrExpr addrSize (bld.RegType = 64<rt>)
  }

let private fxrstoreInternal bld srcAddr addrSz is64bit =
  let loadAt sz off = AST.loadLE sz (srcAddr .+ (numI32 off addrSz))
  append bld {
    direct (regVar bld R.FCW) := AST.loadLE 16<rt> (srcAddr)
    direct (regVar bld R.FSW) := loadAt 16<rt> 2
    direct (regVar bld R.FTW) := loadAt 16<rt> 4
    direct (regVar bld R.FOP) := loadAt 16<rt> 6
    direct (regVar bld R.FIP) := loadAt 64<rt> 8
    direct (regVar bld R.FDP) := loadAt 64<rt> 16
    direct (regVar bld R.MXCSR) := loadAt 32<rt> 24
    direct (regVar bld R.MXCSRMASK) := loadAt 32<rt> 28
  }
  fxsaveStackRegs
  |> List.iteri (fun i st ->
    let struct (stb, sta) = getFPUPseudoRegVars bld st
    append bld {
      direct sta := loadAt 64<rt> (32 + 16 * i)
      direct stb := loadAt 16<rt> (40 + 16 * i)
    }
  )
  fxsaveXmmRegs
  |> List.iteri (fun i xmm ->
    let struct (xmmb, xmma) = pseudoRegVar128 bld xmm
    append bld {
      direct xmma := loadAt 64<rt> (160 + 16 * i)
      direct xmmb := loadAt 64<rt> (168 + 16 * i)
    }
  )
  if is64bit then
    fxsaveXmmRegs64
    |> List.iteri (fun i xmm ->
      let struct (xmmb, xmma) = pseudoRegVar128 bld xmm
      append bld {
        direct xmma := loadAt 64<rt> (288 + 16 * i)
        direct xmmb := loadAt 64<rt> (296 + 16 * i)
      }
    )
  else
    ()

let fxrstor (ins: Instruction) bld =
  lift bld ins {
    let src = transOneOpr bld ins
    let struct (addrExpr, addrSize) = getLoadAddressExpr src
    fxrstoreInternal bld addrExpr addrSize (bld.RegType = 64<rt>)
  }
