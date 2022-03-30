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

module internal B2R2.FrontEnd.BinLifter.Intel.X87Lifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingOperators
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.BinLifter.Intel
open B2R2.FrontEnd.BinLifter.Intel.LiftingUtils

let private undefC0 = AST.undef 1<rt> "C0 is undefined."

let private undefC1 = AST.undef 1<rt> "C1 is undefined."

let private undefC2 = AST.undef 1<rt> "C2 is undefined."

let private undefC3 = AST.undef 1<rt> "C3 is undefined."

let private allCFlagsUndefined ctxt ir =
  !!ir (!.ctxt R.FSWC0 := undefC0)
  !!ir (!.ctxt R.FSWC1 := undefC1)
  !!ir (!.ctxt R.FSWC2 := undefC2)
  !!ir (!.ctxt R.FSWC3 := undefC3)

let private cflagsUndefined023 ctxt ir =
  !!ir (!.ctxt R.FSWC0 := undefC0)
  !!ir (!.ctxt R.FSWC2 := undefC2)
  !!ir (!.ctxt R.FSWC3 := undefC3)

let inline private getFPUPseudoRegVars ctxt r =
  struct (getPseudoRegVar ctxt r 2, getPseudoRegVar ctxt r 1)

let private updateC1OnLoad ctxt ir =
  let top = !.ctxt R.FTOP
  let c1Flag = !.ctxt R.FSWC1
  (* Top value has been wrapped around, which means stack overflow in B2R2. *)
  !!ir (c1Flag := (top == AST.num0 8<rt>))
  !!ir (!.ctxt R.FSWC0 := undefC0)
  !!ir (!.ctxt R.FSWC2 := undefC2)
  !!ir (!.ctxt R.FSWC3 := undefC3)

let private updateC1OnStore ctxt ir =
  let top = !.ctxt R.FTOP
  let c1Flag = !.ctxt R.FSWC1
  (* Top value has been wrapped around, which means stack underflow in B2R2. *)
  !!ir (c1Flag := (top != numI32 7 8<rt>))
  !!ir (!.ctxt R.FSWC0 := undefC0)
  !!ir (!.ctxt R.FSWC2 := undefC2)
  !!ir (!.ctxt R.FSWC3 := undefC3)

let private moveFPRegtoFPReg regdst regsrc ctxt ir =
  let struct (dstB, dstA) = getFPUPseudoRegVars ctxt regdst
  let struct (srcB, srcA) = getFPUPseudoRegVars ctxt regsrc
  !!ir (dstA := srcA)
  !!ir (dstB := srcB)

let private clearFPReg reg ctxt ir =
  let struct (stB, stA) = getFPUPseudoRegVars ctxt reg
  !!ir (stB := AST.num0 16<rt>)
  !!ir (stA := AST.num0 64<rt>)

let private pushFPUStack ctxt ir =
  let top = !.ctxt R.FTOP
  (* We increment TOP here (which is the opposite way of what the manual says),
     because it is more intuitive to consider it as a counter. *)
  !!ir (extractDstAssign top (top .+ AST.num1 8<rt>))
  !?ir (moveFPRegtoFPReg R.ST7 R.ST6 ctxt)
  !?ir (moveFPRegtoFPReg R.ST6 R.ST5 ctxt)
  !?ir (moveFPRegtoFPReg R.ST5 R.ST4 ctxt)
  !?ir (moveFPRegtoFPReg R.ST4 R.ST3 ctxt)
  !?ir (moveFPRegtoFPReg R.ST3 R.ST2 ctxt)
  !?ir (moveFPRegtoFPReg R.ST2 R.ST1 ctxt)
  !?ir (moveFPRegtoFPReg R.ST1 R.ST0 ctxt)

let private popFPUStack ctxt ir =
  let top = !.ctxt R.FTOP
  (* We decrement TOP here (the opposite way compared to the manual) because it
     is more intuitive, because it is more intuitive to consider it as a
     counter. *)
  !!ir (extractDstAssign top (top .- AST.num1 8<rt>))
  !?ir (moveFPRegtoFPReg R.ST0 R.ST1 ctxt)
  !?ir (moveFPRegtoFPReg R.ST1 R.ST2 ctxt)
  !?ir (moveFPRegtoFPReg R.ST2 R.ST3 ctxt)
  !?ir (moveFPRegtoFPReg R.ST3 R.ST4 ctxt)
  !?ir (moveFPRegtoFPReg R.ST4 R.ST5 ctxt)
  !?ir (moveFPRegtoFPReg R.ST5 R.ST6 ctxt)
  !?ir (moveFPRegtoFPReg R.ST6 R.ST7 ctxt)
  !?ir (clearFPReg R.ST7 ctxt)

let inline private getLoadAddressExpr (src: Expr) =
  match src.E with
  | Load (_, _, addr, _) -> struct (addr, TypeCheck.typeOf addr)
  | _ -> Utils.impossible ()

let private castTo80Bit ctxt tmpB tmpA srcExpr ir =
  let oprSize = TypeCheck.typeOf srcExpr
  match oprSize with
  | 32<rt> ->
    let tmpSrc = !*ir oprSize
    let n31 = numI32 31 32<rt>
    let n15 = numI32 15 32<rt>
    let n23 = numI32 23 32<rt>
    let one = numI32 1 32<rt>
    let biasDiff = numI32 0x3f80 32<rt>
    let sign = AST.xtlo 16<rt> (((tmpSrc >> n31) .& one) << n15)
    let exponent =
      AST.xtlo 16<rt> (((tmpSrc >> n23) .& (numI32 0xff 32<rt>)) .+ biasDiff)
    let integerpart = numI64 0x0010000000000000L 64<rt>
    let significand =
      (AST.zext 64<rt> (tmpSrc .& numI32 0x7fffff 32<rt>)) .| integerpart
    !!ir (tmpSrc := srcExpr)
    !!ir (tmpB := sign .| exponent)
    !!ir (tmpA := (significand << numI32 40 64<rt>))
  | 64<rt> ->
    let tmpSrc = !*ir oprSize
    let n63 = numI32 63 64<rt>
    let n15 = numI32 15 64<rt>
    let n52 = numI32 52 64<rt>
    let one = numI32 1 64<rt>
    let biasDiff = numI32 0x3c00 64<rt>
    let sign = AST.xtlo 16<rt> (((tmpSrc >> n63) .& one) << n15)
    let exponent =
      AST.xtlo 16<rt> (((tmpSrc>> n52) .& (numI32 0x7ff 64<rt>)) .+ biasDiff)
    let integerpart = numI64 0x0010000000000000L 64<rt>
    let significand = tmpSrc .& numI64 0xFFFFFFFFFFFFFL 64<rt> .| integerpart
    !!ir (tmpSrc := srcExpr)
    !!ir (tmpB := sign .| exponent)
    !!ir (tmpA := (significand << numI32 11 64<rt>))
  | 80<rt> ->
    match srcExpr.E with
    | Load (_, _, addrExpr, _) ->
      let addrSize = TypeCheck.typeOf addrExpr
      !!ir (tmpB := AST.loadLE 16<rt> (addrExpr .+ numI32 8 addrSize))
      !!ir (tmpA := AST.loadLE 64<rt> addrExpr)
    | BinOp (_, _, { E = Var (_, r, _, _) }, { E = Var (_, _, _, _)}, _) ->
      let reg = Register.pseudoRegToReg (Register.ofRegID r)
      let struct (srcB, srcA) = getFPUPseudoRegVars ctxt reg
      !!ir (tmpB := srcB)
      !!ir (tmpA := srcA)
    | _ -> raise InvalidOperandException
  | _ -> Utils.impossible ()

let private fpuLoad insLen ctxt oprExpr =
  let ir = IRBuilder (64)
  let struct (st0b, st0a) = getFPUPseudoRegVars ctxt R.ST0
  let tmpB, tmpA = !*ir 16<rt>, !*ir 64<rt>
  !<ir insLen
  !?ir (castTo80Bit ctxt tmpB tmpA oprExpr)
  !?ir (pushFPUStack ctxt)
  !!ir (st0b := tmpB)
  !!ir (st0a := tmpA)
  !?ir (updateC1OnLoad ctxt)
  !>ir insLen

let fld ins insLen ctxt =
  let oprExpr = transOneOpr ins insLen ctxt
  fpuLoad insLen ctxt oprExpr

let private castFrom80Bit dstExpr dstSize srcB srcA ir =
  match dstSize with
  | 32<rt> ->
    let n16 = numI32 16 32<rt>
    let sign = (AST.zext 32<rt> srcB .& (numI32 0x8000 32<rt>)) << n16
    let biasDiff = numI32 0x3f80 32<rt>
    let exponent = AST.zext 32<rt> (srcB .& (numI32 0x7fff 16<rt>)) .- biasDiff
    let exponent = exponent << numI32 23 32<rt>
    let n40 = numI32 40 64<rt>
    let significand =
      AST.xtlo 32<rt> ((srcA .& numI64 0x7FFFFFFFFFFFFFFFL 64<rt>) >> n40)
    !!ir (dstExpr := (sign .| exponent .| significand))
  | 64<rt> ->
    let n48 = numI32 48 64<rt>
    let sign = (AST.zext 64<rt> srcB .& (numI32 0x8000 64<rt>)) << n48
    let biasDiff = numI32 0x3c00 64<rt>
    let exponent = AST.zext 64<rt> (srcB .& (numI32 0x7fff 16<rt>)) .- biasDiff
    let exponent = exponent << numI32 52 64<rt>
    let n11 = numI32 11 64<rt>
    let significand = (srcA .& numI64 0x7FFFFFFFFFFFFFFFL 64<rt>) >> n11
    !!ir (dstExpr := (sign .| exponent .| significand))
  | 80<rt> ->
    let struct (addrExpr, addrSize) = getLoadAddressExpr dstExpr
    !!ir (AST.store Endian.Little (addrExpr) srcA)
    !!ir (AST.store Endian.Little (addrExpr .+ numI32 8 addrSize) srcB)
  | _ -> Utils.impossible ()

let ffst (ins: InsInfo) insLen ctxt doPop =
  let ir = IRBuilder (32)
  let struct (st0b, st0a) = getFPUPseudoRegVars ctxt R.ST0
  !<ir insLen
  match ins.Operands with
  | OneOperand (OprReg r) ->
    let struct (dstB, dstA) = getFPUPseudoRegVars ctxt r
    !!ir (dstB := st0b)
    !!ir (dstA := st0a)
  | OneOperand (opr) ->
    let oprExpr = transOprToExpr ins insLen ctxt opr
    let oprSize = TypeCheck.typeOf oprExpr
    !?ir (castFrom80Bit oprExpr oprSize st0b st0a)
  | _ -> raise InvalidOperandException
  if doPop then !?ir (popFPUStack ctxt) else ()
  !?ir (updateC1OnStore ctxt)
  !>ir insLen

let fild ins insLen ctxt =
  let ir = IRBuilder (32)
  let struct (st0b, st0a) = getFPUPseudoRegVars ctxt R.ST0
  let oprExpr = transOneOpr ins insLen ctxt
  let tmpB, tmpA = !*ir 16<rt>, !*ir 64<rt>
  !<ir insLen
  !?ir
    (castTo80Bit ctxt tmpB tmpA (AST.cast CastKind.IntToFloat 64<rt> oprExpr))
  !?ir (pushFPUStack ctxt)
  !!ir (st0b := tmpB)
  !!ir (st0a := tmpA)
  !?ir (updateC1OnLoad ctxt)
  !>ir insLen

let fist ins insLen ctxt doPop =
  let ir = IRBuilder (32)
  let oprExpr = transOneOpr ins insLen ctxt
  let oprSize = TypeCheck.typeOf oprExpr
  let struct (st0b, st0a) = getFPUPseudoRegVars ctxt R.ST0
  let tmp0 = !*ir 64<rt>
  let rcField = !*ir 2<rt> (* Rounding Control *)
  let num2 = numI32 2 2<rt>
  let cst00 = AST.cast CastKind.FtoIRound oprSize tmp0
  let cst01 = AST.cast CastKind.FtoIFloor oprSize tmp0
  let cst10 = AST.cast CastKind.FtoICeil oprSize tmp0
  let cst11 = AST.cast CastKind.FtoITrunc oprSize tmp0
  !<ir insLen
  !?ir (castFrom80Bit tmp0 64<rt> st0b st0a)
  !!ir (rcField := AST.extract (!.ctxt R.FCW) 2<rt> 10)
  !!ir (tmp0 := AST.ite (rcField == AST.num0 2<rt>) cst00 cst11)
  !!ir (tmp0 := AST.ite (rcField == AST.num1 2<rt>) cst01 tmp0)
  !!ir (tmp0 := AST.ite (rcField == num2) cst10 tmp0)
  !!ir (oprExpr := tmp0)
  if doPop then !?ir (popFPUStack ctxt) else ()
  !?ir (updateC1OnStore ctxt)
  !>ir insLen

let fisttp ins insLen ctxt =
  let ir = IRBuilder (32)
  let oprExpr = transOneOpr ins insLen ctxt
  let oprSize = TypeCheck.typeOf oprExpr
  let tmp1 = !*ir 64<rt>
  let struct (st0b, st0a) = getFPUPseudoRegVars ctxt R.ST0
  !<ir insLen
  !?ir (castFrom80Bit tmp1 64<rt> st0b st0a)
  !!ir (oprExpr := AST.cast CastKind.FtoITrunc oprSize tmp1)
  !?ir (popFPUStack ctxt)
  !!ir (!.ctxt R.FSWC1 := AST.b0)
  !!ir (!.ctxt R.FSWC0 := undefC0)
  !!ir (!.ctxt R.FSWC2 := undefC2)
  !!ir (!.ctxt R.FSWC3 := undefC3)
  !>ir insLen

let private getTwoBCDDigits addrExpr addrSize startPos =
  let byteValue = AST.loadLE 8<rt> (addrExpr .+ numI32 startPos addrSize)
  let d1 = AST.extract byteValue 4<rt> 0 |> AST.sext 64<rt>
  let d2 = AST.extract byteValue 4<rt> 4 |> AST.sext 64<rt>
  struct (d1, d2)

let private bcdToInt intgr addrExpr addrSize ir =
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
  !!ir (intgr := d1)
  !!ir (intgr := intgr .+  d2 .* numI64 10L 64<rt>)
  !!ir (intgr := intgr .+  d3 .* numI64 100L 64<rt>)
  !!ir (intgr := intgr .+  d4 .* numI64 1000L 64<rt>)
  !!ir (intgr := intgr .+  d5 .* numI64 10000L 64<rt>)
  !!ir (intgr := intgr .+  d6 .* numI64 100000L 64<rt>)
  !!ir (intgr := intgr .+  d7 .* numI64 1000000L 64<rt>)
  !!ir (intgr := intgr .+  d8 .* numI64 10000000L 64<rt>)
  !!ir (intgr := intgr .+  d9 .* numI64 100000000L 64<rt>)
  !!ir (intgr := intgr .+ d10 .* numI64 1000000000L 64<rt>)
  !!ir (intgr := intgr .+ d11 .* numI64 10000000000L 64<rt>)
  !!ir (intgr := intgr .+ d12 .* numI64 100000000000L 64<rt>)
  !!ir (intgr := intgr .+ d13 .* numI64 1000000000000L 64<rt>)
  !!ir (intgr := intgr .+ d14 .* numI64 10000000000000L 64<rt>)
  !!ir (intgr := intgr .+ d15 .* numI64 100000000000000L 64<rt>)
  !!ir (intgr := intgr .+ d16 .* numI64 1000000000000000L 64<rt>)
  !!ir (intgr := intgr .+ d17 .* numI64 10000000000000000L 64<rt>)
  !!ir (intgr := intgr .+ d18 .* numI64 100000000000000000L 64<rt>)
  !!ir (AST.xthi 1<rt> intgr := signBit)

let fbld ins insLen ctxt =
  let ir = IRBuilder (64)
  let struct (st0b, st0a) = getFPUPseudoRegVars ctxt R.ST0
  let src = transOneOpr ins insLen ctxt
  let struct (addrExpr, addrSize) = getLoadAddressExpr src
  let intgr = !*ir 64<rt>
  let tmpB, tmpA = !*ir 16<rt>, !*ir 64<rt>
  !<ir insLen
  !?ir (bcdToInt intgr addrExpr addrSize)
  !?ir (castTo80Bit ctxt tmpB tmpA (AST.cast CastKind.IntToFloat 64<rt> intgr))
  !?ir (pushFPUStack ctxt)
  !!ir (st0b := tmpB)
  !!ir (st0a := tmpA)
  !?ir (updateC1OnLoad ctxt)
  !>ir insLen

let private storeTwoDigitBCD n10 addrExpr addrSize intgr pos ir =
  let d1 = AST.extract (intgr .% n10) 4<rt> 0
  let d2 = AST.extract ((intgr ./ n10) .% n10) 4<rt> 0
  let ds = AST.concat d2 d1
  !!ir (AST.store Endian.Little (addrExpr .+ numI32 pos addrSize) ds)

let private storeBCD addrExpr addrSize intgr ir =
  let n10 = numI32 10 64<rt>
  let n100 = numI32 100 64<rt>
  let sign = !*ir 1<rt>
  let signByte = (AST.zext 8<rt> sign) << numI32 7 8<rt>
  !!ir (sign := AST.xthi 1<rt> intgr)
  !?ir (storeTwoDigitBCD n10 addrExpr addrSize intgr 0)
  !!ir (intgr := intgr ./ n100)
  !?ir (storeTwoDigitBCD n10 addrExpr addrSize intgr 1)
  !!ir (intgr := intgr ./ n100)
  !?ir (storeTwoDigitBCD n10 addrExpr addrSize intgr 2)
  !!ir (intgr := intgr ./ n100)
  !?ir (storeTwoDigitBCD n10 addrExpr addrSize intgr 3)
  !!ir (intgr := intgr ./ n100)
  !?ir (storeTwoDigitBCD n10 addrExpr addrSize intgr 4)
  !!ir (intgr := intgr ./ n100)
  !?ir (storeTwoDigitBCD n10 addrExpr addrSize intgr 5)
  !!ir (intgr := intgr ./ n100)
  !?ir (storeTwoDigitBCD n10 addrExpr addrSize intgr 6)
  !!ir (intgr := intgr ./ n100)
  !?ir (storeTwoDigitBCD n10 addrExpr addrSize intgr 7)
  !!ir (intgr := intgr ./ n100)
  !?ir (storeTwoDigitBCD n10 addrExpr addrSize intgr 8)
  !!ir (AST.store Endian.Little (addrExpr .+ numI32 9 addrSize) signByte)

let fbstp ins insLen ctxt =
  let ir = IRBuilder (64)
  let dst = transOneOpr ins insLen ctxt
  let struct (addrExpr, addrSize) = getLoadAddressExpr dst
  let struct (st0b, st0a) = getFPUPseudoRegVars ctxt R.ST0
  let tmp = !*ir 64<rt>
  let intgr = !*ir 64<rt>
  !<ir insLen
  !?ir (castFrom80Bit tmp 64<rt> st0b st0a)
  !!ir (intgr := AST.cast CastKind.FtoIRound 64<rt> tmp)
  !?ir (storeBCD addrExpr addrSize intgr)
  !?ir (popFPUStack ctxt)
  !?ir (updateC1OnStore ctxt)
  !>ir insLen

let fxch (ins: InsInfo) insLen ctxt =
  let ir = IRBuilder (16)
  let struct (st0b, st0a) = getFPUPseudoRegVars ctxt R.ST0
  let tmpB, tmpA = !*ir 16<rt>, !*ir 64<rt>
  !<ir insLen
  !!ir (tmpB := st0b)
  !!ir (tmpA := st0a)
  let struct (srcB, srcA) =
    match ins.Operands with
    | OneOperand (OprReg reg) -> getFPUPseudoRegVars ctxt reg
    | NoOperand -> getFPUPseudoRegVars ctxt R.ST1
    | _ -> raise InvalidOperandException
  !!ir (st0b := srcB)
  !!ir (st0a := srcA)
  !!ir (srcB := tmpB)
  !!ir (srcA := tmpA)
  !!ir (!.ctxt R.FSWC1 := AST.b0)
  !?ir (cflagsUndefined023 ctxt)
  !>ir insLen

let private fcmov (ins: InsInfo) insLen ctxt cond =
  let ir = IRBuilder (8)
  let srcReg =
    match ins.Operands with
    | TwoOperands (_, OprReg reg) -> reg
    | _ -> raise InvalidOperandException
  let struct (srcB, srcA) = getFPUPseudoRegVars ctxt srcReg
  let struct (dstB, dstA) = getFPUPseudoRegVars ctxt R.ST0
  !<ir insLen
  !!ir (dstB := AST.ite cond srcB dstB)
  !!ir (dstA := AST.ite cond srcA dstA)
  !!ir (!.ctxt R.FSWC0 := undefC0)
  !!ir (!.ctxt R.FSWC2 := undefC2)
  !!ir (!.ctxt R.FSWC3 := undefC3)
  !>ir insLen

let fcmove ins insLen ctxt =
  !.ctxt R.ZF |> fcmov ins insLen ctxt

let fcmovne ins insLen ctxt =
  !.ctxt R.ZF |> AST.not |> fcmov ins insLen ctxt

let fcmovb ins insLen ctxt =
  !.ctxt R.CF |> fcmov ins insLen ctxt

let fcmovbe ins insLen ctxt =
  (!.ctxt R.CF .| !.ctxt R.ZF) |> fcmov ins insLen ctxt

let fcmovnb ins insLen ctxt =
  !.ctxt R.CF |> AST.not |> fcmov ins insLen ctxt

let fcmovnbe ins insLen ctxt =
  let cond1 = !.ctxt R.CF |> AST.not
  let cond2 = !.ctxt R.ZF |> AST.not
  cond1 .& cond2 |> fcmov ins insLen ctxt

let fcmovu ins insLen ctxt =
  !.ctxt R.PF |> fcmov ins insLen ctxt

let fcmovnu ins insLen ctxt =
  !.ctxt R.PF |> AST.not |> fcmov ins insLen ctxt

let private fpuFBinOp (ins: InsInfo) insLen ctxt binOp doPop leftToRight =
  let ir = IRBuilder (64)
  !<ir insLen
  match ins.Operands with
  | NoOperand ->
    let struct (st0b, st0a) = getFPUPseudoRegVars ctxt R.ST0
    let struct (st1b, st1a) = getFPUPseudoRegVars ctxt R.ST1
    let struct (tmp0, tmp1) = tmpVars2 ir 64<rt>
    let res = !*ir 64<rt>
    !?ir (castFrom80Bit tmp0 64<rt> st0b st0a)
    !?ir (castFrom80Bit tmp1 64<rt> st1b st1a)
    if leftToRight then !!ir (res := binOp tmp0 tmp1)
    else !!ir (res := binOp tmp1 tmp0)
    !?ir (castTo80Bit ctxt st1b st1a res)
  | OneOperand opr ->
    let oprExpr = transOneOpr ins insLen ctxt
    let oprSize = TypeCheck.typeOf oprExpr
    let struct (st0b, st0a) = getFPUPseudoRegVars ctxt R.ST0
    let struct (tmp0, tmp1) = tmpVars2 ir oprSize
    let res = !*ir oprSize
    !?ir (castFrom80Bit tmp0 oprSize st0b st0a)
    !!ir (tmp1 := oprExpr)
    if leftToRight then !!ir (res := binOp tmp0 tmp1)
    else !!ir (res := binOp tmp1 tmp0)
    !?ir (castTo80Bit ctxt st0b st0a res)
  | TwoOperands (OprReg reg0, OprReg reg1) ->
    let struct (r0B, r0A) = getFPUPseudoRegVars ctxt reg0
    let struct (r1B, r1A) = getFPUPseudoRegVars ctxt reg1
    let struct (tmp0, tmp1) = tmpVars2 ir 64<rt>
    let res = !*ir 64<rt>
    !?ir (castFrom80Bit tmp0 64<rt> r0B r0A)
    !?ir (castFrom80Bit tmp1 64<rt> r1B r1A)
    if leftToRight then !!ir (res := binOp tmp0 tmp1)
    else !!ir (res := binOp tmp1 tmp0)
    !?ir (castTo80Bit ctxt r0B r0A res)
  | _ -> raise InvalidOperandException
  if doPop then !?ir (popFPUStack ctxt) else ()
  !?ir (updateC1OnStore ctxt)
  !>ir insLen

let private fpuIntOp ins insLen ctxt binOp leftToRight =
  let ir = IRBuilder (8)
  let struct (st0b, st0a) = getFPUPseudoRegVars ctxt R.ST0
  let oprExpr = transOneOpr ins insLen ctxt
  let struct (tmp, dst) = tmpVars2 ir 64<rt>
  let res = !*ir 64<rt>
  !<ir insLen
  !!ir (tmp := AST.cast CastKind.IntToFloat 64<rt> oprExpr)
  !?ir (castFrom80Bit dst 64<rt> st0b st0a)
  if leftToRight then !!ir (res := binOp dst tmp)
  else !!ir (res := binOp tmp dst)
  !?ir (castTo80Bit ctxt st0b st0a res)
  !>ir insLen

let fpuadd ins insLen ctxt doPop =
  fpuFBinOp ins insLen ctxt AST.fadd doPop true

let fiadd ins insLen ctxt =
  fpuIntOp ins insLen ctxt AST.fadd true

let fpusub ins insLen ctxt doPop =
  fpuFBinOp ins insLen ctxt AST.fsub doPop true

let fisub ins insLen ctxt =
  fpuIntOp ins insLen ctxt AST.fsub true

let fsubr ins insLen ctxt doPop =
  fpuFBinOp ins insLen ctxt AST.fsub doPop false

let fisubr ins insLen ctxt =
  fpuIntOp ins insLen ctxt AST.fsub false

let fpumul ins insLen ctxt doPop =
  fpuFBinOp ins insLen ctxt AST.fmul doPop true

let fimul ins insLen ctxt =
  fpuIntOp ins insLen ctxt AST.fmul true

let fpudiv ins insLen ctxt doPop =
  fpuFBinOp ins insLen ctxt AST.fdiv doPop true

let fidiv ins insLen ctxt =
  fpuIntOp ins insLen ctxt AST.fdiv true

let fdivr ins insLen ctxt doPop =
  fpuFBinOp ins insLen ctxt AST.fdiv doPop false

let fidivr ins insLen ctxt =
  fpuIntOp ins insLen ctxt AST.fdiv false

let inline private castToF64 intexp =
  AST.cast CastKind.IntToFloat 64<rt> intexp

let fprem _ins insLen ctxt round =
  let ir = IRBuilder (32)
  let struct (st0b, st0a) = getFPUPseudoRegVars ctxt R.ST0
  let struct (st1b, st1a) = getFPUPseudoRegVars ctxt R.ST1
  let caster = if round then CastKind.FtoIRound else CastKind.FtoITrunc
  let lblLT64 = ir.NewSymbol "ExpDiffInRange"
  let lblGE64 = ir.NewSymbol "ExpDiffOutOfRange"
  let lblExit = ir.NewSymbol "Exit"
  let struct (tmp0, tmp1) = tmpVars2 ir 64<rt>
  let expDiff = !*ir 16<rt>
  let expMask = numI32 0x7fff 16<rt>
  let n64 = numI32 64 16<rt>
  let n2 = numI32 2 64<rt>
  let struct (divres, intres, tmpres, divider) = tmpVars4 ir 64<rt>
  !<ir insLen
  !?ir (castFrom80Bit tmp0 64<rt> st0b st0a)
  !?ir (castFrom80Bit tmp1 64<rt> st1b st1a)
  !!ir (expDiff := (st0b .& expMask) .- (st1b .& expMask))
  !!ir (AST.cjmp (AST.lt expDiff n64) (AST.name lblLT64) (AST.name lblGE64))
  !!ir (AST.lmark lblLT64) (* D < 64 *)
  !!ir (divres := AST.fdiv tmp0 tmp1)
  !!ir (intres := AST.cast caster 64<rt> divres)
  !!ir (tmpres := AST.fsub tmp0 (AST.fmul tmp1 (castToF64 intres)))
  !?ir (castTo80Bit ctxt st0b st0a tmpres)
  !!ir (!.ctxt R.FSWC2 := AST.b0)
  !!ir (!.ctxt R.FSWC1 := AST.xtlo 1<rt> intres)
  !!ir (!.ctxt R.FSWC3 := AST.extract intres 1<rt> 1)
  !!ir (!.ctxt R.FSWC0 := AST.extract intres 1<rt> 2)
  !!ir (AST.jmp (AST.name lblExit))
  !!ir (AST.lmark lblGE64) (* ELSE *)
  !!ir (!.ctxt R.FSWC2 := AST.b1)
  !!ir (tmpres := AST.fsub (castToF64 expDiff) (castToF64 (numI32 63 64<rt>)))
  !!ir (divider := AST.fpow n2 tmpres)
  !!ir (divres := AST.fdiv (AST.fdiv tmp0 tmp1) divider)
  !!ir (intres := AST.cast CastKind.FtoITrunc 64<rt> divres)
  !!ir (tmpres :=
    AST.fsub tmp0 (AST.fmul tmp1 (AST.fmul (castToF64 intres) divider)))
  !?ir (castTo80Bit ctxt st0b st0a tmpres)
  !!ir (AST.lmark lblExit)
  !>ir insLen

let fabs _ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (st0b, _st0a) = getFPUPseudoRegVars ctxt R.ST0
  !<ir insLen
  !!ir (AST.extract st0b 1<rt> 15 := AST.b0)
  !!ir (!.ctxt R.FSWC1 := AST.b0)
  !!ir (!.ctxt R.FSWC0 := undefC0)
  !!ir (!.ctxt R.FSWC2 := undefC2)
  !!ir (!.ctxt R.FSWC3 := undefC3)
  !>ir insLen

let fchs _ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (st0b, _st0a) = getFPUPseudoRegVars ctxt R.ST0
  let tmp = !*ir 1<rt>
  !<ir insLen
  !!ir (tmp := AST.xthi 1<rt> st0b)
  !!ir (AST.xthi 1<rt> st0b := AST.not tmp)
  !!ir (!.ctxt R.FSWC1 := AST.b0)
  !!ir (!.ctxt R.FSWC0 := undefC0)
  !!ir (!.ctxt R.FSWC2 := undefC2)
  !!ir (!.ctxt R.FSWC3 := undefC3)
  !>ir insLen

let frndint _ins insLen ctxt =
  let ir = IRBuilder (32)
  let struct (st0b, st0a) = getFPUPseudoRegVars ctxt R.ST0
  let tmp0 = !*ir 64<rt>
  let rcField = !*ir 2<rt> (* Rounding Control *)
  let cst00 = AST.cast CastKind.FtoIRound 64<rt> tmp0
  let cst01 = AST.cast CastKind.FtoIFloor 64<rt> tmp0
  let cst10 = AST.cast CastKind.FtoICeil 64<rt> tmp0
  let cst11 = AST.cast CastKind.FtoITrunc 64<rt> tmp0
  let num2 = numI32 2 2<rt>
  !<ir insLen
  !?ir (castFrom80Bit tmp0 64<rt> st0b st0a)
  !!ir (rcField := AST.extract (!.ctxt R.FCW) 2<rt> 10)
  !!ir (tmp0 := AST.ite (rcField == AST.num0 2<rt>) cst00 cst11)
  !!ir (tmp0 := AST.ite (rcField == AST.num1 2<rt>) cst01 tmp0)
  !!ir (tmp0 := AST.ite (rcField == num2) cst10 tmp0)
  !?ir (castTo80Bit ctxt st0b st0a (castToF64 tmp0))
  !?ir (updateC1OnStore ctxt)
  !>ir insLen

let fscale _ins insLen ctxt =
  let ir = IRBuilder (16)
  let struct (tmp0, tmp1, tmp2) = tmpVars3 ir 64<rt>
  let struct (st0b, st0a) = getFPUPseudoRegVars ctxt R.ST0
  let struct (st1b, st1a) = getFPUPseudoRegVars ctxt R.ST1
  !<ir insLen
  !?ir (castFrom80Bit tmp0 64<rt> st0b st0a)
  !?ir (castFrom80Bit tmp1 64<rt> st1b st1a)
  !!ir (tmp2 := numI32 1 64<rt> << (AST.cast CastKind.FtoITrunc 64<rt> tmp1))
  !?ir (castTo80Bit ctxt st0b st0a (AST.fmul tmp1 (castToF64 tmp2)))
  !?ir (updateC1OnStore ctxt)
  !>ir insLen

let fsqrt _ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (st0b, st0a) = getFPUPseudoRegVars ctxt R.ST0
  let tmp0 = !*ir 64<rt>
  !<ir insLen
  !?ir (castFrom80Bit tmp0 64<rt> st0b st0a)
  !?ir (castTo80Bit ctxt st0b st0a (AST.unop UnOpType.FSQRT tmp0))
  !?ir (updateC1OnStore ctxt)
  !>ir insLen

let fxtract _ins insLen ctxt =
  let ir = IRBuilder (64)
  let struct (st0b, st0a) = getFPUPseudoRegVars ctxt R.ST0
  let n3fff = numI32 0x3FFF 16<rt>
  let tmpB, tmpA = !*ir 16<rt>, !*ir 64<rt>
  let tmpF = !*ir 64<rt>
  !<ir insLen
  !!ir (tmpB := (st0b .& numI32 0x8000 16<rt>) .| n3fff)
  !!ir (tmpA := st0a)
  !!ir (tmpF := castToF64 ((st0b .& numI32 0x7fff 16<rt>) .- n3fff))
  !?ir (pushFPUStack ctxt)
  !?ir (castTo80Bit ctxt st0b st0a tmpF)
  !?ir (updateC1OnStore ctxt)
  !>ir insLen

let private prepareTwoOprsForComparison (ins: InsInfo) insLen ctxt ir =
  let struct (tmp0, tmp1) = tmpVars2 ir 64<rt>
  match ins.Operands with
  | NoOperand ->
    let struct (st0b, st0a) = getFPUPseudoRegVars ctxt R.ST0
    let struct (st1b, st1a) = getFPUPseudoRegVars ctxt R.ST1
    !?ir (castFrom80Bit tmp0 64<rt> st0b st0a)
    !?ir (castFrom80Bit tmp1 64<rt> st1b st1a)
  | OneOperand (OprReg r) ->
    let struct (st0b, st0a) = getFPUPseudoRegVars ctxt R.ST0
    let struct (st1b, st1a) = getFPUPseudoRegVars ctxt r
    !?ir (castFrom80Bit tmp0 64<rt> st0b st0a)
    !?ir (castFrom80Bit tmp1 64<rt> st1b st1a)
  | OneOperand (opr) ->
    let struct (st0b, st0a) = getFPUPseudoRegVars ctxt R.ST0
    let oprExpr = transOprToExpr ins insLen ctxt opr
    !?ir (castFrom80Bit tmp0 64<rt> st0b st0a)
    !!ir (tmp1 := AST.cast CastKind.FloatCast 64<rt> oprExpr)
  | TwoOperands (OprReg r1, OprReg r2) ->
    let struct (st0b, st0a) = getFPUPseudoRegVars ctxt r1
    let struct (st1b, st1a) = getFPUPseudoRegVars ctxt r2
    !?ir (castFrom80Bit tmp0 64<rt> st0b st0a)
    !?ir (castFrom80Bit tmp1 64<rt> st1b st1a)
  | _ -> raise InvalidOperandException
  struct (tmp0, tmp1)

let fcom (ins: InsInfo) insLen ctxt nPop unordered =
  let ir = IRBuilder (64)
  let c0 = !.ctxt R.FSWC0
  let c2 = !.ctxt R.FSWC2
  let c3 = !.ctxt R.FSWC3
  !<ir insLen
  let struct (tmp0, tmp1) = prepareTwoOprsForComparison ins insLen ctxt ir
  !!ir (c0 := AST.flt tmp0 tmp1)
  !!ir (c2 := AST.b0)
  !!ir (c3 := (tmp0 == tmp1))
  !!ir (!.ctxt R.FSWC1 := AST.b0)
  if nPop > 0 then !?ir (popFPUStack ctxt) else ()
  if nPop = 2 then !?ir (popFPUStack ctxt) else ()
  !>ir insLen

let ficom ins insLen ctxt doPop =
  let ir = IRBuilder (32)
  let oprExpr = transOneOpr ins insLen ctxt
  let struct (st0b, st0a) = getFPUPseudoRegVars ctxt R.ST0
  let struct (tmp0, tmp1) = tmpVars2 ir 64<rt>
  !<ir insLen
  !?ir (castFrom80Bit tmp0 64<rt> st0b st0a)
  !!ir (tmp1 := AST.cast CastKind.IntToFloat 64<rt> oprExpr)
  !!ir (!.ctxt R.FSWC0 := AST.flt tmp0 tmp1)
  !!ir (!.ctxt R.FSWC2 := AST.b0)
  !!ir (!.ctxt R.FSWC3 := tmp0 == tmp1)
  !!ir (!.ctxt R.FSWC1 := AST.b0)
  if doPop then !?ir (popFPUStack ctxt) else ()
  !>ir insLen

let fcomi ins insLen ctxt doPop =
  let ir = IRBuilder (64)
  let zf = !.ctxt R.ZF
  let pf = !.ctxt R.PF
  let cf = !.ctxt R.CF
  !<ir insLen
  let struct (tmp0, tmp1) = prepareTwoOprsForComparison ins insLen ctxt ir
  !!ir (cf := AST.flt tmp0 tmp1)
  !!ir (pf := AST.b0)
  !!ir (zf := (tmp0 == tmp1))
  !!ir (!.ctxt R.FSWC1 := AST.b0)
  if doPop then !?ir (popFPUStack ctxt) else ()
  !>ir insLen

let ftst _ins insLen ctxt =
  let ir = IRBuilder (16)
  let struct (st0b, st0a) = getFPUPseudoRegVars ctxt R.ST0
  let num0V = AST.num0 64<rt>
  let c0 = !.ctxt R.FSWC0
  let c2 = !.ctxt R.FSWC2
  let c3 = !.ctxt R.FSWC3
  let tmp = !*ir 64<rt>
  !<ir insLen
  !?ir (castFrom80Bit tmp 64<rt> st0b st0a)
  !!ir (c0 := AST.flt tmp num0V)
  !!ir (c2 := AST.b0)
  !!ir (c3 := tmp == num0V)
  !!ir (!.ctxt R.FSWC1 := AST.b0)
  !>ir insLen

let fxam _ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (st0b, st0a) = getFPUPseudoRegVars ctxt R.ST0
  let n7fff = numI32 0x7fff 16<rt>
  let exponent = st0b .& n7fff
  let nanCond = (exponent == n7fff) .& (AST.xtlo 62<rt> st0a != AST.num0 62<rt>)
  let c3Cond1 = (exponent == AST.num0 16<rt>)
  let isAllZero = (st0a == AST.num0 64<rt>) .& (st0b == AST.num0 16<rt>)
  let c2Cond0 = AST.not (isAllZero .| nanCond)
  let c0Cond1 = (exponent == n7fff)
  !<ir insLen
  !!ir (!.ctxt R.FSWC1 := AST.xthi 1<rt> st0b)
  !!ir (!.ctxt R.FSWC3 := c3Cond1)
  !!ir (!.ctxt R.FSWC2 := c2Cond0)
  !!ir (!.ctxt R.FSWC0 := c0Cond1)
  !>ir insLen

let private checkForTrigFunction unsigned lin lout ir =
  let maxLimit = numI64 (1L <<< 63) 64<rt>
  let maxFloat = AST.cast CastKind.IntToFloat 64<rt> maxLimit
  !!ir (AST.cjmp (AST.flt unsigned maxFloat) (AST.name lin) (AST.name lout))

let private ftrig _ins insLen ctxt trigFunc =
  let ir = IRBuilder (32)
  let struct (st0b, st0a) = getFPUPseudoRegVars ctxt R.ST0
  let n7fff = numI32 0x7fff 16<rt>
  let c0 = !.ctxt R.FSWC0
  let c1 = !.ctxt R.FSWC1
  let c2 = !.ctxt R.FSWC2
  let c3 = !.ctxt R.FSWC3
  let lin = ir.NewSymbol "IsInRange"
  let lout = ir.NewSymbol "IsOutOfRange"
  let lexit = ir.NewSymbol "Exit"
  let struct (unsigned, signed, tmp) = tmpVars3 ir 64<rt>
  !<ir insLen
  !?ir (castFrom80Bit unsigned 64<rt> (st0b .& n7fff) st0a)
  !?ir (castFrom80Bit signed 64<rt> st0b st0a)
  !?ir (checkForTrigFunction unsigned lin lout)
  !!ir (AST.lmark lin)
  !!ir (tmp := trigFunc signed)
  !?ir (castTo80Bit ctxt st0b st0a tmp)
  !!ir (c2 := AST.b0)
  !!ir (AST.jmp (AST.name lexit))
  !!ir (AST.lmark lout)
  !!ir (c2 := AST.b1)
  !!ir (AST.lmark lexit)
  !!ir (c0 := undefC0)
  !!ir (c3 := undefC3)
  !!ir (c1:= AST.b0)
  !>ir insLen

let fsin ins insLen ctxt =
  ftrig ins insLen ctxt AST.fsin

let fcos ins insLen ctxt =
  ftrig ins insLen ctxt AST.fcos

let fsincos _ins insLen ctxt =
  let ir = IRBuilder (64)
  let struct (st0b, st0a) = getFPUPseudoRegVars ctxt R.ST0
  let n7fff = numI32 0x7fff 16<rt>
  let c0 = !.ctxt R.FSWC0
  let c2 = !.ctxt R.FSWC2
  let c3 = !.ctxt R.FSWC3
  let lin = ir.NewSymbol "IsInRange"
  let lout = ir.NewSymbol "IsOutOfRange"
  let lexit = ir.NewSymbol "Exit"
  let struct (unsigned, signed, tmpsin, tmpcos) = tmpVars4 ir 64<rt>
  !<ir insLen
  !?ir (castFrom80Bit unsigned 64<rt> (st0b .& n7fff) st0a)
  !?ir (castFrom80Bit signed 64<rt> st0b st0a)
  !?ir (checkForTrigFunction unsigned lin lout)
  !!ir (AST.lmark lin)
  !!ir (tmpcos := AST.fcos signed)
  !!ir (tmpsin := AST.fsin signed)
  !?ir (castTo80Bit ctxt st0b st0a tmpsin)
  !?ir (pushFPUStack ctxt)
  !?ir (castTo80Bit ctxt st0b st0a tmpcos)
  !!ir (c2 := AST.b0)
  !!ir (AST.jmp (AST.name lexit))
  !!ir (AST.lmark lout)
  !!ir (c2 := AST.b1)
  !!ir (AST.lmark lexit)
  !!ir (c0 := undefC0)
  !!ir (c3 := undefC3)
  !?ir (updateC1OnLoad ctxt)
  !>ir insLen

let fptan _ins insLen ctxt =
  let ir = IRBuilder (64)
  let struct (st0b, st0a) = getFPUPseudoRegVars ctxt R.ST0
  let n7fff = numI32 0x7fff 16<rt>
  let c0 = !.ctxt R.FSWC0
  let c2 = !.ctxt R.FSWC2
  let c3 = !.ctxt R.FSWC3
  let lin = ir.NewSymbol "IsInRange"
  let lout = ir.NewSymbol "IsOutOfRange"
  let lexit = ir.NewSymbol "Exit"
  let fone = numI64 0x3ff0000000000000L 64<rt> (* 1.0 *)
  let struct (unsigned, signed, tmp) = tmpVars3 ir 64<rt>
  !<ir insLen
  !?ir (castFrom80Bit unsigned 64<rt> (st0b .& n7fff) st0a)
  !?ir (castFrom80Bit signed 64<rt> st0b st0a)
  !?ir (checkForTrigFunction unsigned lin lout)
  !!ir (AST.lmark lin)
  !!ir (tmp := AST.ftan signed)
  !?ir (castTo80Bit ctxt st0b st0a tmp)
  !!ir (c2 := AST.b0)
  !?ir (pushFPUStack ctxt)
  !?ir (castTo80Bit ctxt st0b st0a fone)
  !!ir (c2 := AST.b0)
  !!ir (AST.jmp (AST.name lexit))
  !!ir (AST.lmark lout)
  !!ir (c2 := AST.b1)
  !!ir (AST.lmark lexit)
  !!ir (c0 := undefC0)
  !!ir (c3 := undefC3)
  !?ir (updateC1OnLoad ctxt)
  !>ir insLen

let fpatan _ins insLen ctxt =
  let ir = IRBuilder (16)
  let struct (st0b, st0a) = getFPUPseudoRegVars ctxt R.ST0
  let struct (st1b, st1a) = getFPUPseudoRegVars ctxt R.ST1
  let struct (tmp0, tmp1, res) = tmpVars3 ir 64<rt>
  !<ir insLen
  !?ir (castFrom80Bit tmp0 64<rt> st0b st0a)
  !?ir (castFrom80Bit tmp1 64<rt> st1b st1a)
  !!ir (res := AST.fatan (AST.fdiv tmp0 tmp1))
  !?ir (castTo80Bit ctxt st1b st1a res)
  !?ir (popFPUStack ctxt)
  !?ir (updateC1OnStore ctxt)
  !?ir (cflagsUndefined023 ctxt)
  !>ir insLen

let f2xm1 _isn insLen ctxt =
  let ir = IRBuilder (16)
  let struct (st0b, st0a) = getFPUPseudoRegVars ctxt R.ST0
  let f1 = numI32 1 64<rt> |> castToF64
  let f2 = numI32 2 64<rt> |> castToF64
  let c1 = !.ctxt R.FSWC1
  let struct (tmp, res) = tmpVars2 ir 64<rt>
  !<ir insLen
  !?ir (castFrom80Bit tmp 64<rt> st0b st0a)
  !!ir (res := AST.fsub (AST.fpow f2 tmp) f1)
  !?ir (castTo80Bit ctxt st0b st0a res)
  !!ir (c1 := AST.b0)
  !?ir (cflagsUndefined023 ctxt)
  !>ir insLen

let fyl2x _ins insLen ctxt =
  let ir = IRBuilder (64)
  let struct (st0b, st0a) = getFPUPseudoRegVars ctxt R.ST0
  let struct (st1b, st1a) = getFPUPseudoRegVars ctxt R.ST1
  let struct (tmp0, tmp1, res) = tmpVars3 ir 64<rt>
  let f2 = numI32 2 64<rt> |> castToF64
  !<ir insLen
  !?ir (castFrom80Bit tmp0 64<rt> st0b st0a)
  !?ir (castFrom80Bit tmp1 64<rt> st1b st1a)
  !!ir (res := AST.fmul tmp1 (AST.flog f2 tmp0))
  !?ir (castTo80Bit ctxt st1b st1a res)
  !?ir (popFPUStack ctxt)
  !?ir (updateC1OnStore ctxt)
  !?ir (cflagsUndefined023 ctxt)
  !>ir insLen

let fyl2xp1 _ins insLen ctxt =
  let ir = IRBuilder (64)
  let struct (st0b, st0a) = getFPUPseudoRegVars ctxt R.ST0
  let struct (st1b, st1a) = getFPUPseudoRegVars ctxt R.ST1
  let struct (tmp0, tmp1, res) = tmpVars3 ir 64<rt>
  let f1 = numI32 1 64<rt> |> castToF64
  let f2 = numI32 2 64<rt> |> castToF64
  !<ir insLen
  !?ir (castFrom80Bit tmp0 64<rt> st0b st0a)
  !?ir (castFrom80Bit tmp1 64<rt> st1b st1a)
  !!ir (res := AST.fmul tmp1 (AST.flog f2 (AST.fadd tmp0 f1)))
  !?ir (castTo80Bit ctxt st1b st1a res)
  !?ir (popFPUStack ctxt)
  !?ir (updateC1OnStore ctxt)
  !?ir (cflagsUndefined023 ctxt)
  !>ir insLen

let fld1 _ins insLen ctxt =
  let oprExpr = numU64 0x3FF0000000000000UL 64<rt>
  fpuLoad insLen ctxt oprExpr

let fldz _ins insLen ctxt =
  let oprExpr = AST.num0 64<rt>
  fpuLoad insLen ctxt oprExpr

let fldpi _ins insLen ctxt =
  let oprExpr = numU64 4614256656552045848UL 64<rt>
  fpuLoad insLen ctxt oprExpr

let fldl2e _ins insLen ctxt =
  let oprExpr = numU64 4599094494223104509UL 64<rt>
  fpuLoad insLen ctxt oprExpr

let fldln2 _ins insLen ctxt =
  let oprExpr = numU64 4604418534313441775UL 64<rt>
  fpuLoad insLen ctxt oprExpr

let fldl2t _ins insLen ctxt =
  let oprExpr = numU64 4614662735865160561UL 64<rt>
  fpuLoad insLen ctxt oprExpr

let fldlg2 _ins insLen ctxt =
  let oprExpr = numU64 4599094494223104511UL 64<rt>
  fpuLoad insLen ctxt oprExpr

let fincstp _ins insLen ctxt =
  let ir = IRBuilder (16)
  let top = !.ctxt R.FTOP
  !<ir insLen
  (* TOP in B2R2 is really a counter, so we decrement TOP here (same as pop). *)
  !!ir (extractDstAssign top (top .- AST.num1 8<rt>))
  !!ir (!.ctxt R.FSWC1 := AST.b0)
  !!ir (!.ctxt R.FSWC0 := undefC0)
  !!ir (!.ctxt R.FSWC2 := undefC2)
  !!ir (!.ctxt R.FSWC3 := undefC3)
  !>ir insLen

let fdecstp _ins insLen ctxt =
  let ir = IRBuilder (8)
  let top = !.ctxt R.FTOP
  !<ir insLen
  (* TOP in B2R2 is really a counter, so we increment TOP here. *)
  !!ir (extractDstAssign top (top .+ AST.num1 8<rt>))
  !!ir (!.ctxt R.FSWC1 := AST.b0)
  !!ir (!.ctxt R.FSWC0 := undefC0)
  !!ir (!.ctxt R.FSWC2 := undefC2)
  !!ir (!.ctxt R.FSWC3 := undefC3)
  !>ir insLen

let ffree (ins: InsInfo) insLen ctxt =
  let ir = IRBuilder (8)
  let top = !.ctxt R.FTOP
  let tagWord = !.ctxt R.FTW
  let struct (top16, shifter, tagValue) = tmpVars3 ir 16<rt>
  let value3 = numI32 3 16<rt>
  let offset =
    match ins.Operands with
    | OneOperand (OprReg R.ST0) -> numI32 0 16<rt>
    | OneOperand (OprReg R.ST1) -> numI32 1 16<rt>
    | OneOperand (OprReg R.ST2) -> numI32 2 16<rt>
    | OneOperand (OprReg R.ST3) -> numI32 3 16<rt>
    | OneOperand (OprReg R.ST4) -> numI32 4 16<rt>
    | OneOperand (OprReg R.ST5) -> numI32 5 16<rt>
    | OneOperand (OprReg R.ST6) -> numI32 6 16<rt>
    | OneOperand (OprReg R.ST7) -> numI32 7 16<rt>
    | _ -> raise InvalidOperandException
  !<ir insLen
  !!ir (top16 := AST.cast CastKind.ZeroExt 16<rt> top)
  !!ir (top16 := top16 .+ offset)
  !!ir (shifter := (numI32 2 16<rt>) .* top16)
  !!ir (tagValue := (value3 << shifter))
  !!ir (tagWord := tagWord .| tagValue)
  !>ir insLen

(* FIXME: check all unmasked pending floating point exceptions. *)
let private checkFPUExceptions ctxt ir = ()

let private clearFPU ctxt ir =
  let cw = numI32 895 16<rt>
  let tw = BitVector.maxUInt16 |> AST.num
  !!ir (!.ctxt R.FCW := cw)
  !!ir (!.ctxt R.FSW := AST.num0 16<rt>)
  !!ir (!.ctxt R.FTW := tw)

let finit _ins insLen ctxt =
  let ir = IRBuilder (32)
  !<ir insLen
  checkFPUExceptions ctxt ir
  clearFPU ctxt ir
  !>ir insLen

let fninit _ins insLen ctxt =
  let ir = IRBuilder (16)
  !<ir insLen
  clearFPU ctxt ir
  !>ir insLen

let fclex _ins insLen ctxt =
  let ir = IRBuilder (8)
  let stsWrd = !.ctxt R.FSW
  !<ir insLen
  !!ir (AST.xtlo 7<rt> stsWrd := AST.num0 7<rt>)
  !!ir (AST.xthi 1<rt> stsWrd := AST.b0)
  !!ir (!.ctxt R.FSWC0 := undefC0)
  !!ir (!.ctxt R.FSWC1 := undefC1)
  !!ir (!.ctxt R.FSWC2 := undefC2)
  !!ir (!.ctxt R.FSWC3 := undefC3)
  !>ir insLen

let fstcw ins insLen ctxt =
  let ir = IRBuilder (16)
  let oprExpr = transOneOpr ins insLen ctxt
  !<ir insLen
  checkFPUExceptions ctxt ir
  !!ir (oprExpr := !.ctxt R.FCW)
  allCFlagsUndefined ctxt ir
  !>ir insLen

let fnstcw ins insLen ctxt =
  let ir = IRBuilder (8)
  let oprExpr = transOneOpr ins insLen ctxt
  !<ir insLen
  !!ir (oprExpr := !.ctxt R.FCW)
  allCFlagsUndefined ctxt ir
  !>ir insLen

let fldcw ins insLen ctxt =
  let ir = IRBuilder (8)
  let oprExpr = transOneOpr ins insLen ctxt
  !<ir insLen
  !!ir (!.ctxt R.FCW := oprExpr)
  !!ir (!.ctxt R.FSWC0 := undefC0)
  !!ir (!.ctxt R.FSWC1 := undefC1)
  !!ir (!.ctxt R.FSWC2 := undefC2)
  !!ir (!.ctxt R.FSWC3 := undefC3)
  !>ir insLen

let private m14fstenv dstAddr addrSize ctxt ir =
  let fiplo = AST.xtlo 16<rt> (!.ctxt R.FIP)
  let fdplo = AST.xtlo 16<rt> (!.ctxt R.FDP)
  !!ir (AST.store Endian.Little (dstAddr) (!.ctxt R.FCW))
  !!ir (AST.store Endian.Little (dstAddr .+ numI32 2 addrSize) (!.ctxt R.FSW))
  !!ir (AST.store Endian.Little (dstAddr .+ numI32 4 addrSize) (!.ctxt R.FTW))
  !!ir (AST.store Endian.Little (dstAddr .+ numI32 6 addrSize) fiplo)
  !!ir (AST.store Endian.Little (dstAddr .+ numI32 8 addrSize) (!.ctxt R.FCS))
  !!ir (AST.store Endian.Little (dstAddr .+ numI32 10 addrSize) fdplo)
  !!ir (AST.store Endian.Little (dstAddr .+ numI32 12 addrSize) (!.ctxt R.FDS))

let private m28fstenv dstAddr addrSize ctxt ir =
  let n0 = numI32 0 16<rt>
  !!ir (AST.store Endian.Little (dstAddr) (!.ctxt R.FCW))
  !!ir (AST.store Endian.Little (dstAddr .+ numI32 2 addrSize) n0)
  !!ir (AST.store Endian.Little (dstAddr .+ numI32 4 addrSize) (!.ctxt R.FSW))
  !!ir (AST.store Endian.Little (dstAddr .+ numI32 6 addrSize) n0)
  !!ir (AST.store Endian.Little (dstAddr .+ numI32 8 addrSize) (!.ctxt R.FTW))
  !!ir (AST.store Endian.Little (dstAddr .+ numI32 10 addrSize) n0)
  !!ir (AST.store Endian.Little (dstAddr .+ numI32 12 addrSize) (!.ctxt R.FIP))
  !!ir (AST.store Endian.Little (dstAddr .+ numI32 20 addrSize) (!.ctxt R.FDP))

let fnstenv ins insLen ctxt =
  let ir = IRBuilder (16)
  let dst = transOneOpr ins insLen ctxt
  let struct (addrExpr, addrSize) = getLoadAddressExpr dst
  !<ir insLen
  match TypeCheck.typeOf dst with
  | 112<rt> -> m14fstenv addrExpr addrSize ctxt ir
  | 224<rt> -> m28fstenv addrExpr addrSize ctxt ir
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let private m14fldenv srcAddr addrSize ctxt ir =
  !!ir (!.ctxt R.FCW := AST.loadLE 16<rt> (srcAddr))
  !!ir (!.ctxt R.FSW := AST.loadLE 16<rt> (srcAddr .+ numI32 2 addrSize))
  !!ir (!.ctxt R.FTW := AST.loadLE 16<rt> (srcAddr .+ numI32 4 addrSize))
  !!ir (AST.xtlo 16<rt> (!.ctxt R.FIP) :=
    AST.loadLE 16<rt> (srcAddr .+ numI32 6 addrSize))
  !!ir (!.ctxt R.FCS := AST.loadLE 16<rt> (srcAddr .+ numI32 8 addrSize))
  !!ir (AST.xtlo 16<rt> (!.ctxt R.FDP) :=
    AST.loadLE 16<rt> (srcAddr .+ numI32 10 addrSize))
  !!ir (!.ctxt R.FDS := AST.loadLE 16<rt> (srcAddr .+ numI32 12 addrSize))

let private m28fldenv srcAddr addrSize ctxt ir =
  !!ir (!.ctxt R.FCW := AST.loadLE 16<rt> (srcAddr))
  !!ir (!.ctxt R.FSW := AST.loadLE 16<rt> (srcAddr .+ numI32 4 addrSize))
  !!ir (!.ctxt R.FTW := AST.loadLE 16<rt> (srcAddr .+ numI32 8 addrSize))
  !!ir (!.ctxt R.FIP := AST.loadLE 64<rt> (srcAddr .+ numI32 12 addrSize))
  !!ir (!.ctxt R.FDP := AST.loadLE 64<rt> (srcAddr .+ numI32 20 addrSize))

let fldenv ins insLen ctxt =
  let ir = IRBuilder (16)
  let src = transOneOpr ins insLen ctxt
  let struct (addrExpr, addrSize) = getLoadAddressExpr src
  !<ir insLen
  match TypeCheck.typeOf src with
  | 112<rt> -> m14fldenv addrExpr addrSize ctxt ir
  | 224<rt> -> m28fldenv addrExpr addrSize ctxt ir
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let private stSts dstAddr addrSize offset ctxt ir =
  let struct (stb, sta) = getFPUPseudoRegVars ctxt R.ST0
  !!ir (AST.store Endian.Little (dstAddr .+ numI32 (offset) addrSize) sta)
  !!ir (AST.store Endian.Little (dstAddr .+ numI32 (offset + 8) addrSize) stb)
  let struct (stb, sta) = getFPUPseudoRegVars ctxt R.ST1
  !!ir (AST.store Endian.Little (dstAddr .+ numI32 (offset + 10) addrSize) sta)
  !!ir (AST.store Endian.Little (dstAddr .+ numI32 (offset + 18) addrSize) stb)
  let struct (stb, sta) = getFPUPseudoRegVars ctxt R.ST2
  !!ir (AST.store Endian.Little (dstAddr .+ numI32 (offset + 20) addrSize) sta)
  !!ir (AST.store Endian.Little (dstAddr .+ numI32 (offset + 28) addrSize) stb)
  let struct (stb, sta) = getFPUPseudoRegVars ctxt R.ST3
  !!ir (AST.store Endian.Little (dstAddr .+ numI32 (offset + 30) addrSize) sta)
  !!ir (AST.store Endian.Little (dstAddr .+ numI32 (offset + 38) addrSize) stb)
  let struct (stb, sta) = getFPUPseudoRegVars ctxt R.ST4
  !!ir (AST.store Endian.Little (dstAddr .+ numI32 (offset + 40) addrSize) sta)
  !!ir (AST.store Endian.Little (dstAddr .+ numI32 (offset + 48) addrSize) stb)
  let struct (stb, sta) = getFPUPseudoRegVars ctxt R.ST5
  !!ir (AST.store Endian.Little (dstAddr .+ numI32 (offset + 50) addrSize) sta)
  !!ir (AST.store Endian.Little (dstAddr .+ numI32 (offset + 58) addrSize) stb)
  let struct (stb, sta) = getFPUPseudoRegVars ctxt R.ST6
  !!ir (AST.store Endian.Little (dstAddr .+ numI32 (offset + 60) addrSize) sta)
  !!ir (AST.store Endian.Little (dstAddr .+ numI32 (offset + 68) addrSize) stb)
  let struct (stb, sta) = getFPUPseudoRegVars ctxt R.ST7
  !!ir (AST.store Endian.Little (dstAddr .+ numI32 (offset + 70) addrSize) sta)
  !!ir (AST.store Endian.Little (dstAddr .+ numI32 (offset + 78) addrSize) stb)

let fnsave ins insLen ctxt =
  let ir = IRBuilder (32)
  let dst = transOneOpr ins insLen ctxt
  let struct (addrExpr, addrSize) = getLoadAddressExpr dst
  !<ir insLen
  match TypeCheck.typeOf dst with
  | 752<rt> ->
    m14fstenv addrExpr addrSize ctxt ir
    stSts addrExpr addrSize 14 ctxt ir
  | 864<rt> ->
    m28fstenv addrExpr addrSize ctxt ir
    stSts addrExpr addrSize 28 ctxt ir
  | _ -> raise InvalidOperandSizeException
  !!ir (!.ctxt R.FCW := numI32 0x037F 16<rt>)
  !!ir (!.ctxt R.FSW := AST.num0 16<rt>)
  !!ir (!.ctxt R.FTW := numI32 0xFFFF 16<rt>)
  !!ir (!.ctxt R.FDP := AST.num0 64<rt>)
  !!ir (!.ctxt R.FIP := AST.num0 64<rt>)
  !!ir (!.ctxt R.FOP := AST.num0 16<rt>)
  !>ir insLen

let private ldSts srcAddr addrSize offset ctxt ir =
  let struct (stb, sta) = getFPUPseudoRegVars ctxt R.ST0
  !!ir (sta := AST.loadLE 64<rt> (srcAddr .+ numI32 (offset) addrSize))
  !!ir (stb := AST.loadLE 16<rt> (srcAddr .+ numI32 (offset + 8) addrSize))
  let struct (stb, sta) = getFPUPseudoRegVars ctxt R.ST1
  !!ir (sta := AST.loadLE 64<rt> (srcAddr .+ numI32 (offset + 10) addrSize))
  !!ir (stb := AST.loadLE 16<rt> (srcAddr .+ numI32 (offset + 18) addrSize))
  let struct (stb, sta) = getFPUPseudoRegVars ctxt R.ST2
  !!ir (sta := AST.loadLE 64<rt> (srcAddr .+ numI32 (offset + 20) addrSize))
  !!ir (stb := AST.loadLE 16<rt> (srcAddr .+ numI32 (offset + 28) addrSize))
  let struct (stb, sta) = getFPUPseudoRegVars ctxt R.ST3
  !!ir (sta := AST.loadLE 64<rt> (srcAddr .+ numI32 (offset + 30) addrSize))
  !!ir (stb := AST.loadLE 16<rt> (srcAddr .+ numI32 (offset + 38) addrSize))
  let struct (stb, sta) = getFPUPseudoRegVars ctxt R.ST4
  !!ir (sta := AST.loadLE 64<rt> (srcAddr .+ numI32 (offset + 40) addrSize))
  !!ir (stb := AST.loadLE 16<rt> (srcAddr .+ numI32 (offset + 48) addrSize))
  let struct (stb, sta) = getFPUPseudoRegVars ctxt R.ST5
  !!ir (sta := AST.loadLE 64<rt> (srcAddr .+ numI32 (offset + 50) addrSize))
  !!ir (stb := AST.loadLE 16<rt> (srcAddr .+ numI32 (offset + 58) addrSize))
  let struct (stb, sta) = getFPUPseudoRegVars ctxt R.ST6
  !!ir (sta := AST.loadLE 64<rt> (srcAddr .+ numI32 (offset + 60) addrSize))
  !!ir (stb := AST.loadLE 16<rt> (srcAddr .+ numI32 (offset + 68) addrSize))
  let struct (stb, sta) = getFPUPseudoRegVars ctxt R.ST7
  !!ir (sta := AST.loadLE 64<rt> (srcAddr .+ numI32 (offset + 70) addrSize))
  !!ir (stb := AST.loadLE 16<rt> (srcAddr .+ numI32 (offset + 78) addrSize))

let frstor ins insLen ctxt =
  let ir = IRBuilder (32)
  let src = transOneOpr ins insLen ctxt
  let struct (addrExpr, addrSize) = getLoadAddressExpr src
  !<ir insLen
  match TypeCheck.typeOf src with
  | 752<rt> ->
    m14fldenv addrExpr addrSize ctxt ir
    ldSts addrExpr addrSize 14 ctxt ir
  | 864<rt> ->
    m28fldenv addrExpr addrSize ctxt ir
    ldSts addrExpr addrSize 28 ctxt ir
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let fnstsw ins insLen ctxt =
  let ir = IRBuilder (8)
  let oprExpr = transOneOpr ins insLen ctxt
  !<ir insLen
  !!ir (oprExpr := !.ctxt R.FSW)
  allCFlagsUndefined ctxt ir
  !>ir insLen

let wait _ins insLen ctxt =
  let ir = IRBuilder (8)
  !<ir insLen
  checkFPUExceptions ctxt ir
  !>ir insLen

let fnop _ins insLen ctxt =
  let ir = IRBuilder (8)
  !<ir insLen
  allCFlagsUndefined ctxt ir
  !>ir insLen

let inline private storeLE addr v =
  AST.store Endian.Little addr v

let private fxsaveInternal ctxt dstAddr addrSize is64bit ir =
  !!ir (storeLE (dstAddr) (!.ctxt R.FCW))
  !!ir (storeLE (dstAddr .+ (numI32 2 addrSize)) (!.ctxt R.FSW))
  !!ir (storeLE (dstAddr .+ (numI32 4 addrSize)) (!.ctxt R.FTW))
  !!ir (storeLE (dstAddr .+ (numI32 6 addrSize)) (!.ctxt R.FOP))
  !!ir (storeLE (dstAddr .+ (numI32 8 addrSize)) (!.ctxt R.FIP))
  !!ir (storeLE (dstAddr .+ (numI32 16 addrSize)) (!.ctxt R.FDP))
  !!ir (storeLE (dstAddr .+ (numI32 24 addrSize)) (!.ctxt R.MXCSR))
  !!ir (storeLE (dstAddr .+ (numI32 28 addrSize)) (!.ctxt R.MXCSRMASK))
  let struct (stb, sta) = getFPUPseudoRegVars ctxt R.ST0
  !!ir (storeLE (dstAddr .+ (numI32 32 addrSize)) sta)
  !!ir (storeLE (dstAddr .+ (numI32 40 addrSize)) stb)
  let struct (stb, sta) = getFPUPseudoRegVars ctxt R.ST1
  !!ir (storeLE (dstAddr .+ (numI32 48 addrSize)) sta)
  !!ir (storeLE (dstAddr .+ (numI32 56 addrSize)) stb)
  let struct (stb, sta) = getFPUPseudoRegVars ctxt R.ST2
  !!ir (storeLE (dstAddr .+ (numI32 64 addrSize)) sta)
  !!ir (storeLE (dstAddr .+ (numI32 72 addrSize)) stb)
  let struct (stb, sta) = getFPUPseudoRegVars ctxt R.ST3
  !!ir (storeLE (dstAddr .+ (numI32 80 addrSize)) sta)
  !!ir (storeLE (dstAddr .+ (numI32 88 addrSize)) stb)
  let struct (stb, sta) = getFPUPseudoRegVars ctxt R.ST4
  !!ir (storeLE (dstAddr .+ (numI32 96 addrSize)) sta)
  !!ir (storeLE (dstAddr .+ (numI32 104 addrSize)) stb)
  let struct (stb, sta) = getFPUPseudoRegVars ctxt R.ST5
  !!ir (storeLE (dstAddr .+ (numI32 112 addrSize)) sta)
  !!ir (storeLE (dstAddr .+ (numI32 120 addrSize)) stb)
  let struct (stb, sta) = getFPUPseudoRegVars ctxt R.ST6
  !!ir (storeLE (dstAddr .+ (numI32 128 addrSize)) sta)
  !!ir (storeLE (dstAddr .+ (numI32 136 addrSize)) stb)
  let struct (stb, sta) = getFPUPseudoRegVars ctxt R.ST7
  !!ir (storeLE (dstAddr .+ (numI32 144 addrSize)) sta)
  !!ir (storeLE (dstAddr .+ (numI32 152 addrSize)) stb)
  let xmmb, xmma = getPseudoRegVar128 ctxt R.XMM0
  !!ir (storeLE (dstAddr .+ (numI32 160 addrSize)) xmma)
  !!ir (storeLE (dstAddr .+ (numI32 168 addrSize)) xmmb)
  let xmmb, xmma = getPseudoRegVar128 ctxt R.XMM1
  !!ir (storeLE (dstAddr .+ (numI32 176 addrSize)) xmma)
  !!ir (storeLE (dstAddr .+ (numI32 184 addrSize)) xmmb)
  let xmmb, xmma = getPseudoRegVar128 ctxt R.XMM2
  !!ir (storeLE (dstAddr .+ (numI32 192 addrSize)) xmma)
  !!ir (storeLE (dstAddr .+ (numI32 200 addrSize)) xmmb)
  let xmmb, xmma = getPseudoRegVar128 ctxt R.XMM3
  !!ir (storeLE (dstAddr .+ (numI32 208 addrSize)) xmma)
  !!ir (storeLE (dstAddr .+ (numI32 216 addrSize)) xmmb)
  let xmmb, xmma = getPseudoRegVar128 ctxt R.XMM4
  !!ir (storeLE (dstAddr .+ (numI32 224 addrSize)) xmma)
  !!ir (storeLE (dstAddr .+ (numI32 232 addrSize)) xmmb)
  let xmmb, xmma = getPseudoRegVar128 ctxt R.XMM5
  !!ir (storeLE (dstAddr .+ (numI32 240 addrSize)) xmma)
  !!ir (storeLE (dstAddr .+ (numI32 248 addrSize)) xmmb)
  let xmmb, xmma = getPseudoRegVar128 ctxt R.XMM6
  !!ir (storeLE (dstAddr .+ (numI32 256 addrSize)) xmma)
  !!ir (storeLE (dstAddr .+ (numI32 264 addrSize)) xmmb)
  let xmmb, xmma = getPseudoRegVar128 ctxt R.XMM7
  !!ir (storeLE (dstAddr .+ (numI32 272 addrSize)) xmma)
  !!ir (storeLE (dstAddr .+ (numI32 280 addrSize)) xmmb)
  if is64bit then
    let xmmb, xmma = getPseudoRegVar128 ctxt R.XMM8
    !!ir (storeLE (dstAddr .+ (numI32 288 addrSize)) xmma)
    !!ir (storeLE (dstAddr .+ (numI32 296 addrSize)) xmmb)
    let xmmb, xmma = getPseudoRegVar128 ctxt R.XMM9
    !!ir (storeLE (dstAddr .+ (numI32 304 addrSize)) xmma)
    !!ir (storeLE (dstAddr .+ (numI32 312 addrSize)) xmmb)
    let xmmb, xmma = getPseudoRegVar128 ctxt R.XMM10
    !!ir (storeLE (dstAddr .+ (numI32 320 addrSize)) xmma)
    !!ir (storeLE (dstAddr .+ (numI32 328 addrSize)) xmmb)
    let xmmb, xmma = getPseudoRegVar128 ctxt R.XMM11
    !!ir (storeLE (dstAddr .+ (numI32 336 addrSize)) xmma)
    !!ir (storeLE (dstAddr .+ (numI32 344 addrSize)) xmmb)
    let xmmb, xmma = getPseudoRegVar128 ctxt R.XMM12
    !!ir (storeLE (dstAddr .+ (numI32 352 addrSize)) xmma)
    !!ir (storeLE (dstAddr .+ (numI32 360 addrSize)) xmmb)
    let xmmb, xmma = getPseudoRegVar128 ctxt R.XMM13
    !!ir (storeLE (dstAddr .+ (numI32 368 addrSize)) xmma)
    !!ir (storeLE (dstAddr .+ (numI32 376 addrSize)) xmmb)
    let xmmb, xmma = getPseudoRegVar128 ctxt R.XMM14
    !!ir (storeLE (dstAddr .+ (numI32 384 addrSize)) xmma)
    !!ir (storeLE (dstAddr .+ (numI32 392 addrSize)) xmmb)
    let xmmb, xmma = getPseudoRegVar128 ctxt R.XMM15
    !!ir (storeLE (dstAddr .+ (numI32 400 addrSize)) xmma)
    !!ir (storeLE (dstAddr .+ (numI32 408 addrSize)) xmmb)
  else ()

let fxsave ins insLen ctxt =
  let ir = IRBuilder (128)
  let dst = transOneOpr ins insLen ctxt
  let struct (addrExpr, addrSize) = getLoadAddressExpr dst
  !<ir insLen
  !?ir (fxsaveInternal ctxt addrExpr addrSize (ctxt.WordBitSize = 64<rt>))
  !>ir insLen

let private fxrstoreInternal ctxt srcAddr addrSz is64bit ir =
  !!ir (!.ctxt R.FCW := AST.loadLE 16<rt> (srcAddr))
  !!ir (!.ctxt R.FSW := AST.loadLE 16<rt> (srcAddr .+ (numI32 2 addrSz)))
  !!ir (!.ctxt R.FTW := AST.loadLE 16<rt> (srcAddr .+ (numI32 4 addrSz)))
  !!ir (!.ctxt R.FOP := AST.loadLE 16<rt> (srcAddr .+ (numI32 6 addrSz)))
  !!ir (!.ctxt R.FIP := AST.loadLE 64<rt> (srcAddr .+ (numI32 8 addrSz)))
  !!ir (!.ctxt R.FDP := AST.loadLE 64<rt> (srcAddr .+ (numI32 16 addrSz)))
  !!ir (!.ctxt R.MXCSR := AST.loadLE 32<rt> (srcAddr .+ (numI32 24 addrSz)))
  !!ir (!.ctxt R.MXCSRMASK := AST.loadLE 32<rt> (srcAddr .+ (numI32 28 addrSz)))
  let struct (stb, sta) = getFPUPseudoRegVars ctxt R.ST0
  !!ir (sta := AST.loadLE 64<rt> (srcAddr .+ (numI32 32 addrSz)))
  !!ir (stb := AST.loadLE 16<rt> (srcAddr .+ (numI32 40 addrSz)))
  let struct (stb, sta) = getFPUPseudoRegVars ctxt R.ST1
  !!ir (sta := AST.loadLE 64<rt> (srcAddr .+ (numI32 48 addrSz)))
  !!ir (stb := AST.loadLE 16<rt> (srcAddr .+ (numI32 56 addrSz)))
  let struct (stb, sta) = getFPUPseudoRegVars ctxt R.ST2
  !!ir (sta := AST.loadLE 64<rt> (srcAddr .+ (numI32 64 addrSz)))
  !!ir (stb := AST.loadLE 16<rt> (srcAddr .+ (numI32 72 addrSz)))
  let struct (stb, sta) = getFPUPseudoRegVars ctxt R.ST3
  !!ir (sta := AST.loadLE 64<rt> (srcAddr .+ (numI32 80 addrSz)))
  !!ir (stb := AST.loadLE 16<rt> (srcAddr .+ (numI32 88 addrSz)))
  let struct (stb, sta) = getFPUPseudoRegVars ctxt R.ST4
  !!ir (sta := AST.loadLE 64<rt> (srcAddr .+ (numI32 96 addrSz)))
  !!ir (stb := AST.loadLE 16<rt> (srcAddr .+ (numI32 104 addrSz)))
  let struct (stb, sta) = getFPUPseudoRegVars ctxt R.ST5
  !!ir (sta := AST.loadLE 64<rt> (srcAddr .+ (numI32 112 addrSz)))
  !!ir (stb := AST.loadLE 16<rt> (srcAddr .+ (numI32 120 addrSz)))
  let struct (stb, sta) = getFPUPseudoRegVars ctxt R.ST6
  !!ir (sta := AST.loadLE 64<rt> (srcAddr .+ (numI32 128 addrSz)))
  !!ir (stb := AST.loadLE 16<rt> (srcAddr .+ (numI32 136 addrSz)))
  let struct (stb, sta) = getFPUPseudoRegVars ctxt R.ST7
  !!ir (sta := AST.loadLE 64<rt> (srcAddr .+ (numI32 144 addrSz)))
  !!ir (stb := AST.loadLE 16<rt> (srcAddr .+ (numI32 152 addrSz)))
  let xmmb, xmma = getPseudoRegVar128 ctxt R.XMM0
  !!ir (xmma := AST.loadLE 64<rt> (srcAddr .+ (numI32 160 addrSz)))
  !!ir (xmmb := AST.loadLE 64<rt> (srcAddr .+ (numI32 168 addrSz)))
  let xmmb, xmma = getPseudoRegVar128 ctxt R.XMM1
  !!ir (xmma := AST.loadLE 64<rt> (srcAddr .+ (numI32 176 addrSz)))
  !!ir (xmmb := AST.loadLE 64<rt> (srcAddr .+ (numI32 184 addrSz)))
  let xmmb, xmma = getPseudoRegVar128 ctxt R.XMM2
  !!ir (xmma := AST.loadLE 64<rt> (srcAddr .+ (numI32 192 addrSz)))
  !!ir (xmmb := AST.loadLE 64<rt> (srcAddr .+ (numI32 200 addrSz)))
  let xmmb, xmma = getPseudoRegVar128 ctxt R.XMM3
  !!ir (xmma := AST.loadLE 64<rt> (srcAddr .+ (numI32 208 addrSz)))
  !!ir (xmmb := AST.loadLE 64<rt> (srcAddr .+ (numI32 216 addrSz)))
  let xmmb, xmma = getPseudoRegVar128 ctxt R.XMM4
  !!ir (xmma := AST.loadLE 64<rt> (srcAddr .+ (numI32 224 addrSz)))
  !!ir (xmmb := AST.loadLE 64<rt> (srcAddr .+ (numI32 232 addrSz)))
  let xmmb, xmma = getPseudoRegVar128 ctxt R.XMM5
  !!ir (xmma := AST.loadLE 64<rt> (srcAddr .+ (numI32 240 addrSz)))
  !!ir (xmmb := AST.loadLE 64<rt> (srcAddr .+ (numI32 248 addrSz)))
  let xmmb, xmma = getPseudoRegVar128 ctxt R.XMM6
  !!ir (xmma := AST.loadLE 64<rt> (srcAddr .+ (numI32 256 addrSz)))
  !!ir (xmmb := AST.loadLE 64<rt> (srcAddr .+ (numI32 264 addrSz)))
  let xmmb, xmma = getPseudoRegVar128 ctxt R.XMM7
  !!ir (xmma := AST.loadLE 64<rt> (srcAddr .+ (numI32 272 addrSz)))
  !!ir (xmmb := AST.loadLE 64<rt> (srcAddr .+ (numI32 280 addrSz)))
  if is64bit then
    let xmmb, xmma = getPseudoRegVar128 ctxt R.XMM8
    !!ir (xmma := AST.loadLE 64<rt> (srcAddr .+ (numI32 288 addrSz)))
    !!ir (xmmb := AST.loadLE 64<rt> (srcAddr .+ (numI32 296 addrSz)))
    let xmmb, xmma = getPseudoRegVar128 ctxt R.XMM9
    !!ir (xmma := AST.loadLE 64<rt> (srcAddr .+ (numI32 304 addrSz)))
    !!ir (xmmb := AST.loadLE 64<rt> (srcAddr .+ (numI32 312 addrSz)))
    let xmmb, xmma = getPseudoRegVar128 ctxt R.XMM10
    !!ir (xmma := AST.loadLE 64<rt> (srcAddr .+ (numI32 320 addrSz)))
    !!ir (xmmb := AST.loadLE 64<rt> (srcAddr .+ (numI32 328 addrSz)))
    let xmmb, xmma = getPseudoRegVar128 ctxt R.XMM11
    !!ir (xmma := AST.loadLE 64<rt> (srcAddr .+ (numI32 336 addrSz)))
    !!ir (xmmb := AST.loadLE 64<rt> (srcAddr .+ (numI32 344 addrSz)))
    let xmmb, xmma = getPseudoRegVar128 ctxt R.XMM12
    !!ir (xmma := AST.loadLE 64<rt> (srcAddr .+ (numI32 352 addrSz)))
    !!ir (xmmb := AST.loadLE 64<rt> (srcAddr .+ (numI32 360 addrSz)))
    let xmmb, xmma = getPseudoRegVar128 ctxt R.XMM13
    !!ir (xmma := AST.loadLE 64<rt> (srcAddr .+ (numI32 368 addrSz)))
    !!ir (xmmb := AST.loadLE 64<rt> (srcAddr .+ (numI32 376 addrSz)))
    let xmmb, xmma = getPseudoRegVar128 ctxt R.XMM14
    !!ir (xmma := AST.loadLE 64<rt> (srcAddr .+ (numI32 384 addrSz)))
    !!ir (xmmb := AST.loadLE 64<rt> (srcAddr .+ (numI32 392 addrSz)))
    let xmmb, xmma = getPseudoRegVar128 ctxt R.XMM15
    !!ir (xmma := AST.loadLE 64<rt> (srcAddr .+ (numI32 400 addrSz)))
    !!ir (xmmb := AST.loadLE 64<rt> (srcAddr .+ (numI32 408 addrSz)))
  else ()

let fxrstor ins insLen ctxt =
  let ir = IRBuilder (128)
  let src = transOneOpr ins insLen ctxt
  let struct (addrExpr, addrSize) = getLoadAddressExpr src
  !<ir insLen
  !?ir (fxrstoreInternal ctxt addrExpr addrSize (ctxt.WordBitSize = 64<rt>))
  !>ir insLen
