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
open B2R2.FrontEnd.BinLifter.Intel
open B2R2.FrontEnd.BinLifter.Intel.Helper
open B2R2.FrontEnd.BinLifter.Intel.LiftingUtils

let private getFPUPseudoRegVars ctxt r =
  getPseudoRegVar ctxt r 2, getPseudoRegVar ctxt r 1

let private checkC1Flag ctxt builder topTagReg =
  let c1 = getRegVar ctxt R.FSWC1
  let tagV = getRegVar ctxt topTagReg
  let rc = AST.extract (getRegVar ctxt R.FCW) 2<rt> 10
  builder <! (c1 := AST.ite (rc == numI32 2 2<rt>) AST.b1 AST.b0)
  builder <! (c1 := AST.ite (tagV == numI32 3 2<rt>) AST.b0 c1)

let private checkFPUOnLoad ctxt builder =
  let top = getRegVar ctxt R.FTOP
  let c1Flag = getRegVar ctxt R.FSWC1
  let cond1, cond2 = tmpVars2 1<rt>
  builder <! (cond1 := top == AST.num0 3<rt>)
  builder <! (cond2 := (getRegVar ctxt R.FTW0 .+ AST.num1 2<rt>) != AST.num0 2<rt>)
  builder <! (c1Flag := AST.ite (cond1 .& cond2) AST.b1 AST.b0)
  builder <! (getRegVar ctxt R.FSWC0 := undefC0)
  builder <! (getRegVar ctxt R.FSWC2 := undefC2)
  builder <! (getRegVar ctxt R.FSWC3 := undefC3)
  builder <! (top := top .- AST.num1 3<rt>)

let private fpuRegValue ctxt reg =
  let stb, sta = getFPUPseudoRegVars ctxt reg
  AST.concat stb sta

let private assignFPUReg reg expr80 ctxt builder =
  let stb, sta = getFPUPseudoRegVars ctxt reg
  builder <! (sta := AST.xtlo 64<rt> expr80)
  builder <! (stb := AST.xthi 16<rt> expr80)

let private getTagValueOnLoad ctxt builder =
  let tmp = AST.tmpvar 2<rt>
  let st0 = fpuRegValue ctxt R.ST0
  let exponent = AST.extract st0 11<rt> 52
  let zero = AST.num0 11<rt>
  let max = BitVector.unsignedMax 11<rt> |> AST.num
  let cond0 = (AST.xtlo 63<rt> st0) == AST.num0 63<rt>
  let condSpecial = (exponent == zero) .| (exponent == max)
  builder <! (tmp := AST.num0 2<rt>)
  builder <! (tmp := AST.ite condSpecial (BitVector.ofInt32 2 2<rt> |> AST.num) tmp)
  builder <! (tmp := AST.ite cond0 (AST.num1 2<rt>) tmp)
  tmp

let private updateTagWordOnLoad ctxt builder =
  let top = getRegVar ctxt R.FTOP
  let tagWord = getRegVar ctxt R.FTW
  let top16, mask, shifter, tagValue16 = tmpVars4 16<rt>
  let tagValue = getTagValueOnLoad ctxt builder
  let value3 = BitVector.ofInt32 3 16<rt> |> AST.num
  builder <! (top16 := AST.cast CastKind.ZeroExt 16<rt> top)
  builder <! (shifter := (BitVector.ofInt32 2 16<rt> |> AST.num) .* top16)
  builder <! (tagValue16 := AST.cast CastKind.ZeroExt 16<rt> tagValue)
  builder <! (tagValue16 := (tagValue16 << shifter))
  builder <! (mask := value3 << shifter)
  builder <! (tagWord := tagWord .& (AST.not mask))
  builder <! (tagWord := tagWord .| tagValue16)

let private updateTagWordOnPop ctxt builder =
  let top = getRegVar ctxt R.FTOP
  let tagWord = getRegVar ctxt R.FTW
  let top16, mask, shifter, tagValue16 = tmpVars4 16<rt>
  let value3 = BitVector.ofInt32 3 16<rt> |> AST.num
  builder <! (top16 := AST.cast CastKind.ZeroExt 16<rt> top)
  builder <! (shifter := (BitVector.ofInt32 2 16<rt> |> AST.num) .* top16)
  builder <! (mask := value3 << shifter)
  builder <! (tagWord := tagWord .| mask)

let private shiftFPUStackDown ctxt builder =
  assignFPUReg R.ST7 (fpuRegValue ctxt R.ST6) ctxt builder
  assignFPUReg R.ST6 (fpuRegValue ctxt R.ST5) ctxt builder
  assignFPUReg R.ST5 (fpuRegValue ctxt R.ST4) ctxt builder
  assignFPUReg R.ST4 (fpuRegValue ctxt R.ST3) ctxt builder
  assignFPUReg R.ST3 (fpuRegValue ctxt R.ST2) ctxt builder
  assignFPUReg R.ST2 (fpuRegValue ctxt R.ST1) ctxt builder
  assignFPUReg R.ST1 (fpuRegValue ctxt R.ST0) ctxt builder

let private popFPUStack ctxt builder =
  let top = getRegVar ctxt R.FTOP
  let c1Flag = getRegVar ctxt R.FSWC1
  let cond1, cond2 = tmpVars2 1<rt>
  assignFPUReg R.ST0 (fpuRegValue ctxt R.ST1) ctxt builder
  assignFPUReg R.ST1 (fpuRegValue ctxt R.ST2) ctxt builder
  assignFPUReg R.ST2 (fpuRegValue ctxt R.ST3) ctxt builder
  assignFPUReg R.ST3 (fpuRegValue ctxt R.ST4) ctxt builder
  assignFPUReg R.ST4 (fpuRegValue ctxt R.ST5) ctxt builder
  assignFPUReg R.ST5 (fpuRegValue ctxt R.ST6) ctxt builder
  assignFPUReg R.ST6 (fpuRegValue ctxt R.ST7) ctxt builder
  assignFPUReg R.ST7 (AST.num0 80<rt>) ctxt builder
  builder <! (cond1 := top == AST.num0 3<rt>)
  builder <! (cond2 := (getRegVar ctxt R.FTW7 .+ AST.num1 2<rt>) == AST.num0 2<rt>)
  builder <! (c1Flag := AST.ite (cond1 .& cond2) (AST.b0) (c1Flag))
  builder <! (getRegVar ctxt R.FSWC0 := undefC0)
  builder <! (getRegVar ctxt R.FSWC2 := undefC2)
  builder <! (getRegVar ctxt R.FSWC3 := undefC3)
  updateTagWordOnPop ctxt builder
  builder <! (top := top .+ AST.num1 3<rt>)

let private m14Stenv dst ctxt builder =
  let v r = getRegVar ctxt r
  let tmp = AST.tmpvar 112<rt>
  builder <! (tmp := AST.num0 112<rt>)
  builder <! (AST.xtlo 48<rt> tmp := AST.concat (v R.FCW)
                                        (AST.concat (v R.FSW) (v R.FTW)))
  builder <! (AST.extract tmp 16<rt> 48 := AST.xtlo 16<rt> (v R.FIP))
  builder <! (AST.extract tmp 11<rt> 64 := AST.xtlo 11<rt> (v R.FOP))
  builder <! (AST.extract tmp 4<rt> 76 := AST.extract (v R.FIP) 4<rt> 16)
  builder <! (AST.extract tmp 16<rt> 80 := AST.xtlo 16<rt> (v R.FDP))
  builder <! (AST.xthi 4<rt> tmp := AST.extract (v R.FDP) 4<rt> 16)
  builder <! (dst := tmp)

let private m14fldenv src ctxt builder =
  let v r = getRegVar ctxt r
  let tmp = AST.tmpvar 112<rt>
  builder <! (tmp := src)
  builder <! (v R.FCW := AST.xtlo 16<rt> tmp)
  builder <! (v R.FSW := AST.extract tmp 16<rt> 16)
  builder <! (v R.FTW := AST.extract tmp 16<rt> 32)
  builder <! (AST.xtlo 16<rt> (v R.FIP) := AST.extract tmp 16<rt> 48)
  builder <! (AST.xtlo 11<rt> (v R.FOP) := AST.extract tmp 11<rt> 64)
  builder <! (AST.extract (v R.FIP) 4<rt> 16 := AST.extract tmp 4<rt> 76)
  builder <! (AST.xtlo 16<rt> (v R.FDP) := AST.extract tmp 16<rt> 80)
  builder <! (AST.extract (v R.FDP) 4<rt> 16 := AST.xthi 4<rt> tmp)

let private m28fldenv src ctxt builder =
  let v r = getRegVar ctxt r
  let tmp = AST.tmpvar 224<rt>
  builder <! (tmp := src)
  builder <! (v R.FCW := AST.xtlo 16<rt> tmp)
  builder <! (v R.FSW := AST.extract tmp 16<rt> 32)
  builder <! (v R.FTW := AST.extract tmp 16<rt> 64)
  builder <! (AST.xtlo 16<rt> (v R.FIP) := AST.extract tmp 16<rt> 96)
  builder <! (AST.xtlo 11<rt> (v R.FOP) := AST.extract tmp 11<rt> 128)
  builder <! (AST.extract (v R.FIP) 16<rt> 16 := AST.extract tmp 16<rt> 139)
  builder <! (AST.xtlo 16<rt> (v R.FDP) := AST.extract tmp 16<rt> 160)
  builder <! (AST.extract (v R.FDP) 16<rt> 16 := AST.extract tmp 16<rt> 204)

let private m28fstenv dst ctxt builder =
  let v r = getRegVar ctxt r
  let tmp = AST.tmpvar 224<rt>
  builder <! (tmp := AST.num0 224<rt>)
  builder <! (AST.xtlo 16<rt> tmp := v R.FCW)
  builder <! (AST.extract tmp 16<rt> 32 := v R.FSW)
  builder <! (AST.extract tmp 16<rt> 64 := v R.FTW)
  builder <! (AST.extract tmp 16<rt> 96 := AST.xtlo 16<rt> (v R.FIP))
  builder <! (AST.extract tmp 11<rt> 128 := AST.xtlo 11<rt> (v R.FOP))
  builder <! (AST.extract tmp 16<rt> 139 := AST.extract (v R.FIP) 16<rt> 16)
  builder <! (AST.extract tmp 16<rt> 160 := AST.xtlo 16<rt> (v R.FDP))
  builder <! (AST.extract tmp 16<rt> 204 := AST.extract (v R.FDP) 16<rt> 16)
  builder <! (dst := tmp)

let private ftrig _ins insAddr insLen ctxt trigFunc =
  let builder = StmtBuilder (32)
  let st0 = fpuRegValue ctxt R.ST0
  let tmp = AST.tmpvar 80<rt>
  let float80SignUnmask = BitVector.signedMax 80<rt> |> AST.num
  let maxLimit = numI64 (1L <<< 63) 64<rt>
  let maxFloat = AST.cast CastKind.IntToFloat 80<rt> maxLimit
  let num3 = BitVector.ofInt32 3 2<rt> |> AST.num
  let c0 = getRegVar ctxt R.FSWC0
  let c1 = getRegVar ctxt R.FSWC1
  let c2 = getRegVar ctxt R.FSWC2
  let c3 = getRegVar ctxt R.FSWC3
  let lblOutOfRange = AST.symbol "IsOutOfRange"
  let lblInRange = AST.symbol "IsInRange"
  let tmp = AST.tmpvar 80<rt>
  startMark insAddr insLen builder
  builder <! (tmp := st0 .& float80SignUnmask)
  builder <! (CJmp (AST.flt tmp maxFloat, Name lblInRange, Name lblOutOfRange ))
  builder <! (LMark lblInRange)
  builder <! (tmp := trigFunc st0)
  assignFPUReg R.ST0 tmp ctxt builder
  builder <! (c1 := AST.ite (getRegVar ctxt R.FTW7 == num3) AST.b0 c1)
  builder <! (c2 := AST.b0)
  builder <! (c0 := undefC0)
  builder <! (c3 := undefC3)
  builder <! (LMark lblOutOfRange)
  builder <! (c2 := AST.b1)
  builder <! (c0 := undefC0)
  builder <! (c1 := undefC1)
  builder <! (c3 := undefC3)
  endMark insAddr insLen builder

let private fpuFBinOp ins insAddr insLen ctxt binOp doPop leftToRight =
  let builder = StmtBuilder (64)
  let res = AST.tmpvar 80<rt>
  startMark insAddr insLen builder
  match ins.Operands with
  | NoOperand ->
    let st0 = fpuRegValue ctxt R.ST0
    let st1 = fpuRegValue ctxt R.ST1
    if leftToRight then builder <! (res := binOp st0 st1)
    else builder <! (res := binOp st1 st0)
    assignFPUReg R.ST1 res ctxt builder
    checkC1Flag ctxt builder R.FTW6
  | OneOperand opr ->
    let oprExpr = transOprToFloat80 ins insAddr insLen ctxt opr
    let st0 = fpuRegValue ctxt R.ST0
    if leftToRight then builder <! (res := binOp st0 oprExpr)
    else builder <! (res := binOp oprExpr st0)
    assignFPUReg R.ST0 res ctxt builder
    checkC1Flag ctxt builder R.FTW7
  | TwoOperands (OprReg reg1, opr2) ->
    let oprExpr1 = getRegVar ctxt reg1
    let oprExpr2 = transOprToExpr ins insAddr insLen ctxt opr2
    if leftToRight then builder <! (res := binOp oprExpr1 oprExpr2)
    else builder <! (res := binOp oprExpr2 oprExpr1)
    assignFPUReg reg1 res ctxt builder
  | _ -> raise InvalidOperandException
  if doPop then popFPUStack ctxt builder else ()
  endMark insAddr insLen builder

let private fpuIntOp ins insAddr insLen ctxt binOp leftToRight =
  let builder = StmtBuilder (8)
  let st0 = fpuRegValue ctxt R.ST0
  let oprExpr = getOneOpr ins |> transOprToExpr ins insAddr insLen ctxt
  let tmp = AST.tmpvar 80<rt>
  startMark insAddr insLen builder
  builder <! (tmp := AST.cast CastKind.IntToFloat 80<rt> oprExpr)
  if leftToRight then builder <! (tmp := binOp st0 tmp)
  else builder <! (tmp := binOp tmp st0)
  assignFPUReg R.ST0 tmp ctxt builder
  endMark insAddr insLen builder

let private bcdToInt intgr bcd builder =
  let getDigit startPos =
    AST.extract bcd 4<rt> startPos |> AST.sext 64<rt>
  let n num =
    numI64 num 64<rt>
  builder <! (intgr := AST.num0 64<rt>)
  builder <! (intgr := intgr .+ getDigit 0)
  builder <! (intgr := intgr .+ (getDigit 4 .* n 10L))
  builder <! (intgr := intgr .+ (getDigit 8 .* n 100L))
  builder <! (intgr := intgr .+ (getDigit 12 .* n 1000L))
  builder <! (intgr := intgr .+ (getDigit 16 .* n 10000L))
  builder <! (intgr := intgr .+ (getDigit 20 .* n 100000L))
  builder <! (intgr := intgr .+ (getDigit 24 .* n 1000000L))
  builder <! (intgr := intgr .+ (getDigit 28 .* n 10000000L))
  builder <! (intgr := intgr .+ (getDigit 32 .* n 100000000L))
  builder <! (intgr := intgr .+ (getDigit 36 .* n 1000000000L))
  builder <! (intgr := intgr .+ (getDigit 40 .* n 10000000000L))
  builder <! (intgr := intgr .+ (getDigit 44 .* n 100000000000L))
  builder <! (intgr := intgr .+ (getDigit 48 .* n 1000000000000L))
  builder <! (intgr := intgr .+ (getDigit 52 .* n 10000000000000L))
  builder <! (intgr := intgr .+ (getDigit 56 .* n 100000000000000L))
  builder <! (intgr := intgr .+ (getDigit 60 .* n 1000000000000000L))
  builder <! (intgr := intgr .+ (getDigit 64 .* n 10000000000000000L))
  builder <! (intgr := intgr .+ (getDigit 68 .* n 100000000000000000L))

let private intTobcd bcd intgr builder =
  let n10 = numI32 10 64<rt>
  let mod10 = intgr .% n10 |> AST.zext 4<rt>
  let digitAt startPos = AST.extract bcd 4<rt> startPos
  let rec doAssign startPos =
    if startPos >= 72 then ()
    else
      builder <! (digitAt startPos := mod10)
      builder <! (intgr := intgr ./ n10)
      doAssign (startPos + 4)
  doAssign 0

let private fpuLoad insAddr insLen ctxt oprExpr =
  let builder = StmtBuilder (64)
  let tmp = AST.tmpvar 80<rt>
  startMark insAddr insLen builder
  builder <! (tmp := AST.cast CastKind.FloatExt 80<rt> oprExpr)
  checkFPUOnLoad ctxt builder
  shiftFPUStackDown ctxt builder
  assignFPUReg R.ST0 tmp ctxt builder
  updateTagWordOnLoad ctxt builder
  endMark insAddr insLen builder

let fld ins insAddr insLen ctxt =
  let opr = getOneOpr ins
  let oprExpr = transOprToExpr ins insAddr insLen ctxt opr
  fpuLoad insAddr insLen ctxt oprExpr

let ffst ins insAddr insLen ctxt doPop =
  let builder = StmtBuilder (32)
  let opr = getOneOpr ins
  let oprExpr = transOprToExpr ins insAddr insLen ctxt opr
  let st0 = fpuRegValue ctxt R.ST0
  let sz = AST.typeOf oprExpr
  let tmp = AST.tmpvar sz
  startMark insAddr insLen builder
  builder <! (tmp := AST.cast CastKind.FloatExt sz st0)
  match opr with
  | OprReg r -> assignFPUReg r tmp ctxt builder
  | _ -> builder <! (oprExpr := tmp)
  checkC1Flag ctxt builder R.FTW7
  cflagsUndefined023 ctxt builder
  if doPop then popFPUStack ctxt builder else ()
  endMark insAddr insLen builder

let fild ins insAddr insLen ctxt =
  let builder = StmtBuilder (32)
  let oprExpr = getOneOpr ins |> transOprToExpr ins insAddr insLen ctxt
  let tmp = AST.tmpvar 80<rt>
  startMark insAddr insLen builder
  builder <! (tmp := AST.cast CastKind.IntToFloat 80<rt> oprExpr)
  checkFPUOnLoad ctxt builder
  shiftFPUStackDown ctxt builder
  assignFPUReg R.ST0 tmp ctxt builder
  updateTagWordOnLoad ctxt builder
  endMark insAddr insLen builder

let fist ins insAddr insLen ctxt doPop =
  let builder = StmtBuilder (32)
  let oprExpr = getOneOpr ins |> transOprToExpr ins insAddr insLen ctxt
  let sz = AST.typeOf oprExpr
  let st0 = fpuRegValue ctxt R.ST0
  let tmp1 = AST.tmpvar sz
  let tmp2 = AST.tmpvar 2<rt>
  let num2 = numI32 2 2<rt>
  let cstK castKind = AST.cast castKind sz st0
  startMark insAddr insLen builder
  builder <! (tmp2 := AST.extract (getRegVar ctxt R.FCW) 2<rt> 10)
  builder <! (tmp1 := AST.ite (tmp2 == AST.num0 2<rt>)
    (cstK CastKind.FtoIRound) (cstK CastKind.FtoITrunc))
  builder <!
    (tmp1 := AST.ite (tmp2 == AST.num1 2<rt>) (cstK CastKind.FtoIFloor) tmp1)
  builder <! (tmp1 := AST.ite (tmp2 == num2) (cstK CastKind.FtoICeil) tmp1)
  builder <! (oprExpr := tmp1)
  builder <! (getRegVar ctxt R.FSWC1 := AST.ite (tmp2 == num2) AST.b1 AST.b0)
  cflagsUndefined023 ctxt builder
  if doPop then popFPUStack ctxt builder else ()
  endMark insAddr insLen builder

let fisttp ins insAddr insLen ctxt =
  let builder = StmtBuilder (64)
  let oprExpr = getOneOpr ins |> transOprToExpr ins insAddr insLen ctxt
  let sz = AST.typeOf oprExpr
  let st0 = fpuRegValue ctxt R.ST0
  startMark insAddr insLen builder
  builder <! (oprExpr := AST.cast CastKind.FtoICeil sz st0)
  builder <! (getRegVar ctxt R.FSWC1 := AST.b0)
  builder <! (getRegVar ctxt R.FSWC0 := undefC0)
  builder <! (getRegVar ctxt R.FSWC2 := undefC2)
  builder <! (getRegVar ctxt R.FSWC3 := undefC3)
  popFPUStack ctxt builder
  endMark insAddr insLen builder

let fbld ins insAddr insLen ctxt =
  let builder = StmtBuilder (64)
  let src = getOneOpr ins |> transOprToExpr ins insAddr insLen ctxt
  let sign = AST.xthi 1<rt> src
  let intgr = AST.tmpvar 64<rt>
  let bcdNum = AST.tmpvar 72<rt>
  let tmp = AST.tmpvar 80<rt>
  startMark insAddr insLen builder
  bcdToInt intgr bcdNum builder
  builder <! (AST.xthi 1<rt> intgr := sign)
  builder <! (tmp := AST.cast CastKind.IntToFloat 80<rt> intgr)
  checkFPUOnLoad ctxt builder
  shiftFPUStackDown ctxt builder
  assignFPUReg R.ST0 tmp ctxt builder
  updateTagWordOnLoad ctxt builder
  endMark insAddr insLen builder

let fbstp ins insAddr insLen ctxt =
  let builder = StmtBuilder (64)
  let dst = getOneOpr ins |> transOprToExpr ins insAddr insLen ctxt
  let st0 = fpuRegValue ctxt R.ST0
  let sign = AST.xthi 1<rt> st0
  let intgr = AST.tmpvar 64<rt>
  let bcdNum = AST.tmpvar 72<rt>
  let tmp = AST.tmpvar 80<rt>
  startMark insAddr insLen builder
  builder <! (intgr := AST.cast CastKind.FtoIRound 64<rt> st0)
  intTobcd bcdNum intgr builder
  builder <! (tmp := AST.num0 80<rt>)
  builder <! (AST.xthi 1<rt> tmp := sign)
  builder <! (AST.xtlo 72<rt> tmp := bcdNum)
  builder <! (dst := tmp)
  endMark insAddr insLen builder

let fxch ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let tmp = AST.tmpvar 80<rt>
  let st0 = fpuRegValue ctxt R.ST0
  startMark insAddr insLen builder
  match ins.Operands with
  | OneOperand (OprReg reg as opr) ->
      let oprExpr = transOprToExpr ins insAddr insLen ctxt opr
      builder <! (tmp := st0)
      assignFPUReg R.ST0 oprExpr ctxt builder
      assignFPUReg reg tmp ctxt builder
  | NoOperand ->
      let st1 = fpuRegValue ctxt R.ST1
      builder <! (tmp := st0)
      assignFPUReg R.ST0 st1 ctxt builder
      assignFPUReg R.ST1 tmp ctxt builder
  | _ -> raise InvalidOperandException
  builder <! (getRegVar ctxt R.FSWC1 := AST.b0)
  cflagsUndefined023 ctxt builder
  endMark insAddr insLen builder

let private fcmov ins insAddr insLen ctxt cond =
  let builder = StmtBuilder (8)
  let _dst, src = getTwoOprs ins
  let src = transOprToExpr ins insAddr insLen ctxt src
  let st0b, st0a = getFPUPseudoRegVars ctxt R.ST0
  startMark insAddr insLen builder
  builder <! (st0a := AST.ite cond (AST.xtlo 64<rt> src) st0a)
  builder <! (st0b := AST.ite cond (AST.xthi 16<rt> src) st0b)
  builder <! (getRegVar ctxt R.FSWC0 := undefC0)
  builder <! (getRegVar ctxt R.FSWC2 := undefC2)
  builder <! (getRegVar ctxt R.FSWC3 := undefC3)
  endMark insAddr insLen builder

let fcmove ins insAddr insLen ctxt =
  getRegVar ctxt R.ZF |> fcmov ins insAddr insLen ctxt

let fcmovne ins insAddr insLen ctxt =
  getRegVar ctxt R.ZF |> AST.not |> fcmov ins insAddr insLen ctxt

let fcmovb ins insAddr insLen ctxt =
  getRegVar ctxt R.CF |> fcmov ins insAddr insLen ctxt

let fcmovbe ins insAddr insLen ctxt =
  (getRegVar ctxt R.CF .| getRegVar ctxt R.ZF) |> fcmov ins insAddr insLen ctxt

let fcmovnb ins insAddr insLen ctxt =
  getRegVar ctxt R.CF |> AST.not |> fcmov ins insAddr insLen ctxt

let fcmovnbe ins insAddr insLen ctxt =
  let cond1 = getRegVar ctxt R.CF |> AST.not
  let cond2 = getRegVar ctxt R.ZF |> AST.not
  cond1 .& cond2 |> fcmov ins insAddr insLen ctxt

let fcmovu ins insAddr insLen ctxt =
  getRegVar ctxt R.PF |> fcmov ins insAddr insLen ctxt

let fcmovnu ins insAddr insLen ctxt =
  getRegVar ctxt R.PF |> AST.not |> fcmov ins insAddr insLen ctxt

let fpuadd ins insAddr insLen ctxt doPop =
  fpuFBinOp ins insAddr insLen ctxt AST.fadd doPop true

let fiadd ins insAddr insLen ctxt =
  fpuIntOp ins insAddr insLen ctxt AST.fadd true

let fpusub ins insAddr insLen ctxt doPop =
  fpuFBinOp ins insAddr insLen ctxt AST.fsub doPop true

let fisub ins insAddr insLen ctxt =
  fpuIntOp ins insAddr insLen ctxt AST.fsub true

let fsubr ins insAddr insLen ctxt doPop =
  fpuFBinOp ins insAddr insLen ctxt AST.fsub doPop false

let fisubr ins insAddr insLen ctxt =
  fpuIntOp ins insAddr insLen ctxt AST.fsub false

let fpumul ins insAddr insLen ctxt doPop =
  fpuFBinOp ins insAddr insLen ctxt AST.fmul doPop true

let fimul ins insAddr insLen ctxt =
  fpuIntOp ins insAddr insLen ctxt AST.fmul true

let fpudiv ins insAddr insLen ctxt doPop =
  fpuFBinOp ins insAddr insLen ctxt AST.fdiv doPop true

let fidiv ins insAddr insLen ctxt =
  fpuIntOp ins insAddr insLen ctxt AST.fdiv true

let fdivr ins insAddr insLen ctxt doPop =
  fpuFBinOp ins insAddr insLen ctxt AST.fdiv doPop false

let fidivr ins insAddr insLen ctxt =
  fpuIntOp ins insAddr insLen ctxt AST.fdiv false

let fprem _ins insAddr insLen ctxt round =
  let builder = StmtBuilder (32)
  let st0 = fpuRegValue ctxt R.ST0
  let st1 = fpuRegValue ctxt R.ST1
  let caster = if round then CastKind.FtoIRound else CastKind.FtoITrunc
  let lblLT64 = AST.symbol "ExpDiffInRange"
  let lblGT64 = AST.symbol "ExpDiffOutOfRange"
  let lblExit = AST.symbol "Exit"
  let expDiff = AST.tmpvar 15<rt>
  let tmp80A, tmp80B, tmpres = tmpVars3 80<rt>
  let tmp64 = AST.tmpvar 64<rt>
  startMark insAddr insLen builder
  builder <! (expDiff := AST.extract st0 15<rt> 64 .- AST.extract st1 15<rt> 64)
  builder <! (CJmp (AST.lt expDiff (numI32 64 15<rt>), Name lblLT64, Name lblGT64))
  builder <! (LMark lblLT64)
  builder <! (tmp80A := AST.fdiv st0 st1)
  builder <! (tmp64 := AST.cast caster 64<rt> tmp80A)
  builder <! (tmp80B := AST.fmul st1 (AST.cast CastKind.IntToFloat 80<rt> tmp64))
  builder <! (tmpres := AST.fsub st0 tmp80B)
  assignFPUReg R.ST0 tmpres ctxt builder
  builder <! (getRegVar ctxt R.FSWC2 := AST.b0)
  builder <! (getRegVar ctxt R.FSWC1 := AST.xtlo 1<rt> tmp64)
  builder <! (getRegVar ctxt R.FSWC3 := AST.extract tmp64 1<rt> 1)
  builder <! (getRegVar ctxt R.FSWC0 := AST.extract tmp64 1<rt> 2)
  builder <! (Jmp (Name lblExit))
  builder <! (LMark lblGT64)
  builder <! (getRegVar ctxt R.FSWC2 := AST.b1)
  builder <! (tmp64 := (AST.zext 64<rt> expDiff) .- numI32 63 64<rt>)
  builder <! (tmp64 := tmp64 .* numI32 2 64<rt>)
  builder <! (tmp80B := AST.cast CastKind.IntToFloat 80<rt> tmp64)
  builder <! (tmp80A := AST.fdiv (AST.fdiv st0 st1) tmp80B)
  builder <! (tmp64 := AST.cast CastKind.FtoITrunc 64<rt> tmp80A)
  builder <! (tmp80A := AST.cast CastKind.IntToFloat 80<rt> tmp64)
  builder <! (tmp80A := AST.fsub st0 (AST.fmul st1 (AST.fmul tmp80A tmp80B)))
  assignFPUReg R.ST0 tmp80A ctxt builder
  builder <! (LMark lblExit)
  endMark insAddr insLen builder

let fabs _ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let st0b, _st0a = getFPUPseudoRegVars ctxt R.ST0
  startMark insAddr insLen builder
  builder <! (AST.extract st0b 1<rt> 15 := AST.b1)
  builder <! (getRegVar ctxt R.FSWC1 := AST.b0)
  builder <! (getRegVar ctxt R.FSWC0 := undefC0)
  builder <! (getRegVar ctxt R.FSWC2 := undefC2)
  builder <! (getRegVar ctxt R.FSWC3 := undefC3)
  endMark insAddr insLen builder

let fchs _ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let st0b, _st0a = getFPUPseudoRegVars ctxt R.ST0
  let tmp = AST.tmpvar 1<rt>
  startMark insAddr insLen builder
  builder <! (tmp := AST.xthi 1<rt> st0b)
  builder <! (AST.xthi 1<rt> st0b := AST.not tmp)
  builder <! (getRegVar ctxt R.FSWC1 := AST.b0)
  builder <! (getRegVar ctxt R.FSWC0 := undefC0)
  builder <! (getRegVar ctxt R.FSWC2 := undefC2)
  builder <! (getRegVar ctxt R.FSWC3 := undefC3)
  endMark insAddr insLen builder

let frndint _ins insAddr insLen ctxt =
  let builder = StmtBuilder (32)
  let st0 = fpuRegValue ctxt R.ST0
  let tmp = AST.tmpvar 80<rt>
  let tmp1 = AST.tmpvar 64<rt>
  let tmp2 = AST.tmpvar 2<rt>
  let num2 = numI32 2 2<rt>
  let cstK castKind = AST.cast castKind 64<rt> st0
  startMark insAddr insLen builder
  builder <! (tmp2 := AST.extract (getRegVar ctxt R.FCW) 2<rt> 10)
  builder <! (tmp1 := AST.ite (tmp2 == AST.num0 2<rt>)
    (cstK CastKind.FtoIRound) (cstK CastKind.FtoITrunc))
  builder <! (tmp1 := AST.ite (tmp2 == AST.num1 2<rt>) (cstK CastKind.FtoIFloor) tmp1)
  builder <! (tmp1 := AST.ite (tmp2 == num2) (cstK CastKind.FtoICeil) tmp1)
  builder <! (tmp := AST.cast CastKind.IntToFloat 80<rt> tmp1)
  assignFPUReg R.ST0 tmp ctxt builder
  builder <! (getRegVar ctxt R.FSWC1 := AST.ite (tmp2 == num2) AST.b1 AST.b0)
  cflagsUndefined023 ctxt builder
  endMark insAddr insLen builder

let fscale _ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let tmp1, tmp2 = tmpVars2 64<rt>
  let tmp3 = AST.tmpvar 80<rt>
  let st0 = fpuRegValue ctxt R.ST0
  let st1 = fpuRegValue ctxt R.ST1
  startMark insAddr insLen builder
  builder <! (tmp1 := AST.cast CastKind.FtoITrunc 64<rt> st1)
  builder <! (tmp2 := numI32 1 64<rt> << tmp1)
  builder <! (tmp3 := AST.cast CastKind.IntToFloat 80<rt> tmp2)
  builder <! (tmp3 := AST.fmul st0 tmp3)
  assignFPUReg R.ST0 tmp3 ctxt builder
  checkC1Flag ctxt builder R.FTW6
  cflagsUndefined023 ctxt builder
  endMark insAddr insLen builder

let fsqrt _ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let st0 = fpuRegValue ctxt R.ST0
  let tmp = AST.tmpvar 80<rt>
  startMark insAddr insLen builder
  builder <! (tmp := AST.unop UnOpType.FSQRT st0)
  assignFPUReg R.ST0 tmp ctxt builder
  checkC1Flag ctxt builder R.FTW7
  endMark insAddr insLen builder

let fxtract _ins insAddr insLen ctxt =
  let builder = StmtBuilder (64)
  let st0 = fpuRegValue ctxt R.ST0
  let tmp = AST.tmpvar 80<rt>
  let exponent = AST.tmpvar 64<rt>
  let significand = AST.tmpvar 80<rt>
  startMark insAddr insLen builder
  builder <! (exponent := AST.num0 64<rt>)
  builder <! (significand := AST.num0 80<rt>)
  builder <! (AST.xtlo 64<rt> significand := AST.xtlo 64<rt> st0)
  builder <! (AST.xthi 1<rt> significand := AST.xthi 1<rt> st0)
  builder <! (AST.extract significand 15<rt> 64 := numI32 16383 15<rt>)
  builder <! (AST.xtlo 15<rt> exponent := AST.extract st0 15<rt> 64)
  builder <! (exponent := exponent .- numI32 16383 64<rt>)
  builder <! (tmp := AST.cast CastKind.IntToFloat 80<rt> exponent)
  assignFPUReg R.ST0 tmp ctxt builder
  checkFPUOnLoad ctxt builder
  shiftFPUStackDown ctxt builder
  assignFPUReg R.ST0 significand ctxt builder
  updateTagWordOnLoad ctxt builder
  checkC1Flag ctxt builder R.FTW7
  cflagsUndefined023 ctxt builder
  endMark insAddr insLen builder

let fcom ins insAddr insLen ctxt nPop unordered =
  let builder = StmtBuilder (64)
  let lblNan = AST.symbol "IsNan"
  let lblExit = AST.symbol "Exit"
  let c0 = getRegVar ctxt R.FSWC0
  let c2 = getRegVar ctxt R.FSWC2
  let c3 = getRegVar ctxt R.FSWC3
  let im = getRegVar ctxt R.FCW |> AST.xtlo 1<rt>
  let tmp1, tmp2 = tmpVars2 80<rt>
  startMark insAddr insLen builder
  match ins.Operands with
  | NoOperand ->
    builder <! (tmp1 := fpuRegValue ctxt R.ST0)
    builder <! (tmp2 := fpuRegValue ctxt R.ST1)
  | OneOperand opr ->
    let oprExpr = transOprToFloat80 ins insAddr insLen ctxt opr
    builder <! (tmp1 := fpuRegValue ctxt R.ST0)
    builder <! (tmp2 := oprExpr)
  | _ -> raise InvalidOperandException
  builder <! (c0 := AST.ite (AST.flt tmp1 tmp2) AST.b1 AST.b0)
  builder <! (c2 := AST.b0)
  builder <! (c3 := AST.ite (tmp1 == tmp2) AST.b1 AST.b0)
  let isNan expr =
    (AST.extract expr 15<rt> 64  == AST.num (BitVector.unsignedMax 15<rt>))
     .& (AST.xtlo 62<rt> expr != AST.num0 62<rt>)
  let cond =
    if unordered then
        let tmp1qNanCond = isNan tmp1 .& (AST.extract tmp1 1<rt> 62 == AST.b1)
        let tmp2qNanCond = isNan tmp2 .& (AST.extract tmp2 1<rt> 62 == AST.b1)
        tmp1qNanCond .| tmp2qNanCond .& (im == AST.b0)
    else isNan tmp1 .| isNan tmp2 .& (im == AST.b0)
  builder <! (CJmp (cond, Name lblNan, Name lblExit))
  builder <! (LMark lblNan)
  builder <! (c0 := AST.b1)
  builder <! (c2 := AST.b1)
  builder <! (c3 := AST.b1)
  builder <! (LMark lblExit)
  builder <! (getRegVar ctxt R.FSWC1 := AST.b0)
  if nPop > 0 then popFPUStack ctxt builder else ()
  if nPop = 2 then popFPUStack ctxt builder else ()
  endMark insAddr insLen builder

let ficom ins insAddr insLen ctxt doPop =
  let builder = StmtBuilder (32)
  let oprExpr = getOneOpr ins |> transOprToExpr ins insAddr insLen ctxt
  let st0 = fpuRegValue ctxt R.ST0
  let tmp = AST.tmpvar 80<rt>
  startMark insAddr insLen builder
  builder <! (tmp := AST.cast CastKind.IntToFloat 80<rt> oprExpr)
  builder <! (getRegVar ctxt R.FSWC0 := AST.ite (AST.flt st0 tmp) AST.b1 AST.b0)
  builder <! (getRegVar ctxt R.FSWC2 := AST.b0)
  builder <! (getRegVar ctxt R.FSWC3 := AST.ite (st0 == tmp) AST.b1 AST.b0)
  builder <! (getRegVar ctxt R.FSWC1 := AST.b0)
  if doPop then popFPUStack ctxt builder else ()
  endMark insAddr insLen builder

let fcomi ins insAddr insLen ctxt doPop =
  let builder = StmtBuilder (64)
  let opr1, opr2 = getTwoOprs ins
  let opr1 = transOprToExpr ins insAddr insLen ctxt opr1
  let opr2 = transOprToExpr ins insAddr insLen ctxt opr2
  let im = getRegVar ctxt R.FCW |> AST.xtlo 1<rt>
  let lblQNan = AST.symbol "IsQNan"
  let lblNan = AST.symbol "IsNan"
  let lblExit = AST.symbol "Exit"
  let lblCond = AST.symbol "IsNanCond"
  let zf = getRegVar ctxt R.ZF
  let pf = getRegVar ctxt R.PF
  let cf = getRegVar ctxt R.CF
  startMark insAddr insLen builder
  builder <! (zf := AST.ite (opr1 == opr2) AST.b1 AST.b0)
  builder <! (pf := AST.b0)
  builder <! (cf := AST.ite (AST.flt opr1 opr2) AST.b1 AST.b0)
  let opr1NanCond =
    (AST.extract opr1 15<rt> 64  == AST.num (BitVector.unsignedMax 15<rt>))
      .& (AST.xtlo 62<rt> opr1 != AST.num0 62<rt>)
  let opr2NanCond =
    (AST.extract opr2 15<rt> 64 == AST.num (BitVector.unsignedMax 15<rt>))
      .& (AST.xtlo 62<rt> opr2 != AST.num0 62<rt>)
  let cond = opr1NanCond .| opr2NanCond .& (im == AST.b0)
  match ins.Opcode with
  | Opcode.FCOMI | Opcode.FCOMIP ->
    builder <! (CJmp (cond, Name lblNan, Name lblExit))
  | Opcode.FUCOMI | Opcode.FUCOMIP ->
    let opr1qNanCond = opr1NanCond .& (AST.extract opr1 1<rt> 62 == AST.b1)
    let opr2qNanCond = opr2NanCond .& (AST.extract opr2 1<rt> 62 == AST.b1)
    builder <! (CJmp (opr1qNanCond .| opr2qNanCond, Name lblQNan, Name lblCond))
    builder <! (LMark lblQNan)
    builder <! (zf:= AST.b1)
    builder <! (pf := AST.b1)
    builder <! (cf := AST.b1)
    builder <! (Jmp (Name lblExit))
    builder <! (LMark lblCond)
    builder <! (CJmp (cond, Name lblNan, Name lblExit))
  | _ -> raise InvalidOpcodeException
  builder <! (LMark lblNan)
  builder <! (zf := AST.b1)
  builder <! (pf := AST.b1)
  builder <! (cf := AST.b1)
  builder <! (LMark lblExit)
  if doPop then popFPUStack ctxt builder else ()
  endMark insAddr insLen builder

let ftst _ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let st0 = fpuRegValue ctxt R.ST0
  let num0V = AST.num0 80<rt>
  let c0 = getRegVar ctxt R.FSWC0
  let c2 = getRegVar ctxt R.FSWC2
  let c3 = getRegVar ctxt R.FSWC3
  let lblNan = AST.symbol "IsNan"
  let lblExit = AST.symbol "Exit"
  startMark insAddr insLen builder
  builder <! (c0 := AST.ite (AST.flt st0 num0V) AST.b1 AST.b0)
  builder <! (c2 := AST.b0)
  builder <! (c3 := AST.ite (st0 == num0V) AST.b1 AST.b0)
  let st0Exponent = AST.extract st0 15<rt> 64
  let st0NanCond =
    (st0Exponent == AST.num (BitVector.unsignedMax 15<rt>))
     .& (AST.xtlo 62<rt> st0 != AST.num0 62<rt>)
  builder <! (CJmp (st0NanCond, Name lblNan, Name lblExit))
  builder <! (LMark lblNan)
  builder <! (c0 := AST.b1)
  builder <! (c2 := AST.b1)
  builder <! (c3 := AST.b1)
  builder <! (LMark lblExit)
  builder <! (getRegVar ctxt R.FSWC1 := AST.b0)
  endMark insAddr insLen builder

let fxam _ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let st0 = fpuRegValue ctxt R.ST0
  let exponent = AST.extract st0 15<rt> 64
  let maxExponent = BitVector.unsignedMax 15<rt> |> AST.num
  let tag7 = getRegVar ctxt R.FTW7
  let nanCond =
    (exponent == maxExponent) .& (AST.xtlo 62<rt> st0 != AST.num0 62<rt>)
  let c3Cond1 = (tag7 == numI32 3 2<rt>) .| (exponent == AST.num0 15<rt>)
  let c2Cond0 = (tag7 == numI32 3 2<rt>) .| (st0 == AST.num0 80<rt>) .| nanCond
  let c0Cond1 = (tag7 == numI32 3 2<rt>) .| (exponent == maxExponent)
  startMark insAddr insLen builder
  builder <! (getRegVar ctxt R.FSWC1 := AST.xthi 1<rt> st0)
  builder <! (getRegVar ctxt R.FSWC3 := AST.ite (c3Cond1) AST.b1 AST.b0)
  builder <! (getRegVar ctxt R.FSWC2 := AST.ite (c2Cond0) AST.b0 AST.b1)
  builder <! (getRegVar ctxt R.FSWC0 := AST.ite (c0Cond1) AST.b1 AST.b0)
  endMark insAddr insLen builder

let fsin ins insAddr insLen ctxt =
  ftrig ins insAddr insLen ctxt AST.fsin

let fcos ins insAddr insLen ctxt =
  ftrig ins insAddr insLen ctxt AST.fcos

let fsincos _ins insAddr insLen ctxt =
  let builder = StmtBuilder (64)
  let st0 = fpuRegValue ctxt R.ST0
  let c0 = getRegVar ctxt R.FSWC0
  let c1 = getRegVar ctxt R.FSWC1
  let c2 = getRegVar ctxt R.FSWC2
  let c3 = getRegVar ctxt R.FSWC3
  let float80SignUnmask = BitVector.signedMax 80<rt> |> AST.num
  let maxLimit = numI64 (1L <<< 63) 64<rt>
  let maxFloat = AST.cast CastKind.IntToFloat 80<rt> maxLimit
  let num3 = BitVector.ofInt32 3 2<rt> |> AST.num
  let lblOutOfRange = AST.symbol "IsOutOfRange"
  let lblInRange = AST.symbol "IsInRange"
  let tmp1, tmp2 = tmpVars2 80<rt>
  startMark insAddr insLen builder
  builder <! (tmp1 := st0 .& float80SignUnmask)
  builder <! (CJmp (AST.flt tmp1 maxFloat, Name lblInRange, Name lblOutOfRange ))
  builder <! (LMark lblInRange)
  builder <! (tmp1 := AST.fcos st0)
  builder <! (tmp2 := AST.fsin st0)
  assignFPUReg R.ST0 tmp2 ctxt builder
  builder <! (c1 := AST.ite (getRegVar ctxt R.FTW7 == num3) AST.b0 c1)
  builder <! (c2 := AST.b0)
  builder <! (c0 := undefC0)
  builder <! (c3 := undefC3)
  checkFPUOnLoad ctxt builder
  shiftFPUStackDown ctxt builder
  assignFPUReg R.ST0 tmp1 ctxt builder
  updateTagWordOnLoad ctxt builder
  builder <! (LMark lblOutOfRange)
  builder <! (c2 := AST.b1)
  builder <! (c0 := undefC0)
  builder <! (c1 := undefC1)
  builder <! (c3 := undefC3)
  endMark insAddr insLen builder

let fptan _ins insAddr insLen ctxt =
  let builder = StmtBuilder (64)
  let st0 = fpuRegValue ctxt R.ST0
  let float80SignUnmask = BitVector.signedMax 80<rt> |> AST.num
  let maxLimit = numI64 (1L <<< 63) 64<rt>
  let maxFloat = AST.cast CastKind.IntToFloat 80<rt> maxLimit
  let num3 = BitVector.ofInt32 3 2<rt> |> AST.num
  let c0 = getRegVar ctxt R.FSWC0
  let c1 = getRegVar ctxt R.FSWC1
  let c2 = getRegVar ctxt R.FSWC2
  let c3 = getRegVar ctxt R.FSWC3
  let lblOutOfRange = AST.symbol "IsOutOfRange"
  let lblInRange = AST.symbol "IsInRange"
  let tmp = AST.tmpvar 80<rt>
  let tmp64 = AST.tmpvar 64<rt>
  startMark insAddr insLen builder
  builder <! (tmp := st0 .& float80SignUnmask)
  builder <! (CJmp (AST.flt tmp maxFloat, Name lblInRange, Name lblOutOfRange ))
  builder <! (LMark lblInRange)
  builder <! (tmp := AST.ftan st0)
  assignFPUReg R.ST0 tmp ctxt builder
  builder <! (c1 := AST.ite (getRegVar ctxt R.FTW7 == num3) AST.b0 c1)
  builder <! (c2 := AST.b0)
  builder <! (c0 := undefC0)
  builder <! (c3 := undefC3)
  builder <! (LMark lblOutOfRange)
  builder <! (c2 := AST.b1)
  builder <! (c0 := undefC0)
  builder <! (c1 := undefC1)
  builder <! (c3 := undefC3)
  builder <! (tmp64 := numI64 4607182418800017408L 64<rt>)
  builder <! (tmp := AST.cast CastKind.FloatExt 80<rt> tmp64)
  checkFPUOnLoad ctxt builder
  shiftFPUStackDown ctxt builder
  assignFPUReg R.ST0 tmp ctxt builder
  updateTagWordOnLoad ctxt builder
  endMark insAddr insLen builder

let fpatan _ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let c1 = getRegVar ctxt R.FSWC1
  let tmp = AST.tmpvar 80<rt>
  startMark insAddr insLen builder
  builder <! (tmp := fpuRegValue ctxt R.ST1 ./ fpuRegValue ctxt R.ST0)
  builder <! (tmp := AST.fatan tmp)
  assignFPUReg R.ST1 tmp ctxt builder
  builder <! (c1 := AST.b0)
  cflagsUndefined023 ctxt builder
  endMark insAddr insLen builder

let f2xm1 _isn insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let st0 = fpuRegValue ctxt R.ST0
  let flt1 = AST.num1 32<rt> |> AST.cast CastKind.IntToFloat 80<rt>
  let flt2 = numI32 2 32<rt> |> AST.cast CastKind.IntToFloat 80<rt>
  let tmp = AST.tmpvar 80<rt>
  startMark insAddr insLen builder
  builder <! (tmp := AST.fpow flt2 st0)
  builder <! (tmp := AST.fsub tmp flt1)
  assignFPUReg R.ST0 tmp ctxt builder
  checkC1Flag ctxt builder R.FTW7
  cflagsUndefined023 ctxt builder
  endMark insAddr insLen builder

let fyl2x _ins insAddr insLen ctxt =
  let builder = StmtBuilder (64)
  let st0 = fpuRegValue ctxt R.ST0
  let st1 = fpuRegValue ctxt R.ST1
  let flt2 = numI32 2 32<rt> |> AST.cast CastKind.IntToFloat 80<rt>
  let t1, t2 = tmpVars2 80<rt>
  startMark insAddr insLen builder
  builder <! (t1 := AST.flog flt2 st0)
  builder <! (t2 := AST.fmul st1 t1)
  assignFPUReg R.ST1 t2 ctxt builder
  popFPUStack ctxt builder
  checkC1Flag ctxt builder R.FTW6
  cflagsUndefined023 ctxt builder
  endMark insAddr insLen builder

let fyl2xp1 _ins insAddr insLen ctxt =
  let builder = StmtBuilder (64)
  let st0 = fpuRegValue ctxt R.ST0
  let st1 = fpuRegValue ctxt R.ST1
  let flt2 = numI32 2 32<rt> |> AST.cast CastKind.IntToFloat 80<rt>
  let f1 = numI32 1 32<rt> |> AST.cast CastKind.IntToFloat 80<rt>
  let tmp = AST.tmpvar 80<rt>
  startMark insAddr insLen builder
  builder <! (tmp := AST.fadd f1 (AST.flog flt2 st0))
  builder <! (tmp := AST.fmul st1 tmp)
  assignFPUReg R.ST1 tmp ctxt builder
  popFPUStack ctxt builder
  checkC1Flag ctxt builder R.FTW6
  cflagsUndefined023 ctxt builder
  endMark insAddr insLen builder

let fld1 _ins insAddr insLen ctxt =
  let oprExpr = BitVector.ofUInt64 0x3FF0000000000000UL 64<rt> |> AST.num
  fpuLoad insAddr insLen ctxt oprExpr

let fldz _ins insAddr insLen ctxt =
  let oprExpr = AST.num0 64<rt>
  fpuLoad insAddr insLen ctxt oprExpr

let fldpi _ins insAddr insLen ctxt =
  let oprExpr = BitVector.ofUInt64 4614256656552045848UL 64<rt> |> AST.num
  fpuLoad insAddr insLen ctxt oprExpr

let fldl2e _ins insAddr insLen ctxt =
  let oprExpr = BitVector.ofUInt64 4599094494223104509UL 64<rt> |> AST.num
  fpuLoad insAddr insLen ctxt oprExpr

let fldln2 _ins insAddr insLen ctxt =
  let oprExpr = BitVector.ofUInt64 4604418534313441775UL 64<rt> |> AST.num
  fpuLoad insAddr insLen ctxt oprExpr

let fldl2t _ins insAddr insLen ctxt =
  let oprExpr = BitVector.ofUInt64 4614662735865160561UL 64<rt> |> AST.num
  fpuLoad insAddr insLen ctxt oprExpr

let fldlg2 _ins insAddr insLen ctxt =
  let oprExpr = BitVector.ofUInt64 4599094494223104511UL 64<rt> |> AST.num
  fpuLoad insAddr insLen ctxt oprExpr

let fincstp _ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let top = getRegVar ctxt R.FTOP
  startMark insAddr insLen builder
  builder <! (top := top .+ AST.num1 3<rt>)
  builder <! (getRegVar ctxt R.FSWC1 := AST.b0)
  builder <! (getRegVar ctxt R.FSWC0 := undefC0)
  builder <! (getRegVar ctxt R.FSWC2 := undefC2)
  builder <! (getRegVar ctxt R.FSWC3 := undefC3)
  endMark insAddr insLen builder

let fdecstp _ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let top = getRegVar ctxt R.FTOP
  startMark insAddr insLen builder
  builder <! (top := top .+ AST.num1 3<rt>)
  builder <! (getRegVar ctxt R.FSWC1 := AST.b0)
  builder <! (getRegVar ctxt R.FSWC0 := undefC0)
  builder <! (getRegVar ctxt R.FSWC2 := undefC2)
  builder <! (getRegVar ctxt R.FSWC3 := undefC3)
  endMark insAddr insLen builder

let ffree ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let top = getRegVar ctxt R.FTOP
  let tagWord = getRegVar ctxt R.FTW
  let top16,shifter, tagValue = tmpVars3 16<rt>
  let value3 = BitVector.ofInt32 3 16<rt> |> AST.num
  let offset =
    match getOneOpr ins with
    | OprReg R.ST0 -> BitVector.ofInt32 0 16<rt> |> AST.num
    | OprReg R.ST1 -> BitVector.ofInt32 1 16<rt> |> AST.num
    | OprReg R.ST2 -> BitVector.ofInt32 2 16<rt> |> AST.num
    | OprReg R.ST3 -> BitVector.ofInt32 3 16<rt> |> AST.num
    | OprReg R.ST4 -> BitVector.ofInt32 4 16<rt> |> AST.num
    | OprReg R.ST5 -> BitVector.ofInt32 5 16<rt> |> AST.num
    | OprReg R.ST6 -> BitVector.ofInt32 6 16<rt> |> AST.num
    | OprReg R.ST7 -> BitVector.ofInt32 7 16<rt> |> AST.num
    | _ -> raise InvalidOperandException
  startMark insAddr insLen builder
  builder <! (top16 := AST.cast CastKind.ZeroExt 16<rt> top)
  builder <! (top16 := top16 .+ offset)
  builder <! (shifter := (BitVector.ofInt32 2 16<rt> |> AST.num) .* top16)
  builder <! (tagValue := (value3 << shifter))
  builder <! (tagWord := tagWord .| tagValue)
  endMark insAddr insLen builder

(* FIXME: check all unmasked pending floating point exceptions. *)
let private checkFPUExceptions ctxt builder = ()

let private clearFPU ctxt builder =
  let cw = BitVector.ofInt32 895 16<rt> |> AST.num
  let tw = BitVector.maxNum16 |> AST.num
  builder <! (getRegVar ctxt R.FCW := cw)
  builder <! (getRegVar ctxt R.FSW := AST.num0 16<rt>)
  builder <! (getRegVar ctxt R.FTW := tw)

let finit _ins insAddr insLen ctxt =
  let builder = StmtBuilder (32)
  startMark insAddr insLen builder
  checkFPUExceptions ctxt builder
  clearFPU ctxt builder
  endMark insAddr insLen builder

let fninit _ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  startMark insAddr insLen builder
  clearFPU ctxt builder
  endMark insAddr insLen builder

let fclex _ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let stsWrd = getRegVar ctxt R.FSW
  startMark insAddr insLen builder
  builder <! (AST.xtlo 7<rt> stsWrd := AST.num0 7<rt>)
  builder <! (AST.xthi 1<rt> stsWrd := AST.b0)
  builder <! (getRegVar ctxt R.FSWC0 := undefC0)
  builder <! (getRegVar ctxt R.FSWC1 := undefC1)
  builder <! (getRegVar ctxt R.FSWC2 := undefC2)
  builder <! (getRegVar ctxt R.FSWC3 := undefC3)
  endMark insAddr insLen builder

let fstcw ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let oprExpr = getOneOpr ins |> transOprToExpr ins insAddr insLen ctxt
  startMark insAddr insLen builder
  checkFPUExceptions ctxt builder
  builder <! (oprExpr := getRegVar ctxt R.FCW)
  allCFlagsUndefined ctxt builder
  endMark insAddr insLen builder

let fnstcw ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let oprExpr = getOneOpr ins |> transOprToExpr ins insAddr insLen ctxt
  startMark insAddr insLen builder
  builder <! (oprExpr := getRegVar ctxt R.FCW)
  allCFlagsUndefined ctxt builder
  endMark insAddr insLen builder

let fldcw ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let oprExpr = getOneOpr ins |> transOprToExpr ins insAddr insLen ctxt
  startMark insAddr insLen builder
  builder <! (getRegVar ctxt R.FCW := oprExpr)
  builder <! (getRegVar ctxt R.FSWC0 := undefC0)
  builder <! (getRegVar ctxt R.FSWC1 := undefC1)
  builder <! (getRegVar ctxt R.FSWC2 := undefC2)
  builder <! (getRegVar ctxt R.FSWC3 := undefC3)
  endMark insAddr insLen builder

let fstenv ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let dst = getOneOpr ins |> transOprToExpr ins insAddr insLen ctxt
  startMark insAddr insLen builder
  match AST.typeOf dst with
  | 112<rt> -> m14Stenv dst ctxt builder
  | 224<rt> -> m28fstenv dst ctxt builder
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let fldenv ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let src = getOneOpr ins |> transOprToExpr ins insAddr insLen ctxt
  startMark insAddr insLen builder
  match AST.typeOf src with
  | 112<rt> -> m14fldenv src ctxt builder
  | 224<rt> -> m28fldenv src ctxt builder
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let private stSts dst ctxt builder =
  let v r = getRegVar ctxt r
  builder <! (AST.xtlo 80<rt> dst := v R.ST0)
  builder <! (AST.extract dst 80<rt> 80 := v R.ST1)
  builder <! (AST.extract dst 80<rt> 160 := v R.ST2)
  builder <! (AST.extract dst 80<rt> 240 := v R.ST3)
  builder <! (AST.extract dst 80<rt> 320 := v R.ST4)
  builder <! (AST.extract dst 80<rt> 400 := v R.ST5)
  builder <! (AST.extract dst 80<rt> 480 := v R.ST6)
  builder <! (AST.extract dst 80<rt> 560 := v R.ST7)

let fsave ins insAddr insLen ctxt =
  let builder = StmtBuilder (32)
  let dst = getOneOpr ins |> transOprToExpr ins insAddr insLen ctxt
  let v r = getRegVar ctxt r
  startMark insAddr insLen builder
  m14Stenv (AST.xtlo 112<rt> dst) ctxt builder
  stSts (AST.xthi 640<rt> dst) ctxt builder
  builder <! (v R.FCW := numI32 0x037F 16<rt>)
  builder <! (v R.FSW := AST.num0 16<rt>)
  builder <! (v R.FTW := numI32 0xFFFF 16<rt>)
  builder <! (v R.FDP := AST.num0 16<rt>)
  builder <! (v R.FIP := AST.num0 16<rt>)
  builder <! (v R.FOP := AST.num0 16<rt>)
  endMark insAddr insLen builder

let private ldSts src ctxt builder =
  assignFPUReg R.ST0 (AST.xtlo 80<rt> src) ctxt builder
  assignFPUReg R.ST1 (AST.extract src 80<rt> 80) ctxt builder
  assignFPUReg R.ST2 (AST.extract src 80<rt> 160) ctxt builder
  assignFPUReg R.ST3 (AST.extract src 80<rt> 240) ctxt builder
  assignFPUReg R.ST4 (AST.extract src 80<rt> 320) ctxt builder
  assignFPUReg R.ST5 (AST.extract src 80<rt> 400) ctxt builder
  assignFPUReg R.ST6 (AST.extract src 80<rt> 480) ctxt builder
  assignFPUReg R.ST7 (AST.extract src 80<rt> 560) ctxt builder

let frstor ins insAddr insLen ctxt =
  let builder = StmtBuilder (32)
  let src = getOneOpr ins |> transOprToExpr ins insAddr insLen ctxt
  startMark insAddr insLen builder
  match AST.typeOf src with
  | 752<rt> ->
    m14fldenv (AST.xtlo 112<rt> src) ctxt builder
  | 864<rt> ->
    m28fldenv (AST.xtlo 224<rt> src) ctxt builder
  | _ -> raise InvalidOperandSizeException
  ldSts (AST.xthi 640<rt> src) ctxt builder
  endMark insAddr insLen builder

let fstsw ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let oprExpr = getOneOpr ins |> transOprToExpr ins insAddr insLen ctxt
  startMark insAddr insLen builder
  checkFPUExceptions ctxt builder
  builder <! (oprExpr := getRegVar ctxt R.FSW)
  allCFlagsUndefined ctxt builder
  endMark insAddr insLen builder

let fnstsw ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let oprExpr = getOneOpr ins |> transOprToExpr ins insAddr insLen ctxt
  startMark insAddr insLen builder
  builder <! (oprExpr := getRegVar ctxt R.FSW)
  allCFlagsUndefined ctxt builder
  endMark insAddr insLen builder

let wait _ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  startMark insAddr insLen builder
  allCFlagsUndefined ctxt builder
  endMark insAddr insLen builder

let fnop _ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  startMark insAddr insLen builder
  allCFlagsUndefined ctxt builder
  endMark insAddr insLen builder

let private updateAddrByOffset addr offset =
  match addr with
  (* Save *)
  | Load (_, _, BinOp (_, _, BinOp (_, _, reg, _, _, _), _, _, _), _, _) ->
    reg := reg .+ offset (* SIB *)
  | Load (_, _, BinOp (_, _, e, _, _, _), _, _) ->
    e := e .+ offset (* Displacemnt *)
  | Load (_, _, expr, _, _) -> expr := expr .+ offset
  | _ -> Utils.impossible ()

let private getAddrRegSize = function
  (* Save *)
  | Load (_, _, Var (t, _, _, _), _, _) -> t
  | Load (_, _, BinOp (_, t, _, _, _, _), _, _) -> t
  (* Load *)
  | TempVar (t, _) -> t
  | _ -> Utils.impossible ()

let private getBaseReg = function
  | Load (_, _, BinOp (_, _, BinOp (_, _, reg, _, _, _), _, _, _), _, _) -> reg
  | Load (_, _, BinOp (_, _, e, _, _, _), _, _) -> e
  | Load (_, _, expr, _, _) -> expr
  | _ -> Utils.impossible ()

let private extendAddr src regType =
  match src with
  | Load (e, _, expr, _, _) -> AST.load e regType expr
  | _ -> Utils.impossible ()

let private saveFxsaveMMX addr offset grv builder =
  let r64 = AST.num0 64<rt>
  let mRegs = [ r64; grv R.MM0; r64; grv R.MM1; r64; grv R.MM2; r64; grv R.MM3;
                r64; grv R.MM4; r64; grv R.MM5; r64; grv R.MM6; r64; grv R.MM7 ]
  List.iter (fun reg -> builder <! (updateAddrByOffset addr offset)
                        builder <! (addr := reg)) mRegs

let private loadFxrstorMMX addr grv builder =
  let offset = AST.num (BitVector.ofInt32 16 (getAddrRegSize addr))
  let mRegs = [ R.MM0; R.MM1; R.MM2; R.MM3; R.MM4; R.MM5; R.MM6; R.MM7 ]
  List.iter (fun reg -> builder <! (updateAddrByOffset addr (offset))
                        builder <! (grv reg := addr)) mRegs

let private saveFxsaveXMM ctxt addr offset xRegs builder =
  let pv r = getPseudoRegVar128 ctxt r
  let exprs =
    List.fold(fun acc r -> let r2, r1 = pv r in r1 :: (r2 :: acc)) [] xRegs
  List.iter (fun reg -> builder <! (updateAddrByOffset addr offset)
                        builder <! (addr := reg)) exprs

let private loadFxrstorXMM ctxt addr xRegs builder =
  let pv r = getPseudoRegVar128 ctxt r
  let offset = AST.num (BitVector.ofInt32 8 (getAddrRegSize addr))
  let exprs =
    List.fold (fun acc r -> let r2, r1 = pv r in r1 :: (r2 :: acc)) [] xRegs
  List.iter (fun reg -> builder <! (updateAddrByOffset addr offset)
                        builder <! (reg := addr)) exprs

let private save64BitPromotedFxsave ctxt dst builder =
  let reserved8 = AST.num0 8<rt>
  let num3 = numI32 3 2<rt>
  let v r = getRegVar ctxt r
  let t0, t1, t2, t3 = tmpVars4 1<rt>
  let t4, t5, t6, t7 = tmpVars4 1<rt>
  let abrTagW = AST.tmpvar 8<rt>
  let offset = AST.num (BitVector.ofInt32 8 (getAddrRegSize dst))
  let regSave = AST.tmpvar (getAddrRegSize dst)
  let baseReg = getBaseReg dst
  let xRegs =
    [ R.XMM0; R.XMM1; R.XMM2; R.XMM3; R.XMM4; R.XMM5; R.XMM6; R.XMM7;
      R.XMM8; R.XMM9; R.XMM10; R.XMM11; R.XMM12; R.XMM13; R.XMM14; R.XMM15 ]
  builder <! (regSave := baseReg)
  builder <! (abrTagW := AST.concat (AST.concat (AST.concat t7 t6) (AST.concat t5 t4))
                                (AST.concat (AST.concat t3 t2) (AST.concat t1 t0)))
  builder <! (t0 := (v R.FTW0 != num3))
  builder <! (t1 := (v R.FTW1 != num3))
  builder <! (t2 := (v R.FTW2 != num3))
  builder <! (t3 := (v R.FTW3 != num3))
  builder <! (t4 := (v R.FTW4 != num3))
  builder <! (t5 := (v R.FTW5 != num3))
  builder <! (t6 := (v R.FTW6 != num3))
  builder <! (t7 := (v R.FTW7 != num3))
  builder <! (dst := AST.concat (AST.concat (v R.FOP) (AST.concat reserved8 abrTagW))
                            (AST.concat (v R.FSW) (v R.FCW)))
  builder <! (updateAddrByOffset dst offset)
  builder <! (dst := v R.FIP)
  builder <! (updateAddrByOffset dst offset)
  builder <! (dst := v R.FDP)
  builder <! (updateAddrByOffset dst offset)
  builder <! (dst := AST.concat (v R.MXCSRMASK) (v R.MXCSR))
  saveFxsaveMMX dst offset v builder
  saveFxsaveXMM ctxt dst offset (List.rev xRegs) builder
  builder <! (baseReg := regSave)

let private save64BitDefaultFxsave ctxt dst builder =
  let reserved8 = AST.num0 8<rt>
  let reserved16 = AST.num0 16<rt>
  let num3 = numI32 3 2<rt>
  let v r = getRegVar ctxt r
  let t0, t1, t2, t3 = tmpVars4 1<rt>
  let t4, t5, t6, t7 = tmpVars4 1<rt>
  let abrTagW = AST.tmpvar 8<rt>
  let offset = AST.num (BitVector.ofInt32 8 (getAddrRegSize dst))
  let regSave = AST.tmpvar (getAddrRegSize dst)
  let baseReg = getBaseReg dst
  let xRegs =
    [ R.XMM0; R.XMM1; R.XMM2; R.XMM3; R.XMM4; R.XMM5; R.XMM6; R.XMM7;
      R.XMM8; R.XMM9; R.XMM10; R.XMM11; R.XMM12; R.XMM13; R.XMM14; R.XMM15 ]
  builder <! (regSave := baseReg)
  builder <! (t0 := (v R.FTW0 != num3))
  builder <! (t1 := (v R.FTW1 != num3))
  builder <! (t2 := (v R.FTW2 != num3))
  builder <! (t3 := (v R.FTW3 != num3))
  builder <! (t4 := (v R.FTW4 != num3))
  builder <! (t5 := (v R.FTW5 != num3))
  builder <! (t6 := (v R.FTW6 != num3))
  builder <! (t7 := (v R.FTW7 != num3))
  builder <! (abrTagW := AST.concat (AST.concat (AST.concat t7 t6) (AST.concat t5 t4))
                                (AST.concat (AST.concat t3 t2) (AST.concat t1 t0)))
  builder <! (dst := AST.concat (AST.concat (v R.FOP) (AST.concat reserved8 abrTagW))
                            (AST.concat (v R.FSW) (v R.FCW)))
  builder <! (updateAddrByOffset dst offset)
  builder <! (dst := AST.concat (AST.xtlo 32<rt> (v R.FIP))
                            (AST.concat (v R.FCS) reserved16))
  builder <! (updateAddrByOffset dst offset)
  builder <! (dst := AST.concat (AST.xtlo 32<rt> (v R.FDP))
                            (AST.concat (v R.FDS) reserved16))
  builder <! (updateAddrByOffset dst offset)
  builder <! (dst := AST.concat (v R.MXCSRMASK) (v R.MXCSR))
  saveFxsaveMMX dst offset v builder
  saveFxsaveXMM ctxt dst offset (List.rev xRegs) builder
  builder <! (baseReg := regSave)

let private saveLegacyFxsave ctxt dst builder =
  let reserved8 = AST.num0 8<rt>
  let reserved16 = AST.num0 16<rt>
  let num3 = numI32 3 2<rt>
  let v r = getRegVar ctxt r
  let t0, t1, t2, t3 = tmpVars4 1<rt>
  let t4, t5, t6, t7 = tmpVars4 1<rt>
  let abrTagW = AST.tmpvar 8<rt>
  let offset = AST.num (BitVector.ofInt32 8 (getAddrRegSize dst))
  let regSave = AST.tmpvar (getAddrRegSize dst)
  let baseReg = getBaseReg dst
  let xRegs = [ R.XMM0; R.XMM1; R.XMM2; R.XMM3; R.XMM4; R.XMM5; R.XMM6; R.XMM7 ]
  builder <! (regSave := baseReg)
  builder <! (t0 := (v R.FTW0 != num3))
  builder <! (t1 := (v R.FTW1 != num3))
  builder <! (t2 := (v R.FTW2 != num3))
  builder <! (t3 := (v R.FTW3 != num3))
  builder <! (t4 := (v R.FTW4 != num3))
  builder <! (t5 := (v R.FTW5 != num3))
  builder <! (t6 := (v R.FTW6 != num3))
  builder <! (t7 := (v R.FTW7 != num3))
  builder <! (abrTagW := AST.concat (AST.concat (AST.concat t7 t6) (AST.concat t5 t4))
                                (AST.concat (AST.concat t3 t2) (AST.concat t1 t0)))
  builder <! (dst := AST.concat (AST.concat (v R.FOP) (AST.concat reserved8 abrTagW))
                            (AST.concat (v R.FSW) (v R.FCW)))
  builder <! (updateAddrByOffset dst offset)
  builder <!
    (dst := AST.concat (AST.xtlo 32<rt> (v R.FIP)) (AST.concat (v R.FCS) reserved16))
  builder <! (updateAddrByOffset dst offset)
  builder <! (dst := AST.concat (AST.xtlo 32<rt> (v R.FDP))
                            (AST.concat (v R.FDS) reserved16))
  builder <! (updateAddrByOffset dst offset)
  builder <! (dst := AST.concat (v R.MXCSRMASK) (v R.MXCSR))
  saveFxsaveMMX dst offset v builder
  saveFxsaveXMM ctxt dst offset (List.rev xRegs) builder
  builder <! (baseReg := regSave)

let private load64BitPromotedFxrstor ctxt src builder =
  let grv r = getRegVar ctxt r
  let offset = AST.num (BitVector.ofInt32 8 (getAddrRegSize src))
  let xRegs =
    [ R.XMM0; R.XMM1; R.XMM2; R.XMM3; R.XMM4; R.XMM5; R.XMM6; R.XMM7;
      R.XMM8; R.XMM9; R.XMM10; R.XMM11; R.XMM12; R.XMM13; R.XMM14; R.XMM15 ]
  let tSrc = AST.tmpvar 64<rt>
  builder <! (tSrc := src)
  builder <! (grv R.FCW := AST.xtlo 16<rt> tSrc)
  builder <! (grv R.FSW := AST.extract tSrc 16<rt> 16)
  builder <! (grv R.FTW := AST.extract tSrc 8<rt> 32)
  builder <! (grv R.FOP := AST.extract tSrc 16<rt> 48)
  builder <! (updateAddrByOffset src offset)
  builder <! (tSrc := src)
  builder <! (grv R.FIP := tSrc)
  builder <! (updateAddrByOffset src offset)
  builder <! (tSrc := src)
  builder <! (grv R.FDP := tSrc)
  builder <! (updateAddrByOffset src offset)
  builder <! (tSrc := src)
  builder <! (grv R.MXCSR := AST.xtlo 32<rt> tSrc)
  builder <! (grv R.MXCSRMASK := AST.xthi 32<rt> tSrc)
  loadFxrstorMMX src grv builder
  loadFxrstorXMM ctxt src xRegs builder

let private load64BitDefaultFxrstor ctxt src builder =
  let grv r = getRegVar ctxt r
  let offset = AST.num (BitVector.ofInt32 8 (getAddrRegSize src))
  let regSave = AST.tmpvar (getAddrRegSize src)
  let baseReg = getBaseReg src
  let t0, t1, t2, t3 = tmpVars4 2<rt>
  let t4, t5, t6, t7 = tmpVars4 2<rt>
  let tmp8 = AST.tmpvar 8<rt>
  let zero2 = AST.num0 2<rt>
  let three2 = numI32 3 2<rt>
  let xRegs =
    [ R.XMM0; R.XMM1; R.XMM2; R.XMM3; R.XMM4; R.XMM5; R.XMM6; R.XMM7;
      R.XMM8; R.XMM9; R.XMM10; R.XMM11; R.XMM12; R.XMM13; R.XMM14; R.XMM15 ]
  builder <! (regSave := baseReg)
  builder <! (tmp8 := AST.extract src 8<rt> 32)
  builder <! (t0 := AST.ite (AST.xtlo 1<rt> tmp8) zero2 three2)
  builder <! (t1 := AST.ite (AST.extract tmp8 1<rt> 1) zero2 three2)
  builder <! (t2 := AST.ite (AST.extract tmp8 1<rt> 2) zero2 three2)
  builder <! (t3 := AST.ite (AST.extract tmp8 1<rt> 3) zero2 three2)
  builder <! (t4 := AST.ite (AST.extract tmp8 1<rt> 4) zero2 three2)
  builder <! (t5 := AST.ite (AST.extract tmp8 1<rt> 5) zero2 three2)
  builder <! (t6 := AST.ite (AST.extract tmp8 1<rt> 6) zero2 three2)
  builder <! (t7 := AST.ite (AST.extract tmp8 1<rt> 7) zero2 three2)
  builder <! (grv R.FCW := AST.xtlo 16<rt> src)
  builder <! (grv R.FSW := AST.extract src 16<rt> 16)
  builder <! (grv R.FTW := AST.concat (AST.concat (AST.concat t7 t6) (AST.concat t5 t4))
                                  (AST.concat (AST.concat t3 t2) (AST.concat t1 t0)))
  builder <! (grv R.FOP := AST.extract src 16<rt> 48)
  builder <! (updateAddrByOffset src offset)
  builder <! (AST.xtlo 32<rt> (grv R.FIP) := AST.xtlo 32<rt> src)
  builder <! (grv R.FCS := AST.extract src 16<rt> 32)
  builder <! (updateAddrByOffset src offset)
  builder <! (AST.xtlo 32<rt> (grv R.FDP) := AST.xtlo 32<rt> src)
  builder <! (grv R.FDS := AST.extract src 16<rt> 32)
  builder <! (updateAddrByOffset src offset)
  builder <! (grv R.MXCSR := AST.xtlo 32<rt> src)
  builder <! (grv R.MXCSRMASK := AST.xthi 32<rt> src)
  loadFxrstorMMX src grv builder
  loadFxrstorXMM ctxt src (List.rev xRegs) builder
  builder <! (baseReg := regSave)

let private loadLegacyFxrstor ctxt src builder =
  let grv r = getRegVar ctxt r
  let offset = AST.num (BitVector.ofInt32 8 (getAddrRegSize src))
  let xRegs = [ R.XMM0; R.XMM1; R.XMM2; R.XMM3; R.XMM4; R.XMM5; R.XMM6; R.XMM7 ]
  let tSrc = AST.tmpvar 64<rt>
  builder <! (tSrc := src)
  builder <! (grv R.FCW := AST.xtlo 16<rt> tSrc)
  builder <! (grv R.FSW := AST.extract tSrc 16<rt> 16)
  builder <! (grv R.FTW := AST.extract tSrc 8<rt> 32)
  builder <! (grv R.FOP := AST.extract tSrc 16<rt> 48)
  builder <! (updateAddrByOffset src offset)
  builder <! (tSrc := src)
  builder <! (AST.xtlo 32<rt> (grv R.FIP) := AST.xtlo 32<rt> tSrc)
  builder <! (grv R.FCS := AST.extract tSrc 16<rt> 32)
  builder <! (updateAddrByOffset src offset)
  builder <! (tSrc := src)
  builder <! (AST.xtlo 32<rt> (grv R.FDP) := AST.xtlo 32<rt> tSrc)
  builder <! (grv R.FDS := AST.extract tSrc 16<rt> 32)
  builder <! (updateAddrByOffset src offset)
  builder <! (tSrc := src)
  builder <! (grv R.MXCSR := AST.xtlo 32<rt> tSrc)
  builder <! (grv R.MXCSRMASK := AST.xthi 32<rt>tSrc)
  loadFxrstorMMX src grv builder
  loadFxrstorXMM ctxt src xRegs builder

let fxrstor ins insAddr insLen ctxt =
  let builder = StmtBuilder (128)
  let src = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  let eSrc = extendAddr src 64<rt>
  startMark insAddr insLen builder
  if ctxt.WordBitSize = 64<rt> then
    if hasREXW ins.REXPrefix then load64BitPromotedFxrstor ctxt eSrc builder
    else load64BitDefaultFxrstor ctxt eSrc builder
  else loadLegacyFxrstor ctxt eSrc builder
  endMark insAddr insLen builder

let fxsave ins insAddr insLen ctxt =
  let builder = StmtBuilder (128)
  let dst = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  let eDst = extendAddr dst 64<rt>
  startMark insAddr insLen builder
  if ctxt.WordBitSize = 64<rt> then
    if hasREXW ins.REXPrefix then save64BitPromotedFxsave ctxt eDst builder
    else save64BitDefaultFxsave ctxt eDst builder
  else saveLegacyFxsave ctxt eDst builder
  endMark insAddr insLen builder
