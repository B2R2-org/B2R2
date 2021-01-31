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
open B2R2.FrontEnd.BinLifter.Intel
open B2R2.FrontEnd.BinLifter.Intel.Helper
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

let private getFPUPseudoRegVars ctxt r =
  getPseudoRegVar ctxt r 2, getPseudoRegVar ctxt r 1

let private checkC1Flag ctxt ir topTagReg =
  let c1 = !.ctxt R.FSWC1
  let tagV = !.ctxt topTagReg
  let rc = AST.extract (!.ctxt R.FCW) 2<rt> 10
  !!ir (c1 := AST.ite (rc == numI32 2 2<rt>) AST.b1 AST.b0)
  !!ir (c1 := AST.ite (tagV == numI32 3 2<rt>) AST.b0 c1)

let private checkFPUOnLoad ctxt ir =
  let top = !.ctxt R.FTOP
  let c1Flag = !.ctxt R.FSWC1
  let struct (cond1, cond2) = tmpVars2 1<rt>
  !!ir (cond1 := top == AST.num0 3<rt>)
  !!ir (cond2 := (!.ctxt R.FTW0 .+ AST.num1 2<rt>) != AST.num0 2<rt>)
  !!ir (c1Flag := AST.ite (cond1 .& cond2) AST.b1 AST.b0)
  !!ir (!.ctxt R.FSWC0 := undefC0)
  !!ir (!.ctxt R.FSWC2 := undefC2)
  !!ir (!.ctxt R.FSWC3 := undefC3)
  !!ir (top := top .- AST.num1 3<rt>)

let private fpuRegValue ctxt reg =
  let stb, sta = getFPUPseudoRegVars ctxt reg
  AST.concat stb sta

let private assignFPUReg reg expr80 ctxt ir =
  let stb, sta = getFPUPseudoRegVars ctxt reg
  !!ir (sta := AST.xtlo 64<rt> expr80)
  !!ir (stb := AST.xthi 16<rt> expr80)

let private getTagValueOnLoad ctxt ir =
  let tmp = AST.tmpvar 2<rt>
  let st0 = fpuRegValue ctxt R.ST0
  let exponent = AST.extract st0 11<rt> 52
  let zero = AST.num0 11<rt>
  let max = BitVector.unsignedMax 11<rt> |> AST.num
  let cond0 = (AST.xtlo 63<rt> st0) == AST.num0 63<rt>
  let condSpecial = (exponent == zero) .| (exponent == max)
  !!ir (tmp := AST.num0 2<rt>)
  !!ir (tmp := AST.ite condSpecial (BitVector.ofInt32 2 2<rt> |> AST.num) tmp)
  !!ir (tmp := AST.ite cond0 (AST.num1 2<rt>) tmp)
  tmp

let private updateTagWordOnLoad ctxt ir =
  let top = !.ctxt R.FTOP
  let tagWord = !.ctxt R.FTW
  let struct (top16, mask, shifter, tagValue16) = tmpVars4 16<rt>
  let tagValue = getTagValueOnLoad ctxt ir
  let value3 = BitVector.ofInt32 3 16<rt> |> AST.num
  !!ir (top16 := AST.cast CastKind.ZeroExt 16<rt> top)
  !!ir (shifter := (BitVector.ofInt32 2 16<rt> |> AST.num) .* top16)
  !!ir (tagValue16 := AST.cast CastKind.ZeroExt 16<rt> tagValue)
  !!ir (tagValue16 := (tagValue16 << shifter))
  !!ir (mask := value3 << shifter)
  !!ir (tagWord := tagWord .& (AST.not mask))
  !!ir (tagWord := tagWord .| tagValue16)

let private updateTagWordOnPop ctxt ir =
  let top = !.ctxt R.FTOP
  let tagWord = !.ctxt R.FTW
  let struct (top16, mask, shifter, tagValue16) = tmpVars4 16<rt>
  let value3 = BitVector.ofInt32 3 16<rt> |> AST.num
  !!ir (top16 := AST.cast CastKind.ZeroExt 16<rt> top)
  !!ir (shifter := (BitVector.ofInt32 2 16<rt> |> AST.num) .* top16)
  !!ir (mask := value3 << shifter)
  !!ir (tagWord := tagWord .| mask)

let private shiftFPUStackDown ctxt ir =
  !?ir (assignFPUReg R.ST7 (fpuRegValue ctxt R.ST6) ctxt)
  !?ir (assignFPUReg R.ST6 (fpuRegValue ctxt R.ST5) ctxt)
  !?ir (assignFPUReg R.ST5 (fpuRegValue ctxt R.ST4) ctxt)
  !?ir (assignFPUReg R.ST4 (fpuRegValue ctxt R.ST3) ctxt)
  !?ir (assignFPUReg R.ST3 (fpuRegValue ctxt R.ST2) ctxt)
  !?ir (assignFPUReg R.ST2 (fpuRegValue ctxt R.ST1) ctxt)
  !?ir (assignFPUReg R.ST1 (fpuRegValue ctxt R.ST0) ctxt)

let private popFPUStack ctxt ir =
  let top = !.ctxt R.FTOP
  let c1Flag = !.ctxt R.FSWC1
  let struct (cond1, cond2) = tmpVars2 1<rt>
  !?ir (assignFPUReg R.ST0 (fpuRegValue ctxt R.ST1) ctxt)
  !?ir (assignFPUReg R.ST1 (fpuRegValue ctxt R.ST2) ctxt)
  !?ir (assignFPUReg R.ST2 (fpuRegValue ctxt R.ST3) ctxt)
  !?ir (assignFPUReg R.ST3 (fpuRegValue ctxt R.ST4) ctxt)
  !?ir (assignFPUReg R.ST4 (fpuRegValue ctxt R.ST5) ctxt)
  !?ir (assignFPUReg R.ST5 (fpuRegValue ctxt R.ST6) ctxt)
  !?ir (assignFPUReg R.ST6 (fpuRegValue ctxt R.ST7) ctxt)
  !?ir (assignFPUReg R.ST7 (AST.num0 80<rt>) ctxt)
  !!ir (cond1 := top == AST.num0 3<rt>)
  !!ir (cond2 := (!.ctxt R.FTW7 .+ AST.num1 2<rt>) == AST.num0 2<rt>)
  !!ir (c1Flag := AST.ite (cond1 .& cond2) (AST.b0) (c1Flag))
  !!ir (!.ctxt R.FSWC0 := undefC0)
  !!ir (!.ctxt R.FSWC2 := undefC2)
  !!ir (!.ctxt R.FSWC3 := undefC3)
  updateTagWordOnPop ctxt ir
  !!ir (top := top .+ AST.num1 3<rt>)

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

let private m14Stenv dst ctxt ir =
  let tmp = AST.tmpvar 112<rt>
  !!ir (tmp := AST.num0 112<rt>)
  !!ir (AST.xtlo 48<rt> tmp :=
    AST.concat (!.ctxt R.FCW) (AST.concat (!.ctxt R.FSW) (!.ctxt R.FTW)))
  !!ir (AST.extract tmp 16<rt> 48 := AST.xtlo 16<rt> (!.ctxt R.FIP))
  !!ir (AST.extract tmp 11<rt> 64 := AST.xtlo 11<rt> (!.ctxt R.FOP))
  !!ir (AST.extract tmp 4<rt> 76 := AST.extract (!.ctxt R.FIP) 4<rt> 16)
  !!ir (AST.extract tmp 16<rt> 80 := AST.xtlo 16<rt> (!.ctxt R.FDP))
  !!ir (AST.xthi 4<rt> tmp := AST.extract (!.ctxt R.FDP) 4<rt> 16)
  !!ir (dst := tmp)

let private m14fldenv src ctxt ir =
  let tmp = AST.tmpvar 112<rt>
  !!ir (tmp := src)
  !!ir (!.ctxt R.FCW := AST.xtlo 16<rt> tmp)
  !!ir (!.ctxt R.FSW := AST.extract tmp 16<rt> 16)
  !!ir (!.ctxt R.FTW := AST.extract tmp 16<rt> 32)
  !!ir (AST.xtlo 16<rt> (!.ctxt R.FIP) := AST.extract tmp 16<rt> 48)
  !!ir (AST.xtlo 11<rt> (!.ctxt R.FOP) := AST.extract tmp 11<rt> 64)
  !!ir (AST.extract (!.ctxt R.FIP) 4<rt> 16 := AST.extract tmp 4<rt> 76)
  !!ir (AST.xtlo 16<rt> (!.ctxt R.FDP) := AST.extract tmp 16<rt> 80)
  !!ir (AST.extract (!.ctxt R.FDP) 4<rt> 16 := AST.xthi 4<rt> tmp)

let private m28fldenv src ctxt ir =
  let tmp = AST.tmpvar 224<rt>
  !!ir (tmp := src)
  !!ir (!.ctxt R.FCW := AST.xtlo 16<rt> tmp)
  !!ir (!.ctxt R.FSW := AST.extract tmp 16<rt> 32)
  !!ir (!.ctxt R.FTW := AST.extract tmp 16<rt> 64)
  !!ir (AST.xtlo 16<rt> (!.ctxt R.FIP) := AST.extract tmp 16<rt> 96)
  !!ir (AST.xtlo 11<rt> (!.ctxt R.FOP) := AST.extract tmp 11<rt> 128)
  !!ir (AST.extract (!.ctxt R.FIP) 16<rt> 16 := AST.extract tmp 16<rt> 139)
  !!ir (AST.xtlo 16<rt> (!.ctxt R.FDP) := AST.extract tmp 16<rt> 160)
  !!ir (AST.extract (!.ctxt R.FDP) 16<rt> 16 := AST.extract tmp 16<rt> 204)

let private m28fstenv dst ctxt ir =
  let tmp = AST.tmpvar 224<rt>
  !!ir (tmp := AST.num0 224<rt>)
  !!ir (AST.xtlo 16<rt> tmp := !.ctxt R.FCW)
  !!ir (AST.extract tmp 16<rt> 32 := !.ctxt R.FSW)
  !!ir (AST.extract tmp 16<rt> 64 := !.ctxt R.FTW)
  !!ir (AST.extract tmp 16<rt> 96 := AST.xtlo 16<rt> (!.ctxt R.FIP))
  !!ir (AST.extract tmp 11<rt> 128 := AST.xtlo 11<rt> (!.ctxt R.FOP))
  !!ir (AST.extract tmp 16<rt> 139 := AST.extract (!.ctxt R.FIP) 16<rt> 16)
  !!ir (AST.extract tmp 16<rt> 160 := AST.xtlo 16<rt> (!.ctxt R.FDP))
  !!ir (AST.extract tmp 16<rt> 204 := AST.extract (!.ctxt R.FDP) 16<rt> 16)
  !!ir (dst := tmp)

let private ftrig _ins insLen ctxt trigFunc =
  let ir = IRBuilder (32)
  let st0 = fpuRegValue ctxt R.ST0
  let float80SignUnmask = BitVector.signedMax 80<rt> |> AST.num
  let maxLimit = numI64 (1L <<< 63) 64<rt>
  let maxFloat = AST.cast CastKind.IntToFloat 80<rt> maxLimit
  let num3 = BitVector.ofInt32 3 2<rt> |> AST.num
  let c0 = !.ctxt R.FSWC0
  let c1 = !.ctxt R.FSWC1
  let c2 = !.ctxt R.FSWC2
  let c3 = !.ctxt R.FSWC3
  let lblOutOfRange = AST.symbol "IsOutOfRange"
  let lblInRange = AST.symbol "IsInRange"
  let tmp = AST.tmpvar 80<rt>
  !<ir insLen
  !!ir (tmp := st0 .& float80SignUnmask)
  !!ir (CJmp (AST.flt tmp maxFloat, Name lblInRange, Name lblOutOfRange ))
  !!ir (LMark lblInRange)
  !!ir (tmp := trigFunc st0)
  !?ir (assignFPUReg R.ST0 tmp ctxt)
  !!ir (c1 := AST.ite (!.ctxt R.FTW7 == num3) AST.b0 c1)
  !!ir (c2 := AST.b0)
  !!ir (c0 := undefC0)
  !!ir (c3 := undefC3)
  !!ir (LMark lblOutOfRange)
  !!ir (c2 := AST.b1)
  !!ir (c0 := undefC0)
  !!ir (c1 := undefC1)
  !!ir (c3 := undefC3)
  !>ir insLen

let private fpuFBinOp ins insLen ctxt binOp doPop leftToRight =
  let ir = IRBuilder (64)
  let res = AST.tmpvar 80<rt>
  !<ir insLen
  match ins.Operands with
  | NoOperand ->
    let st0 = fpuRegValue ctxt R.ST0
    let st1 = fpuRegValue ctxt R.ST1
    if leftToRight then !!ir (res := binOp st0 st1)
    else !!ir (res := binOp st1 st0)
    !?ir (assignFPUReg R.ST1 res ctxt)
    !?ir (checkC1Flag ctxt) R.FTW6
  | OneOperand opr ->
    let oprExpr = transOprToFloat80 ins insLen ctxt opr
    let st0 = fpuRegValue ctxt R.ST0
    if leftToRight then !!ir (res := binOp st0 oprExpr)
    else !!ir (res := binOp oprExpr st0)
    !?ir (assignFPUReg R.ST0 res ctxt)
    !?ir (checkC1Flag ctxt) R.FTW7
  | TwoOperands (OprReg reg1, opr2) ->
    let oprExpr1 = !.ctxt reg1
    let oprExpr2 = transOprToExpr ins insLen ctxt opr2
    if leftToRight then !!ir (res := binOp oprExpr1 oprExpr2)
    else !!ir (res := binOp oprExpr2 oprExpr1)
    !?ir (assignFPUReg reg1 res ctxt)
  | _ -> raise InvalidOperandException
  if doPop then !?ir (popFPUStack ctxt) else ()
  !>ir insLen

let private fpuIntOp ins insLen ctxt binOp leftToRight =
  let ir = IRBuilder (8)
  let st0 = fpuRegValue ctxt R.ST0
  let oprExpr = transOneOpr ins insLen ctxt
  let tmp = AST.tmpvar 80<rt>
  !<ir insLen
  !!ir (tmp := AST.cast CastKind.IntToFloat 80<rt> oprExpr)
  if leftToRight then !!ir (tmp := binOp st0 tmp)
  else !!ir (tmp := binOp tmp st0)
  !?ir (assignFPUReg R.ST0 tmp ctxt)
  !>ir insLen

let private bcdToInt intgr bcd ir =
  let getDigit startPos =
    AST.extract bcd 4<rt> startPos |> AST.sext 64<rt>
  let n num =
    numI64 num 64<rt>
  !!ir (intgr := AST.num0 64<rt>)
  !!ir (intgr := intgr .+ getDigit 0)
  !!ir (intgr := intgr .+ (getDigit 4 .* n 10L))
  !!ir (intgr := intgr .+ (getDigit 8 .* n 100L))
  !!ir (intgr := intgr .+ (getDigit 12 .* n 1000L))
  !!ir (intgr := intgr .+ (getDigit 16 .* n 10000L))
  !!ir (intgr := intgr .+ (getDigit 20 .* n 100000L))
  !!ir (intgr := intgr .+ (getDigit 24 .* n 1000000L))
  !!ir (intgr := intgr .+ (getDigit 28 .* n 10000000L))
  !!ir (intgr := intgr .+ (getDigit 32 .* n 100000000L))
  !!ir (intgr := intgr .+ (getDigit 36 .* n 1000000000L))
  !!ir (intgr := intgr .+ (getDigit 40 .* n 10000000000L))
  !!ir (intgr := intgr .+ (getDigit 44 .* n 100000000000L))
  !!ir (intgr := intgr .+ (getDigit 48 .* n 1000000000000L))
  !!ir (intgr := intgr .+ (getDigit 52 .* n 10000000000000L))
  !!ir (intgr := intgr .+ (getDigit 56 .* n 100000000000000L))
  !!ir (intgr := intgr .+ (getDigit 60 .* n 1000000000000000L))
  !!ir (intgr := intgr .+ (getDigit 64 .* n 10000000000000000L))
  !!ir (intgr := intgr .+ (getDigit 68 .* n 100000000000000000L))

let private intTobcd bcd intgr ir =
  let n10 = numI32 10 64<rt>
  let mod10 = intgr .% n10 |> AST.zext 4<rt>
  let digitAt startPos = AST.extract bcd 4<rt> startPos
  let rec doAssign startPos =
    if startPos >= 72 then ()
    else
      !!ir (digitAt startPos := mod10)
      !!ir (intgr := intgr ./ n10)
      doAssign (startPos + 4)
  doAssign 0

let private fpuLoad insLen ctxt oprExpr =
  let ir = IRBuilder (64)
  let tmp = AST.tmpvar 80<rt>
  !<ir insLen
  !!ir (tmp := AST.cast CastKind.FloatExt 80<rt> oprExpr)
  !?ir (checkFPUOnLoad ctxt)
  !?ir (shiftFPUStackDown ctxt)
  !?ir (assignFPUReg R.ST0 tmp ctxt)
  !?ir (updateTagWordOnLoad ctxt)
  !>ir insLen

let fld ins insLen ctxt =
  let oprExpr = transOneOpr ins insLen ctxt
  fpuLoad insLen ctxt oprExpr

let ffst ins insLen ctxt doPop =
  let opr, oprExpr =
    match ins.Operands with
    | OneOperand opr -> opr, transOprToExpr ins insLen ctxt opr
    | _ -> raise InvalidOperandException
  let st0 = fpuRegValue ctxt R.ST0
  let sz = AST.typeOf oprExpr
  let tmp = AST.tmpvar sz
  let ir = IRBuilder (32)
  !<ir insLen
  !!ir (tmp := AST.cast CastKind.FloatExt sz st0)
  match opr with
  | OprReg r -> !?ir (assignFPUReg r tmp ctxt)
  | _ -> !!ir (oprExpr := tmp)
  !?ir (checkC1Flag ctxt) R.FTW7
  !?ir (cflagsUndefined023 ctxt)
  if doPop then !?ir (popFPUStack ctxt) else ()
  !>ir insLen

let fild ins insLen ctxt =
  let ir = IRBuilder (32)
  let oprExpr = transOneOpr ins insLen ctxt
  let tmp = AST.tmpvar 80<rt>
  !<ir insLen
  !!ir (tmp := AST.cast CastKind.IntToFloat 80<rt> oprExpr)
  !?ir (checkFPUOnLoad ctxt)
  !?ir (shiftFPUStackDown ctxt)
  !?ir (assignFPUReg R.ST0 tmp ctxt)
  !?ir (updateTagWordOnLoad ctxt)
  !>ir insLen

let fist ins insLen ctxt doPop =
  let ir = IRBuilder (32)
  let oprExpr = transOneOpr ins insLen ctxt
  let sz = AST.typeOf oprExpr
  let st0 = fpuRegValue ctxt R.ST0
  let tmp1 = AST.tmpvar sz
  let tmp2 = AST.tmpvar 2<rt>
  let num2 = numI32 2 2<rt>
  let cstK castKind = AST.cast castKind sz st0
  !<ir insLen
  !!ir (tmp2 := AST.extract (!.ctxt R.FCW) 2<rt> 10)
  !!ir (tmp1 := AST.ite (tmp2 == AST.num0 2<rt>)
    (cstK CastKind.FtoIRound) (cstK CastKind.FtoITrunc))
  !!ir
    (tmp1 := AST.ite (tmp2 == AST.num1 2<rt>) (cstK CastKind.FtoIFloor) tmp1)
  !!ir (tmp1 := AST.ite (tmp2 == num2) (cstK CastKind.FtoICeil) tmp1)
  !!ir (oprExpr := tmp1)
  !!ir (!.ctxt R.FSWC1 := AST.ite (tmp2 == num2) AST.b1 AST.b0)
  !?ir (cflagsUndefined023 ctxt)
  if doPop then !?ir (popFPUStack ctxt) else ()
  !>ir insLen

let fisttp ins insLen ctxt =
  let ir = IRBuilder (64)
  let oprExpr = transOneOpr ins insLen ctxt
  let sz = AST.typeOf oprExpr
  let st0 = fpuRegValue ctxt R.ST0
  !<ir insLen
  !!ir (oprExpr := AST.cast CastKind.FtoICeil sz st0)
  !!ir (!.ctxt R.FSWC1 := AST.b0)
  !!ir (!.ctxt R.FSWC0 := undefC0)
  !!ir (!.ctxt R.FSWC2 := undefC2)
  !!ir (!.ctxt R.FSWC3 := undefC3)
  !?ir (popFPUStack ctxt)
  !>ir insLen

let fbld ins insLen ctxt =
  let ir = IRBuilder (64)
  let src = transOneOpr ins insLen ctxt
  let sign = AST.xthi 1<rt> src
  let intgr = AST.tmpvar 64<rt>
  let bcdNum = AST.tmpvar 72<rt>
  let tmp = AST.tmpvar 80<rt>
  !<ir insLen
  !?ir (bcdToInt intgr bcdNum)
  !!ir (AST.xthi 1<rt> intgr := sign)
  !!ir (tmp := AST.cast CastKind.IntToFloat 80<rt> intgr)
  !?ir (checkFPUOnLoad ctxt)
  !?ir (shiftFPUStackDown ctxt)
  !?ir (assignFPUReg R.ST0 tmp ctxt)
  !?ir (updateTagWordOnLoad ctxt)
  !>ir insLen

let fbstp ins insLen ctxt =
  let ir = IRBuilder (64)
  let dst = transOneOpr ins insLen ctxt
  let st0 = fpuRegValue ctxt R.ST0
  let sign = AST.xthi 1<rt> st0
  let intgr = AST.tmpvar 64<rt>
  let bcdNum = AST.tmpvar 72<rt>
  let tmp = AST.tmpvar 80<rt>
  !<ir insLen
  !!ir (intgr := AST.cast CastKind.FtoIRound 64<rt> st0)
  !?ir (intTobcd bcdNum intgr)
  !!ir (tmp := AST.num0 80<rt>)
  !!ir (AST.xthi 1<rt> tmp := sign)
  !!ir (AST.xtlo 72<rt> tmp := bcdNum)
  !!ir (dst := tmp)
  !>ir insLen

let fxch ins insLen ctxt =
  let ir = IRBuilder (16)
  let tmp = AST.tmpvar 80<rt>
  let st0 = fpuRegValue ctxt R.ST0
  !<ir insLen
  match ins.Operands with
  | OneOperand (OprReg reg as opr) ->
      let oprExpr = transOprToExpr ins insLen ctxt opr
      !!ir (tmp := st0)
      !?ir (assignFPUReg R.ST0 oprExpr ctxt)
      !?ir (assignFPUReg reg tmp ctxt)
  | NoOperand ->
      let st1 = fpuRegValue ctxt R.ST1
      !!ir (tmp := st0)
      !?ir (assignFPUReg R.ST0 st1 ctxt)
      !?ir (assignFPUReg R.ST1 tmp ctxt)
  | _ -> raise InvalidOperandException
  !!ir (!.ctxt R.FSWC1 := AST.b0)
  !?ir (cflagsUndefined023 ctxt)
  !>ir insLen

let private fcmov ins insLen ctxt cond =
  let ir = IRBuilder (8)
  let src =
    match ins.Operands with
    | TwoOperands (_, src) -> src
    | _ -> raise InvalidOperandException
  let src = transOprToExpr ins insLen ctxt src
  let st0b, st0a = getFPUPseudoRegVars ctxt R.ST0
  !<ir insLen
  !!ir (st0a := AST.ite cond (AST.xtlo 64<rt> src) st0a)
  !!ir (st0b := AST.ite cond (AST.xthi 16<rt> src) st0b)
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

let fprem _ins insLen ctxt round =
  let ir = IRBuilder (32)
  let st0 = fpuRegValue ctxt R.ST0
  let st1 = fpuRegValue ctxt R.ST1
  let caster = if round then CastKind.FtoIRound else CastKind.FtoITrunc
  let lblLT64 = AST.symbol "ExpDiffInRange"
  let lblGT64 = AST.symbol "ExpDiffOutOfRange"
  let lblExit = AST.symbol "Exit"
  let expDiff = AST.tmpvar 15<rt>
  let struct (tmp80A, tmp80B, tmpres) = tmpVars3 80<rt>
  let tmp64 = AST.tmpvar 64<rt>
  !<ir insLen
  !!ir (expDiff := AST.extract st0 15<rt> 64 .- AST.extract st1 15<rt> 64)
  !!ir (CJmp (AST.lt expDiff (numI32 64 15<rt>), Name lblLT64, Name lblGT64))
  !!ir (LMark lblLT64)
  !!ir (tmp80A := AST.fdiv st0 st1)
  !!ir (tmp64 := AST.cast caster 64<rt> tmp80A)
  !!ir (tmp80B := AST.fmul st1 (AST.cast CastKind.IntToFloat 80<rt> tmp64))
  !!ir (tmpres := AST.fsub st0 tmp80B)
  !?ir (assignFPUReg R.ST0 tmpres ctxt)
  !!ir (!.ctxt R.FSWC2 := AST.b0)
  !!ir (!.ctxt R.FSWC1 := AST.xtlo 1<rt> tmp64)
  !!ir (!.ctxt R.FSWC3 := AST.extract tmp64 1<rt> 1)
  !!ir (!.ctxt R.FSWC0 := AST.extract tmp64 1<rt> 2)
  !!ir (Jmp (Name lblExit))
  !!ir (LMark lblGT64)
  !!ir (!.ctxt R.FSWC2 := AST.b1)
  !!ir (tmp64 := (AST.zext 64<rt> expDiff) .- numI32 63 64<rt>)
  !!ir (tmp64 := tmp64 .* numI32 2 64<rt>)
  !!ir (tmp80B := AST.cast CastKind.IntToFloat 80<rt> tmp64)
  !!ir (tmp80A := AST.fdiv (AST.fdiv st0 st1) tmp80B)
  !!ir (tmp64 := AST.cast CastKind.FtoITrunc 64<rt> tmp80A)
  !!ir (tmp80A := AST.cast CastKind.IntToFloat 80<rt> tmp64)
  !!ir (tmp80A := AST.fsub st0 (AST.fmul st1 (AST.fmul tmp80A tmp80B)))
  !?ir (assignFPUReg R.ST0 tmp80A ctxt)
  !!ir (LMark lblExit)
  !>ir insLen

let fabs _ins insLen ctxt =
  let ir = IRBuilder (8)
  let st0b, _st0a = getFPUPseudoRegVars ctxt R.ST0
  !<ir insLen
  !!ir (AST.extract st0b 1<rt> 15 := AST.b1)
  !!ir (!.ctxt R.FSWC1 := AST.b0)
  !!ir (!.ctxt R.FSWC0 := undefC0)
  !!ir (!.ctxt R.FSWC2 := undefC2)
  !!ir (!.ctxt R.FSWC3 := undefC3)
  !>ir insLen

let fchs _ins insLen ctxt =
  let ir = IRBuilder (8)
  let st0b, _st0a = getFPUPseudoRegVars ctxt R.ST0
  let tmp = AST.tmpvar 1<rt>
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
  let st0 = fpuRegValue ctxt R.ST0
  let t0 = AST.tmpvar 80<rt>
  let t1 = AST.tmpvar 64<rt>
  let t2 = AST.tmpvar 2<rt>
  let num2 = numI32 2 2<rt>
  let cstK castKind = AST.cast castKind 64<rt> st0
  !<ir insLen
  !!ir (t2 := AST.extract (!.ctxt R.FCW) 2<rt> 10)
  !!ir (t1 := AST.ite (t2 == AST.num0 2<rt>)
    (cstK CastKind.FtoIRound) (cstK CastKind.FtoITrunc))
  !!ir (t1 := AST.ite (t2 == AST.num1 2<rt>) (cstK CastKind.FtoIFloor) t1)
  !!ir (t1 := AST.ite (t2 == num2) (cstK CastKind.FtoICeil) t1)
  !!ir (t0 := AST.cast CastKind.IntToFloat 80<rt> t1)
  !?ir (assignFPUReg R.ST0 t0 ctxt)
  !!ir (!.ctxt R.FSWC1 := AST.ite (t2 == num2) AST.b1 AST.b0)
  !?ir (cflagsUndefined023 ctxt)
  !>ir insLen

let fscale _ins insLen ctxt =
  let ir = IRBuilder (16)
  let struct (tmp1, tmp2) = tmpVars2 64<rt>
  let tmp3 = AST.tmpvar 80<rt>
  let st0 = fpuRegValue ctxt R.ST0
  let st1 = fpuRegValue ctxt R.ST1
  !<ir insLen
  !!ir (tmp1 := AST.cast CastKind.FtoITrunc 64<rt> st1)
  !!ir (tmp2 := numI32 1 64<rt> << tmp1)
  !!ir (tmp3 := AST.cast CastKind.IntToFloat 80<rt> tmp2)
  !!ir (tmp3 := AST.fmul st0 tmp3)
  !?ir (assignFPUReg R.ST0 tmp3 ctxt)
  !?ir (checkC1Flag ctxt) R.FTW6
  !?ir (cflagsUndefined023 ctxt)
  !>ir insLen

let fsqrt _ins insLen ctxt =
  let ir = IRBuilder (8)
  let st0 = fpuRegValue ctxt R.ST0
  let tmp = AST.tmpvar 80<rt>
  !<ir insLen
  !!ir (tmp := AST.unop UnOpType.FSQRT st0)
  !?ir (assignFPUReg R.ST0 tmp ctxt)
  !?ir (checkC1Flag ctxt) R.FTW7
  !>ir insLen

let fxtract _ins insLen ctxt =
  let ir = IRBuilder (64)
  let st0 = fpuRegValue ctxt R.ST0
  let tmp = AST.tmpvar 80<rt>
  let exponent = AST.tmpvar 64<rt>
  let significand = AST.tmpvar 80<rt>
  !<ir insLen
  !!ir (exponent := AST.num0 64<rt>)
  !!ir (significand := AST.num0 80<rt>)
  !!ir (AST.xtlo 64<rt> significand := AST.xtlo 64<rt> st0)
  !!ir (AST.xthi 1<rt> significand := AST.xthi 1<rt> st0)
  !!ir (AST.extract significand 15<rt> 64 := numI32 16383 15<rt>)
  !!ir (AST.xtlo 15<rt> exponent := AST.extract st0 15<rt> 64)
  !!ir (exponent := exponent .- numI32 16383 64<rt>)
  !!ir (tmp := AST.cast CastKind.IntToFloat 80<rt> exponent)
  !?ir (assignFPUReg R.ST0 tmp ctxt)
  !?ir (checkFPUOnLoad ctxt)
  !?ir (shiftFPUStackDown ctxt)
  !?ir (assignFPUReg R.ST0 significand ctxt)
  !?ir (updateTagWordOnLoad ctxt)
  !?ir (checkC1Flag ctxt) R.FTW7
  !?ir (cflagsUndefined023 ctxt)
  !>ir insLen

let fcom ins insLen ctxt nPop unordered =
  let ir = IRBuilder (64)
  let lblNan = AST.symbol "IsNan"
  let lblExit = AST.symbol "Exit"
  let c0 = !.ctxt R.FSWC0
  let c2 = !.ctxt R.FSWC2
  let c3 = !.ctxt R.FSWC3
  let im = !.ctxt R.FCW |> AST.xtlo 1<rt>
  let struct (tmp1, tmp2) = tmpVars2 80<rt>
  !<ir insLen
  match ins.Operands with
  | NoOperand ->
    !!ir (tmp1 := fpuRegValue ctxt R.ST0)
    !!ir (tmp2 := fpuRegValue ctxt R.ST1)
  | OneOperand opr ->
    let oprExpr = transOprToFloat80 ins insLen ctxt opr
    !!ir (tmp1 := fpuRegValue ctxt R.ST0)
    !!ir (tmp2 := oprExpr)
  | TwoOperands (o1, o2) ->
    let o1 = transOprToFloat80 ins insLen ctxt o1
    let o2 = transOprToFloat80 ins insLen ctxt o2
    !!ir (tmp1 := o1)
    !!ir (tmp2 := o2)
  | _ -> raise InvalidOperandException
  !!ir (c0 := AST.ite (AST.flt tmp1 tmp2) AST.b1 AST.b0)
  !!ir (c2 := AST.b0)
  !!ir (c3 := AST.ite (tmp1 == tmp2) AST.b1 AST.b0)
  let isNan expr =
    (AST.extract expr 15<rt> 64  == AST.num (BitVector.unsignedMax 15<rt>))
     .& (AST.xtlo 62<rt> expr != AST.num0 62<rt>)
  let cond =
    if unordered then
        let tmp1qNanCond = isNan tmp1 .& (AST.extract tmp1 1<rt> 62 == AST.b1)
        let tmp2qNanCond = isNan tmp2 .& (AST.extract tmp2 1<rt> 62 == AST.b1)
        tmp1qNanCond .| tmp2qNanCond .& (im == AST.b0)
    else isNan tmp1 .| isNan tmp2 .& (im == AST.b0)
  !!ir (CJmp (cond, Name lblNan, Name lblExit))
  !!ir (LMark lblNan)
  !!ir (c0 := AST.b1)
  !!ir (c2 := AST.b1)
  !!ir (c3 := AST.b1)
  !!ir (LMark lblExit)
  !!ir (!.ctxt R.FSWC1 := AST.b0)
  if nPop > 0 then !?ir (popFPUStack ctxt) else ()
  if nPop = 2 then !?ir (popFPUStack ctxt) else ()
  !>ir insLen

let ficom ins insLen ctxt doPop =
  let ir = IRBuilder (32)
  let oprExpr = transOneOpr ins insLen ctxt
  let st0 = fpuRegValue ctxt R.ST0
  let tmp = AST.tmpvar 80<rt>
  !<ir insLen
  !!ir (tmp := AST.cast CastKind.IntToFloat 80<rt> oprExpr)
  !!ir (!.ctxt R.FSWC0 := AST.ite (AST.flt st0 tmp) AST.b1 AST.b0)
  !!ir (!.ctxt R.FSWC2 := AST.b0)
  !!ir (!.ctxt R.FSWC3 := AST.ite (st0 == tmp) AST.b1 AST.b0)
  !!ir (!.ctxt R.FSWC1 := AST.b0)
  if doPop then !?ir (popFPUStack ctxt) else ()
  !>ir insLen

let fcomi ins insLen ctxt doPop =
  let ir = IRBuilder (64)
  let struct (opr1, opr2) = transTwoOprs ins insLen ctxt
  let im = !.ctxt R.FCW |> AST.xtlo 1<rt>
  let lblQNan = AST.symbol "IsQNan"
  let lblNan = AST.symbol "IsNan"
  let lblExit = AST.symbol "Exit"
  let lblCond = AST.symbol "IsNanCond"
  let zf = !.ctxt R.ZF
  let pf = !.ctxt R.PF
  let cf = !.ctxt R.CF
  !<ir insLen
  !!ir (zf := AST.ite (opr1 == opr2) AST.b1 AST.b0)
  !!ir (pf := AST.b0)
  !!ir (cf := AST.ite (AST.flt opr1 opr2) AST.b1 AST.b0)
  let opr1NanCond =
    (AST.extract opr1 15<rt> 64  == AST.num (BitVector.unsignedMax 15<rt>))
      .& (AST.xtlo 62<rt> opr1 != AST.num0 62<rt>)
  let opr2NanCond =
    (AST.extract opr2 15<rt> 64 == AST.num (BitVector.unsignedMax 15<rt>))
      .& (AST.xtlo 62<rt> opr2 != AST.num0 62<rt>)
  let cond = opr1NanCond .| opr2NanCond .& (im == AST.b0)
  match ins.Opcode with
  | Opcode.FCOMI | Opcode.FCOMIP ->
    !!ir (CJmp (cond, Name lblNan, Name lblExit))
  | Opcode.FUCOMI | Opcode.FUCOMIP ->
    let opr1qNanCond = opr1NanCond .& (AST.extract opr1 1<rt> 62 == AST.b1)
    let opr2qNanCond = opr2NanCond .& (AST.extract opr2 1<rt> 62 == AST.b1)
    !!ir (CJmp (opr1qNanCond .| opr2qNanCond, Name lblQNan, Name lblCond))
    !!ir (LMark lblQNan)
    !!ir (zf:= AST.b1)
    !!ir (pf := AST.b1)
    !!ir (cf := AST.b1)
    !!ir (Jmp (Name lblExit))
    !!ir (LMark lblCond)
    !!ir (CJmp (cond, Name lblNan, Name lblExit))
  | _ -> raise InvalidOpcodeException
  !!ir (LMark lblNan)
  !!ir (zf := AST.b1)
  !!ir (pf := AST.b1)
  !!ir (cf := AST.b1)
  !!ir (LMark lblExit)
  if doPop then !?ir (popFPUStack ctxt) else ()
  !>ir insLen

let ftst _ins insLen ctxt =
  let ir = IRBuilder (16)
  let st0 = fpuRegValue ctxt R.ST0
  let num0V = AST.num0 80<rt>
  let c0 = !.ctxt R.FSWC0
  let c2 = !.ctxt R.FSWC2
  let c3 = !.ctxt R.FSWC3
  let lblNan = AST.symbol "IsNan"
  let lblExit = AST.symbol "Exit"
  !<ir insLen
  !!ir (c0 := AST.ite (AST.flt st0 num0V) AST.b1 AST.b0)
  !!ir (c2 := AST.b0)
  !!ir (c3 := AST.ite (st0 == num0V) AST.b1 AST.b0)
  let st0Exponent = AST.extract st0 15<rt> 64
  let st0NanCond =
    (st0Exponent == AST.num (BitVector.unsignedMax 15<rt>))
     .& (AST.xtlo 62<rt> st0 != AST.num0 62<rt>)
  !!ir (CJmp (st0NanCond, Name lblNan, Name lblExit))
  !!ir (LMark lblNan)
  !!ir (c0 := AST.b1)
  !!ir (c2 := AST.b1)
  !!ir (c3 := AST.b1)
  !!ir (LMark lblExit)
  !!ir (!.ctxt R.FSWC1 := AST.b0)
  !>ir insLen

let fxam _ins insLen ctxt =
  let ir = IRBuilder (8)
  let st0 = fpuRegValue ctxt R.ST0
  let exponent = AST.extract st0 15<rt> 64
  let maxExponent = BitVector.unsignedMax 15<rt> |> AST.num
  let tag7 = !.ctxt R.FTW7
  let nanCond =
    (exponent == maxExponent) .& (AST.xtlo 62<rt> st0 != AST.num0 62<rt>)
  let c3Cond1 = (tag7 == numI32 3 2<rt>) .| (exponent == AST.num0 15<rt>)
  let c2Cond0 = (tag7 == numI32 3 2<rt>) .| (st0 == AST.num0 80<rt>) .| nanCond
  let c0Cond1 = (tag7 == numI32 3 2<rt>) .| (exponent == maxExponent)
  !<ir insLen
  !!ir (!.ctxt R.FSWC1 := AST.xthi 1<rt> st0)
  !!ir (!.ctxt R.FSWC3 := AST.ite (c3Cond1) AST.b1 AST.b0)
  !!ir (!.ctxt R.FSWC2 := AST.ite (c2Cond0) AST.b0 AST.b1)
  !!ir (!.ctxt R.FSWC0 := AST.ite (c0Cond1) AST.b1 AST.b0)
  !>ir insLen

let fsin ins insLen ctxt =
  ftrig ins insLen ctxt AST.fsin

let fcos ins insLen ctxt =
  ftrig ins insLen ctxt AST.fcos

let fsincos _ins insLen ctxt =
  let ir = IRBuilder (64)
  let st0 = fpuRegValue ctxt R.ST0
  let c0 = !.ctxt R.FSWC0
  let c1 = !.ctxt R.FSWC1
  let c2 = !.ctxt R.FSWC2
  let c3 = !.ctxt R.FSWC3
  let float80SignUnmask = BitVector.signedMax 80<rt> |> AST.num
  let maxLimit = numI64 (1L <<< 63) 64<rt>
  let maxFloat = AST.cast CastKind.IntToFloat 80<rt> maxLimit
  let num3 = BitVector.ofInt32 3 2<rt> |> AST.num
  let lblOutOfRange = AST.symbol "IsOutOfRange"
  let lblInRange = AST.symbol "IsInRange"
  let struct (tmp1, tmp2) = tmpVars2 80<rt>
  !<ir insLen
  !!ir (tmp1 := st0 .& float80SignUnmask)
  !!ir (CJmp (AST.flt tmp1 maxFloat, Name lblInRange, Name lblOutOfRange ))
  !!ir (LMark lblInRange)
  !!ir (tmp1 := AST.fcos st0)
  !!ir (tmp2 := AST.fsin st0)
  !?ir (assignFPUReg R.ST0 tmp2 ctxt)
  !!ir (c1 := AST.ite (!.ctxt R.FTW7 == num3) AST.b0 c1)
  !!ir (c2 := AST.b0)
  !!ir (c0 := undefC0)
  !!ir (c3 := undefC3)
  !?ir (checkFPUOnLoad ctxt)
  !?ir (shiftFPUStackDown ctxt)
  !?ir (assignFPUReg R.ST0 tmp1 ctxt)
  !?ir (updateTagWordOnLoad ctxt)
  !!ir (LMark lblOutOfRange)
  !!ir (c2 := AST.b1)
  !!ir (c0 := undefC0)
  !!ir (c1 := undefC1)
  !!ir (c3 := undefC3)
  !>ir insLen

let fptan _ins insLen ctxt =
  let ir = IRBuilder (64)
  let st0 = fpuRegValue ctxt R.ST0
  let float80SignUnmask = BitVector.signedMax 80<rt> |> AST.num
  let maxLimit = numI64 (1L <<< 63) 64<rt>
  let maxFloat = AST.cast CastKind.IntToFloat 80<rt> maxLimit
  let num3 = BitVector.ofInt32 3 2<rt> |> AST.num
  let c0 = !.ctxt R.FSWC0
  let c1 = !.ctxt R.FSWC1
  let c2 = !.ctxt R.FSWC2
  let c3 = !.ctxt R.FSWC3
  let lblOutOfRange = AST.symbol "IsOutOfRange"
  let lblInRange = AST.symbol "IsInRange"
  let tmp = AST.tmpvar 80<rt>
  let tmp64 = AST.tmpvar 64<rt>
  !<ir insLen
  !!ir (tmp := st0 .& float80SignUnmask)
  !!ir (CJmp (AST.flt tmp maxFloat, Name lblInRange, Name lblOutOfRange ))
  !!ir (LMark lblInRange)
  !!ir (tmp := AST.ftan st0)
  !?ir (assignFPUReg R.ST0 tmp ctxt)
  !!ir (c1 := AST.ite (!.ctxt R.FTW7 == num3) AST.b0 c1)
  !!ir (c2 := AST.b0)
  !!ir (c0 := undefC0)
  !!ir (c3 := undefC3)
  !!ir (LMark lblOutOfRange)
  !!ir (c2 := AST.b1)
  !!ir (c0 := undefC0)
  !!ir (c1 := undefC1)
  !!ir (c3 := undefC3)
  !!ir (tmp64 := numI64 4607182418800017408L 64<rt>)
  !!ir (tmp := AST.cast CastKind.FloatExt 80<rt> tmp64)
  !?ir (checkFPUOnLoad ctxt)
  !?ir (shiftFPUStackDown ctxt)
  !?ir (assignFPUReg R.ST0 tmp ctxt)
  !?ir (updateTagWordOnLoad ctxt)
  !>ir insLen

let fpatan _ins insLen ctxt =
  let ir = IRBuilder (16)
  let c1 = !.ctxt R.FSWC1
  let tmp = AST.tmpvar 80<rt>
  !<ir insLen
  !!ir (tmp := fpuRegValue ctxt R.ST1 ./ fpuRegValue ctxt R.ST0)
  !!ir (tmp := AST.fatan tmp)
  !?ir (assignFPUReg R.ST1 tmp ctxt)
  !!ir (c1 := AST.b0)
  !?ir (cflagsUndefined023 ctxt)
  !>ir insLen

let f2xm1 _isn insLen ctxt =
  let ir = IRBuilder (16)
  let st0 = fpuRegValue ctxt R.ST0
  let flt1 = AST.num1 32<rt> |> AST.cast CastKind.IntToFloat 80<rt>
  let flt2 = numI32 2 32<rt> |> AST.cast CastKind.IntToFloat 80<rt>
  let tmp = AST.tmpvar 80<rt>
  !<ir insLen
  !!ir (tmp := AST.fpow flt2 st0)
  !!ir (tmp := AST.fsub tmp flt1)
  !?ir (assignFPUReg R.ST0 tmp ctxt)
  !?ir (checkC1Flag ctxt) R.FTW7
  !?ir (cflagsUndefined023 ctxt)
  !>ir insLen

let fyl2x _ins insLen ctxt =
  let ir = IRBuilder (64)
  let st0 = fpuRegValue ctxt R.ST0
  let st1 = fpuRegValue ctxt R.ST1
  let flt2 = numI32 2 32<rt> |> AST.cast CastKind.IntToFloat 80<rt>
  let struct (t1, t2) = tmpVars2 80<rt>
  !<ir insLen
  !!ir (t1 := AST.flog flt2 st0)
  !!ir (t2 := AST.fmul st1 t1)
  !?ir (assignFPUReg R.ST1 t2 ctxt)
  !?ir (popFPUStack ctxt)
  !?ir (checkC1Flag ctxt) R.FTW6
  !?ir (cflagsUndefined023 ctxt)
  !>ir insLen

let fyl2xp1 _ins insLen ctxt =
  let ir = IRBuilder (64)
  let st0 = fpuRegValue ctxt R.ST0
  let st1 = fpuRegValue ctxt R.ST1
  let flt2 = numI32 2 32<rt> |> AST.cast CastKind.IntToFloat 80<rt>
  let f1 = numI32 1 32<rt> |> AST.cast CastKind.IntToFloat 80<rt>
  let tmp = AST.tmpvar 80<rt>
  !<ir insLen
  !!ir (tmp := AST.fadd f1 (AST.flog flt2 st0))
  !!ir (tmp := AST.fmul st1 tmp)
  !?ir (assignFPUReg R.ST1 tmp ctxt)
  !?ir (popFPUStack ctxt)
  !?ir (checkC1Flag ctxt) R.FTW6
  !?ir (cflagsUndefined023 ctxt)
  !>ir insLen

let fld1 _ins insLen ctxt =
  let oprExpr = BitVector.ofUInt64 0x3FF0000000000000UL 64<rt> |> AST.num
  fpuLoad insLen ctxt oprExpr

let fldz _ins insLen ctxt =
  let oprExpr = AST.num0 64<rt>
  fpuLoad insLen ctxt oprExpr

let fldpi _ins insLen ctxt =
  let oprExpr = BitVector.ofUInt64 4614256656552045848UL 64<rt> |> AST.num
  fpuLoad insLen ctxt oprExpr

let fldl2e _ins insLen ctxt =
  let oprExpr = BitVector.ofUInt64 4599094494223104509UL 64<rt> |> AST.num
  fpuLoad insLen ctxt oprExpr

let fldln2 _ins insLen ctxt =
  let oprExpr = BitVector.ofUInt64 4604418534313441775UL 64<rt> |> AST.num
  fpuLoad insLen ctxt oprExpr

let fldl2t _ins insLen ctxt =
  let oprExpr = BitVector.ofUInt64 4614662735865160561UL 64<rt> |> AST.num
  fpuLoad insLen ctxt oprExpr

let fldlg2 _ins insLen ctxt =
  let oprExpr = BitVector.ofUInt64 4599094494223104511UL 64<rt> |> AST.num
  fpuLoad insLen ctxt oprExpr

let fincstp _ins insLen ctxt =
  let ir = IRBuilder (16)
  let top = !.ctxt R.FTOP
  !<ir insLen
  !!ir (top := top .+ AST.num1 3<rt>)
  !!ir (!.ctxt R.FSWC1 := AST.b0)
  !!ir (!.ctxt R.FSWC0 := undefC0)
  !!ir (!.ctxt R.FSWC2 := undefC2)
  !!ir (!.ctxt R.FSWC3 := undefC3)
  !>ir insLen

let fdecstp _ins insLen ctxt =
  let ir = IRBuilder (8)
  let top = !.ctxt R.FTOP
  !<ir insLen
  !!ir (top := top .+ AST.num1 3<rt>)
  !!ir (!.ctxt R.FSWC1 := AST.b0)
  !!ir (!.ctxt R.FSWC0 := undefC0)
  !!ir (!.ctxt R.FSWC2 := undefC2)
  !!ir (!.ctxt R.FSWC3 := undefC3)
  !>ir insLen

let ffree ins insLen ctxt =
  let ir = IRBuilder (8)
  let top = !.ctxt R.FTOP
  let tagWord = !.ctxt R.FTW
  let struct (top16, shifter, tagValue) = tmpVars3 16<rt>
  let value3 = BitVector.ofInt32 3 16<rt> |> AST.num
  let offset =
    match ins.Operands with
    | OneOperand (OprReg R.ST0) -> BitVector.ofInt32 0 16<rt> |> AST.num
    | OneOperand (OprReg R.ST1) -> BitVector.ofInt32 1 16<rt> |> AST.num
    | OneOperand (OprReg R.ST2) -> BitVector.ofInt32 2 16<rt> |> AST.num
    | OneOperand (OprReg R.ST3) -> BitVector.ofInt32 3 16<rt> |> AST.num
    | OneOperand (OprReg R.ST4) -> BitVector.ofInt32 4 16<rt> |> AST.num
    | OneOperand (OprReg R.ST5) -> BitVector.ofInt32 5 16<rt> |> AST.num
    | OneOperand (OprReg R.ST6) -> BitVector.ofInt32 6 16<rt> |> AST.num
    | OneOperand (OprReg R.ST7) -> BitVector.ofInt32 7 16<rt> |> AST.num
    | _ -> raise InvalidOperandException
  !<ir insLen
  !!ir (top16 := AST.cast CastKind.ZeroExt 16<rt> top)
  !!ir (top16 := top16 .+ offset)
  !!ir (shifter := (BitVector.ofInt32 2 16<rt> |> AST.num) .* top16)
  !!ir (tagValue := (value3 << shifter))
  !!ir (tagWord := tagWord .| tagValue)
  !>ir insLen

(* FIXME: check all unmasked pending floating point exceptions. *)
let private checkFPUExceptions ctxt ir = ()

let private clearFPU ctxt ir =
  let cw = BitVector.ofInt32 895 16<rt> |> AST.num
  let tw = BitVector.maxNum16 |> AST.num
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

let fstenv ins insLen ctxt =
  let ir = IRBuilder (16)
  let dst = transOneOpr ins insLen ctxt
  !<ir insLen
  match AST.typeOf dst with
  | 112<rt> -> m14Stenv dst ctxt ir
  | 224<rt> -> m28fstenv dst ctxt ir
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let fldenv ins insLen ctxt =
  let ir = IRBuilder (16)
  let src = transOneOpr ins insLen ctxt
  !<ir insLen
  match AST.typeOf src with
  | 112<rt> -> m14fldenv src ctxt ir
  | 224<rt> -> m28fldenv src ctxt ir
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let private stSts dst ctxt ir =
  let dst = extendAddr dst 80<rt>
  let offset = numI32 10 (getAddrRegSize dst)
  !!ir (dst := !.ctxt R.ST0)
  !!ir (updateAddrByOffset dst offset)
  !!ir (dst := !.ctxt R.ST1)
  !!ir (updateAddrByOffset dst offset)
  !!ir (dst := !.ctxt R.ST2)
  !!ir (updateAddrByOffset dst offset)
  !!ir (dst := !.ctxt R.ST3)
  !!ir (updateAddrByOffset dst offset)
  !!ir (dst := !.ctxt R.ST4)
  !!ir (updateAddrByOffset dst offset)
  !!ir (dst := !.ctxt R.ST5)
  !!ir (updateAddrByOffset dst offset)
  !!ir (dst := !.ctxt R.ST6)
  !!ir (updateAddrByOffset dst offset)
  !!ir (dst := !.ctxt R.ST7)
  !!ir (updateAddrByOffset dst offset)

let fsave ins insLen ctxt =
  let ir = IRBuilder (32)
  let dst = transOneOpr ins insLen ctxt
  let baseReg = getBaseReg dst
  let regSave = AST.tmpvar (getAddrRegSize dst)
  let addrRegSize = getAddrRegSize dst
  !<ir insLen
  !!ir (regSave := baseReg)
  let eDst = extendAddr dst 112<rt>
  m14Stenv eDst ctxt ir
  !!ir (updateAddrByOffset eDst (numI32 28 addrRegSize))
  stSts eDst ctxt ir
  !!ir (!.ctxt R.FCW := numI32 0x037F 16<rt>)
  !!ir (!.ctxt R.FSW := AST.num0 16<rt>)
  !!ir (!.ctxt R.FTW := numI32 0xFFFF 16<rt>)
  !!ir (!.ctxt R.FDP := AST.num0 64<rt>)
  !!ir (!.ctxt R.FIP := AST.num0 64<rt>)
  !!ir (!.ctxt R.FOP := AST.num0 16<rt>)
  !!ir (baseReg := regSave)
  !>ir insLen

let private ldSts src ctxt ir =
  !?ir (assignFPUReg R.ST0 (AST.xtlo 80<rt> src) ctxt)
  !?ir (assignFPUReg R.ST1 (AST.extract src 80<rt> 80) ctxt)
  !?ir (assignFPUReg R.ST2 (AST.extract src 80<rt> 160) ctxt)
  !?ir (assignFPUReg R.ST3 (AST.extract src 80<rt> 240) ctxt)
  !?ir (assignFPUReg R.ST4 (AST.extract src 80<rt> 320) ctxt)
  !?ir (assignFPUReg R.ST5 (AST.extract src 80<rt> 400) ctxt)
  !?ir (assignFPUReg R.ST6 (AST.extract src 80<rt> 480) ctxt)
  !?ir (assignFPUReg R.ST7 (AST.extract src 80<rt> 560) ctxt)

let frstor ins insLen ctxt =
  let ir = IRBuilder (32)
  let src = transOneOpr ins insLen ctxt
  !<ir insLen
  match AST.typeOf src with
  | 752<rt> ->
    m14fldenv (AST.xtlo 112<rt> src) ctxt ir
  | 864<rt> ->
    m28fldenv (AST.xtlo 224<rt> src) ctxt ir
  | _ -> raise InvalidOperandSizeException
  ldSts (AST.xthi 640<rt> src) ctxt ir
  !>ir insLen

let fstsw ins insLen ctxt =
  let ir = IRBuilder (16)
  let oprExpr = transOneOpr ins insLen ctxt
  !<ir insLen
  checkFPUExceptions ctxt ir
  !!ir (oprExpr := !.ctxt R.FSW)
  allCFlagsUndefined ctxt ir
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
  allCFlagsUndefined ctxt ir
  !>ir insLen

let fnop _ins insLen ctxt =
  let ir = IRBuilder (8)
  !<ir insLen
  allCFlagsUndefined ctxt ir
  !>ir insLen

let private saveFxsaveMMX ctxt addr offset ir =
  let r64 = AST.num0 64<rt>
  let mRegs =
    [ r64
      !.ctxt R.MM0; r64; !.ctxt R.MM1; r64; !.ctxt R.MM2; r64; !.ctxt R.MM3
      r64
      !.ctxt R.MM4; r64; !.ctxt R.MM5; r64; !.ctxt R.MM6; r64; !.ctxt R.MM7 ]
  List.iter (fun reg -> !!ir (updateAddrByOffset addr offset)
                        !!ir (addr := reg)) mRegs

let private loadFxrstorMMX ctxt addr ir =
  let offset = AST.num (BitVector.ofInt32 16 (getAddrRegSize addr))
  let mRegs = [ R.MM0; R.MM1; R.MM2; R.MM3; R.MM4; R.MM5; R.MM6; R.MM7 ]
  List.iter (fun reg -> !!ir (updateAddrByOffset addr (offset))
                        !!ir (!.ctxt reg := addr)) mRegs

let private saveFxsaveXMM ctxt addr offset xRegs ir =
  let pv r = getPseudoRegVar128 ctxt r
  let exprs =
    List.fold(fun acc r -> let r2, r1 = pv r in r1 :: (r2 :: acc)) [] xRegs
  List.iter (fun reg -> !!ir (updateAddrByOffset addr offset)
                        !!ir (addr := reg)) exprs

let private loadFxrstorXMM ctxt addr xRegs ir =
  let pv r = getPseudoRegVar128 ctxt r
  let offset = AST.num (BitVector.ofInt32 8 (getAddrRegSize addr))
  let exprs =
    List.fold (fun acc r -> let r2, r1 = pv r in r1 :: (r2 :: acc)) [] xRegs
  List.iter (fun reg -> !!ir (updateAddrByOffset addr offset)
                        !!ir (reg := addr)) exprs

let private save64BitPromotedFxsave ctxt dst ir =
  let reserved8 = AST.num0 8<rt>
  let num3 = numI32 3 2<rt>
  let struct (t0, t1, t2, t3) = tmpVars4 1<rt>
  let struct (t4, t5, t6, t7) = tmpVars4 1<rt>
  let abrTagW = AST.tmpvar 8<rt>
  let offset = AST.num (BitVector.ofInt32 8 (getAddrRegSize dst))
  let regSave = AST.tmpvar (getAddrRegSize dst)
  let baseReg = getBaseReg dst
  let xRegs =
    [ R.XMM0; R.XMM1; R.XMM2; R.XMM3; R.XMM4; R.XMM5; R.XMM6; R.XMM7;
      R.XMM8; R.XMM9; R.XMM10; R.XMM11; R.XMM12; R.XMM13; R.XMM14; R.XMM15 ]
  !!ir (regSave := baseReg)
  !!ir (abrTagW :=
    AST.concat (AST.concat (AST.concat t7 t6) (AST.concat t5 t4))
               (AST.concat (AST.concat t3 t2) (AST.concat t1 t0)))
  !!ir (t0 := (!.ctxt R.FTW0 != num3))
  !!ir (t1 := (!.ctxt R.FTW1 != num3))
  !!ir (t2 := (!.ctxt R.FTW2 != num3))
  !!ir (t3 := (!.ctxt R.FTW3 != num3))
  !!ir (t4 := (!.ctxt R.FTW4 != num3))
  !!ir (t5 := (!.ctxt R.FTW5 != num3))
  !!ir (t6 := (!.ctxt R.FTW6 != num3))
  !!ir (t7 := (!.ctxt R.FTW7 != num3))
  !!ir (dst :=
    AST.concat (AST.concat (!.ctxt R.FOP) (AST.concat reserved8 abrTagW))
               (AST.concat (!.ctxt R.FSW) (!.ctxt R.FCW)))
  !!ir (updateAddrByOffset dst offset)
  !!ir (dst := !.ctxt R.FIP)
  !!ir (updateAddrByOffset dst offset)
  !!ir (dst := !.ctxt R.FDP)
  !!ir (updateAddrByOffset dst offset)
  !!ir (dst := AST.concat (!.ctxt R.MXCSRMASK) (!.ctxt R.MXCSR))
  saveFxsaveMMX ctxt dst offset ir
  saveFxsaveXMM ctxt dst offset (List.rev xRegs) ir
  !!ir (baseReg := regSave)

let private save64BitDefaultFxsave ctxt dst ir =
  let reserved8 = AST.num0 8<rt>
  let reserved16 = AST.num0 16<rt>
  let num3 = numI32 3 2<rt>
  let struct (t0, t1, t2, t3) = tmpVars4 1<rt>
  let struct (t4, t5, t6, t7) = tmpVars4 1<rt>
  let abrTagW = AST.tmpvar 8<rt>
  let offset = AST.num (BitVector.ofInt32 8 (getAddrRegSize dst))
  let regSave = AST.tmpvar (getAddrRegSize dst)
  let baseReg = getBaseReg dst
  let xRegs =
    [ R.XMM0; R.XMM1; R.XMM2; R.XMM3; R.XMM4; R.XMM5; R.XMM6; R.XMM7;
      R.XMM8; R.XMM9; R.XMM10; R.XMM11; R.XMM12; R.XMM13; R.XMM14; R.XMM15 ]
  !!ir (regSave := baseReg)
  !!ir (t0 := (!.ctxt R.FTW0 != num3))
  !!ir (t1 := (!.ctxt R.FTW1 != num3))
  !!ir (t2 := (!.ctxt R.FTW2 != num3))
  !!ir (t3 := (!.ctxt R.FTW3 != num3))
  !!ir (t4 := (!.ctxt R.FTW4 != num3))
  !!ir (t5 := (!.ctxt R.FTW5 != num3))
  !!ir (t6 := (!.ctxt R.FTW6 != num3))
  !!ir (t7 := (!.ctxt R.FTW7 != num3))
  !!ir (abrTagW :=
    AST.concat (AST.concat (AST.concat t7 t6) (AST.concat t5 t4))
               (AST.concat (AST.concat t3 t2) (AST.concat t1 t0)))
  !!ir (dst :=
    AST.concat (AST.concat (!.ctxt R.FOP) (AST.concat reserved8 abrTagW))
               (AST.concat (!.ctxt R.FSW) (!.ctxt R.FCW)))
  !!ir (updateAddrByOffset dst offset)
  !!ir (dst := AST.concat (AST.xtlo 32<rt> (!.ctxt R.FIP))
                           (AST.concat (!.ctxt R.FCS) reserved16))
  !!ir (updateAddrByOffset dst offset)
  !!ir (dst := AST.concat (AST.xtlo 32<rt> (!.ctxt R.FDP))
                           (AST.concat (!.ctxt R.FDS) reserved16))
  !!ir (updateAddrByOffset dst offset)
  !!ir (dst := AST.concat (!.ctxt R.MXCSRMASK) (!.ctxt R.MXCSR))
  saveFxsaveMMX ctxt dst offset ir
  saveFxsaveXMM ctxt dst offset (List.rev xRegs) ir
  !!ir (baseReg := regSave)

let private saveLegacyFxsave ctxt dst ir =
  let reserved8 = AST.num0 8<rt>
  let reserved16 = AST.num0 16<rt>
  let num3 = numI32 3 2<rt>
  let struct (t0, t1, t2, t3) = tmpVars4 1<rt>
  let struct (t4, t5, t6, t7) = tmpVars4 1<rt>
  let abrTagW = AST.tmpvar 8<rt>
  let offset = AST.num (BitVector.ofInt32 8 (getAddrRegSize dst))
  let regSave = AST.tmpvar (getAddrRegSize dst)
  let baseReg = getBaseReg dst
  let xRegs = [ R.XMM0; R.XMM1; R.XMM2; R.XMM3; R.XMM4; R.XMM5; R.XMM6; R.XMM7 ]
  !!ir (regSave := baseReg)
  !!ir (t0 := (!.ctxt R.FTW0 != num3))
  !!ir (t1 := (!.ctxt R.FTW1 != num3))
  !!ir (t2 := (!.ctxt R.FTW2 != num3))
  !!ir (t3 := (!.ctxt R.FTW3 != num3))
  !!ir (t4 := (!.ctxt R.FTW4 != num3))
  !!ir (t5 := (!.ctxt R.FTW5 != num3))
  !!ir (t6 := (!.ctxt R.FTW6 != num3))
  !!ir (t7 := (!.ctxt R.FTW7 != num3))
  !!ir (abrTagW :=
    AST.concat (AST.concat (AST.concat t7 t6) (AST.concat t5 t4))
               (AST.concat (AST.concat t3 t2) (AST.concat t1 t0)))
  !!ir (dst :=
    AST.concat (AST.concat (!.ctxt R.FOP) (AST.concat reserved8 abrTagW))
               (AST.concat (!.ctxt R.FSW) (!.ctxt R.FCW)))
  !!ir (updateAddrByOffset dst offset)
  !!ir
    (dst := AST.concat (AST.xtlo 32<rt> (!.ctxt R.FIP))
                       (AST.concat (!.ctxt R.FCS) reserved16))
  !!ir (updateAddrByOffset dst offset)
  !!ir (dst := AST.concat (AST.xtlo 32<rt> (!.ctxt R.FDP))
                            (AST.concat (!.ctxt R.FDS) reserved16))
  !!ir (updateAddrByOffset dst offset)
  !!ir (dst := AST.concat (!.ctxt R.MXCSRMASK) (!.ctxt R.MXCSR))
  saveFxsaveMMX ctxt dst offset ir
  saveFxsaveXMM ctxt dst offset (List.rev xRegs) ir
  !!ir (baseReg := regSave)

let private load64BitPromotedFxrstor ctxt src ir =
  let offset = AST.num (BitVector.ofInt32 8 (getAddrRegSize src))
  let xRegs =
    [ R.XMM0; R.XMM1; R.XMM2; R.XMM3; R.XMM4; R.XMM5; R.XMM6; R.XMM7;
      R.XMM8; R.XMM9; R.XMM10; R.XMM11; R.XMM12; R.XMM13; R.XMM14; R.XMM15 ]
  let tSrc = AST.tmpvar 64<rt>
  !!ir (tSrc := src)
  !!ir (!.ctxt R.FCW := AST.xtlo 16<rt> tSrc)
  !!ir (!.ctxt R.FSW := AST.extract tSrc 16<rt> 16)
  !!ir (!.ctxt R.FTW := AST.extract tSrc 8<rt> 32)
  !!ir (!.ctxt R.FOP := AST.extract tSrc 16<rt> 48)
  !!ir (updateAddrByOffset src offset)
  !!ir (tSrc := src)
  !!ir (!.ctxt R.FIP := tSrc)
  !!ir (updateAddrByOffset src offset)
  !!ir (tSrc := src)
  !!ir (!.ctxt R.FDP := tSrc)
  !!ir (updateAddrByOffset src offset)
  !!ir (tSrc := src)
  !!ir (!.ctxt R.MXCSR := AST.xtlo 32<rt> tSrc)
  !!ir (!.ctxt R.MXCSRMASK := AST.xthi 32<rt> tSrc)
  loadFxrstorMMX ctxt src ir
  loadFxrstorXMM ctxt src xRegs ir

let private load64BitDefaultFxrstor ctxt src ir =
  let offset = AST.num (BitVector.ofInt32 8 (getAddrRegSize src))
  let regSave = AST.tmpvar (getAddrRegSize src)
  let baseReg = getBaseReg src
  let struct (t0, t1, t2, t3) = tmpVars4 2<rt>
  let struct (t4, t5, t6, t7) = tmpVars4 2<rt>
  let tmp8 = AST.tmpvar 8<rt>
  let zero2 = AST.num0 2<rt>
  let three2 = numI32 3 2<rt>
  let xRegs =
    [ R.XMM0; R.XMM1; R.XMM2; R.XMM3; R.XMM4; R.XMM5; R.XMM6; R.XMM7;
      R.XMM8; R.XMM9; R.XMM10; R.XMM11; R.XMM12; R.XMM13; R.XMM14; R.XMM15 ]
  !!ir (regSave := baseReg)
  !!ir (tmp8 := AST.extract src 8<rt> 32)
  !!ir (t0 := AST.ite (AST.xtlo 1<rt> tmp8) zero2 three2)
  !!ir (t1 := AST.ite (AST.extract tmp8 1<rt> 1) zero2 three2)
  !!ir (t2 := AST.ite (AST.extract tmp8 1<rt> 2) zero2 three2)
  !!ir (t3 := AST.ite (AST.extract tmp8 1<rt> 3) zero2 three2)
  !!ir (t4 := AST.ite (AST.extract tmp8 1<rt> 4) zero2 three2)
  !!ir (t5 := AST.ite (AST.extract tmp8 1<rt> 5) zero2 three2)
  !!ir (t6 := AST.ite (AST.extract tmp8 1<rt> 6) zero2 three2)
  !!ir (t7 := AST.ite (AST.extract tmp8 1<rt> 7) zero2 three2)
  !!ir (!.ctxt R.FCW := AST.xtlo 16<rt> src)
  !!ir (!.ctxt R.FSW := AST.extract src 16<rt> 16)
  !!ir (!.ctxt R.FTW :=
    AST.concat (AST.concat (AST.concat t7 t6) (AST.concat t5 t4))
               (AST.concat (AST.concat t3 t2) (AST.concat t1 t0)))
  !!ir (!.ctxt R.FOP := AST.extract src 16<rt> 48)
  !!ir (updateAddrByOffset src offset)
  !!ir (AST.xtlo 32<rt> (!.ctxt R.FIP) := AST.xtlo 32<rt> src)
  !!ir (!.ctxt R.FCS := AST.extract src 16<rt> 32)
  !!ir (updateAddrByOffset src offset)
  !!ir (AST.xtlo 32<rt> (!.ctxt R.FDP) := AST.xtlo 32<rt> src)
  !!ir (!.ctxt R.FDS := AST.extract src 16<rt> 32)
  !!ir (updateAddrByOffset src offset)
  !!ir (!.ctxt R.MXCSR := AST.xtlo 32<rt> src)
  !!ir (!.ctxt R.MXCSRMASK := AST.xthi 32<rt> src)
  loadFxrstorMMX ctxt src ir
  loadFxrstorXMM ctxt src (List.rev xRegs) ir
  !!ir (baseReg := regSave)

let private loadLegacyFxrstor ctxt src ir =
  let offset = AST.num (BitVector.ofInt32 8 (getAddrRegSize src))
  let xRegs = [ R.XMM0; R.XMM1; R.XMM2; R.XMM3; R.XMM4; R.XMM5; R.XMM6; R.XMM7 ]
  let tSrc = AST.tmpvar 64<rt>
  let struct (t0, t1, t2, t3) = tmpVars4 1<rt>
  let struct (t4, t5, t6, t7) = tmpVars4 1<rt>
  let abrTagW = AST.tmpvar 8<rt>
  let num0, num3 = numI32 0 2<rt>, numI32 3 2<rt>
  !!ir (abrTagW :=
    AST.concat (AST.concat (AST.concat t7 t6) (AST.concat t5 t4))
               (AST.concat (AST.concat t3 t2) (AST.concat t1 t0)))
  !!ir (tSrc := src)
  !!ir (!.ctxt R.FCW := AST.xtlo 16<rt> tSrc)
  !!ir (!.ctxt R.FSW := AST.extract tSrc 16<rt> 16)
  !!ir (abrTagW := AST.extract tSrc 8<rt> 32)
  !!ir (!.ctxt R.FTW0 := AST.ite t0 num0 num3)
  !!ir (!.ctxt R.FTW1 := AST.ite t1 num0 num3)
  !!ir (!.ctxt R.FTW2 := AST.ite t2 num0 num3)
  !!ir (!.ctxt R.FTW3 := AST.ite t3 num0 num3)
  !!ir (!.ctxt R.FTW4 := AST.ite t4 num0 num3)
  !!ir (!.ctxt R.FTW5 := AST.ite t5 num0 num3)
  !!ir (!.ctxt R.FTW6 := AST.ite t6 num0 num3)
  !!ir (!.ctxt R.FTW7 := AST.ite t7 num0 num3)
  !!ir (!.ctxt R.FOP := AST.extract tSrc 16<rt> 48)
  !!ir (updateAddrByOffset src offset)
  !!ir (tSrc := src)
  !!ir (AST.xtlo 32<rt> (!.ctxt R.FIP) := AST.xtlo 32<rt> tSrc)
  !!ir (!.ctxt R.FCS := AST.extract tSrc 16<rt> 32)
  !!ir (updateAddrByOffset src offset)
  !!ir (tSrc := src)
  !!ir (AST.xtlo 32<rt> (!.ctxt R.FDP) := AST.xtlo 32<rt> tSrc)
  !!ir (!.ctxt R.FDS := AST.extract tSrc 16<rt> 32)
  !!ir (updateAddrByOffset src offset)
  !!ir (tSrc := src)
  !!ir (!.ctxt R.MXCSR := AST.xtlo 32<rt> tSrc)
  !!ir (!.ctxt R.MXCSRMASK := AST.xthi 32<rt>tSrc)
  loadFxrstorMMX ctxt src ir
  loadFxrstorXMM ctxt src xRegs ir

let fxrstor ins insLen ctxt =
  let ir = IRBuilder (128)
  let src = transOneOpr ins insLen ctxt
  let eSrc = extendAddr src 64<rt>
  !<ir insLen
  if ctxt.WordBitSize = 64<rt> then
    if hasREXW ins.REXPrefix then load64BitPromotedFxrstor ctxt eSrc ir
    else load64BitDefaultFxrstor ctxt eSrc ir
  else loadLegacyFxrstor ctxt eSrc ir
  !>ir insLen

let fxsave ins insLen ctxt =
  let ir = IRBuilder (128)
  let dst = transOneOpr ins insLen ctxt
  let eDst = extendAddr dst 64<rt>
  !<ir insLen
  if ctxt.WordBitSize = 64<rt> then
    if hasREXW ins.REXPrefix then save64BitPromotedFxsave ctxt eDst ir
    else save64BitDefaultFxsave ctxt eDst ir
  else saveLegacyFxsave ctxt eDst ir
  !>ir insLen
