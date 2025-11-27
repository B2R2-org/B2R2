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

module internal B2R2.FrontEnd.PPC.Lifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils

let (|RawNumOf|) (_, opr) =
  match opr with
  | OprImm imm -> imm
  | _ -> raise InvalidOperandException

let (|RawSftNumOf|) sft (_, opr) =
  match opr with
  | OprImm imm -> imm <<< sft
  | _ -> raise InvalidOperandException

let (|RegOf|) (bld, opr) =
  match opr with
  | OprReg reg -> regVar bld reg
  | _ -> raise InvalidOperandException

let (|RegOrZeroOf|) (bld: ILowUIRBuilder, opr) =
  match opr with
  | OprReg Register.R0 -> AST.num0 bld.RegType
  | OprReg reg -> regVar bld reg
  | _ -> raise InvalidOperandException

let (|NumOf|) (bld: ILowUIRBuilder, opr) =
  match opr with
  | OprImm imm -> numU64 imm bld.RegType
  | _ -> raise InvalidOperandException

let (|SftNumOf|) sft (bld: ILowUIRBuilder, opr) =
  match opr with
  | OprImm imm -> numU64 (imm <<< sft) bld.RegType
  | _ -> raise InvalidOperandException

let minusOne64 = 0xFFFFFFFFFFFFFFFFUL

let minusOne32 = 0xFFFFFFFFu

let getTwoOperands (bld: ILowUIRBuilder) = function
  | TwoOperands(opr1, opr2) ->
    (bld, opr1), (bld, opr2)
  | _ -> raise InvalidOperandException

let getThreeOperands (bld: ILowUIRBuilder) = function
  | ThreeOperands(opr1, opr2, opr3) ->
    (bld, opr1), (bld, opr2), (bld, opr3)
  | _ -> raise InvalidOperandException

let getFourOperands (bld: ILowUIRBuilder) = function
  | FourOperands(opr1, opr2, opr3, opr4) ->
    (bld, opr1), (bld, opr2), (bld, opr3), (bld, opr4)
  | _ -> raise InvalidOperandException

let transOperand bld = function
  | OprReg reg -> regVar bld reg
  | OprImm imm -> numU64 imm bld.RegType
  | OprCY cy -> numU32 (cy |> uint32) 2<rt>
  | OprL l -> numU32 (l |> uint32) 2<rt>
  | _ -> Terminator.futureFeature ()

let transTwoOperands bld = function
  | TwoOperands(opr1, opr2) ->
    transOperand bld opr1, transOperand bld opr2
  | _ -> raise InvalidOperandException

let transThreeOperands bld = function
  | ThreeOperands(opr1, opr2, opr3) ->
    transOperand bld opr1, transOperand bld opr2, transOperand bld opr3
  | _ -> raise InvalidOperandException

let transFourOperands bld = function
  | FourOperands(opr1, opr2, opr3, opr4) ->
    transOperand bld opr1, transOperand bld opr2,
    transOperand bld opr3, transOperand bld opr4
  | _ -> raise InvalidOperandException

let setOVAndSO bld value =
  let ov = AST.extract (regVar bld Register.XER) 1<rt> 30
  let so = AST.extract (regVar bld Register.XER) 1<rt> 31
  bld <+ (ov := value)
  bld <+ (so := so .| ov)

let setOV bld value =
  let ov = AST.extract (regVar bld Register.XER) 1<rt> 30
  bld <+ (ov := value)

let setOV32 bld value =
  let ov32 = AST.extract (regVar bld Register.XER) 1<rt> 19
  bld <+ (ov32 := value)

let setOVAndSOAndOV32 bld value =
  let ov = AST.extract (regVar bld Register.XER) 1<rt> 30
  setOVAndSO bld value
  setOV32 bld ov

let setCA bld value =
  let ca = AST.extract (regVar bld Register.XER) 1<rt> 29
  bld <+ (ca := value)

let setCA32 bld value =
  let ca32 = AST.extract (regVar bld Register.XER) 1<rt> 18
  bld <+ (ca32 := value)

let getAddOV bld in1 in2 out pos =
  let inBit1 = AST.extract in1 1<rt> pos
  let inBit2 = AST.extract in2 1<rt> pos
  let outBit = AST.extract out 1<rt> pos
  (inBit1 == inBit2) .& (inBit1 != outBit)

let setAddOVs bld in1 in2 out =
  setOVAndSO bld (getAddOV bld in1 in2 out 63)
  setOV32 bld (getAddOV bld in1 in2 out 31)

let getRecord bld target =
  let so = AST.extract (regVar bld Register.XER) 1<rt> 31
  let msb = AST.xthi 1<rt> target
  let eqCond = target == AST.num0 64<rt>
  let signCheck = AST.ite msb (numU32 4u 3<rt>) (numU32 2u 3<rt>)
  let c = AST.ite eqCond (AST.num1 3<rt>) signCheck
  AST.concat c so

let setRecord bld target =
  let cr0 = regVar bld Register.CR0
  bld <+ (cr0 := getRecord bld target)

let setRecordUndef bld target undefCond =
  let cr0 = regVar bld Register.CR0
  let so = AST.extract (regVar bld Register.XER) 1<rt> 31
  let undefCr0 = AST.concat (AST.xthi 3<rt> cr0) so
  bld <+ (cr0 := AST.ite undefCond undefCr0 (getRecord bld target))

let setRecordSO bld =
  let cr0 = regVar bld Register.CR0
  let so = AST.extract (regVar bld Register.XER) 1<rt> 31
  bld <+ (AST.xtlo 1<rt> cr0 := so)

let getAddOutCarry bld in1 in2 out pos =
  let struct (t1, t2, t3) = tmpVars3 bld 1<rt>
  bld <+ (t1 := AST.extract in1 1<rt> pos)
  bld <+ (t2 := AST.extract in2 1<rt> pos)
  bld <+ (t3 := AST.not (AST.extract out 1<rt> pos))
  (t1 .& t2) .| (t2 .& t3) .| (t1 .& t3)

let getAddInCarry bld in1 in2 out pos =
  let inBit1 = AST.extract in1 1<rt> pos
  let inBit2 = AST.extract in2 1<rt> pos
  let outBit = AST.extract out 1<rt> pos
  inBit1 <+> inBit2 <+> outBit

let setAddCarrys bld in1 in2 out =
  setCA bld (getAddOutCarry bld in1 in2 out 63)
  setCA32 bld (getAddInCarry bld in1 in2 out 32)

let appendAdd bld dst src1 src2 ovCond rcCond caCond =
  bld <+ (dst := src1 .+ src2)
  if ovCond then setAddOVs bld src1 src2 dst else ()
  if rcCond then setRecord bld dst else ()
  if caCond then setAddCarrys bld src1 src2 dst else ()

let appendAddExt bld dst src1 src2 ovCond rcCond caCond =
  let xer = regVar bld Register.XER
  let ca = AST.extract xer 1<rt> 29
  let sum = src1 .+ src2
  bld <+ (dst := AST.ite ca (sum .+ AST.num1 64<rt>) sum)
  if ovCond then setAddOVs bld src1 src2 dst else ()
  if rcCond then setRecord bld dst else ()
  if caCond then setAddCarrys bld src1 src2 dst else ()

let appendSubf bld dst src1 src2 ovCond rcCond caCond =
  let notSrc1 = tmpVar bld 64<rt>
  bld <+ (notSrc1 := AST.not src1)
  bld <+ (dst := notSrc1 .+ src2 .+ AST.num1 64<rt>)
  if ovCond then setAddOVs bld notSrc1 src2 dst else ()
  if rcCond then setRecord bld dst else ()
  if caCond then setAddCarrys bld notSrc1 src2 dst else ()

let appendSubfExt bld dst src1 src2 ovCond rcCond caCond =
  let notSrc1 = tmpVar bld 64<rt>
  let xer = regVar bld Register.XER
  let ca = AST.extract xer 1<rt> 29
  let sum = notSrc1 .+ src2
  bld <+ (notSrc1 := AST.not src1)
  bld <+ (dst := AST.ite ca (sum .+ AST.num1 64<rt>) sum)
  if ovCond then setAddOVs bld notSrc1 src2 dst else ()
  if rcCond then setRecord bld dst else ()
  if caCond then setAddCarrys bld notSrc1 src2 dst else ()

let getCannotReprIn bld out isDouble isSigned =
  let checkSize = if isDouble then 65<rt> else 33<rt>
  let minusOne = BitVector.UnsignedMax checkSize |> AST.num
  if isSigned then
    let t = tmpVar bld checkSize
    bld <+ (t := AST.xthi checkSize out)
    (t != AST.num0 checkSize) .& (t != minusOne)
  else
    AST.xthi checkSize out != AST.num0 checkSize

let getMulLowWordOV bld out isSigned =
  getCannotReprIn bld out false isSigned

let getMulLowDoubleOV bld out isSigned =
  getCannotReprIn bld out true isSigned

let appendMulLowWord bld dst src1 src2 isSigned ovCond rcCond =
  let struct (in1, in2) = tmpVars2 bld 64<rt>
  let extFunc = if isSigned then AST.sext else AST.zext
  bld <+ (in1 := extFunc 64<rt> (AST.xtlo 32<rt> src1))
  bld <+ (in2 := extFunc 64<rt> (AST.xtlo 32<rt> src2))
  bld <+ (dst := in1 .* in2)
  if ovCond then
    setOVAndSOAndOV32 bld (getMulLowWordOV bld dst isSigned) else ()
  if rcCond then setRecord bld dst else ()

let appendMulHighWord bld dst src1 src2 isSigned rcCond =
  let struct (in1, in2) = tmpVars2 bld 64<rt>
  let extFunc = if isSigned then AST.sext else AST.zext
  bld <+ (in1 := extFunc 64<rt> (AST.xtlo 32<rt> src1))
  bld <+ (in2 := extFunc 64<rt> (AST.xtlo 32<rt> src2))
  bld <+ (AST.xtlo 32<rt> dst := AST.xthi 32<rt> (in1 .* in2))
  if rcCond then setRecordSO bld else ()

let appendMulLowDouble bld dst src1 src2 isSigned ovCond rcCond =
  if ovCond then
    let struct (in1, in2, out) = tmpVars3 bld 128<rt>
    let extFunc = if isSigned then AST.sext else AST.zext
    bld <+ (in1 := extFunc 128<rt> src1)
    bld <+ (in2 := extFunc 128<rt> src2)
    bld <+ (out := in1 .* in2)
    bld <+ (dst := AST.xtlo 64<rt> out)
    setOVAndSOAndOV32 bld (getMulLowDoubleOV bld out isSigned)
  else
    bld <+ (dst := src1 .* src2)
  if rcCond then setRecord bld dst else ()

let appendMulHighDouble bld dst src1 src2 isSigned rcCond =
  let struct (in1, in2, out) = tmpVars3 bld 128<rt>
  let extFunc = if isSigned then AST.sext else AST.zext
  bld <+ (in1 := extFunc 128<rt> src1)
  bld <+ (in2 := extFunc 128<rt> src2)
  bld <+ (out := in1 .* in2)
  bld <+ (dst := AST.xthi 64<rt> out)
  if rcCond then setRecord bld dst else ()

let getDivWordOV bld in1 in2 isSigned =
  if isSigned then
    let cond1 = in1 == numU32 (1u <<< 31) 32<rt>
    let cond2 = in2 == numU32 minusOne32 32<rt>
    let cond3 = in2 == AST.num0 32<rt>
    (cond1 .& cond2) .| cond3
  else in2 == AST.num0 32<rt>

let getDivDoubleOV bld in1 in2 isSigned =
  if isSigned then
    let cond1 = in1 == numU64 (1UL <<< 63) 64<rt>
    let cond2 = in2 == numU64 minusOne64 64<rt>
    let cond3 = in2 == AST.num0 64<rt>
    (cond1 .& cond2) .| cond3
  else in2 == AST.num0 64<rt>

let appendDivWord bld dst src1 src2 isSigned ovCond rcCond =
  let struct (in1, in2) = tmpVars2 bld 32<rt>
  let zeroCond = in2 == AST.num0 32<rt>
  let out32 = if isSigned then in1 ?/ in2 else in1 ./ in2
  let out = AST.concat (AST.xthi 32<rt> dst) out32
  bld <+ (in1 := AST.xtlo 32<rt> src1)
  bld <+ (in2 := AST.xtlo 32<rt> src2)
  bld <+ (dst := AST.ite zeroCond dst out)
  if ovCond then setOVAndSOAndOV32 bld (getDivWordOV bld in1 in2 isSigned)
  if rcCond then setRecordSO bld

let appendDivDouble bld dst src1 src2 isSigned ovCond rcCond =
  let zeroCond = src2 == AST.num0 64<rt>
  let out = if isSigned then src1 ?/ src2 else src1 ./ src2
  bld <+ (dst := AST.ite zeroCond dst out)
  match ovCond, rcCond with
  | true, true ->
    let tmp = tmpVar bld 1<rt>
    bld <+ (tmp := getDivDoubleOV bld src1 src2 isSigned)
    setOVAndSOAndOV32 bld tmp
    setRecordUndef bld dst tmp
  | true, false ->
    setOVAndSOAndOV32 bld (getDivDoubleOV bld src1 src2 isSigned)
  | false, true ->
    setRecordUndef bld dst (getDivDoubleOV bld src1 src2 isSigned)
  | false, false -> ()

let getDivWordExtendedOV bld in1 in2 out isSigned =
  getCannotReprIn bld out false isSigned .| (in2 == AST.num0 64<rt>)

let getDivDoubleExtendedOV bld in1 in2 out isSigned =
  getCannotReprIn bld out true isSigned .| (in2 == AST.num0 128<rt>)

let appendDivWordExtended bld dst src1 src2 isSigned ovCond rcCond =
  let struct (in1, in2, tempOut) = tmpVars3 bld 64<rt>
  let zeroCond = in2 == AST.num0 64<rt>
  let extFunc = if isSigned then AST.sext else AST.zext
  let out = AST.concat (AST.xthi 32<rt> dst) (AST.xtlo 32<rt> tempOut)
  bld <+ (in1 := AST.concat (AST.xtlo 32<rt> src1) (AST.num0 32<rt>))
  bld <+ (in2 := extFunc 64<rt> (AST.xtlo 32<rt> src2))
  bld <+ (tempOut := if isSigned then in1 ?/ in2 else in1 ./ in2)
  bld <+ (dst := AST.ite zeroCond dst out)
  if ovCond then
    setOVAndSOAndOV32 bld (getDivWordExtendedOV bld in1 in2 tempOut isSigned)
  if rcCond then setRecordSO bld

let appendDivDoubleExtended bld dst src1 src2 isSigned ovCond rcCond =
  let struct (in1, in2, out) = tmpVars3 bld 128<rt>
  let zeroCond = in2 == AST.num0 128<rt>
  let extFunc = if isSigned then AST.sext else AST.zext
  let outExpr = if isSigned then in1 ?/ in2 else in1 ./ in2
  bld <+ (in1 := AST.concat src1 (AST.num0 64<rt>))
  bld <+ (in2 := extFunc 128<rt> src2)
  bld <+ (out := AST.ite zeroCond (AST.num0 128<rt>) outExpr)
  bld <+ (dst := AST.xtlo 64<rt> out)
  match ovCond, rcCond with
  | true, true ->
    let tmp = tmpVar bld 1<rt>
    bld <+ (tmp := getDivDoubleExtendedOV bld in1 in2 out isSigned)
    setOVAndSOAndOV32 bld tmp
    setRecordUndef bld dst tmp
  | true, false ->
    setOVAndSOAndOV32 bld (getDivDoubleExtendedOV bld in1 in2 out isSigned)
  | false, true ->
    setRecordUndef bld dst (getDivDoubleExtendedOV bld in1 in2 out isSigned)
  | false, false -> ()

let appendModWord bld dst src1 src2 isSigned =
  let struct (in1, in2) = tmpVars2 bld 32<rt>
  let zeroCond = in2 == AST.num0 32<rt>
  let out32 =
    if isSigned then in1 .- (in1 ?/ in2 .* in2)
    else in1 .- (in1 ./ in2 .* in2)
  let out = AST.concat (AST.xthi 32<rt> dst) out32
  bld <+ (in1 := AST.xtlo 32<rt> src1)
  bld <+ (in2 := AST.xtlo 32<rt> src2)
  bld <+ (dst := AST.ite zeroCond dst out)

let appendModDouble bld dst src1 src2 isSigned =
  let zeroCond = src2 == AST.num0 64<rt>
  let out =
    if isSigned then src1 .- (src1 ?/ src2 .* src2)
    else src1 .- (src1 ./ src2 .* src2)
  bld <+ (dst := AST.ite zeroCond dst out)

let appendMulAddLowDouble bld dst src1 src2 src3 isSigned =
  bld <+ (dst := src1 .* src2 .+ src3)

let appendMulAddHighDouble bld dst src1 src2 src3 isSigned =
  let extFunc = if isSigned then AST.sext else AST.zext
  let in1 = extFunc 128<rt> src1
  let in2 = extFunc 128<rt> src2
  let in3 = extFunc 128<rt> src3
  bld <+ (dst := AST.xthi 64<rt> (in1 .* in2 .+ in3))

let sideEffects (ins: Instruction) insLen bld eff =
  bld <!-- (ins.Address, insLen)
  bld <+ AST.sideEffect eff
  bld --!> insLen

let addi (ins: Instruction) insLen bld =
  match getThreeOperands bld ins.Operands with
  | RegOf rt, RegOrZeroOf ra, NumOf si ->
    bld <!-- (ins.Address, insLen)
    appendAdd bld rt ra si false false false
    bld --!> insLen

let addis (ins: Instruction) insLen bld =
  match getThreeOperands bld ins.Operands with
  | RegOf rt, RegOrZeroOf ra, SftNumOf 16 si ->
    bld <!-- (ins.Address, insLen)
    appendAdd bld rt ra si false false false
    bld --!> insLen

let addpcis (ins: Instruction) insLen bld =
  match getTwoOperands bld ins.Operands with
  | RegOf rt, RawSftNumOf 16 d ->
    let nia = ins.Address + 4UL
    let res = numU64 (nia + d) 64<rt>
    bld <!-- (ins.Address, insLen)
    bld <+ (rt := res)
    bld --!> insLen

let add (ins: Instruction) insLen bld ov rc ca =
  let dst, src1, src2 = transThreeOperands bld ins.Operands
  bld <!-- (ins.Address, insLen)
  appendAdd bld dst src1 src2 ov rc ca
  bld --!> insLen

let adde (ins: Instruction) insLen bld ov rc ca =
  let dst, src1, src2 = transThreeOperands bld ins.Operands
  bld <!-- (ins.Address, insLen)
  appendAddExt bld dst src1 src2 ov rc ca
  bld --!> insLen

let addme (ins: Instruction) insLen bld ov rc ca =
  let dst, src = transTwoOperands bld ins.Operands
  bld <!-- (ins.Address, insLen)
  appendAddExt bld dst src (numU64 minusOne64 64<rt>) ov rc ca
  bld --!> insLen

let addze (ins: Instruction) insLen bld ov rc ca =
  let dst, src = transTwoOperands bld ins.Operands
  bld <!-- (ins.Address, insLen)
  appendAddExt bld dst src (AST.num0 64<rt>) ov rc ca
  bld --!> insLen

let addex (ins: Instruction) insLen bld =
  let dst, src1, src2, _ = transFourOperands bld ins.Operands
  let xer = regVar bld Register.XER
  let ov = AST.extract xer 1<rt> 30
  let sum = src1 .+ src2
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := AST.ite ov (sum .+ AST.num1 64<rt>) sum)
  setOV bld (getAddOutCarry bld src1 src2 dst 63)
  setOV32 bld (getAddInCarry bld src1 src2 dst 32)
  bld --!> insLen

let subf (ins: Instruction) insLen bld ov rc ca =
  let dst, src1, src2 = transThreeOperands bld ins.Operands
  bld <!-- (ins.Address, insLen)
  appendSubf bld dst src1 src2 ov rc ca
  bld --!> insLen

let subfe (ins: Instruction) insLen bld ov rc ca =
  let dst, src1, src2 = transThreeOperands bld ins.Operands
  bld <!-- (ins.Address, insLen)
  appendSubfExt bld dst src1 src2 ov rc ca
  bld --!> insLen

let subfme (ins: Instruction) insLen bld ov rc ca =
  let dst, src = transTwoOperands bld ins.Operands
  bld <!-- (ins.Address, insLen)
  appendSubfExt bld dst src (numU64 minusOne64 64<rt>) ov rc ca
  bld --!> insLen

let subfze (ins: Instruction) insLen bld ov rc ca =
  let dst, src = transTwoOperands bld ins.Operands
  bld <!-- (ins.Address, insLen)
  appendSubfExt bld dst src (AST.num0 64<rt>) ov rc ca
  bld --!> insLen

let neg (ins: Instruction) insLen bld ov rc ca =
  let dst, src = transTwoOperands bld ins.Operands
  bld <!-- (ins.Address, insLen)
  appendSubf bld dst src (AST.num0 64<rt>) ov rc ca
  bld --!> insLen

let mullw (ins: Instruction) insLen bld isSigned ov rc =
  let dst, src1, src2 = transThreeOperands bld ins.Operands
  bld <!-- (ins.Address, insLen)
  appendMulLowWord bld dst src1 src2 isSigned ov rc
  bld --!> insLen

let mulhw (ins: Instruction) insLen bld isSigned rc =
  let dst, src1, src2 = transThreeOperands bld ins.Operands
  bld <!-- (ins.Address, insLen)
  appendMulHighWord bld dst src1 src2 isSigned rc
  bld --!> insLen

let mulld (ins: Instruction) insLen bld isSigned ov rc =
  let dst, src1, src2 = transThreeOperands bld ins.Operands
  bld <!-- (ins.Address, insLen)
  appendMulLowDouble bld dst src1 src2 isSigned ov rc
  bld --!> insLen

let mulhd (ins: Instruction) insLen bld isSigned rc =
  let dst, src1, src2 = transThreeOperands bld ins.Operands
  bld <!-- (ins.Address, insLen)
  appendMulHighDouble bld dst src1 src2 isSigned rc
  bld --!> insLen

let divw (ins: Instruction) insLen bld isSigned ov rc =
  let dst, src1, src2 = transThreeOperands bld ins.Operands
  bld <!-- (ins.Address, insLen)
  appendDivWord bld dst src1 src2 isSigned ov rc
  bld --!> insLen

let divwe (ins: Instruction) insLen bld isSigned ov rc =
  let dst, src1, src2 = transThreeOperands bld ins.Operands
  bld <!-- (ins.Address, insLen)
  appendDivWordExtended bld dst src1 src2 isSigned ov rc
  bld --!> insLen

let divd (ins: Instruction) insLen bld isSigned ov rc =
  let dst, src1, src2 = transThreeOperands bld ins.Operands
  bld <!-- (ins.Address, insLen)
  appendDivDouble bld dst src1 src2 isSigned ov rc
  bld --!> insLen

let divde (ins: Instruction) insLen bld isSigned ov rc =
  let dst, src1, src2 = transThreeOperands bld ins.Operands
  bld <!-- (ins.Address, insLen)
  appendDivDoubleExtended bld dst src1 src2 isSigned ov rc
  bld --!> insLen

let modw (ins: Instruction) insLen bld isSigned =
  let dst, src1, src2 = transThreeOperands bld ins.Operands
  bld <!-- (ins.Address, insLen)
  appendModWord bld dst src1 src2 isSigned
  bld --!> insLen

let modd (ins: Instruction) insLen bld isSigned =
  let dst, src1, src2 = transThreeOperands bld ins.Operands
  bld <!-- (ins.Address, insLen)
  appendModDouble bld dst src1 src2 isSigned
  bld --!> insLen

let maddhd (ins: Instruction) insLen bld isSigned =
  let dst, src1, src2, src3 = transFourOperands bld ins.Operands
  bld <!-- (ins.Address, insLen)
  appendMulAddHighDouble bld dst src1 src2 src3 isSigned
  bld --!> insLen

let maddld (ins: Instruction) insLen bld isSigned =
  let dst, src1, src2, src3 = transFourOperands bld ins.Operands
  bld <!-- (ins.Address, insLen)
  appendMulAddLowDouble bld dst src1 src2 src3 isSigned
  bld --!> insLen

/// Translate IR.
let translate (ins: Instruction) insLen bld =
  match ins.Opcode with
  | Op.ADDI -> addi ins insLen bld
  | Op.ADDIS -> addis ins insLen bld
  | Op.ADDPCIS -> addpcis ins insLen bld
  | Op.ADD -> add ins insLen bld false false false
  | Op.ADD_DOT -> add ins insLen bld false true false
  | Op.ADDO -> add ins insLen bld true false false
  | Op.ADDO_DOT -> add ins insLen bld true true false
  | Op.SUBF -> subf ins insLen bld false false false
  | Op.SUBF_DOT -> subf ins insLen bld false true false
  | Op.SUBFO -> subf ins insLen bld true false false
  | Op.SUBFO_DOT -> subf ins insLen bld true true false
  | Op.ADDIC -> add ins insLen bld false false true
  | Op.ADDIC_DOT -> add ins insLen bld false true true
  | Op.SUBFIC -> subf ins insLen bld false false true
  | Op.ADDC -> add ins insLen bld false false true
  | Op.ADDC_DOT -> add ins insLen bld false true true
  | Op.ADDCO -> add ins insLen bld true false true
  | Op.ADDCO_DOT -> add ins insLen bld true true true
  | Op.SUBFC -> subf ins insLen bld false false true
  | Op.SUBFC_DOT -> subf ins insLen bld false true true
  | Op.SUBFCO -> subf ins insLen bld true false true
  | Op.SUBFCO_DOT -> subf ins insLen bld true true true
  | Op.ADDE -> adde ins insLen bld false false true
  | Op.ADDE_DOT -> adde ins insLen bld false true true
  | Op.ADDEO -> adde ins insLen bld true false true
  | Op.ADDEO_DOT -> adde ins insLen bld true true true
  | Op.SUBFE -> subfe ins insLen bld false false true
  | Op.SUBFE_DOT -> subfe ins insLen bld false true true
  | Op.SUBFEO -> subfe ins insLen bld true false true
  | Op.SUBFEO_DOT -> subfe ins insLen bld true true true
  | Op.ADDME -> addme ins insLen bld false false true
  | Op.ADDME_DOT -> addme ins insLen bld false true true
  | Op.ADDMEO -> addme ins insLen bld true false true
  | Op.ADDMEO_DOT -> addme ins insLen bld true true true
  | Op.SUBFME -> subfme ins insLen bld false false true
  | Op.SUBFME_DOT -> subfme ins insLen bld false true true
  | Op.SUBFMEO -> subfme ins insLen bld true false true
  | Op.SUBFMEO_DOT -> subfme ins insLen bld true true true
  | Op.ADDEX -> addex ins insLen bld
  | Op.ADDZE -> addze ins insLen bld false false true
  | Op.ADDZE_DOT -> addze ins insLen bld false true true
  | Op.ADDZEO -> addze ins insLen bld true false true
  | Op.ADDZEO_DOT -> addze ins insLen bld true true true
  | Op.SUBFZE -> subfze ins insLen bld false false true
  | Op.SUBFZE_DOT -> subfze ins insLen bld false true true
  | Op.SUBFZEO -> subfze ins insLen bld true false true
  | Op.SUBFZEO_DOT -> subfze ins insLen bld true true true
  | Op.NEG -> neg ins insLen bld false false false
  | Op.NEG_DOT -> neg ins insLen bld false true false
  | Op.NEGO -> neg ins insLen bld true false false
  | Op.NEGO_DOT -> neg ins insLen bld true true false
  | Op.MULLI -> mulld ins insLen bld true false false
  | Op.MULLW -> mullw ins insLen bld true false false
  | Op.MULLW_DOT -> mullw ins insLen bld true false true
  | Op.MULLWO -> mullw ins insLen bld true true false
  | Op.MULLWO_DOT -> mullw ins insLen bld true true true
  | Op.MULHW -> mulhw ins insLen bld true false
  | Op.MULHW_DOT -> mulhw ins insLen bld true true
  | Op.MULHWU -> mulhw ins insLen bld false false
  | Op.MULHWU_DOT -> mulhw ins insLen bld false true
  | Op.DIVW -> divw ins insLen bld true false false
  | Op.DIVW_DOT -> divw ins insLen bld true false true
  | Op.DIVWO -> divw ins insLen bld true true false
  | Op.DIVWO_DOT -> divw ins insLen bld true true true
  | Op.DIVWU -> divw ins insLen bld false false false
  | Op.DIVWU_DOT -> divw ins insLen bld false false true
  | Op.DIVWUO -> divw ins insLen bld false true false
  | Op.DIVWUO_DOT -> divw ins insLen bld false true true
  | Op.DIVWE -> divwe ins insLen bld true false false
  | Op.DIVWE_DOT -> divwe ins insLen bld true false true
  | Op.DIVWEO -> divwe ins insLen bld true true false
  | Op.DIVWEO_DOT -> divwe ins insLen bld true true true
  | Op.DIVWEU -> divwe ins insLen bld false false false
  | Op.DIVWEU_DOT -> divwe ins insLen bld false false true
  | Op.DIVWEUO -> divwe ins insLen bld false true false
  | Op.DIVWEUO_DOT -> divwe ins insLen bld false true true
  | Op.MODSW -> modw ins insLen bld false
  | Op.MODUW -> modw ins insLen bld true
  | Op.DARN -> sideEffects ins insLen bld UnsupportedExtension
  | Op.MULLD -> mulld ins insLen bld true false false
  | Op.MULLD_DOT -> mulld ins insLen bld true false true
  | Op.MULLDO -> mulld ins insLen bld true true false
  | Op.MULLDO_DOT -> mulld ins insLen bld true true true
  | Op.MULHD -> mulhd ins insLen bld true false
  | Op.MULHD_DOT -> mulhd ins insLen bld true true
  | Op.MULHDU -> mulhd ins insLen bld false false
  | Op.MULHDU_DOT -> mulhd ins insLen bld false true
  | Op.MADDHD -> maddhd ins insLen bld true
  | Op.MADDHDU -> maddhd ins insLen bld false
  | Op.MADDLD -> maddld ins insLen bld true
  | Op.DIVD -> divd ins insLen bld true false false
  | Op.DIVD_DOT -> divd ins insLen bld true false true
  | Op.DIVDO -> divd ins insLen bld true true false
  | Op.DIVDO_DOT -> divd ins insLen bld true true true
  | Op.DIVDU -> divd ins insLen bld false false false
  | Op.DIVDU_DOT -> divd ins insLen bld false false true
  | Op.DIVDUO -> divd ins insLen bld false true false
  | Op.DIVDUO_DOT -> divd ins insLen bld false true true
  | Op.DIVDE -> divde ins insLen bld true false false
  | Op.DIVDE_DOT -> divde ins insLen bld true false true
  | Op.DIVDEO -> divde ins insLen bld true true false
  | Op.DIVDEO_DOT -> divde ins insLen bld true true true
  | Op.DIVDEU -> divde ins insLen bld false false false
  | Op.DIVDEU_DOT -> divde ins insLen bld false false true
  | Op.DIVDEUO -> divde ins insLen bld false true false
  | Op.DIVDEUO_DOT -> divde ins insLen bld false true true
  | Op.MODSD -> modd ins insLen bld false
  | Op.MODUD -> modd ins insLen bld true
  | o -> raise (NotImplementedIRException(Disasm.opCodeToString o))