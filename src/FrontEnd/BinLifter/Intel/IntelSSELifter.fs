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

module internal B2R2.FrontEnd.BinLifter.Intel.SSELifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingOperators
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.BinLifter.Intel
open B2R2.FrontEnd.BinLifter.Intel.Helper
open B2R2.FrontEnd.BinLifter.Intel.LiftingUtils
open B2R2.FrontEnd.BinLifter.Intel.MMXLifter

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
    if isDouble then numU64 0xffffffffffffUL 64<rt>
    else numU64 0x7fffffUL 32<rt>
  src .& mask

let isNan isDouble expr =
  let exponent = getExponent isDouble expr
  let mantissa = getMantissa isDouble expr
  let e = if isDouble then numI32 0x7ff 32<rt> else numI32 0xff 32<rt>
  let zero = if isDouble then AST.num0 64<rt> else AST.num0 32<rt>
  (exponent == e) .& (mantissa != zero)

let addsubpd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
  let srcB, srcA = transOprToExpr128 ir false ins insLen ctxt src
  !!ir (dstA := AST.fsub dstA srcA)
  !!ir (dstB := AST.fadd dstB srcB)
  !>ir insLen

let addsubps ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
  let srcB, srcA = transOprToExpr128 ir false ins insLen ctxt src
  let struct (t1, t2, t3, t4) = tmpVars4 ir 32<rt>
  !!ir (t1 := AST.fsub (AST.xtlo 32<rt> dstA) (AST.xtlo 32<rt> srcA))
  !!ir (t2 := AST.fadd (AST.xthi 32<rt> dstA) (AST.xthi 32<rt> srcA))
  !!ir (t3 := AST.fsub (AST.xtlo 32<rt> dstB) (AST.xtlo 32<rt> srcB))
  !!ir (t4 := AST.fadd (AST.xthi 32<rt> dstB) (AST.xthi 32<rt> srcB))
  !!ir (dstA := AST.concat t2 t1)
  !!ir (dstB := AST.concat t4 t3)
  !>ir insLen

let buildMove ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / 64<rt>
  match oprSize with
  | 32<rt> | 64<rt> ->
    let struct (dst, src) = transTwoOprs ir false ins insLen ctxt
    !!ir (dst := src)
  | 128<rt> | 256<rt> | 512<rt> ->
    let struct (dst, src) = getTwoOprs ins
    let src = transOprToArr ir false ins insLen ctxt 64<rt> packNum oprSize src
    assignPackedInstr ir false ins insLen ctxt packNum oprSize dst src
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let movaps ins insLen ctxt = buildMove ins insLen ctxt

let movapd ins insLen ctxt = buildMove ins insLen ctxt

let movups ins insLen ctxt = buildMove ins insLen ctxt

let movupd ins insLen ctxt = buildMove ins insLen ctxt

let movhps ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  match dst, src with
  | OprMem (_, _, _, 64<rt>), OprReg r ->
    let dst = transOprToExpr ir false ins insLen ctxt dst
    !!ir (dst := getPseudoRegVar ctxt r 2)
  | OprReg r, OprMem (_, _, _, 64<rt>)->
    let src = transOprToExpr ir false ins insLen ctxt src
    !!ir (getPseudoRegVar ctxt r 2 := src)
  | _ -> raise InvalidOperandException
  !>ir insLen

let movhpd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  match dst, src with
  | OprReg r, OprMem _ ->
    let src = transOprToExpr ir false ins insLen ctxt src
    !!ir (getPseudoRegVar ctxt r 2 := src)
  | OprMem _, OprReg r ->
    let dst = transOprToExpr ir false ins insLen ctxt dst
    !!ir (dst := getPseudoRegVar ctxt r 1)
  | _ -> raise InvalidOperandException
  !>ir insLen

let movhlps ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr128 ir false ins insLen ctxt dst |> snd
  let src = transOprToExpr128 ir false ins insLen ctxt src |> fst
  !!ir (dst := src)
  !>ir insLen

let movlpd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  match dst, src with
  | OprReg r, OprMem _ ->
    let src = transOprToExpr ir false ins insLen ctxt src
    !!ir (getPseudoRegVar ctxt r 1 := src)
  | OprMem _, OprReg r ->
    let dst = transOprToExpr ir false ins insLen ctxt dst
    !!ir (dst := getPseudoRegVar ctxt r 1)
  | _ -> raise InvalidOperandException
  !>ir insLen

let movlps ins insLen ctxt = movlpd ins insLen ctxt

let movlhps ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr128 ir false ins insLen ctxt dst |> fst
  let src = transOprToExpr128 ir false ins insLen ctxt src |> snd
  !!ir (dst := src)
  !>ir insLen

let movmskps ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr ir false ins insLen ctxt dst
  let srcB, srcA= transOprToExpr128 ir false ins insLen ctxt src
  let oprSize = getOperationSize ins
  let srcA = AST.concat (AST.extract srcA 1<rt> 63) (AST.extract srcA 1<rt> 31)
  let srcB = AST.concat (AST.extract srcB 1<rt> 63) (AST.extract srcB 1<rt> 31)
  !!ir (dst := AST.zext oprSize <| AST.concat srcB srcA)
  !>ir insLen

let movmskpd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr ir false ins insLen ctxt dst
  let src1, src2 = transOprToExpr128 ir false ins insLen ctxt src
  let oprSize = getOperationSize ins
  let src63 = AST.zext oprSize (AST.xthi 1<rt> src2)
  let src127 = (AST.zext oprSize (AST.xthi 1<rt> src1)) << AST.num1 oprSize
  !!ir (dstAssign oprSize dst (src63 .| src127))
  !>ir insLen

let movss (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  match dst, src with
  | OprReg r1, OprReg r2 ->
    let dst = getPseudoRegVar ctxt r1 1 |> AST.xtlo 32<rt>
    let src = getPseudoRegVar ctxt r2 1 |> AST.xtlo 32<rt>
    !!ir (dst := src)
  | OprReg r1, OprMem _ ->
    let dst2, dst1 = getPseudoRegVar128 ctxt r1
    let src = transOprToExpr ir false ins insLen ctxt src
    !!ir (dstAssign 32<rt> dst1 src)
    !!ir (dst2 := AST.num0 64<rt>)
  | OprMem _ , OprReg r1 ->
    let dst = transOprToExpr ir false ins insLen ctxt dst
    let src = getPseudoRegVar ctxt r1 1 |> AST.xtlo 32<rt>
    !!ir (dstAssign 32<rt> dst src)
  | _ -> raise InvalidOperandException
  !>ir insLen

let movsd (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  if ins.Operands = NoOperand then
    GeneralLifter.movs ins insLen ctxt
  else
    !<ir insLen
    let struct (dst, src) = getTwoOprs ins
    match dst, src with
    | OprReg r1, OprReg r2 ->
      let dst = getPseudoRegVar ctxt r1 1
      let src = getPseudoRegVar ctxt r2 1
      !!ir (dst := src)
    | OprReg r1, OprMem _ ->
      let dst2, dst1 = getPseudoRegVar128 ctxt r1
      let src = transOprToExpr ir false ins insLen ctxt src
      !!ir (dst1 := src)
      !!ir (dst2 := AST.num0 64<rt>)
    | OprMem _ , OprReg r1 ->
      let dst = transOprToExpr ir false ins insLen ctxt dst
      let src = getPseudoRegVar ctxt r1 1
      !!ir (dstAssign 64<rt> dst src)
    | _ -> raise InvalidOperandException
    !>ir insLen

let addps ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 32<rt> (opP AST.fadd)

let addpd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 64<rt> (opP AST.fadd)

let private getFstOperand = function
  | OneOperand o -> o
  | TwoOperands (o, _) -> o
  | ThreeOperands (o, _, _) -> o
  | FourOperands (o, _, _, _) -> o
  | _ -> raise InvalidOperandException

let private getTwoSrcOperands = function
  | TwoOperands (op1, op2) -> (op1, op2)
  | ThreeOperands (_op1, op2, op3) -> (op2, op3)
  | _ -> raise InvalidOperandException

let private handleScalarFPOp (ins: InsInfo) insLen ctxt sz op =
  let ir = !*ctxt
  !<ir insLen
  let _dst2, dst1 =
    ins.Operands |> getFstOperand |> transOprToExpr128 ir false ins insLen ctxt
  let src1, src2 = getTwoSrcOperands ins.Operands
  let src1 = transOprToExpr64 ir false ins insLen ctxt src1
  let src2 =
    if sz = 32<rt> then transOprToExpr32 ir false ins insLen ctxt src2
    else transOprToExpr64 ir false ins insLen ctxt src2
  let dst1, src1 =
    if sz = 32<rt> then AST.xtlo 32<rt> dst1, AST.xtlo 32<rt> src1
    else dst1, src1
  let struct (t1, t2, t3) = tmpVars3 ir sz
  !!ir (t1 := src1)
  !!ir (t2 := src2)
  !!ir (t3 := op t1 t2)
  !!ir (dst1 := t3)
  !>ir insLen

let addss ins insLen ctxt =
  handleScalarFPOp ins insLen ctxt 32<rt> AST.fadd

let addsd ins insLen ctxt =
  handleScalarFPOp ins insLen ctxt 64<rt> AST.fadd

let subps ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 32<rt> (opP AST.fsub)

let subpd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 64<rt> (opP AST.fsub)

let subss ins insLen ctxt =
  handleScalarFPOp ins insLen ctxt 32<rt> AST.fsub

let subsd ins insLen ctxt =
  handleScalarFPOp ins insLen ctxt 64<rt> AST.fsub

let mulps ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 32<rt> (opP AST.fmul)

let mulpd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 64<rt> (opP AST.fmul)

let mulss ins insLen ctxt =
  handleScalarFPOp ins insLen ctxt 32<rt> AST.fmul

let mulsd ins insLen ctxt =
  handleScalarFPOp ins insLen ctxt 64<rt> AST.fmul

let divps ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 32<rt> (opP AST.fdiv)

let divpd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 64<rt> (opP AST.fdiv)

let divss ins insLen ctxt =
  handleScalarFPOp ins insLen ctxt 32<rt> AST.fdiv

let divsd ins insLen ctxt =
  handleScalarFPOp ins insLen ctxt 64<rt> AST.fdiv

let rcpps ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (opr1, opr2) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ir false ins insLen ctxt opr1
  let src2, src1 = transOprToExpr128 ir false ins insLen ctxt opr2
  let dst1b, dst1a = AST.xthi 32<rt> dst1, AST.xtlo 32<rt> dst1
  let dst2b, dst2a = AST.xthi 32<rt> dst2, AST.xtlo 32<rt> dst2
  let src1b, src1a = AST.xthi 32<rt> src1, AST.xtlo 32<rt> src1
  let src2b, src2a = AST.xthi 32<rt> src2, AST.xtlo 32<rt> src2
  let tmp = !+ir 32<rt>
  let flt1 = numI32 0x3f800000 32<rt>
  !!ir (dst1a := AST.fdiv flt1 src1a)
  !!ir (dst1b := AST.fdiv flt1 src1b)
  !!ir (dst2a := AST.fdiv flt1 src2a)
  !!ir (dst2b := AST.fdiv flt1 src2b)
  !>ir insLen

let rcpss ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (opr1, opr2) = getTwoOprs ins
  let dst = transOprToExpr32 ir false ins insLen ctxt opr1
  let src = transOprToExpr32 ir false ins insLen ctxt opr2
  let tmp = !+ir 32<rt>
  let flt1 = numI32 0x3f800000 32<rt>
  !!ir (dst := AST.fdiv flt1 src)
  !>ir insLen

let sqrtps ins insLen ctxt =
  let ir = !*ctxt
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / 32<rt>
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let src = transOprToArr ir false ins insLen ctxt 32<rt> packNum oprSize src
  let result = Array.map (AST.unop UnOpType.FSQRT) src
  assignPackedInstr ir false ins insLen ctxt packNum oprSize dst result
  !>ir insLen

let sqrtpd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (opr1, opr2) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ir false ins insLen ctxt opr1
  let src2, src1 = transOprToExpr128 ir false ins insLen ctxt opr2
  !!ir (dst1 := AST.unop UnOpType.FSQRT src1)
  !!ir (dst2 := AST.unop UnOpType.FSQRT src2)
  !>ir insLen

let sqrtss ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (opr1, opr2) = getTwoOprs ins
  let dst = transOprToExpr32 ir false ins insLen ctxt opr1
  let src = transOprToExpr32 ir false ins insLen ctxt opr2
  !!ir (dst := AST.unop UnOpType.FSQRT src)
  !>ir insLen

let sqrtsd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (opr1, opr2) = getTwoOprs ins
  let dst = transOprToExpr64 ir false ins insLen ctxt opr1
  let src = transOprToExpr64 ir false ins insLen ctxt opr2
  !!ir (dst := AST.unop UnOpType.FSQRT src)
  !>ir insLen

let rsqrtps ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (opr1, opr2) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ir false ins insLen ctxt opr1
  let src2, src1 = transOprToExpr128 ir false ins insLen ctxt opr2
  let dst1b, dst1a = AST.xthi 32<rt> dst1, AST.xtlo 32<rt> dst1
  let dst2b, dst2a = AST.xthi 32<rt> dst2, AST.xtlo 32<rt> dst2
  let src1b, src1a = AST.xthi 32<rt> src1, AST.xtlo 32<rt> src1
  let src2b, src2a = AST.xthi 32<rt> src2, AST.xtlo 32<rt> src2
  let tmp = !+ir 32<rt>
  let flt1 = numI32 0x3f800000 32<rt>
  !!ir (tmp := AST.unop UnOpType.FSQRT src1a)
  !!ir (dst1a := AST.fdiv flt1 tmp)
  !!ir (tmp := AST.unop UnOpType.FSQRT src1b)
  !!ir (dst1b := AST.fdiv flt1 tmp)
  !!ir (tmp := AST.unop UnOpType.FSQRT src2a)
  !!ir (dst2a := AST.fdiv flt1 tmp)
  !!ir (tmp := AST.unop UnOpType.FSQRT src2b)
  !!ir (dst2b := AST.fdiv flt1 tmp)
  !>ir insLen

let rsqrtss ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (opr1, opr2) = getTwoOprs ins
  let dst = transOprToExpr32 ir false ins insLen ctxt opr1
  let src = transOprToExpr32 ir false ins insLen ctxt opr2
  let tmp = !+ir 32<rt>
  let flt1 = numI32 0x3f800000 32<rt>
  !!ir (tmp := AST.unop UnOpType.FSQRT src)
  !!ir (dst := AST.fdiv flt1 tmp)
  !>ir insLen

let private minMaxPS ins insLen ctxt compare =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ir false ins insLen ctxt dst
  let src2, src1 = transOprToExpr128 ir false ins insLen ctxt src
  let dst1A, dst1B = AST.xtlo 32<rt> dst1, AST.xthi 32<rt> dst1
  let dst2A, dst2B = AST.xtlo 32<rt> dst2, AST.xthi 32<rt> dst2
  let src1A, src1B = AST.xtlo 32<rt> src1, AST.xthi 32<rt> src1
  let src2A, src2B = AST.xtlo 32<rt> src2, AST.xthi 32<rt> src2
  let struct (val4, val3, val2, val1) = tmpVars4 ir 32<rt>
  !!ir (val1 := AST.ite (compare dst1A src1A) dst1A src1A)
  !!ir (val2 := AST.ite (compare dst1B src1B) dst1B src1B)
  !!ir (val3 := AST.ite (compare dst2A src2A) dst2A src2A)
  !!ir (val4 := AST.ite (compare dst2B src2B) dst2B src2B)
  !!ir (dst1A := val1)
  !!ir (dst1B := val2)
  !!ir (dst2A := val3)
  !!ir (dst2B := val4)
  !>ir insLen

let private minMaxPD ins insLen ctxt compare =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ir false ins insLen ctxt dst
  let src2, src1 = transOprToExpr128 ir false ins insLen ctxt src
  let struct (val2, val1) = tmpVars2 ir 64<rt>
  !!ir (val1 := AST.ite (compare dst1 src1) dst1 src1)
  !!ir (val2 := AST.ite (compare dst2 src2) dst2 src2)
  !!ir (dst1 := val1)
  !!ir (dst2 := val2)
  !>ir insLen

let private minMaxSS ins insLen ctxt compare =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr32 ir false ins insLen ctxt dst
  let src = transOprToExpr32 ir false ins insLen ctxt src
  let tmp = !+ir 32<rt>
  !!ir (tmp := AST.ite (compare dst src) dst src)
  !!ir (dst := tmp)
  !>ir insLen

let private minMaxSD ins insLen ctxt compare =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr64 ir false ins insLen ctxt dst
  let src = transOprToExpr64 ir false ins insLen ctxt src
  let tmp = !+ir 64<rt>
  !!ir (tmp := AST.ite (compare dst src) dst src)
  !!ir (dst := tmp)
  !>ir insLen

let maxps ins insLen ctxt =
  minMaxPS ins insLen ctxt AST.fgt

let maxpd ins insLen ctxt =
  minMaxPD ins insLen ctxt AST.fgt

let maxss ins insLen ctxt =
  minMaxSS ins insLen ctxt AST.fgt

let maxsd ins insLen ctxt =
  minMaxSD ins insLen ctxt AST.fgt

let minps ins insLen ctxt =
  minMaxPS ins insLen ctxt AST.flt

let minpd ins insLen ctxt =
  minMaxPD ins insLen ctxt AST.flt

let minss ins insLen ctxt =
  minMaxSS ins insLen ctxt AST.flt

let minsd ins insLen ctxt =
  minMaxSD ins insLen ctxt AST.flt

let private cmppCond ir ins insLen ctxt op3 isDbl c expr1 expr2 =
  let imm =
    transOprToExpr ir false ins insLen ctxt op3 |> AST.xtlo 8<rt>
    .& numI32 0x7 8<rt>
  match imm.E with
  | Num bv ->
    match bv.SmallValue () with
    | 0UL -> !!ir (c := expr1 == expr2)
    | 1UL -> !!ir (c := AST.flt expr1 expr2)
    | 2UL -> !!ir (c := AST.fle expr1 expr2)
    | 3UL -> !!ir (c := isNan isDbl expr1 .| isNan isDbl expr2)
    | 4UL -> !!ir (c := expr1 != expr2)
    | 5UL -> !!ir (c := AST.flt expr1 expr2 |> AST.not)
    | 6UL -> !!ir (c := AST.fle expr1 expr2 |> AST.not)
    | 7UL -> !!ir (c := (isNan isDbl expr1 .| isNan isDbl expr2) |> AST.not)
    | _ -> !!ir (c := AST.b0)
  | _ -> Utils.impossible ()

let cmpps ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (op1, op2, op3) = getThreeOprs ins
  let dst1, dst2 = transOprToExpr128 ir false ins insLen ctxt op1
  let src1, src2 = transOprToExpr128 ir false ins insLen ctxt op2
  let dst1A, dst1B = AST.xtlo 32<rt> dst1, AST.xthi 32<rt> dst1
  let dst2A, dst2B = AST.xtlo 32<rt> dst2, AST.xthi 32<rt> dst2
  let struct (cond1, cond2, cond3, cond4) = tmpVars4 ir 1<rt>
  cmppCond ir ins insLen ctxt op3 false cond1 dst1A (AST.xtlo 32<rt> src1)
  cmppCond ir ins insLen ctxt op3 false cond2 dst1B (AST.xthi 32<rt> src1)
  cmppCond ir ins insLen ctxt op3 false cond3 dst2A (AST.xtlo 32<rt> src2)
  cmppCond ir ins insLen ctxt op3 false cond4 dst2B (AST.xthi 32<rt> src2)
  !!ir (dst1A := AST.ite cond1 (maxNum 32<rt>) (AST.num0 32<rt>))
  !!ir (dst1B := AST.ite cond2 (maxNum 32<rt>) (AST.num0 32<rt>))
  !!ir (dst2A := AST.ite cond3 (maxNum 32<rt>) (AST.num0 32<rt>))
  !!ir (dst2B := AST.ite cond4 (maxNum 32<rt>) (AST.num0 32<rt>))
  !>ir insLen

let cmppd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (op1, op2, op3) = getThreeOprs ins
  let dst1, dst2 = transOprToExpr128 ir false ins insLen ctxt op1
  let src1, src2 = transOprToExpr128 ir false ins insLen ctxt op2
  let struct (cond1, cond2) = tmpVars2 ir 1<rt>
  cmppCond ir ins insLen ctxt op3 true cond1 dst1 src1
  cmppCond ir ins insLen ctxt op3 true cond2 dst2 src2
  !!ir (dst1 := AST.ite cond1 (maxNum 64<rt>) (AST.num0 64<rt>))
  !!ir (dst2 := AST.ite cond2 (maxNum 64<rt>) (AST.num0 64<rt>))
  !>ir insLen

let cmpss ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src, imm) = getThreeOprs ins
  let dst = transOprToExpr32 ir false ins insLen ctxt dst
  let src = transOprToExpr32 ir false ins insLen ctxt src
  let max32 = maxNum 32<rt>
  let cond = !+ir 1<rt>
  cmppCond ir ins insLen ctxt imm false cond dst src
  !!ir (dst := AST.ite cond max32 (AST.num0 32<rt>))
  !>ir insLen

let cmpsd (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | NoOperand -> GeneralLifter.cmps ins insLen ctxt
  | ThreeOperands (dst, src, imm) ->
    let ir = !*ctxt
    !<ir insLen
    let dst = transOprToExpr64 ir false ins insLen ctxt dst
    let src = transOprToExpr64 ir false ins insLen ctxt src
    let max64 = maxNum 64<rt>
    let cond = !+ir 1<rt>
    cmppCond ir ins insLen ctxt imm true cond dst src
    !!ir (dst := AST.ite cond max64 (AST.num0 64<rt>))
    !>ir insLen
  | _ -> raise InvalidOperandException

let comiss ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (opr1, opr2) = getTwoOprs ins
  let opr1 = transOprToExpr32 ir false ins insLen ctxt opr1
  let opr2 = transOprToExpr32 ir false ins insLen ctxt opr2
  let lblNan = !%ir "IsNan"
  let lblExit = !%ir "Exit"
  let zf = !.ctxt R.ZF
  let pf = !.ctxt R.PF
  let cf = !.ctxt R.CF
  !!ir (zf := AST.ite (opr1 == opr2) AST.b1 AST.b0)
  !!ir (pf := AST.b0)
  !!ir (cf := AST.ite (AST.flt opr1 opr2) AST.b1 AST.b0)
  !!ir (AST.cjmp (isNan false opr1 .| isNan false opr2)
                 (AST.name lblNan) (AST.name lblExit))
  !!ir (AST.lmark lblNan)
  !!ir (zf := AST.b1)
  !!ir (pf := AST.b1)
  !!ir (cf := AST.b1)
  !!ir (AST.lmark lblExit)
  !!ir (!.ctxt R.OF := AST.b0)
  !!ir (!.ctxt R.AF := AST.b0)
  !!ir (!.ctxt R.SF := AST.b0)
#if EMULATION
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let comisd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (opr1, opr2) = getTwoOprs ins
  let opr1 = transOprToExpr64 ir false ins insLen ctxt opr1
  let opr2 = transOprToExpr64 ir false ins insLen ctxt opr2
  let lblNan = !%ir "IsNan"
  let lblExit = !%ir "Exit"
  let zf = !.ctxt R.ZF
  let pf = !.ctxt R.PF
  let cf = !.ctxt R.CF
  !!ir (zf := AST.ite (opr1 == opr2) AST.b1 AST.b0)
  !!ir (pf := AST.b0)
  !!ir (cf := AST.ite (AST.flt opr1 opr2) AST.b1 AST.b0)
  !!ir (AST.cjmp (isNan true opr1 .| isNan true opr2)
                 (AST.name lblNan) (AST.name lblExit))
  !!ir (AST.lmark lblNan)
  !!ir (zf := AST.b1)
  !!ir (pf := AST.b1)
  !!ir (cf := AST.b1)
  !!ir (AST.lmark lblExit)
  !!ir (!.ctxt R.OF := AST.b0)
  !!ir (!.ctxt R.AF := AST.b0)
  !!ir (!.ctxt R.SF := AST.b0)
#if EMULATION
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let ucomiss ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (opr1, opr2) = getTwoOprs ins
  let opr1 = transOprToExpr32 ir false ins insLen ctxt opr1
  let opr2 = transOprToExpr32 ir false ins insLen ctxt opr2
  let lblNan = !%ir "IsNan"
  let lblExit = !%ir "Exit"
  let zf = !.ctxt R.ZF
  let pf = !.ctxt R.PF
  let cf = !.ctxt R.CF
  !!ir (zf := AST.ite (opr1 == opr2) AST.b1 AST.b0)
  !!ir (pf := AST.b0)
  !!ir (cf := AST.ite (AST.flt opr1 opr2) AST.b1 AST.b0)
  !!ir (AST.cjmp (isNan false opr1 .| isNan false opr2)
                 (AST.name lblNan) (AST.name lblExit))
  !!ir (AST.lmark lblNan)
  !!ir (zf := AST.b1)
  !!ir (pf := AST.b1)
  !!ir (cf := AST.b1)
  !!ir (AST.lmark lblExit)
  !!ir (!.ctxt R.OF := AST.b0)
  !!ir (!.ctxt R.AF := AST.b0)
  !!ir (!.ctxt R.SF := AST.b0)
#if EMULATION
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let ucomisd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (opr1, opr2) = getTwoOprs ins
  let opr1 = transOprToExpr64 ir false ins insLen ctxt opr1
  let opr2 = transOprToExpr64 ir false ins insLen ctxt opr2
  let lblNan = !%ir "IsNan"
  let lblExit = !%ir "Exit"
  let zf = !.ctxt R.ZF
  let pf = !.ctxt R.PF
  let cf = !.ctxt R.CF
  !!ir (zf := AST.ite (opr1 == opr2) AST.b1 AST.b0)
  !!ir (pf := AST.b0)
  !!ir (cf := AST.ite (AST.flt opr1 opr2) AST.b1 AST.b0)
  !!ir (AST.cjmp (isNan true opr1 .| isNan true opr2)
                 (AST.name lblNan) (AST.name lblExit))
  !!ir (AST.lmark lblNan)
  !!ir (zf := AST.b1)
  !!ir (pf := AST.b1)
  !!ir (cf := AST.b1)
  !!ir (AST.lmark lblExit)
  !!ir (!.ctxt R.OF := AST.b0)
  !!ir (!.ctxt R.AF := AST.b0)
  !!ir (!.ctxt R.SF := AST.b0)
#if EMULATION
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let andps ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 32<rt> opPand

let andpd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 64<rt> opPand

let andnps ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 32<rt> opPandn

let andnpd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 64<rt> opPandn

let orps ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 32<rt> opPor

let orpd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 64<rt> opPor

let private opPxor _ = Array.map2 (<+>)

let xorps ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 32<rt> opPxor

let xorpd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 64<rt> opPxor

let shufps ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src, imm) = getThreeOprs ins
  let dst2, dst1 = transOprToExpr128 ir false ins insLen ctxt dst
  let src2, src1 = transOprToExpr128 ir false ins insLen ctxt src
  let imm = transOprToExpr ir false ins insLen ctxt imm
  let dst1A, dst1B = AST.xtlo 32<rt> dst1, AST.xthi 32<rt> dst1
  let dst2A, dst2B = AST.xtlo 32<rt> dst2, AST.xthi 32<rt> dst2
  let src1A, src1B = AST.xtlo 32<rt> src1, AST.xthi 32<rt> src1
  let src2A, src2B = AST.xtlo 32<rt> src2, AST.xthi 32<rt> src2
  let doShuf cond dst e0 e1 e2 e3 =
    !!ir (dst := AST.num0 32<rt>)
    !!ir (dst := AST.ite (cond == AST.num0 8<rt>) e0 dst)
    !!ir (dst := AST.ite (cond == AST.num1 8<rt>) e1 dst)
    !!ir (dst := AST.ite (cond == numI32 2 8<rt>) e2 dst)
    !!ir (dst := AST.ite (cond == numI32 3 8<rt>) e3 dst)
  let cond shfAmt =
    ((AST.xtlo 8<rt> imm) >> (numI32 shfAmt 8<rt>)) .& (numI32 0b11 8<rt>)
  let struct (tmp1, tmp2, tmp3, tmp4) = tmpVars4 ir 32<rt>
  doShuf (cond 0) tmp1 dst1A dst1B dst2A dst2B
  doShuf (cond 2) tmp2 dst1A dst1B dst2A dst2B
  doShuf (cond 4) tmp3 src1A src1B src2A src2B
  doShuf (cond 6) tmp4 src1A src1B src2A src2B
  !!ir (dst1A := tmp1)
  !!ir (dst1B := tmp2)
  !!ir (dst2A := tmp3)
  !!ir (dst2B := tmp4)
  !>ir insLen

let shufpd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src, imm) = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
  let srcB, srcA = transOprToExpr128 ir false ins insLen ctxt src
  let imm = transOprToExpr ir false ins insLen ctxt imm
  let cond1 = AST.xtlo 1<rt> imm
  let cond2 = AST.extract imm 1<rt> 1
  let struct (src1A, src1B, src2A, src2B) = tmpVars4 ir 64<rt>
  !!ir (src1A := dstA)
  !!ir (src1B := dstB)
  !!ir (src2A := srcA)
  !!ir (src2B := srcB)
  !!ir (dstA := AST.ite cond1 src1B src1A)
  !!ir (dstB := AST.ite cond2 src2B src2A)
  !>ir insLen

let unpckhps ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ir false ins insLen ctxt dst
  let src2, _src1 = transOprToExpr128 ir false ins insLen ctxt src
  let dst1A, dst1B = AST.xtlo 32<rt> dst1, AST.xthi 32<rt> dst1
  let dst2A, dst2B = AST.xtlo 32<rt> dst2, AST.xthi 32<rt> dst2
  let src2A, src2B = AST.xtlo 32<rt> src2, AST.xthi 32<rt> src2
  !!ir (dst1A := dst2A)
  !!ir (dst1B := src2A)
  !!ir (dst2A := dst2B)
  !!ir (dst2B := src2B)
  !>ir insLen

let unpckhpd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ir false ins insLen ctxt dst
  let src2, _src1 = transOprToExpr128 ir false ins insLen ctxt src
  !!ir (dst1 := dst2)
  !!ir (dst2 := src2)
  !>ir insLen

let unpcklps ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
  let _, srcA = transOprToExpr128 ir false ins insLen ctxt src
  let struct (tSrc1A, tSrc1B, tSrc2A) = tmpVars3 ir 64<rt>
  !!ir (tSrc1A := dstA)
  !!ir (tSrc1B := dstB)
  !!ir (tSrc2A := srcA)
  !!ir (dstA := AST.concat (AST.xtlo 32<rt> tSrc2A) (AST.xtlo 32<rt> tSrc1A))
  !!ir (dstB := AST.concat (AST.xthi 32<rt> tSrc2A) (AST.xthi 32<rt> tSrc1A))
  !>ir insLen

let unpcklpd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ir false ins insLen ctxt dst
  let _src2, src1 = transOprToExpr128 ir false ins insLen ctxt src
  !!ir (dst2 := src1)
  !>ir insLen

let cvtpi2ps ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr64 ir false ins insLen ctxt dst
  let src = transOprToExpr64 ir false ins insLen ctxt src
  let struct (tmp2, tmp1) = tmpVars2 ir 32<rt>
  !!ir (tmp1 := AST.xtlo 32<rt> src)
  !!ir (tmp2 := AST.xthi 32<rt> src)
  !!ir (AST.xtlo 32<rt> dst := AST.cast CastKind.SIntToFloat 32<rt> tmp1)
  !!ir (AST.xthi 32<rt> dst := AST.cast CastKind.SIntToFloat 32<rt> tmp2)
  !>ir insLen

let cvtdq2pd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ir false ins insLen ctxt dst
  let src = transOprToExpr64 ir false ins insLen ctxt src
  let struct (tmp1, tmp2) = tmpVars2 ir 32<rt>
  !!ir (tmp1 := AST.xtlo 32<rt> src)
  !!ir (tmp2 := AST.xthi 32<rt> src)
  !!ir (dst1 := AST.cast CastKind.SIntToFloat 64<rt> tmp1)
  !!ir (dst2 := AST.cast CastKind.SIntToFloat 64<rt> tmp2)
  !>ir insLen

let cvtpi2pd ins insLen ctxt = cvtdq2pd ins insLen ctxt

let cvtsi2ss ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr64 ir false ins insLen ctxt dst
  let src = transOprToExpr ir false ins insLen ctxt src
  !!ir (AST.xtlo 32<rt> dst := AST.cast CastKind.SIntToFloat 32<rt> src)
  !>ir insLen

let cvtsi2sd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr64 ir false ins insLen ctxt dst
  let src = transOprToExpr ir false ins insLen ctxt src
  !!ir (dst := AST.cast CastKind.SIntToFloat 64<rt> src)
  !>ir insLen

let cvtps2pi ins insLen ctxt rounded =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr ir false ins insLen ctxt dst
  let src = transOprToExpr64 ir false ins insLen ctxt src
  let struct (tmp1, tmp2) = tmpVars2 ir 32<rt>
  let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
  !!ir (tmp1 := AST.xtlo 32<rt> src)
  !!ir (tmp2 := AST.xthi 32<rt> src)
  !!ir (AST.xtlo 32<rt> dst := AST.cast castKind 32<rt> tmp1)
  !!ir (AST.xthi 32<rt> dst := AST.cast castKind 32<rt> tmp2)
  !>ir insLen

let cvtps2pd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ir false ins insLen ctxt dst
  let src = transOprToExpr64 ir false ins insLen ctxt src
  let struct (tmp1, tmp2) = tmpVars2 ir 32<rt>
  !!ir (tmp1 := AST.xtlo 32<rt> src)
  !!ir (tmp2 := AST.xthi 32<rt> src)
  !!ir (dst1 := AST.cast CastKind.FloatCast 64<rt> tmp1)
  !!ir (dst2 := AST.cast CastKind.FloatCast 64<rt> tmp2)
  !>ir insLen

let cvtpd2ps ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ir false ins insLen ctxt dst
  let src2, src1 = transOprToExpr128 ir false ins insLen ctxt src
  !!ir (AST.xtlo 32<rt> dst1 := AST.cast CastKind.FloatCast 32<rt> src1)
  !!ir (AST.xthi 32<rt> dst1 := AST.cast CastKind.FloatCast 32<rt> src2)
  !!ir (dst2 := AST.num0 64<rt>)
  !>ir insLen

let cvtpd2pi ins insLen ctxt rounded =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr ir false ins insLen ctxt dst
  let src2, src1 = transOprToExpr128 ir false ins insLen ctxt src
  let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
  !!ir (AST.xtlo 32<rt> dst := AST.cast castKind 32<rt> src1)
  !!ir (AST.xthi 32<rt> dst := AST.cast castKind 32<rt> src2)
  !>ir insLen

let cvtpd2dq ins insLen ctxt rounded =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ir false ins insLen ctxt dst
  let src2, src1 = transOprToExpr128 ir false ins insLen ctxt src
  let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
  !!ir (AST.xtlo 32<rt> dst1 := AST.cast castKind 32<rt> src1)
  !!ir (AST.xthi 32<rt> dst1 := AST.cast castKind 32<rt> src2)
  !!ir (dst2 := AST.num0 64<rt>)
  !>ir insLen

let cvtdq2ps ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ir false ins insLen ctxt dst
  let src2, src1 = transOprToExpr128 ir false ins insLen ctxt src
  let struct (tmp1, tmp2, tmp3, tmp4) = tmpVars4 ir 32<rt>
  !!ir (tmp1 := AST.xtlo 32<rt> src1)
  !!ir (tmp2 := AST.xthi 32<rt> src1)
  !!ir (tmp3 := AST.xtlo 32<rt> src2)
  !!ir (tmp4 := AST.xthi 32<rt> src2)
  !!ir (AST.xtlo 32<rt> dst1 := AST.cast CastKind.SIntToFloat 32<rt> tmp1)
  !!ir (AST.xthi 32<rt> dst1 := AST.cast CastKind.SIntToFloat 32<rt> tmp2)
  !!ir (AST.xtlo 32<rt> dst2 := AST.cast CastKind.SIntToFloat 32<rt> tmp3)
  !!ir (AST.xthi 32<rt> dst2 := AST.cast CastKind.SIntToFloat 32<rt> tmp4)
  !>ir insLen

let cvtps2dq ins insLen ctxt rounded =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ir false ins insLen ctxt dst
  let src2, src1 = transOprToExpr128 ir false ins insLen ctxt src
  let struct (tmp1, tmp2, tmp3, tmp4) = tmpVars4 ir 32<rt>
  let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
  !!ir (tmp1 := AST.xtlo 32<rt> src1)
  !!ir (tmp2 := AST.xthi 32<rt> src1)
  !!ir (tmp3 := AST.xtlo 32<rt> src2)
  !!ir (tmp4 := AST.xthi 32<rt> src2)
  !!ir (AST.xtlo 32<rt> dst1 := AST.cast castKind 32<rt> tmp1)
  !!ir (AST.xthi 32<rt> dst1 := AST.cast castKind 32<rt> tmp2)
  !!ir (AST.xtlo 32<rt> dst2 := AST.cast castKind 32<rt> tmp3)
  !!ir (AST.xthi 32<rt> dst2 := AST.cast castKind 32<rt> tmp4)
  !>ir insLen

let cvtss2si ins insLen ctxt rounded =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr ir false ins insLen ctxt dst
  let src = transOprToExpr32 ir false ins insLen ctxt src
  let tmp = !+ir 32<rt>
  let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
  if is64bit ctxt && oprSize = 64<rt> then
    !!ir (dst := AST.cast castKind 64<rt> src)
  else
    !!ir (tmp := AST.cast castKind 32<rt> src)
    !!ir (dstAssign 32<rt> dst tmp)
  !>ir insLen

let cvtss2sd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr64 ir false ins insLen ctxt dst
  let src = transOprToExpr32 ir false ins insLen ctxt src
  !!ir (dst := AST.cast CastKind.FloatCast 64<rt> src)
  !>ir insLen

let cvtsd2ss ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr64 ir false ins insLen ctxt dst
  let src = transOprToExpr64 ir false ins insLen ctxt src
  !!ir (AST.xtlo 32<rt> dst := AST.cast CastKind.FloatCast 32<rt> src)
  !>ir insLen

let cvtsd2si ins insLen ctxt rounded =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr ir false ins insLen ctxt dst
  let src = transOprToExpr64 ir false ins insLen ctxt src
  let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
  let tmp = !+ir 32<rt>
  if is64bit ctxt && oprSize = 64<rt> then
    !!ir (dst := AST.cast castKind 64<rt> src)
  else
    !!ir (tmp := AST.cast castKind 32<rt> src)
    !!ir (dstAssign 32<rt> dst tmp)
  !>ir insLen

let extractps ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src, count) = getThreeOprs ins
  let dst = transOprToExpr ir false ins insLen ctxt dst
  let count = getImmValue count
  let oprSize = getOperationSize ins
  let srtOff = (count &&& 0b11) (* COUNT[1:0] *) * 32L
  match src with
  | OprReg reg ->
    let srcB, srcA = getPseudoRegVar128 ctxt reg
    let lAmt = numI64 (64L - (count % 64L)) 64<rt> (* Left Shift *)
    let rAmt = numI64 (count % 64L) 64<rt> (* Right Shift *)
    let result =
      if count < 64 then
        ((srcB << lAmt) .| (srcA >> rAmt)) .& numU32 0xFFFFFFFFu 64<rt>
      else (srcB >> rAmt) .& numU32 0xFFFFFFFFu 64<rt>
    !!ir (dstAssign oprSize dst (AST.xtlo oprSize result))
  | _ -> raise InvalidOperandException
  !>ir insLen

let hsubpd ins insLen ctxt =
  packedHorizon ins insLen ctxt 64<rt> (opP AST.fsub)

let hsubps ins insLen ctxt =
  packedHorizon ins insLen ctxt 32<rt> (opP AST.fsub)

let haddpd ins insLen ctxt =
  packedHorizon ins insLen ctxt 64<rt> (opP AST.fadd)

let haddps ins insLen ctxt =
  packedHorizon ins insLen ctxt 32<rt> (opP AST.fadd)

let ldmxcsr ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let src = transOneOpr ir ins insLen ctxt
  !!ir (!.ctxt R.MXCSR := src)
  !>ir insLen

let stmxcsr ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let dst = transOneOpr ir ins insLen ctxt
  !!ir (dst := !.ctxt R.MXCSR)
  !>ir insLen

let private opAveragePackedInt (packSz: int<rt>) =
  let dblSz = packSz * 2
  let dblExt expr = AST.zext dblSz expr
  let avg e1 e2 =
    AST.extract (dblExt e1 .+ dblExt e2 .+ AST.num1 dblSz) packSz 1
  Array.map2 avg

let opPavgb _ = opAveragePackedInt 8<rt>

let pavgb ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 8<rt> opPavgb

let opPavgw _ = opAveragePackedInt 16<rt>

let pavgw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 16<rt> opPavgw

let pextrb ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src, count) = getThreeOprs ins
  let count = getImmValue count
  let dExpr = transOprToExpr ir false ins insLen ctxt dst
  let srcB, srcA = transOprToExpr128 ir false ins insLen ctxt src
  let count = (count &&& 0b1111) (* COUNT[3:0] *) * 8L
  let lAmt = numI64 (64L - (count % 64L)) 64<rt> (* Left Shift *)
  let rAmt = numI64 (count % 64L) 64<rt> (* Right Shift *)
  let result =
    if count < 64 then ((srcB << lAmt) .| (srcA >> rAmt)) .& numU32 0xFFu 64<rt>
    else (srcB >> rAmt) .& numU32 0xFFu 64<rt>
    |> AST.xtlo 8<rt>
  match dst with
  | OprReg _ -> !!ir (dstAssign 32<rt> dExpr (AST.zext 32<rt> result))
  | OprMem _ -> !!ir (dExpr := result)
  | _ -> raise InvalidOperandException
  !>ir insLen

let pextrd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src, count) = getThreeOprs ins
  let dst = transOprToExpr ir false ins insLen ctxt dst
  let count = getImmValue count
  let oprSize = getOperationSize ins
  match src with
  | OprReg reg ->
    let srcB, srcA = getPseudoRegVar128 ctxt reg
    let count = (count &&& 0b11) (* COUNT[1:0] *) * 32L
    let lAmt = numI64 (64L - (count % 64L)) 64<rt> (* Left Shift *)
    let rAmt = numI64 (count % 64L) 64<rt> (* Right Shift *)
    let result =
      if count < 64 then
        ((srcB << lAmt) .| (srcA >> rAmt)) .& numU32 0xFFFFFFFFu 64<rt>
      else (srcB >> rAmt) .& numU32 0xFFFFFFFFu 64<rt>
    !!ir (dstAssign oprSize dst (AST.xtlo oprSize result))
  | _ -> raise InvalidOperandException
  !>ir insLen

let pextrq ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src, count) = getThreeOprs ins
  let dst = transOprToExpr ir false ins insLen ctxt dst
  let count = getImmValue count
  let oprSize = getOperationSize ins
  match src with
  | OprReg reg ->
    let srcB, srcA = getPseudoRegVar128 ctxt reg
    let count = (count &&& 0b1) (* COUNT[0] *) * 64L
    let lAmt = numI64 (64L - (count % 64L)) 64<rt> (* Left Shift *)
    let rAmt = numI64 (count % 64L) 64<rt> (* Right Shift *)
    let result =
      if count < 64 then
        ((srcB << lAmt) .| (srcA >> rAmt))
      else (srcB >> rAmt)
    !!ir (dstAssign oprSize dst (AST.xtlo oprSize result))
  | _ -> raise InvalidOperandException
  !>ir insLen

let pextrw ins insLen ctxt =
  let ir = !*ctxt
  let oprSize = getOperationSize ins
  !<ir insLen
  let struct (dst, src, imm8) = getThreeOprs ins
  let packNum = 64<rt> / 16<rt>
  let srcSz =
    match src with
    | OprReg reg -> Register.toRegType reg
    | _ -> raise InvalidOperandException
  let d = transOprToExpr ir false ins insLen ctxt dst
  let src = transOprToArr ir false ins insLen ctxt 16<rt> packNum srcSz src
  let idx = getImmValue imm8 |> int
  match dst with
  | OprMem (_, _, _, 16<rt>) ->
    let idx = idx &&& 0b111
    !!ir (d := src[idx])
  | _ ->
    let idx = idx &&& (Array.length src - 1)
    !!ir (dstAssign oprSize d src[idx])
  !>ir insLen

let pinsrw ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src, count) = getThreeOprs ins
  let src = transOprToExpr ir false ins insLen ctxt src
  let sel = !+ir 64<rt>
  match dst with
  | OprReg reg ->
    match Register.getKind reg with
    | Register.Kind.MMX ->
      let dst = transOprToExpr ir false ins insLen ctxt dst
      let count = getImmValue count
      let mask = !+ir 64<rt>
      !!ir (sel := numI64 (count &&& 0b11) 64<rt>)
      let pos = sel .* numU64 0x10UL 64<rt>
      !!ir (mask := (numU64 0xffffUL 64<rt>) << pos)
      !!ir
        (dst := (dst .& (AST.not mask)) .| (AST.zext 64<rt> src << pos .& mask))
    | Register.Kind.XMM ->
      let dst1, dst2 = transOprToExpr128 ir false ins insLen ctxt dst
      let mask = !+ir 64<rt>
      let count = getImmValue count &&& 0b111
      !!ir (sel := numI64 count 64<rt>)
      if count > 3L then
        let pos = (sel .- numI32 4 64<rt>) .* numI32 16 64<rt>
        !!ir (mask := (numU64 0xffffUL 64<rt>) << pos)
        !!ir (dst1 := (dst1 .& (AST.not mask))
                            .| (AST.zext 64<rt> src << pos .& mask))
      else
        let pos = sel .* numI32 16 64<rt>
        !!ir (mask := (numU64 0xffffUL 64<rt>) << pos)
        !!ir (dst2 := (dst2 .& (AST.not mask))
                            .| (AST.zext 64<rt> src << pos .& mask))
    | _ -> raise InvalidOperandSizeException
  | _ -> raise InvalidOperandException
  !>ir insLen

let private opMaxMinPacked cmp =
  Array.map2 (fun e1 e2 -> AST.ite (cmp e1 e2) e1 e2)

let opPmaxu _ = opMaxMinPacked AST.gt

let opPminu _ = opMaxMinPacked AST.lt

let opPmaxs _ = opMaxMinPacked AST.sgt

let opPmins _ = opMaxMinPacked AST.slt

let pmaxub ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 8<rt> opPmaxu

let pmaxud ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 32<rt> opPmaxu

let pmaxuw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 16<rt> opPmaxu

let pmaxsb ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 8<rt> opPmaxs

let pmaxsd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 32<rt> opPmaxs

let pmaxsw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 16<rt> opPmaxs

let pminub ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 8<rt> opPminu

let pminud ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 32<rt> opPminu

let pminuw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 16<rt> opPminu

let pminsb ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 8<rt> opPmins

let pminsd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 32<rt> opPmins

let pminsw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 16<rt> opPmins

let private mskArrayInit cnt src =
  Array.init cnt (fun i -> AST.extract src 1<rt> (i * 8 + 7))

let private concatBits (bitExprs: Expr[]) =
  let head = bitExprs[0]
  let tail = bitExprs[1..]
  let rt = RegType.fromBitWidth bitExprs.Length
  tail
  |> Array.foldi (fun acc i bitExpr ->
    let e = AST.zext rt bitExpr
    acc .| (e << (numI32 (i + 1) rt))
  ) (AST.zext rt head)
  |> fst

let pmovmskb ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let struct (dst, src) = getTwoOprs ins
  let r = match src with | OprReg r -> r | _ -> raise InvalidOperandException
  match Register.getKind r with
  | Register.Kind.MMX ->
    let struct (dst, src) = transTwoOprs ir false ins insLen ctxt
    let srcSize = TypeCheck.typeOf src
    let cnt = RegType.toByteWidth srcSize
    let tmps = mskArrayInit cnt src
    !!ir (dstAssign oprSize dst <| AST.zext oprSize (concatBits tmps))
  | Register.Kind.XMM ->
    let dst = transOprToExpr ir false ins insLen ctxt dst
    let srcB, srcA = transOprToExpr128 ir false ins insLen ctxt src
    let srcSize = TypeCheck.typeOf srcA
    let cnt = RegType.toByteWidth srcSize
    let tmpsA = mskArrayInit cnt srcA
    let tmpsB = mskArrayInit cnt srcB
    let tmps = AST.concat (concatBits tmpsB) (concatBits tmpsA)
    !!ir (dstAssign oprSize dst <| AST.zext oprSize tmps)
  | Register.Kind.YMM ->
    let dst = transOprToExpr ir false ins insLen ctxt dst
    let srcD, srcC, srcB, srcA = transOprToExpr256 ir false ins insLen ctxt src
    let srcSize = TypeCheck.typeOf srcA
    let cnt = RegType.toByteWidth srcSize
    let tmpsA = mskArrayInit cnt srcA
    let tmpsB = mskArrayInit cnt srcB
    let tmpsC = mskArrayInit cnt srcC
    let tmpsD = mskArrayInit cnt srcD
    let tmps =
      AST.concat (AST.concat (concatBits tmpsD) (concatBits tmpsC))
        (AST.concat (concatBits tmpsB) (concatBits tmpsA))
    !!ir (dstAssign oprSize dst <| AST.zext oprSize tmps)
  | _ -> raise InvalidOperandException
  !>ir insLen

let packedMove ir srcSz packSz dstA dstB src isSignExt =
  let packNum = int (srcSz / packSz)
  let dSz = 128<rt> / packNum
  let tDst = Array.init packNum (fun _ -> !+ir dSz)
  if isSignExt then
    for i in 0 .. packNum - 1 do
      !!ir (tDst[i] := AST.sext dSz (AST.extract src packSz (i * (int packSz))))
  else
    for i in 0 .. packNum - 1 do
      !!ir (tDst[i] := AST.zext dSz (AST.extract src packSz (i * (int packSz))))
  let tDstA, tDstB = tDst |> Array.splitAt (packNum / 2)
  !!ir (dstA := tDstA |> AST.concatArr)
  !!ir (dstB := tDstB |> AST.concatArr)

let pmovbw ins insLen ctxt packSz isSignExt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  match src with
  | OprReg _ ->
    let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
    let _, srcA = transOprToExpr128 ir false ins insLen ctxt src
    packedMove ir 64<rt> packSz dstA dstB srcA isSignExt
  | OprMem _ ->
    let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
    let src = transOprToExpr64 ir false ins insLen ctxt src
    packedMove ir 64<rt> packSz dstA dstB src isSignExt
  | _ -> raise InvalidOperandException
  !>ir insLen

let pmovbd ins insLen ctxt packSz isSignExt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  match src with
  | OprReg _ ->
    let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
    let _, srcA = transOprToExpr128 ir false ins insLen ctxt src
    packedMove ir 32<rt> packSz dstA dstB (AST.xtlo 32<rt> srcA) isSignExt
  | OprMem _ ->
    let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
    let src = transOprToExpr32 ir false ins insLen ctxt src
    packedMove ir 32<rt> packSz dstA dstB src isSignExt
  | _ -> raise InvalidOperandException
  !>ir insLen

let pmovbq ins insLen ctxt packSz isSignExt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  match src with
  | OprReg _ ->
    let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
    let _, srcA = transOprToExpr128 ir false ins insLen ctxt src
    packedMove ir 16<rt> packSz dstA dstB (AST.xtlo 16<rt> srcA) isSignExt
  | OprMem _ ->
    let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
    let src = transOprToExpr16 ir false ins insLen ctxt src
    packedMove ir 16<rt> packSz dstA dstB src isSignExt
  | _ -> raise InvalidOperandException
  !>ir insLen

let private opPmulhuw _ = opPmul AST.xthi AST.zext 32<rt> 16<rt>

let pmulhuw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 16<rt> opPmulhuw

let private opPmulld _ = opPmul AST.xtlo AST.sext 32<rt> 32<rt>

let pmulld ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 32<rt> opPmulld

let private opPsadbw oprSize e1 e2 =
  let abs e1 e2 = AST.ite (AST.lt e1 e2) (e2 .- e1) (e1 .- e2)
  let temp = Array.map2 abs e1 e2
  let n0 = AST.num0 16<rt>
  let inline sum e1 e2 = AST.zext 16<rt> e1 .+ AST.zext 16<rt> e2
  let zeros = Array.init 3 (fun _ -> n0)
  match oprSize with
  | 64<rt> ->
    let res = Array.reduce sum (Array.sub temp 0 8)
    Array.append [| res |] zeros
  | 128<rt> ->
    let res1 = Array.reduce sum (Array.sub temp 0 8)
    let res2 = Array.reduce sum (Array.sub temp 8 8)
    Array.concat [| [| res1 |]; zeros; [| res2 |]; zeros |]
  | _ -> raise InvalidOperandSizeException

let psadbw ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let sPackSz = 8<rt> (* SRC Pack size *)
  let sPackNum = 64<rt> / sPackSz
  let dPackSz = 16<rt> (* DST Pack size *)
  let dPackNum = 64<rt> / dPackSz
  let struct (dst, src) = getTwoOprs ins
  let src1 = transOprToArr ir true ins insLen ctxt sPackSz sPackNum oprSize dst
  let src2 = transOprToArr ir true ins insLen ctxt sPackSz sPackNum oprSize src
  let result = opPsadbw oprSize src1 src2
  assignPackedInstr ir false ins insLen ctxt dPackNum oprSize dst result
  !>ir insLen

let pshufw ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src, ord) = transThreeOprs ir false ins insLen ctxt
  let oprSize = getOperationSize ins
  let cnt = RegType.toBitWidth oprSize / 16
  let tmps = Array.init cnt (fun _ -> !+ir 16<rt>)
  let n16 = numI32 16 oprSize
  let mask2 = numI32 3 16<rt> (* 2-bit mask *)
  for i in 1 .. cnt do
    let order =
      ((AST.xtlo 16<rt> ord) >> (numI32 ((i - 1) * 2) 16<rt>)) .& mask2
    let order' = AST.zext oprSize order
    !!ir (tmps[i - 1] := AST.xtlo 16<rt> (src >> (order' .* n16)))
  done
  !!ir (dst := AST.concatArr tmps)
  !>ir insLen

let pshufd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src, ord) = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
  let srcB, srcA = transOprToExpr128 ir false ins insLen ctxt src
  let ord = getImmValue ord
  let oprSize = getOperationSize ins
  let cnt = RegType.toBitWidth oprSize / 32
  let rShiftTo64 hiExpr lowExpr amount =
    let rightAmt = numI64 (amount % 64L) 64<rt>
    let leftAmt = numI64 (64L - (amount % 64L)) 64<rt>
    if amount < 64L then
      AST.xtlo 32<rt> ((hiExpr << leftAmt) .| (lowExpr >> rightAmt))
    elif amount < 128 then AST.xtlo 32<rt> (hiExpr >> rightAmt)
    else AST.num0 32<rt>
  let amount idx = ((ord >>> (idx * 2)) &&& 0b11L) * 32L
  let struct (tSrcB, tSrcA) = tmpVars2 ir 64<rt>
  !!ir (tSrcA := srcA)
  !!ir (tSrcB := srcB)
  let src amtIdx = rShiftTo64 tSrcB tSrcA (amount amtIdx)
  !!ir (dstA := AST.concat (src 1) (src 0))
  !!ir (dstB := AST.concat (src 3) (src 2))
  !>ir insLen

let pshuflw ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src, imm) = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
  let srcB, srcA = transOprToExpr128 ir false ins insLen ctxt src
  let imm = numI64 (getImmValue imm) 64<rt>
  let tmps = Array.init 4 (fun _ -> !+ir 16<rt>)
  let n16 = numI32 16 64<rt>
  let mask2 = numI32 3 64<rt> (* 2-bit mask *)
  for i in 1 .. 4 do
    let imm =
      (imm >> (numI32 ((i - 1) * 2) 64<rt>)) .& mask2
    !!ir (tmps[i - 1] := AST.xtlo 16<rt> (srcA >> (imm .* n16)))
  done
  !!ir (dstA := AST.concatArr tmps)
  !!ir (dstB := srcB)
  !>ir insLen

let pshufhw ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src, imm) = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
  let srcB, srcA = transOprToExpr128 ir false ins insLen ctxt src
  let imm = numI64 (getImmValue imm) 64<rt>
  let tmps = Array.init 4 (fun _ -> !+ir 16<rt>)
  let n16 = numI32 16 64<rt>
  let mask2 = numI32 3 64<rt> (* 2-bit mask *)
  for i in 1 .. 4 do
    let imm =
      (imm >> (numI32 ((i - 1) * 2) 64<rt>)) .& mask2
    !!ir (tmps[i - 1] := AST.xtlo 16<rt> (srcB >> (imm .* n16)))
  done
  !!ir (dstA := srcA)
  !!ir (dstB := AST.concatArr tmps)
  !>ir insLen

let pshufb ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let packSize = 8<rt>
  let packNum = 64<rt> / packSize
  let allPackNum = oprSize / packSize
  let struct (dst, src) = getTwoOprs ins
  let src = transOprToArr ir false ins insLen ctxt packSize packNum oprSize src
  let struct (mask, n0) = tmpVars2 ir packSize
  !!ir (mask := numI32 (int allPackNum - 1) packSize)
  !!ir (n0 := AST.num0 packSize)
  match oprSize with
  | 64<rt> ->
    let dst = transOprToExpr ir false ins insLen ctxt dst
    let n8 = numI32 8 oprSize
    let shuffle src =
      let idx = src .& mask
      let numShift = AST.zext oprSize idx .* n8
      AST.ite (AST.xthi 1<rt> src) n0 (AST.xtlo packSize (dst >> numShift))
    !!ir (dst := Array.map shuffle src |> AST.concatArr)
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
    let n8 = !+ir 64<rt>
    !!ir (n8 := numI32 8 64<rt>)
    let shuffle src =
      let idx = src .& mask
      let numShift = ((AST.zext 64<rt> idx) .% n8) .* n8
      let tDst = !+ir 64<rt>
      !!ir (tDst := AST.ite (idx .< numI32 8 packSize) dstA dstB)
      AST.ite (AST.xthi 1<rt> src) n0 (AST.xtlo packSize (tDst >> numShift))
    let result = Array.map shuffle src
    !!ir (dstA := Array.sub result 0 packNum |> AST.concatArr)
    !!ir (dstB := Array.sub result packNum packNum |> AST.concatArr)
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let movdqa ins insLen ctxt =
  buildMove ins insLen ctxt

let movdqu ins insLen ctxt =
  buildMove ins insLen ctxt

let movq2dq ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
  let src = transOprToExpr ir false ins insLen ctxt src
  !!ir (dstA := src)
  !!ir (dstB := AST.num0 64<rt>)
  !>ir insLen

let movdq2q ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr ir false ins insLen ctxt dst
  let _, srcA = transOprToExpr128 ir false ins insLen ctxt src
  !!ir (dst := srcA)
  !>ir insLen

let private opPmuludq _ =
  let low32 expr = expr .& numI64 0xffffffffL 64<rt>
  Array.map2 (fun e1 e2 -> low32 e1 .* low32 e2)

let pmuludq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 64<rt> opPmuludq

let paddq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 64<rt> (opP (.+))

let psubq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 64<rt> (opP (.-))

let pslldq ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, cnt) = getTwoOprs ins
  let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
  let cnt = getImmValue cnt
  let amount = if cnt > 15L then 16L * 8L else cnt * 8L
  let rightAmt = numI64 (64L - (amount % 64L)) 64<rt>
  let leftAmt = numI64 (amount % 64L) 64<rt>
  let struct (tDstB, tDstA) = tmpVars2 ir 64<rt>
  !!ir (tDstA := dstA)
  !!ir (tDstB := dstB)
  if amount < 64 then
    !!ir (dstA := tDstA << leftAmt)
    !!ir (dstB := (tDstB << leftAmt) .| (tDstA >> rightAmt))
  elif amount < 128 then
    !!ir (dstA := AST.num0 64<rt>)
    !!ir (dstB := tDstA << leftAmt)
  else
    !!ir (dstA := AST.num0 64<rt>)
    !!ir (dstB := AST.num0 64<rt>)
  !>ir insLen

let psrldq ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, cnt) = getTwoOprs ins
  let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
  let cnt = getImmValue cnt
  let amount = if cnt > 15L then 16L * 8L else cnt * 8L
  let rightAmt = numI64 (amount % 64L) 64<rt>
  let leftAmt = numI64 (64L - (amount % 64L)) 64<rt>
  let struct (tDstB, tDstA) = tmpVars2 ir 64<rt>
  !!ir (tDstA := dstA)
  !!ir (tDstB := dstB)
  if amount < 64 then
    !!ir (dstA := (tDstB << leftAmt) .| (tDstA >> rightAmt))
    !!ir (dstB := tDstB >> rightAmt)
  elif amount < 128 then
    !!ir (dstA := tDstB >> rightAmt)
    !!ir (dstB := AST.num0 64<rt>)
  else
    !!ir (dstA := AST.num0 64<rt>)
    !!ir (dstB := AST.num0 64<rt>)
  !>ir insLen

let punpckhqdq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 64<rt> opUnpackHighData

let punpcklqdq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 64<rt> opUnpackLowData

let movntq ins insLen ctxt = buildMove ins insLen ctxt

let movntps ins insLen ctxt = buildMove ins insLen ctxt

let movntpd ins insLen ctxt = buildMove ins insLen ctxt

let movntdq ins insLen ctxt = buildMove ins insLen ctxt

let movnti ins insLen ctxt = buildMove ins insLen ctxt

let lddqu ins insLen ctxt = buildMove ins insLen ctxt

let movshdup ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ir false ins insLen ctxt dst
  let src2, src1 = transOprToExpr128 ir false ins insLen ctxt src
  let struct (tmp1, tmp2) = tmpVars2 ir 32<rt>
  !!ir (tmp1 := AST.xthi 32<rt> src1)
  !!ir (tmp2 := AST.xthi 32<rt> src2)
  !!ir (AST.xtlo 32<rt> dst1 := tmp1)
  !!ir (AST.xthi 32<rt> dst1 := tmp1)
  !!ir (AST.xtlo 32<rt> dst2 := tmp2)
  !!ir (AST.xthi 32<rt> dst2 := tmp2)
  !>ir insLen

let movsldup ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ir false ins insLen ctxt dst
  let src2, src1 = transOprToExpr128 ir false ins insLen ctxt src
  let struct (tmp1, tmp2) = tmpVars2 ir 32<rt>
  !!ir (tmp1 := AST.xtlo 32<rt> src1)
  !!ir (tmp2 := AST.xtlo 32<rt> src2)
  !!ir (AST.xtlo 32<rt> dst1 := tmp1)
  !!ir (AST.xthi 32<rt> dst1 := tmp1)
  !!ir (AST.xtlo 32<rt> dst2 := tmp2)
  !!ir (AST.xthi 32<rt> dst2 := tmp2)
  !>ir insLen

let movddup ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dst1, dst0 = transOprToExpr128 ir false ins insLen ctxt dst
  let src = transOprToExpr64 ir false ins insLen ctxt src
  !!ir (dst0 := src)
  !!ir (dst1 := src)
  !>ir insLen

let packWithSaturation ir packSz src =
  let z16 = AST.num0 (packSz / 2)
  let z32 = AST.num0 packSz
  let f16 = numU32 0xFFFFu (packSz / 2)
  let f32 = numU32 0xFFFFu packSz
  let tSrc = !+ir packSz
  let tmp = !+ir (packSz / 2)
  !!ir (tSrc := src)
  !!ir (tmp := AST.ite (tSrc ?< z32) z16 (AST.xtlo (packSz / 2) tSrc))
  !!ir (tmp := AST.ite (tSrc ?> f32) f16 tmp)
  tmp

let packusdw ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / 32<rt>
  let struct (dst, src) = getTwoOprs ins
  let src1 = transOprToArr ir true ins insLen ctxt 32<rt> packNum oprSize dst
  let src2 = transOprToArr ir true ins insLen ctxt 32<rt> packNum oprSize src
  let src = Array.append src1 src2
  let result = Array.map (packWithSaturation ir 32<rt>) src
  assignPackedInstr ir false ins insLen ctxt (packNum * 2) oprSize dst result
  !>ir insLen

let palignr ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src, imm) = getThreeOprs ins
  let imm8 = getImmValue imm
  let amount = imm8 * 8L
  let rightAmt = numI64 (amount % 64L) 64<rt>
  let leftAmt = numI64 (64L - (amount % 64L)) 64<rt>
  match getOperationSize ins with
  | 64<rt> ->
    let dst = transOprToExpr ir false ins insLen ctxt dst
    let src = transOprToExpr ir false ins insLen ctxt src
    let struct (tDst, tSrc) = tmpVars2 ir 64<rt>
    !!ir (tDst := dst)
    !!ir (tSrc := src)
    if amount < 64 then !!ir (dst := (tDst << leftAmt) .| (tSrc >> rightAmt))
    elif amount < 128 then !!ir (dst := tDst >> rightAmt)
    else !!ir (dst := AST.num0 64<rt>)
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
    let srcB, srcA = transOprToExpr128 ir false ins insLen ctxt src
    let struct (tDstB, tDstA, tSrcB, tSrcA) = tmpVars4 ir 64<rt>
    !!ir (tDstA := dstA)
    !!ir (tDstB := dstB)
    !!ir (tSrcA := srcA)
    !!ir (tSrcB := srcB)
    if amount < 64 then
      !!ir (dstA := (tSrcB << leftAmt) .| (tSrcA >> rightAmt))
      !!ir (dstB := (tDstA << leftAmt) .| (tSrcB >> rightAmt))
    elif amount < 128 then
      !!ir (dstA := (tDstA << leftAmt) .| (tSrcB >> rightAmt))
      !!ir (dstB := (tDstB << leftAmt) .| (tDstA >> rightAmt))
    elif amount < 192 then
      !!ir (dstA := (tDstB << leftAmt) .| (tDstA >> rightAmt))
      !!ir (dstB := tDstB >> rightAmt)
    elif amount < 256 then
      !!ir (dstA := tDstB >> rightAmt)
      !!ir (dstB := AST.num0 64<rt>)
    else
      !!ir (dstA := AST.num0 64<rt>)
      !!ir (dstB := AST.num0 64<rt>)
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let roundsd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src, imm) = getThreeOprs ins
  let dst = transOprToExpr64 ir false ins insLen ctxt dst
  let src = transOprToExpr64 ir false ins insLen ctxt src
  let imm = transOprToExpr ir false ins insLen ctxt imm
  let rc = (AST.extract (!.ctxt R.MXCSR) 8<rt> 13) .& (numI32 0b11 8<rt>)
  let tmp = !+ir 8<rt>
  let cster castKind = AST.cast castKind 64<rt> src
  let imm2 = (AST.xtlo 8<rt> imm) .& (numI32 0b11 8<rt>)
  !!ir (tmp := AST.ite (AST.extract imm 1<rt> 2) rc imm2)
  !!ir (dst := AST.ite (tmp == AST.num0 8<rt>) (cster CastKind.FtoFRound) dst)
  !!ir (dst := AST.ite (tmp == AST.num1 8<rt>) (cster CastKind.FtoFFloor) dst)
  !!ir (dst := AST.ite (tmp == numI32 2 8<rt>) (cster CastKind.FtoFCeil) dst)
  !!ir (dst := AST.ite (tmp == numI32 3 8<rt>) (cster CastKind.FtoFTrunc) dst)
  !>ir insLen

let pinsrb ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src, count) = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
  let src = transOprToExpr ir false ins insLen ctxt src
  let sel = getImmValue count &&& 0b1111L (* COUNT[3:0] *)
  let mask = numI64 (0xFFL <<< ((int32 sel * 8) % 64)) 64<rt>
  let amount = sel * 8L
  let t = !+ir 64<rt>
  let expAmt = numI64 (amount % 64L) 64<rt>
  !!ir (t := ((AST.zext 64<rt> (AST.xtlo 8<rt> src)) << expAmt) .& mask)
  if amount < 64 then !!ir (dstA := (dstA .& (AST.not mask)) .| t)
  else !!ir (dstB := (dstB .& (AST.not mask)) .| t)
  !>ir insLen

let private packedSign ir packSz control inputVal =
  let n0 = AST.num0 packSz
  let struct (tControl, tInputVal) = tmpVars2 ir packSz
  let struct (cond1, cond2) = tmpVars2 ir 1<rt>
  !!ir (tControl := control)
  !!ir (tInputVal := inputVal)
  !!ir (cond1 := tControl ?< n0)
  !!ir (cond2 := tControl == n0)
  AST.ite cond1 (AST.neg tInputVal) (AST.ite cond2 n0 tInputVal)

let psign ins insLen ctxt packSz =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / packSz
  let struct (dst, src) = getTwoOprs ins
  let srcDst = transOprToArr ir true ins insLen ctxt packSz packNum oprSize dst
  let src = transOprToArr ir true ins insLen ctxt packSz packNum oprSize src
  let result = Array.map2 (packedSign ir packSz) src srcDst
  assignPackedInstr ir false ins insLen ctxt packNum oprSize dst result
  !>ir insLen

let ptest ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (src1, src2) = getTwoOprs ins
  let src1B, src1A = transOprToExpr128 ir false ins insLen ctxt src1
  let src2B, src2A = transOprToExpr128 ir false ins insLen ctxt src2
  let struct (t1, t2, t3, t4) = tmpVars4 ir 64<rt>
  !!ir (t1 := src2A .& src1A)
  !!ir (t2 := src2B .& src1B)
  !!ir (!.ctxt R.ZF := (t1 .| t2) == (AST.num0 64<rt>))
  !!ir (t3 := src2A .& AST.not src1A)
  !!ir (t4 := src2B .& AST.not src1B)
  !!ir (!.ctxt R.CF := (t3 .| t4) == (AST.num0 64<rt>))
  !!ir (!.ctxt R.AF := AST.b0)
  !!ir (!.ctxt R.OF := AST.b0)
  !!ir (!.ctxt R.PF := AST.b0)
  !!ir (!.ctxt R.SF := AST.b0)
#if EMULATION
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen

let opPcmpeqq _ = opPcmp 64<rt> (==)

let pcmpeqq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 64<rt> opPcmpeqq

let packedBlend src1 src2 imm =
  Array.mapi2 (fun i e1 e2 -> AST.ite (AST.extract imm 1<rt> i) e1 e2) src1 src2

let packedVblend src1 src2 (mask: Expr []) =
  Array.mapi2 (fun i e1 e2 -> AST.ite (AST.xthi 1<rt> mask[i]) e1 e2) src1 src2

let blendpd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src, imm) = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
  let srcB, srcA = transOprToExpr128 ir false ins insLen ctxt src
  let imm = transOprToExpr ir false ins insLen ctxt imm
  let cond1 = AST.extract imm 1<rt> 0
  let cond2 = AST.extract imm 1<rt> 1
  !!ir (dstA := AST.ite cond1 srcA dstA)
  !!ir (dstB := AST.ite cond2 srcB dstB)
  !>ir insLen

let blendps ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / 32<rt>
  let struct (dst, src, imm) = getThreeOprs ins
  let src1 = transOprToArr ir true ins insLen ctxt 32<rt> packNum oprSize dst
  let src2 = transOprToArr ir true ins insLen ctxt 32<rt> packNum oprSize src
  let imm = transOprToExpr ir false ins insLen ctxt imm
  let result = packedBlend src2 src1 imm
  assignPackedInstr ir false ins insLen ctxt packNum oprSize dst result
  !>ir insLen

let blendvpd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src, xmm0) = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
  let srcB, srcA = transOprToExpr128 ir false ins insLen ctxt src
  let xmm0B, xmm0A = transOprToExpr128 ir false ins insLen ctxt xmm0
  let cond1 = AST.xthi 1<rt> xmm0A
  let cond2 = AST.xthi 1<rt> xmm0B
  !!ir (dstA := AST.ite cond1 srcA dstA)
  !!ir (dstB := AST.ite cond2 srcB dstB)
  !>ir insLen

let blendvps ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / 32<rt>
  let struct (dst, src, xmm0) = getThreeOprs ins
  let src1 = transOprToArr ir true ins insLen ctxt 32<rt> packNum oprSize dst
  let src2 = transOprToArr ir true ins insLen ctxt 32<rt> packNum oprSize src
  let xmm0 = transOprToArr ir false ins insLen ctxt 32<rt> packNum oprSize xmm0
  let result = packedVblend src2 src1 xmm0
  assignPackedInstr ir false ins insLen ctxt packNum oprSize dst result
  !>ir insLen

let pblendvb ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / 8<rt>
  let struct (dst, src, xmm0) = getThreeOprs ins
  let src1 = transOprToArr ir true ins insLen ctxt 8<rt> packNum oprSize dst
  let src2 = transOprToArr ir true ins insLen ctxt 8<rt> packNum oprSize src
  let xmm0 = transOprToArr ir false ins insLen ctxt 8<rt> packNum oprSize xmm0
  let result = packedVblend src2 src1 xmm0
  assignPackedInstr ir false ins insLen ctxt packNum oprSize dst result
  !>ir insLen

let pblendw ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / 16<rt>
  let struct (dst, src, imm) = getThreeOprs ins
  let src1 = transOprToArr ir true ins insLen ctxt 16<rt> packNum oprSize dst
  let src2 = transOprToArr ir true ins insLen ctxt 16<rt> packNum oprSize src
  let imm = transOprToExpr ir false ins insLen ctxt imm
  let result = packedBlend src2 src1 imm
  assignPackedInstr ir false ins insLen ctxt packNum oprSize dst result
  !>ir insLen

/// XXX (cleanup required)
/// imm8 control byte operation for PCMPESTRI, PCMPESTRM, etc..
/// See Chapter 4.1 of the manual vol. 2B.
type Imm8ControlByte = {
  PackSize   : RegType
  NumElems   : uint32
  Sign       : Sign
  Agg        : Agg
  Polarity   : Polarity
  OutSelect  : OutSelect
  Len        : Length
  Ret        : Return
}

and Sign =
  | Signed
  | UnSigned

and Agg =
  | EqualAny
  | Ranges
  | EqualEach
  | EqualOrdered

and Polarity =
  | PosPolarity
  | NegPolarity
  | PosMasked
  | NegMasked

and OutSelect =
  | Least
  | Most

and Length =
  | Implicit
  | Explicit

and Return =
  | Index
  | Mask

let private getPcmpstrInfo opCode (imm: Expr) =
  let immByte = match imm.E with
                | Num n -> BitVector.GetValue n
                | _ -> raise InvalidExprException
  let agg = match (immByte >>> 2) &&& 3I with
            | v when v = 0I -> EqualAny
            | v when v = 1I -> Ranges
            | v when v = 2I -> EqualEach
            | v when v = 3I -> EqualOrdered
            | _ -> Utils.impossible ()
  let pol = match (immByte >>> 4) &&& 3I with
            | v when v = 0I -> PosPolarity
            | v when v = 1I -> NegPolarity
            | v when v = 2I -> PosMasked
            | v when v = 3I -> NegMasked
            | _ -> Utils.impossible ()
  let size, nElem =
    if immByte &&& 1I = 0I then 8<rt>, 16u else 16<rt>, 8u
  let len, ret =
    match opCode with
    | Opcode.PCMPISTRI | Opcode.VPCMPISTRI -> Implicit, Index
    | Opcode.PCMPESTRI | Opcode.VPCMPESTRI -> Explicit, Index
    | Opcode.PCMPISTRM | Opcode.VPCMPISTRM -> Implicit, Mask
    | Opcode.PCMPESTRM | Opcode.VPCMPESTRM -> Explicit, Mask
    | _ -> raise InvalidOpcodeException
  { PackSize = size
    NumElems = nElem
    Sign = if (immByte >>> 1) &&& 1I = 0I then UnSigned else Signed
    Agg = agg
    Polarity = pol
    OutSelect = if (immByte >>> 6) &&& 1I = 0I then Least else Most
    Len = len
    Ret = ret }

let private explicitValidCheck ctrl reg rSz ir =
  let tmps = [| for _ in 1u .. ctrl.NumElems -> !+ir 1<rt> |]
  let checkNum = numU32 ctrl.NumElems rSz
  let rec getValue idx =
    let v = AST.lt (numU32 idx rSz) (AST.ite (AST.lt checkNum reg) checkNum reg)
    if idx = ctrl.NumElems then ()
    else !!ir (tmps[int idx] := v)
         getValue (idx + 1u)
  getValue 0u
  tmps

let private implicitValidCheck ctrl srcB srcA ir =
  let unitWidth = RegType.toBitWidth ctrl.PackSize
  let tmps = [| for _ in 1u .. ctrl.NumElems -> !+ir 1<rt> |]
  let getSrc idx e = AST.extract e ctrl.PackSize (unitWidth * idx)
  let rec getValue idx =
    if idx = int ctrl.NumElems then ()
    else
      let half = int ctrl.NumElems / 2
      let e, amount = if idx < half then srcA, idx else srcB, idx - half
      let v e = tmps[idx - 1] .& (getSrc amount e != AST.num0 ctrl.PackSize)
      !!ir (tmps[idx] := v e)
      getValue (idx + 1)
  !!ir (tmps[0] := AST.b1 .& (getSrc 0 srcA != AST.num0 ctrl.PackSize))
  getValue 1
  tmps

let private genValidCheck ins insLen ctxt ctrl e1 e2 ir =
  let src1B, src1A = transOprToExpr128 ir false ins insLen ctxt e1
  let src2B, src2A = transOprToExpr128 ir false ins insLen ctxt e2
  match ctrl.Len with
  | Implicit -> implicitValidCheck ctrl src1B src1A ir,
                implicitValidCheck ctrl src2B src2A ir
  | Explicit ->
    let regSize, ax, dx =
      if hasREXW ins.REXPrefix
      then 64<rt>, !.ctxt R.RAX, !.ctxt R.RDX
      else 32<rt>, !.ctxt R.EAX, !.ctxt R.EDX
    explicitValidCheck ctrl ax regSize ir,
    explicitValidCheck ctrl dx regSize ir

let private genBoolRes ir ins insLen ctrl ctxt e1 e2
            (ck1: Expr []) (ck2: Expr []) j i cmp =
  let src1B, src1A = transOprToExpr128 ir false ins insLen ctxt e1
  let src2B, src2A = transOprToExpr128 ir false ins insLen ctxt e2
  let elemSz = RegType.fromBitWidth <| int ctrl.NumElems
  let getSrc s idx =
    let unitWidth = RegType.toBitWidth ctrl.PackSize
    let amount = unitWidth * idx
    let amount = if amount < 64 then amount else amount - 64
    AST.extract s ctrl.PackSize amount
  let b =
    let e1 = if j < int ctrl.NumElems / 2 then src1A else src1B
    let e2 = if i < int ctrl.NumElems / 2 then src2A else src2B
    (AST.ite (cmp (getSrc e1 j) (getSrc e2 i)) (AST.num1 elemSz)
      (AST.num0 elemSz))
  match ctrl.Agg with
  | EqualAny | Ranges ->
    AST.ite (AST.not ck1[j] .& AST.not ck2[i]) (AST.num0 elemSz)
      (AST.ite (AST.not ck1[j] .| AST.not ck2[i]) (AST.num0 elemSz) b)
  | EqualEach ->
    AST.ite (AST.not ck1[i] .& AST.not ck2[i]) (AST.num1 elemSz)
      (AST.ite (AST.not ck1[i] .| AST.not ck2[i]) (AST.num0 elemSz) b)
  | EqualOrdered ->
    AST.ite (AST.not ck1[j] .& AST.not ck2[i]) (AST.num1 elemSz)
      (AST.ite (AST.not ck1[j] .& ck2[i]) (AST.num1 elemSz)
        (AST.ite (ck1[j] .& AST.not ck2[i]) (AST.num0 elemSz) b))

let private aggOpr ins insLen ctxt ctrl src1 src2 ck1 ck2 (res1 : Expr []) ir =
  let nElem = int ctrl.NumElems
  let elemSz = RegType.fromBitWidth <| nElem
  let boolRes = genBoolRes ir ins insLen ctrl ctxt src2 src1 ck2 ck1
  let rangesCmp idx =
    match ctrl.Sign, idx % 2 = 0 with
    | Signed, true -> AST.sge
    | Signed, _ -> AST.sle
    | _, true -> AST.ge
    | _, _ -> AST.le
  match ctrl.Agg with
  | EqualAny ->
    for j in 0 .. nElem - 1 do
      let tRes = [| for _ in 1 .. nElem -> !+ir elemSz |]
      let boolRes i = boolRes j i (==)
      !!ir (tRes[0] := AST.num0 elemSz .| boolRes 0)
      for i in 1 .. nElem - 1 do
        !!ir (tRes[i] := tRes[i - 1] .| boolRes i)
      done
      !!ir (res1[j] := tRes[nElem - 1] << numI32 j elemSz)
    done
  | EqualEach ->
    for i in 0 .. nElem - 1 do
      let boolRes i = boolRes i i (==)
      !!ir (res1[i] := boolRes i << numI32 i elemSz)
    done
  | EqualOrdered ->
    for j in 0 .. nElem - 1 do
      let tRes = [| for _ in 1 .. nElem -> !+ir elemSz |]
      let boolRes k i = boolRes k i (==)
      !!ir (tRes[0] := numI32 -1 elemSz .& boolRes j 0)
      for i in 1 .. nElem - 1 - j do
        let k = i + j
        !!ir (tRes[i] := tRes[i - 1] .& boolRes k i)
      done
      !!ir (res1[j] := tRes[nElem - 1] << numI32 j elemSz)
    done
  | Ranges ->
    for j in 0 .. nElem - 1 do
      let tRes = [| for _ in 1 .. nElem -> !+ir elemSz |]
      let cmp i = rangesCmp i
      let boolRes i = boolRes j i (cmp i)
      !!ir (tRes[0] := AST.num0 elemSz .| (boolRes 0 .& boolRes 1))
      for i in 2 .. 2 .. nElem - 1 do
        !!ir
          (tRes[i] := tRes[i - 1] .| (boolRes i .& boolRes (i + 1)))
      done
      !!ir (res1[j] := tRes[nElem - 1] << numI32 j elemSz)
    done

let private getIntRes2 e ctrInfo (booRes: Expr []) =
  let elemSz = RegType.fromBitWidth <| int ctrInfo.NumElems
  let elemCnt = ctrInfo.NumElems |> int
  match ctrInfo.Polarity with
  | PosPolarity | PosMasked -> e
  | NegPolarity -> numI32 -1 elemSz <+> e
  | NegMasked ->
    List.fold (fun acc i ->
      let e1 = e .& numI32 (pown 2 i) elemSz
      let e2 = (AST.not e) .& numI32 (pown 2 i) elemSz
      (AST.ite (booRes[i]) e2 e1) :: acc) [] [0 .. elemCnt - 1]
    |> List.reduce (.|)

let rec private genOutput ctrl e acc i =
  let elemSz = RegType.fromBitWidth <| int ctrl.NumElems
  let isSmallOut = ctrl.OutSelect = Least
  let e' = e >> numI32 i elemSz
  let next = if isSmallOut then i - 1 else i + 1
  let cond = if isSmallOut then i = 0 else i = int ctrl.NumElems - 1
  if cond then AST.ite (AST.xtlo 1<rt> e') (numI32 i elemSz) acc
  else genOutput ctrl e (AST.ite (AST.xtlo 1<rt> e') (numI32 i elemSz) acc) next

let private pcmpStrRet (ins: InsInfo) info ctxt intRes2 ir =
  let nElem = int info.NumElems
  let elemSz = RegType.fromBitWidth <| nElem
  match info.Ret with
  | Index ->
    let outSz, cx =
      if hasREXW ins.REXPrefix then 64<rt>, R.RCX else 32<rt>, R.ECX
    let cx = !.ctxt cx
    let nMaxSz = numI32 nElem elemSz
    let idx = if info.OutSelect = Least then nElem - 1 else 0
    let out = AST.zext outSz <| genOutput info intRes2 nMaxSz idx
    !!ir (dstAssign outSz cx out)
  | Mask ->
    let xmmB, xmmA = getPseudoRegVar128 ctxt Register.XMM0
    let loop (acc1, acc2) i =
      let src = AST.extract intRes2 1<rt> i
      if (i < nElem / 2) then (acc1, (AST.zext info.PackSize src) :: acc2)
      else ((AST.zext info.PackSize src) :: acc1, acc2)
    if info.OutSelect = Least then
      !!ir (xmmA := AST.zext 64<rt> intRes2)
      !!ir (xmmB := AST.num0 64<rt>)
    else let r1, r2 = List.fold loop ([], []) [0 .. nElem - 1]
         !!ir (xmmB := AST.concatArr (List.toArray r1))
         !!ir (xmmA := AST.concatArr (List.toArray r2))

let private getZSFForPCMPSTR ins insLen ctrl ctxt src1 src2 ir =
  let src1B, src1A = transOprToExpr128 ir false ins insLen ctxt src1
  let src2B, src2A = transOprToExpr128 ir false ins insLen ctxt src2
  let getExZSFlag r =
    let reg = !.ctxt r
    AST.lt (AST.ite (AST.xthi 1<rt> reg) (AST.neg reg) reg)
       (numU32 ctrl.NumElems 32<rt>)
  let rec getImZSFlag acc srcB srcA idx =
    let packSz = ctrl.PackSize
    let packWidth = RegType.toBitWidth packSz
    let half = ctrl.NumElems / 2u |> int
    let e, amount = if idx < half then srcA, idx else srcB, idx - half
    let v e = e >> numI32 (amount * packWidth) 64<rt>
    let next, cond = idx - 1, idx = 0
    if cond then AST.ite (AST.xtlo packSz (v e) == AST.num0 packSz) AST.b1 acc
    else let acc = AST.ite (AST.xtlo packSz (v e) == AST.num0 packSz) AST.b1 acc
         getImZSFlag acc srcB srcA next
  match ctrl.Len with
  | Implicit ->
    !!ir (!.ctxt R.ZF :=
      getImZSFlag AST.b0 src2B src2A (ctrl.NumElems - 1u |> int))
    !!ir (!.ctxt R.SF :=
      getImZSFlag AST.b0 src1B src1A (ctrl.NumElems - 1u |> int))
  | Explicit ->
    !!ir (!.ctxt R.ZF := getExZSFlag R.EDX)
    !!ir (!.ctxt R.SF := getExZSFlag R.EAX)

let pcmpstr ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (src1, src2, imm) = getThreeOprs ins
  let imm = transOprToExpr ir false ins insLen ctxt imm
  let ctrl = getPcmpstrInfo ins.Opcode imm
  let nElem = int ctrl.NumElems
  let elemSz = RegType.fromBitWidth <| nElem
  let ck1, ck2 = genValidCheck ins insLen ctxt ctrl src1 src2 ir
  let struct (intRes1, intRes2) = tmpVars2 ir elemSz
  let res1 = [| for _ in 1 .. nElem -> !+ir elemSz |]
  aggOpr ins insLen ctxt ctrl src1 src2 ck1 ck2 res1 ir
  !!ir (intRes1 := Array.reduce (.|) res1)
  !!ir (intRes2 := getIntRes2 intRes1 ctrl ck2)
  pcmpStrRet ins ctrl ctxt intRes2 ir
  !!ir (!.ctxt R.CF := intRes2 != AST.num0 elemSz)
  getZSFForPCMPSTR ins insLen ctrl ctxt src1 src2 ir
  !!ir (!.ctxt R.OF := AST.xtlo 1<rt> intRes2)
  !!ir (!.ctxt R.AF := AST.b0)
  !!ir (!.ctxt R.PF := AST.b0)
#if EMULATION
  ctxt.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  !>ir insLen
