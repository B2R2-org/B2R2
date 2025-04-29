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

module internal B2R2.FrontEnd.Intel.SSELifter

open B2R2
open B2R2.Collections
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.Intel
open B2R2.FrontEnd.Intel.Helper
open B2R2.FrontEnd.Intel.LiftingUtils
open B2R2.FrontEnd.Intel.MMXLifter

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
    if isDouble then numU64 0xfffffffffffffUL 64<rt>
    else numU64 0x7fffffUL 32<rt>
  src .& mask

let isNan isDouble expr =
  let exponent = getExponent isDouble expr
  let mantissa = getMantissa isDouble expr
  let e = if isDouble then numI32 0x7ff 32<rt> else numI32 0xff 32<rt>
  let zero = if isDouble then AST.num0 64<rt> else AST.num0 32<rt>
  (exponent == e) .& (mantissa != zero)

let addsubpd (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
  let struct (srcB, srcA) = transOprToExpr128 bld false ins insLen src
  bld <+ (dstA := AST.fsub dstA srcA)
  bld <+ (dstB := AST.fadd dstB srcB)
  bld --!> insLen

let addsubps (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
  let struct (srcB, srcA) = transOprToExpr128 bld false ins insLen src
  let struct (t1, t2, t3, t4) = tmpVars4 bld 32<rt>
  bld <+ (t1 := AST.fsub (AST.xtlo 32<rt> dstA) (AST.xtlo 32<rt> srcA))
  bld <+ (t2 := AST.fadd (AST.xthi 32<rt> dstA) (AST.xthi 32<rt> srcA))
  bld <+ (t3 := AST.fsub (AST.xtlo 32<rt> dstB) (AST.xtlo 32<rt> srcB))
  bld <+ (t4 := AST.fadd (AST.xthi 32<rt> dstB) (AST.xthi 32<rt> srcB))
  bld <+ (dstA := AST.concat t2 t1)
  bld <+ (dstB := AST.concat t4 t3)
  bld --!> insLen

let buildMove (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / 64<rt>
  match oprSize with
  | 32<rt> | 64<rt> ->
    let struct (dst, src) = transTwoOprs bld false ins insLen
    bld <+ (dst := src)
  | 128<rt> | 256<rt> | 512<rt> ->
    let struct (dst, src) = getTwoOprs ins
    let src = transOprToArr bld false ins insLen 64<rt> packNum oprSize src
    assignPackedInstr bld false ins insLen packNum oprSize dst src
  | _ -> raise InvalidOperandSizeException
  bld --!> insLen

let movaps ins insLen bld = buildMove ins insLen bld

let movapd ins insLen bld = buildMove ins insLen bld

let movups ins insLen bld = buildMove ins insLen bld

let movupd ins insLen bld = buildMove ins insLen bld

let movhps (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  match dst, src with
  | OprMem (_, _, _, 64<rt>), OprReg r ->
    let dst = transOprToExpr bld false ins insLen dst
    bld <+ (dst := pseudoRegVar bld r 2)
  | OprReg r, OprMem (_, _, _, 64<rt>)->
    let src = transOprToExpr bld false ins insLen src
    bld <+ (pseudoRegVar bld r 2 := src)
  | _ -> raise InvalidOperandException
  bld --!> insLen

let movhpd (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  match dst, src with
  | OprReg r, OprMem _ ->
    let src = transOprToExpr bld false ins insLen src
    bld <+ (pseudoRegVar bld r 2 := src)
  | OprMem _, OprReg r ->
    let dst = transOprToExpr bld false ins insLen dst
    bld <+ (dst := pseudoRegVar bld r 2)
  | _ -> raise InvalidOperandException
  bld --!> insLen

let movhlps (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let struct (_, dst) = transOprToExpr128 bld false ins insLen dst
  let struct (src, _) = transOprToExpr128 bld false ins insLen src
  bld <+ (dst := src)
  bld --!> insLen

let movlpd (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  match dst, src with
  | OprReg r, OprMem _ ->
    let src = transOprToExpr bld false ins insLen src
    bld <+ (pseudoRegVar bld r 1 := src)
  | OprMem _, OprReg r ->
    let dst = transOprToExpr bld false ins insLen dst
    bld <+ (dst := pseudoRegVar bld r 1)
  | _ -> raise InvalidOperandException
  bld --!> insLen

let movlps ins insLen bld = movlpd ins insLen bld

let movlhps (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let struct (dst, _) = transOprToExpr128 bld false ins insLen dst
  let struct (_, src) = transOprToExpr128 bld false ins insLen src
  bld <+ (dst := src)
  bld --!> insLen

let movmskps (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr bld false ins insLen dst
  let struct (srcB, srcA) = transOprToExpr128 bld false ins insLen src
  let oprSize = getOperationSize ins
  let b0 = (srcA >> (numI32 31 64<rt>) .& (numI32 0b1 64<rt>))
  let b1 = (srcA >> (numI32 62 64<rt>) .& (numI32 0b10 64<rt>))
  let b2 = (srcB >> (numI32 29 64<rt>) .& (numI32 0b100 64<rt>))
  let b3 = (srcB >> (numI32 60 64<rt>) .& (numI32 0b1000 64<rt>))
  bld <+ (dstAssign oprSize dst (b3 .| b2 .| b1 .| b0))
  bld --!> insLen

let movmskpd (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr bld false ins insLen dst
  let struct (src1, src2) = transOprToExpr128 bld false ins insLen src
  let oprSize = getOperationSize ins
  let src63 = AST.zext oprSize (AST.xthi 1<rt> src2)
  let src127 = (AST.zext oprSize (AST.xthi 1<rt> src1)) << AST.num1 oprSize
  bld <+ (dstAssign oprSize dst (src63 .| src127))
  bld --!> insLen

let movss (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  match dst, src with
  | OprReg r1, OprReg r2 ->
    let dst = pseudoRegVar bld r1 1 |> AST.xtlo 32<rt>
    let src = pseudoRegVar bld r2 1 |> AST.xtlo 32<rt>
    bld <+ (dst := src)
  | OprReg r1, OprMem _ ->
    let struct (dst2, dst1) = pseudoRegVar128 bld r1
    let src = transOprToExpr bld false ins insLen src
    bld <+ (dstAssign 32<rt> dst1 src)
    bld <+ (dst2 := AST.num0 64<rt>)
  | OprMem _ , OprReg r1 ->
    let dst = transOprToExpr bld false ins insLen dst
    let src = pseudoRegVar bld r1 1 |> AST.xtlo 32<rt>
    bld <+ (dstAssign 32<rt> dst src)
  | _ -> raise InvalidOperandException
  bld --!> insLen

let movsd (ins: InsInfo) insLen bld =
  if ins.Operands = NoOperand then
    GeneralLifter.movs ins insLen bld
  else
    bld <!-- (ins.Address, insLen)
    let struct (dst, src) = getTwoOprs ins
    match dst, src with
    | OprReg r1, OprReg r2 ->
      let dst = pseudoRegVar bld r1 1
      let src = pseudoRegVar bld r2 1
      bld <+ (dst := src)
    | OprReg r1, OprMem _ ->
      let struct (dst2, dst1) = pseudoRegVar128 bld r1
      let src = transOprToExpr bld false ins insLen src
      bld <+ (dst1 := src)
      bld <+ (dst2 := AST.num0 64<rt>)
    | OprMem _ , OprReg r1 ->
      let dst = transOprToExpr bld false ins insLen dst
      let src = pseudoRegVar bld r1 1
      bld <+ (dstAssign 64<rt> dst src)
    | _ -> raise InvalidOperandException
    bld --!> insLen

let addps ins insLen bld =
  buildPackedInstr ins insLen bld false 32<rt> (opP AST.fadd)

let addpd ins insLen bld =
  buildPackedInstr ins insLen bld false 64<rt> (opP AST.fadd)

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

let private handleScalarFPOp (ins: InsInfo) insLen bld sz op =
  bld <!-- (ins.Address, insLen)
  let struct (_dst2, dst1) =
    ins.Operands |> getFstOperand |> transOprToExpr128 bld false ins insLen
  let src1, src2 = getTwoSrcOperands ins.Operands
  let src1 = transOprToExpr64 bld false ins insLen src1
  let src2 =
    if sz = 32<rt> then transOprToExpr32 bld false ins insLen src2
    else transOprToExpr64 bld false ins insLen src2
  let dst1, src1 =
    if sz = 32<rt> then AST.xtlo 32<rt> dst1, AST.xtlo 32<rt> src1
    else dst1, src1
  let struct (t1, t2, t3) = tmpVars3 bld sz
  bld <+ (t1 := src1)
  bld <+ (t2 := src2)
  bld <+ (t3 := op t1 t2)
  bld <+ (dst1 := t3)
  bld --!> insLen

let addss ins insLen bld =
  handleScalarFPOp ins insLen bld 32<rt> AST.fadd

let addsd ins insLen bld =
  handleScalarFPOp ins insLen bld 64<rt> AST.fadd

let subps ins insLen bld =
  buildPackedInstr ins insLen bld false 32<rt> (opP AST.fsub)

let subpd ins insLen bld =
  buildPackedInstr ins insLen bld false 64<rt> (opP AST.fsub)

let subss ins insLen bld =
  handleScalarFPOp ins insLen bld 32<rt> AST.fsub

let subsd ins insLen bld =
  handleScalarFPOp ins insLen bld 64<rt> AST.fsub

let mulps ins insLen bld =
  buildPackedInstr ins insLen bld false 32<rt> (opP AST.fmul)

let mulpd ins insLen bld =
  buildPackedInstr ins insLen bld false 64<rt> (opP AST.fmul)

let mulss ins insLen bld =
  handleScalarFPOp ins insLen bld 32<rt> AST.fmul

let mulsd ins insLen bld =
  handleScalarFPOp ins insLen bld 64<rt> AST.fmul

let divps ins insLen bld =
  buildPackedInstr ins insLen bld false 32<rt> (opP AST.fdiv)

let divpd ins insLen bld =
  buildPackedInstr ins insLen bld false 64<rt> (opP AST.fdiv)

let divss ins insLen bld =
  handleScalarFPOp ins insLen bld 32<rt> AST.fdiv

let divsd ins insLen bld =
  handleScalarFPOp ins insLen bld 64<rt> AST.fdiv

let rcpps (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (opr1, opr2) = getTwoOprs ins
  let struct (dst2, dst1) = transOprToExpr128 bld false ins insLen opr1
  let struct (src2, src1) = transOprToExpr128 bld false ins insLen opr2
  let dst1b, dst1a = AST.xthi 32<rt> dst1, AST.xtlo 32<rt> dst1
  let dst2b, dst2a = AST.xthi 32<rt> dst2, AST.xtlo 32<rt> dst2
  let src1b, src1a = AST.xthi 32<rt> src1, AST.xtlo 32<rt> src1
  let src2b, src2a = AST.xthi 32<rt> src2, AST.xtlo 32<rt> src2
  let tmp = tmpVar bld 32<rt>
  let flt1 = numI32 0x3f800000 32<rt>
  bld <+ (dst1a := AST.fdiv flt1 src1a)
  bld <+ (dst1b := AST.fdiv flt1 src1b)
  bld <+ (dst2a := AST.fdiv flt1 src2a)
  bld <+ (dst2b := AST.fdiv flt1 src2b)
  bld --!> insLen

let rcpss (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (opr1, opr2) = getTwoOprs ins
  let dst = transOprToExpr32 bld false ins insLen opr1
  let src = transOprToExpr32 bld false ins insLen opr2
  let tmp = tmpVar bld 32<rt>
  let flt1 = numI32 0x3f800000 32<rt>
  bld <+ (dst := AST.fdiv flt1 src)
  bld --!> insLen

let sqrtps ins insLen bld =
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / 32<rt>
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let src = transOprToArr bld false ins insLen 32<rt> packNum oprSize src
  let result = Array.map (AST.unop UnOpType.FSQRT) src
  assignPackedInstr bld false ins insLen packNum oprSize dst result
  bld --!> insLen

let sqrtpd (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (opr1, opr2) = getTwoOprs ins
  let struct (dst2, dst1) = transOprToExpr128 bld false ins insLen opr1
  let struct (src2, src1) = transOprToExpr128 bld false ins insLen opr2
  bld <+ (dst1 := AST.unop UnOpType.FSQRT src1)
  bld <+ (dst2 := AST.unop UnOpType.FSQRT src2)
  bld --!> insLen

let sqrtss (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (opr1, opr2) = getTwoOprs ins
  let dst = transOprToExpr32 bld false ins insLen opr1
  let src = transOprToExpr32 bld false ins insLen opr2
  bld <+ (dst := AST.unop UnOpType.FSQRT src)
  bld --!> insLen

let sqrtsd (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (opr1, opr2) = getTwoOprs ins
  let dst = transOprToExpr64 bld false ins insLen opr1
  let src = transOprToExpr64 bld false ins insLen opr2
  bld <+ (dst := AST.unop UnOpType.FSQRT src)
  bld --!> insLen

let rsqrtps (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (opr1, opr2) = getTwoOprs ins
  let struct (dst2, dst1) = transOprToExpr128 bld false ins insLen opr1
  let struct (src2, src1) = transOprToExpr128 bld false ins insLen opr2
  let dst1b, dst1a = AST.xthi 32<rt> dst1, AST.xtlo 32<rt> dst1
  let dst2b, dst2a = AST.xthi 32<rt> dst2, AST.xtlo 32<rt> dst2
  let src1b, src1a = AST.xthi 32<rt> src1, AST.xtlo 32<rt> src1
  let src2b, src2a = AST.xthi 32<rt> src2, AST.xtlo 32<rt> src2
  let tmp = tmpVar bld 32<rt>
  let flt1 = numI32 0x3f800000 32<rt>
  bld <+ (tmp := AST.unop UnOpType.FSQRT src1a)
  bld <+ (dst1a := AST.fdiv flt1 tmp)
  bld <+ (tmp := AST.unop UnOpType.FSQRT src1b)
  bld <+ (dst1b := AST.fdiv flt1 tmp)
  bld <+ (tmp := AST.unop UnOpType.FSQRT src2a)
  bld <+ (dst2a := AST.fdiv flt1 tmp)
  bld <+ (tmp := AST.unop UnOpType.FSQRT src2b)
  bld <+ (dst2b := AST.fdiv flt1 tmp)
  bld --!> insLen

let rsqrtss (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (opr1, opr2) = getTwoOprs ins
  let dst = transOprToExpr32 bld false ins insLen opr1
  let src = transOprToExpr32 bld false ins insLen opr2
  let tmp = tmpVar bld 32<rt>
  let flt1 = numI32 0x3f800000 32<rt>
  bld <+ (tmp := AST.unop UnOpType.FSQRT src)
  bld <+ (dst := AST.fdiv flt1 tmp)
  bld --!> insLen

let private minMaxPS (ins: InsInfo) insLen bld compare =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let struct (dst2, dst1) = transOprToExpr128 bld false ins insLen dst
  let struct (src2, src1) = transOprToExpr128 bld false ins insLen src
  let dst1A, dst1B = AST.xtlo 32<rt> dst1, AST.xthi 32<rt> dst1
  let dst2A, dst2B = AST.xtlo 32<rt> dst2, AST.xthi 32<rt> dst2
  let src1A, src1B = AST.xtlo 32<rt> src1, AST.xthi 32<rt> src1
  let src2A, src2B = AST.xtlo 32<rt> src2, AST.xthi 32<rt> src2
  let struct (val4, val3, val2, val1) = tmpVars4 bld 32<rt>
  bld <+ (val1 := AST.ite (compare dst1A src1A) dst1A src1A)
  bld <+ (val2 := AST.ite (compare dst1B src1B) dst1B src1B)
  bld <+ (val3 := AST.ite (compare dst2A src2A) dst2A src2A)
  bld <+ (val4 := AST.ite (compare dst2B src2B) dst2B src2B)
  bld <+ (dst1A := val1)
  bld <+ (dst1B := val2)
  bld <+ (dst2A := val3)
  bld <+ (dst2B := val4)
  bld --!> insLen

let private minMaxPD (ins: InsInfo) insLen bld compare =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let struct (dst2, dst1) = transOprToExpr128 bld false ins insLen dst
  let struct (src2, src1) = transOprToExpr128 bld false ins insLen src
  let struct (val2, val1) = tmpVars2 bld 64<rt>
  bld <+ (val1 := AST.ite (compare dst1 src1) dst1 src1)
  bld <+ (val2 := AST.ite (compare dst2 src2) dst2 src2)
  bld <+ (dst1 := val1)
  bld <+ (dst2 := val2)
  bld --!> insLen

let private minMaxSS (ins: InsInfo) insLen bld compare =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr32 bld false ins insLen dst
  let src = transOprToExpr32 bld false ins insLen src
  let tmp = tmpVar bld 32<rt>
  bld <+ (tmp := AST.ite (compare dst src) dst src)
  bld <+ (dst := tmp)
  bld --!> insLen

let private minMaxSD (ins: InsInfo) insLen bld compare =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr64 bld false ins insLen dst
  let src = transOprToExpr64 bld false ins insLen src
  let tmp = tmpVar bld 64<rt>
  bld <+ (tmp := AST.ite (compare dst src) dst src)
  bld <+ (dst := tmp)
  bld --!> insLen

let maxps ins insLen bld =
  minMaxPS ins insLen bld AST.fgt

let maxpd ins insLen bld =
  minMaxPD ins insLen bld AST.fgt

let maxss ins insLen bld =
  minMaxSS ins insLen bld AST.fgt

let maxsd ins insLen bld =
  minMaxSD ins insLen bld AST.fgt

let minps ins insLen bld =
  minMaxPS ins insLen bld AST.flt

let minpd ins insLen bld =
  minMaxPD ins insLen bld AST.flt

let minss ins insLen bld =
  minMaxSS ins insLen bld AST.flt

let minsd ins insLen bld =
  minMaxSD ins insLen bld AST.flt

let private cmppCond bld ins insLen op3 isDbl c expr1 expr2 =
  let imm =
    transOprToExpr bld false ins insLen op3 |> AST.xtlo 8<rt>
    .& numI32 0x7 8<rt>
  match imm with
  | Num (bv, _) ->
    match bv.SmallValue () with
    | 0UL -> bld <+ (c := expr1 == expr2)
    | 1UL -> bld <+ (c := AST.flt expr1 expr2)
    | 2UL -> bld <+ (c := AST.fle expr1 expr2)
    | 3UL -> bld <+ (c := isNan isDbl expr1 .| isNan isDbl expr2)
    | 4UL -> bld <+ (c := expr1 != expr2)
    | 5UL -> bld <+ (c := AST.flt expr1 expr2 |> AST.not)
    | 6UL -> bld <+ (c := AST.fle expr1 expr2 |> AST.not)
    | 7UL -> bld <+ (c := (isNan isDbl expr1 .| isNan isDbl expr2) |> AST.not)
    | _ -> bld <+ (c := AST.b0)
  | _ -> Terminator.impossible ()

let cmpps (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (op1, op2, op3) = getThreeOprs ins
  let struct (dst1, dst2) = transOprToExpr128 bld false ins insLen op1
  let struct (src1, src2) = transOprToExpr128 bld false ins insLen op2
  let dst1A, dst1B = AST.xtlo 32<rt> dst1, AST.xthi 32<rt> dst1
  let dst2A, dst2B = AST.xtlo 32<rt> dst2, AST.xthi 32<rt> dst2
  let struct (cond1, cond2, cond3, cond4) = tmpVars4 bld 1<rt>
  cmppCond bld ins insLen op3 false cond1 dst1A (AST.xtlo 32<rt> src1)
  cmppCond bld ins insLen op3 false cond2 dst1B (AST.xthi 32<rt> src1)
  cmppCond bld ins insLen op3 false cond3 dst2A (AST.xtlo 32<rt> src2)
  cmppCond bld ins insLen op3 false cond4 dst2B (AST.xthi 32<rt> src2)
  bld <+ (dst1A := AST.ite cond1 (maxNum 32<rt>) (AST.num0 32<rt>))
  bld <+ (dst1B := AST.ite cond2 (maxNum 32<rt>) (AST.num0 32<rt>))
  bld <+ (dst2A := AST.ite cond3 (maxNum 32<rt>) (AST.num0 32<rt>))
  bld <+ (dst2B := AST.ite cond4 (maxNum 32<rt>) (AST.num0 32<rt>))
  bld --!> insLen

let cmppd (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (op1, op2, op3) = getThreeOprs ins
  let struct (dst1, dst2) = transOprToExpr128 bld false ins insLen op1
  let struct (src1, src2) = transOprToExpr128 bld false ins insLen op2
  let struct (cond1, cond2) = tmpVars2 bld 1<rt>
  cmppCond bld ins insLen op3 true cond1 dst1 src1
  cmppCond bld ins insLen op3 true cond2 dst2 src2
  bld <+ (dst1 := AST.ite cond1 (maxNum 64<rt>) (AST.num0 64<rt>))
  bld <+ (dst2 := AST.ite cond2 (maxNum 64<rt>) (AST.num0 64<rt>))
  bld --!> insLen

let cmpss (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src, imm) = getThreeOprs ins
  let dst = transOprToExpr32 bld false ins insLen dst
  let src = transOprToExpr32 bld false ins insLen src
  let max32 = maxNum 32<rt>
  let cond = tmpVar bld 1<rt>
  cmppCond bld ins insLen imm false cond dst src
  bld <+ (dst := AST.ite cond max32 (AST.num0 32<rt>))
  bld --!> insLen

let cmpsd (ins: InsInfo) insLen bld =
  match ins.Operands with
  | NoOperand -> GeneralLifter.cmps ins insLen bld
  | ThreeOperands (dst, src, imm) ->
    bld <!-- (ins.Address, insLen)
    let dst = transOprToExpr64 bld false ins insLen dst
    let src = transOprToExpr64 bld false ins insLen src
    let max64 = maxNum 64<rt>
    let cond = tmpVar bld 1<rt>
    cmppCond bld ins insLen imm true cond dst src
    bld <+ (dst := AST.ite cond max64 (AST.num0 64<rt>))
    bld --!> insLen
  | _ -> raise InvalidOperandException

let comiss (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (opr1, opr2) = getTwoOprs ins
  let opr1 = transOprToExpr32 bld false ins insLen opr1
  let opr2 = transOprToExpr32 bld false ins insLen opr2
  let lblNan = label bld "IsNan"
  let lblExit = label bld "Exit"
  let zf = regVar bld R.ZF
  let pf = regVar bld R.PF
  let cf = regVar bld R.CF
  bld <+ (zf := AST.ite (opr1 == opr2) AST.b1 AST.b0)
  bld <+ (pf := AST.b0)
  bld <+ (cf := AST.ite (AST.flt opr1 opr2) AST.b1 AST.b0)
  bld <+ (AST.cjmp (isNan false opr1 .| isNan false opr2)
                 (AST.jmpDest lblNan) (AST.jmpDest lblExit))
  bld <+ (AST.lmark lblNan)
  bld <+ (zf := AST.b1)
  bld <+ (pf := AST.b1)
  bld <+ (cf := AST.b1)
  bld <+ (AST.lmark lblExit)
  bld <+ (regVar bld R.OF := AST.b0)
  bld <+ (regVar bld R.AF := AST.b0)
  bld <+ (regVar bld R.SF := AST.b0)
#if EMULATION
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let comisd (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (opr1, opr2) = getTwoOprs ins
  let opr1 = transOprToExpr64 bld false ins insLen opr1
  let opr2 = transOprToExpr64 bld false ins insLen opr2
  let lblNan = label bld "IsNan"
  let lblExit = label bld "Exit"
  let zf = regVar bld R.ZF
  let pf = regVar bld R.PF
  let cf = regVar bld R.CF
  bld <+ (zf := AST.ite (opr1 == opr2) AST.b1 AST.b0)
  bld <+ (pf := AST.b0)
  bld <+ (cf := AST.ite (AST.flt opr1 opr2) AST.b1 AST.b0)
  bld <+ (AST.cjmp (isNan true opr1 .| isNan true opr2)
                 (AST.jmpDest lblNan) (AST.jmpDest lblExit))
  bld <+ (AST.lmark lblNan)
  bld <+ (zf := AST.b1)
  bld <+ (pf := AST.b1)
  bld <+ (cf := AST.b1)
  bld <+ (AST.lmark lblExit)
  bld <+ (regVar bld R.OF := AST.b0)
  bld <+ (regVar bld R.AF := AST.b0)
  bld <+ (regVar bld R.SF := AST.b0)
#if EMULATION
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let ucomiss (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (opr1, opr2) = getTwoOprs ins
  let opr1 = transOprToExpr32 bld false ins insLen opr1
  let opr2 = transOprToExpr32 bld false ins insLen opr2
  let lblNan = label bld "IsNan"
  let lblExit = label bld "Exit"
  let zf = regVar bld R.ZF
  let pf = regVar bld R.PF
  let cf = regVar bld R.CF
  bld <+ (zf := AST.ite (opr1 == opr2) AST.b1 AST.b0)
  bld <+ (pf := AST.b0)
  bld <+ (cf := AST.ite (AST.flt opr1 opr2) AST.b1 AST.b0)
  bld <+ (AST.cjmp (isNan false opr1 .| isNan false opr2)
                 (AST.jmpDest lblNan) (AST.jmpDest lblExit))
  bld <+ (AST.lmark lblNan)
  bld <+ (zf := AST.b1)
  bld <+ (pf := AST.b1)
  bld <+ (cf := AST.b1)
  bld <+ (AST.lmark lblExit)
  bld <+ (regVar bld R.OF := AST.b0)
  bld <+ (regVar bld R.AF := AST.b0)
  bld <+ (regVar bld R.SF := AST.b0)
#if EMULATION
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let ucomisd (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (opr1, opr2) = getTwoOprs ins
  let opr1 = transOprToExpr64 bld false ins insLen opr1
  let opr2 = transOprToExpr64 bld false ins insLen opr2
  let lblNan = label bld "IsNan"
  let lblExit = label bld "Exit"
  let zf = regVar bld R.ZF
  let pf = regVar bld R.PF
  let cf = regVar bld R.CF
  bld <+ (zf := AST.ite (opr1 == opr2) AST.b1 AST.b0)
  bld <+ (pf := AST.b0)
  bld <+ (cf := AST.ite (AST.flt opr1 opr2) AST.b1 AST.b0)
  bld <+ (AST.cjmp (isNan true opr1 .| isNan true opr2)
                 (AST.jmpDest lblNan) (AST.jmpDest lblExit))
  bld <+ (AST.lmark lblNan)
  bld <+ (zf := AST.b1)
  bld <+ (pf := AST.b1)
  bld <+ (cf := AST.b1)
  bld <+ (AST.lmark lblExit)
  bld <+ (regVar bld R.OF := AST.b0)
  bld <+ (regVar bld R.AF := AST.b0)
  bld <+ (regVar bld R.SF := AST.b0)
#if EMULATION
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let andps ins insLen bld =
  buildPackedInstr ins insLen bld false 32<rt> opPand

let andpd ins insLen bld =
  buildPackedInstr ins insLen bld false 64<rt> opPand

let andnps ins insLen bld =
  buildPackedInstr ins insLen bld false 32<rt> opPandn

let andnpd ins insLen bld =
  buildPackedInstr ins insLen bld false 64<rt> opPandn

let orps ins insLen bld =
  buildPackedInstr ins insLen bld false 32<rt> opPor

let orpd ins insLen bld =
  buildPackedInstr ins insLen bld false 64<rt> opPor

let private opPxor _ = Array.map2 (<+>)

let xorps ins insLen bld =
  buildPackedInstr ins insLen bld false 32<rt> opPxor

let xorpd ins insLen bld =
  buildPackedInstr ins insLen bld false 64<rt> opPxor

let shufps (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src, imm) = getThreeOprs ins
  let struct (dst2, dst1) = transOprToExpr128 bld false ins insLen dst
  let struct (src2, src1) = transOprToExpr128 bld false ins insLen src
  let imm = transOprToExpr bld false ins insLen imm
  let dst1A, dst1B = AST.xtlo 32<rt> dst1, AST.xthi 32<rt> dst1
  let dst2A, dst2B = AST.xtlo 32<rt> dst2, AST.xthi 32<rt> dst2
  let src1A, src1B = AST.xtlo 32<rt> src1, AST.xthi 32<rt> src1
  let src2A, src2B = AST.xtlo 32<rt> src2, AST.xthi 32<rt> src2
  let doShuf cond dst e0 e1 e2 e3 =
    bld <+ (dst := AST.num0 32<rt>)
    bld <+ (dst := AST.ite (cond == AST.num0 8<rt>) e0 dst)
    bld <+ (dst := AST.ite (cond == AST.num1 8<rt>) e1 dst)
    bld <+ (dst := AST.ite (cond == numI32 2 8<rt>) e2 dst)
    bld <+ (dst := AST.ite (cond == numI32 3 8<rt>) e3 dst)
  let cond shfAmt =
    ((AST.xtlo 8<rt> imm) >> (numI32 shfAmt 8<rt>)) .& (numI32 0b11 8<rt>)
  let struct (tmp1, tmp2, tmp3, tmp4) = tmpVars4 bld 32<rt>
  doShuf (cond 0) tmp1 dst1A dst1B dst2A dst2B
  doShuf (cond 2) tmp2 dst1A dst1B dst2A dst2B
  doShuf (cond 4) tmp3 src1A src1B src2A src2B
  doShuf (cond 6) tmp4 src1A src1B src2A src2B
  bld <+ (dst1A := tmp1)
  bld <+ (dst1B := tmp2)
  bld <+ (dst2A := tmp3)
  bld <+ (dst2B := tmp4)
  bld --!> insLen

let shufpd (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src, imm) = getThreeOprs ins
  let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
  let struct (srcB, srcA) = transOprToExpr128 bld false ins insLen src
  let imm = transOprToExpr bld false ins insLen imm
  let cond1 = AST.xtlo 1<rt> imm
  let cond2 = AST.extract imm 1<rt> 1
  let struct (src1A, src1B, src2A, src2B) = tmpVars4 bld 64<rt>
  bld <+ (src1A := dstA)
  bld <+ (src1B := dstB)
  bld <+ (src2A := srcA)
  bld <+ (src2B := srcB)
  bld <+ (dstA := AST.ite cond1 src1B src1A)
  bld <+ (dstB := AST.ite cond2 src2B src2A)
  bld --!> insLen

let unpckhps (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let struct (dst2, dst1) = transOprToExpr128 bld false ins insLen dst
  let struct (src2, _src1) = transOprToExpr128 bld false ins insLen src
  let dst1A, dst1B = AST.xtlo 32<rt> dst1, AST.xthi 32<rt> dst1
  let dst2A, dst2B = AST.xtlo 32<rt> dst2, AST.xthi 32<rt> dst2
  let src2A, src2B = AST.xtlo 32<rt> src2, AST.xthi 32<rt> src2
  bld <+ (dst1A := dst2A)
  bld <+ (dst1B := src2A)
  bld <+ (dst2A := dst2B)
  bld <+ (dst2B := src2B)
  bld --!> insLen

let unpckhpd (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let struct (dst2, dst1) = transOprToExpr128 bld false ins insLen dst
  let struct (src2, _src1) = transOprToExpr128 bld false ins insLen src
  bld <+ (dst1 := dst2)
  bld <+ (dst2 := src2)
  bld --!> insLen

let unpcklps (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
  let struct (_, srcA) = transOprToExpr128 bld false ins insLen src
  let struct (tSrc1A, tSrc1B, tSrc2A) = tmpVars3 bld 64<rt>
  bld <+ (tSrc1A := dstA)
  bld <+ (tSrc1B := dstB)
  bld <+ (tSrc2A := srcA)
  bld <+ (dstA := AST.concat (AST.xtlo 32<rt> tSrc2A) (AST.xtlo 32<rt> tSrc1A))
  bld <+ (dstB := AST.concat (AST.xthi 32<rt> tSrc2A) (AST.xthi 32<rt> tSrc1A))
  bld --!> insLen

let unpcklpd (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let struct (dst2, dst1) = transOprToExpr128 bld false ins insLen dst
  let struct (_src2, src1) = transOprToExpr128 bld false ins insLen src
  bld <+ (dst2 := src1)
  bld --!> insLen

let cvtpi2ps (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr64 bld false ins insLen dst
  let src = transOprToExpr64 bld false ins insLen src
  let struct (tmp2, tmp1) = tmpVars2 bld 32<rt>
  bld <+ (tmp1 := AST.xtlo 32<rt> src)
  bld <+ (tmp2 := AST.xthi 32<rt> src)
  bld <+ (AST.xtlo 32<rt> dst := AST.cast CastKind.SIntToFloat 32<rt> tmp1)
  bld <+ (AST.xthi 32<rt> dst := AST.cast CastKind.SIntToFloat 32<rt> tmp2)
  bld --!> insLen

let cvtdq2pd (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let struct (dst2, dst1) = transOprToExpr128 bld false ins insLen dst
  let src = transOprToExpr64 bld false ins insLen src
  let struct (tmp1, tmp2) = tmpVars2 bld 32<rt>
  bld <+ (tmp1 := AST.xtlo 32<rt> src)
  bld <+ (tmp2 := AST.xthi 32<rt> src)
  bld <+ (dst1 := AST.cast CastKind.SIntToFloat 64<rt> tmp1)
  bld <+ (dst2 := AST.cast CastKind.SIntToFloat 64<rt> tmp2)
  bld --!> insLen

let cvtpi2pd ins insLen bld = cvtdq2pd ins insLen bld

let cvtsi2ss (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr64 bld false ins insLen dst
  let src = transOprToExpr bld false ins insLen src
  bld <+ (AST.xtlo 32<rt> dst := AST.cast CastKind.SIntToFloat 32<rt> src)
  bld --!> insLen

let cvtsi2sd (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr64 bld false ins insLen dst
  let src = transOprToExpr bld false ins insLen src
  bld <+ (dst := AST.cast CastKind.SIntToFloat 64<rt> src)
  bld --!> insLen

let cvtps2pi (ins: InsInfo) insLen bld rounded =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr bld false ins insLen dst
  let src = transOprToExpr64 bld false ins insLen src
  let struct (tmp1, tmp2) = tmpVars2 bld 32<rt>
  let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
  bld <+ (tmp1 := AST.xtlo 32<rt> src)
  bld <+ (tmp2 := AST.xthi 32<rt> src)
  bld <+ (AST.xtlo 32<rt> dst := AST.cast castKind 32<rt> tmp1)
  bld <+ (AST.xthi 32<rt> dst := AST.cast castKind 32<rt> tmp2)
  fillOnesToMMXHigh16 bld ins
  bld --!> insLen

let cvtps2pd (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let struct (dst2, dst1) = transOprToExpr128 bld false ins insLen dst
  let src = transOprToExpr64 bld false ins insLen src
  let struct (tmp1, tmp2) = tmpVars2 bld 32<rt>
  bld <+ (tmp1 := AST.xtlo 32<rt> src)
  bld <+ (tmp2 := AST.xthi 32<rt> src)
  bld <+ (dst1 := AST.cast CastKind.FloatCast 64<rt> tmp1)
  bld <+ (dst2 := AST.cast CastKind.FloatCast 64<rt> tmp2)
  bld --!> insLen

let cvtpd2ps (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let struct (dst2, dst1) = transOprToExpr128 bld false ins insLen dst
  let struct (src2, src1) = transOprToExpr128 bld false ins insLen src
  bld <+ (AST.xtlo 32<rt> dst1 := AST.cast CastKind.FloatCast 32<rt> src1)
  bld <+ (AST.xthi 32<rt> dst1 := AST.cast CastKind.FloatCast 32<rt> src2)
  bld <+ (dst2 := AST.num0 64<rt>)
  bld --!> insLen

let cvtpd2pi (ins: InsInfo) insLen bld rounded =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr bld false ins insLen dst
  let struct (src2, src1) = transOprToExpr128 bld false ins insLen src
  let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
  bld <+ (AST.xtlo 32<rt> dst := AST.cast castKind 32<rt> src1)
  bld <+ (AST.xthi 32<rt> dst := AST.cast castKind 32<rt> src2)
  fillOnesToMMXHigh16 bld ins
  bld --!> insLen

let cvtpd2dq (ins: InsInfo) insLen bld rounded =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let struct (dst2, dst1) = transOprToExpr128 bld false ins insLen dst
  let struct (src2, src1) = transOprToExpr128 bld false ins insLen src
  let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
  bld <+ (AST.xtlo 32<rt> dst1 := AST.cast castKind 32<rt> src1)
  bld <+ (AST.xthi 32<rt> dst1 := AST.cast castKind 32<rt> src2)
  bld <+ (dst2 := AST.num0 64<rt>)
  bld --!> insLen

let cvtdq2ps (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let struct (dst2, dst1) = transOprToExpr128 bld false ins insLen dst
  let struct (src2, src1) = transOprToExpr128 bld false ins insLen src
  let struct (tmp1, tmp2, tmp3, tmp4) = tmpVars4 bld 32<rt>
  bld <+ (tmp1 := AST.xtlo 32<rt> src1)
  bld <+ (tmp2 := AST.xthi 32<rt> src1)
  bld <+ (tmp3 := AST.xtlo 32<rt> src2)
  bld <+ (tmp4 := AST.xthi 32<rt> src2)
  bld <+ (AST.xtlo 32<rt> dst1 := AST.cast CastKind.SIntToFloat 32<rt> tmp1)
  bld <+ (AST.xthi 32<rt> dst1 := AST.cast CastKind.SIntToFloat 32<rt> tmp2)
  bld <+ (AST.xtlo 32<rt> dst2 := AST.cast CastKind.SIntToFloat 32<rt> tmp3)
  bld <+ (AST.xthi 32<rt> dst2 := AST.cast CastKind.SIntToFloat 32<rt> tmp4)
  bld --!> insLen

let cvtps2dq (ins: InsInfo) insLen bld rounded =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let struct (dst2, dst1) = transOprToExpr128 bld false ins insLen dst
  let struct (src2, src1) = transOprToExpr128 bld false ins insLen src
  let struct (tmp1, tmp2, tmp3, tmp4) = tmpVars4 bld 32<rt>
  let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
  bld <+ (tmp1 := AST.xtlo 32<rt> src1)
  bld <+ (tmp2 := AST.xthi 32<rt> src1)
  bld <+ (tmp3 := AST.xtlo 32<rt> src2)
  bld <+ (tmp4 := AST.xthi 32<rt> src2)
  bld <+ (AST.xtlo 32<rt> dst1 := AST.cast castKind 32<rt> tmp1)
  bld <+ (AST.xthi 32<rt> dst1 := AST.cast castKind 32<rt> tmp2)
  bld <+ (AST.xtlo 32<rt> dst2 := AST.cast castKind 32<rt> tmp3)
  bld <+ (AST.xthi 32<rt> dst2 := AST.cast castKind 32<rt> tmp4)
  bld --!> insLen

let cvtss2si (ins: InsInfo) insLen bld rounded =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr bld false ins insLen dst
  let src = transOprToExpr32 bld false ins insLen src
  let tmp = tmpVar bld 32<rt>
  let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
  if is64bit bld && oprSize = 64<rt> then
    bld <+ (dst := AST.cast castKind 64<rt> src)
  else
    bld <+ (tmp := AST.cast castKind 32<rt> src)
    bld <+ (dstAssign 32<rt> dst tmp)
  bld --!> insLen

let cvtss2sd (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr64 bld false ins insLen dst
  let src = transOprToExpr32 bld false ins insLen src
  bld <+ (dst := AST.cast CastKind.FloatCast 64<rt> src)
  bld --!> insLen

let cvtsd2ss (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr64 bld false ins insLen dst
  let src = transOprToExpr64 bld false ins insLen src
  bld <+ (AST.xtlo 32<rt> dst := AST.cast CastKind.FloatCast 32<rt> src)
  bld --!> insLen

let cvtsd2si (ins: InsInfo) insLen bld rounded =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr bld false ins insLen dst
  let src = transOprToExpr64 bld false ins insLen src
  let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
  let tmp = tmpVar bld 32<rt>
  if is64bit bld && oprSize = 64<rt> then
    bld <+ (dst := AST.cast castKind 64<rt> src)
  else
    bld <+ (tmp := AST.cast castKind 32<rt> src)
    bld <+ (dstAssign 32<rt> dst tmp)
  bld --!> insLen

let extractps (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let struct (dst, src, imm8) = getThreeOprs ins
  let dst = transOprToExpr bld false ins insLen dst
  let src = transOprToArr bld false ins insLen 32<rt> 2 128<rt> src
  let idx = getImmValue imm8 &&& 0b11L |> int
  bld <+ (dstAssign oprSize dst src[idx])
  bld --!> insLen

let hsubpd ins insLen bld =
  packedHorizon ins insLen bld 64<rt> (opP AST.fsub)

let hsubps ins insLen bld =
  packedHorizon ins insLen bld 32<rt> (opP AST.fsub)

let haddpd ins insLen bld =
  packedHorizon ins insLen bld 64<rt> (opP AST.fadd)

let haddps ins insLen bld =
  packedHorizon ins insLen bld 32<rt> (opP AST.fadd)

let ldmxcsr (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let src = transOneOpr bld ins insLen
  bld <+ (regVar bld R.MXCSR := src)
  bld --!> insLen

let stmxcsr (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let dst = transOneOpr bld ins insLen
  bld <+ (dst := regVar bld R.MXCSR)
  bld --!> insLen

let private opAveragePackedInt (packSz: int<rt>) =
  let dblSz = packSz * 2
  let dblExt expr = AST.zext dblSz expr
  let avg e1 e2 =
    AST.extract (dblExt e1 .+ dblExt e2 .+ AST.num1 dblSz) packSz 1
  Array.map2 avg

let opPavgb _ = opAveragePackedInt 8<rt>

let pavgb ins insLen bld =
  buildPackedInstr ins insLen bld false 8<rt> opPavgb

let opPavgw _ = opAveragePackedInt 16<rt>

let pavgw ins insLen bld =
  buildPackedInstr ins insLen bld false 16<rt> opPavgw

let pextrb (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src, count) = getThreeOprs ins
  let count = getImmValue count
  let dExpr = transOprToExpr bld false ins insLen dst
  let struct (srcB, srcA) = transOprToExpr128 bld false ins insLen src
  let count = (count &&& 0b1111) (* COUNT[3:0] *) * 8L
  let lAmt = numI64 (64L - (count % 64L)) 64<rt> (* Left Shift *)
  let rAmt = numI64 (count % 64L) 64<rt> (* Right Shift *)
  let result =
    if count < 64 then ((srcB << lAmt) .| (srcA >> rAmt)) .& numU32 0xFFu 64<rt>
    else (srcB >> rAmt) .& numU32 0xFFu 64<rt>
    |> AST.xtlo 8<rt>
  match dst with
  | OprReg _ -> bld <+ (dstAssign 32<rt> dExpr (AST.zext 32<rt> result))
  | OprMem _ -> bld <+ (dExpr := result)
  | _ -> raise InvalidOperandException
  bld --!> insLen

let pextrd (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src, count) = getThreeOprs ins
  let dst = transOprToExpr bld false ins insLen dst
  let count = getImmValue count
  let oprSize = getOperationSize ins
  match src with
  | OprReg reg ->
    let struct (srcB, srcA) = pseudoRegVar128 bld reg
    let count = (count &&& 0b11) (* COUNT[1:0] *) * 32L
    let lAmt = numI64 (64L - (count % 64L)) 64<rt> (* Left Shift *)
    let rAmt = numI64 (count % 64L) 64<rt> (* Right Shift *)
    let result =
      if count < 64 then
        ((srcB << lAmt) .| (srcA >> rAmt)) .& numU32 0xFFFFFFFFu 64<rt>
      else (srcB >> rAmt) .& numU32 0xFFFFFFFFu 64<rt>
    bld <+ (dstAssign oprSize dst (AST.xtlo oprSize result))
  | _ -> raise InvalidOperandException
  bld --!> insLen

let pextrq (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src, count) = getThreeOprs ins
  let dst = transOprToExpr bld false ins insLen dst
  let count = getImmValue count
  let oprSize = getOperationSize ins
  match src with
  | OprReg reg ->
    let struct (srcB, srcA) = pseudoRegVar128 bld reg
    let count = (count &&& 0b1) (* COUNT[0] *) * 64L
    let lAmt = numI64 (64L - (count % 64L)) 64<rt> (* Left Shift *)
    let rAmt = numI64 (count % 64L) 64<rt> (* Right Shift *)
    let result =
      if count < 64 then
        ((srcB << lAmt) .| (srcA >> rAmt))
      else (srcB >> rAmt)
    bld <+ (dstAssign oprSize dst (AST.xtlo oprSize result))
  | _ -> raise InvalidOperandException
  bld --!> insLen

let pextrw ins insLen bld =
  let oprSize = getOperationSize ins
  bld <!-- (ins.Address, insLen)
  let struct (dst, src, imm8) = getThreeOprs ins
  let packNum = 64<rt> / 16<rt>
  let srcSz =
    match src with
    | OprReg reg -> Register.toRegType bld.WordSize reg
    | _ -> raise InvalidOperandException
  let d = transOprToExpr bld false ins insLen dst
  let src = transOprToArr bld false ins insLen 16<rt> packNum srcSz src
  let idx = getImmValue imm8 |> int
  match dst with
  | OprMem (_, _, _, 16<rt>) ->
    let idx = idx &&& 0b111
    bld <+ (d := src[idx])
  | _ ->
    let idx = idx &&& (Array.length src - 1)
    bld <+ (dstAssign oprSize d src[idx])
  bld --!> insLen

let pinsrw (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let packSz = 16<rt>
  let pNum = 64<rt> / packSz
  let struct (dst, src, imm8) = getThreeOprs ins
  let src = transOprToExpr bld false ins insLen src |> AST.xtlo packSz
  match dst with
  | OprReg reg ->
    match Register.getKind reg with
    | Register.Kind.MMX ->
      let index = getImmValue imm8 &&& 0b11 |> int
      let dst = transOprToArr bld false ins insLen packSz pNum 64<rt> dst
      bld <+ (dst[index] := src)
      fillOnesToMMXHigh16 bld ins
    | Register.Kind.XMM ->
      let index = getImmValue imm8 &&& 0b111 |> int
      let dst = transOprToArr bld false ins insLen packSz pNum 128<rt> dst
      bld <+ (dst[index] := src)
    | _ -> raise InvalidOperandException
  | _ -> raise InvalidOperandSizeException
  bld --!> insLen

let private opMaxMinPacked cmp =
  Array.map2 (fun e1 e2 -> AST.ite (cmp e1 e2) e1 e2)

let opPmaxu _ = opMaxMinPacked AST.gt

let opPminu _ = opMaxMinPacked AST.lt

let opPmaxs _ = opMaxMinPacked AST.sgt

let opPmins _ = opMaxMinPacked AST.slt

let pmaxub ins insLen bld =
  buildPackedInstr ins insLen bld false 8<rt> opPmaxu

let pmaxud ins insLen bld =
  buildPackedInstr ins insLen bld false 32<rt> opPmaxu

let pmaxuw ins insLen bld =
  buildPackedInstr ins insLen bld false 16<rt> opPmaxu

let pmaxsb ins insLen bld =
  buildPackedInstr ins insLen bld false 8<rt> opPmaxs

let pmaxsd ins insLen bld =
  buildPackedInstr ins insLen bld false 32<rt> opPmaxs

let pmaxsw ins insLen bld =
  buildPackedInstr ins insLen bld false 16<rt> opPmaxs

let pminub ins insLen bld =
  buildPackedInstr ins insLen bld false 8<rt> opPminu

let pminud ins insLen bld =
  buildPackedInstr ins insLen bld false 32<rt> opPminu

let pminuw ins insLen bld =
  buildPackedInstr ins insLen bld false 16<rt> opPminu

let pminsb ins insLen bld =
  buildPackedInstr ins insLen bld false 8<rt> opPmins

let pminsd ins insLen bld =
  buildPackedInstr ins insLen bld false 32<rt> opPmins

let pminsw ins insLen bld =
  buildPackedInstr ins insLen bld false 16<rt> opPmins

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

let pmovmskb (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let struct (dst, src) = getTwoOprs ins
  let r = match src with | OprReg r -> r | _ -> raise InvalidOperandException
  match Register.getKind r with
  | Register.Kind.MMX ->
    let struct (dst, src) = transTwoOprs bld false ins insLen
    let srcSize = TypeCheck.typeOf src
    let cnt = RegType.toByteWidth srcSize
    let tmps = mskArrayInit cnt src
    bld <+ (dstAssign oprSize dst <| AST.zext oprSize (concatBits tmps))
  | Register.Kind.XMM ->
    let dst = transOprToExpr bld false ins insLen dst
    let struct (srcB, srcA) = transOprToExpr128 bld false ins insLen src
    let srcSize = TypeCheck.typeOf srcA
    let cnt = RegType.toByteWidth srcSize
    let tmpsA = mskArrayInit cnt srcA
    let tmpsB = mskArrayInit cnt srcB
    let tmps = AST.concat (concatBits tmpsB) (concatBits tmpsA)
    bld <+ (dstAssign oprSize dst <| AST.zext oprSize tmps)
  | Register.Kind.YMM ->
    let dst = transOprToExpr bld false ins insLen dst
    let struct (srcD, srcC, srcB, srcA) =
      transOprToExpr256 bld false ins insLen src
    let srcSize = TypeCheck.typeOf srcA
    let cnt = RegType.toByteWidth srcSize
    let tmpsA = mskArrayInit cnt srcA
    let tmpsB = mskArrayInit cnt srcB
    let tmpsC = mskArrayInit cnt srcC
    let tmpsD = mskArrayInit cnt srcD
    let tmps =
      AST.concat (AST.concat (concatBits tmpsD) (concatBits tmpsC))
        (AST.concat (concatBits tmpsB) (concatBits tmpsA))
    bld <+ (dstAssign oprSize dst <| AST.zext oprSize tmps)
  | _ -> raise InvalidOperandException
  bld --!> insLen

let packedMove bld srcSz packSz dstA dstB src isSignExt =
  let packNum = int (srcSz / packSz)
  let dSz = 128<rt> / packNum
  let tDst = Array.init packNum (fun _ -> tmpVar bld dSz)
  if isSignExt then
    for i in 0 .. packNum - 1 do
      bld
      <+ (tDst[i] := AST.sext dSz (AST.extract src packSz (i * (int packSz))))
  else
    for i in 0 .. packNum - 1 do
      bld
      <+ (tDst[i] := AST.zext dSz (AST.extract src packSz (i * (int packSz))))
  let tDstA, tDstB = tDst |> Array.splitAt (packNum / 2)
  bld <+ (dstA := tDstA |> AST.revConcat)
  bld <+ (dstB := tDstB |> AST.revConcat)

let pmovbw (ins: InsInfo) insLen bld packSz isSignExt =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  match src with
  | OprReg _ ->
    let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
    let struct (_, srcA) = transOprToExpr128 bld false ins insLen src
    packedMove bld 64<rt> packSz dstA dstB srcA isSignExt
  | OprMem _ ->
    let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
    let src = transOprToExpr64 bld false ins insLen src
    packedMove bld 64<rt> packSz dstA dstB src isSignExt
  | _ -> raise InvalidOperandException
  bld --!> insLen

let pmovbd (ins: InsInfo) insLen bld packSz isSignExt =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  match src with
  | OprReg _ ->
    let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
    let struct (_, srcA) = transOprToExpr128 bld false ins insLen src
    packedMove bld 32<rt> packSz dstA dstB (AST.xtlo 32<rt> srcA) isSignExt
  | OprMem _ ->
    let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
    let src = transOprToExpr32 bld false ins insLen src
    packedMove bld 32<rt> packSz dstA dstB src isSignExt
  | _ -> raise InvalidOperandException
  bld --!> insLen

let pmovbq (ins: InsInfo) insLen bld packSz isSignExt =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  match src with
  | OprReg _ ->
    let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
    let struct (_, srcA) = transOprToExpr128 bld false ins insLen src
    packedMove bld 16<rt> packSz dstA dstB (AST.xtlo 16<rt> srcA) isSignExt
  | OprMem _ ->
    let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
    let src = transOprToExpr16 bld false ins insLen src
    packedMove bld 16<rt> packSz dstA dstB src isSignExt
  | _ -> raise InvalidOperandException
  bld --!> insLen

let private opPmulhuw _ = opPmul AST.xthi AST.zext 32<rt> 16<rt>

let pmulhuw ins insLen bld =
  buildPackedInstr ins insLen bld false 16<rt> opPmulhuw

let private opPmulld _ = opPmul AST.xtlo AST.sext 32<rt> 32<rt>

let pmulld ins insLen bld =
  buildPackedInstr ins insLen bld false 32<rt> opPmulld

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

let psadbw (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let sPackSz = 8<rt> (* SRC Pack size *)
  let sPackNum = 64<rt> / sPackSz
  let dPackSz = 16<rt> (* DST Pack size *)
  let dPackNum = 64<rt> / dPackSz
  let struct (dst, src) = getTwoOprs ins
  let src1 = transOprToArr bld true ins insLen sPackSz sPackNum oprSize dst
  let src2 = transOprToArr bld true ins insLen sPackSz sPackNum oprSize src
  let result = opPsadbw oprSize src1 src2
  assignPackedInstr bld false ins insLen dPackNum oprSize dst result
  bld --!> insLen

let pshufw (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src, ord) = transThreeOprs bld false ins insLen
  let oprSize = getOperationSize ins
  let cnt = RegType.toBitWidth oprSize / 16
  let tmps = Array.init cnt (fun _ -> tmpVar bld 16<rt>)
  let n16 = numI32 16 oprSize
  let mask2 = numI32 3 16<rt> (* 2-bit mask *)
  for i in 1 .. cnt do
    let order =
      ((AST.xtlo 16<rt> ord) >> (numI32 ((i - 1) * 2) 16<rt>)) .& mask2
    let order' = AST.zext oprSize order
    bld <+ (tmps[i - 1] := AST.xtlo 16<rt> (src >> (order' .* n16)))
  done
  bld <+ (dst := AST.revConcat tmps)
  fillOnesToMMXHigh16 bld ins
  bld --!> insLen

let pshufd (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src, ord) = getThreeOprs ins
  let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
  let struct (srcB, srcA) = transOprToExpr128 bld false ins insLen src
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
  let struct (tSrcB, tSrcA) = tmpVars2 bld 64<rt>
  bld <+ (tSrcA := srcA)
  bld <+ (tSrcB := srcB)
  let src amtIdx = rShiftTo64 tSrcB tSrcA (amount amtIdx)
  bld <+ (dstA := AST.concat (src 1) (src 0))
  bld <+ (dstB := AST.concat (src 3) (src 2))
  bld --!> insLen

let pshuflw (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src, imm) = getThreeOprs ins
  let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
  let struct (srcB, srcA) = transOprToExpr128 bld false ins insLen src
  let imm = numI64 (getImmValue imm) 64<rt>
  let tmps = Array.init 4 (fun _ -> tmpVar bld 16<rt>)
  let n16 = numI32 16 64<rt>
  let mask2 = numI32 3 64<rt> (* 2-bit mask *)
  for i in 1 .. 4 do
    let imm =
      (imm >> (numI32 ((i - 1) * 2) 64<rt>)) .& mask2
    bld <+ (tmps[i - 1] := AST.xtlo 16<rt> (srcA >> (imm .* n16)))
  done
  bld <+ (dstA := AST.revConcat tmps)
  bld <+ (dstB := srcB)
  bld --!> insLen

let pshufhw (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src, imm) = getThreeOprs ins
  let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
  let struct (srcB, srcA) = transOprToExpr128 bld false ins insLen src
  let imm = numI64 (getImmValue imm) 64<rt>
  let tmps = Array.init 4 (fun _ -> tmpVar bld 16<rt>)
  let n16 = numI32 16 64<rt>
  let mask2 = numI32 3 64<rt> (* 2-bit mask *)
  for i in 1 .. 4 do
    let imm =
      (imm >> (numI32 ((i - 1) * 2) 64<rt>)) .& mask2
    bld <+ (tmps[i - 1] := AST.xtlo 16<rt> (srcB >> (imm .* n16)))
  done
  bld <+ (dstA := srcA)
  bld <+ (dstB := AST.revConcat tmps)
  bld --!> insLen

let pshufb (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let packSize = 8<rt>
  let packNum = 64<rt> / packSize
  let allPackNum = oprSize / packSize
  let struct (dst, src) = getTwoOprs ins
  let src = transOprToArr bld false ins insLen packSize packNum oprSize src
  let struct (mask, n0) = tmpVars2 bld packSize
  bld <+ (mask := numI32 (int allPackNum - 1) packSize)
  bld <+ (n0 := AST.num0 packSize)
  match oprSize with
  | 64<rt> ->
    let dst = transOprToExpr bld false ins insLen dst
    let n8 = numI32 8 oprSize
    let shuffle src =
      let idx = src .& mask
      let numShift = AST.zext oprSize idx .* n8
      AST.ite (AST.xthi 1<rt> src) n0 (AST.xtlo packSize (dst >> numShift))
    bld <+ (dst := Array.map shuffle src |> AST.revConcat)
    fillOnesToMMXHigh16 bld ins
  | 128<rt> ->
    let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
    let n8 = tmpVar bld 64<rt>
    bld <+ (n8 := numI32 8 64<rt>)
    let shuffle src =
      let idx = src .& mask
      let numShift = ((AST.zext 64<rt> idx) .% n8) .* n8
      let tDst = tmpVar bld 64<rt>
      bld <+ (tDst := AST.ite (idx .< numI32 8 packSize) dstA dstB)
      AST.ite (AST.xthi 1<rt> src) n0 (AST.xtlo packSize (tDst >> numShift))
    let result = Array.map shuffle src
    bld <+ (dstA := Array.sub result 0 packNum |> AST.revConcat)
    bld <+ (dstB := Array.sub result packNum packNum |> AST.revConcat)
  | _ -> raise InvalidOperandSizeException
  bld --!> insLen

let movdqa ins insLen bld =
  buildMove ins insLen bld

let movdqu ins insLen bld =
  buildMove ins insLen bld

let movq2dq (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
  let src = transOprToExpr bld false ins insLen src
  bld <+ (dstA := src)
  bld <+ (dstB := AST.num0 64<rt>)
  bld --!> insLen

let movdq2q (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr bld false ins insLen dst
  let struct (_, srcA) = transOprToExpr128 bld false ins insLen src
  bld <+ (dst := srcA)
  fillOnesToMMXHigh16 bld ins
  bld --!> insLen

let private opPmuludq _ =
  let low32 expr = expr .& numI64 0xffffffffL 64<rt>
  Array.map2 (fun e1 e2 -> low32 e1 .* low32 e2)

let pmuludq ins insLen bld =
  buildPackedInstr ins insLen bld false 64<rt> opPmuludq

let paddq ins insLen bld =
  buildPackedInstr ins insLen bld false 64<rt> (opP (.+))

let psubq ins insLen bld =
  buildPackedInstr ins insLen bld false 64<rt> (opP (.-))

let pslldq (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, cnt) = getTwoOprs ins
  let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
  let cnt = getImmValue cnt
  let amount = if cnt > 15L then 16L * 8L else cnt * 8L
  let rightAmt = numI64 (64L - (amount % 64L)) 64<rt>
  let leftAmt = numI64 (amount % 64L) 64<rt>
  let struct (tDstB, tDstA) = tmpVars2 bld 64<rt>
  bld <+ (tDstA := dstA)
  bld <+ (tDstB := dstB)
  if amount < 64 then
    bld <+ (dstA := tDstA << leftAmt)
    bld <+ (dstB := (tDstB << leftAmt) .| (tDstA >> rightAmt))
  elif amount < 128 then
    bld <+ (dstA := AST.num0 64<rt>)
    bld <+ (dstB := tDstA << leftAmt)
  else
    bld <+ (dstA := AST.num0 64<rt>)
    bld <+ (dstB := AST.num0 64<rt>)
  bld --!> insLen

let psrldq (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, cnt) = getTwoOprs ins
  let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
  let cnt = getImmValue cnt
  let amount = if cnt > 15L then 16L * 8L else cnt * 8L
  let rightAmt = numI64 (amount % 64L) 64<rt>
  let leftAmt = numI64 (64L - (amount % 64L)) 64<rt>
  let struct (tDstB, tDstA) = tmpVars2 bld 64<rt>
  bld <+ (tDstA := dstA)
  bld <+ (tDstB := dstB)
  if amount < 64 then
    bld <+ (dstA := (tDstB << leftAmt) .| (tDstA >> rightAmt))
    bld <+ (dstB := tDstB >> rightAmt)
  elif amount < 128 then
    bld <+ (dstA := tDstB >> rightAmt)
    bld <+ (dstB := AST.num0 64<rt>)
  else
    bld <+ (dstA := AST.num0 64<rt>)
    bld <+ (dstB := AST.num0 64<rt>)
  bld --!> insLen

let punpckhqdq ins insLen bld =
  buildPackedInstr ins insLen bld false 64<rt> opUnpackHighData

let punpcklqdq ins insLen bld =
  buildPackedInstr ins insLen bld false 64<rt> opUnpackLowData

let movntq ins insLen bld = buildMove ins insLen bld

let movntps ins insLen bld = buildMove ins insLen bld

let movntpd ins insLen bld = buildMove ins insLen bld

let movntdq ins insLen bld = buildMove ins insLen bld

let movnti ins insLen bld = buildMove ins insLen bld

let lddqu ins insLen bld = buildMove ins insLen bld

let movshdup (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let struct (dst2, dst1) = transOprToExpr128 bld false ins insLen dst
  let struct (src2, src1) = transOprToExpr128 bld false ins insLen src
  let struct (tmp1, tmp2) = tmpVars2 bld 32<rt>
  bld <+ (tmp1 := AST.xthi 32<rt> src1)
  bld <+ (tmp2 := AST.xthi 32<rt> src2)
  bld <+ (AST.xtlo 32<rt> dst1 := tmp1)
  bld <+ (AST.xthi 32<rt> dst1 := tmp1)
  bld <+ (AST.xtlo 32<rt> dst2 := tmp2)
  bld <+ (AST.xthi 32<rt> dst2 := tmp2)
  bld --!> insLen

let movsldup (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let struct (dst2, dst1) = transOprToExpr128 bld false ins insLen dst
  let struct (src2, src1) = transOprToExpr128 bld false ins insLen src
  let struct (tmp1, tmp2) = tmpVars2 bld 32<rt>
  bld <+ (tmp1 := AST.xtlo 32<rt> src1)
  bld <+ (tmp2 := AST.xtlo 32<rt> src2)
  bld <+ (AST.xtlo 32<rt> dst1 := tmp1)
  bld <+ (AST.xthi 32<rt> dst1 := tmp1)
  bld <+ (AST.xtlo 32<rt> dst2 := tmp2)
  bld <+ (AST.xthi 32<rt> dst2 := tmp2)
  bld --!> insLen

let movddup (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let struct (dst1, dst0) = transOprToExpr128 bld false ins insLen dst
  let src = transOprToExpr64 bld false ins insLen src
  bld <+ (dst0 := src)
  bld <+ (dst1 := src)
  bld --!> insLen

let packWithSaturation bld packSz src =
  let z16 = AST.num0 (packSz / 2)
  let z32 = AST.num0 packSz
  let f16 = numU32 0xFFFFu (packSz / 2)
  let f32 = numU32 0xFFFFu packSz
  let tSrc = tmpVar bld packSz
  let tmp = tmpVar bld (packSz / 2)
  bld <+ (tSrc := src)
  bld <+ (tmp := AST.ite (tSrc ?< z32) z16 (AST.xtlo (packSz / 2) tSrc))
  bld <+ (tmp := AST.ite (tSrc ?> f32) f16 tmp)
  tmp

let packusdw (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / 32<rt>
  let struct (dst, src) = getTwoOprs ins
  let src1 = transOprToArr bld true ins insLen 32<rt> packNum oprSize dst
  let src2 = transOprToArr bld true ins insLen 32<rt> packNum oprSize src
  let src = Array.append src1 src2
  let result = Array.map (packWithSaturation bld 32<rt>) src
  assignPackedInstr bld false ins insLen (packNum * 2) oprSize dst result
  bld --!> insLen

let palignr (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src, imm) = getThreeOprs ins
  let imm8 = getImmValue imm
  let amount = imm8 * 8L
  let rightAmt = numI64 (amount % 64L) 64<rt>
  let leftAmt = numI64 (64L - (amount % 64L)) 64<rt>
  match getOperationSize ins with
  | 64<rt> ->
    let dst = transOprToExpr bld false ins insLen dst
    let src = transOprToExpr bld false ins insLen src
    let struct (tDst, tSrc) = tmpVars2 bld 64<rt>
    bld <+ (tDst := dst)
    bld <+ (tSrc := src)
    if amount < 64 then bld <+ (dst := (tDst << leftAmt) .| (tSrc >> rightAmt))
    elif amount < 128 then bld <+ (dst := tDst >> rightAmt)
    else bld <+ (dst := AST.num0 64<rt>)
    fillOnesToMMXHigh16 bld ins
  | 128<rt> ->
    let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
    let struct (srcB, srcA) = transOprToExpr128 bld false ins insLen src
    let struct (tDstB, tDstA, tSrcB, tSrcA) = tmpVars4 bld 64<rt>
    bld <+ (tDstA := dstA)
    bld <+ (tDstB := dstB)
    bld <+ (tSrcA := srcA)
    bld <+ (tSrcB := srcB)
    if amount < 64 then
      bld <+ (dstA := (tSrcB << leftAmt) .| (tSrcA >> rightAmt))
      bld <+ (dstB := (tDstA << leftAmt) .| (tSrcB >> rightAmt))
    elif amount < 128 then
      bld <+ (dstA := (tDstA << leftAmt) .| (tSrcB >> rightAmt))
      bld <+ (dstB := (tDstB << leftAmt) .| (tDstA >> rightAmt))
    elif amount < 192 then
      bld <+ (dstA := (tDstB << leftAmt) .| (tDstA >> rightAmt))
      bld <+ (dstB := tDstB >> rightAmt)
    elif amount < 256 then
      bld <+ (dstA := tDstB >> rightAmt)
      bld <+ (dstB := AST.num0 64<rt>)
    else
      bld <+ (dstA := AST.num0 64<rt>)
      bld <+ (dstB := AST.num0 64<rt>)
  | _ -> raise InvalidOperandSizeException
  bld --!> insLen

let roundsd (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src, imm) = getThreeOprs ins
  let dst = transOprToExpr64 bld false ins insLen dst
  let src = transOprToExpr64 bld false ins insLen src
  let imm = transOprToExpr bld false ins insLen imm
  let rc = (AST.extract (regVar bld R.MXCSR) 8<rt> 13) .& (numI32 0b11 8<rt>)
  let tmp = tmpVar bld 8<rt>
  let cster castKind = AST.cast castKind 64<rt> src
  let imm2 = (AST.xtlo 8<rt> imm) .& (numI32 0b11 8<rt>)
  bld <+ (tmp := AST.ite (AST.extract imm 1<rt> 2) rc imm2)
  bld <+ (dst := AST.ite (tmp == AST.num0 8<rt>) (cster CastKind.FtoFRound) dst)
  bld <+ (dst := AST.ite (tmp == AST.num1 8<rt>) (cster CastKind.FtoFFloor) dst)
  bld <+ (dst := AST.ite (tmp == numI32 2 8<rt>) (cster CastKind.FtoFCeil) dst)
  bld <+ (dst := AST.ite (tmp == numI32 3 8<rt>) (cster CastKind.FtoFTrunc) dst)
  bld --!> insLen

let pinsrb (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src, count) = getThreeOprs ins
  let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
  let src = transOprToExpr bld false ins insLen src
  let sel = getImmValue count &&& 0b1111L (* COUNT[3:0] *)
  let mask = numI64 (0xFFL <<< ((int32 sel * 8) % 64)) 64<rt>
  let amount = sel * 8L
  let t = tmpVar bld 64<rt>
  let expAmt = numI64 (amount % 64L) 64<rt>
  bld <+ (t := ((AST.zext 64<rt> (AST.xtlo 8<rt> src)) << expAmt) .& mask)
  if amount < 64 then bld <+ (dstA := (dstA .& (AST.not mask)) .| t)
  else bld <+ (dstB := (dstB .& (AST.not mask)) .| t)
  bld --!> insLen

let private packedSign bld packSz control inputVal =
  let n0 = AST.num0 packSz
  let struct (tControl, tInputVal) = tmpVars2 bld packSz
  let struct (cond1, cond2) = tmpVars2 bld 1<rt>
  bld <+ (tControl := control)
  bld <+ (tInputVal := inputVal)
  bld <+ (cond1 := tControl ?< n0)
  bld <+ (cond2 := tControl == n0)
  AST.ite cond1 (AST.neg tInputVal) (AST.ite cond2 n0 tInputVal)

let psign (ins: InsInfo) insLen bld packSz =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / packSz
  let struct (dst, src) = getTwoOprs ins
  let srcDst = transOprToArr bld true ins insLen packSz packNum oprSize dst
  let src = transOprToArr bld true ins insLen packSz packNum oprSize src
  let result = Array.map2 (packedSign bld packSz) src srcDst
  assignPackedInstr bld false ins insLen packNum oprSize dst result
  bld --!> insLen

let ptest (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (src1, src2) = getTwoOprs ins
  let struct (src1B, src1A) = transOprToExpr128 bld false ins insLen src1
  let struct (src2B, src2A) = transOprToExpr128 bld false ins insLen src2
  let struct (t1, t2, t3, t4) = tmpVars4 bld 64<rt>
  bld <+ (t1 := src2A .& src1A)
  bld <+ (t2 := src2B .& src1B)
  bld <+ (regVar bld R.ZF := (t1 .| t2) == (AST.num0 64<rt>))
  bld <+ (t3 := src2A .& AST.not src1A)
  bld <+ (t4 := src2B .& AST.not src1B)
  bld <+ (regVar bld R.CF := (t3 .| t4) == (AST.num0 64<rt>))
  bld <+ (regVar bld R.AF := AST.b0)
  bld <+ (regVar bld R.OF := AST.b0)
  bld <+ (regVar bld R.PF := AST.b0)
  bld <+ (regVar bld R.SF := AST.b0)
#if EMULATION
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen

let opPcmpeqq _ = opPcmp 64<rt> (==)

let pcmpeqq ins insLen bld =
  buildPackedInstr ins insLen bld false 64<rt> opPcmpeqq

let packedBlend src1 src2 imm =
  Array.mapi2 (fun i e1 e2 ->
    AST.ite (AST.extract imm 1<rt> (i % 8)) e1 e2) src1 src2

let packedVblend src1 src2 (mask: Expr []) =
  Array.mapi2 (fun i e1 e2 -> AST.ite (AST.xthi 1<rt> mask[i]) e1 e2) src1 src2

let blendpd (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src, imm) = getThreeOprs ins
  let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
  let struct (srcB, srcA) = transOprToExpr128 bld false ins insLen src
  let imm = transOprToExpr bld false ins insLen imm
  let cond1 = AST.extract imm 1<rt> 0
  let cond2 = AST.extract imm 1<rt> 1
  bld <+ (dstA := AST.ite cond1 srcA dstA)
  bld <+ (dstB := AST.ite cond2 srcB dstB)
  bld --!> insLen

let blendps (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / 32<rt>
  let struct (dst, src, imm) = getThreeOprs ins
  let src1 = transOprToArr bld true ins insLen 32<rt> packNum oprSize dst
  let src2 = transOprToArr bld true ins insLen 32<rt> packNum oprSize src
  let imm = transOprToExpr bld false ins insLen imm
  let result = packedBlend src2 src1 imm
  assignPackedInstr bld false ins insLen packNum oprSize dst result
  bld --!> insLen

let blendvpd (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src, xmm0) = getThreeOprs ins
  let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
  let struct (srcB, srcA) = transOprToExpr128 bld false ins insLen src
  let struct (xmm0B, xmm0A) = transOprToExpr128 bld false ins insLen xmm0
  let cond1 = AST.xthi 1<rt> xmm0A
  let cond2 = AST.xthi 1<rt> xmm0B
  bld <+ (dstA := AST.ite cond1 srcA dstA)
  bld <+ (dstB := AST.ite cond2 srcB dstB)
  bld --!> insLen

let blendvps (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / 32<rt>
  let struct (dst, src, xmm0) = getThreeOprs ins
  let src1 = transOprToArr bld true ins insLen 32<rt> packNum oprSize dst
  let src2 = transOprToArr bld true ins insLen 32<rt> packNum oprSize src
  let xmm0 = transOprToArr bld false ins insLen 32<rt> packNum oprSize xmm0
  let result = packedVblend src2 src1 xmm0
  assignPackedInstr bld false ins insLen packNum oprSize dst result
  bld --!> insLen

let pblendvb (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / 8<rt>
  let struct (dst, src, xmm0) = getThreeOprs ins
  let src1 = transOprToArr bld true ins insLen 8<rt> packNum oprSize dst
  let src2 = transOprToArr bld true ins insLen 8<rt> packNum oprSize src
  let xmm0 = transOprToArr bld false ins insLen 8<rt> packNum oprSize xmm0
  let result = packedVblend src2 src1 xmm0
  assignPackedInstr bld false ins insLen packNum oprSize dst result
  bld --!> insLen

let pblendw (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / 16<rt>
  let struct (dst, src, imm) = getThreeOprs ins
  let src1 = transOprToArr bld true ins insLen 16<rt> packNum oprSize dst
  let src2 = transOprToArr bld true ins insLen 16<rt> packNum oprSize src
  let imm = transOprToExpr bld false ins insLen imm
  let result = packedBlend src2 src1 imm
  assignPackedInstr bld false ins insLen packNum oprSize dst result
  bld --!> insLen

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
  let immByte =
    match imm with
    | Num (n, _) -> BitVector.GetValue n
    | _ -> raise InvalidExprException
  let agg =
    match (immByte >>> 2) &&& 3I with
    | v when v = 0I -> EqualAny
    | v when v = 1I -> Ranges
    | v when v = 2I -> EqualEach
    | v when v = 3I -> EqualOrdered
    | _ -> Terminator.impossible ()
  let pol =
    match (immByte >>> 4) &&& 3I with
    | v when v = 0I -> PosPolarity
    | v when v = 1I -> NegPolarity
    | v when v = 2I -> PosMasked
    | v when v = 3I -> NegMasked
    | _ -> Terminator.impossible ()
  let size, nElem = if immByte &&& 1I = 0I then 8<rt>, 16u else 16<rt>, 8u
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

let private setZFSFOfPCMPSTR bld ctrl src1 src2  =
  let inline checkIfElemIsNull exps =
    Array.map (fun e -> (e == AST.num0 ctrl.PackSize)) exps |> Array.reduce (.|)
  let inline checkIndexOutOfBounds reg =
    let abs = tmpVar bld 32<rt>
    let reg = regVar bld reg
    bld <+ (abs := AST.ite (AST.xthi 1<rt> reg) (AST.neg reg) reg)
    abs .< numU32 ctrl.NumElems 32<rt>
  match ctrl.Len with
  | Implicit ->
    bld <+ (regVar bld R.ZF := checkIfElemIsNull src2)
    bld <+ (regVar bld R.SF := checkIfElemIsNull src1)
  | Explicit ->
    bld <+ (regVar bld R.ZF := checkIndexOutOfBounds R.EDX)
    bld <+ (regVar bld R.SF := checkIndexOutOfBounds R.EAX)

let private combineBits outSz bitArr =
  Array.mapi (fun i b -> AST.zext outSz b << (numI32 i outSz)) bitArr
  |> Array.reduce (.|)

/// Least significant index.
let private leastSign bld expr sz max =
  let lblCont = label bld "Cont"
  let lblLoop = label bld "Loop"
  let lblEnd = label bld "End"
  let cond = tmpVar bld 1<rt>
  let cnt = tmpVar bld sz
  bld <+ (cnt := AST.num0 sz)
  bld <+ (AST.lmark lblLoop)
  let max = numI32 max sz
  let bit = (AST.xtlo 1<rt> (expr >> cnt)) .& AST.b1
  bld <+ (cond := (bit == AST.b0) .& (cnt .< max))
  bld <+ (AST.cjmp cond (AST.jmpDest lblCont) (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblCont)
  bld <+ (cnt := cnt .+ (AST.num1 sz))
  bld <+ (AST.jmp (AST.jmpDest lblLoop))
  bld <+ (AST.lmark lblEnd)
  cnt

/// Most significant index.
let private mostSign bld expr sz max =
  let lblCont = label bld "Cont"
  let lblLoop = label bld "Loop"
  let lblEnd = label bld "End"
  let cond = tmpVar bld 1<rt>
  let idx = tmpVar bld sz
  bld <+ (idx := numI32 (max - 1) sz)
  bld <+ (AST.lmark lblLoop)
  let n0 = AST.num0 sz
  let bit = (AST.xtlo 1<rt> (expr >> idx)) .& AST.b1
  bld <+ (cond := (bit == AST.b0) .& (idx .> n0))
  bld <+ (AST.cjmp cond (AST.jmpDest lblCont) (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblCont)
  bld <+ (idx := idx .- (AST.num1 sz))
  bld <+ (AST.jmp (AST.jmpDest lblLoop))
  bld <+ (AST.lmark lblEnd)
  idx

/// override comparisons for invalid characters.
let private overrideIfDataInvalid bld ctrl aInval bInval boolRes =
  match ctrl.Agg with
  | EqualAny | Ranges ->
    let cond = (AST.not aInval .& bInval) .| (aInval .& AST.not bInval) .|
               (aInval .& bInval)
    bld <+ (boolRes := AST.ite cond AST.b0 boolRes)
  | EqualEach ->
    let cond1 = (AST.not aInval .& bInval) .| (aInval .& AST.not bInval)
    let cond2 = aInval .& bInval
    bld <+ (boolRes := AST.ite cond1 AST.b0 (AST.ite cond2 AST.b1 boolRes))
  | EqualOrdered ->
    let cond1 = AST.not aInval .& bInval
    let cond2 = (aInval .& AST.not bInval) .| (aInval .& bInval)
    bld <+ (boolRes := AST.ite cond1 AST.b0 (AST.ite cond2 AST.b1 boolRes))

let pcmpstr (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (s1, s2, imm) = getThreeOprs ins
  let imm = transOprToExpr bld false ins insLen imm
  let ctrl = getPcmpstrInfo ins.Opcode imm
  let oprSz = getOperationSize ins
  let packSize = ctrl.PackSize
  let nElem = int ctrl.NumElems
  let elemSz = RegType.fromBitWidth nElem
  let upperBound = nElem - 1
  let pNum = 64<rt> / packSize
  let src1 = transOprToArr bld true ins insLen packSize pNum oprSz s1
  let src2 = transOprToArr bld true ins insLen packSize pNum oprSz s2
  let boolRes = Array2D.init nElem nElem (fun _ _ -> tmpVar bld 1<rt>)
  let n0 = AST.num0 packSize
  let regSize, ax, dx =
    if hasREXW ins.REXPrefix then 64<rt>, regVar bld R.RAX, regVar bld R.RDX
    else 32<rt>, regVar bld R.EAX, regVar bld R.EDX

  let struct (aInval, bInval) = tmpVars2 bld 1<rt>
  bld <+ (aInval := AST.b0)
  let (.<=), (.>=) =
    if ctrl.Sign = Signed then AST.sle, AST.sge else AST.le, AST.ge
  for i in 0 .. upperBound do
    bld <+ (bInval := AST.b0)
    (* invalidate characters after EOS. *)
    match ctrl.Len with
    | Implicit -> bld <+ (aInval := aInval .| (src1[i] == n0))
    | Explicit -> bld <+ (aInval := aInval .| (numI32 i regSize == ax))
    for j in 0 .. upperBound do
      (* compare all characters. *)
      if ctrl.Agg = Ranges then
        if i % 2 = 0 then bld <+ (boolRes[i, j] := src1[i] .<= src2[j])
        else bld <+ (boolRes[i, j] := src1[i] .>= src2[j])
      else bld <+ (boolRes[i, j] := src1[i] == src2[j])
      (* invalidate characters after EOS. *)
      match ctrl.Len with
      | Implicit -> bld <+ (bInval := bInval .| (src2[j] == n0))
      | Explicit -> bld <+ (bInval := bInval .| (numI32 j regSize == dx))
      overrideIfDataInvalid bld ctrl aInval bInval boolRes[i, j]
    done
  done

  let inline initIntRes initVal = Array.iter (fun r -> bld <+ (r := initVal))
  let intRes1 = Array.init nElem (fun _ -> tmpVar bld 1<rt>)
  let intRes2 = Array.init nElem (fun _ -> tmpVar bld 1<rt>)

  (* aggregate results. *)
  match ctrl.Agg with
  | EqualAny ->
    initIntRes AST.b0 intRes1
    for i in 0 .. upperBound do
      for j in 0 .. upperBound do
        bld <+ (intRes1[i] := intRes1[i] .| boolRes[j, i])
      done
    done
  | Ranges ->
    initIntRes AST.b0 intRes1
    for i in 0 .. upperBound do
      for j in 0 .. 2 .. upperBound do
        bld <+ (intRes1[i] := intRes1[i] .| (boolRes[j, i] .& boolRes[j + 1, i]))
      done
    done
  | EqualEach ->
    initIntRes AST.b0 intRes1
    for i in 0 .. upperBound do
      bld <+ (intRes1[i] := boolRes[i, i])
    done
  | EqualOrdered ->
    initIntRes AST.b1 intRes1
    let mutable k = 0
    for i in 0 .. upperBound do
      k <- i
      for j in 0 .. upperBound - i do
        bld <+ (intRes1[i] := intRes1[i] .& boolRes[j, k])
        k <- k + 1
      done
    done

  (* optionally negate results. *)
  initIntRes AST.b0 intRes2
  for i in 0 .. upperBound do
    match ctrl.Polarity with
    | PosPolarity | PosMasked -> bld <+ (intRes2[i] := intRes1[i])
    | NegPolarity (* 0b01 *) -> bld <+ (intRes2[i] := AST.not intRes1[i])
    | NegMasked (* 0b11 *) ->
      match ctrl.Len with
      | Implicit ->
        bld <+ (bInval := src2[i] == n0)
        bld <+ (intRes2[i] := AST.ite bInval intRes1[i] (AST.not intRes1[i]))
      | Explicit ->
        let not = AST.not intRes1[i]
        bld <+ (intRes2[i] := AST.ite (numI32 i regSize .>= dx) intRes1[i] not)
  done

  (* output. *)
  let iRes2 = tmpVar bld elemSz
  bld <+ (iRes2 := combineBits elemSz intRes2)
  match ctrl.Ret with
  | Mask ->
    let struct (dstB, dstA) = pseudoRegVar128 bld R.XMM0
    match ctrl.OutSelect with
    | Least (* Bit mask *) ->
      let res = tmpVar bld elemSz
      bld <+ (res := combineBits elemSz intRes2)
      bld <+ (dstA := AST.zext 64<rt> res)
      bld <+ (dstB := AST.num0 64<rt>)
    | Most (* Byte/word mask *) ->
      let nFF = numI32 (if ctrl.PackSize = 8<rt> then 0xFF else 0xFFFF) packSize
      let res = Array.init nElem (fun _ -> tmpVar bld packSize)
      for i in 0 .. upperBound do
        bld <+ (res[i] := AST.ite intRes2[i] nFF n0)
      done
      bld <+ (dstA := Array.sub res 0 pNum |> AST.revConcat)
      bld <+ (dstB := Array.sub res pNum pNum |> AST.revConcat)
  | Index ->
    let outSz, cx =
      if hasREXW ins.REXPrefix then 64<rt>, R.RCX else 32<rt>, R.ECX
    let cx = regVar bld cx
    let n0 = AST.num0 elemSz
    let idx =
      match ctrl.OutSelect with
      | Least -> leastSign bld iRes2 elemSz nElem
      | Most -> mostSign bld iRes2 elemSz nElem
      |> AST.zext 32<rt>
    let idx = AST.ite (iRes2 == n0) (numI32 nElem 32<rt>) idx
    bld <+ (dstAssign outSz cx idx)
  bld <+ (regVar bld R.CF := iRes2 != AST.num0 elemSz)
  setZFSFOfPCMPSTR bld ctrl src1 src2
  bld <+ (regVar bld R.OF := intRes2[0])
  bld <+ (regVar bld R.AF := AST.b0)
  bld <+ (regVar bld R.PF := AST.b0)
#if EMULATION
  bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  bld --!> insLen
