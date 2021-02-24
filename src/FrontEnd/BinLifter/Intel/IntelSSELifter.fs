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
open B2R2.FrontEnd.BinLifter.Intel
open B2R2.FrontEnd.BinLifter.Intel.Helper
open B2R2.FrontEnd.BinLifter.Intel.LiftingUtils
open B2R2.FrontEnd.BinLifter.Intel.MMXLifter

let buildMove ins insLen ctxt bufSize =
  let ir = IRBuilder (bufSize)
  let oprSize = getOperationSize ins
  !<ir insLen
  match oprSize with
  | 32<rt> | 64<rt> ->
    let struct (dst, src) = transTwoOprs ins insLen ctxt
    !!ir (dst := src)
  | 128<rt> | 256<rt> | 512<rt> ->
    let struct (dst, src) = getTwoOprs ins
    let dst = transOprToExprVec ins insLen ctxt dst
    let src = transOprToExprVec ins insLen ctxt src
    List.iter2 (fun d s -> !!ir (d := s)) dst src
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let movaps ins insLen ctxt = buildMove ins insLen ctxt 4

let movapd ins insLen ctxt = buildMove ins insLen ctxt 4

let movups ins insLen ctxt = buildMove ins insLen ctxt 4

let movupd ins insLen ctxt = buildMove ins insLen ctxt 4

let movhps ins insLen ctxt =
  let ir = IRBuilder (4)
  let struct (dst, src) = getTwoOprs ins
  !<ir insLen
  match dst, src with
  | OprMem (_, _, _, 64<rt>), OprReg r ->
    let dst = transOprToExpr ins insLen ctxt dst
    !!ir (dst := getPseudoRegVar ctxt r 2)
  | OprReg r, OprMem (_, _, _, 64<rt>)->
    let src = transOprToExpr ins insLen ctxt src
    !!ir (getPseudoRegVar ctxt r 2 := src)
  | _ -> raise InvalidOperandException
  !>ir insLen

let movhpd ins insLen ctxt =
  let ir = IRBuilder (4)
  let struct (dst, src) = getTwoOprs ins
  !<ir insLen
  match dst, src with
  | OprReg r, OprMem _ ->
    let src = transOprToExpr ins insLen ctxt src
    !!ir (getPseudoRegVar ctxt r 2 := src)
  | OprMem _, OprReg r ->
    let dst = transOprToExpr ins insLen ctxt dst
    !!ir (dst := getPseudoRegVar ctxt r 1)
  | _ -> raise InvalidOperandException
  !>ir insLen

let movhlps ins insLen ctxt =
  let ir = IRBuilder (4)
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr128 ins insLen ctxt dst |> snd
  let src = transOprToExpr128 ins insLen ctxt src |> fst
  !<ir insLen
  !!ir (dst := src)
  !>ir insLen

let movlpd ins insLen ctxt =
  let ir = IRBuilder (4)
  let struct (dst, src) = getTwoOprs ins
  !<ir insLen
  match dst, src with
  | OprReg r, OprMem _ ->
    let src = transOprToExpr ins insLen ctxt src
    !!ir (getPseudoRegVar ctxt r 1 := src)
  | OprMem _, OprReg r ->
    let dst = transOprToExpr ins insLen ctxt dst
    !!ir (dst := getPseudoRegVar ctxt r 1)
  | _ -> raise InvalidOperandException
  !>ir insLen

let movlps ins insLen ctxt = movlpd ins insLen ctxt

let movlhps ins insLen ctxt =
  let ir = IRBuilder (4)
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr128 ins insLen ctxt dst |> fst
  let src = transOprToExpr128 ins insLen ctxt src |> snd
  !<ir insLen
  !!ir (dst := src)
  !>ir insLen

let movmskps ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr ins insLen ctxt dst
  let srcB, srcA= transOprToExpr128 ins insLen ctxt src
  let oprSize = getOperationSize ins
  !<ir insLen
  let srcA = AST.concat (AST.extract srcA 1<rt> 63) (AST.extract srcA 1<rt> 31)
  let srcB = AST.concat (AST.extract srcB 1<rt> 63) (AST.extract srcB 1<rt> 31)
  !!ir (dst := AST.zext oprSize <| AST.concat srcB srcA)
  !>ir insLen

let movmskpd ins insLen ctxt =
  let ir = IRBuilder (4)
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr ins insLen ctxt dst
  let src1, src2 = transOprToExpr128 ins insLen ctxt src
  let oprSize = getOperationSize ins
  !<ir insLen
  let src63 = AST.sext oprSize (AST.xthi 1<rt> src2)
  let src127 = (AST.sext oprSize (AST.xthi 1<rt> src1)) << AST.num1 oprSize
  !!ir (dst := src63 .| src127)
  !>ir insLen

let movss (ins: InsInfo) insLen ctxt =
  let ir = IRBuilder (4)
  let struct (dst, src) = getTwoOprs ins
  !<ir insLen
  match dst, src with
  | OprReg r1, OprReg r2 ->
    let dst = getPseudoRegVar ctxt r1 1 |> AST.xtlo 32<rt>
    let src = getPseudoRegVar ctxt r2 1 |> AST.xtlo 32<rt>
    !!ir (dst := src)
  | OprReg r1, OprMem _ ->
    let dst2, dst1 = getPseudoRegVar128 ctxt r1
    let src = transOprToExpr ins insLen ctxt src
    !!ir (dstAssign 32<rt> dst1 src)
    !!ir (dst2 := AST.num0 64<rt>)
  | OprMem _ , OprReg r1 ->
    let dst = transOprToExpr ins insLen ctxt dst
    let src = getPseudoRegVar ctxt r1 1 |> AST.xtlo 32<rt>
    !!ir (dstAssign 32<rt> dst src)
  | _ -> raise InvalidOperandException
  !>ir insLen

let movsd (ins: InsInfo) insLen ctxt =
  let ir = IRBuilder (4)
  if ins.Operands = NoOperand then
    GeneralLifter.movs ins insLen ctxt
  else
    let struct (dst, src) = getTwoOprs ins
    !<ir insLen
    match dst, src with
    | OprReg r1, OprReg r2 ->
      let dst = getPseudoRegVar ctxt r1 1
      let src = getPseudoRegVar ctxt r2 1
      !!ir (dst := src)
    | OprReg r1, OprMem _ ->
      let dst2, dst1 = getPseudoRegVar128 ctxt r1
      let src = transOprToExpr ins insLen ctxt src
      !!ir (dst1 := src)
      !!ir (dst2 := AST.num0 64<rt>)
    | OprMem _ , OprReg r1 ->
      let dst = transOprToExpr ins insLen ctxt dst
      let src = getPseudoRegVar ctxt r1 1
      !!ir (dstAssign 64<rt> dst src)
    | _ -> raise InvalidOperandException
    !>ir insLen

let addps ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 32<rt> (opP AST.fadd) 8

let addpd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 64<rt> (opP AST.fadd) 8

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
  let ir = IRBuilder(8)
  let _dst2, dst1 =
    ins.Operands |> getFstOperand |> transOprToExpr128 ins insLen ctxt
  let src1, src2 = getTwoSrcOperands ins.Operands
  let src1 = transOprToExpr64 ins insLen ctxt src1
  let src2 =
    if sz = 32<rt> then transOprToExpr32 ins insLen ctxt src2
    else transOprToExpr64 ins insLen ctxt src2
  let dst1, src1 =
    if sz = 32<rt> then AST.xtlo 32<rt> dst1, AST.xtlo 32<rt> src1
    else dst1, src1
  let struct (t1, t2, t3) = tmpVars3 ir sz
  !<ir insLen
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
  buildPackedInstr ins insLen ctxt 32<rt> (opP AST.fsub) 8

let subpd ins insLen ctxt =
  let ir = IRBuilder (4)
  let struct (dst, src) = getTwoOprs ins
  !<ir insLen
  let dst1, dst2 = transOprToExpr128 ins insLen ctxt dst
  let src1, src2 = transOprToExpr128 ins insLen ctxt src
  !!ir (dst1 := dst1 .- src1)
  !!ir (dst2 := dst2 .- src2)
  !>ir insLen

let subss ins insLen ctxt =
  handleScalarFPOp ins insLen ctxt 32<rt> AST.fsub

let subsd ins insLen ctxt =
  handleScalarFPOp ins insLen ctxt 64<rt> AST.fsub

let mulps ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 32<rt> (opP AST.fmul) 8

let mulpd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 64<rt> (opP AST.fmul) 8

let mulss ins insLen ctxt =
  handleScalarFPOp ins insLen ctxt 32<rt> AST.fmul

let mulsd ins insLen ctxt =
  handleScalarFPOp ins insLen ctxt 64<rt> AST.fmul

let divps ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 32<rt> (opP AST.fdiv) 8

let divpd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 64<rt> (opP AST.fdiv) 8

let divss ins insLen ctxt =
  handleScalarFPOp ins insLen ctxt 32<rt> AST.fdiv

let divsd ins insLen ctxt =
  handleScalarFPOp ins insLen ctxt 64<rt> AST.fdiv

let rcpps ins insLen ctxt =
  let ir = IRBuilder(8)
  let struct (opr1, opr2) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insLen ctxt opr1
  let src2, src1 = transOprToExpr128 ins insLen ctxt opr2
  let dst1b, dst1a = AST.xthi 32<rt> dst1, AST.xtlo 32<rt> dst1
  let dst2b, dst2a = AST.xthi 32<rt> dst2, AST.xtlo 32<rt> dst2
  let src1b, src1a = AST.xthi 32<rt> src1, AST.xtlo 32<rt> src1
  let src2b, src2a = AST.xthi 32<rt> src2, AST.xtlo 32<rt> src2
  let tmp = !*ir 32<rt>
  let flt1 = BitVector.ofInt32 0x3f800000 32<rt> |> AST.num
  !<ir insLen
  !!ir (dst1a := AST.fdiv flt1 src1a)
  !!ir (dst1b := AST.fdiv flt1 src1b)
  !!ir (dst2a := AST.fdiv flt1 src2a)
  !!ir (dst2b := AST.fdiv flt1 src2b)
  !>ir insLen

let rcpss ins insLen ctxt =
  let ir = IRBuilder(4)
  let struct (opr1, opr2) = getTwoOprs ins
  let dst = transOprToExpr32 ins insLen ctxt opr1
  let src = transOprToExpr32 ins insLen ctxt opr2
  let tmp = !*ir 32<rt>
  let flt1 = BitVector.ofInt32 0x3f800000 32<rt> |> AST.num
  !<ir insLen
  !!ir (dst := AST.fdiv flt1 src)
  !>ir insLen

let sqrtps ins insLen ctxt =
  let ir = IRBuilder (16)
  let struct (opr1, opr2) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insLen ctxt opr1
  let src2, src1 = transOprToExpr128 ins insLen ctxt opr2
  let struct (tmp1, tmp2, tmp3, tmp4) = tmpVars4 ir 32<rt>
  !<ir insLen
  !!ir (tmp1 := AST.xtlo 32<rt> src1)
  !!ir (tmp2 := AST.xthi 32<rt> src1)
  !!ir (tmp3 := AST.xtlo 32<rt> src2)
  !!ir (tmp4 := AST.xthi 32<rt> src2)
  !!ir (AST.xtlo 32<rt> dst1 := AST.unop UnOpType.FSQRT tmp1)
  !!ir (AST.xthi 32<rt> dst1 := AST.unop UnOpType.FSQRT tmp2)
  !!ir (AST.xtlo 32<rt> dst2 := AST.unop UnOpType.FSQRT tmp3)
  !!ir (AST.xthi 32<rt> dst2 := AST.unop UnOpType.FSQRT tmp4)
  !>ir insLen

let sqrtpd ins insLen ctxt =
  let ir = IRBuilder (4)
  let struct (opr1, opr2) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insLen ctxt opr1
  let src2, src1 = transOprToExpr128 ins insLen ctxt opr2
  !<ir insLen
  !!ir (dst1 := AST.unop UnOpType.FSQRT src1)
  !!ir (dst2 := AST.unop UnOpType.FSQRT src2)
  !>ir insLen

let sqrtss ins insLen ctxt =
  let ir = IRBuilder (4)
  let struct (opr1, opr2) = getTwoOprs ins
  let dst = transOprToExpr32 ins insLen ctxt opr1
  let src = transOprToExpr32 ins insLen ctxt opr2
  !<ir insLen
  !!ir (dst := AST.unop UnOpType.FSQRT src)
  !>ir insLen

let sqrtsd ins insLen ctxt =
  let ir = IRBuilder (4)
  let struct (opr1, opr2) = getTwoOprs ins
  let dst = transOprToExpr64 ins insLen ctxt opr1
  let src = transOprToExpr64 ins insLen ctxt opr2
  !<ir insLen
  !!ir (dst := AST.unop UnOpType.FSQRT src)
  !>ir insLen

let rsqrtps ins insLen ctxt =
  let ir = IRBuilder(16)
  let struct (opr1, opr2) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insLen ctxt opr1
  let src2, src1 = transOprToExpr128 ins insLen ctxt opr2
  let dst1b, dst1a = AST.xthi 32<rt> dst1, AST.xtlo 32<rt> dst1
  let dst2b, dst2a = AST.xthi 32<rt> dst2, AST.xtlo 32<rt> dst2
  let src1b, src1a = AST.xthi 32<rt> src1, AST.xtlo 32<rt> src1
  let src2b, src2a = AST.xthi 32<rt> src2, AST.xtlo 32<rt> src2
  let tmp = !*ir 32<rt>
  let flt1 = BitVector.ofInt32 0x3f800000 32<rt> |> AST.num
  !<ir insLen
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
  let ir = IRBuilder(4)
  let struct (opr1, opr2) = getTwoOprs ins
  let dst = transOprToExpr32 ins insLen ctxt opr1
  let src = transOprToExpr32 ins insLen ctxt opr2
  let tmp = !*ir 32<rt>
  let flt1 = BitVector.ofInt32 0x3f800000 32<rt> |> AST.num
  !<ir insLen
  !!ir (tmp := AST.unop UnOpType.FSQRT src)
  !!ir (dst := AST.fdiv flt1 tmp)
  !>ir insLen

let private minMaxPS ins insLen ctxt compare =
  let ir = IRBuilder (16)
  let struct (dst, src) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insLen ctxt dst
  let src2, src1 = transOprToExpr128 ins insLen ctxt src
  let dst1A, dst1B = AST.xtlo 32<rt> dst1, AST.xthi 32<rt> dst1
  let dst2A, dst2B = AST.xtlo 32<rt> dst2, AST.xthi 32<rt> dst2
  let src1A, src1B = AST.xtlo 32<rt> src1, AST.xthi 32<rt> src1
  let src2A, src2B = AST.xtlo 32<rt> src2, AST.xthi 32<rt> src2
  let struct (val4, val3, val2, val1) = tmpVars4 ir 32<rt>
  !<ir insLen
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
  let ir = IRBuilder (8)
  let struct (dst, src) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insLen ctxt dst
  let src2, src1 = transOprToExpr128 ins insLen ctxt src
  let struct (val2, val1) = tmpVars2 ir 64<rt>
  !<ir insLen
  !!ir (val1 := AST.ite (compare dst1 src1) dst1 src1)
  !!ir (val2 := AST.ite (compare dst2 src2) dst2 src2)
  !!ir (dst1 := val1)
  !!ir (dst2 := val2)
  !>ir insLen

let private minMaxSS ins insLen ctxt compare =
  let ir = IRBuilder (4)
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr32 ins insLen ctxt dst
  let src = transOprToExpr32 ins insLen ctxt src
  let tmp = !*ir 32<rt>
  !<ir insLen
  !!ir (tmp := AST.ite (compare dst src) dst src)
  !!ir (dst := tmp)
  !>ir insLen

let private minMaxSD ins insLen ctxt compare =
  let ir = IRBuilder (4)
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr64 ins insLen ctxt dst
  let src = transOprToExpr64 ins insLen ctxt src
  let tmp = !*ir 64<rt>
  !<ir insLen
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

let cmpps ins insLen ctxt =
  let ir = IRBuilder (64)
  let struct (op1, op2, op3) = getThreeOprs ins
  let dst1, dst2 = transOprToExpr128 ins insLen ctxt op1
  let src1, src2 = transOprToExpr128 ins insLen ctxt op2
  let dst1A, dst1B = AST.xtlo 32<rt> dst1, AST.xthi 32<rt> dst1
  let dst2A, dst2B = AST.xtlo 32<rt> dst2, AST.xthi 32<rt> dst2
  let imm = transOprToExpr ins insLen ctxt op3
  let isNan expr =
    (AST.extract expr 8<rt> 23  == AST.num (BitVector.unsignedMax 8<rt>))
     .& (AST.xtlo 23<rt> expr != AST.num0 23<rt>)
  let cmpCond c expr1 expr2 =
    !!ir (c := AST.b0)
    !!ir (c := AST.ite (imm == AST.num0 3<rt>) (expr1 == expr2) c)
    !!ir (c := AST.ite (imm == AST.num1 3<rt>) (AST.flt expr1  expr2) c)
    !!ir (c := AST.ite (imm == numI32 2 3<rt>) (AST.fle expr1 expr2) c)
    !!ir (c := AST.ite (imm == numI32 3 3<rt>) (isNan expr1 .| isNan expr2) c)
    !!ir (c := AST.ite (imm == numI32 4 3<rt>) (expr1 != expr2) c)
    !!ir (c := AST.ite (imm == numI32 5 3<rt>) (AST.flt expr1 expr2 |> AST.not) c)
    !!ir (c := AST.ite (imm == numI32 6 3<rt>) (AST.fle expr1 expr2 |> AST.not) c)
    !!ir
      (c := AST.ite (imm == numI32 7 3<rt>) (isNan expr1 .| isNan expr2 |> AST.not) c)
  let struct (cond1, cond2, cond3, cond4) = tmpVars4 ir 1<rt>
  !<ir insLen
  cmpCond cond1 dst1A (AST.xtlo 32<rt> src1)
  cmpCond cond2 dst1B (AST.xthi 32<rt> src1)
  cmpCond cond3 dst2A (AST.xtlo 32<rt> src2)
  cmpCond cond4 dst2B (AST.xthi 32<rt> src2)
  !!ir (dst1A := AST.ite cond1 (maxNum 32<rt>) (AST.num0 32<rt>))
  !!ir (dst1B := AST.ite cond2 (maxNum 32<rt>) (AST.num0 32<rt>))
  !!ir (dst2A := AST.ite cond3 (maxNum 32<rt>) (AST.num0 32<rt>))
  !!ir (dst2B := AST.ite cond4 (maxNum 32<rt>) (AST.num0 32<rt>))
  !>ir insLen

let cmppd ins insLen ctxt =
  let ir = IRBuilder (32)
  let struct (op1, op2, op3) = getThreeOprs ins
  let dst1, dst2 = transOprToExpr128 ins insLen ctxt op1
  let src1, src2 = transOprToExpr128 ins insLen ctxt op2
  let imm = transOprToExpr ins insLen ctxt op3
  let isNan expr =
    (AST.extract expr 11<rt> 52  == AST.num (BitVector.unsignedMax 11<rt>))
     .& (AST.xtlo 52<rt> expr != AST.num0 52<rt>)
  let cmpCond c expr1 expr2 =
    !!ir (c := AST.b0)
    !!ir (c := AST.ite (imm == AST.num0 3<rt>) (expr1 == expr2) c)
    !!ir (c := AST.ite (imm == AST.num1 3<rt>) (AST.flt expr1  expr2) c)
    !!ir (c := AST.ite (imm == numI32 2 3<rt>) (AST.fle expr1 expr2) c)
    !!ir (c := AST.ite (imm == numI32 3 3<rt>) (isNan expr1 .| isNan expr2) c)
    !!ir (c := AST.ite (imm == numI32 4 3<rt>) (expr1 != expr2) c)
    !!ir (c := AST.ite (imm == numI32 5 3<rt>) (AST.flt expr1 expr2 |> AST.not) c)
    !!ir (c := AST.ite (imm == numI32 6 3<rt>) (AST.fle expr1 expr2 |> AST.not) c)
    !!ir
      (c := AST.ite (imm == numI32 7 3<rt>) (isNan expr1 .| isNan expr2 |> AST.not) c)
  let struct (cond1, cond2) = tmpVars2 ir 1<rt>
  !<ir insLen
  cmpCond cond1 dst1 src1
  cmpCond cond2 dst2 src2
  !!ir (dst1 := AST.ite cond1 (maxNum 64<rt>) (AST.num0 64<rt>))
  !!ir (dst2 := AST.ite cond2 (maxNum 64<rt>) (AST.num0 64<rt>))
  !>ir insLen

let cmpss ins insLen ctxt =
  let ir = IRBuilder (16)
  let struct (dst, src, imm) = getThreeOprs ins
  let dst = transOprToExpr32 ins insLen ctxt dst
  let src = transOprToExpr32 ins insLen ctxt src
  let imm = transOprToExpr ins insLen ctxt imm |> AST.xtlo 8<rt>
  let n num = numI32 num 8<rt>
  let max32 = maxNum 32<rt>
  let isNan expr =
    (AST.extract expr 8<rt> 23  == AST.num (BitVector.unsignedMax 8<rt>))
     .& (AST.xtlo 23<rt> expr != AST.num0 23<rt>)
  let cond = !*ir 1<rt>
  !<ir insLen
  !!ir (cond := (dst == src))
  !!ir (cond := AST.ite (imm == n 1) (AST.flt dst src) cond)
  !!ir (cond := AST.ite (imm == n 2) (AST.fle dst src) cond)
  !!ir (cond := AST.ite (imm == n 3) ((isNan dst) .| (isNan src)) cond)
  !!ir (cond := AST.ite (imm == n 4) (dst != src) cond)
  !!ir (cond := AST.ite (imm == n 5) (AST.flt dst src |> AST.not) cond)
  !!ir (cond := AST.ite (imm == n 6) (AST.fle dst src |> AST.not) cond)
  !!ir (cond := AST.ite (imm == n 7)
                          ((isNan dst) .| (isNan src) |> AST.not) cond)
  !!ir (dst := AST.ite cond max32 (AST.num0 32<rt>))
  !>ir insLen

let cmpsd (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | NoOperand -> GeneralLifter.cmps ins insLen ctxt
  | ThreeOperands (dst, src, imm) ->
    let ir = IRBuilder (16)
    let dst = transOprToExpr64 ins insLen ctxt dst
    let src = transOprToExpr64 ins insLen ctxt src
    let imm = transOprToExpr ins insLen ctxt imm |> AST.xtlo 8<rt>
    let n i = numI32 i 8<rt>
    let max64 = maxNum 64<rt>
    let isNan expr =
      (AST.extract expr 11<rt> 52  == AST.num (BitVector.unsignedMax 11<rt>))
       .& (AST.xtlo 52<rt> expr != AST.num0 52<rt>)
    let cond = !*ir 1<rt>
    !<ir insLen
    !!ir (cond := (dst == src))
    !!ir (cond := AST.ite (imm == n 1) (AST.flt dst src) cond)
    !!ir (cond := AST.ite (imm == n 2) (AST.fle dst src) cond)
    !!ir (cond := AST.ite (imm == n 3) ((isNan dst) .| (isNan src)) cond)
    !!ir (cond := AST.ite (imm == n 4) (dst != src) cond)
    !!ir (cond := AST.ite (imm == n 5) (AST.flt dst src |> AST.not) cond)
    !!ir (cond := AST.ite (imm == n 6) (AST.fle dst src |> AST.not) cond)
    !!ir (cond := AST.ite (imm == n 7)
                            ((isNan dst) .| (isNan src) |> AST.not) cond)
    !!ir (dst := AST.ite cond max64 (AST.num0 64<rt>))
    !>ir insLen
  | _ -> raise InvalidOperandException

let comiss ins insLen ctxt =
  let ir = IRBuilder (16)
  let struct (opr1, opr2) = getTwoOprs ins
  let opr1 = transOprToExpr32 ins insLen ctxt opr1
  let opr2 = transOprToExpr32 ins insLen ctxt opr2
  let lblNan = ir.NewSymbol "IsNan"
  let lblExit = ir.NewSymbol "Exit"
  let zf = !.ctxt R.ZF
  let pf = !.ctxt R.PF
  let cf = !.ctxt R.CF
  !<ir insLen
  !!ir (zf := AST.ite (opr1 == opr2) AST.b1 AST.b0)
  !!ir (pf := AST.b0)
  !!ir (cf := AST.ite (AST.flt opr1 opr2) AST.b1 AST.b0)
  let isNan expr =
    (AST.extract expr 8<rt> 23  == AST.num (BitVector.unsignedMax 8<rt>))
     .& (AST.xtlo 23<rt> expr != AST.num0 23<rt>)
  !!ir (AST.cjmp (isNan opr1 .| isNan opr2)
                 (AST.name lblNan) (AST.name lblExit))
  !!ir (AST.lmark lblNan)
  !!ir (zf := AST.b1)
  !!ir (pf := AST.b1)
  !!ir (cf := AST.b1)
  !!ir (AST.lmark lblExit)
  !!ir (!.ctxt R.OF := AST.b0)
  !!ir (!.ctxt R.AF := AST.b0)
  !!ir (!.ctxt R.SF := AST.b0)
  !>ir insLen

let comisd ins insLen ctxt =
  let ir = IRBuilder (16)
  let struct (opr1, opr2) = getTwoOprs ins
  let opr1 = transOprToExpr64 ins insLen ctxt opr1
  let opr2 = transOprToExpr64 ins insLen ctxt opr2
  let lblNan = ir.NewSymbol "IsNan"
  let lblExit = ir.NewSymbol "Exit"
  let zf = !.ctxt R.ZF
  let pf = !.ctxt R.PF
  let cf = !.ctxt R.CF
  !<ir insLen
  !!ir (zf := AST.ite (opr1 == opr2) AST.b1 AST.b0)
  !!ir (pf := AST.b0)
  !!ir (cf := AST.ite (AST.flt opr1 opr2) AST.b1 AST.b0)
  let isNan expr =
    (AST.extract expr 11<rt> 52  == AST.num (BitVector.unsignedMax 11<rt>))
     .& (AST.xtlo 52<rt> expr != AST.num0 52<rt>)
  !!ir (AST.cjmp (isNan opr1 .| isNan opr2)
                 (AST.name lblNan) (AST.name lblExit))
  !!ir (AST.lmark lblNan)
  !!ir (zf := AST.b1)
  !!ir (pf := AST.b1)
  !!ir (cf := AST.b1)
  !!ir (AST.lmark lblExit)
  !!ir (!.ctxt R.OF := AST.b0)
  !!ir (!.ctxt R.AF := AST.b0)
  !!ir (!.ctxt R.SF := AST.b0)
  !>ir insLen

let ucomiss ins insLen ctxt =
  let ir = IRBuilder (16)
  let struct (opr1, opr2) = getTwoOprs ins
  let opr1 = transOprToExpr32 ins insLen ctxt opr1
  let opr2 = transOprToExpr32 ins insLen ctxt opr2
  let lblNan = ir.NewSymbol "IsNan"
  let lblExit = ir.NewSymbol "Exit"
  let zf = !.ctxt R.ZF
  let pf = !.ctxt R.PF
  let cf = !.ctxt R.CF
  !<ir insLen
  !!ir (zf := AST.ite (opr1 == opr2) AST.b1 AST.b0)
  !!ir (pf := AST.b0)
  !!ir (cf := AST.ite (AST.flt opr1 opr2) AST.b1 AST.b0)
  let isNan expr =
    (AST.extract expr 8<rt> 23  == AST.num (BitVector.unsignedMax 8<rt>))
     .& (AST.xtlo 23<rt> expr != AST.num0 23<rt>)
  !!ir (AST.cjmp (isNan opr1 .| isNan opr2)
                 (AST.name lblNan) (AST.name lblExit))
  !!ir (AST.lmark lblNan)
  !!ir (zf := AST.b1)
  !!ir (pf := AST.b1)
  !!ir (cf := AST.b1)
  !!ir (AST.lmark lblExit)
  !!ir (!.ctxt R.OF := AST.b0)
  !!ir (!.ctxt R.AF := AST.b0)
  !!ir (!.ctxt R.SF := AST.b0)
  !>ir insLen

let ucomisd ins insLen ctxt =
  let ir = IRBuilder (16)
  let struct (opr1, opr2) = getTwoOprs ins
  let opr1 = transOprToExpr64 ins insLen ctxt opr1
  let opr2 = transOprToExpr64 ins insLen ctxt opr2
  let lblNan = ir.NewSymbol "IsNan"
  let lblExit = ir.NewSymbol "Exit"
  let zf = !.ctxt R.ZF
  let pf = !.ctxt R.PF
  let cf = !.ctxt R.CF
  !<ir insLen
  !!ir (zf := AST.ite (opr1 == opr2) AST.b1 AST.b0)
  !!ir (pf := AST.b0)
  !!ir (cf := AST.ite (AST.flt opr1 opr2) AST.b1 AST.b0)
  let isNan expr =
    (AST.extract expr 11<rt> 52  == AST.num (BitVector.unsignedMax 11<rt>))
     .& (AST.xtlo 52<rt> expr != AST.num0 52<rt>)
  !!ir (AST.cjmp (isNan opr1 .| isNan opr2)
                 (AST.name lblNan) (AST.name lblExit))
  !!ir (AST.lmark lblNan)
  !!ir (zf := AST.b1)
  !!ir (pf := AST.b1)
  !!ir (cf := AST.b1)
  !!ir (AST.lmark lblExit)
  !!ir (!.ctxt R.OF := AST.b0)
  !!ir (!.ctxt R.AF := AST.b0)
  !!ir (!.ctxt R.SF := AST.b0)
  !>ir insLen

let andps ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 32<rt> opPand 16

let andpd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 64<rt> opPand 16

let andnps ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 32<rt> opPandn 8

let andnpd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 64<rt> opPandn 8

let orps ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 32<rt> opPor 16

let orpd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 64<rt> opPor 16

let private opPxor _ = Array.map2 (.|)

let xorps ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 32<rt> opPxor 16

let xorpd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 64<rt> opPxor 16

let shufps ins insLen ctxt =
  let ir = IRBuilder (32)
  let struct (dst, src, imm) = getThreeOprs ins
  let dst2, dst1 = transOprToExpr128 ins insLen ctxt dst
  let src2, src1 = transOprToExpr128 ins insLen ctxt src
  let imm = transOprToExpr ins insLen ctxt imm
  let dst1A, dst1B = AST.xtlo 32<rt> dst1, AST.xthi 32<rt> dst1
  let dst2A, dst2B = AST.xtlo 32<rt> dst2, AST.xthi 32<rt> dst2
  let src1A, src1B = AST.xtlo 32<rt> src1, AST.xthi 32<rt> src1
  let src2A, src2B = AST.xtlo 32<rt> src2, AST.xthi 32<rt> src2
  let doShuf cond dst e0 e1 e2 e3 =
    !!ir (dst := AST.num0 32<rt>)
    !!ir (dst := AST.ite (cond == AST.num0 2<rt>) e0 dst)
    !!ir (dst := AST.ite (cond == AST.num1 2<rt>) e1 dst)
    !!ir (dst := AST.ite (cond == numI32 2 2<rt>) e2 dst)
    !!ir (dst := AST.ite (cond == numI32 3 2<rt>) e3 dst)
  let cond1 = AST.xtlo 2<rt> imm
  let cond2 = AST.extract imm 2<rt> 2
  let cond3 = AST.extract imm 2<rt> 4
  let cond4 = AST.extract imm 2<rt> 6
  let struct (tmp1, tmp2, tmp3, tmp4) = tmpVars4 ir 32<rt>
  !<ir insLen
  doShuf cond1 tmp1 dst1A dst1B dst2A dst2B
  doShuf cond2 tmp2 dst1A dst1B dst2A dst2B
  doShuf cond3 tmp3 src1A src1B src2A src2B
  doShuf cond4 tmp4 src1A src1B src2A src2B
  !!ir (dst1A := tmp1)
  !!ir (dst1B := tmp2)
  !!ir (dst2A := tmp3)
  !!ir (dst2B := tmp4)
  !>ir insLen

let shufpd ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src, imm) = getThreeOprs ins
  let dst2, dst1 = transOprToExpr128 ins insLen ctxt dst
  let src2, src1 = transOprToExpr128 ins insLen ctxt src
  let imm = transOprToExpr ins insLen ctxt imm
  let cond1 = AST.xtlo 1<rt> imm
  let cond2 = AST.extract imm 1<rt> 1
  !<ir insLen
  !!ir (dst1 := AST.ite cond1 dst2 dst1)
  !!ir (dst2 := AST.ite cond2 src2 src1)
  !>ir insLen

let unpckhps ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insLen ctxt dst
  let src2, _src1 = transOprToExpr128 ins insLen ctxt src
  let dst1A, dst1B = AST.xtlo 32<rt> dst1, AST.xthi 32<rt> dst1
  let dst2A, dst2B = AST.xtlo 32<rt> dst2, AST.xthi 32<rt> dst2
  let src2A, src2B = AST.xtlo 32<rt> src2, AST.xthi 32<rt> src2
  !<ir insLen
  !!ir (dst1A := dst2A)
  !!ir (dst1B := src2A)
  !!ir (dst2A := dst2B)
  !!ir (dst2B := src2B)
  !>ir insLen

let unpckhpd ins insLen ctxt =
  let ir = IRBuilder (4)
  let struct (dst, src) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insLen ctxt dst
  let src2, _src1 = transOprToExpr128 ins insLen ctxt src
  !<ir insLen
  !!ir (dst1 := dst2)
  !!ir (dst2 := src2)
  !>ir insLen

let unpcklps ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insLen ctxt dst
  let _src2, src1 = transOprToExpr128 ins insLen ctxt src
  let _dst1A, dst1B = AST.xtlo 32<rt> dst1, AST.xthi 32<rt> dst1
  let dst2A, dst2B = AST.xtlo 32<rt> dst2, AST.xthi 32<rt> dst2
  let src1A, src1B = AST.xtlo 32<rt> src1, AST.xthi 32<rt> src1
  !<ir insLen
  !!ir (dst2A := dst1B)
  !!ir (dst1B := src1A)
  !!ir (dst2B := src1B)
  !>ir insLen

let unpcklpd ins insLen ctxt =
  let ir = IRBuilder (4)
  let struct (dst, src) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insLen ctxt dst
  let _src2, src1 = transOprToExpr128 ins insLen ctxt src
  !<ir insLen
  !!ir (dst2 := src1)
  !>ir insLen

let cvtpi2ps ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr64 ins insLen ctxt dst
  let src = transOprToExpr64 ins insLen ctxt src
  let struct (tmp2, tmp1) = tmpVars2 ir 32<rt>
  !<ir insLen
  !!ir (tmp1 := AST.xtlo 32<rt> src)
  !!ir (tmp2 := AST.xthi 32<rt> src)
  !!ir (AST.xtlo 32<rt> dst := AST.cast CastKind.IntToFloat 32<rt> tmp1)
  !!ir (AST.xthi 32<rt> dst := AST.cast CastKind.IntToFloat 32<rt> tmp2)
  !>ir insLen

let cvtdq2pd ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insLen ctxt dst
  let src = transOprToExpr64 ins insLen ctxt src
  let struct (tmp1, tmp2) = tmpVars2 ir 32<rt>
  !<ir insLen
  !!ir (tmp1 := AST.xtlo 32<rt> src)
  !!ir (tmp2 := AST.xthi 32<rt> src)
  !!ir (dst1 := AST.cast CastKind.IntToFloat 64<rt> tmp1)
  !!ir (dst2 := AST.cast CastKind.IntToFloat 64<rt> tmp2)
  !>ir insLen

let cvtpi2pd ins insLen ctxt = cvtdq2pd ins insLen ctxt

let cvtsi2ss ins insLen ctxt =
  let ir = IRBuilder (4)
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr64 ins insLen ctxt dst
  let src = transOprToExpr ins insLen ctxt src
  !<ir insLen
  !!ir (AST.xtlo 32<rt> dst := AST.cast CastKind.IntToFloat 32<rt> src)
  !>ir insLen

let cvtsi2sd ins insLen ctxt =
  let ir = IRBuilder (4)
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr64 ins insLen ctxt dst
  let src = transOprToExpr ins insLen ctxt src
  !<ir insLen
  !!ir (dst := AST.cast CastKind.IntToFloat 64<rt> src)
  !>ir insLen

let cvtps2pi ins insLen ctxt rounded =
  let ir = IRBuilder (8)
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr ins insLen ctxt dst
  let src = transOprToExpr64 ins insLen ctxt src
  let struct (tmp1, tmp2) = tmpVars2 ir 32<rt>
  let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
  !<ir insLen
  !!ir (tmp1 := AST.xtlo 32<rt> src)
  !!ir (tmp2 := AST.xthi 32<rt> src)
  !!ir (AST.xtlo 32<rt> dst := AST.cast castKind 32<rt> tmp1)
  !!ir (AST.xthi 32<rt> dst := AST.cast castKind 32<rt> tmp2)
  !>ir insLen

let cvtps2pd ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insLen ctxt dst
  let src = transOprToExpr64 ins insLen ctxt src
  let struct (tmp1, tmp2) = tmpVars2 ir 32<rt>
  !<ir insLen
  !!ir (tmp1 := AST.xtlo 32<rt> src)
  !!ir (tmp2 := AST.xthi 32<rt> src)
  !!ir (dst1 := AST.cast CastKind.FloatCast 64<rt> tmp1)
  !!ir (dst2 := AST.cast CastKind.FloatCast 64<rt> tmp2)
  !>ir insLen

let cvtpd2ps ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insLen ctxt dst
  let src2, src1 = transOprToExpr128 ins insLen ctxt src
  !<ir insLen
  !!ir (AST.xtlo 32<rt> dst1 := AST.cast CastKind.FloatCast 32<rt> src1)
  !!ir (AST.xthi 32<rt> dst1 := AST.cast CastKind.FloatCast 32<rt> src2)
  !!ir (dst2 := AST.num0 64<rt>)
  !>ir insLen

let cvtpd2pi ins insLen ctxt rounded =
  let ir = IRBuilder (4)
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr ins insLen ctxt dst
  let src2, src1 = transOprToExpr128 ins insLen ctxt src
  let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
  !<ir insLen
  !!ir (AST.xtlo 32<rt> dst := AST.cast castKind 32<rt> src1)
  !!ir (AST.xthi 32<rt> dst := AST.cast castKind 32<rt> src2)
  !>ir insLen

let cvtpd2dq ins insLen ctxt rounded =
  let ir = IRBuilder (8)
  let struct (dst, src) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insLen ctxt dst
  let src2, src1 = transOprToExpr128 ins insLen ctxt src
  let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
  !<ir insLen
  !!ir (AST.xtlo 32<rt> dst1 := AST.cast castKind 32<rt> src1)
  !!ir (AST.xthi 32<rt> dst1 := AST.cast castKind 32<rt> src2)
  !!ir (dst2 := AST.num0 64<rt>)
  !>ir insLen

let cvtdq2ps ins insLen ctxt =
  let ir = IRBuilder (16)
  let struct (dst, src) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insLen ctxt dst
  let src2, src1 = transOprToExpr128 ins insLen ctxt src
  let struct (tmp1, tmp2, tmp3, tmp4) = tmpVars4 ir 32<rt>
  !<ir insLen
  !!ir (tmp1 := AST.xtlo 32<rt> src1)
  !!ir (tmp2 := AST.xthi 32<rt> src1)
  !!ir (tmp3 := AST.xtlo 32<rt> src2)
  !!ir (tmp4 := AST.xthi 32<rt> src2)
  !!ir (AST.xtlo 32<rt> dst1 := AST.cast CastKind.IntToFloat 32<rt> tmp1)
  !!ir (AST.xthi 32<rt> dst1 := AST.cast CastKind.IntToFloat 32<rt> tmp2)
  !!ir (AST.xtlo 32<rt> dst2 := AST.cast CastKind.IntToFloat 32<rt> tmp3)
  !!ir (AST.xthi 32<rt> dst2 := AST.cast CastKind.IntToFloat 32<rt> tmp4)
  !>ir insLen

let cvtps2dq ins insLen ctxt rounded =
  let ir = IRBuilder (16)
  let struct (dst, src) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insLen ctxt dst
  let src2, src1 = transOprToExpr128 ins insLen ctxt src
  let struct (tmp1, tmp2, tmp3, tmp4) = tmpVars4 ir 32<rt>
  let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
  !<ir insLen
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
  let ir = IRBuilder (4)
  let oprSize = getOperationSize ins
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr ins insLen ctxt dst
  let src = transOprToExpr32 ins insLen ctxt src
  let tmp = !*ir 32<rt>
  let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
  !<ir insLen
  if is64bit ctxt && oprSize = 64<rt> then
    !!ir (dst := AST.cast castKind 64<rt> src)
  else
    !!ir (tmp := AST.cast castKind 32<rt> src)
    !!ir (dstAssign 32<rt> dst tmp)
  !>ir insLen

let cvtss2sd ins insLen ctxt =
  let ir = IRBuilder (4)
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr64 ins insLen ctxt dst
  let src = transOprToExpr32 ins insLen ctxt src
  !<ir insLen
  !!ir (dst := AST.cast CastKind.FloatCast 64<rt> src)
  !>ir insLen

let cvtsd2ss ins insLen ctxt =
  let ir = IRBuilder (4)
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr64 ins insLen ctxt dst
  let src = transOprToExpr64 ins insLen ctxt src
  !<ir insLen
  !!ir (AST.xtlo 32<rt> dst := AST.cast CastKind.FloatCast 32<rt> src)
  !>ir insLen

let cvtsd2si ins insLen ctxt rounded =
  let ir = IRBuilder (8)
  let oprSize = getOperationSize ins
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr ins insLen ctxt dst
  let src = transOprToExpr64 ins insLen ctxt src
  let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
  let tmp = !*ir 32<rt>
  !<ir insLen
  if is64bit ctxt && oprSize = 64<rt> then
    !!ir (dst := AST.cast castKind 64<rt> src)
  else
    !!ir (tmp := AST.cast castKind 32<rt> src)
    !!ir (dstAssign 32<rt> dst tmp)
  !>ir insLen

let ldmxcsr ins insLen ctxt =
  let ir = IRBuilder (4)
  let src = transOneOpr ins insLen ctxt
  !<ir insLen
  !!ir (!.ctxt R.MXCSR := src)
  !>ir insLen

let stmxcsr ins insLen ctxt =
  let ir = IRBuilder (4)
  let dst = transOneOpr ins insLen ctxt
  !<ir insLen
  !!ir (dst := !.ctxt R.MXCSR)
  !>ir insLen

let private opAveragePackedInt (packSz: int<rt>) =
  let dblSz = packSz * 2
  let dblExt expr = AST.zext dblSz expr
  let avg e1 e2 =
    AST.extract (dblExt e1 .+ dblExt e2 .+ AST.num1 dblSz) packSz 1
  Array.map2 avg

let private opPavgb _ = opAveragePackedInt 8<rt>

let pavgb ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 8<rt> opPavgb 64

let private opPavgw _ = opAveragePackedInt 16<rt>

let pavgw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 16<rt> opPavgw 32

let pextrw ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src, count) = getThreeOprs ins
  let dst = transOprToExpr ins insLen ctxt dst
  let count =
    transOprToExpr ins insLen ctxt count
    |> AST.xtlo 8<rt> .& numU32 7u 8<rt>
  let oprSize = getOperationSize ins
  !<ir insLen
  match src with
  | OprReg reg ->
    match Register.getKind reg with
    | Register.Kind.MMX ->
      let src = transOprToExpr ins insLen ctxt src
      let srcOffset = !*ir 64<rt>
      !!ir (srcOffset := AST.zext 64<rt> count)
      let t = (src >> (srcOffset .* numU32 16u 64<rt>)) .& numU32 0xFFFFu 64<rt>
      !!ir (dstAssign oprSize dst (AST.xtlo oprSize t))
    | Register.Kind.XMM ->
      let srcB, srcA = getPseudoRegVar128 ctxt reg
      let tSrc = !*ir 128<rt>
      let srcOffset = !*ir 128<rt>
      !!ir (srcOffset := AST.zext 128<rt> count)
      !!ir (tSrc := AST.concat srcB srcA)
      let t = (tSrc >> (srcOffset .* numU32 16u 128<rt>)) .&
              numU32 0xFFFFu 128<rt>
      !!ir (dstAssign oprSize dst (AST.xtlo oprSize t))
    | _ -> raise InvalidRegisterException
  | _ -> raise InvalidOperandException
  !>ir insLen

let pinsrw ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src, count) = getThreeOprs ins
  let src = transOprToExpr ins insLen ctxt src
  let sel = !*ir 64<rt>
  let getImm = function
    | OprImm (imm, _) -> imm
    | _ -> raise InvalidOperandException
  !<ir insLen
  match dst with
  | OprReg reg ->
    match Register.getSize reg with
    | 64<rt> ->
      let dst = transOprToExpr ins insLen ctxt dst
      let count = transOprToExpr ins insLen ctxt count
      let mask = !*ir 64<rt>
      !!ir (sel := count .| numI64 3L 64<rt>)
      let pos = sel .* numU64 0x10UL 64<rt>
      !!ir (mask := (numU64 0xffffUL 64<rt>) << pos)
      !!ir
        (dst := (dst .& (AST.not mask)) .| (AST.zext 64<rt> src << pos .& mask))
    | 128<rt> ->
      let dst1, dst2 = transOprToExpr128 ins insLen ctxt dst
      let mask = !*ir 64<rt>
      let count = getImm count
      !!ir (sel := numI64 count 64<rt> .| numI64 7L 64<rt>)
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

let private opPmaxub _ = opMaxMinPacked AST.gt

let pmaxub ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 8<rt> opPmaxub 64

let private opPmaxsw _ = opMaxMinPacked AST.sgt

let pmaxsw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 16<rt> opPmaxsw 32

let private opPmaxsb _ = opMaxMinPacked AST.sgt

let pmaxsb ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 8<rt> opPmaxsb 64

let opPminub _ = opMaxMinPacked AST.lt

let pminub ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 8<rt> opPminub 64

let private opPminsw _ = opMaxMinPacked AST.slt

let pminsw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 16<rt> opPminsw 32

let opPminud _ = opMaxMinPacked AST.lt

let pminud ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 32<rt> opPminud 32

let private opPminsb _ = opMaxMinPacked AST.slt

let pminsb ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 8<rt> opPminsb 32

let pmovmskb ins insLen ctxt =
  let ir = IRBuilder (4)
  let oprSize = getOperationSize ins
  let struct (dst, src) = getTwoOprs ins
  !<ir insLen
  let r = match src with | OprReg r -> r | _ -> raise InvalidOperandException
  let arrayInit cnt src =
    Array.init cnt (fun i -> AST.extract src 1<rt> (i * 8 + 7))
  match Register.getKind r with
  | Register.Kind.MMX ->
    let struct (dst, src) = transTwoOprs ins insLen ctxt
    let srcSize = TypeCheck.typeOf src
    let cnt = RegType.toByteWidth srcSize
    let tmps = arrayInit cnt src
    !!ir (dstAssign oprSize dst <| AST.zext oprSize (AST.concatArr tmps))
  | Register.Kind.XMM ->
    let dst = transOprToExpr ins insLen ctxt dst
    let srcB, srcA = transOprToExpr128 ins insLen ctxt src
    let srcSize = TypeCheck.typeOf srcA
    let cnt = RegType.toByteWidth srcSize
    let tmpsA = arrayInit cnt srcA
    let tmpsB = arrayInit cnt srcB
    let tmps = AST.concat (AST.concatArr tmpsB) (AST.concatArr tmpsA)
    !!ir (dstAssign oprSize dst <| AST.zext oprSize tmps)
  | Register.Kind.YMM ->
    let dst = transOprToExpr ins insLen ctxt dst
    let srcD, srcC, srcB, srcA = transOprToExpr256 ins insLen ctxt src
    let srcSize = TypeCheck.typeOf srcA
    let cnt = RegType.toByteWidth srcSize
    let tmpsA = arrayInit cnt srcA
    let tmpsB = arrayInit cnt srcB
    let tmpsC = arrayInit cnt srcC
    let tmpsD = arrayInit cnt srcD
    let tmps = AST.concat (AST.concat (AST.concatArr tmpsD) (AST.concatArr tmpsC))
                      (AST.concat (AST.concatArr tmpsB) (AST.concatArr tmpsA))
    !!ir (dstAssign oprSize dst <| AST.zext oprSize tmps)
  | _ -> raise InvalidOperandException
  !>ir insLen

let private opPmulhuw _ = opPmul AST.xthi AST.zext 32<rt> 16<rt>

let pmulhuw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 16<rt> opPmulhuw 32

let private opPsadbw _ =
  let abs expr = AST.ite (AST.lt expr (AST.num0 8<rt>)) (AST.neg expr) (expr)
  Array.map2 (fun e1 e2 -> abs (e1 .- e2))

let psadbw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 8<rt> opPsadbw 64

let pshufw ins insLen ctxt =
  let struct (dst, src, ord) = transThreeOprs ins insLen ctxt
  let oprSize = getOperationSize ins
  let cnt = RegType.toBitWidth oprSize / 16
  let ir = IRBuilder (2 * cnt)
  !<ir insLen
  let tmps = Array.init cnt (fun _ -> !*ir 16<rt>)
  let n16 = numI32 16 oprSize
  let mask2 = numI32 3 16<rt> (* 2-bit mask *)
  for i in 1 .. cnt do
    let order =
      ((AST.xtlo 16<rt> ord) >> (numI32 ((i - 1) * 2) 16<rt>)) .& mask2
    let order' = AST.zext oprSize order
    !!ir (tmps.[i - 1] := AST.xtlo 16<rt> (src >> (order' .* n16)))
  done
  !!ir (dst := AST.concatArr tmps)
  !>ir insLen

let pshufd ins insLen ctxt =
  let struct (dst, src, ord) = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
  let srcB, srcA = transOprToExpr128 ins insLen ctxt src
  let ord = transOprToExpr ins insLen ctxt ord
  let oprSize = getOperationSize ins
  let cnt = RegType.toBitWidth oprSize / 32
  let ir = IRBuilder (2 * cnt)
  !<ir insLen
  let tmps = Array.init cnt (fun _ -> !*ir 32<rt>)
  let n32 = numI32 32 oprSize
  let mask2 = numI32 3 32<rt> (* 2-bit mask *)
  let tSrc = !*ir oprSize
  let tDst = !*ir oprSize
  !!ir (tSrc := AST.concat srcB srcA)
  for i in 1 .. cnt do
    let order =
      ((AST.xtlo 32<rt> ord) >> (numI32 ((i - 1) * 2) 32<rt>)) .& mask2
    let order' = AST.zext oprSize order
    !!ir (tmps.[i - 1] := AST.xtlo 32<rt> (tSrc >> (order' .* n32)))
  done
  !!ir (tDst := AST.concatArr tmps)
  !!ir (dstA := AST.xtlo 64<rt> tDst)
  !!ir (dstB := AST.xthi 64<rt> tDst)
  !>ir insLen

let pshuflw ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src, imm) = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
  let srcB, srcA = transOprToExpr128 ins insLen ctxt src
  let imm = transOprToExpr ins insLen ctxt imm
  !<ir insLen
  let tmps = Array.init 4 (fun _ -> !*ir 16<rt>)
  let n16 = numI32 16 64<rt>
  let mask2 = numI32 3 64<rt> (* 2-bit mask *)
  for i in 1 .. 4 do
    let imm =
      ((AST.xtlo 64<rt> imm) >> (numI32 ((i - 1) * 2) 64<rt>)) .& mask2
    !!ir (tmps.[i - 1] := AST.xtlo 16<rt> (srcA >> (imm .* n16)))
  done
  !!ir (dstA := AST.concatArr tmps)
  !!ir (dstB := srcB)
  !>ir insLen

let pshufhw ins insLen ctxt =
  let struct (dst, src, imm) = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
  let srcB, srcA = transOprToExpr128 ins insLen ctxt src
  let imm = transOprToExpr ins insLen ctxt imm
  let ir = IRBuilder (8)
  !<ir insLen
  let tmps = Array.init 4 (fun _ -> !*ir 16<rt>)
  let n16 = numI32 16 64<rt>
  let mask2 = numI32 3 64<rt> (* 2-bit mask *)
  for i in 1 .. 4 do
    let imm =
      ((AST.xtlo 64<rt> imm) >> (numI32 ((i - 1) * 2) 64<rt>)) .& mask2
    !!ir (tmps.[i - 1] := AST.xtlo 16<rt> (srcB >> (imm .* n16)))
  done
  !!ir (dstA := srcA)
  !!ir (dstB := AST.concatArr tmps)
  !>ir insLen

let pshufb ins insLen ctxt =
  let oprSize = getOperationSize ins
  let cnt = RegType.toBitWidth oprSize / 8
  let ir = IRBuilder (2 * cnt)
  !<ir insLen
  let tmps = Array.init cnt (fun _ -> !*ir 8<rt>)
  let mask = numI32 (cnt - 1) 8<rt>
  let genTmps dst src =
    for i in 0 .. cnt - 1 do
      let cond = AST.extract src 1<rt> (i * 8 + 7)
      let idx = (AST.extract src 8<rt> (i * 8)) .& mask
      let numShift = AST.zext oprSize idx .* numI32 8 oprSize
      !!ir
        (tmps.[i] :=
          AST.ite cond (AST.num0 8<rt>) (AST.xtlo 8<rt> (dst >> numShift)))
    done
  match oprSize with
  | 64<rt> ->
    let struct (dst, src) = transTwoOprs ins insLen ctxt
    genTmps dst src
    !!ir (dst := AST.concatArr tmps)
  | 128<rt> ->
    let struct (dst, src) = getTwoOprs ins
    let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
    let srcB, srcA = transOprToExpr128 ins insLen ctxt src
    let struct (conDst, conSrc) = tmpVars2 ir oprSize
    let tDst = !*ir oprSize
    !!ir (conDst := AST.concat dstB dstA)
    !!ir (conSrc := AST.concat srcB srcA)
    genTmps conDst conSrc
    !!ir (tDst := AST.concatArr tmps)
    !!ir (dstA := AST.xtlo 64<rt> tDst)
    !!ir (dstB := AST.xthi 64<rt> tDst)
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let movdqa ins insLen ctxt =
  buildMove ins insLen ctxt 4

let movdqu ins insLen ctxt =
  buildMove ins insLen ctxt 4

let movq2dq ins insLen ctxt =
  let ir = IRBuilder (4)
  let struct (dst, src) = getTwoOprs ins
  let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
  let src = transOprToExpr ins insLen ctxt src
  !<ir insLen
  !!ir (dstA := src)
  !!ir (dstB := AST.num0 64<rt>)
  !>ir insLen

let movdq2q ins insLen ctxt =
  let ir = IRBuilder (4)
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr ins insLen ctxt dst
  let _, srcA = transOprToExpr128 ins insLen ctxt src
  !<ir insLen
  !!ir (dst := srcA)
  !>ir insLen

let private opPmuludq _ =
  let low32 expr = expr .& numI64 0xffffffffL 64<rt>
  Array.map2 (fun e1 e2 -> low32 e1 .* low32 e2)

let pmuludq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 64<rt> opPmuludq 8

let paddq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 64<rt> (opP (.+)) 8

let psubq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 64<rt> opPsub 8

let private shiftDQ ins insLen ctxt shift =
  let ir = IRBuilder (8)
  let struct (dst, cnt) = getTwoOprs ins
  let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
  let cnt = transOprToExpr ins insLen ctxt cnt |> castNum 8<rt>
  let oprSize = getOperationSize ins
  let t1 = !*ir 8<rt>
  let struct (t2, tDst) = tmpVars2 ir oprSize
  !<ir insLen
  !!ir (t1 := AST.ite (AST.lt (numU32 15u 8<rt>) cnt) (numU32 16u 8<rt>) cnt)
  !!ir (t2 := AST.concat dstB dstA)
  !!ir (tDst := (shift t2 (AST.zext oprSize (t1 .* numU32 8u 8<rt>))))
  !!ir (dstA := AST.xtlo 64<rt> tDst)
  !!ir (dstB := AST.xthi 64<rt> tDst)
  !>ir insLen

let pslldq ins insLen ctxt =
  shiftDQ ins insLen ctxt (<<)

let psrldq ins insLen ctxt =
  shiftDQ ins insLen ctxt (>>)

let punpckhqdq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 64<rt> opPunpckHigh 8

let punpcklqdq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 64<rt> opPunpckLow 8

let movntq ins insLen ctxt = buildMove ins insLen ctxt 4

let movntps ins insLen ctxt = buildMove ins insLen ctxt 4

let movntpd ins insLen ctxt = buildMove ins insLen ctxt 4

let movntdq ins insLen ctxt = buildMove ins insLen ctxt 4

let movnti ins insLen ctxt = buildMove ins insLen ctxt 4

let lddqu ins insLen ctxt = buildMove ins insLen ctxt 4

let movshdup ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insLen ctxt dst
  let src2, src1 = transOprToExpr128 ins insLen ctxt src
  let struct (tmp1, tmp2) = tmpVars2 ir 32<rt>
  !<ir insLen
  !!ir (tmp1 := AST.xthi 32<rt> src1)
  !!ir (tmp2 := AST.xthi 32<rt> src2)
  !!ir (AST.xtlo 32<rt> dst1 := tmp1)
  !!ir (AST.xthi 32<rt> dst1 := tmp1)
  !!ir (AST.xtlo 32<rt> dst2 := tmp2)
  !!ir (AST.xthi 32<rt> dst2 := tmp2)
  !>ir insLen

let movsldup ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src) = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insLen ctxt dst
  let src2, src1 = transOprToExpr128 ins insLen ctxt src
  let struct (tmp1, tmp2) = tmpVars2 ir 32<rt>
  !<ir insLen
  !!ir (tmp1 := AST.xtlo 32<rt> src1)
  !!ir (tmp2 := AST.xtlo 32<rt> src2)
  !!ir (AST.xtlo 32<rt> dst1 := tmp1)
  !!ir (AST.xthi 32<rt> dst1 := tmp1)
  !!ir (AST.xtlo 32<rt> dst2 := tmp2)
  !!ir (AST.xthi 32<rt> dst2 := tmp2)
  !>ir insLen

let movddup ins insLen ctxt =
  let ir = IRBuilder (4)
  let struct (dst, src) = getTwoOprs ins
  let dst1, dst0 = transOprToExpr128 ins insLen ctxt dst
  let src = transOprToExpr64 ins insLen ctxt src
  !<ir insLen
  !!ir (dst0 := src)
  !!ir (dst1 := src)
  !>ir insLen

let palignr ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src, imm) = getThreeOprs ins
  let imm = transOprToExpr ins insLen ctxt imm
  !<ir insLen
  match getOperationSize ins with
  | 64<rt> ->
    let dst = transOprToExpr ins insLen ctxt dst
    let src = transOprToExpr ins insLen ctxt src
    let t = !*ir 128<rt>
    !!ir
      (t := (AST.concat dst src) >> (AST.zext 128<rt> (imm .* numU32 8u 64<rt>)))
    !!ir (dst := AST.xtlo 64<rt> t)
  | 128<rt> ->
    let dst1, dst2 = transOprToExpr128 ins insLen ctxt dst
    let src1, src2 = transOprToExpr128 ins insLen ctxt src
    let dst = AST.concat dst1 dst2
    let src = AST.concat src1 src2
    let t = !*ir 256<rt>
    !!ir
      (t := (AST.concat dst src) >> (AST.zext 256<rt> (imm .* numU32 8u 128<rt>)))
    !!ir (dst1 := AST.extract t 64<rt> 64)
    !!ir (dst2 := AST.xtlo 64<rt> t)
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let roundsd ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src, imm) = getThreeOprs ins
  let dst = transOprToExpr64 ins insLen ctxt dst
  let src = transOprToExpr64 ins insLen ctxt src
  let imm = transOprToExpr ins insLen ctxt imm
  let rc = AST.extract (!.ctxt R.FCW) 2<rt> 10
  let tmp = !*ir 2<rt>
  let cster castKind = AST.cast castKind 64<rt> src
  !<ir insLen
  !!ir (tmp := AST.ite (AST.extract imm 1<rt> 2) rc (AST.xtlo 2<rt> imm))
  !!ir (dst := AST.num0 64<rt>)
  !!ir (dst := AST.ite (tmp == AST.num0 2<rt>) (cster CastKind.FtoIRound) dst)
  !!ir (dst := AST.ite (tmp == AST.num1 2<rt>) (cster CastKind.FtoIFloor) dst)
  !!ir (dst := AST.ite (tmp == numI32 2 2<rt>) (cster CastKind.FtoICeil) dst)
  !!ir (dst := AST.ite (tmp == numI32 3 2<rt>) (cster CastKind.FtoITrunc) dst)
  !>ir insLen

let pinsrb ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src, count) = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
  let src = transOprToExpr ins insLen ctxt src
  let count = transOprToExpr ins insLen ctxt count
  let oprSize = getOperationSize ins
  let struct (sel, mask, temp, tDst) = tmpVars4 ir oprSize
  let sel8 = sel .* numI32 8 oprSize
  !<ir insLen
  !!ir (sel := count .& numI32 0xf oprSize)
  !!ir (mask := (numI32 0x0ff oprSize) << sel8)
  !!ir (temp := (AST.zext oprSize (AST.extract src 8<rt> 0) << sel8) .& mask)
  !!ir (tDst := ((AST.concat dstB dstA) .& (AST.not mask)) .| temp)
  !!ir (dstA := AST.xtlo 64<rt> tDst)
  !!ir (dstB := AST.xthi 64<rt> tDst)
  !>ir insLen

let ptest ins insLen ctxt =
  let ir = IRBuilder (16)
  let struct (src1, src2) = getTwoOprs ins
  let src1B, src1A = transOprToExpr128 ins insLen ctxt src1
  let src2B, src2A = transOprToExpr128 ins insLen ctxt src2
  let struct (t1, t2, t3, t4) = tmpVars4 ir 64<rt>
  !<ir insLen
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
  !>ir insLen

let opPcmpeqq _ = opPcmp 64<rt> (==)

let pcmpeqq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 64<rt> opPcmpeqq 8

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
                | Num n -> BitVector.getValue n
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
  let tmps = [| for _ in 1u .. ctrl.NumElems -> !*ir 1<rt> |]
  let checkNum = numU32 ctrl.NumElems rSz
  let rec getValue idx =
    let v = AST.lt (numU32 idx rSz) (AST.ite (AST.lt checkNum reg) checkNum reg)
    if idx = ctrl.NumElems then ()
    else !!ir (tmps.[int idx] := v)
         getValue (idx + 1u)
  getValue 0u
  tmps

let private implicitValidCheck ctrl srcB srcA ir =
  let unitWidth = RegType.toBitWidth ctrl.PackSize
  let tmps = [| for _ in 1u .. ctrl.NumElems -> !*ir 1<rt> |]
  let getSrc idx e = AST.extract e ctrl.PackSize (unitWidth * idx)
  let rec getValue idx =
    if idx = int ctrl.NumElems then ()
    else
      let half = int ctrl.NumElems / 2
      let e, amount = if idx < half then srcA, idx else srcB, idx - half
      let v e = tmps.[idx - 1] .& (getSrc amount e != AST.num0 ctrl.PackSize)
      !!ir (tmps.[idx] := v e)
      getValue (idx + 1)
  !!ir (tmps.[0] := AST.b1 .& (getSrc 0 srcA != AST.num0 ctrl.PackSize))
  getValue 1
  tmps

let private genValidCheck ins insLen ctxt ctrl e1 e2 ir =
  let src1B, src1A = transOprToExpr128 ins insLen ctxt e1
  let src2B, src2A = transOprToExpr128 ins insLen ctxt e2
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

let private genBoolRes ins insLen ctrl ctxt e1 e2 (ck1: Expr []) (ck2: Expr []) j i cmp =
  let src1B, src1A = transOprToExpr128 ins insLen ctxt e1
  let src2B, src2A = transOprToExpr128 ins insLen ctxt e2
  let elemSz = RegType.fromBitWidth <| int ctrl.NumElems
  let getSrc s idx =
    let unitWidth = RegType.toBitWidth ctrl.PackSize
    let amount = unitWidth * idx
    let amount = if amount < 64 then amount else amount - 64
    AST.extract s ctrl.PackSize amount
  let b =
    let e1 = if j < int ctrl.NumElems / 2 then src1A else src1B
    let e2 = if i < int ctrl.NumElems / 2 then src2A else src2B
    (AST.ite (cmp (getSrc e1 j) (getSrc e2 i)) (AST.num1 elemSz) (AST.num0 elemSz))
  match ctrl.Agg with
  | EqualAny | Ranges ->
    AST.ite (AST.not ck1.[j] .& AST.not ck2.[i]) (AST.num0 elemSz)
      (AST.ite (AST.not ck1.[j] .| AST.not ck2.[i]) (AST.num0 elemSz) b)
  | EqualEach ->
    AST.ite (AST.not ck1.[i] .& AST.not ck2.[i]) (AST.num1 elemSz)
      (AST.ite (AST.not ck1.[i] .| AST.not ck2.[i]) (AST.num0 elemSz) b)
  | EqualOrdered ->
    AST.ite (AST.not ck1.[j] .& AST.not ck2.[i]) (AST.num1 elemSz)
      (AST.ite (AST.not ck1.[j] .& ck2.[i]) (AST.num1 elemSz)
        (AST.ite (ck1.[j] .& AST.not ck2.[i]) (AST.num0 elemSz) b))

let private aggOpr ins insLen
           ctxt ctrl src1 src2 ck1 ck2 (res1 : Expr []) ir =
  let nElem = int ctrl.NumElems
  let elemSz = RegType.fromBitWidth <| nElem
  let boolRes = genBoolRes ins insLen ctrl ctxt src2 src1 ck2 ck1
  let rangesCmp idx =
    match ctrl.Sign, idx % 2 = 0 with
    | Signed, true -> AST.sge
    | Signed, _ -> AST.sle
    | _, true -> AST.ge
    | _, _ -> AST.le
  match ctrl.Agg with
  | EqualAny ->
    for j in 0 .. nElem - 1 do
      let tRes = [| for _ in 1 .. nElem -> !*ir elemSz |]
      let boolRes i = boolRes j i (==)
      !!ir (tRes.[0] := AST.num0 elemSz .| boolRes 0)
      for i in 1 .. nElem - 1 do
        !!ir (tRes.[i] := tRes.[i - 1] .| boolRes i)
      done
      !!ir (res1.[j] := tRes.[nElem - 1] << numI32 j elemSz)
    done
  | EqualEach ->
    for i in 0 .. nElem - 1 do
      let boolRes i = boolRes i i (==)
      !!ir (res1.[i] := boolRes i << numI32 i elemSz)
    done
  | EqualOrdered ->
    for j in 0 .. nElem - 1 do
      let tRes = [| for _ in 1 .. nElem -> !*ir elemSz |]
      let boolRes k i = boolRes k i (==)
      !!ir (tRes.[0] := numI32 -1 elemSz .& boolRes j 0)
      for i in 1 .. nElem - 1 - j do
        let k = i + j
        !!ir (tRes.[i] := tRes.[i - 1] .& boolRes k i)
      done
      !!ir (res1.[j] := tRes.[nElem - 1] << numI32 j elemSz)
    done
  | Ranges ->
    for j in 0 .. nElem - 1 do
      let tRes = [| for _ in 1 .. nElem -> !*ir elemSz |]
      let cmp i = rangesCmp i
      let boolRes i = boolRes j i (cmp i)
      !!ir (tRes.[0] := AST.num0 elemSz .| (boolRes 0 .& boolRes 1))
      for i in 2 .. 2 .. nElem - 1 do
        !!ir
          (tRes.[i] := tRes.[i - 1] .| (boolRes i .& boolRes (i + 1)))
      done
      !!ir (res1.[j] := tRes.[nElem - 1] << numI32 j elemSz)
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
      (AST.ite (booRes.[i]) e2 e1) :: acc) [] [0 .. elemCnt - 1]
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
  let src1B, src1A = transOprToExpr128 ins insLen ctxt src1
  let src2B, src2A = transOprToExpr128 ins insLen ctxt src2
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
  let ir = IRBuilder (64)
  !<ir insLen
  let struct (src1, src2, imm) = getThreeOprs ins
  let imm = transOprToExpr ins insLen ctxt imm
  let ctrl = getPcmpstrInfo ins.Opcode imm
  let nElem = int ctrl.NumElems
  let elemSz = RegType.fromBitWidth <| nElem
  let ck1, ck2 = genValidCheck ins insLen ctxt ctrl src1 src2 ir
  let struct (intRes1, intRes2) = tmpVars2 ir elemSz
  let res1 = [| for _ in 1 .. nElem -> !*ir elemSz |]
  aggOpr ins insLen ctxt ctrl src1 src2 ck1 ck2 res1 ir
  !!ir (intRes1 := Array.reduce (.|) res1)
  !!ir (intRes2 := getIntRes2 intRes1 ctrl ck2)
  pcmpStrRet ins ctrl ctxt intRes2 ir
  !!ir (!.ctxt R.CF := intRes2 != AST.num0 elemSz)
  getZSFForPCMPSTR ins insLen ctrl ctxt src1 src2 ir
  !!ir (!.ctxt R.OF := AST.xtlo 1<rt> intRes2)
  !!ir (!.ctxt R.AF := AST.b0)
  !!ir (!.ctxt R.PF := AST.b0)
  !>ir insLen
