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
open B2R2.FrontEnd.BinLifter.Intel
open B2R2.FrontEnd.BinLifter.Intel.Helper
open B2R2.FrontEnd.BinLifter.Intel.LiftingUtils
open B2R2.FrontEnd.BinLifter.Intel.MMXLifter

let buildMove ins insAddr insLen ctxt bufSize =
  let builder = StmtBuilder (bufSize)
  let dst, src = getTwoOprs ins
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  match oprSize with
  | 32<rt> | 64<rt> ->
    let dst, src = transTwoOprs ins insAddr insLen ctxt (dst, src)
    builder <! (dst := src)
  | 128<rt> | 256<rt> | 512<rt> ->
    let dst = transOprToExprVec ins insAddr insLen ctxt dst
    let src = transOprToExprVec ins insAddr insLen ctxt src
    List.iter2 (fun d s -> builder <! (d := s)) dst src
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let movaps ins insAddr insLen ctxt = buildMove ins insAddr insLen ctxt 4

let movapd ins insAddr insLen ctxt = buildMove ins insAddr insLen ctxt 4

let movups ins insAddr insLen ctxt = buildMove ins insAddr insLen ctxt 4

let movupd ins insAddr insLen ctxt = buildMove ins insAddr insLen ctxt 4

let movhps ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let dst, src = getTwoOprs ins
  startMark insAddr insLen builder
  match dst, src with
  | OprMem (_, _, _, 64<rt>), OprReg r ->
    let dst = transOprToExpr ins insAddr insLen ctxt dst
    builder <! (dst := getPseudoRegVar ctxt r 2)
  | OprReg r, OprMem (_, _, _, 64<rt>)->
    let src = transOprToExpr ins insAddr insLen ctxt src
    builder <! (getPseudoRegVar ctxt r 2 := src)
  | _ -> raise InvalidOperandException
  endMark insAddr insLen builder

let movhpd ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let dst, src = getTwoOprs ins
  startMark insAddr insLen builder
  match dst, src with
  | OprReg r, OprMem _ ->
    let src = transOprToExpr ins insAddr insLen ctxt src
    builder <! (getPseudoRegVar ctxt r 2 := src)
  | OprMem _, OprReg r ->
    let dst = transOprToExpr ins insAddr insLen ctxt dst
    builder <! (dst := getPseudoRegVar ctxt r 1)
  | _ -> raise InvalidOperandException
  endMark insAddr insLen builder

let movhlps ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr128 ins insAddr insLen ctxt dst |> snd
  let src = transOprToExpr128 ins insAddr insLen ctxt src |> fst
  startMark insAddr insLen builder
  builder <! (dst := src)
  endMark insAddr insLen builder

let movlpd ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let dst, src = getTwoOprs ins
  startMark insAddr insLen builder
  match dst, src with
  | OprReg r, OprMem _ ->
    let src = transOprToExpr ins insAddr insLen ctxt src
    builder <! (getPseudoRegVar ctxt r 1 := src)
  | OprMem _, OprReg r ->
    let dst = transOprToExpr ins insAddr insLen ctxt dst
    builder <! (dst := getPseudoRegVar ctxt r 1)
  | _ -> raise InvalidOperandException
  endMark insAddr insLen builder

let movlps ins insAddr insLen ctxt = movlpd ins insAddr insLen ctxt

let movlhps ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr128 ins insAddr insLen ctxt dst |> fst
  let src = transOprToExpr128 ins insAddr insLen ctxt src |> snd
  startMark insAddr insLen builder
  builder <! (dst := src)
  endMark insAddr insLen builder

let movmskps ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr ins insAddr insLen ctxt dst
  let srcB, srcA= transOprToExpr128 ins insAddr insLen ctxt src
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  let srcA = AST.concat (AST.extract srcA 1<rt> 63) (AST.extract srcA 1<rt> 31)
  let srcB = AST.concat (AST.extract srcB 1<rt> 63) (AST.extract srcB 1<rt> 31)
  builder <! (dst := AST.zext oprSize <| AST.concat srcB srcA)
  endMark insAddr insLen builder

let movmskpd ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr ins insAddr insLen ctxt dst
  let src1, src2 = transOprToExpr128 ins insAddr insLen ctxt src
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  let src63 = AST.sext oprSize (AST.xthi 1<rt> src2)
  let src127 = (AST.sext oprSize (AST.xthi 1<rt> src1)) << AST.num1 oprSize
  builder <! (dst := src63 .| src127)
  endMark insAddr insLen builder

let movss (ins: InsInfo) insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let dst, src = getTwoOprs ins
  startMark insAddr insLen builder
  match dst, src with
  | OprReg r1, OprReg r2 ->
    let dst = getPseudoRegVar ctxt r1 1 |> AST.xtlo 32<rt>
    let src = getPseudoRegVar ctxt r2 1 |> AST.xtlo 32<rt>
    builder <! (dst := src)
  | OprReg r1, OprMem _ ->
    let dst2, dst1 = getPseudoRegVar128 ctxt r1
    let src = transOprToExpr ins insAddr insLen ctxt src
    builder <! (dstAssign 32<rt> dst1 src)
    builder <! (dst2 := AST.num0 64<rt>)
  | OprMem _ , OprReg r1 ->
    let dst = transOprToExpr ins insAddr insLen ctxt dst
    let src = getPseudoRegVar ctxt r1 1 |> AST.xtlo 32<rt>
    builder <! (dstAssign 32<rt> dst src)
  | _ -> raise InvalidOperandException
  endMark insAddr insLen builder

let movsd (ins: InsInfo) insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  if ins.Operands = Operands.NoOperand then
    GeneralLifter.movs ins insAddr insLen ctxt
  else
    let dst, src = getTwoOprs ins
    startMark insAddr insLen builder
    match dst, src with
    | OprReg r1, OprReg r2 ->
      let dst = getPseudoRegVar ctxt r1 1
      let src = getPseudoRegVar ctxt r2 1
      builder <! (dst := src)
    | OprReg r1, OprMem _ ->
      let dst2, dst1 = getPseudoRegVar128 ctxt r1
      let src = transOprToExpr ins insAddr insLen ctxt src
      builder <! (dst1 := src)
      builder <! (dst2 := AST.num0 64<rt>)
    | OprMem _ , OprReg r1 ->
      let dst = transOprToExpr ins insAddr insLen ctxt dst
      let src = getPseudoRegVar ctxt r1 1
      builder <! (dstAssign 64<rt> dst src)
    | _ -> raise InvalidOperandException
    endMark insAddr insLen builder

let addps ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> (opP AST.fadd) 8

let addpd ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> (opP AST.fadd) 8

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

let private handleScalarFPOp ins insAddr insLen ctxt sz op =
  let builder = StmtBuilder(8)
  let _dst2, dst1 =
    ins.Operands |> getFstOperand |> transOprToExpr128 ins insAddr insLen ctxt
  let src1, src2 = getTwoSrcOperands ins.Operands
  let src1 = transOprToExpr64 ins insAddr insLen ctxt src1
  let src2 =
    if sz = 32<rt> then transOprToExpr32 ins insAddr insLen ctxt src2
    else transOprToExpr64 ins insAddr insLen ctxt src2
  let dst1, src1 =
    if sz = 32<rt> then AST.xtlo 32<rt> dst1, AST.xtlo 32<rt> src1
    else dst1, src1
  let t1, t2, t3 = tmpVars3 sz
  startMark insAddr insLen builder
  builder <! (t1 := src1)
  builder <! (t2 := src2)
  builder <! (t3 := op t1 t2)
  builder <! (dst1 := t3)
  endMark insAddr insLen builder

let addss ins insAddr insLen ctxt =
  handleScalarFPOp ins insAddr insLen ctxt 32<rt> AST.fadd

let addsd ins insAddr insLen ctxt =
  handleScalarFPOp ins insAddr insLen ctxt 64<rt> AST.fadd

let subps ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> (opP AST.fsub) 8

let subpd ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let dst, src = getTwoOprs ins
  startMark insAddr insLen builder
  let dst1, dst2 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src1, src2 = transOprToExpr128 ins insAddr insLen ctxt src
  builder <! (dst1 := dst1 .- src1)
  builder <! (dst2 := dst2 .- src2)
  endMark insAddr insLen builder

let subss ins insAddr insLen ctxt =
  handleScalarFPOp ins insAddr insLen ctxt 32<rt> AST.fsub

let subsd ins insAddr insLen ctxt =
  handleScalarFPOp ins insAddr insLen ctxt 64<rt> AST.fsub

let mulps ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> (opP AST.fmul) 8

let mulpd ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> (opP AST.fmul) 8

let mulss ins insAddr insLen ctxt =
  handleScalarFPOp ins insAddr insLen ctxt 32<rt> AST.fmul

let mulsd ins insAddr insLen ctxt =
  handleScalarFPOp ins insAddr insLen ctxt 64<rt> AST.fmul

let divps ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> (opP AST.fdiv) 8

let divpd ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> (opP AST.fdiv) 8

let divss ins insAddr insLen ctxt =
  handleScalarFPOp ins insAddr insLen ctxt 32<rt> AST.fdiv

let divsd ins insAddr insLen ctxt =
  handleScalarFPOp ins insAddr insLen ctxt 64<rt> AST.fdiv

let rcpps ins insAddr insLen ctxt =
  let builder = StmtBuilder(8)
  let opr1, opr2 = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt opr1
  let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt opr2
  let dst1b, dst1a = AST.xthi 32<rt> dst1, AST.xtlo 32<rt> dst1
  let dst2b, dst2a = AST.xthi 32<rt> dst2, AST.xtlo 32<rt> dst2
  let src1b, src1a = AST.xthi 32<rt> src1, AST.xtlo 32<rt> src1
  let src2b, src2a = AST.xthi 32<rt> src2, AST.xtlo 32<rt> src2
  let tmp = AST.tmpvar 32<rt>
  let flt1 = BitVector.ofInt32 0x3f800000 32<rt> |> Num
  startMark insAddr insLen builder
  builder <! (dst1a := AST.fdiv flt1 src1a)
  builder <! (dst1b := AST.fdiv flt1 src1b)
  builder <! (dst2a := AST.fdiv flt1 src2a)
  builder <! (dst2b := AST.fdiv flt1 src2b)
  endMark insAddr insLen builder

let rcpss ins insAddr insLen ctxt =
  let builder = StmtBuilder(4)
  let opr1, opr2 = getTwoOprs ins
  let dst = transOprToExpr32 ins insAddr insLen ctxt opr1
  let src = transOprToExpr32 ins insAddr insLen ctxt opr2
  let tmp = AST.tmpvar 32<rt>
  let flt1 = BitVector.ofInt32 0x3f800000 32<rt> |> Num
  startMark insAddr insLen builder
  builder <! (dst := AST.fdiv flt1 src)
  endMark insAddr insLen builder

let sqrtps ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let opr1, opr2 = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt opr1
  let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt opr2
  let tmp1, tmp2, tmp3, tmp4 = tmpVars4 32<rt>
  startMark insAddr insLen builder
  builder <! (tmp1 := AST.xtlo 32<rt> src1)
  builder <! (tmp2 := AST.xthi 32<rt> src1)
  builder <! (tmp3 := AST.xtlo 32<rt> src2)
  builder <! (tmp4 := AST.xthi 32<rt> src2)
  builder <! (AST.xtlo 32<rt> dst1 := AST.unop UnOpType.FSQRT tmp1)
  builder <! (AST.xthi 32<rt> dst1 := AST.unop UnOpType.FSQRT tmp2)
  builder <! (AST.xtlo 32<rt> dst2 := AST.unop UnOpType.FSQRT tmp3)
  builder <! (AST.xthi 32<rt> dst2 := AST.unop UnOpType.FSQRT tmp4)
  endMark insAddr insLen builder

let sqrtpd ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let opr1, opr2 = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt opr1
  let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt opr2
  startMark insAddr insLen builder
  builder <! (dst1 := AST.unop UnOpType.FSQRT src1)
  builder <! (dst2 := AST.unop UnOpType.FSQRT src2)
  endMark insAddr insLen builder

let sqrtss ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let opr1, opr2 = getTwoOprs ins
  let dst = transOprToExpr32 ins insAddr insLen ctxt opr1
  let src = transOprToExpr32 ins insAddr insLen ctxt opr2
  startMark insAddr insLen builder
  builder <! (dst := AST.unop UnOpType.FSQRT src)
  endMark insAddr insLen builder

let sqrtsd ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let opr1, opr2 = getTwoOprs ins
  let dst = transOprToExpr64 ins insAddr insLen ctxt opr1
  let src = transOprToExpr64 ins insAddr insLen ctxt opr2
  startMark insAddr insLen builder
  builder <! (dst := AST.unop UnOpType.FSQRT src)
  endMark insAddr insLen builder

let rsqrtps ins insAddr insLen ctxt =
  let builder = StmtBuilder(16)
  let opr1, opr2 = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt opr1
  let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt opr2
  let dst1b, dst1a = AST.xthi 32<rt> dst1, AST.xtlo 32<rt> dst1
  let dst2b, dst2a = AST.xthi 32<rt> dst2, AST.xtlo 32<rt> dst2
  let src1b, src1a = AST.xthi 32<rt> src1, AST.xtlo 32<rt> src1
  let src2b, src2a = AST.xthi 32<rt> src2, AST.xtlo 32<rt> src2
  let tmp = AST.tmpvar 32<rt>
  let flt1 = BitVector.ofInt32 0x3f800000 32<rt> |> Num
  startMark insAddr insLen builder
  builder <! (tmp := AST.unop UnOpType.FSQRT src1a)
  builder <! (dst1a := AST.fdiv flt1 tmp)
  builder <! (tmp := AST.unop UnOpType.FSQRT src1b)
  builder <! (dst1b := AST.fdiv flt1 tmp)
  builder <! (tmp := AST.unop UnOpType.FSQRT src2a)
  builder <! (dst2a := AST.fdiv flt1 tmp)
  builder <! (tmp := AST.unop UnOpType.FSQRT src2b)
  builder <! (dst2b := AST.fdiv flt1 tmp)
  endMark insAddr insLen builder

let rsqrtss ins insAddr insLen ctxt =
  let builder = StmtBuilder(4)
  let opr1, opr2 = getTwoOprs ins
  let dst = transOprToExpr32 ins insAddr insLen ctxt opr1
  let src = transOprToExpr32 ins insAddr insLen ctxt opr2
  let tmp = AST.tmpvar 32<rt>
  let flt1 = BitVector.ofInt32 0x3f800000 32<rt> |> Num
  startMark insAddr insLen builder
  builder <! (tmp := AST.unop UnOpType.FSQRT src)
  builder <! (dst := AST.fdiv flt1 tmp)
  endMark insAddr insLen builder

let private minMaxPS ins insAddr insLen ctxt compare =
  let builder = StmtBuilder (16)
  let dst, src = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
  let dst1A, dst1B = AST.xtlo 32<rt> dst1, AST.xthi 32<rt> dst1
  let dst2A, dst2B = AST.xtlo 32<rt> dst2, AST.xthi 32<rt> dst2
  let src1A, src1B = AST.xtlo 32<rt> src1, AST.xthi 32<rt> src1
  let src2A, src2B = AST.xtlo 32<rt> src2, AST.xthi 32<rt> src2
  let val4, val3, val2, val1 = tmpVars4 32<rt>
  startMark insAddr insLen builder
  builder <! (val1 := AST.ite (compare dst1A src1A) dst1A src1A)
  builder <! (val2 := AST.ite (compare dst1B src1B) dst1B src1B)
  builder <! (val3 := AST.ite (compare dst2A src2A) dst2A src2A)
  builder <! (val4 := AST.ite (compare dst2B src2B) dst2B src2B)
  builder <! (dst1A := val1)
  builder <! (dst1B := val2)
  builder <! (dst2A := val3)
  builder <! (dst2B := val4)
  endMark insAddr insLen builder

let private minMaxPD ins insAddr insLen ctxt compare =
  let builder = StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
  let val2, val1 = tmpVars2 64<rt>
  startMark insAddr insLen builder
  builder <! (val1 := AST.ite (compare dst1 src1) dst1 src1)
  builder <! (val2 := AST.ite (compare dst2 src2) dst2 src2)
  builder <! (dst1 := val1)
  builder <! (dst2 := val2)
  endMark insAddr insLen builder

let private minMaxSS ins insAddr insLen ctxt compare =
  let builder = StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr32 ins insAddr insLen ctxt dst
  let src = transOprToExpr32 ins insAddr insLen ctxt src
  let tmp = AST.tmpvar 32<rt>
  startMark insAddr insLen builder
  builder <! (tmp := AST.ite (compare dst src) dst src)
  builder <! (dst := tmp)
  endMark insAddr insLen builder

let private minMaxSD ins insAddr insLen ctxt compare =
  let builder = StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr64 ins insAddr insLen ctxt dst
  let src = transOprToExpr64 ins insAddr insLen ctxt src
  let tmp = AST.tmpvar 64<rt>
  startMark insAddr insLen builder
  builder <! (tmp := AST.ite (compare dst src) dst src)
  builder <! (dst := tmp)
  endMark insAddr insLen builder

let maxps ins insAddr insLen ctxt =
  minMaxPS ins insAddr insLen ctxt AST.fgt

let maxpd ins insAddr insLen ctxt =
  minMaxPD ins insAddr insLen ctxt AST.fgt

let maxss ins insAddr insLen ctxt =
  minMaxSS ins insAddr insLen ctxt AST.fgt

let maxsd ins insAddr insLen ctxt =
  minMaxSD ins insAddr insLen ctxt AST.fgt

let minps ins insAddr insLen ctxt =
  minMaxPS ins insAddr insLen ctxt AST.flt

let minpd ins insAddr insLen ctxt =
  minMaxPD ins insAddr insLen ctxt AST.flt

let minss ins insAddr insLen ctxt =
  minMaxSS ins insAddr insLen ctxt AST.flt

let minsd ins insAddr insLen ctxt =
  minMaxSD ins insAddr insLen ctxt AST.flt

let cmpps ins insAddr insLen ctxt =
  let builder = StmtBuilder (64)
  let op1, op2, op3 = getThreeOprs ins
  let dst1, dst2 = transOprToExpr128 ins insAddr insLen ctxt op1
  let src1, src2 = transOprToExpr128 ins insAddr insLen ctxt op2
  let dst1A, dst1B = AST.xtlo 32<rt> dst1, AST.xthi 32<rt> dst1
  let dst2A, dst2B = AST.xtlo 32<rt> dst2, AST.xthi 32<rt> dst2
  let imm = transOprToExpr ins insAddr insLen ctxt op3
  let isNan expr =
    (AST.extract expr 8<rt> 23  == AST.num (BitVector.unsignedMax 8<rt>))
     .& (AST.xtlo 23<rt> expr != AST.num0 23<rt>)
  let cmpCond c expr1 expr2 =
    builder <! (c := AST.b0)
    builder <! (c := AST.ite (imm == AST.num0 3<rt>) (expr1 == expr2) c)
    builder <! (c := AST.ite (imm == AST.num1 3<rt>) (AST.flt expr1  expr2) c)
    builder <! (c := AST.ite (imm == numI32 2 3<rt>) (AST.fle expr1 expr2) c)
    builder <! (c := AST.ite (imm == numI32 3 3<rt>) (isNan expr1 .| isNan expr2) c)
    builder <! (c := AST.ite (imm == numI32 4 3<rt>) (expr1 != expr2) c)
    builder <! (c := AST.ite (imm == numI32 5 3<rt>) (AST.flt expr1 expr2 |> AST.not) c)
    builder <! (c := AST.ite (imm == numI32 6 3<rt>) (AST.fle expr1 expr2 |> AST.not) c)
    builder <!
      (c := AST.ite (imm == numI32 7 3<rt>) (isNan expr1 .| isNan expr2 |> AST.not) c)
  let cond1, cond2, cond3, cond4 = tmpVars4 1<rt>
  startMark insAddr insLen builder
  cmpCond cond1 dst1A (AST.xtlo 32<rt> src1)
  cmpCond cond2 dst1B (AST.xthi 32<rt> src1)
  cmpCond cond3 dst2A (AST.xtlo 32<rt> src2)
  cmpCond cond4 dst2B (AST.xthi 32<rt> src2)
  builder <! (dst1A := AST.ite cond1 (maxNum 32<rt>) (AST.num0 32<rt>))
  builder <! (dst1B := AST.ite cond2 (maxNum 32<rt>) (AST.num0 32<rt>))
  builder <! (dst2A := AST.ite cond3 (maxNum 32<rt>) (AST.num0 32<rt>))
  builder <! (dst2B := AST.ite cond4 (maxNum 32<rt>) (AST.num0 32<rt>))
  endMark insAddr insLen builder

let cmppd ins insAddr insLen ctxt =
  let builder = StmtBuilder (32)
  let op1, op2, op3 = getThreeOprs ins
  let dst1, dst2 = transOprToExpr128 ins insAddr insLen ctxt op1
  let src1, src2 = transOprToExpr128 ins insAddr insLen ctxt op2
  let imm = transOprToExpr ins insAddr insLen ctxt op3
  let isNan expr =
    (AST.extract expr 11<rt> 52  == AST.num (BitVector.unsignedMax 11<rt>))
     .& (AST.xtlo 52<rt> expr != AST.num0 52<rt>)
  let cmpCond c expr1 expr2 =
    builder <! (c := AST.b0)
    builder <! (c := AST.ite (imm == AST.num0 3<rt>) (expr1 == expr2) c)
    builder <! (c := AST.ite (imm == AST.num1 3<rt>) (AST.flt expr1  expr2) c)
    builder <! (c := AST.ite (imm == numI32 2 3<rt>) (AST.fle expr1 expr2) c)
    builder <! (c := AST.ite (imm == numI32 3 3<rt>) (isNan expr1 .| isNan expr2) c)
    builder <! (c := AST.ite (imm == numI32 4 3<rt>) (expr1 != expr2) c)
    builder <! (c := AST.ite (imm == numI32 5 3<rt>) (AST.flt expr1 expr2 |> AST.not) c)
    builder <! (c := AST.ite (imm == numI32 6 3<rt>) (AST.fle expr1 expr2 |> AST.not) c)
    builder <!
      (c := AST.ite (imm == numI32 7 3<rt>) (isNan expr1 .| isNan expr2 |> AST.not) c)
  let cond1, cond2 = tmpVars2 1<rt>
  startMark insAddr insLen builder
  cmpCond cond1 dst1 src1
  cmpCond cond2 dst2 src2
  builder <! (dst1 := AST.ite cond1 (maxNum 64<rt>) (AST.num0 64<rt>))
  builder <! (dst2 := AST.ite cond2 (maxNum 64<rt>) (AST.num0 64<rt>))
  endMark insAddr insLen builder

let cmpss ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let dst, src, imm = getThreeOprs ins
  let dst = transOprToExpr32 ins insAddr insLen ctxt dst
  let src = transOprToExpr32 ins insAddr insLen ctxt src
  let imm = transOprToExpr ins insAddr insLen ctxt imm |> AST.xtlo 8<rt>
  let n num = numI32 num 8<rt>
  let max32 = maxNum 32<rt>
  let isNan expr =
    (AST.extract expr 8<rt> 23  == AST.num (BitVector.unsignedMax 8<rt>))
     .& (AST.xtlo 23<rt> expr != AST.num0 23<rt>)
  let cond = AST.tmpvar 1<rt>
  startMark insAddr insLen builder
  builder <! (cond := (dst == src))
  builder <! (cond := AST.ite (imm == n 1) (AST.flt dst src) cond)
  builder <! (cond := AST.ite (imm == n 2) (AST.fle dst src) cond)
  builder <! (cond := AST.ite (imm == n 3) ((isNan dst) .| (isNan src)) cond)
  builder <! (cond := AST.ite (imm == n 4) (dst != src) cond)
  builder <! (cond := AST.ite (imm == n 5) (AST.flt dst src |> AST.not) cond)
  builder <! (cond := AST.ite (imm == n 6) (AST.fle dst src |> AST.not) cond)
  builder <! (cond := AST.ite (imm == n 7)
                          ((isNan dst) .| (isNan src) |> AST.not) cond)
  builder <! (dst := AST.ite cond max32 (AST.num0 32<rt>))
  endMark insAddr insLen builder

let cmpsd ins insAddr insLen ctxt =
  match ins.Operands with
  | NoOperand -> GeneralLifter.cmps ins insAddr insLen ctxt
  | ThreeOperands (dst, src, imm) ->
    let builder = StmtBuilder (16)
    let dst = transOprToExpr64 ins insAddr insLen ctxt dst
    let src = transOprToExpr64 ins insAddr insLen ctxt src
    let imm = transOprToExpr ins insAddr insLen ctxt imm |> AST.xtlo 8<rt>
    let n i = numI32 i 8<rt>
    let max64 = maxNum 64<rt>
    let isNan expr =
      (AST.extract expr 11<rt> 52  == AST.num (BitVector.unsignedMax 11<rt>))
       .& (AST.xtlo 52<rt> expr != AST.num0 52<rt>)
    let cond = AST.tmpvar 1<rt>
    startMark insAddr insLen builder
    builder <! (cond := (dst == src))
    builder <! (cond := AST.ite (imm == n 1) (AST.flt dst src) cond)
    builder <! (cond := AST.ite (imm == n 2) (AST.fle dst src) cond)
    builder <! (cond := AST.ite (imm == n 3) ((isNan dst) .| (isNan src)) cond)
    builder <! (cond := AST.ite (imm == n 4) (dst != src) cond)
    builder <! (cond := AST.ite (imm == n 5) (AST.flt dst src |> AST.not) cond)
    builder <! (cond := AST.ite (imm == n 6) (AST.fle dst src |> AST.not) cond)
    builder <! (cond := AST.ite (imm == n 7)
                            ((isNan dst) .| (isNan src) |> AST.not) cond)
    builder <! (dst := AST.ite cond max64 (AST.num0 64<rt>))
    endMark insAddr insLen builder
  | _ -> raise InvalidOperandException

let comiss ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let opr1, opr2 = getTwoOprs ins
  let opr1 = transOprToExpr32 ins insAddr insLen ctxt opr1
  let opr2 = transOprToExpr32 ins insAddr insLen ctxt opr2
  let lblNan = AST.symbol "IsNan"
  let lblExit = AST.symbol "Exit"
  let zf = getRegVar ctxt R.ZF
  let pf = getRegVar ctxt R.PF
  let cf = getRegVar ctxt R.CF
  startMark insAddr insLen builder
  builder <! (zf := AST.ite (opr1 == opr2) AST.b1 AST.b0)
  builder <! (pf := AST.b0)
  builder <! (cf := AST.ite (AST.flt opr1 opr2) AST.b1 AST.b0)
  let isNan expr =
    (AST.extract expr 8<rt> 23  == AST.num (BitVector.unsignedMax 8<rt>))
     .& (AST.xtlo 23<rt> expr != AST.num0 23<rt>)
  builder <! (CJmp (isNan opr1 .| isNan opr2, Name lblNan, Name lblExit))
  builder <! (LMark lblNan)
  builder <! (zf := AST.b1)
  builder <! (pf := AST.b1)
  builder <! (cf := AST.b1)
  builder <! (LMark lblExit)
  builder <! (getRegVar ctxt R.OF := AST.b0)
  builder <! (getRegVar ctxt R.AF := AST.b0)
  builder <! (getRegVar ctxt R.SF := AST.b0)
  endMark insAddr insLen builder

let comisd ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let opr1, opr2 = getTwoOprs ins
  let opr1 = transOprToExpr64 ins insAddr insLen ctxt opr1
  let opr2 = transOprToExpr64 ins insAddr insLen ctxt opr2
  let lblNan = AST.symbol "IsNan"
  let lblExit = AST.symbol "Exit"
  let zf = getRegVar ctxt R.ZF
  let pf = getRegVar ctxt R.PF
  let cf = getRegVar ctxt R.CF
  startMark insAddr insLen builder
  builder <! (zf := AST.ite (opr1 == opr2) AST.b1 AST.b0)
  builder <! (pf := AST.b0)
  builder <! (cf := AST.ite (AST.flt opr1 opr2) AST.b1 AST.b0)
  let isNan expr =
    (AST.extract expr 11<rt> 52  == AST.num (BitVector.unsignedMax 11<rt>))
     .& (AST.xtlo 52<rt> expr != AST.num0 52<rt>)
  builder <! (CJmp (isNan opr1 .| isNan opr2, Name lblNan, Name lblExit))
  builder <! (LMark lblNan)
  builder <! (zf := AST.b1)
  builder <! (pf := AST.b1)
  builder <! (cf := AST.b1)
  builder <! (LMark lblExit)
  builder <! (getRegVar ctxt R.OF := AST.b0)
  builder <! (getRegVar ctxt R.AF := AST.b0)
  builder <! (getRegVar ctxt R.SF := AST.b0)
  endMark insAddr insLen builder

let ucomiss ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let opr1, opr2 = getTwoOprs ins
  let opr1 = transOprToExpr32 ins insAddr insLen ctxt opr1
  let opr2 = transOprToExpr32 ins insAddr insLen ctxt opr2
  let lblNan = AST.symbol "IsNan"
  let lblExit = AST.symbol "Exit"
  let zf = getRegVar ctxt R.ZF
  let pf = getRegVar ctxt R.PF
  let cf = getRegVar ctxt R.CF
  startMark insAddr insLen builder
  builder <! (zf := AST.ite (opr1 == opr2) AST.b1 AST.b0)
  builder <! (pf := AST.b0)
  builder <! (cf := AST.ite (AST.flt opr1 opr2) AST.b1 AST.b0)
  let isNan expr =
    (AST.extract expr 8<rt> 23  == AST.num (BitVector.unsignedMax 8<rt>))
     .& (AST.xtlo 23<rt> expr != AST.num0 23<rt>)
  builder <! (CJmp (isNan opr1 .| isNan opr2, Name lblNan, Name lblExit))
  builder <! (LMark lblNan)
  builder <! (zf := AST.b1)
  builder <! (pf := AST.b1)
  builder <! (cf := AST.b1)
  builder <! (LMark lblExit)
  builder <! (getRegVar ctxt R.OF := AST.b0)
  builder <! (getRegVar ctxt R.AF := AST.b0)
  builder <! (getRegVar ctxt R.SF := AST.b0)
  endMark insAddr insLen builder

let ucomisd ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let opr1, opr2 = getTwoOprs ins
  let opr1 = transOprToExpr64 ins insAddr insLen ctxt opr1
  let opr2 = transOprToExpr64 ins insAddr insLen ctxt opr2
  let lblNan = AST.symbol "IsNan"
  let lblExit = AST.symbol "Exit"
  let zf = getRegVar ctxt R.ZF
  let pf = getRegVar ctxt R.PF
  let cf = getRegVar ctxt R.CF
  startMark insAddr insLen builder
  builder <! (zf := AST.ite (opr1 == opr2) AST.b1 AST.b0)
  builder <! (pf := AST.b0)
  builder <! (cf := AST.ite (AST.flt opr1 opr2) AST.b1 AST.b0)
  let isNan expr =
    (AST.extract expr 11<rt> 52  == AST.num (BitVector.unsignedMax 11<rt>))
     .& (AST.xtlo 52<rt> expr != AST.num0 52<rt>)
  builder <! (CJmp (isNan opr1 .| isNan opr2, Name lblNan, Name lblExit))
  builder <! (LMark lblNan)
  builder <! (zf := AST.b1)
  builder <! (pf := AST.b1)
  builder <! (cf := AST.b1)
  builder <! (LMark lblExit)
  builder <! (getRegVar ctxt R.OF := AST.b0)
  builder <! (getRegVar ctxt R.AF := AST.b0)
  builder <! (getRegVar ctxt R.SF := AST.b0)
  endMark insAddr insLen builder

let andps ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> opPand 16

let andpd ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opPand 16

let andnps ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> opPandn 8

let andnpd ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opPandn 8

let orps ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> opPor 16

let orpd ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opPor 16

let private opPxor _ = Array.map2 (.|)

let xorps ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> opPxor 16

let xorpd ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opPxor 16

let shufps ins insAddr insLen ctxt =
  let builder = StmtBuilder (32)
  let dst, src, imm = getThreeOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
  let imm = transOprToExpr ins insAddr insLen ctxt imm
  let dst1A, dst1B = AST.xtlo 32<rt> dst1, AST.xthi 32<rt> dst1
  let dst2A, dst2B = AST.xtlo 32<rt> dst2, AST.xthi 32<rt> dst2
  let src1A, src1B = AST.xtlo 32<rt> src1, AST.xthi 32<rt> src1
  let src2A, src2B = AST.xtlo 32<rt> src2, AST.xthi 32<rt> src2
  let doShuf cond dst e0 e1 e2 e3 =
    builder <! (dst := AST.num0 32<rt>)
    builder <! (dst := AST.ite (cond == AST.num0 2<rt>) e0 dst)
    builder <! (dst := AST.ite (cond == AST.num1 2<rt>) e1 dst)
    builder <! (dst := AST.ite (cond == numI32 2 2<rt>) e2 dst)
    builder <! (dst := AST.ite (cond == numI32 3 2<rt>) e3 dst)
  let cond1 = AST.xtlo 2<rt> imm
  let cond2 = AST.extract imm 2<rt> 2
  let cond3 = AST.extract imm 2<rt> 4
  let cond4 = AST.extract imm 2<rt> 6
  let tmp1, tmp2, tmp3, tmp4 = tmpVars4 32<rt>
  startMark insAddr insLen builder
  doShuf cond1 tmp1 dst1A dst1B dst2A dst2B
  doShuf cond2 tmp2 dst1A dst1B dst2A dst2B
  doShuf cond3 tmp3 src1A src1B src2A src2B
  doShuf cond4 tmp4 src1A src1B src2A src2B
  builder <! (dst1A := tmp1)
  builder <! (dst1B := tmp2)
  builder <! (dst2A := tmp3)
  builder <! (dst2B := tmp4)
  endMark insAddr insLen builder

let shufpd ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src, imm = getThreeOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
  let imm = transOprToExpr ins insAddr insLen ctxt imm
  let cond1 = AST.xtlo 1<rt> imm
  let cond2 = AST.extract imm 1<rt> 1
  startMark insAddr insLen builder
  builder <! (dst1 := AST.ite cond1 dst2 dst1)
  builder <! (dst2 := AST.ite cond2 src2 src1)
  endMark insAddr insLen builder

let unpckhps ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src2, _src1 = transOprToExpr128 ins insAddr insLen ctxt src
  let dst1A, dst1B = AST.xtlo 32<rt> dst1, AST.xthi 32<rt> dst1
  let dst2A, dst2B = AST.xtlo 32<rt> dst2, AST.xthi 32<rt> dst2
  let src2A, src2B = AST.xtlo 32<rt> src2, AST.xthi 32<rt> src2
  startMark insAddr insLen builder
  builder <! (dst1A := dst2A)
  builder <! (dst1B := src2A)
  builder <! (dst2A := dst2B)
  builder <! (dst2B := src2B)
  endMark insAddr insLen builder

let unpckhpd ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src2, _src1 = transOprToExpr128 ins insAddr insLen ctxt src
  startMark insAddr insLen builder
  builder <! (dst1 := dst2)
  builder <! (dst2 := src2)
  endMark insAddr insLen builder

let unpcklps ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let _src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
  let _dst1A, dst1B = AST.xtlo 32<rt> dst1, AST.xthi 32<rt> dst1
  let dst2A, dst2B = AST.xtlo 32<rt> dst2, AST.xthi 32<rt> dst2
  let src1A, src1B = AST.xtlo 32<rt> src1, AST.xthi 32<rt> src1
  startMark insAddr insLen builder
  builder <! (dst2A := dst1B)
  builder <! (dst1B := src1A)
  builder <! (dst2B := src1B)
  endMark insAddr insLen builder

let unpcklpd ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let _src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
  startMark insAddr insLen builder
  builder <! (dst2 := src1)
  endMark insAddr insLen builder

let cvtpi2ps ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr64 ins insAddr insLen ctxt dst
  let src = transOprToExpr64 ins insAddr insLen ctxt src
  let tmp2, tmp1 = tmpVars2 32<rt>
  startMark insAddr insLen builder
  builder <! (tmp1 := AST.xtlo 32<rt> src)
  builder <! (tmp2 := AST.xthi 32<rt> src)
  builder <! (AST.xtlo 32<rt> dst := AST.cast CastKind.IntToFloat 32<rt> tmp1)
  builder <! (AST.xthi 32<rt> dst := AST.cast CastKind.IntToFloat 32<rt> tmp2)
  endMark insAddr insLen builder

let cvtdq2pd ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src = transOprToExpr64 ins insAddr insLen ctxt src
  let tmp1, tmp2 = tmpVars2 32<rt>
  startMark insAddr insLen builder
  builder <! (tmp1 := AST.xtlo 32<rt> src)
  builder <! (tmp2 := AST.xthi 32<rt> src)
  builder <! (dst1 := AST.cast CastKind.IntToFloat 64<rt> tmp1)
  builder <! (dst2 := AST.cast CastKind.IntToFloat 64<rt> tmp2)
  endMark insAddr insLen builder

let cvtpi2pd ins insAddr insLen ctxt = cvtdq2pd ins insAddr insLen ctxt

let cvtsi2ss ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr64 ins insAddr insLen ctxt dst
  let src = transOprToExpr ins insAddr insLen ctxt src
  startMark insAddr insLen builder
  builder <! (AST.xtlo 32<rt> dst := AST.cast CastKind.IntToFloat 32<rt> src)
  endMark insAddr insLen builder

let cvtsi2sd ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr64 ins insAddr insLen ctxt dst
  let src = transOprToExpr ins insAddr insLen ctxt src
  startMark insAddr insLen builder
  builder <! (dst := AST.cast CastKind.IntToFloat 64<rt> src)
  endMark insAddr insLen builder

let cvtps2pi ins insAddr insLen ctxt rounded =
  let builder = StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr ins insAddr insLen ctxt dst
  let src = transOprToExpr64 ins insAddr insLen ctxt src
  let tmp1, tmp2 = tmpVars2 32<rt>
  let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
  startMark insAddr insLen builder
  builder <! (tmp1 := AST.xtlo 32<rt> src)
  builder <! (tmp2 := AST.xthi 32<rt> src)
  builder <! (AST.xtlo 32<rt> dst := AST.cast castKind 32<rt> tmp1)
  builder <! (AST.xthi 32<rt> dst := AST.cast castKind 32<rt> tmp2)
  endMark insAddr insLen builder

let cvtps2pd ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src = transOprToExpr64 ins insAddr insLen ctxt src
  let tmp1, tmp2 = tmpVars2 32<rt>
  startMark insAddr insLen builder
  builder <! (tmp1 := AST.xtlo 32<rt> src)
  builder <! (tmp2 := AST.xthi 32<rt> src)
  builder <! (dst1 := AST.cast CastKind.FloatExt 64<rt> tmp1)
  builder <! (dst2 := AST.cast CastKind.FloatExt 64<rt> tmp2)
  endMark insAddr insLen builder

let cvtpd2ps ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
  startMark insAddr insLen builder
  builder <! (AST.xtlo 32<rt> dst1 := AST.cast CastKind.FloatExt 32<rt> src1)
  builder <! (AST.xthi 32<rt> dst1 := AST.cast CastKind.FloatExt 32<rt> src2)
  builder <! (dst2 := AST.num0 64<rt>)
  endMark insAddr insLen builder

let cvtpd2pi ins insAddr insLen ctxt rounded =
  let builder = StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr ins insAddr insLen ctxt dst
  let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
  let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
  startMark insAddr insLen builder
  builder <! (AST.xtlo 32<rt> dst := AST.cast castKind 32<rt> src1)
  builder <! (AST.xthi 32<rt> dst := AST.cast castKind 32<rt> src2)
  endMark insAddr insLen builder

let cvtpd2dq ins insAddr insLen ctxt rounded =
  let builder = StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
  let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
  startMark insAddr insLen builder
  builder <! (AST.xtlo 32<rt> dst1 := AST.cast castKind 32<rt> src1)
  builder <! (AST.xthi 32<rt> dst1 := AST.cast castKind 32<rt> src2)
  builder <! (dst2 := AST.num0 64<rt>)
  endMark insAddr insLen builder

let cvtdq2ps ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let dst, src = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
  let tmp1, tmp2, tmp3, tmp4 = tmpVars4 32<rt>
  startMark insAddr insLen builder
  builder <! (tmp1 := AST.xtlo 32<rt> src1)
  builder <! (tmp2 := AST.xthi 32<rt> src1)
  builder <! (tmp3 := AST.xtlo 32<rt> src2)
  builder <! (tmp4 := AST.xthi 32<rt> src2)
  builder <! (AST.xtlo 32<rt> dst1 := AST.cast CastKind.IntToFloat 32<rt> tmp1)
  builder <! (AST.xthi 32<rt> dst1 := AST.cast CastKind.IntToFloat 32<rt> tmp2)
  builder <! (AST.xtlo 32<rt> dst2 := AST.cast CastKind.IntToFloat 32<rt> tmp3)
  builder <! (AST.xthi 32<rt> dst2 := AST.cast CastKind.IntToFloat 32<rt> tmp4)
  endMark insAddr insLen builder

let cvtps2dq ins insAddr insLen ctxt rounded =
  let builder = StmtBuilder (16)
  let dst, src = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
  let tmp1, tmp2, tmp3, tmp4 = tmpVars4 32<rt>
  let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
  startMark insAddr insLen builder
  builder <! (tmp1 := AST.xtlo 32<rt> src1)
  builder <! (tmp2 := AST.xthi 32<rt> src1)
  builder <! (tmp3 := AST.xtlo 32<rt> src2)
  builder <! (tmp4 := AST.xthi 32<rt> src2)
  builder <! (AST.xtlo 32<rt> dst1 := AST.cast castKind 32<rt> tmp1)
  builder <! (AST.xthi 32<rt> dst1 := AST.cast castKind 32<rt> tmp2)
  builder <! (AST.xtlo 32<rt> dst2 := AST.cast castKind 32<rt> tmp3)
  builder <! (AST.xthi 32<rt> dst2 := AST.cast castKind 32<rt> tmp4)
  endMark insAddr insLen builder

let cvtss2si ins insAddr insLen ctxt rounded =
  let builder = StmtBuilder (4)
  let oprSize = getOperationSize ins
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr ins insAddr insLen ctxt dst
  let src = transOprToExpr32 ins insAddr insLen ctxt src
  let tmp = AST.tmpvar 32<rt>
  let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
  startMark insAddr insLen builder
  if is64bit ctxt && oprSize = 64<rt> then
    builder <! (dst := AST.cast castKind 64<rt> src)
  else
    builder <! (tmp := AST.cast castKind 32<rt> src)
    builder <! (dstAssign 32<rt> dst tmp)
  endMark insAddr insLen builder

let cvtss2sd ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr64 ins insAddr insLen ctxt dst
  let src = transOprToExpr32 ins insAddr insLen ctxt src
  startMark insAddr insLen builder
  builder <! (dst := AST.cast CastKind.FloatExt 64<rt> src)
  endMark insAddr insLen builder

let cvtsd2ss ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr64 ins insAddr insLen ctxt dst
  let src = transOprToExpr64 ins insAddr insLen ctxt src
  startMark insAddr insLen builder
  builder <! (AST.xtlo 32<rt> dst := AST.cast CastKind.FloatExt 32<rt> src)
  endMark insAddr insLen builder

let cvtsd2si ins insAddr insLen ctxt rounded =
  let builder = StmtBuilder (8)
  let oprSize = getOperationSize ins
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr ins insAddr insLen ctxt dst
  let src = transOprToExpr64 ins insAddr insLen ctxt src
  let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
  let tmp = AST.tmpvar 32<rt>
  startMark insAddr insLen builder
  if is64bit ctxt && oprSize = 64<rt> then
    builder <! (dst := AST.cast castKind 64<rt> src)
  else
    builder <! (tmp := AST.cast castKind 32<rt> src)
    builder <! dstAssign 32<rt> dst tmp
  endMark insAddr insLen builder

let ldmxcsr ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let src = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  startMark insAddr insLen builder
  builder <! (getRegVar ctxt R.MXCSR := src)
  endMark insAddr insLen builder

let stmxcsr ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let dst = getOneOpr ins |> transOneOpr ins insAddr insLen ctxt
  startMark insAddr insLen builder
  builder <! (dst := getRegVar ctxt R.MXCSR)
  endMark insAddr insLen builder

let private opAveragePackedInt (packSz: int<rt>) =
  let dblSz = packSz * 2
  let dblExt expr = AST.zext dblSz expr
  let avg e1 e2 =
    AST.extract (dblExt e1 .+ dblExt e2 .+ AST.num1 dblSz) packSz 1
  Array.map2 avg

let private opPavgb _ = opAveragePackedInt 8<rt>

let pavgb ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 8<rt> opPavgb 64

let private opPavgw _ = opAveragePackedInt 16<rt>

let pavgw ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 16<rt> opPavgw 32

let pextrw ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src, count = getThreeOprs ins
  let dst = transOprToExpr ins insAddr insLen ctxt dst
  let count =
    transOprToExpr ins insAddr insLen ctxt count
    |> AST.xtlo 8<rt> .& numU32 7u 8<rt>
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  match src with
  | OprReg reg ->
    match Register.getKind reg with
    | Register.Kind.MMX ->
      let src = transOprToExpr ins insAddr insLen ctxt src
      let srcOffset = AST.tmpvar 64<rt>
      builder <! (srcOffset := AST.zext 64<rt> count)
      let t = (src >> (srcOffset .* numU32 16u 64<rt>)) .& numU32 0xFFFFu 64<rt>
      builder <! (dstAssign oprSize dst (AST.xtlo oprSize t))
    | Register.Kind.XMM ->
      let srcB, srcA = getPseudoRegVar128 ctxt reg
      let tSrc = AST.tmpvar 128<rt>
      let srcOffset = AST.tmpvar 128<rt>
      builder <! (srcOffset := AST.zext 128<rt> count)
      builder <! (tSrc := AST.concat srcB srcA)
      let t = (tSrc >> (srcOffset .* numU32 16u 128<rt>)) .&
              numU32 0xFFFFu 128<rt>
      builder <! (dstAssign oprSize dst (AST.xtlo oprSize t))
    | _ -> raise InvalidRegisterException
  | _ -> raise InvalidOperandException
  endMark insAddr insLen builder

let pinsrw ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src, count = getThreeOprs ins
  let src = transOprToExpr ins insAddr insLen ctxt src
  let sel = AST.tmpvar 64<rt>
  let getImm = function
    | OprImm imm -> imm
    | _ -> raise InvalidOperandException
  startMark insAddr insLen builder
  match getOperationSize ins with
  | 64<rt> ->
    let dst = transOprToExpr ins insAddr insLen ctxt dst
    let count = transOprToExpr ins insAddr insLen ctxt count
    let mask = AST.tmpvar 64<rt>
    builder <! (sel := count .| numI64 3L 64<rt>)
    let pos = sel .* numU64 0x10UL 64<rt>
    builder <! (mask := (numU64 0xffffUL 64<rt>) << pos)
    builder <!
      (dst := (dst .& (AST.not mask)) .| (AST.zext 64<rt> src << pos .& mask))
  | 128<rt> ->
    let dst1, dst2 = transOprToExpr128 ins insAddr insLen ctxt dst
    let mask = AST.tmpvar 64<rt>
    let count = getImm count
    builder <! (sel := numI64 count 64<rt> .| numI64 7L 64<rt>)
    if count > 3L then
      let pos = (sel .- numI32 4 64<rt>) .* numI32 16 64<rt>
      builder <! (mask := (numU64 0xffffUL 64<rt>) << pos)
      builder <! (dst1 := (dst1 .& (AST.not mask))
                          .| (AST.zext 64<rt> src << pos .& mask))
    else
      let pos = sel .* numI32 16 64<rt>
      builder <! (mask := (numU64 0xffffUL 64<rt>) << pos)
      builder <! (dst2 := (dst2 .& (AST.not mask))
                          .| (AST.zext 64<rt> src << pos .& mask))
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let private opMaxMinPacked cmp =
  Array.map2 (fun e1 e2 -> AST.ite (cmp e1 e2) e1 e2)

let private opPmaxub _ = opMaxMinPacked AST.gt

let pmaxub ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 8<rt> opPmaxub 64

let private opPmaxsw _ = opMaxMinPacked AST.sgt

let pmaxsw ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 16<rt> opPmaxsw 32

let private opPmaxsb _ = opMaxMinPacked AST.sgt

let pmaxsb ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 8<rt> opPmaxsb 64

let opPminub _ = opMaxMinPacked AST.lt

let pminub ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 8<rt> opPminub 64

let private opPminsw _ = opMaxMinPacked AST.slt

let pminsw ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 16<rt> opPminsw 32

let opPminud _ = opMaxMinPacked AST.lt

let pminud ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> opPminud 32

let private opPminsb _ = opMaxMinPacked AST.slt

let pminsb ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 8<rt> opPminsb 32

let pmovmskb ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  let r = match src with | OprReg r -> r | _ -> raise InvalidOperandException
  let arrayInit cnt src =
    Array.init cnt (fun i -> AST.extract src 1<rt> (i * 8 + 7))
  match Register.getKind r with
  | Register.Kind.MMX ->
    let dst, src = transTwoOprs ins insAddr insLen ctxt (dst, src)
    let srcSize = AST.typeOf src
    let cnt = RegType.toByteWidth srcSize
    let tmps = arrayInit cnt src
    builder <! (dstAssign oprSize dst <| AST.zext oprSize (AST.concatArr tmps))
  | Register.Kind.XMM ->
    let dst = transOprToExpr ins insAddr insLen ctxt dst
    let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
    let srcSize = AST.typeOf srcA
    let cnt = RegType.toByteWidth srcSize
    let tmpsA = arrayInit cnt srcA
    let tmpsB = arrayInit cnt srcB
    let tmps = AST.concat (AST.concatArr tmpsB) (AST.concatArr tmpsA)
    builder <! (dstAssign oprSize dst <| AST.zext oprSize tmps)
  | Register.Kind.YMM ->
    let dst = transOprToExpr ins insAddr insLen ctxt dst
    let srcD, srcC, srcB, srcA = transOprToExpr256 ins insAddr insLen ctxt src
    let srcSize = AST.typeOf srcA
    let cnt = RegType.toByteWidth srcSize
    let tmpsA = arrayInit cnt srcA
    let tmpsB = arrayInit cnt srcB
    let tmpsC = arrayInit cnt srcC
    let tmpsD = arrayInit cnt srcD
    let tmps = AST.concat (AST.concat (AST.concatArr tmpsD) (AST.concatArr tmpsC))
                      (AST.concat (AST.concatArr tmpsB) (AST.concatArr tmpsA))
    builder <! (dstAssign oprSize dst <| AST.zext oprSize tmps)
  | _ -> raise InvalidOperandException
  endMark insAddr insLen builder

let private opPmulhuw _ = opPmul AST.xthi AST.zext 32<rt> 16<rt>

let pmulhuw ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 16<rt> opPmulhuw 32

let private opPsadbw _ =
  let abs expr = AST.ite (AST.lt expr (AST.num0 8<rt>)) (AST.neg expr) (expr)
  Array.map2 (fun e1 e2 -> abs (e1 .- e2))

let psadbw ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 8<rt> opPsadbw 64

let pshufw ins insAddr insLen ctxt =
  let dst, src, ord = getThreeOprs ins |> transThreeOprs ins insAddr insLen ctxt
  let oprSize = getOperationSize ins
  let cnt = RegType.toBitWidth oprSize / 16
  let builder = StmtBuilder (2 * cnt)
  startMark insAddr insLen builder
  let tmps = Array.init cnt (fun _ -> AST.tmpvar 16<rt>)
  let n16 = numI32 16 oprSize
  let mask2 = numI32 3 16<rt> (* 2-bit mask *)
  for i in 1 .. cnt do
    let order =
      ((AST.xtlo 16<rt> ord) >> (numI32 ((i - 1) * 2) 16<rt>)) .& mask2
    let order' = AST.zext oprSize order
    builder <! (tmps.[i - 1] := AST.xtlo 16<rt> (src >> (order' .* n16)))
  done
  builder <! (dst := AST.concatArr tmps)
  endMark insAddr insLen builder

let pshufd ins insAddr insLen ctxt =
  let dst, src, ord = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
  let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
  let ord = transOprToExpr ins insAddr insLen ctxt ord
  let oprSize = getOperationSize ins
  let cnt = RegType.toBitWidth oprSize / 32
  let builder = StmtBuilder (2 * cnt)
  startMark insAddr insLen builder
  let tmps = Array.init cnt (fun _ -> AST.tmpvar 32<rt>)
  let n32 = numI32 32 oprSize
  let mask2 = numI32 3 32<rt> (* 2-bit mask *)
  let tSrc = AST.tmpvar oprSize
  let tDst = AST.tmpvar oprSize
  builder <! (tSrc := AST.concat srcB srcA)
  for i in 1 .. cnt do
    let order =
      ((AST.xtlo 32<rt> ord) >> (numI32 ((i - 1) * 2) 32<rt>)) .& mask2
    let order' = AST.zext oprSize order
    builder <! (tmps.[i - 1] := AST.xtlo 32<rt> (tSrc >> (order' .* n32)))
  done
  builder <! (tDst := AST.concatArr tmps)
  builder <! (dstA := AST.xtlo 64<rt> tDst)
  builder <! (dstB := AST.xthi 64<rt> tDst)
  endMark insAddr insLen builder

let pshuflw ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src, imm = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
  let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
  let imm = transOprToExpr ins insAddr insLen ctxt imm
  startMark insAddr insLen builder
  let tmps = Array.init 4 (fun _ -> AST.tmpvar 16<rt>)
  let n16 = numI32 16 64<rt>
  let mask2 = numI32 3 64<rt> (* 2-bit mask *)
  for i in 1 .. 4 do
    let imm =
      ((AST.xtlo 64<rt> imm) >> (numI32 ((i - 1) * 2) 64<rt>)) .& mask2
    builder <! (tmps.[i - 1] := AST.xtlo 16<rt> (srcA >> (imm .* n16)))
  done
  builder <! (dstA := AST.concatArr tmps)
  builder <! (dstB := srcB)
  endMark insAddr insLen builder

let pshufhw ins insAddr insLen ctxt =
  let dst, src, imm = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
  let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
  let imm = transOprToExpr ins insAddr insLen ctxt imm
  let builder = StmtBuilder (8)
  startMark insAddr insLen builder
  let tmps = Array.init 4 (fun _ -> AST.tmpvar 16<rt>)
  let n16 = numI32 16 64<rt>
  let mask2 = numI32 3 64<rt> (* 2-bit mask *)
  for i in 1 .. 4 do
    let imm =
      ((AST.xtlo 64<rt> imm) >> (numI32 ((i - 1) * 2) 64<rt>)) .& mask2
    builder <! (tmps.[i - 1] := AST.xtlo 16<rt> (srcB >> (imm .* n16)))
  done
  builder <! (dstA := srcA)
  builder <! (dstB := AST.concatArr tmps)
  endMark insAddr insLen builder

let pshufb ins insAddr insLen ctxt =
  let dst, src = getTwoOprs ins
  let oprSize = getOperationSize ins
  let cnt = RegType.toBitWidth oprSize / 8
  let builder = StmtBuilder (2 * cnt)
  startMark insAddr insLen builder
  let tmps = Array.init cnt (fun _ -> AST.tmpvar 8<rt>)
  let mask = numI32 (cnt - 1) 8<rt>
  let genTmps dst src =
    for i in 0 .. cnt - 1 do
      let cond = AST.extract src 1<rt> (i * 8 + 7)
      let idx = (AST.extract src 8<rt> (i * 8)) .& mask
      let numShift = AST.zext oprSize idx .* numI32 8 oprSize
      builder <!
        (tmps.[i] :=
          AST.ite cond (AST.num0 8<rt>) (AST.xtlo 8<rt> (dst >> numShift)))
    done
  match oprSize with
  | 64<rt> ->
    let dst, src = transTwoOprs ins insAddr insLen ctxt (dst, src)
    genTmps dst src
    builder <! (dst := AST.concatArr tmps)
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
    let conDst, conSrc = tmpVars2 oprSize
    let tDst = AST.tmpvar oprSize
    builder <! (conDst := AST.concat dstB dstA)
    builder <! (conSrc := AST.concat srcB srcA)
    genTmps conDst conSrc
    builder <! (tDst := AST.concatArr tmps)
    builder <! (dstA := AST.xtlo 64<rt> tDst)
    builder <! (dstB := AST.xthi 64<rt> tDst)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let movdqa ins insAddr insLen ctxt =
  buildMove ins insAddr insLen ctxt 4

let movdqu ins insAddr insLen ctxt =
  buildMove ins insAddr insLen ctxt 4

let movq2dq ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
  let src = transOprToExpr ins insAddr insLen ctxt src
  startMark insAddr insLen builder
  builder <! (dstA := src)
  builder <! (dstB := AST.num0 64<rt>)
  endMark insAddr insLen builder

let movdq2q ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr ins insAddr insLen ctxt dst
  let _, srcA = transOprToExpr128 ins insAddr insLen ctxt src
  startMark insAddr insLen builder
  builder <! (dst := srcA)
  endMark insAddr insLen builder

let private opPmuludq _ =
  let low32 expr = expr .& numI64 0xffffffffL 64<rt>
  Array.map2 (fun e1 e2 -> low32 e1 .* low32 e2)

let pmuludq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opPmuludq 8

let paddq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> (opP (.+)) 8

let psubq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opPsub 8

let private shiftDQ ins insAddr insLen ctxt shift =
  let builder = StmtBuilder (8)
  let dst, cnt = getTwoOprs ins
  let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
  let cnt = transOprToExpr ins insAddr insLen ctxt cnt |> castNum 8<rt>
  let oprSize = getOperationSize ins
  let t1 = AST.tmpvar 8<rt>
  let t2, tDst = tmpVars2 oprSize
  startMark insAddr insLen builder
  builder <! (t1 := AST.ite (AST.lt (numU32 15u 8<rt>) cnt) (numU32 16u 8<rt>) cnt)
  builder <! (t2 := AST.concat dstB dstA)
  builder <! (tDst := (shift t2 (AST.zext oprSize (t1 .* numU32 8u 8<rt>))))
  builder <! (dstA := AST.xtlo 64<rt> tDst)
  builder <! (dstB := AST.xthi 64<rt> tDst)
  endMark insAddr insLen builder

let pslldq ins insAddr insLen ctxt =
  shiftDQ ins insAddr insLen ctxt (<<)

let psrldq ins insAddr insLen ctxt =
  shiftDQ ins insAddr insLen ctxt (>>)

let punpckhqdq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opPunpckHigh 8

let punpcklqdq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opPunpckLow 8

let movntq ins insAddr insLen ctxt = buildMove ins insAddr insLen ctxt 4

let movntps ins insAddr insLen ctxt = buildMove ins insAddr insLen ctxt 4

let movntpd ins insAddr insLen ctxt = buildMove ins insAddr insLen ctxt 4

let movntdq ins insAddr insLen ctxt = buildMove ins insAddr insLen ctxt 4

let movnti ins insAddr insLen ctxt = buildMove ins insAddr insLen ctxt 4

let lddqu ins insAddr insLen ctxt = buildMove ins insAddr insLen ctxt 4

let movshdup ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
  let tmp1, tmp2 = tmpVars2 32<rt>
  startMark insAddr insLen builder
  builder <! (tmp1 := AST.xthi 32<rt> src1)
  builder <! (tmp2 := AST.xthi 32<rt> src2)
  builder <! (AST.xtlo 32<rt> dst1 := tmp1)
  builder <! (AST.xthi 32<rt> dst1 := tmp1)
  builder <! (AST.xtlo 32<rt> dst2 := tmp2)
  builder <! (AST.xthi 32<rt> dst2 := tmp2)
  endMark insAddr insLen builder

let movsldup ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
  let tmp1, tmp2 = tmpVars2 32<rt>
  startMark insAddr insLen builder
  builder <! (tmp1 := AST.xtlo 32<rt> src1)
  builder <! (tmp2 := AST.xtlo 32<rt> src2)
  builder <! (AST.xtlo 32<rt> dst1 := tmp1)
  builder <! (AST.xthi 32<rt> dst1 := tmp1)
  builder <! (AST.xtlo 32<rt> dst2 := tmp2)
  builder <! (AST.xthi 32<rt> dst2 := tmp2)
  endMark insAddr insLen builder

let movddup ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dst1, dst0 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src = transOprToExpr64 ins insAddr insLen ctxt src
  startMark insAddr insLen builder
  builder <! (dst0 := src)
  builder <! (dst1 := src)
  endMark insAddr insLen builder

let palignr ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src, imm = getThreeOprs ins
  let imm = transOprToExpr ins insAddr insLen ctxt imm
  startMark insAddr insLen builder
  match getOperationSize ins with
  | 64<rt> ->
    let dst = transOprToExpr ins insAddr insLen ctxt dst
    let src = transOprToExpr ins insAddr insLen ctxt src
    let t = AST.tmpvar 128<rt>
    builder <!
      (t := (AST.concat dst src) >> (AST.zext 128<rt> (imm .* numU32 8u 64<rt>)))
    builder <! (dst := AST.xtlo 64<rt> t)
  | 128<rt> ->
    let dst1, dst2 = transOprToExpr128 ins insAddr insLen ctxt dst
    let src1, src2 = transOprToExpr128 ins insAddr insLen ctxt src
    let dst = AST.concat dst1 dst2
    let src = AST.concat src1 src2
    let t = AST.tmpvar 256<rt>
    builder <!
      (t := (AST.concat dst src) >> (AST.zext 256<rt> (imm .* numU32 8u 128<rt>)))
    builder <! (dst1 := AST.extract t 64<rt> 64)
    builder <! (dst2 := AST.xtlo 64<rt> t)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let roundsd ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src, imm = getThreeOprs ins
  let dst = transOprToExpr64 ins insAddr insLen ctxt dst
  let src = transOprToExpr64 ins insAddr insLen ctxt src
  let imm = transOprToExpr ins insAddr insLen ctxt imm
  let rc = AST.extract (getRegVar ctxt R.FCW) 2<rt> 10
  let tmp = AST.tmpvar 2<rt>
  let cster castKind = AST.cast castKind 64<rt> src
  startMark insAddr insLen builder
  builder <! (tmp := AST.ite (AST.extract imm 1<rt> 2) rc (AST.xtlo 2<rt> imm))
  builder <! (dst := AST.num0 64<rt>)
  builder <! (dst := AST.ite (tmp == AST.num0 2<rt>) (cster CastKind.FtoIRound) dst)
  builder <! (dst := AST.ite (tmp == AST.num1 2<rt>) (cster CastKind.FtoIFloor) dst)
  builder <! (dst := AST.ite (tmp == numI32 2 2<rt>) (cster CastKind.FtoICeil) dst)
  builder <! (dst := AST.ite (tmp == numI32 3 2<rt>) (cster CastKind.FtoITrunc) dst)
  endMark insAddr insLen builder

let pinsrb ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src, count = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
  let src, count = transTwoOprs ins insAddr insLen ctxt (src, count)
  let oprSize = getOperationSize ins
  let sel, mask, temp, tDst = tmpVars4 oprSize
  let sel8 = sel .* numI32 8 oprSize
  startMark insAddr insLen builder
  builder <! (sel := count .& numI32 0xf oprSize)
  builder <! (mask := (numI32 0x0ff oprSize) << sel8)
  builder <! (temp := (AST.zext oprSize (AST.extract src 8<rt> 0) << sel8) .& mask)
  builder <! (tDst := ((AST.concat dstB dstA) .& (AST.not mask)) .| temp)
  builder <! (dstA := AST.xtlo 64<rt> tDst)
  builder <! (dstB := AST.xthi 64<rt> tDst)
  endMark insAddr insLen builder

let ptest ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let src1, src2 = getTwoOprs ins
  let src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
  let src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt src2
  let t1, t2, t3, t4 = tmpVars4 64<rt>
  startMark insAddr insLen builder
  builder <! (t1 := src2A .& src1A)
  builder <! (t2 := src2B .& src1B)
  builder <! (getRegVar ctxt R.ZF := (t1 .| t2) == (AST.num0 64<rt>))
  builder <! (t3 := src2A .& AST.not src1A)
  builder <! (t4 := src2B .& AST.not src1B)
  builder <! (getRegVar ctxt R.CF := (t3 .| t4) == (AST.num0 64<rt>))
  builder <! (getRegVar ctxt R.AF := AST.b0)
  builder <! (getRegVar ctxt R.OF := AST.b0)
  builder <! (getRegVar ctxt R.PF := AST.b0)
  builder <! (getRegVar ctxt R.SF := AST.b0)
  endMark insAddr insLen builder

let opPcmpeqq _ = opPcmp 64<rt> (==)

let pcmpeqq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opPcmpeqq 8

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
  let immByte = match imm with
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

let private explicitValidCheck ctrl reg rSz builder =
  let tmps = [| for _ in 1u .. ctrl.NumElems -> AST.tmpvar 1<rt> |]
  let checkNum = numU32 ctrl.NumElems rSz
  let rec getValue idx =
    let v = AST.lt (numU32 idx rSz) (AST.ite (AST.lt checkNum reg) checkNum reg)
    if idx = ctrl.NumElems then ()
    else builder <! (tmps.[int idx] := v)
         getValue (idx + 1u)
  getValue 0u
  tmps

let private implicitValidCheck ctrl srcB srcA builder =
  let unitWidth = RegType.toBitWidth ctrl.PackSize
  let tmps = [| for _ in 1u .. ctrl.NumElems -> AST.tmpvar 1<rt> |]
  let getSrc idx e = AST.extract e ctrl.PackSize (unitWidth * idx)
  let rec getValue idx =
    if idx = int ctrl.NumElems then ()
    else
      let half = int ctrl.NumElems / 2
      let e, amount = if idx < half then srcA, idx else srcB, idx - half
      let v e = tmps.[idx - 1] .& (getSrc amount e != AST.num0 ctrl.PackSize)
      builder <! (tmps.[idx] := v e)
      getValue (idx + 1)
  builder <! (tmps.[0] := AST.b1 .& (getSrc 0 srcA != AST.num0 ctrl.PackSize))
  getValue 1
  tmps

let private genValidCheck ins insAddr insLen ctxt ctrl e1 e2 builder =
  let src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt e1
  let src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt e2
  match ctrl.Len with
  | Implicit -> implicitValidCheck ctrl src1B src1A builder,
                implicitValidCheck ctrl src2B src2A builder
  | Explicit ->
    let regSize, ax, dx =
      if hasREXW ins.REXPrefix
      then 64<rt>, getRegVar ctxt R.RAX, getRegVar ctxt R.RDX
      else 32<rt>, getRegVar ctxt R.EAX, getRegVar ctxt R.EDX
    explicitValidCheck ctrl ax regSize builder,
    explicitValidCheck ctrl dx regSize builder

let private genBoolRes ins insAddr insLen ctrl ctxt e1 e2 (ck1: Expr []) (ck2: Expr []) j i cmp =
  let src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt e1
  let src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt e2
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

let private aggOpr ins insAddr insLen
           ctxt ctrl src1 src2 ck1 ck2 (res1 : Expr []) builder =
  let nElem = int ctrl.NumElems
  let elemSz = RegType.fromBitWidth <| nElem
  let boolRes = genBoolRes ins insAddr insLen ctrl ctxt src2 src1 ck2 ck1
  let rangesCmp idx =
    match ctrl.Sign, idx % 2 = 0 with
    | Signed, true -> AST.sge
    | Signed, _ -> AST.sle
    | _, true -> AST.ge
    | _, _ -> AST.le
  match ctrl.Agg with
  | EqualAny ->
    for j in 0 .. nElem - 1 do
      let tRes = [| for _ in 1 .. nElem -> AST.tmpvar elemSz |]
      let boolRes i = boolRes j i (==)
      builder <! (tRes.[0] := AST.num0 elemSz .| boolRes 0)
      for i in 1 .. nElem - 1 do
        builder <! (tRes.[i] := tRes.[i - 1] .| boolRes i)
      done
      builder <! (res1.[j] := tRes.[nElem - 1] << numI32 j elemSz)
    done
  | EqualEach ->
    for i in 0 .. nElem - 1 do
      let boolRes i = boolRes i i (==)
      builder <! (res1.[i] := boolRes i << numI32 i elemSz)
    done
  | EqualOrdered ->
    for j in 0 .. nElem - 1 do
      let tRes = [| for _ in 1 .. nElem -> AST.tmpvar elemSz |]
      let boolRes k i = boolRes k i (==)
      builder <! (tRes.[0] := numI32 -1 elemSz .& boolRes j 0)
      for i in 1 .. nElem - 1 - j do
        let k = i + j
        builder <! (tRes.[i] := tRes.[i - 1] .& boolRes k i)
      done
      builder <! (res1.[j] := tRes.[nElem - 1] << numI32 j elemSz)
    done
  | Ranges ->
    for j in 0 .. nElem - 1 do
      let tRes = [| for _ in 1 .. nElem -> AST.tmpvar elemSz |]
      let cmp i = rangesCmp i
      let boolRes i = boolRes j i (cmp i)
      builder <! (tRes.[0] := AST.num0 elemSz .| (boolRes 0 .& boolRes 1))
      for i in 2 .. 2 .. nElem - 1 do
        builder <!
          (tRes.[i] := tRes.[i - 1] .| (boolRes i .& boolRes (i + 1)))
      done
      builder <! (res1.[j] := tRes.[nElem - 1] << numI32 j elemSz)
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

let private pcmpStrRet (ins: InsInfo) info ctxt intRes2 builder =
  let nElem = int info.NumElems
  let elemSz = RegType.fromBitWidth <| nElem
  match info.Ret with
  | Index ->
    let outSz, cx =
      if hasREXW ins.REXPrefix then 64<rt>, R.RCX else 32<rt>, R.ECX
    let cx = getRegVar ctxt cx
    let nMaxSz = numI32 nElem elemSz
    let idx = if info.OutSelect = Least then nElem - 1 else 0
    let out = AST.zext outSz <| genOutput info intRes2 nMaxSz idx
    builder <! (dstAssign outSz cx out)
  | Mask ->
    let xmmB, xmmA = getPseudoRegVar128 ctxt Register.XMM0
    let loop (acc1, acc2) i =
      let src = AST.extract intRes2 1<rt> i
      if (i < nElem / 2) then (acc1, (AST.zext info.PackSize src) :: acc2)
      else ((AST.zext info.PackSize src) :: acc1, acc2)
    if info.OutSelect = Least then
      builder <! (xmmA := AST.zext 64<rt> intRes2)
      builder <! (xmmB := AST.num0 64<rt>)
    else let r1, r2 = List.fold loop ([], []) [0 .. nElem - 1]
         builder <! (xmmB := AST.concatArr (List.toArray r1))
         builder <! (xmmA := AST.concatArr (List.toArray r2))

let private getZSFForPCMPSTR ins insAddr insLen ctrl ctxt src1 src2 builder =
  let src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
  let src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt src2
  let getExZSFlag r =
    let reg = getRegVar ctxt r
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
    builder <! (getRegVar ctxt R.ZF :=
      getImZSFlag AST.b0 src2B src2A (ctrl.NumElems - 1u |> int))
    builder <! (getRegVar ctxt R.SF :=
      getImZSFlag AST.b0 src1B src1A (ctrl.NumElems - 1u |> int))
  | Explicit ->
    builder <! (getRegVar ctxt R.ZF := getExZSFlag R.EDX)
    builder <! (getRegVar ctxt R.SF := getExZSFlag R.EAX)

let pcmpstr ins insAddr insLen ctxt =
  let builder = StmtBuilder (64)
  startMark insAddr insLen builder
  let src1, src2, imm = getThreeOprs ins
  let imm = transOprToExpr ins insAddr insLen ctxt imm
  let ctrl = getPcmpstrInfo ins.Opcode imm
  let nElem = int ctrl.NumElems
  let elemSz = RegType.fromBitWidth <| nElem
  let ck1, ck2 = genValidCheck ins insAddr insLen ctxt ctrl src1 src2 builder
  let intRes1, intRes2 = tmpVars2 elemSz
  let res1 = [| for _ in 1 .. nElem -> AST.tmpvar elemSz |]
  aggOpr ins insAddr insLen ctxt ctrl src1 src2 ck1 ck2 res1 builder
  builder <! (intRes1 := Array.reduce (.|) res1)
  builder <! (intRes2 := getIntRes2 intRes1 ctrl ck2)
  pcmpStrRet ins ctrl ctxt intRes2 builder
  builder <! (getRegVar ctxt R.CF := intRes2 != AST.num0 elemSz)
  getZSFForPCMPSTR ins insAddr insLen ctrl ctxt src1 src2 builder
  builder <! (getRegVar ctxt R.OF := AST.xtlo 1<rt> intRes2)
  builder <! (getRegVar ctxt R.AF := AST.b0)
  builder <! (getRegVar ctxt R.PF := AST.b0)
  endMark insAddr insLen builder
