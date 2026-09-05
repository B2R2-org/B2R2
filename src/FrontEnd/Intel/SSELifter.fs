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
open B2R2.FrontEnd.Intel.LiftingUtils
open B2R2.FrontEnd.Intel.MMXLifter

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
    if isDouble then numU64 0xfffffffffffffUL 64<rt>
    else numU64 0x7fffffUL 32<rt>
  src .& mask

let isNan isDouble expr =
  let exponent = getExponent isDouble expr
  let mantissa = getMantissa isDouble expr
  let e = if isDouble then numI32 0x7ff 32<rt> else numI32 0xff 32<rt>
  let zero = if isDouble then AST.num0 64<rt> else AST.num0 32<rt>
  (exponent == e) .& (mantissa != zero)

let addsubpd (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let struct (srcB, srcA) = transOpr128 ins bld false src
    direct dstA := AST.fsub dstA srcA
    direct dstB := AST.fadd dstB srcB
  }

let addsubps (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let struct (srcB, srcA) = transOpr128 ins bld false src
    let struct (t1, t2, t3, t4) = tmpVars4 bld 32<rt>
    direct t1 := AST.fsub (AST.xtlo 32<rt> dstA) (AST.xtlo 32<rt> srcA)
    direct t2 := AST.fadd (AST.xthi 32<rt> dstA) (AST.xthi 32<rt> srcA)
    direct t3 := AST.fsub (AST.xtlo 32<rt> dstB) (AST.xtlo 32<rt> srcB)
    direct t4 := AST.fadd (AST.xthi 32<rt> dstB) (AST.xthi 32<rt> srcB)
    direct dstA := AST.concat t2 t1
    direct dstB := AST.concat t4 t3
  }

let buildMove (ins: Instruction) bld =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packNum = 64<rt> / 64<rt>
    match oprSize with
    | 32<rt> | 64<rt> ->
      let struct (dst, src) = transTwoOprs ins bld false
      direct dst := src
    | 128<rt> | 256<rt> | 512<rt> ->
      let struct (dst, src) = getTwoOprs ins
      let src = transOprToArr ins bld false 64<rt> packNum oprSize src
      assignPackedInstr ins bld false packNum oprSize dst src
    | _ ->
      raise InvalidOperandSizeException
  }

let movaps ins bld = buildMove ins bld

let movapd ins bld = buildMove ins bld

let movups ins bld = buildMove ins bld

let movupd ins bld = buildMove ins bld

let movhps (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    match dst, src with
    | OprMem(_, _, _, 64<rt>), OprReg r ->
      let dst = transOpr ins bld false dst
      direct dst := pseudoRegVar bld r 2
    | OprReg r, OprMem(_, _, _, 64<rt>) ->
      let src = transOpr ins bld false src
      direct (pseudoRegVar bld r 2) := src
    | _ ->
      raise InvalidOperandException
  }

let movhpd (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    match dst, src with
    | OprReg r, OprMem _ ->
      let src = transOpr ins bld false src
      direct (pseudoRegVar bld r 2) := src
    | OprMem _, OprReg r ->
      let dst = transOpr ins bld false dst
      direct dst := pseudoRegVar bld r 2
    | _ ->
      raise InvalidOperandException
  }

let movhlps (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (_, dst) = transOpr128 ins bld false dst
    let struct (src, _) = transOpr128 ins bld false src
    direct dst := src
  }

let movlpd (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    match dst, src with
    | OprReg r, OprMem _ ->
      let src = transOpr ins bld false src
      direct (pseudoRegVar bld r 1) := src
    | OprMem _, OprReg r ->
      let dst = transOpr ins bld false dst
      direct dst := pseudoRegVar bld r 1
    | _ ->
      raise InvalidOperandException
  }

let movlps ins bld = movlpd ins bld

let movlhps (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (dst, _) = transOpr128 ins bld false dst
    let struct (_, src) = transOpr128 ins bld false src
    direct dst := src
  }

let movmskps (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let dst = transOpr ins bld false dst
    let struct (srcB, srcA) = transOpr128 ins bld false src
    let oprSize = getOperationSize ins
    let b0 = (srcA >> (numI32 31 64<rt>) .& (numI32 0b1 64<rt>))
    let b1 = (srcA >> (numI32 62 64<rt>) .& (numI32 0b10 64<rt>))
    let b2 = (srcB >> (numI32 29 64<rt>) .& (numI32 0b100 64<rt>))
    let b3 = (srcB >> (numI32 60 64<rt>) .& (numI32 0b1000 64<rt>))
    sized oprSize dst := b3 .| b2 .| b1 .| b0
  }

let movmskpd (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let dst = transOpr ins bld false dst
    let struct (src1, src2) = transOpr128 ins bld false src
    let oprSize = getOperationSize ins
    let src63 = AST.zext oprSize (AST.xthi 1<rt> src2)
    let src127 = (AST.zext oprSize (AST.xthi 1<rt> src1)) << AST.num1 oprSize
    sized oprSize dst := src63 .| src127
  }

let movss (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    match dst, src with
    | OprReg r1, OprReg r2 ->
      let dst = pseudoRegVar bld r1 1 |> AST.xtlo 32<rt>
      let src = pseudoRegVar bld r2 1 |> AST.xtlo 32<rt>
      direct dst := src
    | OprReg r1, OprMem _ ->
      let struct (dst2, dst1) = pseudoRegVar128 bld r1
      let src = transOpr ins bld false src
      sized 32<rt> dst1 := src
      direct dst2 := AST.num0 64<rt>
    | OprMem _, OprReg r1 ->
      let dst = transOpr ins bld false dst
      let src = pseudoRegVar bld r1 1 |> AST.xtlo 32<rt>
      sized 32<rt> dst := src
    | _ ->
      raise InvalidOperandException
  }

let movsd (ins: Instruction) bld =
  if ins.Operands = NoOperand then
    GeneralLifter.movs ins bld
  else
    lift bld ins {
      let struct (dst, src) = getTwoOprs ins
      match dst, src with
      | OprReg r1, OprReg r2 ->
        let dst = pseudoRegVar bld r1 1
        let src = pseudoRegVar bld r2 1
        direct dst := src
      | OprReg r1, OprMem _ ->
        let struct (dst2, dst1) = pseudoRegVar128 bld r1
        let src = transOpr ins bld false src
        direct dst1 := src
        direct dst2 := AST.num0 64<rt>
      | OprMem _, OprReg r1 ->
        let dst = transOpr ins bld false dst
        let src = pseudoRegVar bld r1 1
        sized 64<rt> dst := src
      | _ ->
        raise InvalidOperandException
    }

let addps ins bld =
  buildPackedInstr ins bld false 32<rt> (opP AST.fadd)

let addpd ins bld =
  buildPackedInstr ins bld false 64<rt> (opP AST.fadd)

let private getFstOperand = function
  | OneOperand o -> o
  | TwoOperands(o, _) -> o
  | ThreeOperands(o, _, _) -> o
  | FourOperands(o, _, _, _) -> o
  | _ -> raise InvalidOperandException

let private getTwoSrcOperands = function
  | TwoOperands(op1, op2) -> (op1, op2)
  | ThreeOperands(_op1, op2, op3) -> (op2, op3)
  | _ -> raise InvalidOperandException

let private handleScalarFPOp (ins: Instruction) bld sz op =
  lift bld ins {
    let struct (_dst2, dst1) =
      ins.Operands |> getFstOperand |> transOpr128 ins bld false
    let src1, src2 = getTwoSrcOperands ins.Operands
    let src1 = transOpr64 ins bld false src1
    let src2 =
      if sz = 32<rt> then transOpr32 ins bld false src2
      else transOpr64 ins bld false src2
    let dst1, src1 =
      if sz = 32<rt> then AST.xtlo 32<rt> dst1, AST.xtlo 32<rt> src1
      else dst1, src1
    let struct (t1, t2, t3) = tmpVars3 bld sz
    direct t1 := src1
    direct t2 := src2
    direct t3 := op t1 t2
    direct dst1 := t3
  }

let addss ins bld = handleScalarFPOp ins bld 32<rt> AST.fadd

let addsd ins bld = handleScalarFPOp ins bld 64<rt> AST.fadd

let subps ins bld =
  buildPackedInstr ins bld false 32<rt> (opP AST.fsub)

let subpd ins bld =
  buildPackedInstr ins bld false 64<rt> (opP AST.fsub)

let subss ins bld = handleScalarFPOp ins bld 32<rt> AST.fsub

let subsd ins bld = handleScalarFPOp ins bld 64<rt> AST.fsub

let mulps ins bld =
  buildPackedInstr ins bld false 32<rt> (opP AST.fmul)

let mulpd ins bld =
  buildPackedInstr ins bld false 64<rt> (opP AST.fmul)

let mulss ins bld = handleScalarFPOp ins bld 32<rt> AST.fmul

let mulsd ins bld = handleScalarFPOp ins bld 64<rt> AST.fmul

let divps ins bld =
  buildPackedInstr ins bld false 32<rt> (opP AST.fdiv)

let divpd ins bld =
  buildPackedInstr ins bld false 64<rt> (opP AST.fdiv)

let divss ins bld = handleScalarFPOp ins bld 32<rt> AST.fdiv

let divsd ins bld = handleScalarFPOp ins bld 64<rt> AST.fdiv

let rcpps (ins: Instruction) bld =
  lift bld ins {
    let struct (opr1, opr2) = getTwoOprs ins
    let struct (dst2, dst1) = transOpr128 ins bld false opr1
    let struct (src2, src1) = transOpr128 ins bld false opr2
    let dst1b, dst1a = AST.xthi 32<rt> dst1, AST.xtlo 32<rt> dst1
    let dst2b, dst2a = AST.xthi 32<rt> dst2, AST.xtlo 32<rt> dst2
    let src1b, src1a = AST.xthi 32<rt> src1, AST.xtlo 32<rt> src1
    let src2b, src2a = AST.xthi 32<rt> src2, AST.xtlo 32<rt> src2
    let tmp = tmpVar bld 32<rt>
    let flt1 = numI32 0x3f800000 32<rt>
    direct dst1a := AST.fdiv flt1 src1a
    direct dst1b := AST.fdiv flt1 src1b
    direct dst2a := AST.fdiv flt1 src2a
    direct dst2b := AST.fdiv flt1 src2b
  }

let rcpss (ins: Instruction) bld =
  lift bld ins {
    let struct (opr1, opr2) = getTwoOprs ins
    let dst = transOpr32 ins bld false opr1
    let src = transOpr32 ins bld false opr2
    let tmp = tmpVar bld 32<rt>
    let flt1 = numI32 0x3f800000 32<rt>
    direct dst := AST.fdiv flt1 src
  }

let sqrtps ins bld =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packNum = 64<rt> / 32<rt>
    let struct (dst, src) = getTwoOprs ins
    let src = transOprToArr ins bld false 32<rt> packNum oprSize src
    let result = Array.map (AST.unop UnOpType.FSQRT) src
    assignPackedInstr ins bld false packNum oprSize dst result
  }

let sqrtpd (ins: Instruction) bld =
  lift bld ins {
    let struct (opr1, opr2) = getTwoOprs ins
    let struct (dst2, dst1) = transOpr128 ins bld false opr1
    let struct (src2, src1) = transOpr128 ins bld false opr2
    direct dst1 := AST.unop UnOpType.FSQRT src1
    direct dst2 := AST.unop UnOpType.FSQRT src2
  }

let sqrtss (ins: Instruction) bld =
  lift bld ins {
    let struct (opr1, opr2) = getTwoOprs ins
    let dst = transOpr32 ins bld false opr1
    let src = transOpr32 ins bld false opr2
    direct dst := AST.unop UnOpType.FSQRT src
  }

let sqrtsd (ins: Instruction) bld =
  lift bld ins {
    let struct (opr1, opr2) = getTwoOprs ins
    let dst = transOpr64 ins bld false opr1
    let src = transOpr64 ins bld false opr2
    direct dst := AST.unop UnOpType.FSQRT src
  }

let rsqrtps (ins: Instruction) bld =
  lift bld ins {
    let struct (opr1, opr2) = getTwoOprs ins
    let struct (dst2, dst1) = transOpr128 ins bld false opr1
    let struct (src2, src1) = transOpr128 ins bld false opr2
    let dst1b, dst1a = AST.xthi 32<rt> dst1, AST.xtlo 32<rt> dst1
    let dst2b, dst2a = AST.xthi 32<rt> dst2, AST.xtlo 32<rt> dst2
    let src1b, src1a = AST.xthi 32<rt> src1, AST.xtlo 32<rt> src1
    let src2b, src2a = AST.xthi 32<rt> src2, AST.xtlo 32<rt> src2
    let tmp = tmpVar bld 32<rt>
    let flt1 = numI32 0x3f800000 32<rt>
    direct tmp := AST.unop UnOpType.FSQRT src1a
    direct dst1a := AST.fdiv flt1 tmp
    direct tmp := AST.unop UnOpType.FSQRT src1b
    direct dst1b := AST.fdiv flt1 tmp
    direct tmp := AST.unop UnOpType.FSQRT src2a
    direct dst2a := AST.fdiv flt1 tmp
    direct tmp := AST.unop UnOpType.FSQRT src2b
    direct dst2b := AST.fdiv flt1 tmp
  }

let rsqrtss (ins: Instruction) bld =
  lift bld ins {
    let struct (opr1, opr2) = getTwoOprs ins
    let dst = transOpr32 ins bld false opr1
    let src = transOpr32 ins bld false opr2
    let tmp = tmpVar bld 32<rt>
    let flt1 = numI32 0x3f800000 32<rt>
    direct tmp := AST.unop UnOpType.FSQRT src
    direct dst := AST.fdiv flt1 tmp
  }

let private minMaxPS (ins: Instruction) bld compare =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (dst2, dst1) = transOpr128 ins bld false dst
    let struct (src2, src1) = transOpr128 ins bld false src
    let dst1A, dst1B = AST.xtlo 32<rt> dst1, AST.xthi 32<rt> dst1
    let dst2A, dst2B = AST.xtlo 32<rt> dst2, AST.xthi 32<rt> dst2
    let src1A, src1B = AST.xtlo 32<rt> src1, AST.xthi 32<rt> src1
    let src2A, src2B = AST.xtlo 32<rt> src2, AST.xthi 32<rt> src2
    let struct (val4, val3, val2, val1) = tmpVars4 bld 32<rt>
    direct val1 := AST.ite (compare dst1A src1A) dst1A src1A
    direct val2 := AST.ite (compare dst1B src1B) dst1B src1B
    direct val3 := AST.ite (compare dst2A src2A) dst2A src2A
    direct val4 := AST.ite (compare dst2B src2B) dst2B src2B
    direct dst1A := val1
    direct dst1B := val2
    direct dst2A := val3
    direct dst2B := val4
  }

let private minMaxPD (ins: Instruction) bld compare =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (dst2, dst1) = transOpr128 ins bld false dst
    let struct (src2, src1) = transOpr128 ins bld false src
    let struct (val2, val1) = tmpVars2 bld 64<rt>
    direct val1 := AST.ite (compare dst1 src1) dst1 src1
    direct val2 := AST.ite (compare dst2 src2) dst2 src2
    direct dst1 := val1
    direct dst2 := val2
  }

let private minMaxSS (ins: Instruction) bld compare =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let dst = transOpr32 ins bld false dst
    let src = transOpr32 ins bld false src
    let tmp = tmpVar bld 32<rt>
    direct tmp := AST.ite (compare dst src) dst src
    direct dst := tmp
  }

let private minMaxSD (ins: Instruction) bld compare =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let dst = transOpr64 ins bld false dst
    let src = transOpr64 ins bld false src
    let tmp = tmpVar bld 64<rt>
    direct tmp := AST.ite (compare dst src) dst src
    direct dst := tmp
  }

let maxps ins bld = minMaxPS ins bld AST.fgt

let maxpd ins bld = minMaxPD ins bld AST.fgt

let maxss ins bld = minMaxSS ins bld AST.fgt

let maxsd ins bld = minMaxSD ins bld AST.fgt

let minps ins bld = minMaxPS ins bld AST.flt

let minpd ins bld = minMaxPD ins bld AST.flt

let minss ins bld = minMaxSS ins bld AST.flt

let minsd ins bld = minMaxSD ins bld AST.flt

let private cmppCond bld ins op3 isDbl c expr1 expr2 =
  let imm =
    transOpr ins bld false op3 |> AST.xtlo 8<rt>
    .& numI32 0x7 8<rt>
  match imm with
  | Num(bv, _) ->
    let cond =
      match bv.ToUInt64() with
      | 0UL -> expr1 == expr2
      | 1UL -> AST.flt expr1 expr2
      | 2UL -> AST.fle expr1 expr2
      | 3UL -> isNan isDbl expr1 .| isNan isDbl expr2
      | 4UL -> expr1 != expr2
      | 5UL -> AST.flt expr1 expr2 |> AST.not
      | 6UL -> AST.fle expr1 expr2 |> AST.not
      | 7UL -> (isNan isDbl expr1 .| isNan isDbl expr2) |> AST.not
      | _ -> AST.b0
    append bld { direct c := cond }
  | _ ->
    Terminator.impossible ()

let cmpps (ins: Instruction) bld =
  lift bld ins {
    let struct (op1, op2, op3) = getThreeOprs ins
    let struct (dst1, dst2) = transOpr128 ins bld false op1
    let struct (src1, src2) = transOpr128 ins bld false op2
    let dst1A, dst1B = AST.xtlo 32<rt> dst1, AST.xthi 32<rt> dst1
    let dst2A, dst2B = AST.xtlo 32<rt> dst2, AST.xthi 32<rt> dst2
    let struct (cond1, cond2, cond3, cond4) = tmpVars4 bld 1<rt>
    cmppCond bld ins op3 false cond1 dst1A (AST.xtlo 32<rt> src1)
    cmppCond bld ins op3 false cond2 dst1B (AST.xthi 32<rt> src1)
    cmppCond bld ins op3 false cond3 dst2A (AST.xtlo 32<rt> src2)
    cmppCond bld ins op3 false cond4 dst2B (AST.xthi 32<rt> src2)
    direct dst1A := AST.ite cond1 (maxNum 32<rt>) (AST.num0 32<rt>)
    direct dst1B := AST.ite cond2 (maxNum 32<rt>) (AST.num0 32<rt>)
    direct dst2A := AST.ite cond3 (maxNum 32<rt>) (AST.num0 32<rt>)
    direct dst2B := AST.ite cond4 (maxNum 32<rt>) (AST.num0 32<rt>)
  }

let cmppd (ins: Instruction) bld =
  lift bld ins {
    let struct (op1, op2, op3) = getThreeOprs ins
    let struct (dst1, dst2) = transOpr128 ins bld false op1
    let struct (src1, src2) = transOpr128 ins bld false op2
    let struct (cond1, cond2) = tmpVars2 bld 1<rt>
    cmppCond bld ins op3 true cond1 dst1 src1
    cmppCond bld ins op3 true cond2 dst2 src2
    direct dst1 := AST.ite cond1 (maxNum 64<rt>) (AST.num0 64<rt>)
    direct dst2 := AST.ite cond2 (maxNum 64<rt>) (AST.num0 64<rt>)
  }

let cmpss (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src, imm) = getThreeOprs ins
    let dst = transOpr32 ins bld false dst
    let src = transOpr32 ins bld false src
    let max32 = maxNum 32<rt>
    let cond = tmpVar bld 1<rt>
    cmppCond bld ins imm false cond dst src
    direct dst := AST.ite cond max32 (AST.num0 32<rt>)
  }

let cmpsd (ins: Instruction) bld =
  match ins.Operands with
  | NoOperand ->
    GeneralLifter.cmps ins bld
  | ThreeOperands(dst, src, imm) ->
    lift bld ins {
      let dst = transOpr64 ins bld false dst
      let src = transOpr64 ins bld false src
      let max64 = maxNum 64<rt>
      let cond = tmpVar bld 1<rt>
      cmppCond bld ins imm true cond dst src
      direct dst := AST.ite cond max64 (AST.num0 64<rt>)
    }
  | _ ->
    raise InvalidOperandException

let comiss (ins: Instruction) bld =
  lift bld ins {
    let struct (opr1, opr2) = getTwoOprs ins
    let opr1 = transOpr32 ins bld false opr1
    let opr2 = transOpr32 ins bld false opr2
    let zf = regVar bld R.ZF
    let pf = regVar bld R.PF
    let cf = regVar bld R.CF
    direct zf := AST.ite (opr1 == opr2) AST.b1 AST.b0
    direct pf := AST.b0
    direct cf := AST.ite (AST.flt opr1 opr2) AST.b1 AST.b0
    _when bld "IsNan" (isNan false opr1 .| isNan false opr2)
      (block {
        direct zf := AST.b1
        direct pf := AST.b1
        direct cf := AST.b1 })
    direct (regVar bld R.OF) := AST.b0
    direct (regVar bld R.AF) := AST.b0
    direct (regVar bld R.SF) := AST.b0
#if EMULATION
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let comisd (ins: Instruction) bld =
  lift bld ins {
    let struct (opr1, opr2) = getTwoOprs ins
    let opr1 = transOpr64 ins bld false opr1
    let opr2 = transOpr64 ins bld false opr2
    let zf = regVar bld R.ZF
    let pf = regVar bld R.PF
    let cf = regVar bld R.CF
    direct zf := AST.ite (opr1 == opr2) AST.b1 AST.b0
    direct pf := AST.b0
    direct cf := AST.ite (AST.flt opr1 opr2) AST.b1 AST.b0
    _when bld "IsNan" (isNan true opr1 .| isNan true opr2)
      (block {
        direct zf := AST.b1
        direct pf := AST.b1
        direct cf := AST.b1 })
    direct (regVar bld R.OF) := AST.b0
    direct (regVar bld R.AF) := AST.b0
    direct (regVar bld R.SF) := AST.b0
#if EMULATION
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let ucomiss (ins: Instruction) bld =
  lift bld ins {
    let struct (opr1, opr2) = getTwoOprs ins
    let opr1 = transOpr32 ins bld false opr1
    let opr2 = transOpr32 ins bld false opr2
    let zf = regVar bld R.ZF
    let pf = regVar bld R.PF
    let cf = regVar bld R.CF
    direct zf := AST.ite (opr1 == opr2) AST.b1 AST.b0
    direct pf := AST.b0
    direct cf := AST.ite (AST.flt opr1 opr2) AST.b1 AST.b0
    _when bld "IsNan" (isNan false opr1 .| isNan false opr2)
      (block {
        direct zf := AST.b1
        direct pf := AST.b1
        direct cf := AST.b1 })
    direct (regVar bld R.OF) := AST.b0
    direct (regVar bld R.AF) := AST.b0
    direct (regVar bld R.SF) := AST.b0
#if EMULATION
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let ucomisd (ins: Instruction) bld =
  lift bld ins {
    let struct (opr1, opr2) = getTwoOprs ins
    let opr1 = transOpr64 ins bld false opr1
    let opr2 = transOpr64 ins bld false opr2
    let zf = regVar bld R.ZF
    let pf = regVar bld R.PF
    let cf = regVar bld R.CF
    direct zf := AST.ite (opr1 == opr2) AST.b1 AST.b0
    direct pf := AST.b0
    direct cf := AST.ite (AST.flt opr1 opr2) AST.b1 AST.b0
    _when bld "IsNan" (isNan true opr1 .| isNan true opr2)
      (block {
        direct zf := AST.b1
        direct pf := AST.b1
        direct cf := AST.b1 })
    direct (regVar bld R.OF) := AST.b0
    direct (regVar bld R.AF) := AST.b0
    direct (regVar bld R.SF) := AST.b0
#if EMULATION
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let andps ins bld = buildPackedInstr ins bld false 32<rt> opPand

let andpd ins bld = buildPackedInstr ins bld false 64<rt> opPand

let andnps ins bld = buildPackedInstr ins bld false 32<rt> opPandn

let andnpd ins bld = buildPackedInstr ins bld false 64<rt> opPandn

let orps ins bld = buildPackedInstr ins bld false 32<rt> opPor

let orpd ins bld = buildPackedInstr ins bld false 64<rt> opPor

let private opPxor _ = Array.map2 (<+>)

let xorps ins bld = buildPackedInstr ins bld false 32<rt> opPxor

let xorpd ins bld = buildPackedInstr ins bld false 64<rt> opPxor

let shufps (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src, imm) = getThreeOprs ins
    let struct (dst2, dst1) = transOpr128 ins bld false dst
    let struct (src2, src1) = transOpr128 ins bld false src
    let imm = transOpr ins bld false imm
    let dst1A, dst1B = AST.xtlo 32<rt> dst1, AST.xthi 32<rt> dst1
    let dst2A, dst2B = AST.xtlo 32<rt> dst2, AST.xthi 32<rt> dst2
    let src1A, src1B = AST.xtlo 32<rt> src1, AST.xthi 32<rt> src1
    let src2A, src2B = AST.xtlo 32<rt> src2, AST.xthi 32<rt> src2
    let doShuf cond dst e0 e1 e2 e3 =
      append bld {
        direct dst := AST.num0 32<rt>
        direct dst := AST.ite (cond == AST.num0 8<rt>) e0 dst
        direct dst := AST.ite (cond == AST.num1 8<rt>) e1 dst
        direct dst := AST.ite (cond == numI32 2 8<rt>) e2 dst
        direct dst := AST.ite (cond == numI32 3 8<rt>) e3 dst
      }
    let cond shfAmt =
      ((AST.xtlo 8<rt> imm) >> (numI32 shfAmt 8<rt>)) .& (numI32 0b11 8<rt>)
    let struct (tmp1, tmp2, tmp3, tmp4) = tmpVars4 bld 32<rt>
    doShuf (cond 0) tmp1 dst1A dst1B dst2A dst2B
    doShuf (cond 2) tmp2 dst1A dst1B dst2A dst2B
    doShuf (cond 4) tmp3 src1A src1B src2A src2B
    doShuf (cond 6) tmp4 src1A src1B src2A src2B
    direct dst1A := tmp1
    direct dst1B := tmp2
    direct dst2A := tmp3
    direct dst2B := tmp4
  }

let shufpd (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src, imm) = getThreeOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let struct (srcB, srcA) = transOpr128 ins bld false src
    let imm = transOpr ins bld false imm
    let cond1 = AST.xtlo 1<rt> imm
    let cond2 = AST.extract imm 1<rt> 1
    let struct (src1A, src1B, src2A, src2B) = tmpVars4 bld 64<rt>
    direct src1A := dstA
    direct src1B := dstB
    direct src2A := srcA
    direct src2B := srcB
    direct dstA := AST.ite cond1 src1B src1A
    direct dstB := AST.ite cond2 src2B src2A
  }

let unpckhps (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (dst2, dst1) = transOpr128 ins bld false dst
    let struct (src2, _src1) = transOpr128 ins bld false src
    let dst1A, dst1B = AST.xtlo 32<rt> dst1, AST.xthi 32<rt> dst1
    let dst2A, dst2B = AST.xtlo 32<rt> dst2, AST.xthi 32<rt> dst2
    let src2A, src2B = AST.xtlo 32<rt> src2, AST.xthi 32<rt> src2
    direct dst1A := dst2A
    direct dst1B := src2A
    direct dst2A := dst2B
    direct dst2B := src2B
  }

let unpckhpd (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (dst2, dst1) = transOpr128 ins bld false dst
    let struct (src2, _src1) = transOpr128 ins bld false src
    direct dst1 := dst2
    direct dst2 := src2
  }

let unpcklps (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let struct (_, srcA) = transOpr128 ins bld false src
    let struct (tSrc1A, tSrc1B, tSrc2A) = tmpVars3 bld 64<rt>
    direct tSrc1A := dstA
    direct tSrc1B := dstB
    direct tSrc2A := srcA
    direct dstA := AST.concat (AST.xtlo 32<rt> tSrc2A) (AST.xtlo 32<rt> tSrc1A)
    direct dstB := AST.concat (AST.xthi 32<rt> tSrc2A) (AST.xthi 32<rt> tSrc1A)
  }

let unpcklpd (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (dst2, dst1) = transOpr128 ins bld false dst
    let struct (_src2, src1) = transOpr128 ins bld false src
    direct dst2 := src1
  }

let cvtpi2ps (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let dst = transOpr64 ins bld false dst
    let src = transOpr64 ins bld false src
    let struct (tmp2, tmp1) = tmpVars2 bld 32<rt>
    direct tmp1 := AST.xtlo 32<rt> src
    direct tmp2 := AST.xthi 32<rt> src
    direct (AST.xtlo 32<rt> dst) := AST.cast CastKind.SIntToFloat 32<rt> tmp1
    direct (AST.xthi 32<rt> dst) := AST.cast CastKind.SIntToFloat 32<rt> tmp2
  }

let cvtdq2pd (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (dst2, dst1) = transOpr128 ins bld false dst
    let src = transOpr64 ins bld false src
    let struct (tmp1, tmp2) = tmpVars2 bld 32<rt>
    direct tmp1 := AST.xtlo 32<rt> src
    direct tmp2 := AST.xthi 32<rt> src
    direct dst1 := AST.cast CastKind.SIntToFloat 64<rt> tmp1
    direct dst2 := AST.cast CastKind.SIntToFloat 64<rt> tmp2
  }

let cvtpi2pd ins bld = cvtdq2pd ins bld

let cvtsi2ss (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let dst = transOpr64 ins bld false dst
    let src = transOpr ins bld false src
    direct (AST.xtlo 32<rt> dst) := AST.cast CastKind.SIntToFloat 32<rt> src
  }

let cvtsi2sd (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let dst = transOpr64 ins bld false dst
    let src = transOpr ins bld false src
    direct dst := AST.cast CastKind.SIntToFloat 64<rt> src
  }

let cvtps2pi (ins: Instruction) bld rounded =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let dst = transOpr ins bld false dst
    let src = transOpr64 ins bld false src
    let struct (tmp1, tmp2) = tmpVars2 bld 32<rt>
    let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
    direct tmp1 := AST.xtlo 32<rt> src
    direct tmp2 := AST.xthi 32<rt> src
    direct (AST.xtlo 32<rt> dst) := AST.cast castKind 32<rt> tmp1
    direct (AST.xthi 32<rt> dst) := AST.cast castKind 32<rt> tmp2
    fillOnesToMMXHigh16 bld ins
  }

let cvtps2pd (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (dst2, dst1) = transOpr128 ins bld false dst
    let src = transOpr64 ins bld false src
    let struct (tmp1, tmp2) = tmpVars2 bld 32<rt>
    direct tmp1 := AST.xtlo 32<rt> src
    direct tmp2 := AST.xthi 32<rt> src
    direct dst1 := AST.cast CastKind.FloatCast 64<rt> tmp1
    direct dst2 := AST.cast CastKind.FloatCast 64<rt> tmp2
  }

let cvtpd2ps (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (dst2, dst1) = transOpr128 ins bld false dst
    let struct (src2, src1) = transOpr128 ins bld false src
    direct (AST.xtlo 32<rt> dst1) := AST.cast CastKind.FloatCast 32<rt> src1
    direct (AST.xthi 32<rt> dst1) := AST.cast CastKind.FloatCast 32<rt> src2
    direct dst2 := AST.num0 64<rt>
  }

let cvtpd2pi (ins: Instruction) bld rounded =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let dst = transOpr ins bld false dst
    let struct (src2, src1) = transOpr128 ins bld false src
    let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
    direct (AST.xtlo 32<rt> dst) := AST.cast castKind 32<rt> src1
    direct (AST.xthi 32<rt> dst) := AST.cast castKind 32<rt> src2
    fillOnesToMMXHigh16 bld ins
  }

let cvtpd2dq (ins: Instruction) bld rounded =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (dst2, dst1) = transOpr128 ins bld false dst
    let struct (src2, src1) = transOpr128 ins bld false src
    let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
    direct (AST.xtlo 32<rt> dst1) := AST.cast castKind 32<rt> src1
    direct (AST.xthi 32<rt> dst1) := AST.cast castKind 32<rt> src2
    direct dst2 := AST.num0 64<rt>
  }

let cvtdq2ps (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (dst2, dst1) = transOpr128 ins bld false dst
    let struct (src2, src1) = transOpr128 ins bld false src
    let struct (tmp1, tmp2, tmp3, tmp4) = tmpVars4 bld 32<rt>
    direct tmp1 := AST.xtlo 32<rt> src1
    direct tmp2 := AST.xthi 32<rt> src1
    direct tmp3 := AST.xtlo 32<rt> src2
    direct tmp4 := AST.xthi 32<rt> src2
    direct (AST.xtlo 32<rt> dst1) := AST.cast CastKind.SIntToFloat 32<rt> tmp1
    direct (AST.xthi 32<rt> dst1) := AST.cast CastKind.SIntToFloat 32<rt> tmp2
    direct (AST.xtlo 32<rt> dst2) := AST.cast CastKind.SIntToFloat 32<rt> tmp3
    direct (AST.xthi 32<rt> dst2) := AST.cast CastKind.SIntToFloat 32<rt> tmp4
  }

let cvtps2dq (ins: Instruction) bld rounded =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (dst2, dst1) = transOpr128 ins bld false dst
    let struct (src2, src1) = transOpr128 ins bld false src
    let struct (tmp1, tmp2, tmp3, tmp4) = tmpVars4 bld 32<rt>
    let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
    direct tmp1 := AST.xtlo 32<rt> src1
    direct tmp2 := AST.xthi 32<rt> src1
    direct tmp3 := AST.xtlo 32<rt> src2
    direct tmp4 := AST.xthi 32<rt> src2
    direct (AST.xtlo 32<rt> dst1) := AST.cast castKind 32<rt> tmp1
    direct (AST.xthi 32<rt> dst1) := AST.cast castKind 32<rt> tmp2
    direct (AST.xtlo 32<rt> dst2) := AST.cast castKind 32<rt> tmp3
    direct (AST.xthi 32<rt> dst2) := AST.cast castKind 32<rt> tmp4
  }

let cvtss2si (ins: Instruction) bld rounded =
  lift bld ins {
    let oprSize = getOperationSize ins
    let struct (dst, src) = getTwoOprs ins
    let dst = transOpr ins bld false dst
    let src = transOpr32 ins bld false src
    let tmp = tmpVar bld 32<rt>
    let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
    if is64bit bld && oprSize = 64<rt> then
      direct dst := AST.cast castKind 64<rt> src
    else
      direct tmp := AST.cast castKind 32<rt> src
      sized 32<rt> dst := tmp
  }

let cvtss2sd (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let dst = transOpr64 ins bld false dst
    let src = transOpr32 ins bld false src
    direct dst := AST.cast CastKind.FloatCast 64<rt> src
  }

let cvtsd2ss (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let dst = transOpr64 ins bld false dst
    let src = transOpr64 ins bld false src
    direct (AST.xtlo 32<rt> dst) := AST.cast CastKind.FloatCast 32<rt> src
  }

let cvtsd2si (ins: Instruction) bld rounded =
  lift bld ins {
    let oprSize = getOperationSize ins
    let struct (dst, src) = getTwoOprs ins
    let dst = transOpr ins bld false dst
    let src = transOpr64 ins bld false src
    let castKind = if rounded then CastKind.FtoIRound else CastKind.FtoITrunc
    let tmp = tmpVar bld 32<rt>
    if is64bit bld && oprSize = 64<rt> then
      direct dst := AST.cast castKind 64<rt> src
    else
      direct tmp := AST.cast castKind 32<rt> src
      sized 32<rt> dst := tmp
  }

let extractps (ins: Instruction) bld =
  lift bld ins {
    let oprSize = getOperationSize ins
    let struct (dst, src, imm8) = getThreeOprs ins
    let dst = transOpr ins bld false dst
    let src = transOprToArr ins bld false 32<rt> 2 128<rt> src
    let idx = getImmValue imm8 &&& 0b11L |> int
    sized oprSize dst := src[idx]
  }

let hsubpd ins bld = packedHorizon ins bld 64<rt> (opP AST.fsub)

let hsubps ins bld = packedHorizon ins bld 32<rt> (opP AST.fsub)

let haddpd ins bld = packedHorizon ins bld 64<rt> (opP AST.fadd)

let haddps ins bld = packedHorizon ins bld 32<rt> (opP AST.fadd)

let ldmxcsr (ins: Instruction) bld =
  lift bld ins {
    let src = transOneOpr ins bld
    direct (regVar bld R.MXCSR) := src
  }

let stmxcsr (ins: Instruction) bld =
  lift bld ins {
    let dst = transOneOpr ins bld
    direct dst := regVar bld R.MXCSR
  }

let private opAveragePackedInt (packSz: int<rt>) =
  let dblSz = packSz * 2
  let dblExt expr = AST.zext dblSz expr
  let avg e1 e2 =
    AST.extract (dblExt e1 .+ dblExt e2 .+ AST.num1 dblSz) packSz 1
  Array.map2 avg

let opPavgb _ = opAveragePackedInt 8<rt>

let pavgb ins bld = buildPackedInstr ins bld false 8<rt> opPavgb

let opPavgw _ = opAveragePackedInt 16<rt>

let pavgw ins bld = buildPackedInstr ins bld false 16<rt> opPavgw

let pextrb (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src, count) = getThreeOprs ins
    let count = getImmValue count
    let dExpr = transOpr ins bld false dst
    let struct (srcB, srcA) = transOpr128 ins bld false src
    let count = (count &&& 0b1111L (* COUNT[3:0] *)) * 8L
    let lAmt = numI64 (64L - (count % 64L)) 64<rt> (* Left Shift *)
    let rAmt = numI64 (count % 64L) 64<rt> (* Right Shift *)
    let result =
      let bit =
        if count < 64L then
          ((srcB << lAmt) .| (srcA >> rAmt)) .& numU32 0xFFu 64<rt>
        else
          (srcB >> rAmt) .& numU32 0xFFu 64<rt>
      bit |> AST.xtlo 8<rt>
    match dst with
    | OprReg _ -> append bld { sized 32<rt> dExpr := AST.zext 32<rt> result }
    | OprMem _ -> append bld { direct dExpr := result }
    | _ -> raise InvalidOperandException
  }

let pextrd (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src, count) = getThreeOprs ins
    let dst = transOpr ins bld false dst
    let count = getImmValue count
    let oprSize = getOperationSize ins
    match src with
    | OprReg reg ->
      let struct (srcB, srcA) = pseudoRegVar128 bld reg
      let count = (count &&& 0b11L (* COUNT[1:0] *)) * 32L
      let lAmt = numI64 (64L - (count % 64L)) 64<rt> (* Left Shift *)
      let rAmt = numI64 (count % 64L) 64<rt> (* Right Shift *)
      let result =
        if count < 64L then
          ((srcB << lAmt) .| (srcA >> rAmt)) .& numU32 0xFFFFFFFFu 64<rt>
        else
          (srcB >> rAmt) .& numU32 0xFFFFFFFFu 64<rt>
      sized oprSize dst := AST.xtlo oprSize result
    | _ ->
      raise InvalidOperandException
  }

let pextrq (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src, count) = getThreeOprs ins
    let dst = transOpr ins bld false dst
    let count = getImmValue count
    let oprSize = getOperationSize ins
    match src with
    | OprReg reg ->
      let struct (srcB, srcA) = pseudoRegVar128 bld reg
      let count = (count &&& 0b1L (* COUNT[0] *)) * 64L
      let lAmt = numI64 (64L - (count % 64L)) 64<rt> (* Left Shift *)
      let rAmt = numI64 (count % 64L) 64<rt> (* Right Shift *)
      let result =
        if count < 64L then (srcB << lAmt) .| (srcA >> rAmt)
        else srcB >> rAmt
      sized oprSize dst := AST.xtlo oprSize result
    | _ ->
      raise InvalidOperandException
  }

let pextrw ins bld =
  lift bld ins {
    let oprSize = getOperationSize ins
    let struct (dst, src, imm8) = getThreeOprs ins
    let packNum = 64<rt> / 16<rt>
    let srcSz =
      match src with
      | OprReg reg -> RegisterHelper.toRegType bld.WordSize reg
      | _ -> raise InvalidOperandException
    let d = transOpr ins bld false dst
    let src = transOprToArr ins bld false 16<rt> packNum srcSz src
    let idx = getImmValue imm8 |> int
    match dst with
    | OprMem(_, _, _, 16<rt>) ->
      let idx = idx &&& 0b111
      direct d := src[idx]
    | _ ->
      let idx = idx &&& (Array.length src - 1)
      sized oprSize d := AST.zext bld.RegType src[idx]
  }

let pinsrw (ins: Instruction) bld =
  lift bld ins {
    let packSz = 16<rt>
    let pNum = 64<rt> / packSz
    let struct (dst, src, imm8) = getThreeOprs ins
    let src = transOpr ins bld false src |> AST.xtlo packSz
    match dst with
    | OprReg reg ->
      match RegisterHelper.getKind reg with
      | RegisterHelper.Kind.MMX ->
        let index = getImmValue imm8 &&& 0b11L |> int
        let dst = transOprToArr ins bld false packSz pNum 64<rt> dst
        direct (dst[index]) := src
        fillOnesToMMXHigh16 bld ins
      | RegisterHelper.Kind.XMM ->
        let index = getImmValue imm8 &&& 0b111L |> int
        let dst = transOprToArr ins bld false packSz pNum 128<rt> dst
        direct (dst[index]) := src
      | _ ->
        raise InvalidOperandException
    | _ ->
      raise InvalidOperandSizeException
  }

let private opMaxMinPacked cmp =
  Array.map2 (fun e1 e2 -> AST.ite (cmp e1 e2) e1 e2)

let opPmaxu _ = opMaxMinPacked AST.gt

let opPminu _ = opMaxMinPacked AST.lt

let opPmaxs _ = opMaxMinPacked AST.sgt

let opPmins _ = opMaxMinPacked AST.slt

let pmaxub ins bld = buildPackedInstr ins bld false 8<rt> opPmaxu

let pmaxud ins bld = buildPackedInstr ins bld false 32<rt> opPmaxu

let pmaxuw ins bld = buildPackedInstr ins bld false 16<rt> opPmaxu

let pmaxsb ins bld = buildPackedInstr ins bld false 8<rt> opPmaxs

let pmaxsd ins bld = buildPackedInstr ins bld false 32<rt> opPmaxs

let pmaxsw ins bld = buildPackedInstr ins bld false 16<rt> opPmaxs

let pminub ins bld = buildPackedInstr ins bld false 8<rt> opPminu

let pminud ins bld = buildPackedInstr ins bld false 32<rt> opPminu

let pminuw ins bld = buildPackedInstr ins bld false 16<rt> opPminu

let pminsb ins bld = buildPackedInstr ins bld false 8<rt> opPmins

let pminsd ins bld = buildPackedInstr ins bld false 32<rt> opPmins

let pminsw ins bld = buildPackedInstr ins bld false 16<rt> opPmins

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

/// Gathers the most significant bit of every byte of the given halves into
/// one mask, the lowest half taking the lowest bits.
let private byteMask (parts: Expr[]) =
  let cnt = RegType.toByteWidth (Expr.typeOf parts[0])
  let rec join (xs: Expr[]) =
    if xs.Length = 1 then
      xs[0]
    else
      Array.init (xs.Length / 2) (fun i ->
        AST.concat xs[(2 * i) + 1] xs[2 * i])
      |> join
  parts |> Array.map (fun p -> mskArrayInit cnt p |> concatBits) |> join

let pmovmskb (ins: Instruction) bld =
  lift bld ins {
    let oprSize = getOperationSize ins
    let struct (dst, src) = getTwoOprs ins
    let r =
      match src with
      | OprReg r -> r
      | _ -> raise InvalidOperandException
    match RegisterHelper.getKind r with
    | RegisterHelper.Kind.MMX ->
      let struct (dst, src) = transTwoOprs ins bld false
      sized oprSize dst := AST.zext oprSize (byteMask [| src |])
    | RegisterHelper.Kind.XMM ->
      let dst = transOpr ins bld false dst
      let struct (srcB, srcA) = transOpr128 ins bld false src
#if EMULATION
      (* One SIMD intrinsic (a BinOp(APP, ...) the evaluator runs as a single
         pmovmskb) gathering the 16 byte MSBs, instead of extracting each by
         hand; the 16-bit mask is then zero-extended into the destination
         GPR. *)
      let mask = AST.app "PMOVMSKB" [ AST.concat srcB srcA ] 16<rt>
      sized oprSize dst := AST.zext oprSize mask
#else
      let tmps = byteMask [| srcA; srcB |]
      sized oprSize dst := AST.zext oprSize tmps
#endif
    | RegisterHelper.Kind.YMM ->
      let dst = transOpr ins bld false dst
      let struct (srcD, srcC, srcB, srcA) =
        transOpr256 ins bld false src
      let tmps = byteMask [| srcA; srcB; srcC; srcD |]
      sized oprSize dst := AST.zext oprSize tmps
    | _ ->
      raise InvalidOperandException
  }

let packedMove bld srcSz packSz dstA dstB src isSignExt =
  append bld {
    let packNum = int (srcSz / packSz)
    let dSz = 128<rt> / packNum
    let tDst = Array.init packNum (fun _ -> tmpVar bld dSz)
    if isSignExt then
      for i in 0 .. packNum - 1 do
        direct (tDst[i]) :=
          AST.sext dSz (AST.extract src packSz (i * (int packSz)))
    else
      for i in 0 .. packNum - 1 do
        direct (tDst[i]) :=
          AST.zext dSz (AST.extract src packSz (i * (int packSz)))
    let tDstA, tDstB = tDst |> Array.splitAt (packNum / 2)
    direct dstA := tDstA |> AST.revConcat
    direct dstB := tDstB |> AST.revConcat
  }

let pmovbw (ins: Instruction) bld packSz isSignExt =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    match src with
    | OprReg _ ->
      let struct (dstB, dstA) = transOpr128 ins bld false dst
      let struct (_, srcA) = transOpr128 ins bld false src
      packedMove bld 64<rt> packSz dstA dstB srcA isSignExt
    | OprMem _ ->
      let struct (dstB, dstA) = transOpr128 ins bld false dst
      let src = transOpr64 ins bld false src
      packedMove bld 64<rt> packSz dstA dstB src isSignExt
    | _ ->
      raise InvalidOperandException
  }

let pmovbd (ins: Instruction) bld packSz isSignExt =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    match src with
    | OprReg _ ->
      let struct (dstB, dstA) = transOpr128 ins bld false dst
      let struct (_, srcA) = transOpr128 ins bld false src
      packedMove bld 32<rt> packSz dstA dstB (AST.xtlo 32<rt> srcA) isSignExt
    | OprMem _ ->
      let struct (dstB, dstA) = transOpr128 ins bld false dst
      let src = transOpr32 ins bld false src
      packedMove bld 32<rt> packSz dstA dstB src isSignExt
    | _ ->
      raise InvalidOperandException
  }

let pmovbq (ins: Instruction) bld packSz isSignExt =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    match src with
    | OprReg _ ->
      let struct (dstB, dstA) = transOpr128 ins bld false dst
      let struct (_, srcA) = transOpr128 ins bld false src
      packedMove bld 16<rt> packSz dstA dstB (AST.xtlo 16<rt> srcA) isSignExt
    | OprMem _ ->
      let struct (dstB, dstA) = transOpr128 ins bld false dst
      let src = transOpr16 ins bld false src
      packedMove bld 16<rt> packSz dstA dstB src isSignExt
    | _ ->
      raise InvalidOperandException
  }

let private opPmulhuw _ = opPmul AST.xthi AST.zext 32<rt> 16<rt>

let pmulhuw ins bld =
  buildPackedInstr ins bld false 16<rt> opPmulhuw

let private opPmulld _ = opPmul AST.xtlo AST.sext 32<rt> 32<rt>

let pmulld ins bld =
  buildPackedInstr ins bld false 32<rt> opPmulld

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
  | _ ->
    raise InvalidOperandSizeException

let psadbw (ins: Instruction) bld =
  lift bld ins {
    let oprSize = getOperationSize ins
    let sPackSz = 8<rt> (* SRC Pack size *)
    let sPackNum = 64<rt> / sPackSz
    let dPackSz = 16<rt> (* DST Pack size *)
    let dPackNum = 64<rt> / dPackSz
    let struct (dst, src) = getTwoOprs ins
    let src1 = transOprToArr ins bld true sPackSz sPackNum oprSize dst
    let src2 = transOprToArr ins bld true sPackSz sPackNum oprSize src
    let result = opPsadbw oprSize src1 src2
    assignPackedInstr ins bld false dPackNum oprSize dst result
  }

let pshufw (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src, ord) = transThreeOprs ins bld false
    let oprSize = getOperationSize ins
    let cnt = RegType.toBitWidth oprSize / 16
    let tmps = Array.init cnt (fun _ -> tmpVar bld 16<rt>)
    let n16 = numI32 16 oprSize
    let mask2 = numI32 3 16<rt> (* 2-bit mask *)
    for i in 1 .. cnt do
      let order =
        ((AST.xtlo 16<rt> ord) >> (numI32 ((i - 1) * 2) 16<rt>)) .& mask2
      let order' = AST.zext oprSize order
      direct (tmps[i - 1]) := AST.xtlo 16<rt> (src >> (order' .* n16))
    done
    direct dst := AST.revConcat tmps
    fillOnesToMMXHigh16 bld ins
  }

let pshufd (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src, ord) = getThreeOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let struct (srcB, srcA) = transOpr128 ins bld false src
    let ord = getImmValue ord
    let oprSize = getOperationSize ins
    let cnt = RegType.toBitWidth oprSize / 32
    let rShiftTo64 hiExpr lowExpr amount =
      let rightAmt = numI64 (amount % 64L) 64<rt>
      let leftAmt = numI64 (64L - (amount % 64L)) 64<rt>
      if amount < 64L then
        AST.xtlo 32<rt> ((hiExpr << leftAmt) .| (lowExpr >> rightAmt))
      elif amount < 128L then
        AST.xtlo 32<rt> (hiExpr >> rightAmt)
      else
        AST.num0 32<rt>
    let amount idx = ((ord >>> (idx * 2)) &&& 0b11L) * 32L
    let struct (tSrcB, tSrcA) = tmpVars2 bld 64<rt>
    direct tSrcA := srcA
    direct tSrcB := srcB
    let src amtIdx = rShiftTo64 tSrcB tSrcA (amount amtIdx)
    direct dstA := AST.concat (src 1) (src 0)
    direct dstB := AST.concat (src 3) (src 2)
  }

let pshuflw (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src, imm) = getThreeOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let struct (srcB, srcA) = transOpr128 ins bld false src
    let imm = numI64 (getImmValue imm) 64<rt>
    let tmps = Array.init 4 (fun _ -> tmpVar bld 16<rt>)
    let n16 = numI32 16 64<rt>
    let mask2 = numI32 3 64<rt> (* 2-bit mask *)
    for i in 1 .. 4 do
      let imm = (imm >> (numI32 ((i - 1) * 2) 64<rt>)) .& mask2
      direct (tmps[i - 1]) := AST.xtlo 16<rt> (srcA >> (imm .* n16))
    done
    direct dstA := AST.revConcat tmps
    direct dstB := srcB
  }

let pshufhw (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src, imm) = getThreeOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let struct (srcB, srcA) = transOpr128 ins bld false src
    let imm = numI64 (getImmValue imm) 64<rt>
    let tmps = Array.init 4 (fun _ -> tmpVar bld 16<rt>)
    let n16 = numI32 16 64<rt>
    let mask2 = numI32 3 64<rt> (* 2-bit mask *)
    for i in 1 .. 4 do
      let imm = (imm >> (numI32 ((i - 1) * 2) 64<rt>)) .& mask2
      direct (tmps[i - 1]) := AST.xtlo 16<rt> (srcB >> (imm .* n16))
    done
    direct dstA := srcA
    direct dstB := AST.revConcat tmps
  }

let pshufb (ins: Instruction) bld =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packSize = 8<rt>
    let packNum = 64<rt> / packSize
    let allPackNum = oprSize / packSize
    let struct (dst, src) = getTwoOprs ins
    let src = transOprToArr ins bld false packSize packNum oprSize src
    let struct (mask, n0) = tmpVars2 bld packSize
    direct mask := numI32 (int allPackNum - 1) packSize
    direct n0 := AST.num0 packSize
    match oprSize with
    | 64<rt> ->
      let dst = transOpr ins bld false dst
      let n8 = numI32 8 oprSize
      let shuffle src =
        let idx = src .& mask
        let numShift = AST.zext oprSize idx .* n8
        AST.ite (AST.xthi 1<rt> src) n0 (AST.xtlo packSize (dst >> numShift))
      direct dst := Array.map shuffle src |> AST.revConcat
      fillOnesToMMXHigh16 bld ins
    | 128<rt> ->
      let struct (dstB, dstA) = transOpr128 ins bld false dst
      let n8 = tmpVar bld 64<rt>
      direct n8 := numI32 8 64<rt>
      let shuffle src =
        let idx = src .& mask
        let numShift = ((AST.zext 64<rt> idx) .% n8) .* n8
        let tDst = tmpVar bld 64<rt>
        append bld {
          direct tDst := AST.ite (idx .< numI32 8 packSize) dstA dstB
        }
        AST.ite (AST.xthi 1<rt> src) n0 (AST.xtlo packSize (tDst >> numShift))
      let result = Array.map shuffle src
      direct dstA := Array.sub result 0 packNum |> AST.revConcat
      direct dstB := Array.sub result packNum packNum |> AST.revConcat
    | _ ->
      raise InvalidOperandSizeException
  }

let movdqa ins bld = buildMove ins bld

let movdqu ins bld = buildMove ins bld

let movq2dq (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let src = transOpr ins bld false src
    direct dstA := src
    direct dstB := AST.num0 64<rt>
  }

let movdq2q (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let dst = transOpr ins bld false dst
    let struct (_, srcA) = transOpr128 ins bld false src
    direct dst := srcA
    fillOnesToMMXHigh16 bld ins
  }

let private opPmuludq _ =
  let low32 expr = expr .& numI64 0xffffffffL 64<rt>
  Array.map2 (fun e1 e2 -> low32 e1 .* low32 e2)

let pmuludq ins bld =
  buildPackedInstr ins bld false 64<rt> opPmuludq

let paddq ins bld =
  buildPackedInstr ins bld false 64<rt> (opP (.+))

let psubq ins bld =
  buildPackedInstr ins bld false 64<rt> (opP (.-))

let pslldq (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, cnt) = getTwoOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let cnt = getImmValue cnt
    let amount = if cnt > 15L then 16L * 8L else cnt * 8L
    let rightAmt = numI64 (64L - (amount % 64L)) 64<rt>
    let leftAmt = numI64 (amount % 64L) 64<rt>
    let struct (tDstB, tDstA) = tmpVars2 bld 64<rt>
    direct tDstA := dstA
    direct tDstB := dstB
    if amount < 64L then
      direct dstA := tDstA << leftAmt
      direct dstB := (tDstB << leftAmt) .| (tDstA >> rightAmt)
    elif amount < 128L then
      direct dstA := AST.num0 64<rt>
      direct dstB := tDstA << leftAmt
    else
      direct dstA := AST.num0 64<rt>
      direct dstB := AST.num0 64<rt>
  }

let psrldq (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, cnt) = getTwoOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let cnt = getImmValue cnt
    let amount = if cnt > 15L then 16L * 8L else cnt * 8L
    let rightAmt = numI64 (amount % 64L) 64<rt>
    let leftAmt = numI64 (64L - (amount % 64L)) 64<rt>
    let struct (tDstB, tDstA) = tmpVars2 bld 64<rt>
    direct tDstA := dstA
    direct tDstB := dstB
    if amount < 64L then
      direct dstA := (tDstB << leftAmt) .| (tDstA >> rightAmt)
      direct dstB := tDstB >> rightAmt
    elif amount < 128L then
      direct dstA := tDstB >> rightAmt
      direct dstB := AST.num0 64<rt>
    else
      direct dstA := AST.num0 64<rt>
      direct dstB := AST.num0 64<rt>
  }

let punpckhqdq ins bld =
  buildPackedInstr ins bld false 64<rt> opUnpackHighData

let punpcklqdq ins bld =
  buildPackedInstr ins bld false 64<rt> opUnpackLowData

let movntq ins bld = buildMove ins bld

let movntps ins bld = buildMove ins bld

let movntpd ins bld = buildMove ins bld

let movntdq ins bld = buildMove ins bld

let movnti ins bld = buildMove ins bld

let lddqu ins bld = buildMove ins bld

let movshdup (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (dst2, dst1) = transOpr128 ins bld false dst
    let struct (src2, src1) = transOpr128 ins bld false src
    let struct (tmp1, tmp2) = tmpVars2 bld 32<rt>
    direct tmp1 := AST.xthi 32<rt> src1
    direct tmp2 := AST.xthi 32<rt> src2
    direct (AST.xtlo 32<rt> dst1) := tmp1
    direct (AST.xthi 32<rt> dst1) := tmp1
    direct (AST.xtlo 32<rt> dst2) := tmp2
    direct (AST.xthi 32<rt> dst2) := tmp2
  }

let movsldup (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (dst2, dst1) = transOpr128 ins bld false dst
    let struct (src2, src1) = transOpr128 ins bld false src
    let struct (tmp1, tmp2) = tmpVars2 bld 32<rt>
    direct tmp1 := AST.xtlo 32<rt> src1
    direct tmp2 := AST.xtlo 32<rt> src2
    direct (AST.xtlo 32<rt> dst1) := tmp1
    direct (AST.xthi 32<rt> dst1) := tmp1
    direct (AST.xtlo 32<rt> dst2) := tmp2
    direct (AST.xthi 32<rt> dst2) := tmp2
  }

let movddup (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (dst1, dst0) = transOpr128 ins bld false dst
    let src = transOpr64 ins bld false src
    direct dst0 := src
    direct dst1 := src
  }

let packWithSaturation bld packSz src =
  let z16 = AST.num0 (packSz / 2)
  let z32 = AST.num0 packSz
  let f16 = numU32 0xFFFFu (packSz / 2)
  let f32 = numU32 0xFFFFu packSz
  let tSrc = tmpVar bld packSz
  let tmp = tmpVar bld (packSz / 2)
  append bld {
    direct tSrc := src
    direct tmp := AST.ite (tSrc ?< z32) z16 (AST.xtlo (packSz / 2) tSrc)
    direct tmp := AST.ite (tSrc ?> f32) f16 tmp
  }
  tmp

let packusdw (ins: Instruction) bld =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packNum = 64<rt> / 32<rt>
    let struct (dst, src) = getTwoOprs ins
    let src1 = transOprToArr ins bld true 32<rt> packNum oprSize dst
    let src2 = transOprToArr ins bld true 32<rt> packNum oprSize src
    let src = Array.append src1 src2
    let result = Array.map (packWithSaturation bld 32<rt>) src
    assignPackedInstr ins bld false (packNum * 2) oprSize dst result
  }

/// Aligns an MMX destination and source under the byte count, taking the
/// window that starts `amount` bits into the pair.
let private palignr64 bld ins dstOpr srcOpr shift =
  let struct (amount, leftAmt, rightAmt) = shift
  append bld {
    let dst = transOpr ins bld false dstOpr
    let src = transOpr ins bld false srcOpr
    let struct (tDst, tSrc) = tmpVars2 bld 64<rt>
    direct tDst := dst
    direct tSrc := src
    if amount < 64L then
      direct dst := (tDst << leftAmt) .| (tSrc >> rightAmt)
    elif amount < 128L then
      direct dst := tDst >> rightAmt
    else
      direct dst := AST.num0 64<rt>
    fillOnesToMMXHigh16 bld ins
  }

/// Aligns an XMM destination and source under the byte count, taking the
/// window that starts `amount` bits into the pair.
let private palignr128 bld ins dstOpr srcOpr shift =
  let struct (amount, leftAmt, rightAmt) = shift
  append bld {
    let struct (dstB, dstA) = transOpr128 ins bld false dstOpr
    let struct (srcB, srcA) = transOpr128 ins bld false srcOpr
    let struct (tDstB, tDstA, tSrcB, tSrcA) = tmpVars4 bld 64<rt>
    direct tDstA := dstA
    direct tDstB := dstB
    direct tSrcA := srcA
    direct tSrcB := srcB
    if amount < 64L then
      direct dstA := (tSrcB << leftAmt) .| (tSrcA >> rightAmt)
      direct dstB := (tDstA << leftAmt) .| (tSrcB >> rightAmt)
    elif amount < 128L then
      direct dstA := (tDstA << leftAmt) .| (tSrcB >> rightAmt)
      direct dstB := (tDstB << leftAmt) .| (tDstA >> rightAmt)
    elif amount < 192L then
      direct dstA := (tDstB << leftAmt) .| (tDstA >> rightAmt)
      direct dstB := tDstB >> rightAmt
    elif amount < 256L then
      direct dstA := tDstB >> rightAmt
      direct dstB := AST.num0 64<rt>
    else
      direct dstA := AST.num0 64<rt>
      direct dstB := AST.num0 64<rt>
  }

let palignr (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src, imm) = getThreeOprs ins
    let amount = getImmValue imm * 8L
    let rightAmt = numI64 (amount % 64L) 64<rt>
    let leftAmt = numI64 (64L - (amount % 64L)) 64<rt>
    let shift = struct (amount, leftAmt, rightAmt)
    match getOperationSize ins with
    | 64<rt> -> palignr64 bld ins dst src shift
    | 128<rt> -> palignr128 bld ins dst src shift
    | _ -> raise InvalidOperandSizeException
  }

let roundsd (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src, imm) = getThreeOprs ins
    let dst = transOpr64 ins bld false dst
    let src = transOpr64 ins bld false src
    let imm = transOpr ins bld false imm
    let rc = (AST.extract (regVar bld R.MXCSR) 8<rt> 13) .& (numI32 0b11 8<rt>)
    let tmp = tmpVar bld 8<rt>
    let cster castKind = AST.cast castKind 64<rt> src
    let imm2 = (AST.xtlo 8<rt> imm) .& (numI32 0b11 8<rt>)
    direct tmp := AST.ite (AST.extract imm 1<rt> 2) rc imm2
    direct dst := AST.ite (tmp == AST.num0 8<rt>) (cster CastKind.FtoFRound) dst
    direct dst := AST.ite (tmp == AST.num1 8<rt>) (cster CastKind.FtoFFloor) dst
    direct dst := AST.ite (tmp == numI32 2 8<rt>) (cster CastKind.FtoFCeil) dst
    direct dst := AST.ite (tmp == numI32 3 8<rt>) (cster CastKind.FtoFTrunc) dst
  }

let pinsrb (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src, count) = getThreeOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let src = transOpr ins bld false src
    let sel = getImmValue count &&& 0b1111L (* COUNT[3:0] *)
    let mask = numI64 (0xFFL <<< ((int32 sel * 8) % 64)) 64<rt>
    let amount = sel * 8L
    let t = tmpVar bld 64<rt>
    let expAmt = numI64 (amount % 64L) 64<rt>
    direct t := ((AST.zext 64<rt> (AST.xtlo 8<rt> src)) << expAmt) .& mask
    if amount < 64L then
      append bld { direct dstA := (dstA .& (AST.not mask)) .| t }
    else
      append bld { direct dstB := (dstB .& (AST.not mask)) .| t }
  }

let private packedSign bld packSz control inputVal =
  let n0 = AST.num0 packSz
  let struct (tControl, tInputVal) = tmpVars2 bld packSz
  let struct (cond1, cond2) = tmpVars2 bld 1<rt>
  append bld {
    direct tControl := control
    direct tInputVal := inputVal
    direct cond1 := tControl ?< n0
    direct cond2 := tControl == n0
  }
  AST.ite cond1 (AST.neg tInputVal) (AST.ite cond2 n0 tInputVal)

let psign (ins: Instruction) bld packSz =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src) = getTwoOprs ins
    let srcDst = transOprToArr ins bld true packSz packNum oprSize dst
    let src = transOprToArr ins bld true packSz packNum oprSize src
    let result = Array.map2 (packedSign bld packSz) src srcDst
    assignPackedInstr ins bld false packNum oprSize dst result
  }

let ptest (ins: Instruction) bld =
  lift bld ins {
    let struct (src1, src2) = getTwoOprs ins
    let struct (src1B, src1A) = transOpr128 ins bld false src1
    let struct (src2B, src2A) = transOpr128 ins bld false src2
    let struct (t1, t2, t3, t4) = tmpVars4 bld 64<rt>
    direct t1 := src2A .& src1A
    direct t2 := src2B .& src1B
    direct (regVar bld R.ZF) := (t1 .| t2) == (AST.num0 64<rt>)
    direct t3 := src2A .& AST.not src1A
    direct t4 := src2B .& AST.not src1B
    direct (regVar bld R.CF) := (t3 .| t4) == (AST.num0 64<rt>)
    direct (regVar bld R.AF) := AST.b0
    direct (regVar bld R.OF) := AST.b0
    direct (regVar bld R.PF) := AST.b0
    direct (regVar bld R.SF) := AST.b0
#if EMULATION
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let opPcmpeqq _ = opPcmp 64<rt> (==)

let pcmpeqq ins bld =
  buildPackedInstr ins bld false 64<rt> opPcmpeqq

let packedBlend src1 src2 imm =
  Array.mapi2 (fun i e1 e2 ->
    AST.ite (AST.extract imm 1<rt> (i % 8)) e1 e2) src1 src2

let packedVblend src1 src2 (mask: Expr[]) =
  Array.mapi2 (fun i e1 e2 -> AST.ite (AST.xthi 1<rt> mask[i]) e1 e2) src1 src2

let blendpd (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src, imm) = getThreeOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let struct (srcB, srcA) = transOpr128 ins bld false src
    let imm = transOpr ins bld false imm
    let cond1 = AST.extract imm 1<rt> 0
    let cond2 = AST.extract imm 1<rt> 1
    direct dstA := AST.ite cond1 srcA dstA
    direct dstB := AST.ite cond2 srcB dstB
  }

let blendps (ins: Instruction) bld =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packNum = 64<rt> / 32<rt>
    let struct (dst, src, imm) = getThreeOprs ins
    let src1 = transOprToArr ins bld true 32<rt> packNum oprSize dst
    let src2 = transOprToArr ins bld true 32<rt> packNum oprSize src
    let imm = transOpr ins bld false imm
    let result = packedBlend src2 src1 imm
    assignPackedInstr ins bld false packNum oprSize dst result
  }

let blendvpd (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src, xmm0) = getThreeOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let struct (srcB, srcA) = transOpr128 ins bld false src
    let struct (xmm0B, xmm0A) = transOpr128 ins bld false xmm0
    let cond1 = AST.xthi 1<rt> xmm0A
    let cond2 = AST.xthi 1<rt> xmm0B
    direct dstA := AST.ite cond1 srcA dstA
    direct dstB := AST.ite cond2 srcB dstB
  }

let blendvps (ins: Instruction) bld =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packNum = 64<rt> / 32<rt>
    let struct (dst, src, xmm0) = getThreeOprs ins
    let src1 = transOprToArr ins bld true 32<rt> packNum oprSize dst
    let src2 = transOprToArr ins bld true 32<rt> packNum oprSize src
    let xmm0 = transOprToArr ins bld false 32<rt> packNum oprSize xmm0
    let result = packedVblend src2 src1 xmm0
    assignPackedInstr ins bld false packNum oprSize dst result
  }

let pblendvb (ins: Instruction) bld =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packNum = 64<rt> / 8<rt>
    let struct (dst, src, xmm0) = getThreeOprs ins
    let src1 = transOprToArr ins bld true 8<rt> packNum oprSize dst
    let src2 = transOprToArr ins bld true 8<rt> packNum oprSize src
    let xmm0 = transOprToArr ins bld false 8<rt> packNum oprSize xmm0
    let result = packedVblend src2 src1 xmm0
    assignPackedInstr ins bld false packNum oprSize dst result
  }

let pblendw (ins: Instruction) bld =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packNum = 64<rt> / 16<rt>
    let struct (dst, src, imm) = getThreeOprs ins
    let src1 = transOprToArr ins bld true 16<rt> packNum oprSize dst
    let src2 = transOprToArr ins bld true 16<rt> packNum oprSize src
    let imm = transOpr ins bld false imm
    let result = packedBlend src2 src1 imm
    assignPackedInstr ins bld false packNum oprSize dst result
  }

/// XXX (cleanup required)
/// imm8 control byte operation for PCMPESTRI, PCMPESTRM, etc..
/// See Chapter 4.1 of the manual vol. 2B.
type Imm8ControlByte =
  { PackSize: RegType
    NumElems: uint32
    Sign: Sign
    Agg: Agg
    Polarity: Polarity
    OutSelect: OutSelect
    Len: Length
    Ret: Return }

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
    | Num(n, _) -> n.ToBigInt()
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

let private setZFSFOfPCMPSTR bld ctrl src1 src2 =
  append bld {
    let inline checkIfElemIsNull exps =
      Array.map (fun e -> (e == AST.num0 ctrl.PackSize)) exps
      |> Array.reduce (.|)
    let inline checkIndexOutOfBounds reg =
      let abs = tmpVar bld 32<rt>
      let reg = regVar bld reg
      append bld {
        direct abs := AST.ite (AST.xthi 1<rt> reg) (AST.neg reg) reg
      }
      abs .< numU32 ctrl.NumElems 32<rt>
    match ctrl.Len with
    | Implicit ->
      direct (regVar bld R.ZF) := checkIfElemIsNull src2
      direct (regVar bld R.SF) := checkIfElemIsNull src1
    | Explicit ->
      direct (regVar bld R.ZF) := checkIndexOutOfBounds R.EDX
      direct (regVar bld R.SF) := checkIndexOutOfBounds R.EAX
  }

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
  append bld {
    direct cnt := AST.num0 sz
    AST.lmark lblLoop
  }
  let max = numI32 max sz
  let bit = (AST.xtlo 1<rt> (expr >> cnt)) .& AST.b1
  append bld {
    direct cond := (bit == AST.b0) .& (cnt .< max)
    AST.cjmp cond (AST.jmpDest lblCont) (AST.jmpDest lblEnd)
    AST.lmark lblCont
    direct cnt := cnt .+ (AST.num1 sz)
    AST.jmp (AST.jmpDest lblLoop)
    AST.lmark lblEnd
  }
  cnt

/// Most significant index.
let private mostSign bld expr sz max =
  let lblCont = label bld "Cont"
  let lblLoop = label bld "Loop"
  let lblEnd = label bld "End"
  let cond = tmpVar bld 1<rt>
  let idx = tmpVar bld sz
  append bld {
    direct idx := numI32 (max - 1) sz
    AST.lmark lblLoop
  }
  let n0 = AST.num0 sz
  let bit = (AST.xtlo 1<rt> (expr >> idx)) .& AST.b1
  append bld {
    direct cond := (bit == AST.b0) .& (idx .> n0)
    AST.cjmp cond (AST.jmpDest lblCont) (AST.jmpDest lblEnd)
    AST.lmark lblCont
    direct idx := idx .- (AST.num1 sz)
    AST.jmp (AST.jmpDest lblLoop)
    AST.lmark lblEnd
  }
  idx

/// override comparisons for invalid characters.
let private overrideIfDataInvalid bld ctrl aInval bInval boolRes =
  append bld {
    match ctrl.Agg with
    | EqualAny | Ranges ->
      let cond = (AST.not aInval .& bInval) .| (aInval .& AST.not bInval) .|
                 (aInval .& bInval)
      direct boolRes := AST.ite cond AST.b0 boolRes
    | EqualEach ->
      let cond1 = (AST.not aInval .& bInval) .| (aInval .& AST.not bInval)
      let cond2 = aInval .& bInval
      direct boolRes := AST.ite cond1 AST.b0 (AST.ite cond2 AST.b1 boolRes)
    | EqualOrdered ->
      let cond1 = AST.not aInval .& bInval
      let cond2 = (aInval .& AST.not bInval) .| (aInval .& bInval)
      direct boolRes := AST.ite cond1 AST.b0 (AST.ite cond2 AST.b1 boolRes)
  }

/// Sets every bit of an aggregation result to the same starting value.
let private initIntRes bld initVal =
  Array.iter (fun r -> append bld { direct r := initVal })

/// Compares every character of one operand against every character of the
/// other, noting as it goes where each string has run out: an implicit length
/// ends at a null character, an explicit one at the index held in AX or DX.
/// `Ranges` reads the first operand two at a time, as the low and the high
/// bound of a range; every other aggregation compares for equality.
let private comparePcmpstrChars bld
                                ctrl
                                (src1: Expr[])
                                (src2: Expr[])
                                (boolRes: Expr array2d)
                                regs =
  let regSize, ax, dx = regs
  let upperBound = int ctrl.NumElems - 1
  let n0 = AST.num0 ctrl.PackSize
  let struct (aInval, bInval) = tmpVars2 bld 1<rt>
  append bld {
    direct aInval := AST.b0
  }
  let (.<=), (.>=) =
    if ctrl.Sign = Signed then AST.sle, AST.sge else AST.le, AST.ge
  for i in 0 .. upperBound do
    append bld {
      direct bInval := AST.b0
    }
    (* invalidate characters after EOS. *)
    match ctrl.Len with
    | Implicit ->
      append bld { direct aInval := aInval .| (src1[i] == n0) }
    | Explicit ->
      append bld { direct aInval := aInval .| (numI32 i regSize == ax) }
    for j in 0 .. upperBound do
      (* compare all characters. *)
      if ctrl.Agg = Ranges then
        if i % 2 = 0 then
          append bld { direct (boolRes[i, j]) := src1[i] .<= src2[j] }
        else
          append bld { direct (boolRes[i, j]) := src1[i] .>= src2[j] }
      else
        append bld {
          direct (boolRes[i, j]) := src1[i] == src2[j]
        }
      (* invalidate characters after EOS. *)
      match ctrl.Len with
      | Implicit ->
        append bld { direct bInval := bInval .| (src2[j] == n0) }
      | Explicit ->
        append bld { direct bInval := bInval .| (numI32 j regSize == dx) }
      overrideIfDataInvalid bld ctrl aInval bInval boolRes[i, j]
    done
  done
  bInval

/// Reduces the grid of character comparisons to one bit per element, the way
/// the aggregation asks: any match anywhere, a match inside either range, a
/// match at the same index, or a run of matches starting at that index.
let private aggregatePcmpstrResult bld
                                   ctrl
                                   (boolRes: Expr array2d)
                                   (intRes1: Expr[]) =
  let upperBound = int ctrl.NumElems - 1
  match ctrl.Agg with
  | EqualAny ->
    initIntRes bld AST.b0 intRes1
    for i in 0 .. upperBound do
      for j in 0 .. upperBound do
        append bld {
          direct (intRes1[i]) := intRes1[i] .| boolRes[j, i]
        }
      done
    done
  | Ranges ->
    initIntRes bld AST.b0 intRes1
    for i in 0 .. upperBound do
      for j in 0 .. 2 .. upperBound do
        append bld {
          direct (intRes1[i]) :=
            intRes1[i] .| (boolRes[j, i] .& boolRes[j + 1, i])
        }
      done
    done
  | EqualEach ->
    initIntRes bld AST.b0 intRes1
    for i in 0 .. upperBound do
      append bld {
        direct (intRes1[i]) := boolRes[i, i]
      }
    done
  | EqualOrdered ->
    initIntRes bld AST.b1 intRes1
    let mutable k = 0
    for i in 0 .. upperBound do
      k <- i
      for j in 0 .. upperBound - i do
        append bld {
          direct (intRes1[i]) := intRes1[i] .& boolRes[j, k]
        }
        k <- k + 1
      done
    done

/// Negates the aggregated bits where the polarity asks for it. A masked
/// polarity negates only the elements still inside the second string, so the
/// bits past its end come through as they stood.
let private negatePcmpstrResult bld
                                ctrl
                                (src2: Expr[])
                                (results: Expr[] * Expr[])
                                bInval
                                regs =
  let intRes1, intRes2 = results
  let regSize, _, dx = regs
  let upperBound = int ctrl.NumElems - 1
  let n0 = AST.num0 ctrl.PackSize
  initIntRes bld AST.b0 intRes2
  for i in 0 .. upperBound do
    match ctrl.Polarity with
    | PosPolarity | PosMasked ->
      append bld {
        direct (intRes2[i]) := intRes1[i]
      }
    | NegPolarity (* 0b01 *) ->
      append bld {
        direct (intRes2[i]) := AST.not intRes1[i]
      }
    | NegMasked (* 0b11 *) ->
      match ctrl.Len with
      | Implicit ->
        append bld {
          direct bInval := src2[i] == n0
          direct (intRes2[i]) := AST.ite bInval intRes1[i] (AST.not intRes1[i])
        }
      | Explicit ->
        let not = AST.not intRes1[i]
        append bld {
          direct (intRes2[i]) :=
            AST.ite (numI32 i regSize .>= dx) intRes1[i] not
        }
  done

/// Writes the bits out the way the opcode asks: as a mask in XMM0, one bit or
/// one whole element wide, or as the index of the first or the last bit set,
/// which is the element count where nothing matched at all.
let private writePcmpstrResult bld
                               (ins: Instruction)
                               ctrl
                               (intRes2: Expr[])
                               iRes2 =
  append bld {
    let packSize = ctrl.PackSize
    let nElem = int ctrl.NumElems
    let elemSz = RegType.fromBitWidth nElem
    let upperBound = nElem - 1
    let pNum = 64<rt> / packSize
    let n0 = AST.num0 packSize
    match ctrl.Ret with
    | Mask ->
      let struct (dstB, dstA) = pseudoRegVar128 bld R.XMM0
      match ctrl.OutSelect with
      | Least (* Bit mask *) ->
        let res = tmpVar bld elemSz
        direct res := combineBits elemSz intRes2
        direct dstA := AST.zext 64<rt> res
        direct dstB := AST.num0 64<rt>
      | Most (* Byte/word mask *) ->
        let nFF =
          numI32 (if ctrl.PackSize = 8<rt> then 0xFF else 0xFFFF) packSize
        let res = Array.init nElem (fun _ -> tmpVar bld packSize)
        for i in 0 .. upperBound do
          direct (res[i]) := AST.ite intRes2[i] nFF n0
        done
        direct dstA := Array.sub res 0 pNum |> AST.revConcat
        direct dstB := Array.sub res pNum pNum |> AST.revConcat
    | Index ->
      let outSz, cx =
        if REXPrefix.hasW ins.REXPrefix then 64<rt>, R.RCX else 32<rt>, R.ECX
      let cx = regVar bld cx
      let n0 = AST.num0 elemSz
      let idx =
        match ctrl.OutSelect with
        | Least -> leastSign bld iRes2 elemSz nElem
        | Most -> mostSign bld iRes2 elemSz nElem
        |> AST.zext 32<rt>
      let idx = AST.ite (iRes2 == n0) (numI32 nElem 32<rt>) idx
      sized outSz cx := idx
  }

let pcmpstr (ins: Instruction) bld =
  lift bld ins {
    let struct (s1, s2, imm) = getThreeOprs ins
    let imm = transOpr ins bld false imm
    let ctrl = getPcmpstrInfo ins.Opcode imm
    let oprSz = getOperationSize ins
    let packSize = ctrl.PackSize
    let nElem = int ctrl.NumElems
    let elemSz = RegType.fromBitWidth nElem
    let pNum = 64<rt> / packSize
    let src1 = transOprToArr ins bld true packSize pNum oprSz s1
    let src2 = transOprToArr ins bld true packSize pNum oprSz s2
    let boolRes = Array2D.init nElem nElem (fun _ _ -> tmpVar bld 1<rt>)
    let regs =
      if REXPrefix.hasW ins.REXPrefix then
        64<rt>, regVar bld R.RAX, regVar bld R.RDX
      else
        32<rt>, regVar bld R.EAX, regVar bld R.EDX
    let bInval = comparePcmpstrChars bld ctrl src1 src2 boolRes regs
    let intRes1 = Array.init nElem (fun _ -> tmpVar bld 1<rt>)
    let intRes2 = Array.init nElem (fun _ -> tmpVar bld 1<rt>)
    aggregatePcmpstrResult bld ctrl boolRes intRes1
    negatePcmpstrResult bld ctrl src2 (intRes1, intRes2) bInval regs
    (* output. *)
    let iRes2 = tmpVar bld elemSz
    direct iRes2 := combineBits elemSz intRes2
    writePcmpstrResult bld ins ctrl intRes2 iRes2
    direct (regVar bld R.CF) := iRes2 != AST.num0 elemSz
    setZFSFOfPCMPSTR bld ctrl src1 src2
    direct (regVar bld R.OF) := intRes2[0]
    direct (regVar bld R.AF) := AST.b0
    direct (regVar bld R.PF) := AST.b0
#if EMULATION
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }
