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
    let oprSize = getOperationSize ins
    let struct (dst, s1, s2) = getDstAndSrcs ins
    let a = transOprToArr ins bld true 64<rt> 1 oprSize s1
    let b = transOprToArr ins bld true 64<rt> 1 oprSize s2
    let result =
      Array.init a.Length (fun i ->
        if i % 2 = 0 then AST.fsub a[i] b[i] else AST.fadd a[i] b[i])
    assignPackedInstr ins bld false 1 oprSize dst result
    if isVexEncoded ins then
      fillZeroFromVLToMaxVL bld dst oprSize 512
    else
      ()
  }

let addsubps (ins: Instruction) bld =
  lift bld ins {
    let oprSize = getOperationSize ins
    let struct (dst, s1, s2) = getDstAndSrcs ins
    let a = transOprToArr ins bld true 32<rt> 2 oprSize s1
    let b = transOprToArr ins bld true 32<rt> 2 oprSize s2
    let result =
      Array.init a.Length (fun i ->
        if i % 2 = 0 then AST.fsub a[i] b[i] else AST.fadd a[i] b[i])
    assignPackedInstr ins bld false 2 oprSize dst result
    if isVexEncoded ins then
      fillZeroFromVLToMaxVL bld dst oprSize 512
    else
      ()
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
    assignEVEXPacked ins bld 32<rt> oprSize dst result
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

/// The minimum or maximum of each lane. Where the comparison is false -- and
/// it is false whenever either operand is a NaN -- the second source is what
/// comes back, which is the rule the manual gives and the reason these are not
/// symmetric.
let private minMaxPacked (ins: Instruction) bld packSz compare =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, s1, s2) = getDstAndSrcs ins
    let a = transOprToArr ins bld true packSz packNum oprSize s1
    let b = transOprToArr ins bld true packSz packNum oprSize s2
    let result = Array.map2 (fun x y -> AST.ite (compare x y) x y) a b
    assignEVEXPacked ins bld packSz oprSize dst result
    if isVexEncoded ins then
      fillZeroFromVLToMaxVL bld dst oprSize 512
    else
      ()
  }

/// The scalar forms touch the low lane alone. A VEX encoding names the source
/// the lanes above it come from, where the legacy one leaves them standing.
let private minMaxScalar (ins: Instruction) bld packSz compare =
  lift bld ins {
    let struct (dst, s1, s2) = getDstAndSrcs ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let struct (s1B, s1A) = transOpr128 ins bld false s1
    let src =
      if packSz = 32<rt> then transOpr32 ins bld false s2
      else transOpr64 ins bld false s2
    let first = if packSz = 32<rt> then AST.xtlo 32<rt> s1A else s1A
    let tmp = tmpVar bld packSz
    direct tmp := AST.ite (compare first src) first src
    if isVexEncoded ins then
      direct dstA := s1A
      direct dstB := s1B
    else
      ()
    direct (if packSz = 32<rt> then AST.xtlo 32<rt> dstA else dstA) := tmp
    if isVexEncoded ins then
      fillZeroFromVLToMaxVL bld dst 128<rt> 512
    else
      ()
  }

let maxps ins bld = minMaxPacked ins bld 32<rt> AST.fgt

let maxpd ins bld = minMaxPacked ins bld 64<rt> AST.fgt

let maxss ins bld = minMaxScalar ins bld 32<rt> AST.fgt

let maxsd ins bld = minMaxScalar ins bld 64<rt> AST.fgt

let minps ins bld = minMaxPacked ins bld 32<rt> AST.flt

let minpd ins bld = minMaxPacked ins bld 64<rt> AST.flt

let minss ins bld = minMaxScalar ins bld 32<rt> AST.flt

let minsd ins bld = minMaxScalar ins bld 64<rt> AST.flt

/// The predicate an immediate names. A legacy encoding has three bits of it
/// and a VEX one five, the sixteen predicates above the first eight being the
/// ones with an unordered answer where the first eight have an ordered one --
/// and the bit above those choosing only whether a signalling NaN raises,
/// which changes nothing about the answer.
///
/// The equality here is a floating-point one, not a comparison of the bit
/// patterns: a positive and a negative zero differ in their bits and are equal
/// as numbers, and a NaN is equal to nothing at all, itself included.
let cmppCond bld ins op3 isDbl c expr1 expr2 =
  let width = if isVexEncoded ins then 0x1F else 0x7
  let imm =
    transOpr ins bld false op3 |> AST.xtlo 8<rt>
    .& numI32 width 8<rt>
  match imm with
  | Num(bv, _) ->
    let unord = isNan isDbl expr1 .| isNan isDbl expr2
    let eq = AST.feq expr1 expr2
    let cond =
      match bv.ToUInt64() % 16UL with
      | 0UL -> eq
      | 1UL -> AST.flt expr1 expr2
      | 2UL -> AST.fle expr1 expr2
      | 3UL -> unord
      | 4UL -> AST.not eq
      | 5UL -> AST.flt expr1 expr2 |> AST.not
      | 6UL -> AST.fle expr1 expr2 |> AST.not
      | 7UL -> AST.not unord
      | 8UL -> eq .| unord
      | 9UL -> AST.fge expr1 expr2 |> AST.not
      | 10UL -> AST.fgt expr1 expr2 |> AST.not
      | 11UL -> AST.b0
      | 12UL -> (AST.not eq) .& (AST.not unord)
      | 13UL -> AST.fge expr1 expr2
      | 14UL -> AST.fgt expr1 expr2
      | _ -> AST.b1
    append bld { direct c := cond }
  | _ ->
    Terminator.impossible ()

/// Compares each lane against the predicate the immediate names, filling the
/// lane with ones where it holds and zeros where it does not.
let private cmpPacked (ins: Instruction) bld packSz =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, s1, s2, imm) = getDstSrcsImm ins
    let a = transOprToArr ins bld true packSz packNum oprSize s1
    let b = transOprToArr ins bld true packSz packNum oprSize s2
    let isDouble = packSz = 64<rt>
    let result =
      Array.init a.Length (fun i ->
        let cond = tmpVar bld 1<rt>
        cmppCond bld ins imm isDouble cond a[i] b[i]
        AST.ite cond (maxNum packSz) (AST.num0 packSz))
    assignPackedInstr ins bld false packNum oprSize dst result
    if isVexEncoded ins then
      fillZeroFromVLToMaxVL bld dst oprSize 512
    else
      ()
  }

let cmppd ins bld = cmpPacked ins bld 64<rt>

let cmpps ins bld = cmpPacked ins bld 32<rt>

/// The scalar compares fill the low lane alone. A VEX encoding names the
/// source the lanes above it come from, where the legacy one leaves them
/// standing.
let private cmpScalar (ins: Instruction) bld packSz =
  lift bld ins {
    let struct (dst, s1, s2, imm) = getDstSrcsImm ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let struct (s1B, s1A) = transOpr128 ins bld false s1
    let src =
      if packSz = 32<rt> then transOpr32 ins bld false s2
      else transOpr64 ins bld false s2
    let first = if packSz = 32<rt> then AST.xtlo 32<rt> s1A else s1A
    let cond = tmpVar bld 1<rt>
    cmppCond bld ins imm (packSz = 64<rt>) cond first src
    let answer = tmpVar bld packSz
    direct answer := AST.ite cond (maxNum packSz) (AST.num0 packSz)
    if isVexEncoded ins then
      direct dstA := s1A
      direct dstB := s1B
    else
      ()
    direct (if packSz = 32<rt> then AST.xtlo 32<rt> dstA else dstA) := answer
    if isVexEncoded ins then
      fillZeroFromVLToMaxVL bld dst 128<rt> 512
    else
      ()
  }

let cmpss ins bld = cmpScalar ins bld 32<rt>

let cmpsd (ins: Instruction) bld =
  match ins.Operands with
  | NoOperand ->
    GeneralLifter.cmps ins bld
  | _ ->
    cmpScalar ins bld 64<rt>

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

/// INSERTPS moves one single-precision lane into the destination and then
/// zeroes whichever lanes the immediate names. The immediate carries three
/// fields: bits [7:6] pick the source lane (a memory source is the lane
/// itself), bits [5:4] the destination lane, and bits [3:0] the lanes to zero
/// afterwards -- the inserted one included, if it is named.
/// DPPD and DPPS multiply the lanes their immediate's high nibble names, sum
/// the products, and write that sum to the lanes its low nibble names -- every
/// other lane, and every product the mask leaves out, is +0.0. The summation
/// order is the manual's, pairwise rather than left to right, because float
/// addition is not associative and the order is what the hardware does.
/// The AES round instructions are lifted as one named call each, not as the
/// arithmetic they stand for: a round written out in IR is hundreds of nodes of
/// S-box lookup and GF(2^8) multiplication, and every evaluator that matters
/// has a single host instruction to hand it to instead. The named call is also
/// the only honest thing to write -- what the round means is the round, and
/// spelling out the field arithmetic would say no more.
let aesenc ins bld = MMXLifter.packedBinIntrinsic ins bld "AESENC"

let aesenclast ins bld = MMXLifter.packedBinIntrinsic ins bld "AESENCLAST"

let aesdec ins bld = MMXLifter.packedBinIntrinsic ins bld "AESDEC"

let aesdeclast ins bld = MMXLifter.packedBinIntrinsic ins bld "AESDECLAST"

/// Stores the bytes a mask selects to the address DI holds, byte by byte.
/// The bytes the mask leaves out are written back as they stood rather than
/// skipped: what the manual guarantees is which bytes end up changed, and a
/// store of the old byte changes none of them.
let private maskedStore bld (src: Expr[]) (mask: Expr[]) count =
  let di = regVar bld (if is64bit bld then R.RDI else R.EDI)
  for i in 0 .. count - 1 do
    let addr = di .+ numI32 i (Expr.typeOf di)
    let old = AST.loadLE 8<rt> addr
    append bld {
      direct old := AST.ite (AST.xthi 1<rt> mask[i]) src[i] old
    }

/// MASKMOVDQU stores the sixteen bytes the mask selects; MASKMOVQ the eight
/// of an MMX register. Neither names its destination: it is always DI.
let private maskmov (ins: Instruction) bld oprSize =
  lift bld ins {
    let struct (src, mask) = getTwoOprs ins
    let count = RegType.toByteWidth oprSize
    let s = transOprToArr ins bld true 8<rt> 8 oprSize src
    let m = transOprToArr ins bld true 8<rt> 8 oprSize mask
    maskedStore bld s m count
  }

let maskmovdqu ins bld = maskmov ins bld 128<rt>

let maskmovq ins bld = maskmov ins bld 64<rt>

/// Rotates a doubleword left, which is most of what a SHA round does.
///
/// The SHA-NI instructions below are written out as the arithmetic they are,
/// not handed to a host call the way the AES rounds above are. The two look
/// alike from a distance and are not: an AES round turns on a 256-entry
/// substitution table, which IR cannot say without 256 nested conditionals and
/// which every host has an instruction for. A SHA round is rotates,
/// exclusive-ors and adds over 32-bit words -- IR says that exactly, and there
/// is no x86 SHA intrinsic to call even where it could not.
let private rotl32 e n =
  (e << numI32 n 32<rt>) .| (e >> numI32 (32 - n) 32<rt>)

let private rotr32 e n = rotl32 e (32 - n)

/// SHA-1's round function, chosen by the two low bits of SHA1RNDS4's
/// immediate: the choice for the first twenty rounds, the majority for the
/// third twenty, parity for the rest.
let private sha1Choice sel b c d =
  match sel with
  | 0 -> (b .& c) .| (AST.not b .& d)
  | 2 -> (b .& c) .| (b .& d) .| (c .& d)
  | _ -> b <+> c <+> d

/// And the constant that goes with it (FIPS 180-4, section 4.2.1).
let private sha1Const sel =
  match sel with
  | 0 -> numU32 0x5A827999u 32<rt>
  | 1 -> numU32 0x6ED9EBA1u 32<rt>
  | 2 -> numU32 0x8F1BBCDCu 32<rt>
  | _ -> numU32 0xCA62C1D6u 32<rt>

/// SHA-256's bit-mixing functions, named as FIPS 180-4 names them.
let private bigSigma0 x = rotr32 x 2 <+> rotr32 x 13 <+> rotr32 x 22

let private bigSigma1 x = rotr32 x 6 <+> rotr32 x 11 <+> rotr32 x 25

let private smallSigma0 x =
  rotr32 x 7 <+> rotr32 x 18 <+> (x >> numI32 3 32<rt>)

let private smallSigma1 x =
  rotr32 x 17 <+> rotr32 x 19 <+> (x >> numI32 10 32<rt>)

let private chOf x y z = (x .& y) <+> (AST.not x .& z)

let private majOf x y z = (x .& y) <+> (x .& z) <+> (y .& z)

/// Reads a 128-bit operand as its four doublewords, lowest first.
let private asWords (ins: Instruction) bld opr =
  transOprToArr ins bld true 32<rt> 2 128<rt> opr

/// SHA1NEXTE folds the next E into the message schedule: the destination's
/// high doubleword, rotated by thirty, added to the source's. The three
/// doublewords below it come through untouched.
let sha1nexte (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let d = asWords ins bld dst
    let s = asWords ins bld src
    let result = [| s[0]; s[1]; s[2]; s[3] .+ rotl32 d[3] 30 |]
    assignPackedInstr ins bld false 2 128<rt> dst result
  }

/// SHA1MSG1 takes the first half of the exclusive-or the schedule's recurrence
/// asks for: each word against the one four places before it.
let sha1msg1 (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let d = asWords ins bld dst
    let s = asWords ins bld src
    let result =
      [| s[2] <+> d[0]; s[3] <+> d[1]; d[0] <+> d[2]; d[1] <+> d[3] |]
    assignPackedInstr ins bld false 2 128<rt> dst result
  }

/// SHA1MSG2 finishes it: the remaining exclusive-or and the rotation by one
/// that makes the next four schedule words. The last of them is built from the
/// first, so that one is held rather than written twice.
let sha1msg2 (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let d = asWords ins bld dst
    let s = asWords ins bld src
    let w16 = tmpVar bld 32<rt>
    direct w16 := rotl32 (d[3] <+> s[2]) 1
    let w17 = rotl32 (d[2] <+> s[1]) 1
    let w18 = rotl32 (d[1] <+> s[0]) 1
    let w19 = rotl32 (d[0] <+> w16) 1
    assignPackedInstr ins bld false 2 128<rt> dst [| w19; w18; w17; w16 |]
  }

/// Runs SHA1RNDS4's four rounds, appending each as it goes and handing back
/// the state it leaves. A round's new values all come from the old ones, so
/// each one is settled into a temporary before the next reads it.
let private sha1Rounds bld sel (state: Expr[]) (w: Expr[]) =
  let k = sha1Const sel
  let mutable a = state[3]
  let mutable b = state[2]
  let mutable c = state[1]
  let mutable d = state[0]
  (* The first round has no E of its own: SHA1NEXTE has already added it into
     the word this one takes. *)
  let mutable e = AST.num0 32<rt>
  for i in 0 .. 3 do
    let struct (nextA, nextC) = tmpVars2 bld 32<rt>
    append bld {
      direct nextA := sha1Choice sel b c d .+ rotl32 a 5 .+ w[i] .+ e .+ k
      direct nextC := rotl32 b 30
    }
    e <- d
    d <- c
    c <- nextC
    b <- a
    a <- nextA
  [| d; c; b; a |]

/// SHA1RNDS4: four rounds of SHA-1 over the state in the destination and the
/// four schedule words in the source.
let sha1rnds4 (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src, imm) = getThreeOprs ins
    let sel = int (getImmValue imm &&& 3L)
    let d = asWords ins bld dst
    let s = asWords ins bld src
    let result = sha1Rounds bld sel d [| s[3]; s[2]; s[1]; s[0] |]
    assignPackedInstr ins bld false 2 128<rt> dst result
  }

/// Runs SHA256RNDS2's two rounds. The eight working variables are spread
/// across the two operands -- A, B, E and F in the source, C, D, G and H in
/// the destination -- and only A, B, E and F come back.
let private sha256Rounds bld (src1: Expr[]) (src2: Expr[]) (wk: Expr[]) =
  let mutable a = src2[3]
  let mutable b = src2[2]
  let mutable c = src1[3]
  let mutable d = src1[2]
  let mutable e = src2[1]
  let mutable f = src2[0]
  let mutable g = src1[1]
  let mutable h = src1[0]
  for i in 0 .. 1 do
    let struct (t1, nextA, nextE) = tmpVars3 bld 32<rt>
    append bld {
      (* What both halves of the round share: the choice over E, F and G, the
         mixing of E, the message word and the H coming in. *)
      direct t1 := chOf e f g .+ bigSigma1 e .+ wk[i] .+ h
      direct nextA := t1 .+ majOf a b c .+ bigSigma0 a
      direct nextE := t1 .+ d
    }
    h <- g
    g <- f
    f <- e
    e <- nextE
    d <- c
    c <- b
    b <- a
    a <- nextA
  [| f; e; b; a |]

/// SHA256RNDS2: two rounds of SHA-256, taking the two message words already
/// added to their round constants from XMM0 -- a register the encoding does
/// not name, and which the parser hands over as a third operand.
let sha256rnds2 (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src, xmm0) = getThreeOprs ins
    let d = asWords ins bld dst
    let s = asWords ins bld src
    let wk = asWords ins bld xmm0
    let result = sha256Rounds bld d s wk
    assignPackedInstr ins bld false 2 128<rt> dst result
  }

/// SHA256MSG1: the first half of SHA-256's schedule recurrence, each word
/// taking the small sigma of the one after it.
let sha256msg1 (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let d = asWords ins bld dst
    let s = asWords ins bld src
    let result =
      [| d[0] .+ smallSigma0 d[1]
         d[1] .+ smallSigma0 d[2]
         d[2] .+ smallSigma0 d[3]
         d[3] .+ smallSigma0 s[0] |]
    assignPackedInstr ins bld false 2 128<rt> dst result
  }

/// SHA256MSG2: the second half, where each of the last two words is built
/// from one of the first two, so those are held as they are made.
let sha256msg2 (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let d = asWords ins bld dst
    let s = asWords ins bld src
    let struct (w16, w17) = tmpVars2 bld 32<rt>
    direct w16 := d[0] .+ smallSigma1 s[2]
    direct w17 := d[1] .+ smallSigma1 s[3]
    let w18 = d[2] .+ smallSigma1 w16
    let w19 = d[3] .+ smallSigma1 w17
    assignPackedInstr ins bld false 2 128<rt> dst [| w16; w17; w18; w19 |]
  }

/// GF2P8MULB multiplies byte by byte in the field AES is built on. Like the
/// AES rounds it is a named call: there is no way to say a field
/// multiplication in IR without writing its shift-and-add out eight times over
/// for each of sixteen bytes.
let gf2p8mulb ins bld = MMXLifter.packedBinIntrinsic ins bld "GF2P8MULB"

/// GF2P8AFFINEQB and its inverse form put each byte through the affine
/// transform the source quadword spells out as eight rows, the immediate
/// adding a constant. Their inverse form takes the byte's field inverse first,
/// which is how the pair spells out the AES substitution box.
let private gfniAffine (ins: Instruction) bld name =
  lift bld ins {
    let struct (dst, s1, s2, imm) = getDstSrcsImm ins
    let struct (dstB, dstA) = transOpr128 ins bld false s1
    let struct (srcB, srcA) = transOpr128 ins bld false s2
    let control = numU64 (uint64 (getImmValue imm) &&& 0xFFUL) 8<rt>
    let t = tmpVar bld 128<rt>
    let args = [ AST.concat dstB dstA; AST.concat srcB srcA; control ]
    direct t := AST.app name args 128<rt>
    let struct (dB, dA) = transOpr128 ins bld false dst
    direct dA := AST.xtlo 64<rt> t
    direct dB := AST.xthi 64<rt> t
    if isVexEncoded ins then
      fillZeroFromVLToMaxVL bld dst 128<rt> 512
    else
      ()
  }

let gf2p8affineqb ins bld = gfniAffine ins bld "GF2P8AFFINEQB"

let gf2p8affineinvqb ins bld = gfniAffine ins bld "GF2P8AFFINEINVQB"

/// PCLMULQDQ multiplies one quadword of each operand without carries, which is
/// what makes AES-GCM's authentication cheap. Like the AES rounds it is one
/// named call: the immediate says which quadwords, and rides along as an
/// argument the way the key generator's round constant does.
let pclmulqdq (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src, imm) = getThreeOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let struct (srcB, srcA) = transOpr128 ins bld false src
    let control = numU64 (uint64 (getImmValue imm) &&& 0x11UL) 8<rt>
    let t = tmpVar bld 128<rt>
    let args = [ AST.concat dstB dstA; AST.concat srcB srcA; control ]
    direct t := AST.app "PCLMULQDQ" args 128<rt>
    direct dstA := AST.xtlo 64<rt> t
    direct dstB := AST.xthi 64<rt> t
  }

/// AESIMC reads its source alone, the destination taking no part.
let aesimc (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let struct (srcB, srcA) = transOpr128 ins bld false src
    let t = tmpVar bld 128<rt>
    direct t := AST.app "AESIMC" [ AST.concat srcB srcA ] 128<rt>
    direct dstA := AST.xtlo 64<rt> t
    direct dstB := AST.xthi 64<rt> t
  }

/// AESKEYGENASSIST carries the round constant in its immediate, which rides
/// along as a second argument to the call.
let aeskeygenassist (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src, imm) = getThreeOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let struct (srcB, srcA) = transOpr128 ins bld false src
    (* The round constant is a byte, and is built as one: translating the
       operand instead would hand back a constant as wide as the instruction
       operates, and the call's second argument is an integer, not a vector. *)
    let rcon = numU64 (uint64 (getImmValue imm) &&& 0xFFUL) 8<rt>
    let t = tmpVar bld 128<rt>
    let src = AST.concat srcB srcA
    direct t := AST.app "AESKEYGENASSIST" [ src; rcon ] 128<rt>
    direct dstA := AST.xtlo 64<rt> t
    direct dstB := AST.xthi 64<rt> t
  }

let private dotProduct (ins: Instruction) bld packSz =
  lift bld ins {
    let struct (dst, s1, s2, imm8) = getDstSrcsImm ins
    let imm = getImmValue imm8
    let packNum = 64<rt> / packSz
    let lanes = if packSz = 64<rt> then 2 else 4
    let dstArr = transOprToArr ins bld true packSz packNum 128<rt> s1
    let srcArr = transOprToArr ins bld true packSz packNum 128<rt> s2
    let zero = AST.num0 packSz (* +0.0 shares its bits *)
    let product i =
      if (imm >>> (4 + i)) &&& 1L = 1L then AST.fmul dstArr[i] srcArr[i]
      else zero
    let sum = tmpVar bld packSz
    if lanes = 2 then
      direct sum := AST.fadd (product 0) (product 1)
    else
      let struct (lo, hi) = tmpVars2 bld packSz
      direct lo := AST.fadd (product 0) (product 1)
      direct hi := AST.fadd (product 2) (product 3)
      direct sum := AST.fadd lo hi
    let result =
      Array.init lanes (fun i -> if (imm >>> i) &&& 1L = 1L then sum else zero)
    assignPackedInstr ins bld false packNum 128<rt> dst result
    if isVexEncoded ins then
      fillZeroFromVLToMaxVL bld dst 128<rt> 512
    else
      ()
  }

let dppd ins bld = dotProduct ins bld 64<rt>

let dpps ins bld = dotProduct ins bld 32<rt>

let insertps (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, s1, src, imm8) = getDstSrcsImm ins
    let imm = getImmValue imm8
    let srcLane = int ((imm >>> 6) &&& 0b11L)
    let inserted =
      match src with
      | OprMem _ ->
        transOpr32 ins bld true src
      | _ ->
        (transOprToArr ins bld true 32<rt> 2 128<rt> src)[srcLane]
    let dstLane = int ((imm >>> 4) &&& 0b11L)
    let old = transOprToArr ins bld true 32<rt> 2 128<rt> s1
    let result =
      Array.init 4 (fun i ->
        if (imm >>> i) &&& 1L = 1L then AST.num0 32<rt>
        elif i = dstLane then inserted
        else old[i])
    assignPackedInstr ins bld false 2 128<rt> dst result
    if isVexEncoded ins then
      fillZeroFromVLToMaxVL bld dst 128<rt> 512
    else
      ()
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
  (* One sum per eight bytes, landing in the low word of each quadword: four
     of them for a 256-bit operand, two for a 128-bit one, one for an MMX. *)
  let groups = RegType.toBitWidth oprSize / 64
  if groups < 1 then raise InvalidOperandSizeException else ()
  Array.init groups (fun g ->
    Array.append [| Array.reduce sum (Array.sub temp (g * 8) 8) |] zeros)
  |> Array.concat

let psadbw (ins: Instruction) bld =
  lift bld ins {
    let oprSize = getOperationSize ins
    let sPackSz = 8<rt> (* SRC Pack size *)
    let sPackNum = 64<rt> / sPackSz
    let dPackSz = 16<rt> (* DST Pack size *)
    let dPackNum = 64<rt> / dPackSz
    let struct (dst, s1, s2) = getDstAndSrcs ins
    let src1 = transOprToArr ins bld true sPackSz sPackNum oprSize s1
    let src2 = transOprToArr ins bld true sPackSz sPackNum oprSize s2
    let result = opPsadbw oprSize src1 src2
    assignPackedInstr ins bld false dPackNum oprSize dst result
    if isVexEncoded ins then
      fillZeroFromVLToMaxVL bld dst oprSize 512
    else
      ()
  }

/// MPSADBW slides a four-byte window of the source over the destination and
/// writes the sum of the four absolute byte differences at each of eight
/// positions. The immediate says where both start: bits [1:0] pick the source
/// window in steps of four bytes, bit [2] the destination offset, zero or
/// four. Every bit above that is ignored. Four differences of unsigned bytes
/// sum to at most 1020, so a word holds each result outright.
let mpsadbw (ins: Instruction) bld =
  lift bld ins {
    let oprSize = getOperationSize ins
    let struct (dst, s1, s2, imm8) = getDstSrcsImm ins
    let imm = getImmValue imm8
    let dstBytes = transOprToArr ins bld true 8<rt> 8 oprSize s1
    let srcBytes = transOprToArr ins bld true 8<rt> 8 oprSize s2
    let absDiff e1 e2 = AST.ite (AST.lt e1 e2) (e2 .- e1) (e1 .- e2)
    (* Each 128-bit lane has selectors of its own, three immediate bits
       apiece, and reads only the bytes of its own lane. *)
    let lanes = max 1 (RegType.toBitWidth oprSize / 128)
    let result =
      Array.init lanes (fun lane ->
        let sel = imm >>> (lane * 3)
        let srcOff = lane * 16 + int (sel &&& 0b11L) * 4
        let dstOff = lane * 16 + int ((sel >>> 2) &&& 0b1L) * 4
        Array.init 8 (fun i ->
          Array.init 4 (fun j ->
            absDiff dstBytes[dstOff + i + j] srcBytes[srcOff + j]
            |> AST.zext 16<rt>)
          |> Array.reduce (.+)))
      |> Array.concat
    assignPackedInstr ins bld false 4 oprSize dst result
    if isVexEncoded ins then
      fillZeroFromVLToMaxVL bld dst oprSize 512
    else
      ()
  }

/// Folds the eight words down to the smallest and the lane it came from,
/// keeping the earlier lane where two are equal. Written as a running pair of
/// temporaries rather than nested conditionals: each step would otherwise
/// carry a copy of everything before it.
let private foldMinWord bld (words: Expr[]) =
  let struct (minVal, minIdx) = tmpVars2 bld 16<rt>
  append bld {
    direct minVal := words[0]
    direct minIdx := AST.num0 16<rt>
  }
  for i in 1 .. 7 do
    let isLess = tmpVar bld 1<rt>
    append bld {
      direct isLess := AST.lt words[i] minVal
      direct minIdx := AST.ite isLess (numI32 i 16<rt>) minIdx
      direct minVal := AST.ite isLess words[i] minVal
    }
  struct (minVal, minIdx)

/// PHMINPOSUW answers with the smallest of the eight unsigned words in lane 0
/// and the lane it came from in lane 1, leaving the six above zero.
let phminposuw (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let words = transOprToArr ins bld true 16<rt> 4 128<rt> src
    let struct (minVal, minIdx) = foldMinWord bld words
    let result =
      Array.init 8 (fun i ->
        match i with
        | 0 -> minVal
        | 1 -> minIdx
        | _ -> AST.num0 16<rt>)
    assignPackedInstr ins bld false 4 128<rt> dst result
    if isVexEncoded ins then
      fillZeroFromVLToMaxVL bld dst 128<rt> 512
    else
      ()
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

/// PSHUFLW and PSHUFHW permute four of the eight words in each 128-bit lane
/// by the immediate -- the low four or the high four -- and copy the other
/// four through untouched. A register wider than a lane is more lanes, each
/// shuffled the same way, and the write mask an EVEX form carries reaches
/// every word of the result, the copied ones included.
let private shuffleHalfWords (ins: Instruction) bld isHigh =
  lift bld ins {
    let oprSize = getOperationSize ins
    let struct (dst, src, imm) = getThreeOprs ins
    let a = transOprToArr ins bld true 16<rt> 4 oprSize src
    let ord = getImmValue imm |> int
    let half = if isHigh then 4 else 0
    let lane i =
      let inLane = i % 8
      if inLane / 4 * 4 = half then
        a[i / 8 * 8 + half + (ord >>> (inLane % 4 * 2) &&& 3)]
      else
        a[i]
    assignEVEXPacked ins bld 16<rt> oprSize dst (Array.init a.Length lane)
    if isVexEncoded ins then
      fillZeroFromVLToMaxVL bld dst oprSize 512
    else
      ()
  }

let pshuflw ins bld = shuffleHalfWords ins bld false

let pshufhw ins bld = shuffleHalfWords ins bld true

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

/// PMULDQ is PMULUDQ read as signed: only the low doubleword of each quadword
/// lane takes part, and it is sign-extended rather than masked.
let opPmuldq _ =
  let low32 expr = AST.xtlo 32<rt> expr |> AST.sext 64<rt>
  Array.map2 (fun e1 e2 -> low32 e1 .* low32 e2)

let pmuldq ins bld =
  buildPackedInstr ins bld false 64<rt> opPmuldq

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

/// The load is what MOVNTDQA means; its non-temporal hint is advice to the
/// cache, which an emulator with no cache to advise has nothing to do about.
let movntdqa ins bld = buildMove ins bld

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

/// The rounding mode an imm8 selects: bit 2 hands the choice to MXCSR.RC, and
/// otherwise bits [1:0] name it. Bit 3 only suppresses the precision
/// exception, which nothing here models.
let private roundingMode bld imm =
  let rc = (AST.extract (regVar bld R.MXCSR) 8<rt> 13) .& (numI32 0b11 8<rt>)
  let fromImm = (AST.xtlo 8<rt> imm) .& (numI32 0b11 8<rt>)
  let mode = tmpVar bld 8<rt>
  append bld {
    direct mode := AST.ite (AST.extract imm 1<rt> 2) rc fromImm
  }
  mode

/// One value rounded the way the mode says: to nearest, down, up, or toward
/// zero.
let private roundedTo sz mode src =
  let cast kind = AST.cast kind sz src
  let picks m = mode == numI32 m 8<rt>
  let orTrunc = cast CastKind.FtoFTrunc
  let orCeil = AST.ite (picks 2) (cast CastKind.FtoFCeil) orTrunc
  let orFloor = AST.ite (picks 1) (cast CastKind.FtoFFloor) orCeil
  AST.ite (picks 0) (cast CastKind.FtoFRound) orFloor

let private roundPacked (ins: Instruction) bld packSz isVex =
  lift bld ins {
    let oprSize = getOperationSize ins
    let struct (dst, src, imm) = getThreeOprs ins
    let imm = transOpr ins bld false imm
    let mode = roundingMode bld imm
    let packNum = 64<rt> / packSz
    let src = transOprToArr ins bld true packSz packNum oprSize src
    let result = src |> Array.map (roundedTo packSz mode)
    assignPackedInstr ins bld false packNum oprSize dst result
    (* A legacy form leaves the register above its lane alone; a VEX one
       clears it. *)
    if isVex then fillZeroFromVLToMaxVL bld dst oprSize 512 else ()
  }

let roundpd ins bld = roundPacked ins bld 64<rt> false

let roundps ins bld = roundPacked ins bld 32<rt> false

let vroundpd ins bld = roundPacked ins bld 64<rt> true

let vroundps ins bld = roundPacked ins bld 32<rt> true

/// The scalar forms round the low lane alone and leave the rest of the
/// destination standing. Their VEX encodings name a second source the round
/// does not read -- the lanes above come from it rather than from the
/// destination -- and clear the register above 128 bits.
let private roundScalar (ins: Instruction) bld packSz isVex =
  lift bld ins {
    let struct (dst, src, imm) =
      match ins.Operands with
      | FourOperands(o1, _, o3, o4) -> struct (o1, o3, o4)
      | _ -> getThreeOprs ins
    let trans = if packSz = 32<rt> then transOpr32 else transOpr64
    let d = trans ins bld false dst
    let s = trans ins bld false src
    let imm = transOpr ins bld false imm
    let mode = roundingMode bld imm
    direct d := roundedTo packSz mode s
    if isVex then fillZeroFromVLToMaxVL bld dst 128<rt> 512 else ()
  }

let roundss ins bld = roundScalar ins bld 32<rt> false

let vroundss ins bld = roundScalar ins bld 32<rt> true

let vroundsd ins bld = roundScalar ins bld 64<rt> true

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

/// PINSRD and PINSRQ write one lane of the destination from a general-purpose
/// register or memory, with the immediate naming the lane. Unlike PINSRB and
/// PINSRW there is no MMX form, so the destination is always 128 bits wide.
let private pinsrDQ (ins: Instruction) bld packSz idxMask =
  lift bld ins {
    let packNum = 64<rt> / packSz
    let struct (dstOpr, s1, src, imm8) = getDstSrcsImm ins
    let src = transOpr ins bld false src |> AST.xtlo packSz
    let index = getImmValue imm8 &&& idxMask |> int
    let lanes = transOprToArr ins bld true packSz packNum 128<rt> s1
    let result =
      Array.init lanes.Length (fun i -> if i = index then src else lanes[i])
    assignPackedInstr ins bld false packNum 128<rt> dstOpr result
    if isVexEncoded ins then
      fillZeroFromVLToMaxVL bld dstOpr 128<rt> 512
    else
      ()
  }

let pinsrd ins bld = pinsrDQ ins bld 32<rt> 0b11L

let pinsrq ins bld = pinsrDQ ins bld 64<rt> 0b1L

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
    let struct (dst, src1, src2) = getDstAndSrcs ins
    let srcDst = transOprToArr ins bld true packSz packNum oprSize src1
    let src = transOprToArr ins bld true packSz packNum oprSize src2
    let result = Array.map2 (packedSign bld packSz) src srcDst
    assignPackedInstr ins bld false packNum oprSize dst result
    if isVexEncoded ins then
      fillZeroFromVLToMaxVL bld dst oprSize 512
    else
      ()
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

/// Takes each lane from one source or the other, as the immediate's bit for
/// that lane says. The 256-bit forms simply have more lanes and read more of
/// the immediate.
let private blendPacked (ins: Instruction) bld packSz =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, s1, s2, imm) = getDstSrcsImm ins
    let imm = getImmValue imm
    let a = transOprToArr ins bld true packSz packNum oprSize s1
    let b = transOprToArr ins bld true packSz packNum oprSize s2
    let result =
      Array.init a.Length (fun i ->
        if (imm >>> i) &&& 1L = 1L then b[i] else a[i])
    assignPackedInstr ins bld false packNum oprSize dst result
    if isVexEncoded ins then
      fillZeroFromVLToMaxVL bld dst oprSize 512
    else
      ()
  }

let blendpd ins bld = blendPacked ins bld 64<rt>

let blendps ins bld = blendPacked ins bld 32<rt>

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

/// The length an explicit-length compare really works to: the absolute value
/// of what the register holds, capped at the element count. So a negative
/// length names an empty string and anything past the element count a full
/// one, which is what the hardware does and not what the register says. The
/// unsigned comparison also settles the one value whose negation is itself,
/// the most negative integer: as an unsigned quantity it is far past the cap.
let private saturatedLen bld ctrl regSize reg =
  let len = tmpVar bld regSize
  let cap = numU32 ctrl.NumElems regSize
  append bld {
    direct len := AST.ite (AST.xthi 1<rt> reg) (AST.neg reg) reg
    direct len := AST.ite (len .> cap) cap len
  }
  len

let private setZFSFOfPCMPSTR bld ctrl src1 src2 regs =
  append bld {
    let inline checkIfElemIsNull exps =
      Array.map (fun e -> (e == AST.num0 ctrl.PackSize)) exps
      |> Array.reduce (.|)
    let regSize, lenA, lenB = regs
    match ctrl.Len with
    | Implicit ->
      direct (regVar bld R.ZF) := checkIfElemIsNull src2
      direct (regVar bld R.SF) := checkIfElemIsNull src1
    | Explicit ->
      direct (regVar bld R.ZF) := lenB .< numU32 ctrl.NumElems regSize
      direct (regVar bld R.SF) := lenA .< numU32 ctrl.NumElems regSize
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
  let regSize, lenA, lenB = regs
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
      append bld { direct aInval := aInval .| (numI32 i regSize .>= lenA) }
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
        append bld { direct bInval := bInval .| (numI32 j regSize .>= lenB) }
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
  let regSize, _, lenB = regs
  let upperBound = int ctrl.NumElems - 1
  let n0 = AST.num0 ctrl.PackSize
  initIntRes bld AST.b0 intRes2
  (* The masked negation reaches only the elements inside the second string,
     and an implicit string ends at its first null character -- whatever
     follows that null is outside it too. So the test starts clear and stays
     set once it has fired; asking whether each element is itself null would
     let the characters behind an embedded null back in. *)
  append bld {
    direct bInval := AST.b0
  }
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
          direct bInval := bInval .| (src2[i] == n0)
          direct (intRes2[i]) := AST.ite bInval intRes1[i] (AST.not intRes1[i])
        }
      | Explicit ->
        let not = AST.not intRes1[i]
        append bld {
          direct (intRes2[i]) :=
            AST.ite (numI32 i regSize .>= lenB) intRes1[i] not
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

/// The lengths a compare works to, beside the width the REX prefix gave them.
/// An implicit-length compare reads no length register at all, so the pair is
/// the raw registers there and the saturated counts only for the explicit
/// forms.
let private pcmpstrLengths bld (ctrl: Imm8ControlByte) regSize ax dx =
  match ctrl.Len with
  | Implicit ->
    regSize, ax, dx
  | Explicit ->
    let lenAx = saturatedLen bld ctrl regSize ax
    let lenDx = saturatedLen bld ctrl regSize dx
    regSize, lenAx, lenDx

/// The flags a compare leaves behind: carry says the result is not empty,
/// overflow carries its first element, and the auxiliary and parity flags are
/// cleared. Zero and sign come from the operand lengths, which is why they are
/// the one pair that needs the sources.
let private setFlagsOfPcmpstr bld ctrl src1 src2 regs intRes2 iRes2 elemSz =
  append bld {
    direct (regVar bld R.CF) := iRes2 != AST.num0 elemSz
  }
  setZFSFOfPCMPSTR bld ctrl src1 src2 regs
  append bld {
    direct (regVar bld R.OF) := Array.item 0 intRes2
    direct (regVar bld R.AF) := AST.b0
    direct (regVar bld R.PF) := AST.b0
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
    let regSize, ax, dx =
      if REXPrefix.hasW ins.REXPrefix then
        64<rt>, regVar bld R.RAX, regVar bld R.RDX
      else
        32<rt>, regVar bld R.EAX, regVar bld R.EDX
    let regs = pcmpstrLengths bld ctrl regSize ax dx
    let bInval = comparePcmpstrChars bld ctrl src1 src2 boolRes regs
    let intRes1 = Array.init nElem (fun _ -> tmpVar bld 1<rt>)
    let intRes2 = Array.init nElem (fun _ -> tmpVar bld 1<rt>)
    aggregatePcmpstrResult bld ctrl boolRes intRes1
    negatePcmpstrResult bld ctrl src2 (intRes1, intRes2) bInval regs
    let iRes2 = tmpVar bld elemSz
    direct iRes2 := combineBits elemSz intRes2
    writePcmpstrResult bld ins ctrl intRes2 iRes2
    setFlagsOfPcmpstr bld ctrl src1 src2 regs intRes2 iRes2 elemSz
#if EMULATION
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }
