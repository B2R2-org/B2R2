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

/// A module for the AArch64 SIMD and floating-point IR translation
/// functions
module internal B2R2.FrontEnd.ARM64.SIMDLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.ARM64
open B2R2.FrontEnd.ARM64.LiftingUtils
open B2R2.FrontEnd.ARM64.GeneralLifter

let private clsBits src oprSize bld =
  let n1 = AST.num1 oprSize
  let struct (expr1, expr2, xExpr) = tmpVars3 bld oprSize
  append bld {
    direct expr1 := src >> n1
    direct expr2 := (src << n1) >> n1
    direct xExpr := (expr1 <+> expr2)
  }
  let bitSize = int oprSize - 1
  clzBits xExpr bitSize oprSize bld

let private fpneg reg eSize =
  let mask =
    match eSize with
    | 16<rt> -> numU64 0x8000UL eSize (* ARMv8.2 *)
    | 32<rt> -> numU64 0x80000000UL eSize
    | 64<rt> -> numU64 0x8000000000000000UL eSize
    | _ -> raise InvalidOperandSizeException
  reg <+> mask

let private fpType bld mode eSize element =
  let res = tmpVar bld eSize
  let struct (checkNan, checkInf) = tmpVars2 bld 1<rt>
  let lblNan = label bld "NaN"
  let lblCon = label bld "Continue"
  let lblEnd = label bld "End"
  append bld {
    direct checkNan := isNaN eSize element
    direct checkInf := isInfinity eSize element
    AST.cjmp (checkNan .| checkInf)
             (AST.jmpDest lblNan)
             (AST.jmpDest lblCon)
    AST.lmark lblNan
  }
  let fpNaN = fpProcessNan bld eSize element
  append bld {
    direct res := AST.ite checkNan fpNaN (fpDefaultInfinity element eSize)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblCon
  }
  let castElem = AST.roundToIntegral mode eSize element
  append bld {
    direct res := AST.ite (isZero eSize element) (fpZero element eSize) castElem
    AST.lmark lblEnd
  }
  fpExceptionsInvalidOnly bld (isSNaN eSize element)
  res

/// <summary>
/// One element rounded to an integral value at its own width, a half's
/// through doubles: the rounded value is a whole number no larger than the
/// half was, so narrowing it back is exact.
/// </summary>
let private roundLane bld eSize round e =
  if eSize = 16<rt> then viaDouble bld (fun w -> round 64<rt> w[0]) [| e |]
  else round eSize e

let private isVecIdxOrLD1ST1 (ins: Instruction) opr =
  let isVecIdx =
    match opr with
    | OprSIMDList simd ->
      match simd[0] with
      | VecRegWithIdx _ -> true
      | _ -> false
    | _ ->
      false
  isVecIdx || (ins.Opcode = Opcode.LD1) || (ins.Opcode = Opcode.ST1)

let private fillZeroHigh64 (ins: Instruction) bld opr =
  if ins.OprSize = 64<rt> then
    match opr with
    | OprSIMDList simds ->
      List.iter (fun simd ->
        match simd with
        | VecReg(reg, _) ->
          let regB = pseudoRegVar bld reg 2
          append bld {
            direct regB := AST.num0 64<rt>
          }
        | _ ->
          ()) simds
    | _ ->
      ()
  else
    ()

/// <summary>
/// FixedToFP: an integer, or a fixed-point number with <c>fbits</c> of
/// fraction, converted to a single or a double.
///
/// The integer is rounded into the format and then scaled by a power of two,
/// which is exact -- the smallest value a fixed-point source reaches is two to
/// the -64th, nowhere near subnormal -- so the conversion's one rounding is
/// the cast's, and Inexact, the only exception it can raise, is asked of the
/// cast.
/// </summary>
let private fixedToFp bld oprSz fbits unsigned src =
  let kind = if unsigned then CastKind.UIntToFloat else CastKind.SIntToFloat
  let integer = AST.cast kind oprSz src
  let r = tmpVar bld oprSz
  append bld { direct r := AST.fdiv integer (powerOfTwoOf oprSz fbits) }
  fpExceptionsRounded bld AST.b0 (AST.not (fpIsExact integer))
  r

/// <summary>
/// How far a shift operand shifts.
///
/// SHLL's amount is written as a shift rather than as a bare number -- the
/// disassembly is `shll v0.4s, v1.4h, lsl #16` -- so the operand carries the
/// kind as well as the count and the general translation has nothing to make
/// of it.
/// </summary>
let private shiftAmountOf = function
  | OprImm imm -> imm
  | OprShift(_, Imm imm) -> imm
  | _ -> raise InvalidOperandException

let private getRndConst amt eSize =
  let n1 = AST.num1 eSize
  let amt = AST.neg amt .- n1
  let isNeg = amt ?< AST.num0 eSize
  AST.ite isNeg (n1 >> AST.neg amt) (n1 << amt)

let private usatQRShl bld expr amt eSize =
  let bitQC = AST.extract (regVar bld R.FPSR) 1<rt> 27
  let max = numU64 0xFFFFFFFFFFFFFFFFUL eSize
  let min = AST.num0 eSize
  let msb = numU64 (1UL <<< (int eSize - 1)) eSize
  let eESz = numI32 (int eSize - 1) eSize
  let n0 = AST.num0 eSize
  let n1 = AST.num1 eSize
  let nAmt = AST.neg amt
  let struct (isNeg, isOver, isSat) = tmpVars3 bld 1<rt>
  let struct (hBit, rExpr, rConst) = tmpVars3 bld eSize
  append bld {
    direct isNeg := amt ?< AST.num0 eSize
    direct rConst := getRndConst amt eSize
    direct isOver := expr .> (max .- rConst)
    direct rExpr := expr .+ rConst
  }
  let h = highestSetBitForIR rExpr (int eSize) eSize bld
  append bld {
    direct hBit := AST.ite isOver (eESz .+ n1) h
    direct isSat := AST.ite isNeg (hBit .< nAmt) (eESz .< (hBit .+ amt))
    direct bitQC := bitQC .| isSat
  }
  let rShf = rExpr >> nAmt
  let lShf = rExpr << amt
  let shf =
    AST.ite isNeg (AST.ite isOver (rShf .+ (msb >> (nAmt .- n1))) rShf) lShf
  let isZero = (AST.not isOver) .& ((rExpr == n0) .| (amt == n0))
  AST.ite isZero rExpr (AST.ite isSat (AST.ite isNeg min max) shf)

let private usatQShl bld expr amt eSize =
  let bitQC = AST.extract (regVar bld R.FPSR) 1<rt> 27
  let hBit = highestSetBitForIR expr (int eSize) eSize bld
  let max = numU64 0xFFFFFFFFFFFFFFFFUL eSize
  let min = AST.num0 eSize
  let struct (isNeg, isSat) = tmpVars2 bld 1<rt>
  let eESz = numI32 (int eSize - 1) eSize
  append bld {
    direct isNeg := amt ?< AST.num0 eSize
    direct isSat := AST.ite isNeg (hBit .< AST.neg amt) (eESz .< (hBit .+ amt))
    direct bitQC := bitQC .| isSat
  }
  let sat = AST.ite isNeg min max
  let r = AST.ite isSat sat (AST.ite isNeg (expr >> AST.neg amt) (expr << amt))
  let isZero = (expr == AST.num0 eSize) .| (amt == AST.num0 eSize)
  AST.ite isZero expr r

/// <summary>
/// The signed saturating shift by a signed amount, with or without rounding:
/// SQSHL and SQRSHL in their register forms.
///
/// The shift is done at twice the element's width, where a left shift of a
/// whole element cannot lose a bit, and the answer is clamped from there.
/// That is why the amount is split into a left half and a right half rather
/// than used as it stands: SatQ raises the sticky QC bit, so a right shift
/// must not go anywhere near the left computation or it would report a
/// saturation that did not happen. Each half is zero where the other one is
/// doing the work, and a shift by zero saturates nothing.
///
/// A left shift further than the element is wide saturates unless the element
/// is zero, which clamping the amount to the width preserves.
///
/// A right shift further than that does not clamp the same way for both
/// forms. Without rounding it leaves the sign in every bit, so one less than
/// the width will do. With rounding it does not: the constant added before
/// the shift is half of what is shifted out, and at that distance it is
/// larger than the whole element, so every value, the most negative
/// included, rounds to zero. Clamping the amount would add a constant for a
/// shorter shift than the one being taken and answer -1 for those.
/// </summary>
let private satQShlBy bld isRound expr amt (eSize: int<rt>) =
  let wide = eSize * 2
  let n0 = AST.num0 eSize
  let widest = numI32 (int eSize) eSize
  let deepest = numI32 (int eSize - 1) eSize
  let struct (isNeg, left, right) = tmpVars3 bld eSize
  let struct (over, capped) = tmpVars2 bld eSize
  append bld {
    direct isNeg := AST.ite (amt ?< n0) (AST.num1 eSize) n0
    direct left := AST.ite (amt ?< n0) n0 (AST.ite (amt ?> widest) widest amt)
    direct right := AST.ite (amt ?< n0) (AST.neg amt) n0
    direct over := AST.ite (right .>= widest) (AST.num1 eSize) n0
    direct capped := AST.ite (right .>= widest) deepest right
  }
  let wideExpr = AST.sext wide expr
  let shifted amount = AST.xtlo eSize (wideExpr ?>> AST.zext wide amount)
  let rounded =
    let one = AST.num1 wide
    let half = one << (AST.zext wide capped .- one)
    wideExpr .+ AST.ite (capped == n0) (AST.num0 wide) half
  let rightRes =
    if isRound then
      let kept = AST.xtlo eSize (rounded ?>> AST.zext wide capped)
      AST.ite (over == AST.num1 eSize) n0 kept
    else
      shifted capped
  let leftRes = satQ bld (wideExpr << AST.zext wide left) eSize false
  AST.ite (isNeg == AST.num1 eSize) rightRes leftRes

/// <summary>
/// One element narrowed to half its width with saturation, in the three
/// combinations the instruction set has: signed to signed, unsigned to
/// unsigned, and signed to unsigned.
///
/// The general SatQ cannot serve here. It compares at twice the destination's
/// width, which for a narrowing is the SOURCE's width, and its comparisons
/// are signed -- so an unsigned source with its top bit set would read as
/// negative and be clamped to nothing. Which comparison to use is exactly
/// what the source's signedness decides, so it is written out.
/// </summary>
let private satNarrow bld e (eSize: int<rt>) srcUnsigned dstUnsigned =
  let half = eSize / 2
  let bitQC = AST.extract (regVar bld R.FPSR) 1<rt> 27
  let maxHalf = getIntMax half dstUnsigned
  let minHalf = if dstUnsigned then AST.num0 half else AST.not maxHalf
  let max =
    if dstUnsigned then AST.zext eSize maxHalf else AST.sext eSize maxHalf
  let min = if dstUnsigned then AST.num0 eSize else AST.sext eSize minHalf
  let struct (tooHigh, tooLow) = tmpVars2 bld 1<rt>
  append bld {
    direct tooHigh := if srcUnsigned then e .> max else e ?> max
    direct tooLow := if srcUnsigned then AST.b0 else e ?< min
    direct bitQC := bitQC .| tooHigh .| tooLow
  }
  AST.ite tooHigh maxHalf (AST.ite tooLow minHalf (AST.xtlo half e))

/// <summary>
/// SQXTN, UQXTN and SQXTUN: every element narrowed to half its width and
/// clamped rather than wrapped.
///
/// SQXTUN is the odd one: it reads a SIGNED element and writes an UNSIGNED
/// one, so a negative operand is not a large answer but the smallest one.
/// </summary>
let qxtn (ins: Instruction) bld isPart2 srcUnsigned dstUnsigned =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    match dst with
    | OprSIMD(ScalarReg _) ->
      let struct (eSize, _, _) = getElemDataSzAndElems src
      let e = transOpr ins bld src
      let result = satNarrow bld e eSize srcUnsigned dstUnsigned
      dstAssignScalar ins bld dst result (eSize / 2)
    | _ ->
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src = transSIMDOprToExpr bld eSize dataSize elements src
      let result = Array.init elements (fun _ -> tmpVar bld (eSize / 2))
      Array.map (fun e -> satNarrow bld e eSize srcUnsigned dstUnsigned) src
      |> Array.iter2 (fun r e -> append bld { direct r := e }) result
      if isPart2 then
        direct dstB := AST.revConcat result
      else
        direct dstA := AST.revConcat result
        direct dstB := AST.num0 64<rt>
  }

/// <summary>
/// SRSHR, URSHR and the two that accumulate: a shift right that rounds.
///
/// Half of what the shift discards is added first, at twice the element's
/// width so that the addition cannot carry out of the element, and the
/// widening is the one the mnemonic names.
/// </summary>
let rshr (ins: Instruction) bld unsigned accumulate =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let dbl = eSize * 2
    let ext = if unsigned then AST.zext else AST.sext
    let amt = transOpr ins bld o3 |> AST.xtlo 8<rt> |> AST.zext dbl
    let rnd = AST.num1 dbl << (amt .- AST.num1 dbl)
    let shifted e = AST.xtlo eSize ((ext dbl e .+ rnd) >> amt)
    match o1 with
    | OprSIMD(ScalarReg _) ->
      let dst = transOpr ins bld o1
      let src = transOpr ins bld o2
      let result =
        if accumulate then dst .+ shifted src else shifted src
      dstAssignScalar ins bld o1 result eSize
    | _ ->
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let dst = transSIMDOprToExpr bld eSize dataSize elements o1
      let src = transSIMDOprToExpr bld eSize dataSize elements o2
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      Array.iteri (fun i r ->
        append bld {
          direct r :=
            if accumulate then dst[i] .+ shifted src[i] else shifted src[i]
        }) result
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

/// <summary>
/// SLI and SRI: a shift that keeps what the shift vacated rather than
/// filling it with zeros.
///
/// What is kept is the destination's own bits in the places the shifted
/// operand does not reach, which is why the destination is read as well as
/// written and why the mask is built from the shift amount.
/// </summary>
let shiftInsert (ins: Instruction) bld isLeft =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let amt = transOpr ins bld o3 |> AST.xtlo 8<rt> |> AST.zext eSize
    let ones = AST.not (AST.num0 eSize)
    (* The bits the shift leaves behind: the low ones for a left shift and the
       high ones for a right shift. *)
    let keep = if isLeft then AST.not (ones << amt) else AST.not (ones >> amt)
    let insert d e = (if isLeft then e << amt else e >> amt) .| (d .& keep)
    match o1 with
    | OprSIMD(ScalarReg _) ->
      let dst = transOpr ins bld o1
      let src = transOpr ins bld o2
      dstAssignScalar ins bld o1 (insert dst src) eSize
    | _ ->
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let dst = transSIMDOprToExpr bld eSize dataSize elements o1
      let src = transSIMDOprToExpr bld eSize dataSize elements o2
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      Array.iteri (fun i r ->
        append bld { direct r := insert dst[i] src[i] }) result
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

/// <summary>
/// SQABS and SQNEG, which clamp rather than wrap.
///
/// There is one operand each of them cannot answer: the most negative value
/// has no positive counterpart at the same width, and both instructions give
/// the largest positive one instead. The arithmetic is done a width wider so
/// that the value which has no answer is still there to be recognised.
/// </summary>
let qabsneg (ins: Instruction) bld isNeg =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let dbl = eSize * 2
    let value e =
      let w = AST.sext dbl e
      if isNeg then AST.neg w
      else AST.ite (w ?< AST.num0 dbl) (AST.neg w) w
    match o1 with
    | OprSIMD(ScalarReg _) ->
      let src = transOpr ins bld o2
      dstAssignScalar ins bld o1 (signedSatQ bld (value src) eSize) eSize
    | _ ->
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let src = transSIMDOprToExpr bld eSize dataSize elements o2
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      Array.map (fun e -> signedSatQ bld (value e) eSize) src
      |> Array.iter2 (fun r e -> append bld { direct r := e }) result
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

/// <summary>
/// SUQADD and USQADD, which add one signedness to the other.
///
/// SUQADD accumulates an unsigned operand into a signed destination and
/// clamps the answer to the signed range; USQADD is the other way round in
/// both. The sum is taken a width wider, where an operand of either
/// signedness fits and the answer that went out of range is still there.
/// </summary>
let usqadd (ins: Instruction) bld dstUnsigned =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let dbl = eSize * 2
    let extDst = if dstUnsigned then AST.zext dbl else AST.sext dbl
    let extSrc = if dstUnsigned then AST.sext dbl else AST.zext dbl
    let sum d e = extDst d .+ extSrc e
    match o1 with
    | OprSIMD(ScalarReg _) ->
      let dst = transOpr ins bld o1
      let src = transOpr ins bld o2
      let result = satQ bld (sum dst src) eSize dstUnsigned
      dstAssignScalar ins bld o1 result eSize
    | _ ->
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let dst = transSIMDOprToExpr bld eSize dataSize elements o1
      let src = transSIMDOprToExpr bld eSize dataSize elements o2
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      Array.iteri (fun i r ->
        let v = satQ bld (sum dst[i] src[i]) eSize dstUnsigned
        append bld { direct r := v }) result
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let abs (ins: Instruction) bld =
  lift bld ins {
    match ins.Operands with
    | TwoOperands(OprSIMD(VecReg _) as o1, o2) ->
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems o2
      let n0 = AST.num0 eSize
      let src = transSIMDOprToExpr bld eSize dataSize elements o2
      let result = Array.map (fun e -> AST.ite (e ?> n0) e (AST.neg e)) src
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | TwoOperands(OprSIMD(ScalarReg _) as o1, o2) ->
      let struct (eSize, _, _) = getElemDataSzAndElems o1
      let src = transOpr ins bld o2
      let n0 = AST.num0 eSize
      let result = AST.ite (src ?> n0) src (AST.neg src)
      dstAssignScalar ins bld o1 result eSize
    | _ ->
      let struct (dst, src) = getTwoOprs ins
      let n0 = AST.num0 ins.OprSize
      let dst = transOpr ins bld dst
      let src = transOpr ins bld src
      let result = AST.ite (src ?> n0) src (AST.neg src)
      sized ins.OprSize dst := result
  }

let add (ins: Instruction) bld =
  lift bld ins {
    match ins.Operands with
    | ThreeOperands(OprSIMD(VecReg _) as o1, o2, o3) ->
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
      let result = Array.map2 (.+) src1 src2
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | ThreeOperands(o1, _, _) (* SIMD Scalar *) ->
      let _, src1, src2 = transThreeOprs ins bld
      let struct (eSize, _, _) = getElemDataSzAndElems o1
      dstAssignScalar ins bld o1 (src1 .+ src2) eSize
    | FourOperands _ (* Arithmetic *) ->
      let dst, s1, s2 = transFourOprsWithBarrelShift ins bld
      let result, _ = addWithCarry s1 s2 (AST.num0 ins.OprSize) ins.OprSize
      sized ins.OprSize dst := result
    | _ ->
      raise InvalidOperandException
  }

let addp (ins: Instruction) bld =
  lift bld ins {
    match ins.Operands with
    | TwoOperands(dst, src) -> (* Scalar *)
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
      let src = transSIMDOprToExpr bld eSize dataSize elements src
      let result = Array.reduce (.+) src
      dstAssignScalar ins bld dst result eSize
    | ThreeOperands(dst, src1, src2) -> (* Vector *)
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
      let src2 = transSIMDOprToExpr bld eSize dataSize elements src2
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      Array.append src1 src2 |> Array.chunkBySize 2
      |> Array.map (fun e -> e[0] .+ e[1])
      |> Array.iter2 (fun e1 e2 -> append bld { direct e1 := e2 }) result
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      raise InvalidOperandException
  }

let addv (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
    let src = transSIMDOprToExpr bld eSize dataSize elements src
    let result = Array.reduce (.+) src
    dstAssignScalar ins bld dst result eSize
  }

let logAnd (ins: Instruction) bld = (* AND *)
  lift bld ins {
    match ins.Operands with
    | ThreeOperands(OprSIMD(VecReg _) as dst, src1, src2) ->
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let struct (src1B, src1A) = transOpr128 ins bld src1
      let struct (src2B, src2A) = transOpr128 ins bld src2
      direct dstA := src1A .& src2A
      if ins.OprSize = 64<rt> then
        append bld { direct dstB := AST.num0 ins.OprSize }
      else
        append bld { direct dstB := src1B .& src2B }
    | _ ->
      let dst, src1, src2 = transOprOfAND ins bld
      sized ins.OprSize dst := src1 .& src2
  }

let bic (ins: Instruction) bld =
  lift bld ins {
    match ins.Operands with
    | ThreeOperands(OprSIMD(VecReg _), OprSIMD(VecReg _), _) ->
      let struct (dst, src1, src2) = getThreeOprs ins
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
      let src2 = transSIMDOprToExpr bld eSize dataSize elements src2
      let result = Array.map2 (fun s1 s2 -> s1 .& AST.not s2) src1 src2
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | ThreeOperands(OprSIMD(VecReg _), OprImm _, OprShift _) ->
      let struct (dst, src, amount) = getThreeOprs ins
      let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let imm =
        transBarrelShiftToExpr ins.OprSize bld src amount
        |> advSIMDExpandImm bld eSize |> AST.not
      dstAssign128 ins bld dst (dstA .& imm) (dstB .& imm) dataSize
    | TwoOperands(OprSIMD(VecReg _), OprImm _) ->
      let struct (dst, src) = getTwoOprs ins
      let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src = transOpr ins bld src
      let imm = advSIMDExpandImm bld eSize src |> AST.not
      dstAssign128 ins bld dst (dstA .& imm) (dstB .& imm) dataSize
    | _ ->
      let dst, src1, src2 = transFourOprsWithBarrelShift ins bld
      sized ins.OprSize dst := src1 .& AST.not src2
  }

let private bitInsert (ins: Instruction) bld isTrue =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld dst
    let struct (src1B, src1A) = transOpr128 ins bld src1
    let struct (src2B, src2A) = transOpr128 ins bld src2
    let struct (opr1A, opr3A, opr4A) = tmpVars3 bld 64<rt>
    let struct (opr1B, opr3B, opr4B) = tmpVars3 bld 64<rt>
    direct opr1A := dstA
    direct opr1B := dstB
    direct opr3A := if isTrue then src2A else AST.not src2A
    direct opr3B := if isTrue then src2B else AST.not src2B
    direct opr4A := src1A
    direct opr4B := src1B
    direct dstA := AST.xor opr1A ((AST.xor opr1A opr4A) .& opr3A)
    if ins.OprSize = 128<rt> then
      direct dstB := AST.xor opr1B ((AST.xor opr1B opr4B) .& opr3B)
    else
      direct dstB := AST.num0 64<rt>
  }

let bif ins bld = bitInsert ins bld false

let bit ins bld = bitInsert ins bld true

let bsl (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld dst
    let struct (src1B, src1A) = transOpr128 ins bld src1
    let struct (src2B, src2A) = transOpr128 ins bld src2
    let struct (opr1A, opr3A, opr4A) = tmpVars3 bld 64<rt>
    let struct (opr1B, opr3B, opr4B) = tmpVars3 bld 64<rt>
    direct opr1A := src2A
    direct opr1B := src2B
    direct opr3A := dstA
    direct opr3B := dstB
    direct opr4A := src1A
    direct opr4B := src1B
    direct dstA := AST.xor opr1A ((AST.xor opr1A opr4A) .& opr3A)
    if ins.OprSize = 128<rt> then
      direct dstB := AST.xor opr1B ((AST.xor opr1B opr4B) .& opr3B)
    else
      direct dstB := AST.num0 64<rt>
  }

let cls (ins: Instruction) bld =
  lift bld ins {
    match ins.Operands with
    | TwoOperands(OprSIMD(VecReg _) as o1, o2) ->
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems o2
      let src = transSIMDOprToExpr bld eSize dataSize elements o2
      let result = Array.map (fun e -> clsBits e eSize bld) src
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      let dst, src = transTwoOprs ins bld
      let result = clsBits src ins.OprSize bld
      sized ins.OprSize dst := result
  }

let clz (ins: Instruction) bld =
  lift bld ins {
    match ins.Operands with
    | TwoOperands(OprSIMD(VecReg _) as o1, o2) ->
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems o2
      let src = transSIMDOprToExpr bld eSize dataSize elements o2
      let result = Array.map (fun e -> clzBits e (int eSize) eSize bld) src
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      let dst, src = transTwoOprs ins bld
      let result = clzBits src (int ins.OprSize) ins.OprSize bld
      sized ins.OprSize dst := result
  }

let private compare (ins: Instruction) bld cond =
  lift bld ins {
    match ins.Operands with
    (* zero *)
    | ThreeOperands(OprSIMD(VecReg _) as o1, o2, OprImm _) ->
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let struct (ones, zeros) = tmpVars2 bld eSize
      direct ones := numI64 -1L eSize
      direct zeros := AST.num0 eSize
      let result = Array.map (fun e -> AST.ite (cond e zeros) ones zeros) src1
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | ThreeOperands(OprSIMD(ScalarReg _) as o1, o2, OprImm _) ->
      let struct (eSize, _, _) = getElemDataSzAndElems o1
      let src1 = transOpr ins bld o2
      let num0 = AST.num0 64<rt>
      let result = tmpVar bld 64<rt>
      direct result := AST.ite (cond src1 num0) (numI64 -1L 64<rt>) num0
      dstAssignScalar ins bld o1 result eSize
    (* register *)
    | ThreeOperands(OprSIMD(VecReg _) as o1, o2, o3) ->
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
      let struct (ones, zeros) = tmpVars2 bld eSize
      direct ones := numI64 -1L eSize
      direct zeros := AST.num0 eSize
      let result =
        Array.map2 (fun e1 e2 -> AST.ite (cond e1 e2) ones zeros) src1 src2
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | ThreeOperands(OprSIMD(ScalarReg _) as o1, o2, o3) ->
      let struct (eSize, _, _) = getElemDataSzAndElems o1
      let src1 = transOpr ins bld o2
      let src2 = transOpr ins bld o3
      let num0 = AST.num0 64<rt>
      let result = tmpVar bld 64<rt>
      direct result := AST.ite (cond src1 src2) (numI64 -1L 64<rt>) num0
      dstAssignScalar ins bld o1 result eSize
    | _ ->
      raise InvalidOperandException
  }

let cmeq ins bld = compare ins bld (==)

let cmgt ins bld = compare ins bld (?>)

let cmge ins bld = compare ins bld (?>=)

let private cmpHigher (ins: Instruction) bld cond =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (ones, zeros) = tmpVars2 bld eSize
    direct ones := numI64 -1L eSize
    direct zeros := AST.num0 eSize
    match dst with
    | OprSIMD(ScalarReg _) ->
      let _, src1, src2 = transThreeOprs ins bld
      let result = AST.ite (cond src1 src2) ones zeros
      dstAssignScalar ins bld dst result eSize
    | _ ->
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
      let src2 = transSIMDOprToExpr bld eSize dataSize elements src2
      let result =
        Array.map2 (fun e1 e2 -> AST.ite (cond e1 e2) ones zeros) src1 src2
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let cmhi ins bld = cmpHigher ins bld (.>)

let cmhs ins bld = cmpHigher ins bld (.>=)

/// The compares against zero, whose only difference is which side of it the
/// answer is true on.
let private cmpZero (ins: Instruction) bld cond =
  lift bld ins {
    let struct (dst, src1, _) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (ones, zeros) = tmpVars2 bld eSize
    direct ones := numI64 -1L eSize
    direct zeros := AST.num0 eSize
    match dst with
    | OprSIMD(ScalarReg _) ->
      let src1 = transOpr ins bld src1
      let result = AST.ite (cond src1 zeros) ones zeros
      dstAssignScalar ins bld dst result eSize
    | _ ->
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
      let result = Array.map (fun e -> AST.ite (cond e zeros) ones zeros) src1
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

/// CMLE, which is CMLT with the boundary on the other side of zero.
let cmle (ins: Instruction) bld = cmpZero ins bld (?<=)

let cmlt (ins: Instruction) bld = cmpZero ins bld (?<)

let cmtst (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (ones, zeros) = tmpVars2 bld eSize
    direct ones := numI64 -1L eSize
    direct zeros := AST.num0 eSize
    match dst with
    | OprSIMD(ScalarReg _) ->
      let _, src1, src2 = transThreeOprs ins bld
      let result = AST.ite ((src1 .& src2) != zeros) ones zeros
      dstAssignScalar ins bld dst result eSize
    | _ ->
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let s1 = transSIMDOprToExpr bld eSize dataSize elements src1
      let s2 = transSIMDOprToExpr bld eSize dataSize elements src2
      let result =
        Array.map2 (fun e1 e2 -> AST.ite ((e1 .& e2) != zeros) ones zeros) s1 s2
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let cnt (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (dstB, dstA) = transOpr128 ins bld dst
    let src = transSIMDOprToExpr bld eSize dataSize elements src
    let result = Array.map (bitCount eSize) src
    dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let dup ins bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (dstB, dstA) = transOpr128 ins bld dst
    let src = transOpr ins bld src
    let element = tmpVar bld eSize
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    direct element := AST.xtlo eSize src
    Array.iter (fun e -> append bld { direct e := element }) result
    dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let eor (ins: Instruction) bld =
  lift bld ins {
    match ins.Operands with
    | ThreeOperands(OprSIMD(VecReg _) as o1, o2, o3) ->
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let struct (src1B, src1A) = transOpr128 ins bld o2
      let struct (src2B, src2A) = transOpr128 ins bld o3
      let struct (opr2, opr3) = tmpVars2 bld 64<rt>
      direct opr2 := AST.num0 64<rt>
      direct opr3 := numI64 -1L 64<rt>
      direct dstA := src2A <+> ((opr2 <+> src1A) .& opr3)
      if ins.OprSize = 64<rt> then
        append bld { direct dstB := AST.num0 ins.OprSize }
      else
        append bld { direct dstB := src2B <+> ((opr2 <+> src1B) .& opr3) }
    | _ ->
      let dst, src1, src2 = transOprOfEOR ins bld
      sized ins.OprSize dst := src1 <+> src2
  }

let ext (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2, idx) = getFourOprs ins
    let pos = getImmValue idx |> int
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (dstB, dstA) = transOpr128 ins bld dst
    let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
    let src2 = transSIMDOprToExpr bld eSize dataSize elements src2
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    let concat = Array.append src1 src2
    let res = Array.sub concat pos (dataSize / eSize)
    Array.iter2 (fun res s -> append bld { direct res := s }) result res
    dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let extr ins bld =
  lift bld ins {
    let dst, src1, src2, lsb = transOprOfEXTR ins bld
    let oSz = ins.OprSize
    if oSz = 32<rt> then
      let con = tmpVar bld 64<rt>
      direct con := AST.concat src1 src2
      let mask = numI64 0xFFFFFFFFL 64<rt>
      sized ins.OprSize dst := (con >> (AST.zext 64<rt> lsb)) .& mask
    elif oSz = 64<rt> then
      let lsb =
        match ins.Operands with
        | ThreeOperands(_, _, OprLSB shift) -> int32 shift
        | FourOperands(_, _, _, OprLSB lsb) -> int32 lsb
        | _ -> raise InvalidOperandException
      if lsb = 0 then
        direct dst := src2
      else
        let leftAmt = numI32 (64 - lsb) 64<rt>
        direct dst := (src1 << leftAmt) .| (src2 >> (numI32 lsb 64<rt>))
    else
      raise InvalidOperandSizeException
  }

let fabd (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let n1 = tmpVar bld eSize
    direct n1 := AST.num1 eSize
    let fpAbsDiff e1 e2 = ((fpSub bld eSize e1 e2) << n1) >> n1
    match dst with
    | OprSIMD(ScalarReg _) ->
      let _, src1, src2 = transThreeOprs ins bld
      dstAssignScalar ins bld dst (fpAbsDiff src1 src2) eSize
    | OprSIMD(VecReg _) ->
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
      let src2 = transSIMDOprToExpr bld eSize dataSize elements src2
      let result = Array.map2 (fpAbsDiff) src1 src2
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      raise InvalidOperandException
  }

let fabs (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let n1 = tmpVar bld eSize
    direct n1 := AST.num1 eSize
    match dst with
    | OprSIMD(ScalarReg _) ->
      let src = transOpr ins bld src
      dstAssignScalar ins bld dst ((src << n1) >> n1) eSize
    | OprSIMD(VecReg _) ->
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src = transSIMDOprToExpr bld eSize dataSize elements src
      let result = Array.map (fun e -> (e << n1) >> n1) src
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      raise InvalidOperandException
  }

let fadd (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    match dst with
    | OprSIMD(ScalarReg _) ->
      let _, src1, src2 = transThreeOprs ins bld
      let result = fpAdd bld dataSize src1 src2
      dstAssignScalar ins bld dst result eSize
    | OprSIMD(VecReg _) ->
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
      let src2 = transSIMDOprToExpr bld eSize dataSize elements src2
      let result = Array.map2 (fpAdd bld eSize) src1 src2
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      raise InvalidOperandException
  }

/// <summary>
/// An across-vector reduction, which the architecture does as a TREE and not
/// as a running total: the elements are folded in pairs, then the pairs in
/// pairs.
///
/// The order is visible in the numeric forms, where a NaN is given up in
/// favour of the other operand. A signalling NaN in the LAST element survives
/// a left fold -- nothing comes after it to drop it, so it is quieted and
/// carried out as the answer -- and does not survive this. That is one case
/// in a vector of four, and it is what FMAXNMV and FMINNMV came back
/// disagreeing about.
/// </summary>
let rec private reduceTree fp (xs: Expr[]) =
  if Array.length xs = 1 then
    xs[0]
  else
    Array.init (Array.length xs / 2) (fun i -> fp xs[i * 2] xs[i * 2 + 1])
    |> reduceTree fp

/// <summary>
/// The pairwise and across-vector floating-point extremes: FMAXP, FMINP,
/// their numeric twins, and the four that reduce a whole vector to one
/// value.
///
/// The pairwise form takes the two operands' elements in order and folds each
/// adjacent pair; the across form folds every element of the one operand it
/// has. Both use the same primitive as the two-operand FMAX and FMIN, so a
/// NaN propagates here exactly as it does there.
/// </summary>
let fpMaxMinReduce (ins: Instruction) bld fp =
  lift bld ins {
    match ins.Operands with
    | TwoOperands(dst, src) ->
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
      let src = transSIMDOprToExpr bld eSize dataSize elements src
      let result = reduceTree (fp bld eSize) src
      dstAssignScalar ins bld dst result eSize
    | ThreeOperands(dst, src1, src2) ->
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
      let src2 = transSIMDOprToExpr bld eSize dataSize elements src2
      let result =
        Array.append src1 src2
        |> Array.chunkBySize 2
        |> Array.map (fun e -> fp bld eSize e[0] e[1])
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      raise InvalidOperandException
  }

/// <summary>
/// FMULX, which is FMUL everywhere except at zero times infinity.
///
/// The indexed form points every lane at the same element of the second
/// operand, which is the only other thing it does differently.
/// </summary>
let fmulx (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    match ins.Operands with
    | ThreeOperands(OprSIMD(VecReg _), _, _) ->
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let src2 =
        match o3 with
        | OprSIMD(VecRegWithIdx _) ->
          let e = transOpr ins bld o3
          Array.create elements e
        | _ ->
          transSIMDOprToExpr bld eSize dataSize elements o3
      let result = Array.map2 (fpMulX bld eSize) src1 src2
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      let src1 = transOpr ins bld o2
      let src2 = transOpr ins bld o3
      dstAssignScalar ins bld o1 (fpMulX bld eSize src1 src2) eSize
  }

let fmaxp ins bld =
  fpMaxMinReduce ins bld (fun bld eSize -> fpMaxMin bld eSize true)

let fminp ins bld =
  fpMaxMinReduce ins bld (fun bld eSize -> fpMaxMin bld eSize false)

let fmaxnmp ins bld =
  fpMaxMinReduce ins bld (fun bld eSize -> fpMaxMinNum bld eSize true)

let fminnmp ins bld =
  fpMaxMinReduce ins bld (fun bld eSize -> fpMaxMinNum bld eSize false)

let faddp (ins: Instruction) bld =
  lift bld ins {
    match ins.Operands with
    | TwoOperands(dst, src) -> (* Scalar *)
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
      let src = transSIMDOprToExpr bld eSize dataSize elements src
      let result =
        Array.chunkBySize 2 src
        |> Array.map (fun e -> fpAdd bld eSize e[0] e[1])
        |> Array.reduce(.+)
      dstAssignScalar ins bld dst result eSize
    | ThreeOperands(dst, src1, src2) -> (* Vector *)
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
      let src2 = transSIMDOprToExpr bld eSize dataSize elements src2
      let concat = Array.append src1 src2
      let result =
        Array.chunkBySize 2 concat
        |> Array.map (fun e -> fpAdd bld eSize e[0] e[1])
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      raise InvalidOperandException
  }

/// <summary>
/// A lane read at the width the comparison is made at.
///
/// A half has no comparison of its own to reach, so its lanes are widened to
/// singles first. Widening is exact, so the verdict is the one the manual
/// asks for -- and the mask that goes back is still the HALF's, because only
/// the reading widens.
/// </summary>
let private compareWidth bld eSize e =
  if eSize <> 16<rt> then
    e
  else
    let t = tmpVar bld 32<rt>
    let w = halfToSingleAsIs bld e
    append bld { direct t := w }
    t

/// <summary>
/// What one lane of a floating-point comparison answers: a mask of ones
/// where it holds, of zeros where it does not, and of zeros where either
/// side is a NaN whichever comparison was asked for.
///
/// And what it raised. Equality is FPCompareEQ, which raises Invalid only
/// for a signalling NaN; every ordering is FPCompareGE or FPCompareGT, which
/// raise it for a quiet one too -- that is the difference `signals` carries.
/// </summary>
let private compareLane bld wSize cmp absolute signals ones zeros e1 e2 =
  let signBit =
    match wSize with
    | 64<rt> -> numU64 0x8000000000000000UL 64<rt>
    | _ -> numU64 0x80000000UL 32<rt>
  let mag e = if absolute then e .& AST.not signBit else e
  let holds =
    cmp (checkZero bld wSize (mag e1)) (checkZero bld wSize (mag e2))
  let anyNaN = (isNaN wSize e1) .| (isNaN wSize e2)
  fpExceptionsCompare bld wSize signals e1 e2
  AST.ite anyNaN zeros (AST.ite holds ones zeros)

/// <summary>
/// The floating-point compares that answer with a mask rather than with the
/// flags.
///
/// Each writes all ones where the comparison holds and zero where it does
/// not, and zero for any pair that includes a NaN: an unordered pair
/// satisfies none of these predicates, which is why the NaN test comes first
/// and not out of the comparison.
///
/// The absolute forms compare magnitudes, which is the sign bit cleared on
/// the way in and nothing else.
/// </summary>
let private fpCompare (ins: Instruction) bld cmp absolute signals =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (ones, zeros) = tmpVars2 bld eSize
    let wSize = if eSize = 16<rt> then 32<rt> else eSize
    let wide e = compareWidth bld eSize e
    let lane e1 e2 =
      compareLane bld wSize cmp absolute signals ones zeros e1 e2
    direct ones := numI64 -1L eSize
    direct zeros := AST.num0 eSize
    match dst, src2 with
    | OprSIMD(ScalarReg _) as o1, _ ->
      let _, s1, s2 = transThreeOprs ins bld
      dstAssignScalar ins bld o1 (lane (wide s1) (wide s2)) eSize
    | OprSIMD(VecReg _), OprFPImm _ ->
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let s1 = transSIMDOprToExpr bld eSize dataSize elements src1
      let z = wide (transOpr ins bld src2 |> AST.xtlo eSize)
      let result = Array.map (fun e -> lane (wide e) z) s1
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | OprSIMD(VecReg _), _ ->
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let s1 = transSIMDOprToExpr bld eSize dataSize elements src1
      let s2 = transSIMDOprToExpr bld eSize dataSize elements src2
      let result = Array.map2 (fun a b -> lane (wide a) (wide b)) s1 s2
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      raise InvalidOperandException
  }

let fcmgt ins bld = fpCompare ins bld AST.fgt false true

let fcmge ins bld = fpCompare ins bld AST.fge false true

let fcmeq ins bld = fpCompare ins bld AST.feq false false

let fcmlt ins bld = fpCompare ins bld AST.flt false true

let fcmle ins bld = fpCompare ins bld AST.fle false true

/// FACGT and FACGE, the same two comparisons on magnitudes.
let facgt ins bld = fpCompare ins bld AST.fgt true true

let facge ins bld = fpCompare ins bld AST.fge true true

/// <summary>
/// The rotation a complex instruction names, as the number of quarter turns.
/// </summary>
let private quarterTurns rot =
  match rot with
  | OprImm deg -> int (deg / 90L)
  | _ -> raise InvalidOperandException

/// <summary>
/// FCADD: each complex pair of the second source rotated by 90 or 270
/// degrees and added to the first source's.
///
/// A rotation by 90 takes (x, y) to (-y, x) and one by 270 to (y, -x), and
/// the negation is FPNeg, a flip of the sign bit that a NaN is not spared.
/// </summary>
let fcadd (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2, rot) = getFourOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (dstB, dstA) = transOpr128 ins bld dst
    let a = transSIMDOprToExpr bld eSize dataSize elements src1
    let b = transSIMDOprToExpr bld eSize dataSize elements src2
    let turned = quarterTurns rot = 3
    let lane i =
      let pair = i / 2 * 2
      let other =
        match i % 2 = 0, turned with
        | true, false -> fpneg b[pair + 1] eSize
        | true, true -> b[pair + 1]
        | false, false -> b[pair]
        | false, true -> fpneg b[pair] eSize
      let t = tmpVar bld eSize
      let sum = fpAdd bld eSize a[i] other
      append bld { direct t := sum }
      t
    let result = Array.init elements lane
    dstAssignForSIMD dstA dstB result dataSize elements bld
  }

/// <summary>
/// The two products one FCMLA lane pair adds, for a pair of the first source
/// and one of the second: which part of the first each multiplies, and the
/// second's parts in the order the rotation puts them, negated where it
/// turns them past the axis.
/// </summary>
let private complexTerms eSize turns (a: Expr[]) pair (re, im) =
  let aRe, aIm = a[pair], a[pair + 1]
  match turns with
  | 0 -> struct (aRe, re, aRe, im)
  | 1 -> struct (aIm, fpneg im eSize, aIm, re)
  | 2 -> struct (aRe, fpneg re eSize, aRe, fpneg im eSize)
  | _ -> struct (aIm, im, aIm, fpneg re eSize)

/// One pair of FCMLA's result: two fused multiply-adds into the
/// destination's pair, each rounded once.
let private complexPair bld eSize (acc: Expr[]) pair terms =
  let struct (x1, y1, x2, y2) = terms
  let struct (r1, r2) = tmpVars2 bld eSize
  let e1 = fpMulAdd bld eSize acc[pair] x1 y1
  append bld { direct r1 := e1 }
  let e2 = fpMulAdd bld eSize acc[pair + 1] x2 y2
  append bld { direct r2 := e2 }
  [| r1; r2 |]

/// <summary>
/// FCMLA: each complex pair of the second source rotated by a quarter turn
/// times the rotation, multiplied by one part of the first source's pair,
/// and added to the destination's pair with one rounding.
///
/// On whole vectors the pairs of the two sources meet pair by pair; by
/// element, every pair of the first meets the one pair of the second that
/// the index names.
/// </summary>
let fcmla (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2, rot) = getFourOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (dstB, dstA) = transOpr128 ins bld dst
    let a = transSIMDOprToExpr bld eSize dataSize elements src1
    let acc = transSIMDOprToExpr bld eSize dataSize elements dst
    let second pair =
      match src2 with
      | OprSIMD(VecRegWithIdx(reg, _, idx)) ->
        let full = if eSize = 16<rt> then EightH else FourS
        let lanes = 128 / int eSize
        let whole = OprSIMD(VecReg(reg, full))
        let b = transSIMDOprToExpr bld eSize 128<rt> lanes whole
        b[int idx * 2], b[int idx * 2 + 1]
      | _ ->
        let b = transSIMDOprToExpr bld eSize dataSize elements src2
        b[pair], b[pair + 1]
    let turns = quarterTurns rot
    let pairOf p =
      let terms = complexTerms eSize turns a (p * 2) (second (p * 2))
      complexPair bld eSize acc (p * 2) terms
    let result = Array.init (elements / 2) pairOf |> Array.concat
    dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let fcsel ins bld =
  lift bld ins {
    let o1, s1, s2, cond = transOprOfFCSEL ins bld
    let struct (eSize, _, _) = getElemDataSzAndElems o1
    let result = AST.ite (conditionHolds bld cond) s1 s2
    dstAssignScalar ins bld o1 result eSize
  }

/// <summary>
/// The constants FPRecipStepFused and FPRSqrtStepFused are written around:
/// two, three, one and a half, and a half, in the size being worked in.
/// </summary>
let private stepConstants eSize =
  match eSize with
  | 32<rt> ->
    let two = numU32 0x40000000u 32<rt>
    let three = numU32 0x40400000u 32<rt>
    let onePointFive = numU32 0x3fc00000u 32<rt>
    struct (two, three, onePointFive, numU32 0x3f000000u 32<rt>)
  | 64<rt> ->
    let two = numU64 0x4000000000000000UL 64<rt>
    let three = numU64 0x4008000000000000UL 64<rt>
    let onePointFive = numU64 0x3ff8000000000000UL 64<rt>
    struct (two, three, onePointFive, numU64 0x3fe0000000000000UL 64<rt>)
  | _ ->
    raise InvalidOperandSizeException

/// The sign an infinite answer carries: the two operands' signs exclusive
/// ored, with the first operand's taken AFTER the negation the step begins
/// with.
let private stepInfinity eSize a b =
  let top = int eSize - 1
  let sign = AST.extract a 1<rt> top <+> AST.extract b 1<rt> top <+> AST.b1
  let inf =
    match eSize with
    | 32<rt> -> numU32 0x7f800000u 32<rt>
    | _ -> numU64 0x7ff0000000000000UL 64<rt>
  AST.ite sign (inf .| (AST.num1 eSize << numI32 top eSize)) inf

/// <summary>
/// The operands FRSQRTS's one rounding is taken on, and whether its answer is
/// halved after it.
///
/// Three less the product, halved, is one and a half less the product with
/// its larger operand halved -- which never computes three less the product,
/// a value that can run past the top of the range where its half does not.
/// Halving that operand is exact unless it is subnormal, and then both are
/// and the product is far too small to reach the top, so the step keeps three
/// and halves its answer instead: exact again, since three less so small a
/// product is nowhere near subnormal. A NaN or an infinity keeps the operands
/// as they came, for the flags to read.
/// </summary>
let private sqrtStepTerms bld eSize a b =
  let struct (_, three, onePointFive, half) = stepConstants eSize
  let mBits, maxExp = if eSize = 32<rt> then 23, 0xff else 52, 0x7ff
  let top = numI32 (int eSize - 1) eSize
  let magnitude e = e .& ((AST.num1 eSize << top) .- AST.num1 eSize)
  let struct (x, y, addend) = tmpVars3 bld eSize
  let halving = tmpVar bld 1<rt>
  let aBig = magnitude a .>= magnitude b
  let big = AST.ite aBig a b
  let small = AST.ite aBig b a
  let e = magnitude big >> numI32 mBits eSize
  let exactHalf = (e .> AST.num1 eSize) .& (e .< numI32 maxExp eSize)
  append bld {
    direct halving := AST.not exactHalf
    direct x := AST.ite halving a (AST.fmul big half)
    direct y := AST.ite halving b small
    direct addend := AST.ite halving three onePointFive
  }
  struct (x, y, addend, halving)

/// <summary>
/// One lane of FRECPS or FRSQRTS: the manual's FPRecipStepFused and
/// FPRSqrtStepFused.
///
/// The value is two less the product, or three less it and then halved, and
/// it is FULLY FUSED -- one rounding for the multiply and the addition
/// together. Computing the product and subtracting it separately rounds
/// twice and gives a different answer wherever the product lands close to
/// the constant, which is exactly where these instructions are used.
///
/// The manual negates the first operand before anything else, and that shows
/// in more than the arithmetic: a NaN operand comes back with its SIGN
/// INVERTED, because what propagates is the negated operand rather than the
/// one the instruction was given.
///
/// Infinity times zero is the one product the fused form cannot compute, so
/// the manual names it: the answer is two, or one and a half, positive
/// however the operands were signed. An infinity anywhere else gives an
/// infinity whose sign is the two operands' exclusive or.
/// </summary>
let private recipStep bld eSize isSqrt a b =
  let struct (two, _, onePointFive, half) = stepConstants eSize
  (* the NaN that propagates is the NEGATED first operand's, because the
     negation is the first thing the manual does -- which is why a NaN comes
     back with its sign inverted rather than as it went in *)
  let negA = tmpVar bld eSize
  let top = numI32 (int eSize - 1) eSize
  append bld { direct negA := a <+> (AST.num1 eSize << top) }
  let struct (isNaN, resNaN) = fpProcessNaNs bld eSize negA b
  let struct (x, y, addend, halving) =
    if isSqrt then sqrtStepTerms bld eSize a b
    else struct (a, b, two, AST.b0)
  let fused = tmpVar bld eSize
  append bld { direct fused := fma eSize true false x y addend }
  let ordinary = AST.ite halving (AST.fmul fused half) fused
  let degenerate =
    (isInfinity eSize a .& isZero eSize b)
    .| (isZero eSize a .& isInfinity eSize b)
  let anyInf = isInfinity eSize a .| isInfinity eSize b
  let res = tmpVar bld eSize
  let infOrOrdinary = AST.ite anyInf (stepInfinity eSize a b) ordinary
  let named = if isSqrt then onePointFive else two
  let finite = AST.ite degenerate named infOrOrdinary
  append bld { direct res := AST.ite isNaN resNaN finite }
  (* what the one rounding raised: the degenerate product raises nothing, so
     it is asked of the constant the manual answers with and not of the NaN
     the arithmetic would make of it *)
  fpExceptionsFused bld eSize true x y addend (AST.ite degenerate addend fused)
  res

/// <summary>
/// The same step for halves, which is done in doubles.
///
/// The step is FUSED, and a fused step on halves cannot be done in singles:
/// the exact 2 - a*b can put a single's rounding exactly on a half's
/// midpoint, and the second rounding then goes to even the wrong way. 2414
/// stepped against 27d9 is 3fff where rounding through a single gives 4000,
/// and 588 pairs of significands do the same for each of FRECPS and FRSQRTS.
/// In a double the step on two halves is exact, so it rounds once.
/// </summary>
let private recipStepHalf bld isSqrt a b =
  let op (w: Expr[]) = recipStep bld 64<rt> isSqrt w[0] w[1]
  viaDouble bld op [| a; b |]

/// <summary>
/// FRECPS and FRSQRTS, a step of the Newton-Raphson iteration that turns an
/// estimate into a reciprocal or a reciprocal square root.
/// </summary>
let private recipStepOp (ins: Instruction) bld isSqrt =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let lane a b =
      if eSize = 16<rt> then recipStepHalf bld isSqrt a b
      else recipStep bld eSize isSqrt a b
    match dst with
    | OprSIMD(ScalarReg _) ->
      let _, s1, s2 = transThreeOprs ins bld
      dstAssignScalar ins bld dst (lane s1 s2) eSize
    | _ ->
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let s1 = transSIMDOprToExpr bld eSize dataSize elements src1
      let s2 = transSIMDOprToExpr bld eSize dataSize elements src2
      let result = Array.map2 lane s1 s2
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let frecps ins bld = recipStepOp ins bld false

let frsqrts ins bld = recipStepOp ins bld true

let fcvt (ins: Instruction) bld =
  lift bld ins {
    match ins.Operands with
    | TwoOperands(OprSIMD(ScalarReg _) as o1, o2) ->
      let struct (eSize, _, _) = getElemDataSzAndElems o1
      let struct (srcSize, _, _) = getElemDataSzAndElems o2
      let src = transOpr ins bld o2
      let result =
        if eSize = 16<rt> then fpConvertToHalf bld srcSize src
        elif eSize > srcSize then fpConvertWiden bld srcSize eSize src
        else fpConvertNarrow bld src
      dstAssignScalar ins bld o1 result eSize
    | _ ->
      let dst, src = transTwoOprs ins bld
      let oprSize = ins.OprSize
      sized oprSize dst := AST.cast CastKind.FloatCast oprSize src
  }

/// <summary>
/// FCVTL and FCVTL2: convert each element of a vector to the floating-point
/// format twice as wide, half to single or single to double.
///
/// The source arrangement says both widths -- the destination's elements are
/// twice the source's -- and the `2` form reads the upper half of the source
/// register rather than the lower one. Which half it reads is the only
/// difference between the two.
/// </summary>
let fcvtLong (ins: Instruction) bld isPart2 =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, _, _) = getElemDataSzAndElems src
    let wide = eSize * 2
    let elements = 64<rt> / eSize
    let struct (dstB, dstA) = transOpr128 ins bld dst
    let part = if isPart2 then 128<rt> else 64<rt>
    let widen e = fpConvertWiden bld eSize wide e
    let result = transSIMDOprVPart bld eSize part src |> Array.map widen
    dstAssignForSIMD dstA dstB result 128<rt> (elements / 2 * 2) bld
  }

/// <summary>
/// FCVTN and FCVTN2: convert each element of a vector to the floating-point
/// format half as wide.
///
/// Here the DESTINATION arrangement says both widths, because it is the
/// narrow side, and the `2` form writes the upper half of the destination
/// while leaving the lower one alone. The plain form clears the upper half,
/// which is what every write to a 64-bit arrangement does.
/// </summary>
let fcvtNarrow (ins: Instruction) bld isPart2 =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, _, _) = getElemDataSzAndElems dst
    let wide = eSize * 2
    let elements = 64<rt> / eSize
    let struct (dstB, dstA) = transOpr128 ins bld dst
    (* and narrowing to one is a rounding the IR has no cast for either *)
    let narrow e =
      if eSize = 16<rt> then fpConvertToHalf bld wide e
      else fpConvertNarrow bld e
    let result =
      transSIMDOprToExpr bld wide 128<rt> elements src |> Array.map narrow
    if isPart2 then
      direct dstB := AST.revConcat result
    else
      direct dstA := AST.revConcat result
      direct dstB := AST.num0 64<rt>
  }

/// Converts every lane of a vector operand to a fixed-point value, leaving
/// zero where an unsigned destination would take a negative one.
let private fpConvertVec ins bld o1 o2 fbits isUnsigned round =
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
  let struct (dstB, dstA) = transOpr128 ins bld o1
  let src = transSIMDOprToExpr bld eSize dataSize elements o2
  let n0 = AST.num0 eSize
  let isNeg e = AST.xthi 1<rt> e == AST.b1
  let fcvt e = fpToFixed eSize e (fbits eSize) isUnsigned round bld
  let result = Array.init elements (fun _ -> tmpVar bld eSize)
  Array.iter2 (fun res e ->
    if isUnsigned then
      append bld { direct res := AST.ite (isNeg e) n0 (fcvt e) }
    else
      append bld { direct res := fcvt e }) result src
  dstAssignForSIMD dstA dstB result dataSize elements bld

let private fpConvert (ins: Instruction) bld isUnsigned round =
  lift bld ins {
    let isNeg e = AST.xthi 1<rt> e == AST.b1
    match ins.Operands with
    (* vector *)
    | TwoOperands(OprSIMD(VecReg _) as o1, o2) ->
      fpConvertVec ins bld o1 o2 AST.num0 isUnsigned round
    (* vector #<fbits> *)
    | ThreeOperands(OprSIMD(VecReg _) as o1, o2, OprFbits fbits) ->
      let toFbits eSize = numI32 (int fbits) eSize
      fpConvertVec ins bld o1 o2 toFbits isUnsigned round
    (* scalar *)
    | TwoOperands(OprSIMD(ScalarReg _) as o1, o2) ->
      let src = transOpr ins bld o2
      let n0 = AST.num0 ins.OprSize
      let fcvt = fpToFixed ins.OprSize src n0 isUnsigned round bld
      let result = if isUnsigned then AST.ite (isNeg src) n0 fcvt else fcvt
      dstAssignScalar ins bld o1 result ins.OprSize
    (* scalar #<fbits> *)
    | ThreeOperands(OprSIMD(ScalarReg _) as o1, _, OprFbits _) ->
      let _, src, fbits = transThreeOprs ins bld
      let n0 = AST.num0 ins.OprSize
      let fcvt = fpToFixed ins.OprSize src fbits isUnsigned round bld
      let result = if isUnsigned then AST.ite (isNeg src) n0 fcvt else fcvt
      dstAssignScalar ins bld o1 result ins.OprSize
    (* float *)
    | TwoOperands(OprRegister _, _) ->
      let dst, src = transTwoOprs ins bld
      let n0 = AST.num0 ins.OprSize
      let fcvt = fpToFixed ins.OprSize src n0 isUnsigned round bld
      let result = if isUnsigned then AST.ite (isNeg src) n0 fcvt else fcvt
      sized ins.OprSize dst := result
    (* float #<fbits> *)
    | ThreeOperands(OprRegister _, _, OprFbits _) ->
      let dst, src, fbits = transThreeOprs ins bld
      let n0 = AST.num0 ins.OprSize
      let fcvt = fpToFixed ins.OprSize src fbits isUnsigned round bld
      let result = if isUnsigned then AST.ite (isNeg src) n0 fcvt else fcvt
      sized ins.OprSize dst := result
    | _ ->
      raise InvalidOperandException
  }

let fcvtas ins bld =
  fpConvert ins bld false FPRounding_TIEAWAY

let fcvtau ins bld =
  fpConvert ins bld true FPRounding_TIEAWAY

/// FCVTNS and FCVTNU, which round to the nearest integer and break a tie by
/// taking the even one. They differ from the six beside them in nothing but
/// that direction.
let fcvtns ins bld =
  fpConvert ins bld false FPRounding_TIEEVEN

let fcvtnu ins bld =
  fpConvert ins bld true FPRounding_TIEEVEN

let fcvtms ins bld =
  fpConvert ins bld false FPRounding_NEGINF

let fcvtmu ins bld =
  fpConvert ins bld true FPRounding_NEGINF

let fcvtps ins bld =
  fpConvert ins bld false FPRounding_POSINF

let fcvtpu ins bld =
  fpConvert ins bld true FPRounding_POSINF

let fcvtzs ins bld =
  fpConvert ins bld false FPRounding_Zero

let fcvtzu ins bld =
  fpConvert ins bld true FPRounding_Zero

let fdiv (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    match dst with
    | OprSIMD(ScalarReg _) ->
      let _, src1, src2 = transThreeOprs ins bld
      let result = fpDiv bld dataSize src1 src2
      dstAssignScalar ins bld dst result eSize
    | OprSIMD(VecReg _) ->
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
      let src2 = transSIMDOprToExpr bld eSize dataSize elements src2
      let result = Array.map2 (fpDiv bld eSize) src1 src2
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      raise InvalidOperandException
  }

/// FMADD is Ra + Rn * Rm with one rounding, so the arithmetic is FPMulAdd and
/// not an FPMul handed to an FPAdd. Its three relatives differ from it only in
/// which operand arrives negated, which is how the pseudocode writes them too.
let fmadd (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, _, _, _) = getFourOprs ins
    let struct (eSize, _, _) = getElemDataSzAndElems dst
    let _, src1, src2, src3 = transFourOprs ins bld
    let result = fpMulAdd bld eSize src3 src1 src2
    dstAssignScalar ins bld dst result eSize
  }

/// FMAX, FMIN and the two numeric forms. All four agree on the shape of the
/// operands and differ only in which primitive each element goes through, so
/// that choice arrives as a function and the four opcodes are named below.
let private fmaxmin (ins: Instruction) bld fp =
  lift bld ins {
    match ins.Operands with
    | ThreeOperands(OprSIMD(ScalarReg _) as o1, o2, o3) ->
      let struct (eSize, _, _) = getElemDataSzAndElems o1
      let src1 = transOpr ins bld o2
      let src2 = transOpr ins bld o3
      let result = fp bld eSize src1 src2
      dstAssignScalar ins bld o1 result eSize
    | _ ->
      let struct (o1, o2, o3) = getThreeOprs ins
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
      let result = Array.map2 (fp bld eSize) src1 src2
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let fmax ins bld =
  fmaxmin ins bld (fun bld eSize -> fpMaxMin bld eSize true)

let fmaxnm ins bld =
  fmaxmin ins bld (fun bld eSize -> fpMaxMinNum bld eSize true)

let fmin ins bld =
  fmaxmin ins bld (fun bld eSize -> fpMaxMin bld eSize false)

let fminnm ins bld =
  fmaxmin ins bld (fun bld eSize -> fpMaxMinNum bld eSize false)

/// FMLA and FMLS accumulate a fused product into the destination, element by
/// element: Vd + Vn * Vm and Vd - Vn * Vm, each element rounded once rather
/// than twice. The subtraction is said the way the pseudocode says it, by
/// negating the first multiplicand, so that a NaN there comes back with its
/// sign flipped.
let private fmlaOrFmls (ins: Instruction) bld negate =
  let mul eSize e1 e2 = if negate then fpneg e1 eSize, e2 else e1, e2
  lift bld ins {
    match ins.Operands with
    | ThreeOperands(OprSIMD(ScalarReg _) as o1, o2, o3) ->
      let struct (eSize, _, _) = getElemDataSzAndElems o1
      let dst = transOpr ins bld o1
      let src1 = transOpr ins bld o2
      let src2 = transOpr ins bld o3
      let e1, e2 = mul eSize src1 src2
      let result = fpMulAdd bld eSize dst e1 e2
      dstAssignScalar ins bld o1 result eSize
    | ThreeOperands(o1, o2, (OprSIMD(VecRegWithIdx _) as o3)) ->
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let src2 = transOpr ins bld o3
      let src3 = transSIMDOprToExpr bld eSize dataSize elements o1
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      Array.iteri2 (fun i e1 e3 ->
        let e1, e2 = mul eSize e1 src2
        let res = fpMulAdd bld eSize e3 e1 e2
        append bld { direct (result[i]) := res }) src1 src3
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      let struct (o1, o2, o3) = getThreeOprs ins
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
      let src3 = transSIMDOprToExpr bld eSize dataSize elements o1
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      Array.map3 (fun e1 e2 e3 ->
        let e1, e2 = mul eSize e1 e2
        fpMulAdd bld eSize e3 e1 e2) src1 src2 src3
      |> Array.iter2 (fun r e -> append bld { direct r := e }) result
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let fmla ins bld = fmlaOrFmls ins bld false

let fmls ins bld = fmlaOrFmls ins bld true

let fmov (ins: Instruction) bld =
  lift bld ins {
    match ins.Operands with
    | TwoOperands(OprRegister _, OprSIMD(VecRegWithIdx _)) ->
      let struct (dst, src) = getTwoOprs ins
      let dst = transOpr ins bld dst
      let struct (srcB, _) = transOpr128 ins bld src
      sized ins.OprSize dst := srcB
    | TwoOperands(OprSIMD(VecRegWithIdx _), OprRegister _) ->
      let struct (dst, src) = getTwoOprs ins
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src = transOpr ins bld src
      direct dstA := dstA
      direct dstB := src
    | TwoOperands(OprSIMD(VecReg _), OprFPImm _) ->
      let struct (dst, src) = getTwoOprs ins
      let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
      let src =
        if eSize <> 64<rt> then
          transOprFPImm ins eSize src |> advSIMDExpandImm bld eSize
        else
          transOprFPImm ins eSize src |> AST.xtlo 64<rt>
      dstAssign128 ins bld dst src src dataSize
    | TwoOperands(OprSIMD(ScalarReg _), _) ->
      let struct (dst, src) = getTwoOprs ins
      let struct (_, dataSize, _) = getElemDataSzAndElems dst
      let src = transOpr ins bld src
      (* a half from a general register is its low sixteen bits *)
      let src =
        if Expr.typeOf src > dataSize then AST.xtlo dataSize src else src
      dstAssignScalar ins bld dst src dataSize
    | _ ->
      let dst, src = transTwoOprs ins bld
      (* and a half into one is zero-extended *)
      let src =
        if Expr.typeOf src < ins.OprSize then AST.zext ins.OprSize src
        else src
      sized ins.OprSize dst := src
  }

/// FMSUB is Ra - Rn * Rm: the multiplicand arrives negated.
let fmsub (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, _, _, _) = getFourOprs ins
    let struct (eSize, _, _) = getElemDataSzAndElems dst
    let _, src1, src2, src3 = transFourOprs ins bld
    let result = fpMulAdd bld eSize src3 (fpneg src1 eSize) src2
    dstAssignScalar ins bld dst result eSize
  }

/// FNMADD is -Ra - Rn * Rm: both the addend and a multiplicand negated.
let fnmadd (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, _, _, _) = getFourOprs ins
    let struct (eSize, _, _) = getElemDataSzAndElems dst
    let _, src1, src2, src3 = transFourOprs ins bld
    let addend = fpneg src3 eSize
    let result = fpMulAdd bld eSize addend (fpneg src1 eSize) src2
    dstAssignScalar ins bld dst result eSize
  }

let fmul ins bld =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    match ins.Operands with
    | ThreeOperands(OprSIMD(ScalarReg _) as o1, o2, o3) ->
      let struct (eSize, _, _) = getElemDataSzAndElems o2
      let src1 = transOpr ins bld o2
      let src2 = transOpr ins bld o3
      dstAssignScalar ins bld o1 (fpMul bld eSize src1 src2) eSize
    | ThreeOperands(OprSIMD(VecReg _), _, OprSIMD(VecReg _)) ->
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
      let src2 = transSIMDOprToExpr bld eSize dataSize elements src2
      let result = Array.map2 (fpMul bld eSize) src1 src2
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems src1
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
      let src2 = transOpr ins bld src2
      let result = Array.map (fun src -> fpMul bld eSize src src2) src1
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let fneg (ins: Instruction) bld =
  lift bld ins {
    match ins.Operands with
    | TwoOperands(OprSIMD(ScalarReg _) as dst, src) ->
      let struct (eSize, _, _) = getElemDataSzAndElems src
      let src = transOpr ins bld src
      let t = tmpVar bld eSize
      direct t := fpneg src eSize
      dstAssignScalar ins bld dst t ins.OprSize
    | TwoOperands(OprSIMD(VecReg _) as dst, src) ->
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src = transSIMDOprToExpr bld eSize dataSize elements src
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      Array.iter2 (fun dst src ->
        append bld { direct dst := fpneg src eSize }) result src
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      raise InvalidOperandException
  }

/// FNMSUB is -Ra + Rn * Rm: the addend negated and the product left alone.
let fnmsub (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, _, _, src) = getFourOprs ins
    let _, src1, src2, src3 = transFourOprs ins bld
    let struct (eSize, _, _) = getElemDataSzAndElems src
    let result = fpMulAdd bld eSize (fpneg src3 eSize) src1 src2
    dstAssignScalar ins bld dst result ins.OprSize
  }

let fnmul (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, _, src) = getThreeOprs ins
    let _, src1, src2 = transThreeOprs ins bld
    let struct (eSize, _, _) = getElemDataSzAndElems src
    let result = tmpVar bld eSize
    direct result := fpMul bld eSize src1 src2
    direct result := fpneg result eSize
    dstAssignScalar ins bld dst result ins.OprSize
  }

let private fpRoundToInt (ins: Instruction) bld mode =
  lift bld ins {
    match ins.Operands with
    | TwoOperands(OprSIMD(ScalarReg _) as dst, src) ->
      let struct (eSize, _, _) = getElemDataSzAndElems dst
      let src = transOpr ins bld src
      let result = roundLane bld eSize (fpType bld mode) src
      dstAssignScalar ins bld dst result eSize
    | TwoOperands(OprSIMD(VecReg _ ) as dst, src) ->
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src = transSIMDOprToExpr bld eSize dataSize elements src
      let result = Array.map (roundLane bld eSize (fpType bld mode)) src
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      raise InvalidOperandException
  }

/// <summary>
/// FRINTI's and FRINTX's rounding of one element, in the direction FPCR
/// names: a NaN processed, and what it raised recorded -- Invalid for a
/// signalling NaN, and for FRINTX alone Inexact where the rounding changed
/// the value.
/// </summary>
let private currentRound bld isExact eSize e =
  let struct (res, rounded) = tmpVars2 bld eSize
  let nan = fpProcessNan bld eSize e
  append bld {
    direct rounded := fpRoundingMode e eSize
    direct res := AST.ite (isNaN eSize e) nan rounded
  }
  let changed = AST.not (isNaN eSize e) .& (rounded != e)
  let inexact = if isExact then changed else AST.b0
  fpExceptionsRounded bld (isSNaN eSize e) inexact
  res

let private fpCurrentRoundToInt (ins: Instruction) bld isExact =
  lift bld ins {
    match ins.Operands with
    | TwoOperands(OprSIMD(ScalarReg _) as dst, src) ->
      let struct (eSize, _, _) = getElemDataSzAndElems dst
      let src = transOpr ins bld src
      let result = roundLane bld eSize (currentRound bld isExact) src
      dstAssignScalar ins bld dst result eSize
    | TwoOperands(OprSIMD(VecReg _ ) as dst, src) ->
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src = transSIMDOprToExpr bld eSize dataSize elements src
      let lane = roundLane bld eSize (currentRound bld isExact)
      let result = Array.map lane src
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      raise InvalidOperandException
  }

let private tieawayCast bld eSize src =
  let sign = AST.xthi 1<rt> src
  let trunc = AST.roundToIntegral RoundingMode.TowardZero eSize src
  let struct (t, res) = tmpVars2 bld eSize
  append bld {
    direct t := AST.fsub src trunc
  }
  let comp1 =
    match eSize with
    | 32<rt> -> numI32 0x3F000000 eSize (* 0.5 *)
    | 64<rt> -> numI64 0x3FE0000000000000L eSize (* 0.5 *)
    | _ -> raise InvalidOperandSizeException
  let comp2 =
    match eSize with
    | 32<rt> -> numI32 0xBF000000 eSize (* -0.5 *)
    | 64<rt> -> numI64 0xBFE0000000000000L eSize (* -0.5 *)
    | _ -> raise InvalidOperandSizeException
  let ceil = fpType bld RoundingMode.TowardPositive eSize src
  let floor = fpType bld RoundingMode.TowardNegative eSize src
  let pRes = AST.ite (AST.fge t comp1) ceil floor
  let nRes = AST.ite (AST.fle t comp2) floor ceil
  append bld {
    direct res := AST.ite sign nRes pRes
  }
  res

let frinta (ins: Instruction) bld =
  lift bld ins {
    match ins.Operands with
    | TwoOperands(OprSIMD(ScalarReg _) as dst, src) ->
      let struct (eSize, _, _) = getElemDataSzAndElems dst
      let src = transOpr ins bld src
      let result = roundLane bld eSize (tieawayCast bld) src
      dstAssignScalar ins bld dst result eSize
    | TwoOperands(OprSIMD(VecReg _ ) as dst, src) ->
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src = transSIMDOprToExpr bld eSize dataSize elements src
      let result = Array.map (roundLane bld eSize (tieawayCast bld)) src
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      raise InvalidOperandException
  }

let frinti ins bld = fpCurrentRoundToInt ins bld false

let frintm ins bld =
  fpRoundToInt ins bld RoundingMode.TowardNegative

let frintn ins bld =
  fpRoundToInt ins bld RoundingMode.ToNearestEven

let frintp ins bld =
  fpRoundToInt ins bld RoundingMode.TowardPositive

let frintx ins bld = fpCurrentRoundToInt ins bld true

let frintz ins bld =
  fpRoundToInt ins bld RoundingMode.TowardZero

let fsqrt ins bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    match ins.Operands with
    | TwoOperands(OprSIMD(ScalarReg _), _) ->
      let src = transOpr ins bld src |> fpSqrt bld eSize
      dstAssignScalar ins bld dst src eSize
    | _ ->
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src = transSIMDOprToExpr bld eSize dataSize elements src
                |> Array.map (fpSqrt bld eSize)
      dstAssignForSIMD dstA dstB src dataSize elements bld
  }

let fsub ins bld =
  lift bld ins {
    let struct (dst, o1, o2) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    match ins.Operands with
    | ThreeOperands(OprSIMD(ScalarReg _), _, _) ->
      let src1 = transOpr ins bld o1
      let src2 = transOpr ins bld o2
      let result = fpSub bld dataSize src1 src2
      dstAssignScalar ins bld dst result eSize
    | _ ->
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o1
      let src2 = transSIMDOprToExpr bld eSize dataSize elements o2
      let result = Array.map2 (fpSub bld eSize) src1 src2
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let insv (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (eSize, _, _) = getElemDataSzAndElems o1
    let dst = transOpr ins bld o1
    let src = transOpr ins bld o2
    direct dst := AST.xtlo eSize src
  }

let loadStoreList (ins: Instruction) bld isLoad =
  lift bld ins {
    let isWBack, _ = getIsWBackAndIsPostIndex ins.Operands
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, _, elements) = getElemDataSzAndElems dst
    let dstArr = transSIMDListToExpr bld dst
    let bReg, mOffs = transOpr ins bld src |> separateMemExpr
    let struct (address, offs) = tmpVars2 bld 64<rt>
    direct address := bReg
    direct offs := AST.num0 64<rt>
    let eByte = eSize / 8<rt>
    let regLen = Array.length dstArr * elements
    let srcArr =
      let mem idx = AST.loadLE eSize (address .+ (numI32 (eByte * idx) 64<rt>))
      Array.init regLen mem
    let dstArr =
      if isVecIdxOrLD1ST1 ins dst then dstArr else dstArr |> Array.transpose
      |> Array.concat
    Array.iter2 (fun dst src ->
      if isLoad then append bld { direct dst := src }
      else append bld { direct src := dst }) dstArr srcArr
    if isLoad then fillZeroHigh64 ins bld dst else ()
    if isWBack then
      direct offs := numI32 (regLen * eByte) 64<rt>
      if isRegOffset src then append bld { direct offs := mOffs } else ()
      direct bReg := address .+ offs
    else
      ()
  }

let loadRep (ins: Instruction) bld =
  lift bld ins {
    let isWBack, _ = getIsWBackAndIsPostIndex ins.Operands
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, _, elements) = getElemDataSzAndElems dst
    let dstArr = transSIMDListToExpr bld dst
    let bReg, mOffs = transOpr ins bld src |> separateMemExpr
    let struct (address, offs) = tmpVars2 bld 64<rt>
    direct address := bReg
    direct offs := AST.num0 64<rt>
    let eByte = eSize / 8<rt>
    let regLen = Array.length dstArr
    let srcArr =
      let mem idx =
        AST.loadLE eSize (address .+ (numI32 (eByte * (idx / elements)) 64<rt>))
      Array.init (regLen * elements) mem
    let dstArr = dstArr |> Array.concat
    Array.iter2 (fun dst src -> append bld { direct dst := src }) dstArr srcArr
    fillZeroHigh64 ins bld dst
    if isWBack then
      direct offs := numI32 (regLen * eByte) 64<rt>
      if isRegOffset src then append bld { direct offs := mOffs } else ()
      direct bReg := address .+ offs
    else
      ()
  }

let ldnp (ins: Instruction) bld =
  lift bld ins {
    let address = tmpVar bld 64<rt>
    let dByte = numI32 (RegType.toByteWidth ins.OprSize) 64<rt>
    match ins.Operands, ins.OprSize with
    | ThreeOperands(OprSIMD _ as src1, src2, src3), 128<rt> ->
      let struct (src1B, src1A) = transOpr128 ins bld src1
      let struct (src2B, src2A) = transOpr128 ins bld src2
      let bReg, offset = transOpr ins bld src3 |> separateMemExpr
      let n8 = numI32 8 64<rt>
      direct address := bReg
      direct address := address .+ offset
      direct src1A := AST.loadLE 64<rt> address
      direct src1B := AST.loadLE 64<rt> (address .+ n8)
      direct src2A := AST.loadLE 64<rt> (address .+ dByte)
      direct src2B := AST.loadLE 64<rt> (address .+ dByte .+ n8)
    | ThreeOperands(OprSIMD _ as src1, src2, src3), _ ->
      let bReg, offset = transOpr ins bld src3 |> separateMemExpr
      let struct (eSize, _, _) = getElemDataSzAndElems src1
      direct address := bReg
      direct address := address .+ offset
      let inline load addr = AST.loadLE ins.OprSize addr
      dstAssignScalar ins bld src1 (load address) eSize
      dstAssignScalar ins bld src2 (load (address .+ dByte)) eSize
    | _ ->
      let src1, src2, (bReg, offset) = transThreeOprsSepMem ins bld
      let oprSize = ins.OprSize
      direct address := bReg
      direct address := address .+ offset
      sized oprSize src1 := AST.loadLE oprSize address
      sized oprSize src2 := AST.loadLE oprSize (address .+ dByte)
  }

let ldp (ins: Instruction) bld =
  lift bld ins {
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    let address = tmpVar bld 64<rt>
    let dByte = numI32 (RegType.toByteWidth ins.OprSize) 64<rt>
    match ins.Operands, ins.OprSize with
    | ThreeOperands(OprSIMD _ as src1, src2, src3), 128<rt> ->
      let struct (src1B, src1A) = transOpr128 ins bld src1
      let struct (src2B, src2A) = transOpr128 ins bld src2
      let bReg, offset = transOpr ins bld src3 |> separateMemExpr
      let n8 = numI32 8 64<rt>
      direct address := bReg
      direct address := if isPostIndex then address else address .+ offset
      direct src1A := AST.loadLE 64<rt> address
      direct src1B := AST.loadLE 64<rt> (address .+ n8)
      direct src2A := AST.loadLE 64<rt> (address .+ dByte)
      direct src2B := AST.loadLE 64<rt> (address .+ dByte .+ n8)
      writeBack bld isWBack isPostIndex bReg address offset
    | ThreeOperands(OprSIMD _ as src1, src2, src3), _ ->
      let bReg, offset = transOpr ins bld src3 |> separateMemExpr
      let struct (eSize, _, _) = getElemDataSzAndElems src1
      direct address := bReg
      direct address := if isPostIndex then address else address .+ offset
      let inline load addr = AST.loadLE ins.OprSize addr
      dstAssignScalar ins bld src1 (load address) eSize
      dstAssignScalar ins bld src2 (load (address .+ dByte)) eSize
      writeBack bld isWBack isPostIndex bReg address offset
    | _ ->
      let src1, src2, (bReg, offset) = transThreeOprsSepMem ins bld
      let oprSize = ins.OprSize
      direct address := bReg
      direct address := if isPostIndex then address else address .+ offset
      sized oprSize src1 := AST.loadLE oprSize address
      sized oprSize src2 := AST.loadLE oprSize (address .+ dByte)
      writeBack bld isWBack isPostIndex bReg address offset
  }

/// Loads from an address the program counter and a literal offset name, which
/// is what the literal form of LDR does.
let private ldrLiteral (ins: Instruction) bld o1 o2 =
  append bld {
    let offset = transOpr ins bld (OprMemory(LiteralMode o2))
    let address = tmpVar bld 64<rt>
    match ins.OprSize with
    | 128<rt> ->
      let struct (dstB, dstA) = transOpr128 ins bld o1
      direct address := getPC bld .+ offset
      direct dstA := AST.loadLE 64<rt> address
      direct dstB := AST.loadLE 64<rt> (address .+ (numI32 8 64<rt>))
    | _ ->
      let dst = transOpr ins bld o1
      let data = tmpVar bld ins.OprSize
      direct address := getPC bld .+ offset
      direct data := AST.loadLE ins.OprSize address
      match o1 with
      | OprSIMD(ScalarReg _) ->
        dstAssignScalar ins bld o1 data ins.OprSize
      | _ ->
        sized ins.OprSize dst := data
  }

let ldr (ins: Instruction) bld =
  lift bld ins {
    match ins.Operands with
    | TwoOperands(o1, OprMemory(LiteralMode o2)) -> (* LDR (literal) *)
      ldrLiteral ins bld o1 o2
    | TwoOperands(o1, o2) ->
      let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
      let address = tmpVar bld 64<rt>
      match ins.OprSize with
      | 128<rt> ->
        let struct (dstB, dstA) = transOpr128 ins bld o1
        let bReg, offset = transOpr ins bld o2 |> separateMemExpr
        direct address := bReg
        direct address := if isPostIndex then address else address .+ offset
        direct dstA := AST.loadLE 64<rt> address
        direct dstB := AST.loadLE 64<rt> (address .+ (numI32 8 64<rt>))
        writeBack bld isWBack isPostIndex bReg address offset
      | _ ->
        let dst = transOpr ins bld o1
        let bReg, offset = transOpr ins bld o2 |> separateMemExpr
        let data = tmpVar bld ins.OprSize
        direct address := bReg
        direct address := if isPostIndex then address else address .+ offset
        direct data := AST.loadLE ins.OprSize address
        match o1 with
        | OprSIMD(ScalarReg _) ->
          dstAssignScalar ins bld o1 data ins.OprSize
        | _ ->
          sized ins.OprSize dst := data
        writeBack bld isWBack isPostIndex bReg address offset
    | _ ->
      raise InvalidOperandException
  }

let ldur (ins: Instruction) bld =
  lift bld ins {
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld ins.OprSize
    let struct (o1, o2) = getTwoOprs ins
    match ins.OprSize with
    | 128<rt> ->
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let bReg, offset = transOpr ins bld o2 |> separateMemExpr
      direct address := bReg
      direct address := if isPostIndex then address else address .+ offset
      direct dstA := AST.loadLE 64<rt> address
      direct dstB := AST.loadLE 64<rt> (address .+ (numI32 8 64<rt>))
      writeBack bld isWBack isPostIndex bReg address offset
    | _ ->
      let dst = transOpr ins bld o1
      let bReg, offset = transOpr ins bld o2 |> separateMemExpr
      direct address := bReg
      direct address := if isPostIndex then address else address .+ offset
      direct data := AST.loadLE ins.OprSize address
      match o1 with
      | OprSIMD(ScalarReg _) -> dstAssignScalar ins bld o1 data ins.OprSize
      | _ -> sized ins.OprSize dst := data
      writeBack bld isWBack isPostIndex bReg address offset
  }

let logShift ins bld shift =
  lift bld ins {
    let dst, src, amt = transThreeOprs ins bld
    sized ins.OprSize dst := shift src amt
  }

let maxMin ins bld opFn =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let struct (dstB, dstA) = transOpr128 ins bld o1
    let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
    let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
    let result = Array.map2 (fun s1 s2 -> AST.ite (opFn s1 s2) s1 s2) src1 src2
    dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let maxMinv ins bld opFn =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o2
    let src = transSIMDOprToExpr bld eSize dataSize elements o2
    let minMax = tmpVar bld eSize
    direct minMax := src[0]
    Array.sub src 1 (elements - 1)
    |> Array.iter (fun e ->
      append bld { direct minMax := AST.ite (opFn minMax e) minMax e })
    dstAssignScalar ins bld o1 minMax eSize
  }

let maxMinp ins bld opFn =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (dstB, dstA) = transOpr128 ins bld dst
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
    let src2 = transSIMDOprToExpr bld eSize dataSize elements src2
    let cal src = Array.chunkBySize 2 src
                  |> Array.map (fun e -> AST.ite (opFn e.[0] e.[1]) e.[0] e.[1])
    let concat = Array.append (cal src1) (cal src2)
    Array.iter2 (fun res s -> append bld { direct res := s }) result concat
    dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let madd (ins: Instruction) bld =
  lift bld ins {
    match ins.Operands with
    | ThreeOperands(_, _, OprSIMD(VecReg _)) ->
      let struct (o1, o2, o3) = getThreeOprs ins
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
      let result = Array.map2 (.*) src1 src2
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | ThreeOperands(OprSIMD _ as o1, o2, o3) ->
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let src2 = transOpr ins bld o3
      let result = Array.map (fun s1 -> s1 .* src2) src1
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      let dst, src1, src2, src3 = transOprOfMADD ins bld
      sized ins.OprSize dst := src3 .+ (src1 .* src2)
  }

let mladdsub (ins: Instruction) bld opFn =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld o1
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o2
    let dst = transSIMDOprToExpr bld eSize dataSize elements o1
    let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
    match ins.Operands with
    | ThreeOperands(_, _, OprSIMD(VecReg _)) ->
      let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
      let prod = Array.map2 (.*) src1 src2
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      let cal = Array.map2 (opFn) dst prod
      Array.iter2 (fun res s -> append bld { direct res := s }) result cal
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      let src2 = transOpr ins bld o3
      let prod = Array.map (fun s1 -> s1 .* src2) src1
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      let cal = Array.map2 (opFn) dst prod
      Array.iter2 (fun res s -> append bld { direct res := s }) result cal
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let mov (ins: Instruction) bld =
  lift bld ins {
    match ins.Operands with
    | TwoOperands(OprSIMD(VecReg _) as o1, o2) ->
      let struct (_, dataSize, _) = getElemDataSzAndElems o1
      let struct (srcB, srcA) = transOpr128 ins bld o2
      dstAssign128 ins bld o1 srcA srcB dataSize
    | TwoOperands(OprSIMD(ScalarReg _), OprSIMD(VecRegWithIdx _)) ->
      let struct (dst, src) = getTwoOprs ins
      let struct (_, dataSize, _) = getElemDataSzAndElems dst
      let src = transOpr ins bld src
      dstAssignScalar ins bld dst src dataSize
    | _ ->
      let dst, src = transTwoOprs ins bld
      sized ins.OprSize dst := src
  }

let movi (ins: Instruction) bld =
  lift bld ins {
    match ins.Operands with
    | TwoOperands(OprSIMD(ScalarReg _), OprImm _) ->
      let dst, src = transTwoOprs ins bld
      sized ins.OprSize dst := src
    | TwoOperands(OprSIMD(VecReg _), OprImm _) ->
      let struct (dst, src) = getTwoOprs ins
      let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
      let imm = if not (dataSize = 128<rt> && eSize = 64<rt>) then
                  transOpr ins bld src
                  |> advSIMDExpandImm bld eSize
                else
                  transOpr ins bld src |> AST.xtlo 64<rt>
      dstAssign128 ins bld dst imm imm dataSize
    | ThreeOperands(OprSIMD(VecReg _), OprImm _, OprShift _) ->
      let struct (dst, src, amount) = getThreeOprs ins
      let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
      let imm = transBarrelShiftToExpr ins.OprSize bld src amount
                |> advSIMDExpandImm bld eSize
      dstAssign128 ins bld dst imm imm dataSize
    | _ ->
      raise InvalidOperandException
  }

let private getWordMask (ins: Instruction) shift =
  match shift with
  | OprShift(LSL, Imm amt) -> numI64 (~~~(0xFFFFL <<< (int amt))) ins.OprSize
  | _ -> raise InvalidOperandException

let movk (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, imm, shf) = getThreeOprs ins
    let dst = transOpr ins bld dst
    let src = transBarrelShiftToExpr ins.OprSize bld imm shf
    let mask = getWordMask ins shf
    sized ins.OprSize dst := (dst .& mask) .| src
  }

let mrs (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    match dst, src with
    | OprRegister rt, OprRegister R.CNTVCT_EL0 ->
      (* CNTVCT_EL0 has no stored value to read; leave the 64-bit virtual count
         to the emulator through a ClockCounterRead side effect naming rt. *)
      AST.sideEffect
        (ClockCounterRead(Some(Register.toRegID rt, false)))
    | _ ->
      let dst = transOpr ins bld dst
      let src =
        match src with
        | OprRegister R.NZCV ->
          let n = (regVar bld R.N |> AST.zext 64<rt>) << numI32 31 64<rt>
          let z = (regVar bld R.Z |> AST.zext 64<rt>) << numI32 30 64<rt>
          let c = (regVar bld R.C |> AST.zext 64<rt>) << numI32 29 64<rt>
          let v = (regVar bld R.V |> AST.zext 64<rt>) << numI32 28 64<rt>
          n .| z .| c .| v
        | _ ->
          transOpr ins bld src
      direct dst := src
  }

let mvni (ins: Instruction) bld =
  lift bld ins {
    match ins.Operands with
    | TwoOperands _ ->
      let struct (dst, src) = getTwoOprs ins
      let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
      let imm = transOpr ins bld src
                |> advSIMDExpandImm bld eSize
                |> AST.not
      dstAssign128 ins bld dst imm imm dataSize
    | _ ->
      let struct (dst, src, shf) = getThreeOprs ins
      let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
      let src = transBarrelShiftToExpr 64<rt> bld src shf
                |> advSIMDExpandImm bld eSize
                |> AST.not
      dstAssign128 ins bld dst src src dataSize
  }

let orn (ins: Instruction) bld =
  lift bld ins {
    match ins.Operands with
    | TwoOperands _ ->
      let struct (dst, src) = getTwoOprs ins
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src = transSIMDOprToExpr bld eSize dataSize elements src
      let result = Array.map AST.not src
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | ThreeOperands(OprSIMD(VecReg _) as o1, o2, o3) ->
      let struct (_, dataSize, _) = getElemDataSzAndElems o1
      let struct (src1B, src1A) = transOpr128 ins bld o2
      let struct (src2B, src2A) = transOpr128 ins bld o3
      let resultB = src1B .| (AST.not src2B)
      let resultA = src1A .| (AST.not src2A)
      dstAssign128 ins bld o1 resultA resultB dataSize
    | _ ->
      let dst, src1, src2 = transOprOfORN ins bld
      sized ins.OprSize dst := src1 .| AST.not src2
  }

let orr (ins: Instruction) bld =
  lift bld ins {
    match ins.Operands with
    | TwoOperands(OprSIMD _, OprImm _) ->
      let struct (dst, imm) = getTwoOprs ins
      let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src = transOpr ins bld imm |> advSIMDExpandImm bld eSize
      dstAssign128 ins bld dst (dstA .| src) (dstB .| src) dataSize
    | ThreeOperands(OprSIMD _, OprImm _, _) ->
      let struct (dst, imm, shf) = getThreeOprs ins
      let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src = transBarrelShiftToExpr ins.OprSize bld imm shf
                |> advSIMDExpandImm bld eSize
      dstAssign128 ins bld dst (dstA .| src) (dstB .| src) dataSize
    | ThreeOperands(OprSIMD(VecReg(_, v)) as o1, o2, o3) ->
      let struct (_, dataSize, _) = getElemDataSzAndElems o1
      let struct (src1B, src1A) = transOpr128 ins bld o2
      let struct (src2B, src2A) = transOpr128 ins bld o3
      let resultB = src1B .| src2B
      let resultA = src1A .| src2A
      dstAssign128 ins bld o1 resultA resultB dataSize
    | _ ->
      let dst, src1, src2 = transOprOfORR ins bld
      sized ins.OprSize dst := src1 .| src2
  }

/// Writes the bit reversal of src into dst, one bit at a time from the top
/// down. The loop stays out of the lift block, where it would allocate an
/// enumerator per lifted instruction.
let private reverseInto bld width dst src =
  for i in 0 .. width - 1 do
    append bld {
      direct (AST.extract dst 1<rt> (width - 1 - i)) := AST.extract src 1<rt> i
    }

let rbit (ins: Instruction) bld =
  lift bld ins {
    match ins.Operands with
    | TwoOperands(OprRegister _, OprRegister _) ->
      let dst, src = transTwoOprs ins bld
      let datasize = if ins.OprSize = 64<rt> then 64 else 32
      let tmp = tmpVar bld ins.OprSize
      direct tmp := numI32 0 ins.OprSize
      reverseInto bld datasize tmp src
      sized ins.OprSize dst := tmp
    | _ ->
      let struct (dst, src) = getTwoOprs ins
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src = transSIMDOprToExpr bld eSize dataSize elements src
      let rev = tmpVar bld eSize
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      direct rev := numI32 0 eSize
      let reverse i e =
        reverseInto bld (int eSize) rev e
        append bld { direct (result[i]) := rev }
      Array.iteri reverse src
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let rev (ins: Instruction) bld =
  lift bld ins {
    let e = if ins.OprSize = 64<rt> then 7 else 3
    let t = tmpVar bld ins.OprSize
    match ins.Operands with
    | TwoOperands(OprSIMD(VecReg _ ) as dst, src) ->
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src = transSIMDOprToExpr bld eSize dataSize elements src
      let revSize = 64 / int eSize
      let result = Array.chunkBySize revSize src |> Array.collect (Array.rev)
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      let dst, src = transTwoOprs ins bld
      direct t := numI32 0 ins.OprSize
      for i in 0 .. e do
        direct (AST.extract t 8<rt> ((e - i) * 8)) :=
          AST.extract src 8<rt> (i * 8)
      sized ins.OprSize dst := t
  }

let rev16 (ins: Instruction) bld =
  lift bld ins {
    let tmp = tmpVar bld ins.OprSize
    match ins.Operands with
    | TwoOperands(OprSIMD(VecReg _ ) as dst, src) ->
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src = transSIMDOprToExpr bld eSize dataSize elements src
      let revSize = 16 / int eSize
      let result = Array.chunkBySize revSize src |> Array.collect (Array.rev)
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      let dst, src = transTwoOprs ins bld
      direct tmp := numI32 0 ins.OprSize
      for i in 0 .. ((int ins.OprSize / 8) - 1) do
        let idx = i * 8
        let revIdx = if i % 2 = 0 then idx + 8 else idx - 8
        direct (AST.extract tmp 8<rt> revIdx) := AST.extract src 8<rt> idx
      done
      sized ins.OprSize dst := tmp
  }

/// <summary>
/// The manual's RecipEstimate: the reciprocal of a nine-bit fixed-point
/// number in [0.5, 1), to nine bits. It is stated as a division and needs no
/// table -- the input is rounded to the middle of its interval by doubling
/// and adding one, the reciprocal taken at nineteen bits, and the answer
/// rounded back to nine.
/// </summary>
let private recipEstimate9 a =
  let rounded = (a .* numI32 2 64<rt>) .+ AST.num1 64<rt>
  let b = numI32 0x80000 64<rt> ./ rounded
  (b .+ AST.num1 64<rt>) ./ numI32 2 64<rt>

/// <summary>
/// The manual's RecipSqrtEstimate, which it states as a SEARCH: the largest
/// b whose square, times the input, stays under two to the twenty-eighth.
///
/// A loop counting b up from 512 is not something the IR can say, but the
/// condition is monotone in b, so the same answer comes out of building b
/// one bit at a time from the top -- nine steps rather than up to five
/// hundred. One temporary per step, because each step names the running
/// value twice and an expression that does that nine times over is five
/// hundred times the size.
/// </summary>
let private recipSqrtEstimate9 bld a =
  let limit = numI32 0x10000000 64<rt>
  let struct (rounded, b) = tmpVars2 bld 64<rt>
  let low = (a .* numI32 2 64<rt>) .+ AST.num1 64<rt>
  let high = ((a >> AST.num1 64<rt>) << AST.num1 64<rt>) .+ AST.num1 64<rt>
  append bld {
    direct rounded :=
      AST.ite (a .< numI32 256 64<rt>) low (high .* numI32 2 64<rt>)
    direct b := numI32 512 64<rt>
  }
  for bit in [ 256; 128; 64; 32; 16; 8; 4; 2; 1 ] do
    let cand = b .+ numI32 bit 64<rt>
    append bld {
      direct b := AST.ite ((rounded .* cand .* cand) .< limit) cand b
    }
  (b .+ AST.num1 64<rt>) ./ numI32 2 64<rt>

/// <summary>
/// URECPE and URSQRTE: a nine-bit estimate of the reciprocal, or of the
/// reciprocal square root, of the top of each element.
///
/// An element too small to estimate answers all ones, which is the largest
/// the format holds: below a half for the reciprocal and below a quarter for
/// the reciprocal square root. Everything else is read as a fixed-point
/// number from its top nine bits and the estimate written back to the same
/// place.
/// </summary>
let uestimate (ins: Instruction) bld isSqrt =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (dstB, dstA) = transOpr128 ins bld dst
    let ones32 = numU32 0xffffffffu 32<rt>
    let tooSmall e =
      if isSqrt then e .< numU32 0x40000000u 32<rt>
      else e .< numU32 0x80000000u 32<rt>
    let lane e =
      let top = AST.zext 64<rt> (e >> numI32 23 32<rt>)
      let est =
        if isSqrt then recipSqrtEstimate9 bld top else recipEstimate9 top
      let scaled = AST.xtlo 32<rt> est << numI32 23 32<rt>
      AST.ite (tooSmall e) ones32 scaled
    let src = transSIMDOprToExpr bld eSize dataSize elements src
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    Array.map lane src
    |> Array.iter2 (fun r e -> append bld { direct r := e }) result
    dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let urecpe ins bld = uestimate ins bld false

let ursqrte ins bld = uestimate ins bld true

/// <summary>
/// The layout of a float as the estimates read it: the width of its fraction
/// and of its exponent, and the constants FPRecipEstimate and FPRSqrtEstimate
/// take the result's exponent from -- which differ between the widths only
/// because the biases do.
/// </summary>
let private estimateLayout eSize =
  match eSize with
  | 16<rt> -> struct (10, 5, 29, 44)
  | 32<rt> -> struct (23, 8, 253, 380)
  | _ -> struct (52, 11, 2045, 3068)

/// <summary>
/// The pieces of an operand the estimates start from, in a double's layout
/// whatever its width, as the manual has them: the sign bit where the width
/// has it, the fraction, the biased exponent, and the fraction moved up to
/// fill fifty-two bits.
/// </summary>
let private estimateParts eSize e =
  let struct (mBits, eBits, _, _) = estimateLayout eSize
  let rt = 64<rt>
  let x = if eSize = rt then e else AST.zext rt e
  let mant = x .& ((AST.num1 rt << numI32 mBits rt) .- AST.num1 rt)
  let rawExp = (x >> numI32 mBits rt) .& numI32 ((1 <<< eBits) - 1) rt
  let sign = x .& (AST.num1 rt << numI32 (int eSize - 1) rt)
  let started = mant << numI32 (52 - mBits) rt
  struct (sign, mant, rawExp, started)

/// The low eSize bits of a value built at sixty-four.
let private toWidth eSize x = if eSize = 64<rt> then x else AST.xtlo eSize x

/// <summary>
/// FRECPX: the exponent replaced by its own complement, which is the
/// reciprocal's exponent, and the significand thrown away.
///
/// A zero or a denormal has no exponent to complement, so both answer with
/// the largest finite one. A NaN is processed -- made quiet, or the default
/// one under DN -- and a signalling one raises Invalid, the only exception
/// this can raise. Nothing else about the value survives -- that is the point
/// of the instruction: it is the part of a reciprocal that cannot overflow.
/// </summary>
let frecpx (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, _, _) = getElemDataSzAndElems dst
    let struct (mantBits, expBits, _, _) = estimateLayout eSize
    let e = tmpVar bld eSize
    let src = transOpr ins bld src
    let expMask = ((AST.num1 eSize << numI32 expBits eSize) .- AST.num1 eSize)
    direct e := (src >> numI32 mantBits eSize) .& expMask
    let sign = src .& (AST.num1 eSize << numI32 (int eSize - 1) eSize)
    let maxExp = expMask .- AST.num1 eSize
    let flipped = AST.ite (e == AST.num0 eSize) maxExp (AST.not e .& expMask)
    let ordinary = sign .| (flipped << numI32 mantBits eSize)
    let nan = fpProcessNan bld eSize src
    fpExceptionsInvalidOnly bld (isSNaN eSize src)
    dstAssignScalar ins bld dst (AST.ite (isNaN eSize src) nan ordinary) eSize
  }

/// <summary>
/// FRECPE for one lane: the manual's FPRecipEstimate, at any of the three
/// widths.
///
/// The shape of it is that the reciprocal's exponent is the negation of the
/// operand's -- a constant less it, once both are biased -- and its
/// significand is a nine-bit table lookup, which RecipEstimate states as a
/// division. A denormal has to be normalised first, by one shift or two
/// depending on where its leading one is, and the exponent adjusted to match.
///
/// Two of the exponent's values fall off the bottom of what the width can
/// hold as a normal, and the manual puts the implicit one back by hand for
/// them, shifting the significand down to make room. Those are the two
/// `result_exp` tests below and they are the only place the sequence is not
/// straight-line arithmetic.
///
/// The special cases are the usual ones with one addition: an operand too
/// small for its reciprocal to be written -- under two to the minus sixteen,
/// the minus hundred and twenty-eight or the minus thousand and twenty-four --
/// OVERFLOWS, to an infinity or to the largest finite number as the rounding
/// direction says.
/// </summary>
let private recipNormalise bld isDen started =
  let struct (frac, exp) = tmpVars2 bld 64<rt>
  let top = (started >> numI32 51 64<rt>) .& AST.num1 64<rt>
  let topSet = top == AST.num1 64<rt>
  let once = started << AST.num1 64<rt>
  let twice = started << numI32 2 64<rt>
  let shifted = AST.ite topSet once twice
  let lowered = AST.ite topSet (AST.num0 64<rt>) (numI32 -1 64<rt>)
  append bld {
    direct frac := AST.ite isDen shifted started
  }
  struct (frac, exp, lowered)

let private recipBody eSize frac exp =
  let struct (mBits, eBits, recipBase, _) = estimateLayout eSize
  let scaled =
    numI32 0x100 64<rt> .| ((frac >> numI32 44 64<rt>) .& numI32 0xff 64<rt>)
  let resExp = numI32 recipBase 64<rt> .- exp
  let est = recipEstimate9 scaled
  let fracE = (est .& numI32 0xff 64<rt>) << numI32 44 64<rt>
  let atZero =
    (AST.num1 64<rt> << numI32 51 64<rt>) .| (fracE >> AST.num1 64<rt>)
  let atMinusOne =
    (AST.num1 64<rt> << numI32 50 64<rt>) .| (fracE >> numI32 2 64<rt>)
  let minusOne = resExp == numI32 -1 64<rt>
  let deep = AST.ite minusOne atMinusOne fracE
  let fracF = AST.ite (resExp == AST.num0 64<rt>) atZero deep
  let outExp = AST.ite minusOne (AST.num0 64<rt>) resExp
  let eMask = numI32 ((1 <<< eBits) - 1) 64<rt>
  let mMask = (AST.num1 64<rt> << numI32 mBits 64<rt>) .- AST.num1 64<rt>
  ((outExp .& eMask) << numI32 mBits 64<rt>)
  .| ((fracF >> numI32 (52 - mBits) 64<rt>) .& mMask)

let private recipEstimate bld eSize e =
  let struct (mBits, eBits, _, _) = estimateLayout eSize
  let struct (sign, mant, rawExp, started) = estimateParts eSize e
  let isDen = rawExp == AST.num0 64<rt>
  let struct (frac, exp, lowered) = recipNormalise bld isDen started
  append bld {
    direct exp := AST.ite isDen lowered rawExp
  }
  let body = sign .| recipBody eSize frac exp
  let eMax = numI32 ((1 <<< eBits) - 1) 64<rt>
  let infinity = sign .| (eMax << numI32 mBits 64<rt>)
  let largest = sign .| ((eMax << numI32 mBits 64<rt>) .- AST.num1 64<rt>)
  let isTop = rawExp == eMax
  let isNaN = isTop .& (mant != AST.num0 64<rt>)
  let isInf = isTop .& (mant == AST.num0 64<rt>)
  let isZero = isDen .& (mant == AST.num0 64<rt>)
  (* under the smallest value whose reciprocal can be written, which is a
     denormal whose fraction does not reach its top two bits *)
  let tiny =
    isDen .& ((started >> numI32 50 64<rt>) == AST.num0 64<rt>)
    .& AST.not isZero
  let toInf = fpOverflowsToInfinity bld (sign != AST.num0 64<rt>)
  let overflow = AST.ite toInf infinity largest
  let small = AST.ite isZero infinity (AST.ite tiny overflow body)
  let nan = fpProcessNan bld eSize e
  fpExceptionsEstimate bld (isSNaN eSize e) isZero tiny
  AST.ite isNaN nan (toWidth eSize (AST.ite isInf sign small))

let frecpe (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    match ins.Operands with
    | TwoOperands(OprSIMD(ScalarReg _), _) ->
      let e = transOpr ins bld src
      dstAssignScalar ins bld dst (recipEstimate bld eSize e) eSize
    | _ ->
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src = transSIMDOprToExpr bld eSize dataSize elements src
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      Array.map (recipEstimate bld eSize) src
      |> Array.iter2 (fun r e -> append bld { direct r := e }) result
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

/// <summary>
/// FRSQRTE for one lane: the manual's FPRSqrtEstimate, at any of the three
/// widths.
///
/// A square root halves the exponent, so the estimate has to know whether
/// the exponent is EVEN or ODD -- the significand is read as nine bits from
/// a different place in each case, and that is the only thing that makes
/// this different in shape from the reciprocal beside it.
///
/// The manual normalises a denormal with a loop that shifts until the top
/// bit is set. The number of shifts is where the leading one already is, so
/// it is found once and used as a shift amount rather than counted out.
///
/// A negative operand has no real square root: it answers the DEFAULT NaN
/// and raises Invalid, which is the one place in these two estimates that a
/// payload is thrown away rather than carried.
/// </summary>
let private rsqrtEstimate bld eSize e =
  let struct (mBits, eBits, _, rsqrtBase) = estimateLayout eSize
  let struct (sign, mant, rawExp, started) = estimateParts eSize e
  let isDen = rawExp == AST.num0 64<rt>
  let top = highestSetBitForIR mant mBits 64<rt> bld
  let shifts = numI32 (mBits - 1) 64<rt> .- top
  let struct (frac, exp) = tmpVars2 bld 64<rt>
  append bld {
    let opened = started << (shifts .+ AST.num1 64<rt>)
    direct frac := AST.ite isDen opened started
    direct exp := AST.ite isDen (AST.neg shifts) rawExp
  }
  let even = (exp .& AST.num1 64<rt>) == AST.num0 64<rt>
  let atEven =
    numI32 0x100 64<rt> .| ((frac >> numI32 44 64<rt>) .& numI32 0xff 64<rt>)
  let atOdd =
    numI32 0x80 64<rt> .| ((frac >> numI32 45 64<rt>) .& numI32 0x7f 64<rt>)
  let scaled = AST.ite even atEven atOdd
  let resExp = (numI32 rsqrtBase 64<rt> .- exp) ?/ numI32 2 64<rt>
  let est = recipSqrtEstimate9 bld scaled
  let eMask = numI32 ((1 <<< eBits) - 1) 64<rt>
  let body =
    ((resExp .& eMask) << numI32 mBits 64<rt>)
    .| ((est .& numI32 0xff 64<rt>) << numI32 (mBits - 8) 64<rt>)
  let isTop = rawExp == eMask
  let isNaN = isTop .& (mant != AST.num0 64<rt>)
  let isZero = isDen .& (mant == AST.num0 64<rt>)
  let infinity = sign .| (eMask << numI32 mBits 64<rt>)
  let negative = sign != AST.num0 64<rt>
  let positive = AST.ite isTop (AST.num0 64<rt>) body
  let noRoot =
    if eSize = 64<rt> then fpDefaultNan eSize
    else AST.zext 64<rt> (fpDefaultNan eSize)
  let signed = AST.ite negative noRoot positive
  let nan = fpProcessNan bld eSize e
  let invalid = isSNaN eSize e .| (negative .& AST.not isNaN .& AST.not isZero)
  fpExceptionsEstimate bld invalid isZero AST.b0
  AST.ite isNaN nan (toWidth eSize (AST.ite isZero infinity signed))

let frsqrte (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    match ins.Operands with
    | TwoOperands(OprSIMD(ScalarReg _), _) ->
      let e = transOpr ins bld src
      dstAssignScalar ins bld dst (rsqrtEstimate bld eSize e) eSize
    | _ ->
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src = transSIMDOprToExpr bld eSize dataSize elements src
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      Array.map (rsqrtEstimate bld eSize) src
      |> Array.iter2 (fun r e -> append bld { direct r := e }) result
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

/// The polynomial product of two elements over GF(2): the same shift and add
/// an ordinary product is, with the addition replaced by exclusive or -- which
let rev32 (ins: Instruction) bld =
  lift bld ins {
    let tmp = tmpVar bld ins.OprSize
    match ins.Operands with
    | TwoOperands(OprSIMD(VecReg _ ) as dst, src) ->
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src = transSIMDOprToExpr bld eSize dataSize elements src
      let revSize = 32 / int eSize
      let result = Array.chunkBySize revSize src |> Array.collect (Array.rev)
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      let dst, src = transTwoOprs ins bld
      direct tmp := numI32 0 ins.OprSize
      for i in 0 .. ((int ins.OprSize / 8) - 1) do
        let revIdx = (i ^^^ 0b11) * 8
        direct (AST.extract tmp 8<rt> revIdx) := AST.extract src 8<rt> (i * 8)
      done
      direct dst := tmp
  }

let icvtf (ins: Instruction) bld unsigned =
  lift bld ins {
    let oprSize = ins.OprSize
    (* a half is reached through a double; every other width converts at its
       own *)
    let convert (eSize: int<rt>) sz fbits src =
      if eSize = 16<rt> then intToHalf bld unsigned fbits src
      else fixedToFp bld sz fbits unsigned src
    match ins.Operands with
    | TwoOperands(OprSIMD(VecReg _), _) ->
      let struct (o1, o2) = getTwoOprs ins
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems o2
      let src = transSIMDOprToExpr bld eSize dataSize elements o2
      let n0 = AST.num0 eSize
      let result = Array.map (convert eSize eSize n0) src
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | TwoOperands(OprSIMD(ScalarReg _) as dst, _) ->
      let struct (eSize, _, _) = getElemDataSzAndElems dst
      let _, src = transTwoOprs ins bld
      let n0 = AST.num0 oprSize
      let result = convert eSize oprSize n0 src
      dstAssignScalar ins bld dst result eSize
    | ThreeOperands(OprSIMD(ScalarReg _), _, _) ->
      let struct (o1, o2, o3) = getThreeOprs ins
      let struct (eSize, _, _) = getElemDataSzAndElems o1
      let src = transOpr ins bld o2
      let fbits = transOpr ins bld o3
      let result = convert eSize eSize fbits src
      dstAssignScalar ins bld o1 result eSize
    | ThreeOperands(OprSIMD(VecReg _), _, _) ->
      let struct (o1, o2, o3) = getThreeOprs ins
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let struct (eSz, dataSize, elements) = getElemDataSzAndElems o2
      let src = transSIMDOprToExpr bld eSz dataSize elements o2
      let fbits = transOpr ins bld o3 |> AST.xtlo eSz
      let result = Array.map (convert eSz eSz fbits) src
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      let dst, src, fbits = transThreeOprs ins bld
      let result = fixedToFp bld oprSize fbits unsigned src
      sized oprSize dst := result
  }

let shl ins bld =
  lift bld ins {
    let struct (dst, src, amt) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
    match ins.Operands with
    | ThreeOperands(OprSIMD(ScalarReg _), _, _) ->
      let _, src, amt = transThreeOprs ins bld
      dstAssignScalar ins bld dst (src << amt) eSize
    | _ ->
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src = transSIMDOprToExpr bld eSize dataSize elements src
      let amt = transOpr ins bld amt |> AST.xtlo eSize
      let result = Array.map (fun e -> e << amt) src
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let smulh ins bld =
  lift bld ins {
    let dst, src1, src2 = transThreeOprs ins bld
    (* The high 64 bits of the signed 64x64->128 product: the evaluator
       holds the 128-bit intermediate, so extract from it directly. *)
    let prod = AST.sext 128<rt> src1 .* AST.sext 128<rt> src2
    direct dst := AST.xthi 64<rt> prod
  }

let smull (ins: Instruction) bld =
  lift bld ins {
    match ins.Operands with
    | ThreeOperands(_, _, OprSIMD(VecRegWithIdx _)) ->
      let struct (o1, o2, o3) = getThreeOprs ins
      let struct (eSize, part, _) = getElemDataSzAndElems o2
      let elements = 64<rt> / eSize
      let dblESz = eSize * 2
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let src1 = transSIMDOprVPart bld eSize part o2
      let src2 = transOpr ins bld o3 |> AST.sext dblESz
      let result = Array.init elements (fun _ -> tmpVar bld dblESz)
      let prod = Array.map (fun s1 -> AST.sext dblESz s1 .* src2) src1
      Array.iter2 (fun r p -> append bld { direct r := p }) result prod
      dstAssignForSIMD dstA dstB result 128<rt> elements bld
    | ThreeOperands(OprSIMD(VecReg _), _, _) ->
      let struct (o1, o2, o3) = getThreeOprs ins
      let struct (eSize, part, _) = getElemDataSzAndElems o2
      let elements = 64<rt> / eSize
      let dblESz = eSize * 2
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let src1 = transSIMDOprVPart bld eSize part o2
      let src2 = transSIMDOprVPart bld eSize part o3
      let result = Array.init elements (fun _ -> tmpVar bld dblESz)
      Array.map2 (fun e1 e2 ->
        AST.sext dblESz e1 .* AST.sext dblESz e2) src1 src2
      |> Array.iter2 (fun r e -> append bld { direct r := e }) result
      dstAssignForSIMD dstA dstB result 128<rt> elements bld
    | _ ->
      let dst, src1, src2 = transThreeOprs ins bld
      direct dst := AST.sext 64<rt> src1 .* AST.sext 64<rt> src2
  }

/// <summary>
/// One element of SSHL or USHL: shifted left by an amount that may be
/// negative, in which case it is shifted right by the other way round.
///
/// The amount is the second operand's low byte read as a SIGNED number, so it
/// runs to plus or minus a hundred and twenty-eight and can ask for more
/// places than the element has. The architecture answers a left shift past
/// the width with zero and a right shift past it with the sign -- all ones or
/// all zeros -- where a shift in the IR by more than the operand's width says
/// nothing at all. Both are therefore clamped before the shift rather than
/// after it.
///
/// The work is done a width wider where the element is narrow, so that
/// negating an amount of minus a hundred and twenty-eight does not itself
/// overflow.
/// </summary>
let private shiftByRegister bld (eSize: int<rt>) unsigned e1 e2 =
  let wide = if eSize < 16<rt> then 16<rt> else eSize
  let struct (amt, v) = tmpVars2 bld wide
  append bld {
    direct amt := AST.xtlo 8<rt> e2 |> AST.sext wide
    direct v := (if unsigned then AST.zext wide e1 else AST.sext wide e1)
  }
  let width = numI32 (int eSize) wide
  let negAmt = AST.neg amt
  let capped = AST.ite (negAmt ?>= width) (width .- AST.num1 wide) negAmt
  let right = if unsigned then v >> capped else v ?>> capped
  let outOfRange = if unsigned then AST.num0 wide else v ?>> capped
  let right = AST.ite (negAmt ?>= width) outOfRange right
  let left = AST.ite (amt ?>= width) (AST.num0 wide) (v << amt)
  AST.xtlo eSize (AST.ite (amt ?< AST.num0 wide) right left)

let sshl (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, o1, o2) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let inline shiftLeft e1 e2 = shiftByRegister bld eSize false e1 e2
    match ins.Operands with
    | ThreeOperands(OprSIMD(ScalarReg _), _, _) ->
      let src1 = transOpr ins bld o1
      let src2 = transOpr ins bld o2
      let result = shiftLeft src1 src2
      dstAssignScalar ins bld dst result eSize
    | _ ->
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o1
      let src2 = transSIMDOprToExpr bld eSize dataSize elements o2
      let result = Array.map2 shiftLeft src1 src2
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let shift ins bld opFn =
  lift bld ins {
    let struct (dst, src, amt) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    match ins.Operands with
    | ThreeOperands(OprSIMD(ScalarReg _), _, _) ->
      let src = transOpr ins bld src
      let amt = transOpr ins bld amt
      dstAssignScalar ins bld dst (opFn src amt) eSize
    | _ ->
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src = transSIMDOprToExpr bld eSize dataSize elements src
      let amt = transOpr ins bld amt |> AST.xtlo eSize
      let result = Array.map (fun e -> opFn e amt) src
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let stnp (ins: Instruction) bld =
  lift bld ins {
    let address = tmpVar bld 64<rt>
    let dByte = numI32 (RegType.toByteWidth ins.OprSize) 64<rt>
    match ins.OprSize with
    | 128<rt> ->
      let struct (src1, src2, src3) = getThreeOprs ins
      let struct (src1B, src1A) = transOpr128 ins bld src1
      let struct (src2B, src2A) = transOpr128 ins bld src2
      let bReg, offset = transOpr ins bld src3 |> separateMemExpr
      let n8 = numI32 8 64<rt>
      direct address := bReg
      direct address := address .+ offset
      direct (AST.loadLE 64<rt> address) := src1A
      direct (AST.loadLE 64<rt> (address .+ n8)) := src1B
      direct (AST.loadLE 64<rt> (address .+ dByte)) := src2A
      direct (AST.loadLE 64<rt> (address .+ dByte .+ n8)) := src2B
    | _ ->
      let src1, src2, (bReg, offset) = transThreeOprsSepMem ins bld
      direct address := bReg
      direct address := address .+ offset
      direct (AST.loadLE ins.OprSize address) := src1
      direct (AST.loadLE ins.OprSize (address .+ dByte)) := src2
  }

let stp (ins: Instruction) bld =
  lift bld ins {
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    let address = tmpVar bld 64<rt>
    let dByte = numI32 (RegType.toByteWidth ins.OprSize) 64<rt>
    match ins.OprSize with
    | 128<rt> ->
      let struct (src1, src2, src3) = getThreeOprs ins
      let struct (src1B, src1A) = transOpr128 ins bld src1
      let struct (src2B, src2A) = transOpr128 ins bld src2
      let bReg, offset = transOpr ins bld src3 |> separateMemExpr
      let n8 = numI32 8 64<rt>
      direct address := bReg
      direct address := if isPostIndex then address else address .+ offset
      direct (AST.loadLE 64<rt> address) := src1A
      direct (AST.loadLE 64<rt> (address .+ n8)) := src1B
      direct (AST.loadLE 64<rt> (address .+ dByte)) := src2A
      direct (AST.loadLE 64<rt> (address .+ dByte .+ n8)) := src2B
      writeBack bld isWBack isPostIndex bReg address offset
    | _ ->
      let src1, src2, (bReg, offset) = transThreeOprsSepMem ins bld
      direct address := bReg
      direct address := if isPostIndex then address else address .+ offset
      direct (AST.loadLE ins.OprSize address) := src1
      direct (AST.loadLE ins.OprSize (address .+ dByte)) := src2
      writeBack bld isWBack isPostIndex bReg address offset
  }

let str (ins: Instruction) bld =
  lift bld ins {
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    match ins.OprSize with
    | 128<rt> ->
      let struct (src1, src2) = getTwoOprs ins
      let struct (srcB, srcA) = transOpr128 ins bld src1
      let bReg, offset = transOpr ins bld src2 |> separateMemExpr
      let address = tmpVar bld 64<rt>
      direct address := bReg
      direct address := if isPostIndex then address else address .+ offset
      direct (AST.loadLE 64<rt> address) := srcA
      direct (AST.loadLE 64<rt> (address .+ (numI32 8 64<rt>))) := srcB
      writeBack bld isWBack isPostIndex bReg address offset
    | _ ->
      let src, (bReg, offset) = transTwoOprsSepMem ins bld
      let address = tmpVar bld 64<rt>
      let data = tmpVar bld ins.OprSize
      direct address := bReg
      direct address := if isPostIndex then address else address .+ offset
      direct data := src
      direct (AST.loadLE ins.OprSize address) := data
      writeBack bld isWBack isPostIndex bReg address offset
  }

let stur (ins: Instruction) bld =
  lift bld ins {
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld ins.OprSize
    match ins.OprSize with
    | 128<rt> ->
      let struct (src1, src2) = getTwoOprs ins
      let struct (src1B, src1A) = transOpr128 ins bld src1
      let bReg, offset = transOpr ins bld src2 |> separateMemExpr
      direct address := bReg
      direct address := if isPostIndex then address else address .+ offset
      direct (AST.loadLE 64<rt> address) := src1A
      direct (AST.loadLE 64<rt> (address .+ (numI32 8 64<rt>))) := src1B
      writeBack bld isWBack isPostIndex bReg address offset
    | _ ->
      let src, (bReg, offset) = transTwoOprsSepMem ins bld
      direct address := bReg
      direct address := if isPostIndex then address else address .+ offset
      direct data := src
      direct (AST.loadLE ins.OprSize address) := data
      writeBack bld isWBack isPostIndex bReg address offset
  }

let sub (ins: Instruction) bld =
  lift bld ins {
    match ins.Operands with
    | TwoOperands(OprSIMD(ScalarReg _) as dst, _) ->
      let struct (eSize, _, _) = getElemDataSzAndElems dst
      let _, src = transTwoOprs ins bld
      dstAssignScalar ins bld dst (AST.neg src) eSize
    | TwoOperands(OprSIMD(VecReg _) as o1, o2) ->
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems o2
      let src = transSIMDOprToExpr bld eSize dataSize elements o2
      let result = Array.map (AST.neg) src
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | ThreeOperands(OprSIMD(ScalarReg _) as dst, _, _)
        when ins.Opcode = Opcode.SUB ->
      let struct (eSize, _, _) = getElemDataSzAndElems dst
      let _, src1, src2 = transThreeOprs ins bld
      dstAssignScalar ins bld dst (src1 .- src2) eSize
    | ThreeOperands(OprSIMD(VecReg _) as o1, o2, o3)
        when ins.Opcode = Opcode.SUB ->
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
      let result = Array.map2 (.-) src1 src2
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      let dst, src1, src2 = transOprOfSUB ins bld
      let result, _ = addWithCarry src1 src2 (AST.num1 ins.OprSize) ins.OprSize
      sized ins.OprSize dst := result
  }

/// The registers a table lookup reads, low half then high half of each, in
/// the order the operand list names them. A lookup index walks this array
/// eight bytes at a time, which is why each register arrives as two halves.
let private tableRegsOf ins bld src1 =
  match src1 with
  | OprSIMDList simds ->
    simds
    |> List.toArray
    |> Array.collect (fun simd ->
      let struct (hi, lo) = transOpr128 ins bld (OprSIMD simd)
      [| lo; hi |]
    )
  | _ ->
    raise InvalidOperandException

/// The byte the destination already holds at one lane, which TBX keeps where
/// TBL writes zero. The lane is a byte index into the pair of doublewords a
/// vector register is kept as, so which half it comes from is fixed at lift
/// time rather than decided in the IR.
let private tblDstByte dstA dstB i =
  let nFF = numI32 -1 8<rt> |> AST.zext 64<rt>
  let half = if i < 8 then dstA else dstB
  ((half >> (numI32 (i * 8) 64<rt>)) .& nFF) |> AST.xtlo 8<rt>

/// The byte one table register holds at an index, counting from its bottom.
/// The index is taken modulo eight because the caller has already decided
/// which register of the table it falls in.
let private tblByte expr idx =
  let n8 = numI32 8 8<rt>
  let nFF = numI32 -1 8<rt> |> AST.zext 64<rt>
  ((expr >> (AST.zext 64<rt> ((idx .% n8) .* n8))) .& nFF) |> AST.xtlo 8<rt>

/// <summary>
/// TBL and TBX, which read a table of vector registers by byte index.
///
/// They differ in one thing: where the index is past the end of the table TBL
/// writes zero and TBX leaves the destination byte as it was. That is the
/// `keepDst` flag, and it is the whole of the difference.
/// </summary>
let tblOrTbx (ins: Instruction) bld keepDst =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
    let elements = dataSize / 8<rt>
    let struct (dstB, dstA) = transOpr128 ins bld dst
    let src = tableRegsOf ins bld src1
    let indices = transSIMDOprToExpr bld 8<rt> dataSize elements src2
    let past = tmpVar bld eSize
    direct past := AST.num0 eSize
    let lenExpr = tmpVar bld 8<rt>
    let len = Array.length src
    direct lenExpr := numI32 (len / 2 * 16) 8<rt>
    let limit i expr index =
      AST.ite (index .< lenExpr) (tblByte expr index) (tblDstByte dstA dstB i)
    let getElem i idx =
      if len = 2 || len = 4 || len = 6 || len = 8 then
        (* each register covers eight indices, and past the last of them the
           lookup gives zero unless the destination is being kept *)
        let outside = if keepDst then tblDstByte dstA dstB i else past
        Array.foldBack (fun k rest ->
          AST.ite (idx .< numI32 (8 * (k + 1)) 8<rt>) (limit i src[k] idx) rest
        ) [| 0 .. len - 1 |] outside
      else
        raise InvalidOperandException
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    Array.mapi getElem indices
    |> Array.iter2 (fun e1 e2 -> append bld { direct e1 := e2 }) result
    dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let tbl ins bld = tblOrTbx ins bld false

let tbx ins bld = tblOrTbx ins bld true

let trn1 ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let struct (dstB, dstA) = transOpr128 ins bld o1
    let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
    let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    Array.iteri (fun i r ->
      let e = if i % 2 = 0 then src1[i] else src2[i - 1]
      append bld { direct r := e }) result
    dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let trn2 ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let struct (dstB, dstA) = transOpr128 ins bld o1
    let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
    let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    Array.iteri (fun i r ->
      let e = if i % 2 = 1 then src2[i] else src1[i + 1]
      append bld { direct r := e }) result
    dstAssignForSIMD dstA dstB result dataSize elements bld
  }

/// The widening absolute difference accumulated into the destination, in
/// both signednesses.
let abal (ins: Instruction) bld unsigned =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems src1
    let elements = 64<rt> / eSize
    let dblESz = eSize * 2
    let struct (dstB, dstA) = transOpr128 ins bld dst
    let dst = transSIMDOprToExpr bld dblESz 128<rt> elements dst
    let s1 = transSIMDOprVPart bld eSize part src1
    let s2 = transSIMDOprVPart bld eSize part src2
    let result = Array.init elements (fun _ -> tmpVar bld dblESz)
    Array.iter2 (fun r e -> append bld { direct r := e }) result dst
    let dblExt e = (if unsigned then AST.zext else AST.sext) dblESz e
    let ge = if unsigned then (.>=) else (?>=)
    Array.map2 (fun e1 e2 ->
      AST.ite (ge e1 e2) (dblExt e1 .- dblExt e2) (dblExt e2 .- dblExt e1))
      s1 s2
    |> Array.iter2 (fun r d ->
      append bld { direct r := r .+ d }) result
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  }

/// The widening absolute difference, in both signednesses.
let abdl (ins: Instruction) bld unsigned =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems src1
    let elements = 64<rt> / eSize
    let dblESz = eSize * 2
    let struct (dstB, dstA) = transOpr128 ins bld dst
    let s1 = transSIMDOprVPart bld eSize part src1
    let s2 = transSIMDOprVPart bld eSize part src2
    let result = Array.init elements (fun _ -> tmpVar bld dblESz)
    let dblExt e = (if unsigned then AST.zext else AST.sext) dblESz e
    let ge = if unsigned then (.>=) else (?>=)
    Array.map2 (fun e1 e2 ->
      AST.ite (ge e1 e2) (dblExt e1 .- dblExt e2) (dblExt e2 .- dblExt e1))
      s1 s2
    |> Array.iter2 (fun r d -> append bld { direct r := d }) result
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  }

/// The pairwise widening accumulate, in both signednesses.
let adalp ins bld unsigned =
  lift bld ins {
    let struct (o1, src) = getTwoOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
    let dst = transSIMDOprToExpr bld (eSize * 2) dataSize (elements / 2) o1
    let src = transSIMDOprToExpr bld eSize dataSize elements src
              |> Array.map ((if unsigned then AST.zext else AST.sext)
                              (2 * eSize))
    let result = Array.init (elements / 2) (fun _ -> tmpVar bld (2 * eSize))
    Array.iter2 (fun dst res -> append bld { direct res := dst }) dst result
    let sum = src |> Array.chunkBySize 2 |> Array.map (fun e -> e[0] .+ e[1])
    Array.iter2 (fun r s -> append bld { direct r := r .+ s }) result sum
    let elems = elements / 4
    let srcB =
      if dataSize = 128<rt> then AST.revConcat (Array.sub result elems elems)
      else AST.num0 64<rt>
    let srcA =
      if dataSize = 128<rt> then AST.revConcat (Array.sub result 0 elems)
      else AST.revConcat result
    dstAssign128 ins bld o1 srcA srcB dataSize
  }

let saddl (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems src2
    let elements = 64<rt> / eSize
    let dblESz = eSize * 2
    let struct (dstB, dstA) = transOpr128 ins bld dst
    let src1 = transSIMDOprVPart bld eSize part src1
    let src2 = transSIMDOprVPart bld eSize part src2
    let result = Array.init elements (fun _ -> tmpVar bld dblESz)
    Array.map2 (fun e1 e2 -> AST.sext dblESz e1 .+ AST.sext dblESz e2) src1 src2
    |> Array.iter2 (fun r e -> append bld { direct r := e }) result
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  }

let saddw (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems src2
    let elements = 64<rt> / eSize
    let dblESz = eSize * 2
    let struct (dstB, dstA) = transOpr128 ins bld dst
    let src1 = transSIMDOprToExpr bld dblESz 128<rt> elements src1
    let src2 = transSIMDOprVPart bld eSize part src2
    let result = Array.init elements (fun _ -> tmpVar bld dblESz)
    Array.map2 (fun e1 e2 -> e1 .+ AST.sext dblESz e2) src1 src2
    |> Array.iter2 (fun r e -> append bld { direct r := e }) result
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  }

let saddlp ins bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
    let sumArr = Array.init (elements / 2) (fun _ -> tmpVar bld (2 * eSize))
    let struct (dstB, dstA) = transOpr128 ins bld dst
    let srcArr =
      transSIMDOprToExpr bld eSize dataSize elements src
      |> Array.map (AST.sext (2 * eSize)) |> Array.chunkBySize 2
      |> Array.map (fun e -> e[0] .+ e[1])
    Array.iter2 (fun sum src -> append bld { direct sum := src }) sumArr srcArr
    dstAssignForSIMD dstA dstB sumArr dataSize (elements / 2) bld
  }

let saddlv ins bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
    let src =
      transSIMDOprToExpr bld eSize dataSize elements src
      |> Array.map (AST.sext (2 * eSize))
    let sum = tmpVar bld (2 * eSize)
    direct sum := src[0]
    Array.sub src 1 (elements - 1)
    |> Array.iter (fun e -> append bld { direct sum := sum .+ e })
    dstAssignScalar ins bld dst sum (2 * eSize)
  }

let uaddl (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems src2
    let elements = 64<rt> / eSize
    let dblESz = eSize * 2
    let struct (dstB, dstA) = transOpr128 ins bld dst
    let src1 = transSIMDOprVPart bld eSize part src1
    let src2 = transSIMDOprVPart bld eSize part src2
    let result = Array.init elements (fun _ -> tmpVar bld dblESz)
    Array.map2 (fun e1 e2 -> AST.zext dblESz e1 .+ AST.zext dblESz e2) src1 src2
    |> Array.iter2 (fun r e -> append bld { direct r := e }) result
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  }

let uaddw (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems src2
    let elements = 64<rt> / eSize
    let dblESz = eSize * 2
    let struct (dstB, dstA) = transOpr128 ins bld dst
    let src1 = transSIMDOprToExpr bld dblESz 128<rt> elements src1
    let src2 = transSIMDOprVPart bld eSize part src2
    let result = Array.init elements (fun _ -> tmpVar bld dblESz)
    Array.map2 (fun e1 e2 -> e1 .+ AST.zext dblESz e2) src1 src2
    |> Array.iter2 (fun r e -> append bld { direct r := e }) result
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  }

let uaddlp ins bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
    let sumArr = Array.init (elements / 2) (fun _ -> tmpVar bld (2 * eSize))
    let struct (dstB, dstA) = transOpr128 ins bld dst
    let srcArr = transSIMDOprToExpr bld eSize dataSize elements src
              |> Array.map (AST.zext (2 * eSize))
              |> Array.chunkBySize 2
              |> Array.map (fun e -> e[0] .+ e[1])
    Array.iter2 (fun sum src -> append bld { direct sum := src }) sumArr srcArr
    dstAssignForSIMD dstA dstB sumArr dataSize (elements / 2) bld
  }

let uaddlv ins bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
    let src = transSIMDOprToExpr bld eSize dataSize elements src
              |> Array.map (AST.zext (2 * eSize))
    let sum = tmpVar bld (2 * eSize)
    direct sum := src[0]
    Array.sub src 1 (elements - 1)
    |> Array.iter (fun e -> append bld { direct sum := sum .+ e })
    dstAssignScalar ins bld dst sum (2 * eSize)
  }

let smlal (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems src1
    let dataSize = 64<rt>
    let elements = dataSize / eSize
    let dblESz = eSize * 2
    let struct (dstB, dstA) = transOpr128 ins bld dst
    let dst = transSIMDOprToExpr bld dblESz 128<rt> elements dst
    let opr1 = transSIMDOprVPart bld eSize part src1
    let result = Array.init elements (fun _ -> tmpVar bld dblESz)
    match ins.Operands with
    | ThreeOperands(_, _, OprSIMD(VecReg _)) ->
      let opr2 = transSIMDOprVPart bld eSize part src2
      Array.map3 (fun e1 e2 e3 ->
        e3 .+ (AST.sext dblESz e1 .* AST.sext dblESz e2)) opr1 opr2 dst
      |> Array.iter2 (fun r e -> append bld { direct r := e }) result
      dstAssignForSIMD dstA dstB result 128<rt> elements bld
    | _ ->
      let opr2 = tmpVar bld dblESz
      direct opr2 := transOpr ins bld src2 |> AST.sext dblESz
      Array.map2 (fun e1 e3 -> e3 .+ (AST.sext dblESz e1 .* opr2)) opr1 dst
      |> Array.iter2 (fun r e -> append bld { direct r := e }) result
      dstAssignForSIMD dstA dstB result (2 * dataSize) elements bld
  }

let smlsl (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems src1
    let dataSize = 64<rt>
    let elements = dataSize / eSize
    let dblESz = eSize * 2
    let dblDSize = dataSize * 2
    let struct (dstB, dstA) = transOpr128 ins bld dst
    let opr1 = transSIMDOprVPart bld eSize part src1
    let opr3 = transSIMDOprToExpr bld dblESz 128<rt> elements dst
    let result = Array.init elements (fun _ -> tmpVar bld dblESz)
    match ins.Operands with
    | ThreeOperands(_, _, OprSIMD(VecReg _)) ->
      let opr2 = transSIMDOprVPart bld eSize part src2
      Array.map3 (fun e1 e2 e3 ->
        e3 .- (AST.sext dblESz e1 .* AST.sext dblESz e2)) opr1 opr2 opr3
      |> Array.iter2 (fun r e -> append bld { direct r := e }) result
      dstAssignForSIMD dstA dstB result dblDSize elements bld
    | _ ->
      let opr2 = tmpVar bld dblESz
      direct opr2 := transOpr ins bld src2 |> AST.sext dblESz
      Array.map2 (fun e1 e3 ->
        AST.sext dblESz e3 .- (AST.sext dblESz e1 .* opr2)) opr1 opr3
      |> Array.iter2 (fun r e -> append bld { direct r := e }) result
      dstAssignForSIMD dstA dstB result dblDSize elements bld
  }

let private ssatQMulH bld e1 e2 (eSize: int<rt>) =
  let dblESz = 2 * eSize
  let shfAmt = numI32 (int eSize) dblESz
  let product =
    AST.shl (AST.sext dblESz e1 .* AST.sext dblESz e2) (AST.num1 dblESz)
  let sign1 = AST.xthi 1<rt> e1
  let sign2 = AST.xthi 1<rt> e2
  let input = AST.ite (sign1 != sign2) (product ?>> shfAmt) (product >> shfAmt)
  signedSatQ bld input eSize

let sqdmulh (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    match ins.Operands with
    | ThreeOperands(OprSIMD(VecReg _), _, OprSIMD(VecRegWithIdx _)) ->
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let src2 = transOpr ins bld o3
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      Array.map (fun e1 -> ssatQMulH bld e1 src2 eSize) src1
      |> Array.iter2 (fun res prod -> append bld { direct res := prod }) result
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | ThreeOperands(OprSIMD(VecReg _), _, _) ->
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      Array.map2 (fun e1 e2 -> ssatQMulH bld e1 e2 eSize) src1 src2
      |> Array.iter2 (fun res prod -> append bld { direct res := prod }) result
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | ThreeOperands(OprSIMD(ScalarReg _), _, _) ->
      let src1 = transOpr ins bld o2
      let src2 = transOpr ins bld o3
      let result = ssatQMulH bld src1 src2 eSize
      dstAssignScalar ins bld o1 result eSize
    | _ ->
      raise InvalidOperandException
  }

let private ssatQMulL bld e1 e2 (eSize: int<rt>) =
  let dblESz = 2 * eSize
  let bitQC = AST.extract (regVar bld R.FPSR) 1<rt> 27
  let sign1 = AST.xthi 1<rt> e1
  let sign2 = AST.xthi 1<rt> e2
  let mult = AST.sext dblESz e1 .* AST.sext dblESz e2
  let product = AST.shl mult (AST.num1 dblESz)
  let overflow =
    let overflowBit = AST.extract mult 1<rt> (int dblESz - 2)
    sign1 .& sign2 .& overflowBit
  let underflow =
    let srcIsNotZero = (AST.num0 eSize != e1) .& (AST.num0 eSize != e2)
    srcIsNotZero .& (sign1 != sign2) .& (AST.not <| AST.xthi 1<rt> product)
  let max = getIntMax dblESz false
  let min = AST.not max
  append bld {
    direct bitQC := bitQC .| overflow .| underflow
  }
  AST.ite overflow max (AST.ite underflow min product)

let sqdmull (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems o2
    match ins.Operands with
    | ThreeOperands(OprSIMD(VecReg _), _, OprSIMD(VecRegWithIdx _)) ->
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let src1 = transSIMDOprVPart bld eSize part o2
      let src2 = transOpr ins bld o3
      let elements = 64<rt> / eSize
      let result = Array.init elements (fun _ -> tmpVar bld (2 * eSize))
      Array.map (fun e1 -> ssatQMulL bld e1 src2 eSize) src1
      |> Array.iter2 (fun res prod -> append bld { direct res := prod }) result
      dstAssignForSIMD dstA dstB result 128<rt> elements bld
    | ThreeOperands(OprSIMD(VecReg _), _, _) ->
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let src1 = transSIMDOprVPart bld eSize part o2
      let src2 = transSIMDOprVPart bld eSize part o3
      let elements = 64<rt> / eSize
      let result = Array.init elements (fun _ -> tmpVar bld (2 * eSize))
      Array.map2 (fun e1 e2 -> ssatQMulL bld e1 e2 eSize) src1 src2
      |> Array.iter2 (fun res prod -> append bld { direct res := prod }) result
      dstAssignForSIMD dstA dstB result 128<rt> elements bld
    | ThreeOperands(OprSIMD(ScalarReg _), _, _) ->
      let src1 = transOpr ins bld o2
      let src2 = transOpr ins bld o3
      let result = ssatQMulL bld src1 src2 eSize
      dstAssignScalar ins bld o1 result eSize
    | _ ->
      raise InvalidOperandException
  }

let private ssatQMAdd bld src1 src2 dstElm eSize =
  let bitQC = AST.extract (regVar bld R.FPSR) 1<rt> 27
  let max = getIntMax (2 * eSize) false
  let min = AST.not max
  let product = ssatQMulL bld src1 src2 eSize
  let accum = dstElm .+ product
  let o1 = AST.xthi 1<rt> dstElm
  let o2 = AST.xthi 1<rt> product
  let r = AST.xthi 1<rt> accum
  let outOfRange = (o1 == o2) .& (o1 <+> r)
  let overflow = (o1 == AST.b0) .& outOfRange
  let underflow = (o1 == AST.b1) .& outOfRange
  append bld {
    direct bitQC := bitQC .| overflow .| underflow
  }
  AST.ite overflow max (AST.ite underflow min accum)

let sqdmlal (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems o2
    match ins.Operands with
    | ThreeOperands(OprSIMD(VecReg _), _, OprSIMD(VecRegWithIdx _)) ->
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let elements = 64<rt> / eSize
      let dblESz = 2 * eSize
      let dst = transSIMDOprToExpr bld dblESz 128<rt> elements o1
      let src1 = transSIMDOprVPart bld eSize part o2
      let src2 = transOpr ins bld o3
      let result = Array.init elements (fun _ -> tmpVar bld dblESz)
      Array.map2 (fun e1 e2 -> ssatQMAdd bld e1 src2 e2 eSize) src1 dst
      |> Array.iter2 (fun res accum ->
        append bld { direct res := accum }) result
      dstAssignForSIMD dstA dstB result 128<rt> elements bld
    | ThreeOperands(OprSIMD(VecReg _), _, _) ->
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let elements = 64<rt> / eSize
      let dblESz = 2 * eSize
      let dst = transSIMDOprToExpr bld dblESz 128<rt> elements o1
      let src1 = transSIMDOprVPart bld eSize part o2
      let src2 = transSIMDOprVPart bld eSize part o3
      let result = Array.init elements (fun _ -> tmpVar bld dblESz)
      Array.map3 (fun e1 e2 e3 -> ssatQMAdd bld e1 e2 e3 eSize) src1 src2 dst
      |> Array.iter2 (fun res accum ->
        append bld { direct res := accum }) result
      dstAssignForSIMD dstA dstB result 128<rt> elements bld
    | ThreeOperands(OprSIMD(ScalarReg _), _, _) ->
      let dst = transOpr ins bld o1
      let src1 = transOpr ins bld o2
      let src2 = transOpr ins bld o3
      let result = ssatQMAdd bld src1 src2 dst eSize
      dstAssignScalar ins bld o1 result eSize
    | _ ->
      raise InvalidOperandException
  }

/// The doubling multiply and SUBTRACT, read the way the accumulate above is:
/// a signed difference leaves the range when the accumulator and the product
/// differ in sign and the answer takes the product's rather than the
/// accumulator's.
let private ssatQMSub bld src1 src2 dstElm eSize =
  let bitQC = AST.extract (regVar bld R.FPSR) 1<rt> 27
  let max = getIntMax (2 * eSize) false
  let min = AST.not max
  let product = ssatQMulL bld src1 src2 eSize
  let accum = dstElm .- product
  let o1 = AST.xthi 1<rt> dstElm
  let o2 = AST.xthi 1<rt> product
  let r = AST.xthi 1<rt> accum
  let outOfRange = (o1 <+> o2) .& (o1 <+> r)
  let overflow = (o1 == AST.b0) .& outOfRange
  let underflow = (o1 == AST.b1) .& outOfRange
  append bld {
    direct bitQC := bitQC .| overflow .| underflow
  }
  AST.ite overflow max (AST.ite underflow min accum)

let sqdmlsl (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems o2
    match ins.Operands with
    | ThreeOperands(OprSIMD(VecReg _), _, OprSIMD(VecRegWithIdx _)) ->
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let elements = 64<rt> / eSize
      let dblESz = 2 * eSize
      let dst = transSIMDOprToExpr bld dblESz 128<rt> elements o1
      let src1 = transSIMDOprVPart bld eSize part o2
      let src2 = transOpr ins bld o3
      let result = Array.init elements (fun _ -> tmpVar bld dblESz)
      Array.map2 (fun e1 e2 -> ssatQMSub bld e1 src2 e2 eSize) src1 dst
      |> Array.iter2 (fun res accum ->
        append bld { direct res := accum }) result
      dstAssignForSIMD dstA dstB result 128<rt> elements bld
    | ThreeOperands(OprSIMD(VecReg _), _, _) ->
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let elements = 64<rt> / eSize
      let dblESz = 2 * eSize
      let dst = transSIMDOprToExpr bld dblESz 128<rt> elements o1
      let src1 = transSIMDOprVPart bld eSize part o2
      let src2 = transSIMDOprVPart bld eSize part o3
      let result = Array.init elements (fun _ -> tmpVar bld dblESz)
      Array.map3 (fun e1 e2 e3 -> ssatQMSub bld e1 e2 e3 eSize) src1 src2 dst
      |> Array.iter2 (fun res accum ->
        append bld { direct res := accum }) result
      dstAssignForSIMD dstA dstB result 128<rt> elements bld
    | ThreeOperands(OprSIMD(ScalarReg _), _, _) ->
      let dst = transOpr ins bld o1
      let src1 = transOpr ins bld o2
      let src2 = transOpr ins bld o3
      let result = ssatQMSub bld src1 src2 dst eSize
      dstAssignScalar ins bld o1 result eSize
    | _ ->
      raise InvalidOperandException
  }

let umlal (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems src1
    let dataSize = 64<rt>
    let elements = dataSize / eSize
    let dblESz = eSize * 2
    let struct (dstB, dstA) = transOpr128 ins bld dst
    let dst = transSIMDOprToExpr bld dblESz 128<rt> elements dst
    let opr1 = transSIMDOprVPart bld eSize part src1
    let result = Array.init elements (fun _ -> tmpVar bld dblESz)
    match ins.Operands with
    | ThreeOperands(_, _, OprSIMD(VecReg _)) ->
      let opr2 = transSIMDOprVPart bld eSize part src2
      Array.map3 (fun e1 e2 e3 ->
        e3 .+ (AST.zext dblESz e1 .* AST.zext dblESz e2)) opr1 opr2 dst
      |> Array.iter2 (fun r e -> append bld { direct r := e }) result
      dstAssignForSIMD dstA dstB result 128<rt> elements bld
    | _ ->
      let opr2 = tmpVar bld dblESz
      direct opr2 := transOpr ins bld src2 |> AST.zext dblESz
      Array.map2 (fun e1 e3 -> e3 .+ (AST.zext dblESz e1 .* opr2)) opr1 dst
      |> Array.iter2 (fun r e -> append bld { direct r := e }) result
      dstAssignForSIMD dstA dstB result 128<rt> elements bld
  }

let umlsl (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems src1
    let dataSize = 64<rt>
    let elements = dataSize / eSize
    let dblESz = eSize * 2
    let dblDSize = dataSize * 2
    let struct (dstB, dstA) = transOpr128 ins bld dst
    let opr1 = transSIMDOprVPart bld eSize part src1
    let opr3 = transSIMDOprToExpr bld dblESz 128<rt> elements dst
    let result = Array.init elements (fun _ -> tmpVar bld dblESz)
    match ins.Operands with
    | ThreeOperands(_, _, OprSIMD(VecReg _)) ->
      let opr2 = transSIMDOprVPart bld eSize part src2
      Array.map3 (fun e1 e2 e3 ->
        e3 .- (AST.zext dblESz e1 .* AST.zext dblESz e2)) opr1 opr2 opr3
      |> Array.iter2 (fun r e -> append bld { direct r := e }) result
      dstAssignForSIMD dstA dstB result dblDSize elements bld
    | _ ->
      let opr2 = tmpVar bld dblESz
      direct opr2 := transOpr ins bld src2 |> AST.zext dblESz
      Array.map2 (fun e1 e3 -> e3 .- (AST.zext dblESz e1 .* opr2)) opr1 opr3
      |> Array.iter2 (fun r e -> append bld { direct r := e }) result
      dstAssignForSIMD dstA dstB result dblDSize elements bld
  }

let umulh ins bld =
  lift bld ins {
    let dst, src1, src2 = transThreeOprs ins bld
    (* The high 64 bits of the unsigned 64x64->128 product, extracted from the
       128-bit intermediate the evaluator holds. *)
    let prod = AST.zext 128<rt> src1 .* AST.zext 128<rt> src2
    direct dst := AST.xthi 64<rt> prod
  }

let umull (ins: Instruction) bld =
  lift bld ins {
    match ins.Operands with
    | ThreeOperands(_, _, OprSIMD(VecRegWithIdx _)) ->
      let struct (o1, o2, o3) = getThreeOprs ins
      let struct (eSize, part, _) = getElemDataSzAndElems o2
      let elements = 64<rt> / eSize
      let dblESz = eSize * 2
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let opr1 = transSIMDOprVPart bld eSize part o2
      let opr2 = tmpVar bld dblESz
      direct opr2 := transOpr ins bld o3 |> AST.zext dblESz
      let result = Array.init elements (fun _ -> tmpVar bld dblESz)
      Array.map (fun e1 -> AST.zext dblESz e1 .* opr2) opr1
      |> Array.iter2 (fun r e -> append bld { direct r := e }) result
      dstAssignForSIMD dstA dstB result 128<rt> elements bld
    | ThreeOperands(OprSIMD(VecReg _), _, _) ->
      let struct (o1, o2, o3) = getThreeOprs ins
      let struct (eSize, part, _) = getElemDataSzAndElems o2
      let elements = 64<rt> / eSize
      let dblESz = eSize * 2
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let opr1 = transSIMDOprVPart bld eSize part o2
      let opr2 = transSIMDOprVPart bld eSize part o3
      let result = Array.init elements (fun _ -> tmpVar bld dblESz)
      Array.map2 (fun e1 e2 -> AST.zext dblESz e1 .* AST.zext dblESz e2)
        opr1 opr2
      |> Array.iter2 (fun r e -> append bld { direct r := e }) result
      dstAssignForSIMD dstA dstB result 128<rt> elements bld
    | _ ->
      let dst, src1, src2 = transThreeOprs ins bld
      direct dst := AST.zext 64<rt> src1 .* AST.zext 64<rt> src2
  }

/// A saturating add of two doublewords, which has no wider width to compute
/// in: the overflow is read off the operands instead. An unsigned sum went
/// over when it came out below either operand, and a signed one when both
/// operands shared a sign that the answer does not.
let private satQAdd64 bld unsigned src1 src2 =
  let input = src1 .+ src2
  let bitQC = AST.extract (regVar bld R.FPSR) 1<rt> 27
  let n0 = AST.num0 64<rt>
  let max = getIntMax 64<rt> unsigned
  let overflow =
    if unsigned then input .< src1
    else ((src1 <+> src2) ?>= n0) .& ((input <+> src1) ?< n0)
  let limit =
    if unsigned then max else AST.ite (src1 ?< n0) (AST.not max) max
  append bld {
    direct bitQC := bitQC .| overflow
  }
  AST.ite overflow limit input

/// <summary>
/// The saturating add, in both signednesses.
///
/// Every width but the widest is done one bit wider than the element and then
/// clamped, which is the direct reading of the pseudocode. At sixty-four bits
/// there is no wider type to compute in, so the overflow is read off the
/// signs instead: an unsigned sum that came out below what went in carried,
/// and a signed sum of two operands of the same sign that came out with the
/// other sign went over.
/// </summary>
let qadd (ins: Instruction) bld unsigned =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let ext = if unsigned then AST.zext else AST.sext
    let satQ64 src1 src2 = satQAdd64 bld unsigned src1 src2
    match ins.Operands with
    | ThreeOperands(OprSIMD(VecReg _), _, _) ->
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      if eSize = 64<rt> then
        Array.map2 satQ64 src1 src2
        |> Array.iter2 (fun element i ->
          append bld { direct element := i }) result
      else
        Array.map2 (fun e1 e2 ->
          ext (2 * eSize) e1 .+ ext (2 * eSize) e2) src1 src2
        |> Array.iter2 (fun element i ->
          append bld { direct element := satQ bld i eSize unsigned }) result
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | ThreeOperands(OprSIMD(ScalarReg _), _, _) ->
      let src1 = transOpr ins bld o2
      let src2 = transOpr ins bld o3
      let result =
        if eSize = 64<rt> then
          satQ64 src1 src2
        else
          let input = AST.zext (2 * eSize) src1 .+ AST.zext (2 * eSize) src2
          satQ bld input eSize true
      dstAssignScalar ins bld o1 result eSize
    | _ ->
      raise InvalidOperandException
  }

let uqrshl (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    match ins.Operands with
    | ThreeOperands(OprSIMD(VecReg _), _, _) ->
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      Array.map2 (fun e shf ->
        let shf = shf |> AST.xtlo 8<rt> |> AST.sext eSize
        usatQRShl bld e shf eSize) src1 src2
      |> Array.iter2 (fun r e -> append bld { direct r := e }) result
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | ThreeOperands(OprSIMD(ScalarReg _), _, _) ->
      let src1 = transOpr ins bld o2
      let shift =
        transOpr ins bld o3 |> AST.xtlo 8<rt> |> AST.sext eSize
      let result = usatQRShl bld src1 shift eSize
      dstAssignScalar ins bld o1 result eSize
    | _ ->
      raise InvalidOperandException
  }

/// <summary>
/// SQSHL and SQRSHL in their register forms: the signed saturating shift by
/// an amount another vector carries.
///
/// The amount is the LOW BYTE of its element read as a signed number, so a
/// negative one shifts right. Reading the whole element instead would make
/// every amount above 127 a huge left shift rather than the right shift the
/// byte says.
/// </summary>
let sqshlReg (ins: Instruction) bld isRound =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let amountOf e = e |> AST.xtlo 8<rt> |> AST.sext eSize
    match ins.Operands with
    | ThreeOperands(OprSIMD(VecReg _), _, OprSIMD _) ->
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      Array.map2 (fun e shf ->
        satQShlBy bld isRound e (amountOf shf) eSize) src1 src2
      |> Array.iter2 (fun r e -> append bld { direct r := e }) result
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | ThreeOperands(OprSIMD(VecReg _), _, _) ->
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let shift = numI64 (shiftAmountOf o3) eSize
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      Array.map (fun e -> satQShlBy bld isRound e shift eSize) src1
      |> Array.iter2 (fun r e -> append bld { direct r := e }) result
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | ThreeOperands(OprSIMD(ScalarReg _), _, OprSIMD _) ->
      let src1 = transOpr ins bld o2
      let shift = transOpr ins bld o3 |> amountOf
      let result = satQShlBy bld isRound src1 shift eSize
      dstAssignScalar ins bld o1 result eSize
    | ThreeOperands(OprSIMD(ScalarReg _), _, _) ->
      let src1 = transOpr ins bld o2
      let shift = numI64 (shiftAmountOf o3) eSize
      let result = satQShlBy bld isRound src1 shift eSize
      dstAssignScalar ins bld o1 result eSize
    | _ ->
      raise InvalidOperandException
  }

/// <summary>
/// SQRDMULH: multiply two signed elements, double the product, round it and
/// keep the top half, saturating.
///
/// The manual says (2*a*b + 2^(esize-1)) >> esize, and that doubling is the
/// one place a product of two elements no longer fits in two elements' worth
/// of bits: a and b both at the signed minimum give exactly the bit above the
/// top. Halving both sides of the shift says the same thing without leaving
/// the width -- (a*b + 2^(esize-2)) >> (esize-1) -- because shifting a
/// doubled value one place further is the value itself.
/// </summary>
let private rdmulhElem bld (eSize: int<rt>) e1 e2 =
  let wide = eSize * 2
  let product = AST.sext wide e1 .* AST.sext wide e2
  let half = AST.num1 wide << numI32 (int eSize - 2) wide
  let rounded = (product .+ half) ?>> numI32 (int eSize - 1) wide
  satQ bld rounded eSize false

let sqrdmulh (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    match ins.Operands with
    | ThreeOperands(OprSIMD(VecReg _), _, OprSIMD(VecRegWithIdx _)) ->
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let src2 = transOpr ins bld o3
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      Array.map (fun e1 -> rdmulhElem bld eSize e1 src2) src1
      |> Array.iter2 (fun r e -> append bld { direct r := e }) result
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | ThreeOperands(OprSIMD(VecReg _), _, _) ->
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      Array.map2 (rdmulhElem bld eSize) src1 src2
      |> Array.iter2 (fun r e -> append bld { direct r := e }) result
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | ThreeOperands(OprSIMD(ScalarReg _), _, _) ->
      let src1 = transOpr ins bld o2
      let src2 = transOpr ins bld o3
      let result = rdmulhElem bld eSize src1 src2
      dstAssignScalar ins bld o1 result eSize
    | _ ->
      raise InvalidOperandException
  }

/// <summary>
/// SQSHRN and SQRSHRN: shift each element right by an immediate and narrow it
/// to half its width, saturating.
///
/// The shift is of the SOURCE element, which is twice as wide as what is
/// written, so the rounding constant and the shift both belong at the source
/// width and only the saturation looks at the narrow one.
/// </summary>
let sqshrn (ins: Instruction) bld isPart2 isRound srcUnsigned dstUnsigned =
  lift bld ins {
    let struct (dst, src, amt) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
    let shift = numI64 (shiftAmountOf amt) eSize
    let rnd = AST.num1 eSize << (shift .- AST.num1 eSize)
    let shifted e =
      let e = if isRound then e .+ rnd else e
      if srcUnsigned then e >> shift else e ?>> shift
    let narrowed e = satNarrow bld (shifted e) eSize srcUnsigned dstUnsigned
    match ins.Operands with
    | ThreeOperands(OprSIMD(ScalarReg _), _, _) ->
      let src = transOpr ins bld src
      dstAssignScalar ins bld dst (narrowed src) (eSize / 2)
    | _ ->
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src = transSIMDOprToExpr bld eSize dataSize elements src
      let result = Array.init elements (fun _ -> tmpVar bld (eSize / 2))
      Array.map narrowed src
      |> Array.iter2 (fun r e -> append bld { direct r := e }) result
      if isPart2 then
        direct dstB := AST.revConcat result
      else
        direct dstA := AST.revConcat result
        direct dstB := AST.num0 64<rt>
  }

/// The saturating subtract, in both signednesses, read the same way round as
/// the add above: an unsigned difference borrows when the first operand is
/// the smaller, and a signed one goes over when the operands differ in sign
/// and the answer takes the second one's.
/// The saturating subtract of two doublewords, read the way satQAdd64 reads
/// the add: an unsigned difference went under when the first operand is the
/// smaller, and a signed one when the operands differ in sign and the answer
/// takes the second's.
let private satQSub64 bld unsigned src1 src2 =
  let eval = src1 .- src2
  let bitQC = AST.extract (regVar bld R.FPSR) 1<rt> 27
  let n0 = AST.num0 64<rt>
  let max = getIntMax 64<rt> false
  let underflow =
    if unsigned then src1 .< src2
    else ((src1 <+> src2) ?< n0) .& ((eval <+> src1) ?< n0)
  let limit =
    if unsigned then n0 else AST.ite (src1 ?< n0) (AST.not max) max
  append bld {
    direct bitQC := bitQC .| underflow
  }
  AST.ite underflow limit eval

let qsub (ins: Instruction) bld unsigned =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let ext = if unsigned then AST.zext else AST.sext
    let satQ64 src1 src2 = satQSub64 bld unsigned src1 src2
    match ins.Operands with
    | ThreeOperands(OprSIMD(VecReg _), _, _) ->
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      if eSize = 64<rt> then
        Array.map2 satQ64 src1 src2
        |> Array.iter2 (fun element i ->
          append bld { direct element := i }) result
      else
        Array.map2 (fun e1 e2 ->
          ext (2 * eSize) e1 .- ext (2 * eSize) e2) src1 src2
        |> Array.iter2 (fun element i ->
          append bld { direct element := satQ bld i eSize unsigned }) result
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | ThreeOperands(OprSIMD(ScalarReg _), _, _) ->
      let src1 = transOpr ins bld o2
      let src2 = transOpr ins bld o3
      let result =
        if eSize = 64<rt> then
          satQ64 src1 src2
        else
          let input = AST.zext (2 * eSize) src1 .- AST.zext (2 * eSize) src2
          satQ bld input eSize true
      dstAssignScalar ins bld o1 result eSize
    | _ ->
      raise InvalidOperandException
  }

let uqshl (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    match ins.Operands with
    | ThreeOperands(OprSIMD(VecReg _), _, OprImm _) ->
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let shift = transOpr ins bld o3 |> AST.xtlo 8<rt>
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      let shf = tmpVar bld eSize
      direct shf := shift |> AST.sext eSize
      Array.map (fun e -> usatQShl bld e shf eSize) src1
      |> Array.iter2 (fun r e -> append bld { direct r := e }) result
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | ThreeOperands(OprSIMD(VecReg _), _, _) ->
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      Array.map2 (fun e shf ->
        let shf = shf |> AST.xtlo 8<rt> |> AST.sext eSize
        usatQShl bld e shf eSize) src1 src2
      |> Array.iter2 (fun r e -> append bld { direct r := e }) result
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | ThreeOperands(OprSIMD(ScalarReg _), _, _) ->
      let src1 = transOpr ins bld o2
      let shift = transOpr ins bld o3 |> AST.xtlo 8<rt>
      let result = usatQShl bld src1 (AST.sext eSize shift) eSize
      dstAssignScalar ins bld o1 result eSize
    | _ ->
      raise InvalidOperandException
  }

let shiftULeftLong (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems o2
    let elements = 64<rt> / eSize
    let dblESz = eSize * 2
    let struct (dstB, dstA) = transOpr128 ins bld o1
    let src = transSIMDOprVPart bld eSize part o2
    let amt = tmpVar bld dblESz
    direct amt := numI64 (shiftAmountOf o3) dblESz
    let result = Array.init elements (fun _ -> tmpVar bld dblESz)
    Array.map (fun e -> AST.zext dblESz e << amt) src
    |> Array.iter2 (fun r e -> append bld { direct r := e }) result
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  }

let shiftSLeftLong (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems o2
    let elements = 64<rt> / eSize
    let dblESz = eSize * 2
    let struct (dstB, dstA) = transOpr128 ins bld o1
    let src = transSIMDOprVPart bld eSize part o2
    let amt = tmpVar bld dblESz
    direct amt := transOpr ins bld o3 |> AST.xtlo dblESz
    let result = Array.init elements (fun _ -> tmpVar bld dblESz)
    Array.map (fun e -> AST.sext dblESz e << amt) src
    |> Array.iter2 (fun r e -> append bld { direct r := e }) result
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  }

/// One element of an unsigned rounding shift left. A negative amount shifts
/// the other way, and rounds by adding half a place before it does; shifting
/// right by more than the element is wide leaves nothing. At sixty-four bits
/// that rounded sum can carry out of the element, so the bit it lost is put
/// back at the top before the shift.
let private urshlElem bld eSize bounds e1 e2 =
  let n0, n1 = bounds
  let struct (rndCst, shf, elem, res) = tmpVars4 bld 64<rt>
  let cond = tmpVar bld 1<rt>
  append bld {
    direct shf := AST.xtlo 8<rt> e2 |> AST.sext 64<rt>
    direct cond := shf ?< n0
    direct rndCst := AST.ite cond (n1 << (AST.neg shf .- n1)) n0
    direct elem := AST.zext 64<rt> e1 .+ rndCst
  }
  let isOver = AST.neg shf .> numI32 (int eSize) 64<rt>
  if eSize = 64<rt> then
    let isCarry = e1 .> elem
    let cElem = tmpVar bld 64<rt>
    append bld {
      direct cElem := (elem >> n1) .| numU64 0x8000000000000000UL 64<rt>
      direct res := AST.ite cond
             (AST.ite isOver
               n0
               (AST.ite isCarry
                 (cElem >> (AST.neg shf .- n1))
                 (elem >> AST.neg shf)))
                 (elem << shf)
    }
  else
    append bld {
      direct res := AST.ite cond
                     (AST.ite isOver n0 (elem >> AST.neg shf))
                     (elem << shf)
    }
  AST.xtlo eSize res

let urshl (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src, shift) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
    let struct (n0, n1) = tmpVars2 bld 64<rt>
    direct n0 := AST.num0 64<rt>
    direct n1 := AST.num1 64<rt>
    let shiftRndLeft e1 e2 = urshlElem bld eSize (n0, n1) e1 e2
    match ins.Operands with
    | ThreeOperands(OprSIMD(ScalarReg _), _, _) ->
      let src = transOpr ins bld src
      let shift = transOpr ins bld shift
      let result = shiftRndLeft src shift
      dstAssignScalar ins bld dst result eSize
    | _ ->
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src = transSIMDOprToExpr bld eSize dataSize elements src
      let shift = transSIMDOprToExpr bld eSize dataSize elements shift
      let result = Array.map2 shiftRndLeft src shift
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let srshl (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src, shift) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
    let struct (n0, n1) = tmpVars2 bld eSize
    direct n0 := AST.num0 eSize
    direct n1 := AST.num1 eSize
    let inline shiftRndLeft e1 e2 =
      let struct (rndCst, shf, elem) = tmpVars3 bld eSize
      let struct (cond, signBit) = tmpVars2 bld 1<rt>
      append bld {
        direct shf := AST.xtlo 8<rt> e2 |> AST.sext eSize
        direct signBit := AST.xthi 1<rt> e1
        direct cond := shf ?< n0
        direct rndCst := AST.ite cond (n1 << (AST.neg shf .- n1)) n0
        direct elem := e1 .+ rndCst
      }
      let isOver = AST.neg shf .> numI32 (int eSize) eSize
      AST.ite cond (AST.ite isOver n0 (AST.ite signBit
                     (elem ?>> AST.neg shf)
                     (elem >> AST.neg shf))) (elem << shf)
    match ins.Operands with
    | ThreeOperands(OprSIMD(ScalarReg _), _, _) ->
      let src = transOpr ins bld src
      let shift = transOpr ins bld shift
      let result = shiftRndLeft src shift
      dstAssignScalar ins bld dst result eSize
    | _ ->
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src = transSIMDOprToExpr bld eSize dataSize elements src
      let shift = transSIMDOprToExpr bld eSize dataSize elements shift
      let result = Array.map2 shiftRndLeft src shift
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

/// <summary>
/// The rounding halving add, in both signednesses.
///
/// The element is widened before the sum, because what is wanted is bits
/// esize:1 of a value that has esize+1 of them; the widening is the one the
/// mnemonic names, so that the signed form brings a sign down into the
/// element rather than a zero. There is no sixty-four bit element form of
/// this instruction, so widening to sixty-four is always enough.
/// </summary>
let rhadd ins bld unsigned =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let struct (dstB, dstA) = transOpr128 ins bld o1
    let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
    let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
    let ext = if unsigned then AST.zext else AST.sext
    let inline roundAdd e1 e2 =
      let e1 = ext 64<rt> e1
      let e2 = ext 64<rt> e2
      (e1 .+ e2 .+ AST.num1 64<rt>) >> AST.num1 64<rt>
      |> AST.xtlo eSize
    let result = Array.map2 roundAdd src1 src2
    dstAssignForSIMD dstA dstB result dataSize elements bld
  }

/// <summary>
/// The halving add and subtract, in both signednesses: bits esize:1 of a sum
/// or difference that has one more bit than the element does.
///
/// The rounding form above adds one before the shift; these two truncate.
/// </summary>
let hsub ins bld unsigned isSub =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let struct (dstB, dstA) = transOpr128 ins bld o1
    let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
    let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
    let ext = if unsigned then AST.zext else AST.sext
    let inline halve e1 e2 =
      let e1 = ext 64<rt> e1
      let e2 = ext 64<rt> e2
      (if isSub then e1 .- e2 else e1 .+ e2) >> AST.num1 64<rt>
      |> AST.xtlo eSize
    let result = Array.map2 halve src1 src2
    dstAssignForSIMD dstA dstB result dataSize elements bld
  }

/// <summary>
/// The absolute difference of each pair of elements, and the form that
/// accumulates it into the destination.
///
/// The magnitude is taken by choosing which way round to subtract, which is
/// exact at the element's own width: the larger minus the smaller never goes
/// out of range, where a subtraction the other way round would wrap and an
/// absolute value taken afterwards would keep the wrap.
/// </summary>
let absDiff ins bld unsigned accumulate =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let struct (dstB, dstA) = transOpr128 ins bld o1
    let dst = transSIMDOprToExpr bld eSize dataSize elements o1
    let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
    let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
    let ge = if unsigned then (.>=) else (?>=)
    let diff e1 e2 = AST.ite (ge e1 e2) (e1 .- e2) (e2 .- e1)
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    Array.iteri (fun i r ->
      let d = diff src1[i] src2[i]
      append bld {
        direct r := if accumulate then dst[i] .+ d else d
      }) result
    dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let shiftRight ins bld shifter =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    match ins.Operands with
    | ThreeOperands(OprSIMD(ScalarReg _), _, _) ->
      let dst = transOpr ins bld o1
      let src = transOpr ins bld o2
      let shf = transOpr ins bld o3
      dstAssignScalar ins bld o1 (dst .+ shifter src shf) eSize
    | _ ->
      let struct (dstB, dstA) = transOpr128 ins bld o1
      let dst = transSIMDOprToExpr bld eSize dataSize elements o1
      let src = transSIMDOprToExpr bld eSize dataSize elements o2
      let shf = transOpr ins bld o3 |> AST.xtlo eSize
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      Array.map2 (fun e1 e2 -> e1 .+ (shifter e2 shf)) dst src
      |> Array.iter2 (fun e1 e2 -> append bld { direct e1 := e2 }) result
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let ssubl (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems src1
    let dataSize = 64<rt>
    let elements = dataSize / eSize
    let dblESz = eSize * 2
    let struct (dstB, dstA) = transOpr128 ins bld dst
    let opr1 = transSIMDOprVPart bld eSize part src1
    let opr2 = transSIMDOprVPart bld eSize part src2
    let result = Array.init elements (fun _ -> tmpVar bld dblESz)
    Array.map2 (fun e1 e2 -> AST.sext dblESz e1 .- AST.sext dblESz e2) opr1 opr2
    |> Array.iter2 (fun r e -> append bld { direct r := e }) result
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  }

let ssubw (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems o3
    let elements = 64<rt> / eSize
    let dblESz = eSize * 2
    let struct (dstB, dstA) = transOpr128 ins bld o1
    let opr1 = transSIMDOprToExpr bld dblESz 128<rt> elements o2
    let opr2 = transSIMDOprVPart bld eSize part o3
    let result = Array.init elements (fun _ -> tmpVar bld dblESz)
    Array.map2 (fun e1 e2 -> AST.sext dblESz e1 .- AST.sext dblESz e2) opr1 opr2
    |> Array.iter2 (fun r e -> append bld { direct r := e }) result
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  }

let ushl ins bld =
  lift bld ins {
    let struct (dst, o1, o2) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let inline shiftLeft e1 e2 = shiftByRegister bld eSize true e1 e2
    match ins.Operands with
    | ThreeOperands(OprSIMD(ScalarReg _), _, _) ->
      let src1 = transOpr ins bld o1
      let src2 = transOpr ins bld o2
      let result = shiftLeft src1 src2
      dstAssignScalar ins bld dst result eSize
    | _ ->
      let struct (dstB, dstA) = transOpr128 ins bld dst
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o1
      let src2 = transSIMDOprToExpr bld eSize dataSize elements o2
      let result = Array.map2 shiftLeft src1 src2
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let usubl (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems o2
    let elements = 64<rt> / eSize
    let dblESz = eSize * 2
    let struct (dstB, dstA) = transOpr128 ins bld o1
    let src1 = transSIMDOprVPart bld eSize part o2
    let src2 = transSIMDOprVPart bld eSize part o3
    let result = Array.init elements (fun _ -> tmpVar bld dblESz)
    Array.iteri (fun i r ->
      append bld {
        direct r := AST.zext dblESz src1[i] .- AST.zext dblESz src2[i]
      }) result
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  }

let usubw (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems o3
    let elements = 64<rt> / eSize
    let dblESz = eSize * 2
    let struct (dstB, dstA) = transOpr128 ins bld o1
    let src1 = transSIMDOprToExpr bld dblESz 128<rt> elements o2
    let src2 = transSIMDOprVPart bld eSize part o3
    let result = Array.init elements (fun _ -> tmpVar bld dblESz)
    Array.iteri (fun i r ->
      append bld {
        direct r := AST.zext dblESz src1[i] .- AST.zext dblESz src2[i]
      }) result
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  }

let uzp ins bld op =
  lift bld ins {
    let struct (dst, src1, srcH) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (dstB, dstA) = transOpr128 ins bld dst
    let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
    let srcH = transSIMDOprToExpr bld eSize dataSize elements srcH
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    Array.append src1 srcH
    |> Array.mapi (fun i x -> (i, x))
    |> Array.filter (fun (i, _) -> i % 2 = op)
    |> Array.map snd
    |> Array.iter2 (fun e1 e2 -> append bld { direct e1 := e2 }) result
    dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let xtn (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
    let struct (dstB, dstA) = transOpr128 ins bld dst
    let src = transSIMDOprToExpr bld eSize dataSize elements src
              |> Array.map (AST.xtlo (eSize / 2))
    direct dstA := AST.revConcat src
    direct dstB := AST.num0 64<rt>
  }

let xtn2 (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
    let struct (dstB, dstA) = transOpr128 ins bld dst
    let src = transSIMDOprToExpr bld eSize dataSize elements src
              |> Array.map (AST.xtlo (eSize / 2))
    direct dstA := dstA
    direct dstB := AST.revConcat src
  }

/// SHRN/SHRN2: shift each wide source element right by the immediate and narrow
/// it to the lower half width. SHRN writes the low 64-bit destination half (and
/// zeroes the high half); SHRN2 writes the high half, preserving the low one.
/// RSHRN/RSHRN2 first add half of what the shift is about to discard, which is
/// a one in the bit below the ones that are kept.
let shrn (ins: Instruction) bld isPart2 isRound =
  lift bld ins {
    let struct (dst, src, amt) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
    let struct (dstB, dstA) = transOpr128 ins bld dst
    let amt = transOpr ins bld amt |> AST.xtlo eSize
    let rnd = AST.num1 eSize << (amt .- AST.num1 eSize)
    let narrow e =
      AST.xtlo (eSize / 2) ((if isRound then e .+ rnd else e) >> amt)
    let src = transSIMDOprToExpr bld eSize dataSize elements src
              |> Array.map narrow
    if isPart2 then
      direct dstB := AST.revConcat src
    else
      direct dstA := AST.revConcat src
      direct dstB := AST.num0 64<rt>
  }

/// ADDHN/SUBHN (and their *2 forms): add or subtract two wide vectors and keep
/// the high half of each result element, narrowing to half the width. The base
/// form writes the low destination half (zeroing the high half); the *2 form
/// writes the high half, preserving the low one.
/// RADDHN/RSUBHN first add half of what is about to be discarded, which is a
/// one in the top bit of the part being thrown away; the addition is done at
/// the wide width, where it cannot carry out of the answer.
let addSubHN (ins: Instruction) bld isPart2 isRound op =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems src1
    let struct (dstB, dstA) = transOpr128 ins bld dst
    let s1 = transSIMDOprToExpr bld eSize dataSize elements src1
    let s2 = transSIMDOprToExpr bld eSize dataSize elements src2
    let half = RegType.toBitWidth (eSize / 2)
    let shf = numI32 half eSize
    let rnd = AST.num1 eSize << numI32 (half - 1) eSize
    let rounded v = if isRound then v .+ rnd else v
    let narrow v = AST.xtlo (eSize / 2) (rounded v >> shf)
    let result = Array.map2 (fun a b -> narrow (op a b)) s1 s2
    if isPart2 then
      direct dstB := AST.revConcat result
    else
      direct dstA := AST.revConcat result
      direct dstB := AST.num0 64<rt>
  }

let zip ins bld isPart1 =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (dstB, dstA) = transOpr128 ins bld dst
    let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
    let src2 = transSIMDOprToExpr bld eSize dataSize elements src2
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    let half = elements / 2
    let src1 =
      if isPart1 then Array.sub src1 0 half else Array.sub src1 half half
    let src2 =
      if isPart1 then Array.sub src2 0 half else Array.sub src2 half half
    Array.map2 (fun e1 e2 -> [| e1; e2 |]) src1 src2 |> Array.concat
    |> Array.iter2 (fun e1 e2 -> append bld { direct e1 := e2 }) result
    dstAssignForSIMD dstA dstB result dataSize elements bld
  }

/// The logical shift left(or right) is the alias of LS{L|R}V and UBFM.
/// Therefore, it is necessary to distribute to the original instruction.
let distLogicalLeftShift (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(_, _, OprImm _) -> logShift ins bld (<<)
  | ThreeOperands(_, _, OprRegister _) -> lslv ins bld
  | _ -> raise InvalidOperandException

let distLogicalRightShift (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(_, _, OprImm _) -> logShift ins bld (>>)
  | ThreeOperands(_, _, OprRegister _) -> lsrv ins bld
  | _ -> raise InvalidOperandException
