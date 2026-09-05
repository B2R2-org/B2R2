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

let private fpType bld cast eSize element =
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
  let castElem = AST.cast cast eSize element
  append bld {
    direct res := AST.ite (isZero eSize element) (fpZero element eSize) castElem
    AST.lmark lblEnd
  }
  res

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

let private fixedToFp bld oprSz fbits unsigned src =
  let divBits =
    AST.cast CastKind.UIntToFloat oprSz (numU64 0x1uL oprSz << fbits)
  let intOperand, num0 =
    if unsigned then
      let float0 = AST.cast CastKind.UIntToFloat oprSz (AST.num0 oprSz)
      AST.cast CastKind.UIntToFloat oprSz src, float0
    else
      let float0 = AST.cast CastKind.SIntToFloat oprSz (AST.num0 oprSz)
      AST.cast CastKind.SIntToFloat oprSz src, float0
  let realOperand = fpDiv bld oprSz intOperand divBits
  let cond = AST.eq realOperand num0
  AST.ite cond (AST.num0 oprSz) realOperand

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

let abs (ins: Instruction) insLen bld =
  lift bld ins insLen {
    match ins.Operands with
    | TwoOperands(OprSIMD(VecReg _) as o1, o2) ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld o1
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems o2
      let n0 = AST.num0 eSize
      let src = transSIMDOprToExpr bld eSize dataSize elements o2
      let result = Array.map (fun e -> AST.ite (e ?> n0) e (AST.neg e)) src
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | TwoOperands(OprSIMD(ScalarReg _) as o1, o2) ->
      let struct (eSize, _, _) = getElemDataSzAndElems o1
      let src = transOprToExpr ins bld o2
      let n0 = AST.num0 eSize
      let result = AST.ite (src ?> n0) src (AST.neg src)
      dstAssignScalar ins bld o1 result eSize
    | _ ->
      let struct (dst, src) = getTwoOprs ins
      let n0 = AST.num0 ins.OprSize
      let dst = transOprToExpr ins bld dst
      let src = transOprToExpr ins bld src
      let result = AST.ite (src ?> n0) src (AST.neg src)
      sized ins.OprSize dst := result
  }

let add (ins: Instruction) insLen bld =
  lift bld ins insLen {
    match ins.Operands with
    | ThreeOperands(OprSIMD(VecReg _) as o1, o2, o3) ->
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
      let struct (dstB, dstA) = transOprToExpr128 ins bld o1
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

let addp (ins: Instruction) insLen bld =
  lift bld ins insLen {
    match ins.Operands with
    | TwoOperands(dst, src) -> (* Scalar *)
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
      let src = transSIMDOprToExpr bld eSize dataSize elements src
      let result = Array.reduce (.+) src
      dstAssignScalar ins bld dst result eSize
    | ThreeOperands(dst, src1, src2) -> (* Vector *)
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
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

let addv (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
    let src = transSIMDOprToExpr bld eSize dataSize elements src
    let result = Array.reduce (.+) src
    dstAssignScalar ins bld dst result eSize
  }

let logAnd (ins: Instruction) insLen bld = (* AND *)
  lift bld ins insLen {
    match ins.Operands with
    | ThreeOperands(OprSIMD(VecReg _) as dst, src1, src2) ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
      let struct (src1B, src1A) = transOprToExpr128 ins bld src1
      let struct (src2B, src2A) = transOprToExpr128 ins bld src2
      direct dstA := src1A .& src2A
      if ins.OprSize = 64<rt> then
        append bld { direct dstB := AST.num0 ins.OprSize }
      else
        append bld { direct dstB := src1B .& src2B }
    | _ ->
      let dst, src1, src2 = transOprToExprOfAND ins bld
      sized ins.OprSize dst := src1 .& src2
  }

let bic (ins: Instruction) insLen bld =
  lift bld ins insLen {
    match ins.Operands with
    | ThreeOperands(OprSIMD(VecReg _), OprSIMD(VecReg _), _) ->
      let struct (dst, src1, src2) = getThreeOprs ins
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
      let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
      let src2 = transSIMDOprToExpr bld eSize dataSize elements src2
      let result = Array.map2 (fun s1 s2 -> s1 .& AST.not s2) src1 src2
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | ThreeOperands(OprSIMD(VecReg _), OprImm _, OprShift _) ->
      let struct (dst, src, amount) = getThreeOprs ins
      let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
      let imm =
        transBarrelShiftToExpr ins.OprSize bld src amount
        |> advSIMDExpandImm bld eSize |> AST.not
      dstAssign128 ins bld dst (dstA .& imm) (dstB .& imm) dataSize
    | TwoOperands(OprSIMD(VecReg _), OprImm _) ->
      let struct (dst, src) = getTwoOprs ins
      let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
      let src = transOprToExpr ins bld src
      let imm = advSIMDExpandImm bld eSize src |> AST.not
      dstAssign128 ins bld dst (dstA .& imm) (dstB .& imm) dataSize
    | _ ->
      let dst, src1, src2 = transFourOprsWithBarrelShift ins bld
      sized ins.OprSize dst := src1 .& AST.not src2
  }

let private bitInsert (ins: Instruction) insLen bld isTrue =
  lift bld ins insLen {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOprToExpr128 ins bld dst
    let struct (src1B, src1A) = transOprToExpr128 ins bld src1
    let struct (src2B, src2A) = transOprToExpr128 ins bld src2
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

let bif ins insLen bld = bitInsert ins insLen bld false

let bit ins insLen bld = bitInsert ins insLen bld true

let bsl (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOprToExpr128 ins bld dst
    let struct (src1B, src1A) = transOprToExpr128 ins bld src1
    let struct (src2B, src2A) = transOprToExpr128 ins bld src2
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

let cls (ins: Instruction) insLen bld =
  lift bld ins insLen {
    match ins.Operands with
    | TwoOperands(OprSIMD(VecReg _) as o1, o2) ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld o1
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems o2
      let src = transSIMDOprToExpr bld eSize dataSize elements o2
      let result = Array.map (fun e -> clsBits e eSize bld) src
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      let dst, src = transTwoOprs ins bld
      let result = clsBits src ins.OprSize bld
      sized ins.OprSize dst := result
  }

let clz (ins: Instruction) insLen bld =
  lift bld ins insLen {
    match ins.Operands with
    | TwoOperands(OprSIMD(VecReg _) as o1, o2) ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld o1
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems o2
      let src = transSIMDOprToExpr bld eSize dataSize elements o2
      let result = Array.map (fun e -> clzBits e (int eSize) eSize bld) src
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      let dst, src = transTwoOprs ins bld
      let result = clzBits src (int ins.OprSize) ins.OprSize bld
      sized ins.OprSize dst := result
  }

let private compare (ins: Instruction) insLen bld cond =
  lift bld ins insLen {
    match ins.Operands with
    (* zero *)
    | ThreeOperands(OprSIMD(VecReg _) as o1, o2, OprImm _) ->
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
      let struct (dstB, dstA) = transOprToExpr128 ins bld o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let struct (ones, zeros) = tmpVars2 bld eSize
      direct ones := numI64 -1L eSize
      direct zeros := AST.num0 eSize
      let result = Array.map (fun e -> AST.ite (cond e zeros) ones zeros) src1
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | ThreeOperands(OprSIMD(ScalarReg _) as o1, o2, OprImm _) ->
      let struct (eSize, _, _) = getElemDataSzAndElems o1
      let src1 = transOprToExpr ins bld o2
      let num0 = AST.num0 64<rt>
      let result = tmpVar bld 64<rt>
      direct result := AST.ite (cond src1 num0) (numI64 -1L 64<rt>) num0
      dstAssignScalar ins bld o1 result eSize
    (* register *)
    | ThreeOperands(OprSIMD(VecReg _) as o1, o2, o3) ->
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
      let struct (dstB, dstA) = transOprToExpr128 ins bld o1
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
      let src1 = transOprToExpr ins bld o2
      let src2 = transOprToExpr ins bld o3
      let num0 = AST.num0 64<rt>
      let result = tmpVar bld 64<rt>
      direct result := AST.ite (cond src1 src2) (numI64 -1L 64<rt>) num0
      dstAssignScalar ins bld o1 result eSize
    | _ ->
      raise InvalidOperandException
  }

let cmeq ins insLen bld = compare ins insLen bld (==)

let cmgt ins insLen bld = compare ins insLen bld (?>)

let cmge ins insLen bld = compare ins insLen bld (?>=)

let private cmpHigher (ins: Instruction) insLen bld cond =
  lift bld ins insLen {
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
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
      let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
      let src2 = transSIMDOprToExpr bld eSize dataSize elements src2
      let result =
        Array.map2 (fun e1 e2 -> AST.ite (cond e1 e2) ones zeros) src1 src2
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let cmhi ins insLen bld = cmpHigher ins insLen bld (.>)

let cmhs ins insLen bld = cmpHigher ins insLen bld (.>=)

let cmlt (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src1, _) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (ones, zeros) = tmpVars2 bld eSize
    direct ones := numI64 -1L eSize
    direct zeros := AST.num0 eSize
    match dst with
    | OprSIMD(ScalarReg _) ->
      let src1 = transOprToExpr ins bld src1
      let result = AST.ite (src1 ?< zeros) ones zeros
      dstAssignScalar ins bld dst result eSize
    | _ ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
      let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
      let result = Array.map (fun e -> AST.ite (e ?< zeros) ones zeros) src1
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let cmtst (ins: Instruction) insLen bld =
  lift bld ins insLen {
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
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
      let s1 = transSIMDOprToExpr bld eSize dataSize elements src1
      let s2 = transSIMDOprToExpr bld eSize dataSize elements src2
      let result =
        Array.map2 (fun e1 e2 -> AST.ite ((e1 .& e2) != zeros) ones zeros) s1 s2
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let cnt (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (dstB, dstA) = transOprToExpr128 ins bld dst
    let src = transSIMDOprToExpr bld eSize dataSize elements src
    let result = Array.map (bitCount eSize) src
    dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let dup ins insLen bld =
  lift bld ins insLen {
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (dstB, dstA) = transOprToExpr128 ins bld dst
    let src = transOprToExpr ins bld src
    let element = tmpVar bld eSize
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    direct element := AST.xtlo eSize src
    Array.iter (fun e -> append bld { direct e := element }) result
    dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let eor (ins: Instruction) insLen bld =
  lift bld ins insLen {
    match ins.Operands with
    | ThreeOperands(OprSIMD(VecReg _) as o1, o2, o3) ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld o1
      let struct (src1B, src1A) = transOprToExpr128 ins bld o2
      let struct (src2B, src2A) = transOprToExpr128 ins bld o3
      let struct (opr2, opr3) = tmpVars2 bld 64<rt>
      direct opr2 := AST.num0 64<rt>
      direct opr3 := numI64 -1L 64<rt>
      direct dstA := src2A <+> ((opr2 <+> src1A) .& opr3)
      if ins.OprSize = 64<rt> then
        append bld { direct dstB := AST.num0 ins.OprSize }
      else
        append bld { direct dstB := src2B <+> ((opr2 <+> src1B) .& opr3) }
    | _ ->
      let dst, src1, src2 = transOprToExprOfEOR ins bld
      sized ins.OprSize dst := src1 <+> src2
  }

let ext (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src1, src2, idx) = getFourOprs ins
    let pos = getImmValue idx |> int
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (dstB, dstA) = transOprToExpr128 ins bld dst
    let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
    let src2 = transSIMDOprToExpr bld eSize dataSize elements src2
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    let concat = Array.append src1 src2
    let res = Array.sub concat pos (dataSize / eSize)
    Array.iter2 (fun res s -> append bld { direct res := s }) result res
    dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let extr ins insLen bld =
  lift bld ins insLen {
    let dst, src1, src2, lsb = transOprToExprOfEXTR ins bld
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

let fabd (ins: Instruction) insLen bld =
  lift bld ins insLen {
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
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
      let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
      let src2 = transSIMDOprToExpr bld eSize dataSize elements src2
      let result = Array.map2 (fpAbsDiff) src1 src2
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      raise InvalidOperandException
  }

let fabs (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let n1 = tmpVar bld eSize
    direct n1 := AST.num1 eSize
    match dst with
    | OprSIMD(ScalarReg _) ->
      let src = transOprToExpr ins bld src
      dstAssignScalar ins bld dst ((src << n1) >> n1) eSize
    | OprSIMD(VecReg _) ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
      let src = transSIMDOprToExpr bld eSize dataSize elements src
      let result = Array.map (fun e -> (e << n1) >> n1) src
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      raise InvalidOperandException
  }

let fadd (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    match dst with
    | OprSIMD(ScalarReg _) ->
      let _, src1, src2 = transThreeOprs ins bld
      let result = fpAdd bld dataSize src1 src2
      dstAssignScalar ins bld dst result eSize
    | OprSIMD(VecReg _) ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
      let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
      let src2 = transSIMDOprToExpr bld eSize dataSize elements src2
      let result = Array.map2 (fpAdd bld eSize) src1 src2
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      raise InvalidOperandException
  }

let faddp (ins: Instruction) insLen bld =
  lift bld ins insLen {
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
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
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

let fcmgt (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (ones, zeros) = tmpVars2 bld eSize
    let chkNan e1 e2 = (isNaN eSize e1) .| (isNaN eSize e2)
    let fpgt e1 e2 = AST.fgt (checkZero bld eSize e1) (checkZero bld eSize e2)
    direct ones := numI64 -1L eSize
    direct zeros := AST.num0 eSize
    match dst, src2 with
    | OprSIMD(ScalarReg _) as o1, _ ->
      let _, src1, src2 = transThreeOprs ins bld
      let cond = chkNan src1 src2
      let result = AST.ite cond zeros (AST.ite (fpgt src1 src2) ones zeros)
      dstAssignScalar ins bld o1 result eSize
    | OprSIMD(VecReg _), OprFPImm _ ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
      let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
      let src2 = transOprToExpr ins bld src2 |> AST.xtlo eSize
      let result =
        Array.map (fun e ->
          AST.ite (chkNan e src2) zeros (AST.ite (fpgt e src2) ones zeros)) src1
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | OprSIMD(VecReg _), _ ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
      let s1 = transSIMDOprToExpr bld eSize dataSize elements src1
      let s2 = transSIMDOprToExpr bld eSize dataSize elements src2
      let result =
        Array.map2 (fun e1 e2 ->
          AST.ite (chkNan e1 e2) zeros (AST.ite (fpgt e1 e2) ones zeros)) s1 s2
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      raise InvalidOperandException
  }

let fcsel ins insLen bld =
  lift bld ins insLen {
    let o1, s1, s2, cond = transOprToExprOfFCSEL ins bld
    let struct (eSize, _, _) = getElemDataSzAndElems o1
    let fs1 = AST.cast CastKind.FloatCast ins.OprSize s1
    let fs2 = AST.cast CastKind.FloatCast ins.OprSize s2
    let result = AST.ite (conditionHolds bld cond) fs1 fs2
    dstAssignScalar ins bld o1 result eSize
  }

let fcvt (ins: Instruction) insLen bld =
  lift bld ins insLen {
    match ins.Operands with
    | TwoOperands(OprSIMD(ScalarReg _) as o1, o2) ->
      let struct (eSize, _, _) = getElemDataSzAndElems o1
      let src = transOprToExpr ins bld o2
      let result = AST.cast CastKind.FloatCast eSize src
      dstAssignScalar ins bld o1 result eSize
    | _ ->
      let dst, src = transTwoOprs ins bld
      let oprSize = ins.OprSize
      sized oprSize dst := AST.cast CastKind.FloatCast oprSize src
  }

/// Converts every lane of a vector operand to a fixed-point value, leaving
/// zero where an unsigned destination would take a negative one.
let private fpConvertVec ins bld o1 o2 fbits isUnsigned round =
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
  let struct (dstB, dstA) = transOprToExpr128 ins bld o1
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

let private fpConvert (ins: Instruction) insLen bld isUnsigned round =
  lift bld ins insLen {
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
      let src = transOprToExpr ins bld o2
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

let fcvtas ins insLen bld =
  fpConvert ins insLen bld false FPRounding_TIEAWAY

let fcvtau ins insLen bld =
  fpConvert ins insLen bld true FPRounding_TIEAWAY

let fcvtms ins insLen bld =
  fpConvert ins insLen bld false FPRounding_NEGINF

let fcvtmu ins insLen bld =
  fpConvert ins insLen bld true FPRounding_NEGINF

let fcvtps ins insLen bld =
  fpConvert ins insLen bld false FPRounding_POSINF

let fcvtpu ins insLen bld =
  fpConvert ins insLen bld true FPRounding_POSINF

let fcvtzs ins insLen bld =
  fpConvert ins insLen bld false FPRounding_Zero

let fcvtzu ins insLen bld =
  fpConvert ins insLen bld true FPRounding_Zero

let fdiv (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    match dst with
    | OprSIMD(ScalarReg _) ->
      let _, src1, src2 = transThreeOprs ins bld
      let result = fpDiv bld dataSize src1 src2
      dstAssignScalar ins bld dst result eSize
    | OprSIMD(VecReg _) ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
      let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
      let src2 = transSIMDOprToExpr bld eSize dataSize elements src2
      let result = Array.map2 (fpDiv bld eSize) src1 src2
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      raise InvalidOperandException
  }

let fmadd (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, _, _, _) = getFourOprs ins
    let struct (eSize, _, _) = getElemDataSzAndElems dst
    let _, src1, src2, src3 = transFourOprs ins bld
    let result = (fpAdd bld eSize src3 (fpMul bld eSize src1 src2))
    dstAssignScalar ins bld dst result eSize
  }

let fmaxmin (ins: Instruction) insLen bld fop =
  lift bld ins insLen {
    match ins.Operands with
    | ThreeOperands(OprSIMD(ScalarReg _) as o1, o2, o3) ->
      let struct (eSize, _, _) = getElemDataSzAndElems o1
      let src1 = transOprToExpr ins bld o2
      let src2 = transOprToExpr ins bld o3
      let cond = fop src1 src2
      let result = AST.ite cond src1 src2
      dstAssignScalar ins bld o1 result eSize
    | _ ->
      let struct (o1, o2, o3) = getThreeOprs ins
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
      let struct (dstB, dstA) = transOprToExpr128 ins bld o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      let inline cond e1 e2 =
        let src1 = AST.cast CastKind.FloatCast eSize e1
        let src2 = AST.cast CastKind.FloatCast eSize e2
        AST.ite (fop src1 src2) src1 src2
      Array.iteri2 (fun i e1 e2 ->
        append bld { direct (result[i]) := cond e1 e2 }) src1 src2
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let fmls (ins: Instruction) insLen bld =
  lift bld ins insLen {
    match ins.Operands with
    | ThreeOperands(OprSIMD(ScalarReg _) as o1, o2, o3) ->
      let struct (eSize, _, _) = getElemDataSzAndElems o1
      let dst = transOprToExpr ins bld o1
      let src1 = transOprToExpr ins bld o2
      let src2 = transOprToExpr ins bld o3
      let element1 = fpneg src1 eSize
      let result = fpAdd bld eSize dst (fpMul bld eSize element1 src2)
      dstAssignScalar ins bld o1 result eSize
    | ThreeOperands(o1, o2, (OprSIMD(VecRegWithIdx _) as o3)) ->
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
      let struct (dstB, dstA) = transOprToExpr128 ins bld o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let src2 = transOprToExpr ins bld o3
      let src3 = transSIMDOprToExpr bld eSize dataSize elements o1
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      Array.iteri2 (fun i e1 e3 ->
        let e1 = fpneg e1 eSize
        let res = fpAdd bld eSize e3 (fpMul bld eSize e1 src2)
        append bld { direct (result[i]) := res }) src1 src3
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      let struct (o1, o2, o3) = getThreeOprs ins
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
      let struct (dstB, dstA) = transOprToExpr128 ins bld o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
      let src3 = transSIMDOprToExpr bld eSize dataSize elements o1
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      Array.map3 (fun e1 e2 e3 ->
        let e1 = fpneg e1 eSize
        fpAdd bld eSize e3 (fpMul bld eSize e1 e2)) src1 src2 src3
      |> Array.iter2 (fun r e -> append bld { direct r := e }) result
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let fmov (ins: Instruction) insLen bld =
  lift bld ins insLen {
    match ins.Operands with
    | TwoOperands(OprRegister _, OprSIMD(VecRegWithIdx _)) ->
      let struct (dst, src) = getTwoOprs ins
      let dst = transOprToExpr ins bld dst
      let struct (srcB, _) = transOprToExpr128 ins bld src
      sized ins.OprSize dst := srcB
    | TwoOperands(OprSIMD(VecRegWithIdx _), OprRegister _) ->
      let struct (dst, src) = getTwoOprs ins
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
      let src = transOprToExpr ins bld src
      direct dstA := dstA
      direct dstB := src
    | TwoOperands(OprSIMD(VecReg _), OprFPImm _) ->
      let struct (dst, src) = getTwoOprs ins
      let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
      let src =
        if eSize <> 64<rt> then
          transOprToExprFPImm ins eSize src |> advSIMDExpandImm bld eSize
        else
          transOprToExprFPImm ins eSize src |> AST.xtlo 64<rt>
      dstAssign128 ins bld dst src src dataSize
    | TwoOperands(OprSIMD(ScalarReg _), _) ->
      let struct (dst, src) = getTwoOprs ins
      let struct (_, dataSize, _) = getElemDataSzAndElems dst
      let src = transOprToExpr ins bld src
      dstAssignScalar ins bld dst src dataSize
    | _ ->
      let dst, src = transTwoOprs ins bld
      sized ins.OprSize dst := src
  }

let fmsub (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, _, _, _) = getFourOprs ins
    let struct (eSize, _, _) = getElemDataSzAndElems dst
    let _, src1, src2, src3 = transFourOprs ins bld
    let result = (fpSub bld eSize src3 (fpMul bld eSize src1 src2))
    dstAssignScalar ins bld dst result eSize
  }

let fmul ins insLen bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = getThreeOprs ins
    match ins.Operands with
    | ThreeOperands(OprSIMD(ScalarReg _) as o1, o2, o3) ->
      let struct (eSize, _, _) = getElemDataSzAndElems o2
      let src1 = transOprToExpr ins bld o2
      let src2 = transOprToExpr ins bld o3
      dstAssignScalar ins bld o1 (fpMul bld eSize src1 src2) eSize
    | ThreeOperands(OprSIMD(VecReg _), _, OprSIMD(VecReg _)) ->
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
      let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
      let src2 = transSIMDOprToExpr bld eSize dataSize elements src2
      let result = Array.map2 (fpMul bld eSize) src1 src2
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems src1
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
      let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
      let src2 = transOprToExpr ins bld src2
      let result = Array.map (fun src -> fpMul bld eSize src src2) src1
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let fneg (ins: Instruction) insLen bld =
  lift bld ins insLen {
    match ins.Operands with
    | TwoOperands(OprSIMD(ScalarReg _) as dst, src) ->
      let struct (eSize, _, _) = getElemDataSzAndElems src
      let src = transOprToExpr ins bld src
      let t = tmpVar bld eSize
      direct t := fpneg src eSize
      dstAssignScalar ins bld dst t ins.OprSize
    | TwoOperands(OprSIMD(VecReg _) as dst, src) ->
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
      let src = transSIMDOprToExpr bld eSize dataSize elements src
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      Array.iter2 (fun dst src ->
        append bld { direct dst := fpneg src eSize }) result src
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      raise InvalidOperandException
  }

let fnmsub (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, _, _, src) = getFourOprs ins
    let _, src1, src2, src3 = transFourOprs ins bld
    let struct (eSize, _, _) = getElemDataSzAndElems src
    let t = tmpVar bld eSize
    direct t := fpneg src3 eSize
    let result = fpAdd bld eSize t (fpMul bld eSize src1 src2)
    dstAssignScalar ins bld dst result ins.OprSize
  }

let fnmul (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, _, src) = getThreeOprs ins
    let _, src1, src2 = transThreeOprs ins bld
    let struct (eSize, _, _) = getElemDataSzAndElems src
    let result = tmpVar bld eSize
    direct result := fpMul bld eSize src1 src2
    direct result := fpneg result eSize
    dstAssignScalar ins bld dst result ins.OprSize
  }

let getIntRoundMode src oprSz bld =
  let fpcr = regVar bld R.FPCR |> AST.xtlo 32<rt>
  let rm = AST.shr (AST.shl fpcr (numI32 8 32<rt>)) (numI32 0x1E 32<rt>)
  AST.ite (rm == numI32 0 32<rt>)
    (AST.cast CastKind.FtoIRound oprSz src) (* 0, RN *)
    (AST.ite (rm == numI32 1 32<rt>)
      (AST.cast CastKind.FtoICeil oprSz src) (* 1, RZ *)
      (AST.ite (rm == numI32 2 32<rt>)
        (AST.cast CastKind.FtoIFloor oprSz src) (* 2, RP *)
        (AST.cast CastKind.FtoITrunc oprSz src))) (* 3, RM *)

let private fpRoundToInt (ins: Instruction) insLen bld cast =
  lift bld ins insLen {
    match ins.Operands with
    | TwoOperands(OprSIMD(ScalarReg _) as dst, src) ->
      let struct (eSize, _, _) = getElemDataSzAndElems dst
      let src = transOprToExpr ins bld src
      let result = fpType bld cast eSize src
      dstAssignScalar ins bld dst result eSize
    | TwoOperands(OprSIMD(VecReg _ ) as dst, src) ->
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
      let src = transSIMDOprToExpr bld eSize dataSize elements src
      let result = Array.map (fpType bld cast eSize) src
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      raise InvalidOperandException
  }

let private fpCurrentRoundToInt (ins: Instruction) insLen bld =
  lift bld ins insLen {
    match ins.Operands with
    | TwoOperands(OprSIMD(ScalarReg _) as dst, src) ->
      let src = transOprToExpr ins bld src
      let result = fpRoundingMode src ins.OprSize bld
      dstAssignScalar ins bld dst result ins.OprSize
    | TwoOperands(OprSIMD(VecReg _ ) as dst, src) ->
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
      let src = transSIMDOprToExpr bld eSize dataSize elements src
      let result = Array.map (fun s -> fpRoundingMode s eSize bld) src
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      raise InvalidOperandException
  }

let private tieawayCast bld eSize src =
  let sign = AST.xthi 1<rt> src
  let trunc = AST.cast CastKind.FtoFTrunc eSize src
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
  let ceil = fpType bld CastKind.FtoFCeil eSize src
  let floor = fpType bld CastKind.FtoFFloor eSize src
  let pRes = AST.ite (AST.fge t comp1) ceil floor
  let nRes = AST.ite (AST.fle t comp2) floor ceil
  append bld {
    direct res := AST.ite sign nRes pRes
  }
  res

let frinta (ins: Instruction) insLen bld =
  lift bld ins insLen {
    match ins.Operands with
    | TwoOperands(OprSIMD(ScalarReg _) as dst, src) ->
      let struct (eSize, _, _) = getElemDataSzAndElems dst
      let src = transOprToExpr ins bld src
      let result = tieawayCast bld eSize src
      dstAssignScalar ins bld dst result eSize
    | TwoOperands(OprSIMD(VecReg _ ) as dst, src) ->
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
      let src = transSIMDOprToExpr bld eSize dataSize elements src
      let result = Array.map (tieawayCast bld eSize) src
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      raise InvalidOperandException
  }

let frinti ins insLen bld = fpCurrentRoundToInt ins insLen bld

let frintm ins insLen bld =
  fpRoundToInt ins insLen bld CastKind.FtoFFloor

let frintn ins insLen bld =
  fpRoundToInt ins insLen bld CastKind.FtoFRound

let frintp ins insLen bld =
  fpRoundToInt ins insLen bld CastKind.FtoFCeil

let frintx ins insLen bld = fpCurrentRoundToInt ins insLen bld

let frintz ins insLen bld =
  fpRoundToInt ins insLen bld CastKind.FtoFTrunc

let fsqrt ins insLen bld =
  lift bld ins insLen {
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    match ins.Operands with
    | TwoOperands(OprSIMD(ScalarReg _), _) ->
      let src = transOprToExpr ins bld src |> AST.fsqrt
      dstAssignScalar ins bld dst src eSize
    | _ ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
      let src = transSIMDOprToExpr bld eSize dataSize elements src
                |> Array.map (AST.fsqrt)
      dstAssignForSIMD dstA dstB src dataSize elements bld
  }

let fsub ins insLen bld =
  lift bld ins insLen {
    let struct (dst, o1, o2) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    match ins.Operands with
    | ThreeOperands(OprSIMD(ScalarReg _), _, _) ->
      let src1 = transOprToExpr ins bld o1
      let src2 = transOprToExpr ins bld o2
      let result = fpSub bld dataSize src1 src2
      dstAssignScalar ins bld dst result eSize
    | _ ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o1
      let src2 = transSIMDOprToExpr bld eSize dataSize elements o2
      let result = Array.map2 (fpSub bld eSize) src1 src2
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let insv (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let struct (eSize, _, _) = getElemDataSzAndElems o1
    let dst = transOprToExpr ins bld o1
    let src = transOprToExpr ins bld o2
    direct dst := AST.xtlo eSize src
  }

let loadStoreList (ins: Instruction) insLen bld isLoad =
  lift bld ins insLen {
    let isWBack, _ = getIsWBackAndIsPostIndex ins.Operands
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, _, elements) = getElemDataSzAndElems dst
    let dstArr = transSIMDListToExpr bld dst
    let bReg, mOffs = transOprToExpr ins bld src |> separateMemExpr
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

let loadRep (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let isWBack, _ = getIsWBackAndIsPostIndex ins.Operands
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, _, elements) = getElemDataSzAndElems dst
    let dstArr = transSIMDListToExpr bld dst
    let bReg, mOffs = transOprToExpr ins bld src |> separateMemExpr
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

let ldnp (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let address = tmpVar bld 64<rt>
    let dByte = numI32 (RegType.toByteWidth ins.OprSize) 64<rt>
    match ins.Operands, ins.OprSize with
    | ThreeOperands(OprSIMD _ as src1, src2, src3), 128<rt> ->
      let struct (src1B, src1A) = transOprToExpr128 ins bld src1
      let struct (src2B, src2A) = transOprToExpr128 ins bld src2
      let bReg, offset = transOprToExpr ins bld src3 |> separateMemExpr
      let n8 = numI32 8 64<rt>
      direct address := bReg
      direct address := address .+ offset
      direct src1A := AST.loadLE 64<rt> address
      direct src1B := AST.loadLE 64<rt> (address .+ n8)
      direct src2A := AST.loadLE 64<rt> (address .+ dByte)
      direct src2B := AST.loadLE 64<rt> (address .+ dByte .+ n8)
    | ThreeOperands(OprSIMD _ as src1, src2, src3), _ ->
      let bReg, offset = transOprToExpr ins bld src3 |> separateMemExpr
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

let ldp (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    let address = tmpVar bld 64<rt>
    let dByte = numI32 (RegType.toByteWidth ins.OprSize) 64<rt>
    match ins.Operands, ins.OprSize with
    | ThreeOperands(OprSIMD _ as src1, src2, src3), 128<rt> ->
      let struct (src1B, src1A) = transOprToExpr128 ins bld src1
      let struct (src2B, src2A) = transOprToExpr128 ins bld src2
      let bReg, offset = transOprToExpr ins bld src3 |> separateMemExpr
      let n8 = numI32 8 64<rt>
      direct address := bReg
      direct address := if isPostIndex then address else address .+ offset
      direct src1A := AST.loadLE 64<rt> address
      direct src1B := AST.loadLE 64<rt> (address .+ n8)
      direct src2A := AST.loadLE 64<rt> (address .+ dByte)
      direct src2B := AST.loadLE 64<rt> (address .+ dByte .+ n8)
      writeBack bld isWBack isPostIndex bReg address offset
    | ThreeOperands(OprSIMD _ as src1, src2, src3), _ ->
      let bReg, offset = transOprToExpr ins bld src3 |> separateMemExpr
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
    let offset = transOprToExpr ins bld (OprMemory(LiteralMode o2))
    let address = tmpVar bld 64<rt>
    match ins.OprSize with
    | 128<rt> ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld o1
      direct address := getPC bld .+ offset
      direct dstA := AST.loadLE 64<rt> address
      direct dstB := AST.loadLE 64<rt> (address .+ (numI32 8 64<rt>))
    | _ ->
      let dst = transOprToExpr ins bld o1
      let data = tmpVar bld ins.OprSize
      direct address := getPC bld .+ offset
      direct data := AST.loadLE ins.OprSize address
      match o1 with
      | OprSIMD(ScalarReg _) ->
        dstAssignScalar ins bld o1 data ins.OprSize
      | _ ->
        sized ins.OprSize dst := data
  }

let ldr (ins: Instruction) insLen bld =
  lift bld ins insLen {
    match ins.Operands with
    | TwoOperands(o1, OprMemory(LiteralMode o2)) -> (* LDR (literal) *)
      ldrLiteral ins bld o1 o2
    | TwoOperands(o1, o2) ->
      let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
      let address = tmpVar bld 64<rt>
      match ins.OprSize with
      | 128<rt> ->
        let struct (dstB, dstA) = transOprToExpr128 ins bld o1
        let bReg, offset = transOprToExpr ins bld o2 |> separateMemExpr
        direct address := bReg
        direct address := if isPostIndex then address else address .+ offset
        direct dstA := AST.loadLE 64<rt> address
        direct dstB := AST.loadLE 64<rt> (address .+ (numI32 8 64<rt>))
        writeBack bld isWBack isPostIndex bReg address offset
      | _ ->
        let dst = transOprToExpr ins bld o1
        let bReg, offset = transOprToExpr ins bld o2 |> separateMemExpr
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

let ldur (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld ins.OprSize
    let struct (o1, o2) = getTwoOprs ins
    match ins.OprSize with
    | 128<rt> ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld o1
      let bReg, offset = transOprToExpr ins bld o2 |> separateMemExpr
      direct address := bReg
      direct address := if isPostIndex then address else address .+ offset
      direct dstA := AST.loadLE 64<rt> address
      direct dstB := AST.loadLE 64<rt> (address .+ (numI32 8 64<rt>))
      writeBack bld isWBack isPostIndex bReg address offset
    | _ ->
      let dst = transOprToExpr ins bld o1
      let bReg, offset = transOprToExpr ins bld o2 |> separateMemExpr
      direct address := bReg
      direct address := if isPostIndex then address else address .+ offset
      direct data := AST.loadLE ins.OprSize address
      match o1 with
      | OprSIMD(ScalarReg _) -> dstAssignScalar ins bld o1 data ins.OprSize
      | _ -> sized ins.OprSize dst := data
      writeBack bld isWBack isPostIndex bReg address offset
  }

let logShift ins insLen bld shift =
  lift bld ins insLen {
    let dst, src, amt = transThreeOprs ins bld
    sized ins.OprSize dst := shift src amt
  }

let maxMin ins insLen bld opFn =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let struct (dstB, dstA) = transOprToExpr128 ins bld o1
    let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
    let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
    let result = Array.map2 (fun s1 s2 -> AST.ite (opFn s1 s2) s1 s2) src1 src2
    dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let maxMinv ins insLen bld opFn =
  lift bld ins insLen {
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

let maxMinp ins insLen bld opFn =
  lift bld ins insLen {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (dstB, dstA) = transOprToExpr128 ins bld dst
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
    let src2 = transSIMDOprToExpr bld eSize dataSize elements src2
    let cal src = Array.chunkBySize 2 src
                  |> Array.map (fun e -> AST.ite (opFn e.[0] e.[1]) e.[0] e.[1])
    let concat = Array.append (cal src1) (cal src2)
    Array.iter2 (fun res s -> append bld { direct res := s }) result concat
    dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let madd (ins: Instruction) insLen bld =
  lift bld ins insLen {
    match ins.Operands with
    | ThreeOperands(_, _, OprSIMD(VecReg _)) ->
      let struct (o1, o2, o3) = getThreeOprs ins
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
      let struct (dstB, dstA) = transOprToExpr128 ins bld o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
      let result = Array.map2 (.*) src1 src2
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | ThreeOperands(OprSIMD _ as o1, o2, o3) ->
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
      let struct (dstB, dstA) = transOprToExpr128 ins bld o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let src2 = transOprToExpr ins bld o3
      let result = Array.map (fun s1 -> s1 .* src2) src1
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      let dst, src1, src2, src3 = transOprToExprOfMADD ins bld
      sized ins.OprSize dst := src3 .+ (src1 .* src2)
  }

let mladdsub (ins: Instruction) insLen bld opFn =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dstB, dstA) = transOprToExpr128 ins bld o1
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
      let src2 = transOprToExpr ins bld o3
      let prod = Array.map (fun s1 -> s1 .* src2) src1
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      let cal = Array.map2 (opFn) dst prod
      Array.iter2 (fun res s -> append bld { direct res := s }) result cal
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let mov (ins: Instruction) insLen bld =
  lift bld ins insLen {
    match ins.Operands with
    | TwoOperands(OprSIMD(VecReg _) as o1, o2) ->
      let struct (_, dataSize, _) = getElemDataSzAndElems o1
      let struct (srcB, srcA) = transOprToExpr128 ins bld o2
      dstAssign128 ins bld o1 srcA srcB dataSize
    | TwoOperands(OprSIMD(ScalarReg _), OprSIMD(VecRegWithIdx _)) ->
      let struct (dst, src) = getTwoOprs ins
      let struct (_, dataSize, _) = getElemDataSzAndElems dst
      let src = transOprToExpr ins bld src
      dstAssignScalar ins bld dst src dataSize
    | _ ->
      let dst, src = transTwoOprs ins bld
      sized ins.OprSize dst := src
  }

let movi (ins: Instruction) insLen bld =
  lift bld ins insLen {
    match ins.Operands with
    | TwoOperands(OprSIMD(ScalarReg _), OprImm _) ->
      let dst, src = transTwoOprs ins bld
      sized ins.OprSize dst := src
    | TwoOperands(OprSIMD(VecReg _), OprImm _) ->
      let struct (dst, src) = getTwoOprs ins
      let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
      let imm = if not (dataSize = 128<rt> && eSize = 64<rt>) then
                  transOprToExpr ins bld src
                  |> advSIMDExpandImm bld eSize
                else
                  transOprToExpr ins bld src |> AST.xtlo 64<rt>
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

let movk (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, imm, shf) = getThreeOprs ins
    let dst = transOprToExpr ins bld dst
    let src = transBarrelShiftToExpr ins.OprSize bld imm shf
    let mask = getWordMask ins shf
    sized ins.OprSize dst := (dst .& mask) .| src
  }

let mrs (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src) = getTwoOprs ins
    match dst, src with
    | OprRegister rt, OprRegister R.CNTVCT_EL0 ->
      (* CNTVCT_EL0 has no stored value to read; leave the 64-bit virtual count
         to the emulator through a ClockCounterRead side effect naming rt. *)
      AST.sideEffect
        (ClockCounterRead(Some(Register.toRegID rt, false)))
    | _ ->
      let dst = transOprToExpr ins bld dst
      let src =
        match src with
        | OprRegister R.NZCV ->
          let n = (regVar bld R.N |> AST.zext 64<rt>) << numI32 31 64<rt>
          let z = (regVar bld R.Z |> AST.zext 64<rt>) << numI32 30 64<rt>
          let c = (regVar bld R.C |> AST.zext 64<rt>) << numI32 29 64<rt>
          let v = (regVar bld R.V |> AST.zext 64<rt>) << numI32 28 64<rt>
          n .| z .| c .| v
        | _ ->
          transOprToExpr ins bld src
      direct dst := src
  }

let mvni (ins: Instruction) insLen bld =
  lift bld ins insLen {
    match ins.Operands with
    | TwoOperands _ ->
      let struct (dst, src) = getTwoOprs ins
      let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
      let imm = transOprToExpr ins bld src
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

let orn (ins: Instruction) insLen bld =
  lift bld ins insLen {
    match ins.Operands with
    | TwoOperands _ ->
      let struct (dst, src) = getTwoOprs ins
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
      let src = transSIMDOprToExpr bld eSize dataSize elements src
      let result = Array.map AST.not src
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | ThreeOperands(OprSIMD(VecReg _) as o1, o2, o3) ->
      let struct (_, dataSize, _) = getElemDataSzAndElems o1
      let struct (src1B, src1A) = transOprToExpr128 ins bld o2
      let struct (src2B, src2A) = transOprToExpr128 ins bld o3
      let resultB = src1B .| (AST.not src2B)
      let resultA = src1A .| (AST.not src2A)
      dstAssign128 ins bld o1 resultA resultB dataSize
    | _ ->
      let dst, src1, src2 = transOprToExprOfORN ins bld
      sized ins.OprSize dst := src1 .| AST.not src2
  }

let orr (ins: Instruction) insLen bld =
  lift bld ins insLen {
    match ins.Operands with
    | TwoOperands(OprSIMD _, OprImm _) ->
      let struct (dst, imm) = getTwoOprs ins
      let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
      let src = transOprToExpr ins bld imm |> advSIMDExpandImm bld eSize
      dstAssign128 ins bld dst (dstA .| src) (dstB .| src) dataSize
    | ThreeOperands(OprSIMD _, OprImm _, _) ->
      let struct (dst, imm, shf) = getThreeOprs ins
      let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
      let src = transBarrelShiftToExpr ins.OprSize bld imm shf
                |> advSIMDExpandImm bld eSize
      dstAssign128 ins bld dst (dstA .| src) (dstB .| src) dataSize
    | ThreeOperands(OprSIMD(VecReg(_, v)) as o1, o2, o3) ->
      let struct (_, dataSize, _) = getElemDataSzAndElems o1
      let struct (src1B, src1A) = transOprToExpr128 ins bld o2
      let struct (src2B, src2A) = transOprToExpr128 ins bld o3
      let resultB = src1B .| src2B
      let resultA = src1A .| src2A
      dstAssign128 ins bld o1 resultA resultB dataSize
    | _ ->
      let dst, src1, src2 = transOprToExprOfORR ins bld
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

let rbit (ins: Instruction) insLen bld =
  lift bld ins insLen {
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
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
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

let rev (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let e = if ins.OprSize = 64<rt> then 7 else 3
    let t = tmpVar bld ins.OprSize
    match ins.Operands with
    | TwoOperands(OprSIMD(VecReg _ ) as dst, src) ->
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
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

let rev16 (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let tmp = tmpVar bld ins.OprSize
    match ins.Operands with
    | TwoOperands(OprSIMD(VecReg _ ) as dst, src) ->
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
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

let rev32 (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let tmp = tmpVar bld ins.OprSize
    match ins.Operands with
    | TwoOperands(OprSIMD(VecReg _ ) as dst, src) ->
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
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

let icvtf (ins: Instruction) insLen bld unsigned =
  lift bld ins insLen {
    let oprSize = ins.OprSize
    match ins.Operands with
    | TwoOperands(OprSIMD(VecReg _), _) ->
      let struct (o1, o2) = getTwoOprs ins
      let struct (dstB, dstA) = transOprToExpr128 ins bld o1
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems o2
      let src = transSIMDOprToExpr bld eSize dataSize elements o2
      let n0 = AST.num0 eSize
      let result = Array.map (fixedToFp bld eSize n0 unsigned) src
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | TwoOperands(OprSIMD(ScalarReg _) as dst, _) ->
      let struct (eSize, _, _) = getElemDataSzAndElems dst
      let _, src = transTwoOprs ins bld
      let n0 = AST.num0 oprSize
      let result = fixedToFp bld oprSize n0 unsigned src
      dstAssignScalar ins bld dst result eSize
    | ThreeOperands(OprSIMD(ScalarReg _), _, _) ->
      let struct (o1, o2, o3) = getThreeOprs ins
      let struct (eSize, _, _) = getElemDataSzAndElems o1
      let src = transOprToExpr ins bld o2
      let fbits = transOprToExpr ins bld o3
      let result = fixedToFp bld eSize fbits unsigned src
      dstAssignScalar ins bld o1 result eSize
    | ThreeOperands(OprSIMD(VecReg _), _, _) ->
      let struct (o1, o2, o3) = getThreeOprs ins
      let struct (dstB, dstA) = transOprToExpr128 ins bld o1
      let struct (eSz, dataSize, elements) = getElemDataSzAndElems o2
      let src = transSIMDOprToExpr bld eSz dataSize elements o2
      let fbits = transOprToExpr ins bld o3 |> AST.xtlo eSz
      let result = Array.map (fixedToFp bld eSz fbits unsigned) src
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      let dst, src, fbits = transThreeOprs ins bld
      let result = fixedToFp bld oprSize fbits unsigned src
      sized oprSize dst := result
  }

let shl ins insLen bld =
  lift bld ins insLen {
    let struct (dst, src, amt) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
    match ins.Operands with
    | ThreeOperands(OprSIMD(ScalarReg _), _, _) ->
      let _, src, amt = transThreeOprs ins bld
      dstAssignScalar ins bld dst (src << amt) eSize
    | _ ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
      let src = transSIMDOprToExpr bld eSize dataSize elements src
      let amt = transOprToExpr ins bld amt |> AST.xtlo eSize
      let result = Array.map (fun e -> e << amt) src
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let smulh ins insLen bld =
  lift bld ins insLen {
    let dst, src1, src2 = transThreeOprs ins bld
    (* The high 64 bits of the signed 64x64->128 product: the evaluator
       holds the 128-bit intermediate, so extract from it directly. *)
    let prod = AST.sext 128<rt> src1 .* AST.sext 128<rt> src2
    direct dst := AST.xthi 64<rt> prod
  }

let smull (ins: Instruction) insLen bld =
  lift bld ins insLen {
    match ins.Operands with
    | ThreeOperands(_, _, OprSIMD(VecRegWithIdx _)) ->
      let struct (o1, o2, o3) = getThreeOprs ins
      let struct (eSize, part, _) = getElemDataSzAndElems o2
      let elements = 64<rt> / eSize
      let dblESz = eSize * 2
      let struct (dstB, dstA) = transOprToExpr128 ins bld o1
      let src1 = transSIMDOprVPart bld eSize part o2
      let src2 = transOprToExpr ins bld o3 |> AST.sext dblESz
      let result = Array.init elements (fun _ -> tmpVar bld dblESz)
      let prod = Array.map (fun s1 -> AST.sext dblESz s1 .* src2) src1
      Array.iter2 (fun r p -> append bld { direct r := p }) result prod
      dstAssignForSIMD dstA dstB result 128<rt> elements bld
    | ThreeOperands(OprSIMD(VecReg _), _, _) ->
      let struct (o1, o2, o3) = getThreeOprs ins
      let struct (eSize, part, _) = getElemDataSzAndElems o2
      let elements = 64<rt> / eSize
      let dblESz = eSize * 2
      let struct (dstB, dstA) = transOprToExpr128 ins bld o1
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

let sshl (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, o1, o2) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let inline shiftLeft e1 e2 =
      let shf = tmpVar bld eSize
      append bld {
        direct shf := AST.xtlo 8<rt> e2 |> AST.sext eSize
      }
      AST.ite (shf ?< AST.num0 eSize) (e1 ?>> AST.neg shf) (e1 << shf)
    match ins.Operands with
    | ThreeOperands(OprSIMD(ScalarReg _), _, _) ->
      let src1 = transOprToExpr ins bld o1
      let src2 = transOprToExpr ins bld o2
      let result = shiftLeft src1 src2
      dstAssignScalar ins bld dst result eSize
    | _ ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o1
      let src2 = transSIMDOprToExpr bld eSize dataSize elements o2
      let result = Array.map2 shiftLeft src1 src2
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let shift ins insLen bld opFn =
  lift bld ins insLen {
    let struct (dst, src, amt) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    match ins.Operands with
    | ThreeOperands(OprSIMD(ScalarReg _), _, _) ->
      let src = transOprToExpr ins bld src
      let amt = transOprToExpr ins bld amt
      dstAssignScalar ins bld dst (opFn src amt) eSize
    | _ ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
      let src = transSIMDOprToExpr bld eSize dataSize elements src
      let amt = transOprToExpr ins bld amt |> AST.xtlo eSize
      let result = Array.map (fun e -> opFn e amt) src
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let stnp (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let address = tmpVar bld 64<rt>
    let dByte = numI32 (RegType.toByteWidth ins.OprSize) 64<rt>
    match ins.OprSize with
    | 128<rt> ->
      let struct (src1, src2, src3) = getThreeOprs ins
      let struct (src1B, src1A) = transOprToExpr128 ins bld src1
      let struct (src2B, src2A) = transOprToExpr128 ins bld src2
      let bReg, offset = transOprToExpr ins bld src3 |> separateMemExpr
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

let stp (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    let address = tmpVar bld 64<rt>
    let dByte = numI32 (RegType.toByteWidth ins.OprSize) 64<rt>
    match ins.OprSize with
    | 128<rt> ->
      let struct (src1, src2, src3) = getThreeOprs ins
      let struct (src1B, src1A) = transOprToExpr128 ins bld src1
      let struct (src2B, src2A) = transOprToExpr128 ins bld src2
      let bReg, offset = transOprToExpr ins bld src3 |> separateMemExpr
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

let str (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    match ins.OprSize with
    | 128<rt> ->
      let struct (src1, src2) = getTwoOprs ins
      let struct (srcB, srcA) = transOprToExpr128 ins bld src1
      let bReg, offset = transOprToExpr ins bld src2 |> separateMemExpr
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

let stur (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld ins.OprSize
    match ins.OprSize with
    | 128<rt> ->
      let struct (src1, src2) = getTwoOprs ins
      let struct (src1B, src1A) = transOprToExpr128 ins bld src1
      let bReg, offset = transOprToExpr ins bld src2 |> separateMemExpr
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

let sub (ins: Instruction) insLen bld =
  lift bld ins insLen {
    match ins.Operands with
    | TwoOperands(OprSIMD(ScalarReg _) as dst, _) ->
      let struct (eSize, _, _) = getElemDataSzAndElems dst
      let _, src = transTwoOprs ins bld
      dstAssignScalar ins bld dst (AST.neg src) eSize
    | TwoOperands(OprSIMD(VecReg _) as o1, o2) ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld o1
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
      let struct (dstB, dstA) = transOprToExpr128 ins bld o1
      let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
      let result = Array.map2 (.-) src1 src2
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | _ ->
      let dst, src1, src2 = transOprToExprOfSUB ins bld
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
      let struct (hi, lo) = transOprToExpr128 ins bld (OprSIMD simd)
      [| lo; hi |]
    )
  | _ ->
    raise InvalidOperandException

let tbl (ins: Instruction) insLen bld = (* FIMXE *)
  lift bld ins insLen {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
    let elements = dataSize / 8<rt>
    let struct (dstB, dstA) = transOprToExpr128 ins bld dst
    let src = tableRegsOf ins bld src1
    let indices = transSIMDOprToExpr bld 8<rt> dataSize elements src2
    let n8 = numI32 8 8<rt>
    let nFF = numI32 -1 8<rt> |> AST.zext 64<rt>
    let zeros = tmpVar bld eSize
    direct zeros := AST.num0 eSize
    let inline elem expr idx =
      let idx = idx .% n8
      ((expr >> (AST.zext 64<rt> (idx .* n8))) .& nFF) |> AST.xtlo 8<rt>
    let lenExpr = tmpVar bld 8<rt>
    let len = Array.length src
    direct lenExpr := numI32 (len / 2 * 16) 8<rt>
    let inline limit i expr index =
      let dst =
        if i < 8 then (dstA >> (numI32 (i * 8) 64<rt>)) .& nFF
        else (dstB >> (numI32 (i * 8) 64<rt>)) .& nFF
        |> AST.xtlo 8<rt>
      AST.ite (index .< lenExpr) (elem expr index) dst
    let getElem i idx =
      if len = 2 || len = 4 || len = 6 || len = 8 then
        (* each register covers eight indices, and past the last of them the
           lookup gives zero *)
        Array.foldBack (fun k rest ->
          AST.ite (idx .< numI32 (8 * (k + 1)) 8<rt>) (limit i src[k] idx) rest
        ) [| 0 .. len - 1 |] zeros
      else
        raise InvalidOperandException
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    Array.mapi getElem indices
    |> Array.iter2 (fun e1 e2 -> append bld { direct e1 := e2 }) result
    dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let trn1 ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let struct (dstB, dstA) = transOprToExpr128 ins bld o1
    let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
    let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    Array.iteri (fun i r ->
      let e = if i % 2 = 0 then src1[i] else src2[i - 1]
      append bld { direct r := e }) result
    dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let trn2 ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let struct (dstB, dstA) = transOprToExpr128 ins bld o1
    let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
    let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    Array.iteri (fun i r ->
      let e = if i % 2 = 1 then src2[i] else src1[i + 1]
      append bld { direct r := e }) result
    dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let uabal (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems src1
    let elements = 64<rt> / eSize
    let dblESz = eSize * 2
    let struct (dstB, dstA) = transOprToExpr128 ins bld dst
    let dst = transSIMDOprToExpr bld dblESz 128<rt> elements dst
    let s1 = transSIMDOprVPart bld eSize part src1
    let s2 = transSIMDOprVPart bld eSize part src2
    let result = Array.init elements (fun _ -> tmpVar bld dblESz)
    Array.iter2 (fun r e -> append bld { direct r := e }) result dst
    let dblExt e = AST.zext dblESz e
    Array.map2 (fun e1 e2 ->
      AST.ite (e1 .>= e2) (dblExt e1 .- dblExt e2) (dblExt e2 .- dblExt e1))
      s1 s2
    |> Array.iter2 (fun r absDiff ->
      append bld { direct r := r .+ absDiff }) result
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  }

let uabdl (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems src1
    let elements = 64<rt> / eSize
    let dblESz = eSize * 2
    let struct (dstB, dstA) = transOprToExpr128 ins bld dst
    let s1 = transSIMDOprVPart bld eSize part src1
    let s2 = transSIMDOprVPart bld eSize part src2
    let result = Array.init elements (fun _ -> tmpVar bld dblESz)
    let dblExt e = AST.zext dblESz e
    Array.map2 (fun e1 e2 ->
      AST.ite (e1 .>= e2) (dblExt e1 .- dblExt e2) (dblExt e2 .- dblExt e1))
      s1 s2
    |> Array.iter2 (fun r absDiff -> append bld { direct r := absDiff }) result
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  }

let uadalp ins insLen bld =
  lift bld ins insLen {
    let struct (o1, src) = getTwoOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
    let dst = transSIMDOprToExpr bld (eSize * 2) dataSize (elements / 2) o1
    let src = transSIMDOprToExpr bld eSize dataSize elements src
              |> Array.map (AST.zext (2 * eSize))
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

let saddl (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems src2
    let elements = 64<rt> / eSize
    let dblESz = eSize * 2
    let struct (dstB, dstA) = transOprToExpr128 ins bld dst
    let src1 = transSIMDOprVPart bld eSize part src1
    let src2 = transSIMDOprVPart bld eSize part src2
    let result = Array.init elements (fun _ -> tmpVar bld dblESz)
    Array.map2 (fun e1 e2 -> AST.sext dblESz e1 .+ AST.sext dblESz e2) src1 src2
    |> Array.iter2 (fun r e -> append bld { direct r := e }) result
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  }

let saddw (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems src2
    let elements = 64<rt> / eSize
    let dblESz = eSize * 2
    let struct (dstB, dstA) = transOprToExpr128 ins bld dst
    let src1 = transSIMDOprToExpr bld dblESz 128<rt> elements src1
    let src2 = transSIMDOprVPart bld eSize part src2
    let result = Array.init elements (fun _ -> tmpVar bld dblESz)
    Array.map2 (fun e1 e2 -> e1 .+ AST.sext dblESz e2) src1 src2
    |> Array.iter2 (fun r e -> append bld { direct r := e }) result
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  }

let saddlp ins insLen bld =
  lift bld ins insLen {
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
    let sumArr = Array.init (elements / 2) (fun _ -> tmpVar bld (2 * eSize))
    let struct (dstB, dstA) = transOprToExpr128 ins bld dst
    let srcArr =
      transSIMDOprToExpr bld eSize dataSize elements src
      |> Array.map (AST.sext (2 * eSize)) |> Array.chunkBySize 2
      |> Array.map (fun e -> e[0] .+ e[1])
    Array.iter2 (fun sum src -> append bld { direct sum := src }) sumArr srcArr
    dstAssignForSIMD dstA dstB sumArr dataSize (elements / 2) bld
  }

let saddlv ins insLen bld =
  lift bld ins insLen {
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

let uaddl (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems src2
    let elements = 64<rt> / eSize
    let dblESz = eSize * 2
    let struct (dstB, dstA) = transOprToExpr128 ins bld dst
    let src1 = transSIMDOprVPart bld eSize part src1
    let src2 = transSIMDOprVPart bld eSize part src2
    let result = Array.init elements (fun _ -> tmpVar bld dblESz)
    Array.map2 (fun e1 e2 -> AST.zext dblESz e1 .+ AST.zext dblESz e2) src1 src2
    |> Array.iter2 (fun r e -> append bld { direct r := e }) result
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  }

let uaddw (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems src2
    let elements = 64<rt> / eSize
    let dblESz = eSize * 2
    let struct (dstB, dstA) = transOprToExpr128 ins bld dst
    let src1 = transSIMDOprToExpr bld dblESz 128<rt> elements src1
    let src2 = transSIMDOprVPart bld eSize part src2
    let result = Array.init elements (fun _ -> tmpVar bld dblESz)
    Array.map2 (fun e1 e2 -> e1 .+ AST.zext dblESz e2) src1 src2
    |> Array.iter2 (fun r e -> append bld { direct r := e }) result
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  }

let uaddlp ins insLen bld =
  lift bld ins insLen {
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
    let sumArr = Array.init (elements / 2) (fun _ -> tmpVar bld (2 * eSize))
    let struct (dstB, dstA) = transOprToExpr128 ins bld dst
    let srcArr = transSIMDOprToExpr bld eSize dataSize elements src
              |> Array.map (AST.zext (2 * eSize))
              |> Array.chunkBySize 2
              |> Array.map (fun e -> e[0] .+ e[1])
    Array.iter2 (fun sum src -> append bld { direct sum := src }) sumArr srcArr
    dstAssignForSIMD dstA dstB sumArr dataSize (elements / 2) bld
  }

let uaddlv ins insLen bld =
  lift bld ins insLen {
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

let smlal (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems src1
    let dataSize = 64<rt>
    let elements = dataSize / eSize
    let dblESz = eSize * 2
    let struct (dstB, dstA) = transOprToExpr128 ins bld dst
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
      direct opr2 := transOprToExpr ins bld src2 |> AST.sext dblESz
      Array.map2 (fun e1 e3 -> e3 .+ (AST.sext dblESz e1 .* opr2)) opr1 dst
      |> Array.iter2 (fun r e -> append bld { direct r := e }) result
      dstAssignForSIMD dstA dstB result (2 * dataSize) elements bld
  }

let smlsl (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems src1
    let dataSize = 64<rt>
    let elements = dataSize / eSize
    let dblESz = eSize * 2
    let dblDSize = dataSize * 2
    let struct (dstB, dstA) = transOprToExpr128 ins bld dst
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
      direct opr2 := transOprToExpr ins bld src2 |> AST.sext dblESz
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

let sqdmulh (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    match ins.Operands with
    | ThreeOperands(OprSIMD(VecReg _), _, OprSIMD(VecRegWithIdx _)) ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let src2 = transOprToExpr ins bld o3
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      Array.map (fun e1 -> ssatQMulH bld e1 src2 eSize) src1
      |> Array.iter2 (fun res prod -> append bld { direct res := prod }) result
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | ThreeOperands(OprSIMD(VecReg _), _, _) ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      Array.map2 (fun e1 e2 -> ssatQMulH bld e1 e2 eSize) src1 src2
      |> Array.iter2 (fun res prod -> append bld { direct res := prod }) result
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | ThreeOperands(OprSIMD(ScalarReg _), _, _) ->
      let src1 = transOprToExpr ins bld o2
      let src2 = transOprToExpr ins bld o3
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

let sqdmull (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems o2
    match ins.Operands with
    | ThreeOperands(OprSIMD(VecReg _), _, OprSIMD(VecRegWithIdx _)) ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld o1
      let src1 = transSIMDOprVPart bld eSize part o2
      let src2 = transOprToExpr ins bld o3
      let elements = 64<rt> / eSize
      let result = Array.init elements (fun _ -> tmpVar bld (2 * eSize))
      Array.map (fun e1 -> ssatQMulL bld e1 src2 eSize) src1
      |> Array.iter2 (fun res prod -> append bld { direct res := prod }) result
      dstAssignForSIMD dstA dstB result 128<rt> elements bld
    | ThreeOperands(OprSIMD(VecReg _), _, _) ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld o1
      let src1 = transSIMDOprVPart bld eSize part o2
      let src2 = transSIMDOprVPart bld eSize part o3
      let elements = 64<rt> / eSize
      let result = Array.init elements (fun _ -> tmpVar bld (2 * eSize))
      Array.map2 (fun e1 e2 -> ssatQMulL bld e1 e2 eSize) src1 src2
      |> Array.iter2 (fun res prod -> append bld { direct res := prod }) result
      dstAssignForSIMD dstA dstB result 128<rt> elements bld
    | ThreeOperands(OprSIMD(ScalarReg _), _, _) ->
      let src1 = transOprToExpr ins bld o2
      let src2 = transOprToExpr ins bld o3
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

let sqdmlal (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems o2
    match ins.Operands with
    | ThreeOperands(OprSIMD(VecReg _), _, OprSIMD(VecRegWithIdx _)) ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld o1
      let elements = 64<rt> / eSize
      let dblESz = 2 * eSize
      let dst = transSIMDOprToExpr bld dblESz 128<rt> elements o1
      let src1 = transSIMDOprVPart bld eSize part o2
      let src2 = transOprToExpr ins bld o3
      let result = Array.init elements (fun _ -> tmpVar bld dblESz)
      Array.map2 (fun e1 e2 -> ssatQMAdd bld e1 src2 e2 eSize) src1 dst
      |> Array.iter2 (fun res accum ->
        append bld { direct res := accum }) result
      dstAssignForSIMD dstA dstB result 128<rt> elements bld
    | ThreeOperands(OprSIMD(VecReg _), _, _) ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld o1
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
      let dst = transOprToExpr ins bld o1
      let src1 = transOprToExpr ins bld o2
      let src2 = transOprToExpr ins bld o3
      let result = ssatQMAdd bld src1 src2 dst eSize
      dstAssignScalar ins bld o1 result eSize
    | _ ->
      raise InvalidOperandException
  }

let umlal (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems src1
    let dataSize = 64<rt>
    let elements = dataSize / eSize
    let dblESz = eSize * 2
    let struct (dstB, dstA) = transOprToExpr128 ins bld dst
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
      direct opr2 := transOprToExpr ins bld src2 |> AST.zext dblESz
      Array.map2 (fun e1 e3 -> e3 .+ (AST.zext dblESz e1 .* opr2)) opr1 dst
      |> Array.iter2 (fun r e -> append bld { direct r := e }) result
      dstAssignForSIMD dstA dstB result 128<rt> elements bld
  }

let umlsl (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems src1
    let dataSize = 64<rt>
    let elements = dataSize / eSize
    let dblESz = eSize * 2
    let dblDSize = dataSize * 2
    let struct (dstB, dstA) = transOprToExpr128 ins bld dst
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
      direct opr2 := transOprToExpr ins bld src2 |> AST.zext dblESz
      Array.map2 (fun e1 e3 -> e3 .- (AST.zext dblESz e1 .* opr2)) opr1 opr3
      |> Array.iter2 (fun r e -> append bld { direct r := e }) result
      dstAssignForSIMD dstA dstB result dblDSize elements bld
  }

let umulh ins insLen bld =
  lift bld ins insLen {
    let dst, src1, src2 = transThreeOprs ins bld
    (* The high 64 bits of the unsigned 64x64->128 product, extracted from the
       128-bit intermediate the evaluator holds. *)
    let prod = AST.zext 128<rt> src1 .* AST.zext 128<rt> src2
    direct dst := AST.xthi 64<rt> prod
  }

let umull (ins: Instruction) insLen bld =
  lift bld ins insLen {
    match ins.Operands with
    | ThreeOperands(_, _, OprSIMD(VecRegWithIdx _)) ->
      let struct (o1, o2, o3) = getThreeOprs ins
      let struct (eSize, part, _) = getElemDataSzAndElems o2
      let elements = 64<rt> / eSize
      let dblESz = eSize * 2
      let struct (dstB, dstA) = transOprToExpr128 ins bld o1
      let opr1 = transSIMDOprVPart bld eSize part o2
      let opr2 = tmpVar bld dblESz
      direct opr2 := transOprToExpr ins bld o3 |> AST.zext dblESz
      let result = Array.init elements (fun _ -> tmpVar bld dblESz)
      Array.map (fun e1 -> AST.zext dblESz e1 .* opr2) opr1
      |> Array.iter2 (fun r e -> append bld { direct r := e }) result
      dstAssignForSIMD dstA dstB result 128<rt> elements bld
    | ThreeOperands(OprSIMD(VecReg _), _, _) ->
      let struct (o1, o2, o3) = getThreeOprs ins
      let struct (eSize, part, _) = getElemDataSzAndElems o2
      let elements = 64<rt> / eSize
      let dblESz = eSize * 2
      let struct (dstB, dstA) = transOprToExpr128 ins bld o1
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

let uqadd (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let inline satQ64 src1 src2 =
      let input = src1 .+ src2
      let bitQC = AST.extract (regVar bld R.FPSR) 1<rt> 27
      let max = numU64 0xffffffff_ffffffffUL 64<rt>
      let overflow = input .< src1
      append bld {
        direct bitQC := bitQC .| overflow
      }
      AST.ite overflow max input
    match ins.Operands with
    | ThreeOperands(OprSIMD(VecReg _), _, _) ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      if eSize = 64<rt> then
        Array.map2 satQ64 src1 src2
        |> Array.iter2 (fun element i ->
          append bld { direct element := i }) result
      else
        Array.map2 (fun e1 e2 ->
          AST.zext (2 * eSize) e1 .+ AST.zext (2 * eSize) e2) src1 src2
        |> Array.iter2 (fun element i ->
          append bld { direct element := satQ bld i eSize true }) result
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | ThreeOperands(OprSIMD(ScalarReg _), _, _) ->
      let src1 = transOprToExpr ins bld o2
      let src2 = transOprToExpr ins bld o3
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

let uqrshl (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    match ins.Operands with
    | ThreeOperands(OprSIMD(VecReg _), _, _) ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      Array.map2 (fun e shf ->
        let shf = shf |> AST.xtlo 8<rt> |> AST.sext eSize
        usatQRShl bld e shf eSize) src1 src2
      |> Array.iter2 (fun r e -> append bld { direct r := e }) result
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | ThreeOperands(OprSIMD(ScalarReg _), _, _) ->
      let src1 = transOprToExpr ins bld o2
      let shift =
        transOprToExpr ins bld o3 |> AST.xtlo 8<rt> |> AST.sext eSize
      let result = usatQRShl bld src1 shift eSize
      dstAssignScalar ins bld o1 result eSize
    | _ ->
      raise InvalidOperandException
  }

let uqsub (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let inline satQ64 src1 src2 =
      let eval = src1 .- src2
      let bitQC = AST.extract (regVar bld R.FPSR) 1<rt> 27
      let underflow = src1 .< src2
      append bld {
        direct bitQC := bitQC .| underflow
      }
      AST.ite underflow (AST.num0 64<rt>) eval
    match ins.Operands with
    | ThreeOperands(OprSIMD(VecReg _), _, _) ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      if eSize = 64<rt> then
        Array.map2 satQ64 src1 src2
        |> Array.iter2 (fun element i ->
          append bld { direct element := i }) result
      else
        Array.map2 (fun e1 e2 ->
          AST.zext (2 * eSize) e1 .- AST.zext (2 * eSize) e2) src1 src2
        |> Array.iter2 (fun element i ->
          append bld { direct element := satQ bld i eSize true }) result
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | ThreeOperands(OprSIMD(ScalarReg _), _, _) ->
      let src1 = transOprToExpr ins bld o2
      let src2 = transOprToExpr ins bld o3
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

let uqshl (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    match ins.Operands with
    | ThreeOperands(OprSIMD(VecReg _), _, OprImm _) ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let shift = transOprToExpr ins bld o3 |> AST.xtlo 8<rt>
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      let shf = tmpVar bld eSize
      direct shf := shift |> AST.sext eSize
      Array.map (fun e -> usatQShl bld e shf eSize) src1
      |> Array.iter2 (fun r e -> append bld { direct r := e }) result
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | ThreeOperands(OprSIMD(VecReg _), _, _) ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld o1
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
      let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
      let result = Array.init elements (fun _ -> tmpVar bld eSize)
      Array.map2 (fun e shf ->
        let shf = shf |> AST.xtlo 8<rt> |> AST.sext eSize
        usatQShl bld e shf eSize) src1 src2
      |> Array.iter2 (fun r e -> append bld { direct r := e }) result
      dstAssignForSIMD dstA dstB result dataSize elements bld
    | ThreeOperands(OprSIMD(ScalarReg _), _, _) ->
      let src1 = transOprToExpr ins bld o2
      let shift = transOprToExpr ins bld o3 |> AST.xtlo 8<rt>
      let result = usatQShl bld src1 (AST.sext eSize shift) eSize
      dstAssignScalar ins bld o1 result eSize
    | _ ->
      raise InvalidOperandException
  }

let shiftULeftLong (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems o2
    let elements = 64<rt> / eSize
    let dblESz = eSize * 2
    let struct (dstB, dstA) = transOprToExpr128 ins bld o1
    let src = transSIMDOprVPart bld eSize part o2
    let amt = tmpVar bld dblESz
    direct amt := transOprToExpr ins bld o3 |> AST.xtlo dblESz
    let result = Array.init elements (fun _ -> tmpVar bld dblESz)
    Array.map (fun e -> AST.zext dblESz e << amt) src
    |> Array.iter2 (fun r e -> append bld { direct r := e }) result
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  }

let shiftSLeftLong (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems o2
    let elements = 64<rt> / eSize
    let dblESz = eSize * 2
    let struct (dstB, dstA) = transOprToExpr128 ins bld o1
    let src = transSIMDOprVPart bld eSize part o2
    let amt = tmpVar bld dblESz
    direct amt := transOprToExpr ins bld o3 |> AST.xtlo dblESz
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

let urshl (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src, shift) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
    let struct (n0, n1) = tmpVars2 bld 64<rt>
    direct n0 := AST.num0 64<rt>
    direct n1 := AST.num1 64<rt>
    let shiftRndLeft e1 e2 = urshlElem bld eSize (n0, n1) e1 e2
    match ins.Operands with
    | ThreeOperands(OprSIMD(ScalarReg _), _, _) ->
      let src = transOprToExpr ins bld src
      let shift = transOprToExpr ins bld shift
      let result = shiftRndLeft src shift
      dstAssignScalar ins bld dst result eSize
    | _ ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
      let src = transSIMDOprToExpr bld eSize dataSize elements src
      let shift = transSIMDOprToExpr bld eSize dataSize elements shift
      let result = Array.map2 shiftRndLeft src shift
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let srshl (ins: Instruction) insLen bld =
  lift bld ins insLen {
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
      let src = transOprToExpr ins bld src
      let shift = transOprToExpr ins bld shift
      let result = shiftRndLeft src shift
      dstAssignScalar ins bld dst result eSize
    | _ ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
      let src = transSIMDOprToExpr bld eSize dataSize elements src
      let shift = transSIMDOprToExpr bld eSize dataSize elements shift
      let result = Array.map2 shiftRndLeft src shift
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let urhadd ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let struct (dstB, dstA) = transOprToExpr128 ins bld o1
    let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
    let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
    let inline roundAdd e1 e2 =
      let e1 = AST.zext 64<rt> e1
      let e2 = AST.zext 64<rt> e2
      (e1 .+ e2 .+ AST.num1 64<rt>) >> AST.num1 64<rt>
      |> AST.xtlo eSize
    let result = Array.map2 roundAdd src1 src2
    dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let shiftRight ins insLen bld shifter =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let struct (dstB, dstA) = transOprToExpr128 ins bld o1
    let dst = transSIMDOprToExpr bld eSize dataSize elements o1
    let src = transSIMDOprToExpr bld eSize dataSize elements o2
    let shf = transOprToExpr ins bld o3 |> AST.xtlo eSize
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    Array.map2 (fun e1 e2 -> e1 .+ (shifter e2 shf)) dst src
    |> Array.iter2 (fun e1 e2 -> append bld { direct e1 := e2 }) result
    dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let ssubl (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems src1
    let dataSize = 64<rt>
    let elements = dataSize / eSize
    let dblESz = eSize * 2
    let struct (dstB, dstA) = transOprToExpr128 ins bld dst
    let opr1 = transSIMDOprVPart bld eSize part src1
    let opr2 = transSIMDOprVPart bld eSize part src2
    let result = Array.init elements (fun _ -> tmpVar bld dblESz)
    Array.map2 (fun e1 e2 -> AST.sext dblESz e1 .- AST.sext dblESz e2) opr1 opr2
    |> Array.iter2 (fun r e -> append bld { direct r := e }) result
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  }

let ssubw (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems o3
    let elements = 64<rt> / eSize
    let dblESz = eSize * 2
    let struct (dstB, dstA) = transOprToExpr128 ins bld o1
    let opr1 = transSIMDOprToExpr bld dblESz 128<rt> elements o2
    let opr2 = transSIMDOprVPart bld eSize part o3
    let result = Array.init elements (fun _ -> tmpVar bld dblESz)
    Array.map2 (fun e1 e2 -> AST.sext dblESz e1 .- AST.sext dblESz e2) opr1 opr2
    |> Array.iter2 (fun r e -> append bld { direct r := e }) result
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  }

let ushl ins insLen bld =
  lift bld ins insLen {
    let struct (dst, o1, o2) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let inline shiftLeft e1 e2 =
      let shf = tmpVar bld eSize
      append bld {
        direct shf := AST.xtlo 8<rt> e2 |> AST.sext eSize
      }
      AST.ite (shf ?< AST.num0 eSize) (e1 >> AST.neg shf) (e1 << shf)
    match ins.Operands with
    | ThreeOperands(OprSIMD(ScalarReg _), _, _) ->
      let src1 = transOprToExpr ins bld o1
      let src2 = transOprToExpr ins bld o2
      let result = shiftLeft src1 src2
      dstAssignScalar ins bld dst result eSize
    | _ ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld dst
      let src1 = transSIMDOprToExpr bld eSize dataSize elements o1
      let src2 = transSIMDOprToExpr bld eSize dataSize elements o2
      let result = Array.map2 shiftLeft src1 src2
      dstAssignForSIMD dstA dstB result dataSize elements bld
  }

let usubl (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems o2
    let elements = 64<rt> / eSize
    let dblESz = eSize * 2
    let struct (dstB, dstA) = transOprToExpr128 ins bld o1
    let src1 = transSIMDOprVPart bld eSize part o2
    let src2 = transSIMDOprVPart bld eSize part o3
    let result = Array.init elements (fun _ -> tmpVar bld dblESz)
    Array.iteri (fun i r ->
      append bld {
        direct r := AST.zext dblESz src1[i] .- AST.zext dblESz src2[i]
      }) result
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  }

let usubw (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems o3
    let elements = 64<rt> / eSize
    let dblESz = eSize * 2
    let struct (dstB, dstA) = transOprToExpr128 ins bld o1
    let src1 = transSIMDOprToExpr bld dblESz 128<rt> elements o2
    let src2 = transSIMDOprVPart bld eSize part o3
    let result = Array.init elements (fun _ -> tmpVar bld dblESz)
    Array.iteri (fun i r ->
      append bld {
        direct r := AST.zext dblESz src1[i] .- AST.zext dblESz src2[i]
      }) result
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  }

let uzp ins insLen bld op =
  lift bld ins insLen {
    let struct (dst, src1, srcH) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (dstB, dstA) = transOprToExpr128 ins bld dst
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

let xtn (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
    let struct (dstB, dstA) = transOprToExpr128 ins bld dst
    let src = transSIMDOprToExpr bld eSize dataSize elements src
              |> Array.map (AST.xtlo (eSize / 2))
    direct dstA := AST.revConcat src
    direct dstB := AST.num0 64<rt>
  }

let xtn2 (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
    let struct (dstB, dstA) = transOprToExpr128 ins bld dst
    let src = transSIMDOprToExpr bld eSize dataSize elements src
              |> Array.map (AST.xtlo (eSize / 2))
    direct dstA := dstA
    direct dstB := AST.revConcat src
  }

/// SHRN/SHRN2: shift each wide source element right by the immediate and narrow
/// it to the lower half width. SHRN writes the low 64-bit destination half (and
/// zeroes the high half); SHRN2 writes the high half, preserving the low one.
let shrn (ins: Instruction) insLen bld isPart2 =
  lift bld ins insLen {
    let struct (dst, src, amt) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
    let struct (dstB, dstA) = transOprToExpr128 ins bld dst
    let amt = transOprToExpr ins bld amt |> AST.xtlo eSize
    let src = transSIMDOprToExpr bld eSize dataSize elements src
              |> Array.map (fun e -> AST.xtlo (eSize / 2) (e >> amt))
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
let addSubHN (ins: Instruction) insLen bld isPart2 op =
  lift bld ins insLen {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems src1
    let struct (dstB, dstA) = transOprToExpr128 ins bld dst
    let s1 = transSIMDOprToExpr bld eSize dataSize elements src1
    let s2 = transSIMDOprToExpr bld eSize dataSize elements src2
    let shf = numI32 (RegType.toBitWidth (eSize / 2)) eSize
    let result =
      Array.map2 (fun a b -> AST.xtlo (eSize / 2) (op a b >> shf)) s1 s2
    if isPart2 then
      direct dstB := AST.revConcat result
    else
      direct dstA := AST.revConcat result
      direct dstB := AST.num0 64<rt>
  }

let zip ins insLen bld isPart1 =
  lift bld ins insLen {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (dstB, dstA) = transOprToExpr128 ins bld dst
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
let distLogicalLeftShift (ins: Instruction) insLen bld =
  match ins.Operands with
  | ThreeOperands(_, _, OprImm _) -> logShift ins insLen bld (<<)
  | ThreeOperands(_, _, OprRegister _) -> lslv ins insLen bld
  | _ -> raise InvalidOperandException

let distLogicalRightShift (ins: Instruction) insLen bld =
  match ins.Operands with
  | ThreeOperands(_, _, OprImm _) -> logShift ins insLen bld (>>)
  | ThreeOperands(_, _, OprRegister _) -> lsrv ins insLen bld
  | _ -> raise InvalidOperandException
