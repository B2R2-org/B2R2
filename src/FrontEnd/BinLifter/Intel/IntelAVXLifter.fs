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

module internal B2R2.FrontEnd.BinLifter.Intel.AVXLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.Intel
open B2R2.FrontEnd.BinLifter.Intel.LiftingUtils
open B2R2.FrontEnd.BinLifter.Intel.MMXLifter

let private haveEVEXPrx = function
  | Some v -> Option.isSome v.EVEXPrx
  | None -> false

let private r128to256 = function
  | OprReg R.XMM0 -> R.YMM0
  | OprReg R.XMM1 -> R.YMM1
  | OprReg R.XMM2 -> R.YMM2
  | OprReg R.XMM3 -> R.YMM3
  | OprReg R.XMM4 -> R.YMM4
  | OprReg R.XMM5 -> R.YMM5
  | OprReg R.XMM6 -> R.YMM6
  | OprReg R.XMM7 -> R.YMM7
  | OprReg R.XMM8 -> R.YMM8
  | OprReg R.XMM9 -> R.YMM9
  | OprReg R.XMM10 -> R.YMM10
  | OprReg R.XMM11 -> R.YMM11
  | OprReg R.XMM12 -> R.YMM12
  | OprReg R.XMM13 -> R.YMM13
  | OprReg R.XMM14 -> R.YMM14
  | OprReg R.XMM15 -> R.YMM15
  | _ -> raise InvalidOperandException

let private r128to512 = function
  | OprReg R.XMM0 -> R.ZMM0
  | OprReg R.XMM1 -> R.ZMM1
  | OprReg R.XMM2 -> R.ZMM2
  | OprReg R.XMM3 -> R.ZMM3
  | OprReg R.XMM4 -> R.ZMM4
  | OprReg R.XMM5 -> R.ZMM5
  | OprReg R.XMM6 -> R.ZMM6
  | OprReg R.XMM7 -> R.ZMM7
  | OprReg R.XMM8 -> R.ZMM8
  | OprReg R.XMM9 -> R.ZMM9
  | OprReg R.XMM10 -> R.ZMM10
  | OprReg R.XMM11 -> R.ZMM11
  | OprReg R.XMM12 -> R.ZMM12
  | OprReg R.XMM13 -> R.ZMM13
  | OprReg R.XMM14 -> R.ZMM14
  | OprReg R.XMM15 -> R.ZMM15
  | _ -> raise InvalidOperandException

let private r256to512 = function
  | OprReg R.YMM0 -> R.ZMM0
  | OprReg R.YMM1 -> R.ZMM1
  | OprReg R.YMM2 -> R.ZMM2
  | OprReg R.YMM3 -> R.ZMM3
  | OprReg R.YMM4 -> R.ZMM4
  | OprReg R.YMM5 -> R.ZMM5
  | OprReg R.YMM6 -> R.ZMM6
  | OprReg R.YMM7 -> R.ZMM7
  | OprReg R.YMM8 -> R.ZMM8
  | OprReg R.YMM9 -> R.ZMM9
  | OprReg R.YMM10 -> R.ZMM10
  | OprReg R.YMM11 -> R.ZMM11
  | OprReg R.YMM12 -> R.ZMM12
  | OprReg R.YMM13 -> R.ZMM13
  | OprReg R.YMM14 -> R.ZMM14
  | OprReg R.YMM15 -> R.ZMM15
  | _ -> raise InvalidOperandException

let private fillZeroHigh128 ctxt dst builder =
  let dst = r128to256 dst
  let dstC, dstD = getPseudoRegVar ctxt dst 3, getPseudoRegVar ctxt dst 4
  let n0 = AST.num0 64<rt>
  builder <! (dstC := n0)
  builder <! (dstD := n0)

let private fillZeroHigh256 ctxt dst builder =
  let dst = r256to512 dst
  let dstE, dstF, dstG, dstH =
    getPseudoRegVar ctxt dst 3, getPseudoRegVar ctxt dst 4,
    getPseudoRegVar ctxt dst 5, getPseudoRegVar ctxt dst 6
  let n0 = AST.num0 64<rt>
  builder <! (dstE := n0)
  builder <! (dstF := n0)
  builder <! (dstG := n0)
  builder <! (dstH := n0)

let private vexedPackedFPBinOp32 ins insAddr insLen ctxt op =
  let builder = StmtBuilder (16)
  let dst, src1, src2 = getThreeOprs ins
  let oprSz = getOperationSize ins
  let do32PackedOp dst64 src1 src2 builder =
    let dstA, dstB = AST.xtlo 32<rt> dst64, AST.xthi 32<rt> dst64
    let src1A, src1B = AST.xtlo 32<rt> src1, AST.xthi 32<rt> src1
    let src2A, src2B = AST.xtlo 32<rt> src2, AST.xthi 32<rt> src2
    builder <! (dstA := op src1A src2A)
    builder <! (dstB := op src1B src2B)
  startMark insAddr insLen builder
  match oprSz with
  | 128<rt> ->
    let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
    let src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
    let src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt src2
    do32PackedOp dst1 src1A src2A builder
    do32PackedOp dst2 src1B src2B builder
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dst4, dst3, dst2, dst1 = transOprToExpr256 ins insAddr insLen ctxt dst
    let sr1D, sr1C, sr1B, sr1A = transOprToExpr256 ins insAddr insLen ctxt src1
    let sr2D, sr2C, sr2B, sr2A = transOprToExpr256 ins insAddr insLen ctxt src2
    do32PackedOp dst1 sr1A sr2A builder
    do32PackedOp dst2 sr1B sr2B builder
    do32PackedOp dst3 sr1C sr2C builder
    do32PackedOp dst4 sr1D sr2D builder
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let private vexedPackedFPBinOp64 ins insAddr insLen ctxt op =
  let builder = StmtBuilder (16)
  let dst, src1, src2 = getThreeOprs ins
  let oprSz = getOperationSize ins
  startMark insAddr insLen builder
  match oprSz with
  | 128<rt> ->
    let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
    let src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
    let src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt src2
    builder <! (dst1 := op src1A src2A)
    builder <! (dst2 := op src1B src2B)
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dst4, dst3, dst2, dst1 = transOprToExpr256 ins insAddr insLen ctxt dst
    let sr1D, sr1C, sr1B, sr1A = transOprToExpr256 ins insAddr insLen ctxt src1
    let sr2D, sr2C, sr2B, sr2A = transOprToExpr256 ins insAddr insLen ctxt src2
    builder <! (dst1 := op sr1A sr2A)
    builder <! (dst2 := op sr1B sr2B)
    builder <! (dst3 := op sr1C sr2C)
    builder <! (dst4 := op sr1D sr2D)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let private vexedScalarFPBinOp ins insAddr insLen ctxt sz op =
  let builder = StmtBuilder (8)
  let dst, src1, src2 = getThreeOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
  startMark insAddr insLen builder
  match sz with
  | 32<rt> ->
    let src2 = transOprToExpr32 ins insAddr insLen ctxt src2
    builder <! (AST.xtlo 32<rt> dst1 := op (AST.xtlo 32<rt> src1A) src2)
    builder <! (AST.xthi 32<rt> dst1 := AST.xthi 32<rt> src1A)
  | 64<rt> ->
    let src2 = transOprToExpr64 ins insAddr insLen ctxt src2
    builder <! (dst1 := op src1A src2)
  | _ -> raise InvalidOperandSizeException
  builder <! (dst2 := src1B)
  fillZeroHigh128 ctxt dst builder
  endMark insAddr insLen builder

let vsqrtps ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let dst, src = getTwoOprs ins
  let oprSz = getOperationSize ins
  let do32PackedSqrt dst64 src builder =
    let dstA, dstB = AST.xtlo 32<rt> dst64, AST.xthi 32<rt> dst64
    let srcA, srcB = AST.xtlo 32<rt> src, AST.xthi 32<rt> src
    builder <! (dstA := AST.fsqrt srcA)
    builder <! (dstB := AST.fsqrt srcB)
  startMark insAddr insLen builder
  match oprSz with
  | 128<rt> ->
    let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
    let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
    do32PackedSqrt dst1 srcA builder
    do32PackedSqrt dst2 srcB builder
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dst4, dst3, dst2, dst1 = transOprToExpr256 ins insAddr insLen ctxt dst
    let srD, srC, srB, srA = transOprToExpr256 ins insAddr insLen ctxt src
    do32PackedSqrt dst1 srA  builder
    do32PackedSqrt dst2 srB  builder
    do32PackedSqrt dst3 srC  builder
    do32PackedSqrt dst4 srD  builder
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vsqrtpd ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let dst, src = getTwoOprs ins
  let oprSz = getOperationSize ins
  startMark insAddr insLen builder
  match oprSz with
  | 128<rt> ->
    let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
    let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
    builder <! (dst1 := AST.fsqrt src1)
    builder <! (dst2 := AST.fsqrt src2)
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dst4, dst3, dst2, dst1 = transOprToExpr256 ins insAddr insLen ctxt dst
    let sr4, sr3, sr2, sr1 = transOprToExpr256 ins insAddr insLen ctxt src
    builder <! (dst1 := AST.fsqrt sr1)
    builder <! (dst2 := AST.fsqrt sr2)
    builder <! (dst3 := AST.fsqrt sr3)
    builder <! (dst4 := AST.fsqrt sr4)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let private vsqrts ins insAddr insLen ctxt sz =
  let builder = StmtBuilder (16)
  let dst, src1, src2 = getThreeOprs ins
  let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
  let src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
  startMark insAddr insLen builder
  match sz with
  | 32<rt> ->
    let src2 = transOprToExpr32 ins insAddr insLen ctxt src2
    builder <! (AST.xtlo 32<rt> dst1 := AST.fsqrt src2)
    builder <! (AST.xthi 32<rt> dst1 := AST.xthi 32<rt> src1A)
  | 64<rt> ->
    let src2 = transOprToExpr64 ins insAddr insLen ctxt src2
    builder <! (dst1 := AST.fsqrt src2)
  | _ -> raise InvalidOperandSizeException
  builder <! (dst2 := src1B)
  fillZeroHigh128 ctxt dst builder
  endMark insAddr insLen builder

let vsqrtss ins insAddr insLen ctxt =
  vsqrts ins insAddr insLen ctxt 32<rt>

let vsqrtsd ins insAddr insLen ctxt =
  vsqrts ins insAddr insLen ctxt 64<rt>

let vaddps ins insAddr insLen ctxt =
  match getOperationSize ins with
  | 512<rt> -> GeneralLifter.nop insAddr insLen
  | _ -> vexedPackedFPBinOp32 ins insAddr insLen ctxt AST.fadd

let vaddpd ins insAddr insLen ctxt =
  vexedPackedFPBinOp64 ins insAddr insLen ctxt AST.fadd

let vaddss ins insAddr insLen ctxt =
  vexedScalarFPBinOp ins insAddr insLen ctxt 32<rt> AST.fadd

let vaddsd ins insAddr insLen ctxt =
  vexedScalarFPBinOp ins insAddr insLen ctxt 64<rt> AST.fadd

let vsubps ins insAddr insLen ctxt =
  match getOperationSize ins with
  | 512<rt> -> GeneralLifter.nop insAddr insLen
  | _ -> vexedPackedFPBinOp32 ins insAddr insLen ctxt AST.fsub

let vsubpd ins insAddr insLen ctxt =
  vexedPackedFPBinOp64 ins insAddr insLen ctxt AST.fsub

let vsubss ins insAddr insLen ctxt =
  vexedScalarFPBinOp ins insAddr insLen ctxt 32<rt> AST.fsub

let vsubsd ins insAddr insLen ctxt =
  vexedScalarFPBinOp ins insAddr insLen ctxt 64<rt> AST.fsub

let vmulps ins insAddr insLen ctxt =
  vexedPackedFPBinOp32 ins insAddr insLen ctxt AST.fmul

let vmulpd ins insAddr insLen ctxt =
  vexedPackedFPBinOp64 ins insAddr insLen ctxt AST.fmul

let vmulss ins insAddr insLen ctxt =
  vexedScalarFPBinOp ins insAddr insLen ctxt 32<rt> AST.fmul

let vmulsd ins insAddr insLen ctxt =
  vexedScalarFPBinOp ins insAddr insLen ctxt 64<rt> AST.fmul

let vdivps ins insAddr insLen ctxt =
  vexedPackedFPBinOp32 ins insAddr insLen ctxt AST.fdiv

let vdivpd ins insAddr insLen ctxt =
  match getOperationSize ins with
  | 512<rt> -> GeneralLifter.nop insAddr insLen (* FIXME: #196 *)
  | _ -> vexedPackedFPBinOp64 ins insAddr insLen ctxt AST.fdiv

let vdivss ins insAddr insLen ctxt =
  vexedScalarFPBinOp ins insAddr insLen ctxt 32<rt> AST.fdiv

let vdivsd ins insAddr insLen ctxt =
  vexedScalarFPBinOp ins insAddr insLen ctxt 64<rt> AST.fdiv

let vcvtsi2ss ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src1, src2 = getThreeOprs ins
  let dstB , dstA = transOprToExpr128 ins insAddr insLen ctxt dst
  let src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
  let src2 = transOprToExpr ins insAddr insLen ctxt src2
  startMark insAddr insLen builder
  builder <! (AST.xtlo 32<rt> dstA := AST.cast CastKind.IntToFloat 32<rt> src2)
  builder <! (AST.xthi 32<rt> dstA := AST.xthi 32<rt> src1A)
  builder <! (dstB := src1B)
  fillZeroHigh128 ctxt dst builder
  endMark insAddr insLen builder

let vcvtsi2sd ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src1, src2 = getThreeOprs ins
  let dstB , dstA = transOprToExpr128 ins insAddr insLen ctxt dst
  let src1B, _src1A = transOprToExpr128 ins insAddr insLen ctxt src1
  let src2 = transOprToExpr ins insAddr insLen ctxt src2
  startMark insAddr insLen builder
  builder <! (dstA := AST.cast CastKind.IntToFloat 64<rt> src2)
  builder <! (dstB := src1B)
  fillZeroHigh128 ctxt dst builder
  endMark insAddr insLen builder

let vcvtsd2ss ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src1, src2 = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
  let src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
  let src2 = transOprToExpr64 ins insAddr insLen ctxt src2
  startMark insAddr insLen builder
  builder <! (AST.xtlo 32<rt> dstA := AST.cast CastKind.FloatExt 32<rt> src2)
  builder <! (AST.xthi 32<rt> dstA := AST.xthi 32<rt> src1A)
  builder <! (dstB := src1B)
  fillZeroHigh128 ctxt dst builder
  endMark insAddr insLen builder

let vcvtss2sd ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src1, src2 = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
  let src1B, _src1A = transOprToExpr128 ins insAddr insLen ctxt src1
  let src2 = transOprToExpr32 ins insAddr insLen ctxt src2
  startMark insAddr insLen builder
  builder <! (dstA := AST.cast CastKind.FloatExt 64<rt> src2)
  builder <! (dstB := src1B)
  fillZeroHigh128 ctxt dst builder
  endMark insAddr insLen builder

let private getEVEXPrx = function
  | Some v -> match v.EVEXPrx with
              | Some ev -> ev
              | None -> Utils.impossible ()
  | None -> Utils.impossible ()

let private buildVectorMove ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  if oprSize = 128<rt> then
    match dst with
    | OprReg _ ->
      let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
      let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
      builder <! (dstA := srcA)
      builder <! (dstB := srcB)
      fillZeroHigh128 ctxt dst builder
    | OprMem _ ->
      let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
      let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
      builder <! (dstA := srcA)
      builder <! (dstB := srcB)
    | _ -> raise InvalidOperandException
  elif oprSize = 256<rt> then
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
    let srcD, srcC, srcB, srcA = transOprToExpr256 ins insAddr insLen ctxt src
    builder <! (dstA := srcA)
    builder <! (dstB := srcB)
    builder <! (dstC := srcC)
    builder <! (dstD := srcD)
  elif oprSize = 512<rt> then
    let ePrx = getEVEXPrx ins.VEXInfo
    let k = getRegVar ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
    let masking dst =
      match ePrx.Z with
      | Zeroing -> AST.num0 32<rt>
      | Merging -> dst
    let cond idx =
      (* no write mask *)
      let noWritemask = if ePrx.AAA = 0uy then AST.num1 1<rt> else AST.num0 1<rt>
      AST.extract k 1<rt> idx .| noWritemask
    let kl, vl = 16, 512
    match dst with
    | OprReg _ ->
      let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
        transOprToExpr512 ins insAddr insLen ctxt dst
      let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
        transOprToExpr512 ins insAddr insLen ctxt src
      let ite i src dst extFn =
        AST.ite (cond i) (extFn 32<rt> src) (masking (extFn 32<rt> dst))
      builder <! (AST.xtlo 32<rt> dstA := ite 0 srcA dstA AST.xtlo)
      builder <! (AST.xthi 32<rt> dstA := ite 1 srcA dstA AST.xthi)
      builder <! (AST.xtlo 32<rt> dstB := ite 2 srcB dstB AST.xtlo)
      builder <! (AST.xthi 32<rt> dstB := ite 3 srcB dstB AST.xthi)
      builder <! (AST.xtlo 32<rt> dstC := ite 4 srcC dstC AST.xtlo)
      builder <! (AST.xthi 32<rt> dstC := ite 5 srcC dstC AST.xthi)
      builder <! (AST.xtlo 32<rt> dstD := ite 6 srcD dstD AST.xtlo)
      builder <! (AST.xthi 32<rt> dstD := ite 7 srcD dstD AST.xthi)
      builder <! (AST.xtlo 32<rt> dstE := ite 8 srcE dstE AST.xtlo)
      builder <! (AST.xthi 32<rt> dstE := ite 9 srcE dstE AST.xthi)
      builder <! (AST.xtlo 32<rt> dstF := ite 10 srcF dstF AST.xtlo)
      builder <! (AST.xthi 32<rt> dstF := ite 11 srcF dstF AST.xthi)
      builder <! (AST.xtlo 32<rt> dstG := ite 12 srcG dstG AST.xtlo)
      builder <! (AST.xthi 32<rt> dstG := ite 13 srcG dstG AST.xthi)
      builder <! (AST.xtlo 32<rt> dstH := ite 14 srcH dstH AST.xtlo)
      builder <! (AST.xthi 32<rt> dstH := ite 15 srcH dstH AST.xthi)
    | OprMem _ ->
      let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
        transOprToExpr512 ins insAddr insLen ctxt dst
      let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
        transOprToExpr512 ins insAddr insLen ctxt src
      let ite i src dst extFn =
        AST.ite (cond i) (extFn 32<rt> src) (extFn 32<rt> dst)
      let evAssign src dst idx =
        AST.concat (ite (idx + 1) src dst AST.xthi) (ite idx src dst AST.xtlo)
      builder <! (dstA := evAssign srcA dstA 0)
      builder <! (dstB := evAssign srcB dstB 2)
      builder <! (dstC := evAssign srcC dstB 4)
      builder <! (dstD := evAssign srcD dstB 6)
      builder <! (dstE := evAssign srcE dstB 8)
      builder <! (dstF := evAssign srcF dstB 10)
      builder <! (dstG := evAssign srcG dstB 12)
      builder <! (dstH := evAssign srcH dstB 14)
    | _ -> raise InvalidOperandException
  else raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vmovd ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  let n0 = AST.num0 64<rt>
  let regToReg r1 r2 =
    match Register.getKind r1, Register.getKind r2 with
    | Register.Kind.XMM, Register.Kind.GP ->
      let dstD, dstC, dstB, dstA = getPseudoRegVar256 ctxt (r128to256 dst)
      let src = getRegVar ctxt r2
      builder <! (dstAssign 32<rt> dstA src)
      builder <! (dstB := n0)
      builder <! (dstC := n0)
      builder <! (dstD := n0)
    | Register.Kind.GP, Register.Kind.XMM ->
      let dst = getRegVar ctxt r1
      let srcA = getPseudoRegVar ctxt r2 1
      builder <! (dstAssign oprSize dst (AST.xtlo 32<rt> srcA))
    | _ -> raise InvalidOperandException
  match dst, src with
  | OprReg r1, OprReg r2 -> regToReg r1 r2
  | OprReg r, OprMem _ ->
    let dstD, dstC, dstB, dstA = getPseudoRegVar256 ctxt (r128to256 dst)
    let src = transOprToExpr ins insAddr insLen ctxt src
    builder <! (dstAssign 32<rt> dstA src)
    builder <! (dstB := n0)
    builder <! (dstC := n0)
    builder <! (dstD := n0)
  | OprMem _, OprReg r ->
    let dst = transOprToExpr ins insAddr insLen ctxt dst
    let srcA = getPseudoRegVar ctxt r 1
    builder <! (dst := AST.xtlo 32<rt> srcA)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vmovq ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let dst, src = getTwoOprs ins
  startMark insAddr insLen builder
  let n0 = AST.num0 64<rt>
  let regToReg r1 r2 =
    match Register.getKind r1, Register.getKind r2 with
    | Register.Kind.XMM, Register.Kind.XMM ->
      let dstD, dstC, dstB, dstA = getPseudoRegVar256 ctxt (r128to256 dst)
      let srcA = getPseudoRegVar ctxt r2 1
      builder <! (dstA := srcA)
      builder <! (dstB := n0)
      builder <! (dstC := n0)
      builder <! (dstD := n0)
    | Register.Kind.XMM, Register.Kind.GP ->
      let dstD, dstC, dstB, dstA = getPseudoRegVar256 ctxt (r128to256 dst)
      let src = getRegVar ctxt r2
      builder <! (dstA := src)
      builder <! (dstB := n0)
      builder <! (dstC := n0)
      builder <! (dstD := n0)
    | Register.Kind.GP, Register.Kind.XMM ->
      let dst = getRegVar ctxt r1
      let srcA = getPseudoRegVar ctxt r2 1
      builder <! (dst := srcA)
    | _ -> raise InvalidOperandException
  match dst, src with
  | OprReg r1, OprReg r2 -> regToReg r1 r2
  | OprReg _, OprMem _ ->
    let dstD, dstC, dstB, dstA = getPseudoRegVar256 ctxt (r128to256 dst)
    let src = transOprToExpr ins insAddr insLen ctxt src
    builder <! (dstA := src)
    builder <! (dstB := n0)
    builder <! (dstC := n0)
    builder <! (dstD := n0)
  | OprMem _, OprReg r ->
    let dst = transOprToExpr ins insAddr insLen ctxt dst
    let srcA = getPseudoRegVar ctxt r 1
    builder <! (dst := srcA)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vmovdqu ins insAddr insLen ctxt =
  buildVectorMove ins insAddr insLen ctxt

let private fillZeroFromVLToMaxVL ctxt dst vl maxVl builder =
  let n0 = AST.num0 64<rt>
  match maxVl, vl with
  | 512, 128 ->
    let dst = r128to512 dst
    let dstC, dstD, dstE, dstF, dstG, dstH =
      getPseudoRegVar ctxt dst 3, getPseudoRegVar ctxt dst 4,
      getPseudoRegVar ctxt dst 5, getPseudoRegVar ctxt dst 6,
      getPseudoRegVar ctxt dst 7, getPseudoRegVar ctxt dst 8
    builder <! (dstC := n0)
    builder <! (dstD := n0)
    builder <! (dstE := n0)
    builder <! (dstF := n0)
    builder <! (dstG := n0)
    builder <! (dstH := n0)
  | 512, 256 ->
    let dst = r256to512 dst
    let dstE, dstF, dstG, dstH =
      getPseudoRegVar ctxt dst 5, getPseudoRegVar ctxt dst 6,
      getPseudoRegVar ctxt dst 7, getPseudoRegVar ctxt dst 8
    builder <! (dstE := n0)
    builder <! (dstF := n0)
    builder <! (dstG := n0)
    builder <! (dstH := n0)
  | _ -> Utils.impossible ()

let vmovdqu16 ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let oprSize = getOperationSize ins
  let ePrx = getEVEXPrx ins.VEXInfo
  let k = getRegVar ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
  let masking dst =
    match ePrx.Z with
    | Zeroing -> AST.num0 16<rt>
    | Merging -> dst
  let cond idx =
    (* no write mask *)
    let noWritemask = if ePrx.AAA = 0uy then AST.num1 1<rt> else AST.num0 1<rt>
    AST.extract k 1<rt> idx .| noWritemask
  startMark insAddr insLen builder
  match oprSize with
  | 128<rt> ->
    let kl, vl = 8, 128
    match dst with
    | OprReg _ ->
      let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
      let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
      let assign dst src idx =
        let pos = (idx % 4) * 16
        let dst = AST.extract dst 16<rt> pos
        dst := AST.ite (cond idx) (AST.extract src 16<rt> pos) (masking dst)
      builder <! (assign dstA srcA 0)
      builder <! (assign dstA srcA 1)
      builder <! (assign dstA srcA 2)
      builder <! (assign dstA srcA 3)
      builder <! (assign dstB srcB 4)
      builder <! (assign dstB srcB 5)
      builder <! (assign dstB srcB 6)
      builder <! (assign dstB srcB 7)
      fillZeroFromVLToMaxVL ctxt dst vl 512 builder
    | OprMem _ ->
      let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
      let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
      let tmps = Array.init 4 (fun _ -> AST.tmpvar 16<rt>)
      let assign dst src idx =
        for i in 0 .. 3 do
          let pos = i * 16
          let dst = AST.extract dst 16<rt> pos
          builder <!
            (tmps.[i] := AST.ite (cond (idx + i)) (AST.extract src 16<rt> pos) dst)
        AST.concatArr tmps
      builder <! (dstA := assign dstA srcA 0)
      builder <! (dstB := assign dstB srcB 4)
    | _ -> raise InvalidOperandException
  | 256<rt> ->
    let kl, vl = 16, 256
    match dst with
    | OprReg _ ->
      let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
      let srcD, srcC, srcB, srcA = transOprToExpr256 ins insAddr insLen ctxt src
      let assign dst src idx =
        let pos = (idx % 4) * 16
        let dst = AST.extract dst 16<rt> pos
        dst := AST.ite (cond idx) (AST.extract src 16<rt> pos) (masking dst)
      builder <! (assign dstA srcA 0)
      builder <! (assign dstA srcA 1)
      builder <! (assign dstA srcA 2)
      builder <! (assign dstA srcA 3)
      builder <! (assign dstB srcB 4)
      builder <! (assign dstB srcB 5)
      builder <! (assign dstB srcB 6)
      builder <! (assign dstB srcB 7)
      builder <! (assign dstC srcA 8)
      builder <! (assign dstC srcA 9)
      builder <! (assign dstC srcA 10)
      builder <! (assign dstC srcA 11)
      builder <! (assign dstD srcB 12)
      builder <! (assign dstD srcB 13)
      builder <! (assign dstD srcB 14)
      builder <! (assign dstD srcB 15)
      fillZeroFromVLToMaxVL ctxt dst vl 512 builder
    | OprMem _ ->
      let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
      let srcD, srcC, srcB, srcA = transOprToExpr256 ins insAddr insLen ctxt src
      let tmps = Array.init 4 (fun _ -> AST.tmpvar 16<rt>)
      let assign dst src idx =
        for i in 0 .. 3 do
          let pos = i * 16
          let dst = AST.extract dst 16<rt> pos
          builder <!
            (tmps.[i] := AST.ite (cond (idx + i)) (AST.extract src 16<rt> pos) dst)
        AST.concatArr tmps
      builder <! (dstA := assign dstA srcA 0)
      builder <! (dstB := assign dstB srcB 4)
      builder <! (dstC := assign dstC srcC 8)
      builder <! (dstD := assign dstD srcD 12)
    | _ -> raise InvalidOperandException
  | 512<rt> ->
    let kl, vl = 32, 512
    match dst with
    | OprReg _ ->
      let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
        transOprToExpr512 ins insAddr insLen ctxt dst
      let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
        transOprToExpr512 ins insAddr insLen ctxt src
      let assign dst src idx =
        let pos = (idx % 4) * 16
        let dst = AST.extract dst 16<rt> pos
        dst := AST.ite (cond idx) (AST.extract src 16<rt> pos) (masking dst)
      builder <! (assign dstA srcA 0)
      builder <! (assign dstA srcA 1)
      builder <! (assign dstA srcA 2)
      builder <! (assign dstA srcA 3)
      builder <! (assign dstB srcB 4)
      builder <! (assign dstB srcB 5)
      builder <! (assign dstB srcB 6)
      builder <! (assign dstB srcB 7)
      builder <! (assign dstC srcA 8)
      builder <! (assign dstC srcA 9)
      builder <! (assign dstC srcA 10)
      builder <! (assign dstC srcA 11)
      builder <! (assign dstD srcB 12)
      builder <! (assign dstD srcB 13)
      builder <! (assign dstD srcB 14)
      builder <! (assign dstD srcB 15)
      builder <! (assign dstF srcA 16)
      builder <! (assign dstF srcA 17)
      builder <! (assign dstF srcA 18)
      builder <! (assign dstF srcA 19)
      builder <! (assign dstG srcB 20)
      builder <! (assign dstG srcB 21)
      builder <! (assign dstG srcB 22)
      builder <! (assign dstG srcB 23)
      builder <! (assign dstH srcA 24)
      builder <! (assign dstH srcA 25)
      builder <! (assign dstH srcA 26)
      builder <! (assign dstH srcA 27)
      builder <! (assign dstG srcB 28)
      builder <! (assign dstG srcB 29)
      builder <! (assign dstG srcB 30)
      builder <! (assign dstG srcB 31)
    | OprMem _ ->
      let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
        transOprToExpr512 ins insAddr insLen ctxt dst
      let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
        transOprToExpr512 ins insAddr insLen ctxt src
      let tmps = Array.init 4 (fun _ -> AST.tmpvar 16<rt>)
      let assign dst src idx =
        for i in 0 .. 3 do
          let pos = i * 16
          let dst = AST.extract dst 16<rt> pos
          builder <!
            (tmps.[i] := AST.ite (cond (idx + i)) (AST.extract src 16<rt> pos) dst)
        AST.concatArr tmps
      builder <! (dstA := assign dstA srcA 0)
      builder <! (dstB := assign dstB srcB 4)
      builder <! (dstC := assign dstC srcC 8)
      builder <! (dstD := assign dstD srcD 12)
      builder <! (dstE := assign dstE srcE 16)
      builder <! (dstF := assign dstF srcF 20)
      builder <! (dstG := assign dstG srcG 24)
      builder <! (dstH := assign dstH srcH 28)
    | _ -> raise InvalidOperandException
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vmovdqu64 ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let oprSize = getOperationSize ins
  let ePrx = getEVEXPrx ins.VEXInfo
  let k = getRegVar ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
  let masking dst =
    match ePrx.Z with
    | Zeroing -> AST.num0 64<rt>
    | Merging -> dst
  let cond idx =
    if ePrx.AAA = 0uy then AST.num0 1<rt> (* no write mask *)
    else AST.extract k 1<rt> idx
  startMark insAddr insLen builder
  match oprSize with
  | 128<rt> ->
    let kl, vl = 4, 128
    match dst with
    | OprReg _ ->
      let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
      let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
      builder <! (dstA := AST.ite (cond 0) srcA (masking dstA))
      builder <! (dstB := AST.ite (cond 1) srcB (masking dstB))
      fillZeroFromVLToMaxVL ctxt dst vl 512 builder
    | OprMem _ ->
      let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
      let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
      builder <! (dstA := AST.ite (cond 0) srcA dstA)
      builder <! (dstB := AST.ite (cond 1) srcB dstB)
    | _ -> raise InvalidOperandException
  | 256<rt> ->
    let kl, vl = 8, 256
    match dst with
    | OprReg _ ->
      let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
      let srcD, srcC, srcB, srcA = transOprToExpr256 ins insAddr insLen ctxt src
      builder <! (dstA := AST.ite (cond 0) srcA (masking dstA))
      builder <! (dstB := AST.ite (cond 1) srcB (masking dstB))
      builder <! (dstC := AST.ite (cond 2) srcC (masking dstC))
      builder <! (dstD := AST.ite (cond 3) srcD (masking dstD))
      fillZeroFromVLToMaxVL ctxt dst vl 512 builder
    | OprMem _ ->
      let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
      let srcD, srcC, srcB, srcA = transOprToExpr256 ins insAddr insLen ctxt src
      builder <! (dstA := AST.ite (cond 0) srcA dstA)
      builder <! (dstB := AST.ite (cond 1) srcB dstB)
      builder <! (dstC := AST.ite (cond 2) srcC dstC)
      builder <! (dstD := AST.ite (cond 3) srcD dstD)
    | _ -> raise InvalidOperandException
  | 512<rt> ->
    let kl, vl = 16, 512
    match dst with
    | OprReg _ ->
      let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
        transOprToExpr512 ins insAddr insLen ctxt dst
      let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
        transOprToExpr512 ins insAddr insLen ctxt src
      builder <! (dstA := AST.ite (cond 0) srcA (masking dstA))
      builder <! (dstB := AST.ite (cond 1) srcB (masking dstB))
      builder <! (dstC := AST.ite (cond 2) srcC (masking dstC))
      builder <! (dstD := AST.ite (cond 3) srcD (masking dstD))
      builder <! (dstE := AST.ite (cond 4) srcE (masking dstE))
      builder <! (dstF := AST.ite (cond 5) srcF (masking dstF))
      builder <! (dstG := AST.ite (cond 6) srcG (masking dstG))
      builder <! (dstH := AST.ite (cond 7) srcH (masking dstH))
    | OprMem _ ->
      let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
        transOprToExpr512 ins insAddr insLen ctxt dst
      let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
        transOprToExpr512 ins insAddr insLen ctxt src
      builder <! (dstA := AST.ite (cond 0) srcA dstA)
      builder <! (dstB := AST.ite (cond 1) srcB dstB)
      builder <! (dstC := AST.ite (cond 2) srcC dstC)
      builder <! (dstD := AST.ite (cond 3) srcD dstD)
      builder <! (dstE := AST.ite (cond 4) srcE dstE)
      builder <! (dstF := AST.ite (cond 5) srcF dstF)
      builder <! (dstG := AST.ite (cond 6) srcG dstG)
      builder <! (dstH := AST.ite (cond 7) srcH dstH)
    | _ -> raise InvalidOperandException
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vmovdqa ins insAddr insLen ctxt = buildVectorMove ins insAddr insLen ctxt

let vmovdqa64 ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let oprSize = getOperationSize ins
  let ePrx = getEVEXPrx ins.VEXInfo
  let k = getRegVar ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
  let masking dst =
    match ePrx.Z with
    | Zeroing -> AST.num0 64<rt>
    | Merging -> dst
  let cond idx =
    (* no write mask *)
    let noWritemask = if ePrx.AAA = 0uy then AST.num1 1<rt> else AST.num0 1<rt>
    AST.extract k 1<rt> idx .| noWritemask
  startMark insAddr insLen builder
  match oprSize with
  | 128<rt> ->
    let kl, vl = 2, 128
    match dst with
    | OprReg _ ->
      let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
      let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
      builder <! (dstA := AST.ite (cond 0) srcA (masking dstA))
      builder <! (dstB := AST.ite (cond 1) srcB (masking dstB))
      fillZeroFromVLToMaxVL ctxt dst vl 512 builder
    | OprMem _ ->
      let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
      let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
      builder <! (dstA := AST.ite (cond 0) srcA dstA)
      builder <! (dstB := AST.ite (cond 1) srcB dstB)
    | _ -> raise InvalidOperandException
  | 256<rt> ->
    let kl, vl = 4, 256
    match dst with
    | OprReg _ ->
      let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
      let srcD, srcC, srcB, srcA = transOprToExpr256 ins insAddr insLen ctxt src
      builder <! (dstA := AST.ite (cond 0) srcA (masking dstA))
      builder <! (dstB := AST.ite (cond 1) srcB (masking dstB))
      builder <! (dstC := AST.ite (cond 2) srcC (masking dstC))
      builder <! (dstD := AST.ite (cond 3) srcD (masking dstD))
      fillZeroFromVLToMaxVL ctxt dst vl 512 builder
    | OprMem _ ->
      let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
      let srcD, srcC, srcB, srcA = transOprToExpr256 ins insAddr insLen ctxt src
      builder <! (dstA := AST.ite (cond 0) srcA dstA)
      builder <! (dstB := AST.ite (cond 1) srcB dstB)
      builder <! (dstC := AST.ite (cond 2) srcC dstC)
      builder <! (dstD := AST.ite (cond 3) srcD dstD)
    | _ -> raise InvalidOperandException
  | 512<rt> ->
    let kl, vl = 8, 512
    match dst with
    | OprReg _ ->
      let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
        transOprToExpr512 ins insAddr insLen ctxt dst
      let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
        transOprToExpr512 ins insAddr insLen ctxt src
      builder <! (dstA := AST.ite (cond 0) srcA (masking dstA))
      builder <! (dstB := AST.ite (cond 1) srcB (masking dstB))
      builder <! (dstC := AST.ite (cond 2) srcC (masking dstC))
      builder <! (dstD := AST.ite (cond 3) srcD (masking dstD))
      builder <! (dstE := AST.ite (cond 4) srcE (masking dstE))
      builder <! (dstF := AST.ite (cond 5) srcF (masking dstF))
      builder <! (dstG := AST.ite (cond 6) srcG (masking dstG))
      builder <! (dstH := AST.ite (cond 7) srcH (masking dstH))
    | OprMem _ ->
      let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
        transOprToExpr512 ins insAddr insLen ctxt dst
      let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
        transOprToExpr512 ins insAddr insLen ctxt src
      builder <! (dstA := AST.ite (cond 0) srcA dstA)
      builder <! (dstB := AST.ite (cond 1) srcB dstB)
      builder <! (dstC := AST.ite (cond 2) srcC dstC)
      builder <! (dstD := AST.ite (cond 3) srcD dstD)
      builder <! (dstE := AST.ite (cond 4) srcE dstE)
      builder <! (dstF := AST.ite (cond 5) srcF dstF)
      builder <! (dstG := AST.ite (cond 6) srcG dstG)
      builder <! (dstH := AST.ite (cond 7) srcH dstH)
    | _ -> raise InvalidOperandException
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vmovntdq ins insAddr insLen ctxt =
  SSELifter.buildMove ins insAddr insLen ctxt 16

let vmovups ins insAddr insLen ctxt =
  buildVectorMove ins insAddr insLen ctxt

let vmovupd ins insAddr insLen ctxt =
  buildVectorMove ins insAddr insLen ctxt

let vmovddup ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src = getTwoOprs ins
  startMark insAddr insLen builder
  match getOperationSize ins with
  | 128<rt> ->
    let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
    let src = transOprToExpr64 ins insAddr insLen ctxt src
    builder <! (dst1 := src)
    builder <! (dst2 := src)
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dst4, dst3, dst2, dst1 = transOprToExpr256 ins insAddr insLen ctxt dst
    let _src4, src3, _src2, src1 = transOprToExpr256 ins insAddr insLen ctxt src
    builder <! (dst1 := src1)
    builder <! (dst2 := src1)
    builder <! (dst3 := src3)
    builder <! (dst4 := src3)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vmovntps ins insAddr insLen ctxt =
  SSELifter.buildMove ins insAddr insLen ctxt 16

let vmovntpd ins insAddr insLen ctxt =
  SSELifter.buildMove ins insAddr insLen ctxt 16

let vmovhlps ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src1, src2 = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
  let src1B, _src1A = transOprToExpr128 ins insAddr insLen ctxt src1
  let src2B, _src2A = transOprToExpr128 ins insAddr insLen ctxt src2
  startMark insAddr insLen builder
  builder <! (dstA := src1B)
  builder <! (dstB := src2B)
  fillZeroHigh128 ctxt dst builder
  endMark insAddr insLen builder

let vmovhpd ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  startMark insAddr insLen builder
  match ins.Operands with
  | TwoOperands (dst, src) ->
    if haveEVEXPrx ins.VEXInfo then ()
    else
      let dst = transOprToExpr64 ins insAddr insLen ctxt dst
      let src2, _src1 = transOprToExpr128 ins insAddr insLen ctxt src
      builder <! (dst := src2)
  | ThreeOperands (dst, src1, src2)->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let _src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
    let src2 = transOprToExpr64 ins insAddr insLen ctxt src2
    builder <! (dstA := src1A)
    builder <! (dstB := src2)
    fillZeroHigh128 ctxt dst builder
  | _ -> raise InvalidOperandException
  endMark insAddr insLen builder

let vmovlhps ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src1, src2 = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
  let _src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
  let _src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt src2
  startMark insAddr insLen builder
  builder <! (dstA := src1A)
  builder <! (dstB := src2A)
  fillZeroHigh128 ctxt dst builder
  endMark insAddr insLen builder

let vmovlpd ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  startMark insAddr insLen builder
  match ins.Operands with
  | TwoOperands (dst, src) ->
    let dst = transOprToExpr64 ins insAddr insLen ctxt dst
    let _src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
    builder <! (dst := src1)
  | ThreeOperands (dst, src1, src2)->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let src1B, _src1A = transOprToExpr128 ins insAddr insLen ctxt src1
    let _src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt src2
    builder <! (dstA := src2A)
    builder <! (dstB := src1B)
    fillZeroHigh128 ctxt dst builder
  | _ -> raise InvalidOperandException
  endMark insAddr insLen builder

let vmovmskpd ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr ins insAddr insLen ctxt dst
  let dstSz = AST.typeOf dst
  let mskpd r =
    match Register.getKind r with
    | Register.Kind.XMM -> SSELifter.movmskpd ins insAddr insLen ctxt
    | Register.Kind.YMM ->
      startMark insAddr insLen builder
      let src4, src3, src2, src1 = transOprToExpr256 ins insAddr insLen ctxt src
      let src63 = AST.sext dstSz (AST.xthi 1<rt> src1)
      let src127 = (AST.sext dstSz (AST.xthi 1<rt> src2)) << AST.num1 dstSz
      let src191 = (AST.sext dstSz (AST.xthi 1<rt> src3)) << numI32 2 dstSz
      let src255 = (AST.sext dstSz (AST.xthi 1<rt> src4)) << numI32 3 dstSz
      builder <! (dst := src63 .| src127 .| src191 .| src255)
      endMark insAddr insLen builder
    | _ -> raise InvalidOperandException
  match src with
  | OprReg r -> mskpd r
  | _ -> raise InvalidOperandSizeException

let vmovmskps ins insAddr insLen ctxt =
  let builder = StmtBuilder (4)
  let dst, src = getTwoOprs ins
  let dst = transOprToExpr ins insAddr insLen ctxt dst
  let dstSz = AST.typeOf dst
  let mskpd r =
    match Register.getKind r with
    | Register.Kind.XMM -> SSELifter.movmskps ins insAddr insLen ctxt
    | Register.Kind.YMM ->
      startMark insAddr insLen builder
      let src4, src3, src2, src1 = transOprToExpr256 ins insAddr insLen ctxt src
      let src1A, src1B = AST.xtlo 32<rt> src1, AST.xthi 32<rt> src1
      let src2A, src2B = AST.xtlo 32<rt> src2, AST.xthi 32<rt> src2
      let src3A, src3B = AST.xtlo 32<rt> src3, AST.xthi 32<rt> src3
      let src4A, src4B = AST.xtlo 32<rt> src4, AST.xthi 32<rt> src4
      let src31 = AST.sext dstSz (AST.xthi 1<rt> src1A)
      let src63 = AST.sext dstSz (AST.xthi 1<rt> src1B) << AST.num1 dstSz
      let src95 = (AST.sext dstSz (AST.xthi 1<rt> src2A)) << numI32 2 dstSz
      let src127 = (AST.sext dstSz (AST.xthi 1<rt> src2B)) << numI32 3 dstSz
      let src159 = (AST.sext dstSz (AST.xthi 1<rt> src3A)) << numI32 4 dstSz
      let src191 = (AST.sext dstSz (AST.xthi 1<rt> src3B)) << numI32 5 dstSz
      let src223 = (AST.sext dstSz (AST.xthi 1<rt> src4A)) << numI32 6 dstSz
      let src255 = (AST.sext dstSz (AST.xthi 1<rt> src4B)) << numI32 7 dstSz
      builder <! (dst := src31 .| src63 .| src95 .| src127)
      builder <! (dst := dst .| src159 .| src191 .| src223 .| src255)
      endMark insAddr insLen builder
    | _ -> raise InvalidOperandException
  match src with
  | OprReg r -> mskpd r
  | _ -> raise InvalidOperandSizeException

let vmovsd ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  startMark insAddr insLen builder
  match ins.Operands with
  | TwoOperands (OprMem _ , _) -> SSELifter.movsd ins insAddr insLen ctxt
  | TwoOperands (OprReg _ as dst, src) ->
    let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
    let src = transOprToExpr64 ins insAddr insLen ctxt src
    builder <! (dst1 := src)
    builder <! (dst2 := AST.num0 64<rt>)
    fillZeroHigh128 ctxt dst builder
    endMark insAddr insLen builder
  | ThreeOperands (dst, src1, src2)->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let src1B, _src1A = transOprToExpr128 ins insAddr insLen ctxt src1
    let _src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt src2
    builder <! (dstA := src2A)
    builder <! (dstB := src1B)
    fillZeroHigh128 ctxt dst builder
    endMark insAddr insLen builder
  | _ -> raise InvalidOperandException

let vmovshdup ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let dst, src = getTwoOprs ins
  startMark insAddr insLen builder
  match getOperationSize ins with
  | 128<rt> ->
    let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
    let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
    builder <! (AST.xtlo 32<rt> dst1 := AST.xthi 32<rt> src1)
    builder <! (AST.xthi 32<rt> dst1 := AST.xthi 32<rt> src1)
    builder <! (AST.xtlo 32<rt> dst2 := AST.xthi 32<rt> src2)
    builder <! (AST.xthi 32<rt> dst2 := AST.xthi 32<rt> src2)
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dst4, dst3, dst2, dst1 = transOprToExpr256 ins insAddr insLen ctxt dst
    let src4, src3, src2, src1 = transOprToExpr256 ins insAddr insLen ctxt src
    builder <! (AST.xtlo 32<rt> dst1 := AST.xthi 32<rt> src1)
    builder <! (AST.xthi 32<rt> dst1 := AST.xthi 32<rt> src1)
    builder <! (AST.xtlo 32<rt> dst2 := AST.xthi 32<rt> src2)
    builder <! (AST.xthi 32<rt> dst2 := AST.xthi 32<rt> src2)
    builder <! (AST.xtlo 32<rt> dst3 := AST.xthi 32<rt> src3)
    builder <! (AST.xthi 32<rt> dst3 := AST.xthi 32<rt> src3)
    builder <! (AST.xtlo 32<rt> dst4 := AST.xthi 32<rt> src4)
    builder <! (AST.xthi 32<rt> dst4 := AST.xthi 32<rt> src4)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vmovsldup ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let dst, src = getTwoOprs ins
  startMark insAddr insLen builder
  match getOperationSize ins with
  | 128<rt> ->
    let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
    let src2, src1 = transOprToExpr128 ins insAddr insLen ctxt src
    builder <! (AST.xtlo 32<rt> dst1 := AST.xtlo 32<rt> src1)
    builder <! (AST.xthi 32<rt> dst1 := AST.xtlo 32<rt> src1)
    builder <! (AST.xtlo 32<rt> dst2 := AST.xtlo 32<rt> src2)
    builder <! (AST.xthi 32<rt> dst2 := AST.xtlo 32<rt> src2)
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dst4, dst3, dst2, dst1 = transOprToExpr256 ins insAddr insLen ctxt dst
    let src4, src3, src2, src1 = transOprToExpr256 ins insAddr insLen ctxt src
    builder <! (AST.xtlo 32<rt> dst1 := AST.xtlo 32<rt> src1)
    builder <! (AST.xthi 32<rt> dst1 := AST.xtlo 32<rt> src1)
    builder <! (AST.xtlo 32<rt> dst2 := AST.xtlo 32<rt> src2)
    builder <! (AST.xthi 32<rt> dst2 := AST.xtlo 32<rt> src2)
    builder <! (AST.xtlo 32<rt> dst3 := AST.xtlo 32<rt> src3)
    builder <! (AST.xthi 32<rt> dst3 := AST.xtlo 32<rt> src3)
    builder <! (AST.xtlo 32<rt> dst4 := AST.xtlo 32<rt> src4)
    builder <! (AST.xthi 32<rt> dst4 := AST.xtlo 32<rt> src4)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vmovss ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  startMark insAddr insLen builder
  match ins.Operands with
  | TwoOperands (OprMem _ , _) -> SSELifter.movss ins insAddr insLen ctxt
  | TwoOperands (OprReg _ as dst, src) ->
    let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
    let src = transOprToExpr32 ins insAddr insLen ctxt src
    builder <! (AST.xtlo 32<rt> dst1 := src)
    builder <! (AST.xthi 32<rt> dst1 := AST.num0 32<rt>)
    builder <! (dst2 := AST.num0 64<rt>)
    fillZeroHigh128 ctxt dst builder
    endMark insAddr insLen builder
  | ThreeOperands (dst, src1, src2)->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
    let _src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt src2
    builder <! (AST.xtlo 32<rt> dstA := AST.xtlo 32<rt> src2A)
    builder <! (AST.xthi 32<rt> dstA := AST.xthi 32<rt> src1A)
    builder <! (dstB := src1B)
    fillZeroHigh128 ctxt dst builder
    endMark insAddr insLen builder
  | _ -> raise InvalidOperandException

let vandps ins insAddr insLen ctxt =
  vexedPackedFPBinOp32 ins insAddr insLen ctxt (.&)

let vandpd ins insAddr insLen ctxt =
  vexedPackedFPBinOp64 ins insAddr insLen ctxt (.&)

let private andnpdOp e1 e2 = (AST.not e1) .& e2

let vandnps ins insAddr insLen ctxt =
  vexedPackedFPBinOp32 ins insAddr insLen ctxt andnpdOp

let vandnpd ins insAddr insLen ctxt =
  vexedPackedFPBinOp64 ins insAddr insLen ctxt andnpdOp

let vorps ins insAddr insLen ctxt =
  vexedPackedFPBinOp32 ins insAddr insLen ctxt (.|)

let vorpd ins insAddr insLen ctxt =
  vexedPackedFPBinOp64 ins insAddr insLen ctxt (.|)

let vshufi32x4 ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let dst, src1, src2, imm = getFourOprs ins
  let oprSize = getOperationSize ins
  let ePrx = getEVEXPrx ins.VEXInfo
  let k = getRegVar ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
  let masking dst =
    match ePrx.Z with
    | Zeroing -> AST.num0 32<rt>
    | Merging -> dst
  let cond idx =
    (* no write mask *)
    let noWritemask = if ePrx.AAA = 0uy then AST.num1 1<rt> else AST.num0 1<rt>
    AST.extract k 1<rt> idx .| noWritemask
  let imm = transOprToExpr ins insAddr insLen ctxt imm
  let tmpDest, tmp = tmpVars2 oprSize
  startMark insAddr insLen builder
  match oprSize with
  | 256<rt> ->
    let kl, vl = 8, 256
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
    let src1D, src1C, src1B, src1A =
      transOprToExpr256 ins insAddr insLen ctxt src1
    let src2D, src2C, src2B, src2A =
      transOprToExpr256 ins insAddr insLen ctxt src2
    let conSrc1 = AST.concat (AST.concat src1D src1C) (AST.concat src1B src1A)
    let conSrc2 = AST.concat (AST.concat src2D src2C) (AST.concat src2B src2A)
    let srcLow src = AST.extract src 128<rt> 0
    let srcHigh src = AST.extract src 128<rt> 128
    let select2 src pos = AST.ite (AST.extract imm 1<rt> pos) (srcHigh src) (srcLow src)
    builder <! (AST.extract tmpDest 128<rt> 0 := select2 conSrc1 0)
    builder <! (AST.extract tmpDest 128<rt> 128 := select2 conSrc2 1)
    let assign dst idx dstPos tmpPos =
      let dst = AST.extract dst 32<rt> dstPos
      dst := AST.ite (cond idx) (AST.extract tmpDest 32<rt> tmpPos) (masking dst)
    builder <! (assign dstA 0 0 0)
    builder <! (assign dstA 1 32 32)
    builder <! (assign dstB 2 0 64)
    builder <! (assign dstB 3 32 96)
    builder <! (assign dstC 4 0 128)
    builder <! (assign dstC 5 32 160)
    builder <! (assign dstD 6 0 192)
    builder <! (assign dstD 7 32 224)
  | 512<rt> ->
    let kl, vl = 16, 512
    let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
      transOprToExpr512 ins insAddr insLen ctxt dst
    let src1H, src1G, src1F, src1E, src1D, src1C, src1B, src1A =
      transOprToExpr512 ins insAddr insLen ctxt src1
    let src2H, src2G, src2F, src2E, src2D, src2C, src2B, src2A =
      transOprToExpr512 ins insAddr insLen ctxt src2
    let conSrc1 = AST.concat (AST.concat (AST.concat src1H src1G) (AST.concat src1F src1E))
                         (AST.concat (AST.concat src1D src1C) (AST.concat src1B src1A))
    let conSrc2 = AST.concat (AST.concat (AST.concat src2H src2G) (AST.concat src2F src2E))
                         (AST.concat (AST.concat src2D src2C) (AST.concat src2B src2A))
    let src128 src = AST.extract src 128<rt> 0
    let src256 src = AST.extract src 128<rt> 128
    let src384 src = AST.extract src 128<rt> 256
    let src512 src = AST.extract src 128<rt> 384
    let n0 = AST.num0 2<rt>
    let n1 = AST.num1 2<rt>
    let n2 = numI32 2 2<rt>
    let control pos = AST.extract imm 2<rt> pos
    let select4 src pos =
      let control = control pos
      AST.ite (control == n0) (src128 src)
       (AST.ite (control == n1) (src256 src) (AST.ite (control == n2) (src384 src)
                                             (src512 src)))
    let tmpSrc2 = Array.init kl (fun _ -> AST.tmpvar 32<rt>)
    for i in 0 .. kl - 1 do
      let tSrc2 =
        match src2 with
          | OprMem _ when ePrx.B = 1uy -> AST.extract src2A 32<rt> 0
          | _ -> AST.extract conSrc2 32<rt> (i * 32)
      builder <! (tmpSrc2.[i] := tSrc2)
    let tmpSrc2 = AST.concatArr tmpSrc2
    builder <! (AST.extract tmpDest 128<rt> 0 := select4 conSrc1 0)
    builder <! (AST.extract tmpDest 128<rt> 128 := select4 conSrc2 2)
    builder <! (AST.extract tmpDest 128<rt> 256 := select4 tmpSrc2 4)
    builder <! (AST.extract tmpDest 128<rt> 384 := select4 tmpSrc2 6)
    let assign dst idx dstPos tmpPos =
      let dst = AST.extract dst 32<rt> dstPos
      dst := AST.ite (cond idx) (AST.extract tmpDest 32<rt> tmpPos) (masking dst)
    builder <! (assign dstA 0 0 0)
    builder <! (assign dstA 1 32 32)
    builder <! (assign dstB 2 0 64)
    builder <! (assign dstB 3 32 96)
    builder <! (assign dstC 4 0 128)
    builder <! (assign dstC 5 32 160)
    builder <! (assign dstD 6 0 192)
    builder <! (assign dstD 7 32 224)
    builder <! (assign dstE 8 0 256)
    builder <! (assign dstE 9 32 288)
    builder <! (assign dstF 10 0 320)
    builder <! (assign dstF 11 32 352)
    builder <! (assign dstG 12 0 384)
    builder <! (assign dstG 13 32 416)
    builder <! (assign dstH 14 0 448)
    builder <! (assign dstH 15 32 480)
  | _ -> raise InvalidOperandException
  endMark insAddr insLen builder

let vshufps ins insAddr insLen ctxt =
  let builder = StmtBuilder (32)
  let dst, src1, src2, imm = getFourOprs ins
  let imm = transOprToExpr ins insAddr insLen ctxt imm
  let cond1 = AST.xtlo 2<rt> imm
  let cond2 = AST.extract imm 2<rt> 2
  let cond3 = AST.extract imm 2<rt> 4
  let cond4 = AST.extract imm 2<rt> 6
  let doShuf cond dst e1 e2 =
    builder <! (dst := AST.num0 32<rt>)
    builder <! (dst := AST.ite (cond == AST.num0 2<rt>) (AST.xtlo 32<rt> e1) dst)
    builder <! (dst := AST.ite (cond == AST.num1 2<rt>) (AST.xthi 32<rt> e1) dst)
    builder <! (dst := AST.ite (cond == numI32 2 2<rt>) (AST.xtlo 32<rt> e2) dst)
    builder <! (dst := AST.ite (cond == numI32 3 2<rt>) (AST.xthi 32<rt> e2) dst)
  startMark insAddr insLen builder
  match getOperationSize ins with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let sr1B, sr1A = transOprToExpr128 ins insAddr insLen ctxt src1
    let sr2B, sr2A = transOprToExpr128 ins insAddr insLen ctxt src2
    doShuf cond1 (AST.xtlo 32<rt> dstA) sr1A sr1B
    doShuf cond2 (AST.xthi 32<rt> dstA) sr1A sr1B
    doShuf cond3 (AST.xtlo 32<rt> dstB) sr2A sr2B
    doShuf cond4 (AST.xthi 32<rt> dstB) sr2A sr2B
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
    let sr1D, sr1C, sr1B, sr1A = transOprToExpr256 ins insAddr insLen ctxt src1
    let sr2D, sr2C, sr2B, sr2A = transOprToExpr256 ins insAddr insLen ctxt src2
    doShuf cond1 (AST.xtlo 32<rt> dstA) sr1A sr1B
    doShuf cond2 (AST.xthi 32<rt> dstA) sr1A sr1B
    doShuf cond3 (AST.xtlo 32<rt> dstB) sr2A sr2B
    doShuf cond4 (AST.xthi 32<rt> dstB) sr2A sr2B
    doShuf cond1 (AST.xtlo 32<rt> dstC) sr1C sr1D
    doShuf cond2 (AST.xthi 32<rt> dstC) sr1C sr1D
    doShuf cond3 (AST.xtlo 32<rt> dstD) sr2C sr2D
    doShuf cond4 (AST.xthi 32<rt> dstD) sr2C sr2D
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vshufpd ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src1, src2, imm = getFourOprs ins
  let imm = transOprToExpr ins insAddr insLen ctxt imm
  let cond1 = AST.xtlo 1<rt> imm
  let cond2 = AST.extract imm 1<rt> 1
  let cond3 = AST.extract imm 1<rt> 2
  let cond4 = AST.extract imm 1<rt> 3
  startMark insAddr insLen builder
  match getOperationSize ins with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
    let src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt src2
    builder <! (dstA := AST.ite cond1 src1B src1A)
    builder <! (dstB := AST.ite cond2 src2B src2A)
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
    let sr1D, sr1C, sr1B, sr1A = transOprToExpr256 ins insAddr insLen ctxt src1
    let sr2D, sr2C, sr2B, sr2A = transOprToExpr256 ins insAddr insLen ctxt src2
    builder <! (dstA := AST.ite cond1 sr1B sr1A)
    builder <! (dstB := AST.ite cond2 sr2B sr2A)
    builder <! (dstC := AST.ite cond3 sr1C sr1D)
    builder <! (dstB := AST.ite cond4 sr2C sr2D)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vunpckhps ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let dst, src1, src2 = getThreeOprs ins
  startMark insAddr insLen builder
  match getOperationSize ins with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let src1B, _src1A = transOprToExpr128 ins insAddr insLen ctxt src1
    let src2B, _src2A = transOprToExpr128 ins insAddr insLen ctxt src2
    builder <! (AST.xtlo 32<rt> dstA := AST.xtlo 32<rt> src1B)
    builder <! (AST.xthi 32<rt> dstA := AST.xtlo 32<rt> src2B)
    builder <! (AST.xtlo 32<rt> dstB := AST.xthi 32<rt> src1B)
    builder <! (AST.xthi 32<rt> dstB := AST.xthi 32<rt> src2B)
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
    let sr1D, _, sr1B, _ = transOprToExpr256 ins insAddr insLen ctxt src1
    let sr2D, _, sr2B, _ = transOprToExpr256 ins insAddr insLen ctxt src2
    builder <! (AST.xtlo 32<rt> dstA := AST.xtlo 32<rt> sr1B)
    builder <! (AST.xthi 32<rt> dstA := AST.xtlo 32<rt> sr2B)
    builder <! (AST.xtlo 32<rt> dstB := AST.xthi 32<rt> sr1B)
    builder <! (AST.xthi 32<rt> dstB := AST.xthi 32<rt> sr2B)
    builder <! (AST.xtlo 32<rt> dstC := AST.xtlo 32<rt> sr1D)
    builder <! (AST.xthi 32<rt> dstC := AST.xtlo 32<rt> sr2D)
    builder <! (AST.xtlo 32<rt> dstD := AST.xthi 32<rt> sr1D)
    builder <! (AST.xthi 32<rt> dstD := AST.xthi 32<rt> sr2D)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vunpckhpd ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src1, src2 = getThreeOprs ins
  startMark insAddr insLen builder
  match getOperationSize ins with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let src1B, _src1A = transOprToExpr128 ins insAddr insLen ctxt src1
    let src2B, _src2A = transOprToExpr128 ins insAddr insLen ctxt src2
    builder <! (dstA := src1B)
    builder <! (dstB := src2B)
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
    let sr1D, _, sr1B, _ = transOprToExpr256 ins insAddr insLen ctxt src1
    let sr2D, _, sr2B, _ = transOprToExpr256 ins insAddr insLen ctxt src2
    builder <! (dstA := sr1B)
    builder <! (dstB := sr2B)
    builder <! (dstC := sr1D)
    builder <! (dstD := sr2D)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vunpcklps ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let dst, src1, src2 = getThreeOprs ins
  startMark insAddr insLen builder
  match getOperationSize ins with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let _src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
    let _src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt src2
    builder <! (AST.xtlo 32<rt> dstA := AST.xtlo 32<rt> src1A)
    builder <! (AST.xthi 32<rt> dstA := AST.xtlo 32<rt> src2A)
    builder <! (AST.xtlo 32<rt> dstB := AST.xthi 32<rt> src1A)
    builder <! (AST.xthi 32<rt> dstB := AST.xthi 32<rt> src2A)
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
    let _, src1C, _, src1A = transOprToExpr256 ins insAddr insLen ctxt src1
    let _, src2C, _, src2A = transOprToExpr256 ins insAddr insLen ctxt src2
    builder <! (AST.xtlo 32<rt> dstA := AST.xtlo 32<rt> src1A)
    builder <! (AST.xthi 32<rt> dstA := AST.xtlo 32<rt> src2A)
    builder <! (AST.xtlo 32<rt> dstB := AST.xthi 32<rt> src1A)
    builder <! (AST.xthi 32<rt> dstB := AST.xthi 32<rt> src2A)
    builder <! (AST.xtlo 32<rt> dstC := AST.xtlo 32<rt> src1C)
    builder <! (AST.xthi 32<rt> dstC := AST.xtlo 32<rt> src2C)
    builder <! (AST.xtlo 32<rt> dstD := AST.xthi 32<rt> src1C)
    builder <! (AST.xthi 32<rt> dstD := AST.xthi 32<rt> src2C)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vunpcklpd ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src1, src2 = getThreeOprs ins
  startMark insAddr insLen builder
  match getOperationSize ins with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let _src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
    let _src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt src2
    builder <! (dstA := src1A)
    builder <! (dstB := src2A)
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
    let _, src1C, _, src1A = transOprToExpr256 ins insAddr insLen ctxt src1
    let _, src2C, _, src2A = transOprToExpr256 ins insAddr insLen ctxt src2
    builder <! (dstA := src1A)
    builder <! (dstB := src2A)
    builder <! (dstC := src1C)
    builder <! (dstD := src2C)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vxorps ins insAddr insLen ctxt =
  match getOperationSize ins with
  | 512<rt> ->
    let builder = StmtBuilder (16)
    let dst, src1, src2 = getThreeOprs ins
    startMark insAddr insLen builder
    let ePrx = getEVEXPrx ins.VEXInfo
    let k = getRegVar ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
    let masking dst =
      match ePrx.Z with
      | Zeroing -> AST.num0 32<rt>
      | Merging -> dst
    let cond idx =
      (* no write mask *)
      let noWritemask = if ePrx.AAA = 0uy then AST.num1 1<rt> else AST.num0 1<rt>
      AST.extract k 1<rt> idx .| noWritemask
    let tmpDest = Array.init 2 (fun _ -> AST.tmpvar 32<rt>)
    let evAssign dst s1 s2 src2A idx =
      for i in 0 .. 1 do
        let s1 = AST.extract s1 32<rt> (i * 32)
        let s2 = AST.extract s2 32<rt> (i * 32)
        let dst = AST.extract dst 32<rt> (i * 32)
        let tSrc =
          match src2 with
          | OprMem _ when ePrx.AAA (* B *) = 1uy ->
            s1 <+> (AST.extract src2A 32<rt> 0)
          | _ -> s1 <+> s2
        builder <! (tmpDest.[i] := AST.ite (cond (idx + i)) tSrc (masking dst))
      AST.concatArr tmpDest
    let kl, vl = 16, 512
    let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
      transOprToExpr512 ins insAddr insLen ctxt dst
    let src1H, src1G, src1F, src1E, src1D, src1C, src1B, src1A =
      transOprToExpr512 ins insAddr insLen ctxt src1
    let src2H, src2G, src2F, src2E, src2D, src2C, src2B, src2A =
      transOprToExpr512 ins insAddr insLen ctxt src2
    builder <! (dstA := evAssign dstA src1A src2A src2A 0)
    builder <! (dstB := evAssign dstB src1B src2B src2A 2)
    builder <! (dstC := evAssign dstC src1C src2C src2A 4)
    builder <! (dstD := evAssign dstD src1D src2D src2A 6)
    builder <! (dstE := evAssign dstE src1E src2E src2A 8)
    builder <! (dstF := evAssign dstF src1F src2F src2A 10)
    builder <! (dstG := evAssign dstG src1G src2G src2A 12)
    builder <! (dstH := evAssign dstH src1H src2H src2A 14)
    endMark insAddr insLen builder
  | _ -> vexedPackedFPBinOp32 ins insAddr insLen ctxt (<+>)

let vxorpd ins insAddr insLen ctxt =
  vexedPackedFPBinOp64 ins insAddr insLen ctxt (<+>)

let vbroadcasti128 ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
  let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
  startMark insAddr insLen builder
  builder <! (dstA := srcA)
  builder <! (dstB := srcB)
  builder <! (dstC := srcA)
  builder <! (dstD := srcB)
  endMark insAddr insLen builder

let vbroadcastss ins insAddr insLen ctxt =
  let builder = StmtBuilder (32)
  let dst, src = getTwoOprs ins
  let src = transOprToExpr32 ins insAddr insLen ctxt src
  let tmp = AST.tmpvar 32<rt>
  startMark insAddr insLen builder
  match getOperationSize ins with
  | 128<rt> ->
    let dst2, dst1 = transOprToExpr128 ins insAddr insLen ctxt dst
    builder <! (tmp := src)
    builder <! (AST.xtlo 32<rt> dst1 := tmp)
    builder <! (AST.xthi 32<rt> dst1 := tmp)
    builder <! (AST.xtlo 32<rt> dst2 := tmp)
    builder <! (AST.xthi 32<rt> dst2 := tmp)
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dst4, dst3, dst2, dst1 = transOprToExpr256 ins insAddr insLen ctxt dst
    builder <! (tmp := src)
    builder <! (AST.xtlo 32<rt> dst1 := tmp)
    builder <! (AST.xthi 32<rt> dst1 := tmp)
    builder <! (AST.xtlo 32<rt> dst2 := tmp)
    builder <! (AST.xthi 32<rt> dst2 := tmp)
    builder <! (AST.xtlo 32<rt> dst3 := tmp)
    builder <! (AST.xthi 32<rt> dst3 := tmp)
    builder <! (AST.xtlo 32<rt> dst4 := tmp)
    builder <! (AST.xthi 32<rt> dst4 := tmp)
  | 512<rt> -> ()
  | _ -> raise InvalidOperandException
  endMark insAddr insLen builder

let vextracti32x8 ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src, imm = getThreeOprs ins
  let oprSize = getOperationSize ins
  let ePrx = getEVEXPrx ins.VEXInfo
  let k = getRegVar ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
  let masking dst =
    match ePrx.Z with
    | Zeroing -> AST.num0 32<rt>
    | Merging -> dst
  let cond idx =
    (* no write mask *)
    let noWritemask = if ePrx.AAA = 0uy then AST.num1 1<rt> else AST.num0 1<rt>
    AST.extract k 1<rt> idx .| noWritemask
  let tDest = AST.tmpvar 256<rt>
  let vl = 512
  let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
  let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
    transOprToExpr512 ins insAddr insLen ctxt src
  let imm = transOprToExpr ins insAddr insLen ctxt imm
  startMark insAddr insLen builder
  let srcLow = AST.concat (AST.concat srcD srcC) (AST.concat srcB srcA)
  let srcHigh = AST.concat (AST.concat srcH srcG) (AST.concat srcF srcE)
  builder <! (tDest := AST.ite (AST.xtlo 1<rt> imm) srcHigh srcLow)
  match dst with
  | OprReg _ ->
    let tmps = Array.init 2 (fun _ -> AST.tmpvar 32<rt>)
    let assign dst src idx =
      for i in 0 .. 1 do
        let dstPos = i * 32
        let srcPos = 32 * (idx + i)
        let dst = AST.extract dst 32<rt> dstPos
        let src = AST.extract src 32<rt> srcPos
        builder <!
          (tmps.[i] := AST.ite (cond (idx + i)) src (masking dst))
      AST.concatArr tmps
    builder <! (dstA := assign dstA tDest 0)
    builder <! (dstB := assign dstB tDest 2)
    builder <! (dstC := assign dstC tDest 4)
    builder <! (dstD := assign dstD tDest 6)
  | OprMem _ ->
    let tmps = Array.init 2 (fun _ -> AST.tmpvar 32<rt>)
    let assign dst src idx =
      for i in 0 .. 1 do
        let dstPos = i * 32
        let srcPos = 32 * (idx + i)
        let dst = AST.extract dst 32<rt> dstPos
        builder <!
          (tmps.[i] := AST.ite (cond (idx + i)) (AST.extract src 32<rt> srcPos) dst)
      AST.concatArr tmps
    builder <! (dstA := assign dstA tDest 0)
    builder <! (dstB := assign dstB tDest 2)
    builder <! (dstC := assign dstC tDest 4)
    builder <! (dstD := assign dstD tDest 6)
  | _ -> raise InvalidOperandException
  endMark insAddr insLen builder

let vextracti64x4 ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src, imm = getThreeOprs ins
  let oprSize = getOperationSize ins
  let ePrx = getEVEXPrx ins.VEXInfo
  let k = getRegVar ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
  let masking dst =
    match ePrx.Z with
    | Zeroing -> AST.num0 64<rt>
    | Merging -> dst
  let cond idx =
    (* no write mask *)
    let noWritemask = if ePrx.AAA = 0uy then AST.num1 1<rt> else AST.num0 1<rt>
    AST.extract k 1<rt> idx .| noWritemask
  let tDest = AST.tmpvar 256<rt>
  let vl = 512
  let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
  let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
    transOprToExpr512 ins insAddr insLen ctxt src
  let imm = transOprToExpr ins insAddr insLen ctxt imm
  startMark insAddr insLen builder
  let srcLow = AST.concat (AST.concat srcD srcC) (AST.concat srcB srcA)
  let srcHigh = AST.concat (AST.concat srcH srcG) (AST.concat srcF srcE)
  builder <! (tDest := AST.ite (AST.xtlo 1<rt> imm) srcHigh srcLow)
  match dst with
  | OprReg _ ->
    builder <! (dstA := AST.ite (cond 0) (AST.extract tDest 64<rt> 0) (masking dstA))
    builder <! (dstB := AST.ite (cond 1) (AST.extract tDest 64<rt> 64) (masking dstB))
    builder <! (dstC := AST.ite (cond 2) (AST.extract tDest 64<rt> 128) (masking dstC))
    builder <! (dstD := AST.ite (cond 3) (AST.extract tDest 64<rt> 192) (masking dstD))
  | OprMem _ ->
    builder <! (dstA := AST.ite (cond 0) (AST.extract tDest 64<rt> 0) dstA)
    builder <! (dstB := AST.ite (cond 1) (AST.extract tDest 64<rt> 64) dstB)
    builder <! (dstC := AST.ite (cond 2) (AST.extract tDest 64<rt> 128) dstC)
    builder <! (dstD := AST.ite (cond 3) (AST.extract tDest 64<rt> 192) dstD)
  | _ -> raise InvalidOperandException
  endMark insAddr insLen builder

let vinserti128 ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src1, src2, imm = getFourOprs ins
  let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
  let src1D, src1C, src1B, src1A = transOprToExpr256 ins insAddr insLen ctxt src1
  let src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt src2
  let imm = transOprToExpr ins insAddr insLen ctxt imm
  let cond = AST.tmpvar 1<rt>
  startMark insAddr insLen builder
  builder <! (cond := AST.xtlo 1<rt> imm)
  builder <! (dstA := AST.ite cond src1A src2A)
  builder <! (dstB := AST.ite cond src1B src2B)
  builder <! (dstC := AST.ite cond src2A src1C)
  builder <! (dstD := AST.ite cond src2B src1D)
  endMark insAddr insLen builder

let vpaddb ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 8<rt> (opP (.+)) 32

let vpaddd ins insAddr insLen ctxt =
  match getOperationSize ins with
  | 512<rt> ->
    let builder = StmtBuilder (16)
    let dst, src1, src2 = getThreeOprs ins
    startMark insAddr insLen builder
    let ePrx = getEVEXPrx ins.VEXInfo
    let k = getRegVar ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
    let masking dst =
      match ePrx.Z with
      | Zeroing -> AST.num0 32<rt>
      | Merging -> dst
    let cond idx =
      (* no write mask *)
      let noWritemask = if ePrx.AAA = 0uy then AST.num1 1<rt> else AST.num0 1<rt>
      AST.extract k 1<rt> idx .| noWritemask
    let tmpDest = Array.init 2 (fun _ -> AST.tmpvar 32<rt>)
    let evAssign dst s1 s2 src2A idx =
      for i in 0 .. 1 do
        let s1 = AST.extract s1 32<rt> (i * 32)
        let s2 = AST.extract s2 32<rt> (i * 32)
        let dst = AST.extract dst 32<rt> (i * 32)
        let tSrc =
          match src2 with
          | OprMem _ when ePrx.AAA (* B *) = 1uy ->
            s1 .+ (AST.extract src2A 32<rt> 0)
          | _ -> s1 .+ s2
        builder <! (tmpDest.[i] := AST.ite (cond (idx + i)) tSrc (masking dst))
      AST.concatArr tmpDest
    let kl, vl = 16, 512
    let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
      transOprToExpr512 ins insAddr insLen ctxt dst
    let src1H, src1G, src1F, src1E, src1D, src1C, src1B, src1A =
      transOprToExpr512 ins insAddr insLen ctxt src1
    let src2H, src2G, src2F, src2E, src2D, src2C, src2B, src2A =
      transOprToExpr512 ins insAddr insLen ctxt src2
    builder <! (dstA := evAssign dstA src1A src2A src2A 0)
    builder <! (dstB := evAssign dstB src1B src2B src2A 2)
    builder <! (dstC := evAssign dstC src1C src2C src2A 4)
    builder <! (dstD := evAssign dstD src1D src2D src2A 6)
    builder <! (dstE := evAssign dstE src1E src2E src2A 8)
    builder <! (dstF := evAssign dstF src1F src2F src2A 10)
    builder <! (dstG := evAssign dstG src1G src2G src2A 12)
    builder <! (dstH := evAssign dstH src1H src2H src2A 14)
    endMark insAddr insLen builder
  | _ -> buildPackedInstr ins insAddr insLen ctxt 32<rt> (opP (.+)) 16

let vpaddq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> (opP (.+)) 16

let vpalignr ins insAddr insLen ctxt =
  let builder = StmtBuilder (16)
  let dst, src1, src2, imm = getFourOprs ins
  let oprSize = getOperationSize ins
  let imm = transOprToExpr ins insAddr insLen ctxt imm
  let n8 = numU32 8u 256<rt>
  let imm = AST.zext 256<rt> imm
  startMark insAddr insLen builder
  if oprSize = 128<rt> then
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
    let src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt src2
    let t = AST.tmpvar 256<rt>
    let tSrc1, tSrc2 = tmpVars2 oprSize
    builder <! (tSrc1 := AST.concat src1B src1A)
    builder <! (tSrc2 := AST.concat src2B src2A)
    builder <! (t := (AST.concat tSrc1 tSrc2) >> (imm .* n8))
    builder <! (dstA := AST.xtlo 64<rt> t)
    builder <! (dstB := AST.xthi 64<rt> (AST.xtlo 128<rt> t))
    fillZeroHigh128 ctxt dst builder
  elif oprSize = 256<rt> then
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
    let src1D, src1C, src1B, src1A = transOprToExpr256 ins insAddr insLen ctxt src1
    let src2D, src2C, src2B, src2A = transOprToExpr256 ins insAddr insLen ctxt src2
    let t1, t2 = tmpVars2 256<rt>
    let tSrc1High, tSrc1Low, tSrc2High, tSrc2Low = tmpVars4 128<rt>
    builder <! (tSrc1Low := AST.concat src1B src1A)
    builder <! (tSrc1High := AST.concat src1D src1C)
    builder <! (tSrc2Low := AST.concat src2B src2A)
    builder <! (tSrc2High := AST.concat src2D src2C)
    builder <! (t1 := (AST.concat tSrc1Low tSrc2Low) >> (imm .* n8))
    builder <! (dstA := AST.xtlo 64<rt> t1)
    builder <! (dstB := AST.xthi 64<rt> (AST.xtlo 128<rt> t1))
    builder <! (t2 := (AST.concat tSrc1High tSrc2High) >> (imm .* n8))
    builder <! (dstC := AST.xtlo 64<rt> t2)
    builder <! (dstD := AST.xthi 64<rt> (AST.xtlo 128<rt> t2))
  else raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vpand ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opPand 16

let vpandn ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opPandn 16

let vpbroadcastb ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let oprSize = getOperationSize ins
  match oprSize with
  | 512<rt> -> () (* FIXME: #196 *)
  | _ ->
    let src =
      match src with
      | OprReg _ -> transOprToExpr128 ins insAddr insLen ctxt src |> snd
      | OprMem _ -> transOprToExpr ins insAddr insLen ctxt src
      | _ -> raise InvalidOperandException
      |> AST.xtlo 8<rt>
    let tSrc = AST.tmpvar 8<rt>
    startMark insAddr insLen builder
    builder <! (tSrc := src)
    let tmps = Array.init 8 (fun _ -> AST.tmpvar 8<rt>)
    for i in 0 .. 7 do builder <! (tmps.[i] := tSrc) done
    let t = AST.tmpvar 64<rt>
    builder <! (t := AST.concatArr tmps)
    match oprSize with
    | 128<rt> ->
      let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
      builder <! (dstA := t)
      builder <! (dstB := t)
      fillZeroHigh128 ctxt dst builder
    | 256<rt> ->
      let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
      builder <! (dstA := t)
      builder <! (dstB := t)
      builder <! (dstC := t)
      builder <! (dstD := t)
    | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vpbroadcastd ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src = getTwoOprs ins
  let oprSize = getOperationSize ins
  let temp = AST.tmpvar 32<rt>
  let src =
    match src with
    | OprReg r ->
      match Register.getKind r with
      | Register.Kind.XMM ->
        transOprToExpr128 ins insAddr insLen ctxt src |> snd
      | Register.Kind.GP -> transOprToExpr ins insAddr insLen ctxt src
      | _ -> raise InvalidOperandException
    | OprMem _ -> transOprToExpr ins insAddr insLen ctxt src
    | _ -> raise InvalidOperandException
    |> AST.xtlo 32<rt>
  startMark insAddr insLen builder
  builder <! (temp := src)
  match oprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    builder <! (AST.extract dstA 32<rt> 0 := temp)
    builder <! (AST.extract dstA 32<rt> 32 := temp)
    builder <! (AST.extract dstB 32<rt> 0 := temp)
    builder <! (AST.extract dstB 32<rt> 32 := temp)
    fillZeroFromVLToMaxVL ctxt dst 128 512 builder
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
    builder <! (AST.extract dstA 32<rt> 0 := temp)
    builder <! (AST.extract dstA 32<rt> 32 := temp)
    builder <! (AST.extract dstB 32<rt> 0 := temp)
    builder <! (AST.extract dstB 32<rt> 32 := temp)
    builder <! (AST.extract dstC 32<rt> 0 := temp)
    builder <! (AST.extract dstC 32<rt> 32 := temp)
    builder <! (AST.extract dstD 32<rt> 0 := temp)
    builder <! (AST.extract dstD 32<rt> 32 := temp)
    fillZeroFromVLToMaxVL ctxt dst 256 512 builder
  | 512<rt> ->
    let kl, vl = 16, 512
    let ePrx = getEVEXPrx ins.VEXInfo
    let k = getRegVar ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
    let masking dst =
      match ePrx.Z with
      | Zeroing -> AST.num0 32<rt>
      | Merging -> dst
    let cond idx =
      (* no write mask *)
      let noWritemask = if ePrx.AAA = 0uy then AST.num1 1<rt> else AST.num0 1<rt>
      AST.extract k 1<rt> idx .| noWritemask
    let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
      transOprToExpr512 ins insAddr insLen ctxt dst
    let assign dst idx sPos =
      let extDst = AST.extract dst 32<rt> sPos
      extDst := AST.ite (cond idx) temp (masking extDst)
    builder <! (assign dstA 0 0)
    builder <! (assign dstA 1 32)
    builder <! (assign dstB 2 0)
    builder <! (assign dstB 3 32)
    builder <! (assign dstC 4 0)
    builder <! (assign dstC 5 32)
    builder <! (assign dstD 6 0)
    builder <! (assign dstD 7 32)
    builder <! (assign dstE 8 0)
    builder <! (assign dstE 9 32)
    builder <! (assign dstF 10 0)
    builder <! (assign dstF 11 32)
    builder <! (assign dstG 12 0)
    builder <! (assign dstG 13 32)
    builder <! (assign dstH 14 0)
    builder <! (assign dstH 15 32)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vpcmpeqb ins insAddr insLen ctxt =
  match getOperationSize ins with
  | 512<rt> -> GeneralLifter.nop insAddr insLen (* FIXME: #197 *)
  | _ -> buildPackedInstr ins insAddr insLen ctxt 8<rt> opPcmpeqb 64

let vpcmpeqd ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> opPcmpeqd 32

let vpcmpeqq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> SSELifter.opPcmpeqq 16

let vpcmpgtb ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 8<rt> opPcmpgtb 64

let vpinsrd ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src1, src2, imm = getFourOprs ins
  let oprSize = getOperationSize ins
  let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
  let src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
  let src2 = transOprToExpr ins insAddr insLen ctxt src2
  let imm = transOprToExpr ins insAddr insLen ctxt imm
  let sel, mask, temp, tDst = tmpVars4 128<rt>
  startMark insAddr insLen builder (* write_d_element *)
  builder <! (sel := AST.zext 128<rt> (AST.xtlo 2<rt> imm))
  builder <! (mask := numU64 0xFFFFFFFFUL 128<rt> << (sel .* numI32 32 128<rt>))
  builder <!
    (temp := ((AST.zext 128<rt> src2) << (sel .* numI32 32 128<rt>)) .& mask)
  builder <! (tDst := (((AST.concat src1B src1A) .& AST.not mask) .| temp))
  builder <! (dstA := AST.extract tDst 64<rt> 0)
  builder <! (dstB := AST.extract tDst 64<rt> 64)
  fillZeroFromVLToMaxVL ctxt dst 128 512 builder
  endMark insAddr insLen builder

let vpminub ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 8<rt> SSELifter.opPminub 64

let vpminud ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> SSELifter.opPminud 32

let private opVpmuludq _ =
  let low32 expr = expr .& numI64 0xffffffffL 64<rt>
  Array.map2 (fun e1 e2 -> low32 e1 .* low32 e2)

let vpmuludq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opVpmuludq 16

let vpor ins insAddr insLen ctxt =
  match getOperationSize ins with
  | 512<rt> -> GeneralLifter.nop insAddr insLen
  | _ -> buildPackedInstr ins insAddr insLen ctxt 64<rt> opPor 8

let vpshufb ins insAddr insLen ctxt =
  let dst, src1, src2 = getThreeOprs ins
  let oprSize = getOperationSize ins
  let cnt = if oprSize = 128<rt> then 16 else 32
  let builder = StmtBuilder (2 * cnt)
  let tDst, tSrc1, tSrc2 = tmpVars3 oprSize
  startMark insAddr insLen builder
  match oprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
    let src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt src2
    builder <! (tSrc1 := AST.concat src1B src1A)
    builder <! (tSrc2 := AST.concat src2B src2A)
    let tmps = Array.init cnt (fun _ -> AST.tmpvar 8<rt>)
    let mask = numU32 0x0Fu 8<rt>
    for i in 0 .. cnt - 1 do
      let cond = AST.extract tSrc2 1<rt> (i * 8 + 7)
      let idx = (AST.extract tSrc2 8<rt> (i * 8)) .& mask
      let s = AST.zext oprSize idx .* numI32 8 oprSize
      builder <!
        (tmps.[i] := AST.ite cond (AST.num0 8<rt>) (AST.xtlo 8<rt> (tSrc1 >> s)))
    done
    builder <! (tDst := AST.concatArr tmps)
    builder <! (dstA := AST.xtlo 64<rt> tDst)
    builder <! (dstB := AST.xthi 64<rt> tDst)
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
    let src1D, src1C, src1B, src1A =
      transOprToExpr256 ins insAddr insLen ctxt src1
    let src2D, src2C, src2B, src2A =
      transOprToExpr256 ins insAddr insLen ctxt src2
    builder <! (tSrc1 := AST.concat (AST.concat src1D src1C) (AST.concat src1B src1A))
    builder <! (tSrc2 := AST.concat (AST.concat src2D src2C) (AST.concat src2B src2A))
    let tmps = Array.init cnt (fun _ -> AST.tmpvar 8<rt>)
    let mask = numU32 0x0Fu 8<rt>
    for i in 0 .. cnt - 1 do
      let cond = AST.extract tSrc2 1<rt> (i * 8 + 7)
      let idx = (AST.extract tSrc2 8<rt> (i * 8)) .& mask
      let s = AST.zext oprSize idx .* numI32 8 oprSize
      builder <!
        (tmps.[i] := AST.ite cond (AST.num0 8<rt>) (AST.xtlo 8<rt> (tSrc1 >> s)))
    done
    builder <! (tDst := AST.concatArr tmps)
    builder <! (dstA := AST.xtlo 64<rt> tDst)
    builder <! (dstB := AST.extract tDst 64<rt> 64)
    builder <!
      (dstC := AST.extract tDst 64<rt> (RegType.toBitWidth (AST.typeOf tDst) - 64))
    builder <! (dstD := AST.xthi 64<rt> tDst)
  | 512<rt> ->
    let kl, vl = 64, 512
    let ePrx = getEVEXPrx ins.VEXInfo
    let k = getRegVar ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
    let cond idx =
      if ePrx.AAA = 0uy then AST.num0 1<rt> (* no write mask *)
      else AST.extract k 1<rt> idx
    let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
      transOprToExpr512 ins insAddr insLen ctxt dst
    let src1H, src1G, src1F, src1E, src1D, src1C, src1B, src1A =
      transOprToExpr512 ins insAddr insLen ctxt src1
    let src2H, src2G, src2F, src2E, src2D, src2C, src2B, src2A =
      transOprToExpr512 ins insAddr insLen ctxt src2
    builder <!
      (tSrc1 := AST.concat (AST.concat (AST.concat src1H src1G) (AST.concat src1F src1E))
                       (AST.concat (AST.concat src1D src1C) (AST.concat src1B src1A)))
    builder <!
      (tSrc2 := AST.concat (AST.concat (AST.concat src2H src2G) (AST.concat src2F src2E))
                       (AST.concat (AST.concat src2D src2C) (AST.concat src2B src2A)))
    let num0F = numU32 0x0Fu 8<rt>
    let jmask = AST.tmpvar 8<rt>
    let tmps = Array.init kl (fun _ -> AST.tmpvar 8<rt>)
    builder <! (jmask := numI32 (kl - 1) 8<rt> .& (AST.not num0F))
    for i in 0 .. kl - 1 do
      let cond idx =
        (* no write mask *)
        let noWritemask = if ePrx.AAA = 0uy then AST.num1 1<rt> else AST.num0 1<rt>
        AST.extract k 1<rt> idx .| noWritemask
      let index1 = AST.extract tSrc2 8<rt> (i * 8)
      let index2 = (index1 .& num0F) .+ (numI32 i 8<rt> .& jmask)
      let src1 =
        AST.xtlo 8<rt> (tSrc1 >> (AST.zext oprSize (index2 .* numI32 8 8<rt>)))
      builder <! (tmps.[i] := AST.ite (cond i) (AST.ite (AST.xthi 1<rt> index1)
                                               (AST.num0 8<rt>) src1) (AST.num0 8<rt>))
    done
    builder <! (tDst := AST.concatArr tmps)
    builder <! (dstA := AST.extract tDst 64<rt> 0)
    builder <! (dstB := AST.extract tDst 64<rt> 64)
    builder <! (dstC := AST.extract tDst 64<rt> 128)
    builder <! (dstD := AST.extract tDst 64<rt> 192)
    builder <! (dstE := AST.extract tDst 64<rt> 256)
    builder <! (dstF := AST.extract tDst 64<rt> 320)
    builder <! (dstG := AST.extract tDst 64<rt> 384)
    builder <! (dstH := AST.extract tDst 64<rt> 448)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vpshufd ins insAddr insLen ctxt =
  let dst, src, ord = getThreeOprs ins
  let ord = transOprToExpr ins insAddr insLen ctxt ord
  let oprSize = getOperationSize ins
  let cnt = RegType.toBitWidth oprSize / 32
  let builder = StmtBuilder (2 * cnt)
  let tmps = Array.init cnt (fun _ -> AST.tmpvar 32<rt>)
  let n32 = numI32 32 oprSize
  let mask2 = numI32 3 32<rt> (* 2-bit mask *)
  let tSrc = AST.tmpvar oprSize
  let tDst = AST.tmpvar oprSize
  let shuffleDword src =
    for i in 1 .. cnt do
      let order =
        ((AST.xtlo 32<rt> ord) >> (numI32 ((i - 1) * 2) 32<rt>)) .& mask2
      let order' = AST.zext oprSize order
      builder <! (tmps.[i - 1] := AST.xtlo 32<rt> (src >> (order' .* n32)))
    done
  startMark insAddr insLen builder
  match oprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
    builder <! (tSrc := AST.concat srcB srcA)
    shuffleDword tSrc
    builder <! (tDst := AST.concatArr tmps)
    builder <! (dstA := AST.extract tDst 64<rt> 0)
    builder <! (dstB := AST.extract tDst 64<rt> 64)
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
    let srcD, srcC, srcB, srcA = transOprToExpr256 ins insAddr insLen ctxt src
    builder <! (tSrc := AST.concat (AST.concat srcD srcC) (AST.concat srcB srcA))
    shuffleDword tSrc
    builder <! (tDst := AST.concatArr tmps)
    builder <! (dstA := AST.extract tDst 64<rt> 0)
    builder <! (dstB := AST.extract tDst 64<rt> 64)
    builder <! (dstC := AST.extract tDst 64<rt> 128)
    builder <! (dstD := AST.extract tDst 64<rt> 192)
    fillZeroHigh256 ctxt dst builder
  | 512<rt> -> () (* FIXME: #196 *)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let private opShiftVpackedDataLogical oprSize packSz shift src1 (src2: Expr []) =
  let count = src2.[0] |> AST.zext oprSize
  let cond = AST.gt count (numI32 ((int packSz) - 1) oprSize)
  let shifted expr = AST.extract (shift (AST.zext oprSize expr) count) packSz 0
  Array.map (fun e -> AST.ite cond (AST.num0 packSz) (shifted e)) src1

let private opVpslld oprSize = opShiftVpackedDataLogical oprSize 32<rt> (<<)

let vpslld ins insAddr insLen ctxt =
  match getOperationSize ins with
  | 512<rt> -> GeneralLifter.nop insAddr insLen
  | _ -> buildPackedInstr ins insAddr insLen ctxt 32<rt> opVpslld 16

let private shiftVDQ ins insAddr insLen ctxt shift =
  let builder = StmtBuilder (8)
  let dst, src, cnt = getThreeOprs ins
  let cnt = transOprToExpr ins insAddr insLen ctxt cnt |> castNum 8<rt>
  let oprSize = getOperationSize ins
  let t = AST.tmpvar 8<rt>
  startMark insAddr insLen builder
  builder <! (t := AST.ite (AST.lt (numU32 15u 8<rt>) cnt) (numU32 16u 8<rt>) cnt)
  match oprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let srcB, srcA = transOprToExpr128 ins insAddr insLen ctxt src
    let tDst, tSrc = tmpVars2 128<rt>
    builder <! (tDst := AST.concat dstB dstA)
    builder <! (tSrc := AST.concat srcB srcA)
    builder <! (tDst := (shift tSrc (AST.zext oprSize (t .* numU32 8u 8<rt>))))
    builder <! (dstA := AST.xtlo 64<rt> tDst)
    builder <! (dstB := AST.xthi 64<rt> tDst)
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
    let srcD, srcC, srcB, srcA = transOprToExpr256 ins insAddr insLen ctxt src
    let tDst, tSrc = tmpVars2 256<rt>
    builder <! (tDst := AST.concat (AST.concat dstD dstC) (AST.concat dstB dstA))
    builder <! (tSrc := AST.concat (AST.concat srcD srcC) (AST.concat srcB srcA))
    builder <! (tDst := (shift tSrc (AST.zext oprSize (t .* numU32 8u 8<rt>))))
    builder <! (dstA := AST.xtlo 64<rt> tDst)
    builder <! (dstB := AST.xtlo 64<rt> tDst)
    builder <! (dstC := AST.extract tDst 64<rt> 128)
    builder <! (dstD := AST.xthi 64<rt> tDst)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let private opVpsllq oprSize = opShiftVpackedDataLogical oprSize 64<rt> (<<)

let vpsllq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opVpsllq 16

let vpslldq ins insAddr insLen ctxt = shiftVDQ ins insAddr insLen ctxt (<<)

let vpsrlq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opVpsllq 16

let vpsrldq ins insAddr insLen ctxt = shiftVDQ ins insAddr insLen ctxt (>>)

let private opVpsrld oprSize = opShiftVpackedDataLogical oprSize 32<rt> (<<)

let vpsrld ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> opVpsrld 16

let vpsubb ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 8<rt> opPsub 128

let vptest ins insAddr insLen ctxt =
  if getOperationSize ins = 128<rt> then SSELifter.ptest ins insAddr insLen ctxt
  else
    let builder = StmtBuilder (16)
    let src1, src2 = getTwoOprs ins
    let src1D, src1C, src1B, src1A =
      transOprToExpr256 ins insAddr insLen ctxt src1
    let src2D, src2C, src2B, src2A =
      transOprToExpr256 ins insAddr insLen ctxt src2
    let t1, t2, t3, t4 = tmpVars4 64<rt>
    let t5, t6, t7, t8 = tmpVars4 64<rt>
    startMark insAddr insLen builder
    builder <! (t1 := src2A .& src1A)
    builder <! (t2 := src2B .& src1B)
    builder <! (t3 := src2C .& src1C)
    builder <! (t4 := src2D .& src1D)
    builder <! (getRegVar ctxt R.ZF := (t1 .| t2 .| t3 .| t4) == (AST.num0 64<rt>))
    builder <! (t5 := src2A .& AST.not src1A)
    builder <! (t6 := src2B .& AST.not src1B)
    builder <! (t7 := src2C .& AST.not src1C)
    builder <! (t8 := src2D .& AST.not src1D)
    builder <! (getRegVar ctxt R.CF := (t5 .| t6 .| t7 .| t8) == (AST.num0 64<rt>))
    builder <! (getRegVar ctxt R.AF := AST.b0)
    builder <! (getRegVar ctxt R.OF := AST.b0)
    builder <! (getRegVar ctxt R.PF := AST.b0)
    builder <! (getRegVar ctxt R.SF := AST.b0)
    endMark insAddr insLen builder

let vpunpckhdq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> opPunpckHigh 16

let vpunpckhqdq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opPunpckHigh 16

let vpunpckldq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 32<rt> opPunpckLow 16

let vpunpcklqdq ins insAddr insLen ctxt =
  buildPackedInstr ins insAddr insLen ctxt 64<rt> opPunpckLow 16

let vpxor ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src1, src2 = getThreeOprs ins
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  match oprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
    let src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt src2
    builder <! (dstB := src1B <+> src2B)
    builder <! (dstA := src1A <+> src2A)
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
    let src1D, src1C, src1B, src1A =
      transOprToExpr256 ins insAddr insLen ctxt src1
    let src2D, src2C, src2B, src2A =
      transOprToExpr256 ins insAddr insLen ctxt src2
    builder <! (dstD := src1D <+> src2D)
    builder <! (dstC := src1C <+> src2C)
    builder <! (dstB := src1B <+> src2B)
    builder <! (dstA := src1A <+> src2A)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vpxord ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src1, src2 = getThreeOprs ins
  let oprSize = getOperationSize ins
  startMark insAddr insLen builder
  let ePrx = getEVEXPrx ins.VEXInfo
  let k = getRegVar ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
  let masking dst =
    match ePrx.Z with
    | Zeroing -> AST.num0 32<rt>
    | Merging -> dst
  let cond idx =
    (* no write mask *)
    let noWritemask = if ePrx.AAA = 0uy then AST.num1 1<rt> else AST.num0 1<rt>
    AST.extract k 1<rt> idx .| noWritemask
  let tmpDest = Array.init 2 (fun _ -> AST.tmpvar 32<rt>)
  let evAssign dst s1 s2 src2A dstA idx =
    for i in 0 .. 1 do
      let s1 = AST.extract s1 32<rt> (i * 32)
      let s2 = AST.extract s2 32<rt> (i * 32)
      let dst = AST.extract dstA 32<rt> 0
      let tSrc =
        match src2 with
        | OprMem _ when ePrx.AAA (* B *) = 1uy ->
          s1 <+> (AST.extract src2A 32<rt> 0)
        | _ -> s1 <+> s2
      builder <! (tmpDest.[i] := AST.ite (cond (idx + i)) tSrc (masking dst))
    AST.concatArr tmpDest
  match oprSize with
  | 128<rt> ->
    let kl, vl = 4, 128
    let dstB, dstA = transOprToExpr128 ins insAddr insLen ctxt dst
    let src1B, src1A = transOprToExpr128 ins insAddr insLen ctxt src1
    let src2B, src2A = transOprToExpr128 ins insAddr insLen ctxt src2
    builder <! (dstA := evAssign dstA src1A src2A src2A dstA 0)
    builder <! (dstB := evAssign dstB src1B src2B src2A dstA 2)
    fillZeroHigh128 ctxt dst builder
  | 256<rt> ->
    let kl, vl = 8, 256
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insAddr insLen ctxt dst
    let src1D, src1C, src1B, src1A =
      transOprToExpr256 ins insAddr insLen ctxt src1
    let src2D, src2C, src2B, src2A =
      transOprToExpr256 ins insAddr insLen ctxt src2
    builder <! (dstA := evAssign dstA src1A src2A src2A dstA 0)
    builder <! (dstB := evAssign dstB src1B src2B src2A dstA 2)
    builder <! (dstC := evAssign dstC src1C src2B src2A dstA 4)
    builder <! (dstD := evAssign dstD src1D src2B src2A dstA 6)
    fillZeroHigh256 ctxt dst builder
  | 512<rt> ->
    let kl, vl = 16, 512
    let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
      transOprToExpr512 ins insAddr insLen ctxt dst
    let src1H, src1G, src1F, src1E, src1D, src1C, src1B, src1A =
      transOprToExpr512 ins insAddr insLen ctxt src1
    let src2H, src2G, src2F, src2E, src2D, src2C, src2B, src2A =
      transOprToExpr512 ins insAddr insLen ctxt src2
    builder <! (dstA := evAssign dstA src1A src2A src2A dstA 0)
    builder <! (dstB := evAssign dstB src1B src2B src2A dstA 2)
    builder <! (dstC := evAssign dstC src1C src2C src2A dstA 4)
    builder <! (dstD := evAssign dstD src1D src2D src2A dstA 6)
    builder <! (dstE := evAssign dstE src1E src2E src2A dstA 8)
    builder <! (dstF := evAssign dstF src1F src2F src2A dstA 10)
    builder <! (dstG := evAssign dstG src1G src2G src2A dstA 12)
    builder <! (dstH := evAssign dstH src1H src2H src2A dstA 14)
  | _ -> raise InvalidOperandSizeException
  endMark insAddr insLen builder

let vzeroupper ins insAddr insLen ctxt =
  let builder = StmtBuilder (32)
  startMark insAddr insLen builder
  let n0 = AST.num0 64<rt>
  builder <! (getPseudoRegVar ctxt R.YMM0 3 := n0)
  builder <! (getPseudoRegVar ctxt R.YMM0 4 := n0)
  builder <! (getPseudoRegVar ctxt R.YMM1 3 := n0)
  builder <! (getPseudoRegVar ctxt R.YMM1 4 := n0)
  builder <! (getPseudoRegVar ctxt R.YMM2 3 := n0)
  builder <! (getPseudoRegVar ctxt R.YMM2 4 := n0)
  builder <! (getPseudoRegVar ctxt R.YMM3 3 := n0)
  builder <! (getPseudoRegVar ctxt R.YMM3 4 := n0)
  builder <! (getPseudoRegVar ctxt R.YMM4 3 := n0)
  builder <! (getPseudoRegVar ctxt R.YMM4 4 := n0)
  builder <! (getPseudoRegVar ctxt R.YMM5 3 := n0)
  builder <! (getPseudoRegVar ctxt R.YMM5 4 := n0)
  builder <! (getPseudoRegVar ctxt R.YMM6 3 := n0)
  builder <! (getPseudoRegVar ctxt R.YMM6 4 := n0)
  builder <! (getPseudoRegVar ctxt R.YMM7 3 := n0)
  builder <! (getPseudoRegVar ctxt R.YMM7 4 := n0)
  if is64bit ctxt then
    builder <! (getPseudoRegVar ctxt R.YMM8 3 := n0)
    builder <! (getPseudoRegVar ctxt R.YMM8 4 := n0)
    builder <! (getPseudoRegVar ctxt R.YMM9 3 := n0)
    builder <! (getPseudoRegVar ctxt R.YMM9 4 := n0)
    builder <! (getPseudoRegVar ctxt R.YMM10 3 := n0)
    builder <! (getPseudoRegVar ctxt R.YMM10 4 := n0)
    builder <! (getPseudoRegVar ctxt R.YMM11 3 := n0)
    builder <! (getPseudoRegVar ctxt R.YMM11 4 := n0)
    builder <! (getPseudoRegVar ctxt R.YMM12 3 := n0)
    builder <! (getPseudoRegVar ctxt R.YMM12 4 := n0)
    builder <! (getPseudoRegVar ctxt R.YMM13 3 := n0)
    builder <! (getPseudoRegVar ctxt R.YMM13 4 := n0)
    builder <! (getPseudoRegVar ctxt R.YMM14 3 := n0)
    builder <! (getPseudoRegVar ctxt R.YMM14 4 := n0)
    builder <! (getPseudoRegVar ctxt R.YMM15 3 := n0)
    builder <! (getPseudoRegVar ctxt R.YMM15 4 := n0)
  endMark insAddr insLen builder

let vfmadd132sd ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src2, src3 = getThreeOprs ins
  let _dstB , dstA = transOprToExpr128 ins insAddr insLen ctxt dst
  let src2 = transOprToExpr64 ins insAddr insLen ctxt src2
  let src3 = transOprToExpr64 ins insAddr insLen ctxt src3
  let tmp = AST.tmpvar 64<rt>
  startMark insAddr insLen builder
  builder <! (tmp := AST.fmul dstA src3)
  builder <! (dstA := AST.fadd tmp src2)
  fillZeroHigh128 ctxt dst builder
  endMark insAddr insLen builder

let vfmadd213sd ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src2, src3 = getThreeOprs ins
  let _dstB , dstA = transOprToExpr128 ins insAddr insLen ctxt dst
  let src2 = transOprToExpr64 ins insAddr insLen ctxt src2
  let src3 = transOprToExpr64 ins insAddr insLen ctxt src3
  let tmp = AST.tmpvar 64<rt>
  startMark insAddr insLen builder
  builder <! (tmp := AST.fmul dstA src2)
  builder <! (dstA := AST.fadd tmp src3)
  fillZeroHigh128 ctxt dst builder
  endMark insAddr insLen builder

let vfmadd231sd ins insAddr insLen ctxt =
  let builder = StmtBuilder (8)
  let dst, src2, src3 = getThreeOprs ins
  let _dstB , dstA = transOprToExpr128 ins insAddr insLen ctxt dst
  let src2 = transOprToExpr64 ins insAddr insLen ctxt src2
  let src3 = transOprToExpr64 ins insAddr insLen ctxt src3
  let tmp = AST.tmpvar 64<rt>
  startMark insAddr insLen builder
  builder <! (tmp := AST.fmul src2 src3)
  builder <! (dstA := AST.fadd dstA tmp)
  fillZeroHigh128 ctxt dst builder
  endMark insAddr insLen builder

