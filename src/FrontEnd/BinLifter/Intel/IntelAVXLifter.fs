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
open B2R2.FrontEnd.BinLifter.LiftingOperators
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

let private fillZeroHigh128 ctxt dst ir =
  let dst = r128to256 dst
  let dstC, dstD = getPseudoRegVar ctxt dst 3, getPseudoRegVar ctxt dst 4
  let n0 = AST.num0 64<rt>
  !!ir (dstC := n0)
  !!ir (dstD := n0)

let private fillZeroHigh256 ctxt dst ir =
  let dst = r256to512 dst
  let dstE, dstF, dstG, dstH =
    getPseudoRegVar ctxt dst 3, getPseudoRegVar ctxt dst 4,
    getPseudoRegVar ctxt dst 5, getPseudoRegVar ctxt dst 6
  let n0 = AST.num0 64<rt>
  !!ir (dstE := n0)
  !!ir (dstF := n0)
  !!ir (dstG := n0)
  !!ir (dstH := n0)

let private vexedPackedFPBinOp32 ins insLen ctxt op =
  let ir = IRBuilder (16)
  let struct (dst, src1, src2) = getThreeOprs ins
  let oprSz = getOperationSize ins
  let do32PackedOp dst64 src1 src2 ir =
    let dstA, dstB = AST.xtlo 32<rt> dst64, AST.xthi 32<rt> dst64
    let src1A, src1B = AST.xtlo 32<rt> src1, AST.xthi 32<rt> src1
    let src2A, src2B = AST.xtlo 32<rt> src2, AST.xthi 32<rt> src2
    !!ir (dstA := op src1A src2A)
    !!ir (dstB := op src1B src2B)
  !<ir insLen
  match oprSz with
  | 128<rt> ->
    let dst2, dst1 = transOprToExpr128 ins insLen ctxt dst
    let src1B, src1A = transOprToExpr128 ins insLen ctxt src1
    let src2B, src2A = transOprToExpr128 ins insLen ctxt src2
    do32PackedOp dst1 src1A src2A ir
    do32PackedOp dst2 src1B src2B ir
    fillZeroHigh128 ctxt dst ir
  | 256<rt> ->
    let dst4, dst3, dst2, dst1 = transOprToExpr256 ins insLen ctxt dst
    let sr1D, sr1C, sr1B, sr1A = transOprToExpr256 ins insLen ctxt src1
    let sr2D, sr2C, sr2B, sr2A = transOprToExpr256 ins insLen ctxt src2
    do32PackedOp dst1 sr1A sr2A ir
    do32PackedOp dst2 sr1B sr2B ir
    do32PackedOp dst3 sr1C sr2C ir
    do32PackedOp dst4 sr1D sr2D ir
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let private vexedPackedFPBinOp64 ins insLen ctxt op =
  let ir = IRBuilder (16)
  let struct (dst, src1, src2) = getThreeOprs ins
  let oprSz = getOperationSize ins
  !<ir insLen
  match oprSz with
  | 128<rt> ->
    let dst2, dst1 = transOprToExpr128 ins insLen ctxt dst
    let src1B, src1A = transOprToExpr128 ins insLen ctxt src1
    let src2B, src2A = transOprToExpr128 ins insLen ctxt src2
    !!ir (dst1 := op src1A src2A)
    !!ir (dst2 := op src1B src2B)
    fillZeroHigh128 ctxt dst ir
  | 256<rt> ->
    let dst4, dst3, dst2, dst1 = transOprToExpr256 ins insLen ctxt dst
    let sr1D, sr1C, sr1B, sr1A = transOprToExpr256 ins insLen ctxt src1
    let sr2D, sr2C, sr2B, sr2A = transOprToExpr256 ins insLen ctxt src2
    !!ir (dst1 := op sr1A sr2A)
    !!ir (dst2 := op sr1B sr2B)
    !!ir (dst3 := op sr1C sr2C)
    !!ir (dst4 := op sr1D sr2D)
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let private vexedScalarFPBinOp ins insLen ctxt sz op =
  let ir = IRBuilder (8)
  let struct (dst, src1, src2) = getThreeOprs ins
  let dst2, dst1 = transOprToExpr128 ins insLen ctxt dst
  let src1B, src1A = transOprToExpr128 ins insLen ctxt src1
  !<ir insLen
  match sz with
  | 32<rt> ->
    let src2 = transOprToExpr32 ins insLen ctxt src2
    !!ir (AST.xtlo 32<rt> dst1 := op (AST.xtlo 32<rt> src1A) src2)
    !!ir (AST.xthi 32<rt> dst1 := AST.xthi 32<rt> src1A)
  | 64<rt> ->
    let src2 = transOprToExpr64 ins insLen ctxt src2
    !!ir (dst1 := op src1A src2)
  | _ -> raise InvalidOperandSizeException
  !!ir (dst2 := src1B)
  fillZeroHigh128 ctxt dst ir
  !>ir insLen

let vsqrtps ins insLen ctxt =
  let ir = IRBuilder (16)
  let struct (dst, src) = getTwoOprs ins
  let oprSz = getOperationSize ins
  let do32PackedSqrt dst64 src ir =
    let dstA, dstB = AST.xtlo 32<rt> dst64, AST.xthi 32<rt> dst64
    let srcA, srcB = AST.xtlo 32<rt> src, AST.xthi 32<rt> src
    !!ir (dstA := AST.fsqrt srcA)
    !!ir (dstB := AST.fsqrt srcB)
  !<ir insLen
  match oprSz with
  | 128<rt> ->
    let dst2, dst1 = transOprToExpr128 ins insLen ctxt dst
    let srcB, srcA = transOprToExpr128 ins insLen ctxt src
    do32PackedSqrt dst1 srcA ir
    do32PackedSqrt dst2 srcB ir
    fillZeroHigh128 ctxt dst ir
  | 256<rt> ->
    let dst4, dst3, dst2, dst1 = transOprToExpr256 ins insLen ctxt dst
    let srD, srC, srB, srA = transOprToExpr256 ins insLen ctxt src
    do32PackedSqrt dst1 srA  ir
    do32PackedSqrt dst2 srB  ir
    do32PackedSqrt dst3 srC  ir
    do32PackedSqrt dst4 srD  ir
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let vsqrtpd ins insLen ctxt =
  let ir = IRBuilder (16)
  let struct (dst, src) = getTwoOprs ins
  let oprSz = getOperationSize ins
  !<ir insLen
  match oprSz with
  | 128<rt> ->
    let dst2, dst1 = transOprToExpr128 ins insLen ctxt dst
    let src2, src1 = transOprToExpr128 ins insLen ctxt src
    !!ir (dst1 := AST.fsqrt src1)
    !!ir (dst2 := AST.fsqrt src2)
    fillZeroHigh128 ctxt dst ir
  | 256<rt> ->
    let dst4, dst3, dst2, dst1 = transOprToExpr256 ins insLen ctxt dst
    let sr4, sr3, sr2, sr1 = transOprToExpr256 ins insLen ctxt src
    !!ir (dst1 := AST.fsqrt sr1)
    !!ir (dst2 := AST.fsqrt sr2)
    !!ir (dst3 := AST.fsqrt sr3)
    !!ir (dst4 := AST.fsqrt sr4)
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let private vsqrts ins insLen ctxt sz =
  let ir = IRBuilder (16)
  let struct (dst, src1, src2) = getThreeOprs ins
  let dst2, dst1 = transOprToExpr128 ins insLen ctxt dst
  let src1B, src1A = transOprToExpr128 ins insLen ctxt src1
  !<ir insLen
  match sz with
  | 32<rt> ->
    let src2 = transOprToExpr32 ins insLen ctxt src2
    !!ir (AST.xtlo 32<rt> dst1 := AST.fsqrt src2)
    !!ir (AST.xthi 32<rt> dst1 := AST.xthi 32<rt> src1A)
  | 64<rt> ->
    let src2 = transOprToExpr64 ins insLen ctxt src2
    !!ir (dst1 := AST.fsqrt src2)
  | _ -> raise InvalidOperandSizeException
  !!ir (dst2 := src1B)
  fillZeroHigh128 ctxt dst ir
  !>ir insLen

let vsqrtss ins insLen ctxt =
  vsqrts ins insLen ctxt 32<rt>

let vsqrtsd ins insLen ctxt =
  vsqrts ins insLen ctxt 64<rt>

let vaddps ins insLen ctxt =
  match getOperationSize ins with
  | 512<rt> -> GeneralLifter.nop insLen
  | _ -> vexedPackedFPBinOp32 ins insLen ctxt AST.fadd

let vaddpd ins insLen ctxt =
  vexedPackedFPBinOp64 ins insLen ctxt AST.fadd

let vaddss ins insLen ctxt =
  vexedScalarFPBinOp ins insLen ctxt 32<rt> AST.fadd

let vaddsd ins insLen ctxt =
  vexedScalarFPBinOp ins insLen ctxt 64<rt> AST.fadd

let vsubps ins insLen ctxt =
  match getOperationSize ins with
  | 512<rt> -> GeneralLifter.nop insLen
  | _ -> vexedPackedFPBinOp32 ins insLen ctxt AST.fsub

let vsubpd ins insLen ctxt =
  vexedPackedFPBinOp64 ins insLen ctxt AST.fsub

let vsubss ins insLen ctxt =
  vexedScalarFPBinOp ins insLen ctxt 32<rt> AST.fsub

let vsubsd ins insLen ctxt =
  vexedScalarFPBinOp ins insLen ctxt 64<rt> AST.fsub

let vmulps ins insLen ctxt =
  vexedPackedFPBinOp32 ins insLen ctxt AST.fmul

let vmulpd ins insLen ctxt =
  vexedPackedFPBinOp64 ins insLen ctxt AST.fmul

let vmulss ins insLen ctxt =
  vexedScalarFPBinOp ins insLen ctxt 32<rt> AST.fmul

let vmulsd ins insLen ctxt =
  vexedScalarFPBinOp ins insLen ctxt 64<rt> AST.fmul

let vdivps ins insLen ctxt =
  vexedPackedFPBinOp32 ins insLen ctxt AST.fdiv

let vdivpd ins insLen ctxt =
  match getOperationSize ins with
  | 512<rt> -> GeneralLifter.nop insLen (* FIXME: #196 *)
  | _ -> vexedPackedFPBinOp64 ins insLen ctxt AST.fdiv

let vdivss ins insLen ctxt =
  vexedScalarFPBinOp ins insLen ctxt 32<rt> AST.fdiv

let vdivsd ins insLen ctxt =
  vexedScalarFPBinOp ins insLen ctxt 64<rt> AST.fdiv

let vcvtsi2ss ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src1, src2) = getThreeOprs ins
  let dstB , dstA = transOprToExpr128 ins insLen ctxt dst
  let src1B, src1A = transOprToExpr128 ins insLen ctxt src1
  let src2 = transOprToExpr ins insLen ctxt src2
  !<ir insLen
  !!ir (AST.xtlo 32<rt> dstA := AST.cast CastKind.IntToFloat 32<rt> src2)
  !!ir (AST.xthi 32<rt> dstA := AST.xthi 32<rt> src1A)
  !!ir (dstB := src1B)
  fillZeroHigh128 ctxt dst ir
  !>ir insLen

let vcvtsi2sd ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src1, src2) = getThreeOprs ins
  let dstB , dstA = transOprToExpr128 ins insLen ctxt dst
  let src1B, _src1A = transOprToExpr128 ins insLen ctxt src1
  let src2 = transOprToExpr ins insLen ctxt src2
  !<ir insLen
  !!ir (dstA := AST.cast CastKind.IntToFloat 64<rt> src2)
  !!ir (dstB := src1B)
  fillZeroHigh128 ctxt dst ir
  !>ir insLen

let vcvtsd2ss ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src1, src2) = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
  let src1B, src1A = transOprToExpr128 ins insLen ctxt src1
  let src2 = transOprToExpr64 ins insLen ctxt src2
  !<ir insLen
  !!ir (AST.xtlo 32<rt> dstA := AST.cast CastKind.FloatCast 32<rt> src2)
  !!ir (AST.xthi 32<rt> dstA := AST.xthi 32<rt> src1A)
  !!ir (dstB := src1B)
  fillZeroHigh128 ctxt dst ir
  !>ir insLen

let vcvtss2sd ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src1, src2) = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
  let src1B, _src1A = transOprToExpr128 ins insLen ctxt src1
  let src2 = transOprToExpr32 ins insLen ctxt src2
  !<ir insLen
  !!ir (dstA := AST.cast CastKind.FloatCast 64<rt> src2)
  !!ir (dstB := src1B)
  fillZeroHigh128 ctxt dst ir
  !>ir insLen

let private getEVEXPrx = function
  | Some v -> match v.EVEXPrx with
              | Some ev -> ev
              | None -> Utils.impossible ()
  | None -> Utils.impossible ()

let private buildVectorMove ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src) = getTwoOprs ins
  let oprSize = getOperationSize ins
  !<ir insLen
  if oprSize = 128<rt> then
    match dst with
    | OprReg _ ->
      let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
      let srcB, srcA = transOprToExpr128 ins insLen ctxt src
      !!ir (dstA := srcA)
      !!ir (dstB := srcB)
      fillZeroHigh128 ctxt dst ir
    | OprMem _ ->
      let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
      let srcB, srcA = transOprToExpr128 ins insLen ctxt src
      !!ir (dstA := srcA)
      !!ir (dstB := srcB)
    | _ -> raise InvalidOperandException
  elif oprSize = 256<rt> then
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
    let srcD, srcC, srcB, srcA = transOprToExpr256 ins insLen ctxt src
    !!ir (dstA := srcA)
    !!ir (dstB := srcB)
    !!ir (dstC := srcC)
    !!ir (dstD := srcD)
  elif oprSize = 512<rt> then
    let ePrx = getEVEXPrx ins.VEXInfo
    let k = !.ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
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
        transOprToExpr512 ins insLen ctxt dst
      let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
        transOprToExpr512 ins insLen ctxt src
      let ite i src dst extFn =
        AST.ite (cond i) (extFn 32<rt> src) (masking (extFn 32<rt> dst))
      !!ir (AST.xtlo 32<rt> dstA := ite 0 srcA dstA AST.xtlo)
      !!ir (AST.xthi 32<rt> dstA := ite 1 srcA dstA AST.xthi)
      !!ir (AST.xtlo 32<rt> dstB := ite 2 srcB dstB AST.xtlo)
      !!ir (AST.xthi 32<rt> dstB := ite 3 srcB dstB AST.xthi)
      !!ir (AST.xtlo 32<rt> dstC := ite 4 srcC dstC AST.xtlo)
      !!ir (AST.xthi 32<rt> dstC := ite 5 srcC dstC AST.xthi)
      !!ir (AST.xtlo 32<rt> dstD := ite 6 srcD dstD AST.xtlo)
      !!ir (AST.xthi 32<rt> dstD := ite 7 srcD dstD AST.xthi)
      !!ir (AST.xtlo 32<rt> dstE := ite 8 srcE dstE AST.xtlo)
      !!ir (AST.xthi 32<rt> dstE := ite 9 srcE dstE AST.xthi)
      !!ir (AST.xtlo 32<rt> dstF := ite 10 srcF dstF AST.xtlo)
      !!ir (AST.xthi 32<rt> dstF := ite 11 srcF dstF AST.xthi)
      !!ir (AST.xtlo 32<rt> dstG := ite 12 srcG dstG AST.xtlo)
      !!ir (AST.xthi 32<rt> dstG := ite 13 srcG dstG AST.xthi)
      !!ir (AST.xtlo 32<rt> dstH := ite 14 srcH dstH AST.xtlo)
      !!ir (AST.xthi 32<rt> dstH := ite 15 srcH dstH AST.xthi)
    | OprMem _ ->
      let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
        transOprToExpr512 ins insLen ctxt dst
      let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
        transOprToExpr512 ins insLen ctxt src
      let ite i src dst extFn =
        AST.ite (cond i) (extFn 32<rt> src) (extFn 32<rt> dst)
      let evAssign src dst idx =
        AST.concat (ite (idx + 1) src dst AST.xthi) (ite idx src dst AST.xtlo)
      !!ir (dstA := evAssign srcA dstA 0)
      !!ir (dstB := evAssign srcB dstB 2)
      !!ir (dstC := evAssign srcC dstB 4)
      !!ir (dstD := evAssign srcD dstB 6)
      !!ir (dstE := evAssign srcE dstB 8)
      !!ir (dstF := evAssign srcF dstB 10)
      !!ir (dstG := evAssign srcG dstB 12)
      !!ir (dstH := evAssign srcH dstB 14)
    | _ -> raise InvalidOperandException
  else raise InvalidOperandSizeException
  !>ir insLen

let vmovd ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src) = getTwoOprs ins
  let oprSize = getOperationSize ins
  !<ir insLen
  let n0 = AST.num0 64<rt>
  let regToReg r1 r2 =
    match Register.getKind r1, Register.getKind r2 with
    | Register.Kind.XMM, Register.Kind.GP ->
      let dstD, dstC, dstB, dstA = getPseudoRegVar256 ctxt (r128to256 dst)
      let src = !.ctxt r2
      !!ir (dstAssign 32<rt> dstA src)
      !!ir (dstB := n0)
      !!ir (dstC := n0)
      !!ir (dstD := n0)
    | Register.Kind.GP, Register.Kind.XMM ->
      let dst = !.ctxt r1
      let srcA = getPseudoRegVar ctxt r2 1
      !!ir (dstAssign oprSize dst (AST.xtlo 32<rt> srcA))
    | _ -> raise InvalidOperandException
  match dst, src with
  | OprReg r1, OprReg r2 -> regToReg r1 r2
  | OprReg r, OprMem _ ->
    let dstD, dstC, dstB, dstA = getPseudoRegVar256 ctxt (r128to256 dst)
    let src = transOprToExpr ins insLen ctxt src
    !!ir (dstAssign 32<rt> dstA src)
    !!ir (dstB := n0)
    !!ir (dstC := n0)
    !!ir (dstD := n0)
  | OprMem _, OprReg r ->
    let dst = transOprToExpr ins insLen ctxt dst
    let srcA = getPseudoRegVar ctxt r 1
    !!ir (dst := AST.xtlo 32<rt> srcA)
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let vmovq ins insLen ctxt =
  let ir = IRBuilder (4)
  let struct (dst, src) = getTwoOprs ins
  !<ir insLen
  let n0 = AST.num0 64<rt>
  let regToReg r1 r2 =
    match Register.getKind r1, Register.getKind r2 with
    | Register.Kind.XMM, Register.Kind.XMM ->
      let dstD, dstC, dstB, dstA = getPseudoRegVar256 ctxt (r128to256 dst)
      let srcA = getPseudoRegVar ctxt r2 1
      !!ir (dstA := srcA)
      !!ir (dstB := n0)
      !!ir (dstC := n0)
      !!ir (dstD := n0)
    | Register.Kind.XMM, Register.Kind.GP ->
      let dstD, dstC, dstB, dstA = getPseudoRegVar256 ctxt (r128to256 dst)
      let src = !.ctxt r2
      !!ir (dstA := src)
      !!ir (dstB := n0)
      !!ir (dstC := n0)
      !!ir (dstD := n0)
    | Register.Kind.GP, Register.Kind.XMM ->
      let dst = !.ctxt r1
      let srcA = getPseudoRegVar ctxt r2 1
      !!ir (dst := srcA)
    | _ -> raise InvalidOperandException
  match dst, src with
  | OprReg r1, OprReg r2 -> regToReg r1 r2
  | OprReg _, OprMem _ ->
    let dstD, dstC, dstB, dstA = getPseudoRegVar256 ctxt (r128to256 dst)
    let src = transOprToExpr ins insLen ctxt src
    !!ir (dstA := src)
    !!ir (dstB := n0)
    !!ir (dstC := n0)
    !!ir (dstD := n0)
  | OprMem _, OprReg r ->
    let dst = transOprToExpr ins insLen ctxt dst
    let srcA = getPseudoRegVar ctxt r 1
    !!ir (dst := srcA)
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let vmovdqu ins insLen ctxt =
  buildVectorMove ins insLen ctxt

let private fillZeroFromVLToMaxVL ctxt dst vl maxVl ir =
  let n0 = AST.num0 64<rt>
  match maxVl, vl with
  | 512, 128 ->
    let dst = r128to512 dst
    let dstC, dstD, dstE, dstF, dstG, dstH =
      getPseudoRegVar ctxt dst 3, getPseudoRegVar ctxt dst 4,
      getPseudoRegVar ctxt dst 5, getPseudoRegVar ctxt dst 6,
      getPseudoRegVar ctxt dst 7, getPseudoRegVar ctxt dst 8
    !!ir (dstC := n0)
    !!ir (dstD := n0)
    !!ir (dstE := n0)
    !!ir (dstF := n0)
    !!ir (dstG := n0)
    !!ir (dstH := n0)
  | 512, 256 ->
    let dst = r256to512 dst
    let dstE, dstF, dstG, dstH =
      getPseudoRegVar ctxt dst 5, getPseudoRegVar ctxt dst 6,
      getPseudoRegVar ctxt dst 7, getPseudoRegVar ctxt dst 8
    !!ir (dstE := n0)
    !!ir (dstF := n0)
    !!ir (dstG := n0)
    !!ir (dstH := n0)
  | _ -> Utils.impossible ()

let vmovdqu16 ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src) = getTwoOprs ins
  let oprSize = getOperationSize ins
  let ePrx = getEVEXPrx ins.VEXInfo
  let k = !.ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
  let masking dst =
    match ePrx.Z with
    | Zeroing -> AST.num0 16<rt>
    | Merging -> dst
  let cond idx =
    (* no write mask *)
    let noWritemask = if ePrx.AAA = 0uy then AST.num1 1<rt> else AST.num0 1<rt>
    AST.extract k 1<rt> idx .| noWritemask
  !<ir insLen
  match oprSize with
  | 128<rt> ->
    let kl, vl = 8, 128
    match dst with
    | OprReg _ ->
      let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
      let srcB, srcA = transOprToExpr128 ins insLen ctxt src
      let assign dst src idx =
        let pos = (idx % 4) * 16
        let dst = AST.extract dst 16<rt> pos
        dst := AST.ite (cond idx) (AST.extract src 16<rt> pos) (masking dst)
      !!ir (assign dstA srcA 0)
      !!ir (assign dstA srcA 1)
      !!ir (assign dstA srcA 2)
      !!ir (assign dstA srcA 3)
      !!ir (assign dstB srcB 4)
      !!ir (assign dstB srcB 5)
      !!ir (assign dstB srcB 6)
      !!ir (assign dstB srcB 7)
      fillZeroFromVLToMaxVL ctxt dst vl 512 ir
    | OprMem _ ->
      let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
      let srcB, srcA = transOprToExpr128 ins insLen ctxt src
      let tmps = Array.init 4 (fun _ -> !*ir 16<rt>)
      let assign dst src idx =
        for i in 0 .. 3 do
          let pos = i * 16
          let dst = AST.extract dst 16<rt> pos
          !!ir
            (tmps[i] := AST.ite (cond (idx + i)) (AST.extract src 16<rt> pos) dst)
        AST.concatArr tmps
      !!ir (dstA := assign dstA srcA 0)
      !!ir (dstB := assign dstB srcB 4)
    | _ -> raise InvalidOperandException
  | 256<rt> ->
    let kl, vl = 16, 256
    match dst with
    | OprReg _ ->
      let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
      let srcD, srcC, srcB, srcA = transOprToExpr256 ins insLen ctxt src
      let assign dst src idx =
        let pos = (idx % 4) * 16
        let dst = AST.extract dst 16<rt> pos
        dst := AST.ite (cond idx) (AST.extract src 16<rt> pos) (masking dst)
      !!ir (assign dstA srcA 0)
      !!ir (assign dstA srcA 1)
      !!ir (assign dstA srcA 2)
      !!ir (assign dstA srcA 3)
      !!ir (assign dstB srcB 4)
      !!ir (assign dstB srcB 5)
      !!ir (assign dstB srcB 6)
      !!ir (assign dstB srcB 7)
      !!ir (assign dstC srcA 8)
      !!ir (assign dstC srcA 9)
      !!ir (assign dstC srcA 10)
      !!ir (assign dstC srcA 11)
      !!ir (assign dstD srcB 12)
      !!ir (assign dstD srcB 13)
      !!ir (assign dstD srcB 14)
      !!ir (assign dstD srcB 15)
      fillZeroFromVLToMaxVL ctxt dst vl 512 ir
    | OprMem _ ->
      let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
      let srcD, srcC, srcB, srcA = transOprToExpr256 ins insLen ctxt src
      let tmps = Array.init 4 (fun _ -> !*ir 16<rt>)
      let assign dst src idx =
        for i in 0 .. 3 do
          let pos = i * 16
          let dst = AST.extract dst 16<rt> pos
          !!ir
            (tmps[i] := AST.ite (cond (idx + i)) (AST.extract src 16<rt> pos) dst)
        AST.concatArr tmps
      !!ir (dstA := assign dstA srcA 0)
      !!ir (dstB := assign dstB srcB 4)
      !!ir (dstC := assign dstC srcC 8)
      !!ir (dstD := assign dstD srcD 12)
    | _ -> raise InvalidOperandException
  | 512<rt> ->
    let kl, vl = 32, 512
    match dst with
    | OprReg _ ->
      let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
        transOprToExpr512 ins insLen ctxt dst
      let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
        transOprToExpr512 ins insLen ctxt src
      let assign dst src idx =
        let pos = (idx % 4) * 16
        let dst = AST.extract dst 16<rt> pos
        dst := AST.ite (cond idx) (AST.extract src 16<rt> pos) (masking dst)
      !!ir (assign dstA srcA 0)
      !!ir (assign dstA srcA 1)
      !!ir (assign dstA srcA 2)
      !!ir (assign dstA srcA 3)
      !!ir (assign dstB srcB 4)
      !!ir (assign dstB srcB 5)
      !!ir (assign dstB srcB 6)
      !!ir (assign dstB srcB 7)
      !!ir (assign dstC srcA 8)
      !!ir (assign dstC srcA 9)
      !!ir (assign dstC srcA 10)
      !!ir (assign dstC srcA 11)
      !!ir (assign dstD srcB 12)
      !!ir (assign dstD srcB 13)
      !!ir (assign dstD srcB 14)
      !!ir (assign dstD srcB 15)
      !!ir (assign dstF srcA 16)
      !!ir (assign dstF srcA 17)
      !!ir (assign dstF srcA 18)
      !!ir (assign dstF srcA 19)
      !!ir (assign dstG srcB 20)
      !!ir (assign dstG srcB 21)
      !!ir (assign dstG srcB 22)
      !!ir (assign dstG srcB 23)
      !!ir (assign dstH srcA 24)
      !!ir (assign dstH srcA 25)
      !!ir (assign dstH srcA 26)
      !!ir (assign dstH srcA 27)
      !!ir (assign dstG srcB 28)
      !!ir (assign dstG srcB 29)
      !!ir (assign dstG srcB 30)
      !!ir (assign dstG srcB 31)
    | OprMem _ ->
      let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
        transOprToExpr512 ins insLen ctxt dst
      let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
        transOprToExpr512 ins insLen ctxt src
      let tmps = Array.init 4 (fun _ -> !*ir 16<rt>)
      let assign dst src idx =
        for i in 0 .. 3 do
          let pos = i * 16
          let dst = AST.extract dst 16<rt> pos
          !!ir
            (tmps[i] := AST.ite (cond (idx + i)) (AST.extract src 16<rt> pos) dst)
        AST.concatArr tmps
      !!ir (dstA := assign dstA srcA 0)
      !!ir (dstB := assign dstB srcB 4)
      !!ir (dstC := assign dstC srcC 8)
      !!ir (dstD := assign dstD srcD 12)
      !!ir (dstE := assign dstE srcE 16)
      !!ir (dstF := assign dstF srcF 20)
      !!ir (dstG := assign dstG srcG 24)
      !!ir (dstH := assign dstH srcH 28)
    | _ -> raise InvalidOperandException
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let vmovdqu64 ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src) = getTwoOprs ins
  let oprSize = getOperationSize ins
  let ePrx = getEVEXPrx ins.VEXInfo
  let k = !.ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
  let masking dst =
    match ePrx.Z with
    | Zeroing -> AST.num0 64<rt>
    | Merging -> dst
  let cond idx =
    if ePrx.AAA = 0uy then AST.num0 1<rt> (* no write mask *)
    else AST.extract k 1<rt> idx
  !<ir insLen
  match oprSize with
  | 128<rt> ->
    let kl, vl = 4, 128
    match dst with
    | OprReg _ ->
      let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
      let srcB, srcA = transOprToExpr128 ins insLen ctxt src
      !!ir (dstA := AST.ite (cond 0) srcA (masking dstA))
      !!ir (dstB := AST.ite (cond 1) srcB (masking dstB))
      fillZeroFromVLToMaxVL ctxt dst vl 512 ir
    | OprMem _ ->
      let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
      let srcB, srcA = transOprToExpr128 ins insLen ctxt src
      !!ir (dstA := AST.ite (cond 0) srcA dstA)
      !!ir (dstB := AST.ite (cond 1) srcB dstB)
    | _ -> raise InvalidOperandException
  | 256<rt> ->
    let kl, vl = 8, 256
    match dst with
    | OprReg _ ->
      let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
      let srcD, srcC, srcB, srcA = transOprToExpr256 ins insLen ctxt src
      !!ir (dstA := AST.ite (cond 0) srcA (masking dstA))
      !!ir (dstB := AST.ite (cond 1) srcB (masking dstB))
      !!ir (dstC := AST.ite (cond 2) srcC (masking dstC))
      !!ir (dstD := AST.ite (cond 3) srcD (masking dstD))
      fillZeroFromVLToMaxVL ctxt dst vl 512 ir
    | OprMem _ ->
      let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
      let srcD, srcC, srcB, srcA = transOprToExpr256 ins insLen ctxt src
      !!ir (dstA := AST.ite (cond 0) srcA dstA)
      !!ir (dstB := AST.ite (cond 1) srcB dstB)
      !!ir (dstC := AST.ite (cond 2) srcC dstC)
      !!ir (dstD := AST.ite (cond 3) srcD dstD)
    | _ -> raise InvalidOperandException
  | 512<rt> ->
    let kl, vl = 16, 512
    match dst with
    | OprReg _ ->
      let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
        transOprToExpr512 ins insLen ctxt dst
      let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
        transOprToExpr512 ins insLen ctxt src
      !!ir (dstA := AST.ite (cond 0) srcA (masking dstA))
      !!ir (dstB := AST.ite (cond 1) srcB (masking dstB))
      !!ir (dstC := AST.ite (cond 2) srcC (masking dstC))
      !!ir (dstD := AST.ite (cond 3) srcD (masking dstD))
      !!ir (dstE := AST.ite (cond 4) srcE (masking dstE))
      !!ir (dstF := AST.ite (cond 5) srcF (masking dstF))
      !!ir (dstG := AST.ite (cond 6) srcG (masking dstG))
      !!ir (dstH := AST.ite (cond 7) srcH (masking dstH))
    | OprMem _ ->
      let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
        transOprToExpr512 ins insLen ctxt dst
      let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
        transOprToExpr512 ins insLen ctxt src
      !!ir (dstA := AST.ite (cond 0) srcA dstA)
      !!ir (dstB := AST.ite (cond 1) srcB dstB)
      !!ir (dstC := AST.ite (cond 2) srcC dstC)
      !!ir (dstD := AST.ite (cond 3) srcD dstD)
      !!ir (dstE := AST.ite (cond 4) srcE dstE)
      !!ir (dstF := AST.ite (cond 5) srcF dstF)
      !!ir (dstG := AST.ite (cond 6) srcG dstG)
      !!ir (dstH := AST.ite (cond 7) srcH dstH)
    | _ -> raise InvalidOperandException
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let vmovdqa ins insLen ctxt = buildVectorMove ins insLen ctxt

let vmovdqa64 ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src) = getTwoOprs ins
  let oprSize = getOperationSize ins
  let ePrx = getEVEXPrx ins.VEXInfo
  let k = !.ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
  let masking dst =
    match ePrx.Z with
    | Zeroing -> AST.num0 64<rt>
    | Merging -> dst
  let cond idx =
    (* no write mask *)
    let noWritemask = if ePrx.AAA = 0uy then AST.num1 1<rt> else AST.num0 1<rt>
    AST.extract k 1<rt> idx .| noWritemask
  !<ir insLen
  match oprSize with
  | 128<rt> ->
    let kl, vl = 2, 128
    match dst with
    | OprReg _ ->
      let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
      let srcB, srcA = transOprToExpr128 ins insLen ctxt src
      !!ir (dstA := AST.ite (cond 0) srcA (masking dstA))
      !!ir (dstB := AST.ite (cond 1) srcB (masking dstB))
      fillZeroFromVLToMaxVL ctxt dst vl 512 ir
    | OprMem _ ->
      let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
      let srcB, srcA = transOprToExpr128 ins insLen ctxt src
      !!ir (dstA := AST.ite (cond 0) srcA dstA)
      !!ir (dstB := AST.ite (cond 1) srcB dstB)
    | _ -> raise InvalidOperandException
  | 256<rt> ->
    let kl, vl = 4, 256
    match dst with
    | OprReg _ ->
      let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
      let srcD, srcC, srcB, srcA = transOprToExpr256 ins insLen ctxt src
      !!ir (dstA := AST.ite (cond 0) srcA (masking dstA))
      !!ir (dstB := AST.ite (cond 1) srcB (masking dstB))
      !!ir (dstC := AST.ite (cond 2) srcC (masking dstC))
      !!ir (dstD := AST.ite (cond 3) srcD (masking dstD))
      fillZeroFromVLToMaxVL ctxt dst vl 512 ir
    | OprMem _ ->
      let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
      let srcD, srcC, srcB, srcA = transOprToExpr256 ins insLen ctxt src
      !!ir (dstA := AST.ite (cond 0) srcA dstA)
      !!ir (dstB := AST.ite (cond 1) srcB dstB)
      !!ir (dstC := AST.ite (cond 2) srcC dstC)
      !!ir (dstD := AST.ite (cond 3) srcD dstD)
    | _ -> raise InvalidOperandException
  | 512<rt> ->
    let kl, vl = 8, 512
    match dst with
    | OprReg _ ->
      let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
        transOprToExpr512 ins insLen ctxt dst
      let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
        transOprToExpr512 ins insLen ctxt src
      !!ir (dstA := AST.ite (cond 0) srcA (masking dstA))
      !!ir (dstB := AST.ite (cond 1) srcB (masking dstB))
      !!ir (dstC := AST.ite (cond 2) srcC (masking dstC))
      !!ir (dstD := AST.ite (cond 3) srcD (masking dstD))
      !!ir (dstE := AST.ite (cond 4) srcE (masking dstE))
      !!ir (dstF := AST.ite (cond 5) srcF (masking dstF))
      !!ir (dstG := AST.ite (cond 6) srcG (masking dstG))
      !!ir (dstH := AST.ite (cond 7) srcH (masking dstH))
    | OprMem _ ->
      let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
        transOprToExpr512 ins insLen ctxt dst
      let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
        transOprToExpr512 ins insLen ctxt src
      !!ir (dstA := AST.ite (cond 0) srcA dstA)
      !!ir (dstB := AST.ite (cond 1) srcB dstB)
      !!ir (dstC := AST.ite (cond 2) srcC dstC)
      !!ir (dstD := AST.ite (cond 3) srcD dstD)
      !!ir (dstE := AST.ite (cond 4) srcE dstE)
      !!ir (dstF := AST.ite (cond 5) srcF dstF)
      !!ir (dstG := AST.ite (cond 6) srcG dstG)
      !!ir (dstH := AST.ite (cond 7) srcH dstH)
    | _ -> raise InvalidOperandException
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let vmovntdq ins insLen ctxt =
  SSELifter.buildMove ins insLen ctxt 16

let vmovups ins insLen ctxt =
  buildVectorMove ins insLen ctxt

let vmovupd ins insLen ctxt =
  buildVectorMove ins insLen ctxt

let vmovddup ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src) = getTwoOprs ins
  !<ir insLen
  match getOperationSize ins with
  | 128<rt> ->
    let dst2, dst1 = transOprToExpr128 ins insLen ctxt dst
    let src = transOprToExpr64 ins insLen ctxt src
    !!ir (dst1 := src)
    !!ir (dst2 := src)
    fillZeroHigh128 ctxt dst ir
  | 256<rt> ->
    let dst4, dst3, dst2, dst1 = transOprToExpr256 ins insLen ctxt dst
    let _src4, src3, _src2, src1 = transOprToExpr256 ins insLen ctxt src
    !!ir (dst1 := src1)
    !!ir (dst2 := src1)
    !!ir (dst3 := src3)
    !!ir (dst4 := src3)
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let vmovntps ins insLen ctxt =
  SSELifter.buildMove ins insLen ctxt 16

let vmovntpd ins insLen ctxt =
  SSELifter.buildMove ins insLen ctxt 16

let vmovhlps ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src1, src2) = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
  let src1B, _src1A = transOprToExpr128 ins insLen ctxt src1
  let src2B, _src2A = transOprToExpr128 ins insLen ctxt src2
  !<ir insLen
  !!ir (dstA := src1B)
  !!ir (dstB := src2B)
  fillZeroHigh128 ctxt dst ir
  !>ir insLen

let vmovhpd (ins: InsInfo) insLen ctxt =
  let ir = IRBuilder (8)
  !<ir insLen
  match ins.Operands with
  | TwoOperands (dst, src) ->
    if haveEVEXPrx ins.VEXInfo then ()
    else
      let dst = transOprToExpr64 ins insLen ctxt dst
      let src2, _src1 = transOprToExpr128 ins insLen ctxt src
      !!ir (dst := src2)
  | ThreeOperands (dst, src1, src2)->
    let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
    let _src1B, src1A = transOprToExpr128 ins insLen ctxt src1
    let src2 = transOprToExpr64 ins insLen ctxt src2
    !!ir (dstA := src1A)
    !!ir (dstB := src2)
    fillZeroHigh128 ctxt dst ir
  | _ -> raise InvalidOperandException
  !>ir insLen

let vmovlhps ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src1, src2) = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
  let _src1B, src1A = transOprToExpr128 ins insLen ctxt src1
  let _src2B, src2A = transOprToExpr128 ins insLen ctxt src2
  !<ir insLen
  !!ir (dstA := src1A)
  !!ir (dstB := src2A)
  fillZeroHigh128 ctxt dst ir
  !>ir insLen

let vmovlpd (ins: InsInfo) insLen ctxt =
  let ir = IRBuilder (8)
  !<ir insLen
  match ins.Operands with
  | TwoOperands (dst, src) ->
    let dst = transOprToExpr64 ins insLen ctxt dst
    let _, srcA = transOprToExpr128 ins insLen ctxt src
    !!ir (dst := srcA)
  | ThreeOperands (dst, src1, src2)->
    let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
    let src1B, _src1A = transOprToExpr128 ins insLen ctxt src1
    let src2 = transOprToExpr ins insLen ctxt src2
    !!ir (dstA := src2)
    !!ir (dstB := src1B)
    fillZeroHigh128 ctxt dst ir
  | _ -> raise InvalidOperandException
  !>ir insLen

let vmovmskpd ins insLen ctxt =
  let ir = IRBuilder (4)
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr ins insLen ctxt dst
  let dstSz = TypeCheck.typeOf dst
  let mskpd r =
    match Register.getKind r with
    | Register.Kind.XMM -> SSELifter.movmskpd ins insLen ctxt
    | Register.Kind.YMM ->
      !<ir insLen
      let src4, src3, src2, src1 = transOprToExpr256 ins insLen ctxt src
      let src63 = AST.sext dstSz (AST.xthi 1<rt> src1)
      let src127 = (AST.sext dstSz (AST.xthi 1<rt> src2)) << AST.num1 dstSz
      let src191 = (AST.sext dstSz (AST.xthi 1<rt> src3)) << numI32 2 dstSz
      let src255 = (AST.sext dstSz (AST.xthi 1<rt> src4)) << numI32 3 dstSz
      !!ir (dst := src63 .| src127 .| src191 .| src255)
      !>ir insLen
    | _ -> raise InvalidOperandException
  match src with
  | OprReg r -> mskpd r
  | _ -> raise InvalidOperandSizeException

let vmovmskps ins insLen ctxt =
  let ir = IRBuilder (4)
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr ins insLen ctxt dst
  let dstSz = TypeCheck.typeOf dst
  let mskpd r =
    match Register.getKind r with
    | Register.Kind.XMM -> SSELifter.movmskps ins insLen ctxt
    | Register.Kind.YMM ->
      !<ir insLen
      let src4, src3, src2, src1 = transOprToExpr256 ins insLen ctxt src
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
      !!ir (dst := src31 .| src63 .| src95 .| src127)
      !!ir (dst := dst .| src159 .| src191 .| src223 .| src255)
      !>ir insLen
    | _ -> raise InvalidOperandException
  match src with
  | OprReg r -> mskpd r
  | _ -> raise InvalidOperandSizeException

let vmovsd (ins: InsInfo) insLen ctxt =
  let ir = IRBuilder (8)
  !<ir insLen
  match ins.Operands with
  | TwoOperands (OprMem _ , _) -> SSELifter.movsd ins insLen ctxt
  | TwoOperands (OprReg _ as dst, src) ->
    let dst2, dst1 = transOprToExpr128 ins insLen ctxt dst
    let src = transOprToExpr64 ins insLen ctxt src
    !!ir (dst1 := src)
    !!ir (dst2 := AST.num0 64<rt>)
    fillZeroHigh128 ctxt dst ir
    !>ir insLen
  | ThreeOperands (dst, src1, src2)->
    let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
    let src1B, _src1A = transOprToExpr128 ins insLen ctxt src1
    let _src2B, src2A = transOprToExpr128 ins insLen ctxt src2
    !!ir (dstA := src2A)
    !!ir (dstB := src1B)
    fillZeroHigh128 ctxt dst ir
    !>ir insLen
  | _ -> raise InvalidOperandException

let vmovshdup ins insLen ctxt =
  let ir = IRBuilder (16)
  let struct (dst, src) = getTwoOprs ins
  !<ir insLen
  match getOperationSize ins with
  | 128<rt> ->
    let dst2, dst1 = transOprToExpr128 ins insLen ctxt dst
    let src2, src1 = transOprToExpr128 ins insLen ctxt src
    !!ir (AST.xtlo 32<rt> dst1 := AST.xthi 32<rt> src1)
    !!ir (AST.xthi 32<rt> dst1 := AST.xthi 32<rt> src1)
    !!ir (AST.xtlo 32<rt> dst2 := AST.xthi 32<rt> src2)
    !!ir (AST.xthi 32<rt> dst2 := AST.xthi 32<rt> src2)
    fillZeroHigh128 ctxt dst ir
  | 256<rt> ->
    let dst4, dst3, dst2, dst1 = transOprToExpr256 ins insLen ctxt dst
    let src4, src3, src2, src1 = transOprToExpr256 ins insLen ctxt src
    !!ir (AST.xtlo 32<rt> dst1 := AST.xthi 32<rt> src1)
    !!ir (AST.xthi 32<rt> dst1 := AST.xthi 32<rt> src1)
    !!ir (AST.xtlo 32<rt> dst2 := AST.xthi 32<rt> src2)
    !!ir (AST.xthi 32<rt> dst2 := AST.xthi 32<rt> src2)
    !!ir (AST.xtlo 32<rt> dst3 := AST.xthi 32<rt> src3)
    !!ir (AST.xthi 32<rt> dst3 := AST.xthi 32<rt> src3)
    !!ir (AST.xtlo 32<rt> dst4 := AST.xthi 32<rt> src4)
    !!ir (AST.xthi 32<rt> dst4 := AST.xthi 32<rt> src4)
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let vmovsldup ins insLen ctxt =
  let ir = IRBuilder (16)
  let struct (dst, src) = getTwoOprs ins
  !<ir insLen
  match getOperationSize ins with
  | 128<rt> ->
    let dst2, dst1 = transOprToExpr128 ins insLen ctxt dst
    let src2, src1 = transOprToExpr128 ins insLen ctxt src
    !!ir (AST.xtlo 32<rt> dst1 := AST.xtlo 32<rt> src1)
    !!ir (AST.xthi 32<rt> dst1 := AST.xtlo 32<rt> src1)
    !!ir (AST.xtlo 32<rt> dst2 := AST.xtlo 32<rt> src2)
    !!ir (AST.xthi 32<rt> dst2 := AST.xtlo 32<rt> src2)
    fillZeroHigh128 ctxt dst ir
  | 256<rt> ->
    let dst4, dst3, dst2, dst1 = transOprToExpr256 ins insLen ctxt dst
    let src4, src3, src2, src1 = transOprToExpr256 ins insLen ctxt src
    !!ir (AST.xtlo 32<rt> dst1 := AST.xtlo 32<rt> src1)
    !!ir (AST.xthi 32<rt> dst1 := AST.xtlo 32<rt> src1)
    !!ir (AST.xtlo 32<rt> dst2 := AST.xtlo 32<rt> src2)
    !!ir (AST.xthi 32<rt> dst2 := AST.xtlo 32<rt> src2)
    !!ir (AST.xtlo 32<rt> dst3 := AST.xtlo 32<rt> src3)
    !!ir (AST.xthi 32<rt> dst3 := AST.xtlo 32<rt> src3)
    !!ir (AST.xtlo 32<rt> dst4 := AST.xtlo 32<rt> src4)
    !!ir (AST.xthi 32<rt> dst4 := AST.xtlo 32<rt> src4)
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let vmovss (ins: InsInfo) insLen ctxt =
  let ir = IRBuilder (8)
  !<ir insLen
  match ins.Operands with
  | TwoOperands (OprMem _ , _) -> SSELifter.movss ins insLen ctxt
  | TwoOperands (OprReg _ as dst, src) ->
    let dst2, dst1 = transOprToExpr128 ins insLen ctxt dst
    let src = transOprToExpr32 ins insLen ctxt src
    !!ir (AST.xtlo 32<rt> dst1 := src)
    !!ir (AST.xthi 32<rt> dst1 := AST.num0 32<rt>)
    !!ir (dst2 := AST.num0 64<rt>)
    fillZeroHigh128 ctxt dst ir
    !>ir insLen
  | ThreeOperands (dst, src1, src2)->
    let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
    let src1B, src1A = transOprToExpr128 ins insLen ctxt src1
    let _src2B, src2A = transOprToExpr128 ins insLen ctxt src2
    !!ir (AST.xtlo 32<rt> dstA := AST.xtlo 32<rt> src2A)
    !!ir (AST.xthi 32<rt> dstA := AST.xthi 32<rt> src1A)
    !!ir (dstB := src1B)
    fillZeroHigh128 ctxt dst ir
    !>ir insLen
  | _ -> raise InvalidOperandException

let vandps ins insLen ctxt =
  vexedPackedFPBinOp32 ins insLen ctxt (.&)

let vandpd ins insLen ctxt =
  vexedPackedFPBinOp64 ins insLen ctxt (.&)

let private andnpdOp e1 e2 = (AST.not e1) .& e2

let vandnps ins insLen ctxt =
  vexedPackedFPBinOp32 ins insLen ctxt andnpdOp

let vandnpd ins insLen ctxt =
  vexedPackedFPBinOp64 ins insLen ctxt andnpdOp

let vorps ins insLen ctxt =
  vexedPackedFPBinOp32 ins insLen ctxt (.|)

let vorpd ins insLen ctxt =
  vexedPackedFPBinOp64 ins insLen ctxt (.|)

let vshufi32x4 ins insLen ctxt =
  let ir = IRBuilder (16)
  let struct (dst, src1, src2, imm) = getFourOprs ins
  let oprSize = getOperationSize ins
  let ePrx = getEVEXPrx ins.VEXInfo
  let k = !.ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
  let masking dst =
    match ePrx.Z with
    | Zeroing -> AST.num0 32<rt>
    | Merging -> dst
  let cond idx =
    (* no write mask *)
    let noWritemask = if ePrx.AAA = 0uy then AST.num1 1<rt> else AST.num0 1<rt>
    AST.extract k 1<rt> idx .| noWritemask
  let i8 = getImmValue imm
  !<ir insLen
  match oprSize with
  | 256<rt> ->
    let kl, vl = 8, 256
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
    let src1D, src1C, src1B, src1A =
      transOprToExpr256 ins insLen ctxt src1
    let src2D, src2C, src2B, src2A =
      transOprToExpr256 ins insLen ctxt src2
    let struct (tDstD, tDstC, tDstB, tDstA) = tmpVars4 ir 64<rt>
    let imm0 (* imm8[0] *) = i8 &&& 0b1L
    let imm1 (* imm8[1] *) = (i8 >>> 1) &&& 0b1L
    !!ir (tDstA := if imm0 = 0L then src1A else src1C)
    !!ir (tDstB := if imm0 = 0L then src1D else src1B)
    !!ir (tDstC := if imm1 = 0L then src2C else src2A)
    !!ir (tDstD := if imm1 = 0L then src2D else src2B)
    let assign dst tDst idx =
      let pos = (idx % 2) * 32
      let dst = AST.extract dst 32<rt> pos
      dst := AST.ite (cond idx) (AST.extract tDst 32<rt> pos) (masking dst)
    !!ir (assign dstA tDstA 0)
    !!ir (assign dstA tDstA 1)
    !!ir (assign dstB tDstB 2)
    !!ir (assign dstB tDstB 3)
    !!ir (assign dstC tDstC 4)
    !!ir (assign dstC tDstC 5)
    !!ir (assign dstD tDstD 6)
    !!ir (assign dstD tDstD 7)
  | 512<rt> ->
    let kl, vl = 16, 512
    let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
      transOprToExpr512 ins insLen ctxt dst
    let src1H, src1G, src1F, src1E, src1D, src1C, src1B, src1A =
      transOprToExpr512 ins insLen ctxt src1
    let src2H, src2G, src2F, src2E, src2D, src2C, src2B, src2A =
      transOprToExpr512 ins insLen ctxt src2
    let struct (tDstD, tDstC, tDstB, tDstA) = tmpVars4 ir 64<rt>
    let struct (tDstH, tDstG, tDstF, tDstE) = tmpVars4 ir 64<rt>
    let tS2Arr = Array.init (kl / 2) (fun _ -> !*ir 64<rt>)
    let src2Arr = [| src2A; src2B; src2C; src2D; src2E; src2F; src2G; src2H |]
    match src2 with
    | OprMem _ when ePrx.B = 1uy ->
      let tSrcA = !*ir 64<rt>
      let tSrcA32 (* SRC2[31:0] *) = AST.extract src2A 32<rt> 0
      !!ir (tSrcA := AST.concat tSrcA32 tSrcA32)
      for i in 0 .. (kl / 2) - 1 do !!ir (tS2Arr[i] := tSrcA)
    | _ -> for i in 0 .. (kl / 2) - 1 do !!ir (tS2Arr[i] := src2Arr[i])
    let select4 control srcA srcB srcC srcD =
      match control (* control[1:0] *) with
      | 0b00L -> srcA
      | 0b01L -> srcB
      | 0b10L -> srcC
      | _ (* 11 *) -> srcD
    let ctrl imm8 amt = (imm8 >>> amt) &&& 0b11L
    !!ir (tDstA := select4 (ctrl i8 0) src1A src1C src1E src1G)
    !!ir (tDstB := select4 (ctrl i8 0) src1B src1D src1F src1H)
    !!ir (tDstC := select4 (ctrl i8 2) src1A src1C src1E src1G)
    !!ir (tDstD := select4 (ctrl i8 2) src1B src1D src1F src1H)
    !!ir (tDstE := select4 (ctrl i8 4) tS2Arr[0] tS2Arr[2] tS2Arr[4] tS2Arr[6])
    !!ir (tDstF := select4 (ctrl i8 4) tS2Arr[1] tS2Arr[3] tS2Arr[5] tS2Arr[7])
    !!ir (tDstG := select4 (ctrl i8 6) tS2Arr[0] tS2Arr[2] tS2Arr[4] tS2Arr[6])
    !!ir (tDstH := select4 (ctrl i8 6) tS2Arr[1] tS2Arr[3] tS2Arr[5] tS2Arr[7])
    let assign dst tDst idx =
      let pos = (idx % 2) * 32
      let dst = AST.extract dst 32<rt> pos
      dst := AST.ite (cond idx) (AST.extract tDst 32<rt> pos) (masking dst)
    !!ir (assign dstA tDstA 0)
    !!ir (assign dstA tDstA 1)
    !!ir (assign dstB tDstB 2)
    !!ir (assign dstB tDstB 3)
    !!ir (assign dstC tDstC 4)
    !!ir (assign dstC tDstC 5)
    !!ir (assign dstD tDstD 6)
    !!ir (assign dstD tDstD 7)
    !!ir (assign dstE tDstE 8)
    !!ir (assign dstE tDstE 9)
    !!ir (assign dstF tDstF 10)
    !!ir (assign dstF tDstF 11)
    !!ir (assign dstG tDstG 12)
    !!ir (assign dstG tDstG 13)
    !!ir (assign dstH tDstH 14)
    !!ir (assign dstH tDstH 15)
  | _ -> raise InvalidOperandException
  !>ir insLen

let vshufps ins insLen ctxt =
  let ir = IRBuilder (32)
  let struct (dst, src1, src2, imm) = getFourOprs ins
  let imm = transOprToExpr ins insLen ctxt imm
  let cond1 = AST.xtlo 2<rt> imm
  let cond2 = AST.extract imm 2<rt> 2
  let cond3 = AST.extract imm 2<rt> 4
  let cond4 = AST.extract imm 2<rt> 6
  let doShuf cond dst e1 e2 =
    !!ir (dst := AST.num0 32<rt>)
    !!ir (dst := AST.ite (cond == AST.num0 2<rt>) (AST.xtlo 32<rt> e1) dst)
    !!ir (dst := AST.ite (cond == AST.num1 2<rt>) (AST.xthi 32<rt> e1) dst)
    !!ir (dst := AST.ite (cond == numI32 2 2<rt>) (AST.xtlo 32<rt> e2) dst)
    !!ir (dst := AST.ite (cond == numI32 3 2<rt>) (AST.xthi 32<rt> e2) dst)
  !<ir insLen
  match getOperationSize ins with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
    let sr1B, sr1A = transOprToExpr128 ins insLen ctxt src1
    let sr2B, sr2A = transOprToExpr128 ins insLen ctxt src2
    doShuf cond1 (AST.xtlo 32<rt> dstA) sr1A sr1B
    doShuf cond2 (AST.xthi 32<rt> dstA) sr1A sr1B
    doShuf cond3 (AST.xtlo 32<rt> dstB) sr2A sr2B
    doShuf cond4 (AST.xthi 32<rt> dstB) sr2A sr2B
    fillZeroHigh128 ctxt dst ir
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
    let sr1D, sr1C, sr1B, sr1A = transOprToExpr256 ins insLen ctxt src1
    let sr2D, sr2C, sr2B, sr2A = transOprToExpr256 ins insLen ctxt src2
    doShuf cond1 (AST.xtlo 32<rt> dstA) sr1A sr1B
    doShuf cond2 (AST.xthi 32<rt> dstA) sr1A sr1B
    doShuf cond3 (AST.xtlo 32<rt> dstB) sr2A sr2B
    doShuf cond4 (AST.xthi 32<rt> dstB) sr2A sr2B
    doShuf cond1 (AST.xtlo 32<rt> dstC) sr1C sr1D
    doShuf cond2 (AST.xthi 32<rt> dstC) sr1C sr1D
    doShuf cond3 (AST.xtlo 32<rt> dstD) sr2C sr2D
    doShuf cond4 (AST.xthi 32<rt> dstD) sr2C sr2D
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let vshufpd ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src1, src2, imm) = getFourOprs ins
  let imm = transOprToExpr ins insLen ctxt imm
  let cond1 = AST.xtlo 1<rt> imm
  let cond2 = AST.extract imm 1<rt> 1
  let cond3 = AST.extract imm 1<rt> 2
  let cond4 = AST.extract imm 1<rt> 3
  !<ir insLen
  match getOperationSize ins with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
    let src1B, src1A = transOprToExpr128 ins insLen ctxt src1
    let src2B, src2A = transOprToExpr128 ins insLen ctxt src2
    !!ir (dstA := AST.ite cond1 src1B src1A)
    !!ir (dstB := AST.ite cond2 src2B src2A)
    fillZeroHigh128 ctxt dst ir
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
    let sr1D, sr1C, sr1B, sr1A = transOprToExpr256 ins insLen ctxt src1
    let sr2D, sr2C, sr2B, sr2A = transOprToExpr256 ins insLen ctxt src2
    !!ir (dstA := AST.ite cond1 sr1B sr1A)
    !!ir (dstB := AST.ite cond2 sr2B sr2A)
    !!ir (dstC := AST.ite cond3 sr1D sr1C)
    !!ir (dstD := AST.ite cond4 sr2D sr2C)
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let vunpckhps ins insLen ctxt =
  let ir = IRBuilder (16)
  let struct (dst, src1, src2) = getThreeOprs ins
  !<ir insLen
  match getOperationSize ins with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
    let src1B, _src1A = transOprToExpr128 ins insLen ctxt src1
    let src2B, _src2A = transOprToExpr128 ins insLen ctxt src2
    !!ir (AST.xtlo 32<rt> dstA := AST.xtlo 32<rt> src1B)
    !!ir (AST.xthi 32<rt> dstA := AST.xtlo 32<rt> src2B)
    !!ir (AST.xtlo 32<rt> dstB := AST.xthi 32<rt> src1B)
    !!ir (AST.xthi 32<rt> dstB := AST.xthi 32<rt> src2B)
    fillZeroHigh128 ctxt dst ir
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
    let sr1D, _, sr1B, _ = transOprToExpr256 ins insLen ctxt src1
    let sr2D, _, sr2B, _ = transOprToExpr256 ins insLen ctxt src2
    !!ir (AST.xtlo 32<rt> dstA := AST.xtlo 32<rt> sr1B)
    !!ir (AST.xthi 32<rt> dstA := AST.xtlo 32<rt> sr2B)
    !!ir (AST.xtlo 32<rt> dstB := AST.xthi 32<rt> sr1B)
    !!ir (AST.xthi 32<rt> dstB := AST.xthi 32<rt> sr2B)
    !!ir (AST.xtlo 32<rt> dstC := AST.xtlo 32<rt> sr1D)
    !!ir (AST.xthi 32<rt> dstC := AST.xtlo 32<rt> sr2D)
    !!ir (AST.xtlo 32<rt> dstD := AST.xthi 32<rt> sr1D)
    !!ir (AST.xthi 32<rt> dstD := AST.xthi 32<rt> sr2D)
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let vunpckhpd ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src1, src2) = getThreeOprs ins
  !<ir insLen
  match getOperationSize ins with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
    let src1B, _src1A = transOprToExpr128 ins insLen ctxt src1
    let src2B, _src2A = transOprToExpr128 ins insLen ctxt src2
    !!ir (dstA := src1B)
    !!ir (dstB := src2B)
    fillZeroHigh128 ctxt dst ir
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
    let sr1D, _, sr1B, _ = transOprToExpr256 ins insLen ctxt src1
    let sr2D, _, sr2B, _ = transOprToExpr256 ins insLen ctxt src2
    !!ir (dstA := sr1B)
    !!ir (dstB := sr2B)
    !!ir (dstC := sr1D)
    !!ir (dstD := sr2D)
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let vunpcklps ins insLen ctxt =
  let ir = IRBuilder (16)
  let struct (dst, src1, src2) = getThreeOprs ins
  !<ir insLen
  match getOperationSize ins with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
    let _src1B, src1A = transOprToExpr128 ins insLen ctxt src1
    let _src2B, src2A = transOprToExpr128 ins insLen ctxt src2
    !!ir (AST.xtlo 32<rt> dstA := AST.xtlo 32<rt> src1A)
    !!ir (AST.xthi 32<rt> dstA := AST.xtlo 32<rt> src2A)
    !!ir (AST.xtlo 32<rt> dstB := AST.xthi 32<rt> src1A)
    !!ir (AST.xthi 32<rt> dstB := AST.xthi 32<rt> src2A)
    fillZeroHigh128 ctxt dst ir
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
    let _, src1C, _, src1A = transOprToExpr256 ins insLen ctxt src1
    let _, src2C, _, src2A = transOprToExpr256 ins insLen ctxt src2
    !!ir (AST.xtlo 32<rt> dstA := AST.xtlo 32<rt> src1A)
    !!ir (AST.xthi 32<rt> dstA := AST.xtlo 32<rt> src2A)
    !!ir (AST.xtlo 32<rt> dstB := AST.xthi 32<rt> src1A)
    !!ir (AST.xthi 32<rt> dstB := AST.xthi 32<rt> src2A)
    !!ir (AST.xtlo 32<rt> dstC := AST.xtlo 32<rt> src1C)
    !!ir (AST.xthi 32<rt> dstC := AST.xtlo 32<rt> src2C)
    !!ir (AST.xtlo 32<rt> dstD := AST.xthi 32<rt> src1C)
    !!ir (AST.xthi 32<rt> dstD := AST.xthi 32<rt> src2C)
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let vunpcklpd ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src1, src2) = getThreeOprs ins
  !<ir insLen
  match getOperationSize ins with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
    let _src1B, src1A = transOprToExpr128 ins insLen ctxt src1
    let _src2B, src2A = transOprToExpr128 ins insLen ctxt src2
    !!ir (dstA := src1A)
    !!ir (dstB := src2A)
    fillZeroHigh128 ctxt dst ir
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
    let _, src1C, _, src1A = transOprToExpr256 ins insLen ctxt src1
    let _, src2C, _, src2A = transOprToExpr256 ins insLen ctxt src2
    !!ir (dstA := src1A)
    !!ir (dstB := src2A)
    !!ir (dstC := src1C)
    !!ir (dstD := src2C)
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let vxorps ins insLen ctxt =
  match getOperationSize ins with
  | 512<rt> ->
    let ir = IRBuilder (16)
    let struct (dst, src1, src2) = getThreeOprs ins
    !<ir insLen
    let ePrx = getEVEXPrx ins.VEXInfo
    let k = !.ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
    let masking dst =
      match ePrx.Z with
      | Zeroing -> AST.num0 32<rt>
      | Merging -> dst
    let cond idx =
      (* no write mask *)
      let noWritemask = if ePrx.AAA = 0uy then AST.num1 1<rt> else AST.num0 1<rt>
      AST.extract k 1<rt> idx .| noWritemask
    let tmpDest = Array.init 2 (fun _ -> !*ir 32<rt>)
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
        !!ir (tmpDest[i] := AST.ite (cond (idx + i)) tSrc (masking dst))
      AST.concatArr tmpDest
    let kl, vl = 16, 512
    let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
      transOprToExpr512 ins insLen ctxt dst
    let src1H, src1G, src1F, src1E, src1D, src1C, src1B, src1A =
      transOprToExpr512 ins insLen ctxt src1
    let src2H, src2G, src2F, src2E, src2D, src2C, src2B, src2A =
      transOprToExpr512 ins insLen ctxt src2
    !!ir (dstA := evAssign dstA src1A src2A src2A 0)
    !!ir (dstB := evAssign dstB src1B src2B src2A 2)
    !!ir (dstC := evAssign dstC src1C src2C src2A 4)
    !!ir (dstD := evAssign dstD src1D src2D src2A 6)
    !!ir (dstE := evAssign dstE src1E src2E src2A 8)
    !!ir (dstF := evAssign dstF src1F src2F src2A 10)
    !!ir (dstG := evAssign dstG src1G src2G src2A 12)
    !!ir (dstH := evAssign dstH src1H src2H src2A 14)
    !>ir insLen
  | _ -> vexedPackedFPBinOp32 ins insLen ctxt (<+>)

let vxorpd ins insLen ctxt =
  vexedPackedFPBinOp64 ins insLen ctxt (<+>)

let vbroadcasti128 ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src) = getTwoOprs ins
  let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
  let srcB, srcA = transOprToExpr128 ins insLen ctxt src
  !<ir insLen
  !!ir (dstA := srcA)
  !!ir (dstB := srcB)
  !!ir (dstC := srcA)
  !!ir (dstD := srcB)
  !>ir insLen

let vbroadcastss ins insLen ctxt =
  let ir = IRBuilder (32)
  let struct (dst, src) = getTwoOprs ins
  let src = transOprToExpr32 ins insLen ctxt src
  let tmp = !*ir 32<rt>
  !<ir insLen
  match getOperationSize ins with
  | 128<rt> ->
    let dst2, dst1 = transOprToExpr128 ins insLen ctxt dst
    !!ir (tmp := src)
    !!ir (AST.xtlo 32<rt> dst1 := tmp)
    !!ir (AST.xthi 32<rt> dst1 := tmp)
    !!ir (AST.xtlo 32<rt> dst2 := tmp)
    !!ir (AST.xthi 32<rt> dst2 := tmp)
    fillZeroHigh128 ctxt dst ir
  | 256<rt> ->
    let dst4, dst3, dst2, dst1 = transOprToExpr256 ins insLen ctxt dst
    !!ir (tmp := src)
    !!ir (AST.xtlo 32<rt> dst1 := tmp)
    !!ir (AST.xthi 32<rt> dst1 := tmp)
    !!ir (AST.xtlo 32<rt> dst2 := tmp)
    !!ir (AST.xthi 32<rt> dst2 := tmp)
    !!ir (AST.xtlo 32<rt> dst3 := tmp)
    !!ir (AST.xthi 32<rt> dst3 := tmp)
    !!ir (AST.xtlo 32<rt> dst4 := tmp)
    !!ir (AST.xthi 32<rt> dst4 := tmp)
  | 512<rt> -> ()
  | _ -> raise InvalidOperandException
  !>ir insLen

let vextracti32x8 ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src, imm) = getThreeOprs ins
  let oprSize = getOperationSize ins
  let ePrx = getEVEXPrx ins.VEXInfo
  let k = !.ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
  let masking dst =
    match ePrx.Z with
    | Zeroing -> AST.num0 32<rt>
    | Merging -> dst
  let cond idx =
    (* no write mask *)
    let noWritemask = if ePrx.AAA = 0uy then AST.num1 1<rt> else AST.num0 1<rt>
    AST.extract k 1<rt> idx .| noWritemask
  let vl = 512
  let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
  let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
    transOprToExpr512 ins insLen ctxt src
  let imm0 = getImmValue imm &&& 0b1L (* imm8[0] *)
  let struct (tDstD, tDstC, tDstB, tDstA) = tmpVars4 ir 64<rt>
  !<ir insLen
  if imm0 = 0L then
    !!ir (tDstA := srcA)
    !!ir (tDstB := srcB)
    !!ir (tDstC := srcC)
    !!ir (tDstD := srcD)
  else (* imm0 = 1 *)
    !!ir (tDstA := srcE)
    !!ir (tDstB := srcF)
    !!ir (tDstC := srcG)
    !!ir (tDstD := srcH)
  match dst with
  | OprReg _ ->
    let tmps = Array.init 2 (fun _ -> !*ir 32<rt>)
    let assign dst src idx =
      for i in 0 .. 1 do
        let dst = AST.extract dst 32<rt> (i * 32)
        let src = AST.extract src 32<rt> (i * 32)
        !!ir (tmps[i] := AST.ite (cond (idx + i)) src (masking dst))
      AST.concatArr tmps
    !!ir (dstA := assign dstA tDstA 0)
    !!ir (dstB := assign dstB tDstB 2)
    !!ir (dstC := assign dstC tDstC 4)
    !!ir (dstD := assign dstD tDstD 6)
  | OprMem _ ->
    let tmps = Array.init 2 (fun _ -> !*ir 32<rt>)
    let assign dst src idx =
      for i in 0 .. 1 do
        let dst = AST.extract dst 32<rt> (i * 32)
        let src = AST.extract src 32<rt> (i * 32)
        !!ir (tmps[i] := AST.ite (cond (idx + i)) src dst)
      AST.concatArr tmps
    !!ir (dstA := assign dstA tDstA 0)
    !!ir (dstB := assign dstB tDstB 2)
    !!ir (dstC := assign dstC tDstC 4)
    !!ir (dstD := assign dstD tDstD 6)
  | _ -> raise InvalidOperandException
  !>ir insLen

let vextracti64x4 ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src, imm) = getThreeOprs ins
  let oprSize = getOperationSize ins
  let ePrx = getEVEXPrx ins.VEXInfo
  let k = !.ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
  let masking dst =
    match ePrx.Z with
    | Zeroing -> AST.num0 64<rt>
    | Merging -> dst
  let cond idx =
    (* no write mask *)
    let noWritemask = if ePrx.AAA = 0uy then AST.num1 1<rt> else AST.num0 1<rt>
    AST.extract k 1<rt> idx .| noWritemask
  let vl = 512
  let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
  let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
    transOprToExpr512 ins insLen ctxt src
  let imm0 = getImmValue imm &&& 0b1L (* imm8[0] *)
  let struct (tDstD, tDstC, tDstB, tDstA) = tmpVars4 ir 64<rt>
  !<ir insLen
  if imm0 = 0L then
    !!ir (tDstA := srcA)
    !!ir (tDstB := srcB)
    !!ir (tDstC := srcC)
    !!ir (tDstD := srcD)
  else (* imm0 = 1 *)
    !!ir (tDstA := srcE)
    !!ir (tDstB := srcF)
    !!ir (tDstC := srcG)
    !!ir (tDstD := srcH)
  match dst with
  | OprReg _ ->
    !!ir (dstA := AST.ite (cond 0) tDstA (masking dstA))
    !!ir (dstB := AST.ite (cond 1) tDstB (masking dstB))
    !!ir (dstC := AST.ite (cond 2) tDstC (masking dstC))
    !!ir (dstD := AST.ite (cond 3) tDstD (masking dstD))
  | OprMem _ ->
    !!ir (dstA := AST.ite (cond 0) tDstA dstA)
    !!ir (dstB := AST.ite (cond 1) tDstB dstB)
    !!ir (dstC := AST.ite (cond 2) tDstC dstC)
    !!ir (dstD := AST.ite (cond 3) tDstD dstD)
  | _ -> raise InvalidOperandException
  !>ir insLen

let vinserti128 ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src1, src2, imm) = getFourOprs ins
  let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
  let src1D, src1C, src1B, src1A = transOprToExpr256 ins insLen ctxt src1
  let src2B, src2A = transOprToExpr128 ins insLen ctxt src2
  let imm = transOprToExpr ins insLen ctxt imm
  let cond = !*ir 1<rt>
  !<ir insLen
  !!ir (cond := AST.xtlo 1<rt> imm)
  !!ir (dstA := AST.ite cond src1A src2A)
  !!ir (dstB := AST.ite cond src1B src2B)
  !!ir (dstC := AST.ite cond src2A src1C)
  !!ir (dstD := AST.ite cond src2B src1D)
  !>ir insLen

let vpaddb ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 8<rt> (opP (.+)) 32

let vpaddd ins insLen ctxt =
  match getOperationSize ins with
  | 512<rt> ->
    let ir = IRBuilder (16)
    let struct (dst, src1, src2) = getThreeOprs ins
    !<ir insLen
    let ePrx = getEVEXPrx ins.VEXInfo
    let k = !.ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
    let masking dst =
      match ePrx.Z with
      | Zeroing -> AST.num0 32<rt>
      | Merging -> dst
    let cond idx =
      (* no write mask *)
      let noWritemask = if ePrx.AAA = 0uy then AST.num1 1<rt> else AST.num0 1<rt>
      AST.extract k 1<rt> idx .| noWritemask
    let tmpDest = Array.init 2 (fun _ -> !*ir 32<rt>)
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
        !!ir (tmpDest[i] := AST.ite (cond (idx + i)) tSrc (masking dst))
      AST.concatArr tmpDest
    let kl, vl = 16, 512
    let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
      transOprToExpr512 ins insLen ctxt dst
    let src1H, src1G, src1F, src1E, src1D, src1C, src1B, src1A =
      transOprToExpr512 ins insLen ctxt src1
    let src2H, src2G, src2F, src2E, src2D, src2C, src2B, src2A =
      transOprToExpr512 ins insLen ctxt src2
    !!ir (dstA := evAssign dstA src1A src2A src2A 0)
    !!ir (dstB := evAssign dstB src1B src2B src2A 2)
    !!ir (dstC := evAssign dstC src1C src2C src2A 4)
    !!ir (dstD := evAssign dstD src1D src2D src2A 6)
    !!ir (dstE := evAssign dstE src1E src2E src2A 8)
    !!ir (dstF := evAssign dstF src1F src2F src2A 10)
    !!ir (dstG := evAssign dstG src1G src2G src2A 12)
    !!ir (dstH := evAssign dstH src1H src2H src2A 14)
    !>ir insLen
  | _ -> buildPackedInstr ins insLen ctxt 32<rt> (opP (.+)) 16

let vpaddq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 64<rt> (opP (.+)) 16

let vpalignr ins insLen ctxt =
  let ir = IRBuilder (16)
  let struct (dst, src1, src2, imm) = getFourOprs ins
  let oprSize = getOperationSize ins
  let imm = getImmValue imm
  let amount = imm * 8L
  let rAmt = numI64 (amount % 64L) 64<rt> (* Right Shift *)
  let lAmt = numI64 (64L - (amount % 64L)) 64<rt> (* Left Shift *)
  !<ir insLen
  if oprSize = 128<rt> then
    let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
    let src1B, src1A = transOprToExpr128 ins insLen ctxt src1
    let src2B, src2A = transOprToExpr128 ins insLen ctxt src2
    let struct (tSrc1A, tSrc1B, tSrc2A, tSrc2B) = tmpVars4 ir 64<rt>
    !!ir (tSrc1A := src1A)
    !!ir (tSrc1B := src1B)
    !!ir (tSrc2A := src2A)
    !!ir (tSrc2B := src2B)
    if amount < 64 then
      !!ir (dstA := (tSrc2B << lAmt) .| (tSrc2A >> rAmt))
      !!ir (dstB := (tSrc1A << lAmt) .| (tSrc2B >> rAmt))
    elif amount < 128 then
      !!ir (dstA := (tSrc1A << lAmt) .| (tSrc2B >> rAmt))
      !!ir (dstB := (tSrc1B << lAmt) .| (tSrc1A >> rAmt))
    elif amount < 192 then
      !!ir (dstA := (tSrc1B << lAmt) .| (tSrc1A >> rAmt))
      !!ir (dstB := tSrc1B >> rAmt)
    else
      !!ir (dstA := tSrc1B >> rAmt)
      !!ir (dstB := AST.num0 64<rt>)
    fillZeroHigh128 ctxt dst ir
  elif oprSize = 256<rt> then
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
    let src1D, src1C, src1B, src1A = transOprToExpr256 ins insLen ctxt src1
    let src2D, src2C, src2B, src2A = transOprToExpr256 ins insLen ctxt src2
    let struct (tSrc1A, tSrc1B, tSrc1C, tSrc1D) = tmpVars4 ir 64<rt>
    let struct (tSrc2A, tSrc2B, tSrc2C, tSrc2D) = tmpVars4 ir 64<rt>
    !!ir (tSrc1A := src1A)
    !!ir (tSrc1B := src1B)
    !!ir (tSrc1C := src1C)
    !!ir (tSrc1D := src1D)
    !!ir (tSrc2A := src2A)
    !!ir (tSrc2B := src2B)
    !!ir (tSrc2C := src2C)
    !!ir (tSrc2D := src2D)
    if amount < 64 then
      !!ir (dstA := (tSrc2B << lAmt) .| (tSrc2A >> rAmt))
      !!ir (dstB := (tSrc1A << lAmt) .| (tSrc2B >> rAmt))
      !!ir (dstC := (tSrc2D << lAmt) .| (tSrc2C >> rAmt))
      !!ir (dstD := (tSrc1C << lAmt) .| (tSrc2D >> rAmt))
    elif amount < 128 then
      !!ir (dstA := (tSrc1A << lAmt) .| (tSrc2B >> rAmt))
      !!ir (dstB := (tSrc1B << lAmt) .| (tSrc1A >> rAmt))
      !!ir (dstC := (tSrc1C << lAmt) .| (tSrc2D >> rAmt))
      !!ir (dstD := (tSrc1D << lAmt) .| (tSrc1C >> rAmt))
    elif amount < 192 then
      !!ir (dstA := (tSrc1B << lAmt) .| (tSrc1A >> rAmt))
      !!ir (dstB := tSrc1B >> rAmt)
      !!ir (dstC := (tSrc1D << lAmt) .| (tSrc1C >> rAmt))
      !!ir (dstD := tSrc1D >> rAmt)
    else
      !!ir (dstA := tSrc1B >> rAmt)
      !!ir (dstB := AST.num0 64<rt>)
      !!ir (dstC := tSrc1D >> rAmt)
      !!ir (dstD := AST.num0 64<rt>)
  else raise InvalidOperandSizeException
  !>ir insLen

let vpand ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 64<rt> opPand 16

let vpandn ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 64<rt> opPandn 16

let vpbroadcastb ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src) = getTwoOprs ins
  let oprSize = getOperationSize ins
  match oprSize with
  | 512<rt> -> () (* FIXME: #196 *)
  | _ ->
    let src =
      match src with
      | OprReg _ -> transOprToExpr128 ins insLen ctxt src |> snd
      | OprMem _ -> transOprToExpr ins insLen ctxt src
      | _ -> raise InvalidOperandException
      |> AST.xtlo 8<rt>
    let tSrc = !*ir 8<rt>
    !<ir insLen
    !!ir (tSrc := src)
    let tmps = Array.init 8 (fun _ -> !*ir 8<rt>)
    for i in 0 .. 7 do !!ir (tmps[i] := tSrc) done
    let t = !*ir 64<rt>
    !!ir (t := AST.concatArr tmps)
    match oprSize with
    | 128<rt> ->
      let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
      !!ir (dstA := t)
      !!ir (dstB := t)
      fillZeroHigh128 ctxt dst ir
    | 256<rt> ->
      let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
      !!ir (dstA := t)
      !!ir (dstB := t)
      !!ir (dstC := t)
      !!ir (dstD := t)
    | _ -> raise InvalidOperandSizeException
  !>ir insLen

let vpbroadcastd ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src) = getTwoOprs ins
  let oprSize = getOperationSize ins
  let temp = !*ir 32<rt>
  let src =
    match src with
    | OprReg r ->
      match Register.getKind r with
      | Register.Kind.XMM ->
        transOprToExpr128 ins insLen ctxt src |> snd
      | Register.Kind.GP -> transOprToExpr ins insLen ctxt src
      | _ -> raise InvalidOperandException
    | OprMem _ -> transOprToExpr ins insLen ctxt src
    | _ -> raise InvalidOperandException
    |> AST.xtlo 32<rt>
  !<ir insLen
  !!ir (temp := src)
  match oprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
    !!ir (AST.extract dstA 32<rt> 0 := temp)
    !!ir (AST.extract dstA 32<rt> 32 := temp)
    !!ir (AST.extract dstB 32<rt> 0 := temp)
    !!ir (AST.extract dstB 32<rt> 32 := temp)
    fillZeroFromVLToMaxVL ctxt dst 128 512 ir
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
    !!ir (AST.extract dstA 32<rt> 0 := temp)
    !!ir (AST.extract dstA 32<rt> 32 := temp)
    !!ir (AST.extract dstB 32<rt> 0 := temp)
    !!ir (AST.extract dstB 32<rt> 32 := temp)
    !!ir (AST.extract dstC 32<rt> 0 := temp)
    !!ir (AST.extract dstC 32<rt> 32 := temp)
    !!ir (AST.extract dstD 32<rt> 0 := temp)
    !!ir (AST.extract dstD 32<rt> 32 := temp)
    fillZeroFromVLToMaxVL ctxt dst 256 512 ir
  | 512<rt> ->
    let kl, vl = 16, 512
    let ePrx = getEVEXPrx ins.VEXInfo
    let k = !.ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
    let masking dst =
      match ePrx.Z with
      | Zeroing -> AST.num0 32<rt>
      | Merging -> dst
    let cond idx =
      (* no write mask *)
      let noWritemask = if ePrx.AAA = 0uy then AST.num1 1<rt> else AST.num0 1<rt>
      AST.extract k 1<rt> idx .| noWritemask
    let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
      transOprToExpr512 ins insLen ctxt dst
    let assign dst idx sPos =
      let extDst = AST.extract dst 32<rt> sPos
      extDst := AST.ite (cond idx) temp (masking extDst)
    !!ir (assign dstA 0 0)
    !!ir (assign dstA 1 32)
    !!ir (assign dstB 2 0)
    !!ir (assign dstB 3 32)
    !!ir (assign dstC 4 0)
    !!ir (assign dstC 5 32)
    !!ir (assign dstD 6 0)
    !!ir (assign dstD 7 32)
    !!ir (assign dstE 8 0)
    !!ir (assign dstE 9 32)
    !!ir (assign dstF 10 0)
    !!ir (assign dstF 11 32)
    !!ir (assign dstG 12 0)
    !!ir (assign dstG 13 32)
    !!ir (assign dstH 14 0)
    !!ir (assign dstH 15 32)
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let vpcmpeqb ins insLen ctxt =
  match getOperationSize ins with
  | 512<rt> -> GeneralLifter.nop insLen (* FIXME: #197 *)
  | _ -> buildPackedInstr ins insLen ctxt 8<rt> opPcmpeqb 64

let vpcmpeqd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 32<rt> opPcmpeqd 32

let vpcmpeqq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 64<rt> SSELifter.opPcmpeqq 16

let vpcmpgtb ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 8<rt> opPcmpgtb 64

let vpinsrd ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src1, src2, count) = getFourOprs ins
  let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
  let src1B, src1A = transOprToExpr128 ins insLen ctxt src1
  let src2 = transOprToExpr ins insLen ctxt src2
  let sel = getImmValue count &&& 0b11L (* COUNT[1:0] *)
  let mask = numI64 (0xFFFFFFFFL <<< ((int32 sel * 32) % 64)) 64<rt>
  let amount = sel * 32L
  let t = !*ir 64<rt>
  let expAmt = numI64 (amount % 64L) 64<rt>
  !<ir insLen
  !!ir (t := ((AST.zext 64<rt> src2) << expAmt) .& mask)
  if amount < 64 then !!ir (dstA := (src1A .& (AST.not mask)) .& t)
  else !!ir (dstB := (src1B .& (AST.not mask)) .& t)
  fillZeroFromVLToMaxVL ctxt dst 128 512 ir
  !>ir insLen

let vpminub ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 8<rt> SSELifter.opPminub 64

let vpminud ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 32<rt> SSELifter.opPminud 32

let private opVpmuludq _ =
  let low32 expr = expr .& numI64 0xffffffffL 64<rt>
  Array.map2 (fun e1 e2 -> low32 e1 .* low32 e2)

let vpmuludq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 64<rt> opVpmuludq 16

let vpor ins insLen ctxt =
  match getOperationSize ins with
  | 512<rt> -> GeneralLifter.nop insLen
  | _ -> buildPackedInstr ins insLen ctxt 64<rt> opPor 8

let vpshufb ins insLen ctxt =
  let struct (dst, src1, src2) = getThreeOprs ins
  let oprSize = getOperationSize ins
  let cnt = if oprSize = 128<rt> then 16 else 32
  let ir = IRBuilder (2 * cnt)
  !<ir insLen
  match oprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
    let src1B, src1A = transOprToExpr128 ins insLen ctxt src1
    let src2B, src2A = transOprToExpr128 ins insLen ctxt src2
    let highTmps = Array.init cnt (fun _ -> !*ir 8<rt>)
    let lowTmps = Array.init cnt (fun _ -> !*ir 8<rt>)
    let struct (tSrc1, tSrc2) = tmpVars2 ir 64<rt>
    let mask = numU32 0x0Fu 8<rt>
    for i in 0 .. cnt - 1 do
      !!ir (tSrc1 := if i < 8 then src1A else src1B)
      !!ir (tSrc2 := if i < 8 then src2A else src2B)
      let cond = AST.extract tSrc2 1<rt> (((i * 8) % 64) + 7)
      let idx = (AST.extract tSrc2 8<rt> ((i * 8) % 64)) .& mask
      let numShift = (AST.zext 64<rt> idx) .* (numI32 8 64<rt>)
      let n0 = AST.num0 8<rt>
      let temp = AST.xtlo 8<rt> (tSrc1 >> numShift)
      if i < 8 then !!ir (lowTmps[i] := AST.ite cond n0 temp)
      else !!ir (highTmps[i - 8] := AST.ite cond n0 temp)
    done
    !!ir (dstA := AST.concatArr lowTmps)
    !!ir (dstB := AST.concatArr highTmps)
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
    let src1D, src1C, src1B, src1A = transOprToExpr256 ins insLen ctxt src1
    let src2D, src2C, src2B, src2A = transOprToExpr256 ins insLen ctxt src2
    let tmpsA = Array.init cnt (fun _ -> !*ir 8<rt>)
    let tmpsB = Array.init cnt (fun _ -> !*ir 8<rt>)
    let tmpsC = Array.init cnt (fun _ -> !*ir 8<rt>)
    let tmpsD = Array.init cnt (fun _ -> !*ir 8<rt>)
    let mask = numU32 0x0Fu 8<rt>
    let struct (tSrc1, tSrc2) = tmpVars2 ir 64<rt>
    let src1 = [| src1A; src1B; src1C; src1D  |]
    let src2 = [| src2A; src2B; src2C; src2D  |]
    for i in 0 .. cnt - 1 do
      !!ir (tSrc1 := src1[i / 8])
      !!ir (tSrc2 := src2[i / 8])
      let cond = AST.extract tSrc2 1<rt> (((i * 8) % 64) + 7)
      let idx = (AST.extract tSrc2 8<rt> ((i * 8) % 64)) .& mask
      let numShift = (AST.zext 64<rt> idx) .* (numI32 8 64<rt>)
      let n0 = AST.num0 8<rt>
      let temp = AST.xtlo 8<rt> (tSrc1 >> numShift)
      if i < 8 then !!ir (tmpsA[i] := AST.ite cond n0 temp)
      elif i < 16 then !!ir (tmpsB[i - 8] := AST.ite cond n0 temp)
      elif i < 24 then !!ir (tmpsC[i - 16] := AST.ite cond n0 temp)
      else !!ir (tmpsD[i - 24] := AST.ite cond n0 temp)
    done
    !!ir (dstA := AST.concatArr tmpsA)
    !!ir (dstB := AST.concatArr tmpsB)
    !!ir (dstC := AST.concatArr tmpsC)
    !!ir (dstD := AST.concatArr tmpsD)
    fillZeroHigh128 ctxt dst ir
  (*
  | 512<rt> ->
    let kl, vl = 64, 512
    let ePrx = getEVEXPrx ins.VEXInfo
    let k = !.ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
    let cond idx =
      if ePrx.AAA = 0uy then AST.num0 1<rt> (* no write mask *)
      else AST.extract k 1<rt> idx
    let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
      transOprToExpr512 ins insLen ctxt dst
    let src1H, src1G, src1F, src1E, src1D, src1C, src1B, src1A =
      transOprToExpr512 ins insLen ctxt src1
    let src2H, src2G, src2F, src2E, src2D, src2C, src2B, src2A =
      transOprToExpr512 ins insLen ctxt src2
    let tmpsA = Array.init kl (fun _ -> !*ir 8<rt>)
    let tmpsB = Array.init kl (fun _ -> !*ir 8<rt>)
    let tmpsC = Array.init kl (fun _ -> !*ir 8<rt>)
    let tmpsD = Array.init kl (fun _ -> !*ir 8<rt>)
    let tmpsE = Array.init kl (fun _ -> !*ir 8<rt>)
    let tmpsF = Array.init kl (fun _ -> !*ir 8<rt>)
    let tmpsG = Array.init kl (fun _ -> !*ir 8<rt>)
    let tmpsH = Array.init kl (fun _ -> !*ir 8<rt>)
    let src1 = [| src1A; src1B; src1C; src1D; src1E; src1F; src1G; src1H |]
    let src2 = [| src2A; src2B; src2C; src2D; src2E; src2F; src2G; src2H |]
    let struct (tSrc1, tSrc2) = tmpVars2 ir 64<rt>

    let num0F = numU32 0x0Fu 8<rt>
    let jmask = !*ir 8<rt>
    let cond idx =
      (* no write mask *)
      let noWritemask =
        if ePrx.AAA = 0uy then AST.num1 1<rt> else AST.num0 1<rt>
      AST.extract k 1<rt> idx .| noWritemask

    !!ir (jmask := numI32 (kl - 1) 8<rt> .& (AST.not num0F))
    let jmask = (kl - 1) &&& ~~~0xF

    for i in 0 .. kl - 1 do
      !!ir (tSrc1 := src1[i / 8])
      !!ir (tSrc2 := src2[i / 8])
      let index1 = AST.extract tSrc2 8<rt> ((i * 8) % 64)
      let index2 = (index1 .& num0F) .+ (numI32 (i % 8) 8<rt> .& jmask)

    done
    !!ir (dstA := AST.concatArr tmpsA)
    !!ir (dstB := AST.concatArr tmpsB)
    !!ir (dstC := AST.concatArr tmpsC)
    !!ir (dstD := AST.concatArr tmpsD)
    !!ir (dstE := AST.concatArr tmpsE)
    !!ir (dstF := AST.concatArr tmpsF)
    !!ir (dstG := AST.concatArr tmpsG)
    !!ir (dstH := AST.concatArr tmpsH)
  *)
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let vpshufd ins insLen ctxt =
  let struct (dst, src, ord) = getThreeOprs ins
  let ord = getImmValue ord
  let oprSize = getOperationSize ins
  let cnt = RegType.toBitWidth oprSize / 32
  let ir = IRBuilder (2 * cnt)
  let rShiftTo64 hiExpr lowExpr amount =
    let rightAmt = numI64 (amount % 64L) 64<rt>
    let leftAmt = numI64 (64L - (amount % 64L)) 64<rt>
    if amount < 64L then
      AST.xtlo 32<rt> ((hiExpr << leftAmt) .| (lowExpr >> rightAmt))
    elif amount < 128 then AST.xtlo 32<rt> (hiExpr >> rightAmt)
    else AST.num0 32<rt>
  let amount idx = ((ord >>> (idx * 2)) &&& 0b11L) * 32L
  !<ir insLen
  match oprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
    let srcB, srcA = transOprToExpr128 ins insLen ctxt src
    let struct (tSrcB, tSrcA) = tmpVars2 ir 64<rt>
    !!ir (tSrcA := srcA)
    !!ir (tSrcB := srcB)
    let src amtIdx = rShiftTo64 tSrcB tSrcA (amount amtIdx)
    !!ir (dstA := AST.concat (src 1) (src 0))
    !!ir (dstB := AST.concat (src 3) (src 2))
    fillZeroHigh128 ctxt dst ir
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
    let srcD, srcC, srcB, srcA = transOprToExpr256 ins insLen ctxt src
    let struct (tSrcD, tSrcC, tSrcB, tSrcA) = tmpVars4 ir 64<rt>
    !!ir (tSrcA := srcA)
    !!ir (tSrcB := srcB)
    !!ir (tSrcC := srcC)
    !!ir (tSrcD := srcD)
    let lowSrc amtIdx = rShiftTo64 tSrcB tSrcA (amount amtIdx)
    let hiSrc amtIdx = rShiftTo64 tSrcD tSrcC (amount amtIdx)
    !!ir (dstA := AST.concat (lowSrc 1) (lowSrc 0))
    !!ir (dstB := AST.concat (lowSrc 3) (lowSrc 2))
    !!ir (dstC := AST.concat (hiSrc 1) (hiSrc 0))
    !!ir (dstD := AST.concat (hiSrc 3) (hiSrc 2))
    fillZeroHigh256 ctxt dst ir
  | 512<rt> -> () (* FIXME: #196 *)
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let private opShiftVpackedDataLogical oprSize packSz shift src1 (src2: Expr []) =
  let count = src2[0] |> AST.zext oprSize
  let cond = AST.gt count (numI32 ((int packSz) - 1) oprSize)
  let shifted expr = AST.extract (shift (AST.zext oprSize expr) count) packSz 0
  Array.map (fun e -> AST.ite cond (AST.num0 packSz) (shifted e)) src1

let private opVpslld oprSize = opShiftVpackedDataLogical oprSize 32<rt> (<<)

let vpslld ins insLen ctxt =
  match getOperationSize ins with
  | 512<rt> -> GeneralLifter.nop insLen
  | _ -> buildPackedInstr ins insLen ctxt 32<rt> opVpslld 16

let private opVpsllq oprSize = opShiftVpackedDataLogical oprSize 64<rt> (<<)

let vpsllq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 64<rt> opVpsllq 16

let vpslldq ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src, cnt) = getThreeOprs ins
  let cnt = getImmValue cnt
  let amount = cnt * 8L
  let rightAmt = numI64 (64L - (amount % 64L)) 64<rt>
  let leftAmt = numI64 (amount % 64L) 64<rt>
  let oprSize = getOperationSize ins
  !<ir insLen
  let cnt = if cnt > 15L then 16L else cnt
  match oprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
    let srcB, srcA = transOprToExpr128 ins insLen ctxt src
    let struct (tSrcB, tSrcA) = tmpVars2 ir 64<rt>
    !!ir (tSrcA := srcA)
    !!ir (tSrcB := srcB)
    if amount < 64 then
      !!ir (dstA := tSrcA << leftAmt)
      !!ir (dstB := (tSrcB << leftAmt) .| (tSrcA >> rightAmt))
    elif amount < 128 then
      !!ir (dstA := AST.num0 64<rt>)
      !!ir (dstB := tSrcA << leftAmt)
    else
      !!ir (dstA := AST.num0 64<rt>)
      !!ir (dstB := AST.num0 64<rt>)
    fillZeroHigh128 ctxt dst ir
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
    let srcD, srcC, srcB, srcA = transOprToExpr256 ins insLen ctxt src
    let struct (tSrcD, tSrcC, tSrcB, tSrcA) = tmpVars4 ir 64<rt>
    !!ir (tSrcA := srcA)
    !!ir (tSrcB := srcB)
    !!ir (tSrcC := srcC)
    !!ir (tSrcD := srcD)
    if amount < 64 then
      !!ir (dstA := tSrcA << leftAmt)
      !!ir (dstB := (tSrcB << leftAmt) .| (tSrcA >> rightAmt))
      !!ir (dstC := (tSrcC << leftAmt) .| (tSrcB >> rightAmt))
      !!ir (dstD := (tSrcD << leftAmt) .| (tSrcC >> rightAmt))
    elif amount < 128 then
      !!ir (dstA := AST.num0 64<rt>)
      !!ir (dstB := tSrcA << leftAmt)
      !!ir (dstC := (tSrcB << leftAmt) .| (tSrcA >> rightAmt))
      !!ir (dstD := (tSrcC << leftAmt) .| (tSrcB >> rightAmt))
    elif amount < 192 then
      !!ir (dstA := AST.num0 64<rt>)
      !!ir (dstB := AST.num0 64<rt>)
      !!ir (dstC := tSrcA << leftAmt)
      !!ir (dstD := (tSrcB << leftAmt) .| (tSrcA >> rightAmt))
    elif amount < 256 then
      !!ir (dstA := AST.num0 64<rt>)
      !!ir (dstB := AST.num0 64<rt>)
      !!ir (dstC := AST.num0 64<rt>)
      !!ir (dstD := tSrcA << leftAmt)
    else
      !!ir (dstA := AST.num0 64<rt>)
      !!ir (dstB := AST.num0 64<rt>)
      !!ir (dstC := AST.num0 64<rt>)
      !!ir (dstD := AST.num0 64<rt>)
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let vpsrlq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 64<rt> opVpsllq 16

let vpsrldq ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src, cnt) = getThreeOprs ins
  let cnt = getImmValue cnt
  let cnt = if cnt > 15L then 16L else cnt
  let amount = cnt * 8L
  let rightAmt = numI64 (amount % 64L) 64<rt>
  let leftAmt = numI64 (64L - (amount % 64L)) 64<rt>
  let oprSize = getOperationSize ins
  !<ir insLen
  match oprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
    let srcB, srcA = transOprToExpr128 ins insLen ctxt src
    let struct (tSrcB, tSrcA) = tmpVars2 ir 64<rt>
    !!ir (tSrcA := srcA)
    !!ir (tSrcB := srcB)
    (* FIXME: refactoring *)
    /// Case 1
    let index = (int amount) / 64
    let src = [| tSrcA; tSrcB; AST.num0 64<rt>; AST.num0 64<rt> |]
    !!ir (dstA := (src[index + 1] << leftAmt) .| (src[index] >> rightAmt))
    !!ir (dstB := src[index + 1] >> rightAmt)
    (*
    /// Case 2
    if amount < 64 then
      !!ir (dstA := (srcB << leftAmt) .| (srcA >> rightAmt))
      !!ir (dstB := srcB >> rightAmt)
    elif amount < 128 then
      !!ir (dstA := srcB >> rightAmt)
      !!ir (dstB := AST.num0 64<rt>)
    else
      !!ir (dstA := AST.num0 64<rt>)
      !!ir (dstB := AST.num0 64<rt>)
    *)
    fillZeroHigh128 ctxt dst ir
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
    let srcD, srcC, srcB, srcA = transOprToExpr256 ins insLen ctxt src
    let struct (tSrcD, tSrcC, tSrcB, tSrcA) = tmpVars4 ir 64<rt>
    !!ir (tSrcA := srcA)
    !!ir (tSrcB := srcB)
    !!ir (tSrcC := srcC)
    !!ir (tSrcD := srcD)
    if amount < 64 then
      !!ir (dstA := (tSrcB << leftAmt) .| (tSrcA >> rightAmt))
      !!ir (dstB := (tSrcC << leftAmt) .| (tSrcB >> rightAmt))
      !!ir (dstC := (tSrcD << leftAmt) .| (tSrcC >> rightAmt))
      !!ir (dstD := tSrcD >> rightAmt)
    elif amount < 128 then
      !!ir (dstA := (tSrcC << leftAmt) .| (tSrcB >> rightAmt))
      !!ir (dstB := (tSrcD << leftAmt) .| (tSrcC >> rightAmt))
      !!ir (dstC := tSrcD >> rightAmt)
      !!ir (dstD := AST.num0 64<rt>)
    elif amount < 192 then
      !!ir (dstA := (tSrcD << leftAmt) .| (tSrcC >> rightAmt))
      !!ir (dstB := tSrcD >> rightAmt)
      !!ir (dstC := AST.num0 64<rt>)
      !!ir (dstD := AST.num0 64<rt>)
    else
      !!ir (dstA := tSrcD >> rightAmt)
      !!ir (dstB := AST.num0 64<rt>)
      !!ir (dstC := AST.num0 64<rt>)
      !!ir (dstD := AST.num0 64<rt>)
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let private opVpsrld oprSize = opShiftVpackedDataLogical oprSize 32<rt> (<<)

let vpsrld ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 32<rt> opVpsrld 16

let vpsubb ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 8<rt> opPsub 128

let vptest ins insLen ctxt =
  if getOperationSize ins = 128<rt> then SSELifter.ptest ins insLen ctxt
  else
    let ir = IRBuilder (16)
    let struct (src1, src2) = getTwoOprs ins
    let src1D, src1C, src1B, src1A =
      transOprToExpr256 ins insLen ctxt src1
    let src2D, src2C, src2B, src2A =
      transOprToExpr256 ins insLen ctxt src2
    let struct (t1, t2, t3, t4) = tmpVars4 ir 64<rt>
    let struct (t5, t6, t7, t8) = tmpVars4 ir 64<rt>
    !<ir insLen
    !!ir (t1 := src2A .& src1A)
    !!ir (t2 := src2B .& src1B)
    !!ir (t3 := src2C .& src1C)
    !!ir (t4 := src2D .& src1D)
    !!ir (!.ctxt R.ZF := (t1 .| t2 .| t3 .| t4) == (AST.num0 64<rt>))
    !!ir (t5 := src2A .& AST.not src1A)
    !!ir (t6 := src2B .& AST.not src1B)
    !!ir (t7 := src2C .& AST.not src1C)
    !!ir (t8 := src2D .& AST.not src1D)
    !!ir (!.ctxt R.CF := (t5 .| t6 .| t7 .| t8) == (AST.num0 64<rt>))
    !!ir (!.ctxt R.AF := AST.b0)
    !!ir (!.ctxt R.OF := AST.b0)
    !!ir (!.ctxt R.PF := AST.b0)
    !!ir (!.ctxt R.SF := AST.b0)
    !>ir insLen

let vpunpckhdq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 32<rt> opPunpckHigh 16

let vpunpckhqdq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 64<rt> opPunpckHigh 16

let vpunpckldq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 32<rt> opPunpckLow 16

let vpunpcklqdq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 64<rt> opPunpckLow 16

let vpxor ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src1, src2) = getThreeOprs ins
  let oprSize = getOperationSize ins
  !<ir insLen
  match oprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
    let src1B, src1A = transOprToExpr128 ins insLen ctxt src1
    let src2B, src2A = transOprToExpr128 ins insLen ctxt src2
    !!ir (dstB := src1B <+> src2B)
    !!ir (dstA := src1A <+> src2A)
    fillZeroHigh128 ctxt dst ir
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
    let src1D, src1C, src1B, src1A =
      transOprToExpr256 ins insLen ctxt src1
    let src2D, src2C, src2B, src2A =
      transOprToExpr256 ins insLen ctxt src2
    !!ir (dstD := src1D <+> src2D)
    !!ir (dstC := src1C <+> src2C)
    !!ir (dstB := src1B <+> src2B)
    !!ir (dstA := src1A <+> src2A)
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let vpxord ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src1, src2) = getThreeOprs ins
  let oprSize = getOperationSize ins
  !<ir insLen
  let ePrx = getEVEXPrx ins.VEXInfo
  let k = !.ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
  let masking dst =
    match ePrx.Z with
    | Zeroing -> AST.num0 32<rt>
    | Merging -> dst
  let cond idx =
    (* no write mask *)
    let noWritemask = if ePrx.AAA = 0uy then AST.num1 1<rt> else AST.num0 1<rt>
    AST.extract k 1<rt> idx .| noWritemask
  let tmpDest = Array.init 2 (fun _ -> !*ir 32<rt>)
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
      !!ir (tmpDest[i] := AST.ite (cond (idx + i)) tSrc (masking dst))
    AST.concatArr tmpDest
  match oprSize with
  | 128<rt> ->
    let kl, vl = 4, 128
    let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
    let src1B, src1A = transOprToExpr128 ins insLen ctxt src1
    let src2B, src2A = transOprToExpr128 ins insLen ctxt src2
    !!ir (dstA := evAssign dstA src1A src2A src2A dstA 0)
    !!ir (dstB := evAssign dstB src1B src2B src2A dstA 2)
    fillZeroHigh128 ctxt dst ir
  | 256<rt> ->
    let kl, vl = 8, 256
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
    let src1D, src1C, src1B, src1A =
      transOprToExpr256 ins insLen ctxt src1
    let src2D, src2C, src2B, src2A =
      transOprToExpr256 ins insLen ctxt src2
    !!ir (dstA := evAssign dstA src1A src2A src2A dstA 0)
    !!ir (dstB := evAssign dstB src1B src2B src2A dstA 2)
    !!ir (dstC := evAssign dstC src1C src2B src2A dstA 4)
    !!ir (dstD := evAssign dstD src1D src2B src2A dstA 6)
    fillZeroHigh256 ctxt dst ir
  | 512<rt> ->
    let kl, vl = 16, 512
    let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
      transOprToExpr512 ins insLen ctxt dst
    let src1H, src1G, src1F, src1E, src1D, src1C, src1B, src1A =
      transOprToExpr512 ins insLen ctxt src1
    let src2H, src2G, src2F, src2E, src2D, src2C, src2B, src2A =
      transOprToExpr512 ins insLen ctxt src2
    !!ir (dstA := evAssign dstA src1A src2A src2A dstA 0)
    !!ir (dstB := evAssign dstB src1B src2B src2A dstA 2)
    !!ir (dstC := evAssign dstC src1C src2C src2A dstA 4)
    !!ir (dstD := evAssign dstD src1D src2D src2A dstA 6)
    !!ir (dstE := evAssign dstE src1E src2E src2A dstA 8)
    !!ir (dstF := evAssign dstF src1F src2F src2A dstA 10)
    !!ir (dstG := evAssign dstG src1G src2G src2A dstA 12)
    !!ir (dstH := evAssign dstH src1H src2H src2A dstA 14)
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let vzeroupper ins insLen ctxt =
  let ir = IRBuilder (32)
  !<ir insLen
  let n0 = AST.num0 64<rt>
  !!ir (getPseudoRegVar ctxt R.YMM0 3 := n0)
  !!ir (getPseudoRegVar ctxt R.YMM0 4 := n0)
  !!ir (getPseudoRegVar ctxt R.YMM1 3 := n0)
  !!ir (getPseudoRegVar ctxt R.YMM1 4 := n0)
  !!ir (getPseudoRegVar ctxt R.YMM2 3 := n0)
  !!ir (getPseudoRegVar ctxt R.YMM2 4 := n0)
  !!ir (getPseudoRegVar ctxt R.YMM3 3 := n0)
  !!ir (getPseudoRegVar ctxt R.YMM3 4 := n0)
  !!ir (getPseudoRegVar ctxt R.YMM4 3 := n0)
  !!ir (getPseudoRegVar ctxt R.YMM4 4 := n0)
  !!ir (getPseudoRegVar ctxt R.YMM5 3 := n0)
  !!ir (getPseudoRegVar ctxt R.YMM5 4 := n0)
  !!ir (getPseudoRegVar ctxt R.YMM6 3 := n0)
  !!ir (getPseudoRegVar ctxt R.YMM6 4 := n0)
  !!ir (getPseudoRegVar ctxt R.YMM7 3 := n0)
  !!ir (getPseudoRegVar ctxt R.YMM7 4 := n0)
  if is64bit ctxt then
    !!ir (getPseudoRegVar ctxt R.YMM8 3 := n0)
    !!ir (getPseudoRegVar ctxt R.YMM8 4 := n0)
    !!ir (getPseudoRegVar ctxt R.YMM9 3 := n0)
    !!ir (getPseudoRegVar ctxt R.YMM9 4 := n0)
    !!ir (getPseudoRegVar ctxt R.YMM10 3 := n0)
    !!ir (getPseudoRegVar ctxt R.YMM10 4 := n0)
    !!ir (getPseudoRegVar ctxt R.YMM11 3 := n0)
    !!ir (getPseudoRegVar ctxt R.YMM11 4 := n0)
    !!ir (getPseudoRegVar ctxt R.YMM12 3 := n0)
    !!ir (getPseudoRegVar ctxt R.YMM12 4 := n0)
    !!ir (getPseudoRegVar ctxt R.YMM13 3 := n0)
    !!ir (getPseudoRegVar ctxt R.YMM13 4 := n0)
    !!ir (getPseudoRegVar ctxt R.YMM14 3 := n0)
    !!ir (getPseudoRegVar ctxt R.YMM14 4 := n0)
    !!ir (getPseudoRegVar ctxt R.YMM15 3 := n0)
    !!ir (getPseudoRegVar ctxt R.YMM15 4 := n0)
  !>ir insLen

let vfmadd132sd ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src2, src3) = getThreeOprs ins
  let _dstB , dstA = transOprToExpr128 ins insLen ctxt dst
  let src2 = transOprToExpr64 ins insLen ctxt src2
  let src3 = transOprToExpr64 ins insLen ctxt src3
  let tmp = !*ir 64<rt>
  !<ir insLen
  !!ir (tmp := AST.fmul dstA src3)
  !!ir (dstA := AST.fadd tmp src2)
  fillZeroHigh128 ctxt dst ir
  !>ir insLen

let vfmadd213sd ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src2, src3) = getThreeOprs ins
  let _dstB , dstA = transOprToExpr128 ins insLen ctxt dst
  let src2 = transOprToExpr64 ins insLen ctxt src2
  let src3 = transOprToExpr64 ins insLen ctxt src3
  let tmp = !*ir 64<rt>
  !<ir insLen
  !!ir (tmp := AST.fmul dstA src2)
  !!ir (dstA := AST.fadd tmp src3)
  fillZeroHigh128 ctxt dst ir
  !>ir insLen

let vfmadd231sd ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src2, src3) = getThreeOprs ins
  let _dstB , dstA = transOprToExpr128 ins insLen ctxt dst
  let src2 = transOprToExpr64 ins insLen ctxt src2
  let src3 = transOprToExpr64 ins insLen ctxt src3
  let tmp = !*ir 64<rt>
  !<ir insLen
  !!ir (tmp := AST.fmul src2 src3)
  !!ir (dstA := AST.fadd dstA tmp)
  fillZeroHigh128 ctxt dst ir
  !>ir insLen
