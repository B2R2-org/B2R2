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
  !!ir (AST.xtlo 32<rt> dstA := AST.cast CastKind.FloatExt 32<rt> src2)
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
  !!ir (dstA := AST.cast CastKind.FloatExt 64<rt> src2)
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
      let tmps = Array.init 4 (fun _ -> AST.tmpvar 16<rt>)
      let assign dst src idx =
        for i in 0 .. 3 do
          let pos = i * 16
          let dst = AST.extract dst 16<rt> pos
          !!ir
            (tmps.[i] := AST.ite (cond (idx + i)) (AST.extract src 16<rt> pos) dst)
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
      let tmps = Array.init 4 (fun _ -> AST.tmpvar 16<rt>)
      let assign dst src idx =
        for i in 0 .. 3 do
          let pos = i * 16
          let dst = AST.extract dst 16<rt> pos
          !!ir
            (tmps.[i] := AST.ite (cond (idx + i)) (AST.extract src 16<rt> pos) dst)
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
      let tmps = Array.init 4 (fun _ -> AST.tmpvar 16<rt>)
      let assign dst src idx =
        for i in 0 .. 3 do
          let pos = i * 16
          let dst = AST.extract dst 16<rt> pos
          !!ir
            (tmps.[i] := AST.ite (cond (idx + i)) (AST.extract src 16<rt> pos) dst)
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

let vmovhpd ins insLen ctxt =
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

let vmovlpd ins insLen ctxt =
  let ir = IRBuilder (8)
  !<ir insLen
  match ins.Operands with
  | TwoOperands (dst, src) ->
    let dst = transOprToExpr64 ins insLen ctxt dst
    let _src2, src1 = transOprToExpr128 ins insLen ctxt src
    !!ir (dst := src1)
  | ThreeOperands (dst, src1, src2)->
    let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
    let src1B, _src1A = transOprToExpr128 ins insLen ctxt src1
    let _src2B, src2A = transOprToExpr128 ins insLen ctxt src2
    !!ir (dstA := src2A)
    !!ir (dstB := src1B)
    fillZeroHigh128 ctxt dst ir
  | _ -> raise InvalidOperandException
  !>ir insLen

let vmovmskpd ins insLen ctxt =
  let ir = IRBuilder (4)
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr ins insLen ctxt dst
  let dstSz = AST.typeOf dst
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
  let dstSz = AST.typeOf dst
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

let vmovsd ins insLen ctxt =
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

let vmovss ins insLen ctxt =
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
  let imm = transOprToExpr ins insLen ctxt imm
  let struct (tmpDest, tmp) = tmpVars2 oprSize
  !<ir insLen
  match oprSize with
  | 256<rt> ->
    let kl, vl = 8, 256
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
    let src1D, src1C, src1B, src1A =
      transOprToExpr256 ins insLen ctxt src1
    let src2D, src2C, src2B, src2A =
      transOprToExpr256 ins insLen ctxt src2
    let conSrc1 = AST.concat (AST.concat src1D src1C) (AST.concat src1B src1A)
    let conSrc2 = AST.concat (AST.concat src2D src2C) (AST.concat src2B src2A)
    let srcLow src = AST.extract src 128<rt> 0
    let srcHigh src = AST.extract src 128<rt> 128
    let select2 src pos = AST.ite (AST.extract imm 1<rt> pos) (srcHigh src) (srcLow src)
    !!ir (AST.extract tmpDest 128<rt> 0 := select2 conSrc1 0)
    !!ir (AST.extract tmpDest 128<rt> 128 := select2 conSrc2 1)
    let assign dst idx dstPos tmpPos =
      let dst = AST.extract dst 32<rt> dstPos
      dst := AST.ite (cond idx) (AST.extract tmpDest 32<rt> tmpPos) (masking dst)
    !!ir (assign dstA 0 0 0)
    !!ir (assign dstA 1 32 32)
    !!ir (assign dstB 2 0 64)
    !!ir (assign dstB 3 32 96)
    !!ir (assign dstC 4 0 128)
    !!ir (assign dstC 5 32 160)
    !!ir (assign dstD 6 0 192)
    !!ir (assign dstD 7 32 224)
  | 512<rt> ->
    let kl, vl = 16, 512
    let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
      transOprToExpr512 ins insLen ctxt dst
    let src1H, src1G, src1F, src1E, src1D, src1C, src1B, src1A =
      transOprToExpr512 ins insLen ctxt src1
    let src2H, src2G, src2F, src2E, src2D, src2C, src2B, src2A =
      transOprToExpr512 ins insLen ctxt src2
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
      !!ir (tmpSrc2.[i] := tSrc2)
    let tmpSrc2 = AST.concatArr tmpSrc2
    !!ir (AST.extract tmpDest 128<rt> 0 := select4 conSrc1 0)
    !!ir (AST.extract tmpDest 128<rt> 128 := select4 conSrc2 2)
    !!ir (AST.extract tmpDest 128<rt> 256 := select4 tmpSrc2 4)
    !!ir (AST.extract tmpDest 128<rt> 384 := select4 tmpSrc2 6)
    let assign dst idx dstPos tmpPos =
      let dst = AST.extract dst 32<rt> dstPos
      dst := AST.ite (cond idx) (AST.extract tmpDest 32<rt> tmpPos) (masking dst)
    !!ir (assign dstA 0 0 0)
    !!ir (assign dstA 1 32 32)
    !!ir (assign dstB 2 0 64)
    !!ir (assign dstB 3 32 96)
    !!ir (assign dstC 4 0 128)
    !!ir (assign dstC 5 32 160)
    !!ir (assign dstD 6 0 192)
    !!ir (assign dstD 7 32 224)
    !!ir (assign dstE 8 0 256)
    !!ir (assign dstE 9 32 288)
    !!ir (assign dstF 10 0 320)
    !!ir (assign dstF 11 32 352)
    !!ir (assign dstG 12 0 384)
    !!ir (assign dstG 13 32 416)
    !!ir (assign dstH 14 0 448)
    !!ir (assign dstH 15 32 480)
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
    !!ir (dstC := AST.ite cond3 sr1C sr1D)
    !!ir (dstB := AST.ite cond4 sr2C sr2D)
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
        !!ir (tmpDest.[i] := AST.ite (cond (idx + i)) tSrc (masking dst))
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
  let tmp = AST.tmpvar 32<rt>
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
  let tDest = AST.tmpvar 256<rt>
  let vl = 512
  let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
  let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
    transOprToExpr512 ins insLen ctxt src
  let imm = transOprToExpr ins insLen ctxt imm
  !<ir insLen
  let srcLow = AST.concat (AST.concat srcD srcC) (AST.concat srcB srcA)
  let srcHigh = AST.concat (AST.concat srcH srcG) (AST.concat srcF srcE)
  !!ir (tDest := AST.ite (AST.xtlo 1<rt> imm) srcHigh srcLow)
  match dst with
  | OprReg _ ->
    let tmps = Array.init 2 (fun _ -> AST.tmpvar 32<rt>)
    let assign dst src idx =
      for i in 0 .. 1 do
        let dstPos = i * 32
        let srcPos = 32 * (idx + i)
        let dst = AST.extract dst 32<rt> dstPos
        let src = AST.extract src 32<rt> srcPos
        !!ir
          (tmps.[i] := AST.ite (cond (idx + i)) src (masking dst))
      AST.concatArr tmps
    !!ir (dstA := assign dstA tDest 0)
    !!ir (dstB := assign dstB tDest 2)
    !!ir (dstC := assign dstC tDest 4)
    !!ir (dstD := assign dstD tDest 6)
  | OprMem _ ->
    let tmps = Array.init 2 (fun _ -> AST.tmpvar 32<rt>)
    let assign dst src idx =
      for i in 0 .. 1 do
        let dstPos = i * 32
        let srcPos = 32 * (idx + i)
        let dst = AST.extract dst 32<rt> dstPos
        !!ir
          (tmps.[i] := AST.ite (cond (idx + i)) (AST.extract src 32<rt> srcPos) dst)
      AST.concatArr tmps
    !!ir (dstA := assign dstA tDest 0)
    !!ir (dstB := assign dstB tDest 2)
    !!ir (dstC := assign dstC tDest 4)
    !!ir (dstD := assign dstD tDest 6)
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
  let tDest = AST.tmpvar 256<rt>
  let vl = 512
  let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
  let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
    transOprToExpr512 ins insLen ctxt src
  let imm = transOprToExpr ins insLen ctxt imm
  !<ir insLen
  let srcLow = AST.concat (AST.concat srcD srcC) (AST.concat srcB srcA)
  let srcHigh = AST.concat (AST.concat srcH srcG) (AST.concat srcF srcE)
  !!ir (tDest := AST.ite (AST.xtlo 1<rt> imm) srcHigh srcLow)
  match dst with
  | OprReg _ ->
    !!ir (dstA := AST.ite (cond 0) (AST.extract tDest 64<rt> 0) (masking dstA))
    !!ir (dstB := AST.ite (cond 1) (AST.extract tDest 64<rt> 64) (masking dstB))
    !!ir (dstC := AST.ite (cond 2) (AST.extract tDest 64<rt> 128) (masking dstC))
    !!ir (dstD := AST.ite (cond 3) (AST.extract tDest 64<rt> 192) (masking dstD))
  | OprMem _ ->
    !!ir (dstA := AST.ite (cond 0) (AST.extract tDest 64<rt> 0) dstA)
    !!ir (dstB := AST.ite (cond 1) (AST.extract tDest 64<rt> 64) dstB)
    !!ir (dstC := AST.ite (cond 2) (AST.extract tDest 64<rt> 128) dstC)
    !!ir (dstD := AST.ite (cond 3) (AST.extract tDest 64<rt> 192) dstD)
  | _ -> raise InvalidOperandException
  !>ir insLen

let vinserti128 ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src1, src2, imm) = getFourOprs ins
  let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
  let src1D, src1C, src1B, src1A = transOprToExpr256 ins insLen ctxt src1
  let src2B, src2A = transOprToExpr128 ins insLen ctxt src2
  let imm = transOprToExpr ins insLen ctxt imm
  let cond = AST.tmpvar 1<rt>
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
        !!ir (tmpDest.[i] := AST.ite (cond (idx + i)) tSrc (masking dst))
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
  let imm = transOprToExpr ins insLen ctxt imm
  let n8 = numU32 8u 256<rt>
  let imm = AST.zext 256<rt> imm
  !<ir insLen
  if oprSize = 128<rt> then
    let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
    let src1B, src1A = transOprToExpr128 ins insLen ctxt src1
    let src2B, src2A = transOprToExpr128 ins insLen ctxt src2
    let t = AST.tmpvar 256<rt>
    let struct (tSrc1, tSrc2) = tmpVars2 oprSize
    !!ir (tSrc1 := AST.concat src1B src1A)
    !!ir (tSrc2 := AST.concat src2B src2A)
    !!ir (t := (AST.concat tSrc1 tSrc2) >> (imm .* n8))
    !!ir (dstA := AST.xtlo 64<rt> t)
    !!ir (dstB := AST.xthi 64<rt> (AST.xtlo 128<rt> t))
    fillZeroHigh128 ctxt dst ir
  elif oprSize = 256<rt> then
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
    let src1D, src1C, src1B, src1A = transOprToExpr256 ins insLen ctxt src1
    let src2D, src2C, src2B, src2A = transOprToExpr256 ins insLen ctxt src2
    let struct (t1, t2) = tmpVars2 256<rt>
    let struct (tSrc1High, tSrc1Low, tSrc2High, tSrc2Low) = tmpVars4 128<rt>
    !!ir (tSrc1Low := AST.concat src1B src1A)
    !!ir (tSrc1High := AST.concat src1D src1C)
    !!ir (tSrc2Low := AST.concat src2B src2A)
    !!ir (tSrc2High := AST.concat src2D src2C)
    !!ir (t1 := (AST.concat tSrc1Low tSrc2Low) >> (imm .* n8))
    !!ir (dstA := AST.xtlo 64<rt> t1)
    !!ir (dstB := AST.xthi 64<rt> (AST.xtlo 128<rt> t1))
    !!ir (t2 := (AST.concat tSrc1High tSrc2High) >> (imm .* n8))
    !!ir (dstC := AST.xtlo 64<rt> t2)
    !!ir (dstD := AST.xthi 64<rt> (AST.xtlo 128<rt> t2))
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
    let tSrc = AST.tmpvar 8<rt>
    !<ir insLen
    !!ir (tSrc := src)
    let tmps = Array.init 8 (fun _ -> AST.tmpvar 8<rt>)
    for i in 0 .. 7 do !!ir (tmps.[i] := tSrc) done
    let t = AST.tmpvar 64<rt>
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
  let temp = AST.tmpvar 32<rt>
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
  let struct (dst, src1, src2, imm) = getFourOprs ins
  let oprSize = getOperationSize ins
  let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
  let src1B, src1A = transOprToExpr128 ins insLen ctxt src1
  let src2 = transOprToExpr ins insLen ctxt src2
  let imm = transOprToExpr ins insLen ctxt imm
  let struct (sel, mask, temp, tDst) = tmpVars4 128<rt>
  !<ir insLen (* write_d_element *)
  !!ir (sel := AST.zext 128<rt> (AST.xtlo 2<rt> imm))
  !!ir (mask := numU64 0xFFFFFFFFUL 128<rt> << (sel .* numI32 32 128<rt>))
  !!ir
    (temp := ((AST.zext 128<rt> src2) << (sel .* numI32 32 128<rt>)) .& mask)
  !!ir (tDst := (((AST.concat src1B src1A) .& AST.not mask) .| temp))
  !!ir (dstA := AST.extract tDst 64<rt> 0)
  !!ir (dstB := AST.extract tDst 64<rt> 64)
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
  let struct (tDst, tSrc1, tSrc2) = tmpVars3 oprSize
  !<ir insLen
  match oprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
    let src1B, src1A = transOprToExpr128 ins insLen ctxt src1
    let src2B, src2A = transOprToExpr128 ins insLen ctxt src2
    !!ir (tSrc1 := AST.concat src1B src1A)
    !!ir (tSrc2 := AST.concat src2B src2A)
    let tmps = Array.init cnt (fun _ -> AST.tmpvar 8<rt>)
    let mask = numU32 0x0Fu 8<rt>
    for i in 0 .. cnt - 1 do
      let cond = AST.extract tSrc2 1<rt> (i * 8 + 7)
      let idx = (AST.extract tSrc2 8<rt> (i * 8)) .& mask
      let s = AST.zext oprSize idx .* numI32 8 oprSize
      !!ir
        (tmps.[i] := AST.ite cond (AST.num0 8<rt>) (AST.xtlo 8<rt> (tSrc1 >> s)))
    done
    !!ir (tDst := AST.concatArr tmps)
    !!ir (dstA := AST.xtlo 64<rt> tDst)
    !!ir (dstB := AST.xthi 64<rt> tDst)
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
    let src1D, src1C, src1B, src1A =
      transOprToExpr256 ins insLen ctxt src1
    let src2D, src2C, src2B, src2A =
      transOprToExpr256 ins insLen ctxt src2
    !!ir (tSrc1 := AST.concat (AST.concat src1D src1C) (AST.concat src1B src1A))
    !!ir (tSrc2 := AST.concat (AST.concat src2D src2C) (AST.concat src2B src2A))
    let tmps = Array.init cnt (fun _ -> AST.tmpvar 8<rt>)
    let mask = numU32 0x0Fu 8<rt>
    for i in 0 .. cnt - 1 do
      let cond = AST.extract tSrc2 1<rt> (i * 8 + 7)
      let idx = (AST.extract tSrc2 8<rt> (i * 8)) .& mask
      let s = AST.zext oprSize idx .* numI32 8 oprSize
      !!ir
        (tmps.[i] := AST.ite cond (AST.num0 8<rt>) (AST.xtlo 8<rt> (tSrc1 >> s)))
    done
    !!ir (tDst := AST.concatArr tmps)
    !!ir (dstA := AST.xtlo 64<rt> tDst)
    !!ir (dstB := AST.extract tDst 64<rt> 64)
    !!ir
      (dstC := AST.extract tDst 64<rt> (RegType.toBitWidth (AST.typeOf tDst) - 64))
    !!ir (dstD := AST.xthi 64<rt> tDst)
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
    !!ir
      (tSrc1 := AST.concat (AST.concat (AST.concat src1H src1G) (AST.concat src1F src1E))
                       (AST.concat (AST.concat src1D src1C) (AST.concat src1B src1A)))
    !!ir
      (tSrc2 := AST.concat (AST.concat (AST.concat src2H src2G) (AST.concat src2F src2E))
                       (AST.concat (AST.concat src2D src2C) (AST.concat src2B src2A)))
    let num0F = numU32 0x0Fu 8<rt>
    let jmask = AST.tmpvar 8<rt>
    let tmps = Array.init kl (fun _ -> AST.tmpvar 8<rt>)
    !!ir (jmask := numI32 (kl - 1) 8<rt> .& (AST.not num0F))
    for i in 0 .. kl - 1 do
      let cond idx =
        (* no write mask *)
        let noWritemask = if ePrx.AAA = 0uy then AST.num1 1<rt> else AST.num0 1<rt>
        AST.extract k 1<rt> idx .| noWritemask
      let index1 = AST.extract tSrc2 8<rt> (i * 8)
      let index2 = (index1 .& num0F) .+ (numI32 i 8<rt> .& jmask)
      let src1 =
        AST.xtlo 8<rt> (tSrc1 >> (AST.zext oprSize (index2 .* numI32 8 8<rt>)))
      !!ir (tmps.[i] := AST.ite (cond i) (AST.ite (AST.xthi 1<rt> index1)
                                               (AST.num0 8<rt>) src1) (AST.num0 8<rt>))
    done
    !!ir (tDst := AST.concatArr tmps)
    !!ir (dstA := AST.extract tDst 64<rt> 0)
    !!ir (dstB := AST.extract tDst 64<rt> 64)
    !!ir (dstC := AST.extract tDst 64<rt> 128)
    !!ir (dstD := AST.extract tDst 64<rt> 192)
    !!ir (dstE := AST.extract tDst 64<rt> 256)
    !!ir (dstF := AST.extract tDst 64<rt> 320)
    !!ir (dstG := AST.extract tDst 64<rt> 384)
    !!ir (dstH := AST.extract tDst 64<rt> 448)
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let vpshufd ins insLen ctxt =
  let struct (dst, src, ord) = getThreeOprs ins
  let ord = transOprToExpr ins insLen ctxt ord
  let oprSize = getOperationSize ins
  let cnt = RegType.toBitWidth oprSize / 32
  let ir = IRBuilder (2 * cnt)
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
      !!ir (tmps.[i - 1] := AST.xtlo 32<rt> (src >> (order' .* n32)))
    done
  !<ir insLen
  match oprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
    let srcB, srcA = transOprToExpr128 ins insLen ctxt src
    !!ir (tSrc := AST.concat srcB srcA)
    shuffleDword tSrc
    !!ir (tDst := AST.concatArr tmps)
    !!ir (dstA := AST.extract tDst 64<rt> 0)
    !!ir (dstB := AST.extract tDst 64<rt> 64)
    fillZeroHigh128 ctxt dst ir
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
    let srcD, srcC, srcB, srcA = transOprToExpr256 ins insLen ctxt src
    !!ir (tSrc := AST.concat (AST.concat srcD srcC) (AST.concat srcB srcA))
    shuffleDword tSrc
    !!ir (tDst := AST.concatArr tmps)
    !!ir (dstA := AST.extract tDst 64<rt> 0)
    !!ir (dstB := AST.extract tDst 64<rt> 64)
    !!ir (dstC := AST.extract tDst 64<rt> 128)
    !!ir (dstD := AST.extract tDst 64<rt> 192)
    fillZeroHigh256 ctxt dst ir
  | 512<rt> -> () (* FIXME: #196 *)
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let private opShiftVpackedDataLogical oprSize packSz shift src1 (src2: Expr []) =
  let count = src2.[0] |> AST.zext oprSize
  let cond = AST.gt count (numI32 ((int packSz) - 1) oprSize)
  let shifted expr = AST.extract (shift (AST.zext oprSize expr) count) packSz 0
  Array.map (fun e -> AST.ite cond (AST.num0 packSz) (shifted e)) src1

let private opVpslld oprSize = opShiftVpackedDataLogical oprSize 32<rt> (<<)

let vpslld ins insLen ctxt =
  match getOperationSize ins with
  | 512<rt> -> GeneralLifter.nop insLen
  | _ -> buildPackedInstr ins insLen ctxt 32<rt> opVpslld 16

let private shiftVDQ ins insLen ctxt shift =
  let ir = IRBuilder (8)
  let struct (dst, src, cnt) = getThreeOprs ins
  let cnt = transOprToExpr ins insLen ctxt cnt |> castNum 8<rt>
  let oprSize = getOperationSize ins
  let t = AST.tmpvar 8<rt>
  !<ir insLen
  !!ir (t := AST.ite (AST.lt (numU32 15u 8<rt>) cnt) (numU32 16u 8<rt>) cnt)
  match oprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
    let srcB, srcA = transOprToExpr128 ins insLen ctxt src
    let struct (tDst, tSrc) = tmpVars2 128<rt>
    !!ir (tDst := AST.concat dstB dstA)
    !!ir (tSrc := AST.concat srcB srcA)
    !!ir (tDst := (shift tSrc (AST.zext oprSize (t .* numU32 8u 8<rt>))))
    !!ir (dstA := AST.xtlo 64<rt> tDst)
    !!ir (dstB := AST.xthi 64<rt> tDst)
    fillZeroHigh128 ctxt dst ir
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
    let srcD, srcC, srcB, srcA = transOprToExpr256 ins insLen ctxt src
    let struct (tDst, tSrc) = tmpVars2 256<rt>
    !!ir (tDst := AST.concat (AST.concat dstD dstC) (AST.concat dstB dstA))
    !!ir (tSrc := AST.concat (AST.concat srcD srcC) (AST.concat srcB srcA))
    !!ir (tDst := (shift tSrc (AST.zext oprSize (t .* numU32 8u 8<rt>))))
    !!ir (dstA := AST.xtlo 64<rt> tDst)
    !!ir (dstB := AST.xtlo 64<rt> tDst)
    !!ir (dstC := AST.extract tDst 64<rt> 128)
    !!ir (dstD := AST.xthi 64<rt> tDst)
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let private opVpsllq oprSize = opShiftVpackedDataLogical oprSize 64<rt> (<<)

let vpsllq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 64<rt> opVpsllq 16

let vpslldq ins insLen ctxt = shiftVDQ ins insLen ctxt (<<)

let vpsrlq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 64<rt> opVpsllq 16

let vpsrldq ins insLen ctxt = shiftVDQ ins insLen ctxt (>>)

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
    let struct (t1, t2, t3, t4) = tmpVars4 64<rt>
    let struct (t5, t6, t7, t8) = tmpVars4 64<rt>
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
      !!ir (tmpDest.[i] := AST.ite (cond (idx + i)) tSrc (masking dst))
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
  let tmp = AST.tmpvar 64<rt>
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
  let tmp = AST.tmpvar 64<rt>
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
  let tmp = AST.tmpvar 64<rt>
  !<ir insLen
  !!ir (tmp := AST.fmul src2 src3)
  !!ir (dstA := AST.fadd dstA tmp)
  fillZeroHigh128 ctxt dst ir
  !>ir insLen
