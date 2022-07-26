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
open B2R2.FrontEnd.BinLifter.LiftingUtils
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

let private do32PackedOp op dst64 src1 src2 ir =
  let dstA, dstB = AST.xtlo 32<rt> dst64, AST.xthi 32<rt> dst64
  let src1A, src1B = AST.xtlo 32<rt> src1, AST.xthi 32<rt> src1
  let src2A, src2B = AST.xtlo 32<rt> src2, AST.xthi 32<rt> src2
  !!ir (dstA := op src1A src2A)
  !!ir (dstB := op src1B src2B)

let private vexedPackedFPBinOp32 ins insLen ctxt op =
  let ir = IRBuilder (16)
  let struct (dst, src1, src2) = getThreeOprs ins
  let oprSz = getOperationSize ins
  !<ir insLen
  match oprSz with
  | 128<rt> ->
    let dst2, dst1 = transOprToExpr128 ins insLen ctxt dst
    let src1B, src1A = transOprToExpr128 ins insLen ctxt src1
    let src2B, src2A = transOprToExpr128 ins insLen ctxt src2
    do32PackedOp op dst1 src1A src2A ir
    do32PackedOp op dst2 src1B src2B ir
    fillZeroHigh128 ctxt dst ir
  | 256<rt> ->
    let dst4, dst3, dst2, dst1 = transOprToExpr256 ins insLen ctxt dst
    let sr1D, sr1C, sr1B, sr1A = transOprToExpr256 ins insLen ctxt src1
    let sr2D, sr2C, sr2B, sr2A = transOprToExpr256 ins insLen ctxt src2
    do32PackedOp op dst1 sr1A sr2A ir
    do32PackedOp op dst2 sr1B sr2B ir
    do32PackedOp op dst3 sr1C sr2C ir
    do32PackedOp op dst4 sr1D sr2D ir
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
    let src1D, src1C, src1B, src1A = transOprToExpr256 ins insLen ctxt src1
    let src2D, src2C, src2B, src2A = transOprToExpr256 ins insLen ctxt src2
    !!ir (dst1 := op src1A src2A)
    !!ir (dst2 := op src1B src2B)
    !!ir (dst3 := op src1C src2C)
    !!ir (dst4 := op src1D src2D)
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

let private do32PackedSqrt dst64 src ir =
  let dstA, dstB = AST.xtlo 32<rt> dst64, AST.xthi 32<rt> dst64
  let srcA, srcB = AST.xtlo 32<rt> src, AST.xthi 32<rt> src
  !!ir (dstA := AST.fsqrt srcA)
  !!ir (dstB := AST.fsqrt srcB)

let vsqrtps ins insLen ctxt =
  let ir = IRBuilder (16)
  let struct (dst, src) = getTwoOprs ins
  let oprSz = getOperationSize ins
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
  let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
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
  let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
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

let maskWithEPrx ePrx dst rt =
  match ePrx.Z with
  | Zeroing -> AST.num0 rt
  | Merging -> dst

let private getVectorMoveCond ePrx k idx =
  (* no write mask *)
  let noWritemask = if ePrx.AAA = 0uy then AST.num1 1<rt> else AST.num0 1<rt>
  AST.extract k 1<rt> idx .| noWritemask

let private makeIteMovReg ePrx k i src dst extFn =
  AST.ite (getVectorMoveCond ePrx k i)
    (extFn 32<rt> src) (maskWithEPrx ePrx (extFn 32<rt> dst) 32<rt>)

let private makeIteMovMem ePrx k i src dst extFn =
  AST.ite (getVectorMoveCond ePrx k i) (extFn 32<rt> src) (extFn 32<rt> dst)

let private makeAssignForVecMove ePrx k src dst idx =
  AST.concat (makeIteMovMem ePrx k (idx + 1) src dst AST.xthi)
             (makeIteMovMem ePrx k idx src dst AST.xtlo)

let private makeAssignForEVEX ir ePrx k dst s1 s2 src2A src2 idx opFn =
  let tmps = Array.init 2 (fun _ -> !*ir 32<rt>)
  for i in 0 .. 1 do
    let s1 = AST.extract s1 32<rt> (i * 32)
    let s2 = AST.extract s2 32<rt> (i * 32)
    let dst = AST.extract dst 32<rt> (i * 32)
    let tSrc =
      match src2 with
      | OprMem _ when ePrx.AAA (* B *) = 1uy -> opFn s1 (AST.xtlo 32<rt> src2A)
      | _ -> opFn s1 s2
    !!ir (tmps[i] := AST.ite (getVectorMoveCond ePrx k (idx + i))
                             tSrc (maskWithEPrx ePrx dst 32<rt>))
  AST.concatArr tmps

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
    match dst with
    | OprReg _ ->
      let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
        transOprToExpr512 ins insLen ctxt dst
      let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
        transOprToExpr512 ins insLen ctxt src
      !!ir (AST.xtlo 32<rt> dstA := makeIteMovReg ePrx k 0 srcA dstA AST.xtlo)
      !!ir (AST.xthi 32<rt> dstA := makeIteMovReg ePrx k 1 srcA dstA AST.xthi)
      !!ir (AST.xtlo 32<rt> dstB := makeIteMovReg ePrx k 2 srcB dstB AST.xtlo)
      !!ir (AST.xthi 32<rt> dstB := makeIteMovReg ePrx k 3 srcB dstB AST.xthi)
      !!ir (AST.xtlo 32<rt> dstC := makeIteMovReg ePrx k 4 srcC dstC AST.xtlo)
      !!ir (AST.xthi 32<rt> dstC := makeIteMovReg ePrx k 5 srcC dstC AST.xthi)
      !!ir (AST.xtlo 32<rt> dstD := makeIteMovReg ePrx k 6 srcD dstD AST.xtlo)
      !!ir (AST.xthi 32<rt> dstD := makeIteMovReg ePrx k 7 srcD dstD AST.xthi)
      !!ir (AST.xtlo 32<rt> dstE := makeIteMovReg ePrx k 8 srcE dstE AST.xtlo)
      !!ir (AST.xthi 32<rt> dstE := makeIteMovReg ePrx k 9 srcE dstE AST.xthi)
      !!ir (AST.xtlo 32<rt> dstF := makeIteMovReg ePrx k 10 srcF dstF AST.xtlo)
      !!ir (AST.xthi 32<rt> dstF := makeIteMovReg ePrx k 11 srcF dstF AST.xthi)
      !!ir (AST.xtlo 32<rt> dstG := makeIteMovReg ePrx k 12 srcG dstG AST.xtlo)
      !!ir (AST.xthi 32<rt> dstG := makeIteMovReg ePrx k 13 srcG dstG AST.xthi)
      !!ir (AST.xtlo 32<rt> dstH := makeIteMovReg ePrx k 14 srcH dstH AST.xtlo)
      !!ir (AST.xthi 32<rt> dstH := makeIteMovReg ePrx k 15 srcH dstH AST.xthi)
    | OprMem _ ->
      let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
        transOprToExpr512 ins insLen ctxt dst
      let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
        transOprToExpr512 ins insLen ctxt src
      !!ir (dstA := makeAssignForVecMove ePrx k srcA dstA 0)
      !!ir (dstB := makeAssignForVecMove ePrx k srcB dstB 2)
      !!ir (dstC := makeAssignForVecMove ePrx k srcC dstB 4)
      !!ir (dstD := makeAssignForVecMove ePrx k srcD dstB 6)
      !!ir (dstE := makeAssignForVecMove ePrx k srcE dstB 8)
      !!ir (dstF := makeAssignForVecMove ePrx k srcF dstB 10)
      !!ir (dstG := makeAssignForVecMove ePrx k srcG dstB 12)
      !!ir (dstH := makeAssignForVecMove ePrx k srcH dstB 14)
    | _ -> raise InvalidOperandException
  else raise InvalidOperandSizeException
  !>ir insLen

let vmovd ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src) = getTwoOprs ins
  let oprSize = getOperationSize ins
  !<ir insLen
  let n0 = AST.num0 64<rt>
  match dst, src with
  | OprReg r1, OprReg r2 ->
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
  match dst, src with
  | OprReg r1, OprReg r2 ->
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

let private makeAssignWithMaskR32 ir ePrx k elemSz dst src idx =
  let elemNum = 64 / int elemSz
  let tmps = Array.init elemNum (fun _ -> !*ir elemSz)
  for i in 0 .. (elemNum - 1) do
    let pos = i * int elemSz
    let dst = AST.extract dst elemSz pos
    !!ir (tmps[i] := AST.ite (getVectorMoveCond ePrx k (idx + i))
                             src (maskWithEPrx ePrx dst elemSz))
  AST.concatArr tmps

let private makeAssignWithMask ir ePrx k elemSz dst src idx =
  let elemNum = 64 / int elemSz
  let tmps = Array.init elemNum (fun _ -> !*ir elemSz)
  for i in 0 .. (elemNum - 1) do
    let pos = i * int elemSz
    let dst = AST.extract dst elemSz pos
    !!ir (tmps[i] := AST.ite (getVectorMoveCond ePrx k (idx + i))
                             (AST.extract src elemSz pos)
                             (maskWithEPrx ePrx dst elemSz))
  AST.concatArr tmps

let private makeAssignWithoutMask ir ePrx k elemSz dst src idx =
  let elemNum = 64 / int elemSz
  let tmps = Array.init elemNum (fun _ -> !*ir elemSz)
  for i in 0 .. (elemNum - 1) do
    let pos = i * int elemSz
    let dst = AST.extract dst elemSz pos
    !!ir (tmps[i] := AST.ite (getVectorMoveCond ePrx k (idx + i))
                             (AST.extract src elemSz pos) dst)
  AST.concatArr tmps

let vmovdqu16 ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src) = getTwoOprs ins
  let oprSize = getOperationSize ins
  let ePrx = getEVEXPrx ins.VEXInfo
  let k = !.ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
  !<ir insLen
  match oprSize with
  | 128<rt> ->
    let vl = 128
    match dst with
    | OprReg _ ->
      let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
      let srcB, srcA = transOprToExpr128 ins insLen ctxt src
      !!ir (dstA := makeAssignWithMask ir ePrx k 16<rt> dstA srcA 0)
      !!ir (dstB := makeAssignWithMask ir ePrx k 16<rt> dstB srcB 4)
      fillZeroFromVLToMaxVL ctxt dst vl 512 ir
    | OprMem _ ->
      let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
      let srcB, srcA = transOprToExpr128 ins insLen ctxt src
      !!ir (dstA := makeAssignWithoutMask ir ePrx k 16<rt> dstA srcA 0)
      !!ir (dstB := makeAssignWithoutMask ir ePrx k 16<rt> dstB srcB 4)
    | _ -> raise InvalidOperandException
  | 256<rt> ->
    let vl = 256
    match dst with
    | OprReg _ ->
      let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
      let srcD, srcC, srcB, srcA = transOprToExpr256 ins insLen ctxt src
      !!ir (dstA := makeAssignWithMask ir ePrx k 16<rt> dstA srcA 0)
      !!ir (dstB := makeAssignWithMask ir ePrx k 16<rt> dstB srcB 4)
      !!ir (dstC := makeAssignWithMask ir ePrx k 16<rt> dstC srcC 8)
      !!ir (dstD := makeAssignWithMask ir ePrx k 16<rt> dstD srcD 12)
      fillZeroFromVLToMaxVL ctxt dst vl 512 ir
    | OprMem _ ->
      let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
      let srcD, srcC, srcB, srcA = transOprToExpr256 ins insLen ctxt src
      !!ir (dstA := makeAssignWithoutMask ir ePrx k 16<rt> dstA srcA 0)
      !!ir (dstB := makeAssignWithoutMask ir ePrx k 16<rt> dstB srcB 4)
      !!ir (dstC := makeAssignWithoutMask ir ePrx k 16<rt> dstC srcC 8)
      !!ir (dstD := makeAssignWithoutMask ir ePrx k 16<rt> dstD srcD 12)
    | _ -> raise InvalidOperandException
  | 512<rt> ->
    match dst with
    | OprReg _ ->
      let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
        transOprToExpr512 ins insLen ctxt dst
      let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
        transOprToExpr512 ins insLen ctxt src
      !!ir (dstA := makeAssignWithMask ir ePrx k 16<rt> dstA srcA 0)
      !!ir (dstB := makeAssignWithMask ir ePrx k 16<rt> dstB srcB 4)
      !!ir (dstC := makeAssignWithMask ir ePrx k 16<rt> dstC srcC 8)
      !!ir (dstD := makeAssignWithMask ir ePrx k 16<rt> dstD srcD 12)
      !!ir (dstE := makeAssignWithMask ir ePrx k 16<rt> dstE srcE 16)
      !!ir (dstF := makeAssignWithMask ir ePrx k 16<rt> dstF srcF 20)
      !!ir (dstG := makeAssignWithMask ir ePrx k 16<rt> dstG srcG 24)
      !!ir (dstH := makeAssignWithMask ir ePrx k 16<rt> dstH srcH 28)
    | OprMem _ ->
      let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
        transOprToExpr512 ins insLen ctxt dst
      let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
        transOprToExpr512 ins insLen ctxt src
      !!ir (dstA := makeAssignWithoutMask ir ePrx k 16<rt> dstA srcA 0)
      !!ir (dstB := makeAssignWithoutMask ir ePrx k 16<rt> dstB srcB 4)
      !!ir (dstC := makeAssignWithoutMask ir ePrx k 16<rt> dstC srcC 8)
      !!ir (dstD := makeAssignWithoutMask ir ePrx k 16<rt> dstD srcD 12)
      !!ir (dstE := makeAssignWithoutMask ir ePrx k 16<rt> dstE srcE 16)
      !!ir (dstF := makeAssignWithoutMask ir ePrx k 16<rt> dstF srcF 20)
      !!ir (dstG := makeAssignWithoutMask ir ePrx k 16<rt> dstG srcG 24)
      !!ir (dstH := makeAssignWithoutMask ir ePrx k 16<rt> dstH srcH 28)
    | _ -> raise InvalidOperandException
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let vmovdqu64 ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src) = getTwoOprs ins
  let oprSize = getOperationSize ins
  let ePrx = getEVEXPrx ins.VEXInfo
  let k = !.ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
  !<ir insLen
  match oprSize with
  | 128<rt> ->
    let vl = 128
    match dst with
    | OprReg _ ->
      let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
      let srcB, srcA = transOprToExpr128 ins insLen ctxt src
      !!ir (dstA := AST.ite (getVectorMoveCond ePrx k 0)
                            srcA (maskWithEPrx ePrx dstA 64<rt>))
      !!ir (dstB := AST.ite (getVectorMoveCond ePrx k 1)
                            srcB (maskWithEPrx ePrx dstB 64<rt>))
      fillZeroFromVLToMaxVL ctxt dst vl 512 ir
    | OprMem _ ->
      let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
      let srcB, srcA = transOprToExpr128 ins insLen ctxt src
      !!ir (dstA := AST.ite (getVectorMoveCond ePrx k 0) srcA dstA)
      !!ir (dstB := AST.ite (getVectorMoveCond ePrx k 1) srcB dstB)
    | _ -> raise InvalidOperandException
  | 256<rt> ->
    let vl = 256
    match dst with
    | OprReg _ ->
      let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
      let srcD, srcC, srcB, srcA = transOprToExpr256 ins insLen ctxt src
      !!ir (dstA := AST.ite (getVectorMoveCond ePrx k 0)
                            srcA (maskWithEPrx ePrx dstA 64<rt>))
      !!ir (dstB := AST.ite (getVectorMoveCond ePrx k 1)
                            srcB (maskWithEPrx ePrx dstB 64<rt>))
      !!ir (dstC := AST.ite (getVectorMoveCond ePrx k 2)
                            srcC (maskWithEPrx ePrx dstC 64<rt>))
      !!ir (dstD := AST.ite (getVectorMoveCond ePrx k 3)
                            srcD (maskWithEPrx ePrx dstD 64<rt>))
      fillZeroFromVLToMaxVL ctxt dst vl 512 ir
    | OprMem _ ->
      let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
      let srcD, srcC, srcB, srcA = transOprToExpr256 ins insLen ctxt src
      !!ir (dstA := AST.ite (getVectorMoveCond ePrx k 0) srcA dstA)
      !!ir (dstB := AST.ite (getVectorMoveCond ePrx k 1) srcB dstB)
      !!ir (dstC := AST.ite (getVectorMoveCond ePrx k 2) srcC dstC)
      !!ir (dstD := AST.ite (getVectorMoveCond ePrx k 3) srcD dstD)
    | _ -> raise InvalidOperandException
  | 512<rt> ->
    match dst with
    | OprReg _ ->
      let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
        transOprToExpr512 ins insLen ctxt dst
      let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
        transOprToExpr512 ins insLen ctxt src
      !!ir (dstA := AST.ite (getVectorMoveCond ePrx k 0)
                            srcA (maskWithEPrx ePrx dstA 64<rt>))
      !!ir (dstB := AST.ite (getVectorMoveCond ePrx k 1)
                            srcB (maskWithEPrx ePrx dstB 64<rt>))
      !!ir (dstC := AST.ite (getVectorMoveCond ePrx k 2)
                            srcC (maskWithEPrx ePrx dstC 64<rt>))
      !!ir (dstD := AST.ite (getVectorMoveCond ePrx k 3)
                            srcD (maskWithEPrx ePrx dstD 64<rt>))
      !!ir (dstE := AST.ite (getVectorMoveCond ePrx k 4)
                            srcE (maskWithEPrx ePrx dstE 64<rt>))
      !!ir (dstF := AST.ite (getVectorMoveCond ePrx k 5)
                            srcF (maskWithEPrx ePrx dstF 64<rt>))
      !!ir (dstG := AST.ite (getVectorMoveCond ePrx k 6)
                            srcG (maskWithEPrx ePrx dstG 64<rt>))
      !!ir (dstH := AST.ite (getVectorMoveCond ePrx k 7)
                            srcH (maskWithEPrx ePrx dstH 64<rt>))
    | OprMem _ ->
      let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
        transOprToExpr512 ins insLen ctxt dst
      let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
        transOprToExpr512 ins insLen ctxt src
      !!ir (dstA := AST.ite (getVectorMoveCond ePrx k 0) srcA dstA)
      !!ir (dstB := AST.ite (getVectorMoveCond ePrx k 1) srcB dstB)
      !!ir (dstC := AST.ite (getVectorMoveCond ePrx k 2) srcC dstC)
      !!ir (dstD := AST.ite (getVectorMoveCond ePrx k 3) srcD dstD)
      !!ir (dstE := AST.ite (getVectorMoveCond ePrx k 4) srcE dstE)
      !!ir (dstF := AST.ite (getVectorMoveCond ePrx k 5) srcF dstF)
      !!ir (dstG := AST.ite (getVectorMoveCond ePrx k 6) srcG dstG)
      !!ir (dstH := AST.ite (getVectorMoveCond ePrx k 7) srcH dstH)
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
  !<ir insLen
  match oprSize with
  | 128<rt> ->
    let vl = 128
    match dst with
    | OprReg _ ->
      let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
      let srcB, srcA = transOprToExpr128 ins insLen ctxt src
      !!ir (dstA := AST.ite (getVectorMoveCond ePrx k 0)
                            srcA (maskWithEPrx ePrx dstA 64<rt>))
      !!ir (dstB := AST.ite (getVectorMoveCond ePrx k 1)
                            srcB (maskWithEPrx ePrx dstB 64<rt>))
      fillZeroFromVLToMaxVL ctxt dst vl 512 ir
    | OprMem _ ->
      let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
      let srcB, srcA = transOprToExpr128 ins insLen ctxt src
      !!ir (dstA := AST.ite (getVectorMoveCond ePrx k 0) srcA dstA)
      !!ir (dstB := AST.ite (getVectorMoveCond ePrx k 1) srcB dstB)
    | _ -> raise InvalidOperandException
  | 256<rt> ->
    let vl = 256
    match dst with
    | OprReg _ ->
      let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
      let srcD, srcC, srcB, srcA = transOprToExpr256 ins insLen ctxt src
      !!ir (dstA := AST.ite (getVectorMoveCond ePrx k 0)
                            srcA (maskWithEPrx ePrx dstA 64<rt>))
      !!ir (dstB := AST.ite (getVectorMoveCond ePrx k 1)
                            srcB (maskWithEPrx ePrx dstB 64<rt>))
      !!ir (dstC := AST.ite (getVectorMoveCond ePrx k 2)
                            srcC (maskWithEPrx ePrx dstC 64<rt>))
      !!ir (dstD := AST.ite (getVectorMoveCond ePrx k 3)
                            srcD (maskWithEPrx ePrx dstD 64<rt>))
      fillZeroFromVLToMaxVL ctxt dst vl 512 ir
    | OprMem _ ->
      let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
      let srcD, srcC, srcB, srcA = transOprToExpr256 ins insLen ctxt src
      !!ir (dstA := AST.ite (getVectorMoveCond ePrx k 0) srcA dstA)
      !!ir (dstB := AST.ite (getVectorMoveCond ePrx k 1) srcB dstB)
      !!ir (dstC := AST.ite (getVectorMoveCond ePrx k 2) srcC dstC)
      !!ir (dstD := AST.ite (getVectorMoveCond ePrx k 3) srcD dstD)
    | _ -> raise InvalidOperandException
  | 512<rt> ->
    match dst with
    | OprReg _ ->
      let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
        transOprToExpr512 ins insLen ctxt dst
      let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
        transOprToExpr512 ins insLen ctxt src
      !!ir (dstA := AST.ite (getVectorMoveCond ePrx k 0)
                            srcA (maskWithEPrx ePrx dstA 64<rt>))
      !!ir (dstB := AST.ite (getVectorMoveCond ePrx k 1)
                            srcB (maskWithEPrx ePrx dstB 64<rt>))
      !!ir (dstC := AST.ite (getVectorMoveCond ePrx k 2)
                            srcC (maskWithEPrx ePrx dstC 64<rt>))
      !!ir (dstD := AST.ite (getVectorMoveCond ePrx k 3)
                            srcD (maskWithEPrx ePrx dstD 64<rt>))
      !!ir (dstE := AST.ite (getVectorMoveCond ePrx k 4)
                            srcE (maskWithEPrx ePrx dstE 64<rt>))
      !!ir (dstF := AST.ite (getVectorMoveCond ePrx k 5)
                            srcF (maskWithEPrx ePrx dstF 64<rt>))
      !!ir (dstG := AST.ite (getVectorMoveCond ePrx k 6)
                            srcG (maskWithEPrx ePrx dstG 64<rt>))
      !!ir (dstH := AST.ite (getVectorMoveCond ePrx k 7)
                            srcH (maskWithEPrx ePrx dstH 64<rt>))
    | OprMem _ ->
      let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
        transOprToExpr512 ins insLen ctxt dst
      let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
        transOprToExpr512 ins insLen ctxt src
      !!ir (dstA := AST.ite (getVectorMoveCond ePrx k 0) srcA dstA)
      !!ir (dstB := AST.ite (getVectorMoveCond ePrx k 1) srcB dstB)
      !!ir (dstC := AST.ite (getVectorMoveCond ePrx k 2) srcC dstC)
      !!ir (dstD := AST.ite (getVectorMoveCond ePrx k 3) srcD dstD)
      !!ir (dstE := AST.ite (getVectorMoveCond ePrx k 4) srcE dstE)
      !!ir (dstF := AST.ite (getVectorMoveCond ePrx k 5) srcF dstF)
      !!ir (dstG := AST.ite (getVectorMoveCond ePrx k 6) srcG dstG)
      !!ir (dstH := AST.ite (getVectorMoveCond ePrx k 7) srcH dstH)
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
  | TwoOperands (OprMem _, _) -> SSELifter.movsd ins insLen ctxt
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
  | TwoOperands (OprMem _, _) -> SSELifter.movss ins insLen ctxt
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
  let i8 = getImmValue imm
  !<ir insLen
  match oprSize with
  | 256<rt> ->
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
    !!ir (dstA := makeAssignWithMask ir ePrx k 32<rt> dstA tDstA 0)
    !!ir (dstB := makeAssignWithMask ir ePrx k 32<rt> dstB tDstB 2)
    !!ir (dstC := makeAssignWithMask ir ePrx k 32<rt> dstC tDstC 4)
    !!ir (dstD := makeAssignWithMask ir ePrx k 32<rt> dstD tDstD 6)
  | 512<rt> ->
    let kl = 16
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
    !!ir (dstA := makeAssignWithMask ir ePrx k 32<rt> dstA tDstA 0)
    !!ir (dstB := makeAssignWithMask ir ePrx k 32<rt> dstB tDstB 2)
    !!ir (dstC := makeAssignWithMask ir ePrx k 32<rt> dstC tDstC 4)
    !!ir (dstD := makeAssignWithMask ir ePrx k 32<rt> dstD tDstD 6)
    !!ir (dstE := makeAssignWithMask ir ePrx k 32<rt> dstE tDstE 8)
    !!ir (dstF := makeAssignWithMask ir ePrx k 32<rt> dstF tDstF 10)
    !!ir (dstG := makeAssignWithMask ir ePrx k 32<rt> dstG tDstG 12)
    !!ir (dstH := makeAssignWithMask ir ePrx k 32<rt> dstH tDstH 14)
  | _ -> raise InvalidOperandException
  !>ir insLen

let private doShuf ir cond dst e1 e2 =
  !!ir (dst := AST.num0 32<rt>)
  !!ir (dst := AST.ite (cond == AST.num0 8<rt>) (AST.xtlo 32<rt> e1) dst)
  !!ir (dst := AST.ite (cond == AST.num1 8<rt>) (AST.xthi 32<rt> e1) dst)
  !!ir (dst := AST.ite (cond == numI32 2 8<rt>) (AST.xtlo 32<rt> e2) dst)
  !!ir (dst := AST.ite (cond == numI32 3 8<rt>) (AST.xthi 32<rt> e2) dst)

let private makeShufCond imm shfAmt =
  ((AST.xtlo 8<rt> imm) >> (numI32 shfAmt 8<rt>)) .& (numI32 0b11 8<rt>)

let vshufps ins insLen ctxt =
  let ir = IRBuilder (32)
  let struct (dst, src1, src2, imm) = getFourOprs ins
  let imm = transOprToExpr ins insLen ctxt imm
  !<ir insLen
  match getOperationSize ins with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
    let sr1B, sr1A = transOprToExpr128 ins insLen ctxt src1
    let sr2B, sr2A = transOprToExpr128 ins insLen ctxt src2
    doShuf ir (makeShufCond imm 0) (AST.xtlo 32<rt> dstA) sr1A sr1B
    doShuf ir (makeShufCond imm 2) (AST.xthi 32<rt> dstA) sr1A sr1B
    doShuf ir (makeShufCond imm 4) (AST.xtlo 32<rt> dstB) sr2A sr2B
    doShuf ir (makeShufCond imm 6) (AST.xthi 32<rt> dstB) sr2A sr2B
    fillZeroHigh128 ctxt dst ir
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
    let sr1D, sr1C, sr1B, sr1A = transOprToExpr256 ins insLen ctxt src1
    let sr2D, sr2C, sr2B, sr2A = transOprToExpr256 ins insLen ctxt src2
    doShuf ir (makeShufCond imm 0) (AST.xtlo 32<rt> dstA) sr1A sr1B
    doShuf ir (makeShufCond imm 2) (AST.xthi 32<rt> dstA) sr1A sr1B
    doShuf ir (makeShufCond imm 4) (AST.xtlo 32<rt> dstB) sr2A sr2B
    doShuf ir (makeShufCond imm 6) (AST.xthi 32<rt> dstB) sr2A sr2B
    doShuf ir (makeShufCond imm 0) (AST.xtlo 32<rt> dstC) sr1C sr1D
    doShuf ir (makeShufCond imm 2) (AST.xthi 32<rt> dstC) sr1C sr1D
    doShuf ir (makeShufCond imm 4) (AST.xtlo 32<rt> dstD) sr2C sr2D
    doShuf ir (makeShufCond imm 6) (AST.xthi 32<rt> dstD) sr2C sr2D
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
    let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
      transOprToExpr512 ins insLen ctxt dst
    let s1H, s1G, s1F, s1E, s1D, s1C, s1B, s1A =
      transOprToExpr512 ins insLen ctxt src1
    let s2H, s2G, s2F, s2E, s2D, s2C, s2B, s2A =
      transOprToExpr512 ins insLen ctxt src2
    !!ir (dstA := makeAssignForEVEX ir ePrx k dstA s1A s2A s2A src2 0 (<+>))
    !!ir (dstB := makeAssignForEVEX ir ePrx k dstB s1B s2B s2A src2 2 (<+>))
    !!ir (dstC := makeAssignForEVEX ir ePrx k dstC s1C s2C s2A src2 4 (<+>))
    !!ir (dstD := makeAssignForEVEX ir ePrx k dstD s1D s2D s2A src2 6 (<+>))
    !!ir (dstE := makeAssignForEVEX ir ePrx k dstE s1E s2E s2A src2 8 (<+>))
    !!ir (dstF := makeAssignForEVEX ir ePrx k dstF s1F s2F s2A src2 10 (<+>))
    !!ir (dstG := makeAssignForEVEX ir ePrx k dstG s1G s2G s2A src2 12 (<+>))
    !!ir (dstH := makeAssignForEVEX ir ePrx k dstH s1H s2H s2A src2 14 (<+>))
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
  let ePrx = getEVEXPrx ins.VEXInfo
  let k = !.ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
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
    !!ir (dstA := makeAssignWithMask ir ePrx k 32<rt> dstA tDstA 0)
    !!ir (dstB := makeAssignWithMask ir ePrx k 32<rt> dstB tDstB 2)
    !!ir (dstC := makeAssignWithMask ir ePrx k 32<rt> dstC tDstC 4)
    !!ir (dstD := makeAssignWithMask ir ePrx k 32<rt> dstD tDstD 6)
  | OprMem _ ->
    !!ir (dstA := makeAssignWithoutMask ir ePrx k 32<rt> dstA tDstA 0)
    !!ir (dstB := makeAssignWithoutMask ir ePrx k 32<rt> dstB tDstB 2)
    !!ir (dstC := makeAssignWithoutMask ir ePrx k 32<rt> dstC tDstC 4)
    !!ir (dstD := makeAssignWithoutMask ir ePrx k 32<rt> dstD tDstD 6)
  | _ -> raise InvalidOperandException
  !>ir insLen

let vextracti64x4 ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src, imm) = getThreeOprs ins
  let ePrx = getEVEXPrx ins.VEXInfo
  let k = !.ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
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
    !!ir (dstA := AST.ite (getVectorMoveCond ePrx k 0)
                          tDstA (maskWithEPrx ePrx dstA 64<rt>))
    !!ir (dstB := AST.ite (getVectorMoveCond ePrx k 1)
                          tDstB (maskWithEPrx ePrx dstB 64<rt>))
    !!ir (dstC := AST.ite (getVectorMoveCond ePrx k 2)
                          tDstC (maskWithEPrx ePrx dstC 64<rt>))
    !!ir (dstD := AST.ite (getVectorMoveCond ePrx k 3)
                          tDstD (maskWithEPrx ePrx dstD 64<rt>))
  | OprMem _ ->
    !!ir (dstA := AST.ite (getVectorMoveCond ePrx k 0) tDstA dstA)
    !!ir (dstB := AST.ite (getVectorMoveCond ePrx k 1) tDstB dstB)
    !!ir (dstC := AST.ite (getVectorMoveCond ePrx k 2) tDstC dstC)
    !!ir (dstD := AST.ite (getVectorMoveCond ePrx k 3) tDstD dstD)
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
    let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
      transOprToExpr512 ins insLen ctxt dst
    let s1H, s1G, s1F, s1E, s1D, s1C, s1B, s1A =
      transOprToExpr512 ins insLen ctxt src1
    let s2H, s2G, s2F, s2E, s2D, s2C, s2B, s2A =
      transOprToExpr512 ins insLen ctxt src2
    !!ir (dstA := makeAssignForEVEX ir ePrx k dstA s1A s2A s2A src2 0 (.+))
    !!ir (dstB := makeAssignForEVEX ir ePrx k dstB s1B s2B s2A src2 2 (.+))
    !!ir (dstC := makeAssignForEVEX ir ePrx k dstC s1C s2C s2A src2 4 (.+))
    !!ir (dstD := makeAssignForEVEX ir ePrx k dstD s1D s2D s2A src2 6 (.+))
    !!ir (dstE := makeAssignForEVEX ir ePrx k dstE s1E s2E s2A src2 8 (.+))
    !!ir (dstF := makeAssignForEVEX ir ePrx k dstF s1F s2F s2A src2 10 (.+))
    !!ir (dstG := makeAssignForEVEX ir ePrx k dstG s1G s2G s2A src2 12 (.+))
    !!ir (dstH := makeAssignForEVEX ir ePrx k dstH s1H s2H s2A src2 14 (.+))
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
    let ePrx = getEVEXPrx ins.VEXInfo
    let k = !.ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
    let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
      transOprToExpr512 ins insLen ctxt dst
    !!ir (dstA := makeAssignWithMaskR32 ir ePrx k 32<rt> dstA temp 0)
    !!ir (dstB := makeAssignWithMaskR32 ir ePrx k 32<rt> dstB temp 2)
    !!ir (dstC := makeAssignWithMaskR32 ir ePrx k 32<rt> dstC temp 4)
    !!ir (dstD := makeAssignWithMaskR32 ir ePrx k 32<rt> dstD temp 6)
    !!ir (dstE := makeAssignWithMaskR32 ir ePrx k 32<rt> dstE temp 8)
    !!ir (dstF := makeAssignWithMaskR32 ir ePrx k 32<rt> dstF temp 10)
    !!ir (dstG := makeAssignWithMaskR32 ir ePrx k 32<rt> dstG temp 12)
    !!ir (dstH := makeAssignWithMaskR32 ir ePrx k 32<rt> dstH temp 14)
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
  let n0 = AST.num0 8<rt>
  let mask = numU32 0x0Fu 8<rt>
  !<ir insLen
  match oprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
    let src1B, src1A = transOprToExpr128 ins insLen ctxt src1
    let src2B, src2A = transOprToExpr128 ins insLen ctxt src2
    let highTmps = Array.init 8 (fun _ -> !*ir 8<rt>)
    let lowTmps = Array.init 8 (fun _ -> !*ir 8<rt>)
    let struct (tSrc1, tSrc2) = tmpVars2 ir 64<rt>
    for i in 0 .. cnt - 1 do
      !!ir (tSrc2 := if i < 8 then src2A else src2B)
      let cond = AST.extract tSrc2 1<rt> (((i * 8) % 64) + 7)
      let idx = (AST.extract tSrc2 8<rt> ((i * 8) % 64)) .& mask
      let numShift =
        ((AST.zext 64<rt> idx) .* (numI32 8 64<rt>)) .% (numI32 64 64<rt>)
      !!ir (tSrc1 := AST.ite (idx .< numI32 8 8<rt>) src1A src1B)
      let src1 = AST.xtlo 8<rt> (tSrc1 >> numShift)
      if i < 8 then !!ir (lowTmps[i] := AST.ite cond n0 src1)
      else !!ir (highTmps[i % 8] := AST.ite cond n0 src1)
    done
    !!ir (dstA := AST.concatArr lowTmps)
    !!ir (dstB := AST.concatArr highTmps)
    fillZeroHigh128 ctxt dst ir
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
    let src1D, src1C, src1B, src1A = transOprToExpr256 ins insLen ctxt src1
    let src2D, src2C, src2B, src2A = transOprToExpr256 ins insLen ctxt src2
    let tmpsA = Array.init 8 (fun _ -> !*ir 8<rt>)
    let tmpsB = Array.init 8 (fun _ -> !*ir 8<rt>)
    let tmpsC = Array.init 8 (fun _ -> !*ir 8<rt>)
    let tmpsD = Array.init 8 (fun _ -> !*ir 8<rt>)
    let struct (tSrc1, tSrc2) = tmpVars2 ir 64<rt>
    let src1 = [| src1A; src1B; src1C; src1D  |]
    let src2 = [| src2A; src2B; src2C; src2D  |]
    let n8 = numI32 8 8<rt>
    let n16 = numI32 16 8<rt>
    let n24 = numI32 24 8<rt>
    for i in 0 .. cnt - 1 do
      !!ir (tSrc1 := src1[i / 8])
      !!ir (tSrc2 := src2[i / 8])
      let cond = AST.extract tSrc2 1<rt> (((i * 8) % 64) + 7)
      let idx = (AST.extract tSrc2 8<rt> ((i * 8) % 64)) .& mask
      let numShift =
        ((AST.zext 64<rt> idx) .* (numI32 8 64<rt>)) .% (numI32 64 64<rt>)
      let src1 =
        AST.ite (idx .< n8) src1A (AST.ite (idx .< n16) src1B
        (AST.ite (idx .< n24) src1C src1D))
      !!ir (tSrc1 := src1)
      let src1 = AST.xtlo 8<rt> (tSrc1 >> numShift)
      if i < 8 then !!ir (tmpsA[i] := AST.ite cond n0 src1)
      elif i < 16 then !!ir (tmpsB[i % 8] := AST.ite cond n0 src1)
      elif i < 24 then !!ir (tmpsC[i % 8] := AST.ite cond n0 src1)
      else !!ir (tmpsD[i % 8] := AST.ite cond n0 src1)
    done
    !!ir (dstA := AST.concatArr tmpsA)
    !!ir (dstB := AST.concatArr tmpsB)
    !!ir (dstC := AST.concatArr tmpsC)
    !!ir (dstD := AST.concatArr tmpsD)
  | 512<rt> ->
    let kl = 64
    let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
      transOprToExpr512 ins insLen ctxt dst
    let src1H, src1G, src1F, src1E, src1D, src1C, src1B, src1A =
      transOprToExpr512 ins insLen ctxt src1
    let src2H, src2G, src2F, src2E, src2D, src2C, src2B, src2A =
      transOprToExpr512 ins insLen ctxt src2
    let tmpsA = Array.init 8 (fun _ -> !*ir 8<rt>)
    let tmpsB = Array.init 8 (fun _ -> !*ir 8<rt>)
    let tmpsC = Array.init 8 (fun _ -> !*ir 8<rt>)
    let tmpsD = Array.init 8 (fun _ -> !*ir 8<rt>)
    let tmpsE = Array.init 8 (fun _ -> !*ir 8<rt>)
    let tmpsF = Array.init 8 (fun _ -> !*ir 8<rt>)
    let tmpsG = Array.init 8 (fun _ -> !*ir 8<rt>)
    let tmpsH = Array.init 8 (fun _ -> !*ir 8<rt>)
    let src1 = [| src1A; src1B; src1C; src1D; src1E; src1F; src1G; src1H |]
    let src2 = [| src2A; src2B; src2C; src2D; src2E; src2F; src2G; src2H |]
    let struct (tSrc1, tSrc2) = tmpVars2 ir 64<rt>
    let numF = numU32 0xFu 8<rt>
    let n0 = AST.num0 8<rt>
    let jmask = !*ir 8<rt>
    let ePrx = getEVEXPrx ins.VEXInfo
    let k = !.ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
    let lblNoMask = ir.NewSymbol "NoMasking"
    let lblZero = ir.NewSymbol "Zeroing"
    let lblL0 = ir.NewSymbol "L0" (* index & 0x80 *)
    let lblL1 = ir.NewSymbol "L1"
    let lblEnd = ir.NewSymbol "End"
    let struct (index, cond) = tmpVars2 ir 8<rt>
    let getTmpDst idx =
      if idx < 8 then tmpsA[idx]
      elif idx < 16 then tmpsB[idx % 8]
      elif idx < 24 then tmpsC[idx % 8]
      elif idx < 32 then tmpsD[idx % 8]
      elif idx < 40 then tmpsE[idx % 8]
      elif idx < 48 then tmpsF[idx % 8]
      elif idx < 56 then tmpsG[idx % 8]
      else tmpsG[idx % 8]
    let n8 = numI32 8 8<rt>
    let n16 = numI32 16 8<rt>
    let n24 = numI32 24 8<rt>
    let n32 = numI32 32 8<rt>
    let n40 = numI32 40 8<rt>
    let n48 = numI32 48 8<rt>
    let n56 = numI32 56 8<rt>
    !!ir (jmask := numI32 ((kl - 1) &&& ~~~0xF) 8<rt>)
    for i in 0 .. kl - 1 do
      !!ir (tSrc2 := src2[i / 8])
      !!ir (AST.cjmp (getVectorMoveCond ePrx k i)
                     (AST.name lblNoMask) (AST.name lblZero))
      !!ir (AST.lmark lblNoMask)
      !!ir (index := AST.extract tSrc2 8<rt> ((i * 8) % 64))
      !!ir (cond := index .& numI32 0x80 8<rt>)
      !!ir (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
      !!ir (AST.lmark lblL0)
      !!ir (getTmpDst i := n0)
      !!ir (AST.jmp (AST.name lblEnd))
      !!ir (AST.lmark lblL1)
      !!ir (index := (index .& numF) .+ (numI32 (i % 8) 8<rt> .& jmask))
      let numShift =
        ((AST.zext 64<rt> index) .* (numI32 8 64<rt>)) .% (numI32 64 64<rt>)
      let src1 =
        AST.ite (index .< n8) src1A (AST.ite (index .< n16) src1B
          (AST.ite (index .< n24) src1C (AST.ite (index .< n32) src1D
            (AST.ite (index .< n40) src1E (AST.ite (index .< n48) src1E
              (AST.ite (index .< n56) src1G src1H))))))
      !!ir (tSrc1 := src1)
      let src1 = AST.xtlo 8<rt> (tSrc1 >> numShift)
      !!ir (getTmpDst i := src1)
      !!ir (AST.jmp (AST.name lblEnd))
      !!ir (AST.lmark lblZero)
      !!ir (getTmpDst i := n0)
      !!ir (AST.lmark lblEnd)
    done
    !!ir (dstA := AST.concatArr tmpsA)
    !!ir (dstB := AST.concatArr tmpsB)
    !!ir (dstC := AST.concatArr tmpsC)
    !!ir (dstD := AST.concatArr tmpsD)
    !!ir (dstE := AST.concatArr tmpsE)
    !!ir (dstF := AST.concatArr tmpsF)
    !!ir (dstG := AST.concatArr tmpsG)
    !!ir (dstH := AST.concatArr tmpsH)
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

let private opShiftVpackedDataLogical oprSize packSz shf src1 (src2: Expr []) =
  let count = src2[0] |> AST.zext oprSize
  let cond = AST.gt count (numI32 ((int packSz) - 1) oprSize)
  let shifted expr = AST.extract (shf (AST.zext oprSize expr) count) packSz 0
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
    let index = (int amount) / 64
    let src = [| tSrcA; tSrcB; AST.num0 64<rt>; AST.num0 64<rt> |]
    !!ir (dstA := (src[index + 1] << leftAmt) .| (src[index] >> rightAmt))
    !!ir (dstB := src[index + 1] >> rightAmt)
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
    let src1D, src1C, src1B, src1A = transOprToExpr256 ins insLen ctxt src1
    let src2D, src2C, src2B, src2A = transOprToExpr256 ins insLen ctxt src2
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
    let src1D, src1C, src1B, src1A = transOprToExpr256 ins insLen ctxt src1
    let src2D, src2C, src2B, src2A = transOprToExpr256 ins insLen ctxt src2
    !!ir (dstD := src1D <+> src2D)
    !!ir (dstC := src1C <+> src2C)
    !!ir (dstB := src1B <+> src2B)
    !!ir (dstA := src1A <+> src2A)
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let private makeAssignForEVEXWithDst ir ePrx k s1 s2 src2A dstA src2 idx =
  let tmps = Array.init 2 (fun _ -> !*ir 32<rt>)
  for i in 0 .. 1 do
    let s1 = AST.extract s1 32<rt> (i * 32)
    let s2 = AST.extract s2 32<rt> (i * 32)
    let dst = AST.extract dstA 32<rt> 0
    let tSrc =
      match src2 with
      | OprMem _ when ePrx.AAA (* B *) = 1uy -> s1 <+> (AST.xtlo 32<rt> src2A)
      | _ -> s1 <+> s2
    !!ir (tmps[i] := AST.ite (getVectorMoveCond ePrx k (idx + i))
                             tSrc (maskWithEPrx ePrx dst 32<rt>))
  AST.concatArr tmps

let vpxord ins insLen ctxt =
  let ir = IRBuilder (8)
  let struct (dst, src1, src2) = getThreeOprs ins
  let oprSize = getOperationSize ins
  !<ir insLen
  let ePrx = getEVEXPrx ins.VEXInfo
  let k = !.ctxt (ePrx.AAA |> Disasm.getOpmaskRegister)
  match oprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
    let s1B, s1A = transOprToExpr128 ins insLen ctxt src1
    let s2B, s2A = transOprToExpr128 ins insLen ctxt src2
    !!ir (dstA := makeAssignForEVEXWithDst ir ePrx k s1A s2A s2A dstA src2 0)
    !!ir (dstB := makeAssignForEVEXWithDst ir ePrx k s1B s2B s2A dstA src2 2)
    fillZeroHigh128 ctxt dst ir
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ins insLen ctxt dst
    let s1D, s1C, s1B, s1A = transOprToExpr256 ins insLen ctxt src1
    let s2D, s2C, s2B, s2A = transOprToExpr256 ins insLen ctxt src2
    !!ir (dstA := makeAssignForEVEXWithDst ir ePrx k s1A s2A s2A dstA src2 0)
    !!ir (dstB := makeAssignForEVEXWithDst ir ePrx k s1B s2B s2A dstA src2 2)
    !!ir (dstC := makeAssignForEVEXWithDst ir ePrx k s1C s2B s2A dstA src2 4)
    !!ir (dstD := makeAssignForEVEXWithDst ir ePrx k s1D s2B s2A dstA src2 6)
    fillZeroHigh256 ctxt dst ir
  | 512<rt> ->
    let dstH, dstG, dstF, dstE, dstD, dstC, dstB, dstA =
      transOprToExpr512 ins insLen ctxt dst
    let s1H, s1G, s1F, s1E, s1D, s1C, s1B, s1A =
      transOprToExpr512 ins insLen ctxt src1
    let s2H, s2G, s2F, s2E, s2D, s2C, s2B, s2A =
      transOprToExpr512 ins insLen ctxt src2
    !!ir (dstA := makeAssignForEVEXWithDst ir ePrx k s1A s2A s2A dstA src2 0)
    !!ir (dstB := makeAssignForEVEXWithDst ir ePrx k s1B s2B s2A dstA src2 2)
    !!ir (dstC := makeAssignForEVEXWithDst ir ePrx k s1C s2C s2A dstA src2 4)
    !!ir (dstD := makeAssignForEVEXWithDst ir ePrx k s1D s2D s2A dstA src2 6)
    !!ir (dstE := makeAssignForEVEXWithDst ir ePrx k s1E s2E s2A dstA src2 8)
    !!ir (dstF := makeAssignForEVEXWithDst ir ePrx k s1F s2F s2A dstA src2 10)
    !!ir (dstG := makeAssignForEVEXWithDst ir ePrx k s1G s2G s2A dstA src2 12)
    !!ir (dstH := makeAssignForEVEXWithDst ir ePrx k s1H s2H s2A dstA src2 14)
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
  let _dstB, dstA = transOprToExpr128 ins insLen ctxt dst
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
  let _dstB, dstA = transOprToExpr128 ins insLen ctxt dst
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
  let _dstB, dstA = transOprToExpr128 ins insLen ctxt dst
  let src2 = transOprToExpr64 ins insLen ctxt src2
  let src3 = transOprToExpr64 ins insLen ctxt src3
  let tmp = !*ir 64<rt>
  !<ir insLen
  !!ir (tmp := AST.fmul src2 src3)
  !!ir (dstA := AST.fadd dstA tmp)
  fillZeroHigh128 ctxt dst ir
  !>ir insLen
