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
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter.LiftingOperators
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.BinLifter.Intel
open B2R2.FrontEnd.BinLifter.Intel.LiftingUtils
open B2R2.FrontEnd.BinLifter.Intel.MMXLifter
open B2R2.FrontEnd.BinLifter.Intel.SSELifter

let private haveEVEXPrx = function
  | Some v -> Option.isSome v.EVEXPrx
  | None -> false

let private getEVEXPrx = function
  | Some v -> match v.EVEXPrx with
              | Some ev -> ev
              | None -> Utils.impossible ()
  | None -> Utils.impossible ()

let private maskWithEPrx ePrx dst rt =
  match ePrx.Z with
  | Zeroing -> AST.num0 rt
  | Merging -> dst

let private getVectorMoveCond ePrx k idx =
  (* no write mask *)
  let noWritemask = if ePrx.AAA = 0uy then AST.num1 1<rt> else AST.num0 1<rt>
  AST.extract k 1<rt> idx .| noWritemask

let private makeAssignWithMask ir ePrx k oprSize packSz dst src isMem =
  let packNum = oprSize / packSz
  let tmp = Array.init packNum (fun _ -> !+ir packSz)
  let mask idx dst src =
    let cond = getVectorMoveCond ePrx k idx
    let fallThrough = if isMem then dst else (maskWithEPrx ePrx dst packSz)
    AST.ite cond src fallThrough
  Array.mapi2 mask dst src |> Array.iter2 (fun e1 e2 -> !!ir (e1 := e2)) tmp
  tmp

let private makeAssignEVEX ir ePrx k oprSz packSz dst src1 src2 opFn isMem =
  let src2A = Array.head src2 (* SRC2[31:0] *)
  let packNum = oprSz / packSz
  let tmp = Array.init packNum (fun _ -> !+ir packSz)
  let mask idx src1 src2 =
    let cond = getVectorMoveCond ePrx k idx
    let tSrc =
      if isMem && ePrx.B (* B *) = 1uy then opFn src1 src2A else opFn src1 src2
    AST.ite cond tSrc (maskWithEPrx ePrx (Array.item idx dst) packSz)
  Array.mapi2 mask src1 src2 |> Array.iter2 (fun e1 e2 -> !!ir (e1 := e2)) tmp
  tmp

let private buildPackedFPInstr ins insLen ctxt packSz opFn =
  let ir = !*ctxt
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / packSz
  !<ir insLen
  let struct (dst, src1, src2) = getThreeOprs ins
  let src1 = transOprToArr ir false ins insLen ctxt packSz packNum oprSize src1
  let src2 = transOprToArr ir false ins insLen ctxt packSz packNum oprSize src2
  let src = Array.map2 opFn src1 src2
  assignPackedInstr ir false ins insLen ctxt packNum oprSize dst src
  fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  !>ir insLen

let private vexedScalarFPBinOp ins insLen ctxt sz op =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2) = getThreeOprs ins
  let dst2, dst1 = transOprToExpr128 ir false ins insLen ctxt dst
  let src1B, src1A = transOprToExpr128 ir false ins insLen ctxt src1
  match sz with
  | 32<rt> ->
    let src2 = transOprToExpr32 ir false ins insLen ctxt src2
    !!ir (AST.xtlo 32<rt> dst1 := op (AST.xtlo 32<rt> src1A) src2)
    !!ir (AST.xthi 32<rt> dst1 := AST.xthi 32<rt> src1A)
  | 64<rt> ->
    let src2 = transOprToExpr64 ir false ins insLen ctxt src2
    !!ir (dst1 := op src1A src2)
  | _ -> raise InvalidOperandSizeException
  !!ir (dst2 := src1B)
  fillZeroFromVLToMaxVL ctxt dst (getOperationSize ins) 512 ir
  !>ir insLen

let vsqrtps ins insLen ctxt =
  let ir = !*ctxt
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / 32<rt>
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let src = transOprToArr ir false ins insLen ctxt 32<rt> packNum oprSize src
  let result = Array.map (AST.unop UnOpType.FSQRT) src
  assignPackedInstr ir false ins insLen ctxt packNum oprSize dst result
  fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  !>ir insLen

let vsqrtpd ins insLen ctxt =
  let ir = !*ctxt
  let struct (dst, src) = getTwoOprs ins
  let oprSz = getOperationSize ins
  !<ir insLen
  match oprSz with
  | 128<rt> ->
    let dst2, dst1 = transOprToExpr128 ir false ins insLen ctxt dst
    let src2, src1 = transOprToExpr128 ir false ins insLen ctxt src
    !!ir (dst1 := AST.fsqrt src1)
    !!ir (dst2 := AST.fsqrt src2)
    fillZeroHigh128 ctxt dst ir
  | 256<rt> ->
    let dst4, dst3, dst2, dst1 = transOprToExpr256 ir false ins insLen ctxt dst
    let sr4, sr3, sr2, sr1 = transOprToExpr256 ir false ins insLen ctxt src
    !!ir (dst1 := AST.fsqrt sr1)
    !!ir (dst2 := AST.fsqrt sr2)
    !!ir (dst3 := AST.fsqrt sr3)
    !!ir (dst4 := AST.fsqrt sr4)
  | _ -> raise InvalidOperandSizeException
  fillZeroFromVLToMaxVL ctxt dst oprSz 512 ir
  !>ir insLen

let private vsqrts ins insLen ctxt sz =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2) = getThreeOprs ins
  let dst2, dst1 = transOprToExpr128 ir false ins insLen ctxt dst
  let src1B, src1A = transOprToExpr128 ir false ins insLen ctxt src1
  match sz with
  | 32<rt> ->
    let src2 = transOprToExpr32 ir false ins insLen ctxt src2
    !!ir (AST.xtlo 32<rt> dst1 := AST.fsqrt src2)
    !!ir (AST.xthi 32<rt> dst1 := AST.xthi 32<rt> src1A)
  | 64<rt> ->
    let src2 = transOprToExpr64 ir false ins insLen ctxt src2
    !!ir (dst1 := AST.fsqrt src2)
  | _ -> raise InvalidOperandSizeException
  !!ir (dst2 := src1B)
  fillZeroFromVLToMaxVL ctxt dst (getOperationSize ins) 512 ir
  !>ir insLen

let vsqrtss ins insLen ctxt =
  vsqrts ins insLen ctxt 32<rt>

let vsqrtsd ins insLen ctxt =
  vsqrts ins insLen ctxt 64<rt>

let vaddps ins insLen ctxt =
  buildPackedFPInstr ins insLen ctxt 32<rt> AST.fadd

let vaddpd ins insLen ctxt =
  buildPackedFPInstr ins insLen ctxt 64<rt> AST.fadd

let vaddss ins insLen ctxt =
  vexedScalarFPBinOp ins insLen ctxt 32<rt> AST.fadd

let vaddsd ins insLen ctxt =
  vexedScalarFPBinOp ins insLen ctxt 64<rt> AST.fadd

let vsubps ins insLen ctxt =
  buildPackedFPInstr ins insLen ctxt 32<rt> AST.fsub

let vsubpd ins insLen ctxt =
  buildPackedFPInstr ins insLen ctxt 64<rt> AST.fsub

let vsubss ins insLen ctxt =
  vexedScalarFPBinOp ins insLen ctxt 32<rt> AST.fsub

let vsubsd ins insLen ctxt =
  vexedScalarFPBinOp ins insLen ctxt 64<rt> AST.fsub

let vmulps ins insLen ctxt =
  buildPackedFPInstr ins insLen ctxt 32<rt> AST.fmul

let vmulpd ins insLen ctxt =
  buildPackedFPInstr ins insLen ctxt 64<rt> AST.fmul

let vmulss ins insLen ctxt =
  vexedScalarFPBinOp ins insLen ctxt 32<rt> AST.fmul

let vmulsd ins insLen ctxt =
  vexedScalarFPBinOp ins insLen ctxt 64<rt> AST.fmul

let vdivps ins insLen ctxt =
  buildPackedFPInstr ins insLen ctxt 32<rt> AST.fdiv

let vdivpd ins insLen ctxt =
  buildPackedFPInstr ins insLen ctxt 64<rt> AST.fdiv

let vdivss ins insLen ctxt =
  vexedScalarFPBinOp ins insLen ctxt 32<rt> AST.fdiv

let vdivsd ins insLen ctxt =
  vexedScalarFPBinOp ins insLen ctxt 64<rt> AST.fdiv

let vcvtsi2ss ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2) = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
  let src1B, src1A = transOprToExpr128 ir false ins insLen ctxt src1
  let src2 = transOprToExpr ir false ins insLen ctxt src2
  !!ir (AST.xtlo 32<rt> dstA := AST.cast CastKind.SIntToFloat 32<rt> src2)
  !!ir (AST.xthi 32<rt> dstA := AST.xthi 32<rt> src1A)
  !!ir (dstB := src1B)
  fillZeroFromVLToMaxVL ctxt dst (getOperationSize ins) 512 ir
  !>ir insLen

let vcvtsi2sd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2) = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
  let src1B, _src1A = transOprToExpr128 ir false ins insLen ctxt src1
  let src2 = transOprToExpr ir false ins insLen ctxt src2
  !!ir (dstA := AST.cast CastKind.SIntToFloat 64<rt> src2)
  !!ir (dstB := src1B)
  fillZeroFromVLToMaxVL ctxt dst (getOperationSize ins) 512 ir
  !>ir insLen

let vcvtsd2ss ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2) = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
  let src1B, src1A = transOprToExpr128 ir false ins insLen ctxt src1
  let src2 = transOprToExpr64 ir false ins insLen ctxt src2
  !!ir (AST.xtlo 32<rt> dstA := AST.cast CastKind.FloatCast 32<rt> src2)
  !!ir (AST.xthi 32<rt> dstA := AST.xthi 32<rt> src1A)
  !!ir (dstB := src1B)
  fillZeroFromVLToMaxVL ctxt dst (getOperationSize ins) 512 ir
  !>ir insLen

let vcvtss2sd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2) = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
  let src1B, _src1A = transOprToExpr128 ir false ins insLen ctxt src1
  let src2 = transOprToExpr32 ir false ins insLen ctxt src2
  !!ir (dstA := AST.cast CastKind.FloatCast 64<rt> src2)
  !!ir (dstB := src1B)
  fillZeroFromVLToMaxVL ctxt dst (getOperationSize ins) 512 ir
  !>ir insLen

let vmovd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let oprSize = getOperationSize ins
  match oprSize with
  | 32<rt> ->
    let dst = transOprToExpr ir false ins insLen ctxt dst
    let _, srcA = transOprToExpr128 ir false ins insLen ctxt src
    !!ir (dstAssign oprSize dst (AST.xtlo oprSize srcA))
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
    let src = transOprToExpr ir false ins insLen ctxt src
    !!ir (dstA := AST.zext 64<rt> src)
    !!ir (dstB := AST.num0 64<rt>)
    fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let vmovq ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let oprSize = getOperationSize ins
  let n0 = AST.num0 64<rt>
  match dst, src with
  | OprReg _, OprMem _ ->
    let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
    let src = transOprToExpr ir false ins insLen ctxt src
    !!ir (dstA := src)
    !!ir (dstB := n0)
    fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  | OprMem _, OprReg _ ->
    let dst = transOprToExpr ir false ins insLen ctxt dst
    let _, srcA = transOprToExpr128 ir false ins insLen ctxt src
    !!ir (dst := srcA)
  | OprReg r1, OprReg r2 ->
    match Register.getKind r1, Register.getKind r2 with
    | Register.Kind.XMM, Register.Kind.GP ->
      let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
      let src = transOprToExpr ir false ins insLen ctxt src
      !!ir (dstA := src)
      !!ir (dstB := n0)
      fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
    | Register.Kind.GP, Register.Kind.XMM ->
      let dst = transOprToExpr ir false ins insLen ctxt dst
      let _, srcA = transOprToExpr128 ir false ins insLen ctxt src
      !!ir (dst := srcA)
    | _ -> (* XMM, XMM *)
      let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
      let _, srcA = transOprToExpr128 ir false ins insLen ctxt src
      !!ir (dstA := srcA)
      !!ir (dstB := n0)
      fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  | _ -> raise InvalidOperandException
  !>ir insLen

let private buildVectorMove ins insLen ctxt packSz =
  let ir = !*ctxt
  !<ir insLen
  let oprSz = getOperationSize ins
  let isAVX512 = haveEVEXPrx ins.VEXInfo
  let packSz, packNum =
    if isAVX512 then packSz, 64<rt> / packSz else 64<rt>, 64<rt> / 64<rt>
  let struct (dst, src) = getTwoOprs ins
  let src = transOprToArr ir false ins insLen ctxt packSz packNum oprSz src
  let result =
    if isAVX512 then
      let eDst = transOprToArr ir false ins insLen ctxt packSz packNum oprSz dst
      let ePrx = getEVEXPrx ins.VEXInfo
      let k = !.ctxt (ePrx.AAA |> int |> Register.opmask)
      makeAssignWithMask ir ePrx k oprSz packSz eDst src (isMemOpr dst)
    else src
  assignPackedInstr ir false ins insLen ctxt packNum oprSz dst result
  fillZeroFromVLToMaxVL ctxt dst oprSz 512 ir
  !>ir insLen

let vmovapd ins insLen ctxt = buildVectorMove ins insLen ctxt 64<rt>
let vmovaps ins insLen ctxt = buildVectorMove ins insLen ctxt 32<rt>

let private buildVectorMoveAVX512 ins insLen ctxt packSz =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / packSz
  let struct (dst, src) = getTwoOprs ins
  let ePrx = getEVEXPrx ins.VEXInfo
  let k = !.ctxt (ePrx.AAA |> int |> Register.opmask)
  let eDst = transOprToArr ir false ins insLen ctxt packSz packNum oprSize dst
  let src = transOprToArr ir false ins insLen ctxt packSz packNum oprSize src
  let result =
    makeAssignWithMask ir ePrx k oprSize packSz eDst src (isMemOpr dst)
  assignPackedInstr ir false ins insLen ctxt packNum oprSize dst result
  fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  !>ir insLen

let vmovdqu ins insLen ctxt = buildVectorMove ins insLen ctxt 64<rt>

let vmovdqu16 ins insLen ctxt = buildVectorMoveAVX512 ins insLen ctxt 16<rt>
let vmovdqu64 ins insLen ctxt = buildVectorMoveAVX512 ins insLen ctxt 64<rt>

let vmovdqa ins insLen ctxt = buildVectorMove ins insLen ctxt 64<rt>

let vmovdqa64 ins insLen ctxt = buildVectorMoveAVX512 ins insLen ctxt 64<rt>

let vmovntdq ins insLen ctxt =
  buildMove ins insLen ctxt

let vmovups ins insLen ctxt = buildVectorMove ins insLen ctxt 32<rt>
let vmovupd ins insLen ctxt = buildVectorMove ins insLen ctxt 64<rt>

let vmovddup ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let oprSize = getOperationSize ins
  match oprSize with
  | 128<rt> ->
    let dst2, dst1 = transOprToExpr128 ir false ins insLen ctxt dst
    let src = transOprToExpr64 ir false ins insLen ctxt src
    !!ir (dst1 := src)
    !!ir (dst2 := src)
  | 256<rt> ->
    let dst4, dst3, dst2, dst1 = transOprToExpr256 ir false ins insLen ctxt dst
    let _src4, src3, _src2, src1 =
      transOprToExpr256 ir false ins insLen ctxt src
    !!ir (dst1 := src1)
    !!ir (dst2 := src1)
    !!ir (dst3 := src3)
    !!ir (dst4 := src3)
  | _ -> raise InvalidOperandSizeException
  fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  !>ir insLen

let vmovntps ins insLen ctxt =
  buildMove ins insLen ctxt

let vmovntpd ins insLen ctxt =
  buildMove ins insLen ctxt

let vmovhlps ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2) = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
  let src1B, _src1A = transOprToExpr128 ir false ins insLen ctxt src1
  let src2B, _src2A = transOprToExpr128 ir false ins insLen ctxt src2
  !!ir (dstA := src2B)
  !!ir (dstB := src1B)
  fillZeroFromVLToMaxVL ctxt dst (getOperationSize ins) 512 ir
  !>ir insLen

let vmovhpd (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  match ins.Operands with
  | TwoOperands (dst, src) ->
    if haveEVEXPrx ins.VEXInfo then ()
    else
      let dst = transOprToExpr64 ir false ins insLen ctxt dst
      let src2, _src1 = transOprToExpr128 ir false ins insLen ctxt src
      !!ir (dst := src2)
  | ThreeOperands (dst, src1, src2)->
    let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
    let _src1B, src1A = transOprToExpr128 ir false ins insLen ctxt src1
    let src2 = transOprToExpr64 ir false ins insLen ctxt src2
    !!ir (dstA := src1A)
    !!ir (dstB := src2)
    fillZeroFromVLToMaxVL ctxt dst (getOperationSize ins) 512 ir
  | _ -> raise InvalidOperandException
  !>ir insLen

let vmovlhps ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2) = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
  let _src1B, src1A = transOprToExpr128 ir true ins insLen ctxt src1
  let _src2B, src2A = transOprToExpr128 ir true ins insLen ctxt src2
  !!ir (dstA := src1A)
  !!ir (dstB := src2A)
  fillZeroFromVLToMaxVL ctxt dst (getOperationSize ins) 512 ir
  !>ir insLen

let vmovlpd (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  match ins.Operands with
  | TwoOperands (dst, src) ->
    let dst = transOprToExpr64 ir false ins insLen ctxt dst
    let _, srcA = transOprToExpr128 ir false ins insLen ctxt src
    !!ir (dst := srcA)
  | ThreeOperands (dst, src1, src2)->
    let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
    let src1B, _src1A = transOprToExpr128 ir false ins insLen ctxt src1
    let src2 = transOprToExpr ir false ins insLen ctxt src2
    !!ir (dstA := src2)
    !!ir (dstB := src1B)
    fillZeroFromVLToMaxVL ctxt dst (getOperationSize ins) 512 ir
  | _ -> raise InvalidOperandException
  !>ir insLen

let vmovmskpd ins insLen ctxt =
  let ir = !*ctxt
  let struct (dst, src) = getTwoOprs ins
  let mskpd r =
    match Register.getKind r with
    | Register.Kind.XMM -> movmskpd ins insLen ctxt
    | Register.Kind.YMM ->
      !<ir insLen
      let dst = transOprToExpr ir false ins insLen ctxt dst
      let dstSz = TypeCheck.typeOf dst
      let src4, src3, src2, src1 =
        transOprToExpr256 ir false ins insLen ctxt src
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
  let ir = !*ctxt
  let struct (dst, src) = getTwoOprs ins
  let mskpd r =
    match Register.getKind r with
    | Register.Kind.XMM -> movmskps ins insLen ctxt
    | Register.Kind.YMM ->
      !<ir insLen
      let oprSz = getOperationSize ins
      let dst = transOprToExpr ir false ins insLen ctxt dst
      let srcD, srcC, srcB, srcA =
        transOprToExpr256 ir false ins insLen ctxt src
      let b0 = (srcA >> (numI32 31 64<rt>) .& (numI32 0b1 64<rt>))
      let b1 = (srcA >> (numI32 62 64<rt>) .& (numI32 0b10 64<rt>))
      let b2 = (srcB >> (numI32 29 64<rt>) .& (numI32 0b100 64<rt>))
      let b3 = (srcB >> (numI32 60 64<rt>) .& (numI32 0b1000 64<rt>))
      let b4 = (srcC >> (numI32 27 64<rt>) .& (numI32 0b10000 64<rt>))
      let b5 = (srcC >> (numI32 58 64<rt>) .& (numI32 0b100000 64<rt>))
      let b6 = (srcD >> (numI32 25 64<rt>) .& (numI32 0b1000000 64<rt>))
      let b7 = (srcD >> (numI32 56 64<rt>) .& (numI32 0b10000000 64<rt>))
      !!ir (dstAssign oprSz dst (b7 .| b6 .| b5 .| b4 .| b3 .| b2 .| b1 .| b0))
      !>ir insLen
    | _ -> raise InvalidOperandException
  match src with
  | OprReg r -> mskpd r
  | _ -> raise InvalidOperandSizeException

let vmovsd (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  match ins.Operands with
  | TwoOperands (OprMem _, _) -> movsd ins insLen ctxt
  | TwoOperands (OprReg _ as dst, src) ->
    let dst2, dst1 = transOprToExpr128 ir false ins insLen ctxt dst
    let src = transOprToExpr64 ir false ins insLen ctxt src
    !!ir (dst1 := src)
    !!ir (dst2 := AST.num0 64<rt>)
    fillZeroFromVLToMaxVL ctxt dst (getOperationSize ins) 512 ir
    !>ir insLen
  | ThreeOperands (dst, src1, src2)->
    let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
    let src1B, _src1A = transOprToExpr128 ir false ins insLen ctxt src1
    let _src2B, src2A = transOprToExpr128 ir false ins insLen ctxt src2
    !!ir (dstA := src2A)
    !!ir (dstB := src1B)
    fillZeroFromVLToMaxVL ctxt dst (getOperationSize ins) 512 ir
    !>ir insLen
  | _ -> raise InvalidOperandException

let vmovshdup ins insLen ctxt =
  let ir = !*ctxt
  let struct (dst, src) = getTwoOprs ins
  !<ir insLen
  let oprSize = getOperationSize ins
  match oprSize with
  | 128<rt> ->
    let dst2, dst1 = transOprToExpr128 ir false ins insLen ctxt dst
    let src2, src1 = transOprToExpr128 ir false ins insLen ctxt src
    !!ir (AST.xtlo 32<rt> dst1 := AST.xthi 32<rt> src1)
    !!ir (AST.xthi 32<rt> dst1 := AST.xthi 32<rt> src1)
    !!ir (AST.xtlo 32<rt> dst2 := AST.xthi 32<rt> src2)
    !!ir (AST.xthi 32<rt> dst2 := AST.xthi 32<rt> src2)
  | 256<rt> ->
    let dst4, dst3, dst2, dst1 = transOprToExpr256 ir false ins insLen ctxt dst
    let src4, src3, src2, src1 = transOprToExpr256 ir false ins insLen ctxt src
    !!ir (AST.xtlo 32<rt> dst1 := AST.xthi 32<rt> src1)
    !!ir (AST.xthi 32<rt> dst1 := AST.xthi 32<rt> src1)
    !!ir (AST.xtlo 32<rt> dst2 := AST.xthi 32<rt> src2)
    !!ir (AST.xthi 32<rt> dst2 := AST.xthi 32<rt> src2)
    !!ir (AST.xtlo 32<rt> dst3 := AST.xthi 32<rt> src3)
    !!ir (AST.xthi 32<rt> dst3 := AST.xthi 32<rt> src3)
    !!ir (AST.xtlo 32<rt> dst4 := AST.xthi 32<rt> src4)
    !!ir (AST.xthi 32<rt> dst4 := AST.xthi 32<rt> src4)
  | _ -> raise InvalidOperandSizeException
  fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  !>ir insLen

let vmovsldup ins insLen ctxt =
  let ir = !*ctxt
  let struct (dst, src) = getTwoOprs ins
  !<ir insLen
  let oprSize = getOperationSize ins
  match oprSize with
  | 128<rt> ->
    let dst2, dst1 = transOprToExpr128 ir false ins insLen ctxt dst
    let src2, src1 = transOprToExpr128 ir false ins insLen ctxt src
    !!ir (AST.xtlo 32<rt> dst1 := AST.xtlo 32<rt> src1)
    !!ir (AST.xthi 32<rt> dst1 := AST.xtlo 32<rt> src1)
    !!ir (AST.xtlo 32<rt> dst2 := AST.xtlo 32<rt> src2)
    !!ir (AST.xthi 32<rt> dst2 := AST.xtlo 32<rt> src2)
  | 256<rt> ->
    let dst4, dst3, dst2, dst1 = transOprToExpr256 ir false ins insLen ctxt dst
    let src4, src3, src2, src1 = transOprToExpr256 ir false ins insLen ctxt src
    !!ir (AST.xtlo 32<rt> dst1 := AST.xtlo 32<rt> src1)
    !!ir (AST.xthi 32<rt> dst1 := AST.xtlo 32<rt> src1)
    !!ir (AST.xtlo 32<rt> dst2 := AST.xtlo 32<rt> src2)
    !!ir (AST.xthi 32<rt> dst2 := AST.xtlo 32<rt> src2)
    !!ir (AST.xtlo 32<rt> dst3 := AST.xtlo 32<rt> src3)
    !!ir (AST.xthi 32<rt> dst3 := AST.xtlo 32<rt> src3)
    !!ir (AST.xtlo 32<rt> dst4 := AST.xtlo 32<rt> src4)
    !!ir (AST.xthi 32<rt> dst4 := AST.xtlo 32<rt> src4)
  | _ -> raise InvalidOperandSizeException
  fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  !>ir insLen

let vmovss (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  match ins.Operands with
  | TwoOperands (OprMem _, _) -> movss ins insLen ctxt
  | TwoOperands (OprReg _ as dst, src) ->
    let dst2, dst1 = transOprToExpr128 ir false ins insLen ctxt dst
    let src = transOprToExpr32 ir false ins insLen ctxt src
    !!ir (AST.xtlo 32<rt> dst1 := src)
    !!ir (AST.xthi 32<rt> dst1 := AST.num0 32<rt>)
    !!ir (dst2 := AST.num0 64<rt>)
    fillZeroFromVLToMaxVL ctxt dst (getOperationSize ins) 512 ir
    !>ir insLen
  | ThreeOperands (dst, src1, src2)->
    let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
    let src1B, src1A = transOprToExpr128 ir false ins insLen ctxt src1
    let _src2B, src2A = transOprToExpr128 ir false ins insLen ctxt src2
    !!ir (AST.xtlo 32<rt> dstA := AST.xtlo 32<rt> src2A)
    !!ir (AST.xthi 32<rt> dstA := AST.xthi 32<rt> src1A)
    !!ir (dstB := src1B)
    fillZeroFromVLToMaxVL ctxt dst (getOperationSize ins) 512 ir
    !>ir insLen
  | _ -> raise InvalidOperandException

let vandps ins insLen ctxt =
  buildPackedFPInstr ins insLen ctxt 32<rt> (.&)

let vandpd ins insLen ctxt =
  buildPackedFPInstr ins insLen ctxt 64<rt> (.&)

let private andnpdOp e1 e2 = (AST.not e1) .& e2

let vandnps ins insLen ctxt =
  buildPackedFPInstr ins insLen ctxt 32<rt> andnpdOp

let vandnpd ins insLen ctxt =
  buildPackedFPInstr ins insLen ctxt 64<rt> andnpdOp

let vorps ins insLen ctxt =
  buildPackedFPInstr ins insLen ctxt 32<rt> (.|)

let vorpd ins insLen ctxt =
  buildPackedFPInstr ins insLen ctxt 64<rt> (.|)

let vshufi32x4 ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let packSz = 32<rt>
  let packNum = 64<rt> / packSz
  let struct (dst, src1, src2, imm) = getFourOprs ins
  let isSrc2Mem =
    match src2 with
    | OprMem _ -> true
    | _ -> false
  let src1 = transOprToArr ir false ins insLen ctxt packSz packNum oprSize src1
  let src2 = transOprToArr ir false ins insLen ctxt packSz packNum oprSize src2
  let imm8 = getImmValue imm
  let ePrx = getEVEXPrx ins.VEXInfo
  let k = !.ctxt (ePrx.AAA |> int |> Register.opmask)
  let tmpSrc2 = Array.init (oprSize / packSz) (fun _ -> !+ir 32<rt>)
  if isSrc2Mem && ePrx.B = 1uy then
    let tSrc2 = !+ir 32<rt>
    !!ir (tSrc2 := Array.head src2)
    Array.iter (fun e -> !!ir (e := tSrc2)) tmpSrc2
  else Array.iter2 (fun e1 e2 -> !!ir (e1 := e2)) tmpSrc2 src2
  match oprSize with
  | 256<rt> ->
    let halfPNum = oprSize / packSz / 2
    let orgDst =
      transOprToArr ir false ins insLen ctxt packSz packNum oprSize dst
    let tDstA = Array.init halfPNum (fun _ -> !+ir packSz)
    let tDstB = Array.init halfPNum (fun _ -> !+ir packSz)
    let imm0 (* imm8[0] *) = imm8 &&& 0b1L |> int
    let imm1 (* imm8[1] *) = (imm8 >>> 1) &&& 0b1L |> int
    Array.iteri (fun idx e -> !!ir (e := src1[ (imm0 * halfPNum) + idx ])) tDstA
    Array.iteri (fun idx e -> !!ir (e := src2[ (imm1 * halfPNum) + idx ])) tDstB
    let tDst = Array.append tDstA tDstB
    let result = makeAssignWithMask ir ePrx k oprSize packSz orgDst tDst false
    assignPackedInstr ir false ins insLen ctxt packNum oprSize dst result
  | 512<rt> ->
    let pNum = oprSize / packSz / 4
    let orgDst =
      transOprToArr ir false ins insLen ctxt packSz packNum oprSize dst
    let tDstA = Array.init pNum (fun _ -> !+ir packSz)
    let tDstB = Array.init pNum (fun _ -> !+ir packSz)
    let tDstC = Array.init pNum (fun _ -> !+ir packSz)
    let tDstD = Array.init pNum (fun _ -> !+ir packSz)
    let ctrl0 = (imm8 >>> 0) &&& 0b11L |> int
    let ctrl1 = (imm8 >>> 2) &&& 0b11L |> int
    let ctrl2 = (imm8 >>> 4) &&& 0b11L |> int
    let ctrl3 = (imm8 >>> 6) &&& 0b11L |> int
    Array.iteri (fun idx e -> !!ir (e := src1[ (ctrl0 * pNum) + idx ])) tDstA
    Array.iteri (fun idx e -> !!ir (e := src1[ (ctrl1 * pNum) + idx ])) tDstB
    Array.iteri (fun idx e -> !!ir (e := tmpSrc2[ (ctrl2 * pNum) + idx ])) tDstC
    Array.iteri (fun idx e -> !!ir (e := tmpSrc2[ (ctrl3 * pNum) + idx ])) tDstD
    let tDst = Array.concat [| tDstA; tDstB; tDstC; tDstD |]
    let result = makeAssignWithMask ir ePrx k oprSize packSz orgDst tDst false
    assignPackedInstr ir false ins insLen ctxt packNum oprSize dst result
  | _ -> raise InvalidOperandException
  fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
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
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2, imm) = getFourOprs ins
  let imm = transOprToExpr ir false ins insLen ctxt imm
  let oprSize = getOperationSize ins
  match oprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
    let sr1B, sr1A = transOprToExpr128 ir true ins insLen ctxt src1
    let sr2B, sr2A = transOprToExpr128 ir true ins insLen ctxt src2
    doShuf ir (makeShufCond imm 0) (AST.xtlo 32<rt> dstA) sr1A sr1B
    doShuf ir (makeShufCond imm 2) (AST.xthi 32<rt> dstA) sr1A sr1B
    doShuf ir (makeShufCond imm 4) (AST.xtlo 32<rt> dstB) sr2A sr2B
    doShuf ir (makeShufCond imm 6) (AST.xthi 32<rt> dstB) sr2A sr2B
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ir false ins insLen ctxt dst
    let sr1D, sr1C, sr1B, sr1A = transOprToExpr256 ir true ins insLen ctxt src1
    let sr2D, sr2C, sr2B, sr2A = transOprToExpr256 ir true ins insLen ctxt src2
    doShuf ir (makeShufCond imm 0) (AST.xtlo 32<rt> dstA) sr1A sr1B
    doShuf ir (makeShufCond imm 2) (AST.xthi 32<rt> dstA) sr1A sr1B
    doShuf ir (makeShufCond imm 4) (AST.xtlo 32<rt> dstB) sr2A sr2B
    doShuf ir (makeShufCond imm 6) (AST.xthi 32<rt> dstB) sr2A sr2B
    doShuf ir (makeShufCond imm 0) (AST.xtlo 32<rt> dstC) sr1C sr1D
    doShuf ir (makeShufCond imm 2) (AST.xthi 32<rt> dstC) sr1C sr1D
    doShuf ir (makeShufCond imm 4) (AST.xtlo 32<rt> dstD) sr2C sr2D
    doShuf ir (makeShufCond imm 6) (AST.xthi 32<rt> dstD) sr2C sr2D
  | _ -> raise InvalidOperandSizeException
  fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  !>ir insLen

let vshufpd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2, imm) = getFourOprs ins
  let imm = transOprToExpr ir false ins insLen ctxt imm
  let cond1 = AST.xtlo 1<rt> imm
  let cond2 = AST.extract imm 1<rt> 1
  let cond3 = AST.extract imm 1<rt> 2
  let cond4 = AST.extract imm 1<rt> 3
  let oprSize = getOperationSize ins
  match oprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
    let src1B, src1A = transOprToExpr128 ir true ins insLen ctxt src1
    let src2B, src2A = transOprToExpr128 ir true ins insLen ctxt src2
    !!ir (dstA := AST.ite cond1 src1B src1A)
    !!ir (dstB := AST.ite cond2 src2B src2A)
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ir false ins insLen ctxt dst
    let sr1D, sr1C, sr1B, sr1A = transOprToExpr256 ir true ins insLen ctxt src1
    let sr2D, sr2C, sr2B, sr2A = transOprToExpr256 ir true ins insLen ctxt src2
    !!ir (dstA := AST.ite cond1 sr1B sr1A)
    !!ir (dstB := AST.ite cond2 sr2B sr2A)
    !!ir (dstC := AST.ite cond3 sr1D sr1C)
    !!ir (dstD := AST.ite cond4 sr2D sr2C)
  | _ -> raise InvalidOperandSizeException
  fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  !>ir insLen

let vunpckhps ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2) = getThreeOprs ins
  let oprSize = getOperationSize ins
  match oprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
    let src1B, _src1A = transOprToExpr128 ir false ins insLen ctxt src1
    let src2B, _src2A = transOprToExpr128 ir false ins insLen ctxt src2
    !!ir (AST.xtlo 32<rt> dstA := AST.xtlo 32<rt> src1B)
    !!ir (AST.xthi 32<rt> dstA := AST.xtlo 32<rt> src2B)
    !!ir (AST.xtlo 32<rt> dstB := AST.xthi 32<rt> src1B)
    !!ir (AST.xthi 32<rt> dstB := AST.xthi 32<rt> src2B)
    fillZeroHigh128 ctxt dst ir
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ir false ins insLen ctxt dst
    let sr1D, _, sr1B, _ = transOprToExpr256 ir false ins insLen ctxt src1
    let sr2D, _, sr2B, _ = transOprToExpr256 ir false ins insLen ctxt src2
    !!ir (AST.xtlo 32<rt> dstA := AST.xtlo 32<rt> sr1B)
    !!ir (AST.xthi 32<rt> dstA := AST.xtlo 32<rt> sr2B)
    !!ir (AST.xtlo 32<rt> dstB := AST.xthi 32<rt> sr1B)
    !!ir (AST.xthi 32<rt> dstB := AST.xthi 32<rt> sr2B)
    !!ir (AST.xtlo 32<rt> dstC := AST.xtlo 32<rt> sr1D)
    !!ir (AST.xthi 32<rt> dstC := AST.xtlo 32<rt> sr2D)
    !!ir (AST.xtlo 32<rt> dstD := AST.xthi 32<rt> sr1D)
    !!ir (AST.xthi 32<rt> dstD := AST.xthi 32<rt> sr2D)
  | _ -> raise InvalidOperandSizeException
  fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  !>ir insLen

let vunpckhpd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2) = getThreeOprs ins
  let oprSize = getOperationSize ins
  match oprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
    let src1B, _src1A = transOprToExpr128 ir false ins insLen ctxt src1
    let src2B, _src2A = transOprToExpr128 ir false ins insLen ctxt src2
    !!ir (dstA := src1B)
    !!ir (dstB := src2B)
    fillZeroHigh128 ctxt dst ir
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ir false ins insLen ctxt dst
    let sr1D, _, sr1B, _ = transOprToExpr256 ir false ins insLen ctxt src1
    let sr2D, _, sr2B, _ = transOprToExpr256 ir false ins insLen ctxt src2
    !!ir (dstA := sr1B)
    !!ir (dstB := sr2B)
    !!ir (dstC := sr1D)
    !!ir (dstD := sr2D)
  | _ -> raise InvalidOperandSizeException
  fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  !>ir insLen

let vunpcklps ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2) = getThreeOprs ins
  let oprSize = getOperationSize ins
  match oprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
    let _src1B, src1A = transOprToExpr128 ir true ins insLen ctxt src1
    let _src2B, src2A = transOprToExpr128 ir true ins insLen ctxt src2
    !!ir (AST.xtlo 32<rt> dstA := AST.xtlo 32<rt> src1A)
    !!ir (AST.xthi 32<rt> dstA := AST.xtlo 32<rt> src2A)
    !!ir (AST.xtlo 32<rt> dstB := AST.xthi 32<rt> src1A)
    !!ir (AST.xthi 32<rt> dstB := AST.xthi 32<rt> src2A)
    fillZeroHigh128 ctxt dst ir
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ir false ins insLen ctxt dst
    let _, src1C, _, src1A = transOprToExpr256 ir true ins insLen ctxt src1
    let _, src2C, _, src2A = transOprToExpr256 ir true ins insLen ctxt src2
    !!ir (AST.xtlo 32<rt> dstA := AST.xtlo 32<rt> src1A)
    !!ir (AST.xthi 32<rt> dstA := AST.xtlo 32<rt> src2A)
    !!ir (AST.xtlo 32<rt> dstB := AST.xthi 32<rt> src1A)
    !!ir (AST.xthi 32<rt> dstB := AST.xthi 32<rt> src2A)
    !!ir (AST.xtlo 32<rt> dstC := AST.xtlo 32<rt> src1C)
    !!ir (AST.xthi 32<rt> dstC := AST.xtlo 32<rt> src2C)
    !!ir (AST.xtlo 32<rt> dstD := AST.xthi 32<rt> src1C)
    !!ir (AST.xthi 32<rt> dstD := AST.xthi 32<rt> src2C)
  | _ -> raise InvalidOperandSizeException
  fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  !>ir insLen

let vunpcklpd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2) = getThreeOprs ins
  let oprSize = getOperationSize ins
  match oprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
    let _src1B, src1A = transOprToExpr128 ir true ins insLen ctxt src1
    let _src2B, src2A = transOprToExpr128 ir true ins insLen ctxt src2
    !!ir (dstA := src1A)
    !!ir (dstB := src2A)
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ir false ins insLen ctxt dst
    let _, src1C, _, src1A = transOprToExpr256 ir true ins insLen ctxt src1
    let _, src2C, _, src2A = transOprToExpr256 ir true ins insLen ctxt src2
    !!ir (dstA := src1A)
    !!ir (dstB := src2A)
    !!ir (dstC := src1C)
    !!ir (dstD := src2C)
  | _ -> raise InvalidOperandSizeException
  fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  !>ir insLen

let vxorps ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSz = getOperationSize ins
  let packSz = 32<rt>
  let packNum = 64<rt> / packSz
  let struct (dst, src1, src2) = getThreeOprs ins
  let eDst = transOprToArr ir false ins insLen ctxt packSz packNum oprSz dst
  let tSrc1 = transOprToArr ir false ins insLen ctxt packSz packNum oprSz src1
  let tSrc2 = transOprToArr ir false ins insLen ctxt packSz packNum oprSz src2
  let result =
    if haveEVEXPrx ins.VEXInfo then
      let isSrc2Mem = isMemOpr src2
      let ePrx = getEVEXPrx ins.VEXInfo
      let k = !.ctxt (ePrx.AAA |> int |> Register.opmask)
      makeAssignEVEX ir ePrx k oprSz packSz eDst tSrc1 tSrc2 (<+>) isSrc2Mem
    else Array.map2 (<+>) tSrc1 tSrc2
  assignPackedInstr ir false ins insLen ctxt packNum oprSz dst result
  fillZeroFromVLToMaxVL ctxt dst oprSz 512 ir
  !>ir insLen

let vxorpd ins insLen ctxt =
  buildPackedFPInstr ins insLen ctxt 64<rt> (<+>)

let vbroadcasti128 ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let dstD, dstC, dstB, dstA = transOprToExpr256 ir false ins insLen ctxt dst
  let srcB, srcA = transOprToExpr128 ir false ins insLen ctxt src
  !!ir (dstA := srcA)
  !!ir (dstB := srcB)
  !!ir (dstC := srcA)
  !!ir (dstD := srcB)
  fillZeroFromVLToMaxVL ctxt dst (getOperationSize ins) 512 ir
  !>ir insLen

let vbroadcastss ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let src = transOprToExpr32 ir false ins insLen ctxt src
  let tmp = !+ir 32<rt>
  let oprSize = getOperationSize ins
  match oprSize with
  | 128<rt> ->
    let dst2, dst1 = transOprToExpr128 ir false ins insLen ctxt dst
    !!ir (tmp := src)
    !!ir (AST.xtlo 32<rt> dst1 := tmp)
    !!ir (AST.xthi 32<rt> dst1 := tmp)
    !!ir (AST.xtlo 32<rt> dst2 := tmp)
    !!ir (AST.xthi 32<rt> dst2 := tmp)
    fillZeroHigh128 ctxt dst ir
  | 256<rt> ->
    let dst4, dst3, dst2, dst1 = transOprToExpr256 ir false ins insLen ctxt dst
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
  fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  !>ir insLen

let vextracti32x8 ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let packSz = 32<rt>
  let packNum = 64<rt> / packSz
  let allPackNum = oprSize / packSz
  let struct (dst, src, imm) = getThreeOprs ins
  let ePrx = getEVEXPrx ins.VEXInfo
  let k = !.ctxt (ePrx.AAA |> int |> Register.opmask)
  let eDst = transOprToArr ir false ins insLen ctxt packSz packNum oprSize dst
  let src =
    transOprToArr ir false ins insLen ctxt packSz packNum (oprSize * 2) src
  let imm0 = getImmValue imm &&& 0b1L |> int (* imm8[0] *)
  let tmpDst = Array.sub src (allPackNum * imm0) allPackNum
  let result =
    makeAssignWithMask ir ePrx k oprSize packSz eDst tmpDst (isMemOpr dst)
  assignPackedInstr ir false ins insLen ctxt packNum oprSize dst result
  fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  !>ir insLen

let vextracti128 ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src, imm) = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
  let srcD, srcC, srcB, srcA = transOprToExpr256 ir false ins insLen ctxt src
  let imm = transOprToExpr ir false ins insLen ctxt imm
  let cond = !+ir 1<rt>
  !!ir (cond := AST.xtlo 1<rt> imm)
  !!ir (dstA := AST.ite cond srcC srcA)
  !!ir (dstB := AST.ite cond srcD srcB)
  fillZeroFromVLToMaxVL ctxt dst (getOperationSize ins) 512 ir
  !>ir insLen

let vextracti64x4 ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src, imm) = getThreeOprs ins
  let ePrx = getEVEXPrx ins.VEXInfo
  let k = !.ctxt (ePrx.AAA |> int |> Register.opmask)
  let dstD, dstC, dstB, dstA = transOprToExpr256 ir false ins insLen ctxt dst
  let srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA =
    transOprToExpr512 ir false ins insLen ctxt src
  let imm0 = getImmValue imm &&& 0b1L (* imm8[0] *)
  let struct (tDstD, tDstC, tDstB, tDstA) = tmpVars4 ir 64<rt>
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
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2, imm) = getFourOprs ins
  let dstD, dstC, dstB, dstA = transOprToExpr256 ir false ins insLen ctxt dst
  let src1D, src1C, src1B, src1A =
    transOprToExpr256 ir false ins insLen ctxt src1
  let src2B, src2A = transOprToExpr128 ir false ins insLen ctxt src2
  let imm = transOprToExpr ir false ins insLen ctxt imm
  let cond = !+ir 1<rt>
  !!ir (cond := AST.xtlo 1<rt> imm)
  !!ir (dstA := AST.ite cond src1A src2A)
  !!ir (dstB := AST.ite cond src1B src2B)
  !!ir (dstC := AST.ite cond src2A src1C)
  !!ir (dstD := AST.ite cond src2B src1D)
  !>ir insLen

let vpaddb ins insLen ctxt =
  buildPackedInstr ins insLen ctxt true 8<rt> (opP (.+))

let vpmullw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt true 16<rt> MMXLifter.opPmullw

let vpaddd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSz = getOperationSize ins
  let packSz = 32<rt>
  let packNum = 64<rt> / packSz
  let struct (dst, src1, src2) = getThreeOprs ins
  let eDst = transOprToArr ir false ins insLen ctxt packSz packNum oprSz dst
  let tSrc1 = transOprToArr ir false ins insLen ctxt packSz packNum oprSz src1
  let tSrc2 = transOprToArr ir false ins insLen ctxt packSz packNum oprSz src2
  let result =
    if haveEVEXPrx ins.VEXInfo then
      let isSrc2Mem = isMemOpr src2
      let ePrx = getEVEXPrx ins.VEXInfo
      let k = !.ctxt (ePrx.AAA |> int |> Register.opmask)
      makeAssignEVEX ir ePrx k oprSz packSz eDst tSrc1 tSrc2 (.+) isSrc2Mem
    else Array.map2 (.+) tSrc1 tSrc2
  assignPackedInstr ir false ins insLen ctxt packNum oprSz dst result
  fillZeroFromVLToMaxVL ctxt dst oprSz 512 ir
  !>ir insLen

let vpaddq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt true 64<rt> (opP (.+))

let vpalignr ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSz = getOperationSize ins
  let packSz = 8<rt>
  let packNum = 64<rt> / packSz
  let struct (dst, src1, src2, imm) = getFourOprs ins
  let src1 = transOprToArr ir false ins insLen ctxt packSz packNum oprSz src1
  let src2 = transOprToArr ir false ins insLen ctxt packSz packNum oprSz src2
  let imm = getImmValue imm |> int
  let initRes = Array.init 16 (fun _ -> !+ir 8<rt>)
  Array.iter (fun e -> !!ir (e := AST.num0 8<rt>)) initRes
  let result =
    if imm >= 32 then
      match oprSz with
      | 128<rt> -> initRes
      | 256<rt> -> Array.append initRes initRes
      | _ -> raise InvalidOperandSizeException
    else
      let cnt = if imm < 16 then 16 else 32 - imm
      let zeroPad = Array.sub initRes 0 (16 - cnt)
      match oprSz with
      | 128<rt> ->
        Array.append (Array.sub (Array.append src2 src1) imm cnt) zeroPad
      | 256<rt> ->
        let src1L, src1H = Array.splitAt 16 src1
        let src2L, src2H = Array.splitAt 16 src2
        let srcL = Array.sub (Array.append src2L src1L) imm cnt
        let srcH = Array.sub (Array.append src2H src1H) imm cnt
        Array.concat [| srcL; zeroPad; srcH; zeroPad |]
      | _ -> raise InvalidOperandSizeException
  assignPackedInstr ir false ins insLen ctxt packNum oprSz dst result
  fillZeroFromVLToMaxVL ctxt dst oprSz 512 ir
  !>ir insLen

let vpand ins insLen ctxt =
  buildPackedInstr ins insLen ctxt true 64<rt> opPand

let vpandn ins insLen ctxt =
  buildPackedInstr ins insLen ctxt true 64<rt> opPandn

let vblendvpd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / 64<rt>
  let struct (dst, src1, src2, src3) = getFourOprs ins
  let src1 = transOprToArr ir false ins insLen ctxt 64<rt> packNum oprSize src1
  let src2 = transOprToArr ir false ins insLen ctxt 64<rt> packNum oprSize src2
  let src3 = transOprToArr ir false ins insLen ctxt 64<rt> packNum oprSize src3
  let result = packedVblend src2 src1 src3
  assignPackedInstr ir false ins insLen ctxt packNum oprSize dst result
  fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  !>ir insLen

let vblendvps ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / 32<rt>
  let struct (dst, src1, src2, src3) = getFourOprs ins
  let src1 = transOprToArr ir false ins insLen ctxt 32<rt> packNum oprSize src1
  let src2 = transOprToArr ir false ins insLen ctxt 32<rt> packNum oprSize src2
  let src3 = transOprToArr ir false ins insLen ctxt 32<rt> packNum oprSize src3
  let result = packedVblend src2 src1 src3
  assignPackedInstr ir false ins insLen ctxt packNum oprSize dst result
  fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  !>ir insLen

let vpblendd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / 32<rt>
  let struct (dst, src1, src2, imm) = getFourOprs ins
  let src1 = transOprToArr ir false ins insLen ctxt 32<rt> packNum oprSize src1
  let src2 = transOprToArr ir false ins insLen ctxt 32<rt> packNum oprSize src2
  let imm = transOprToExpr ir false ins insLen ctxt imm
  let result = packedBlend src2 src1 imm
  assignPackedInstr ir false ins insLen ctxt packNum oprSize dst result
  fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  !>ir insLen

let vpblendw ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / 16<rt>
  let struct (dst, src1, src2, imm) = getFourOprs ins
  let src1 = transOprToArr ir false ins insLen ctxt 16<rt> packNum oprSize src1
  let src2 = transOprToArr ir false ins insLen ctxt 16<rt> packNum oprSize src2
  let imm = transOprToExpr ir false ins insLen ctxt imm
  let result = packedBlend src2 src1 imm
  assignPackedInstr ir false ins insLen ctxt packNum oprSize dst result
  fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  !>ir insLen

let vpblendvb ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / 8<rt>
  let struct (dst, src1, src2, src3) = getFourOprs ins
  let src1 = transOprToArr ir false ins insLen ctxt 8<rt> packNum oprSize src1
  let src2 = transOprToArr ir false ins insLen ctxt 8<rt> packNum oprSize src2
  let src3 = transOprToArr ir false ins insLen ctxt 8<rt> packNum oprSize src3
  let result = packedVblend src2 src1 src3
  assignPackedInstr ir false ins insLen ctxt packNum oprSize dst result
  fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  !>ir insLen

let vpackusdw ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / 32<rt>
  let allPackNum = oprSize / 32<rt>
  let struct (dst, src1, src2) = getThreeOprs ins
  let src1 = transOprToArr ir false ins insLen ctxt 32<rt> packNum oprSize src1
  let src2 = transOprToArr ir false ins insLen ctxt 32<rt> packNum oprSize src2
  let src =
    match oprSize with
    | 128<rt> -> Array.append src1 src2
    | 256<rt> ->
      let loSrc1, hiSrc1 = Array.splitAt (allPackNum / 2) src1
      let loSrc2, hiSrc2 = Array.splitAt (allPackNum / 2) src2
      Array.concat [| loSrc1; loSrc2; hiSrc1; hiSrc2 |]
    | _ -> raise InvalidOperandSizeException
  let result = Array.map (packWithSaturation ir 32<rt>) src
  assignPackedInstr ir false ins insLen ctxt (packNum * 2) oprSize dst result
  fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  !>ir insLen

let private saturateSignedWordToUnsignedByte ir expr = (* FIXME: MMXLifter *)
  let tExpr = !+ir 16<rt>
  !!ir (tExpr := expr)
  let checkMin = AST.slt tExpr (numI32 0 16<rt>)
  let checkMax = AST.sgt tExpr (numI32 255 16<rt>)
  let minNum = numU32 0u 8<rt>
  let maxNum = numU32 0xffu 8<rt>
  AST.ite checkMin minNum (AST.ite checkMax maxNum (AST.xtlo 8<rt> tExpr))

let vpackuswb ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / 16<rt>
  let allPackNum = oprSize / 16<rt>
  let struct (dst, src1, src2) = getThreeOprs ins
  let src1 = transOprToArr ir false ins insLen ctxt 16<rt> packNum oprSize src1
  let src2 = transOprToArr ir false ins insLen ctxt 16<rt> packNum oprSize src2
  let src =
    match oprSize with
    | 128<rt> -> Array.append src1 src2
    | 256<rt> ->
      let loSrc1, hiSrc1 = Array.splitAt (allPackNum / 2) src1
      let loSrc2, hiSrc2 = Array.splitAt (allPackNum / 2) src2
      Array.concat [| loSrc1; loSrc2; hiSrc1; hiSrc2 |]
    | _ -> raise InvalidOperandSizeException
  let result = Array.map (saturateSignedWordToUnsignedByte ir) src
  assignPackedInstr ir false ins insLen ctxt (packNum * 2) oprSize dst result
  fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  !>ir insLen

let vpavgb ins insLen ctxt =
  buildPackedInstr ins insLen ctxt true 8<rt> SSELifter.opPavgb

let vpavgw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt true 16<rt> SSELifter.opPavgw

let vpbroadcast ins insLen ctxt packSz =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / packSz
  let allPackNum = oprSize / packSz
  let struct (dst, src) = getTwoOprs ins
  let eDst = transOprToArr ir false ins insLen ctxt packSz packNum oprSize dst
  let src =
    match src with
    | OprReg r ->
      match Register.getKind r with
      | Register.Kind.XMM ->
        transOprToExpr128 ir false ins insLen ctxt src |> snd
      | Register.Kind.GP -> transOprToExpr ir false ins insLen ctxt src
      | _ -> raise InvalidOperandException
    | OprMem _ -> transOprToExpr ir false ins insLen ctxt src
    | _ -> raise InvalidOperandException
    |> AST.xtlo packSz
  let temp = !+ir packSz
  !!ir (temp := src)
  let src = Array.init allPackNum (fun _ -> temp)
  let result =
    if haveEVEXPrx ins.VEXInfo then
      let ePrx = getEVEXPrx ins.VEXInfo
      let k = !.ctxt (ePrx.AAA |> int |> Register.opmask)
      makeAssignWithMask ir ePrx k oprSize packSz eDst src (isMemOpr dst)
    else src
  assignPackedInstr ir false ins insLen ctxt packNum oprSize dst result
  fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  !>ir insLen

let vpbroadcastb ins insLen ctxt = vpbroadcast ins insLen ctxt 8<rt>
let vpbroadcastd ins insLen ctxt = vpbroadcast ins insLen ctxt 32<rt>
let vpbroadcastw ins insLen ctxt = vpbroadcast ins insLen ctxt 16<rt>

let vpcmpeqb ins insLen ctxt =
  match getOperationSize ins with
  | 512<rt> -> GeneralLifter.nop insLen ctxt (* FIXME: #197 *)
  | _ -> buildPackedInstr ins insLen ctxt true 8<rt> opPcmpeqb

let vpcmpeqd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt true 32<rt> opPcmpeqd

let vpcmpeqq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt true 64<rt> SSELifter.opPcmpeqq

let vpcmpgtb ins insLen ctxt =
  buildPackedInstr ins insLen ctxt true 8<rt> opPcmpgtb

let vpinsrb ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2, count) = getFourOprs ins
  let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
  let src1B, src1A = transOprToExpr128 ir false ins insLen ctxt src1
  let src2 = transOprToExpr ir false ins insLen ctxt src2
  let sel = getImmValue count &&& 0b1111L (* COUNT[3:0] *)
  let mask = numI64 (0xFFL <<< ((int32 sel * 8) % 64)) 64<rt>
  let amount = sel * 8L
  let t = !+ir 64<rt>
  let expAmt = numI64 (amount % 64L) 64<rt>
  !!ir (t := ((AST.zext 64<rt> src2) << expAmt) .& mask)
  if amount < 64 then
    !!ir (dstA := (src1A .& (AST.not mask)) .| t)
    !!ir (dstB := src1B)
  else
    !!ir (dstA := src1A)
    !!ir (dstB := (src1B .& (AST.not mask)) .| t)
  fillZeroFromVLToMaxVL ctxt dst (getOperationSize ins) 512 ir
  !>ir insLen

let vperm2i128 ins insLen ctxt =
  let ir = !*ctxt
  let struct (dst, src1, src2, imm) = getFourOprs ins
  let dstD, dstC, dstB, dstA = transOprToExpr256 ir false ins insLen ctxt dst
  let src1D, src1C, src1B, src1A =
    transOprToExpr256 ir false ins insLen ctxt src1
  let src2D, src2C, src2B, src2A =
    transOprToExpr256 ir false ins insLen ctxt src2
  let imm = getImmValue imm
  let struct (tDstA, tDstB, tDstC, tDstD) = tmpVars4 ir 64<rt>
  !<ir insLen
  let cond count = (imm >>> count) &&& 0b11L
  let imm0 (* imm8[3] *) = (imm >>> 3) &&& 0b1L
  let imm1 (* imm8[7] *) = (imm >>> 7) &&& 0b1L
  let getSrc cond =
    match cond with
    | 0L -> src1A, src1B
    | 1L -> src1C, src1D
    | 2L -> src2A, src2B
    | _ -> src2C, src2D
  let src1, src2 = getSrc (cond 0)
  !!ir (tDstA := src1)
  !!ir (tDstB := src2)
  let src1, src2 = getSrc (cond 4)
  !!ir (tDstC := src1)
  !!ir (tDstD := src2)
  !!ir (dstA := if imm0 = 1L then AST.num0 64<rt> else tDstA)
  !!ir (dstB := if imm0 = 1L then AST.num0 64<rt> else tDstB)
  !!ir (dstC := if imm1 = 1L then AST.num0 64<rt> else tDstC)
  !!ir (dstD := if imm1 = 1L then AST.num0 64<rt> else tDstD)
  !>ir insLen

let private getSrc cond dst e0 e1 e2 e3 e4 e5 e6 e7 ir =
  !!ir (dst := AST.ite (cond == AST.num0 8<rt>) e0
              (AST.ite (cond == AST.num1 8<rt>) e1
              (AST.ite (cond == numI32 2 8<rt>) e2
              (AST.ite (cond == numI32 3 8<rt>) e3
              (AST.ite (cond == numI32 4 8<rt>) e4
              (AST.ite (cond == numI32 5 8<rt>) e5
              (AST.ite (cond == numI32 6 8<rt>) e6 e7)))))))

let vpermd ins insLen ctxt =
  let ir = !*ctxt
  let struct (dst, src1, src2) = getThreeOprs ins
  let dstD, dstC, dstB, dstA = transOprToExpr256 ir false ins insLen ctxt dst
  let src1D, src1C, src1B, src1A =
    transOprToExpr256 ir false ins insLen ctxt src1
  let src2D, src2C, src2B, src2A =
    transOprToExpr256 ir false ins insLen ctxt src2
  let struct (tmp1A, tmp2A, tmp1B, tmp2B) = tmpVars4 ir 32<rt>
  let struct (tmp1C, tmp2C, tmp1D, tmp2D) = tmpVars4 ir 32<rt>
  let xthi operand = AST.xthi 32<rt> operand
  let xtlo operand = AST.xtlo 32<rt> operand
  !<ir insLen
  !!ir (tmp1A := xtlo src2A)
  !!ir (tmp2A := xthi src2A)
  !!ir (tmp1B := xtlo src2B)
  !!ir (tmp2B := xthi src2B)
  !!ir (tmp1C := xtlo src2C)
  !!ir (tmp2C := xthi src2C)
  !!ir (tmp1D := xtlo src2D)
  !!ir (tmp2D := xthi src2D)
  let tmp = !+ir 8<rt>
  let cond src pos =
    !!ir (tmp := AST.extract src 8<rt> pos .& numI32 0b00000111 8<rt>)
  cond src1A 0
  getSrc tmp (xtlo dstA) tmp1A tmp2A tmp1B tmp2B tmp1C tmp2C tmp1D tmp2D ir
  cond src1A 32
  getSrc tmp (xthi dstA) tmp1A tmp2A tmp1B tmp2B tmp1C tmp2C tmp1D tmp2D ir
  cond src1B 0
  getSrc tmp (xtlo dstB) tmp1A tmp2A tmp1B tmp2B tmp1C tmp2C tmp1D tmp2D ir
  cond src1B 32
  getSrc tmp (xthi dstB) tmp1A tmp2A tmp1B tmp2B tmp1C tmp2C tmp1D tmp2D ir
  cond src1C 0
  getSrc tmp (xtlo dstC) tmp1A tmp2A tmp1B tmp2B tmp1C tmp2C tmp1D tmp2D ir
  cond src1C 32
  getSrc tmp (xthi dstC) tmp1A tmp2A tmp1B tmp2B tmp1C tmp2C tmp1D tmp2D ir
  cond src1D 0
  getSrc tmp (xtlo dstD) tmp1A tmp2A tmp1B tmp2B tmp1C tmp2C tmp1D tmp2D ir
  cond src1D 32
  getSrc tmp (xthi dstD) tmp1A tmp2A tmp1B tmp2B tmp1C tmp2C tmp1D tmp2D ir
  !>ir insLen

let vpermq ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let struct (dst, src, imm) = getThreeOprs ins
  let src = transOprToArr ir true ins insLen ctxt 64<rt> 1 oprSize src
  let imm = getImmValue imm |> int
  let result = Array.init 4 (fun i -> src[ (imm >>> (i * 2)) &&& 0b11 ])
  assignPackedInstr ir false ins insLen ctxt 1 oprSize dst result
  fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  !>ir insLen

let vpinsrd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2, count) = getFourOprs ins
  let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
  let src1B, src1A = transOprToExpr128 ir false ins insLen ctxt src1
  let src2 = transOprToExpr ir false ins insLen ctxt src2
  let sel = getImmValue count &&& 0b11L (* COUNT[1:0] *)
  let mask = numI64 (0xFFFFFFFFL <<< ((int32 sel * 32) % 64)) 64<rt>
  let amount = sel * 32L
  let t = !+ir 64<rt>
  let expAmt = numI64 (amount % 64L) 64<rt>
  !!ir (t := ((AST.zext 64<rt> src2) << expAmt) .& mask)
  if amount < 64 then !!ir (dstA := (src1A .& (AST.not mask)) .| t)
  else !!ir (dstB := (src1B .& (AST.not mask)) .| t)
  fillZeroFromVLToMaxVL ctxt dst (getOperationSize ins) 512 ir
  !>ir insLen

let vpinsrq ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2, count) = getFourOprs ins
  let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
  let src1B, src1A = transOprToExpr128 ir false ins insLen ctxt src1
  let src2 = transOprToExpr ir false ins insLen ctxt src2
  let sel = getImmValue count &&& 0b1L (* COUNT[0] *)
  let mask = numI64 (0xFFFFFFFFFFFFFFFFL <<< ((int32 sel * 64) % 64)) 64<rt>
  let amount = sel * 64L
  let t = !+ir 64<rt>
  let expAmt = numI64 (amount % 64L) 64<rt>
  !!ir (t := ((AST.zext 64<rt> src2) << expAmt) .& mask)
  if amount < 64 then !!ir (dstA := (src1A .& (AST.not mask)) .| t)
  else !!ir (dstB := (src1B .& (AST.not mask)) .| t)
  fillZeroFromVLToMaxVL ctxt dst (getOperationSize ins) 512 ir
  !>ir insLen

let vpinsrw ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let packSz = 16<rt>
  let packNum = 64<rt> / packSz
  let struct (dst, src1, src2, imm8) = getFourOprs ins
  let src1 = transOprToArr ir true ins insLen ctxt packSz packNum 128<rt> src1
  let src2 = transOprToExpr ir false ins insLen ctxt src2 |> AST.xtlo packSz
  let tmps = Array.init 8 (fun _ -> !+ir packSz)
  let index = (getImmValue imm8 &&& 0b111) |> int
  Array.iter2 (fun t e -> !!ir (t := e)) tmps src1
  !!ir (tmps[index] := src2)
  assignPackedInstr ir false ins insLen ctxt packNum 128<rt> dst tmps
  fillZeroFromVLToMaxVL ctxt dst 128<rt> 512 ir
  !>ir insLen

let vpmaxsd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt true 32<rt> SSELifter.opPmaxs

let vpminub ins insLen ctxt =
  buildPackedInstr ins insLen ctxt true 8<rt> SSELifter.opPminu

let vpminud ins insLen ctxt =
  buildPackedInstr ins insLen ctxt true 32<rt> SSELifter.opPminu

let vpminsb ins insLen ctxt =
  buildPackedInstr ins insLen ctxt true 8<rt> SSELifter.opPmins

let vpminsd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt true 32<rt> SSELifter.opPmins

let vpmovx ins insLen ctxt srcSz dstSz isSignExt =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / dstSz
  let struct (dst, src) = getTwoOprs ins
  let ext = if isSignExt then AST.sext dstSz else AST.zext dstSz
  let inline extSrc num src =
    Array.init num (fun i -> AST.extract src srcSz (i * (int srcSz)))
  match src, oprSize with
  | OprMem (_, _, _, 128<rt>), 128<rt> | OprReg _, 128<rt> ->
    let sNum = oprSize / dstSz
    let _, srcA = transOprToExpr128 ir false ins insLen ctxt src
    let result = Array.map ext (extSrc sNum srcA)
    assignPackedInstr ir false ins insLen ctxt packNum oprSize dst result
    fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  | OprMem (_, _, _, 128<rt>), 256<rt> | OprReg _, 256<rt> ->
    let sNum = (oprSize / 2) / dstSz
    let src =
      let srcB, srcA = transOprToExpr128 ir false ins insLen ctxt src
      if (dstSz / srcSz) = 2 then
        Array.append (extSrc sNum srcA) (extSrc sNum srcB)
      else extSrc (sNum * 2) srcA
    let result = Array.map ext src
    assignPackedInstr ir false ins insLen ctxt packNum oprSize dst result
    fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  | OprMem (_, _, _, 256<rt>), 512<rt> | OprReg _, 512<rt> ->
    let sNum = (oprSize / 4) / dstSz
    let src =
      let srcD, srcC, srcB, srcA =
        transOprToExpr256 ir false ins insLen ctxt src
      if (dstSz / srcSz) = 2 then
        Array.concat
          [| (extSrc sNum srcA); (extSrc sNum srcB)
             (extSrc sNum srcC); (extSrc sNum srcD) |]
      else extSrc (sNum * 2) srcA
    let result = Array.map ext src
    assignPackedInstr ir false ins insLen ctxt packNum oprSize dst result

  | OprMem (_, _, _, memSz), _ ->
    let sNum = memSz / srcSz
    let src = transOprToExpr ir false ins insLen ctxt src
    let result = Array.map ext (extSrc sNum src)
    assignPackedInstr ir false ins insLen ctxt packNum oprSize dst result
    fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let vpmovd2m ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let packSize = 32<rt>
  let packNum = 64<rt> / packSize
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr ir false ins insLen ctxt dst
  let src = transOprToArr ir false ins insLen ctxt packSize packNum oprSize src
  let tmp = !+ir 16<rt>
  !!ir (tmp := AST.num0 16<rt>)
  let assignShf idx expr =
    !!ir (tmp := tmp .| ((AST.zext 16<rt> expr) << (numI32 idx 16<rt>)))
  Array.map (fun e -> AST.xthi 1<rt> e) src |> Array.iteri assignShf
  !!ir (dst := AST.zext 64<rt> tmp)
  !>ir insLen

let private opVpmulhuw _ = opPmul AST.xthi AST.zext 32<rt> 16<rt>

let vpmulhuw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt true 16<rt> opVpmulhuw

let private opVpmuludq _ =
  let low32 expr = expr .& numI64 0xffffffffL 64<rt>
  Array.map2 (fun e1 e2 -> low32 e1 .* low32 e2)

let vpmuludq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt true 64<rt> opVpmuludq

let private opVpmulld _ = opPmul AST.xtlo AST.sext 32<rt> 32<rt>

let vpmulld ins insLen ctxt =
  buildPackedInstr ins insLen ctxt true 32<rt> opVpmulld

let vpor ins insLen ctxt =
  match getOperationSize ins with
  | 512<rt> -> GeneralLifter.nop insLen ctxt
  | _ -> buildPackedInstr ins insLen ctxt true 64<rt> opPor

let vpshufb ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSz = getOperationSize ins
  let packSz = 8<rt>
  let packNum = 64<rt> / packSz
  let struct (dst, src1, src2) = getThreeOprs ins
  let nPackSz = numI32 (int packSz) packSz
  let n64 = numI32 64 packSz
  let src1 = transOprToArr ir true ins insLen ctxt 64<rt> 1 oprSz src1
  let src2 = transOprToArr ir true ins insLen ctxt packSz packNum oprSz src2
  let mask = numI32 0xF packSz
  let n0 = AST.num0 packSz
  let n1 = AST.num1 1<rt>
  let inline getSrcByIdx i idx =
    let shfAmt = (idx .& mask) .* nPackSz
    let index = AST.zext 64<rt> (shfAmt .% n64)
    let idxA = (i / (128<rt> / packSz)) * 2
    let idxB = idxA + 1
    ((AST.ite (shfAmt .< n64) src1[idxA] src1[idxB]) >> index)
    |> AST.xtlo packSz
  let inline shuffle i src2 =
    AST.ite (AST.xthi 1<rt> src2 == n1) n0 (getSrcByIdx i src2)
  let inline shuffleOfEVEX ePrx k i dst src2 =
    let cond = getVectorMoveCond ePrx k i
    let shuff = AST.ite (AST.xthi 1<rt> src2 == n1) n0 (getSrcByIdx i src2)
    AST.ite cond shuff (maskWithEPrx ePrx dst packSz)
  let result =
    if haveEVEXPrx ins.VEXInfo then
      let eDst = transOprToArr ir false ins insLen ctxt packSz packNum oprSz dst
      let ePrx = getEVEXPrx ins.VEXInfo
      let k = !.ctxt (ePrx.AAA |> int |> Register.opmask)
      Array.mapi2 (shuffleOfEVEX ePrx k) eDst src2
    else Array.mapi shuffle src2
  assignPackedInstr ir false ins insLen ctxt packNum oprSz dst result
  fillZeroFromVLToMaxVL ctxt dst oprSz 512 ir
  !>ir insLen

let vpshufd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let packSize = 32<rt>
  let packNum = 64<rt> / packSize
  let allPackNum = oprSize / packSize
  let struct (dst, src1, src2) = getThreeOprs ins
  let eDst = transOprToArr ir false ins insLen ctxt packSize packNum oprSize dst
  let src = transOprToArr ir false ins insLen ctxt packSize packNum oprSize src1
  let ord = getImmValue src2 |> int
  let inline getIdx i = (i / 4 * 4) + ((ord >>> ((i &&& 0x3) * 2)) &&& 0x3)
  let result =
    if haveEVEXPrx ins.VEXInfo then
      let ePrx = getEVEXPrx ins.VEXInfo
      let k = !.ctxt (ePrx.AAA |> int |> Register.opmask)
      let src =
        if (isMemOpr src1) && ePrx.B (* B *) = 1uy then
          Array.init allPackNum (fun _ -> Array.head src)
        else src
      let src = Array.init allPackNum (fun i -> src[ getIdx i ])
      makeAssignWithMask ir ePrx k oprSize packSize eDst src false
    else
      let getIdx i = (i / 4 * 4) + ((ord >>> ((i &&& 0x3) * 2)) &&& 0x3)
      Array.init allPackNum (fun i -> src[ getIdx i ])
  assignPackedInstr ir false ins insLen ctxt packNum oprSize dst result
  fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  !>ir insLen

let private opShiftVpackedDataLogical packSz shf src1 src2 =
  let count = src2 |> AST.zext 64<rt>
  let cond = AST.gt count (numI32 ((int packSz) - 1) 64<rt>)
  let shifted expr = AST.extract (shf (AST.zext 64<rt> expr) count) packSz 0
  Array.map (fun e -> AST.ite cond (AST.num0 packSz) (shifted e)) src1

let private vpsll ins insLen ctxt packSz =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / packSz
  let struct (dst, src1, src2) = getThreeOprs ins
  let src1 = transOprToArr ir true ins insLen ctxt packSz packNum oprSize src1
  let src2 =
    match src2 with
    | OprImm _ ->
      transOprToExpr ir false ins insLen ctxt src2 |> AST.xtlo packSz
    | _ -> transOprToExpr128 ir false ins insLen ctxt src2 |> snd
  let result = opShiftVpackedDataLogical packSz (<<) src1 src2
  assignPackedInstr ir false ins insLen ctxt packNum oprSize dst result
  fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  !>ir insLen

let vpslld ins insLen ctxt =
  match getOperationSize ins with
  | 512<rt> -> GeneralLifter.nop insLen ctxt
  | _ -> vpsll ins insLen ctxt 32<rt>

let vpsllq ins insLen ctxt = vpsll ins insLen ctxt 64<rt>

let vpslldq ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src, cnt) = getThreeOprs ins
  let cnt = getImmValue cnt
  let cnt = if cnt > 15L then 16L else cnt
  let amount = cnt * 8L
  let rightAmt = numI64 (64L - (amount % 64L)) 64<rt>
  let leftAmt = numI64 (amount % 64L) 64<rt>
  let oprSize = getOperationSize ins
  match oprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
    let srcB, srcA = transOprToExpr128 ir false ins insLen ctxt src
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
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ir false ins insLen ctxt dst
    let srcD, srcC, srcB, srcA = transOprToExpr256 ir false ins insLen ctxt src
    let struct (tSrcD, tSrcC, tSrcB, tSrcA) = tmpVars4 ir 64<rt>
    !!ir (tSrcA := srcA)
    !!ir (tSrcB := srcB)
    !!ir (tSrcC := srcC)
    !!ir (tSrcD := srcD)
    if amount < 64 then
      !!ir (dstA := tSrcA << leftAmt)
      !!ir (dstB := (tSrcB << leftAmt) .| (tSrcA >> rightAmt))
      !!ir (dstC := tSrcC << leftAmt)
      !!ir (dstD := (tSrcD << leftAmt) .| (tSrcC >> rightAmt))
    elif amount < 128 then
      !!ir (dstA := AST.num0 64<rt>)
      !!ir (dstB := tSrcA << leftAmt)
      !!ir (dstC := AST.num0 64<rt>)
      !!ir (dstD := tSrcC << leftAmt)
    else
      !!ir (dstA := AST.num0 64<rt>)
      !!ir (dstB := AST.num0 64<rt>)
      !!ir (dstC := AST.num0 64<rt>)
      !!ir (dstD := AST.num0 64<rt>)
  | _ -> raise InvalidOperandSizeException
  fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  !>ir insLen

let private shiftPackedDataRight ins insLen ctxt packSize shf =
  let ir = !*ctxt
  !<ir insLen
  let oprSz = getOperationSize ins
  let packNum = 64<rt> / packSize
  let struct (dst, src1, src2) = getThreeOprs ins
  let src1 = transOprToArr ir false ins insLen ctxt packSize packNum oprSz src1
  let src2 =
    match src2 with
    | OprImm _ -> transOprToExpr ir false ins insLen ctxt src2
    | _ -> transOprToExpr128 ir false ins insLen ctxt src2 |> snd
  let struct (tCnt, max) = tmpVars2 ir 64<rt>
  let cnt = !+ir packSize
  !!ir (max := numI32 (int packSize) 64<rt>)
  !!ir (tCnt := AST.xtlo 64<rt> src2)
  !!ir (tCnt := AST.ite (tCnt .> max .- AST.num1 64<rt>) max tCnt)
  !!ir (cnt := AST.xtlo packSize tCnt)
  let result = Array.map (fun e -> shf e cnt) src1
  assignPackedInstr ir false ins insLen ctxt packNum oprSz dst result
  fillZeroFromVLToMaxVL ctxt dst oprSz 512 ir
  !>ir insLen

let vpsrad ins insLen ctxt = shiftPackedDataRight ins insLen ctxt 32<rt> (?>>)
let vpsraw ins insLen ctxt = shiftPackedDataRight ins insLen ctxt 16<rt> (?>>)

let vpsravd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSz = getOperationSize ins
  let packSize = 32<rt>
  let packNum = 64<rt> / packSize
  let struct (dst, src1, src2) = getThreeOprs ins
  let src1 = transOprToArr ir false ins insLen ctxt packSize packNum oprSz src1
  let src2 = transOprToArr ir false ins insLen ctxt packSize packNum oprSz src2
  let struct (n0, n32, max) = tmpVars3 ir packSize
  !!ir (n0 := AST.num0 packSize)
  !!ir (n32 := numI32 32 packSize)
  !!ir (max := numI32 0xFFFFFFFF packSize)
  let fillSignBit e1 e2 =
    AST.ite (e2 .< n32) (e1 ?>> e2) (AST.ite (AST.xthi 1<rt> e1) max n0)
  let result = Array.map2 fillSignBit src1 src2
  assignPackedInstr ir false ins insLen ctxt packNum oprSz dst result
  fillZeroFromVLToMaxVL ctxt dst oprSz 512 ir
  !>ir insLen

let vpsrlq ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let packSz = 64<rt>
  let packNum = 64<rt> / packSz
  let struct (dst, src1, src2) = getThreeOprs ins
  let src1 = transOprToArr ir true ins insLen ctxt packSz packNum oprSize src1
  let src2 =
    match src2 with
    | OprImm _ ->
      transOprToExpr ir false ins insLen ctxt src2 |> AST.xtlo packSz
    | _ -> transOprToExpr128 ir false ins insLen ctxt src2 |> snd
  let result = opShiftVpackedDataLogical packSz (>>) src1 src2
  assignPackedInstr ir false ins insLen ctxt packNum oprSize dst result
  fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  !>ir insLen

let vpsrldq ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src, cnt) = getThreeOprs ins
  let cnt = getImmValue cnt
  let cnt = if cnt > 15L then 16L else cnt
  let amount = cnt * 8L
  let rightAmt = numI64 (amount % 64L) 64<rt>
  let leftAmt = numI64 (64L - (amount % 64L)) 64<rt>
  let oprSize = getOperationSize ins
  match oprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
    let srcB, srcA = transOprToExpr128 ir false ins insLen ctxt src
    let struct (tSrcB, tSrcA) = tmpVars2 ir 64<rt>
    !!ir (tSrcA := srcA)
    !!ir (tSrcB := srcB)
    let index = (int amount) / 64
    let src = [| tSrcA; tSrcB; AST.num0 64<rt>; AST.num0 64<rt> |]
    !!ir (dstA := (src[index + 1] << leftAmt) .| (src[index] >> rightAmt))
    !!ir (dstB := src[index + 1] >> rightAmt)
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ir false ins insLen ctxt dst
    let srcD, srcC, srcB, srcA = transOprToExpr256 ir false ins insLen ctxt src
    let struct (tSrcD, tSrcC, tSrcB, tSrcA) = tmpVars4 ir 64<rt>
    !!ir (tSrcA := srcA)
    !!ir (tSrcB := srcB)
    !!ir (tSrcC := srcC)
    !!ir (tSrcD := srcD)
    if amount < 64 then
      !!ir (dstA := (tSrcB << leftAmt) .| (tSrcA >> rightAmt))
      !!ir (dstB := tSrcB >> rightAmt)
      !!ir (dstC := (tSrcD << leftAmt) .| (tSrcC >> rightAmt))
      !!ir (dstD := tSrcD >> rightAmt)
    elif amount < 128 then
      !!ir (dstA := (tSrcB >> rightAmt))
      !!ir (dstB := AST.num0 64<rt>)
      !!ir (dstC := tSrcD >> rightAmt)
      !!ir (dstD := AST.num0 64<rt>)
    else
      !!ir (dstA := AST.num0 64<rt>)
      !!ir (dstB := AST.num0 64<rt>)
      !!ir (dstC := AST.num0 64<rt>)
      !!ir (dstD := AST.num0 64<rt>)
  | _ -> raise InvalidOperandSizeException
  fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir
  !>ir insLen

let vpsrld ins insLen ctxt = shiftPackedDataRight ins insLen ctxt 32<rt> (>>)
let vpsrlw ins insLen ctxt = shiftPackedDataRight ins insLen ctxt 16<rt> (>>)

let vpsubb ins insLen ctxt =
  buildPackedInstr ins insLen ctxt true 8<rt> (opP (.-))

let vpsubd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt true 32<rt> (opP (.-))

let vptest ins insLen ctxt =
  if getOperationSize ins = 128<rt> then SSELifter.ptest ins insLen ctxt
  else
    let ir = !*ctxt
    !<ir insLen
    let struct (src1, src2) = getTwoOprs ins
    let src1D, src1C, src1B, src1A =
      transOprToExpr256 ir false ins insLen ctxt src1
    let src2D, src2C, src2B, src2A =
      transOprToExpr256 ir false ins insLen ctxt src2
    let struct (t1, t2, t3, t4) = tmpVars4 ir 64<rt>
    let struct (t5, t6, t7, t8) = tmpVars4 ir 64<rt>
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
#if EMULATION
    ctxt.ConditionCodeOp <- BinLifter.ConditionCodeOp.EFlags
#endif
    !>ir insLen

let vpunpckhdq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt true 32<rt> opUnpackHighData

let vpunpckhqdq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt true 64<rt> opUnpackHighData

let vpunpckhwd ins insLen ctxt = unpackLowHighData ins insLen ctxt 16<rt> true
let vpunpcklwd ins insLen ctxt = unpackLowHighData ins insLen ctxt 16<rt> false

let vpunpckldq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt true 32<rt> opUnpackLowData

let vpunpcklqdq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt true 64<rt> opUnpackLowData

let vpxor ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2) = getThreeOprs ins
  let oprSize = getOperationSize ins
  match oprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
    let src1B, src1A = transOprToExpr128 ir false ins insLen ctxt src1
    let src2B, src2A = transOprToExpr128 ir false ins insLen ctxt src2
    !!ir (dstB := src1B <+> src2B)
    !!ir (dstA := src1A <+> src2A)
  | 256<rt> ->
    let dstD, dstC, dstB, dstA = transOprToExpr256 ir false ins insLen ctxt dst
    let src1D, src1C, src1B, src1A =
      transOprToExpr256 ir false ins insLen ctxt src1
    let src2D, src2C, src2B, src2A =
      transOprToExpr256 ir false ins insLen ctxt src2
    !!ir (dstD := src1D <+> src2D)
    !!ir (dstC := src1C <+> src2C)
    !!ir (dstB := src1B <+> src2B)
    !!ir (dstA := src1A <+> src2A)
  | _ -> raise InvalidOperandSizeException
  fillZeroFromVLToMaxVL ctxt dst 128<rt> 512 ir
  !>ir insLen

let vpxord ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSz = getOperationSize ins
  let packSz = 32<rt>
  let packNum = 64<rt> / packSz
  let struct (dst, src1, src2) = getThreeOprs ins
  let tDst = transOprToArr ir false ins insLen ctxt packSz packNum oprSz dst
  let tSrc1 = transOprToArr ir false ins insLen ctxt packSz packNum oprSz src1
  let tSrc2 = transOprToArr ir false ins insLen ctxt packSz packNum oprSz src2
  let result =
    if haveEVEXPrx ins.VEXInfo then
      let isSrc2Mem = isMemOpr src2
      let ePrx = getEVEXPrx ins.VEXInfo
      let k = !.ctxt (ePrx.AAA |> int |> Register.opmask)
      makeAssignEVEX ir ePrx k oprSz packSz tDst tSrc1 tSrc2 (<+>) isSrc2Mem
    else Array.map2 (<+>) tSrc1 tSrc2
  assignPackedInstr ir false ins insLen ctxt packNum oprSz dst result
  fillZeroFromVLToMaxVL ctxt dst oprSz 512 ir
  !>ir insLen

let vzeroupper ins insLen ctxt =
  let ir = !*ctxt
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
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src2, src3) = getThreeOprs ins
  let _dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
  let src2 = transOprToExpr64 ir false ins insLen ctxt src2
  let src3 = transOprToExpr64 ir false ins insLen ctxt src3
  let tmp = !+ir 64<rt>
  !!ir (tmp := AST.fmul dstA src3)
  !!ir (dstA := AST.fadd tmp src2)
  fillZeroFromVLToMaxVL ctxt dst 128<rt> 512 ir
  !>ir insLen

let vfmadd213sd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src2, src3) = getThreeOprs ins
  let _dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
  let src2 = transOprToExpr64 ir false ins insLen ctxt src2
  let src3 = transOprToExpr64 ir false ins insLen ctxt src3
  let tmp = !+ir 64<rt>
  !!ir (tmp := AST.fmul dstA src2)
  !!ir (dstA := AST.fadd tmp src3)
  fillZeroFromVLToMaxVL ctxt dst 128<rt> 512 ir
  !>ir insLen

let vfmadd231sd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src2, src3) = getThreeOprs ins
  let _dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
  let src2 = transOprToExpr64 ir false ins insLen ctxt src2
  let src3 = transOprToExpr64 ir false ins insLen ctxt src3
  let tmp = !+ir 64<rt>
  !!ir (tmp := AST.fmul src2 src3)
  !!ir (dstA := AST.fadd dstA tmp)
  fillZeroFromVLToMaxVL ctxt dst 128<rt> 512 ir
  !>ir insLen
