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

module internal B2R2.FrontEnd.Intel.AVXLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.Intel
open B2R2.FrontEnd.Intel.LiftingUtils
open B2R2.FrontEnd.Intel.MMXLifter
open B2R2.FrontEnd.Intel.SSELifter

let private haveEVEXPrx = function
  | Some v -> Option.isSome v.EVEXPrx
  | None -> false

let private getEVEXPrx = function
  | Some v -> match v.EVEXPrx with
              | Some ev -> ev
              | None -> Terminator.impossible ()
  | None -> Terminator.impossible ()

let private maskWithEPrx ePrx dst rt =
  match ePrx.Z with
  | Zeroing -> AST.num0 rt
  | Merging -> dst

let private getVectorMoveCond ePrx k idx =
  (* no write mask *)
  let noWritemask = if ePrx.AAA = 0uy then AST.num1 1<rt> else AST.num0 1<rt>
  AST.extract k 1<rt> idx .| noWritemask

let private makeAssignWithMask bld ePrx k oprSize packSz dst src isMem =
  let packNum = oprSize / packSz
  let tmp = Array.init packNum (fun _ -> tmpVar bld packSz)
  let mask idx dst src =
    let cond = getVectorMoveCond ePrx k idx
    let fallThrough = if isMem then dst else (maskWithEPrx ePrx dst packSz)
    AST.ite cond src fallThrough
  Array.mapi2 mask dst src |> Array.iter2 (fun e1 e2 -> bld <+ (e1 := e2)) tmp
  tmp

let private makeAssignEVEX bld ePrx k oprSz packSz dst src1 src2 opFn isMem =
  let src2A = Array.head src2 (* SRC2[31:0] *)
  let packNum = oprSz / packSz
  let tmp = Array.init packNum (fun _ -> tmpVar bld packSz)
  let mask idx src1 src2 =
    let cond = getVectorMoveCond ePrx k idx
    let tSrc =
      if isMem && ePrx.B (* B *) = 1uy then opFn src1 src2A else opFn src1 src2
    AST.ite cond tSrc (maskWithEPrx ePrx (Array.item idx dst) packSz)
  Array.mapi2 mask src1 src2 |> Array.iter2 (fun e1 e2 -> bld <+ (e1 := e2)) tmp
  tmp

let private buildPackedFPInstr ins insLen bld packSz opFn =
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / packSz
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let src1 = transOprToArr bld false ins insLen packSz packNum oprSize src1
  let src2 = transOprToArr bld false ins insLen packSz packNum oprSize src2
  let src = Array.map2 opFn src1 src2
  assignPackedInstr bld false ins insLen packNum oprSize dst src
  fillZeroFromVLToMaxVL bld dst oprSize 512
  bld --!> insLen

let private vexedScalarFPBinOp (ins: Instruction) insLen bld sz op =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (dst2, dst1) = transOprToExpr128 bld false ins insLen dst
  let struct (src1B, src1A) = transOprToExpr128 bld false ins insLen src1
  match sz with
  | 32<rt> ->
    let src2 = transOprToExpr32 bld false ins insLen src2
    bld <+ (AST.xtlo 32<rt> dst1 := op (AST.xtlo 32<rt> src1A) src2)
    bld <+ (AST.xthi 32<rt> dst1 := AST.xthi 32<rt> src1A)
  | 64<rt> ->
    let src2 = transOprToExpr64 bld false ins insLen src2
    bld <+ (dst1 := op src1A src2)
  | _ -> raise InvalidOperandSizeException
  bld <+ (dst2 := src1B)
  fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
  bld --!> insLen

let vsqrtps ins insLen bld =
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / 32<rt>
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let src = transOprToArr bld false ins insLen 32<rt> packNum oprSize src
  let result = Array.map (AST.unop UnOpType.FSQRT) src
  assignPackedInstr bld false ins insLen packNum oprSize dst result
  fillZeroFromVLToMaxVL bld dst oprSize 512
  bld --!> insLen

let vsqrtpd ins insLen bld =
  let struct (dst, src) = getTwoOprs ins
  let oprSz = getOperationSize ins
  bld <!-- (ins.Address, insLen)
  match oprSz with
  | 128<rt> ->
    let struct (dst2, dst1) = transOprToExpr128 bld false ins insLen dst
    let struct (src2, src1) = transOprToExpr128 bld false ins insLen src
    bld <+ (dst1 := AST.fsqrt src1)
    bld <+ (dst2 := AST.fsqrt src2)
    fillZeroHigh128 bld dst
  | 256<rt> ->
    let struct (dst4, dst3, dst2, dst1) =
      transOprToExpr256 bld false ins insLen dst
    let struct (sr4, sr3, sr2, sr1) =
      transOprToExpr256 bld false ins insLen src
    bld <+ (dst1 := AST.fsqrt sr1)
    bld <+ (dst2 := AST.fsqrt sr2)
    bld <+ (dst3 := AST.fsqrt sr3)
    bld <+ (dst4 := AST.fsqrt sr4)
  | _ -> raise InvalidOperandSizeException
  fillZeroFromVLToMaxVL bld dst oprSz 512
  bld --!> insLen

let private vsqrts (ins: Instruction) insLen bld sz =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (dst2, dst1) = transOprToExpr128 bld false ins insLen dst
  let struct (src1B, src1A) = transOprToExpr128 bld false ins insLen src1
  match sz with
  | 32<rt> ->
    let src2 = transOprToExpr32 bld false ins insLen src2
    bld <+ (AST.xtlo 32<rt> dst1 := AST.fsqrt src2)
    bld <+ (AST.xthi 32<rt> dst1 := AST.xthi 32<rt> src1A)
  | 64<rt> ->
    let src2 = transOprToExpr64 bld false ins insLen src2
    bld <+ (dst1 := AST.fsqrt src2)
  | _ -> raise InvalidOperandSizeException
  bld <+ (dst2 := src1B)
  fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
  bld --!> insLen

let vsqrtss ins insLen bld =
  vsqrts ins insLen bld 32<rt>

let vsqrtsd ins insLen bld =
  vsqrts ins insLen bld 64<rt>

let vaddps ins insLen bld =
  buildPackedFPInstr ins insLen bld 32<rt> AST.fadd

let vaddpd ins insLen bld =
  buildPackedFPInstr ins insLen bld 64<rt> AST.fadd

let vaddss ins insLen bld =
  vexedScalarFPBinOp ins insLen bld 32<rt> AST.fadd

let vaddsd ins insLen bld =
  vexedScalarFPBinOp ins insLen bld 64<rt> AST.fadd

let vsubps ins insLen bld =
  buildPackedFPInstr ins insLen bld 32<rt> AST.fsub

let vsubpd ins insLen bld =
  buildPackedFPInstr ins insLen bld 64<rt> AST.fsub

let vsubss ins insLen bld =
  vexedScalarFPBinOp ins insLen bld 32<rt> AST.fsub

let vsubsd ins insLen bld =
  vexedScalarFPBinOp ins insLen bld 64<rt> AST.fsub

let vmulps ins insLen bld =
  buildPackedFPInstr ins insLen bld 32<rt> AST.fmul

let vmulpd ins insLen bld =
  buildPackedFPInstr ins insLen bld 64<rt> AST.fmul

let vmulss ins insLen bld =
  vexedScalarFPBinOp ins insLen bld 32<rt> AST.fmul

let vmulsd ins insLen bld =
  vexedScalarFPBinOp ins insLen bld 64<rt> AST.fmul

let vdivps ins insLen bld =
  buildPackedFPInstr ins insLen bld 32<rt> AST.fdiv

let vdivpd ins insLen bld =
  buildPackedFPInstr ins insLen bld 64<rt> AST.fdiv

let vdivss ins insLen bld =
  vexedScalarFPBinOp ins insLen bld 32<rt> AST.fdiv

let vdivsd ins insLen bld =
  vexedScalarFPBinOp ins insLen bld 64<rt> AST.fdiv

let vcvtsi2ss (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
  let struct (src1B, src1A) = transOprToExpr128 bld false ins insLen src1
  let src2 = transOprToExpr bld false ins insLen src2
  bld <+ (AST.xtlo 32<rt> dstA := AST.cast CastKind.SIntToFloat 32<rt> src2)
  bld <+ (AST.xthi 32<rt> dstA := AST.xthi 32<rt> src1A)
  bld <+ (dstB := src1B)
  fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
  bld --!> insLen

let vcvtsi2sd (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
  let struct (src1B, _src1A) = transOprToExpr128 bld false ins insLen src1
  let src2 = transOprToExpr bld false ins insLen src2
  bld <+ (dstA := AST.cast CastKind.SIntToFloat 64<rt> src2)
  bld <+ (dstB := src1B)
  fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
  bld --!> insLen

let vcvtsd2ss (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
  let struct (src1B, src1A) = transOprToExpr128 bld false ins insLen src1
  let src2 = transOprToExpr64 bld false ins insLen src2
  bld <+ (AST.xtlo 32<rt> dstA := AST.cast CastKind.FloatCast 32<rt> src2)
  bld <+ (AST.xthi 32<rt> dstA := AST.xthi 32<rt> src1A)
  bld <+ (dstB := src1B)
  fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
  bld --!> insLen

let vcvtss2sd (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
  let struct (src1B, _src1A) = transOprToExpr128 bld false ins insLen src1
  let src2 = transOprToExpr32 bld false ins insLen src2
  bld <+ (dstA := AST.cast CastKind.FloatCast 64<rt> src2)
  bld <+ (dstB := src1B)
  fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
  bld --!> insLen

let vmovd (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let oprSize = getOperationSize ins
  match oprSize with
  | 32<rt> ->
    let dst = transOprToExpr bld false ins insLen dst
    let struct (_, srcA) = transOprToExpr128 bld false ins insLen src
    bld <+ (dstAssign oprSize dst (AST.xtlo oprSize srcA))
  | 128<rt> ->
    let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
    let src = transOprToExpr bld false ins insLen src
    bld <+ (dstA := AST.zext 64<rt> src)
    bld <+ (dstB := AST.num0 64<rt>)
    fillZeroFromVLToMaxVL bld dst oprSize 512
  | _ -> raise InvalidOperandSizeException
  bld --!> insLen

let vmovq (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let oprSize = getOperationSize ins
  let n0 = AST.num0 64<rt>
  match dst, src with
  | OprReg _, OprMem _ ->
    let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
    let src = transOprToExpr bld false ins insLen src
    bld <+ (dstA := src)
    bld <+ (dstB := n0)
    fillZeroFromVLToMaxVL bld dst oprSize 512
  | OprMem _, OprReg _ ->
    let dst = transOprToExpr bld false ins insLen dst
    let struct (_, srcA) = transOprToExpr128 bld false ins insLen src
    bld <+ (dst := srcA)
  | OprReg r1, OprReg r2 ->
    match Register.getKind r1, Register.getKind r2 with
    | Register.Kind.XMM, Register.Kind.GP ->
      let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
      let src = transOprToExpr bld false ins insLen src
      bld <+ (dstA := src)
      bld <+ (dstB := n0)
      fillZeroFromVLToMaxVL bld dst oprSize 512
    | Register.Kind.GP, Register.Kind.XMM ->
      let dst = transOprToExpr bld false ins insLen dst
      let struct (_, srcA) = transOprToExpr128 bld false ins insLen src
      bld <+ (dst := srcA)
    | _ -> (* XMM, XMM *)
      let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
      let struct (_, srcA) = transOprToExpr128 bld false ins insLen src
      bld <+ (dstA := srcA)
      bld <+ (dstB := n0)
      fillZeroFromVLToMaxVL bld dst oprSize 512
  | _ -> raise InvalidOperandException
  bld --!> insLen

let private buildVectorMove (ins: Instruction) insLen bld packSz =
  bld <!-- (ins.Address, insLen)
  let oprSz = getOperationSize ins
  let isAVX512 = haveEVEXPrx ins.VEXInfo
  let packSz, packNum =
    if isAVX512 then packSz, 64<rt> / packSz else 64<rt>, 64<rt> / 64<rt>
  let struct (dst, src) = getTwoOprs ins
  let src = transOprToArr bld false ins insLen packSz packNum oprSz src
  let result =
    if isAVX512 then
      let eDst = transOprToArr bld false ins insLen packSz packNum oprSz dst
      let ePrx = getEVEXPrx ins.VEXInfo
      let k = regVar bld (ePrx.AAA |> int |> Register.opmask)
      makeAssignWithMask bld ePrx k oprSz packSz eDst src (isMemOpr dst)
    else src
  assignPackedInstr bld false ins insLen packNum oprSz dst result
  fillZeroFromVLToMaxVL bld dst oprSz 512
  bld --!> insLen

let vmovapd ins insLen bld = buildVectorMove ins insLen bld 64<rt>
let vmovaps ins insLen bld = buildVectorMove ins insLen bld 32<rt>

let private buildVectorMoveAVX512 (ins: Instruction) insLen bld packSz =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / packSz
  let struct (dst, src) = getTwoOprs ins
  let ePrx = getEVEXPrx ins.VEXInfo
  let k = regVar bld (ePrx.AAA |> int |> Register.opmask)
  let eDst = transOprToArr bld false ins insLen packSz packNum oprSize dst
  let src = transOprToArr bld false ins insLen packSz packNum oprSize src
  let result =
    makeAssignWithMask bld ePrx k oprSize packSz eDst src (isMemOpr dst)
  assignPackedInstr bld false ins insLen packNum oprSize dst result
  fillZeroFromVLToMaxVL bld dst oprSize 512
  bld --!> insLen

let vmovdqu ins insLen bld = buildVectorMove ins insLen bld 64<rt>

let vmovdqu16 ins insLen bld = buildVectorMoveAVX512 ins insLen bld 16<rt>
let vmovdqu64 ins insLen bld = buildVectorMoveAVX512 ins insLen bld 64<rt>

let vmovdqa ins insLen bld = buildVectorMove ins insLen bld 64<rt>

let vmovdqa64 ins insLen bld = buildVectorMoveAVX512 ins insLen bld 64<rt>

let vmovntdq ins insLen bld =
  buildMove ins insLen bld

let vmovups ins insLen bld = buildVectorMove ins insLen bld 32<rt>
let vmovupd ins insLen bld = buildVectorMove ins insLen bld 64<rt>

let vmovddup (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let oprSize = getOperationSize ins
  match oprSize with
  | 128<rt> ->
    let struct (dst2, dst1) = transOprToExpr128 bld false ins insLen dst
    let src = transOprToExpr64 bld false ins insLen src
    bld <+ (dst1 := src)
    bld <+ (dst2 := src)
  | 256<rt> ->
    let struct (dst4, dst3, dst2, dst1) =
      transOprToExpr256 bld false ins insLen dst
    let struct (_src4, src3, _src2, src1) =
      transOprToExpr256 bld false ins insLen src
    bld <+ (dst1 := src1)
    bld <+ (dst2 := src1)
    bld <+ (dst3 := src3)
    bld <+ (dst4 := src3)
  | _ -> raise InvalidOperandSizeException
  fillZeroFromVLToMaxVL bld dst oprSize 512
  bld --!> insLen

let vmovntps ins insLen bld =
  buildMove ins insLen bld

let vmovntpd ins insLen bld =
  buildMove ins insLen bld

let vmovhlps (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
  let struct (src1B, _src1A) = transOprToExpr128 bld false ins insLen src1
  let struct (src2B, _src2A) = transOprToExpr128 bld false ins insLen src2
  bld <+ (dstA := src2B)
  bld <+ (dstB := src1B)
  fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
  bld --!> insLen

let vmovhpd (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | TwoOperands (dst, src) ->
    if haveEVEXPrx ins.VEXInfo then ()
    else
      let dst = transOprToExpr64 bld false ins insLen dst
      let struct (src2, _src1) = transOprToExpr128 bld false ins insLen src
      bld <+ (dst := src2)
  | ThreeOperands (dst, src1, src2)->
    let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
    let struct (_src1B, src1A) = transOprToExpr128 bld false ins insLen src1
    let src2 = transOprToExpr64 bld false ins insLen src2
    bld <+ (dstA := src1A)
    bld <+ (dstB := src2)
    fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
  | _ -> raise InvalidOperandException
  bld --!> insLen

let vmovlhps (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
  let struct (_src1B, src1A) = transOprToExpr128 bld true ins insLen src1
  let struct (_src2B, src2A) = transOprToExpr128 bld true ins insLen src2
  bld <+ (dstA := src1A)
  bld <+ (dstB := src2A)
  fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
  bld --!> insLen

let vmovlpd (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | TwoOperands (dst, src) ->
    let dst = transOprToExpr64 bld false ins insLen dst
    let struct (_, srcA) = transOprToExpr128 bld false ins insLen src
    bld <+ (dst := srcA)
  | ThreeOperands (dst, src1, src2)->
    let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
    let struct (src1B, _src1A) = transOprToExpr128 bld false ins insLen src1
    let src2 = transOprToExpr bld false ins insLen src2
    bld <+ (dstA := src2)
    bld <+ (dstB := src1B)
    fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
  | _ -> raise InvalidOperandException
  bld --!> insLen

let vmovmskpd ins insLen bld =
  let struct (dst, src) = getTwoOprs ins
  let mskpd r =
    match Register.getKind r with
    | Register.Kind.XMM -> movmskpd ins insLen bld
    | Register.Kind.YMM ->
      bld <!-- (ins.Address, insLen)
      let dst = transOprToExpr bld false ins insLen dst
      let dstSz = Expr.TypeOf dst
      let struct (src4, src3, src2, src1) =
        transOprToExpr256 bld false ins insLen src
      let src63 = AST.sext dstSz (AST.xthi 1<rt> src1)
      let src127 = (AST.sext dstSz (AST.xthi 1<rt> src2)) << AST.num1 dstSz
      let src191 = (AST.sext dstSz (AST.xthi 1<rt> src3)) << numI32 2 dstSz
      let src255 = (AST.sext dstSz (AST.xthi 1<rt> src4)) << numI32 3 dstSz
      bld <+ (dst := src63 .| src127 .| src191 .| src255)
      bld --!> insLen
    | _ -> raise InvalidOperandException
  match src with
  | OprReg r -> mskpd r
  | _ -> raise InvalidOperandSizeException

let vmovmskps ins insLen bld =
  let struct (dst, src) = getTwoOprs ins
  let mskpd r =
    match Register.getKind r with
    | Register.Kind.XMM -> movmskps ins insLen bld
    | Register.Kind.YMM ->
      bld <!-- (ins.Address, insLen)
      let oprSz = getOperationSize ins
      let dst = transOprToExpr bld false ins insLen dst
      let struct (srcD, srcC, srcB, srcA) =
        transOprToExpr256 bld false ins insLen src
      let b0 = (srcA >> (numI32 31 64<rt>) .& (numI32 0b1 64<rt>))
      let b1 = (srcA >> (numI32 62 64<rt>) .& (numI32 0b10 64<rt>))
      let b2 = (srcB >> (numI32 29 64<rt>) .& (numI32 0b100 64<rt>))
      let b3 = (srcB >> (numI32 60 64<rt>) .& (numI32 0b1000 64<rt>))
      let b4 = (srcC >> (numI32 27 64<rt>) .& (numI32 0b10000 64<rt>))
      let b5 = (srcC >> (numI32 58 64<rt>) .& (numI32 0b100000 64<rt>))
      let b6 = (srcD >> (numI32 25 64<rt>) .& (numI32 0b1000000 64<rt>))
      let b7 = (srcD >> (numI32 56 64<rt>) .& (numI32 0b10000000 64<rt>))
      bld
      <+ (dstAssign oprSz dst (b7 .| b6 .| b5 .| b4 .| b3 .| b2 .| b1 .| b0))
      bld --!> insLen
    | _ -> raise InvalidOperandException
  match src with
  | OprReg r -> mskpd r
  | _ -> raise InvalidOperandSizeException

let vmovsd (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | TwoOperands (OprMem _, _) -> movsd ins insLen bld
  | TwoOperands (OprReg _ as dst, src) ->
    let struct (dst2, dst1) = transOprToExpr128 bld false ins insLen dst
    let src = transOprToExpr64 bld false ins insLen src
    bld <+ (dst1 := src)
    bld <+ (dst2 := AST.num0 64<rt>)
    fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
    bld --!> insLen
  | ThreeOperands (dst, src1, src2)->
    let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
    let struct (src1B, _src1A) = transOprToExpr128 bld false ins insLen src1
    let struct (_src2B, src2A) = transOprToExpr128 bld false ins insLen src2
    bld <+ (dstA := src2A)
    bld <+ (dstB := src1B)
    fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
    bld --!> insLen
  | _ -> raise InvalidOperandException

let vmovshdup ins insLen bld =
  let struct (dst, src) = getTwoOprs ins
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  match oprSize with
  | 128<rt> ->
    let struct (dst2, dst1) = transOprToExpr128 bld false ins insLen dst
    let struct (src2, src1) = transOprToExpr128 bld false ins insLen src
    bld <+ (AST.xtlo 32<rt> dst1 := AST.xthi 32<rt> src1)
    bld <+ (AST.xthi 32<rt> dst1 := AST.xthi 32<rt> src1)
    bld <+ (AST.xtlo 32<rt> dst2 := AST.xthi 32<rt> src2)
    bld <+ (AST.xthi 32<rt> dst2 := AST.xthi 32<rt> src2)
  | 256<rt> ->
    let struct (dst4, dst3, dst2, dst1) =
      transOprToExpr256 bld false ins insLen dst
    let struct (src4, src3, src2, src1) =
      transOprToExpr256 bld false ins insLen src
    bld <+ (AST.xtlo 32<rt> dst1 := AST.xthi 32<rt> src1)
    bld <+ (AST.xthi 32<rt> dst1 := AST.xthi 32<rt> src1)
    bld <+ (AST.xtlo 32<rt> dst2 := AST.xthi 32<rt> src2)
    bld <+ (AST.xthi 32<rt> dst2 := AST.xthi 32<rt> src2)
    bld <+ (AST.xtlo 32<rt> dst3 := AST.xthi 32<rt> src3)
    bld <+ (AST.xthi 32<rt> dst3 := AST.xthi 32<rt> src3)
    bld <+ (AST.xtlo 32<rt> dst4 := AST.xthi 32<rt> src4)
    bld <+ (AST.xthi 32<rt> dst4 := AST.xthi 32<rt> src4)
  | _ -> raise InvalidOperandSizeException
  fillZeroFromVLToMaxVL bld dst oprSize 512
  bld --!> insLen

let vmovsldup ins insLen bld =
  let struct (dst, src) = getTwoOprs ins
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  match oprSize with
  | 128<rt> ->
    let struct (dst2, dst1) = transOprToExpr128 bld false ins insLen dst
    let struct (src2, src1) = transOprToExpr128 bld false ins insLen src
    bld <+ (AST.xtlo 32<rt> dst1 := AST.xtlo 32<rt> src1)
    bld <+ (AST.xthi 32<rt> dst1 := AST.xtlo 32<rt> src1)
    bld <+ (AST.xtlo 32<rt> dst2 := AST.xtlo 32<rt> src2)
    bld <+ (AST.xthi 32<rt> dst2 := AST.xtlo 32<rt> src2)
  | 256<rt> ->
    let struct (dst4, dst3, dst2, dst1) =
      transOprToExpr256 bld false ins insLen dst
    let struct (src4, src3, src2, src1) =
      transOprToExpr256 bld false ins insLen src
    bld <+ (AST.xtlo 32<rt> dst1 := AST.xtlo 32<rt> src1)
    bld <+ (AST.xthi 32<rt> dst1 := AST.xtlo 32<rt> src1)
    bld <+ (AST.xtlo 32<rt> dst2 := AST.xtlo 32<rt> src2)
    bld <+ (AST.xthi 32<rt> dst2 := AST.xtlo 32<rt> src2)
    bld <+ (AST.xtlo 32<rt> dst3 := AST.xtlo 32<rt> src3)
    bld <+ (AST.xthi 32<rt> dst3 := AST.xtlo 32<rt> src3)
    bld <+ (AST.xtlo 32<rt> dst4 := AST.xtlo 32<rt> src4)
    bld <+ (AST.xthi 32<rt> dst4 := AST.xtlo 32<rt> src4)
  | _ -> raise InvalidOperandSizeException
  fillZeroFromVLToMaxVL bld dst oprSize 512
  bld --!> insLen

let vmovss (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | TwoOperands (OprMem _, _) -> movss ins insLen bld
  | TwoOperands (OprReg _ as dst, src) ->
    let struct (dst2, dst1) = transOprToExpr128 bld false ins insLen dst
    let src = transOprToExpr32 bld false ins insLen src
    bld <+ (AST.xtlo 32<rt> dst1 := src)
    bld <+ (AST.xthi 32<rt> dst1 := AST.num0 32<rt>)
    bld <+ (dst2 := AST.num0 64<rt>)
    fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
    bld --!> insLen
  | ThreeOperands (dst, src1, src2)->
    let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
    let struct (src1B, src1A) = transOprToExpr128 bld false ins insLen src1
    let struct (_src2B, src2A) = transOprToExpr128 bld false ins insLen src2
    bld <+ (AST.xtlo 32<rt> dstA := AST.xtlo 32<rt> src2A)
    bld <+ (AST.xthi 32<rt> dstA := AST.xthi 32<rt> src1A)
    bld <+ (dstB := src1B)
    fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
    bld --!> insLen
  | _ -> raise InvalidOperandException

let vandps ins insLen bld =
  buildPackedFPInstr ins insLen bld 32<rt> (.&)

let vandpd ins insLen bld =
  buildPackedFPInstr ins insLen bld 64<rt> (.&)

let private andnpdOp e1 e2 = (AST.not e1) .& e2

let vandnps ins insLen bld =
  buildPackedFPInstr ins insLen bld 32<rt> andnpdOp

let vandnpd ins insLen bld =
  buildPackedFPInstr ins insLen bld 64<rt> andnpdOp

let vorps ins insLen bld =
  buildPackedFPInstr ins insLen bld 32<rt> (.|)

let vorpd ins insLen bld =
  buildPackedFPInstr ins insLen bld 64<rt> (.|)

let vshufi32x4 (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let packSz = 32<rt>
  let packNum = 64<rt> / packSz
  let struct (dst, src1, src2, imm) = getFourOprs ins
  let isSrc2Mem =
    match src2 with
    | OprMem _ -> true
    | _ -> false
  let src1 = transOprToArr bld false ins insLen packSz packNum oprSize src1
  let src2 = transOprToArr bld false ins insLen packSz packNum oprSize src2
  let imm8 = getImmValue imm
  let ePrx = getEVEXPrx ins.VEXInfo
  let k = regVar bld (ePrx.AAA |> int |> Register.opmask)
  let tmpSrc2 = Array.init (oprSize / packSz) (fun _ -> tmpVar bld 32<rt>)
  if isSrc2Mem && ePrx.B = 1uy then
    let tSrc2 = tmpVar bld 32<rt>
    bld <+ (tSrc2 := Array.head src2)
    Array.iter (fun e -> bld <+ (e := tSrc2)) tmpSrc2
  else Array.iter2 (fun e1 e2 -> bld <+ (e1 := e2)) tmpSrc2 src2
  match oprSize with
  | 256<rt> ->
    let halfPNum = oprSize / packSz / 2
    let orgDst =
      transOprToArr bld false ins insLen packSz packNum oprSize dst
    let tDstA = Array.init halfPNum (fun _ -> tmpVar bld packSz)
    let tDstB = Array.init halfPNum (fun _ -> tmpVar bld packSz)
    let imm0 (* imm8[0] *) = imm8 &&& 0b1L |> int
    let imm1 (* imm8[1] *) = (imm8 >>> 1) &&& 0b1L |> int
    Array.iteri (fun idx e ->
      bld <+ (e := src1[ (imm0 * halfPNum) + idx ])) tDstA
    Array.iteri (fun idx e ->
      bld <+ (e := src2[ (imm1 * halfPNum) + idx ])) tDstB
    let tDst = Array.append tDstA tDstB
    let result = makeAssignWithMask bld ePrx k oprSize packSz orgDst tDst false
    assignPackedInstr bld false ins insLen packNum oprSize dst result
  | 512<rt> ->
    let pNum = oprSize / packSz / 4
    let orgDst =
      transOprToArr bld false ins insLen packSz packNum oprSize dst
    let tDstA = Array.init pNum (fun _ -> tmpVar bld packSz)
    let tDstB = Array.init pNum (fun _ -> tmpVar bld packSz)
    let tDstC = Array.init pNum (fun _ -> tmpVar bld packSz)
    let tDstD = Array.init pNum (fun _ -> tmpVar bld packSz)
    let ctrl0 = (imm8 >>> 0) &&& 0b11L |> int
    let ctrl1 = (imm8 >>> 2) &&& 0b11L |> int
    let ctrl2 = (imm8 >>> 4) &&& 0b11L |> int
    let ctrl3 = (imm8 >>> 6) &&& 0b11L |> int
    Array.iteri (fun idx e -> bld <+ (e := src1[ (ctrl0 * pNum) + idx ])) tDstA
    Array.iteri (fun idx e -> bld <+ (e := src1[ (ctrl1 * pNum) + idx ])) tDstB
    Array.iteri (fun idx e ->
      bld <+ (e := tmpSrc2[ (ctrl2 * pNum) + idx ])) tDstC
    Array.iteri (fun idx e ->
      bld <+ (e := tmpSrc2[ (ctrl3 * pNum) + idx ])) tDstD
    let tDst = Array.concat [| tDstA; tDstB; tDstC; tDstD |]
    let result = makeAssignWithMask bld ePrx k oprSize packSz orgDst tDst false
    assignPackedInstr bld false ins insLen packNum oprSize dst result
  | _ -> raise InvalidOperandException
  fillZeroFromVLToMaxVL bld dst oprSize 512
  bld --!> insLen

let private doShuf bld cond dst e1 e2 =
  bld <+ (dst := AST.num0 32<rt>)
  bld <+ (dst := AST.ite (cond == AST.num0 8<rt>) (AST.xtlo 32<rt> e1) dst)
  bld <+ (dst := AST.ite (cond == AST.num1 8<rt>) (AST.xthi 32<rt> e1) dst)
  bld <+ (dst := AST.ite (cond == numI32 2 8<rt>) (AST.xtlo 32<rt> e2) dst)
  bld <+ (dst := AST.ite (cond == numI32 3 8<rt>) (AST.xthi 32<rt> e2) dst)

let private makeShufCond imm shfAmt =
  ((AST.xtlo 8<rt> imm) >> (numI32 shfAmt 8<rt>)) .& (numI32 0b11 8<rt>)

let vshufps (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2, imm) = getFourOprs ins
  let imm = transOprToExpr bld false ins insLen imm
  let oprSize = getOperationSize ins
  match oprSize with
  | 128<rt> ->
    let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
    let struct (sr1B, sr1A) = transOprToExpr128 bld true ins insLen src1
    let struct (sr2B, sr2A) = transOprToExpr128 bld true ins insLen src2
    doShuf bld (makeShufCond imm 0) (AST.xtlo 32<rt> dstA) sr1A sr1B
    doShuf bld (makeShufCond imm 2) (AST.xthi 32<rt> dstA) sr1A sr1B
    doShuf bld (makeShufCond imm 4) (AST.xtlo 32<rt> dstB) sr2A sr2B
    doShuf bld (makeShufCond imm 6) (AST.xthi 32<rt> dstB) sr2A sr2B
  | 256<rt> ->
    let struct (dstD, dstC, dstB, dstA) =
      transOprToExpr256 bld false ins insLen dst
    let struct (sr1D, sr1C, sr1B, sr1A) =
      transOprToExpr256 bld true ins insLen src1
    let struct (sr2D, sr2C, sr2B, sr2A) =
      transOprToExpr256 bld true ins insLen src2
    doShuf bld (makeShufCond imm 0) (AST.xtlo 32<rt> dstA) sr1A sr1B
    doShuf bld (makeShufCond imm 2) (AST.xthi 32<rt> dstA) sr1A sr1B
    doShuf bld (makeShufCond imm 4) (AST.xtlo 32<rt> dstB) sr2A sr2B
    doShuf bld (makeShufCond imm 6) (AST.xthi 32<rt> dstB) sr2A sr2B
    doShuf bld (makeShufCond imm 0) (AST.xtlo 32<rt> dstC) sr1C sr1D
    doShuf bld (makeShufCond imm 2) (AST.xthi 32<rt> dstC) sr1C sr1D
    doShuf bld (makeShufCond imm 4) (AST.xtlo 32<rt> dstD) sr2C sr2D
    doShuf bld (makeShufCond imm 6) (AST.xthi 32<rt> dstD) sr2C sr2D
  | _ -> raise InvalidOperandSizeException
  fillZeroFromVLToMaxVL bld dst oprSize 512
  bld --!> insLen

let vshufpd (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2, imm) = getFourOprs ins
  let imm = transOprToExpr bld false ins insLen imm
  let cond1 = AST.xtlo 1<rt> imm
  let cond2 = AST.extract imm 1<rt> 1
  let cond3 = AST.extract imm 1<rt> 2
  let cond4 = AST.extract imm 1<rt> 3
  let oprSize = getOperationSize ins
  match oprSize with
  | 128<rt> ->
    let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
    let struct (src1B, src1A) = transOprToExpr128 bld true ins insLen src1
    let struct (src2B, src2A) = transOprToExpr128 bld true ins insLen src2
    bld <+ (dstA := AST.ite cond1 src1B src1A)
    bld <+ (dstB := AST.ite cond2 src2B src2A)
  | 256<rt> ->
    let struct (dstD, dstC, dstB, dstA) =
      transOprToExpr256 bld false ins insLen dst
    let struct (sr1D, sr1C, sr1B, sr1A) =
      transOprToExpr256 bld true ins insLen src1
    let struct (sr2D, sr2C, sr2B, sr2A) =
      transOprToExpr256 bld true ins insLen src2
    bld <+ (dstA := AST.ite cond1 sr1B sr1A)
    bld <+ (dstB := AST.ite cond2 sr2B sr2A)
    bld <+ (dstC := AST.ite cond3 sr1D sr1C)
    bld <+ (dstD := AST.ite cond4 sr2D sr2C)
  | _ -> raise InvalidOperandSizeException
  fillZeroFromVLToMaxVL bld dst oprSize 512
  bld --!> insLen

let vunpckhps (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let oprSize = getOperationSize ins
  match oprSize with
  | 128<rt> ->
    let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
    let struct (src1B, _src1A) = transOprToExpr128 bld false ins insLen src1
    let struct (src2B, _src2A) = transOprToExpr128 bld false ins insLen src2
    bld <+ (AST.xtlo 32<rt> dstA := AST.xtlo 32<rt> src1B)
    bld <+ (AST.xthi 32<rt> dstA := AST.xtlo 32<rt> src2B)
    bld <+ (AST.xtlo 32<rt> dstB := AST.xthi 32<rt> src1B)
    bld <+ (AST.xthi 32<rt> dstB := AST.xthi 32<rt> src2B)
    fillZeroHigh128 bld dst
  | 256<rt> ->
    let struct (dstD, dstC, dstB, dstA) =
      transOprToExpr256 bld false ins insLen dst
    let struct (sr1D, _, sr1B, _) =
      transOprToExpr256 bld false ins insLen src1
    let struct (sr2D, _, sr2B, _) =
      transOprToExpr256 bld false ins insLen src2
    bld <+ (AST.xtlo 32<rt> dstA := AST.xtlo 32<rt> sr1B)
    bld <+ (AST.xthi 32<rt> dstA := AST.xtlo 32<rt> sr2B)
    bld <+ (AST.xtlo 32<rt> dstB := AST.xthi 32<rt> sr1B)
    bld <+ (AST.xthi 32<rt> dstB := AST.xthi 32<rt> sr2B)
    bld <+ (AST.xtlo 32<rt> dstC := AST.xtlo 32<rt> sr1D)
    bld <+ (AST.xthi 32<rt> dstC := AST.xtlo 32<rt> sr2D)
    bld <+ (AST.xtlo 32<rt> dstD := AST.xthi 32<rt> sr1D)
    bld <+ (AST.xthi 32<rt> dstD := AST.xthi 32<rt> sr2D)
  | _ -> raise InvalidOperandSizeException
  fillZeroFromVLToMaxVL bld dst oprSize 512
  bld --!> insLen

let vunpckhpd (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let oprSize = getOperationSize ins
  match oprSize with
  | 128<rt> ->
    let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
    let struct (src1B, _src1A) = transOprToExpr128 bld false ins insLen src1
    let struct (src2B, _src2A) = transOprToExpr128 bld false ins insLen src2
    bld <+ (dstA := src1B)
    bld <+ (dstB := src2B)
    fillZeroHigh128 bld dst
  | 256<rt> ->
    let struct (dstD, dstC, dstB, dstA) =
      transOprToExpr256 bld false ins insLen dst
    let struct (sr1D, _, sr1B, _) =
      transOprToExpr256 bld false ins insLen src1
    let struct (sr2D, _, sr2B, _) =
      transOprToExpr256 bld false ins insLen src2
    bld <+ (dstA := sr1B)
    bld <+ (dstB := sr2B)
    bld <+ (dstC := sr1D)
    bld <+ (dstD := sr2D)
  | _ -> raise InvalidOperandSizeException
  fillZeroFromVLToMaxVL bld dst oprSize 512
  bld --!> insLen

let vunpcklps (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let oprSize = getOperationSize ins
  match oprSize with
  | 128<rt> ->
    let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
    let struct (_src1B, src1A) = transOprToExpr128 bld true ins insLen src1
    let struct (_src2B, src2A) = transOprToExpr128 bld true ins insLen src2
    bld <+ (AST.xtlo 32<rt> dstA := AST.xtlo 32<rt> src1A)
    bld <+ (AST.xthi 32<rt> dstA := AST.xtlo 32<rt> src2A)
    bld <+ (AST.xtlo 32<rt> dstB := AST.xthi 32<rt> src1A)
    bld <+ (AST.xthi 32<rt> dstB := AST.xthi 32<rt> src2A)
    fillZeroHigh128 bld dst
  | 256<rt> ->
    let struct (dstD, dstC, dstB, dstA) =
      transOprToExpr256 bld false ins insLen dst
    let struct (_, src1C, _, src1A) =
      transOprToExpr256 bld true ins insLen src1
    let struct (_, src2C, _, src2A) =
      transOprToExpr256 bld true ins insLen src2
    bld <+ (AST.xtlo 32<rt> dstA := AST.xtlo 32<rt> src1A)
    bld <+ (AST.xthi 32<rt> dstA := AST.xtlo 32<rt> src2A)
    bld <+ (AST.xtlo 32<rt> dstB := AST.xthi 32<rt> src1A)
    bld <+ (AST.xthi 32<rt> dstB := AST.xthi 32<rt> src2A)
    bld <+ (AST.xtlo 32<rt> dstC := AST.xtlo 32<rt> src1C)
    bld <+ (AST.xthi 32<rt> dstC := AST.xtlo 32<rt> src2C)
    bld <+ (AST.xtlo 32<rt> dstD := AST.xthi 32<rt> src1C)
    bld <+ (AST.xthi 32<rt> dstD := AST.xthi 32<rt> src2C)
  | _ -> raise InvalidOperandSizeException
  fillZeroFromVLToMaxVL bld dst oprSize 512
  bld --!> insLen

let vunpcklpd (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let oprSize = getOperationSize ins
  match oprSize with
  | 128<rt> ->
    let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
    let struct (_src1B, src1A) = transOprToExpr128 bld true ins insLen src1
    let struct (_src2B, src2A) = transOprToExpr128 bld true ins insLen src2
    bld <+ (dstA := src1A)
    bld <+ (dstB := src2A)
  | 256<rt> ->
    let struct (dstD, dstC, dstB, dstA) =
      transOprToExpr256 bld false ins insLen dst
    let struct (_, src1C, _, src1A) =
      transOprToExpr256 bld true ins insLen src1
    let struct (_, src2C, _, src2A) =
      transOprToExpr256 bld true ins insLen src2
    bld <+ (dstA := src1A)
    bld <+ (dstB := src2A)
    bld <+ (dstC := src1C)
    bld <+ (dstD := src2C)
  | _ -> raise InvalidOperandSizeException
  fillZeroFromVLToMaxVL bld dst oprSize 512
  bld --!> insLen

let vxorps (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSz = getOperationSize ins
  let packSz = 32<rt>
  let packNum = 64<rt> / packSz
  let struct (dst, src1, src2) = getThreeOprs ins
  let eDst = transOprToArr bld false ins insLen packSz packNum oprSz dst
  let tSrc1 = transOprToArr bld false ins insLen packSz packNum oprSz src1
  let tSrc2 = transOprToArr bld false ins insLen packSz packNum oprSz src2
  let result =
    if haveEVEXPrx ins.VEXInfo then
      let isSrc2Mem = isMemOpr src2
      let ePrx = getEVEXPrx ins.VEXInfo
      let k = regVar bld (ePrx.AAA |> int |> Register.opmask)
      makeAssignEVEX bld ePrx k oprSz packSz eDst tSrc1 tSrc2 (<+>) isSrc2Mem
    else Array.map2 (<+>) tSrc1 tSrc2
  assignPackedInstr bld false ins insLen packNum oprSz dst result
  fillZeroFromVLToMaxVL bld dst oprSz 512
  bld --!> insLen

let vxorpd ins insLen bld =
  buildPackedFPInstr ins insLen bld 64<rt> (<+>)

let vbroadcasti128 (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let struct (dstD, dstC, dstB, dstA) =
    transOprToExpr256 bld false ins insLen dst
  let struct (srcB, srcA) = transOprToExpr128 bld false ins insLen src
  bld <+ (dstA := srcA)
  bld <+ (dstB := srcB)
  bld <+ (dstC := srcA)
  bld <+ (dstD := srcB)
  fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
  bld --!> insLen

let vbroadcastss (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let src = transOprToExpr32 bld false ins insLen src
  let tmp = tmpVar bld 32<rt>
  let oprSize = getOperationSize ins
  match oprSize with
  | 128<rt> ->
    let struct (dst2, dst1) = transOprToExpr128 bld false ins insLen dst
    bld <+ (tmp := src)
    bld <+ (AST.xtlo 32<rt> dst1 := tmp)
    bld <+ (AST.xthi 32<rt> dst1 := tmp)
    bld <+ (AST.xtlo 32<rt> dst2 := tmp)
    bld <+ (AST.xthi 32<rt> dst2 := tmp)
    fillZeroHigh128 bld dst
  | 256<rt> ->
    let struct (dst4, dst3, dst2, dst1) =
      transOprToExpr256 bld false ins insLen dst
    bld <+ (tmp := src)
    bld <+ (AST.xtlo 32<rt> dst1 := tmp)
    bld <+ (AST.xthi 32<rt> dst1 := tmp)
    bld <+ (AST.xtlo 32<rt> dst2 := tmp)
    bld <+ (AST.xthi 32<rt> dst2 := tmp)
    bld <+ (AST.xtlo 32<rt> dst3 := tmp)
    bld <+ (AST.xthi 32<rt> dst3 := tmp)
    bld <+ (AST.xtlo 32<rt> dst4 := tmp)
    bld <+ (AST.xthi 32<rt> dst4 := tmp)
  | 512<rt> -> ()
  | _ -> raise InvalidOperandException
  fillZeroFromVLToMaxVL bld dst oprSize 512
  bld --!> insLen

let vextracti32x8 (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let packSz = 32<rt>
  let packNum = 64<rt> / packSz
  let allPackNum = oprSize / packSz
  let struct (dst, src, imm) = getThreeOprs ins
  let ePrx = getEVEXPrx ins.VEXInfo
  let k = regVar bld (ePrx.AAA |> int |> Register.opmask)
  let eDst = transOprToArr bld false ins insLen packSz packNum oprSize dst
  let src =
    transOprToArr bld false ins insLen packSz packNum (oprSize * 2) src
  let imm0 = getImmValue imm &&& 0b1L |> int (* imm8[0] *)
  let tmpDst = Array.sub src (allPackNum * imm0) allPackNum
  let result =
    makeAssignWithMask bld ePrx k oprSize packSz eDst tmpDst (isMemOpr dst)
  assignPackedInstr bld false ins insLen packNum oprSize dst result
  fillZeroFromVLToMaxVL bld dst oprSize 512
  bld --!> insLen

let vextracti128 (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src, imm) = getThreeOprs ins
  let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
  let struct (srcD, srcC, srcB, srcA) =
    transOprToExpr256 bld false ins insLen src
  let imm = transOprToExpr bld false ins insLen imm
  let cond = tmpVar bld 1<rt>
  bld <+ (cond := AST.xtlo 1<rt> imm)
  bld <+ (dstA := AST.ite cond srcC srcA)
  bld <+ (dstB := AST.ite cond srcD srcB)
  fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
  bld --!> insLen

let vextracti64x4 (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src, imm) = getThreeOprs ins
  let ePrx = getEVEXPrx ins.VEXInfo
  let k = regVar bld (ePrx.AAA |> int |> Register.opmask)
  let struct (dstD, dstC, dstB, dstA) =
    transOprToExpr256 bld false ins insLen dst
  let struct (srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA) =
    transOprToExpr512 bld false ins insLen src
  let imm0 = getImmValue imm &&& 0b1L (* imm8[0] *)
  let struct (tDstD, tDstC, tDstB, tDstA) = tmpVars4 bld 64<rt>
  if imm0 = 0L then
    bld <+ (tDstA := srcA)
    bld <+ (tDstB := srcB)
    bld <+ (tDstC := srcC)
    bld <+ (tDstD := srcD)
  else (* imm0 = 1 *)
    bld <+ (tDstA := srcE)
    bld <+ (tDstB := srcF)
    bld <+ (tDstC := srcG)
    bld <+ (tDstD := srcH)
  match dst with
  | OprReg _ ->
    bld <+ (dstA := AST.ite (getVectorMoveCond ePrx k 0)
                          tDstA (maskWithEPrx ePrx dstA 64<rt>))
    bld <+ (dstB := AST.ite (getVectorMoveCond ePrx k 1)
                          tDstB (maskWithEPrx ePrx dstB 64<rt>))
    bld <+ (dstC := AST.ite (getVectorMoveCond ePrx k 2)
                          tDstC (maskWithEPrx ePrx dstC 64<rt>))
    bld <+ (dstD := AST.ite (getVectorMoveCond ePrx k 3)
                          tDstD (maskWithEPrx ePrx dstD 64<rt>))
  | OprMem _ ->
    bld <+ (dstA := AST.ite (getVectorMoveCond ePrx k 0) tDstA dstA)
    bld <+ (dstB := AST.ite (getVectorMoveCond ePrx k 1) tDstB dstB)
    bld <+ (dstC := AST.ite (getVectorMoveCond ePrx k 2) tDstC dstC)
    bld <+ (dstD := AST.ite (getVectorMoveCond ePrx k 3) tDstD dstD)
  | _ -> raise InvalidOperandException
  bld --!> insLen

let vinserti128 (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2, imm) = getFourOprs ins
  let struct (dstD, dstC, dstB, dstA) =
    transOprToExpr256 bld false ins insLen dst
  let struct (src1D, src1C, src1B, src1A) =
    transOprToExpr256 bld false ins insLen src1
  let struct (src2B, src2A) = transOprToExpr128 bld false ins insLen src2
  let imm = transOprToExpr bld false ins insLen imm
  let cond = tmpVar bld 1<rt>
  bld <+ (cond := AST.xtlo 1<rt> imm)
  bld <+ (dstA := AST.ite cond src1A src2A)
  bld <+ (dstB := AST.ite cond src1B src2B)
  bld <+ (dstC := AST.ite cond src2A src1C)
  bld <+ (dstD := AST.ite cond src2B src1D)
  bld --!> insLen

let vpaddb ins insLen bld =
  buildPackedInstr ins insLen bld true 8<rt> (opP (.+))

let vpmullw ins insLen bld =
  buildPackedInstr ins insLen bld true 16<rt> MMXLifter.opPmullw

let vpaddd (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSz = getOperationSize ins
  let packSz = 32<rt>
  let packNum = 64<rt> / packSz
  let struct (dst, src1, src2) = getThreeOprs ins
  let eDst = transOprToArr bld false ins insLen packSz packNum oprSz dst
  let tSrc1 = transOprToArr bld false ins insLen packSz packNum oprSz src1
  let tSrc2 = transOprToArr bld false ins insLen packSz packNum oprSz src2
  let result =
    if haveEVEXPrx ins.VEXInfo then
      let isSrc2Mem = isMemOpr src2
      let ePrx = getEVEXPrx ins.VEXInfo
      let k = regVar bld (ePrx.AAA |> int |> Register.opmask)
      makeAssignEVEX bld ePrx k oprSz packSz eDst tSrc1 tSrc2 (.+) isSrc2Mem
    else Array.map2 (.+) tSrc1 tSrc2
  assignPackedInstr bld false ins insLen packNum oprSz dst result
  fillZeroFromVLToMaxVL bld dst oprSz 512
  bld --!> insLen

let vpaddq ins insLen bld =
  buildPackedInstr ins insLen bld true 64<rt> (opP (.+))

let vpalignr (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSz = getOperationSize ins
  let packSz = 8<rt>
  let packNum = 64<rt> / packSz
  let struct (dst, src1, src2, imm) = getFourOprs ins
  let src1 = transOprToArr bld false ins insLen packSz packNum oprSz src1
  let src2 = transOprToArr bld false ins insLen packSz packNum oprSz src2
  let imm = getImmValue imm |> int
  let initRes = Array.init 16 (fun _ -> tmpVar bld 8<rt>)
  Array.iter (fun e -> bld <+ (e := AST.num0 8<rt>)) initRes
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
  assignPackedInstr bld false ins insLen packNum oprSz dst result
  fillZeroFromVLToMaxVL bld dst oprSz 512
  bld --!> insLen

let vpand ins insLen bld =
  buildPackedInstr ins insLen bld true 64<rt> opPand

let vpandn ins insLen bld =
  buildPackedInstr ins insLen bld true 64<rt> opPandn

let vblendvpd (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / 64<rt>
  let struct (dst, src1, src2, src3) = getFourOprs ins
  let src1 = transOprToArr bld false ins insLen 64<rt> packNum oprSize src1
  let src2 = transOprToArr bld false ins insLen 64<rt> packNum oprSize src2
  let src3 = transOprToArr bld false ins insLen 64<rt> packNum oprSize src3
  let result = packedVblend src2 src1 src3
  assignPackedInstr bld false ins insLen packNum oprSize dst result
  fillZeroFromVLToMaxVL bld dst oprSize 512
  bld --!> insLen

let vblendvps (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / 32<rt>
  let struct (dst, src1, src2, src3) = getFourOprs ins
  let src1 = transOprToArr bld false ins insLen 32<rt> packNum oprSize src1
  let src2 = transOprToArr bld false ins insLen 32<rt> packNum oprSize src2
  let src3 = transOprToArr bld false ins insLen 32<rt> packNum oprSize src3
  let result = packedVblend src2 src1 src3
  assignPackedInstr bld false ins insLen packNum oprSize dst result
  fillZeroFromVLToMaxVL bld dst oprSize 512
  bld --!> insLen

let vpblendd (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / 32<rt>
  let struct (dst, src1, src2, imm) = getFourOprs ins
  let src1 = transOprToArr bld false ins insLen 32<rt> packNum oprSize src1
  let src2 = transOprToArr bld false ins insLen 32<rt> packNum oprSize src2
  let imm = transOprToExpr bld false ins insLen imm
  let result = packedBlend src2 src1 imm
  assignPackedInstr bld false ins insLen packNum oprSize dst result
  fillZeroFromVLToMaxVL bld dst oprSize 512
  bld --!> insLen

let vpblendw (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / 16<rt>
  let struct (dst, src1, src2, imm) = getFourOprs ins
  let src1 = transOprToArr bld false ins insLen 16<rt> packNum oprSize src1
  let src2 = transOprToArr bld false ins insLen 16<rt> packNum oprSize src2
  let imm = transOprToExpr bld false ins insLen imm
  let result = packedBlend src2 src1 imm
  assignPackedInstr bld false ins insLen packNum oprSize dst result
  fillZeroFromVLToMaxVL bld dst oprSize 512
  bld --!> insLen

let vpblendvb (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / 8<rt>
  let struct (dst, src1, src2, src3) = getFourOprs ins
  let src1 = transOprToArr bld false ins insLen 8<rt> packNum oprSize src1
  let src2 = transOprToArr bld false ins insLen 8<rt> packNum oprSize src2
  let src3 = transOprToArr bld false ins insLen 8<rt> packNum oprSize src3
  let result = packedVblend src2 src1 src3
  assignPackedInstr bld false ins insLen packNum oprSize dst result
  fillZeroFromVLToMaxVL bld dst oprSize 512
  bld --!> insLen

let vpackusdw (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / 32<rt>
  let allPackNum = oprSize / 32<rt>
  let struct (dst, src1, src2) = getThreeOprs ins
  let src1 = transOprToArr bld false ins insLen 32<rt> packNum oprSize src1
  let src2 = transOprToArr bld false ins insLen 32<rt> packNum oprSize src2
  let src =
    match oprSize with
    | 128<rt> -> Array.append src1 src2
    | 256<rt> ->
      let loSrc1, hiSrc1 = Array.splitAt (allPackNum / 2) src1
      let loSrc2, hiSrc2 = Array.splitAt (allPackNum / 2) src2
      Array.concat [| loSrc1; loSrc2; hiSrc1; hiSrc2 |]
    | _ -> raise InvalidOperandSizeException
  let result = Array.map (packWithSaturation bld 32<rt>) src
  assignPackedInstr bld false ins insLen (packNum * 2) oprSize dst result
  fillZeroFromVLToMaxVL bld dst oprSize 512
  bld --!> insLen

let private saturateSignedWordToUnsignedByte bld expr = (* FIXME: MMXLifter *)
  let tExpr = tmpVar bld 16<rt>
  bld <+ (tExpr := expr)
  let checkMin = AST.slt tExpr (numI32 0 16<rt>)
  let checkMax = AST.sgt tExpr (numI32 255 16<rt>)
  let minNum = numU32 0u 8<rt>
  let maxNum = numU32 0xffu 8<rt>
  AST.ite checkMin minNum (AST.ite checkMax maxNum (AST.xtlo 8<rt> tExpr))

let vpackuswb (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / 16<rt>
  let allPackNum = oprSize / 16<rt>
  let struct (dst, src1, src2) = getThreeOprs ins
  let src1 = transOprToArr bld false ins insLen 16<rt> packNum oprSize src1
  let src2 = transOprToArr bld false ins insLen 16<rt> packNum oprSize src2
  let src =
    match oprSize with
    | 128<rt> -> Array.append src1 src2
    | 256<rt> ->
      let loSrc1, hiSrc1 = Array.splitAt (allPackNum / 2) src1
      let loSrc2, hiSrc2 = Array.splitAt (allPackNum / 2) src2
      Array.concat [| loSrc1; loSrc2; hiSrc1; hiSrc2 |]
    | _ -> raise InvalidOperandSizeException
  let result = Array.map (saturateSignedWordToUnsignedByte bld) src
  assignPackedInstr bld false ins insLen (packNum * 2) oprSize dst result
  fillZeroFromVLToMaxVL bld dst oprSize 512
  bld --!> insLen

let vpavgb ins insLen bld =
  buildPackedInstr ins insLen bld true 8<rt> SSELifter.opPavgb

let vpavgw ins insLen bld =
  buildPackedInstr ins insLen bld true 16<rt> SSELifter.opPavgw

let vpbroadcast (ins: Instruction) insLen bld packSz =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / packSz
  let allPackNum = oprSize / packSz
  let struct (dst, src) = getTwoOprs ins
  let eDst = transOprToArr bld false ins insLen packSz packNum oprSize dst
  let src =
    match src with
    | OprReg r ->
      match Register.getKind r with
      | Register.Kind.XMM ->
        let struct (_, r) = transOprToExpr128 bld false ins insLen src
        r
      | Register.Kind.GP -> transOprToExpr bld false ins insLen src
      | _ -> raise InvalidOperandException
    | OprMem _ -> transOprToExpr bld false ins insLen src
    | _ -> raise InvalidOperandException
    |> AST.xtlo packSz
  let temp = tmpVar bld packSz
  bld <+ (temp := src)
  let src = Array.init allPackNum (fun _ -> temp)
  let result =
    if haveEVEXPrx ins.VEXInfo then
      let ePrx = getEVEXPrx ins.VEXInfo
      let k = regVar bld (ePrx.AAA |> int |> Register.opmask)
      makeAssignWithMask bld ePrx k oprSize packSz eDst src (isMemOpr dst)
    else src
  assignPackedInstr bld false ins insLen packNum oprSize dst result
  fillZeroFromVLToMaxVL bld dst oprSize 512
  bld --!> insLen

let vpbroadcastb ins insLen bld = vpbroadcast ins insLen bld 8<rt>
let vpbroadcastd ins insLen bld = vpbroadcast ins insLen bld 32<rt>
let vpbroadcastw ins insLen bld = vpbroadcast ins insLen bld 16<rt>

let vpcmpeqb ins insLen bld =
  match getOperationSize ins with
  | 512<rt> -> GeneralLifter.nop ins.Address insLen bld (* FIXME: #197 *)
  | _ -> buildPackedInstr ins insLen bld true 8<rt> opPcmpeqb

let vpcmpeqd ins insLen bld =
  buildPackedInstr ins insLen bld true 32<rt> opPcmpeqd

let vpcmpeqq ins insLen bld =
  buildPackedInstr ins insLen bld true 64<rt> opPcmpeqq

let vpcmpgtb ins insLen bld =
  buildPackedInstr ins insLen bld true 8<rt> opPcmpgtb

let vpinsrb (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2, count) = getFourOprs ins
  let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
  let struct (src1B, src1A) = transOprToExpr128 bld false ins insLen src1
  let src2 = transOprToExpr bld false ins insLen src2
  let sel = getImmValue count &&& 0b1111L (* COUNT[3:0] *)
  let mask = numI64 (0xFFL <<< ((int32 sel * 8) % 64)) 64<rt>
  let amount = sel * 8L
  let t = tmpVar bld 64<rt>
  let expAmt = numI64 (amount % 64L) 64<rt>
  bld <+ (t := ((AST.zext 64<rt> src2) << expAmt) .& mask)
  if amount < 64 then
    bld <+ (dstA := (src1A .& (AST.not mask)) .| t)
    bld <+ (dstB := src1B)
  else
    bld <+ (dstA := src1A)
    bld <+ (dstB := (src1B .& (AST.not mask)) .| t)
  fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
  bld --!> insLen

let vperm2i128 ins insLen bld =
  let struct (dst, src1, src2, imm) = getFourOprs ins
  let struct (dstD, dstC, dstB, dstA) =
    transOprToExpr256 bld false ins insLen dst
  let struct (src1D, src1C, src1B, src1A) =
    transOprToExpr256 bld false ins insLen src1
  let struct (src2D, src2C, src2B, src2A) =
    transOprToExpr256 bld false ins insLen src2
  let imm = getImmValue imm
  let struct (tDstA, tDstB, tDstC, tDstD) = tmpVars4 bld 64<rt>
  bld <!-- (ins.Address, insLen)
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
  bld <+ (tDstA := src1)
  bld <+ (tDstB := src2)
  let src1, src2 = getSrc (cond 4)
  bld <+ (tDstC := src1)
  bld <+ (tDstD := src2)
  bld <+ (dstA := if imm0 = 1L then AST.num0 64<rt> else tDstA)
  bld <+ (dstB := if imm0 = 1L then AST.num0 64<rt> else tDstB)
  bld <+ (dstC := if imm1 = 1L then AST.num0 64<rt> else tDstC)
  bld <+ (dstD := if imm1 = 1L then AST.num0 64<rt> else tDstD)
  bld --!> insLen

let private getSrc cond dst e0 e1 e2 e3 e4 e5 e6 e7 bld =
  bld <+ (dst := AST.ite (cond == AST.num0 8<rt>) e0
              (AST.ite (cond == AST.num1 8<rt>) e1
              (AST.ite (cond == numI32 2 8<rt>) e2
              (AST.ite (cond == numI32 3 8<rt>) e3
              (AST.ite (cond == numI32 4 8<rt>) e4
              (AST.ite (cond == numI32 5 8<rt>) e5
              (AST.ite (cond == numI32 6 8<rt>) e6 e7)))))))

let vpermd ins insLen bld =
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (dstD, dstC, dstB, dstA) =
    transOprToExpr256 bld false ins insLen dst
  let struct (src1D, src1C, src1B, src1A) =
    transOprToExpr256 bld false ins insLen src1
  let struct (src2D, src2C, src2B, src2A) =
    transOprToExpr256 bld false ins insLen src2
  let struct (tmp1A, tmp2A, tmp1B, tmp2B) = tmpVars4 bld 32<rt>
  let struct (tmp1C, tmp2C, tmp1D, tmp2D) = tmpVars4 bld 32<rt>
  let xthi operand = AST.xthi 32<rt> operand
  let xtlo operand = AST.xtlo 32<rt> operand
  bld <!-- (ins.Address, insLen)
  bld <+ (tmp1A := xtlo src2A)
  bld <+ (tmp2A := xthi src2A)
  bld <+ (tmp1B := xtlo src2B)
  bld <+ (tmp2B := xthi src2B)
  bld <+ (tmp1C := xtlo src2C)
  bld <+ (tmp2C := xthi src2C)
  bld <+ (tmp1D := xtlo src2D)
  bld <+ (tmp2D := xthi src2D)
  let tmp = tmpVar bld 8<rt>
  let cond src pos =
    bld <+ (tmp := AST.extract src 8<rt> pos .& numI32 0b00000111 8<rt>)
  cond src1A 0
  getSrc tmp (xtlo dstA) tmp1A tmp2A tmp1B tmp2B tmp1C tmp2C tmp1D tmp2D bld
  cond src1A 32
  getSrc tmp (xthi dstA) tmp1A tmp2A tmp1B tmp2B tmp1C tmp2C tmp1D tmp2D bld
  cond src1B 0
  getSrc tmp (xtlo dstB) tmp1A tmp2A tmp1B tmp2B tmp1C tmp2C tmp1D tmp2D bld
  cond src1B 32
  getSrc tmp (xthi dstB) tmp1A tmp2A tmp1B tmp2B tmp1C tmp2C tmp1D tmp2D bld
  cond src1C 0
  getSrc tmp (xtlo dstC) tmp1A tmp2A tmp1B tmp2B tmp1C tmp2C tmp1D tmp2D bld
  cond src1C 32
  getSrc tmp (xthi dstC) tmp1A tmp2A tmp1B tmp2B tmp1C tmp2C tmp1D tmp2D bld
  cond src1D 0
  getSrc tmp (xtlo dstD) tmp1A tmp2A tmp1B tmp2B tmp1C tmp2C tmp1D tmp2D bld
  cond src1D 32
  getSrc tmp (xthi dstD) tmp1A tmp2A tmp1B tmp2B tmp1C tmp2C tmp1D tmp2D bld
  bld --!> insLen

let vpermq (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let struct (dst, src, imm) = getThreeOprs ins
  let src = transOprToArr bld true ins insLen 64<rt> 1 oprSize src
  let imm = getImmValue imm |> int
  let result = Array.init 4 (fun i -> src[ (imm >>> (i * 2)) &&& 0b11 ])
  assignPackedInstr bld false ins insLen 1 oprSize dst result
  fillZeroFromVLToMaxVL bld dst oprSize 512
  bld --!> insLen

let vpinsrd (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2, count) = getFourOprs ins
  let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
  let struct (src1B, src1A) = transOprToExpr128 bld false ins insLen src1
  let src2 = transOprToExpr bld false ins insLen src2
  let sel = getImmValue count &&& 0b11L (* COUNT[1:0] *)
  let mask = numI64 (0xFFFFFFFFL <<< ((int32 sel * 32) % 64)) 64<rt>
  let amount = sel * 32L
  let t = tmpVar bld 64<rt>
  let expAmt = numI64 (amount % 64L) 64<rt>
  bld <+ (t := ((AST.zext 64<rt> src2) << expAmt) .& mask)
  if amount < 64 then bld <+ (dstA := (src1A .& (AST.not mask)) .| t)
  else bld <+ (dstB := (src1B .& (AST.not mask)) .| t)
  fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
  bld --!> insLen

let vpinsrq (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2, count) = getFourOprs ins
  let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
  let struct (src1B, src1A) = transOprToExpr128 bld false ins insLen src1
  let src2 = transOprToExpr bld false ins insLen src2
  let sel = getImmValue count &&& 0b1L (* COUNT[0] *)
  let mask = numI64 (0xFFFFFFFFFFFFFFFFL <<< ((int32 sel * 64) % 64)) 64<rt>
  let amount = sel * 64L
  let t = tmpVar bld 64<rt>
  let expAmt = numI64 (amount % 64L) 64<rt>
  bld <+ (t := ((AST.zext 64<rt> src2) << expAmt) .& mask)
  if amount < 64 then bld <+ (dstA := (src1A .& (AST.not mask)) .| t)
  else bld <+ (dstB := (src1B .& (AST.not mask)) .| t)
  fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
  bld --!> insLen

let vpinsrw (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let packSz = 16<rt>
  let packNum = 64<rt> / packSz
  let struct (dst, src1, src2, imm8) = getFourOprs ins
  let src1 = transOprToArr bld true ins insLen packSz packNum 128<rt> src1
  let src2 = transOprToExpr bld false ins insLen src2 |> AST.xtlo packSz
  let tmps = Array.init 8 (fun _ -> tmpVar bld packSz)
  let index = (getImmValue imm8 &&& 0b111) |> int
  Array.iter2 (fun t e -> bld <+ (t := e)) tmps src1
  bld <+ (tmps[index] := src2)
  assignPackedInstr bld false ins insLen packNum 128<rt> dst tmps
  fillZeroFromVLToMaxVL bld dst 128<rt> 512
  bld --!> insLen

let vpmaxsd ins insLen bld =
  buildPackedInstr ins insLen bld true 32<rt> SSELifter.opPmaxs

let vpminub ins insLen bld =
  buildPackedInstr ins insLen bld true 8<rt> SSELifter.opPminu

let vpminud ins insLen bld =
  buildPackedInstr ins insLen bld true 32<rt> SSELifter.opPminu

let vpminsb ins insLen bld =
  buildPackedInstr ins insLen bld true 8<rt> SSELifter.opPmins

let vpminsd ins insLen bld =
  buildPackedInstr ins insLen bld true 32<rt> SSELifter.opPmins

let vpmovx (ins: Instruction) insLen bld srcSz dstSz isSignExt =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / dstSz
  let struct (dst, src) = getTwoOprs ins
  let ext = if isSignExt then AST.sext dstSz else AST.zext dstSz
  let inline extSrc num src =
    Array.init num (fun i -> AST.extract src srcSz (i * (int srcSz)))
  match src, oprSize with
  | OprMem (_, _, _, 128<rt>), 128<rt> | OprReg _, 128<rt> ->
    let sNum = oprSize / dstSz
    let struct (_, srcA) = transOprToExpr128 bld false ins insLen src
    let result = Array.map ext (extSrc sNum srcA)
    assignPackedInstr bld false ins insLen packNum oprSize dst result
    fillZeroFromVLToMaxVL bld dst oprSize 512
  | OprMem (_, _, _, 128<rt>), 256<rt> | OprReg _, 256<rt> ->
    let sNum = (oprSize / 2) / dstSz
    let src =
      let struct (srcB, srcA) = transOprToExpr128 bld false ins insLen src
      if (dstSz / srcSz) = 2 then
        Array.append (extSrc sNum srcA) (extSrc sNum srcB)
      else extSrc (sNum * 2) srcA
    let result = Array.map ext src
    assignPackedInstr bld false ins insLen packNum oprSize dst result
    fillZeroFromVLToMaxVL bld dst oprSize 512
  | OprMem (_, _, _, 256<rt>), 512<rt> | OprReg _, 512<rt> ->
    let sNum = (oprSize / 4) / dstSz
    let src =
      let struct (srcD, srcC, srcB, srcA) =
        transOprToExpr256 bld false ins insLen src
      if (dstSz / srcSz) = 2 then
        Array.concat
          [| (extSrc sNum srcA); (extSrc sNum srcB)
             (extSrc sNum srcC); (extSrc sNum srcD) |]
      else extSrc (sNum * 2) srcA
    let result = Array.map ext src
    assignPackedInstr bld false ins insLen packNum oprSize dst result

  | OprMem (_, _, _, memSz), _ ->
    let sNum = memSz / srcSz
    let src = transOprToExpr bld false ins insLen src
    let result = Array.map ext (extSrc sNum src)
    assignPackedInstr bld false ins insLen packNum oprSize dst result
    fillZeroFromVLToMaxVL bld dst oprSize 512
  | _ -> raise InvalidOperandSizeException
  bld --!> insLen

let vpmovd2m (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let packSize = 32<rt>
  let packNum = 64<rt> / packSize
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr bld false ins insLen dst
  let src = transOprToArr bld false ins insLen packSize packNum oprSize src
  let tmp = tmpVar bld 16<rt>
  bld <+ (tmp := AST.num0 16<rt>)
  let assignShf idx expr =
    bld <+ (tmp := tmp .| ((AST.zext 16<rt> expr) << (numI32 idx 16<rt>)))
  Array.map (fun e -> AST.xthi 1<rt> e) src |> Array.iteri assignShf
  bld <+ (dst := AST.zext 64<rt> tmp)
  bld --!> insLen

let private opVpmulhuw _ = opPmul AST.xthi AST.zext 32<rt> 16<rt>

let vpmulhuw ins insLen bld =
  buildPackedInstr ins insLen bld true 16<rt> opVpmulhuw

let private opVpmuludq _ =
  let low32 expr = expr .& numI64 0xffffffffL 64<rt>
  Array.map2 (fun e1 e2 -> low32 e1 .* low32 e2)

let vpmuludq ins insLen bld =
  buildPackedInstr ins insLen bld true 64<rt> opVpmuludq

let private opVpmulld _ = opPmul AST.xtlo AST.sext 32<rt> 32<rt>

let vpmulld ins insLen bld =
  buildPackedInstr ins insLen bld true 32<rt> opVpmulld

let vpor (ins: Instruction) insLen bld =
  match getOperationSize ins with
  | 512<rt> -> GeneralLifter.nop ins.Address insLen bld
  | _ -> buildPackedInstr ins insLen bld true 64<rt> opPor

let vpshufb (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSz = getOperationSize ins
  let packSz = 8<rt>
  let packNum = 64<rt> / packSz
  let struct (dst, src1, src2) = getThreeOprs ins
  let nPackSz = numI32 (int packSz) packSz
  let n64 = numI32 64 packSz
  let src1 = transOprToArr bld true ins insLen 64<rt> 1 oprSz src1
  let src2 = transOprToArr bld true ins insLen packSz packNum oprSz src2
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
      let eDst = transOprToArr bld false ins insLen packSz packNum oprSz dst
      let ePrx = getEVEXPrx ins.VEXInfo
      let k = regVar bld (ePrx.AAA |> int |> Register.opmask)
      Array.mapi2 (shuffleOfEVEX ePrx k) eDst src2
    else Array.mapi shuffle src2
  assignPackedInstr bld false ins insLen packNum oprSz dst result
  fillZeroFromVLToMaxVL bld dst oprSz 512
  bld --!> insLen

let vpshufd (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let packSize = 32<rt>
  let packNum = 64<rt> / packSize
  let allPackNum = oprSize / packSize
  let struct (dst, src1, src2) = getThreeOprs ins
  let eDst = transOprToArr bld false ins insLen packSize packNum oprSize dst
  let src = transOprToArr bld false ins insLen packSize packNum oprSize src1
  let ord = getImmValue src2 |> int
  let inline getIdx i = (i / 4 * 4) + ((ord >>> ((i &&& 0x3) * 2)) &&& 0x3)
  let result =
    if haveEVEXPrx ins.VEXInfo then
      let ePrx = getEVEXPrx ins.VEXInfo
      let k = regVar bld (ePrx.AAA |> int |> Register.opmask)
      let src =
        if (isMemOpr src1) && ePrx.B (* B *) = 1uy then
          Array.init allPackNum (fun _ -> Array.head src)
        else src
      let src = Array.init allPackNum (fun i -> src[ getIdx i ])
      makeAssignWithMask bld ePrx k oprSize packSize eDst src false
    else
      let getIdx i = (i / 4 * 4) + ((ord >>> ((i &&& 0x3) * 2)) &&& 0x3)
      Array.init allPackNum (fun i -> src[ getIdx i ])
  assignPackedInstr bld false ins insLen packNum oprSize dst result
  fillZeroFromVLToMaxVL bld dst oprSize 512
  bld --!> insLen

let private opShiftVpackedDataLogical packSz shf src1 src2 =
  let count = src2 |> AST.zext 64<rt>
  let cond = AST.gt count (numI32 ((int packSz) - 1) 64<rt>)
  let shifted expr = AST.extract (shf (AST.zext 64<rt> expr) count) packSz 0
  Array.map (fun e -> AST.ite cond (AST.num0 packSz) (shifted e)) src1

let private vpsll (ins: Instruction) insLen bld packSz =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / packSz
  let struct (dst, src1, src2) = getThreeOprs ins
  let src1 = transOprToArr bld true ins insLen packSz packNum oprSize src1
  let src2 =
    match src2 with
    | OprImm _ ->
      transOprToExpr bld false ins insLen src2 |> AST.xtlo packSz
    | _ ->
      let struct (_, e) = transOprToExpr128 bld false ins insLen src2
      e
  let result = opShiftVpackedDataLogical packSz (<<) src1 src2
  assignPackedInstr bld false ins insLen packNum oprSize dst result
  fillZeroFromVLToMaxVL bld dst oprSize 512
  bld --!> insLen

let vpslld ins insLen bld =
  match getOperationSize ins with
  | 512<rt> -> GeneralLifter.nop ins.Address insLen bld
  | _ -> vpsll ins insLen bld 32<rt>

let vpsllq ins insLen bld = vpsll ins insLen bld 64<rt>

let vpslldq (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src, cnt) = getThreeOprs ins
  let cnt = getImmValue cnt
  let cnt = if cnt > 15L then 16L else cnt
  let amount = cnt * 8L
  let rightAmt = numI64 (64L - (amount % 64L)) 64<rt>
  let leftAmt = numI64 (amount % 64L) 64<rt>
  let oprSize = getOperationSize ins
  match oprSize with
  | 128<rt> ->
    let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
    let struct (srcB, srcA) = transOprToExpr128 bld false ins insLen src
    let struct (tSrcB, tSrcA) = tmpVars2 bld 64<rt>
    bld <+ (tSrcA := srcA)
    bld <+ (tSrcB := srcB)
    if amount < 64 then
      bld <+ (dstA := tSrcA << leftAmt)
      bld <+ (dstB := (tSrcB << leftAmt) .| (tSrcA >> rightAmt))
    elif amount < 128 then
      bld <+ (dstA := AST.num0 64<rt>)
      bld <+ (dstB := tSrcA << leftAmt)
    else
      bld <+ (dstA := AST.num0 64<rt>)
      bld <+ (dstB := AST.num0 64<rt>)
  | 256<rt> ->
    let struct (dstD, dstC, dstB, dstA) =
      transOprToExpr256 bld false ins insLen dst
    let struct (srcD, srcC, srcB, srcA) =
      transOprToExpr256 bld false ins insLen src
    let struct (tSrcD, tSrcC, tSrcB, tSrcA) = tmpVars4 bld 64<rt>
    bld <+ (tSrcA := srcA)
    bld <+ (tSrcB := srcB)
    bld <+ (tSrcC := srcC)
    bld <+ (tSrcD := srcD)
    if amount < 64 then
      bld <+ (dstA := tSrcA << leftAmt)
      bld <+ (dstB := (tSrcB << leftAmt) .| (tSrcA >> rightAmt))
      bld <+ (dstC := tSrcC << leftAmt)
      bld <+ (dstD := (tSrcD << leftAmt) .| (tSrcC >> rightAmt))
    elif amount < 128 then
      bld <+ (dstA := AST.num0 64<rt>)
      bld <+ (dstB := tSrcA << leftAmt)
      bld <+ (dstC := AST.num0 64<rt>)
      bld <+ (dstD := tSrcC << leftAmt)
    else
      bld <+ (dstA := AST.num0 64<rt>)
      bld <+ (dstB := AST.num0 64<rt>)
      bld <+ (dstC := AST.num0 64<rt>)
      bld <+ (dstD := AST.num0 64<rt>)
  | _ -> raise InvalidOperandSizeException
  fillZeroFromVLToMaxVL bld dst oprSize 512
  bld --!> insLen

let private shiftPackedDataRight (ins: Instruction) insLen bld packSize shf =
  bld <!-- (ins.Address, insLen)
  let oprSz = getOperationSize ins
  let packNum = 64<rt> / packSize
  let struct (dst, src1, src2) = getThreeOprs ins
  let src1 = transOprToArr bld false ins insLen packSize packNum oprSz src1
  let src2 =
    match src2 with
    | OprImm _ -> transOprToExpr bld false ins insLen src2
    | _ -> let struct (_, e) = transOprToExpr128 bld false ins insLen src2 in e
  let struct (tCnt, max) = tmpVars2 bld 64<rt>
  let cnt = tmpVar bld packSize
  bld <+ (max := numI32 (int packSize) 64<rt>)
  bld <+ (tCnt := AST.xtlo 64<rt> src2)
  bld <+ (tCnt := AST.ite (tCnt .> max .- AST.num1 64<rt>) max tCnt)
  bld <+ (cnt := AST.xtlo packSize tCnt)
  let result = Array.map (fun e -> shf e cnt) src1
  assignPackedInstr bld false ins insLen packNum oprSz dst result
  fillZeroFromVLToMaxVL bld dst oprSz 512
  bld --!> insLen

let vpsrad ins insLen bld = shiftPackedDataRight ins insLen bld 32<rt> (?>>)
let vpsraw ins insLen bld = shiftPackedDataRight ins insLen bld 16<rt> (?>>)

let vpsravd (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSz = getOperationSize ins
  let packSize = 32<rt>
  let packNum = 64<rt> / packSize
  let struct (dst, src1, src2) = getThreeOprs ins
  let src1 = transOprToArr bld false ins insLen packSize packNum oprSz src1
  let src2 = transOprToArr bld false ins insLen packSize packNum oprSz src2
  let struct (n0, n32, max) = tmpVars3 bld packSize
  bld <+ (n0 := AST.num0 packSize)
  bld <+ (n32 := numI32 32 packSize)
  bld <+ (max := numI32 0xFFFFFFFF packSize)
  let fillSignBit e1 e2 =
    AST.ite (e2 .< n32) (e1 ?>> e2) (AST.ite (AST.xthi 1<rt> e1) max n0)
  let result = Array.map2 fillSignBit src1 src2
  assignPackedInstr bld false ins insLen packNum oprSz dst result
  fillZeroFromVLToMaxVL bld dst oprSz 512
  bld --!> insLen

let vpsrlq (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let packSz = 64<rt>
  let packNum = 64<rt> / packSz
  let struct (dst, src1, src2) = getThreeOprs ins
  let src1 = transOprToArr bld true ins insLen packSz packNum oprSize src1
  let src2 =
    match src2 with
    | OprImm _ ->
      transOprToExpr bld false ins insLen src2 |> AST.xtlo packSz
    | _ -> let struct (_, e) = transOprToExpr128 bld false ins insLen src2 in e
  let result = opShiftVpackedDataLogical packSz (>>) src1 src2
  assignPackedInstr bld false ins insLen packNum oprSize dst result
  fillZeroFromVLToMaxVL bld dst oprSize 512
  bld --!> insLen

let vpsrldq (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src, cnt) = getThreeOprs ins
  let cnt = getImmValue cnt
  let cnt = if cnt > 15L then 16L else cnt
  let amount = cnt * 8L
  let rightAmt = numI64 (amount % 64L) 64<rt>
  let leftAmt = numI64 (64L - (amount % 64L)) 64<rt>
  let oprSize = getOperationSize ins
  match oprSize with
  | 128<rt> ->
    let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
    let struct (srcB, srcA) = transOprToExpr128 bld false ins insLen src
    let struct (tSrcB, tSrcA) = tmpVars2 bld 64<rt>
    bld <+ (tSrcA := srcA)
    bld <+ (tSrcB := srcB)
    let index = (int amount) / 64
    let src = [| tSrcA; tSrcB; AST.num0 64<rt>; AST.num0 64<rt> |]
    bld <+ (dstA := (src[index + 1] << leftAmt) .| (src[index] >> rightAmt))
    bld <+ (dstB := src[index + 1] >> rightAmt)
  | 256<rt> ->
    let struct (dstD, dstC, dstB, dstA) =
      transOprToExpr256 bld false ins insLen dst
    let struct (srcD, srcC, srcB, srcA) =
      transOprToExpr256 bld false ins insLen src
    let struct (tSrcD, tSrcC, tSrcB, tSrcA) = tmpVars4 bld 64<rt>
    bld <+ (tSrcA := srcA)
    bld <+ (tSrcB := srcB)
    bld <+ (tSrcC := srcC)
    bld <+ (tSrcD := srcD)
    if amount < 64 then
      bld <+ (dstA := (tSrcB << leftAmt) .| (tSrcA >> rightAmt))
      bld <+ (dstB := tSrcB >> rightAmt)
      bld <+ (dstC := (tSrcD << leftAmt) .| (tSrcC >> rightAmt))
      bld <+ (dstD := tSrcD >> rightAmt)
    elif amount < 128 then
      bld <+ (dstA := (tSrcB >> rightAmt))
      bld <+ (dstB := AST.num0 64<rt>)
      bld <+ (dstC := tSrcD >> rightAmt)
      bld <+ (dstD := AST.num0 64<rt>)
    else
      bld <+ (dstA := AST.num0 64<rt>)
      bld <+ (dstB := AST.num0 64<rt>)
      bld <+ (dstC := AST.num0 64<rt>)
      bld <+ (dstD := AST.num0 64<rt>)
  | _ -> raise InvalidOperandSizeException
  fillZeroFromVLToMaxVL bld dst oprSize 512
  bld --!> insLen

let vpsrld ins insLen bld = shiftPackedDataRight ins insLen bld 32<rt> (>>)
let vpsrlw ins insLen bld = shiftPackedDataRight ins insLen bld 16<rt> (>>)

let vpsubb ins insLen bld =
  buildPackedInstr ins insLen bld true 8<rt> (opP (.-))

let vpsubd ins insLen bld =
  buildPackedInstr ins insLen bld true 32<rt> (opP (.-))

let vptest ins insLen bld =
  if getOperationSize ins = 128<rt> then SSELifter.ptest ins insLen bld
  else
    bld <!-- (ins.Address, insLen)
    let struct (src1, src2) = getTwoOprs ins
    let struct (src1D, src1C, src1B, src1A) =
      transOprToExpr256 bld false ins insLen src1
    let struct (src2D, src2C, src2B, src2A) =
      transOprToExpr256 bld false ins insLen src2
    let struct (t1, t2, t3, t4) = tmpVars4 bld 64<rt>
    let struct (t5, t6, t7, t8) = tmpVars4 bld 64<rt>
    bld <+ (t1 := src2A .& src1A)
    bld <+ (t2 := src2B .& src1B)
    bld <+ (t3 := src2C .& src1C)
    bld <+ (t4 := src2D .& src1D)
    bld <+ (regVar bld R.ZF := (t1 .| t2 .| t3 .| t4) == (AST.num0 64<rt>))
    bld <+ (t5 := src2A .& AST.not src1A)
    bld <+ (t6 := src2B .& AST.not src1B)
    bld <+ (t7 := src2C .& AST.not src1C)
    bld <+ (t8 := src2D .& AST.not src1D)
    bld <+ (regVar bld R.CF := (t5 .| t6 .| t7 .| t8) == (AST.num0 64<rt>))
    bld <+ (regVar bld R.AF := AST.b0)
    bld <+ (regVar bld R.OF := AST.b0)
    bld <+ (regVar bld R.PF := AST.b0)
    bld <+ (regVar bld R.SF := AST.b0)
#if EMULATION
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
    bld --!> insLen

let vpunpckhdq ins insLen bld =
  buildPackedInstr ins insLen bld true 32<rt> opUnpackHighData

let vpunpckhqdq ins insLen bld =
  buildPackedInstr ins insLen bld true 64<rt> opUnpackHighData

let vpunpckhwd ins insLen bld = unpackLowHighData ins insLen bld 16<rt> true
let vpunpcklwd ins insLen bld = unpackLowHighData ins insLen bld 16<rt> false

let vpunpckldq ins insLen bld =
  buildPackedInstr ins insLen bld true 32<rt> opUnpackLowData

let vpunpcklqdq ins insLen bld =
  buildPackedInstr ins insLen bld true 64<rt> opUnpackLowData

let vpxor (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let oprSize = getOperationSize ins
  match oprSize with
  | 128<rt> ->
    let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
    let struct (src1B, src1A) = transOprToExpr128 bld false ins insLen src1
    let struct (src2B, src2A) = transOprToExpr128 bld false ins insLen src2
    bld <+ (dstB := src1B <+> src2B)
    bld <+ (dstA := src1A <+> src2A)
  | 256<rt> ->
    let struct (dstD, dstC, dstB, dstA) =
      transOprToExpr256 bld false ins insLen dst
    let struct (src1D, src1C, src1B, src1A) =
      transOprToExpr256 bld false ins insLen src1
    let struct (src2D, src2C, src2B, src2A) =
      transOprToExpr256 bld false ins insLen src2
    bld <+ (dstD := src1D <+> src2D)
    bld <+ (dstC := src1C <+> src2C)
    bld <+ (dstB := src1B <+> src2B)
    bld <+ (dstA := src1A <+> src2A)
  | _ -> raise InvalidOperandSizeException
  fillZeroFromVLToMaxVL bld dst 128<rt> 512
  bld --!> insLen

let vpxord (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSz = getOperationSize ins
  let packSz = 32<rt>
  let packNum = 64<rt> / packSz
  let struct (dst, src1, src2) = getThreeOprs ins
  let tDst = transOprToArr bld false ins insLen packSz packNum oprSz dst
  let tSrc1 = transOprToArr bld false ins insLen packSz packNum oprSz src1
  let tSrc2 = transOprToArr bld false ins insLen packSz packNum oprSz src2
  let result =
    if haveEVEXPrx ins.VEXInfo then
      let isSrc2Mem = isMemOpr src2
      let ePrx = getEVEXPrx ins.VEXInfo
      let k = regVar bld (ePrx.AAA |> int |> Register.opmask)
      makeAssignEVEX bld ePrx k oprSz packSz tDst tSrc1 tSrc2 (<+>) isSrc2Mem
    else Array.map2 (<+>) tSrc1 tSrc2
  assignPackedInstr bld false ins insLen packNum oprSz dst result
  fillZeroFromVLToMaxVL bld dst oprSz 512
  bld --!> insLen

let vzeroupper (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let n0 = AST.num0 64<rt>
  bld <+ (pseudoRegVar bld R.YMM0 3 := n0)
  bld <+ (pseudoRegVar bld R.YMM0 4 := n0)
  bld <+ (pseudoRegVar bld R.YMM1 3 := n0)
  bld <+ (pseudoRegVar bld R.YMM1 4 := n0)
  bld <+ (pseudoRegVar bld R.YMM2 3 := n0)
  bld <+ (pseudoRegVar bld R.YMM2 4 := n0)
  bld <+ (pseudoRegVar bld R.YMM3 3 := n0)
  bld <+ (pseudoRegVar bld R.YMM3 4 := n0)
  bld <+ (pseudoRegVar bld R.YMM4 3 := n0)
  bld <+ (pseudoRegVar bld R.YMM4 4 := n0)
  bld <+ (pseudoRegVar bld R.YMM5 3 := n0)
  bld <+ (pseudoRegVar bld R.YMM5 4 := n0)
  bld <+ (pseudoRegVar bld R.YMM6 3 := n0)
  bld <+ (pseudoRegVar bld R.YMM6 4 := n0)
  bld <+ (pseudoRegVar bld R.YMM7 3 := n0)
  bld <+ (pseudoRegVar bld R.YMM7 4 := n0)
  if is64bit bld then
    bld <+ (pseudoRegVar bld R.YMM8 3 := n0)
    bld <+ (pseudoRegVar bld R.YMM8 4 := n0)
    bld <+ (pseudoRegVar bld R.YMM9 3 := n0)
    bld <+ (pseudoRegVar bld R.YMM9 4 := n0)
    bld <+ (pseudoRegVar bld R.YMM10 3 := n0)
    bld <+ (pseudoRegVar bld R.YMM10 4 := n0)
    bld <+ (pseudoRegVar bld R.YMM11 3 := n0)
    bld <+ (pseudoRegVar bld R.YMM11 4 := n0)
    bld <+ (pseudoRegVar bld R.YMM12 3 := n0)
    bld <+ (pseudoRegVar bld R.YMM12 4 := n0)
    bld <+ (pseudoRegVar bld R.YMM13 3 := n0)
    bld <+ (pseudoRegVar bld R.YMM13 4 := n0)
    bld <+ (pseudoRegVar bld R.YMM14 3 := n0)
    bld <+ (pseudoRegVar bld R.YMM14 4 := n0)
    bld <+ (pseudoRegVar bld R.YMM15 3 := n0)
    bld <+ (pseudoRegVar bld R.YMM15 4 := n0)
  bld --!> insLen

let vfmadd132sd (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src2, src3) = getThreeOprs ins
  let struct (_dstB, dstA) = transOprToExpr128 bld false ins insLen dst
  let src2 = transOprToExpr64 bld false ins insLen src2
  let src3 = transOprToExpr64 bld false ins insLen src3
  let tmp = tmpVar bld 64<rt>
  bld <+ (tmp := AST.fmul dstA src3)
  bld <+ (dstA := AST.fadd tmp src2)
  fillZeroFromVLToMaxVL bld dst 128<rt> 512
  bld --!> insLen

let vfmadd213sd (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src2, src3) = getThreeOprs ins
  let struct (_dstB, dstA) = transOprToExpr128 bld false ins insLen dst
  let src2 = transOprToExpr64 bld false ins insLen src2
  let src3 = transOprToExpr64 bld false ins insLen src3
  let tmp = tmpVar bld 64<rt>
  bld <+ (tmp := AST.fmul dstA src2)
  bld <+ (dstA := AST.fadd tmp src3)
  fillZeroFromVLToMaxVL bld dst 128<rt> 512
  bld --!> insLen

let vfmadd231sd (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src2, src3) = getThreeOprs ins
  let struct (_dstB, dstA) = transOprToExpr128 bld false ins insLen dst
  let src2 = transOprToExpr64 bld false ins insLen src2
  let src3 = transOprToExpr64 bld false ins insLen src3
  let tmp = tmpVar bld 64<rt>
  bld <+ (tmp := AST.fmul src2 src3)
  bld <+ (dstA := AST.fadd dstA tmp)
  fillZeroFromVLToMaxVL bld dst 128<rt> 512
  bld --!> insLen
