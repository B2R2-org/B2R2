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

/// The value a lane the opmask masks off keeps: zeroed under {z}, left as it
/// was otherwise. A masked store leaves the memory lane alone either way.
let private maskedOut (ins: Instruction) isMem packSz dst =
  if isMem || not ins.IsZeroing then dst else AST.num0 packSz

/// Writes each lane of src to a fresh temporary, under the opmask. An
/// instruction with no opmask writes every lane, so it gets no mask logic at
/// all rather than a comparison against K0 that is true by construction.
let private makeAssignWithMask bld ins oprSize packSz dst src isMem =
  let packNum = oprSize / packSz
  let tmp = Array.init packNum (fun _ -> tmpVar bld packSz)
  let mask =
    match opMaskVar bld ins with
    | ValueNone ->
      fun _ _ src -> src
    | ValueSome k ->
      fun idx dst src ->
        AST.ite (AST.extract k 1<rt> idx) src (maskedOut ins isMem packSz dst)
  Array.mapi2 mask dst src
  |> Array.iter2 (fun e1 e2 -> append bld { direct e1 := e2 }) tmp
  tmp

/// The masked lanes of a three-operand EVEX operation. An embedded broadcast
/// needs nothing here: transOprToArr already gave every lane of src2 the one
/// element the source named.
let private makeAssignEVEX bld ins oprSz packSz dst src1 src2 opFn =
  let packNum = oprSz / packSz
  let tmp = Array.init packNum (fun _ -> tmpVar bld packSz)
  let mask =
    match opMaskVar bld ins with
    | ValueNone ->
      fun _ src1 src2 -> opFn src1 src2
    | ValueSome k ->
      fun idx src1 src2 ->
        let dst = maskedOut ins false packSz (Array.item idx dst)
        AST.ite (AST.extract k 1<rt> idx) (opFn src1 src2) dst
  Array.mapi2 mask src1 src2
  |> Array.iter2 (fun e1 e2 -> append bld { direct e1 := e2 }) tmp
  tmp

let private buildPackedFPInstr ins bld packSz opFn =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src1, src2) = getThreeOprs ins
    let src1 = transOprToArr ins bld false packSz packNum oprSize src1
    let src2 = transOprToArr ins bld false packSz packNum oprSize src2
    let src = Array.map2 opFn src1 src2
    assignPackedInstr ins bld false packNum oprSize dst src
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let private vexedScalarFPBinOp (ins: Instruction) bld sz op =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dst2, dst1) = transOpr128 ins bld false dst
    let struct (src1B, src1A) = transOpr128 ins bld false src1
    match sz with
    | 32<rt> ->
      let src2 = transOpr32 ins bld false src2
      direct (AST.xtlo 32<rt> dst1) := op (AST.xtlo 32<rt> src1A) src2
      direct (AST.xthi 32<rt> dst1) := AST.xthi 32<rt> src1A
    | 64<rt> ->
      let src2 = transOpr64 ins bld false src2
      direct dst1 := op src1A src2
    | _ ->
      raise InvalidOperandSizeException
    direct dst2 := src1B
    fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
  }

let vsqrtps ins bld =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packNum = 64<rt> / 32<rt>
    let struct (dst, src) = getTwoOprs ins
    let src = transOprToArr ins bld false 32<rt> packNum oprSize src
    let result = Array.map (AST.unop UnOpType.FSQRT) src
    assignPackedInstr ins bld false packNum oprSize dst result
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let vsqrtpd ins bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let oprSz = getOperationSize ins
    match oprSz with
    | 128<rt> ->
      let struct (dst2, dst1) = transOpr128 ins bld false dst
      let struct (src2, src1) = transOpr128 ins bld false src
      direct dst1 := AST.fsqrt src1
      direct dst2 := AST.fsqrt src2
      fillZeroHigh128 bld dst
    | 256<rt> ->
      let struct (dst4, dst3, dst2, dst1) =
        transOpr256 ins bld false dst
      let struct (sr4, sr3, sr2, sr1) =
        transOpr256 ins bld false src
      direct dst1 := AST.fsqrt sr1
      direct dst2 := AST.fsqrt sr2
      direct dst3 := AST.fsqrt sr3
      direct dst4 := AST.fsqrt sr4
    | _ ->
      raise InvalidOperandSizeException
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

/// The VEX AES rounds: the same host call the legacy forms make, over one
/// 128-bit lane or two. A VEX.128 form writes its lane and clears everything
/// above it, and a VEX.256 form -- the VAES extension -- runs the round on
/// each lane on its own, the two sharing nothing.
let private vaesRound (ins: Instruction) bld name =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let oprSz = getOperationSize ins
    match oprSz with
    | 128<rt> ->
      let struct (dstB, dstA) = transOpr128 ins bld false dst
      let struct (aB, aA) = transOpr128 ins bld false src1
      let struct (bB, bA) = transOpr128 ins bld false src2
      let t = tmpVar bld 128<rt>
      direct t := AST.app name [ AST.concat aB aA; AST.concat bB bA ] 128<rt>
      direct dstA := AST.xtlo 64<rt> t
      direct dstB := AST.xthi 64<rt> t
    | 256<rt> ->
      let struct (dstD, dstC, dstB, dstA) = transOpr256 ins bld false dst
      let struct (a4, a3, a2, a1) = transOpr256 ins bld false src1
      let struct (b4, b3, b2, b1) = transOpr256 ins bld false src2
      let struct (lo, hi) = tmpVars2 bld 128<rt>
      direct lo := AST.app name [ AST.concat a2 a1; AST.concat b2 b1 ] 128<rt>
      direct hi := AST.app name [ AST.concat a4 a3; AST.concat b4 b3 ] 128<rt>
      direct dstA := AST.xtlo 64<rt> lo
      direct dstB := AST.xthi 64<rt> lo
      direct dstC := AST.xtlo 64<rt> hi
      direct dstD := AST.xthi 64<rt> hi
    | _ ->
      raise InvalidOperandSizeException
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

let vaesenc ins bld = vaesRound ins bld "AESENC"

let vaesenclast ins bld = vaesRound ins bld "AESENCLAST"

let vaesdec ins bld = vaesRound ins bld "AESDEC"

let vaesdeclast ins bld = vaesRound ins bld "AESDECLAST"

/// VAESIMC has one source and no wider form: the inverse mixing is only ever
/// wanted a key at a time.
let vaesimc (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let struct (srcB, srcA) = transOpr128 ins bld false src
    let t = tmpVar bld 128<rt>
    direct t := AST.app "AESIMC" [ AST.concat srcB srcA ] 128<rt>
    direct dstA := AST.xtlo 64<rt> t
    direct dstB := AST.xthi 64<rt> t
    fillZeroFromVLToMaxVL bld dst 128<rt> 512
  }

/// VAESKEYGENASSIST, likewise 128-bit only, with the round constant its
/// immediate carries.
let vaeskeygenassist (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src, imm) = getThreeOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let struct (srcB, srcA) = transOpr128 ins bld false src
    let rcon = numU64 (uint64 (getImmValue imm) &&& 0xFFUL) 8<rt>
    let t = tmpVar bld 128<rt>
    let src = AST.concat srcB srcA
    direct t := AST.app "AESKEYGENASSIST" [ src; rcon ] 128<rt>
    direct dstA := AST.xtlo 64<rt> t
    direct dstB := AST.xthi 64<rt> t
    fillZeroFromVLToMaxVL bld dst 128<rt> 512
  }

/// VPCLMULQDQ: the carry-less multiply over one lane or two, its immediate
/// picking a quadword from each source within every lane it runs on.
let vpclmulqdq (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2, imm) = getFourOprs ins
    let oprSz = getOperationSize ins
    let control = numU64 (uint64 (getImmValue imm) &&& 0x11UL) 8<rt>
    match oprSz with
    | 128<rt> ->
      let struct (dstB, dstA) = transOpr128 ins bld false dst
      let struct (aB, aA) = transOpr128 ins bld false src1
      let struct (bB, bA) = transOpr128 ins bld false src2
      let t = tmpVar bld 128<rt>
      let args = [ AST.concat aB aA; AST.concat bB bA; control ]
      direct t := AST.app "PCLMULQDQ" args 128<rt>
      direct dstA := AST.xtlo 64<rt> t
      direct dstB := AST.xthi 64<rt> t
    | 256<rt> ->
      let struct (dstD, dstC, dstB, dstA) = transOpr256 ins bld false dst
      let struct (a4, a3, a2, a1) = transOpr256 ins bld false src1
      let struct (b4, b3, b2, b1) = transOpr256 ins bld false src2
      let struct (lo, hi) = tmpVars2 bld 128<rt>
      let loArgs = [ AST.concat a2 a1; AST.concat b2 b1; control ]
      let hiArgs = [ AST.concat a4 a3; AST.concat b4 b3; control ]
      direct lo := AST.app "PCLMULQDQ" loArgs 128<rt>
      direct hi := AST.app "PCLMULQDQ" hiArgs 128<rt>
      direct dstA := AST.xtlo 64<rt> lo
      direct dstB := AST.xthi 64<rt> lo
      direct dstC := AST.xtlo 64<rt> hi
      direct dstD := AST.xthi 64<rt> hi
    | _ ->
      raise InvalidOperandSizeException
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

let private vsqrts (ins: Instruction) bld sz =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dst2, dst1) = transOpr128 ins bld false dst
    let struct (src1B, src1A) = transOpr128 ins bld false src1
    match sz with
    | 32<rt> ->
      let src2 = transOpr32 ins bld false src2
      direct (AST.xtlo 32<rt> dst1) := AST.fsqrt src2
      direct (AST.xthi 32<rt> dst1) := AST.xthi 32<rt> src1A
    | 64<rt> ->
      let src2 = transOpr64 ins bld false src2
      direct dst1 := AST.fsqrt src2
    | _ ->
      raise InvalidOperandSizeException
    direct dst2 := src1B
    fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
  }

let vsqrtss ins bld = vsqrts ins bld 32<rt>

let vsqrtsd ins bld = vsqrts ins bld 64<rt>

let vaddps ins bld = buildPackedFPInstr ins bld 32<rt> AST.fadd

let vaddpd ins bld = buildPackedFPInstr ins bld 64<rt> AST.fadd

let vaddss ins bld = vexedScalarFPBinOp ins bld 32<rt> AST.fadd

let vaddsd ins bld = vexedScalarFPBinOp ins bld 64<rt> AST.fadd

let vsubps ins bld = buildPackedFPInstr ins bld 32<rt> AST.fsub

let vsubpd ins bld = buildPackedFPInstr ins bld 64<rt> AST.fsub

let vsubss ins bld = vexedScalarFPBinOp ins bld 32<rt> AST.fsub

let vsubsd ins bld = vexedScalarFPBinOp ins bld 64<rt> AST.fsub

let vmulps ins bld = buildPackedFPInstr ins bld 32<rt> AST.fmul

let vmulpd ins bld = buildPackedFPInstr ins bld 64<rt> AST.fmul

let vmulss ins bld = vexedScalarFPBinOp ins bld 32<rt> AST.fmul

let vmulsd ins bld = vexedScalarFPBinOp ins bld 64<rt> AST.fmul

let vdivps ins bld = buildPackedFPInstr ins bld 32<rt> AST.fdiv

let vdivpd ins bld = buildPackedFPInstr ins bld 64<rt> AST.fdiv

let vdivss ins bld = vexedScalarFPBinOp ins bld 32<rt> AST.fdiv

let vdivsd ins bld = vexedScalarFPBinOp ins bld 64<rt> AST.fdiv

let vcvtsi2ss (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let struct (src1B, src1A) = transOpr128 ins bld false src1
    let src2 = transOpr ins bld false src2
    direct (AST.xtlo 32<rt> dstA) := AST.cast CastKind.SIntToFloat 32<rt> src2
    direct (AST.xthi 32<rt> dstA) := AST.xthi 32<rt> src1A
    direct dstB := src1B
    fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
  }

let vcvtsi2sd (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let struct (src1B, _src1A) = transOpr128 ins bld false src1
    let src2 = transOpr ins bld false src2
    direct dstA := AST.cast CastKind.SIntToFloat 64<rt> src2
    direct dstB := src1B
    fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
  }

let vcvtsd2ss (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let struct (src1B, src1A) = transOpr128 ins bld false src1
    let src2 = transOpr64 ins bld false src2
    direct (AST.xtlo 32<rt> dstA) := AST.cast CastKind.FloatCast 32<rt> src2
    direct (AST.xthi 32<rt> dstA) := AST.xthi 32<rt> src1A
    direct dstB := src1B
    fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
  }

let vcvtss2sd (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let struct (src1B, _src1A) = transOpr128 ins bld false src1
    let src2 = transOpr32 ins bld false src2
    direct dstA := AST.cast CastKind.FloatCast 64<rt> src2
    direct dstB := src1B
    fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
  }

let vmovd (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let oprSize = getOperationSize ins
    match oprSize with
    | 32<rt> ->
      let dst = transOpr ins bld false dst
      let struct (_, srcA) = transOpr128 ins bld false src
      sized oprSize dst := AST.xtlo oprSize srcA
    | 128<rt> ->
      let struct (dstB, dstA) = transOpr128 ins bld false dst
      let src = transOpr ins bld false src
      direct dstA := AST.zext 64<rt> src
      direct dstB := AST.num0 64<rt>
      fillZeroFromVLToMaxVL bld dst oprSize 512
    | _ ->
      raise InvalidOperandSizeException
  }

let vmovq (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let oprSize = getOperationSize ins
    let n0 = AST.num0 64<rt>
    match dst, src with
    | OprReg _, OprMem _ ->
      let struct (dstB, dstA) = transOpr128 ins bld false dst
      let src = transOpr ins bld false src
      direct dstA := src
      direct dstB := n0
      fillZeroFromVLToMaxVL bld dst oprSize 512
    | OprMem _, OprReg _ ->
      let dst = transOpr ins bld false dst
      let struct (_, srcA) = transOpr128 ins bld false src
      direct dst := srcA
    | OprReg r1, OprReg r2 ->
      match RegisterHelper.getKind r1, RegisterHelper.getKind r2 with
      | RegisterHelper.Kind.XMM, RegisterHelper.Kind.GP ->
        let struct (dstB, dstA) = transOpr128 ins bld false dst
        let src = transOpr ins bld false src
        direct dstA := src
        direct dstB := n0
        fillZeroFromVLToMaxVL bld dst oprSize 512
      | RegisterHelper.Kind.GP, RegisterHelper.Kind.XMM ->
        let dst = transOpr ins bld false dst
        let struct (_, srcA) = transOpr128 ins bld false src
        direct dst := srcA
      | _ -> (* XMM, XMM *)
        let struct (dstB, dstA) = transOpr128 ins bld false dst
        let struct (_, srcA) = transOpr128 ins bld false src
        direct dstA := srcA
        direct dstB := n0
        fillZeroFromVLToMaxVL bld dst oprSize 512
    | _ ->
      raise InvalidOperandException
  }

let private buildVectorMove (ins: Instruction) bld packSz =
  lift bld ins {
    let oprSz = getOperationSize ins
    let isAVX512 = haveEVEXPrx ins.VEXInfo
    let packSz, packNum =
      if isAVX512 then packSz, 64<rt> / packSz else 64<rt>, 64<rt> / 64<rt>
    let struct (dst, src) = getTwoOprs ins
    let src = transOprToArr ins bld false packSz packNum oprSz src
    let result =
      if isAVX512 then
        let eDst = transOprToArr ins bld false packSz packNum oprSz dst
        makeAssignWithMask bld ins oprSz packSz eDst src (isMemOpr dst)
      else
        src
    assignPackedInstr ins bld false packNum oprSz dst result
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

let vmovapd ins bld = buildVectorMove ins bld 64<rt>

let vmovaps ins bld = buildVectorMove ins bld 32<rt>

let private buildVectorMoveAVX512 (ins: Instruction) bld packSz =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src) = getTwoOprs ins
    let eDst = transOprToArr ins bld false packSz packNum oprSize dst
    let src = transOprToArr ins bld false packSz packNum oprSize src
    let result =
      makeAssignWithMask bld ins oprSize packSz eDst src (isMemOpr dst)
    assignPackedInstr ins bld false packNum oprSize dst result
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let vmovdqu ins bld = buildVectorMove ins bld 64<rt>

let vmovdqu16 ins bld = buildVectorMoveAVX512 ins bld 16<rt>

let vmovdqu64 ins bld = buildVectorMoveAVX512 ins bld 64<rt>

let vmovdqa ins bld = buildVectorMove ins bld 64<rt>

let vmovdqa64 ins bld = buildVectorMoveAVX512 ins bld 64<rt>

let vmovntdq ins bld = buildMove ins bld

let vmovups ins bld = buildVectorMove ins bld 32<rt>

let vmovupd ins bld = buildVectorMove ins bld 64<rt>

let vmovddup (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let oprSize = getOperationSize ins
    match oprSize with
    | 128<rt> ->
      let struct (dst2, dst1) = transOpr128 ins bld false dst
      let src = transOpr64 ins bld false src
      direct dst1 := src
      direct dst2 := src
    | 256<rt> ->
      let struct (dst4, dst3, dst2, dst1) =
        transOpr256 ins bld false dst
      let struct (_src4, src3, _src2, src1) =
        transOpr256 ins bld false src
      direct dst1 := src1
      direct dst2 := src1
      direct dst3 := src3
      direct dst4 := src3
    | _ ->
      raise InvalidOperandSizeException
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let vmovntps ins bld = buildMove ins bld

let vmovntpd ins bld = buildMove ins bld

let vmovhlps (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let struct (src1B, _src1A) = transOpr128 ins bld false src1
    let struct (src2B, _src2A) = transOpr128 ins bld false src2
    direct dstA := src2B
    direct dstB := src1B
    fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
  }

let vmovhpd (ins: Instruction) bld =
  lift bld ins {
    match ins.Operands with
    | TwoOperands(dst, src) ->
      if haveEVEXPrx ins.VEXInfo then
        ()
      else
        let dst = transOpr64 ins bld false dst
        let struct (src2, _src1) = transOpr128 ins bld false src
        direct dst := src2
    | ThreeOperands(dst, src1, src2) ->
      let struct (dstB, dstA) = transOpr128 ins bld false dst
      let struct (_src1B, src1A) = transOpr128 ins bld false src1
      let src2 = transOpr64 ins bld false src2
      direct dstA := src1A
      direct dstB := src2
      fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
    | _ ->
      raise InvalidOperandException
  }

let vmovlhps (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let struct (_src1B, src1A) = transOpr128 ins bld true src1
    let struct (_src2B, src2A) = transOpr128 ins bld true src2
    direct dstA := src1A
    direct dstB := src2A
    fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
  }

let vmovlpd (ins: Instruction) bld =
  lift bld ins {
    match ins.Operands with
    | TwoOperands(dst, src) ->
      let dst = transOpr64 ins bld false dst
      let struct (_, srcA) = transOpr128 ins bld false src
      direct dst := srcA
    | ThreeOperands(dst, src1, src2) ->
      let struct (dstB, dstA) = transOpr128 ins bld false dst
      let struct (src1B, _src1A) = transOpr128 ins bld false src1
      let src2 = transOpr ins bld false src2
      direct dstA := src2
      direct dstB := src1B
      fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
    | _ ->
      raise InvalidOperandException
  }

let vmovmskpd ins bld =
  let struct (dst, src) = getTwoOprs ins
  let mskpd r =
    match RegisterHelper.getKind r with
    | RegisterHelper.Kind.XMM ->
      movmskpd ins bld
    | RegisterHelper.Kind.YMM ->
      lift bld ins {
        let dst = transOpr ins bld false dst
        let dstSz = Expr.typeOf dst
        let struct (src4, src3, src2, src1) =
          transOpr256 ins bld false src
        let src63 = AST.sext dstSz (AST.xthi 1<rt> src1)
        let src127 = (AST.sext dstSz (AST.xthi 1<rt> src2)) << AST.num1 dstSz
        let src191 = (AST.sext dstSz (AST.xthi 1<rt> src3)) << numI32 2 dstSz
        let src255 = (AST.sext dstSz (AST.xthi 1<rt> src4)) << numI32 3 dstSz
        direct dst := src63 .| src127 .| src191 .| src255
      }
    | _ ->
      raise InvalidOperandException
  match src with
  | OprReg r -> mskpd r
  | _ -> raise InvalidOperandSizeException

let vmovmskps ins bld =
  let struct (dst, src) = getTwoOprs ins
  let mskpd r =
    match RegisterHelper.getKind r with
    | RegisterHelper.Kind.XMM ->
      movmskps ins bld
    | RegisterHelper.Kind.YMM ->
      lift bld ins {
        let oprSz = getOperationSize ins
        let dst = transOpr ins bld false dst
        let struct (srcD, srcC, srcB, srcA) =
          transOpr256 ins bld false src
        let b0 = (srcA >> (numI32 31 64<rt>) .& (numI32 0b1 64<rt>))
        let b1 = (srcA >> (numI32 62 64<rt>) .& (numI32 0b10 64<rt>))
        let b2 = (srcB >> (numI32 29 64<rt>) .& (numI32 0b100 64<rt>))
        let b3 = (srcB >> (numI32 60 64<rt>) .& (numI32 0b1000 64<rt>))
        let b4 = (srcC >> (numI32 27 64<rt>) .& (numI32 0b10000 64<rt>))
        let b5 = (srcC >> (numI32 58 64<rt>) .& (numI32 0b100000 64<rt>))
        let b6 = (srcD >> (numI32 25 64<rt>) .& (numI32 0b1000000 64<rt>))
        let b7 = (srcD >> (numI32 56 64<rt>) .& (numI32 0b10000000 64<rt>))
        let bits = b7 .| b6 .| b5 .| b4 .| b3 .| b2 .| b1 .| b0
        sized oprSz dst := bits
      }
    | _ ->
      raise InvalidOperandException
  match src with
  | OprReg r -> mskpd r
  | _ -> raise InvalidOperandSizeException

let vmovsd (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprMem _, _) ->
    movsd ins bld
  | TwoOperands(OprReg _ as dst, src) ->
    lift bld ins {
      let struct (dst2, dst1) = transOpr128 ins bld false dst
      let src = transOpr64 ins bld false src
      direct dst1 := src
      direct dst2 := AST.num0 64<rt>
      fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
    }
  | ThreeOperands(dst, src1, src2) ->
    lift bld ins {
      let struct (dstB, dstA) = transOpr128 ins bld false dst
      let struct (src1B, _src1A) = transOpr128 ins bld false src1
      let struct (_src2B, src2A) = transOpr128 ins bld false src2
      direct dstA := src2A
      direct dstB := src1B
      fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
    }
  | _ ->
    raise InvalidOperandException

let vmovshdup ins bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let oprSize = getOperationSize ins
    match oprSize with
    | 128<rt> ->
      let struct (dst2, dst1) = transOpr128 ins bld false dst
      let struct (src2, src1) = transOpr128 ins bld false src
      direct (AST.xtlo 32<rt> dst1) := AST.xthi 32<rt> src1
      direct (AST.xthi 32<rt> dst1) := AST.xthi 32<rt> src1
      direct (AST.xtlo 32<rt> dst2) := AST.xthi 32<rt> src2
      direct (AST.xthi 32<rt> dst2) := AST.xthi 32<rt> src2
    | 256<rt> ->
      let struct (dst4, dst3, dst2, dst1) =
        transOpr256 ins bld false dst
      let struct (src4, src3, src2, src1) =
        transOpr256 ins bld false src
      direct (AST.xtlo 32<rt> dst1) := AST.xthi 32<rt> src1
      direct (AST.xthi 32<rt> dst1) := AST.xthi 32<rt> src1
      direct (AST.xtlo 32<rt> dst2) := AST.xthi 32<rt> src2
      direct (AST.xthi 32<rt> dst2) := AST.xthi 32<rt> src2
      direct (AST.xtlo 32<rt> dst3) := AST.xthi 32<rt> src3
      direct (AST.xthi 32<rt> dst3) := AST.xthi 32<rt> src3
      direct (AST.xtlo 32<rt> dst4) := AST.xthi 32<rt> src4
      direct (AST.xthi 32<rt> dst4) := AST.xthi 32<rt> src4
    | _ ->
      raise InvalidOperandSizeException
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let vmovsldup ins bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let oprSize = getOperationSize ins
    match oprSize with
    | 128<rt> ->
      let struct (dst2, dst1) = transOpr128 ins bld false dst
      let struct (src2, src1) = transOpr128 ins bld false src
      direct (AST.xtlo 32<rt> dst1) := AST.xtlo 32<rt> src1
      direct (AST.xthi 32<rt> dst1) := AST.xtlo 32<rt> src1
      direct (AST.xtlo 32<rt> dst2) := AST.xtlo 32<rt> src2
      direct (AST.xthi 32<rt> dst2) := AST.xtlo 32<rt> src2
    | 256<rt> ->
      let struct (dst4, dst3, dst2, dst1) =
        transOpr256 ins bld false dst
      let struct (src4, src3, src2, src1) =
        transOpr256 ins bld false src
      direct (AST.xtlo 32<rt> dst1) := AST.xtlo 32<rt> src1
      direct (AST.xthi 32<rt> dst1) := AST.xtlo 32<rt> src1
      direct (AST.xtlo 32<rt> dst2) := AST.xtlo 32<rt> src2
      direct (AST.xthi 32<rt> dst2) := AST.xtlo 32<rt> src2
      direct (AST.xtlo 32<rt> dst3) := AST.xtlo 32<rt> src3
      direct (AST.xthi 32<rt> dst3) := AST.xtlo 32<rt> src3
      direct (AST.xtlo 32<rt> dst4) := AST.xtlo 32<rt> src4
      direct (AST.xthi 32<rt> dst4) := AST.xtlo 32<rt> src4
    | _ ->
      raise InvalidOperandSizeException
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let vmovss (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprMem _, _) ->
    movss ins bld
  | TwoOperands(OprReg _ as dst, src) ->
    lift bld ins {
      let struct (dst2, dst1) = transOpr128 ins bld false dst
      let src = transOpr32 ins bld false src
      direct (AST.xtlo 32<rt> dst1) := src
      direct (AST.xthi 32<rt> dst1) := AST.num0 32<rt>
      direct dst2 := AST.num0 64<rt>
      fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
    }
  | ThreeOperands(dst, src1, src2) ->
    lift bld ins {
      let struct (dstB, dstA) = transOpr128 ins bld false dst
      let struct (src1B, src1A) = transOpr128 ins bld false src1
      let struct (_src2B, src2A) = transOpr128 ins bld false src2
      direct (AST.xtlo 32<rt> dstA) := AST.xtlo 32<rt> src2A
      direct (AST.xthi 32<rt> dstA) := AST.xthi 32<rt> src1A
      direct dstB := src1B
      fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
    }
  | _ ->
    raise InvalidOperandException

let vandps ins bld = buildPackedFPInstr ins bld 32<rt> (.&)

let vandpd ins bld = buildPackedFPInstr ins bld 64<rt> (.&)

let private andnpdOp e1 e2 = (AST.not e1) .& e2

let vandnps ins bld = buildPackedFPInstr ins bld 32<rt> andnpdOp

let vandnpd ins bld = buildPackedFPInstr ins bld 64<rt> andnpdOp

let vorps ins bld = buildPackedFPInstr ins bld 32<rt> (.|)

let vorpd ins bld = buildPackedFPInstr ins bld 64<rt> (.|)

/// Copies `dst.Length` lanes of `src`, starting at lane `first`, into `dst`.
let private copyLanes bld (dst: Expr[]) (src: Expr[]) first =
  for i in 0 .. dst.Length - 1 do
    append bld { direct (dst[i]) := src[first + i] }

/// Picks the four 128-bit lanes of a 512-bit shuffle, two from each source,
/// under the four two-bit control fields of the immediate.
let private vshufLanes512 bld pNum packSz imm8 (src1, tmpSrc2) =
  let parts =
    Array.init 4 (fun _ -> Array.init pNum (fun _ -> tmpVar bld packSz))
  for i in 0 .. 3 do
    let src = if i < 2 then src1 else tmpSrc2
    copyLanes bld parts[i] src ((((imm8 >>> (i * 2)) &&& 0b11L) |> int) * pNum)
  Array.concat parts

let vshufi32x4 (ins: Instruction) bld =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packSz = 32<rt>
    let packNum = 64<rt> / packSz
    let struct (dst, src1, src2, imm) = getFourOprs ins
    let src1 = transOprToArr ins bld false packSz packNum oprSize src1
    let src2 = transOprToArr ins bld false packSz packNum oprSize src2
    let imm8 = getImmValue imm
    let tmpSrc2 = Array.init (oprSize / packSz) (fun _ -> tmpVar bld 32<rt>)
    copyLanes bld tmpSrc2 src2 0
    let orgDst = transOprToArr ins bld false packSz packNum oprSize dst
    let tDst =
      match oprSize with
      | 256<rt> ->
        let halfPNum = oprSize / packSz / 2
        let tDstA = Array.init halfPNum (fun _ -> tmpVar bld packSz)
        let tDstB = Array.init halfPNum (fun _ -> tmpVar bld packSz)
        copyLanes bld tDstA src1 ((imm8 &&& 0b1L |> int) * halfPNum)
        copyLanes bld tDstB src2 (((imm8 >>> 1) &&& 0b1L |> int) * halfPNum)
        Array.append tDstA tDstB
      | 512<rt> ->
        vshufLanes512 bld (oprSize / packSz / 4) packSz imm8 (src1, tmpSrc2)
      | _ ->
        raise InvalidOperandException
    let result = makeAssignWithMask bld ins oprSize packSz orgDst tDst false
    assignPackedInstr ins bld false packNum oprSize dst result
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let private doShuf bld cond dst e1 e2 =
  append bld {
    direct dst := AST.num0 32<rt>
    direct dst := AST.ite (cond == AST.num0 8<rt>) (AST.xtlo 32<rt> e1) dst
    direct dst := AST.ite (cond == AST.num1 8<rt>) (AST.xthi 32<rt> e1) dst
    direct dst := AST.ite (cond == numI32 2 8<rt>) (AST.xtlo 32<rt> e2) dst
    direct dst := AST.ite (cond == numI32 3 8<rt>) (AST.xthi 32<rt> e2) dst
  }

let private makeShufCond imm shfAmt =
  ((AST.xtlo 8<rt> imm) >> (numI32 shfAmt 8<rt>)) .& (numI32 0b11 8<rt>)

let vshufps (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2, imm) = getFourOprs ins
    let imm = transOpr ins bld false imm
    let oprSize = getOperationSize ins
    match oprSize with
    | 128<rt> ->
      let struct (dstB, dstA) = transOpr128 ins bld false dst
      let struct (sr1B, sr1A) = transOpr128 ins bld true src1
      let struct (sr2B, sr2A) = transOpr128 ins bld true src2
      doShuf bld (makeShufCond imm 0) (AST.xtlo 32<rt> dstA) sr1A sr1B
      doShuf bld (makeShufCond imm 2) (AST.xthi 32<rt> dstA) sr1A sr1B
      doShuf bld (makeShufCond imm 4) (AST.xtlo 32<rt> dstB) sr2A sr2B
      doShuf bld (makeShufCond imm 6) (AST.xthi 32<rt> dstB) sr2A sr2B
    | 256<rt> ->
      let struct (dstD, dstC, dstB, dstA) =
        transOpr256 ins bld false dst
      let struct (sr1D, sr1C, sr1B, sr1A) =
        transOpr256 ins bld true src1
      let struct (sr2D, sr2C, sr2B, sr2A) =
        transOpr256 ins bld true src2
      doShuf bld (makeShufCond imm 0) (AST.xtlo 32<rt> dstA) sr1A sr1B
      doShuf bld (makeShufCond imm 2) (AST.xthi 32<rt> dstA) sr1A sr1B
      doShuf bld (makeShufCond imm 4) (AST.xtlo 32<rt> dstB) sr2A sr2B
      doShuf bld (makeShufCond imm 6) (AST.xthi 32<rt> dstB) sr2A sr2B
      doShuf bld (makeShufCond imm 0) (AST.xtlo 32<rt> dstC) sr1C sr1D
      doShuf bld (makeShufCond imm 2) (AST.xthi 32<rt> dstC) sr1C sr1D
      doShuf bld (makeShufCond imm 4) (AST.xtlo 32<rt> dstD) sr2C sr2D
      doShuf bld (makeShufCond imm 6) (AST.xthi 32<rt> dstD) sr2C sr2D
    | _ ->
      raise InvalidOperandSizeException
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let vshufpd (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2, imm) = getFourOprs ins
    let imm = transOpr ins bld false imm
    let cond1 = AST.xtlo 1<rt> imm
    let cond2 = AST.extract imm 1<rt> 1
    let cond3 = AST.extract imm 1<rt> 2
    let cond4 = AST.extract imm 1<rt> 3
    let oprSize = getOperationSize ins
    match oprSize with
    | 128<rt> ->
      let struct (dstB, dstA) = transOpr128 ins bld false dst
      let struct (src1B, src1A) = transOpr128 ins bld true src1
      let struct (src2B, src2A) = transOpr128 ins bld true src2
      direct dstA := AST.ite cond1 src1B src1A
      direct dstB := AST.ite cond2 src2B src2A
    | 256<rt> ->
      let struct (dstD, dstC, dstB, dstA) =
        transOpr256 ins bld false dst
      let struct (sr1D, sr1C, sr1B, sr1A) =
        transOpr256 ins bld true src1
      let struct (sr2D, sr2C, sr2B, sr2A) =
        transOpr256 ins bld true src2
      direct dstA := AST.ite cond1 sr1B sr1A
      direct dstB := AST.ite cond2 sr2B sr2A
      direct dstC := AST.ite cond3 sr1D sr1C
      direct dstD := AST.ite cond4 sr2D sr2C
    | _ ->
      raise InvalidOperandSizeException
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let vunpckhps (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let oprSize = getOperationSize ins
    match oprSize with
    | 128<rt> ->
      let struct (dstB, dstA) = transOpr128 ins bld false dst
      let struct (src1B, _src1A) = transOpr128 ins bld false src1
      let struct (src2B, _src2A) = transOpr128 ins bld false src2
      direct (AST.xtlo 32<rt> dstA) := AST.xtlo 32<rt> src1B
      direct (AST.xthi 32<rt> dstA) := AST.xtlo 32<rt> src2B
      direct (AST.xtlo 32<rt> dstB) := AST.xthi 32<rt> src1B
      direct (AST.xthi 32<rt> dstB) := AST.xthi 32<rt> src2B
      fillZeroHigh128 bld dst
    | 256<rt> ->
      let struct (dstD, dstC, dstB, dstA) =
        transOpr256 ins bld false dst
      let struct (sr1D, _, sr1B, _) =
        transOpr256 ins bld false src1
      let struct (sr2D, _, sr2B, _) =
        transOpr256 ins bld false src2
      direct (AST.xtlo 32<rt> dstA) := AST.xtlo 32<rt> sr1B
      direct (AST.xthi 32<rt> dstA) := AST.xtlo 32<rt> sr2B
      direct (AST.xtlo 32<rt> dstB) := AST.xthi 32<rt> sr1B
      direct (AST.xthi 32<rt> dstB) := AST.xthi 32<rt> sr2B
      direct (AST.xtlo 32<rt> dstC) := AST.xtlo 32<rt> sr1D
      direct (AST.xthi 32<rt> dstC) := AST.xtlo 32<rt> sr2D
      direct (AST.xtlo 32<rt> dstD) := AST.xthi 32<rt> sr1D
      direct (AST.xthi 32<rt> dstD) := AST.xthi 32<rt> sr2D
    | _ ->
      raise InvalidOperandSizeException
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let vunpckhpd (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let oprSize = getOperationSize ins
    match oprSize with
    | 128<rt> ->
      let struct (dstB, dstA) = transOpr128 ins bld false dst
      let struct (src1B, _src1A) = transOpr128 ins bld false src1
      let struct (src2B, _src2A) = transOpr128 ins bld false src2
      direct dstA := src1B
      direct dstB := src2B
      fillZeroHigh128 bld dst
    | 256<rt> ->
      let struct (dstD, dstC, dstB, dstA) =
        transOpr256 ins bld false dst
      let struct (sr1D, _, sr1B, _) =
        transOpr256 ins bld false src1
      let struct (sr2D, _, sr2B, _) =
        transOpr256 ins bld false src2
      direct dstA := sr1B
      direct dstB := sr2B
      direct dstC := sr1D
      direct dstD := sr2D
    | _ ->
      raise InvalidOperandSizeException
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let vunpcklps (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let oprSize = getOperationSize ins
    match oprSize with
    | 128<rt> ->
      let struct (dstB, dstA) = transOpr128 ins bld false dst
      let struct (_src1B, src1A) = transOpr128 ins bld true src1
      let struct (_src2B, src2A) = transOpr128 ins bld true src2
      direct (AST.xtlo 32<rt> dstA) := AST.xtlo 32<rt> src1A
      direct (AST.xthi 32<rt> dstA) := AST.xtlo 32<rt> src2A
      direct (AST.xtlo 32<rt> dstB) := AST.xthi 32<rt> src1A
      direct (AST.xthi 32<rt> dstB) := AST.xthi 32<rt> src2A
      fillZeroHigh128 bld dst
    | 256<rt> ->
      let struct (dstD, dstC, dstB, dstA) =
        transOpr256 ins bld false dst
      let struct (_, src1C, _, src1A) =
        transOpr256 ins bld true src1
      let struct (_, src2C, _, src2A) =
        transOpr256 ins bld true src2
      direct (AST.xtlo 32<rt> dstA) := AST.xtlo 32<rt> src1A
      direct (AST.xthi 32<rt> dstA) := AST.xtlo 32<rt> src2A
      direct (AST.xtlo 32<rt> dstB) := AST.xthi 32<rt> src1A
      direct (AST.xthi 32<rt> dstB) := AST.xthi 32<rt> src2A
      direct (AST.xtlo 32<rt> dstC) := AST.xtlo 32<rt> src1C
      direct (AST.xthi 32<rt> dstC) := AST.xtlo 32<rt> src2C
      direct (AST.xtlo 32<rt> dstD) := AST.xthi 32<rt> src1C
      direct (AST.xthi 32<rt> dstD) := AST.xthi 32<rt> src2C
    | _ ->
      raise InvalidOperandSizeException
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let vunpcklpd (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let oprSize = getOperationSize ins
    match oprSize with
    | 128<rt> ->
      let struct (dstB, dstA) = transOpr128 ins bld false dst
      let struct (_src1B, src1A) = transOpr128 ins bld true src1
      let struct (_src2B, src2A) = transOpr128 ins bld true src2
      direct dstA := src1A
      direct dstB := src2A
    | 256<rt> ->
      let struct (dstD, dstC, dstB, dstA) =
        transOpr256 ins bld false dst
      let struct (_, src1C, _, src1A) =
        transOpr256 ins bld true src1
      let struct (_, src2C, _, src2A) =
        transOpr256 ins bld true src2
      direct dstA := src1A
      direct dstB := src2A
      direct dstC := src1C
      direct dstD := src2C
    | _ ->
      raise InvalidOperandSizeException
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let vxorps (ins: Instruction) bld =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packSz = 32<rt>
    let packNum = 64<rt> / packSz
    let struct (dst, src1, src2) = getThreeOprs ins
    let eDst = transOprToArr ins bld false packSz packNum oprSz dst
    let tSrc1 = transOprToArr ins bld false packSz packNum oprSz src1
    let tSrc2 = transOprToArr ins bld false packSz packNum oprSz src2
    let result =
      if haveEVEXPrx ins.VEXInfo then
        makeAssignEVEX bld ins oprSz packSz eDst tSrc1 tSrc2 (<+>)
      else
        Array.map2 (<+>) tSrc1 tSrc2
    assignPackedInstr ins bld false packNum oprSz dst result
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

let vxorpd ins bld = buildPackedFPInstr ins bld 64<rt> (<+>)

let vbroadcasti128 (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (dstD, dstC, dstB, dstA) =
      transOpr256 ins bld false dst
    let struct (srcB, srcA) = transOpr128 ins bld false src
    direct dstA := srcA
    direct dstB := srcB
    direct dstC := srcA
    direct dstD := srcB
    fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
  }

let vbroadcastss (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let src = transOpr32 ins bld false src
    let tmp = tmpVar bld 32<rt>
    let oprSize = getOperationSize ins
    match oprSize with
    | 128<rt> ->
      let struct (dst2, dst1) = transOpr128 ins bld false dst
      direct tmp := src
      direct (AST.xtlo 32<rt> dst1) := tmp
      direct (AST.xthi 32<rt> dst1) := tmp
      direct (AST.xtlo 32<rt> dst2) := tmp
      direct (AST.xthi 32<rt> dst2) := tmp
      fillZeroHigh128 bld dst
    | 256<rt> ->
      let struct (dst4, dst3, dst2, dst1) =
        transOpr256 ins bld false dst
      direct tmp := src
      direct (AST.xtlo 32<rt> dst1) := tmp
      direct (AST.xthi 32<rt> dst1) := tmp
      direct (AST.xtlo 32<rt> dst2) := tmp
      direct (AST.xthi 32<rt> dst2) := tmp
      direct (AST.xtlo 32<rt> dst3) := tmp
      direct (AST.xthi 32<rt> dst3) := tmp
      direct (AST.xtlo 32<rt> dst4) := tmp
      direct (AST.xthi 32<rt> dst4) := tmp
    | 512<rt> ->
      ()
    | _ ->
      raise InvalidOperandException
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let vextracti32x8 (ins: Instruction) bld =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packSz = 32<rt>
    let packNum = 64<rt> / packSz
    let allPackNum = oprSize / packSz
    let struct (dst, src, imm) = getThreeOprs ins
    let eDst = transOprToArr ins bld false packSz packNum oprSize dst
    let src =
      transOprToArr ins bld false packSz packNum (oprSize * 2) src
    let imm0 = getImmValue imm &&& 0b1L |> int (* imm8[0] *)
    let tmpDst = Array.sub src (allPackNum * imm0) allPackNum
    let result =
      makeAssignWithMask bld ins oprSize packSz eDst tmpDst (isMemOpr dst)
    assignPackedInstr ins bld false packNum oprSize dst result
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let vextracti128 (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src, imm) = getThreeOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let struct (srcD, srcC, srcB, srcA) =
      transOpr256 ins bld false src
    let imm = transOpr ins bld false imm
    let cond = tmpVar bld 1<rt>
    direct cond := AST.xtlo 1<rt> imm
    direct dstA := AST.ite cond srcC srcA
    direct dstB := AST.ite cond srcD srcB
    fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
  }

let vextracti64x4 (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src, imm) = getThreeOprs ins
    let struct (dstD, dstC, dstB, dstA) =
      transOpr256 ins bld false dst
    let struct (srcH, srcG, srcF, srcE, srcD, srcC, srcB, srcA) =
      transOpr512 ins bld false src
    let imm0 = getImmValue imm &&& 0b1L (* imm8[0] *)
    let struct (tDstD, tDstC, tDstB, tDstA) = tmpVars4 bld 64<rt>
    if imm0 = 0L then
      direct tDstA := srcA
      direct tDstB := srcB
      direct tDstC := srcC
      direct tDstD := srcD
    else (* imm0 = 1 *)
      direct tDstA := srcE
      direct tDstB := srcF
      direct tDstC := srcG
      direct tDstD := srcH
    let k = opMaskVar bld ins
    let isMem = isMemOpr dst
    let written idx dst tDst =
      match k with
      | ValueNone ->
        tDst
      | ValueSome k ->
        let kept = maskedOut ins isMem 64<rt> dst
        AST.ite (AST.extract k 1<rt> idx) tDst kept
    direct dstA := written 0 dstA tDstA
    direct dstB := written 1 dstB tDstB
    direct dstC := written 2 dstC tDstC
    direct dstD := written 3 dstD tDstD
  }

let vinserti128 (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2, imm) = getFourOprs ins
    let struct (dstD, dstC, dstB, dstA) =
      transOpr256 ins bld false dst
    let struct (src1D, src1C, src1B, src1A) =
      transOpr256 ins bld false src1
    let struct (src2B, src2A) = transOpr128 ins bld false src2
    let imm = transOpr ins bld false imm
    let cond = tmpVar bld 1<rt>
    direct cond := AST.xtlo 1<rt> imm
    direct dstA := AST.ite cond src1A src2A
    direct dstB := AST.ite cond src1B src2B
    direct dstC := AST.ite cond src2A src1C
    direct dstD := AST.ite cond src2B src1D
  }

let vpaddb ins bld =
  buildPackedInstr ins bld true 8<rt> (opP (.+))

let vpmullw ins bld =
  buildPackedInstr ins bld true 16<rt> MMXLifter.opPmullw

let vpaddd (ins: Instruction) bld =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packSz = 32<rt>
    let packNum = 64<rt> / packSz
    let struct (dst, src1, src2) = getThreeOprs ins
    let eDst = transOprToArr ins bld false packSz packNum oprSz dst
    let tSrc1 = transOprToArr ins bld false packSz packNum oprSz src1
    let tSrc2 = transOprToArr ins bld false packSz packNum oprSz src2
    let result =
      if haveEVEXPrx ins.VEXInfo then
        makeAssignEVEX bld ins oprSz packSz eDst tSrc1 tSrc2 (.+)
      else
        Array.map2 (.+) tSrc1 tSrc2
    assignPackedInstr ins bld false packNum oprSz dst result
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

let vpaddq ins bld =
  buildPackedInstr ins bld true 64<rt> (opP (.+))

let vpalignr (ins: Instruction) bld =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packSz = 8<rt>
    let packNum = 64<rt> / packSz
    let struct (dst, src1, src2, imm) = getFourOprs ins
    let src1 = transOprToArr ins bld false packSz packNum oprSz src1
    let src2 = transOprToArr ins bld false packSz packNum oprSz src2
    let imm = getImmValue imm |> int
    let initRes = Array.init 16 (fun _ -> tmpVar bld 8<rt>)
    Array.iter (fun e -> append bld { direct e := AST.num0 8<rt> }) initRes
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
        | _ ->
          raise InvalidOperandSizeException
    assignPackedInstr ins bld false packNum oprSz dst result
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

/// The VEX forms of the packed integer operations begin here. Each is the
/// operation the legacy encoding already carries, over a destination the
/// encoding names separately -- so the operation itself is shared, and what
/// the VEX form adds is only that the register above the vector length is
/// cleared.
let vpaddw ins bld = buildPackedInstr ins bld true 16<rt> (opP (.+))

let vpaddsb ins bld = buildPackedInstr ins bld true 8<rt> opPaddsb

let vpaddsw ins bld = buildPackedInstr ins bld true 16<rt> opPaddsw

let vpaddusb ins bld = buildPackedInstr ins bld true 8<rt> opPaddusb

let vpaddusw ins bld = buildPackedInstr ins bld true 16<rt> opPaddusw

let vpsubw ins bld = buildPackedInstr ins bld true 16<rt> (opP (.-))

let vpsubq ins bld = buildPackedInstr ins bld true 64<rt> (opP (.-))

let vpsubsb ins bld = buildPackedInstr ins bld true 8<rt> opPsubsb

let vpsubsw ins bld = buildPackedInstr ins bld true 16<rt> opPsubsw

let vpsubusb ins bld = buildPackedInstr ins bld true 8<rt> opPsubusb

let vpsubusw ins bld = buildPackedInstr ins bld true 16<rt> opPsubusw

let vpcmpeqw ins bld = buildPackedInstr ins bld true 16<rt> opPcmpeqw

let vpcmpgtw ins bld = buildPackedInstr ins bld true 16<rt> opPcmpgtw

let vpcmpgtd ins bld = buildPackedInstr ins bld true 32<rt> opPcmpgtd

let vpcmpgtq ins bld = buildPackedInstr ins bld true 64<rt> opPcmpgtq

let vpmaxsb ins bld = buildPackedInstr ins bld true 8<rt> opPmaxs

let vpmaxsw ins bld = buildPackedInstr ins bld true 16<rt> opPmaxs

let vpmaxub ins bld = buildPackedInstr ins bld true 8<rt> opPmaxu

let vpmaxuw ins bld = buildPackedInstr ins bld true 16<rt> opPmaxu

let vpmaxud ins bld = buildPackedInstr ins bld true 32<rt> opPmaxu

let vpminsw ins bld = buildPackedInstr ins bld true 16<rt> opPmins

let vpminuw ins bld = buildPackedInstr ins bld true 16<rt> opPminu

let vpmulhw ins bld = buildPackedInstr ins bld true 16<rt> opPmulhw

let vpmulhrsw ins bld = buildPackedInstr ins bld true 16<rt> opPmulhrsw

let vpmuldq ins bld = buildPackedInstr ins bld true 64<rt> opPmuldq

let vpmaddwd ins bld = buildPackedInstr ins bld true 32<rt> opPmaddwd

let vpmaddubsw ins bld = buildPackedInstr ins bld true 16<rt> opPmaddubsw

let vpabsb ins bld = buildPackedInstr ins bld true 8<rt> opPabsb

let vpabsw ins bld = buildPackedInstr ins bld true 16<rt> opPabsw

let vpabsd ins bld = buildPackedInstr ins bld true 32<rt> opPabsd

let vpunpckhbw ins bld =
  buildPackedInstr ins bld true 8<rt> opUnpackHighData

let vpunpcklbw ins bld =
  buildPackedInstr ins bld true 8<rt> opUnpackLowData

let vpand ins bld = buildPackedInstr ins bld true 64<rt> opPand

let vpandn ins bld = buildPackedInstr ins bld true 64<rt> opPandn

let vblendvpd (ins: Instruction) bld =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packNum = 64<rt> / 64<rt>
    let struct (dst, src1, src2, src3) = getFourOprs ins
    let src1 = transOprToArr ins bld false 64<rt> packNum oprSize src1
    let src2 = transOprToArr ins bld false 64<rt> packNum oprSize src2
    let src3 = transOprToArr ins bld false 64<rt> packNum oprSize src3
    let result = packedVblend src2 src1 src3
    assignPackedInstr ins bld false packNum oprSize dst result
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let vblendvps (ins: Instruction) bld =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packNum = 64<rt> / 32<rt>
    let struct (dst, src1, src2, src3) = getFourOprs ins
    let src1 = transOprToArr ins bld false 32<rt> packNum oprSize src1
    let src2 = transOprToArr ins bld false 32<rt> packNum oprSize src2
    let src3 = transOprToArr ins bld false 32<rt> packNum oprSize src3
    let result = packedVblend src2 src1 src3
    assignPackedInstr ins bld false packNum oprSize dst result
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let vpblendd (ins: Instruction) bld =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packNum = 64<rt> / 32<rt>
    let struct (dst, src1, src2, imm) = getFourOprs ins
    let src1 = transOprToArr ins bld false 32<rt> packNum oprSize src1
    let src2 = transOprToArr ins bld false 32<rt> packNum oprSize src2
    let imm = transOpr ins bld false imm
    let result = packedBlend src2 src1 imm
    assignPackedInstr ins bld false packNum oprSize dst result
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let vpblendw (ins: Instruction) bld =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packNum = 64<rt> / 16<rt>
    let struct (dst, src1, src2, imm) = getFourOprs ins
    let src1 = transOprToArr ins bld false 16<rt> packNum oprSize src1
    let src2 = transOprToArr ins bld false 16<rt> packNum oprSize src2
    let imm = transOpr ins bld false imm
    let result = packedBlend src2 src1 imm
    assignPackedInstr ins bld false packNum oprSize dst result
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let vpblendvb (ins: Instruction) bld =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packNum = 64<rt> / 8<rt>
    let struct (dst, src1, src2, src3) = getFourOprs ins
    let src1 = transOprToArr ins bld false 8<rt> packNum oprSize src1
    let src2 = transOprToArr ins bld false 8<rt> packNum oprSize src2
    let src3 = transOprToArr ins bld false 8<rt> packNum oprSize src3
    let result = packedVblend src2 src1 src3
    assignPackedInstr ins bld false packNum oprSize dst result
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let vpackusdw (ins: Instruction) bld =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packNum = 64<rt> / 32<rt>
    let allPackNum = oprSize / 32<rt>
    let struct (dst, src1, src2) = getThreeOprs ins
    let src1 = transOprToArr ins bld false 32<rt> packNum oprSize src1
    let src2 = transOprToArr ins bld false 32<rt> packNum oprSize src2
    let src =
      match oprSize with
      | 128<rt> ->
        Array.append src1 src2
      | 256<rt> ->
        let loSrc1, hiSrc1 = Array.splitAt (allPackNum / 2) src1
        let loSrc2, hiSrc2 = Array.splitAt (allPackNum / 2) src2
        Array.concat [| loSrc1; loSrc2; hiSrc1; hiSrc2 |]
      | _ ->
        raise InvalidOperandSizeException
    let result = Array.map (packWithSaturation bld 32<rt>) src
    assignPackedInstr ins bld false (packNum * 2) oprSize dst result
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let private saturateSignedWordToUnsignedByte bld expr = (* FIXME: MMXLifter *)
  let tExpr = tmpVar bld 16<rt>
  append bld { direct tExpr := expr }
  let checkMin = AST.slt tExpr (numI32 0 16<rt>)
  let checkMax = AST.sgt tExpr (numI32 255 16<rt>)
  let minNum = numU32 0u 8<rt>
  let maxNum = numU32 0xffu 8<rt>
  AST.ite checkMin minNum (AST.ite checkMax maxNum (AST.xtlo 8<rt> tExpr))

let vpackuswb (ins: Instruction) bld =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packNum = 64<rt> / 16<rt>
    let allPackNum = oprSize / 16<rt>
    let struct (dst, src1, src2) = getThreeOprs ins
    let src1 = transOprToArr ins bld false 16<rt> packNum oprSize src1
    let src2 = transOprToArr ins bld false 16<rt> packNum oprSize src2
    let src =
      match oprSize with
      | 128<rt> ->
        Array.append src1 src2
      | 256<rt> ->
        let loSrc1, hiSrc1 = Array.splitAt (allPackNum / 2) src1
        let loSrc2, hiSrc2 = Array.splitAt (allPackNum / 2) src2
        Array.concat [| loSrc1; loSrc2; hiSrc1; hiSrc2 |]
      | _ ->
        raise InvalidOperandSizeException
    let result = Array.map (saturateSignedWordToUnsignedByte bld) src
    assignPackedInstr ins bld false (packNum * 2) oprSize dst result
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let vpavgb ins bld =
  buildPackedInstr ins bld true 8<rt> SSELifter.opPavgb

let vpavgw ins bld =
  buildPackedInstr ins bld true 16<rt> SSELifter.opPavgw

let vpbroadcast (ins: Instruction) bld packSz =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packNum = 64<rt> / packSz
    let allPackNum = oprSize / packSz
    let struct (dst, src) = getTwoOprs ins
    let eDst = transOprToArr ins bld false packSz packNum oprSize dst
    let src =
      let opr =
        match src with
        | OprReg r ->
          match RegisterHelper.getKind r with
          | RegisterHelper.Kind.XMM ->
            let struct (_, r) = transOpr128 ins bld false src
            r
          | RegisterHelper.Kind.GP ->
            transOpr ins bld false src
          | _ ->
            raise InvalidOperandException
        | OprMem _ ->
          transOpr ins bld false src
        | _ ->
          raise InvalidOperandException
      opr |> AST.xtlo packSz
    let temp = tmpVar bld packSz
    direct temp := src
    let src = Array.init allPackNum (fun _ -> temp)
    let result =
      if haveEVEXPrx ins.VEXInfo then
        makeAssignWithMask bld ins oprSize packSz eDst src (isMemOpr dst)
      else
        src
    assignPackedInstr ins bld false packNum oprSize dst result
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let vpbroadcastb ins bld = vpbroadcast ins bld 8<rt>

let vpbroadcastd ins bld = vpbroadcast ins bld 32<rt>

let vpbroadcastw ins bld = vpbroadcast ins bld 16<rt>

let vpcmpeqb ins bld =
  match getOperationSize ins with
  | 512<rt> -> GeneralLifter.nop ins bld (* FIXME: #197 *)
  | _ -> buildPackedInstr ins bld true 8<rt> opPcmpeqb

let vpcmpeqd ins bld =
  buildPackedInstr ins bld true 32<rt> opPcmpeqd

let vpcmpeqq ins bld =
  buildPackedInstr ins bld true 64<rt> opPcmpeqq

let vpcmpgtb ins bld =
  buildPackedInstr ins bld true 8<rt> opPcmpgtb

let vpinsrb (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2, count) = getFourOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let struct (src1B, src1A) = transOpr128 ins bld false src1
    let src2 = transOpr ins bld false src2
    let sel = getImmValue count &&& 0b1111L (* COUNT[3:0] *)
    let mask = numI64 (0xFFL <<< ((int32 sel * 8) % 64)) 64<rt>
    let amount = sel * 8L
    let t = tmpVar bld 64<rt>
    let expAmt = numI64 (amount % 64L) 64<rt>
    direct t := ((AST.zext 64<rt> src2) << expAmt) .& mask
    if amount < 64L then
      direct dstA := (src1A .& (AST.not mask)) .| t
      direct dstB := src1B
    else
      direct dstA := src1A
      direct dstB := (src1B .& (AST.not mask)) .| t
    fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
  }

let vperm2i128 ins bld =
  lift bld ins {
    let struct (dst, src1, src2, imm) = getFourOprs ins
    let struct (dstD, dstC, dstB, dstA) =
      transOpr256 ins bld false dst
    let struct (src1D, src1C, src1B, src1A) =
      transOpr256 ins bld false src1
    let struct (src2D, src2C, src2B, src2A) =
      transOpr256 ins bld false src2
    let imm = getImmValue imm
    let struct (tDstA, tDstB, tDstC, tDstD) = tmpVars4 bld 64<rt>
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
    direct tDstA := src1
    direct tDstB := src2
    let src1, src2 = getSrc (cond 4)
    direct tDstC := src1
    direct tDstD := src2
    direct dstA := if imm0 = 1L then AST.num0 64<rt> else tDstA
    direct dstB := if imm0 = 1L then AST.num0 64<rt> else tDstB
    direct dstC := if imm1 = 1L then AST.num0 64<rt> else tDstC
    direct dstD := if imm1 = 1L then AST.num0 64<rt> else tDstD
  }

let private getSrc cond dst e0 e1 e2 e3 e4 e5 e6 e7 bld =
  append bld {
    direct dst := AST.ite (cond == AST.num0 8<rt>)
             e0
             (AST.ite (cond == AST.num1 8<rt>)
               e1
               (AST.ite (cond == numI32 2 8<rt>)
                 e2
                 (AST.ite (cond == numI32 3 8<rt>)
                   e3
                   (AST.ite (cond == numI32 4 8<rt>)
                     e4
                     (AST.ite (cond == numI32 5 8<rt>)
                       e5
                       (AST.ite (cond == numI32 6 8<rt>) e6 e7))))))
  }

let vpermd ins bld =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstD, dstC, dstB, dstA) =
      transOpr256 ins bld false dst
    let struct (src1D, src1C, src1B, src1A) =
      transOpr256 ins bld false src1
    let struct (src2D, src2C, src2B, src2A) =
      transOpr256 ins bld false src2
    let struct (tmp1A, tmp2A, tmp1B, tmp2B) = tmpVars4 bld 32<rt>
    let struct (tmp1C, tmp2C, tmp1D, tmp2D) = tmpVars4 bld 32<rt>
    let xthi operand = AST.xthi 32<rt> operand
    let xtlo operand = AST.xtlo 32<rt> operand
    direct tmp1A := xtlo src2A
    direct tmp2A := xthi src2A
    direct tmp1B := xtlo src2B
    direct tmp2B := xthi src2B
    direct tmp1C := xtlo src2C
    direct tmp2C := xthi src2C
    direct tmp1D := xtlo src2D
    direct tmp2D := xthi src2D
    let tmp = tmpVar bld 8<rt>
    let cond src pos =
      append bld {
        direct tmp := AST.extract src 8<rt> pos .& numI32 0b00000111 8<rt>
      }
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
  }

let private permuteQwordsByImm oprSize (src: Expr[]) imm =
  let imm = getImmValue imm |> int
  let sel j = (j / 4) * 4 + ((imm >>> ((j % 4) * 2)) &&& 0b11)
  Array.init (oprSize / 64<rt>) (fun j -> src[sel j])

let private permuteQwordsByIdx (src: Expr[]) idx =
  let kl = Array.length src
  let idx = idx .& numI32 (kl - 1) 64<rt>
  let pick i acc = AST.ite (idx == numI32 i 64<rt>) src[i] acc
  Array.foldBack pick [| 1 .. kl - 1 |] src[0]

let private maskQwordsWithEVEX bld (ins: Instruction) oprSize dst res =
  if haveEVEXPrx ins.VEXInfo then
    let eDst = transOprToArr ins bld false 64<rt> 1 oprSize dst
    makeAssignWithMask bld ins oprSize 64<rt> eDst res false
  else
    res

let vpermq (ins: Instruction) bld =
  lift bld ins {
    let oprSize = getOperationSize ins
    let struct (dst, src1, src2) = getThreeOprs ins
    let src1 = transOprToArr ins bld true 64<rt> 1 oprSize src1
    let result =
      match src2 with
      | OprImm _ ->
        permuteQwordsByImm oprSize src1 src2
      | _ ->
        let src2 = transOprToArr ins bld true 64<rt> 1 oprSize src2
        Array.map (permuteQwordsByIdx src1) src2
    let result = maskQwordsWithEVEX bld ins oprSize dst result
    assignPackedInstr ins bld false 1 oprSize dst result
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let vpinsrd (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2, count) = getFourOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let struct (src1B, src1A) = transOpr128 ins bld false src1
    let src2 = transOpr ins bld false src2
    let sel = getImmValue count &&& 0b11L (* COUNT[1:0] *)
    let mask = numI64 (0xFFFFFFFFL <<< ((int32 sel * 32) % 64)) 64<rt>
    let amount = sel * 32L
    let t = tmpVar bld 64<rt>
    let expAmt = numI64 (amount % 64L) 64<rt>
    direct t := ((AST.zext 64<rt> src2) << expAmt) .& mask
    if amount < 64L then
      append bld { direct dstA := (src1A .& (AST.not mask)) .| t }
    else
      append bld { direct dstB := (src1B .& (AST.not mask)) .| t }
    fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
  }

let vpinsrq (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2, count) = getFourOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let struct (src1B, src1A) = transOpr128 ins bld false src1
    let src2 = transOpr ins bld false src2
    let sel = getImmValue count &&& 0b1L (* COUNT[0] *)
    let mask = numI64 (0xFFFFFFFFFFFFFFFFL <<< ((int32 sel * 64) % 64)) 64<rt>
    let amount = sel * 64L
    let t = tmpVar bld 64<rt>
    let expAmt = numI64 (amount % 64L) 64<rt>
    direct t := ((AST.zext 64<rt> src2) << expAmt) .& mask
    if amount < 64L then
      append bld { direct dstA := (src1A .& (AST.not mask)) .| t }
    else
      append bld { direct dstB := (src1B .& (AST.not mask)) .| t }
    fillZeroFromVLToMaxVL bld dst (getOperationSize ins) 512
  }

let vpinsrw (ins: Instruction) bld =
  lift bld ins {
    let packSz = 16<rt>
    let packNum = 64<rt> / packSz
    let struct (dst, src1, src2, imm8) = getFourOprs ins
    let src1 = transOprToArr ins bld true packSz packNum 128<rt> src1
    let src2 = transOpr ins bld false src2 |> AST.xtlo packSz
    let tmps = Array.init 8 (fun _ -> tmpVar bld packSz)
    let index = (getImmValue imm8 &&& 0b111L) |> int
    Array.iter2 (fun t e -> append bld { direct t := e }) tmps src1
    direct (tmps[index]) := src2
    assignPackedInstr ins bld false packNum 128<rt> dst tmps
    fillZeroFromVLToMaxVL bld dst 128<rt> 512
  }

/// The broadcasts fill every lane from one element of the source. The element
/// is the source's lowest, and the only question each of them answers is how
/// wide it is.
let private vbroadcast (ins: Instruction) bld packSz =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src) = getTwoOprs ins
    let value =
      if packSz = 64<rt> then transOpr64 ins bld false src
      else transOpr32 ins bld false src
    let lanes = RegType.toBitWidth oprSize / RegType.toBitWidth packSz
    assignPackedInstr ins bld false packNum oprSize dst
                      (Array.create lanes value)
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let vbroadcastsd ins bld = vbroadcast ins bld 64<rt>

let vpbroadcastq ins bld = vbroadcast ins bld 64<rt>

/// VBROADCASTF128 fills both halves of a 256-bit register from one 128-bit
/// source, which is a memory operand and nothing else.
let vbroadcastf128 (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (srcB, srcA) = transOpr128 ins bld false src
    let struct (dstD, dstC, dstB, dstA) = transOpr256 ins bld false dst
    direct dstA := srcA
    direct dstB := srcB
    direct dstC := srcA
    direct dstD := srcB
    fillZeroFromVLToMaxVL bld dst 256<rt> 512
  }

/// VEXTRACTF128 takes one 128-bit lane out of a 256-bit register, the
/// immediate's low bit naming it.
let vextractf128 (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src, imm) = getThreeOprs ins
    let struct (srcD, srcC, srcB, srcA) = transOpr256 ins bld false src
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    if getImmValue imm &&& 1L = 0L then
      direct dstA := srcA
      direct dstB := srcB
    else
      direct dstA := srcC
      direct dstB := srcD
    (* Into a register the write clears what lies above it; into memory there
       is nothing above to clear. *)
    match dst with
    | OprReg _ -> fillZeroFromVLToMaxVL bld dst 128<rt> 512
    | _ -> ()
  }

/// VINSERTF128 replaces one 128-bit lane of the first source and takes the
/// other from it unchanged.
let vinsertf128 (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, s1, s2, imm) = getFourOprs ins
    let struct (aD, aC, aB, aA) = transOpr256 ins bld false s1
    let struct (bB, bA) = transOpr128 ins bld false s2
    let struct (dstD, dstC, dstB, dstA) = transOpr256 ins bld false dst
    if getImmValue imm &&& 1L = 0L then
      direct dstA := bA
      direct dstB := bB
      direct dstC := aC
      direct dstD := aD
    else
      direct dstA := aA
      direct dstB := aB
      direct dstC := bA
      direct dstD := bB
    fillZeroFromVLToMaxVL bld dst 256<rt> 512
  }

/// Zeroes every vector register, which VZEROALL does and VZEROUPPER does only
/// above the low 128 bits of each. A 32-bit guest has eight of them and a
/// 64-bit one sixteen.
let private zeroAllVectors bld is64 =
  let low = [ R.YMM0; R.YMM1; R.YMM2; R.YMM3; R.YMM4; R.YMM5; R.YMM6; R.YMM7 ]
  let high =
    [ R.YMM8
      R.YMM9
      R.YMM10
      R.YMM11
      R.YMM12
      R.YMM13
      R.YMM14
      R.YMM15 ]
  let regs = if is64 then low @ high else low
  for r in regs do
    for part in 1 .. 4 do
      append bld {
        direct (pseudoRegVar bld r part) := AST.num0 64<rt>
      }

let vzeroall (ins: Instruction) bld =
  lift bld ins {
    zeroAllVectors bld (is64bit bld)
  }

/// VTESTPS and VTESTPD test sign bits and nothing else: ZF says the sign bits
/// the two operands share are all clear, CF says the same of the source's
/// signs against the destination's inverted ones. The other four flags are
/// cleared, which is as much of the answer as the two that carry it.
let private vtest (ins: Instruction) bld packSz =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (src1, src2) = getTwoOprs ins
    let a = transOprToArr ins bld true packSz packNum oprSize src1
    let b = transOprToArr ins bld true packSz packNum oprSize src2
    let signOf (e: Expr) = AST.xthi 1<rt> e
    let anyBoth =
      Array.map2 (fun x y -> signOf x .& signOf y) a b |> Array.reduce (.|)
    let anyOnly =
      Array.map2 (fun x y -> AST.not (signOf x) .& signOf y) a b
      |> Array.reduce (.|)
    direct (regVar bld R.ZF) := AST.not anyBoth
    direct (regVar bld R.CF) := AST.not anyOnly
    direct (regVar bld R.OF) := AST.b0
    direct (regVar bld R.AF) := AST.b0
    direct (regVar bld R.PF) := AST.b0
    direct (regVar bld R.SF) := AST.b0
#if EMULATION
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let vtestps ins bld = vtest ins bld 32<rt>

let vtestpd ins bld = vtest ins bld 64<rt>

/// The variable shifts move each lane by a count of its own, and a count at or
/// past the lane's width clears it rather than wrapping.
let private vShiftVariable (ins: Instruction) bld packSz isLeft =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, s1, s2) = getDstAndSrcs ins
    let a = transOprToArr ins bld true packSz packNum oprSize s1
    let b = transOprToArr ins bld true packSz packNum oprSize s2
    let width = numI32 (RegType.toBitWidth packSz) packSz
    let result =
      Array.map2 (fun v c ->
        let shifted = if isLeft then v << c else v >> c
        AST.ite (AST.lt c width) shifted (AST.num0 packSz)) a b
    assignPackedInstr ins bld false packNum oprSize dst result
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let vpsllvd ins bld = vShiftVariable ins bld 32<rt> true

let vpsllvq ins bld = vShiftVariable ins bld 64<rt> true

let vpsrlvd ins bld = vShiftVariable ins bld 32<rt> false

let vpsrlvq ins bld = vShiftVariable ins bld 64<rt> false

/// VPSLLW shifts every word by one count, and that count is the low quadword
/// of a 128-bit source however wide the operation is -- which is why it cannot
/// ride the packed builder, whose second operand is as wide as the first.
let vpsllw (ins: Instruction) bld =
  lift bld ins {
    let oprSize = getOperationSize ins
    let struct (dst, s1, s2) = getDstAndSrcs ins
    let a = transOprToArr ins bld true 16<rt> 4 oprSize s1
    let count = tmpVar bld 16<rt>
    (* The count comes as a whole 128-bit operand or as an immediate; either
       way only its low bits mean anything, and a count past fifteen clears
       every word. *)
    let raw =
      match s2 with
      | OprImm _ -> numI64 (getImmValue s2 &&& 0xFFL) 64<rt>
      | _ -> transOpr64 ins bld true s2
    let tooFar = tmpVar bld 1<rt>
    direct tooFar := AST.gt raw (numI32 15 64<rt>)
    direct count := AST.xtlo 16<rt> raw
    let result =
      a |> Array.map (fun v ->
        AST.ite tooFar (AST.num0 16<rt>) (v << count))
    assignPackedInstr ins bld false 4 oprSize dst result
    if isVexEncoded ins then
      fillZeroFromVLToMaxVL bld dst oprSize 512
    else
      ()
  }

/// Picks one element of an array by an index only known at run time, as the
/// chain of choices that is.
let private selectByIndex (elems: Expr[]) idx =
  let mutable picked = elems[elems.Length - 1]
  for i in elems.Length - 2 .. -1 .. 0 do
    picked <- AST.ite (idx == numI32 i (Expr.typeOf idx)) elems[i] picked
  picked

/// VPERMILPS and VPERMILPD rearrange within each 128-bit lane and never
/// across: the control for a lane names one of that lane's own elements. The
/// control is either a vector, a field of each of its elements, or an
/// immediate that every lane reads the same way.
let private vpermil (ins: Instruction) bld packSz =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, s1, s2) = getDstAndSrcs ins
    let a = transOprToArr ins bld true packSz packNum oprSize s1
    let perLaneCount = 128 / RegType.toBitWidth packSz
    let mask = int64 perLaneCount - 1L
    let shift = if packSz = 64<rt> then 1 else 0
    let result =
      match s2 with
      | OprImm _ ->
        let imm = getImmValue s2
        Array.init a.Length (fun i ->
          let lane = i / perLaneCount
          (* An immediate spends the same bits on every lane for doubles, and
             two bits per element for singles. *)
          let sel =
            if packSz = 64<rt> then int ((imm >>> i) &&& 1L)
            else int ((imm >>> ((i % perLaneCount) * 2)) &&& 3L)
          a[lane * perLaneCount + sel])
      | _ ->
        let ctrl = transOprToArr ins bld true packSz packNum oprSize s2
        Array.init a.Length (fun i ->
          let lane = i / perLaneCount
          let idx = tmpVar bld packSz
          append bld {
            direct idx := (ctrl[i] >> numI32 shift packSz)
                          .& numI64 mask packSz
          }
          selectByIndex (Array.sub a (lane * perLaneCount) perLaneCount) idx)
    assignPackedInstr ins bld false packNum oprSize dst result
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let vpermilps ins bld = vpermil ins bld 32<rt>

let vpermilpd ins bld = vpermil ins bld 64<rt>

/// VPERM2F128 builds each half of the result from a 128-bit lane of either
/// source, or from nothing at all where the immediate says to zero it.
let vperm2f128 (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, s1, s2, imm) = getDstSrcsImm ins
    let imm = getImmValue imm
    let a = transOprToArr ins bld true 64<rt> 1 256<rt> s1
    let b = transOprToArr ins bld true 64<rt> 1 256<rt> s2
    let lanes = Array.append a b (* the four 128-bit lanes to choose from *)
    let half sel =
      let pick = int (sel &&& 0b11L) * 2
      [| lanes[pick]; lanes[pick + 1] |]
    let zeroed = [| AST.num0 64<rt>; AST.num0 64<rt> |]
    let low = if imm &&& 0b1000L <> 0L then zeroed else half imm
    let high =
      if imm &&& 0b10000000L <> 0L then zeroed else half (imm >>> 4)
    assignPackedInstr ins bld false 1 256<rt> dst (Array.append low high)
    fillZeroFromVLToMaxVL bld dst 256<rt> 512
  }

/// VPERMPD reorders the four quadwords of a 256-bit register by an immediate,
/// crossing the 128-bit lanes as VPERMILPD does not.
let vpermpd (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src, imm) = getThreeOprs ins
    let imm = getImmValue imm
    let a = transOprToArr ins bld true 64<rt> 1 256<rt> src
    let result = Array.init 4 (fun i -> a[int ((imm >>> (i * 2)) &&& 3L)])
    assignPackedInstr ins bld false 1 256<rt> dst result
    fillZeroFromVLToMaxVL bld dst 256<rt> 512
  }

/// VPERMPS reorders the eight doublewords by an index vector, likewise across
/// the whole register.
let vpermps (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, s1, s2) = getThreeOprs ins
    let ctrl = transOprToArr ins bld true 32<rt> 2 256<rt> s1
    let a = transOprToArr ins bld true 32<rt> 2 256<rt> s2
    let result =
      Array.init 8 (fun i ->
        let idx = tmpVar bld 32<rt>
        append bld {
          direct idx := ctrl[i] .& numI32 7 32<rt>
        }
        selectByIndex a idx)
    assignPackedInstr ins bld false 2 256<rt> dst result
    fillZeroFromVLToMaxVL bld dst 256<rt> 512
  }

/// The masked moves read or write only the elements whose mask element has
/// its sign bit set. As a load, the elements the mask leaves out come back
/// zero and their addresses are never touched; as a store, the memory they
/// would have covered is left alone -- which is why each element is a load or
/// a store of its own rather than one wide access.
let private maskedMove (ins: Instruction) bld packSz =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, s1, s2) = getDstAndSrcs ins
    let mask = transOprToArr ins bld true packSz packNum oprSize s1
    let count = RegType.toBitWidth oprSize / RegType.toBitWidth packSz
    let bytes = RegType.toByteWidth packSz
    let addressOf opr =
      match transOpr ins bld false opr with
      | Load(_, _, addr, _) -> addr
      | _ -> raise InvalidOperandException
    let elemAt addr i =
      AST.loadLE packSz (addr .+ numI32 (i * bytes) (Expr.typeOf addr))
    match dst with
    | OprMem _ ->
      let addr = addressOf dst
      let value = transOprToArr ins bld true packSz packNum oprSize s2
      for i in 0 .. count - 1 do
        let at = elemAt addr i
        append bld {
          direct at := AST.ite (AST.xthi 1<rt> mask[i]) value[i] at
        }
    | _ ->
      let addr = addressOf s2
      let result =
        Array.init count (fun i ->
          AST.ite (AST.xthi 1<rt> mask[i]) (elemAt addr i) (AST.num0 packSz))
      assignPackedInstr ins bld false packNum oprSize dst result
      fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let vmaskmovps ins bld = maskedMove ins bld 32<rt>

let vmaskmovpd ins bld = maskedMove ins bld 64<rt>

let vpmaskmovd ins bld = maskedMove ins bld 32<rt>

let vpmaskmovq ins bld = maskedMove ins bld 64<rt>

/// The conversions whose elements keep their width: an integer lane becomes a
/// float of the same size, or the other way about. The rounding a float-to-
/// integer conversion uses is the one the legacy forms use, which is to
/// nearest rather than what MXCSR says -- a gap this shares with them rather
/// than one it adds.
let private cvtSameWidth (ins: Instruction) bld packSz castKind =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src) = getTwoOprs ins
    let a = transOprToArr ins bld true packSz packNum oprSize src
    let result = a |> Array.map (AST.cast castKind packSz)
    assignPackedInstr ins bld false packNum oprSize dst result
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let vcvtdq2ps ins bld =
  cvtSameWidth ins bld 32<rt> CastKind.SIntToFloat

let vcvtps2dq ins bld =
  cvtSameWidth ins bld 32<rt> CastKind.FtoIRound

let vcvttps2dq ins bld =
  cvtSameWidth ins bld 32<rt> CastKind.FtoITrunc

/// The conversions that change a lane's width. The instruction's operation
/// size is the destination's width; the source is twice that where the lanes
/// narrow and half of it where they widen, which is how each side is read at
/// the width it really has.
let private operandWidth (bld: ILowUIRBuilder) opr =
  match opr with
  | OprReg r -> RegisterHelper.toRegType bld.WordSize r
  | OprMem(_, _, _, sz) -> sz
  | _ -> raise InvalidOperandException

let private cvtNarrowing (ins: Instruction) bld castKind =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    (* The source is as wide as its own operand -- half a 256-bit register's
       worth of doubles becomes a 128-bit register's worth of floats, and a
       128-bit source fills only half the destination, the rest coming back
       zero. *)
    let srcSize = operandWidth bld src
    let dstSize = getOperationSize ins
    let a = transOprToArr ins bld true 64<rt> 1 srcSize src
    let lanes = RegType.toBitWidth dstSize / 32
    let result =
      Array.init lanes (fun i ->
        if i < a.Length then AST.cast castKind 32<rt> a[i]
        else AST.num0 32<rt>)
    assignPackedInstr ins bld false 2 dstSize dst result
    fillZeroFromVLToMaxVL bld dst dstSize 512
  }

let private cvtWidening (ins: Instruction) bld castKind =
  lift bld ins {
    let dstSize = getOperationSize ins
    let srcSize = RegType.fromBitWidth (RegType.toBitWidth dstSize / 2)
    let struct (dst, src) = getTwoOprs ins
    let a = transOprToArr ins bld true 32<rt> 2 srcSize src
    let result = a |> Array.map (AST.cast castKind 64<rt>)
    assignPackedInstr ins bld false 1 dstSize dst result
    fillZeroFromVLToMaxVL bld dst dstSize 512
  }

let vcvtpd2ps ins bld = cvtNarrowing ins bld CastKind.FloatCast

let vcvtpd2dq ins bld = cvtNarrowing ins bld CastKind.FtoIRound

let vcvttpd2dq ins bld = cvtNarrowing ins bld CastKind.FtoITrunc

let vcvtdq2pd ins bld = cvtWidening ins bld CastKind.SIntToFloat

let vcvtps2pd ins bld = cvtWidening ins bld CastKind.FloatCast

/// The gathers load one element per index, and only where the mask element's
/// sign bit is set: an element the mask leaves out keeps what the destination
/// held and its address is never formed at all -- which is why each load sits
/// behind a branch rather than inside a conditional expression, whose other
/// side would be evaluated too. The mask register is cleared whole at the end,
/// which is how a program tells a gather that finished from one that faulted
/// part way through.
let private gather (ins: Instruction) bld idxSz dataSz =
  lift bld ins {
    let struct (dst, vsib, maskOpr) = getThreeOprs ins
    let dstSize = getOperationSize ins
    let dataNum = 64<rt> / dataSz
    match vsib with
    | OprMem(baseReg, Some(idxReg, scale), disp, _) ->
      let addrSz = bld.RegType
      let baseExpr =
        match baseReg with
        | Some r -> regVar bld r
        | None -> AST.num0 addrSz
      let dispExpr =
        match disp with
        | Some d -> numI64 d addrSz
        | None -> AST.num0 addrSz
      let idxWidth = operandWidth bld (OprReg idxReg)
      let indices =
        transOprToArr ins bld true idxSz (64<rt> / idxSz) idxWidth
                      (OprReg idxReg)
      let slots = transOprToArr ins bld false dataSz dataNum dstSize dst
      let mask = transOprToArr ins bld true dataSz dataNum dstSize maskOpr
      let count =
        min (RegType.toBitWidth dstSize / RegType.toBitWidth dataSz)
            (RegType.toBitWidth idxWidth / RegType.toBitWidth idxSz)
      let scaleNum = numI32 (int scale) addrSz
      for i in 0 .. slots.Length - 1 do
        if i < count then
          let addr = tmpVar bld addrSz
          _if bld "Gathered" (AST.xthi 1<rt> mask[i])
            (block {
              direct addr :=
                baseExpr .+ dispExpr
                .+ ((AST.sext addrSz indices[i]) .* scaleNum)
              direct (slots[i]) := AST.loadLE dataSz addr })
            (block { })
        else
          append bld {
            direct (slots[i]) := AST.num0 dataSz
          }
      (* Every mask element goes, whether it was used or not. *)
      let maskSlots =
        transOprToArr ins bld false dataSz dataNum dstSize maskOpr
      for m in maskSlots do
        append bld {
          direct m := AST.num0 dataSz
        }
      (* The mask register is written like any other, so what lies above the
         vector length in it is cleared as well. *)
      fillZeroFromVLToMaxVL bld maskOpr dstSize 512
      fillZeroFromVLToMaxVL bld dst dstSize 512
    | _ ->
      raise InvalidOperandException
  }

let vgatherdpd ins bld = gather ins bld 32<rt> 64<rt>

let vgatherqpd ins bld = gather ins bld 64<rt> 64<rt>

let vgatherdps ins bld = gather ins bld 32<rt> 32<rt>

let vgatherqps ins bld = gather ins bld 64<rt> 32<rt>

let vpgatherdd ins bld = gather ins bld 32<rt> 32<rt>

let vpgatherdq ins bld = gather ins bld 32<rt> 64<rt>

let vpgatherqd ins bld = gather ins bld 64<rt> 32<rt>

let vpgatherqq ins bld = gather ins bld 64<rt> 64<rt>

/// The reciprocal and reciprocal-square-root approximations. What the manual
/// promises is a relative error under 1.5 * 2^-12 and nothing more: the exact
/// bits are the implementation's to choose, and these compute the real
/// quotient rather than any particular approximation of it -- which is what
/// the legacy forms do too, and as close as a model can come without copying
/// one processor's table.
let private vapproxRecip (ins: Instruction) bld packSz isSqrt =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src) = getTwoOprs ins
    let a = transOprToArr ins bld true packSz packNum oprSize src
    let one = numI32 0x3f800000 packSz
    let result =
      a |> Array.map (fun v ->
        if isSqrt then AST.fdiv one (AST.unop UnOpType.FSQRT v)
        else AST.fdiv one v)
    assignPackedInstr ins bld false packNum oprSize dst result
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

/// The scalar forms leave the lanes above the low one to the named source.
let private vapproxRecipScalar (ins: Instruction) bld isSqrt =
  lift bld ins {
    let struct (dst, s1, s2) = getDstAndSrcs ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let struct (s1B, s1A) = transOpr128 ins bld false s1
    let src = transOpr32 ins bld false s2
    let one = numI32 0x3f800000 32<rt>
    let answer = tmpVar bld 32<rt>
    direct answer :=
      (if isSqrt then AST.fdiv one (AST.unop UnOpType.FSQRT src)
       else AST.fdiv one src)
    direct dstA := s1A
    direct dstB := s1B
    direct (AST.xtlo 32<rt> dstA) := answer
    fillZeroFromVLToMaxVL bld dst 128<rt> 512
  }

let vrcpps ins bld = vapproxRecip ins bld 32<rt> false

let vrsqrtps ins bld = vapproxRecip ins bld 32<rt> true

let vrcpss ins bld = vapproxRecipScalar ins bld false

let vrsqrtss ins bld = vapproxRecipScalar ins bld true

let vpmaxsd ins bld =
  buildPackedInstr ins bld true 32<rt> SSELifter.opPmaxs

let vpminub ins bld =
  buildPackedInstr ins bld true 8<rt> SSELifter.opPminu

let vpminud ins bld =
  buildPackedInstr ins bld true 32<rt> SSELifter.opPminu

let vpminsb ins bld =
  buildPackedInstr ins bld true 8<rt> SSELifter.opPmins

let vpminsd ins bld =
  buildPackedInstr ins bld true 32<rt> SSELifter.opPmins

/// The source lanes a VPMOV extension reads, which follow from where the
/// operand lives and from how far the extension widens each lane.
let private vpmovSrcLanes bld ins srcSz dstSz oprSize src =
  let inline extSrc num s =
    Array.init num (fun i -> AST.extract s srcSz (i * (int srcSz)))
  match src, oprSize with
  | OprMem(_, _, _, 128<rt>), 128<rt> | OprReg _, 128<rt> ->
    let struct (_, srcA) = transOpr128 ins bld false src
    extSrc (oprSize / dstSz) srcA
  | OprMem(_, _, _, 128<rt>), 256<rt> | OprReg _, 256<rt> ->
    let sNum = (oprSize / 2) / dstSz
    let struct (srcB, srcA) = transOpr128 ins bld false src
    if (dstSz / srcSz) = 2 then
      Array.append (extSrc sNum srcA) (extSrc sNum srcB)
    else
      extSrc (sNum * 2) srcA
  | OprMem(_, _, _, 256<rt>), 512<rt> | OprReg _, 512<rt> ->
    let sNum = (oprSize / 4) / dstSz
    let struct (srcD, srcC, srcB, srcA) =
      transOpr256 ins bld false src
    if (dstSz / srcSz) = 2 then
      Array.concat
        [| (extSrc sNum srcA)
           (extSrc sNum srcB)
           (extSrc sNum srcC)
           (extSrc sNum srcD) |]
    else
      extSrc (sNum * 2) srcA
  | OprMem(_, _, _, memSz), _ ->
    let srcExpr = transOpr ins bld false src
    extSrc (memSz / srcSz) srcExpr
  | _ ->
    raise InvalidOperandSizeException

let vpmovx (ins: Instruction) bld srcSz dstSz isSignExt =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packNum = 64<rt> / dstSz
    let struct (dst, src) = getTwoOprs ins
    let ext = if isSignExt then AST.sext dstSz else AST.zext dstSz
    let lanes = vpmovSrcLanes bld ins srcSz dstSz oprSize src
    let result = Array.map ext lanes
    assignPackedInstr ins bld false packNum oprSize dst result
    if oprSize = 512<rt> then () else fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let vpmovd2m (ins: Instruction) bld =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packSize = 32<rt>
    let packNum = 64<rt> / packSize
    let struct (dst, src) = getTwoOprs ins
    let dst = transOpr ins bld false dst
    let src = transOprToArr ins bld false packSize packNum oprSize src
    let tmp = tmpVar bld 16<rt>
    direct tmp := AST.num0 16<rt>
    let assignShf idx expr =
      append bld {
        direct tmp := tmp .| ((AST.zext 16<rt> expr) << (numI32 idx 16<rt>))
      }
    Array.map (fun e -> AST.xthi 1<rt> e) src |> Array.iteri assignShf
    direct dst := AST.zext 64<rt> tmp
  }

let private opVpmulhuw _ = opPmul AST.xthi AST.zext 32<rt> 16<rt>

let vpmulhuw ins bld =
  buildPackedInstr ins bld true 16<rt> opVpmulhuw

let private opVpmuludq _ =
  let low32 expr = expr .& numI64 0xffffffffL 64<rt>
  Array.map2 (fun e1 e2 -> low32 e1 .* low32 e2)

let vpmuludq ins bld =
  buildPackedInstr ins bld true 64<rt> opVpmuludq

let private opVpmulld _ = opPmul AST.xtlo AST.sext 32<rt> 32<rt>

let vpmulld ins bld =
  buildPackedInstr ins bld true 32<rt> opVpmulld

let vpor (ins: Instruction) bld =
  match getOperationSize ins with
  | 512<rt> -> GeneralLifter.nop ins bld
  | _ -> buildPackedInstr ins bld true 64<rt> opPor

let vpshufb (ins: Instruction) bld =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packSz = 8<rt>
    let packNum = 64<rt> / packSz
    let struct (dst, src1, src2) = getThreeOprs ins
    let nPackSz = numI32 (int packSz) packSz
    let n64 = numI32 64 packSz
    let src1 = transOprToArr ins bld true 64<rt> 1 oprSz src1
    let src2 = transOprToArr ins bld true packSz packNum oprSz src2
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
    let inline shuffleOfEVEX k i dst src2 =
      let shuff = AST.ite (AST.xthi 1<rt> src2 == n1) n0 (getSrcByIdx i src2)
      match k with
      | ValueNone ->
        shuff
      | ValueSome k ->
        let kept = maskedOut ins false packSz dst
        AST.ite (AST.extract k 1<rt> i) shuff kept
    let result =
      if haveEVEXPrx ins.VEXInfo then
        let eDst = transOprToArr ins bld false packSz packNum oprSz dst
        Array.mapi2 (shuffleOfEVEX (opMaskVar bld ins)) eDst src2
      else
        Array.mapi shuffle src2
    assignPackedInstr ins bld false packNum oprSz dst result
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

let vpshufd (ins: Instruction) bld =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packSize = 32<rt>
    let packNum = 64<rt> / packSize
    let allPackNum = oprSize / packSize
    let struct (dst, src1, src2) = getThreeOprs ins
    let eDst = transOprToArr ins bld false packSize packNum oprSize dst
    let src = transOprToArr ins bld false packSize packNum oprSize src1
    let ord = getImmValue src2 |> int
    let inline getIdx i = (i / 4 * 4) + ((ord >>> ((i &&& 0x3) * 2)) &&& 0x3)
    let result =
      if haveEVEXPrx ins.VEXInfo then
        let src = Array.init allPackNum (fun i -> src[getIdx i])
        makeAssignWithMask bld ins oprSize packSize eDst src false
      else
        let getIdx i = (i / 4 * 4) + ((ord >>> ((i &&& 0x3) * 2)) &&& 0x3)
        Array.init allPackNum (fun i -> src[getIdx i])
    assignPackedInstr ins bld false packNum oprSize dst result
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let private opShiftVpackedDataLogical packSz shf src1 src2 =
  let count = src2 |> AST.zext 64<rt>
  let cond = AST.gt count (numI32 ((int packSz) - 1) 64<rt>)
  let shifted expr = AST.extract (shf (AST.zext 64<rt> expr) count) packSz 0
  Array.map (fun e -> AST.ite cond (AST.num0 packSz) (shifted e)) src1

let private vpsll (ins: Instruction) bld packSz =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src1, src2) = getThreeOprs ins
    let src1 = transOprToArr ins bld true packSz packNum oprSize src1
    let src2 =
      match src2 with
      | OprImm _ ->
        transOpr ins bld false src2 |> AST.xtlo packSz
      | _ ->
        let struct (_, e) = transOpr128 ins bld false src2
        e
    let result = opShiftVpackedDataLogical packSz (<<) src1 src2
    assignPackedInstr ins bld false packNum oprSize dst result
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let vpslld ins bld =
  match getOperationSize ins with
  | 512<rt> -> GeneralLifter.nop ins bld
  | _ -> vpsll ins bld 32<rt>

let vpsllq ins bld = vpsll ins bld 64<rt>

/// Shifts an XMM value left by whole bytes.
let private vpslldq128 bld ins dstOpr srcOpr shift =
  let struct (amount, leftAmt, rightAmt) = shift
  append bld {
    let struct (dstB, dstA) = transOpr128 ins bld false dstOpr
    let struct (srcB, srcA) = transOpr128 ins bld false srcOpr
    let struct (tSrcB, tSrcA) = tmpVars2 bld 64<rt>
    direct tSrcA := srcA
    direct tSrcB := srcB
    if amount < 64L then
      direct dstA := tSrcA << leftAmt
      direct dstB := (tSrcB << leftAmt) .| (tSrcA >> rightAmt)
    elif amount < 128L then
      direct dstA := AST.num0 64<rt>
      direct dstB := tSrcA << leftAmt
    else
      direct dstA := AST.num0 64<rt>
      direct dstB := AST.num0 64<rt>
  }

/// Shifts each 128-bit lane of a YMM value left by whole bytes.
let private vpslldq256 bld ins dstOpr srcOpr shift =
  let struct (amount, leftAmt, rightAmt) = shift
  append bld {
    let struct (dstD, dstC, dstB, dstA) =
      transOpr256 ins bld false dstOpr
    let struct (srcD, srcC, srcB, srcA) =
      transOpr256 ins bld false srcOpr
    let struct (tSrcD, tSrcC, tSrcB, tSrcA) = tmpVars4 bld 64<rt>
    direct tSrcA := srcA
    direct tSrcB := srcB
    direct tSrcC := srcC
    direct tSrcD := srcD
    if amount < 64L then
      direct dstA := tSrcA << leftAmt
      direct dstB := (tSrcB << leftAmt) .| (tSrcA >> rightAmt)
      direct dstC := tSrcC << leftAmt
      direct dstD := (tSrcD << leftAmt) .| (tSrcC >> rightAmt)
    elif amount < 128L then
      direct dstA := AST.num0 64<rt>
      direct dstB := tSrcA << leftAmt
      direct dstC := AST.num0 64<rt>
      direct dstD := tSrcC << leftAmt
    else
      direct dstA := AST.num0 64<rt>
      direct dstB := AST.num0 64<rt>
      direct dstC := AST.num0 64<rt>
      direct dstD := AST.num0 64<rt>
  }

let vpslldq (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src, cnt) = getThreeOprs ins
    let cnt = getImmValue cnt
    let amount = (if cnt > 15L then 16L else cnt) * 8L
    let rightAmt = numI64 (64L - (amount % 64L)) 64<rt>
    let leftAmt = numI64 (amount % 64L) 64<rt>
    let shift = struct (amount, leftAmt, rightAmt)
    let oprSize = getOperationSize ins
    match oprSize with
    | 128<rt> -> vpslldq128 bld ins dst src shift
    | 256<rt> -> vpslldq256 bld ins dst src shift
    | _ -> raise InvalidOperandSizeException
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let private shiftPackedDataRight (ins: Instruction) bld packSize shf =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packNum = 64<rt> / packSize
    let struct (dst, src1, src2) = getThreeOprs ins
    let src1 = transOprToArr ins bld false packSize packNum oprSz src1
    let src2 =
      match src2 with
      | OprImm _ ->
        transOpr ins bld false src2
      | _ ->
        let struct (_, e) = transOpr128 ins bld false src2
        e
    let struct (tCnt, max) = tmpVars2 bld 64<rt>
    let cnt = tmpVar bld packSize
    direct max := numI32 (int packSize) 64<rt>
    direct tCnt := AST.xtlo 64<rt> src2
    direct tCnt := AST.ite (tCnt .> max .- AST.num1 64<rt>) max tCnt
    direct cnt := AST.xtlo packSize tCnt
    let result = Array.map (fun e -> shf e cnt) src1
    assignPackedInstr ins bld false packNum oprSz dst result
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

let vpsrad ins bld = shiftPackedDataRight ins bld 32<rt> (?>>)

let vpsraw ins bld = shiftPackedDataRight ins bld 16<rt> (?>>)

let vpsravd (ins: Instruction) bld =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packSize = 32<rt>
    let packNum = 64<rt> / packSize
    let struct (dst, src1, src2) = getThreeOprs ins
    let src1 = transOprToArr ins bld false packSize packNum oprSz src1
    let src2 = transOprToArr ins bld false packSize packNum oprSz src2
    let struct (n0, n32, max) = tmpVars3 bld packSize
    direct n0 := AST.num0 packSize
    direct n32 := numI32 32 packSize
    direct max := numI32 0xFFFFFFFF packSize
    let fillSignBit e1 e2 =
      AST.ite (e2 .< n32) (e1 ?>> e2) (AST.ite (AST.xthi 1<rt> e1) max n0)
    let result = Array.map2 fillSignBit src1 src2
    assignPackedInstr ins bld false packNum oprSz dst result
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

let vpsrlq (ins: Instruction) bld =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packSz = 64<rt>
    let packNum = 64<rt> / packSz
    let struct (dst, src1, src2) = getThreeOprs ins
    let src1 = transOprToArr ins bld true packSz packNum oprSize src1
    let src2 =
      match src2 with
      | OprImm _ ->
        transOpr ins bld false src2 |> AST.xtlo packSz
      | _ ->
        let struct (_, e) = transOpr128 ins bld false src2
        e
    let result = opShiftVpackedDataLogical packSz (>>) src1 src2
    assignPackedInstr ins bld false packNum oprSize dst result
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

/// Shifts an XMM value right by whole bytes.
let private vpsrldq128 bld ins dstOpr srcOpr shift =
  let struct (amount, leftAmt, rightAmt) = shift
  append bld {
    let struct (dstB, dstA) = transOpr128 ins bld false dstOpr
    let struct (srcB, srcA) = transOpr128 ins bld false srcOpr
    let struct (tSrcB, tSrcA) = tmpVars2 bld 64<rt>
    direct tSrcA := srcA
    direct tSrcB := srcB
    let index = (int amount) / 64
    let src = [| tSrcA; tSrcB; AST.num0 64<rt>; AST.num0 64<rt> |]
    direct dstA := (src[index + 1] << leftAmt) .| (src[index] >> rightAmt)
    direct dstB := src[index + 1] >> rightAmt
  }

/// Shifts each 128-bit lane of a YMM value right by whole bytes.
let private vpsrldq256 bld ins dstOpr srcOpr shift =
  let struct (amount, leftAmt, rightAmt) = shift
  append bld {
    let struct (dstD, dstC, dstB, dstA) =
      transOpr256 ins bld false dstOpr
    let struct (srcD, srcC, srcB, srcA) =
      transOpr256 ins bld false srcOpr
    let struct (tSrcD, tSrcC, tSrcB, tSrcA) = tmpVars4 bld 64<rt>
    direct tSrcA := srcA
    direct tSrcB := srcB
    direct tSrcC := srcC
    direct tSrcD := srcD
    if amount < 64L then
      direct dstA := (tSrcB << leftAmt) .| (tSrcA >> rightAmt)
      direct dstB := tSrcB >> rightAmt
      direct dstC := (tSrcD << leftAmt) .| (tSrcC >> rightAmt)
      direct dstD := tSrcD >> rightAmt
    elif amount < 128L then
      direct dstA := (tSrcB >> rightAmt)
      direct dstB := AST.num0 64<rt>
      direct dstC := tSrcD >> rightAmt
      direct dstD := AST.num0 64<rt>
    else
      direct dstA := AST.num0 64<rt>
      direct dstB := AST.num0 64<rt>
      direct dstC := AST.num0 64<rt>
      direct dstD := AST.num0 64<rt>
  }

let vpsrldq (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src, cnt) = getThreeOprs ins
    let cnt = getImmValue cnt
    let amount = (if cnt > 15L then 16L else cnt) * 8L
    let rightAmt = numI64 (amount % 64L) 64<rt>
    let leftAmt = numI64 (64L - (amount % 64L)) 64<rt>
    let shift = struct (amount, leftAmt, rightAmt)
    let oprSize = getOperationSize ins
    match oprSize with
    | 128<rt> -> vpsrldq128 bld ins dst src shift
    | 256<rt> -> vpsrldq256 bld ins dst src shift
    | _ -> raise InvalidOperandSizeException
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let vpsrld ins bld = shiftPackedDataRight ins bld 32<rt> (>>)

let vpsrlw ins bld = shiftPackedDataRight ins bld 16<rt> (>>)

let vpsubb ins bld =
  buildPackedInstr ins bld true 8<rt> (opP (.-))

let vpsubd ins bld =
  buildPackedInstr ins bld true 32<rt> (opP (.-))

let vptest ins bld =
  if getOperationSize ins = 128<rt> then
    SSELifter.ptest ins bld
  else
    lift bld ins {
      let struct (src1, src2) = getTwoOprs ins
      let struct (src1D, src1C, src1B, src1A) =
        transOpr256 ins bld false src1
      let struct (src2D, src2C, src2B, src2A) =
        transOpr256 ins bld false src2
      let struct (t1, t2, t3, t4) = tmpVars4 bld 64<rt>
      let struct (t5, t6, t7, t8) = tmpVars4 bld 64<rt>
      direct t1 := src2A .& src1A
      direct t2 := src2B .& src1B
      direct t3 := src2C .& src1C
      direct t4 := src2D .& src1D
      direct (regVar bld R.ZF) := (t1 .| t2 .| t3 .| t4) == (AST.num0 64<rt>)
      direct t5 := src2A .& AST.not src1A
      direct t6 := src2B .& AST.not src1B
      direct t7 := src2C .& AST.not src1C
      direct t8 := src2D .& AST.not src1D
      direct (regVar bld R.CF) := (t5 .| t6 .| t7 .| t8) == (AST.num0 64<rt>)
      direct (regVar bld R.AF) := AST.b0
      direct (regVar bld R.OF) := AST.b0
      direct (regVar bld R.PF) := AST.b0
      direct (regVar bld R.SF) := AST.b0
#if EMULATION
      bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
    }

let vpunpckhdq ins bld =
  buildPackedInstr ins bld true 32<rt> opUnpackHighData

let vpunpckhqdq ins bld =
  buildPackedInstr ins bld true 64<rt> opUnpackHighData

let vpunpckhwd ins bld = unpackLowHighData ins bld 16<rt> true

let vpunpcklwd ins bld = unpackLowHighData ins bld 16<rt> false

let vpunpckldq ins bld =
  buildPackedInstr ins bld true 32<rt> opUnpackLowData

let vpunpcklqdq ins bld =
  buildPackedInstr ins bld true 64<rt> opUnpackLowData

let vpxor (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let oprSize = getOperationSize ins
    match oprSize with
    | 128<rt> ->
      let struct (dstB, dstA) = transOpr128 ins bld false dst
      let struct (src1B, src1A) = transOpr128 ins bld false src1
      let struct (src2B, src2A) = transOpr128 ins bld false src2
      direct dstB := src1B <+> src2B
      direct dstA := src1A <+> src2A
    | 256<rt> ->
      let struct (dstD, dstC, dstB, dstA) =
        transOpr256 ins bld false dst
      let struct (src1D, src1C, src1B, src1A) =
        transOpr256 ins bld false src1
      let struct (src2D, src2C, src2B, src2A) =
        transOpr256 ins bld false src2
      direct dstD := src1D <+> src2D
      direct dstC := src1C <+> src2C
      direct dstB := src1B <+> src2B
      direct dstA := src1A <+> src2A
    | _ ->
      raise InvalidOperandSizeException
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

let vpxord (ins: Instruction) bld =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packSz = 32<rt>
    let packNum = 64<rt> / packSz
    let struct (dst, src1, src2) = getThreeOprs ins
    let tDst = transOprToArr ins bld false packSz packNum oprSz dst
    let tSrc1 = transOprToArr ins bld false packSz packNum oprSz src1
    let tSrc2 = transOprToArr ins bld false packSz packNum oprSz src2
    let result =
      if haveEVEXPrx ins.VEXInfo then
        makeAssignEVEX bld ins oprSz packSz tDst tSrc1 tSrc2 (<+>)
      else
        Array.map2 (<+>) tSrc1 tSrc2
    assignPackedInstr ins bld false packNum oprSz dst result
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

let vzeroupper (ins: Instruction) bld =
  lift bld ins {
    let n0 = AST.num0 64<rt>
    direct (pseudoRegVar bld R.YMM0 3) := n0
    direct (pseudoRegVar bld R.YMM0 4) := n0
    direct (pseudoRegVar bld R.YMM1 3) := n0
    direct (pseudoRegVar bld R.YMM1 4) := n0
    direct (pseudoRegVar bld R.YMM2 3) := n0
    direct (pseudoRegVar bld R.YMM2 4) := n0
    direct (pseudoRegVar bld R.YMM3 3) := n0
    direct (pseudoRegVar bld R.YMM3 4) := n0
    direct (pseudoRegVar bld R.YMM4 3) := n0
    direct (pseudoRegVar bld R.YMM4 4) := n0
    direct (pseudoRegVar bld R.YMM5 3) := n0
    direct (pseudoRegVar bld R.YMM5 4) := n0
    direct (pseudoRegVar bld R.YMM6 3) := n0
    direct (pseudoRegVar bld R.YMM6 4) := n0
    direct (pseudoRegVar bld R.YMM7 3) := n0
    direct (pseudoRegVar bld R.YMM7 4) := n0
    if is64bit bld then
      direct (pseudoRegVar bld R.YMM8 3) := n0
      direct (pseudoRegVar bld R.YMM8 4) := n0
      direct (pseudoRegVar bld R.YMM9 3) := n0
      direct (pseudoRegVar bld R.YMM9 4) := n0
      direct (pseudoRegVar bld R.YMM10 3) := n0
      direct (pseudoRegVar bld R.YMM10 4) := n0
      direct (pseudoRegVar bld R.YMM11 3) := n0
      direct (pseudoRegVar bld R.YMM11 4) := n0
      direct (pseudoRegVar bld R.YMM12 3) := n0
      direct (pseudoRegVar bld R.YMM12 4) := n0
      direct (pseudoRegVar bld R.YMM13 3) := n0
      direct (pseudoRegVar bld R.YMM13 4) := n0
      direct (pseudoRegVar bld R.YMM14 3) := n0
      direct (pseudoRegVar bld R.YMM14 4) := n0
      direct (pseudoRegVar bld R.YMM15 3) := n0
      direct (pseudoRegVar bld R.YMM15 4) := n0
    else
      ()
  }

/// Where the digits send the operands: 132 multiplies the destination by the
/// third operand and adds the second, 213 multiplies the second by the
/// destination, and 231 multiplies the two sources and adds the destination.
type private FmaOrder =
  | Fma132
  | Fma213
  | Fma231

/// Whether the addend alternates sign across the lanes, and which way round:
/// FMADDSUB subtracts in the even lanes, FMSUBADD adds in them.
type private FmaAddend =
  | Plus
  | Minus
  | SubtractsInEvenLanes
  | AddsInEvenLanes

/// The fused multiply-add is one host operation, not a multiply and an add:
/// it rounds once, and a lifter that spells it out as the two rounds twice and
/// lands a bit away often enough to matter. So it goes out as a named call,
/// the only three-operand one here.
/// The negations ride along as flags rather than being applied here: a
/// negation is a flip of a sign bit, and flipping a NaN operand's sign before
/// the operation would change which NaN the answer carries.
let private fmaCall sz negProduct negAddend x y z =
  let prodBit = if negProduct then 1UL else 0UL
  let addBit = if negAddend then 2UL else 0UL
  let args = [ x; y; z; numU64 (prodBit ||| addBit) 8<rt> ]
  AST.app (if sz = 32<rt> then "FMA32" else "FMA64") args sz

let private fmaPick order d s2 s3 =
  match order with
  | Fma132 -> d, s3, s2
  | Fma213 -> s2, d, s3
  | Fma231 -> s2, s3, d

/// One lane's fused multiply-add, with the signs the variant asks for.
let private fmaLane sz order negProduct addend lane d s2 s3 =
  let x, y, z = fmaPick order d s2 s3
  let subtracts =
    match addend with
    | Plus -> false
    | Minus -> true
    | SubtractsInEvenLanes -> lane % 2 = 0
    | AddsInEvenLanes -> lane % 2 = 1
  fmaCall sz negProduct subtracts x y z

let private fmaPacked (ins: Instruction) bld sz order negProduct addend =
  lift bld ins {
    let oprSize = getOperationSize ins
    let packNum = 64<rt> / sz
    let struct (dst, src2, src3) = getThreeOprs ins
    let d = transOprToArr ins bld true sz packNum oprSize dst
    let a = transOprToArr ins bld true sz packNum oprSize src2
    let b = transOprToArr ins bld true sz packNum oprSize src3
    let result =
      Array.init d.Length (fun i ->
        fmaLane sz order negProduct addend i d[i] a[i] b[i])
    assignPackedInstr ins bld false packNum oprSize dst result
    fillZeroFromVLToMaxVL bld dst oprSize 512
  }

/// The scalar forms work on the low lane and leave the rest of the
/// destination register as it stood.
let private fmaScalar (ins: Instruction) bld sz order negProduct addend =
  lift bld ins {
    let struct (dst, src2, src3) = getThreeOprs ins
    let struct (_dstB, dstA) = transOpr128 ins bld false dst
    let s2 =
      if sz = 32<rt> then transOpr32 ins bld false src2
      else transOpr64 ins bld false src2
    let s3 =
      if sz = 32<rt> then transOpr32 ins bld false src3
      else transOpr64 ins bld false src3
    let low = if sz = 32<rt> then AST.xtlo 32<rt> dstA else dstA
    let tmp = tmpVar bld sz
    direct tmp := fmaLane sz order negProduct addend 0 low s2 s3
    direct low := tmp
    fillZeroFromVLToMaxVL bld dst 128<rt> 512
  }

let vfmadd132pd ins bld =
  fmaPacked ins bld 64<rt> Fma132 false Plus

let vfmadd132ps ins bld =
  fmaPacked ins bld 32<rt> Fma132 false Plus

let vfmadd132sd ins bld =
  fmaScalar ins bld 64<rt> Fma132 false Plus

let vfmadd132ss ins bld =
  fmaScalar ins bld 32<rt> Fma132 false Plus

let vfmsub132pd ins bld =
  fmaPacked ins bld 64<rt> Fma132 false Minus

let vfmsub132ps ins bld =
  fmaPacked ins bld 32<rt> Fma132 false Minus

let vfmsub132sd ins bld =
  fmaScalar ins bld 64<rt> Fma132 false Minus

let vfmsub132ss ins bld =
  fmaScalar ins bld 32<rt> Fma132 false Minus

let vfnmadd132pd ins bld =
  fmaPacked ins bld 64<rt> Fma132 true Plus

let vfnmadd132ps ins bld =
  fmaPacked ins bld 32<rt> Fma132 true Plus

let vfnmadd132sd ins bld =
  fmaScalar ins bld 64<rt> Fma132 true Plus

let vfnmadd132ss ins bld =
  fmaScalar ins bld 32<rt> Fma132 true Plus

let vfnmsub132pd ins bld =
  fmaPacked ins bld 64<rt> Fma132 true Minus

let vfnmsub132ps ins bld =
  fmaPacked ins bld 32<rt> Fma132 true Minus

let vfnmsub132sd ins bld =
  fmaScalar ins bld 64<rt> Fma132 true Minus

let vfnmsub132ss ins bld =
  fmaScalar ins bld 32<rt> Fma132 true Minus

let vfmaddsub132pd ins bld =
  fmaPacked ins bld 64<rt> Fma132 false SubtractsInEvenLanes

let vfmaddsub132ps ins bld =
  fmaPacked ins bld 32<rt> Fma132 false SubtractsInEvenLanes

let vfmsubadd132pd ins bld =
  fmaPacked ins bld 64<rt> Fma132 false AddsInEvenLanes

let vfmsubadd132ps ins bld =
  fmaPacked ins bld 32<rt> Fma132 false AddsInEvenLanes

let vfmadd213pd ins bld =
  fmaPacked ins bld 64<rt> Fma213 false Plus

let vfmadd213ps ins bld =
  fmaPacked ins bld 32<rt> Fma213 false Plus

let vfmadd213sd ins bld =
  fmaScalar ins bld 64<rt> Fma213 false Plus

let vfmadd213ss ins bld =
  fmaScalar ins bld 32<rt> Fma213 false Plus

let vfmsub213pd ins bld =
  fmaPacked ins bld 64<rt> Fma213 false Minus

let vfmsub213ps ins bld =
  fmaPacked ins bld 32<rt> Fma213 false Minus

let vfmsub213sd ins bld =
  fmaScalar ins bld 64<rt> Fma213 false Minus

let vfmsub213ss ins bld =
  fmaScalar ins bld 32<rt> Fma213 false Minus

let vfnmadd213pd ins bld =
  fmaPacked ins bld 64<rt> Fma213 true Plus

let vfnmadd213ps ins bld =
  fmaPacked ins bld 32<rt> Fma213 true Plus

let vfnmadd213sd ins bld =
  fmaScalar ins bld 64<rt> Fma213 true Plus

let vfnmadd213ss ins bld =
  fmaScalar ins bld 32<rt> Fma213 true Plus

let vfnmsub213pd ins bld =
  fmaPacked ins bld 64<rt> Fma213 true Minus

let vfnmsub213ps ins bld =
  fmaPacked ins bld 32<rt> Fma213 true Minus

let vfnmsub213sd ins bld =
  fmaScalar ins bld 64<rt> Fma213 true Minus

let vfnmsub213ss ins bld =
  fmaScalar ins bld 32<rt> Fma213 true Minus

let vfmaddsub213pd ins bld =
  fmaPacked ins bld 64<rt> Fma213 false SubtractsInEvenLanes

let vfmaddsub213ps ins bld =
  fmaPacked ins bld 32<rt> Fma213 false SubtractsInEvenLanes

let vfmsubadd213pd ins bld =
  fmaPacked ins bld 64<rt> Fma213 false AddsInEvenLanes

let vfmsubadd213ps ins bld =
  fmaPacked ins bld 32<rt> Fma213 false AddsInEvenLanes

let vfmadd231pd ins bld =
  fmaPacked ins bld 64<rt> Fma231 false Plus

let vfmadd231ps ins bld =
  fmaPacked ins bld 32<rt> Fma231 false Plus

let vfmadd231sd ins bld =
  fmaScalar ins bld 64<rt> Fma231 false Plus

let vfmadd231ss ins bld =
  fmaScalar ins bld 32<rt> Fma231 false Plus

let vfmsub231pd ins bld =
  fmaPacked ins bld 64<rt> Fma231 false Minus

let vfmsub231ps ins bld =
  fmaPacked ins bld 32<rt> Fma231 false Minus

let vfmsub231sd ins bld =
  fmaScalar ins bld 64<rt> Fma231 false Minus

let vfmsub231ss ins bld =
  fmaScalar ins bld 32<rt> Fma231 false Minus

let vfnmadd231pd ins bld =
  fmaPacked ins bld 64<rt> Fma231 true Plus

let vfnmadd231ps ins bld =
  fmaPacked ins bld 32<rt> Fma231 true Plus

let vfnmadd231sd ins bld =
  fmaScalar ins bld 64<rt> Fma231 true Plus

let vfnmadd231ss ins bld =
  fmaScalar ins bld 32<rt> Fma231 true Plus

let vfnmsub231pd ins bld =
  fmaPacked ins bld 64<rt> Fma231 true Minus

let vfnmsub231ps ins bld =
  fmaPacked ins bld 32<rt> Fma231 true Minus

let vfnmsub231sd ins bld =
  fmaScalar ins bld 64<rt> Fma231 true Minus

let vfnmsub231ss ins bld =
  fmaScalar ins bld 32<rt> Fma231 true Minus

let vfmaddsub231pd ins bld =
  fmaPacked ins bld 64<rt> Fma231 false SubtractsInEvenLanes

let vfmaddsub231ps ins bld =
  fmaPacked ins bld 32<rt> Fma231 false SubtractsInEvenLanes

let vfmsubadd231pd ins bld =
  fmaPacked ins bld 64<rt> Fma231 false AddsInEvenLanes

let vfmsubadd231ps ins bld =
  fmaPacked ins bld 32<rt> Fma231 false AddsInEvenLanes
