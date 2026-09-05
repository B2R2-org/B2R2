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

module internal B2R2.FrontEnd.Intel.MMXLifter

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.Intel
open B2R2.FrontEnd.Intel.LiftingUtils

let private movdRegToReg ins bld r1 r2 =
  let tmp = tmpVar bld 32<rt>
  match RegisterHelper.getKind r1, RegisterHelper.getKind r2 with
  | RegisterHelper.Kind.XMM, _ ->
    append bld {
      direct (pseudoRegVar bld r1 1) := AST.zext 64<rt> (regVar bld r2)
      direct (pseudoRegVar bld r1 2) := AST.num0 64<rt>
    }
  | _, RegisterHelper.Kind.XMM ->
    append bld {
      direct tmp := AST.xtlo 32<rt> (pseudoRegVar bld r2 1)
      sized 32<rt> (regVar bld r1) := tmp
    }
  | RegisterHelper.Kind.MMX, _ ->
    append bld {
      direct (regVar bld r1) := AST.zext 64<rt> (regVar bld r2)
    }
    fillOnesToMMXHigh16 bld ins
  | _, RegisterHelper.Kind.MMX ->
    append bld {
      direct tmp := AST.xtlo 32<rt> (regVar bld r2)
      sized 32<rt> (regVar bld r1) := tmp
    }
  | _, _ ->
    Terminator.impossible ()

let private movdRegToMem bld dst r =
  match RegisterHelper.getKind r with
  | RegisterHelper.Kind.XMM ->
    append bld {
      direct dst := AST.xtlo 32<rt> (pseudoRegVar bld r 1)
    }
  | RegisterHelper.Kind.MMX ->
    append bld {
      direct dst := AST.xtlo 32<rt> (regVar bld r)
    }
  | _ ->
    Terminator.impossible ()

let private movdMemToReg ins bld src r =
  match RegisterHelper.getKind r with
  | RegisterHelper.Kind.XMM ->
    append bld {
      direct (pseudoRegVar bld r 1) := AST.zext 64<rt> src
      direct (pseudoRegVar bld r 2) := AST.num0 64<rt>
    }
  | RegisterHelper.Kind.MMX ->
    append bld {
      direct (regVar bld r) := AST.zext 64<rt> src
    }
    fillOnesToMMXHigh16 bld ins
  | _ ->
    Terminator.impossible ()

let movd (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    match dst, src with
    | OprReg r1, OprReg r2 ->
      movdRegToReg ins bld r1 r2
    | OprMem _, OprReg r ->
      let dst = transOprToExpr bld false ins dst
      movdRegToMem bld dst r
    | OprReg r, OprMem _ ->
      let src = transOprToExpr bld false ins src
      movdMemToReg ins bld src r
    | _, _ ->
      raise InvalidOperandException
  }

let private movqRegToReg ins bld r1 r2 =
  match RegisterHelper.getKind r1, RegisterHelper.getKind r2 with
  | RegisterHelper.Kind.XMM, RegisterHelper.Kind.XMM ->
    append bld {
      direct (pseudoRegVar bld r1 1) := pseudoRegVar bld r2 1
      direct (pseudoRegVar bld r1 2) := AST.num0 64<rt>
    }
  | RegisterHelper.Kind.XMM, _ ->
    append bld {
      direct (pseudoRegVar bld r1 1) := regVar bld r2
      direct (pseudoRegVar bld r1 2) := AST.num0 64<rt>
    }
  | RegisterHelper.Kind.GP, RegisterHelper.Kind.XMM ->
    append bld {
      direct (regVar bld r1) := pseudoRegVar bld r2 1
    }
  | RegisterHelper.Kind.MMX, RegisterHelper.Kind.MMX
  | RegisterHelper.Kind.MMX, RegisterHelper.Kind.GP ->
    append bld {
      direct (regVar bld r1) := regVar bld r2
    }
    fillOnesToMMXHigh16 bld ins
  | RegisterHelper.Kind.GP, RegisterHelper.Kind.MMX ->
    append bld {
      direct (regVar bld r1) := regVar bld r2
    }
  | _ ->
    raise InvalidOperandException

let private movqRegToMem bld dst r =
  match RegisterHelper.getKind r with
  | RegisterHelper.Kind.XMM -> append bld { direct dst := pseudoRegVar bld r 1 }
  | RegisterHelper.Kind.MMX -> append bld { direct dst := regVar bld r }
  | _ -> raise InvalidOperandException

let private movqMemToReg ins bld src r =
  match RegisterHelper.getKind r with
  | RegisterHelper.Kind.XMM ->
    append bld {
      direct (pseudoRegVar bld r 1) := src
      direct (pseudoRegVar bld r 2) := AST.num0 64<rt>
    }
  | RegisterHelper.Kind.MMX ->
    append bld {
      direct (regVar bld r) := src
    }
    fillOnesToMMXHigh16 bld ins
  | _ ->
    raise InvalidOperandException

let movq (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    match dst, src with
    | OprReg r1, OprReg r2 ->
      movqRegToReg ins bld r1 r2
    | OprMem _, OprReg r ->
      let dst = transOprToExpr bld false ins dst
      movqRegToMem bld dst r
    | OprReg r, OprMem _ ->
      let src = transOprToExpr bld false ins src
      movqMemToReg ins bld src r
    | _, _ ->
      raise InvalidOperandException
  }

let private saturateSignedDwordToSignedWord expr =
  let checkMin = AST.slt expr (numI32 -32768 32<rt>)
  let checkMax = AST.sgt expr (numI32 32767 32<rt>)
  let minNum = numI32 -32768 16<rt>
  let maxNum = numI32 32767 16<rt>
  AST.ite checkMin minNum (AST.ite checkMax maxNum (AST.xtlo 16<rt> expr))

let private saturateSignedWordToSignedByte expr =
  let checkMin = AST.slt expr (numI32 -128 16<rt>)
  let checkMax = AST.sgt expr (numI32 127 16<rt>)
  let minNum = numI32 -128 8<rt>
  let maxNum = numI32 127 8<rt>
  AST.ite checkMin minNum (AST.ite checkMax maxNum (AST.xtlo 8<rt> expr))

let private saturateSignedWordToUnsignedByte expr =
  let checkMin = AST.slt expr (numI32 0 16<rt>)
  let checkMax = AST.sgt expr (numI32 255 16<rt>)
  let minNum = numU32 0u 8<rt>
  let maxNum = numU32 0xffu 8<rt>
  AST.ite checkMin minNum (AST.ite checkMax maxNum (AST.xtlo 8<rt> expr))

let private saturateToSignedByte expr =
  let checkMin = AST.slt expr (numI32 0xff80 16<rt>)
  let checkMax = AST.sgt expr (numI32 0x7f 16<rt>)
  let minNum = numI32 0x80 8<rt>
  let maxNum = numI32 0x7f 8<rt>
  AST.ite checkMin minNum (AST.ite checkMax maxNum (AST.xtlo 8<rt> expr))

let private saturateToSignedWord expr =
  let checkMin = AST.slt expr (numI32 0xffff8000 32<rt>)
  let checkMax = AST.sgt expr (numI32 0x7fff 32<rt>)
  let minNum = numI32 0x8000 16<rt>
  let maxNum = numI32 0x7fff 16<rt>
  AST.ite checkMin minNum (AST.ite checkMax maxNum (AST.xtlo 16<rt> expr))

let private saturateToUnsignedByte expr =
  let checkMin = AST.slt expr (numI32 0 16<rt>)
  let checkMax = AST.sgt expr (numI32 0xff 16<rt>)
  let minNum = numU32 0u 8<rt>
  let maxNum = numU32 0xffu 8<rt>
  AST.ite checkMin minNum (AST.ite checkMax maxNum (AST.xtlo 8<rt> expr))

let private saturateToUnsignedWord expr =
  let checkMin = AST.slt expr (numI32 0 32<rt>)
  let checkMax = AST.sgt expr (numI32 0xffff 32<rt>)
  let minNum = numU32 0u 16<rt>
  let maxNum = numU32 0xffffu 16<rt>
  AST.ite checkMin minNum (AST.ite checkMax maxNum (AST.xtlo 16<rt> expr))

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

let fillZeroHigh128 bld dst =
  append bld {
    let dst = r128to256 dst
    let dstC, dstD = pseudoRegVar bld dst 3, pseudoRegVar bld dst 4
    let n0 = AST.num0 64<rt>
    direct dstC := n0
    direct dstD := n0
  }

let fillZeroHigh256 bld dst =
  append bld {
    let dst = r256to512 dst
    let dstE, dstF, dstG, dstH =
      let pseudoRegVar = pseudoRegVar bld dst
      pseudoRegVar 3, pseudoRegVar 4, pseudoRegVar 5, pseudoRegVar 6
    let n0 = AST.num0 64<rt>
    direct dstE := n0
    direct dstF := n0
    direct dstG := n0
    direct dstH := n0
  }

let fillZeroFromVLToMaxVL bld dst vl maxVl =
  let n0 = AST.num0 64<rt>
  match dst with
  | OprReg _ ->
    match maxVl, vl with
    | 512, 128<rt> ->
      let dst = r128to512 dst
      let dstC, dstD, dstE, dstF, dstG, dstH =
        let regVar = pseudoRegVar bld dst
        regVar 3, regVar 4, regVar 5, regVar 6, regVar 7, regVar 8
      append bld {
        direct dstC := n0
        direct dstD := n0
        direct dstE := n0
        direct dstF := n0
        direct dstG := n0
        direct dstH := n0
      }
    | 512, 256<rt> ->
      let dst = r256to512 dst
      let dstE, dstF, dstG, dstH =
        let pseudoRegVar = pseudoRegVar bld dst
        pseudoRegVar 5, pseudoRegVar 6, pseudoRegVar 7, pseudoRegVar 8
      append bld {
        direct dstE := n0
        direct dstF := n0
        direct dstG := n0
        direct dstH := n0
      }
    | 512, 512<rt> ->
      ()
    | _ ->
      raise InvalidOperandSizeException
  | _ ->
    ()

let private buildPackedTwoOprs ins bld isFillZero packSz opFn dst src =
  lift bld (ins: Instruction) {
    let oprSize = getOperationSize ins
    let packNum = 64<rt> / packSz
    let src1 = transOprToArr bld true ins packSz packNum oprSize dst
    let src2 = transOprToArr bld true ins packSz packNum oprSize src
    let result = opFn oprSize src1 src2
    assignPackedInstr bld false ins packNum oprSize dst result
    if isFillZero then fillZeroFromVLToMaxVL bld dst oprSize 512 else ()
  }

let private buildPackedThreeOprs i bld isFillZero packSz opFn dst s1 s2 =
  lift bld (i: Instruction) {
    let oprSize = getOperationSize i
    let packNum = 64<rt> / packSz
    let src1 = transOprToArr bld true i packSz packNum oprSize s1
    let src2 = transOprToArr bld true i packSz packNum oprSize s2
    let result = opFn oprSize src1 src2
    assignPackedInstr bld false i packNum oprSize dst result
    if isFillZero then fillZeroFromVLToMaxVL bld dst oprSize 512 else ()
  }

let buildPackedInstr (ins: Instruction) bld isFillZero packSz opFn =
  match ins.Operands with
  | TwoOperands(o1, o2) ->
    buildPackedTwoOprs ins bld isFillZero packSz opFn o1 o2
  | ThreeOperands(o1, o2, o3) ->
    buildPackedThreeOprs ins bld isFillZero packSz opFn o1 o2 o3
  | _ ->
    raise InvalidOperandException

let private packWithSaturation (ins: Instruction) bld packSz opFn =
  lift bld ins {
    let oprSize = getOperationSize ins
    let sPackSz = packSz
    let sPackNum = 64<rt> / sPackSz
    let dPackSz = packSz / 2
    let dPackNum = 64<rt> / dPackSz
    let struct (dst, src) = getTwoOprs ins
    let src1 = transOprToArr bld true ins sPackSz sPackNum oprSize dst
    let src2 = transOprToArr bld true ins sPackSz sPackNum oprSize src
    let result = opFn oprSize src1 src2
    assignPackedInstr bld false ins dPackNum oprSize dst result
  }

let private opPackssdw _ src1 src2 =
  Array.append src1 src2 |> Array.map saturateSignedDwordToSignedWord

let packssdw ins bld =
  packWithSaturation ins bld 32<rt> opPackssdw

let private opPacksswb _ src1 src2 =
  Array.append src1 src2 |> Array.map saturateSignedWordToSignedByte

let packsswb ins bld =
  packWithSaturation ins bld 16<rt> opPacksswb

let private opPackuswb _ src1 src2 =
  Array.append src1 src2 |> Array.map saturateSignedWordToUnsignedByte

let packuswb ins bld =
  packWithSaturation ins bld 16<rt> opPackuswb

let private interleaveAndSplit (src1: Expr[]) (src2: Expr[]) totalPackNum =
  let interleaved = Array.zeroCreate (totalPackNum * 2)
  for i in 0 .. totalPackNum - 1 do
    interleaved[i * 2] <- src1[i]
    interleaved[i * 2 + 1] <- src2[i]
  done
  Array.splitAt totalPackNum interleaved

let unpackLowHighData (ins: Instruction) bld packSize isHigh =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packNum = 64<rt> / packSize
    let allPackNum = oprSz / packSize
    let struct (dst, src1, src2) = getThreeOprs ins
    let src1 = transOprToArr bld true ins packSize packNum oprSz src1
    let src2 = transOprToArr bld true ins packSize packNum oprSz src2
    let resultA, resultB = interleaveAndSplit src1 src2 allPackNum
    let result =
      if oprSz = 128<rt> then
        if isHigh then resultB else resultA
      elif oprSz = 256<rt> then
        let resALow, resAHigh = Array.splitAt (allPackNum / 2) resultA
        let resBLow, resBHigh = Array.splitAt (allPackNum / 2) resultB
        if isHigh then Array.append resAHigh resBHigh
        else Array.append resALow resBLow
      else
        raise InvalidOperandSizeException
    assignPackedInstr bld false ins packNum oprSz dst result
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

let opUnpackHighData oprSize src1 src2 =
  let resultA, resultB = interleaveAndSplit src1 src2 (Array.length src1)
  match oprSize with
  | 64<rt> | 128<rt> ->
    resultB
  | 256<rt> ->
    let _, resAHigh = Array.splitAt (Array.length resultA / 2) resultA
    let _, resBHigh = Array.splitAt (Array.length resultB / 2) resultB
    Array.append resAHigh resBHigh
  | _ ->
    raise InvalidOperandSizeException

let opUnpackLowData oprSize src1 src2 =
  let resultA, resultB = interleaveAndSplit src1 src2 (Array.length src1)
  match oprSize with
  | 64<rt> | 128<rt> ->
    resultA
  | 256<rt> ->
    let resALow, _ = Array.splitAt (Array.length resultA / 2) resultA
    let resBLow, _ = Array.splitAt (Array.length resultB / 2) resultB
    Array.append resALow resBLow
  | _ ->
    raise InvalidOperandSizeException

/// A two-operand 128-bit packed op lowered as one SIMD intrinsic -- a
/// BinOp(APP, ...) the evaluator runs on a single Vector128 op -- instead of
/// the per-lane scalar decomposition: read dst/src as 128-bit, apply, and write
/// the halves back. The 128-bit intermediate rides the evaluator's wide path.
let private packedBinIntrinsic (ins: Instruction) bld name =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (dstB, dstA) = transOprToExpr128 bld false ins dst
    let struct (srcB, srcA) = transOprToExpr128 bld false ins src
    let t = tmpVar bld 128<rt>
    let s1 = AST.concat dstB dstA
    let s2 = AST.concat srcB srcA
    direct t := AST.app name [ s1; s2 ] 128<rt>
    direct dstA := AST.xtlo 64<rt> t
    direct dstB := AST.xthi 64<rt> t
  }

let punpckhbw ins bld =
  buildPackedInstr ins bld false 8<rt> opUnpackHighData

let punpckhwd ins bld =
  buildPackedInstr ins bld false 16<rt> opUnpackHighData

let punpckhdq ins bld =
  buildPackedInstr ins bld false 32<rt> opUnpackHighData

let punpcklbw ins bld =
#if EMULATION
  if getOperationSize ins = 128<rt> then
    packedBinIntrinsic ins bld "PUNPCKLBW"
  else
    buildPackedInstr ins bld false 8<rt> opUnpackLowData
#else
  buildPackedInstr ins bld false 8<rt> opUnpackLowData
#endif

let punpcklwd ins bld =
#if EMULATION
  if getOperationSize ins = 128<rt> then
    packedBinIntrinsic ins bld "PUNPCKLWD"
  else
    buildPackedInstr ins bld false 16<rt> opUnpackLowData
#else
  buildPackedInstr ins bld false 16<rt> opUnpackLowData
#endif

let punpckldq ins bld =
#if EMULATION
  if getOperationSize ins = 128<rt> then
    packedBinIntrinsic ins bld "PUNPCKLDQ"
  else
    buildPackedInstr ins bld false 32<rt> opUnpackLowData
#else
  buildPackedInstr ins bld false 32<rt> opUnpackLowData
#endif

let opP op _ = Array.map2 (op)

let paddb ins bld =
  buildPackedInstr ins bld false 8<rt> (opP (.+))

let paddw ins bld =
  buildPackedInstr ins bld false 16<rt> (opP (.+))

let paddd ins bld =
  buildPackedInstr ins bld false 32<rt> (opP (.+))

let private opPaddsb oprSize src1 src2 =
  let src1 = src1 |> Array.map (AST.sext 16<rt>)
  let src2 = src2 |> Array.map (AST.sext 16<rt>)
  (opP (.+)) 16<rt> src1 src2 |> Array.map saturateToSignedByte

let paddsb ins bld = buildPackedInstr ins bld false 8<rt> opPaddsb

let private opPaddsw oprSize src1 src2 =
  let src1 = src1 |> Array.map (AST.sext 32<rt>)
  let src2 = src2 |> Array.map (AST.sext 32<rt>)
  (opP (.+)) 32<rt> src1 src2 |> Array.map saturateToSignedWord

let paddsw ins bld =
  buildPackedInstr ins bld false 16<rt> opPaddsw

let private opPaddusb oprSize src1 src2 =
  let src1 = src1 |> Array.map (AST.zext 16<rt>)
  let src2 = src2 |> Array.map (AST.zext 16<rt>)
  (opP (.+)) 16<rt> src1 src2 |> Array.map saturateToUnsignedByte

let paddusb ins bld =
  buildPackedInstr ins bld false 8<rt> opPaddusb

let private opPaddusw oprSize src1 src2 =
  let src1 = src1 |> Array.map (AST.zext 32<rt>)
  let src2 = src2 |> Array.map (AST.zext 32<rt>)
  (opP (.+)) 32<rt> src1 src2 |> Array.map saturateToUnsignedWord

let paddusw ins bld =
  buildPackedInstr ins bld false 16<rt> opPaddusw

let private makeHorizonSrc src1 src2 =
  let combined = Array.append src1 src2
  let comLen = Array.length combined
  let odd = Array.zeroCreate (comLen / 2)
  let even = Array.zeroCreate (comLen / 2)
  for i in 0 .. comLen - 1 do
    if i % 2 = 0 then odd[i / 2] <- combined[i] else even[i / 2] <- combined[i]
  odd, even

let packedHorizon (ins: Instruction) bld packSz opFn =
  lift bld ins {
    let oprSize = getOperationSize ins
    let struct (dst, src) = getTwoOprs ins
    let packNum = 64<rt> / packSz
    let src1 = transOprToArr bld true ins packSz packNum oprSize dst
    let src2 = transOprToArr bld true ins packSz packNum oprSize src
    let src1, src2 = makeHorizonSrc src1 src2
    let result = opFn oprSize src1 src2
    assignPackedInstr bld false ins packNum oprSize dst result
  }

let phaddd ins bld = packedHorizon ins bld 32<rt> (opP (.+))

let phaddw ins bld = packedHorizon ins bld 16<rt> (opP (.+))

let phaddsw ins bld = packedHorizon ins bld 16<rt> opPaddsw

let psubb ins bld =
#if EMULATION
  if getOperationSize ins = 128<rt> then
    packedBinIntrinsic ins bld "PSUBB"
  else
    buildPackedInstr ins bld false 8<rt> (opP (.-))
#else
  buildPackedInstr ins bld false 8<rt> (opP (.-))
#endif

let psubw ins bld =
  buildPackedInstr ins bld false 16<rt> (opP (.-))

let psubd ins bld =
  buildPackedInstr ins bld false 32<rt> (opP (.-))

let private opPsubsb oprSize src1 src2 =
  let src1 = src1 |> Array.map (AST.sext 16<rt>)
  let src2 = src2 |> Array.map (AST.sext 16<rt>)
  (opP (.-)) 16<rt> src1 src2 |> Array.map saturateToSignedByte

let psubsb ins bld = buildPackedInstr ins bld false 8<rt> opPsubsb

let private opPsubsw oprSize src1 src2 =
  let src1 = src1 |> Array.map (AST.sext 32<rt>)
  let src2 = src2 |> Array.map (AST.sext 32<rt>)
  (opP (.-)) 32<rt> src1 src2 |> Array.map saturateToSignedWord

let psubsw ins bld =
  buildPackedInstr ins bld false 16<rt> opPsubsw

let private opPsubusb _ src1 src2 =
  let src1 = src1 |> Array.map (AST.zext 16<rt>)
  let src2 = src2 |> Array.map (AST.zext 16<rt>)
  (opP (.-)) 16<rt> src1 src2 |> Array.map saturateToUnsignedByte

let psubusb ins bld =
  buildPackedInstr ins bld false 8<rt> opPsubusb

let private opPsubusw _ src1 src2 =
  let src1 = src1 |> Array.map (AST.zext 32<rt>)
  let src2 = src2 |> Array.map (AST.zext 32<rt>)
  (opP (.-)) 32<rt> src1 src2 |> Array.map saturateToUnsignedWord

let psubusw ins bld =
  buildPackedInstr ins bld false 16<rt> opPsubusw

let phsubd ins bld = packedHorizon ins bld 32<rt> (opP (.-))

let phsubw ins bld = packedHorizon ins bld 16<rt> (opP (.-))

let phsubsw ins bld = packedHorizon ins bld 16<rt> opPsubsw

let opPmul resType extr extSz packSz src1 src2 =
  Array.map2 (fun e1 e2 -> extr extSz e1 .* extr extSz e2) src1 src2
  |> Array.map (resType packSz)

let private opPmulhw _ = opPmul AST.xthi AST.sext 32<rt> 16<rt>

let pmulhw ins bld =
  buildPackedInstr ins bld false 16<rt> opPmulhw

let opPmullw _ = opPmul AST.xtlo AST.sext 32<rt> 16<rt>

let pmullw ins bld =
  buildPackedInstr ins bld false 16<rt> opPmullw

let private opPmaddwd _ =
  let lowAndSExt expr = AST.xtlo 16<rt> expr |> AST.sext 32<rt>
  let highAndSExt expr = AST.xthi 16<rt> expr |> AST.sext 32<rt>
  let mulLow e1 e2 = lowAndSExt e1 .* lowAndSExt e2
  let mulHigh e1 e2 = highAndSExt e1 .* highAndSExt e2
  let packAdd e1 e2 = mulLow e1 e2 .+ mulHigh e1 e2
  Array.map2 packAdd

let pmaddwd ins bld =
  buildPackedInstr ins bld false 32<rt> opPmaddwd

let opPcmp packSz cmpOp =
  Array.map2 (fun e1 e2 ->
    AST.ite (cmpOp e1 e2) (getMask packSz) (AST.num0 packSz))

let opPcmpeqb _ = opPcmp 8<rt> (==)

let pcmpeqb ins bld =
#if EMULATION
  if getOperationSize ins = 128<rt> then
    packedBinIntrinsic ins bld "PCMPEQB"
  else
    buildPackedInstr ins bld false 8<rt> opPcmpeqb
#else
  buildPackedInstr ins bld false 8<rt> opPcmpeqb
#endif

let private opPcmpeqw _ = opPcmp 16<rt> (==)

let pcmpeqw ins bld =
  buildPackedInstr ins bld false 16<rt> opPcmpeqw

let opPcmpeqd _ = opPcmp 32<rt> (==)

let pcmpeqd ins bld =
  buildPackedInstr ins bld false 32<rt> opPcmpeqd

let opPcmpgtb _ = opPcmp 8<rt> AST.sgt

let pcmpgtb ins bld =
  buildPackedInstr ins bld false 8<rt> opPcmpgtb

let private opPcmpgtw _ = opPcmp 16<rt> AST.sgt

let pcmpgtw ins bld =
  buildPackedInstr ins bld false 16<rt> opPcmpgtw

let private opPcmpgtd _ = opPcmp 32<rt> AST.sgt

let pcmpgtd ins bld =
  buildPackedInstr ins bld false 32<rt> opPcmpgtd

let opPand _ = Array.map2 (.&)

let pand ins bld = buildPackedInstr ins bld false 64<rt> opPand

let opPandn _ = Array.map2 (fun e1 e2 -> (AST.not e1) .& e2)

let pandn ins bld = buildPackedInstr ins bld false 64<rt> opPandn

let opPor _ = Array.map2 (.|)

let por ins bld = buildPackedInstr ins bld false 64<rt> opPor

let pxor (ins: Instruction) bld =
  lift bld ins {
    let oprSize = getOperationSize ins
    match oprSize with
    | 64<rt> ->
      let struct (dst, src) = transTwoOprs bld false ins
      direct dst := dst <+> src
      fillOnesToMMXHigh16 bld ins
    | 128<rt> ->
      let struct (dst, src) = getTwoOprs ins
      let struct (dstB, dstA) = transOprToExpr128 bld false ins dst
      let struct (srcB, srcA) = transOprToExpr128 bld false ins src
      direct dstA := dstA <+> srcA
      direct dstB := dstB <+> srcB
    | _ ->
      raise InvalidOperandSizeException
  }

let private opShiftPackedDataLogical oprSize packSz shift src1 src2 =
  let pNum = int (oprSize / packSz)
  let z = AST.num0 packSz
  match oprSize with
  | 64<rt> ->
    let count = AST.revConcat src2 |> AST.zext 64<rt>
    let cond = count .> (numI32 ((int packSz) - 1) 64<rt>)
    Array.map (fun e ->
      AST.ite cond z (AST.xtlo packSz (shift (AST.zext 64<rt> e) count))) src1
  | 128<rt> ->
    let count = AST.revConcat (Array.sub src2 0 (pNum / 2)) |> AST.zext 64<rt>
    let cond = count .> (numI32 ((int packSz) - 1) 64<rt>)
    Array.map (fun e ->
      AST.ite cond z (AST.xtlo packSz (shift (AST.zext 64<rt> e) count))) src1
  | _ ->
    raise InvalidOperandSizeException

let private opPsllw oprSize = opShiftPackedDataLogical oprSize 16<rt> (<<)

let psllw ins bld = buildPackedInstr ins bld false 16<rt> opPsllw

let private opPslld oprSize = opShiftPackedDataLogical oprSize 32<rt> (<<)

let pslld ins bld = buildPackedInstr ins bld false 32<rt> opPslld

let private opPsllq oprSize = opShiftPackedDataLogical oprSize 64<rt> (<<)

let psllq ins bld = buildPackedInstr ins bld false 64<rt> opPsllq

let private opPsrlw oprSize = opShiftPackedDataLogical oprSize 16<rt> (>>)

let psrlw ins bld = buildPackedInstr ins bld false 16<rt> opPsrlw

let private opPsrld oprSize = opShiftPackedDataLogical oprSize 32<rt> (>>)

let psrld ins bld = buildPackedInstr ins bld false 32<rt> opPsrld

let private opPsrlq oprSize = opShiftPackedDataLogical oprSize 64<rt> (>>)

let psrlq ins bld = buildPackedInstr ins bld false 64<rt> opPsrlq

let private opShiftPackedDataRightArith oprSize packSz src1 src2 =
  let pNum = int (oprSize / packSz)
  match oprSize with
  | 64<rt> ->
    let count = AST.revConcat src2 |> AST.zext 64<rt>
    let cond = count .> (numI32 ((int packSz) - 1) 64<rt>)
    let count = AST.ite cond (numI32 (int packSz) 64<rt>) count
    Array.map (fun e -> AST.xtlo packSz ((AST.sext 64<rt> e) ?>> count)) src1
  | 128<rt> ->
    let count = AST.revConcat (Array.sub src2 0 (pNum / 2)) |> AST.zext 64<rt>
    let cond = count .> (numI32 ((int packSz) - 1) 64<rt>)
    let count = AST.ite cond (numI32 (int packSz) 64<rt>) count
    Array.map (fun e -> AST.xtlo packSz ((AST.sext 64<rt> e) ?>> count)) src1
  | _ ->
    raise InvalidOperandSizeException

let private opPsraw oprSize = opShiftPackedDataRightArith oprSize 16<rt>

let psraw ins bld = buildPackedInstr ins bld false 16<rt> opPsraw

let private opPsrad oprSize = opShiftPackedDataRightArith oprSize 32<rt>

let psrad ins bld = buildPackedInstr ins bld false 32<rt> opPsrad

let emms (ins: Instruction) bld =
  lift bld ins {
    direct (regVar bld R.FTW) := maxNum 16<rt>
  }
