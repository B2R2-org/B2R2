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
  match Register.getKind r1, Register.getKind r2 with
  | Register.Kind.XMM, _ ->
    bld <+ (pseudoRegVar bld r1 1 := AST.zext 64<rt> (regVar bld r2))
    bld <+ (pseudoRegVar bld r1 2 := AST.num0 64<rt>)
  | _, Register.Kind.XMM ->
    bld <+ (tmp := AST.xtlo 32<rt> (pseudoRegVar bld r2 1))
    bld <+ (dstAssign 32<rt> (regVar bld r1) tmp)
  | Register.Kind.MMX, _ ->
    bld <+ (regVar bld r1 := AST.zext 64<rt> (regVar bld r2))
    fillOnesToMMXHigh16 bld ins
  | _, Register.Kind.MMX ->
    bld <+ (tmp := AST.xtlo 32<rt> (regVar bld r2))
    bld <+ (dstAssign 32<rt> (regVar bld r1) tmp)
  | _, _ -> Terminator.impossible ()

let private movdRegToMem bld dst r =
  match Register.getKind r with
  | Register.Kind.XMM ->
    bld <+ (dst := AST.xtlo 32<rt> (pseudoRegVar bld r 1))
  | Register.Kind.MMX -> bld <+ (dst := AST.xtlo 32<rt> (regVar bld r))
  | _ -> Terminator.impossible ()

let private movdMemToReg ins bld src r =
  match Register.getKind r with
  | Register.Kind.XMM ->
    bld <+ (pseudoRegVar bld r 1 := AST.zext 64<rt> src)
    bld <+ (pseudoRegVar bld r 2 := AST.num0 64<rt>)
  | Register.Kind.MMX ->
    bld <+ (regVar bld r := AST.zext 64<rt> src)
    fillOnesToMMXHigh16 bld ins
  | _ -> Terminator.impossible ()

let movd (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  match dst, src with
  | OprReg r1, OprReg r2 -> movdRegToReg ins bld r1 r2
  | OprMem _, OprReg r ->
    let dst = transOprToExpr bld false ins insLen dst
    movdRegToMem bld dst r
  | OprReg r, OprMem _ ->
    let src = transOprToExpr bld false ins insLen src
    movdMemToReg ins bld src r
  | _, _ -> raise InvalidOperandException
  bld --!> insLen

let private movqRegToReg ins bld r1 r2 =
  match Register.getKind r1, Register.getKind r2 with
  | Register.Kind.XMM, Register.Kind.XMM ->
    bld <+ (pseudoRegVar bld r1 1 := pseudoRegVar bld r2 1)
    bld <+ (pseudoRegVar bld r1 2 := AST.num0 64<rt>)
  | Register.Kind.XMM, _ ->
    bld <+ (pseudoRegVar bld r1 1 := regVar bld r2)
    bld <+ (pseudoRegVar bld r1 2 := AST.num0 64<rt>)
  | Register.Kind.GP, Register.Kind.XMM ->
    bld <+ (regVar bld r1 := pseudoRegVar bld r2 1)
  | Register.Kind.MMX, Register.Kind.MMX
  | Register.Kind.MMX, Register.Kind.GP ->
    bld <+ (regVar bld r1 := regVar bld r2)
    fillOnesToMMXHigh16 bld ins
  | Register.Kind.GP, Register.Kind.MMX ->
    bld <+ (regVar bld r1 := regVar bld r2)
  | _ -> raise InvalidOperandException

let private movqRegToMem bld dst r =
  match Register.getKind r with
  | Register.Kind.XMM -> bld <+ (dst := pseudoRegVar bld r 1)
  | Register.Kind.MMX -> bld <+ (dst := regVar bld r)
  | _ -> raise InvalidOperandException

let private movqMemToReg ins bld src r =
  match Register.getKind r with
  | Register.Kind.XMM ->
    bld <+ (pseudoRegVar bld r 1 := src)
    bld <+ (pseudoRegVar bld r 2 := AST.num0 64<rt>)
  | Register.Kind.MMX ->
    bld <+ (regVar bld r := src)
    fillOnesToMMXHigh16 bld ins
  | _ -> raise InvalidOperandException

let movq (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  match dst, src with
  | OprReg r1, OprReg r2 -> movqRegToReg ins bld r1 r2
  | OprMem _, OprReg r ->
    let dst = transOprToExpr bld false ins insLen dst
    movqRegToMem bld dst r
  | OprReg r, OprMem _ ->
    let src = transOprToExpr bld false ins insLen src
    movqMemToReg ins bld src r
  | _, _ -> raise InvalidOperandException
  bld --!> insLen

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
  let dst = r128to256 dst
  let dstC, dstD = pseudoRegVar bld dst 3, pseudoRegVar bld dst 4
  let n0 = AST.num0 64<rt>
  bld <+ (dstC := n0)
  bld <+ (dstD := n0)

let fillZeroHigh256 bld dst =
  let dst = r256to512 dst
  let dstE, dstF, dstG, dstH =
    pseudoRegVar bld dst 3, pseudoRegVar bld dst 4,
    pseudoRegVar bld dst 5, pseudoRegVar bld dst 6
  let n0 = AST.num0 64<rt>
  bld <+ (dstE := n0)
  bld <+ (dstF := n0)
  bld <+ (dstG := n0)
  bld <+ (dstH := n0)

let fillZeroFromVLToMaxVL bld dst vl maxVl =
  let n0 = AST.num0 64<rt>
  match dst with
  | OprReg _ ->
    match maxVl, vl with
    | 512, 128<rt> ->
      let dst = r128to512 dst
      let dstC, dstD, dstE, dstF, dstG, dstH =
        pseudoRegVar bld dst 3, pseudoRegVar bld dst 4,
        pseudoRegVar bld dst 5, pseudoRegVar bld dst 6,
        pseudoRegVar bld dst 7, pseudoRegVar bld dst 8
      bld <+ (dstC := n0)
      bld <+ (dstD := n0)
      bld <+ (dstE := n0)
      bld <+ (dstF := n0)
      bld <+ (dstG := n0)
      bld <+ (dstH := n0)
    | 512, 256<rt> ->
      let dst = r256to512 dst
      let dstE, dstF, dstG, dstH =
        pseudoRegVar bld dst 5, pseudoRegVar bld dst 6,
        pseudoRegVar bld dst 7, pseudoRegVar bld dst 8
      bld <+ (dstE := n0)
      bld <+ (dstF := n0)
      bld <+ (dstG := n0)
      bld <+ (dstH := n0)
    | 512, 512<rt> -> ()
    | _ -> raise InvalidOperandSizeException
  | _ -> ()

let private buildPackedTwoOprs ins insLen bld isFillZero packSz opFn dst src =
  bld <!-- ((ins: Instruction).Address, insLen)
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / packSz
  let src1 = transOprToArr bld true ins insLen packSz packNum oprSize dst
  let src2 = transOprToArr bld true ins insLen packSz packNum oprSize src
  let result = opFn oprSize src1 src2
  assignPackedInstr bld false ins insLen packNum oprSize dst result
  if isFillZero then fillZeroFromVLToMaxVL bld dst oprSize 512 else ()
  bld --!> insLen

let private buildPackedThreeOprs i iLen bld isFillZero packSz opFn dst s1 s2 =
  bld <!-- ((i: Instruction).Address, iLen)
  let oprSize = getOperationSize i
  let packNum = 64<rt> / packSz
  let src1 = transOprToArr bld true i iLen packSz packNum oprSize s1
  let src2 = transOprToArr bld true i iLen packSz packNum oprSize s2
  let result = opFn oprSize src1 src2
  assignPackedInstr bld false i iLen packNum oprSize dst result
  if isFillZero then fillZeroFromVLToMaxVL bld dst oprSize 512 else ()
  bld --!> iLen

let buildPackedInstr (ins: Instruction) insLen bld isFillZero packSz opFn =
  match ins.Operands with
  | TwoOperands(o1, o2) ->
    buildPackedTwoOprs ins insLen bld isFillZero packSz opFn o1 o2
  | ThreeOperands(o1, o2, o3) ->
    buildPackedThreeOprs ins insLen bld isFillZero packSz opFn o1 o2 o3
  | _ -> raise InvalidOperandException

let private packWithSaturation (ins: Instruction) insLen bld packSz opFn =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let sPackSz = packSz
  let sPackNum = 64<rt> / sPackSz
  let dPackSz = packSz / 2
  let dPackNum = 64<rt> / dPackSz
  let struct (dst, src) = getTwoOprs ins
  let src1 = transOprToArr bld true ins insLen sPackSz sPackNum oprSize dst
  let src2 = transOprToArr bld true ins insLen sPackSz sPackNum oprSize src
  let result = opFn oprSize src1 src2
  assignPackedInstr bld false ins insLen dPackNum oprSize dst result
  bld --!> insLen

let private opPackssdw _ src1 src2 =
  Array.append src1 src2 |> Array.map saturateSignedDwordToSignedWord

let packssdw ins insLen bld =
  packWithSaturation ins insLen bld 32<rt> opPackssdw

let private opPacksswb _ src1 src2 =
  Array.append src1 src2 |> Array.map saturateSignedWordToSignedByte

let packsswb ins insLen bld =
  packWithSaturation ins insLen bld 16<rt> opPacksswb

let private opPackuswb _ src1 src2 =
  Array.append src1 src2 |> Array.map saturateSignedWordToUnsignedByte

let packuswb ins insLen bld =
  packWithSaturation ins insLen bld 16<rt> opPackuswb

let private interleaveAndSplit (src1: Expr[]) (src2: Expr[]) totalPackNum =
  let interleaved = Array.zeroCreate (totalPackNum * 2)
  for i in 0 .. totalPackNum - 1 do
    interleaved[i * 2] <- src1[i]
    interleaved[i * 2 + 1] <- src2[i]
  done
  Array.splitAt totalPackNum interleaved

let unpackLowHighData (ins: Instruction) insLen bld packSize isHigh =
  bld <!-- (ins.Address, insLen)
  let oprSz = getOperationSize ins
  let packNum = 64<rt> / packSize
  let allPackNum = oprSz / packSize
  let struct (dst, src1, src2) = getThreeOprs ins
  let src1 = transOprToArr bld true ins insLen packSize packNum oprSz src1
  let src2 = transOprToArr bld true ins insLen packSize packNum oprSz src2
  let resultA, resultB = interleaveAndSplit src1 src2 allPackNum
  let result =
    if oprSz = 128<rt> then
      if isHigh then resultB else resultA
    elif oprSz = 256<rt> then
      let resALow, resAHigh = Array.splitAt (allPackNum / 2) resultA
      let resBLow, resBHigh = Array.splitAt (allPackNum / 2) resultB
      if isHigh then Array.append resAHigh resBHigh else
      Array.append resALow resBLow
    else raise InvalidOperandSizeException
  assignPackedInstr bld false ins insLen packNum oprSz dst result
  fillZeroFromVLToMaxVL bld dst oprSz 512
  bld --!> insLen

let opUnpackHighData oprSize src1 src2 =
  let resultA, resultB = interleaveAndSplit src1 src2 (Array.length src1)
  match oprSize with
  | 64<rt> | 128<rt> -> resultB
  | 256<rt> ->
    let _, resAHigh = Array.splitAt (Array.length resultA / 2) resultA
    let _, resBHigh = Array.splitAt (Array.length resultB / 2) resultB
    Array.append resAHigh resBHigh
  | _ -> raise InvalidOperandSizeException

let opUnpackLowData oprSize src1 src2 =
  let resultA, resultB = interleaveAndSplit src1 src2 (Array.length src1)
  match oprSize with
  | 64<rt> | 128<rt> -> resultA
  | 256<rt> ->
    let resALow, _ = Array.splitAt (Array.length resultA / 2) resultA
    let resBLow, _ = Array.splitAt (Array.length resultB / 2) resultB
    Array.append resALow resBLow
  | _ -> raise InvalidOperandSizeException

let punpckhbw ins insLen bld =
  buildPackedInstr ins insLen bld false 8<rt> opUnpackHighData

let punpckhwd ins insLen bld =
  buildPackedInstr ins insLen bld false 16<rt> opUnpackHighData

let punpckhdq ins insLen bld =
  buildPackedInstr ins insLen bld false 32<rt> opUnpackHighData

let punpcklbw ins insLen bld =
  buildPackedInstr ins insLen bld false 8<rt> opUnpackLowData

let punpcklwd ins insLen bld =
  buildPackedInstr ins insLen bld false 16<rt> opUnpackLowData

let punpckldq ins insLen bld =
  buildPackedInstr ins insLen bld false 32<rt> opUnpackLowData

let opP op _ = Array.map2 (op)

let paddb ins insLen bld =
  buildPackedInstr ins insLen bld false 8<rt> (opP (.+))

let paddw ins insLen bld =
  buildPackedInstr ins insLen bld false 16<rt> (opP (.+))

let paddd ins insLen bld =
  buildPackedInstr ins insLen bld false 32<rt> (opP (.+))

let private opPaddsb oprSize src1 src2 =
  let src1 = src1 |> Array.map (AST.sext 16<rt>)
  let src2 = src2 |> Array.map (AST.sext 16<rt>)
  (opP (.+)) 16<rt> src1 src2 |> Array.map saturateToSignedByte

let paddsb ins insLen bld = buildPackedInstr ins insLen bld false 8<rt> opPaddsb

let private opPaddsw oprSize src1 src2 =
  let src1 = src1 |> Array.map (AST.sext 32<rt>)
  let src2 = src2 |> Array.map (AST.sext 32<rt>)
  (opP (.+)) 32<rt> src1 src2 |> Array.map saturateToSignedWord

let paddsw ins insLen bld =
  buildPackedInstr ins insLen bld false 16<rt> opPaddsw

let private opPaddusb oprSize src1 src2 =
  let src1 = src1 |> Array.map (AST.zext 16<rt>)
  let src2 = src2 |> Array.map (AST.zext 16<rt>)
  (opP (.+)) 16<rt> src1 src2 |> Array.map saturateToUnsignedByte

let paddusb ins insLen bld =
  buildPackedInstr ins insLen bld false 8<rt> opPaddusb

let private opPaddusw oprSize src1 src2 =
  let src1 = src1 |> Array.map (AST.zext 32<rt>)
  let src2 = src2 |> Array.map (AST.zext 32<rt>)
  (opP (.+)) 32<rt> src1 src2 |> Array.map saturateToUnsignedWord

let paddusw ins insLen bld =
  buildPackedInstr ins insLen bld false 16<rt> opPaddusw

let private makeHorizonSrc src1 src2 =
  let combined = Array.append src1 src2
  let comLen = Array.length combined
  let odd = Array.zeroCreate (comLen / 2)
  let even = Array.zeroCreate (comLen / 2)
  for i in 0 .. comLen - 1 do
    if i % 2 = 0 then odd[i / 2] <- combined[i]
    else even[i / 2] <- combined[i]
  odd, even

let packedHorizon (ins: Instruction) insLen bld packSz opFn =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  let struct (dst, src) = getTwoOprs ins
  let packNum = 64<rt> / packSz
  let src1 = transOprToArr bld true ins insLen packSz packNum oprSize dst
  let src2 = transOprToArr bld true ins insLen packSz packNum oprSize src
  let src1, src2 = makeHorizonSrc src1 src2
  let result = opFn oprSize src1 src2
  assignPackedInstr bld false ins insLen packNum oprSize dst result
  bld --!> insLen

let phaddd ins insLen bld = packedHorizon ins insLen bld 32<rt> (opP (.+))

let phaddw ins insLen bld = packedHorizon ins insLen bld 16<rt> (opP (.+))

let phaddsw ins insLen bld = packedHorizon ins insLen bld 16<rt> opPaddsw

let psubb ins insLen bld =
  buildPackedInstr ins insLen bld false 8<rt> (opP (.-))

let psubw ins insLen bld =
  buildPackedInstr ins insLen bld false 16<rt> (opP (.-))

let psubd ins insLen bld =
  buildPackedInstr ins insLen bld false 32<rt> (opP (.-))

let private opPsubsb oprSize src1 src2 =
  let src1 = src1 |> Array.map (AST.sext 16<rt>)
  let src2 = src2 |> Array.map (AST.sext 16<rt>)
  (opP (.-)) 16<rt> src1 src2 |> Array.map saturateToSignedByte

let psubsb ins insLen bld = buildPackedInstr ins insLen bld false 8<rt> opPsubsb

let private opPsubsw oprSize src1 src2 =
  let src1 = src1 |> Array.map (AST.sext 32<rt>)
  let src2 = src2 |> Array.map (AST.sext 32<rt>)
  (opP (.-)) 32<rt> src1 src2 |> Array.map saturateToSignedWord

let psubsw ins insLen bld =
  buildPackedInstr ins insLen bld false 16<rt> opPsubsw

let private opPsubusb _ src1 src2 =
  let src1 = src1 |> Array.map (AST.zext 16<rt>)
  let src2 = src2 |> Array.map (AST.zext 16<rt>)
  (opP (.-)) 16<rt> src1 src2 |> Array.map saturateToUnsignedByte

let psubusb ins insLen bld =
  buildPackedInstr ins insLen bld false 8<rt> opPsubusb

let private opPsubusw _ src1 src2 =
  let src1 = src1 |> Array.map (AST.zext 32<rt>)
  let src2 = src2 |> Array.map (AST.zext 32<rt>)
  (opP (.-)) 32<rt> src1 src2 |> Array.map saturateToUnsignedWord

let psubusw ins insLen bld =
  buildPackedInstr ins insLen bld false 16<rt> opPsubusw

let phsubd ins insLen bld = packedHorizon ins insLen bld 32<rt> (opP (.-))

let phsubw ins insLen bld = packedHorizon ins insLen bld 16<rt> (opP (.-))

let phsubsw ins insLen bld = packedHorizon ins insLen bld 16<rt> opPsubsw

let opPmul resType extr extSz packSz src1 src2 =
  Array.map2 (fun e1 e2 -> extr extSz e1 .* extr extSz e2) src1 src2
  |> Array.map (resType packSz)

let private opPmulhw _ = opPmul AST.xthi AST.sext 32<rt> 16<rt>

let pmulhw ins insLen bld =
  buildPackedInstr ins insLen bld false 16<rt> opPmulhw

let opPmullw _ = opPmul AST.xtlo AST.sext 32<rt> 16<rt>

let pmullw ins insLen bld =
  buildPackedInstr ins insLen bld false 16<rt> opPmullw

let private opPmaddwd _ =
  let lowAndSExt expr = AST.xtlo 16<rt> expr |> AST.sext 32<rt>
  let highAndSExt expr = AST.xthi 16<rt> expr |> AST.sext 32<rt>
  let mulLow e1 e2 = lowAndSExt e1 .* lowAndSExt e2
  let mulHigh e1 e2 = highAndSExt e1 .* highAndSExt e2
  let packAdd e1 e2 = mulLow e1 e2 .+ mulHigh e1 e2
  Array.map2 packAdd

let pmaddwd ins insLen bld =
  buildPackedInstr ins insLen bld false 32<rt> opPmaddwd

let opPcmp packSz cmpOp =
  Array.map2 (fun e1 e2 ->
    AST.ite (cmpOp e1 e2) (getMask packSz) (AST.num0 packSz))

let opPcmpeqb _ = opPcmp 8<rt> (==)

let pcmpeqb ins insLen bld =
  buildPackedInstr ins insLen bld false 8<rt> opPcmpeqb

let private opPcmpeqw _ = opPcmp 16<rt> (==)

let pcmpeqw ins insLen bld =
  buildPackedInstr ins insLen bld false 16<rt> opPcmpeqw

let opPcmpeqd _ = opPcmp 32<rt> (==)

let pcmpeqd ins insLen bld =
  buildPackedInstr ins insLen bld false 32<rt> opPcmpeqd

let opPcmpgtb _ = opPcmp 8<rt> AST.sgt

let pcmpgtb ins insLen bld =
  buildPackedInstr ins insLen bld false 8<rt> opPcmpgtb

let private opPcmpgtw _ = opPcmp 16<rt> AST.sgt

let pcmpgtw ins insLen bld =
  buildPackedInstr ins insLen bld false 16<rt> opPcmpgtw

let private opPcmpgtd _ = opPcmp 32<rt> AST.sgt

let pcmpgtd ins insLen bld =
  buildPackedInstr ins insLen bld false 32<rt> opPcmpgtd

let opPand _ = Array.map2 (.&)

let pand ins insLen bld = buildPackedInstr ins insLen bld false 64<rt> opPand

let opPandn _ = Array.map2 (fun e1 e2 -> (AST.not e1) .& e2)

let pandn ins insLen bld = buildPackedInstr ins insLen bld false 64<rt> opPandn

let opPor _ = Array.map2 (.|)

let por ins insLen bld = buildPackedInstr ins insLen bld false 64<rt> opPor

let pxor (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let oprSize = getOperationSize ins
  match oprSize with
  | 64<rt> ->
    let struct (dst, src) = transTwoOprs bld false ins insLen
    bld <+ (dst := dst <+> src)
    fillOnesToMMXHigh16 bld ins
  | 128<rt> ->
    let struct (dst, src) = getTwoOprs ins
    let struct (dstB, dstA) = transOprToExpr128 bld false ins insLen dst
    let struct (srcB, srcA) = transOprToExpr128 bld false ins insLen src
    bld <+ (dstA := dstA <+> srcA)
    bld <+ (dstB := dstB <+> srcB)
  | _ -> raise InvalidOperandSizeException
  bld --!> insLen

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
  | _ -> raise InvalidOperandSizeException

let private opPsllw oprSize = opShiftPackedDataLogical oprSize 16<rt> (<<)

let psllw ins insLen bld = buildPackedInstr ins insLen bld false 16<rt> opPsllw

let private opPslld oprSize = opShiftPackedDataLogical oprSize 32<rt> (<<)

let pslld ins insLen bld = buildPackedInstr ins insLen bld false 32<rt> opPslld

let private opPsllq oprSize = opShiftPackedDataLogical oprSize 64<rt> (<<)

let psllq ins insLen bld = buildPackedInstr ins insLen bld false 64<rt> opPsllq

let private opPsrlw oprSize = opShiftPackedDataLogical oprSize 16<rt> (>>)

let psrlw ins insLen bld = buildPackedInstr ins insLen bld false 16<rt> opPsrlw

let private opPsrld oprSize = opShiftPackedDataLogical oprSize 32<rt> (>>)

let psrld ins insLen bld = buildPackedInstr ins insLen bld false 32<rt> opPsrld

let private opPsrlq oprSize = opShiftPackedDataLogical oprSize 64<rt> (>>)

let psrlq ins insLen bld = buildPackedInstr ins insLen bld false 64<rt> opPsrlq

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
  | _ -> raise InvalidOperandSizeException

let private opPsraw oprSize = opShiftPackedDataRightArith oprSize 16<rt>

let psraw ins insLen bld = buildPackedInstr ins insLen bld false 16<rt> opPsraw

let private opPsrad oprSize = opShiftPackedDataRightArith oprSize 32<rt>

let psrad ins insLen bld = buildPackedInstr ins insLen bld false 32<rt> opPsrad

let emms (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  bld <+ (regVar bld R.FTW := maxNum 16<rt>)
  bld --!> insLen
