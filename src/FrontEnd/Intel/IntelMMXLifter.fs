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
open B2R2.Collections
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingOperators
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.Intel
open B2R2.FrontEnd.Intel.LiftingUtils

let private movdRegToReg ins ctxt r1 r2 ir =
  let tmp = !+ir 32<rt>
  match Register.getKind r1, Register.getKind r2 with
  | Register.Kind.XMM, _ ->
    !!ir (getPseudoRegVar ctxt r1 1 := AST.zext 64<rt> (!.ctxt r2))
    !!ir (getPseudoRegVar ctxt r1 2 := AST.num0 64<rt>)
  | _, Register.Kind.XMM ->
    !!ir (tmp := AST.xtlo 32<rt> (getPseudoRegVar ctxt r2 1))
    !!ir (dstAssign 32<rt> (!.ctxt r1) tmp)
  | Register.Kind.MMX, _ ->
    !!ir (!.ctxt r1 := AST.zext 64<rt> (!.ctxt r2))
    fillOnesToMMXHigh16 ir ins ctxt
  | _, Register.Kind.MMX ->
    !!ir (tmp := AST.xtlo 32<rt> (!.ctxt r2))
    !!ir (dstAssign 32<rt> (!.ctxt r1) tmp)
  | _, _ -> Terminator.impossible ()

let private movdRegToMem ctxt dst r ir =
  match Register.getKind r with
  | Register.Kind.XMM ->
    !!ir (dst := AST.xtlo 32<rt> (getPseudoRegVar ctxt r 1))
  | Register.Kind.MMX -> !!ir (dst := AST.xtlo 32<rt> (!.ctxt r))
  | _ -> Terminator.impossible ()

let private movdMemToReg ins ctxt src r ir =
  match Register.getKind r with
  | Register.Kind.XMM ->
    !!ir (getPseudoRegVar ctxt r 1 := AST.zext 64<rt> src)
    !!ir (getPseudoRegVar ctxt r 2 := AST.num0 64<rt>)
  | Register.Kind.MMX ->
    !!ir (!.ctxt r := AST.zext 64<rt> src)
    fillOnesToMMXHigh16 ir ins ctxt
  | _ -> Terminator.impossible ()

let movd ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  match dst, src with
  | OprReg r1, OprReg r2 -> movdRegToReg ins ctxt r1 r2 ir
  | OprMem _, OprReg r ->
    let dst = transOprToExpr ir false ins insLen ctxt dst
    movdRegToMem ctxt dst r ir
  | OprReg r, OprMem _ ->
    let src = transOprToExpr ir false ins insLen ctxt src
    movdMemToReg ins ctxt src r ir
  | _, _ -> raise InvalidOperandException
  !>ir insLen

let private movqRegToReg ins ctxt r1 r2 ir =
  match Register.getKind r1, Register.getKind r2 with
  | Register.Kind.XMM, Register.Kind.XMM ->
    !!ir (getPseudoRegVar ctxt r1 1 := getPseudoRegVar ctxt r2 1 )
    !!ir (getPseudoRegVar ctxt r1 2 := AST.num0 64<rt>)
  | Register.Kind.XMM, _ ->
    !!ir (getPseudoRegVar ctxt r1 1 := !.ctxt r2)
    !!ir (getPseudoRegVar ctxt r1 2 := AST.num0 64<rt>)
  | Register.Kind.GP, Register.Kind.XMM ->
    !!ir (!.ctxt r1 := getPseudoRegVar ctxt r2 1)
  | Register.Kind.MMX, Register.Kind.MMX
  | Register.Kind.MMX, Register.Kind.GP ->
    !!ir (!.ctxt r1 := !.ctxt r2)
    fillOnesToMMXHigh16 ir ins ctxt
  | Register.Kind.GP, Register.Kind.MMX ->
    !!ir (!.ctxt r1 := !.ctxt r2)
  | _ -> raise InvalidOperandException

let private movqRegToMem ctxt dst r ir =
  match Register.getKind r with
  | Register.Kind.XMM -> !!ir (dst := getPseudoRegVar ctxt r 1)
  | Register.Kind.MMX -> !!ir (dst := !.ctxt r)
  | _ -> raise InvalidOperandException

let private movqMemToReg ins ctxt src r ir =
  match Register.getKind r with
  | Register.Kind.XMM ->
    !!ir (getPseudoRegVar ctxt r 1 := src)
    !!ir (getPseudoRegVar ctxt r 2 := AST.num0 64<rt>)
  | Register.Kind.MMX ->
    !!ir (!.ctxt r := src)
    fillOnesToMMXHigh16 ir ins ctxt
  | _ -> raise InvalidOperandException

let movq ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  match dst, src with
  | OprReg r1, OprReg r2 -> movqRegToReg ins ctxt r1 r2 ir
  | OprMem _, OprReg r ->
    let dst = transOprToExpr ir false ins insLen ctxt dst
    movqRegToMem ctxt dst r ir
  | OprReg r, OprMem _ ->
    let src = transOprToExpr ir false ins insLen ctxt src
    movqMemToReg ins ctxt src r ir
  | _, _ -> raise InvalidOperandException
  !>ir insLen

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

let fillZeroHigh128 ctxt dst ir =
  let dst = r128to256 dst
  let dstC, dstD = getPseudoRegVar ctxt dst 3, getPseudoRegVar ctxt dst 4
  let n0 = AST.num0 64<rt>
  !!ir (dstC := n0)
  !!ir (dstD := n0)

let fillZeroHigh256 ctxt dst ir =
  let dst = r256to512 dst
  let dstE, dstF, dstG, dstH =
    getPseudoRegVar ctxt dst 3, getPseudoRegVar ctxt dst 4,
    getPseudoRegVar ctxt dst 5, getPseudoRegVar ctxt dst 6
  let n0 = AST.num0 64<rt>
  !!ir (dstE := n0)
  !!ir (dstF := n0)
  !!ir (dstG := n0)
  !!ir (dstH := n0)

let fillZeroFromVLToMaxVL ctxt dst vl maxVl ir =
  let n0 = AST.num0 64<rt>
  match dst with
  | OprReg _ ->
    match maxVl, vl with
    | 512, 128<rt> ->
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
    | 512, 256<rt> ->
      let dst = r256to512 dst
      let dstE, dstF, dstG, dstH =
        getPseudoRegVar ctxt dst 5, getPseudoRegVar ctxt dst 6,
        getPseudoRegVar ctxt dst 7, getPseudoRegVar ctxt dst 8
      !!ir (dstE := n0)
      !!ir (dstF := n0)
      !!ir (dstG := n0)
      !!ir (dstH := n0)
    | 512, 512<rt> -> ()
    | _ -> raise InvalidOperandSizeException
  | _ -> ()

let private buildPackedTwoOprs ins insLen ctxt isFillZero packSz opFn dst src =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let packNum = 64<rt> / packSz
  let src1 = transOprToArr ir true ins insLen ctxt packSz packNum oprSize dst
  let src2 = transOprToArr ir true ins insLen ctxt packSz packNum oprSize src
  let result = opFn oprSize src1 src2
  assignPackedInstr ir false ins insLen ctxt packNum oprSize dst result
  if isFillZero then fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir else ()
  !>ir insLen

let private buildPackedThreeOprs i iLen ctxt isFillZero packSz opFn dst s1 s2 =
  let ir = !*ctxt
  !<ir iLen
  let oprSize = getOperationSize i
  let packNum = 64<rt> / packSz
  let src1 = transOprToArr ir true i iLen ctxt packSz packNum oprSize s1
  let src2 = transOprToArr ir true i iLen ctxt packSz packNum oprSize s2
  let result = opFn oprSize src1 src2
  assignPackedInstr ir false i iLen ctxt packNum oprSize dst result
  if isFillZero then fillZeroFromVLToMaxVL ctxt dst oprSize 512 ir else ()
  !>ir iLen

let buildPackedInstr (ins: InsInfo) insLen ctxt isFillZero packSz opFn =
  match ins.Operands with
  | TwoOperands (o1, o2) ->
    buildPackedTwoOprs ins insLen ctxt isFillZero packSz opFn o1 o2
  | ThreeOperands (o1, o2, o3) ->
    buildPackedThreeOprs ins insLen ctxt isFillZero packSz opFn o1 o2 o3
  | _ -> raise InvalidOperandException

let private packWithSaturation ins insLen ctxt packSz opFn =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let sPackSz = packSz
  let sPackNum = 64<rt> / sPackSz
  let dPackSz = packSz / 2
  let dPackNum = 64<rt> / dPackSz
  let struct (dst, src) = getTwoOprs ins
  let src1 = transOprToArr ir true ins insLen ctxt sPackSz sPackNum oprSize dst
  let src2 = transOprToArr ir true ins insLen ctxt sPackSz sPackNum oprSize src
  let result = opFn oprSize src1 src2
  assignPackedInstr ir false ins insLen ctxt dPackNum oprSize dst result
  !>ir insLen

let private opPackssdw _ src1 src2 =
  Array.append src1 src2 |> Array.map saturateSignedDwordToSignedWord

let packssdw ins insLen ctxt =
  packWithSaturation ins insLen ctxt 32<rt> opPackssdw

let private opPacksswb _ src1 src2 =
  Array.append src1 src2 |> Array.map saturateSignedWordToSignedByte

let packsswb ins insLen ctxt =
  packWithSaturation ins insLen ctxt 16<rt> opPacksswb

let private opPackuswb _ src1 src2 =
  Array.append src1 src2 |> Array.map saturateSignedWordToUnsignedByte

let packuswb ins insLen ctxt =
  packWithSaturation ins insLen ctxt 16<rt> opPackuswb

let unpackLowHighData ins insLen ctxt packSize isHigh =
  let ir = !*ctxt
  !<ir insLen
  let oprSz = getOperationSize ins
  let packNum = 64<rt> / packSize
  let allPackNum = oprSz / packSize
  let struct (dst, src1, src2) = getThreeOprs ins
  let src1 = transOprToArr ir true ins insLen ctxt packSize packNum oprSz src1
  let src2 = transOprToArr ir true ins insLen ctxt packSize packNum oprSz src2
  let resultA, resultB =
    Array.fold2 (fun acc e1 e2 -> e2 :: e1 :: acc) [] src1 src2
    |> List.rev |> List.toArray |> Array.splitAt allPackNum
  let result =
    if oprSz = 128<rt> then
      if isHigh then resultB else resultA
    elif oprSz = 256<rt> then
      let resALow, resAHigh = Array.splitAt (allPackNum / 2) resultA
      let resBLow, resBHigh = Array.splitAt (allPackNum / 2) resultB
      if isHigh then Array.append resAHigh resBHigh else
      Array.append resALow resBLow
    else raise InvalidOperandSizeException
  assignPackedInstr ir false ins insLen ctxt packNum oprSz dst result
  fillZeroFromVLToMaxVL ctxt dst oprSz 512 ir
  !>ir insLen

let opUnpackHighData oprSize src1 src2 =
  let result =
    Array.fold2 (fun acc e1 e2 -> e2 :: e1 :: acc) [] src1 src2
    |> List.rev |> List.toArray
  let resultA, resultB = Array.splitAt (Array.length result / 2) result
  match oprSize with
  | 64<rt> | 128<rt> -> resultB
  | 256<rt> ->
    let _, resAHigh = Array.splitAt (Array.length resultA / 2) resultA
    let _, resBHigh = Array.splitAt (Array.length resultB / 2) resultB
    Array.append resAHigh resBHigh
  | _ -> raise InvalidOperandSizeException

let opUnpackLowData oprSize src1 src2 =
  let result =
    Array.fold2 (fun acc e1 e2 -> e2 :: e1 :: acc) [] src1 src2
    |> List.rev |> List.toArray
  let resultA, resultB = Array.splitAt (Array.length result / 2) result
  match oprSize with
  | 64<rt> | 128<rt> -> resultA
  | 256<rt> ->
    let resALow, _ = Array.splitAt (Array.length resultA / 2) resultA
    let resBLow, _ = Array.splitAt (Array.length resultB / 2) resultB
    Array.append resALow resBLow
  | _ -> raise InvalidOperandSizeException

let punpckhbw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 8<rt> opUnpackHighData

let punpckhwd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 16<rt> opUnpackHighData

let punpckhdq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 32<rt> opUnpackHighData

let punpcklbw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 8<rt> opUnpackLowData

let punpcklwd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 16<rt> opUnpackLowData

let punpckldq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 32<rt> opUnpackLowData

let opP op _ = Array.map2 (op)

let paddb ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 8<rt> (opP (.+))

let paddw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 16<rt> (opP (.+))

let paddd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 32<rt> (opP (.+))

let private opPaddsb oprSize src1 src2 =
  let src1 = src1 |> Array.map (AST.sext 16<rt>)
  let src2 = src2 |> Array.map (AST.sext 16<rt>)
  (opP (.+)) 16<rt> src1 src2 |> Array.map saturateToSignedByte

let paddsb ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 8<rt> opPaddsb

let private opPaddsw oprSize src1 src2 =
  let src1 = src1 |> Array.map (AST.sext 32<rt>)
  let src2 = src2 |> Array.map (AST.sext 32<rt>)
  (opP (.+)) 32<rt> src1 src2 |> Array.map saturateToSignedWord

let paddsw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 16<rt> opPaddsw

let private opPaddusb oprSize src1 src2 =
  let src1 = src1 |> Array.map (AST.zext 16<rt>)
  let src2 = src2 |> Array.map (AST.zext 16<rt>)
  (opP (.+)) 16<rt> src1 src2 |> Array.map saturateToUnsignedByte

let paddusb ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 8<rt> opPaddusb

let private opPaddusw oprSize src1 src2 =
  let src1 = src1 |> Array.map (AST.zext 32<rt>)
  let src2 = src2 |> Array.map (AST.zext 32<rt>)
  (opP (.+)) 32<rt> src1 src2 |> Array.map saturateToUnsignedWord

let paddusw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 16<rt> opPaddusw

let private makeHorizonSrc src1 src2 =
  let (odd, even), _ =
    Array.foldi (fun (odd, even) i e ->
                  if i % 2 = 0 then e :: odd, even
                  else odd, e :: even) ([], []) (Array.append src1 src2)
  odd |> List.rev |> List.toArray, even |> List.rev |> List.toArray

let packedHorizon ins insLen ctxt packSz opFn =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  let struct (dst, src) = getTwoOprs ins
  let packNum = 64<rt> / packSz
  let src1 = transOprToArr ir true ins insLen ctxt packSz packNum oprSize dst
  let src2 = transOprToArr ir true ins insLen ctxt packSz packNum oprSize src
  let src1, src2 = makeHorizonSrc src1 src2
  let result = opFn oprSize src1 src2
  assignPackedInstr ir false ins insLen ctxt packNum oprSize dst result
  !>ir insLen

let phaddd ins insLen ctxt =
  packedHorizon ins insLen ctxt 32<rt> (opP (.+))

let phaddw ins insLen ctxt =
  packedHorizon ins insLen ctxt 16<rt> (opP (.+))

let phaddsw ins insLen ctxt =
  packedHorizon ins insLen ctxt 16<rt> opPaddsw

let psubb ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 8<rt> (opP (.-))

let psubw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 16<rt> (opP (.-))

let psubd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 32<rt> (opP (.-))

let private opPsubsb oprSize src1 src2 =
  let src1 = src1 |> Array.map (AST.sext 16<rt>)
  let src2 = src2 |> Array.map (AST.sext 16<rt>)
  (opP (.-)) 16<rt> src1 src2 |> Array.map saturateToSignedByte

let psubsb ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 8<rt> opPsubsb

let private opPsubsw oprSize src1 src2 =
  let src1 = src1 |> Array.map (AST.sext 32<rt>)
  let src2 = src2 |> Array.map (AST.sext 32<rt>)
  (opP (.-)) 32<rt> src1 src2 |> Array.map saturateToSignedWord

let psubsw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 16<rt> opPsubsw

let private opPsubusb _ src1 src2 =
  let src1 = src1 |> Array.map (AST.zext 16<rt>)
  let src2 = src2 |> Array.map (AST.zext 16<rt>)
  (opP (.-)) 16<rt> src1 src2 |> Array.map saturateToUnsignedByte

let psubusb ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 8<rt> opPsubusb

let private opPsubusw _ src1 src2 =
  let src1 = src1 |> Array.map (AST.zext 32<rt>)
  let src2 = src2 |> Array.map (AST.zext 32<rt>)
  (opP (.-)) 32<rt> src1 src2 |> Array.map saturateToUnsignedWord

let psubusw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 16<rt> opPsubusw

let phsubd ins insLen ctxt =
  packedHorizon ins insLen ctxt 32<rt> (opP (.-))

let phsubw ins insLen ctxt =
  packedHorizon ins insLen ctxt 16<rt> (opP (.-))

let phsubsw ins insLen ctxt =
  packedHorizon ins insLen ctxt 16<rt> opPsubsw

let opPmul resType extr extSz packSz src1 src2 =
  Array.map2 (fun e1 e2 -> extr extSz e1 .* extr extSz e2) src1 src2
  |> Array.map (resType packSz)

let private opPmulhw _ = opPmul AST.xthi AST.sext 32<rt> 16<rt>

let pmulhw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 16<rt> opPmulhw

let opPmullw _ = opPmul AST.xtlo AST.sext 32<rt> 16<rt>

let pmullw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 16<rt> opPmullw

let private opPmaddwd _ =
  let lowAndSExt expr = AST.xtlo 16<rt> expr |> AST.sext 32<rt>
  let highAndSExt expr = AST.xthi 16<rt> expr |> AST.sext 32<rt>
  let mulLow e1 e2 = lowAndSExt e1 .* lowAndSExt e2
  let mulHigh e1 e2 = highAndSExt e1 .* highAndSExt e2
  let packAdd e1 e2 = mulLow e1 e2 .+ mulHigh e1 e2
  Array.map2 packAdd

let pmaddwd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 32<rt> opPmaddwd

let opPcmp packSz cmpOp =
  Array.map2 (fun e1 e2 ->
    AST.ite (cmpOp e1 e2) (getMask packSz) (AST.num0 packSz))

let opPcmpeqb _ = opPcmp 8<rt> (==)

let pcmpeqb ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 8<rt> opPcmpeqb

let private opPcmpeqw _ = opPcmp 16<rt> (==)

let pcmpeqw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 16<rt> opPcmpeqw

let opPcmpeqd _ = opPcmp 32<rt> (==)

let pcmpeqd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 32<rt> opPcmpeqd

let opPcmpgtb _ = opPcmp 8<rt> AST.sgt

let pcmpgtb ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 8<rt> opPcmpgtb

let private opPcmpgtw _ = opPcmp 16<rt> AST.sgt

let pcmpgtw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 16<rt> opPcmpgtw

let private opPcmpgtd _ = opPcmp 32<rt> AST.sgt

let pcmpgtd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 32<rt> opPcmpgtd

let opPand _ = Array.map2 (.&)

let pand ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 64<rt> opPand

let opPandn _ = Array.map2 (fun e1 e2 -> (AST.not e1) .& e2)

let pandn ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 64<rt> opPandn

let opPor _ = Array.map2 (.|)

let por ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 64<rt> opPor

let pxor ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let oprSize = getOperationSize ins
  match oprSize with
  | 64<rt> ->
    let struct (dst, src) = transTwoOprs ir false ins insLen ctxt
    !!ir (dst := dst <+> src)
    fillOnesToMMXHigh16 ir ins ctxt
  | 128<rt> ->
    let struct (dst, src) = getTwoOprs ins
    let dstB, dstA = transOprToExpr128 ir false ins insLen ctxt dst
    let srcB, srcA = transOprToExpr128 ir false ins insLen ctxt src
    !!ir (dstA := dstA <+> srcA)
    !!ir (dstB := dstB <+> srcB)
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let private opShiftPackedDataLogical oprSize packSz shift src1 src2 =
  let pNum = int (oprSize / packSz)
  let z = AST.num0 packSz
  match oprSize with
  | 64<rt> ->
    let count = AST.concatArr src2 |> AST.zext 64<rt>
    let cond = count .> (numI32 ((int packSz) - 1) 64<rt>)
    Array.map (fun e ->
      AST.ite cond z (AST.xtlo packSz (shift (AST.zext 64<rt> e) count))) src1
  | 128<rt> ->
    let count = AST.concatArr (Array.sub src2 0 (pNum / 2)) |> AST.zext 64<rt>
    let cond = count .> (numI32 ((int packSz) - 1) 64<rt>)
    Array.map (fun e ->
      AST.ite cond z (AST.xtlo packSz (shift (AST.zext 64<rt> e) count))) src1
   | _ -> raise InvalidOperandSizeException

let private opPsllw oprSize = opShiftPackedDataLogical oprSize 16<rt> (<<)

let psllw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 16<rt> opPsllw

let private opPslld oprSize = opShiftPackedDataLogical oprSize 32<rt> (<<)

let pslld ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 32<rt> opPslld

let private opPsllq oprSize = opShiftPackedDataLogical oprSize 64<rt> (<<)

let psllq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 64<rt> opPsllq

let private opPsrlw oprSize = opShiftPackedDataLogical oprSize 16<rt> (>>)

let psrlw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 16<rt> opPsrlw

let private opPsrld oprSize = opShiftPackedDataLogical oprSize 32<rt> (>>)

let psrld ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 32<rt> opPsrld

let private opPsrlq oprSize = opShiftPackedDataLogical oprSize 64<rt> (>>)

let psrlq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 64<rt> opPsrlq

let private opShiftPackedDataRightArith oprSize packSz src1 src2 =
  let pNum = int (oprSize / packSz)
  match oprSize with
  | 64<rt> ->
    let count = AST.concatArr src2 |> AST.zext 64<rt>
    let cond = count .> (numI32 ((int packSz) - 1) 64<rt>)
    let count = AST.ite cond (numI32 (int packSz) 64<rt>) count
    Array.map (fun e -> AST.xtlo packSz ((AST.sext 64<rt> e) ?>> count)) src1
  | 128<rt> ->
    let count = AST.concatArr (Array.sub src2 0 (pNum / 2)) |> AST.zext 64<rt>
    let cond = count .> (numI32 ((int packSz) - 1) 64<rt>)
    let count = AST.ite cond (numI32 (int packSz) 64<rt>) count
    Array.map (fun e -> AST.xtlo packSz ((AST.sext 64<rt> e) ?>> count)) src1
   | _ -> raise InvalidOperandSizeException

let private opPsraw oprSize = opShiftPackedDataRightArith oprSize 16<rt>

let psraw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 16<rt> opPsraw

let private opPsrad oprSize = opShiftPackedDataRightArith oprSize 32<rt>

let psrad ins insLen ctxt =
  buildPackedInstr ins insLen ctxt false 32<rt> opPsrad

let emms _ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  !!ir (!.ctxt R.FTW := maxNum 16<rt>)
  !>ir insLen
