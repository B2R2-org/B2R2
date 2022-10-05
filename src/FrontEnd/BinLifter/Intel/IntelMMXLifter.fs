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

module internal B2R2.FrontEnd.BinLifter.Intel.MMXLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingOperators
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.BinLifter.Intel
open B2R2.FrontEnd.BinLifter.Intel.LiftingUtils

let private movdRegToReg ctxt r1 r2 ir =
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
  | _, Register.Kind.MMX ->
    !!ir (tmp := AST.xtlo 32<rt> (!.ctxt r2))
    !!ir (dstAssign 32<rt> (!.ctxt r1) tmp)
  | _, _ -> Utils.impossible ()

let private movdRegToMem ctxt dst r ir =
  match Register.getKind r with
  | Register.Kind.XMM ->
    !!ir (dst := AST.xtlo 32<rt> (getPseudoRegVar ctxt r 1))
  | Register.Kind.MMX -> !!ir (dst := AST.xtlo 32<rt> (!.ctxt r))
  | _ -> Utils.impossible ()

let private movdMemToReg ctxt src r ir =
  match Register.getKind r with
  | Register.Kind.XMM ->
    !!ir (getPseudoRegVar ctxt r 1 := AST.zext 64<rt> src)
    !!ir (getPseudoRegVar ctxt r 2 := AST.num0 64<rt>)
  | Register.Kind.MMX -> !!ir (!.ctxt r := AST.zext 64<rt> src)
  | _ -> Utils.impossible ()

let movd ins insLen ctxt =
  let ir = !*ctxt
  let struct (dst, src) = getTwoOprs ins
  !<ir insLen
  match dst, src  with
  | OprReg r1, OprReg r2 -> movdRegToReg ctxt r1 r2 ir
  | OprMem _, OprReg r -> let dst = transOprToExpr ins insLen ctxt dst
                          movdRegToMem ctxt dst r ir
  | OprReg r, OprMem _ -> let src = transOprToExpr ins insLen ctxt src
                          movdMemToReg ctxt src r ir
  | _, _ -> raise InvalidOperandException
  !>ir insLen

let private movqRegToReg ctxt r1 r2 ir =
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
  | Register.Kind.MMX, Register.Kind.GP
  | Register.Kind.GP, Register.Kind.MMX ->
    !!ir (!.ctxt r1 := !.ctxt r2)
  | _, _ -> Utils.impossible ()

let private movqRegToMem ctxt dst r ir =
  match Register.getKind r with
  | Register.Kind.XMM -> !!ir (dst := getPseudoRegVar ctxt r 1)
  | Register.Kind.MMX -> !!ir (dst := !.ctxt r)
  | _ -> Utils.impossible ()

let private movqMemToReg ctxt src r ir =
  match Register.getKind r with
  | Register.Kind.XMM ->
    !!ir (getPseudoRegVar ctxt r 1 := src)
    !!ir (getPseudoRegVar ctxt r 2 := AST.num0 64<rt>)
  | Register.Kind.MMX -> !!ir (!.ctxt r := src)
  | _ -> Utils.impossible ()

let movq ins insLen ctxt =
  let ir = !*ctxt
  let struct (dst, src) = getTwoOprs ins
  !<ir insLen
  match dst, src with
  | OprReg r1, OprReg r2 -> movqRegToReg ctxt r1 r2 ir
  | OprMem _, OprReg r -> let dst = transOprToExpr ins insLen ctxt dst
                          movqRegToMem ctxt dst r ir
  | OprReg r, OprMem _ -> let src = transOprToExpr ins insLen ctxt src
                          movqMemToReg ctxt src r ir
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

let makeSrc ir packSize packNum src =
  let tSrc = Array.init packNum (fun _ -> !+ir packSize)
  for i in 0 .. packNum - 1 do
    !!ir (tSrc[i] := AST.extract src packSize (i * (int packSize)))
  tSrc

let private buildPackedTwoOprs ins insLen ctxt packSz opFn dst src =
  let ir = !*ctxt
  let oprSize = getOperationSize ins
  let packNum = oprSize / packSz
  let makeSrc = makeSrc ir packSz
  !<ir insLen
  match oprSize with
  | 64<rt> ->
    let dst = transOprToExpr ins insLen ctxt dst
    let src = transOprToExpr ins insLen ctxt src
    let src1 = makeSrc packNum dst
    let src2 = match src.E with
               | Load (_, rt, _, _) -> makeSrc (rt / packSz) src
               | _ -> makeSrc packNum src
    !!ir (dst := opFn oprSize src1 src2 |> AST.concatArr)
  | 128<rt> ->
    let packNum = packNum / (oprSize / 64<rt>)
    let srcAppend src =
      let src = transOprToExprVec ins insLen ctxt src
      List.map (makeSrc packNum) src |> List.fold Array.append [||]
    let tSrc = opFn oprSize (srcAppend dst) (srcAppend src)
    let dst = transOprToExprVec ins insLen ctxt dst
    let packNum = Array.length tSrc / List.length dst
    let assign idx dst =
      !!ir (dst := Array.sub tSrc (packNum * idx) packNum |> AST.concatArr)
    List.iteri assign dst
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let private buildPackedThreeOprs ins iLen ctxt packSz opFn dst s1 s2 =
  let ir = !*ctxt
  let oprSize = getOperationSize ins
  let packNum = oprSize / packSz
  let makeSrc = makeSrc ir packSz
  !<ir iLen
  match oprSize with
  | 64<rt> ->
    let dst = transOprToExpr ins iLen ctxt dst
    let src1 = transOprToExpr ins iLen ctxt s1
    let src2 = transOprToExpr ins iLen ctxt s2
    let src1 = makeSrc packNum src1
    let src2 = makeSrc packNum src2
    !!ir (dst := opFn oprSize src1 src2 |> AST.concatArr)
  | 128<rt> | 256<rt> ->
    let packNum = packNum / (oprSize / 64<rt>)
    let dst = transOprToExprVec ins iLen ctxt dst
    let srcAppend src =
      let src = transOprToExprVec ins iLen ctxt src
      List.map (makeSrc packNum) src |> List.fold Array.append [||]
    let tSrc = opFn oprSize (srcAppend s1) (srcAppend s2)
    let assign idx dst =
      !!ir (dst := Array.sub tSrc (packNum * idx) packNum |> AST.concatArr)
    List.iteri assign dst
  | _ -> raise InvalidOperandSizeException
  !>ir iLen

let buildPackedInstr (ins: InsInfo) insLen ctxt packSz opFn =
  match ins.Operands with
  | TwoOperands (o1, o2) ->
    buildPackedTwoOprs ins insLen ctxt packSz opFn o1 o2
  | ThreeOperands (o1, o2, o3) ->
    buildPackedThreeOprs ins insLen ctxt packSz opFn o1 o2 o3
  | _ -> raise InvalidOperandException

let private opPackssdw _ src1 src2 =
  Array.append src1 src2 |> Array.map saturateSignedDwordToSignedWord

let packssdw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 32<rt> opPackssdw

let private opPacksswb _ src1 src2 =
  Array.append src1 src2 |> Array.map saturateSignedWordToSignedByte

let packsswb ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 16<rt> opPacksswb

let private opPackuswb _ src1 src2 =
  Array.append src1 src2 |> Array.map saturateSignedWordToUnsignedByte

let packuswb ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 16<rt> opPackuswb

let private opPunpck oprSize src1 src2 isHigh =
  match oprSize with
  | 64<rt> | 128<rt> ->
    let half = Array.length src1 / 2
    let sPos = if isHigh then half else 0
    let src1 = Array.sub src1 sPos half
    let src2 = Array.sub src2 sPos half
    Array.fold2 (fun acc e1 e2 -> e2 :: e1 :: acc) [] src1 src2
    |> List.rev |> List.toArray
  | 256<rt> ->
    let half = Array.length src1 / 2
    let src1A = Array.sub src1 0 half
    let src1B = Array.sub src1 half half
    let src2A = Array.sub src2 0 half
    let src2B = Array.sub src2 half half
    let half = Array.length src1A / 2
    let sPos = if isHigh then half else 0
    let src1A = Array.sub src1A sPos half
    let src2A = Array.sub src2A sPos half
    let src1B = Array.sub src1B sPos half
    let src2B = Array.sub src2B sPos half
    List.append
      (Array.fold2 (fun acc e1 e2 -> e2 :: e1 :: acc) [] src1B src2B)
      (Array.fold2 (fun acc e1 e2 -> e2 :: e1 :: acc) [] src1A src2A)
    |> List.rev |> List.toArray
  | _ -> raise InvalidOperandSizeException

let opPunpckHigh oprSize src1 src2 = opPunpck oprSize src1 src2 true

let opPunpckLow oprSize src1 src2 = opPunpck oprSize src1 src2 false

let punpckhbw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 8<rt> opPunpckHigh

let punpckhwd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 16<rt> opPunpckHigh

let punpckhdq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 32<rt> opPunpckHigh

let punpcklbw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 8<rt> opPunpckLow

let punpcklwd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 16<rt> opPunpckLow

let punpckldq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 32<rt> opPunpckLow

let opP op _ = Array.map2 (op)

let paddb ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 8<rt> (opP (.+))

let paddw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 16<rt> (opP (.+))

let paddd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 32<rt> (opP (.+))

let private opPaddsb oprSize src1 src2 =
  let src1 = src1 |> Array.map (AST.sext 16<rt>)
  let src2 = src2 |> Array.map (AST.sext 16<rt>)
  (opP (.+)) 16<rt> src1 src2 |> Array.map saturateToSignedByte

let paddsb ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 8<rt> opPaddsb

let private opPaddsw oprSize src1 src2 =
  let src1 = src1 |> Array.map (AST.sext 32<rt>)
  let src2 = src2 |> Array.map (AST.sext 32<rt>)
  (opP (.+)) 32<rt> src1 src2 |> Array.map saturateToSignedWord

let paddsw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 16<rt> opPaddsw

let private opPaddusb oprSize src1 src2 =
  let src1 = src1 |> Array.map (AST.zext 16<rt>)
  let src2 = src2 |> Array.map (AST.zext 16<rt>)
  (opP (.+)) 16<rt> src1 src2 |> Array.map saturateToUnsignedByte

let paddusb ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 8<rt> opPaddusb

let private opPaddusw oprSize src1 src2 =
  let src1 = src1 |> Array.map (AST.zext 32<rt>)
  let src2 = src2 |> Array.map (AST.zext 32<rt>)
  (opP (.+)) 32<rt> src1 src2 |> Array.map saturateToUnsignedWord

let paddusw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 16<rt> opPaddusw

let private makeHorizonSrc ir packSz src1 src2 =
  let packNum = 64<rt> / packSz
  let pHalf = packNum / 2
  let t1 = Array.init packNum (fun _ -> !+ir packSz)
  let t2 = Array.init packNum (fun _ -> !+ir packSz)
  for i in 0 .. pHalf - 1 do
    !!ir (t1[i] := AST.extract src1 packSz (2 * i * (int packSz)))
    !!ir (t2[i] := AST.extract src1 packSz ((2 * i + 1) * (int packSz)))
    !!ir (t1[i + pHalf] := AST.extract src2 packSz (2 * i * (int packSz)))
    !!ir (t2[i + pHalf] := AST.extract src2 packSz ((2 * i + 1) * (int packSz)))
  done
  t1, t2

let packedHorizon ins insLen ctxt packSz opFn =
  let ir = !*ctxt
  let struct (dst, src) = getTwoOprs ins
  let oprSize = getOperationSize ins
  !<ir insLen
  match oprSize with
  | 64<rt> ->
    let dst = transOprToExpr ins insLen ctxt dst
    let src = transOprToExpr ins insLen ctxt src
    let src1, src2 = makeHorizonSrc ir packSz dst src
    !!ir (dst := opFn oprSize src1 src2 |> AST.concatArr)
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
    let srcB, srcA = transOprToExpr128 ins insLen ctxt src
    let src1, src2 = makeHorizonSrc ir packSz dstA dstB
    !!ir (dstA := opFn oprSize src1 src2 |> AST.concatArr)
    let src3, src4 = makeHorizonSrc ir packSz srcA srcB
    !!ir (dstB := opFn oprSize src3 src4 |> AST.concatArr)
  | _ -> raise InvalidOperandSizeException
  !>ir insLen

let phaddd ins insLen ctxt =
  packedHorizon ins insLen ctxt 32<rt> (opP (.+))

let phaddw ins insLen ctxt =
  packedHorizon ins insLen ctxt 16<rt> (opP (.+))

let phaddsw ins insLen ctxt =
  packedHorizon ins insLen ctxt 16<rt> opPaddsw

let psubb ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 8<rt> (opP (.-))

let psubw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 16<rt> (opP (.-))

let psubd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 32<rt> (opP (.-))

let private opPsubsb oprSize src1 src2 =
  let src1 = src1 |> Array.map (AST.sext 16<rt>)
  let src2 = src2 |> Array.map (AST.sext 16<rt>)
  (opP (.-)) 16<rt> src1 src2 |> Array.map saturateToSignedByte

let psubsb ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 8<rt> opPsubsb

let private opPsubsw oprSize src1 src2 =
  let src1 = src1 |> Array.map (AST.sext 32<rt>)
  let src2 = src2 |> Array.map (AST.sext 32<rt>)
  (opP (.-)) 32<rt> src1 src2 |> Array.map saturateToSignedWord

let psubsw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 16<rt> opPsubsw

let private opPsubusb _ src1 src2 =
  let src1 = src1 |> Array.map (AST.zext 16<rt>)
  let src2 = src2 |> Array.map (AST.zext 16<rt>)
  (opP (.-)) 16<rt> src1 src2 |> Array.map saturateToUnsignedByte

let psubusb ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 8<rt> opPsubusb

let private opPsubusw _ src1 src2 =
  let src1 = src1 |> Array.map (AST.zext 32<rt>)
  let src2 = src2 |> Array.map (AST.zext 32<rt>)
  (opP (.-)) 32<rt> src1 src2 |> Array.map saturateToUnsignedWord

let psubusw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 16<rt> opPsubusw

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
  buildPackedInstr ins insLen ctxt 16<rt> opPmulhw

let private opPmullw _ = opPmul AST.xtlo AST.sext 32<rt> 16<rt>

let pmullw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 16<rt> opPmullw

let private opPmaddwd _ =
  let lowAndSExt expr = AST.xtlo 16<rt> expr |> AST.sext 32<rt>
  let highAndSExt expr = AST.xthi 16<rt> expr |> AST.sext 32<rt>
  let mulLow e1 e2 = lowAndSExt e1 .* lowAndSExt e2
  let mulHigh e1 e2 = highAndSExt e1 .* highAndSExt e2
  let packAdd e1 e2 = mulLow e1 e2 .+ mulHigh e1 e2
  Array.map2 packAdd

let pmaddwd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 32<rt> opPmaddwd

let opPcmp packSz cmpOp =
  Array.map2 (fun e1 e2 ->
    AST.ite (cmpOp e1 e2) (getMask packSz) (AST.num0 packSz))

let opPcmpeqb _ = opPcmp 8<rt> (==)

let pcmpeqb ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 8<rt> opPcmpeqb

let private opPcmpeqw _ = opPcmp 16<rt> (==)

let pcmpeqw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 16<rt> opPcmpeqw

let opPcmpeqd _ = opPcmp 32<rt> (==)

let pcmpeqd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 32<rt> opPcmpeqd

let opPcmpgtb _ = opPcmp 8<rt> AST.sgt

let pcmpgtb ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 8<rt> opPcmpgtb

let private opPcmpgtw _ = opPcmp 16<rt> AST.sgt

let pcmpgtw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 16<rt> opPcmpgtw

let private opPcmpgtd _ = opPcmp 32<rt> AST.sgt

let pcmpgtd ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 32<rt> opPcmpgtd

let opPand _ = Array.map2 (.&)

let pand ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 64<rt> opPand

let opPandn _ = Array.map2 (fun e1 e2 -> (AST.not e1) .& e2)

let pandn ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 64<rt> opPandn

let opPor _ = Array.map2 (.|)

let por ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 64<rt> opPor

let pxor ins insLen ctxt =
  let ir = !*ctxt
  let oprSize = getOperationSize ins
  !<ir insLen
  match oprSize with
  | 64<rt> ->
    let struct (dst, src) = transTwoOprs ins insLen ctxt
    !!ir (dst := dst <+> src)
  | 128<rt> ->
    let struct (dst, src) = getTwoOprs ins
    let dstB, dstA = transOprToExpr128 ins insLen ctxt dst
    let srcB, srcA = transOprToExpr128 ins insLen ctxt src
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
  buildPackedInstr ins insLen ctxt 16<rt> opPsllw

let private opPslld oprSize = opShiftPackedDataLogical oprSize 32<rt> (<<)

let pslld ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 32<rt> opPslld

let private opPsllq oprSize = opShiftPackedDataLogical oprSize 64<rt> (<<)

let psllq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 64<rt> opPsllq

let private opPsrlw oprSize = opShiftPackedDataLogical oprSize 16<rt> (>>)

let psrlw ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 16<rt> opPsrlw

let private opPsrld oprSize = opShiftPackedDataLogical oprSize 32<rt> (>>)

let psrld ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 32<rt> opPsrld

let private opPsrlq oprSize = opShiftPackedDataLogical oprSize 64<rt> (>>)

let psrlq ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 64<rt> opPsrlq

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
  buildPackedInstr ins insLen ctxt 16<rt> opPsraw

let private opPsrad oprSize = opShiftPackedDataRightArith oprSize 32<rt>

let psrad ins insLen ctxt =
  buildPackedInstr ins insLen ctxt 32<rt> opPsrad

let emms _ins insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  !!ir (!.ctxt R.FTW := maxNum 16<rt>)
  !>ir insLen
