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

module internal B2R2.FrontEnd.BinLifter.ARM64.Lifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingOperators
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.BinLifter.ARM64
open B2R2.FrontEnd.BinLifter.ARM64.LiftingUtils

/// A module for all AArch64-IR translation functions
let sideEffects insLen ctxt name =
  let ir = !*ctxt
  !<ir insLen
  !!ir (AST.sideEffect name)
  !>ir insLen

let abs ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  let n1 = !+ir eSize
  !!ir (n1 := AST.num1 eSize)
  let dstB, dstA = transOprToExpr128 ins ctxt addr dst
  let src = transSIMDOprToExpr ctxt eSize dataSize elements src
  let result = Array.map (fun e -> (e << n1) >> n1) src
  dstAssignForSIMD dstA dstB result dataSize elements ir
  !>ir insLen

let adc ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let c = AST.zext ins.OprSize (getRegVar ctxt R.C)
  !<ir insLen
  let result, _ = addWithCarry src1 src2 c ins.OprSize
  dstAssign ins.OprSize dst result ir
  !>ir insLen

let adcs ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let c = AST.zext ins.OprSize (getRegVar ctxt R.C)
  !<ir insLen
  let result, (n, z, c, v)= addWithCarry src1 src2 c ins.OprSize
  !!ir (getRegVar ctxt R.N := n)
  !!ir (getRegVar ctxt R.Z := z)
  !!ir (getRegVar ctxt R.C := c)
  !!ir (getRegVar ctxt R.V := v)
  dstAssign ins.OprSize dst result ir
  !>ir insLen

let add ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  match ins.Operands with
  | ThreeOperands (OprSIMD (SIMDVecReg _) as o1, o2, o3) ->
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let dstB, dstA = transOprToExpr128 ins ctxt addr o1
    let src1 = transSIMDOprToExpr ctxt eSize dataSize elements o2
    let src2 = transSIMDOprToExpr ctxt eSize dataSize elements o3
    let result = Array.map2 (.+) src1 src2
    dstAssignForSIMD dstA dstB result dataSize elements ir
  | ThreeOperands _ (* SIMD Scalar *) ->
    let dst, src1, src2 = transThreeOprs ins ctxt addr
    dstAssign ins.OprSize dst (src1 .+ src2) ir
  | FourOperands _ (* Arithmetic *) ->
    let dst, s1, s2 = transFourOprsWithBarrelShift ins ctxt addr
    let result, _ = addWithCarry s1 s2 (AST.num0 ins.OprSize) ins.OprSize
    dstAssign ins.OprSize dst result ir
  | _ -> raise InvalidOperandException
  !>ir insLen

let addp ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  match ins.Operands with
  | TwoOperands (dst, src) -> (* Scalar *)
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
    let src = transSIMDOprToExpr ctxt eSize dataSize elements src
    let result = Array.reduce (.+) src
    dstAssignScalar ins ctxt addr dst result eSize ir
  | ThreeOperands (dst, src1, src2) -> (* Vector *)
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let dstB, dstA = transOprToExpr128 ins ctxt addr dst
    let src1 = transSIMDOprToExpr ctxt eSize dataSize elements src1
    let src2 = transSIMDOprToExpr ctxt eSize dataSize elements src2
    let result =
      Array.append src1 src2 |> Array.chunkBySize 2
      |> Array.map (fun e -> e[0] .+ e[1])
    dstAssignForSIMD dstA dstB result dataSize elements ir
  | _ -> raise InvalidOperandException
  !>ir insLen

let adds ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2 = transFourOprsWithBarrelShift ins ctxt addr
  let oSz = ins.OprSize
  !<ir insLen
  let result, (n, z, c, v) = addWithCarry src1 src2 (AST.num0 oSz) oSz
  !!ir (getRegVar ctxt R.N := n)
  !!ir (getRegVar ctxt R.Z := z)
  !!ir (getRegVar ctxt R.C := c)
  !!ir (getRegVar ctxt R.V := v)
  dstAssign ins.OprSize dst result ir
  !>ir insLen

let addv ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
  let src = transSIMDOprToExpr ctxt eSize dataSize elements src
  let result = Array.reduce (.+) src
  dstAssignScalar ins ctxt addr dst result eSize ir
  !>ir insLen

let adr ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, label = transTwoOprs ins ctxt addr
  !<ir insLen
  !!ir (dst := getPC ctxt .+ label)
  !>ir insLen

let adrp ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, lbl = transTwoOprs ins ctxt addr
  !<ir insLen
  !!ir (dst := (getPC ctxt .& numI64 0xfffffffffffff000L 64<rt>) .+ lbl)
  !>ir insLen

let logAnd ins insLen ctxt addr = (* AND *)
  let ir = !*ctxt
  !<ir insLen
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let dstB, dstA = transOprToExpr128 ins ctxt addr dst
    let src1B, src1A = transOprToExpr128 ins ctxt addr src1
    let src2B, src2A = transOprToExpr128 ins ctxt addr src2
    !!ir (dstA := src1A .& src2A)
    !!ir (dstB := src1B .& src2B)
  | _ ->
    let dst, src1, src2 = transOprToExprOfAND ins ctxt addr
    dstAssign ins.OprSize dst (src1 .& src2) ir
  !>ir insLen

let asrv ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let amount = src2 .% oprSzToExpr ins.OprSize
  !<ir insLen
  !!ir (dst := shiftReg src1 amount ins.OprSize SRTypeASR)
  !>ir insLen

let ands ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2 = transOprToExprOfAND ins ctxt addr
  let result = !+ir ins.OprSize
  !<ir insLen
  !!ir (result := src1 .& src2)
  !!ir (getRegVar ctxt R.N := AST.xthi 1<rt> result)
  !!ir (getRegVar ctxt R.Z := (result == AST.num0 ins.OprSize))
  !!ir (getRegVar ctxt R.C := AST.b0)
  !!ir (getRegVar ctxt R.V := AST.b0)
  dstAssign ins.OprSize dst result ir
  !>ir insLen

let b ins insLen ctxt addr =
  let ir = !*ctxt
  let label = transOneOpr ins ctxt addr
  let pc = getPC ctxt
  !<ir insLen
  !!ir (AST.interjmp (pc .+ label) InterJmpKind.Base)
  !>ir insLen

let bCond ins insLen ctxt addr cond =
  let ir = !*ctxt
  let label = transOneOpr ins ctxt addr
  let pc = getPC ctxt
  let fall = pc .+ numU32 insLen 64<rt>
  !<ir insLen
  !!ir (AST.intercjmp (conditionHolds ctxt cond) (pc .+ label) fall)
  !>ir insLen

let bfm ins insLen ctxt addr dst src immr imms =
  let ir = !*ctxt
  let oSz = ins.OprSize
  let width = oprSzToExpr ins.OprSize
  let struct (wmask, tmask) = decodeBitMasks immr imms (int oSz)
  let dst = transOprToExpr ins ctxt addr dst
  let src = transOprToExpr ins ctxt addr src
  let immr = transOprToExpr ins ctxt addr immr
  !<ir insLen
  let struct (wMask, tMask) = tmpVars2 ir oSz
  let bot = !+ir ins.OprSize
  !!ir (wMask := numI64 wmask oSz)
  !!ir (tMask := numI64 tmask oSz)
  !!ir (bot := (dst .& AST.not wMask) .| (rorForIR src immr width .& wMask))
  dstAssign ins.OprSize dst ((dst .& AST.not tMask) .| (bot .& tMask)) ir
  !>ir insLen

let bfi ins insLen ctxt addr =
  let struct (dst, src, lsb, width) = getFourOprs ins
  let immr =
    ((getImmValue lsb * -1L) &&& 0x3F) % (int64 ins.OprSize) |> OprImm
  let imms = getImmValue width - 1L |> OprImm
  bfm ins insLen ctxt addr dst src immr imms

let bfxil ins insLen ctxt addr =
  let struct (dst, src, lsb, width) = getFourOprs ins
  let imms = (getImmValue lsb) + (getImmValue width) - 1L |> OprImm
  bfm ins insLen ctxt addr dst src lsb imms

let bic ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  match ins.Operands with
  | ThreeOperands (OprSIMD (SIMDVecReg _), OprSIMD (SIMDVecReg _), _) ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let dstB, dstA = transOprToExpr128 ins ctxt addr dst
    let src1 = transSIMDOprToExpr ctxt eSize dataSize elements src1
    let src2 = transSIMDOprToExpr ctxt eSize dataSize elements src2
    let result = Array.map2 (fun s1 s2 -> s1 .& AST.not s2) src1 src2
    dstAssignForSIMD dstA dstB result dataSize elements ir
  | ThreeOperands (OprSIMD (SIMDVecReg _), OprImm _, OprShift _)  ->
    let struct (dst, src, amount) = getThreeOprs ins
    let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
    let dstB, dstA = transOprToExpr128 ins ctxt addr dst
    let imm =
      transBarrelShiftToExpr ins.OprSize ctxt src amount
      |> advSIMDExpandImm ir eSize |> AST.not
    dstAssign128 ins ctxt addr dst (dstA .& imm) (dstB .& imm) dataSize ir
  | _ ->
    let dst, src1, src2 = transFourOprsWithBarrelShift ins ctxt addr
    dstAssign ins.OprSize dst (src1 .& AST.not src2) ir
  !>ir insLen

let bics ins insLen ctxt addr =
  let dst, src1, src2 = transFourOprsWithBarrelShift ins ctxt addr
  let ir = !*ctxt
  let result = !+ir ins.OprSize
  !<ir insLen
  !!ir (result := src1 .& AST.not src2)
  !!ir (getRegVar ctxt R.N := AST.xthi 1<rt> result)
  !!ir (getRegVar ctxt R.Z := result == AST.num0 ins.OprSize)
  !!ir (getRegVar ctxt R.C := AST.b0)
  !!ir (getRegVar ctxt R.V := AST.b0)
  dstAssign ins.OprSize dst result ir
  !>ir insLen

let private bitInsert ins insLen ctxt addr isTrue =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2) = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ins ctxt addr dst
  let src1B, src1A = transOprToExpr128 ins ctxt addr src1
  let src2B, src2A = transOprToExpr128 ins ctxt addr src2
  let struct (opr1A, opr3A, opr4A) = tmpVars3 ir 64<rt>
  let struct (opr1B, opr3B, opr4B) = tmpVars3 ir 64<rt>
  !!ir (opr1A := dstA)
  !!ir (opr1B := dstB)
  !!ir (opr3A := if isTrue then src2A else AST.not src2A)
  !!ir (opr3B := if isTrue then src2B else AST.not src2B)
  !!ir (opr4A := src1A)
  !!ir (opr4B := src1B)
  !!ir (dstA := AST.xor opr1A ((AST.xor opr1A opr4A) .& opr3A))
  if ins.OprSize = 128<rt> then
    !!ir (dstB := AST.xor opr1B ((AST.xor opr1B opr4B) .& opr3B))
  else !!ir (dstB := AST.num0 64<rt>)
  !>ir insLen

let bif ins insLen ctxt addr = bitInsert ins insLen ctxt addr false
let bit ins insLen ctxt addr = bitInsert ins insLen ctxt addr true

let bl ins insLen ctxt addr =
  let ir = !*ctxt
  let label = transOneOpr ins ctxt addr
  let pc = getPC ctxt
  !<ir insLen
  !!ir (getRegVar ctxt R.X30 := pc .+ numI64 4L ins.OprSize)
  (* FIXME: BranchTo (BranchType_DIRCALL) *)
  !!ir (AST.interjmp (pc .+ label) InterJmpKind.IsCall)
  !>ir insLen

let blr ins insLen ctxt addr =
  let ir = !*ctxt
  let src = transOneOpr ins ctxt addr
  let pc = getPC ctxt
  !<ir insLen
  !!ir (getRegVar ctxt R.X30 := pc .+ numI64 4L ins.OprSize)
  (* FIXME: BranchTo (BranchType_INDCALL) *)
  !!ir (AST.interjmp src InterJmpKind.IsCall)
  !>ir insLen

let br ins insLen ctxt addr =
  let ir = !*ctxt
  let dst = transOneOpr ins ctxt addr
  !<ir insLen
  (* FIXME: BranchTo (BranchType_INDIR) *)
  !!ir (AST.interjmp dst InterJmpKind.Base)
  !>ir insLen

let bsl ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2) = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ins ctxt addr dst
  let src1B, src1A = transOprToExpr128 ins ctxt addr src1
  let src2B, src2A = transOprToExpr128 ins ctxt addr src2
  let struct (opr1A, opr3A, opr4A) = tmpVars3 ir 64<rt>
  let struct (opr1B, opr3B, opr4B) = tmpVars3 ir 64<rt>
  !!ir (opr1A := src2A)
  !!ir (opr1B := src2B)
  !!ir (opr3A := dstA)
  !!ir (opr3B := dstB)
  !!ir (opr4A := src1A)
  !!ir (opr4B := src1B)
  !!ir (dstA := AST.xor opr1A ((AST.xor opr1A opr4A) .& opr3A))
  if ins.OprSize = 128<rt> then
    !!ir (dstB := AST.xor opr1B ((AST.xor opr1B opr4B) .& opr3B))
  else !!ir (dstB := AST.num0 64<rt>)
  !>ir insLen

let inline private compareBranch ins insLen ctxt addr cmp =
  let ir = !*ctxt
  let test, label = transTwoOprs ins ctxt addr
  let pc = getPC ctxt
  let fall = pc .+ numU32 insLen 64<rt>
  !<ir insLen
  !!ir (AST.intercjmp (cmp test (AST.num0 ins.OprSize)) (pc .+ label) fall)
  !>ir insLen

let compareAndSwap ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src, mem = transThreeOprs ins ctxt addr
  let struct (compareVal, newVal, oldVal) = tmpVars3 ir ins.OprSize
  let memVal = !+ir 64<rt>
  let cond = oldVal == compareVal
  !<ir insLen
  !!ir (compareVal := dst)
  !!ir (newVal := src)
  !!ir (memVal := mem)
  !!ir (oldVal := memVal |> AST.xtlo ins.OprSize)
  !!ir (mem := AST.ite cond (newVal |> AST.sext 64<rt>) memVal)
  !!ir (dst := oldVal |> AST.zext ins.OprSize)
  !>ir insLen

let cbnz ins insLen ctxt addr = compareBranch ins insLen ctxt addr (!=)

let cbz ins insLen ctxt addr = compareBranch ins insLen ctxt addr (==)

let ccmn ins insLen ctxt addr =
  let ir = !*ctxt
  let src, imm, nzcv, cond = transOprToExprOfCCMN ins ctxt addr
  !<ir insLen
  let oSz = ins.OprSize
  let tCond = !+ir 1<rt>
  !!ir (tCond := conditionHolds ctxt cond)
  let _, (n, z, c, v) = addWithCarry src imm (AST.num0 oSz) oSz
  !!ir (getRegVar ctxt R.N := (AST.ite tCond n (AST.extract nzcv 1<rt> 3)))
  !!ir (getRegVar ctxt R.Z := (AST.ite tCond z (AST.extract nzcv 1<rt> 2)))
  !!ir (getRegVar ctxt R.C := (AST.ite tCond c (AST.extract nzcv 1<rt> 1)))
  !!ir (getRegVar ctxt R.V := (AST.ite tCond v (AST.xtlo 1<rt> nzcv)))
  !>ir insLen

let ccmp ins insLen ctxt addr =
  let ir = !*ctxt
  let src, imm, nzcv, cond = transOprToExprOfCCMP ins ctxt addr
  let oSz = ins.OprSize
  !<ir insLen
  let tCond = !+ir 1<rt>
  !!ir (tCond := conditionHolds ctxt cond)
  let _, (n, z, c, v) = addWithCarry src (AST.not imm) (AST.num1 oSz) oSz
  !!ir (getRegVar ctxt R.N := (AST.ite tCond n (AST.extract nzcv 1<rt> 3)))
  !!ir (getRegVar ctxt R.Z := (AST.ite tCond z (AST.extract nzcv 1<rt> 2)))
  !!ir (getRegVar ctxt R.C := (AST.ite tCond c (AST.extract nzcv 1<rt> 1)))
  !!ir (getRegVar ctxt R.V := (AST.ite tCond v (AST.xtlo 1<rt> nzcv)))
  !>ir insLen

let clz ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src = transTwoOprs ins ctxt addr
  !<ir insLen
  let res = countLeadingZeroBitsForIR src ins.OprSize ir
  !!ir (dst := oprSzToExpr ins.OprSize .- (res .+ AST.num1 ins.OprSize))
  !>ir insLen

let cmn ins insLen ctxt addr =
  let ir = !*ctxt
  let src1, src2 = transThreeOprsWithBarrelShift ins ctxt addr
  let oSz = ins.OprSize
  !<ir insLen
  let _, (n, z, c, v) = addWithCarry src1 src2 (AST.num0 oSz) oSz
  !!ir (getRegVar ctxt R.N := n)
  !!ir (getRegVar ctxt R.Z := z)
  !!ir (getRegVar ctxt R.C := c)
  !!ir (getRegVar ctxt R.V := v)
  !>ir insLen

let cmp ins insLen ctxt addr =
  let ir = !*ctxt
  let src1, src2 = transOprToExprOfCMP ins ctxt addr
  let oSz = ins.OprSize
  !<ir insLen
  let _, (n, z, c, v) = addWithCarry src1 (AST.not src2) (AST.num1 oSz) oSz
  !!ir (getRegVar ctxt R.N := n)
  !!ir (getRegVar ctxt R.Z := z)
  !!ir (getRegVar ctxt R.C := c)
  !!ir (getRegVar ctxt R.V := v)
  !>ir insLen

let private compare ins insLen ctxt addr cond =
  let ir = !*ctxt
  !<ir insLen
  match ins.Operands with
  (* zero *)
  | ThreeOperands (OprSIMD (SIMDVecReg _) as o1, o2, OprImm _) ->
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let dstB, dstA = transOprToExpr128 ins ctxt addr o1
    let src1 = transSIMDOprToExpr ctxt eSize dataSize elements o2
    let struct (ones, zeros) = tmpVars2 ir eSize
    !!ir (ones := numI64 -1L eSize)
    !!ir (zeros := AST.num0 eSize)
    let result = Array.map (fun e -> AST.ite (cond e zeros) ones zeros) src1
    dstAssignForSIMD dstA dstB result dataSize elements ir
  | ThreeOperands (OprSIMD (SIMDFPScalarReg _) as o1, o2, OprImm _) ->
    let struct (eSize, _, _) = getElemDataSzAndElems o1
    let src1 = transOprToExpr ins ctxt addr o2
    let num0 = AST.num0 64<rt>
    let result = !+ir 64<rt>
    !!ir (result := AST.ite (cond src1 num0) (numI64 -1L 64<rt>) num0)
    dstAssignScalar ins ctxt addr o1 result eSize ir
  (* register *)
  | ThreeOperands (OprSIMD (SIMDVecReg _) as o1, o2, o3) ->
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let dstB, dstA = transOprToExpr128 ins ctxt addr o1
    let src1 = transSIMDOprToExpr ctxt eSize dataSize elements o2
    let src2 = transSIMDOprToExpr ctxt eSize dataSize elements o3
    let struct (ones, zeros) = tmpVars2 ir eSize
    !!ir (ones := numI64 -1L eSize)
    !!ir (zeros := AST.num0 eSize)
    let result =
      Array.map2 (fun e1 e2 -> AST.ite (cond e1 e2) ones zeros) src1 src2
    dstAssignForSIMD dstA dstB result dataSize elements ir
  | ThreeOperands (OprSIMD (SIMDFPScalarReg _) as o1, o2, o3) ->
    let struct (eSize, _, _) = getElemDataSzAndElems o1
    let src1 = transOprToExpr ins ctxt addr o2
    let src2 = transOprToExpr ins ctxt addr o3
    let num0 = AST.num0 64<rt>
    let result = !+ir 64<rt>
    !!ir (result := AST.ite (cond src1 src2) (numI64 -1L 64<rt>) num0)
    dstAssignScalar ins ctxt addr o1 result eSize ir
  | _ -> raise InvalidOperandException
  !>ir insLen

let cmeq ins insLen ctxt addr = compare ins insLen ctxt addr (==)
let cmgt ins insLen ctxt addr = compare ins insLen ctxt addr (.>)
let cmge ins insLen ctxt addr = compare ins insLen ctxt addr (.>=)

let private cmpHigher ins insLen ctxt addr cond =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  let struct (ones, zeros) = tmpVars2 ir eSize
  !!ir (ones := numI64 -1 eSize)
  !!ir (zeros := AST.num0 eSize)
  match dst with
  | OprSIMD (SIMDFPScalarReg _) ->
    let _, src1, src2 = transThreeOprs ins ctxt addr
    let result = AST.ite (src1 .> src2) ones zeros
    dstAssignScalar ins ctxt addr dst result eSize ir
  | _ ->
    let dstB, dstA = transOprToExpr128 ins ctxt addr dst
    let src1 = transSIMDOprToExpr ctxt eSize dataSize elements src1
    let src2 = transSIMDOprToExpr ctxt eSize dataSize elements src2
    let result =
      Array.map2 (fun e1 e2 -> AST.ite (cond e1 e2) ones zeros) src1 src2
    dstAssignForSIMD dstA dstB result dataSize elements ir
  !>ir insLen

let cmhi ins insLen ctxt addr = cmpHigher ins insLen ctxt addr (.>)
let cmhs ins insLen ctxt addr = cmpHigher ins insLen ctxt addr (.>=)

let cmlt ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, _) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  let struct (ones, zeros) = tmpVars2 ir eSize
  !!ir (ones := numI64 -1 eSize)
  !!ir (zeros := AST.num0 eSize)
  match dst with
  | OprSIMD (SIMDFPScalarReg _) ->
    let src1 = transOprToExpr ins ctxt addr src1
    let result = AST.ite (src1 .> zeros) ones zeros
    dstAssignScalar ins ctxt addr dst result eSize ir
  | _ ->
    let dstB, dstA = transOprToExpr128 ins ctxt addr dst
    let src1 = transSIMDOprToExpr ctxt eSize dataSize elements src1
    let result = Array.map (fun e -> AST.ite (e .< zeros) ones zeros) src1
    dstAssignForSIMD dstA dstB result dataSize elements ir
  !>ir insLen

let cmtst ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  let struct (ones, zeros) = tmpVars2 ir eSize
  !!ir (ones := numI64 -1 eSize)
  !!ir (zeros := AST.num0 eSize)
  match dst with
  | OprSIMD (SIMDFPScalarReg _) ->
    let _, src1, src2 = transThreeOprs ins ctxt addr
    let result = AST.ite ((src1 .& src2) != zeros) ones zeros
    dstAssignScalar ins ctxt addr dst result eSize ir
  | _ ->
    let dstB, dstA = transOprToExpr128 ins ctxt addr dst
    let s1 = transSIMDOprToExpr ctxt eSize dataSize elements src1
    let s2 = transSIMDOprToExpr ctxt eSize dataSize elements src2
    let result =
      Array.map2 (fun e1 e2 -> AST.ite ((e1 .& e2) != zeros) ones zeros) s1 s2
    dstAssignForSIMD dstA dstB result dataSize elements ir
  !>ir insLen

let cnt ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  let dstB, dstA = transOprToExpr128 ins ctxt addr dst
  let src = transSIMDOprToExpr ctxt eSize dataSize elements src
  let result = Array.map (bitCount eSize) src
  dstAssignForSIMD dstA dstB result dataSize elements ir
  !>ir insLen

let csel ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, s1, s2, cond = transOprToExprOfCSEL ins ctxt addr
  !<ir insLen
  dstAssign ins.OprSize dst (AST.ite (conditionHolds ctxt cond) s1 s2) ir
  !>ir insLen

let csinc ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, s1, s2, cond = transOprToExprOfCSINC ins ctxt addr
  !<ir insLen
  let oprSize = ins.OprSize
  let cond = conditionHolds ctxt cond
  dstAssign oprSize dst (AST.ite cond s1 (s2 .+ AST.num1 oprSize)) ir
  !>ir insLen

let csinv ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2, cond = transOprToExprOfCSINV ins ctxt addr
  !<ir insLen
  let cond = conditionHolds ctxt cond
  dstAssign ins.OprSize dst (AST.ite cond src1 (AST.not src2)) ir
  !>ir insLen

let csneg ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, s1, s2, cond = transOprToExprOfCSNEG ins ctxt addr
  !<ir insLen
  let s2 = AST.not s2 .+ AST.num1 ins.OprSize
  dstAssign ins.OprSize dst (AST.ite (conditionHolds ctxt cond) s1 s2) ir
  !>ir insLen

let dczva ins insLen ctxt addr =
  let ir = !*ctxt
  let src = transOneOpr ins ctxt addr
  let dczid = getRegVar ctxt R.DCZIDEL0
  let struct (idx, n4, len) = tmpVars3 ir 64<rt>
  let lblLoop = !%ir "Loop"
  let lblLoopCont = !%ir "LoopContinue"
  let lblEnd = !%ir "End"
  !<ir insLen
  !!ir (idx := AST.num0 64<rt>)
  !!ir (n4 := numI32 4 64<rt>)
  !!ir (len := (numI32 2 64<rt> << (dczid .+ numI32 1 64<rt>)))
  !!ir (len := len ./ n4)
  !!ir (AST.lmark lblLoop)
  !!ir (AST.cjmp (idx == len) (AST.name lblEnd) (AST.name lblLoopCont))
  !!ir (AST.lmark lblLoopCont)
  !!ir (AST.loadLE 32<rt> (src .+ (idx .* n4)) := AST.num0 32<rt>)
  !!ir (idx := idx .+ AST.num1 64<rt>)
  !!ir (AST.jmp (AST.name lblLoop))
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let dup ins insLen ctxt addr =
  let ir = !*ctxt
  let struct (dst, src) = getTwoOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  let dstB, dstA = transOprToExpr128 ins ctxt addr dst
  let src = transOprToExpr ins ctxt addr src
  let element = !+ir eSize
  let result = Array.init elements (fun _ -> !+ir eSize)
  !<ir insLen
  !!ir (element := AST.xtlo eSize src)
  Array.iter (fun e -> !!ir (e := element)) result
  dstAssignForSIMD dstA dstB result dataSize elements ir
  !>ir insLen

let eor ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  match ins.Operands with
  | ThreeOperands (OprSIMD (SIMDVecReg _) as o1, o2, o3) ->
    let dstB, dstA = transOprToExpr128 ins ctxt addr o1
    let src1B, src1A = transOprToExpr128 ins ctxt addr o2
    let src2B, src2A = transOprToExpr128 ins ctxt addr o3
    let struct (opr2, opr3) = tmpVars2 ir 64<rt>
    !!ir (opr2 := AST.num0 64<rt>)
    !!ir (opr3 := numI64 -1 64<rt>)
    !!ir (dstA := src2A <+> ((opr2 <+> src1A) .& opr3))
    if ins.OprSize = 64<rt> then ()
    else !!ir (dstB := src2B <+> ((opr2 <+> src1B) .& opr3))
  | _ ->
    let dst, src1, src2 = transOprToExprOfEOR ins ctxt addr
    dstAssign ins.OprSize dst (src1 <+> src2) ir
  !>ir insLen

let ext ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2, idx) = getFourOprs ins
  let pos = getImmValue idx |> int
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  let dstB, dstA = transOprToExpr128 ins ctxt addr dst
  let src1 = transSIMDOprToExpr ctxt eSize dataSize elements src1
  let src2 = transSIMDOprToExpr ctxt eSize dataSize elements src2
  let concat = Array.append src1 src2
  let result = Array.sub concat pos (dataSize / eSize)
  dstAssignForSIMD dstA dstB result dataSize elements ir
  !>ir insLen

let extr ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2, lsb = transOprToExprOfEXTR ins ctxt addr
  let oSz = ins.OprSize
  !<ir insLen
  if oSz = 32<rt> then
    let con = !+ir 64<rt>
    !!ir (con := AST.concat src1 src2)
    let mask = numI32 0xFFFFFFFF 64<rt>
    dstAssign ins.OprSize dst ((con >> (AST.zext 64<rt> lsb)) .& mask) ir
  elif oSz = 64<rt> then
    let lsb =
      match ins.Operands with
      | ThreeOperands (_, _, OprLSB shift) -> int32 shift
      | FourOperands (_, _, _, OprLSB lsb) -> int32 lsb
      | _ -> raise InvalidOperandException
    if lsb = 0 then !!ir (dst := src2)
    else
      let leftAmt = numI32 (64 - lsb) 64<rt>
      !!ir (dst := (src1 << leftAmt) .| (src2 >> (numI32 lsb 64<rt>)))
  else raise InvalidOperandSizeException
  !>ir insLen

let fabd ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  let n1 = !+ir eSize
  !!ir (n1 := AST.num1 eSize)
  let fpAbsDiff e1 e2 = ((AST.fsub e1 e2) << n1) >> n1
  match dst with
  | OprSIMD (SIMDFPScalarReg _) ->
    let _, src1, src2 = transThreeOprs ins ctxt addr
    dstAssignScalar ins ctxt addr dst (fpAbsDiff src1 src2) eSize ir
  | OprSIMD (SIMDVecReg _) ->
    let dstB, dstA = transOprToExpr128 ins ctxt addr dst
    let src1 = transSIMDOprToExpr ctxt eSize dataSize elements src1
    let src2 = transSIMDOprToExpr ctxt eSize dataSize elements src2
    let result = Array.map2 (fpAbsDiff) src1 src2
    dstAssignForSIMD dstA dstB result dataSize elements ir
  | _ -> raise InvalidOperandException
  !>ir insLen

let fabs ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  let n1 = !+ir eSize
  !!ir (n1 := AST.num1 eSize)
  match dst with
  | OprSIMD (SIMDFPScalarReg _) ->
    let src = transOprToExpr ins ctxt addr src
    dstAssignScalar ins ctxt addr dst ((src << n1) >> n1) eSize ir
  | OprSIMD (SIMDVecReg _) ->
    let dstB, dstA = transOprToExpr128 ins ctxt addr dst
    let src = transSIMDOprToExpr ctxt eSize dataSize elements src
    let result = Array.map (fun e -> (e << n1) >> n1) src
    dstAssignForSIMD dstA dstB result dataSize elements ir
  | _ -> raise InvalidOperandException
  !>ir insLen

let fadd ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  match dst with
  | OprSIMD (SIMDFPScalarReg _) ->
    let _, src1, src2 = transThreeOprs ins ctxt addr
    dstAssignScalar ins ctxt addr dst (AST.fadd src1 src2) eSize ir
  | OprSIMD (SIMDVecReg _) ->
    let dstB, dstA = transOprToExpr128 ins ctxt addr dst
    let src1 = transSIMDOprToExpr ctxt eSize dataSize elements src1
    let src2 = transSIMDOprToExpr ctxt eSize dataSize elements src2
    let result = Array.map2 (AST.fadd) src1 src2
    dstAssignForSIMD dstA dstB result dataSize elements ir
  | _ -> raise InvalidOperandException
  !>ir insLen

let faddp ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  match ins.Operands with
  | TwoOperands (dst, src) -> (* Scalar *)
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
    let src = transSIMDOprToExpr ctxt eSize dataSize elements src
    let result = Array.reduce (AST.fadd) src
    dstAssignScalar ins ctxt addr dst result eSize ir
  | ThreeOperands (dst, src1, src2) -> (* Vector *)
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let dstB, dstA = transOprToExpr128 ins ctxt addr dst
    let src1 = transSIMDOprToExpr ctxt eSize dataSize elements src1
    let src2 = transSIMDOprToExpr ctxt eSize dataSize elements src2
    let concat = Array.append src1 src2
    let result =
      Array.chunkBySize 2 concat |> Array.map (fun e -> AST.fadd e[0] e[1])
    dstAssignForSIMD dstA dstB result dataSize elements ir
  | _ -> raise InvalidOperandException
  !>ir insLen

let private fpCompare v1 v2 =
  AST.ite (AST.eq v1 v2) (numI32 0b0110 8<rt>)
    (AST.ite (AST.flt v1 v2) (numI32 0b1000 8<rt>) (numI32 0b0010 8<rt>))

let private getFlag flags pos = AST.extract flags 1<rt> pos

let fccmp ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let src1, src2, nzcv, cond = transOprToExprOfCCMP ins ctxt addr
  let tCond = !+ir 1<rt>
  let flags = !+ir 8<rt>
  !!ir (tCond := conditionHolds ctxt cond)
  !!ir (flags := fpCompare src1 src2)
  !!ir (getRegVar ctxt R.N := AST.ite tCond (getFlag flags 3) (getFlag nzcv 3))
  !!ir (getRegVar ctxt R.Z := AST.ite tCond (getFlag flags 2) (getFlag nzcv 2))
  !!ir (getRegVar ctxt R.C := AST.ite tCond (getFlag flags 1) (getFlag nzcv 1))
  !!ir (getRegVar ctxt R.V := AST.ite tCond (getFlag flags 0) (getFlag nzcv 0))
  !>ir insLen

let fccmpe ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let src1, src2, nzcv, cond = transOprToExprOfCCMP ins ctxt addr
  let tCond = !+ir 1<rt>
  let flags = !+ir 8<rt>
  !!ir (tCond := conditionHolds ctxt cond)
  !!ir (flags := fpCompare src1 src2) (* FIXME: signal_nans *)
  !!ir (getRegVar ctxt R.N := AST.ite tCond (getFlag flags 3) (getFlag nzcv 3))
  !!ir (getRegVar ctxt R.Z := AST.ite tCond (getFlag flags 2) (getFlag nzcv 2))
  !!ir (getRegVar ctxt R.C := AST.ite tCond (getFlag flags 1) (getFlag nzcv 1))
  !!ir (getRegVar ctxt R.V := AST.ite tCond (getFlag flags 0) (getFlag nzcv 0))
  !>ir insLen

let fcmgt ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  let struct (ones, zeros) = tmpVars2 ir eSize
  !!ir (ones := numI64 -1 eSize)
  !!ir (zeros := AST.num0 eSize)
  match dst, src2 with
  | OprSIMD (SIMDFPScalarReg _) as o1, _ ->
    let _, src1, src2 = transThreeOprs ins ctxt addr
    let result = AST.ite (AST.fgt src1 src2) ones zeros
    dstAssignScalar ins ctxt addr o1 result eSize ir
  | OprSIMD (SIMDVecReg _), OprFPImm _ ->
    let dstB, dstA = transOprToExpr128 ins ctxt addr dst
    let src1 = transSIMDOprToExpr ctxt eSize dataSize elements src1
    let src2 = transOprToExpr ins ctxt addr src2 |> AST.xtlo eSize
    let result =
      Array.map (fun e -> AST.ite (AST.fgt e src2) ones zeros) src1
    dstAssignForSIMD dstA dstB result dataSize elements ir
  | OprSIMD (SIMDVecReg _), _ ->
    let dstB, dstA = transOprToExpr128 ins ctxt addr dst
    let src1 = transSIMDOprToExpr ctxt eSize dataSize elements src1
    let src2 = transSIMDOprToExpr ctxt eSize dataSize elements src2
    let result =
      Array.map2 (fun e1 e2 -> AST.ite (AST.fgt e1 e2) ones zeros) src1 src2
    dstAssignForSIMD dstA dstB result dataSize elements ir
  | _ -> raise InvalidOperandException
  !>ir insLen

let fcmp ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let src1, src2 = transTwoOprs ins ctxt addr
  let nzcv = !+ir 8<rt>
  !!ir (nzcv := fpCompare src1 src2)
  !!ir (getRegVar ctxt R.N := AST.extract nzcv 1<rt> 3)
  !!ir (getRegVar ctxt R.Z := AST.extract nzcv 1<rt> 2)
  !!ir (getRegVar ctxt R.C := AST.extract nzcv 1<rt> 1)
  !!ir (getRegVar ctxt R.V := AST.extract nzcv 1<rt> 0)
  !>ir insLen

let getExponent oprSize src =
  match oprSize with
  | 64<rt> ->
    let numMantissa =  numI32 52 64<rt>
    let mask = numI32 0x7FF 64<rt>
    AST.xtlo 32<rt> ((src >> numMantissa) .& mask)
  | _ ->
    let numMantissa = numI32 23 32<rt>
    let mask = numI32 0xff 32<rt>
    (src >> numMantissa) .& mask

let getMantissa oprSize src =
  let mask =
    if oprSize = 64<rt> then numU64 0xffffffffffffUL 64<rt>
    else numU64 0x7fffffUL 32<rt>
  src .& mask

let isNan oprSize expr = (* FIXME *)
  let exponent = getExponent oprSize expr
  let mantissa = getMantissa oprSize expr
  let e = if oprSize = 64<rt> then numI32 0x7ff 32<rt> else numI32 0xff 32<rt>
  let zero = if oprSize = 64<rt> then AST.num0 64<rt> else AST.num0 32<rt>
  (exponent == e) .& (mantissa != zero)

let fcmpe ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let src1, src2 = transTwoOprs ins ctxt addr
  let nzcv = !+ir 8<rt>
  let condNan = !+ir 1<rt>
  let isNanOp1OrOp2 = isNan ins.OprSize src1 .| isNan ins.OprSize src2
  !!ir (condNan := isNanOp1OrOp2)
  !!ir (nzcv := fpCompare src1 src2)
  !!ir (getRegVar ctxt R.N := AST.ite condNan AST.b0 (getFlag nzcv 3))
  !!ir (getRegVar ctxt R.Z := AST.ite condNan AST.b0 (getFlag nzcv 2))
  !!ir (getRegVar ctxt R.C := AST.ite condNan AST.b1 (getFlag nzcv 1))
  !!ir (getRegVar ctxt R.V := AST.ite condNan AST.b1 (getFlag nzcv 0))
  !>ir insLen

let fcsel ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, s1, s2, cond = transOprToExprOfCSEL ins ctxt addr
  let fs1 = AST.cast CastKind.FloatCast ins.OprSize s1
  let fs2 = AST.cast CastKind.FloatCast ins.OprSize s2
  !<ir insLen
  dstAssign ins.OprSize dst (AST.ite (conditionHolds ctxt cond) fs1 fs2) ir
  !>ir insLen

let fcvt ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let dst, src = transTwoOprs ins ctxt addr
  let oprSize = ins.OprSize
  dstAssign oprSize dst (AST.cast CastKind.FloatCast oprSize src) ir
  !>ir insLen

let private fpConvert ins insLen ctxt addr isUnsigned round =
  let ir = !*ctxt
  !<ir insLen
  match ins.Operands with
  (* vector *)
  | TwoOperands (OprSIMD (SIMDVecReg _) as o1, o2) ->
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let dstB, dstA = transOprToExpr128 ins ctxt addr o1
    let src = transSIMDOprToExpr ctxt eSize dataSize elements o2
    let n0 = AST.num0 eSize
    let result =
      Array.map (fun e -> fpToFixed eSize e n0 isUnsigned round) src
    dstAssignForSIMD dstA dstB result dataSize elements ir
  (* vector #<fbits> *)
  | ThreeOperands (OprSIMD (SIMDVecReg _) as o1, o2, OprFbits fbits) ->
    let struct (eSz, dataSize, elements) = getElemDataSzAndElems o1
    let dstB, dstA = transOprToExpr128 ins ctxt addr o1
    let src = transSIMDOprToExpr ctxt eSz dataSize elements o2
    let fbits = numI32 (int fbits) eSz
    let result =
      Array.map (fun e -> fpToFixed eSz e fbits isUnsigned FPRounding_Zero) src
    dstAssignForSIMD dstA dstB result dataSize elements ir
  (* scalar *)
  | TwoOperands (OprSIMD (SIMDFPScalarReg _) as o1, o2) ->
    let src = transOprToExpr ins ctxt addr o2
    let result =
      fpToFixed ins.OprSize src (AST.num0 ins.OprSize) isUnsigned round
    dstAssignScalar ins ctxt addr o1 result ins.OprSize ir
  (* scalar #<fbits> *)
  | ThreeOperands (OprSIMD (SIMDFPScalarReg _) as o1, _, OprFbits _) ->
    let _, src, fbits = transThreeOprs ins ctxt addr
    let result = fpToFixed ins.OprSize src fbits isUnsigned FPRounding_Zero
    dstAssignScalar ins ctxt addr o1 result ins.OprSize ir
  (* float *)
  | TwoOperands (OprRegister _, _) ->
    let dst, src = transTwoOprs ins ctxt addr
    let result =
      fpToFixed ins.OprSize src (AST.num0 ins.OprSize) isUnsigned round
    dstAssign ins.OprSize dst result ir
  (* float #<fbits> *)
  | ThreeOperands (OprRegister _, _, OprFbits _) ->
    let dst, src, fbits = transThreeOprs ins ctxt addr
    let result = fpToFixed ins.OprSize src fbits isUnsigned FPRounding_Zero
    dstAssign ins.OprSize dst result ir
  | _ -> raise InvalidOperandException
  !>ir insLen

let fcvtas ins insLen ctxt addr =
  fpConvert ins insLen ctxt addr false FPRounding_TIEAWAY
let fcvtau ins insLen ctxt addr =
  fpConvert ins insLen ctxt addr true FPRounding_TIEAWAY

let fcvtms ins insLen ctxt addr =
  fpConvert ins insLen ctxt addr false FPRounding_POSINF
let fcvtmu ins insLen ctxt addr =
  fpConvert ins insLen ctxt addr true FPRounding_POSINF

let fcvtps ins insLen ctxt addr =
  fpConvert ins insLen ctxt addr false FPRounding_TIEEVEN
let fcvtpu ins insLen ctxt addr =
  fpConvert ins insLen ctxt addr true FPRounding_TIEEVEN

let fcvtzs ins insLen ctxt addr =
  fpConvert ins insLen ctxt addr false FPRounding_NEGINF
let fcvtzu ins insLen ctxt addr =
  fpConvert ins insLen ctxt addr true FPRounding_NEGINF

let fdiv ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  match dst with
  | OprSIMD (SIMDFPScalarReg _) ->
    let _, src1, src2 = transThreeOprs ins ctxt addr
    dstAssignScalar ins ctxt addr dst (AST.fdiv src1 src2) eSize ir
  | OprSIMD (SIMDVecReg _) ->
    let dstB, dstA = transOprToExpr128 ins ctxt addr dst
    let src1 = transSIMDOprToExpr ctxt eSize dataSize elements src1
    let src2 = transSIMDOprToExpr ctxt eSize dataSize elements src2
    let result = Array.map2 (AST.fdiv) src1 src2
    dstAssignForSIMD dstA dstB result dataSize elements ir
  | _ -> raise InvalidOperandException
  !>ir insLen

let fmadd ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, _, _, _) = getFourOprs ins
  let struct (eSize, _, _) = getElemDataSzAndElems dst
  let _, src1, src2, src3 = transFourOprs ins ctxt addr
  let result = (AST.fadd src3 (AST.fmul src1 src2))
  dstAssignScalar ins ctxt addr dst result eSize ir
  !>ir insLen

let fmov ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  match ins.Operands with
  | TwoOperands (OprRegister _, OprSIMD (SIMDVecRegWithIdx _)) ->
    let struct (dst, src) = getTwoOprs ins
    let dst = transOprToExpr ins ctxt addr dst
    let srcB, _ = transOprToExpr128 ins ctxt addr src
    dstAssign ins.OprSize dst srcB ir
  | TwoOperands (OprSIMD (SIMDVecRegWithIdx _), OprRegister _) ->
    let struct (dst, src) = getTwoOprs ins
    let dstB, dstA = transOprToExpr128 ins ctxt addr dst
    let src = transOprToExpr ins ctxt addr src
    !!ir (dstA := dstA)
    !!ir (dstB := src)
  | TwoOperands (OprSIMD (SIMDVecReg _), OprFPImm _) ->
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
    let src =
      if eSize <> 64<rt> then
        transOprToExprFPImm ins eSize src |> advSIMDExpandImm ir eSize
      else transOprToExprFPImm ins eSize src
    dstAssign128 ins ctxt addr dst src src dataSize ir
  | _ ->
    let dst, src = transTwoOprs ins ctxt addr
    dstAssign ins.OprSize dst src ir
  !>ir insLen

let fmsub ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, _, _, _) = getFourOprs ins
  let struct (eSize, _, _) = getElemDataSzAndElems dst
  let _, src1, src2, src3 = transFourOprs ins ctxt addr
  let result = AST.fsub src3 (AST.fmul src1 src2)
  dstAssignScalar ins ctxt addr dst result eSize ir
  !>ir insLen

let fmul ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let oprSize = ins.OprSize
  dstAssign oprSize dst (AST.fmul src1 src2) ir
  !>ir insLen

let fsub ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let oprSize = ins.OprSize
  dstAssign oprSize dst (AST.fsub src1 src2) ir
  !>ir insLen

let insv ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let struct (o1, o2) = getTwoOprs ins
  let struct (eSize, _, _) = getElemDataSzAndElems o1
  let dst = transOprToExpr ins ctxt addr o1
  let src = transOprToExpr ins ctxt addr o2
  !!ir (dst := AST.xtlo eSize src)
  !>ir insLen

let ld1 ins insLen ctxt addr =
  let ir = !*ctxt
  let isWBack, _ = getIsWBackAndIsPostIndex ins.Operands
  let struct (dst, src) = getTwoOprs ins
  let struct (eSize, _, elements) = getElemDataSzAndElems dst
  let dstArr = transSIMDListToExpr ctxt dst
  let bReg, mOffs = transOprToExpr ins ctxt addr src |> separateMemExpr
  let struct (address, offs, ebyte) = tmpVars3 ir 64<rt>
  !<ir insLen
  !!ir (ebyte := numI32 (eSize / 8<rt>) 64<rt>)
  !!ir (offs := AST.num0 64<rt>)
  !!ir (address := bReg)
  for r in 0 .. Array.length dstArr - 1 do
    for e in 0 .. elements - 1 do
      !!ir (dstArr[r][e] := AST.loadLE eSize (address .+ offs))
      !!ir (offs := offs .+ ebyte)
    done
  done
  if isWBack then
    if isRegOffset src then !!ir (offs := mOffs) else ()
    !!ir (bReg := address .+ offs)
  !>ir insLen

let ldar ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, (bReg, offset) = transTwoOprsSepMem ins ctxt addr
  let address = !+ir 64<rt>
  !<ir insLen
  !!ir (address := bReg .+ offset)
  mark ctxt address (memSizeToExpr ins.OprSize) ir
  dstAssign ins.OprSize dst (AST.loadLE ins.OprSize address) ir
  !>ir insLen

let ldarb ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, (bReg, offset) = transTwoOprsSepMem ins ctxt addr
  let address = !+ir 64<rt>
  !<ir insLen
  !!ir (address := bReg .+ offset)
  mark ctxt address (memSizeToExpr 8<rt>) ir
  dstAssign ins.OprSize dst (AST.loadLE 8<rt> address) ir
  !>ir insLen

let ldax ins insLen ctxt addr size =
  let ir = !*ctxt
  let dst, (bReg, offset) = transTwoOprsSepMem ins ctxt addr
  let address = !+ir 64<rt>
  !<ir insLen
  !!ir (address := bReg .+ offset)
  mark ctxt address (memSizeToExpr size) ir
  dstAssign ins.OprSize dst (AST.loadLE size address) ir
  !>ir insLen

let ldaxr ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, (bReg, offset) = transTwoOprsSepMem ins ctxt addr
  let address = !+ir 64<rt>
  !<ir insLen
  !!ir (address := bReg .+ offset)
  mark ctxt address (memSizeToExpr ins.OprSize) ir
  dstAssign ins.OprSize dst (AST.loadLE ins.OprSize address) ir
  !>ir insLen

let ldaxp ins insLen ctxt addr =
  let ir = !*ctxt
  let dst1, dst2, (bReg, offset) = transThreeOprsSepMem ins ctxt addr
  let address = !+ir 64<rt>
  !<ir insLen
  !!ir (address := bReg .+ offset)
  mark ctxt address (memSizeToExpr ins.OprSize) ir
  if ins.OprSize = 32<rt> then
    let src = AST.loadLE 64<rt> address
    dstAssign ins.OprSize dst1 (AST.xtlo 32<rt> src) ir
    dstAssign ins.OprSize dst2 (AST.xthi 32<rt> src) ir
  else
    !!ir (dst1 := (AST.loadLE 64<rt> address))
    !!ir (dst2 := (AST.loadLE 64<rt> (address .+ numI32 8 64<rt>)))
  !>ir insLen

let ldp ins insLen ctxt addr =
  let ir = !*ctxt
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = !+ir 64<rt>
  let dByte = numI32 (RegType.toByteWidth ins.OprSize) 64<rt>
  !<ir insLen
  match ins.OprSize with
  | 128<rt> ->
    let struct (src1, src2, src3) = getThreeOprs ins
    let src1B, src1A = transOprToExpr128 ins ctxt addr src1
    let src2B, src2A = transOprToExpr128 ins ctxt addr src2
    let bReg, offset = transOprToExpr ins ctxt addr src3 |> separateMemExpr
    let n8 = numI32 8 64<rt>
    !!ir (address := bReg)
    !!ir (address := if isPostIndex then address else address .+ offset)
    !!ir (src1A := AST.loadLE 64<rt> address)
    !!ir (src1B := AST.loadLE 64<rt> address .+ n8)
    !!ir (src2A := AST.loadLE 64<rt> (address .+ dByte))
    !!ir (src2B := AST.loadLE 64<rt> (address .+ dByte .+ n8))
    if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
    else if isWBack then !!ir (bReg := address) else ()
  | _ ->
    let src1, src2, (bReg, offset) = transThreeOprsSepMem ins ctxt addr
    let oprSize = ins.OprSize
    !!ir (address := bReg)
    !!ir (address := if isPostIndex then address else address .+ offset)
    dstAssign oprSize src1 (AST.loadLE oprSize address) ir
    dstAssign oprSize src2 (AST.loadLE oprSize (address .+ dByte)) ir
    if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
    else if isWBack then !!ir (bReg := address) else ()
  !>ir insLen

let ldpsw ins insLen ctxt addr =
  let ir = !*ctxt
  let src1, src2, (bReg, offset) = transThreeOprsSepMem ins ctxt addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = !+ir 64<rt>
  let data1 = !+ir 32<rt>
  let data2 = !+ir 32<rt>
  !<ir insLen
  !!ir (address := bReg)
  !!ir (address := if isPostIndex then address else address .+ offset)
  !!ir (data1 := AST.loadLE 32<rt> address)
  !!ir (data2 := AST.loadLE 32<rt> (address .+ numI32 4 64<rt>))
  !!ir (src1 := AST.sext 64<rt> data1)
  !!ir (src2 := AST.sext 64<rt> data2)
  if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
  else if isWBack then !!ir (bReg := address) else ()
  !>ir insLen

let ldr ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  match ins.Operands with
  | TwoOperands (o1, OprMemory (LiteralMode o2)) -> (* LDR (literal) *)
    let offset = transOprToExpr ins ctxt addr (OprMemory (LiteralMode o2))
    let address = !+ir 64<rt>
    match ins.OprSize with
    | 128<rt> ->
      let dstB, dstA = transOprToExpr128 ins ctxt addr o1
      !!ir (address := getPC ctxt .+ offset)
      !!ir (dstA := AST.loadLE 64<rt> address)
      !!ir (dstB := AST.loadLE 64<rt> (address .+ (numI32 8 64<rt>)))
    | _ ->
      let dst = transOprToExpr ins ctxt addr o1
      let data = !+ir ins.OprSize
      !!ir (address := getPC ctxt .+ offset)
      !!ir (data := AST.loadLE ins.OprSize address)
      match o1 with
      | OprSIMD (SIMDFPScalarReg _) ->
        dstAssignScalar ins ctxt addr o1 data ins.OprSize ir (* FIXME *)
      | _ -> dstAssign ins.OprSize dst data ir
  | TwoOperands (o1, o2) ->
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    let address = !+ir 64<rt>
    match ins.OprSize with
    | 128<rt> ->
      let dstB, dstA = transOprToExpr128 ins ctxt addr o1
      let bReg, offset = transOprToExpr ins ctxt addr o2 |> separateMemExpr
      !!ir (address := bReg)
      !!ir (address := if isPostIndex then address else address .+ offset)
      !!ir (dstA := AST.loadLE 64<rt> address)
      !!ir (dstB := AST.loadLE 64<rt> (address .+ (numI32 8 64<rt>)))
      if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
      else if isWBack then !!ir (bReg := address) else ()
    | _ ->
      let dst = transOprToExpr ins ctxt addr o1
      let bReg, offset = transOprToExpr ins ctxt addr o2 |> separateMemExpr
      let data = !+ir ins.OprSize
      !!ir (address := bReg)
      !!ir (address := if isPostIndex then address else address .+ offset)
      !!ir (data := AST.loadLE ins.OprSize address)
      match o1 with
      | OprSIMD (SIMDFPScalarReg _) ->
        dstAssignScalar ins ctxt addr o1 data ins.OprSize ir (* FIXME *)
      | _ -> dstAssign ins.OprSize dst data ir
      if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
      else if isWBack then !!ir (bReg := address) else ()
  | _ -> raise InvalidOperandException
  !>ir insLen

let ldrb ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, (bReg, offset) = transTwoOprsSepMem ins ctxt addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = !+ir 64<rt>
  let data = !+ir 8<rt>
  !<ir insLen
  !!ir (address := bReg)
  !!ir (address := if isPostIndex then address else address .+ offset)
  !!ir (data := AST.loadLE 8<rt> address)
  dstAssign ins.OprSize dst (AST.zext 32<rt> data) ir
  if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
  else if isWBack then !!ir (bReg := address) else ()
  !>ir insLen

let ldrh ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, (bReg, offset) = transTwoOprsSepMem ins ctxt addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = !+ir 64<rt>
  let data = !+ir 16<rt>
  !<ir insLen
  !!ir (address := bReg)
  !!ir (address := if isPostIndex then address else address .+ offset)
  !!ir (data := AST.loadLE 16<rt> address)
  dstAssign ins.OprSize dst (AST.zext 32<rt> data) ir
  if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
  else if isWBack then !!ir (bReg := address) else ()
  !>ir insLen

let ldrsb ins insLen ctxt addr =
  let dst, (bReg, offset) = transTwoOprsSepMem ins ctxt addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let ir = !*ctxt
  let address = !+ir 64<rt>
  let data = !+ir 8<rt>
  !<ir insLen
  !!ir (address := bReg)
  !!ir (address := if isPostIndex then address else address .+ offset)
  !!ir (data := AST.loadLE 8<rt> address)
  dstAssign ins.OprSize dst (AST.sext ins.OprSize data) ir
  if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
  else if isWBack then !!ir (bReg := address) else ()
  !>ir insLen

let ldrsh ins insLen ctxt addr =
  let dst, (bReg, offset) = transTwoOprsSepMem ins ctxt addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let ir = !*ctxt
  let address = !+ir 64<rt>
  let data = !+ir 16<rt>
  !<ir insLen
  !!ir (address := bReg)
  !!ir (address := if isPostIndex then address else address .+ offset)
  !!ir (data := AST.loadLE 16<rt> address)
  dstAssign ins.OprSize dst (AST.sext ins.OprSize data) ir
  if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
  else if isWBack then !!ir (bReg := address) else ()
  !>ir insLen

let ldrsw ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let address = !+ir 64<rt>
  let data = !+ir 32<rt>
  match ins.Operands with
  | TwoOperands (o1, OprMemory (LiteralMode o2)) ->
    let dst = transOprToExpr ins ctxt addr o1
    let offset = transOprToExpr ins ctxt addr (OprMemory (LiteralMode o2))
    !!ir (address := getPC ctxt .+ offset)
    !!ir (data := AST.loadLE 32<rt> address)
    !!ir (dst := AST.sext 64<rt> data)
  | TwoOperands (o1, o2) ->
    let dst = transOprToExpr ins ctxt addr o1
    let bReg, offset = transOprToExpr ins ctxt addr o2 |> separateMemExpr
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    !!ir (address := bReg)
    !!ir (address := address .+ offset)
    !!ir (data := AST.loadLE 32<rt> address)
    !!ir (dst := AST.sext 64<rt> data)
    if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
    else if isWBack then !!ir (bReg := address) else ()
  | _ -> raise InvalidOperandException
  !>ir insLen

let ldtr ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, (bReg, offset) = transTwoOprsSepMem ins ctxt addr
  let address = !+ir 64<rt>
  let data = !+ir ins.OprSize
  !<ir insLen
  !!ir (address := bReg .+ offset)
  !!ir (data := AST.loadLE ins.OprSize address)
  dstAssign ins.OprSize dst (AST.zext ins.OprSize data) ir
  !>ir insLen

let ldur ins insLen ctxt addr =
  let ir = !*ctxt
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = !+ir 64<rt>
  let data = !+ir ins.OprSize
  !<ir insLen
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src) = getTwoOprs ins
    let dstB, dstA = transOprToExpr128 ins ctxt addr dst
    let bReg, offset = transOprToExpr ins ctxt addr src |> separateMemExpr
    !!ir (address := bReg)
    !!ir (address := if isPostIndex then address else address .+ offset)
    !!ir (dstA := AST.loadLE 64<rt> address)
    !!ir (dstB := AST.loadLE 64<rt> (address .+ (numI32 8 64<rt>)))
    if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
    else if isWBack then !!ir (bReg := address) else ()
  | _ ->
    let dst, (bReg, offset) = transTwoOprsSepMem ins ctxt addr
    !!ir (address := bReg)
    !!ir (address := if isPostIndex then address else address .+ offset)
    !!ir (data := AST.loadLE ins.OprSize address)
    dstAssign ins.OprSize dst data ir
    if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
    else if isWBack then !!ir (bReg := address) else ()
  !>ir insLen

let ldurb ins insLen ctxt addr =
  let ir = !*ctxt
  let src, (bReg, offset) = transTwoOprsSepMem ins ctxt addr
  let address = !+ir 64<rt>
  let data = !+ir 8<rt>
  !<ir insLen
  !!ir (address := bReg)
  !!ir (address := address .+ offset)
  !!ir (data := AST.loadLE 8<rt> address)
  dstAssign ins.OprSize src (AST.zext 32<rt> data) ir
  !>ir insLen

let ldurh ins insLen ctxt addr =
  let ir = !*ctxt
  let src, (bReg, offset) = transTwoOprsSepMem ins ctxt addr
  let address = !+ir 64<rt>
  let data = !+ir 16<rt>
  !<ir insLen
  !!ir (address := bReg)
  !!ir (address := address .+ offset)
  !!ir (data := AST.loadLE 16<rt> address)
  dstAssign ins.OprSize src (AST.zext 32<rt> data) ir
  !>ir insLen

let ldursb ins insLen ctxt addr =
  let dst, (bReg, offset) = transTwoOprsSepMem ins ctxt addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let ir = !*ctxt
  let address = !+ir 64<rt>
  let data = !+ir 8<rt>
  !<ir insLen
  !!ir (address := bReg.+ offset)
  !!ir (data := AST.loadLE 8<rt> address)
  !!ir (dst := AST.sext ins.OprSize data)
  !>ir insLen

let ldursh ins insLen ctxt addr =
  let dst, (bReg, offset) = transTwoOprsSepMem ins ctxt addr
  let ir = !*ctxt
  let address = !+ir 64<rt>
  let data = !+ir 16<rt>
  !<ir insLen
  !!ir (address := bReg.+ offset)
  !!ir (data := AST.loadLE 16<rt> address)
  dstAssign ins.OprSize dst (AST.sext ins.OprSize data) ir
  !>ir insLen

let ldursw ins insLen ctxt addr =
  let dst, (bReg, offset) = transTwoOprsSepMem ins ctxt addr
  let ir = !*ctxt
  let address = !+ir 64<rt>
  let data = !+ir 32<rt>
  !<ir insLen
  !!ir (address := bReg)
  !!ir (address := address .+ offset)
  !!ir (data := AST.loadLE 32<rt> address)
  dstAssign ins.OprSize dst (AST.sext 64<rt> data) ir
  !>ir insLen

let logShift ins insLen ctxt addr shift =
  let ir = !*ctxt
  let dst, src, amt = transThreeOprs ins ctxt addr
  !<ir insLen
  dstAssign ins.OprSize dst (shift src amt) ir
  !>ir insLen

let lslv ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let oprSz = ins.OprSize
  let dataSize = numI32 (RegType.toBitWidth ins.OprSize) oprSz
  !<ir insLen
  let result = shiftReg src1 (src2 .% dataSize) oprSz SRTypeLSL
  dstAssign ins.OprSize dst result ir
  !>ir insLen

let lsrv ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let oprSz = ins.OprSize
  let dataSize = numI32 (RegType.toBitWidth oprSz) oprSz
  !<ir insLen
  let result = shiftReg src1 (src2 .% dataSize) oprSz SRTypeLSR
  dstAssign ins.OprSize dst result ir
  !>ir insLen

let madd ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  match ins.Operands with
  | ThreeOperands (OprSIMD _ as o1, o2, o3) ->
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let dstB, dstA = transOprToExpr128 ins ctxt addr o1
    let src1 = transSIMDOprToExpr ctxt eSize dataSize elements o2
    let src2 = transSIMDOprToExpr ctxt eSize dataSize elements o3
    let result = Array.map2 (.*) src1 src2
    dstAssignForSIMD dstA dstB  result dataSize elements ir
  | _ ->
    let dst, src1, src2, src3 = transOprToExprOfMADD ins ctxt addr
    dstAssign ins.OprSize dst (src3 .+ (src1 .* src2)) ir
  !>ir insLen

let mov ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  match ins.Operands with
  | TwoOperands (OprSIMD (SIMDVecReg _), OprSIMD (SIMDVecReg _)) ->
    let struct (dst, src) = getTwoOprs ins
    let struct (_, dataSize, _) = getElemDataSzAndElems dst
    let srcB, srcA = transOprToExpr128 ins ctxt addr src
    dstAssign128 ins ctxt addr dst srcA srcB dataSize ir
  | _ ->
    let dst, src = transTwoOprs ins ctxt addr
    dstAssign ins.OprSize dst src ir
  !>ir insLen

let movi ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  match ins.Operands with
  | TwoOperands (OprSIMD (SIMDFPScalarReg _), OprImm _) ->
    let dst, src = transTwoOprs ins ctxt addr
    dstAssign ins.OprSize dst src ir
  | TwoOperands (OprSIMD (SIMDVecReg _), OprImm _) ->
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
    let imm = if not (dataSize = 128<rt> && eSize = 64<rt>) then
                transOprToExpr ins ctxt addr src
                |> advSIMDExpandImm ir eSize
              else transOprToExpr ins ctxt addr src
    dstAssign128 ins ctxt addr dst imm imm dataSize ir
  | ThreeOperands (OprSIMD (SIMDVecReg _), OprImm _, OprShift _) ->
    let struct (dst, src, amount) = getThreeOprs ins
    let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
    let imm = transBarrelShiftToExpr ins.OprSize ctxt src amount
              |> advSIMDExpandImm ir eSize
    dstAssign128 ins ctxt addr dst imm imm dataSize ir
  | _ -> raise InvalidOperandException
  !>ir insLen

let private getWordMask ins shift =
  match shift with
  | OprShift (SRTypeLSL, Imm amt) ->
    numI64 (~~~ (0xFFFFL <<< (int amt))) ins.OprSize
  | _ -> raise InvalidOperandException

let movk ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, imm, shf) = getThreeOprs ins
  let dst = transOprToExpr ins ctxt addr dst
  let src = transBarrelShiftToExpr ins.OprSize ctxt imm shf
  let mask = getWordMask ins shf
  dstAssign ins.OprSize dst ((dst .& mask) .| src) ir
  !>ir insLen

let movn ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let dst, src = transThreeOprsWithBarrelShift ins ctxt addr
  dstAssign ins.OprSize dst (AST.not src) ir
  !>ir insLen

let movz ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let dst, src = transThreeOprsWithBarrelShift ins ctxt addr
  dstAssign ins.OprSize dst src ir
  !>ir insLen

let mrs ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src = transTwoOprs ins ctxt addr
  !<ir insLen
  !!ir (dst := src)
  !>ir insLen

let msr ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src = transTwoOprs ins ctxt addr
  !<ir insLen
  !!ir (dst := src)
  !>ir insLen

let msub ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2, src3 = transOprToExprOfMSUB ins ctxt addr
  !<ir insLen
  dstAssign ins.OprSize dst (src3 .- (src1 .* src2)) ir
  !>ir insLen

let mvni ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  match ins.Operands with
  | TwoOperands _ ->
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
    let imm = transOprToExpr ins ctxt addr src
              |> advSIMDExpandImm ir eSize
              |> AST.not
    dstAssign128 ins ctxt addr dst imm imm dataSize ir
  | _ ->
    let struct (dst, src, shf) = getThreeOprs ins
    let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
    let src = transBarrelShiftToExpr 64<rt> ctxt src shf
              |> advSIMDExpandImm ir eSize
              |> AST.not
    dstAssign128 ins ctxt addr dst src src dataSize ir
  !>ir insLen

let nop insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  !>ir insLen

let orn ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  match ins.Operands with
  | TwoOperands _ ->
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let dstB, dstA = transOprToExpr128 ins ctxt addr dst
    let src = transSIMDOprToExpr ctxt eSize dataSize elements src
    let result = Array.map AST.not src
    !<ir insLen
    dstAssignForSIMD dstA dstB result dataSize elements ir
  | ThreeOperands (OprSIMD (SIMDVecReg _ ) as o1, o2, o3) ->
    let struct (_, dataSize, _) = getElemDataSzAndElems o1
    let src1B, src1A = transOprToExpr128 ins ctxt addr o2
    let src2B, src2A = transOprToExpr128 ins ctxt addr o3
    let resultB = src1B .| (AST.not src2B)
    let resultA = src1A .| (AST.not src2A)
    dstAssign128 ins ctxt addr o1 resultA resultB dataSize ir
  | _ ->
    let dst, src1, src2 = transOprToExprOfORN ins ctxt addr
    dstAssign ins.OprSize dst (src1 .| AST.not src2) ir
  !>ir insLen

let orr ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  match ins.Operands with
  | ThreeOperands (OprSIMD _, OprImm _, _) ->
    let struct (dst, imm, shf) = getThreeOprs ins
    let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
    let dstB, dstA = transOprToExpr128 ins ctxt addr dst
    let src = transBarrelShiftToExpr ins.OprSize ctxt imm shf
              |> advSIMDExpandImm ir eSize
    dstAssign128 ins ctxt addr dst (dstA .| src) (dstB .| src) dataSize ir
  | ThreeOperands (OprSIMD (SIMDVecReg (_, v)) as o1, o2, o3) ->
    let struct (_, dataSize, _) = getElemDataSzAndElems o1
    let src1B, src1A = transOprToExpr128 ins ctxt addr o2
    let src2B, src2A = transOprToExpr128 ins ctxt addr o3
    let resultB = src1B .| src2B
    let resultA = src1A .| src2A
    dstAssign128 ins ctxt addr o1 resultA resultB dataSize ir
  | _ ->
    let dst, src1, src2 = transOprToExprOfORR ins ctxt addr
    dstAssign ins.OprSize dst (src1 .| src2) ir
  !>ir insLen

let rbit ins insLen ctxt addr =
  let ir = !*ctxt
  match ins.Operands with
  | TwoOperands (OprRegister _, OprRegister _) ->
    let dst, src = transTwoOprs ins ctxt addr
    let datasize = if ins.OprSize = 64<rt> then 64 else 32
    let tmp = !+ir ins.OprSize
    !<ir insLen
    for i in 0 .. (datasize - 1) do
      !!ir (AST.extract tmp 1<rt> (datasize - 1 - i) := AST.extract src 1<rt> i)
    dstAssign ins.OprSize dst tmp ir
  | _ ->
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let dstB, dstA = transOprToExpr128 ins ctxt addr dst
    let src = transSIMDOprToExpr ctxt eSize dataSize elements src
    let rev = !+ir eSize
    let result = Array.init elements (fun _ -> !+ir eSize)
    !<ir insLen
    let reverse i e =
      let eSize = int eSize
      for i in 0 .. eSize - 1 do
        !!ir (AST.extract rev 1<rt> (eSize - 1 - i) := AST.extract e 1<rt> i)
      !!ir (result[i] := rev)
    Array.iteri reverse src
    dstAssignForSIMD dstA dstB result dataSize elements ir
  !>ir insLen

let ret ins insLen ctxt addr =
  let ir = !*ctxt
  let src = transOneOpr ins ctxt addr
  let target = !+ir 64<rt>
  !<ir insLen
  !!ir (target := src)
  branchTo ins ctxt target BrTypeRET InterJmpKind.IsRet ir
  !>ir insLen

let rev ins insLen ctxt addr =
  let ir = !*ctxt
  let e = if ins.OprSize = 64<rt> then 7 else 3
  let t = !+ir ins.OprSize
  !<ir insLen
  match ins.Operands with
  | TwoOperands (OprSIMD _, OprSIMD _) -> (* FIXME: SIMD Register *)
    !!ir (AST.sideEffect UnsupportedFP)
  | _ ->
    let dst, src = transTwoOprs ins ctxt addr
    for i in 0 .. e do
      !!ir (AST.extract t 8<rt> ((e - i) * 8) := AST.extract src 8<rt> (i * 8))
    dstAssign ins.OprSize dst t ir
  !>ir insLen

let rev16 ins insLen ctxt addr =
  let ir = !*ctxt
  let tmp = !+ir ins.OprSize
  !<ir insLen
  match ins.Operands with
  | TwoOperands (OprSIMD _, OprSIMD _) -> (* FIXME: SIMD Register *)
    !!ir (AST.sideEffect UnsupportedFP)
  | _ ->
    let dst, src = transTwoOprs ins ctxt addr
    for i in 0 .. ((int ins.OprSize / 8) - 1) do
      let idx = i * 8
      let revIdx = if i % 2 = 0 then idx + 8 else idx - 8
      !!ir (AST.extract tmp 8<rt> revIdx := AST.extract src 8<rt> idx)
    done
    dstAssign ins.OprSize dst tmp ir
  !>ir insLen

let rev32 ins insLen ctxt addr =
  let ir = !*ctxt
  let tmp = !+ir ins.OprSize
  !<ir insLen
  match ins.Operands with
  | TwoOperands(OprSIMD _, OprSIMD _) -> (* FIXME: SIMD Register *)
    !!ir (AST.sideEffect UnsupportedFP)
  | _ ->
    let dst, src = transTwoOprs ins ctxt addr
    for i in 0 .. ((int ins.OprSize / 8) - 1) do
      let revIdx = (i ^^^ 0b11) * 8
      !!ir (AST.extract tmp 8<rt> revIdx := AST.extract src 8<rt> (i * 8))
    done
    !!ir (dst := tmp)
  !>ir insLen

let rorv ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let amount = src2 .% oprSzToExpr ins.OprSize
  !<ir insLen
  dstAssign ins.OprSize dst (shiftReg src1 amount ins.OprSize SRTypeROR) ir
  !>ir insLen

let sbc ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let c = AST.zext ins.OprSize (getRegVar ctxt R.C)
  !<ir insLen
  let result, _ = addWithCarry src1 (AST.not src2) c ins.OprSize
  dstAssign ins.OprSize dst result ir
  !>ir insLen

let sbfm ins insLen ctxt addr dst src immr imms =
  let ir = !*ctxt
  let oprSz = ins.OprSize
  let width = oprSzToExpr oprSz
  let struct (wmask, tmask) = decodeBitMasks immr imms (int oprSz)
  let immr = transOprToExpr ins ctxt addr immr
  let imms = transOprToExpr ins ctxt addr imms
  !<ir insLen
  let struct (bot, top, tMask, srcS) = tmpVars4 ir oprSz
  !!ir (bot := rorForIR src immr width .& (numI64 wmask oprSz))
  !!ir (srcS := (src >> (imms .- AST.num1 oprSz)) .& (numI32 1 oprSz))
  !!ir (top := replicateForIR srcS (AST.num1 oprSz) oprSz ir)
  !!ir (tMask := numI64 tmask oprSz)
  dstAssign ins.OprSize dst ((top .& AST.not tMask) .| (bot .& tMask)) ir
  !>ir insLen

let sbfiz ins insLen ctxt addr =
  let struct (dst, src, lsb, width) = getFourOprs ins
  let dst = transOprToExpr ins ctxt addr dst
  let src = transOprToExpr ins ctxt addr src
  let immr =
    ((getImmValue lsb * -1L) &&& 0x3F) % (int64 ins.OprSize) |> OprImm
  let imms = getImmValue width - 1L |> OprImm
  sbfm ins insLen ctxt addr dst src immr imms

let sbfx ins insLen ctxt addr =
  let struct (dst, src, lsb, width) = getFourOprs ins
  let dst = transOprToExpr ins ctxt addr dst
  let src = transOprToExpr ins ctxt addr src
  let imms = (getImmValue lsb) + (getImmValue width) - 1L |> OprImm
  sbfm ins insLen ctxt addr dst src lsb imms

let fixedToFp oprSz src fbits unsigned round =
  let divBits =
    AST.cast CastKind.UIntToFloat oprSz (numU64 0x1uL oprSz << fbits)
  let intOperand, num0 =
    if unsigned then
      AST.cast CastKind.UIntToFloat oprSz src,
      AST.cast CastKind.UIntToFloat oprSz (AST.num0 oprSz)
    else
      AST.cast CastKind.SIntToFloat oprSz src,
      AST.cast CastKind.SIntToFloat oprSz (AST.num0 oprSz)
  let realOperand = AST.fdiv intOperand divBits
  let cond = AST.eq realOperand num0
  let result =
    match round with
    | FPRounding_TIEEVEN
    | FPRounding_TIEAWAY -> AST.cast CastKind.FtoFRound oprSz
    | FPRounding_Zero -> AST.cast CastKind.FtoFTrunc oprSz
    | FPRounding_POSINF -> AST.cast CastKind.FtoFCeil oprSz
    | FPRounding_NEGINF -> AST.cast CastKind.FtoFFloor oprSz
  AST.ite cond (AST.num0 oprSz) realOperand

let icvtf ins insLen ctxt addr unsigned =
  let ir = !*ctxt
  let oprSize = ins.OprSize
  !<ir insLen
  match ins.Operands with
  | TwoOperands (OprSIMD (SIMDVecReg _), _) ->
    let struct (o1, o2) = getTwoOprs ins
    let dstB, dstA = transOprToExpr128 ins ctxt addr o1
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o2
    let src = transSIMDOprToExpr ctxt eSize dataSize elements o2
    let result = Array.map (fun s -> fixedToFp eSize s (AST.num0 eSize)
                                      unsigned FPRounding_TIEEVEN) src
    dstAssignForSIMD dstA dstB result dataSize elements ir
  | TwoOperands (OprSIMD (SIMDFPScalarReg _), _) ->
    let dst, src = transTwoOprs ins ctxt addr
    let result = fixedToFp oprSize src (AST.num0 oprSize)
                  unsigned FPRounding_TIEEVEN
    dstAssign oprSize dst result ir
  | ThreeOperands (OprSIMD (SIMDVecReg _), _, _) ->
    let struct (o1, o2, o3) = getThreeOprs ins
    let dstB, dstA = transOprToExpr128 ins ctxt addr o1
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o2
    let src = transSIMDOprToExpr ctxt eSize dataSize elements o2
    let fbits = transOprToExpr ins ctxt addr o3 |> AST.xtlo eSize
    let result = Array.map (fun s ->
                  fixedToFp eSize s fbits unsigned FPRounding_TIEEVEN) src
    dstAssignForSIMD dstA dstB result dataSize elements ir
  | _ ->
    let dst, src, fbits = transThreeOprs ins ctxt addr (* FIXME *)
    let result = fixedToFp oprSize src fbits unsigned FPRounding_TIEEVEN
    dstAssign oprSize dst result ir
  !>ir insLen

let sdiv ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let num0 = AST.num0 ins.OprSize
  let cond1 = AST.eq src2 num0
  let fSrc1 = AST.cast CastKind.SIntToFloat ins.OprSize src1
  let fSrc2 = AST.cast CastKind.SIntToFloat ins.OprSize src2
  let realSrc = AST.fdiv fSrc1 fSrc2
  let cond2  = AST.eq realSrc num0
  let cond3 = AST.fgt realSrc num0
  !<ir insLen
  let roundDown = realSrc |> AST.cast CastKind.FtoITrunc ins.OprSize
  let roundUp = realSrc |> AST.cast CastKind.FtoICeil ins.OprSize
  let roundToZero = AST.ite cond2 num0 (AST.ite cond3 roundDown roundUp)
  let result = AST.ite cond1 num0 roundToZero
  dstAssign ins.OprSize dst result ir
  !>ir insLen

let shl ins insLen ctxt addr =
  let ir = !*ctxt
  let struct (dst, src, amt) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
  !<ir insLen
  match ins.Operands with
  | ThreeOperands (OprSIMD (SIMDFPScalarReg _), _, _) ->
    let dst, src, amt = transThreeOprs ins ctxt addr
    dstAssign ins.OprSize dst (src << amt) ir
  | _ ->
    let dstB, dstA = transOprToExpr128 ins ctxt addr dst
    let src = transSIMDOprToExpr ctxt eSize dataSize elements src
    let amt = transOprToExpr ins ctxt addr amt |> AST.xtlo eSize
    let result = Array.map (fun e -> e << amt) src
    dstAssignForSIMD dstA dstB result dataSize elements ir
  !>ir insLen

let smaddl ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2, src3 = transFourOprs ins ctxt addr
  !<ir insLen
  !!ir (dst := src3 .+ (AST.sext 64<rt> src1 .* AST.sext 64<rt> src2))
  !>ir insLen

let smov ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let dst, src = transTwoOprs ins ctxt addr
  !!ir (dst := AST.sext ins.OprSize src)
  !>ir insLen

let smsubl ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2, src3 = transOprToExprOfSMSUBL ins ctxt addr
  !<ir insLen
  !!ir (dst := src3 .- (AST.sext 64<rt> src1 .* AST.sext 64<rt> src2))
  !>ir insLen

let smulh ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let tSrc1B = !+ir 64<rt>
  let tSrc1A = !+ir 64<rt>
  let tSrc2B = !+ir 64<rt>
  let tSrc2A = !+ir 64<rt>
  let n32 = numI32 32 64<rt>
  let mask = numI64 0xFFFFFFFFL 64<rt>
  !<ir insLen
  !!ir (tSrc1B := (src1 >> n32) .& mask)
  !!ir (tSrc1A := src1 .& mask)
  !!ir (tSrc2B := (src2 >> n32) .& mask)
  !!ir (tSrc2A := src2 .& mask)
  let high = tSrc1B .* tSrc2B
  let mid = (tSrc1A .* tSrc2B) .+ (tSrc1B .* tSrc2A)
  let low = (tSrc1A .* tSrc2A) >> n32
  !!ir (dst := high .+ ((mid .+ low) >> n32)) (* [127:64] *)
  !>ir insLen

let smull ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  match ins.Operands with
  | ThreeOperands (OprSIMD _, _, _) -> !!ir (AST.sideEffect UnsupportedFP)
  | _ ->
    let dst, src1, src2 = transThreeOprs ins ctxt addr
    !!ir (dst := AST.sext 64<rt> src1 .* AST.sext 64<rt> src2)
  !>ir insLen

let shift ins insLen ctxt addr opFn =
  let ir = !*ctxt
  let struct (dst, src, amt) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  !<ir insLen
  match ins.Operands with
  | ThreeOperands (OprSIMD (SIMDFPScalarReg _), _, _) ->
    let dst, src, amt = transThreeOprs ins ctxt addr
    dstAssign ins.OprSize dst (opFn src amt) ir
  | _ ->
    let dstB, dstA = transOprToExpr128 ins ctxt addr dst
    let src = transSIMDOprToExpr ctxt eSize dataSize elements src
    let amt = transOprToExpr ins ctxt addr amt |> AST.xtlo eSize
    let result = Array.map (fun e -> opFn e amt) src
    dstAssignForSIMD dstA dstB result dataSize elements ir
  !>ir insLen

let stlr ins insLen ctxt addr =
  let ir = !*ctxt
  let src, (bReg, offset) = transTwoOprsSepMem ins ctxt addr
  let address = !+ir 64<rt>
  !<ir insLen
  !!ir (address := bReg .+ offset)
  dstAssign ins.OprSize (AST.loadLE ins.OprSize address) src ir
  !>ir insLen

let stlrb ins insLen ctxt addr =
  let ir = !*ctxt
  let src, (bReg, offset) = transTwoOprsSepMem ins ctxt addr
  let address = !+ir 64<rt>
  let data = !+ir 8<rt>
  !<ir insLen
  !!ir (address := bReg .+ offset)
  !!ir (data := AST.xtlo 8<rt> src)
  !!ir (AST.loadLE 8<rt> address := data)
  !>ir insLen

let stlx ins insLen ctxt addr size =
  let ir = !*ctxt
  let src1, src2, (bReg, offset) = transThreeOprsSepMem ins ctxt addr
  let address = !+ir 64<rt>
  let data = !+ir size
  !<ir insLen
  !!ir (address := bReg .+ offset)
  !!ir (data := AST.xtlo size src2)
  let status = exclusiveMonitorsPass ctxt address size data ir
  dstAssign 32<rt> src1 status ir
  !>ir insLen

let stlxr ins insLen ctxt addr =
  let ir = !*ctxt
  let src1, src2, (bReg, offset) = transThreeOprsSepMem ins ctxt addr
  let address = !+ir 64<rt>
  let data = !+ir ins.OprSize
  !<ir insLen
  !!ir (address := bReg .+ offset)
  !!ir (data := AST.zext ins.OprSize src2)
  let status = exclusiveMonitorsPass ctxt address ins.OprSize data ir
  dstAssign 32<rt> src1 status ir
  !>ir insLen

let stlxp ins insLen ctxt addr =
  let ir = !*ctxt
  let src1, src2, src3, (bReg, offset) = transFourOprsSepMem ins ctxt addr
  let address = !+ir 64<rt>
  !<ir insLen
  !!ir (address := bReg .+ offset)
  if ins.OprSize = 32<rt> then
    let data = !+ir 64<rt>
    !!ir (data := AST.concat (AST.xtlo 32<rt> src3) (AST.xtlo 32<rt> src2))
    let status = exclusiveMonitorsPass ctxt address 64<rt> data ir
    dstAssign 32<rt> src1 status ir
  else
    let status = exclusiveMonitorsPassPair ctxt address 64<rt> src2 src3 ir
    dstAssign 32<rt> src1 status ir
  !>ir insLen

let stp ins insLen ctxt addr =
  let ir = !*ctxt
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  !<ir insLen
  let address = !+ir 64<rt>
  let dByte = numI32 (RegType.toByteWidth ins.OprSize) 64<rt>
  match ins.OprSize with
  | 128<rt> ->
    let struct (src1, src2, src3) = getThreeOprs ins
    let src1B, src1A = transOprToExpr128 ins ctxt addr src1
    let src2B, src2A = transOprToExpr128 ins ctxt addr src2
    let bReg, offset = transOprToExpr ins ctxt addr src3 |> separateMemExpr
    let n8 = numI32 8 64<rt>
    !!ir (address := bReg)
    !!ir (address := if isPostIndex then address else address .+ offset)
    unmark ctxt address (memSizeToExpr ins.OprSize) ir
    !!ir (AST.loadLE 64<rt> address := src1A)
    !!ir (AST.loadLE 64<rt> (address .+ n8) := src1B)
    !!ir (AST.loadLE 64<rt> (address .+ dByte) := src2A)
    !!ir (AST.loadLE 64<rt> (address .+ dByte .+ n8) := src2B)
    if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
    else if isWBack then !!ir (bReg := address) else ()
  | _ ->
    let src1, src2, (bReg, offset) = transThreeOprsSepMem ins ctxt addr
    !!ir (address := bReg)
    !!ir (address := if isPostIndex then address else address .+ offset)
    unmark ctxt address (memSizeToExpr ins.OprSize) ir
    !!ir (AST.loadLE ins.OprSize address := src1)
    !!ir (AST.loadLE ins.OprSize (address .+ dByte) := src2)
    if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
    else if isWBack then !!ir (bReg := address) else ()
  !>ir insLen

let str ins insLen ctxt addr =
  let ir = !*ctxt
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  !<ir insLen
  match ins.OprSize with
  | 128<rt> ->
    let struct (src1, src2) = getTwoOprs ins
    let srcB, srcA = transOprToExpr128 ins ctxt addr src1
    let bReg, offset = transOprToExpr ins ctxt addr src2 |> separateMemExpr
    let address = !+ir 64<rt>
    !!ir (address := bReg)
    !!ir (address := if isPostIndex then address else address .+ offset)
    unmark ctxt address (memSizeToExpr ins.OprSize) ir
    !!ir (AST.loadLE 64<rt> address := srcA)
    !!ir (AST.loadLE 64<rt> (address .+ (numI32 8 64<rt>)) := srcB)
    if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
    else if isWBack then !!ir (bReg := address) else ()
  | _ ->
    let src, (bReg, offset) = transTwoOprsSepMem ins ctxt addr
    let address = !+ir 64<rt>
    let data = !+ir ins.OprSize
    !!ir (address := bReg)
    !!ir (address := if isPostIndex then address else address .+ offset)
    !!ir (data := src)
    unmark ctxt address (memSizeToExpr ins.OprSize) ir
    !!ir (AST.loadLE ins.OprSize address := data)
    if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
    else if isWBack then !!ir (bReg := address) else ()
  !>ir insLen

let strb ins insLen ctxt addr =
  let ir = !*ctxt
  let src, (bReg, offset) = transTwoOprsSepMem ins ctxt addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = !+ir 64<rt>
  let data = !+ir 8<rt>
  !<ir insLen
  !!ir (address := bReg)
  !!ir (address := if isPostIndex then address else address .+ offset)
  !!ir (data := AST.xtlo 8<rt> src)
  unmark ctxt address (memSizeToExpr ins.OprSize) ir
  !!ir (AST.loadLE 8<rt> address := data)
  if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
  else if isWBack then !!ir (bReg := address) else ()
  !>ir insLen

let strh ins insLen ctxt addr =
  let ir = !*ctxt
  let src, (bReg, offset) = transTwoOprsSepMem ins ctxt addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = !+ir 64<rt>
  let data = !+ir 16<rt>
  !<ir insLen
  !!ir (address := bReg)
  !!ir (address := if isPostIndex then address else address .+ offset)
  !!ir (data := AST.xtlo 16<rt> src)
  unmark ctxt address (memSizeToExpr ins.OprSize) ir
  !!ir (AST.loadLE 16<rt> address := data)
  if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
  else if isWBack then !!ir (bReg := address) else ()
  !>ir insLen

let stur ins insLen ctxt addr =
  let ir = !*ctxt
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = !+ir 64<rt>
  let data = !+ir ins.OprSize
  !<ir insLen
  match ins.OprSize with
  | 128<rt> ->
    let struct (src1, src2) = getTwoOprs ins
    let src1B, src1A = transOprToExpr128 ins ctxt addr src1
    let bReg, offset = transOprToExpr ins ctxt addr src2 |> separateMemExpr
    !!ir (address := bReg)
    !!ir (address := if isPostIndex then address else address .+ offset)
    unmark ctxt address (memSizeToExpr ins.OprSize) ir
    !!ir (AST.loadLE 64<rt> address := src1A)
    !!ir (AST.loadLE 64<rt> (address .+ (numI32 8 64<rt>)) := src1B)
    if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
    else if isWBack then !!ir (bReg := address) else ()
  | _ ->
    let src, (bReg, offset) = transTwoOprsSepMem ins ctxt addr
    !!ir (address := bReg)
    !!ir (address := if isPostIndex then address else address .+ offset)
    !!ir (data := src)
    unmark ctxt address (memSizeToExpr ins.OprSize) ir
    !!ir (AST.loadLE ins.OprSize address := data)
    if isWBack && isPostIndex then !!ir (bReg := address .+ offset)
    else if isWBack then !!ir (bReg := address) else ()
  !>ir insLen

let sturb ins insLen ctxt addr =
  let ir = !*ctxt
  let src, (bReg, offset) = transTwoOprsSepMem ins ctxt addr
  let address = !+ir 64<rt>
  let data = !+ir 8<rt>
  !<ir insLen
  !!ir (address := bReg)
  !!ir (address := address .+ offset)
  !!ir (data := AST.xtlo 8<rt> src)
  unmark ctxt address (memSizeToExpr ins.OprSize) ir
  !!ir (AST.loadLE 8<rt> address := data)
  !>ir insLen

let sturh ins insLen ctxt addr =
  let ir = !*ctxt
  let src, (bReg, offset) = transTwoOprsSepMem ins ctxt addr
  let address = !+ir 64<rt>
  let data = !+ir 16<rt>
  !<ir insLen
  !!ir (address := bReg)
  !!ir (address := address .+ offset)
  !!ir (data := AST.xtlo 16<rt> src)
  unmark ctxt address (memSizeToExpr ins.OprSize) ir
  !!ir (AST.loadLE 16<rt> address := data)
  !>ir insLen

let sub ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  match ins.Operands with
  | TwoOperands (OprSIMD (SIMDFPScalarReg _), _) ->
    let dst, src = transTwoOprs ins ctxt addr
    dstAssign ins.OprSize dst (AST.neg src) ir
  | TwoOperands (OprSIMD (SIMDVecReg _) as o1, o2) ->
    let dstB, dstA = transOprToExpr128 ins ctxt addr o1
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o2
    let src = transSIMDOprToExpr ctxt eSize dataSize elements o2
    let result = Array.map (AST.neg) src
    dstAssignForSIMD dstA dstB result dataSize elements ir
  | ThreeOperands (OprSIMD (SIMDFPScalarReg _), _, _)
      when ins.Opcode = Opcode.SUB ->
    let dst, src1, src2 = transThreeOprs ins ctxt addr
    dstAssign ins.OprSize dst (src1 .- src2) ir
  | ThreeOperands (OprSIMD (SIMDVecReg _) as o1, o2, o3)
      when ins.Opcode = Opcode.SUB ->
    let dstB, dstA = transOprToExpr128 ins ctxt addr o1
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let src1 = transSIMDOprToExpr ctxt eSize dataSize elements o2
    let src2 = transSIMDOprToExpr ctxt eSize dataSize elements o3
    let result = Array.map2 (.-) src1 src2
    dstAssignForSIMD dstA dstB result dataSize elements ir
  | _ ->
    let dst, src1, src2 = transOprToExprOfSUB ins ctxt addr
    let result, _ = addWithCarry src1 src2 (AST.num1 ins.OprSize) ins.OprSize
    dstAssign ins.OprSize dst result ir
  !>ir insLen

let subs ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let dst, src1, src2 = transOprToExprOfSUBS ins ctxt addr
  let result, (n, z, c, v) =
    addWithCarry src1 src2 (AST.num1 ins.OprSize) ins.OprSize
  !!ir (getRegVar ctxt R.N := n)
  !!ir (getRegVar ctxt R.Z := z)
  !!ir (getRegVar ctxt R.C := c)
  !!ir (getRegVar ctxt R.V := v)
  dstAssign ins.OprSize dst result ir
  !>ir insLen

let svc ins insLen ctxt =
  let ir = !*ctxt
  let n =
    match ins.Operands with
    | OneOperand (OprImm n) -> int n
    | _ -> raise InvalidOperandException
  !<ir insLen
  !!ir (AST.sideEffect (Interrupt n))
  !>ir insLen

let sxtb ins insLen ctxt addr =
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr ins ctxt addr dst
  let src = transOprToExpr ins ctxt addr src
  let src = if ins.OprSize = 64<rt> then unwrapReg src else src
  sbfm ins insLen ctxt addr dst src (OprImm 0L) (OprImm 7L)

let sxth ins insLen ctxt addr =
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr ins ctxt addr dst
  let src = transOprToExpr ins ctxt addr src
  let src = if ins.OprSize = 64<rt> then unwrapReg src else src
  sbfm ins insLen ctxt addr dst src (OprImm 0L) (OprImm 15L)

let sxtw ins insLen ctxt addr =
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr ins ctxt addr dst
  let src = transOprToExpr ins ctxt addr src |> unwrapReg
  sbfm ins insLen ctxt addr dst src (OprImm 0L) (OprImm 31L)

let tbnz ins insLen ctxt addr =
  let ir = !*ctxt
  let test, imm, label = transThreeOprs ins ctxt addr
  let pc = getPC ctxt
  let fall = pc .+ numU32 insLen 64<rt>
  let cond = (test >> imm .& AST.num1 ins.OprSize) == AST.num1 ins.OprSize
  !<ir insLen
  !!ir (AST.intercjmp cond (pc .+ label) fall)
  !>ir insLen

let tbz ins insLen ctxt addr =
  let ir = !*ctxt
  let test, imm, label = transThreeOprs ins ctxt addr
  let pc = getPC ctxt
  let fall = pc .+ numU32 insLen 64<rt>
  let cond = (test >> imm .& AST.num1 ins.OprSize) == AST.num0 ins.OprSize
  !<ir insLen
  !!ir (AST.intercjmp cond (pc .+ label) fall)
  !>ir insLen

let tst ins insLen ctxt addr =
  let ir = !*ctxt
  let src1, src2 = transOprToExprOfTST ins ctxt addr
  let result = !+ir ins.OprSize
  !<ir insLen
  !!ir (result := src1 .& src2)
  !!ir (getRegVar ctxt R.N := AST.xthi 1<rt> result)
  !!ir (getRegVar ctxt R.Z := result == AST.num0 ins.OprSize)
  !!ir (getRegVar ctxt R.C := AST.b0)
  !!ir (getRegVar ctxt R.V := AST.b0)
  !>ir insLen

let uaddw ins insLen ctxt addr =
  let ir = !*ctxt
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (eSize, dataSize, _) = getElemDataSzAndElems src2
  let elements = 64<rt> / eSize
  let dstB, dstA = transOprToExpr128 ins ctxt addr dst
  let src1 = transSIMDOprToExpr ctxt (2 * eSize) 128<rt> elements src1
  let src2 =
    if dataSize = 128<rt> then
      let src2 = transSIMDOprToExpr ctxt eSize dataSize (elements * 2) src2
      Array.sub src2 elements elements
    else transSIMDOprToExpr ctxt eSize dataSize elements src2
  !<ir insLen
  let result =
    Array.map2 (fun e1 e2 -> e1 .+ (AST.zext (2 * eSize) e2)) src1 src2
  dstAssignForSIMD dstA dstB result 128<rt> elements ir
  !>ir insLen

let ubfm ins insLen ctxt addr dst src immr imms =
  let ir = !*ctxt
  let oSz = ins.OprSize
  let width = oprSzToExpr oSz
  let struct (wmask, tmask) = decodeBitMasks immr imms (int oSz)
  let dst = transOprToExpr ins ctxt addr dst
  let src = transOprToExpr ins ctxt addr src
  let immr = transOprToExpr ins ctxt addr immr
  let bot = !+ir oSz
  !<ir insLen
  !!ir (bot := rorForIR src immr width .& (numI64 wmask oSz))
  dstAssign ins.OprSize dst (bot .& (numI64 tmask oSz)) ir
  !>ir insLen

let ubfiz ins insLen ctxt addr =
  let struct (dst, src, lsb, width) = getFourOprs ins
  let immr =
    ((getImmValue lsb * -1L) &&& 0x3F) % (int64 ins.OprSize) |> OprImm
  let imms = getImmValue width - 1L |> OprImm
  ubfm ins insLen ctxt addr dst src immr imms

let ubfx ins insLen ctxt addr =
  let struct (dst, src, lsb, width) = getFourOprs ins
  let imms = (getImmValue lsb) + (getImmValue width) - 1L |> OprImm
  ubfm ins insLen ctxt addr dst src lsb imms

let udiv ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let num0 = AST.num0 ins.OprSize
  let cond1 = AST.eq src2 num0
  let realSrc = AST.fdiv src1 src2
  let cond2 = AST.eq realSrc num0
  !<ir insLen
  let roundDown = realSrc |> AST.cast CastKind.FtoITrunc ins.OprSize
  let roundToZero = AST.ite cond2 num0 roundDown
  let result = AST.ite cond1 num0 roundToZero
  dstAssign ins.OprSize dst result ir
  !>ir insLen

let umaddl ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2, src3 = transFourOprs ins ctxt addr
  !<ir insLen
  !!ir (dst := src3 .+ (AST.zext 64<rt> src1 .* AST.zext 64<rt> src2))
  !>ir insLen

let umax ins insLen ctxt addr =
  let ir = !*ctxt
  let struct (o1, o2, o3) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
  //let dstB, dstA = transOprToExpr128 ins ctxt addr o1
  let dst = transSIMDOprToExpr ctxt eSize dataSize elements o1
  let s1 = transSIMDOprToExpr ctxt eSize dataSize elements o2
  let s2 = transSIMDOprToExpr ctxt eSize dataSize elements o3
  !<ir insLen
  Array.iteri (fun i d -> !!ir (d := AST.ite (s1[i] .>= s2[i]) s1[i] s2[i])) dst
  !>ir insLen

let umamiv ins insLen ctxt addr opFn =
  let ir = !*ctxt
  let struct (o1, o2) = getTwoOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems o2
  let dst = transOprToExpr ins ctxt addr o1
  let src = transSIMDOprToExpr ctxt eSize dataSize elements o2
  let min = !+ir eSize
  !<ir insLen
  !!ir (min := src[0])
  Array.sub src 1 (elements - 1)
  |> Array.iter (fun e -> !!ir (min := AST.ite (opFn min e) min e))
  dstAssign eSize dst min ir
  !>ir insLen

let umov ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let dst, src = transTwoOprs ins ctxt addr
  dstAssign ins.OprSize dst src ir
  !>ir insLen

let umsubl ins insLen ctxt addr =
  let dst, src1, src2, src3 = transOprToExprOfUMADDL ins ctxt addr
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src3 .- (AST.zext 64<rt> src1 .* AST.zext 64<rt> src2))
  !>ir insLen

let umulh ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let struct (tSrc1B, tSrc1A, tSrc2B, tSrc2A) = tmpVars4 ir 64<rt>
  let n32 = numI32 32 64<rt>
  let mask = numI64 0xFFFFFFFFL 64<rt>
  !<ir insLen
  !!ir (tSrc1B := (src1 >> n32) .& mask)
  !!ir (tSrc1A := src1 .& mask)
  !!ir (tSrc2B := (src2 >> n32) .& mask)
  !!ir (tSrc2A := src2 .& mask)
  let high = tSrc1B .* tSrc2B
  let mid = (tSrc1A .* tSrc2B) .+ (tSrc1B .* tSrc2A)
  let low = (tSrc1A .* tSrc2A) >> n32
  !!ir (dst := high .+ ((mid .+ low) >> n32)) (* [127:64] *)
  !>ir insLen

let umull ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  match ins.Operands with
  | ThreeOperands (OprSIMD _, _, _) -> !!ir (AST.sideEffect UnsupportedFP)
  | _ ->
    let dst, src1, src2 = transThreeOprs ins ctxt addr
    !!ir (dst := AST.zext 64<rt> src1 .* AST.zext 64<rt> src2)
  !>ir insLen

let uqsub ins insLen ctxt addr =
  let ir = !*ctxt
  let struct (o1, o2, o3) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
  let diff = !+ir 64<rt>
  !<ir insLen
  match ins.Operands with
  | ThreeOperands (OprSIMD (SIMDVecReg _), _, _) ->
    let dstB, dstA = transOprToExpr128 ins ctxt addr o1
    let src1 = transSIMDOprToExpr ctxt eSize dataSize elements o2
    let src2 = transSIMDOprToExpr ctxt eSize dataSize elements o3
    let result =
      Array.map2 (fun e1 e2 ->
        let diff = AST.zext 64<rt> e1 .- AST.zext 64<rt> e2
        satQ diff eSize true ir) src1 src2
    dstAssignForSIMD dstA dstB result dataSize elements ir
  | ThreeOperands (OprSIMD (SIMDFPScalarReg _), _, _) ->
    let dst, src1, src2 = transThreeOprs ins ctxt addr
    !!ir (diff := AST.zext 64<rt> src1 .- AST.zext 64<rt> src2)
    dstAssign eSize dst (satQ diff eSize true ir) ir
  | _ -> raise InvalidOperandException
  !>ir insLen

let shiftULeftLong ins insLen ctxt addr =
  let ir = !*ctxt
  let struct (o1, o2, o3) = getThreeOprs ins
  let struct (eSize, _, _) = getElemDataSzAndElems o2
  let elements = 64<rt> / eSize
  !<ir insLen
  let dst = transSIMDOprToExpr ctxt (2 * eSize) 128<rt> elements o1
  let src = vectorPart ctxt o2 eSize
  let amt = transOprToExpr ins ctxt addr o3
  let result = Array.map (fun s ->
                 AST.zext (2 * eSize) s << (amt |> AST.xtlo (2 * eSize))) src
  Array.iter2 (fun d r -> !!ir (d := r)) dst result
  !>ir insLen

let shiftSLeftLong ins insLen ctxt addr =
  let ir = !*ctxt
  let struct (o1, o2, o3) = getThreeOprs ins
  let struct (eSize, _, _) = getElemDataSzAndElems o2
  let elements = 64<rt> / eSize
  !<ir insLen
  let dst = transSIMDOprToExpr ctxt (2 * eSize) 128<rt> elements o1
  let src = vectorPart ctxt o2 eSize
  let amt = transOprToExpr ins ctxt addr o3
  let result = Array.map (fun s ->
                 AST.sext (2 * eSize) s << (amt |> AST.xtlo (2 * eSize))) src
  Array.iter2 (fun d r -> !!ir (d := r)) dst result
  !>ir insLen

let roundShiftLeft ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  match ins.Operands with
  | ThreeOperands (OprSIMD (SIMDFPScalarReg _), _, _) ->
    let dst, src, shiftReg = transThreeOprs ins ctxt addr
    let round = src << (shiftReg .& numI64 0xffL 64<rt>)
    dstAssign ins.OprSize dst round ir
  | _ ->
    let struct (dst, src, shiftReg) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
    let dstB, dstA = transOprToExpr128 ins ctxt addr dst
    let src = transSIMDOprToExpr ctxt eSize dataSize elements src
    let shiftReg = transSIMDOprToExpr ctxt eSize dataSize elements shiftReg
                   |> Array.map (fun r -> r .& numI64 0xffL eSize)
    let result = Array.map2 (<<) src shiftReg
    dstAssignForSIMD dstA dstB result dataSize elements ir
  !>ir insLen

let urhadd ins insLen ctxt addr =
  let ir = !*ctxt
  let struct (o1, o2, o3) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
  let dstB, dstA = transOprToExpr128 ins ctxt addr o1
  let src1 = transSIMDOprToExpr ctxt eSize dataSize elements o2
  let src2 = transSIMDOprToExpr ctxt eSize dataSize elements o3
  !<ir insLen
  let result = Array.map2 (fun s1 s2 ->
                 (s1 .+ s2 .+ AST.num1 eSize) >> AST.num1 eSize) src1 src2
  dstAssignForSIMD dstA dstB result dataSize elements ir
  !>ir insLen

let shiftRight ins insLen ctxt addr shifter =
  let ir = !*ctxt
  let struct (o1, o2, o3) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
  let dst = transSIMDOprToExpr ctxt eSize dataSize elements o1
  let src = transSIMDOprToExpr ctxt eSize dataSize elements o2
  let shf = transOprToExpr ins ctxt addr o3 |> AST.xtlo eSize
  !<ir insLen
  Array.map2 (fun e1 e2 -> e1 .+ (shifter e2 shf)) dst src
  |> Array.iter2 (fun e1 e2 -> !!ir (e1 := e2)) dst
  !>ir insLen

let ssubl ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let struct (o1, o2, o3) = getThreeOprs ins
  let struct (eSize, _, _) = getElemDataSzAndElems o2
  let elements = 64<rt> / eSize
  let dstB, dstA = transOprToExpr128 ins ctxt addr o1
  let src1 = vectorPart ctxt o2 eSize
  let src2 = vectorPart ctxt o3 eSize
  let result = Array.map2 (fun s1 s2 ->
                 AST.sext (2 * eSize) s1 .- AST.sext (2 * eSize) s2) src1 src2
  dstAssignForSIMD dstA dstB result 128<rt> elements ir
  !>ir insLen

let ssubw ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let struct (o1, o2, o3) = getThreeOprs ins
  let struct (eSize, _, _) = getElemDataSzAndElems o3
  let elements = 64<rt> / eSize
  let dstB, dstA = transOprToExpr128 ins ctxt addr o1
  let src1 = transSIMDOprToExpr ctxt (2 * eSize) 128<rt> elements o2
  let src2 = vectorPart ctxt o3 eSize
  let result =
    Array.map2 (fun s1 s2 -> s1 .- AST.sext (2 * eSize) s2) src1 src2
  dstAssignForSIMD dstA dstB result 128<rt> elements ir
  !>ir insLen

let uxtb ins insLen ctxt addr =
  let struct (dst, src) = getTwoOprs ins
  ubfm ins insLen ctxt addr dst src (OprImm 0L) (OprImm 7L)

let uxth ins insLen ctxt addr =
  let struct (dst, src) = getTwoOprs ins
  ubfm ins insLen ctxt addr dst src (OprImm 0L) (OprImm 15L)

let uzp ins insLen ctxt addr op =
  let ir = !*ctxt
  let struct (dst, src1, srcH) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  !<ir insLen
  let dstB, dstA = transOprToExpr128 ins ctxt addr dst
  let src1 = transSIMDOprToExpr ctxt eSize dataSize elements src1
  let srcH = transSIMDOprToExpr ctxt eSize dataSize elements srcH
  let result =
    Array.append src1 srcH
    |> Array.mapi (fun i x -> (i, x))
    |> Array.filter (fun (i, _) -> i % 2 = op)
    |> Array.map snd
  dstAssignForSIMD dstA dstB result dataSize elements ir
  !>ir insLen

let xtn ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
  let dstB, dstA = transOprToExpr128 ins ctxt addr dst
  let src = transSIMDOprToExpr ctxt eSize dataSize elements src
            |> Array.map (AST.xtlo (eSize / 2))
  !!ir (dstA := AST.concatArr src)
  !!ir (dstB := AST.num0 64<rt>)
  !>ir insLen

let xtn2 ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src) = getTwoOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
  let dstB, dstA = transOprToExpr128 ins ctxt addr dst
  let src = transSIMDOprToExpr ctxt eSize dataSize elements src
            |> Array.map (AST.xtlo (eSize / 2))
  !!ir (dstA := dstA)
  !!ir (dstB := AST.concatArr src)
  !>ir insLen

let zip ins insLen ctxt addr =
  let ir = !*ctxt
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  !<ir insLen
  let dstB, dstA = transOprToExpr128 ins ctxt addr dst
  let src1 = transSIMDOprToExpr ctxt eSize dataSize elements src1
  let src2 = transSIMDOprToExpr ctxt eSize dataSize elements src2
  let result = Array.init elements (fun i -> if i % 2 = 0 then src1.[i / 2]
                                             else src2.[i / 2])
  dstAssignForSIMD dstA dstB result dataSize elements ir
  !>ir insLen

/// The logical shift left(or right) is the alias of LS{L|R}V and UBFM.
/// Therefore, it is necessary to distribute to the original instruction.
let distLogicalLeftShift ins insLen ctxt addr =
  match ins.Operands with
  | ThreeOperands (_, _, OprImm _) -> logShift ins insLen ctxt addr (<<)
  | ThreeOperands (_, _, OprRegister _) -> lslv ins insLen ctxt addr
  | _ -> raise InvalidOperandException

let distLogicalRightShift ins insLen ctxt addr =
  match ins.Operands with
  | ThreeOperands (_, _, OprImm _) -> logShift ins insLen ctxt addr (>>)
  | ThreeOperands (_, _, OprRegister _) -> lsrv ins insLen ctxt addr
  | _ -> raise InvalidOperandException

/// Translate IR.
let translate ins insLen ctxt =
  let addr = ins.Address
  match ins.Opcode with
  | Opcode.ABS -> abs ins insLen ctxt addr
  | Opcode.ADC -> adc ins insLen ctxt addr
  | Opcode.ADCS -> adcs ins insLen ctxt addr
  | Opcode.ADD -> add ins insLen ctxt addr
  | Opcode.ADDP -> addp ins insLen ctxt addr
  | Opcode.ADDS -> adds ins insLen ctxt addr
  | Opcode.ADDV -> addv ins insLen ctxt addr
  | Opcode.ADR -> adr ins insLen ctxt addr
  | Opcode.ADRP -> adrp ins insLen ctxt addr
  | Opcode.AND -> logAnd ins insLen ctxt addr
  | Opcode.ANDS -> ands ins insLen ctxt addr
  | Opcode.ASR -> asrv ins insLen ctxt addr
  | Opcode.B -> b ins insLen ctxt addr
  | Opcode.BAL -> bCond ins insLen ctxt addr AL
  | Opcode.BCC -> bCond ins insLen ctxt addr CC
  | Opcode.BCS -> bCond ins insLen ctxt addr CS
  | Opcode.BEQ -> bCond ins insLen ctxt addr EQ
  | Opcode.BFI -> bfi ins insLen ctxt addr
  | Opcode.BFXIL -> bfxil ins insLen ctxt addr
  | Opcode.BGE -> bCond ins insLen ctxt addr GE
  | Opcode.BGT -> bCond ins insLen ctxt addr GT
  | Opcode.BHI -> bCond ins insLen ctxt addr HI
  | Opcode.BIC -> bic ins insLen ctxt addr
  | Opcode.BICS -> bics ins insLen ctxt addr
  | Opcode.BIF -> bif ins insLen ctxt addr
  | Opcode.BIT -> bit ins insLen ctxt addr
  | Opcode.BL -> bl ins insLen ctxt addr
  | Opcode.BLE -> bCond ins insLen ctxt addr LE
  | Opcode.BLR -> blr ins insLen ctxt addr
  | Opcode.BLS -> bCond ins insLen ctxt addr LS
  | Opcode.BLT -> bCond ins insLen ctxt addr LT
  | Opcode.BMI -> bCond ins insLen ctxt addr MI
  | Opcode.BNE -> bCond ins insLen ctxt addr NE
  | Opcode.BNV -> bCond ins insLen ctxt addr NV
  | Opcode.BPL -> bCond ins insLen ctxt addr PL
  | Opcode.BR -> br ins insLen ctxt addr
  | Opcode.BRK -> sideEffects insLen ctxt Breakpoint
  | Opcode.BSL -> bsl ins insLen ctxt addr
  | Opcode.BVC -> bCond ins insLen ctxt addr VC
  | Opcode.BVS -> bCond ins insLen ctxt addr VS
  | Opcode.CAS | Opcode.CASA | Opcode.CASL | Opcode.CASAL ->
    compareAndSwap ins insLen ctxt addr
  | Opcode.CBNZ -> cbnz ins insLen ctxt addr
  | Opcode.CBZ -> cbz ins insLen ctxt addr
  | Opcode.CCMN -> ccmn ins insLen ctxt addr
  | Opcode.CCMP -> ccmp ins insLen ctxt addr
  | Opcode.CLZ -> clz ins insLen ctxt addr
  | Opcode.CMEQ -> cmeq ins insLen ctxt addr
  | Opcode.CMGE -> cmge ins insLen ctxt addr
  | Opcode.CMGT -> cmgt ins insLen ctxt addr
  | Opcode.CMHI -> cmhi ins insLen ctxt addr
  | Opcode.CMHS -> cmhs ins insLen ctxt addr
  | Opcode.CMLT -> cmlt ins insLen ctxt addr
  | Opcode.CMN -> cmn ins insLen ctxt addr
  | Opcode.CMP -> cmp ins insLen ctxt addr
  | Opcode.CMTST -> cmtst ins insLen ctxt addr
  | Opcode.CNEG | Opcode.CSNEG -> csneg ins insLen ctxt addr
  | Opcode.CNT -> cnt ins insLen ctxt addr
  | Opcode.CSEL -> csel ins insLen ctxt addr
  | Opcode.CSETM | Opcode.CINV | Opcode.CSINV -> csinv ins insLen ctxt addr
  | Opcode.CSINC | Opcode.CINC | Opcode.CSET -> csinc ins insLen ctxt addr
  | Opcode.DCZVA -> dczva ins insLen ctxt addr
  | Opcode.DMB | Opcode.DSB | Opcode.ISB -> nop insLen ctxt
  | Opcode.DUP -> dup ins insLen ctxt addr
  | Opcode.EOR | Opcode.EON -> eor ins insLen ctxt addr
  | Opcode.EXT -> ext ins insLen ctxt addr
  | Opcode.EXTR | Opcode.ROR -> extr ins insLen ctxt addr
  | Opcode.FABD -> fabd ins insLen ctxt addr
  | Opcode.FABS -> fabs ins insLen ctxt addr
  | Opcode.FADD -> fadd ins insLen ctxt addr
  | Opcode.FADDP -> faddp ins insLen ctxt addr
  | Opcode.FCCMP -> fccmp ins insLen ctxt addr
  | Opcode.FCCMPE -> fccmpe ins insLen ctxt addr
  | Opcode.FCMGT -> fcmgt ins insLen ctxt addr
  | Opcode.FCMP -> fcmp ins insLen ctxt addr
  | Opcode.FCMPE -> fcmpe ins insLen ctxt addr
  | Opcode.FCSEL -> fcsel ins insLen ctxt addr
  | Opcode.FCVT -> fcvt ins insLen ctxt addr
  | Opcode.FCVTAS -> fcvtas ins insLen ctxt addr
  | Opcode.FCVTAU -> fcvtau ins insLen ctxt addr
  | Opcode.FCVTMS -> fcvtms ins insLen ctxt addr
  | Opcode.FCVTMU -> fcvtmu ins insLen ctxt addr
  | Opcode.FCVTPS -> fcvtps ins insLen ctxt addr
  | Opcode.FCVTPU -> fcvtpu ins insLen ctxt addr
  | Opcode.FCVTZS -> fcvtzs ins insLen ctxt addr
  | Opcode.FCVTZU -> fcvtzu ins insLen ctxt addr
  | Opcode.FDIV -> fdiv ins insLen ctxt addr
  | Opcode.FMADD -> fmadd ins insLen ctxt addr
  | Opcode.FMAX -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.FMAXNM -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.FMOV -> fmov ins insLen ctxt addr
  | Opcode.FMSUB -> fmsub ins insLen ctxt addr
  | Opcode.FMUL -> fmul ins insLen ctxt addr
  | Opcode.FNEG -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.FNMUL -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.FRINTA -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.FRINTM -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.FRINTP -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.FRINTZ -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.FSQRT -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.FSUB -> fsub ins insLen ctxt addr
  | Opcode.HINT -> nop insLen ctxt
  | Opcode.INS -> insv ins insLen ctxt addr
  | Opcode.LD1 -> ld1 ins insLen ctxt addr
  | Opcode.LD1R -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.LD2 -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.LD2R -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.LD3 -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.LD3R -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.LD4 -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.LD4R -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.LDAR -> ldar ins insLen ctxt addr
  | Opcode.LDARB -> ldarb ins insLen ctxt addr
  | Opcode.LDAXP | Opcode.LDXP -> ldaxp ins insLen ctxt addr
  | Opcode.LDAXR | Opcode.LDXR -> ldaxr ins insLen ctxt addr
  | Opcode.LDAXRB | Opcode.LDXRB -> ldax ins insLen ctxt addr 8<rt>
  | Opcode.LDAXRH | Opcode.LDXRH -> ldax ins insLen ctxt addr 16<rt>
  | Opcode.LDP -> ldp ins insLen ctxt addr
  | Opcode.LDPSW -> ldpsw ins insLen ctxt addr
  | Opcode.LDR -> ldr ins insLen ctxt addr
  | Opcode.LDRB -> ldrb ins insLen ctxt addr
  | Opcode.LDRH -> ldrh ins insLen ctxt addr
  | Opcode.LDRSB -> ldrsb ins insLen ctxt addr
  | Opcode.LDRSH -> ldrsh ins insLen ctxt addr
  | Opcode.LDRSW -> ldrsw ins insLen ctxt addr
  | Opcode.LDUR -> ldur ins insLen ctxt addr
  | Opcode.LDURB -> ldurb ins insLen ctxt addr
  | Opcode.LDURH -> ldurh ins insLen ctxt addr
  | Opcode.LDURSB -> ldursb ins insLen ctxt addr
  | Opcode.LDURSH -> ldursh ins insLen ctxt addr
  | Opcode.LDURSW -> ldursw ins insLen ctxt addr
  | Opcode.LSL -> distLogicalLeftShift ins insLen ctxt addr
  | Opcode.LSR -> distLogicalRightShift ins insLen ctxt addr
  | Opcode.MADD -> madd ins insLen ctxt addr
  | Opcode.MLA -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.MNEG -> msub ins insLen ctxt addr
  | Opcode.MOV -> mov ins insLen ctxt addr
  | Opcode.MOVI -> movi ins insLen ctxt addr
  | Opcode.MOVK -> movk ins insLen ctxt addr
  | Opcode.MOVN -> movn ins insLen ctxt addr
  | Opcode.MOVZ -> movz ins insLen ctxt addr
  | Opcode.MRS -> mrs ins insLen ctxt addr
  | Opcode.MSR -> msr ins insLen ctxt addr
  | Opcode.MSUB -> msub ins insLen ctxt addr
  | Opcode.MUL -> madd ins insLen ctxt addr
  | Opcode.MVN -> orn ins insLen ctxt addr
  | Opcode.MVNI -> mvni ins insLen ctxt addr
  | Opcode.NEG -> sub ins insLen ctxt addr
  | Opcode.NEGS -> subs ins insLen ctxt addr
  | Opcode.NOP -> nop insLen ctxt
  | Opcode.ORN -> orn ins insLen ctxt addr
  | Opcode.ORR -> orr ins insLen ctxt addr
  | Opcode.RBIT -> rbit ins insLen ctxt addr
  | Opcode.RET -> ret ins insLen ctxt addr
  | Opcode.REV -> rev ins insLen ctxt addr
  | Opcode.REV16 -> rev16 ins insLen ctxt addr
  | Opcode.REV32 -> rev32 ins insLen ctxt addr
  | Opcode.REV64 -> rev ins insLen ctxt addr
  | Opcode.RORV -> rorv ins insLen ctxt addr
  | Opcode.SBC -> sbc ins insLen ctxt addr
  | Opcode.SBFIZ -> sbfiz ins insLen ctxt addr
  | Opcode.SBFX -> sbfx ins insLen ctxt addr
  | Opcode.SCVTF -> icvtf ins insLen ctxt addr false
  | Opcode.SDIV -> sdiv ins insLen ctxt addr
  | Opcode.SHL -> shl ins insLen ctxt addr
  | Opcode.SMADDL -> smaddl ins insLen ctxt addr
  | Opcode.SMOV -> smov ins insLen ctxt addr
  | Opcode.SMSUBL | Opcode.SMNEGL -> smsubl ins insLen ctxt addr
  | Opcode.SMULH -> smulh ins insLen ctxt addr
  | Opcode.SMULL -> smull ins insLen ctxt addr
  | Opcode.SSHL | Opcode.USHL -> shift ins insLen ctxt addr (<<)
  | Opcode.UXTL | Opcode.UXTL2 | Opcode.USHLL | Opcode.USHLL2 ->
    shiftULeftLong ins insLen ctxt addr
  | Opcode.SXTL | Opcode.SXTL2 | Opcode.SSHLL | Opcode.SSHLL2 ->
    shiftSLeftLong ins insLen ctxt addr
  | Opcode.SSHR -> shift ins insLen ctxt addr (?>>)
  | Opcode.SSRA -> shiftRight ins insLen ctxt addr (?>>)
  | Opcode.SSUBL | Opcode.SSUBL2 -> ssubl ins insLen ctxt addr
  | Opcode.SSUBW | Opcode.SSUBW2 -> ssubw ins insLen ctxt addr
  | Opcode.ST1 -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.ST2 -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.ST3 -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.ST4 -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.STLR -> stlr ins insLen ctxt addr
  | Opcode.STLRB -> stlrb ins insLen ctxt addr
  | Opcode.STLXP | Opcode.STXP -> stlxp ins insLen ctxt addr
  | Opcode.STLXR | Opcode.STXR -> stlxr ins insLen ctxt addr
  | Opcode.STLXRB | Opcode.STXRB -> stlx ins insLen ctxt addr 8<rt>
  | Opcode.STLXRH | Opcode.STXRH -> stlx ins insLen ctxt addr 16<rt>
  | Opcode.STP -> stp ins insLen ctxt addr
  | Opcode.STR -> str ins insLen ctxt addr
  | Opcode.STRB -> strb ins insLen ctxt addr
  | Opcode.STRH -> strh ins insLen ctxt addr
  | Opcode.STUR -> stur ins insLen ctxt addr
  | Opcode.STURB -> sturb ins insLen ctxt addr
  | Opcode.STURH -> sturh ins insLen ctxt addr
  | Opcode.SUB -> sub ins insLen ctxt addr
  | Opcode.SUBS -> subs ins insLen ctxt addr
  | Opcode.SVC -> svc ins insLen ctxt
  | Opcode.SXTB -> sxtb ins insLen ctxt addr
  | Opcode.SXTH -> sxth ins insLen ctxt addr
  | Opcode.SXTW -> sxtw ins insLen ctxt addr
  | Opcode.TBL -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.TBNZ -> tbnz ins insLen ctxt addr
  | Opcode.TBZ -> tbz ins insLen ctxt addr
  | Opcode.TST -> tst ins insLen ctxt addr
  | Opcode.UADDLV -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.UADDW | Opcode.UADDW2 -> uaddw ins insLen ctxt addr
  | Opcode.UBFIZ -> ubfiz ins insLen ctxt addr
  | Opcode.UBFX -> ubfx ins insLen ctxt addr
  | Opcode.UCVTF -> icvtf ins insLen ctxt addr true
  | Opcode.UDIV -> udiv ins insLen ctxt addr
  | Opcode.UMADDL -> umaddl ins insLen ctxt addr
  | Opcode.UMAX -> umax ins insLen ctxt addr
  | Opcode.UMAXV -> umamiv ins insLen ctxt addr (.>=)
  | Opcode.UMINV -> umamiv ins insLen ctxt addr (.<=)
  | Opcode.UMLAL -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.UMLAL2 -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.UMOV -> umov ins insLen ctxt addr
  | Opcode.UMSUBL | Opcode.UMNEGL -> umsubl ins insLen ctxt addr
  | Opcode.UMULH -> umulh ins insLen ctxt addr
  | Opcode.UMULL -> umull ins insLen ctxt addr
  | Opcode.UQSUB -> uqsub ins insLen ctxt addr
  | Opcode.URSHL | Opcode.SRSHL -> roundShiftLeft ins insLen ctxt addr
  | Opcode.URHADD -> urhadd ins insLen ctxt addr
  | Opcode.USHR -> shift ins insLen ctxt addr (>>)
  | Opcode.USRA -> shiftRight ins insLen ctxt addr (>>)
  | Opcode.USUBW | Opcode.USUBW2 -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.UXTB -> uxtb ins insLen ctxt addr
  | Opcode.UXTH -> uxth ins insLen ctxt addr
  | Opcode.UZP1 -> uzp ins insLen ctxt addr 0
  | Opcode.UZP2 -> uzp ins insLen ctxt addr 1
  | Opcode.XTN -> xtn ins insLen ctxt addr
  | Opcode.XTN2 -> xtn2 ins insLen ctxt addr
  | Opcode.ZIP1 | Opcode.ZIP2 -> zip ins insLen ctxt addr
  | o ->
#if DEBUG
         eprintfn "%A" o
#endif
         raise <| NotImplementedIRException (Disasm.opCodeToString o)

// vim: set tw=80 sts=2 sw=2:
