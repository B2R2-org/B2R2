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

module internal B2R2.FrontEnd.ARM64.Lifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.ARM64
open B2R2.FrontEnd.ARM64.LiftingUtils

/// A module for all AArch64-IR translation functions
let sideEffects insAddr insLen bld name =
  bld <!-- (insAddr, insLen)
  bld <+ (AST.sideEffect name)
  bld --!> insLen

let abs (ins: InsInfo) insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  match ins.Operands with
  | TwoOperands (OprSIMD (SIMDVecReg _) as o1, o2) ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o2
    let n0 = AST.num0 eSize
    let src = transSIMDOprToExpr bld eSize dataSize elements o2
    let result = Array.map (fun e -> AST.ite (e ?> n0) e (AST.neg e)) src
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | TwoOperands (OprSIMD (SIMDFPScalarReg _) as o1, o2) ->
    let struct (eSize, _, _) = getElemDataSzAndElems o1
    let src = transOprToExpr ins bld addr src
    let n0 = AST.num0 eSize
    let result = AST.ite (src ?> n0) src (AST.neg src)
    dstAssignScalar ins bld addr o1 result eSize
  | _ ->
    let n0 = AST.num0 ins.OprSize
    let dst = transOprToExpr ins bld addr dst
    let src = transOprToExpr ins bld addr src
    let result = AST.ite (src ?> n0) src (AST.neg src)
    dstAssign ins.OprSize dst result bld
  bld --!> insLen

let adc ins insLen bld addr =
  let dst, src1, src2 = transThreeOprs ins bld addr
  let c = AST.zext ins.OprSize (regVar bld R.C)
  bld <!-- (ins.Address, insLen)
  let result, _ = addWithCarry src1 src2 c ins.OprSize
  dstAssign ins.OprSize dst result bld
  bld --!> insLen

let adcs ins insLen bld addr =
  let dst, src1, src2 = transThreeOprs ins bld addr
  bld <!-- (ins.Address, insLen)
  let c = tmpVar bld ins.OprSize
  bld <+ (c := AST.zext ins.OprSize (regVar bld R.C))
  let result, (n, z, c, v) = addWithCarry src1 src2 c ins.OprSize
  bld <+ (regVar bld R.N := n)
  bld <+ (regVar bld R.Z := z)
  bld <+ (regVar bld R.C := c)
  bld <+ (regVar bld R.V := v)
  dstAssign ins.OprSize dst result bld
  bld --!> insLen

let add ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | ThreeOperands (OprSIMD (SIMDVecReg _) as o1, o2, o3) ->
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
    let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
    let result = Array.map2 (.+) src1 src2
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | ThreeOperands (o1, _, _) (* SIMD Scalar *) ->
    let _, src1, src2 = transThreeOprs ins bld addr
    let struct (eSize, _, _) = getElemDataSzAndElems o1
    dstAssignScalar ins bld addr o1 (src1 .+ src2) eSize
  | FourOperands _ (* Arithmetic *) ->
    let dst, s1, s2 = transFourOprsWithBarrelShift ins bld addr
    let result, _ = addWithCarry s1 s2 (AST.num0 ins.OprSize) ins.OprSize
    dstAssign ins.OprSize dst result bld
  | _ -> raise InvalidOperandException
  bld --!> insLen

let addp ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | TwoOperands (dst, src) -> (* Scalar *)
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
    let src = transSIMDOprToExpr bld eSize dataSize elements src
    let result = Array.reduce (.+) src
    dstAssignScalar ins bld addr dst result eSize
  | ThreeOperands (dst, src1, src2) -> (* Vector *)
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
    let src2 = transSIMDOprToExpr bld eSize dataSize elements src2
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    Array.append src1 src2 |> Array.chunkBySize 2
    |> Array.map (fun e -> e[0] .+ e[1])
    |> Array.iter2 (fun e1 e2 -> bld <+ (e1 := e2)) result
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | _ -> raise InvalidOperandException
  bld --!> insLen

let adds ins insLen bld addr =
  let dst, src1, src2 = transFourOprsWithBarrelShift ins bld addr
  let oSz = ins.OprSize
  bld <!-- (ins.Address, insLen)
  let result, (n, z, c, v) = addWithCarry src1 src2 (AST.num0 oSz) oSz
  bld <+ (regVar bld R.N := n)
  bld <+ (regVar bld R.Z := z)
  bld <+ (regVar bld R.C := c)
  bld <+ (regVar bld R.V := v)
  dstAssign ins.OprSize dst result bld
  bld --!> insLen

let addv ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
  let src = transSIMDOprToExpr bld eSize dataSize elements src
  let result = Array.reduce (.+) src
  dstAssignScalar ins bld addr dst result eSize
  bld --!> insLen

let adr ins insLen bld addr =
  let dst, label = transTwoOprs ins bld addr
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := getPC bld .+ label)
  bld --!> insLen

let adrp ins insLen bld addr =
  let dst, lbl = transTwoOprs ins bld addr
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := (getPC bld .& numI64 0xfffffffffffff000L 64<rt>) .+ lbl)
  bld --!> insLen

let logAnd ins insLen bld addr = (* AND *)
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | ThreeOperands (OprSIMD (SIMDVecReg _) as dst, src1, src2) ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let struct (src1B, src1A) = transOprToExpr128 ins bld addr src1
    let struct (src2B, src2A) = transOprToExpr128 ins bld addr src2
    bld <+ (dstA := src1A .& src2A)
    if ins.OprSize = 64<rt> then bld <+ (dstB := AST.num0 ins.OprSize)
    else bld <+ (dstB := src1B .& src2B)
  | _ ->
    let dst, src1, src2 = transOprToExprOfAND ins bld addr
    dstAssign ins.OprSize dst (src1 .& src2) bld
  bld --!> insLen

let asrv ins insLen bld addr =
  let dst, src1, src2 = transThreeOprs ins bld addr
  let amount = src2 .% oprSzToExpr ins.OprSize
  bld <!-- (ins.Address, insLen)
  dstAssign ins.OprSize dst (shiftReg src1 amount ins.OprSize SRTypeASR) bld
  bld --!> insLen

let ands ins insLen bld addr =
  let dst, src1, src2 = transOprToExprOfAND ins bld addr
  let result = tmpVar bld ins.OprSize
  bld <!-- (ins.Address, insLen)
  bld <+ (result := src1 .& src2)
  bld <+ (regVar bld R.N := AST.xthi 1<rt> result)
  bld <+ (regVar bld R.Z := (result == AST.num0 ins.OprSize))
  bld <+ (regVar bld R.C := AST.b0)
  bld <+ (regVar bld R.V := AST.b0)
  dstAssign ins.OprSize dst result bld
  bld --!> insLen

let b ins insLen bld addr =
  let label = transOneOpr ins bld addr
  let pc = numU64 (ins:InsInfo).Address bld.RegType
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.interjmp (pc .+ label) InterJmpKind.Base)
  bld --!> insLen

let bCond ins insLen bld addr cond =
  let label = transOneOpr ins bld addr
  let pc = numU64 (ins:InsInfo).Address bld.RegType
  let fall = pc .+ numU32 insLen 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.intercjmp (conditionHolds bld cond) (pc .+ label) fall)
  bld --!> insLen

let bfm ins insLen bld addr dst src immr imms =
  let oSz = ins.OprSize
  let width = oprSzToExpr ins.OprSize
  let struct (wmask, tmask) = decodeBitMasks immr imms (int oSz)
  let dst = transOprToExpr ins bld addr dst
  let src = transOprToExpr ins bld addr src
  let immr = transOprToExpr ins bld addr immr
  bld <!-- (ins.Address, insLen)
  let struct (wMask, tMask) = tmpVars2 bld oSz
  let bot = tmpVar bld ins.OprSize
  bld <+ (wMask := numI64 wmask oSz)
  bld <+ (tMask := numI64 tmask oSz)
  bld <+ (bot := (dst .& AST.not wMask) .| (rorForIR src immr width .& wMask))
  dstAssign ins.OprSize dst ((dst .& AST.not tMask) .| (bot .& tMask)) bld
  bld --!> insLen

let bfi ins insLen bld addr =
  let struct (dst, src, lsb, width) = getFourOprs ins
  let immr =
    ((getImmValue lsb * -1L) &&& 0x3F) % (int64 ins.OprSize) |> OprImm
  let imms = getImmValue width - 1L |> OprImm
  bfm ins insLen bld addr dst src immr imms

let bfxil ins insLen bld addr =
  let struct (dst, src, lsb, width) = getFourOprs ins
  let imms = (getImmValue lsb) + (getImmValue width) - 1L |> OprImm
  bfm ins insLen bld addr dst src lsb imms

let bic ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | ThreeOperands (OprSIMD (SIMDVecReg _), OprSIMD (SIMDVecReg _), _) ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
    let src2 = transSIMDOprToExpr bld eSize dataSize elements src2
    let result = Array.map2 (fun s1 s2 -> s1 .& AST.not s2) src1 src2
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | ThreeOperands (OprSIMD (SIMDVecReg _), OprImm _, OprShift _) ->
    let struct (dst, src, amount) = getThreeOprs ins
    let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let imm =
      transBarrelShiftToExpr ins.OprSize bld src amount
      |> advSIMDExpandImm bld eSize |> AST.not
    dstAssign128 ins bld addr dst (dstA .& imm) (dstB .& imm) dataSize
  | TwoOperands (OprSIMD (SIMDVecReg _), OprImm _) ->
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let src = transOprToExpr ins bld addr src
    let imm = advSIMDExpandImm bld eSize src |> AST.not
    dstAssign128 ins bld addr dst (dstA .& imm) (dstB .& imm) dataSize
  | _ ->
    let dst, src1, src2 = transFourOprsWithBarrelShift ins bld addr
    dstAssign ins.OprSize dst (src1 .& AST.not src2) bld
  bld --!> insLen

let bics ins insLen bld addr =
  let dst, src1, src2 = transFourOprsWithBarrelShift ins bld addr
  let result = tmpVar bld ins.OprSize
  bld <!-- (ins.Address, insLen)
  bld <+ (result := src1 .& AST.not src2)
  bld <+ (regVar bld R.N := AST.xthi 1<rt> result)
  bld <+ (regVar bld R.Z := result == AST.num0 ins.OprSize)
  bld <+ (regVar bld R.C := AST.b0)
  bld <+ (regVar bld R.V := AST.b0)
  dstAssign ins.OprSize dst result bld
  bld --!> insLen

let private bitInsert ins insLen bld addr isTrue =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
  let struct (src1B, src1A) = transOprToExpr128 ins bld addr src1
  let struct (src2B, src2A) = transOprToExpr128 ins bld addr src2
  let struct (opr1A, opr3A, opr4A) = tmpVars3 bld 64<rt>
  let struct (opr1B, opr3B, opr4B) = tmpVars3 bld 64<rt>
  bld <+ (opr1A := dstA)
  bld <+ (opr1B := dstB)
  bld <+ (opr3A := if isTrue then src2A else AST.not src2A)
  bld <+ (opr3B := if isTrue then src2B else AST.not src2B)
  bld <+ (opr4A := src1A)
  bld <+ (opr4B := src1B)
  bld <+ (dstA := AST.xor opr1A ((AST.xor opr1A opr4A) .& opr3A))
  if ins.OprSize = 128<rt> then
    bld <+ (dstB := AST.xor opr1B ((AST.xor opr1B opr4B) .& opr3B))
  else bld <+ (dstB := AST.num0 64<rt>)
  bld --!> insLen

let bif ins insLen bld addr = bitInsert ins insLen bld addr false
let bit ins insLen bld addr = bitInsert ins insLen bld addr true

let bl ins insLen bld addr =
  let label = transOneOpr ins bld addr
  let pc = numU64 (ins:InsInfo).Address bld.RegType
  bld <!-- (ins.Address, insLen)
  bld <+ (regVar bld R.X30 := pc .+ numI64 4L ins.OprSize)
  (* FIXME: BranchTo (BranchType_DIRCALL) *)
  bld <+ (AST.interjmp (pc .+ label) InterJmpKind.IsCall)
  bld --!> insLen

let blr ins insLen bld addr =
  let src = transOneOpr ins bld addr
  let pc = numU64 (ins:InsInfo).Address bld.RegType
  bld <!-- (ins.Address, insLen)
  bld <+ (regVar bld R.X30 := pc .+ numI64 4L ins.OprSize)
  (* FIXME: BranchTo (BranchType_INDCALL) *)
  bld <+ (AST.interjmp src InterJmpKind.IsCall)
  bld --!> insLen

let br ins insLen bld addr =
  let dst = transOneOpr ins bld addr
  bld <!-- (ins.Address, insLen)
  (* FIXME: BranchTo (BranchType_INDIR) *)
  bld <+ (AST.interjmp dst InterJmpKind.Base)
  bld --!> insLen

let bsl ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
  let struct (src1B, src1A) = transOprToExpr128 ins bld addr src1
  let struct (src2B, src2A) = transOprToExpr128 ins bld addr src2
  let struct (opr1A, opr3A, opr4A) = tmpVars3 bld 64<rt>
  let struct (opr1B, opr3B, opr4B) = tmpVars3 bld 64<rt>
  bld <+ (opr1A := src2A)
  bld <+ (opr1B := src2B)
  bld <+ (opr3A := dstA)
  bld <+ (opr3B := dstB)
  bld <+ (opr4A := src1A)
  bld <+ (opr4B := src1B)
  bld <+ (dstA := AST.xor opr1A ((AST.xor opr1A opr4A) .& opr3A))
  if ins.OprSize = 128<rt> then
    bld <+ (dstB := AST.xor opr1B ((AST.xor opr1B opr4B) .& opr3B))
  else bld <+ (dstB := AST.num0 64<rt>)
  bld --!> insLen

let inline private compareBranch ins insLen bld addr cmp =
  let test, label = transTwoOprs ins bld addr
  let pc = numU64 (ins:InsInfo).Address bld.RegType
  let fall = pc .+ numU32 insLen 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.intercjmp (cmp test (AST.num0 ins.OprSize)) (pc .+ label) fall)
  bld --!> insLen

let compareAndSwap ins insLen bld addr =
  let dst, src, mem = transThreeOprs ins bld addr
  let struct (compareVal, newVal, oldVal) = tmpVars3 bld ins.OprSize
  let memVal = tmpVar bld 64<rt>
  let cond = oldVal == compareVal
  bld <!-- (ins.Address, insLen)
  bld <+ (compareVal := dst)
  bld <+ (newVal := src)
  bld <+ (memVal := mem)
  bld <+ (oldVal := memVal |> AST.xtlo ins.OprSize)
  bld <+ (mem := AST.ite cond (newVal |> AST.sext 64<rt>) memVal)
  bld <+ (dst := oldVal |> AST.zext ins.OprSize)
  bld --!> insLen

let cbnz ins insLen bld addr = compareBranch ins insLen bld addr (!=)

let cbz ins insLen bld addr = compareBranch ins insLen bld addr (==)

let ccmn ins insLen bld addr =
  let src, imm, nzcv, cond = transOprToExprOfCCMN ins bld addr
  bld <!-- (ins.Address, insLen)
  let oSz = ins.OprSize
  let tCond = tmpVar bld 1<rt>
  bld <+ (tCond := conditionHolds bld cond)
  let _, (n, z, c, v) = addWithCarry src imm (AST.num0 oSz) oSz
  bld <+ (regVar bld R.N := (AST.ite tCond n (AST.extract nzcv 1<rt> 3)))
  bld <+ (regVar bld R.Z := (AST.ite tCond z (AST.extract nzcv 1<rt> 2)))
  bld <+ (regVar bld R.C := (AST.ite tCond c (AST.extract nzcv 1<rt> 1)))
  bld <+ (regVar bld R.V := (AST.ite tCond v (AST.xtlo 1<rt> nzcv)))
  bld --!> insLen

let ccmp ins insLen bld addr =
  let src, imm, nzcv, cond = transOprToExprOfCCMP ins bld addr
  let oSz = ins.OprSize
  bld <!-- (ins.Address, insLen)
  let tCond = tmpVar bld 1<rt>
  bld <+ (tCond := conditionHolds bld cond)
  let _, (n, z, c, v) = addWithCarry src (AST.not imm) (AST.num1 oSz) oSz
  bld <+ (regVar bld R.N := (AST.ite tCond n (AST.extract nzcv 1<rt> 3)))
  bld <+ (regVar bld R.Z := (AST.ite tCond z (AST.extract nzcv 1<rt> 2)))
  bld <+ (regVar bld R.C := (AST.ite tCond c (AST.extract nzcv 1<rt> 1)))
  bld <+ (regVar bld R.V := (AST.ite tCond v (AST.xtlo 1<rt> nzcv)))
  bld --!> insLen

let private clzBits src bitSize oprSize bld =
  let x = tmpVar bld oprSize
  match oprSize with
  | 8<rt> ->
    let mask1 = numI32 0x55 8<rt>
    let mask2 = numI32 0x33 8<rt>
    let mask3 = numI32 0x0f 8<rt>
    bld <+ (x := src)
    bld <+ (x := x .| (x >> numI32 1 8<rt>))
    bld <+ (x := x .| (x >> numI32 2 8<rt>))
    bld <+ (x := x .| (x >> numI32 4 8<rt>))
    bld <+ (x := x .- ((x >> numI32 1 8<rt>) .& mask1))
    bld <+ (x := ((x >> numI32 2 8<rt>) .& mask2) .+ (x .& mask2))
    bld <+ (x := ((x >> numI32 4 8<rt>) .+ x) .& mask3)
    numI32 bitSize 8<rt> .- (x .& numI32 15 8<rt>)
  | 16<rt> ->
    let mask1 = numI32 0x5555 16<rt>
    let mask2 = numI32 0x3333 16<rt>
    let mask3 = numI32 0x0f0f 16<rt>
    bld <+ (x := src)
    bld <+ (x := x .| (x >> numI32 1 16<rt>))
    bld <+ (x := x .| (x >> numI32 2 16<rt>))
    bld <+ (x := x .| (x >> numI32 4 16<rt>))
    bld <+ (x := x .| (x >> numI32 8 16<rt>))
    bld <+ (x := x .- ((x >> numI32 1 16<rt>) .& mask1))
    bld <+ (x := ((x >> numI32 2 16<rt>) .& mask2) .+ (x .& mask2))
    bld <+ (x := ((x >> numI32 4 16<rt>) .+ x) .& mask3)
    bld <+ (x := x .+ (x >> numI32 8 16<rt>))
    numI32 bitSize 16<rt> .- (x .& numI32 31 16<rt>)
  | 32<rt> ->
    let mask1 = numI32 0x55555555 32<rt>
    let mask2 = numI32 0x33333333 32<rt>
    let mask3 = numI32 0x0f0f0f0f 32<rt>
    bld <+ (x := src)
    bld <+ (x := x .| (x >> numI32 1 32<rt>))
    bld <+ (x := x .| (x >> numI32 2 32<rt>))
    bld <+ (x := x .| (x >> numI32 4 32<rt>))
    bld <+ (x := x .| (x >> numI32 8 32<rt>))
    bld <+ (x := x .| (x >> numI32 16 32<rt>))
    bld <+ (x := x .- ((x >> numI32 1 32<rt>) .& mask1))
    bld <+ (x := ((x >> numI32 2 32<rt>) .& mask2) .+ (x .& mask2))
    bld <+ (x := ((x >> numI32 4 32<rt>) .+ x) .& mask3)
    bld <+ (x := x .+ (x >> numI32 8 32<rt>))
    bld <+ (x := x .+ (x >> numI32 16 32<rt>))
    numI32 bitSize 32<rt> .- (x .& numI32 63 32<rt>)
  | 64<rt> ->
    let mask1 = numU64 0x5555555555555555UL 64<rt>
    let mask2 = numU64 0x3333333333333333UL 64<rt>
    let mask3 = numU64 0x0f0f0f0f0f0f0f0fUL 64<rt>
    bld <+ (x := src)
    bld <+ (x := x .| (x >> numI32 1 64<rt>))
    bld <+ (x := x .| (x >> numI32 2 64<rt>))
    bld <+ (x := x .| (x >> numI32 4 64<rt>))
    bld <+ (x := x .| (x >> numI32 8 64<rt>))
    bld <+ (x := x .| (x >> numI32 16 64<rt>))
    bld <+ (x := x .| (x >> numI32 32 64<rt>))
    bld <+ (x := x .- ((x >> numI32 1 64<rt>) .& mask1))
    bld <+ (x := ((x >> numI32 2 64<rt>) .& mask2) .+ (x .& mask2))
    bld <+ (x := ((x >> numI32 4 64<rt>) .+ x) .& mask3)
    bld <+ (x := x .+ (x >> numI32 8 64<rt>))
    bld <+ (x := x .+ (x >> numI32 16 64<rt>))
    bld <+ (x := x .+ (x >> numI32 32 64<rt>))
    numI32 bitSize 64<rt> .- (x .& numI32 127 64<rt>)
  | _ -> raise InvalidOperandSizeException

let private clsBits src oprSize bld =
  let n1 = AST.num1 oprSize
  let struct (expr1, expr2, xExpr) = tmpVars3 bld oprSize
  bld <+ (expr1 := src >> n1)
  bld <+ (expr2 := (src << n1) >> n1)
  bld <+ (xExpr := (expr1 <+> expr2))
  let bitSize = int oprSize - 1
  clzBits xExpr bitSize oprSize bld

let cls ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | TwoOperands (OprSIMD (SIMDVecReg _) as o1, o2) ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o2
    let src = transSIMDOprToExpr bld eSize dataSize elements o2
    let result = Array.map (fun e -> clsBits e eSize bld ) src
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | _ ->
    let dst, src = transTwoOprs ins bld addr
    let result = clsBits src ins.OprSize bld
    dstAssign ins.OprSize dst result bld
  bld --!> insLen

let clz ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | TwoOperands (OprSIMD (SIMDVecReg _) as o1, o2) ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o2
    let src = transSIMDOprToExpr bld eSize dataSize elements o2
    let result = Array.map (fun e -> clzBits e (int eSize) eSize bld ) src
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | _ ->
    let dst, src = transTwoOprs ins bld addr
    let result = clzBits src (int ins.OprSize) ins.OprSize bld
    dstAssign ins.OprSize dst result bld
  bld --!> insLen

let cmn ins insLen bld addr =
  let src1, src2 = transThreeOprsWithBarrelShift ins bld addr
  let oSz = ins.OprSize
  bld <!-- (ins.Address, insLen)
  let _, (n, z, c, v) = addWithCarry src1 src2 (AST.num0 oSz) oSz
  bld <+ (regVar bld R.N := n)
  bld <+ (regVar bld R.Z := z)
  bld <+ (regVar bld R.C := c)
  bld <+ (regVar bld R.V := v)
  bld --!> insLen

let cmp ins insLen bld addr =
  let src1, src2 = transOprToExprOfCMP ins bld addr
  let oSz = ins.OprSize
  bld <!-- (ins.Address, insLen)
  let _, (n, z, c, v) = addWithCarry src1 (AST.not src2) (AST.num1 oSz) oSz
  bld <+ (regVar bld R.N := n)
  bld <+ (regVar bld R.Z := z)
  bld <+ (regVar bld R.C := c)
  bld <+ (regVar bld R.V := v)
  bld --!> insLen

let private compare ins insLen bld addr cond =
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  (* zero *)
  | ThreeOperands (OprSIMD (SIMDVecReg _) as o1, o2, OprImm _) ->
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
    let struct (ones, zeros) = tmpVars2 bld eSize
    bld <+ (ones := numI64 -1L eSize)
    bld <+ (zeros := AST.num0 eSize)
    let result = Array.map (fun e -> AST.ite (cond e zeros) ones zeros) src1
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | ThreeOperands (OprSIMD (SIMDFPScalarReg _) as o1, o2, OprImm _) ->
    let struct (eSize, _, _) = getElemDataSzAndElems o1
    let src1 = transOprToExpr ins bld addr o2
    let num0 = AST.num0 64<rt>
    let result = tmpVar bld 64<rt>
    bld <+ (result := AST.ite (cond src1 num0) (numI64 -1L 64<rt>) num0)
    dstAssignScalar ins bld addr o1 result eSize
  (* register *)
  | ThreeOperands (OprSIMD (SIMDVecReg _) as o1, o2, o3) ->
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
    let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
    let struct (ones, zeros) = tmpVars2 bld eSize
    bld <+ (ones := numI64 -1L eSize)
    bld <+ (zeros := AST.num0 eSize)
    let result =
      Array.map2 (fun e1 e2 -> AST.ite (cond e1 e2) ones zeros) src1 src2
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | ThreeOperands (OprSIMD (SIMDFPScalarReg _) as o1, o2, o3) ->
    let struct (eSize, _, _) = getElemDataSzAndElems o1
    let src1 = transOprToExpr ins bld addr o2
    let src2 = transOprToExpr ins bld addr o3
    let num0 = AST.num0 64<rt>
    let result = tmpVar bld 64<rt>
    bld <+ (result := AST.ite (cond src1 src2) (numI64 -1L 64<rt>) num0)
    dstAssignScalar ins bld addr o1 result eSize
  | _ -> raise InvalidOperandException
  bld --!> insLen

let cmeq ins insLen bld addr = compare ins insLen bld addr (==)
let cmgt ins insLen bld addr = compare ins insLen bld addr (?>)
let cmge ins insLen bld addr = compare ins insLen bld addr (?>=)

let private cmpHigher ins insLen bld addr cond =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  let struct (ones, zeros) = tmpVars2 bld eSize
  bld <+ (ones := numI64 -1 eSize)
  bld <+ (zeros := AST.num0 eSize)
  match dst with
  | OprSIMD (SIMDFPScalarReg _) ->
    let _, src1, src2 = transThreeOprs ins bld addr
    let result = AST.ite (cond src1 src2) ones zeros
    dstAssignScalar ins bld addr dst result eSize
  | _ ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
    let src2 = transSIMDOprToExpr bld eSize dataSize elements src2
    let result =
      Array.map2 (fun e1 e2 -> AST.ite (cond e1 e2) ones zeros) src1 src2
    dstAssignForSIMD dstA dstB result dataSize elements bld
  bld --!> insLen

let cmhi ins insLen bld addr = cmpHigher ins insLen bld addr (.>)
let cmhs ins insLen bld addr = cmpHigher ins insLen bld addr (.>=)

let cmlt ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, _) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  let struct (ones, zeros) = tmpVars2 bld eSize
  bld <+ (ones := numI64 -1 eSize)
  bld <+ (zeros := AST.num0 eSize)
  match dst with
  | OprSIMD (SIMDFPScalarReg _) ->
    let src1 = transOprToExpr ins bld addr src1
    let result = AST.ite (src1 ?< zeros) ones zeros
    dstAssignScalar ins bld addr dst result eSize
  | _ ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
    let result = Array.map (fun e -> AST.ite (e ?< zeros) ones zeros) src1
    dstAssignForSIMD dstA dstB result dataSize elements bld
  bld --!> insLen

let cmtst ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  let struct (ones, zeros) = tmpVars2 bld eSize
  bld <+ (ones := numI64 -1 eSize)
  bld <+ (zeros := AST.num0 eSize)
  match dst with
  | OprSIMD (SIMDFPScalarReg _) ->
    let _, src1, src2 = transThreeOprs ins bld addr
    let result = AST.ite ((src1 .& src2) != zeros) ones zeros
    dstAssignScalar ins bld addr dst result eSize
  | _ ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let s1 = transSIMDOprToExpr bld eSize dataSize elements src1
    let s2 = transSIMDOprToExpr bld eSize dataSize elements src2
    let result =
      Array.map2 (fun e1 e2 -> AST.ite ((e1 .& e2) != zeros) ones zeros) s1 s2
    dstAssignForSIMD dstA dstB result dataSize elements bld
  bld --!> insLen

let cnt ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
  let src = transSIMDOprToExpr bld eSize dataSize elements src
  let result = Array.map (bitCount eSize) src
  dstAssignForSIMD dstA dstB result dataSize elements bld
  bld --!> insLen

let csel ins insLen bld addr =
  let dst, s1, s2, cond = transOprToExprOfCSEL ins bld addr
  bld <!-- (ins.Address, insLen)
  dstAssign ins.OprSize dst (AST.ite (conditionHolds bld cond) s1 s2) bld
  bld --!> insLen

let csinc ins insLen bld addr =
  let dst, s1, s2, cond = transOprToExprOfCSINC ins bld addr
  bld <!-- (ins.Address, insLen)
  let oprSize = ins.OprSize
  let cond = conditionHolds bld cond
  dstAssign oprSize dst (AST.ite cond s1 (s2 .+ AST.num1 oprSize)) bld
  bld --!> insLen

let csinv ins insLen bld addr =
  let dst, src1, src2, cond = transOprToExprOfCSINV ins bld addr
  bld <!-- (ins.Address, insLen)
  let cond = conditionHolds bld cond
  dstAssign ins.OprSize dst (AST.ite cond src1 (AST.not src2)) bld
  bld --!> insLen

let csneg ins insLen bld addr =
  let dst, s1, s2, cond = transOprToExprOfCSNEG ins bld addr
  bld <!-- (ins.Address, insLen)
  let s2 = AST.not s2 .+ AST.num1 ins.OprSize
  dstAssign ins.OprSize dst (AST.ite (conditionHolds bld cond) s1 s2) bld
  bld --!> insLen

let ctz ins insLen bld addr =
  let dst, src = transTwoOprs ins bld addr
  bld <!-- (ins.Address, insLen)
  let revSrc = tmpVar bld ins.OprSize
  bld <+ (revSrc := bitReverse src ins.OprSize)
  let res = countLeadingZeroBitsForIR revSrc (int ins.OprSize) ins.OprSize bld
  dstAssign ins.OprSize dst res bld
  bld --!> insLen

let dczva ins insLen bld addr =
  let src = transOneOpr ins bld addr
  let dczid = regVar bld R.DCZIDEL0
  let struct (idx, n4, len) = tmpVars3 bld 64<rt>
  let lblLoop = label bld "Loop"
  let lblLoopCont = label bld "LoopContinue"
  let lblEnd = label bld "End"
  bld <!-- (ins.Address, insLen)
  bld <+ (idx := AST.num0 64<rt>)
  bld <+ (n4 := numI32 4 64<rt>)
  bld <+ (len := (numI32 2 64<rt> << (dczid .+ numI32 1 64<rt>)))
  bld <+ (len := len ./ n4)
  bld <+ (AST.lmark lblLoop)
  bld <+ (AST.cjmp (idx == len) (AST.jmpDest lblEnd) (AST.jmpDest lblLoopCont))
  bld <+ (AST.lmark lblLoopCont)
  bld <+ (AST.loadLE 32<rt> (src .+ (idx .* n4)) := AST.num0 32<rt>)
  bld <+ (idx := idx .+ AST.num1 64<rt>)
  bld <+ (AST.jmp (AST.jmpDest lblLoop))
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let dup ins insLen bld addr =
  let struct (dst, src) = getTwoOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
  let src = transOprToExpr ins bld addr src
  let element = tmpVar bld eSize
  let result = Array.init elements (fun _ -> tmpVar bld eSize)
  bld <!-- (ins.Address, insLen)
  bld <+ (element := AST.xtlo eSize src)
  Array.iter (fun e -> bld <+ (e := element)) result
  dstAssignForSIMD dstA dstB result dataSize elements bld
  bld --!> insLen

let eor ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | ThreeOperands (OprSIMD (SIMDVecReg _) as o1, o2, o3) ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let struct (src1B, src1A) = transOprToExpr128 ins bld addr o2
    let struct (src2B, src2A) = transOprToExpr128 ins bld addr o3
    let struct (opr2, opr3) = tmpVars2 bld 64<rt>
    bld <+ (opr2 := AST.num0 64<rt>)
    bld <+ (opr3 := numI64 -1 64<rt>)
    bld <+ (dstA := src2A <+> ((opr2 <+> src1A) .& opr3))
    if ins.OprSize = 64<rt> then bld <+ (dstB := AST.num0 ins.OprSize)
    else bld <+ (dstB := src2B <+> ((opr2 <+> src1B) .& opr3))
  | _ ->
    let dst, src1, src2 = transOprToExprOfEOR ins bld addr
    dstAssign ins.OprSize dst (src1 <+> src2) bld
  bld --!> insLen

let ext ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2, idx) = getFourOprs ins
  let pos = getImmValue idx |> int
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
  let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
  let src2 = transSIMDOprToExpr bld eSize dataSize elements src2
  let result = Array.init elements (fun _ -> tmpVar bld eSize)
  let concat = Array.append src1 src2
  let res = Array.sub concat pos (dataSize / eSize)
  Array.iter2 (fun res s -> bld <+ (res := s)) result res
  dstAssignForSIMD dstA dstB result dataSize elements bld
  bld --!> insLen

let extr ins insLen bld addr =
  let dst, src1, src2, lsb = transOprToExprOfEXTR ins bld addr
  let oSz = ins.OprSize
  bld <!-- (ins.Address, insLen)
  if oSz = 32<rt> then
    let con = tmpVar bld 64<rt>
    bld <+ (con := AST.concat src1 src2)
    let mask = numI64 0xFFFFFFFFL 64<rt>
    dstAssign ins.OprSize dst ((con >> (AST.zext 64<rt> lsb)) .& mask) bld
  elif oSz = 64<rt> then
    let lsb =
      match ins.Operands with
      | ThreeOperands (_, _, OprLSB shift) -> int32 shift
      | FourOperands (_, _, _, OprLSB lsb) -> int32 lsb
      | _ -> raise InvalidOperandException
    if lsb = 0 then bld <+ (dst := src2)
    else
      let leftAmt = numI32 (64 - lsb) 64<rt>
      bld <+ (dst := (src1 << leftAmt) .| (src2 >> (numI32 lsb 64<rt>)))
  else raise InvalidOperandSizeException
  bld --!> insLen

let fabd ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  let n1 = tmpVar bld eSize
  bld <+ (n1 := AST.num1 eSize)
  let fpAbsDiff e1 e2 = ((fpSub bld eSize e1 e2) << n1) >> n1
  match dst with
  | OprSIMD (SIMDFPScalarReg _) ->
    let _, src1, src2 = transThreeOprs ins bld addr
    dstAssignScalar ins bld addr dst (fpAbsDiff src1 src2) eSize
  | OprSIMD (SIMDVecReg _) ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
    let src2 = transSIMDOprToExpr bld eSize dataSize elements src2
    let result = Array.map2 (fpAbsDiff) src1 src2
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | _ -> raise InvalidOperandException
  bld --!> insLen

let fabs ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  let n1 = tmpVar bld eSize
  bld <+ (n1 := AST.num1 eSize)
  match dst with
  | OprSIMD (SIMDFPScalarReg _) ->
    let src = transOprToExpr ins bld addr src
    dstAssignScalar ins bld addr dst ((src << n1) >> n1) eSize
  | OprSIMD (SIMDVecReg _) ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let src = transSIMDOprToExpr bld eSize dataSize elements src
    let result = Array.map (fun e -> (e << n1) >> n1) src
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | _ -> raise InvalidOperandException
  bld --!> insLen

let fadd ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  match dst with
  | OprSIMD (SIMDFPScalarReg _) ->
    let _, src1, src2 = transThreeOprs ins bld addr
    let result = fpAdd bld dataSize src1 src2
    dstAssignScalar ins bld addr dst result eSize
  | OprSIMD (SIMDVecReg _) ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
    let src2 = transSIMDOprToExpr bld eSize dataSize elements src2
    let result = Array.map2 (fpAdd bld eSize) src1 src2
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | _ -> raise InvalidOperandException
  bld --!> insLen

let faddp ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | TwoOperands (dst, src) -> (* Scalar *)
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
    let src = transSIMDOprToExpr bld eSize dataSize elements src
    let result =
      Array.chunkBySize 2 src
      |> Array.map (fun e -> fpAdd bld eSize e[0] e[1])
      |> Array.reduce(.+)
    dstAssignScalar ins bld addr dst result eSize
  | ThreeOperands (dst, src1, src2) -> (* Vector *)
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
    let src2 = transSIMDOprToExpr bld eSize dataSize elements src2
    let concat = Array.append src1 src2
    let result =
      Array.chunkBySize 2 concat
      |> Array.map (fun e -> fpAdd bld eSize e[0] e[1])
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | _ -> raise InvalidOperandException
  bld --!> insLen

let private fpneg reg eSize =
  let mask =
    match eSize with
    | 16<rt> -> numU64 0x8000UL eSize (* ARMv8.2 *)
    | 32<rt> -> numU64 0x80000000UL eSize
    | 64<rt> -> numU64 0x8000000000000000UL eSize
    | _ -> raise InvalidOperandSizeException
  reg <+> mask

let private checkZero bld dataSize fpVal =
  let isFZ = (regVar bld R.FPCR >> numI32 24 64<rt>) |> AST.xtlo 1<rt>
  let struct (n0, f0) = tmpVars2 bld dataSize
  bld <+ (n0 := AST.num0 dataSize)
  bld <+ (f0 := fpZero fpVal dataSize)
  let inline isOnes exp =
    match dataSize with
    | 32<rt> -> exp == numI32 0xFF 32<rt>
    | 64<rt> -> exp == numI32 0x7FF 64<rt>
    | _ -> raise InvalidOperandSizeException
  let struct (exp, frac) = tmpVars2 bld dataSize
  match dataSize with
  | 32<rt> ->
    bld <+ (exp := (fpVal >> numI32 23 32<rt>) .& numI32 0xff 32<rt>)
    bld <+ (frac := fpVal .& numU32 0x7fffffu 32<rt>)
  | 64<rt> ->
    bld <+ (exp := (fpVal >> numI64 52 64<rt>) .& numI64 0x7ff 64<rt>)
    bld <+ (frac := fpVal .& numU64 0xfffffffffffffUL 64<rt>)
  | _ -> raise InvalidOperandSizeException
  AST.ite ((exp == n0) .& (frac == n0 .| isFZ)) f0
    (AST.ite ((isOnes exp) .& (frac != n0)) f0 fpVal)

let private fpCompare bld oprSz src1 src2 =
  let struct (v1, v2) = tmpVars2 bld oprSz
  let isOpNaN = tmpVar bld 1<rt>
  let result = tmpVar bld 8<rt>
  bld <+ (v1 := checkZero bld oprSz src1)
  bld <+ (v2 := checkZero bld oprSz src2)
  let lblOpNaN = label bld "OpNaN"
  let lblCmp = label bld "Cmp"
  let lblEq = label bld "Eq"
  let lblNeq = label bld "Neq"
  let lblEnd = label bld "End"
  bld <+ (isOpNaN := isNaN oprSz src1 .| isNaN oprSz src2)
  bld <+ (AST.cjmp isOpNaN (AST.jmpDest lblOpNaN) (AST.jmpDest lblCmp))
  bld <+ (AST.lmark lblOpNaN)
  bld <+ (result := numI32 0b0011 8<rt>)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblCmp)
  bld <+ (AST.cjmp (AST.feq v1 v2) (AST.jmpDest lblEq) (AST.jmpDest lblNeq))
  bld <+ (AST.lmark lblEq)
  bld <+ (result := numI32 0b110 8<rt>)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblNeq)
  let cond = AST.flt v1 v2
  bld <+ (result := AST.ite cond (numI32 0b1000 8<rt>) (numI32 0b0010 8<rt>))
  bld <+ (AST.lmark lblEnd)
  result

let fcmp ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let src1, src2 = transTwoOprs ins bld addr
  let flags = tmpVar bld 8<rt>
  bld <+ (flags := fpCompare bld ins.OprSize src1 src2)
  bld <+ (regVar bld R.N := AST.extract flags 1<rt> 3)
  bld <+ (regVar bld R.Z := AST.extract flags 1<rt> 2)
  bld <+ (regVar bld R.C := AST.extract flags 1<rt> 1)
  bld <+ (regVar bld R.V := AST.extract flags 1<rt> 0)
  bld --!> insLen

let fccmp ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let src1, src2, nzcv, cond = transOprToExprOfCCMP ins bld addr
  let flags = tmpVar bld 8<rt>
  let comp = fpCompare bld ins.OprSize src1 src2
  bld <+ (flags := AST.ite (conditionHolds bld cond) comp (AST.xtlo 8<rt> nzcv))
  bld <+ (regVar bld R.N := AST.extract flags 1<rt> 3)
  bld <+ (regVar bld R.Z := AST.extract flags 1<rt> 2)
  bld <+ (regVar bld R.C := AST.extract flags 1<rt> 1)
  bld <+ (regVar bld R.V := AST.extract flags 1<rt> 0)
  bld --!> insLen

let fcmgt ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  let struct (ones, zeros) = tmpVars2 bld eSize
  let chkNan e1 e2 = (isNaN eSize e1) .| (isNaN eSize e2)
  let fpgt e1 e2 =
    AST.fgt (checkZero bld eSize e1) (checkZero bld eSize e2)
  bld <+ (ones := numI64 -1 eSize)
  bld <+ (zeros := AST.num0 eSize)
  match dst, src2 with
  | OprSIMD (SIMDFPScalarReg _) as o1, _ ->
    let _, src1, src2 = transThreeOprs ins bld addr
    let cond = chkNan src1 src2
    let result = AST.ite cond zeros (AST.ite (fpgt src1 src2) ones zeros)
    dstAssignScalar ins bld addr o1 result eSize
  | OprSIMD (SIMDVecReg _), OprFPImm _ ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
    let src2 = transOprToExpr ins bld addr src2 |> AST.xtlo eSize
    let result =
      Array.map (fun e ->
        AST.ite (chkNan e src2) zeros (AST.ite (fpgt e src2) ones zeros)) src1
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | OprSIMD (SIMDVecReg _), _ ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let s1 = transSIMDOprToExpr bld eSize dataSize elements src1
    let s2 = transSIMDOprToExpr bld eSize dataSize elements src2
    let result =
      Array.map2 (fun e1 e2 ->
        AST.ite (chkNan e1 e2) zeros (AST.ite (fpgt e1 e2) ones zeros)) s1 s2
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | _ -> raise InvalidOperandException
  bld --!> insLen

let fcsel ins insLen bld addr =
  let o1, s1, s2, cond = transOprToExprOfFCSEL ins bld addr
  let struct (eSize, _, _) = getElemDataSzAndElems o1
  let fs1 = AST.cast CastKind.FloatCast ins.OprSize s1
  let fs2 = AST.cast CastKind.FloatCast ins.OprSize s2
  bld <!-- (ins.Address, insLen)
  let result = AST.ite (conditionHolds bld cond) fs1 fs2
  dstAssignScalar ins bld addr o1 result eSize
  bld --!> insLen

let fcvt ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | TwoOperands (OprSIMD (SIMDFPScalarReg _) as o1, o2) ->
    let struct (eSize, _, _) = getElemDataSzAndElems o1
    let src = transOprToExpr ins bld addr o2
    let result = AST.cast CastKind.FloatCast eSize src
    dstAssignScalar ins bld addr o1 result eSize
  | _ ->
    let dst, src = transTwoOprs ins bld addr
    let oprSize = ins.OprSize
    dstAssign oprSize dst (AST.cast CastKind.FloatCast oprSize src) bld
  bld --!> insLen

let private fpConvert ins insLen bld addr isUnsigned round =
  let isNeg e = AST.xthi 1<rt> e == AST.b1
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  (* vector *)
  | TwoOperands (OprSIMD (SIMDVecReg _) as o1, o2) ->
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let src = transSIMDOprToExpr bld eSize dataSize elements o2
    let n0 = AST.num0 eSize
    let fcvt e = fpToFixed eSize e (AST.num0 eSize) isUnsigned round bld
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    Array.iter2 (fun res e -> if isUnsigned then
                                bld <+ (res := AST.ite (isNeg e) n0 (fcvt e))
                              else bld <+ (res := fcvt e)) result src
    dstAssignForSIMD dstA dstB result dataSize elements bld
  (* vector #<fbits> *)
  | ThreeOperands (OprSIMD (SIMDVecReg _) as o1, o2, OprFbits fbits) ->
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let src = transSIMDOprToExpr bld eSize dataSize elements o2
    let n0 = AST.num0 eSize
    let fbits = numI32 (int fbits) eSize
    let fcvt e = fpToFixed eSize e fbits isUnsigned round bld
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    Array.iter2 (fun res e -> if isUnsigned then
                                bld <+ (res := AST.ite (isNeg e) n0 (fcvt e))
                              else bld <+ (res := fcvt e)) result src
    dstAssignForSIMD dstA dstB result dataSize elements bld
  (* scalar *)
  | TwoOperands (OprSIMD (SIMDFPScalarReg _) as o1, o2) ->
    let src = transOprToExpr ins bld addr o2
    let n0 = AST.num0 ins.OprSize
    let fcvt = fpToFixed ins.OprSize src n0 isUnsigned round bld
    let result = if isUnsigned then AST.ite (isNeg src) n0 fcvt else fcvt
    dstAssignScalar ins bld addr o1 result ins.OprSize
  (* scalar #<fbits> *)
  | ThreeOperands (OprSIMD (SIMDFPScalarReg _) as o1, _, OprFbits _) ->
    let _, src, fbits = transThreeOprs ins bld addr
    let n0 = AST.num0 ins.OprSize
    let fcvt = fpToFixed ins.OprSize src fbits isUnsigned round bld
    let result = if isUnsigned then AST.ite (isNeg src) n0 fcvt else fcvt
    dstAssignScalar ins bld addr o1 result ins.OprSize
  (* float *)
  | TwoOperands (OprRegister _, _) ->
    let dst, src = transTwoOprs ins bld addr
    let n0 = AST.num0 ins.OprSize
    let fcvt = fpToFixed ins.OprSize src n0 isUnsigned round bld
    let result = if isUnsigned then AST.ite (isNeg src) n0 fcvt else fcvt
    dstAssign ins.OprSize dst result bld
  (* float #<fbits> *)
  | ThreeOperands (OprRegister _, _, OprFbits _) ->
    let dst, src, fbits = transThreeOprs ins bld addr
    let n0 = AST.num0 ins.OprSize
    let fcvt = fpToFixed ins.OprSize src fbits isUnsigned round bld
    let result = if isUnsigned then AST.ite (isNeg src) n0 fcvt else fcvt
    dstAssign ins.OprSize dst result bld
  | _ -> raise InvalidOperandException
  bld --!> insLen

let fcvtas ins insLen bld addr =
  fpConvert ins insLen bld addr false FPRounding_TIEAWAY
let fcvtau ins insLen bld addr =
  fpConvert ins insLen bld addr true FPRounding_TIEAWAY

let fcvtms ins insLen bld addr =
  fpConvert ins insLen bld addr false FPRounding_NEGINF
let fcvtmu ins insLen bld addr =
  fpConvert ins insLen bld addr true FPRounding_NEGINF

let fcvtps ins insLen bld addr =
  fpConvert ins insLen bld addr false FPRounding_POSINF
let fcvtpu ins insLen bld addr =
  fpConvert ins insLen bld addr true FPRounding_POSINF

let fcvtzs ins insLen bld addr =
  fpConvert ins insLen bld addr false FPRounding_Zero
let fcvtzu ins insLen bld addr =
  fpConvert ins insLen bld addr true FPRounding_Zero

let fdiv ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  match dst with
  | OprSIMD (SIMDFPScalarReg _) ->
    let _, src1, src2 = transThreeOprs ins bld addr
    let result = fpDiv bld dataSize src1 src2
    dstAssignScalar ins bld addr dst result eSize
  | OprSIMD (SIMDVecReg _) ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
    let src2 = transSIMDOprToExpr bld eSize dataSize elements src2
    let result = Array.map2 (fpDiv bld eSize) src1 src2
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | _ -> raise InvalidOperandException
  bld --!> insLen

let fmadd ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, _, _, _) = getFourOprs ins
  let struct (eSize, _, _) = getElemDataSzAndElems dst
  let _, src1, src2, src3 = transFourOprs ins bld addr
  let result = (fpAdd bld eSize src3 (fpMul bld eSize src1 src2))
  dstAssignScalar ins bld addr dst result eSize
  bld --!> insLen

let fmaxmin ins insLen bld addr fop =
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | ThreeOperands (OprSIMD (SIMDFPScalarReg _) as o1, o2, o3) ->
    let struct (eSize, _, _) = getElemDataSzAndElems o1
    let src1 = transOprToExpr ins bld addr o2
    let src2 = transOprToExpr ins bld addr o3
    let cond = fop src1 src2
    let result = AST.ite cond src1 src2
    dstAssignScalar ins bld addr o1 result eSize
  | _ ->
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
    let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    let inline cond e1 e2 =
      let src1 = AST.cast CastKind.FloatCast eSize e1
      let src2 = AST.cast CastKind.FloatCast eSize e2
      AST.ite (fop src1 src2) src1 src2
    Array.iteri2 (fun i e1 e2 -> bld <+ (result[i] := cond e1 e2)) src1 src2
    dstAssignForSIMD dstA dstB result dataSize elements bld
  bld --!> insLen

let fmls ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | ThreeOperands (OprSIMD (SIMDFPScalarReg _) as o1, o2, o3) ->
    let struct (eSize, _, _) = getElemDataSzAndElems o1
    let dst = transOprToExpr ins bld addr o1
    let src1 = transOprToExpr ins bld addr o2
    let src2 = transOprToExpr ins bld addr o3
    let element1 = fpneg src1 eSize
    let result = fpAdd bld eSize dst (fpMul bld eSize element1 src2)
    dstAssignScalar ins bld addr o1 result eSize
  | ThreeOperands (o1, o2, (OprSIMD (SIMDVecRegWithIdx _) as o3)) ->
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
    let src2 = transOprToExpr ins bld addr o3
    let src3 = transSIMDOprToExpr bld eSize dataSize elements o1
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    Array.iteri2 (fun i e1 e3 ->
      let e1 = fpneg e1 eSize
      let res = fpAdd bld eSize e3 (fpMul bld eSize e1 src2)
      bld <+ (result[i] := res)) src1 src3
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | _ ->
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
    let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
    let src3 = transSIMDOprToExpr bld eSize dataSize elements o1
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    Array.map3 (fun e1 e2 e3 ->
      let e1 = fpneg e1 eSize
      fpAdd bld eSize e3 (fpMul bld eSize e1 e2)) src1 src2 src3
    |> Array.iter2 (fun r e -> bld <+ (r := e)) result
    dstAssignForSIMD dstA dstB result dataSize elements bld
  bld --!> insLen

let fmov ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | TwoOperands (OprRegister _, OprSIMD (SIMDVecRegWithIdx _)) ->
    let struct (dst, src) = getTwoOprs ins
    let dst = transOprToExpr ins bld addr dst
    let struct (srcB, _) = transOprToExpr128 ins bld addr src
    dstAssign ins.OprSize dst srcB bld
  | TwoOperands (OprSIMD (SIMDVecRegWithIdx _), OprRegister _) ->
    let struct (dst, src) = getTwoOprs ins
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let src = transOprToExpr ins bld addr src
    bld <+ (dstA := dstA)
    bld <+ (dstB := src)
  | TwoOperands (OprSIMD (SIMDVecReg _), OprFPImm _) ->
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
    let src =
      if eSize <> 64<rt> then
        transOprToExprFPImm ins eSize src |> advSIMDExpandImm bld eSize
      else transOprToExprFPImm ins eSize src |> AST.xtlo 64<rt>
    dstAssign128 ins bld addr dst src src dataSize
  | TwoOperands (OprSIMD (SIMDFPScalarReg _), _) ->
    let struct (dst, src) = getTwoOprs ins
    let struct (_, dataSize, _) = getElemDataSzAndElems dst
    let src = transOprToExpr ins bld addr src
    dstAssignScalar ins bld addr dst src dataSize
  | _ ->
    let dst, src = transTwoOprs ins bld addr
    dstAssign ins.OprSize dst src bld
  bld --!> insLen

let fmsub ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, _, _, _) = getFourOprs ins
  let struct (eSize, _, _) = getElemDataSzAndElems dst
  let _, src1, src2, src3 = transFourOprs ins bld addr
  let result = (fpSub bld eSize src3 (fpMul bld eSize src1 src2))
  dstAssignScalar ins bld addr dst result eSize
  bld --!> insLen

let fmul ins insLen bld addr =
  let struct (dst, src1, src2) = getThreeOprs ins
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | ThreeOperands (OprSIMD (SIMDFPScalarReg _) as o1, o2, o3) ->
    let struct (eSize, _, _) = getElemDataSzAndElems o2
    let src1 = transOprToExpr ins bld addr o2
    let src2 = transOprToExpr ins bld addr o3
    dstAssignScalar ins bld addr o1 (fpMul bld eSize src1 src2) eSize
  | ThreeOperands (OprSIMD (SIMDVecReg _), _, OprSIMD (SIMDVecReg _) ) ->
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
    let src2 = transSIMDOprToExpr bld eSize dataSize elements src2
    let result = Array.map2 (fpMul bld eSize) src1 src2
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | _ ->
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems src1
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
    let src2 = transOprToExpr ins bld addr src2
    let result = Array.map (fun src -> fpMul bld eSize src src2) src1
    dstAssignForSIMD dstA dstB result dataSize elements bld
  bld --!> insLen

let fneg ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | TwoOperands (OprSIMD (SIMDFPScalarReg _) as dst, src) ->
    let struct (eSize, _, _) = getElemDataSzAndElems src
    let src = transOprToExpr ins bld addr src
    let t = tmpVar bld eSize
    bld <+ (t := fpneg src eSize)
    dstAssignScalar ins bld addr dst t ins.OprSize
  | TwoOperands (OprSIMD (SIMDVecReg _) as dst, src) ->
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let src = transSIMDOprToExpr bld eSize dataSize elements src
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    Array.iter2 (fun dst src -> bld <+ (dst := fpneg src eSize)) result src
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | _ -> raise InvalidOperandException
  bld --!> insLen

let fnmsub ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, _, _, src) = getFourOprs ins
  let _, src1, src2, src3 = transFourOprs ins bld addr
  let struct (eSize, _, _) = getElemDataSzAndElems src
  let t = tmpVar bld eSize
  bld <+ (t := fpneg src3 eSize)
  let result = fpAdd bld eSize t (fpMul bld eSize src1 src2)
  dstAssignScalar ins bld addr dst result ins.OprSize
  bld --!> insLen

let fnmul ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, _, src) = getThreeOprs ins
  let _, src1, src2 = transThreeOprs ins bld addr
  let struct (eSize, _, _) = getElemDataSzAndElems src
  let result = tmpVar bld eSize
  bld <+ (result := fpMul bld eSize src1 src2)
  bld <+ (result := fpneg result eSize)
  dstAssignScalar ins bld addr dst result ins.OprSize
  bld --!> insLen

let getIntRoundMode src oprSz bld =
  let fpcr = regVar bld R.FPCR |> AST.xtlo 32<rt>
  let rm = AST.shr (AST.shl fpcr (numI32 8 32<rt>)) (numI32 0x1E 32<rt>)
  AST.ite (rm == numI32 0 32<rt>)
    (AST.cast CastKind.FtoIRound oprSz src) (* 0, RN *)
    (AST.ite (rm == numI32 1 32<rt>)
      (AST.cast CastKind.FtoICeil oprSz src) (* 1, RZ *)
      (AST.ite (rm == numI32 2 32<rt>)
        (AST.cast CastKind.FtoIFloor oprSz src) (* 2, RP *)
        (AST.cast CastKind.FtoITrunc oprSz src))) (* 3, RM *)

let private fpType bld cast eSize element =
  let res = tmpVar bld eSize
  let struct (checkNan, checkInf) = tmpVars2 bld 1<rt>
  let lblNan = label bld "NaN"
  let lblCon = label bld "Continue"
  let lblEnd = label bld "End"
  bld <+ (checkNan := isNaN eSize element)
  bld <+ (checkInf := isInfinity eSize element)
  bld <+ (AST.cjmp (checkNan .| checkInf)
                 (AST.jmpDest lblNan) (AST.jmpDest lblCon))
  bld <+ (AST.lmark lblNan)
  let fpNaN = fpProcessNan bld eSize element
  bld <+ (res := AST.ite checkNan fpNaN (fpDefaultInfinity element eSize))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblCon)
  let castElem = AST.cast cast eSize element
  bld <+ (res := AST.ite (isZero eSize element) (fpZero element eSize) castElem)
  bld <+ (AST.lmark lblEnd)
  res

let private fpRoundToInt ins insLen bld addr cast =
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | TwoOperands (OprSIMD (SIMDFPScalarReg _) as dst, src) ->
    let struct (eSize, _, _) = getElemDataSzAndElems dst
    let src = transOprToExpr ins bld addr src
    let result = fpType bld cast eSize src
    dstAssignScalar ins bld addr dst result eSize
  | TwoOperands (OprSIMD (SIMDVecReg _ ) as dst, src) ->
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let src = transSIMDOprToExpr bld eSize dataSize elements src
    let result = Array.map (fpType bld cast eSize) src
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | _ -> raise InvalidOperandException
  bld --!> insLen

let private fpCurrentRoundToInt ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | TwoOperands (OprSIMD (SIMDFPScalarReg _) as dst, src) ->
    let src = transOprToExpr ins bld addr src
    let result = fpRoundingMode src ins.OprSize bld
    dstAssignScalar ins bld addr dst result ins.OprSize
  | TwoOperands (OprSIMD (SIMDVecReg _ ) as dst, src) ->
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let src = transSIMDOprToExpr bld eSize dataSize elements src
    let result = Array.map (fun s -> fpRoundingMode s eSize bld) src
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | _ -> raise InvalidOperandException
  bld --!> insLen

let private tieawayCast bld eSize src =
  let sign = AST.xthi 1<rt> src
  let trunc = AST.cast CastKind.FtoFTrunc eSize src
  let struct (t, res) = tmpVars2 bld eSize
  bld <+ (t := AST.fsub src trunc)
  let comp1 =
    match eSize with
    | 32<rt> -> numI32 0x3F000000 eSize (* 0.5 *)
    | 64<rt> -> numI64 0x3FE0000000000000L eSize (* 0.5 *)
    | _ -> raise InvalidOperandSizeException
  let comp2 =
    match eSize with
    | 32<rt> -> numI32 0xBF000000 eSize (* -0.5 *)
    | 64<rt> -> numI64 0xBFE0000000000000L eSize (* -0.5 *)
    | _ -> raise InvalidOperandSizeException
  let ceil = fpType bld CastKind.FtoFCeil eSize src
  let floor = fpType bld CastKind.FtoFFloor eSize src
  let pRes = AST.ite (AST.fge t comp1) ceil floor
  let nRes = AST.ite (AST.fle t comp2) floor ceil
  bld <+ (res := AST.ite sign nRes pRes)
  res

let frinta ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | TwoOperands (OprSIMD (SIMDFPScalarReg _) as dst, src) ->
    let struct (eSize, _, _) = getElemDataSzAndElems dst
    let src = transOprToExpr ins bld addr src
    let result = tieawayCast bld eSize src
    dstAssignScalar ins bld addr dst result eSize
  | TwoOperands (OprSIMD (SIMDVecReg _ ) as dst, src) ->
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let src = transSIMDOprToExpr bld eSize dataSize elements src
    let result = Array.map (tieawayCast bld eSize) src
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | _ -> raise InvalidOperandException
  bld --!> insLen

let frinti ins insLen bld addr =
  fpCurrentRoundToInt ins insLen bld addr
let frintm ins insLen bld addr =
  fpRoundToInt ins insLen bld addr CastKind.FtoFFloor
let frintn ins insLen bld addr =
  fpRoundToInt ins insLen bld addr CastKind.FtoFRound
let frintp ins insLen bld addr =
  fpRoundToInt ins insLen bld addr CastKind.FtoFCeil
let frintx ins insLen bld addr =
  fpCurrentRoundToInt ins insLen bld addr
let frintz ins insLen bld addr =
  fpRoundToInt ins insLen bld addr CastKind.FtoFTrunc

let fsqrt ins insLen bld addr =
  let struct (dst, src) = getTwoOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | TwoOperands (OprSIMD (SIMDFPScalarReg _), _) ->
    let src = transOprToExpr ins bld addr src |> AST.fsqrt
    dstAssignScalar ins bld addr dst src eSize
  | _ ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let src = transSIMDOprToExpr bld eSize dataSize elements src
              |> Array.map (AST.fsqrt)
    dstAssignForSIMD dstA dstB src dataSize elements bld
  bld --!> insLen

let fsub ins insLen bld addr =
  let struct (dst, o1, o2) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | ThreeOperands (OprSIMD (SIMDFPScalarReg _), _, _) ->
    let src1 = transOprToExpr ins bld addr o1
    let src2 = transOprToExpr ins bld addr o2
    let result = fpSub bld dataSize src1 src2
    dstAssignScalar ins bld addr dst result eSize
  | _ ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let src1 = transSIMDOprToExpr bld eSize dataSize elements o1
    let src2 = transSIMDOprToExpr bld eSize dataSize elements o2
    let result = Array.map2 (fpSub bld eSize) src1 src2
    dstAssignForSIMD dstA dstB result dataSize elements bld
  bld --!> insLen

let insv ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (o1, o2) = getTwoOprs ins
  let struct (eSize, _, _) = getElemDataSzAndElems o1
  let dst = transOprToExpr ins bld addr o1
  let src = transOprToExpr ins bld addr o2
  bld <+ (dst := AST.xtlo eSize src)
  bld --!> insLen

let private isVecIdxOrLD1ST1 ins opr =
  let isVecIdx =
    match opr with
    | OprSIMDList simd ->
      match simd[0] with
      | SIMDVecRegWithIdx _ -> true
      | _ -> false
    | _ -> false
  isVecIdx || (ins.Opcode = Opcode.LD1) || (ins.Opcode = Opcode.ST1)

let private fillZeroHigh64 ins bld opr =
    if ins.OprSize = 64<rt> then
      match opr with
      | OprSIMDList simds ->
        List.iter (fun simd ->
          match simd with
          | SIMDVecReg (reg, _) ->
            let regB = pseudoRegVar bld reg 2
            bld <+ (regB := AST.num0 64<rt>)
          | _ -> ()) simds
      | _ -> ()
    else ()

let loadStoreList ins insLen bld addr isLoad =
  let isWBack, _ = getIsWBackAndIsPostIndex ins.Operands
  let struct (dst, src) = getTwoOprs ins
  let struct (eSize, _, elements) = getElemDataSzAndElems dst
  let dstArr = transSIMDListToExpr bld dst
  let bReg, mOffs = transOprToExpr ins bld addr src |> separateMemExpr
  let struct (address, offs) = tmpVars2 bld 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (address := bReg)
  bld <+ (offs := AST.num0 64<rt>)
  let eByte = eSize / 8<rt>
  let regLen = Array.length dstArr * elements
  let srcArr =
    let mem idx = AST.loadLE eSize (address .+ (numI32 (eByte * idx) 64<rt>))
    Array.init regLen mem
  let dstArr =
    if isVecIdxOrLD1ST1 ins dst then dstArr else dstArr |> Array.transpose
    |> Array.concat
  Array.iter2 (fun dst src ->
    if isLoad then bld <+ (dst := src) else bld <+ (src := dst)) dstArr srcArr
  if isLoad then fillZeroHigh64 ins bld dst else ()
  if isWBack then
    bld <+ (offs := numI32 (regLen * eByte) 64<rt>)
    if isRegOffset src then bld <+ (offs := mOffs) else ()
    bld <+ (bReg := address .+ offs)
  bld --!> insLen

let loadRep ins insLen bld addr =
  let isWBack, _ = getIsWBackAndIsPostIndex ins.Operands
  let struct (dst, src) = getTwoOprs ins
  let struct (eSize, _, elements) = getElemDataSzAndElems dst
  let dstArr = transSIMDListToExpr bld dst
  let bReg, mOffs = transOprToExpr ins bld addr src |> separateMemExpr
  let struct (address, offs) = tmpVars2 bld 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (address := bReg)
  bld <+ (offs := AST.num0 64<rt>)
  let eByte = eSize / 8<rt>
  let regLen = Array.length dstArr
  let srcArr =
    let mem idx =
      AST.loadLE eSize (address .+ (numI32 (eByte * (idx / elements)) 64<rt>))
    Array.init (regLen * elements) mem
  let dstArr = dstArr |> Array.concat
  Array.iter2 (fun dst src -> bld <+ (dst := src)) dstArr srcArr
  fillZeroHigh64 ins bld dst
  if isWBack then
    bld <+ (offs := numI32 (regLen * eByte) 64<rt>)
    if isRegOffset src then bld <+ (offs := mOffs) else ()
    bld <+ (bReg := address .+ offs)
  bld --!> insLen

let ldar ins insLen bld addr =
  let dst, (bReg, offset) = transTwoOprsSepMem ins bld addr
  let address = tmpVar bld 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (address := bReg .+ offset)
  mark bld address (memSizeToExpr ins.OprSize)
  dstAssign ins.OprSize dst (AST.loadLE ins.OprSize address) bld
  bld --!> insLen

let ldarb ins insLen bld addr =
  let dst, (bReg, offset) = transTwoOprsSepMem ins bld addr
  let address = tmpVar bld 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (address := bReg .+ offset)
  mark bld address (memSizeToExpr 8<rt>)
  dstAssign ins.OprSize dst (AST.loadLE 8<rt> address) bld
  bld --!> insLen

let ldax ins insLen bld addr size =
  let dst, (bReg, offset) = transTwoOprsSepMem ins bld addr
  let address = tmpVar bld 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (address := bReg .+ offset)
  mark bld address (memSizeToExpr size)
  dstAssign ins.OprSize dst (AST.loadLE size address) bld
  bld --!> insLen

let ldaxr ins insLen bld addr =
  let dst, (bReg, offset) = transTwoOprsSepMem ins bld addr
  let address = tmpVar bld 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (address := bReg .+ offset)
  mark bld address (memSizeToExpr ins.OprSize)
  dstAssign ins.OprSize dst (AST.loadLE ins.OprSize address) bld
  bld --!> insLen

let ldaxp ins insLen bld addr =
  let dst1, dst2, (bReg, offset) = transThreeOprsSepMem ins bld addr
  let address = tmpVar bld 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (address := bReg .+ offset)
  mark bld address (memSizeToExpr ins.OprSize)
  if ins.OprSize = 32<rt> then
    let src = AST.loadLE 64<rt> address
    dstAssign ins.OprSize dst1 (AST.xtlo 32<rt> src) bld
    dstAssign ins.OprSize dst2 (AST.xthi 32<rt> src) bld
  else
    bld <+ (dst1 := (AST.loadLE 64<rt> address))
    bld <+ (dst2 := (AST.loadLE 64<rt> (address .+ numI32 8 64<rt>)))
  bld --!> insLen

let ldnp ins insLen bld addr =
  let address = tmpVar bld 64<rt>
  let dByte = numI32 (RegType.toByteWidth ins.OprSize) 64<rt>
  bld <!-- (ins.Address, insLen)
  match ins.Operands, ins.OprSize with
  | ThreeOperands (OprSIMD _ as src1, src2, src3), 128<rt> ->
    let struct (src1B, src1A) = transOprToExpr128 ins bld addr src1
    let struct (src2B, src2A) = transOprToExpr128 ins bld addr src2
    let bReg, offset = transOprToExpr ins bld addr src3 |> separateMemExpr
    let n8 = numI32 8 64<rt>
    bld <+ (address := bReg)
    bld <+ (address := address .+ offset)
    bld <+ (src1A := AST.loadLE 64<rt> address)
    bld <+ (src1B := AST.loadLE 64<rt> (address .+ n8))
    bld <+ (src2A := AST.loadLE 64<rt> (address .+ dByte))
    bld <+ (src2B := AST.loadLE 64<rt> (address .+ dByte .+ n8))
  | ThreeOperands (OprSIMD _ as src1, src2, src3), _ ->
    let bReg, offset = transOprToExpr ins bld addr src3 |> separateMemExpr
    let struct (eSize, _, _) = getElemDataSzAndElems src1
    bld <+ (address := bReg)
    bld <+ (address := address .+ offset)
    let inline load addr = AST.loadLE ins.OprSize addr
    dstAssignScalar ins bld addr src1 (load address) eSize
    dstAssignScalar ins bld addr src2 (load (address .+ dByte)) eSize
  | _ ->
    let src1, src2, (bReg, offset) = transThreeOprsSepMem ins bld addr
    let oprSize = ins.OprSize
    bld <+ (address := bReg)
    bld <+ (address := address .+ offset)
    dstAssign oprSize src1 (AST.loadLE oprSize address) bld
    dstAssign oprSize src2 (AST.loadLE oprSize (address .+ dByte)) bld
  bld --!> insLen

let ldp ins insLen bld addr =
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = tmpVar bld 64<rt>
  let dByte = numI32 (RegType.toByteWidth ins.OprSize) 64<rt>
  bld <!-- (ins.Address, insLen)
  match ins.Operands, ins.OprSize with
  | ThreeOperands (OprSIMD _ as src1, src2, src3), 128<rt> ->
    let struct (src1B, src1A) = transOprToExpr128 ins bld addr src1
    let struct (src2B, src2A) = transOprToExpr128 ins bld addr src2
    let bReg, offset = transOprToExpr ins bld addr src3 |> separateMemExpr
    let n8 = numI32 8 64<rt>
    bld <+ (address := bReg)
    bld <+ (address := if isPostIndex then address else address .+ offset)
    bld <+ (src1A := AST.loadLE 64<rt> address)
    bld <+ (src1B := AST.loadLE 64<rt> (address .+ n8))
    bld <+ (src2A := AST.loadLE 64<rt> (address .+ dByte))
    bld <+ (src2B := AST.loadLE 64<rt> (address .+ dByte .+ n8))
    if isWBack && isPostIndex then bld <+ (bReg := address .+ offset)
    else if isWBack then bld <+ (bReg := address) else ()
  | ThreeOperands (OprSIMD _ as src1, src2, src3), _ ->
    let bReg, offset = transOprToExpr ins bld addr src3 |> separateMemExpr
    let struct (eSize, _, _) = getElemDataSzAndElems src1
    bld <+ (address := bReg)
    bld <+ (address := if isPostIndex then address else address .+ offset)
    let inline load addr = AST.loadLE ins.OprSize addr
    dstAssignScalar ins bld addr src1 (load address) eSize
    dstAssignScalar ins bld addr src2 (load (address .+ dByte)) eSize
    if isWBack && isPostIndex then bld <+ (bReg := address .+ offset)
    else if isWBack then bld <+ (bReg := address) else ()
  | _ ->
    let src1, src2, (bReg, offset) = transThreeOprsSepMem ins bld addr
    let oprSize = ins.OprSize
    bld <+ (address := bReg)
    bld <+ (address := if isPostIndex then address else address .+ offset)
    dstAssign oprSize src1 (AST.loadLE oprSize address) bld
    dstAssign oprSize src2 (AST.loadLE oprSize (address .+ dByte)) bld
    if isWBack && isPostIndex then bld <+ (bReg := address .+ offset)
    else if isWBack then bld <+ (bReg := address) else ()
  bld --!> insLen

let ldpsw ins insLen bld addr =
  let src1, src2, (bReg, offset) = transThreeOprsSepMem ins bld addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = tmpVar bld 64<rt>
  let data1 = tmpVar bld 32<rt>
  let data2 = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (address := bReg)
  bld <+ (address := if isPostIndex then address else address .+ offset)
  bld <+ (data1 := AST.loadLE 32<rt> address)
  bld <+ (data2 := AST.loadLE 32<rt> (address .+ numI32 4 64<rt>))
  bld <+ (src1 := AST.sext 64<rt> data1)
  bld <+ (src2 := AST.sext 64<rt> data2)
  if isWBack && isPostIndex then bld <+ (bReg := address .+ offset)
  else if isWBack then bld <+ (bReg := address) else ()
  bld --!> insLen

let ldr ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | TwoOperands (o1, OprMemory (LiteralMode o2)) -> (* LDR (literal) *)
    let offset = transOprToExpr ins bld addr (OprMemory (LiteralMode o2))
    let address = tmpVar bld 64<rt>
    match ins.OprSize with
    | 128<rt> ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
      bld <+ (address := getPC bld .+ offset)
      bld <+ (dstA := AST.loadLE 64<rt> address)
      bld <+ (dstB := AST.loadLE 64<rt> (address .+ (numI32 8 64<rt>)))
    | _ ->
      let dst = transOprToExpr ins bld addr o1
      let data = tmpVar bld ins.OprSize
      bld <+ (address := getPC bld .+ offset)
      bld <+ (data := AST.loadLE ins.OprSize address)
      match o1 with
      | OprSIMD (SIMDFPScalarReg _) ->
        dstAssignScalar ins bld addr o1 data ins.OprSize
      | _ -> dstAssign ins.OprSize dst data bld
  | TwoOperands (o1, o2) ->
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    let address = tmpVar bld 64<rt>
    match ins.OprSize with
    | 128<rt> ->
      let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
      let bReg, offset = transOprToExpr ins bld addr o2 |> separateMemExpr
      bld <+ (address := bReg)
      bld <+ (address := if isPostIndex then address else address .+ offset)
      bld <+ (dstA := AST.loadLE 64<rt> address)
      bld <+ (dstB := AST.loadLE 64<rt> (address .+ (numI32 8 64<rt>)))
      if isWBack && isPostIndex then bld <+ (bReg := address .+ offset)
      else if isWBack then bld <+ (bReg := address) else ()
    | _ ->
      let dst = transOprToExpr ins bld addr o1
      let bReg, offset = transOprToExpr ins bld addr o2 |> separateMemExpr
      let data = tmpVar bld ins.OprSize
      bld <+ (address := bReg)
      bld <+ (address := if isPostIndex then address else address .+ offset)
      bld <+ (data := AST.loadLE ins.OprSize address)
      match o1 with
      | OprSIMD (SIMDFPScalarReg _) ->
        dstAssignScalar ins bld addr o1 data ins.OprSize
      | _ -> dstAssign ins.OprSize dst data bld
      if isWBack && isPostIndex then bld <+ (bReg := address .+ offset)
      else if isWBack then bld <+ (bReg := address) else ()
  | _ -> raise InvalidOperandException
  bld --!> insLen

let ldrb ins insLen bld addr =
  let dst, (bReg, offset) = transTwoOprsSepMem ins bld addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = tmpVar bld 64<rt>
  let data = tmpVar bld 8<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (address := bReg)
  bld <+ (address := if isPostIndex then address else address .+ offset)
  bld <+ (data := AST.loadLE 8<rt> address)
  dstAssign ins.OprSize dst (AST.zext 32<rt> data) bld
  if isWBack && isPostIndex then bld <+ (bReg := address .+ offset)
  else if isWBack then bld <+ (bReg := address) else ()
  bld --!> insLen

let ldrh ins insLen bld addr =
  let dst, (bReg, offset) = transTwoOprsSepMem ins bld addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = tmpVar bld 64<rt>
  let data = tmpVar bld 16<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (address := bReg)
  bld <+ (address := if isPostIndex then address else address .+ offset)
  bld <+ (data := AST.loadLE 16<rt> address)
  dstAssign ins.OprSize dst (AST.zext 32<rt> data) bld
  if isWBack && isPostIndex then bld <+ (bReg := address .+ offset)
  else if isWBack then bld <+ (bReg := address) else ()
  bld --!> insLen

let ldrsb ins insLen bld addr =
  let dst, (bReg, offset) = transTwoOprsSepMem ins bld addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = tmpVar bld 64<rt>
  let data = tmpVar bld 8<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (address := bReg)
  bld <+ (address := if isPostIndex then address else address .+ offset)
  bld <+ (data := AST.loadLE 8<rt> address)
  dstAssign ins.OprSize dst (AST.sext ins.OprSize data) bld
  if isWBack && isPostIndex then bld <+ (bReg := address .+ offset)
  else if isWBack then bld <+ (bReg := address) else ()
  bld --!> insLen

let ldrsh ins insLen bld addr =
  let dst, (bReg, offset) = transTwoOprsSepMem ins bld addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = tmpVar bld 64<rt>
  let data = tmpVar bld 16<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (address := bReg)
  bld <+ (address := if isPostIndex then address else address .+ offset)
  bld <+ (data := AST.loadLE 16<rt> address)
  dstAssign ins.OprSize dst (AST.sext ins.OprSize data) bld
  if isWBack && isPostIndex then bld <+ (bReg := address .+ offset)
  else if isWBack then bld <+ (bReg := address) else ()
  bld --!> insLen

let ldrsw ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let address = tmpVar bld 64<rt>
  let data = tmpVar bld 32<rt>
  match ins.Operands with
  | TwoOperands (o1, OprMemory (LiteralMode o2)) ->
    let dst = transOprToExpr ins bld addr o1
    let offset = transOprToExpr ins bld addr (OprMemory (LiteralMode o2))
    bld <+ (address := getPC bld .+ offset)
    bld <+ (data := AST.loadLE 32<rt> address)
    bld <+ (dst := AST.sext 64<rt> data)
  | TwoOperands (o1, o2) ->
    let dst = transOprToExpr ins bld addr o1
    let bReg, offset = transOprToExpr ins bld addr o2 |> separateMemExpr
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    bld <+ (address := bReg)
    bld <+ (address := if isPostIndex then address else address .+ offset)
    bld <+ (data := AST.loadLE 32<rt> address)
    bld <+ (dst := AST.sext 64<rt> data)
    if isWBack && isPostIndex then bld <+ (bReg := address .+ offset)
    else if isWBack then bld <+ (bReg := address) else ()
  | _ -> raise InvalidOperandException
  bld --!> insLen

let ldtr ins insLen bld addr =
  let dst, (bReg, offset) = transTwoOprsSepMem ins bld addr
  let address = tmpVar bld 64<rt>
  let data = tmpVar bld ins.OprSize
  bld <!-- (ins.Address, insLen)
  bld <+ (address := bReg .+ offset)
  bld <+ (data := AST.loadLE ins.OprSize address)
  dstAssign ins.OprSize dst (AST.zext ins.OprSize data) bld
  bld --!> insLen

let ldur ins insLen bld addr =
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = tmpVar bld 64<rt>
  let data = tmpVar bld ins.OprSize
  let struct (o1, o2) = getTwoOprs ins
  bld <!-- (ins.Address, insLen)
  match ins.OprSize with
  | 128<rt> ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let bReg, offset = transOprToExpr ins bld addr o2 |> separateMemExpr
    bld <+ (address := bReg)
    bld <+ (address := if isPostIndex then address else address .+ offset)
    bld <+ (dstA := AST.loadLE 64<rt> address)
    bld <+ (dstB := AST.loadLE 64<rt> (address .+ (numI32 8 64<rt>)))
    if isWBack && isPostIndex then bld <+ (bReg := address .+ offset)
    else if isWBack then bld <+ (bReg := address) else ()
  | _ ->
    let dst = transOprToExpr ins bld addr o1
    let bReg, offset = transOprToExpr ins bld addr o2 |> separateMemExpr
    bld <+ (address := bReg)
    bld <+ (address := if isPostIndex then address else address .+ offset)
    bld <+ (data := AST.loadLE ins.OprSize address)
    match o1 with
      | OprSIMD (SIMDFPScalarReg _) ->
        dstAssignScalar ins bld addr o1 data ins.OprSize
      | _ -> dstAssign ins.OprSize dst data bld
    if isWBack && isPostIndex then bld <+ (bReg := address .+ offset)
    else if isWBack then bld <+ (bReg := address) else ()
  bld --!> insLen

let ldurb ins insLen bld addr =
  let src, (bReg, offset) = transTwoOprsSepMem ins bld addr
  let address = tmpVar bld 64<rt>
  let data = tmpVar bld 8<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (address := bReg)
  bld <+ (address := address .+ offset)
  bld <+ (data := AST.loadLE 8<rt> address)
  dstAssign ins.OprSize src (AST.zext 32<rt> data) bld
  bld --!> insLen

let ldurh ins insLen bld addr =
  let src, (bReg, offset) = transTwoOprsSepMem ins bld addr
  let address = tmpVar bld 64<rt>
  let data = tmpVar bld 16<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (address := bReg)
  bld <+ (address := address .+ offset)
  bld <+ (data := AST.loadLE 16<rt> address)
  dstAssign ins.OprSize src (AST.zext 32<rt> data) bld
  bld --!> insLen

let ldursb ins insLen bld addr =
  let dst, (bReg, offset) = transTwoOprsSepMem ins bld addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = tmpVar bld 64<rt>
  let data = tmpVar bld 8<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (address := bReg.+ offset)
  bld <+ (data := AST.loadLE 8<rt> address)
  dstAssign ins.OprSize dst (AST.sext ins.OprSize data) bld
  bld --!> insLen

let ldursh ins insLen bld addr =
  let dst, (bReg, offset) = transTwoOprsSepMem ins bld addr
  let address = tmpVar bld 64<rt>
  let data = tmpVar bld 16<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (address := bReg.+ offset)
  bld <+ (data := AST.loadLE 16<rt> address)
  dstAssign ins.OprSize dst (AST.sext ins.OprSize data) bld
  bld --!> insLen

let ldursw ins insLen bld addr =
  let dst, (bReg, offset) = transTwoOprsSepMem ins bld addr
  let address = tmpVar bld 64<rt>
  let data = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (address := bReg)
  bld <+ (address := address .+ offset)
  bld <+ (data := AST.loadLE 32<rt> address)
  dstAssign ins.OprSize dst (AST.sext 64<rt> data) bld
  bld --!> insLen

let logShift ins insLen bld addr shift =
  let dst, src, amt = transThreeOprs ins bld addr
  bld <!-- (ins.Address, insLen)
  dstAssign ins.OprSize dst (shift src amt) bld
  bld --!> insLen

let lslv ins insLen bld addr =
  let dst, src1, src2 = transThreeOprs ins bld addr
  let oprSz = ins.OprSize
  let dataSize = numI32 (RegType.toBitWidth ins.OprSize) oprSz
  bld <!-- (ins.Address, insLen)
  let result = shiftReg src1 (src2 .% dataSize) oprSz SRTypeLSL
  dstAssign ins.OprSize dst result bld
  bld --!> insLen

let lsrv ins insLen bld addr =
  let dst, src1, src2 = transThreeOprs ins bld addr
  let oprSz = ins.OprSize
  let dataSize = numI32 (RegType.toBitWidth oprSz) oprSz
  bld <!-- (ins.Address, insLen)
  let result = shiftReg src1 (src2 .% dataSize) oprSz SRTypeLSR
  dstAssign ins.OprSize dst result bld
  bld --!> insLen

let maxMin ins insLen bld addr opFn =
  let struct (o1, o2, o3) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
  let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
  let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
  let result = Array.map2 (fun s1 s2 -> AST.ite (opFn s1 s2) s1 s2) src1 src2
  bld <!-- (ins.Address, insLen)
  dstAssignForSIMD dstA dstB result dataSize elements bld
  bld --!> insLen

let maxMinv ins insLen bld addr opFn =
  let struct (o1, o2) = getTwoOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems o2
  let dst = transOprToExpr ins bld addr o1
  let src = transSIMDOprToExpr bld eSize dataSize elements o2
  let minMax = tmpVar bld eSize
  bld <!-- (ins.Address, insLen)
  bld <+ (minMax := src[0])
  Array.sub src 1 (elements - 1)
  |> Array.iter (fun e -> bld <+ (minMax := AST.ite (opFn minMax e) minMax e))
  dstAssignScalar ins bld addr o1 minMax eSize
  bld --!> insLen

let maxMinp ins insLen bld addr opFn =
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
  let result = Array.init elements (fun _ -> tmpVar bld eSize)
  let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
  let src2 = transSIMDOprToExpr bld eSize dataSize elements src2
  let cal src = Array.chunkBySize 2 src
                |> Array.map (fun e -> AST.ite (opFn e.[0] e.[1]) e.[0] e.[1])
  let concat = Array.append (cal src1) (cal src2)
  bld <!-- (ins.Address, insLen)
  Array.iter2 (fun res s -> bld <+ (res := s)) result concat
  dstAssignForSIMD dstA dstB result dataSize elements bld
  bld --!> insLen

let madd ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | ThreeOperands (_, _, OprSIMD (SIMDVecReg _)) ->
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
    let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
    let result = Array.map2 (.*) src1 src2
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | ThreeOperands (OprSIMD _ as o1, o2, o3) ->
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
    let src2 = transOprToExpr ins bld addr o3
    let result = Array.map (fun s1 -> s1 .* src2) src1
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | _ ->
    let dst, src1, src2, src3 = transOprToExprOfMADD ins bld addr
    dstAssign ins.OprSize dst (src3 .+ (src1 .* src2)) bld
  bld --!> insLen

let mladdsub ins insLen bld addr opFn =
  bld <!-- (ins.Address, insLen)
  let struct (o1, o2, o3) = getThreeOprs ins
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems o2
  let dst = transSIMDOprToExpr bld eSize dataSize elements o1
  let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
  match ins.Operands with
  | ThreeOperands (_, _, OprSIMD (SIMDVecReg _)) ->
    let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
    let prod = Array.map2 (.*) src1 src2
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    let cal = Array.map2 (opFn) dst prod
    Array.iter2 (fun res s -> bld <+ (res := s)) result cal
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | _ ->
    let src2 = transOprToExpr ins bld addr o3
    let prod = Array.map (fun s1 -> s1 .* src2) src1
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    let cal = Array.map2 (opFn) dst prod
    Array.iter2 (fun res s -> bld <+ (res := s)) result cal
    dstAssignForSIMD dstA dstB result dataSize elements bld
  bld --!> insLen

let mov ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | TwoOperands (OprSIMD (SIMDVecReg _) as o1, o2) ->
    let struct (_, dataSize, _) = getElemDataSzAndElems o1
    let struct (srcB, srcA) = transOprToExpr128 ins bld addr o2
    dstAssign128 ins bld addr o1 srcA srcB dataSize
  | TwoOperands (OprSIMD (SIMDFPScalarReg _), OprSIMD (SIMDVecRegWithIdx _)) ->
    let struct (dst, src) = getTwoOprs ins
    let struct (_, dataSize, _) = getElemDataSzAndElems dst
    let src = transOprToExpr ins bld addr src
    dstAssignScalar ins bld addr dst src dataSize
  | _ ->
    let dst, src = transTwoOprs ins bld addr
    dstAssign ins.OprSize dst src bld
  bld --!> insLen

let movi ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | TwoOperands (OprSIMD (SIMDFPScalarReg _), OprImm _) ->
    let dst, src = transTwoOprs ins bld addr
    dstAssign ins.OprSize dst src bld
  | TwoOperands (OprSIMD (SIMDVecReg _), OprImm _) ->
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
    let imm = if not (dataSize = 128<rt> && eSize = 64<rt>) then
                transOprToExpr ins bld addr src
                |> advSIMDExpandImm bld eSize
              else transOprToExpr ins bld addr src |> AST.xtlo 64<rt>
    dstAssign128 ins bld addr dst imm imm dataSize
  | ThreeOperands (OprSIMD (SIMDVecReg _), OprImm _, OprShift _) ->
    let struct (dst, src, amount) = getThreeOprs ins
    let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
    let imm = transBarrelShiftToExpr ins.OprSize bld src amount
              |> advSIMDExpandImm bld eSize
    dstAssign128 ins bld addr dst imm imm dataSize
  | _ -> raise InvalidOperandException
  bld --!> insLen

let private getWordMask ins shift =
  match shift with
  | OprShift (SRTypeLSL, Imm amt) ->
    numI64 (~~~ (0xFFFFL <<< (int amt))) ins.OprSize
  | _ -> raise InvalidOperandException

let movk ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, imm, shf) = getThreeOprs ins
  let dst = transOprToExpr ins bld addr dst
  let src = transBarrelShiftToExpr ins.OprSize bld imm shf
  let mask = getWordMask ins shf
  dstAssign ins.OprSize dst ((dst .& mask) .| src) bld
  bld --!> insLen

let movn ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let dst, src = transThreeOprsWithBarrelShift ins bld addr
  dstAssign ins.OprSize dst (AST.not src) bld
  bld --!> insLen

let movz ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let dst, src = transThreeOprsWithBarrelShift ins bld addr
  dstAssign ins.OprSize dst src bld
  bld --!> insLen

let mrs ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr ins bld addr dst
  let src =
    match src with
    | OprRegister R.NZCV ->
      let n = (regVar bld R.N |> AST.zext 64<rt>) << numI32 31 64<rt>
      let z = (regVar bld R.Z |> AST.zext 64<rt>) << numI32 30 64<rt>
      let c = (regVar bld R.C |> AST.zext 64<rt>) << numI32 29 64<rt>
      let v = (regVar bld R.V |> AST.zext 64<rt>) << numI32 28 64<rt>
      n .| z .| c .| v
    | _ -> transOprToExpr ins bld addr src
  bld <+ (dst := src)
  bld --!> insLen

let msr ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  match dst with
  | OprRegister R.NZCV ->
    let src = transOprToExpr ins bld addr src
    bld <+ (regVar bld R.N := AST.extract src 1<rt> 31)
    bld <+ (regVar bld R.Z := AST.extract src 1<rt> 30)
    bld <+ (regVar bld R.C := AST.extract src 1<rt> 29)
    bld <+ (regVar bld R.V := AST.extract src 1<rt> 28)
  | _ ->
    let dst = transOprToExpr ins bld addr dst
    let src = transOprToExpr ins bld addr src
    bld <+ (dst := src)
  bld --!> insLen

let msub ins insLen bld addr =
  let dst, src1, src2, src3 = transOprToExprOfMSUB ins bld addr
  bld <!-- (ins.Address, insLen)
  dstAssign ins.OprSize dst (src3 .- (src1 .* src2)) bld
  bld --!> insLen

let mvni ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | TwoOperands _ ->
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
    let imm = transOprToExpr ins bld addr src
              |> advSIMDExpandImm bld eSize
              |> AST.not
    dstAssign128 ins bld addr dst imm imm dataSize
  | _ ->
    let struct (dst, src, shf) = getThreeOprs ins
    let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
    let src = transBarrelShiftToExpr 64<rt> bld src shf
              |> advSIMDExpandImm bld eSize
              |> AST.not
    dstAssign128 ins bld addr dst src src dataSize
  bld --!> insLen

let nop insAddr insLen bld =
  bld <!-- (insAddr, insLen)
  bld --!> insLen

let orn ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | TwoOperands _ ->
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let src = transSIMDOprToExpr bld eSize dataSize elements src
    let result = Array.map AST.not src
    bld <!-- (ins.Address, insLen)
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | ThreeOperands (OprSIMD (SIMDVecReg _) as o1, o2, o3) ->
    let struct (_, dataSize, _) = getElemDataSzAndElems o1
    let struct (src1B, src1A) = transOprToExpr128 ins bld addr o2
    let struct (src2B, src2A) = transOprToExpr128 ins bld addr o3
    let resultB = src1B .| (AST.not src2B)
    let resultA = src1A .| (AST.not src2A)
    dstAssign128 ins bld addr o1 resultA resultB dataSize
  | _ ->
    let dst, src1, src2 = transOprToExprOfORN ins bld addr
    dstAssign ins.OprSize dst (src1 .| AST.not src2) bld
  bld --!> insLen

let orr ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | TwoOperands (OprSIMD _, OprImm _) ->
    let struct (dst, imm) = getTwoOprs ins
    let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let src = transOprToExpr ins bld addr imm |> advSIMDExpandImm bld eSize
    dstAssign128 ins bld addr dst (dstA .| src) (dstB .| src) dataSize
  | ThreeOperands (OprSIMD _, OprImm _, _) ->
    let struct (dst, imm, shf) = getThreeOprs ins
    let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let src = transBarrelShiftToExpr ins.OprSize bld imm shf
              |> advSIMDExpandImm bld eSize
    dstAssign128 ins bld addr dst (dstA .| src) (dstB .| src) dataSize
  | ThreeOperands (OprSIMD (SIMDVecReg (_, v)) as o1, o2, o3) ->
    let struct (_, dataSize, _) = getElemDataSzAndElems o1
    let struct (src1B, src1A) = transOprToExpr128 ins bld addr o2
    let struct (src2B, src2A) = transOprToExpr128 ins bld addr o3
    let resultB = src1B .| src2B
    let resultA = src1A .| src2A
    dstAssign128 ins bld addr o1 resultA resultB dataSize
  | _ ->
    let dst, src1, src2 = transOprToExprOfORR ins bld addr
    dstAssign ins.OprSize dst (src1 .| src2) bld
  bld --!> insLen

let rbit ins insLen bld addr =
  match ins.Operands with
  | TwoOperands (OprRegister _, OprRegister _) ->
    let dst, src = transTwoOprs ins bld addr
    let datasize = if ins.OprSize = 64<rt> then 64 else 32
    let tmp = tmpVar bld ins.OprSize
    bld <!-- (ins.Address, insLen)
    bld <+ (tmp := numI32 0 ins.OprSize)
    for i in 0 .. (datasize - 1) do
      bld <+ (AST.extract tmp 1<rt> (datasize - 1 - i) := AST.extract src 1<rt> i)
    dstAssign ins.OprSize dst tmp bld
  | _ ->
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let src = transSIMDOprToExpr bld eSize dataSize elements src
    let rev = tmpVar bld eSize
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    bld <!-- (ins.Address, insLen)
    bld <+ (rev := numI32 0 eSize)
    let reverse i e =
      let eSize = int eSize
      for i in 0 .. eSize - 1 do
        bld <+ (AST.extract rev 1<rt> (eSize - 1 - i) := AST.extract e 1<rt> i)
      bld <+ (result[i] := rev)
    Array.iteri reverse src
    dstAssignForSIMD dstA dstB result dataSize elements bld
  bld --!> insLen

let ret ins insLen bld addr =
  let src = transOneOpr ins bld addr
  let target = tmpVar bld 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (target := src)
  branchTo ins bld target BrTypeRET InterJmpKind.IsRet
  bld --!> insLen

let rev ins insLen bld addr =
  let e = if ins.OprSize = 64<rt> then 7 else 3
  let t = tmpVar bld ins.OprSize
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | TwoOperands (OprSIMD (SIMDVecReg _ ) as dst, src) ->
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let src = transSIMDOprToExpr bld eSize dataSize elements src
    let revSize = 64 / int eSize
    let result = Array.chunkBySize revSize src |> Array.collect (Array.rev)
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | _ ->
    let dst, src = transTwoOprs ins bld addr
    bld <+ (t := numI32 0 ins.OprSize)
    for i in 0 .. e do
      bld <+ (AST.extract t 8<rt> ((e - i) * 8) := AST.extract src 8<rt> (i * 8))
    dstAssign ins.OprSize dst t bld
  bld --!> insLen

let rev16 ins insLen bld addr =
  let tmp = tmpVar bld ins.OprSize
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | TwoOperands (OprSIMD (SIMDVecReg _ ) as dst, src) ->
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let src = transSIMDOprToExpr bld eSize dataSize elements src
    let revSize = 16 / int eSize
    let result = Array.chunkBySize revSize src |> Array.collect (Array.rev)
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | _ ->
    let dst, src = transTwoOprs ins bld addr
    bld <+ (tmp := numI32 0 ins.OprSize)
    for i in 0 .. ((int ins.OprSize / 8) - 1) do
      let idx = i * 8
      let revIdx = if i % 2 = 0 then idx + 8 else idx - 8
      bld <+ (AST.extract tmp 8<rt> revIdx := AST.extract src 8<rt> idx)
    done
    dstAssign ins.OprSize dst tmp bld
  bld --!> insLen

let rev32 ins insLen bld addr =
  let tmp = tmpVar bld ins.OprSize
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | TwoOperands (OprSIMD (SIMDVecReg _ ) as dst, src) ->
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let src = transSIMDOprToExpr bld eSize dataSize elements src
    let revSize = 32 / int eSize
    let result = Array.chunkBySize revSize src |> Array.collect (Array.rev)
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | _ ->
    let dst, src = transTwoOprs ins bld addr
    bld <+ (tmp := numI32 0 ins.OprSize)
    for i in 0 .. ((int ins.OprSize / 8) - 1) do
      let revIdx = (i ^^^ 0b11) * 8
      bld <+ (AST.extract tmp 8<rt> revIdx := AST.extract src 8<rt> (i * 8))
    done
    bld <+ (dst := tmp)
  bld --!> insLen

let rorv ins insLen bld addr =
  let dst, src1, src2 = transThreeOprs ins bld addr
  let amount = src2 .% oprSzToExpr ins.OprSize
  bld <!-- (ins.Address, insLen)
  dstAssign ins.OprSize dst (shiftReg src1 amount ins.OprSize SRTypeROR) bld
  bld --!> insLen

let sbc ins insLen bld addr =
  let dst, src1, src2 = transThreeOprs ins bld addr
  let c = AST.zext ins.OprSize (regVar bld R.C)
  bld <!-- (ins.Address, insLen)
  let result, _ = addWithCarry src1 (AST.not src2) c ins.OprSize
  dstAssign ins.OprSize dst result bld
  bld --!> insLen

let sbfm ins insLen bld addr dst src immr imms =
  let oprSz = ins.OprSize
  let width = oprSzToExpr oprSz
  let struct (wmask, tmask) = decodeBitMasks immr imms (int oprSz)
  let immr = transOprToExpr ins bld addr immr
  let imms = transOprToExpr ins bld addr imms
  let n0 = AST.num0 oprSz
  bld <!-- (ins.Address, insLen)
  let struct (bot, srcS, top, tMask) = tmpVars4 bld oprSz
  bld <+ (bot := rorForIR src immr width .& (numI64 wmask oprSz))
  bld <+ (srcS := (src >> imms) .& (AST.num1 oprSz))
  bld <+ (top := AST.ite (srcS == n0) n0 (numI32 -1 oprSz))
  bld <+ (tMask := numI64 tmask oprSz)
  dstAssign ins.OprSize dst ((top .& AST.not tMask) .| (bot .& tMask)) bld
  bld --!> insLen

let sbfiz ins insLen bld addr =
  let struct (dst, src, lsb, width) = getFourOprs ins
  let dst = transOprToExpr ins bld addr dst
  let src = transOprToExpr ins bld addr src
  let immr = ((getImmValue lsb * -1L) &&& 0x3F) % (int64 ins.OprSize) |> OprImm
  let imms = getImmValue width - 1L |> OprImm
  sbfm ins insLen bld addr dst src immr imms

let sbfx ins insLen bld addr =
  let struct (dst, src, lsb, width) = getFourOprs ins
  let dst = transOprToExpr ins bld addr dst
  let src = transOprToExpr ins bld addr src
  let imms = (getImmValue lsb) + (getImmValue width) - 1L |> OprImm
  sbfm ins insLen bld addr dst src lsb imms

let private fixedToFp bld oprSz fbits unsigned src =
  let divBits =
    AST.cast CastKind.UIntToFloat oprSz (numU64 0x1uL oprSz << fbits)
  let intOperand, num0 =
    if unsigned then
      AST.cast CastKind.UIntToFloat oprSz src,
      AST.cast CastKind.UIntToFloat oprSz (AST.num0 oprSz)
    else
      AST.cast CastKind.SIntToFloat oprSz src,
      AST.cast CastKind.SIntToFloat oprSz (AST.num0 oprSz)
  let realOperand = fpDiv bld oprSz intOperand divBits
  let cond = AST.eq realOperand num0
  AST.ite cond (AST.num0 oprSz) realOperand

let icvtf ins insLen bld addr unsigned =
  let oprSize = ins.OprSize
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | TwoOperands (OprSIMD (SIMDVecReg _), _) ->
    let struct (o1, o2) = getTwoOprs ins
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o2
    let src = transSIMDOprToExpr bld eSize dataSize elements o2
    let n0 = AST.num0 eSize
    let result =
      Array.map (fixedToFp bld eSize n0 unsigned) src
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | TwoOperands (OprSIMD (SIMDFPScalarReg _) as dst, _) ->
    let struct (eSize, _, _) = getElemDataSzAndElems dst
    let _, src = transTwoOprs ins bld addr
    let n0 = AST.num0 oprSize
    let result = fixedToFp bld oprSize n0 unsigned src
    dstAssignScalar ins bld addr dst result eSize
  | ThreeOperands (OprSIMD (SIMDFPScalarReg _), _, _) ->
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, _, _) = getElemDataSzAndElems o1
    let src = transOprToExpr ins bld addr o2
    let fbits = transOprToExpr ins bld addr o3
    let result = fixedToFp bld eSize fbits unsigned src
    dstAssignScalar ins bld addr o1 result eSize
  | ThreeOperands (OprSIMD (SIMDVecReg _), _, _) ->
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let struct (eSz, dataSize, elements) = getElemDataSzAndElems o2
    let src = transSIMDOprToExpr bld eSz dataSize elements o2
    let fbits = transOprToExpr ins bld addr o3 |> AST.xtlo eSz
    let result = Array.map (fixedToFp bld eSz fbits unsigned) src
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | _ ->
    let dst, src, fbits = transThreeOprs ins bld addr
    let result = fixedToFp bld oprSize fbits unsigned src
    dstAssign oprSize dst result bld
  bld --!> insLen

let sdiv ins insLen bld addr =
  let dst, src1, src2 = transThreeOprs ins bld addr
  let num0 = AST.num0 ins.OprSize
  let cond1 = AST.eq src2 num0
  let divSrc = src1 ?/ src2
  bld <!-- (ins.Address, insLen)
  let result = AST.ite cond1 num0 divSrc
  dstAssign ins.OprSize dst result bld
  bld --!> insLen

let shl ins insLen bld addr =
  let struct (dst, src, amt) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | ThreeOperands (OprSIMD (SIMDFPScalarReg _), _, _) ->
    let _, src, amt = transThreeOprs ins bld addr
    dstAssignScalar ins bld addr dst (src << amt) eSize
  | _ ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let src = transSIMDOprToExpr bld eSize dataSize elements src
    let amt = transOprToExpr ins bld addr amt |> AST.xtlo eSize
    let result = Array.map (fun e -> e << amt) src
    dstAssignForSIMD dstA dstB result dataSize elements bld
  bld --!> insLen

let smaddl ins insLen bld addr =
  let dst, src1, src2, src3 = transFourOprs ins bld addr
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := src3 .+ (AST.sext 64<rt> src1 .* AST.sext 64<rt> src2))
  bld --!> insLen

let smov ins insLen bld addr =
  let result = tmpVar bld ins.OprSize
  bld <!-- (ins.Address, insLen)
  let dst, src = transTwoOprs ins bld addr
  bld <+ (result := AST.sext ins.OprSize src)
  dstAssign ins.OprSize dst result bld
  bld --!> insLen

let smsubl ins insLen bld addr =
  let dst, src1, src2, src3 = transOprToExprOfSMSUBL ins bld addr
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := src3 .- (AST.sext 64<rt> src1 .* AST.sext 64<rt> src2))
  bld --!> insLen

let private checkOverflowOnDMul e1 e2 =
  let mask64 = numI64 0xFFFFFFFFFFFFFFFFL 64<rt>
  let bit32 = numI64 0x100000000L 64<rt>
  let cond = mask64 .- e1 .< e2
  AST.ite cond bit32 (AST.num0 64<rt>)

let private mul64BitReg src1 src2 bld =
  let struct (hiSrc1, loSrc1, hiSrc2, loSrc2) = tmpVars4 bld 64<rt>
  let struct (tHigh, tLow) = tmpVars2 bld 64<rt>
  let struct (tSrc1, tSrc2) = tmpVars2 bld 64<rt>
  let struct (src1IsNeg, src2IsNeg, signBit) = tmpVars3 bld 1<rt>
  let struct (pHigh, pMid, pLow) = tmpVars3 bld 64<rt>
  let struct (pMid1, pMid2) = tmpVars2 bld 64<rt>
  let struct (high, low) = tmpVars2 bld 64<rt>
  let n32 = numI32 32 64<rt>
  let mask32 = numI64 0xFFFFFFFFL 64<rt>
  let zero = numI32 0 64<rt>
  let one = numI32 1 64<rt>
  bld <+ (src1IsNeg := AST.xthi 1<rt> src1)
  bld <+ (src2IsNeg := AST.xthi 1<rt> src2)
  bld <+ (tSrc1 := AST.ite src1IsNeg (AST.neg src1) src1)
  bld <+ (tSrc2 := AST.ite src2IsNeg (AST.neg src2) src2)
  bld <+ (hiSrc1 := (tSrc1 >> n32) .& mask32) (* SRC1[63:32] *)
  bld <+ (loSrc1 := tSrc1 .& mask32) (* SRC1[31:0] *)
  bld <+ (hiSrc2 := (tSrc2 >> n32) .& mask32) (* SRC2[63:32] *)
  bld <+ (loSrc2 := tSrc2 .& mask32) (* SRC2[31:0] *)
  bld <+ (pHigh := hiSrc1 .* hiSrc2)
  bld <+ (pMid1 := hiSrc1 .* loSrc2)
  bld <+ (pMid2 := loSrc1 .* hiSrc2)
  bld <+ (pMid := pMid1 .+ pMid2)
  bld <+ (pLow := loSrc1 .* loSrc2)
  let overFlowBit = checkOverflowOnDMul (hiSrc1 .* loSrc2) (loSrc1 .* hiSrc2)
  bld <+ (high := pHigh .+ ((pMid .+ (pLow >> n32)) >> n32) .+ overFlowBit)
  bld <+ (low := pLow .+ ((pMid .& mask32) << n32))
  bld <+ (signBit := src1IsNeg <+> src2IsNeg)
  bld <+ (tHigh := AST.ite signBit (AST.not high) high)
  bld <+ (tLow := AST.ite signBit (AST.neg low) low)
  let carry = AST.ite (signBit .& (tLow == zero)) one zero
  bld <+ (tHigh := tHigh .+ carry)
  tHigh

let smulh ins insLen bld addr =
  let dst, src1, src2 = transThreeOprs ins bld addr
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := mul64BitReg src1 src2 bld)
  bld --!> insLen

let smull ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | ThreeOperands (_, _, OprSIMD (SIMDVecRegWithIdx _)) ->
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems o2
    let elements = 64<rt> / eSize
    let dblESz = eSize * 2
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let src1 = transSIMDOprVPart bld eSize part o2
    let src2 = transOprToExpr ins bld addr o3 |> AST.sext dblESz
    let result = Array.init elements (fun _ -> tmpVar bld dblESz)
    let prod = Array.map (fun s1 -> AST.sext dblESz s1 .* src2) src1
    Array.iter2 (fun r p -> bld <+ (r := p)) result prod
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  | ThreeOperands (OprSIMD (SIMDVecReg _), _, _) ->
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems o2
    let elements = 64<rt> / eSize
    let dblESz = eSize * 2
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let src1 = transSIMDOprVPart bld eSize part o2
    let src2 = transSIMDOprVPart bld eSize part o3
    let result = Array.init elements (fun _ -> tmpVar bld dblESz)
    Array.map2 (fun e1 e2 ->
      AST.sext dblESz e1 .* AST.sext dblESz e2) src1 src2
    |> Array.iter2 (fun r e -> bld <+ (r := e)) result
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  | _ ->
    let dst, src1, src2 = transThreeOprs ins bld addr
    bld <+ (dst := AST.sext 64<rt> src1 .* AST.sext 64<rt> src2)
  bld --!> insLen

let sshl ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, o1, o2) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  let inline shiftLeft e1 e2 =
    let shf = tmpVar bld eSize
    bld <+ (shf := AST.xtlo 8<rt> e2 |> AST.sext eSize)
    AST.ite (shf ?< AST.num0 eSize) (e1 ?>> AST.neg shf) (e1 << shf)
  match ins.Operands with
  | ThreeOperands (OprSIMD (SIMDFPScalarReg _), _, _) ->
    let src1 = transOprToExpr ins bld addr o1
    let src2 = transOprToExpr ins bld addr o2
    let result = shiftLeft src1 src2
    dstAssignScalar ins bld addr dst result eSize
  | _ ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let src1 = transSIMDOprToExpr bld eSize dataSize elements o1
    let src2 = transSIMDOprToExpr bld eSize dataSize elements o2
    let result = Array.map2 shiftLeft src1 src2
    dstAssignForSIMD dstA dstB result dataSize elements bld
  bld --!> insLen

let shift ins insLen bld addr opFn =
  let struct (dst, src, amt) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | ThreeOperands (OprSIMD (SIMDFPScalarReg _), _, _) ->
    let src = transOprToExpr ins bld addr src
    let amt = transOprToExpr ins bld addr amt
    dstAssignScalar ins bld addr dst (opFn src amt) eSize
  | _ ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let src = transSIMDOprToExpr bld eSize dataSize elements src
    let amt = transOprToExpr ins bld addr amt |> AST.xtlo eSize
    let result = Array.map (fun e -> opFn e amt) src
    dstAssignForSIMD dstA dstB result dataSize elements bld
  bld --!> insLen

let stlr ins insLen bld addr =
  let src, (bReg, offset) = transTwoOprsSepMem ins bld addr
  let address = tmpVar bld 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (address := bReg .+ offset)
  dstAssign ins.OprSize (AST.loadLE ins.OprSize address) src bld
  bld --!> insLen

let stlrb ins insLen bld addr =
  let src, (bReg, offset) = transTwoOprsSepMem ins bld addr
  let address = tmpVar bld 64<rt>
  let data = tmpVar bld 8<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (address := bReg .+ offset)
  bld <+ (data := AST.xtlo 8<rt> src)
  bld <+ (AST.loadLE 8<rt> address := data)
  bld --!> insLen

let stlx ins insLen bld addr size =
  let src1, src2, (bReg, offset) = transThreeOprsSepMem ins bld addr
  let address = tmpVar bld 64<rt>
  let data = tmpVar bld size
  bld <!-- (ins.Address, insLen)
  bld <+ (address := bReg .+ offset)
  bld <+ (data := AST.xtlo size src2)
  let status = exclusiveMonitorsPass bld address size data
  dstAssign 32<rt> src1 status bld
  bld --!> insLen

let stlxr ins insLen bld addr =
  let src1, src2, (bReg, offset) = transThreeOprsSepMem ins bld addr
  let address = tmpVar bld 64<rt>
  let data = tmpVar bld ins.OprSize
  bld <!-- (ins.Address, insLen)
  bld <+ (address := bReg .+ offset)
  bld <+ (data := AST.zext ins.OprSize src2)
  let status = exclusiveMonitorsPass bld address ins.OprSize data
  dstAssign 32<rt> src1 status bld
  bld --!> insLen

let stlxp ins insLen bld addr =
  let src1, src2, src3, (bReg, offset) = transFourOprsSepMem ins bld addr
  let address = tmpVar bld 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (address := bReg .+ offset)
  if ins.OprSize = 32<rt> then
    let data = tmpVar bld 64<rt>
    bld <+ (data := AST.concat (AST.xtlo 32<rt> src3) (AST.xtlo 32<rt> src2))
    let status = exclusiveMonitorsPass bld address 64<rt> data
    dstAssign 32<rt> src1 status bld
  else
    let status = exclusiveMonitorsPassPair bld address 64<rt> src2 src3
    dstAssign 32<rt> src1 status bld
  bld --!> insLen

let stnp ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let address = tmpVar bld 64<rt>
  let dByte = numI32 (RegType.toByteWidth ins.OprSize) 64<rt>
  match ins.OprSize with
  | 128<rt> ->
    let struct (src1, src2, src3) = getThreeOprs ins
    let struct (src1B, src1A) = transOprToExpr128 ins bld addr src1
    let struct (src2B, src2A) = transOprToExpr128 ins bld addr src2
    let bReg, offset = transOprToExpr ins bld addr src3 |> separateMemExpr
    let n8 = numI32 8 64<rt>
    bld <+ (address := bReg)
    bld <+ (address := address .+ offset)
    unmark bld address (memSizeToExpr ins.OprSize)
    bld <+ (AST.loadLE 64<rt> address := src1A)
    bld <+ (AST.loadLE 64<rt> (address .+ n8) := src1B)
    bld <+ (AST.loadLE 64<rt> (address .+ dByte) := src2A)
    bld <+ (AST.loadLE 64<rt> (address .+ dByte .+ n8) := src2B)
  | _ ->
    let src1, src2, (bReg, offset) = transThreeOprsSepMem ins bld addr
    bld <+ (address := bReg)
    bld <+ (address := address .+ offset)
    unmark bld address (memSizeToExpr ins.OprSize)
    bld <+ (AST.loadLE ins.OprSize address := src1)
    bld <+ (AST.loadLE ins.OprSize (address .+ dByte) := src2)
  bld --!> insLen

let stp ins insLen bld addr =
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  bld <!-- (ins.Address, insLen)
  let address = tmpVar bld 64<rt>
  let dByte = numI32 (RegType.toByteWidth ins.OprSize) 64<rt>
  match ins.OprSize with
  | 128<rt> ->
    let struct (src1, src2, src3) = getThreeOprs ins
    let struct (src1B, src1A) = transOprToExpr128 ins bld addr src1
    let struct (src2B, src2A) = transOprToExpr128 ins bld addr src2
    let bReg, offset = transOprToExpr ins bld addr src3 |> separateMemExpr
    let n8 = numI32 8 64<rt>
    bld <+ (address := bReg)
    bld <+ (address := if isPostIndex then address else address .+ offset)
    unmark bld address (memSizeToExpr ins.OprSize)
    bld <+ (AST.loadLE 64<rt> address := src1A)
    bld <+ (AST.loadLE 64<rt> (address .+ n8) := src1B)
    bld <+ (AST.loadLE 64<rt> (address .+ dByte) := src2A)
    bld <+ (AST.loadLE 64<rt> (address .+ dByte .+ n8) := src2B)
    if isWBack && isPostIndex then bld <+ (bReg := address .+ offset)
    else if isWBack then bld <+ (bReg := address) else ()
  | _ ->
    let src1, src2, (bReg, offset) = transThreeOprsSepMem ins bld addr
    bld <+ (address := bReg)
    bld <+ (address := if isPostIndex then address else address .+ offset)
    unmark bld address (memSizeToExpr ins.OprSize)
    bld <+ (AST.loadLE ins.OprSize address := src1)
    bld <+ (AST.loadLE ins.OprSize (address .+ dByte) := src2)
    if isWBack && isPostIndex then bld <+ (bReg := address .+ offset)
    else if isWBack then bld <+ (bReg := address) else ()
  bld --!> insLen

let str ins insLen bld addr =
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  bld <!-- (ins.Address, insLen)
  match ins.OprSize with
  | 128<rt> ->
    let struct (src1, src2) = getTwoOprs ins
    let struct (srcB, srcA) = transOprToExpr128 ins bld addr src1
    let bReg, offset = transOprToExpr ins bld addr src2 |> separateMemExpr
    let address = tmpVar bld 64<rt>
    bld <+ (address := bReg)
    bld <+ (address := if isPostIndex then address else address .+ offset)
    unmark bld address (memSizeToExpr ins.OprSize)
    bld <+ (AST.loadLE 64<rt> address := srcA)
    bld <+ (AST.loadLE 64<rt> (address .+ (numI32 8 64<rt>)) := srcB)
    if isWBack && isPostIndex then bld <+ (bReg := address .+ offset)
    else if isWBack then bld <+ (bReg := address) else ()
  | _ ->
    let src, (bReg, offset) = transTwoOprsSepMem ins bld addr
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld ins.OprSize
    bld <+ (address := bReg)
    bld <+ (address := if isPostIndex then address else address .+ offset)
    bld <+ (data := src)
    unmark bld address (memSizeToExpr ins.OprSize)
    bld <+ (AST.loadLE ins.OprSize address := data)
    if isWBack && isPostIndex then bld <+ (bReg := address .+ offset)
    else if isWBack then bld <+ (bReg := address) else ()
  bld --!> insLen

let strb ins insLen bld addr =
  let src, (bReg, offset) = transTwoOprsSepMem ins bld addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = tmpVar bld 64<rt>
  let data = tmpVar bld 8<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (address := bReg)
  bld <+ (address := if isPostIndex then address else address .+ offset)
  bld <+ (data := AST.xtlo 8<rt> src)
  unmark bld address (memSizeToExpr ins.OprSize)
  bld <+ (AST.loadLE 8<rt> address := data)
  if isWBack && isPostIndex then bld <+ (bReg := address .+ offset)
  else if isWBack then bld <+ (bReg := address) else ()
  bld --!> insLen

let strh ins insLen bld addr =
  let src, (bReg, offset) = transTwoOprsSepMem ins bld addr
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = tmpVar bld 64<rt>
  let data = tmpVar bld 16<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (address := bReg)
  bld <+ (address := if isPostIndex then address else address .+ offset)
  bld <+ (data := AST.xtlo 16<rt> src)
  unmark bld address (memSizeToExpr ins.OprSize)
  bld <+ (AST.loadLE 16<rt> address := data)
  if isWBack && isPostIndex then bld <+ (bReg := address .+ offset)
  else if isWBack then bld <+ (bReg := address) else ()
  bld --!> insLen

let sttrb ins insLen bld addr =
  let src, (bReg, offset) = transTwoOprsSepMem ins bld addr
  let address = tmpVar bld 64<rt>
  let data = tmpVar bld 8<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (address := bReg)
  bld <+ (address := address .+ offset)
  bld <+ (data := AST.xtlo 8<rt> src)
  unmark bld address (memSizeToExpr ins.OprSize)
  bld <+ (AST.loadLE 8<rt> address := data)
  bld --!> insLen

let stur ins insLen bld addr =
  let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
  let address = tmpVar bld 64<rt>
  let data = tmpVar bld ins.OprSize
  bld <!-- (ins.Address, insLen)
  match ins.OprSize with
  | 128<rt> ->
    let struct (src1, src2) = getTwoOprs ins
    let struct (src1B, src1A) = transOprToExpr128 ins bld addr src1
    let bReg, offset = transOprToExpr ins bld addr src2 |> separateMemExpr
    bld <+ (address := bReg)
    bld <+ (address := if isPostIndex then address else address .+ offset)
    unmark bld address (memSizeToExpr ins.OprSize)
    bld <+ (AST.loadLE 64<rt> address := src1A)
    bld <+ (AST.loadLE 64<rt> (address .+ (numI32 8 64<rt>)) := src1B)
    if isWBack && isPostIndex then bld <+ (bReg := address .+ offset)
    else if isWBack then bld <+ (bReg := address) else ()
  | _ ->
    let src, (bReg, offset) = transTwoOprsSepMem ins bld addr
    bld <+ (address := bReg)
    bld <+ (address := if isPostIndex then address else address .+ offset)
    bld <+ (data := src)
    unmark bld address (memSizeToExpr ins.OprSize)
    bld <+ (AST.loadLE ins.OprSize address := data)
    if isWBack && isPostIndex then bld <+ (bReg := address .+ offset)
    else if isWBack then bld <+ (bReg := address) else ()
  bld --!> insLen

let sturb ins insLen bld addr =
  let src, (bReg, offset) = transTwoOprsSepMem ins bld addr
  let address = tmpVar bld 64<rt>
  let data = tmpVar bld 8<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (address := bReg)
  bld <+ (address := address .+ offset)
  bld <+ (data := AST.xtlo 8<rt> src)
  unmark bld address (memSizeToExpr ins.OprSize)
  bld <+ (AST.loadLE 8<rt> address := data)
  bld --!> insLen

let sturh ins insLen bld addr =
  let src, (bReg, offset) = transTwoOprsSepMem ins bld addr
  let address = tmpVar bld 64<rt>
  let data = tmpVar bld 16<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (address := bReg)
  bld <+ (address := address .+ offset)
  bld <+ (data := AST.xtlo 16<rt> src)
  unmark bld address (memSizeToExpr ins.OprSize)
  bld <+ (AST.loadLE 16<rt> address := data)
  bld --!> insLen

let sub ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | TwoOperands (OprSIMD (SIMDFPScalarReg _) as dst, _) ->
    let struct (eSize, _, _) = getElemDataSzAndElems dst
    let _, src = transTwoOprs ins bld addr
    dstAssignScalar ins bld addr dst (AST.neg src) eSize
  | TwoOperands (OprSIMD (SIMDVecReg _) as o1, o2) ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o2
    let src = transSIMDOprToExpr bld eSize dataSize elements o2
    let result = Array.map (AST.neg) src
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | ThreeOperands (OprSIMD (SIMDFPScalarReg _) as dst, _, _)
      when ins.Opcode = Opcode.SUB ->
    let struct (eSize, _, _) = getElemDataSzAndElems dst
    let _, src1, src2 = transThreeOprs ins bld addr
    dstAssignScalar ins bld addr dst (src1 .- src2) eSize
  | ThreeOperands (OprSIMD (SIMDVecReg _) as o1, o2, o3)
      when ins.Opcode = Opcode.SUB ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
    let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
    let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
    let result = Array.map2 (.-) src1 src2
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | _ ->
    let dst, src1, src2 = transOprToExprOfSUB ins bld addr
    let result, _ = addWithCarry src1 src2 (AST.num1 ins.OprSize) ins.OprSize
    dstAssign ins.OprSize dst result bld
  bld --!> insLen

let subs ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let dst, src1, src2 = transOprToExprOfSUBS ins bld addr
  let result, (n, z, c, v) =
    addWithCarry src1 src2 (AST.num1 ins.OprSize) ins.OprSize
  bld <+ (regVar bld R.N := n)
  bld <+ (regVar bld R.Z := z)
  bld <+ (regVar bld R.C := c)
  bld <+ (regVar bld R.V := v)
  dstAssign ins.OprSize dst result bld
  bld --!> insLen

let svc ins insLen bld =
  let n =
    match ins.Operands with
    | OneOperand (OprImm n) -> int n
    | _ -> raise InvalidOperandException
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.sideEffect (Interrupt n))
  bld --!> insLen

let sxtb ins insLen bld addr =
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr ins bld addr dst
  let src = transOprToExpr ins bld addr src
  let src = if ins.OprSize = 64<rt> then unwrapReg src else src
  sbfm ins insLen bld addr dst src (OprImm 0L) (OprImm 7L)

let sxth ins insLen bld addr =
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr ins bld addr dst
  let src = transOprToExpr ins bld addr src
  let src = if ins.OprSize = 64<rt> then unwrapReg src else src
  sbfm ins insLen bld addr dst src (OprImm 0L) (OprImm 15L)

let sxtw ins insLen bld addr =
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr ins bld addr dst
  let src = transOprToExpr ins bld addr src |> unwrapReg
  sbfm ins insLen bld addr dst src (OprImm 0L) (OprImm 31L)

let tbl ins insLen bld addr = (* FIMXE *)
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
  let elements = dataSize / 8<rt>
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
  let src =
    match src1 with
    | OprSIMDList simds ->
      Array.map (fun simd ->
        let struct (dstB, dstA) = transOprToExpr128 ins bld addr (OprSIMD simd)
        [| dstA; dstB |]) (List.toArray simds)
    | _ -> raise InvalidOperandException
    |> Array.concat
  let indices = transSIMDOprToExpr bld 8<rt> dataSize elements src2
  let n8 = numI32 8 8<rt>
  let nFF = numI32 -1 8<rt> |> AST.zext 64<rt>
  let zeros = tmpVar bld eSize
  bld <+ (zeros := AST.num0 eSize)
  let inline elem expr idx =
    let idx = idx .% n8
    ((expr >> (AST.zext 64<rt> (idx .* n8))) .& nFF) |> AST.xtlo 8<rt>
  let lenExpr = tmpVar bld 8<rt>
  let len = Array.length src
  bld <+ (lenExpr := numI32 (len / 2 * 16) 8<rt>)
  let inline limit i expr index =
    let dst =
      if i < 8 then (dstA >> (numI32 (i * 8) 64<rt>)) .& nFF
      else (dstB >> (numI32 (i * 8) 64<rt>)) .& nFF
      |> AST.xtlo 8<rt>
    AST.ite (index .< lenExpr) (elem expr index) dst
  let getElem i idx =
    if len = 2 then
      AST.ite (idx .< numI32 8 8<rt>) (limit i src[0] idx)
        (AST.ite (idx .< numI32 16 8<rt>) (limit i src[1] idx) zeros)
    elif len = 4 then
      AST.ite (idx .< numI32 8 8<rt>) (limit i src[0] idx)
        (AST.ite (idx .< numI32 16 8<rt>) (limit i src[1] idx)
          (AST.ite (idx .< numI32 24 8<rt>) (limit i src[2] idx)
            (AST.ite (idx .< numI32 32 8<rt>) (limit i src[3] idx) zeros)))
    elif len = 6 then
      AST.ite (idx .< numI32 8 8<rt>) (limit i src[0] idx)
        (AST.ite (idx .< numI32 16 8<rt>) (limit i src[1] idx)
          (AST.ite (idx .< numI32 24 8<rt>) (limit i src[2] idx)
            (AST.ite (idx .< numI32 32 8<rt>) (limit i src[3] idx)
              (AST.ite (idx .< numI32 40 8<rt>) (limit i src[4] idx)
                (AST.ite (idx .< numI32 48 8<rt>) (limit i src[5] idx)
                  zeros)))))
    elif len = 8 then
      AST.ite (idx .< numI32 8 8<rt>) (limit i src[0] idx)
        (AST.ite (idx .< numI32 16 8<rt>) (limit i src[1] idx)
          (AST.ite (idx .< numI32 24 8<rt>) (limit i src[2] idx)
            (AST.ite (idx .< numI32 32 8<rt>) (limit i src[3] idx)
              (AST.ite (idx .< numI32 40 8<rt>) (limit i src[4] idx)
                (AST.ite (idx .< numI32 48 8<rt>) (limit i src[5] idx)
                  (AST.ite (idx .< numI32 56 8<rt>) (limit i src[6] idx)
                    (AST.ite (idx .< numI32 64 8<rt>) (limit i src[7] idx)
                      zeros)))))))
    else failwith "Invalid number of registers."
  let result = Array.init elements (fun _ -> tmpVar bld eSize)
  Array.mapi getElem indices
  |> Array.iter2 (fun e1 e2 -> bld <+ (e1 := e2)) result
  dstAssignForSIMD dstA dstB result dataSize elements bld
  bld --!> insLen

let tbnz ins insLen bld addr =
  let test, imm, label = transThreeOprs ins bld addr
  let pc = numU64 (ins:InsInfo).Address bld.RegType
  let fall = pc .+ numU32 insLen 64<rt>
  let cond = (test >> imm .& AST.num1 ins.OprSize) == AST.num1 ins.OprSize
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.intercjmp cond (pc .+ label) fall)
  bld --!> insLen

let tbz ins insLen bld addr =
  let test, imm, label = transThreeOprs ins bld addr
  let pc = numU64 (ins:InsInfo).Address bld.RegType
  let fall = pc .+ numU32 insLen 64<rt>
  let cond = (test >> imm .& AST.num1 ins.OprSize) == AST.num0 ins.OprSize
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.intercjmp cond (pc .+ label) fall)
  bld --!> insLen

let trn1 ins insLen bld addr =
  let struct (o1, o2, o3) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
  let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
  let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
  let result = Array.init elements (fun _ -> tmpVar bld eSize)
  bld <!-- (ins.Address, insLen)
  Array.iteri (fun i r ->
    bld <+ (r := if i % 2 = 0 then src1[i] else src2[i - 1])) result
  dstAssignForSIMD dstA dstB result dataSize elements bld
  bld --!> insLen

let trn2 ins insLen bld addr =
  let struct (o1, o2, o3) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
  let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
  let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
  let result = Array.init elements (fun _ -> tmpVar bld eSize)
  bld <!-- (ins.Address, insLen)
  Array.iteri (fun i r ->
    bld <+ (r := if i % 2 = 1 then src2[i] else src1[i + 1])) result
  dstAssignForSIMD dstA dstB result dataSize elements bld
  bld --!> insLen

let tst ins insLen bld addr =
  let src1, src2 = transOprToExprOfTST ins bld addr
  let result = tmpVar bld ins.OprSize
  bld <!-- (ins.Address, insLen)
  bld <+ (result := src1 .& src2)
  bld <+ (regVar bld R.N := AST.xthi 1<rt> result)
  bld <+ (regVar bld R.Z := result == AST.num0 ins.OprSize)
  bld <+ (regVar bld R.C := AST.b0)
  bld <+ (regVar bld R.V := AST.b0)
  bld --!> insLen

let uabal ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (eSize, part, _) = getElemDataSzAndElems src1
  let elements = 64<rt> / eSize
  let dblESz = eSize * 2
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
  let dst = transSIMDOprToExpr bld dblESz 128<rt> elements dst
  let s1 = transSIMDOprVPart bld eSize part src1
  let s2 = transSIMDOprVPart bld eSize part src2
  let result = Array.init elements (fun _ -> tmpVar bld dblESz)
  Array.iter2 (fun r e -> bld <+ (r := e)) result dst
  let dblExt e = AST.zext dblESz e
  Array.map2 (fun e1 e2 ->
    AST.ite (e1 .>= e2) (dblExt e1 .- dblExt e2) (dblExt e2 .- dblExt e1)) s1 s2
  |> Array.iter2 (fun r absDiff -> bld <+ (r := r .+ absDiff)) result
  dstAssignForSIMD dstA dstB result 128<rt> elements bld
  bld --!> insLen

let uabdl ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (eSize, part, _) = getElemDataSzAndElems src1
  let elements = 64<rt> / eSize
  let dblESz = eSize * 2
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
  let s1 = transSIMDOprVPart bld eSize part src1
  let s2 = transSIMDOprVPart bld eSize part src2
  let result = Array.init elements (fun _ -> tmpVar bld dblESz)
  let dblExt e = AST.zext dblESz e
  Array.map2 (fun e1 e2 ->
    AST.ite (e1 .>= e2) (dblExt e1 .- dblExt e2) (dblExt e2 .- dblExt e1)) s1 s2
  |> Array.iter2 (fun r absDiff -> bld <+ (r := absDiff)) result
  dstAssignForSIMD dstA dstB result 128<rt> elements bld
  bld --!> insLen

let uadalp ins insLen bld addr =
  let struct (o1, src) = getTwoOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
  bld <!-- (ins.Address, insLen)
  let dst = transSIMDOprToExpr bld (eSize * 2) dataSize (elements / 2) o1
  let src = transSIMDOprToExpr bld eSize dataSize elements src
            |> Array.map (AST.zext (2 * eSize))
  let result = Array.init (elements / 2) (fun _ -> tmpVar bld (2 * eSize))
  Array.iter2 (fun dst res -> bld <+ (res := dst)) dst result
  let sum = src |> Array.chunkBySize 2 |> Array.map (fun e -> e[0] .+ e[1])
  Array.iter2 (fun r s -> bld <+ (r := r .+ s)) result sum
  let elems = elements / 4
  let srcB =
    if dataSize = 128<rt> then AST.revConcat (Array.sub result elems elems)
    else AST.num0 64<rt>
  let srcA =
    if dataSize = 128<rt> then AST.revConcat (Array.sub result 0 elems)
    else AST.revConcat result
  dstAssign128 ins bld addr o1 srcA srcB dataSize
  bld --!> insLen

let saddl ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (eSize, part, _) = getElemDataSzAndElems src2
  let elements = 64<rt> / eSize
  let dblESz = eSize * 2
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
  let src1 = transSIMDOprVPart bld eSize part src1
  let src2 = transSIMDOprVPart bld eSize part src2
  let result = Array.init elements (fun _ -> tmpVar bld dblESz)
  Array.map2 (fun e1 e2 -> AST.sext dblESz e1 .+ AST.sext dblESz e2) src1 src2
  |> Array.iter2 (fun r e -> bld <+ (r := e)) result
  dstAssignForSIMD dstA dstB result 128<rt> elements bld
  bld --!> insLen

let saddw ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (eSize, part, _) = getElemDataSzAndElems src2
  let elements = 64<rt> / eSize
  let dblESz = eSize * 2
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
  let src1 = transSIMDOprToExpr bld dblESz 128<rt> elements src1
  let src2 = transSIMDOprVPart bld eSize part src2
  let result = Array.init elements (fun _ -> tmpVar bld dblESz)
  Array.map2 (fun e1 e2 -> e1 .+ AST.sext dblESz e2) src1 src2
  |> Array.iter2 (fun r e -> bld <+ (r := e)) result
  dstAssignForSIMD dstA dstB result 128<rt> elements bld
  bld --!> insLen

let saddlp ins insLen bld addr =
  let struct (dst, src) = getTwoOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
  let sumArr = Array.init (elements / 2) (fun _ -> tmpVar bld (2 * eSize))
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
  let srcArr =
    transSIMDOprToExpr bld eSize dataSize elements src
    |> Array.map (AST.sext (2 * eSize)) |> Array.chunkBySize 2
    |> Array.map (fun e -> e[0] .+ e[1])
  bld <!-- (ins.Address, insLen)
  Array.iter2 (fun sum src -> bld <+ (sum := src)) sumArr srcArr
  dstAssignForSIMD dstA dstB sumArr dataSize (elements / 2) bld
  bld --!> insLen

let saddlv ins insLen bld addr =
  let struct (dst, src) = getTwoOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
  let src =
    transSIMDOprToExpr bld eSize dataSize elements src
    |> Array.map (AST.sext (2 * eSize))
  let sum = tmpVar bld (2 * eSize)
  bld <!-- (ins.Address, insLen)
  bld <+ (sum := src[0])
  Array.sub src 1 (elements - 1)
  |> Array.iter (fun e -> bld <+ (sum := sum .+ e))
  dstAssignScalar ins bld addr dst sum (2 * eSize)
  bld --!> insLen

let uaddl ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (eSize, part, _) = getElemDataSzAndElems src2
  let elements = 64<rt> / eSize
  let dblESz = eSize * 2
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
  let src1 = transSIMDOprVPart bld eSize part src1
  let src2 = transSIMDOprVPart bld eSize part src2
  let result = Array.init elements (fun _ -> tmpVar bld dblESz)
  Array.map2 (fun e1 e2 -> AST.zext dblESz e1 .+ AST.zext dblESz e2) src1 src2
  |> Array.iter2 (fun r e -> bld <+ (r := e)) result
  dstAssignForSIMD dstA dstB result 128<rt> elements bld
  bld --!> insLen

let uaddw ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (eSize, part, _) = getElemDataSzAndElems src2
  let elements = 64<rt> / eSize
  let dblESz = eSize * 2
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
  let src1 = transSIMDOprToExpr bld dblESz 128<rt> elements src1
  let src2 = transSIMDOprVPart bld eSize part src2
  let result = Array.init elements (fun _ -> tmpVar bld dblESz)
  Array.map2 (fun e1 e2 -> e1 .+ AST.zext dblESz e2) src1 src2
  |> Array.iter2 (fun r e -> bld <+ (r := e)) result
  dstAssignForSIMD dstA dstB result 128<rt> elements bld
  bld --!> insLen

let uaddlp ins insLen bld addr =
  let struct (dst, src) = getTwoOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
  let sumArr = Array.init (elements / 2) (fun _ -> tmpVar bld (2 * eSize))
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
  let srcArr = transSIMDOprToExpr bld eSize dataSize elements src
            |> Array.map (AST.zext (2 * eSize))
            |> Array.chunkBySize 2
            |> Array.map (fun e -> e[0] .+ e[1])
  bld <!-- (ins.Address, insLen)
  Array.iter2 (fun sum src -> bld <+ (sum := src)) sumArr srcArr
  dstAssignForSIMD dstA dstB sumArr dataSize (elements / 2) bld
  bld --!> insLen

let uaddlv ins insLen bld addr =
  let struct (dst, src) = getTwoOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
  let src = transSIMDOprToExpr bld eSize dataSize elements src
            |> Array.map (AST.zext (2 * eSize))
  let sum = tmpVar bld (2 * eSize)
  bld <!-- (ins.Address, insLen)
  bld <+ (sum := src[0])
  Array.sub src 1 (elements - 1)
  |> Array.iter (fun e -> bld <+ (sum := sum .+ e))
  dstAssignScalar ins bld addr dst sum (2 * eSize)
  bld --!> insLen

let ubfm ins insLen bld addr dst src immr imms =
  let oSz = ins.OprSize
  let width = oprSzToExpr oSz
  let struct (wmask, tmask) = decodeBitMasks immr imms (int oSz)
  let dst = transOprToExpr ins bld addr dst
  let src = transOprToExpr ins bld addr src
  let immr = transOprToExpr ins bld addr immr
  let bot = tmpVar bld oSz
  bld <!-- (ins.Address, insLen)
  bld <+ (bot := rorForIR src immr width .& (numI64 wmask oSz))
  dstAssign ins.OprSize dst (bot .& (numI64 tmask oSz)) bld
  bld --!> insLen

let ubfiz ins insLen bld addr =
  let struct (dst, src, lsb, width) = getFourOprs ins
  let immr =
    ((getImmValue lsb * -1L) &&& 0x3F) % (int64 ins.OprSize) |> OprImm
  let imms = getImmValue width - 1L |> OprImm
  ubfm ins insLen bld addr dst src immr imms

let ubfx ins insLen bld addr =
  let struct (dst, src, lsb, width) = getFourOprs ins
  let imms = (getImmValue lsb) + (getImmValue width) - 1L |> OprImm
  ubfm ins insLen bld addr dst src lsb imms

let udiv ins insLen bld addr =
  let dst, src1, src2 = transThreeOprs ins bld addr
  let num0 = AST.num0 ins.OprSize
  let cond1 = AST.eq src2 num0
  let divSrc = src1 ./ src2
  bld <!-- (ins.Address, insLen)
  let result = AST.ite cond1 num0 divSrc
  dstAssign ins.OprSize dst result bld
  bld --!> insLen

let umaddl ins insLen bld addr =
  let dst, src1, src2, src3 = transFourOprs ins bld addr
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := src3 .+ (AST.zext 64<rt> src1 .* AST.zext 64<rt> src2))
  bld --!> insLen

let smlal ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (eSize, part, _) = getElemDataSzAndElems src1
  let dataSize = 64<rt>
  let elements = dataSize / eSize
  let dblESz = eSize * 2
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
  let dst = transSIMDOprToExpr bld dblESz 128<rt> elements dst
  let opr1 = transSIMDOprVPart bld eSize part src1
  let result = Array.init elements (fun _ -> tmpVar bld dblESz)
  match ins.Operands with
  | ThreeOperands (_, _, OprSIMD (SIMDVecReg _)) ->
    let opr2 = transSIMDOprVPart bld eSize part src2
    Array.map3 (fun e1 e2 e3 ->
      e3 .+ (AST.sext dblESz e1 .* AST.sext dblESz e2)) opr1 opr2 dst
    |> Array.iter2 (fun r e -> bld <+ (r := e)) result
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  | _ ->
    let opr2 = tmpVar bld dblESz
    bld <+ (opr2 := transOprToExpr ins bld addr src2 |> AST.sext dblESz)
    Array.map2 (fun e1 e3 -> e3 .+ (AST.sext dblESz e1 .* opr2)) opr1 dst
    |> Array.iter2 (fun r e -> bld <+ (r := e)) result
    dstAssignForSIMD dstA dstB result (2 * dataSize) elements bld
  bld --!> insLen

let smlsl ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (eSize, part, _) = getElemDataSzAndElems src1
  let dataSize = 64<rt>
  let elements = dataSize / eSize
  let dblESz = eSize * 2
  let dblDSize = dataSize * 2
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
  let opr1 = transSIMDOprVPart bld eSize part src1
  let opr3 = transSIMDOprToExpr bld dblESz 128<rt> elements dst
  let result = Array.init elements (fun _ -> tmpVar bld dblESz)
  match ins.Operands with
  | ThreeOperands (_, _, OprSIMD (SIMDVecReg _)) ->
    let opr2 = transSIMDOprVPart bld eSize part src2
    Array.map3 (fun e1 e2 e3 ->
      e3 .- (AST.sext dblESz e1 .* AST.sext dblESz e2)) opr1 opr2 opr3
    |> Array.iter2 (fun r e -> bld <+ (r := e)) result
    dstAssignForSIMD dstA dstB result dblDSize elements bld
  | _ ->
    let opr2 = tmpVar bld dblESz
    bld <+ (opr2 := transOprToExpr ins bld addr src2 |> AST.sext dblESz)
    Array.map2 (fun e1 e3 ->
      AST.sext dblESz e3 .- (AST.sext dblESz e1 .* opr2)) opr1 opr3
    |> Array.iter2 (fun r e -> bld <+ (r := e)) result
    dstAssignForSIMD dstA dstB result dblDSize elements bld
  bld --!> insLen

let private ssatQMulH bld e1 e2 (eSize: int<rt>) =
  let dblESz = 2 * eSize
  let shfAmt = numI32 (int eSize) dblESz
  let product =
    AST.shl (AST.sext dblESz e1 .* AST.sext dblESz e2) (AST.num1 dblESz)
  let sign1 = AST.xthi 1<rt> e1
  let sign2 = AST.xthi 1<rt> e2
  let input = AST.ite (sign1 != sign2) (product ?>> shfAmt) (product >> shfAmt)
  signedSatQ bld input eSize

let sqdmulh ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (o1, o2, o3) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
  match ins.Operands with
  | ThreeOperands (OprSIMD (SIMDVecReg _), _, OprSIMD (SIMDVecRegWithIdx _)) ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
    let src2 = transOprToExpr ins bld addr o3
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    Array.map (fun e1 -> ssatQMulH bld e1 src2 eSize) src1
    |> Array.iter2 (fun res prod -> bld <+ (res := prod)) result
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | ThreeOperands (OprSIMD (SIMDVecReg _), _, _) ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
    let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    Array.map2 (fun e1 e2 -> ssatQMulH bld e1 e2 eSize) src1 src2
    |> Array.iter2 (fun res prod -> bld <+ (res := prod)) result
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | ThreeOperands (OprSIMD (SIMDFPScalarReg _), _, _) ->
    let src1 = transOprToExpr ins bld addr o2
    let src2 = transOprToExpr ins bld addr o3
    let result = ssatQMulH bld src1 src2 eSize
    dstAssignScalar ins bld addr o1 result eSize
  | _ -> raise InvalidOperandException
  bld --!> insLen

let private ssatQMulL bld e1 e2 (eSize: int<rt>) =
  let dblESz = 2 * eSize
  let bitQC = AST.extract (regVar bld R.FPSR) 1<rt> 27
  let sign1 = AST.xthi 1<rt> e1
  let sign2 = AST.xthi 1<rt> e2
  let mult = AST.sext dblESz e1 .* AST.sext dblESz e2
  let product = AST.shl mult (AST.num1 dblESz)
  let overflow =
    let overflowBit = AST.extract mult 1<rt> (int dblESz - 2)
    sign1 .& sign2 .& overflowBit
  let underflow =
    let srcIsNotZero = (AST.num0 eSize != e1) .& (AST.num0 eSize != e2)
    srcIsNotZero .& (sign1 != sign2) .& (AST.not <| AST.xthi 1<rt> product)
  let max = getIntMax dblESz false
  let min = AST.not max
  bld <+ (bitQC := bitQC .| overflow .| underflow)
  AST.ite overflow max (AST.ite underflow min product)

let sqdmull ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (o1, o2, o3) = getThreeOprs ins
  let struct (eSize, part, _) = getElemDataSzAndElems o2
  match ins.Operands with
  | ThreeOperands (OprSIMD (SIMDVecReg _), _, OprSIMD (SIMDVecRegWithIdx _)) ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let src1 = transSIMDOprVPart bld eSize part o2
    let src2 = transOprToExpr ins bld addr o3
    let elements = 64<rt> / eSize
    let result = Array.init elements (fun _ -> tmpVar bld (2 * eSize))
    Array.map (fun e1 -> ssatQMulL bld e1 src2 eSize) src1
    |> Array.iter2 (fun res prod -> bld <+ (res := prod)) result
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  | ThreeOperands (OprSIMD (SIMDVecReg _), _, _) ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let src1 = transSIMDOprVPart bld eSize part o2
    let src2 = transSIMDOprVPart bld eSize part o3
    let elements = 64<rt> / eSize
    let result = Array.init elements (fun _ -> tmpVar bld (2 * eSize))
    Array.map2 (fun e1 e2 -> ssatQMulL bld e1 e2 eSize) src1 src2
    |> Array.iter2 (fun res prod -> bld <+ (res := prod)) result
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  | ThreeOperands (OprSIMD (SIMDFPScalarReg _), _, _) ->
    let src1 = transOprToExpr ins bld addr o2
    let src2 = transOprToExpr ins bld addr o3
    let result = ssatQMulL bld src1 src2 eSize
    dstAssignScalar ins bld addr o1 result eSize
  | _ -> raise InvalidOperandException
  bld --!> insLen

let private ssatQMAdd bld src1 src2 dstElm eSize =
  let bitQC = AST.extract (regVar bld R.FPSR) 1<rt> 27
  let max = getIntMax (2 * eSize) false
  let min = AST.not max
  let product = ssatQMulL bld src1 src2 eSize
  let accum = dstElm .+ product
  let o1 = AST.xthi 1<rt> dstElm
  let o2 = AST.xthi 1<rt> product
  let r = AST.xthi 1<rt> accum
  let outOfRange = (o1 == o2) .& (o1 <+> r)
  let overflow = (o1 == AST.b0) .& outOfRange
  let underflow = (o1 == AST.b1) .& outOfRange
  bld <+ (bitQC := bitQC .| overflow .| underflow)
  AST.ite overflow max (AST.ite underflow min accum)

let sqdmlal ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (o1, o2, o3) = getThreeOprs ins
  let struct (eSize, part, _) = getElemDataSzAndElems o2
  match ins.Operands with
  | ThreeOperands (OprSIMD (SIMDVecReg _), _, OprSIMD (SIMDVecRegWithIdx _)) ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let elements = 64<rt> / eSize
    let dblESz = 2 * eSize
    let dst = transSIMDOprToExpr bld dblESz 128<rt> elements o1
    let src1 = transSIMDOprVPart bld eSize part o2
    let src2 = transOprToExpr ins bld addr o3
    let result = Array.init elements (fun _ -> tmpVar bld dblESz)
    Array.map2 (fun e1 e2 -> ssatQMAdd bld e1 src2 e2 eSize) src1 dst
    |> Array.iter2 (fun res accum -> bld <+ (res := accum)) result
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  | ThreeOperands (OprSIMD (SIMDVecReg _), _, _) ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let elements = 64<rt> / eSize
    let dblESz = 2 * eSize
    let dst = transSIMDOprToExpr bld dblESz 128<rt> elements o1
    let src1 = transSIMDOprVPart bld eSize part o2
    let src2 = transSIMDOprVPart bld eSize part o3
    let result = Array.init elements (fun _ -> tmpVar bld dblESz)
    Array.map3 (fun e1 e2 e3 -> ssatQMAdd bld e1 e2 e3 eSize) src1 src2 dst
    |> Array.iter2 (fun res accum -> bld <+ (res := accum)) result
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  | ThreeOperands (OprSIMD (SIMDFPScalarReg _), _, _) ->
    let dst = transOprToExpr ins bld addr o1
    let src1 = transOprToExpr ins bld addr o2
    let src2 = transOprToExpr ins bld addr o3
    let result = ssatQMAdd bld src1 src2 dst eSize
    dstAssignScalar ins bld addr o1 result eSize
  | _ -> raise InvalidOperandException
  bld --!> insLen

let umlal ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (eSize, part, _) = getElemDataSzAndElems src1
  let dataSize = 64<rt>
  let elements = dataSize / eSize
  let dblESz = eSize * 2
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
  let dst = transSIMDOprToExpr bld dblESz 128<rt> elements dst
  let opr1 = transSIMDOprVPart bld eSize part src1
  let result = Array.init elements (fun _ -> tmpVar bld dblESz)
  match ins.Operands with
  | ThreeOperands (_, _, OprSIMD (SIMDVecReg _)) ->
    let opr2 = transSIMDOprVPart bld eSize part src2
    Array.map3 (fun e1 e2 e3 ->
      e3 .+ (AST.zext dblESz e1 .* AST.zext dblESz e2)) opr1 opr2 dst
    |> Array.iter2 (fun r e -> bld <+ (r := e)) result
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  | _ ->
    let opr2 = tmpVar bld dblESz
    bld <+ (opr2 := transOprToExpr ins bld addr src2 |> AST.zext dblESz)
    Array.map2 (fun e1 e3 -> e3 .+ (AST.zext dblESz e1 .* opr2)) opr1 dst
    |> Array.iter2 (fun r e -> bld <+ (r := e)) result
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  bld --!> insLen

let umlsl ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (eSize, part, _) = getElemDataSzAndElems src1
  let dataSize = 64<rt>
  let elements = dataSize / eSize
  let dblESz = eSize * 2
  let dblDSize = dataSize * 2
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
  let opr1 = transSIMDOprVPart bld eSize part src1
  let opr3 = transSIMDOprToExpr bld dblESz 128<rt> elements dst
  let result = Array.init elements (fun _ -> tmpVar bld dblESz)
  match ins.Operands with
  | ThreeOperands (_, _, OprSIMD (SIMDVecReg _)) ->
    let opr2 = transSIMDOprVPart bld eSize part src2
    Array.map3 (fun e1 e2 e3 ->
      e3 .- (AST.zext dblESz e1 .* AST.zext dblESz e2)) opr1 opr2 opr3
    |> Array.iter2 (fun r e -> bld <+ (r := e)) result
    dstAssignForSIMD dstA dstB result dblDSize elements bld
  | _ ->
    let opr2 = tmpVar bld dblESz
    bld <+ (opr2 := transOprToExpr ins bld addr src2 |> AST.zext dblESz)
    Array.map2 (fun e1 e3 -> e3 .- (AST.zext dblESz e1 .* opr2)) opr1 opr3
    |> Array.iter2 (fun r e -> bld <+ (r := e)) result
    dstAssignForSIMD dstA dstB result dblDSize elements bld
  bld --!> insLen

let umov ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let dst, src = transTwoOprs ins bld addr
  dstAssign ins.OprSize dst src bld
  bld --!> insLen

let umsubl ins insLen bld addr =
  let dst, src1, src2, src3 = transOprToExprOfUMADDL ins bld addr
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := src3 .- (AST.zext 64<rt> src1 .* AST.zext 64<rt> src2))
  bld --!> insLen

let umulh ins insLen bld addr =
  let dst, src1, src2 = transThreeOprs ins bld addr
  let struct (hiSrc1, loSrc1, hiSrc2, loSrc2) = tmpVars4 bld 64<rt>
  let struct (pMid, pLow) = tmpVars2 bld 64<rt>
  let struct (hi1Lo2, lo1Hi2) = tmpVars2 bld 64<rt>
  let n32 = numI32 32 64<rt>
  let mask = numI64 0xFFFFFFFFL 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (hiSrc1 := (src1 >> n32) .& mask) (* SRC1[63:32] *)
  bld <+ (loSrc1 := src1 .& mask) (* SRC1[31:0] *)
  bld <+ (hiSrc2 := (src2 >> n32) .& mask) (* SRC2[63:32] *)
  bld <+ (loSrc2 := src2 .& mask) (* SRC2[31:0] *)
  let pHigh = hiSrc1 .* hiSrc2
  bld <+ (hi1Lo2 := hiSrc1 .* loSrc2)
  bld <+ (lo1Hi2 := loSrc1 .* hiSrc2)
  bld <+ (pMid := hi1Lo2 .+ lo1Hi2)
  bld <+ (pLow := loSrc1 .* loSrc2)
  let high = pHigh .+ ((pMid .+ (pLow  >> n32)) >> n32)
  bld <+ (dst := high .+ checkOverflowOnDMul hi1Lo2 lo1Hi2)
  bld --!> insLen

let umull ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  match ins.Operands with
  | ThreeOperands (_, _, OprSIMD (SIMDVecRegWithIdx _)) ->
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems o2
    let elements = 64<rt> / eSize
    let dblESz = eSize * 2
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let opr1 = transSIMDOprVPart bld eSize part o2
    let opr2 = tmpVar bld dblESz
    bld <+ (opr2 := transOprToExpr ins bld addr o3 |> AST.zext dblESz)
    let result = Array.init elements (fun _ -> tmpVar bld dblESz)
    Array.map (fun e1 -> AST.zext dblESz e1 .* opr2) opr1
    |> Array.iter2 (fun r e -> bld <+ (r := e)) result
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  | ThreeOperands (OprSIMD (SIMDVecReg _), _, _) ->
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (eSize, part, _) = getElemDataSzAndElems o2
    let elements = 64<rt> / eSize
    let dblESz = eSize * 2
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let opr1 = transSIMDOprVPart bld eSize part o2
    let opr2 = transSIMDOprVPart bld eSize part o3
    let result = Array.init elements (fun _ -> tmpVar bld dblESz)
    Array.map2 (fun e1 e2 -> AST.zext dblESz e1 .* AST.zext dblESz e2) opr1 opr2
    |> Array.iter2 (fun r e -> bld <+ (r := e)) result
    dstAssignForSIMD dstA dstB result 128<rt> elements bld
  | _ ->
    let dst, src1, src2 = transThreeOprs ins bld addr
    bld <+ (dst := AST.zext 64<rt> src1 .* AST.zext 64<rt> src2)
  bld --!> insLen

let uqadd ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (o1, o2, o3) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
  let inline satQ64 src1 src2 =
    let input = src1 .+ src2
    let bitQC = AST.extract (regVar bld R.FPSR) 1<rt> 27
    let max = numU64 0xffffffff_ffffffffUL 64<rt>
    let overflow = input .< src1
    bld <+ (bitQC := bitQC .| overflow)
    AST.ite overflow max input
  match ins.Operands with
  | ThreeOperands (OprSIMD (SIMDVecReg _), _, _) ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
    let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    if eSize = 64<rt> then
      Array.map2 satQ64 src1 src2
      |> Array.iter2 (fun element i -> bld <+ (element := i)) result
    else
      Array.map2 (fun e1 e2 ->
        AST.zext (2 * eSize) e1 .+ AST.zext (2 * eSize) e2) src1 src2
      |> Array.iter2 (fun element i ->
        bld <+ (element := satQ bld i eSize true)) result
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | ThreeOperands (OprSIMD (SIMDFPScalarReg _), _, _) ->
    let src1 = transOprToExpr ins bld addr o2
    let src2 = transOprToExpr ins bld addr o3
    let result =
      if eSize = 64<rt> then satQ64 src1 src2
      else
        let input = AST.zext (2 * eSize) src1 .+ AST.zext (2 * eSize) src2
        satQ bld input eSize true
    dstAssignScalar ins bld addr o1 result eSize
  | _ -> raise InvalidOperandException
  bld --!> insLen

let private getRndConst amt eSize =
  let n1 = AST.num1 eSize
  let amt = AST.neg amt .- n1
  let isNeg = amt ?< AST.num0 eSize
  AST.ite isNeg (n1 >> AST.neg amt) (n1 << amt)

let private usatQRShl bld expr amt eSize =
  let bitQC = AST.extract (regVar bld R.FPSR) 1<rt> 27
  let max = numU64 0xFFFFFFFFFFFFFFFFUL eSize
  let min = AST.num0 eSize
  let msb = numU64 (1UL <<< (int eSize - 1)) eSize
  let eESz = numI32 (int eSize - 1) eSize
  let n0 = AST.num0 eSize
  let n1 = AST.num1 eSize
  let nAmt = AST.neg amt
  let struct (isNeg, isOver, isSat) = tmpVars3 bld 1<rt>
  let struct (hBit, rExpr, rConst) = tmpVars3 bld eSize
  bld <+ (isNeg := amt ?< AST.num0 eSize)
  bld <+ (rConst := getRndConst amt eSize)
  bld <+ (isOver := expr .> (max .- rConst))
  bld <+ (rExpr := expr .+ rConst)
  let h = highestSetBitForIR rExpr (int eSize) eSize bld
  bld <+ (hBit := AST.ite isOver (eESz .+ n1) h)
  bld <+ (isSat := AST.ite isNeg (hBit .< nAmt) (eESz .< (hBit .+ amt)))
  bld <+ (bitQC := bitQC .| isSat)
  let rShf = rExpr >> nAmt
  let lShf = rExpr << amt
  let shf =
    AST.ite isNeg (AST.ite isOver (rShf .+ (msb >> (nAmt .- n1))) rShf) lShf
  let isZero = (AST.not isOver) .& ((rExpr == n0) .| (amt == n0))
  AST.ite isZero rExpr (AST.ite isSat (AST.ite isNeg min max) shf)

let uqrshl ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (o1, o2, o3) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
  match ins.Operands with
  | ThreeOperands (OprSIMD (SIMDVecReg _), _, _) ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
    let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    Array.map2 (fun e shf ->
      let shf = shf |> AST.xtlo 8<rt> |> AST.sext eSize
      usatQRShl bld e shf eSize) src1 src2
    |> Array.iter2 (fun r e -> bld <+ (r := e)) result
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | ThreeOperands (OprSIMD (SIMDFPScalarReg _), _, _) ->
    let src1 = transOprToExpr ins bld addr o2
    let shift =
      transOprToExpr ins bld addr o3 |> AST.xtlo 8<rt> |> AST.sext eSize
    let result = usatQRShl bld src1 shift eSize
    dstAssignScalar ins bld addr o1 result eSize
  | _ -> raise InvalidOperandException
  bld --!> insLen

let uqsub ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (o1, o2, o3) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
  let inline satQ64 src1 src2 =
    let eval = src1 .- src2
    let bitQC = AST.extract (regVar bld R.FPSR) 1<rt> 27
    let underflow = src1 .< src2
    bld <+ (bitQC := bitQC .| underflow)
    AST.ite underflow (AST.num0 64<rt>) eval
  match ins.Operands with
  | ThreeOperands (OprSIMD (SIMDVecReg _), _, _) ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
    let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    if eSize = 64<rt> then
      Array.map2 satQ64 src1 src2
      |> Array.iter2 (fun element i -> bld <+ (element := i)) result
    else
      Array.map2 (fun e1 e2 ->
        AST.zext (2 * eSize) e1 .- AST.zext (2 * eSize) e2) src1 src2
      |> Array.iter2 (fun element i ->
        bld <+ (element := satQ bld i eSize true)) result
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | ThreeOperands (OprSIMD (SIMDFPScalarReg _), _, _) ->
    let src1 = transOprToExpr ins bld addr o2
    let src2 = transOprToExpr ins bld addr o3
    let result =
      if eSize = 64<rt> then satQ64 src1 src2
      else
        let input = AST.zext (2 * eSize) src1 .- AST.zext (2 * eSize) src2
        satQ bld input eSize true
    dstAssignScalar ins bld addr o1 result eSize
  | _ -> raise InvalidOperandException
  bld --!> insLen

let private usatQShl bld expr amt eSize =
  let bitQC = AST.extract (regVar bld R.FPSR) 1<rt> 27
  let hBit = highestSetBitForIR expr (int eSize) eSize bld
  let max = numU64 0xFFFFFFFFFFFFFFFFUL eSize
  let min = AST.num0 eSize
  let struct (isNeg, isSat) = tmpVars2 bld 1<rt>
  let eESz = numI32 (int eSize - 1) eSize
  bld <+ (isNeg := amt ?< AST.num0 eSize)
  bld <+ (isSat := AST.ite isNeg (hBit .< AST.neg amt) (eESz .< (hBit .+ amt)))
  bld <+ (bitQC := bitQC .| isSat)
  let sat = AST.ite isNeg min max
  let r = AST.ite isSat sat (AST.ite isNeg (expr >> AST.neg amt) (expr << amt))
  let isZero = (expr == AST.num0 eSize) .| (amt == AST.num0 eSize)
  AST.ite isZero expr r

let uqshl ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (o1, o2, o3) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
  match ins.Operands with
  | ThreeOperands (OprSIMD (SIMDVecReg _), _, OprImm _) ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
    let shift = transOprToExpr ins bld addr o3 |> AST.xtlo 8<rt>
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    let shf = tmpVar bld eSize
    bld <+ (shf := shift |> AST.sext eSize)
    Array.map (fun e -> usatQShl bld e shf eSize) src1
    |> Array.iter2 (fun r e -> bld <+ (r := e)) result
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | ThreeOperands (OprSIMD (SIMDVecReg _), _, _) ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
    let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
    let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
    let result = Array.init elements (fun _ -> tmpVar bld eSize)
    Array.map2 (fun e shf ->
      let shf = shf |> AST.xtlo 8<rt> |> AST.sext eSize
      usatQShl bld e shf eSize) src1 src2
    |> Array.iter2 (fun r e -> bld <+ (r := e)) result
    dstAssignForSIMD dstA dstB result dataSize elements bld
  | ThreeOperands (OprSIMD (SIMDFPScalarReg _), _, _) ->
    let src1 = transOprToExpr ins bld addr o2
    let shift = transOprToExpr ins bld addr o3 |> AST.xtlo 8<rt>
    let result = usatQShl bld src1 (AST.sext eSize shift) eSize
    dstAssignScalar ins bld addr o1 result eSize
  | _ -> raise InvalidOperandException
  bld --!> insLen

let shiftULeftLong ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (o1, o2, o3) = getThreeOprs ins
  let struct (eSize, part, _) = getElemDataSzAndElems o2
  let elements = 64<rt> / eSize
  let dblESz = eSize * 2
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
  let src = transSIMDOprVPart bld eSize part o2
  let amt = tmpVar bld dblESz
  bld <+ (amt := transOprToExpr ins bld addr o3 |> AST.xtlo dblESz)
  let result = Array.init elements (fun _ -> tmpVar bld dblESz)
  Array.map (fun e -> AST.zext dblESz e << amt) src
  |> Array.iter2 (fun r e -> bld <+ (r := e)) result
  dstAssignForSIMD dstA dstB result 128<rt> elements bld
  bld --!> insLen

let shiftSLeftLong ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (o1, o2, o3) = getThreeOprs ins
  let struct (eSize, part, _) = getElemDataSzAndElems o2
  let elements = 64<rt> / eSize
  let dblESz = eSize * 2
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
  let src = transSIMDOprVPart bld eSize part o2
  let amt = tmpVar bld dblESz
  bld <+ (amt := transOprToExpr ins bld addr o3 |> AST.xtlo dblESz)
  let result = Array.init elements (fun _ -> tmpVar bld dblESz)
  Array.map (fun e -> AST.sext dblESz e << amt) src
  |> Array.iter2 (fun r e -> bld <+ (r := e)) result
  dstAssignForSIMD dstA dstB result 128<rt> elements bld
  bld --!> insLen

let urshl ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src, shift) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
  let struct (n0, n1) = tmpVars2 bld 64<rt>
  bld <+ (n0 := AST.num0 64<rt>)
  bld <+ (n1 := AST.num1 64<rt>)
  let inline shiftRndLeft e1 e2 =
    let struct (rndCst, shf, elem, res) = tmpVars4 bld 64<rt>
    let cond = tmpVar bld 1<rt>
    bld <+ (shf := AST.xtlo 8<rt> e2 |> AST.sext 64<rt>)
    bld <+ (cond := shf ?< n0)
    bld <+ (rndCst := AST.ite cond (n1 << (AST.neg shf .- n1)) n0)
    bld <+ (elem := AST.zext 64<rt> e1 .+ rndCst)
    let isOver = AST.neg shf .> numI32 (int eSize) 64<rt>
    if eSize = 64<rt> then
      let isCarry = e1 .> elem
      let cElem = tmpVar bld 64<rt>
      bld <+ (cElem := (elem >> n1) .| numU64 0x8000000000000000UL 64<rt>)
      bld <+ (res := AST.ite cond
                     (AST.ite isOver n0
                       (AST.ite isCarry (cElem >> (AST.neg shf .- n1))
                         (elem >> AST.neg shf))) (elem << shf))
    else
      bld <+ (res := AST.ite cond
                     (AST.ite isOver n0 (elem >> AST.neg shf)) (elem << shf))
    AST.xtlo eSize res
  match ins.Operands with
  | ThreeOperands (OprSIMD (SIMDFPScalarReg _), _, _) ->
    let src = transOprToExpr ins bld addr src
    let shift = transOprToExpr ins bld addr shift
    let result = shiftRndLeft src shift
    dstAssignScalar ins bld addr dst result eSize
  | _ ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let src = transSIMDOprToExpr bld eSize dataSize elements src
    let shift = transSIMDOprToExpr bld eSize dataSize elements shift
    let result = Array.map2 shiftRndLeft src shift
    dstAssignForSIMD dstA dstB result dataSize elements bld
  bld --!> insLen

let srshl ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src, shift) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
  let struct (n0, n1) = tmpVars2 bld eSize
  bld <+ (n0 := AST.num0 eSize)
  bld <+ (n1 := AST.num1 eSize)
  let inline shiftRndLeft e1 e2 =
    let struct (rndCst, shf, elem) = tmpVars3 bld eSize
    let struct (cond, signBit) = tmpVars2 bld 1<rt>
    bld <+ (shf := AST.xtlo 8<rt> e2 |> AST.sext eSize)
    bld <+ (signBit := AST.xthi 1<rt> e1)
    bld <+ (cond := shf ?< n0)
    bld <+ (rndCst := AST.ite cond (n1 << (AST.neg shf .- n1)) n0)
    bld <+ (elem := e1 .+ rndCst)
    let isOver = AST.neg shf .> numI32 (int eSize) eSize
    AST.ite cond (AST.ite isOver n0 (AST.ite signBit
                   (elem ?>> AST.neg shf) (elem >> AST.neg shf))) (elem << shf)
  match ins.Operands with
  | ThreeOperands (OprSIMD (SIMDFPScalarReg _), _, _) ->
    let src = transOprToExpr ins bld addr src
    let shift = transOprToExpr ins bld addr shift
    let result = shiftRndLeft src shift
    dstAssignScalar ins bld addr dst result eSize
  | _ ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let src = transSIMDOprToExpr bld eSize dataSize elements src
    let shift = transSIMDOprToExpr bld eSize dataSize elements shift
    let result = Array.map2 shiftRndLeft src shift
    dstAssignForSIMD dstA dstB result dataSize elements bld
  bld --!> insLen

let urhadd ins insLen bld addr =
  let struct (o1, o2, o3) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
  let src1 = transSIMDOprToExpr bld eSize dataSize elements o2
  let src2 = transSIMDOprToExpr bld eSize dataSize elements o3
  bld <!-- (ins.Address, insLen)
  let inline roundAdd e1 e2 =
    let e1 = AST.zext 64<rt> e1
    let e2 = AST.zext 64<rt> e2
    (e1 .+ e2 .+ AST.num1 64<rt>) >> AST.num1 64<rt>
    |> AST.xtlo eSize
  let result = Array.map2 roundAdd src1 src2
  dstAssignForSIMD dstA dstB result dataSize elements bld
  bld --!> insLen

let shiftRight ins insLen bld addr shifter =
  let struct (o1, o2, o3) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
  let dst = transSIMDOprToExpr bld eSize dataSize elements o1
  let src = transSIMDOprToExpr bld eSize dataSize elements o2
  let shf = transOprToExpr ins bld addr o3 |> AST.xtlo eSize
  let result = Array.init elements (fun _ -> tmpVar bld eSize)
  bld <!-- (ins.Address, insLen)
  Array.map2 (fun e1 e2 -> e1 .+ (shifter e2 shf)) dst src
  |> Array.iter2 (fun e1 e2 -> bld <+ (e1 := e2)) result
  dstAssignForSIMD dstA dstB result dataSize elements bld
  bld --!> insLen

let ssubl ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (eSize, part, _) = getElemDataSzAndElems src1
  let dataSize = 64<rt>
  let elements = dataSize / eSize
  let dblESz = eSize * 2
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
  let opr1 = transSIMDOprVPart bld eSize part src1
  let opr2 = transSIMDOprVPart bld eSize part src2
  let result = Array.init elements (fun _ -> tmpVar bld dblESz)
  Array.map2 (fun e1 e2 -> AST.sext dblESz e1 .-  AST.sext dblESz e2) opr1 opr2
  |> Array.iter2 (fun r e -> bld <+ (r := e)) result
  dstAssignForSIMD dstA dstB result 128<rt> elements bld
  bld --!> insLen

let ssubw ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (o1, o2, o3) = getThreeOprs ins
  let struct (eSize, part, _) = getElemDataSzAndElems o3
  let elements = 64<rt> / eSize
  let dblESz = eSize * 2
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
  let opr1 = transSIMDOprToExpr bld dblESz 128<rt> elements o2
  let opr2 = transSIMDOprVPart bld eSize part o3
  let result = Array.init elements (fun _ -> tmpVar bld dblESz)
  Array.map2 (fun e1 e2 -> AST.sext dblESz e1 .- AST.sext dblESz e2) opr1 opr2
  |> Array.iter2 (fun r e -> bld <+ (r := e)) result
  dstAssignForSIMD dstA dstB result 128<rt> elements bld
  bld --!> insLen

let ushl ins insLen bld addr =
  let struct (dst, o1, o2) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  bld <!-- (ins.Address, insLen)
  let inline shiftLeft e1 e2 =
    let shf = tmpVar bld eSize
    bld <+ (shf := AST.xtlo 8<rt> e2 |> AST.sext eSize)
    AST.ite (shf ?< AST.num0 eSize) (e1 >> AST.neg shf) (e1 << shf)
  match ins.Operands with
  | ThreeOperands (OprSIMD (SIMDFPScalarReg _), _, _) ->
    let src1 = transOprToExpr ins bld addr o1
    let src2 = transOprToExpr ins bld addr o2
    let result = shiftLeft src1 src2
    dstAssignScalar ins bld addr dst result eSize
  | _ ->
    let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
    let src1 = transSIMDOprToExpr bld eSize dataSize elements o1
    let src2 = transSIMDOprToExpr bld eSize dataSize elements o2
    let result = Array.map2 shiftLeft src1 src2
    dstAssignForSIMD dstA dstB result dataSize elements bld
  bld --!> insLen

let usubl ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (o1, o2, o3) = getThreeOprs ins
  let struct (eSize, part, _) = getElemDataSzAndElems o2
  let elements = 64<rt> / eSize
  let dblESz = eSize * 2
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
  let src1 = transSIMDOprVPart bld eSize part o2
  let src2 = transSIMDOprVPart bld eSize part o3
  let result = Array.init elements (fun _ -> tmpVar bld dblESz)
  Array.iteri (fun i r ->
    bld <+ (r := AST.zext dblESz src1[i] .- AST.zext dblESz src2[i])) result
  dstAssignForSIMD dstA dstB result 128<rt> elements bld
  bld --!> insLen

let usubw ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (o1, o2, o3) = getThreeOprs ins
  let struct (eSize, part, _) = getElemDataSzAndElems o3
  let elements = 64<rt> / eSize
  let dblESz = eSize * 2
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr o1
  let src1 = transSIMDOprToExpr bld dblESz 128<rt> elements o2
  let src2 = transSIMDOprVPart bld eSize part o3
  let result = Array.init elements (fun _ -> tmpVar bld dblESz)
  Array.iteri (fun i r ->
    bld <+ (r := AST.zext dblESz src1[i] .- AST.zext dblESz src2[i])) result
  dstAssignForSIMD dstA dstB result 128<rt> elements bld
  bld --!> insLen

let uxtb ins insLen bld addr =
  let struct (dst, src) = getTwoOprs ins
  ubfm ins insLen bld addr dst src (OprImm 0L) (OprImm 7L)

let uxth ins insLen bld addr =
  let struct (dst, src) = getTwoOprs ins
  ubfm ins insLen bld addr dst src (OprImm 0L) (OprImm 15L)

let uzp ins insLen bld addr op =
  let struct (dst, src1, srcH) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  bld <!-- (ins.Address, insLen)
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
  let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
  let srcH = transSIMDOprToExpr bld eSize dataSize elements srcH
  let result = Array.init elements (fun _ -> tmpVar bld eSize)
  Array.append src1 srcH
  |> Array.mapi (fun i x -> (i, x))
  |> Array.filter (fun (i, _) -> i % 2 = op)
  |> Array.map snd
  |> Array.iter2 (fun e1 e2 -> bld <+ (e1 := e2)) result
  dstAssignForSIMD dstA dstB result dataSize elements bld
  bld --!> insLen

let xtn ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
  let src = transSIMDOprToExpr bld eSize dataSize elements src
            |> Array.map (AST.xtlo (eSize / 2))
  bld <+ (dstA := AST.revConcat src)
  bld <+ (dstB := AST.num0 64<rt>)
  bld --!> insLen

let xtn2 ins insLen bld addr =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src) = getTwoOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
  let src = transSIMDOprToExpr bld eSize dataSize elements src
            |> Array.map (AST.xtlo (eSize / 2))
  bld <+ (dstA := dstA)
  bld <+ (dstB := AST.revConcat src)
  bld --!> insLen

let zip ins insLen bld addr isPart1 =
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  bld <!-- (ins.Address, insLen)
  let struct (dstB, dstA) = transOprToExpr128 ins bld addr dst
  let src1 = transSIMDOprToExpr bld eSize dataSize elements src1
  let src2 = transSIMDOprToExpr bld eSize dataSize elements src2
  let result = Array.init elements (fun _ -> tmpVar bld eSize)
  let half = elements / 2
  let src1 = if isPart1 then Array.sub src1 0 half else Array.sub src1 half half
  let src2 = if isPart1 then Array.sub src2 0 half else Array.sub src2 half half
  Array.map2 (fun e1 e2 -> [| e1; e2 |]) src1 src2 |> Array.concat
  |> Array.iter2 (fun e1 e2 -> bld <+ (e1 := e2)) result
  dstAssignForSIMD dstA dstB result dataSize elements bld
  bld --!> insLen

/// The logical shift left(or right) is the alias of LS{L|R}V and UBFM.
/// Therefore, it is necessary to distribute to the original instruction.
let distLogicalLeftShift ins insLen bld addr =
  match ins.Operands with
  | ThreeOperands (_, _, OprImm _) -> logShift ins insLen bld addr (<<)
  | ThreeOperands (_, _, OprRegister _) -> lslv ins insLen bld addr
  | _ -> raise InvalidOperandException

let distLogicalRightShift ins insLen bld addr =
  match ins.Operands with
  | ThreeOperands (_, _, OprImm _) -> logShift ins insLen bld addr (>>)
  | ThreeOperands (_, _, OprRegister _) -> lsrv ins insLen bld addr
  | _ -> raise InvalidOperandException

/// Translate IR.
let translate ins insLen bld =
  let addr = ins.Address
  match ins.Opcode with
  | Opcode.ABS -> abs ins insLen bld addr
  | Opcode.ADC -> adc ins insLen bld addr
  | Opcode.ADCS -> adcs ins insLen bld addr
  | Opcode.ADD -> add ins insLen bld addr
  | Opcode.ADDP -> addp ins insLen bld addr
  | Opcode.ADDS -> adds ins insLen bld addr
  | Opcode.ADDV -> addv ins insLen bld addr
  | Opcode.ADR -> adr ins insLen bld addr
  | Opcode.ADRP -> adrp ins insLen bld addr
  | Opcode.AND -> logAnd ins insLen bld addr
  | Opcode.ANDS -> ands ins insLen bld addr
  | Opcode.ASR -> asrv ins insLen bld addr
  | Opcode.B -> b ins insLen bld addr
  | Opcode.BAL -> bCond ins insLen bld addr AL
  | Opcode.BCC -> bCond ins insLen bld addr CC
  | Opcode.BCS -> bCond ins insLen bld addr CS
  | Opcode.BEQ -> bCond ins insLen bld addr EQ
  | Opcode.BFI -> bfi ins insLen bld addr
  | Opcode.BFXIL -> bfxil ins insLen bld addr
  | Opcode.BGE -> bCond ins insLen bld addr GE
  | Opcode.BGT -> bCond ins insLen bld addr GT
  | Opcode.BHI -> bCond ins insLen bld addr HI
  | Opcode.BIC -> bic ins insLen bld addr
  | Opcode.BICS -> bics ins insLen bld addr
  | Opcode.BIF -> bif ins insLen bld addr
  | Opcode.BIT -> bit ins insLen bld addr
  | Opcode.BL -> bl ins insLen bld addr
  | Opcode.BLE -> bCond ins insLen bld addr LE
  | Opcode.BLR -> blr ins insLen bld addr
  | Opcode.BLS -> bCond ins insLen bld addr LS
  | Opcode.BLT -> bCond ins insLen bld addr LT
  | Opcode.BMI -> bCond ins insLen bld addr MI
  | Opcode.BNE -> bCond ins insLen bld addr NE
  | Opcode.BNV -> bCond ins insLen bld addr NV
  | Opcode.BPL -> bCond ins insLen bld addr PL
  | Opcode.BR -> br ins insLen bld addr
  | Opcode.BRK -> sideEffects ins.Address insLen bld Breakpoint
  | Opcode.BSL -> bsl ins insLen bld addr
  | Opcode.BVC -> bCond ins insLen bld addr VC
  | Opcode.BVS -> bCond ins insLen bld addr VS
  | Opcode.CAS | Opcode.CASA | Opcode.CASL | Opcode.CASAL ->
    compareAndSwap ins insLen bld addr
  | Opcode.CBNZ -> cbnz ins insLen bld addr
  | Opcode.CBZ -> cbz ins insLen bld addr
  | Opcode.CCMN -> ccmn ins insLen bld addr
  | Opcode.CCMP -> ccmp ins insLen bld addr
  | Opcode.CLS -> cls ins insLen bld addr
  | Opcode.CLZ -> clz ins insLen bld addr
  | Opcode.CMEQ -> cmeq ins insLen bld addr
  | Opcode.CMGE -> cmge ins insLen bld addr
  | Opcode.CMGT -> cmgt ins insLen bld addr
  | Opcode.CMHI -> cmhi ins insLen bld addr
  | Opcode.CMHS -> cmhs ins insLen bld addr
  | Opcode.CMLT -> cmlt ins insLen bld addr
  | Opcode.CMN -> cmn ins insLen bld addr
  | Opcode.CMP -> cmp ins insLen bld addr
  | Opcode.CMTST -> cmtst ins insLen bld addr
  | Opcode.CNEG | Opcode.CSNEG -> csneg ins insLen bld addr
  | Opcode.CNT -> cnt ins insLen bld addr
  | Opcode.CSEL -> csel ins insLen bld addr
  | Opcode.CSETM | Opcode.CINV | Opcode.CSINV -> csinv ins insLen bld addr
  | Opcode.CSINC | Opcode.CINC | Opcode.CSET -> csinc ins insLen bld addr
  | Opcode.CTZ -> ctz ins insLen bld addr
  | Opcode.DCZVA -> dczva ins insLen bld addr
  | Opcode.DMB | Opcode.DSB | Opcode.ISB -> nop ins.Address insLen bld
  | Opcode.DUP -> dup ins insLen bld addr
  | Opcode.EOR | Opcode.EON -> eor ins insLen bld addr
  | Opcode.EXT -> ext ins insLen bld addr
  | Opcode.EXTR | Opcode.ROR -> extr ins insLen bld addr
  | Opcode.FABD -> fabd ins insLen bld addr
  | Opcode.FABS -> fabs ins insLen bld addr
  | Opcode.FADD -> fadd ins insLen bld addr
  | Opcode.FADDP -> faddp ins insLen bld addr
  | Opcode.FCCMP -> fccmp ins insLen bld addr
  | Opcode.FCCMPE -> fccmp ins insLen bld addr
  | Opcode.FCMGT -> fcmgt ins insLen bld addr
  | Opcode.FCMP -> fcmp ins insLen bld addr
  | Opcode.FCMPE -> fcmp ins insLen bld addr
  | Opcode.FCSEL -> fcsel ins insLen bld addr
  | Opcode.FCVT -> fcvt ins insLen bld addr
  | Opcode.FCVTAS -> fcvtas ins insLen bld addr
  | Opcode.FCVTAU -> fcvtau ins insLen bld addr
  | Opcode.FCVTMS -> fcvtms ins insLen bld addr
  | Opcode.FCVTMU -> fcvtmu ins insLen bld addr
  | Opcode.FCVTPS -> fcvtps ins insLen bld addr
  | Opcode.FCVTPU -> fcvtpu ins insLen bld addr
  | Opcode.FCVTZS -> fcvtzs ins insLen bld addr
  | Opcode.FCVTZU -> fcvtzu ins insLen bld addr
  | Opcode.FDIV -> fdiv ins insLen bld addr
  | Opcode.FMADD -> fmadd ins insLen bld addr
  | Opcode.FMAX -> fmaxmin ins insLen bld addr AST.fgt
  | Opcode.FMAXNM -> sideEffects ins.Address insLen bld UnsupportedFP
  | Opcode.FMIN -> fmaxmin ins insLen bld addr AST.flt
  | Opcode.FMLS -> fmls ins insLen bld addr
  | Opcode.FMOV -> fmov ins insLen bld addr
  | Opcode.FMSUB -> fmsub ins insLen bld addr
  | Opcode.FMUL -> fmul ins insLen bld addr
  | Opcode.FNEG -> fneg ins insLen bld addr
  | Opcode.FNMSUB -> fnmsub ins insLen bld addr
  | Opcode.FNMUL -> fnmul ins insLen bld addr
  | Opcode.FRINTA -> frinta ins insLen bld addr
  | Opcode.FRINTM -> frintm ins insLen bld addr
  | Opcode.FRINTP -> frintp ins insLen bld addr
  | Opcode.FRINTI -> frinti ins insLen bld addr
  | Opcode.FRINTN -> frintn ins insLen bld addr
  | Opcode.FRINTX -> frintx ins insLen bld addr
  | Opcode.FRINTZ -> frintz ins insLen bld addr
  | Opcode.FSQRT -> fsqrt ins insLen bld addr
  | Opcode.FSUB -> fsub ins insLen bld addr
  | Opcode.HINT -> nop ins.Address insLen bld
  | Opcode.INS -> insv ins insLen bld addr
  | Opcode.LD1 | Opcode.LD2 | Opcode.LD3 | Opcode.LD4 ->
    loadStoreList ins insLen bld addr true
  | Opcode.LD1R | Opcode.LD2R | Opcode.LD3R | Opcode.LD4R ->
    loadRep ins insLen bld addr
  | Opcode.LDAR -> ldar ins insLen bld addr
  | Opcode.LDARB -> ldarb ins insLen bld addr
  | Opcode.LDAXP | Opcode.LDXP -> ldaxp ins insLen bld addr
  | Opcode.LDAXR | Opcode.LDXR -> ldaxr ins insLen bld addr
  | Opcode.LDAXRB | Opcode.LDXRB -> ldax ins insLen bld addr 8<rt>
  | Opcode.LDAXRH | Opcode.LDXRH -> ldax ins insLen bld addr 16<rt>
  | Opcode.LDNP -> ldnp ins insLen bld addr
  | Opcode.LDP -> ldp ins insLen bld addr
  | Opcode.LDPSW -> ldpsw ins insLen bld addr
  | Opcode.LDR -> ldr ins insLen bld addr
  | Opcode.LDRB -> ldrb ins insLen bld addr
  | Opcode.LDRH -> ldrh ins insLen bld addr
  | Opcode.LDRSB -> ldrsb ins insLen bld addr
  | Opcode.LDRSH -> ldrsh ins insLen bld addr
  | Opcode.LDRSW -> ldrsw ins insLen bld addr
  | Opcode.LDUR -> ldur ins insLen bld addr
  | Opcode.LDURB -> ldurb ins insLen bld addr
  | Opcode.LDURH -> ldurh ins insLen bld addr
  | Opcode.LDURSB -> ldursb ins insLen bld addr
  | Opcode.LDURSH -> ldursh ins insLen bld addr
  | Opcode.LDURSW -> ldursw ins insLen bld addr
  | Opcode.LSL -> distLogicalLeftShift ins insLen bld addr
  | Opcode.LSR -> distLogicalRightShift ins insLen bld addr
  | Opcode.MADD -> madd ins insLen bld addr
  | Opcode.MLA -> mladdsub ins insLen bld addr (.+)
  | Opcode.MLS -> mladdsub ins insLen bld addr (.-)
  | Opcode.MNEG -> msub ins insLen bld addr
  | Opcode.MOV -> mov ins insLen bld addr
  | Opcode.MOVI -> movi ins insLen bld addr
  | Opcode.MOVK -> movk ins insLen bld addr
  | Opcode.MOVN -> movn ins insLen bld addr
  | Opcode.MOVZ -> movz ins insLen bld addr
  | Opcode.MRS -> mrs ins insLen bld addr
  | Opcode.MSR -> msr ins insLen bld addr
  | Opcode.MSUB -> msub ins insLen bld addr
  | Opcode.MUL -> madd ins insLen bld addr
  | Opcode.MVN -> orn ins insLen bld addr
  | Opcode.MVNI -> mvni ins insLen bld addr
  | Opcode.NEG -> sub ins insLen bld addr
  | Opcode.NEGS -> subs ins insLen bld addr
  | Opcode.NOT -> orn ins insLen bld addr
  | Opcode.NOP -> nop ins.Address insLen bld
  | Opcode.ORN -> orn ins insLen bld addr
  | Opcode.ORR -> orr ins insLen bld addr
  | Opcode.PRFM | Opcode.PRFUM -> nop ins.Address insLen bld
  | Opcode.RBIT -> rbit ins insLen bld addr
  | Opcode.RET -> ret ins insLen bld addr
  | Opcode.REV -> rev ins insLen bld addr
  | Opcode.REV16 -> rev16 ins insLen bld addr
  | Opcode.REV32 -> rev32 ins insLen bld addr
  | Opcode.REV64 -> rev ins insLen bld addr
  | Opcode.RORV -> rorv ins insLen bld addr
  | Opcode.SADDL | Opcode.SADDL2 -> saddl ins insLen bld addr
  | Opcode.SADDW | Opcode.SADDW2 -> saddw ins insLen bld addr
  | Opcode.SADDLP -> saddlp ins insLen bld addr
  | Opcode.SADDLV -> saddlv ins insLen bld addr
  | Opcode.SBC -> sbc ins insLen bld addr
  | Opcode.SBFIZ -> sbfiz ins insLen bld addr
  | Opcode.SBFX -> sbfx ins insLen bld addr
  | Opcode.SCVTF -> icvtf ins insLen bld addr false
  | Opcode.SDIV -> sdiv ins insLen bld addr
  | Opcode.SHL -> shl ins insLen bld addr
  | Opcode.SMADDL -> smaddl ins insLen bld addr
  | Opcode.SMOV -> smov ins insLen bld addr
  | Opcode.SMSUBL | Opcode.SMNEGL -> smsubl ins insLen bld addr
  | Opcode.SMULH -> smulh ins insLen bld addr
  | Opcode.SMULL | Opcode.SMULL2 -> smull ins insLen bld addr
  | Opcode.SSHL -> sshl ins insLen bld addr
  | Opcode.UXTL | Opcode.UXTL2 | Opcode.USHLL | Opcode.USHLL2 ->
    shiftULeftLong ins insLen bld addr
  | Opcode.SXTL | Opcode.SXTL2 | Opcode.SSHLL | Opcode.SSHLL2 ->
    shiftSLeftLong ins insLen bld addr
  | Opcode.SSHR -> shift ins insLen bld addr (?>>)
  | Opcode.SSRA -> shiftRight ins insLen bld addr (?>>)
  | Opcode.SSUBL | Opcode.SSUBL2 -> ssubl ins insLen bld addr
  | Opcode.SSUBW | Opcode.SSUBW2 -> ssubw ins insLen bld addr
  | Opcode.SMAX -> maxMin ins insLen bld addr (?>=)
  | Opcode.SMAXP -> maxMinp ins insLen bld addr (?>=)
  | Opcode.SMAXV -> maxMinv ins insLen bld addr (?>=)
  | Opcode.SMIN -> maxMin ins insLen bld addr (?<=)
  | Opcode.SMINP -> maxMinp ins insLen bld addr (?<=)
  | Opcode.SMINV -> maxMinv ins insLen bld addr (?<=)
  | Opcode.SMLAL | Opcode.SMLAL2 -> smlal ins insLen bld addr
  | Opcode.SMLSL | Opcode.SMLSL2 -> smlsl ins insLen bld addr
  | Opcode.SQDMULH -> sqdmulh ins insLen bld addr
  | Opcode.SQDMULL | Opcode.SQDMULL2 -> sqdmull ins insLen bld addr
  | Opcode.SQDMLAL | Opcode.SQDMLAL2 -> sqdmlal ins insLen bld addr
  | Opcode.ST1 | Opcode.ST2 | Opcode.ST3 | Opcode.ST4 ->
    loadStoreList ins insLen bld addr false
  | Opcode.STLR -> stlr ins insLen bld addr
  | Opcode.STLRB -> stlrb ins insLen bld addr
  | Opcode.STLXP | Opcode.STXP -> stlxp ins insLen bld addr
  | Opcode.STLXR | Opcode.STXR -> stlxr ins insLen bld addr
  | Opcode.STLXRB | Opcode.STXRB -> stlx ins insLen bld addr 8<rt>
  | Opcode.STLXRH | Opcode.STXRH -> stlx ins insLen bld addr 16<rt>
  | Opcode.STNP -> stnp ins insLen bld addr
  | Opcode.STP -> stp ins insLen bld addr
  | Opcode.STR -> str ins insLen bld addr
  | Opcode.STRB -> strb ins insLen bld addr
  | Opcode.STRH -> strh ins insLen bld addr
  | Opcode.STTRB -> sttrb ins insLen bld addr
  | Opcode.STUR -> stur ins insLen bld addr
  | Opcode.STURB -> sturb ins insLen bld addr
  | Opcode.STURH -> sturh ins insLen bld addr
  | Opcode.SUB -> sub ins insLen bld addr
  | Opcode.SUBS -> subs ins insLen bld addr
  | Opcode.SVC -> svc ins insLen bld
  | Opcode.SXTB -> sxtb ins insLen bld addr
  | Opcode.SXTH -> sxth ins insLen bld addr
  | Opcode.SXTW -> sxtw ins insLen bld addr
  | Opcode.TBL -> tbl ins insLen bld addr
  | Opcode.TBNZ -> tbnz ins insLen bld addr
  | Opcode.TBZ -> tbz ins insLen bld addr
  | Opcode.TRN1 -> trn1 ins insLen bld addr
  | Opcode.TRN2 -> trn2 ins insLen bld addr
  | Opcode.TST -> tst ins insLen bld addr
  | Opcode.UABAL | Opcode.UABAL2 -> uabal ins insLen bld addr
  | Opcode.UABDL | Opcode.UABDL2 -> uabdl ins insLen bld addr
  | Opcode.UADALP -> uadalp ins insLen bld addr
  | Opcode.UADDL | Opcode.UADDL2 -> uaddl ins insLen bld addr
  | Opcode.UADDLP -> uaddlp ins insLen bld addr
  | Opcode.UADDLV -> uaddlv ins insLen bld addr
  | Opcode.UADDW | Opcode.UADDW2 -> uaddw ins insLen bld addr
  | Opcode.UBFIZ -> ubfiz ins insLen bld addr
  | Opcode.UBFX -> ubfx ins insLen bld addr
  | Opcode.UCVTF -> icvtf ins insLen bld addr true
  | Opcode.UDIV -> udiv ins insLen bld addr
  | Opcode.UMADDL -> umaddl ins insLen bld addr
  | Opcode.UMAX -> maxMin ins insLen bld addr (.>=)
  | Opcode.UMAXP -> maxMinp ins insLen bld addr (.>=)
  | Opcode.UMAXV -> maxMinv ins insLen bld addr (.>=)
  | Opcode.UMIN -> maxMin ins insLen bld addr (.<=)
  | Opcode.UMINP -> maxMinp ins insLen bld addr (.<=)
  | Opcode.UMINV -> maxMinv ins insLen bld addr (.<=)
  | Opcode.UMLAL | Opcode.UMLAL2 -> umlal ins insLen bld addr
  | Opcode.UMLSL | Opcode.UMLSL2 -> umlsl ins insLen bld addr
  | Opcode.UMOV -> umov ins insLen bld addr
  | Opcode.UMSUBL | Opcode.UMNEGL -> umsubl ins insLen bld addr
  | Opcode.UMULH -> umulh ins insLen bld addr
  | Opcode.UMULL | Opcode.UMULL2 -> umull ins insLen bld addr
  | Opcode.UQADD -> uqadd ins insLen bld addr
  | Opcode.UQRSHL -> uqrshl ins insLen bld addr
  | Opcode.UQSHL -> uqshl ins insLen bld addr
  | Opcode.UQSUB -> uqsub ins insLen bld addr
  | Opcode.URSHL -> urshl ins insLen bld addr
  | Opcode.SRSHL -> srshl ins insLen bld addr
  | Opcode.URHADD -> urhadd ins insLen bld addr
  | Opcode.USHL -> ushl ins insLen bld addr
  | Opcode.USHR -> shift ins insLen bld addr (>>)
  | Opcode.USRA -> shiftRight ins insLen bld addr (>>)
  | Opcode.USUBL | Opcode.USUBL2 -> usubl ins insLen bld addr
  | Opcode.USUBW | Opcode.USUBW2 -> usubw ins insLen bld addr
  | Opcode.UXTB -> uxtb ins insLen bld addr
  | Opcode.UXTH -> uxth ins insLen bld addr
  | Opcode.UZP1 -> uzp ins insLen bld addr 0
  | Opcode.UZP2 -> uzp ins insLen bld addr 1
  | Opcode.XTN -> xtn ins insLen bld addr
  | Opcode.XTN2 -> xtn2 ins insLen bld addr
  | Opcode.ZIP1 -> zip ins insLen bld addr true
  | Opcode.ZIP2 -> zip ins insLen bld addr false
  | o ->
#if DEBUG
         eprintfn "%A" o
#endif
         raise <| NotImplementedIRException (Disasm.opCodeToString o)

// vim: set tw=80 sts=2 sw=2:
