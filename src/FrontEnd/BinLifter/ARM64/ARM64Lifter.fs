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

let adc ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let c = AST.zext ins.OprSize (getRegVar ctxt R.C)
  !<ir insLen
  let result, _ = addWithCarry src1 src2 c ins.OprSize
  !!ir (dstAssign ins.OprSize dst result)
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
  !!ir (dstAssign ins.OprSize dst result)
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
    !!ir (dstAssign ins.OprSize dst (src1 .+ src2))
  | FourOperands _ (* Arithmetic *) ->
    let dst, s1, s2 = transFourOprsWithBarrelShift ins ctxt addr
    let result, _ = addWithCarry s1 s2 (AST.num0 ins.OprSize) ins.OprSize
    !!ir (dstAssign ins.OprSize dst result)
  | _ -> raise InvalidOperandException
  !>ir insLen

let private addPair elements =
  let elem1, elem2 =
    let rec loop idx e1 e2 elems =
      match elems with
      | [] -> e1, e2
      | e :: t -> if idx % 2 = 0 then loop (idx + 1) (e :: e1) e2 t
                  else loop (idx + 1) e1 (e :: e2) t
    loop 0 [] [] elements
  List.map2 (.+) elem1 elem2 |> List.rev

let addp ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems dst
  let dstB, dstA = transOprToExpr128 ins ctxt addr dst
  let src1 = transSIMDOprToExpr ctxt eSize dataSize elements src1
  let src2 = transSIMDOprToExpr ctxt eSize dataSize elements src2
  let result = Array.append src1 src2 |> Array.toList |> addPair |> List.toArray
  dstAssignForSIMD dstA dstB result dataSize elements ir
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
  !!ir (dstAssign ins.OprSize dst result)
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
    !!ir (dstAssign ins.OprSize dst (src1 .& src2))
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
  !!ir (dstAssign ins.OprSize dst result)
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
  !!ir (dstAssign ins.OprSize dst ((dst .& AST.not tMask) .| (bot .& tMask)))
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
    let imm = transBarrelShiftToExpr ins.OprSize ctxt src amount
              |> advSIMDExpandImm ir eSize
              |> AST.not
    dstAssign128 ins ctxt addr dst (dstA .& imm) (dstB .& imm) dataSize ir
  | _ ->
    let dst, src1, src2 = transFourOprsWithBarrelShift ins ctxt addr
    !!ir (dstAssign ins.OprSize dst (src1 .& AST.not src2))
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
  !!ir (dstAssign ins.OprSize dst result)
  !>ir insLen

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
  let struct (s1, s2) = tmpVars2 ir oSz
  let _, (n, z, c, v) = addWithCarry src1 (AST.not src2) (AST.num1 oSz) oSz
  !!ir (getRegVar ctxt R.N := n)
  !!ir (getRegVar ctxt R.Z := z)
  !!ir (getRegVar ctxt R.C := c)
  !!ir (getRegVar ctxt R.V := v)
  !>ir insLen

let compare ins insLen ctxt addr cond =
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
    let dst = transOprToExpr ins ctxt addr o1
    let src1 = transOprToExpr ins ctxt addr o2
    let num0 = AST.num0 64<rt>
    let result = !+ir 64<rt>
    !!ir (result := AST.ite (cond src1 num0) (numI64 -1L 64<rt>) num0)
    !!ir (dst := result)
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
    let dst = transOprToExpr ins ctxt addr o1
    let src1 = transOprToExpr ins ctxt addr o2
    let src2 = transOprToExpr ins ctxt addr o3
    let num0 = AST.num0 64<rt>
    let result = !+ir 64<rt>
    !!ir (result := AST.ite (cond src1 src2) (numI64 -1L 64<rt>) num0)
    !!ir (dst := result)
  | _ -> raise InvalidOperandException
  !>ir insLen

let cmeq ins insLen ctxt addr = compare ins insLen ctxt addr (==)
let cmgt ins insLen ctxt addr = compare ins insLen ctxt addr (.>)
let cmge ins insLen ctxt addr = compare ins insLen ctxt addr (.>=)

let csel ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, s1, s2, cond = transOprToExprOfCSEL ins ctxt addr
  !<ir insLen
  !!ir (dstAssign ins.OprSize dst (AST.ite (conditionHolds ctxt cond) s1 s2))
  !>ir insLen

let csinc ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, s1, s2, cond = transOprToExprOfCSINC ins ctxt addr
  !<ir insLen
  let oprSize = ins.OprSize
  let cond = conditionHolds ctxt cond
  !!ir (dstAssign oprSize dst (AST.ite cond s1 (s2 .+ AST.num1 oprSize)))
  !>ir insLen

let csinv ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2, cond = transOprToExprOfCSINV ins ctxt addr
  !<ir insLen
  let cond = conditionHolds ctxt cond
  !!ir (dstAssign ins.OprSize dst (AST.ite cond src1 (AST.not src2)))
  !>ir insLen

let csneg ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, s1, s2, cond = transOprToExprOfCSNEG ins ctxt addr
  !<ir insLen
  let s2 = AST.not s2 .+ AST.num1 ins.OprSize
  !!ir (dstAssign ins.OprSize dst (AST.ite (conditionHolds ctxt cond) s1 s2))
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
    !!ir (dstAssign ins.OprSize dst (src1 <+> src2))
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
    !!ir (dstAssign ins.OprSize dst ((con >> (AST.zext 64<rt> lsb)) .& mask))
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

let fabs ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let dst, src = transTwoOprs ins ctxt addr
  let oprSize = ins.OprSize
  let n1 = AST.num1 oprSize
  !!ir (dstAssign oprSize dst ((src << n1) >> n1))
  !>ir insLen

let fadd ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let oprSize = ins.OprSize
  !!ir (dstAssign oprSize dst (AST.fadd src1 src2))
  !>ir insLen

let private fpCompare v1 v2 =
  AST.ite (AST.eq v1 v2) (numI32 0b0110 8<rt>)
    (AST.ite (AST.flt v1 v2) (numI32 0b1000 8<rt>) (numI32 0b0010 8<rt>))

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

let getExponent isDouble src =
  if isDouble then
    let numMantissa =  numI32 52 64<rt>
    let mask = numI32 0x7FF 64<rt>
    AST.xtlo 32<rt> ((src >> numMantissa) .& mask)
  else
    let numMantissa = numI32 23 32<rt>
    let mask = numI32 0xff 32<rt>
    (src >> numMantissa) .& mask

let getMantissa isDouble src =
  let mask =
    if isDouble then numU64 0xffffffffffffUL 64<rt>
    else numU64 0x7fffffUL 32<rt>
  src .& mask

let isNan isDouble expr =
  let exponent = getExponent isDouble expr
  let mantissa = getMantissa isDouble expr
  let e = if isDouble then numI32 0x7ff 32<rt> else numI32 0xff 32<rt>
  let zero = if isDouble then AST.num0 64<rt> else AST.num0 32<rt>
  (exponent == e) .& (mantissa != zero)

let fcmpe ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let src1, src2 = transTwoOprs ins ctxt addr
  let nzcv = !+ir 8<rt>
  let lblNan = !%ir "IsNan"
  let lblExit = !%ir "Exit"
  let isNan =  (* FIXME *)
    match ins.OprSize with
    | 64<rt> -> isNan true src1 .| isNan true src2
    | _ -> isNan false src2 .| isNan false src2
  !!ir (nzcv := fpCompare src1 src2)
  !!ir (getRegVar ctxt R.N := AST.extract nzcv 1<rt> 3)
  !!ir (getRegVar ctxt R.Z := AST.extract nzcv 1<rt> 2)
  !!ir (getRegVar ctxt R.C := AST.extract nzcv 1<rt> 1)
  !!ir (AST.cjmp isNan (AST.name lblNan) (AST.name lblExit))
  !!ir (AST.lmark lblNan)
  !!ir (getRegVar ctxt R.V := AST.num1 1<rt>)
  !!ir (AST.lmark lblExit)
  !!ir (nzcv := fpCompare src1 src2)
  !!ir (getRegVar ctxt R.V := AST.num0 1<rt>)
  !>ir insLen

let fcsel ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, s1, s2, cond = transOprToExprOfCSEL ins ctxt addr
  let fs1 = AST.cast CastKind.FloatCast ins.OprSize s1
  let fs2 = AST.cast CastKind.FloatCast ins.OprSize s2
  !<ir insLen
  !!ir (dstAssign ins.OprSize dst (AST.ite (conditionHolds ctxt cond) fs1 fs2))
  !>ir insLen

let fcvt ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let dst, src = transTwoOprs ins ctxt addr
  let oprSize = ins.OprSize
  !!ir (dstAssign oprSize dst (AST.cast CastKind.FloatCast oprSize src))
  !>ir insLen

let fcvtm ins insLen ctxt addr unsigned =
  let ir = !*ctxt
  let oprSize = ins.OprSize
  !<ir insLen
  let dst, src = transTwoOprs ins ctxt addr
  let result = fpToFixed ins src (AST.num0 oprSize) unsigned FPRounding_NEGINF
  !!ir (dstAssign oprSize dst result)
  !>ir insLen

let fcvtz ins insLen ctxt addr unsigned =
  let ir = !*ctxt
  let oprSize = ins.OprSize
  !<ir insLen
  match ins.Operands with
  | TwoOperands _ ->
    let dst, src = transTwoOprs ins ctxt addr
    let result = fpToFixed ins src (AST.num0 oprSize) unsigned FPRounding_Zero
    !!ir (dstAssign oprSize dst result)
  | _ ->
    let dst, src, fbits = transThreeOprs ins ctxt addr
    let result = fpToFixed ins src fbits unsigned FPRounding_Zero
    !!ir (dstAssign oprSize dst result)
  !>ir insLen

let fdiv ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let oprSize = ins.OprSize
  !!ir (dstAssign oprSize dst (AST.fdiv src1 src2))
  !>ir insLen

let fmov ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  match ins.Operands with
  | TwoOperands (OprRegister _, OprSIMD (SIMDVecRegWithIdx _)) ->
    let struct (dst, src) = getTwoOprs ins
    let dst = transOprToExpr ins ctxt addr dst
    let srcB, _ = transOprToExpr128 ins ctxt addr src
    !!ir (dstAssign ins.OprSize dst srcB)
  | TwoOperands (OprSIMD (SIMDVecRegWithIdx _), OprRegister _) ->
    let struct (dst, src) = getTwoOprs ins
    let dstB, dstA = transOprToExpr128 ins ctxt addr dst
    let src = transOprToExpr ins ctxt addr src
    !!ir (dstA := dstA)
    !!ir (dstB := src)
  | TwoOperands (OprSIMD (SIMDVecReg _), OprFPImm _) ->
    let struct (dst, src) = getTwoOprs ins
    let struct (eSize, dataSize, _) = getElemDataSzAndElems dst
    let src = if eSize <> 64<rt> then
                transOprToExprFPImm ins eSize src
                |> advSIMDExpandImm ir eSize
              else transOprToExprFPImm ins eSize src
    dstAssign128 ins ctxt addr dst src src dataSize ir
  | _ ->
    let dst, src = transTwoOprs ins ctxt addr
    !!ir (dstAssign ins.OprSize dst src)
  !>ir insLen

let fmul ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let oprSize = ins.OprSize
  !!ir (dstAssign oprSize dst (AST.fmul src1 src2))
  !>ir insLen

let fsub ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let oprSize = ins.OprSize
  !!ir (dstAssign oprSize dst (AST.fsub src1 src2))
  !>ir insLen

let insv ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  match ins.Operands with
  | TwoOperands (OprSIMD (SIMDVecRegWithIdx (_, _, fstIdx)),
    OprSIMD (SIMDVecRegWithIdx (_, _, sndIdx))) ->
    let struct (o1, o2) = getTwoOprs ins
    let dst = transVectorWithIdx ins ctxt addr fstIdx o1
    let src = transVectorWithIdx ins ctxt addr sndIdx o2
    !!ir (dst := src)
  | TwoOperands (OprSIMD (SIMDVecRegWithIdx (_, _, idx)), OprRegister _) ->
    let struct (o1, o2) = getTwoOprs ins
    let src = transOprToExpr ins ctxt addr o2
    let struct (eSize, _, _) = getElemDataSzAndElems o1
    let dst = transVectorWithIdx ins ctxt addr idx o1
    !!ir (dst := AST.xtlo eSize src)
  | _ -> raise InvalidOperandException
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
  !!ir (dstAssign ins.OprSize dst (AST.loadLE ins.OprSize address))
  !>ir insLen

let ldarb ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, (bReg, offset) = transTwoOprsSepMem ins ctxt addr
  let address = !+ir 64<rt>
  !<ir insLen
  !!ir (address := bReg .+ offset)
  mark ctxt address (memSizeToExpr 8<rt>) ir
  !!ir (dstAssign ins.OprSize dst (AST.loadLE 8<rt> address))
  !>ir insLen

let ldax ins insLen ctxt addr size =
  let ir = !*ctxt
  let dst, (bReg, offset) = transTwoOprsSepMem ins ctxt addr
  let address = !+ir 64<rt>
  !<ir insLen
  !!ir (address := bReg .+ offset)
  mark ctxt address (memSizeToExpr size) ir
  !!ir (dstAssign ins.OprSize dst (AST.loadLE size address))
  !>ir insLen

let ldaxr ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, (bReg, offset) = transTwoOprsSepMem ins ctxt addr
  let address = !+ir 64<rt>
  !<ir insLen
  !!ir (address := bReg .+ offset)
  mark ctxt address (memSizeToExpr ins.OprSize) ir
  !!ir (dstAssign ins.OprSize dst (AST.loadLE ins.OprSize address))
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
    !!ir (dstAssign ins.OprSize dst1 (AST.xtlo 32<rt> src))
    !!ir (dstAssign ins.OprSize dst2 (AST.xthi 32<rt> src))
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
    !!ir (dstAssign oprSize src1 (AST.loadLE oprSize address))
    !!ir (dstAssign oprSize src2 (AST.loadLE oprSize (address .+ dByte)))
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
      !!ir (dstAssign ins.OprSize dst data)
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
      !!ir (dstAssign ins.OprSize dst data)
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
  !!ir (dstAssign ins.OprSize dst (AST.zext 32<rt> data))
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
  !!ir (dstAssign ins.OprSize dst (AST.zext 32<rt> data))
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
  !!ir (dstAssign ins.OprSize dst (AST.sext ins.OprSize data))
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
  !!ir (dstAssign ins.OprSize dst (AST.sext ins.OprSize data))
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
  !!ir (dstAssign ins.OprSize dst (AST.zext ins.OprSize data))
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
    !!ir (dstAssign ins.OprSize dst data)
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
  !!ir (dstAssign ins.OprSize src (AST.zext 32<rt> data))
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
  !!ir (dstAssign ins.OprSize src (AST.zext 32<rt> data))
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
  !!ir (dstAssign ins.OprSize dst (AST.sext ins.OprSize data))
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
  !!ir (dstAssign ins.OprSize dst (AST.sext 64<rt> data))
  !>ir insLen

let logShift ins insLen ctxt addr shift =
  let ir = !*ctxt
  let dst, src, amt = transThreeOprs ins ctxt addr
  !<ir insLen
  !!ir (dstAssign ins.OprSize dst (shift src amt))
  !>ir insLen

let lslv ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let oprSz = ins.OprSize
  let dataSize = numI32 (RegType.toBitWidth ins.OprSize) oprSz
  !<ir insLen
  let result = shiftReg src1 (src2 .% dataSize) oprSz SRTypeLSL
  !!ir (dstAssign ins.OprSize dst result)
  !>ir insLen

let lsrv ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let oprSz = ins.OprSize
  let dataSize = numI32 (RegType.toBitWidth oprSz) oprSz
  !<ir insLen
  let result = shiftReg src1 (src2 .% dataSize) oprSz SRTypeLSR
  !!ir (dstAssign ins.OprSize dst result)
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
    !!ir (dstAssign ins.OprSize dst (src3 .+ (src1 .* src2)))
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
    !!ir (dstAssign ins.OprSize dst src)
  !>ir insLen

let movi ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  match ins.Operands with
  | TwoOperands (OprSIMD (SIMDFPScalarReg _), OprImm _) ->
    let dst, src = transTwoOprs ins ctxt addr
    !!ir (dstAssign ins.OprSize dst src)
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
  !!ir (dstAssign ins.OprSize dst ((dst .& mask) .| src))
  !>ir insLen

let movn ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let dst, src = transThreeOprsWithBarrelShift ins ctxt addr
  !!ir (dstAssign ins.OprSize dst (AST.not src))
  !>ir insLen

let movz ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  let dst, src = transThreeOprsWithBarrelShift ins ctxt addr
  !!ir (dstAssign ins.OprSize dst src)
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
  !!ir (dstAssign ins.OprSize dst (src3 .- (src1 .* src2)))
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
  | TwoOperands _ -> !!ir (AST.sideEffect UnsupportedFP)
  | ThreeOperands (OprSIMD _, OprSIMD _, OprSIMD _) ->
    !!ir (AST.sideEffect UnsupportedFP)
  | _ ->
    let dst, src1, src2 = transOprToExprOfORN ins ctxt addr
    !!ir (dstAssign ins.OprSize dst (src1 .| AST.not src2))
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
    !!ir (dstAssign ins.OprSize dst (src1 .| src2))
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
    !!ir (dstAssign ins.OprSize dst tmp)
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
    !!ir (dstAssign ins.OprSize dst t)
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
    !!ir (dstAssign ins.OprSize dst tmp)
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
  !!ir (dstAssign ins.OprSize dst (shiftReg src1 amount ins.OprSize SRTypeROR))
  !>ir insLen

let sbc ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2 = transThreeOprs ins ctxt addr
  let c = AST.zext ins.OprSize (getRegVar ctxt R.C)
  !<ir insLen
  let result, _ = addWithCarry src1 (AST.not src2) c ins.OprSize
  !!ir (dstAssign ins.OprSize dst result)
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
  !!ir (dstAssign ins.OprSize dst ((top .& AST.not tMask) .| (bot .& tMask)))
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
  let intOperand = if unsigned then AST.cast CastKind.UIntToFloat oprSz src
                   else AST.cast CastKind.SIntToFloat oprSz src
  let num0 = AST.cast CastKind.SIntToFloat oprSz (AST.num0 oprSz)
  let divBits = AST.cast CastKind.SIntToFloat oprSz (AST.num1 oprSz << fbits)
  let realOperand = AST.fdiv intOperand divBits
  let cond = AST.eq realOperand num0
  let result =
    match round with
    | FPRounding_TIEEVEN
    | FPRounding_TIEAWAY -> AST.cast CastKind.FtoFRound oprSz
    | FPRounding_Zero -> AST.cast CastKind.FtoFTrunc oprSz
    | FPRounding_POSINF -> AST.cast CastKind.FtoFCeil oprSz
    | FPRounding_NEGINF -> AST.cast CastKind.FtoFFloor oprSz
  AST.ite cond (AST.num0 oprSz) (result realOperand)

let scvtf ins insLen ctxt addr =
  let ir = !*ctxt
  let oprSize = ins.OprSize
  !<ir insLen
  match ins.Operands with
  | TwoOperands (_) ->
    let dst, src = transTwoOprs ins ctxt addr
    let result = fixedToFp oprSize src (AST.num0 oprSize)
                  false FPRounding_TIEEVEN
    !!ir (dstAssign oprSize dst result)
  | _ ->
    let dst, src, fbits = transThreeOprs ins ctxt addr
    let result = fixedToFp oprSize src fbits false FPRounding_TIEEVEN
    !!ir (dstAssign oprSize dst result)
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
  !!ir (dstAssign ins.OprSize dst result)
  !>ir insLen

let shl ins insLen ctxt addr =
  let ir = !*ctxt
  let struct (dst, src, amt) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems src
  !<ir insLen
  match ins.Operands with
  | ThreeOperands (OprSIMD (SIMDFPScalarReg _), _, _) ->
    let dst, src, amt = transThreeOprs ins ctxt addr
    !!ir (dstAssign ins.OprSize dst (src << amt))
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
    !!ir (dstAssign ins.OprSize dst (opFn src amt))
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
  !!ir (dstAssign ins.OprSize (AST.loadLE ins.OprSize address) src)
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
  !!ir (dstAssign 32<rt> src1 status)
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
  !!ir (dstAssign 32<rt> src1 status)
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
    !!ir (dstAssign 32<rt> src1 status)
  else
    let status = exclusiveMonitorsPassPair ctxt address 64<rt> src2 src3 ir
    !!ir (dstAssign 32<rt> src1 status)
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
    !!ir (dstAssign ins.OprSize dst (AST.neg src))
  | TwoOperands (OprSIMD (SIMDVecReg _) as o1, o2) ->
    let dstB, dstA = transOprToExpr128 ins ctxt addr o1
    let struct (eSize, dataSize, elements) = getElemDataSzAndElems o2
    let src = transSIMDOprToExpr ctxt eSize dataSize elements o2
    let result = Array.map (AST.neg) src
    dstAssignForSIMD dstA dstB result dataSize elements ir
  | ThreeOperands (OprSIMD (SIMDFPScalarReg _), _, _)
      when ins.Opcode = Opcode.SUB ->
    let dst, src1, src2 = transThreeOprs ins ctxt addr
    !!ir (dstAssign ins.OprSize dst (src1 .- src2))
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
    !!ir (dstAssign ins.OprSize dst result)
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
  !!ir (dstAssign ins.OprSize dst result)
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
  !!ir (dstAssign ins.OprSize dst (bot .& (numI64 tmask oSz)))
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
  !!ir (dstAssign ins.OprSize dst result)
  !>ir insLen

let umaddl ins insLen ctxt addr =
  let ir = !*ctxt
  let dst, src1, src2, src3 = transFourOprs ins ctxt addr
  !<ir insLen
  !!ir (dst := src3 .+ (AST.zext 64<rt> src1 .* AST.zext 64<rt> src2))
  !>ir insLen

let uminv ins insLen ctxt addr =
  let ir = !*ctxt
  let struct (o1, o2) = getTwoOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems o2
  let dst = transOprToExpr ins ctxt addr o1
  let src = transSIMDOprToExpr ctxt eSize dataSize elements o2
  let min = !+ir eSize
  !<ir insLen
  !!ir (min := src[0])
  Array.sub src 1 (elements - 1)
  |> Array.iter (fun e -> !!ir (min := AST.ite (min .<= e) min e))
  !!ir (dstAssign eSize dst min)
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
    !!ir (dstAssign eSize dst (satQ diff eSize true ir))
  | _ -> raise InvalidOperandException
  !>ir insLen

let private vectorPart ctxt eSize srcSize elements src =
  let regA, regB =
    match src with
    | OprSIMD (SIMDVecReg (reg, _)) ->
      getPseudoRegVar ctxt reg 1, getPseudoRegVar ctxt reg 2
    | _ -> raise InvalidOperandException
  let pos = int eSize
  if srcSize <> 128<rt> then
    Array.init elements (fun i -> AST.extract regA eSize (i * pos))
  else Array.init (elements / 2) (fun i -> AST.extract regB eSize (i * pos))

let shiftLeftLong ins insLen ctxt addr =
  let ir = !*ctxt
  let struct (o1, o2, o3) = getThreeOprs ins
  let struct (_, srcDataSize, srcElements) = getElemDataSzAndElems o2
  let fixedDataSize = 64<rt>
  let eSize = fixedDataSize / srcElements
  let qSize = srcDataSize / srcElements
  let elements = fixedDataSize / qSize
  !<ir insLen
  let dst = transSIMDOprToExpr ctxt (2 * qSize) (2 * fixedDataSize) elements o1
  let amt = transOprToExpr ins ctxt addr o3 |> AST.xtlo (2 * qSize)
  let result = vectorPart ctxt eSize srcDataSize srcElements o2
               |> Array.map (fun s -> (AST.zext (2 * qSize) s) << amt)
  Array.iter2 (fun d s -> !!ir (d := s)) dst result
  !>ir insLen

let roundShiftLeft ins insLen ctxt addr =
  let ir = !*ctxt
  !<ir insLen
  match ins.Operands with
  | ThreeOperands (OprSIMD (SIMDFPScalarReg _), _, _) ->
    let dst, src, shiftReg = transThreeOprs ins ctxt addr
    let round = src << (shiftReg .& numI64 0xffL 64<rt>)
    !!ir (dstAssign ins.OprSize dst round)
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

let usra ins insLen ctxt addr =
  let ir = !*ctxt
  let struct (o1, o2, o3) = getThreeOprs ins
  let struct (eSize, dataSize, elements) = getElemDataSzAndElems o1
  let dst = transSIMDOprToExpr ctxt eSize dataSize elements o1
  let src = transSIMDOprToExpr ctxt eSize dataSize elements o2
  let shf = transOprToExpr ins ctxt addr o3 |> AST.xtlo eSize
  !<ir insLen
  Array.map2 (fun e1 e2 -> e1 .+ (e2 >> shf)) dst src
  |> Array.iter2 (fun e1 e2 -> !!ir (e1 := e2)) dst
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
  | Opcode.ADC -> adc ins insLen ctxt addr
  | Opcode.ADCS -> adcs ins insLen ctxt addr
  | Opcode.ADD -> add ins insLen ctxt addr
  | Opcode.ADDP -> addp ins insLen ctxt addr
  | Opcode.ADDS -> adds ins insLen ctxt addr
  | Opcode.ADDV -> sideEffects insLen ctxt UnsupportedFP
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
  | Opcode.BIF -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.BIT -> sideEffects insLen ctxt UnsupportedFP
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
  | Opcode.BSL -> sideEffects insLen ctxt UnsupportedFP
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
  | Opcode.CMHI -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.CMHS -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.CMLT -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.CMN -> cmn ins insLen ctxt addr
  | Opcode.CMP -> cmp ins insLen ctxt addr
  | Opcode.CMTST -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.CNEG | Opcode.CSNEG -> csneg ins insLen ctxt addr
  | Opcode.CNT -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.CSEL -> csel ins insLen ctxt addr
  | Opcode.CSETM | Opcode.CINV | Opcode.CSINV -> csinv ins insLen ctxt addr
  | Opcode.CSINC | Opcode.CINC | Opcode.CSET -> csinc ins insLen ctxt addr
  | Opcode.DCZVA -> dczva ins insLen ctxt addr
  | Opcode.DMB | Opcode.DSB | Opcode.ISB -> nop insLen ctxt
  | Opcode.DUP -> dup ins insLen ctxt addr
  | Opcode.EOR | Opcode.EON -> eor ins insLen ctxt addr
  | Opcode.EXT -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.EXTR | Opcode.ROR -> extr ins insLen ctxt addr
  | Opcode.FABD -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.FABS -> fabs ins insLen ctxt addr
  | Opcode.FADD -> fadd ins insLen ctxt addr
  | Opcode.FADDP -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.FCCMP -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.FCCMPE -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.FCMP -> fcmp ins insLen ctxt addr
  | Opcode.FCMPE -> fcmpe ins insLen ctxt addr
  | Opcode.FCSEL -> fcsel ins insLen ctxt addr
  | Opcode.FCVT -> fcvt ins insLen ctxt addr
  | Opcode.FCVTMS -> fcvtm ins insLen ctxt addr false
  | Opcode.FCVTMU -> fcvtm ins insLen ctxt addr true
  | Opcode.FCVTZS -> fcvtz ins insLen ctxt addr false
  | Opcode.FCVTZU -> fcvtz ins insLen ctxt addr true
  | Opcode.FDIV -> fdiv ins insLen ctxt addr
  | Opcode.FMADD -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.FMAX -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.FMAXNM -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.FMOV -> fmov ins insLen ctxt addr
  | Opcode.FMSUB -> sideEffects insLen ctxt UnsupportedFP
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
  | Opcode.SCVTF -> scvtf ins insLen ctxt addr
  | Opcode.SDIV -> sdiv ins insLen ctxt addr
  | Opcode.SHL -> shl ins insLen ctxt addr
  | Opcode.SMADDL -> smaddl ins insLen ctxt addr
  | Opcode.SMSUBL | Opcode.SMNEGL -> smsubl ins insLen ctxt addr
  | Opcode.SMULH -> smulh ins insLen ctxt addr
  | Opcode.SMULL -> smull ins insLen ctxt addr
  | Opcode.SSHL | Opcode.USHL -> shift ins insLen ctxt addr (<<)
  | Opcode.SSHLL | Opcode.SSHLL2 | Opcode.USHLL | Opcode.USHLL2 ->
    shiftLeftLong ins insLen ctxt addr
  | Opcode.SSHR -> shift ins insLen ctxt addr (?>>)
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
  | Opcode.UCVTF -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.UDIV -> udiv ins insLen ctxt addr
  | Opcode.UMADDL -> umaddl ins insLen ctxt addr
  | Opcode.UMAX -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.UMAXV -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.UMINV -> uminv ins insLen ctxt addr
  | Opcode.UMLAL -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.UMLAL2 -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.UMOV -> sideEffects insLen ctxt UnsupportedFP
  | Opcode.UMSUBL | Opcode.UMNEGL -> umsubl ins insLen ctxt addr
  | Opcode.UMULH -> umulh ins insLen ctxt addr
  | Opcode.UMULL -> umull ins insLen ctxt addr
  | Opcode.UQSUB -> uqsub ins insLen ctxt addr
  | Opcode.URSHL | Opcode.SRSHL -> roundShiftLeft ins insLen ctxt addr
  | Opcode.USHR -> shift ins insLen ctxt addr (>>)
  | Opcode.USRA -> usra ins insLen ctxt addr
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
