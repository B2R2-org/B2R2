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

module internal B2R2.FrontEnd.SH4.GeneralLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils

let numI32 (n: int) = BitVector(n, 32<rt>) |> AST.num

let numI32PC (n: int) = BitVector(n, 32<rt>) |> AST.num

let numI64 (n: int64) = BitVector(n, 16<rt>) |> AST.num

let exprToInt (n: Expr) =
  match n with
  | Num(a, _) -> a
  | _ -> Terminator.impossible ()

let bv1Check s =
  (exprToInt s).IsOne

let trsOprToExpr bld = function
  | OpReg(Regdir r) -> regVar bld r
  | OpReg(RegIndir r) -> regVar bld r
  | OpReg(IdxGBRIndir(r, _)) -> regVar bld r
  | OpReg(Imm n) -> numI32PC n
  | _ -> Terminator.impossible ()

let trsOneOpr (ins: Instruction) bld =
  match ins.Operands with
  | OneOperand r -> trsOprToExpr bld r
  | _ -> raise InvalidOperandException

let trsTwoOpr (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(o1, o2) ->
    struct (trsOprToExpr bld o1, trsOprToExpr bld o2)
  | _ -> raise InvalidOperandException

let trsThreeOpr (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(o1, o2, o3) ->
    struct (trsOprToExpr bld o1, trsOprToExpr bld o2, trsOprToExpr bld o3)
  | _ -> raise InvalidOperandException

let trsMemOpr1toExpr (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OpReg(RegIndirPreDec r1), OpReg(Regdir r2)) ->
    struct (regVar bld r1, regVar bld r2, -1)
  | TwoOperands(OpReg(RegIndirPostInc r1), OpReg(Regdir r2)) ->
     struct (regVar bld r1, regVar bld r2, 1)
  | TwoOperands(OpReg(RegIndir r1), OpReg(Regdir r2)) ->
    struct (regVar bld r1, regVar bld r2, 0)
  | _ -> Terminator.impossible ()

let trsMemOpr2toExpr (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OpReg(Regdir r1), OpReg(RegIndirPreDec r2)) ->
    (regVar bld r1, regVar bld r2, -1)
  | TwoOperands(OpReg(Regdir r1), OpReg(RegIndirPostInc r2)) ->
    (regVar bld r1, regVar bld r2, 1)
  | TwoOperands(OpReg(Regdir r1), OpReg(RegIndir r2)) ->
    (regVar bld r1, regVar bld r2, 0)
  | _ -> Terminator.impossible ()

let trsMemOpr3toExpr (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OpReg(RegIndirDisp(imm, r1)), OpReg(Regdir r2)) ->
    struct (regVar bld r1, regVar bld r2, numI32 imm)
  | _ -> Terminator.impossible ()

let trsMemOpr4toExpr (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OpReg(Regdir r1), OpReg(RegIndirDisp(imm, r2))) ->
    struct (regVar bld r1, regVar bld r2, numI32 imm)
  | _ -> Terminator.impossible ()

let illSlot1 (ins: Instruction) bld len =
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld R.SPC := regVar bld R.PC .- numI32 2)
  bld <+ (regVar bld R.SSR := regVar bld R.SR)
  bld <+ (regVar bld R.SGR := regVar bld R.R15)
  bld <+ (regVar bld R.EXPEVT := numI32PC 0x000001A0)
  bld <+ (regVar bld R.MD := AST.b1)
  bld <+ (regVar bld R.RB := AST.b1)
  bld <+ (regVar bld R.BL := AST.b1)
  bld <+ (regVar bld R.PC := regVar bld R.VBR .+ numI32PC 0x00000100)
  bld <+ (AST.sideEffect (Exception("ILLSLOT")))
  bld --!> len

let illSlot2 bld len =
  bld <+ (regVar bld R.SPC := regVar bld R.PC .- numI32 2)
  bld <+ (regVar bld R.SSR := regVar bld R.SR)
  bld <+ (regVar bld R.SGR := regVar bld R.R15)
  bld <+ (regVar bld R.EXPEVT := numI32PC 0x000001A0)
  bld <+ (regVar bld R.MD := AST.b1)
  bld <+ (regVar bld R.RB := AST.b1)
  bld <+ (regVar bld R.BL := AST.b1)
  bld <+ (regVar bld R.PC := regVar bld R.VBR .+ numI32PC 0x00000100)
  bld <+ (AST.sideEffect (Exception("ILLSLOT")))
  bld --!> len

let fpudis bld =
  bld <+ (regVar bld R.SPC := regVar bld R.PC)
  bld <+ (regVar bld R.SSR := regVar bld R.SR)
  bld <+ (regVar bld R.SGR := regVar bld R.R15)
  bld <+ (regVar bld R.EXPEVT := numI32PC 0x00000800)
  bld <+ (regVar bld R.MD := AST.b1)
  bld <+ (regVar bld R.RB := AST.b1)
  bld <+ (regVar bld R.BL := AST.b1)
  bld <+ (regVar bld R.PC := regVar bld R.VBR .+ numI32PC 0x00000100)
  bld <+ (AST.sideEffect (Exception("FPUDIS")))

let slotFpudis bld =
  bld <+ (regVar bld R.SPC := regVar bld R.PC .- numI32 2)
  bld <+ (regVar bld R.SSR := regVar bld R.SR)
  bld <+ (regVar bld R.SGR := regVar bld R.R15)
  bld <+ (regVar bld R.EXPEVT := numI32PC 0x00000820)
  bld <+ (regVar bld R.MD := AST.b1)
  bld <+ (regVar bld R.RB := AST.b1)
  bld <+ (regVar bld R.BL := AST.b1)
  bld <+ (regVar bld R.PC := regVar bld R.VBR .+ numI32PC 0x00000100)
  bld <+ (AST.sideEffect (Exception("SLOTFPUDIS")))

let fpuExc bld =
  bld <+ (regVar bld R.SPC := regVar bld R.PC)
  bld <+ (regVar bld R.SSR := regVar bld R.SR)
  bld <+ (regVar bld R.SGR := regVar bld R.R15)
  bld <+ (regVar bld R.EXPEVT := numI32PC 0x00000120)
  bld <+ (regVar bld R.MD := AST.b1)
  bld <+ (regVar bld R.RB := AST.b1)
  bld <+ (regVar bld R.BL := AST.b1)
  bld <+ (regVar bld R.PC := regVar bld R.VBR .+ numI32PC 0x00000100)
  bld <+ (AST.sideEffect (Exception("FPUEXC")))

let trap bld imm =
  bld <+ (regVar bld R.SPC := regVar bld R.PC .+ numI32 2)
  bld <+ (regVar bld R.SSR := regVar bld R.SR)
  bld <+ (regVar bld R.SGR := regVar bld R.R15)
  bld <+ (regVar bld R.TRA := imm << numI32 2)
  bld <+ (regVar bld R.EXPEVT := numI32PC 0x00000160)
  bld <+ (regVar bld R.MD := AST.b1)
  bld <+ (regVar bld R.RB := AST.b1)
  bld <+ (regVar bld R.BL := AST.b1)
  bld <+ (regVar bld R.PC := regVar bld R.VBR .+ numI32PC 0x00000100)
  bld <+ (AST.sideEffect (Exception("TRAPA")))

let resinst bld =
  bld <+ (regVar bld R.SPC := regVar bld R.PC)
  bld <+ (regVar bld R.SSR := regVar bld R.SR)
  bld <+ (regVar bld R.SGR := regVar bld R.R15)
  bld <+ (regVar bld R.EXPEVT := numI32PC 0x00000180)
  bld <+ (regVar bld R.MD := AST.b1)
  bld <+ (regVar bld R.RB := AST.b1)
  bld <+ (regVar bld R.BL := AST.b1)
  bld <+ (regVar bld R.PC := regVar bld R.VBR .+ numI32PC 0x00000100)
  bld <+ (AST.sideEffect (Exception("RESINST")))

let fpuCheck fps n =
  bv1Check (AST.extract fps 1<rt> n)

let signedSaturate r =
  AST.ite ((r ?< numI32 (int ((-2.0) ** 32)))
            .| (r ?> numI32 (int ((2.0) ** 32))))
          (AST.ite ((r ?< numI32 (int ((-2.0) ** 32))))
                   (numI32 (int ((-2.0) ** 32)))
                   (numI32 (int ((2.0) ** 32))))
          r

/// Carry Forward check
let cfonAdd e1 e2 r =
  let e1H = AST.xthi 1<rt> e1
  let e2H = AST.xthi 1<rt> e2
  let rH = AST.neg (AST.xthi 1<rt> r)
  (e1H .& e2H) .| (e2H .& rH) .| (e1H .& rH)

/// Overflow check
let ofonAdd e1 e2 r =
  let e1H = AST.xthi 1<rt> e1
  let e2H = AST.xthi 1<rt> e2
  let rH = AST.xthi 1<rt> r
  (e1H .& e2H .& (AST.neg rH)) .| ((AST.neg e1H) .& (AST.neg e2H) .& rH)

let add ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  match src with
  | Num(n, _) ->
    let t1 = tmpVar bld 8<rt>
    let t2 = tmpVar bld 32<rt>
    bld <!-- (ins.Address, len)
    bld <+ (t1 := n |> AST.num |> AST.sext 8<rt>)
    bld <+ (t2 := dst |> AST.sext 32<rt>)
    bld <+ (t2 := t2 .+ t1)
    bld <+ (dst := t2)
    bld --!> len
  | Var(_, _, s, _) ->
    let oprSize = 32<rt>
    let struct (t1, t2) = tmpVars2 bld oprSize
    bld <!-- (ins.Address, len)
    bld <+ (t1 := s |> Register.ofString |> regVar bld |> AST.sext 32<rt>)
    bld <+ (t2 := dst |> AST.sext 32<rt>)
    bld <+ (t2 := t2 .+ t1)
    bld <+ (dst := AST.xtlo 32<rt> t2)
    bld --!> len
  | _ -> Terminator.impossible ()

let addc ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let oprSize = 32<rt>
  let struct (t1,t2) = tmpVars2 bld oprSize
  let t = tmpVar bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (t := AST.zext 1<rt> (regVar bld R.T))
  bld <+ (t1 := AST.zext 32<rt> <| AST.sext 32<rt> src)
  bld <+ (t2 := AST.zext 32<rt> <| AST.sext 32<rt> dst)
  bld <+ (t2 := t2 .+ t1 .+ t)
  bld <+ (t := AST.extract t2 1<rt> 32)
  bld <+ (dst := AST.xtlo 32<rt> t2)
  bld <+ ((regVar bld R.T) := t)
  bld --!> len

let addv ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let oprSize = 32<rt>
  let struct (t1,t2) = tmpVars2 bld oprSize
  let t = tmpVar bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (t1 := AST.sext 32<rt> src)
  bld <+ (t2 := AST.sext 32<rt> dst)
  bld <+ (t2 := t2 .+ t1)
  bld <+ (dst := AST.xtlo 32<rt> t2)
  bld <+ (t := ((t2 .< (pown -2 31 |> numI32PC))
             .| (t2 ?>= (pown 2 31 |> numI32PC))))
  bld --!> len

let ``and`` ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  match src with
  | Num(n, _) ->
    let t1 = tmpVar bld 8<rt>
    let t2 = tmpVar bld 32<rt>
    bld <!-- (ins.Address, len)
    bld <+ (t1 := n |> AST.num |> AST.zext 8<rt>)
    bld <+ (t2 := AST.zext 32<rt> dst)
    bld <+ (t2 := t2 .& t1)
    bld <+ (dst := AST.xtlo 32<rt> t2)
    bld --!> len
  | Var(_, _, s, _) ->
    let oprSize = 32<rt>
    let struct (t1,t2) = tmpVars2 bld oprSize
    bld <!-- (ins.Address, len)
    bld <+ (t1 := Register.ofString s |> regVar bld |> AST.zext 32<rt>)
    bld <+ (t2 := AST.zext 32<rt> dst)
    bld <+ (t2 := t2 .& t1)
    bld <+ (dst := AST.xtlo 32<rt> t2)
    bld --!> len
  | _ -> Terminator.impossible ()

let andb ins len bld =
  let struct (src, _) = trsTwoOpr ins bld
  let struct (r0,gbr,addr) = tmpVars3 bld 32<rt>
  let struct (imm,value) = tmpVars2 bld 8<rt>
  bld <!-- (ins.Address, len)
  bld <+ (r0 := R.R0 |> regVar bld |> AST.sext 32<rt>)
  bld <+ (gbr := R.GBR |> regVar bld |> AST.sext 32<rt>)
  bld <+ (imm := AST.zext 8<rt> src)
  bld <+ (addr := (r0 .+ gbr) |> AST.zext 32<rt>)
  bld <+ (value := addr |> AST.loadLE 8<rt> |> AST.zext 8<rt>)
  bld <+ (value := value .& imm)
  bld <+ (AST.store Endian.Little addr value)
  bld --!> len

let bfHelper bld ins len =
  let disp = trsOneOpr ins bld
  let struct (pc, newPC, delayedPC) = tmpVars3 bld 32<rt>
  let t = tmpVar bld 1<rt>
  let label = tmpVar bld 8<rt>
  let temp = tmpVar bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (t := regVar bld R.T |> AST.zext 1<rt>)
  bld <+ (pc := regVar bld R.PC |> AST.sext 32<rt>)
  bld <+ (newPC := (regVar bld R.PC .+ numI32 2) |> AST.sext 32<rt>)
  bld <+ (delayedPC := (regVar bld R.PC .+ numI32 4) |> AST.sext 32<rt>)
  bld <+ (label := (AST.sext 8<rt> disp) << AST.b1)
  bld <+ (temp := AST.zext 32<rt> (pc .+ label .+ (numI32 4)))
  bld <+ (newPC := AST.ite (t == AST.b0) (temp) (newPC))
  bld <+ (delayedPC := AST.ite (t == AST.b0) (temp .+ numI32 2) (delayedPC))
  bld <+ (regVar bld R.PC .+ numI32 2 := AST.xtlo 32<rt> newPC)
  bld <+ (regVar bld R.PC .+ numI32 4 := AST.xtlo 32<rt> delayedPC)
  bld --!> len

let bf ins len bld =
  bfHelper bld ins len

let bfsHelper bld ins len =
  let disp = trsOneOpr ins bld
  let struct (pc, delayedPC) = tmpVars2 bld 32<rt>
  let t = tmpVar bld 1<rt>
  let label = tmpVar bld 8<rt>
  let temp = tmpVar bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (t := regVar bld R.T |> AST.zext 1<rt>)
  bld <+ (pc := regVar bld R.PC |> AST.sext 32<rt>)
  bld <+ (delayedPC := (regVar bld R.PC .+ numI32 2) |> AST.sext 32<rt>)
  bld <+ (label := (AST.sext 8<rt> disp) << AST.b1)
  bld <+ (temp := AST.zext 32<rt> (pc .+ label .+ (numI32 4)))
  bld <+ (delayedPC := AST.ite (t == AST.b0) (temp .+ numI32 2) (delayedPC))
  bld <+ (regVar bld R.PC .+ numI32 2 := AST.xtlo 32<rt> delayedPC)
  bld --!> len

let bfs (ins: Instruction) len bld =
  bld <!-- (ins.Address, len)
  bld --!> len

let braHelper bld ins len =
  let disp = trsOneOpr ins bld
  let struct (pc, temp, delayedPC) = tmpVars3 bld 32<rt>
  let label = tmpVar bld 12<rt>
  bld <!-- (ins.Address, len)
  bld <+ (pc := AST.sext 32<rt> pc)
  bld <+ (label := AST.sext 12<rt> disp)
  bld <+ (temp := AST.zext 32<rt> (pc .+ label .+ (numI32 4)))
  bld <+ (delayedPC := temp)
  bld <+ (regVar bld R.PC .+ (numI32 2) := AST.xtlo 32<rt> delayedPC)
  bld --!> len

let bra (ins: Instruction) len bld =
  bld <!-- (ins.Address, len)
  braHelper bld ins len

let brafHelper bld ins len =
  let dst = trsOneOpr ins bld
  let struct (pc, op1, target, delayedPC) = tmpVars4 bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (pc := regVar bld R.PC |> AST.sext 32<rt>)
  bld <+ (op1 := AST.sext 32<rt> dst)
  bld <+ (target := (pc .+ op1 .+ (numI32 4)) |> AST.zext 32<rt>)
  bld <+ (delayedPC := target .| (AST.neg AST.b1))
  bld <+ (regVar bld R.PC .+ (numI32 2) := AST.xtlo 32<rt> delayedPC)
  bld --!> len

let braf (ins: Instruction) len bld =
  bld <!-- (ins.Address, len)
  brafHelper bld ins len

let bsrHelper bld ins len =
  let disp = trsOneOpr ins bld
  let struct (pc, delayedPR, temp, delayedPC) = tmpVars4 bld 32<rt>
  let label = tmpVar bld 12<rt>
  bld <!-- (ins.Address, len)
  bld <+ (pc := regVar bld R.PC |> AST.sext 32<rt>)
  bld <+ (label := (AST.sext 32<rt> disp) << AST.b1)
  bld <+ (delayedPR := pc .+ numI32 4)
  bld <+ (temp := (pc .+ label .+ numI32 4) |> AST.zext 32<rt>)
  bld <+ (delayedPC := temp)
  bld <+ (regVar bld R.PR := AST.xtlo 32<rt> delayedPR)
  bld <+ (regVar bld R.PC := AST.xtlo 32<rt> delayedPC)
  bld --!> len

let bsr (ins: Instruction) len bld =
  bld <!-- (ins.Address, len)
  bsrHelper bld ins len

let bsrfHelper bld ins len =
  let dst = trsOneOpr ins bld
  let struct (pc, delayedPR, op1, delayedPC) = tmpVars4 bld 32<rt>
  let target = tmpVar bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (pc := regVar bld R.PC |> AST.sext 32<rt>)
  bld <+ (op1 := AST.sext 32<rt> dst)
  bld <+ (delayedPR := pc .+ numI32 4)
  bld <+ (target := (pc .+ op1 .+ numI32 4) |> AST.zext 32<rt>)
  bld <+ (delayedPC := target .| (AST.neg AST.b1))
  bld <+ (regVar bld R.PR := AST.xtlo 32<rt> delayedPR)
  bld <+ (regVar bld R.PC := AST.xtlo 32<rt> delayedPC)
  bld --!> len

let bsrf (ins: Instruction) len bld =
  bld <!-- (ins.Address, len)
  bsrfHelper bld ins len

let btHelper bld ins len =
  let disp = trsOneOpr ins bld
  let struct (pc, newPC, delayedPC, temp) = tmpVars4 bld 32<rt>
  let t = tmpVar bld 1<rt>
  let label = tmpVar bld 8<rt>
  bld <!-- (ins.Address, len)
  bld <+ (t := regVar bld R.T |> AST.zext 1<rt>)
  bld <+ (pc := regVar bld R.PC |> AST.sext 32<rt>)
  bld <+ (newPC := (regVar bld R.PC .+ numI32 2) |> AST.sext 32<rt>)
  bld <+ (delayedPC := (regVar bld R.PC .+ numI32 4) |> AST.sext 32<rt>)
  bld <+ (label := (AST.sext 8<rt> disp) << AST.b1)
  bld <+ (temp := (pc .+ label .+ numI32 4) |> AST.zext 32<rt>)
  bld <+ (newPC := AST.ite (t == AST.b1) (temp) (newPC))
  bld <+ (delayedPC := AST.ite (t == AST.b1) (temp .+ numI32 2) (delayedPC))
  bld <+ (regVar bld R.PC .+ numI32 2 := AST.xtlo 32<rt> newPC)
  bld <+ (regVar bld R.PC .+ numI32 4 := AST.xtlo 32<rt> delayedPC)
  bld --!> len

let bt ins len bld =
  btHelper bld ins len

let btsHelper bld ins len =
  let disp = trsOneOpr ins bld
  let struct (pc, delayedPC, temp) = tmpVars3 bld 32<rt>
  let t = tmpVar bld 1<rt>
  let label = tmpVar bld 8<rt>
  bld <!-- (ins.Address, len)
  bld <+ (t := regVar bld R.T |> AST.zext 1<rt>)
  bld <+ (pc := regVar bld R.PC |> AST.sext 32<rt>)
  bld <+ (delayedPC := (regVar bld R.PC .+ numI32 2) |> AST.sext 32<rt>)
  bld <+ (label := (AST.sext 8<rt> disp) << AST.b1)
  bld <+ (temp := (pc .+ label .+ numI32 4) |> AST.zext 32<rt>)
  bld <+ (delayedPC := AST.ite (t == AST.b1) (temp) (delayedPC))
  bld <+ (regVar bld R.PC .+ numI32 2 := AST.xtlo 32<rt> delayedPC)
  bld --!> len

let bts (ins: Instruction) len bld =
  bld <!-- (ins.Address, len)
  btsHelper bld ins len

let clrmac (ins: Instruction) len bld =
  let struct (macl, mach) = tmpVars2 bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (macl := AST.b0)
  bld <+ (mach := AST.b0)
  bld <+ (regVar bld R.MACL := AST.zext 32<rt> macl)
  bld <+ (regVar bld R.MACH := AST.zext 32<rt> mach)
  bld --!> len

let clrs (ins: Instruction) len bld =
  let s = tmpVar bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (s := AST.b0)
  bld <+ (regVar bld R.S := AST.extract s 1<rt> 1)
  bld --!> len

let clrt (ins: Instruction) len bld =
  let t = tmpVar bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (t := AST.b0)
  bld <+ (regVar bld R.T := AST.extract t 1<rt> 1)
  bld --!> len

let cmpeq ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  match src with
  | Num(n, _) ->
    let r0 = tmpVar bld 32<rt>
    let imm = tmpVar bld 8<rt>
    let t = tmpVar bld 1<rt>
    bld <!-- (ins.Address, len)
    bld <+ (r0 := AST.sext 32<rt> (regVar bld R.R0))
    bld <+ (imm := AST.sext 8<rt> (AST.num n))
    bld <+ (t := r0 == imm)
    bld <+ (regVar bld R.T := AST.extract t 1<rt> 1)
    bld --!> len
  | Var(_, _, r, _) ->
    let struct (op1, op2) = tmpVars2 bld 32<rt>
    let t = tmpVar bld 1<rt>
    bld <!-- (ins.Address, len)
    bld <+ (op1 := (r |> Register.ofString |> regVar bld |> AST.sext 32<rt>))
    bld <+ (op2 := AST.sext 32<rt> dst)
    bld <+ (t := op2 == op1)
    bld <+ (regVar bld R.T := AST.extract t 1<rt> 1)
    bld --!> len
  | _ -> Terminator.impossible ()

let cmpge ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (op1, op2) = tmpVars2 bld 32<rt>
  let t = tmpVar bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := src |> AST.sext 32<rt>)
  bld <+ (op2 := AST.sext 32<rt> dst)
  bld <+ (t := op2 ?>= op1)
  bld <+ (regVar bld R.T := AST.extract t 1<rt> 1)
  bld --!> len

let cmpgt ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (op1, op2) = tmpVars2 bld 32<rt>
  let t = tmpVar bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := src |> AST.sext 32<rt>)
  bld <+ (op2 := AST.sext 32<rt> dst)
  bld <+ (t := op2 ?> op1)
  bld <+ (regVar bld R.T := AST.extract t 1<rt> 1)
  bld --!> len

let cmphi ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (op1, op2) = tmpVars2 bld 32<rt>
  let t = tmpVar bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := src |> AST.zext 32<rt>)
  bld <+ (op2 := AST.zext 32<rt> dst)
  bld <+ (t := op2 .> op1)
  bld <+ (regVar bld R.T := AST.extract t 1<rt> 1)
  bld --!> len

let cmphs ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (op1, op2) = tmpVars2 bld 32<rt>
  let t = tmpVar bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := src |> AST.zext 32<rt>)
  bld <+ (op2 := AST.zext 32<rt> dst)
  bld <+ (t := op2 .>= op1)
  bld <+ (regVar bld R.T := AST.extract t 1<rt> 1)
  bld --!> len

let cmppl ins len bld =
  let dst = trsOneOpr ins bld
  let op1 = tmpVar bld 32<rt>
  let t = tmpVar bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.sext 32<rt> dst)
  bld <+ (t := op1 ?> AST.b0)
  bld <+ (regVar bld R.T := AST.extract t 1<rt> 1)
  bld --!> len

let cmppz ins len bld =
  let dst = trsOneOpr ins bld
  let op1 = tmpVar bld 32<rt>
  let t = tmpVar bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.sext 32<rt> dst)
  bld <+ (t := op1 ?>= AST.b0)
  bld <+ (regVar bld R.T := AST.extract t 1<rt> 1)
  bld --!> len

let cmpstr ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (op1, op2, temp) = tmpVars3 bld 32<rt>
  let t = tmpVar bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.sext 32<rt> src)
  bld <+ (op2 := AST.sext 32<rt> dst)
  bld <+ (temp := op1 <+> op2)
  bld <+ (t := (AST.extract temp 8<rt> 1) == AST.b0)
  bld <+ (t := ((AST.extract temp 8<rt> 8) == AST.b0) .| t)
  bld <+ (t := ((AST.extract temp 8<rt> 16) == AST.b0) .| t)
  bld <+ (t := ((AST.extract temp 8<rt> 24) == AST.b0) .| t)
  bld <+ (regVar bld R.T := AST.extract t 1<rt> 1)
  bld --!> len

let div0s ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (op1, op2) = tmpVars2 bld 32<rt>
  let struct (q, m, t) = tmpVars3 bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.sext 32<rt> src)
  bld <+ (op2 := AST.sext 32<rt> dst)
  bld <+ (q := AST.extract op2 1<rt> 31)
  bld <+ (m := AST.extract op1 1<rt> 31)
  bld <+ (t := m <+> q)
  bld <+ (regVar bld R.Q := AST.extract q 1<rt> 1)
  bld <+ (regVar bld R.M := AST.extract m 1<rt> 1)
  bld <+ (regVar bld R.T := AST.extract t 1<rt> 1)
  bld --!> len

let div0u (ins: Instruction) len bld =
  let struct (q, m, t) = tmpVars3 bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (q := AST.b0)
  bld <+ (m := AST.b0)
  bld <+ (t := AST.b0)
  bld <+ (regVar bld R.Q := AST.extract q 1<rt> 1)
  bld <+ (regVar bld R.M := AST.extract m 1<rt> 1)
  bld <+ (regVar bld R.T := AST.extract t 1<rt> 1)
  bld --!> len

let div1 ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (q, m, t) = tmpVars3 bld 1<rt>
  let oldq = tmpVar bld 1<rt>
  let struct (op1, op2) = tmpVars2 bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (q := regVar bld R.Q |> AST.zext 1<rt>)
  bld <+ (m := regVar bld R.M |> AST.zext 1<rt>)
  bld <+ (t := regVar bld R.T |> AST.zext 1<rt>)
  bld <+ (op1 := AST.sext 32<rt> src |> AST.zext 32<rt>)
  bld <+ (op2 := AST.sext 32<rt> dst |> AST.zext 32<rt>)
  bld <+ (oldq := q)
  bld <+ (q := AST.extract op2 1<rt> 31)
  bld <+ (op2 := (op2 << AST.b1) .| t)
  bld <+ (op2 := AST.ite (oldq == m) (op2 .- op1) (op2 .+ op1))
  bld <+ (q := AST.extract op2 1<rt> 32 |> AST.xor (q <+> m))
  bld <+ (t := AST.b1 .- (q <+> m))
  bld <+ (dst := AST.xtlo 32<rt> op2)
  bld <+ (regVar bld R.Q := AST.extract q 1<rt> 1)
  bld <+ (regVar bld R.T := AST.extract t 1<rt> 1)
  bld --!> len

let dmulsl ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (op1, op2) = tmpVars2 bld 32<rt>
  let mac = tmpVar bld 64<rt>
  let struct (macl, mach) = tmpVars2 bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.sext 32<rt> src)
  bld <+ (op2 := AST.sext 32<rt> dst)
  bld <+ (mac := op2 .* op1)
  bld <+ (macl := mac)
  bld <+ (mach := mac >> numI32 32)
  bld <+ (regVar bld R.MACL := AST.zext 32<rt> macl)
  bld <+ (regVar bld R.MACH := AST.zext 32<rt> mach)
  bld --!> len

let dmulul ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (op1, op2) = tmpVars2 bld 32<rt>
  let mac = tmpVar bld 64<rt>
  let struct (macl, mach) = tmpVars2 bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.sext 32<rt> src |> AST.zext 32<rt>)
  bld <+ (op2 := AST.sext 32<rt> dst |> AST.zext 32<rt>)
  bld <+ (mac := op2 .* op1)
  bld <+ (macl := mac)
  bld <+ (mach := mac >> numI32 32)
  bld <+ (regVar bld R.MACL := AST.zext 32<rt> macl)
  bld <+ (regVar bld R.MACH := AST.zext 32<rt> mach)
  bld --!> len

let dt ins len bld =
  let dst = trsOneOpr ins bld
  let op1 = tmpVar bld 32<rt>
  let t = tmpVar bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.sext 32<rt> dst)
  bld <+ (op1 := op1 .- AST.b1)
  bld <+ (t := op1 == AST.b0)
  bld <+ (dst := AST.xtlo 32<rt> op1)
  bld <+ (regVar bld R.T := AST.extract t 1<rt> 1)
  bld --!> len

let extsb ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (op1, op2) = tmpVars2 bld 8<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.sext 8<rt> src)
  bld <+ (op2 := op1)
  bld <+ (dst := AST.xtlo 32<rt> op2)
  bld --!> len

let extsw ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (op1, op2) = tmpVars2 bld 16<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.sext 16<rt> src)
  bld <+ (op2 := op1)
  bld <+ (dst := AST.xtlo 32<rt> op2)
  bld --!> len

let extub ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (op1, op2) = tmpVars2 bld 8<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.zext 8<rt> src)
  bld <+ (op2 := op1)
  bld <+ (dst := AST.xtlo 32<rt> op2)
  bld --!> len

let extuw ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (op1, op2) = tmpVars2 bld 16<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.zext 16<rt> src)
  bld <+ (op2 := op1)
  bld <+ (dst := AST.xtlo 32<rt> op2)
  bld --!> len

let fabs ins len bld =
  let dst = trsOneOpr ins bld
  match dst with
  | Var(_, _, s, _) ->
    if s.StartsWith "fr" then
      let struct (sr, op1) = tmpVars2 bld 32<rt>
      bld <!-- (ins.Address, len)
      bld <+ (sr := regVar bld R.SR |> AST.zext 32<rt>)
      bld <+ (op1 := dst)
      bld <+ (op1 := AST.ite (AST.fle op1 AST.b0) (AST.neg op1) (op1))
      bld <+ (dst := op1)
      bld --!> len
    else
      let sr = tmpVar bld 32<rt>
      let op1 = tmpVar bld 64<rt>
      bld <!-- (ins.Address, len)
      bld <+ (sr := regVar bld R.SR |> AST.zext 32<rt>)
      bld <+ (op1 := dst)
      bld <+ (op1 := AST.ite (AST.fle op1 AST.b0) (AST.neg op1) (op1))
      bld <+ (dst := op1)
      bld --!> len
  | _ -> Terminator.impossible ()

let fadd ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  match src with
  | Var(_, _, s, _) ->
    if s.StartsWith "fr" then
      let struct (sr, fps, op1, op2) = tmpVars4 bld 32<rt>
      bld <!-- (ins.Address, len)
      bld <+ (sr := regVar bld R.SR |> AST.zext 32<rt>)
      bld <+ (fps := regVar bld R.FPSCR |> AST.zext 32<rt>)
      bld <+ (op1 := src)
      bld <+ (op2 := dst)
      bld <+ (op2 := AST.fadd op1 op2)
      if ((fpuCheck fps 16) && (fpuCheck fps 11)) then fpuExc bld
      elif (fpuCheck fps 17) then fpuExc bld
      elif ((fpuCheck fps 7) || (fpuCheck fps 8) || (fpuCheck fps 9)) then
        fpuExc bld
      else ()
      bld <+ (dst := op2)
      bld <+ (regVar bld R.FPSCR := AST.zext 32<rt> fps)
      bld --!> len
    else
      let struct (sr, fps) = tmpVars2 bld 32<rt>
      let struct (op1, op2) = tmpVars2 bld 64<rt>
      bld <!-- (ins.Address, len)
      bld <+ (sr := regVar bld R.SR |> AST.zext 32<rt>)
      bld <+ (fps := regVar bld R.FPSCR |> AST.zext 32<rt>)
      bld <+ (op1 := src)
      bld <+ (op2 := dst)
      bld <+ (op2 := AST.fadd op1 op2)
      if ((fpuCheck fps 16) && (fpuCheck fps 11)) then fpuExc bld
      elif (fpuCheck fps 17) then fpuExc bld
      elif ((fpuCheck fps 7) || (fpuCheck fps 8) || (fpuCheck fps 9)) then
        fpuExc bld
      else ()
      bld <+ (dst := op2)
      bld <+ (regVar bld R.FPSCR := AST.zext 32<rt> fps)
      bld --!> len
  | _ -> Terminator.impossible ()

let fcmpeq ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let t = tmpVar bld 1<rt>
  match src with
  | Var(_, _, s, _) ->
    if s.StartsWith "fr" then
      let struct (sr, fps, op1, op2) = tmpVars4 bld 32<rt>
      bld <!-- (ins.Address, len)
      bld <+ (sr := regVar bld R.SR |> AST.zext 32<rt>)
      bld <+ (fps := regVar bld R.FPSCR |> AST.zext 32<rt>)
      bld <+ (op1 := src)
      bld <+ (op2 := dst)
      bld <+ (t := AST.ite (AST.neg ((AST.flt op1 op2) .|
           (AST.fgt op1 op2))) (AST.b1) (AST.b0))
      if ((fpuCheck fps 16) && (fpuCheck fps 11)) then fpuExc bld
      else ()
      bld <+ (dst := op2)
      bld <+ (regVar bld R.FPSCR := AST.zext 32<rt> fps)
      bld <+ (regVar bld R.T := AST.extract t 1<rt> 1)
      bld --!> len
    else
      let struct (sr, fps) = tmpVars2 bld 32<rt>
      let struct (op1, op2) = tmpVars2 bld 64<rt>
      bld <!-- (ins.Address, len)
      bld <+ (sr := regVar bld R.SR |> AST.zext 32<rt>)
      bld <+ (fps := regVar bld R.FPSCR |> AST.zext 32<rt>)
      bld <+ (op1 := src)
      bld <+ (op2 := dst)
      bld <+ (t := AST.ite (AST.neg ((AST.flt op1 op2) .|
           (AST.fgt op1 op2))) (AST.b1) (AST.b0))
      if ((fpuCheck fps 16) && (fpuCheck fps 11)) then fpuExc bld
      else ()
      bld <+ (dst := op2)
      bld <+ (regVar bld R.FPSCR := AST.zext 32<rt> fps)
      bld <+ (regVar bld R.T := AST.extract t 1<rt> 1)
      bld --!> len
  | _ -> Terminator.impossible ()

let fcmpgt ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let t = tmpVar bld 1<rt>
  match src with
  | Var(_, _, s, _) ->
    if s.StartsWith "fr" then
      let struct (sr, fps, op1, op2) = tmpVars4 bld 32<rt>
      bld <!-- (ins.Address, len)
      bld <+ (sr := regVar bld R.SR |> AST.zext 32<rt>)
      bld <+ (fps := regVar bld R.FPSCR |> AST.zext 32<rt>)
      bld <+ (op1 := src)
      bld <+ (op2 := dst)
      bld <+ (t := AST.ite (AST.fgt op1 op2) (AST.b1) (AST.b0))
      if ((fpuCheck fps 16) && (fpuCheck fps 11)) then fpuExc bld
      else ()
      bld <+ (dst := op2)
      bld <+ (regVar bld R.FPSCR := AST.zext 32<rt> fps)
      bld <+ (regVar bld R.T := AST.extract t 1<rt> 1)
      bld --!> len
    else
      let struct (sr, fps) = tmpVars2 bld 32<rt>
      let struct (op1, op2) = tmpVars2 bld 64<rt>
      bld <!-- (ins.Address, len)
      bld <+ (sr := regVar bld R.SR |> AST.zext 32<rt>)
      bld <+ (fps := regVar bld R.FPSCR |> AST.zext 32<rt>)
      bld <+ (op1 := src)
      bld <+ (op2 := dst)
      bld <+ (t := AST.ite (AST.fgt op1 op2) (AST.b1) (AST.b0))
      if ((fpuCheck fps 16) && (fpuCheck fps 11)) then fpuExc bld
      else ()
      bld <+ (dst := op2)
      bld <+ (regVar bld R.FPSCR := AST.zext 32<rt> fps)
      bld <+ (regVar bld R.T := AST.extract t 1<rt> 1)
      bld --!> len
  | _ -> Terminator.impossible ()

let fcnvds ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (sr, fps, fpul) = tmpVars3 bld 32<rt>
  let op1 = tmpVar bld 64<rt>
  bld <!-- (ins.Address, len)
  bld <+ (sr := regVar bld R.SR |> AST.zext 32<rt>)
  bld <+ (fps := regVar bld R.FPSCR |> AST.zext 32<rt>)
  bld <+ (op1 := src)
  bld <+ (fpul := AST.cast CastKind.FloatCast 32<rt> op1)
  bld <+ (regVar bld R.FPSCR := AST.zext 32<rt> fps)
  bld <+ (regVar bld R.FPUL := AST.zext 32<rt> fpul)
  bld --!> len

let fcnvsd ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (sr, fps, fpul) = tmpVars3 bld 32<rt>
  let op1 = tmpVar bld 64<rt>
  bld <!-- (ins.Address, len)
  bld <+ (sr := regVar bld R.SR |> AST.zext 32<rt>)
  bld <+ (fps := regVar bld R.FPSCR |> AST.zext 32<rt>)
  bld <+ (op1 := src)
  bld <+ (fpul := AST.cast CastKind.FloatCast 64<rt> op1)
  bld <+ (regVar bld R.FPSCR := AST.zext 32<rt> fps)
  bld <+ (regVar bld R.FPUL := AST.zext 32<rt> fpul)
  bld --!> len

let fdiv ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (sr, fps) = tmpVars2 bld 32<rt>
  let struct (op1, op2) =
    match src with
    | Var(_, _, r, _) ->
      if r.StartsWith "dr" then
        tmpVars2 bld 64<rt>
      else
        tmpVars2 bld 32<rt>
    | _ -> Terminator.impossible ()
  bld <!-- (ins.Address, len)
  bld <+ (sr := regVar bld R.SR |> AST.zext 32<rt>)
  bld <+ (fps := regVar bld R.FPSCR |> AST.zext 32<rt>)
  bld <+ (op1 := src)
  bld <+ (op2 := dst)
  bld <+ (op2 := AST.fdiv op2 op1)
  if (fpuCheck fps 16) && (fpuCheck fps 11) then fpuExc bld else ()
  if (fpuCheck fps 15) && (fpuCheck fps 10) then fpuExc bld else ()
  if (fpuCheck fps 17) then fpuExc bld else ()
  if (fpuCheck fps 7) || (fpuCheck fps 8) || (fpuCheck fps 9) then fpuExc bld
  else ()
  bld <+ (dst := op2)
  bld <+ (regVar bld R.FPSCR := AST.zext 32<rt> fps)
  bld --!> len

let fipr = function
  | _ -> Terminator.futureFeature ()

let fldi0 ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (sr, op1) = tmpVars2 bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (sr := regVar bld R.SR |> AST.zext 32<rt>)
  bld <+ (op1 := numI32 0x00000000)
  bld <+ (dst := AST.zext 32<rt> op1)
  bld --!> len

let fldi1 ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (sr, op1) = tmpVars2 bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (sr := regVar bld R.SR |> AST.zext 32<rt>)
  bld <+ (op1 := numI32 0x3F800000)
  bld <+ (dst := AST.zext 32<rt> op1)
  bld --!> len

let flds ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (sr, op1, fpul) = tmpVars3 bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (sr := regVar bld R.SR |> AST.zext 32<rt>)
  bld <+ (op1 := src)
  bld <+ (fpul := op1)
  bld <+ (regVar bld R.FPUL := AST.zext 32<rt> fpul)
  bld --!> len

let ``float`` ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let mode =
    match dst with
    | Var(_, _, r, _) ->
        if r.StartsWith "DR" then 64<rt> else 32<rt>
    | _ -> Terminator.impossible ()
  let struct (fpul, sr, fps, op1) = tmpVars4 bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (fpul := regVar bld R.FPUL |> AST.sext 32<rt>)
  bld <+ (sr := regVar bld R.SR |> AST.zext 32<rt>)
  bld <+ (fps := regVar bld R.FPSCR |> AST.zext 32<rt>)
  bld <+ (op1 := AST.cast CastKind.SIntToFloat mode fpul)
  bld <+ (dst := op1)
  bld --!> len

let fmac ins len bld =
  let struct (fr, src, dst) = trsThreeOpr ins bld
  let struct (sr, fps, fr0) = tmpVars3 bld 32<rt>
  let struct (op1, op2) = tmpVars2 bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (sr := regVar bld R.SR |> AST.zext 32<rt>)
  bld <+ (fps := regVar bld R.FPSCR |> AST.zext 32<rt>)
  bld <+ (fr0 := fr)
  bld <+ (op1 := src)
  bld <+ (op2 := dst)
  bld <+ (op2 := AST.fmul fr0 op1 |> AST.fadd op2)
  if (fpuCheck fps 16) && (fpuCheck fps 11) then fpuExc bld else ()
  if (fpuCheck fps 17) then fpuExc bld else ()
  if (fpuCheck fps 7) || (fpuCheck fps 8) || (fpuCheck fps 9) then
    (fpuExc bld)
  else ()
  bld <+ (dst := op2)
  bld <+ (regVar bld R.FPSCR := AST.zext 32<rt> fps)
  bld --!> len

let fmov ins len = function
 | _ -> Terminator.futureFeature ()
  (*
let fmov ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (sr, op1, op2) = tmpVars3 bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (sr := regVar bld R.SR |> AST.zext 32<rt>)
  bld <+ (op1 := src)
  bld <+ (op2 := op1)
  bld <+ (dst := op2)
  bld --!> len
  match ins.Operands with
  | TwoOperands(OpReg(Regdir r1), OpReg(Regdir r2))//dr,dr
  | TwoOperands(OpReg(Regdir r1), OpReg(Regdir r2))//dr,xd
  | TwoOperands(OpReg(Regdir r1), OpReg(RegIndir r2))
  | TwoOperands(OpReg(Regdir r1), OpReg(RedIndirPreDec r2))
  | TwoOperands(OpReg(Regdir r1), OpReg(IdxRegIndir r2))
  | TwoOperands(OpReg(Regdir r1), OpReg(Regdir r2))//xd,dr
  | TwoOperands(OpReg(Regdir r1), OpReg(Regdir r2))//xd,xd
  | TwoOperands(OpReg(Regdir r1), OpReg(RegIndir r2))
  | TwoOperands(OpReg(Regdir r1), OpReg(RedIndirPreDec r2))
  | TwoOperands(OpReg(Regdir r1), OpReg(IdxRegIndir r2))
  | TwoOperands(OpReg(RegIndir r1), OpReg(Regdir r2))
  | TwoOperands(OpReg(RegIndirPostInc r1), OpReg(Regdir r2))
  | TwoOperands(OpReg(IdxRegIndir r1), OpReg(Regdir r2))
  | TwoOperands(OpReg(RegIndir r1), OpReg(Regdir r2))
  | TwoOperands(OpReg(RegIndirPostInc r1), OpReg(Regdir r2))
  | TwoOperands(OpReg(IdxRegIndir r1), OpReg(Regdir r2))
  *)

let fmovs ins len = function
 | _ -> Terminator.futureFeature ()
(*
let fmovs ins len bld =
  match ins.Operands with
  | TwoOperands(OpReg(Regdir r1), OpReg(Regdir r2))
  | TwoOperands(OpReg(Regdir r1), OpReg(RegIndir r2))
  | TwoOperands(OpReg(Regdir r1), OpReg(RedIndirPreDec r2))
  | TwoOperands(OpReg(Regdir r1), OpReg(IdxRegIndir r2))
  | TwoOperands(OpReg(RegIndir r1), OpReg(Regdir r2))
  | TwoOperands(OpReg(RegIndirPostInc r1), OpReg(Regdir r2))
  | TwoOperands(OpReg(IdxRegIndir r1), OpReg(Regdir r2))
*)

let fmul ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (sr, fps) = tmpVars2 bld 32<rt>
  let struct (op1, op2) =
    match src with
    | Var(_, _, r, _) ->
      if r.StartsWith "FR" then tmpVars2 bld 32<rt>
      else
        tmpVars2 bld 64<rt>
    | _ -> Terminator.impossible ()
  bld <!-- (ins.Address, len)
  bld <+ (sr := regVar bld R.SR |> AST.zext 32<rt>)
  bld <+ (fps := regVar bld R.FPSCR |> AST.zext 32<rt>)
  bld <+ (op1 := src)
  bld <+ (op2 := dst)
  bld <+ (op2 := AST.fmul op1 op2)
  if (fpuCheck fps 16) && (fpuCheck fps 11) then (fpuExc bld) else ()
  if (fpuCheck fps 17) then fpuExc bld else ()
  if (fpuCheck fps 7) || (fpuCheck fps 8) || (fpuCheck fps 9) then fpuExc bld
  else ()
  bld <+ (dst := op2)
  bld <+ (regVar bld R.FPSCR := AST.zext 32<rt> fps)
  bld --!> len

let fneg ins len bld =
  let (dst) = trsOneOpr ins bld
  let sr = tmpVar bld 32<rt>
  let fps = tmpVar bld 32<rt>
  let mode =
    match dst with
    | Var(_, _, r, _) -> r.StartsWith "DR"
    | _ -> Terminator.impossible ()
  let op1 = if mode then tmpVar bld 64<rt> else bld.Stream.NewTempVar 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (sr := regVar bld R.SR |> AST.zext 32<rt>)
  if mode then () else (bld <+ (fps := regVar bld R.FPSCR |> AST.zext 32<rt>))
  bld <+ (op1 := dst)
  bld <+ (op1 := AST.fsub AST.b0 op1)
  bld <+ (dst := op1)
  bld --!> len

let frchg (ins: Instruction) len bld =
  let sr = tmpVar bld 32<rt>
  let fr = tmpVar bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (sr := regVar bld R.SR |> AST.zext 32<rt>)
  bld <+ (fr := regVar bld R.FPSCR_FR |> AST.zext 1<rt>)
  bld <+ (fr := fr <+> AST.b1)
  bld <+ (regVar bld R.FPSCR_FR := AST.extract fr 1<rt> 1)
  bld --!> len

let fschg (ins: Instruction) len bld =
  let sr = tmpVar bld 32<rt>
  let fr = tmpVar bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (sr := regVar bld R.SR |> AST.zext 32<rt>)
  bld <+ (fr := regVar bld R.FPSCR_SZ |> AST.zext 1<rt>)
  bld <+ (fr := fr <+> AST.b1)
  bld <+ (regVar bld R.FPSCR_SZ := AST.extract fr 1<rt> 1)
  bld --!> len

let fsqrt ins len bld =
  let dst = trsOneOpr ins bld
  let struct (sr, fps) = tmpVars2 bld 32<rt>
  let mode =
    match dst with
    | Var(_, _, r, _) -> r.StartsWith "DR"
    | _ -> Terminator.impossible ()
  let op1 = if mode then tmpVar bld 64<rt> else bld.Stream.NewTempVar 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (sr := regVar bld R.SR |> AST.zext 32<rt>)
  bld <+ (fps := regVar bld R.FPSCR |> AST.zext 32<rt>)
  bld <+ (op1 := dst)
  bld <+ (op1 := AST.fsqrt op1)
  if (fpuCheck fps 16) && (fpuCheck fps 11) then fpuExc bld else ()
  if (fpuCheck fps 17) then fpuExc bld else ()
  if (fpuCheck fps 7) then fpuExc bld else ()
  bld <+ (dst := op1)
  bld <+ (regVar bld R.FPSCR := AST.zext 32<rt> fps)
  bld --!> len

let fsts ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (sr, fpul, op1) = tmpVars3 bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (sr := regVar bld R.SR |> AST.zext 32<rt>)
  bld <+ (fpul := regVar bld R.FPUL |> AST.sext 32<rt>)
  bld <+ (op1 := fpul)
  bld <+ (dst := op1)
  bld --!> len

let fsub ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let mode =
    match dst with
    | Var(_, _, r, _) -> r.StartsWith "DR"
    | _ -> Terminator.impossible ()
  let struct (sr, fps) = tmpVars2 bld 32<rt>
  let struct (op1, op2) =
    if mode then tmpVars2 bld 64<rt> else tmpVars2 bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (sr := regVar bld R.SR |> AST.zext 32<rt>)
  bld <+ (fps := regVar bld R.FPSCR |> AST.zext 32<rt>)
  bld <+ (op1 := src)
  bld <+ (op2 := dst)
  bld <+ (op2 := AST.fsub op2 op1)
  if (fpuCheck fps 16) && (fpuCheck fps 11) then fpuExc bld else ()
  if (fpuCheck fps 17) then fpuExc bld else ()
  if (fpuCheck fps 7) || (fpuCheck fps 8) || (fpuCheck fps 9) then fpuExc bld
  else ()
  bld <+ (dst := op2)
  bld <+ (regVar bld R.FPSCR := AST.zext 32<rt> fps)
  bld --!> len

let ftrc ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (sr, fps, fpul) = tmpVars3 bld 32<rt>
  let mode =
    match dst with
    | Var(_, _, r, _) -> r.StartsWith "DR"
    | _ -> Terminator.impossible ()
  let op1 = if mode then tmpVar bld 64<rt> else bld.Stream.NewTempVar 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (sr := regVar bld R.SR |> AST.zext 32<rt>)
  bld <+ (fps := regVar bld R.FPSCR |> AST.zext 32<rt>)
  bld <+ (op1 := src)
  // FTRC
  if (fpuCheck fps 16) && (fpuCheck fps 11) then fpuExc bld else ()
  bld <+ (regVar bld R.FPUL := AST.zext 32<rt> fpul)
  bld <+ (regVar bld R.FPSCR := AST.zext 32<rt> fps)
  bld --!> len

let ftrv ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (sr, fps, xmtrx, op1) = tmpVars4 bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (sr := regVar bld R.SR |> AST.zext 32<rt>)
  bld <+ (fps := regVar bld R.FPSCR |> AST.zext 32<rt>)
  bld <+ (xmtrx := src)
  bld <+ (op1 := dst)
  // bld <+ (op1 :=) FTRV_S
  if (fpuCheck fps 7) || (fpuCheck fps 8)
    || (fpuCheck fps 9) || (fpuCheck fps 11) then fpuExc bld else ()
  bld <+ (dst := op1)
  bld <+ (regVar bld R.FPSCR := AST.zext 32<rt> fps)
  bld --!> len

let jmp ins len bld =
  let dst = trsOneOpr ins bld
  let struct (op1, target, delayedPC) = tmpVars3 bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.sext 32<rt> dst)
  bld <+ (target := op1)
  bld <+ (delayedPC := target .& (AST.b1 |> AST.neg))
  bld <+ (regVar bld R.PC := AST.xtlo 32<rt> delayedPC)
  bld --!> len

let jsr ins len bld =
  let dst = trsOneOpr ins bld
  let struct (pc, op1, delayedPR) = tmpVars3 bld 32<rt>
  let struct (target, delayedPC) = tmpVars2 bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (pc := R.PC |> regVar bld |> AST.sext 32<rt>)
  bld <+ (op1 := AST.sext 32<rt> dst)
  bld <+ (delayedPR := pc .+ numI32 4)
  bld <+ (target := op1)
  bld <+ (delayedPC := target .& (AST.b1 |> AST.neg))
  bld <+ (regVar bld R.PR := AST.xtlo 32<rt> delayedPR)
  bld <+ (regVar bld R.PC := AST.xtlo 32<rt> delayedPC)
  bld --!> len

let ldc ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  match dst with
  | Var(_, _, s, _) ->
    match s with
    | "gbr" ->
      let struct (op1, gbr) = tmpVars2 bld 32<rt>
      bld <!-- (ins.Address, len)
      bld <+ (op1 := AST.sext 32<rt> src)
      bld <+ (gbr := op1)
      bld <+ (regVar bld R.GBR := AST.xtlo 32<rt> gbr)
      bld --!> len
    | "sr" ->
      let struct (op1, sr) = tmpVars2 bld 32<rt>
      let md = tmpVar bld 1<rt>
      bld <!-- (ins.Address, len)
      bld <+ (md := R.MD |> regVar bld |> AST.zext 1<rt>)
      if bv1Check md then () else resinst bld
      bld <+ (op1 := AST.sext 32<rt> src)
      bld <+ (sr := op1)
      bld <+ (regVar bld R.SR := AST.xtlo 32<rt> sr)
      bld --!> len
    | "vbr" ->
      let struct (op1, vbr) = tmpVars2 bld 32<rt>
      let md = tmpVar bld 1<rt>
      bld <!-- (ins.Address, len)
      bld <+ (md := R.MD |> regVar bld |> AST.zext 1<rt>)
      if bv1Check md then () else resinst bld
      bld <+ (op1 := AST.sext 32<rt> src)
      bld <+ (vbr := op1)
      bld <+ (regVar bld R.VBR := AST.xtlo 32<rt> vbr)
      bld --!> len
    | "ssr" ->
      let struct (op1, ssr) = tmpVars2 bld 32<rt>
      let md = tmpVar bld 1<rt>
      bld <!-- (ins.Address, len)
      bld <+ (md := R.MD |> regVar bld |> AST.zext 1<rt>)
      if bv1Check md then () else resinst bld
      bld <+ (op1 := AST.sext 32<rt> src)
      bld <+ (ssr := op1)
      bld <+ (regVar bld R.SSR := AST.xtlo 32<rt> ssr)
      bld --!> len
    | "spc" ->
      let struct (op1, spc) = tmpVars2 bld 32<rt>
      let md = tmpVar bld 1<rt>
      bld <!-- (ins.Address, len)
      bld <+ (md := R.MD |> regVar bld |> AST.zext 1<rt>)
      if bv1Check md then () else resinst bld
      bld <+ (op1 := AST.sext 32<rt> src)
      bld <+ (spc := op1)
      bld <+ (regVar bld R.SPC := AST.xtlo 32<rt> spc)
      bld --!> len
    | "dbr" ->
      let struct (op1, dbr) = tmpVars2 bld 32<rt>
      let md = tmpVar bld 1<rt>
      bld <!-- (ins.Address, len)
      bld <+ (md := R.MD |> regVar bld |> AST.zext 1<rt>)
      if bv1Check md then () else resinst bld
      bld <+ (op1 := AST.sext 32<rt> src)
      bld <+ (dbr := op1)
      bld <+ (regVar bld R.DBR := AST.xtlo 32<rt> dbr)
      bld --!> len
    | _ ->
      let struct (op1, rnBank) = tmpVars2 bld 32<rt>
      let md = tmpVar bld 1<rt>
      bld <!-- (ins.Address, len)
      bld <+ (md := R.MD |> regVar bld |> AST.zext 1<rt>)
      if bv1Check md then () else resinst bld
      bld <+ (op1 := AST.sext 32<rt> src)
      bld <+ (rnBank := op1)
      bld <+ (dst := AST.xtlo 32<rt> rnBank)
      bld --!> len
  | _ -> Terminator.impossible ()

let ldcl ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  match src with
  | Var(_, _, s, _) ->
    match s with
    | "gbr" ->
      let struct (op1, address, gbr) = tmpVars3 bld 32<rt>
      bld <!-- (ins.Address, len)
      bld <+ (op1 := AST.sext 32<rt> src)
      bld <+ (address := AST.zext 32<rt> op1)
      bld <+ (gbr := address |> AST.loadLE 32<rt> |> AST.zext 32<rt>)
      bld <+ (op1 := op1 .+ numI32 4)
      bld <+ (src := AST.xtlo 32<rt> op1)
      bld <+ (regVar bld R.GBR := AST.xtlo 32<rt> gbr)
      bld --!> len
    | "sr" ->
      let md = tmpVar bld 1<rt>
      let struct (op1, address, sr) = tmpVars3 bld 32<rt>
      bld <!-- (ins.Address, len)
      bld <+ (md := regVar bld R.MD |> AST.zext 1<rt>)
      if bv1Check md then () else resinst bld
      bld <+ (op1 := AST.sext 32<rt> src)
      bld <+ (address := AST.zext 32<rt> op1)
      bld <+ (sr := AST.loadLE 32<rt> address |> AST.sext 32<rt>)
      bld <+ (op1 := op1 .+ numI32 4)
      bld <+ (src := AST.xtlo 32<rt> op1)
      bld <+ (regVar bld R.SR := AST.xtlo 32<rt> sr)
      bld --!> len
    | "vbr" ->
      let md = tmpVar bld 1<rt>
      let struct (op1, address, vbr) = tmpVars3 bld 32<rt>
      bld <!-- (ins.Address, len)
      bld <+ (md := regVar bld R.MD |> AST.zext 1<rt>)
      if bv1Check md then () else resinst bld
      bld <+ (op1 := AST.sext 32<rt> src)
      bld <+ (address := AST.zext 32<rt> op1)
      bld <+ (vbr := AST.loadLE 32<rt> address |> AST.sext 32<rt>)
      bld <+ (op1 := op1 .+ numI32 4)
      bld <+ (src := AST.xtlo 32<rt> op1)
      bld <+ (regVar bld R.VBR := AST.xtlo 32<rt> vbr)
      bld --!> len
    | "ssr" ->
      let md = tmpVar bld 1<rt>
      let struct (op1, address, ssr) = tmpVars3 bld 32<rt>
      bld <!-- (ins.Address, len)
      bld <+ (md := regVar bld R.MD |> AST.zext 1<rt>)
      if bv1Check md then () else resinst bld
      bld <+ (op1 := AST.sext 32<rt> src)
      bld <+ (address := AST.zext 32<rt> op1)
      bld <+ (ssr := AST.loadLE 32<rt> address |> AST.sext 32<rt>)
      bld <+ (op1 := op1 .+ numI32 4)
      bld <+ (src := AST.xtlo 32<rt> op1)
      bld <+ (regVar bld R.SSR := AST.xtlo 32<rt> ssr)
      bld --!> len
    | "spc" ->
      let md = tmpVar bld 1<rt>
      let struct (op1, address, spc) = tmpVars3 bld 32<rt>
      bld <!-- (ins.Address, len)
      bld <+ (md := regVar bld R.MD |> AST.zext 1<rt>)
      if bv1Check md then () else resinst bld
      bld <+ (op1 := AST.sext 32<rt> src)
      bld <+ (address := AST.zext 32<rt> op1)
      bld <+ (spc := AST.loadLE 32<rt> address |> AST.sext 32<rt>)
      bld <+ (op1 := op1 .+ numI32 4)
      bld <+ (src := AST.xtlo 32<rt> op1)
      bld <+ (regVar bld R.SPC := AST.xtlo 32<rt> spc)
      bld --!> len
    | "dbr" ->
      let md = tmpVar bld 1<rt>
      let struct (op1, address, dbr) = tmpVars3 bld 32<rt>
      bld <!-- (ins.Address, len)
      bld <+ (md := regVar bld R.MD |> AST.zext 1<rt>)
      if bv1Check md then () else resinst bld
      bld <+ (op1 := AST.sext 32<rt> src)
      bld <+ (address := AST.zext 32<rt> op1)
      bld <+ (dbr := AST.loadLE 32<rt> address |> AST.sext 32<rt>)
      bld <+ (op1 := op1 .+ numI32 4)
      bld <+ (src := AST.xtlo 32<rt> op1)
      bld <+ (regVar bld R.DBR := AST.xtlo 32<rt> dbr)
      bld --!> len
    | _ ->
      let md = tmpVar bld 1<rt>
      let struct (op1, address, rnBank) = tmpVars3 bld 32<rt>
      bld <!-- (ins.Address, len)
      bld <+ (md := regVar bld R.MD |> AST.zext 1<rt>)
      if bv1Check md then () else resinst bld
      bld <+ (op1 := AST.sext 32<rt> src)
      bld <+ (address := AST.zext 32<rt> op1)
      bld <+ (rnBank := AST.loadLE 32<rt> address |> AST.sext 32<rt>)
      bld <+ (op1 := op1 .+ numI32 4)
      bld <+ (src := AST.xtlo 32<rt> op1)
      bld <+ (dst := AST.xtlo 32<rt> rnBank)
      bld --!> len
  | _ -> Terminator.impossible ()

let lds ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  match dst with
  | Var(_, _, s, _) ->
    match s with
    | "fpscr" ->
      let struct (sr, op1) = tmpVars2 bld 32<rt>
      let struct (fps, pr, sz, fr) = tmpVars4 bld 1<rt>
      bld <!-- (ins.Address, len)
      bld <+ (sr := regVar bld R.SR |> AST.zext 32<rt>)
      bld <+ (op1 := AST.sext 32<rt> src)
      bld <+ (fps := op1)
      bld <+ (pr := AST.extract op1 1<rt> 20)
      bld <+ (sz := AST.extract op1 1<rt> 21)
      bld <+ (fr := AST.extract op1 1<rt> 22)
      bld <+ (regVar bld R.FPSCR := AST.zext 32<rt> fps)
      bld <+ (regVar bld R.FPSCR_PR := pr)
      bld <+ (regVar bld R.FPSCR_SZ := sz)
      bld <+ (regVar bld R.FPSCR_FR := fr)
      bld --!> len
    | "fpul" ->
      let struct (sr, op1, fpul) = tmpVars3 bld 32<rt>
      bld <!-- (ins.Address, len)
      bld <+ (sr := regVar bld R.SR |> AST.zext 32<rt>)
      bld <+ (op1 := AST.sext 32<rt> src)
      bld <+ (fpul := op1)
      bld <+ (regVar bld R.FPUL := AST.zext 32<rt> fpul)
      bld --!> len
    | "mach" ->
      let struct (op1, mach) = tmpVars2 bld 32<rt>
      bld <!-- (ins.Address, len)
      bld <+ (op1 := AST.sext 32<rt> src)
      bld <+ (mach := op1)
      bld <+ (regVar bld R.MACH := AST.zext 32<rt> mach)
      bld --!> len
    | "macl" ->
      let struct (op1, macl) = tmpVars2 bld 32<rt>
      bld <!-- (ins.Address, len)
      bld <+ (op1 := AST.sext 32<rt> src)
      bld <+ (macl := op1)
      bld <+ (regVar bld R.MACL := AST.zext 32<rt> macl)
      bld --!> len
    | "pr" ->
      let struct (op1, newPR, delayedPR) = tmpVars3 bld 32<rt>
      bld <!-- (ins.Address, len)
      bld <+ (op1 := AST.sext 32<rt> src)
      bld <+ (newPR := op1)
      bld <+ (delayedPR := newPR)
      bld <+ (regVar bld R.PR := AST.xtlo 32<rt> newPR)
      bld <+ (regVar bld R.PR := AST.xtlo 32<rt> delayedPR)
      bld --!> len
    | _ -> Terminator.impossible ()
  | _ -> Terminator.impossible ()

let ldsl ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  match dst with
  | Var(_, _, s, _) ->
    match s with
    | "fpscr" ->
      let struct (sr, op1, address, value) = tmpVars4 bld 32<rt>
      let struct (fps, pr, sz, fr) = tmpVars4 bld 1<rt>
      bld <!-- (ins.Address, len)
      bld <+ (sr := regVar bld R.SR |> AST.zext 32<rt>)
      bld <+ (op1 := AST.sext 32<rt> src)
      bld <+ (address := AST.zext 32<rt> op1)
      bld <+ (value := AST.loadLE 32<rt> address)
      bld <+ (fps := op1)
      bld <+ (pr := AST.extract op1 1<rt> 20)
      bld <+ (sz := AST.extract op1 1<rt> 21)
      bld <+ (fr := AST.extract op1 1<rt> 22)
      bld <+ (op1 := op1 .+ numI32 4)
      bld <+ (src := AST.xtlo 32<rt> op1)
      bld <+ (regVar bld R.FPSCR := AST.zext 32<rt> fps)
      bld <+ (regVar bld R.FPSCR_PR := pr)
      bld <+ (regVar bld R.FPSCR_SZ := sz)
      bld <+ (regVar bld R.FPSCR_FR := fr)
      bld --!> len
    | "fpul" ->
      let struct (sr, op1, fpul, address) = tmpVars4 bld 32<rt>
      bld <!-- (ins.Address, len)
      bld <+ (sr := regVar bld R.SR |> AST.zext 32<rt>)
      bld <+ (op1 := AST.sext 32<rt> src)
      bld <+ (address := AST.zext 32<rt> op1)
      bld <+ (fpul := AST.loadLE 32<rt> address)
      bld <+ (op1 := op1 .+ numI32 4)
      bld <+ (src := AST.xtlo 32<rt> op1)
      bld <+ (regVar bld R.FPUL := AST.zext 32<rt> fpul)
      bld --!> len
    | "mach" ->
      let struct (op1, address, mach) = tmpVars3 bld 32<rt>
      bld <!-- (ins.Address, len)
      bld <+ (op1 := AST.sext 32<rt> src)
      bld <+ (address := AST.zext 32<rt> op1)
      bld <+ (mach := AST.loadLE 32<rt> address |> AST.sext 32<rt>)
      bld <+ (op1 := op1 .+ numI32 4)
      bld <+ (src := AST.xtlo 32<rt> op1)
      bld <+ (regVar bld R.MACH := AST.zext 32<rt> mach)
      bld --!> len
    | "macl" ->
      let struct (op1, address, macl) = tmpVars3 bld 32<rt>
      bld <!-- (ins.Address, len)
      bld <+ (op1 := AST.sext 32<rt> src)
      bld <+ (address := AST.zext 32<rt> op1)
      bld <+ (macl := AST.loadLE 32<rt> address |> AST.sext 32<rt>)
      bld <+ (op1 := op1 .+ numI32 4)
      bld <+ (src := AST.xtlo 32<rt> op1)
      bld <+ (regVar bld R.MACL := AST.zext 32<rt> macl)
      bld --!> len
    | "pr" ->
      let struct (op1, newPR, delayedPR, address) = tmpVars4 bld 32<rt>
      bld <!-- (ins.Address, len)
      bld <+ (op1 := AST.sext 32<rt> src)
      bld <+ (address := AST.zext 32<rt> op1)
      bld <+ (newPR := AST.loadLE 32<rt> address |> AST.sext 32<rt>)
      bld <+ (delayedPR := newPR)
      bld <+ (op1 := op1 .+ numI32 4)
      bld <+ (src := AST.xtlo 32<rt> op1)
      bld <+ (regVar bld R.PR := AST.xtlo 32<rt> newPR)
      bld <+ (regVar bld R.PR := AST.xtlo 32<rt> delayedPR)
      bld --!> len
    | _ -> Terminator.impossible ()
  | _ -> Terminator.impossible ()

let ldtlb ins len = function
  | _ -> Terminator.futureFeature ()

let macl ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (macl, mach, temp) = tmpVars3 bld 32<rt>
  let struct (mField, nField) = tmpVars2 bld 4<rt>
  let struct (mAddr, nAddr, mul) = tmpVars3 bld 32<rt>
  let s = tmpVar bld 1<rt>
  let struct (value1, value2) = tmpVars2 bld 16<rt>
  let result = tmpVar bld 32<rt>
  let mac = tmpVar bld 32<rt>
  let struct (m, n) =
    match src, dst with
    | Var(_, _, n1, _), Var(_, _, n2, _) ->
      struct (numI32 (int (n1[1..2])), numI32 (int (n2[1..2])))
    | _ -> Terminator.impossible ()
  bld <!-- (ins.Address, len)
  bld <+ (macl := regVar bld R.MACL |> AST.zext 32<rt>)
  bld <+ (mach := regVar bld R.MACH |> AST.zext 32<rt>)
  bld <+ (s := regVar bld R.S |> AST.zext 1<rt>)
  bld <+ (mField := AST.zext 4<rt> m)
  bld <+ (nField := AST.zext 4<rt> n)
  bld <+ (mAddr := AST.zext 32<rt> src)
  bld <+ (nAddr := AST.zext 32<rt> dst)
  bld <+ (value2 := AST.zext 32<rt> nAddr |> AST.loadLE 32<rt>
  |> AST.sext 32<rt>)
  bld <+ (nAddr := nAddr .+ numI32 4)
  bld <+ (mAddr := AST.ite (mField == nField)
                             (mAddr .+ numI32 4) (mAddr))
  bld <+ (nAddr := AST.ite (mField == nField)
                             (nAddr .+ numI32 4) (nAddr))
  bld <+ (value1 := AST.zext 32<rt> mAddr |> AST.loadLE 32<rt>
  |> AST.sext 32<rt>)
  bld <+ (mAddr := mAddr .+ numI32 4)
  bld <+ (mul := value2 .* value1)
  bld <+ (mac := macl .+ (mach << numI32 32))
  bld <+ (result := mac .+ mul)
  bld <+ (result := AST.ite (s == AST.b1)
    (AST.ite ((((result <+> mac) .& (result <+> mul)) >> numI32 63) == AST.b1)
    (AST.ite ((mac >> numI32 62) == AST.b0)
             (numI64 (int (2.0 ** 47 - 1.0))) (numI64 (int (-2.0 ** 47))))
    (signedSaturate result))
    (result))
  bld <+ (macl := result)
  bld <+ (mach := result >> numI32 32)
  bld <+ (src := AST.xtlo 32<rt> mAddr)
  bld <+ (dst := AST.xtlo 32<rt> nAddr)
  bld <+ (regVar bld R.MACL := AST.zext 32<rt> macl)
  bld <+ (regVar bld R.MACH := AST.zext 32<rt> mach)
  bld --!> len

let macw ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (macl, mach, temp) = tmpVars3 bld 32<rt>
  let struct (mField, nField) = tmpVars2 bld 4<rt>
  let struct (mAddr, nAddr, mul) = tmpVars3 bld 32<rt>
  let s = tmpVar bld 1<rt>
  let struct (value1, value2) = tmpVars2 bld 16<rt>
  let result = tmpVar bld 32<rt>
  let struct (m, n) =
    match src, dst with
    | Var(_, _, n1, _), Var(_, _, n2, _) ->
      struct (numI32 (int (n1[1..2])), numI32 (int (n2[1..2])))
    | _ -> Terminator.impossible ()
  bld <!-- (ins.Address, len)
  bld <+ (macl := regVar bld R.MACL |> AST.zext 32<rt>)
  bld <+ (mach := regVar bld R.MACH |> AST.zext 32<rt>)
  bld <+ (s := regVar bld R.S |> AST.zext 1<rt>)
  bld <+ (mField := AST.zext 4<rt> m)
  bld <+ (nField := AST.zext 4<rt> n)
  bld <+ (mAddr := AST.zext 32<rt> src)
  bld <+ (nAddr := AST.zext 32<rt> dst)
  bld <+ (value2 := AST.zext 32<rt> nAddr |> AST.loadLE 16<rt>
  |> AST.sext 16<rt>)
  bld <+ (nAddr := nAddr .+ numI32 2)
  bld <+ (mAddr := AST.ite (mField == nField)
                             (mAddr .+ numI32 2) (mAddr))
  bld <+ (nAddr := AST.ite (mField == nField)
                             (nAddr .+ numI32 2) (nAddr))
  bld <+ (value1 := AST.zext 32<rt> mAddr |> AST.loadLE 16<rt>
  |> AST.sext 16<rt>)
  bld <+ (mAddr := mAddr .+ numI32 2)
  bld <+ (mul := value2 .* value1)
  bld <+ (macl := AST.ite (s == AST.b1) (mul .+ AST.sext 32<rt> macl) (macl))
  bld <+ (temp := AST.ite (signedSaturate macl) (macl) (temp))
  bld <+ (result := AST.ite (s == AST.b1)
  (AST.ite (macl == temp) (AST.zext 32<rt> macl .| (mach << numI32 32))
  (AST.zext 32<rt> temp .| (AST.b1 << numI32 32)))
  (mul .+ macl .+ (mach << numI32 32)))
  bld <+ (macl := result)
  bld <+ (mach := result >> numI32 32)
  bld <+ (src := AST.xtlo 32<rt> mAddr)
  bld <+ (dst := AST.xtlo 32<rt> nAddr)
  bld <+ (regVar bld R.MACL := AST.zext 32<rt> macl)
  bld <+ (regVar bld R.MACH := AST.zext 32<rt> mach)
  bld --!> len

let mov ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  match src with
  | Num(s, _) ->
    let struct (imm, op2) = tmpVars2 bld 8<rt>
    bld <!-- (ins.Address, len)
    bld <+ (imm := AST.num s |> AST.sext 8<rt>)
    bld <+ (op2 := imm)
    bld <+ (dst := AST.xtlo 32<rt> op2)
    bld --!> len
  | Var(_, _, r, _) ->
    let struct (op1, op2) = tmpVars2 bld 32<rt>
    bld <!-- (ins.Address, len)
    bld <+ (op1 := AST.zext 32<rt> src)
    bld <+ (op2 := op1)
    bld <+ (dst := AST.xtlo 32<rt> op2)
    bld --!> len
  | _ -> Terminator.impossible ()

let mova ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (pc, r0) = tmpVars2 bld 32<rt>
  let disp = tmpVar bld 8<rt>
  bld <!-- (ins.Address, len)
  bld <+ (pc := regVar bld R.PC |> AST.sext 32<rt>)
  bld <+ (disp := (AST.zext 8<rt> src) << numI32 2)
  bld <+ (r0 := disp .+ ((pc .+ numI32 4) .& (AST.neg (numI32 3))))
  bld <+ (regVar bld R.R0 := AST.xtlo 32<rt> r0)
  bld --!> len

let movb (ins: Instruction) len bld =
  match ins.Operands with
  | TwoOperands(OpReg(Regdir _), OpReg(RegIndir _)) ->
    let struct (src, dst) = trsTwoOpr ins bld
    let struct (op1, op2 ,address) = tmpVars3 bld 32<rt>
    bld <!-- (ins.Address, len)
    bld <+ (op1 := AST.sext 32<rt> src)
    bld <+ (op2 := AST.sext 32<rt> dst)
    bld <+ (address := AST.zext 32<rt> op2)
    bld <+ (AST.store Endian.Little address op1)
    bld --!> len
  | TwoOperands(OpReg(Regdir _), OpReg(RegIndirPreDec _)) ->
    let struct (src, dst) = trsTwoOpr ins bld
    let struct (op1, op2, address) = tmpVars3 bld 32<rt>
    bld <!-- (ins.Address, len)
    bld <+ (op1 := AST.sext 32<rt> src)
    bld <+ (op2 := AST.sext 32<rt> dst)
    bld <+ (address := (op2 .- AST.b1) |> AST.zext 32<rt>)
    bld <+ (AST.store Endian.Little address op1)
    bld <+ (op2 := address)
    bld <+ (dst := AST.xtlo 32<rt> op2)
    bld --!> len
  | TwoOperands(OpReg(Regdir _), OpReg(IdxRegIndir(_))) ->
    let struct (src, dst) = trsTwoOpr ins bld
    let struct (r0, op1, op2, address) = tmpVars4 bld 32<rt>
    bld <!-- (ins.Address, len)
    bld <+ (r0 := regVar bld R.R0 |> AST.sext 32<rt>)
    bld <+ (op1 := AST.sext 32<rt> src)
    bld <+ (op2 := AST.sext 32<rt> dst)
    bld <+ (address := (r0 .+ op2) |> AST.zext 32<rt>)
    bld <+ (AST.store Endian.Little address op1)
    bld --!> len
  | TwoOperands(OpReg(Regdir _), OpReg(GBRIndirDisp _)) ->
    let struct (src, dst) = trsTwoOpr ins bld
    let struct (gbr, address) = tmpVars2 bld 32<rt>
    let disp = tmpVar bld 8<rt>
    let r0 = tmpVar bld 32<rt>
    bld <!-- (ins.Address, len)
    bld <+ (gbr := regVar bld R.GBR |> AST.sext 32<rt>)
    bld <+ (r0 := regVar bld R.R0 |> AST.sext 32<rt>)
    bld <+ (disp := AST.zext 8<rt> dst)
    bld <+ (address := (gbr .+ disp) |> AST.zext 32<rt>)
    bld <+ (AST.store Endian.Little address r0)
    bld --!> len
  | TwoOperands(OpReg(Regdir _), OpReg(RegIndirDisp _)) ->
    let struct (src, dst, imm) = trsMemOpr4toExpr ins bld
    let struct (op2, address, r0) = tmpVars3 bld 32<rt>
    let disp = tmpVar bld 4<rt>
    bld <!-- (ins.Address, len)
    bld <+ (r0 := regVar bld R.R0 |> AST.sext 32<rt>)
    bld <+ (disp := AST.zext 4<rt> imm)
    bld <+ (op2 := AST.sext 32<rt> dst)
    bld <+ (address := (disp .+ op2) |> AST.zext 32<rt>)
    bld <+ (AST.store Endian.Little address r0)
    bld --!> len
  | TwoOperands(OpReg(RegIndir _), OpReg(Regdir _)) -> //0100 0100 0100 0000
    let struct (src, dst) = trsTwoOpr ins bld
    let struct (op1, address) = tmpVars2 bld 32<rt>
    let op2 = tmpVar bld 32<rt>
    bld <!-- (ins.Address, len)
    bld <+ (op1 := AST.sext 32<rt> src)
    bld <+ (address := AST.zext 32<rt> op1)
    bld <+ (op2 := AST.loadLE 8<rt> address |> AST.sext 8<rt>)
    bld <+ (dst := AST.xtlo 8<rt> op2)
    bld --!> len
  | TwoOperands(OpReg(RegIndirPostInc _), OpReg(Regdir _)) ->
    let struct (src, dst) = trsTwoOpr ins bld
    let struct (mField, nField) = tmpVars2 bld 4<rt>
    let op1 = tmpVar bld 32<rt>
    let address = tmpVar bld 32<rt>
    let op2 = tmpVar bld 16<rt>
    let struct (m, n) =
      match src, dst with
      | Var(_, _, n1, _), Var(_, _, n2, _) ->
        struct (numI32 (int (n1[1..2])), numI32 (int (n2[1..2])))
      | _ -> Terminator.impossible ()
    bld <!-- (ins.Address, len)
    bld <+ (mField := AST.zext 4<rt> m)
    bld <+ (nField := AST.zext 4<rt> n)
    bld <+ (op1 := AST.sext 32<rt> src)
    bld <+ (address := AST.zext 32<rt> op1)
    bld <+ (op2 := AST.loadLE 32<rt> address |> AST.sext 32<rt>)
    bld <+ (op1 := AST.ite (mField == nField) (op2) (op1 .+ numI32 4))
    bld <+ (src := AST.xtlo 32<rt> op1)
    bld <+ (dst := AST.xtlo 32<rt> op2)
    bld --!> len
  | TwoOperands(OpReg(IdxRegIndir _), OpReg(Regdir(_))) ->
    let struct (src, dst) = trsTwoOpr ins bld
    let struct (r0, op1, address) = tmpVars3 bld 32<rt>
    let op2 = tmpVar bld 8<rt>
    bld <!-- (ins.Address, len)
    bld <+ (r0 := regVar bld R.R0 |> AST.sext 32<rt>)
    bld <+ (op1 := AST.sext 32<rt> src)
    bld <+ (address := (r0 .+ op1) |> AST.zext 32<rt>)
    bld <+ (op2 := AST.loadLE 8<rt> address |> AST.sext 8<rt>)
    bld <+ (dst := AST.xtlo 8<rt> op2)
    bld --!> len
  | TwoOperands(OpReg(GBRIndirDisp _), OpReg(Regdir _)) ->
    let struct (src, dst) = trsTwoOpr ins bld
    let struct (gbr, address) = tmpVars2 bld 32<rt>
    let disp = tmpVar bld 8<rt>
    let r0 = tmpVar bld 8<rt>
    bld <!-- (ins.Address, len)
    bld <+ (gbr := regVar bld R.GBR |> AST.sext 32<rt>)
    bld <+ (disp := AST.zext 8<rt> src)
    bld <+ (address := (gbr .+ disp) |> AST.zext 32<rt>)
    bld <+ (r0 := AST.loadLE 8<rt> address |> AST.sext 8<rt>)
    bld <+ (dst := AST.xtlo 8<rt> r0)
    bld --!> len
  | TwoOperands(OpReg(RegIndirDisp _), OpReg(Regdir _)) ->
    let struct (src, dst, imm) = trsMemOpr3toExpr ins bld
    let struct (op2, address) = tmpVars2 bld 32<rt>
    let disp = tmpVar bld 4<rt>
    let r0 = tmpVar bld 8<rt>
    bld <!-- (ins.Address, len)
    bld <+ (disp := AST.zext 4<rt> imm)
    bld <+ (op2 := AST.sext 32<rt> src)
    bld <+ (address := (disp .+ op2) |> AST.zext 32<rt>)
    bld <+ (r0 := AST.loadLE 8<rt> address |> AST.sext 8<rt>)
    bld <+ (regVar bld R.R0 := AST.xtlo 8<rt> r0)
    bld --!> len
  | _ -> Terminator.impossible ()

let movl (ins: Instruction) len bld =
  match ins.Operands with
  | TwoOperands(OpReg(Regdir _), OpReg(RegIndir _)) ->
    let struct (src, dst) = trsTwoOpr ins bld
    let struct (op1, op2 ,address) = tmpVars3 bld 32<rt>
    bld <!-- (ins.Address, len)
    bld <+ (op1 := AST.sext 32<rt> src)
    bld <+ (op2 := AST.sext 32<rt> dst)
    bld <+ (address := AST.zext 32<rt> op2)
    bld <+ (AST.store Endian.Little address op1)
    bld --!> len
  | TwoOperands(OpReg(Regdir _), OpReg(RegIndirPreDec _)) ->
    let struct (src, dst) = trsTwoOpr ins bld
    let struct (op1, op2, address) = tmpVars3 bld 32<rt>
    bld <!-- (ins.Address, len)
    bld <+ (op1 := AST.sext 32<rt> src)
    bld <+ (op2 := AST.sext 32<rt> dst)
    bld <+ (address := (op2 .- numI32 4) |> AST.zext 32<rt>)
    bld <+ (AST.store Endian.Little address op1)
    bld <+ (op2 := address)
    bld <+ (dst := AST.xtlo 32<rt> op2)
    bld --!> len
  | TwoOperands(OpReg(Regdir _), OpReg(IdxRegIndir(_))) ->
    let struct (src, dst) = trsTwoOpr ins bld
    let struct (r0, op1, op2, address) = tmpVars4 bld 32<rt>
    bld <!-- (ins.Address, len)
    bld <+ (r0 := regVar bld R.R0 |> AST.sext 32<rt>)
    bld <+ (op1 := AST.sext 32<rt> src)
    bld <+ (op2 := AST.sext 32<rt> dst)
    bld <+ (address := (r0 .+ op2) |> AST.zext 32<rt>)
    bld <+ (AST.store Endian.Little address op1)
    bld --!> len
  | TwoOperands(OpReg(Regdir _), OpReg(GBRIndirDisp _)) ->
    let struct (src, dst) = trsTwoOpr ins bld
    let struct (gbr, address) = tmpVars2 bld 32<rt>
    let disp = tmpVar bld 8<rt>
    let r0 = tmpVar bld 32<rt>
    bld <!-- (ins.Address, len)
    bld <+ (gbr := regVar bld R.GBR |> AST.sext 32<rt>)
    bld <+ (r0 := regVar bld R.R0 |> AST.sext 32<rt>)
    bld <+ (disp := AST.zext 8<rt> dst << numI32 2)
    bld <+ (address := (gbr .+ disp) |> AST.zext 32<rt>)
    bld <+ (AST.store Endian.Little address r0)
    bld --!> len
  | TwoOperands(OpReg(Regdir _), OpReg(RegIndirDisp _)) ->
    let struct (src, dst, imm) = trsMemOpr4toExpr ins bld
    let struct (op3, address, op1) = tmpVars3 bld 32<rt>
    let disp = tmpVar bld 4<rt>
    bld <!-- (ins.Address, len)
    bld <+ (disp := AST.zext 4<rt> imm << numI32 2)
    bld <+ (op1 := AST.sext 32<rt> src)
    bld <+ (op3 := AST.sext 32<rt> dst)
    bld <+ (address := (disp .+ op3) |> AST.zext 32<rt>)
    bld <+ (AST.store Endian.Little address op1)
    bld --!> len
  | TwoOperands(OpReg(RegIndir _), OpReg(Regdir _)) ->
    let struct (src, dst) = trsTwoOpr ins bld
    let struct (op1, address) = tmpVars2 bld 32<rt>
    let op2 = tmpVar bld 32<rt>
    bld <!-- (ins.Address, len)
    bld <+ (op1 := AST.sext 32<rt> src)
    bld <+ (address := AST.zext 32<rt> op1)
    bld <+ (op2 := AST.loadLE 32<rt> address |> AST.sext 32<rt>)
    bld <+ (dst := AST.xtlo 32<rt> op2)
    bld --!> len
  | TwoOperands(OpReg(RegIndirPostInc _), OpReg(Regdir _)) ->
    let struct (src, dst) = trsTwoOpr ins bld
    let struct (mField, nField) = tmpVars2 bld 4<rt>
    let op1 = tmpVar bld 32<rt>
    let address = tmpVar bld 32<rt>
    let op2 = tmpVar bld 16<rt>
    let struct (m, n) =
      match src, dst with
      | Var(_, _, n1, _), Var(_, _, n2, _) ->
        struct (numI32 (int (n1[1..2])), numI32 (int (n2[1..2])))
      | _ -> Terminator.impossible ()
    bld <!-- (ins.Address, len)
    bld <+ (mField := AST.zext 4<rt> m)
    bld <+ (nField := AST.zext 4<rt> n)
    bld <+ (op1 := AST.sext 32<rt> src)
    bld <+ (address := AST.zext 32<rt> op1)
    bld <+ (op2 := AST.loadLE 32<rt> address |> AST.sext 32<rt>)
    bld <+ (op1 := AST.ite (mField == nField) (op2) (op1 .+ numI32 4))
    bld <+ (src := AST.xtlo 32<rt> op1)
    bld <+ (dst := AST.xtlo 32<rt> op2)
    bld --!> len
  | TwoOperands(OpReg(IdxRegIndir _), OpReg(Regdir _)) ->
    let struct (src, dst) = trsTwoOpr ins bld
    let struct (r0, op1, address) = tmpVars3 bld 32<rt>
    let op2 = tmpVar bld 32<rt>
    bld <!-- (ins.Address, len)
    bld <+ (r0 := regVar bld R.R0 |> AST.sext 32<rt>)
    bld <+ (op1 := AST.sext 32<rt> src)
    bld <+ (address := (r0 .+ op1) |> AST.zext 32<rt>)
    bld <+ (op2 := AST.loadLE 32<rt> address |> AST.sext 32<rt>)
    bld <+ (dst := AST.xtlo 32<rt> op2)
    bld --!> len
  | TwoOperands(OpReg(GBRIndirDisp _), OpReg(Regdir _)) ->
    let struct (src, dst) = trsTwoOpr ins bld
    let struct (gbr, address) = tmpVars2 bld 32<rt>
    let disp = tmpVar bld 8<rt>
    let r0 = tmpVar bld 32<rt>
    bld <!-- (ins.Address, len)
    bld <+ (gbr := regVar bld R.GBR |> AST.sext 32<rt>)
    bld <+ (disp := AST.zext 8<rt> src << numI32 2)
    bld <+ (address := (gbr .+ disp) |> AST.zext 32<rt>)
    bld <+ (r0 := AST.loadLE 32<rt> address |> AST.sext 32<rt>)
    bld <+ (dst := AST.xtlo 32<rt> r0)
    bld --!> len
  | TwoOperands(OpReg(PCRelDisp _), OpReg(Regdir _)) ->
    let struct (src, dst) = trsTwoOpr ins bld
    let struct (pc, address) = tmpVars2 bld 32<rt>
    let disp = tmpVar bld 8<rt>
    let op2 = tmpVar bld 16<rt>
    bld <!-- (ins.Address, len)
    bld <+ (pc := regVar bld R.PC |> AST.sext 32<rt>)
    bld <+ (disp := AST.zext 8<rt> src << numI32 2)
    bld <+ (address := ((pc .+ numI32 4) .& (numI32 3 |> AST.neg))
                     |> AST.zext 32<rt>)
    bld <+ (op2 := AST.loadLE 32<rt> address |> AST.sext 32<rt>)
    bld <+ (dst := AST.xtlo 32<rt> op2)
    bld --!> len
  | TwoOperands(OpReg(RegIndirDisp _), OpReg(Regdir _)) ->
    let struct (src, dst, imm) = trsMemOpr3toExpr ins bld
    let struct (op2, address) = tmpVars2 bld 32<rt>
    let disp = tmpVar bld 4<rt>
    let op3 = tmpVar bld 32<rt>
    bld <!-- (ins.Address, len)
    bld <+ (disp := AST.zext 4<rt> imm << numI32 2)
    bld <+ (op2 := AST.sext 32<rt> src)
    bld <+ (address := (disp .+ op2) |> AST.zext 32<rt>)
    bld <+ (op3 := AST.loadLE 32<rt> address |> AST.sext 32<rt>)
    bld <+ (dst := AST.xtlo 32<rt> op3)
    bld --!> len
  | _ -> Terminator.impossible ()

let movw (ins: Instruction) len bld =
  match ins.Operands with
  | TwoOperands(OpReg(Regdir _), OpReg(RegIndir _)) ->
    let struct (src, dst) = trsTwoOpr ins bld
    let struct (op1, op2 ,address) = tmpVars3 bld 32<rt>
    bld <!-- (ins.Address, len)
    bld <+ (op1 := AST.sext 32<rt> src)
    bld <+ (op2 := AST.sext 32<rt> dst)
    bld <+ (address := AST.zext 32<rt> op2)
    bld <+ (AST.store Endian.Little address op1)
    bld --!> len
  | TwoOperands(OpReg(Regdir _), OpReg(RegIndirPreDec _)) ->
    let struct (src, dst) = trsTwoOpr ins bld
    let struct (op1, op2, address) = tmpVars3 bld 32<rt>
    bld <!-- (ins.Address, len)
    bld <+ (op1 := AST.sext 32<rt> src)
    bld <+ (op2 := AST.sext 32<rt> dst)
    bld <+ (address := (op2 .- numI32 2) |> AST.zext 32<rt>)
    bld <+ (AST.store Endian.Little address op1)
    bld <+ (op2 := address)
    bld <+ (dst := AST.xtlo 32<rt> op2)
    bld --!> len
  | TwoOperands(OpReg(Regdir _), OpReg(IdxRegIndir(_))) ->
    let struct (src, dst) = trsTwoOpr ins bld
    let struct (r0, op1, op2, address) = tmpVars4 bld 32<rt>
    bld <!-- (ins.Address, len)
    bld <+ (r0 := regVar bld R.R0 |> AST.sext 32<rt>)
    bld <+ (op1 := AST.sext 32<rt> src)
    bld <+ (op2 := AST.sext 32<rt> dst)
    bld <+ (address := (r0 .+ op2) |> AST.zext 32<rt>)
    bld <+ (AST.store Endian.Little address op1)
    bld --!> len
  | TwoOperands(OpReg(Regdir _), OpReg(GBRIndirDisp(_))) ->
    let struct (src, dst) = trsTwoOpr ins bld
    let struct (gbr, address) = tmpVars2 bld 32<rt>
    let disp = tmpVar bld 8<rt>
    let r0 = tmpVar bld 32<rt>
    bld <!-- (ins.Address, len)
    bld <+ (gbr := regVar bld R.GBR |> AST.sext 32<rt>)
    bld <+ (r0 := regVar bld R.R0 |> AST.sext 32<rt>)
    bld <+ (disp := AST.zext 8<rt> dst << AST.b1)
    bld <+ (address := (gbr .+ disp) |> AST.zext 32<rt>)
    bld <+ (AST.store Endian.Little address r0)
    bld --!> len
  | TwoOperands(OpReg(Regdir _), OpReg(RegIndirDisp(_))) ->
    let struct (src, dst, imm) = trsMemOpr4toExpr ins bld
    let struct (op2, address, r0) = tmpVars3 bld 32<rt>
    let disp = tmpVar bld 4<rt>
    bld <!-- (ins.Address, len)
    bld <+ (r0 := regVar bld R.R0 |> AST.sext 32<rt>)
    bld <+ (disp := AST.zext 4<rt> imm << AST.b1)
    bld <+ (op2 := AST.sext 32<rt> src)
    bld <+ (address := (disp .+ op2) |> AST.zext 32<rt>)
    bld <+ (AST.store Endian.Little address r0)
    bld --!> len
  | TwoOperands(OpReg(RegIndir _), OpReg(Regdir _)) ->
    let struct (src, dst) = trsTwoOpr ins bld
    let struct (op1, address) = tmpVars2 bld 32<rt>
    let op2 = tmpVar bld 16<rt>
    bld <!-- (ins.Address, len)
    bld <+ (op1 := AST.sext 32<rt> src)
    bld <+ (address := AST.zext 32<rt> op1)
    bld <+ (op2 := AST.loadLE 16<rt> address |> AST.sext 16<rt>)
    bld <+ (dst := AST.xtlo 16<rt> op2)
    bld --!> len
  | TwoOperands(OpReg(RegIndirPostInc _), OpReg(Regdir _)) ->
    let struct (src, dst) = trsTwoOpr ins bld
    let struct (mField, nField) = tmpVars2 bld 4<rt>
    let op1 = tmpVar bld 32<rt>
    let address = tmpVar bld 32<rt>
    let op2 = tmpVar bld 16<rt>
    let struct (m, n) =
      match src, dst with
      | Var(_, _, n1, _), Var(_, _, n2, _) ->
        struct (numI32 (int (n1[1..2])), numI32 (int (n2[1..2])))
      | _ -> Terminator.impossible ()
    bld <!-- (ins.Address, len)
    bld <+ (mField := AST.zext 4<rt> m)
    bld <+ (nField := AST.zext 4<rt> n)
    bld <+ (op1 := AST.sext 32<rt> src)
    bld <+ (address := AST.zext 32<rt> op1)
    bld <+ (op2 := AST.loadLE 16<rt> address |> AST.sext 16<rt>)
    bld <+ (op1 := AST.ite (mField == nField) (op2) (op1 .+ numI32 2))
    bld <+ (src := AST.xtlo 32<rt> op1)
    bld <+ (dst := AST.xtlo 16<rt> op2)
    bld --!> len
  | TwoOperands(OpReg(IdxRegIndir(_)), OpReg(Regdir(_))) ->
    let struct (src, dst) = trsTwoOpr ins bld
    let struct (r0, op1, address) = tmpVars3 bld 32<rt>
    let op2 = tmpVar bld 16<rt>
    bld <!-- (ins.Address, len)
    bld <+ (r0 := regVar bld R.R0 |> AST.sext 32<rt>)
    bld <+ (op1 := AST.sext 32<rt> src)
    bld <+ (address := (r0 .+ op1) |> AST.zext 32<rt>)
    bld <+ (op2 := AST.loadLE 16<rt> address |> AST.sext 16<rt>)
    bld <+ (dst := AST.xtlo 16<rt> op2)
    bld --!> len
  | TwoOperands(OpReg(GBRIndirDisp(_)), OpReg(Regdir _)) ->
    let struct (src, dst) = trsTwoOpr ins bld
    let struct (gbr, address) = tmpVars2 bld 32<rt>
    let disp = tmpVar bld 8<rt>
    let r0 = tmpVar bld 16<rt>
    bld <!-- (ins.Address, len)
    bld <+ (gbr := regVar bld R.GBR |> AST.sext 32<rt>)
    bld <+ (disp := AST.zext 8<rt> src << AST.b1)
    bld <+ (address := ((gbr .+ numI32 4) .+ disp) |> AST.zext 32<rt>)
    bld <+ (r0 := AST.loadLE 16<rt> address |> AST.sext 16<rt>)
    bld <+ (dst := AST.xtlo 16<rt> r0)
    bld --!> len
  | TwoOperands(OpReg(PCRelDisp(_)), OpReg(Regdir _)) ->
    let struct (src, dst) = trsTwoOpr ins bld
    let struct (pc, address) = tmpVars2 bld 32<rt>
    let disp = tmpVar bld 8<rt>
    let op2 = tmpVar bld 16<rt>
    bld <!-- (ins.Address, len)
    bld <+ (pc := regVar bld R.PC |> AST.sext 32<rt>)
    bld <+ (disp := AST.zext 8<rt> src << AST.b1)
    bld <+ (address := ((pc .+ numI32 4) .+ disp) |> AST.zext 32<rt>)
    bld <+ (op2 := AST.loadLE 16<rt> address |> AST.sext 16<rt>)
    bld <+ (dst := AST.xtlo 16<rt> op2)
    bld --!> len
  | TwoOperands(OpReg(RegIndirDisp(_)), OpReg(Regdir _)) ->
    let struct (src, dst, imm) = trsMemOpr3toExpr ins bld
    let struct (op2, address) = tmpVars2 bld 32<rt>
    let disp = tmpVar bld 4<rt>
    let r0 = tmpVar bld 16<rt>
    bld <!-- (ins.Address, len)
    bld <+ (disp := AST.zext 4<rt> imm << AST.b1)
    bld <+ (op2 := AST.sext 32<rt> src)
    bld <+ (address := (disp .+ op2) |> AST.zext 32<rt>)
    bld <+ (r0 := AST.loadLE 16<rt> address |> AST.sext 16<rt>)
    bld <+ (regVar bld R.R0 := AST.xtlo 16<rt> r0)
    bld --!> len
  | _ -> Terminator.impossible ()

let movcal ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (r0, op1, address) = tmpVars3 bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (r0 := regVar bld R.R0 |> AST.sext 32<rt>)
  bld <+ (op1 := AST.sext 32<rt> dst)
  bld <+ (address := AST.zext 32<rt> op1)
  bld <+ (AST.store Endian.Little op1 r0)
  bld --!> len

let movt ins len bld =
  let dst = trsOneOpr ins bld
  let struct (t, op1) = tmpVars2 bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (t := regVar bld R.T |> AST.zext 1<rt>)
  bld <+ (op1 := t)
  bld <+ (dst := AST.xtlo 32<rt> op1)
  bld --!> len

let mull ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (op1, op2) = tmpVars2 bld 32<rt>
  let macl = tmpVar bld 64<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.sext 32<rt> src)
  bld <+ (op2 := AST.sext 32<rt> dst)
  bld <+ (macl := op1 .* op2)
  bld <+ (regVar bld R.MACL := AST.zext 32<rt> macl)
  bld --!> len

let mulsw ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (op1, op2) = tmpVars2 bld 16<rt>
  let macl = tmpVar bld 64<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.sext 32<rt> src |> AST.sext 16<rt>)
  bld <+ (op2 := AST.sext 32<rt> dst |> AST.sext 16<rt>)
  bld <+ (macl := op1 .* op2)
  bld <+ (regVar bld R.MACL := AST.zext 32<rt> macl)
  bld --!> len

let muluw ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (op1, op2) = tmpVars2 bld 16<rt>
  let macl = tmpVar bld 64<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.sext 32<rt> src |> AST.zext 16<rt>)
  bld <+ (op2 := AST.sext 32<rt> dst |> AST.zext 16<rt>)
  bld <+ (macl := op1 .* op2)
  bld <+ (regVar bld R.MACL := AST.zext 32<rt> macl)
  bld --!> len

let neg ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (op1, op2) = tmpVars2 bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.sext 32<rt> src)
  bld <+ (op2 := op1)
  bld <+ (dst := AST.xtlo 32<rt> op2)
  bld --!> len

let negc ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (op1, op2) = tmpVars2 bld 32<rt>
  let t = tmpVar bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (t := regVar bld R.T |> AST.zext 1<rt>)
  bld <+ (op1 := AST.zext 32<rt> src)
  bld <+ (op2 := (AST.neg op1) .- t)
  bld <+ (t := AST.extract op2 1<rt> 32)
  bld <+ (dst := AST.xtlo 32<rt> op2)
  bld <+ (regVar bld R.T := AST.extract t 1<rt> 1)
  bld --!> len

let nop (ins: Instruction) len bld =
  bld <!-- (ins.Address, len)
  bld --!> len

let ``not`` ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (op1, op2) = tmpVars2 bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.zext 32<rt> src)
  bld <+ (op2 := AST.neg op1)
  bld <+ (dst := AST.xtlo 32<rt> op2)
  bld --!> len

let ocbi (ins: Instruction) len bld =
  bld <!-- (ins.Address, len)
  bld --!> len

let ocbp (ins: Instruction) len bld =
  bld <!-- (ins.Address, len)
  bld --!> len

let ocbwb (ins: Instruction) len bld =
  bld <!-- (ins.Address, len)
  bld --!> len

let ``or`` ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  match src with
  | Num _ ->
    let r0 = tmpVar bld 32<rt>
    let imm = tmpVar bld 8<rt>
    bld <!-- (ins.Address, len)
    bld <+ (r0 := regVar bld R.R0 |> AST.zext 32<rt>)
    bld <+ (imm := AST.zext 8<rt> src)
    bld <+ (r0 := r0 .| imm)
    bld <+ (regVar bld R.R0 := AST.xtlo 32<rt> r0)
    bld --!> len
  | Var _ ->
    let struct (op1, op2) = tmpVars2 bld 32<rt>
    bld <!-- (ins.Address, len)
    bld <+ (op1 := AST.zext 32<rt> src)
    bld <+ (op2 := AST.zext 32<rt> dst)
    bld <+ (op2 := op1 .| op2)
    bld <+ (dst := AST.xtlo 32<rt> op2)
    bld --!> len
  | _ -> Terminator.impossible ()

let orb ins len bld =
  let struct (src, _) = trsTwoOpr ins bld
  let struct (r0, gbr, address) = tmpVars3 bld 32<rt>
  let struct (imm, value) = tmpVars2 bld 8<rt>
  bld <!-- (ins.Address, len)
  bld <+ (r0 := regVar bld R.R0 |> AST.sext 32<rt>)
  bld <+ (gbr := regVar bld R.GBR |> AST.sext 32<rt>)
  bld <+ (imm := AST.zext 8<rt> src)
  bld <+ (address := (r0 .+ gbr) |> AST.zext 32<rt>)
  bld <+ (value := AST.loadLE 8<rt> address |> AST.zext 8<rt>)
  bld <+ (value := value .| imm)
  bld <+ (AST.store Endian.Little address value)
  bld --!> len

let pref ins len = function
  | _ -> Terminator.futureFeature ()

let rotcl ins len bld =
  let dst = trsOneOpr ins bld
  let t = tmpVar bld 1<rt>
  let op1 = tmpVar bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (t := regVar bld R.T |> AST.zext 32<rt>)
  bld <+ (op1 := AST.zext 32<rt> dst)
  bld <+ (op1 := (op1 << AST.b1) .| t)
  bld <+ (t := AST.extract op1 1<rt> 32)
  bld <+ (dst := AST.xtlo 32<rt> op1)
  bld <+ (regVar bld R.T := AST.extract t 1<rt> 1)
  bld --!> len

let rotcr ins len bld =
  let dst = trsOneOpr ins bld
  let struct (oldt, t) = tmpVars2 bld 1<rt>
  let op1 = tmpVar bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (t := regVar bld R.T |> AST.zext 32<rt>)
  bld <+ (op1 := AST.zext 32<rt> dst)
  bld <+ (oldt := t)
  bld <+ (t := AST.extract op1 1<rt> 1)
  bld <+ (op1 := (op1 >> AST.b1) .| (oldt << (numI32 31)))
  bld <+ (dst := AST.xtlo 32<rt> op1)
  bld <+ (regVar bld R.T := AST.extract t 1<rt> 1)
  bld --!> len

let rotl ins len bld =
  let dst = trsOneOpr ins bld
  let t = tmpVar bld 1<rt>
  let op1 = tmpVar bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.zext 32<rt> dst)
  bld <+ (t := AST.extract op1 1<rt> 31)
  bld <+ (op1 := (op1 << AST.b1) .| t)
  bld <+ (dst := AST.xtlo 32<rt> op1)
  bld <+ (regVar bld R.T := AST.extract t 1<rt> 1)
  bld --!> len

let rotr ins len bld =
  let dst = trsOneOpr ins bld
  let t = tmpVar bld 1<rt>
  let op1 = tmpVar bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.zext 32<rt> dst)
  bld <+ (t := AST.extract op1 1<rt> 1)
  bld <+ (op1 := (op1 >> AST.b1) .| (t << (numI32 31)))
  bld <+ (dst := AST.xtlo 32<rt> op1)
  bld <+ (regVar bld R.T := AST.extract t 1<rt> 1)
  bld --!> len

let rte (ins: Instruction) len bld =
  let md = tmpVar bld 1<rt>
  let struct (ssr, pc, target, delayedPC) = tmpVars4 bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (md := regVar bld R.MD |> AST.zext 1<rt>)
  if fpuCheck md 1 then () else resinst bld
  bld <+ (ssr := regVar bld R.SSR |> AST.sext 32<rt>)
  bld <+ (pc := regVar bld R.PC |> AST.sext 32<rt>)
  bld <+ (target := pc)
  bld <+ (delayedPC := target .& (AST.neg AST.b1))
  bld <+ (regVar bld R.PC .+ numI32 2 := AST.xtlo 32<rt> delayedPC)
  bld --!> len

let rts (ins: Instruction) len bld =
  let struct (pr, target, delayedPC) = tmpVars3 bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (pr := regVar bld R.PR |> AST.sext 32<rt>)
  bld <+ (target := pr)
  bld <+ (delayedPC := target .& (AST.neg AST.b1))
  bld <+ (regVar bld R.PC .+ numI32 2 := AST.xtlo 32<rt> delayedPC)
  bld --!> len

let sets (ins: Instruction) len bld =
  let s = tmpVar bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (s := AST.b1)
  bld <+ (regVar bld R.S := AST.extract s 1<rt> 1)
  bld --!> len

let sett (ins: Instruction) len bld =
  let t = tmpVar bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (t := AST.b1)
  bld <+ (regVar bld R.T := AST.extract t 1<rt> 1)
  bld --!> len

let shad ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (op1, op2) = tmpVars2 bld 32<rt>
  let shift = tmpVar bld 5<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.sext 32<rt> src)
  bld <+ (op2 := AST.sext 32<rt> dst)
  bld <+ (shift := AST.zext 5<rt> op1)
  bld <+ (op2 := AST.ite (op1 ?>= AST.b0) (op2 << shift)
  (AST.ite (shift != AST.b0) (op2 >> (numI32 32 .- shift))
  (AST.ite (op2 ?< AST.b0) (numI32 -1) (AST.b0))))
  bld <+ (dst := AST.xtlo 32<rt> op2)
  bld --!> len

let shal ins len bld =
  let dst = trsOneOpr ins bld
  let op1 = tmpVar bld 32<rt>
  let t = tmpVar bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.sext 32<rt> dst)
  bld <+ (t := AST.extract op1 1<rt> 32)
  bld <+ (op1 := op1 << AST.b1)
  bld <+ (dst := AST.xtlo 32<rt> op1)
  bld <+ (regVar bld R.T := AST.extract t 1<rt> 1)
  bld --!> len

let shar ins len bld =
  let dst = trsOneOpr ins bld
  let op1 = tmpVar bld 32<rt>
  let t = tmpVar bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.sext 32<rt> dst)
  bld <+ (t := AST.extract op1 1<rt> 1)
  bld <+ (op1 := op1 >> AST.b1)
  bld <+ (dst := AST.xtlo 32<rt> op1)
  bld <+ (regVar bld R.T := AST.extract t 1<rt> 1)
  bld --!> len

let shld ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (op1, op2) = tmpVars2 bld 32<rt>
  let shift = tmpVar bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.sext 32<rt> src)
  bld <+ (op2 := AST.sext 32<rt> dst)
  bld <+ (shift := AST.zext 32<rt> (AST.extract op1 5<rt> 0))
  bld <+ (op2 := AST.ite (op1 ?>= (AST.num0 32<rt>)) (op2 << shift)
              (AST.ite (shift != AST.num0 32<rt>)
                       (op2 >> (numI32 32 .- shift)) (numI32 0)))
  bld <+ (dst := AST.xtlo 32<rt> op2)
  bld --!> len

let shll ins len bld =
  let dst = trsOneOpr ins bld
  let op1 = tmpVar bld 32<rt>
  let t = tmpVar bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.zext 32<rt> dst)
  bld <+ (t := AST.extract op1 1<rt> 1)
  bld <+ (op1 := op1 << AST.b1)
  bld <+ (dst := AST.xtlo 32<rt> op1)
  bld <+ (regVar bld R.T := AST.extract t 1<rt> 1)
  bld --!> len

let shll2 ins len bld =
  let dst = trsOneOpr ins bld
  let op1 = tmpVar bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.zext 32<rt> dst)
  bld <+ (op1 := op1 << numI32 2)
  bld <+ (dst := AST.xtlo 32<rt> op1)
  bld --!> len

let shll8 ins len bld =
  let dst = trsOneOpr ins bld
  let op1 = tmpVar bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.zext 32<rt> dst)
  bld <+ (op1 := op1 << numI32 8)
  bld <+ (dst := AST.xtlo 32<rt> op1)
  bld --!> len

let shll16 ins len bld =
  let dst = trsOneOpr ins bld
  let op1 = tmpVar bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.zext 32<rt> dst)
  bld <+ (op1 := op1 << numI32 16)
  bld <+ (dst := AST.xtlo 32<rt> op1)
  bld --!> len

let shlr ins len bld =
  let dst = trsOneOpr ins bld
  let op1 = tmpVar bld 32<rt>
  let t = tmpVar bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.zext 32<rt> dst)
  bld <+ (t := AST.extract op1 1<rt> 1)
  bld <+ (op1 := op1 >> AST.b1)
  bld <+ (dst := AST.xtlo 32<rt> op1)
  bld <+ (regVar bld R.T := AST.extract t 1<rt> 1)
  bld --!> len

let shlr2 ins len bld =
  let dst = trsOneOpr ins bld
  let op1 = tmpVar bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.zext 32<rt> dst)
  bld <+ (op1 := op1 >> numI32 2)
  bld <+ (dst := AST.xtlo 32<rt> op1)
  bld --!> len

let shlr8 ins len bld =
  let dst = trsOneOpr ins bld
  let op1 = tmpVar bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.zext 32<rt> dst)
  bld <+ (op1 := op1 >> numI32 8)
  bld <+ (dst := AST.xtlo 32<rt> op1)
  bld --!> len

let shlr16 ins len bld =
  let dst = trsOneOpr ins bld
  let op1 = tmpVar bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.zext 32<rt> dst)
  bld <+ (op1 := op1 >> numI32 16)
  bld <+ (dst := AST.xtlo 32<rt> op1)
  bld --!> len

let sleep (ins: Instruction) len bld =
  bld <!-- (ins.Address, len)
  bld --!> len

let stc ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let md = tmpVar bld 1<rt>
  let struct (reg, op1) = tmpVars2 bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (md := regVar bld R.MD |> AST.zext 1<rt>)
  if (fpuCheck md 1) then () else resinst bld
  bld <+ (reg := src |> AST.sext 32<rt>)
  bld <+ (op1 := reg)
  bld <+ (dst := AST.xtlo 32<rt> op1)
  bld --!> len

let stcl ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let md = tmpVar bld 1<rt>
  let struct (reg, op1, address) = tmpVars3 bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (md := regVar bld R.MD |> AST.zext 1<rt>)
  if (fpuCheck md 1) then () else resinst bld
  bld <+ (reg := AST.sext 32<rt> src)
  bld <+ (op1 := AST.sext 32<rt> dst)
  bld <+ (address := (op1 .- numI32 4) |> AST.zext 32<rt>)
  bld <+ (AST.store Endian.Little address reg)
  bld <+ (op1 := address)
  bld <+ (dst := AST.xtlo 32<rt> op1)
  bld --!> len

let sts ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  match src with
  | Var(_, _, r, _) ->
    if (r = "fpscr" || r = "fpul") then
      let struct (sr, fps, op1) = tmpVars3 bld 32<rt>
      bld <!-- (ins.Address, len)
      bld <+ (sr := regVar bld R.SR |> AST.zext 32<rt>)
      bld <+ (fps := src |> AST.zext 32<rt>)
      bld <+ (op1 := fps)
      bld <+ (dst := AST.xtlo 32<rt> op1)
      bld --!> len
    else
      let struct (reg, op1) = tmpVars2 bld 32<rt>
      bld <!-- (ins.Address, len)
      bld <+ (reg := AST.sext 32<rt> src)
      bld <+ (op1 := reg)
      bld <+ (dst := AST.xtlo 32<rt> op1)
      bld --!> len
  | _ -> Terminator.impossible ()

let stsl ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  match src with
  | Var(_, _, r, _) ->
    if (r = "fpscr" || r = "fpul") then
      let struct (sr, reg, op1, address) = tmpVars4 bld 32<rt>
      bld <!-- (ins.Address, len)
      bld <+ (sr := regVar bld R.SR |> AST.zext 32<rt>)
      bld <+ (reg := AST.zext 32<rt> src)
      bld <+ (op1 := AST.sext 32<rt> dst)
      bld <+ (address := op1 .- numI32 4 |> AST.zext 32<rt>)
      bld <+ (op1 := address)
      bld <+ (dst := AST.xtlo 32<rt> op1)
      bld --!> len
    else
      let struct (reg, op1, address) = tmpVars3 bld 32<rt>
      bld <!-- (ins.Address, len)
      bld <+ (reg := AST.sext 32<rt> src)
      bld <+ (op1 := AST.sext 32<rt> dst)
      bld <+ (address := (op1 .- numI32 4) |> AST.zext 32<rt>)
      bld <+ (AST.store Endian.Little address reg)
      bld <+ (op1 := address)
      bld <+ (dst := AST.xtlo 32<rt> op1)
      bld --!> len
  | _ -> Terminator.impossible ()

let sub ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (op1, op2) = tmpVars2 bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.sext 32<rt> src)
  bld <+ (op2 := AST.sext 32<rt> dst)
  bld <+ (op2 := op2 .- op1)
  bld <+ (dst := AST.xtlo 32<rt> op2)
  bld --!> len

let subc ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (op1, op2) = tmpVars2 bld 32<rt>
  let t = tmpVar bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (t := regVar bld R.T |> AST.zext 1<rt>)
  bld <+ (op1 := AST.sext 32<rt> src |> AST.zext 32<rt>)
  bld <+ (op1 := AST.sext 32<rt> dst |> AST.zext 32<rt>)
  bld <+ (op2 := (op2 .- op1) .- t)
  bld <+ (t := AST.extract op2 1<rt> 32)
  bld <+ (dst := AST.xtlo 32<rt> op2)
  bld <+ (regVar bld R.T := AST.extract t 1<rt> 1)
  bld --!> len

let subv ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (op1, op2) = tmpVars2 bld 32<rt>
  let t = tmpVar bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.sext 32<rt> src)
  bld <+ (op2 := AST.sext 32<rt> dst)
  bld <+ (op2 := op2 .- op1)
  bld <+ (t := ((op2 ?< (pown -2 31 |> numI32PC))
       .| (op2 ?>= (pown 2 31 |> numI32PC))))
  bld <+ (dst := AST.xtlo 32<rt> op2)
  bld <+ (regVar bld R.T := AST.extract t 1<rt> 1)
  bld --!> len

let swapb ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (op1, op2) = tmpVars2 bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.zext 32<rt> src)
  bld <+ (op2 := ((AST.extract op1 16<rt> 16) << (numI32 16))
               .| (AST.extract op1 8<rt> 32)
               .| (AST.extract op1 8<rt> 8))
  bld <+ (dst := AST.xtlo 32<rt> op2)
  bld --!> len

let swapw ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (op1, op2) = tmpVars2 bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.zext 32<rt> src)
  bld <+ (op2 := ((AST.extract op1 16<rt> 32) << (numI32 16))
               .| (AST.extract op1 16<rt> 16))
  bld <+ (dst := AST.xtlo 32<rt> op2)
  bld --!> len

let tasb ins len bld =
  let dst = trsOneOpr ins bld
  let struct (op1, address) = tmpVars2 bld 32<rt>
  let value = tmpVar bld 8<rt>
  let t = tmpVar bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.sext 32<rt> dst)
  bld <+ (address := AST.zext 32<rt> op1)
  //OCBP
  bld <+ (value := AST.loadLE 8<rt> address |> AST.zext 8<rt>)
  bld <+ (t := AST.ite (value == AST.b0) (AST.b1) (AST.b0))
  bld <+ (value := value .| (AST.b1 << numI32 7))
  bld <+ (AST.store Endian.Little address value)
  bld <+ (regVar bld R.T := AST.extract t 1<rt> 1)
  bld --!> len

let trapa ins len bld =
  let dst = trsOneOpr ins bld
  let imm = tmpVar bld 8<rt>
  bld <!-- (ins.Address, len)
  bld <+ (imm := AST.zext 8<rt> dst)
  trap bld imm
  bld --!> len

let tst ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let r0 = tmpVar bld 32<rt>
  let imm = tmpVar bld 8<rt>
  let t = tmpVar bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (r0 := regVar bld R.R0 |> AST.sext 32<rt>)
  bld <+ (imm := AST.zext 8<rt> src)
  bld <+ (t := (r0 .| imm) == AST.b0)
  bld <+ (regVar bld R.T := AST.extract t 1<rt> 1)
  bld --!> len

let tstb ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (r0, gbr, address) = tmpVars3 bld 32<rt>
  let struct (imm, value) = tmpVars2 bld 8<rt>
  let t = tmpVar bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (r0 := regVar bld R.R0 |> AST.sext 32<rt>)
  bld <+ (gbr := regVar bld R.GBR |> AST.sext 32<rt>)
  bld <+ (imm := AST.zext 8<rt> src)
  bld <+ (address := (r0 .+ gbr) |> AST.zext 32<rt>)
  bld <+ (value := AST.loadLE 8<rt> address |> AST.zext 8<rt>)
  bld <+ (t := (value .| imm) == AST.b0)
  bld <+ (regVar bld R.T := AST.extract t 1<rt> 1)
  bld --!> len

let xor ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (op1, op2) = tmpVars2 bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.zext 32<rt> src)
  bld <+ (op2 := AST.zext 32<rt> dst)
  bld <+ (op2 := op2 <+> op1)
  bld <+ (dst := AST.xtlo 32<rt> op2)
  bld --!> len

let xorb ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (r0, gbr, address) = tmpVars3 bld 32<rt>
  let struct (imm, value) = tmpVars2 bld 8<rt>
  bld <!-- (ins.Address, len)
  bld <+ (r0 := regVar bld R.R0 |> AST.sext 32<rt>)
  bld <+ (gbr := regVar bld R.GBR |> AST.sext 32<rt>)
  bld <+ (imm := src |> AST.zext 8<rt>)
  bld <+ (address := (r0 .+ gbr) |> AST.zext 32<rt>)
  bld <+ (value := AST.loadLE 8<rt> address |> AST.zext 8<rt>)
  bld <+ (value := value <+> imm)
  bld <+ (AST.store Endian.Little address value)
  bld --!> len

let xtrct ins len bld =
  let struct (src, dst) = trsTwoOpr ins bld
  let struct (op1, op2) = tmpVars2 bld 32<rt>
  bld <!-- (ins.Address, len)
  bld <+ (op1 := AST.zext 32<rt> src)
  bld <+ (op2 := AST.zext 32<rt> dst)
  bld <+ (op2 := (AST.xtlo 16<rt> op2) .| (AST.xthi 16<rt> op1))
  bld <+ (dst := AST.xtlo 32<rt> op2)
  bld --!> len
