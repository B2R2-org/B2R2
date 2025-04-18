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

module B2R2.FrontEnd.SH4.GeneralLifter

open System.Collections.Generic
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingOperators
open B2R2.FrontEnd.SH4

let delaySlot = List<IRBuilder>()

let numI32 n = BitVector.OfInt32 n 32<rt> |> AST.num

let numI32PC n = BitVector.OfInt32 n 32<rt> |> AST.num

let numI64 n = BitVector.OfInt64 n 16<rt> |> AST.num

let exprToInt (n: Expr) =
  match n.E with
  | Num a -> a
  | _ -> Terminator.impossible()

let bv1Check s =
  exprToInt s |> BitVector.IsOne

let inline (!.) (ctxt: TranslationContext) reg =
  Register.toRegID reg |> ctxt.GetRegVar

let trsOprToExpr ctxt = function
  | OpReg (Regdir r) -> !.ctxt r
  | OpReg (RegIndir r) -> !.ctxt r
  | OpReg (IdxGbr (r, _)) -> !.ctxt r
  | OpReg (Imm n) -> numI32PC n
  | _ -> Terminator.impossible()

let trsOneOpr ins ctxt =
  match ins.Operands with
  | OneOperand r -> trsOprToExpr ctxt r
  | _ -> raise InvalidOperandException

let trsTwoOpr ins ctxt =
  match ins.Operands with
  | TwoOperands (o1, o2) ->
    struct (trsOprToExpr ctxt o1,
            trsOprToExpr ctxt o2)
  | _ -> raise InvalidOperandException

let trsThreeOpr ins ctxt =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) ->
    struct (trsOprToExpr ctxt o1,
            trsOprToExpr ctxt o2,
            trsOprToExpr ctxt o3)
  | _ -> raise InvalidOperandException

let trsMemOpr1toExpr ins ctxt =
  match ins.Operands with
  | TwoOperands (OpReg (PreDec r1), OpReg (Regdir r2))
    -> struct (!.ctxt r1, !.ctxt r2, -1)
  | TwoOperands (OpReg (PostInc r1), OpReg (Regdir r2))
    -> struct (!.ctxt r1, !.ctxt r2, 1)
  | TwoOperands (OpReg (RegIndir r1), OpReg (Regdir r2))
    -> struct (!.ctxt r1, !.ctxt r2, 0)
  | _ -> Terminator.impossible()

let trsMemOpr2toExpr ins ctxt =
  match ins.Operands with
  | TwoOperands (OpReg (Regdir r1), OpReg (PreDec r2))
    -> (!.ctxt r1, !.ctxt r2, -1)
  | TwoOperands (OpReg (Regdir r1), OpReg (PostInc r2))
    -> (!.ctxt r1, !.ctxt r2, 1)
  | TwoOperands (OpReg (Regdir r1), OpReg (RegIndir r2))
    -> (!.ctxt r1, !.ctxt r2, 0)
  | _ -> Terminator.impossible()

let trsMemOpr3toExpr ins ctxt =
  match ins.Operands with
  | TwoOperands (OpReg (RegDisp (imm, r1)), OpReg (Regdir r2))
    -> struct (!.ctxt r1, !.ctxt r2, numI32 imm)
  | _ -> Terminator.impossible()

let trsMemOpr4toExpr ins ctxt =
  match ins.Operands with
  | TwoOperands (OpReg (Regdir r1), OpReg (RegDisp (imm, r2)))
    -> struct (!.ctxt r1, !.ctxt r2, numI32 imm)
  | _ -> Terminator.impossible()

let inline tmpVars2 ir t =
  struct (!+ir t, !+ir t)

let inline tmpVars3 ir t =
  struct (!+ir t, !+ir t, !+ir t)

let inline tmpVars4 ir t =
  struct (!+ir t, !+ir t, !+ir t, !+ir t)

let illSlot1 ins ir len ctxt =
  !<ir ins.Address len
  !!ir (!.ctxt R.SPC := !.ctxt R.PC .- numI32 2)
  !!ir (!.ctxt R.SSR := !.ctxt R.SR)
  !!ir (!.ctxt R.SGR := !.ctxt R.R15)
  !!ir (!.ctxt R.EXPEVT := numI32PC 0x000001A0)
  !!ir (!.ctxt R.MD := AST.b1)
  !!ir (!.ctxt R.RB := AST.b1)
  !!ir (!.ctxt R.BL := AST.b1)
  !!ir (!.ctxt R.PC := !.ctxt R.VBR .+ numI32PC 0x00000100)
  !!ir (AST.sideEffect (Exception("ILLSLOT")))
  !>ir len

let illSlot2 ir len ctxt =
  !!ir (!.ctxt R.SPC := !.ctxt R.PC .- numI32 2)
  !!ir (!.ctxt R.SSR := !.ctxt R.SR)
  !!ir (!.ctxt R.SGR := !.ctxt R.R15)
  !!ir (!.ctxt R.EXPEVT := numI32PC 0x000001A0)
  !!ir (!.ctxt R.MD := AST.b1)
  !!ir (!.ctxt R.RB := AST.b1)
  !!ir (!.ctxt R.BL := AST.b1)
  !!ir (!.ctxt R.PC := !.ctxt R.VBR .+ numI32PC 0x00000100)
  !!ir (AST.sideEffect (Exception("ILLSLOT")))
  !>ir len

let fpudis ir ctxt =
  !!ir (!.ctxt R.SPC := !.ctxt R.PC)
  !!ir (!.ctxt R.SSR := !.ctxt R.SR)
  !!ir (!.ctxt R.SGR := !.ctxt R.R15)
  !!ir (!.ctxt R.EXPEVT := numI32PC 0x00000800)
  !!ir (!.ctxt R.MD := AST.b1)
  !!ir (!.ctxt R.RB := AST.b1)
  !!ir (!.ctxt R.BL := AST.b1)
  !!ir (!.ctxt R.PC := !.ctxt R.VBR .+ numI32PC 0x00000100)
  !!ir (AST.sideEffect (Exception("FPUDIS")))

let slotFpudis ir ctxt =
  !!ir (!.ctxt R.SPC := !.ctxt R.PC .- numI32 2)
  !!ir (!.ctxt R.SSR := !.ctxt R.SR)
  !!ir (!.ctxt R.SGR := !.ctxt R.R15)
  !!ir (!.ctxt R.EXPEVT := numI32PC 0x00000820)
  !!ir (!.ctxt R.MD := AST.b1)
  !!ir (!.ctxt R.RB := AST.b1)
  !!ir (!.ctxt R.BL := AST.b1)
  !!ir (!.ctxt R.PC := !.ctxt R.VBR .+ numI32PC 0x00000100)
  !!ir (AST.sideEffect (Exception("SLOTFPUDIS")))

let fpuExc ir ctxt =
  !!ir (!.ctxt R.SPC := !.ctxt R.PC)
  !!ir (!.ctxt R.SSR := !.ctxt R.SR)
  !!ir (!.ctxt R.SGR := !.ctxt R.R15)
  !!ir (!.ctxt R.EXPEVT := numI32PC 0x00000120)
  !!ir (!.ctxt R.MD := AST.b1)
  !!ir (!.ctxt R.RB := AST.b1)
  !!ir (!.ctxt R.BL := AST.b1)
  !!ir (!.ctxt R.PC := !.ctxt R.VBR .+ numI32PC 0x00000100)
  !!ir (AST.sideEffect (Exception("FPUEXC")))

let trap ir imm ctxt =
  !!ir (!.ctxt R.SPC := !.ctxt R.PC .+ numI32 2)
  !!ir (!.ctxt R.SSR := !.ctxt R.SR)
  !!ir (!.ctxt R.SGR := !.ctxt R.R15)
  !!ir (!.ctxt R.TRA := imm << numI32 2)
  !!ir (!.ctxt R.EXPEVT := numI32PC 0x00000160)
  !!ir (!.ctxt R.MD := AST.b1)
  !!ir (!.ctxt R.RB := AST.b1)
  !!ir (!.ctxt R.BL := AST.b1)
  !!ir (!.ctxt R.PC := !.ctxt R.VBR .+ numI32PC 0x00000100)
  !!ir (AST.sideEffect (Exception("TRAPA")))

let resinst ir ctxt =
  !!ir (!.ctxt R.SPC := !.ctxt R.PC)
  !!ir (!.ctxt R.SSR := !.ctxt R.SR)
  !!ir (!.ctxt R.SGR := !.ctxt R.R15)
  !!ir (!.ctxt R.EXPEVT := numI32PC 0x00000180)
  !!ir (!.ctxt R.MD := AST.b1)
  !!ir (!.ctxt R.RB := AST.b1)
  !!ir (!.ctxt R.BL := AST.b1)
  !!ir (!.ctxt R.PC := !.ctxt R.VBR .+ numI32PC 0x00000100)
  !!ir (AST.sideEffect (Exception("RESINST")))

let fpudisChecker ir ctxt =
  if ((bv1Check (!.ctxt R.FD)) && (delaySlot.Count = 1)) then slotFpudis ir ctxt
  elif ((bv1Check (!.ctxt R.FD)) && (delaySlot.Count = 0)) then fpudis ir ctxt
  else ()

let fpuCheck fps n =
  bv1Check (AST.extract fps 1<rt> n)

let signedSaturate r =
  AST.ite ((r ?< numI32 (int ((-2.0)**32))) .| (r ?> numI32 (int ((2.0)**32))))
          (AST.ite ((r ?< numI32 (int ((-2.0)**32))))
                   (numI32 (int ((-2.0)**32))) (numI32 (int ((2.0)**32))))
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

let add ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  match src.E with
  | Num n ->
    let ir = IRBuilder (8)
    let t1 = !+ir 8<rt>
    let t2 = !+ir 32<rt>
    !<ir ins.Address len
    !!ir (t1 := n |> AST.num |> AST.sext 8<rt>)
    !!ir (t2 := dst |> AST.sext 32<rt>)
    !!ir (t2 := t2 .+ t1)
    !!ir (dst := t2)
    !>ir len
  | Var (_, _, s) ->
    let oprSize = 32<rt>
    let ir = IRBuilder (8)
    let struct (t1, t2) = tmpVars2 ir oprSize
    !<ir ins.Address len
    !!ir (t1 := s |> Register.ofString |> !.ctxt |> AST.sext 32<rt>)
    !!ir (t2 := dst |> AST.sext 32<rt>)
    !!ir (t2 := t2 .+ t1)
    !!ir (dst := AST.xtlo 32<rt> t2)
    !>ir len
  | _ -> Terminator.impossible()

let addc ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let oprSize = 32<rt>
  let ir = IRBuilder (16)
  let struct (t1,t2) = tmpVars2 ir oprSize
  let t = !+ir 1<rt>
  !<ir ins.Address len
  !!ir (t := AST.zext 1<rt> (!.ctxt R.T))
  !!ir (t1 := AST.zext 32<rt> <| AST.sext 32<rt> src)
  !!ir (t2 := AST.zext 32<rt> <| AST.sext 32<rt> dst)
  !!ir (t2 := t2 .+ t1 .+ t)
  !!ir (t := AST.extract t2 1<rt> 32)
  !!ir (dst := AST.xtlo 32<rt> t2)
  !!ir ((!.ctxt R.T) := t)
  !>ir len

let addv ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let oprSize = 32<rt>
  let ir = IRBuilder (8)
  let struct (t1,t2) = tmpVars2 ir oprSize
  let t = !+ir 1<rt>
  !<ir ins.Address len
  !!ir (t1 := AST.sext 32<rt> src)
  !!ir (t2 := AST.sext 32<rt> dst)
  !!ir (t2 := t2 .+ t1)
  !!ir (dst := AST.xtlo 32<rt> t2)
  !!ir (t := ((t2 .< (pown -2 31 |> numI32PC))
             .| (t2 ?>= (pown 2 31 |> numI32PC))))
  !>ir len

let ``and`` ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  match src.E with
  | Num n ->
    let ir = IRBuilder (8)
    let t1 = !+ir 8<rt>
    let t2 = !+ir 32<rt>
    !<ir ins.Address len
    !!ir (t1 := n |> AST.num |> AST.zext 8<rt>)
    !!ir (t2 := AST.zext 32<rt> dst)
    !!ir (t2 := t2 .& t1)
    !!ir (dst := AST.xtlo 32<rt> t2)
    !>ir len
  | Var (_, _, s) ->
    let oprSize = 32<rt>
    let ir = IRBuilder 8
    let struct (t1,t2) = tmpVars2 ir oprSize
    !<ir ins.Address len
    !!ir (t1 := Register.ofString s |> !.ctxt |> AST.zext 32<rt>)
    !!ir (t2 := AST.zext 32<rt> dst)
    !!ir (t2 := t2 .& t1)
    !!ir (dst := AST.xtlo 32<rt> t2)
    !>ir len
  | _ -> Terminator.impossible()

let andb ins len ctxt =
  let struct (src, _) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  let struct (r0,gbr,addr) = tmpVars3 ir 32<rt>
  let struct (imm,value) = tmpVars2 ir 8<rt>
  !<ir ins.Address len
  !!ir (r0 := R.R0 |> !.ctxt |> AST.sext 32<rt>)
  !!ir (gbr := R.GBR |> !.ctxt |> AST.sext 32<rt>)
  !!ir (imm := AST.zext 8<rt> src)
  !!ir (addr := (r0 .+ gbr) |> AST.zext 32<rt>)
  !!ir (value := addr |> AST.loadLE 8<rt> |> AST.zext 8<rt>)
  !!ir (value := value .& imm)
  !!ir (AST.store Endian.Little addr value)
  !>ir len

let bfHelper ir ins len ctxt =
  let disp = trsOneOpr ins ctxt
  let struct (pc, newPC, delayedPC) = tmpVars3 ir 32<rt>
  let t = !+ir 1<rt>
  let label = !+ir 8<rt>
  let temp = !+ir 32<rt>
  !<ir ins.Address len
  !!ir (t := !.ctxt R.T |> AST.zext 1<rt>)
  !!ir (pc := !.ctxt R.PC |> AST.sext 32<rt>)
  !!ir (newPC := (!.ctxt R.PC .+ numI32 2) |> AST.sext 32<rt>)
  !!ir (delayedPC := (!.ctxt R.PC .+ numI32 4) |> AST.sext 32<rt>)
  !!ir (label := (AST.sext 8<rt> disp) << AST.b1)
  !!ir (temp := AST.zext 32<rt> (pc .+ label .+ (numI32 4)))
  !!ir (newPC := AST.ite (t == AST.b0) (temp) (newPC))
  !!ir (delayedPC := AST.ite (t == AST.b0) (temp .+ numI32 2) (delayedPC))
  !!ir (!.ctxt R.PC .+ numI32 2 := AST.xtlo 32<rt> newPC)
  !!ir (!.ctxt R.PC .+ numI32 4 := AST.xtlo 32<rt> delayedPC)
  !>ir len

let bf ins len ctxt =
  let ir = IRBuilder (32)
  if (delaySlot.Count = 1) then (illSlot1 ins ir len ctxt)
  else (bfHelper ir ins len ctxt)

let bfsHelper ir ins len ctxt =
  let disp = trsOneOpr ins ctxt
  let struct (pc, delayedPC) = tmpVars2 ir 32<rt>
  let t = !+ir 1<rt>
  let label = !+ir 8<rt>
  let temp = !+ir 32<rt>
  !<ir ins.Address len
  !!ir (t := !.ctxt R.T |> AST.zext 1<rt>)
  !!ir (pc := !.ctxt R.PC |> AST.sext 32<rt>)
  !!ir (delayedPC := (!.ctxt R.PC .+ numI32 2) |> AST.sext 32<rt>)
  !!ir (label := (AST.sext 8<rt> disp) << AST.b1)
  !!ir (temp := AST.zext 32<rt> (pc .+ label .+ (numI32 4)))
  !!ir (delayedPC := AST.ite (t == AST.b0) (temp .+ numI32 2) (delayedPC))
  !!ir (!.ctxt R.PC .+ numI32 2 := AST.xtlo 32<rt> delayedPC)
  delaySlot.Clear()
  !>ir len

let bfs ins len ctxt =
  let ir = IRBuilder (32)
  if (delaySlot.Count = 1) then (illSlot1 ins ir len ctxt)
  else
    !<ir ins.Address len
    delaySlot.Add (bfsHelper ir ins len ctxt)
    !>ir len

let braHelper ir ins len ctxt =
  let disp = trsOneOpr ins ctxt
  let struct (pc, temp, delayedPC) = tmpVars3 ir 32<rt>
  let label = !+ir 12<rt>
  !<ir ins.Address len
  !!ir (pc := AST.sext 32<rt> pc)
  !!ir (label := AST.sext 12<rt> disp)
  !!ir (temp := AST.zext 32<rt> (pc .+ label .+ (numI32 4)))
  !!ir (delayedPC := temp)
  !!ir (!.ctxt R.PC .+ (numI32 2) := AST.xtlo 32<rt> delayedPC)
  delaySlot.Clear()
  !>ir len

let bra ins len ctxt =
  let ir = IRBuilder (32)
  if (delaySlot.Count = 1) then (illSlot1 ins ir len ctxt)
  else
    !<ir ins.Address len
    delaySlot.Add (braHelper ir ins len ctxt)
    !>ir len

let brafHelper ir ins len ctxt =
  let dst = trsOneOpr ins ctxt
  let struct (pc, op1, target, delayedPC) = tmpVars4 ir 32<rt>
  !<ir ins.Address len
  !!ir (pc := !.ctxt R.PC |> AST.sext 32<rt>)
  !!ir (op1 := AST.sext 32<rt> dst)
  !!ir (target := (pc .+ op1 .+ (numI32 4)) |> AST.zext 32<rt>)
  !!ir (delayedPC := target .| (AST.neg AST.b1))
  !!ir (!.ctxt R.PC .+ (numI32 2) := AST.xtlo 32<rt> delayedPC)
  delaySlot.Clear()
  !>ir len

let braf ins len ctxt =
  let ir = IRBuilder (32)
  if (delaySlot.Count = 1) then (illSlot1 ins ir len ctxt)
  else
    !<ir ins.Address len
    delaySlot.Add (brafHelper ir ins len ctxt)
    !>ir len

let bsrHelper ir ins len ctxt =
  let disp = trsOneOpr ins ctxt
  let struct (pc, delayedPR, temp, delayedPC) = tmpVars4 ir 32<rt>
  let label = !+ir 12<rt>
  !<ir ins.Address len
  !!ir (pc := !.ctxt R.PC |> AST.sext 32<rt>)
  !!ir (label := (AST.sext 32<rt> disp) << AST.b1)
  !!ir (delayedPR := pc .+ numI32 4)
  !!ir (temp := (pc .+ label .+ numI32 4) |> AST.zext 32<rt>)
  !!ir (delayedPC := temp)
  !!ir (!.ctxt R.PR := AST.xtlo 32<rt> delayedPR)
  !!ir (!.ctxt R.PC := AST.xtlo 32<rt> delayedPC)
  delaySlot.Clear()
  !>ir len

let bsr ins len ctxt =
  let ir = IRBuilder (32)
  if (delaySlot.Count = 1) then (illSlot1 ins ir len ctxt)
  else
    !<ir ins.Address len
    delaySlot.Add (bsrHelper ir ins len ctxt)
    !>ir len

let bsrfHelper ir ins len ctxt =
  let dst = trsOneOpr ins ctxt
  let struct (pc, delayedPR, op1, delayedPC) = tmpVars4 ir 32<rt>
  let target = !+ir 32<rt>
  !<ir ins.Address len
  !!ir (pc := !.ctxt R.PC |> AST.sext 32<rt>)
  !!ir (op1 := AST.sext 32<rt> dst)
  !!ir (delayedPR := pc .+ numI32 4)
  !!ir (target := (pc .+ op1 .+ numI32 4) |> AST.zext 32<rt>)
  !!ir (delayedPC := target .| (AST.neg AST.b1))
  !!ir (!.ctxt R.PR := AST.xtlo 32<rt> delayedPR)
  !!ir (!.ctxt R.PC := AST.xtlo 32<rt> delayedPC)
  delaySlot.Clear()
  !>ir len

let bsrf ins len ctxt =
  let ir = IRBuilder (32)
  if (delaySlot.Count = 1) then (illSlot1 ins ir len ctxt)
  else
    !<ir ins.Address len
    delaySlot.Add (bsrfHelper ir ins len ctxt)
    !>ir len

let btHelper ir ins len ctxt =
  let disp = trsOneOpr ins ctxt
  let struct (pc, newPC, delayedPC, temp) = tmpVars4 ir 32<rt>
  let t = !+ir 1<rt>
  let label = !+ir 8<rt>
  !<ir ins.Address len
  !!ir (t := !.ctxt R.T |> AST.zext 1<rt>)
  !!ir (pc := !.ctxt R.PC |> AST.sext 32<rt>)
  !!ir (newPC := (!.ctxt R.PC .+ numI32 2) |> AST.sext 32<rt>)
  !!ir (delayedPC := (!.ctxt R.PC .+ numI32 4) |> AST.sext 32<rt>)
  !!ir (label := (AST.sext 8<rt> disp) << AST.b1)
  !!ir (temp := (pc .+ label .+ numI32 4) |> AST.zext 32<rt>)
  !!ir (newPC := AST.ite (t == AST.b1) (temp) (newPC))
  !!ir (delayedPC := AST.ite (t == AST.b1) (temp .+ numI32 2) (delayedPC))
  !!ir (!.ctxt R.PC .+ numI32 2 := AST.xtlo 32<rt> newPC)
  !!ir (!.ctxt R.PC .+ numI32 4 := AST.xtlo 32<rt> delayedPC)
  !>ir len

let bt ins len ctxt =
  let ir = IRBuilder (32)
  if (delaySlot.Count = 1) then (illSlot1 ins ir len ctxt)
  else (btHelper ir ins len ctxt)

let btsHelper ir ins len ctxt =
  let disp = trsOneOpr ins ctxt
  let struct (pc, delayedPC, temp) = tmpVars3 ir 32<rt>
  let t = !+ir 1<rt>
  let label = !+ir 8<rt>
  !<ir ins.Address len
  !!ir (t := !.ctxt R.T |> AST.zext 1<rt>)
  !!ir (pc := !.ctxt R.PC |> AST.sext 32<rt>)
  !!ir (delayedPC := (!.ctxt R.PC .+ numI32 2) |> AST.sext 32<rt>)
  !!ir (label := (AST.sext 8<rt> disp) << AST.b1)
  !!ir (temp := (pc .+ label .+ numI32 4) |> AST.zext 32<rt>)
  !!ir (delayedPC := AST.ite (t == AST.b1) (temp) (delayedPC))
  !!ir (!.ctxt R.PC .+ numI32 2 := AST.xtlo 32<rt> delayedPC)
  delaySlot.Clear()
  !>ir len

let bts ins len ctxt =
  let ir = IRBuilder (32)
  if (delaySlot.Count = 1) then (illSlot1 ins ir len ctxt)
  else
    !<ir ins.Address len
    delaySlot.Add (btsHelper ir ins len ctxt)
    !>ir len

let clrmac ins len ctxt =
  let ir = IRBuilder (8)
  let struct (macl, mach) = tmpVars2 ir 1<rt>
  !<ir ins.Address len
  !!ir (macl := AST.b0)
  !!ir (mach := AST.b0)
  !!ir (!.ctxt R.MACL := AST.zext 32<rt> macl)
  !!ir (!.ctxt R.MACH := AST.zext 32<rt> mach)
  !>ir len

let clrs ins len ctxt =
  let ir = IRBuilder (4)
  let s = !+ir 1<rt>
  !<ir ins.Address len
  !!ir (s := AST.b0)
  !!ir (!.ctxt R.S := AST.extract s 1<rt> 1)
  !>ir len

let clrt ins len ctxt =
  let ir = IRBuilder (4)
  let t = !+ir 1<rt>
  !<ir ins.Address len
  !!ir (t := AST.b0)
  !!ir (!.ctxt R.T := AST.extract t 1<rt> 1)
  !>ir len

let cmpeq ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  match src.E with
  | Num n ->
    let ir = IRBuilder 8
    let r0 = !+ir 32<rt>
    let imm = !+ir 8<rt>
    let t = !+ir 1<rt>
    !<ir ins.Address len
    !!ir (r0 := AST.sext 32<rt> (!.ctxt R.R0))
    !!ir (imm := AST.sext 8<rt> (AST.num n))
    !!ir (t := r0 == imm)
    !!ir (!.ctxt R.T := AST.extract t 1<rt> 1)
    !>ir len
  | Var (_, _, r) ->
    let ir = IRBuilder (8)
    let struct (op1, op2) = tmpVars2 ir 32<rt>
    let t = !+ir 1<rt>
    !<ir ins.Address len
    !!ir (op1 := (r |> Register.ofString |> !.ctxt |> AST.sext 32<rt>))
    !!ir (op2 := AST.sext 32<rt> dst)
    !!ir (t := op2 == op1)
    !!ir (!.ctxt R.T := AST.extract t 1<rt> 1)
    !>ir len
  | _ -> Terminator.impossible()

let cmpge ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (8)
  let struct (op1, op2) = tmpVars2 ir 32<rt>
  let t = !+ir 1<rt>
  !<ir ins.Address len
  !!ir (op1 := src |> AST.sext 32<rt>)
  !!ir (op2 := AST.sext 32<rt> dst)
  !!ir (t := op2 ?>= op1)
  !!ir (!.ctxt R.T := AST.extract t 1<rt> 1)
  !>ir len

let cmpgt ins len ctxt=
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (8)
  let struct (op1, op2) = tmpVars2 ir 32<rt>
  let t = !+ir 1<rt>
  !<ir ins.Address len
  !!ir (op1 := src |> AST.sext 32<rt>)
  !!ir (op2 := AST.sext 32<rt> dst)
  !!ir (t := op2 ?> op1)
  !!ir (!.ctxt R.T := AST.extract t 1<rt> 1)
  !>ir len

let cmphi ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (8)
  let struct (op1, op2) = tmpVars2 ir 32<rt>
  let t = !+ir 1<rt>
  !<ir ins.Address len
  !!ir (op1 := src |> AST.zext 32<rt>)
  !!ir (op2 := AST.zext 32<rt> dst)
  !!ir (t := op2 .> op1)
  !!ir (!.ctxt R.T := AST.extract t 1<rt> 1)
  !>ir len

let cmphs ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (8)
  let struct (op1, op2) = tmpVars2 ir 32<rt>
  let t = !+ir 1<rt>
  !<ir ins.Address len
  !!ir (op1 := src |> AST.zext 32<rt>)
  !!ir (op2 := AST.zext 32<rt> dst)
  !!ir (t := op2 .>= op1)
  !!ir (!.ctxt R.T := AST.extract t 1<rt> 1)
  !>ir len

let cmppl ins len ctxt =
  let dst = trsOneOpr ins ctxt
  let ir = IRBuilder (4)
  let op1 = !+ir 32<rt>
  let t = !+ir 1<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.sext 32<rt> dst)
  !!ir (t := op1 ?> AST.b0)
  !!ir (!.ctxt R.T := AST.extract t 1<rt> 1)
  !>ir len

let cmppz ins len ctxt =
  let dst = trsOneOpr ins ctxt
  let ir = IRBuilder (8)
  let op1 = !+ir 32<rt>
  let t = !+ir 1<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.sext 32<rt> dst)
  !!ir (t := op1 ?>= AST.b0)
  !!ir (!.ctxt R.T := AST.extract t 1<rt> 1)
  !>ir len

let cmpstr ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  let struct (op1, op2, temp) = tmpVars3 ir 32<rt>
  let t = !+ir 1<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.sext 32<rt> src)
  !!ir (op2 := AST.sext 32<rt> dst)
  !!ir (temp := op1 <+> op2)
  !!ir (t := (AST.extract temp 8<rt> 1) == AST.b0)
  !!ir (t := ((AST.extract temp 8<rt> 8) == AST.b0) .| t)
  !!ir (t := ((AST.extract temp 8<rt> 16) == AST.b0) .| t)
  !!ir (t := ((AST.extract temp 8<rt> 24) == AST.b0) .| t)
  !!ir (!.ctxt R.T := AST.extract t 1<rt> 1)
  !>ir len

let div0s ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  let struct (op1, op2) = tmpVars2 ir 32<rt>
  let struct (q, m, t) = tmpVars3 ir 1<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.sext 32<rt> src)
  !!ir (op2 := AST.sext 32<rt> dst)
  !!ir (q := AST.extract op2 1<rt> 31)
  !!ir (m := AST.extract op1 1<rt> 31)
  !!ir (t := m <+> q)
  !!ir (!.ctxt R.Q := AST.extract q 1<rt> 1)
  !!ir (!.ctxt R.M := AST.extract m 1<rt> 1)
  !!ir (!.ctxt R.T := AST.extract t 1<rt> 1)
  !>ir len

let div0u ins len ctxt =
  let ir = IRBuilder (8)
  let struct (q, m, t) = tmpVars3 ir 1<rt>
  !<ir ins.Address len
  !!ir (q := AST.b0)
  !!ir (m := AST.b0)
  !!ir (t := AST.b0)
  !!ir (!.ctxt R.Q := AST.extract q 1<rt> 1)
  !!ir (!.ctxt R.M := AST.extract m 1<rt> 1)
  !!ir (!.ctxt R.T := AST.extract t 1<rt> 1)
  !>ir len

let div1 ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  let struct (q, m, t) = tmpVars3 ir 1<rt>
  let oldq = !+ir 1<rt>
  let struct (op1, op2) = tmpVars2 ir 32<rt>
  !<ir ins.Address len
  !!ir (q := !.ctxt R.Q |> AST.zext 1<rt>)
  !!ir (m := !.ctxt R.M |> AST.zext 1<rt>)
  !!ir (t := !.ctxt R.T |> AST.zext 1<rt>)
  !!ir (op1 := AST.sext 32<rt> src |> AST.zext 32<rt>)
  !!ir (op2 := AST.sext 32<rt> dst |> AST.zext 32<rt>)
  !!ir (oldq := q)
  !!ir (q := AST.extract op2 1<rt> 31)
  !!ir (op2 := (op2 << AST.b1) .| t)
  !!ir (op2 := AST.ite (oldq == m) (op2 .- op1) (op2 .+ op1))
  !!ir (q := AST.extract op2 1<rt> 32 |> AST.xor (q <+> m))
  !!ir (t:= AST.b1 .- (q <+> m))
  !!ir (dst := AST.xtlo 32<rt> op2)
  !!ir (!.ctxt R.Q := AST.extract q 1<rt> 1)
  !!ir (!.ctxt R.T := AST.extract t 1<rt> 1)
  !>ir len

let dmulsl ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  let struct (op1, op2) = tmpVars2 ir 32<rt>
  let mac = !+ir 64<rt>
  let struct (macl, mach) = tmpVars2 ir 32<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.sext 32<rt> src)
  !!ir (op2 := AST.sext 32<rt> dst)
  !!ir (mac := op2 .* op1)
  !!ir (macl := mac)
  !!ir (mach := mac >> numI32 32)
  !!ir (!.ctxt R.MACL := AST.zext 32<rt> macl)
  !!ir (!.ctxt R.MACH := AST.zext 32<rt> mach)
  !>ir len

let dmulul ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  let struct (op1, op2) = tmpVars2 ir 32<rt>
  let mac = !+ir 64<rt>
  let struct (macl, mach) = tmpVars2 ir 32<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.sext 32<rt> src |> AST.zext 32<rt>)
  !!ir (op2 := AST.sext 32<rt> dst |> AST.zext 32<rt>)
  !!ir (mac := op2 .* op1)
  !!ir (macl := mac)
  !!ir (mach := mac >> numI32 32)
  !!ir (!.ctxt R.MACL := AST.zext 32<rt> macl)
  !!ir (!.ctxt R.MACH := AST.zext 32<rt> mach)
  !>ir len

let dt ins len ctxt =
  let dst = trsOneOpr ins ctxt
  let ir = IRBuilder (8)
  let op1 = !+ir 32<rt>
  let t = !+ir 1<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.sext 32<rt> dst)
  !!ir (op1 := op1 .- AST.b1)
  !!ir (t := op1 == AST.b0)
  !!ir (dst := AST.xtlo 32<rt> op1)
  !!ir (!.ctxt R.T := AST.extract t 1<rt> 1)
  !>ir len

let extsb ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (8)
  let struct (op1, op2) = tmpVars2 ir 8<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.sext 8<rt> src)
  !!ir (op2 := op1)
  !!ir (dst := AST.xtlo 32<rt> op2)
  !>ir len

let extsw ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (8)
  let struct (op1, op2) = tmpVars2 ir 16<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.sext 16<rt> src)
  !!ir (op2 := op1)
  !!ir (dst := AST.xtlo 32<rt> op2)
  !>ir len

let extub ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (8)
  let struct (op1, op2) = tmpVars2 ir 8<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.zext 8<rt> src)
  !!ir (op2 := op1)
  !!ir (dst := AST.xtlo 32<rt> op2)
  !>ir len

let extuw ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (8)
  let struct (op1, op2) = tmpVars2 ir 16<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.zext 16<rt> src)
  !!ir (op2 := op1)
  !!ir (dst := AST.xtlo 32<rt> op2)
  !>ir len

let fabs ins len ctxt =
  let dst = trsOneOpr ins ctxt
  let ir = IRBuilder (16)
  match dst.E with
  | Var (_, _, s) ->
    if s.StartsWith "fr" then
      let struct (sr, op1) = tmpVars2 ir 32<rt>
      !<ir ins.Address len
      !!ir (sr := !.ctxt R.SR |> AST.zext 32<rt>)
      !!ir (op1 := dst)
      fpudisChecker ir ctxt
      !!ir (op1 := AST.ite (AST.fle op1 AST.b0) (AST.neg op1) (op1))
      !!ir (dst := op1)
      !>ir len
    else
      let sr = !+ir 32<rt>
      let op1 = !+ir 64<rt>
      !<ir ins.Address len
      !!ir (sr := !.ctxt R.SR |> AST.zext 32<rt>)
      !!ir (op1 := dst)
      fpudisChecker ir ctxt
      !!ir (op1 := AST.ite (AST.fle op1 AST.b0) (AST.neg op1) (op1))
      !!ir (dst := op1)
      !>ir len
  | _ -> Terminator.impossible()

let fadd ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  match src.E with
  | Var (_, _, s) ->
    if s.StartsWith "fr" then
      let struct (sr, fps, op1, op2) = tmpVars4 ir 32<rt>
      !<ir ins.Address len
      !!ir (sr := !.ctxt R.SR |> AST.zext 32<rt>)
      !!ir (fps := !.ctxt R.FPSCR |> AST.zext 32<rt>)
      !!ir (op1 := src)
      !!ir (op2 := dst)
      fpudisChecker ir ctxt
      !!ir (op2 := AST.fadd op1 op2)
      if ((fpuCheck fps 16) && (fpuCheck fps 11)) then fpuExc ir ctxt
      elif (fpuCheck fps 17) then fpuExc ir ctxt
      elif ((fpuCheck fps 7) || (fpuCheck fps 8) || (fpuCheck fps 9)) then
        fpuExc ir ctxt
      else ()
      !!ir (dst := op2)
      !!ir (!.ctxt R.FPSCR := AST.zext 32<rt> fps)
      !>ir len
    else
      let struct (sr, fps) = tmpVars2 ir 32<rt>
      let struct (op1, op2) = tmpVars2 ir 64<rt>
      !<ir ins.Address len
      !!ir (sr := !.ctxt R.SR |> AST.zext 32<rt>)
      !!ir (fps := !.ctxt R.FPSCR |> AST.zext 32<rt>)
      !!ir (op1 := src)
      !!ir (op2 := dst)
      fpudisChecker ir ctxt
      !!ir (op2 := AST.fadd op1 op2)
      if ((fpuCheck fps 16) && (fpuCheck fps 11)) then fpuExc ir ctxt
      elif (fpuCheck fps 17) then fpuExc ir ctxt
      elif ((fpuCheck fps 7) || (fpuCheck fps 8) || (fpuCheck fps 9)) then
        fpuExc ir ctxt
      else ()
      !!ir (dst := op2)
      !!ir (!.ctxt R.FPSCR := AST.zext 32<rt> fps)
      !>ir len
  | _ -> Terminator.impossible()

let fcmpeq ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  let t = !+ir 1<rt>
  match src.E with
  | Var (_, _, s) ->
    if s.StartsWith "fr" then
      let struct (sr, fps, op1, op2) = tmpVars4 ir 32<rt>
      !<ir ins.Address len
      !!ir (sr := !.ctxt R.SR |> AST.zext 32<rt>)
      !!ir (fps := !.ctxt R.FPSCR |> AST.zext 32<rt>)
      !!ir (op1 := src)
      !!ir (op2 := dst)
      fpudisChecker ir ctxt
      !!ir (t := AST.ite (AST.neg ((AST.flt op1 op2) .|
           (AST.fgt op1 op2))) (AST.b1) (AST.b0))
      if ((fpuCheck fps 16) && (fpuCheck fps 11)) then fpuExc ir ctxt
      else ()
      !!ir (dst := op2)
      !!ir (!.ctxt R.FPSCR := AST.zext 32<rt> fps)
      !!ir (!.ctxt R.T := AST.extract t 1<rt> 1)
      !>ir len
    else
      let struct (sr, fps) = tmpVars2 ir 32<rt>
      let struct (op1, op2) = tmpVars2 ir 64<rt>
      !<ir ins.Address len
      !!ir (sr := !.ctxt R.SR |> AST.zext 32<rt>)
      !!ir (fps := !.ctxt R.FPSCR |> AST.zext 32<rt>)
      !!ir (op1 := src)
      !!ir (op2 := dst)
      fpudisChecker ir ctxt
      !!ir (t := AST.ite (AST.neg ((AST.flt op1 op2) .|
           (AST.fgt op1 op2))) (AST.b1) (AST.b0))
      if ((fpuCheck fps 16) && (fpuCheck fps 11)) then fpuExc ir ctxt
      else ()
      !!ir (dst := op2)
      !!ir (!.ctxt R.FPSCR := AST.zext 32<rt> fps)
      !!ir (!.ctxt R.T := AST.extract t 1<rt> 1)
      !>ir len
  | _ -> Terminator.impossible()

let fcmpgt ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  let t = !+ir 1<rt>
  match src.E with
  | Var (_, _, s) ->
    if s.StartsWith "fr" then
      let struct (sr, fps, op1, op2) = tmpVars4 ir 32<rt>
      !<ir ins.Address len
      !!ir (sr := !.ctxt R.SR |> AST.zext 32<rt>)
      !!ir (fps := !.ctxt R.FPSCR |> AST.zext 32<rt>)
      !!ir (op1 := src)
      !!ir (op2 := dst)
      fpudisChecker ir ctxt
      !!ir (t := AST.ite (AST.fgt op1 op2) (AST.b1) (AST.b0))
      if ((fpuCheck fps 16) && (fpuCheck fps 11)) then fpuExc ir ctxt
      else ()
      !!ir (dst := op2)
      !!ir (!.ctxt R.FPSCR := AST.zext 32<rt> fps)
      !!ir (!.ctxt R.T := AST.extract t 1<rt> 1)
      !>ir len
    else
      let struct (sr, fps) = tmpVars2 ir 32<rt>
      let struct (op1, op2) = tmpVars2 ir 64<rt>
      !<ir ins.Address len
      !!ir (sr := !.ctxt R.SR |> AST.zext 32<rt>)
      !!ir (fps := !.ctxt R.FPSCR |> AST.zext 32<rt>)
      !!ir (op1 := src)
      !!ir (op2 := dst)
      fpudisChecker ir ctxt
      !!ir (t := AST.ite (AST.fgt op1 op2) (AST.b1) (AST.b0))
      if ((fpuCheck fps 16) && (fpuCheck fps 11)) then fpuExc ir ctxt
      else ()
      !!ir (dst := op2)
      !!ir (!.ctxt R.FPSCR := AST.zext 32<rt> fps)
      !!ir (!.ctxt R.T := AST.extract t 1<rt> 1)
      !>ir len
  | _ -> Terminator.impossible()

let fcnvds ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  let struct (sr, fps, fpul) = tmpVars3 ir 32<rt>
  let op1 = !+ir 64<rt>
  !<ir ins.Address len
  !!ir (sr := !.ctxt R.SR |> AST.zext 32<rt>)
  !!ir (fps := !.ctxt R.FPSCR |> AST.zext 32<rt>)
  !!ir (op1 := src)
  fpudisChecker ir ctxt
  !!ir (fpul := AST.cast CastKind.FloatCast 32<rt> op1)
  !!ir (!.ctxt R.FPSCR := AST.zext 32<rt> fps)
  !!ir (!.ctxt R.FPUL := AST.zext 32<rt> fpul)
  !>ir len

let fcnvsd ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  let struct (sr, fps, fpul) = tmpVars3 ir 32<rt>
  let op1 = !+ir 64<rt>
  !<ir ins.Address len
  !!ir (sr := !.ctxt R.SR |> AST.zext 32<rt>)
  !!ir (fps := !.ctxt R.FPSCR |> AST.zext 32<rt>)
  !!ir (op1 := src)
  fpudisChecker ir ctxt
  !!ir (fpul := AST.cast CastKind.FloatCast 64<rt> op1)
  !!ir (!.ctxt R.FPSCR := AST.zext 32<rt> fps)
  !!ir (!.ctxt R.FPUL := AST.zext 32<rt> fpul)
  !>ir len

let fdiv ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  let struct (sr, fps) = tmpVars2 ir 32<rt>
  let struct (op1, op2) =
    match src.E with
    | Var (_, _, r) ->
      if r.StartsWith "dr" then
        tmpVars2 ir 64<rt>
      else
        tmpVars2 ir 32<rt>
    | _ -> Terminator.impossible()
  !<ir ins.Address len
  !!ir (sr := !.ctxt R.SR |> AST.zext 32<rt>)
  !!ir (fps := !.ctxt R.FPSCR |> AST.zext 32<rt>)
  !!ir (op1 := src)
  !!ir (op2 := dst)
  fpudisChecker ir ctxt
  !!ir (op2 := AST.fdiv op2 op1)
  if (fpuCheck fps 16) && (fpuCheck fps 11) then (fpuExc ir ctxt) else ()
  if (fpuCheck fps 15) && (fpuCheck fps 10) then (fpuExc ir ctxt) else ()
  if (fpuCheck fps 17) then fpuExc ir ctxt else ()
  if (fpuCheck fps 7) || (fpuCheck fps 8) || (fpuCheck fps 9) then
    (fpuExc ir ctxt)
  else ()
  !!ir (dst := op2)
  !!ir (!.ctxt R.FPSCR := AST.zext 32<rt> fps)
  !>ir len

let fipr = function
  | _ -> Terminator.futureFeature()

let fldi0 ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  let struct (sr, op1) = tmpVars2 ir 32<rt>
  !<ir ins.Address len
  !!ir (sr := !.ctxt R.SR |> AST.zext 32<rt>)
  fpudisChecker ir ctxt
  !!ir (op1 := numI32 0x00000000)
  !!ir (dst := AST.zext 32<rt> op1)
  !>ir len

let fldi1 ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  let struct (sr, op1) = tmpVars2 ir 32<rt>
  !<ir ins.Address len
  !!ir (sr := !.ctxt R.SR |> AST.zext 32<rt>)
  fpudisChecker ir ctxt
  !!ir (op1 := numI32 0x3F800000)
  !!ir (dst := AST.zext 32<rt> op1)
  !>ir len

let flds ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  let struct (sr, op1, fpul) = tmpVars3 ir 32<rt>
  !<ir ins.Address len
  !!ir (sr := !.ctxt R.SR |> AST.zext 32<rt>)
  !!ir (op1 := src)
  fpudisChecker ir ctxt
  !!ir (fpul := op1)
  !!ir (!.ctxt R.FPUL := AST.zext 32<rt> fpul)
  !>ir len

let ``float`` ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  let mode =
    match dst.E with
    | Var (_, _, r) ->
        if r.StartsWith "DR" then 64<rt> else 32<rt>
    | _ -> Terminator.impossible()
  let struct (fpul, sr, fps, op1) = tmpVars4 ir 32<rt>
  !<ir ins.Address len
  !!ir (fpul := !.ctxt R.FPUL |> AST.sext 32<rt>)
  !!ir (sr := !.ctxt R.SR |> AST.zext 32<rt>)
  !!ir (fps := !.ctxt R.FPSCR |> AST.zext 32<rt>)
  fpudisChecker ir ctxt
  !!ir (op1 := AST.cast CastKind.SIntToFloat mode fpul)
  !!ir (dst := op1)
  !>ir len

let fmac ins len ctxt =
  let struct (fr, src, dst) = trsThreeOpr ins ctxt
  let ir = IRBuilder (16)
  let struct (sr, fps, fr0) = tmpVars3 ir 32<rt>
  let struct (op1, op2) = tmpVars2 ir 32<rt>
  !<ir ins.Address len
  !!ir (sr := !.ctxt R.SR |> AST.zext 32<rt>)
  !!ir (fps := !.ctxt R.FPSCR |> AST.zext 32<rt>)
  !!ir (fr0 := fr)
  !!ir (op1 := src)
  !!ir (op2 := dst)
  fpudisChecker ir ctxt
  !!ir (op2 := AST.fmul fr0 op1 |> AST.fadd op2)
  if (fpuCheck fps 16) && (fpuCheck fps 11) then (fpuExc ir ctxt) else ()
  if (fpuCheck fps 17) then fpuExc ir ctxt else ()
  if (fpuCheck fps 7) || (fpuCheck fps 8) || (fpuCheck fps 9) then
    (fpuExc ir ctxt)
  else ()
  !!ir (dst := op2)
  !!ir (!.ctxt R.FPSCR := AST.zext 32<rt> fps)
  !>ir len

let fmov ins len = function
 | _ -> Terminator.futureFeature()
  (*
let fmov ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  let struct (sr, op1, op2) = tmpVars3 ir 32<rt>
  !<ir ins.Address len
  !!ir (sr := !.ctxt R.SR |> AST.zext 32<rt>)
  !!ir (op1 := src)
  fpudisChecker ir ctxt
  !!ir (op2 := op1)
  !!ir (dst := op2)
  !>ir len
  match ins.Operands with
  | TwoOperands(OpReg (Regdir r1), OpReg (Regdir r2))//dr,dr
  | TwoOperands(OpReg (Regdir r1), OpReg (Regdir r2))//dr,xd
  | TwoOperands(OpReg (Regdir r1), OpReg (RegIndir r2))
  | TwoOperands(OpReg (Regdir r1), OpReg (PreDec r2))
  | TwoOperands(OpReg (Regdir r1), OpReg (IdxIndir r2))
  | TwoOperands(OpReg (Regdir r1), OpReg (Regdir r2))//xd,dr
  | TwoOperands(OpReg (Regdir r1), OpReg (Regdir r2))//xd,xd
  | TwoOperands(OpReg (Regdir r1), OpReg (RegIndir r2))
  | TwoOperands(OpReg (Regdir r1), OpReg (PreDec r2))
  | TwoOperands(OpReg (Regdir r1), OpReg (IdxIndir r2))
  | TwoOperands(OpReg (RegIndir r1), OpReg (Regdir r2))
  | TwoOperands(OpReg (PostInc r1), OpReg (Regdir r2))
  | TwoOperands(OpReg (IdxIndir r1), OpReg (Regdir r2))
  | TwoOperands(OpReg (RegIndir r1), OpReg (Regdir r2))
  | TwoOperands(OpReg (PostInc r1), OpReg (Regdir r2))
  | TwoOperands(OpReg (IdxIndir r1), OpReg (Regdir r2))
  *)
let fmovs ins len = function
 | _ -> Terminator.futureFeature()
(*
let fmovs ins len ctxt =
  match ins.Operands with
  | TwoOperands(OpReg (Regdir r1), OpReg (Regdir r2))
  | TwoOperands(OpReg (Regdir r1), OpReg (RegIndir r2))
  | TwoOperands(OpReg (Regdir r1), OpReg (PreDec r2))
  | TwoOperands(OpReg (Regdir r1), OpReg (IdxIndir r2))
  | TwoOperands(OpReg (RegIndir r1), OpReg (Regdir r2))
  | TwoOperands(OpReg (PostInc r1), OpReg (Regdir r2))
  | TwoOperands(OpReg (IdxIndir r1), OpReg (Regdir r2))
*)
let fmul ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  let struct (sr, fps) = tmpVars2 ir 32<rt>
  let struct (op1, op2) =
    match src.E with
    | Var (_, _, r) ->
      if r.StartsWith "FR" then tmpVars2 ir 32<rt>
      else
        tmpVars2 ir 64<rt>
    | _ -> Terminator.impossible()
  !<ir ins.Address len
  !!ir (sr := !.ctxt R.SR |> AST.zext 32<rt>)
  !!ir (fps := !.ctxt R.FPSCR |> AST.zext 32<rt>)
  !!ir (op1 := src)
  !!ir (op2 := dst)
  fpudisChecker ir ctxt
  !!ir (op2 := AST.fmul op1 op2)
  if (fpuCheck fps 16) && (fpuCheck fps 11) then (fpuExc ir ctxt) else ()
  if (fpuCheck fps 17) then fpuExc ir ctxt else ()
  if (fpuCheck fps 7) || (fpuCheck fps 8) || (fpuCheck fps 9) then
    (fpuExc ir ctxt)
  else ()
  !!ir (dst := op2)
  !!ir (!.ctxt R.FPSCR := AST.zext 32<rt> fps)
  !>ir len

let fneg ins len ctxt =
  let (dst) = trsOneOpr ins ctxt
  let ir = IRBuilder (16)
  let sr = !+ir 32<rt>
  let fps = !+ir 32<rt>
  let mode =
    match dst.E with
    | Var (_, _, r) -> r.StartsWith "DR"
    | _ -> Terminator.impossible()
  let op1 = if mode then !+ir 64<rt> else !+ir 32<rt>
  !<ir ins.Address len
  !!ir (sr := !.ctxt R.SR |> AST.zext 32<rt>)
  if mode then () else (!!ir (fps := !.ctxt R.FPSCR |> AST.zext 32<rt>))
  !!ir (op1 := dst)
  fpudisChecker ir ctxt
  !!ir (op1 := AST.fsub AST.b0 op1)
  !!ir (dst := op1)
  !>ir len

let frchg ins len ctxt =
  let ir = IRBuilder (16)
  let sr = !+ir 32<rt>
  let fr = !+ir 1<rt>
  !<ir ins.Address len
  !!ir (sr := !.ctxt R.SR |> AST.zext 32<rt>)
  !!ir (fr := !.ctxt R.FPSCR_FR |> AST.zext 1<rt>)
  fpudisChecker ir ctxt
  !!ir (fr := fr <+> AST.b1)
  !!ir (!.ctxt R.FPSCR_FR := AST.extract fr 1<rt> 1)
  !>ir len

let fschg ins len ctxt =
  let ir = IRBuilder (16)
  let sr = !+ir 32<rt>
  let fr = !+ir 1<rt>
  !<ir ins.Address len
  !!ir (sr := !.ctxt R.SR |> AST.zext 32<rt>)
  !!ir (fr := !.ctxt R.FPSCR_SZ |> AST.zext 1<rt>)
  fpudisChecker ir ctxt
  !!ir (fr := fr <+> AST.b1)
  !!ir (!.ctxt R.FPSCR_SZ := AST.extract fr 1<rt> 1)
  !>ir len

let fsqrt ins len ctxt =
  let dst = trsOneOpr ins ctxt
  let ir = IRBuilder (16)
  let struct (sr, fps) = tmpVars2 ir 32<rt>
  let mode =
    match dst.E with
    | Var (_, _, r) -> r.StartsWith "DR"
    | _ -> Terminator.impossible()
  let op1 = if mode then !+ir 64<rt> else !+ir 32<rt>
  !<ir ins.Address len
  !!ir (sr := !.ctxt R.SR |> AST.zext 32<rt>)
  !!ir (fps := !.ctxt R.FPSCR |> AST.zext 32<rt>)
  !!ir (op1 := dst)
  fpudisChecker ir ctxt
  !!ir (op1 := AST.fsqrt op1)
  if (fpuCheck fps 16) && (fpuCheck fps 11) then (fpuExc ir ctxt) else ()
  if (fpuCheck fps 17) then fpuExc ir ctxt else ()
  if (fpuCheck fps 7) then fpuExc ir ctxt else ()
  !!ir (dst := op1)
  !!ir (!.ctxt R.FPSCR := AST.zext 32<rt> fps)
  !>ir len

let fsts ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (8)
  let struct (sr, fpul, op1) = tmpVars3 ir 32<rt>
  !<ir ins.Address len
  !!ir (sr := !.ctxt R.SR |> AST.zext 32<rt>)
  !!ir (fpul := !.ctxt R.FPUL |> AST.sext 32<rt>)
  fpudisChecker ir ctxt
  !!ir (op1 := fpul)
  !!ir (dst := op1)
  !>ir len

let fsub ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  let mode =
    match dst.E with
    | Var (_, _, r) -> r.StartsWith "DR"
    | _ -> Terminator.impossible()
  let struct (sr, fps) = tmpVars2 ir 32<rt>
  let struct (op1, op2) =
    if mode then tmpVars2 ir 64<rt> else tmpVars2 ir 32<rt>
  !<ir ins.Address len
  !!ir (sr := !.ctxt R.SR |> AST.zext 32<rt>)
  !!ir (fps := !.ctxt R.FPSCR |> AST.zext 32<rt>)
  !!ir (op1 := src)
  !!ir (op2 := dst)
  fpudisChecker ir ctxt
  !!ir (op2 := AST.fsub op2 op1)
  if (fpuCheck fps 16) && (fpuCheck fps 11) then (fpuExc ir ctxt) else ()
  if (fpuCheck fps 17) then fpuExc ir ctxt else ()
  if (fpuCheck fps 7) || (fpuCheck fps 8) || (fpuCheck fps 9) then
    (fpuExc ir ctxt)
  else ()
  !!ir (dst := op2)
  !!ir (!.ctxt R.FPSCR := AST.zext 32<rt> fps)
  !>ir len

let ftrc ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  let struct (sr, fps, fpul) = tmpVars3 ir 32<rt>
  let mode =
    match dst.E with
    | Var (_, _, r) -> r.StartsWith "DR"
    | _ -> Terminator.impossible()
  let op1 = if mode then !+ir 64<rt> else !+ir 32<rt>
  !<ir ins.Address len
  !!ir (sr := !.ctxt R.SR |> AST.zext 32<rt>)
  !!ir (fps := !.ctxt R.FPSCR |> AST.zext 32<rt>)
  !!ir (op1 := src)
  fpudisChecker ir ctxt
  // FTRC
  if (fpuCheck fps 16) && (fpuCheck fps 11) then (fpuExc ir ctxt) else ()
  !!ir (!.ctxt R.FPUL := AST.zext 32<rt> fpul)
  !!ir (!.ctxt R.FPSCR := AST.zext 32<rt> fps)
  !>ir len

let ftrv ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  let struct (sr, fps, xmtrx, op1) = tmpVars4 ir 32<rt>
  !<ir ins.Address len
  !!ir (sr := !.ctxt R.SR |> AST.zext 32<rt>)
  !!ir (fps := !.ctxt R.FPSCR |> AST.zext 32<rt>)
  !!ir (xmtrx := src)
  !!ir (op1 := dst)
  fpudisChecker ir ctxt
  // !!ir (op1 :=) FTRV_S
  if (fpuCheck fps 7) || (fpuCheck fps 8)
    || (fpuCheck fps 9) || (fpuCheck fps 11) then fpuExc ir ctxt else ()
  !!ir (dst := op1)
  !!ir (!.ctxt R.FPSCR := AST.zext 32<rt> fps)
  !>ir len

let jmp ins len ctxt =
  let dst = trsOneOpr ins ctxt
  let ir = IRBuilder (8)
  let struct (op1, target, delayedPC) = tmpVars3 ir 32<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.sext 32<rt> dst)
  if (delaySlot.Count = 1) then illSlot2 ir len ctxt
  else
    !!ir (target := op1)
    !!ir (delayedPC := target .& (AST.b1 |> AST.neg))
    !!ir (!.ctxt R.PC := AST.xtlo 32<rt> delayedPC)
    !>ir len

let jsr ins len ctxt =
  let dst = trsOneOpr ins ctxt
  let ir = IRBuilder (8)
  let struct (pc, op1, delayedPR) = tmpVars3 ir 32<rt>
  let struct (target, delayedPC) = tmpVars2 ir 32<rt>
  !<ir ins.Address len
  !!ir (pc := R.PC |> !.ctxt |> AST.sext 32<rt>)
  !!ir (op1 := AST.sext 32<rt> dst)
  if (delaySlot.Count = 1) then illSlot2 ir len ctxt
  else
    !!ir (delayedPR := pc .+ numI32 4)
    !!ir (target := op1)
    !!ir (delayedPC := target .& (AST.b1 |> AST.neg))
    !!ir (!.ctxt R.PR := AST.xtlo 32<rt> delayedPR)
    !!ir (!.ctxt R.PC := AST.xtlo 32<rt> delayedPC)
    !>ir len

let ldc ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (8)
  match dst.E with
  | Var (_, _, s) ->
    match s with
    | "gbr" ->
      let struct (op1, gbr) = tmpVars2 ir 32<rt>
      !<ir ins.Address len
      !!ir (op1 := AST.sext 32<rt> src)
      !!ir (gbr := op1)
      !!ir (!.ctxt R.GBR := AST.xtlo 32<rt> gbr)
      !>ir len
    | "sr" ->
      let struct (op1, sr) = tmpVars2 ir 32<rt>
      let md = !+ir 1<rt>
      !<ir ins.Address len
      !!ir (md := R.MD |> !.ctxt |> AST.zext 1<rt>)
      if bv1Check md then () else resinst ir ctxt
      !!ir (op1 := AST.sext 32<rt> src)
      !!ir (sr := op1)
      !!ir (!.ctxt R.SR := AST.xtlo 32<rt> sr)
      !>ir len
    | "vbr" ->
      let struct (op1, vbr) = tmpVars2 ir 32<rt>
      let md = !+ir 1<rt>
      !<ir ins.Address len
      !!ir (md := R.MD |> !.ctxt |> AST.zext 1<rt>)
      if bv1Check md then () else resinst ir ctxt
      !!ir (op1 := AST.sext 32<rt> src)
      !!ir (vbr := op1)
      !!ir (!.ctxt R.VBR := AST.xtlo 32<rt> vbr)
      !>ir len
    | "ssr" ->
      let struct (op1, ssr) = tmpVars2 ir 32<rt>
      let md = !+ir 1<rt>
      !<ir ins.Address len
      !!ir (md := R.MD |> !.ctxt |> AST.zext 1<rt>)
      if bv1Check md then () else resinst ir ctxt
      !!ir (op1 := AST.sext 32<rt> src)
      !!ir (ssr := op1)
      !!ir (!.ctxt R.SSR := AST.xtlo 32<rt> ssr)
      !>ir len
    | "spc" ->
      let struct (op1, spc) = tmpVars2 ir 32<rt>
      let md = !+ir 1<rt>
      !<ir ins.Address len
      !!ir (md := R.MD |> !.ctxt |> AST.zext 1<rt>)
      if bv1Check md then () else resinst ir ctxt
      !!ir (op1 := AST.sext 32<rt> src)
      !!ir (spc := op1)
      !!ir (!.ctxt R.SPC := AST.xtlo 32<rt> spc)
      !>ir len
    | "dbr" ->
      let struct (op1, dbr) = tmpVars2 ir 32<rt>
      let md = !+ir 1<rt>
      !<ir ins.Address len
      !!ir (md := R.MD |> !.ctxt |> AST.zext 1<rt>)
      if bv1Check md then () else resinst ir ctxt
      !!ir (op1 := AST.sext 32<rt> src)
      !!ir (dbr := op1)
      !!ir (!.ctxt R.DBR := AST.xtlo 32<rt> dbr)
      !>ir len
    | _ ->
      let struct (op1, rnBank) = tmpVars2 ir 32<rt>
      let md = !+ir 1<rt>
      !<ir ins.Address len
      !!ir (md := R.MD |> !.ctxt |> AST.zext 1<rt>)
      if bv1Check md then () else resinst ir ctxt
      !!ir (op1 := AST.sext 32<rt> src)
      !!ir (rnBank := op1)
      !!ir (dst := AST.xtlo 32<rt> rnBank)
      !>ir len
  | _ -> Terminator.impossible()

let ldcl ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  match src.E with
  | Var (_, _, s) ->
    match s with
    | "gbr" ->
      let struct (op1, address, gbr) = tmpVars3 ir 32<rt>
      !<ir ins.Address len
      !!ir (op1 := AST.sext 32<rt> src)
      !!ir (address := AST.zext 32<rt> op1)
      !!ir (gbr := address |> AST.loadLE 32<rt> |> AST.zext 32<rt>)
      !!ir (op1 := op1 .+ numI32 4)
      !!ir (src := AST.xtlo 32<rt> op1)
      !!ir (!.ctxt R.GBR := AST.xtlo 32<rt> gbr)
      !>ir len
    | "sr" ->
      let md = !+ir 1<rt>
      let struct (op1, address, sr) = tmpVars3 ir 32<rt>
      !<ir ins.Address len
      !!ir (md := !.ctxt R.MD |> AST.zext 1<rt>)
      if bv1Check md then () else resinst ir ctxt
      !!ir (op1 := AST.sext 32<rt> src)
      !!ir (address := AST.zext 32<rt> op1)
      !!ir (sr := AST.loadLE 32<rt> address |> AST.sext 32<rt>)
      !!ir (op1 := op1 .+ numI32 4)
      !!ir (src := AST.xtlo 32<rt> op1)
      !!ir (!.ctxt R.SR := AST.xtlo 32<rt> sr)
      !>ir len
    | "vbr" ->
      let md = !+ir 1<rt>
      let struct (op1, address, vbr) = tmpVars3 ir 32<rt>
      !<ir ins.Address len
      !!ir (md := !.ctxt R.MD |> AST.zext 1<rt>)
      if bv1Check md then () else resinst ir ctxt
      !!ir (op1 := AST.sext 32<rt> src)
      !!ir (address := AST.zext 32<rt> op1)
      !!ir (vbr := AST.loadLE 32<rt> address |> AST.sext 32<rt>)
      !!ir (op1 := op1 .+ numI32 4)
      !!ir (src := AST.xtlo 32<rt> op1)
      !!ir (!.ctxt R.VBR := AST.xtlo 32<rt> vbr)
      !>ir len
    | "ssr" ->
      let md = !+ir 1<rt>
      let struct (op1, address, ssr) = tmpVars3 ir 32<rt>
      !<ir ins.Address len
      !!ir (md := !.ctxt R.MD |> AST.zext 1<rt>)
      if bv1Check md then () else resinst ir ctxt
      !!ir (op1 := AST.sext 32<rt> src)
      !!ir (address := AST.zext 32<rt> op1)
      !!ir (ssr := AST.loadLE 32<rt> address |> AST.sext 32<rt>)
      !!ir (op1 := op1 .+ numI32 4)
      !!ir (src := AST.xtlo 32<rt> op1)
      !!ir (!.ctxt R.SSR := AST.xtlo 32<rt> ssr)
      !>ir len
    | "spc" ->
      let md = !+ir 1<rt>
      let struct (op1, address, spc) = tmpVars3 ir 32<rt>
      !<ir ins.Address len
      !!ir (md := !.ctxt R.MD |> AST.zext 1<rt>)
      if bv1Check md then () else resinst ir ctxt
      !!ir (op1 := AST.sext 32<rt> src)
      !!ir (address := AST.zext 32<rt> op1)
      !!ir (spc := AST.loadLE 32<rt> address |> AST.sext 32<rt>)
      !!ir (op1 := op1 .+ numI32 4)
      !!ir (src := AST.xtlo 32<rt> op1)
      !!ir (!.ctxt R.SPC := AST.xtlo 32<rt> spc)
      !>ir len
    | "dbr" ->
      let md = !+ir 1<rt>
      let struct (op1, address, dbr) = tmpVars3 ir 32<rt>
      !<ir ins.Address len
      !!ir (md := !.ctxt R.MD |> AST.zext 1<rt>)
      if bv1Check md then () else resinst ir ctxt
      !!ir (op1 := AST.sext 32<rt> src)
      !!ir (address := AST.zext 32<rt> op1)
      !!ir (dbr := AST.loadLE 32<rt> address |> AST.sext 32<rt>)
      !!ir (op1 := op1 .+ numI32 4)
      !!ir (src := AST.xtlo 32<rt> op1)
      !!ir (!.ctxt R.DBR := AST.xtlo 32<rt> dbr)
      !>ir len
    | _ ->
      let md = !+ir 1<rt>
      let struct (op1, address, rnBank) = tmpVars3 ir 32<rt>
      !<ir ins.Address len
      !!ir (md := !.ctxt R.MD |> AST.zext 1<rt>)
      if bv1Check md then () else resinst ir ctxt
      !!ir (op1 := AST.sext 32<rt> src)
      !!ir (address := AST.zext 32<rt> op1)
      !!ir (rnBank := AST.loadLE 32<rt> address |> AST.sext 32<rt>)
      !!ir (op1 := op1 .+ numI32 4)
      !!ir (src := AST.xtlo 32<rt> op1)
      !!ir (dst := AST.xtlo 32<rt> rnBank)
      !>ir len
  | _ -> Terminator.impossible()

let lds ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  match dst.E with
  | Var (_, _, s) ->
    match s with
    | "fpscr" ->
      let ir = IRBuilder (16)
      let struct (sr, op1) = tmpVars2 ir 32<rt>
      let struct (fps, pr, sz, fr) = tmpVars4 ir 1<rt>
      !<ir ins.Address len
      !!ir (sr := !.ctxt R.SR |> AST.zext 32<rt>)
      !!ir (op1 := AST.sext 32<rt> src)
      fpudisChecker ir ctxt
      !!ir (fps := op1)
      !!ir (pr := AST.extract op1 1<rt> 20)
      !!ir (sz := AST.extract op1 1<rt> 21)
      !!ir (fr := AST.extract op1 1<rt> 22)
      !!ir (!.ctxt R.FPSCR := AST.zext 32<rt> fps)
      !!ir (!.ctxt R.FPSCR_PR := pr)
      !!ir (!.ctxt R.FPSCR_SZ := sz)
      !!ir (!.ctxt R.FPSCR_FR := fr)
      !>ir len
    | "fpul" ->
      let ir = IRBuilder (8)
      let struct (sr, op1, fpul) = tmpVars3 ir 32<rt>
      !<ir ins.Address len
      !!ir (sr := !.ctxt R.SR |> AST.zext 32<rt>)
      !!ir (op1 := AST.sext 32<rt> src)
      fpudisChecker ir ctxt
      !!ir (fpul := op1)
      !!ir (!.ctxt R.FPUL := AST.zext 32<rt> fpul)
      !>ir len
    | "mach" ->
      let ir = IRBuilder (8)
      let struct (op1, mach) = tmpVars2 ir 32<rt>
      !<ir ins.Address len
      !!ir (op1 := AST.sext 32<rt> src)
      !!ir (mach := op1)
      !!ir (!.ctxt R.MACH := AST.zext 32<rt> mach)
      !>ir len
    | "macl" ->
      let ir = IRBuilder (8)
      let struct (op1, macl) = tmpVars2 ir 32<rt>
      !<ir ins.Address len
      !!ir (op1 := AST.sext 32<rt> src)
      !!ir (macl := op1)
      !!ir (!.ctxt R.MACL := AST.zext 32<rt> macl)
      !>ir len
    | "pr" ->
      let ir = IRBuilder (16)
      let struct (op1, newPR, delayedPR) = tmpVars3 ir 32<rt>
      !<ir ins.Address len
      !!ir (op1 := AST.sext 32<rt> src)
      !!ir (newPR := op1)
      !!ir (delayedPR := newPR)
      !!ir (!.ctxt R.PR := AST.xtlo 32<rt> newPR)
      !!ir (!.ctxt R.PR := AST.xtlo 32<rt> delayedPR)
      !>ir len
    | _ -> Terminator.impossible()
  | _ -> Terminator.impossible()

let ldsl ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  match dst.E with
  | Var (_, _, s) ->
    match s with
    | "fpscr" ->
      let ir = IRBuilder (16)
      let struct (sr, op1, address, value) = tmpVars4 ir 32<rt>
      let struct (fps, pr, sz, fr) = tmpVars4 ir 1<rt>
      !<ir ins.Address len
      !!ir (sr := !.ctxt R.SR |> AST.zext 32<rt>)
      !!ir (op1 := AST.sext 32<rt> src)
      fpudisChecker ir ctxt
      !!ir (address := AST.zext 32<rt> op1)
      !!ir (value := AST.loadLE 32<rt> address)
      !!ir (fps := op1)
      !!ir (pr := AST.extract op1 1<rt> 20)
      !!ir (sz := AST.extract op1 1<rt> 21)
      !!ir (fr := AST.extract op1 1<rt> 22)
      !!ir (op1 := op1 .+ numI32 4)
      !!ir (src := AST.xtlo 32<rt> op1)
      !!ir (!.ctxt R.FPSCR := AST.zext 32<rt> fps)
      !!ir (!.ctxt R.FPSCR_PR := pr)
      !!ir (!.ctxt R.FPSCR_SZ := sz)
      !!ir (!.ctxt R.FPSCR_FR := fr)
      !>ir len
    | "fpul" ->
      let ir = IRBuilder (8)
      let struct (sr, op1, fpul, address) = tmpVars4 ir 32<rt>
      !<ir ins.Address len
      !!ir (sr := !.ctxt R.SR |> AST.zext 32<rt>)
      !!ir (op1 := AST.sext 32<rt> src)
      fpudisChecker ir ctxt
      !!ir (address := AST.zext 32<rt> op1)
      !!ir (fpul := AST.loadLE 32<rt> address)
      !!ir (op1 := op1 .+ numI32 4)
      !!ir (src := AST.xtlo 32<rt> op1)
      !!ir (!.ctxt R.FPUL := AST.zext 32<rt> fpul)
      !>ir len
    | "mach" ->
      let ir = IRBuilder (8)
      let struct (op1, address, mach) = tmpVars3 ir 32<rt>
      !<ir ins.Address len
      !!ir (op1 := AST.sext 32<rt> src)
      !!ir (address := AST.zext 32<rt> op1)
      !!ir (mach := AST.loadLE 32<rt> address |> AST.sext 32<rt>)
      !!ir (op1 := op1 .+ numI32 4)
      !!ir (src := AST.xtlo 32<rt> op1)
      !!ir (!.ctxt R.MACH := AST.zext 32<rt> mach)
      !>ir len
    | "macl" ->
      let ir = IRBuilder (8)
      let struct (op1, address, macl) = tmpVars3 ir 32<rt>
      !<ir ins.Address len
      !!ir (op1 := AST.sext 32<rt> src)
      !!ir (address := AST.zext 32<rt> op1)
      !!ir (macl := AST.loadLE 32<rt> address |> AST.sext 32<rt>)
      !!ir (op1 := op1 .+ numI32 4)
      !!ir (src := AST.xtlo 32<rt> op1)
      !!ir (!.ctxt R.MACL := AST.zext 32<rt> macl)
      !>ir len
    | "pr" ->
      let ir = IRBuilder (16)
      let struct (op1, newPR, delayedPR, address) = tmpVars4 ir 32<rt>
      !<ir ins.Address len
      !!ir (op1 := AST.sext 32<rt> src)
      !!ir (address := AST.zext 32<rt> op1)
      !!ir (newPR := AST.loadLE 32<rt> address |> AST.sext 32<rt>)
      !!ir (delayedPR := newPR)
      !!ir (op1 := op1 .+ numI32 4)
      !!ir (src := AST.xtlo 32<rt> op1)
      !!ir (!.ctxt R.PR := AST.xtlo 32<rt> newPR)
      !!ir (!.ctxt R.PR := AST.xtlo 32<rt> delayedPR)
      !>ir len
    | _ -> Terminator.impossible()
  | _ -> Terminator.impossible()

let ldtlb ins len = function
  | _ -> Terminator.futureFeature()

let macl ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (64)
  let struct (macl, mach, temp) = tmpVars3 ir 32<rt>
  let struct (mField, nField) = tmpVars2 ir 4<rt>
  let struct (mAddr, nAddr, mul) = tmpVars3 ir 32<rt>
  let s = !+ir 1<rt>
  let struct (value1, value2) = tmpVars2 ir 16<rt>
  let result = !+ir 32<rt>
  let mac = !+ir 32<rt>
  let struct (m, n) =
    match src.E, dst.E with
    | Var (_, _, n1), Var (_, _, n2) ->
      struct (numI32 (int (n1[1..2])), numI32 (int (n2[1..2])))
    | _ -> Terminator.impossible()
  !<ir ins.Address len
  !!ir (macl := !.ctxt R.MACL |> AST.zext 32<rt>)
  !!ir (mach := !.ctxt R.MACH |> AST.zext 32<rt>)
  !!ir (s := !.ctxt R.S |> AST.zext 1<rt>)
  !!ir (mField := AST.zext 4<rt> m)
  !!ir (nField := AST.zext 4<rt> n)
  !!ir (mAddr := AST.zext 32<rt> src)
  !!ir (nAddr := AST.zext 32<rt> dst)
  !!ir (value2 := AST.zext 32<rt> nAddr |> AST.loadLE 32<rt>
  |> AST.sext 32<rt>)
  !!ir (nAddr := nAddr .+ numI32 4)
  !!ir (mAddr := AST.ite (mField == nField)
                             (mAddr .+ numI32 4) (mAddr))
  !!ir (nAddr := AST.ite (mField == nField)
                             (nAddr .+ numI32 4) (nAddr))
  !!ir (value1 := AST.zext 32<rt> mAddr |> AST.loadLE 32<rt>
  |> AST.sext 32<rt>)
  !!ir (mAddr := mAddr .+ numI32 4)
  !!ir (mul := value2 .* value1)
  !!ir (mac := macl .+ (mach << numI32 32))
  !!ir (result := mac .+ mul)
  !!ir (result := AST.ite (s == AST.b1)
    (AST.ite ((((result <+> mac) .& (result <+> mul)) >> numI32 63) == AST.b1)
    (AST.ite ((mac >> numI32 62) == AST.b0)
             (numI64 (int (2.0**47 - 1.0))) (numI64 (int (-2.0**47))))
    (signedSaturate result))
    (result))
  !!ir (macl := result)
  !!ir (mach := result >> numI32 32)
  !!ir (src := AST.xtlo 32<rt> mAddr)
  !!ir (dst := AST.xtlo 32<rt> nAddr)
  !!ir (!.ctxt R.MACL := AST.zext 32<rt> macl)
  !!ir (!.ctxt R.MACH := AST.zext 32<rt> mach)
  !>ir len

let macw ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (64)
  let struct (macl, mach, temp) = tmpVars3 ir 32<rt>
  let struct (mField, nField) = tmpVars2 ir 4<rt>
  let struct (mAddr, nAddr, mul) = tmpVars3 ir 32<rt>
  let s = !+ir 1<rt>
  let struct (value1, value2) = tmpVars2 ir 16<rt>
  let result = !+ir 32<rt>
  let struct (m, n) =
    match src.E, dst.E with
    | Var (_, _, n1), Var (_, _, n2) ->
      struct (numI32 (int (n1[1..2])), numI32 (int (n2[1..2])))
    | _ -> Terminator.impossible()
  !<ir ins.Address len
  !!ir (macl := !.ctxt R.MACL |> AST.zext 32<rt>)
  !!ir (mach := !.ctxt R.MACH |> AST.zext 32<rt>)
  !!ir (s := !.ctxt R.S |> AST.zext 1<rt>)
  !!ir (mField := AST.zext 4<rt> m)
  !!ir (nField := AST.zext 4<rt> n)
  !!ir (mAddr := AST.zext 32<rt> src)
  !!ir (nAddr := AST.zext 32<rt> dst)
  !!ir (value2 := AST.zext 32<rt> nAddr |> AST.loadLE 16<rt>
  |> AST.sext 16<rt>)
  !!ir (nAddr := nAddr .+ numI32 2)
  !!ir (mAddr := AST.ite (mField == nField)
                             (mAddr .+ numI32 2) (mAddr))
  !!ir (nAddr := AST.ite (mField == nField)
                             (nAddr .+ numI32 2) (nAddr))
  !!ir (value1 := AST.zext 32<rt> mAddr |> AST.loadLE 16<rt>
  |> AST.sext 16<rt>)
  !!ir (mAddr := mAddr .+ numI32 2)
  !!ir (mul := value2 .* value1)
  !!ir (macl := AST.ite (s == AST.b1) (mul .+ AST.sext 32<rt> macl) (macl))
  !!ir (temp := AST.ite (signedSaturate macl) (macl) (temp))
  !!ir (result := AST.ite (s == AST.b1)
  (AST.ite (macl == temp) (AST.zext 32<rt> macl .| (mach << numI32 32))
  (AST.zext 32<rt> temp .| (AST.b1 << numI32 32)))
  (mul .+ macl .+ (mach << numI32 32)))
  !!ir (macl := result)
  !!ir (mach := result >> numI32 32)
  !!ir (src := AST.xtlo 32<rt> mAddr)
  !!ir (dst := AST.xtlo 32<rt> nAddr)
  !!ir (!.ctxt R.MACL := AST.zext 32<rt> macl)
  !!ir (!.ctxt R.MACH := AST.zext 32<rt> mach)
  !>ir len

let mov ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (8)
  match src.E with
  | Num s ->
    let struct (imm, op2) = tmpVars2 ir 8<rt>
    !<ir ins.Address len
    !!ir (imm := AST.num s |> AST.sext 8<rt>)
    !!ir (op2 := imm)
    !!ir (dst := AST.xtlo 32<rt> op2)
    !>ir len
  | Var (_, _, r) ->
    let struct (op1, op2) = tmpVars2 ir 32<rt>
    !<ir ins.Address len
    !!ir (op1 := AST.zext 32<rt> src)
    !!ir (op2 := op1)
    !!ir (dst := AST.xtlo 32<rt> op2)
    !>ir len
  | _ -> Terminator.impossible()

let mova ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (8)
  let struct (pc, r0) = tmpVars2 ir 32<rt>
  let disp = !+ir 8<rt>
  !<ir ins.Address len
  !!ir (pc := !.ctxt R.PC |> AST.sext 32<rt>)
  !!ir (disp := (AST.zext 8<rt> src) << numI32 2)
  if (delaySlot.Count = 1) then illSlot2 ir len ctxt
  else
    !!ir (r0 := disp .+ ((pc .+ numI32 4) .& (AST.neg (numI32 3))))
    !!ir (!.ctxt R.R0 := AST.xtlo 32<rt> r0)
    !>ir len

let movb ins len ctxt =
  let ir = IRBuilder (16)
  match ins.Operands with
  | TwoOperands (OpReg (Regdir _), OpReg (RegIndir _)) ->
    let struct (src, dst) = trsTwoOpr ins ctxt
    let struct (op1, op2 ,address) = tmpVars3 ir 32<rt>
    !<ir ins.Address len
    !!ir (op1 := AST.sext 32<rt> src)
    !!ir (op2 := AST.sext 32<rt> dst)
    !!ir (address := AST.zext 32<rt> op2)
    !!ir (AST.store Endian.Little address op1)
    !>ir len
  | TwoOperands (OpReg (Regdir _), OpReg (PreDec _)) ->
    let struct (src, dst) = trsTwoOpr ins ctxt
    let struct (op1, op2, address) = tmpVars3 ir 32<rt>
    !<ir ins.Address len
    !!ir (op1 := AST.sext 32<rt> src)
    !!ir (op2 := AST.sext 32<rt> dst)
    !!ir (address := (op2 .- AST.b1) |> AST.zext 32<rt>)
    !!ir (AST.store Endian.Little address op1)
    !!ir (op2 := address)
    !!ir (dst := AST.xtlo 32<rt> op2)
    !>ir len
  | TwoOperands (OpReg (Regdir _), OpReg (IdxIndir (_))) ->
    let struct (src, dst) = trsTwoOpr ins ctxt
    let struct (r0, op1, op2, address) = tmpVars4 ir 32<rt>
    !<ir ins.Address len
    !!ir (r0 := !.ctxt R.R0 |> AST.sext 32<rt>)
    !!ir (op1 := AST.sext 32<rt> src)
    !!ir (op2 := AST.sext 32<rt> dst)
    !!ir (address := (r0 .+ op2) |> AST.zext 32<rt>)
    !!ir (AST.store Endian.Little address op1)
    !>ir len
  | TwoOperands (OpReg (Regdir _), OpReg (GbrDisp _)) ->
    let struct (src, dst) = trsTwoOpr ins ctxt
    let struct (gbr, address) = tmpVars2 ir 32<rt>
    let disp = !+ir 8<rt>
    let r0 = !+ir 32<rt>
    !<ir ins.Address len
    !!ir (gbr := !.ctxt R.GBR |> AST.sext 32<rt>)
    !!ir (r0 := !.ctxt R.R0 |> AST.sext 32<rt>)
    !!ir (disp := AST.zext 8<rt> dst)
    !!ir (address := (gbr .+ disp) |> AST.zext 32<rt>)
    !!ir (AST.store Endian.Little address r0)
    !>ir len
  | TwoOperands (OpReg (Regdir _), OpReg (RegDisp _)) ->
    let struct (src, dst, imm) = trsMemOpr4toExpr ins ctxt
    let struct (op2, address, r0) = tmpVars3 ir 32<rt>
    let disp = !+ir 4<rt>
    !<ir ins.Address len
    !!ir (r0 := !.ctxt R.R0 |> AST.sext 32<rt>)
    !!ir (disp := AST.zext 4<rt> imm)
    !!ir (op2 := AST.sext 32<rt> dst)
    !!ir (address := (disp .+ op2) |> AST.zext 32<rt>)
    !!ir (AST.store Endian.Little address r0)
    !>ir len
  | TwoOperands (OpReg (RegIndir _), OpReg (Regdir _)) -> //0100 0100 0100 0000
    let struct (src, dst) = trsTwoOpr ins ctxt
    let struct (op1, address) = tmpVars2 ir 32<rt>
    let op2 = !+ir 32<rt>
    !<ir ins.Address len
    !!ir (op1 := AST.sext 32<rt> src)
    !!ir (address := AST.zext 32<rt> op1)
    !!ir (op2 := AST.loadLE 8<rt> address |> AST.sext 8<rt>)
    !!ir (dst := AST.xtlo 8<rt> op2)
    !>ir len
  | TwoOperands (OpReg (PostInc _), OpReg (Regdir _)) ->
    let struct (src, dst) = trsTwoOpr ins ctxt
    let struct (mField, nField) = tmpVars2 ir 4<rt>
    let op1 = !+ir 32<rt>
    let address = !+ir 32<rt>
    let op2 = !+ir 16<rt>
    let struct (m, n) =
      match src.E, dst.E with
      | Var (_, _, n1), Var (_, _, n2) ->
        struct (numI32 (int (n1[1..2])), numI32 (int (n2[1..2])))
      | _ -> Terminator.impossible()
    !<ir ins.Address len
    !!ir (mField := AST.zext 4<rt> m)
    !!ir (nField := AST.zext 4<rt> n)
    !!ir (op1 := AST.sext 32<rt> src)
    !!ir (address := AST.zext 32<rt> op1)
    !!ir (op2 := AST.loadLE 32<rt> address |> AST.sext 32<rt>)
    !!ir (op1 := AST.ite (mField == nField) (op2) (op1 .+ numI32 4))
    !!ir (src := AST.xtlo 32<rt> op1)
    !!ir (dst := AST.xtlo 32<rt> op2)
    !>ir len
  | TwoOperands (OpReg (IdxIndir _), OpReg (Regdir (_))) ->
    let struct (src, dst) = trsTwoOpr ins ctxt
    let struct (r0, op1, address) = tmpVars3 ir 32<rt>
    let op2 = !+ir 8<rt>
    !<ir ins.Address len
    !!ir (r0 := !.ctxt R.R0 |> AST.sext 32<rt>)
    !!ir (op1 := AST.sext 32<rt> src)
    !!ir (address := (r0 .+ op1) |> AST.zext 32<rt>)
    !!ir (op2 := AST.loadLE 8<rt> address |> AST.sext 8<rt>)
    !!ir (dst := AST.xtlo 8<rt> op2)
    !>ir len
  | TwoOperands (OpReg (GbrDisp _), OpReg (Regdir _)) ->
    let struct (src, dst) = trsTwoOpr ins ctxt
    let struct (gbr, address) = tmpVars2 ir 32<rt>
    let disp = !+ir 8<rt>
    let r0 = !+ir 8<rt>
    !<ir ins.Address len
    !!ir (gbr := !.ctxt R.GBR |> AST.sext 32<rt>)
    !!ir (disp := AST.zext 8<rt> src)
    !!ir (address := (gbr .+ disp) |> AST.zext 32<rt>)
    !!ir (r0 := AST.loadLE 8<rt> address |> AST.sext 8<rt>)
    !!ir (dst := AST.xtlo 8<rt> r0)
    !>ir len
  | TwoOperands (OpReg (RegDisp _), OpReg (Regdir _)) ->
    let struct (src, dst, imm) = trsMemOpr3toExpr ins ctxt
    let struct (op2, address) = tmpVars2 ir 32<rt>
    let disp = !+ir 4<rt>
    let r0 = !+ir 8<rt>
    !<ir ins.Address len
    !!ir (disp := AST.zext 4<rt> imm)
    !!ir (op2 := AST.sext 32<rt> src)
    !!ir (address := (disp .+ op2) |> AST.zext 32<rt>)
    !!ir (r0 := AST.loadLE 8<rt> address |> AST.sext 8<rt>)
    !!ir (!.ctxt R.R0 := AST.xtlo 8<rt> r0)
    !>ir len
  | _ -> Terminator.impossible()

let movl ins len ctxt =
  let ir = IRBuilder (16)
  match ins.Operands with
  | TwoOperands (OpReg (Regdir _), OpReg (RegIndir _)) ->
    let struct (src, dst) = trsTwoOpr ins ctxt
    let struct (op1, op2 ,address) = tmpVars3 ir 32<rt>
    !<ir ins.Address len
    !!ir (op1 := AST.sext 32<rt> src)
    !!ir (op2 := AST.sext 32<rt> dst)
    !!ir (address := AST.zext 32<rt> op2)
    !!ir (AST.store Endian.Little address op1)
    !>ir len
  | TwoOperands (OpReg (Regdir _), OpReg (PreDec _)) ->
    let struct (src, dst) = trsTwoOpr ins ctxt
    let struct (op1, op2, address) = tmpVars3 ir 32<rt>
    !<ir ins.Address len
    !!ir (op1 := AST.sext 32<rt> src)
    !!ir (op2 := AST.sext 32<rt> dst)
    !!ir (address := (op2 .- numI32 4) |> AST.zext 32<rt>)
    !!ir (AST.store Endian.Little address op1)
    !!ir (op2 := address)
    !!ir (dst := AST.xtlo 32<rt> op2)
    !>ir len
  | TwoOperands (OpReg (Regdir _), OpReg (IdxIndir (_))) ->
    let struct (src, dst) = trsTwoOpr ins ctxt
    let struct (r0, op1, op2, address) = tmpVars4 ir 32<rt>
    !<ir ins.Address len
    !!ir (r0 := !.ctxt R.R0 |> AST.sext 32<rt>)
    !!ir (op1 := AST.sext 32<rt> src)
    !!ir (op2 := AST.sext 32<rt> dst)
    !!ir (address := (r0 .+ op2) |> AST.zext 32<rt>)
    !!ir (AST.store Endian.Little address op1)
    !>ir len
  | TwoOperands (OpReg (Regdir _), OpReg (GbrDisp _)) ->
    let struct (src, dst) = trsTwoOpr ins ctxt
    let struct (gbr, address) = tmpVars2 ir 32<rt>
    let disp = !+ir 8<rt>
    let r0 = !+ir 32<rt>
    !<ir ins.Address len
    !!ir (gbr := !.ctxt R.GBR |> AST.sext 32<rt>)
    !!ir (r0 := !.ctxt R.R0 |> AST.sext 32<rt>)
    !!ir (disp := AST.zext 8<rt> dst << numI32 2)
    !!ir (address := (gbr .+ disp) |> AST.zext 32<rt>)
    !!ir (AST.store Endian.Little address r0)
    !>ir len
  | TwoOperands (OpReg (Regdir _), OpReg (RegDisp _)) ->
    let struct (src, dst, imm) = trsMemOpr4toExpr ins ctxt
    let struct (op3, address, op1) = tmpVars3 ir 32<rt>
    let disp = !+ir 4<rt>
    !<ir ins.Address len
    !!ir (disp := AST.zext 4<rt> imm << numI32 2)
    !!ir (op1 := AST.sext 32<rt> src)
    !!ir (op3 := AST.sext 32<rt> dst)
    !!ir (address := (disp .+ op3) |> AST.zext 32<rt>)
    !!ir (AST.store Endian.Little address op1)
    !>ir len
  | TwoOperands (OpReg (RegIndir _), OpReg (Regdir _)) ->
    let struct (src, dst) = trsTwoOpr ins ctxt
    let struct (op1, address) = tmpVars2 ir 32<rt>
    let op2 = !+ir 32<rt>
    !<ir ins.Address len
    !!ir (op1 := AST.sext 32<rt> src)
    !!ir (address := AST.zext 32<rt> op1)
    !!ir (op2 := AST.loadLE 32<rt> address |> AST.sext 32<rt>)
    !!ir (dst := AST.xtlo 32<rt> op2)
    !>ir len
  | TwoOperands (OpReg (PostInc _), OpReg (Regdir _)) ->
    let struct (src, dst) = trsTwoOpr ins ctxt
    let struct (mField, nField) = tmpVars2 ir 4<rt>
    let op1 = !+ir 32<rt>
    let address = !+ir 32<rt>
    let op2 = !+ir 16<rt>
    let struct (m, n) =
      match src.E, dst.E with
      | Var (_, _, n1), Var (_, _, n2) ->
        struct (numI32 (int (n1[1..2])), numI32 (int (n2[1..2])))
      | _ -> Terminator.impossible()
    !<ir ins.Address len
    !!ir (mField := AST.zext 4<rt> m)
    !!ir (nField := AST.zext 4<rt> n)
    !!ir (op1 := AST.sext 32<rt> src)
    !!ir (address := AST.zext 32<rt> op1)
    !!ir (op2 := AST.loadLE 32<rt> address |> AST.sext 32<rt>)
    !!ir (op1 := AST.ite (mField == nField) (op2) (op1 .+ numI32 4))
    !!ir (src := AST.xtlo 32<rt> op1)
    !!ir (dst := AST.xtlo 32<rt> op2)
    !>ir len
  | TwoOperands (OpReg (IdxIndir _), OpReg (Regdir _)) ->
    let struct (src, dst) = trsTwoOpr ins ctxt
    let struct (r0, op1, address) = tmpVars3 ir 32<rt>
    let op2 = !+ir 32<rt>
    !<ir ins.Address len
    !!ir (r0 := !.ctxt R.R0 |> AST.sext 32<rt>)
    !!ir (op1 := AST.sext 32<rt> src)
    !!ir (address := (r0 .+ op1) |> AST.zext 32<rt>)
    !!ir (op2 := AST.loadLE 32<rt> address |> AST.sext 32<rt>)
    !!ir (dst := AST.xtlo 32<rt> op2)
    !>ir len
  | TwoOperands (OpReg (GbrDisp _), OpReg (Regdir _)) ->
    let struct (src, dst) = trsTwoOpr ins ctxt
    let struct (gbr, address) = tmpVars2 ir 32<rt>
    let disp = !+ir 8<rt>
    let r0 = !+ir 32<rt>
    !<ir ins.Address len
    !!ir (gbr := !.ctxt R.GBR |> AST.sext 32<rt>)
    !!ir (disp := AST.zext 8<rt> src << numI32 2)
    !!ir (address := (gbr .+ disp) |> AST.zext 32<rt>)
    !!ir (r0 := AST.loadLE 32<rt> address |> AST.sext 32<rt>)
    !!ir (dst := AST.xtlo 32<rt> r0)
    !>ir len
  | TwoOperands (OpReg (PCrDisp _), OpReg (Regdir _)) ->
    let struct (src, dst) = trsTwoOpr ins ctxt
    let struct (pc, address) = tmpVars2 ir 32<rt>
    let disp = !+ir 8<rt>
    let op2 = !+ir 16<rt>
    !<ir ins.Address len
    !!ir (pc := !.ctxt R.PC |> AST.sext 32<rt>)
    !!ir (disp := AST.zext 8<rt> src << numI32 2)
    if (delaySlot.Count = 1) then illSlot2 ir len ctxt
    else
      !!ir (address := ((pc .+ numI32 4) .& (numI32 3 |> AST.neg))
                       |> AST.zext 32<rt>)
      !!ir (op2 := AST.loadLE 32<rt> address |> AST.sext 32<rt>)
      !!ir (dst := AST.xtlo 32<rt> op2)
      !>ir len
  | TwoOperands (OpReg (RegDisp _), OpReg (Regdir _)) ->
    let struct (src, dst, imm) = trsMemOpr3toExpr ins ctxt
    let struct (op2, address) = tmpVars2 ir 32<rt>
    let disp = !+ir 4<rt>
    let op3 = !+ir 32<rt>
    !<ir ins.Address len
    !!ir (disp := AST.zext 4<rt> imm << numI32 2)
    !!ir (op2 := AST.sext 32<rt> src)
    !!ir (address := (disp .+ op2) |> AST.zext 32<rt>)
    !!ir (op3 := AST.loadLE 32<rt> address |> AST.sext 32<rt>)
    !!ir (dst := AST.xtlo 32<rt> op3)
    !>ir len
  | _ -> Terminator.impossible()

let movw ins len ctxt =
  let ir = IRBuilder (16)
  match ins.Operands with
  | TwoOperands (OpReg (Regdir _), OpReg (RegIndir _)) ->
    let struct (src, dst) = trsTwoOpr ins ctxt
    let struct (op1, op2 ,address) = tmpVars3 ir 32<rt>
    !<ir ins.Address len
    !!ir (op1 := AST.sext 32<rt> src)
    !!ir (op2 := AST.sext 32<rt> dst)
    !!ir (address := AST.zext 32<rt> op2)
    !!ir (AST.store Endian.Little address op1)
    !>ir len
  | TwoOperands (OpReg (Regdir _), OpReg (PreDec _)) ->
    let struct (src, dst) = trsTwoOpr ins ctxt
    let struct (op1, op2, address) = tmpVars3 ir 32<rt>
    !<ir ins.Address len
    !!ir (op1 := AST.sext 32<rt> src)
    !!ir (op2 := AST.sext 32<rt> dst)
    !!ir (address := (op2 .- numI32 2) |> AST.zext 32<rt>)
    !!ir (AST.store Endian.Little address op1)
    !!ir (op2 := address)
    !!ir (dst := AST.xtlo 32<rt> op2)
    !>ir len
  | TwoOperands (OpReg (Regdir _), OpReg (IdxIndir (_))) ->
    let struct (src, dst) = trsTwoOpr ins ctxt
    let struct (r0, op1, op2, address) = tmpVars4 ir 32<rt>
    !<ir ins.Address len
    !!ir (r0 := !.ctxt R.R0 |> AST.sext 32<rt>)
    !!ir (op1 := AST.sext 32<rt> src)
    !!ir (op2 := AST.sext 32<rt> dst)
    !!ir (address := (r0 .+ op2) |> AST.zext 32<rt>)
    !!ir (AST.store Endian.Little address op1)
    !>ir len
  | TwoOperands (OpReg (Regdir _), OpReg (GbrDisp (_))) ->
    let struct (src, dst) = trsTwoOpr ins ctxt
    let struct (gbr, address) = tmpVars2 ir 32<rt>
    let disp = !+ir 8<rt>
    let r0 = !+ir 32<rt>
    !<ir ins.Address len
    !!ir (gbr := !.ctxt R.GBR |> AST.sext 32<rt>)
    !!ir (r0 := !.ctxt R.R0 |> AST.sext 32<rt>)
    !!ir (disp := AST.zext 8<rt> dst << AST.b1)
    !!ir (address := (gbr .+ disp) |> AST.zext 32<rt>)
    !!ir (AST.store Endian.Little address r0)
    !>ir len
  | TwoOperands (OpReg (Regdir _), OpReg (RegDisp (_))) ->
    let struct (src, dst, imm) = trsMemOpr4toExpr ins ctxt
    let struct (op2, address, r0) = tmpVars3 ir 32<rt>
    let disp = !+ir 4<rt>
    !<ir ins.Address len
    !!ir (r0 := !.ctxt R.R0 |> AST.sext 32<rt>)
    !!ir (disp := AST.zext 4<rt> imm << AST.b1)
    !!ir (op2 := AST.sext 32<rt> src)
    !!ir (address := (disp .+ op2) |> AST.zext 32<rt>)
    !!ir (AST.store Endian.Little address r0)
    !>ir len
  | TwoOperands (OpReg (RegIndir _), OpReg (Regdir _)) ->
    let struct (src, dst) = trsTwoOpr ins ctxt
    let struct (op1, address) = tmpVars2 ir 32<rt>
    let op2 = !+ir 16<rt>
    !<ir ins.Address len
    !!ir (op1 := AST.sext 32<rt> src)
    !!ir (address := AST.zext 32<rt> op1)
    !!ir (op2 := AST.loadLE 16<rt> address |> AST.sext 16<rt>)
    !!ir (dst := AST.xtlo 16<rt> op2)
    !>ir len
  | TwoOperands (OpReg (PostInc _), OpReg (Regdir _)) ->
    let struct (src, dst) = trsTwoOpr ins ctxt
    let struct (mField, nField) = tmpVars2 ir 4<rt>
    let op1 = !+ir 32<rt>
    let address = !+ir 32<rt>
    let op2 = !+ir 16<rt>
    let struct (m, n) =
      match src.E, dst.E with
      | Var (_, _, n1), Var (_, _, n2) ->
        struct (numI32 (int (n1[1..2])), numI32 (int (n2[1..2])))
      | _ -> Terminator.impossible()
    !<ir ins.Address len
    !!ir (mField := AST.zext 4<rt> m)
    !!ir (nField := AST.zext 4<rt> n)
    !!ir (op1 := AST.sext 32<rt> src)
    !!ir (address := AST.zext 32<rt> op1)
    !!ir (op2 := AST.loadLE 16<rt> address |> AST.sext 16<rt>)
    !!ir (op1 := AST.ite (mField == nField) (op2) (op1 .+ numI32 2))
    !!ir (src := AST.xtlo 32<rt> op1)
    !!ir (dst := AST.xtlo 16<rt> op2)
    !>ir len
  | TwoOperands (OpReg (IdxIndir (_)), OpReg (Regdir (_))) ->
    let struct (src, dst) = trsTwoOpr ins ctxt
    let struct (r0, op1, address) = tmpVars3 ir 32<rt>
    let op2 = !+ir 16<rt>
    !<ir ins.Address len
    !!ir (r0 := !.ctxt R.R0 |> AST.sext 32<rt>)
    !!ir (op1 := AST.sext 32<rt> src)
    !!ir (address := (r0 .+ op1) |> AST.zext 32<rt>)
    !!ir (op2 := AST.loadLE 16<rt> address |> AST.sext 16<rt>)
    !!ir (dst := AST.xtlo 16<rt> op2)
    !>ir len
  | TwoOperands (OpReg (GbrDisp (_)), OpReg (Regdir _)) ->
    let struct (src, dst) = trsTwoOpr ins ctxt
    let struct (gbr, address) = tmpVars2 ir 32<rt>
    let disp = !+ir 8<rt>
    let r0 = !+ir 16<rt>
    !<ir ins.Address len
    !!ir (gbr := !.ctxt R.GBR |> AST.sext 32<rt>)
    !!ir (disp := AST.zext 8<rt> src << AST.b1)
    !!ir (address := ((gbr .+ numI32 4) .+ disp) |> AST.zext 32<rt>)
    !!ir (r0 := AST.loadLE 16<rt> address |> AST.sext 16<rt>)
    !!ir (dst := AST.xtlo 16<rt> r0)
    !>ir len
  | TwoOperands (OpReg (PCrDisp (_)), OpReg (Regdir _)) ->
    let struct (src, dst) = trsTwoOpr ins ctxt
    let struct (pc, address) = tmpVars2 ir 32<rt>
    let disp = !+ir 8<rt>
    let op2 = !+ir 16<rt>
    !<ir ins.Address len
    !!ir (pc := !.ctxt R.PC |> AST.sext 32<rt>)
    !!ir (disp := AST.zext 8<rt> src << AST.b1)
    if (delaySlot.Count = 1) then illSlot2 ir len ctxt
    else
      !!ir (address := ((pc .+ numI32 4) .+ disp) |> AST.zext 32<rt>)
      !!ir (op2 := AST.loadLE 16<rt> address |> AST.sext 16<rt>)
      !!ir (dst := AST.xtlo 16<rt> op2)
      !>ir len
  | TwoOperands (OpReg (RegDisp (_)), OpReg (Regdir _)) ->
    let struct (src, dst, imm) = trsMemOpr3toExpr ins ctxt
    let struct (op2, address) = tmpVars2 ir 32<rt>
    let disp = !+ir 4<rt>
    let r0 = !+ir 16<rt>
    !<ir ins.Address len
    !!ir (disp := AST.zext 4<rt> imm << AST.b1)
    !!ir (op2 := AST.sext 32<rt> src)
    !!ir (address := (disp .+ op2) |> AST.zext 32<rt>)
    !!ir (r0 := AST.loadLE 16<rt> address |> AST.sext 16<rt>)
    !!ir (!.ctxt R.R0 := AST.xtlo 16<rt> r0)
    !>ir len
  | _ -> Terminator.impossible()

let movcal ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (8)
  let struct (r0, op1, address) = tmpVars3 ir 32<rt>
  !<ir ins.Address len
  !!ir (r0 := !.ctxt R.R0 |> AST.sext 32<rt>)
  !!ir (op1 := AST.sext 32<rt> dst)
  !!ir (address := AST.zext 32<rt> op1)
  !!ir (AST.store Endian.Little op1 r0)
  !>ir len

let movt ins len ctxt =
  let dst = trsOneOpr ins ctxt
  let ir = IRBuilder (8)
  let struct (t, op1) = tmpVars2 ir 1<rt>
  !<ir ins.Address len
  !!ir (t := !.ctxt R.T |> AST.zext 1<rt>)
  !!ir (op1 := t)
  !!ir (dst := AST.xtlo 32<rt> op1)
  !>ir len

let mull ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (8)
  let struct (op1, op2) = tmpVars2 ir 32<rt>
  let macl = !+ir 64<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.sext 32<rt> src)
  !!ir (op2 := AST.sext 32<rt> dst)
  !!ir (macl := op1 .* op2)
  !!ir (!.ctxt R.MACL := AST.zext 32<rt> macl)
  !>ir len

let mulsw ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (8)
  let struct (op1, op2) = tmpVars2 ir 16<rt>
  let macl = !+ir 64<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.sext 32<rt> src |> AST.sext 16<rt>)
  !!ir (op2 := AST.sext 32<rt> dst |> AST.sext 16<rt>)
  !!ir (macl := op1 .* op2)
  !!ir (!.ctxt R.MACL := AST.zext 32<rt> macl)
  !>ir len

let muluw ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (8)
  let struct (op1, op2) = tmpVars2 ir 16<rt>
  let macl = !+ir 64<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.sext 32<rt> src |> AST.zext 16<rt>)
  !!ir (op2 := AST.sext 32<rt> dst |> AST.zext 16<rt>)
  !!ir (macl := op1 .* op2)
  !!ir (!.ctxt R.MACL := AST.zext 32<rt> macl)
  !>ir len

let neg ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (8)
  let struct (op1, op2) = tmpVars2 ir 32<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.sext 32<rt> src)
  !!ir (op2 := op1)
  !!ir (dst := AST.xtlo 32<rt> op2)
  !>ir len

let negc ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  let struct (op1, op2) = tmpVars2 ir 32<rt>
  let t = !+ir 1<rt>
  !<ir ins.Address len
  !!ir (t := !.ctxt R.T |> AST.zext 1<rt>)
  !!ir (op1 := AST.zext 32<rt> src)
  !!ir (op2 := (AST.neg op1) .- t)
  !!ir (t := AST.extract op2 1<rt> 32)
  !!ir (dst := AST.xtlo 32<rt> op2)
  !!ir (!.ctxt R.T := AST.extract t 1<rt> 1)
  !>ir len

let nop ins len ctxt =
  let ir = IRBuilder (2)
  !<ir ins.Address len
  !>ir len

let ``not`` ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (8)
  let struct (op1, op2) = tmpVars2 ir 32<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.zext 32<rt> src)
  !!ir (op2 := AST.neg op1)
  !!ir (dst := AST.xtlo 32<rt> op2)
  !>ir len

let ocbi ins len ctxt =
  let ir = IRBuilder(2)
  !<ir ins.Address len
  !>ir len

let ocbp ins len ctxt =
  let ir = IRBuilder(2)
  !<ir ins.Address len
  !>ir len

let ocbwb ins len ctxt =
  let ir = IRBuilder(2)
  !<ir ins.Address len
  !>ir len

let ``or`` ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (8)
  match src.E with
  | Num _ ->
    let r0 = !+ir 32<rt>
    let imm = !+ir 8<rt>
    !<ir ins.Address len
    !!ir (r0 := !.ctxt R.R0 |> AST.zext 32<rt>)
    !!ir (imm := AST.zext 8<rt> src)
    !!ir (r0 := r0 .| imm)
    !!ir (!.ctxt R.R0 := AST.xtlo 32<rt> r0)
    !>ir len
  | Var _ ->
    let struct (op1, op2) = tmpVars2 ir 32<rt>
    !<ir ins.Address len
    !!ir (op1 := AST.zext 32<rt> src)
    !!ir (op2 := AST.zext 32<rt> dst)
    !!ir (op2 := op1 .| op2)
    !!ir (dst := AST.xtlo 32<rt> op2)
    !>ir len
  | _ -> Terminator.impossible()

let orb ins len ctxt =
  let struct (src, _) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  let struct (r0, gbr, address) = tmpVars3 ir 32<rt>
  let struct (imm, value) = tmpVars2 ir 8<rt>
  !<ir ins.Address len
  !!ir (r0 := !.ctxt R.R0 |> AST.sext 32<rt>)
  !!ir (gbr := !.ctxt R.GBR |> AST.sext 32<rt>)
  !!ir (imm := AST.zext 8<rt> src)
  !!ir (address := (r0 .+ gbr) |> AST.zext 32<rt>)
  !!ir (value := AST.loadLE 8<rt> address  |> AST.zext 8<rt>)
  !!ir (value := value .| imm)
  !!ir (AST.store Endian.Little address value)
  !>ir len

let pref ins len = function
  | _ -> Terminator.futureFeature()

let rotcl ins len ctxt =
  let dst = trsOneOpr ins ctxt
  let ir = IRBuilder (16)
  let t = !+ir 1<rt>
  let op1 = !+ir 32<rt>
  !<ir ins.Address len
  !!ir (t := !.ctxt R.T |> AST.zext 32<rt>)
  !!ir (op1 := AST.zext 32<rt> dst)
  !!ir (op1 := (op1 << AST.b1) .| t)
  !!ir (t := AST.extract op1 1<rt> 32)
  !!ir (dst := AST.xtlo 32<rt> op1)
  !!ir (!.ctxt R.T := AST.extract t 1<rt> 1)
  !>ir len

let rotcr ins len ctxt =
  let dst = trsOneOpr ins ctxt
  let ir = IRBuilder (16)
  let struct (oldt, t) = tmpVars2 ir 1<rt>
  let op1 = !+ir 32<rt>
  !<ir ins.Address len
  !!ir (t := !.ctxt R.T |> AST.zext 32<rt>)
  !!ir (op1 := AST.zext 32<rt> dst)
  !!ir (oldt := t)
  !!ir (t := AST.extract op1 1<rt> 1)
  !!ir (op1 := (op1 >> AST.b1) .| (oldt << (numI32 31)))
  !!ir (dst := AST.xtlo 32<rt> op1)
  !!ir (!.ctxt R.T := AST.extract t 1<rt> 1)
  !>ir len

let rotl ins len ctxt =
  let dst = trsOneOpr ins ctxt
  let ir = IRBuilder (16)
  let t = !+ir 1<rt>
  let op1 = !+ir 32<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.zext 32<rt> dst)
  !!ir (t := AST.extract op1 1<rt> 31)
  !!ir (op1 := (op1 << AST.b1) .| t)
  !!ir (dst := AST.xtlo 32<rt> op1)
  !!ir (!.ctxt R.T := AST.extract t 1<rt> 1)
  !>ir len

let rotr ins len ctxt =
  let dst = trsOneOpr ins ctxt
  let ir = IRBuilder (16)
  let t = !+ir 1<rt>
  let op1 = !+ir 32<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.zext 32<rt> dst)
  !!ir (t := AST.extract op1 1<rt> 1)
  !!ir (op1 := (op1 >> AST.b1) .| (t << (numI32 31)))
  !!ir (dst := AST.xtlo 32<rt> op1)
  !!ir (!.ctxt R.T := AST.extract t 1<rt> 1)
  !>ir len

let rte ins len ctxt =
  let ir = IRBuilder (16)
  let md = !+ir 1<rt>
  let struct (ssr, pc, target, delayedPC) = tmpVars4 ir 32<rt>
  !<ir ins.Address len
  !!ir (md := !.ctxt R.MD |> AST.zext 1<rt>)
  if fpuCheck md 1 then () else resinst ir ctxt
  !!ir (ssr := !.ctxt R.SSR |> AST.sext 32<rt>)
  !!ir (pc := !.ctxt R.PC |> AST.sext 32<rt>)
  if (delaySlot.Count = 1) then illSlot2 ir len ctxt
  else
    !!ir (target := pc)
    !!ir (delayedPC := target .& (AST.neg AST.b1))
    !!ir (!.ctxt R.PC .+ numI32 2 := AST.xtlo 32<rt> delayedPC)
    !>ir len

let rts ins len ctxt =
  let ir = IRBuilder (8)
  let struct (pr, target, delayedPC) = tmpVars3 ir 32<rt>
  !<ir ins.Address len
  !!ir (pr := !.ctxt R.PR |> AST.sext 32<rt>)
  if (delaySlot.Count = 1) then illSlot2 ir len ctxt
  else
    !!ir (target := pr)
    !!ir (delayedPC := target .& (AST.neg AST.b1))
    !!ir (!.ctxt R.PC .+ numI32 2 := AST.xtlo 32<rt> delayedPC)
    !>ir len

let sets ins len ctxt =
  let ir = IRBuilder (8)
  let s = !+ir 1<rt>
  !<ir ins.Address len
  !!ir (s := AST.b1)
  !!ir (!.ctxt R.S := AST.extract s 1<rt> 1)
  !>ir len

let sett ins len ctxt =
  let ir = IRBuilder (8)
  let t = !+ir 1<rt>
  !<ir ins.Address len
  !!ir (t := AST.b1)
  !!ir (!.ctxt R.T := AST.extract t 1<rt> 1)
  !>ir len

let shad ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  let struct (op1, op2) = tmpVars2 ir 32<rt>
  let shift = !+ir 5<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.sext 32<rt> src)
  !!ir (op2 := AST.sext 32<rt> dst)
  !!ir (shift := AST.zext 5<rt> op1)
  !!ir (op2 := AST.ite (op1 ?>= AST.b0) (op2 << shift)
  (AST.ite (shift != AST.b0) (op2 >> (numI32 32 .- shift))
  (AST.ite (op2 ?< AST.b0) (numI32 -1) (AST.b0))))
  !!ir (dst := AST.xtlo 32<rt> op2)
  !>ir len

let shal ins len ctxt =
  let dst = trsOneOpr ins ctxt
  let ir = IRBuilder (8)
  let op1 = !+ir 32<rt>
  let t = !+ir 1<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.sext 32<rt> dst)
  !!ir (t := AST.extract op1 1<rt> 32)
  !!ir (op1 := op1 << AST.b1)
  !!ir (dst := AST.xtlo 32<rt> op1)
  !!ir (!.ctxt R.T := AST.extract t 1<rt> 1)
  !>ir len

let shar ins len ctxt =
  let dst = trsOneOpr ins ctxt
  let ir = IRBuilder (8)
  let op1 = !+ir 32<rt>
  let t = !+ir 1<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.sext 32<rt> dst)
  !!ir (t := AST.extract op1 1<rt> 1)
  !!ir (op1 := op1 >> AST.b1)
  !!ir (dst := AST.xtlo 32<rt> op1)
  !!ir (!.ctxt R.T := AST.extract t 1<rt> 1)
  !>ir len

let shld ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  let struct (op1, op2) = tmpVars2 ir 32<rt>
  let shift = !+ir 32<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.sext 32<rt> src)
  !!ir (op2 := AST.sext 32<rt> dst)
  !!ir (shift := AST.zext 32<rt> (AST.extract op1 5<rt> 0))
  !!ir (op2 := AST.ite (op1 ?>= (AST.num0 32<rt>)) (op2 << shift)
              (AST.ite (shift != AST.num0 32<rt>)
                       (op2 >> (numI32 32 .- shift)) (numI32 0)))
  !!ir (dst := AST.xtlo 32<rt> op2)
  !>ir len

let shll ins len ctxt =
  let dst = trsOneOpr ins ctxt
  let ir = IRBuilder (8)
  let op1 = !+ir 32<rt>
  let t = !+ir 1<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.zext 32<rt> dst)
  !!ir (t := AST.extract op1 1<rt> 1)
  !!ir (op1 := op1 << AST.b1)
  !!ir (dst := AST.xtlo 32<rt> op1)
  !!ir (!.ctxt R.T := AST.extract t 1<rt> 1)
  !>ir len

let shll2 ins len ctxt =
  let dst = trsOneOpr ins ctxt
  let ir = IRBuilder (8)
  let op1 = !+ir 32<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.zext 32<rt> dst)
  !!ir (op1 := op1 << numI32 2)
  !!ir (dst := AST.xtlo 32<rt> op1)
  !>ir len

let shll8 ins len ctxt =
  let dst = trsOneOpr ins ctxt
  let ir = IRBuilder (8)
  let op1 = !+ir 32<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.zext 32<rt> dst)
  !!ir (op1 := op1 << numI32 8)
  !!ir (dst := AST.xtlo 32<rt> op1)
  !>ir len

let shll16 ins len ctxt =
  let dst = trsOneOpr ins ctxt
  let ir = IRBuilder (8)
  let op1 = !+ir 32<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.zext 32<rt> dst)
  !!ir (op1 := op1 << numI32 16)
  !!ir (dst := AST.xtlo 32<rt> op1)
  !>ir len

let shlr ins len ctxt =
  let dst = trsOneOpr ins ctxt
  let ir = IRBuilder (8)
  let op1 = !+ir 32<rt>
  let t = !+ir 1<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.zext 32<rt> dst)
  !!ir (t := AST.extract op1 1<rt> 1)
  !!ir (op1 := op1 >> AST.b1)
  !!ir (dst := AST.xtlo 32<rt> op1)
  !!ir (!.ctxt R.T := AST.extract t 1<rt> 1)
  !>ir len

let shlr2 ins len ctxt =
  let dst = trsOneOpr ins ctxt
  let ir = IRBuilder (8)
  let op1 = !+ir 32<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.zext 32<rt> dst)
  !!ir (op1 := op1 >> numI32 2)
  !!ir (dst := AST.xtlo 32<rt> op1)
  !>ir len

let shlr8 ins len ctxt =
  let dst = trsOneOpr ins ctxt
  let ir = IRBuilder (8)
  let op1 = !+ir 32<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.zext 32<rt> dst)
  !!ir (op1 := op1 >> numI32 8)
  !!ir (dst := AST.xtlo 32<rt> op1)
  !>ir len

let shlr16 ins len ctxt =
  let dst = trsOneOpr ins ctxt
  let ir = IRBuilder (8)
  let op1 = !+ir 32<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.zext 32<rt> dst)
  !!ir (op1 := op1 >> numI32 16)
  !!ir (dst := AST.xtlo 32<rt> op1)
  !>ir len

let sleep ins len ctxt =
  let ir = IRBuilder (2)
  !<ir ins.Address len
  !>ir len

let stc ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  let md = !+ir 1<rt>
  let struct (reg, op1) = tmpVars2 ir 32<rt>
  !<ir ins.Address len
  !!ir (md := !.ctxt R.MD |> AST.zext 1<rt>)
  if (fpuCheck md 1) then () else resinst ir ctxt
  !!ir (reg := src |> AST.sext 32<rt>)
  !!ir (op1 := reg)
  !!ir (dst := AST.xtlo 32<rt> op1)
  !>ir len

let stcl ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  let md = !+ir 1<rt>
  let struct (reg, op1, address) = tmpVars3 ir 32<rt>
  !<ir ins.Address len
  !!ir (md := !.ctxt R.MD |> AST.zext 1<rt>)
  if (fpuCheck md 1) then () else resinst ir ctxt
  !!ir (reg := AST.sext 32<rt> src)
  !!ir (op1 := AST.sext 32<rt> dst)
  !!ir (address := (op1 .- numI32 4) |> AST.zext 32<rt>)
  !!ir (AST.store Endian.Little address reg)
  !!ir (op1 := address)
  !!ir (dst := AST.xtlo 32<rt> op1)
  !>ir len

let sts ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  match src.E with
  | Var (_, _, r) ->
    if (r = "fpscr" || r = "fpul") then
      let struct (sr, fps, op1) = tmpVars3 ir 32<rt>
      !<ir ins.Address len
      !!ir (sr := !.ctxt R.SR |> AST.zext 32<rt>)
      !!ir (fps := src |> AST.zext 32<rt>)
      fpudisChecker ir ctxt
      !!ir (op1 := fps)
      !!ir (dst := AST.xtlo 32<rt> op1)
      !>ir len
    else
      let struct (reg, op1) = tmpVars2 ir 32<rt>
      !<ir ins.Address len
      !!ir (reg := AST.sext 32<rt> src)
      !!ir (op1 := reg)
      !!ir (dst := AST.xtlo 32<rt> op1)
      !>ir len
  | _ -> Terminator.impossible()

let stsl ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  match src.E with
  | Var (_, _, r) ->
    if (r = "fpscr" || r = "fpul") then
      let struct (sr, reg, op1, address) = tmpVars4 ir 32<rt>
      !<ir ins.Address len
      !!ir (sr := !.ctxt R.SR |> AST.zext 32<rt>)
      !!ir (reg := AST.zext 32<rt> src)
      !!ir (op1 := AST.sext 32<rt> dst)
      fpudisChecker ir ctxt
      !!ir (address := op1 .- numI32 4 |> AST.zext 32<rt>)
      !!ir (op1 := address)
      !!ir (dst := AST.xtlo 32<rt> op1)
      !>ir len
    else
      let struct (reg, op1, address) = tmpVars3 ir 32<rt>
      !<ir ins.Address len
      !!ir (reg := AST.sext 32<rt> src)
      !!ir (op1 := AST.sext 32<rt> dst)
      !!ir (address := (op1 .- numI32 4) |> AST.zext 32<rt>)
      !!ir (AST.store Endian.Little address reg)
      !!ir (op1 := address)
      !!ir (dst := AST.xtlo 32<rt> op1)
      !>ir len
  | _ -> Terminator.impossible()

let sub ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (8)
  let struct (op1, op2) = tmpVars2 ir 32<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.sext 32<rt> src)
  !!ir (op2 := AST.sext 32<rt> dst)
  !!ir (op2 := op2 .- op1)
  !!ir (dst := AST.xtlo 32<rt> op2)
  !>ir len

let subc ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  let struct (op1, op2) = tmpVars2 ir 32<rt>
  let t = !+ir 1<rt>
  !<ir ins.Address len
  !!ir (t := !.ctxt R.T |> AST.zext 1<rt>)
  !!ir (op1 := AST.sext 32<rt> src |> AST.zext 32<rt>)
  !!ir (op1 := AST.sext 32<rt> dst |> AST.zext 32<rt>)
  !!ir (op2 := (op2 .- op1) .- t)
  !!ir (t := AST.extract op2 1<rt> 32)
  !!ir (dst := AST.xtlo 32<rt> op2)
  !!ir (!.ctxt R.T := AST.extract t 1<rt> 1)
  !>ir len

let subv ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (8)
  let struct (op1, op2) = tmpVars2 ir 32<rt>
  let t = !+ir 1<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.sext 32<rt> src)
  !!ir (op2 := AST.sext 32<rt> dst)
  !!ir (op2 := op2 .- op1)
  !!ir (t := ((op2 ?< (pown -2 31 |> numI32PC))
       .| (op2 ?>= (pown 2 31 |> numI32PC))))
  !!ir (dst := AST.xtlo 32<rt> op2)
  !!ir (!.ctxt R.T := AST.extract t 1<rt> 1)
  !>ir len

let swapb ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (8)
  let struct (op1, op2) = tmpVars2 ir 32<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.zext 32<rt> src)
  !!ir (op2 := ((AST.extract op1 16<rt> 16) << (numI32 16))
               .| (AST.extract op1 8<rt> 32)
               .| (AST.extract op1 8<rt> 8))
  !!ir (dst := AST.xtlo 32<rt> op2)
  !>ir len

let swapw ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (8)
  let struct (op1, op2) = tmpVars2 ir 32<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.zext 32<rt> src)
  !!ir (op2 := ((AST.extract op1 16<rt> 32) << (numI32 16))
               .| (AST.extract op1 16<rt> 16))
  !!ir (dst := AST.xtlo 32<rt> op2)
  !>ir len

let tasb ins len ctxt =
  let dst = trsOneOpr ins ctxt
  let ir = IRBuilder (16)
  let struct (op1, address) = tmpVars2 ir 32<rt>
  let value = !+ir 8<rt>
  let t = !+ir 1<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.sext 32<rt> dst)
  !!ir (address := AST.zext 32<rt> op1)
  //OCBP
  !!ir (value := AST.loadLE 8<rt> address |> AST.zext 8<rt>)
  !!ir (t := AST.ite (value == AST.b0) (AST.b1) (AST.b0))
  !!ir (value := value .| (AST.b1 << numI32 7))
  !!ir (AST.store Endian.Little address value)
  !!ir (!.ctxt R.T := AST.extract t 1<rt> 1)
  !>ir len


let trapa ins len ctxt =
  let dst = trsOneOpr ins ctxt
  let ir = IRBuilder (8)
  let imm = !+ir 8<rt>
  !<ir ins.Address len
  !!ir (imm := AST.zext 8<rt> dst)
  if (delaySlot.Count = 1) then illSlot2 ir len ctxt
  else
    trap ir imm ctxt
    !>ir len

let tst ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  let r0 = !+ir 32<rt>
  let imm = !+ir 8<rt>
  let t = !+ir 1<rt>
  !<ir ins.Address len
  !!ir (r0 := !.ctxt R.R0 |> AST.sext 32<rt>)
  !!ir (imm := AST.zext 8<rt> src)
  !!ir (t := (r0 .| imm) == AST.b0)
  !!ir (!.ctxt R.T := AST.extract t 1<rt> 1)
  !>ir len

let tstb ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  let struct (r0, gbr, address) = tmpVars3 ir 32<rt>
  let struct (imm, value) = tmpVars2 ir 8<rt>
  let t = !+ir 1<rt>
  !<ir ins.Address len
  !!ir (r0 := !.ctxt R.R0 |> AST.sext 32<rt>)
  !!ir (gbr := !.ctxt R.GBR |> AST.sext 32<rt>)
  !!ir (imm := AST.zext 8<rt> src)
  !!ir (address := (r0 .+ gbr) |> AST.zext 32<rt>)
  !!ir (value := AST.loadLE 8<rt> address |> AST.zext 8<rt>)
  !!ir (t := (value .| imm) == AST.b0)
  !!ir (!.ctxt R.T := AST.extract t 1<rt> 1)
  !>ir len

let xor ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (8)
  let struct (op1, op2) = tmpVars2 ir 32<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.zext 32<rt> src)
  !!ir (op2 := AST.zext 32<rt> dst)
  !!ir (op2 := op2 <+> op1)
  !!ir (dst := AST.xtlo 32<rt> op2)
  !>ir len

let xorb ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (16)
  let struct (r0, gbr, address) = tmpVars3 ir 32<rt>
  let struct (imm, value) = tmpVars2 ir 8<rt>
  !<ir ins.Address len
  !!ir (r0 := !.ctxt R.R0 |> AST.sext 32<rt>)
  !!ir (gbr := !.ctxt R.GBR |> AST.sext 32<rt>)
  !!ir (imm := src |> AST.zext 8<rt>)
  !!ir (address := (r0 .+ gbr) |> AST.zext 32<rt>)
  !!ir (value := AST.loadLE 8<rt> address |> AST.zext 8<rt>)
  !!ir (value := value <+> imm)
  !!ir (AST.store Endian.Little address value)
  !>ir len

let xtrct ins len ctxt =
  let struct (src, dst) = trsTwoOpr ins ctxt
  let ir = IRBuilder (8)
  let struct (op1, op2) = tmpVars2 ir 32<rt>
  !<ir ins.Address len
  !!ir (op1 := AST.zext 32<rt> src)
  !!ir (op2 := AST.zext 32<rt> dst)
  !!ir (op2 := (AST.xtlo 16<rt> op2) .| (AST.xthi 16<rt> op1))
  !!ir (dst := AST.xtlo 32<rt> op2)
  !>ir len
