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

namespace B2R2.MiddleEnd.DataFlow

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.ControlFlowGraph

module internal ConstantPropagation =
  let evalUnOp op c =
    match op with
    | UnOpType.NEG -> ConstantDomain.neg c
    | UnOpType.NOT -> ConstantDomain.not c
    | _ -> ConstantDomain.NotAConst

  let evalBinOp op c1 c2 =
    match op with
    | BinOpType.ADD -> ConstantDomain.add c1 c2
    | BinOpType.SUB -> ConstantDomain.sub c1 c2
    | BinOpType.MUL -> ConstantDomain.mul c1 c2
    | BinOpType.DIV -> ConstantDomain.div c1 c2
    | BinOpType.SDIV -> ConstantDomain.sdiv c1 c2
    | BinOpType.MOD -> ConstantDomain.``mod`` c1 c2
    | BinOpType.SMOD -> ConstantDomain.smod c1 c2
    | BinOpType.SHL -> ConstantDomain.shl c1 c2
    | BinOpType.SHR -> ConstantDomain.shr c1 c2
    | BinOpType.SAR -> ConstantDomain.sar c1 c2
    | BinOpType.AND -> ConstantDomain.``and`` c1 c2
    | BinOpType.OR -> ConstantDomain.``or`` c1 c2
    | BinOpType.XOR -> ConstantDomain.xor c1 c2
    | BinOpType.CONCAT -> ConstantDomain.concat c1 c2
    | _ -> ConstantDomain.NotAConst

  let evalRelOp op c1 c2 =
    match op with
    | RelOpType.EQ -> ConstantDomain.eq c1 c2
    | RelOpType.NEQ -> ConstantDomain.neq c1 c2
    | RelOpType.GT -> ConstantDomain.gt c1 c2
    | RelOpType.GE -> ConstantDomain.ge c1 c2
    | RelOpType.SGT -> ConstantDomain.sgt c1 c2
    | RelOpType.SGE -> ConstantDomain.sge c1 c2
    | RelOpType.LT -> ConstantDomain.lt c1 c2
    | RelOpType.LE -> ConstantDomain.le c1 c2
    | RelOpType.SLT -> ConstantDomain.slt c1 c2
    | RelOpType.SLE -> ConstantDomain.sle c1 c2
    | _ -> ConstantDomain.NotAConst

  let evalCast op rt c =
    match op with
    | CastKind.SignExt -> ConstantDomain.signExt rt c
    | CastKind.ZeroExt -> ConstantDomain.zeroExt rt c
    | _ -> ConstantDomain.NotAConst

/// Represents a constant propagation analysis.
type ConstantPropagation(hdl, vs) =
  let evaluateVarPoint (state: ConstantPropagationState) pp varKind =
    let vp = { ProgramPoint = pp; VarKind = varKind }
    match state.UseDefMap.TryGetValue vp with
    | false, _ -> ConstantDomain.Undef
    | true, defVp -> (state: IAbsValProvider<_, _>).GetAbsValue defVp

  let rec evaluateExpr state pp e =
    match e with
    | PCVar(rt, _, _) ->
      let addr = (pp: ProgramPoint).Address
      let bv = BitVector(addr, rt)
      ConstantDomain.Const bv
    | Num(bv, _) -> ConstantDomain.Const bv
    | Var _ | TempVar _ -> evaluateVarPoint state pp (VarKind.ofIRExpr e)
    | Load(_m, rt, addr, _) ->
      match state.EvaluateStackPointerExpr(pp, addr) with
      | StackPointerDomain.ConstSP bv ->
        let addr = BitVector.ToUInt64 bv
        let offset = LowUIRSparseDataFlow.toFrameOffset addr
        let c = evaluateVarPoint state pp (StackLocal offset)
        match c with
        | ConstantDomain.Const bv when bv.Length < rt ->
          ConstantDomain.Const <| BitVector.ZExt(bv, rt)
        | ConstantDomain.Const bv when bv.Length > rt ->
          ConstantDomain.Const <| BitVector.Extract(bv, rt, 0)
        | _ -> c
      | StackPointerDomain.NotConstSP -> ConstantDomain.NotAConst
      | StackPointerDomain.Undef -> ConstantDomain.Undef
    | UnOp(op, e, _) ->
      evaluateExpr state pp e
      |> ConstantPropagation.evalUnOp op
    | BinOp(op, _, e1, e2, _) ->
      let c1 = evaluateExpr state pp e1
      let c2 = evaluateExpr state pp e2
      ConstantPropagation.evalBinOp op c1 c2
    | RelOp(op, e1, e2, _) ->
      let c1 = evaluateExpr state pp e1
      let c2 = evaluateExpr state pp e2
      ConstantPropagation.evalRelOp op c1 c2
    | Ite(e1, e2, e3, _) ->
      let c1 = evaluateExpr state pp e1
      let c2 = evaluateExpr state pp e2
      let c3 = evaluateExpr state pp e3
      ConstantDomain.ite c1 c2 c3
    | Cast(op, rt, e, _) ->
      let c = evaluateExpr state pp e
      ConstantPropagation.evalCast op rt c
    | Extract(e, rt, pos, _) ->
      let c = evaluateExpr state pp e
      ConstantDomain.extract c rt pos
    | FuncName _ | ExprList _ | Undefined _ -> ConstantDomain.NotAConst
    | _ -> Terminator.impossible ()

  let lattice =
    { new ILattice<ConstantDomain.Lattice> with
        member _.Bottom = ConstantDomain.Undef
        member _.Join(a, b) = ConstantDomain.join a b
        member _.Subsume(a, b) = ConstantDomain.subsume a b }

  let rec scheme =
    { new LowUIRSparseDataFlow.IScheme<ConstantDomain.Lattice> with
        member _.EvalExpr(pp, expr) = evaluateExpr state pp expr }

  and state =
    ConstantPropagationState(hdl, lattice, scheme)
    |> fun state ->
      for v in vs do state.MarkVertexAsPending v done
      state

  member _.Reset() = state.Reset()

  member _.MarkVertexAsPending v = state.MarkVertexAsPending v

  member _.MarkVertexAsRemoval v = state.MarkVertexAsRemoval v

  interface IDataFlowComputable<VarPoint,
                                ConstantDomain.Lattice,
                                ConstantPropagationState,
                                LowUIRBasicBlock> with
    member _.Compute cfg =
      LowUIRSparseDataFlow.compute cfg state

and internal ConstantPropagationState =
  LowUIRSparseDataFlow.State<ConstantDomain.Lattice>
