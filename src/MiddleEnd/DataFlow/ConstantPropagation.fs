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
open B2R2.BinIR.LowUIR
open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.ControlFlowGraph

/// Performs sparse constant propagation over the LowUIR representation.
type ConstantPropagation(hdl, vs) =
  let evaluateVarPoint (state: LowUIRSparseDataFlow.State<_>) pp varKind =
    let vp = { ProgramPoint = pp; VarKind = varKind }
    match state.UseDefMap.TryGetValue vp with
    | true, defVp -> state.DomainSubState.GetAbsValue defVp
    | false, _ -> ConstantDomain.Undef

  let rec evaluateExpr state pp e =
    match e with
    | PCVar(rt, _, _) ->
      let addr = (pp: ProgramPoint).Address
      let bv = BitVector(addr, rt)
      ConstantDomain.Const bv
    | Num(bv, _) ->
      ConstantDomain.Const bv
    | Var _ | TempVar _ ->
      evaluateVarPoint state pp (VarKind.ofIRExpr e)
    | Load(_m, rt, addr, _) ->
      match state.EvaluateStackPointerExpr(pp, addr) with
      | StackPointerDomain.ConstSP bv ->
        let addr = bv.ToUInt64()
        let offset = LowUIRStackPointer.toFrameOffset addr
        let c = evaluateVarPoint state pp (StackLocal offset)
        match c with
        | ConstantDomain.Const bv when bv.Length < rt ->
          ConstantDomain.Const <| BitVector.ZExt(bv, rt)
        | ConstantDomain.Const bv when bv.Length > rt ->
          ConstantDomain.Const <| BitVector.Extract(bv, rt, 0)
        | _ ->
          c
      | StackPointerDomain.NotConstSP ->
        ConstantDomain.NotAConst
      | StackPointerDomain.Undef ->
        ConstantDomain.Undef
    | UnOp(op, e, _) ->
      evaluateExpr state pp e
      |> ConstantDomain.evalUnOp op
    | BinOp(op, _, e1, e2, _) ->
      let c1 = evaluateExpr state pp e1
      let c2 = evaluateExpr state pp e2
      ConstantDomain.evalBinOp op c1 c2
    | RelOp(op, e1, e2, _) ->
      let c1 = evaluateExpr state pp e1
      let c2 = evaluateExpr state pp e2
      ConstantDomain.evalRelOp op c1 c2
    | Ite(e1, e2, e3, _) ->
      let c1 = evaluateExpr state pp e1
      let c2 = evaluateExpr state pp e2
      let c3 = evaluateExpr state pp e3
      ConstantDomain.ite c1 c2 c3
    | Cast(op, rt, e, _) ->
      let c = evaluateExpr state pp e
      ConstantDomain.evalCast op rt c
    | Extract(e, rt, pos, _) ->
      let c = evaluateExpr state pp e
      ConstantDomain.extract c rt pos
    | FuncName _ | ExprList _ | Undefined _ ->
      ConstantDomain.NotAConst
    | _ ->
      Terminator.impossible ()

  let lattice = ConstantDomain.createLattice ()

  let rec scheme =
    { new LowUIRSparseDataFlow.IScheme<ConstantDomain.Lattice> with
        member _.GetBaseCase _ = ConstantDomain.NotAConst
        member _.EvalExpr(pp, expr) = evaluateExpr state pp expr }

  and state =
    LowUIRSparseDataFlow.State(hdl, lattice, scheme)
    |> fun state ->
      for v in vs do state.MarkVertexAsPending v done
      state

  /// Returns the underlying state of this analysis.
  member _.State with get() = state

  interface IDataFlowComputable<VarPoint,
                                ConstantDomain.Lattice,
                                LowUIRBasicBlock> with
    member _.Compute cfg = LowUIRSparseDataFlow.compute cfg state
