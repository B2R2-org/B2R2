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
open B2R2.FrontEnd
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.DataFlow.LowUIRSensitiveDataFlow

/// Represents a LowUIR-based sensitive constant propagation analysis. This
/// analysis is aware of stack pointers on basic blocks and distinguishes each
/// basic block by its stack pointer value.
[<AllowNullLiteral>]
type LowUIRSensitiveConstantPropagation<'ExeCtx when 'ExeCtx: comparison>
  public (hdl: BinHandle, scheme: IScheme<ConstantDomain.Lattice, 'ExeCtx>) =

  let evaluateVarPoint (state: State<_, _>) spp varKind =
    let svp = { SensitiveProgramPoint = spp; VarKind = varKind }
    match state.UseDefMap.TryGetValue svp with
    | false, _ -> ConstantDomain.Undef
    | true, rds ->
      rds
      |> Seq.fold (fun acc defSvp ->
        (state: IAbsValProvider<_, _>).GetAbsValue defSvp
        |> ConstantDomain.join acc) ConstantDomain.Undef

  let rec evaluateExpr state spp e =
    match e with
    | PCVar (rt, _, _) ->
      let addr = (spp: SensitiveProgramPoint<_>).ProgramPoint.Address
      let bv = BitVector.OfUInt64 addr rt
      ConstantDomain.Const bv
    | Num (bv, _) -> ConstantDomain.Const bv
    | Var _ | TempVar _ -> evaluateVarPoint state spp (VarKind.ofIRExpr e)
    | Load (_m, rt, addr, _) ->
      match state.StackPointerSubState.EvalExpr(spp, addr) with
      | StackPointerDomain.ConstSP bv ->
        let addr = BitVector.ToUInt64 bv
        let offset = LowUIRSparseDataFlow.toFrameOffset addr
        let c = evaluateVarPoint state spp (StackLocal offset)
        match c with
        | ConstantDomain.Const bv when bv.Length < rt ->
          ConstantDomain.Const <| BitVector.ZExt (bv, rt)
        | ConstantDomain.Const bv when bv.Length > rt ->
          ConstantDomain.Const <| BitVector.Extract (bv, rt, 0)
        | _ -> c
      | StackPointerDomain.NotConstSP -> ConstantDomain.NotAConst
      | StackPointerDomain.Undef -> ConstantDomain.Undef
    | UnOp (op, e, _) ->
      evaluateExpr state spp e
      |> ConstantPropagation.evalUnOp op
    | BinOp (op, _, e1, e2, _) ->
      let c1 = evaluateExpr state spp e1
      let c2 = evaluateExpr state spp e2
      ConstantPropagation.evalBinOp op c1 c2
    | RelOp (op, e1, e2, _) ->
      let c1 = evaluateExpr state spp e1
      let c2 = evaluateExpr state spp e2
      ConstantPropagation.evalRelOp op c1 c2
    | Ite (e1, e2, e3, _) ->
      let c1 = evaluateExpr state spp e1
      let c2 = evaluateExpr state spp e2
      let c3 = evaluateExpr state spp e3
      ConstantDomain.ite c1 c2 c3
    | Cast (op, rt, e, _) ->
      let c = evaluateExpr state spp e
      ConstantPropagation.evalCast op rt c
    | Extract (e, rt, pos, _) ->
      let c = evaluateExpr state spp e
      ConstantDomain.extract c rt pos
    | FuncName _ | ExprList _ | Undefined _ -> ConstantDomain.NotAConst
    | _ -> Terminator.impossible ()

  let lattice =
    { new ILattice<ConstantDomain.Lattice> with
        member _.Bottom = ConstantDomain.Undef
        member _.Join(a, b) = ConstantDomain.join a b
        member _.Subsume(a, b) = ConstantDomain.subsume a b  }

  let mutable evaluator = null

  let rec state = State<_, _> (hdl, lattice, scheme, evaluator)

  do evaluator <-
      { new IExprEvaluatable<SensitiveProgramPoint<'ExeCtx>,
                             ConstantDomain.Lattice> with
          member _.EvalExpr(pp, expr) = evaluateExpr state pp expr }

  member _.EvalExpr pp e = evaluateExpr pp e

  member _.MarkEdgeAsPending src dst = state.MarkEdgeAsPending src dst

  member _.Reset () = state.Reset ()

  member _.State with get () = state

  interface IDataFlowComputable<SensitiveVarPoint<'ExeCtx>,
                                ConstantDomain.Lattice,
                                State<ConstantDomain.Lattice, 'ExeCtx>,
                                LowUIRBasicBlock> with
    member _.Compute cfg =
      compute cfg state
