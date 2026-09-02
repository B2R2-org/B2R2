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
open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.ControlFlowGraph

/// Performs sparse stack pointer propagation over the LowUIR representation.
type StackPointerPropagation(hdl: BinHandle, vs) =
  let spInitial = LowUIRStackPointer.initialValue hdl

  let getBaseCase varKind =
    match spInitial with
    | Some(stackVar, c) when varKind = stackVar -> c
    | _ -> StackPointerDomain.Undef

  let rec evaluateExpr (state: LowUIRSparseDataFlow.State<_>) pp e =
    match e with
    | Num(bv, _) ->
      StackPointerDomain.ConstSP bv
    | Var _ | TempVar _ ->
      state.GetAbsValueOfUse(pp, VarKind.ofIRExpr e)
    | ExprList _ ->
      StackPointerDomain.NotConstSP
    | Load _ ->
      StackPointerDomain.NotConstSP
    | UnOp _ ->
      StackPointerDomain.NotConstSP
    | FuncName _ ->
      StackPointerDomain.NotConstSP
    | BinOp(op, _, e1, e2, _) ->
      let c1 = evaluateExpr state pp e1
      let c2 = evaluateExpr state pp e2
      StackPointerDomain.evalBinOp op c1 c2
    | RelOp _ ->
      StackPointerDomain.NotConstSP
    | Ite _ ->
      StackPointerDomain.NotConstSP
    | Cast _ ->
      StackPointerDomain.NotConstSP
    | Extract _ ->
      StackPointerDomain.NotConstSP
    | Undefined _ ->
      StackPointerDomain.NotConstSP
    | _ ->
      Terminator.impossible ()

  let lattice = StackPointerDomain.createLattice ()

  let rec scheme =
    { new LowUIRSparseDataFlow.IScheme<StackPointerDomain.Lattice> with
        member _.GetBaseCase varKind = getBaseCase varKind
        member _.EvalExpr(pp, expr) = evaluateExpr state pp expr }

  and state =
    LowUIRSparseDataFlow.State(hdl, lattice, scheme)
    |> fun state ->
      for v in vs do state.MarkVertexAsPending v done
      state

  /// Returns the underlying state of this analysis.
  member _.State with get() = state

  interface IDataFlowComputable<VarPoint,
                                StackPointerDomain.Lattice,
                                LowUIRBasicBlock> with
    member _.Compute cfg = LowUIRSparseDataFlow.compute cfg state
