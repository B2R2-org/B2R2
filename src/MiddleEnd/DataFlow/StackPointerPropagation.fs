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
open B2R2.FrontEnd
open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.ControlFlowGraph

module internal StackPointerPropagation =
  let evalBinOp op c1 c2 =
    match op with
    | BinOpType.ADD -> StackPointerDomain.add c1 c2
    | BinOpType.SUB -> StackPointerDomain.sub c1 c2
    | BinOpType.AND -> StackPointerDomain.``and`` c1 c2
    | _ -> StackPointerDomain.NotConstSP

type StackPointerPropagation(hdl: BinHandle, vs) =
  let initialStackPointerValue =
    hdl.RegisterFactory.StackPointer
    |> Option.get
    |> hdl.RegisterFactory.GetRegType
    |> fun rt -> BitVector(Constants.InitialStackPointer, rt)
    |> StackPointerDomain.ConstSP

  let isStackPointer rid =
    match hdl.RegisterFactory.StackPointer with
    | Some spRid -> rid = spRid
    | None -> false

  let getBaseCase varKind =
    match varKind with
    | Regular rid when isStackPointer rid -> initialStackPointerValue
    | _ -> StackPointerDomain.Undef

  let evaluateVarPoint (state: StackPointerPropagationState) pp varKind =
    let vp = { ProgramPoint = pp; VarKind = varKind }
    match state.UseDefMap.TryGetValue vp with
    | true, defVp when ProgramPoint.IsFake(defVp.ProgramPoint) ->
      getBaseCase varKind
    | true, defVp ->
      state.DomainSubState.GetAbsValue defVp
    | false, _ -> StackPointerDomain.Undef

  let rec evaluateExpr (state: StackPointerPropagationState) pp e =
    match e with
    | Num(bv, _) -> StackPointerDomain.ConstSP bv
    | Var _ | TempVar _ -> evaluateVarPoint state pp (VarKind.ofIRExpr e)
    | ExprList _ -> StackPointerDomain.NotConstSP
    | Load _ -> StackPointerDomain.NotConstSP
    | UnOp _ -> StackPointerDomain.NotConstSP
    | FuncName _ -> StackPointerDomain.NotConstSP
    | BinOp(op, _, e1, e2, _) ->
      let c1 = evaluateExpr state pp e1
      let c2 = evaluateExpr state pp e2
      StackPointerPropagation.evalBinOp op c1 c2
    | RelOp _ -> StackPointerDomain.NotConstSP
    | Ite _ -> StackPointerDomain.NotConstSP
    | Cast _ -> StackPointerDomain.NotConstSP
    | Extract _ -> StackPointerDomain.NotConstSP
    | Undefined _ -> StackPointerDomain.NotConstSP
    | _ -> Terminator.impossible ()

  let lattice =
    { new ILattice<StackPointerDomain.Lattice> with
        member _.Bottom = StackPointerDomain.Undef
        member _.Join(a, b) = StackPointerDomain.join a b
        member _.Subsume(a, b) = StackPointerDomain.subsume a b }

  let rec scheme =
    { new LowUIRSparseDataFlow.IScheme<StackPointerDomain.Lattice> with
        member _.EvalExpr(pp, expr) = evaluateExpr state pp expr }

  and state =
    StackPointerPropagationState(hdl, lattice, scheme)
    |> fun state ->
      for v in vs do state.MarkVertexAsPending v done
      state

  interface IDataFlowComputable<VarPoint,
                                StackPointerDomain.Lattice,
                                StackPointerPropagationState,
                                LowUIRBasicBlock> with
    member _.Compute cfg = LowUIRSparseDataFlow.compute cfg state

and internal StackPointerPropagationState =
  LowUIRSparseDataFlow.State<StackPointerDomain.Lattice>
