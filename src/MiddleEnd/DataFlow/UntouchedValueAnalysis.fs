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

type UntouchedValueAnalysis =
  inherit VarBasedDataFlowAnalysis<UntouchedValueDomain.Lattice>

  new (hdl: BinHandle) =
    let isStackPointer rid =
      match hdl.RegisterFactory.StackPointer with
      | Some spRid -> rid = spRid
      | None -> false

    let mkUntouched varKind =
      UntouchedValueDomain.RegisterTag varKind
      |> UntouchedValueDomain.Untouched

    let getBaseCase varKind =
      match varKind with
      | Regular rid when isStackPointer rid -> UntouchedValueDomain.Touched
      | Regular _ -> mkUntouched varKind
      | _ -> UntouchedValueDomain.Undef (* not intended *)

    let evaluateVarPoint (state: VarBasedDataFlowState<_>) pp varKind =
      let vp = { ProgramPoint = pp; VarKind = varKind }
      match state.UseDefMap.TryGetValue vp with
      | false, _ -> getBaseCase varKind (* initialize here *)
      | true, defVp -> state.DomainSubState.GetAbsValue defVp

    let rec evaluateExpr state pp e =
      match e with
      | Var _ | TempVar _ -> evaluateVarPoint state pp (VarKind.ofIRExpr e)
      | Load (_, _, addr, _) ->
        match state.StackPointerSubState.EvalExpr pp addr with
        | StackPointerDomain.ConstSP bv ->
          let addr = BitVector.ToUInt64 bv
          let offset = VarBasedDataFlowState<_>.ToFrameOffset addr
          evaluateVarPoint state pp (StackLocal offset)
        | _ -> UntouchedValueDomain.Touched
      | Extract (e, _, _, _)
      | Cast (CastKind.ZeroExt, _, e, _)
      | Cast (CastKind.SignExt, _, e, _) -> evaluateExpr state pp e
      | _ -> UntouchedValueDomain.Touched

    let analysis =
      { new IVarBasedDataFlowAnalysis<UntouchedValueDomain.Lattice> with
          member _.OnInitialize state = state

          member _.Bottom = UntouchedValueDomain.Undef

          member _.Join a b = UntouchedValueDomain.join a b

          member _.Subsume a b = UntouchedValueDomain.subsume a b

          member _.EvalExpr state pp e = evaluateExpr state pp e }

    { inherit VarBasedDataFlowAnalysis<UntouchedValueDomain.Lattice>
        (hdl, analysis) }
