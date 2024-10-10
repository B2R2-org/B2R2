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

namespace B2R2.MiddleEnd.DataFlow.SSA

open B2R2
open B2R2.BinIR.SSA
open B2R2.FrontEnd
open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.DataFlow.Constants

/// Stack pointer propagation analysis on SSACFG.
type SSAStackPointerPropagation =
  inherit SSAVarBasedDataFlowAnalysis<StackPointerDomain.Lattice>

  new (hdl: BinHandle) =
    let rec evalExpr (state: SSAVarBasedDataFlowState<_>) = function
      | Num bv -> StackPointerDomain.ConstSP bv
      | Var v -> state.GetRegValue v
      | Nil -> StackPointerDomain.NotConstSP
      | Load _ -> StackPointerDomain.NotConstSP
      | UnOp _ -> StackPointerDomain.NotConstSP
      | FuncName _ -> StackPointerDomain.NotConstSP
      | BinOp (op, _, e1, e2) ->
        let c1 = evalExpr state e1
        let c2 = evalExpr state e2
        StackPointerPropagation.evalBinOp op c1 c2
      | RelOp _ -> StackPointerDomain.NotConstSP
      | Ite _ -> StackPointerDomain.NotConstSP
      | Cast _ -> StackPointerDomain.NotConstSP
      | Extract _ -> StackPointerDomain.NotConstSP
      | Undefined _ -> StackPointerDomain.NotConstSP
      | _ -> Utils.impossible ()

    let isStackRelatedRegister regId =
      hdl.RegisterFactory.IsStackPointer regId
      || hdl.RegisterFactory.IsFramePointer regId

    let evalDef (state: SSAVarBasedDataFlowState<_>) var e =
      match var.Kind with
      | RegVar (_, regid, _) when isStackRelatedRegister regid ->
        state.SetRegValue (var, evalExpr state e)
      | RegVar _ ->
        state.SetRegValue (var, StackPointerDomain.NotConstSP)
      | TempVar _ ->
        state.SetRegValue (var, evalExpr state e)
      | _ -> ()

    let evalPhi (state: SSAVarBasedDataFlowState<_>) ssaCFG blk dst srcIDs =
      match state.GetExecutedSources ssaCFG blk srcIDs with
      | [||] -> ()
      | executedSrcIDs ->
        match dst.Kind with
        | RegVar _ | TempVar _ ->
          executedSrcIDs
          |> Array.map (fun i ->
            { dst with Identifier = i } |> state.GetRegValue)
          |> Array.reduce StackPointerDomain.join
          |> fun merged -> state.SetRegValue (dst, merged)
        | _ -> ()

    let evalJmp (state: SSAVarBasedDataFlowState<_>) ssaCFG blk =
      state.MarkSuccessorsExecutable ssaCFG blk

    let analysis =
      { new ISSAVarBasedDataFlowAnalysis<StackPointerDomain.Lattice> with
          member _.OnInitialize state =
            match hdl.RegisterFactory.StackPointer with
            | Some sp ->
              let rt = hdl.RegisterFactory.RegIDToRegType sp
              let str = hdl.RegisterFactory.RegIDToString sp
              let var = { Kind = RegVar (rt, sp, str); Identifier = 0 }
              let spVal = BitVector.OfUInt64 InitialStackPointer rt
              state.SetRegValueWithoutPushing var
              <| StackPointerDomain.ConstSP spVal
              state
            | None -> state

          member _.Bottom with get() = StackPointerDomain.Undef

          member _.Join a b = StackPointerDomain.join a b

          member _.Transfer ssaCFG blk _pp stmt state =
            match stmt with
            | Def (var, e) -> evalDef state var e
            | Phi (var, ns) -> evalPhi state ssaCFG blk var ns
            | Jmp _ -> evalJmp state ssaCFG blk
            | LMark _ | ExternalCall _ | SideEffect _ -> ()

          member _.Subsume lhs rhs = StackPointerDomain.subsume lhs rhs

          member _.UpdateMemFromBinaryFile _rt _addr =
            StackPointerDomain.Undef

          member _.EvalExpr state e = evalExpr state e }

    { inherit SSAVarBasedDataFlowAnalysis<StackPointerDomain.Lattice>
        (hdl, analysis) }
