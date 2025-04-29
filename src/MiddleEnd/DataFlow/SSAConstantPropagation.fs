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

/// Sparse conditional constant propagation analysis on SSACFG.
type SSAConstantPropagation =
  inherit SSAVarBasedDataFlowAnalysis<ConstantDomain.Lattice>

  new (hdl: BinHandle) =
    let evalLoad (state: SSAVarBasedDataFlowState<_>) m rt addr =
      match addr with
      | ConstantDomain.Const addr ->
        let addr = BitVector.ToUInt64 addr
        state.GetMemValue m rt addr
      | _ -> ConstantDomain.NotAConst

    let rec evalExpr (state: SSAVarBasedDataFlowState<_>) = function
      | Num bv -> ConstantDomain.Const bv
      | Var v -> state.GetRegValue v
      | Load (m, rt, addr) ->
        evalExpr state addr |> evalLoad state m rt
      | UnOp (op, _, e) ->
        evalExpr state e |> ConstantPropagation.evalUnOp op
      | BinOp (op, _, e1, e2) ->
        let c1 = evalExpr state e1
        let c2 = evalExpr state e2
        ConstantPropagation.evalBinOp op c1 c2
      | RelOp (op, _, e1, e2) ->
        let c1 = evalExpr state e1
        let c2 = evalExpr state e2
        ConstantPropagation.evalRelOp op c1 c2
      | Ite (e1, _, e2, e3) ->
        let c1 = evalExpr state e1
        let c2 = evalExpr state e2
        let c3 = evalExpr state e3
        ConstantDomain.ite c1 c2 c3
      | Cast (op, rt, e) ->
        let c = evalExpr state e
        ConstantPropagation.evalCast op rt c
      | Extract (e, rt, pos) ->
        let c = evalExpr state e
        ConstantDomain.extract c rt pos
      | FuncName _ | Nil | Undefined _ -> ConstantDomain.NotAConst
      | _ -> Terminator.impossible ()

    let evalDef (state: SSAVarBasedDataFlowState<_>) var e =
      match var.Kind with
      | MemVar -> ()
      | _ -> state.SetRegValue (var, evalExpr state e)

    let evalPhi (state: SSAVarBasedDataFlowState<_>) cfg blk dst srcIDs =
      match state.GetExecutedSources cfg blk srcIDs with
      | [||] -> ()
      | executedSrcIDs ->
        match dst.Kind with
        | MemVar -> ()
        | _ ->
          executedSrcIDs
          |> Array.map (fun i ->
            { dst with Identifier = i } |> state.GetRegValue)
          |> Array.reduce ConstantDomain.join
          |> fun merged -> state.SetRegValue (dst, merged)

    let evalJmp (state: SSAVarBasedDataFlowState<_>) cfg blk =
      state.MarkSuccessorsExecutable cfg blk

    let analysis =
      { new ISSAVarBasedDataFlowAnalysis<ConstantDomain.Lattice> with
          member _.OnInitialize state =
            match hdl.RegisterFactory.StackPointer with
            | Some sp ->
              let rt = hdl.RegisterFactory.GetRegType sp
              let str = hdl.RegisterFactory.GetRegString sp
              let var = { Kind = RegVar (rt, sp, str); Identifier = 0 }
              let spVal = BitVector.OfUInt64 InitialStackPointer rt
              state.SetRegValueWithoutAdding var <| ConstantDomain.Const spVal
              state
            | None -> state

          member _.Bottom with get() = ConstantDomain.Undef

          member _.Join a b = ConstantDomain.join a b

          member _.Transfer ssaCFG blk _pp stmt state =
            match stmt with
            | Def (var, e) -> evalDef state var e
            | Phi (var, ns) -> evalPhi state ssaCFG blk var ns
            | Jmp _ -> evalJmp state ssaCFG blk
            | LMark _ | ExternalCall _ | SideEffect _ -> ()

          member _.Subsume lhs rhs = ConstantDomain.subsume lhs rhs

          member _.UpdateMemFromBinaryFile _rt _addr = ConstantDomain.Undef

          member _.EvalExpr state e = evalExpr state e }

    { inherit SSAVarBasedDataFlowAnalysis<ConstantDomain.Lattice>
        (hdl, analysis) }
