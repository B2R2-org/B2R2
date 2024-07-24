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
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.DataFlow

type UntouchedValueAnalysis<'E when 'E: equality> =
  inherit IncrementalDataFlowAnalysis<UntouchedValueDomain.Lattice, 'E>

  new (hdl: BinHandle) =
    let evaluateVarPoint (state: IncrementalDataFlowState<_, _>)  pp varKind =
      let varDef = state.CalculateIncomingVarDef pp
      let vps = VarDefDomain.get varKind varDef
      if Set.isEmpty vps then (* initialize here *)
        UntouchedValueDomain.RegisterTag varKind
        |> UntouchedValueDomain.Untouched
      else
        vps
        |> Set.map (state: IDataFlowState<_, _>).GetAbsValue
        |> Seq.reduce UntouchedValueDomain.join

    let rec evaluateExpr state pp e =
      match e.E with
      | Var _ | TempVar _ -> evaluateVarPoint state pp (VarKind.ofIRExpr e)
      | Load (_, _, addr) ->
        match state.EvaluateExprIntoConst pp addr with
        | ConstantDomain.Const bv ->
          let addr = BitVector.ToUInt64 bv
          evaluateVarPoint state pp (Memory (Some addr))
        | _ -> UntouchedValueDomain.Touched
      | Extract (e, _, _)
      | Cast (CastKind.ZeroExt, _, e)
      | Cast (CastKind.SignExt, _, e) -> evaluateExpr state pp e
      | _ -> UntouchedValueDomain.Touched

    let analysis =
      { new IIncrementalDataFlowAnalysis<UntouchedValueDomain.Lattice, 'E> with
          member __.OnInitialize state = state // FIXME

          member __.Bottom = UntouchedValueDomain.Undef

          member __.Join a b = UntouchedValueDomain.join a b

          member __.Subsume a b = UntouchedValueDomain.subsume a b

          member __.Transfer _g _v pp stmt state =
            match stmt.S with
            | Put (dst, src) ->
              let varKind = VarKind.ofIRExpr dst
              let varPoint = { ProgramPoint = pp; VarKind = varKind }
              let v = evaluateExpr state pp src
              Some (varPoint, v)
            | Store (_, addr, value) ->
              match state.EvaluateExprIntoConst pp addr with
              | ConstantDomain.Const bv ->
                let varKind = Memory (Some (BitVector.ToUInt64 bv))
                let varPoint = { ProgramPoint = pp; VarKind = varKind }
                let v = evaluateExpr state pp value
                Some (varPoint, v)
              | _ -> None
            | _ -> None

          member __.EvalExpr state pp e = evaluateExpr state pp e

          member __.GetNextVertices g v =
            (g: IGraph<_, _>).GetSuccs v
            |> Seq.map (fun v -> v.ID) }

    { inherit IncrementalDataFlowAnalysis<UntouchedValueDomain.Lattice, 'E>
        (hdl, analysis) }
