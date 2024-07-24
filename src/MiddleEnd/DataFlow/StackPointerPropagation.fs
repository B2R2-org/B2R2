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

type StackPointerPropagation<'E when 'E: equality> =
  inherit IncrementalDataFlowAnalysis<StackPointerDomain.Lattice, 'E>

  new (hdl: BinHandle) =
    let isStackRelatedRegister rid =
      hdl.RegisterFactory.IsStackPointer rid
      || hdl.RegisterFactory.IsFramePointer rid

    /// TODO: move into StackPointerDomain module
    let evalBinOp op c1 c2 =
      match op with
      | BinOpType.ADD -> StackPointerDomain.add c1 c2
      | BinOpType.SUB -> StackPointerDomain.sub c1 c2
      | BinOpType.AND -> StackPointerDomain.``and`` c1 c2
      | _ -> StackPointerDomain.NotConstSP

    let rec evaluateExpr (state: IncrementalDataFlowState<_, _>) pp e =
      match e.E with
      | Num bv -> StackPointerDomain.ConstSP bv
      | Var _ | TempVar _ ->
        state.GetVarDef pp
        |> VarDefDomain.get (VarKind.ofIRExpr e)
        |> Seq.map (state: IDataFlowState<_, _>).GetAbsValue
        |> Seq.reduce StackPointerDomain.join
      | Nil -> StackPointerDomain.NotConstSP
      | Load _ -> StackPointerDomain.NotConstSP
      | UnOp _ -> StackPointerDomain.NotConstSP
      | FuncName _ -> StackPointerDomain.NotConstSP
      | BinOp (op, _, e1, e2) ->
        let c1 = evaluateExpr state pp e1
        let c2 = evaluateExpr state pp e2
        evalBinOp op c1 c2
      | RelOp _ -> StackPointerDomain.NotConstSP
      | Ite _ -> StackPointerDomain.NotConstSP
      | Cast _ -> StackPointerDomain.NotConstSP
      | Extract _ -> StackPointerDomain.NotConstSP
      | Undefined _ -> StackPointerDomain.NotConstSP
      | _ -> Utils.impossible ()

    let evaluateSrcByVarKind state pp src = function
      | Regular rid when isStackRelatedRegister rid -> evaluateExpr state pp src
      | Regular _ -> StackPointerDomain.NotConstSP
      | Temporary _ -> evaluateExpr state pp src
      | _ -> StackPointerDomain.NotConstSP

    let analysis =
      { new IIncrementalDataFlowAnalysis<StackPointerDomain.Lattice, 'E> with
          member __.OnInitialize state = state // FIXME

          member __.Bottom = StackPointerDomain.Undef

          member __.Join a b = StackPointerDomain.join a b

          member __.Subsume a b = StackPointerDomain.subsume a b

          member __.Transfer _g _v pp stmt state =
            match stmt.S with
            | Put (dst, src) ->
              let varKind = VarKind.ofIRExpr dst
              let varPoint = { ProgramPoint = pp; VarKind = varKind }
              let v = evaluateSrcByVarKind state pp src varKind
              Some (varPoint, v)
            // We ignore the data-flow through memory operations in SPP.
            | _ -> None

          member __.EvalExpr state pp e = evaluateExpr state pp e

          member __.GetNextVertices g v =
            (g: IGraph<_, _>).GetSuccs v
            |> Seq.map (fun v -> v.ID) }

    { inherit IncrementalDataFlowAnalysis<StackPointerDomain.Lattice, 'E>
        (hdl, analysis) }
