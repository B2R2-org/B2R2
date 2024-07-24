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
open B2R2.MiddleEnd.BinGraph

type VarBasedDataFlowAnalysis<'Lattice, 'E when 'E: equality>
  public (hdl, analysis: IVarBasedDataFlowAnalysis<'Lattice, 'E>) =

  let getStatements (v: IVertex<IRBasicBlock>) =
    v.VData.LiftedInstructions
    |> Array.collect (fun x ->
      let addr = x.Original.Address
      let stmts = x.Stmts
      Array.mapi (fun i stmt -> ProgramPoint (addr, i), stmt) stmts)

  let updateConstant (state: VarBasedDataFlowState<_, _>) vp e =
    let prevConst = state.GetConstant vp
    let currConst = state.EvaluateExprIntoConst vp.ProgramPoint e
    if ConstantDomain.subsume prevConst currConst then false
    else
      state.SetConstant vp <| ConstantDomain.join prevConst currConst
      true

  let transferConstant (state: VarBasedDataFlowState<_, _>) pp stmt =
    if (pp: ProgramPoint).Address = 0x5UL then ()
    match stmt.S with
    | Put (dst, src) ->
      let varKind = VarKind.ofIRExpr dst
      let varPoint = { ProgramPoint = pp; VarKind = varKind }
      updateConstant state varPoint src
    | Store (_, addr, value) ->
      match state.EvaluateExprIntoConst pp addr with
      | ConstantDomain.Const bv ->
        let loc = BitVector.ToUInt64 bv
        let varKind = Memory (Some loc)
        let varPoint = { ProgramPoint = pp; VarKind = varKind }
        updateConstant state varPoint value
      | _ -> false
    | _ -> false

  let updateVarDef (state: VarBasedDataFlowState<_, _>) varDef pp =
    let prevVarDef = state.GetVarDef pp
    if varDef = prevVarDef then false
    else
      state.SetVarDef pp <| VarDefDomain.join prevVarDef varDef
      true

  let transferVarDef (state: VarBasedDataFlowState<_, _>) pp stmt =
    let varDef = state.CalculateIncomingVarDef pp
    match stmt.S with
    | Put (dst, _src) ->
      let dstVarKind = VarKind.ofIRExpr dst
      let vp = { ProgramPoint = pp; VarKind = dstVarKind }
      let vps = Set.singleton vp
      let varDef = Map.add vp.VarKind vps varDef
      updateVarDef state varDef pp
    | Store (_, addr, _value) ->
      match state.EvaluateExprIntoConst pp addr with
      | ConstantDomain.Const bv ->
        let loc = BitVector.ToUInt64 bv
        let varKind = Memory (Some loc)
        let vp = { ProgramPoint = pp; VarKind = varKind }
        let vps = Set.singleton vp
        let varDef = Map.add vp.VarKind vps varDef
        updateVarDef state varDef pp
      | _ -> updateVarDef state varDef pp
    | _ -> updateVarDef state varDef pp

  let transferDom state g v pp stmt =
    match analysis.Transfer g v pp stmt state with
    | None -> false
    | Some (vp, value) ->
      let prevAbsValue = (state :> IDataFlowState<_, _>).GetAbsValue vp
      if analysis.Subsume prevAbsValue value then false
      else
        state.SetAbsValue vp value
        true

  let transferStmt state g v pp stmt =
    let constantChanged = transferConstant state pp stmt
    let varDefChanged = transferVarDef state pp stmt
    let domChanged = transferDom state g v pp stmt
    constantChanged || varDefChanged || domChanged

  let transfer (state: VarBasedDataFlowState<_, _>) g v stmts =
    let mutable hasChanged = false
    let mutable i = 0
    for (pp, stmt) in (stmts: _ []) do
      if i > 0 then state.AddIncomingProgramPoint pp <| fst stmts[i - 1]
      if transferStmt state g v pp stmt then hasChanged <- true
      i <- i + 1
    hasChanged

  let propagate (state: VarBasedDataFlowState<_, _>) g v lastPp =
    for vid in analysis.GetNextVertices g v do
      let nextV = g.FindVertexByID vid
      let pp = nextV.VData.PPoint
      state.AddIncomingProgramPoint pp lastPp
      state.PushWork vid

  let addInitialWorks vs (state: VarBasedDataFlowState<_, _>) =
    vs |> Seq.fold (fun state (v: IVertex<_>) ->
      (state: VarBasedDataFlowState<_, _>).PushWork v.ID
      state) state

  interface IDataFlowAnalysis<VarPoint, 'Lattice,
                              VarBasedDataFlowState<'Lattice, 'E>,
                              IRBasicBlock, 'E> with

    member __.InitializeState vs =
      VarBasedDataFlowState<'Lattice, 'E> (hdl, analysis)
      |> analysis.OnInitialize
      |> addInitialWorks vs

    member __.Compute g state =
      while not <| state.IsWorklistEmpty do
        let vid = state.PopWork ()
        let v = g.FindVertexByID vid
        let stmts = getStatements v
        if transfer state g v stmts then
          propagate state g v <| fst (Array.last stmts)
      state

type private DummyLattice = int

type DummyVarBasedDataFlowAnalysis<'E when 'E: equality> =
  inherit VarBasedDataFlowAnalysis<DummyLattice, 'E>

  new (hdl: BinHandle) =
    let getVid (v: IVertex<_>) = v.ID
    let analysis =
      { new IVarBasedDataFlowAnalysis<DummyLattice, 'E> with
          member __.OnInitialize state = state
          member __.Bottom = 0
          member __.Join _a _b = 0
          member __.Subsume _a _b = true
          member __.Transfer _g _v _pp _stmt _state = None
          member __.EvalExpr _state _pp _e = 0
          member __.GetNextVertices g v = g.GetSuccs v |> Seq.map getVid  }
    { inherit VarBasedDataFlowAnalysis<DummyLattice, 'E> (hdl, analysis) }
