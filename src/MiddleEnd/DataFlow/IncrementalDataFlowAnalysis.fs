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

type IncrementalDataFlowAnalysis<'Lattice, 'E when 'E: equality>
  public (hdl, analysis: IIncrementalDataFlowAnalysis<'Lattice, 'E>) =

  (* TODO: don't define transfer functions as members. *)
  member private __.TransferConstantAndVarDef pp stmt state =
    let constantChanged = __.TransferConstant pp stmt state
    let varDefChanged = __.TransferVarDef pp stmt state
    constantChanged || varDefChanged

  member private __.TransferConstant pp stmt
                   (state: IncrementalDataFlowState<'Lattice, 'E>) =
    let fnUpdate vp e =
      let prevConst = state.GetConstant vp
      let currConst = state.EvaluateExprIntoConst pp e
      if ConstantDomain.subsume prevConst currConst then false
      else state.SetConstant vp <| ConstantDomain.join prevConst currConst; true
    match stmt.S with
    | Put (dst, src) ->
      let varKind = VarKind.ofIRExpr dst
      let varPoint = { ProgramPoint = pp; VarKind = varKind }
      fnUpdate varPoint src
    | Store (_, addr, value) ->
      match state.EvaluateExprIntoConst pp addr with
      | ConstantDomain.Const bv ->
        let loc = BitVector.ToUInt64 bv
        let varKind = Memory (Some loc)
        let varPoint = { ProgramPoint = pp; VarKind = varKind }
        fnUpdate varPoint value
      | _ -> false
    | _ -> false

  /// Transfer function for var definition analysis.
  /// Note that a source expression is not used here since var definition
  /// analysis does not need to evaluate expressions.
  member private __.TransferVarDef (pp: ProgramPoint) stmt
                   (state: IncrementalDataFlowState<'Lattice, 'E>) =
    let varDef = state.CalculateIncomingVarDef pp
    let varDef =
      match stmt.S with
      | Put (dst, _src) ->
        let dstVarKind = VarKind.ofIRExpr dst
        let vp = { ProgramPoint = pp; VarKind = dstVarKind }
        let vps = Set.singleton vp
        let varDef = Map.add vp.VarKind vps varDef
        varDef
      | Store (_, addr, _value) ->
        match state.EvaluateExprIntoConst pp addr with
        | ConstantDomain.Const bv ->
          let loc = BitVector.ToUInt64 bv
          let varKind = Memory (Some loc)
          let vp = { ProgramPoint = pp; VarKind = varKind }
          let vps = Set.singleton vp
          Map.add vp.VarKind vps varDef
        | _ -> varDef
      | _ -> varDef
    let prevVarDef = state.GetVarDef pp
    if varDef = prevVarDef then false
    else
      let joinedVarDef = VarDefDomain.join prevVarDef varDef
      state.SetVarDef pp joinedVarDef
      true

  interface IDataFlowAnalysis<VarPoint, 'Lattice,
                              IncrementalDataFlowState<'Lattice, 'E>,
                              IRBasicBlock, 'E> with

    member __.InitializeState () =
      IncrementalDataFlowState<'Lattice, 'E> (hdl, analysis)
      |> analysis.OnInitialize

    /// Execute each vertex in the worklist until a fixed point is reached.
    member __.Compute g state =
      while not <| state.IsWorklistEmpty do
        let vid = state.PopWork ()
        let v = g.FindVertexByID vid
        let stmts =
          v.VData.LiftedInstructions
          |> Array.collect (fun x ->
            let addr = x.Original.Address
            x.Stmts |> Array.mapi (fun i stmt -> ProgramPoint (addr, i), stmt))
        (* TODO: what about abstract vertices? they do not have a unqiue
           identifier unlike normal vertices other than VertexID. *)
        let mutable dirty = false
        let mutable lastExecutedPp = None
        for pp, stmt in stmts do
          match lastExecutedPp with
          | None -> ()
          | Some lastPp -> state.AddIncomingProgramPoint pp lastPp
          lastExecutedPp <- Some pp
          match analysis.Transfer g v pp stmt state with
          | None -> ()
          | Some (vp, value) ->
            let prevAbsValue = (state :> IDataFlowState<_, _>).GetAbsValue vp
            if analysis.Subsume prevAbsValue value then ()
            else
              state.SetAbsValue vp value
              dirty <- true
          if __.TransferConstantAndVarDef pp stmt state then
            dirty <- true
        if dirty then
          for vid in analysis.GetNextVertices g v do
            let lastPp = Option.get lastExecutedPp
            let nextV = g.FindVertexByID vid
            let pp = nextV.VData.PPoint
            state.AddIncomingProgramPoint pp lastPp
            state.PushWork vid
      state

(*
[<RequireQualifiedAccess>]
module IncrementalDataFlowAnalysis =
  type DummyLattice = DummyValue

  /// Dummy incremental data flow analysis only for using its internal lattices
  /// such as ConstantDomain and VarDefDomain. We fill the lattice and the
  /// methods with dummy values.
  let createDummy<'E when 'E: equality> (hdl) =
    { new IncrementalDataFlowAnalysis<DummyLattice, 'E> (hdl) with
      override __.Bottom = DummyValue
      override __.subsume (_a, _b) = true
      override __.Join (_a, _b) = __.Bottom
      override __.Transfer (_g, _v, _pp, _stmt) = None }
*)
