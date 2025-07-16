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

open System.Collections.Generic
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.DataFlow.LowUIRSensitiveDataFlow

/// Represents a LowUIR-based sensitive constant propagation analysis. This
/// analysis is aware of stack pointers on basic blocks and distinguishes each
/// basic block by its stack pointer value.
[<AllowNullLiteral>]
type LowUIRSensitiveConstantPropagation (hdl: BinHandle) =
  let perVertexStackPointerDelta = Dictionary<IVertex<LowUIRBasicBlock>, int> ()

  /// Postponed vertices that are not yet processed because the data-flow
  /// analysis has not yet reached them due to incomplete CFG traversal.
  let verticesPostponed = HashSet<IVertex<LowUIRBasicBlock>> ()

  /// Vertices that are resumable, i.e., the data-flow analysis on these
  /// vertices is already completed, and we can resume their analysis on the
  /// CFG.
  let verticesResumable = HashSet<IVertex<LowUIRBasicBlock>> ()

  let getStackPointerId hdl =
    (hdl: BinHandle).RegisterFactory.StackPointer.Value

  let convertStackPointerToInt32 bv = BitVector.ToUInt64 bv |> toFrameOffset

  /// Assuming that the stack pointer is always computed only using the
  /// stack pointer register, we use a lightweight manner to compute the stack
  /// pointer delta for the given vertex. This enables us to keep our design
  /// where we compute stack pointers after reaching definition analysis.
  let rec computeStackPointerDelta (state: State<_, _>) v =
    let spId = getStackPointerId state.BinHandle
    let spRegType = state.BinHandle.RegisterFactory.GetRegType spId
    let stmtInfos = state.GetStmtInfos v
    let initialBV = BitVector.OfUInt64 (Constants.InitialStackPointer) spRegType
    stmtInfos
    |> Array.fold (fun offBV (stmt, _) ->
      match stmt with
      | Put (Var (_, regId, _, _), src, _)
        when regId = spId -> evalStackPointer spId offBV src
      | _ -> offBV) initialBV
    |> convertStackPointerToInt32

  and evalStackPointer spId offBV = function
    | BinOp (binOp, _, e1, e2, _) ->
      let v1 = evalStackPointer spId offBV e1
      let v2 = evalStackPointer spId offBV e2
      match binOp with
      | BinOpType.ADD -> v1 + v2
      | BinOpType.SUB -> v1 - v2
      | _ -> Terminator.impossible ()
    | Num (bv, _) -> bv
    | Var (_, regId, _, _) when regId = spId -> offBV
    | _ -> Terminator.impossible ()

  let getStackPointerDelta state v =
    match perVertexStackPointerDelta.TryGetValue v with
    | true, delta -> delta
    | false, _ ->
      let delta = computeStackPointerDelta state v
      perVertexStackPointerDelta[v] <- delta
      delta

  let isCallRelatedFunction = function
    | "call"
    | "callcode"
    | "delegatecall"
    | "staticcall" -> true
    | _ -> false

  let exprToVar = function
    | SSA.Var v -> v
    | _ -> assert false; Terminator.impossible ()

  /// Finds a path condition that is related to inter-contract calls. We do not
  /// use SMT solvers to solve the path condition, but rather use a simple
  /// pattern matching to gather the path condition and solve it by an
  /// inconsistency check later.
  let rec tryExtractPathCondition (state: State<_, _>) recentVar cond =
    match cond with
    | SSA.Num bv when BitVector.IsOne bv -> Some (recentVar, true)
    | SSA.ExprList exprs -> (* TODO: tail-recursion w/ continuation *)
      exprs |> List.tryPick (fun e ->
        let var = exprToVar e
        match state.TryFindSSADefStmtFromSSAVar var with
        | Some (SSA.Def (_, e)) -> tryExtractPathCondition state var e
        | _ -> None)
    | SSA.BinOp (BinOpType.APP, _, SSA.FuncName callName, _)
      when isCallRelatedFunction callName ->
      Some (recentVar, true)
    | SSA.Cast (_, _, SSA.RelOp (RelOpType.EQ, _, e, SSA.Num bv_0x0))
      when BitVector.IsZero bv_0x0 ->
      match tryExtractPathCondition state recentVar e with
      | Some (d, b) -> Some (d, not b) (* Apply negation. *)
      | _ -> None
    | SSA.Extract (e, _, _) -> tryExtractPathCondition state recentVar e
    | _ -> None

  let isConditionalEdge (edgeKind: CFGEdgeKind) =
    edgeKind.IsInterCJmpTrueEdge || edgeKind.IsInterCJmpFalseEdge

  let computeCondition (state: State<_, _>) (kind: CFGEdgeKind) lastSStmt =
    assert isConditionalEdge kind
    match lastSStmt with
    | SSA.Jmp (SSA.InterCJmp (cond, _, _)) ->
      let fakePP = ProgramPoint.GetFake ()
      let dummyExeCtx = { StackOffset = 0; Conditions = Map.empty }
      let fakeTPP = { ProgramPoint = fakePP
                      ExecutionContext = dummyExeCtx }
      let dummyVarKind = Temporary -1
      let fakeTVP = { SensitiveProgramPoint = fakeTPP; VarKind = dummyVarKind }
      let fakeId = state.DefToUid fakeTVP
      let fakeVar = state.UidToSSAVar fakeId
      tryExtractPathCondition state fakeVar cond
      |> Option.map (fun (v, b) ->
        let b = if kind.IsInterCJmpFalseEdge then not b else b
        v, b)
    | _ -> Terminator.impossible ()

  let makeContext state srcV srcTag maybeDstConditions =
    let srcSP = srcTag.StackOffset
    let delta = getStackPointerDelta state srcV
    let dstSP = srcSP + delta
    let srcConditions = srcTag.Conditions
    let dstConditions = Option.defaultValue srcConditions maybeDstConditions
    Some { StackOffset = dstSP; Conditions = dstConditions }

  /// The successor's incoming stack offset is the outgoing stack offset of the
  /// current vertex. We do lightweight stack pointer computation here, as we
  /// might have not yet propagated stack pointers. Plus, we do selectively
  /// path-sensitive analysis only for specific conditions such as calls and
  /// invariant checks, and this is for avoiding infeasible paths introduced
  /// by the try-catch mechanism in EVM.
  let getSuccessorExecutionContext state srcV srcTag (kind: CFGEdgeKind) =
    if (not << isConditionalEdge) kind then makeContext state srcV srcTag None
    else
      let lastSStmt = state.GetSSAStmts srcV srcTag |> Array.last
      match computeCondition state kind lastSStmt with
      | None -> makeContext state srcV srcTag None
      | Some (var, b) ->
        let defId = state.SSAVarToUid var
        let defSvp = state.UidToDef defId
        let defPP = defSvp.SensitiveProgramPoint.ProgramPoint
        let key = defPP
        let prevConditions = srcTag.Conditions
        let nextConditions =
          match Map.tryFind key prevConditions with
          | None -> Some <| Map.add key b prevConditions
          | Some prevB when prevB = b -> Some prevConditions
          | _ -> None (* Detected inconsistency *)
        match nextConditions with
        | None -> None
        | Some conditions -> makeContext state srcV srcTag (Some conditions)

  let onRemoveVertex v =
    verticesPostponed.Remove v |> ignore
    verticesResumable.Remove v |> ignore
    perVertexStackPointerDelta.Remove v |> ignore

  let evaluateVarPoint (state: State<_, _>) myPp varKind =
    let myVp = { SensitiveProgramPoint = myPp; VarKind = varKind }
    let id = state.UseToUid myVp
    match state.UseDefMap.TryGetValue id with
    | false, _ -> ConstantDomain.Undef
    | true, rds ->
      rds
      |> Seq.fold (fun acc id ->
        let vp = state.UidToDef id
        let v = (state: IAbsValProvider<_, _>).GetAbsValue vp
        ConstantDomain.join acc v) ConstantDomain.Undef

  let rec evaluateExpr state myPp e =
    match e with
    | PCVar (rt, _, _) ->
      let addr = (myPp: SensitiveProgramPoint<_>).ProgramPoint.Address
      let bv = BitVector.OfUInt64 addr rt
      ConstantDomain.Const bv
    | Num (bv, _) -> ConstantDomain.Const bv
    | Var _ | TempVar _ -> evaluateVarPoint state myPp (VarKind.ofIRExpr e)
    | Load (_m, rt, addr, _) ->
      match state.StackPointerSubState.EvalExpr myPp addr with
      | StackPointerDomain.ConstSP bv ->
        let addr = BitVector.ToUInt64 bv
        let offset = LowUIRSparseDataFlow.toFrameOffset addr
        let c = evaluateVarPoint state myPp (StackLocal offset)
        match c with
        | ConstantDomain.Const bv when bv.Length < rt ->
          ConstantDomain.Const <| BitVector.ZExt (bv, rt)
        | ConstantDomain.Const bv when bv.Length > rt ->
          ConstantDomain.Const <| BitVector.Extract (bv, rt, 0)
        | _ -> c
      | StackPointerDomain.NotConstSP -> ConstantDomain.NotAConst
      | StackPointerDomain.Undef -> ConstantDomain.Undef
    | UnOp (op, e, _) ->
      evaluateExpr state myPp e
      |> ConstantPropagation.evalUnOp op
    | BinOp (op, _, e1, e2, _) ->
      let c1 = evaluateExpr state myPp e1
      let c2 = evaluateExpr state myPp e2
      ConstantPropagation.evalBinOp op c1 c2
    | RelOp (op, e1, e2, _) ->
      let c1 = evaluateExpr state myPp e1
      let c2 = evaluateExpr state myPp e2
      ConstantPropagation.evalRelOp op c1 c2
    | Ite (e1, e2, e3, _) ->
      let c1 = evaluateExpr state myPp e1
      let c2 = evaluateExpr state myPp e2
      let c3 = evaluateExpr state myPp e3
      ConstantDomain.ite c1 c2 c3
    | Cast (op, rt, e, _) ->
      let c = evaluateExpr state myPp e
      ConstantPropagation.evalCast op rt c
    | Extract (e, rt, pos, _) ->
      let c = evaluateExpr state myPp e
      ConstantDomain.extract c rt pos
    | FuncName _ | ExprList _ | Undefined _ -> ConstantDomain.NotAConst
    | _ -> Terminator.impossible ()

  let lattice =
    { new ILattice<ConstantDomain.Lattice> with
        member _.Bottom = ConstantDomain.Undef
        member _.Join(a, b) = ConstantDomain.join a b
        member _.Subsume(a, b) = ConstantDomain.subsume a b  }

  let rec scheme =
    { new IScheme<ConstantDomain.Lattice, Tag> with
        member _.DefaultExecutionContext with get () =
          { StackOffset = 0; Conditions = Map.empty }

        member _.TryComputeExecutionContext v tag _dstV edge =
          getSuccessorExecutionContext state v tag edge

        member _.EvalExpr pp expr = evaluateExpr state pp expr

        member _.OnVertexNewlyAnalyzed v =
          if verticesPostponed.Remove v |> not then ()
          else verticesResumable.Add v |> ignore

        member _.OnRemoveVertex v = onRemoveVertex v }

  and state = State<_, _> (hdl, lattice, scheme)

  member _.PostponedVertices with get () = verticesPostponed

  member _.ResumableVertices with get () = verticesResumable

  member _.GetStackPointerDelta state v = getStackPointerDelta state v

  member _.MarkEdgeAsPending src dst = state.MarkEdgeAsPending src dst

  member _.Reset () = state.Reset ()

  interface IDataFlowComputable<SensitiveVarPoint<Tag>,
                                ConstantDomain.Lattice,
                                State<ConstantDomain.Lattice, Tag>,
                                LowUIRBasicBlock> with
    member _.Compute cfg =
      compute cfg state

and Tag = {
  /// The stack offset of the current vertex.
  StackOffset: int
  /// A mapping from a program point to a boolean value indicating whether the
  /// variable defined at that point has been evaluated to true or false.
  /// We do not use SensitiveProgramPoint here because we hate path explosion.
  Conditions: Map<ProgramPoint, bool>
}
