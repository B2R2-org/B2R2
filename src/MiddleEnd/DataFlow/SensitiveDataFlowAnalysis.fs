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
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.Collections
open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.BinGraph

/// A data-flow analysis that is sensitive to the given auxiliary information.
/// You can use this analysis to implement a sensitive data-flow analysis, such
/// as flow-sensitive analysis, stack-sensitive analysis, and conditional
/// analysis. This is useful especially for binary analysis, where a single
/// basic block can be executed with different contextual information.
/// This analysis is based on sparse data-flow analysis, which boosts the
/// convergence speed of the analysis by avoiding unnecessary computations.
type SensitiveLowUIRDataFlowAnalysis<'L, 'ExeCtx, 'UsrCtx
                                when 'L: equality
                                 and 'ExeCtx: equality
                                 and 'ExeCtx: comparison
                                 and 'UsrCtx: (new: unit -> 'UsrCtx)>
  public (hdl: BinHandle,
          analysis: ISensitiveLowUIRDataFlowAnalysis<'L, 'ExeCtx, 'UsrCtx>) =

  /// Dataflow chains become invalid when a vertex is removed from the graph.
  let rec removeInvalidChains (state: SensitiveLowUIRDataFlowState<_, _, _>) =
    match state.DequeueVertexForRemoval () with
    | true, v when state.PerVertexPossibleTags.ContainsKey v ->
      analysis.OnRemoveVertex state v
      for (_, pp) in state.GetStmtInfos v do
        state.StmtOfBBLs.Remove pp |> ignore
      for tag in state.PerVertexPossibleTags[v] do
        let key = v, tag
        state.PerVertexIncomingDefs.Remove key |> ignore
        state.PerVertexOutgoingDefs.Remove key |> ignore
        state.PerVertexStackPointerInfos.Remove key |> ignore
        state.InvalidateSSAStmts v tag
      state.PerVertexPossibleTags.Remove v |> ignore
      removeInvalidChains state
    | true, _ -> removeInvalidChains state
    | false, _ -> ()

  let getStackValue state pp e =
    match (state: ISensitiveLowUIRDataFlowSubState<_, _>).EvalExpr pp e with
    | StackPointerDomain.ConstSP bv -> Ok <| BitVector.ToUInt64 bv
    | _ -> Error ErrorCase.InvalidExprEvaluation

  /// When a use is removed, we need to remove all the old chains.
  let removeOldChains (state: SensitiveLowUIRDataFlowState<_, _, _>) useId =
    match state.UseDefMap.TryGetValue useId with
    | true, prevDefIds ->
      for prevDefId in prevDefIds do
        (* Erase the old def-use. *)
        let prevDefUses = state.DefUseMap[prevDefId]
        state.DefUseMap[prevDefId] <- Set.remove useId prevDefUses
        (* Erase the old use-def which will be overwritten by the new def. *)
      state.UseDefMap.Remove useId |> ignore
    | _ -> ()

  /// Add a new def-use chain.
  let updateDefUseChain (state: SensitiveLowUIRDataFlowState<_, _, _>)
                        useId defId =
    match state.DefUseMap.TryGetValue defId with
    | false, _ -> state.DefUseMap[defId] <- Set.singleton useId
    | true, uses -> state.DefUseMap[defId] <- Set.add useId uses

  /// Overwrite the use-def chain. Unlike `updateDefUseChain`, this strongly
  /// updates the existing use-def chain, as we already know exactly which
  /// definitions are used by the use at the moment.
  let updateUseDefChain (state: SensitiveLowUIRDataFlowState<_, _, _>) id defs =
    state.UseDefMap[id] <- defs

  let updateChains (state: SensitiveLowUIRDataFlowState<_, _, _>) vk defs tpp =
    match Map.tryFind vk defs with
    | None -> ()
    | Some rds ->
      let useId = state.UseToUid { SensitiveProgramPoint = tpp; VarKind = vk }
      removeOldChains state useId
      for defId in rds do
        updateDefUseChain state useId defId
      updateUseDefChain state useId rds

  let rec updateWithExpr state defs (tpp: SensitiveProgramPoint<_>) = function
    | Num (_)
    | Undefined (_)
    | FuncName (_) -> ()
    | Var (_rt, rid, _rstr, _) -> updateChains state (Regular rid) defs tpp
    | TempVar (_, n, _) -> updateChains state (Temporary n) defs tpp
    | ExprList (exprs, _) ->
      for expr in exprs do
        updateWithExpr state defs tpp expr
    | Load (_, _, expr, _) ->
      updateWithExpr state defs tpp expr
      getStackValue state.StackPointerSubState tpp expr
      |> Result.iter (fun loc ->
        let offset = SensitiveLowUIRDataFlowState<_, _, _>.ToFrameOffset loc
        updateChains state (StackLocal offset) defs tpp)
      updateWithExpr state defs tpp expr
    | UnOp (_, expr, _) ->
      updateWithExpr state defs tpp expr
    | BinOp (_, _, expr1, expr2, _) ->
      updateWithExpr state defs tpp expr1
      updateWithExpr state defs tpp expr2
    | RelOp (_, expr1, expr2, _) ->
      updateWithExpr state defs tpp expr1
      updateWithExpr state defs tpp expr2
    | Ite (expr1, expr2, expr3, _) ->
      updateWithExpr state defs tpp expr1
      updateWithExpr state defs tpp expr2
      updateWithExpr state defs tpp expr3
    | Cast (_, _, expr, _) ->
      updateWithExpr state defs tpp expr
    | Extract (expr, _, _, _) ->
      updateWithExpr state defs tpp expr
    | _ -> ()

  let updateWithJmp state defs pp = function
    | Jmp (expr, _) ->
      updateWithExpr state defs pp expr
    | CJmp (expr, target1, target2, _) ->
      updateWithExpr state defs pp expr
      updateWithExpr state defs pp target1
      updateWithExpr state defs pp target2
    | InterJmp (expr, _jmpKind, _) ->
      updateWithExpr state defs pp expr
    | InterCJmp (cond, target1, target2, _) ->
      updateWithExpr state defs pp cond
      updateWithExpr state defs pp target1
      updateWithExpr state defs pp target2
    | _ -> Terminator.impossible ()

  let isIntraEdge lbl =
    match lbl with
    | IntraCJmpTrueEdge
    | IntraCJmpFalseEdge
    | IntraJmpEdge -> true
    | _ -> false

  let getIncomingDefs (state: SensitiveLowUIRDataFlowState<_, _, _>) v tag =
    let k = v, tag
    match state.PerVertexIncomingDefs.TryGetValue k with
    | false, _ -> Map.empty
    | true, defs -> defs

  let getOutgoingDefs (state: SensitiveLowUIRDataFlowState<_, _, _>) v tag =
    let k = v, tag
    match state.PerVertexOutgoingDefs.TryGetValue k with
    | false, _ -> Map.empty
    | true, defs -> defs

  let getPossibleTags (state: SensitiveLowUIRDataFlowState<_, _, _>) v =
    match state.PerVertexPossibleTags.TryGetValue v with
    | false, _ -> Seq.empty
    | true, s -> s

  let stackPointerToFrameOffset sp =
    match sp with
    | StackPointerDomain.ConstSP bv ->
      BitVector.ToUInt64 bv
      |> SensitiveLowUIRDataFlowState<_, _, _>.ToFrameOffset
    | _ -> Terminator.impossible ()

  /// Join the two reaching definition maps. We filter out temporary variables
  /// here.
  /// TODO: check if it is propagated through intra-block edges like
  /// `VarBasedDataFlowAnalysis`.
  let joinDefs dstInSP (m1: ReachingDefs) (m2: ReachingDefs) =
    let dstInStackOff = stackPointerToFrameOffset dstInSP
    m1 |> Map.fold (fun (changed, acc) vk defs ->
      let shouldBePruned =
        match vk with
        | Temporary _ -> true
        | StackLocal offset when offset < dstInStackOff -> true
        | _ -> false
      if shouldBePruned then changed, acc
      else
        match Map.tryFind vk m2 with
        | None -> true, Map.add vk defs acc
        | Some defs' ->
          let defs'' = Set.union defs defs'
          if defs'' = defs' then changed, acc
          else true, Map.add vk defs'' acc) (false, m2)

  let strongUpdateReachingDef state rds vk tvp =
    let id = (state: SensitiveLowUIRDataFlowState<_, _, _>).DefToUid tvp
    let set = Set.singleton id
    Map.add vk set rds

  /// Strongly updates the stack pointer value for the given tagged variable.
  /// We assume that the stack pointer value is always a constant value in a
  /// single vertex with a single tag (sensitivity).
  let updateStackPointer (state: SensitiveLowUIRDataFlowState<_, _, _>) tpp vk
                         e =
    let subState = state.StackPointerSubState
    let spValue = subState.EvalExpr tpp e
    let tvp = { SensitiveProgramPoint = tpp; VarKind = vk }
    subState.SetAbsValue tvp spValue

  /// (1) Compute the (outgoing) reaching definitions for the given vertex.
  /// (2) Update the def-use/use-def chains on the fly.
  /// (3) We update every stack pointer values while executing the vertex.
  let execute (state: SensitiveLowUIRDataFlowState<_, _, _>)
              (v: IVertex<LowUIRBasicBlock>) tag inDefs =
    let stmtInfos = state.GetStmtInfos v
    let mutable outDefs = inDefs
    for (stmt, pp) in stmtInfos do
      match stmt with
      | Put (dst, src, _) ->
        let varKind = VarKind.ofIRExpr dst
        let tpp = { ProgramPoint = pp; ExecutionContext = tag }
        let tvp = { SensitiveProgramPoint = tpp; VarKind = varKind }
        updateWithExpr state outDefs tpp src
        updateWithExpr state outDefs tpp dst
        updateStackPointer state tpp varKind src
        outDefs <- strongUpdateReachingDef state outDefs varKind tvp
      | Store (_, addr, value, _) ->
        let tpp = { ProgramPoint = pp; ExecutionContext = tag }
        updateWithExpr state outDefs tpp addr
        updateWithExpr state outDefs tpp value
        match state.StackPointerSubState.EvalExpr tpp addr with
        | StackPointerDomain.ConstSP bv ->
          let loc = BitVector.ToUInt64 bv
          let offset = SensitiveLowUIRDataFlowState<_, _, _>.ToFrameOffset loc
          let varKind = StackLocal offset
          let tpp = { ProgramPoint = pp; ExecutionContext = tag }
          let tvp = { SensitiveProgramPoint = tpp; VarKind = varKind }
          // updateStackPointer state tpp varKind value
          outDefs <- strongUpdateReachingDef state outDefs varKind tvp
        | _ -> ()
      | InterJmp (dstExpr, _, _) ->
        let tpp = { ProgramPoint = pp; ExecutionContext = tag }
        updateWithExpr state outDefs tpp dstExpr
      | InterCJmp (condExpr, tExpr, fExpr, _) ->
        let tpp = { ProgramPoint = pp; ExecutionContext = tag }
        updateWithExpr state outDefs tpp condExpr
        updateWithExpr state outDefs tpp tExpr
        updateWithExpr state outDefs tpp fExpr
      | ExternalCall (e, _) ->
        let tpp = { ProgramPoint = pp; ExecutionContext = tag }
        updateWithExpr state outDefs tpp e
      | Jmp _ | CJmp _ -> Terminator.futureFeature ()
      | SideEffect _ -> ()
      | ISMark _ | IEMark _ | LMark _ -> ()
    outDefs

  let prepareQueue (state: SensitiveLowUIRDataFlowState<_, _, _>) g =
    let queue = UniqueQueue ()
    for s, d in state.PendingEdges do
      if not <| (g: IDiGraph<_, _>).HasVertex d.ID then ()
      elif s = null then (* Root node has been created. *)
        let s = s, analysis.DefaultExecutionContext
        let d = d
        queue.Enqueue (s, d)
      elif g.HasVertex s.ID then
        for inSP in getPossibleTags state s do
          let s = s, inSP
          let d = d
          queue.Enqueue (s, d)
    queue

  let tryPropagateRDs state src srcExeCtx dst dstExeCtx =
    let srcOutDefs = getOutgoingDefs state src srcExeCtx
    let dstInDefs = getIncomingDefs state dst dstExeCtx
    let dstInSP =
      if isNull src then
        let spRid = state.BinHandle.RegisterFactory.StackPointer.Value
        let spRegType = state.BinHandle.RegisterFactory.GetRegType spRid
        BitVector.OfUInt64 Constants.InitialStackPointer spRegType
        |> StackPointerDomain.ConstSP
      else snd state.PerVertexStackPointerInfos[src, srcExeCtx]
    match joinDefs dstInSP srcOutDefs dstInDefs with
    | false, _ -> None
    | true, dstInDefs' -> Some dstInDefs'

  let addPossibleTag (state: SensitiveLowUIRDataFlowState<_, _, _>) v tag =
    let possibleTags = state.PerVertexPossibleTags
    let hasSet = possibleTags.ContainsKey v
    if not hasSet then
      possibleTags[v] <- HashSet [ tag ]
      analysis.OnVertexNewlyAnalyzed state v
    else possibleTags[v].Add tag |> ignore

  let getOutSP (state: SensitiveLowUIRDataFlowState<_, _, _>) v tag =
    if isNull v then
      let spRid = state.BinHandle.RegisterFactory.StackPointer.Value
      let spRegType = state.BinHandle.RegisterFactory.GetRegType spRid
      BitVector.OfUInt64 Constants.InitialStackPointer spRegType
      |> StackPointerDomain.ConstSP
    else snd state.PerVertexStackPointerInfos[v, tag]

  let evaluateRecentSP (state: SensitiveLowUIRDataFlowState<_, _, _>) m =
    let spRid = state.BinHandle.RegisterFactory.StackPointer.Value
    let spRegType = state.BinHandle.RegisterFactory.GetRegType spRid
    let spVarKind = Regular spRid
    match Map.tryFind spVarKind m with
    | None ->
      BitVector.OfUInt64 Constants.InitialStackPointer spRegType
      |> StackPointerDomain.ConstSP
    | Some defs ->
      defs
      |> Seq.head
      |> state.UidToDef
      |> state.StackPointerSubState.GetAbsValue

  let executeAndPropagateRDs (state: SensitiveLowUIRDataFlowState<_, _, _>)
                             queue g src dst srcExeCtx dstExeCtx dstDefs =
    let dstKey = dst, dstExeCtx
    let isFirstVisit = not <| state.PerVertexIncomingDefs.ContainsKey dstKey
    let dstOutDefs = getOutgoingDefs state dst dstExeCtx
    let dstOutDefs' = execute state dst dstExeCtx dstDefs
    let dstOutSP = evaluateRecentSP state dstOutDefs'
    let maybeJoinedOutDefs = (* TODO: Reduce cost for joining states. *)
      match joinDefs dstOutSP dstOutDefs dstOutDefs' with
      | false, _ when not isFirstVisit -> None
      | false, _ -> Some dstOutDefs'
      | true, dstOutDefs' -> Some dstOutDefs'
    if isFirstVisit then addPossibleTag state dst dstExeCtx
    match maybeJoinedOutDefs with
    | None -> ()
    | Some dstOutDefs' ->
      let srcOutSP = getOutSP state src srcExeCtx
      let dstOutSP = evaluateRecentSP state dstOutDefs'
      let dstSPInfo = srcOutSP, dstOutSP
      state.PerVertexStackPointerInfos[dstKey] <- dstSPInfo
      state.PerVertexIncomingDefs[dstKey] <- dstDefs
      state.PerVertexOutgoingDefs[dstKey] <- dstOutDefs'
      state.InvalidateSSAStmts dst dstExeCtx (* Caches can be obsolete. *)
      for succ in (g: IDiGraph<_, _>).GetSuccs dst do
        (queue: UniqueQueue<_>).Enqueue ((dst, dstExeCtx), succ)

  /// Compute the successor tag and the reaching definitions for the given
  /// edge. If the edge is infeasible or the reaching definitions do not change,
  /// return None.
  let tryComputeSuccessorTagAndDefs (g: IDiGraph<_, _>) state src srcTag dst =
    if isNull src then Some (analysis.DefaultExecutionContext, Map.empty)
    else
      let edge = g.FindEdge (src, dst)
      let kind = edge.Label
      match analysis.TryComputeExecutionContext state src srcTag dst kind with
      | None -> None (* Infeasible flow. *)
      | Some dstTag ->
        tryPropagateRDs state src srcTag dst dstTag
        |> Option.map (fun dstInDefs -> dstTag, dstInDefs)

  let calculateChains g state =
    let q = prepareQueue state g
    while not q.IsEmpty do
      let (src, srcTag), dst = q.Dequeue ()
      tryComputeSuccessorTagAndDefs g state src srcTag dst
      |> Option.iter (fun (dstTag, defs) ->
        executeAndPropagateRDs state q g src dst srcTag dstTag defs)

  let updateAbsValue state subState defUseMap tvp prev curr =
    if (subState: ISensitiveLowUIRDataFlowSubState<_, _>).Subsume prev curr then
      ()
    else
      subState.SetAbsValue tvp <| subState.Join prev curr
      let id = (state: SensitiveLowUIRDataFlowState<_, _, _>).DefToUid tvp
      match (defUseMap: Dictionary<_, _>).TryGetValue id with
      | false, _ -> ()
      | true, uses ->
        for useId in uses do
          let tvp = state.UidToUse useId
          let tpp = tvp.SensitiveProgramPoint
          subState.DefSiteQueue.Enqueue tpp

  let domainTransfer (state: SensitiveLowUIRDataFlowState<_, _, _>) tag
                     (stmt, pp) =
    match stmt with
    | Put (dst, src, _) ->
      let varKind = VarKind.ofIRExpr dst
      let myPp = { ProgramPoint = pp; ExecutionContext = tag }
      let myVp = { SensitiveProgramPoint = myPp; VarKind = varKind }
      let subState = state.DomainSubState
      let prev = subState.GetAbsValue myVp
      let curr = analysis.EvalExpr state myPp src
      let defUseMap = state.DefUseMap
      updateAbsValue state subState defUseMap myVp prev curr
    | Store (_, addr, value, _) ->
      let tpp = { ProgramPoint = pp; ExecutionContext = tag }
      match state.StackPointerSubState.EvalExpr tpp addr with
      | StackPointerDomain.ConstSP bv ->
        let loc = BitVector.ToUInt64 bv
        let offset = SensitiveLowUIRDataFlowState<_, _, _>.ToFrameOffset loc
        let varKind = StackLocal offset
        let tvp = { SensitiveProgramPoint = tpp; VarKind = varKind }
        let subState = state.DomainSubState
        let prev = subState.GetAbsValue tvp
        let curr = analysis.EvalExpr state tpp value
        let defUseMap = state.DefUseMap
        updateAbsValue state subState defUseMap tvp prev curr
      | _ -> ()
    | _ -> ()

  let isExecuted (state: SensitiveLowUIRDataFlowState<_, _, _>)
                 (subState: ISensitiveLowUIRDataFlowSubState<_, _>) tpp =
    let pp = (tpp: SensitiveProgramPoint<_>).ProgramPoint
    let tag = tpp.ExecutionContext
    match state.StmtOfBBLs.TryGetValue pp with
    | false, _ -> false
    | true, (_, v) -> subState.ExecutedVertices.Contains (v, tag)

  let processDefSite (state: SensitiveLowUIRDataFlowState<_, _, _>)
                     (subState: ISensitiveLowUIRDataFlowSubState<_, _>)
                     fnTransfer =
    match subState.DefSiteQueue.TryDequeue () with
    | true, myPp when isExecuted state subState myPp ->
      let pp = myPp.ProgramPoint
      let tag = myPp.ExecutionContext
      let stmt, _ = state.StmtOfBBLs[pp]
      fnTransfer state tag (stmt, pp)
    | _ -> ()

  let transferFlow g (state: SensitiveLowUIRDataFlowState<_, _, _>)
                   (subState: ISensitiveLowUIRDataFlowSubState<_, _>) v exeCtx
                   fnTransfer =
    let key = v, exeCtx
    subState.ExecutedVertices.Add key |> ignore
    for stmt in state.GetStmtInfos v do fnTransfer state exeCtx stmt done
    (g: IDiGraph<_, _>).GetSuccs v
    |> Array.map (fun succ -> v, exeCtx, succ)
    |> Array.iter subState.FlowQueue.Enqueue

  let tryGetSuccessorExecutionContext (g: IDiGraph<_, _>) state src srcTag dst =
    if isNull src then Some analysis.DefaultExecutionContext
    else
      let edge = g.FindEdge (src, dst)
      let edgeKind = edge.Label
      analysis.TryComputeExecutionContext state src srcTag dst edgeKind

  let processFlow g state subState fnTransfer =
    let subState = subState :> ISensitiveLowUIRDataFlowSubState<_, _>
    match subState.FlowQueue.TryDequeue () with
    | false, _ -> ()
    | true, (src, srcTag, dst) ->
      if not <| subState.ExecutedFlows.Add (src, srcTag, dst) then ()
      else
        match (g: IDiGraph<_, _>).TryFindVertexByID dst.ID with
        | Some dst ->
          match tryGetSuccessorExecutionContext g state src srcTag dst with
          | None -> () (* Prune infeasible flow. *)
          | Some dstTag -> transferFlow g state subState dst dstTag fnTransfer
        | None -> ()

  let registerPendingVertices state subState =
    let subState = subState :> ISensitiveLowUIRDataFlowSubState<_, _>
    for s, d in (state: SensitiveLowUIRDataFlowState<_, _, _>).PendingEdges do
      if isNull s then
        let tag = analysis.DefaultExecutionContext
        subState.FlowQueue.Enqueue (s, tag, d)
      else
        for tag in getPossibleTags state s do
          subState.FlowQueue.Enqueue (s, tag, d)

  let propagateAux g state subState fnTransfer =
    registerPendingVertices state subState
    while not subState.FlowQueue.IsEmpty
          || not subState.DefSiteQueue.IsEmpty do
      processFlow g state subState fnTransfer
      processDefSite state subState fnTransfer

  let propagateDomain g state =
    propagateAux g state state.DomainSubState domainTransfer

  interface IDataFlowAnalysis<SensitiveVarPoint<'ExeCtx>,
                              'L,
                              SensitiveLowUIRDataFlowState<'L, 'ExeCtx,
                                                           'UsrCtx>,
                              LowUIRBasicBlock> with

    member _.InitializeState vs =
      assert (Seq.length vs <= 1) (* Must be a root node. *)
      SensitiveLowUIRDataFlowState<_, _, _> (hdl, analysis)
      |> analysis.OnStateInitialized
      |> fun state ->
        for v in vs do state.MarkEdgeAsPending null v done
        state

    /// Compute the data flow incrementally.
    member _.Compute g state =
      removeInvalidChains state
      calculateChains g state
      propagateDomain g state
      state.ClearPendingEdges ()
      state
