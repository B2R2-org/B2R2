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
open System.Collections.Generic

type VarBasedDataFlowAnalysis<'Lattice>
  public (hdl: BinHandle, analysis: IVarBasedDataFlowAnalysis<'Lattice>) =

  /// Dataflow chains become invalid when a vertex is removed from the graph.
  let rec removeInvalidChains (state: VarBasedDataFlowState<_>) =
    match state.DequeueVertexForRemoval () with
    | true, v when state.PerVertexIncomingDefs.ContainsKey v ->
      for (_, pp) in state.GetStmtInfos v do
        state.StmtOfBBLs.Remove pp |> ignore
      state.PhiInfos.Remove v |> ignore
      state.PerVertexIncomingDefs.Remove v |> ignore
      state.PerVertexOutgoingDefs.Remove v |> ignore
      removeInvalidChains state
    | true, _ -> removeInvalidChains state
    | false, _ -> ()

  let getStackValue state pp e =
    match (state: IVarBasedDataFlowSubState<_>).EvalExpr pp e with
    | StackPointerDomain.ConstSP bv -> Ok <| BitVector.ToUInt64 bv
    | _ -> Error ErrorCase.InvalidExprEvaluation

  let getPhiInfo state v =
    match (state: VarBasedDataFlowState<_>).PhiInfos.TryGetValue v with
    | true, dict -> dict
    | false, _ ->
      let dict = Dictionary ()
      state.PhiInfos[v] <- dict
      dict

  /// Linear time algorithm to compute the inverse dominance frontier.
  let computeInverseDF (g: IDiGraph<_, _>) (dom: IDominance<_, _>) v =
    let s = HashSet ()
    for pred in g.GetPreds v do
      let mutable x = pred
      while x <> dom.ImmediateDominator v do
        s.Add x |> ignore
        x <- dom.ImmediateDominator x
    s

  /// Collect the vertices that are candidates for phi insertion at this point.
  /// We reduce the search space to only those vertices that are possibly
  /// affected by the changes in the graph.
  let collectPhiInsertionCandidates g state =
    let workset = HashSet ()
    for v in (state: VarBasedDataFlowState<_>).PendingVertices do
      if not <| (g: IDiGraph<_, _>).HasVertex v.ID then ()
      else
        workset.Add v |> ignore
        for succ in g.GetSuccs v do
          if g.GetPreds succ |> Seq.length > 1 then
            workset.Add succ |> ignore
    workset

  let placePhi state v varKind =
    let phiInfos = (state: VarBasedDataFlowState<_>).PhiInfos
    if not <| phiInfos.ContainsKey v then
      phiInfos[v] <- PhiInfo ()
    let phiInfo = phiInfos[v]
    if not <| phiInfo.ContainsKey varKind then
      phiInfo[varKind] <- Dictionary ()

  let isInnerScopeVarKind (v: IVertex<LowUIRBasicBlock>) = function
    | Temporary _ when v.VData.Internals.PPoint.Address = 0UL -> true
    | _ -> false

  let getDefinedVarKinds memo state v =
    match (memo: Dictionary<_, _>).TryGetValue v with
    | true, kinds -> kinds
    | false, _ ->
      let stackState = (state: VarBasedDataFlowState<_>).StackPointerSubState
      let varKinds = HashSet ()
      for (stmt, pp) in state.GetStmtInfos v do
        match stmt with
        | Put (dst, _, _) ->
          let vk = VarKind.ofIRExpr dst
          varKinds.Add vk |> ignore
        | Store (_, addr, _, _) ->
          getStackValue stackState pp addr
          |> Result.iter (fun loc ->
            let offset = VarBasedDataFlowState<_>.ToFrameOffset loc
            let vk = StackLocal offset
            varKinds.Add vk |> ignore)
        | _ -> ()
      memo[v] <- varKinds
      varKinds

  /// We do not calculate all dominance frontier sets, but only those that are
  /// selectively used to insert phi nodes.
  let placePhis g state (dom: IDominance<_, _>) =
    let memo = Dictionary ()
    for v in collectPhiInsertionCandidates g state do
      for affectingVertex in computeInverseDF g dom v do
        for varKind in getDefinedVarKinds memo state affectingVertex do
          if not (isInnerScopeVarKind v varKind) then
            placePhi state v varKind

  let updateIncomingDefsWithPhis state (v: IVertex<LowUIRBasicBlock>) ins =
    match (state: VarBasedDataFlowState<_>).PhiInfos.TryGetValue v with
    | false, _ -> ins
    | true, phiInfo ->
      let pp = v.VData.Internals.PPoint
      phiInfo.Keys
      |> Seq.fold (fun ins vk ->
        let vp = { ProgramPoint = pp; VarKind = vk }
        Map.add vk vp ins) ins

  let removeOldChains state useVp defVp =
    match (state: VarBasedDataFlowState<_>).UseDefMap.TryGetValue useVp with
    | true, prevDef when prevDef.ProgramPoint <> defVp.ProgramPoint ->
      (* Erase the old def-use. *)
      state.DefUseMap[prevDef].Remove useVp |> ignore
      (* Erase the old use-def which will be overwritten by the new def. *)
      state.UseDefMap.Remove useVp |> ignore
    | _ -> ()

  let updateDefUseChain state useVp defVp =
    match (state: VarBasedDataFlowState<_>).DefUseMap.TryGetValue defVp with
    | false, _ -> state.DefUseMap[defVp] <- HashSet [ useVp ]
    | true, uses -> uses.Add useVp |> ignore

  let updateUseDefChain state useVp defVp =
    (state: VarBasedDataFlowState<_>).UseDefMap[useVp] <- defVp

  let updateChains state vk defs pp =
    match Map.tryFind vk defs with
    | None -> ()
    | Some defVp ->
      let useVp = { ProgramPoint = pp; VarKind = vk }
      removeOldChains state useVp defVp
      updateDefUseChain state useVp defVp
      updateUseDefChain state useVp defVp

  let rec updateWithExpr state defs (pp: ProgramPoint) = function
    | Num (_)
    | Undefined (_)
    | FuncName (_) -> ()
    | Var (_rt, rid, _rstr, _) -> updateChains state (Regular rid) defs pp
    | TempVar (_, n, _) -> updateChains state (Temporary n) defs pp
    | ExprList (exprs, _) ->
      exprs |> List.iter (updateWithExpr state defs pp)
    | Load (_, _, expr, _) ->
      updateWithExpr state defs pp expr
      getStackValue state.StackPointerSubState pp expr
      |> Result.iter (fun loc ->
        let offset = VarBasedDataFlowState<_>.ToFrameOffset loc
        updateChains state (StackLocal offset) defs pp)
      updateWithExpr state defs pp expr
    | UnOp (_, expr, _) ->
      updateWithExpr state defs pp expr
    | BinOp (_, _, expr1, expr2, _) ->
      updateWithExpr state defs pp expr1
      updateWithExpr state defs pp expr2
    | RelOp (_, expr1, expr2, _) ->
      updateWithExpr state defs pp expr1
      updateWithExpr state defs pp expr2
    | Ite (expr1, expr2, expr3, _) ->
      updateWithExpr state defs pp expr1
      updateWithExpr state defs pp expr2
      updateWithExpr state defs pp expr3
    | Cast (_, _, expr, _) ->
      updateWithExpr state defs pp expr
    | Extract (expr, _, _, _) ->
      updateWithExpr state defs pp expr
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

  /// Update DU/UD chains stored in the state as well as the out variables by
  /// executing the given statement. The `defs` stores every definition
  /// including temporary variables, but the `outs` only stores the
  /// non-temporary variables.
  let updateWithStmt state (outs: byref<_>) (defs: byref<_>) stmt pp =
    match stmt with
    | Put (dst, src, _) ->
      updateWithExpr state defs pp src
      let kind = VarKind.ofIRExpr dst
      let vp = { ProgramPoint = pp; VarKind = kind }
      defs <- Map.add kind vp defs
      if not (VarKind.isTemporary kind) then outs <- Map.add kind vp outs
      else ()
    | Store (_, addr, value, _) ->
      updateWithExpr state defs pp addr
      updateWithExpr state defs pp value
      match getStackValue state.StackPointerSubState pp addr with
      | Ok loc ->
        let offset = VarBasedDataFlowState<_>.ToFrameOffset loc
        let kind = StackLocal offset
        let vp = { ProgramPoint = pp; VarKind = kind }
        defs <- Map.add kind vp defs
        if not (VarKind.isTemporary kind) then outs <- Map.add kind vp outs
        else ()
      | _ -> ()
    | Jmp _
    | CJmp _
    | InterJmp _
    | InterCJmp _ -> updateWithJmp state defs pp stmt
    | _ -> ()

  let isIntraEdge lbl =
    match lbl with
    | IntraCJmpTrueEdge
    | IntraCJmpFalseEdge
    | IntraJmpEdge -> true
    | _ -> false

  /// Update the DU/UD chains for the given basic block and return the defined
  /// variables in the block.
  let updateChainsWithBBLStmts g (state: VarBasedDataFlowState<_>) v defs =
    let blkAddr = (v: IVertex<LowUIRBasicBlock>).VData.Internals.PPoint.Address
    let intraBlockContinues =
      (g: IDiGraph<_, _>).GetSuccEdges v
      |> Array.exists (fun e -> isIntraEdge e.Label)
    let stmtInfos = state.GetStmtInfos v
    let mutable outs = defs
    let mutable defs = defs
    let mutable prevAddr = blkAddr
    for i = 0 to stmtInfos.Length - 1 do
      let stmt, pp = stmtInfos[i]
      if pp.Address <> prevAddr then defs <- outs else ()
      updateWithStmt state &outs &defs stmt pp
      prevAddr <- pp.Address
    if intraBlockContinues then defs else outs

  /// Update the def-use/use-def chains for the vertices in the dominator tree.
  let rec update g state domTree (visited: HashSet<_>) v ins =
    assert (not <| visited.Contains v)
    visited.Add v |> ignore
    let ins = updateIncomingDefsWithPhis state v ins
    let outs = updateChainsWithBBLStmts g state v ins
    for child in (domTree: DominatorTree<_, _>).GetChildren v do
      update g state domTree visited child outs
    state.PerVertexIncomingDefs[v] <- ins
    state.PerVertexOutgoingDefs[v] <- outs

  let getOutgoingDefs (state: VarBasedDataFlowState<_>) v =
    match state.PerVertexOutgoingDefs.TryGetValue v with
    | false, _ -> Map.empty
    | true, defs -> defs

  /// We only visit the vertices that have changed and update data-flow chains.
  let rec incrementalUpdate g state visited (dom: IDominance<_, _>) v =
    if (visited: HashSet<_>).Contains v then ()
    elif (state: VarBasedDataFlowState<_>).IsVertexPending v
         && (g: IDiGraph<_, _>).HasVertex v.ID then
      let idom = dom.ImmediateDominator v
      let defs = if isNull idom then Map.empty else getOutgoingDefs state idom
      update g state dom.DominatorTree visited v defs
    else
      for child in dom.DominatorTree.GetChildren v do
        incrementalUpdate g state visited dom child

#if DEBUG
  let hasProperPhiOperandNumbers state g v =
    match (state: VarBasedDataFlowState<_>).PhiInfos.TryGetValue v with
    | false, _ -> true
    | true, phiInfo ->
      let predCount = (g: IDiGraph<_, _>).GetPreds v |> Seq.length
      phiInfo.Values |> Seq.forall (fun d -> d.Count <= predCount)
#endif

  let getEndPP (state: VarBasedDataFlowState<_>) v =
    (state: VarBasedDataFlowState<_>).GetStmtInfos v
    |> Array.last
    |> snd

  let updatePhiWithPredecessor state inDefs pred incomingDef useSite =
    let incomingPP = getEndPP state pred
    match (inDefs: Dictionary<_, _>).TryGetValue incomingPP with
    | true, oldDef when oldDef = incomingDef -> () (* already added *)
    | true, oldDef ->
      state.DefUseMap[oldDef].Remove useSite |> ignore (* remove the old one *)
      inDefs[incomingPP] <- incomingDef
      updateDefUseChain state useSite incomingDef
    | false, _ ->
      inDefs[incomingPP] <- incomingDef
      updateDefUseChain state useSite incomingDef

  /// Update the dataflow information of phis. Unlike Cytron's approach though,
  /// the update process is done **after** the dominator tree traversal. This is
  /// to ensure that the predecessors of phi insertion points are executed
  /// before updating the phi information.
  let updatePhis g (state: VarBasedDataFlowState<_>) visited =
    for v in visited do
      match state.PhiInfos.TryGetValue v with
      | true, phiInfo ->
        for (KeyValue (vk, inDefs)) in phiInfo do
          for pred in (g: IDiGraph<_, _>).GetPreds v do
            match Map.tryFind vk <| getOutgoingDefs state pred with
            | None -> ()
            | Some def ->
              { ProgramPoint = v.VData.Internals.PPoint; VarKind = vk }
              |> updatePhiWithPredecessor state inDefs pred def
      | false, _ -> ()
#if DEBUG
      assert (hasProperPhiOperandNumbers state g v)
#endif

  /// This is a modification of Cytron's algorithm that uses the dominator tree
  /// to calculate the def-use/use-def chains. This has theoretically the same
  /// worst-case time complexity as the original algorithm, but it is more
  /// efficient for incremental changes in practice since its search space is
  /// reduced to the affected vertices that are possibly updated.
  let calculateChains g state dom =
    let visited = HashSet<IVertex<LowUIRBasicBlock>> ()
    placePhis g state dom
    incrementalUpdate g state visited dom g.SingleRoot
    updatePhis g state visited

  let isStackRelatedRegister rid =
    hdl.RegisterFactory.IsStackPointer rid
    || hdl.RegisterFactory.IsFramePointer rid

  let updateAbsValue subState defUseMap vp prev curr =
    if (subState: IVarBasedDataFlowSubState<_>).Subsume prev curr then ()
    else
      subState.SetAbsValue vp <| subState.Join prev curr
      match (defUseMap: Dictionary<_, _>).TryGetValue vp with
      | false, _ -> ()
      | true, defs ->
        defs
        |> Seq.iter (fun vp -> subState.DefSiteQueue.Enqueue vp.ProgramPoint)

  let spTransfer (state: VarBasedDataFlowState<_>) (stmt, pp) =
    match stmt with
    | Put (dst, src, _) ->
      let varKind = VarKind.ofIRExpr dst
      let currConst =
        match varKind with
        | Regular rid when isStackRelatedRegister rid ->
          state.StackPointerSubState.EvalExpr pp src
          |> Some
        | Regular _ -> StackPointerDomain.NotConstSP |> Some
        | Temporary _ -> state.StackPointerSubState.EvalExpr pp src |> Some
        | _ -> None
      match currConst with
      | None -> ()
      | Some currConst ->
        let vp = { ProgramPoint = pp; VarKind = varKind }
        let subState = state.StackPointerSubState
        let prevConst = subState.GetAbsValue vp
        let defUseMap = state.DefUseMap
        updateAbsValue subState defUseMap vp prevConst currConst
    | _ -> ()

  let domainTransfer (state: VarBasedDataFlowState<_>) (stmt, pp) =
    match stmt with
    | Put (dst, src, _) ->
      let varKind = VarKind.ofIRExpr dst
      let vp = { ProgramPoint = pp; VarKind = varKind }
      let subState = state.DomainSubState
      let prev = subState.GetAbsValue vp
      let curr = analysis.EvalExpr state pp src
      let defUseMap = state.DefUseMap
      updateAbsValue subState defUseMap vp prev curr
    | Store (_, addr, value, _) ->
      match state.StackPointerSubState.EvalExpr pp addr with
      | StackPointerDomain.ConstSP bv ->
        let loc = BitVector.ToUInt64 bv
        let offset = VarBasedDataFlowState<_>.ToFrameOffset loc
        let varKind = StackLocal offset
        let vp = { ProgramPoint = pp; VarKind = varKind }
        let subState = state.DomainSubState
        let prev = subState.GetAbsValue vp
        let curr = analysis.EvalExpr state pp value
        let defUseMap = state.DefUseMap
        updateAbsValue subState defUseMap vp prev curr
      | _ -> ()
    | _ -> ()

  let transferPhi state subState phiInfo defPp =
    phiInfo
    |> Seq.iter (fun (KeyValue (varKind, defs: Dictionary<_, _>)) ->
      let vp = { ProgramPoint = defPp; VarKind = varKind }
      let prev = (subState: IVarBasedDataFlowSubState<_>).GetAbsValue vp
      let curr =
        defs.Values |> Seq.fold (fun c (def: VarPoint) ->
          subState.GetAbsValue def
          |> subState.Join c) subState.Bottom
      let defUseMap = (state: VarBasedDataFlowState<_>).DefUseMap
      updateAbsValue subState defUseMap vp prev curr)

  let isExecuted state (subState: IVarBasedDataFlowSubState<_>) defPp =
    match (state: VarBasedDataFlowState<_>).StmtOfBBLs.TryGetValue defPp with
    | false, _ -> false
    | true, (_, v) -> subState.ExecutedVertices.Contains v

  let processDefSite state (subState: IVarBasedDataFlowSubState<_>) fnTransfer =
    match subState.DefSiteQueue.TryDequeue () with
    | true, defPp when isExecuted state subState defPp ->
      if defPp.Position <> 0 then (* non-phi *)
        let stmt, _ = (state: VarBasedDataFlowState<_>).StmtOfBBLs[defPp]
        fnTransfer state (stmt, defPp)
      else (* phi *)
        let _, bbl = state.StmtOfBBLs[defPp]
        assert (state.PhiInfos.ContainsKey bbl)
        transferPhi state subState state.PhiInfos[bbl] defPp
    | _ -> ()

  let transferFlow state subState g v fnTransfer =
    (subState: IVarBasedDataFlowSubState<_>).ExecutedVertices.Add v |> ignore
    (* Execute phis first. *)
    match (state: VarBasedDataFlowState<_>).PhiInfos.TryGetValue v with
    | false, _ -> ()
    | true, phiInfo ->
      transferPhi state subState phiInfo v.VData.Internals.PPoint
    for stmt in state.GetStmtInfos v do fnTransfer state stmt done
    (g: IDiGraph<_, _>).GetSuccs v
    |> Array.map (fun succ -> v, succ)
    |> Array.iter subState.FlowQueue.Enqueue

  let processFlow g state subState fnTransfer =
    match (subState: IVarBasedDataFlowSubState<_>).FlowQueue.TryDequeue () with
    | false, _ -> ()
    | true, (src, dst) ->
      if not <| subState.ExecutedFlows.Add (src, dst) then ()
      else
        match (g: IDiGraph<_, _>).TryFindVertexByID dst.ID with
        | Some v -> transferFlow state subState g v fnTransfer
        | None -> ()

  let registerPendingVertices state (subState: IVarBasedDataFlowSubState<_>) =
    (state: VarBasedDataFlowState<_>).EnqueuePendingVertices subState

  let propagateAux g state subState fnTransfer =
    registerPendingVertices state subState
    while not subState.FlowQueue.IsEmpty
          || not subState.DefSiteQueue.IsEmpty do
      processFlow g state subState fnTransfer
      processDefSite state subState fnTransfer

  let propagateStackPointer g state =
    propagateAux g state state.StackPointerSubState spTransfer

  let propagateDomain g state =
    propagateAux g state state.DomainSubState domainTransfer

  interface IDataFlowAnalysis<VarPoint,
                              'Lattice,
                              VarBasedDataFlowState<'Lattice>,
                              LowUIRBasicBlock> with

    member _.InitializeState vs =
      VarBasedDataFlowState<'Lattice> (hdl, analysis)
      |> analysis.OnInitialize
      |> fun state ->
        for v in vs do state.MarkVertexAsPending v done
        state

    /// Compute the data flow incrementally.
    member _.Compute g state =
      let df = Dominance.CooperDominanceFrontier ()
      let dom = Dominance.LengauerTarjanDominance.create g df
      removeInvalidChains state
      calculateChains g state dom
      propagateStackPointer g state
      calculateChains g state dom
      propagateDomain g state
      state.ClearPendingVertices ()
      state
