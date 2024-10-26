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
open B2R2.MiddleEnd.BinGraph.Dominator
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

  let updateGlobalName (globals: HashSet<_>) (varKill: HashSet<_>) vk =
    if varKill.Contains vk then ()
    else globals.Add vk |> ignore

  let getStackValue state pp e =
    match (state: IVarBasedDataFlowSubState<_>).EvalExpr pp e with
    | StackPointerDomain.ConstSP bv -> Ok <| BitVector.ToUInt64 bv
    | _ -> Error ErrorCase.InvalidExprEvaluation

  let rec updateGlobals globals varKill stackState pp expr =
    match expr.E with
    | Num _ | Undefined _ | FuncName _ | Name _ | Nil | PCVar _ -> ()
    | Var (_, rid, _) ->
      updateGlobalName globals varKill (Regular rid)
    | TempVar (_, n) ->
      updateGlobalName globals varKill (Temporary n)
    | UnOp (_, e) -> updateGlobals globals varKill stackState pp e
    | BinOp (_, _, lhs, rhs)
    | RelOp (_, lhs, rhs) ->
      updateGlobals globals varKill stackState pp lhs
      updateGlobals globals varKill stackState pp rhs
    | Load (_, _, e) ->
      updateGlobals globals varKill stackState pp e
      getStackValue stackState pp e
      |> Result.iter (fun loc ->
        let offset = VarBasedDataFlowState<_>.ToFrameOffset loc
        updateGlobalName globals varKill (StackLocal offset))
    | Ite (cond, e1, e2) ->
      updateGlobals globals varKill stackState pp cond
      updateGlobals globals varKill stackState pp e1
      updateGlobals globals varKill stackState pp e2
    | Cast (_, _, e) ->
      updateGlobals globals varKill stackState pp e
    | Extract (e, _, _) ->
      updateGlobals globals varKill stackState pp e

  let addDefSite (defSites: Dictionary<_, _>) vk blk =
    match defSites.TryGetValue vk with
    | false, _ -> defSites[vk] <- List [ blk ]
    | true, lst -> lst.Add blk

  /// Iterate over the vertices to find the def sites for each variable kind
  /// (defSites) and the global variables that are live across multible bbls
  /// (globals).
  let findDefVars g state (defSites: Dictionary<_, _>) globals =
    let varKill = HashSet ()
    let stackState = (state: VarBasedDataFlowState<_>).StackPointerSubState
    for v in (g: IGraph<_, _>).Vertices do
      varKill.Clear ()
      for (stmt, pp) in state.GetStmtInfos v do
        match stmt.S with
        | Put (dst, src) ->
          let vk = VarKind.ofIRExpr dst
          updateGlobals globals varKill stackState pp src
          varKill.Add vk |> ignore
          addDefSite defSites vk v
        | Store (_, addr, value) ->
          updateGlobals globals varKill stackState pp value
          getStackValue stackState pp addr
          |> Result.iter (fun loc ->
            let offset = VarBasedDataFlowState<_>.ToFrameOffset loc
            let vk = StackLocal offset
            varKill.Add vk |> ignore
            addDefSite defSites vk v)
        | _ -> ()

  let getPhiInfo state v =
    match (state: VarBasedDataFlowState<_>).PhiInfos.TryGetValue v with
    | true, dict -> dict
    | false, _ ->
      let dict = Dictionary ()
      state.PhiInfos[v] <- dict
      dict

  let placePhis state domCtx globals defSites (frontiers: _[]) =
    let domInfo = domCtx.ForwardDomInfo
    let phiSites = HashSet ()
    for varKind in globals do
      let workList =
        match (defSites: Dictionary<_, List<_>>).TryGetValue varKind with
        | true, defs -> Queue defs
        | false, _ -> Queue ()
      phiSites.Clear ()
      while workList.Count <> 0 do
        let node: IVertex<LowUIRBasicBlock> = workList.Dequeue ()
        let frontier = frontiers[domInfo.DFNumMap[node.ID]]
        for df: IVertex<LowUIRBasicBlock> in frontier do
          if phiSites.Contains df then ()
          else
            match varKind with
            | Temporary _ when df.VData.Internals.PPoint.Position = 0 -> ()
            | _ ->
              let phiInfo = getPhiInfo state df
              if phiInfo.ContainsKey varKind then ()
              else
                (* insert a new phi *)
                phiInfo[varKind] <- Dictionary ()
                (* we may need to update chains from the phi site *)
                state.MarkVertexAsPending df
              phiSites.Add df |> ignore
              workList.Enqueue df

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
    | FuncName (_)
    | Nil -> ()
    | Var (_rt, rid, _rstr) -> updateChains state (Regular rid) defs pp
    | TempVar (_, n) -> updateChains state (Temporary n) defs pp
    | Load (_, _, expr) ->
      updateWithExpr state defs pp expr.E
      getStackValue state.StackPointerSubState pp expr
      |> Result.iter (fun loc ->
        let offset = VarBasedDataFlowState<_>.ToFrameOffset loc
        updateChains state (StackLocal offset) defs pp)
      updateWithExpr state defs pp expr.E
    | UnOp (_, expr) ->
      updateWithExpr state defs pp expr.E
    | BinOp (_, _, expr1, expr2) ->
      updateWithExpr state defs pp expr1.E
      updateWithExpr state defs pp expr2.E
    | RelOp (_, expr1, expr2) ->
      updateWithExpr state defs pp expr1.E
      updateWithExpr state defs pp expr2.E
    | Ite (expr1, expr2, expr3) ->
      updateWithExpr state defs pp expr1.E
      updateWithExpr state defs pp expr2.E
      updateWithExpr state defs pp expr3.E
    | Cast (_, _, expr) ->
      updateWithExpr state defs pp expr.E
    | Extract (expr, _, _) ->
      updateWithExpr state defs pp expr.E
    | _ -> ()

  let updateWithJmp state defs pp = function
    | Jmp ({ E = expr }) ->
      updateWithExpr state defs pp expr
    | CJmp ({ E = expr }, { E = target1 }, { E = target2 }) ->
      updateWithExpr state defs pp expr
      updateWithExpr state defs pp target1
      updateWithExpr state defs pp target2
    | InterJmp ({ E = expr }, _jmpKind) ->
      updateWithExpr state defs pp expr
    | InterCJmp ({ E = cond }, { E = target1 }, { E = target2 }) ->
      updateWithExpr state defs pp cond
      updateWithExpr state defs pp target1
      updateWithExpr state defs pp target2
    | _ -> Utils.impossible ()

  /// Update DU/UD chains stored in the state as well as the out variables by
  /// executing the given statement. The `defs` stores every definition
  /// including temporary variables, but the `outs` only stores the
  /// non-temporary variables.
  let updateWithStmt state (outs: byref<_>) (defs: byref<_>) stmt pp =
    match stmt.S with
    | Put (dst, { E = src }) ->
      updateWithExpr state defs pp src
      let kind = VarKind.ofIRExpr dst
      let vp = { ProgramPoint = pp; VarKind = kind }
      defs <- Map.add kind vp defs
      if not (VarKind.isTemporary kind) then outs <- Map.add kind vp outs
      else ()
    | Store (_, addr, value) ->
      updateWithExpr state defs pp addr.E
      updateWithExpr state defs pp value.E
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
    | InterCJmp _ -> updateWithJmp state defs pp stmt.S
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
      (g: IGraph<_, _>).GetSuccEdges v
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
    if intraBlockContinues then outs else defs

  /// Update the def-use/use-def chains for the vertices in the dominator tree.
  let rec update g state domTree (visited: HashSet<_>) v ins =
    assert (not <| visited.Contains v)
    visited.Add v |> ignore
    let ins = updateIncomingDefsWithPhis state v ins
    let outs = updateChainsWithBBLStmts g state v ins
    traverseSuccessors g state domTree outs visited (Map.find v domTree)
    state.PerVertexIncomingDefs[v] <- ins
    state.PerVertexOutgoingDefs[v] <- outs

  and traverseSuccessors g state domTree outs visited = function
    | succ :: rest ->
      update g state domTree visited succ outs
      traverseSuccessors g state domTree outs visited rest
    | [] -> ()

  let getOutgoingDefs (state: VarBasedDataFlowState<_>) v =
    match state.PerVertexOutgoingDefs.TryGetValue v with
    | false, _ -> Map.empty
    | true, defs -> defs

  /// We only visit the vertices that have changed and update data-flow chains.
  let rec incrementalUpdate g state domTree visited domInfo v =
    if (visited: HashSet<_>).Contains v then ()
    elif (state: VarBasedDataFlowState<_>).IsVertexPending v then
      let dfnum = domInfo.DFNumMap[v.ID]
      let idomNum = domInfo.IDom[dfnum]
      let idom = domInfo.Vertex[idomNum]
      update g state domTree visited v (getOutgoingDefs state idom)
    else
      for child in Map.find v domTree do
        incrementalUpdate g state domTree visited domInfo child

#if DEBUG
  let hasProperPhiOperandNumbers state g v =
    match (state: VarBasedDataFlowState<_>).PhiInfos.TryGetValue v with
    | false, _ -> true
    | true, phiInfo ->
      let predCount = (g: IGraph<_, _>).GetPreds v |> Seq.length
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
          for pred in (g: IGraph<_, _>).GetPreds v do
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
  let calculateChains g state domCtx domTree frontiers =
    let globals = HashSet<VarKind> ()
    let defSites = Dictionary<VarKind, List<IVertex<LowUIRBasicBlock>>> ()
    let visited = HashSet<IVertex<LowUIRBasicBlock>> ()
    let domInfo = domCtx.ForwardDomInfo
    let root = domCtx.ForwardRoot
    findDefVars g state defSites globals
    placePhis state domCtx globals defSites frontiers
    incrementalUpdate g state domTree visited domInfo root
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
    match stmt.S with
    | Put (dst, src) ->
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
    match stmt.S with
    | Put (dst, src) ->
      let varKind = VarKind.ofIRExpr dst
      let vp = { ProgramPoint = pp; VarKind = varKind }
      let subState = state.DomainSubState
      let prev = subState.GetAbsValue vp
      let curr = analysis.EvalExpr state pp src
      let defUseMap = state.DefUseMap
      updateAbsValue subState defUseMap vp prev curr
    | Store (_, addr, value) ->
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
    (g: IGraph<_, _>).GetSuccs v
    |> Array.map (fun succ -> v, succ)
    |> Array.iter subState.FlowQueue.Enqueue

  let processFlow g state subState fnTransfer =
    match (subState: IVarBasedDataFlowSubState<_>).FlowQueue.TryDequeue () with
    | false, _ -> ()
    | true, (src, dst) ->
      if not <| subState.ExecutedFlows.Add (src, dst) then ()
      else
        match (g: IGraph<_, _>).TryFindVertexByID dst.ID with
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

    member __.InitializeState vs =
      VarBasedDataFlowState<'Lattice> (hdl, analysis)
      |> analysis.OnInitialize
      |> fun state ->
        for v in vs do state.MarkVertexAsPending v done
        state

    /// Compute the data flow incrementally.
    member __.Compute g state =
      let domCtx = initDominatorContext g
      let domTree, _ = dominatorTree domCtx
      let domFrontiers = frontiers domCtx
      removeInvalidChains state
      calculateChains g state domCtx domTree domFrontiers
      propagateStackPointer g state
      calculateChains g state domCtx domTree domFrontiers
      propagateDomain g state
      state.ClearPendingVertices ()
      state
