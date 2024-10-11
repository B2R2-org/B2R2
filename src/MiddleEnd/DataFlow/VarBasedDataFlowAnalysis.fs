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

/// This module contains the implementation of incremental data flow analysis
/// that calculates def-use/use-def chains.
[<RequireQualifiedAccess>]
module private Chains =
  let collectDefsFromStmt state (defs: HashSet<VarKind>) pp stmt =
    match stmt.S with
    | Put (dst, _) ->
      let vk = VarKind.ofIRExpr dst
      defs.Add vk |> ignore
    | Store (_, addr, _) ->
      (state: IVarBasedDataFlowSubState<_>).EvalExpr pp addr
      |> function
        | StackPointerDomain.ConstSP bv ->
          let loc = BitVector.ToUInt64 bv
          let vk = Memory (Some loc)
          defs.Add vk |> ignore
        | _ -> ()
    | _ -> ()

  let updateAndGetInnerDefs (state: VarBasedDataFlowState<_>) v =
    let defs = HashSet ()
    let stackState = state.StackPointerSubState
    for (stmt, pp) in state.GetStmtInfos v do
      collectDefsFromStmt stackState defs pp stmt
    state.PerVertexInnerDefs[v] <- defs
    defs

  /// Calculates the set of def sites for each variable kind. This is used to
  /// update the phi information. Note that we update the inner definitions here
  /// to apply the former changes (e.g. stack pointer propagation).
  let calculateDefSites g state =
    let defSites = Dictionary ()
    (g: IGraph<_, _>).IterVertex (fun v ->
      for varKind in updateAndGetInnerDefs state v do
        match defSites.TryGetValue varKind with
        | false, _-> defSites[varKind] <- List [ v ]
        | true, lst -> lst.Add v)
    defSites

  let removeOldDefUses state useVp defVp =
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

  let inline updateUseDefChain state useVp defVp =
    (state: VarBasedDataFlowState<_>).UseDefMap[useVp] <- defVp

  let updateChains state vk defs pp =
    match Map.tryFind vk defs with
    | None -> ()
    | Some defVp ->
      let useVp = { ProgramPoint = pp; VarKind = vk }
      removeOldDefUses state useVp defVp
      updateDefUseChain state useVp defVp
      updateUseDefChain state useVp defVp

  let rec executeExpr state defs (pp: ProgramPoint) = function
    | Num (_)
    | Undefined (_)
    | FuncName (_)
    | Nil -> ()
    | Var (_rt, rid, _rstr) -> updateChains state (Regular rid) defs pp
    | TempVar (_, n) -> updateChains state (Temporary n) defs pp
    | Load (_, _, expr) ->
      executeExpr state defs pp expr.E
      match state.StackPointerSubState.EvalExpr pp expr with
      | StackPointerDomain.ConstSP bv ->
        let loc = BitVector.ToUInt64 bv
        updateChains state (Memory (Some loc)) defs pp
      | _ -> ()
      executeExpr state defs pp expr.E
    | UnOp (_, expr) ->
      executeExpr state defs pp expr.E
    | BinOp (_, _, expr1, expr2) ->
      executeExpr state defs pp expr1.E
      executeExpr state defs pp expr2.E
    | RelOp (_, expr1, expr2) ->
      executeExpr state defs pp expr1.E
      executeExpr state defs pp expr2.E
    | Ite (expr1, expr2, expr3) ->
      executeExpr state defs pp expr1.E
      executeExpr state defs pp expr2.E
      executeExpr state defs pp expr3.E
    | Cast (_, _, expr) ->
      executeExpr state defs pp expr.E
    | Extract (expr, _, _) ->
      executeExpr state defs pp expr.E
    | _ -> ()

  let executeJmp state defs pp = function
    | Jmp ({ E = expr }) ->
      executeExpr state defs pp expr
    | CJmp ({ E = expr }, { E = target1 }, { E = target2 }) ->
      executeExpr state defs pp expr
      executeExpr state defs pp target1
      executeExpr state defs pp target2
    | InterJmp ({ E = expr }, _jmpKind) ->
      executeExpr state defs pp expr
    | InterCJmp ({ E = cond }, { E = target1 }, { E = target2 }) ->
      executeExpr state defs pp cond
      executeExpr state defs pp target1
      executeExpr state defs pp target2
    | _ -> Utils.impossible ()

  /// Update DU/UD chains stored in the state as well as the out variables by
  /// executing the given statement. The `defs` stores every definition
  /// including temporary variables, but the `outs` only stores the
  /// non-temporary variables.
  let executeStmt state (outs: byref<_>) (defs: byref<_>) stmt pp =
    match stmt.S with
    | Put (dst, { E = src }) ->
      executeExpr state defs pp src
      let kind = VarKind.ofIRExpr dst
      let vp = { ProgramPoint = pp; VarKind = kind }
      defs <- Map.add kind vp defs
      if not (VarKind.isTemporary kind) then outs <- Map.add kind vp outs
      else ()
    | Store (_, addr, value) ->
      executeExpr state defs pp addr.E
      executeExpr state defs pp value.E
      match state.StackPointerSubState.EvalExpr pp addr with
      | StackPointerDomain.ConstSP bv ->
        let loc = BitVector.ToUInt64 bv
        let kind = Memory (Some loc)
        let vp = { ProgramPoint = pp; VarKind = kind }
        defs <- Map.add kind vp defs
        if not (VarKind.isTemporary kind) then outs <- Map.add kind vp outs
        else ()
      | _ -> ()
    | Jmp _
    | CJmp _
    | InterJmp _
    | InterCJmp _ -> executeJmp state defs pp stmt.S
    | _ -> ()

  let inline isIntraEdge lbl =
    match lbl with
    | IntraCJmpTrueEdge
    | IntraCJmpFalseEdge
    | IntraJmpEdge -> true
    | _ -> false

  let executeBBL g (state: VarBasedDataFlowState<_>) v defs =
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
      executeStmt state &outs &defs stmt pp
      prevAddr <- pp.Address
    if intraBlockContinues then outs else defs

  /// Updates the def-use chain whose use exists in the successors.
  let rec executePhi state m child =
    let phiInfos = (state: VarBasedDataFlowState<_>).PhiInfos
    match phiInfos.TryGetValue child with
    | false, _ -> ()
    | true, phiInfo ->
      phiInfo.Keys
      |> Seq.filter (fun vk -> Map.containsKey vk m)
      |> Seq.iter (fun vk -> executePhiAux state vk m[vk] child)

  and executePhiAux (state: VarBasedDataFlowState<_>) varKind defVp v =
    assert (state.PhiInfos.ContainsKey v)
    let phiInfo = state.PhiInfos[v]
    (* Add this defSite to the current phi info. *)
    let prevDefs = phiInfo[varKind]
    phiInfo[varKind] <- Set.add defVp prevDefs
    (* And, update the def-use chain. *)
    let useVp = { ProgramPoint = v.VData.Internals.PPoint; VarKind = varKind }
    updateDefUseChain state useVp defVp

  let executeSuccessorPhis state g v outs  =
    (g: IGraph<_, _>).GetSuccs v
    |> Seq.iter (executePhi state outs)

  let addPhis phiInfos vid pp ins =
    match (phiInfos: Dictionary<_, PhiInfo>).TryGetValue vid with
    | false, _ -> ins
    | true, phiInfo ->
      phiInfo.Keys
      |> Seq.fold (fun ins vk ->
        let vp = { ProgramPoint = pp; VarKind = vk }
        Map.add vk vp ins) ins

  /// Updates the def-use/use-def chains for the vertices in the dominator tree.
  let rec update g state domTree (visited: HashSet<_>) v ins =
    assert (not <| visited.Contains v)
    visited.Add v |> ignore
    let phiInfos = (state: VarBasedDataFlowState<_>).PhiInfos
    let ins = addPhis phiInfos v v.VData.Internals.PPoint ins
    let outs = executeBBL g state v ins
    executeSuccessorPhis state g v outs
    traverseChildren g state domTree outs visited (Map.find v domTree)
    state.PerVertexIncomingDefs[v] <- ins
    state.PerVertexOutgoingDefs[v] <- outs

  and traverseChildren g state domTree m visited = function
    | child :: rest ->
      update g state domTree visited child m
      traverseChildren g state domTree m visited rest
    | [] -> ()

  let getOutgoingDefs (state: VarBasedDataFlowState<_>) v =
    match state.PerVertexOutgoingDefs.TryGetValue v with
    | false, _ -> Map.empty
    | true, defs -> defs

  let getIncomingDefs g (state: VarBasedDataFlowState<_>) v =
    match state.PerVertexIncomingDefs.TryGetValue v with
    | true, defs -> defs
    | false, _ ->
      (g: IGraph<_, _>).GetPreds v
      |> Array.fold (fun defs pred ->
        getOutgoingDefs state pred
        |> Map.fold (fun defs vk def -> Map.add vk def defs) defs
      ) Map.empty

  /// We visits the dominator tree in a depth-first manner to calculate the
  /// def-use/use-def chains as Cytron's SSA construction algorithm does.
  /// But, we are only interested in the vertices that have changes in the CFG,
  /// so we only visit the vertices that are possibly updated by the changes.
  let rec visitDomTree g (s: VarBasedDataFlowState<_>) domTree visited v =
    if (visited: HashSet<_>).Contains v then ()
    elif s.IsVertexPending v then
      update g s domTree visited v (getIncomingDefs g s v)
    else List.iter (visitDomTree g s domTree visited) (Map.find v domTree)

  let getPhiInfo state vid =
    match (state: VarBasedDataFlowState<_>).PhiInfos.TryGetValue vid with
    | true, dict -> dict
    | false, _ ->
      let dict = Dictionary ()
      state.PhiInfos[vid] <- dict
      dict

  /// Refer to Cytron's algorithm.
  let addPhi state varKind (phiSites, worklist) v =
    if Set.contains (v: IVertex<LowUIRBasicBlock>) phiSites then
      phiSites, worklist
    else
      match varKind with
      | Temporary _ when v.VData.Internals.PPoint.Position = 0 ->
        phiSites, worklist
      | _ ->
        let phiInfo = getPhiInfo state v
        if phiInfo.ContainsKey varKind then ()
        else
          (* insert a new phi *)
          phiInfo[varKind] <- Set.empty
          (* we may need to update chains from the phi site *)
          state.MarkVertexAsPending v
        let phiSites = Set.add v phiSites
        let innerDef = state.PerVertexInnerDefs[v]
        if not <| innerDef.Contains varKind then
          phiSites, v :: worklist (* add the current vertex to the worklist *)
        else phiSites, worklist

  /// Refer to Cytron's algorithm.
  let rec iterDefs state phiSites vk forwardDomInfo frontiers worklist =
    match worklist with
    | [] -> ()
    | (v: IVertex<_>) :: tl ->
      let dfNum = (forwardDomInfo: DomInfo<_>).DFNumMap[v.ID]
      let frontier = (frontiers: IVertex<_> list [])[dfNum]
      let phiSites, tl = List.fold (addPhi state vk) (phiSites, tl) frontier
      iterDefs state phiSites vk forwardDomInfo frontiers tl

  /// Updates the phi information of the vertices using dominance frontiers.
  let updatePhiInfos state perVarKindDefSites domCtx frontiers =
    let domInfo = (domCtx: DominatorContext<_, _>).ForwardDomInfo
    for KeyValue (varKind, defs) in perVarKindDefSites do
      iterDefs state Set.empty varKind domInfo frontiers (Seq.toList defs)

  /// This is a modification of Cytron's algorithm that uses the dominator tree
  /// to calculate the def-use/use-def chains. This has theoretically the same
  /// worst-case time complexity as the original algorithm, but it is more
  /// efficient for incremental changes in practice since its search space is
  /// reduced to the affected vertices that are possibly updated.
  let calculate g state domCtx domTree frontiers =
    let perVarKindDefSites = calculateDefSites g state
    updatePhiInfos state perVarKindDefSites domCtx frontiers
    visitDomTree g state domTree (HashSet ()) domCtx.ForwardRoot

/// This module contains the implementation of incremental data flow analysis
/// that propagates the data flow values.
[<RequireQualifiedAccess>]
module private Propagation =
  let isStackRelatedRegister hdl rid =
    (hdl: BinHandle).RegisterFactory.IsStackPointer rid
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

  let spTransfer hdl (state: VarBasedDataFlowState<_>) _ (stmt, pp) =
    match stmt.S with
    | Put (dst, src) ->
      let varKind = VarKind.ofIRExpr dst
      let currConst =
        match varKind with
        | Regular rid when isStackRelatedRegister hdl rid ->
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

  let domainTransfer _ (state: VarBasedDataFlowState<_>) analysis (stmt, pp) =
    match stmt.S with
    | Put (dst, src) ->
      let varKind = VarKind.ofIRExpr dst
      let vp = { ProgramPoint = pp; VarKind = varKind }
      let subState = state.DomainSubState
      let prev = subState.GetAbsValue vp
      let curr = (analysis: IVarBasedDataFlowAnalysis<_>).EvalExpr state pp src
      let defUseMap = state.DefUseMap
      updateAbsValue subState defUseMap vp prev curr
    | Store (_, addr, value) ->
      match state.StackPointerSubState.EvalExpr pp addr with
      | StackPointerDomain.ConstSP bv ->
        let loc = BitVector.ToUInt64 bv
        let varKind = Memory (Some loc)
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
    |> Seq.iter (fun (KeyValue (varKind, defs)) ->
      let vp = { ProgramPoint = defPp; VarKind = varKind }
      let prev = (subState: IVarBasedDataFlowSubState<_>).GetAbsValue vp
      let curr =
        defs |> Set.fold (fun c (def: VarPoint) ->
          subState.GetAbsValue def
          |> subState.Join c) subState.Bottom
      let defUseMap = (state: VarBasedDataFlowState<_>).DefUseMap
      updateAbsValue subState defUseMap vp prev curr)

  let isExecuted state (subState: IVarBasedDataFlowSubState<_>) defPp =
    match (state: VarBasedDataFlowState<_>).StmtOfBBLs.TryGetValue defPp with
    | false, _ -> false
    | true, (_, v) -> subState.ExecutedVertices.Contains v

  let isPhiProgramPoint state pp =
    let _, v = (state: VarBasedDataFlowState<_>).StmtOfBBLs[pp]
    let pp' = v.VData.Internals.PPoint
    pp = pp'

  let inline tryDequeueDefSite (subState: IVarBasedDataFlowSubState<_>) =
    subState.DefSiteQueue.TryDequeue ()

  let processDefSite hdl state analysis subState fnTransfer =
    match tryDequeueDefSite subState with
    | true, defPp when isExecuted state subState defPp ->
      if not <| isPhiProgramPoint state defPp then (* non-phi *)
        let stmt, _ = (state: VarBasedDataFlowState<_>).StmtOfBBLs[defPp]
        fnTransfer hdl state analysis (stmt, defPp)
      else (* phi *)
        let _, bbl = state.StmtOfBBLs[defPp]
        assert (state.PhiInfos.ContainsKey bbl)
        transferPhi state subState state.PhiInfos[bbl] defPp
    | _ -> ()

  let transferFlow hdl state analysis subState g v fnTransfer =
    (subState: IVarBasedDataFlowSubState<_>).ExecutedVertices.Add v |> ignore
    (* Execute phis first. *)
    match (state: VarBasedDataFlowState<_>).PhiInfos.TryGetValue v with
    | false, _ -> ()
    | true, phiInfo ->
      transferPhi state subState phiInfo v.VData.Internals.PPoint
    for stmt in state.GetStmtInfos v do fnTransfer hdl state analysis stmt done
    (g: IGraph<_, _>).GetSuccs v
    |> Seq.map (fun succ -> v, succ)
    |> Seq.iter subState.FlowQueue.Enqueue

  let processFlow hdl g state analysis subState fnTransfer =
    match (subState: IVarBasedDataFlowSubState<_>).FlowQueue.TryDequeue () with
    | false, _ -> ()
    | true, (src, dst) ->
      if not <| subState.ExecutedFlows.Add (src, dst) then ()
      else
        match (g: IGraph<_, _>).TryFindVertexByID dst.ID with
        | Some v -> transferFlow hdl state analysis subState g v fnTransfer
        | None -> ()

  let registerPendingVertices state (subState: IVarBasedDataFlowSubState<_>) =
    (state: VarBasedDataFlowState<_>).EnqueuePendingVertices subState

  let propagateAux hdl g state analysis subState fnTransfer =
    registerPendingVertices state subState
    while not subState.FlowQueue.IsEmpty
          || not subState.DefSiteQueue.IsEmpty do
      processFlow hdl g state analysis subState fnTransfer
      processDefSite hdl state analysis subState fnTransfer

  let propagateStackPointer hdl g state analysis =
    propagateAux hdl g state analysis state.StackPointerSubState spTransfer

  let propagateDomain hdl g state analysis =
    propagateAux hdl g state analysis state.DomainSubState domainTransfer

type VarBasedDataFlowAnalysis<'Lattice>
  public (hdl, analysis: IVarBasedDataFlowAnalysis<'Lattice>) =

  /// Compute the data flow analysis incrementally in four stages: (1) calculate
  /// def-use/use-def chains, (2) propagate stack pointer values, (3) calculate
  /// def-use/use-def chains again, but this time with the updated stack pointer
  /// values, and (4) propagate domain values.
  let computeIncrementally g state =
    let domCtx = initDominatorContext g
    let domTree, _ = dominatorTree domCtx
    let domFrontiers = frontiers domCtx
    Chains.calculate g state domCtx domTree domFrontiers
    Propagation.propagateStackPointer hdl g state analysis
    Chains.calculate g state domCtx domTree domFrontiers
    Propagation.propagateDomain hdl g state analysis
    state.ClearPendingVertices ()
    state

  let addPendingVertices vs (state: VarBasedDataFlowState<_>) =
    for v in vs do state.MarkVertexAsPending v done
    state

  interface IDataFlowAnalysis<VarPoint,
                              'Lattice,
                              VarBasedDataFlowState<'Lattice>,
                              LowUIRBasicBlock> with

    member __.InitializeState vs =
      VarBasedDataFlowState<'Lattice> (hdl, analysis)
      |> analysis.OnInitialize
      |> addPendingVertices vs

    member __.Compute g state =
      computeIncrementally g state
