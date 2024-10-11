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
  let private updateDefUseChain state defSite useSitePp =
    match (state: VarBasedDataFlowState<_>).DefUseMap.TryGetValue defSite with
    | false, _ -> state.DefUseMap[defSite] <- Set.singleton useSitePp
    | true, useSites -> state.DefUseMap[defSite] <- Set.add useSitePp useSites

  let private updateUseDefChain state defSite useSitePp varKind =
    let vp = { ProgramPoint = useSitePp; VarKind = varKind }
    (state: VarBasedDataFlowState<_>).UseDefMap[vp] <- defSite

  let private removeOldDefUses state vp pp newDefSite =
    match (state: VarBasedDataFlowState<_>).UseDefMap.TryGetValue vp with
    | true, prevDefSite when prevDefSite <> newDefSite ->
      (* Erase the old def-use. *)
      let usesOfPrevDefSite = state.DefUseMap[prevDefSite]
      state.DefUseMap[prevDefSite] <- Set.remove pp usesOfPrevDefSite
      (* Erase the old use-def which will be overwritten by the new def. *)
      state.UseDefMap.Remove vp |> ignore
    | _ -> ()

  let private updateChains state vk m pp =
    match Map.tryFind vk m with
    | None -> ()
    | Some defSite ->
      let vp = { ProgramPoint = pp; VarKind = vk }
      removeOldDefUses state vp pp defSite
      updateDefUseChain state defSite pp
      updateUseDefChain state defSite pp vk

  let rec private executeExpr state m (pp: ProgramPoint) = function
    | Num (_)
    | Undefined (_)
    | FuncName (_)
    | Nil -> ()
    | Var (_rt, rid, _rstr) -> updateChains state (VarKind.Regular rid) m pp
    | TempVar (_, n) -> updateChains state (Temporary n) m pp
    | Load (_, _, expr) ->
      executeExpr state m pp expr.E
      match state.EvaluateToStackPointer pp expr with
      | StackPointerDomain.ConstSP bv ->
        let loc = BitVector.ToUInt64 bv
        updateChains state (Memory (Some loc)) m pp
      | _ -> ()
      executeExpr state m pp expr.E
    | UnOp (_, expr) ->
      executeExpr state m pp expr.E
    | BinOp (_, _, expr1, expr2) ->
      executeExpr state m pp expr1.E
      executeExpr state m pp expr2.E
    | RelOp (_, expr1, expr2) ->
      executeExpr state m pp expr1.E
      executeExpr state m pp expr2.E
    | Ite (expr1, expr2, expr3) ->
      executeExpr state m pp expr1.E
      executeExpr state m pp expr2.E
      executeExpr state m pp expr3.E
    | Cast (_, _, expr) ->
      executeExpr state m pp expr.E
    | Extract (expr, _, _) ->
      executeExpr state m pp expr.E
    | _ -> ()

  let private renameJmp state m pp = function
    | Jmp ({ E = expr }) ->
      executeExpr state m pp expr
    | CJmp ({ E = expr }, { E = target1 }, { E = target2 }) ->
      executeExpr state m pp expr
      executeExpr state m pp target1
      executeExpr state m pp target2
    | InterJmp ({ E = expr }, _jmpKind) ->
      executeExpr state m pp expr
    | InterCJmp ({ E = cond }, { E = target1 }, { E = target2 }) ->
      executeExpr state m pp cond
      executeExpr state m pp target1
      executeExpr state m pp target2
    | _ -> Utils.impossible ()

  /// Executes the statement to update the def-use/use-def chains. At the same
  /// time, it updates the current mapping of variable kinds to their def sites
  /// to be used for the children of the current vertex in the dominator tree.
  let private executeStmt state m (pp, stmt) =
    match stmt.S with
    | Put (dst, { E = src }) ->
      let varKind = VarKind.ofIRExpr dst
      executeExpr state m pp src
      Map.add varKind pp m
    | Store (_, addr, value) ->
      executeExpr state m pp addr.E
      executeExpr state m pp value.E
      match state.EvaluateToStackPointer pp addr with
      | StackPointerDomain.ConstSP bv ->
        let loc = BitVector.ToUInt64 bv
        let varKind = Memory (Some loc)
        Map.add varKind pp m
      | _ -> m
    | Jmp _
    | CJmp _
    | InterJmp _
    | InterCJmp _ -> renameJmp state m pp stmt.S; m
    | _ -> m

  let private updateVidToPp g (state: VarBasedDataFlowState<_>) vid =
    let v = (g: IGraph<_, _>).FindVertexByID vid
    let pp = (v.VData: LowUIRBasicBlock).Internals.PPoint
    state.VidToPp[vid] <- pp

  let private collectDefsFromStmt state defs (pp, stmt) =
    match stmt.S with
    | Put (dst, _) -> Map.add (VarKind.ofIRExpr dst) pp defs
    | Store (_, addr, _) ->
      (state: VarBasedDataFlowState<_>).EvaluateToStackPointer pp addr
      |> function
        | StackPointerDomain.ConstSP bv ->
          let loc = BitVector.ToUInt64 bv
          Map.add (Memory (Some loc)) pp defs
        | _ -> defs
    | _ -> defs

  /// Updates the def-use chain whose use exists in the successors.
  let rec private executePhi state m child =
    let phiInfos = (state: VarBasedDataFlowState<_>).PhiInfos
    let childVid = (child: IVertex<_>).ID
    match phiInfos.TryGetValue childVid with
    | false, _ -> ()
    | true, phiInfo ->
      phiInfo.Keys
      |> Seq.filter (fun vk -> Map.containsKey vk m)
      |> Seq.iter (fun vk -> executePhiAux state vk m[vk] childVid)

  and executePhiAux (state: VarBasedDataFlowState<_>) varKind defSite vid =
    assert (state.PhiInfos.ContainsKey vid)
    let phiInfo = state.PhiInfos[vid]
    (* Add this defSite to the current phi info. *)
    let prevDefSites = phiInfo[varKind]
    let currDefSites = Set.add defSite prevDefSites
    phiInfo[varKind] <- currDefSites
    (* And, update the def-use chain. *)
    let usePp = state.VidToPp[vid]
    updateDefUseChain state defSite usePp

  let appendPhis phiInfos vid pp inM =
    match (phiInfos: Dictionary<_, PhiInfo>).TryGetValue vid with
    | false, _ -> inM
    | true, phiInfo -> Seq.fold (fun m vk -> Map.add vk pp m) inM phiInfo.Keys

  let hasRedundantVarKind varKind =
    match varKind with
    | Temporary _ -> true
    | _ -> false

  let executeStmts state v inM =
    (state: VarBasedDataFlowState<_>).GetStmtInfos v
    |> Seq.fold (executeStmt state) inM
    |> Map.filter (fun vk _ -> not <| hasRedundantVarKind vk)

  let executeSuccessorPhis state g v outM  =
    (g: IGraph<_, _>).GetSuccs v
    |> Seq.iter (executePhi state outM)

  let markVertexVisited v visited =
    let vid = (v: IVertex<_>).ID
    (visited: HashSet<_>).Add vid |> ignore
    vid

  /// Updates the def-use/use-def chains for the vertices in the dominator tree.
  let rec private update g state domTree (visited: HashSet<_>) v inM =
    assert (not <| visited.Contains (v: IVertex<_>).ID)
    let vid = markVertexVisited v visited
    let phiInfos = (state: VarBasedDataFlowState<_>).PhiInfos
    let inM = appendPhis phiInfos vid state.VidToPp[vid] inM
    let outM = executeStmts state v inM
    executeSuccessorPhis state g v outM
    traverseChildren g state domTree outM visited (Map.find v domTree)
    state.PerVertexIncomingDefs[vid] <- inM
    state.PerVertexOutgoingDefs[vid] <- outM

  and private traverseChildren g state domTree m visited = function
    | child :: rest ->
      update g state domTree visited child m
      traverseChildren g state domTree m visited rest
    | [] -> ()

  let private joinDefs = Map.fold (fun acc vk d -> Map.add vk d acc)

  let private getOutgoingDefs (state: VarBasedDataFlowState<_>) v =
    match state.PerVertexOutgoingDefs.TryGetValue (v: IVertex<_>).ID with
    | false, _ -> Map.empty
    | true, m -> m

  let private getIncomingDefs g (s: VarBasedDataFlowState<_>) v =
    match s.PerVertexIncomingDefs.TryGetValue (v: IVertex<_>).ID with
    | true, m -> m
    | false, _ ->
      (g: IGraph<_, _>).GetPreds v
      |> Seq.fold (fun acc p -> joinDefs acc <| getOutgoingDefs s p) Map.empty

  /// We visits the dominator tree in a depth-first manner to calculate the
  /// def-use/use-def chains as Cytron's SSA construction algorithm does.
  /// But, we are only interested in the vertices that have changes in the CFG,
  /// so we only visit the vertices that are possibly updated by the changes.
  let rec private visitDomTree g s domTree visited v =
    let pendingVertices = (s: VarBasedDataFlowState<_>).PendingVertices
    let vid = (v: IVertex<_>).ID
    let hasVisited = (visited: HashSet<_>).Contains vid
    let isInteresting = pendingVertices.Contains vid
    if hasVisited then ()
    elif isInteresting then update g s domTree visited v (getIncomingDefs g s v)
    else Seq.iter (visitDomTree g s domTree visited) (Map.find v domTree)

  let private updateAndGetInnerDefs state v =
    let stmts = (state: VarBasedDataFlowState<_>).GetStmtInfos v
    let defs = Seq.fold (collectDefsFromStmt state) Map.empty stmts
    state.PerVertexInnerDefs[v.ID] <- defs
    defs

  /// Calculates the set of def sites for each variable kind. This is used to
  /// update the phi information. Note that we update the inner definitions here
  /// to apply the former changes (e.g. stack pointer propagation).
  let private calculateDefSites g state =
    let defSites = Dictionary ()
    (g: IGraph<_, _>).IterVertex (fun v ->
      updateVidToPp g state v.ID
      for varKind in Map.keys <| updateAndGetInnerDefs state v do
        match defSites.TryGetValue varKind with
        | false, _-> defSites[varKind] <- Set.singleton v.ID
        | true, m -> defSites[varKind] <- Set.add v.ID m)
    defSites

  let getPhiInfo state vid =
    match (state: VarBasedDataFlowState<_>).PhiInfos.TryGetValue vid with
    | true, dict -> dict
    | false, _ ->
      let dict = Dictionary ()
      state.PhiInfos[vid] <- dict
      dict

  /// Refer to Cytron's algorithm.
  let private addPhi state varKind (phiSites, worklist) v =
    if Set.contains (v: IVertex<LowUIRBasicBlock>).ID phiSites then
      phiSites, worklist
    else
      match varKind with
      | Temporary _ when v.VData.Internals.PPoint.Position = 0 ->
        phiSites, worklist
      | _ ->
        let vid = v.ID
        let phiInfo = getPhiInfo state vid
        if phiInfo.ContainsKey varKind then ()
        else
          (* insert a new phi *)
          phiInfo[varKind] <- Set.empty
          (* we may need to update chains from the phi site *)
          state.PendingVertices.Add vid |> ignore
        let phiSites = Set.add vid phiSites
        let innerDef = state.PerVertexInnerDefs[vid]
        if not <| Map.containsKey varKind innerDef then
          phiSites, vid :: worklist (* add the current vertex to the worklist *)
        else phiSites, worklist

  /// Refer to Cytron's algorithm.
  let rec private iterDefs state phiSites vk forwardDomInfo frontiers worklist =
    match worklist with
    | [] -> ()
    | vid :: tl ->
      let dfNum = (forwardDomInfo: DomInfo<_>).DFNumMap[vid]
      let frontier = (frontiers: IVertex<_> list [])[dfNum]
      let phiSites, tl = List.fold (addPhi state vk) (phiSites, tl) frontier
      iterDefs state phiSites vk forwardDomInfo frontiers tl

  /// Updates the phi information of the vertices using dominance frontiers.
  let private updatePhiInfos state perVarKindDefSites domCtx frontiers =
    let domInfo = (domCtx: DominatorContext<_, _>).ForwardDomInfo
    for KeyValue (varKind, defVids) in perVarKindDefSites do
      iterDefs state Set.empty varKind domInfo frontiers (Seq.toList defVids)

  /// This is a modification of Cytron's algorithm that uses the dominator tree
  /// to calculate the def-use/use-def chains. This has theoretically same
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
  let private isStackRelatedRegister hdl rid =
    (hdl: BinHandle).RegisterFactory.IsStackPointer rid
    || hdl.RegisterFactory.IsFramePointer rid

  let private isExecuted state (subState: IDataFlowSubState<_>) defPp =
    match (state: VarBasedDataFlowState<_>).PpToStmt.TryGetValue defPp with
    | false, _ -> false
    | true, (vid, _) -> subState.ExecutedVertices.Contains vid

  let private updateAbsValue subState defUseMap vp defSite prev curr =
    if (subState: IDataFlowSubState<_>).Subsume prev curr then ()
    else
      subState.SetAbsValue vp <| subState.Join prev curr
      match (defUseMap: Dictionary<_, _>).TryGetValue defSite with
      | false, _ -> ()
      | true, defSites -> Set.iter subState.DefSiteQueue.Enqueue defSites

  let private spTransfer (state: VarBasedDataFlowState<_>) _ (pp, stmt) =
    match stmt.S with
    | Put (dst, src) ->
      let varKind = VarKind.ofIRExpr dst
      let currConst =
        match varKind with
        | Regular rid when isStackRelatedRegister state.BinHandle rid ->
          (state: VarBasedDataFlowState<_>).EvaluateToStackPointer pp src
          |> Some
        | Regular _ -> StackPointerDomain.NotConstSP |> Some
        | Temporary _ -> state.EvaluateToStackPointer pp src |> Some
        | _ -> None
      match currConst with
      | None -> ()
      | Some currConst ->
        let vp = { ProgramPoint = pp; VarKind = varKind }
        let prevConst = state.GetStackPointerValue vp
        let subState = state.StackPointerSubState
        let defUseMap = state.DefUseMap
        updateAbsValue subState defUseMap vp pp prevConst currConst
    | _ -> ()

  let private domainTransfer state analysis (pp, stmt) =
    match stmt.S with
    | Put (dst, src) ->
      let varKind = VarKind.ofIRExpr dst
      let vp = { ProgramPoint = pp; VarKind = varKind }
      let prev = (state: VarBasedDataFlowState<_>).GetDomainValue vp
      let curr = (analysis: IVarBasedDataFlowAnalysis<_>).EvalExpr state pp src
      let subState = state.DomainSubState
      let defUseMap = state.DefUseMap
      updateAbsValue subState defUseMap vp pp prev curr
    | Store (_, addr, value) ->
      match state.EvaluateToStackPointer pp addr with
      | StackPointerDomain.ConstSP bv ->
        let loc = BitVector.ToUInt64 bv
        let varKind = Memory (Some loc)
        let vp = { ProgramPoint = pp; VarKind = varKind }
        let prev = state.GetDomainValue vp
        let curr = analysis.EvalExpr state pp value
        let subState = state.DomainSubState
        let defUseMap = state.DefUseMap
        updateAbsValue subState defUseMap vp pp prev curr
      | _ -> ()
    | _ -> ()

  let private transferPhi state subState phiInfo defPp =
    phiInfo |> Seq.iter (fun (KeyValue (varKind, defPps)) ->
      let vp = { ProgramPoint = defPp; VarKind = varKind }
      let prev = (subState: IDataFlowSubState<_>).GetAbsValue vp
      let curr =
        defPps |> Set.fold (fun c defPp ->
          { ProgramPoint = defPp; VarKind = varKind }
          |> subState.GetAbsValue
          |> subState.Join c) subState.Bottom
      let defUseMap = (state: VarBasedDataFlowState<_>).DefUseMap
      updateAbsValue subState defUseMap vp defPp prev curr)

  let private isPhiProgramPoint state pp =
    let vid, _ = (state: VarBasedDataFlowState<_>).PpToStmt[pp]
    let pp' = state.VidToPp[vid]
    pp = pp'

  let private processDefSite state analysis subState fnTransfer =
    match (subState: IDataFlowSubState<_>).DefSiteQueue.TryDequeue () with
    | true, defPp when isExecuted state subState defPp ->
      if not <| isPhiProgramPoint state defPp then (* non-phi *)
        let stmt = (state: VarBasedDataFlowState<_>).PpToStmt[defPp] |> snd
        fnTransfer state analysis (defPp, stmt)
      else (* phi *)
        let vid = state.PpToStmt[defPp] |> fst
        assert (state.PhiInfos.ContainsKey vid)
        transferPhi state subState state.PhiInfos[vid] defPp
    | _ -> ()

  let private transferFlow state analysis subState g v fnTransfer =
    let stmts = (state: VarBasedDataFlowState<_>).GetStmtInfos v
    let vid = v.ID
    (subState: IDataFlowSubState<_>).ExecutedVertices.Add vid |> ignore
    match state.PhiInfos.TryGetValue vid with (* Execute phis first. *)
    | false, _ -> ()
    | true, phiInfo -> transferPhi state subState phiInfo state.VidToPp[vid]
    Seq.iter (fnTransfer state analysis) stmts
    (g: IGraph<_, _>).GetSuccs v
    |> Seq.map (fun succ -> vid, succ.ID)
    |> Seq.iter subState.FlowQueue.Enqueue

  let private processFlow g state analysis subState fnTransfer =
    match (subState: IDataFlowSubState<_>).FlowQueue.TryDequeue () with
    | false, _ -> ()
    | true, (srcVid, dstVid) ->
      if not <| subState.ExecutedFlows.Add (srcVid, dstVid) then ()
      else
        match (g: IGraph<_, _>).TryFindVertexByID dstVid with
        | Some v -> transferFlow state analysis subState g v fnTransfer
        | None -> ()

  let private registerPendingVertices state (subState: IDataFlowSubState<_>) =
    (state: VarBasedDataFlowState<_>).PendingVertices
    |> Seq.iter (fun vid -> subState.FlowQueue.Enqueue (-1, vid) |> ignore)

  let private propagateAux g state analysis subState fnTransfer =
    registerPendingVertices state subState
    while not subState.FlowQueue.IsEmpty
          || not subState.DefSiteQueue.IsEmpty do
      processFlow g state analysis subState fnTransfer
      processDefSite state analysis subState fnTransfer

  let propagateStackPointer g state analysis =
    propagateAux g state analysis state.StackPointerSubState spTransfer

  let propagateDomain g state analysis =
    propagateAux g state analysis state.DomainSubState domainTransfer

type VarBasedDataFlowAnalysis<'Lattice>
  public (hdl, analysis: IVarBasedDataFlowAnalysis<'Lattice>) =

  /// Computes the data flow analysis incrementally. It has four steps:
  /// (1) calculate def-use/use-def chains.
  /// (2) propagate stack pointer values.
  /// (3) calculate def-use/use-def chains again, but this time with the updated
  ///     stack pointer values.
  /// (4) propagate domain values.
  let computeIncrementally g state =
    let domCtx = initDominatorContext g
    let domTree, _ = dominatorTree domCtx
    let domFrontiers = frontiers domCtx
    Chains.calculate g state domCtx domTree domFrontiers
    Propagation.propagateStackPointer g state analysis
    Chains.calculate g state domCtx domTree domFrontiers
    Propagation.propagateDomain g state analysis
    state.PendingVertices.Clear ()
    state

  let addPendingVertices vs state =
    let pendingVertices = (state: VarBasedDataFlowState<_>).PendingVertices
    Seq.iter (fun (v: IVertex<_>) -> pendingVertices.Add v.ID |> ignore) vs
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