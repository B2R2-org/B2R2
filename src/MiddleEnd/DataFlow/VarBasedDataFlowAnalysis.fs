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

[<AutoOpen>]
module private Chains =
  let updateDefUseChain state defSite useSitePp =
    match (state: VarBasedDataFlowState<_>).DefUseMap.TryGetValue defSite with
    | false, _ ->
      state.DefUseMap[defSite] <- Set.singleton <| DefSite.Single useSitePp
    | true, useSites ->
      state.DefUseMap[defSite] <- Set.add (DefSite.Single useSitePp) useSites

  let updateDefUseChainWithPhi state defSite usePhiVid =
    match (state: VarBasedDataFlowState<_>).DefUseMap.TryGetValue defSite with
    | false, _ ->
      state.DefUseMap[defSite] <- Set.singleton <| DefSite.Phi usePhiVid
    | true, useSites ->
      state.DefUseMap[defSite] <- Set.add (DefSite.Phi usePhiVid) useSites

  let updateUseDefChain state defSite useSitePp varKind =
    let vp = { IRProgramPoint = useSitePp; VarKind = varKind }
    (state: VarBasedDataFlowState<_>).UseDefMap[vp] <- defSite

  let removeOldDefUses state vp pp newDefSite =
    match (state: VarBasedDataFlowState<_>).UseDefMap.TryGetValue vp with
    | true, prevDefSite when prevDefSite <> newDefSite ->
      (* Oh, you gotta be killed :D *)
      (* Erase the old def-use. *)
      let usesOfPrevDefSite = state.DefUseMap[prevDefSite]
      let useSite = DefSite.Single pp
      state.DefUseMap[prevDefSite] <- Set.remove useSite usesOfPrevDefSite
      (* Here, we do not erase the old use-def since we anyways gonna
         overwrite it. *)
      state.UseDefMap.Remove vp |> ignore
    | _ -> ()

  let updateChains state vk m pp =
    match Map.tryFind vk m with
    | None -> ()
    | Some defSite ->
      let vp = { IRProgramPoint = pp; VarKind = vk }
      removeOldDefUses state vp pp defSite
      updateDefUseChain state defSite pp
      updateUseDefChain state defSite pp vk

  let rec executeExpr state m (pp: IRProgramPoint) = function
    | Num (_)
    | Undefined (_)
    | FuncName (_)
    | Nil -> ()
    | Var (_rt, rid, _rstr) -> updateChains state (VarKind.Regular rid) m pp
    | TempVar (_, n) -> updateChains state (Temporary n) m pp
    | Load (_, _, expr) ->
      executeExpr state m pp expr.E
      match state.EvaluateExprToStackPointer pp expr with
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

  let renameJmp state m pp = function
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

  let executeStmt state m (pp, stmt) =
    match stmt.S with
    | Put (dst, { E = src }) ->
      let varKind = VarKind.ofIRExpr dst
      executeExpr state m pp src
      Map.add varKind (DefSite.Single pp) m
    | Store (_, addr, value) ->
      executeExpr state m pp addr.E
      executeExpr state m pp value.E
      match state.EvaluateExprToStackPointer pp addr with
      | StackPointerDomain.ConstSP bv ->
        let loc = BitVector.ToUInt64 bv
        let varKind = Memory (Some loc)
        Map.add varKind (DefSite.Single pp) m
      | _ -> m
    | Jmp _
    | CJmp _
    | InterJmp _
    | InterCJmp _ -> renameJmp state m pp stmt.S; m
    | _ -> m

  let updateVidToPp g state vid=
    let v = (g: IGraph<_, _>).FindVertexByID vid
    (state: VarBasedDataFlowState<_>).VidToPp[vid] <-
      if (v: IVertex<LowUIRBasicBlock>).VData.Internals.IsAbstract then
        let callerV = g.GetPreds v |> Seq.exactlyOne
        let callSite = callerV.VData.Internals.LastInstruction.Address
        let callee = v.VData.Internals.AbstractContent.EntryPoint
        IRPPAbs (callSite, callee, 0)
      else
        IRPPReg v.VData.Internals.PPoint

  let collectDefsFromStmt state defs (pp, stmt) =
    match stmt.S with
    | Put (dst, _) ->
      let defSite = DefSite.Single pp
      Map.add (VarKind.ofIRExpr dst) defSite defs
    | Store (_, addr, _) ->
      (state: VarBasedDataFlowState<_>).EvaluateExprToStackPointer pp addr
      |> function
        | StackPointerDomain.ConstSP bv ->
          let loc = BitVector.ToUInt64 bv
          let defSite = DefSite.Single pp
          Map.add (Memory (Some loc)) defSite defs
        | _ -> defs
    | _ -> defs

  let addPhi state varKind (phiSites, worklist) v =
    if Set.contains (v: IVertex<LowUIRBasicBlock>) phiSites then
      phiSites, worklist
    else
      match varKind with
      | Temporary _ when v.VData.Internals.PPoint.Position = 0 ->
        phiSites, worklist
      | _ ->
        let phiInfos = (state: VarBasedDataFlowState<_>).PhiInfos
        let phiInfo =
          match phiInfos.TryGetValue v.ID with
          | false, _ ->
            let dict = Dictionary ()
            state.PhiInfos[v.ID] <- dict
            dict
          | true, dict -> dict
        if phiInfo.ContainsKey varKind then ()
        else
          (* insert a new phi *)
          phiInfo[varKind] <- Set.empty
          (* we may need to update chains from the phi site *)
          state.PendingVertices.Add v.ID |> ignore
        let phiSites = Set.add v phiSites
        let innerDef = state.InnerDefs[v.ID]
        if not <| Map.containsKey varKind innerDef then
          phiSites, v.ID :: worklist
        else phiSites, worklist

  let rec iterDefs state phiSites vk forwardDomInfo frontiers worklist =
    match worklist with
    | [] -> ()
    | vid :: tl ->
      let dfNum = (forwardDomInfo: DomInfo<_>).DFNumMap[vid]
      let frontier = (frontiers: IVertex<_> list [])[dfNum]
      let phiSites, tl = List.fold (addPhi state vk) (phiSites, tl) frontier
      iterDefs state phiSites vk forwardDomInfo frontiers tl

  let renamePhi state m child =
    let phiInfos = (state: VarBasedDataFlowState<_>).PhiInfos
    match phiInfos.TryGetValue (child: IVertex<_>).ID with
    | false, _ -> ()
    | true, phiInfo ->
      let varKinds = phiInfo.Keys
      varKinds |> Seq.iter (fun varKind ->
        match Map.tryFind varKind m with
        | None -> ()
        | Some defSite ->
          (* Add this defSite to the current phi info. *)
          let prevDefSites = phiInfo[varKind]
          let currDefSites = Set.add defSite prevDefSites
          phiInfo[varKind] <- currDefSites
          (* And, update the def-use chain. *)
          updateDefUseChainWithPhi state defSite child.ID)

  let rec rename2 g state domTree inM (visited: HashSet<_>) v =
    let vid = (v: IVertex<_>).ID
    assert (not <| visited.Contains vid)
    visited.Add vid |> ignore
    let stmts = (state: VarBasedDataFlowState<_>).GetStatements g v
    (* Introduce phis. *)
    let inM =
      match state.PhiInfos.TryGetValue v.ID with
      | false, _ -> inM
      | true, phiInfo ->
        phiInfo
        |> Seq.fold (fun m (KeyValue (varKind, _defSites)) ->
          Map.add varKind (DefSite.Phi v.ID) m) inM
    (* Execute the statements. *)
    let outM = stmts |> Array.fold (executeStmt state) inM
    (* Filter out temporary variables. *)
    let outM = outM |> Map.filter (fun vk _ ->
      match vk with
      | Temporary _ -> false
      | _ -> true)
    (* Update phi information of succs. *)
    g.GetSuccs v |> Seq.iter (renamePhi state outM)
    (* Visit its sub-tree in the dominator tree. *)
    traverseChildren2 g state domTree outM visited (Map.find v domTree)
    (* Update the intermediate chains for incremental analysis. *)
    state.IncomingDefs[v.ID] <- inM
    state.OutgoingDefs[v.ID] <- outM

  and traverseChildren2 g state domTree m visited = function
    | child :: rest ->
      rename2 g state domTree m visited child
      traverseChildren2 g state domTree m visited rest
    | [] -> ()

  let joinDefs m1 m2 =
    m1 |> Map.fold (fun acc vk defSite -> Map.add vk defSite acc) m2

  let rec visitDomTree g state domTree visited v =
    let pendingVertices = (state: VarBasedDataFlowState<_>).PendingVertices
    let vid = (v: IVertex<_>).ID
    let hasVisited = (visited: HashSet<_>).Contains vid
    let isInteresting = pendingVertices.Contains vid
    if hasVisited then ()
    else if isInteresting then
      let incomingDefs = state.IncomingDefs
      let incomingDef =
        match incomingDefs.TryGetValue v.ID with
        | false, _ ->
          let preds = (g: IGraph<_, _>).GetPreds v
          preds |> Seq.fold (fun m pred ->
            let predVid = pred.ID
            let outM =
              match state.OutgoingDefs.TryGetValue predVid with
              | false, _ -> Map.empty
              | true, m -> m
            joinDefs m outM) Map.empty
        | true, m -> m
      rename2 g state domTree incomingDef visited v (* traverse the sub-tree *)
    else
      (* check its children too *)
      for child in Map.find v domTree do
        visitDomTree g state domTree visited child

  /// This is a modification of Cytron's algorithm that uses the dominator tree
  /// to calculate the def-use/use-def chains. This has theoretically same
  /// worst-case time complexity as the original algorithm, but it is more
  /// efficient for incremental changes in practice since its search space is
  /// reduced to the affected vertices that are possibly updated.
  /// Unlike calculateChainsIncrementally, this algorithm ensures that every
  /// vertex is visited only once since it strictly follows the dominator tree.
  let calculateChainsIncrementally g state domCtx domTree frontiers =
    (* 1. Calculate inner defs. *)
    let defSites = Dictionary ()
    (g: IGraph<_, _>).IterVertex (fun v ->
      let stmts = (state: VarBasedDataFlowState<_>).GetStatements g v
      updateVidToPp g state v.ID
      let defs = Array.fold (collectDefsFromStmt state) Map.empty stmts
      state.InnerDefs[v.ID] <- defs
      let varKinds = Map.keys defs
      for varKind in varKinds do
        if defSites.ContainsKey varKind then
          defSites[varKind] <- Set.add v.ID defSites[varKind]
        else defSites[varKind] <- Set.singleton v.ID)
    (* 2. Update phi information. *)
    let forwardDomInfo = (domCtx: DominatorContext<_, _>).ForwardDomInfo
    for KeyValue (varKind, defVids) in defSites do
      Seq.toList defVids
      |> iterDefs state Set.empty varKind forwardDomInfo frontiers
    (* 3. Update chains. *)
    visitDomTree g state domTree (HashSet ()) domCtx.ForwardRoot

type VarBasedDataFlowAnalysis<'Lattice>
  public (hdl, analysis: IVarBasedDataFlowAnalysis<'Lattice>) =

  let isStackRelatedRegister rid =
    (hdl: BinHandle).RegisterFactory.IsStackPointer rid
    || hdl.RegisterFactory.IsFramePointer rid

  let hasSameLocationExceptIndex irpp1 irpp2 =
    match irpp1, irpp2 with
    | IRPPReg pp1, IRPPReg pp2 -> pp1.Address = pp2.Address
    | IRPPAbs (cs1, c1, i1), IRPPAbs (cs2, c2, i2) ->
      cs1 = cs2 && c1 = c2 && i1 = i2
    | _ -> false

  let tryGetPpFromDefSite g defSite =
    match defSite with
    | DefSite.Single pp -> Some pp
    | DefSite.Phi vid ->
      let v = (g: IGraph<LowUIRBasicBlock, _>).TryFindVertexByID vid
      match v with
      | None -> None
      | Some v ->
        if v.VData.Internals.IsAbstract then
          let callerV = g.GetPreds v |> Seq.exactlyOne
          let callSite = callerV.VData.Internals.LastInstruction.Address
          let callee = v.VData.Internals.AbstractContent.EntryPoint
          Some <| IRPPAbs (callSite, callee, -1)
        else
          Some (IRPPReg <| ProgramPoint (v.VData.Internals.PPoint.Address, -1))

  let isExecuted state sparseState defSite =
    match defSite with
    | DefSite.Single pp ->
      match (state: VarBasedDataFlowState<_>).PpToStmt.TryGetValue pp with
      | false, _ -> None
      | true, (vid, _) -> Some vid
    | DefSite.Phi vid -> Some vid
    |> function
      | None -> false
      | Some vid -> sparseState.ExecutedVertices.Contains vid

  let updateAbsValue sparseState defUseMap vp defSite prev curr =
    if sparseState.Subsume prev curr then ()
    else
      sparseState.SetAbsValue vp <| sparseState.Join prev curr
      match (defUseMap: Dictionary<_, _>).TryGetValue defSite with
      | false, _ -> ()
      | true, defSites -> Set.iter sparseState.DefSiteQueue.Enqueue defSites

  let transferStackPointer state (pp, stmt) =
    match stmt.S with
    | Put (dst, src) ->
      let varKind = VarKind.ofIRExpr dst
      let currConst =
        match varKind with
        | Regular rid when isStackRelatedRegister rid ->
          (state: VarBasedDataFlowState<_>).EvaluateExprToStackPointer pp src
          |> Some
        | Regular _ -> StackPointerDomain.NotConstSP |> Some
        | Temporary _ -> state.EvaluateExprToStackPointer pp src |> Some
        | _ -> None
      match currConst with
      | None -> ()
      | Some currConst ->
        let vp = { IRProgramPoint = pp; VarKind = varKind }
        let prevConst = state.GetStackPointer vp
        let sparseState = state.StackPointerSparseState
        let defUseMap = state.DefUseMap
        let defSite = DefSite.Single pp
        updateAbsValue sparseState defUseMap vp defSite prevConst currConst
    | _ -> ()

  let transferLattice state (pp, stmt) =
    match stmt.S with
    | Put (dst, src) ->
      let varKind = VarKind.ofIRExpr dst
      let vp = { IRProgramPoint = pp; VarKind = varKind }
      let prev = (state: VarBasedDataFlowState<_>).GetAbsValue vp
      let curr = analysis.EvalExpr state pp src
      let sparseState = state.DomainSparseState
      let defUseMap = state.DefUseMap
      let defSite = DefSite.Single pp
      updateAbsValue sparseState defUseMap vp defSite prev curr
    | Store (_, addr, value) ->
      match state.EvaluateExprToStackPointer pp addr with
      | StackPointerDomain.ConstSP bv ->
        let loc = BitVector.ToUInt64 bv
        let varKind = Memory (Some loc)
        let vp = { IRProgramPoint = pp; VarKind = varKind }
        let prev = state.GetAbsValue vp
        let curr = analysis.EvalExpr state pp value
        let sparseState = state.DomainSparseState
        let defUseMap = state.DefUseMap
        let defSite = DefSite.Single pp
        updateAbsValue sparseState defUseMap vp defSite prev curr
      | _ -> ()
    | _ -> ()

  let transferPhi g state sparseState phiInfo defSite =
    phiInfo |> Seq.iter (fun (KeyValue (varKind, defSites)) ->
      match tryGetPpFromDefSite g defSite with
      | None -> ()
      | Some defPp ->
        let vp = { IRProgramPoint = defPp; VarKind = varKind }
        let prev = sparseState.GetAbsValue vp
        let curr =
          defSites |> Set.fold (fun c defSite ->
            match tryGetPpFromDefSite g defSite with
            | None -> c
            | Some defPp ->
              { IRProgramPoint = defPp; VarKind = varKind }
              |> sparseState.GetAbsValue
              |> sparseState.Join c) sparseState.Bottom
        let defUseMap = (state: VarBasedDataFlowState<_>).DefUseMap
        updateAbsValue sparseState defUseMap vp defSite prev curr)

  let processDefSite g state sparseState fnTransfer =
    match sparseState.DefSiteQueue.TryDequeue () with
    | Some defSite when isExecuted state sparseState defSite ->
      match defSite with
      | DefSite.Single pp ->
        let _vid, stmt = (state: VarBasedDataFlowState<_>).PpToStmt[pp]
        fnTransfer state (pp, stmt)
      | DefSite.Phi vid ->
        transferPhi g state sparseState state.PhiInfos[vid] defSite
    | _ -> ()

  let transferFlow state sparseState g v fnTransfer =
    let stmts = (state: VarBasedDataFlowState<_>).GetStatements g v
    let vid = v.ID
    sparseState.ExecutedVertices.Add vid |> ignore
    match state.PhiInfos.TryGetValue v.ID with (* Execute phis first. *)
    | false, _ -> ()
    | true, phiInfo -> transferPhi g state sparseState phiInfo (DefSite.Phi vid)
    Seq.iter (fnTransfer state) stmts
    g.GetSuccs v
    |> Seq.map (fun succ -> vid, succ.ID)
    |> Seq.iter sparseState.FlowQueue.Enqueue

  let processFlow g state (sparseState: SparseState<'T>) fnTransfer =
    match sparseState.FlowQueue.TryDequeue () with
    | None -> ()
    | Some (srcVid, dstVid) ->
      if not <| sparseState.ExecutedFlows.Add (srcVid, dstVid) then ()
      else
        match (g: IGraph<_, _>).TryFindVertexByID dstVid with
        | Some v -> transferFlow state sparseState g v fnTransfer
        | None -> ()

  let propagate g state sparseState fnTransfer =
    (state: VarBasedDataFlowState<_>).PendingVertices
    |> Seq.iter (fun vid -> sparseState.FlowQueue.Enqueue (-1, vid) |> ignore)
    while not sparseState.FlowQueue.IsEmpty
          || not sparseState.DefSiteQueue.IsEmpty do
      processFlow g state sparseState fnTransfer
      processDefSite g state sparseState fnTransfer

  let calculateStackPointer g state =
    propagate g state state.StackPointerSparseState transferStackPointer

  let calculateLattice g state =
    propagate g state state.DomainSparseState transferLattice

  let computeIncrementally g state =
    let domCtx = Dominator.initDominatorContext g
    let domTree, _ = Dominator.dominatorTree domCtx
    let domFrontiers = Dominator.frontiers domCtx
    let sw = System.Diagnostics.Stopwatch ()
    sw.Start ()
    calculateChainsIncrementally g state domCtx domTree domFrontiers
    sw.Stop ()
    let time1 = sw.ElapsedMilliseconds
    sw.Reset ()
    sw.Start ()
    calculateStackPointer g state
    sw.Stop ()
    let time2 = sw.ElapsedMilliseconds
    sw.Reset ()
    sw.Start ()
    calculateChainsIncrementally g state domCtx domTree domFrontiers
    sw.Stop ()
    let time3 = sw.ElapsedMilliseconds
    sw.Reset ()
    sw.Start ()
    calculateLattice g state
    sw.Stop ()
    let time4 = sw.ElapsedMilliseconds
    sw.Reset ()
    // state.Times <- (time1, time2, time3, time4)
    state.PendingVertices.Clear ()
    state

  let isFirstTime state =
    Seq.isEmpty (state: VarBasedDataFlowState<_>).DefUseMap

  let addPendingVertices vs state =
    let pendingVertices = (state: VarBasedDataFlowState<_>).PendingVertices
    Seq.iter (fun (v: IVertex<_>) -> pendingVertices.Add v.ID |> ignore) vs
    state

  interface IDataFlowAnalysis<IRVarPoint,
                              'Lattice,
                              VarBasedDataFlowState<'Lattice>,
                              LowUIRBasicBlock> with

    member __.InitializeState vs =
      VarBasedDataFlowState<'Lattice> (hdl, analysis)
      |> analysis.OnInitialize
      |> addPendingVertices vs

    /// We have three ways to compute the data flow analysis: exhaustive,
    /// incremental1, and incremental2. The exhaustive computation calculates
    /// the def-use/use-def chains from scratch as Cytron's algorithm does. Both
    /// incremental1 and incremental2 calculate the chains incrementally. The
    /// difference between them is that incremental1 calculates the chains
    /// using order-based abstract interpretation, while incremental2 uses the
    /// dominator tree to reduce the number of visiting vertices.
    member __.Compute g state =
      computeIncrementally g state