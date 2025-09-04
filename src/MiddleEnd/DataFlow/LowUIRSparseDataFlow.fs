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

/// Provides types and functions for LowUIR-based sparse data-flow analysis.
module B2R2.MiddleEnd.DataFlow.LowUIRSparseDataFlow

open System.Collections.Generic
open B2R2
open B2R2.Collections
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.BinGraph

/// Translate the given stack pointer address to a local frame offset.
let inline toFrameOffset stackAddr =
  int (stackAddr - Constants.InitialStackPointer)

/// Represents a state used in LowUIR-based sparse dataflow analysis.
[<AllowNullLiteral>]
type State<'Lattice when 'Lattice: equality>
  public(hdl: BinHandle,
         lattice: ILattice<'Lattice>,
         scheme: IScheme<'Lattice>) =

  /// Initial stack pointer value in the stack pointer domain.
  let spInitial =
    match hdl.RegisterFactory.StackPointer with
    | None -> None
    | Some rid ->
      let rt = hdl.RegisterFactory.GetRegType rid
      let varKind = Regular rid
      let bv = BitVector(Constants.InitialStackPointer, rt)
      let c = StackPointerDomain.ConstSP bv
      Some(varKind, c)

  /// Mapping from a CFG vertex to its StmtInfo array.
  let stmtInfoCache = Dictionary<IVertex<LowUIRBasicBlock>, StmtInfo[]>()

  /// Mapping from a VarPoint to its abstract value in the user's domain.
  let domainAbsValues = Dictionary<VarPoint, 'Lattice>()

  /// Mapping from a VarPoint to its abstract value in the stack-pointer domain.
  let spAbsValues = Dictionary<VarPoint, StackPointerDomain.Lattice>()

  let phiInfos = Dictionary<IVertex<LowUIRBasicBlock>, PhiInfo>()

  let perVertexIncomingDefs =
    Dictionary<IVertex<LowUIRBasicBlock>, Map<VarKind, VarPoint>>()

  let perVertexOutgoingDefs =
    Dictionary<IVertex<LowUIRBasicBlock>, Map<VarKind, VarPoint>>()

  let defUseMap = Dictionary<VarPoint, HashSet<VarPoint>>()

  let useDefMap = Dictionary<VarPoint, VarPoint>()

  let stmtOfBBLs = Dictionary<ProgramPoint, StmtOfBBL>()

  /// Set of vertices that need to be analyzed for reconstructing data flow
  /// information.
  let verticesForProcessing = HashSet<IVertex<LowUIRBasicBlock>>()

  /// Queue of vertices that need to be removed.
  let verticesForRemoval = Queue<IVertex<LowUIRBasicBlock>>()

  /// SSA variable identifier counter.
  let mutable ssaVarCounter = 0

  /// A mapping from a variable point to its corresponding SSA variable.
  let vpToSSAVar = Dictionary<VarPoint, SSA.Variable>()

  /// A mapping from an SSA variable to its corresponding variable point.
  let ssaVarToVp = Dictionary<SSA.Variable, VarPoint>()

  let domainGetAbsValue vp =
    match domainAbsValues.TryGetValue vp with
    | false, _ -> lattice.Bottom
    | true, v -> v

  let spGetAbsValue vp =
    match spAbsValues.TryGetValue vp with
    | false, _ -> StackPointerDomain.Undef
    | true, c -> c

  let spGetInitialAbsValue varKind =
    match spInitial with
    | Some(stackVar, c) when varKind = stackVar -> c
    | _ -> StackPointerDomain.Undef

  let spEvaluateVar varKind pp =
    let vp = { ProgramPoint = pp; VarKind = varKind }
    match useDefMap.TryGetValue vp with
    | false, _ -> spGetInitialAbsValue varKind
    | true, defVp -> spGetAbsValue defVp

  let rec spEvaluateExpr pp (e: Expr) =
    match e with
    | Num(bv, _) -> StackPointerDomain.ConstSP bv
    | Var _ | TempVar _ -> spEvaluateVar (VarKind.ofIRExpr e) pp
    | Load(_, _, addr, _) ->
      match spEvaluateExpr pp addr with
      | StackPointerDomain.ConstSP bv ->
        let offset = BitVector.ToUInt64 bv |> toFrameOffset
        spEvaluateVar (StackLocal offset) pp
      | c -> c
    | BinOp(binOpType, _, e1, e2, _) ->
      let v1 = spEvaluateExpr pp e1
      let v2 = spEvaluateExpr pp e2
      match binOpType with
      | BinOpType.ADD -> StackPointerDomain.add v1 v2
      | BinOpType.SUB -> StackPointerDomain.sub v1 v2
      | BinOpType.AND -> StackPointerDomain.``and`` v1 v2
      | _ -> StackPointerDomain.NotConstSP
    | _ -> StackPointerDomain.NotConstSP

  /// Updates the mapping from a program point to its corresponding statements.
  let updatePPToStmts stmts v =
    Array.iter (fun (stmt, pp) -> stmtOfBBLs[pp] <- (stmt, v)) stmts

  let rec getStatements (v: IVertex<LowUIRBasicBlock>) =
    match stmtInfoCache.TryGetValue v with
    | true, stmts -> stmts
    | false, _ ->
      let pp = v.VData.Internals.PPoint
      let stmts = getStatementsAux v pp
      updatePPToStmts stmts v
      stmtInfoCache[v] <- stmts
      stmts

  and getStatementsAux (v: IVertex<LowUIRBasicBlock>) (pp: ProgramPoint) =
    if not v.VData.Internals.IsAbstract then (* regular vertex *)
      let startPos = pp.Position
      v.VData.Internals.LiftedInstructions
      |> Array.collect (fun ins ->
        ins.Stmts |> Array.mapi (fun i stmt ->
          stmt, ProgramPoint(ins.Original.Address, startPos + i)))
    else (* abstract vertex *)
      let startPos = 1 (* we reserve 0 for phi definitions. *)
      let cs = Option.get pp.CallSite
      let addr = pp.Address
      v.VData.Internals.AbstractContent.Rundown
      |> Array.mapi (fun i s -> s, ProgramPoint(cs, addr, startPos + i))

  /// Returns a fresh identifier for the given variable kind and increments the
  /// identifier.
  let getNewVarId () =
    ssaVarCounter <- ssaVarCounter + 1
    ssaVarCounter

  /// Converts a variable kind to an SSA variable kind.
  let toSSAVarKind vk =
    match vk with
    | Regular rid ->
      let rt = hdl.RegisterFactory.GetRegType rid
      let rname = hdl.RegisterFactory.GetRegString rid
      SSA.RegVar(rt, rid, rname)
    | Memory(Some _) -> SSA.MemVar
    | Memory None -> SSA.MemVar
    | StackLocal offset -> SSA.StackVar(0<rt>, offset)
    | Temporary n ->
      let rt = 0<rt>
      SSA.TempVar(rt, n)

  /// Returns an SSA variable for the given variable point.
  let getSSAVar vp =
    match vpToSSAVar.TryGetValue vp with
    | true, v -> v
    | false, _ ->
      let ssaVarId = getNewVarId ()
      let ssaVarKind = toSSAVarKind vp.VarKind
      let ssaVar = { SSA.Kind = ssaVarKind; SSA.Identifier = ssaVarId }
      vpToSSAVar[vp] <- ssaVar
      ssaVarToVp[ssaVar] <- vp
      ssaVar

  /// Returns an empty SSA variable for the given variable kind.
  let mkEmptySSAVar vk = { SSA.Kind = toSSAVarKind vk; SSA.Identifier = 0 }

  /// Returns an SSA variable for the given use.
  let getSSAVarFromUse pp vk =
    let vp = { ProgramPoint = pp; VarKind = vk }
    match useDefMap.TryGetValue vp with
    | false, _ -> mkEmptySSAVar vp.VarKind (* coming from its caller context *)
    | true, defVp -> getSSAVar defVp

  /// Translates an IR expression to its SSA expression.
  let rec translateToSSAExpr (pp: ProgramPoint) e =
    match e with
    | Num(bv, _) -> SSA.Num bv
    | PCVar(rt, _, _) ->
      assert (Option.isNone pp.CallSite)
      SSA.Num <| BitVector(pp.Address, rt)
    | Var _ | TempVar _ ->
      let vk = VarKind.ofIRExpr e
      let ssaVar = getSSAVarFromUse pp vk
      SSA.Var ssaVar
    | ExprList(exprs, _) ->
      List.map (translateToSSAExpr pp) exprs
      |> SSA.ExprList
    | Load(_, rt, addr, _) ->
      match spEvaluateExpr pp addr with
      | StackPointerDomain.ConstSP bv ->
        let offset = BitVector.ToUInt64 bv |> toFrameOffset
        let vk = StackLocal offset
        let ssaVar = getSSAVarFromUse pp vk
        SSA.Var ssaVar
      | _ ->
        let emptyMemVar = mkEmptySSAVar (Memory None)
        let e = translateToSSAExpr pp addr
        SSA.Load(emptyMemVar, rt, e)
    | BinOp(binOpType, rt, e1, e2, _) ->
      let e1 = translateToSSAExpr pp e1
      let e2 = translateToSSAExpr pp e2
      SSA.BinOp(binOpType, rt, e1, e2)
    | RelOp(relOpType, e1, e2, _) ->
      let rt = Expr.TypeOf e1
      let e1 = translateToSSAExpr pp e1
      let e2 = translateToSSAExpr pp e2
      SSA.RelOp(relOpType, rt, e1, e2)
    | Extract(e, rt, startPos, _) ->
      let e = translateToSSAExpr pp e
      SSA.Extract(e, rt, startPos)
    | UnOp(unOpType, e, _) ->
      let rt = Expr.TypeOf e
      let e = translateToSSAExpr pp e
      SSA.UnOp(unOpType, rt, e)
    | Cast(castKind, rt, e, _) ->
      let e = translateToSSAExpr pp e
      SSA.Cast(castKind, rt, e)
    | FuncName(s, _) -> SSA.FuncName s
    | Undefined(rt, s, _) -> SSA.Undefined(rt, s)
    | Ite(e1, e2, e3, _) ->
      let rt = Expr.TypeOf e2
      let e1 = translateToSSAExpr pp e1
      let e2 = translateToSSAExpr pp e2
      let e3 = translateToSSAExpr pp e3
      SSA.Ite(e1, rt, e2, e3)
    | _ -> Terminator.impossible ()

  let translateLabel addr = function
    | JmpDest(lbl, _) -> lbl
    | Undefined(_, s, _) -> AST.label s -1 addr
    | _ -> raise InvalidExprException

  /// Translate an ordinary IR statement to an SSA statement. It returns a dummy
  /// exception statement if the given IR statement is invalid.
  let translateToSSAStmt pp stmt =
    match stmt with
    | Put(dst, src, _) ->
      let vk = VarKind.ofIRExpr dst
      let vp = { ProgramPoint = pp; VarKind = vk }
      let v = getSSAVar vp
      let e = translateToSSAExpr pp src
      SSA.Def(v, e)
    | Store(_, addr, value, _) ->
      match spEvaluateExpr pp addr with
      | StackPointerDomain.ConstSP bv ->
        let offset = BitVector.ToUInt64 bv |> toFrameOffset
        let vk = StackLocal offset
        let vp = { ProgramPoint = pp; VarKind = vk }
        let v = getSSAVar vp
        let e = translateToSSAExpr pp value
        SSA.Def(v, e)
      | _ ->
        let prevMemVar = mkEmptySSAVar (Memory None) (* empty one *)
        let newMemVar = getSSAVar { ProgramPoint = pp; VarKind = Memory None }
        let rt = Expr.TypeOf value
        let e1 = translateToSSAExpr pp addr
        let e2 = translateToSSAExpr pp value
        let e = SSA.Store(prevMemVar, rt, e1, e2)
        SSA.Def(newMemVar, e)
    | Jmp(expr, _) ->
      let addr = 0x0UL (* use dummy address for simplicity *)
      let label = translateLabel addr expr
      let e = SSA.IntraJmp label
      SSA.Jmp e
    | CJmp(expr, label1, label2, _) ->
      let addr = 0x0UL (* use dummy address for simplicity *)
      let expr = translateToSSAExpr pp expr
      let label1 = translateLabel addr label1
      let label2 = translateLabel addr label2
      let e = SSA.IntraCJmp(expr, label1, label2)
      SSA.Jmp e
    | InterJmp(expr, _, _) ->
      let expr = translateToSSAExpr pp expr
      let e = SSA.InterJmp(expr)
      SSA.Jmp e
    | InterCJmp(expr1, expr2, expr3, _) ->
      let expr1 = translateToSSAExpr pp expr1
      let expr2 = translateToSSAExpr pp expr2
      let expr3 = translateToSSAExpr pp expr3
      let e = SSA.InterCJmp(expr1, expr2, expr3)
      SSA.Jmp e
    | SideEffect(sideEff, _) ->
      SSA.SideEffect sideEff
    | _ ->
      SSA.SideEffect <| Exception "Invalid SSA stmt encountered"

  let convertDefsToIds defs =
    defs
    |> Seq.map (fun def ->
      let v = getSSAVar def
      v.Identifier)
    |> Seq.toArray

  /// Generates a phi statement for the given variable point.
  let generatePhiSSAStmt vp =
    let _, v = stmtOfBBLs[vp.ProgramPoint]
    let phiInfo = phiInfos[v]
    let varKind = vp.VarKind
    let defs = phiInfo[varKind]
    let var = getSSAVar vp
    let ids = convertDefsToIds defs.Values
    SSA.Phi(var, ids)

  let domainSubState =
    let flowQueue = UniqueQueue()
    let defSiteQueue = UniqueQueue()
    let executedFlows = HashSet()
    let executedVertices = HashSet()
    { new ISubstate<'Lattice> with
        member _.FlowQueue = flowQueue
        member _.DefSiteQueue = defSiteQueue
        member _.ExecutedFlows = executedFlows
        member _.ExecutedVertices = executedVertices
        member _.Bottom = lattice.Bottom
        member _.GetAbsValue vp = domainGetAbsValue vp
        member _.SetAbsValue(vp, absVal) = domainAbsValues[vp] <- absVal
        member _.Join(a, b) = lattice.Join(a, b)
        member _.Subsume(a, b) = lattice.Subsume(a, b) }

  let spSubState =
    let flowQueue = UniqueQueue()
    let defSiteQueue = UniqueQueue()
    let executedFlows = HashSet()
    let executedVertices = HashSet()
    { new ISubstate<StackPointerDomain.Lattice> with
        member _.FlowQueue = flowQueue
        member _.DefSiteQueue = defSiteQueue
        member _.ExecutedFlows = executedFlows
        member _.ExecutedVertices = executedVertices
        member _.Bottom = StackPointerDomain.Undef
        member _.GetAbsValue vp = spGetAbsValue vp
        member _.SetAbsValue(vp, absVal) = spAbsValues[vp] <- absVal
        member _.Join(a, b) = StackPointerDomain.join a b
        member _.Subsume(a, b) = StackPointerDomain.subsume a b }

  let resetSubState (subState: ISubstate<_>) =
    subState.FlowQueue.Clear()
    subState.DefSiteQueue.Clear()
    subState.ExecutedFlows.Clear()
    subState.ExecutedVertices.Clear()

  let reset () =
    stmtInfoCache.Clear()
    domainAbsValues.Clear()
    spAbsValues.Clear()
    phiInfos.Clear()
    perVertexIncomingDefs.Clear()
    perVertexOutgoingDefs.Clear()
    defUseMap.Clear()
    useDefMap.Clear()
    stmtOfBBLs.Clear()
    verticesForProcessing.Clear()
    vpToSSAVar.Clear()
    ssaVarCounter <- 0
    ssaVarToVp.Clear()
    resetSubState spSubState
    resetSubState domainSubState

  /// Binary handle associated with this state.
  member _.BinHandle with get() = hdl

  /// Scheme used for this data flow analysis.
  member _.Scheme with get() = scheme

  /// Evaluate the given expression at the given program point in the
  /// stack-pointer domain in order to retrieve a concrete stack pointer value
  /// if exists.
  member _.EvaluateStackPointerExpr(pp, e: Expr) =
    spEvaluateExpr pp e

  /// Mapping from a CFG vertex to its phi information.
  member _.PhiInfos with get() = phiInfos

  /// Mapping from a CFG vertex to its incoming definitions.
  member _.PerVertexIncomingDefs with get() = perVertexIncomingDefs

  /// Mapping from a CFG vertex to its outgoing definitions.
  member _.PerVertexOutgoingDefs with get() = perVertexOutgoingDefs

  /// Mapping from a variable def to its uses.
  member _.DefUseMap with get() = defUseMap

  /// Mapping from a variable use to its definition.
  member _.UseDefMap with get() = useDefMap

  /// Mapping from a SSA variable to its corresponding variable point.
  member _.SSAVarToVp with get() = ssaVarToVp

  /// Mapping from a program point to `StmtOfBBL`, which is a pair of a Low-UIR
  /// statement and its corresponding vertex that contains the statement.
  member _.StmtOfBBLs with get() = stmtOfBBLs

  /// Sub-state for the stack-pointer domain.
  member internal _.StackPointerSubState with get() = spSubState

  /// Sub-state for the user's domain.
  member _.DomainSubState with get() = domainSubState

  /// Currently pending vertices for processing.
  member _.PendingVertices with get(): IEnumerable<IVertex<LowUIRBasicBlock>> =
    verticesForProcessing

  /// Mark the given vertex as pending, which means that the vertex needs to be
  /// processed.
  member _.MarkVertexAsPending v = verticesForProcessing.Add v |> ignore

  /// Mark the given vertex as removal, which means that the vertex needs to be
  /// removed.
  member _.MarkVertexAsRemoval v = verticesForRemoval.Enqueue v |> ignore

  /// Check if the given vertex is pending for processing.
  member _.IsVertexPending v = verticesForProcessing.Contains v

  /// Clear the pending vertices.
  member _.ClearPendingVertices() = verticesForProcessing.Clear()

  /// Enqueue the pending vertices to the given sub-state.
  member internal _.EnqueuePendingVertices(subState: ISubstate<_>) =
    for v in verticesForProcessing do
      subState.FlowQueue.Enqueue(null, v)

  /// Dequeue the vertex for removal. When there is no vertex to remove, it
  /// returns `false`.
  member _.DequeueVertexForRemoval() = verticesForRemoval.TryDequeue()

  /// Return the array of StmtInfos of the given vertex.
  member _.GetStmtInfos v = getStatements v

  /// Return the terminator statment of the given vertex in an SSA form.
  member _.GetTerminatorInSSA v =
    getStatements v
    |> Array.last
    |> fun (irStmt, pp) -> translateToSSAStmt pp irStmt

  /// Try to get the definition of the given SSA variable in an SSA form.
  member _.TryGetSSADef v =
    if not <| ssaVarToVp.ContainsKey v then None
    else
      let vp = ssaVarToVp[v]
      let pp = vp.ProgramPoint
      let stmt, v = stmtOfBBLs[pp]
      let pp' = v.VData.Internals.PPoint
      let isPhi = pp = pp'
      if not isPhi then
        match translateToSSAStmt pp stmt with
        | SSA.SideEffect _ -> None
        | s -> Some s
      else generatePhiSSAStmt vp |> Some

  member _.GetAbsValue v = domainGetAbsValue ssaVarToVp[v]

  /// Reset this state.
  member _.Reset() = reset ()

  interface IAbsValProvider<VarPoint, 'Lattice> with
    member _.GetAbsValue absLoc = domainGetAbsValue absLoc

/// Represents a substate for the LowUIR-based sparse dataflow analysis.
and ISubstate<'Lattice when 'Lattice: equality> =
  inherit IAbsValProvider<VarPoint, 'Lattice>
  inherit ILattice<'Lattice>

  /// The edge queue for calculating the data flow.
  abstract FlowQueue:
    UniqueQueue<IVertex<LowUIRBasicBlock> | null * IVertex<LowUIRBasicBlock>>

  /// The definition site queue for calculating the data flow.
  abstract DefSiteQueue: UniqueQueue<ProgramPoint>

  /// Executed edges during the data flow calculation.
  abstract ExecutedFlows:
    HashSet<IVertex<LowUIRBasicBlock> * IVertex<LowUIRBasicBlock>>

  /// Executed vertices during the data flow calculation.
  abstract ExecutedVertices: HashSet<IVertex<LowUIRBasicBlock>>

  /// Get the abstract value at the given location.
  abstract SetAbsValue: vp: VarPoint * 'Lattice -> unit

/// A mapping from a variable kind of a phi to its definitions. We represent
/// each definition as a mapping from predecessor's program point to a variable
/// point. This way, a definition from the same predecessor can be replaced by
/// the latest definition.
and private PhiInfo = Dictionary<VarKind, Dictionary<ProgramPoint, VarPoint>>

/// Represents how we perform LowUIR-based sparse dataflow analysis.
and IScheme<'Lattice when 'Lattice: equality> =
  inherit IExprEvaluatable<ProgramPoint, 'Lattice>

[<AutoOpen>]
module internal AnalysisCore = begin

  /// Dataflow chains become invalid when a vertex is removed from the graph.
  let rec removeInvalidChains (state: State<_>) =
    match state.DequeueVertexForRemoval() with
    | true, v when state.PerVertexIncomingDefs.ContainsKey v ->
      for (_, pp) in state.GetStmtInfos v do
        state.StmtOfBBLs.Remove pp |> ignore
      state.PhiInfos.Remove v |> ignore
      state.PerVertexIncomingDefs.Remove v |> ignore
      state.PerVertexOutgoingDefs.Remove v |> ignore
      removeInvalidChains state
    | true, _ -> removeInvalidChains state
    | false, _ -> ()

  let getStackValue (state: State<_>) pp e =
    match state.EvaluateStackPointerExpr(pp, e) with
    | StackPointerDomain.ConstSP bv -> Ok <| BitVector.ToUInt64 bv
    | _ -> Error ErrorCase.InvalidExprEvaluation

  /// Linear time algorithm to compute the inverse dominance frontier.
  let computeInverseDF (g: IDiGraph<_, _>) (dom: IDominance<_, _>) v =
    let s = HashSet()
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
    let workset = HashSet()
    for v in (state: State<_>).PendingVertices do
      if not <| (g: IDiGraph<_, _>).HasVertex v.ID then ()
      else
        workset.Add v |> ignore
        for succ in g.GetSuccs v do
          if g.GetPreds succ |> Seq.length > 1 then
            workset.Add succ |> ignore
    workset

  let placePhi state v varKind =
    let phiInfos = (state: State<_>).PhiInfos
    if not <| phiInfos.ContainsKey v then
      phiInfos[v] <- PhiInfo ()
    let phiInfo = phiInfos[v]
    if not <| phiInfo.ContainsKey varKind then
      phiInfo[varKind] <- Dictionary ()

  let isInnerScopeVarKind (v: IVertex<LowUIRBasicBlock>) = function
    | Temporary _ when v.VData.Internals.PPoint.Address = 0UL -> true
    | _ -> false

  let getDefinedVarKinds memo (state: State<_>) v =
    match (memo: Dictionary<_, _>).TryGetValue v with
    | true, kinds -> kinds
    | false, _ ->
      let varKinds = HashSet()
      for (stmt, pp) in state.GetStmtInfos v do
        match stmt with
        | Put(dst, _, _) ->
          let vk = VarKind.ofIRExpr dst
          varKinds.Add vk |> ignore
        | Store(_, addr, _, _) ->
          getStackValue state pp addr
          |> Result.iter (fun loc ->
            let offset = toFrameOffset loc
            let vk = StackLocal offset
            varKinds.Add vk |> ignore)
        | _ -> ()
      memo[v] <- varKinds
      varKinds

  /// We do not calculate all dominance frontier sets, but only those that are
  /// selectively used to insert phi nodes.
  let placePhis g state (dom: IDominance<_, _>) =
    let memo = Dictionary()
    for v in collectPhiInsertionCandidates g state do
      for affectingVertex in computeInverseDF g dom v do
        for varKind in getDefinedVarKinds memo state affectingVertex do
          if not (isInnerScopeVarKind v varKind) then
            placePhi state v varKind

  let updateIncomingDefsWithPhis state (v: IVertex<LowUIRBasicBlock>) ins =
    match (state: State<_>).PhiInfos.TryGetValue v with
    | false, _ -> ins
    | true, phiInfo ->
      let pp = v.VData.Internals.PPoint
      phiInfo.Keys
      |> Seq.fold (fun ins vk ->
        let vp = { ProgramPoint = pp; VarKind = vk }
        Map.add vk vp ins) ins

  let removeOldChains state useVp defVp =
    match (state: State<_>).UseDefMap.TryGetValue useVp with
    | true, prevDef when prevDef.ProgramPoint <> defVp.ProgramPoint ->
      (* Erase the old def-use. *)
      state.DefUseMap[prevDef].Remove useVp |> ignore
      (* Erase the old use-def which will be overwritten by the new def. *)
      state.UseDefMap.Remove useVp |> ignore
    | _ -> ()

  let updateDefUseChain state useVp defVp =
    match (state: State<_>).DefUseMap.TryGetValue defVp with
    | false, _ -> state.DefUseMap[defVp] <- HashSet [ useVp ]
    | true, uses -> uses.Add useVp |> ignore

  let updateUseDefChain state useVp defVp =
    (state: State<_>).UseDefMap[useVp] <- defVp

  let updateChains state vk defs pp =
    match Map.tryFind vk defs with
    | None -> ()
    | Some defVp ->
      let useVp = { ProgramPoint = pp; VarKind = vk }
      removeOldChains state useVp defVp
      updateDefUseChain state useVp defVp
      updateUseDefChain state useVp defVp

  let rec updateWithExpr state defs (pp: ProgramPoint) = function
    | Num(_)
    | Undefined(_)
    | FuncName(_) -> ()
    | Var(_rt, rid, _rstr, _) -> updateChains state (Regular rid) defs pp
    | TempVar(_, n, _) -> updateChains state (Temporary n) defs pp
    | ExprList(exprs, _) ->
      exprs |> List.iter (updateWithExpr state defs pp)
    | Load(_, _, expr, _) ->
      updateWithExpr state defs pp expr
      getStackValue state pp expr
      |> Result.iter (fun loc ->
        let offset = toFrameOffset loc
        updateChains state (StackLocal offset) defs pp)
      updateWithExpr state defs pp expr
    | UnOp(_, expr, _) ->
      updateWithExpr state defs pp expr
    | BinOp(_, _, expr1, expr2, _) ->
      updateWithExpr state defs pp expr1
      updateWithExpr state defs pp expr2
    | RelOp(_, expr1, expr2, _) ->
      updateWithExpr state defs pp expr1
      updateWithExpr state defs pp expr2
    | Ite(expr1, expr2, expr3, _) ->
      updateWithExpr state defs pp expr1
      updateWithExpr state defs pp expr2
      updateWithExpr state defs pp expr3
    | Cast(_, _, expr, _) ->
      updateWithExpr state defs pp expr
    | Extract(expr, _, _, _) ->
      updateWithExpr state defs pp expr
    | _ -> ()

  let updateWithJmp state defs pp = function
    | Jmp(expr, _) ->
      updateWithExpr state defs pp expr
    | CJmp(expr, target1, target2, _) ->
      updateWithExpr state defs pp expr
      updateWithExpr state defs pp target1
      updateWithExpr state defs pp target2
    | InterJmp(expr, _jmpKind, _) ->
      updateWithExpr state defs pp expr
    | InterCJmp(cond, target1, target2, _) ->
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
    | Put(dst, src, _) ->
      updateWithExpr state defs pp src
      let kind = VarKind.ofIRExpr dst
      let vp = { ProgramPoint = pp; VarKind = kind }
      defs <- Map.add kind vp defs
      if not (VarKind.isTemporary kind) then outs <- Map.add kind vp outs
      else ()
    | Store(_, addr, value, _) ->
      updateWithExpr state defs pp addr
      updateWithExpr state defs pp value
      match getStackValue state pp addr with
      | Ok loc ->
        let offset = toFrameOffset loc
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
  let updateChainsWithBBLStmts g (state: State<_>) v defs =
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

  let getOutgoingDefs (state: State<_>) v =
    match state.PerVertexOutgoingDefs.TryGetValue v with
    | false, _ -> Map.empty
    | true, defs -> defs

  /// We only visit the vertices that have changed and update data-flow chains.
  let rec incrementalUpdate g state visited (dom: IDominance<_, _>) v =
    if (visited: HashSet<_>).Contains v then ()
    elif (state: State<_>).IsVertexPending v
         && (g: IDiGraph<_, _>).HasVertex v.ID then
      let idom = dom.ImmediateDominator v
      let defs = if isNull idom then Map.empty else getOutgoingDefs state idom
      update g state dom.DominatorTree visited v defs
    else
      for child in dom.DominatorTree.GetChildren v do
        incrementalUpdate g state visited dom child

  #if DEBUG
  let hasProperPhiOperandNumbers state g v =
    match (state: State<_>).PhiInfos.TryGetValue v with
    | false, _ -> true
    | true, phiInfo ->
      let predCount = (g: IDiGraph<_, _>).GetPreds v |> Seq.length
      phiInfo.Values |> Seq.forall (fun d -> d.Count <= predCount)
  #endif

  let getEndPP (state: State<_>) v =
    (state: State<_>).GetStmtInfos v
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
  let updatePhis g (state: State<_>) visited =
    for v in visited do
      match state.PhiInfos.TryGetValue v with
      | true, phiInfo ->
        for (KeyValue(vk, inDefs)) in phiInfo do
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
    let visited = HashSet<IVertex<LowUIRBasicBlock>>()
    placePhis g state dom
    incrementalUpdate g state visited dom g.SingleRoot
    updatePhis g state visited

  let isStackRelatedRegister (hdl: BinHandle) rid =
    hdl.RegisterFactory.IsStackPointer rid
    || hdl.RegisterFactory.IsFramePointer rid

  let updateAbsValue subState defUseMap vp prev curr =
    if (subState: ISubstate<_>).Subsume(prev, curr) then ()
    else
      subState.SetAbsValue(vp, subState.Join(prev, curr))
      match (defUseMap: Dictionary<_, _>).TryGetValue vp with
      | false, _ -> ()
      | true, defs ->
        defs
        |> Seq.iter (fun vp -> subState.DefSiteQueue.Enqueue vp.ProgramPoint)

  let spTransfer (state: State<_>) (stmt, pp) =
    match stmt with
    | Put(dst, src, _) ->
      let varKind = VarKind.ofIRExpr dst
      let currConst =
        match varKind with
        | Regular rid when isStackRelatedRegister state.BinHandle rid ->
          state.EvaluateStackPointerExpr(pp, src)
          |> Some
        | Regular _ -> StackPointerDomain.NotConstSP |> Some
        | Temporary _ -> state.EvaluateStackPointerExpr(pp, src) |> Some
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

  let domainTransfer (state: State<_>) (stmt, pp) =
    match stmt with
    | Put(dst, src, _) ->
      let varKind = VarKind.ofIRExpr dst
      let vp = { ProgramPoint = pp; VarKind = varKind }
      let subState = state.DomainSubState
      let prev = subState.GetAbsValue vp
      let curr = state.Scheme.EvalExpr(pp, src)
      let defUseMap = state.DefUseMap
      updateAbsValue subState defUseMap vp prev curr
    | Store(_, addr, value, _) ->
      match state.EvaluateStackPointerExpr(pp, addr) with
      | StackPointerDomain.ConstSP bv ->
        let loc = BitVector.ToUInt64 bv
        let offset = toFrameOffset loc
        let varKind = StackLocal offset
        let vp = { ProgramPoint = pp; VarKind = varKind }
        let subState = state.DomainSubState
        let prev = subState.GetAbsValue vp
        let curr = state.Scheme.EvalExpr(pp, value)
        let defUseMap = state.DefUseMap
        updateAbsValue subState defUseMap vp prev curr
      | _ -> ()
    | _ -> ()

  let transferPhi state subState phiInfo defPp =
    phiInfo
    |> Seq.iter (fun (KeyValue(varKind, defs: Dictionary<_, _>)) ->
      let vp = { ProgramPoint = defPp; VarKind = varKind }
      let prev = (subState: ISubstate<_>).GetAbsValue vp
      let curr =
        defs.Values |> Seq.fold (fun c (def: VarPoint) ->
          subState.Join(c, subState.GetAbsValue def)) subState.Bottom
      let defUseMap = (state: State<_>).DefUseMap
      updateAbsValue subState defUseMap vp prev curr)

  let isExecuted state (subState: ISubstate<_>) defPp =
    match (state: State<_>).StmtOfBBLs.TryGetValue defPp with
    | false, _ -> false
    | true, (_, v) -> subState.ExecutedVertices.Contains v

  let processDefSite state (subState: ISubstate<_>) fnTransfer =
    match subState.DefSiteQueue.TryDequeue() with
    | true, defPp when isExecuted state subState defPp ->
      if defPp.Position <> 0 then (* non-phi *)
        let stmt, _ = (state: State<_>).StmtOfBBLs[defPp]
        fnTransfer state (stmt, defPp)
      else (* phi *)
        let _, bbl = state.StmtOfBBLs[defPp]
        assert (state.PhiInfos.ContainsKey bbl)
        transferPhi state subState state.PhiInfos[bbl] defPp
    | _ -> ()

  let transferFlow state subState g v fnTransfer =
    (subState: ISubstate<_>).ExecutedVertices.Add v |> ignore
    (* Execute phis first. *)
    match (state: State<_>).PhiInfos.TryGetValue v with
    | false, _ -> ()
    | true, phiInfo ->
      transferPhi state subState phiInfo v.VData.Internals.PPoint
    for stmt in state.GetStmtInfos v do fnTransfer state stmt done
    (g: IDiGraph<_, _>).GetSuccs v
    |> Array.map (fun succ -> v, succ)
    |> Array.iter subState.FlowQueue.Enqueue

  let processFlow g state subState fnTransfer =
    match (subState: ISubstate<_>).FlowQueue.TryDequeue() with
    | false, _ -> ()
    | true, (src, dst) ->
      if not <| subState.ExecutedFlows.Add(src, dst) then ()
      else
        match (g: IDiGraph<_, _>).TryFindVertexByID dst.ID with
        | Some v -> transferFlow state subState g v fnTransfer
        | None -> ()

  let registerPendingVertices state (subState: ISubstate<_>) =
    (state: State<_>).EnqueuePendingVertices subState

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

end (* end of AnalysisCore *)

/// Compute the data flow incrementally.
let compute g (state: State<_>) =
  let df = Dominance.CooperDominanceFrontier()
  let dom = Dominance.LengauerTarjanDominance.create g df
  removeInvalidChains state
  calculateChains g state dom
  propagateStackPointer g state
  calculateChains g state dom
  propagateDomain g state
  state.ClearPendingVertices()
  state
