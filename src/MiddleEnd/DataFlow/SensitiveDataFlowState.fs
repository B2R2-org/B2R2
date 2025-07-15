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
open B2R2.Collections
open B2R2.FrontEnd
open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.BinGraph
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.Collections

[<AllowNullLiteral>]
type SensitiveLowUIRDataFlowState<'L, 'ExeCtx, 'UsrCtx
                             when 'L: equality
                              and 'ExeCtx: equality
                              and 'ExeCtx: comparison
                              and 'UsrCtx: (new: unit -> 'UsrCtx)>
  public (hdl,
          analysis: ISensitiveLowUIRDataFlowAnalysis<'L, 'ExeCtx, 'UsrCtx>)
         as this =

  let defSvpUidMapper = IdMapper<SensitiveVarPoint<'ExeCtx>> ()

  let useSvpUidMapper = IdMapper<SensitiveVarPoint<'ExeCtx>> ()

  let uidToDefSvp = Dictionary<Uid, SensitiveVarPoint<'ExeCtx>> ()

  let uidToUseSvp = Dictionary<Uid, SensitiveVarPoint<'ExeCtx>> ()

  let uidToSSAVar = Dictionary<Uid, SSA.Variable> ()

  let ssaVarToUid = Dictionary<SSA.Variable, Uid> ()

  let mutable freshSSAVarId = 1

  let perVertexPossibleExeCtxs =
    Dictionary<IVertex<LowUIRBasicBlock>, HashSet<'ExeCtx>> ()

  let ssaStmtCache =
    Dictionary<IVertex<LowUIRBasicBlock> * 'ExeCtx, SSA.Stmt[]> ()

  let perPointSSAStmtCache =
    Dictionary<SensitiveProgramPoint<'ExeCtx>, SSA.Stmt> ()

  let mutable userContext = new 'UsrCtx ()

  /// Initial stack pointer value in the stack pointer domain.
  let spInitial =
    match (hdl: BinHandle).RegisterFactory.StackPointer with
    | None -> None
    | Some rid ->
      let rt = hdl.RegisterFactory.GetRegType rid
      let varKind = Regular rid
      let bv = BitVector.OfUInt64 Constants.InitialStackPointer rt
      let c = StackPointerDomain.ConstSP bv
      Some (varKind, c)

  let perVertexStackPointerInfos =
    Dictionary<IVertex<LowUIRBasicBlock> * 'ExeCtx,
               StackPointerDomain.Lattice * StackPointerDomain.Lattice> ()

  /// Mapping from a CFG vertex to its StmtInfo array.
  let stmtInfoCache = Dictionary<IVertex<LowUIRBasicBlock>, StmtInfo[]> ()

  /// Mapping from a MyVarPoint to its abstract value in the user's domain.
  let domainAbsValues = Dictionary<SensitiveVarPoint<'ExeCtx>, 'L> ()

  /// Mapping from a MyVarPoint to its abstract value in the stack-pointer
  /// domain.
  let spAbsValues =
    Dictionary<SensitiveVarPoint<'ExeCtx>, StackPointerDomain.Lattice> ()

  let perVertexIncomingDefs =
    Dictionary<IVertex<LowUIRBasicBlock> * 'ExeCtx, Map<VarKind, Set<Uid>>> ()

  let perVertexOutgoingDefs =
    Dictionary<IVertex<LowUIRBasicBlock> * 'ExeCtx, Map<VarKind, Set<Uid>>> ()

  let defUseMap = Dictionary<Uid, Set<Uid>> ()

  let useDefMap = Dictionary<Uid, Set<Uid>> ()

  let stmtOfBBLs = Dictionary<ProgramPoint, StmtOfBBL> ()

  let edgesForProcessing =
    HashSet<IVertex<LowUIRBasicBlock> * IVertex<LowUIRBasicBlock>> ()

  /// Queue of vertices that need to be removed.
  let verticesForRemoval = Queue<IVertex<LowUIRBasicBlock>> ()

  let defSvpToUid svp =
    let uid = defSvpUidMapper[svp]
    if not <| uidToDefSvp.ContainsKey uid then uidToDefSvp[uid] <- svp
    uid

  let useSvpToUid svp =
    let uid = useSvpUidMapper[svp]
    if not <| uidToUseSvp.ContainsKey uid then uidToUseSvp[uid] <- svp
    uid

  let domainGetAbsValue vp =
    match domainAbsValues.TryGetValue vp with
    | false, _ -> analysis.Bottom
    | true, v -> v

  let spGetAbsValue vp =
    match spAbsValues.TryGetValue vp with
    | false, _ -> StackPointerDomain.Undef
    | true, c -> c

  let spGetInitialAbsValue varKind =
    match spInitial with
    | Some (stackVar, c) when varKind = stackVar -> c
    | _ -> StackPointerDomain.Undef

  let spEvaluateVar varKind tpp =
    let tvp = { SensitiveProgramPoint = tpp; VarKind = varKind }
    let id = useSvpToUid tvp
    match useDefMap.TryGetValue id with
    | false, _ -> spGetInitialAbsValue varKind
    | true, ids ->
      ids
      |> Seq.fold (fun acc id ->
        let defVp = uidToDefSvp[id]
        let defAbsValue = spGetAbsValue defVp
        StackPointerDomain.join acc defAbsValue) StackPointerDomain.Undef

  let rec spEvaluateExpr myPp (e: Expr) =
    match e with
    | Num (bv, _) -> StackPointerDomain.ConstSP bv
    | Var _ | TempVar _ -> spEvaluateVar (VarKind.ofIRExpr e) myPp
    | Load (_, _, addr, _) ->
      match spEvaluateExpr myPp addr with
      | StackPointerDomain.ConstSP bv ->
        let offset =
          BitVector.ToUInt64 bv
          |> SensitiveLowUIRDataFlowState<_, _, _>.ToFrameOffset
        spEvaluateVar (StackLocal offset) myPp
      | c -> c
    | BinOp (binOpType, _, e1, e2, _) ->
      let v1 = spEvaluateExpr myPp e1
      let v2 = spEvaluateExpr myPp e2
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
          stmt, ProgramPoint (ins.Original.Address, startPos + i)))
    else (* abstract vertex *)
      let startPos = 1 (* we reserve 0 for phi definitions. *)
      let cs = Option.get pp.CallSite
      let addr = pp.Address
      v.VData.Internals.AbstractContent.Rundown
      |> Array.mapi (fun i s -> s, ProgramPoint (cs, addr, startPos + i))

  let tryGetReachingDefIdsFromUseId id =
    match useDefMap.TryGetValue id with
    | true, rds -> Some rds
    | false, _ -> None

  let generateFreshSSAVarId () =
    let id = freshSSAVarId
    freshSSAVarId <- freshSSAVarId + 1
    id

  let generateSSAVar (id: Uid) =
    assert (not <| uidToSSAVar.ContainsKey id)
    let tvp = uidToDefSvp[id]
    let tpp = tvp.SensitiveProgramPoint
    let ssaVarKind =
      match tvp.VarKind with
      | Regular rid ->
        let rt = hdl.RegisterFactory.GetRegType rid
        let rname = hdl.RegisterFactory.GetRegString rid
        SSA.RegVar (rt, rid, rname)
      | StackLocal offset ->
        let rt = 0<rt>
        SSA.StackVar (rt, offset)
      | Temporary n ->
        let rt = 0<rt>
        SSA.TempVar (rt, n)
      | _ -> Terminator.futureFeature ()
    let ssaVarId =
      if ProgramPoint.IsFake tpp.ProgramPoint then 0 (* Unreachable variable. *)
      else generateFreshSSAVarId ()
    let v = { SSA.Kind = ssaVarKind; SSA.Identifier = ssaVarId }
    uidToSSAVar[id] <- v
    ssaVarToUid[v] <- id
    v

  let defIdToSSAVar (id: Uid) =
    match uidToSSAVar.TryGetValue id with
    | true, var -> var
    | false, _ -> generateSSAVar id

  /// Converts an use to its reaching definitions. If the use has no definitions
  /// (e.g. parameter of a function), it creates a fake definition and returns
  /// it.
  let convertUseIdToReachingDefSSAExpr id exeCtx varKind =
    tryGetReachingDefIdsFromUseId id
    |> function
      | Some defIds ->
        defIds
        |> Set.toList
        |> List.map (defIdToSSAVar >> SSA.Var)
        |> SSA.ExprList
      | None -> (* Reading a value coming out of a function. *)
        let fakeDefPp = ProgramPoint.GetFake ()
        let fakeSpp = { ProgramPoint = fakeDefPp; ExecutionContext = exeCtx }
        let fakeSvp = { SensitiveProgramPoint = fakeSpp; VarKind = varKind }
        let fakeId = defSvpToUid fakeSvp
        let fakeSSAVar = defIdToSSAVar fakeId
        SSA.Var fakeSSAVar

  let rec computeSSAExpr pp exeCtx = function
    | Var _ | TempVar _ as e -> (* Track its use-def chain. *)
      let varKind = VarKind.ofIRExpr e
      let spp = { ProgramPoint = pp; ExecutionContext = exeCtx }
      let svp = { SensitiveProgramPoint = spp; VarKind = varKind }
      let id = useSvpToUid svp
      convertUseIdToReachingDefSSAExpr id exeCtx varKind
    | ExprList (l, _) -> List.map (computeSSAExpr pp exeCtx) l |> SSA.ExprList
    | UnOp (op, e, _) ->
      let sexpr = computeSSAExpr pp exeCtx e
      let rt = Expr.TypeOf e
      SSA.UnOp (op, rt, sexpr)
    | BinOp (op, rt, e1, e2, _) ->
      let sexpr1 = computeSSAExpr pp exeCtx e1
      let sexpr2 = computeSSAExpr pp exeCtx e2
      SSA.BinOp (op, rt, sexpr1, sexpr2)
    | RelOp (op, e1, e2, _) ->
      let sexpr1 = computeSSAExpr pp exeCtx e1
      let sexpr2 = computeSSAExpr pp exeCtx e2
      let rt = Expr.TypeOf e1
      SSA.RelOp (op, rt, sexpr1, sexpr2)
    | Extract (e, _, pos, _) ->
      let sexpr = computeSSAExpr pp exeCtx e
      let rt = Expr.TypeOf e
      SSA.Extract (sexpr, rt, pos)
    | Cast (op, _, e, _) ->
      let sexpr = computeSSAExpr pp exeCtx e
      let rt = Expr.TypeOf e
      SSA.Cast (op, rt, sexpr)
    | Ite (e1, e2, e3, _) ->
      let sexpr1 = computeSSAExpr pp exeCtx e1
      let sexpr2 = computeSSAExpr pp exeCtx e2
      let sexpr3 = computeSSAExpr pp exeCtx e3
      let rt = Expr.TypeOf e2
      SSA.Ite (sexpr1, rt, sexpr2, sexpr3)
    | Load (_, rt, e, _) ->
      let spp = { ProgramPoint = pp; ExecutionContext = exeCtx }
      match spEvaluateExpr spp e with
      | StackPointerDomain.ConstSP bv ->
        let varKind =
          BitVector.ToUInt64 bv
          |> SensitiveLowUIRDataFlowState<_, _, _>.ToFrameOffset
          |> StackLocal
        let useSvp = { SensitiveProgramPoint = spp; VarKind = varKind }
        let useId = useSvpToUid useSvp
        convertUseIdToReachingDefSSAExpr useId exeCtx varKind
      | _ ->
        let e = computeSSAExpr pp exeCtx e
        let fakeMemoryVar = { SSA.Kind = SSA.MemVar; SSA.Identifier = -1 }
        SSA.Load (fakeMemoryVar, rt, e)
    | PCVar (rt, _rname, _) ->
      let fakeAddr = 0xdeadbeef1UL
      let bv = BitVector.OfUInt64 fakeAddr rt
      SSA.Num bv
    | Num (bv, _) -> SSA.Num bv
    | FuncName (name, _) -> SSA.FuncName name
    | Undefined (rt, name, _) -> SSA.Undefined (rt, name)
    | JmpDest (_, _) -> Terminator.impossible ()

  /// Comptues the pseudo-SSA statement for the given statement at the given
  /// program point and execution context. Note that this function actually does
  /// not compute the exact SSA statement (e.g. it does not compute phi nodes
  /// and does not introduce fresh memory variables).
  let computeSSAStmt stmt pp exeCtx =
    match stmt with
    | Put (dstVar, e, _) ->
      let expr = computeSSAExpr pp exeCtx e
      let tpp = { ProgramPoint = pp; ExecutionContext = exeCtx }
      let varKind = VarKind.ofIRExpr dstVar
      let tvp = { SensitiveProgramPoint = tpp; VarKind = varKind }
      let id = defSvpToUid tvp
      let var = defIdToSSAVar id
      SSA.Def (var, expr)
    | Store (_, dstExpr, srcExpr, _) ->
      let tpp = { ProgramPoint = pp; ExecutionContext = exeCtx }
      match spEvaluateExpr tpp dstExpr with
      | StackPointerDomain.ConstSP bv ->
        let offset =
          BitVector.ToUInt64 bv
          |> SensitiveLowUIRDataFlowState<_, _, _>.ToFrameOffset
        let varKind = StackLocal offset
        let tvp = { SensitiveProgramPoint = tpp; VarKind = varKind }
        let id = defSvpToUid tvp
        let var = defIdToSSAVar id
        let srcExpr = computeSSAExpr pp exeCtx srcExpr
        SSA.Def (var, srcExpr)
      | _ ->
        let rt = Expr.TypeOf srcExpr
        let dstExpr = computeSSAExpr pp exeCtx dstExpr
        let srcExpr = computeSSAExpr pp exeCtx srcExpr
        let fakeInMemoryVar = { SSA.Kind = SSA.MemVar; SSA.Identifier = -1 }
        let fakeOutMemoryVar = { SSA.Kind = SSA.MemVar; SSA.Identifier = -1 }
        let storeExpr = SSA.Store (fakeInMemoryVar, rt, dstExpr, srcExpr)
        SSA.Def (fakeOutMemoryVar, storeExpr)
    | InterJmp (targetExpr, _, _) ->
      let targetExpr = computeSSAExpr pp exeCtx targetExpr
      let jmpType = SSA.InterJmp targetExpr
      SSA.Jmp jmpType
    | InterCJmp (condExpr, tTargetExpr, fTargetExpr, _) ->
      let condExpr = computeSSAExpr pp exeCtx condExpr
      let tTargetExpr = computeSSAExpr pp exeCtx tTargetExpr
      let fTargetExpr = computeSSAExpr pp exeCtx fTargetExpr
      let jmpType = SSA.InterCJmp (condExpr, tTargetExpr, fTargetExpr)
      SSA.Jmp jmpType
    | SideEffect (se, _) ->
      SSA.SideEffect se
    | ExternalCall (extCallExpr, _) ->
      let extCallSExpr = computeSSAExpr pp exeCtx extCallExpr
      let inVars = [] (* We just fill in empty variables for now. *)
      let outVars = []
      SSA.ExternalCall (extCallSExpr, inVars, outVars)
    | _ -> Terminator.impossible ()

  let getSSAStmt pp exeCtx =
    let tpp = { ProgramPoint = pp; ExecutionContext = exeCtx }
    match perPointSSAStmtCache.TryGetValue tpp with
    | true, sstmts -> sstmts
    | false, _ ->
      assert (not << ProgramPoint.IsFake) pp
      let stmt, _ = stmtOfBBLs[pp]
      let sstmt = computeSSAStmt stmt pp exeCtx
      perPointSSAStmtCache[tpp] <- sstmt
      sstmt

  let isNoOpStmt = function
    | ISMark _ | IEMark _ | LMark _ -> true
    | _ -> false

  /// Translates the statements of the given vertex with a tag into a sequence
  /// of sensitive statements.
  let computeSSAStmts v tag =
    getStatements v
    |> Array.filter (fun (stmt, _pp) -> (not << isNoOpStmt) stmt)
    |> Array.map (fun (_stmt, pp) -> getSSAStmt pp tag)

  let domainSubState =
    let flowQueue = UniqueQueue ()
    let defSiteQueue = UniqueQueue ()
    let executedFlows = HashSet ()
    let executedVertices = HashSet ()
    { new ISensitiveLowUIRDataFlowSubState<'L, 'ExeCtx> with
        member _.FlowQueue = flowQueue
        member _.DefSiteQueue = defSiteQueue
        member _.ExecutedFlows = executedFlows
        member _.ExecutedVertices = executedVertices
        member _.Bottom = analysis.Bottom
        member _.GetAbsValue vp = domainGetAbsValue vp
        member _.SetAbsValue vp absVal = domainAbsValues[vp] <- absVal
        member _.Join a b = analysis.Join a b
        member _.Subsume a b = analysis.Subsume a b
        member _.EvalExpr pp expr = analysis.EvalExpr this pp expr }

  let spSubState =
    let flowQueue = UniqueQueue ()
    let defSiteQueue = UniqueQueue ()
    let executedFlows = HashSet ()
    let executedVertices = HashSet ()
    { new ISensitiveLowUIRDataFlowSubState<StackPointerDomain.Lattice, 'ExeCtx>
          with
        member _.FlowQueue = flowQueue
        member _.DefSiteQueue = defSiteQueue
        member _.ExecutedFlows = executedFlows
        member _.ExecutedVertices = executedVertices
        member _.Bottom = StackPointerDomain.Undef
        member _.GetAbsValue vp = spGetAbsValue vp
        member _.SetAbsValue vp absVal = spAbsValues[vp] <- absVal
        member _.Join a b = StackPointerDomain.join a b
        member _.Subsume a b = StackPointerDomain.subsume a b
        member _.EvalExpr myPp expr = spEvaluateExpr myPp expr }

  let resetSubState (subState: ISensitiveLowUIRDataFlowSubState<_, _>) =
    subState.FlowQueue.Clear ()
    subState.DefSiteQueue.Clear ()
    subState.ExecutedFlows.Clear ()
    subState.ExecutedVertices.Clear ()

  let reset () =
    stmtInfoCache.Clear ()
    ssaStmtCache.Clear ()
    perPointSSAStmtCache.Clear ()
    domainAbsValues.Clear ()
    spAbsValues.Clear ()
    perVertexIncomingDefs.Clear ()
    perVertexOutgoingDefs.Clear ()
    defUseMap.Clear ()
    useDefMap.Clear ()
    stmtOfBBLs.Clear ()
    edgesForProcessing.Clear ()
    defSvpUidMapper.Clear ()
    useSvpUidMapper.Clear ()
    uidToDefSvp.Clear ()
    uidToUseSvp.Clear ()
    uidToSSAVar.Clear ()
    ssaVarToUid.Clear ()
    perVertexPossibleExeCtxs.Clear ()
    perVertexStackPointerInfos.Clear ()
    freshSSAVarId <- 1
    userContext <- new 'UsrCtx ()
    resetSubState spSubState
    resetSubState domainSubState

  member _.UserContext with get () = userContext

  member _.DefToUid (tvp: SensitiveVarPoint<_>) = defSvpToUid tvp

  member _.UidToDef (id: Uid) = uidToDefSvp[id]

  member _.UseToUid (svp: SensitiveVarPoint<_>) = useSvpToUid svp

  member _.UidToUse (id: Uid) = uidToUseSvp[id]

  member _.SSAVarToUid (var: SSA.Variable) =
    assert ssaVarToUid.ContainsKey var
    ssaVarToUid[var]

  member _.UidToSSAVar (id: Uid) =
    // assert idToSSAVarMapping.ContainsKey id
    // idToSSAVarMapping[id]
    defIdToSSAVar id

  member _.PerVertexPossibleTags with get () = perVertexPossibleExeCtxs

  member _.PerVertexStackPointerInfos with get () = perVertexStackPointerInfos

  /// Mapping from a CFG vertex to its incoming definitions.
  member _.PerVertexIncomingDefs with get () = perVertexIncomingDefs

  /// Mapping from a CFG vertex to its outgoing definitions.
  member _.PerVertexOutgoingDefs with get () = perVertexOutgoingDefs

  /// Mapping from a variable def to its uses.
  member _.DefUseMap with get () = defUseMap

  /// Mapping from a variable use to its definition.
  member _.UseDefMap with get () = useDefMap

  /// Mapping from a program point to `StmtOfBBL`, which is a pair of a Low-UIR
  /// statement and its corresponding vertex that contains the statement.
  member _.StmtOfBBLs with get () = stmtOfBBLs

  /// Sub-state for the stack-pointer domain.
  member _.StackPointerSubState with get () = spSubState

  /// Sub-state for the user's domain.
  member _.DomainSubState with get () = domainSubState

  /// Currently pending vertices for processing.
  member _.PendingEdges with get (): IEnumerable<_> = edgesForProcessing

  /// The given binary handle.
  member _.BinHandle with get () = hdl

  /// Mark the given vertex as pending, which means that the vertex needs to be
  /// processed.
  member _.MarkEdgeAsPending s d = edgesForProcessing.Add (s, d) |> ignore

  /// Mark the given vertex as removal, which means that the vertex needs to be
  /// removed.
  member _.MarkVertexAsRemoval v = verticesForRemoval.Enqueue v |> ignore

  /// Check if the given vertex is pending for processing.
  member _.IsEdgePending src dst = edgesForProcessing.Contains (src, dst)

  /// Clear the pending vertices.
  member _.ClearPendingEdges () = edgesForProcessing.Clear ()

  /// Dequeue the vertex for removal. When there is no vertex to remove, it
  /// returns `false`.
  member _.DequeueVertexForRemoval () = verticesForRemoval.TryDequeue ()

  /// Return the array of StmtInfos of the given vertex.
  member _.GetStmtInfos v = getStatements v

  member _.GetSSAStmts (v: IVertex<LowUIRBasicBlock>) (tag: 'ExeCtx) =
    let vWithTag = v, tag
    match ssaStmtCache.TryGetValue vWithTag with
    | true, stmts -> stmts
    | false, _ ->
      let stmts = computeSSAStmts v tag
      ssaStmtCache[vWithTag] <- stmts
      stmts

  /// Remove the cached SSA statements for the given vertex and tag.
  member _.InvalidateSSAStmts (v: IVertex<LowUIRBasicBlock>) (exeCtx: 'ExeCtx) =
    let vWithExeCtx = v, exeCtx
    ssaStmtCache.Remove vWithExeCtx |> ignore
    for _stmt, pp in getStatements v do
      let tpp = { ProgramPoint = pp; ExecutionContext = exeCtx }
      perPointSSAStmtCache.Remove tpp |> ignore

  member _.TryFindSSADefStmtFromSSAVar var =
    let id = ssaVarToUid[var]
    let svp = uidToDefSvp[id]
    let spp = svp.SensitiveProgramPoint
    let pp = spp.ProgramPoint
    if ProgramPoint.IsFake pp then None
    else
      let tag = spp.ExecutionContext
      Some <| getSSAStmt pp tag

  member this.FindSSADefStmtFromSSAVar var =
    this.TryFindSSADefStmtFromSSAVar var
    |> Option.get

  /// Reset this state.
  member _.Reset () = reset ()

  /// Translate the given stack pointer address to a local frame offset.
  static member inline ToFrameOffset stackAddr =
    int (stackAddr - Constants.InitialStackPointer)

  interface IDataFlowState<SensitiveVarPoint<'ExeCtx>, 'L> with
    member _.GetAbsValue absLoc = domainGetAbsValue absLoc

and ISensitiveLowUIRDataFlowSubState<'L, 'ExeCtx
                                when 'L: equality
                                 and 'ExeCtx: equality
                                 and 'ExeCtx: comparison> =
  inherit IDataFlowState<SensitiveVarPoint<'ExeCtx>, 'L>
  inherit ILatticeOperatable<'L>

  /// The edge queue for calculating the data flow.
  abstract FlowQueue:
    UniqueQueue<IVertex<LowUIRBasicBlock> * 'ExeCtx * IVertex<LowUIRBasicBlock>>

  /// The definition site queue for calculating the data flow.
  abstract DefSiteQueue: UniqueQueue<SensitiveProgramPoint<'ExeCtx>>

  /// Executed edges during the data flow calculation.
  abstract ExecutedFlows:
    HashSet<IVertex<LowUIRBasicBlock> * 'ExeCtx * IVertex<LowUIRBasicBlock>>

  /// Executed vertices during the data flow calculation.
  abstract ExecutedVertices: HashSet<IVertex<LowUIRBasicBlock> * 'ExeCtx>

  /// Get the abstract value at the given location.
  abstract SetAbsValue: vp: SensitiveVarPoint<'ExeCtx> -> 'L -> unit

  abstract EvalExpr:
       SensitiveProgramPoint<'ExeCtx>
    -> Expr
    -> 'L

/// The main interface for a sensitive data-flow analysis.
and ISensitiveLowUIRDataFlowAnalysis<'L, 'ExeCtx, 'UsrCtx
                                when 'L: equality
                                 and 'ExeCtx: equality
                                 and 'ExeCtx: comparison
                                 and 'UsrCtx: (new: unit -> 'UsrCtx)> =
  inherit ISensitiveDataFlowAnalysis<'L,
                                     SensitiveLowUIRDataFlowState<'L, 'ExeCtx,
                                                                  'UsrCtx>,
                                     'ExeCtx, LowUIRBasicBlock,
                                     'UsrCtx>
  inherit IStateInitialization<SensitiveVarPoint<'ExeCtx>,'L,
                               SensitiveLowUIRDataFlowState<'L, 'ExeCtx,
                                                            'UsrCtx>>
  inherit ILatticeOperatable<'L>
  inherit ILowUIRExprEvaluatable<'L,
                                 SensitiveLowUIRDataFlowState<'L, 'ExeCtx,
                                                              'UsrCtx>,
                                 SensitiveVarPoint<'ExeCtx>,
                                 SensitiveProgramPoint<'ExeCtx>>
  inherit IVertexAnalysis<SensitiveVarPoint<'ExeCtx>, 'L,
                          SensitiveLowUIRDataFlowState<'L, 'ExeCtx, 'UsrCtx>,
                          LowUIRBasicBlock>
  inherit IVertexRemoval<SensitiveVarPoint<'ExeCtx>, 'L,
                         SensitiveLowUIRDataFlowState<'L, 'ExeCtx, 'UsrCtx>,
                         LowUIRBasicBlock>

and ISensitiveDataFlowAnalysis<'L, 'State, 'ExeCtx, 'V, 'UsrCtx
                          when 'ExeCtx: equality
                           and 'ExeCtx: comparison
                           and 'V: equality
                           and 'UsrCtx: (new: unit -> 'UsrCtx)> =
  /// A default execution context that a root node in a CFG can have.
  abstract DefaultExecutionContext: 'ExeCtx

  /// Compute a tag that the successor can have from the current context. This
  /// returns None if the edge should be pruned (e.g. path-sensitive analysis).
  abstract TryComputeExecutionContext:
       'State
    -> IVertex<'V>
    -> exeCtx: 'ExeCtx
    -> successor: IVertex<'V>
    -> CFGEdgeKind
    -> 'ExeCtx option

and IStateInitialization<'AbsLoc, 'AbsVal, 'State
                    when 'AbsLoc: equality
                     and 'State :> IDataFlowState<'AbsLoc, 'AbsVal>> =
  /// A callback for initializing the state.
  abstract OnStateInitialized:
       'State
    -> 'State

and ILatticeOperatable<'L when 'L: equality> =
  /// Initial abstract value representing the bottom of the lattice. Our
  /// analysis starts with this value until it reaches a fixed point.
  abstract Bottom: 'L

  /// Join operator.
  abstract Join: 'L -> 'L -> 'L

  /// Subsume operator, which checks if the first lattice subsumes the second.
  /// This is to know if the analysis should stop or not.
  abstract Subsume: 'L -> 'L -> bool

and ILowUIRExprEvaluatable<'L, 'State, 'AbsLoc, 'PPoint
                      when 'L: equality
                       and 'PPoint: equality
                       and 'AbsLoc: equality
                       and 'State :> IDataFlowState<'AbsLoc, 'L>> =
  /// Evaluate the given expression based on the current abstract state.
  abstract EvalExpr:
       'State
    -> 'PPoint
    -> Expr
    -> 'L

and IVertexAnalysis<'AbsLoc, 'AbsVal, 'State, 'V
               when 'State :> IDataFlowState<'AbsLoc, 'AbsVal>
                and 'AbsLoc: equality
                and 'V: equality> =
  /// Called when a vertex is newly analyzed.
  abstract OnVertexNewlyAnalyzed:
       'State
    -> IVertex<'V>
    -> unit

and IVertexRemoval<'AbsLoc, 'AbsVal, 'State, 'V
              when 'State :> IDataFlowState<'AbsLoc, 'AbsVal>
               and 'AbsLoc: equality
               and 'V: equality> =
  /// Called when a vertex is removed.
  abstract OnRemoveVertex:
       'State
    -> IVertex<'V>
    -> unit

and ReachingDefs = Map<VarKind, Set<Uid>>

and Uid = int

and SensitiveVarPoint<'Sensitivity when 'Sensitivity: equality
                                    and 'Sensitivity: comparison> = {
  SensitiveProgramPoint: SensitiveProgramPoint<'Sensitivity>
  VarKind: VarKind
}

and SensitiveProgramPoint<'Sensitivity when 'Sensitivity: equality
                                        and 'Sensitivity: comparison> = {
  ProgramPoint: ProgramPoint
  ExecutionContext: 'Sensitivity
}
