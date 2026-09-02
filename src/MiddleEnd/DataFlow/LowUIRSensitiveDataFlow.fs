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

/// Provides types and functions for LowUIR-based sensitive data-flow analysis.
module B2R2.MiddleEnd.DataFlow.LowUIRSensitiveDataFlow

open System.Collections.Generic
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.Collections
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.BinGraph

/// Represents a state used in LowUIR-based sensitive dataflow analysis.
type State<'L, 'ExeCtx
  when 'L: equality
  and 'ExeCtx: equality
  and 'ExeCtx: comparison>
  public(hdl,
         lattice: ILattice<'L>,
         scheme: IScheme<'ExeCtx>,
         evaluator: IExprEvaluatable<SensitiveProgramPoint<'ExeCtx>, 'L>) =

  let mutable freshSSAVarId = 1

  let ssaVarToDefSvp = Dictionary<SSA.Variable, SensitiveVarPoint<'ExeCtx>>()

  let defSvpToSSAVar = Dictionary<SensitiveVarPoint<'ExeCtx>, SSA.Variable>()

  let perVertexPossibleExeCtxs =
    Dictionary<IVertex<LowUIRBasicBlock>, HashSet<'ExeCtx>>()

  let ssaStmtCache =
    Dictionary<IVertex<LowUIRBasicBlock> * 'ExeCtx, SSA.Stmt[]>()

  let perPointSSAStmtCache =
    Dictionary<SensitiveProgramPoint<'ExeCtx>, SSA.Stmt>()

  /// Holds the initial stack pointer value in the stack pointer domain.
  let spInitial = LowUIRStackPointer.initialValue hdl

  let perVertexStackPointerInfos =
    Dictionary<IVertex<LowUIRBasicBlock> * 'ExeCtx,
               StackPointerDomain.Lattice * StackPointerDomain.Lattice>()

  /// Caches the statements of every CFG vertex, along with their program
  /// points.
  let stmtCache = LowUIRStmtCache()

  /// Maps a SensitiveVarPoint to its abstract value in the user's domain.
  let domainAbsValues = Dictionary<SensitiveVarPoint<'ExeCtx>, 'L>()

  /// Maps a SensitiveVarPoint to its abstract value in the stack-pointer
  /// domain.
  let spAbsValues =
    Dictionary<SensitiveVarPoint<'ExeCtx>, StackPointerDomain.Lattice>()

  let perVertexIncomingDefs =
    Dictionary<IVertex<LowUIRBasicBlock> * 'ExeCtx,
               Map<VarKind, Set<SensitiveVarPoint<'ExeCtx>>>>()

  let perVertexOutgoingDefs =
    Dictionary<IVertex<LowUIRBasicBlock> * 'ExeCtx,
               Map<VarKind, Set<SensitiveVarPoint<'ExeCtx>>>>()

  let defUseMap = Dictionary<SensitiveVarPoint<'ExeCtx>,
                             Set<SensitiveVarPoint<'ExeCtx>>>()

  let useDefMap = Dictionary<SensitiveVarPoint<'ExeCtx>,
                             Set<SensitiveVarPoint<'ExeCtx>>>()

  let edgesForProcessing =
    HashSet<IVertex<LowUIRBasicBlock> | null * IVertex<LowUIRBasicBlock>>()

  /// Holds the vertices that need to be removed.
  let verticesForRemoval = HashSet<IVertex<LowUIRBasicBlock>>()

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

  let spEvaluateVar varKind spp =
    let svp = { SensitiveProgramPoint = spp; VarKind = varKind }
    match useDefMap.TryGetValue svp with
    | false, _ ->
      spGetInitialAbsValue varKind
    | true, defs ->
      defs
      |> Seq.fold (fun acc defSvp ->
        if defSvp.SensitiveProgramPoint.ProgramPoint.IsFake then
          spGetInitialAbsValue varKind
        else
          let defAbsValue = spGetAbsValue defSvp
          StackPointerDomain.join acc defAbsValue) StackPointerDomain.Undef

  let spEvaluateExpr spp e = LowUIRStackPointer.evalExpr spEvaluateVar spp e

  let getStatements v = stmtCache.GetStmtInfos v

  let tryGetReachingDefIdsFromUseId id =
    match useDefMap.TryGetValue id with
    | true, rds -> Some rds
    | false, _ -> None

  let generateFreshSSAVarId () =
    let id = freshSSAVarId
    freshSSAVarId <- freshSSAVarId + 1
    id

  let generateSSAVar defSvp =
    let svp = defSvp
    let spp = svp.SensitiveProgramPoint
    let ssaVarKind =
      match svp.VarKind with
      | Regular rid ->
        let rt = hdl.RegisterFactory.GetRegType rid
        let rname = hdl.RegisterFactory.GetRegisterName rid
        SSA.RegVar(rt, rid, rname)
      | StackLocal offset ->
        let rt = 0<rt>
        SSA.StackVar(rt, offset)
      | Temporary n ->
        let rt = 0<rt>
        SSA.TempVar(rt, n)
      | _ ->
        Terminator.futureFeature ()
    let ssaVarId =
      if spp.ProgramPoint.IsFake then 0 (* Unreachable variable. *)
      else generateFreshSSAVarId ()
    { SSA.Kind = ssaVarKind; SSA.Identifier = ssaVarId }

  /// Returns the SSA variable corresponding to the given definition sensitive
  /// variable point. If the variable does not exist, it creates a new SSA
  /// variable and returns it.
  let getSSAVarFromDefSvp defSvp =
    match defSvpToSSAVar.TryGetValue defSvp with
    | true, ssaVar ->
      ssaVar
    | false, _ ->
      let var = generateSSAVar defSvp
      defSvpToSSAVar[defSvp] <- var
      ssaVarToDefSvp[var] <- defSvp
      var

  let getDefSvpFromSSAVar var =
    assert ssaVarToDefSvp.ContainsKey var
    ssaVarToDefSvp[var]

  /// Converts an use to its reaching definitions. If the use has no definitions
  /// (e.g. parameter of a function), it creates a fake definition and returns
  /// it.
  let convertUseToReachingDefSSAExpr id exeCtx varKind =
    tryGetReachingDefIdsFromUseId id
    |> function
      | Some defs ->
        defs
        |> Set.toList
        |> List.map (getSSAVarFromDefSvp >> SSA.Var)
        |> SSA.ExprList
      | None -> (* Reading a value coming out of a function. *)
        let fakePp = ProgramPoint.Fake
        let fakeSpp = { ProgramPoint = fakePp; ExecutionContext = exeCtx }
        let fakeSvp = { SensitiveProgramPoint = fakeSpp; VarKind = varKind }
        let fakeSSAVar = getSSAVarFromDefSvp fakeSvp
        SSA.Var fakeSSAVar

  let rec computeSSAExpr pp exeCtx = function
    | Var _ | TempVar _ as e -> (* Track its use-def chain. *)
      let varKind = VarKind.ofIRExpr e
      let spp = { ProgramPoint = pp; ExecutionContext = exeCtx }
      let svp = { SensitiveProgramPoint = spp; VarKind = varKind }
      convertUseToReachingDefSSAExpr svp exeCtx varKind
    | ExprList(l, _) ->
      List.map (computeSSAExpr pp exeCtx) l |> SSA.ExprList
    | UnOp(op, e, _) ->
      let sexpr = computeSSAExpr pp exeCtx e
      let rt = Expr.typeOf e
      SSA.UnOp(op, rt, sexpr)
    | BinOp(op, rt, e1, e2, _) ->
      let sexpr1 = computeSSAExpr pp exeCtx e1
      let sexpr2 = computeSSAExpr pp exeCtx e2
      SSA.BinOp(op, rt, sexpr1, sexpr2)
    | RelOp(op, e1, e2, _) ->
      let sexpr1 = computeSSAExpr pp exeCtx e1
      let sexpr2 = computeSSAExpr pp exeCtx e2
      let rt = Expr.typeOf e1
      SSA.RelOp(op, rt, sexpr1, sexpr2)
    | Extract(e, _, pos, _) ->
      let sexpr = computeSSAExpr pp exeCtx e
      let rt = Expr.typeOf e
      SSA.Extract(sexpr, rt, pos)
    | Cast(op, _, e, _) ->
      let sexpr = computeSSAExpr pp exeCtx e
      let rt = Expr.typeOf e
      SSA.Cast(op, rt, sexpr)
    | Ite(e1, e2, e3, _) ->
      let sexpr1 = computeSSAExpr pp exeCtx e1
      let sexpr2 = computeSSAExpr pp exeCtx e2
      let sexpr3 = computeSSAExpr pp exeCtx e3
      let rt = Expr.typeOf e2
      SSA.Ite(sexpr1, rt, sexpr2, sexpr3)
    | Load(_, rt, e, _) ->
      let spp = { ProgramPoint = pp; ExecutionContext = exeCtx }
      match spEvaluateExpr spp e with
      | StackPointerDomain.ConstSP bv ->
        let varKind =
          bv.ToUInt64() |> LowUIRStackPointer.toFrameOffset |> StackLocal
        let useSvp = { SensitiveProgramPoint = spp; VarKind = varKind }
        convertUseToReachingDefSSAExpr useSvp exeCtx varKind
      | _ ->
        let e = computeSSAExpr pp exeCtx e
        let fakeMemoryVar = { SSA.Kind = SSA.MemVar; SSA.Identifier = -1 }
        SSA.Load(fakeMemoryVar, rt, e)
    | PCVar(rt, _rname, _) ->
      let fakeAddr = 0xdeadbeef1UL
      let bv = BitVector(fakeAddr, rt)
      SSA.Num bv
    | Num(bv, _) ->
      SSA.Num bv
    | FuncName(name, _) ->
      SSA.FuncName name
    | Undefined(rt, name, _) ->
      SSA.Undefined(rt, name)
    | JmpDest(_, _) ->
      Terminator.impossible ()

  /// Computes the pseudo-SSA statement for the given statement at the given
  /// program point and execution context. Note that this function actually does
  /// not compute the exact SSA statement (e.g. it does not compute phi nodes
  /// and does not introduce fresh memory variables).
  let computeSSAStmt stmt pp exeCtx =
    match stmt with
    | Put(dstVar, e, _) ->
      let expr = computeSSAExpr pp exeCtx e
      let spp = { ProgramPoint = pp; ExecutionContext = exeCtx }
      let varKind = VarKind.ofIRExpr dstVar
      let svp = { SensitiveProgramPoint = spp; VarKind = varKind }
      let var = getSSAVarFromDefSvp svp
      SSA.Def(var, expr)
    | Store(_, dstExpr, srcExpr, _) ->
      let spp = { ProgramPoint = pp; ExecutionContext = exeCtx }
      match spEvaluateExpr spp dstExpr with
      | StackPointerDomain.ConstSP bv ->
        let offset = bv.ToUInt64() |> LowUIRStackPointer.toFrameOffset
        let varKind = StackLocal offset
        let svp = { SensitiveProgramPoint = spp; VarKind = varKind }
        let var = getSSAVarFromDefSvp svp
        let srcExpr = computeSSAExpr pp exeCtx srcExpr
        SSA.Def(var, srcExpr)
      | _ ->
        let rt = Expr.typeOf srcExpr
        let dstExpr = computeSSAExpr pp exeCtx dstExpr
        let srcExpr = computeSSAExpr pp exeCtx srcExpr
        let fakeInMemoryVar = { SSA.Kind = SSA.MemVar; SSA.Identifier = -1 }
        let fakeOutMemoryVar = { SSA.Kind = SSA.MemVar; SSA.Identifier = -1 }
        let storeExpr = SSA.Store(fakeInMemoryVar, rt, dstExpr, srcExpr)
        SSA.Def(fakeOutMemoryVar, storeExpr)
    | InterJmp(targetExpr, _, _) ->
      let targetExpr = computeSSAExpr pp exeCtx targetExpr
      let jmpType = SSA.InterJmp targetExpr
      SSA.Jmp jmpType
    | InterCJmp(condExpr, tTargetExpr, fTargetExpr, _) ->
      let condExpr = computeSSAExpr pp exeCtx condExpr
      let tTargetExpr = computeSSAExpr pp exeCtx tTargetExpr
      let fTargetExpr = computeSSAExpr pp exeCtx fTargetExpr
      let jmpType = SSA.InterCJmp(condExpr, tTargetExpr, fTargetExpr)
      SSA.Jmp jmpType
    | SideEffect(se, _) ->
      SSA.SideEffect se
    | ExternalCall(extCallExpr, _) ->
      let extCallSExpr = computeSSAExpr pp exeCtx extCallExpr
      let inVars = [] (* We just fill in empty variables for now. *)
      let outVars = []
      SSA.ExternalCall(extCallSExpr, inVars, outVars)
    | _ ->
      Terminator.impossible ()

  let getSSAStmt pp exeCtx =
    let spp = { ProgramPoint = pp; ExecutionContext = exeCtx }
    match perPointSSAStmtCache.TryGetValue spp with
    | true, sstmts ->
      sstmts
    | false, _ ->
      assert (not pp.IsFake)
      assert (stmtCache.StmtOfBBLs.ContainsKey pp)
      let stmt, _ = stmtCache.StmtOfBBLs[pp]
      let sstmt = computeSSAStmt stmt pp exeCtx
      perPointSSAStmtCache[spp] <- sstmt
      sstmt

  let isNoOpStmt = function
    | ISMark _ | IEMark _ | LMark _ -> true
    | _ -> false

  /// Translates the statements of the given vertex with a exeCtx into a
  /// sequence of sensitive statements.
  let computeSSAStmts v exeCtx =
    getStatements v
    |> Array.filter (fun (stmt, _pp) -> (not << isNoOpStmt) stmt)
    |> Array.map (fun (_stmt, pp) -> getSSAStmt pp exeCtx)

  let invalidateSSAStmts (v: IVertex<LowUIRBasicBlock>) (exeCtx: 'ExeCtx) =
    let vWithExeCtx = v, exeCtx
    ssaStmtCache.Remove vWithExeCtx |> ignore
    for _stmt, pp in stmtCache.GetStmtInfos v do
      let spp = { ProgramPoint = pp; ExecutionContext = exeCtx }
      perPointSSAStmtCache.Remove spp |> ignore

  let domainSubState =
    let flowQueue = UniqueQueue()
    let defSiteQueue = UniqueQueue()
    let executedFlows = HashSet()
    let executedVertices = HashSet()
    { new ISubState<'L, 'ExeCtx> with
        member _.FlowQueue = flowQueue
        member _.DefSiteQueue = defSiteQueue
        member _.ExecutedFlows = executedFlows
        member _.ExecutedVertices = executedVertices
        member _.Bottom = lattice.Bottom
        member _.GetAbsValue vp = domainGetAbsValue vp
        member _.SetAbsValue(vp, absVal) = domainAbsValues[vp] <- absVal
        member _.Join(a, b) = lattice.Join(a, b)
        member _.Subsume(a, b) = lattice.Subsume(a, b)
        member _.EvalExpr(pp, expr) = evaluator.EvalExpr(pp, expr) }

  let spSubState =
    let flowQueue = UniqueQueue()
    let defSiteQueue = UniqueQueue()
    let executedFlows = HashSet()
    let executedVertices = HashSet()
    { new ISubState<StackPointerDomain.Lattice, 'ExeCtx> with
        member _.FlowQueue = flowQueue
        member _.DefSiteQueue = defSiteQueue
        member _.ExecutedFlows = executedFlows
        member _.ExecutedVertices = executedVertices
        member _.Bottom = StackPointerDomain.Undef
        member _.GetAbsValue vp = spGetAbsValue vp
        member _.SetAbsValue(vp, absVal) = spAbsValues[vp] <- absVal
        member _.Join(a, b) = StackPointerDomain.join a b
        member _.Subsume(a, b) = StackPointerDomain.subsume a b
        member _.EvalExpr(spp, expr) = spEvaluateExpr spp expr }

  let resetSubState (subState: ISubState<_, _>) =
    subState.FlowQueue.Clear()
    subState.DefSiteQueue.Clear()
    subState.ExecutedFlows.Clear()
    subState.ExecutedVertices.Clear()

  let reset () =
    stmtCache.Clear()
    ssaStmtCache.Clear()
    perPointSSAStmtCache.Clear()
    domainAbsValues.Clear()
    spAbsValues.Clear()
    perVertexIncomingDefs.Clear()
    perVertexOutgoingDefs.Clear()
    defUseMap.Clear()
    useDefMap.Clear()
    edgesForProcessing.Clear()
    verticesForRemoval.Clear()
    defSvpToSSAVar.Clear()
    ssaVarToDefSvp.Clear()
    perVertexPossibleExeCtxs.Clear()
    perVertexStackPointerInfos.Clear()
    freshSSAVarId <- 1
    resetSubState spSubState
    resetSubState domainSubState

  /// Returns the scheme used for this data flow analysis.
  member _.Scheme with get() = scheme

  /// Maps a CFG vertex to the execution contexts it may run under.
  member _.PerVertexPossibleExeCtxs
    with get() = perVertexPossibleExeCtxs :> IReadOnlyDictionary<_, _>

  member internal _.MutablePerVertexPossibleExeCtxs
    with get() = perVertexPossibleExeCtxs

  /// Maps a CFG vertex and an execution context to its incoming and outgoing
  /// stack pointer values.
  member _.PerVertexStackPointerInfos
    with get() = perVertexStackPointerInfos :> IReadOnlyDictionary<_, _>

  member internal _.MutablePerVertexStackPointerInfos
    with get() = perVertexStackPointerInfos

  /// Maps a CFG vertex to its incoming definitions.
  member _.PerVertexIncomingDefs
    with get() = perVertexIncomingDefs :> IReadOnlyDictionary<_, _>

  member internal _.MutablePerVertexIncomingDefs
    with get() = perVertexIncomingDefs

  /// Maps a CFG vertex to its outgoing definitions.
  member _.PerVertexOutgoingDefs
    with get() = perVertexOutgoingDefs :> IReadOnlyDictionary<_, _>

  member internal _.MutablePerVertexOutgoingDefs
    with get() = perVertexOutgoingDefs

  /// Maps a variable def to its uses.
  member _.DefUseMap with get() = defUseMap :> IReadOnlyDictionary<_, _>

  member internal _.MutableDefUseMap with get() = defUseMap

  /// Maps a variable use to its definition.
  member _.UseDefMap with get() = useDefMap :> IReadOnlyDictionary<_, _>

  member internal _.MutableUseDefMap with get() = useDefMap

  /// Maps a program point to `StmtOfBBL`, which is a pair of a Low-UIR
  /// statement and its corresponding vertex that contains the statement.
  member _.StmtOfBBLs with get() = stmtCache.StmtOfBBLs

  /// Returns the sub-state for the stack-pointer domain.
  member internal _.StackPointerSubState with get() = spSubState

  /// Returns the sub-state for the user's domain.
  member _.DomainSubState with get() = domainSubState

  /// Returns the edges that are currently pending for processing.
  member _.PendingEdges with get(): IEnumerable<_> = edgesForProcessing

  /// Returns a sequence of vertices that are pending for removal.
  member _.VerticesForRemoval with get() = verticesForRemoval: IEnumerable<_>

  /// Returns the binary handle given to this state.
  member _.BinHandle with get() = hdl

  /// Marks the given edge as pending, which means that the edge needs to be
  /// processed.
  member _.MarkEdgeAsPending(s, d) = edgesForProcessing.Add(s, d) |> ignore

  /// Marks the given vertex for removal, so that the next run forgets what
  /// it knows of the vertex. It returns false when the vertex was already
  /// marked.
  member _.TryMarkVertexAsRemoval v = verticesForRemoval.Add v

  /// Checks if the given edge is pending for processing.
  member _.IsEdgePending(src, dst) = edgesForProcessing.Contains(src, dst)

  /// Clears the pending edges.
  member _.ClearPendingEdges() = edgesForProcessing.Clear()

  /// Clears the vertices to be removed.
  member _.ClearRemovalVertices() = verticesForRemoval.Clear()

  /// Returns the array of StmtInfos of the given vertex.
  member _.GetStmtInfos v = getStatements v

  /// Returns the SSA statements of the given vertex under the given execution
  /// context, computing them on the first request and caching them.
  member _.GetSSAStmts(v: IVertex<LowUIRBasicBlock>, exeCtx: 'ExeCtx) =
    let vWithCtx = v, exeCtx
    match ssaStmtCache.TryGetValue vWithCtx with
    | true, stmts ->
      stmts
    | false, _ ->
      let stmts = computeSSAStmts v exeCtx
      ssaStmtCache[vWithCtx] <- stmts
      stmts

  /// Invalidates the given vertex, which means that all the information
  /// associated with the vertex is removed from the state. The order of
  /// the removal is important, and it should be done in the current order.
  member _.InvalidateVertex(v: IVertex<LowUIRBasicBlock>) =
    scheme.OnRemoveVertex v
    match perVertexPossibleExeCtxs.TryGetValue v with
    | false, _ ->
      ()
    | true, exeCtxs ->
      for exeCtx in exeCtxs do
        let key = v, exeCtx
        perVertexIncomingDefs.Remove key |> ignore
        perVertexOutgoingDefs.Remove key |> ignore
        perVertexStackPointerInfos.Remove key |> ignore
        invalidateSSAStmts v exeCtx
      perVertexPossibleExeCtxs.Remove v |> ignore
    stmtCache.Remove v

  /// Returns the SSA statement that defines the given SSA variable. This
  /// returns None when the definition sits at a fake program point, which has
  /// no statement behind it.
  member _.TryFindSSADefStmtFromSSAVar var =
    let svp = getDefSvpFromSSAVar var
    let spp = svp.SensitiveProgramPoint
    let pp = spp.ProgramPoint
    if pp.IsFake then None else Some <| getSSAStmt pp spp.ExecutionContext

  /// Returns the SSA statement that defines the given SSA variable. This
  /// raises an exception when there is no such statement.
  member this.FindSSADefStmtFromSSAVar var =
    this.TryFindSSADefStmtFromSSAVar var
    |> Option.get

  /// Invalidates the cached SSA statements of the given vertex under the given
  /// execution context.
  member _.InvalidateSSAStmts(v, exeCtx) = invalidateSSAStmts v exeCtx

  /// Returns the sensitive variable point that defines the given SSA
  /// variable.
  member _.GetDefSvpFromSSAVar var = getDefSvpFromSSAVar var

  /// Returns the SSA variable standing for the given definition, minting
  /// one when the definition has none yet.
  member _.GetSSAVarFromDefSvp svp = getSSAVarFromDefSvp svp

  /// Returns the abstract value of the given expression at the given sensitive
  /// program point.
  member _.EvalExpr(pp, expr) = evaluator.EvalExpr(pp, expr)

  /// Resets this state.
  member _.Reset() = reset ()

  interface IAbsValProvider<SensitiveVarPoint<'ExeCtx>, 'L> with
    member _.GetAbsValue absLoc = domainGetAbsValue absLoc

/// Represents a sub-state for the context-sensitive data-flow analysis.
and ISubState<'L, 'ExeCtx
  when 'L: equality
  and 'ExeCtx: equality
  and 'ExeCtx: comparison> =
  inherit IAbsValProvider<SensitiveVarPoint<'ExeCtx>, 'L>
  inherit ILattice<'L>
  inherit IExprEvaluatable<SensitiveProgramPoint<'ExeCtx>, 'L>

  /// Returns the edge queue for calculating the data flow.
  abstract FlowQueue:
    UniqueQueue<IVertex<LowUIRBasicBlock> | null
              * 'ExeCtx
              * IVertex<LowUIRBasicBlock>>

  /// Returns the definition site queue for calculating the data flow.
  abstract DefSiteQueue: UniqueQueue<SensitiveProgramPoint<'ExeCtx>>

  /// Returns the edges executed during the data flow calculation.
  abstract ExecutedFlows:
    HashSet<IVertex<LowUIRBasicBlock> * 'ExeCtx * IVertex<LowUIRBasicBlock>>

  /// Returns the vertices executed during the data flow calculation.
  abstract ExecutedVertices: HashSet<IVertex<LowUIRBasicBlock> * 'ExeCtx>

  /// Sets the abstract value at the given location.
  abstract SetAbsValue: vp: SensitiveVarPoint<'ExeCtx> * 'L -> unit

/// Represents the main interface for a sensitive data-flow analysis.
and IScheme<'ExeCtx when 'ExeCtx: equality and 'ExeCtx: comparison> =
  /// Returns the default execution context that a root node in a CFG can
  /// have.
  abstract DefaultExecutionContext: 'ExeCtx

  /// Computes an execution context that the successor can have from the current
  /// context. This returns None if the edge should be pruned (e.g.
  /// path-sensitive analysis).
  abstract TryComputeExecutionContext:
       IVertex<LowUIRBasicBlock>
    * exeCtx: 'ExeCtx
    * successor: IVertex<LowUIRBasicBlock>
    * CFGEdgeKind
    -> 'ExeCtx option

  /// Runs when a vertex is newly analyzed.
  abstract OnVertexNewlyAnalyzed: IVertex<LowUIRBasicBlock> -> unit

  /// Runs when a vertex is removed.
  abstract OnRemoveVertex: IVertex<LowUIRBasicBlock> -> unit

/// Represents the reaching definitions of each variable in the sensitive
/// data-flow analysis.
and SensitiveReachingDefs<'ExeCtx
  when 'ExeCtx: equality
  and 'ExeCtx: comparison> =
  Map<VarKind, Set<SensitiveVarPoint<'ExeCtx>>>

/// Represents a program point in the sensitive data-flow analysis.
and SensitiveProgramPoint<'ExeCtx
  when 'ExeCtx: equality
  and 'ExeCtx: comparison> =
  { ProgramPoint: ProgramPoint
    ExecutionContext: 'ExeCtx }

/// Represents a variable point in the sensitive data-flow analysis.
and SensitiveVarPoint<'ExeCtx when 'ExeCtx: equality and 'ExeCtx: comparison> =
  { SensitiveProgramPoint: SensitiveProgramPoint<'ExeCtx>
    VarKind: VarKind }

[<AutoOpen>]
module internal AnalysisCore = begin

  /// Invalidates the dataflow chains of the vertices that are pending
  /// removal, since a vertex leaving the graph makes its chains invalid.
  let removeInvalidChains (state: State<_, _>) =
    for v in state.VerticesForRemoval do
      state.InvalidateVertex v
    state.ClearRemovalVertices()

  let getStackValue state pp e =
    match (state: ISubState<_, _>).EvalExpr(pp, e) with
    | StackPointerDomain.ConstSP bv -> Ok <| bv.ToUInt64()
    | _ -> Error ErrorCase.InvalidExprEvaluation

  /// Removes all the old chains of the given use.
  let removeOldChains (state: State<_, _>) useId =
    match state.UseDefMap.TryGetValue useId with
    | true, prevDefIds ->
      for prevDefId in prevDefIds do
        (* Erase the old def-use. *)
        let prevDefUses = state.MutableDefUseMap[prevDefId]
        state.MutableDefUseMap[prevDefId] <- Set.remove useId prevDefUses
        (* Erase the old use-def which will be overwritten by the new def. *)
      state.MutableUseDefMap.Remove useId |> ignore
    | _ ->
      ()

  /// Adds a new def-use chain.
  let updateDefUseChain (state: State<_, _>) useId defId =
    match state.MutableDefUseMap.TryGetValue defId with
    | false, _ -> state.MutableDefUseMap[defId] <- Set.singleton useId
    | true, uses -> state.MutableDefUseMap[defId] <- Set.add useId uses

  /// Overwrites the use-def chain. Unlike `updateDefUseChain`, this strongly
  /// updates the existing use-def chain, as we already know exactly which
  /// definitions are used by the use at the moment.
  let updateUseDefChain (state: State<_, _>) id defs =
    state.MutableUseDefMap[id] <- defs

  let makeFakeDefSvp exeCtx vk =
    let fakePp = ProgramPoint.Fake
    let fakeSpp = { ProgramPoint = fakePp; ExecutionContext = exeCtx }
    { SensitiveProgramPoint = fakeSpp; VarKind = vk }

  let updateChains (state: State<_, _>) vk defs spp =
    match Map.tryFind vk defs with
    | None -> (* Uses function arguments. *)
      let useSvp = { SensitiveProgramPoint = spp; VarKind = vk }
      let defSvp = makeFakeDefSvp spp.ExecutionContext vk
      updateDefUseChain state useSvp defSvp
      updateUseDefChain state useSvp (Set.singleton defSvp)
    | Some rds ->
      let useSvp = { SensitiveProgramPoint = spp; VarKind = vk }
      removeOldChains state useSvp
      for defSvp in rds do updateDefUseChain state useSvp defSvp
      updateUseDefChain state useSvp rds

  let updateWithExpr state defs (spp: SensitiveProgramPoint<_>) expr =
    let onVarRead vk = updateChains state vk defs spp
    let tryStackOffset e =
      match getStackValue state.StackPointerSubState spp e with
      | Ok loc -> Some(LowUIRStackPointer.toFrameOffset loc)
      | Error _ -> None
    VarKind.iterUses onVarRead tryStackOffset expr

  let getIncomingDefs (state: State<_, _>) v exeCtx =
    let k = v, exeCtx
    match state.PerVertexIncomingDefs.TryGetValue k with
    | false, _ -> Map.empty
    | true, defs -> defs

  let getOutgoingDefs (state: State<_, _>) v exeCtx =
    let k = v, exeCtx
    match state.PerVertexOutgoingDefs.TryGetValue k with
    | false, _ -> Map.empty
    | true, defs -> defs

  let getPossibleExeCtxs (state: State<_, _>) v =
    match state.PerVertexPossibleExeCtxs.TryGetValue v with
    | false, _ -> Seq.empty
    | true, s -> s

  let stackPointerToFrameOffset sp =
    match sp with
    | StackPointerDomain.ConstSP bv ->
      bv.ToUInt64() |> LowUIRStackPointer.toFrameOffset
    | _ ->
      Terminator.impossible ()

  /// Returns true if the given variable kind does not survive a join into a
  /// vertex whose incoming stack pointer sits at the given frame offset.
  let isPrunedVarKind dstInStackOff vk =
    match vk with
    | Temporary _ -> true
    | StackLocal offset when offset < dstInStackOff -> true
    | _ -> false

  /// Joins the two reaching definition maps. We filter out temporary variables
  /// here.
  /// TODO: check if it is propagated through intra-block edges like
  /// `LowUIRSparseDataFlow`.
  let joinDefs dstInSP (m1: SensitiveReachingDefs<_>)
                       (m2: SensitiveReachingDefs<_>) =
    let dstInStackOff = stackPointerToFrameOffset dstInSP
    m1 |> Map.fold (fun (changed, acc) vk defs ->
      if isPrunedVarKind dstInStackOff vk then
        changed, acc
      else
        match Map.tryFind vk m2 with
        | None ->
          true, Map.add vk defs acc
        | Some defs' ->
          let defs'' = Set.union defs defs'
          if defs'' = defs' then changed, acc
          else true, Map.add vk defs'' acc) (false, m2)

  let strongUpdateReachingDef rds vk svp =
    let set = Set.singleton svp
    Map.add vk set rds

  /// Strongly updates the stack pointer value for the given tagged variable.
  /// We assume that the stack pointer value is always a constant value in a
  /// single vertex with a single execution context (sensitivity).
  let updateStackPointer (state: State<_, _>) spp vk e =
    let subState = state.StackPointerSubState
    let spValue = subState.EvalExpr(spp, e)
    let svp = { SensitiveProgramPoint = spp; VarKind = vk }
    subState.SetAbsValue(svp, spValue)

  /// Executes the given vertex, which (1) computes its outgoing reaching
  /// definitions, (2) updates the def-use/use-def chains on the fly, and (3)
  /// updates every stack pointer value along the way.
  let execute state (v: IVertex<LowUIRBasicBlock>) exeCtx inDefs =
    let stmtInfos = (state: State<_, _>).GetStmtInfos v
    let mutable outDefs = inDefs
    for (stmt, pp) in stmtInfos do
      match stmt with
      | Put(dst, src, _) ->
        let varKind = VarKind.ofIRExpr dst
        let spp = { ProgramPoint = pp; ExecutionContext = exeCtx }
        let svp = { SensitiveProgramPoint = spp; VarKind = varKind }
        updateWithExpr state outDefs spp src
        updateStackPointer state spp varKind src
        outDefs <- strongUpdateReachingDef outDefs varKind svp
      | Store(_, addr, value, _) ->
        let spp = { ProgramPoint = pp; ExecutionContext = exeCtx }
        updateWithExpr state outDefs spp addr
        updateWithExpr state outDefs spp value
        match state.StackPointerSubState.EvalExpr(spp, addr) with
        | StackPointerDomain.ConstSP bv ->
          let loc = bv.ToUInt64()
          let offset = LowUIRStackPointer.toFrameOffset loc
          let varKind = StackLocal offset
          let spp = { ProgramPoint = pp; ExecutionContext = exeCtx }
          let svp = { SensitiveProgramPoint = spp; VarKind = varKind }
          // updateStackPointer state spp varKind value
          outDefs <- strongUpdateReachingDef outDefs varKind svp
        | _ ->
          ()
      | InterJmp(dstExpr, _, _) ->
        let spp = { ProgramPoint = pp; ExecutionContext = exeCtx }
        updateWithExpr state outDefs spp dstExpr
      | InterCJmp(condExpr, tExpr, fExpr, _) ->
        let spp = { ProgramPoint = pp; ExecutionContext = exeCtx }
        updateWithExpr state outDefs spp condExpr
        updateWithExpr state outDefs spp tExpr
        updateWithExpr state outDefs spp fExpr
      | ExternalCall(e, _) ->
        let spp = { ProgramPoint = pp; ExecutionContext = exeCtx }
        updateWithExpr state outDefs spp e
      | Jmp _ | CJmp _ ->
        Terminator.futureFeature ()
      | SideEffect _ ->
        ()
      | ISMark _ | IEMark _ | LMark _ ->
        ()
    outDefs

  let prepareQueue (state: State<_, _>) g =
    let queue = UniqueQueue()
    for s, d in state.PendingEdges do
      if not <| (g: IDiGraph<_, _>).Contains d then
        ()
      elif s = null then (* Root node has been created. *)
        let s = s, state.Scheme.DefaultExecutionContext
        let d = d
        queue.Enqueue(s, d)
      elif g.Contains s then
        for inSP in getPossibleExeCtxs state s do
          let s = s, inSP
          let d = d
          queue.Enqueue(s, d)
      else
        ()
    queue

  /// Introduces a fake definition for a variable that one side of a merge
  /// point defines and the other does not. Such a variable still flows through
  /// the side that never defines it, carrying whatever value it held on
  /// function entry. `updateChains` covers a variable absent from the map;
  /// this function covers the merge point.
  let introduceFakeDefsAtMergePoint exeCtx dstInStackOff m1 m2 =
    let introduceMissingFakeDefs other m =
      (m, Map.keys other)
      ||> Seq.fold (fun m vk ->
        if Map.containsKey vk m || isPrunedVarKind dstInStackOff vk then m
        else Map.add vk (Set.singleton (makeFakeDefSvp exeCtx vk)) m)
    introduceMissingFakeDefs m2 m1, introduceMissingFakeDefs m1 m2

  let tryJoinRDs (state: State<_, _>) src srcExeCtx dst dstExeCtx =
    let srcOutDefs = getOutgoingDefs state src srcExeCtx
    let dstInDefs = getIncomingDefs state dst dstExeCtx
    let dstInSP =
      if isNull src then
        let spRid = state.BinHandle.RegisterFactory.StackPointer.Value
        let spRegType = state.BinHandle.RegisterFactory.GetRegType spRid
        BitVector(Constants.InitialStackPointer, spRegType)
        |> StackPointerDomain.ConstSP
      else
        snd state.PerVertexStackPointerInfos[src, srcExeCtx]
    let srcOutDefs, dstInDefs =
      if state.PerVertexIncomingDefs.ContainsKey(dst, dstExeCtx) then
        let off = stackPointerToFrameOffset dstInSP
        introduceFakeDefsAtMergePoint dstExeCtx off srcOutDefs dstInDefs
      else
        srcOutDefs, dstInDefs
    match joinDefs dstInSP srcOutDefs dstInDefs with
    | true, dstInDefs' -> Some dstInDefs'
    (* This can happen when this was the first visit to the vertex. *)
    | false, _ when Map.isEmpty dstInDefs -> Some Map.empty
    | _ -> None

  let addPossibleExeCtx (state: State<_, _>) v exeCtx =
    let possibleExeCtxs = state.MutablePerVertexPossibleExeCtxs
    let hasSet = possibleExeCtxs.ContainsKey v
    if not hasSet then
      possibleExeCtxs[v] <- HashSet [ exeCtx ]
      state.Scheme.OnVertexNewlyAnalyzed v
    else
      possibleExeCtxs[v].Add exeCtx |> ignore

  let getInitialStackPointer (state: State<_, _>) =
    let spRid = state.BinHandle.RegisterFactory.StackPointer.Value
    let spRegType = state.BinHandle.RegisterFactory.GetRegType spRid
    BitVector(Constants.InitialStackPointer, spRegType)
    |> StackPointerDomain.ConstSP

  let getOutSP (state: State<_, _>) v exeCtx =
    if isNull v then getInitialStackPointer state
    else snd state.PerVertexStackPointerInfos[v, exeCtx]

  let evaluateRecentSP (state: State<_, _>) m =
    let spRid = state.BinHandle.RegisterFactory.StackPointer.Value
    let spRegType = state.BinHandle.RegisterFactory.GetRegType spRid
    let spVarKind = Regular spRid
    match Map.tryFind spVarKind m with
    (* There was no use of stack pointers: no-op only block. *)
    | None ->
      getInitialStackPointer state
    | Some defs ->
      let def = defs |> Seq.head
      let defPP = def.SensitiveProgramPoint.ProgramPoint
      if defPP.IsFake then getInitialStackPointer state
      else state.StackPointerSubState.GetAbsValue def

  let executeAndPropagateRDs (state: State<_, _>)
                             queue
                             g
                             src
                             dst
                             srcExeCtx
                             dstExeCtx
                             dstDefs =
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
    if isFirstVisit then addPossibleExeCtx state dst dstExeCtx else ()
    match maybeJoinedOutDefs with
    | None ->
      ()
    | Some dstOutDefs' ->
      let srcOutSP = getOutSP state src srcExeCtx
      let dstOutSP = evaluateRecentSP state dstOutDefs'
      let dstSPInfo = srcOutSP, dstOutSP
      state.MutablePerVertexStackPointerInfos[dstKey] <- dstSPInfo
      state.MutablePerVertexIncomingDefs[dstKey] <- dstDefs
      state.MutablePerVertexOutgoingDefs[dstKey] <- dstOutDefs'
      state.InvalidateSSAStmts(dst, dstExeCtx) (* Caches can be obsolete. *)
      for succ in (g: IDiGraph<_, _>).GetSuccs dst do
        (queue: UniqueQueue<_>).Enqueue((dst, dstExeCtx), succ)

  /// Computes the successor execution context and the reaching definitions for
  /// the given edge. If the edge is infeasible or the reaching definitions do
  /// not change, return None.
  let tryComputeSuccessorExeCtxAndDefs g (st: State<_, _>) src srcExeCtx dst =
    if isNull src then
      Some(st.Scheme.DefaultExecutionContext, Map.empty)
    else
      let edge = (g: IDiGraph<_, _>).FindEdge(src, dst)
      let kind = edge.Label
      match st.Scheme.TryComputeExecutionContext(src, srcExeCtx, dst, kind) with
      | None ->
        None (* Infeasible flow. *)
      | Some dstExeCtx ->
        tryJoinRDs st src srcExeCtx dst dstExeCtx
        |> Option.map (fun dstInDefs -> dstExeCtx, dstInDefs)

  let calculateChains g state =
    let q = prepareQueue state g
    while not q.IsEmpty do
      let (src, srcExeCtx), dst = q.Dequeue()
      tryComputeSuccessorExeCtxAndDefs g state src srcExeCtx dst
      |> Option.iter (fun (dstExeCtx, defs) ->
        executeAndPropagateRDs state q g src dst srcExeCtx dstExeCtx defs)

  let updateAbsValue subState defUseMap svp prev curr =
    if (subState: ISubState<_, _>).Subsume(prev, curr) then
      ()
    else
      subState.SetAbsValue(svp, subState.Join(prev, curr))
      match (defUseMap: IReadOnlyDictionary<_, _>).TryGetValue svp with
      | false, _ ->
        ()
      | true, uses ->
        for useSvp in uses do
          let useSpp = useSvp.SensitiveProgramPoint
          subState.DefSiteQueue.Enqueue useSpp

  let domainTransfer (state: State<_, _>) exeCtx (stmt, pp) =
    match stmt with
    | Put(dst, src, _) ->
      let varKind = VarKind.ofIRExpr dst
      let spp = { ProgramPoint = pp; ExecutionContext = exeCtx }
      let svp = { SensitiveProgramPoint = spp; VarKind = varKind }
      let subState = state.DomainSubState
      let prev = subState.GetAbsValue svp
      let curr = state.EvalExpr(spp, src)
      let defUseMap = state.DefUseMap
      updateAbsValue subState defUseMap svp prev curr
    | Store(_, addr, value, _) ->
      let spp = { ProgramPoint = pp; ExecutionContext = exeCtx }
      match state.StackPointerSubState.EvalExpr(spp, addr) with
      | StackPointerDomain.ConstSP bv ->
        let loc = bv.ToUInt64()
        let offset = LowUIRStackPointer.toFrameOffset loc
        let varKind = StackLocal offset
        let svp = { SensitiveProgramPoint = spp; VarKind = varKind }
        let subState = state.DomainSubState
        let prev = subState.GetAbsValue svp
        let curr = state.EvalExpr(spp, value)
        let defUseMap = state.DefUseMap
        updateAbsValue subState defUseMap svp prev curr
      | _ ->
        ()
    | _ ->
      ()

  let isExecuted (state: State<_, _>) (subState: ISubState<_, _>) spp =
    let pp = (spp: SensitiveProgramPoint<_>).ProgramPoint
    let exeCtx = spp.ExecutionContext
    match state.StmtOfBBLs.TryGetValue pp with
    | false, _ -> false
    | true, (_, v) -> subState.ExecutedVertices.Contains(v, exeCtx)

  let processDefSite (state: State<_, _>)
                     (subState: ISubState<_, _>)
                     fnTransfer =
    match subState.DefSiteQueue.TryDequeue() with
    | true, spp when isExecuted state subState spp ->
      let pp = spp.ProgramPoint
      let exeCtx = spp.ExecutionContext
      let stmt, _ = state.StmtOfBBLs[pp]
      fnTransfer state exeCtx (stmt, pp)
    | _ ->
      ()

  let transferFlow g
                   (state: State<_, _>)
                   (subState: ISubState<_, _>)
                   v
                   exeCtx
                   fnTransfer =
    let key = v, exeCtx
    subState.ExecutedVertices.Add key |> ignore
    for stmt in state.GetStmtInfos v do fnTransfer state exeCtx stmt done
    (g: IDiGraph<_, _>).GetSuccs v
    |> Array.map (fun succ -> v, exeCtx, succ)
    |> Array.iter subState.FlowQueue.Enqueue

  let tryGetSuccessorExeCtx g (state: State<_, _>) src srcExeCtx dst =
    if isNull src then
      Some state.Scheme.DefaultExecutionContext
    elif not <| (g: IDiGraph<_, _>).HasEdge(src, dst) then
      None
    else
      let edge = g.FindEdge(src, dst)
      let edgeKind = edge.Label
      state.Scheme.TryComputeExecutionContext(src, srcExeCtx, dst, edgeKind)

  let processFlow g state subState fnTransfer =
    let subState = subState :> ISubState<_, _>
    match subState.FlowQueue.TryDequeue() with
    | false, _ ->
      ()
    | true, (src, srcExeCtx, dst) ->
      (* A flow queued before the graph was rebuilt can name a vertex the
         graph no longer holds, and such a flow leads nowhere. *)
      if not <| subState.ExecutedFlows.Add(src, srcExeCtx, dst) then
        ()
      elif not <| (g: IDiGraph<_, _>).Contains dst then
        ()
      else
        match tryGetSuccessorExeCtx g state src srcExeCtx dst with
        | None ->
          () (* Prune infeasible flow. *)
        | Some dstExeCtx ->
          transferFlow g state subState dst dstExeCtx fnTransfer

  let registerPendingVertices state subState =
    let subState = subState :> ISubState<_, _>
    for s, d in (state: State<_, _>).PendingEdges do
      if isNull s then
        let exeCtx = state.Scheme.DefaultExecutionContext
        subState.FlowQueue.Enqueue(s, exeCtx, d)
      else
        for exeCtx in getPossibleExeCtxs state s do
          subState.FlowQueue.Enqueue(s, exeCtx, d)

  let propagateDomain g (state: State<_, _>) =
    let subState = state.DomainSubState
    registerPendingVertices state subState
    while not subState.FlowQueue.IsEmpty
          || not subState.DefSiteQueue.IsEmpty do
      processFlow g state subState domainTransfer
      processDefSite state subState domainTransfer

end (* End of AnalysisCore *)

/// Computes the data flow incrementally.
[<CompiledName "Compute">]
let compute g state =
  removeInvalidChains state
  calculateChains g state
  propagateDomain g state
  state.ClearPendingEdges()
  state
