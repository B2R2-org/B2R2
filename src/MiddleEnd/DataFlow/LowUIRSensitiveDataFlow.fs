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

/// Translate the given stack pointer address to a local frame offset.
let inline toFrameOffset stackAddr =
  int (stackAddr - Constants.InitialStackPointer)

/// Represents a state used in LowUIR-based sensitive dataflow analysis.
[<AllowNullLiteral>]
type State<'L, 'ExeCtx when 'L: equality
                        and 'ExeCtx: equality
                        and 'ExeCtx: comparison>
  public(hdl, lattice: ILattice<'L>, scheme: IScheme<'L, 'ExeCtx>) =

  let mutable evaluator: IExprEvaluatable<_, _> = null

  let mutable freshSSAVarId = 1

  let ssaVarToDefSvp = Dictionary<SSA.Variable, SensitiveVarPoint<'ExeCtx>>()

  let defSvpToSSAVar = Dictionary<SensitiveVarPoint<'ExeCtx>, SSA.Variable>()

  let perVertexPossibleExeCtxs =
    Dictionary<IVertex<LowUIRBasicBlock>, HashSet<'ExeCtx>>()

  let ssaStmtCache =
    Dictionary<IVertex<LowUIRBasicBlock> * 'ExeCtx, SSA.Stmt[]>()

  let perPointSSAStmtCache =
    Dictionary<SensitiveProgramPoint<'ExeCtx>, SSA.Stmt>()

  /// Initial stack pointer value in the stack pointer domain.
  let spInitial =
    match (hdl: BinHandle).RegisterFactory.StackPointer with
    | None -> None
    | Some rid ->
      let rt = hdl.RegisterFactory.GetRegType rid
      let varKind = Regular rid
      let bv = BitVector.OfUInt64(Constants.InitialStackPointer, rt)
      let c = StackPointerDomain.ConstSP bv
      Some(varKind, c)

  let perVertexStackPointerInfos =
    Dictionary<IVertex<LowUIRBasicBlock> * 'ExeCtx,
               StackPointerDomain.Lattice * StackPointerDomain.Lattice>()

  /// Mapping from a CFG vertex to its StmtInfo array.
  let stmtInfoCache = Dictionary<IVertex<LowUIRBasicBlock>, StmtInfo[]>()

  /// Mapping from a MyVarPoint to its abstract value in the user's domain.
  let domainAbsValues = Dictionary<SensitiveVarPoint<'ExeCtx>, 'L>()

  /// Mapping from a MyVarPoint to its abstract value in the stack-pointer
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

  let stmtOfBBLs = Dictionary<ProgramPoint, StmtOfBBL>()

  let edgesForProcessing =
    HashSet<IVertex<LowUIRBasicBlock> * IVertex<LowUIRBasicBlock>>()

  /// Queue of vertices that need to be removed.
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

  let spEvaluateVar varKind tpp =
    let tvp = { SensitiveProgramPoint = tpp; VarKind = varKind }
    match useDefMap.TryGetValue tvp with
    | false, _ -> spGetInitialAbsValue varKind
    | true, defs ->
      defs
      |> Seq.fold (fun acc defSvp ->
        let defAbsValue = spGetAbsValue defSvp
        StackPointerDomain.join acc defAbsValue) StackPointerDomain.Undef

  let rec spEvaluateExpr myPp (e: Expr) =
    match e with
    | Num(bv, _) -> StackPointerDomain.ConstSP bv
    | Var _ | TempVar _ -> spEvaluateVar (VarKind.ofIRExpr e) myPp
    | Load(_, _, addr, _) ->
      match spEvaluateExpr myPp addr with
      | StackPointerDomain.ConstSP bv ->
        let offset = BitVector.ToUInt64 bv |> toFrameOffset
        spEvaluateVar (StackLocal offset) myPp
      | c -> c
    | BinOp(binOpType, _, e1, e2, _) ->
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
          stmt, ProgramPoint(ins.Original.Address, startPos + i)))
    else (* abstract vertex *)
      let startPos = 1 (* we reserve 0 for phi definitions. *)
      let cs = Option.get pp.CallSite
      let addr = pp.Address
      v.VData.Internals.AbstractContent.Rundown
      |> Array.mapi (fun i s -> s, ProgramPoint(cs, addr, startPos + i))

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
        let rname = hdl.RegisterFactory.GetRegString rid
        SSA.RegVar(rt, rid, rname)
      | StackLocal offset ->
        let rt = 0<rt>
        SSA.StackVar(rt, offset)
      | Temporary n ->
        let rt = 0<rt>
        SSA.TempVar(rt, n)
      | _ -> Terminator.futureFeature ()
    let ssaVarId =
      if ProgramPoint.IsFake spp.ProgramPoint then 0 (* Unreachable variable. *)
      else generateFreshSSAVarId ()
    { SSA.Kind = ssaVarKind; SSA.Identifier = ssaVarId }

  /// Returns the SSA variable corresponding to the given definition sensitive
  /// variable point. If the variable does not exist, it creates a new SSA
  /// variable and returns it.
  let getSSAVarFromDefSvp defSvp =
    match defSvpToSSAVar.TryGetValue defSvp with
    | true, ssaVar -> ssaVar
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
        let fakeDefPp = ProgramPoint.GetFake()
        let fakeSpp = { ProgramPoint = fakeDefPp; ExecutionContext = exeCtx }
        let fakeSvp = { SensitiveProgramPoint = fakeSpp; VarKind = varKind }
        let fakeSSAVar = getSSAVarFromDefSvp fakeSvp
        SSA.Var fakeSSAVar

  let rec computeSSAExpr pp exeCtx = function
    | Var _ | TempVar _ as e -> (* Track its use-def chain. *)
      let varKind = VarKind.ofIRExpr e
      let spp = { ProgramPoint = pp; ExecutionContext = exeCtx }
      let svp = { SensitiveProgramPoint = spp; VarKind = varKind }
      convertUseToReachingDefSSAExpr svp exeCtx varKind
    | ExprList(l, _) -> List.map (computeSSAExpr pp exeCtx) l |> SSA.ExprList
    | UnOp(op, e, _) ->
      let sexpr = computeSSAExpr pp exeCtx e
      let rt = Expr.TypeOf e
      SSA.UnOp(op, rt, sexpr)
    | BinOp(op, rt, e1, e2, _) ->
      let sexpr1 = computeSSAExpr pp exeCtx e1
      let sexpr2 = computeSSAExpr pp exeCtx e2
      SSA.BinOp(op, rt, sexpr1, sexpr2)
    | RelOp(op, e1, e2, _) ->
      let sexpr1 = computeSSAExpr pp exeCtx e1
      let sexpr2 = computeSSAExpr pp exeCtx e2
      let rt = Expr.TypeOf e1
      SSA.RelOp(op, rt, sexpr1, sexpr2)
    | Extract(e, _, pos, _) ->
      let sexpr = computeSSAExpr pp exeCtx e
      let rt = Expr.TypeOf e
      SSA.Extract(sexpr, rt, pos)
    | Cast(op, _, e, _) ->
      let sexpr = computeSSAExpr pp exeCtx e
      let rt = Expr.TypeOf e
      SSA.Cast(op, rt, sexpr)
    | Ite(e1, e2, e3, _) ->
      let sexpr1 = computeSSAExpr pp exeCtx e1
      let sexpr2 = computeSSAExpr pp exeCtx e2
      let sexpr3 = computeSSAExpr pp exeCtx e3
      let rt = Expr.TypeOf e2
      SSA.Ite(sexpr1, rt, sexpr2, sexpr3)
    | Load(_, rt, e, _) ->
      let spp = { ProgramPoint = pp; ExecutionContext = exeCtx }
      match spEvaluateExpr spp e with
      | StackPointerDomain.ConstSP bv ->
        let varKind = BitVector.ToUInt64 bv |> toFrameOffset |> StackLocal
        let useSvp = { SensitiveProgramPoint = spp; VarKind = varKind }
        convertUseToReachingDefSSAExpr useSvp exeCtx varKind
      | _ ->
        let e = computeSSAExpr pp exeCtx e
        let fakeMemoryVar = { SSA.Kind = SSA.MemVar; SSA.Identifier = -1 }
        SSA.Load(fakeMemoryVar, rt, e)
    | PCVar(rt, _rname, _) ->
      let fakeAddr = 0xdeadbeef1UL
      let bv = BitVector.OfUInt64(fakeAddr, rt)
      SSA.Num bv
    | Num(bv, _) -> SSA.Num bv
    | FuncName(name, _) -> SSA.FuncName name
    | Undefined(rt, name, _) -> SSA.Undefined(rt, name)
    | JmpDest(_, _) -> Terminator.impossible ()

  /// Comptues the pseudo-SSA statement for the given statement at the given
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
      let tpp = { ProgramPoint = pp; ExecutionContext = exeCtx }
      match spEvaluateExpr tpp dstExpr with
      | StackPointerDomain.ConstSP bv ->
        let offset = BitVector.ToUInt64 bv |> toFrameOffset
        let varKind = StackLocal offset
        let svp = { SensitiveProgramPoint = tpp; VarKind = varKind }
        let var = getSSAVarFromDefSvp svp
        let srcExpr = computeSSAExpr pp exeCtx srcExpr
        SSA.Def(var, srcExpr)
      | _ ->
        let rt = Expr.TypeOf srcExpr
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
    | _ -> Terminator.impossible ()

  let getSSAStmt pp exeCtx =
    let tpp = { ProgramPoint = pp; ExecutionContext = exeCtx }
    match perPointSSAStmtCache.TryGetValue tpp with
    | true, sstmts -> sstmts
    | false, _ ->
      assert (not << ProgramPoint.IsFake) pp
      assert (stmtOfBBLs.ContainsKey pp)
      let stmt, _ = stmtOfBBLs[pp]
      let sstmt = computeSSAStmt stmt pp exeCtx
      perPointSSAStmtCache[tpp] <- sstmt
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
    match stmtInfoCache.TryGetValue v with
    | false, _ -> Terminator.impossible ()
    | true, stmtInfos ->
      for _stmt, pp in stmtInfos do
        let tpp = { ProgramPoint = pp; ExecutionContext = exeCtx }
        perPointSSAStmtCache.Remove tpp |> ignore

  let domainSubState =
    let flowQueue = UniqueQueue()
    let defSiteQueue = UniqueQueue()
    let executedFlows = HashSet()
    let executedVertices = HashSet()
    { new SubState<'L, 'ExeCtx> with
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
    { new SubState<StackPointerDomain.Lattice, 'ExeCtx> with
        member _.FlowQueue = flowQueue
        member _.DefSiteQueue = defSiteQueue
        member _.ExecutedFlows = executedFlows
        member _.ExecutedVertices = executedVertices
        member _.Bottom = StackPointerDomain.Undef
        member _.GetAbsValue vp = spGetAbsValue vp
        member _.SetAbsValue(vp, absVal) = spAbsValues[vp] <- absVal
        member _.Join(a, b) = StackPointerDomain.join a b
        member _.Subsume(a, b) = StackPointerDomain.subsume a b
        member _.EvalExpr(myPp, expr) = spEvaluateExpr myPp expr }

  let resetSubState (subState: SubState<_, _>) =
    subState.FlowQueue.Clear()
    subState.DefSiteQueue.Clear()
    subState.ExecutedFlows.Clear()
    subState.ExecutedVertices.Clear()

  let reset () =
    stmtInfoCache.Clear()
    ssaStmtCache.Clear()
    perPointSSAStmtCache.Clear()
    domainAbsValues.Clear()
    spAbsValues.Clear()
    perVertexIncomingDefs.Clear()
    perVertexOutgoingDefs.Clear()
    defUseMap.Clear()
    useDefMap.Clear()
    stmtOfBBLs.Clear()
    edgesForProcessing.Clear()
    defSvpToSSAVar.Clear()
    ssaVarToDefSvp.Clear()
    perVertexPossibleExeCtxs.Clear()
    perVertexStackPointerInfos.Clear()
    freshSSAVarId <- 1
    resetSubState spSubState
    resetSubState domainSubState

  member _.Scheme with get() = scheme

  member _.PerVertexPossibleExeCtxs with get() = perVertexPossibleExeCtxs

  member _.PerVertexStackPointerInfos with get() = perVertexStackPointerInfos

  /// Mapping from a CFG vertex to its incoming definitions.
  member _.PerVertexIncomingDefs with get() = perVertexIncomingDefs

  /// Mapping from a CFG vertex to its outgoing definitions.
  member _.PerVertexOutgoingDefs with get() = perVertexOutgoingDefs

  /// Mapping from a variable def to its uses.
  member _.DefUseMap with get() = defUseMap

  /// Mapping from a variable use to its definition.
  member _.UseDefMap with get() = useDefMap

  /// Mapping from a program point to `StmtOfBBL`, which is a pair of a Low-UIR
  /// statement and its corresponding vertex that contains the statement.
  member _.StmtOfBBLs with get() = stmtOfBBLs

  /// Sub-state for the stack-pointer domain.
  member _.StackPointerSubState with get() = spSubState

  /// Sub-state for the user's domain.
  member _.DomainSubState with get() = domainSubState

  /// Currently pending vertices for processing.
  member _.PendingEdges with get(): IEnumerable<_> = edgesForProcessing

  /// A setter for the evaluator.
  member _.Evaluator with set v = evaluator <- v

  /// Returns a sequence of vertices that are pending for removal.
  member _.VerticesForRemoval with get() = verticesForRemoval: IEnumerable<_>

  /// The given binary handle.
  member _.BinHandle with get() = hdl

  /// Mark the given vertex as pending, which means that the vertex needs to be
  /// processed.
  member _.MarkEdgeAsPending(s, d) = edgesForProcessing.Add(s, d) |> ignore

  /// Mark the given vertex as removal, which means that the vertex needs to be
  /// removed. Returns false if the vertex is already marked for removal.
  member _.MarkVertexAsRemoval v = verticesForRemoval.Add v

  /// Check if the given vertex is pending for processing.
  member _.IsEdgePending(src, dst) = edgesForProcessing.Contains(src, dst)

  /// Clear the pending vertices.
  member _.ClearPendingEdges() = edgesForProcessing.Clear()

  /// Clear the vertices to be removed.
  member _.ClearRemovalVertices() = verticesForRemoval.Clear()

  /// Return the array of StmtInfos of the given vertex.
  member _.GetStmtInfos v = getStatements v

  member _.GetSSAStmts(v: IVertex<LowUIRBasicBlock>, exeCtx: 'ExeCtx) =
    let vWithCtx = v, exeCtx
    match ssaStmtCache.TryGetValue vWithCtx with
    | true, stmts -> stmts
    | false, _ ->
      let stmts = computeSSAStmts v exeCtx
      ssaStmtCache[vWithCtx] <- stmts
      stmts

  /// Invalidate the given vertex, which means that all the information
  /// associated with the vertex is removed from the state. The order of
  /// the removal is important, and it should be done in the current order.
  member _.InvalidateVertex(v: IVertex<LowUIRBasicBlock>) =
    scheme.OnRemoveVertex v
    match perVertexPossibleExeCtxs.TryGetValue v with
    | false, _ -> ()
    | true, exeCtxs ->
      for exeCtx in exeCtxs do
        let key = v, exeCtx
        perVertexIncomingDefs.Remove key |> ignore
        perVertexOutgoingDefs.Remove key |> ignore
        perVertexStackPointerInfos.Remove key |> ignore
        invalidateSSAStmts v exeCtx
      perVertexPossibleExeCtxs.Remove v |> ignore
    match stmtInfoCache.TryGetValue v with
    | false, _ -> ()
    | true, stmtInfos ->
      for (_, pp) in stmtInfos do
        stmtOfBBLs.Remove pp |> ignore
      stmtInfoCache.Remove v |> ignore

  member _.TryFindSSADefStmtFromSSAVar var =
    let svp = getDefSvpFromSSAVar var
    let spp = svp.SensitiveProgramPoint
    let pp = spp.ProgramPoint
    if ProgramPoint.IsFake pp then
      None
    else
      Some <| getSSAStmt pp spp.ExecutionContext

  member this.FindSSADefStmtFromSSAVar var =
    this.TryFindSSADefStmtFromSSAVar var
    |> Option.get

  member _.InvalidateSSAStmts(v, exeCtx) =
    invalidateSSAStmts v exeCtx

  member _.SSAVarToDefSVP var = getDefSvpFromSSAVar var

  member _.DefSVPToSSAVar svp = getSSAVarFromDefSvp svp

  member _.EvalExpr(pp, expr) = evaluator.EvalExpr(pp, expr)

  /// Reset this state.
  member _.Reset() = reset ()

  interface IAbsValProvider<SensitiveVarPoint<'ExeCtx>, 'L> with
    member _.GetAbsValue absLoc = domainGetAbsValue absLoc

and SubState<'L, 'ExeCtx when 'L: equality
                          and 'ExeCtx: equality
                          and 'ExeCtx: comparison> =
  inherit IAbsValProvider<SensitiveVarPoint<'ExeCtx>, 'L>
  inherit ILattice<'L>
  inherit IExprEvaluatable<SensitiveProgramPoint<'ExeCtx>, 'L>

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
  abstract SetAbsValue: vp: SensitiveVarPoint<'ExeCtx> * 'L -> unit

/// The main interface for a sensitive data-flow analysis.
and IScheme<'L, 'ExeCtx when 'L: equality
                         and 'ExeCtx: equality
                         and 'ExeCtx: comparison> =
  /// A default execution context that a root node in a CFG can have.
  abstract DefaultExecutionContext: 'ExeCtx

  /// Compute an execution context that the successor can have from the current
  /// context. This returns None if the edge should be pruned (e.g.
  /// path-sensitive analysis).
  abstract TryComputeExecutionContext:
       IVertex<LowUIRBasicBlock>
    * exeCtx: 'ExeCtx
    * successor: IVertex<LowUIRBasicBlock>
    * CFGEdgeKind
    -> 'ExeCtx option

  /// Called when a vertex is newly analyzed.
  abstract OnVertexNewlyAnalyzed: IVertex<LowUIRBasicBlock> -> unit

  /// Called when a vertex is removed.
  abstract OnRemoveVertex: IVertex<LowUIRBasicBlock> -> unit

and SensitiveReachingDefs<'ExeCtx when 'ExeCtx: equality
                          and 'ExeCtx: comparison> =
  Map<VarKind, Set<SensitiveVarPoint<'ExeCtx>>>

/// Represents a program point in the sensitive data-flow analysis.
and SensitiveProgramPoint<'ExeCtx when 'ExeCtx: equality
                                   and 'ExeCtx: comparison> =
  { ProgramPoint: ProgramPoint
    ExecutionContext: 'ExeCtx }

/// Represents a variable point in the sensitive data-flow analysis.
and SensitiveVarPoint<'ExeCtx when 'ExeCtx: equality
                               and 'ExeCtx: comparison> =
  { SensitiveProgramPoint: SensitiveProgramPoint<'ExeCtx>
    VarKind: VarKind }

[<AutoOpen>]
module internal AnalysisCore = begin

  /// Dataflow chains become invalid when a vertex is removed from the graph.
  let removeInvalidChains (state: State<_, _>) =
    for v in state.VerticesForRemoval do
      state.InvalidateVertex v
    state.ClearRemovalVertices()

  let getStackValue state pp e =
    match (state: SubState<_, _>).EvalExpr(pp, e) with
    | StackPointerDomain.ConstSP bv -> Ok <| BitVector.ToUInt64 bv
    | _ -> Error ErrorCase.InvalidExprEvaluation

  /// When a use is removed, we need to remove all the old chains.
  let removeOldChains (state: State<_, _>) useId =
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
  let updateDefUseChain (state: State<_, _>) useId defId =
    match state.DefUseMap.TryGetValue defId with
    | false, _ -> state.DefUseMap[defId] <- Set.singleton useId
    | true, uses -> state.DefUseMap[defId] <- Set.add useId uses

  /// Overwrite the use-def chain. Unlike `updateDefUseChain`, this strongly
  /// updates the existing use-def chain, as we already know exactly which
  /// definitions are used by the use at the moment.
  let updateUseDefChain (state: State<_, _>) id defs =
    state.UseDefMap[id] <- defs

  let updateChains (state: State<_, _>) vk defs tpp =
    match Map.tryFind vk defs with
    | None -> ()
    | Some rds ->
      let useSvp = { SensitiveProgramPoint = tpp; VarKind = vk }
      removeOldChains state useSvp
      for defSvp in rds do updateDefUseChain state useSvp defSvp
      updateUseDefChain state useSvp rds

  let rec updateWithExpr state defs (tpp: SensitiveProgramPoint<_>) = function
    | Num(_)
    | Undefined(_)
    | FuncName(_) -> ()
    | Var(_rt, rid, _rstr, _) -> updateChains state (Regular rid) defs tpp
    | TempVar(_, n, _) -> updateChains state (Temporary n) defs tpp
    | ExprList(exprs, _) ->
      for expr in exprs do
        updateWithExpr state defs tpp expr
    | Load(_, _, expr, _) ->
      updateWithExpr state defs tpp expr
      getStackValue state.StackPointerSubState tpp expr
      |> Result.iter (fun loc ->
        let offset = toFrameOffset loc
        updateChains state (StackLocal offset) defs tpp)
      updateWithExpr state defs tpp expr
    | UnOp(_, expr, _) ->
      updateWithExpr state defs tpp expr
    | BinOp(_, _, expr1, expr2, _) ->
      updateWithExpr state defs tpp expr1
      updateWithExpr state defs tpp expr2
    | RelOp(_, expr1, expr2, _) ->
      updateWithExpr state defs tpp expr1
      updateWithExpr state defs tpp expr2
    | Ite(expr1, expr2, expr3, _) ->
      updateWithExpr state defs tpp expr1
      updateWithExpr state defs tpp expr2
      updateWithExpr state defs tpp expr3
    | Cast(_, _, expr, _) ->
      updateWithExpr state defs tpp expr
    | Extract(expr, _, _, _) ->
      updateWithExpr state defs tpp expr
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

  let isIntraEdge lbl =
    match lbl with
    | IntraCJmpTrueEdge
    | IntraCJmpFalseEdge
    | IntraJmpEdge -> true
    | _ -> false

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
    | StackPointerDomain.ConstSP bv -> BitVector.ToUInt64 bv |> toFrameOffset
    | _ -> Terminator.impossible ()

  /// Join the two reaching definition maps. We filter out temporary variables
  /// here.
  /// TODO: check if it is propagated through intra-block edges like
  /// `VarBasedDataFlowAnalysis`.
  let joinDefs dstInSP (m1: SensitiveReachingDefs<_>)
                       (m2: SensitiveReachingDefs<_>) =
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

  let strongUpdateReachingDef rds vk svp =
    let set = Set.singleton svp
    Map.add vk set rds

  /// Strongly updates the stack pointer value for the given tagged variable.
  /// We assume that the stack pointer value is always a constant value in a
  /// single vertex with a single execution context (sensitivity).
  let updateStackPointer (state: State<_, _>) tpp vk
                         e =
    let subState = state.StackPointerSubState
    let spValue = subState.EvalExpr(tpp, e)
    let tvp = { SensitiveProgramPoint = tpp; VarKind = vk }
    subState.SetAbsValue(tvp, spValue)

  /// (1) Compute the (outgoing) reaching definitions for the given vertex.
  /// (2) Update the def-use/use-def chains on the fly.
  /// (3) We update every stack pointer values while executing the vertex.
  let execute state (v: IVertex<LowUIRBasicBlock>) exeCtx inDefs =
    let stmtInfos = (state: State<_, _>).GetStmtInfos v
    let mutable outDefs = inDefs
    for (stmt, pp) in stmtInfos do
      match stmt with
      | Put(dst, src, _) ->
        let varKind = VarKind.ofIRExpr dst
        let tpp = { ProgramPoint = pp; ExecutionContext = exeCtx }
        let tvp = { SensitiveProgramPoint = tpp; VarKind = varKind }
        updateWithExpr state outDefs tpp src
        updateWithExpr state outDefs tpp dst
        updateStackPointer state tpp varKind src
        outDefs <- strongUpdateReachingDef outDefs varKind tvp
      | Store(_, addr, value, _) ->
        let tpp = { ProgramPoint = pp; ExecutionContext = exeCtx }
        updateWithExpr state outDefs tpp addr
        updateWithExpr state outDefs tpp value
        match state.StackPointerSubState.EvalExpr(tpp, addr) with
        | StackPointerDomain.ConstSP bv ->
          let loc = BitVector.ToUInt64 bv
          let offset = toFrameOffset loc
          let varKind = StackLocal offset
          let tpp = { ProgramPoint = pp; ExecutionContext = exeCtx }
          let tvp = { SensitiveProgramPoint = tpp; VarKind = varKind }
          // updateStackPointer state tpp varKind value
          outDefs <- strongUpdateReachingDef outDefs varKind tvp
        | _ -> ()
      | InterJmp(dstExpr, _, _) ->
        let tpp = { ProgramPoint = pp; ExecutionContext = exeCtx }
        updateWithExpr state outDefs tpp dstExpr
      | InterCJmp(condExpr, tExpr, fExpr, _) ->
        let tpp = { ProgramPoint = pp; ExecutionContext = exeCtx }
        updateWithExpr state outDefs tpp condExpr
        updateWithExpr state outDefs tpp tExpr
        updateWithExpr state outDefs tpp fExpr
      | ExternalCall(e, _) ->
        let tpp = { ProgramPoint = pp; ExecutionContext = exeCtx }
        updateWithExpr state outDefs tpp e
      | Jmp _ | CJmp _ -> Terminator.futureFeature ()
      | SideEffect _ -> ()
      | ISMark _ | IEMark _ | LMark _ -> ()
    outDefs

  let prepareQueue (state: State<_, _>) g =
    let queue = UniqueQueue()
    for s, d in state.PendingEdges do
      if not <| (g: IDiGraph<_, _>).HasVertex d.ID then ()
      elif s = null then (* Root node has been created. *)
        let s = s, state.Scheme.DefaultExecutionContext
        let d = d
        queue.Enqueue(s, d)
      elif g.HasVertex s.ID then
        for inSP in getPossibleExeCtxs state s do
          let s = s, inSP
          let d = d
          queue.Enqueue(s, d)
    queue

  let tryPropagateRDs state src srcExeCtx dst dstExeCtx =
    let srcOutDefs = getOutgoingDefs state src srcExeCtx
    let dstInDefs = getIncomingDefs state dst dstExeCtx
    let dstInSP =
      if isNull src then
        let spRid = state.BinHandle.RegisterFactory.StackPointer.Value
        let spRegType = state.BinHandle.RegisterFactory.GetRegType spRid
        BitVector.OfUInt64(Constants.InitialStackPointer, spRegType)
        |> StackPointerDomain.ConstSP
      else snd state.PerVertexStackPointerInfos[src, srcExeCtx]
    match joinDefs dstInSP srcOutDefs dstInDefs with
    | false, _ -> None
    | true, dstInDefs' -> Some dstInDefs'

  let addPossibleExeCtx (state: State<_, _>) v exeCtx =
    let possibleExeCtxs = state.PerVertexPossibleExeCtxs
    let hasSet = possibleExeCtxs.ContainsKey v
    if not hasSet then
      possibleExeCtxs[v] <- HashSet [ exeCtx ]
      state.Scheme.OnVertexNewlyAnalyzed v
    else possibleExeCtxs[v].Add exeCtx |> ignore

  let getOutSP (state: State<_, _>) v exeCtx =
    if isNull v then
      let spRid = state.BinHandle.RegisterFactory.StackPointer.Value
      let spRegType = state.BinHandle.RegisterFactory.GetRegType spRid
      BitVector.OfUInt64(Constants.InitialStackPointer, spRegType)
      |> StackPointerDomain.ConstSP
    else snd state.PerVertexStackPointerInfos[v, exeCtx]

  let evaluateRecentSP (state: State<_, _>) m =
    let spRid = state.BinHandle.RegisterFactory.StackPointer.Value
    let spRegType = state.BinHandle.RegisterFactory.GetRegType spRid
    let spVarKind = Regular spRid
    match Map.tryFind spVarKind m with
    | None ->
      BitVector.OfUInt64(Constants.InitialStackPointer, spRegType)
      |> StackPointerDomain.ConstSP
    | Some defs ->
      defs
      |> Seq.head
      |> state.StackPointerSubState.GetAbsValue

  let executeAndPropagateRDs (state: State<_, _>)
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
    if isFirstVisit then addPossibleExeCtx state dst dstExeCtx
    match maybeJoinedOutDefs with
    | None -> ()
    | Some dstOutDefs' ->
      let srcOutSP = getOutSP state src srcExeCtx
      let dstOutSP = evaluateRecentSP state dstOutDefs'
      let dstSPInfo = srcOutSP, dstOutSP
      state.PerVertexStackPointerInfos[dstKey] <- dstSPInfo
      state.PerVertexIncomingDefs[dstKey] <- dstDefs
      state.PerVertexOutgoingDefs[dstKey] <- dstOutDefs'
      state.InvalidateSSAStmts(dst, dstExeCtx) (* Caches can be obsolete. *)
      for succ in (g: IDiGraph<_, _>).GetSuccs dst do
        (queue: UniqueQueue<_>).Enqueue((dst, dstExeCtx), succ)

  /// Compute the successor execution context and the reaching definitions for
  /// the given edge. If the edge is infeasible or the reaching definitions do
  /// not change, return None.
  let tryComputeSuccessorExeCtxAndDefs g (st: State<_, _>) src srcExeCtx dst =
    if isNull src then Some(st.Scheme.DefaultExecutionContext, Map.empty)
    else
      let edge = (g: IDiGraphAccessible<_, _>).FindEdge(src, dst)
      let kind = edge.Label
      match st.Scheme.TryComputeExecutionContext(src, srcExeCtx, dst, kind) with
      | None -> None (* Infeasible flow. *)
      | Some dstExeCtx ->
        tryPropagateRDs st src srcExeCtx dst dstExeCtx
        |> Option.map (fun dstInDefs -> dstExeCtx, dstInDefs)

  let calculateChains g state =
    let q = prepareQueue state g
    while not q.IsEmpty do
      let (src, srcExeCtx), dst = q.Dequeue()
      tryComputeSuccessorExeCtxAndDefs g state src srcExeCtx dst
      |> Option.iter (fun (dstExeCtx, defs) ->
        executeAndPropagateRDs state q g src dst srcExeCtx dstExeCtx defs)

  let updateAbsValue subState defUseMap svp prev curr =
    if (subState: SubState<_, _>).Subsume(prev, curr) then
      ()
    else
      subState.SetAbsValue(svp, subState.Join(prev, curr))
      match (defUseMap: Dictionary<_, _>).TryGetValue svp with
      | false, _ -> ()
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
        let loc = BitVector.ToUInt64 bv
        let offset = toFrameOffset loc
        let varKind = StackLocal offset
        let svp = { SensitiveProgramPoint = spp; VarKind = varKind }
        let subState = state.DomainSubState
        let prev = subState.GetAbsValue svp
        let curr = state.EvalExpr(spp, value)
        let defUseMap = state.DefUseMap
        updateAbsValue subState defUseMap svp prev curr
      | _ -> ()
    | _ -> ()

  let isExecuted (state: State<_, _>) (subState: SubState<_, _>) spp =
    let pp = (spp: SensitiveProgramPoint<_>).ProgramPoint
    let exeCtx = spp.ExecutionContext
    match state.StmtOfBBLs.TryGetValue pp with
    | false, _ -> false
    | true, (_, v) -> subState.ExecutedVertices.Contains(v, exeCtx)

  let processDefSite (state: State<_, _>)
                     (subState: SubState<_, _>)
                     fnTransfer =
    match subState.DefSiteQueue.TryDequeue() with
    | true, myPp when isExecuted state subState myPp ->
      let pp = myPp.ProgramPoint
      let exeCtx = myPp.ExecutionContext
      let stmt, _ = state.StmtOfBBLs[pp]
      fnTransfer state exeCtx (stmt, pp)
    | _ -> ()

  let transferFlow g (state: State<_, _>)
                   (subState: SubState<_, _>) v exeCtx
                   fnTransfer =
    let key = v, exeCtx
    subState.ExecutedVertices.Add key |> ignore
    for stmt in state.GetStmtInfos v do fnTransfer state exeCtx stmt done
    (g: IDiGraph<_, _>).GetSuccs v
    |> Array.map (fun succ -> v, exeCtx, succ)
    |> Array.iter subState.FlowQueue.Enqueue

  let tryGetSuccessorExeCtx g (state: State<_, _>) src srcExeCtx dst =
    if isNull src then Some state.Scheme.DefaultExecutionContext
    else
      let edge = (g: IDiGraphAccessible<_, _>).FindEdge(src, dst)
      let edgeKind = edge.Label
      state.Scheme.TryComputeExecutionContext(src, srcExeCtx, dst, edgeKind)

  let processFlow g state subState fnTransfer =
    let subState = subState :> SubState<_, _>
    match subState.FlowQueue.TryDequeue() with
    | false, _ -> ()
    | true, (src, srcExeCtx, dst) ->
      if not <| subState.ExecutedFlows.Add(src, srcExeCtx, dst) then ()
      else
        match (g: IDiGraph<_, _>).TryFindVertexByID dst.ID with
        | Some dst ->
          match tryGetSuccessorExeCtx g state src srcExeCtx dst with
          | None -> () (* Prune infeasible flow. *)
          | Some dstExeCtx ->
            transferFlow g state subState dst dstExeCtx fnTransfer
        | None -> ()

  let registerPendingVertices state subState =
    let subState = subState :> SubState<_, _>
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

let compute g state =
  removeInvalidChains state
  calculateChains g state
  propagateDomain g state
  state.ClearPendingEdges()
  state
