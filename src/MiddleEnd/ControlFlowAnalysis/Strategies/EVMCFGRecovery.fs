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

namespace B2R2.MiddleEnd.ControlFlowAnalysis.Strategies

open System
open System.Collections.Generic
open B2R2
open B2R2.BinIR
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.DataFlow.LowUIRSensitiveDataFlow

[<AutoOpen>]
module private EVMCFGRecovery =
  let summarizer = EVMFunctionSummarizer() :> IFunctionSummarizable<_, _>

  let getFunctionContext (ctx: CFGBuildingContext<EVMFuncUserContext, _>)
                          calleeAddr =
    match ctx.ManagerChannel.GetBuildingContext calleeAddr with
    | FinalCtx calleeCtx
    | StillBuilding calleeCtx -> Ok calleeCtx
    | FailedBuilding -> Error ErrorCase.FailedToRecoverCFG

  let getFunctionUserContext ctx calleeAddr =
    getFunctionContext ctx calleeAddr
    |> Result.bind (fun calleeCtx -> Ok calleeCtx.UserContext)

  /// Check if this vertex was executed in the data-flow analysis. Note that
  /// incomplete CFG traversal can lead to that situation, as we conduct path-
  /// sensitive data-flow analysis.
  let isExecuted (state: State<_, _>) v =
    state.PerVertexPossibleExeCtxs.ContainsKey v

  let rec expandExpr (state: State<_, _>) e =
    match e with
    | SSA.Var var ->
      (* Note that we use fake definition for variables that are not defined in
         the current function. This is because we cannot find the definition of
         such variables, and we assume that they are defined in the caller
         function. *)
      match state.FindSSADefStmtFromSSAVar var with
      | SSA.Def(_, e) -> expandExpr state e
      | _ -> Terminator.impossible ()
    | SSA.ExprList [ expr ] -> expandExpr state expr
    | SSA.ExprList [] -> e (* Can be an empty list of external call params. *)
    | SSA.ExprList exprs -> assert (exprs <> []); e (* Ignore phis. *)
    | SSA.BinOp(op, rt, e1, e2) ->
      let e1' = expandExpr state e1
      let e2' = expandExpr state e2
      SSA.BinOp(op, rt, e1', e2')
    | SSA.UnOp(op, rt, e) ->
      let e' = expandExpr state e
      SSA.UnOp(op, rt, e')
    | SSA.Extract(e, rt, i) ->
      let e' = expandExpr state e
      SSA.Extract(e', rt, i)
    | SSA.Cast(castKind, rt, e) ->
      let e' = expandExpr state e
      SSA.Cast(castKind, rt, e')
    | SSA.Load(memVar, rt, e) ->
      let e' = expandExpr state e
      SSA.Load(memVar, rt, e')
    | SSA.Ite(cond, rt, tExpr, fExpr) ->
      let cond' = expandExpr state cond
      let tExpr' = expandExpr state tExpr
      let fExpr' = expandExpr state fExpr
      SSA.Ite(cond', rt, tExpr', fExpr')
    | SSA.RelOp(op, rt, e1, e2) ->
      let e1' = expandExpr state e1
      let e2' = expandExpr state e2
      SSA.RelOp(op, rt, e1', e2')
    | SSA.Store(memVar, rt, addr, value) ->
      let addr' = expandExpr state addr
      let value' = expandExpr state value
      SSA.Store(memVar, rt, addr', value')
    | SSA.Num _
    | SSA.FuncName _
    | SSA.Undefined _ -> e

  let fourBytesBitmaskBv = BitVector.OfUInt32(UInt32.MaxValue, 256<rt>)

  let isPossiblyFuncSig bv = (bv: BitVector).And fourBytesBitmaskBv = bv

  let isMsgDataDivision = function
    | SSA.BinOp(BinOpType.DIV, _,
                 SSA.BinOp(BinOpType.APP, _, SSA.FuncName "msg.data", _),
                 SSA.Num _disivorBv)
    | SSA.BinOp(BinOpType.DIV, _,
                 SSA.Num _disivorBv,
                 SSA.BinOp(BinOpType.APP, _, SSA.FuncName "msg.data", _))
      -> true
    | SSA.BinOp(BinOpType.SHR, _,
                 SSA.BinOp(BinOpType.APP, _, SSA.FuncName "msg.data", _),
                 SSA.Num _shiftBv)
      -> true
    | _ -> false

  let hasFuncSigExpr = function
    | SSA.BinOp(BinOpType.AND, _, SSA.Num bitmaskBv, msgDataDivisionExpr)
    | SSA.BinOp(BinOpType.AND, _, msgDataDivisionExpr, SSA.Num bitmaskBv)
      when isMsgDataDivision msgDataDivisionExpr
        && bitmaskBv = fourBytesBitmaskBv
      -> true
    | _ -> false

  let rec tryDetectPubFunc ctx state cond =
    match expandExpr state cond with
    | SSA.Extract(e, _, _) -> tryDetectPubFunc ctx state e
    | SSA.Cast(_, _, e) -> tryDetectPubFunc ctx state e
    | SSA.RelOp(RelOpType.EQ, _, SSA.Num hashBv, e)
    | SSA.RelOp(RelOpType.EQ, _, e, SSA.Num hashBv)
      when isPossiblyFuncSig hashBv
        && (hasFuncSigExpr e || isMsgDataDivision e) ->
      true
    | _ -> false

  let scanAndGetVertex ctx cfgRec addr =
    let pp = ProgramPoint(addr, 0)
    if ctx.BBLFactory.Contains pp then ()
    else CFGRecovery.scanBBLs ctx [ addr ] |> ignore
    CFGRecovery.getVertex ctx cfgRec pp

  /// Returns the list of root variables for the given variables.
  let rec findRootVars (state: State<_, _>) acc worklist =
    match worklist with
    | [] -> acc
    | var :: rest ->
      match state.TryFindSSADefStmtFromSSAVar var with
      | Some(SSA.Def(_, e)) ->
        match e with
        | SSA.Var rdVar -> findRootVars state acc (rdVar :: rest)
        | SSA.ExprList exprs ->
          exprs
          |> List.choose (function
            | SSA.Var rdVar -> Some rdVar
            | _ -> None)
          |> List.append rest
          |> findRootVars state acc
        | _ -> findRootVars state (var :: acc) rest (* End of the chain. *)
      | _ -> findRootVars state (var :: acc) rest (* End of the chain. *)

  let extractVarsFromExpr e =
    match e with
    | SSA.Var var -> [ var ]
    | SSA.ExprList exprs ->
      exprs
      |> List.choose (function
        | SSA.Var var -> Some var
        | _ -> None)
    | _ -> []

  let findRootVarsFromExpr state e =
    extractVarsFromExpr e
    |> findRootVars state []

  let getDefSiteVertex (state: State<_, _>) var =
    let svp = state.SSAVarToDefSVP var
    let spp = svp.SensitiveProgramPoint
    let pp = spp.ProgramPoint
    assert state.StmtOfBBLs.ContainsKey pp
    snd state.StmtOfBBLs[pp]

  /// Try to find a feasible path from `srcV` to `dstV` in the given graph `g`.
  /// We use BFS to find a path fast.
  let tryFindFeasiblePath g srcV dstV =
    let q = Queue()
    let visited = HashSet<IVertex<_>>()
    let push v p = if not <| visited.Add v then () else q.Enqueue(v, v :: p)
    let mutable foundPath = None
    push srcV []
    while Option.isNone foundPath && q.Count > 0 do
      let v, p = q.Dequeue()
      for succ in (g: IDiGraphAccessible<_, _>).GetSuccs v do
        if succ = dstV then foundPath <- Some(dstV :: p)
        else push succ p
    Option.map List.rev foundPath

  /// Find a feasible path from `srcV` to `dstV` in the given graph `g`.
  let findFeasiblePath g srcV dstV =
    if srcV = dstV then [ srcV; dstV ]
    else
      match tryFindFeasiblePath g srcV dstV with
      | Some p -> p
      | None -> Terminator.impossible ()

  let tryGetOverApproximatedJumpDstExprOfJmp (state: State<_, _>) v =
    match SensitiveDFHelper.tryOverApproximateTerminator state v with
    | Some(SSA.Jmp(SSA.InterJmp dst)) -> Some dst
    | _ -> None

  let getOverApproximatedJumpDstExprOfJmp (state: State<_, _>) v =
    tryGetOverApproximatedJumpDstExprOfJmp state v
    |> Option.get

  let isFallthroughNode v =
    not (v: IVertex<LowUIRBasicBlock>).VData.Internals.IsAbstract
    && not v.VData.Internals.LastInstruction.IsBranch

  let hasPolyJumpTarget (state: State<_, _>) v =
    if isFallthroughNode v then false
    else
      match tryGetOverApproximatedJumpDstExprOfJmp state v with
      | None -> false
      | Some e ->
        e
        |> findRootVarsFromExpr state
        |> Seq.distinct
        |> Seq.length
        |> (<) 1

  let collectPolyJumpsFromReachables (g: IDiGraphAccessible<_, _>) state start =
    let q = Queue()
    let visited = HashSet()
    let push v = if not <| visited.Add v then () else q.Enqueue v
    let mutable polyJumps = []
    push start
    while not <| Seq.isEmpty q do
      let v = q.Dequeue()
      if not <| isExecuted state v then ()
      elif hasPolyJumpTarget state v then polyJumps <- v :: polyJumps
      else for succ in g.GetSuccs v do push succ
    polyJumps

  /// Find the intersection of two pathes. Time complexity is O((n+m)*log(n))
  /// where n and m are the lengths of the two pathes.
  let intersectPathes p1 p2 =
    let p1Set = Set.ofList p1
    List.filter (fun v -> Set.contains v p1Set) p2

  let introduceNewSharedRegion (ctx: CFGBuildingContext<_, _>) entryPoint =
    ctx.ManagerChannel.StartBuilding entryPoint
    getFunctionUserContext ctx entryPoint
    |> Result.iter (fun userCtx -> userCtx.SetSharedRegion())

  let findAndIntroduceSharedRegion ctx state v rdVars =
    assert (not <| Seq.isEmpty rdVars)
    let defVertices = Seq.map (getDefSiteVertex state) rdVars
    let g = ctx.CFG
    let pathes = Seq.map (fun d -> findFeasiblePath g d v) defVertices
    let firstPath, restPathes = Seq.head pathes, Seq.tail pathes
    let intersetedPath = Seq.fold intersectPathes firstPath restPathes
    let regionEntry = Seq.head intersetedPath
    let regionEntryAddr = regionEntry.VData.Internals.PPoint.Address
    assert (not regionEntry.VData.Internals.IsAbstract)
    (* This should reset the current analysis. *)
    introduceNewSharedRegion ctx regionEntryAddr

  let handlePolyJumps (ctx: CFGBuildingContext<_, _>) state polyJumps =
    assert (not <| Seq.isEmpty polyJumps)
    for polyJmpV in polyJumps do
      getOverApproximatedJumpDstExprOfJmp state polyJmpV
      |> findRootVarsFromExpr state
      |> findAndIntroduceSharedRegion ctx state polyJmpV
    Some StopAndReload

  let makeCalleeInfoFromBuildingContext = function
    | FinalCtx ctx -> ctx.NonReturningStatus, ctx.UnwindingBytes
    | StillBuilding _ -> NoRet, 0
    | _ -> Terminator.impossible ()

  let fromBBLToCallSite (blk: ILowUIRBasicBlock) =
    match blk.PPoint.CallSite with
    | None -> LeafCallSite blk.LastInstruction.Address
    | Some callSite -> ChainedCallSite(callSite, blk.PPoint.Address)

  /// This is the eseence of our CFG recovery in EVM, which finds a function
  /// entry point.
  let rec findFunctionEntry (path: IVertex<LowUIRBasicBlock> list) =
    assert (List.length path >= 2)
    let defSite, head, tail =
      match path with
      | defSite :: head :: tail -> defSite, head, tail
      | _ -> Terminator.impossible ()
    findFunctionEntryAux defSite head tail

  and findFunctionEntryAux pred curr path =
    match path with
    (* 1. It is already a function. *)
    | v :: path' when curr.VData.Internals.IsAbstract ->
      findFunctionEntryAux curr v path'
    (* 2. Call-fallthrough node cannot be an entry point. *)
    | v :: path' when pred <> null
                   && pred.VData.Internals.IsAbstract
                   && not curr.VData.Internals.IsAbstract ->
      findFunctionEntryAux curr v path'
    (* 3. Fallthrough node cannot be an entry point. *)
    | v :: path' when pred <> null
                   && not pred.VData.Internals.LastInstruction.IsBranch ->
      findFunctionEntryAux curr v path'
    (* 4. Conditional branch's target is **less likely** to be an entry point.*)
    | v :: path' when pred <> null
                   && not pred.VData.Internals.IsAbstract
                   && pred.VData.Internals.LastInstruction.IsCondBranch ->
      findFunctionEntryAux curr v path'
    (* 5. If the vertex is a function, then we found it. *)
    | _ when not curr.VData.Internals.IsAbstract ->
      curr
    | _ -> Terminator.impossible () (* Not found. *)

  let introduceNewFunction (ctx: CFGBuildingContext<_, _>) newEntryPoint =
    ctx.ManagerChannel.StartBuilding newEntryPoint

  let isInfeasibleEntryPoint (ctx: CFGBuildingContext<_, _>) v =
    let g = ctx.CFG
    let preds = g.GetPreds v
    preds |> Array.exists (fun pred ->
      not pred.VData.Internals.IsAbstract
      && pred.VData.Internals.LastInstruction.IsCondBranch)

  let findAndIntroduceFunction ctx srcV rds =
    let sampledDefSite = Seq.head rds
    let sampledPath = findFeasiblePath ctx.CFG sampledDefSite srcV
    let newEntryPoint = findFunctionEntry sampledPath
    let newEntryPointAddr = newEntryPoint.VData.Internals.PPoint.Address
    if isInfeasibleEntryPoint ctx newEntryPoint then (* likely shared region *)
      introduceNewSharedRegion ctx newEntryPointAddr
      Some StopAndReload
    else
      introduceNewFunction ctx newEntryPointAddr
      Some StopAndReload

  /// Find the latest stack pointer **after** the execution of the given vertex.
  let findLatestStackOffset ctx (state: State<_, _>) v =
    let tags = state.PerVertexPossibleExeCtxs[v]
    let tag = Seq.head tags
    let stackOffset = tag.StackOffset
    let userCtx = ctx.UserContext :> EVMFuncUserContext
    let delta = userCtx.GetStackPointerDelta(state, v)
    stackOffset + delta

  let isFakeVar var = (var: SSA.Variable).Identifier = 0

  /// We met a returning jump, which uses an incoming variable as its target,
  /// and we extract stack pointer difference and the target variable's stack
  /// pointer offset to abstract the return information, which will be used
  /// to build an inter-procedural (call) edge to this function later.
  let analyzeReturnInfo ctx state v incomingVars =
    assert (List.forall isFakeVar incomingVars)
    let var = List.head incomingVars
    let returnTargetStackOff =
      match var.Kind with
      | SSA.StackVar(_, off) -> uint64 off (* 0, 32, 64, ... *)
      | _ -> Terminator.impossible ()
    let stackPointerDiff = findLatestStackOffset ctx state v
    let fnUserCtx: EVMFuncUserContext = ctx.UserContext
    fnUserCtx.SetReturnTargetStackOff returnTargetStackOff
    fnUserCtx.SetStackPointerDiff(uint64 stackPointerDiff)
    None

  let computeCPState ctx =
    let userCtx = ctx.UserContext :> EVMFuncUserContext
    let dfa = userCtx.CP :> IDataFlowComputable<_, _, _, _>
    let cpState = dfa.Compute ctx.CFG
    cpState

  /// Summarize the callee's context.
  let summarize ctx calleeInfo =
    let retStatus, unwindingBytes = calleeInfo
    summarizer.Summarize(ctx, retStatus, unwindingBytes, null)

  let isCallRelatedFunction = function
    | "call"
    | "callcode"
    | "delegatecall"
    | "staticcall" -> true
    | _ -> false

  let exprToVar = function
    | SSA.Var v -> v
    | _ -> assert false; Terminator.impossible ()

  /// Finds a path condition that is related to inter-contract calls. We do not
  /// use SMT solvers to solve the path condition, but rather use a simple
  /// pattern matching to gather the path condition and solve it by an
  /// inconsistency check later.
  let rec tryExtractPathCondition (state: State<_, _>) recentVar cond =
    match cond with
    | SSA.Num bv when BitVector.IsOne bv -> Some(recentVar, true)
    | SSA.ExprList exprs -> (* TODO: tail-recursion w/ continuation *)
      exprs |> List.tryPick (fun e ->
        let var = exprToVar e
        match state.TryFindSSADefStmtFromSSAVar var with
        | Some(SSA.Def(_, e)) -> tryExtractPathCondition state var e
        | _ -> None)
    | SSA.BinOp(BinOpType.APP, _, SSA.FuncName callName, _)
      when isCallRelatedFunction callName ->
      Some(recentVar, true)
    | SSA.Cast(_, _, SSA.RelOp(RelOpType.EQ, _, e, SSA.Num bv_0x0))
      when BitVector.IsZero bv_0x0 ->
      match tryExtractPathCondition state recentVar e with
      | Some(d, b) -> Some(d, not b) (* Apply negation. *)
      | _ -> None
    | SSA.Extract(e, _, _) -> tryExtractPathCondition state recentVar e
    | _ -> None

  let isConditionalEdge (edgeKind: CFGEdgeKind) =
    edgeKind.IsInterCJmpTrueEdge || edgeKind.IsInterCJmpFalseEdge

  let computeCondition (state: State<_, _>) (kind: CFGEdgeKind) lastSStmt =
    assert isConditionalEdge kind
    match lastSStmt with
    | SSA.Jmp(SSA.InterCJmp(cond, _, _)) ->
      let fakePP = ProgramPoint.GetFake()
      let dummyExeCtx = { StackOffset = 0; Conditions = Map.empty }
      let fakeSPP = { ProgramPoint = fakePP; ExecutionContext = dummyExeCtx }
      let dummyVarKind = Temporary -1
      let fakeSVP = { SensitiveProgramPoint = fakeSPP; VarKind = dummyVarKind }
      let fakeVar = state.DefSVPToSSAVar fakeSVP
      tryExtractPathCondition state fakeVar cond
      |> Option.map (fun (v, b) ->
        let b = if kind.IsInterCJmpFalseEdge then not b else b
        v, b)
    | _ -> Terminator.impossible ()

  let makeExeCtx (usrCtx: EVMFuncUserContext) state srcV srcTag
                  maybeDstConditions =
    let srcSP = srcTag.StackOffset
    let delta = usrCtx.GetStackPointerDelta(state, srcV)
    let dstSP = srcSP + delta
    let srcConditions = srcTag.Conditions
    let dstConditions = Option.defaultValue srcConditions maybeDstConditions
    Some { StackOffset = dstSP; Conditions = dstConditions }

  /// The successor's incoming stack offset is the outgoing stack offset of the
  /// current vertex. We do lightweight stack pointer computation here, as we
  /// might have not yet propagated stack pointers. Plus, we do selectively
  /// path-sensitive analysis only for specific conditions such as calls and
  /// invariant checks, and this is for avoiding infeasible paths introduced
  /// by the try-catch mechanism in EVM.
  let getSuccessorExecutionContext (ctx: CFGBuildingContext<_, _>) srcV exeCtx
                                   _dstV (kind: CFGEdgeKind) =
    let usrCtx = ctx.UserContext :> EVMFuncUserContext
    let state = usrCtx.CP.State
    if (not << isConditionalEdge) kind then
      makeExeCtx usrCtx state srcV exeCtx None
    else
      let lastSStmt = state.GetSSAStmts(srcV, exeCtx) |> Array.last
      match computeCondition state kind lastSStmt with
      | None -> makeExeCtx usrCtx state srcV exeCtx None
      | Some(var, b) ->
        let defSvp = state.SSAVarToDefSVP var
        let defPP = defSvp.SensitiveProgramPoint.ProgramPoint
        let key = defPP
        let prevConditions = exeCtx.Conditions
        let nextConditions =
          match Map.tryFind key prevConditions with
          | None -> Some <| Map.add key b prevConditions
          | Some prevB when prevB = b -> Some prevConditions
          | _ -> None (* Detected inconsistency *)
        match nextConditions with
        | None -> None
        | Some conds -> makeExeCtx usrCtx state srcV exeCtx (Some conds)

  /// If a vertex was not analyzed yet due to incomplete CFG traversal, we
  /// postpone its analysis to the next time when the vertex is visited in the
  /// data-flow analysis.
  let postponeVertexAnalysis ctx (v: IVertex<LowUIRBasicBlock>) =
    let userCtx = ctx.UserContext :> EVMFuncUserContext
    if userCtx.PostponedVertices.Contains v then ()
    else
      let pp = v.VData.Internals.PPoint
      let act = ResumeAnalysis(pp, ExpandCFG [ pp ])
      userCtx.PostponedVertices.Add v |> ignore
      CFGRecovery.pushAction ctx act

  let connectEdgeAndPushPP ctx cfgRec (ppQueue: Queue<_>) srcV dstV kind =
    CFGRecovery.connectEdge ctx cfgRec srcV dstV kind
    ppQueue.Enqueue dstV.VData.Internals.PPoint

  let handleJmpWithBV ctx cfgRec state ppQueue srcVertex dstBv edgeKind =
    let dstAddr = BitVector.ToUInt64 dstBv
    match ctx.ManagerChannel.GetBuildingContext dstAddr with
    | FailedBuilding -> (* Ignore when the target is not a function. *)
      let dstV = scanAndGetVertex ctx cfgRec dstAddr
      connectEdgeAndPushPP ctx cfgRec ppQueue srcVertex dstV edgeKind
      let preds = ctx.CFG.GetPreds dstV
      let hasMultiplePreds = Seq.length preds > 1
      if not hasMultiplePreds then None
      else (* Check if this edge insertion introduces poly jumps *)
        let polyJumps = collectPolyJumpsFromReachables ctx.CFG state dstV
        let hasPolyJumps = not <| Seq.isEmpty polyJumps
        if hasPolyJumps then handlePolyJumps ctx state polyJumps else None
    | bldCtx -> (* Okay, this is a function, so we connect to the function. *)
      let srcBlk = srcVertex.VData.Internals
      let callSite = fromBBLToCallSite srcBlk
      let calleeInfo = makeCalleeInfoFromBuildingContext bldCtx
      let act = MakeCall(callSite, dstAddr, calleeInfo)
      Some <| CFGRecovery.handleCall ctx cfgRec srcVertex callSite dstAddr act

  let handleDirectJmpWithVars ctx cfgRec state ppQueue srcVertex dstVars edge =
    match SensitiveDFHelper.constantFoldSSAVars state dstVars with
    | ConstantDomain.Const dstBv ->
      handleJmpWithBV ctx cfgRec state ppQueue srcVertex dstBv edge
    | _ -> Terminator.futureFeature () (* Function pointers not supported. *)

  let handleInterJmp ctx cfgRec queue v =
    let state = computeCPState ctx
    let needsPostpone = not <| isExecuted state v
    if needsPostpone then (* Can happen with infeasible path conditions. *)
      (* Resume its analysis when data-flow analysis propagates information to
         it later. *)
      postponeVertexAnalysis ctx v
      Some MoveOn
    else
      match SensitiveDFHelper.tryOverApproximateTerminator state v with
      | Some(SSA.Jmp(SSA.InterJmp dstExpr)) ->
        if v.VData.Internals.PPoint.Address = 0x2fa5UL then ()
        let rdVars = findRootVarsFromExpr state dstExpr
        let incomingVars = List.filter isFakeVar rdVars
        let usesIncomingVars = not <| List.isEmpty incomingVars
        (* Check if this returns from the **current** function. *)
        if usesIncomingVars then analyzeReturnInfo ctx state v incomingVars
        elif v.VData.Internals.IsAbstract then
          let hasMultipleRdVars = (List.distinct >> List.length) rdVars > 1
          if hasMultipleRdVars then (* Highly likely a shared region. *)
            findAndIntroduceSharedRegion ctx state v rdVars
            Some StopAndReload
          else
            handleDirectJmpWithVars ctx cfgRec state queue v rdVars InterJmpEdge
        else
          let rds = List.map (getDefSiteVertex state) rdVars
          let possiblyReturnEdge = Seq.exists (fun d -> d <> v) rds
          if possiblyReturnEdge then findAndIntroduceFunction ctx v rds
          else
            handleDirectJmpWithVars ctx cfgRec state queue v rdVars InterJmpEdge
      | Some(SSA.SideEffect Terminate) -> None (* No return! *)
      | _ -> Terminator.impossible ()

  let tryJoinMaybeCFGResults r1 r2 =
    match r1, r2 with
    | None, _ -> r2
    | _, None -> r1
    | Some x1, Some x2 ->
      match x1, x2 with
      (* FailStop is stronger than any other CFGResults. *)
      | FailStop _, _ -> r1
      | _, FailStop _ -> r2
      (* StopAndReload is the next. *)
      | StopAndReload, _
      | _, StopAndReload -> Some StopAndReload
      | MoveOn, _ -> r2
      | _, MoveOn -> r1
      | _ -> None

  let handleInterCJmp ctx cfgRec q v =
    let state = computeCPState ctx
    match SensitiveDFHelper.tryOverApproximateTerminator state v with
    | Some(SSA.Jmp(SSA.InterCJmp(cond, dstExpr, SSA.Num fBv))) ->
      let dstVarList = extractVarsFromExpr dstExpr
      match SensitiveDFHelper.constantFoldSSAVars state dstVarList with
      | ConstantDomain.Const tBv ->
        let isEntryFunction = ctx.FunctionAddress = 0x0UL
        if isEntryFunction && tryDetectPubFunc ctx state cond then
          let tJmpAddr = BitVector.ToUInt64 tBv
          let fJmpAddr = BitVector.ToUInt64 fBv
          let fJmpV = scanAndGetVertex ctx cfgRec fJmpAddr
          let callee = tJmpAddr
          let cs = fromBBLToCallSite v.VData
          let act = MakeCall(cs, callee, (NoRet, 0)) (* treat as NoRet *)
          let ret = CFGRecovery.handleCall ctx cfgRec v cs callee act
          match getFunctionUserContext ctx callee with
          | Ok userCtx ->
            userCtx.SetSharedRegion()
            connectEdgeAndPushPP ctx cfgRec q v fJmpV InterCJmpFalseEdge
            Some ret
          | Error errorCase -> Some <| FailStop errorCase
        else
          (* Consider control-flows into shared regions even for the branches.
             See 0x5283fc3a1aac4dac6b9581d3ab65f4ee2f3de7dc:
             0x1ffd conditionally jumps into 0x0e95, and 0x0e95 has a
             self-loop, which should be treated as a shared region. *)
          let r1 = handleJmpWithBV ctx cfgRec state q v tBv InterCJmpTrueEdge
          let r2 = handleJmpWithBV ctx cfgRec state q v fBv InterCJmpFalseEdge
          tryJoinMaybeCFGResults r1 r2
      | _ -> Terminator.futureFeature ()
    | _ -> Terminator.impossible ()

  /// We need to use UserContext of the callee function, so we need to directly
  /// access the callee context instead of using the abstraction.
  /// TODO: What if the callee has been reset? Timing issue here?
  let connectAbsVertex ctx cfgRec caller callee callsite isTail calleeInfo
                       calleeCtx =
    let abs = summarize calleeCtx calleeInfo
    let calleeOpt = Some callee
    let callee = CFGRecovery.getAbsVertex ctx cfgRec callsite calleeOpt abs
    let edgeKind = if isTail then TailCallEdge else CallEdge
    CFGRecovery.connectEdge ctx cfgRec caller callee edgeKind
    callee

  let connectCall ctx cfgRec caller callee cs info =
    getFunctionContext ctx callee
    |> Result.map (connectAbsVertex ctx cfgRec caller callee cs false info)
    |> CFGRecovery.toCFGResult

  let handleCall ctx cfgRec cs callee calleeInfo =
    let caller = ctx.CallerVertices[cs]
    let callsite = fromBBLToCallSite caller.VData.Internals
    let absPp = ProgramPoint(callsite, callee, 0)
    let act = ExpandCFG [ absPp ]
    CFGRecovery.pushAction ctx act
    connectCall ctx cfgRec caller callee cs calleeInfo

type EVMCFGRecovery() as this =
  let syscallAnalysis = SyscallAnalysis()
  let jmptblAnalysis = JmpTableAnalysis None

  interface ICFGRecovery<EVMFuncUserContext, DummyContext> with
    member _.Summarizer = summarizer

    member _.ActionPrioritizer = CFGRecovery.prioritizer

    member _.AllowBBLOverlap = false

    member _.FindCandidates _ = [| 0x0UL |]

    member _.OnAction(ctx, queue, action) =
      CFGRecovery.onAction ctx this queue syscallAnalysis jmptblAnalysis false
                           action

    member _.OnCyclicDependency(builders) =
      CFGRecovery.onCyclicDependency builders

    member _.OnCreate ctx =
      let scheme =
        { new IScheme<ConstantDomain.Lattice, EVMExeCtx> with
            member _.DefaultExecutionContext =
              { StackOffset = 0; Conditions = Map.empty }
            member _.OnRemoveVertex v =
              let usrCtx = ctx.UserContext
              usrCtx.PostponedVertices.Remove v |> ignore
              usrCtx.ResumableVertices.Remove v |> ignore
              usrCtx.PerVertexStackPointerDelta.Remove v |> ignore
            member _.OnVertexNewlyAnalyzed v =
              let usrCtx = ctx.UserContext
              if not <| usrCtx.PostponedVertices.Remove v then ()
              else usrCtx.ResumableVertices.Add v |> ignore
            member _.TryComputeExecutionContext(src, srcExeCtx, dst, edgeKind) =
              getSuccessorExecutionContext ctx src srcExeCtx dst edgeKind }
      let cp = LowUIRSensitiveConstantPropagation(ctx.BinHandle, scheme)
      ctx.UserContext.CP <- cp

    member _.OnFinish ctx =
      let fnUserCtx = ctx.UserContext
      assert Seq.isEmpty fnUserCtx.ResumableVertices
      let status, unwinding =
        match fnUserCtx.StackPointerDiff with
        | Some diff -> NotNoRet, int diff
        | None -> NoRet, 0
      ctx.NonReturningStatus <- status
      ctx.UnwindingBytes <- unwinding
      MoveOn

    member _.AnalyzeIndirectJump(ctx, ppQueue, _pp, srcVertex) =
      let state = computeCPState ctx
      let needsPostpone = not <| isExecuted state srcVertex
      if needsPostpone then (* Can happen with infeasible path conditions. *)
        (* Resume its analysis when data-flow analysis propagates information to
           it later. *)
        postponeVertexAnalysis ctx srcVertex
        Some MoveOn
      else handleInterJmp ctx this ppQueue srcVertex

    member _.AnalyzeIndirectCondJump(ctx, ppQueue, _pp, srcVertex) =
      let state = computeCPState ctx
      let needsPostpone = not <| isExecuted state srcVertex
      if needsPostpone then (* Can happen with infeasible path conditions. *)
        (* Resume its analysis when data-flow analysis propagates information to
           it later. *)
        postponeVertexAnalysis ctx srcVertex
        Some MoveOn
      else handleInterCJmp ctx this ppQueue srcVertex

    member _.AnalyzeCall(ctx, cs, callee, calleeInfo, _) =
      handleCall ctx this cs callee calleeInfo

    member _.ResumeAnalysis(ctx, pp, callbackAction) =
      let userCtx = ctx.UserContext
      match ctx.Vertices.TryGetValue pp with
      | false, _ -> Terminator.impossible ()
      | true, v when userCtx.ResumableVertices.Remove v ->
        CFGRecovery.pushAction ctx callbackAction
        MoveOn
      | true, v -> (* Needs more time :p *)
        assert userCtx.PostponedVertices.Contains v
        let isStalled = ctx.ActionQueue.IsEmpty()
        if isStalled then (* Ignore that block, as it is a dead code. *)
          MoveOn
        else (* Busy waiting. *)
          CFGRecovery.pushAction ctx (ResumeAnalysis(pp, callbackAction))
          MoveOn

    member _.OnAddVertex(ctx, v) =
      let vData = v.VData.Internals
      let isAbstract = vData.IsAbstract
      let hasEntryPointAddr = vData.PPoint.Address = ctx.FunctionAddress
      let isEntryPoint = not isAbstract && hasEntryPointAddr
      let cp = ctx.UserContext.CP
      if isEntryPoint then cp.MarkEdgeAsPending(null, v)

    member _.OnAddEdge(ctx, srcV, dstV, _kind) =
      ctx.UserContext.CP.State.MarkEdgeAsPending(srcV, dstV)

    member _.OnRemoveVertex(ctx, v) =
      ctx.UserContext.CP.State.MarkVertexAsRemoval v |> ignore
