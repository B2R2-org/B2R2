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
open B2R2.MiddleEnd.DataFlow.SensitiveDFHelper

[<AutoOpen>]
module private EVMCFGRecovery =
  let UseCallFallthroughHeuristic = true

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

  let fourBytesBitmaskBv = BitVector(UInt32.MaxValue, 256<rt>)

  let isPossiblyFuncSig (bv: BitVector) =
    bv &&& fourBytesBitmaskBv = bv

  let isMsgDataDivision = function
    | SSA.BinOp(BinOpType.DIV, _,
                SSA.BinOp(BinOpType.APP, _, SSA.FuncName "msg.data", _),
                SSA.Num _disivorBv)
    | SSA.BinOp(BinOpType.DIV, _,
                SSA.Num _disivorBv,
                SSA.BinOp(BinOpType.APP, _, SSA.FuncName "msg.data", _))
      -> true
    | SSA.BinOp(BinOpType.DIV, _,
                SSA.BinOp (BinOpType.APP, _, SSA.FuncName "msg.data", _),
                SSA.BinOp (BinOpType.APP, _, SSA.FuncName "exp",
                           SSA.ExprList [ SSA.Num bv_0x2; SSA.Num bv_0xe0 ]))
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
    match cond with
    | SSA.ExprList exprs -> exprs |> List.exists (tryDetectPubFunc ctx state)
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
    match tryOverApproximateTerminator state v with
    | Some(SSA.Jmp(SSA.InterJmp dst)) -> Some dst
    | _ -> None

  let getOverApproximatedJumpDstExprOfJmp (state: State<_, _>) v =
    tryGetOverApproximatedJumpDstExprOfJmp state v
    |> Option.get

  let isFallthroughNode v =
    not (v: IVertex<LowUIRBasicBlock>).VData.Internals.IsAbstract
    && not v.VData.Internals.LastInstruction.IsBranch

  let hasMultipleDefSites (state: State<_, _>) vars =
    vars
    |> Seq.distinctBy (fun var ->
      let svp = state.SSAVarToDefSVP var
      let spp = svp.SensitiveProgramPoint
      spp.ProgramPoint)
    |> Seq.length > 1

  let hasPolyJumpTarget (state: State<_, _>) v =
    if isFallthroughNode v then false
    else
      match tryGetOverApproximatedJumpDstExprOfJmp state v with
      | None -> false
      | Some e ->
        e
        |> findRootVarsFromExpr state
        |> hasMultipleDefSites state

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

  let UsesOptimizedReload = true

  let removeReachableVertices ctx cfgRec root =
    let removals = HashSet ()
    let possiblyIncomings = HashSet ()
    let rec removeReachables (vs: IVertex<LowUIRBasicBlock> list) =
      match vs with
      | [] -> ()
      | v :: vs when removals.Add v |> not -> removeReachables vs
      | v :: vs ->
        let pp = v.VData.Internals.PPoint
        let preds = ctx.CFG.GetPreds v
        let succs = ctx.CFG.GetSuccs v
        CFGRecovery.tryRemoveVertexAt ctx cfgRec pp |> ignore
        preds |> Array.iter (possiblyIncomings.Add >> ignore)
        succs |> Array.toList |> List.append vs |> removeReachables
    removeReachables root
    possiblyIncomings.ExceptWith removals
    possiblyIncomings

  let reanalyzeVertex (ctx: CFGBuildingContext<_, _>) srcV =
    let srcPP = (srcV: IVertex<LowUIRBasicBlock>).VData.Internals.PPoint
    ctx.VisitedPPoints.Remove srcPP |> ignore
    CFGRecovery.pushAction ctx <| ExpandCFG [ srcPP ]

  let removeAndReanalyze ctx cfgRec srcV newEP =
    let ppoint = ProgramPoint (newEP, 0)
    match ctx.Vertices.TryGetValue ppoint with
    | false, _ -> reanalyzeVertex ctx srcV
    | true, ep ->
      removeReachableVertices ctx cfgRec [ ep ]
      |> Seq.iter (reanalyzeVertex ctx)

  let introduceNewSharedRegion (ctx: CFGBuildingContext<_, _>) cfgRec srcV ep =
    assert (ep <> ctx.FunctionAddress)
    ctx.ManagerChannel.StartBuilding ep
    getFunctionUserContext ctx ep
    |> Result.iter (fun userCtx -> userCtx.SetSharedRegion ())
    if not UsesOptimizedReload then Some StopAndReload
    else removeAndReanalyze ctx cfgRec srcV ep; None

  let findAndIntroduceSharedRegion ctx cfgRec state v rdVars =
    assert (not <| Seq.isEmpty rdVars)
    let g = ctx.CFG
    let defVertices = Seq.map (getDefSiteVertex g state) rdVars
    let pathes = Seq.map (fun d -> findFeasiblePath g d v) defVertices
    let firstPath, restPathes = Seq.head pathes, Seq.tail pathes
    let intersetedPath = Seq.fold intersectPathes firstPath restPathes
    let regionEntry = Seq.head intersetedPath
    let regionEntryAddr = regionEntry.VData.Internals.PPoint.Address
    if ctx.FunctionAddress = regionEntryAddr then
      None
    else
      assert (not regionEntry.VData.Internals.IsAbstract)
      (* This should reset the current analysis. *)
      introduceNewSharedRegion ctx cfgRec null regionEntryAddr

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

  let handlePolyJumps (ctx: CFGBuildingContext<_, _>) cfgRec state polyJumps =
    assert (not <| Seq.isEmpty polyJumps)
    let mutable r = None
    for polyJmpV in polyJumps do
      getOverApproximatedJumpDstExprOfJmp state polyJmpV
      |> findRootVarsFromExpr state
      |> findAndIntroduceSharedRegion ctx cfgRec state polyJmpV
      |> fun res -> r <- tryJoinMaybeCFGResults r res
    r

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

  let introduceNewFunction (ctx: CFGBuildingContext<_, _>) cfgRec srcV newEP =
    assert (newEP <> ctx.FunctionAddress)
    ctx.ManagerChannel.StartBuilding newEP
    if not UsesOptimizedReload then Some StopAndReload
    else removeAndReanalyze ctx cfgRec srcV newEP; None

  let isInfeasibleEntryPoint (ctx: CFGBuildingContext<_, _>) v =
    let g = ctx.CFG
    let preds = g.GetPreds v
    preds |> Array.exists (fun pred ->
      not pred.VData.Internals.IsAbstract
      && pred.VData.Internals.LastInstruction.IsCondBranch)

  let isFallthroughedNode (ctx: CFGBuildingContext<_, _>) v =
    let g = ctx.CFG
    let preds = g.GetPreds v
    Array.exists isFallthroughNode preds

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
    | SSA.Num bv when bv.IsOne -> Some(recentVar, true, true)
    | SSA.ExprList exprs -> (* TODO: tail-recursion w/ continuation *)
      exprs |> List.tryPick (fun e ->
        let var = exprToVar e
        match state.TryFindSSADefStmtFromSSAVar var with
        | Some(SSA.Def(_, e)) -> tryExtractPathCondition state var e
        | _ -> None)
    | SSA.BinOp(BinOpType.APP, _, SSA.FuncName callName, _)
      when isCallRelatedFunction callName ->
      Some(recentVar, true, false)
    | SSA.Cast(_, _, SSA.RelOp(RelOpType.EQ, _, e, SSA.Num bv_0x0))
      when bv_0x0.IsZero ->
      match tryExtractPathCondition state recentVar e with
      | Some(d, b, isConstant) -> Some(d, not b, isConstant) (* Negation. *)
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
    | _ -> Terminator.impossible ()

  let hasNoFixpoint ctx srcV exeCtx dstV =
    let usrCtx = ctx.UserContext :> EVMFuncUserContext
    let backEdges = usrCtx.BackEdges
    let currSrcDstPair = srcV, dstV
    let state = usrCtx.CP.State
    if not <| backEdges.Contains currSrcDstPair then false
    elif not <| state.PerVertexPossibleExeCtxs.ContainsKey dstV then false
    else
      let delta = usrCtx.GetStackPointerDelta usrCtx.CP.State srcV
      let srcOutSP = exeCtx.StackOffset + delta
      let dstExeCtxs = state.PerVertexPossibleExeCtxs[dstV]
      let dstSPs = Seq.map (fun t -> t.StackOffset) dstExeCtxs
      if Seq.contains srcOutSP dstSPs then
        false
      else
        true

  let MaxExecutionContextsPerVertex = 8

  let tooManyContexts (usrCtx: EVMFuncUserContext) dstV dstExeCtx =
    let state = usrCtx.CP.State
    match state.PerVertexPossibleExeCtxs.TryGetValue dstV with
    | true, dstPossibleExeCtxs when dstPossibleExeCtxs.Contains dstExeCtx ->
      false
    | true, dstPossibleExeCtxs
      when dstPossibleExeCtxs.Count >= MaxExecutionContextsPerVertex ->
      true
    | _ ->
      false

  let makeExeCtx (usrCtx: EVMFuncUserContext) state srcV srcTag
                  maybeDstConditions =
    let srcSP = srcTag.StackOffset
    let delta = usrCtx.GetStackPointerDelta(state, srcV)
    let dstSP = srcSP + delta
    let srcConditions = srcTag.Conditions
    let dstConditions = Option.defaultValue srcConditions maybeDstConditions
    { StackOffset = dstSP; Conditions = dstConditions }

  let tryMakeExeCtx (usrCtx: EVMFuncUserContext) state srcV srcTag
                  maybeDstConditions =
    let dstExeCtx = makeExeCtx usrCtx state srcV srcTag maybeDstConditions
    if tooManyContexts usrCtx srcV dstExeCtx then None
    else Some dstExeCtx

  /// The successor's incoming stack offset is the outgoing stack offset of the
  /// current vertex. We do lightweight stack pointer computation here, as we
  /// might have not yet propagated stack pointers. Plus, we do selectively
  /// path-sensitive analysis only for specific conditions such as calls and
  /// invariant checks, and this is for avoiding infeasible paths introduced
  /// by the try-catch mechanism in EVM.
  let getSuccessorExecutionContext (ctx: CFGBuildingContext<_, _>) srcV exeCtx
                                   dstV (kind: CFGEdgeKind) =
    let usrCtx = ctx.UserContext :> EVMFuncUserContext
    let state = usrCtx.CP.State
    if hasNoFixpoint ctx srcV exeCtx dstV then
      None
    elif (not << isConditionalEdge) kind || isFallthroughNode srcV then
      tryMakeExeCtx usrCtx state srcV exeCtx None
    else
      let lastSStmt = state.GetSSAStmts(srcV, exeCtx) |> Array.last
      match computeCondition state kind lastSStmt with
      | None -> tryMakeExeCtx usrCtx state srcV exeCtx None
      | Some(_var, b, true)
        when b && kind.IsInterCJmpFalseEdge
          || not b && kind.IsInterCJmpTrueEdge -> (* Infeasible path. *)
        None
      | Some(var, b, _isConstant) ->
        let b = if kind.IsInterCJmpFalseEdge then not b else b
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
        | Some conds -> tryMakeExeCtx usrCtx state srcV exeCtx (Some conds)

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

  let reconnectVertices ctx (cfgRec: ICFGRecovery<_, _>)
                        (dividedEdges: List<ProgramPoint * ProgramPoint>) =
    for (srcPPoint, dstPPoint) in dividedEdges do
      let preds, succs = CFGRecovery.tryRemoveVertexAt ctx cfgRec srcPPoint
      if Array.isEmpty preds && Array.isEmpty succs then
        (* Don't reconnect previously unseen blocks, which can be introduced by
           tail-calls. N.B. BBLFactory cannot see tail-calls. *)
        ()
      else
        let srcVertex = scanAndGetVertex ctx cfgRec srcPPoint.Address
        let dstVertex = scanAndGetVertex ctx cfgRec dstPPoint.Address
#if CFGDEBUG
        dbglog ctx.ThreadID "Reconnect" $"{srcPPoint} -> {dstPPoint}"
#endif
        let lastAddr = dstVertex.VData.Internals.LastInstruction.Address
        let callsite = LeafCallSite lastAddr
        if not <| ctx.CallerVertices.ContainsKey callsite then ()
        else ctx.CallerVertices[callsite] <- dstVertex
        CFGRecovery.connectEdge ctx cfgRec srcVertex dstVertex FallThroughEdge
        for e in preds do
          CFGRecovery.connectEdge ctx cfgRec e.First srcVertex e.Label
        for e in succs do
          if e.Second.VData.Internals.PPoint = srcPPoint then
            CFGRecovery.connectEdge ctx cfgRec dstVertex srcVertex e.Label
          else
            CFGRecovery.connectEdge ctx cfgRec dstVertex e.Second e.Label

  let scanBBLsAndConnect ctx cfgRec src dstAddr edgeKind =
    match CFGRecovery.scanBBLs ctx [ dstAddr ] with
    | Ok dividedEdges ->
      let dstPPoint = ProgramPoint (dstAddr, 0)
      let v = scanAndGetVertex ctx cfgRec dstAddr
      CFGRecovery.connectEdge ctx cfgRec src v edgeKind
      reconnectVertices ctx cfgRec dividedEdges
      CFGRecovery.addExpandCFGAction ctx dstPPoint
    | Error e -> Error e

  let getFallthroughAddress (srcV: IVertex<LowUIRBasicBlock>) =
    let bbl = srcV.VData.Internals
    let lastIns = bbl.LastInstruction
    lastIns.Address + uint64 lastIns.Length

  let hasCallFallthroughAddress (ctx: CFGBuildingContext<_, _>) srcV =
    let userCtx = ctx.UserContext :> EVMFuncUserContext
    let fallthroughAddr = getFallthroughAddress srcV
    let fallthroughBV = BitVector.OfUInt64 fallthroughAddr 256<rt>
    let state = userCtx.CP.State
    let maximumStackOff = -32
    let minimumStackOff = findLatestStackOffset ctx state srcV
    let possibleStackOffs = [ minimumStackOff .. 0x20 .. maximumStackOff ]
    let exeCtxs = state.PerVertexPossibleExeCtxs[srcV]
    exeCtxs
    |> Seq.exists (fun exeCtx ->
      let outDefs = state.PerVertexOutgoingDefs[srcV, exeCtx]
      possibleStackOffs
      |> List.exists (fun stackOff ->
        let vk = StackLocal stackOff
        match Map.tryFind vk outDefs with
        | None -> false
        | Some defs ->
          defs
          |> Set.exists (fun defSvp ->
            match state.DomainSubState.GetAbsValue defSvp with
            | ConstantDomain.Const bv when bv = fallthroughBV ->
              true
            | _ ->
              false)))

  /// Handles a jump with a bitvector, which is the target address of the jump.
  let handleJmpWithBV ctx cfgRec srcV dstBv edgeKind =
    let dstAddr = BitVector.ToUInt64 dstBv
    match ctx.ManagerChannel.GetBuildingContext dstAddr with
    | FailedBuilding -> (* Ignore when the target is not a function. *)
      if UseCallFallthroughHeuristic
         && edgeKind = InterJmpEdge
         && not (srcV: IVertex<LowUIRBasicBlock>).VData.Internals.IsAbstract
         (* 0x2bb @ 0x003249c0beadbcf04c65bb0a392b810c23ffdc8b *)
         && getFallthroughAddress srcV <> dstAddr
         && hasCallFallthroughAddress ctx srcV then
        (* Check if the current stack frame contains the fallthrough node's
           address. This is for (1) introducing more functions early to maximize
           parallelism, and (2) detecting non-returning functions. *)
        introduceNewFunction ctx cfgRec srcV dstAddr
      else
        match scanBBLsAndConnect ctx cfgRec srcV dstAddr edgeKind with
        | Ok () ->
          let state = computeCPState ctx (* Recalculate the reaching defs. *)
          let dstV = scanAndGetVertex ctx cfgRec dstAddr
          let preds = ctx.CFG.GetPreds dstV
          let hasMultiplePreds = Seq.length preds > 1
          if not hasMultiplePreds then None
          (* [14e3,155f] -> 1382 @ 0x00000000000000343662d3fad10d154530c0d4f1 *)
          elif preds
               |> Array.filter (fun p -> p.VData.Internals.IsAbstract)
               |> Array.length > 1 then
            introduceNewSharedRegion ctx cfgRec srcV dstAddr
          else (* Check if this edge insertion introduces poly jumps *)
            let polyJumps = collectPolyJumpsFromReachables ctx.CFG state dstV
            let hasPolyJumps = not <| Seq.isEmpty polyJumps
            if hasPolyJumps then
              handlePolyJumps ctx cfgRec state polyJumps
            else
              None
        | Error errorCase -> Some <| FailStop errorCase
    | bldCtx -> (* Okay, this is a function, so we connect to the function. *)
      let srcBlk = srcV.VData.Internals
      let callSite = fromBBLToCallSite srcBlk
      let calleeInfo = makeCalleeInfoFromBuildingContext bldCtx
      let act = MakeCall(callSite, dstAddr, calleeInfo)
      Some <| CFGRecovery.handleCall ctx cfgRec srcV callSite dstAddr act

  let handleDirectJmpWithVars ctx cfgRec state srcV dstVars edge =
    match constantFoldSSAVars state dstVars with
    | ConstantDomain.Const dstBv -> handleJmpWithBV ctx cfgRec srcV dstBv edge
    | _ -> None (* Function pointers not supported:
                   0x000000000000cca70b6e0997a94681a3114eddd7 *)

  let findAndIntroduceFunction ctx cfgRec srcV rds rdVars =
    let sampledDefSite = Seq.head rds
    let sampledPath = findFeasiblePath ctx.CFG sampledDefSite srcV
    let newEntryPoint = findFunctionEntry sampledPath
    let newEntryPointAddr = newEntryPoint.VData.Internals.PPoint.Address
    let hasAbstractPred =
      ctx.CFG.GetPreds srcV
      |> Array.exists (fun pred -> pred.VData.Internals.IsAbstract)
    if newEntryPointAddr = 0x9acUL then ()
    if isInfeasibleEntryPoint ctx newEntryPoint || hasAbstractPred then
      introduceNewSharedRegion ctx cfgRec srcV newEntryPointAddr
    (* 0x00000000000006c7676171937c444f6bde3d6282: 0x3e6a *)
    elif isFallthroughedNode ctx newEntryPoint then (* cannot be an EP *)
      let state = ctx.UserContext.CP.State
      handleDirectJmpWithVars ctx cfgRec state srcV rdVars InterJmpEdge
    else
      introduceNewFunction ctx cfgRec srcV newEntryPointAddr

  let handleInterJmp ctx cfgRec v =
    let state = computeCPState ctx
    match tryOverApproximateTerminator state v with
    | Some(SSA.Jmp(SSA.InterJmp dstExpr)) ->
      let rdVars = findRootVarsFromExpr state dstExpr
      let incomingVars = List.filter isFakeVar rdVars
      let usesIncomingVars = not <| List.isEmpty incomingVars
      (* Check if this returns from the **current** function. *)
      if usesIncomingVars then analyzeReturnInfo ctx state v incomingVars
      elif v.VData.Internals.IsAbstract then
        let hasMultipleRdVars = hasMultipleDefSites state rdVars
        if hasMultipleRdVars then (* Highly likely a shared region. *)
          findAndIntroduceSharedRegion ctx cfgRec state v rdVars
        else
            handleDirectJmpWithVars ctx cfgRec state v rdVars InterJmpEdge
      else
        let g = ctx.CFG
        let rds = List.map (getDefSiteVertex g state) rdVars
        let possiblyReturnEdge = Seq.exists (fun d -> d <> v) rds
        if possiblyReturnEdge then
          findAndIntroduceFunction ctx cfgRec v rds rdVars
        else
          handleDirectJmpWithVars ctx cfgRec state v rdVars InterJmpEdge
    | Some(SSA.SideEffect Terminate) -> None (* No return! *)
    | _ -> Terminator.impossible ()

  let handleInterCJmp ctx cfgRec v =
    let state = computeCPState ctx
    match tryOverApproximateTerminator state v with
    | Some(SSA.Jmp(SSA.InterCJmp(cond, dstExpr, SSA.Num fBv))) ->
      let dstVarList = extractVarsFromExpr dstExpr
      match constantFoldSSAVars state dstVarList with
      | ConstantDomain.Const tBv ->
        let isEntryFunction = ctx.FunctionAddress = 0x0UL
        let cond = expandExpr state cond
        if isEntryFunction && tryDetectPubFunc ctx state cond then
          let tJmpAddr = BitVector.ToUInt64 tBv
          let fJmpAddr = BitVector.ToUInt64 fBv
          match scanBBLsAndConnect ctx cfgRec v fJmpAddr InterCJmpFalseEdge with
          | Ok() ->
            let callee = tJmpAddr
            let cs = fromBBLToCallSite v.VData
            let act = MakeCall(cs, callee, (NoRet, 0)) (* treat as NoRet *)
            let ret = CFGRecovery.handleCall ctx cfgRec v cs callee act
            match getFunctionUserContext ctx callee with
            | Ok userCtx ->
              userCtx.SetPublicFunction()
              Some ret
            | Error errorCase -> Some <| FailStop errorCase
          | Error errorCase -> Some <| FailStop errorCase
        else
          (* Consider control-flows into shared regions even for the branches.
             See 0x5283fc3a1aac4dac6b9581d3ab65f4ee2f3de7dc:
             0x1ffd conditionally jumps into 0x0e95, and 0x0e95 has a
             self-loop, which should be treated as a shared region. *)
          let r1 = handleJmpWithBV ctx cfgRec v tBv InterCJmpTrueEdge
          (* 0x5283fc3a1aac4dac6b9581d3ab65f4ee2f3de7dc: a BBL at 0x6fd jumps to
             0x70b, which splits itself into two blocks, and this removes the
             previous vertex at 0x6fd. So, we need to fetch the vertex again by
             using the address of the BBL. *)
          let v = scanAndGetVertex ctx cfgRec v.VData.Internals.PPoint.Address
          let r2 = handleJmpWithBV ctx cfgRec v fBv InterCJmpFalseEdge
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

  let private hasFinalContext ctx addr =
    match ctx.ManagerChannel.GetBuildingContext addr with
    | FinalCtx _ -> true
    | _ -> false

  let connectCall ctx cfgRec caller callee cs info =
    assert (if ctx.FunctionAddress = callee then true
            else hasFinalContext ctx callee)
    getFunctionContext ctx callee
    |> Result.map (connectAbsVertex ctx cfgRec caller callee cs false info)
    |> CFGRecovery.toCFGResult

  let handleCall ctx cfgRec cs callee calleeInfo =
    let caller = ctx.CallerVertices[cs]
    let callsite = fromBBLToCallSite caller.VData.Internals
    let absPp = ProgramPoint(callsite, callee, 0)
    let act = ExpandCFG [ absPp ]
    CFGRecovery.pushAction ctx act
    if not <| ctx.CFG.HasVertex caller.ID then MoveOn
    else connectCall ctx cfgRec caller callee cs calleeInfo

  /// Postpone the analysis of the source vertex if it was not executed in the
  /// data-flow analysis, and run the given function if it was executed.
  let postponeOrGo ctx srcVertex fn =
    let state = computeCPState ctx
    let needsPostpone = not <| isExecuted state srcVertex
    if needsPostpone then (* Can happen with infeasible path conditions. *)
      (* Resume its analysis when data-flow analysis propagates information to
         it later. *)
      postponeVertexAnalysis ctx srcVertex
      Some MoveOn
    else fn ()

  let findBackEdges (backEdges: HashSet<_>) (g: IDiGraph<_, _>) =
    let seen = HashSet()
    let onStack = Dictionary()
    let rec dfs u =
      seen.Add u |> ignore
      onStack[u] <- true
      for v in g.GetSuccs u do
        if not <| seen.Contains v then dfs v
        elif onStack.ContainsKey v && onStack[v] then
          backEdges.Add(u, v) |> ignore
      onStack[u] <- false
    for v in g.Vertices do
      if not <| seen.Contains v then dfs v

  /// Update the back-edges of the current function.
  /// TODO: We can use the dynamic DFS algorithm by Yang et al. (VLDB '19).
  let updateBackEdges ctx _srcV _dstV =
    let usrCtx = ctx.UserContext :> EVMFuncUserContext
    let backEdges = usrCtx.BackEdges
    backEdges.Clear()
    findBackEdges backEdges ctx.CFG

  /// Traverses the graph `g` starting from the vertex `v`, and mark vertices
  /// as removal, as every vertex affected by the removal of `v` should be
  /// marked as removal.
  let rec traverseForRemovalMark visited g pendingFn removalFn worklist =
    match worklist with
    | [] -> ()
    | v :: rest ->
      (visited: HashSet<_>).Add v |> ignore
      for pred in (g: IDiGraph<_, _>).GetPreds v do (* For recalculation. *)
        pendingFn pred v
      if v = g.SingleRoot then
        pendingFn null v
      if not <| removalFn v then
        traverseForRemovalMark visited g pendingFn removalFn rest
      else
        let succs = (g: IDiGraph<_, _>).GetSuccs v
        let succs = succs |> Array.filter (not << visited.Contains)
        let rest = succs |> Array.toList |> List.append rest
        traverseForRemovalMark visited g pendingFn removalFn rest

  let beforeRemoveVertex (ctx: CFGBuildingContext<EVMFuncUserContext, _>) v =
    let g = ctx.CFG
    let visited = HashSet()
    let state = ctx.UserContext.CP.State
    let pendingFn = state.MarkEdgeAsPending
    let removalFn = state.MarkVertexAsRemoval
    traverseForRemovalMark visited g pendingFn removalFn [ v ]

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

    member _.OnCreate(ctx) =
      if isNull ctx.UserContext.CP then
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
              member _.TryComputeExecutionContext src srcExeCtx dst edgeKind =
                getSuccessorExecutionContext ctx src srcExeCtx dst edgeKind }
        let cp = LowUIRSensitiveConstantPropagation(ctx.BinHandle, scheme)
        ctx.UserContext.CP <- cp

    member _.OnFinish(ctx) =
      let fnUserCtx = ctx.UserContext
      assert Seq.isEmpty fnUserCtx.ResumableVertices
      let oldNoRetStatus = ctx.NonReturningStatus
      let newNoRetStatus, unwinding =
        match fnUserCtx.StackPointerDiff with
        | Some diff -> NotNoRet, int diff
        | None -> NoRet, 0
      ctx.NonReturningStatus <- newNoRetStatus
      ctx.UnwindingBytes <- unwinding
      match oldNoRetStatus, newNoRetStatus with
      | NoRet, NotNoRet
      | NoRet, ConditionalNoRet _ -> MoveOnButReloadCallers oldNoRetStatus
      | _ -> MoveOn

    member _.AnalyzeIndirectJump(ctx, _ppQueue, _pp, srcV) =
      postponeOrGo ctx srcV (fun () -> handleInterJmp ctx this srcV)

    member _.AnalyzeIndirectCondJump(ctx, _ppQueue, _pp, srcV) =
      postponeOrGo ctx srcV (fun () -> handleInterCJmp ctx this srcV)

    member _.AnalyzeCall(ctx, cs, callee, calleeInfo, _) =
      handleCall ctx this cs callee calleeInfo

    member _.ResumeAnalysis(ctx, pp, callbackAction) =
      let userCtx = ctx.UserContext
      match ctx.Vertices.TryGetValue pp with
      | false, _ -> MoveOn
      | true, v when userCtx.ResumableVertices.Remove v ->
        match ctx.VisitedPPoints.Remove pp with
        | true -> ()
        | false -> Terminator.impossible ()
        CFGRecovery.pushAction ctx callbackAction
        MoveOn
      | true, v when not <| userCtx.PostponedVertices.Contains v ->
        (* Ignore this block, as it might has been replaced by other blocks. *)
        (* 0x0000000000000fa82d0b7ede9c6f96571b630c13: 0x24b0 *)
        MoveOn
      | true, v -> (* Needs more time :p *)
        assert userCtx.PostponedVertices.Contains v
        let isStalled =
          let items = ctx.ActionQueue.UnorderedItems
          items
          |> Seq.filter (fun struct (a, _) -> not a.IsResumeAnalysis)
          |> Seq.isEmpty
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
      if not isEntryPoint then ()
      else ctx.UserContext.CP.State.MarkEdgeAsPending null v

    member _.OnAddEdge(ctx, srcV, dstV, _kind) =
      ctx.UserContext.CP.State.MarkEdgeAsPending srcV dstV
      updateBackEdges ctx srcV dstV

    member _.BeforeRemoveVertex(ctx, v) =
      beforeRemoveVertex ctx v
