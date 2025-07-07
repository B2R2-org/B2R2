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
open B2R2.FrontEnd
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.DataFlow.Constants

[<AutoOpen>]
module private EVMCFGRecovery =
  let summarizer = EVMFunctionSummarizer () :> IFunctionSummarizable<_, _>

  let getFunctionContext ctx calleeAddr =
    match ctx.ManagerChannel.GetBuildingContext calleeAddr with
    | FinalCtx calleeCtx
    | StillBuilding calleeCtx -> Ok calleeCtx
    | FailedBuilding -> Error ErrorCase.FailedToRecoverCFG

  let getFunctionUserContext ctx calleeAddr =
    getFunctionContext ctx calleeAddr
    |> Result.bind (fun calleeCtx ->
      Ok (calleeCtx.UserContext :> EVMFuncUserContext))

  let rec expandExpr state e =
    match e with
    | SSA.Var v ->
      match (state: VarBasedDataFlowState<_>).TryGetSSADef v with
      | None -> e
      | Some stmt ->
        match stmt with
        | SSA.Def (_, e) -> expandExpr state e
        | SSA.Phi (_, _ids) -> e
        | _ -> Terminator.impossible ()
    | SSA.BinOp (op, rt, e1, e2) ->
      let e1' = expandExpr state e1
      let e2' = expandExpr state e2
      SSA.BinOp (op, rt, e1', e2')
    | SSA.UnOp (op, rt, e) ->
      let e' = expandExpr state e
      SSA.UnOp (op, rt, e')
    | SSA.Extract (e, rt, i) ->
      let e' = expandExpr state e
      SSA.Extract (e', rt, i)
    | SSA.Cast (castKind, rt, e) ->
      let e' = expandExpr state e
      SSA.Cast (castKind, rt, e')
    | SSA.Load (memVar, rt, e) ->
      let e' = expandExpr state e
      SSA.Load (memVar, rt, e')
    | SSA.Store (memVar, rt, e1, e2) ->
      let e1' = expandExpr state e1
      let e2' = expandExpr state e2
      SSA.Store (memVar, rt, e1', e2')
    | SSA.Ite (cond, rt, tExpr, fExpr) ->
      let cond' = expandExpr state cond
      let tExpr' = expandExpr state tExpr
      let fExpr' = expandExpr state fExpr
      SSA.Ite (cond', rt, tExpr', fExpr')
    | SSA.RelOp (op, rt, e1, e2) ->
      let e1' = expandExpr state e1
      let e2' = expandExpr state e2
      SSA.RelOp (op, rt, e1', e2')
    | SSA.Nil
    | SSA.Num _
    | SSA.FuncName _
    | SSA.Undefined _ -> e

  let fourBytesBitmaskBv = BitVector.OfUInt32 UInt32.MaxValue 256<rt>

  let isPossiblyFuncSig bv = (bv: BitVector).And fourBytesBitmaskBv = bv

  let isMsgDataDivision = function
    | SSA.BinOp (BinOpType.DIV, _,
                 SSA.BinOp (BinOpType.APP, _, SSA.FuncName "msg.data", _),
                 SSA.Num _disivorBv)
    | SSA.BinOp (BinOpType.DIV, _,
                 SSA.Num _disivorBv,
                 SSA.BinOp (BinOpType.APP, _, SSA.FuncName "msg.data", _))
      -> true
    | SSA.BinOp (BinOpType.SHR, _,
                 SSA.BinOp (BinOpType.APP, _, SSA.FuncName "msg.data", _),
                 SSA.Num _shiftBv)
      -> true
    | _ -> false

  let hasFuncSigExpr = function
    | SSA.BinOp (BinOpType.AND, _, SSA.Num bitmaskBv, msgDataDivisionExpr)
    | SSA.BinOp (BinOpType.AND, _, msgDataDivisionExpr, SSA.Num bitmaskBv)
        when isMsgDataDivision msgDataDivisionExpr
          && bitmaskBv = fourBytesBitmaskBv
      -> true
    | _ -> false

  let rec tryDetectPubFunc ctx (state: VarBasedDataFlowState<_>) cond =
    match expandExpr state cond with
    | SSA.Extract (e, _, _) -> tryDetectPubFunc ctx state e
    | SSA.Cast (_, _, e) -> tryDetectPubFunc ctx state e
    | SSA.RelOp (RelOpType.EQ, _, SSA.Num hashBv, e)
    | SSA.RelOp (RelOpType.EQ, _, e, SSA.Num hashBv)
        when isPossiblyFuncSig hashBv
          && (hasFuncSigExpr e || isMsgDataDivision e) ->
      true
    | _ -> false

  let scanAndGetVertex ctx addr =
    let pp = ProgramPoint (addr, 0)
    if ctx.BBLFactory.Contains pp then ()
    else CFGRecovery.scanBBLs ctx [ addr ] |> ignore
    CFGRecovery.getVertex ctx pp

  let rec findReachingDefVars (state: VarBasedDataFlowState<_>) acc var =
    match state.TryGetSSADef var with
    | None -> var :: acc
    | Some stmt ->
      match stmt with
      | SSA.Def (_, e) ->
        match e with
        | SSA.Var v -> findReachingDefVars state acc v
        | _ -> var :: acc
      | SSA.Phi (_, ids) ->
        ids
        |> Seq.map (fun id -> { var with Identifier = id })
        |> Seq.fold (findReachingDefVars state) acc
      | _ -> Terminator.impossible ()

  let getDefSite (state: VarBasedDataFlowState<_>) var =
    assert (state.SSAVarToVp.ContainsKey var)
    let vp = state.SSAVarToVp[var]
    let pp = vp.ProgramPoint
    snd state.StmtOfBBLs[pp]

  /// Try to find a feasible path from `srcV` to `dstV` in the given graph `g`.
  /// We use BFS to find a path fast.
  let tryFindFeasiblePath g srcV dstV =
    let q = Queue ()
    let visited = HashSet<IVertex<_>> ()
    let push v p = if not <| visited.Add v then () else q.Enqueue (v, v :: p)
    let mutable foundPath = None
    push srcV []
    while Option.isNone foundPath && q.Count > 0 do
      let v, p = q.Dequeue ()
      for succ in (g: IDiGraphAccessible<_, _>).GetSuccs v do
        if succ = dstV then foundPath <- Some (dstV :: p)
        else push succ p
    Option.map List.rev foundPath

  /// Find a feasible path from `srcV` to `dstV` in the given graph `g`.
  let findFeasiblePath g srcV dstV =
    match tryFindFeasiblePath g srcV dstV with
    | Some p -> p
    | None -> Terminator.impossible ()

  let tryGetInterJmpDstVar (state: VarBasedDataFlowState<_>) v =
    match state.GetTerminatorInSSA v with
    | SSA.Jmp (SSA.InterJmp (SSA.Var var)) -> Some var
    | _ -> None

  let hasPolyJumpTarget (state: VarBasedDataFlowState<_>) v =
    match tryGetInterJmpDstVar state v with
    | None -> false
    | Some jumpDstVar ->
      findReachingDefVars state [] jumpDstVar
      |> Seq.distinct
      |> Seq.length
      |> (<) 1

  let collectPolyJumpsFromReachables (g: IDiGraphAccessible<_, _>) state start =
    let q = Queue ()
    let visited = HashSet ()
    let push v = if not <| visited.Add v then () else q.Enqueue v
    let mutable polyJumps = []
    push start
    while not <| Seq.isEmpty q do
      let v = q.Dequeue ()
      if hasPolyJumpTarget state v then polyJumps <- v :: polyJumps
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
    |> Result.iter (fun userCtx -> userCtx.SetSharedRegion ())

  let findAndIntroduceSharedRegion ctx state v rdVars  =
    assert (not <| Seq.isEmpty rdVars)
    let rds = Seq.map (getDefSite state) rdVars
    let g = ctx.CFG
    let pathes = Seq.map (fun d -> findFeasiblePath g d v) rds
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
      tryGetInterJmpDstVar state polyJmpV
      |> Option.get
      |> findReachingDefVars state []
      |> findAndIntroduceSharedRegion ctx state polyJmpV
    Some StopAndReload

  let makeCalleeInfoFromBuildingContext = function
    | FinalCtx ctx -> ctx.NonReturningStatus, ctx.UnwindingBytes
    | StillBuilding _ -> NoRet, 0
    | _ -> Terminator.impossible ()

  let fromBBLToCallSite (blk: ILowUIRBasicBlock) =
    match blk.PPoint.CallSite with
    | None -> LeafCallSite blk.LastInstruction.Address
    | Some callSite -> ChainedCallSite (callSite, blk.PPoint.Address)

  let connectEdgeAndPushPP ctx (ppQueue: Queue<_>) srcV dstV kind =
    CFGRecovery.connectEdge ctx srcV dstV kind
    ppQueue.Enqueue dstV.VData.Internals.PPoint

  let handleDirectJmp ctx state ppQueue srcVertex dstVar =
    let domSubState = (state: VarBasedDataFlowState<_>).DomainSubState
    (* We use GetAbsValue instead of expandExpr, since the target address
       can be applied AND-operation, which necessites constand-folding. *)
    match domSubState.GetAbsValue (dstVar: SSA.Variable) with
    | ConstantDomain.Const dstBv ->
      let dstAddr = BitVector.ToUInt64 dstBv
      match ctx.ManagerChannel.GetBuildingContext dstAddr with
      | FailedBuilding -> (* Ignore when the target is not a function. *)
        let dstV = scanAndGetVertex ctx dstAddr
        connectEdgeAndPushPP ctx ppQueue srcVertex dstV InterJmpEdge
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
        let act = MakeCall (callSite, dstAddr, calleeInfo)
        let res = CFGRecovery.handleCall ctx srcVertex callSite dstAddr act
        Some res
    | _ -> Terminator.futureFeature () (* Function pointers not supported. *)

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
                   && not <| pred.VData.Internals.LastInstruction.IsBranch () ->
      findFunctionEntryAux curr v path'
    (* 4. Conditional branch's target is **less likely** to be an entry point.*)
    | v :: path' when pred <> null
                   && not pred.VData.Internals.IsAbstract
                   && pred.VData.Internals.LastInstruction.IsCondBranch () ->
      findFunctionEntryAux curr v path'
    (* 5. If the vertex is a function, then we found it. *)
    | _ when not curr.VData.Internals.IsAbstract ->
      curr
    | _ -> Terminator.impossible () (* Not found. *)

  let introduceNewFunction (ctx: CFGBuildingContext<_, _>) newEntryPoint =
    ctx.ManagerChannel.StartBuilding newEntryPoint

  let findAndIntroduceFunction ctx srcV rds =
    let sampledDefSite = Seq.head rds
    let sampledPath = findFeasiblePath ctx.CFG sampledDefSite srcV
    let newEntryPoint = findFunctionEntry sampledPath
    let newEntryPointAddr = newEntryPoint.VData.Internals.PPoint.Address
    introduceNewFunction ctx newEntryPointAddr
    Some StopAndReload

  let tryFindReachingDefByVarKind state varKind v =
    let outgoingDefs = (state: VarBasedDataFlowState<_>).PerVertexOutgoingDefs
    match outgoingDefs.TryGetValue v with
    | true, defs -> Map.tryFind varKind defs
    | false, _ -> None

  /// Find the latest stack pointer **after** the execution of the given vertex.
  let findLatestStackOffset hdl state v =
    let spRegId = (hdl: BinHandle).RegisterFactory.StackPointer.Value
    let spVarKind = Regular spRegId
    match tryFindReachingDefByVarKind state spVarKind v with
    | None -> 0UL (* No defs, so we return 0. *)
    | Some varPoint ->
      let spSubState = state.StackPointerSubState
      let absValue = spSubState.GetAbsValue varPoint
      match absValue with
      | StackPointerDomain.ConstSP spBv ->
        BitVector.ToUInt64 spBv - InitialStackPointer
      | _ -> Terminator.impossible ()

  /// We met a returning jump, which uses an incoming variable as its target,
  /// and we extract stack pointer difference and the target variable's stack
  /// pointer offset to abstract the return information, which will be used
  /// to build an inter-procedural (call) edge to this function later.
  let analyzeReturnInfo ctx state v incomingVars =
    assert (Seq.forall (fun v -> (v: SSA.Variable).Identifier = 0) incomingVars)
    let var = Seq.head incomingVars
    let returnTargetStackOff =
      match var.Kind with
      | SSA.StackVar (_, off) -> uint64 off (* 0, 32, 64, ... *)
      | _ -> Terminator.impossible ()
    let hdl = ctx.BinHandle
    let stackPointerDiff = findLatestStackOffset hdl state v
    let fnUserCtx: EVMFuncUserContext = ctx.UserContext
    fnUserCtx.SetReturnTargetStackOff returnTargetStackOff
    fnUserCtx.SetStackPointerDiff stackPointerDiff
    None

  let handleInterJmp ctx ppQueue srcV =
    let cp = ConstantPropagation ctx.BinHandle
    let dfa = cp :> IDataFlowAnalysis<_, _, _, _>
    let state = dfa.Compute ctx.CFG ctx.CPState
    match state.GetTerminatorInSSA srcV with
    | SSA.Jmp (SSA.InterJmp (SSA.Var var)) ->
      let rdVars = findReachingDefVars state [] var
      let incomingVars = rdVars |> Seq.filter (fun v -> v.Identifier = 0)
      let usesIncomingVars = not <| Seq.isEmpty incomingVars
      (* Check if this returns from the **current** function. *)
      if usesIncomingVars then analyzeReturnInfo ctx state srcV incomingVars
      elif srcV.VData.Internals.IsAbstract then
        let hasMultipleRdVars = (Seq.distinct >> Seq.length) rdVars > 1
        if hasMultipleRdVars then (* Highly likely a shared region. *)
          findAndIntroduceSharedRegion ctx state srcV rdVars
          Some StopAndReload
        else
          handleDirectJmp ctx state ppQueue srcV var
      else
        let rds = Seq.map (getDefSite state) rdVars
        let possiblyReturnEdge = Seq.exists (fun d -> d <> srcV) rds
        if possiblyReturnEdge then findAndIntroduceFunction ctx srcV rds
        else handleDirectJmp ctx state ppQueue srcV var
    | SSA.SideEffect Terminate -> None (* No return! *)
    | _ -> Terminator.impossible ()

  let handleInterCJmp ctx ppQueue srcVertex =
    let cp = ConstantPropagation ctx.BinHandle
    let dfa = cp :> IDataFlowAnalysis<_, _, _, _>
    let state = dfa.Compute ctx.CFG ctx.CPState
    let subState = state.DomainSubState
    match state.GetTerminatorInSSA srcVertex with
    | SSA.Jmp (SSA.InterCJmp (cond, SSA.Var tJmpVar, SSA.Num fJmpBv)) ->
      match subState.GetAbsValue tJmpVar with
      | ConstantDomain.Const tJmpBv ->
        let isEntryFunction = ctx.FunctionAddress = 0x0UL
        if isEntryFunction && tryDetectPubFunc ctx state cond then
          let tJmpAddr = BitVector.ToUInt64 tJmpBv
          let fJmpAddr = BitVector.ToUInt64 fJmpBv
          let fJmpV = scanAndGetVertex ctx fJmpAddr
          let callee = tJmpAddr
          let cs = fromBBLToCallSite srcVertex.VData
          let act = MakeCall (cs, callee, (NoRet, 0)) (* treat as NoRet *)
          connectEdgeAndPushPP ctx ppQueue srcVertex fJmpV InterCJmpFalseEdge
          let ret = CFGRecovery.handleCall ctx srcVertex cs callee act
          getFunctionUserContext ctx callee
          |> Result.iter (fun userCtx -> userCtx.SetSharedRegion ())
          Some ret
        else
          let tJmpAddr = BitVector.ToUInt64 tJmpBv
          let fJmpAddr = BitVector.ToUInt64 fJmpBv
          let tJmpV = scanAndGetVertex ctx tJmpAddr
          let fJmpV = scanAndGetVertex ctx fJmpAddr
          connectEdgeAndPushPP ctx ppQueue srcVertex tJmpV InterCJmpTrueEdge
          connectEdgeAndPushPP ctx ppQueue srcVertex fJmpV InterCJmpFalseEdge
          None
      | _ -> Terminator.futureFeature ()
    | _ -> Terminator.impossible ()

  /// Summarize the callee's context.
  let summarize ctx calleeInfo =
    let retStatus, unwindingBytes = calleeInfo
    summarizer.Summarize (ctx, retStatus, unwindingBytes, null)

  /// We need to use UserContext of the callee function, so we need to directly
  /// access the callee context instead of using the abstraction.
  /// TODO: What if the callee has been reset? Timing issue here?
  let connectAbsVertex ctx caller callee callsite isTail calleeInfo calleeCtx =
    let abs = summarize calleeCtx calleeInfo
    let calleeOpt = Some callee
    let callee = CFGRecovery.getAbsVertex ctx callsite calleeOpt abs
    let edgeKind = if isTail then TailCallEdge else CallEdge
    CFGRecovery.connectEdge ctx caller callee edgeKind
    callee

  let connectCall ctx caller callee callsite calleeInfo =
    getFunctionContext ctx callee
    |> Result.map (connectAbsVertex ctx caller callee callsite false calleeInfo)
    |> CFGRecovery.toCFGResult

  let handleCall ctx cs callee calleeInfo =
    let caller = ctx.CallerVertices[cs]
    let callsite = fromBBLToCallSite caller.VData.Internals
    let absPp = ProgramPoint (callsite, callee, 0)
    let act = ExpandCFG [ absPp ]
    CFGRecovery.pushAction ctx act
    connectCall ctx caller callee callsite calleeInfo

type EVMCFGRecovery () =
  inherit CFGRecovery<EVMFuncUserContext, DummyContext> (false)

  interface IIndirectJmpAnalyzable<EVMFuncUserContext, DummyContext> with
    member _.AnalyzeIndirectJump ctx ppQueue _pp srcVertex =
      handleInterJmp ctx ppQueue srcVertex

    member _.AnalyzeIndirectCondJump ctx ppQueue _pp srcVertex =
      handleInterCJmp ctx ppQueue srcVertex

  interface ICallAnalyzable<EVMFuncUserContext, DummyContext> with
    member _.AnalyzeCall ctx cs callee calleeInfo _ =
      handleCall ctx cs callee calleeInfo

  interface ICFGBuildingStrategy<EVMFuncUserContext, DummyContext> with
    member _.OnFinish ctx =
      let fnUserCtx = ctx.UserContext
      let status, unwinding =
        match fnUserCtx.StackPointerDiff with
        | Some diff -> NotNoRet, int diff
        | None -> NoRet, 0
      ctx.NonReturningStatus <- status
      ctx.UnwindingBytes <- unwinding
      MoveOn

    member _.FindCandidates _ = [| 0x0UL |]
