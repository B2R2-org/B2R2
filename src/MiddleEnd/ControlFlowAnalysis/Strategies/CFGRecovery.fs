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
open B2R2.BinIR.LowUIR
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis

module internal CFGRecovery =
  let inline markVertexAsPendingForAnalysis ctx v =
    ctx.CP.MarkVertexAsPending v

  let inline markVertexAsRemovalForAnalysis ctx v =
    ctx.CP.MarkVertexAsRemoval v
    ctx.CFG.GetSuccs v |> Seq.iter ctx.CP.MarkVertexAsPending

  let prioritizer =
    { new IPrioritizable with
        member _.GetPriority action =
          match action with
          | InitiateCFG -> 4
          | ExpandCFG _ -> 4
          | MakeCall _ -> 3
          | MakeTlCall _ -> 3
          | MakeIndCall _ -> 3
          | MakeSyscall _ -> 3
          | MakeIndEdges _ -> 2
          | WaitForCallee _ -> 2
          | ResumeAnalysis _ -> 2
          | UpdateCallEdges _ -> 1
          | StartTblRec _ -> 0
          | EndTblRec _ -> 0 }

  let addCallerVertex ctx callsiteAddr vertex =
    if ctx.CallerVertices.ContainsKey callsiteAddr then ()
    else ctx.CallerVertices.Add (callsiteAddr, vertex) |> ignore

  let scanBBLs (ctx: CFGBuildingContext<_, _>) entryPoints =
    ctx.ScanBBLs entryPoints

  let pushAction (ctx: CFGBuildingContext<_, _>) action =
    ctx.ActionQueue.Push prioritizer action

  let getCalleePPoint callsite calleeAddrOpt =
    match calleeAddrOpt with
    | Some addr -> ProgramPoint (callsite, addr, 0)
    | None -> ProgramPoint (callsite, 0UL, -1)

  let makeVertex ctx cfgRec pp (bbl: LowUIRBasicBlock) =
    match ctx.JumpTableRecoveryStatus.TryPeek () with
    | true, status -> bbl.DominatingJumpTableEntry <- Some status
    | false, _ -> ()
    let v = ctx.CFG.AddVertex bbl
    ctx.Vertices[pp] <- v
    (cfgRec: ICFGRecovery<_, _>).OnAddVertex ctx v
    v

  let makeAbsVertex ctx (cfgRec: ICFGRecovery<_, _>) csAddr calleeOpt abs =
    let calleePPoint = getCalleePPoint csAddr calleeOpt
    let bbl = LowUIRBasicBlock.CreateAbstract (calleePPoint, abs)
    let v = ctx.CFG.AddVertex bbl
    ctx.Vertices[calleePPoint] <- v
    cfgRec.OnAddVertex ctx v
    v

  /// Retrieves a vertex (which is either cached or newly created). This
  /// function can raise an exception if the given program point has no
  /// corresponding basic block in the BBL factory, i.e., bad instruction(s),
  /// etc.
  let getVertex ctx cfgRec ppoint =
    match ctx.Vertices.TryGetValue ppoint with
    | true, v -> v
    | false, _ ->
      let bbl = ctx.BBLFactory.Find ppoint
      makeVertex ctx cfgRec ppoint bbl

  let getAbsVertex ctx cfgRec callsiteAddr calleeAddrOpt abs =
    let calleePPoint = getCalleePPoint callsiteAddr calleeAddrOpt
    match ctx.Vertices.TryGetValue calleePPoint with
    | true, v -> v
    | false, _ ->
      makeAbsVertex ctx cfgRec callsiteAddr calleeAddrOpt abs

  let doesAbsVertexExist ctx callsiteAddr calleeAddr =
    getCalleePPoint callsiteAddr (Some calleeAddr)
    |> ctx.Vertices.ContainsKey

  let isGetPCThunk (ctx: CFGBuildingContext<_, _>) srcBBL calleeAddr =
    if ctx.BinHandle.File.ISA.IsX86 then
      let ins = (srcBBL: ILowUIRBasicBlock).LastInstruction
      let nextAddr = ins.Address + uint64 ins.Length
      if calleeAddr = nextAddr then
        match ctx.BBLFactory.PeekBBL calleeAddr with
        | Ok bbl -> bbl[0].IsPop (* Call to pop *)
        | Error _ -> false
      else false
    else false

  let postponeActionOnCallee ctx calleeAddr action =
    let pendingCallActions = ctx.PendingCallActions
    let queue = ctx.ActionQueue
    let lst =
      match pendingCallActions.TryGetValue calleeAddr with
      | false, _ ->
        let lst = List ()
        pendingCallActions[calleeAddr] <- lst
        queue.Push prioritizer <| WaitForCallee calleeAddr
        lst
      | true, lst -> lst
    lst.Add action

  /// Try to remove a vertex in the CFG whose program point is given as `ppoint`
  /// and return its predecessors and successors. When there's no such vertex,
  /// return empty arrays.
  let tryRemoveVertexAt ctx ppoint =
    match ctx.Vertices.TryGetValue ppoint with
    | true, v ->
      let preds =
        ctx.CFG.GetPredEdges v
        |> Array.filter (fun e -> e.First.VData.Internals.PPoint <> ppoint)
      let succs = ctx.CFG.GetSuccEdges v
      ctx.CFG.RemoveVertex v
      ctx.Vertices.Remove ppoint |> ignore
      markVertexAsRemovalForAnalysis ctx v
      preds, succs
    | false, _ ->
      [||], [||]

  let connectEdge ctx cfgRec srcVertex dstVertex edgeKind =
    ctx.CFG.AddEdge (srcVertex, dstVertex, edgeKind)
    (cfgRec: ICFGRecovery<_, _>).OnAddEdge ctx srcVertex dstVertex edgeKind
#if CFGDEBUG
    let edgeStr = CFGEdgeKind.toString edgeKind
    let srcPPoint = (srcVertex.VData :> IAddressable).PPoint
    let dstPPoint = (dstVertex.VData :> IAddressable).PPoint
    dbglog ctx.ThreadID "ConnectEdge" $"{srcPPoint} -> {dstPPoint} ({edgeStr})"
#endif

  let reconnectVertices ctx (cfgRec: ICFGRecovery<_, _>)
                        (dividedEdges: List<ProgramPoint * ProgramPoint>) =
    for (srcPPoint, dstPPoint) in dividedEdges do
      let preds, succs = tryRemoveVertexAt ctx srcPPoint
      if Array.isEmpty preds && Array.isEmpty succs then
        (* Don't reconnect previously unseen blocks, which can be introduced by
           tail-calls. N.B. BBLFactory cannot see tail-calls. *)
        ()
      else
        let srcVertex = getVertex ctx cfgRec srcPPoint
        let dstVertex = getVertex ctx cfgRec dstPPoint
#if CFGDEBUG
        dbglog ctx.ThreadID "Reconnect" $"{srcPPoint} -> {dstPPoint}"
#endif
        let lastAddr = dstVertex.VData.Internals.LastInstruction.Address
        let callsite = LeafCallSite lastAddr
        if not <| ctx.CallerVertices.ContainsKey callsite then ()
        else ctx.CallerVertices[callsite] <- dstVertex
        connectEdge ctx cfgRec srcVertex dstVertex FallThroughEdge
        for e in preds do
          connectEdge ctx cfgRec e.First srcVertex e.Label
        for e in succs do
          if e.Second.VData.Internals.PPoint = srcPPoint then
            connectEdge ctx cfgRec dstVertex srcVertex e.Label
          else
            connectEdge ctx cfgRec dstVertex e.Second e.Label

  let addExpandCFGAction ctx pp =
    pushAction ctx <| ExpandCFG [ pp ]
    Ok ()

  let isWithinFunction ctx fnAddr dstAddr =
    match ctx.ManagerChannel.GetNextFunctionAddress fnAddr with
    | Some nextFnAddr -> dstAddr < nextFnAddr
    | None -> true

  /// Retrieves a vertex (which is either cached or newly created) for the given
  /// program point only if the vertex is valid, i.e., the vertex is within the
  /// range of the current function. This function is more expensive than
  /// `getVertex`, but needs to be used when the target program point is not
  /// guaranteed to be valid.
  let getValidVertex ctx cfgRec pp =
    match ctx.Vertices.TryGetValue pp with
    | true, v -> Ok v
    | false, _ ->
      match ctx.BBLFactory.TryFind pp with
      | Ok bbl ->
        let fnAddr = ctx.FunctionAddress
        let max = bbl.Internals.Range.Max
        if isWithinFunction ctx fnAddr max then
          Ok (makeVertex ctx cfgRec pp bbl)
        else
          Error ErrorCase.ItemNotFound
      | Error _ -> Error ErrorCase.ItemNotFound

  let scanBBLsAndConnect ctx cfgRec src dstAddr edgeKind =
    match scanBBLs ctx [ dstAddr ] with
    | Ok dividedEdges ->
      let dstPPoint = ProgramPoint (dstAddr, 0)
      match getValidVertex ctx cfgRec dstPPoint with
      | Ok dstVertex ->
        connectEdge ctx cfgRec src dstVertex edgeKind
        reconnectVertices ctx cfgRec dividedEdges
        addExpandCFGAction ctx dstPPoint
      | Error e -> Error e
    | Error e -> Error e

  let toCFGResult = function
    | Ok _ -> MoveOn
    | Error e -> FailStop e

  let isExecutableAddr (ctx: CFGBuildingContext<_, _>) targetAddr =
    ctx.BinHandle.File.IsExecutableAddr targetAddr

  let makeCalleeInfoFromCtx ctx = ctx.NonReturningStatus, ctx.UnwindingBytes

  let handleCall ctx cfgRec srcVertex callsite calleeAddr action =
    let srcBBL: ILowUIRBasicBlock = (srcVertex: IVertex<_>).VData
    (* When a caller node is split into multiple nodes, we can detect the same
       abs-vertex multiple times. So we'd better check duplicates here. *)
    if doesAbsVertexExist ctx callsite calleeAddr then MoveOn
    elif isGetPCThunk ctx srcBBL calleeAddr then
      scanBBLsAndConnect ctx cfgRec srcVertex calleeAddr InterJmpEdge
      |> toCFGResult
    elif isExecutableAddr ctx calleeAddr then
      let fnAddr = ctx.FunctionAddress
      let actionQueue = ctx.ActionQueue
      addCallerVertex ctx callsite (getVertex ctx cfgRec srcBBL.PPoint)
      ctx.IntraCallTable.AddRegularCall callsite calleeAddr
      if fnAddr = calleeAddr then (* self-recursion *)
        actionQueue.Push prioritizer action
      else
        match ctx.ManagerChannel.AddDependency (fnAddr, calleeAddr) with
        (* Wait for the callee to finish *)
        | StillBuilding _
        | FailedBuilding -> postponeActionOnCallee ctx calleeAddr action
        (* Directly push the given action into its action queue. *)
        | FinalCtx calleeCtx ->
          let calleeInfo = makeCalleeInfoFromCtx calleeCtx
          match action with
          | MakeCall _ -> MakeCall (callsite, calleeAddr, calleeInfo)
          | MakeTlCall _ -> MakeTlCall (callsite, calleeAddr, calleeInfo)
          | _ -> action
          |> pushAction ctx
      MoveOn
    else FailStop ErrorCase.FailedToRecoverCFG

  let findCandidates (builders: ICFGBuildable<_, _>[]) =
    builders
    |> Array.choose (fun b ->
      if not b.Context.IsExternal then Some <| b.EntryPoint
      else None)

  /// Try to get a vertex (which is either cached or newly created).
  let tryGetVertex ctx cfgRec ppoint =
    match ctx.Vertices.TryGetValue ppoint with
    | true, v -> Ok v
    | false, _ ->
      match ctx.BBLFactory.TryFind ppoint with
      | Ok bbl -> Ok (makeVertex ctx cfgRec ppoint bbl)
      | Error _ -> Error ErrorCase.ItemNotFound

  let connectEdgeIfValid ctx cfgRec (ppQueue: Queue<_>) srcVertex edgeKind
                         dstPPoint =
    match getValidVertex ctx cfgRec dstPPoint with
    | Ok dstVertex ->
      connectEdge ctx cfgRec srcVertex dstVertex edgeKind
      ppQueue.Enqueue dstPPoint
    | Error _ -> ()

  let maskedPPoint ctx targetAddr =
    let rt = ctx.BinHandle.File.ISA.WordSize |> WordSize.toRegType
    let mask = BitVector.UnsignedMax rt |> BitVector.ToUInt64
    ProgramPoint (targetAddr &&& mask, 0)

  let jmpToDstAddr ctx cfgRec (ppQueue: Queue<_>) srcVertex dstAddr jmpKind =
    let dstPPoint = maskedPPoint ctx dstAddr
    match getValidVertex ctx cfgRec dstPPoint with
    | Ok dstVertex ->
      connectEdge ctx cfgRec srcVertex dstVertex jmpKind
      ppQueue.Enqueue dstPPoint
    | Error _ -> ()

  let makeIntraFallThroughEdge ctx cfgRec (ppQueue: Queue<_>) srcVertex =
    match ppQueue.TryPeek () with
    | true, nextPPoint ->
      let dstVertex = getVertex ctx cfgRec nextPPoint
      connectEdge ctx cfgRec srcVertex dstVertex FallThroughEdge
    | false, _ -> ()

  /// Build a CFG starting from the given program points.
  let buildCFG ctx cfgRec (syscallAnalysis: ISyscallAnalyzable)
               useTailcallHeuristic (actionQueue: CFGActionQueue) initPPs =
    let queue = Queue<ProgramPoint>(collection = initPPs)
    let mutable result = MoveOn
    while queue.Count > 0 && result = MoveOn do
      let ppoint = queue.Dequeue()
      if not <| ctx.VisitedPPoints.Add ppoint then ()
      else
        let srcVertex = getVertex ctx cfgRec ppoint
        let srcBBL = srcVertex.VData
        let srcData = srcBBL :> ILowUIRBasicBlock
        match srcData.Terminator with
        | IEMark _ ->
          let last = srcData.LastInstruction
          let nextPPoint = ProgramPoint(last.Address + uint64 last.Length, 0)
          match tryGetVertex ctx cfgRec nextPPoint with
          | Ok dstVertex ->
            connectEdge ctx cfgRec srcVertex dstVertex FallThroughEdge
            queue.Enqueue nextPPoint
          | Error _ -> () (* Ignore when a bad instruction follows *)
        | Jmp (JmpDest (lbl, _), _) ->
          let dstPPoint = srcBBL.LabelMap[lbl]
          let dstVertex = getVertex ctx cfgRec dstPPoint
          connectEdge ctx cfgRec srcVertex dstVertex IntraJmpEdge
          queue.Enqueue dstPPoint
        | CJmp (_, JmpDest (tLbl, _), JmpDest (fLbl, _), _) ->
          let tPPoint, fPPoint = srcBBL.LabelMap[tLbl], srcBBL.LabelMap[fLbl]
          let tVertex, fVertex =
            getVertex ctx cfgRec tPPoint, getVertex ctx cfgRec fPPoint
          connectEdge ctx cfgRec srcVertex tVertex IntraCJmpTrueEdge
          connectEdge ctx cfgRec srcVertex fVertex IntraCJmpFalseEdge
          queue.Enqueue tPPoint
          queue.Enqueue fPPoint
        | InterJmp (PCVar _, InterJmpKind.Base, _) -> (* intra loop *)
          let dstPPoint = ProgramPoint (ppoint.Address, 0)
          let dstVertex = getVertex ctx cfgRec dstPPoint
          connectEdge ctx cfgRec srcVertex dstVertex InterJmpEdge
        | InterJmp (BinOp (BinOpType.ADD, _, PCVar _, Num (n, _), _),
                    InterJmpKind.Base, _) ->
          let target = srcData.LastInstruction.Address + BitVector.ToUInt64 n
          jmpToDstAddr ctx cfgRec queue srcVertex target InterJmpEdge
        | InterJmp (Num (n, _), InterJmpKind.Base, _) ->
          let target = BitVector.ToUInt64 n
          if useTailcallHeuristic then
            match ctx.ManagerChannel.GetBuildingContext target with
            | FailedBuilding -> (* function does not exist *)
              jmpToDstAddr ctx cfgRec queue srcVertex target InterJmpEdge
            | _ ->
              let lastInsAddr = srcData.LastInstruction.Address
              let callSite = LeafCallSite lastInsAddr
              let act = MakeTlCall (callSite, target, (UnknownNoRet, 0))
              result <- handleCall ctx cfgRec srcVertex callSite target act
          else
            jmpToDstAddr ctx cfgRec queue srcVertex target InterJmpEdge
        | InterJmp (BinOp (BinOpType.ADD, _, PCVar _, Num (n, _), _),
                    InterJmpKind.IsCall, _) ->
          let lastInsAddr = srcData.LastInstruction.Address
          let callsite = LeafCallSite lastInsAddr
          let target = lastInsAddr + BitVector.ToUInt64 n
          let act = MakeCall (callsite, target, (UnknownNoRet, 0))
          result <- handleCall ctx cfgRec srcVertex callsite target act
        | InterJmp (Num (n, _), InterJmpKind.IsCall, _) ->
          let lastInsAddr = srcData.LastInstruction.Address
          let callsite = LeafCallSite lastInsAddr
          let target = BitVector.ToUInt64 n
          let act = MakeCall (callsite, target, (UnknownNoRet, 0))
          result <- handleCall ctx cfgRec srcVertex callsite target act
        | InterCJmp (_, BinOp (BinOpType.ADD, _, PCVar _, Num (tv, _), _),
                        BinOp (BinOpType.ADD, _, PCVar _, Num (fv, _), _), _) ->
          let lastAddr = (srcBBL :> ILowUIRBasicBlock).LastInstruction.Address
          let tpp = maskedPPoint ctx (lastAddr + BitVector.ToUInt64 tv)
          let fpp = maskedPPoint ctx (lastAddr + BitVector.ToUInt64 fv)
          connectEdgeIfValid ctx cfgRec queue srcVertex InterCJmpTrueEdge tpp
          connectEdgeIfValid ctx cfgRec queue srcVertex InterCJmpFalseEdge fpp
        | InterCJmp (_, BinOp (BinOpType.ADD, _, PCVar _, Num (tv, _), _),
                        PCVar _, _) ->
          let lastAddr = (srcBBL :> ILowUIRBasicBlock).LastInstruction.Address
          let tpp = maskedPPoint ctx (lastAddr + BitVector.ToUInt64 tv)
          let fPPoint = maskedPPoint ctx lastAddr
          let fVertex = getVertex ctx cfgRec fPPoint
          connectEdgeIfValid ctx cfgRec queue srcVertex InterCJmpTrueEdge tpp
          connectEdge ctx cfgRec srcVertex fVertex InterCJmpFalseEdge
        | InterCJmp (_, PCVar _,
                        BinOp (BinOpType.ADD, _, PCVar _, Num (fv, _), _), _) ->
          let lastAddr = (srcBBL :> ILowUIRBasicBlock).LastInstruction.Address
          let tpp = maskedPPoint ctx lastAddr
          let fpp = maskedPPoint ctx (lastAddr + BitVector.ToUInt64 fv)
          let tVertex = getVertex ctx cfgRec tpp
          connectEdge ctx cfgRec srcVertex tVertex InterCJmpTrueEdge
          connectEdgeIfValid ctx cfgRec queue srcVertex InterCJmpFalseEdge fpp
        | InterCJmp (_, Num (tv, _), Num (fv, _), _) ->
          let tpp = maskedPPoint ctx (BitVector.ToUInt64 tv)
          let fpp = maskedPPoint ctx (BitVector.ToUInt64 fv)
          connectEdgeIfValid ctx cfgRec queue srcVertex InterCJmpTrueEdge tpp
          connectEdgeIfValid ctx cfgRec queue srcVertex InterCJmpFalseEdge fpp
        | InterJmp (_, InterJmpKind.Base, _) -> (* Indirect jumps *)
          cfgRec.AnalyzeIndirectJump ctx queue ppoint srcVertex
          |> Option.iter (fun r -> result <- r)
        | InterJmp (_, InterJmpKind.IsCall, _) -> (* Indirect calls *)
          let callsiteAddr = srcData.LastInstruction.Address
          let callsite = LeafCallSite callsiteAddr
          addCallerVertex ctx callsite srcVertex
          actionQueue.Push prioritizer <| MakeIndCall (callsite)
        | InterCJmp (_, _, _, _) -> (* Indirect cond jumps *)
          cfgRec.AnalyzeIndirectCondJump ctx queue ppoint srcVertex
          |> Option.iter (fun r -> result <- r)
        | SideEffect (Interrupt 0x80, _) | SideEffect (SysCall, _) ->
          let callsiteAddr = srcData.LastInstruction.Address
          let callsite = LeafCallSite callsiteAddr
          let isExit = syscallAnalysis.IsExit (ctx, srcVertex)
          ctx.IntraCallTable.AddSystemCall callsite isExit
          addCallerVertex ctx callsite srcVertex
          actionQueue.Push prioritizer <| MakeSyscall (callsite, isExit)
        | Jmp _
        | CJmp _
        | InterJmp _
        | InterCJmp _
        | SideEffect (Exception _, _)
        | SideEffect (Terminate, _)
        | SideEffect (Breakpoint, _) ->
          ()
#if DEBUG
        | ISMark _ | LMark _ -> Terminator.impossible ()
#endif
        | _ -> makeIntraFallThroughEdge ctx cfgRec queue srcVertex
    done
    result

  let getFunctionAbstraction ctx (summarizer: IFunctionSummarizable<_, _>)
                             callIns calleeAddr calleeInfo =
    match ctx.ManagerChannel.GetBuildingContext calleeAddr with
    | FinalCtx calleeCtx
    | StillBuilding calleeCtx ->
      let retStatus, unwindingBytes = calleeInfo
      Ok <| summarizer.Summarize (calleeCtx, retStatus, unwindingBytes, callIns)
    | FailedBuilding -> Error ErrorCase.FailedToRecoverCFG

  let connectAbsVertex ctx cfgRec caller calleeAddr isTail abs =
    let callerBBL = (caller: IVertex<LowUIRBasicBlock>).VData.Internals
    let callIns = callerBBL.LastInstruction
    let callsiteAddr = callIns.Address
    let callsite = LeafCallSite callsiteAddr
    let callee = getAbsVertex ctx cfgRec callsite (Some calleeAddr) abs
    let edgeKind = if isTail then TailCallEdge else CallEdge
    connectEdge ctx cfgRec caller callee edgeKind
    callee, callsiteAddr + uint64 callIns.Length

  let connectRet ctx cfgRec (callee, fallthroughAddr) =
    scanBBLsAndConnect ctx cfgRec callee fallthroughAddr RetEdge |> ignore
    (* Depending on the correctness of the noret analysis, there can always be
       an invalid returning edge. In such cases, we won't connect the edge, but
       we don't have to signal an error here. The rest of the process should
       keep going. *)
    Ok ()

  let connectExnEdge ctx cfgRec (callsiteAddr: Addr) =
    match ctx.ExnInfo.TryFindExceptionTarget callsiteAddr with
    | Some target ->
      (* Necessary to lookup the caller again as bbls could be divided *)
      let callsite = LeafCallSite callsiteAddr
      let caller = ctx.CallerVertices[callsite]
      scanBBLsAndConnect ctx cfgRec caller target ExceptionFallThroughEdge
    | None -> Ok ()

  let connectCallWithFT ctx (cfgRec: ICFGRecovery<_, _>) caller calleeAddr
                        calleeInfo =
    let lastIns =
      (caller: IVertex<LowUIRBasicBlock>).VData.Internals.LastInstruction
    getFunctionAbstraction ctx cfgRec.Summarizer lastIns calleeAddr calleeInfo
    |> Result.map (connectAbsVertex ctx cfgRec caller calleeAddr false)
    |> Result.bind (connectRet ctx cfgRec)
    |> Result.bind (fun _ -> connectExnEdge ctx cfgRec lastIns.Address)
    |> toCFGResult

  let connectCallWithoutFT ctx (cfgRec: ICFGRecovery<_, _>) caller calleeAddr
                           calleeInfo =
    let lastIns =
      (caller: IVertex<LowUIRBasicBlock>).VData.Internals.LastInstruction
    getFunctionAbstraction ctx cfgRec.Summarizer lastIns calleeAddr calleeInfo
    |> Result.map (connectAbsVertex ctx cfgRec caller calleeAddr false)
    |> Result.bind (fun _ -> connectExnEdge ctx cfgRec lastIns.Address)
    |> toCFGResult

  let connectCallEdge ctx (cfgRec: ICFGRecovery<_, _>) callsiteAddr callee
                      calleeInfo isTailCall =
    let caller = ctx.CallerVertices[callsiteAddr]
    if isTailCall then
      let lastIns = caller.VData.Internals.LastInstruction
      getFunctionAbstraction ctx cfgRec.Summarizer lastIns callee calleeInfo
      |> Result.map (connectAbsVertex ctx cfgRec caller callee true)
      |> toCFGResult
    elif ctx.FunctionAddress = callee then
      (* recursion = 100% returns (not no-ret) *)
      let lastIns = caller.VData.Internals.LastInstruction
      (* TODO: its unwinding bytes cannot be decided at this moment. *)
      cfgRec.Summarizer.Summarize (ctx, NotNoRet, 0, lastIns)
      |> connectAbsVertex ctx cfgRec caller callee false
      |> connectRet ctx cfgRec
      |> toCFGResult
    else
      match calleeInfo with
      | NoRet, _ -> connectCallWithoutFT ctx cfgRec caller callee calleeInfo
      | NotNoRet, _ -> connectCallWithFT ctx cfgRec caller callee calleeInfo
      | ConditionalNoRet nth, _ ->
        if CondAwareNoretAnalysis.hasNonZero ctx.BinHandle caller nth then
          connectCallWithoutFT ctx cfgRec caller callee calleeInfo
        else connectCallWithFT ctx cfgRec caller callee calleeInfo
      | UnknownNoRet, _ -> Terminator.impossible ()

  let connectIndirectCallEdge ctx cfgRec callsiteAddr =
    let caller = ctx.CallerVertices[callsiteAddr]
    let callIns = caller.VData.Internals.LastInstruction
    let callSiteAddr = callIns.Address
    let callSite = LeafCallSite callSiteAddr
    let summarizer = (cfgRec: ICFGRecovery<_, _>).Summarizer
    let abs = summarizer.MakeUnknownFunctionAbstraction (ctx.BinHandle, callIns)
    let absV = getAbsVertex ctx cfgRec callSite None abs
    connectEdge ctx cfgRec caller absV CallEdge
    connectRet ctx cfgRec (absV, callSiteAddr + uint64 callIns.Length)
    |> Result.bind (fun _ -> connectExnEdge ctx cfgRec callIns.Address)
    |> toCFGResult

  let connectSyscallEdge ctx syscallAnalysis cfgRec callsiteAddr isExit =
    let caller = ctx.CallerVertices[callsiteAddr]
    (syscallAnalysis: ISyscallAnalyzable).MakeAbstract (ctx, caller, isExit)
    |> connectAbsVertex ctx cfgRec caller 0UL false
    |> fun callee ->
      if not isExit then connectRet ctx cfgRec callee |> ignore
      else ()
    MoveOn

  let readJumpTable ctx (jmptbl: JmpTableInfo) idx =
    let size = jmptbl.EntrySize
    let addr = jmptbl.TableAddress + uint64 (idx * size)
    jmptbl.JumpBase + uint64 (ctx.BinHandle.ReadInt (addr, size))

  let pushJmpTblRecoveryAction ctx queue bblAddr jmptbl idx =
    let targetAddr = readJumpTable ctx jmptbl idx
    (queue: CFGActionQueue).Push prioritizer
    <| StartTblRec (jmptbl, idx, bblAddr, targetAddr)
    queue.Push prioritizer
    <| EndTblRec (jmptbl, idx)
    MoveOn

  let recoverIndirectBranches ctx (jmptblAnalysis: IJmpTableAnalyzable<_, _>)
                              queue insAddr bblAddr =
    match jmptblAnalysis.Identify ctx insAddr bblAddr with
    | Ok jmptbl ->
#if CFGDEBUG
      dbglog ctx.ThreadID "JumpTable"
      <| $"{insAddr:x}: [{jmptbl.TableAddress:x}] w/ base {jmptbl.JumpBase:x}"
#endif
      ctx.ManagerChannel.NotifyJumpTableRecovery (ctx.FunctionAddress, jmptbl)
      |> function
        | GoRecovery -> pushJmpTblRecoveryAction ctx queue bblAddr jmptbl 0
        | StopRecoveryButReload -> StopAndReload
        | StopRecoveryAndContinue -> MoveOn
    | Error _ ->
#if CFGDEBUG
      dbglog ctx.ThreadID "JumpTable" $"{insAddr:x} unknown pattern"
#endif
      MoveOn (* We ignore this indirect branch. *)

  let isFailedBuilding (ctx: CFGBuildingContext<'FnCtx, 'GlCtx>) calleeAddr =
    match ctx.ManagerChannel.GetBuildingContext calleeAddr with
    | FailedBuilding -> true
    | _ -> false

  let popOffJmpTblRecoveryAction ctx =
    match ctx.ActionQueue.Pop () with
    | EndTblRec _ -> ()
    | _ -> assert false

  let recoverJumpTableEntry ctx cfgRec queue insAddr srcAddr dstAddr =
    let srcVertex = getVertex ctx cfgRec (ProgramPoint (srcAddr, 0))
    let fnAddr = ctx.FunctionAddress
    if dstAddr < fnAddr
      || not (isExecutableAddr ctx dstAddr)
      || not (isWithinFunction ctx fnAddr dstAddr)
    then
      match ctx.JumpTableRecoveryStatus.TryPeek () with
      | true, (tblAddr, 0) ->
        (* The first jump table entry was invalid. For example, the target could
           be outside the boundary of the current function. In this case, we
           conclude that the indirect jump is not using a jump table, and thus,
           we simply ignore the indirect branch. *)
        ctx.ManagerChannel.CancelJumpTableRecovery (fnAddr, insAddr, tblAddr)
        popOffJmpTblRecoveryAction ctx
        ctx.JumpTableRecoveryStatus.Pop () |> ignore
        MoveOn
      | _ ->
        FailStop ErrorCase.FailedToRecoverCFG
    else
      scanBBLsAndConnect ctx cfgRec srcVertex dstAddr IndirectJmpEdge
      |> toCFGResult

  let sendJmpTblRecoverySuccess ctx queue jmptbl idx =
    let fnAddr = ctx.FunctionAddress
    let tblAddr = jmptbl.TableAddress
    let nextTarget = readJumpTable ctx jmptbl (idx + 1)
    ctx.ManagerChannel.ReportJumpTableSuccess (fnAddr, tblAddr, idx, nextTarget)
    |> function
      | true ->
        let callsiteAddr = jmptbl.InsAddr
        let callsite = LeafCallSite callsiteAddr
        let srcVertex = ctx.CallerVertices[callsite]
        let srcAddr = srcVertex.VData.Internals.BlockAddress
        pushJmpTblRecoveryAction ctx queue srcAddr jmptbl (idx + 1)
      | false ->
#if CFGDEBUG
        dbglog ctx.ThreadID "JumpTable" $"No more to add"
#endif
        MoveOn

  let isNoRet (v: IVertex<LowUIRBasicBlock>) =
    v.VData.Internals.AbstractContent.ReturningStatus = NoRet

  let updateCallEdgesForEachCallsite ctx callsites calleeAddr calleeInfo =
    for callsite in callsites do
      let absPp = ProgramPoint (callsite, calleeAddr, 0)
      match ctx.Vertices.TryGetValue absPp with
      | true, absV when isNoRet absV ->
        let edge = ctx.CFG.GetPredEdges absV |> Array.exactlyOne
        let isTailCall = edge.Label = TailCallEdge
        let action =
          if isTailCall then MakeTlCall (callsite, calleeAddr, calleeInfo)
          else MakeCall (callsite, calleeAddr, calleeInfo)
#if CFGDEBUG
        let fnAddr = ctx.FunctionAddress
        dbglog ctx.ThreadID (nameof UpdateCallEdges)
        <| $"{callsite:x} -> {calleeAddr:x} @ {fnAddr:x}"
#endif
        tryRemoveVertexAt ctx absPp |> ignore
        ctx.ActionQueue.Push prioritizer action
      | _ -> ()
    MoveOn

  let updateCallEdges (ctx: CFGBuildingContext<_, _>) calleeAddr calleeInfo =
    match ctx.IntraCallTable.TryGetCallsites calleeAddr with
    | true, callsites ->
      updateCallEdgesForEachCallsite ctx callsites calleeAddr calleeInfo
    | false, _ ->
      Terminator.impossible ()

  let hasReturnNode (ctx: CFGBuildingContext<'FnCtx, 'GlCtx>) =
    ctx.CFG.TryFindVertex (fun v ->
      if v.VData.Internals.IsAbstract then
        v.VData.Internals.AbstractContent.ReturningStatus = NotNoRet
      else v.VData.Internals.LastInstruction.IsRET)
    |> Option.isSome

  let finalizeRecovery ctx (cfgRec: ICFGRecovery<_, _>) postAnalysis =
    let oldNoRetStatus = ctx.NonReturningStatus
    ICFGAnalysis.run { Context = ctx } postAnalysis
    let newNoRetStatus = ctx.NonReturningStatus
    ctx.UnwindingBytes <- cfgRec.Summarizer.ComputeUnwindingAmount ctx
    match oldNoRetStatus, newNoRetStatus with
    | NoRet, NotNoRet
    | NoRet, ConditionalNoRet _ -> MoveOnButReloadCallers oldNoRetStatus
    | _ -> MoveOn

  let onAction (ctx: CFGBuildingContext<_, _>) cfgRec queue syscallAnalysis
               jmptblAnalysis useTCHeuristic (action: CFGAction) =
    try
      match action with
      | InitiateCFG ->
        let fnAddr = ctx.FunctionAddress
#if CFGDEBUG
        dbglog ctx.ThreadID (nameof InitiateCFG) $"{fnAddr:x}"
#endif
        let pp = ProgramPoint (fnAddr, 0)
        match scanBBLs ctx [ fnAddr ] with
        | Ok _ ->
          buildCFG ctx cfgRec syscallAnalysis useTCHeuristic queue [| pp |]
        | Error e ->
          FailStop e
      | ExpandCFG pps ->
#if CFGDEBUG
        let targets = pps |> Seq.map (fun pp -> $"{pp}") |> String.concat ";"
        dbglog ctx.ThreadID (nameof ExpandCFG)
        <| $"{targets} @ {ctx.FunctionAddress:x}"
#endif
        buildCFG ctx cfgRec syscallAnalysis useTCHeuristic queue pps
      | MakeCall (callSite, calleeAddr, calleeInfo) ->
#if CFGDEBUG
        dbglog ctx.ThreadID (nameof MakeCall)
        <| $"{ctx.FunctionAddress:x} to {calleeAddr:x}"
#endif
        cfgRec.AnalyzeCall ctx callSite calleeAddr calleeInfo false
      | MakeTlCall (callSite, calleeAddr, calleeInfo) ->
#if CFGDEBUG
        dbglog ctx.ThreadID (nameof MakeTlCall)
        <| $"{ctx.FunctionAddress:x} to {calleeAddr:x}"
#endif
        cfgRec.AnalyzeCall ctx callSite calleeAddr calleeInfo true
      | MakeIndCall (callsiteAddr) ->
#if CFGDEBUG
        dbglog ctx.ThreadID (nameof MakeIndCall)
        <| $"{callsiteAddr:x} @ {ctx.FunctionAddress:x}"
#endif
        connectIndirectCallEdge ctx cfgRec callsiteAddr
      | MakeSyscall (callsiteAddr, isExit) ->
#if CFGDEBUG
        dbglog ctx.ThreadID (nameof MakeSyscall) $"{ctx.FunctionAddress:x}"
#endif
        connectSyscallEdge ctx syscallAnalysis cfgRec callsiteAddr isExit
      | MakeIndEdges (bblAddr, insAddr) ->
#if CFGDEBUG
        dbglog ctx.ThreadID (nameof MakeIndEdges)
        <| $"{bblAddr:x} @ {ctx.FunctionAddress:x}"
#endif
        recoverIndirectBranches ctx jmptblAnalysis queue insAddr bblAddr
      | WaitForCallee calleeAddr ->
#if CFGDEBUG
        dbglog ctx.ThreadID (nameof WaitForCallee)
        <| $"{ctx.FunctionAddress:x} waits for {calleeAddr:x}"
#endif
        if not (ctx.PendingCallActions.ContainsKey calleeAddr) then
#if CFGDEBUG
          dbglog ctx.ThreadID (nameof WaitForCallee) "-> move on"
#endif
          MoveOn
        elif isFailedBuilding ctx calleeAddr then
#if CFGDEBUG
          dbglog ctx.ThreadID (nameof WaitForCallee) "-> failstop"
#endif
          FailStop ErrorCase.FailedToRecoverCFG
        else
#if CFGDEBUG
          dbglog ctx.ThreadID (nameof WaitForCallee) "-> wait"
#endif
          Wait (* yet resolved *)
      | StartTblRec (jmptbl, idx, srcAddr, dstAddr) ->
#if CFGDEBUG
        let fnAddr = ctx.FunctionAddress
        dbglog ctx.ThreadID (nameof StartTblRec)
        <| $"{jmptbl.InsAddr:x}[{idx}] -> {dstAddr:x} @ {fnAddr:x}"
#endif
        ctx.JumpTableRecoveryStatus.Push (jmptbl.TableAddress, idx)
        recoverJumpTableEntry ctx cfgRec queue jmptbl.InsAddr srcAddr dstAddr
      | EndTblRec (jmptbl, idx) ->
#if CFGDEBUG
        dbglog ctx.ThreadID (nameof EndTblRec)
        <| $"{jmptbl.InsAddr:x}[{idx}] @ {ctx.FunctionAddress:x}"
#endif
        jmptbl.NumEntries <- idx + 1
        ctx.JumpTables.Add jmptbl
        ctx.JumpTableRecoveryStatus.Pop () |> ignore
        sendJmpTblRecoverySuccess ctx queue jmptbl idx
      | UpdateCallEdges (calleeAddr, calleeInfo) ->
#if CFGDEBUG
        let noret, unwinding = calleeInfo
        let fnAddr = ctx.FunctionAddress
        dbglog ctx.ThreadID (nameof UpdateCallEdges)
        <| $"{calleeAddr:x} changed to ({noret}:{unwinding}) @ {fnAddr:x}"
#endif
        updateCallEdges ctx calleeAddr calleeInfo
      | ResumeAnalysis (pp, callbackAction) ->
        cfgRec.ResumeAnalysis ctx pp callbackAction
    with e ->
      Console.Error.WriteLine $"OnAction failed:\n{e}"
      FailStop ErrorCase.FailedToRecoverCFG

  let onFinish ctx cfgRec postAnalysis =
    assert (ctx.JumpTableRecoveryStatus.Count = 0)
    let nextFn = ctx.ManagerChannel.GetNextFunctionAddress ctx.FunctionAddress
    match ctx.FindOverlap nextFn with
    | Some v ->
#if CFGDEBUG
      let addr = v.VData.Internals.PPoint.Address
      dbglog ctx.ThreadID "OnFinish"
      <| $"Found overlap at {addr:x} @ {ctx.FunctionAddress}"
#endif
      match v.VData.DominatingJumpTableEntry with
      | Some (tblAddr, idx) ->
        let fnAddr = ctx.FunctionAddress
        ctx.ManagerChannel.NotifyBogusJumpTableEntry (fnAddr, tblAddr, idx)
        |> function
          | true -> StopAndReload
          | false -> finalizeRecovery ctx cfgRec postAnalysis
      | None -> finalizeRecovery ctx cfgRec postAnalysis
    | _ -> finalizeRecovery ctx cfgRec postAnalysis

  let onCyclicDependency (deps: (Addr * ICFGBuildable<_, _>)[]) =
    let sorted = deps |> Array.sortBy fst
#if CFGDEBUG
    sorted
    |> Array.map (fun (addr, _) -> $"{addr:x}")
    |> String.concat ","
    |> dbglog ManagerTid "OnCyclicDependency"
#endif
    let target =
      sorted (* If there's no ret instruction, it is likely non-returning *)
      |> Array.tryFind (fun (_, bld) -> not (hasReturnNode bld.Context))
      |> Option.defaultValue (Array.head sorted)
      |> snd
#if CFGDEBUG
    dbglog ManagerTid "OnCyclicDependency"
    <| $"target = {target.EntryPoint:x}"
#endif
    target

/// Base strategy for building a CFG.
type CFGRecovery<'FnCtx,
                 'GlCtx when 'FnCtx :> IResettable
                         and 'FnCtx: (new: unit -> 'FnCtx)
                         and 'GlCtx: (new: unit -> 'GlCtx)>
  public (summarizer: IFunctionSummarizable<'FnCtx, 'GlCtx>,
          jmptblAnalysis: IJmpTableAnalyzable<'FnCtx, 'GlCtx>,
          syscallAnalysis: ISyscallAnalyzable,
          postAnalysis: ICFGAnalysis<_>,
          useTailcallHeuristic,
          allowBBLOverlap,
          useSSA) as this =

  interface ICFGRecovery<'FnCtx, 'GlCtx> with
    member _.Summarizer = summarizer

    member _.AnalyzeCall ctx callSite calleeAddr calleeInfo isTailCall =
      CFGRecovery.connectCallEdge ctx this callSite calleeAddr calleeInfo
                                  isTailCall

    member _.AnalyzeIndirectJump ctx _ppQueue pp srcVertex =
      let insAddr = srcVertex.VData.Internals.LastInstruction.Address
      let callsite = LeafCallSite insAddr
      CFGRecovery.addCallerVertex ctx callsite srcVertex
      CFGRecovery.pushAction ctx <| MakeIndEdges (pp.Address, insAddr)
      None

    member _.AnalyzeIndirectCondJump _ _ _ _ = None

    member _.ResumeAnalysis _ _ _ = Terminator.impossible ()

    member _.FindCandidates (builders) =
      CFGRecovery.findCandidates builders

    member _.OnAction (ctx, queue, action) =
      CFGRecovery.onAction ctx this queue syscallAnalysis jmptblAnalysis
                           useTailcallHeuristic action

    member _.OnCreate _ctx = ()

    member _.OnFinish ctx =
      CFGRecovery.onFinish ctx this postAnalysis

    member _.OnCyclicDependency deps =
      CFGRecovery.onCyclicDependency deps

    member _.ActionPrioritizer with get () =
      CFGRecovery.prioritizer

    member _.AllowBBLOverlap with get () = allowBBLOverlap

    member _.OnAddVertex ctx vertex =
      if not useSSA then
        CFGRecovery.markVertexAsPendingForAnalysis ctx vertex
      else ()

    member _.OnAddEdge ctx _srcVertex dstVertex _edgeKind =
      if not useSSA then
        CFGRecovery.markVertexAsPendingForAnalysis ctx dstVertex
      else ()

  new (allowBBLOverlap, useSSA) =
    let summarizer = FunctionSummarizer ()
    let syscallAnalysis = SyscallAnalysis ()
    let jmptblAnalysis, postAnalysis =
      if useSSA then
        let ssaLifter = SSALifter () :> ICFGAnalysis<_>
        JmpTableAnalysis (Some ssaLifter) :> IJmpTableAnalyzable<_, _>,
        ssaLifter <+> CondAwareNoretAnalysis ()
      else
        JmpTableAnalysis None :> IJmpTableAnalyzable<_, _>,
        CondAwareNoretAnalysis ()
    CFGRecovery (summarizer,
                 jmptblAnalysis,
                 syscallAnalysis,
                 postAnalysis,
                 true,
                 allowBBLOverlap,
                 useSSA)

/// Base strategy for building a CFG without any customizable context.
type CFGRecovery =
  inherit CFGRecovery<DummyContext, DummyContext>

  new () =
    { inherit CFGRecovery<DummyContext, DummyContext> (false, false) }

  new (allowBBLOverlap) =
    { inherit CFGRecovery<DummyContext, DummyContext> (allowBBLOverlap, false) }

  new (summarizer,
       jmptblAnalysis,
       syscallAnalysis,
       postAnalysis,
       useTailcallHeuristic,
       allowBBLOverlap) =
    { inherit CFGRecovery<DummyContext, DummyContext> (summarizer,
                                                       jmptblAnalysis,
                                                       syscallAnalysis,
                                                       postAnalysis,
                                                       useTailcallHeuristic,
                                                       allowBBLOverlap,
                                                       false) }
