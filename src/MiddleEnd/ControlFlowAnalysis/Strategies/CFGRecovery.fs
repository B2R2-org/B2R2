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

[<AutoOpen>]
module private CFGRecovery =
  let inline markVertexAsPendingForAnalysis useSSA ctx v =
    if useSSA then ()
    else ctx.CPState.MarkVertexAsPending v

  let inline markVertexAsRemovalForAnalysis useSSA ctx v =
    if useSSA then ()
    else
      ctx.CPState.MarkVertexAsRemoval v
      ctx.CFG.GetSuccs v |> Seq.iter ctx.CPState.MarkVertexAsPending

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
          useSSA) =

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
          | StartTblRec _ -> 0
          | EndTblRec _ -> 0 }

  let scanBBLs ctx mode entryPoints =
    ctx.BBLFactory.ScanBBLs mode entryPoints
    |> Async.AwaitTask
    |> Async.RunSynchronously

  let getVertex ctx ppoint =
    match ctx.Vertices.TryGetValue ppoint with
    | true, v -> v
    | false, _ ->
      let v, g = ctx.CFG.AddVertex (ctx.BBLFactory.Find ppoint)
      ctx.CFG <- g
      ctx.Vertices[ppoint] <- v
      markVertexAsPendingForAnalysis useSSA ctx v
      v

  let tryGetVertex ctx ppoint =
    match ctx.Vertices.TryGetValue ppoint with
    | true, v -> Ok v
    | false, _ ->
      match ctx.BBLFactory.TryFind ppoint with
      | Ok bbl ->
        let v, g = ctx.CFG.AddVertex bbl
        ctx.CFG <- g
        ctx.Vertices[ppoint] <- v
        markVertexAsPendingForAnalysis useSSA ctx v
        Ok v
      | Error _ -> Error ErrorCase.ItemNotFound

  let getCalleePPoint callsite calleeAddrOpt =
    match calleeAddrOpt with
    | Some addr -> ProgramPoint (callsite, addr, 0)
    | None -> ProgramPoint (callsite, 0UL, -1)

  let getAbsVertex ctx callsiteAddr calleeAddrOpt abs =
    let calleePPoint = getCalleePPoint callsiteAddr calleeAddrOpt
    match ctx.Vertices.TryGetValue calleePPoint with
    | true, v -> v
    | false, _ ->
      let calleePPoint = getCalleePPoint callsiteAddr calleeAddrOpt
      let bbl = LowUIRBasicBlock.CreateAbstract (calleePPoint, abs)
      let v, g = ctx.CFG.AddVertex bbl
      ctx.CFG <- g
      ctx.Vertices[calleePPoint] <- v
      markVertexAsPendingForAnalysis useSSA ctx v
      v

  let removeVertex ctx ppoint =
    match ctx.Vertices.TryGetValue ppoint with
    | true, v ->
      let preds =
        ctx.CFG.GetPredEdges v
        |> Array.filter (fun e -> e.First.VData.Internals.PPoint <> ppoint)
      let succs = ctx.CFG.GetSuccEdges v
      ctx.Vertices.Remove ppoint |> ignore
      ctx.CFG <- ctx.CFG.RemoveVertex v
      preds, succs, v
    | false, _ ->
      [||], [||], null

  let connectEdge ctx srcVertex dstVertex edgeKind =
    ctx.CFG <- ctx.CFG.AddEdge (srcVertex, dstVertex, edgeKind)
    markVertexAsPendingForAnalysis useSSA ctx dstVertex

#if CFGDEBUG
    let edgeStr = CFGEdgeKind.toString edgeKind
    let srcPPoint = (srcVertex.VData :> IAddressable).PPoint
    let dstPPoint = (dstVertex.VData :> IAddressable).PPoint
    dbglog ctx.ThreadID "ConnectEdge"
    <| $"{srcPPoint} -> {dstPPoint} ({edgeStr})"
#endif

  let maskedPPoint ctx targetAddr =
    let rt = ctx.BinHandle.File.ISA.WordSize |> WordSize.toRegType
    let mask = BitVector.UnsignedMax rt |> BitVector.ToUInt64
    ProgramPoint (targetAddr &&& mask, 0)

  let jmpToDstAddr ctx (ppQueue: Queue<_>) srcVertex dstAddr jmpKind =
    let dstPPoint = maskedPPoint ctx dstAddr
    let dstVertex = getVertex ctx dstPPoint
    connectEdge ctx srcVertex dstVertex jmpKind
    ppQueue.Enqueue dstPPoint

  let postponeActionOnCallee ctx calleeAddr action =
    let pendingActions = ctx.PendingActions
    let queue = ctx.ActionQueue
    let lst =
      match pendingActions.TryGetValue calleeAddr with
      | false, _ ->
        let lst = List ()
        pendingActions[calleeAddr] <- lst
        queue.Push prioritizer <| WaitForCallee calleeAddr
        lst
      | true, lst -> lst
    lst.Add action

  let addCallerVertex ctx callsiteAddr vertex =
    if ctx.CallerVertices.ContainsKey callsiteAddr then ()
    else ctx.CallerVertices.Add (callsiteAddr, vertex) |> ignore

  let isExecutableAddr (ctx: CFGBuildingContext<_, _>) targetAddr =
    ctx.BinHandle.File.IsExecutableAddr targetAddr

  let pushCallAction ctx srcPp callsiteAddr calleeAddr action =
    if isExecutableAddr ctx calleeAddr then
      let mode = ctx.FunctionMode
      let fnAddr = ctx.FunctionAddress
      let actionQueue = ctx.ActionQueue
      addCallerVertex ctx callsiteAddr (getVertex ctx srcPp)
      ctx.IntraCallTable.AddRegularCall srcPp callsiteAddr calleeAddr
      ctx.ManagerChannel.AddDependency (fnAddr, calleeAddr, mode)
      if fnAddr = calleeAddr then (* self-recursion *)
        actionQueue.Push prioritizer action
      else
        match ctx.ManagerChannel.GetBuildingContext calleeAddr with
        (* Wait for the callee to finish *)
        | StillBuilding _
        | FailedBuilding -> postponeActionOnCallee ctx calleeAddr action
        (* Directly push the given action into its action queue. *)
        | FinalCtx _ -> actionQueue.Push prioritizer action
      Continue
    else FailStop ErrorCase.FailedToRecoverCFG

  /// Build a CFG starting from the given program points.
  let buildCFG ctx (actionQueue: CFGActionQueue) initPPs =
    let ppQueue = Queue<ProgramPoint> (collection=initPPs)
    let mutable result = Continue
    while ppQueue.Count > 0 && result = Continue do
      let ppoint = ppQueue.Dequeue ()
      if ctx.VisitedPPoints.Contains ppoint then ()
      else
        ctx.VisitedPPoints.Add ppoint |> ignore
        let srcVertex = getVertex ctx ppoint
        let srcBBL = srcVertex.VData
        let srcData = srcBBL :> ILowUIRBasicBlock
        match srcData.Terminator.S with
        | IEMark _ ->
          let last = srcData.LastInstruction
          let nextPPoint = ProgramPoint (last.Address + uint64 last.Length, 0)
          match tryGetVertex ctx nextPPoint with
          | Ok dstVertex ->
            connectEdge ctx srcVertex dstVertex FallThroughEdge
            ppQueue.Enqueue nextPPoint
          | Error _ -> () (* Ignore when a bad instruction follows *)
        | Jmp { E = Name lbl } ->
          let dstPPoint = srcBBL.LabelMap[lbl]
          let dstVertex = getVertex ctx dstPPoint
          connectEdge ctx srcVertex dstVertex IntraJmpEdge
          ppQueue.Enqueue dstPPoint
        | CJmp (_, { E = Name tLbl }, { E = Name fLbl }) ->
          let tPPoint, fPPoint = srcBBL.LabelMap[tLbl], srcBBL.LabelMap[fLbl]
          let tVertex, fVertex = getVertex ctx tPPoint, getVertex ctx fPPoint
          connectEdge ctx srcVertex tVertex IntraCJmpTrueEdge
          connectEdge ctx srcVertex fVertex IntraCJmpFalseEdge
          ppQueue.Enqueue tPPoint
          ppQueue.Enqueue fPPoint
        | InterJmp ({ E = PCVar _ }, InterJmpKind.Base) ->
          let dstPPoint = ProgramPoint (ppoint.Address, 0)
          let dstVertex = getVertex ctx dstPPoint
          connectEdge ctx srcVertex dstVertex InterJmpEdge
        | InterJmp ({ E = BinOp (BinOpType.ADD, _, { E = PCVar _ },
                                                   { E = Num n }) },
                          InterJmpKind.Base) ->
          let target = srcData.LastInstruction.Address + BitVector.ToUInt64 n
          jmpToDstAddr ctx ppQueue srcVertex target InterJmpEdge
        | InterJmp ({ E = Num n }, InterJmpKind.Base) ->
          if useTailcallHeuristic then
            let dstAddr = BitVector.ToUInt64 n
            match ctx.ManagerChannel.GetBuildingContext dstAddr with
            | FailedBuilding -> (* function does not exist *)
              jmpToDstAddr ctx ppQueue srcVertex dstAddr InterJmpEdge
            | _ ->
              let callSite = srcData.LastInstruction.Address
              let act = MakeTlCall (callSite, dstAddr)
              result <- pushCallAction ctx srcData.PPoint callSite dstAddr act
          else
            let dstAddr = BitVector.ToUInt64 n
            jmpToDstAddr ctx ppQueue srcVertex dstAddr InterJmpEdge
        | InterJmp ({ E = BinOp (BinOpType.ADD, _, { E = PCVar _ },
                                                   { E = Num n }) },
                          InterJmpKind.IsCall) ->
          let callsiteAddr = srcData.LastInstruction.Address
          let target = callsiteAddr + BitVector.ToUInt64 n
          let act = MakeCall (callsiteAddr, target)
          result <- pushCallAction ctx srcData.PPoint callsiteAddr target act
        | InterJmp ({ E = Num n }, InterJmpKind.IsCall) ->
          let callsiteAddr = srcData.LastInstruction.Address
          let target = BitVector.ToUInt64 n
          let act = MakeCall (callsiteAddr, target)
          result <- pushCallAction ctx srcData.PPoint callsiteAddr target act
        | InterCJmp (_, { E = BinOp (BinOpType.ADD, _, { E = PCVar _ },
                                                       { E = Num tv }) },
                        { E = BinOp (BinOpType.ADD, _, { E = PCVar _ },
                                                       { E = Num fv }) }) ->
          let lastAddr = (srcBBL :> ILowUIRBasicBlock).LastInstruction.Address
          let tPPoint = maskedPPoint ctx (lastAddr + BitVector.ToUInt64 tv)
          let fPPoint = maskedPPoint ctx (lastAddr + BitVector.ToUInt64 fv)
          let tVertex, fVertex = getVertex ctx tPPoint, getVertex ctx fPPoint
          connectEdge ctx srcVertex tVertex InterCJmpTrueEdge
          connectEdge ctx srcVertex fVertex InterCJmpFalseEdge
          ppQueue.Enqueue tPPoint
          ppQueue.Enqueue fPPoint
        | InterCJmp (_, { E = BinOp (BinOpType.ADD, _, { E = PCVar _ },
                                                       { E = Num tv }) },
                        { E = PCVar _ }) ->
          let lastAddr = (srcBBL :> ILowUIRBasicBlock).LastInstruction.Address
          let tPPoint = maskedPPoint ctx (lastAddr + BitVector.ToUInt64 tv)
          let fPPoint = maskedPPoint ctx lastAddr
          let tVertex, fVertex = getVertex ctx tPPoint, getVertex ctx fPPoint
          connectEdge ctx srcVertex tVertex InterCJmpTrueEdge
          connectEdge ctx srcVertex fVertex InterCJmpFalseEdge
          ppQueue.Enqueue tPPoint
        | InterCJmp (_, { E = PCVar _ },
                        { E = BinOp (BinOpType.ADD, _, { E = PCVar _ },
                                                       { E = Num fv }) }) ->
          let lastAddr = (srcBBL :> ILowUIRBasicBlock).LastInstruction.Address
          let tPPoint = maskedPPoint ctx lastAddr
          let fPPoint = maskedPPoint ctx (lastAddr + BitVector.ToUInt64 fv)
          let tVertex, fVertex = getVertex ctx tPPoint, getVertex ctx fPPoint
          connectEdge ctx srcVertex tVertex InterCJmpTrueEdge
          connectEdge ctx srcVertex fVertex InterCJmpFalseEdge
          ppQueue.Enqueue fPPoint
        | InterCJmp (_, { E = Num tv }, { E = Num fv }) ->
          let tPPoint = maskedPPoint ctx (BitVector.ToUInt64 tv)
          let fPPoint = maskedPPoint ctx (BitVector.ToUInt64 fv)
          let tVertex, fVertex = getVertex ctx tPPoint, getVertex ctx fPPoint
          connectEdge ctx srcVertex tVertex InterCJmpTrueEdge
          connectEdge ctx srcVertex fVertex InterCJmpFalseEdge
          ppQueue.Enqueue tPPoint
          ppQueue.Enqueue fPPoint
        | InterJmp (_, InterJmpKind.Base) -> (* Indirect jumps *)
          let insAddr = srcVertex.VData.Internals.LastInstruction.Address
          addCallerVertex ctx insAddr srcVertex
          actionQueue.Push prioritizer
          <| MakeIndEdges (ppoint.Address, insAddr)
        | InterJmp (_, InterJmpKind.IsCall) -> (* Indirect calls *)
          let callSiteAddr = srcData.LastInstruction.Address
          addCallerVertex ctx callSiteAddr srcVertex
          actionQueue.Push prioritizer
          <| MakeIndCall (callSiteAddr)
        | Jmp _ | CJmp _ | InterCJmp _ ->
          ()
        | SideEffect (Interrupt 0x80) | SideEffect SysCall ->
          let callsiteAddr = srcData.LastInstruction.Address
          let isExit = syscallAnalysis.IsExit (ctx, srcVertex)
          ctx.IntraCallTable.AddSystemCall callsiteAddr isExit
          addCallerVertex ctx callsiteAddr srcVertex
          actionQueue.Push prioritizer
          <| MakeSyscall (callsiteAddr, isExit)
        | _ ->
          ()
    done
    result

  /// This is to update the caller information when a basic block is split. This
  /// is only effective when the block makes a call, and the callee(s) are
  /// known.
  let handleCallerSplit ctx callerAddr splitAddr callsiteAddr =
    assert (callerAddr < splitAddr && splitAddr <= callsiteAddr)
    match ctx.IntraCallTable.TryGetCallee callsiteAddr with
    | true, RegularCallee calleeAddr ->
      let callingBBLs = ctx.IntraCallTable.GetCallingBBLs calleeAddr
      callingBBLs.Remove callerAddr |> ignore
      callingBBLs.Add splitAddr |> ignore
    | _ -> ()

  let reconnectVertices ctx (dividedEdges: List<ProgramPoint * ProgramPoint>) =
    for (srcPPoint, dstPPoint) in dividedEdges do
      let preds, succs, origVertex = removeVertex ctx srcPPoint
      if Array.isEmpty preds && Array.isEmpty succs then
        (* Don't reconnect previously unseen blocks, which can be introduced by
           tail-calls. N.B. BBLFactory cannot see tail-calls. *)
        ()
      else
        let srcVertex = getVertex ctx srcPPoint
        let dstVertex = getVertex ctx dstPPoint
#if CFGDEBUG
        dbglog ctx.ThreadID "Reconnect" $"{srcPPoint} -> {dstPPoint}"
#endif
        let lastAddr = dstVertex.VData.Internals.LastInstruction.Address
        let callSiteAddr = lastAddr
        if not <| ctx.CallerVertices.ContainsKey callSiteAddr then ()
        else ctx.CallerVertices[callSiteAddr] <- dstVertex
        handleCallerSplit ctx srcPPoint.Address dstPPoint.Address lastAddr
        connectEdge ctx srcVertex dstVertex FallThroughEdge
        markVertexAsPendingForAnalysis useSSA ctx srcVertex
        markVertexAsRemovalForAnalysis useSSA ctx origVertex
        for e in preds do
          connectEdge ctx e.First srcVertex e.Label
        for e in succs do
          if e.Second.VData.Internals.PPoint = srcPPoint then
            connectEdge ctx dstVertex srcVertex e.Label
          else
            connectEdge ctx dstVertex e.Second e.Label

  let addExpandCFGAction (queue: CFGActionQueue) addr =
    queue.Push prioritizer <| ExpandCFG ([ addr ])

  let getFunctionAbstraction ctx callIns calleeAddr =
    match ctx.ManagerChannel.GetBuildingContext calleeAddr with
    | FinalCtx calleeCtx
    | StillBuilding calleeCtx ->
      summarizer.Summarize (calleeCtx, callIns) |> Ok
    | FailedBuilding -> Error ErrorCase.FailedToRecoverCFG

  let connectAbsVertex ctx (caller: IVertex<LowUIRBasicBlock>) calleeAddr abs =
    let callIns = caller.VData.Internals.LastInstruction
    let callsiteAddr = callIns.Address
    let callee = getAbsVertex ctx callsiteAddr (Some calleeAddr) abs
    connectEdge ctx caller callee CallEdge
    callee, callsiteAddr + uint64 callIns.Length

  let connectRet ctx (callee, fallthroughAddr) =
    match scanBBLs ctx ctx.FunctionMode [ fallthroughAddr ] with
    | Ok dividedEdges ->
      let fallthroughPPoint = ProgramPoint (fallthroughAddr, 0)
      let fallthroughVertex = getVertex ctx fallthroughPPoint
      connectEdge ctx callee fallthroughVertex RetEdge
      reconnectVertices ctx dividedEdges
      Ok fallthroughAddr
    | Error e -> Error e

  let toCFGResult = function
    | Ok _ -> Continue
    | Error e -> FailStop e

  let connectAbsWithFT ctx caller calleeAddr queue =
    let lastIns =
      (caller: IVertex<LowUIRBasicBlock>).VData.Internals.LastInstruction
    getFunctionAbstraction ctx lastIns calleeAddr
    |> Result.map (connectAbsVertex ctx caller calleeAddr)
    |> Result.bind (connectRet ctx)
    |> Result.map (addExpandCFGAction queue)
    |> toCFGResult

  let connectAbsWithoutFT ctx caller calleeAddr =
    let lastIns =
      (caller: IVertex<LowUIRBasicBlock>).VData.Internals.LastInstruction
    getFunctionAbstraction ctx lastIns calleeAddr
    |> Result.map (connectAbsVertex ctx caller calleeAddr)
    |> toCFGResult

  let connectCallEdge ctx queue callSiteAddr calleeAddr isTailCall =
    let caller = ctx.CallerVertices[callSiteAddr]
    if isTailCall then connectAbsWithoutFT ctx caller calleeAddr
    elif ctx.FunctionAddress = calleeAddr then
      (* recursion = 100% returns (not no-ret) *)
      summarizer.Summarize (ctx, caller.VData.Internals.LastInstruction)
      |> connectAbsVertex ctx caller calleeAddr
      |> connectRet ctx
      |> Result.map (addExpandCFGAction queue)
      |> toCFGResult
    else
      match ctx.ManagerChannel.GetNonReturningStatus calleeAddr with
      | NoRet -> connectAbsWithoutFT ctx caller calleeAddr
      | NotNoRet -> connectAbsWithFT ctx caller calleeAddr queue
      | ConditionalNoRet nth ->
        if CondAwareNoretAnalysis.hasNonZero ctx.BinHandle caller nth then
          connectAbsWithoutFT ctx caller calleeAddr
        else connectAbsWithFT ctx caller calleeAddr queue
      | UnknownNoRet -> Utils.futureFeature ()

  let connectIndirectCallEdge ctx queue callSiteAddr =
    let caller = ctx.CallerVertices[callSiteAddr]
    let callIns = caller.VData.Internals.LastInstruction
    let callSite = callIns.Address
    let wordSize = ctx.BinHandle.File.ISA.WordSize
    let abs = summarizer.SummarizeUnknown (ctx, callIns)
    let absV = getAbsVertex ctx callSite None abs
    connectEdge ctx caller absV CallEdge
    connectRet ctx (absV, callSite + uint64 callIns.Length)
    |> Result.map (addExpandCFGAction queue)
    |> toCFGResult

  let connectSyscallEdge ctx callSiteAddr isExit =
    let caller = ctx.CallerVertices[callSiteAddr]
    syscallAnalysis.MakeAbstract (ctx, caller, isExit)
    |> connectAbsVertex ctx caller 0UL
    |> fun callee -> if not isExit then connectRet ctx callee |> ignore
    Continue

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
    Continue

  let recoverIndirectBranches ctx queue insAddr bblAddr =
    match jmptblAnalysis.Identify ctx insAddr bblAddr with
    | Ok jmptbl ->
#if CFGDEBUG
      dbglog ctx.ThreadID "JumpTable"
      <| $"{insAddr:x}: [{jmptbl.TableAddress:x}] w/ base {jmptbl.JumpBase:x}"
#endif
      ctx.ManagerChannel.NotifyJumpTableRecovery (ctx.FunctionAddress, jmptbl)
      |> function
        | true -> pushJmpTblRecoveryAction ctx queue bblAddr jmptbl 0
        | false -> StopAndReload
    | Error _ ->
#if CFGDEBUG
      dbglog ctx.ThreadID "JumpTable" $"{insAddr:x} unknown pattern"
#endif
      Continue (* We ignore this indirect branch. *)

  let isFailedBuilding (ctx: CFGBuildingContext<'FnCtx, 'GlCtx>) calleeAddr =
    match ctx.ManagerChannel.GetBuildingContext calleeAddr with
    | FailedBuilding -> true
    | _ -> false

  let recoverJumpTableEntry ctx queue srcAddr dstAddr =
    let srcVertex = getVertex ctx (ProgramPoint (srcAddr, 0))
    let fnAddr = ctx.FunctionAddress
    if dstAddr < fnAddr || not (isExecutableAddr ctx dstAddr) then
      match ctx.JumpTableRecoveryStatus with
      | Some (tblAddr, 0) ->
        (* The first jump table entry was invalid. For example, the target could
           be outside the boundary of the current function. In this case, we
           conclude that the indirect jump is not using a jump table, and thus,
           we simply ignore the indirect branch. *)
        ctx.ManagerChannel.CancelJumpTableRecovery (fnAddr, tblAddr)
        ctx.ActionQueue.Pop () |> ignore (* pop off `EndTblRec` *)
        Continue
      | _ ->
        FailStop ErrorCase.FailedToRecoverCFG
    else
      match scanBBLs ctx ctx.FunctionMode [ dstAddr ] with
      | Ok dividedEdges ->
        let targetPPoint = ProgramPoint (dstAddr, 0)
        let targetVertex = getVertex ctx targetPPoint
        connectEdge ctx srcVertex targetVertex IndirectJmpEdge
        reconnectVertices ctx dividedEdges
        addExpandCFGAction queue dstAddr
        Continue
      | Error e -> FailStop e

  let sendJmpTblRecoverySuccess ctx queue jmptbl idx =
    let fnAddr = ctx.FunctionAddress
    let tblAddr = jmptbl.TableAddress
    let nextTarget = readJumpTable ctx jmptbl (idx + 1)
    ctx.ManagerChannel.ReportJumpTableSuccess (fnAddr, tblAddr, idx, nextTarget)
    |> function
      | true ->
        let srcVertex = ctx.CallerVertices[jmptbl.InsAddr]
        let srcAddr = srcVertex.VData.Internals.BlockAddress
        pushJmpTblRecoveryAction ctx queue srcAddr jmptbl (idx + 1)
      | false ->
#if CFGDEBUG
        dbglog ctx.ThreadID "JumpTable" $"No more to add"
#endif
        Continue

  let hasReturnNode (ctx: CFGBuildingContext<'FnCtx, 'GlCtx>) =
    ctx.CFG.TryFindVertexBy (fun v ->
      if v.VData.Internals.IsAbstract then
        v.VData.Internals.AbstractContent.ReturningStatus = NotNoRet
      else v.VData.Internals.LastInstruction.IsRET ())
    |> Option.isSome

  new (useSSA) =
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
                 useSSA)

  interface ICFGBuildingStrategy<'FnCtx, 'GlCtx> with
    member __.ActionPrioritizer = prioritizer

    member __.FindCandidates (builders) =
      builders
      |> Array.choose (fun b ->
        if not b.Context.IsExternal then Some <| (b.EntryPoint, b.Mode)
        else None)

    member __.OnAction (ctx, queue, action) =
      try
        match action with
        | InitiateCFG ->
          let fnAddr, mode = ctx.FunctionAddress, ctx.FunctionMode
#if CFGDEBUG
          dbglog ctx.ThreadID (nameof InitiateCFG) $"{fnAddr:x}"
#endif
          let pp = ProgramPoint (fnAddr, 0)
          match scanBBLs ctx mode [ fnAddr ] with
          | Ok _ -> buildCFG ctx queue [| pp |]
          | Error e -> FailStop e
        | ExpandCFG addrs ->
#if CFGDEBUG
          let targets =
            addrs |> Seq.map (fun addr -> $"{addr:x}") |> String.concat ";"
          dbglog ctx.ThreadID (nameof ExpandCFG)
          <| $"{targets} @ {ctx.FunctionAddress:x}"
#endif
          let newPPs = addrs |> Seq.map (fun addr -> ProgramPoint (addr, 0))
          buildCFG ctx queue newPPs
        | MakeCall (callSiteAddr, calleeAddr) ->
#if CFGDEBUG
          dbglog ctx.ThreadID (nameof MakeCall)
          <| $"{ctx.FunctionAddress:x} to {calleeAddr:x}"
#endif
          connectCallEdge ctx queue callSiteAddr calleeAddr false
        | MakeTlCall (callSiteAddr, calleeAddr) ->
#if CFGDEBUG
          dbglog ctx.ThreadID (nameof MakeTlCall)
          <| $"{ctx.FunctionAddress:x} to {calleeAddr:x}"
#endif
          connectCallEdge ctx queue callSiteAddr calleeAddr true
        | MakeIndCall (callSiteAddr) ->
#if CFGDEBUG
          dbglog ctx.ThreadID (nameof MakeIndCall)
          <| $"{callSiteAddr:x} @ {ctx.FunctionAddress:x}"
#endif
          connectIndirectCallEdge ctx queue callSiteAddr
        | MakeSyscall (callSiteAddr, isExit) ->
#if CFGDEBUG
          dbglog ctx.ThreadID (nameof MakeSyscall) $"{ctx.FunctionAddress:x}"
#endif
          connectSyscallEdge ctx callSiteAddr isExit
        | MakeIndEdges (bblAddr, insAddr) ->
#if CFGDEBUG
          dbglog ctx.ThreadID (nameof MakeIndEdges)
          <| $"{bblAddr:x} @ {ctx.FunctionAddress:x}"
#endif
          recoverIndirectBranches ctx queue insAddr bblAddr
        | WaitForCallee calleeAddr ->
#if CFGDEBUG
          dbglog ctx.ThreadID (nameof WaitForCallee)
          <| $"{ctx.FunctionAddress:x} waits for {calleeAddr:x}"
#endif
          if not (ctx.PendingActions.ContainsKey calleeAddr) then
#if CFGDEBUG
            dbglog ctx.ThreadID (nameof WaitForCallee) "-> continue"
#endif
            Continue
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
          ctx.JumpTableRecoveryStatus <- Some (jmptbl.TableAddress, idx)
          recoverJumpTableEntry ctx queue srcAddr dstAddr
        | EndTblRec (jmptbl, idx) ->
#if CFGDEBUG
          dbglog ctx.ThreadID (nameof EndTblRec)
          <| $"{jmptbl.InsAddr:x}[{idx}] @ {ctx.FunctionAddress:x}"
#endif
          jmptbl.NumEntries <- idx + 1
          ctx.JumpTables.Add jmptbl
          ctx.JumpTableRecoveryStatus <- None
          sendJmpTblRecoverySuccess ctx queue jmptbl idx
      with e ->
        Console.Error.WriteLine $"OnAction failed:\n{e}"
        FailStop ErrorCase.FailedToRecoverCFG

    member _.OnFinish (ctx) =
      let oldNoRetStatus = ctx.NonReturningStatus
      ICFGAnalysis.run { Context = ctx } postAnalysis
      let newNoRetStatus = ctx.NonReturningStatus
      match oldNoRetStatus, newNoRetStatus with
      | NoRet, NotNoRet
      | NoRet, ConditionalNoRet _ ->
        let callers = Array.zeroCreate ctx.Callers.Count
        ctx.Callers.CopyTo callers
        ContinueWithCallers callers
      | _ -> Continue

    member _.OnCyclicDependency (deps) =
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

/// Base strategy for building a CFG without any customizable context.
type CFGRecovery =
  inherit CFGRecovery<DummyContext, DummyContext>

  new () =
    { inherit CFGRecovery<DummyContext, DummyContext> (false) }

  new (summarizer,
       jmptblAnalysis,
       syscallAnalysis,
       postAnalysis,
       useTailcallHeuristic) =
    { inherit CFGRecovery<DummyContext, DummyContext> (summarizer,
                                                       jmptblAnalysis,
                                                       syscallAnalysis,
                                                       postAnalysis,
                                                       useTailcallHeuristic,
                                                       false) }
