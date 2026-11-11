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

open System.Collections.Generic
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis

/// Contains common functions for CFG recovery strategies.
module internal CFGRecoveryCommon =
  let inline markVertexAsPendingForAnalysis (ctx: CFGBuildingContext<_, _>) v =
    ctx.CP.State.MarkVertexAsPending v
    ctx.UVA.State.MarkVertexAsPending v

  let inline markVertexAsRemovalForAnalysis (ctx: CFGBuildingContext<_, _>) v =
    ctx.CP.State.MarkVertexAsRemoval v
    ctx.UVA.State.MarkVertexAsRemoval v
    for succ in ctx.CFG.GetSuccs v do
      ctx.CP.State.MarkVertexAsPending succ
      ctx.UVA.State.MarkVertexAsPending succ

  let prioritizer =
    { new IPrioritizable with
        member _.GetPriority action =
          match action with
          | InitiateCFG -> 4
          | ExpandCFG _ -> 4
          | StartGapAnalysis _ -> 4
          | MakeCall _ -> 3
          | MakeTlCall _ -> 3
          | MakeIndCall _ -> 3
          | MakeSyscall _ -> 3
          | MakeIndEdges _ -> 2
          | WaitForCallee _ -> 2
          | ResumeAnalysis _ -> 2
          | UpdateCallEdges _ -> 1
          | StartTblRec _ -> 0
          | EndTblRec _ -> 0
          | RetryIndEdges _ -> -1
          | EndGapAnalysis -> -2 }

  /// Notes that the vertex ends with the call at the call site, unless a vertex
  /// that starts where it does was noted first.
  let addCallerVertex (ctx: CFGBuildingContext<_, _>) callsite vertex =
    let pp = (vertex: IVertex<LowUIRBasicBlock>).VData.Internals.PPoint
    match ctx.CallerVertices.TryGetValue callsite with
    | true, vs when vs.Exists(fun v -> v.VData.Internals.PPoint = pp) -> ()
    | true, vs -> vs.Add vertex
    | false, _ -> ctx.CallerVertices[callsite] <- List [ vertex ]

  /// Returns a vertex that ends with the call at the call site: the one noted
  /// first, when the call switches instruction sets. They all end with the
  /// same instruction.
  let getCallerVertex (ctx: CFGBuildingContext<_, _>) callsite =
    ctx.CallerVertices[callsite][0]

  /// Tries to return a vertex that ends with the call at the call site, as
  /// getCallerVertex does.
  let tryGetCallerVertex (ctx: CFGBuildingContext<_, _>) callsite =
    match ctx.CallerVertices.TryGetValue callsite with
    | true, vs -> Some vs[0]
    | false, _ -> None

  /// Replaces the vertex that ended with the call at the call site until a
  /// division removed it from the CFG with the given vertex, which ends with
  /// the call now. A block divided more than once in a scan has had its vertex
  /// replaced by then, so the start of the vertex does not tell which it was.
  let replaceCallerVertex (ctx: CFGBuildingContext<_, _>) callsite vertex =
    let isRemoved (v: IVertex<LowUIRBasicBlock>) =
      match ctx.Vertices.TryGetValue v.VData.Internals.PPoint with
      | true, current -> not (obj.ReferenceEquals(current, v))
      | false, _ -> true
    match ctx.CallerVertices.TryGetValue callsite with
    | true, vs ->
      let idx = vs.FindIndex isRemoved
      if idx < 0 then () else vs[idx] <- vertex
    | false, _ ->
      ()

  let scanBBLs (ctx: CFGBuildingContext<_, _>) entryPoints =
    ctx.ScanBBLs entryPoints

  let pushAction (ctx: CFGBuildingContext<_, _>) action =
    ctx.ActionQueue.Push(action)

  let getCalleePPoint callsite calleeAddrOpt =
    match calleeAddrOpt with
    | Some addr -> ProgramPoint(callsite, addr, 0)
    | None -> ProgramPoint(callsite, 0UL, -1)

  let isDuringGapAnalysis (ctx: CFGBuildingContext<_, _>) =
    ctx.GapToAnalyze.IsSome

  let makeVertex ctx (cfgRec: ICFGRecovery<_, _>) pp (bbl: LowUIRBasicBlock) =
    let v = (ctx: CFGBuildingContext<_, _>).CFG.AddVertex bbl
    ctx.Vertices[pp] <- v
    cfgRec.OnAddVertex(ctx, v)
    if isDuringGapAnalysis ctx then ctx.GapAnalysisVertices.Add(pp) |> ignore
    else ()
    (* The block outlives a rebuild, so it drops what an earlier build set. *)
    bbl.DominatingJumpTableEntry <-
      match ctx.JumpTableRecoveryStatus.TryPeek() with
      | true, status -> Some status
      | false, _ -> None
    v

  let makeAbsVertex ctx (cfgRec: ICFGRecovery<_, _>) csAddr calleeOpt abs =
    let pp = getCalleePPoint csAddr calleeOpt
    let bbl = LowUIRBasicBlock.CreateAbstract(pp, abs)
    let v = (ctx: CFGBuildingContext<_, _>).CFG.AddVertex bbl
    ctx.Vertices[pp] <- v
    cfgRec.OnAddVertex(ctx, v)
    if isDuringGapAnalysis ctx then ctx.GapAnalysisVertices.Add(pp) |> ignore
    else ()
    v

  /// Retrieves a vertex (which is either cached or newly created). This
  /// function can raise an exception if the given program point has no
  /// corresponding basic block in the BBL factory, i.e., bad instruction(s),
  /// etc.
  let getVertex (ctx: CFGBuildingContext<_, _>) cfgRec ppoint =
    match ctx.Vertices.TryGetValue ppoint with
    | true, v ->
      v
    | false, _ ->
      let bbl = ctx.BBLFactory.Find ppoint
      makeVertex ctx cfgRec ppoint bbl

  let getAbsVertex ctx cfgRec callsiteAddr calleeAddrOpt abs =
    let calleePPoint = getCalleePPoint callsiteAddr calleeAddrOpt
    match (ctx: CFGBuildingContext<_, _>).Vertices.TryGetValue calleePPoint with
    | true, v -> v
    | false, _ -> makeAbsVertex ctx cfgRec callsiteAddr calleeAddrOpt abs

  let doesAbsVertexExist ctx callsiteAddr calleeAddr =
    getCalleePPoint callsiteAddr (Some calleeAddr)
    |> (ctx: CFGBuildingContext<_, _>).Vertices.ContainsKey

  let isStaticallyLinked (ctx: CFGBuildingContext<_, _>) =
    Option.isNone ctx.BinHandle.File.InterpreterPath

  let postponeActionOnCallee (ctx: CFGBuildingContext<_, _>) calleeAddr action =
    let pendingCallActions = ctx.PendingCallActions
    let queue = ctx.ActionQueue
    let lst =
      match pendingCallActions.TryGetValue calleeAddr with
      | false, _ ->
        let lst = List()
        pendingCallActions[calleeAddr] <- lst
        queue.Push(WaitForCallee calleeAddr)
        lst
      | true, lst ->
        lst
    lst.Add action

  /// Tries to remove a vertex in the CFG whose program point is given as
  /// `ppoint` and returns its predecessors and successors. When there's no
  /// such vertex, this returns empty arrays.
  let tryRemoveVertexAt ctx (cfgRec: ICFGRecovery<_, _>) ppoint =
    match (ctx: CFGBuildingContext<_, _>).Vertices.TryGetValue ppoint with
    | true, v ->
      let preds =
        ctx.CFG.GetPredEdges v
        |> Array.filter (fun e -> e.First.VData.Internals.PPoint <> ppoint)
      let succs = ctx.CFG.GetSuccEdges(v)
      cfgRec.OnRemoveVertex(ctx, v)
      ctx.CFG.RemoveVertex(v)
      ctx.Vertices.Remove(ppoint) |> ignore
      ctx.VisitedPPoints.Remove(ppoint) |> ignore
      preds, succs
    | false, _ ->
      [||], [||]

  let isFromUnreachablesToReachables (ctx: CFGBuildingContext<_, _>) srcV dstV =
    let srcPP = (srcV: IVertex<LowUIRBasicBlock>).VData.Internals.PPoint
    let dstPP = (dstV: IVertex<LowUIRBasicBlock>).VData.Internals.PPoint
    ctx.GapAnalysisVertices.Contains(srcPP)
    && not <| ctx.GapAnalysisVertices.Contains(dstPP)

  let connectEdge (ctx: CFGBuildingContext<_, _>) cfgRec srcV dstV edgeKind =
    if isFromUnreachablesToReachables ctx srcV dstV then
      ()
    else
      ctx.CFG.AddEdge(srcV, dstV, edgeKind)
      (cfgRec: ICFGRecovery<_, _>).OnAddEdge(ctx, srcV, dstV, edgeKind)
#if CFGDEBUG
      let edgeStr = CFGEdgeKind.toString edgeKind
      let srcPP = (srcV.VData :> IAddressable).PPoint
      let dstPP = (dstV.VData :> IAddressable).PPoint
      dbglog ctx.ThreadID "ConnectEdge" $"{srcPP} -> {dstPP} ({edgeStr})"
#endif

  let reconnectVertices ctx
                        (cfgRec: ICFGRecovery<_, _>)
                        (dividedEdges: (ProgramPoint * ProgramPoint) seq) =
    for (srcPPoint, dstPPoint) in dividedEdges do
      let srcVertex = getVertex ctx cfgRec srcPPoint
      let isSrcRoot = ctx.CFG.Roots |> Array.contains srcVertex
      let entry = srcVertex.VData.DominatingJumpTableEntry
      let preds, succs = tryRemoveVertexAt ctx cfgRec srcPPoint
      if Array.isEmpty preds && Array.isEmpty succs then
        (* Don't reconnect previously unseen blocks, which can be introduced by
           tail-calls. N.B. BBLFactory cannot see tail-calls. *)
        ()
      else
        let srcVertex = getVertex ctx cfgRec srcPPoint
        (* The code before the division came from the same entry as before. *)
        srcVertex.VData.DominatingJumpTableEntry <- entry
        let dstVertex = getVertex ctx cfgRec dstPPoint
        if isSrcRoot then (* If a root was re-added, register this again. *)
          ctx.CFG.AddRoot(srcVertex) |> ignore
        else
          ()
#if CFGDEBUG
        dbglog ctx.ThreadID "Reconnect" $"{srcPPoint} -> {dstPPoint}"
#endif
        let lastAddr = dstVertex.VData.Internals.LastInstruction.Address
        let callsite = LeafCallSite lastAddr
        replaceCallerVertex ctx callsite dstVertex
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
    Ok()

  let isWithinFunction (ctx: CFGBuildingContext<_, _>) fnAddr dstAddr =
    match ctx.ManagerChannel.GetNextFunctionAddress fnAddr with
    | Some nextFnAddr -> dstAddr < nextFnAddr
    | None -> true

  /// Checks if the given address lies within a reachable vertex, past its
  /// start, while a gap analysis runs. A gap analysis keeps reachable vertices
  /// whole even when a scan divides their blocks, so a vertex at the address
  /// would overlap the one that holds it.
  let isWithinReachables (ctx: CFGBuildingContext<_, _>) addr =
    isDuringGapAnalysis ctx
    && ctx.Vertices
       |> Seq.exists (fun (KeyValue(pp, v)) ->
         let range = v.VData.Internals.Range
         not v.VData.Internals.IsAbstract
         && not <| ctx.GapAnalysisVertices.Contains pp
         && range.Min < addr && addr <= range.Max)

  /// Retrieves a vertex (which is either cached or newly created) for the given
  /// program point only if the vertex is valid, i.e., the vertex is within the
  /// range of the current function, and not within a reachable vertex while a
  /// gap analysis runs. This function is more expensive than `getVertex`, but
  /// needs to be used when the target program point is not guaranteed to be
  /// valid.
  let getValidVertex (ctx: CFGBuildingContext<_, _>) cfgRec pp =
    match ctx.Vertices.TryGetValue pp with
    | true, v ->
      Ok v
    | false, _ ->
      match ctx.BBLFactory.TryFind pp with
      | Ok bbl ->
        let range = bbl.Internals.Range
        if not <| isWithinFunction ctx ctx.FunctionAddress range.Max then
          ctx.BlocksPastBoundary.Add range
          Error ErrorCase.ItemNotFound
        elif isWithinReachables ctx (pp: ProgramPoint).Address then
          Error ErrorCase.ItemNotFound
        else
          Ok(makeVertex ctx cfgRec pp bbl)
      | Error _ ->
        Error ErrorCase.ItemNotFound

  /// Checks if an edge that has the given address as a destination goes from
  /// unreachables to reachables, into the middle of a reachable vertex: the
  /// scan for the edge divides its block there, or an earlier scan has.
  let isIntrudingReachables ctx dstAddr dividedEdges =
    dividedEdges
    |> Seq.exists (fun (srcPP, dstPP) ->
      isDuringGapAnalysis ctx
      && (dstPP: ProgramPoint).Address = dstAddr
      && not <| ctx.GapAnalysisVertices.Contains(srcPP))
    || isWithinReachables ctx dstAddr

  /// Filters out divided edges caused by edges that go from unreachables to
  /// reachables.
  let excludeUnreachableIncomings (ctx: CFGBuildingContext<_, _>) dividedEdges =
    if not <| isDuringGapAnalysis ctx then dividedEdges
    else dividedEdges |> Seq.filter (fst >> ctx.GapAnalysisVertices.Contains)

  let scanBBLsAndConnect ctx cfgRec src dstAddr edgeKind =
    match scanBBLs ctx [ dstAddr ] with
    | Ok(dividedEdges) when isIntrudingReachables ctx dstAddr dividedEdges ->
      Ok(())
    | Ok(dividedEdges) ->
      let dstPPoint = ProgramPoint(dstAddr, 0)
      let dividedEdges = excludeUnreachableIncomings ctx dividedEdges
      match getValidVertex ctx cfgRec dstPPoint with
      | Ok dstVertex ->
        connectEdge ctx cfgRec src dstVertex edgeKind
        reconnectVertices ctx cfgRec dividedEdges
        addExpandCFGAction ctx dstPPoint
      | Error e ->
        Error e
    | Error e ->
      Error e

  let toCFGResult = function
    | Ok _ -> MoveOn
    | Error e -> FailStop e

  let isExecutableAddr (ctx: CFGBuildingContext<_, _>) targetAddr =
    ctx.BinHandle.File.IsExecutableAddr targetAddr

  /// Adds the dependency of the function on the callee of the given action,
  /// returning the status of the callee. The function notes a callee that it
  /// calls as its tail only on the guess that a function starts there, which
  /// it refutes once built if it reaches the code there otherwise.
  let addDependency (ctx: CFGBuildingContext<_, _>) calleeAddr action =
    let fnAddr = ctx.FunctionAddress
    match action with
    | MakeTlCall _ ->
      match ctx.ManagerChannel.AddTailCallDependency(fnAddr, calleeAddr) with
      | KnownTailCallee status ->
        status
      | GuessedTailCallee status ->
        ctx.GuessedTailCallees.Add calleeAddr |> ignore
        status
    | _ ->
      ctx.ManagerChannel.AddDependency(fnAddr, calleeAddr)

  let handleResolvedCall ctx cfgRec callerPPoint callsite calleeAddr action =
    let fnAddr = (ctx: CFGBuildingContext<_, _>).FunctionAddress
    let actionQueue = ctx.ActionQueue
    addCallerVertex ctx callsite (getVertex ctx cfgRec callerPPoint)
    ctx.IntraCallTable.AddRegularCall(callsite, calleeAddr)
    if fnAddr = calleeAddr then (* self-recursion *)
      actionQueue.Push(action)
    else
      match addDependency ctx calleeAddr action with
      (* Wait for the callee to finish. *)
      | Building
      | Failed ->
        postponeActionOnCallee ctx calleeAddr action
      (* Directly push the given action into its action queue. *)
      | Built calleeInfo ->
        match action with
        | MakeCall _ -> MakeCall(callsite, calleeAddr, calleeInfo)
        | MakeTlCall _ -> MakeTlCall(callsite, calleeAddr, calleeInfo)
        | _ -> action
        |> pushAction ctx
    MoveOn

  let handleCall ctx cfgRec rules srcVertex callsite calleeAddr action =
    let srcBBL: ILowUIRBasicBlock = (srcVertex: IVertex<_>).VData
    (* When a caller node is split into multiple nodes, we can detect the same
       abs-vertex multiple times. So we'd better check duplicates here. *)
    if doesAbsVertexExist ctx callsite calleeAddr then
      MoveOn
    elif (rules: ICFGRecoveryRules<_, _>).IsGetPCThunk(ctx, srcBBL, calleeAddr)
    then
      scanBBLsAndConnect ctx cfgRec srcVertex calleeAddr InterJmpEdge
      |> toCFGResult
    (* If an address 0 is encountered (i.e., call 0) and the binary is
       statically linked, it is likely that this block is unreachable but left
       in the binary. *)
    elif isStaticallyLinked ctx && calleeAddr = 0x0UL then
      (* We treat this call as an indirect call to an unknown function. *)
      addCallerVertex ctx callsite srcVertex
      pushAction ctx <| MakeIndCall(callsite)
      MoveOn
    elif isExecutableAddr ctx calleeAddr then
      handleResolvedCall ctx cfgRec srcBBL.PPoint callsite calleeAddr action
    else
      FailStop ErrorCase.FailedToRecoverCFG

  /// Resolves a call whose target is loaded from a PC-relative relocation
  /// slot.
  let tryHandleRelocationBackedCall ctx cfgRec rules srcVertex isTailCall e =
    let srcBBL: ILowUIRBasicBlock = (srcVertex: IVertex<_>).VData
    let ppoint = srcBBL.PPoint
    match e with
    | Load(Addr = BinOp(Op = BinOpType.ADD; Left = PCVar _; Right = Num bv)) ->
      (* Only a real block loads through the PC; an abstract vertex, which
         summarizes a callee, has no instruction to take the address of. *)
      let callsiteAddr = srcBBL.LastInstruction.Address
      let callsite = LeafCallSite callsiteAddr
      let relocationSlotAddr = callsiteAddr + bv.ToUInt64()
      let file = (ctx: CFGBuildingContext<_, _>).BinHandle.File
      match BinFileOps.tryResolveRelocationValue file relocationSlotAddr with
      | Ok(BinFile.BinRelocationValue.Bound name) ->
        let ch = ctx.ManagerChannel
        let reference = RelocationSlot relocationSlotAddr
        match ch.GetExternalCalleeStatus(reference, name) with
        | Built calleeInfo ->
          let action =
            if isTailCall then
              MakeTlCall(callsite, relocationSlotAddr, calleeInfo)
            else
              MakeCall(callsite, relocationSlotAddr, calleeInfo)
          action
          |> handleResolvedCall ctx cfgRec ppoint callsite relocationSlotAddr
          |> Some
        | _ ->
          Terminator.impossible ()
      | Ok(BinFile.BinRelocationValue.Rebased target) ->
        let action =
          if isTailCall then
            MakeTlCall(callsite, target, CalleeInfo.Unknown)
          else
            MakeCall(callsite, target, CalleeInfo.Unknown)
        Some(handleCall ctx cfgRec rules srcVertex callsite target action)
      | Error _ ->
        None
    | _ ->
      None

  /// Tries to get a vertex (which is either cached or newly created).
  let tryGetVertex (ctx: CFGBuildingContext<_, _>) cfgRec ppoint =
    match ctx.Vertices.TryGetValue ppoint with
    | true, v ->
      Ok v
    | false, _ ->
      match ctx.BBLFactory.TryFind ppoint with
      | Ok bbl -> Ok(makeVertex ctx cfgRec ppoint bbl)
      | Error _ -> Error ErrorCase.ItemNotFound

  let connectEdgeIfValid ctx
                         cfgRec
                         (ppQueue: Queue<_>)
                         srcVertex
                         edgeKind
                         dstPPoint =
    match getValidVertex ctx cfgRec dstPPoint with
    | Ok dstVertex ->
      connectEdge ctx cfgRec srcVertex dstVertex edgeKind
      ppQueue.Enqueue dstPPoint
    | Error _ ->
      ()

  let maskedPPoint (ctx: CFGBuildingContext<_, _>) targetAddr =
    let rt = ctx.BinHandle.ISA.WordSize |> WordSize.toRegType
    let mask = (BitVector.UnsignedMax rt).ToUInt64()
    ProgramPoint(targetAddr &&& mask, 0)

  let jmpToDstAddr ctx cfgRec (ppQueue: Queue<_>) srcVertex dstAddr jmpKind =
    let dstPPoint = maskedPPoint ctx dstAddr
    match getValidVertex ctx cfgRec dstPPoint with
    | Ok dstVertex ->
      connectEdge ctx cfgRec srcVertex dstVertex jmpKind
      ppQueue.Enqueue dstPPoint
    | Error _ ->
      ()

  /// Connects a vertex that ends in the middle of an instruction to the vertex
  /// holding the next statement of the very same instruction. The destination
  /// is derived from the source vertex itself; peeking at the work queue would
  /// pick up an unrelated program point that happens to be scheduled next.
  let makeIntraFallThroughEdge ctx cfgRec (ppQueue: Queue<_>) srcVertex =
    let bbl = (srcVertex: IVertex<LowUIRBasicBlock>).VData.Internals
    let lastIns = Array.last bbl.LiftedInstructions
    let nextPos = bbl.PPoint.Position + lastIns.Stmts.Length
    let nextPPoint = ProgramPoint(lastIns.Original.Address, nextPos)
    match tryGetVertex ctx cfgRec nextPPoint with
    | Ok dstVertex ->
      connectEdge ctx cfgRec srcVertex dstVertex FallThroughEdge
      ppQueue.Enqueue nextPPoint
    | Error _ ->
      ()

  let isFuncEntryPoint (ctx: CFGBuildingContext<_, _>) addr =
    match ctx.ManagerChannel.GetCalleeStatus addr with
    | Building | Built _ -> true
    | Failed -> false

  /// Checks if a block that the function has built covers the given address.
  let coversAddr (ctx: CFGBuildingContext<_, _>) addr =
    ctx.CFG.Vertices
    |> Array.exists (fun v ->
      let bbl = v.VData.Internals
      not bbl.IsAbstract && bbl.Range.IsIncluding addr)

  /// Checks if a block that the function reaches but leaves out, as it runs
  /// past where the next function starts, covers the given address.
  let leavesOutAddr (ctx: CFGBuildingContext<_, _>) addr =
    ctx.BlocksPastBoundary
    |> Seq.exists (fun (range: AddrRange) -> range.IsIncluding addr)

  /// Checks if a block that the function has built branches to the given
  /// address on a condition.
  let branchesOnConditionTo (ctx: CFGBuildingContext<_, _>) addr =
    ctx.CFG.Vertices
    |> Array.exists (fun v ->
      let bbl = v.VData.Internals
      not bbl.IsAbstract
      && bbl.LastInstruction.IsCondBranch
      && bbl.LastInstruction.DirectBranchTarget() = (true, addr))

  /// Checks if a block that the function has built runs on into the given
  /// address, ending right before it in an instruction that does not branch.
  let runsOnInto (ctx: CFGBuildingContext<_, _>) addr =
    ctx.CFG.Vertices
    |> Array.exists (fun v ->
      let bbl = v.VData.Internals
      not bbl.IsAbstract
      && not bbl.LastInstruction.IsBranch
      && bbl.LastInstruction.Address + uint64 bbl.LastInstruction.Length = addr)

  /// Checks if the function reaches the given address otherwise than by a jump
  /// that calls a function there as its tail: its code covers the address, or
  /// branches there on a condition, or runs on into it, right up to it or past
  /// where the next function starts.
  let reachesOtherwise ctx addr =
    coversAddr ctx addr
    || leavesOutAddr ctx addr
    || branchesOnConditionTo ctx addr
    || runsOnInto ctx addr

  /// Connects the given vertex to the true target of the conditional jump that
  /// ends it, or calls the function there when the jump is a tail call.
  let connectTrueTarget ctx cfgRec rules queue useTCHeuristic srcVertex tpp =
    let bbl = (srcVertex: IVertex<LowUIRBasicBlock>).VData.Internals
    let jmpAddr = bbl.LastInstruction.Address
    let target = (tpp: ProgramPoint).Address
    let callee = (rules: ICFGRecoveryRules<_, _>).ToCalleeAddr(ctx, target)
    if useTCHeuristic && rules.IsCondTailCall(ctx, jmpAddr, callee) then
      let callsite = LeafCallSite jmpAddr
      let act = MakeTlCall(callsite, callee, CalleeInfo.Unknown)
      handleCall ctx cfgRec rules srcVertex callsite callee act
    else
      connectEdgeIfValid ctx cfgRec queue srcVertex InterCJmpTrueEdge tpp
      MoveOn

  /// Checks if the jump at jmpAddr calls the function at callee as its tail:
  /// the rules tell so, or they guess so and no guess that a function starts
  /// there has been refuted.
  let isTailCall ctx (rules: ICFGRecoveryRules<_, _>) jmpAddr callee =
    match rules.JudgeTailCall(ctx, jmpAddr, callee) with
    | TailCall -> true
    | TentativeTailCall -> ctx.ManagerChannel.GuessTailCallee callee
    | NotTailCall -> false

  /// Calls the function that the call ending the given vertex enters at target.
  let handleDirectCall ctx cfgRec rules srcVertex target =
    let bbl = (srcVertex: IVertex<LowUIRBasicBlock>).VData.Internals
    let callsite = LeafCallSite bbl.LastInstruction.Address
    let callee = (rules: ICFGRecoveryRules<_, _>).ToCalleeAddr(ctx, target)
    let act = MakeCall(callsite, callee, CalleeInfo.Unknown)
    handleCall ctx cfgRec rules srcVertex callsite callee act

  /// Checks if the code that goes on to the given address runs into the entry
  /// of another function, as code written by hand does that shares the rest
  /// of a function, such as __subdf3 of libgcc, which runs into __adddf3.
  let runsIntoOtherFunction (ctx: CFGBuildingContext<_, _>) addr =
    addr <> ctx.FunctionAddress && isFuncEntryPoint ctx addr

  /// Calls the function that the code ending the given vertex runs into at the
  /// given entry as its tail.
  let handleRunInto ctx cfgRec rules srcVertex entry =
    let bbl = (srcVertex: IVertex<LowUIRBasicBlock>).VData.Internals
    let callsite = LeafCallSite bbl.LastInstruction.Address
    let act = MakeTlCall(callsite, entry, CalleeInfo.Unknown)
    handleCall ctx cfgRec rules srcVertex callsite entry act

  /// Matches the kind of a call that switches 32-bit ARM to the other
  /// instruction set, telling the one the callee starts in.
  [<return: Struct>]
  let (|ModeSwitchingCall|_|) (kind: InterJmpKind) =
    if kind = (InterJmpKind.IsCall ||| InterJmpKind.SwitchToThumb) then
      ValueSome ARM32Mode.Thumb
    elif kind = (InterJmpKind.IsCall ||| InterJmpKind.SwitchToARM) then
      ValueSome ARM32Mode.ARM
    else
      ValueNone

  /// Matches the kind of a jump that switches 32-bit ARM to the instruction
  /// set that the function is in already. Of the two jumps that a branch which
  /// may switch ends in, this is the only one that can stay in the function.
  [<return: Struct>]
  let (|SameModeJump|_|) (ctx: CFGBuildingContext<_, _>) kind =
    match ctx.EntryMode with
    | ARM32Mode.Thumb when kind = InterJmpKind.SwitchToThumb -> ValueSome()
    | ARM32Mode.ARM when kind = InterJmpKind.SwitchToARM -> ValueSome()
    | _ -> ValueNone

  /// Builds a CFG starting from the given program points.
  let buildCFG ctx
               cfgRec
               (rules: ICFGRecoveryRules<_, _>)
               (syscallAnalysis: ISyscallAnalyzable)
               useTailcallHeuristic
               (actionQueue: CFGActionQueue)
               initPPs =
    let queue = Queue<ProgramPoint>(collection = initPPs)
    let connectTrue =
      connectTrueTarget ctx cfgRec rules queue useTailcallHeuristic
    let mutable result = MoveOn
    while queue.Count > 0 && result = MoveOn do
      let ppoint = queue.Dequeue()
      if not <| (ctx: CFGBuildingContext<_, _>).VisitedPPoints.Add ppoint then
        ()
      else
        let srcVertex = getVertex ctx cfgRec ppoint
        let srcBBL = srcVertex.VData
        let srcData = srcBBL :> ILowUIRBasicBlock
        match srcData.Terminator with
        | IEMark _ ->
          let last = srcData.LastInstruction
          let nextAddr = last.Address + uint64 last.Length
          if useTailcallHeuristic && runsIntoOtherFunction ctx nextAddr then
            result <- handleRunInto ctx cfgRec rules srcVertex nextAddr
          else
            let nextPPoint = ProgramPoint(nextAddr, 0)
            match tryGetVertex ctx cfgRec nextPPoint with
            | Ok dstVertex ->
              connectEdge ctx cfgRec srcVertex dstVertex FallThroughEdge
              queue.Enqueue nextPPoint
            | Error _ ->
              () (* Ignore when a bad instruction follows *)
        | Jmp(Target = JmpDest(Target = lbl)) ->
          let dstPPoint = srcBBL.LabelMap[lbl]
          let dstVertex = getVertex ctx cfgRec dstPPoint
          connectEdge ctx cfgRec srcVertex dstVertex IntraJmpEdge
          queue.Enqueue dstPPoint
        | CJmp(TrueTarget = JmpDest(Target = tLbl)
               FalseTarget = JmpDest(Target = fLbl)) ->
          let tPPoint, fPPoint = srcBBL.LabelMap[tLbl], srcBBL.LabelMap[fLbl]
          let tVertex, fVertex =
            getVertex ctx cfgRec tPPoint, getVertex ctx cfgRec fPPoint
          connectEdge ctx cfgRec srcVertex tVertex IntraCJmpTrueEdge
          connectEdge ctx cfgRec srcVertex fVertex IntraCJmpFalseEdge
          queue.Enqueue tPPoint
          queue.Enqueue fPPoint
        (* intra loop *)
        | InterJmp(Target = PCVar _; Kind = InterJmpKind.Base) ->
          let dstPPoint = ProgramPoint(ppoint.Address, 0)
          let dstVertex = getVertex ctx cfgRec dstPPoint
          connectEdge ctx cfgRec srcVertex dstVertex InterJmpEdge
        | InterJmp(Target = BinOp(Op = BinOpType.ADD
                                  Left = PCVar _
                                  Right = Num(Value = n))
                   Kind = InterJmpKind.Base) ->
          let target = srcData.LastInstruction.Address + n.ToUInt64()
          jmpToDstAddr ctx cfgRec queue srcVertex target InterJmpEdge
        | InterJmp(Target = Num(Value = n); Kind = InterJmpKind.Base) ->
          let target = n.ToUInt64()
          let lastInsAddr = srcData.LastInstruction.Address
          if useTailcallHeuristic then
            let callee = rules.ToCalleeAddr(ctx, target)
            if not <| isTailCall ctx rules lastInsAddr callee then
              jmpToDstAddr ctx cfgRec queue srcVertex target InterJmpEdge
            else
              let callSite = LeafCallSite lastInsAddr
              let act = MakeTlCall(callSite, callee, CalleeInfo.Unknown)
              result <-
                handleCall ctx cfgRec rules srcVertex callSite callee act
          else
            jmpToDstAddr ctx cfgRec queue srcVertex target InterJmpEdge
        | InterJmp(Target = BinOp(Op = BinOpType.ADD
                                  Left = PCVar _
                                  Right = Num(Value = n))
                   Kind = InterJmpKind.IsCall) ->
          let lastInsAddr = srcData.LastInstruction.Address
          let callsite = LeafCallSite lastInsAddr
          let target = lastInsAddr + n.ToUInt64()
          let act = MakeCall(callsite, target, CalleeInfo.Unknown)
          result <- handleCall ctx cfgRec rules srcVertex callsite target act
        | InterJmp(Target = Num(Value = n); Kind = InterJmpKind.IsCall) ->
          result <- handleDirectCall ctx cfgRec rules srcVertex (n.ToUInt64())
        | InterJmp(Target = Num(Value = n); Kind = ModeSwitchingCall mode) ->
          ctx.ManagerChannel.NoteEntryMode(n.ToUInt64(), mode)
          result <- handleDirectCall ctx cfgRec rules srcVertex (n.ToUInt64())
        | InterCJmp(TrueTarget = BinOp(Op = BinOpType.ADD
                                       Left = PCVar _
                                       Right = Num(Value = tv))
                    FalseTarget = BinOp(Op = BinOpType.ADD
                                        Left = PCVar _
                                        Right = Num(Value = fv))) ->
          let lastAddr = (srcBBL :> ILowUIRBasicBlock).LastInstruction.Address
          let tpp = maskedPPoint ctx (lastAddr + tv.ToUInt64())
          let fpp = maskedPPoint ctx (lastAddr + fv.ToUInt64())
          result <- connectTrue srcVertex tpp
          connectEdgeIfValid ctx cfgRec queue srcVertex InterCJmpFalseEdge fpp
        | InterCJmp(TrueTarget = BinOp(Op = BinOpType.ADD
                                       Left = PCVar _
                                       Right = Num(Value = tv))
                    FalseTarget = PCVar _) ->
          let lastAddr = (srcBBL :> ILowUIRBasicBlock).LastInstruction.Address
          let tpp = maskedPPoint ctx (lastAddr + tv.ToUInt64())
          let fPPoint = maskedPPoint ctx lastAddr
          let fVertex = getVertex ctx cfgRec fPPoint
          connectEdgeIfValid ctx cfgRec queue srcVertex InterCJmpTrueEdge tpp
          connectEdge ctx cfgRec srcVertex fVertex InterCJmpFalseEdge
        | InterCJmp(TrueTarget = PCVar _
                    FalseTarget = BinOp(Op = BinOpType.ADD
                                        Left = PCVar _
                                        Right = Num(Value = fv))) ->
          let lastAddr = (srcBBL :> ILowUIRBasicBlock).LastInstruction.Address
          let tpp = maskedPPoint ctx lastAddr
          let fpp = maskedPPoint ctx (lastAddr + fv.ToUInt64())
          let tVertex = getVertex ctx cfgRec tpp
          connectEdge ctx cfgRec srcVertex tVertex InterCJmpTrueEdge
          connectEdgeIfValid ctx cfgRec queue srcVertex InterCJmpFalseEdge fpp
        | InterCJmp(TrueTarget = Num(Value = tv)
                    FalseTarget = Num(Value = fv)) ->
          let tpp = maskedPPoint ctx (tv.ToUInt64())
          let fpp = maskedPPoint ctx (fv.ToUInt64())
          result <- connectTrue srcVertex tpp
          connectEdgeIfValid ctx cfgRec queue srcVertex InterCJmpFalseEdge fpp
        | InterJmp(Kind = SameModeJump ctx)
          when srcData.LastInstruction.IsRET ->
          ()
        | InterJmp(Target = e; Kind = InterJmpKind.Base)
        | InterJmp(Target = e; Kind = SameModeJump ctx) -> (* Indirect jmp *)
          let resolved =
            tryHandleRelocationBackedCall ctx cfgRec rules srcVertex true e
          match resolved with
          | Some r ->
            result <- r
          | None ->
            cfgRec.AnalyzeIndirectJump(ctx, srcVertex)
            |> Option.iter (fun r -> result <- r)
        | InterJmp(Target = e; Kind = InterJmpKind.IsCall)
        | InterJmp(Target = e; Kind = ModeSwitchingCall _) -> (* Ind call *)
          let callsiteAddr = srcData.LastInstruction.Address
          let callsite = LeafCallSite callsiteAddr
          let resolved =
            tryHandleRelocationBackedCall ctx cfgRec rules srcVertex false e
          match resolved with
          | Some r ->
            result <- r
          | None ->
            addCallerVertex ctx callsite srcVertex
            actionQueue.Push(MakeIndCall(callsite))
        | InterCJmp _ -> (* Indirect cond jumps *)
          cfgRec.AnalyzeIndirectCondJump(ctx, srcVertex)
          |> Option.iter (fun r -> result <- r)
        | SideEffect(Effect = Interrupt 0x80) | SideEffect(Effect = SysCall) ->
          let callsiteAddr = srcData.LastInstruction.Address
          let callsite = LeafCallSite callsiteAddr
          let isExit = syscallAnalysis.IsExit(ctx, srcVertex)
          ctx.IntraCallTable.AddSystemCall(callsite, isExit)
          addCallerVertex ctx callsite srcVertex
          actionQueue.Push(MakeSyscall(callsite, isExit))
        | Jmp _
        | CJmp _
        | InterJmp _
        | InterCJmp _
        | SideEffect(Effect = UndefinedInstruction)
        | SideEffect(Effect = Exception _)
        | SideEffect(Effect = Terminate)
        | SideEffect(Effect = Breakpoint) ->
          ()
#if DEBUG
        | ISMark _ | LMark _ ->
          Terminator.impossible ()
#endif
        | _ ->
          makeIntraFallThroughEdge ctx cfgRec queue srcVertex
    done
    result

  let getFunctionSummary ctx
                         (summarizer: IFunctionSummarizable<_, _>)
                         callIns
                         calleeAddr
                         calleeInfo =
    let ch = (ctx: CFGBuildingContext<_, _>).ManagerChannel
    match ch.GetCalleeStatus calleeAddr with
    | Built _
    | Building ->
      Ok <| summarizer.Summarize(ctx, calleeAddr, calleeInfo, callIns)
    | Failed ->
      Error ErrorCase.FailedToRecoverCFG

  /// Computes how far the stack pointer moves between a call site and the
  /// landing pad it unwinds to. The two canonical frame addresses tell us how
  /// deep each point is in the frame; on top of that difference the return
  /// address pushed by the call is also popped. Falls back to unwinding just
  /// the return address when the CFAs are not both stack-pointer-relative.
  let getExceptionUnwindingAmount (hdl: BinHandle) callsiteAddr lpAddr =
    let wordSize = hdl.ISA.WordSize |> WordSize.toByteWidth
    match hdl.File with
    | :? BinFile.ELFBinFile as elf ->
      let csCFA = elf.TryFindCFARegOffset callsiteAddr
      let lpCFA = elf.TryFindCFARegOffset lpAddr
      match csCFA, lpCFA with
      | Some(rid1, off1), Some(rid2, off2) when
          hdl.RegisterFactory.IsStackPointer rid1
          && hdl.RegisterFactory.IsStackPointer rid2 ->
        off1 - off2 + wordSize
      | _ ->
        wordSize
    | _ ->
      wordSize

  /// Creates an exception abstraction. Without calculating CFA, we can compute
  /// how much stack pointer is adjusted before entering the landing pad, as we
  /// introduce this abstraction only after a function call and thus we can
  /// simply unwind the stack by the size of a single element for the return
  /// address pushed by the call instruction.
  let getExceptionAbstraction (hdl: BinHandle) callsiteAddr lpAddr =
    let rid = hdl.RegisterFactory.StackPointer.Value
    let rname = hdl.RegisterFactory.GetRegisterName(rid)
    let rt = hdl.RegisterFactory.GetRegType(rid)
    let dst = LowUIR.AST.var rt rid rname
    let sp = LowUIR.AST.var rt rid rname
    let unwinding = getExceptionUnwindingAmount hdl callsiteAddr lpAddr
    let unwindingAmount = BitVector(unwinding, rt) |> LowUIR.AST.num
    let src = LowUIR.AST.binop BinOpType.ADD sp unwindingAmount
    let rundown = [| LowUIR.AST.assign dst src |]
    FunctionSummary(0UL, 0, rundown, false, NotNoRet)

  let connectAbsVertex ctx cfgRec caller calleeAddr isTail abs =
    let callerBBL = (caller: IVertex<LowUIRBasicBlock>).VData.Internals
    let callIns = callerBBL.LastInstruction
    let callsiteAddr = callIns.Address
    let callsite = LeafCallSite callsiteAddr
    let callee = getAbsVertex ctx cfgRec callsite (Some calleeAddr) abs
    let edgeKind = if isTail then TailCallEdge else CallEdge
    connectEdge ctx cfgRec caller callee edgeKind
    callee, ReturnAddress.ofCall callIns

  let connectRet ctx cfgRec (callee, fallthroughAddr) =
    scanBBLsAndConnect ctx cfgRec callee fallthroughAddr RetEdge |> ignore
    (* Depending on the correctness of the noret analysis, there can always be
       an invalid returning edge. In such cases, we won't connect the edge, but
       we don't have to signal an error here. The rest of the process should
       keep going. *)
    Ok()

  let connectExnEdge (ctx: CFGBuildingContext<_, _>) cfgRec callsiteAddr =
    match ctx.ExnInfo.TryFindExceptionTarget(callsiteAddr) with
    | Some(landingPad) ->
      let abs = getExceptionAbstraction ctx.BinHandle callsiteAddr landingPad
      let absV = getAbsVertex ctx cfgRec (LeafCallSite callsiteAddr) None abs
      (* Necessary to lookup the caller again as bbls could be divided *)
      let callsite = LeafCallSite(callsiteAddr)
      for caller in ctx.CallerVertices[callsite] do
        connectEdge ctx cfgRec caller absV ExceptionFallThroughEdge
      scanBBLsAndConnect ctx cfgRec absV landingPad ExceptionFallThroughEdge
    | None ->
      Ok()

  let connectCallWithFT ctx
                        (cfgRec: ICFGRecovery<_, _>)
                        caller
                        calleeAddr
                        calleeInfo =
    let lastIns =
      (caller: IVertex<LowUIRBasicBlock>).VData.Internals.LastInstruction
    getFunctionSummary ctx cfgRec.Summarizer lastIns calleeAddr calleeInfo
    |> Result.map (connectAbsVertex ctx cfgRec caller calleeAddr false)
    |> Result.bind (connectRet ctx cfgRec)
    |> Result.bind (fun _ -> connectExnEdge ctx cfgRec lastIns.Address)
    |> toCFGResult

  let connectCallWithoutFT ctx
                           (cfgRec: ICFGRecovery<_, _>)
                           caller
                           calleeAddr
                           calleeInfo =
    let lastIns =
      (caller: IVertex<LowUIRBasicBlock>).VData.Internals.LastInstruction
    getFunctionSummary ctx cfgRec.Summarizer lastIns calleeAddr calleeInfo
    |> Result.map (connectAbsVertex ctx cfgRec caller calleeAddr false)
    |> Result.bind (fun _ -> connectExnEdge ctx cfgRec lastIns.Address)
    |> toCFGResult

  let connectCallEdge ctx
                      (cfgRec: ICFGRecovery<_, _>)
                      callsiteAddr
                      callee
                      calleeInfo
                      isTailCall =
    let caller = getCallerVertex ctx callsiteAddr
    if isTailCall then
      let lastIns = caller.VData.Internals.LastInstruction
      getFunctionSummary ctx cfgRec.Summarizer lastIns callee calleeInfo
      |> Result.map (connectAbsVertex ctx cfgRec caller callee true)
      |> toCFGResult
    elif ctx.FunctionAddress = callee then
      (* recursion = 100% returns (not no-ret) *)
      let lastIns = caller.VData.Internals.LastInstruction
      (* TODO: its unwinding bytes cannot be decided at this moment. *)
      let selfInfo =
        { Status = NotNoRet
          Unwinding = 0
          Clobbered = ClobberedRegisters.ofCallingConvention ctx.BinHandle
          IsExternal = false }
      cfgRec.Summarizer.Summarize(ctx, callee, selfInfo, lastIns)
      |> connectAbsVertex ctx cfgRec caller callee false
      |> connectRet ctx cfgRec
      |> toCFGResult
    else
      match calleeInfo.Status with
      | NoRet ->
        connectCallWithoutFT ctx cfgRec caller callee calleeInfo
      | NotNoRet ->
        connectCallWithFT ctx cfgRec caller callee calleeInfo
      | ConditionalNoRet loc ->
        let hdl = ctx.BinHandle
        if CondAwareNoretAnalysis.passesNonZero hdl ctx.CFG caller loc then
          connectCallWithoutFT ctx cfgRec caller callee calleeInfo
        else
          connectCallWithFT ctx cfgRec caller callee calleeInfo
      | UnknownNoRet ->
        Terminator.impossible ()

  /// Checks if the call that the abstract vertex at the given program point
  /// stands for has been judged never to return from its conditionally
  /// non-returning callee, and yet the given caller may now pass the callee
  /// an argument that lets it return.
  let mayReturnAfterAll (ctx: CFGBuildingContext<_, _>) caller absPp =
    match ctx.Vertices.TryGetValue absPp with
    | true, absV ->
      match absV.VData.Internals.AbstractContent.ReturningStatus with
      | ConditionalNoRet loc ->
        let hdl, g = ctx.BinHandle, ctx.CFG
        g.GetSuccEdges absV |> Array.forall (fun e -> e.Label <> RetEdge)
        && not (CondAwareNoretAnalysis.passesNonZero hdl g caller loc)
      | _ ->
        false
    | false, _ ->
      false

  /// Judges the call ending the given vertex again once the vertex gains a
  /// predecessor, if the call has been judged never to return because every
  /// predecessor it had passed a non-zero argument to a conditionally
  /// non-returning callee. The new predecessor may pass zero, in which case
  /// the call gets made again, so that it returns.
  let rejudgeConditionalCall ctx (v: IVertex<LowUIRBasicBlock>) =
    let vData = v.VData.Internals
    if vData.IsAbstract || not vData.LastInstruction.IsCall then
      ()
    else
      let callsite = LeafCallSite vData.LastInstruction.Address
      let callTable = (ctx: CFGBuildingContext<_, _>).IntraCallTable
      match callTable.TryGetCallee callsite with
      | true, RegularCallee callee ->
        let absPp = getCalleePPoint callsite (Some callee)
        if mayReturnAfterAll ctx v absPp then
          match ctx.ManagerChannel.GetCalleeStatus callee with
          | Built info ->
            ctx.ActionQueue.Push(MakeCall(callsite, callee, info))
          | _ ->
            ()
        else
          ()
      | _ ->
        ()

  /// Computes how many bytes the callee of the given indirect call pops on
  /// return, which is a word when the call passes a hidden sret pointer.
  let computeSRetUnwinding ctx (sretAnalysis: ISRetAnalyzable<_, _>) caller =
    if sretAnalysis.IsSRetCall(ctx, caller) then
      WordSize.toByteWidth ctx.BinHandle.ISA.WordSize
    else
      0

  /// Copies the given summary, saying that its function has the given
  /// non-returning status.
  let withReturningStatus status (abs: FunctionSummary<_>) =
    FunctionSummary(abs.EntryPoint,
                    abs.UnwindingBytes,
                    abs.Rundown,
                    abs.IsExternal,
                    status)

  /// Computes the summary of the callee of the given indirect call, which the
  /// rules decide when they tell, and the sret analysis otherwise.
  let computeIndirectCalleeAbstraction
     ctx
     (rules: ICFGRecoveryRules<_, _>)
     (sretAnalysis: ISRetAnalyzable<_, _>)
     (summarizer: IFunctionSummarizable<_, _>)
     (caller: IVertex<LowUIRBasicBlock>) =
    let hdl = (ctx: CFGBuildingContext<_, _>).BinHandle
    let callIns = caller.VData.Internals.LastInstruction
    let status, unwindingBytes =
      rules.TryJudgeIndirectReturn(ctx, caller)
      |> Option.defaultWith (fun () ->
        NotNoRet, computeSRetUnwinding ctx sretAnalysis caller)
    summarizer.MakeUnknownFunctionSummary(hdl, callIns, unwindingBytes)
    |> withReturningStatus status

  /// Connects the given indirect callee back to the code at retAddr, unless
  /// the callee never returns.
  let connectIndirectRet ctx cfgRec (absV: IVertex<LowUIRBasicBlock>) retAddr =
    match absV.VData.Internals.AbstractContent.ReturningStatus with
    | NoRet -> Ok()
    | _ -> connectRet ctx cfgRec (absV, retAddr)

  /// Connects every vertex that ends with the indirect call at the call site to
  /// the one callee of the call, whichever instruction set the call goes to.
  let connectIndirectCallEdge ctx sretAnalysis cfgRec rules callsiteAddr =
    let caller = getCallerVertex ctx callsiteAddr
    let callIns = caller.VData.Internals.LastInstruction
    let callSiteAddr = callIns.Address
    let callSite = LeafCallSite callSiteAddr
    let summarizer = (cfgRec: ICFGRecovery<_, _>).Summarizer
    let abs =
      computeIndirectCalleeAbstraction ctx rules sretAnalysis summarizer caller
    let absV = getAbsVertex ctx cfgRec callSite None abs
    for caller in ctx.CallerVertices[callsiteAddr] do
      connectEdge ctx cfgRec caller absV CallEdge
    connectIndirectRet ctx cfgRec absV (ReturnAddress.ofCall callIns)
    |> Result.bind (fun _ -> connectExnEdge ctx cfgRec callIns.Address)
    |> toCFGResult

  let connectSyscallEdge ctx syscallAnalysis cfgRec callsiteAddr isExit =
    let caller = getCallerVertex ctx callsiteAddr
    (syscallAnalysis: ISyscallAnalyzable).MakeAbstract(ctx, caller, isExit)
    |> connectAbsVertex ctx cfgRec caller 0UL false
    |> fun callee ->
      if not isExit then connectRet ctx cfgRec callee |> ignore else ()
    MoveOn

  let pushJmpTblRecoveryAction ctx queue jmptbl idx targetAddr =
    if idx = 0 then
      (ctx: CFGBuildingContext<_, _>).JumpTables[jmptbl.TableAddress] <- jmptbl
    else
      ()
    (queue: CFGActionQueue).Push(StartTblRec(jmptbl, idx, targetAddr))
    queue.Push(EndTblRec(jmptbl, idx))
    MoveOn

  /// Checks if the given table starts within the other table at tblAddr, no
  /// later than the end of its entry at idx, while the two tables belong to
  /// different indirect branches. A table that starts where the other one
  /// does, with entries of the same size, is that table itself, which the two
  /// branches share, as the copies of a computed goto do.
  let startsByEntryOf (ctx: CFGBuildingContext<_, _>) jmptbl (tblAddr, idx) =
    match ctx.JumpTables.TryGetValue tblAddr with
    | true, other when other.InsAddr <> (jmptbl: JmpTableInfo).InsAddr ->
      let entryEnd = tblAddr + uint64 ((idx + 1) * other.EntrySize)
      let isSameTable =
        jmptbl.TableAddress = tblAddr && jmptbl.EntrySize = other.EntrySize
      tblAddr <= jmptbl.TableAddress && jmptbl.TableAddress < entryEnd
      && not isSameTable
    | _ ->
      false

  /// Finds the entry of another table through which the indirect branch of the
  /// given table was first reached, if the given table starts within that table
  /// no later than the end of the entry. Ending that table before the given one
  /// would drop the very entry that led to it, so the entry is what is wrong.
  let tryFindSelfDefeatingEntry (ctx: CFGBuildingContext<_, _>) jmptbl =
    let insAddr = (jmptbl: JmpTableInfo).InsAddr
    tryGetCallerVertex ctx (LeafCallSite insAddr)
    |> Option.bind (fun v -> v.VData.DominatingJumpTableEntry)
    |> Option.filter (startsByEntryOf ctx jmptbl)

  /// Tells the manager that the given entry is bogus, and reloads the function
  /// if the manager has cut its table short of the entry.
  let blameEntry ctx (tblAddr, idx) =
    let fnAddr = (ctx: CFGBuildingContext<_, _>).FunctionAddress
#if CFGDEBUG
    dbglog ctx.ThreadID "JumpTable"
    <| $"{tblAddr:x}[{idx}] leads to a table within its own"
#endif
    if ctx.JumpTableChannel.NotifyBogusEntry(fnAddr, tblAddr, idx) then
      StopAndReload
    else
      MoveOn (* We ignore this indirect branch. *)

  /// Starts recovering the given table from its first entry, unless the slot
  /// of that entry holds none, in which case no table starts there.
  let startJmpTblRecovery ctx queue jmptbl =
    let hdl = (ctx: CFGBuildingContext<_, _>).BinHandle
    match JmpTableInfo.tryReadTarget hdl jmptbl 0 with
    | Some targetAddr ->
      pushJmpTblRecoveryAction ctx queue jmptbl 0 targetAddr
    | None ->
      let fnAddr, tblAddr = ctx.FunctionAddress, jmptbl.TableAddress
      ctx.JumpTableChannel.CancelRecovery(fnAddr, jmptbl.InsAddr, tblAddr)
      MoveOn (* We ignore this indirect branch. *)

  /// Notifies the manager of the given jump table, and follows its decision.
  /// When the table starts within the entries of another, its code may have
  /// folded the smallest index into its address, so it may start right after
  /// those entries instead. We move it there once, if the conditional jumps on
  /// every path to its indirect branch say so, and ignore the branch if not.
  let rec notifyRecovery ctx jmptblAnalysis queue jmptbl canMove =
    let fnAddr = (ctx: CFGBuildingContext<_, _>).FunctionAddress
    match ctx.JumpTableChannel.NotifyRecovery(fnAddr, jmptbl) with
    | GoRecovery ->
      startJmpTblRecovery ctx queue jmptbl
    | StopRecoveryButReload ->
      StopAndReload
    | StopRecoveryAndContinue ->
      MoveOn
    | Overlapping tableEnd when canMove ->
      let analysis: IJmpTableAnalyzable<_, _> = jmptblAnalysis
      if analysis.ConfirmStart(ctx, jmptbl, tableEnd) then
#if CFGDEBUG
        dbglog ctx.ThreadID "JumpTable"
        <| $"{jmptbl.InsAddr:x}: moved to [{tableEnd:x}]"
#endif
        let jmptbl = { jmptbl with TableAddress = tableEnd }
        notifyRecovery ctx jmptblAnalysis queue jmptbl false
      else
        MoveOn (* We ignore this indirect branch. *)
    | Overlapping _ ->
      MoveOn

  /// Recovers the indirect branch at the given address. A branch whose analysis
  /// fails is read again once nothing else is left to do, as the data flow of
  /// the CFG built so far may lack the paths that give its index its values,
  /// such as those past a call that the function waits to learn returns.
  let recoverIndirectBranches ctx jmptblAnalysis queue insAddr =
    let analysis: IJmpTableAnalyzable<_, _> = jmptblAnalysis
    match analysis.Identify(ctx, insAddr) with
    | Ok(jmptbl) ->
#if CFGDEBUG
      dbglog ctx.ThreadID "JumpTable"
      <| $"{insAddr:x}: [{jmptbl.TableAddress:x}] w/ base {jmptbl.JumpBase:x}"
#endif
      match tryFindSelfDefeatingEntry ctx jmptbl with
      | Some entry -> blameEntry ctx entry
      | None -> notifyRecovery ctx jmptblAnalysis queue jmptbl true
    | Error _ ->
#if CFGDEBUG
      dbglog ctx.ThreadID "JumpTable" $"{insAddr:x} unknown pattern"
#endif
      pushAction ctx <| RetryIndEdges(insAddr, ctx.CFG.EdgeCount)
      MoveOn (* We ignore this indirect branch for now. *)

  /// Recovers the indirect branch at the given address again if the CFG has
  /// gained edges since its analysis failed with the given number of them.
  let retryIndirectBranches ctx jmptblAnalysis queue insAddr numEdges =
    if (ctx: CFGBuildingContext<_, _>).CFG.EdgeCount > numEdges then
      recoverIndirectBranches ctx jmptblAnalysis queue insAddr
    else
      MoveOn

  let isFailedBuilding (ctx: CFGBuildingContext<'FnCtx, 'GlCtx>) calleeAddr =
    match ctx.ManagerChannel.GetCalleeStatus calleeAddr with
    | Failed -> true
    | _ -> false

  /// Checks if the function calls the callee as its tail on the guess that a
  /// function starts there, which has been given up since. Built again, the
  /// function takes the jump there to stay within.
  let isGivenUpGuess (ctx: CFGBuildingContext<_, _>) calleeAddr =
    ctx.GuessedTailCallees.Contains calleeAddr
    && isFailedBuilding ctx calleeAddr

  let popOffJmpTblRecoveryAction (ctx: CFGBuildingContext<_, _>) =
    match ctx.ActionQueue.Pop() with
    | EndTblRec _ -> ()
    | _ -> assert false

  /// Checks if the given target is the base of the given table and lies within
  /// the block ending with its indirect jump, after the start of the block and
  /// before the jump, as the ADR of clang names itself the base. No case starts
  /// in the middle of the code that dispatches the switch, since the jump would
  /// only run that code again, so an entry past the first that sends the jump
  /// there lies past the table.
  let isOwnDispatchBase (srcVertex: IVertex<LowUIRBasicBlock>) jmptbl dstAddr =
    let blkAddr = srcVertex.VData.Internals.PPoint.Address
    dstAddr = (jmptbl: JmpTableInfo).JumpBase
    && blkAddr < dstAddr && dstAddr < jmptbl.InsAddr

  /// Ends the given table right before the entry at the given index, which
  /// lies past the table, and moves on without recovering the entry.
  let endTableBefore ctx (jmptbl: JmpTableInfo) idx =
    let fnAddr = (ctx: CFGBuildingContext<_, _>).FunctionAddress
    let tblAddr = jmptbl.TableAddress
    let success = ctx.JumpTableChannel.NotifyBogusEntry(fnAddr, tblAddr, idx)
    assert success
    popOffJmpTblRecoveryAction ctx
    ctx.JumpTableRecoveryStatus.Pop() |> ignore
    MoveOn

  let rec isNopRunTo (instrs: IInstruction list) addr endAddr =
    if addr = endAddr then
      true
    else
      match instrs with
      | ins :: rest when ins.IsNop ->
        isNopRunTo rest (addr + uint64 ins.Length) endAddr
      | _ ->
        false

  /// Checks if the given jump table target is a dummy entry, which points to
  /// the padding between the current function and the next one, or to the
  /// next one itself if no padding lies between them. Compilers fill the
  /// entries of unreachable cases with the end of the function, where such
  /// padding begins.
  let isDummyJumpTarget ctx isDstFuncEntry dstAddr =
    match (ctx: CFGBuildingContext<_, _>).BBLFactory.PeekBBL dstAddr with
    | Ok(ins :: _ as instrs)
    | Error(ins :: _ as instrs) when ins.IsNop || isDstFuncEntry ->
      let fnAddr = ctx.FunctionAddress
      match ctx.ManagerChannel.GetNextFunctionAddress fnAddr with
      | Some nextFnAddr when fnAddr < dstAddr && dstAddr <= nextFnAddr ->
        isNopRunTo instrs dstAddr nextFnAddr
      | _ ->
        false
    | _ ->
      false

  /// Checks if the entries of a jump table that point to the given target are
  /// holes, which add no edge: the target is the padding at the end of the
  /// function, or what the rules of the architecture take for a hole.
  let isHoleTarget ctx rules isDstFuncEntry dstAddr =
    isDummyJumpTarget ctx isDstFuncEntry dstAddr
    || (rules: ICFGRecoveryRules<_, _>).IsJumpTableHole(ctx, dstAddr)

  let recoverJumpTableEntry ctx cfgRec rules idx jmptbl dstAddr =
    let callsite = LeafCallSite (jmptbl: JmpTableInfo).InsAddr
    let srcVertex = getCallerVertex ctx callsite
    let fnAddr = (ctx: CFGBuildingContext<_, _>).FunctionAddress
    let isDstFuncEntry = isFuncEntryPoint ctx dstAddr
    if idx = 0 && isDstFuncEntry then jmptbl.IsFunctionPointerTable <- true
    else ()
    if not (isExecutableAddr ctx dstAddr) then
      match ctx.JumpTableRecoveryStatus.TryPeek() with
      | true, (tblAddr, 0) ->
        (* The first jump table entry was invalid. For example, the target was
           not executable. In this case, we conclude that the indirect jump is
           not using a jump table, and thus, we simply ignore the indirect
           branch, along with the table we took it for. *)
        let insAddr = (jmptbl: JmpTableInfo).InsAddr
        ctx.JumpTableChannel.CancelRecovery(fnAddr, insAddr, tblAddr)
        ctx.JumpTables.Remove tblAddr |> ignore
        popOffJmpTblRecoveryAction ctx
        ctx.JumpTableRecoveryStatus.Pop() |> ignore
        MoveOn
      | _ ->
        FailStop ErrorCase.FailedToRecoverCFG
    elif idx > 0 && isOwnDispatchBase srcVertex jmptbl dstAddr then
      endTableBefore ctx jmptbl idx
    elif jmptbl.IsFunctionPointerTable then
      if not isDstFuncEntry then (* End of the table. *)
        endTableBefore ctx jmptbl idx
      else
        let lastInsAddr = srcVertex.VData.Internals.LastInstruction.Address
        let callsite = LeafCallSite lastInsAddr
        let act = MakeTlCall(callsite, dstAddr, CalleeInfo.Unknown)
        handleCall ctx cfgRec rules srcVertex callsite dstAddr act
    elif isHoleTarget ctx rules isDstFuncEntry dstAddr then
      (* A hole in the table: it adds no edge, but the entries after it are
         still part of the table, so we move on to the next one. *)
      MoveOn
    else
      scanBBLsAndConnect ctx cfgRec srcVertex dstAddr IndirectJmpEdge
      |> toCFGResult

  let sendJmpTblRecoverySuccess ctx queue jmptbl idx =
    let fnAddr = (ctx: CFGBuildingContext<_, _>).FunctionAddress
    let tblAddr = jmptbl.TableAddress
    let nextTarget = JmpTableInfo.tryReadTarget ctx.BinHandle jmptbl (idx + 1)
    let isFnPointerTbl = jmptbl.IsFunctionPointerTable
    let ch = ctx.JumpTableChannel
    let isExpanding =
      ch.ReportSuccess(fnAddr, tblAddr, idx, nextTarget, isFnPointerTbl)
    match nextTarget with
    | Some targetAddr when isExpanding ->
      pushJmpTblRecoveryAction ctx queue jmptbl (idx + 1) targetAddr
    | _ ->
#if CFGDEBUG
      dbglog ctx.ThreadID "JumpTable" $"No more to add"
#endif
      MoveOn

  let isNoRet (v: IVertex<LowUIRBasicBlock>) =
    v.VData.Internals.AbstractContent.ReturningStatus = NoRet

  let updateCallEdgesForEachCallsite ctx
                                     cfgRec
                                     callsites
                                     calleeAddr
                                     calleeInfo =
    for callsite in callsites do
      let absPp = ProgramPoint(callsite, calleeAddr, 0)
      match (ctx: CFGBuildingContext<_, _>).Vertices.TryGetValue absPp with
      | true, absV when isNoRet absV ->
        let edge = ctx.CFG.GetPredEdges absV |> Array.exactlyOne
        let isTailCall = edge.Label = TailCallEdge
        let action =
          if isTailCall then MakeTlCall(callsite, calleeAddr, calleeInfo)
          else MakeCall(callsite, calleeAddr, calleeInfo)
#if CFGDEBUG
        let fnAddr = ctx.FunctionAddress
        dbglog ctx.ThreadID (nameof UpdateCallEdges)
        <| $"{callsite:x} -> {calleeAddr:x} @ {fnAddr:x}"
#endif
        tryRemoveVertexAt ctx cfgRec absPp |> ignore
        ctx.ActionQueue.Push(action)
      | _ ->
        ()
    MoveOn

  let updateCallEdges ctx cfgRec calleeAddr calleeInfo =
    let callTable = (ctx: CFGBuildingContext<_, _>).IntraCallTable
    match callTable.TryGetCallsites calleeAddr with
    | true, callsites ->
      updateCallEdgesForEachCallsite ctx cfgRec callsites calleeAddr calleeInfo
    | false, _ ->
      Terminator.impossible ()

  let hasReturnNode (ctx: CFGBuildingContext<'FnCtx, 'GlCtx>) =
    ctx.CFG.TryFindVertexBy(fun v ->
      if v.VData.Internals.IsAbstract then
        v.VData.Internals.AbstractContent.ReturningStatus = NotNoRet
      else
        v.VData.Internals.LastInstruction.IsRET)
    |> Option.isSome

  /// Checks if a block of the function runs on into the given entry, where an
  /// instruction of the block past its first one starts.
  let runsIntoEntry (ctx: CFGBuildingContext<_, _>) entry =
    ctx.CFG.Vertices
    |> Array.exists (fun v ->
      let bbl = v.VData.Internals
      not bbl.IsAbstract
      && bbl.Range.Min < entry
      && bbl.Instructions |> Array.exists (fun ins -> ins.Address = entry))

  /// Cuts the block of the function that runs on into the entry of the next
  /// function there, telling whether it did. Such a block, scanned before the
  /// next function came to light, keeps the code past the entry, while the
  /// function ends at the entry and drops what that code jumps to. Built
  /// again, the function calls the next one as its tail where it runs into it.
  let cutsAtNextEntry (ctx: CFGBuildingContext<_, _>) =
    match ctx.ManagerChannel.GetNextFunctionAddress ctx.FunctionAddress with
    | Some entry when runsIntoEntry ctx entry ->
      Result.isOk (ctx.ScanBBLs [ entry ])
    | _ ->
      false

  /// Copies the recovered edges to other indirect branches that use the same
  /// jump table. The table owner performs the actual recovery only once.
  let connectDelayedJumpTableEdges ctx (cfgRec: ICFGRecovery<_, _>) =
    let tryFindIndBranchVertex addr = tryGetCallerVertex ctx (LeafCallSite addr)
    for jmptbl in ctx.JumpTables.Values do
      match jmptbl.WaitingInstructions with
      | [] ->
        ()
      | waitingInstructions ->
        match tryFindIndBranchVertex jmptbl.InsAddr with
        | None ->
          ()
        | Some originalVertex ->
          let recoveredEdges = ctx.CFG.GetSuccEdges originalVertex
          for insAddr in waitingInstructions do
            match tryFindIndBranchVertex insAddr with
            | None ->
              ()
            | Some waitingVertex ->
              for edge in recoveredEdges do
                connectEdge ctx cfgRec waitingVertex edge.Second edge.Label

  let finalizeRecovery ctx (cfgRec: ICFGRecovery<_, _>) postAnalysis =
    connectDelayedJumpTableEdges ctx cfgRec
    let oldNoRetStatus = ctx.NonReturningStatus
    ICFGAnalysis.run { Context = ctx } postAnalysis
    let newNoRetStatus = ctx.NonReturningStatus
    ctx.UnwindingBytes <- cfgRec.Summarizer.ComputeUnwindingAmount ctx
    match oldNoRetStatus, newNoRetStatus with
    | NoRet, NotNoRet
    | NoRet, ConditionalNoRet _ -> MoveOnButReloadCallers oldNoRetStatus
    | _ -> MoveOn

  /// Finalizes the recovery, unless the function runs into the next one
  /// through a jump table entry that turns out bogus, which rebuilds it.
  let checkOverlap (ctx: CFGBuildingContext<_, _>) cfgRec postAnalysis =
    let nextFn = ctx.ManagerChannel.GetNextFunctionAddress ctx.FunctionAddress
    match ctx.FindOverlap nextFn with
    | Some v ->
#if CFGDEBUG
      let addr = v.VData.Internals.PPoint.Address
      dbglog ctx.ThreadID "OnFinish"
      <| $"Found overlap at {addr:x} @ {ctx.FunctionAddress}"
#endif
      match v.VData.DominatingJumpTableEntry with
      | Some(tblAddr, idx) ->
        let fnAddr = ctx.FunctionAddress
        ctx.JumpTableChannel.NotifyBogusEntry(fnAddr, tblAddr, idx)
        |> function
          | true -> StopAndReload
          | false -> finalizeRecovery ctx cfgRec postAnalysis
      | None ->
        finalizeRecovery ctx cfgRec postAnalysis
    | _ ->
      finalizeRecovery ctx cfgRec postAnalysis

  /// Refutes the guesses that the built function finds wrong: it calls the code
  /// at an address as its tail on the guess that a function starts there, yet
  /// it reaches the code there otherwise. Telling the manager so, it tells
  /// whether it refuted any, which builds it again with its jumps there
  /// staying within.
  let refutesGuesses (ctx: CFGBuildingContext<_, _>) rules =
    let refuted =
      ctx.GuessedTailCallees
      |> Seq.filter (fun callee ->
        (rules: ICFGRecoveryRules<_, _>).RefutesTailCall(ctx, callee))
      |> Seq.toArray
    Array.iter ctx.ManagerChannel.RefuteTailCallee refuted
    not (Array.isEmpty refuted)

  /// Refutes the guess that the built function starts where it does, if it
  /// starts only on that guess and its own code tells otherwise.
  let refuteOwnGuess (ctx: CFGBuildingContext<_, _>) rules =
    if ctx.IsGuessedEntry
       && (rules: ICFGRecoveryRules<_, _>).RefutesEntry ctx then
      ctx.ManagerChannel.RefuteTailCallee ctx.FunctionAddress
    else
      ()

  let onFinish (ctx: CFGBuildingContext<_, _>) cfgRec rules postAnalysis =
    assert (ctx.JumpTableRecoveryStatus.Count = 0)
    if (rules: ICFGRecoveryRules<_, _>).RequiresRebuild ctx then
      StopAndReload
    elif refutesGuesses ctx rules then
      StopAndReload
    elif cutsAtNextEntry ctx then
      StopAndReload
    else
      refuteOwnGuess ctx rules
      checkOverlap ctx cfgRec postAnalysis

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

  let findVertexByAddr (ctx: CFGBuildingContext<_, _>) addr =
    ctx.Vertices.Values
    |> Seq.find (fun v ->
      let bbl = v.VData.Internals
      not bbl.IsAbstract && bbl.Range.IsIncluding(addr))

  let isNoReturnAbsVertex (v: IVertex<LowUIRBasicBlock>) =
    v.VData.Internals.IsAbstract &&
    v.VData.Internals.AbstractContent.ReturningStatus = NoRet

  /// Tries to fill a no-return fall-through edge if applicable. This recovers a
  /// fall-through edge from an abstract no-return vertex to the next vertex,
  /// which may be missing due to our precise analysis of no-return functions
  /// whereas a compiler may have generated a fall-through edge after a call to
  /// a no-return function.
  let recoverNoReturnFallThroughEdge (ctx: CFGBuildingContext<_, _>) v =
    let g = ctx.CFG
    let addr = (v: IVertex<LowUIRBasicBlock>).VData.Internals.PPoint.Address
    let maybePredAddr = addr - 1UL
    let maybePred = findVertexByAddr ctx maybePredAddr
    match Array.tryExactlyOne <| g.GetSuccs(maybePred) with
    | Some(succOfMaybePred) when isNoReturnAbsVertex succOfMaybePred ->
      g.AddEdge(succOfMaybePred, v, NoReturnFallThroughEdge)
    | _ ->
      ()
