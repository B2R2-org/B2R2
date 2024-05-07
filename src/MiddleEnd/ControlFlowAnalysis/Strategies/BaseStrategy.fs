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
open B2R2.MiddleEnd.SSA
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis

/// Base strategy for building a CFG.
type BaseStrategy<'FnCtx,
                  'GlCtx when 'FnCtx :> IResettable
                          and 'FnCtx: (new: unit -> 'FnCtx)
                          and 'GlCtx: (new: unit -> 'GlCtx)>
  public (ssaLifter: SSALifter<_>,
          noRetAnalyzer: INoReturnIdentifiable<_, _, 'FnCtx, 'GlCtx>,
          summarizer: IFunctionSummarizable<_, _, 'FnCtx, 'GlCtx>,
          allowOverlap) =

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
      v

  let getAbsVertex ctx callsiteAddr calleeAddr abs =
    let key = callsiteAddr, calleeAddr
    match ctx.AbsVertices.TryGetValue key with
    | true, v -> v
    | false, _ ->
      let calleePPoint = ProgramPoint (calleeAddr, 0)
      let bbl = IRBasicBlock.CreateAbstract (calleePPoint, abs)
      let v, g = ctx.CFG.AddVertex bbl
      ctx.CFG <- g
      ctx.AbsVertices[key] <- v
      v

  let removeVertex ctx ppoint =
    match ctx.Vertices.TryGetValue ppoint with
    | true, v ->
      let preds =
        ctx.CFG.GetPredEdges v
        |> Seq.filter (fun e -> e.First.VData.PPoint <> ppoint)
      let succs = ctx.CFG.GetSuccEdges v
      ctx.Vertices.Remove ppoint |> ignore
      ctx.CFG <- ctx.CFG.RemoveVertex v
      preds, succs
    | false, _ ->
      [||], [||]

  let connectEdge ctx srcVertex dstVertex edgeKind =
    ctx.CFG <- ctx.CFG.AddEdge (srcVertex, dstVertex, edgeKind)
#if CFGDEBUG
    dbglog ctx.ThreadID "ConnectEdge"
    <| $"{srcVertex.VData.PPoint} -> {dstVertex.VData.PPoint}"
#endif

  let maskedPPoint ctx targetAddr =
    let rt = ctx.BinHandle.File.ISA.WordSize |> WordSize.toRegType
    let mask = BitVector.UnsignedMax rt |> BitVector.ToUInt64
    ProgramPoint (targetAddr &&& mask, 0)

  /// Build a CFG starting from the given program points.
  let buildCFG ctx (actionQueue: CFGActionQueue) fnAddr initPPs mode =
    let ppQueue = Queue<ProgramPoint> (collection=initPPs)
    while ppQueue.Count > 0 do
      let ppoint = ppQueue.Dequeue ()
      if ctx.VisitedPPoints.Contains ppoint then ()
      else
        ctx.VisitedPPoints.Add ppoint |> ignore
        let srcVertex = getVertex ctx ppoint
        let srcBBL = srcVertex.VData
        match srcBBL.Terminator.S with
        | IEMark _ ->
          let last = srcBBL.LastInstruction
          let nextPPoint = ProgramPoint (last.Address + uint64 last.Length, 0)
          let dstVertex = getVertex ctx nextPPoint
          connectEdge ctx srcVertex dstVertex FallThroughEdge
          ppQueue.Enqueue nextPPoint
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
        | InterJmp ({ E = BinOp (BinOpType.ADD, _, { E = PCVar _ },
                                                   { E = Num n }) },
                          InterJmpKind.Base) ->
          let target = srcBBL.LastInstruction.Address + BitVector.ToUInt64 n
          let dstPPoint = maskedPPoint ctx target
          let dstVertex = getVertex ctx dstPPoint
          connectEdge ctx srcVertex dstVertex InterJmpEdge
          ppQueue.Enqueue dstPPoint
        | InterJmp ({ E = Num n }, InterJmpKind.Base) ->
          let dstPPoint = maskedPPoint ctx (BitVector.ToUInt64 n)
          let dstVertex = getVertex ctx dstPPoint
          connectEdge ctx srcVertex dstVertex InterJmpEdge
          ppQueue.Enqueue dstPPoint
        | InterJmp ({ E = BinOp (BinOpType.ADD, _, { E = PCVar _ },
                                                   { E = Num n }) },
                          InterJmpKind.IsCall) ->
          let callerAddr = srcBBL.PPoint.Address
          let callsiteAddr = srcBBL.LastInstruction.Address
          let target = callsiteAddr + BitVector.ToUInt64 n
          ctx.ManagerChannel.UpdateDependency (fnAddr, target, mode)
          ctx.CallTable.AddRegularCall srcBBL.PPoint callsiteAddr target
          actionQueue.Push <| MakeCall (fnAddr, callerAddr, target, mode)
        | InterJmp ({ E = Num n }, InterJmpKind.IsCall) ->
          let callerAddr = srcBBL.PPoint.Address
          let callsiteAddr = srcBBL.LastInstruction.Address
          let target = BitVector.ToUInt64 n
          ctx.ManagerChannel.UpdateDependency (fnAddr, target, mode)
          ctx.CallTable.AddRegularCall srcBBL.PPoint callsiteAddr target
          actionQueue.Push <| MakeCall (fnAddr, callerAddr, target, mode)
        | InterCJmp (_, { E = BinOp (BinOpType.ADD, _, { E = PCVar _ },
                                                       { E = Num tv }) },
                        { E = BinOp (BinOpType.ADD, _, { E = PCVar _ },
                                                       { E = Num fv }) }) ->
          let lastAddr = srcBBL.LastInstruction.Address
          let tPPoint = maskedPPoint ctx (lastAddr + BitVector.ToUInt64 tv)
          let fPPoint = maskedPPoint ctx (lastAddr + BitVector.ToUInt64 fv)
          let tVertex, fVertex = getVertex ctx tPPoint, getVertex ctx fPPoint
          connectEdge ctx srcVertex tVertex InterCJmpTrueEdge
          connectEdge ctx srcVertex fVertex InterCJmpFalseEdge
          ppQueue.Enqueue tPPoint
          ppQueue.Enqueue fPPoint
        | InterCJmp (_, { E = Num tv }, { E = Num fv }) ->
          let tPPoint = maskedPPoint ctx (BitVector.ToUInt64 tv)
          let fPPoint = maskedPPoint ctx (BitVector.ToUInt64 fv)
          let tVertex, fVertex = getVertex ctx tPPoint, getVertex ctx fPPoint
          connectEdge ctx srcVertex tVertex InterCJmpTrueEdge
          connectEdge ctx srcVertex fVertex InterCJmpFalseEdge
          ppQueue.Enqueue tPPoint
          ppQueue.Enqueue fPPoint
        | Jmp _ | CJmp _ | InterJmp _ | InterCJmp _ ->
          ()
        | SideEffect SysCall ->
          Utils.futureFeature ()
        | _ ->
          ()
    done
    Success

  /// This is to update the caller information when a basic block is split. This
  /// is only effective when the block makes a call, and the callee(s) are
  /// known.
  let handleCallerSplit ctx callerAddr splitAddr callsiteAddr =
    assert (callerAddr < splitAddr && splitAddr <= callsiteAddr)
    match ctx.CallTable.TryGetCallee callsiteAddr with
    | true, RegularCallee calleeAddr ->
      let callsites = ctx.CallTable.GetCallers calleeAddr
      callsites.Remove callerAddr |> ignore
      callsites.Add splitAddr |> ignore
    | _ -> ()

  let reconnectVertices ctx (dividedEdges: List<ProgramPoint * ProgramPoint>) =
    for (srcPPoint, dstPPoint) in dividedEdges do
      let preds, succs = removeVertex ctx srcPPoint
      let srcVertex = getVertex ctx srcPPoint
      let dstVertex = getVertex ctx dstPPoint
#if CFGDEBUG
      dbglog ctx.ThreadID "Reconnect" $"{srcPPoint} -> {dstPPoint}"
#endif
      let lastAddr = dstVertex.VData.LastInstruction.Address
      handleCallerSplit ctx srcPPoint.Address dstPPoint.Address lastAddr
      ctx.CFG <- ctx.CFG.AddEdge (srcVertex, dstVertex, FallThroughEdge)
      for predEdge in preds do
        ctx.CFG <- ctx.CFG.AddEdge (predEdge.First, srcVertex, predEdge.Label)
      for succEdge in succs do
        ctx.CFG <- ctx.CFG.AddEdge (dstVertex, succEdge.Second, succEdge.Label)

  let addExpandCFGAction (queue: CFGActionQueue) fnAddr mode addr =
    queue.Push <| ExpandCFG (fnAddr, mode, [ addr ])

  let getFunctionAbstraction ctx callIns calleeAddr =
    match ctx.ManagerChannel.GetBuildingContext calleeAddr with
    | FinalCtx calleeCtx
    | StillBuilding calleeCtx ->
      summarizer.Summarize (calleeCtx, callIns) |> Ok
    | FailedBuilding -> Error ErrorCase.FailedToRecoverCFG

  let connectAbsVertex ctx (caller: IVertex<IRBasicBlock>) calleeAddr abs =
    let callIns = caller.VData.LastInstruction
    let callsiteAddr = callIns.Address
    let callee = getAbsVertex ctx callsiteAddr calleeAddr abs
    connectEdge ctx caller callee CallEdge
    callee, callsiteAddr + uint64 callIns.Length

  let connectRet ctx mode (callee, fallthroughAddr) =
    let dividedEdges = scanBBLs ctx mode [ fallthroughAddr ]
    let fallthroughPPoint = ProgramPoint (fallthroughAddr, 0)
    let fallthroughVertex = getVertex ctx fallthroughPPoint
    connectEdge ctx callee fallthroughVertex RetEdge
    reconnectVertices ctx dividedEdges
    fallthroughAddr

  let toCFGResult = function
    | Ok _ -> Success
    | Error e -> Failure e

  let connectCallEdge ctx queue fnAddr callerAddr calleeAddr mode =
    let caller = getVertex ctx (ProgramPoint (callerAddr, 0))
    if fnAddr = calleeAddr then (* recursion = always returns (not noret) *)
      summarizer.Summarize (ctx, caller.VData.LastInstruction)
      |> connectAbsVertex ctx caller calleeAddr
      |> connectRet ctx mode
      |> addExpandCFGAction queue fnAddr mode
      Success
    else
      match ctx.ManagerChannel.GetNonReturningStatus calleeAddr with
      | NoRet ->
        getFunctionAbstraction ctx caller.VData.LastInstruction calleeAddr
        |> Result.map (connectAbsVertex ctx caller calleeAddr)
        |> toCFGResult
      | NotNoRet ->
        getFunctionAbstraction ctx caller.VData.LastInstruction calleeAddr
        |> Result.map (connectAbsVertex ctx caller calleeAddr)
        |> Result.map (connectRet ctx mode)
        |> Result.map (addExpandCFGAction queue fnAddr mode)
        |> toCFGResult
      | UnknownNoRet -> Wait calleeAddr
      | _ -> Failure ErrorCase.FailedToRecoverCFG

  new () =
    let ssaLifter = SSALifter ()
    let noRetAnalyzer = ConditionAwareNoretAnalysis ()
    let summarizer = BaseFunctionSummarizer ()
    BaseStrategy (ssaLifter, noRetAnalyzer, summarizer, false)

  new (ssaLifter) =
    let noRetAnalyzer = ConditionAwareNoretAnalysis ()
    let summarizer = BaseFunctionSummarizer ()
    BaseStrategy (ssaLifter, noRetAnalyzer, summarizer, false)

  interface IFunctionBuildingStrategy<IRBasicBlock,
                                      CFGEdgeKind,
                                      'FnCtx,
                                      'GlCtx> with
    member __.AllowBBLOverlap = allowOverlap

    member __.ActionPrioritizer =
      { new IPrioritizable with
          member _.GetPriority action =
            match action with
            | InitiateCFG _ -> 4
            | ExpandCFG _ -> 4
            | MakeCall _ -> 3
            | IndirectEdge _ -> 2
            | SyscallEdge _ -> 1
            | JumpTableEntryStart _ -> 0
            | JumpTableEntryEnd _ -> 0 }

    member __.OnAction (ctx, queue, action) =
      try
        match action with
        | InitiateCFG (fnAddr, mode) ->
#if CFGDEBUG
          dbglog ctx.ThreadID (nameof InitiateCFG) $"{fnAddr:x}"
#endif
          let pp = ProgramPoint (fnAddr, 0)
          scanBBLs ctx mode [ fnAddr ] |> ignore
          buildCFG ctx queue fnAddr [| pp |] mode
        | ExpandCFG (fnAddr, mode, addrs) ->
#if CFGDEBUG
          let targets =
            addrs |> Seq.map (fun addr -> $"{addr:x}") |> String.concat ";"
          dbglog ctx.ThreadID (nameof ExpandCFG) $"{fnAddr:x} ({targets})"
#endif
          let newPPs = addrs |> Seq.map (fun addr -> ProgramPoint (addr, 0))
          buildCFG ctx queue fnAddr newPPs mode
        | MakeCall (fnAddr, callerAddr, calleeAddr, mode) ->
#if CFGDEBUG
          dbglog ctx.ThreadID (nameof MakeCall)
          <| $"{fnAddr:x} to {calleeAddr:x}"
#endif
          connectCallEdge ctx queue fnAddr callerAddr calleeAddr mode
        | _ ->
          failwith "X"
      with e ->
        Console.Error.WriteLine $"OnAction failed:\n{e}"
        Failure ErrorCase.FailedToRecoverCFG

    member _.OnFinish (ctx) =
      if noRetAnalyzer.IsNoReturn (ctx) then ctx.NonReturningStatus <- NoRet
      else ctx.NonReturningStatus <- NotNoRet
      let root = ctx.CFG.TryGetSingleRoot () |> Option.get
      let ssaCFG, _ = ssaLifter.Lift ctx.CFG root
      ctx.SSACFG <- ssaCFG
      Success

    member _.OnCyclicDependency (deps) =
      let sorted = deps |> Seq.sortBy fst
#if CFGDEBUG
      sorted
      |> Seq.map (fun (addr, _) -> $"{addr:x}")
      |> String.concat ","
      |> dbglog 0 "OnCyclicDependency"
#endif
      let _, builder = Seq.head sorted
      builder.Context.NonReturningStatus <- NotNoRet
