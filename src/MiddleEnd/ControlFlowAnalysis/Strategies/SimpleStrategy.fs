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
open B2R2.MiddleEnd.SSA

type CFGAction<'Abs when 'Abs: null> =
  /// Build an initial CFG that is reachable from the given function start
  /// address.
  | InitiateCFG of fnAddr: Addr * mode: ArchOperationMode
  /// Add more reachable edges to the initial CFG using the new program points.
  | ExpandCFG of fnAddr: Addr * mode: ArchOperationMode * addrs: seq<Addr>
  /// Connect a call edge.
  | ConnectCallEdge of fnAddr: Addr * calleeAddr: Addr * mode: ArchOperationMode
  | IndirectEdge of IRBasicBlock<'Abs>
  | SyscallEdge of IRBasicBlock<'Abs>
  | JumpTableEntryStart of IRBasicBlock<'Abs> * Addr * Addr
  | JumpTableEntryEnd of IRBasicBlock<'Abs> * Addr * Addr
with
  interface ICFGAction with
    member __.Priority =
      match __ with
      | InitiateCFG _ -> 4
      | ExpandCFG _ -> 4
      | ConnectCallEdge _ -> 3
      | IndirectEdge _ -> 2
      | SyscallEdge _ -> 1
      | JumpTableEntryStart _ -> 0
      | JumpTableEntryEnd _ -> 0

type EmptyState () = class end

type CFGContext () =
  let visitedBBLs = HashSet<ProgramPoint> ()

  /// The set of visited basic blocks. This is to prevent visiting the same
  /// basic block multiple times.
  member _.VisitedBBLs with get() = visitedBBLs

  interface IResettable with
    member __.Reset () =
      __.VisitedBBLs.Clear ()

/// Simple strategy for building a CFG.
type SimpleStrategy (noRetAnalyzer: INoReturnIdentifiable) =
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

  let connectEdge ctx srcVertex dstPPoint edgeKind =
    let dstVertex = getVertex ctx dstPPoint
    ctx.CFG <- ctx.CFG.AddEdge (srcVertex, dstVertex, edgeKind)
#if CFGDEBUG
    dbglog ctx.ThreadID "ConnectEdge" $"{srcVertex.VData.PPoint} -> {dstPPoint}"
#endif

  let maskedPPoint ctx targetAddr =
    let rt = ctx.BinHandle.File.ISA.WordSize |> WordSize.toRegType
    let mask = BitVector.UnsignedMax rt |> BitVector.ToUInt64
    ProgramPoint (targetAddr &&& mask, 0)

  let updateCallingNodes ctx callerAddr calleeAddr =
    match ctx.CallingNodes.TryGetValue calleeAddr with
    | true, callsites -> callsites.Add callerAddr |> ignore
    | false, _ -> ctx.CallingNodes[calleeAddr] <- HashSet ([ callerAddr ])

  /// Build a CFG starting from the given program points.
  let buildCFG ctx (actionQueue: CFGActionQueue<_>) fnAddr initPPs mode =
    let ppQueue = Queue<ProgramPoint> (collection=initPPs)
    while ppQueue.Count > 0 do
      let ppoint = ppQueue.Dequeue ()
      let userCtx: CFGContext = ctx.UserContext
      if userCtx.VisitedBBLs.Contains ppoint then ()
      else
        userCtx.VisitedBBLs.Add ppoint |> ignore
        let srcVertex = getVertex ctx ppoint
        let srcBBL = srcVertex.VData
        match srcBBL.Terminator.S with
        | IEMark _ ->
          let last = srcBBL.LastInstruction
          let nextPPoint = ProgramPoint (last.Address + uint64 last.Length, 0)
          connectEdge ctx srcVertex nextPPoint FallThroughEdge
          ppQueue.Enqueue nextPPoint
        | Jmp { E = Name lbl } ->
          let dstPPoint = srcBBL.LabelMap[lbl]
          connectEdge ctx srcVertex dstPPoint IntraJmpEdge
          ppQueue.Enqueue dstPPoint
        | CJmp (_, { E = Name tLbl }, { E = Name fLbl }) ->
          let tPPoint = srcBBL.LabelMap[tLbl]
          let fPPoint = srcBBL.LabelMap[fLbl]
          connectEdge ctx srcVertex tPPoint IntraCJmpTrueEdge
          connectEdge ctx srcVertex fPPoint IntraCJmpFalseEdge
          ppQueue.Enqueue tPPoint
          ppQueue.Enqueue fPPoint
        | InterJmp ({ E = BinOp (BinOpType.ADD, _, { E = PCVar _ },
                                                   { E = Num n }) },
                          InterJmpKind.Base) ->
          let target = srcBBL.LastInstruction.Address + BitVector.ToUInt64 n
          let dstPPoint = maskedPPoint ctx target
          connectEdge ctx srcVertex dstPPoint InterJmpEdge
          ppQueue.Enqueue dstPPoint
        | InterJmp ({ E = Num n }, InterJmpKind.Base) ->
          let dstPPoint = maskedPPoint ctx (BitVector.ToUInt64 n)
          connectEdge ctx srcVertex dstPPoint InterJmpEdge
          ppQueue.Enqueue dstPPoint
        | InterJmp ({ E = BinOp (BinOpType.ADD, _, { E = PCVar _ },
                                                   { E = Num n }) },
                          InterJmpKind.IsCall) ->
          let callsiteAddr = srcBBL.LastInstruction.Address
          let target = callsiteAddr + BitVector.ToUInt64 n
          ctx.ManagerChannel.UpdateDependency (fnAddr, target, mode)
          ctx.Callees[callsiteAddr] <- RegularCallee target
          updateCallingNodes ctx srcBBL.PPoint.Address target
          actionQueue.Push <| ConnectCallEdge (fnAddr, target, mode)
        | InterJmp ({ E = Num n }, InterJmpKind.IsCall) ->
          let callsiteAddr = srcBBL.LastInstruction.Address
          let target = BitVector.ToUInt64 n
          ctx.ManagerChannel.UpdateDependency (fnAddr, target, mode)
          ctx.Callees[callsiteAddr] <- RegularCallee target
          updateCallingNodes ctx srcBBL.PPoint.Address target
          actionQueue.Push <| ConnectCallEdge (fnAddr, target, mode)
        | InterCJmp (_, { E = BinOp (BinOpType.ADD, _, { E = PCVar _ },
                                                       { E = Num tv }) },
                        { E = BinOp (BinOpType.ADD, _, { E = PCVar _ },
                                                       { E = Num fv }) }) ->
          let lastAddr = srcBBL.LastInstruction.Address
          let tPPoint = maskedPPoint ctx (lastAddr + BitVector.ToUInt64 tv)
          let fPPoint = maskedPPoint ctx (lastAddr + BitVector.ToUInt64 fv)
          connectEdge ctx srcVertex tPPoint InterCJmpTrueEdge
          connectEdge ctx srcVertex fPPoint InterCJmpFalseEdge
          ppQueue.Enqueue tPPoint
          ppQueue.Enqueue fPPoint
        | InterCJmp (_, { E = Num tv }, { E = Num fv }) ->
          let tPPoint = maskedPPoint ctx (BitVector.ToUInt64 tv)
          let fPPoint = maskedPPoint ctx (BitVector.ToUInt64 fv)
          connectEdge ctx srcVertex tPPoint InterCJmpTrueEdge
          connectEdge ctx srcVertex fPPoint InterCJmpFalseEdge
          ppQueue.Enqueue tPPoint
          ppQueue.Enqueue fPPoint
        | Jmp _ | CJmp _ | InterJmp _ | InterCJmp _ ->
          ()
        | _ ->
          ()
    done
    Success

  let amendCallingNodes ctx (srcVertex: IVertex<IRBasicBlock<_>>) dstAddr =
    let lastAddress = srcVertex.VData.LastInstruction.Address
    match ctx.CallingNodes.TryGetValue lastAddress with
    | true, callsites ->
      callsites.Remove srcVertex.VData.PPoint.Address |> ignore
      callsites.Add dstAddr |> ignore
    | false, _ -> ()

  let reconnectVertices ctx (dividedEdges: List<ProgramPoint * ProgramPoint>) =
    for (srcPPoint, dstPPoint) in dividedEdges do
      let preds, succs = removeVertex ctx srcPPoint
      let srcVertex = getVertex ctx srcPPoint
      let dstVertex = getVertex ctx dstPPoint
#if CFGDEBUG
      dbglog ctx.ThreadID "Reconnect" $"{srcPPoint} -> {dstPPoint}"
#endif
      amendCallingNodes ctx srcVertex dstPPoint.Address
      ctx.CFG <- ctx.CFG.AddEdge (srcVertex, dstVertex, FallThroughEdge)
      for predEdge in preds do
        let predVertex = getVertex ctx predEdge.First.VData.PPoint
        ctx.CFG <- ctx.CFG.AddEdge (predVertex, srcVertex, predEdge.Label)
      for succEdge in succs do
        let succVertex = getVertex ctx succEdge.Second.VData.PPoint
        ctx.CFG <- ctx.CFG.AddEdge (dstVertex, succVertex, succEdge.Label)

  let connectFallThroughEdges ctx queue fnAddr mode callingNodes =
    let newAddrs = List<Addr> ()
    let newEdges = List<ProgramPoint * ProgramPoint> ()
    for (callerAddr: Addr) in callingNodes do
      let srcVertex = getVertex ctx (ProgramPoint (callerAddr, 0))
      let callIns = srcVertex.VData.LastInstruction
      let fallthroughAddr = callIns.Address + uint64 callIns.Length
      let dstPPoint = ProgramPoint (fallthroughAddr, 0)
      newAddrs.Add (fallthroughAddr)
      newEdges.Add ((srcVertex.VData.PPoint, dstPPoint))
    let dividedEdges = scanBBLs ctx mode newAddrs
    for (srcPPoint, dstPPoint) in newEdges do
      let srcVertex = getVertex ctx srcPPoint
      connectEdge ctx srcVertex dstPPoint CallFallThroughEdge
    reconnectVertices ctx dividedEdges
    (queue: CFGActionQueue<_>).Push <| ExpandCFG (fnAddr, mode, newAddrs)
    Success

  let connectCallEdge ctx queue fnAddr mode calleeAddr =
    if fnAddr = calleeAddr then (* recursion = always returns (not noret) *)
      [| fnAddr |] |> connectFallThroughEdges ctx queue fnAddr mode
    else
      match ctx.ManagerChannel.GetNonReturningStatus calleeAddr with
      | NoRet -> Success
      | NotNoRet ->
        ctx.CallingNodes[calleeAddr]
        |> connectFallThroughEdges ctx queue fnAddr mode
      | UnknownNoRet -> Wait calleeAddr
      | _ -> Failure ErrorCase.FailedToRecoverCFG

  new () =
    let noRetAnalyzer =
      { new INoReturnIdentifiable with
          member _.IsNoReturn (_) = false }
    SimpleStrategy noRetAnalyzer

  interface IFunctionBuildingStrategy<IRBasicBlock<SSAFunctionAbstraction>,
                                      CFGEdgeKind,
                                      SSAFunctionAbstraction,
                                      CFGAction<SSAFunctionAbstraction>,
                                      CFGContext,
                                      EmptyState> with
    member __.PopulateInitialAction (entryPoint, mode) =
      InitiateCFG (entryPoint, mode)

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
        | ConnectCallEdge (fnAddr, calleeAddr, mode) ->
#if CFGDEBUG
          dbglog ctx.ThreadID (nameof ConnectCallEdge)
          <| $"{fnAddr:x} to {calleeAddr:x}"
#endif
          connectCallEdge ctx queue fnAddr mode calleeAddr
        | _ ->
          failwith "X"
      with e ->
        Console.Error.WriteLine $"OnAction failed:\n{e}"
        Failure ErrorCase.FailedToRecoverCFG

    member _.OnFinish (ctx) =
      if noRetAnalyzer.IsNoReturn (ctx.CFG) then ctx.NonReturningStatus <- NoRet
      else ctx.NonReturningStatus <- NotNoRet
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