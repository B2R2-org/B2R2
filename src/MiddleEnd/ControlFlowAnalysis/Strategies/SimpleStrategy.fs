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
  | InitialCFG of fnAddr: Addr * mode: ArchOperationMode
  /// Add more reachable edges to the initial CFG from the given new program
  /// points.
  | ExpandCFG of fnAddr: Addr * mode: ArchOperationMode * addrs: seq<Addr>
  /// Connect a call edge.
  | CallEdge of fnAddr: Addr * calleeAddr: Addr * mode: ArchOperationMode
  | IndirectEdge of IRBasicBlock<'Abs>
  | SyscallEdge of IRBasicBlock<'Abs>
  | JumpTableEntryStart of IRBasicBlock<'Abs> * Addr * Addr
  | JumpTableEntryEnd of IRBasicBlock<'Abs> * Addr * Addr
with
  interface ICFGAction with
    member __.Priority =
      match __ with
      | InitialCFG _ -> 4
      | ExpandCFG _ -> 4
      | CallEdge _ -> 3
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
  let scanBBLs ctxt mode entryPoints =
    ctxt.BBLFactory.ScanBBLs mode entryPoints
    |> Async.AwaitTask
    |> Async.RunSynchronously

  let getVertex ctxt ppoint =
    match ctxt.Vertices.TryGetValue ppoint with
    | true, v -> v
    | false, _ ->
      let v, g = ctxt.CFG.AddVertex (ctxt.BBLFactory.Find ppoint)
      ctxt.CFG <- g
      ctxt.Vertices[ppoint] <- v
      v

  let connectEdge ctxt srcVertex dstPPoint edgeKind =
    let dstVertex = getVertex ctxt dstPPoint
    ctxt.CFG <- ctxt.CFG.AddEdge (srcVertex, dstVertex, edgeKind)

  let maskedPPoint ctxt targetAddr =
    let rt = ctxt.BinHandle.File.ISA.WordSize |> WordSize.toRegType
    let mask = BitVector.UnsignedMax rt |> BitVector.ToUInt64
    ProgramPoint (targetAddr &&& mask, 0)

  let updateCallingNodes ctxt callingNode calleeAddr =
    match ctxt.CallingNodes.TryGetValue calleeAddr with
    | true, callsites -> callsites.Add callingNode |> ignore
    | false, _ -> ctxt.CallingNodes[calleeAddr] <- HashSet ([ callingNode ])

  let constructCFG ctxt (actionQueue: CFGActionQueue<_>) fnAddr initPPs mode =
    let ppQueue = Queue<ProgramPoint> (collection=initPPs)
    while ppQueue.Count > 0 do
      let ppoint = ppQueue.Dequeue ()
      let userCtxt: CFGContext = ctxt.UserContext
      if userCtxt.VisitedBBLs.Contains ppoint then ()
      else
        userCtxt.VisitedBBLs.Add ppoint |> ignore
        let srcVertex = getVertex ctxt ppoint
        let srcBBL = srcVertex.VData
        match srcBBL.Terminator.S with
        | IEMark _ ->
          let last = srcBBL.LastInstruction
          let nextPPoint = ProgramPoint (last.Address + uint64 last.Length, 0)
          connectEdge ctxt srcVertex nextPPoint FallThroughEdge
          ppQueue.Enqueue nextPPoint
        | Jmp { E = Name lbl } ->
          let dstPPoint = srcBBL.LabelMap[lbl]
          connectEdge ctxt srcVertex dstPPoint IntraJmpEdge
          ppQueue.Enqueue dstPPoint
        | CJmp (_, { E = Name tLbl }, { E = Name fLbl }) ->
          let tPPoint = srcBBL.LabelMap[tLbl]
          let fPPoint = srcBBL.LabelMap[fLbl]
          connectEdge ctxt srcVertex tPPoint IntraCJmpTrueEdge
          connectEdge ctxt srcVertex fPPoint IntraCJmpFalseEdge
          ppQueue.Enqueue tPPoint
          ppQueue.Enqueue fPPoint
        | InterJmp ({ E = BinOp (BinOpType.ADD, _, { E = PCVar _ },
                                                   { E = Num n }) },
                          InterJmpKind.Base) ->
          let target = srcBBL.LastInstruction.Address + BitVector.ToUInt64 n
          let dstPPoint = maskedPPoint ctxt target
          connectEdge ctxt srcVertex dstPPoint InterJmpEdge
          ppQueue.Enqueue dstPPoint
        | InterJmp ({ E = Num n }, InterJmpKind.Base) ->
          let dstPPoint = maskedPPoint ctxt (BitVector.ToUInt64 n)
          connectEdge ctxt srcVertex dstPPoint InterJmpEdge
          ppQueue.Enqueue dstPPoint
        | InterJmp ({ E = BinOp (BinOpType.ADD, _, { E = PCVar _ },
                                                   { E = Num n }) },
                          InterJmpKind.IsCall) ->
          let callsiteAddr = srcBBL.LastInstruction.Address
          let target = callsiteAddr + BitVector.ToUInt64 n
          ctxt.ManagerChannel.UpdateDependency (fnAddr, target, mode)
          ctxt.Callees.Add (callsiteAddr, RegularCallee target)
          updateCallingNodes ctxt srcVertex target
          actionQueue.Push <| CallEdge (fnAddr, target, mode)
        | InterJmp ({ E = Num n }, InterJmpKind.IsCall) ->
          let callsiteAddr = srcBBL.LastInstruction.Address
          let target = BitVector.ToUInt64 n
          ctxt.ManagerChannel.UpdateDependency (fnAddr, target, mode)
          ctxt.Callees.Add (callsiteAddr, RegularCallee target)
          updateCallingNodes ctxt srcVertex target
          actionQueue.Push <| CallEdge (fnAddr, target, mode)
        | InterCJmp (_, { E = BinOp (BinOpType.ADD, _, { E = PCVar _ },
                                                       { E = Num tv }) },
                        { E = BinOp (BinOpType.ADD, _, { E = PCVar _ },
                                                       { E = Num fv }) }) ->
          let lastAddr = srcBBL.LastInstruction.Address
          let tPPoint = maskedPPoint ctxt (lastAddr + BitVector.ToUInt64 tv)
          let fPPoint = maskedPPoint ctxt (lastAddr + BitVector.ToUInt64 fv)
          connectEdge ctxt srcVertex tPPoint InterCJmpTrueEdge
          connectEdge ctxt srcVertex fPPoint InterCJmpFalseEdge
          ppQueue.Enqueue tPPoint
          ppQueue.Enqueue fPPoint
        | InterCJmp (_, { E = Num tv }, { E = Num fv }) ->
          let tPPoint = maskedPPoint ctxt (BitVector.ToUInt64 tv)
          let fPPoint = maskedPPoint ctxt (BitVector.ToUInt64 fv)
          connectEdge ctxt srcVertex tPPoint InterCJmpTrueEdge
          connectEdge ctxt srcVertex fPPoint InterCJmpFalseEdge
          ppQueue.Enqueue tPPoint
          ppQueue.Enqueue fPPoint
        | Jmp _ | CJmp _ | InterJmp _ | InterCJmp _ ->
          ()
        | _ ->
          ()

  let connectFallThroughEdges ctxt queue fnAddr mode callingNodes =
    let newAddrs = List<Addr> ()
    let newEdges = List<IVertex<_> * ProgramPoint> ()
    callingNodes
    |> Seq.iter (fun (srcVertex: IVertex<IRBasicBlock<_>>) ->
      let callIns = srcVertex.VData.LastInstruction
      let fallthroughAddr = callIns.Address + uint64 callIns.Length
      let dstPPoint = ProgramPoint (fallthroughAddr, 0)
      newAddrs.Add (fallthroughAddr)
      newEdges.Add ((srcVertex, dstPPoint))
    )
    scanBBLs ctxt mode newAddrs
    (queue: CFGActionQueue<_>).Push <| ExpandCFG (fnAddr, mode, newAddrs)
    newEdges |> Seq.iter (fun (srcVertex, dstPPoint) ->
      connectEdge ctxt srcVertex dstPPoint CallFallThroughEdge
    )
    Success

  let connectCallEdge ctxt queue fnAddr mode calleeAddr =
    if fnAddr = calleeAddr then (* recursion = always returns *)
      let fnPP = ProgramPoint (fnAddr, 0)
      [| getVertex ctxt fnPP |]
      |> connectFallThroughEdges ctxt queue fnAddr mode
    else
      match ctxt.ManagerChannel.GetBuildingContext calleeAddr with
      | Some calleeContext ->
        if calleeContext.IsNoRet then Success
        else
          ctxt.CallingNodes[calleeAddr]
          |> connectFallThroughEdges ctxt queue fnAddr mode
      | None -> Postponement

  new () =
    let noRetAnalyzer =
      { new INoReturnIdentifiable with
          member _.IsNoReturn (_) = true }
    SimpleStrategy noRetAnalyzer

  interface IFunctionBuildingStrategy<IRBasicBlock<SSAFunctionAbstraction>,
                                      CFGEdgeKind,
                                      SSAFunctionAbstraction,
                                      CFGAction<SSAFunctionAbstraction>,
                                      CFGContext,
                                      EmptyState> with
    member __.PopulateInitialAction (entryPoint, mode) =
      InitialCFG (entryPoint, mode)

    member _.OnAction (ctxt, queue, action) =
      try
        match action with
        | InitialCFG (fnAddr, mode) ->
          let pp = ProgramPoint (fnAddr, 0)
          scanBBLs ctxt mode [ fnAddr ]
          constructCFG ctxt queue fnAddr [| pp |] mode
          Success
        | ExpandCFG (fnAddr, mode, addrs) ->
          let newPPs = addrs |> Seq.map (fun addr -> ProgramPoint (addr, 0))
          constructCFG ctxt queue fnAddr newPPs mode
          Success
        | CallEdge (fnAddr, calleeAddr, mode) ->
          connectCallEdge ctxt queue fnAddr mode calleeAddr
        | _ ->
          failwith "X"
      with e ->
        Console.Error.WriteLine $"OnAction failed:\n{e}"
        Failure ErrorCase.FailedToRecoverCFG

    member _.OnFinish (ctxt) =
      ctxt.IsNoRet <- noRetAnalyzer.IsNoReturn (ctxt.CFG)
      Success