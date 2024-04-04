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
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.SSA

type CFGAction<'Abs when 'Abs: null> =
  /// Build an initial CFG that is reachable from the given entry point.
  | InitialCFG of entryPoint: Addr * mode: ArchOperationMode
  ///
  | CallEdge of calleeAddr: Addr
  | IndirectEdge of IRBasicBlock<'Abs>
  | SyscallEdge of IRBasicBlock<'Abs>
  | JumpTableEntryStart of IRBasicBlock<'Abs> * Addr * Addr
  | JumpTableEntryEnd of IRBasicBlock<'Abs> * Addr * Addr
with
  interface ICFGAction with
    member __.Priority =
      match __ with
      | InitialCFG _ -> 4
      | CallEdge _ -> 3
      | IndirectEdge _ -> 2
      | SyscallEdge _ -> 1
      | JumpTableEntryStart _ -> 0
      | JumpTableEntryEnd _ -> 0

type BuildingState () =
  let mutable workingJumpTable: (Addr * Addr) option = None

  member _.WorkingJumpTable
    with get() = workingJumpTable and set(v) = workingJumpTable <- v

  interface IResettable with
    member __.Reset () =
      __.WorkingJumpTable <- None

type CFGQuery =
  | FunctionInfo of calleeAddr: Addr
  | JumpTableRegistration of jtAddr: Addr
  | JumpTableConfirmation of entryPoint: Addr * jtAddr: Addr

/// Simple strategy for building a CFG.
type SimpleStrategy (noRetAnalyzer: INoReturnIdentifiable) =
  let scanBBLs ctxt entryPoint mode =
    ctxt.BBLFactory.ScanBBLs [ (entryPoint, mode) ]
    |> Async.AwaitTask
    |> Async.RunSynchronously

  let vertices = Dictionary<ProgramPoint, IVertex<_>> ()

  let getVertex ctxt ppoint =
    match vertices.TryGetValue ppoint with
    | true, v -> v
    | false, _ ->
      let v, g = ctxt.CFG.AddVertex (ctxt.BBLFactory.Find ppoint)
      ctxt.CFG <- g
      vertices[ppoint] <- v
      v

  let connectEdge ctxt srcVertex dstPPoint edgeKind =
    let dstVertex = getVertex ctxt dstPPoint
    ctxt.CFG <- ctxt.CFG.AddEdge (srcVertex, dstVertex, edgeKind)

  let maskedPPoint ctxt targetAddr =
    let rt = ctxt.BinHandle.File.ISA.WordSize |> WordSize.toRegType
    let mask = BitVector.UnsignedMax rt |> BitVector.ToUInt64
    ProgramPoint (targetAddr &&& mask, 0)

  let constructCFG ctxt addr mode =
    let queue = Queue<ProgramPoint> ([| ProgramPoint (addr, 0) |])
    let visited = HashSet<ProgramPoint> ()
    while queue.Count > 0 do
      let ppoint = queue.Dequeue ()
      if visited.Contains ppoint then ()
      else
        visited.Add ppoint |> ignore
        let srcVertex = getVertex ctxt ppoint
        let srcBBL = srcVertex.VData
        match srcBBL.Terminator.S with
        | IEMark _ ->
          let last = srcBBL.LastInstruction
          let nextPPoint = ProgramPoint (last.Address + uint64 last.Length, 0)
          connectEdge ctxt srcVertex nextPPoint FallThroughEdge
          queue.Enqueue nextPPoint
        | Jmp { E = Name lbl } ->
          let dstPPoint = srcBBL.LabelMap[lbl]
          connectEdge ctxt srcVertex dstPPoint IntraJmpEdge
          queue.Enqueue dstPPoint
        | CJmp (_, { E = Name tLbl }, { E = Name fLbl }) ->
          let tPPoint = srcBBL.LabelMap[tLbl]
          let fPPoint = srcBBL.LabelMap[fLbl]
          connectEdge ctxt srcVertex tPPoint IntraCJmpTrueEdge
          connectEdge ctxt srcVertex fPPoint IntraCJmpFalseEdge
          queue.Enqueue tPPoint
          queue.Enqueue fPPoint
        | InterJmp ({ E = BinOp (BinOpType.ADD, _, { E = PCVar _ },
                                                   { E = Num n }) },
                          InterJmpKind.Base) ->
          let target = srcBBL.LastInstruction.Address + BitVector.ToUInt64 n
          let dstPPoint = maskedPPoint ctxt target
          connectEdge ctxt srcVertex dstPPoint InterJmpEdge
          queue.Enqueue dstPPoint
        | InterJmp ({ E = Num n }, InterJmpKind.Base) ->
          let dstPPoint = maskedPPoint ctxt (BitVector.ToUInt64 n)
          connectEdge ctxt srcVertex dstPPoint InterJmpEdge
          queue.Enqueue dstPPoint
        | InterJmp ({ E = BinOp (BinOpType.ADD, _, { E = PCVar _ },
                                                   { E = Num n }) },
                          InterJmpKind.IsCall) ->
          let target = srcBBL.LastInstruction.Address + BitVector.ToUInt64 n
          ctxt.ManagerState.UpdateDependency (addr, target, mode)
        | InterJmp ({ E = Num n }, InterJmpKind.IsCall) ->
          ctxt.ManagerState.UpdateDependency (addr, BitVector.ToUInt64 n, mode)
        | InterCJmp (_, { E = BinOp (BinOpType.ADD, _, { E = PCVar _ },
                                                       { E = Num tv }) },
                        { E = BinOp (BinOpType.ADD, _, { E = PCVar _ },
                                                       { E = Num fv }) }) ->
          let lastAddr = srcBBL.LastInstruction.Address
          let tPPoint = maskedPPoint ctxt (lastAddr + BitVector.ToUInt64 tv)
          let fPPoint = maskedPPoint ctxt (lastAddr + BitVector.ToUInt64 fv)
          connectEdge ctxt srcVertex tPPoint InterCJmpTrueEdge
          connectEdge ctxt srcVertex fPPoint InterCJmpFalseEdge
          queue.Enqueue tPPoint
          queue.Enqueue fPPoint
        | InterCJmp (_, { E = Num tv }, { E = Num fv }) ->
          let tPPoint = maskedPPoint ctxt (BitVector.ToUInt64 tv)
          let fPPoint = maskedPPoint ctxt (BitVector.ToUInt64 fv)
          connectEdge ctxt srcVertex tPPoint InterCJmpTrueEdge
          connectEdge ctxt srcVertex fPPoint InterCJmpFalseEdge
          queue.Enqueue tPPoint
          queue.Enqueue fPPoint
        | Jmp _ | CJmp _ | InterJmp _ | InterCJmp _ ->
          ()
        | _ ->
          ()

  new () =
    let noRetAnalyzer =
      { new INoReturnIdentifiable with
          member _.IsNoReturn (_, _) = true }
    SimpleStrategy noRetAnalyzer

  interface IFunctionBuildingStrategy<IRBasicBlock<SSAFunctionAbstraction>,
                                      CFGEdgeKind,
                                      SSAFunctionAbstraction,
                                      CFGAction<SSAFunctionAbstraction>,
                                      BuildingState,
                                      CFGQuery,
                                      int> with
    member __.PopulateInitialAction (entryPoint, mode) =
      InitialCFG (entryPoint, mode)

    member _.OnAction (ctxt, queue, action) =
      match action with
      | InitialCFG (entryPoint, mode) ->
        scanBBLs ctxt entryPoint mode
        try constructCFG ctxt entryPoint mode; Success
        with _ -> Failure ErrorCase.FailedToRecoverCFG
      | _ ->
        failwith "X"

    member _.OnFinish (ctxt) =
      failwith "X"

    member _.OnQuery (msg, validator) =
      failwith "X"
