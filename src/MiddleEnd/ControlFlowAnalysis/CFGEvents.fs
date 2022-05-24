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

namespace B2R2.MiddleEnd.ControlFlowAnalysis

open B2R2
open B2R2.MiddleEnd.ControlFlowGraph

/// A basic event that triggers CFG modifications.
type BasicCFGEvent =
  /// Add a new function.
  | CFGFunc of entry: Addr * mode: ArchOperationMode
  /// Add a new inter edge. Note intra edges are connected during bbl parsing.
  | CFGEdge of fn: RegularFunction
             * src: ProgramPoint * dst: Addr * edge: CFGEdgeKind
  /// Add an inter-procedural fake block for the call instruction.
  | CFGCall of fn: RegularFunction * callSite: Addr * callee: Addr * noFn: bool
  /// Add a fake return edge for the call instruction.
  | CFGRet of fn: RegularFunction * callee: Addr * ftAddr: Addr * callSite: Addr
  /// Add a fake block for an indirect call instruction.
  | CFGIndCall of fn: RegularFunction * callSite: Addr
  /// Add a fake block for a tail-call.
  | CFGTailCall of fn: RegularFunction * callSite: Addr * callee: Addr

/// List of CFGEvents. We divide events into three groups: (1) basic events, (2)
/// callee-analysis events, and (3) per-function-analysis events. The basic
/// events are essential ones for building regular CFGs. The callee-analysis
/// events are to detect mutually recursive callee analysis events. The
/// function-analysis events are to perform per-function analysis in order to
/// recover high-level CFG information, such as no-return information, and
/// indirect branch targets.
type CFGEvents = {
  /// List of basic CFG events (LIFO).
  BasicEvents: BasicCFGEvent list
  /// Callee analysis edges, where each edge shows dependency between two
  /// functions. This maps a source node to a set of destination nodes.
  CalleeAnalysisEdges: Map<Addr, Set<Addr>>
  /// List of function addresses (FIFO) that needs to perform per-function
  /// analyses.
  FunctionAnalysisAddrs: Addr list
}

[<RequireQualifiedAccess>]
module CFGEvents =
  let empty =
    { BasicEvents = []
      CalleeAnalysisEdges = Map.empty
      FunctionAnalysisAddrs = [] }

  let addFuncEvt entry mode evts =
    { evts with
        BasicEvents = CFGFunc (entry, mode) :: evts.BasicEvents
        FunctionAnalysisAddrs = entry :: evts.FunctionAnalysisAddrs }

  let addEdgeEvt fn src dst edge evts =
    { evts with
        BasicEvents = CFGEdge (fn, src, dst, edge) :: evts.BasicEvents }

  let addCallEvt fn callSiteAddr callee noFn evts =
    { evts with
        BasicEvents =
          CFGCall (fn, callSiteAddr, callee, noFn) :: evts.BasicEvents }

  let addRetEvt fn callee ftAddr callSiteAddr evts =
    { evts with
        BasicEvents =
          CFGRet (fn, callee, ftAddr, callSiteAddr) :: evts.BasicEvents }

  let addIndCallEvt fn callSiteAddr evts =
    { evts with
        BasicEvents = CFGIndCall (fn, callSiteAddr) :: evts.BasicEvents }

  let addTailCallEvt fn callSiteAddr callee evts =
    { evts with
        BasicEvents =
          CFGTailCall (fn, callSiteAddr, callee) :: evts.BasicEvents }

  let addPerFuncAnalysisEvt entry evts =
    { evts with FunctionAnalysisAddrs = entry :: evts.FunctionAnalysisAddrs }

  let addCalleeAnalysisEvt src dst evts =
    let s =
      match Map.tryFind src evts.CalleeAnalysisEdges with
      | Some set -> set
      | None -> Set.empty
    let dsts = Set.add dst s
    { evts with
        CalleeAnalysisEdges = Map.add src dsts evts.CalleeAnalysisEdges }

  let updateEvtsAfterBBLSplit oldPp newPp evts =
    let basicEvents =
      evts.BasicEvents
      |> List.map (fun elm ->
        match elm with
        | CFGEdge (fn, src, dst, edge) when src = oldPp ->
          CFGEdge (fn, newPp, dst, edge)
        | elm -> elm)
    { evts with BasicEvents = basicEvents }

  let updateEvtsAfterBBLMerge srcPp dstPp evts =
    let basicEvents =
      evts.BasicEvents
      |> List.map (fun elm ->
        match elm with
        | CFGEdge (fn, src, dst, edge) when src = dstPp ->
          CFGEdge (fn, srcPp, dst, edge)
        | elm -> elm)
    { evts with BasicEvents = basicEvents }

  let updateEvtsAfterFuncSplit (newFn: RegularFunction) evts =
    let basicEvents =
      evts.BasicEvents
      |> List.map (fun elm ->
        match elm with
        | CFGEdge (_, src, dst, edge) when newFn.HasVertex src ->
          CFGEdge (newFn, src, dst, edge)
        | CFGCall (_, callSite, callee, noFn)
          when newFn.Entry < callSite && newFn.MaxAddr > callSite ->
          CFGCall (newFn, callSite, callee, noFn)
        | CFGRet (_, callee, ftAddr, callSite)
          when newFn.Entry < ftAddr && (newFn.MaxAddr + 1UL) >= ftAddr ->
          CFGRet (newFn, callee, ftAddr, callSite)
        | CFGIndCall (_, callSite)
          when newFn.Entry < callSite && newFn.MaxAddr > callSite ->
          CFGIndCall (newFn, callSite)
        | CFGTailCall (_, callSite, callee)
          when newFn.Entry < callSite && newFn.MaxAddr > callSite ->
          CFGTailCall (newFn, callSite, callee)
        | elm -> elm)
    { evts with BasicEvents = basicEvents }
