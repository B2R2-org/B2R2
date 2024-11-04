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

namespace B2R2.MiddleEnd.ControlFlowGraph

open System.Collections.Generic
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph

/// Disassembly-based CFG, where each node contains disassembly code.
type DisasmCFG = IGraph<DisasmBasicBlock, CFGEdgeKind>

/// Temporarily stores vertex information for creating DisasmCFG.
type private TemporaryDisasmVertex = {
  Instructions: SortedList<Addr, Instruction>
  Successors: List<Addr * CFGEdgeKind>
  mutable Vertex: IVertex<DisasmBasicBlock>
}

type private DisasmVMap = Dictionary<Addr, TemporaryDisasmVertex>

[<AutoOpen>]
module private DisasmCFGHelper =
  let addEdgeToDisasmVertex (vMap: DisasmVMap) addr succ =
    match succ with
    | Some (succAddr, edge) ->
      let tmpV = vMap[addr]
      tmpV.Successors.Add (succAddr, edge)
    | None -> ()

  let hasSameAddress (v1: IVertex<_>) (v2: IVertex<_>) =
    let v1Addr = (v1.VData :> IAddressable).PPoint.Address
    let v2Addr = (v2.VData :> IAddressable).PPoint.Address
    v1Addr = v2Addr

  let hasSingleIncomingEdge (g: LowUIRCFG) v =
    g.GetPreds v
    |> Seq.filter (not << hasSameAddress v)
    |> Seq.tryExactlyOne
    |> Option.isSome

  let hasManyOutgoingEdges (g: LowUIRCFG) v =
    let cnt = g.GetSuccs v |> Array.length
    cnt > 1

  let getNeighbors (g: LowUIRCFG) v =
    let preds = g.GetPreds v
    let succs = g.GetSuccs v
    Seq.append preds succs

  let isIntraNode g v =
    getNeighbors g v
    |> Seq.exists (hasSameAddress v)

  /// Collect pairs of vertices that can be merged. Such a pair should have only
  /// one possible flow between them.
  let collectVerticesToMerge (g: LowUIRCFG) =
    let verticesToMerge = Dictionary ()
    for v in g.Vertices do
      match g.GetSuccs v |> Seq.tryExactlyOne with
      | Some succ when hasSingleIncomingEdge g succ ->
        (* Merge a caller node and its fallthrough node. *)
        if (v.VData :> IAbstractable<_>).IsAbstract then
          let pred = g.GetPreds v |> Seq.exactlyOne
          verticesToMerge[pred] <- succ
          assert (pred.VData.Internals.PPoint < succ.VData.Internals.PPoint)
        (* Going in to an intra node *)
        elif not <| isIntraNode g v && isIntraNode g succ then
          verticesToMerge[v] <- succ
          assert (v.VData.Internals.PPoint < succ.VData.Internals.PPoint)
        (* Going out from an intra node *)
        elif isIntraNode g v && not <| isIntraNode g succ then
          verticesToMerge[v] <- succ
          assert (v.VData.Internals.PPoint < succ.VData.Internals.PPoint)
        else ()
      | _ -> ()
    verticesToMerge

  let sortVertices (g: LowUIRCFG) =
    g.Vertices |> Array.sortByDescending (fun v -> v.VData.Internals.PPoint)

  let getTempVertex (vMap: DisasmVMap) addr =
    match vMap.TryGetValue addr with
    | true, tmpV -> tmpV
    | false, _ ->
      let tmpV =
        { Instructions = SortedList ()
          Successors = List ()
          Vertex = null }
      vMap[addr] <- tmpV
      tmpV

  let initTempDisasmVertex vMap (bbl: ILowUIRBasicBlock) =
    let tmpV = getTempVertex vMap bbl.PPoint.Address
    let insList = tmpV.Instructions
    bbl.LiftedInstructions
    |> Array.iter (fun lifted ->
      let ins = lifted.Original
      if insList.ContainsKey ins.Address then ()
      else insList.Add (ins.Address, ins))

  let mergeDisasmVertexInfos (vMap: DisasmVMap) srcAddr ftAddr =
    let src = vMap[srcAddr]
    let dst = vMap[ftAddr]
    for KeyValue (addr, ins) in dst.Instructions do
      src.Instructions.Add (addr, ins)
    vMap.Remove ftAddr |> ignore
    for succ in dst.Successors do
      addEdgeToDisasmVertex vMap srcAddr <| Some succ

  let isNonReturningAbsVertex (g: LowUIRCFG) v =
    g.GetSuccs v |> Array.isEmpty

  let addEdgesToDisasmVertex (g: LowUIRCFG) verticesToMerge vMap v =
    let edges = g.GetSuccEdges v
    let srcAddr = (v: IVertex<LowUIRBasicBlock>).VData.Internals.PPoint.Address
    edges |> Seq.iter (fun (e: Edge<LowUIRBasicBlock, _>) ->
      if e.Second.VData.Internals.IsAbstract then
        if (verticesToMerge: Dictionary<_, _>).ContainsKey e.First
          || isNonReturningAbsVertex g e.Second then ()
        else
          (* When we reach here, we have a call fallthrough edge that meets an
             existing vertex. So we should connect an edge to it. *)
          let last = v.VData.Internals.LastInstruction
          let fallthroughAddr = last.Address + uint64 last.Length
          let succ = Some (fallthroughAddr, e.Label)
          addEdgeToDisasmVertex vMap srcAddr succ
      else
        let dstAddr = e.Second.VData.Internals.PPoint.Address
        let succ = if srcAddr = dstAddr then None else Some (dstAddr, e.Label)
        addEdgeToDisasmVertex vMap srcAddr succ)

  let prepareDisasmCFGInfo (g: LowUIRCFG) =
    let vMap = DisasmVMap ()
    let verticesToMerge = collectVerticesToMerge g
    for v in sortVertices g do
      if v.VData.Internals.IsAbstract then ()
      else
        initTempDisasmVertex vMap v.VData
        match verticesToMerge.TryGetValue v with
        | true, ft ->
          let srcAddr = v.VData.Internals.PPoint.Address
          let ftAddr = ft.VData.Internals.PPoint.Address
          if hasManyOutgoingEdges g v then
            addEdgeToDisasmVertex vMap srcAddr (Some (ftAddr, FallThroughEdge))
            addEdgesToDisasmVertex g verticesToMerge vMap v
          else mergeDisasmVertexInfos vMap srcAddr ftAddr
        | false, _ ->
          if v.VData.Internals.PPoint.Position = 0 then
            addEdgesToDisasmVertex g verticesToMerge vMap v
          else ()
    vMap

  let addDisasmCFGVertices (vMap: DisasmVMap) newGraph =
    vMap |> Seq.fold (fun (g: DisasmCFG) (KeyValue (addr, tmpV)) ->
      let ppoint = ProgramPoint (addr, 0)
      let instrs = tmpV.Instructions.Values |> Seq.toArray
      let bbl = DisasmBasicBlock (ppoint, instrs)
      let v, g = g.AddVertex bbl
      tmpV.Vertex <- v
      g) newGraph

  let addDisasmCFGEdges (vMap: DisasmVMap) newGraph =
    vMap.Values |> Seq.fold (fun (g: DisasmCFG) tmpV ->
      let src = tmpV.Vertex
      tmpV.Successors |> Seq.fold (fun g (succ, label) ->
        if vMap.ContainsKey succ |> not then ()
        let dst = vMap[succ].Vertex
        g.AddEdge (src, dst, label)
      ) g
    ) newGraph

  let createEmptyDisasmCFGByType (implType: ImplementationType) =
    match implType with
    | Imperative -> ImperativeDiGraph () :> DisasmCFG
    | Persistent -> PersistentDiGraph () :> DisasmCFG

  let createDisasmCFG (implType: ImplementationType) vMap =
    createEmptyDisasmCFGByType implType
    |> addDisasmCFGVertices vMap
    |> addDisasmCFGEdges vMap

[<RequireQualifiedAccess>]
module DisasmCFG =
  /// Constructor for DisasmCFG.
  type IConstructable =
    /// Construct a DisasmCFG.
    abstract Construct: ImplementationType -> DisasmCFG

  /// Create a new DisasmCFG from the given LowUIRCFG.
  [<CompiledName "Create">]
  let create (g: LowUIRCFG) =
    g
    |> prepareDisasmCFGInfo
    |> createDisasmCFG g.ImplementationType
