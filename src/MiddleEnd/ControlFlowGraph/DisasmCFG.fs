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

/// Disassembly-based CFG, where each node contains disassembly code. This is
/// the most user-friendly CFG, although we do not use this for internal
/// analyses. Therefore, this class does not provide ways to modify the CFG.
type DisasmCFG (ircfg: LowUIRCFG) =
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

  /// There are three cases:
  /// (1) it has only one incoming edge (mergable)
  /// (2) it has many incoming edges from a single instruction (mergable)
  /// (3) otherwise (not mergable)
  /// Note that the second case can happen when it has multiple incoming edges
  /// from intra nodes.
  let isMergableWithPredecessors (g: LowUIRCFG) v =
    g.GetPreds v
    |> Array.filter (not << hasSameAddress v)
    |> Array.distinctBy (fun v -> (v.VData :> IAddressable).PPoint.Address)
    |> Array.tryExactlyOne
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
      | Some succ when isMergableWithPredecessors g succ ->
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
    vMap |> Seq.fold (fun (g: IDiGraph<_, _>) (KeyValue (addr, tmpV)) ->
      let ppoint = ProgramPoint (addr, 0)
      let instrs = tmpV.Instructions.Values |> Seq.toArray
      let bbl = DisasmBasicBlock (ppoint, instrs)
      let v, g = g.AddVertex bbl
      tmpV.Vertex <- v
      g) newGraph

  let addDisasmCFGEdges (vMap: DisasmVMap) newGraph =
    vMap.Values |> Seq.fold (fun (g: IDiGraph<_, _>) tmpV ->
      let src = tmpV.Vertex
      tmpV.Successors |> Seq.fold (fun g (succ, label) ->
        if vMap.ContainsKey succ |> not then ()
        let dst = vMap[succ].Vertex
        g.AddEdge (src, dst, label)
      ) g
    ) newGraph

  let createEmptyDisasmCFGByType (implType: ImplementationType) =
    match implType with
    | Imperative -> ImperativeDiGraph () :> IDiGraph<_, _>
    | Persistent -> PersistentDiGraph () :> IDiGraph<_, _>

  let createDisasmCFG vMap =
    createEmptyDisasmCFGByType ircfg.ImplementationType
    |> addDisasmCFGVertices vMap
    |> addDisasmCFGEdges vMap

  let g =
    prepareDisasmCFGInfo ircfg
    |> createDisasmCFG
#if DEBUG
    |> fun g -> assert (g.Unreachables.Length = 1); g
#endif

  /// Number of vertices.
  member _.Size with get() = g.Size

  /// Get an array of all vertices in this CFG.
  member _.Vertices with get() = g.Vertices

  /// Get an array of all edges in this CFG.
  member _.Edges with get() = g.Edges

  /// Get an array of unreachable vertices in this CFG.
  member _.Unreachables with get() = g.Unreachables

  /// Get an array of exit vertices in this CFG.
  member _.Exits with get() = g.Exits

  /// Get exactly one root vertex of this CFG. If there are multiple root
  /// vertices, this will raise an exception.
  member _.SingleRoot with get() = g.SingleRoot

  /// Get the root vertices of this CFG.
  member _.Roots with get() = g.GetRoots ()

  /// Get the implementation type of this CFG.
  member _.ImplementationType with get() = g.ImplementationType

  /// Is this empty? A CFG is empty when there is no vertex.
  member _.IsEmpty () = g.IsEmpty ()

  /// Find an edge between the given source and destination vertices.
  member _.FindEdge (src, dst) = g.FindEdge (src, dst)

  /// Find an edge between the given source and destination vertices. This
  /// function returns an Option type. If there is no such an edge, it returns
  /// None.
  member _.TryFindEdge (src, dst) = g.TryFindEdge (src, dst)

  /// Get the predecessors of the given vertex.
  member _.GetPreds v = g.GetPreds v

  /// Get the predecessor edges of the given vertex.
  member _.GetPredEdges v = g.GetPredEdges v

  /// Get the successors of the given vertex.
  member _.GetSuccs v = g.GetSuccs v

  /// Get the successor edges of the given vertex.
  member _.GetSuccEdges v = g.GetSuccEdges v

  /// Fold the vertices of this CFG with the given function and accumulator.
  member _.FoldVertex fn acc = g.FoldVertex fn acc

  /// Iterate over the vertices of this CFG with the given function.
  member _.IterVertex fn = g.IterVertex fn

  /// Fold the edges of this CFG with the given function and accumulator.
  member _.FoldEdge fn acc = g.FoldEdge fn acc

  /// Iterate over the edges of this CFG with the given function.
  member _.IterEdge fn = g.IterEdge fn

  interface IDiGraphAccessible<DisasmBasicBlock, CFGEdgeKind> with
    member _.Size = g.Size
    member _.Vertices = g.Vertices
    member _.Edges = g.Edges
    member _.Unreachables = g.Unreachables
    member _.Exits = g.Exits
    member _.SingleRoot = g.SingleRoot
    member _.ImplementationType = g.ImplementationType
    member _.IsEmpty () = g.IsEmpty ()
    member _.HasVertex vid = g.HasVertex vid
    member _.FindVertexByID vid = g.FindVertexByID vid
    member _.TryFindVertexByID vid = g.TryFindVertexByID vid
    member _.FindVertexByData vdata = g.FindVertexByData vdata
    member _.TryFindVertexByData vdata = g.TryFindVertexByData vdata
    member _.FindVertexBy fn = g.FindVertexBy fn
    member _.TryFindVertexBy fn = g.TryFindVertexBy fn
    member _.FindEdge (src, dst) = g.FindEdge (src, dst)
    member _.TryFindEdge (src, dst) = g.TryFindEdge (src, dst)
    member _.GetPreds v = g.GetPreds v
    member _.GetPredEdges v = g.GetPredEdges v
    member _.GetSuccs v = g.GetSuccs v
    member _.GetSuccEdges v = g.GetSuccEdges v
    member _.GetRoots () = g.GetRoots ()
    member _.FoldVertex fn acc = g.FoldVertex fn acc
    member _.IterVertex fn = g.IterVertex fn
    member _.FoldEdge fn acc = g.FoldEdge fn acc
    member _.IterEdge fn = g.IterEdge fn
    member _.ToDOTStr (name, vFn, eFn) = g.ToDOTStr (name, vFn, eFn)

  interface ISCCEnumerable<DisasmBasicBlock> with
    member _.GetSCCEnumerator () = SCC.Tarjan.compute g

/// Temporarily stores vertex information for creating DisasmCFG.
and private TemporaryDisasmVertex = {
  Instructions: SortedList<Addr, Instruction>
  Successors: List<Addr * CFGEdgeKind>
  mutable Vertex: IVertex<DisasmBasicBlock>
}

/// Mapping from address to TemporaryDisasmVertex.
and private DisasmVMap = Dictionary<Addr, TemporaryDisasmVertex>
