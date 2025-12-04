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
type DisasmCFG(disasmBuilder, ircfg: LowUIRCFG) =
  let isAbsVertex (v: IVertex<LowUIRBasicBlock>) = v.VData.Internals.IsAbstract

  let haveSameAddresses v1 v2 =
    let addr1 = (v1: IVertex<LowUIRBasicBlock>).VData.Internals.PPoint.Address
    let addr2 = (v2: IVertex<LowUIRBasicBlock>).VData.Internals.PPoint.Address
    addr1 = addr2

  let getInstructions (v: IVertex<LowUIRBasicBlock>) =
    let insList = SortedList()
    v.VData.Internals.LiftedInstructions
    |> Array.iter (fun lifted ->
      let ins = lifted.Original
      if insList.ContainsKey ins.Address then ()
      else insList.Add(ins.Address, ins))
    insList

  let getTempVertex (vMap: TempDisasmVMap) (v: IVertex<LowUIRBasicBlock>) =
    let addr = v.VData.Internals.PPoint.Address
    match vMap.TryGetValue(addr) with
    | true, tmpV -> tmpV
    | false, _ ->
      let tmpV =
        { Address = addr
          Instructions = getInstructions v
          Successors = List()
          IRVertex = v }
      vMap[addr] <- tmpV
      tmpV

  let connect tempVMap srcTmpV (dst: IVertex<LowUIRBasicBlock>) edgeKind =
    let dstAddr = dst.VData.Internals.PPoint.Address
    srcTmpV.Successors.Add(dstAddr, edgeKind)
    getTempVertex tempVMap dst |> ignore

  let merge (tempVMap: TempDisasmVMap) src dstTmpV =
    let srcInss = getInstructions src
    for (KeyValue(addr, ins)) in srcInss do dstTmpV.Instructions.Add(addr, ins)
    tempVMap[src.VData.Internals.PPoint.Address] <- dstTmpV

  let isIntraEdge = function
    | IntraJmpEdge | IntraCJmpTrueEdge | IntraCJmpFalseEdge -> true
    | _ -> false

  let areConsecutive (srcTmpV: TemporaryDisasmVertex) (dst: IVertex<_>) =
    let lastIns = srcTmpV.Instructions.Values |> Seq.last
    let fallthroughAddr = lastIns.Address + uint64 lastIns.Length
    let nextAddr = (dst.VData: LowUIRBasicBlock).Internals.PPoint.Address
    fallthroughAddr = nextAddr

  let hasOnePred (g: LowUIRCFG) (v: IVertex<_>) =
    g.GetPredEdges(v)
    |> Array.filter (fun e -> not <| isIntraEdge e.Label)
    |> Array.length = 1

  let hasOneSucc (g: LowUIRCFG) (v: IVertex<_>) =
    g.GetSuccEdges(v)
    |> Array.filter (fun e -> not <| isIntraEdge e.Label)
    |> Array.length = 1

  let hasIntraBackEdge (g: LowUIRCFG) (v: IVertex<_>) =
    g.GetPredEdges(v)
    |> Array.exists (fun e -> haveSameAddresses e.First e.Second)

  let areMergable g src (srcTmpV: TemporaryDisasmVertex) dst =
    areConsecutive srcTmpV dst
    && hasOnePred g dst
    && hasOneSucc g src
    (* We should check this to handle self-loops with intra-jumps. *)
    && not <| hasIntraBackEdge g srcTmpV.IRVertex

  let rec skipAbsVertices (g: LowUIRCFG) (v: IVertex<LowUIRBasicBlock>) =
    if not v.VData.Internals.IsAbstract then v
    else
      match g.GetSuccs(v) with
      | [||] -> v
      | [| succ |] -> skipAbsVertices g succ
      | _ -> Terminator.impossible ()

  let connectOrMerge tempVMap g src dst e =
    let srcTmpV = getTempVertex tempVMap src
    if isAbsVertex dst || isIntraEdge e then (* Ignore calls and intra-jumps. *)
      ()
    elif areMergable g src srcTmpV dst then (* Merge consecutive nodes. *)
      merge tempVMap dst srcTmpV
    else (* Otherwise, connect them. *)
      connect tempVMap srcTmpV dst e

  let collectFreshSuccEdges (visited: HashSet<_>) (g: IDiGraph<_, _>) v =
    g.GetSuccEdges(v)
    |> Array.filter (not << visited.Contains)
    |> Array.toList

  let rec dfs g tempVMap (visited: HashSet<_>) edges =
    match edges with
    | [] -> ()
    | (e: Edge<LowUIRBasicBlock, _>) :: rest ->
      visited.Add(e) |> ignore
      let s, d, e = e.First, e.Second, e.Label
      if not <| isAbsVertex s then
        connectOrMerge tempVMap g s (skipAbsVertices g d) e
      dfs g tempVMap visited <| (collectFreshSuccEdges visited g d) @ rest

  /// Prepare DisasmCFG information while doing the following transformations:
  /// - Remove intra-node edges by merging the corresponding nodes.
  /// - Remove abstract nodes by connecting their predecessors and successors.
  /// - Merge consecutive nodes.
  /// This has a time complexity of O(|V| + |E|), as we do a DFS traversal of
  /// the given LowUIRCFG.
  let prepareDisasmCFGInfo (g: LowUIRCFG) =
    let tempVMap = TempDisasmVMap()
    let visited = HashSet()
    for root in g.Roots do
      getTempVertex tempVMap root |> ignore
      dfs g tempVMap visited (g.GetSuccEdges(root) |> Array.toList)
    tempVMap

  let getDisasmVertex g (vMap: DisasmVMap) (tempVMap: TempDisasmVMap) addr =
    match vMap.TryGetValue(addr) with
    | true, v -> v, g
    | false, _ ->
      let tmpV = tempVMap[addr]
      let ppoint = ProgramPoint(tmpV.Address, 0)
      let instrs = tmpV.Instructions.Values |> Seq.toArray
      let bbl = DisasmBasicBlock(disasmBuilder, ppoint, instrs)
      let v, g = (g: IDiGraph<_, _>).AddVertex(bbl)
      vMap[addr] <- v
      v, g

  let updateDisasmCFG (tempVMap: TempDisasmVMap) newGraph =
    let vMap = DisasmVMap()
    tempVMap.Values
    |> Seq.distinctBy (fun v -> v.Address)
    |> Seq.fold (fun (g: IDiGraph<_, _>) tmpV ->
      let srcDisasmV, g = getDisasmVertex g vMap tempVMap tmpV.Address
      tmpV.Successors |> Seq.fold (fun g (dst, label) ->
        let dstDisasmV, g = getDisasmVertex g vMap tempVMap dst
        g.AddEdge(srcDisasmV, dstDisasmV, label)
      ) g
    ) newGraph

  let createEmptyDisasmCFGByType (implType: ImplementationType) =
    match implType with
    | Imperative -> ImperativeDiGraph() :> IDiGraph<_, _>
    | Persistent -> PersistentDiGraph() :> IDiGraph<_, _>

  let createDisasmCFG tempVMap =
    createEmptyDisasmCFGByType ircfg.ImplementationType
    |> updateDisasmCFG tempVMap

  let g =
    ircfg
    |> prepareDisasmCFGInfo
    |> createDisasmCFG

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
  member _.Roots with get() = g.GetRoots()

  /// Get the implementation type of this CFG.
  member _.ImplementationType with get() = g.ImplementationType

  /// Is this empty? A CFG is empty when there is no vertex.
  member _.IsEmpty() = g.IsEmpty()

  /// Find an edge between the given source and destination vertices.
  member _.FindEdge(src, dst) = g.FindEdge(src, dst)

  /// Find an edge between the given source and destination vertices. This
  /// function returns an Option type. If there is no such an edge, it returns
  /// None.
  member _.TryFindEdge(src, dst) = g.TryFindEdge(src, dst)

  /// Get the predecessors of the given vertex.
  member _.GetPreds v = g.GetPreds v

  /// Get the predecessor edges of the given vertex.
  member _.GetPredEdges v = g.GetPredEdges v

  /// Get the successors of the given vertex.
  member _.GetSuccs v = g.GetSuccs v

  /// Get the successor edges of the given vertex.
  member _.GetSuccEdges v = g.GetSuccEdges v

  /// Fold the vertices of this CFG with the given function and accumulator.
  member _.FoldVertex(fn, acc) = g.FoldVertex(fn, acc)

  /// Iterate over the vertices of this CFG with the given function.
  member _.IterVertex fn = g.IterVertex fn

  /// Fold the edges of this CFG with the given function and accumulator.
  member _.FoldEdge(fn, acc) = g.FoldEdge(fn, acc)

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
    member _.IsEmpty() = g.IsEmpty()
    member _.HasVertex vid = g.HasVertex vid
    member _.HasEdge(src, dst) = g.HasEdge(src, dst)
    member _.FindVertexByID vid = g.FindVertexByID vid
    member _.TryFindVertexByID vid = g.TryFindVertexByID vid
    member _.FindVertexByData vdata = g.FindVertexByData vdata
    member _.TryFindVertexByData vdata = g.TryFindVertexByData vdata
    member _.FindVertexBy fn = g.FindVertexBy fn
    member _.TryFindVertexBy fn = g.TryFindVertexBy fn
    member _.FindEdge(src, dst) = g.FindEdge(src, dst)
    member _.TryFindEdge(src, dst) = g.TryFindEdge(src, dst)
    member _.GetPreds v = g.GetPreds v
    member _.GetPredEdges v = g.GetPredEdges v
    member _.GetSuccs v = g.GetSuccs v
    member _.GetSuccEdges v = g.GetSuccEdges v
    member _.GetRoots() = g.GetRoots()
    member _.Reverse vs = g.Reverse vs
    member _.FoldVertex(fn, acc) = g.FoldVertex(fn, acc)
    member _.IterVertex fn = g.IterVertex fn
    member _.FoldEdge(fn, acc) = g.FoldEdge(fn, acc)
    member _.IterEdge fn = g.IterEdge fn

  interface ISCCEnumerable<DisasmBasicBlock> with
    member _.GetSCCEnumerator() = SCC.Tarjan.compute g

/// Temporarily stores vertex information for creating DisasmCFG.
and private TemporaryDisasmVertex =
  { /// An address of this vertex.
    Address: Addr
    /// Instructions that will be gathered while merging vertices.
    Instructions: SortedList<Addr, IInstruction>
    /// Successor addresses along with edge kinds.
    Successors: List<Addr * CFGEdgeKind>
    /// Corresponding IR-level vertex. This represents the original vertex when
    /// merging vertices, which is guaranteed by our depth-first traversal.
    IRVertex: IVertex<LowUIRBasicBlock> }

/// Mapping from address to TemporaryDisasmVertex.
and private TempDisasmVMap = Dictionary<Addr, TemporaryDisasmVertex>

/// Mapping from address to TemporaryDisasmVertex.
and private DisasmVMap = Dictionary<Addr, IVertex<DisasmBasicBlock>>
