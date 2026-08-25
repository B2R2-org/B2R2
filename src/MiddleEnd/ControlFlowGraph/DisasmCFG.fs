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

/// Represents a disassembly-based CFG, where each node contains disassembly
/// code. This is the most user-friendly CFG, although we do not use this for
/// internal analyses. This is a read-only graph: it is built out of a
/// LowUIRCFG and is not modified afterwards.
type DisasmCFG = IDiGraph<DisasmBasicBlock, CFGEdgeKind>

/// Represents the vertex information held while a DisasmCFG is built.
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

/// Represents a mapping from an address to a TemporaryDisasmVertex.
and private TempDisasmVMap = Dictionary<Addr, TemporaryDisasmVertex>

/// Represents a mapping from an address to a DisasmCFG vertex.
and private DisasmVMap = Dictionary<Addr, IVertex<DisasmBasicBlock>>

/// <summary>
/// Provides a way to create a
/// <see cref="T:B2R2.MiddleEnd.ControlFlowGraph.DisasmCFG"/>.
/// </summary>
[<RequireQualifiedAccess>]
module DisasmCFG =
  let private isAbsVertex (v: IVertex<LowUIRBasicBlock>) =
    v.VData.Internals.IsAbstract

  let private haveSameAddresses v1 v2 =
    let addr1 = (v1: IVertex<LowUIRBasicBlock>).VData.Internals.PPoint.Address
    let addr2 = (v2: IVertex<LowUIRBasicBlock>).VData.Internals.PPoint.Address
    addr1 = addr2

  let private getInstructions (v: IVertex<LowUIRBasicBlock>) =
    let insList = SortedList()
    v.VData.Internals.LiftedInstructions
    |> Array.iter (fun lifted ->
      let ins = lifted.Original
      if insList.ContainsKey ins.Address then ()
      else insList.Add(ins.Address, ins))
    insList

  let private getTempVertex (vMap: TempDisasmVMap) v =
    let addr = (v: IVertex<LowUIRBasicBlock>).VData.Internals.PPoint.Address
    match vMap.TryGetValue(addr) with
    | true, tmpV ->
      tmpV
    | false, _ ->
      let tmpV =
        { Address = addr
          Instructions = getInstructions v
          Successors = List()
          IRVertex = v }
      vMap[addr] <- tmpV
      tmpV

  let private connect tempVMap srcTmpV (dst: IVertex<LowUIRBasicBlock>) e =
    let dstAddr = dst.VData.Internals.PPoint.Address
    srcTmpV.Successors.Add(dstAddr, e)
    getTempVertex tempVMap dst |> ignore

  let private merge (tempVMap: TempDisasmVMap) absorbed hostTmpV =
    let inss = getInstructions absorbed
    for (KeyValue(addr, ins)) in inss do hostTmpV.Instructions.Add(addr, ins)
    tempVMap[absorbed.VData.Internals.PPoint.Address] <- hostTmpV

  let private isIntraEdge = function
    | IntraJmpEdge | IntraCJmpTrueEdge | IntraCJmpFalseEdge -> true
    | _ -> false

  let private areConsecutive srcTmpV (dst: IVertex<LowUIRBasicBlock>) =
    let insList = (srcTmpV: TemporaryDisasmVertex).Instructions
    let lastIns = insList.Values |> Seq.last
    let fallthroughAddr = lastIns.Address + uint64 lastIns.Length
    fallthroughAddr = dst.VData.Internals.PPoint.Address

  let private hasOnePred (g: LowUIRCFG) (v: IVertex<_>) =
    g.GetPredEdges(v)
    |> Array.filter (fun e -> not <| isIntraEdge e.Label)
    |> Array.length = 1

  let private hasOneSucc (g: LowUIRCFG) (v: IVertex<_>) =
    g.GetSuccEdges(v)
    |> Array.filter (fun e -> not <| isIntraEdge e.Label)
    |> Array.length = 1

  let private hasIntraBackEdge (g: LowUIRCFG) (v: IVertex<_>) =
    g.GetPredEdges(v)
    |> Array.exists (fun e -> haveSameAddresses e.First e.Second)

  let private areMergable g src (srcTmpV: TemporaryDisasmVertex) dst =
    areConsecutive srcTmpV dst
    && hasOnePred g dst
    && hasOneSucc g src
    (* We should check this to handle self-loops with intra-jumps. *)
    && not <| hasIntraBackEdge g srcTmpV.IRVertex

  let rec private skipAbsVertices (g: LowUIRCFG) v =
    if not (v: IVertex<LowUIRBasicBlock>).VData.Internals.IsAbstract then
      v
    else
      match g.GetSuccs(v) with
      | [||] -> v
      | [| succ |] -> skipAbsVertices g succ
      | _ -> Terminator.impossible ()

  let private connectOrMerge tempVMap g src dst e =
    let srcTmpV = getTempVertex tempVMap src
    if isAbsVertex dst || isIntraEdge e then (* Ignore calls and intra-jumps. *)
      ()
    elif areMergable g src srcTmpV dst then (* Merge consecutive nodes. *)
      merge tempVMap dst srcTmpV
    else (* Otherwise, connect them. *)
      connect tempVMap srcTmpV dst e

  (* Expands a vertex only the first time it is reached, so that each edge is
     pushed exactly once. The edges go on in reverse so that they come off in
     the order the graph hands them out. *)
  let private pushSuccEdges (stack: Stack<_>) (visited: HashSet<_>) g v =
    if visited.Add v then
      let succs = (g: IDiGraph<_, _>).GetSuccEdges(v)
      for i = succs.Length - 1 downto 0 do stack.Push succs[i]
    else
      ()

  let private dfs g tempVMap visited (stack: Stack<Edge<LowUIRBasicBlock, _>>) =
    while stack.Count > 0 do
      let edge = stack.Pop()
      let s, d, e = edge.First, edge.Second, edge.Label
      if not <| isAbsVertex s then
        connectOrMerge tempVMap g s (skipAbsVertices g d) e
      else
        ()
      pushSuccEdges stack visited g d

  /// Prepares DisasmCFG information while doing the following
  /// transformations.
  /// - Remove intra-node edges by merging the corresponding nodes.
  /// - Remove abstract nodes by connecting their predecessors and successors.
  /// - Merge consecutive nodes.
  /// This has a time complexity of O(|V| + |E|), as we do a DFS traversal of
  /// the given LowUIRCFG.
  let private prepareDisasmCFGInfo (g: LowUIRCFG) =
    let tempVMap = TempDisasmVMap()
    let visited = HashSet()
    let stack = Stack()
    let rootAddrs = List()
    for root in g.Roots do
      rootAddrs.Add root.VData.Internals.PPoint.Address
      getTempVertex tempVMap root |> ignore
      pushSuccEdges stack visited g root
      dfs g tempVMap visited stack
    tempVMap, rootAddrs

  let private getDisasmVertex builder g (vMap: DisasmVMap) tempVMap addr =
    match vMap.TryGetValue(addr) with
    | true, v ->
      v
    | false, _ ->
      let tmpV = (tempVMap: TempDisasmVMap)[addr]
      let ppoint = ProgramPoint(tmpV.Address, 0)
      let instrs = tmpV.Instructions.Values |> Seq.toArray
      let bbl = DisasmBasicBlock(builder, ppoint, instrs)
      let v = (g: IMutableDiGraph<_, _>).AddVertex(bbl)
      vMap[addr] <- v
      v

  /// Finds the vertex that each root of the original graph ended up in. A root
  /// merged into the block ahead of it is no vertex of its own any more, hence
  /// the map answers which block holds it rather than the address being used
  /// as it stands. Two roots can land in the one block, which the graph must
  /// not hear of twice.
  let private getRootVertices (tempVMap: TempDisasmVMap) vMap rootAddrs =
    rootAddrs
    |> Seq.map (fun addr -> (vMap: DisasmVMap)[tempVMap[addr].Address])
    |> Seq.distinct
    |> Seq.toArray

  let private updateDisasmCFG builder tempVMap rootAddrs g =
    let vMap = DisasmVMap()
    (tempVMap: TempDisasmVMap).Values
    |> Seq.distinctBy (fun v -> v.Address)
    |> Seq.iter (fun tmpV ->
      let srcDisasmV = getDisasmVertex builder g vMap tempVMap tmpV.Address
      tmpV.Successors |> Seq.iter (fun (dst, label) ->
        let dstDisasmV = getDisasmVertex builder g vMap tempVMap dst
        (g: IMutableDiGraph<_, _>).AddEdge(srcDisasmV, dstDisasmV, label)))
    (* Every vertex is in place by now, hence the roots can be named rather
       than left to whichever vertex the graph happened to take in first. *)
    g.SetRoots(getRootVertices tempVMap vMap rootAddrs)

  /// Creates a disassembly-based CFG out of the given IR-level CFG, whose
  /// implementation type the result keeps.
  let create disasmBuilder (ircfg: LowUIRCFG): DisasmCFG =
    let tempVMap, rootAddrs = prepareDisasmCFGInfo ircfg
    let g = GraphFactory.create ircfg.ImplementationType
    updateDisasmCFG disasmBuilder tempVMap rootAddrs g
    g
