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

namespace B2R2.BinCorpus

open B2R2
open B2R2.BinGraph
open System.Collections.Generic
open System.Runtime.InteropServices

/// Raised when the given address is not a start address of a function.
exception InvalidFunctionAddressException

/// Super Control Flow Graph (SCFG) of a program. We use LowUIR to construct a
/// SCFG, and it is important to note that LowUIR-level CFG is more specific
/// than the one from disassembly. That is, a single machine instruction (thus,
/// a single basic block) may correspond to multiple basic blocks in the
/// LowUIR-level CFG.
type SCFG (hdl, acc, ?graphImpl, ?ignoreIllegal) =
  let graphImpl = defaultArg graphImpl PersistentGraph
  let instrMap = acc.InstrMap
  let bblMap = acc.BasicBlockMap
  let calleeMap = acc.CalleeMap
  let g = acc.Graph
  let noRetInfo = acc.NoReturnInfo
  let indMap = acc.IndirectBranchMap
  let ignoreIllegal = defaultArg ignoreIllegal true

  member __.InstrMap with get () = instrMap

  member __.BasicBlockMap with get () = bblMap

  member __.Graph with get () = g

  member __.CalleeMap with get () = calleeMap

  member __.NoReturnInfo with get () = noRetInfo

  member __.IndirectBranchMap with get () = indMap

  /// Retrieve an IR-based CFG (subgraph) of a function starting at the given
  /// address (addr) from the SCFG, and the root node. When the
  /// preserveRecursiveEdge parameter is false, we create fake blocks for
  /// recursive calls, which is useful for intra-procedural analyses.
  member __.GetFunctionCFG (addr: Addr,
                            [<Optional; DefaultParameterValue(true)>]
                            preserveRecursiveEdge) =
    let newGraph = IRCFG.init graphImpl
    let vMap = Dictionary<ProgramPoint, Vertex<IRBasicBlock>> ()
    let visited = HashSet<ProgramPoint> ()
    let rec loop newGraph pos =
      if visited.Contains pos then newGraph
      else
        visited.Add pos |> ignore
        getVertex newGraph pos
        |> foldSuccessors (Map.find pos bblMap.VertexMap)
    and getVertex newGraph pos =
      match vMap.TryGetValue pos with
      | true, v -> v, newGraph
      | false, _ ->
        let oldV = Map.find pos bblMap.VertexMap
        let v, newGraph = DiGraph.addVertex newGraph oldV.VData
        vMap.[pos] <- v
        v, newGraph
    and foldSuccessors origVertex (curVertex, newGraph) =
      DiGraph.getSuccs g origVertex
      |> List.fold (fun newGraph succ ->
        g.FindEdgeData origVertex succ
        |> addEdge newGraph curVertex succ) newGraph
    and addEdge newGraph parent child e =
      match e with
      | ExternalCallEdge | ExternalJmpEdge | RetEdge | ImplicitCallEdge ->
        newGraph
      | CallEdge
        when preserveRecursiveEdge && child.VData.PPoint.Address = addr ->
        let child, newGraph = getVertex newGraph child.VData.PPoint
        DiGraph.addEdge newGraph parent child RecursiveCallEdge
      | CallEdge | IndirectCallEdge ->
        let last = parent.VData.LastInstruction
        let fallPp = ProgramPoint (last.Address + uint64 last.Length, 0)
        let childPp =
          if child.VData.IsFakeBlock () then ProgramPoint.GetFake ()
          else child.VData.PPoint
        let fake = IRBasicBlock ([||], childPp)
        let child, newGraph = DiGraph.addVertex newGraph fake
        let newGraph = DiGraph.addEdge newGraph parent child e
        if SCFGUtils.isNoReturn noRetInfo parent then newGraph
        else
          try
            let fall, newGraph = getVertex newGraph fallPp
            DiGraph.addEdge newGraph child fall RetEdge
          with :? KeyNotFoundException ->
#if DEBUG
            printfn "[W] Illegal fall-through edge (%x) ignored." fallPp.Address
#endif
            newGraph
      | InterJmpEdge ->
        if calleeMap.Contains child.VData.PPoint.Address then
          let childPp = child.VData.PPoint
          let fake = IRBasicBlock ([||], childPp)
          let child, newGraph = DiGraph.addVertex newGraph fake
          DiGraph.addEdge newGraph parent child CallEdge
        else
          let child, newGraph = getVertex newGraph child.VData.PPoint
          let newGraph = DiGraph.addEdge newGraph parent child e
          loop newGraph child.VData.PPoint
      | _ ->
        let child, newGraph = getVertex newGraph child.VData.PPoint
        let newGraph = DiGraph.addEdge newGraph parent child e
        loop newGraph child.VData.PPoint
    if calleeMap.Contains addr then
      let rootPos = ProgramPoint (addr, 0)
      let newGraph = loop newGraph rootPos
      newGraph, vMap.[rootPos]
    else raise InvalidFunctionAddressException

  member private __.ReverseLookUp src =
    let queue = Queue<Vertex<IRBasicBlock>> ([ src ])
    let visited = HashSet<Vertex<IRBasicBlock>> ()
    let rec loop () =
      if queue.Count = 0 then None
      else
        let v = queue.Dequeue ()
        if visited.Contains v then loop ()
        else
          visited.Add v |> ignore
          let addr = v.VData.PPoint.Address
          if calleeMap.Contains addr then Some v
          else
            DiGraph.getPreds g v
            |> List.iter (fun v ->
              if visited.Contains v then ()
              else queue.Enqueue (v))
            loop ()
    loop ()

  /// Find a basic block (vertex) in the SCFG that the given address belongs to.
  member __.FindVertex (addr) =
    IntervalSet.findAll (AddrRange (addr, addr + 1UL)) bblMap.Boundaries
    |> List.map (fun r -> ProgramPoint (AddrRange.GetMin r, 0))
    |> List.sortBy (fun p -> if p.Address = addr then -1 else 1)
    |> List.choose (fun p -> Map.tryFind p bblMap.VertexMap)
    |> List.tryHead

  /// For a given address, find the first vertex of a function that the address
  /// belongs to.
  member __.FindFunctionVertex (addr) =
    IntervalSet.findAll (AddrRange (addr, addr + 1UL)) bblMap.Boundaries
    |> List.map (fun r ->
      let addr = AddrRange.GetMin r
      Map.find (ProgramPoint (addr, 0)) bblMap.VertexMap)
    |> List.tryPick __.ReverseLookUp

  member __.AddEntry hdl parseMode (entry: Addr) =
    let calleeMap = calleeMap.AddEntry hdl entry
    let acc =
      { InstrMap = instrMap
        BasicBlockMap = bblMap
        CalleeMap = calleeMap
        Graph = g
        NoReturnInfo = noRetInfo
        IndirectBranchMap = indMap }
    match SCFGUtils.updateCFG hdl parseMode acc false [(None, entry)] with
    | Ok (acc, _) ->
      SCFG (hdl, acc, graphImpl, ignoreIllegal)
      |> Ok
    | Error () -> if ignoreIllegal then Error () else Utils.impossible ()

  member __.AddEdge hdl parseMode src dst edgeKind =
    let acc =
      { InstrMap = instrMap
        BasicBlockMap = bblMap
        CalleeMap = calleeMap
        Graph = g
        NoReturnInfo = noRetInfo
        IndirectBranchMap = indMap }
    let edgeInfo = Some (ProgramPoint (src, 0), edgeKind), dst
    match SCFGUtils.updateCFG hdl parseMode acc false [edgeInfo] with
    | Ok (acc, hasNewIndBranch) ->
      let scfg =
        SCFG (hdl, acc, graphImpl, ignoreIllegal)
      Ok (scfg, hasNewIndBranch)
    | Error () ->
      if ignoreIllegal then Error () else Utils.impossible ()

  member __.AddNoReturnInfo hdl noRetFuncs noRetCallSites =
    let noRetFuncs = Set.union noRetFuncs noRetInfo.NoReturnFuncs
    let noRetCallSites = Set.union noRetCallSites noRetInfo.NoReturnCallSites
    let noRetInfo = NoReturnInfo.Init noRetFuncs noRetCallSites
    let acc = { acc with NoReturnInfo = noRetInfo }
    let acc = SCFGUtils.removeNoReturnFallThroughs acc
    SCFG (hdl, acc, graphImpl, ignoreIllegal)

  member __.AddIndirectBranchMap hdl indMap' =
    let indMap =
      indMap' |> Map.fold (fun acc addr info -> Map.add addr info acc) indMap
    let acc = { acc with IndirectBranchMap = indMap }
    SCFG (hdl, acc, graphImpl, ignoreIllegal)
