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

namespace B2R2.BinGraph

open B2R2
open B2R2.BinCorpus
open System.Collections.Generic
open System.Runtime.InteropServices

/// Raised when the given address is not a start address of a function.
exception InvalidFunctionAddressException

/// Super Control Flow Graph (SCFG) of a program. We use LowUIR to construct a
/// SCFG, and it is important to note that LowUIR-level CFG is more specific
/// than the one from disassembly. That is, a single machine instruction (thus,
/// a single basic block) may correspond to multiple basic blocks in the
/// LowUIR-level CFG.
type SCFG internal (app, g, vertices, graphImplementationType) =
  let mutable boundaries = IntervalSet.empty
  let g = SCFGUtils.removeDanglings app g vertices
  do boundaries <- SCFGUtils.computeBoundaries app vertices

  /// SCFG should be constructed only via this method. The ignoreIllegal
  /// argument indicates we will ignore any illegal vertices/edges during the
  /// creation of an SCFG.
  static member Init (hdl, app, graphImpl, ?ignoreIllegal) =
    let ignoreIllegal = defaultArg ignoreIllegal true
    let g = IRCFG.init graphImpl
    let vertices = SCFGUtils.VMap ()
    let leaders = app.LeaderInfos |> Set.toArray |> Array.map (fun l -> l.Point)
    let fold = if ignoreIllegal then SCFGUtils.fold else SCFGUtils.foldUntilErr
    [ 0 .. leaders.Length - 1 ]
    |> fold (SCFGUtils.createNode app vertices leaders) g
    |> Result.bind (fun g ->
      [ 0 .. leaders.Length - 1 ]
      |> fold (SCFGUtils.joinEdges hdl app vertices leaders) g
      |> Result.bind (fun g ->
        SCFG (app, g, vertices, graphImpl) |> Ok))

  member val GraphImplementationType = graphImplementationType with get

  /// The actual graph data structure of the SCFG.
  member __.Graph with get () = g

  /// The set of boundaries (intervals) of the basic blocks.
  member __.Boundaries with get () = boundaries

  /// A mapping from the start address of a basic block to the vertex in the
  /// SCFG.
  member __.Vertices with get () = vertices

  /// Return a vertex located at the given address.
  member __.GetVertex (addr) =
    match vertices.TryGetValue (ProgramPoint (addr, 0)) with
    | false, _ -> raise VertexNotFoundException
    | true, v -> v

  /// Retrieve an IR-based CFG (subgraph) of a function starting at the given
  /// address (addr) from the SCFG, and the root node. When the
  /// preserveRecursiveEdge parameter is false, we create fake blocks for
  /// recursive calls, which is useful for intra-procedural analyses.
  member __.GetFunctionCFG (addr: Addr,
                            [<Optional; DefaultParameterValue(true)>]
                            preserveRecursiveEdge) =
    let newGraph = IRCFG.init graphImplementationType
    let vMap = Dictionary<ProgramPoint, Vertex<IRBasicBlock>> ()
    let visited = HashSet<ProgramPoint> ()
    let rec loop newGraph pos =
      if visited.Contains pos then newGraph
      else
        visited.Add pos |> ignore
        getVertex newGraph pos |> foldSuccessors vertices.[pos]
    and getVertex newGraph pos =
      let origVertex = vertices.[pos]
      match vMap.TryGetValue pos with
      | (false, _) ->
        let v, newGraph = DiGraph.addVertex newGraph origVertex.VData
        vMap.Add (pos, v)
        v, newGraph
      | (true, v) -> v, newGraph
    and foldSuccessors origVertex (curVertex, newGraph) =
      DiGraph.getSuccs g origVertex
      |> List.fold (fun newGraph succ ->
        g.FindEdgeData origVertex succ |> addEdge newGraph curVertex succ) newGraph
    and addEdge newGraph parent child e =
      match e with
      | ExternalCallEdge | ExternalJmpEdge | RetEdge | ImplicitCallEdge -> newGraph
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
        match app.CalleeMap.Find childPp.Address with
        | Some callee when callee.IsNoReturn -> newGraph
        | _ when SCFGUtils.isNoReturn app parent -> newGraph
        | _ ->
          try
            let fall, newGraph = getVertex newGraph fallPp
            DiGraph.addEdge newGraph child fall RetEdge
          with :? KeyNotFoundException ->
#if DEBUG
            printfn "[W] Illegal fall-through edge (%x) ignored." fallPp.Address
#endif
            newGraph
      | InterJmpEdge ->
        match app.CalleeMap.Find (child.VData.PPoint.Address) with
        | Some _ ->
          let childPp = child.VData.PPoint
          let fake = IRBasicBlock ([||], childPp)
          let child, newGraph = DiGraph.addVertex newGraph fake
          DiGraph.addEdge newGraph parent child CallEdge
        | _ ->
          let child, newGraph = getVertex newGraph child.VData.PPoint
          let newGraph = DiGraph.addEdge newGraph parent child e
          loop newGraph child.VData.PPoint
      | _ ->
        let child, newGraph = getVertex newGraph child.VData.PPoint
        let newGraph = DiGraph.addEdge newGraph parent child e
        loop newGraph child.VData.PPoint
    if app.CalleeMap.Contains addr then
      let rootPos = ProgramPoint (addr, 0)
      let newGraph = loop newGraph rootPos
      newGraph, vMap.[rootPos]
    else raise InvalidFunctionAddressException

  member private __.ReverseLookUp addr =
    let queue = Queue<Addr> ([ addr ])
    let visited = HashSet<Addr> ()
    let rec loop () =
      if queue.Count = 0 then None
      else
        let addr = queue.Dequeue ()
        if visited.Contains addr then loop ()
        else
          visited.Add addr |> ignore
          match vertices.TryGetValue (ProgramPoint (addr, 0)) with
          | false, _ -> loop ()
          | true, v ->
            if app.CalleeMap.Contains addr then Some v
            else
              DiGraph.getPreds g v
              |> List.iter (fun v ->
                let addr = v.VData.PPoint.Address
                if visited.Contains addr then ()
                else queue.Enqueue (addr))
              loop ()
    loop ()

  /// Find a basic block (vertex) in the SCFG that the given address belongs to.
  member __.FindVertex (addr) =
    IntervalSet.findAll (AddrRange (addr, addr + 1UL)) __.Boundaries
    |> List.map (fun r -> ProgramPoint (AddrRange.GetMin r, 0))
    |> List.sortBy (fun p -> if p.Address = addr then -1 else 1)
    |> List.choose (fun p -> vertices.TryGetValue p |> Utils.tupleToOpt)
    |> List.tryHead

  /// For a given address, find the first vertex of a function that the address
  /// belongs to.
  member __.FindFunctionVertex (addr) =
    IntervalSet.findAll (AddrRange (addr, addr + 1UL)) __.Boundaries
    |> List.map (fun r -> AddrRange.GetMin r)
    |> List.tryPick __.ReverseLookUp

  /// For a given address, find the address of a function that the address
  /// belongs to.
  member __.FindFunctionEntry (addr) =
    __.FindFunctionVertex (addr)
    |> Option.map (fun v -> v.VData.PPoint.Address)

  /// For a given function name, find the corresponding function address if
  /// exists.
  member __.FindFunctionEntryByName (name: string) =
    app.CalleeMap.Find (name)
    |> Option.bind (fun callee -> callee.Addr)

  /// Retrieve call target addresses.
  member __.CallTargets () =
    [] |> DiGraph.foldEdge g (fun acc _ dst e ->
      match e with
      | CallEdge -> dst.VData.PPoint.Address :: acc
      | _ -> acc)
