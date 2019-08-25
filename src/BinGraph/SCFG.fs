(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Soomin Kim <soomink@kaist.ac.kr>
          Sang Kil Cha <sangkilc@kaist.ac.kr>

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
open System.Collections.Generic

/// Raised when the given address is not a start address of a function.
exception InvalidFunctionAddressException

/// Super Control Flow Graph (SCFG) of a program. We use LowUIR to construct a
/// SCFG, and it is important to note that LowUIR-level CFG is more specific
/// than the one from disassembly. That is, a single machine instruction (thus,
/// a single basic block) may correspond to multiple basic blocks in the
/// LowUIR-level CFG.
type SCFG (hdl, app) =
  let g = IRCFG ()
  let vertices = SCFGUtils.VMap ()
  let mutable boundaries = IntervalSet.empty
  do
    let leaders = app.LeaderPositions |> Set.toArray
    for i = 0 to leaders.Length - 1 do
      SCFGUtils.createNode g app vertices leaders i
#if DEBUG
    printfn "[*] All the nodes are created."
#endif
    for i = 0 to leaders.Length - 1 do
      SCFGUtils.connectEdges hdl g app vertices leaders i
#if DEBUG
    printfn "[*] All the edges are connected."
#endif
    boundaries <- SCFGUtils.computeBoundaries app vertices
#if DEBUG
    printfn "[*] Boundary computation is done."
#endif

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
  /// address (addr) from the SCFG, and the root node.
  member __.GetFunctionCFG (addr: Addr) =
    let newGraph = IRCFG ()
    let vMap = new Dictionary<ProgramPoint, Vertex<IRBasicBlock>> ()
    let rec loop parentVertex pos e =
      let oldVertex = vertices.[pos]
      let visited, curVertex = getCurrentVertex oldVertex pos e
      addEdge parentVertex curVertex e
      if visited || e = CallEdge then ()
      else iterSuccessors oldVertex curVertex oldVertex.Succs
    and getCurrentVertex oldVertex pos e =
      match e, vMap.TryGetValue pos with
      | CallEdge, (false, _) ->
        let fake = IRBasicBlock([||], pos)
        let v = newGraph.AddVertex fake
        vMap.Add (pos, v)
        false, v
      | _, (false, _) ->
        let v = newGraph.AddVertex oldVertex.VData
        vMap.Add (pos, v)
        false, v
      | _, (true, v) -> true, v
    and addEdge parentVertex curVertex e =
      match parentVertex with
      | None -> ()
      | Some p ->
        newGraph.AddEdge p curVertex e
        if e = CallEdge then
          let last = p.VData.LastInstruction
          let fallthrough = last.Address + uint64 last.Length
          let fallPP = ProgramPoint (fallthrough, 0)
          match app.CalleeMap.Find (curVertex.VData.PPoint.Address) with
          | None -> raise VertexNotFoundException
          | Some callee ->
            if callee.IsNoReturn || (not <| vMap.ContainsKey fallPP) then ()
            else
              let falltarget = vMap.[fallPP]
              newGraph.AddEdge curVertex falltarget RetEdge
        else ()
    and iterSuccessors oldVertex curVertex succs =
      let last = curVertex.VData.LastInstruction
      let fallAddr = last.Address + uint64 last.Length
      let succs = (* Make sure fall-through vertex comes first. *)
        succs |> List.sortBy (fun s ->
          if fallAddr = s.VData.PPoint.Address then -1 else 1)
      match succs with
      | [] -> ()
      | succ :: tl ->
        let succPos = succ.VData.PPoint
        match g.FindEdgeData oldVertex succ with
        | ExternalEdge | RetEdge | ImplicitCallEdge -> ()
        | e -> loop (Some curVertex) succPos e
        iterSuccessors oldVertex curVertex tl
    if app.CalleeMap.Contains addr then
      let rootPos = ProgramPoint (addr, 0)
      loop None rootPos UnknownEdge
      newGraph, vMap.[rootPos]
    else raise InvalidFunctionAddressException

  member private __.ReverseLookUp point =
    let queue = Queue<ProgramPoint> ([ point ])
    let visited = HashSet<ProgramPoint> ()
    let rec loop () =
      if queue.Count = 0 then None
      else
        let point = queue.Dequeue ()
        visited.Add point |> ignore
        match vertices.TryGetValue point with
        | false, _ -> loop ()
        | true, v ->
          if app.CalleeMap.Contains point.Address then Some v
          else
            v.Preds
            |> List.iter (fun v ->
              let point = v.VData.PPoint
              if visited.Contains point then ()
              else queue.Enqueue (point))
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
    |> List.map (fun r -> ProgramPoint (AddrRange.GetMin r, 0))
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
    g.FoldEdge (fun acc _ dst e ->
      match e with
      | CallEdge -> dst.VData.PPoint.Address :: acc
      | _ -> acc) []
