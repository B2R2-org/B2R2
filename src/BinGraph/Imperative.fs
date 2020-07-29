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
open System.Collections.Generic

/// Imperative vertex.
type ImpVertex<'D when 'D :> VertexData> (?v: 'D) =
  inherit Vertex<'D> (v)

  let mutable preds = []
  let mutable succs = []

  /// List of predecessors.
  override __.Preds with get () = preds and set v = preds <- v

  /// List of successors.
  override __.Succs with get () = succs and set v = succs <- v

  static member Init () : Vertex<'D> = upcast (ImpVertex<'D> ())

  static member Init data : Vertex<'D> = upcast (ImpVertex<'D> (data))

/// Imperative GraphCore for directed graph (DiGraph).
type ImperativeCore<'D, 'E when 'D :> VertexData and 'D: equality>
    (init, edgeData, ?vertices, ?edges, ?unreachables, ?exits) =
  inherit GraphCore<'D, 'E, DiGraph<'D, 'E>> ()

  let vertices = defaultArg vertices (HashSet ())
  let edges = defaultArg edges (Dictionary ())
  let unreachables = defaultArg unreachables (HashSet ())
  let exits = defaultArg exits (HashSet ())

  member private __.CheckVertexExistence v =
    if not <| vertices.Contains v then raise VertexNotFoundException

  override __.ImplementationType = ImperativeGraph

  override __.InitGraph core =
    match core with
    | Some core -> init <| core.Clone ()
    | None -> init <| ImperativeCore (init, edgeData)

  override __.Vertices with get () =
    vertices |> Seq.fold (fun acc v -> Set.add v acc) Set.empty

  override __.Unreachables with get () =
    unreachables |> Seq.fold (fun acc v -> v :: acc) []

  override __.Exits with get () =
    exits |> Seq.fold (fun acc v -> v :: acc) []

  override __.GetSize () = vertices.Count

  member private __.AddVertexToCore v =
    vertices.Add v |> ignore
    unreachables.Add v |> ignore
    exits.Add v |> ignore

  override __.AddDummyVertex g =
    let v = ImpVertex.Init ()
    __.AddVertexToCore v
    v, g

  override __.AddVertex g data =
    let v = ImpVertex.Init data
    __.AddVertexToCore v
    v, g

  override __.GetVertex vid =
    match Seq.tryFind (fun (v: Vertex<_>) -> v.GetID () = vid) vertices with
    | Some v -> v
    | None -> raise VertexNotFoundException

  override __.ContainsVertex vid =
    vertices |> Seq.exists (fun (v: Vertex<_>) -> v.GetID () = vid)

  override __.RemoveVertex g v =
    __.CheckVertexExistence v
    v.Preds
    |> List.iter (fun p -> __.RemoveEdge g p v |> ignore)
    v.Succs
    |> List.iter (fun s -> __.RemoveEdge g v s |> ignore)
    vertices.Remove v |> ignore
    unreachables.Remove v |> ignore
    exits.Remove v |> ignore
    g

  override __.FoldVertex fn acc =
    vertices |> Seq.fold fn acc

  override __.IterVertex fn =
    vertices |> Seq.iter fn

  override __.FindVertexBy fn =
    vertices |> Seq.find fn

  override __.TryFindVertexBy fn =
    vertices |> Seq.tryFind fn

  override __.GetPreds v =
    __.CheckVertexExistence v
    v.Preds

  override __.GetSuccs v =
    __.CheckVertexExistence v
    v.Succs

  member private __.AddEdgeToCore (src: Vertex<'D>) (dst: Vertex<'D>) e =
    __.CheckVertexExistence src
    __.CheckVertexExistence dst
    edges.[(src.GetID (), dst.GetID ())] <- (src, dst, e)
    src.Succs <- dst :: src.Succs
    dst.Preds <- src :: dst.Preds
    unreachables.Remove dst |> ignore
    exits.Remove src |> ignore

  override __.AddDummyEdge g src dst =
    __.AddEdgeToCore src dst edgeData
    g

  override __.AddEdge g src dst e =
    __.AddEdgeToCore src dst e
    g

  override __.RemoveEdge g src dst =
    __.CheckVertexExistence src
    __.CheckVertexExistence dst
    let srcid = src.GetID ()
    let dstid = dst.GetID ()
    src.Succs <- List.filter (fun s -> s.GetID () <> dstid) src.Succs
    dst.Preds <- List.filter (fun p -> p.GetID () <> srcid) dst.Preds
    if List.isEmpty dst.Preds then unreachables.Add dst |> ignore
    if List.isEmpty src.Succs then exits.Add src |> ignore
    edges.Remove ((srcid, dstid)) |> ignore
    g

  override __.FoldEdge fn acc =
    edges.Values
    |> Seq.fold (fun acc (src, dst, e) -> fn acc src dst e) acc

  override __.IterEdge fn =
    edges.Values
    |> Seq.iter (fun (src, dst, e) -> fn src dst e)

  override __.FindEdge src dst =
    if edges.ContainsKey (src.GetID (), dst.GetID ()) then
      let _, _, e = edges.[(src.GetID (), dst.GetID ())]
      e
    else raise EdgeNotFoundException

  override __.TryFindEdge src dst =
    if edges.ContainsKey (src.GetID (), dst.GetID ()) then
      let _, _, e = edges.[(src.GetID (), dst.GetID ())]
      Some e
    else None

  override __.Clone () =
    let g = __.InitGraph None
    let core = ImperativeCore (init, edgeData) :> GraphCore<_, _, _>
    __.IterVertex (fun v -> core.AddVertex g v.VData |> ignore)
    __.IterEdge (fun src dst e ->
      let src = core.GetVertex <| src.GetID ()
      let dst = core.GetVertex <| dst.GetID ()
      src.Succs <- dst :: src.Succs
      dst.Preds <- src :: dst.Preds
      core.AddEdge g src dst e |> ignore)
    core

/// Imperative GraphCore for directed graph (DiGraph) that uses AddrRange as key
/// for each vertex, which is useful for managing CFGs of a binary.
type ImperativeRangedCore<'D, 'E when 'D :> RangedVertexData and 'D: equality>
    (init, edgeData, ?vertices, ?rangemap, ?edges, ?unreachables, ?exits) =
  inherit GraphCore<'D, 'E, DiGraph<'D, 'E>> ()

  let vertices = defaultArg vertices (HashSet ())
  let mutable rangemap = defaultArg rangemap IntervalMap.empty
  let edges = defaultArg edges (Dictionary ())
  let unreachables = defaultArg unreachables (HashSet ())
  let exits = defaultArg exits (HashSet ())

  member private __.CheckVertexExistence v =
    if not <| vertices.Contains v then raise VertexNotFoundException

  override __.ImplementationType = ImperativeGraph

  override __.InitGraph core =
    match core with
    | Some core -> init <| core.Clone ()
    | None -> init <| ImperativeRangedCore (init, edgeData)

  override __.Vertices with get () =
    vertices |> Seq.fold (fun acc v -> Set.add v acc) Set.empty

  override __.Unreachables with get () =
    unreachables |> Seq.fold (fun acc v -> v :: acc) []

  override __.Exits with get () =
    exits |> Seq.fold (fun acc v -> v :: acc) []

  override __.GetSize () = vertices.Count

  member private __.AddVertexToCore v =
    vertices.Add v |> ignore
    unreachables.Add v |> ignore
    exits.Add v |> ignore

  override __.AddDummyVertex g =
    let v = ImpVertex.Init ()
    __.AddVertexToCore v
    v, g

  override __.AddVertex g data =
    let v = ImpVertex.Init data
    __.AddVertexToCore v
    rangemap <- IntervalMap.add v.VData.AddrRange v rangemap
    v, g

  override __.GetVertex vid =
    match Seq.tryFind (fun (v: Vertex<_>) -> v.GetID () = vid) vertices with
    | Some v -> v
    | None -> raise VertexNotFoundException

  override __.ContainsVertex vid =
    vertices |> Seq.exists (fun (v: Vertex<_>) -> v.GetID () = vid)

  override __.RemoveVertex g v =
    __.CheckVertexExistence v
    v.Preds
    |> List.iter (fun p -> __.RemoveEdge g p v |> ignore)
    v.Succs
    |> List.iter (fun s -> __.RemoveEdge g v s |> ignore)
    vertices.Remove v |> ignore
    if v.IsDummy () |> not then
      rangemap <- IntervalMap.remove v.VData.AddrRange rangemap
    unreachables.Remove v |> ignore
    exits.Remove v |> ignore
    g

  override __.FoldVertex fn acc =
    vertices |> Seq.fold fn acc

  override __.IterVertex fn =
    vertices |> Seq.iter fn

  override __.FindVertexBy fn =
    vertices |> Seq.find fn

  override __.TryFindVertexBy fn =
    vertices |> Seq.tryFind fn

  override __.GetPreds v =
    __.CheckVertexExistence v
    v.Preds

  override __.GetSuccs v =
    __.CheckVertexExistence v
    v.Succs

  member private __.AddEdgeToCore (src: Vertex<'D>) (dst: Vertex<'D>) e =
    __.CheckVertexExistence src
    __.CheckVertexExistence dst
    if not <| vertices.Contains src then failwith "No"
    if not <| vertices.Contains dst then failwith "No"
    edges.[(src.GetID (), dst.GetID ())] <- (src, dst, e)
    src.Succs <- dst :: src.Succs
    dst.Preds <- src :: dst.Preds
    unreachables.Remove dst |> ignore
    exits.Remove src |> ignore

  override __.AddDummyEdge g src dst =
    __.AddEdgeToCore src dst edgeData
    g

  override __.AddEdge g src dst e =
    __.AddEdgeToCore src dst e
    g

  override __.RemoveEdge g src dst =
    __.CheckVertexExistence src
    __.CheckVertexExistence dst
    let srcid = src.GetID ()
    let dstid = dst.GetID ()
    src.Succs <- List.filter (fun s -> s.GetID () <> dstid) src.Succs
    dst.Preds <- List.filter (fun p -> p.GetID () <> srcid) dst.Preds
    if List.isEmpty dst.Preds then unreachables.Add dst |> ignore
    if List.isEmpty src.Succs then exits.Add src |> ignore
    edges.Remove ((srcid, dstid)) |> ignore
    g

  override __.FoldEdge fn acc =
    edges.Values
    |> Seq.fold (fun acc (src, dst, e) -> fn acc src dst e) acc

  override __.IterEdge fn =
    edges.Values
    |> Seq.iter (fun (src, dst, e) -> fn src dst e)

  override __.FindEdge src dst =
    if edges.ContainsKey (src.GetID (), dst.GetID ()) then
      let _, _, e = edges.[(src.GetID (), dst.GetID ())]
      e
    else raise EdgeNotFoundException

  override __.TryFindEdge src dst =
    if edges.ContainsKey (src.GetID (), dst.GetID ()) then
      let _, _, e = edges.[(src.GetID (), dst.GetID ())]
      Some e
    else None

  override __.Clone () =
    let g = __.InitGraph None
    let core = ImperativeRangedCore (init, edgeData) :> GraphCore<_, _, _>
    __.IterVertex (fun v -> core.AddVertex g v.VData |> ignore)
    __.IterEdge (fun src dst e ->
      let src = core.GetVertex <| src.GetID ()
      let dst = core.GetVertex <| dst.GetID ()
      src.Succs <- dst :: src.Succs
      dst.Preds <- src :: dst.Preds
      core.AddEdge g src dst e |> ignore)
    core
