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

namespace B2R2.MiddleEnd.BinGraph

open System.Collections.Generic

/// Represents a directed graph that is modified in place, keeping its state
/// in hash tables of its own.
type MutableDiGraph<'V, 'E when 'V: equality and 'E: equality>
  private(initialID: VertexID) =

  let vertices = Dictionary<VertexID, IVertex<'V>>()

  (* The key is a struct tuple, for a reference tuple would put one allocation
     on every lookup, and looking an edge up is what most of the modifying
     operations start with. *)
  let edges = Dictionary<struct (VertexID * VertexID), Edge<'V, 'E>>()

  (* The adjacency lists hold the edges rather than their far endpoints, which
     is what lets the edges of a vertex be handed out without a lookup of
     their own, and is what the persistent graph holds, too. *)
  let preds = Dictionary<VertexID, List<Edge<'V, 'E>>>()

  let succs = Dictionary<VertexID, List<Edge<'V, 'E>>>()

  let exits = HashSet<IVertex<'V>>()

  let mutable id = initialID

  let roots = List<IVertex<'V>>()

  (* Reading the endpoints out of an adjacency list one by one is what keeps
     an accessor to the single allocation of its result; mapping over the list
     would add one more. *)
  let toSrcArray (es: List<Edge<'V, 'E>>) =
    let arr = Array.zeroCreate es.Count
    for i in 0 .. es.Count - 1 do arr[i] <- es[i].First
    arr

  let toDstArray (es: List<Edge<'V, 'E>>) =
    let arr = Array.zeroCreate es.Count
    for i in 0 .. es.Count - 1 do arr[i] <- es[i].Second
    arr

  (* A vertex belongs to this graph only when it is the very object we store
     for its ID. Comparing IDs is not enough, because a vertex of another
     graph can carry an ID we also use. *)
  let isOwnVertex (v: IVertex<'V>) =
    match vertices.TryGetValue v.ID with
    | true, v' -> obj.ReferenceEquals(v', v)
    | false, _ -> false

  (* An edge is this graph's own only when its endpoints are the very objects
     the given ones are, for the same reason. *)
  let hasOwnEnds (edge: Edge<'V, 'E>) src dst =
    obj.ReferenceEquals(edge.First, src)
    && obj.ReferenceEquals(edge.Second, dst)

  let findOwnVertex (v: IVertex<'V>) =
    if isOwnVertex v then vertices[v.ID]
    else GraphUtils.raiseVertexNotFoundByID v.ID

  let addVertex (data: VertexData<'V>) (vid: VertexID) =
    let v = Vertex(vid, data) :> IVertex<'V>
    if roots.Count = 0 then roots.Add v else ()
    vertices.Add(vid, v) |> ignore
    preds.Add(vid, List())
    succs.Add(vid, List())
    exits.Add v |> ignore
    v

  let addVertexWithData (data: VertexData<'V>) =
    id <- id + 1
    addVertex data id

  let addVertexWithDataAndID (data: VertexData<'V>) (vid: VertexID) =
    GraphUtils.checkVertexIDNotReserved vid
    id <- max id vid
    addVertex data vid

  let addEdge (src: IVertex<'V>) (dst: IVertex<'V>) label =
    let src = findOwnVertex src
    let dst = findOwnVertex dst
    let key = struct (src.ID, dst.ID)
    if edges.ContainsKey key then
      ()
    else
      let edge = Edge(src, dst, label)
      edges[key] <- edge
      succs[src.ID].Add edge
      preds[dst.ID].Add edge
      exits.Remove src |> ignore

  let removeEdge (src: IVertex<'V>) (dst: IVertex<'V>) =
    let src = findOwnVertex src
    let dst = findOwnVertex dst
    let srcID = src.ID
    let dstID = dst.ID
    succs[srcID].RemoveAll(fun e -> e.Second.ID = dstID) |> ignore
    preds[dstID].RemoveAll(fun e -> e.First.ID = srcID) |> ignore
    if succs[srcID].Count = 0 then exits.Add src |> ignore else ()
    edges.Remove(struct (srcID, dstID)) |> ignore

  let removeVertex v =
    let v = findOwnVertex v
    let vid = v.ID
    preds[vid] |> Seq.toArray |> Array.iter (fun e -> removeEdge e.First v)
    succs[vid] |> Seq.toArray |> Array.iter (fun e -> removeEdge v e.Second)
    vertices.Remove vid |> ignore
    preds.Remove vid |> ignore
    succs.Remove vid |> ignore
    exits.Remove v |> ignore
    roots.Remove v |> ignore

  let addRoot v =
    let v = findOwnVertex v
    if roots.Contains v then () else roots.Add v

  let setRoots vs =
    let vs = vs |> Seq.map findOwnVertex |> Seq.toArray
    roots.Clear()
    roots.AddRange vs

  let tryFindVertexBy fn = vertices.Values |> Seq.tryFind fn

  let findVertexBy fn =
    match tryFindVertexBy fn with
    | Some v -> v
    | None -> GraphUtils.raiseVertexNotFoundByPredicate ()

  let clone () =
    let g = MutableDiGraph<'V, 'E>(id)
    let ig = g :> IMutableDiGraph<'V, 'E>
    for v in vertices.Values do ig.AddVertexCopy v |> ignore
    for e in edges.Values do g.CopyEdgeFrom e
    for KeyValue(vid, ss) in succs do g.CopyAdjacencyOrder(vid, ss, preds[vid])
    g.CopyRootsFrom roots
    g

  new() = MutableDiGraph 0

  /// Returns a copy of this graph, which can be modified without affecting
  /// this graph. The copy holds vertices of its own, each carrying the ID of
  /// the one it stands for, so a vertex of this graph crosses over to the copy
  /// by `FindVertexByID`. A persistent graph forks by taking a snapshot
  /// instead, which costs no copy at all, hence this is not an operation both
  /// of the protocols offer.
  member _.Clone() = clone ()

  /// Adds a copy of the given edge, keeping the absence of its label.
  member private this.CopyEdgeFrom(e: Edge<'V, 'E>) =
    let g = this :> IDiGraph<'V, 'E>
    let src = g.FindVertexByID e.First.ID
    let dst = g.FindVertexByID e.Second.ID
    if e.HasLabel then addEdge src dst (EdgeLabel e.Label)
    else addEdge src dst null

  /// Rewrites the adjacency lists of the given vertex to follow the order of
  /// the given ones. Copying the edges above adds them in whatever order the
  /// edge table hands them out, which is not the order the original was built
  /// in, and adjacency order is what a traversal order follows.
  member private _.CopyAdjacencyOrder(vid, ss: List<Edge<'V, 'E>>, ps) =
    let reorder (dst: List<Edge<'V, 'E>>) (src: List<Edge<'V, 'E>>) =
      dst.Clear()
      for e in src do dst.Add edges[struct (e.First.ID, e.Second.ID)]
    reorder succs[vid] ss
    reorder preds[vid] ps

  /// Replaces the roots of this graph with the ones matching the given.
  member private this.CopyRootsFrom(roots: List<IVertex<'V>>) =
    let g = this :> IMutableDiGraph<'V, 'E>
    roots
    |> Seq.map (fun r -> g.FindVertexByID r.ID)
    |> g.SetRoots

  interface IDiGraph<'V, 'E> with

    member _.VertexCount with get() = vertices.Count

    member _.EdgeCount with get() = edges.Count

    member _.Vertices with get() = GraphUtils.toArray vertices.Values

    member _.Edges with get() = GraphUtils.toArray edges.Values

    member _.Exits with get() = GraphUtils.toArray exits

    member _.Roots with get() = GraphUtils.toArray roots

    member _.SingleRoot with get() =
      match roots.Count with
      | 1 -> roots[0]
      | 0 -> raise NoRootVertexException
      | _ -> raise MultipleRootVerticesException

    member _.ImplementationType with get() = Mutable

    member _.IsEmpty with get() = vertices.Count = 0

    member _.Contains v = isOwnVertex v

    member _.HasVertexByID vid = vertices.ContainsKey vid

    member _.HasEdge(src, dst) =
      match edges.TryGetValue(key = struct (src.ID, dst.ID)) with
      | true, edge -> hasOwnEnds edge src dst
      | false, _ -> false

    member _.FindVertexBy fn = findVertexBy fn

    member _.TryFindVertexBy fn = tryFindVertexBy fn

    member _.FindVertexByID vid =
      match vertices.TryGetValue vid with
      | true, v -> v
      | false, _ -> GraphUtils.raiseVertexNotFoundByID vid

    member _.TryFindVertexByID vid =
      match vertices.TryGetValue vid with
      | false, _ -> None
      | true, v -> Some v

    member _.FindVertexByData data =
      match tryFindVertexBy (fun v -> v.VData = data) with
      | Some v -> v
      | None -> GraphUtils.raiseVertexNotFoundByData data

    member _.TryFindVertexByData data =
      tryFindVertexBy (fun v -> v.VData = data)

    member _.FindEdge(src: IVertex<'V>, dst: IVertex<'V>) =
      match edges.TryGetValue(key = struct (src.ID, dst.ID)) with
      | true, edge when hasOwnEnds edge src dst -> edge
      | _ -> raise EdgeNotFoundException

    member _.TryFindEdge(src: IVertex<'V>, dst: IVertex<'V>) =
      match edges.TryGetValue(key = struct (src.ID, dst.ID)) with
      | true, edge when hasOwnEnds edge src dst -> Some edge
      | _ -> None

    member _.GetPreds(v: IVertex<'V>) =
      if isOwnVertex v then toSrcArray preds[v.ID] else [||]

    member _.GetPredEdges(v: IVertex<'V>) =
      if isOwnVertex v then GraphUtils.toArray preds[v.ID] else [||]

    member _.GetSuccs(v: IVertex<'V>) =
      if isOwnVertex v then toDstArray succs[v.ID] else [||]

    member _.GetSuccEdges(v: IVertex<'V>) =
      if isOwnVertex v then GraphUtils.toArray succs[v.ID] else [||]

    member this.Reverse vs = ReversedDiGraph(this, Seq.toArray vs)

  interface IMutableDiGraph<'V, 'E> with

    member _.AddVertex v = addVertexWithData (VertexData v)

    member this.AddVertex(v, vid) =
      assert ((this: IMutableDiGraph<_, _>).HasVertexByID vid |> not)
      addVertexWithDataAndID (VertexData v) vid

    member _.AddVertex() = addVertexWithData null

    member _.AddVertexCopy(v: IVertex<'V>) =
      if v.HasData then addVertexWithDataAndID (VertexData v.VData) v.ID
      else addVertexWithDataAndID null v.ID

    member _.RemoveVertex v = removeVertex v

    member _.AddEdge(src: IVertex<'V>, dst: IVertex<'V>, label) =
      addEdge src dst (EdgeLabel label)

    member _.AddEdge(src: IVertex<'V>, dst: IVertex<'V>) =
      addEdge src dst null

    member _.RemoveEdge(src: IVertex<'V>, dst: IVertex<'V>) =
      removeEdge src dst

    member _.RemoveEdge(edge: Edge<'V, 'E>) =
      removeEdge edge.First edge.Second

    member _.AddRoot v = addRoot v

    member _.SetRoots vs = setRoots vs
