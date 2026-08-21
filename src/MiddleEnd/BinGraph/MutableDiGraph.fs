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

  let vertices = Dictionary<VertexID, Vertex<'V>>()

  let edges = Dictionary<VertexID * VertexID, Edge<'V, 'E>>()

  let preds = Dictionary<VertexID, List<Vertex<'V>>>()

  let succs = Dictionary<VertexID, List<Vertex<'V>>>()

  let exits = HashSet<Vertex<'V>>()

  let mutable id = initialID

  let roots = List<Vertex<'V>>()

  (* A vertex belongs to this graph only when it is the very object we store
     for its ID. Comparing IDs is not enough, because vertices compare by ID,
     so a vertex of another graph can carry an ID we also use. *)
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
    let v = Vertex(vid, data)
    if roots.Count = 0 then roots.Add v else ()
    vertices.Add(vid, v) |> ignore
    preds.Add(vid, List())
    succs.Add(vid, List())
    exits.Add v |> ignore
    v :> IVertex<'V>

  let addVertexWithData (data: VertexData<'V>) =
    id <- id + 1
    addVertex data id

  let addVertexWithDataAndID (data: VertexData<'V>) (vid: VertexID) =
    id <- max id vid
    addVertex data vid

  let addEdge (src: IVertex<'V>) (dst: IVertex<'V>) label =
    let src = findOwnVertex src
    let dst = findOwnVertex dst
    let srcID = src.ID
    let dstID = dst.ID
    if edges.ContainsKey(srcID, dstID) then
      ()
    else
      edges[(srcID, dstID)] <- Edge(src, dst, label)
      succs[srcID].Add dst
      preds[dstID].Add src
      exits.Remove src |> ignore

  let removeEdge (src: IVertex<'V>) (dst: IVertex<'V>) =
    let src = findOwnVertex src
    let dst = findOwnVertex dst
    let srcID = src.ID
    let dstID = dst.ID
    succs[srcID].RemoveAll(fun s -> s.ID = dstID) |> ignore
    preds[dstID].RemoveAll(fun p -> p.ID = srcID) |> ignore
    if succs[srcID].Count = 0 then exits.Add src |> ignore else ()
    edges.Remove((srcID, dstID)) |> ignore

  let removeVertex v =
    let v = findOwnVertex v
    let vid = v.ID
    preds[vid] |> Seq.toArray |> Array.iter (fun p -> removeEdge p v)
    succs[vid] |> Seq.toArray |> Array.iter (fun s -> removeEdge v s)
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

  let tryFindVertexBy fn =
    vertices.Values
    |> Seq.tryFind fn
    |> Option.map (fun v -> v :> IVertex<'V>)

  let findVertexBy fn =
    match tryFindVertexBy fn with
    | Some v -> v
    | None -> GraphUtils.raiseVertexNotFoundByPredicate ()

  let getPredVertices (v: IVertex<'V>) =
    if isOwnVertex v then Seq.toArray preds[v.ID] else [||]

  let getSuccVertices (v: IVertex<'V>) =
    if isOwnVertex v then Seq.toArray succs[v.ID] else [||]

  let clone () =
    let g = MutableDiGraph<'V, 'E>(id)
    let ig = g :> IMutableDiGraph<'V, 'E>
    for v in vertices.Values do ig.AddVertexCopy v |> ignore
    for e in edges.Values do g.CopyEdgeFrom e
    for KeyValue(vid, ss) in succs do g.CopyAdjacencyOrder(vid, ss, preds[vid])
    g.CopyRootsFrom roots
    g

  new() = MutableDiGraph 0

  /// Adds a copy of the given edge, keeping the absence of its label.
  member private this.CopyEdgeFrom(e: Edge<'V, 'E>) =
    let g = this :> IDiGraphAccessible<'V, 'E>
    let src = g.FindVertexByID e.First.ID
    let dst = g.FindVertexByID e.Second.ID
    if e.HasLabel then addEdge src dst (EdgeLabel e.Label)
    else addEdge src dst null

  /// Rewrites the adjacency lists of the given vertex to follow the order of
  /// the given ones. Copying the edges above adds them in whatever order the
  /// edge table hands them out, which is not the order the original was built
  /// in, and adjacency order is what a traversal order follows.
  member private _.CopyAdjacencyOrder(vid, ss: List<Vertex<'V>>, ps) =
    let reorder (dst: List<Vertex<'V>>) (src: List<Vertex<'V>>) =
      dst.Clear()
      for v in src do dst.Add vertices[v.ID]
    reorder succs[vid] ss
    reorder preds[vid] ps

  /// Replaces the roots of this graph with the ones matching the given.
  member private this.CopyRootsFrom(roots: List<Vertex<'V>>) =
    let g = this :> IMutableDiGraph<'V, 'E>
    roots
    |> Seq.map (fun r -> g.FindVertexByID r.ID)
    |> g.SetRoots

  interface IDiGraphAccessible<'V, 'E> with

    member _.Size with get() = vertices.Count

    member _.Vertices with get() =
      vertices.Values |> Seq.map (fun v -> v :> IVertex<'V>) |> Seq.toArray

    member _.Edges with get() =
      edges
      |> Seq.toArray
      |> Array.map (fun (KeyValue(_, edge)) -> edge)

    member _.Exits with get() =
      exits
      |> Seq.toArray
      |> Array.map (fun v -> v :> IVertex<'V>)

    member _.SingleRoot with get() =
      match roots.Count with
      | 1 -> roots[0]
      | 0 -> raise NoRootVertexException
      | _ -> raise MultipleRootVerticesException

    member _.ImplementationType with get() = Mutable

    member _.IsEmpty() = vertices.Count = 0

    member _.Contains v = isOwnVertex v

    member _.HasVertexByID vid = vertices.ContainsKey vid

    member _.HasEdge(src, dst) =
      match edges.TryGetValue(key = (src.ID, dst.ID)) with
      | true, edge -> hasOwnEnds edge src dst
      | false, _ -> false

    member _.FindVertexBy fn = findVertexBy fn

    member _.TryFindVertexBy fn = tryFindVertexBy fn

    member _.FindVertexByID vid =
      match vertices.TryGetValue vid with
      | true, v -> v :> IVertex<'V>
      | false, _ -> GraphUtils.raiseVertexNotFoundByID vid

    member _.TryFindVertexByID vid =
      match vertices.TryGetValue vid with
      | false, _ -> None
      | true, v -> Some v

    member _.FindVertexByData data =
      match tryFindVertexBy (fun v -> (v :> IVertex<'V>).VData = data) with
      | Some v -> v
      | None -> GraphUtils.raiseVertexNotFoundByData data

    member _.TryFindVertexByData data =
      tryFindVertexBy (fun v -> (v :> IVertex<'V>).VData = data)

    member _.FindEdge(src: IVertex<'V>, dst: IVertex<'V>) =
      match edges.TryGetValue(key = (src.ID, dst.ID)) with
      | true, edge when hasOwnEnds edge src dst -> edge
      | _ -> raise EdgeNotFoundException

    member _.TryFindEdge(src: IVertex<'V>, dst: IVertex<'V>) =
      match edges.TryGetValue(key = (src.ID, dst.ID)) with
      | true, edge when hasOwnEnds edge src dst -> Some edge
      | _ -> None

    member _.GetPreds(v: IVertex<'V>) =
      getPredVertices v
      |> Array.map (fun v -> v :> IVertex<'V>)

    member _.GetPredEdges(v: IVertex<'V>) =
      getPredVertices v
      |> Array.map (fun pred -> edges[(pred.ID, v.ID)])

    member _.GetSuccs(v: IVertex<'V>) =
      getSuccVertices v
      |> Array.map (fun v -> v :> IVertex<'V>)

    member _.GetSuccEdges(v: IVertex<'V>) =
      getSuccVertices v
      |> Array.map (fun succ -> edges[(v.ID, succ.ID)])

    member _.GetRoots() =
      roots
      |> Seq.toArray
      |> Array.map (fun v -> v :> IVertex<'V>)

    member this.Reverse vs =
      let out = MutableDiGraph<'V, 'E>()
      DiGraph.reverseInto this vs out
      out

    member _.FoldVertex(fn, acc) =
      vertices.Values |> Seq.fold (fun acc v -> fn acc (v :> IVertex<'V>)) acc

    member _.IterVertex fn =
      vertices.Values |> Seq.iter (fun v -> fn (v :> IVertex<'V>))

    member _.FoldEdge(fn, acc) = edges.Values |> Seq.fold fn acc

    member _.IterEdge fn = edges.Values |> Seq.iter fn

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

    member _.Clone() = clone ()
