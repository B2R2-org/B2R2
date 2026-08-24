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

/// Represents a persistent directed graph.
type PersistentDiGraph<'V, 'E
  when 'V: equality
  and 'E: equality> private(roots, vs, preds, succs, id, edges) =
  let vertices: Map<VertexID, IVertex<'V>> = vs

  let preds: Map<VertexID, Edge<'V, 'E> list> = preds

  let succs: Map<VertexID, Edge<'V, 'E> list> = succs

  let id: VertexID = id

  (* Counting the edges of the adjacency maps would walk every one of them, so
     the count rides along instead, every operation below handing on the one
     it leaves behind. *)
  let edgeCount: int = edges

  (* The vertices, preds, and succs maps always share the same key set. *)
  let findVertex vid =
    assert (Map.containsKey vid vertices)
    Map.find vid vertices

  let verticesWithNoEdge (map: Map<VertexID, Edge<'V, 'E> list>) =
    map
    |> Map.fold (fun acc vid edges ->
      if List.isEmpty edges then findVertex vid :: acc else acc) []
    |> List.toArray

  let tryFindVertexBy fn =
    vertices
    |> Map.tryPick (fun _ v -> if fn v then Some v else None)

  let findVertexBy fn =
    match tryFindVertexBy fn with
    | Some v -> v
    | None -> GraphUtils.raiseVertexNotFoundByPredicate ()

  let findEdges vid (map: Map<VertexID, Edge<'V, 'E> list>) =
    match Map.tryFind vid map with
    | Some edges -> edges
    | None -> GraphUtils.raiseVertexNotFoundByID vid

  (* A vertex belongs to this graph only when it is the very object we store
     for its ID. Comparing IDs is not enough, because a vertex of another
     graph can carry an ID we also use. Snapshots of one
     graph share their vertex objects, so they all agree here. *)
  let isOwnVertex (v: IVertex<'V>) =
    match Map.tryFind v.ID vertices with
    | Some v' -> obj.ReferenceEquals(v', v)
    | None -> false

  (* An edge is this graph's own only when its endpoints are the very objects
     the given ones are, for the same reason. *)
  let hasOwnEnds (edge: Edge<'V, 'E>) src dst =
    obj.ReferenceEquals(edge.First, src)
    && obj.ReferenceEquals(edge.Second, dst)

  let checkVertexExistence (v: IVertex<'V>) =
    if isOwnVertex v then () else GraphUtils.raiseVertexNotFoundByID v.ID

  let getPredEdges (v: IVertex<'V>) =
    if isOwnVertex v then findEdges v.ID preds else []

  let getSuccEdges (v: IVertex<'V>) =
    if isOwnVertex v then findEdges v.ID succs else []

  let removeSuccEdge succs (edge: Edge<'V, 'E>) =
    let isElseThen targetID (edge: Edge<'V, 'E>) = edge.Second.ID <> targetID
    succs
    |> Map.map (fun id succs ->
      if edge.First.ID = id then List.filter (isElseThen edge.Second.ID) succs
      else succs)

  let removePredEdge preds (edge: Edge<'V, 'E>) =
    let isElseThen targetID (edge: Edge<'V, 'E>) = edge.First.ID <> targetID
    preds
    |> Map.map (fun id preds ->
      if edge.Second.ID = id then List.filter (isElseThen edge.First.ID) preds
      else preds)

  let addVertex (data: VertexData<'V>) vid nextvid =
    let v = Vertex(vid, data) :> IVertex<'V>
    let roots = if List.isEmpty roots then [ v ] else roots
    let vertices = Map.add vid v vertices
    let preds = Map.add vid [] preds
    let succs = Map.add vid [] succs
    let g =
      PersistentDiGraph(roots, vertices, preds, succs, nextvid, edgeCount)
    struct (v, g)

  let addVertexWithData (data: VertexData<'V>) =
    let vid = id + 1
    addVertex data vid vid

  let addVertexWithDataAndID data vid =
    GraphUtils.checkVertexIDNotReserved vid
    GraphUtils.checkVertexIDNotTaken (Map.containsKey vid vertices) vid
    addVertex data vid (max id vid)

  (* A graph holds at most one edge for an ordered pair of vertices, hence
     adding an edge that is already there changes nothing, and the label of the
     existing edge is the one that stays. *)
  let addEdge (src: IVertex<'V>) (dst: IVertex<'V>) label =
    checkVertexExistence src
    checkVertexExistence dst
    let srcid = src.ID
    let dstid = dst.ID
    let outgoings = findEdges srcid succs
    if outgoings |> List.exists (fun e -> e.Second.ID = dstid) then
      PersistentDiGraph(roots, vertices, preds, succs, id, edgeCount)
    else
      let edge = Edge(src, dst, label)
      let succs = Map.add srcid (edge :: outgoings) succs
      let preds = Map.add dstid (edge :: findEdges dstid preds) preds
      PersistentDiGraph(roots, vertices, preds, succs, id, edgeCount + 1)

  (* A self-loop is gone once the incoming edges are, hence taking the length
     of the outgoing ones afterwards counts it but the once. *)
  let removeVertex (v: IVertex<'V>) =
    checkVertexExistence v
    let incoming = findEdges v.ID preds
    let succs = incoming |> List.fold removeSuccEdge succs
    let outgoing = findEdges v.ID succs
    let preds = outgoing |> List.fold removePredEdge preds
    let vertices = Map.remove v.ID vertices
    let preds = Map.remove v.ID preds
    let succs = Map.remove v.ID succs
    let roots = List.filter (fun r -> r <> v) roots
    let gone = List.length incoming + List.length outgoing
    PersistentDiGraph(roots, vertices, preds, succs, id, edgeCount - gone)

  (* Removing an edge that is not there changes nothing, the count included. *)
  let removeEdge (edge: Edge<'V, 'E>) =
    checkVertexExistence edge.First
    checkVertexExistence edge.Second
    let dstid = edge.Second.ID
    let existed =
      findEdges edge.First.ID succs
      |> List.exists (fun e -> e.Second.ID = dstid)
    let preds = removePredEdge preds edge
    let succs = removeSuccEdge succs edge
    let n = if existed then edgeCount - 1 else edgeCount
    PersistentDiGraph(roots, vertices, preds, succs, id, n)

  let addRoot v =
    checkVertexExistence v
    let roots = if List.contains v roots then roots else v :: roots
    PersistentDiGraph(roots, vertices, preds, succs, id, edgeCount)

  let setRoots vs =
    let roots = Seq.toList vs
    roots |> List.iter checkVertexExistence
    PersistentDiGraph(roots, vertices, preds, succs, id, edgeCount)

  new() = PersistentDiGraph([], Map.empty, Map.empty, Map.empty, 0, 0)

  /// Checks whether a vertex of the given ID belongs to this graph. An ID
  /// names a vertex only within the chain of snapshots that handed it out,
  /// hence this is a service of a graph holding a name index rather than of a
  /// graph as such. Use `Contains` when a vertex is what one has at hand.
  member _.HasVertexByID(vid) = vertices |> Map.containsKey vid

  /// Finds the vertex of the given ID, raising `VertexNotFoundException` when
  /// this graph holds no such vertex.
  member _.FindVertexByID(vid) =
    match Map.tryFind vid vertices with
    | Some v -> v
    | None -> GraphUtils.raiseVertexNotFoundByID vid

  /// Finds the vertex of the given ID, answering None when this graph holds no
  /// such vertex.
  member _.TryFindVertexByID(vid) = Map.tryFind vid vertices

  interface IDiGraph<'V, 'E> with

    member _.VertexCount with get() = vertices.Count

    member _.EdgeCount with get() = edgeCount

    member _.Vertices with get() = GraphUtils.toArray vertices.Values

    member _.Edges with get() = succs.Values |> Seq.concat |> Seq.toArray

    member _.Exits with get() = verticesWithNoEdge succs

    member _.Roots with get() = List.toArray roots

    member _.SingleRoot with get() =
      match roots with
      | [ r ] -> r
      | [] -> raise NoRootVertexException
      | _ -> raise MultipleRootVerticesException

    member _.ImplementationType with get() = Persistent

    member _.IsEmpty with get() = vertices.Count = 0

    member _.Contains v = isOwnVertex v

    member _.HasEdge(src, dst) =
      match succs.TryFind src.ID with
      | None -> false
      | Some edges -> edges |> List.exists (fun e -> hasOwnEnds e src dst)

    member _.FindVertexByData data =
      match tryFindVertexBy (fun v -> v.VData = data) with
      | Some v -> v
      | None -> GraphUtils.raiseVertexNotFoundByData data

    member _.TryFindVertexByData data =
      tryFindVertexBy (fun v -> v.VData = data)

    member _.FindVertexBy fn = findVertexBy fn

    member _.TryFindVertexBy fn = tryFindVertexBy fn

    member _.FindEdge(src: IVertex<'V>, dst: IVertex<'V>) =
      match Map.tryFind src.ID succs with
      | Some edges ->
        match edges |> List.tryFind (fun e -> hasOwnEnds e src dst) with
        | Some edge -> edge
        | None -> raise EdgeNotFoundException
      | None ->
        raise EdgeNotFoundException

    member _.TryFindEdge(src: IVertex<'V>, dst: IVertex<'V>) =
      match Map.tryFind src.ID succs with
      | Some edges -> edges |> List.tryFind (fun e -> hasOwnEnds e src dst)
      | None -> None

    member _.GetPreds(v: IVertex<'V>) =
      getPredEdges v |> GraphUtils.toArrayInReverse (fun e -> e.First)

    member _.GetPredEdges(v: IVertex<'V>) =
      getPredEdges v |> GraphUtils.toReversedArray

    member _.GetSuccs(v: IVertex<'V>) =
      getSuccEdges v |> GraphUtils.toArrayInReverse (fun e -> e.Second)

    member _.GetSuccEdges(v: IVertex<'V>) =
      getSuccEdges v |> GraphUtils.toReversedArray

    member this.Reverse(vs) = ReversedDiGraph(this, Seq.toArray vs)

  interface IPersistentDiGraph<'V, 'E> with

    member _.AddVertex value =
      let struct (v, g) = addVertexWithData (VertexData value)
      v, g

    member _.AddVertex(value, vid: VertexID) =
      let struct (v, g) = addVertexWithDataAndID (VertexData value) vid
      v, g

    member _.AddVertex() =
      let struct (v, g) = addVertexWithData null
      v, g

    member _.AddVertexCopy(v: IVertex<'V>) =
      let struct (v', g) =
        if v.HasData then addVertexWithDataAndID (VertexData v.VData) v.ID
        else addVertexWithDataAndID null v.ID
      v', g

    member _.RemoveVertex v = removeVertex v

    member _.AddEdge(src: IVertex<'V>, dst: IVertex<'V>, label) =
      addEdge src dst (EdgeLabel label)

    member _.AddEdge(src: IVertex<'V>, dst: IVertex<'V>) =
      addEdge src dst null

    member _.RemoveEdge(src: IVertex<'V>, dst: IVertex<'V>) =
      removeEdge (Edge(src, dst, null))

    member _.RemoveEdge(edge: Edge<'V, 'E>) = removeEdge edge

    member _.AddRoot v = addRoot v

    member _.SetRoots vs = setRoots vs
