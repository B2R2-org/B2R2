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
  and 'E: equality>(roots, vs, preds, succs, id) =
  let vertices = vs

  let preds: Map<VertexID, Edge<'V, 'E> list> = preds

  let succs: Map<VertexID, Edge<'V, 'E> list> = succs

  let id: VertexID = id

  let unreachables () =
    preds
    |> Map.fold (fun acc vid ps ->
      if List.isEmpty ps then (Map.find vid vertices :> IVertex<'V>) :: acc
      else acc) []
    |> List.toArray

  let tryFindVertexBy fn =
    vertices
    |> Map.tryPick (fun _ v ->
      let v = v :> IVertex<'V>
      if fn v then Some v else None)

  let findVertexBy fn =
    match tryFindVertexBy fn with
    | Some v -> v
    | None -> GraphUtils.raiseVertexNotFoundByPredicate ()

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
    let v = PersistentVertex(vid, data)
    let roots = if List.isEmpty roots then [ v :> IVertex<'V> ] else roots
    let vertices = Map.add vid v vertices
    let preds = Map.add vid [] preds
    let succs = Map.add vid [] succs
    let g = PersistentDiGraph(roots, vertices, preds, succs, nextvid)
    struct (v, g)

  let addVertexWithData (data: VertexData<'V>) =
    let vid = id + 1
    addVertex data vid vid

  let addVertexWithDataAndID data vid = addVertex data vid (max id vid)

  let findEdges vid (map: Map<VertexID, Edge<'V, 'E> list>) =
    match Map.tryFind vid map with
    | Some edges -> edges
    | None -> GraphUtils.raiseVertexNotFoundByID vid

  let addEdge (src: IVertex<'V>) (dst: IVertex<'V>) label =
    let srcid = src.ID
    let dstid = dst.ID
    let edge = Edge(src, dst, label)
    let succs = Map.add srcid (edge :: findEdges srcid succs) succs
    let preds = Map.add dstid (edge :: findEdges dstid preds) preds
    PersistentDiGraph(roots, vertices, preds, succs, id)

  let checkVertexExistence (v: IVertex<'V>) =
    if Map.containsKey v.ID vertices then ()
    else GraphUtils.raiseVertexNotFoundByID v.ID

  new() = PersistentDiGraph([], Map.empty, Map.empty, Map.empty, 0)

  interface IDiGraphAccessible<'V, 'E> with

    member _.Size with get() = vertices.Count

    member _.Vertices with get() =
      vertices.Values |> Seq.map (fun v -> v :> IVertex<'V>) |> Seq.toArray

    member _.Edges with get() =
      succs
      |> Map.toSeq
      |> Seq.collect snd
      |> Seq.toArray

    member _.Unreachables with get() = unreachables ()

    member _.Exits with get() =
      succs
      |> Map.fold (fun acc vid ss ->
        if List.isEmpty ss then (Map.find vid vertices :> IVertex<'V>) :: acc
        else acc) []
      |> List.toArray

    member _.SingleRoot with get() =
      match roots with
      | [ r ] -> r
      | _ -> raise MultipleRootVerticesException

    member _.ImplementationType with get() = Persistent

    member _.IsEmpty() = vertices.Count = 0

    member _.HasVertex vid = vertices |> Map.containsKey vid

    member _.HasEdge(src, dst) =
      match succs.TryFind src.ID with
      | None -> false
      | Some edges -> edges |> List.exists (fun edge -> edge.Second.ID = dst.ID)

    member _.FindVertexByID vid =
      match Map.tryFind vid vertices with
      | Some v -> v :> IVertex<'V>
      | None -> GraphUtils.raiseVertexNotFoundByID vid

    member _.TryFindVertexByID vid =
      vertices
      |> Map.tryFind vid
      |> Option.map (fun v -> v :> IVertex<'V>)

    member _.FindVertexByData data =
      match tryFindVertexBy (fun v -> v.VData = data) with
      | Some v -> v
      | None -> GraphUtils.raiseVertexNotFoundByData data

    member _.TryFindVertexByData data =
      tryFindVertexBy (fun v -> v.VData = data)

    member _.FindVertexBy fn = findVertexBy fn

    member _.TryFindVertexBy fn = tryFindVertexBy fn

    member _.FindEdge(src: IVertex<'V>, dst: IVertex<'V>) =
      let dstID = dst.ID
      match Map.tryFind src.ID succs with
      | Some edges ->
        match edges |> List.tryFind (fun edge -> edge.Second.ID = dstID) with
        | Some edge -> edge
        | None -> raise EdgeNotFoundException
      | None ->
        raise EdgeNotFoundException

    member _.TryFindEdge(src: IVertex<'V>, dst: IVertex<'V>) =
      let dstID = dst.ID
      match Map.tryFind src.ID succs with
      | Some edges ->
        edges |> List.tryFind (fun edge -> edge.Second.ID = dstID)
      | None ->
        None

    member _.GetPreds(v: IVertex<'V>) =
      Map.tryFind v.ID preds
      |> Option.defaultValue []
      |> List.fold (fun acc e -> (e.First :> IVertex<'V>) :: acc) []
      |> List.toArray

    member _.GetPredEdges(v: IVertex<'V>) =
      Map.tryFind v.ID preds
      |> Option.defaultValue []
      |> List.toArray

    member _.GetSuccs(v: IVertex<'V>) =
      Map.tryFind v.ID succs
      |> Option.defaultValue []
      |> List.fold (fun acc e -> (e.Second :> IVertex<'V>) :: acc) []
      |> List.toArray

    member _.GetSuccEdges(v: IVertex<'V>) =
      Map.tryFind v.ID succs
      |> Option.defaultValue []
      |> List.toArray

    member _.GetRoots() = roots |> List.toArray

    member this.Reverse(vs) = GraphUtils.reverse this vs (PersistentDiGraph())

    member _.FoldVertex(fn, acc) =
      vertices.Values
      |> Seq.fold (fun acc v -> fn acc (v :> IVertex<'V>)) acc

    member _.IterVertex fn =
      vertices.Values |> Seq.iter (fun v -> fn (v :> IVertex<'V>))

    member _.FoldEdge(fn, acc) =
      succs.Values
      |> Seq.fold (fun acc edges ->
        List.fold fn acc edges) acc

    member _.IterEdge fn =
      succs.Values |> Seq.iter (fun edges -> List.iter fn edges)

  interface IDiGraph<'V, 'E> with

    member _.AddVertex value =
      let struct (v, g) = addVertexWithData (VertexData value)
      v, g

    member this.AddVertex(value, vid: VertexID) =
      assert ((this: IDiGraph<_, _>).HasVertex vid |> not)
      let struct (v, g) = addVertexWithDataAndID (VertexData value) vid
      v, g

    member _.AddVertex() =
      let struct (v, g) = addVertexWithData null
      v, g

    member _.RemoveVertex v =
      let succs = findEdges v.ID preds |> List.fold removeSuccEdge succs
      let preds = findEdges v.ID succs |> List.fold removePredEdge preds
      let vertices = Map.remove v.ID vertices
      let preds = Map.remove v.ID preds
      let succs = Map.remove v.ID succs
      let roots = List.filter (fun r -> r <> v) roots
      PersistentDiGraph(roots, vertices, preds, succs, id)

    member _.AddEdge(src: IVertex<'V>, dst: IVertex<'V>, label) =
      addEdge src dst (EdgeLabel label)

    member _.AddEdge(src: IVertex<'V>, dst: IVertex<'V>) =
      addEdge src dst null

    member this.RemoveEdge(src: IVertex<'V>, dst: IVertex<'V>) =
      let edge = Edge(src, dst, null)
      (this :> IDiGraph<_, _>).RemoveEdge edge

    member _.RemoveEdge(edge: Edge<'V, 'E>) =
      checkVertexExistence edge.First
      checkVertexExistence edge.Second
      let preds = removePredEdge preds edge
      let succs = removeSuccEdge succs edge
      PersistentDiGraph(roots, vertices, preds, succs, id)

    member _.AddRoot(v) =
      assert (vertices.ContainsKey v.ID)
      let roots = if List.contains v roots then roots else v :: roots
      PersistentDiGraph(roots, vertices, preds, succs, id)

    member _.SetRoots(vs) =
      for v in vs do assert (vertices.ContainsKey v.ID)
      let roots = Seq.toList vs
      PersistentDiGraph(roots, vertices, preds, succs, id)

    member this.Reverse(vs) = GraphUtils.reverse this vs (PersistentDiGraph())

    member this.Clone() = this
