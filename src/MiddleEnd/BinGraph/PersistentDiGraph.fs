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

/// Persistent directed graph.
type PersistentDiGraph<'V, 'E when 'V: equality
                               and 'E: equality> (roots, vs, preds, succs, id) =
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

  new () = PersistentDiGraph ([], Map.empty, Map.empty, Map.empty, 0)

  member private __.RemoveSuccEdge succs (edge: Edge<'V, 'E>) =
    let isElseThen targetID (edge: Edge<'V, 'E>) = edge.Second.ID <> targetID
    succs
    |> Map.map (fun id succs ->
      if edge.First.ID = id then List.filter (isElseThen edge.Second.ID) succs
      else succs)

  member private __.RemovePredEdge preds (edge: Edge<'V, 'E>) =
    let isElseThen targetID (edge: Edge<'V, 'E>) = edge.First.ID <> targetID
    preds
    |> Map.map (fun id preds ->
      if edge.Second.ID = id then List.filter (isElseThen edge.First.ID) preds
      else preds)

  member private __.AddVertexInternal (data: VertexData<'V>, vid, nextvid) =
    let v = PersistentVertex (vid, data)
    let roots = if List.isEmpty roots then [ v :> IVertex<'V> ] else roots
    let vertices = Map.add vid v vertices
    let preds = Map.add vid [] preds
    let succs = Map.add vid [] succs
    let g = PersistentDiGraph (roots, vertices, preds, succs, nextvid)
    (v :> IVertex<'V>), (g :> IGraph<'V, 'E>)

  member private __.AddVertex (data: VertexData<'V>) =
    let vid = id + 1
    __.AddVertexInternal (data, vid, vid)

  member private __.AddVertex (data: VertexData<'V>, vid: VertexID) =
    __.AddVertexInternal (data, vid, max id vid)

  member private __.AddEdge (src: IVertex<'V>, dst: IVertex<'V>, label) =
    let srcid = src.ID
    let dstid = dst.ID
    let edge = Edge (src, dst, label)
    let preds = Map.add dstid (edge :: Map.find dstid preds) preds
    let succs = Map.add srcid (edge :: Map.find srcid succs) succs
    PersistentDiGraph (roots, vertices, preds, succs, id)

  interface IGraph<'V, 'E> with
    member __.IsEmpty () = vertices.Count = 0

    member __.Size with get() = vertices.Count

    member __.Vertices with get() =
      vertices.Values |> Seq.map (fun v -> v :> IVertex<'V>) |> Seq.toArray

    member __.Edges with get() =
      succs
      |> Map.toSeq
      |> Seq.collect snd
      |> Seq.toArray

    member __.Unreachables with get() = unreachables ()

    member __.Exits with get () =
      succs
      |> Map.fold (fun acc vid ss ->
        if List.isEmpty ss then (Map.find vid vertices :> IVertex<'V>) :: acc
        else acc) []
      |> List.toArray

    member __.SingleRoot with get() =
      match roots with
      | [ r ] -> r
      | _ -> raise MultipleRootVerticesException

    member __.ImplementationType with get() = Persistent

    member __.AddVertex value =
      __.AddVertex (data=VertexData value)

    member __.AddVertex (value, vid: VertexID) =
      assert ((__: IGraph<_, _>).HasVertex vid |> not)
      __.AddVertex (data=VertexData value, vid=vid)

    member __.AddVertex () =
      __.AddVertex (data=null)

    member __.RemoveVertex v =
      let succs = Map.find v.ID preds |> List.fold __.RemoveSuccEdge succs
      let preds = Map.find v.ID succs |> List.fold __.RemovePredEdge preds
      let vertices = Map.remove v.ID vertices
      let preds = Map.remove v.ID preds
      let succs = Map.remove v.ID succs
      let roots = List.filter (fun r -> r <> v) roots
      PersistentDiGraph (roots, vertices, preds, succs, id)

    member __.HasVertex vid =
      vertices |> Map.containsKey vid

    member __.FindVertexByID vid =
      vertices |> Map.find vid :> IVertex<'V>

    member __.TryFindVertexByID vid =
      vertices
      |> Map.tryFind vid
      |> Option.map (fun v -> v :> IVertex<'V>)

    member __.FindVertexByData data =
      vertices
      |> Map.pick (fun _ v ->
        let v = v :> IVertex<'V>
        if v.VData = data then Some v else None)

    member __.TryFindVertexByData data =
      vertices
      |> Map.tryPick (fun _ v ->
        let v = v :> IVertex<'V>
        if v.VData = data then Some v else None)

    member __.FindVertexBy fn =
      vertices
      |> Map.pick (fun _ v ->
        let v = v :> IVertex<'V>
        if fn v then Some v else None)

    member __.TryFindVertexBy fn =
      vertices
      |> Map.tryPick (fun _ v ->
        let v = v :> IVertex<'V>
        if fn v then Some v else None)

    member __.AddEdge (src: IVertex<'V>, dst: IVertex<'V>, label) =
      __.AddEdge (src, dst, EdgeLabel label)

    member __.AddEdge (src: IVertex<'V>, dst: IVertex<'V>) =
      __.AddEdge (src, dst, null)

    member __.RemoveEdge (src: IVertex<'V>, dst: IVertex<'V>) =
      let edge = Edge (src, dst, null)
      (__ :> IGraph<_, _>).RemoveEdge edge

    member __.RemoveEdge (edge: Edge<'V, 'E>) =
      let preds = __.RemovePredEdge preds edge
      let succs = __.RemoveSuccEdge succs edge
      PersistentDiGraph (roots, vertices, preds, succs, id)

    member __.FindEdge (src: IVertex<'V>, dst: IVertex<'V>) =
      let dstID = dst.ID
      Map.find src.ID succs
      |> List.find (fun edge -> edge.Second.ID = dstID)

    member __.TryFindEdge (src: IVertex<'V>, dst: IVertex<'V>) =
      let dstID = dst.ID
      Map.find src.ID succs
      |> List.tryFind (fun edge -> edge.Second.ID = dstID)

    member __.GetPreds (v: IVertex<'V>) =
      Map.find v.ID preds
      |> List.fold (fun acc e -> (e.First :> IVertex<'V>) :: acc) []
      :> IReadOnlyCollection<_>

    member __.GetPredEdges (v: IVertex<'V>) =
      Map.find v.ID preds
      :> IReadOnlyCollection<_>

    member __.GetSuccs (v: IVertex<'V>) =
      Map.find v.ID succs
      |> List.fold (fun acc e -> (e.Second :> IVertex<'V>) :: acc) []
      :> IReadOnlyCollection<_>

    member __.GetSuccEdges (v: IVertex<'V>) =
      Map.find v.ID succs
      :> IReadOnlyCollection<_>

    member __.GetRoots () =
      roots :> IReadOnlyCollection<_>

    member __.AddRoot (v) =
      assert (vertices.ContainsKey v.ID)
      let roots = if List.contains v roots then roots else v :: roots
      PersistentDiGraph(roots, vertices, preds, succs, id)

    member __.SetRoot (v) =
      assert (vertices.ContainsKey v.ID)
      PersistentDiGraph ([ v ], vertices, preds, succs, id)

    member __.FoldVertex fn acc =
      vertices.Values
      |> Seq.fold (fun acc v -> fn acc (v :> IVertex<'V>)) acc

    member __.IterVertex fn =
      vertices.Values |> Seq.iter (fun v -> fn (v :> IVertex<'V>))

    member __.FoldEdge fn acc =
      succs.Values
      |> Seq.fold (fun acc edges ->
        List.fold fn acc edges) acc

    member __.IterEdge fn =
      succs.Values |> Seq.iter (fun edges -> List.iter fn edges)

    member __.SubGraph vs =
      GraphUtils.subGraph __ (PersistentDiGraph ()) vs

    member __.Reverse () =
      GraphUtils.reverse __ (PersistentDiGraph ())

    member __.Clone () =
      __ :> IGraph<'V, 'E>

    member __.ToDOTStr (name, vToStrFn, _eToStrFn) =
      GraphUtils.toDiGraphDOTString __ name vToStrFn _eToStrFn
