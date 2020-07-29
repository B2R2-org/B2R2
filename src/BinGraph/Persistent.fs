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

/// Persistent vertex.
type PerVertex<'D when 'D :> VertexData> (?v: 'D) =
  inherit Vertex<'D> (v)

  override __.Preds
    with get () = Utils.impossible () and set _ = Utils.impossible ()

  override __.Succs
    with get () = Utils.impossible () and set _ = Utils.impossible ()

  static member Init () : Vertex<'D> = upcast (PerVertex<'D> ())

  static member Init data : Vertex<'D> = upcast (PerVertex<'D> (data))

/// Persistent GraphCore for directed graph (DiGraph).
type PersistentCore<'D, 'E when 'D :> VertexData and 'D: equality>
    (init, edgeData, ?vertices, ?preds, ?succs) =
  inherit GraphCore<'D, 'E, DiGraph<'D, 'E>> ()

  let vertices = defaultArg vertices Map.empty
  let preds: Map<VertexID, (Vertex<'D> * Vertex<'D> * 'E) list> =
    defaultArg preds Map.empty
  let succs: Map<VertexID, (Vertex<'D> * Vertex<'D> * 'E) list> =
    defaultArg succs Map.empty

  override __.ImplementationType = PersistentGraph

  override __.InitGraph core =
    match core with
    | Some core -> init core
    | None -> init <| PersistentCore (init, edgeData)

  override __.Vertices with get () =
    vertices |> Map.fold (fun acc _ v -> Set.add v acc) Set.empty

  override __.Unreachables with get () =
    preds
    |> Map.fold (fun acc vid ps ->
      if List.isEmpty ps then (Map.find vid vertices) :: acc
      else acc) []

  override __.Exits with get () =
    succs
    |> Map.fold (fun acc vid ss ->
      if List.isEmpty ss then (Map.find vid vertices) :: acc
      else acc) []

  override __.GetSize () = Map.count vertices

  member private __.InitGraphWithNewVertex (v: Vertex<'D>) =
    let vid = v.GetID ()
    let vertices = Map.add vid v vertices
    let preds = Map.add vid [] preds
    let succs = Map.add vid [] succs
    let core = PersistentCore (init, edgeData, vertices, preds, succs)
    __.InitGraph (Some (upcast core))

  override __.AddDummyVertex _g =
    let v = PerVertex.Init ()
    v, __.InitGraphWithNewVertex v

  override __.AddVertex _g data =
    let v = PerVertex.Init data
    v, __.InitGraphWithNewVertex v

  override __.GetVertex vid =
    match Map.tryFind vid vertices with
    | Some v -> v
    | None -> raise VertexNotFoundException

  member inline private __.RemoveEdgeFromMap map srcId dstId =
    let isChild (_, child: Vertex<_>, _) = child.GetID () <> dstId
    map
    |> Map.map (fun id ss ->
      if srcId = id then List.filter isChild ss else ss)

  override __.RemoveVertex _g v =
    let vid = v.GetID ()
    let succs =
      Map.find vid preds
      |> List.fold (fun succs (_, p, _) ->
        __.RemoveEdgeFromMap succs (p.GetID ()) vid) succs
    let preds =
      Map.find vid succs
      |> List.fold (fun preds (_, s, _) ->
        __.RemoveEdgeFromMap preds (s.GetID ()) vid) preds
    let vertices = Map.remove vid vertices
    let preds = Map.remove vid preds
    let succs = Map.remove vid succs
    let core = PersistentCore (init, edgeData, vertices, preds, succs)
    __.InitGraph (Some (upcast core))

  override __.ContainsVertex vid =
    vertices |> Map.containsKey vid

  override __.FoldVertex fn acc =
    vertices |> Map.fold (fun acc _ v -> fn acc v) acc

  override __.IterVertex fn =
    vertices |> Map.iter (fun _ v -> fn v)

  override __.FindVertexBy fn =
    vertices |> Map.pick (fun _ v -> if fn v then Some v else None)

  override __.TryFindVertexBy fn =
    vertices |> Map.tryPick (fun _ v -> if fn v then Some v else None)

  member private __.Snd (_, e, _) = e

  member private __.Thrd (_, _, e) = e

  override __.GetPreds v =
    Map.find (v.GetID ()) preds |> List.map __.Snd

  override __.GetSuccs v =
    Map.find (v.GetID ()) succs |> List.map __.Snd

  member private __.InitGraphWithNewEdge (src: Vertex<'D>) (dst: Vertex<'D>) e =
    let srcid = src.GetID ()
    let dstid = dst.GetID ()
    let preds = Map.add dstid ((dst, src, e) :: Map.find dstid preds) preds
    let succs = Map.add srcid ((src, dst, e) :: Map.find srcid succs) succs
    let core = PersistentCore (init, edgeData, vertices, preds, succs)
    __.InitGraph (Some (upcast core))

  override __.AddDummyEdge _g src dst =
    __.InitGraphWithNewEdge src dst edgeData

  override __.AddEdge _g src dst e =
    __.InitGraphWithNewEdge src dst e

  override __.RemoveEdge _g src dst =
    let srcid = src.GetID ()
    let dstid = dst.GetID ()
    let preds = __.RemoveEdgeFromMap preds dstid srcid
    let succs = __.RemoveEdgeFromMap succs srcid dstid
    let core = PersistentCore (init, edgeData, vertices, preds, succs)
    __.InitGraph (Some (upcast core))

  override __.FoldEdge fn acc =
    let folder acc (s, d, e) = fn acc s d e
    succs
    |> Map.fold (fun acc _ lst ->
      lst |> List.fold folder acc) acc

  override __.IterEdge fn =
    let iterator (s, d, e) = fn s d e
    succs
    |> Map.iter (fun _ lst -> lst |> List.iter iterator)

  override __.FindEdge src dst =
    let dstID = dst.GetID ()
    Map.find (src.GetID ()) succs
    |> List.find (fun (_, v, _) -> v.GetID () = dstID)
    |> __.Thrd

  override __.TryFindEdge src dst =
    Map.tryFind (src.GetID ()) succs
    |> Option.bind (fun lst ->
      let dstID = dst.GetID ()
      lst |> List.tryFind (fun (_, v, _) -> v.GetID () = dstID))
    |> function
      | Some (_, _, e) -> Some e
      | None -> None

  override __.Clone () =
    __ :> GraphCore<'D, 'E, DiGraph<'D, 'E>>

/// Persistent GraphCore for directed graph (DiGraph) that uses AddrRange as a
/// key for each vertex. This is useful for handling CFGs of a binary.
type PersistentRangedCore<'D, 'E when 'D :> RangedVertexData and 'D: equality>
    (init, edgeData, ?vertices, ?rangemap, ?edges, ?preds, ?succs) =
  inherit GraphCore<'D, 'E, DiGraph<'D, 'E>> ()

  let vertices = defaultArg vertices Map.empty
  let rangemap = defaultArg rangemap IntervalMap.empty
  let edges = defaultArg edges Map.empty
  let preds: Map<VertexID, Vertex<'D> list> = defaultArg preds Map.empty
  let succs: Map<VertexID, Vertex<'D> list> = defaultArg succs Map.empty

  override __.ImplementationType = PersistentGraph

  override __.InitGraph core =
    match core with
    | Some core -> init core
    | None -> init <| PersistentRangedCore (init, edgeData)

  override __.Vertices with get () =
    vertices |> Map.fold (fun acc _ v -> Set.add v acc) Set.empty

  override __.Unreachables with get () =
    preds
    |> Map.fold (fun acc vid ps ->
      if List.isEmpty ps then (Map.find vid vertices) :: acc
      else acc) []

  override __.Exits with get () =
    succs
    |> Map.fold (fun acc vid ss ->
      if List.isEmpty ss then (Map.find vid vertices) :: acc
      else acc) []

  override __.GetSize () = Map.count vertices

  member private __.InitGraphWithNewVertex (v: Vertex<'D>) =
    let vid = v.GetID ()
    let vertices = Map.add vid v vertices
    let rangemap =
      if v.IsDummy () then rangemap
      else IntervalMap.add v.VData.AddrRange v rangemap
    let preds = Map.add vid [] preds
    let succs = Map.add vid [] succs
    let core = PersistentRangedCore (init, edgeData,
                                     vertices, rangemap, edges, preds, succs)
    __.InitGraph (Some (upcast core))

  override __.AddDummyVertex _g =
    let v = PerVertex.Init ()
    v, __.InitGraphWithNewVertex v

  override __.AddVertex _g data =
    let v = PerVertex.Init data
    v, __.InitGraphWithNewVertex v

  override __.GetVertex vid =
    match Map.tryFind vid vertices with
    | Some v -> v
    | None -> raise VertexNotFoundException

  member inline private __.RemoveEdgeFromMap map srcId dstId =
    map
    |> Map.map (fun id ss ->
      if srcId = id then
        List.filter (fun (child: Vertex<_>) -> child.GetID () <> dstId) ss
      else ss)

  override __.RemoveVertex _g v =
    let vid = v.GetID ()
    let edges, succs =
      Map.find vid preds
      |> List.fold (fun (edges, succs) p ->
        let p = p.GetID ()
        Map.remove (p, vid) edges,
        __.RemoveEdgeFromMap succs p vid) (edges, succs)
    let edges, preds =
      Map.find vid succs
      |> List.fold (fun (edges, preds) s ->
        let s = s.GetID ()
        Map.remove (vid, s) edges,
        __.RemoveEdgeFromMap preds s vid) (edges, preds)
    let vertices = Map.remove vid vertices
    let rangemap =
      if v.IsDummy () then rangemap
      else IntervalMap.remove v.VData.AddrRange rangemap
    let preds = Map.remove vid preds
    let succs = Map.remove vid succs
    let core = PersistentRangedCore (init, edgeData,
                                     vertices, rangemap, edges, preds, succs)
    __.InitGraph (Some (upcast core))

  override __.ContainsVertex vid =
    vertices |> Map.containsKey vid

  override __.FoldVertex fn acc =
    vertices |> Map.fold (fun acc _ v -> fn acc v) acc

  override __.IterVertex fn =
    vertices |> Map.iter (fun _ v -> fn v)

  override __.FindVertexBy fn =
    vertices |> Map.pick (fun _ v -> if fn v then Some v else None)

  override __.TryFindVertexBy fn =
    vertices |> Map.tryPick (fun _ v -> if fn v then Some v else None)

  override __.GetPreds v =
    Map.find (v.GetID ()) preds

  override __.GetSuccs v =
    Map.find (v.GetID ()) succs

  member private __.InitGraphWithNewEdge (src: Vertex<'D>) (dst: Vertex<'D>) e =
    let srcid = src.GetID ()
    let dstid = dst.GetID ()
    let edges = Map.add (srcid, dstid) (src, dst, e) edges
    let preds = Map.add dstid (src :: Map.find dstid preds) preds
    let succs = Map.add srcid (dst :: Map.find srcid succs) succs
    let core = PersistentRangedCore (init, edgeData,
                                     vertices, rangemap, edges, preds, succs)
    __.InitGraph (Some (upcast core))

  override __.AddDummyEdge _g src dst =
    __.InitGraphWithNewEdge src dst edgeData

  override __.AddEdge _g src dst e =
    __.InitGraphWithNewEdge src dst e

  override __.RemoveEdge _g src dst =
    let srcid = src.GetID ()
    let dstid = dst.GetID ()
    let preds = __.RemoveEdgeFromMap preds dstid srcid
    let succs = __.RemoveEdgeFromMap succs srcid dstid
    let edges = Map.remove (srcid, dstid) edges
    let core = PersistentRangedCore (init, edgeData,
                                     vertices, rangemap, edges, preds, succs)
    __.InitGraph (Some (upcast core))

  override __.FoldEdge fn acc =
    edges
    |> Map.fold (fun acc _ (src, dst, e) -> fn acc src dst e) acc

  override __.IterEdge fn =
    edges
    |> Map.iter (fun _ (src, dst, e) -> fn src dst e)

  override __.FindEdge src dst =
    match Map.tryFind (src.GetID (), dst.GetID ()) edges with
    | Some (_, _, e) -> e
    | None -> raise EdgeNotFoundException

  override __.TryFindEdge src dst =
    match Map.tryFind (src.GetID (), dst.GetID ()) edges with
    | Some (_, _, e) -> Some e
    | None -> None

  override __.Clone () =
    __ :> GraphCore<'D, 'E, DiGraph<'D, 'E>>
