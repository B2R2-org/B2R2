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

type PersistentCore<'D, 'E when 'D :> VertexData and 'D: equality>
    (init, dummyEdge, ?vertices, ?edges, ?preds, ?succs) =
  inherit GraphCore<'D, 'E, DiGraph<'D, 'E>> ()

  let vertices = defaultArg vertices Map.empty
  let edges = defaultArg edges Map.empty
  let preds = defaultArg preds Map.empty
  let succs = defaultArg succs Map.empty

  override __.InitGraph core =
    match core with
    | Some core -> init core
    | None -> init <| PersistentCore (init, dummyEdge)

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
    let core = PersistentCore (init, dummyEdge, vertices, edges, preds, succs)
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

  override __.RemoveVertex _g v =
    let vid = v.GetID ()
    let ps = Map.find vid preds
    let ss = Map.find vid succs
    (* Remove edges from/to it *)
    let edges =
      ps |> List.fold (fun edges (p: Vertex<'D>) ->
        Map.remove (p.GetID (), vid) edges) edges
    let edges =
      ss |> List.fold (fun edges (s: Vertex<'D>) ->
        Map.remove (vid, s.GetID ()) edges) edges
    (* Update succs *)
    let succs =
      ps |> List.fold (fun succs (p: Vertex<_>) ->
        succs |> Map.map (fun id ss ->
          if p.GetID () = id then
            List.filter (fun (s: Vertex<_>) -> s.GetID () <> vid) ss
          else ss)) succs
    (* Update preds *)
    let preds =
      ss |> List.fold (fun preds (s: Vertex<_>) ->
        preds |> Map.map (fun id ps ->
          if s.GetID () = id then
            List.filter (fun (p: Vertex<_>) -> p.GetID () <> vid) ps
          else ps)) preds
    let vertices = Map.remove vid vertices
    let preds = Map.remove vid preds
    let succs = Map.remove vid succs
    let core = PersistentCore (init, dummyEdge, vertices, edges, preds, succs)
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
    let core = PersistentCore (init, dummyEdge, vertices, edges, preds, succs)
    __.InitGraph (Some (upcast core))

  override __.AddDummyEdge _g src dst =
    __.InitGraphWithNewEdge src dst dummyEdge

  override __.AddEdge _g src dst e =
    __.InitGraphWithNewEdge src dst e

  override __.GetEdge src dst =
    match Map.tryFind (src.GetID (), dst.GetID ()) edges with
    | Some (_, _, e) -> e
    | _ -> raise EdgeNotFoundException

  override __.RemoveEdge _g src dst =
    let srcid = src.GetID ()
    let dstid = dst.GetID ()
    let preds =
      preds |> Map.map (fun vid ps ->
        if vid = dstid then
          List.filter (fun (p: Vertex<'D>) -> p.GetID () <> srcid) ps
        else ps)
    let succs =
      succs |> Map.map (fun vid ss ->
        if vid = srcid then
          List.filter (fun (s: Vertex<'D>) -> s.GetID () <> dstid) ss
        else ss)
    let edges = Map.remove (srcid, dstid) edges
    let core = PersistentCore (init, dummyEdge, vertices, edges, preds, succs)
    __.InitGraph (Some (upcast core))

  override __.FoldEdge fn acc =
    edges
    |> Map.fold (fun acc _ (src, dst, e) -> fn acc src dst e) acc

  override __.IterEdge fn =
    edges
    |> Map.iter (fun _ (src, dst, e) -> fn src dst e)

  override __.FindEdgeBy fn =
    edges
    |> Map.pick (fun _ (src, dst, e) -> if fn src dst e then Some e else None)

  override __.TryFindEdgeBy fn =
    edges |> Map.tryPick (fun _ (src, dst, e) ->
      if fn src dst e then Some e else None)

  override __.Clone () =
    __ :> GraphCore<'D, 'E, DiGraph<'D, 'E>>

type PersistentRangedCore<'D, 'E when 'D :> RangedVertexData and 'D: equality>
    (init, dummyEdge, ?vertices, ?rangemap, ?edges, ?preds, ?succs) =
  inherit GraphCore<'D, 'E, DiGraph<'D, 'E>> ()

  let vertices = defaultArg vertices Map.empty
  let rangemap = defaultArg rangemap IntervalMap.empty
  let edges = defaultArg edges Map.empty
  let preds = defaultArg preds Map.empty
  let succs = defaultArg succs Map.empty

  override __.InitGraph core =
    match core with
    | Some core -> init core
    | None -> init <| PersistentRangedCore (init, dummyEdge)

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
    let core =
      PersistentRangedCore (init, dummyEdge, vertices, rangemap, edges, preds, succs)
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

  override __.RemoveVertex _g v =
    let vid = v.GetID ()
    let ps = Map.find vid preds
    let ss = Map.find vid succs
    (* Remove edges from/to it *)
    let edges =
      ps |> List.fold (fun edges (p: Vertex<'D>) ->
        Map.remove (p.GetID (), vid) edges) edges
    let edges =
      ss |> List.fold (fun edges (s: Vertex<'D>) ->
        Map.remove (vid, s.GetID ()) edges) edges
    (* Update succs *)
    let succs =
      ps |> List.fold (fun succs (p: Vertex<_>) ->
        succs |> Map.map (fun id ss ->
          if p.GetID () = id then
            List.filter (fun (s: Vertex<_>) -> s.GetID () <> vid) ss
          else ss)) succs
    (* Update preds *)
    let preds =
      ss |> List.fold (fun preds (s: Vertex<_>) ->
        preds |> Map.map (fun id ps ->
          if s.GetID () = id then
            List.filter (fun (p: Vertex<_>) -> p.GetID () <> vid) ps
          else ps)) preds
    let vertices = Map.remove vid vertices
    let rangemap =
      if v.IsDummy () then rangemap
      else IntervalMap.remove v.VData.AddrRange rangemap
    let preds = Map.remove vid preds
    let succs = Map.remove vid succs
    let core =
      PersistentRangedCore (init, dummyEdge, vertices, rangemap, edges, preds, succs)
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
    let core =
      PersistentRangedCore (init, dummyEdge, vertices, rangemap, edges, preds, succs)
    __.InitGraph (Some (upcast core))

  override __.AddDummyEdge _g src dst =
    __.InitGraphWithNewEdge src dst dummyEdge

  override __.AddEdge _g src dst e =
    __.InitGraphWithNewEdge src dst e

  override __.GetEdge src dst =
    match Map.tryFind (src.GetID (), dst.GetID ()) edges with
    | Some (_, _, e) -> e
    | _ -> raise EdgeNotFoundException

  override __.RemoveEdge _g src dst =
    let srcid = src.GetID ()
    let dstid = dst.GetID ()
    let preds =
      preds |> Map.map (fun vid ps ->
        if vid = dstid then
          List.filter (fun (p: Vertex<'D>) -> p.GetID () <> srcid) ps
        else ps)
    let succs =
      succs |> Map.map (fun vid ss ->
        if vid = srcid then
          List.filter (fun (s: Vertex<'D>) -> s.GetID () <> dstid) ss
        else ss)
    let edges = Map.remove (srcid, dstid) edges
    let core =
      PersistentRangedCore (init, dummyEdge, vertices, rangemap, edges, preds, succs)
    __.InitGraph (Some (upcast core))

  override __.FoldEdge fn acc =
    edges
    |> Map.fold (fun acc _ (src, dst, e) -> fn acc src dst e) acc

  override __.IterEdge fn =
    edges
    |> Map.iter (fun _ (src, dst, e) -> fn src dst e)

  override __.FindEdgeBy fn =
    edges
    |> Map.pick (fun _ (src, dst, e) -> if fn src dst e then Some e else None)

  override __.TryFindEdgeBy fn =
    edges |> Map.tryPick (fun _ (src, dst, e) ->
      if fn src dst e then Some e else None)

  override __.Clone () =
    __ :> GraphCore<'D, 'E, DiGraph<'D, 'E>>
