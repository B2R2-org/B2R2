(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>
          Soomin Kim <soomink@kaist.ac.kr>

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
open B2R2.Utils

type RangedVertexData (range: AddrRange) =
  inherit VertexData(VertexData.genID ())
  member __.AddrRange = range

module IM = IntervalMap

type RangedDiGraph<'V, 'E when 'V :> RangedVertexData> () =
  inherit DiGraph<'V, 'E>()
  let mutable vertices: IntervalMap<Vertex<'V>>  = IM.empty
  let mutable edges: Map<EdgeID, Vertex<'V> * Vertex<'V> * Edge<'E>> = Map.empty
  let mutable size = 0

  member private __.Vertices with get () = vertices and set(v) = vertices <- v

  member private __.Edges with get() = edges and set(v) = edges <- v

  member private __.IncSize () = size <- size + 1

  member private __.DecSize () = size <- size - 1

  member private __.CheckVertexExistence (v: Vertex<'V>) =
    match IM.tryFind v.VData.AddrRange __.Vertices with
    | Some myVertex when v === myVertex -> ()
    | _ -> raise VertexNotFoundException

  override __.IsEmpty () = IM.isEmpty vertices

  override __.Size () = size

  override __.AddVertex data =
    if IM.contains data.AddrRange __.Vertices then
      IM.tryFind data.AddrRange __.Vertices |> Option.get
    else
      let v = Vertex<_>(data)
      __.Vertices <- IM.add data.AddrRange v __.Vertices
      __.Unreachables <- v :: __.Unreachables
      __.Exits <- v :: __.Exits
      __.IncSize ()
      v

  override __.RemoveVertex v =
    __.CheckVertexExistence v
    v.Succs |> List.iter (fun succ -> __.RemoveEdge v succ)
    v.Preds |> List.iter (fun pred -> __.RemoveEdge pred v)
    __.Vertices <- IM.remove v.VData.AddrRange __.Vertices
    __.Unreachables <-
      List.filter (fun e -> e.GetID () <> v.GetID ()) __.Unreachables
    __.Exits <- List.filter (fun e -> e.GetID () <> v.GetID ()) __.Exits
    __.DecSize ()

  override __.FindVertex (v:Vertex<_>) =
    match IM.tryFind v.VData.AddrRange __.Vertices with
    | Some v -> v
    | _ -> raise VertexNotFoundException

  /// XXX: is it right way to find vertex?
  override __.FindVertexByData vdata =
    match IM.tryFind vdata.AddrRange __.Vertices with
    | Some v -> v
    | _ -> raise VertexNotFoundException

  override __.TryFindVertexByData vdata =
    IM.tryFind vdata.AddrRange __.Vertices

  override __.AddEdge src dst e =
    __.CheckVertexExistence src
    __.CheckVertexExistence dst
    src.Succs <- dst :: src.Succs
    dst.Preds <- src :: dst.Preds
    __.Edges <- Map.add (src.GetID (), dst.GetID ()) (src, dst, Edge e) __.Edges
    __.Unreachables <-
      List.filter (fun v -> v.GetID () <> dst.GetID ()) __.Unreachables
    __.Exits <- List.filter (fun v -> v.GetID () <> src.GetID ()) __.Exits

  override __.RemoveEdge src dst =
    __.CheckVertexExistence src
    __.CheckVertexExistence dst
    src.Succs <- List.filter (fun s -> s.GetID () <> dst.GetID ()) src.Succs
    dst.Preds <- List.filter (fun p -> p.GetID () <> src.GetID ()) dst.Preds
    if List.length dst.Preds = 0 then __.Unreachables <- dst :: __.Unreachables
    if List.length src.Succs = 0 then __.Exits <- src :: __.Exits
    __.Edges <- Map.remove (src.GetID (), dst.GetID ()) __.Edges

  member __.Clone (?reverse) =
    let g = RangedDiGraph<'V, 'E>()
    let isReverse = defaultArg reverse false
    let dict = System.Collections.Generic.Dictionary<VertexID, Vertex<'V>>()
    let addEdgeNormal (s: Vertex<'V>) (d: Vertex<'V>) =
      g.AddEdge dict.[s.GetID ()] dict.[d.GetID ()] (__.FindEdge s d)
    let addEdgeReverse (s: Vertex<'V>) (d: Vertex<'V>) =
      g.AddEdge dict.[d.GetID ()] dict.[s.GetID ()] (__.FindEdge s d)
    let addEdge = if isReverse then addEdgeReverse else addEdgeNormal
    __.IterVertex (fun v -> dict.Add(v.GetID (), g.AddVertex v.VData))
    __.IterEdge addEdge
    if isReverse then () else g.FindVertex (__.GetRoot ()) |> g.SetRoot
    g

  override __.Reverse () = upcast __.Clone (true)

  override __.FoldVertex fn acc =
    __.Vertices |> IM.fold (fun acc _ v -> fn acc v) acc

  override __.IterVertex fn =
    __.Vertices |> IM.fold (fun () _ v -> fn v) ()

  override __.FoldEdge fn acc =
    __.Edges |> Map.fold (fun acc _ (src, dst, _) -> fn acc src dst) acc

  override __.IterEdge fn =
    __.Edges |> Map.iter (fun _ (src, dst, _) -> fn src dst)

  member __.FindVertexByRange range =
    match IM.tryFind range __.Vertices with
    | None -> raise VertexNotFoundException
    | Some v -> v

  override __.FindEdge (src: Vertex<'V>) (dst: Vertex<'V>) =
    match Map.tryFind (src.GetID (), dst.GetID ()) __.Edges with
    | None -> raise EdgeNotFoundException
    | Some (_, _, Edge eData) -> eData

  override __.GetVertices () =
    __.Vertices |> IM.fold (fun acc _ v -> Set.add v acc) Set.empty

// vim: set tw=80 sts=2 sw=2:
