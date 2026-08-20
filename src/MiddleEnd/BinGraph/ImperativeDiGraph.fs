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

/// Represents an imperative directed graph.
type ImperativeDiGraph<'V, 'E when 'V: equality and 'E: equality>() =
  let vertices = Dictionary<VertexID, Vertex<'V>>()

  let edges = Dictionary<VertexID * VertexID, Edge<'V, 'E>>()

  let preds = Dictionary<VertexID, List<Vertex<'V>>>()

  let succs = Dictionary<VertexID, List<Vertex<'V>>>()

  let unreachables = HashSet<Vertex<'V>>()

  let exits = HashSet<Vertex<'V>>()

  let mutable id = 0

  let roots = List<Vertex<'V>>()

  (* A vertex belongs to this graph only when it is the very object we store
     for its ID. Comparing IDs is not enough, because vertices compare by ID,
     so a vertex of another graph can carry an ID we also use. *)
  let isOwnVertex (v: IVertex<'V>) =
    match vertices.TryGetValue v.ID with
    | true, v' -> obj.ReferenceEquals(v', v)
    | false, _ -> false

  let findOwnVertex (v: IVertex<'V>) =
    if isOwnVertex v then vertices[v.ID]
    else GraphUtils.raiseVertexNotFoundByID v.ID

  let addVertex (data: VertexData<'V>) (vid: VertexID) =
    let v = Vertex(vid, data)
    if roots.Count = 0 then roots.Add v else ()
    vertices.Add(vid, v) |> ignore
    preds.Add(vid, List())
    succs.Add(vid, List())
    unreachables.Add v |> ignore
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
      unreachables.Remove dst |> ignore
      exits.Remove src |> ignore

  let removeEdge (src: IVertex<'V>) (dst: IVertex<'V>) =
    let src = findOwnVertex src
    let dst = findOwnVertex dst
    let srcID = src.ID
    let dstID = dst.ID
    succs[srcID].RemoveAll(fun s -> s.ID = dstID) |> ignore
    preds[dstID].RemoveAll(fun p -> p.ID = srcID) |> ignore
    if preds[dstID].Count = 0 then unreachables.Add dst |> ignore else ()
    if succs[srcID].Count = 0 then exits.Add src |> ignore else ()
    edges.Remove((srcID, dstID)) |> ignore

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
    let g = ImperativeDiGraph<'V, 'E>()
    let ig = g :> IDiGraph<_, _>
    let dictOldToNew = Dictionary<VertexID, VertexID>()
    vertices.Values |> Seq.iter (fun v ->
      let v', _ = ig.AddVertex((v :> IVertex<_>).VData)
      dictOldToNew.Add(v.ID, v'.ID))
    (* Every edge endpoint is a vertex of this graph, hence mapped above. *)
    edges.Values |> Seq.iter (fun e ->
      assert (dictOldToNew.ContainsKey e.First.ID)
      assert (dictOldToNew.ContainsKey e.Second.ID)
      let src = ig.FindVertexByID dictOldToNew[e.First.ID]
      let dst = ig.FindVertexByID dictOldToNew[e.Second.ID]
      ig.AddEdge(src, dst, e.Label) |> ignore)
    g

  interface IDiGraphAccessible<'V, 'E> with

    member _.Size with get() = vertices.Count

    member _.Vertices with get() =
      vertices.Values |> Seq.map (fun v -> v :> IVertex<'V>) |> Seq.toArray

    member _.Edges with get() =
      edges
      |> Seq.toArray
      |> Array.map (fun (KeyValue(_, edge)) -> edge)

    member _.Unreachables with get() =
      unreachables
      |> Seq.toArray
      |> Array.map (fun v -> v :> IVertex<'V>)

    member _.Exits with get() =
      exits
      |> Seq.toArray
      |> Array.map (fun v -> v :> IVertex<'V>)

    member _.SingleRoot with get() =
      if roots.Count = 1 then roots[0] else raise MultipleRootVerticesException

    member _.ImplementationType with get() = Imperative

    member _.IsEmpty() = vertices.Count = 0

    member _.HasVertex vid = vertices.ContainsKey vid

    member _.HasEdge(src, dst) = edges.ContainsKey((src.ID, dst.ID))

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
      | true, edge -> edge
      | false, _ -> raise EdgeNotFoundException

    member _.TryFindEdge(src: IVertex<'V>, dst: IVertex<'V>) =
      match edges.TryGetValue(key = (src.ID, dst.ID)) with
      | true, edge -> Some edge
      | false, _ -> None

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

    member this.Reverse vs = GraphUtils.reverse this vs (ImperativeDiGraph())

    member _.FoldVertex(fn, acc) =
      vertices.Values |> Seq.fold (fun acc v -> fn acc (v :> IVertex<'V>)) acc

    member _.IterVertex fn =
      vertices.Values |> Seq.iter (fun v -> fn (v :> IVertex<'V>))

    member _.FoldEdge(fn, acc) = edges.Values |> Seq.fold fn acc

    member _.IterEdge fn = edges.Values |> Seq.iter fn

  interface IDiGraph<'V, 'E> with

    member this.AddVertex v = addVertexWithData (VertexData v), this

    member this.AddVertex(v, vid) =
      assert ((this: IDiGraph<_, _>).HasVertex vid |> not)
      addVertexWithDataAndID (VertexData v) vid, this

    member this.AddVertex() = addVertexWithData null, this

    member this.RemoveVertex v =
      let v = findOwnVertex v
      let vid = v.ID
      preds[vid] |> Seq.toArray |> Array.iter (fun p -> removeEdge p v)
      succs[vid] |> Seq.toArray |> Array.iter (fun s -> removeEdge v s)
      vertices.Remove vid |> ignore
      preds.Remove vid |> ignore
      succs.Remove vid |> ignore
      unreachables.Remove v |> ignore
      exits.Remove v |> ignore
      roots.Remove v |> ignore
      this

    member this.AddEdge(src: IVertex<'V>, dst: IVertex<'V>, label) =
      addEdge src dst (EdgeLabel label)
      this

    member this.AddEdge(src: IVertex<'V>, dst: IVertex<'V>) =
      addEdge src dst null
      this

    member this.RemoveEdge(src: IVertex<'V>, dst: IVertex<'V>) =
      removeEdge src dst
      this

    member this.RemoveEdge(edge: Edge<'V, 'E>) =
      removeEdge edge.First edge.Second
      this

    member this.AddRoot(v) =
      let v = findOwnVertex v
      if roots.Contains v then () else roots.Add v
      this

    member this.SetRoots(vs) =
      let vs = vs |> Seq.map findOwnVertex |> Seq.toArray
      roots.Clear()
      roots.AddRange vs
      this

    member this.Reverse(vs) = GraphUtils.reverse this vs (ImperativeDiGraph())

    member _.Clone() = clone ()
