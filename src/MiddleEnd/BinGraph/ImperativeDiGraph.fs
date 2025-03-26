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

/// Imperative directed graph.
type ImperativeDiGraph<'V, 'E when 'V: equality and 'E: equality> () =
  let vertices = Dictionary<VertexID, ImperativeVertex<'V>> ()

  let edges = Dictionary<VertexID * VertexID, Edge<'V, 'E>> ()

  let unreachables = HashSet<ImperativeVertex<'V>> ()

  let exits = HashSet<ImperativeVertex<'V>> ()

  let mutable id = 0

  let roots = List<ImperativeVertex<'V>> ()

  let checkVertexExistence (v: IVertex<'V>) =
    if not <| vertices.ContainsKey v.ID then raise VertexNotFoundException
    else ()

  let addVertex (data: VertexData<'V>) (vid: VertexID) =
    let v = ImperativeVertex (vid, data)
    if roots.Count = 0 then roots.Add v else ()
    vertices.Add (vid, v) |> ignore
    unreachables.Add v |> ignore
    exits.Add v |> ignore
    (v :> IVertex<'V>)

  let addVertexWithData (data: VertexData<'V>) =
    id <- id + 1
    addVertex data id

  let addVertexWithDataAndID (data: VertexData<'V>) (vid: VertexID) =
    id <- max id vid
    addVertex data vid

  let addEdge (src: IVertex<'V>) (dst: IVertex<'V>) label =
    let src = src :?> ImperativeVertex<'V>
    let dst = dst :?> ImperativeVertex<'V>
    checkVertexExistence src
    checkVertexExistence dst
    let srcID = (src :> IVertex<_>).ID
    let dstID = (dst :> IVertex<_>).ID
    if edges.ContainsKey (srcID, dstID) then ()
    else
      edges[(srcID, dstID)] <- Edge (src, dst, label)
      src.Succs.Add dst
      dst.Preds.Add src
      unreachables.Remove dst |> ignore
      exits.Remove src |> ignore

  let removeEdge (src: IVertex<'V>) (dst: IVertex<'V>) =
    let src = src :?> ImperativeVertex<'V>
    let dst = dst :?> ImperativeVertex<'V>
    checkVertexExistence src
    checkVertexExistence dst
    let srcid = src.ID
    let dstid = dst.ID
    src.Succs.RemoveAll (fun s -> s.ID = dstid) |> ignore
    dst.Preds.RemoveAll (fun p -> p.ID = srcid) |> ignore
    if dst.Preds.Count = 0 then unreachables.Add dst |> ignore else ()
    if src.Succs.Count = 0 then exits.Add src |> ignore else ()
    edges.Remove ((srcid, dstid)) |> ignore

  let findVertexBy fn =
    vertices.Values |> Seq.find fn :> IVertex<'V>

  let tryFindVertexBy fn =
    vertices.Values
    |> Seq.tryFind fn
    |> Option.map (fun v -> v :> IVertex<'V>)

  let clone () =
    let g = ImperativeDiGraph<'V, 'E> ()
    let ig = g :> IDiGraph<_, _>
    let dictOldToNew = Dictionary<VertexID, VertexID> ()
    vertices.Values |> Seq.iter (fun v ->
      let v', _ = ig.AddVertex (v :> IVertex<_>).VData
      dictOldToNew.Add (v.ID, v'.ID))
    edges.Values |> Seq.iter (fun e ->
      let src = ig.FindVertexByID dictOldToNew[e.First.ID]
      let dst = ig.FindVertexByID dictOldToNew[e.Second.ID]
      ig.AddEdge (src, dst, e.Label) |> ignore)
    g

  interface IDiGraphAccessible<'V, 'E> with

    member __.Size with get() = vertices.Count

    member __.Vertices with get() =
      vertices.Values |> Seq.map (fun v -> v :> IVertex<'V>) |> Seq.toArray

    member __.Edges with get() =
      edges
      |> Seq.toArray
      |> Array.map (fun (KeyValue (_, edge)) -> edge)

    member __.Unreachables with get() =
      unreachables
      |> Seq.toArray
      |> Array.map (fun v -> v :> IVertex<'V>)

    member __.Exits with get() =
      exits
      |> Seq.toArray
      |> Array.map (fun v -> v :> IVertex<'V>)

    member __.SingleRoot with get() =
      if roots.Count = 1 then roots[0]
      else raise MultipleRootVerticesException

    member __.ImplementationType with get() = Imperative

    member __.IsEmpty () = vertices.Count = 0

    member __.HasVertex vid = vertices.ContainsKey vid

    member __.FindVertexBy fn = findVertexBy fn

    member __.TryFindVertexBy fn = tryFindVertexBy fn

    member __.FindVertexByID vid = vertices[vid]

    member __.TryFindVertexByID vid =
      match vertices.TryGetValue vid with
      | false, _ -> None
      | true, v -> Some v

    member __.FindVertexByData data =
      findVertexBy (fun v -> (v :> IVertex<'V>).VData = data)

    member __.TryFindVertexByData data =
      tryFindVertexBy (fun v -> (v :> IVertex<'V>).VData = data)

    member __.FindEdge (src: IVertex<'V>, dst: IVertex<'V>) =
      match edges.TryGetValue (key=(src.ID, dst.ID)) with
      | true, edge -> edge
      | false, _ -> raise EdgeNotFoundException

    member __.TryFindEdge (src: IVertex<'V>, dst: IVertex<'V>) =
      match edges.TryGetValue (key=(src.ID, dst.ID)) with
      | true, edge -> Some edge
      | false, _ -> None

    member __.GetPreds (v: IVertex<'V>) =
      (v :?> ImperativeVertex<'V>).Preds
      |> Seq.toArray
      |> Array.map (fun v -> v :> IVertex<'V>)

    member __.GetPredEdges (v: IVertex<'V>) =
      (v :?> ImperativeVertex<'V>).Preds
      |> Seq.toArray
      |> Array.map (fun pred -> edges[(pred.ID, v.ID)])

    member __.GetSuccs (v: IVertex<'V>) =
      (v :?> ImperativeVertex<'V>).Succs
      |> Seq.toArray
      |> Array.map (fun v -> v :> IVertex<'V>)

    member __.GetSuccEdges (v: IVertex<'V>) =
      (v :?> ImperativeVertex<'V>).Succs
      |> Seq.toArray
      |> Array.map (fun succ -> edges[(v.ID, succ.ID)])

    member __.GetRoots () =
      roots
      |> Seq.toArray
      |> Array.map (fun v -> v :> IVertex<'V>)

    member __.Reverse vs =
      GraphUtils.reverse __ vs (ImperativeDiGraph ())

    member __.FoldVertex fn acc =
      vertices.Values |> Seq.fold (fun acc v -> fn acc (v :> IVertex<'V>)) acc

    member __.IterVertex fn =
      vertices.Values |> Seq.iter (fun v -> fn (v :> IVertex<'V>))

    member __.FoldEdge fn acc =
      edges.Values |> Seq.fold fn acc

    member __.IterEdge fn =
      edges.Values |> Seq.iter fn

  interface IDiGraph<'V, 'E> with

    member __.AddVertex v =
      addVertexWithData (VertexData v), __

    member __.AddVertex (v, vid) =
      assert ((__: IDiGraph<_, _>).HasVertex vid |> not)
      addVertexWithDataAndID (VertexData v) vid, __

    member __.AddVertex () =
      addVertexWithData null, __

    member __.RemoveVertex v =
      let v = v :?> ImperativeVertex<'V>
      checkVertexExistence v
      v.Preds |> Seq.toArray |> Array.iter (fun p -> removeEdge p v)
      v.Succs |> Seq.toArray |> Array.iter (fun s -> removeEdge v s)
      vertices.Remove v.ID |> ignore
      unreachables.Remove v |> ignore
      exits.Remove v |> ignore
      roots.Remove v |> ignore
      __

    member __.AddEdge (src: IVertex<'V>, dst: IVertex<'V>, label) =
      addEdge src dst (EdgeLabel label)
      __

    member __.AddEdge (src: IVertex<'V>, dst: IVertex<'V>) =
      addEdge src dst null
      __

    member __.RemoveEdge (src: IVertex<'V>, dst: IVertex<'V>) =
      removeEdge src dst
      __

    member __.RemoveEdge (edge: Edge<'V, 'E>) =
      removeEdge edge.First edge.Second
      __

    member __.AddRoot (v) =
      let v = v :?> ImperativeVertex<'V>
      assert (vertices.ContainsKey v.ID)
      if roots.Contains v then () else roots.Add v
      __

    member __.SetRoots (vs) =
      roots.Clear ()
      for v in vs do
        assert (vertices.ContainsKey v.ID)
        roots.Add (v :?> ImperativeVertex<'V>)
      __

    member __.Reverse (vs) =
      GraphUtils.reverse __ vs (ImperativeDiGraph ())

    member __.Clone () =
      clone ()
