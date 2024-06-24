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
  let vertices = HashSet<ImperativeVertex<'V>> ()
  let edges = Dictionary<VertexID * VertexID, Edge<'V, 'E>> ()
  let unreachables = HashSet<ImperativeVertex<'V>> ()
  let exits = HashSet<ImperativeVertex<'V>> ()
  let mutable id = 0
  let roots = List<ImperativeVertex<'V>> ()

  member inline private __.CheckVertexExistence v =
    if not <| vertices.Contains v then raise VertexNotFoundException
    else ()

  member private __.AddVertexInternal (data: VertexData<'V>, vid: VertexID) =
    let v = ImperativeVertex (vid, data)
    if roots.Count = 0 then roots.Add v else ()
    vertices.Add v |> ignore
    unreachables.Add v |> ignore
    exits.Add v |> ignore
    (v :> IVertex<'V>), (__ :> IGraph<'V, 'E>)

  member private __.AddVertex (data: VertexData<'V>) =
    id <- id + 1
    __.AddVertexInternal (data, id)

  member private __.AddVertex (data: VertexData<'V>, vid: VertexID) =
    id <- max id vid
    __.AddVertexInternal (data, vid)

  member private __.AddEdge (src: IVertex<'V>, dst: IVertex<'V>, label) =
    let src = src :?> ImperativeVertex<'V>
    let dst = dst :?> ImperativeVertex<'V>
    __.CheckVertexExistence src
    __.CheckVertexExistence dst
    let srcID = (src :> IVertex<_>).ID
    let dstID = (dst :> IVertex<_>).ID
    if edges.ContainsKey (srcID, dstID) then ()
    else
      edges[(srcID, dstID)] <- Edge (src, dst, label)
      src.Succs.Add dst
      dst.Preds.Add src
      unreachables.Remove dst |> ignore
      exits.Remove src |> ignore
    __ :> IGraph<'V, 'E>

  interface IGraph<'V, 'E> with
    member __.IsEmpty () = vertices.Count = 0

    member __.Size with get() = vertices.Count

    member __.Vertices with get() =
      vertices |> Seq.map (fun v -> v :> IVertex<'V>) |> Seq.toArray

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

    member __.AddVertex v =
      __.AddVertex (data=VertexData v)

    member __.AddVertex (v, vid) =
      assert ((__: IGraph<_, _>).HasVertex vid |> not)
      __.AddVertex (data=VertexData v, vid=vid)

    member __.AddVertex () =
      __.AddVertex (data=null)

    member __.RemoveVertex v =
      let v = v :?> ImperativeVertex<'V>
      __.CheckVertexExistence v
      v.Preds
      |> Seq.toArray
      |> Array.iter (fun p -> (__ :> IGraph<_, _>).RemoveEdge (p, v) |> ignore)
      v.Succs
      |> Seq.toArray
      |> Array.iter (fun s -> (__ :> IGraph<_, _>).RemoveEdge (v, s) |> ignore)
      vertices.Remove v |> ignore
      unreachables.Remove v |> ignore
      exits.Remove v |> ignore
      roots.Remove v |> ignore
      __

    member __.HasVertex vid =
      vertices
      |> Seq.exists (fun v -> (v :> IVertex<'V>).ID = vid)

    member __.FindVertexByID vid =
      vertices
      |> Seq.find (fun v -> (v :> IVertex<'V>).ID = vid)
      :> IVertex<'V>

    member __.TryFindVertexByID vid =
      vertices
      |> Seq.tryFind (fun v -> (v :> IVertex<_>).ID = vid)
      |> Option.map (fun v -> v :> IVertex<'V>)

    member __.FindVertexByData data =
      vertices
      |> Seq.find (fun v -> (v :> IVertex<'V>).VData = data)
      :> IVertex<'V>

    member __.TryFindVertexByData data =
      vertices
      |> Seq.tryFind (fun v -> (v :> IVertex<'V>).VData = data)
      |> Option.map (fun v -> v :> IVertex<'V>)

    member __.FindVertexBy fn =
      vertices |> Seq.find fn :> IVertex<'V>

    member __.TryFindVertexBy fn =
      vertices
      |> Seq.tryFind fn
      |> Option.map (fun v -> v :> IVertex<'V>)

    member __.AddEdge (src: IVertex<'V>, dst: IVertex<'V>, label) =
      __.AddEdge (src, dst, EdgeLabel label)

    member __.AddEdge (src: IVertex<'V>, dst: IVertex<'V>) =
      __.AddEdge (src, dst, null)

    member __.RemoveEdge (src: IVertex<'V>, dst: IVertex<'V>) =
      let src = src :?> ImperativeVertex<'V>
      let dst = dst :?> ImperativeVertex<'V>
      __.CheckVertexExistence src
      __.CheckVertexExistence dst
      let srcid = src.ID
      let dstid = dst.ID
      src.Succs.RemoveAll (fun s -> s.ID = dstid) |> ignore
      dst.Preds.RemoveAll (fun p -> p.ID = srcid) |> ignore
      if dst.Preds.Count = 0 then unreachables.Add dst |> ignore else ()
      if src.Succs.Count = 0 then exits.Add src |> ignore else ()
      edges.Remove ((srcid, dstid)) |> ignore
      __ :> IGraph<'V, 'E>

    member __.RemoveEdge (edge: Edge<'V, 'E>) =
      (__ :> IGraph<_, _>).RemoveEdge (edge.First, edge.Second)

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
      :> IReadOnlyCollection<_>

    member __.GetPredEdges (v: IVertex<'V>) =
      (v :?> ImperativeVertex<'V>).Preds
      |> Seq.toArray
      |> Array.map (fun pred -> edges[(pred.ID, v.ID)])
      :> IReadOnlyCollection<_>

    member __.GetSuccs (v: IVertex<'V>) =
      (v :?> ImperativeVertex<'V>).Succs
      |> Seq.toArray
      |> Array.map (fun v -> v :> IVertex<'V>)
      :> IReadOnlyCollection<_>

    member __.GetSuccEdges (v: IVertex<'V>) =
      (v :?> ImperativeVertex<'V>).Succs
      |> Seq.toArray
      |> Array.map (fun succ -> edges[(v.ID, succ.ID)])
      :> IReadOnlyCollection<_>

    member __.GetRoots () =
      roots
      |> Seq.toArray
      |> Array.map (fun v -> v :> IVertex<'V>)
      :> IReadOnlyCollection<_>

    member __.AddRoot (v) =
      let v = v :?> ImperativeVertex<'V>
      assert (vertices.Contains v)
      if roots.Contains v then () else roots.Add v
      __

    member __.SetRoot (v) =
      assert (vertices.Contains (v :?> ImperativeVertex<'V>))
      roots.Clear ()
      roots.Add (v :?> ImperativeVertex<'V>)
      __

    member __.FoldVertex fn acc =
      vertices |> Seq.fold (fun acc v -> fn acc (v :> IVertex<'V>)) acc

    member __.IterVertex fn =
      vertices |> Seq.iter (fun v -> fn (v :> IVertex<'V>))

    member __.FoldEdge fn acc =
      edges.Values |> Seq.fold fn acc

    member __.IterEdge fn =
      edges.Values |> Seq.iter fn

    member __.SubGraph vs =
      GraphUtils.subGraph __ (ImperativeDiGraph ()) vs

    member __.Reverse () =
      GraphUtils.reverse __ (ImperativeDiGraph ())

    member __.Clone () =
      let g = ImperativeDiGraph () :> IGraph<_, _>
      let dictOldToNew= Dictionary<VertexID, VertexID> ()
      (__ :> IGraph<_, _>).IterVertex (fun v ->
        let v', _ = g.AddVertex v.VData
        dictOldToNew.Add (v.ID, v'.ID))
      (__ :> IGraph<_, _>).IterEdge (fun e ->
        let src = g.FindVertexByID dictOldToNew[e.First.ID]
        let dst = g.FindVertexByID dictOldToNew[e.Second.ID]
        g.AddEdge (src, dst, e.Label) |> ignore)
      g

    member __.ToDOTStr (name, vToStrFn, _eToStrFn) =
      GraphUtils.toDiGraphDOTString __ name vToStrFn _eToStrFn
