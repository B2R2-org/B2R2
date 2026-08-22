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

/// Represents the transpose of a directed graph, read as a view over the graph
/// it was taken from rather than built as a copy of it. The vertices are the
/// very ones of that graph, so a vertex needs no looking up to cross between
/// the two, which is what every post-dominance query rests on. What it reads
/// of that graph it reads once, at construction, so that it answers for the
/// state the graph was in when it was taken, as a copy of it would.
type internal ReversedDiGraph<'V, 'E when 'V: equality and 'E: equality>
  (orig: IDiGraph<'V, 'E>, roots: IVertex<'V>[]) =

  let vertices = orig.Vertices

  let edgeCount = orig.EdgeCount

  let implType = orig.ImplementationType

  (* Reversing swaps the two adjacency directions, hence the edges the original
     holds as the ones into a vertex are the ones out of it here. They are the
     original's own edge objects, from which both the neighbors and the edges
     of this graph are read. *)
  let outgoing = Dictionary<IVertex<'V>, Edge<'V, 'E>[]>()

  let incoming = Dictionary<IVertex<'V>, Edge<'V, 'E>[]>()

  do
    for v in vertices do
      outgoing[v] <- orig.GetPredEdges v
      incoming[v] <- orig.GetSuccEdges v
    for r in roots do
      if outgoing.ContainsKey r then ()
      else GraphUtils.raiseVertexNotFoundByID r.ID

  let reverse (v: IVertex<'V>) (e: Edge<'V, 'E>) =
    if e.HasLabel then Edge(v, e.First, EdgeLabel e.Label)
    else Edge(v, e.First, null)

  (* An edge of a transpose is a pair of its own, so it is an object of its
     own, and one is made only once a caller asks for any of them. Both
     directions read this one table, so that the edge out of a vertex and the
     edge into its neighbor are the same object. *)
  let reversed =
    lazy
      (let table = Dictionary<struct (VertexID * VertexID), Edge<'V, 'E>>()
       for KeyValue(v, es) in outgoing do
         for e in es do table[struct (v.ID, e.First.ID)] <- reverse v e
       table)

  let exits =
    lazy (vertices |> Array.filter (fun v -> outgoing[v].Length = 0))

  let toSuccArray (es: Edge<'V, 'E>[]) =
    let arr = Array.zeroCreate es.Length
    for i in 0 .. es.Length - 1 do arr[i] <- es[i].First
    arr

  let toPredArray (es: Edge<'V, 'E>[]) =
    let arr = Array.zeroCreate es.Length
    for i in 0 .. es.Length - 1 do arr[i] <- es[i].Second
    arr

  let toSuccEdges (v: IVertex<'V>) (es: Edge<'V, 'E>[]) =
    let table = reversed.Value
    let arr = Array.zeroCreate es.Length
    for i in 0 .. es.Length - 1 do
      arr[i] <- table[struct (v.ID, es[i].First.ID)]
    arr

  let toPredEdges (v: IVertex<'V>) (es: Edge<'V, 'E>[]) =
    let table = reversed.Value
    let arr = Array.zeroCreate es.Length
    for i in 0 .. es.Length - 1 do
      arr[i] <- table[struct (es[i].Second.ID, v.ID)]
    arr

  (* A vertex belongs to this graph only when it is one of the very objects the
     original handed over, which is why this asks of the vertex rather than of
     its ID. *)
  let ownsBoth (src: IVertex<'V>) (dst: IVertex<'V>) =
    outgoing.ContainsKey src && outgoing.ContainsKey dst

  let tryFindEdge src dst =
    if ownsBoth src dst then
      match reversed.Value.TryGetValue(struct (src.ID, dst.ID)) with
      | true, edge -> Some edge
      | false, _ -> None
    else
      None

  let tryFindVertexBy fn = vertices |> Array.tryFind fn

  let findVertexBy fn =
    match tryFindVertexBy fn with
    | Some v -> v
    | None -> GraphUtils.raiseVertexNotFoundByPredicate ()

  interface IDiGraph<'V, 'E> with

    member _.VertexCount with get() = vertices.Length

    member _.EdgeCount with get() = edgeCount

    member _.Vertices with get() = Array.copy vertices

    member _.Edges with get() = GraphUtils.toArray reversed.Value.Values

    member _.Exits with get() = Array.copy exits.Value

    member _.Roots with get() = Array.copy roots

    member _.SingleRoot with get() =
      match roots.Length with
      | 1 -> roots[0]
      | 0 -> raise NoRootVertexException
      | _ -> raise MultipleRootVerticesException

    member _.ImplementationType with get() = implType

    member _.IsEmpty with get() = vertices.Length = 0

    member _.Contains v = outgoing.ContainsKey v

    member _.HasEdge(src, dst) = (tryFindEdge src dst).IsSome

    member _.FindVertexBy fn = findVertexBy fn

    member _.TryFindVertexBy fn = tryFindVertexBy fn

    member _.FindVertexByData data =
      match tryFindVertexBy (fun v -> v.VData = data) with
      | Some v -> v
      | None -> GraphUtils.raiseVertexNotFoundByData data

    member _.TryFindVertexByData data =
      tryFindVertexBy (fun v -> v.VData = data)

    member _.FindEdge(src, dst) =
      match tryFindEdge src dst with
      | Some edge -> edge
      | None -> raise EdgeNotFoundException

    member _.TryFindEdge(src, dst) = tryFindEdge src dst

    member _.GetPreds(v: IVertex<'V>) =
      match incoming.TryGetValue v with
      | true, es -> toPredArray es
      | false, _ -> [||]

    member _.GetPredEdges(v: IVertex<'V>) =
      match incoming.TryGetValue v with
      | true, es -> toPredEdges v es
      | false, _ -> [||]

    member _.GetSuccs(v: IVertex<'V>) =
      match outgoing.TryGetValue v with
      | true, es -> toSuccArray es
      | false, _ -> [||]

    member _.GetSuccEdges(v: IVertex<'V>) =
      match outgoing.TryGetValue v with
      | true, es -> toSuccEdges v es
      | false, _ -> [||]

    member this.Reverse vs = ReversedDiGraph(this, Seq.toArray vs)
