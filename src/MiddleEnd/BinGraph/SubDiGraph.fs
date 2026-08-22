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

/// Represents the subgraph a set of vertices induces in a directed graph, read
/// as a view over that graph rather than built as a copy of it. The vertices
/// are the very ones of that graph, and so are the edges, an induced subgraph
/// keeping every edge whose two endpoints it holds. What it reads of that
/// graph it reads once, at construction, so that it answers for the state the
/// graph was in when it was taken.
type internal SubDiGraph<'V, 'E when 'V: equality and 'E: equality>
  (orig: IDiGraph<'V, 'E>, vs: IVertex<'V>[], roots: IVertex<'V>[]) =

  let implType = orig.ImplementationType

  let outgoing = Dictionary<IVertex<'V>, Edge<'V, 'E>[]>()

  let incoming = Dictionary<IVertex<'V>, Edge<'V, 'E>[]>()

  let mutable edgeCount = 0

  do
    let held = HashSet<IVertex<'V>> vs
    let isHeldSucc (e: Edge<'V, 'E>) = held.Contains e.Second
    let isHeldPred (e: Edge<'V, 'E>) = held.Contains e.First
    for v in vs do
      let outs = orig.GetSuccEdges v |> Array.filter isHeldSucc
      outgoing[v] <- outs
      incoming[v] <- orig.GetPredEdges v |> Array.filter isHeldPred
      edgeCount <- edgeCount + outs.Length
    for r in roots do
      if held.Contains r then () else GraphUtils.raiseVertexNotFoundByID r.ID

  let toSuccArray (es: Edge<'V, 'E>[]) =
    let arr = Array.zeroCreate es.Length
    for i in 0 .. es.Length - 1 do arr[i] <- es[i].Second
    arr

  let toPredArray (es: Edge<'V, 'E>[]) =
    let arr = Array.zeroCreate es.Length
    for i in 0 .. es.Length - 1 do arr[i] <- es[i].First
    arr

  let exits =
    lazy (vs |> Array.filter (fun v -> outgoing[v].Length = 0))

  let tryFindEdge (src: IVertex<'V>) (dst: IVertex<'V>) =
    match outgoing.TryGetValue src with
    | true, es ->
      es |> Array.tryFind (fun e -> obj.ReferenceEquals(e.Second, dst))
    | false, _ ->
      None

  let tryFindVertexBy fn = vs |> Array.tryFind fn

  let findVertexBy fn =
    match tryFindVertexBy fn with
    | Some v -> v
    | None -> GraphUtils.raiseVertexNotFoundByPredicate ()

  interface IDiGraph<'V, 'E> with

    member _.VertexCount with get() = vs.Length

    member _.EdgeCount with get() = edgeCount

    member _.Vertices with get() = Array.copy vs

    member _.Edges with get() =
      let arr = Array.zeroCreate edgeCount
      let mutable i = 0
      for v in vs do
        for e in outgoing[v] do
          arr[i] <- e
          i <- i + 1
      arr

    member _.Exits with get() = Array.copy exits.Value

    member _.Roots with get() = Array.copy roots

    member _.SingleRoot with get() =
      match roots.Length with
      | 1 -> roots[0]
      | 0 -> raise NoRootVertexException
      | _ -> raise MultipleRootVerticesException

    member _.ImplementationType with get() = implType

    member _.IsEmpty with get() = vs.Length = 0

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
      | true, es -> Array.copy es
      | false, _ -> [||]

    member _.GetSuccs(v: IVertex<'V>) =
      match outgoing.TryGetValue v with
      | true, es -> toSuccArray es
      | false, _ -> [||]

    member _.GetSuccEdges(v: IVertex<'V>) =
      match outgoing.TryGetValue v with
      | true, es -> Array.copy es
      | false, _ -> [||]

    member this.Reverse vs = ReversedDiGraph(this, Seq.toArray vs)
