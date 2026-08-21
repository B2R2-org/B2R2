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

/// Represents a directed graph that is modified in place, but keeps its state
/// in a persistent graph. Reads go to the snapshot it currently holds, and
/// every modification replaces that snapshot with the graph the modification
/// returned. Wrapping a persistent graph in this is what lets code that builds
/// a graph be written once against `IMutableDiGraph`, whichever of the two
/// protocols the graph at hand has, and what lets a caller take a snapshot of
/// a graph as it is being built.
type MutablePersistentDiGraph<'V, 'E when 'V: equality and 'E: equality>
  (init: IPersistentDiGraph<'V, 'E>) =

  let mutable g = init

  let addVertex (v, g') = g <- g'; v

  let update g' = g <- g'

  /// Gets the snapshot this graph currently holds. Modifying this graph later
  /// on replaces the snapshot rather than change it, so the returned graph
  /// keeps the state it has at the moment of this call.
  member _.Snapshot with get() = g

  interface IMutableDiGraph<'V, 'E> with

    member _.Size = g.Size

    member _.Vertices = g.Vertices

    member _.Edges = g.Edges

    member _.Exits = g.Exits

    member _.SingleRoot = g.SingleRoot

    member _.ImplementationType = g.ImplementationType

    member _.IsEmpty() = g.IsEmpty()

    member _.HasVertex vid = g.HasVertex vid

    member _.HasEdge(src, dst) = g.HasEdge(src, dst)

    member _.FindVertexByID vid = g.FindVertexByID vid

    member _.TryFindVertexByID vid = g.TryFindVertexByID vid

    member _.FindVertexByData data = g.FindVertexByData data

    member _.TryFindVertexByData data = g.TryFindVertexByData data

    member _.FindVertexBy fn = g.FindVertexBy fn

    member _.TryFindVertexBy fn = g.TryFindVertexBy fn

    member _.FindEdge(src, dst) = g.FindEdge(src, dst)

    member _.TryFindEdge(src, dst) = g.TryFindEdge(src, dst)

    member _.GetPreds v = g.GetPreds v

    member _.GetPredEdges v = g.GetPredEdges v

    member _.GetSuccs v = g.GetSuccs v

    member _.GetSuccEdges v = g.GetSuccEdges v

    member _.GetRoots() = g.GetRoots()

    member _.Reverse vs = g.Reverse vs

    member _.FoldVertex(fn, acc) = g.FoldVertex(fn, acc)

    member _.IterVertex fn = g.IterVertex fn

    member _.FoldEdge(fn, acc) = g.FoldEdge(fn, acc)

    member _.IterEdge fn = g.IterEdge fn

    member _.AddVertex(data: 'V) = g.AddVertex data |> addVertex

    member _.AddVertex(data: 'V, vid: VertexID) =
      g.AddVertex(data, vid) |> addVertex

    member _.AddVertex() = g.AddVertex() |> addVertex

    member _.AddVertexCopy v = g.AddVertexCopy v |> addVertex

    member _.RemoveVertex v = g.RemoveVertex v |> update

    member _.AddEdge(src, dst) = g.AddEdge(src, dst) |> update

    member _.AddEdge(src, dst, label) = g.AddEdge(src, dst, label) |> update

    member _.RemoveEdge(src, dst) = g.RemoveEdge(src, dst) |> update

    member _.RemoveEdge(edge: Edge<'V, 'E>) = g.RemoveEdge edge |> update

    member _.AddRoot v = g.AddRoot v |> update

    member _.SetRoots vs = g.SetRoots vs |> update

    member _.Clone() = MutablePersistentDiGraph g
