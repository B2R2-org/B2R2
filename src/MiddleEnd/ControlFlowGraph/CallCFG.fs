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

namespace B2R2.MiddleEnd.ControlFlowGraph

open B2R2.MiddleEnd.BinGraph

/// Call graph, where each node represents a function. This is essentially a
/// wrapper class of `IGraph<CallBasicBlock, CFGEdgeKind>`, which provides a
/// uniform interface for both imperative and persistent graphs.
type CallCFG (t: ImplementationType) =
  let g =
    match t with
    | Imperative ->
      ImperativeDiGraph<CallBasicBlock, CFGEdgeKind> () :> IGraph<_, _>
    | Persistent ->
      PersistentDiGraph<CallBasicBlock, CFGEdgeKind> () :> IGraph<_, _>

  /// Number of vertices.
  member _.Size with get() = g.Size

  /// Get an array of all vertices in this CFG.
  member _.Vertices with get() = g.Vertices

  /// Get an array of all edges in this CFG.
  member _.Edges with get() = g.Edges

  /// Get an array of unreachable vertices in this CFG.
  member _.Unreachables with get() = g.Unreachables

  /// Get an array of exit vertices in this CFG.
  member _.Exits with get() = g.Exits

  /// Get the root vertices of this CFG.
  member _.Roots with get() = g.GetRoots ()

  /// Get the implementation type of this CFG.
  member _.ImplementationType with get() = g.ImplementationType

  /// Is this empty? A CFG is empty when there is no vertex.
  member _.IsEmpty () = g.IsEmpty ()

  /// Fold the vertices of this CFG with the given function and accumulator.
  member _.FoldVertex fn acc = g.FoldVertex fn acc

  /// Iterate over the vertices of this CFG with the given function.
  member _.IterVertex fn = g.IterVertex fn

  /// Fold the edges of this CFG with the given function and accumulator.
  member _.FoldEdge fn acc = g.FoldEdge fn acc

  /// Iterate over the edges of this CFG with the given function.
  member _.IterEdge fn = g.IterEdge fn

  interface IReadOnlyGraph<CallBasicBlock, CFGEdgeKind> with
    member _.Size = g.Size
    member _.Vertices = g.Vertices
    member _.Edges = g.Edges
    member _.Unreachables = g.Unreachables
    member _.Exits = g.Exits
    member _.SingleRoot = g.SingleRoot
    member _.ImplementationType = g.ImplementationType
    member _.IsEmpty () = g.IsEmpty ()
    member _.HasVertex vid = g.HasVertex vid
    member _.FindVertexByID vid = g.FindVertexByID vid
    member _.TryFindVertexByID vid = g.TryFindVertexByID vid
    member _.FindVertexByData vdata = g.FindVertexByData vdata
    member _.TryFindVertexByData vdata = g.TryFindVertexByData vdata
    member _.FindVertexBy fn = g.FindVertexBy fn
    member _.TryFindVertexBy fn = g.TryFindVertexBy fn
    member _.FindEdge (src, dst) = g.FindEdge (src, dst)
    member _.TryFindEdge (src, dst) = g.TryFindEdge (src, dst)
    member _.GetPreds v = g.GetPreds v
    member _.GetPredEdges v = g.GetPredEdges v
    member _.GetSuccs v = g.GetSuccs v
    member _.GetSuccEdges v = g.GetSuccEdges v
    member _.GetRoots () = g.GetRoots ()
    member _.FoldVertex fn acc = g.FoldVertex fn acc
    member _.IterVertex fn = g.IterVertex fn
    member _.FoldEdge fn acc = g.FoldEdge fn acc
    member _.IterEdge fn = g.IterEdge fn
    member _.Reverse vs = g.Reverse vs
    member _.Clone () = g.Clone ()
    member _.ToDOTStr (name, vFn, eFn) = g.ToDOTStr (name, vFn, eFn)

  interface IGraph<CallBasicBlock, CFGEdgeKind> with
    member _.AddVertex data = g.AddVertex data
    member _.AddVertex (data, vid) = g.AddVertex (data, vid)
    member _.AddVertex () = g.AddVertex ()
    member _.RemoveVertex v = g.RemoveVertex v
    member _.AddEdge (src, dst) = g.AddEdge (src, dst)
    member _.AddEdge (src, dst, label) = g.AddEdge (src, dst, label)
    member _.RemoveEdge (src, dst) = g.RemoveEdge (src, dst)
    member _.RemoveEdge edge = g.RemoveEdge edge
    member _.AddRoot v = g.AddRoot v
    member _.SetRoots vs = g.SetRoots vs
    member _.Reverse vs = g.Reverse vs
    member _.Clone () = g.Clone ()
