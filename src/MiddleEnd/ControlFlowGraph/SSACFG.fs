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

open B2R2.BinIR.SSA
open B2R2.MiddleEnd.BinGraph

/// SSA-based CFG, where each node contains SSA-based basic blocks. This is a
/// wrapper class of `IGraph<SSABasicBlock, CFGEdgeKind>`, which provides a
/// uniform interface for both imperative and persistent graphs.
type SSACFG private (g: IGraph<SSABasicBlock, CFGEdgeKind>) =
  let mutable g = g

  let addVertex (v, g') = g <- g'; v

  let update g' = g <- g'

  /// Create a new CFG with the given implementation type.
  new (t: ImplementationType) =
    let g =
      match t with
      | Imperative ->
        ImperativeDiGraph<SSABasicBlock, CFGEdgeKind> () :> IGraph<_, _>
      | Persistent ->
        PersistentDiGraph<SSABasicBlock, CFGEdgeKind> () :> IGraph<_, _>
    SSACFG g

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

  /// Get exactly one root vertex of this CFG. If there are multiple root
  /// vertices, this will raise an exception.
  member _.SingleRoot with get() = g.SingleRoot

  /// Get the root vertices of this CFG.
  member _.Roots with get() = g.GetRoots ()

  /// Get the implementation type of this CFG.
  member _.ImplementationType with get() = g.ImplementationType

  /// Is this empty? A CFG is empty when there is no vertex.
  member _.IsEmpty () = g.IsEmpty ()

  /// Add a vertex to the graph using a data value, and return the added vertex.
  member _.AddVertex data = g.AddVertex data |> addVertex

  /// Add a vertex to this CFG using a data value and a vertex ID, and return
  /// the added vertex. This function assumes that the vertex ID is unique in
  /// the graph, thus it needs to be used with caution.
  member _.AddVertex (data, vid) = g.AddVertex (data, vid) |> addVertex

  /// Add a dummy vertex to this CFG without any data attached to it.
  member _.AddVertex () = g.AddVertex () |> addVertex

  /// Remove the given vertex from this CFG.
  member _.RemoveVertex v = g.RemoveVertex v |> update

  /// Check the existence of the given vertex from this CFG.
  member _.HasVertex vid = g.HasVertex vid

  /// Find a vertex by its VertexID. This function raises an exception when
  /// there is no such a vertex.
  member _.FindVertexByID vid = g.FindVertexByID vid

  /// Find a vertex by its VertexID. This function returns an Option type.
  /// If there is no such a vertex, it returns None.
  member _.TryFindVertexByID vid = g.TryFindVertexByID vid

  /// Find a vertex that has the given data value from this CFG.
  member _.FindVertexByData vdata = g.FindVertexByData vdata

  /// Find a vertex that has the given VertexData from this CFG. This function
  /// returns an Option type. If there is no such a vertex, it returns None.
  member _.TryFindVertexByData vdata = g.TryFindVertexByData vdata

  /// Find a vertex that satisfies the given predicate function.
  member _.FindVertexBy fn = g.FindVertexBy fn

  /// Find a vertex that satisfies the given predicate function. This function
  /// returns an Option type. If there is no such a vertex, it returns None.
  member _.TryFindVertexBy fn = g.TryFindVertexBy fn

  /// Add an edge between the given source and destination vertices.
  member _.AddEdge (src, dst) = g.AddEdge (src, dst) |> update

  /// Add an edge between the given source and destination vertices with a
  /// label.
  member _.AddEdge (src, dst, label) = g.AddEdge (src, dst, label) |> update

  /// Remove an edge between the given source and destination vertices.
  member _.RemoveEdge (src, dst) = g.RemoveEdge (src, dst) |> update

  /// Remove an edge from this CFG.
  member _.RemoveEdge edge = g.RemoveEdge edge |> update

  /// Find an edge between the given source and destination vertices.
  member _.FindEdge (src, dst) = g.FindEdge (src, dst)

  /// Find an edge between the given source and destination vertices. This
  /// function returns an Option type. If there is no such an edge, it returns
  /// None.
  member _.TryFindEdge (src, dst) = g.TryFindEdge (src, dst)

  /// Get the predecessors of the given vertex.
  member _.GetPreds v = g.GetPreds v

  /// Get the predecessor edges of the given vertex.
  member _.GetPredEdges v = g.GetPredEdges v

  /// Get the successors of the given vertex.
  member _.GetSuccs v = g.GetSuccs v

  /// Get the successor edges of the given vertex.
  member _.GetSuccEdges v = g.GetSuccEdges v

  /// Add a root vertex to this CFG.
  member _.AddRoot v = g.AddRoot v |> update

  /// Set the root vertex of this CFG.
  member _.SetRoot v = g.SetRoot v |> update

  /// Fold the vertices of this CFG with the given function and an accumulator.
  member _.FoldVertex fn acc = g.FoldVertex fn acc

  /// Iterate over the vertices of this CFG with the given function.
  member _.IterVertex fn = g.IterVertex fn

  /// Fold the edges of this CFG with the given function and an accumulator.
  member _.FoldEdge fn acc = g.FoldEdge fn acc

  /// Iterate over the edges of this CFG with the given function.
  member _.IterEdge fn = g.IterEdge fn

  /// Get a subgraph of this CFG that contains only the given vertices.
  member _.SubGraph vs = g.SubGraph vs |> SSACFG

  /// Reverse the direction of the edges in this CFG.
  member _.Reverse () = g.Reverse () |> SSACFG

  /// Clone this CFG.
  member _.Clone () = g.Clone () |> SSACFG

  /// Convert this CFG to a DOT string.
  member _.ToDOTStr (name, vFn, eFn) = g.ToDOTStr (name, vFn, eFn)

  /// Find the definition of the given variable kind (targetVarKind) at the
  /// given node v. We simply follow the dominator tree of the given SSACFG
  /// until we find a definition.
  member __.FindDef (v: IVertex<SSABasicBlock>) targetVarKind =
    let stmtInfo =
      v.VData.Internals.Statements
      |> Array.tryFindBack (fun (_, stmt) ->
        match stmt with
        | Def ({ Kind = k }, _) when k = targetVarKind -> true
        | _ -> false)
    match stmtInfo with
    | Some stmtInfo -> Some (snd stmtInfo)
    | None ->
      match v.VData.ImmDominator with
      | Some idom ->
        __.FindDef idom targetVarKind
      | None -> None

  /// Find the reaching definition of the given variable kind (targetVarKind) at
  /// the entry of node v. We simply follow the dominator tree of the given
  /// SSACFG until we find a definition.
  member __.FindReachingDef (v: IVertex<SSABasicBlock>) targetVarKind =
    match v.VData.ImmDominator with
    | Some idom ->
      __.FindDef idom targetVarKind
    | None -> None

  interface IGraph<SSABasicBlock, CFGEdgeKind> with
    member _.IsEmpty () = g.IsEmpty ()
    member _.Size = g.Size
    member _.Vertices = g.Vertices
    member _.Edges = g.Edges
    member _.Unreachables = g.Unreachables
    member _.Exits = g.Exits
    member _.SingleRoot = g.SingleRoot
    member _.ImplementationType = g.ImplementationType
    member _.AddVertex data = g.AddVertex data
    member _.AddVertex (data, vid) = g.AddVertex (data, vid)
    member _.AddVertex () = g.AddVertex ()
    member _.RemoveVertex v = g.RemoveVertex v
    member _.HasVertex vid = g.HasVertex vid
    member _.FindVertexByID vid = g.FindVertexByID vid
    member _.TryFindVertexByID vid = g.TryFindVertexByID vid
    member _.FindVertexByData vdata = g.FindVertexByData vdata
    member _.TryFindVertexByData vdata = g.TryFindVertexByData vdata
    member _.FindVertexBy fn = g.FindVertexBy fn
    member _.TryFindVertexBy fn = g.TryFindVertexBy fn
    member _.AddEdge (src, dst) = g.AddEdge (src, dst)
    member _.AddEdge (src, dst, label) = g.AddEdge (src, dst, label)
    member _.RemoveEdge (src, dst) = g.RemoveEdge (src, dst)
    member _.RemoveEdge edge = g.RemoveEdge edge
    member _.FindEdge (src, dst) = g.FindEdge (src, dst)
    member _.TryFindEdge (src, dst) = g.TryFindEdge (src, dst)
    member _.GetPreds v = g.GetPreds v
    member _.GetPredEdges v = g.GetPredEdges v
    member _.GetSuccs v = g.GetSuccs v
    member _.GetSuccEdges v = g.GetSuccEdges v
    member _.GetRoots () = g.GetRoots ()
    member _.AddRoot v = g.AddRoot v
    member _.SetRoot v = g.SetRoot v
    member _.FoldVertex fn acc = g.FoldVertex fn acc
    member _.IterVertex fn = g.IterVertex fn
    member _.FoldEdge fn acc = g.FoldEdge fn acc
    member _.IterEdge fn = g.IterEdge fn
    member _.SubGraph vs = g.SubGraph vs
    member _.Reverse () = g.Reverse ()
    member _.Clone () = g.Clone ()
    member _.ToDOTStr (name, vFn, eFn) = g.ToDOTStr (name, vFn, eFn)
