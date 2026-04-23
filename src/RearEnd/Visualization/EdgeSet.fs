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

namespace B2R2.RearEnd.Visualization

open B2R2.MiddleEnd.BinGraph
open System.Collections.Generic

type VertexEdge = IVertex<VisBBlock> * VisEdge

/// Maintains the edge flow assignments for either forward or backward edges.
type EdgeSet =
  { FwdOutEdges: Dictionary<IVertex<VisBBlock>, VertexEdge list>
    FwdInEdges: Dictionary<IVertex<VisBBlock>, VertexEdge list>
    BwdInEdges: Dictionary<IVertex<VisBBlock>, VertexEdge list>
    BwdOutEdges: Dictionary<IVertex<VisBBlock>, VertexEdge list>
    SelfCycleEdge: Dictionary<IVertex<VisBBlock>, VertexEdge list> }

with
  member this.GetFwdInEdges(v: IVertex<VisBBlock>) =
    match this.FwdInEdges.TryGetValue v with
    | true, edges -> List.rev edges
    | false, _ -> []

  member this.GetFwdOutEdges(v: IVertex<VisBBlock>) =
    match this.FwdOutEdges.TryGetValue v with
    | true, edges -> List.rev edges
    | false, _ -> []

  member this.GetBwdInEdges(v: IVertex<VisBBlock>) =
    match this.BwdInEdges.TryGetValue v with
    | true, edges -> List.rev edges
    | false, _ -> []

  member this.GetBwdOutEdges(v: IVertex<VisBBlock>) =
    match this.BwdOutEdges.TryGetValue v with
    | true, edges -> List.rev edges
    | false, _ -> []

  member this.GetSelfCycleEdge(v: IVertex<VisBBlock>) =
    match this.SelfCycleEdge.TryGetValue v with
    | true, edge -> List.rev edge
    | false, _ -> []

  member this.GetInEdges(v: IVertex<VisBBlock>) =
    this.GetFwdInEdges v @ this.GetBwdInEdges v

  member this.GetOutEdges(v: IVertex<VisBBlock>) =
    this.GetFwdOutEdges v @ this.GetBwdOutEdges v

  static member Empty =
    { FwdInEdges = Dictionary()
      FwdOutEdges = Dictionary()
      BwdInEdges = Dictionary()
      BwdOutEdges = Dictionary()
      SelfCycleEdge = Dictionary() }

  static let addEdge key value (dict: Dictionary<_, _>) =
    let existingEdges =
      match dict.TryGetValue key with
      | true, edges -> edges
      | false, _ -> []
    dict[key] <- value :: existingEdges

  static member Create(edges: Edge<VisBBlock, VisEdge>[]) =
    let sets = EdgeSet.Empty
    for edge in edges do
      let src, dst, kind = edge.First, edge.Second, edge.Label
      if src <> dst then
        if kind.IsBackEdge then
          addEdge src (dst, kind) sets.BwdOutEdges
          addEdge dst (src, kind) sets.BwdInEdges
        else
          addEdge src (dst, kind) sets.FwdOutEdges
          addEdge dst (src, kind) sets.FwdInEdges
      else
        addEdge src (src, kind) sets.SelfCycleEdge
    sets

and [<RequireQualifiedAccess>] EdgeFlow =
  | Incoming
  | Outgoing