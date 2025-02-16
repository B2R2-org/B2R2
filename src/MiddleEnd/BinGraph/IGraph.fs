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

/// General graph data type. This one can be either directed or undirected.
[<AllowNullLiteral>]
type IGraph<'V, 'E when 'V: equality and 'E: equality> =
  inherit IReadOnlyGraph<'V, 'E>

  /// Add a vertex to the graph using a data value, and return a reference to
  /// the added vertex.
  abstract AddVertex: data: 'V -> IVertex<'V> * IGraph<'V, 'E>

  /// Add a vertex to the graph using a data value and a vertex ID, and return a
  /// reference to the added vertex. This function assumes that the vertex ID is
  /// unique in the graph, thus it needs to be used with caution.
  abstract AddVertex: data: 'V * vid: VertexID -> IVertex<'V> * IGraph<'V, 'E>

  /// Add a vertex to the grpah without any data attached to it.
  abstract AddVertex: unit -> IVertex<'V> * IGraph<'V, 'E>

  /// Remove the given vertex from the graph.
  abstract RemoveVertex: IVertex<'V> -> IGraph<'V, 'E>

  /// Add an edge between src and dst. If this is a directed graph, add an edge
  /// from src to dst.
  abstract AddEdge: src: IVertex<'V> * dst: IVertex<'V> -> IGraph<'V, 'E>

  /// Add an edge from src to dst with the given label. If this is a directed
  /// graph, add an edge from src to dst.
  abstract AddEdge:
    src: IVertex<'V> * dst: IVertex<'V> * label: 'E -> IGraph<'V, 'E>

  /// Remove the edge that spans between src and dst. If this is a directed
  /// graph, remove the edge from src to dst.
  abstract RemoveEdge: src: IVertex<'V> * dst: IVertex<'V> -> IGraph<'V, 'E>

  /// Remove the given edge from the graph. The input edge does not need to have
  /// the same label as the one in the graph; we only check the source and
  /// destination vertices to perform this operation.
  abstract RemoveEdge: edge: Edge<'V, 'E> -> IGraph<'V, 'E>

  /// Explicitly add a root vertex to this graph. `AddVertex` will automatically
  /// set the root vertex to the first vertex added to the graph, but this
  /// function allows the user to add root vertices explicitly.
  abstract AddRoot: IVertex<'V> -> IGraph<'V, 'E>

  /// Set root vertices for this graph. `AddVertex` will automatically set the
  /// root vertex to the first vertex added to the graph, but this function
  /// allows the user to set root vertices explicitly.
  abstract SetRoots: IEnumerable<IVertex<'V>> -> IGraph<'V, 'E>

  /// Return a new transposed (i.e., reversed) graph. For directed graphs, the
  /// given set of vertices will be used to set the root vertices of the
  /// transposed graph. For undirected graphs, the parameter is ignored and this
  /// function will return the same graph as the input graph.
  abstract Reverse: IEnumerable<IVertex<'V>> -> IGraph<'V, 'E>

  /// Return a cloned copy of this graph.
  abstract Clone: unit -> IGraph<'V, 'E>

/// Module for IGraph<'V, 'E> type to provide utility functions.
module IGraph =
  /// Compute a subgraph of the given graph (inGraph) using only the vertices
  /// in the given set (vs). The resulting graph will have the same structure
  /// as the original graph, but only the vertices in the set and the edges
  /// between them will be included. This function assumes that the (outGraph)
  /// is an empty graph. Otherwise, the behavior is undefined.
  let subGraph inGraph outGraph (vs: HashSet<IVertex<'V>>) =
    (* Add vertices *)
    vs
    |> Seq.fold (fun (g: IGraph<'V, 'E>) (v: IVertex<'V>) ->
      g.AddVertex v.VData |> snd) outGraph
    |>
    (* Add edges where both ends are in vs *)
    (inGraph :> IGraph<_, _>).FoldEdge (fun (g: IGraph<'V, 'E>) e ->
      if vs.Contains e.First && vs.Contains e.Second then
        let src = g.FindVertexByID <| e.First.ID
        let dst = g.FindVertexByID <| e.Second.ID
        (g :> IGraph<'V, _>).AddEdge (src, dst, e.Label)
      else g)
