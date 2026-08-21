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

/// Represents an interface for computing dominance relationships of nodes in
/// digraphs, in both directions.
type IDominance<'V when 'V: equality> =
  inherit IForwardDominance<'V>
  inherit IPostDominance<'V>

/// Represents an interface for computing the dominance relationships that read
/// the edges of a digraph in their own direction. Ask for this rather than for
/// IDominance wherever post-dominance is of no interest, so that the signature
/// says as much.
and IForwardDominance<'V when 'V: equality> =
  /// Gets the dominators of the given vertex.
  abstract Dominators: IVertex<'V> -> IEnumerable<IVertex<'V>>

  /// Gets the immediate dominator of the given vertex, or null if it does not
  /// exist.
  abstract ImmediateDominator: IVertex<'V> -> IVertex<'V> | null

  /// Gets the dominator tree.
  abstract DominatorTree: DominatorTree<'V>

  /// Gets the dominance frontier of the given vertex.
  abstract DominanceFrontier: IVertex<'V> -> IEnumerable<IVertex<'V>>

/// Represents an interface for computing the dominance relationships that read
/// the edges of a digraph backwards. Every one of these costs a transposed
/// graph, which an implementation is free to build only when first asked.
and IPostDominance<'V when 'V: equality> =
  /// Gets the post-dominators of the given vertex.
  abstract PostDominators: IVertex<'V> -> IEnumerable<IVertex<'V>>

  /// Gets the immediate post-dominator of the given vertex, or null if it does
  /// not exist.
  abstract ImmediatePostDominator: IVertex<'V> -> IVertex<'V> | null

  /// Gets the post-dominator tree.
  abstract PostDominatorTree: DominatorTree<'V>

  /// Gets the post-dominance frontier of the given vertex.
  abstract PostDominanceFrontier: IVertex<'V> -> IEnumerable<IVertex<'V>>

/// Represents an interface for computing dominance frontier of nodes in
/// digraphs.
and IDominanceFrontier<'V when 'V: equality> =
  /// Gets the dominance frontier of a vertex, which is the set of all vertices
  /// that are not strictly dominated by the vertex but are reachable from the
  /// vertex.
  abstract DominanceFrontier: IVertex<'V> -> IEnumerable<IVertex<'V>>

/// Represents an interface for providing dominance frontier instances.
and IDominanceFrontierProvider<'V, 'E when 'V: equality and 'E: equality> =
  /// Returns an IDominanceFrontier instance for the given graph, reading the
  /// dominance of that same graph from the given IForwardDominance. Ask for the
  /// post-dominance frontiers of a graph by passing the transposed graph along
  /// with the dominance of the transposed graph.
  abstract CreateIDominanceFrontier:
      g: IDiGraphAccessible<'V, 'E>
    * dom: IForwardDominance<'V>
   -> IDominanceFrontier<'V>

/// Represents a dominator tree, in which the children of a node are the nodes
/// it immediately dominates. A graph with more than one root, or with a vertex
/// no root reaches, has more than one node that nothing dominates, so this is a
/// forest, and `GetRoots` returns the nodes it grows from.
and DominatorTree<'V when 'V: equality>
  public(vertices: IEnumerable<IVertex<'V>>,
         getIDom: IVertex<'V> -> IVertex<'V> | null) =

  let domTree = Dictionary<IVertex<'V>, List<IVertex<'V>>>()
  let roots = List<IVertex<'V>>()

  do
    for v in vertices do
      let idom = getIDom v
      if isNull idom then roots.Add v
      elif domTree.ContainsKey idom then domTree[idom].Add v
      else domTree[idom] <- List [ v ]

  /// Gets the vertices that nothing dominates, i.e., the roots of this forest.
  member _.GetRoots() = roots

  /// Gets the children of a vertex in the dominator tree.
  member _.GetChildren(v: IVertex<'V>) =
    match domTree.TryGetValue v with
    | true, children -> children
    | false, _ -> List()
