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
/// digraphs.
type IDominance<'V, 'E when 'V: equality and 'E: equality> =
  /// Gets the dominators of the given vertex.
  abstract Dominators: IVertex<'V> -> IEnumerable<IVertex<'V>>

  /// Gets the immediate dominator of the given vertex, or null if it does not
  /// exist.
  abstract ImmediateDominator: IVertex<'V> -> IVertex<'V> | null

  /// Gets the dominator tree.
  abstract DominatorTree: DominatorTree<'V, 'E>

  /// Gets the dominance frontier of the given vertex.
  abstract DominanceFrontier: IVertex<'V> -> IEnumerable<IVertex<'V>>

  /// Gets the post-dominators of the given vertex.
  abstract PostDominators: IVertex<'V> -> IEnumerable<IVertex<'V>>

  /// Gets the immediate post-dominator of the given vertex, or null if it does
  /// not exist.
  abstract ImmediatePostDominator: IVertex<'V> -> IVertex<'V> | null

  /// Gets the post-dominator tree.
  abstract PostDominatorTree: DominatorTree<'V, 'E>

  /// Gets the post-dominance frontier of the given vertex.
  abstract PostDominanceFrontier: IVertex<'V> -> IEnumerable<IVertex<'V>>

/// Represents an interface for computing dominance frontier of nodes in
/// digraphs.
and IDominanceFrontier<'V, 'E when 'V: equality and 'E: equality> =
  /// Gets the dominance frontier of a vertex, which is the set of all vertices
  /// that are not strictly dominated by the vertex but are reachable from the
  /// vertex.
  abstract DominanceFrontier: IVertex<'V> -> IEnumerable<IVertex<'V>>

/// Represents an interface for providing dominance frontier instances.
and IDominanceFrontierProvider<'V, 'E when 'V: equality and 'E: equality> =
  /// Returns an IDominanceFrontier instance using the given graph and the
  /// IDominance instance. The third argument `isPostDominance` is a boolean
  /// flag indicating whether the dominance frontier is for post-dominance.
  abstract CreateIDominanceFrontier:
      g: IDiGraphAccessible<'V, 'E>
    * dom: IDominance<'V, 'E>
    * isPostDominance: bool
   -> IDominanceFrontier<'V, 'E>

/// Represents a dominator tree interface. A dominator tree is a tree where each
/// node's children are those nodes it immediately dominates.
and DominatorTree<'V, 'E when 'V: equality
                          and 'E: equality>
  public(g: IDiGraphAccessible<'V, 'E>,
         getIDom: IVertex<'V> -> IVertex<'V> | null) =

  let domTree = Dictionary<IVertex<'V>, List<IVertex<'V>>>()
  let dummyRoot = GraphUtils.makeDummyVertex ()

  do
    domTree[dummyRoot] <- List()
    g.IterVertex(fun v ->
      let idom = getIDom v
      if isNull idom then domTree[dummyRoot].Add v
      elif domTree.ContainsKey idom then domTree[idom].Add v
      else domTree[idom] <- List [ v ])

  /// Gets the dummy root. Dummy root points to all the roots of the dominator
  /// tree.
  member _.GetRoot() = dummyRoot

  /// Gets the children of a vertex in the dominator tree.
  member _.GetChildren(v: IVertex<'V>) =
    match domTree.TryGetValue v with
    | true, children -> children
    | false, _ -> List()
