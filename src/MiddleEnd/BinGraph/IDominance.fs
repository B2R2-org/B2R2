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

/// Interface for computing forward and backward dominance relationships of
/// nodes in digraphs.
type IDominance<'V, 'E when 'V: equality and 'E: equality> =
  abstract member Dominators : IVertex<'V> -> IEnumerable<IVertex<'V>>
  abstract member ImmediateDominator : IVertex<'V> -> IVertex<'V>
  abstract member DominatorTree : DominatorTree<'V, 'E>
  abstract member DominanceFrontier : IVertex<'V> -> IEnumerable<IVertex<'V>>
  abstract member PostDominators: IVertex<'V> -> IEnumerable<IVertex<'V>>
  abstract member ImmediatePostDominator: IVertex<'V> -> IVertex<'V>
  abstract member PostDominatorTree: DominatorTree<'V, 'E>
  abstract member PostDominanceFrontier: IVertex<'V> -> IEnumerable<IVertex<'V>>

/// Interface for computing dominance relationships of nodes in digraphs.
and IForwardDominance<'V, 'E when 'V: equality and 'E: equality> =
  inherit IDominanceFrontier<'V, 'E>

  // Get the dominators of a vertex.
  abstract member Dominators: IVertex<'V> -> IEnumerable<IVertex<'V>>

  /// Get the immediate dominator of a vertex, which is the vertex that strictly
  /// dominates the vertex and is closest to the vertex. If the vertex is a root
  /// vertex, then the immediate dominator is `null`.
  abstract member ImmediateDominator: IVertex<'V> -> IVertex<'V>

  /// Get the dominator tree of the given implementation type.
  abstract member DominatorTree: DominatorTree<'V, 'E>

/// Interface for computing dominance frontier of nodes in digraphs.
and IDominanceFrontier<'V, 'E when 'V: equality and 'E: equality> =
  /// Get the dominance frontier of a vertex, which is the set of all vertices
  /// that are not strictly dominated by the vertex but are reachable from the
  /// vertex.
  abstract DominanceFrontier: IVertex<'V> -> IEnumerable<IVertex<'V>>

/// Interface for providing dominance frontier instances.
and IDominanceFrontierProvider<'V, 'E when 'V: equality and 'E: equality> =
  /// Return IDominanceFrontier instance using the given graph and the
  /// IDominance instance.
  abstract CreateIDominanceFrontier:
      IDiGraphAccessible<'V, 'E>
    * IForwardDominance<'V, 'E>
   -> IDominanceFrontier<'V, 'E>

/// Dominator tree interface. A dominator tree is a tree where each node's
/// children are those nodes it immediately dominates.
and DominatorTree<'V, 'E when 'V: equality
                          and 'E: equality>
  public (g: IDiGraphAccessible<'V, 'E>, getIDom: IVertex<'V> -> IVertex<'V>) =

  let domTree = Dictionary<IVertex<'V>, List<IVertex<'V>>> ()

  do g.IterVertex (fun v ->
       let idom = getIDom v
       if isNull idom then ()
       elif domTree.ContainsKey idom then domTree[idom].Add v
       else domTree[idom] <- List [ v ])

  /// Get the children of a vertex in the dominator tree.
  member _.GetChildren (v: IVertex<'V>) =
    match domTree.TryGetValue v with
    | true, children -> children
    | false, _ -> List ()
