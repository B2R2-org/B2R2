(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>
          Soomin Kim <soomink@kaist.ac.kr>

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

module B2R2.BinGraph.Dominator

open System.Collections.Generic

type DomInfo<'V when 'V :> VertexData> = {
  /// Vertex ID -> DFNum
  DFNumMap      : Dictionary<VertexID, int>
  /// DFNum -> Vertex
  Vertex        : Vertex<'V> []
  /// DFNum -> DFNum in the ancestor chain s.t. DFNum of its Semi is minimal.
  Label         : int []
  /// DFNum -> DFNum of the parent node (zero if not exists).
  Parent        : int []
  /// DFNum -> DFNum of the child node (zero if not exists).
  Child         : int []
  /// DFNum -> DFNum of an ancestor.
  Ancestor      : int []
  /// DFNum -> DFNum of a semidominator.
  Semi          : int []
  /// DFNum -> set of DFNums (vertices that share the same sdom).
  Bucket        : Set<int> []
  /// DFNum -> Size
  Size          : int []
  /// DFNum -> DFNum of an immediate dominator.
  IDom          : int []
  /// Length of the arrays.
  MaxLength     : int
}

type DominatorContext<'V, 'E when 'V :> VertexData> = {
  ForwardGraph: DiGraph<'V, 'E>
  ForwardRoot: Vertex<'V>
  ForwardDomInfo: DomInfo<'V>
  BackwardGraph: DiGraph<'V, 'E>
  BackwardRoot: Vertex<'V>
  BackwardDomInfo: DomInfo<'V>
}

/// Initialize dominator context for a given graph (g) and the root node of g.
val initDominatorContext:
  DiGraph<'V, 'E> -> Vertex<'V> -> DominatorContext<'V, 'E>

/// Return immediate dominator of the given node (v) in the graph (g).
val idom:
  DominatorContext<'V, 'E> -> Vertex<'V> -> Vertex<'V> option

/// Return immediate post-dominator of the given node (v) in the graph (g).
val ipdom:
  DominatorContext<'V, 'E> -> Vertex<'V> -> Vertex<'V> option

/// Return a list of dominators of the given node (v) in the graph (g).
val doms:
  DominatorContext<'V, 'E> -> Vertex<'V> -> Vertex<'V> list

/// Return a list of post-dominators of the given node (v) in the graph (g).
val pdoms:
  DominatorContext<'V, 'E> -> Vertex<'V> -> Vertex<'V> list

/// Return the dominance frontier of a given node (v) in the graph (g).
val frontier:
  DominatorContext<'V, 'E> -> Vertex<'V> -> Vertex<'V> list

/// Return the dominator tree and its root of the graph
val dominatorTree:
  DominatorContext<'V, 'E> -> Map<Vertex<'V>, Vertex<'V> list> * Vertex<'V>
