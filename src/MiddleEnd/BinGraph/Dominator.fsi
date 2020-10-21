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

module B2R2.MiddleEnd.BinGraph.Dominator

open System.Collections.Generic

type DomInfo<'D when 'D :> VertexData> = {
  /// Vertex ID -> DFNum
  DFNumMap: Dictionary<VertexID, int>
  /// DFNum -> Vertex
  Vertex: Vertex<'D> []
  /// DFNum -> DFNum in the ancestor chain s.t. DFNum of its Semi is minimal.
  Label: int []
  /// DFNum -> DFNum of the parent node (zero if not exists).
  Parent: int []
  /// DFNum -> DFNum of the child node (zero if not exists).
  Child: int []
  /// DFNum -> DFNum of an ancestor.
  Ancestor: int []
  /// DFNum -> DFNum of a semidominator.
  Semi: int []
  /// DFNum -> set of DFNums (vertices that share the same sdom).
  Bucket: Set<int> []
  /// DFNum -> Size
  Size: int []
  /// DFNum -> DFNum of an immediate dominator.
  IDom: int []
  /// Length of the arrays.
  MaxLength: int
}

/// Storing DomInfo of a graph. We use this to repeatedly compute doms/pdoms of
/// the same graph.
type DominatorContext<'D, 'E when 'D :> VertexData and 'D : equality> = {
  ForwardGraph: DiGraph<'D, 'E>
  ForwardRoot: Vertex<'D>
  ForwardDomInfo: DomInfo<'D>
  BackwardGraph: DiGraph<'D, 'E>
  BackwardRoot: Vertex<'D>
  BackwardDomInfo: DomInfo<'D>
}

val initDominatorContext:
  DiGraph<'D, 'E> -> Vertex<'D> -> DominatorContext<'D, 'E>

val idom: DominatorContext<'D, 'E> -> Vertex<'D> -> Vertex<'D> option

val ipdom: DominatorContext<'D, 'E> -> Vertex<'D> -> Vertex<'D> option

val doms: DominatorContext<'D, 'E> -> Vertex<'D> -> Vertex<'D> list

val pdoms: DominatorContext<'D, 'E> -> Vertex<'D> -> Vertex<'D> list

val frontier: DominatorContext<'D, 'E> -> Vertex<'D> -> Vertex<'D> list

val frontiers: DominatorContext<'D, 'E> -> Vertex<'D> list []

val dominatorTree:
  DominatorContext<'D, 'E> -> Map<Vertex<'D>, Vertex<'D> list> * Vertex<'D>

// vim: set tw=80 sts=2 sw=2:
