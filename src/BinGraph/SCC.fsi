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

module B2R2.BinGraph.SCC

/// SCC = a strongly connected component.
type SCC<'V when 'V :> VertexData> = Set<Vertex<'V>>

type CondensationBlock<'V when 'V :> VertexData> =
  inherit VertexData
  new: SCC<'V> -> CondensationBlock<'V>

  member SCC: SCC<'V>

/// Condensation graph is a directed acyclic graph(DAG), each of its vertex is
/// corresponding to original graph's SCC.
type CondensationGraph<'V when 'V :> VertexData> =
  SimpleDiGraph<CondensationBlock<'V>, unit>

/// Compute a set of strongly connected components from a given digraph. We use
/// Tarjan's algorithm.
val compute: DiGraph<'V, 'E> -> Vertex<'V> -> Set<SCC<'V>> when 'V :> VertexData

val condensation: DiGraph<'V, 'E> -> Vertex<'V> -> CondensationGraph<'V>
