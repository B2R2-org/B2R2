(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>

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

/// Return immediate dominator of the given node (v) in the graph (g).
val idom : DiGraph<'V, 'E> -> Vertex<'V> -> Vertex<'V> option

/// Return immediate post-dominator of the given node (v) in the graph (g).
val ipdom : DiGraph<'V, 'E> -> Vertex<'V> -> Vertex<'V> option

/// Return a list of dominators of the given node (v) in the graph (g).
val doms : DiGraph<'V, 'E> -> Vertex<'V> -> Vertex<'V> list

/// Return a list of post-dominators of the given node (v) in the graph (g).
val pdoms : DiGraph<'V, 'E> -> Vertex<'V> -> Vertex<'V> list

/// Return the dominance frontier of a given node (v) in the graph (g).
val frontier : DiGraph<'V, 'E> -> Vertex<'V> -> Vertex<'V> list
