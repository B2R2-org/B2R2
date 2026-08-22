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

[<AutoOpen>]
module internal B2R2.MiddleEnd.BinGraph.Dominance.DominanceHelper

open B2R2.MiddleEnd.BinGraph

/// Finds the vertex of the given graph that carries the ID of the given one.
/// A vertex is the object it is, so a graph and the transpose built from it
/// share none of their vertices, only the names; a vertex crosses from the one
/// graph to the other by being looked up under the name they agree on.
let crossTo g (v: IVertex<'V>) =
  (g: IDiGraph<_, _>).FindVertexByID v.ID

let private crossToOrNull g (v: IVertex<'V> | null): IVertex<'V> | null =
  match v with
  | null -> null
  | v -> crossTo g v

/// Composes the dominance of a graph with the dominance of its transposed
/// graph, the latter answering every post-dominance query. Every vertex such a
/// query takes or hands back crosses the boundary between the two graphs, the
/// post-dominator tree included, which is why the tree is grown anew over the
/// vertices the caller knows rather than handed over as the transpose has it.
let combineDominance g bwG fw (bw: Lazy<IForwardDominance<'V>>) =
  let toBw v = crossTo (bwG: Lazy<IDiGraph<'V, _>>).Value v
  let ipdom v = bw.Value.ImmediateDominator(toBw v) |> crossToOrNull g
  let pdt = lazy DominatorTree((g: IDiGraph<'V, _>).Vertices, ipdom)
  { new IDominance<'V> with
      member _.Dominators v = (fw: IForwardDominance<'V>).Dominators v
      member _.ImmediateDominator v = fw.ImmediateDominator v
      member _.DominatorTree = fw.DominatorTree
      member _.DominanceFrontier v = fw.DominanceFrontier v
      member _.PostDominators v =
        bw.Value.Dominators(toBw v) |> Seq.map (crossTo g)
      member _.ImmediatePostDominator v = ipdom v
      member _.PostDominatorTree = pdt.Value
      member _.PostDominanceFrontier v =
        bw.Value.DominanceFrontier(toBw v) |> Seq.map (crossTo g) }
