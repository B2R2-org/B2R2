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

/// Composes the dominance of a graph with the dominance of its transpose, the
/// latter answering every post-dominance query. A transpose holds the very
/// vertices of the graph it was taken from, so nothing has to be carried from
/// the one graph over to the other on the way through here.
let combineDominance fw (bw: Lazy<IForwardDominance<'V>>) =
  { new IDominance<'V> with
      member _.Dominators v = (fw: IForwardDominance<'V>).Dominators v
      member _.ImmediateDominator v = fw.ImmediateDominator v
      member _.DominatorTree = fw.DominatorTree
      member _.DominanceFrontier v = fw.DominanceFrontier v
      member _.PostDominators v = bw.Value.Dominators v
      member _.ImmediatePostDominator v = bw.Value.ImmediateDominator v
      member _.PostDominatorTree = bw.Value.DominatorTree
      member _.PostDominanceFrontier v = bw.Value.DominanceFrontier v }
