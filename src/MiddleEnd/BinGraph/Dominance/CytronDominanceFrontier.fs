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

namespace B2R2.MiddleEnd.BinGraph.Dominance

open System.Collections.Generic
open B2R2.MiddleEnd.BinGraph

/// Dominance frontier algorithm presented by Cytron et al. in their paper
/// "Efficiently Computing Static Single Assignment Form and the Control
/// Dependence Graph", TOPLAS 1991.
type CytronDominanceFrontier<'V, 'E when 'V: equality and 'E: equality> () =
  let traverseBottomUp (domTree: DominatorTree<_, _>) root =
    let stack1, stack2 = Stack (), Stack ()
    stack1.Push root
    while stack1.Count > 0 do
      let v = stack1.Pop ()
      stack2.Push v
      for child in domTree.GetChildren v do stack1.Push child
    stack2

  /// Compute dominance frontiers.
  let computeDF (g: IDiGraphAccessible<_, _>) (dom: IForwardDominance<_, _>) =
    let frontiers = Dictionary<IVertex<_>, HashSet<IVertex<_>>> ()
    for v in traverseBottomUp dom.DominatorTree g.SingleRoot do
      let df = HashSet<IVertex<_>> ()
      for succ in g.GetSuccs v do
        if dom.ImmediateDominator succ <> v then df.Add succ |> ignore
        else ()
      done
      for child in dom.DominatorTree.GetChildren v do
        for node in frontiers[child] do
          if dom.ImmediateDominator node <> v then df.Add node |> ignore
          else ()
        done
      done
      frontiers[v] <- df
    frontiers

  interface IDominanceFrontierProvider<'V, 'E> with
    member _.CreateIDominanceFrontier (g, dom) =
      let frontiers = computeDF g dom
      { new IDominanceFrontier<'V, 'E> with
          member _.DominanceFrontier (v) = frontiers[v] }
