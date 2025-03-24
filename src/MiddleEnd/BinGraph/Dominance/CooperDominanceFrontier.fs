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

/// Dominance frontier algorithm presented by Cooper et al. in their paper
/// "A Simple, Fast Dominance Algorithm", SPE 2001.
type CooperDominanceFrontier<'V, 'E when 'V: equality and 'E: equality> () =
  let computeDF (g: IDiGraphAccessible<_, _>) (dom: IForwardDominance<_, _>) =
    let frontiers = Dictionary<IVertex<_>, HashSet<IVertex<_>>> ()
    let root = g.SingleRoot
    for v in g.Vertices do frontiers[v] <- HashSet<IVertex<_>> ()
    for v in g.Vertices do
      let preds = g.GetPreds v
      if (v <> root && preds.Length < 2) ||
         (v = root && preds.Length = 0) then ()
      else
        for p in preds do
          let mutable runner = p
          while runner <> dom.ImmediateDominator v do
            frontiers[runner].Add v |> ignore
            runner <- dom.ImmediateDominator runner
    frontiers

  interface IDominanceFrontierProvider<'V, 'E> with
    member _.CreateIDominanceFrontier (g, dom) =
      let frontiers = computeDF g dom
      { new IDominanceFrontier<'V, 'E> with
          member _.DominanceFrontier (v) = frontiers[v] }
