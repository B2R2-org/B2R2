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

/// <namespacedoc>
///   <summary>
///   Contains loop analyses for directed graphs. Each module here identifies
///   one kind of loop structure.
///   </summary>
/// </namespacedoc>
///
/// <summary>
/// Provides the identification of natural loops, the loops that a back edge
/// closes: an edge whose head dominates its tail, and thus the one entry point
/// that every path into the loop goes through.
/// </summary>
[<RequireQualifiedAccess>]
module B2R2.MiddleEnd.BinGraph.Loop.NaturalLoop

open System.Collections.Generic
open B2R2.MiddleEnd.BinGraph

let private findBackEdges g =
  let df = Dominance.CytronDominanceFrontier()
  let dom = Dominance.LengauerTarjanDominance.create g df
  g.FoldEdge((fun acc edge ->
    match dom.Dominators edge.First with
    | ds when ds |> Seq.exists (fun v -> v = edge.Second) -> edge :: acc
    | _ -> acc), [])

let private findNaturalLoopBody g (edge: Edge<_, _>) =
  let body = HashSet()
  let stack = Stack()
  let n, h = edge.First, edge.Second
  body.Add h |> ignore
  stack.Push n
  while stack.Count > 0 do
    let v = stack.Pop()
    if not (body.Contains v) then
      body.Add v |> ignore
      for pred in (g: IDiGraphAccessible<_, _>).GetPreds v do stack.Push pred
    else
      ()
  body

/// Finds every natural loop of the given directed graph, as a map from each
/// back edge to the body of the loop that the edge closes.
[<CompiledName "FindAll">]
let findAll (g: IDiGraphAccessible<_, _>) =
  let dict = Dictionary()
  for edge in findBackEdges g do
    dict[edge] <- findNaturalLoopBody g edge
  dict
