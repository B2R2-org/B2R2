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

/// <summary>
/// Provides the identification of natural loops, the loops that a back edge
/// closes: an edge whose head dominates its tail, and thus the one entry point
/// that every path into the loop goes through. Every such edge retreats, while
/// on a graph that is not reducible not every retreating edge is one of these
/// (see <see cref="T:B2R2.MiddleEnd.BinGraph.Loop.RetreatingEdge"/>).
/// </summary>
[<RequireQualifiedAccess>]
module B2R2.MiddleEnd.BinGraph.Loop.NaturalLoop

open System.Collections.Generic
open B2R2.MiddleEnd.BinGraph

/// Numbers the given dominator tree in an Euler tour, handing back the number
/// each vertex is entered and left at. A vertex dominates exactly the vertices
/// of its subtree, which the tour lays out as the numbers between the two, so
/// that a pair of numbers answers a dominance query rather than a walk up the
/// dominator chain. The tree is a forest, hence the tour starts afresh at
/// every root of it, with the one counter running through them all.
let private numberDominatorTree (tree: DominatorTree<_>) =
  let entries = Dictionary<IVertex<_>, int>()
  let exits = Dictionary<IVertex<_>, int>()
  let stack = Stack()
  let mutable cnt = 0
  for root in tree.Roots do stack.Push(root, false)
  while stack.Count > 0 do
    match stack.Pop() with
    | v, true ->
      exits[v] <- cnt
    | v, false ->
      entries[v] <- cnt
      cnt <- cnt + 1
      stack.Push(v, true)
      for child in tree.GetChildren v do stack.Push(child, false)
  entries, exits

let private findBackEdges g =
  let df = Dominance.CytronDominanceFrontier()
  let dom = Dominance.LengauerTarjanDominance.create g df
  let entries, exits = numberDominatorTree dom.DominatorTree
  let collect acc (edge: Edge<_, _>) =
    let n, h = edge.First, edge.Second
    if entries[h] <= entries[n] && entries[n] < exits[h] then
      edge :: acc
    else
      acc
  g |> DiGraph.foldEdge collect []

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
      for pred in (g: IDiGraph<_, _>).GetPreds v do stack.Push pred
    else
      ()
  body

/// Finds every natural loop of the given directed graph, as a map from each
/// back edge to the body of the loop that the edge closes.
[<CompiledName "FindAll">]
let findAll (g: IDiGraph<_, _>) =
  let dict = Dictionary()
  for edge in findBackEdges g do
    dict[edge] <- findNaturalLoopBody g edge
  dict
