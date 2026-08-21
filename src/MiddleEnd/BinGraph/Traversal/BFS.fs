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

/// Provides breadth-first traversal functions.
[<RequireQualifiedAccess>]
module B2R2.MiddleEnd.BinGraph.Traversal.BFS

open System.Collections.Generic
open B2R2.MiddleEnd.BinGraph

(* Drains the queue, appending every vertex to the given collection as it is
   dequeued and enqueueing the successors that no walk has reached yet. *)
let private drainQueue (g: IDiGraphAccessible<_, _>) visited queue ordered =
  while (queue: Queue<IVertex<_>>).Count > 0 do
    let v = queue.Dequeue()
    (ordered: ResizeArray<_>).Add v
    for s in g.GetSuccs v do
      if (visited: HashSet<_>).Add s.ID then queue.Enqueue s else ()

(* The vertices reachable from the given ones, in breadth-first order. They
   are all sources of a single walk, so they make up its first level however
   many of them there are. *)
let private orderFromRoots g roots =
  let visited = HashSet<VertexID>()
  let queue = Queue<IVertex<_>>()
  let ordered = ResizeArray<IVertex<_>>()
  for r: IVertex<_> in roots do
    if visited.Add r.ID then queue.Enqueue r else ()
  drainQueue g visited queue ordered
  ordered

(* Every vertex of the graph, the ones reachable from its roots first. *)
let private orderOfEveryVertex (g: IDiGraphAccessible<_, _>) =
  let visited = HashSet<VertexID>()
  let queue = Queue<IVertex<_>>()
  let ordered = ResizeArray<IVertex<_>>()
  for r in g.GetRoots() do
    if visited.Add r.ID then queue.Enqueue r else ()
  drainQueue g visited queue ordered
  (* walk the unreachable vertices, too. *)
  for v in g.Vertices do
    if visited.Add v.ID then
      queue.Enqueue v
      drainQueue g visited queue ordered
    else
      ()
  ordered

let private foldReversed fn acc (ordered: ResizeArray<_>) =
  let mutable acc = acc
  for i = ordered.Count - 1 downto 0 do
    acc <- fn acc ordered[i]
  acc

let private iterReversed fn (ordered: ResizeArray<_>) =
  for i = ordered.Count - 1 downto 0 do
    fn ordered[i]

/// Folds vertices of the graph in a breadth-first manner, starting from the
/// given root vertices, which together make up the first level of the walk.
[<CompiledName "FoldWithRoots">]
let foldWithRoots g roots fn acc = orderFromRoots g roots |> Seq.fold fn acc

/// Folds vertices of the graph in a breadth-first manner. This function
/// visits every vertex in the graph including unreachable ones. For those
/// unreachable vertices, the order is random.
[<CompiledName "Fold">]
let fold g fn acc = orderOfEveryVertex g |> Seq.fold fn acc

/// Iterates vertices of the graph in a breadth-first manner, starting from
/// the given root vertices, which together make up the first level of the
/// walk.
[<CompiledName "IterWithRoots">]
let iterWithRoots g roots fn = orderFromRoots g roots |> Seq.iter fn

/// Iterates vertices of the graph in a breadth-first manner. This function
/// visits every vertex in the graph including unreachable ones. For those
/// unreachable vertices, the order is random.
[<CompiledName "Iter">]
let iter g fn = orderOfEveryVertex g |> Seq.iter fn

/// Folds vertices of the graph in the reverse of the order that a
/// breadth-first walk from the given root vertices visits them in. The walk
/// itself runs forwards; it is the folding that runs backwards.
[<CompiledName "FoldRevWithRoots">]
let foldRevWithRoots g roots fn acc =
  orderFromRoots g roots |> foldReversed fn acc

/// Folds vertices of the graph in the reverse of the order that a
/// breadth-first walk visits them in. This function visits every vertex in
/// the graph including unreachable ones. For those unreachable vertices, the
/// order is random.
[<CompiledName "FoldRev">]
let foldRev g fn acc = orderOfEveryVertex g |> foldReversed fn acc

/// Iterates vertices of the graph in the reverse of the order that a
/// breadth-first walk from the given root vertices visits them in. The walk
/// itself runs forwards; it is the iteration that runs backwards.
[<CompiledName "IterRevWithRoots">]
let iterRevWithRoots g roots fn = orderFromRoots g roots |> iterReversed fn

/// Iterates vertices of the graph in the reverse of the order that a
/// breadth-first walk visits them in. This function visits every vertex in
/// the graph including unreachable ones. For those unreachable vertices, the
/// order is random.
[<CompiledName "IterRev">]
let iterRev g fn = orderOfEveryVertex g |> iterReversed fn
