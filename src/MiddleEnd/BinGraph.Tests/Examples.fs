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

module B2R2.MiddleEnd.BinGraph.Tests.Examples

open B2R2.MiddleEnd.BinGraph

let private makeGraph (t: ImplementationType) =
  match t with
  | Persistent ->
    let g = PersistentDiGraph<int, int>()
    MutablePersistentDiGraph g :> IMutableDiGraph<_, _>
  | Mutable ->
    MutableDiGraph<int, int>() :> IMutableDiGraph<_, _>

/// Adds `count` number of nodes to the given graph.
let private addNodes count (g: IMutableDiGraph<_, _>) =
  [ 1 .. count ]
  |> List.fold (fun vmap i -> Map.add i (g.AddVertex i) vmap) Map.empty

let private prepare count t =
  let g = makeGraph t
  let vmap = addNodes count g
  let mutable cnt = 0
  let addEdge i j =
    cnt <- cnt + 1
    g.AddEdge(vmap[i], vmap[j], cnt)
  g, vmap, addEdge

/// Empty graph, which has no vertex at all.
let emptyDigraph t = makeGraph t

/// Graph example from Wikipedia.
let digraph1 t =
  let g, vmap, addEdge = prepare 6 t
  addEdge 1 2
  addEdge 2 3
  addEdge 2 4
  addEdge 2 6
  addEdge 3 5
  addEdge 4 5
  addEdge 5 2
  g, vmap

/// Graph example from Tiger book.
let digraph2 t =
  let g, vmap, addEdge = prepare 6 t
  addEdge 1 2
  addEdge 1 3
  addEdge 3 4
  addEdge 4 5
  addEdge 4 6
  addEdge 6 4
  g, vmap

/// Arbitrarily generated example.
let digraph3 t =
  let g, vmap, addEdge = prepare 5 t
  addEdge 1 2
  addEdge 1 3
  addEdge 2 4
  addEdge 3 4
  addEdge 3 5
  g, vmap

/// Another graph example from Tiger book (Fig. 19.5).
let digraph4 t =
  let g, vmap, addEdge = prepare 13 t
  addEdge 1 2
  addEdge 1 5
  addEdge 1 9
  addEdge 2 3
  addEdge 3 3
  addEdge 3 4
  addEdge 4 13
  addEdge 5 6
  addEdge 5 7
  addEdge 6 4
  addEdge 6 8
  addEdge 7 8
  addEdge 7 12
  addEdge 8 5
  addEdge 8 13
  addEdge 9 10
  addEdge 9 11
  addEdge 10 12
  addEdge 11 12
  addEdge 12 13
  g, vmap

/// Another arbitrarily generated example containing a loop. Exits: 6
let digraph5 t =
  let g, vmap, addEdge = prepare 6 t
  addEdge 1 2
  addEdge 1 3
  addEdge 2 4
  addEdge 3 4
  addEdge 3 5
  addEdge 4 6
  addEdge 5 6
  addEdge 6 1
  g, vmap

/// Little larger example. Exits: 6, 22, 23
let digraph6 t =
  let g, vmap, addEdge = prepare 23 t
  addEdge 1 2
  addEdge 1 3
  addEdge 2 4
  addEdge 2 7
  addEdge 3 5
  addEdge 3 6
  addEdge 4 7
  addEdge 5 8
  addEdge 5 10
  addEdge 7 9
  addEdge 7 11
  addEdge 8 10
  addEdge 9 12
  addEdge 9 13
  addEdge 10 19
  addEdge 11 22
  addEdge 12 13
  addEdge 13 14
  addEdge 13 15
  addEdge 14 16
  addEdge 15 16
  addEdge 16 17
  addEdge 16 18
  addEdge 17 18
  addEdge 18 19
  addEdge 18 20
  addEdge 19 21
  addEdge 19 23
  addEdge 20 22
  addEdge 21 22
  g, vmap

/// Another arbitrarily generated example.
let digraph7 t =
  let g, vmap, addEdge = prepare 5 t
  addEdge 1 2
  addEdge 1 3
  addEdge 2 4
  addEdge 3 4
  addEdge 3 5
  g, vmap

/// Example taken from Bourdoncle Components paper written by Matt Elder.
let digraph8 t =
  let g, vmap, addEdge = prepare 8 t
  addEdge 1 2
  addEdge 2 3
  addEdge 3 4
  addEdge 4 5
  addEdge 5 2
  addEdge 5 6
  addEdge 6 3
  addEdge 6 7
  addEdge 7 2
  addEdge 7 8
  g, vmap

/// Another example taken from Wikipedia.
let digraph9 t =
  let g, vmap, addEdge = prepare 8 t
  addEdge 1 2
  addEdge 2 3
  addEdge 2 5
  addEdge 2 6
  addEdge 3 4
  addEdge 3 7
  addEdge 4 3
  addEdge 4 8
  addEdge 5 1
  addEdge 5 6
  addEdge 6 7
  addEdge 7 6
  addEdge 8 4
  addEdge 8 7
  g, vmap

/// Arbitrarily generated example with isolated subgraphs.
let digraph10 t =
  let g, vmap, addEdge = prepare 5 t
  addEdge 1 2
  addEdge 2 3
  addEdge 3 1
  addEdge 4 5
  addEdge 5 4
  g, vmap

/// Example taken from Dragon book (Fig. 9.38). Exits: 9, 10
let digraph11 t =
  let g, vmap, addEdge = prepare 10 t
  addEdge 1 2
  addEdge 1 3
  addEdge 2 3
  addEdge 3 4
  addEdge 4 3
  addEdge 4 5
  addEdge 4 6
  addEdge 5 7
  addEdge 6 7
  addEdge 7 4
  addEdge 7 8
  addEdge 8 3
  addEdge 8 9
  addEdge 8 10
  addEdge 9 1
  addEdge 10 7
  g, vmap

/// Arbitrarily generated example, where the vertex 5 is unreachable from the
/// root (1) while it has an edge into the reachable part. Exits: 4
let digraph12 t =
  let g, vmap, addEdge = prepare 5 t
  addEdge 1 2
  addEdge 1 3
  addEdge 2 4
  addEdge 3 4
  addEdge 5 3
  g, vmap

/// Arbitrarily generated example, which has no regular exit, and whose loop
/// tail (3) has two back edges. Exits: 3
let digraph13 t =
  let g, vmap, addEdge = prepare 3 t
  addEdge 1 2
  addEdge 2 3
  addEdge 3 1
  addEdge 3 2
  g, vmap
