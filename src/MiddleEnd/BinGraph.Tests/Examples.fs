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
  | Persistent -> PersistentDiGraph<int, int> () :> IDiGraph<_, _>
  | Imperative -> ImperativeDiGraph<int, int> () :> IDiGraph<_, _>

/// Add `count` number of nodes to the graph.
let private addNodes count g =
  [ 1.. count ]
  |> List.fold (fun (g: IDiGraph<_, _>, vmap) i ->
    let n, g = g.AddVertex i
    g, Map.add i n vmap
  ) (g, Map.empty)

let private prepare count t =
  let g, vmap = makeGraph t |> addNodes count
  let mutable cnt = 0
  let addEdge (g: IDiGraph<_, _>) i j =
    cnt <- cnt + 1
    g.AddEdge (vmap[i], vmap[j], cnt)
  g, vmap, addEdge

/// Graph example from Wikipedia.
let digraph1 t =
  let g, vmap, addEdge = prepare 6 t
  let g = addEdge g 1 2
  let g = addEdge g 2 3
  let g = addEdge g 2 4
  let g = addEdge g 2 6
  let g = addEdge g 3 5
  let g = addEdge g 4 5
  let g = addEdge g 5 2
  g, vmap

/// Graph example from Tiger book.
let digraph2 t =
  let g, vmap, addEdge = prepare 6 t
  let g = addEdge g 1 2
  let g = addEdge g 1 3
  let g = addEdge g 3 4
  let g = addEdge g 4 5
  let g = addEdge g 4 6
  let g = addEdge g 6 4
  g, vmap

/// Arbitrarily generated example.
let digraph3 t =
  let g, vmap, addEdge = prepare 5 t
  let g = addEdge g 1 2
  let g = addEdge g 1 3
  let g = addEdge g 2 4
  let g = addEdge g 3 4
  let g = addEdge g 3 5
  g, vmap

/// Another graph example from Tiger book (Fig. 19.5).
let digraph4 t =
  let g, vmap, addEdge = prepare 13 t
  let g = addEdge g 1 2
  let g = addEdge g 1 5
  let g = addEdge g 1 9
  let g = addEdge g 2 3
  let g = addEdge g 3 3
  let g = addEdge g 3 4
  let g = addEdge g 4 13
  let g = addEdge g 5 6
  let g = addEdge g 5 7
  let g = addEdge g 6 4
  let g = addEdge g 6 8
  let g = addEdge g 7 8
  let g = addEdge g 7 12
  let g = addEdge g 8 5
  let g = addEdge g 8 13
  let g = addEdge g 9 10
  let g = addEdge g 9 11
  let g = addEdge g 10 12
  let g = addEdge g 11 12
  let g = addEdge g 12 13
  g, vmap

/// Another arbitrarily generated example containing a loop. Exits: 6
let digraph5 t =
  let g, vmap, addEdge = prepare 6 t
  let g = addEdge g 1 2
  let g = addEdge g 1 3
  let g = addEdge g 2 4
  let g = addEdge g 3 4
  let g = addEdge g 3 5
  let g = addEdge g 4 6
  let g = addEdge g 5 6
  let g = addEdge g 6 1
  g, vmap

/// Little larger example. Exits: 6, 22, 23
let digraph6 t =
  let g, vmap, addEdge = prepare 23 t
  let g = addEdge g 1 2
  let g = addEdge g 1 3
  let g = addEdge g 2 4
  let g = addEdge g 2 7
  let g = addEdge g 3 5
  let g = addEdge g 3 6
  let g = addEdge g 4 7
  let g = addEdge g 5 8
  let g = addEdge g 5 10
  let g = addEdge g 7 9
  let g = addEdge g 7 11
  let g = addEdge g 8 10
  let g = addEdge g 9 12
  let g = addEdge g 9 13
  let g = addEdge g 10 19
  let g = addEdge g 11 22
  let g = addEdge g 12 13
  let g = addEdge g 13 14
  let g = addEdge g 13 15
  let g = addEdge g 14 16
  let g = addEdge g 15 16
  let g = addEdge g 16 17
  let g = addEdge g 16 18
  let g = addEdge g 17 18
  let g = addEdge g 18 19
  let g = addEdge g 18 20
  let g = addEdge g 19 21
  let g = addEdge g 19 23
  let g = addEdge g 20 22
  let g = addEdge g 21 22
  g, vmap

/// Another arbitrarily generated example.
let digraph7 t =
  let g, vmap, addEdge = prepare 5 t
  let g = addEdge g 1 2
  let g = addEdge g 1 3
  let g = addEdge g 2 4
  let g = addEdge g 3 4
  let g = addEdge g 3 5
  g, vmap

/// Example taken from Bourdoncle Components paper written by Matt Elder.
let digraph8 t =
  let g, vmap, addEdge = prepare 8 t
  let g = addEdge g 1 2
  let g = addEdge g 2 3
  let g = addEdge g 3 4
  let g = addEdge g 4 5
  let g = addEdge g 5 2
  let g = addEdge g 5 6
  let g = addEdge g 6 3
  let g = addEdge g 6 7
  let g = addEdge g 7 2
  let g = addEdge g 7 8
  g, vmap

/// Another example taken from Wikipedia.
let digraph9 t =
  let g, vmap, addEdge = prepare 8 t
  let g = addEdge g 1 2
  let g = addEdge g 2 3
  let g = addEdge g 2 5
  let g = addEdge g 2 6
  let g = addEdge g 3 4
  let g = addEdge g 3 7
  let g = addEdge g 4 3
  let g = addEdge g 4 8
  let g = addEdge g 5 1
  let g = addEdge g 5 6
  let g = addEdge g 6 7
  let g = addEdge g 7 6
  let g = addEdge g 8 4
  let g = addEdge g 8 7
  g, vmap

/// Arbitrarily generated example with isolated subgraphs.
let digraph10 t =
  let g, vmap, addEdge = prepare 5 t
  let g = addEdge g 1 2
  let g = addEdge g 2 3
  let g = addEdge g 3 1
  let g = addEdge g 4 5
  let g = addEdge g 5 4
  g, vmap

/// Example taken from Dragon book (Fig. 9.38). Exits: 9, 10
let digraph11 t =
  let g, vmap, addEdge = prepare 10 t
  let g = addEdge g 1 2
  let g = addEdge g 1 3
  let g = addEdge g 2 3
  let g = addEdge g 3 4
  let g = addEdge g 4 3
  let g = addEdge g 4 5
  let g = addEdge g 4 6
  let g = addEdge g 5 7
  let g = addEdge g 6 7
  let g = addEdge g 7 4
  let g = addEdge g 7 8
  let g = addEdge g 8 3
  let g = addEdge g 8 9
  let g = addEdge g 8 10
  let g = addEdge g 9 1
  let g = addEdge g 10 7
  g, vmap
