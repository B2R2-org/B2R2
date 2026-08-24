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
/// Provides the identification of retreating edges, the edges that close a
/// cycle of a depth-first traversal: an edge whose head the traversal is still
/// inside of when it reads the edge. Every back edge of a natural loop
/// retreats, and on a graph that is not reducible some retreating edges close
/// no natural loop, since their head does not dominate their tail.
/// </summary>
[<RequireQualifiedAccess>]
module B2R2.MiddleEnd.BinGraph.Loop.RetreatingEdge

open System.Collections.Generic
open B2R2.MiddleEnd.BinGraph

/// Numbers the vertices of the given graph in the reverse of the order a
/// depth-first traversal leaves them in, which is the order that puts every
/// vertex ahead of the ones it reaches by tree, forward, and cross edges
/// alike, so that only a retreating edge reads a number no larger than its
/// own.
let private computeDepthFirstNumbers (g: IDiGraph<_, _>) =
  let dfNums = Dictionary<IVertex<_>, int>()
  Traversal.DFS.foldRevPostorder g (fun cnt v ->
    dfNums[v] <- cnt
    cnt + 1
  ) 0 |> ignore
  dfNums

/// Finds every retreating edge of the given directed graph. A vertex can be
/// the source of more than one of them, hence the edges, not their sources,
/// are what the result holds.
[<CompiledName "FindAll">]
let findAll (g: IDiGraph<_, _>) =
  let dfNums = computeDepthFirstNumbers g
  let retreating = HashSet<Edge<_, _>>()
  g |> DiGraph.iterEdge (fun e ->
    if dfNums[e.First] < dfNums[e.Second] then ()
    else retreating.Add e |> ignore)
  retreating
