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

namespace B2R2.MiddleEnd.BinGraph.Traversal

open System.Collections.Generic
open B2R2.MiddleEnd.BinGraph

/// Depth-first traversal functions.
module DFS =
  let rec private reversePrependTo lst (arr: _[]) idx =
    if idx >= 0 then reversePrependTo (arr[idx] :: lst) arr (idx - 1)
    else lst

  let private prependSuccessors (g: IReadOnlyGraph<_, _>) lst v =
    let succs = g.GetSuccs v
    reversePrependTo lst succs (succs.Length - 1)

  let rec private foldPreorderLoop visited g fn acc = function
    | [] -> acc
    | v: IVertex<_> :: tovisit when (visited: HashSet<_>).Contains v.ID ->
      foldPreorderLoop visited g fn acc tovisit
    | v :: tovisit ->
      visited.Add v.ID |> ignore
      foldPreorderLoop visited g fn (fn acc v) (prependSuccessors g tovisit v)

  let rec internal foldPostorderLoop visited g fn acc vstack = function
    | [] -> acc
    | v: IVertex<_> :: tovisit when (visited: HashSet<_>).Contains v.ID ->
      foldPostorderLoop visited g fn acc vstack tovisit
    | v :: tovisit ->
      visited.Add v.ID |> ignore
      let struct (acc, vstack) = consume visited g fn acc (v :: vstack)
      foldPostorderLoop visited g fn acc vstack (prependSuccessors g tovisit v)

  and private consume visited g fn acc = function
    | [] -> struct (acc, [])
    | v :: rest ->
      let allSuccsVisited =
        g.GetSuccs v
        |> Seq.forall (fun s -> visited.Contains s.ID)
      if allSuccsVisited then consume visited g fn (fn acc v) rest
      else struct (acc, v :: rest)

  /// Fold vertices of the graph in a depth-first manner with the preorder
  /// traversal.
  let foldPreorder g roots fn acc =
    let visited = HashSet<VertexID> ()
    foldPreorderLoop visited g fn acc roots

  /// Iterate vertices of the graph in a depth-first manner with the preorder
  /// traversal.
  let iterPreorder g roots fn =
    foldPreorder g roots (fun () v -> fn v) ()

  /// Fold vertices of the graph in a depth-first manner with the postorder
  /// traversal. The traversal starts from each vertex in roots.
  let foldPostorder g roots fn acc =
    let visited = HashSet<VertexID> ()
    foldPostorderLoop visited g fn acc [] roots

  /// Iterate vertices of the graph in a depth-first manner with the postorder
  /// traversal. The traversal starts from each vertex in roots.
  let iterPostorder g roots fn =
    foldPostorder g roots (fun () v -> fn v) ()

  /// Fold vertices of the graph in a depth-first manner with the reverse
  /// postorder traversal. The traversal starts from each vertex in roots.
  let foldRevPostorder g roots fn acc =
    foldPostorder g roots (fun acc v -> v :: acc) []
    |> List.fold fn acc

  /// Iterate vertices of the graph in a depth-first manner with the reverse
  /// postorder traversal. The traversal starts from each vertex in roots.
  let iterRevPostorder g roots fn =
    foldPostorder g roots (fun acc v -> v :: acc) []
    |> List.iter fn

/// Topological traversal functions.
module Topological =
  /// Topologically fold every vertex of the given graph. Topological order is
  /// theorectically the same as the reverse postorder traversal, but this
  /// function is different from `DFS.foldRevPostorder` in that this function
  /// visits every vertex in the graph including unreachable ones.
  let fold (g: IGraph<_, _>) roots fn acc =
    let visited = HashSet<VertexID> ()
    let roots =
      g.Unreachables
      |> Set.ofSeq
      |> List.foldBack Set.add roots
      |> Set.toList
      |> DFS.foldPostorderLoop visited g (fun acc v -> v :: acc) [] []
    (* Consider unreachable loop components. For those vertices, the order is
       random *)
    g.Vertices
    |> Array.toList
    |> DFS.foldPostorderLoop visited g (fun acc v -> v :: acc) roots []
    |> List.fold fn acc
