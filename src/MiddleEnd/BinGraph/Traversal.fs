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
  /// traversal, starting from the given root vertices.
  let foldPreorderWithRoots (g: IReadOnlyGraph<_, _>) roots fn acc =
    let visited = HashSet<VertexID> ()
    foldPreorderLoop visited g fn acc roots

  /// Fold vertices of the graph in a depth-first manner with the preorder
  /// traversal. This function visits every vertex in the graph including
  /// unreachable ones. For those unreachable vertices, the order is random.
  let foldPreorder (g: IReadOnlyGraph<_, _>) fn acc =
    let visited = HashSet<VertexID> ()
    let roots = g.GetRoots () |> Array.toList
    let acc = foldPreorderLoop visited g fn acc roots
    g.Vertices (* fold unreachable vertices, too. *)
    |> Array.toList
    |> foldPreorderLoop visited g fn acc

  /// Iterate vertices of the graph in a depth-first manner with the preorder
  /// traversal, starting from the given root vertices.
  let iterPreorderWithRoots g roots fn =
    foldPreorderWithRoots g roots (fun () v -> fn v) ()

  /// Iterate vertices of the graph in a depth-first manner with the preorder
  /// traversal. This function visits every vertex in the graph including
  /// unreachable ones. For those unreachable vertices, the order is random.
  let iterPreorder g fn =
    foldPreorder g (fun () v -> fn v) ()

  /// Fold vertices of the graph in a depth-first manner with the postorder
  /// traversal, starting from the given root vertices.
  let foldPostorderWithRoots (g: IReadOnlyGraph<_, _>) roots fn acc =
    let visited = HashSet<VertexID> ()
    foldPostorderLoop visited g fn acc [] roots

  /// Fold vertices of the graph in a depth-first manner with the postorder
  /// traversal. This function visits every vertex in the graph including
  /// unreachable ones. For those unreachable vertices, the order is random.
  let foldPostorder (g: IReadOnlyGraph<_, _>) fn acc =
    let visited = HashSet<VertexID> ()
    let roots = g.GetRoots () |> Array.toList
    let acc = foldPostorderLoop visited g fn acc [] roots
    g.Vertices
    |> Array.toList
    |> foldPostorderLoop visited g fn acc []

  /// Iterate vertices of the graph in a depth-first manner with the postorder
  /// traversal, starting from the given root vertices.
  let iterPostorderWithRoots g roots fn =
    foldPostorderWithRoots g roots (fun () v -> fn v) ()

  /// Iterate vertices of the graph in a depth-first manner with the postorder
  /// traversal. This function visits every vertex in the graph including
  /// unreachable ones. For those unreachable vertices, the order is random.
  let iterPostorder g fn =
    foldPostorder g (fun () v -> fn v) ()

  /// Fold vertices of the graph in a depth-first manner with the reverse
  /// postorder traversal, starting from the given root vertices.
  let foldRevPostorderWithRoots g roots fn acc =
    foldPostorderWithRoots g roots (fun acc v -> v :: acc) []
    |> List.fold fn acc

  /// Fold vertices of the graph in a depth-first manner with the reverse
  /// postorder traversal. This function visits every vertex in the graph
  /// including unreachable ones. For those unreachable vertices, the order is
  /// random.
  let foldRevPostorder (g: IReadOnlyGraph<_, _>) fn acc =
    foldPostorder g (fun acc v -> v :: acc) []
    |> List.fold fn acc

  /// Iterate vertices of the graph in a depth-first manner with the reverse
  /// postorder traversal, starting from the given root vertices.
  let iterRevPostorderWithRoots g roots fn =
    foldPostorderWithRoots g roots (fun acc v -> v :: acc) []
    |> List.iter fn

  /// Iterate vertices of the graph in a depth-first manner with the reverse
  /// postorder traversal. This function visits every vertex in the graph
  /// including unreachable ones. For those unreachable vertices, the order is
  /// random.
  let iterRevPostorder g fn =
    foldPostorder g (fun acc v -> v :: acc) []
    |> List.iter fn
