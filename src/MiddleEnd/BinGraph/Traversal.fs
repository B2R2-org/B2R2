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

  let private prependSuccessors (g: IDiGraphAccessible<_, _>) lst v =
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
  let foldPreorderWithRoots (g: IDiGraphAccessible<_, _>) roots fn acc =
    let visited = HashSet<VertexID> ()
    foldPreorderLoop visited g fn acc roots

  /// Fold vertices of the graph in a depth-first manner with the preorder
  /// traversal. This function visits every vertex in the graph including
  /// unreachable ones. For those unreachable vertices, the order is random.
  let foldPreorder (g: IDiGraphAccessible<_, _>) fn acc =
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
  let foldPostorderWithRoots (g: IDiGraphAccessible<_, _>) roots fn acc =
    let visited = HashSet<VertexID> ()
    foldPostorderLoop visited g fn acc [] roots

  /// Fold vertices of the graph in a depth-first manner with the postorder
  /// traversal. This function visits every vertex in the graph including
  /// unreachable ones. For those unreachable vertices, the order is random.
  let foldPostorder (g: IDiGraphAccessible<_, _>) fn acc =
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
  let foldRevPostorder (g: IDiGraphAccessible<_, _>) fn acc =
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

  /// Fold vertices of the graph in a depth-first postorder manner.
  let foldPostorderWithRoots2 (g: IDiGraphAccessible<_, _>) roots fn acc =
    let visited = HashSet<VertexID> ()
    let mutable acc = acc
    let rec visit (v: IVertex<_>) =
      if visited.Add v.ID then
        for s in g.GetSuccs v do
          visit s
        acc <- fn acc v
    for r in roots do
      if not (visited.Contains (r: IVertex<_>).ID) then
        visit r
    acc

  /// Fold vertices of the graph in a depth-first postorder manner.
  let foldPostorderWithRoots3 (g: IDiGraphAccessible<_, _>) roots fn acc =
    let visited = HashSet<VertexID>()
    let mutable acc = acc
    let stack = Stack<IVertex<_> * bool>()
    for root: IVertex<_> in roots do
      if visited.Add root.ID then
        stack.Push (root, false)
        while stack.Count > 0 do
          let v, visitedChildren = stack.Pop()
          if visitedChildren then acc <- fn acc v
          else
            stack.Push (v, true)
            for succ in Seq.rev (g.GetSuccs v) do
              if visited.Add succ.ID then
                stack.Push (succ, false)
    acc

/// Breadth-first traversal functions.
module BFS =
  /// Fold vertices of the graph in a reverse breadth-first traversal manner.
  let reverseFoldWithRoots (g: IDiGraphAccessible<_, _>) roots fn acc =
    let visited = HashSet<VertexID> ()
    let queue = Queue<IVertex<_>> ()
    let vertices = ResizeArray<IVertex<_>>()
    for r in roots do
      queue.Enqueue r
      visited.Add r.ID |> ignore
    while queue.Count > 0 do
      let v = queue.Dequeue ()
      vertices.Add v
      for s in g.GetSuccs v do
        if not (visited.Contains s.ID) then
          queue.Enqueue s
          visited.Add s.ID |> ignore
    let mutable acc = acc
    for v in Seq.rev vertices do
      acc <- fn acc v
    acc