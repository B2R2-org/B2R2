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

module B2R2.MiddleEnd.BinGraph.Traversal

open System.Collections.Generic

let rec private prependReverseTo lst (arr: _[]) idx =
  if idx >= 0 then prependReverseTo (arr[idx] :: lst) arr (idx - 1)
  else lst

let private prependSuccessors (g: IReadOnlyGraph<_, _>) lst v =
  let succs = g.GetSuccs v
  prependReverseTo lst succs (succs.Length - 1)

let rec private foldPreorderLoop visited g fn acc = function
  | [] -> acc
  | v: IVertex<_> :: tovisit when (visited: HashSet<_>).Contains v.ID ->
    foldPreorderLoop visited g fn acc tovisit
  | v :: tovisit ->
    visited.Add v.ID |> ignore
    foldPreorderLoop visited g fn (fn acc v) (prependSuccessors g tovisit v)

let rec private foldPostorderLoop visited g fn acc vstack = function
  | [] -> acc
  | v: IVertex<_> :: tovisit when (visited: HashSet<_>).Contains v.ID ->
    foldPostorderLoop visited g fn acc vstack tovisit
  | v :: tovisit ->
    visited.Add v.ID |> ignore
    let struct (acc, vstack) = consume visited g fn acc (v :: vstack)
    foldPostorderLoop visited g fn acc vstack (prependSuccessors g tovisit v)

and consume visited g fn acc = function
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
  let visited = HashSet<int> ()
  foldPreorderLoop visited g fn acc roots

/// Fold vertices, except them in the second list, of the graph in a
/// depth-first manner with the preorder traversal.
let foldPreorderExcept g roots excepts fn acc =
  let visited =
    excepts
    |> List.map (fun (v: IVertex<_>) -> v.ID)
    |> HashSet
  foldPreorderLoop visited g fn acc roots

/// Iterate vertices of the graph in a depth-first manner with the preorder
/// traversal.
let iterPreorder g roots fn =
  foldPreorder g roots (fun () v -> fn v) ()

/// Iterate vertices, except them in the second list, of the graph in a
/// depth-first manner with the preorder traversal.
let iterPreorderExcept g roots excepts fn =
  foldPreorderExcept g roots excepts (fun () v -> fn v) ()

/// Fold vertices of the graph in a depth-first manner with the postorder
/// traversal. The traversal starts from each vertex in roots.
let foldPostorder g roots fn acc =
  let visited = HashSet<int> ()
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

/// Topologically fold every vertex of the given graph. For every unreachable
/// nodes, we accumulate vertices reachable from the node in a postorder
/// fashion. The accumulated list becomes the reverse postordered vertices,
/// which is essentially the same as a topologically sorted list of vertices.
/// We then simply fold the accumulated list. The second parameter (root) is for
/// providing root vertices in case there is no unreachable node, e.g., when
/// there is a loop to the root node.
let foldTopologically (g: IGraph<_, _>) roots fn acc =
  let visited = HashSet<int> ()
  let roots =
    g.Unreachables
    |> Set.ofSeq
    |> List.foldBack Set.add roots
    |> Set.toList
    |> foldPostorderLoop visited g (fun acc v -> v :: acc) [] []
  (* Consider unreachable loop components. For those vertices, the order is
     random *)
  g.Vertices
  |> Array.toList
  |> foldPostorderLoop visited g (fun acc v -> v :: acc) roots []
  |> List.fold fn acc
