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

let inline private prependSuccessors g lst v =
  DiGraph.getSuccs g v |> List.fold (fun lst s -> s :: lst) lst

let rec foldPreorderLoop visited g fn acc = function
  | [] -> acc
  | v: Vertex<_> :: tovisit when v.GetID () |> (visited: HashSet<_>).Contains ->
    foldPreorderLoop visited g fn acc tovisit
  | v :: tovisit ->
    v.GetID () |> visited.Add |> ignore
    foldPreorderLoop visited g fn (fn acc v) (prependSuccessors g tovisit v)

/// Fold vertices of the graph in a depth-first manner with the preorder
/// traversal.
let foldPreorder g v fn acc =
  let visited = new HashSet<int> ()
  foldPreorderLoop visited g fn acc [v]

/// Iterate vertices of the graph in a depth-first manner with the preorder
/// traversal.
let iterPreorder g v fn =
  foldPreorder g v (fun () v -> fn v) ()

let rec foldPostorderLoop visited g fn acc vstack = function
  | [] -> acc
  | v: Vertex<_> :: tovisit when v.GetID () |> (visited: HashSet<_>).Contains ->
    foldPostorderLoop visited g fn acc vstack tovisit
  | v :: tovisit ->
    v.GetID () |> visited.Add |> ignore
    let struct (acc, vstack) = consume visited g fn acc (v :: vstack)
    foldPostorderLoop visited g fn acc vstack (prependSuccessors g tovisit v)
and consume visited g fn acc = function
  | [] -> struct (acc, [])
  | v :: rest ->
    let allSuccsVisited =
      DiGraph.getSuccs g v
      |> List.forall (fun s -> s.GetID () |> visited.Contains)
    if allSuccsVisited then consume visited g fn (fn acc v) rest
    else struct (acc, v :: rest)

/// Fold vertices of the graph in a depth-first manner with the postorder
/// traversal.
let foldPostorder g v fn acc =
  let visited = new HashSet<int> ()
  foldPostorderLoop visited g fn acc [] [v]

/// Iterate vertices of the graph in a depth-first manner with the postorder
/// traversal.
let iterPostorder g v fn =
  foldPostorder g v (fun () v -> fn v) ()

/// Fold vertices of the graph in a depth-first manner with the reverse
/// postorder traversal.
let foldRevPostorder g v fn acc =
  foldPostorder g v (fun acc v -> v :: acc) []
  |> List.fold fn acc

/// Iterate vertices of the graph in a depth-first manner with the reverse
/// postorder traversal.
let iterRevPostorder g v fn =
  foldPostorder g v (fun acc v -> v :: acc) []
  |> List.iter fn

/// Topologically fold every vertex of the given graph. For every unreachable
/// nodes, we accumulate vertices reachable from the node in a postorder
/// fashion. The accumulated list becomes the reverse postordered vertices,
/// which is essentially the same as a topologically sorted list of vertices.
/// We then simply fold the accumulated list. The second parameter (root) is for
/// providing root vertices in case there is no unreachable node, e.g., when
/// there is a loop to the root node.
let foldTopologically g roots fn acc =
  let visited = new HashSet<int> ()
  DiGraph.getUnreachables g
  |> Set.ofSeq
  |> List.foldBack Set.add roots
  |> Set.toList
  |> foldPostorderLoop visited g (fun acc v -> v :: acc) [] []
  |> List.fold fn acc
