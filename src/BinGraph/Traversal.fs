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

module B2R2.BinGraph.Traversal

open System.Collections.Generic

let inline private prependSuccessors lst (v: Vertex<_>) =
  v.Succs |> List.fold (fun lst s -> s :: lst) lst

/// Fold vertices of the graph in a depth-first manner with the preorder
/// traversal.
let foldPreorder (v: Vertex<_>) fn acc =
  let visited = new HashSet<int> ()
  let rec loop acc = function
    | [] -> acc
    | v :: tovisit when Vertex<_>.GetID v |> visited.Contains ->
      loop acc tovisit
    | v :: tovisit ->
      visited.Add (v.GetID ()) |> ignore
      loop (fn acc v) (prependSuccessors tovisit v)
  loop acc [v]

/// Iterate vertices of the graph in a depth-first manner with the preorder
/// traversal.
let iterPreorder v fn =
  foldPreorder v (fun () v -> fn v) ()

/// Fold vertices of the graph in a depth-first manner with the postorder
/// traversal.
let foldPostorder (v: Vertex<_>) fn acc =
  let visited = new HashSet<int> ()
  let rec loop acc vstack = function
    | [] -> acc
    | v :: tovisit when Vertex<_>.GetID v |> visited.Contains ->
      loop acc vstack tovisit
    | v :: tovisit ->
      visited.Add (v.GetID ()) |> ignore
      let struct (acc, vstack) = consume acc (v :: vstack)
      loop acc vstack (prependSuccessors tovisit v)
  and consume acc = function
    | [] -> struct (acc, [])
    | v :: rest ->
      if v.Succs |> List.forall (fun s -> s.GetID () |> visited.Contains) then
        consume (fn acc v) rest
      else
        struct (acc, v :: rest)
  loop acc [] [v]

/// Iterate vertices of the graph in a depth-first manner with the postorder
/// traversal.
let iterPostorder (v: Vertex<_>) fn =
  foldPostorder v (fun () v -> fn v) ()

/// Fold vertices of the graph in a depth-first manner with the reverse
/// postorder traversal.
let foldRevPostorder (v: Vertex<_>) fn acc =
  foldPostorder v (fun acc v -> v :: acc) []
  |> List.fold fn acc

/// Iterate vertices of the graph in a depth-first manner with the reverse
/// postorder traversal.
let iterRevPostorder (v: Vertex<_>) fn =
  foldPostorder v (fun acc v -> v :: acc) []
  |> List.iter fn

/// Topologically fold every vertex of the given graph. For every unreachable
/// nodes, we accumulate vertices reachable from the node in a postorder
/// fashion. The accumulated list becomes the reverse postordered vertices,
/// which is essentially the same as a topologically sorted list of vertices.
/// We then simply fold the accumulated list. The second parameter (root) is for
/// providing root vertices in case there is no unreachable node, e.g., when
/// there is a loop to the root node.
let foldTopologically (g: DiGraph<_, _>) roots fn acc =
  g.Unreachables
  |> Set.ofSeq
  |> List.foldBack Set.add roots
  |> Set.fold (fun acc root ->
    foldPostorder root (fun acc v -> v :: acc) acc) []
  |> List.fold fn acc
