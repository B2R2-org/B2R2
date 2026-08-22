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
///   Contains graph traversal algorithms used throughout B2R2's middle-end
///   analyses.
///   </summary>
/// </namespacedoc>
///
/// <summary>
/// Provides depth-first traversal functions.
/// </summary>
[<RequireQualifiedAccess>]
module B2R2.MiddleEnd.BinGraph.Traversal.DFS

open System.Collections.Generic
open B2R2.MiddleEnd.BinGraph

let private pushSuccsRev (g: IDiGraph<_, _>) (stack: Stack<_>) v =
  let succs = g.GetSuccs v
  for i in succs.Length - 1 .. -1 .. 0 do stack.Push succs[i]

(* Walks the given vertices in a depth-first preorder, sharing the visited set
   with the caller so that several walks can extend the same traversal. The
   successors of a vertex go onto the stack in reverse, so that the first of
   them is the first to come back off, and a vertex is folded the moment the
   walk reaches it. Each of the given vertices is walked out in full before
   the next one is pushed, for the stack is empty by then. *)
let private foldPreorderCore visited g fn acc vs =
  let stack = Stack<IVertex<_>>()
  let mutable acc = acc
  for v: IVertex<_> in vs do
    stack.Push v
    while stack.Count > 0 do
      let v = stack.Pop()
      if (visited: HashSet<_>).Add v then
        acc <- fn acc v
        pushSuccsRev g stack v
      else
        ()
  acc

let private pushSuccs (g: IDiGraph<_, _>) (stack: Stack<_>) v =
  stack.Push(struct (v, g.GetSuccs v, 0))

(* Walks the given vertices in a depth-first postorder, sharing the visited
   set with the caller so that several walks can extend the same traversal. A
   vertex is marked visited only when the walk actually descends into it, for
   otherwise a successor that is merely queued would be mistaken for a
   finished one, and a deeper path reaching it later could not claim it as its
   own child. Each stack entry carries the successors of its vertex along with
   the index of the one to descend into next, so a vertex is folded only once
   its successors are exhausted. *)
let private foldPostorderCore visited g fn acc vs =
  let stack = Stack<struct (IVertex<_> * IVertex<_>[] * int)>()
  let mutable acc = acc
  for v: IVertex<_> in vs do
    if (visited: HashSet<_>).Add v then
      pushSuccs g stack v
      while stack.Count > 0 do
        let struct (v, succs, i) = stack.Pop()
        if i = succs.Length then
          acc <- fn acc v
        else
          stack.Push(struct (v, succs, i + 1))
          let s = succs[i]
          if visited.Add s then pushSuccs g stack s else ()
    else
      ()
  acc

(* Collects the given walk into a buffer, which read back to front is the
   reverse of the walk. Prepending the vertices onto a list gives that order
   just as well, but puts a cell on the heap for every vertex, where a buffer
   grows in place. *)
let private toBuffer walk =
  let buf = List<IVertex<_>>()
  walk buf.Add
  buf

let private foldInReverse fn acc (buf: List<IVertex<_>>) =
  let mutable acc = acc
  for i in buf.Count - 1 .. -1 .. 0 do acc <- fn acc buf[i]
  acc

let private iterInReverse fn (buf: List<IVertex<_>>) =
  for i in buf.Count - 1 .. -1 .. 0 do fn buf[i]

/// Folds vertices of the graph in a depth-first manner with the preorder
/// traversal, starting from the given root vertices.
[<CompiledName "FoldPreorderWithRoots">]
let foldPreorderWithRoots g roots fn acc =
  let visited = HashSet<IVertex<_>>()
  foldPreorderCore visited g fn acc roots

/// Folds vertices of the graph in a depth-first manner with the preorder
/// traversal. This function visits every vertex in the graph including
/// unreachable ones. For those unreachable vertices, the order is random.
[<CompiledName "FoldPreorder">]
let foldPreorder (g: IDiGraph<_, _>) fn acc =
  let visited = HashSet<IVertex<_>>()
  let acc = foldPreorderCore visited g fn acc (g.Roots)
  (* fold unreachable vertices, too. *)
  foldPreorderCore visited g fn acc g.Vertices

/// Iterates vertices of the graph in a depth-first manner with the preorder
/// traversal, starting from the given root vertices.
[<CompiledName "IterPreorderWithRoots">]
let iterPreorderWithRoots g roots fn =
  foldPreorderWithRoots g roots (fun () v -> fn v) ()

/// Iterates vertices of the graph in a depth-first manner with the preorder
/// traversal. This function visits every vertex in the graph including
/// unreachable ones. For those unreachable vertices, the order is random.
[<CompiledName "IterPreorder">]
let iterPreorder g fn = foldPreorder g (fun () v -> fn v) ()

/// Folds vertices of the graph in a depth-first manner with the postorder
/// traversal, starting from the given root vertices.
[<CompiledName "FoldPostorderWithRoots">]
let foldPostorderWithRoots g roots fn acc =
  let visited = HashSet<IVertex<_>>()
  foldPostorderCore visited g fn acc roots

/// Folds vertices of the graph in a depth-first manner with the postorder
/// traversal. This function visits every vertex in the graph including
/// unreachable ones. For those unreachable vertices, the order is random.
[<CompiledName "FoldPostorder">]
let foldPostorder (g: IDiGraph<_, _>) fn acc =
  let visited = HashSet<IVertex<_>>()
  let acc = foldPostorderCore visited g fn acc (g.Roots)
  (* fold unreachable vertices, too. *)
  foldPostorderCore visited g fn acc g.Vertices

/// Iterates vertices of the graph in a depth-first manner with the postorder
/// traversal, starting from the given root vertices.
[<CompiledName "IterPostorderWithRoots">]
let iterPostorderWithRoots g roots fn =
  foldPostorderWithRoots g roots (fun () v -> fn v) ()

/// Iterates vertices of the graph in a depth-first manner with the postorder
/// traversal. This function visits every vertex in the graph including
/// unreachable ones. For those unreachable vertices, the order is random.
[<CompiledName "IterPostorder">]
let iterPostorder g fn = foldPostorder g (fun () v -> fn v) ()

/// Folds vertices of the graph in a depth-first manner with the reverse
/// postorder traversal, starting from the given root vertices.
[<CompiledName "FoldRevPostorderWithRoots">]
let foldRevPostorderWithRoots g roots fn acc =
  toBuffer (iterPostorderWithRoots g roots) |> foldInReverse fn acc

/// Folds vertices of the graph in a depth-first manner with the reverse
/// postorder traversal. This function visits every vertex in the graph
/// including unreachable ones. For those unreachable vertices, the order is
/// random.
[<CompiledName "FoldRevPostorder">]
let foldRevPostorder g fn acc =
  toBuffer (iterPostorder g) |> foldInReverse fn acc

/// Iterates vertices of the graph in a depth-first manner with the reverse
/// postorder traversal, starting from the given root vertices.
[<CompiledName "IterRevPostorderWithRoots">]
let iterRevPostorderWithRoots g roots fn =
  toBuffer (iterPostorderWithRoots g roots) |> iterInReverse fn

/// Iterates vertices of the graph in a depth-first manner with the reverse
/// postorder traversal. This function visits every vertex in the graph
/// including unreachable ones. For those unreachable vertices, the order is
/// random.
[<CompiledName "IterRevPostorder">]
let iterRevPostorder g fn =
  toBuffer (iterPostorder g) |> iterInReverse fn
