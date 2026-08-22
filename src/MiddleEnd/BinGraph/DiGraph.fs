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

/// Provides functions over a directed graph: ones that walk it, and ones that
/// build a new graph out of it.
[<RequireQualifiedAccess>]
module B2R2.MiddleEnd.BinGraph.DiGraph

/// Folds every vertex of the given graph. The order can be arbitrary.
[<CompiledName "FoldVertex">]
let foldVertex fn acc (g: #IDiGraph<'V, 'E>) =
  Array.fold fn acc g.Vertices

/// Iterates every vertex of the given graph. The order can be arbitrary.
[<CompiledName "IterVertex">]
let iterVertex fn (g: #IDiGraph<'V, 'E>) =
  Array.iter fn g.Vertices

/// Folds every edge of the given graph. The order can be arbitrary.
[<CompiledName "FoldEdge">]
let foldEdge fn acc (g: #IDiGraph<'V, 'E>) =
  Array.fold fn acc g.Edges

/// Iterates every edge of the given graph. The order can be arbitrary.
[<CompiledName "IterEdge">]
let iterEdge fn (g: #IDiGraph<'V, 'E>) = Array.iter fn g.Edges

/// Fills in the given empty graph with the transpose (i.e., the reverse) of
/// the given graph, and uses the given vertices as the roots of the result.
/// Every vertex keeps its ID, so that a vertex of the one graph and its
/// counterpart in the other are found by the same ID.
[<CompiledName "ReverseInto">]
let reverseInto g roots (out: IMutableDiGraph<'V, 'E>) =
  let g: IDiGraph<'V, 'E> = g
  g |> iterVertex (fun v -> out.AddVertexCopy v |> ignore)
  g |> iterEdge (fun e ->
    let src = out.FindVertexByID e.First.ID
    let dst = out.FindVertexByID e.Second.ID
    if e.HasLabel then
      out.AddEdge(dst, src, e.Label)
    else
      out.AddEdge(dst, src))
  roots
  |> Seq.map (fun (root: IVertex<'V>) ->
    assert (g.Contains root)
    out.FindVertexByID root.ID)
  |> out.SetRoots
