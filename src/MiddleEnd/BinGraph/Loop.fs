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

module B2R2.MiddleEnd.BinGraph.Loop

open System.Collections.Generic

let private getBackEdges g =
  let ctx = Dominator.initDominatorContext g
  let doms =
    []
    |> g.FoldVertex (fun acc v ->
      (v, Dominator.doms ctx v) :: acc)
    |> Map.ofList
  []
  |> g.FoldEdge (fun acc edge ->
    match doms[edge.First] with
    | ds when ds |> Array.exists (fun v -> v = edge.Second) -> edge :: acc
    | _ -> acc)

let private findIn (g: IGraph<_, _>) (v: IVertex<_>) =
  g.FindVertexByID v.ID

let getNaturalLoops (g: IGraph<_, _>) root =
  let rev = g.Reverse ()
  getBackEdges g
  |> List.fold (fun acc edge ->
    let s = findIn rev edge.First
    let d = findIn rev edge.Second
    let vertices =
      [ d ]
      |> Traversal.foldPreorderExcept rev [ s ] [ d ] (fun acc v ->
        (findIn g v) :: acc)
      |> HashSet
    vertices :: acc) []
