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

open B2R2.Utils
open System.Collections.Generic

let private getBackEdges g root =
  let ctx = Dominator.initDominatorContext g root
  let doms =
    []
    |> DiGraph.foldVertex g (fun acc v ->
      (v, Dominator.doms ctx v) :: acc)
    |> Map.ofList
  []
  |> DiGraph.foldEdge g (fun acc s d e ->
    match doms.[s] with
    | l when l |> List.exists (fun v -> v = d) -> (s, d) :: acc
    | _ -> acc)

let private findIn g v = DiGraph<_, _>.findVertexByID g (Vertex<_>.GetID v)

let getNaturalLoops g root =
  let rev = DiGraph.reverse g
  getBackEdges g root
  |> List.fold (fun acc (s, d) ->
    let s = findIn rev s
    let d = findIn rev d
    let vertices =
      []
      |> Traversal.foldPreorderExcept rev [ s ] [ d ] (fun acc v ->
        (findIn g v) :: acc)
      |> HashSet
    vertices :: acc) []
    