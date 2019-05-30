(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Soomin Kim <soomink@kaist.ac.kr>

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

module B2R2.BinGraph.Algorithms

let rec private kahnTopologicalSortLoop acc (g: SimpleDiGraph<_, _>) =
  match g.Unreachables with
  | [] -> acc
  | vertices ->
    let acc = List.fold (fun acc (v: Vertex<_>) -> v.VData :: acc) acc vertices
    List.iter (fun v -> g.RemoveVertex v) vertices
    kahnTopologicalSortLoop acc g

let kahnTopologicalSort (g: SimpleDiGraph<_, _>) =
  let h = g.Clone ()
  List.rev <| kahnTopologicalSortLoop [] h

let rec checkStack visited (stack: Vertex<_> list) orderMap cnt =
  match stack with
  | [] -> stack, orderMap, cnt
  | v :: stack ->
    if List.exists (fun s -> Set.contains s visited |> not) v.Succs then
      v :: stack, orderMap, cnt
    else
      let orderMap = Map.add v cnt orderMap
      checkStack visited stack orderMap (cnt - 1)

let dfsOrdering (visited, stack, orderMap, cnt) v =
  let visited = Set.add v visited
  let stack, orderMap, cnt = checkStack visited (v :: stack) orderMap cnt
  visited, stack, orderMap, cnt

let dfsTopologicalSort (g: DiGraph<_, _>) =
  let size = g.Size () - 1
  let _, _, dfsOrder, _ =
    g.FoldVertexDFS dfsOrdering (Set.empty, [], Map.empty, size)
  /// XXX: The below is normalizing. This is also a temporary patch..
  let min = Map.fold (fun acc _ x -> if acc < x then acc else x) (-1) dfsOrder
  let dfsOrder = Map.map (fun _ x -> x - min) dfsOrder
  let size = g.Size ()
  g.FoldVertex (fun acc v ->
    if Map.containsKey v acc then acc else Map.add v size acc) dfsOrder
