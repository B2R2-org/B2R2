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
  let df = Dominance.CytronDominanceFrontier()
  let dom = Dominance.LengauerTarjanDominance.create g df
  g.FoldEdge((fun acc edge ->
    match dom.Dominators edge.First with
    | ds when ds |> Seq.exists (fun v -> v = edge.Second) -> edge :: acc
    | _ -> acc), [])

let private findNaturalLoopBody g (edge: Edge<_, _>) =
  let body = HashSet()
  let stack = Stack()
  let n, h = edge.First, edge.Second
  body.Add h |> ignore
  stack.Push  n
  while stack.Count > 0 do
    let v = stack.Pop()
    if not (body.Contains v) then
      body.Add v |> ignore
      for pred in (g: IDiGraphAccessible<_, _>).GetPreds v do stack.Push pred
    else ()
  body

let getNaturalLoops (g: IDiGraph<_, _>) =
  let dict = Dictionary()
  for edge in getBackEdges g do
    dict[edge] <- findNaturalLoopBody g edge
  dict
