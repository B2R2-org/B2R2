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

/// Several useful functions for directed graphs.
module internal B2R2.MiddleEnd.BinGraph.GraphUtils

open System.Text

let reverse (inGraph: IGraph<_, _>) roots outGraph =
  outGraph
  |> inGraph.FoldVertex (fun (outGraph: IGraph<_, _>) v ->
    outGraph.AddVertex (v.VData, v.ID) |> snd)
  |> inGraph.FoldEdge (fun outGraph edge ->
    let src = outGraph.FindVertexByID edge.First.ID
    let dst = outGraph.FindVertexByID edge.Second.ID
    outGraph.AddEdge (dst, src, edge.Label))
  |> fun outGraph -> (* renew root vertices *)
    roots |> Seq.map (fun (root: IVertex<_>) ->
      assert (inGraph.HasVertex root.ID)
      outGraph.FindVertexByID root.ID)
    |> outGraph.SetRoots

let inline private (!!) (sb: StringBuilder) (s: string) =
  sb.Append s |> ignore

let toDiGraphDOTString (g: IReadOnlyGraph<_, _>) name vToStrFn _eToStrFn =
  let sb = StringBuilder ()
  let vertexToString v =
    let id, lbl = vToStrFn v
    !!sb $"  {id}{lbl};\n"
  let edgeToString (e: Edge<_, _>) =
    !!sb $"  {vToStrFn e.First |> fst} -> {vToStrFn e.Second |> fst};\n"
  !!sb $"digraph {name} {{\n"
  !!sb $"  node[shape=box]\n"
  g.IterVertex vertexToString
  g.IterEdge edgeToString
  sb.Append("}\n").ToString()