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

namespace B2R2.RearEnd.Visualization

#if DEBUG
module VisDebug =
  open System
  open B2R2.MiddleEnd.BinGraph
  open B2R2.MiddleEnd.ControlFlowGraph

  let private fs = IO.File.Create ("visualization.log")

  let private getBytes (s: string) =
    Text.Encoding.ASCII.GetBytes(s + Environment.NewLine)

  /// Log the given string followed by a new line (for debugging).
  let logn s =
    let bytes = getBytes s
    fs.Write (bytes, 0, bytes.Length)
    fs.Flush ()

  let private ppNode (vGraph: IDiGraph<_, _>) (vNode: IVertex<VisBBlock>) =
    logn "Node {"
    sprintf "\tID: %d" vNode.ID |> logn
    sprintf "\tAddr: (%x)" ((vNode.VData :> IVisualizable).BlockAddress)
    |> logn
    sprintf "\tLayer: %d" vNode.VData.Layer |> logn
    logn "\tPreds: ["
    Seq.iter (fun (v: IVertex<VisBBlock>) ->
      sprintf "%d, " v.ID |> logn) <| vGraph.GetPreds vNode
    logn "]"
    logn "\tSuccss: ["
    Seq.iter (fun (v: IVertex<VisBBlock>) ->
      sprintf "%d, " v.ID |> logn) <| vGraph.GetSuccs vNode
    logn "]"
    logn "}"

  let pp (vGraph: VisGraph) =
    vGraph.IterVertex (ppNode vGraph)
#endif
