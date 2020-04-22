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

namespace B2R2.BinGraph

type ControlFlowGraph<'V, 'E when 'V :> BasicBlock and 'V: equality> () =
  inherit SimpleDiGraph<'V, 'E>()

  member __.Clone (?reverse) =
    let g = ControlFlowGraph<'V, 'E>()
    let isReverse = defaultArg reverse false
    let dict = System.Collections.Generic.Dictionary<VertexID, Vertex<'V>>()
    let addEdgeNormal (s: Vertex<'V>) (d: Vertex<'V>) e =
      g.AddEdge dict.[s.GetID ()] dict.[d.GetID ()] e
    let addEdgeReverse (s: Vertex<'V>) (d: Vertex<'V>) e =
      g.AddEdge dict.[d.GetID ()] dict.[s.GetID ()] e
    let addEdge = if isReverse then addEdgeReverse else addEdgeNormal
    __.IterVertex (fun v -> dict.Add(v.GetID (), g.AddVertex v.VData))
    __.IterEdge addEdge
    g

  member __.SubGraph vs =
    let g = ControlFlowGraph<'V, 'E> ()
    Set.iter (fun (v: Vertex<'V>) -> g.AddVertex v.VData |> ignore) vs
    __.IterEdge (fun src dst e ->
      if Set.contains src vs && Set.contains dst vs then
        g.AddEdge src dst e)
    g

type IRCFG = ControlFlowGraph<IRBasicBlock, CFGEdgeKind>

// vim: set tw=80 sts=2 sw=2:
