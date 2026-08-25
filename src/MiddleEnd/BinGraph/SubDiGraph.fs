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

namespace B2R2.MiddleEnd.BinGraph

open System.Collections.Generic

/// Builds the adjacency tables of the subgraph a set of vertices induces.
module private InducedTables =
  let build (orig: IDiGraph<'V, 'E>) (vs: IVertex<'V>[]) roots =
    let outgoing = Dictionary<IVertex<'V>, Edge<'V, 'E>[]>()
    let incoming = Dictionary<IVertex<'V>, Edge<'V, 'E>[]>()
    let held = HashSet<IVertex<'V>> vs
    let isHeldSucc (e: Edge<'V, 'E>) = held.Contains e.Second
    let isHeldPred (e: Edge<'V, 'E>) = held.Contains e.First
    for v in vs do
      outgoing[v] <- orig.GetSuccEdges v |> Array.filter isHeldSucc
      incoming[v] <- orig.GetPredEdges v |> Array.filter isHeldPred
    { Vertices = vs
      Outgoing = outgoing
      Incoming = incoming
      Roots = roots
      ImplType = orig.ImplementationType }

/// Represents the subgraph a set of vertices induces in a directed graph, read
/// as a view over that graph rather than built as a copy of it. The vertices
/// are the very ones of that graph, and so are the edges, an induced subgraph
/// keeping every edge whose two endpoints it holds. What it reads of that
/// graph it reads once, at construction, so that it answers for the state the
/// graph was in when it was taken.
type internal SubDiGraph<'V, 'E when 'V: equality and 'E: equality>
  (orig: IDiGraph<'V, 'E>, vs, roots) =
  inherit SnapshotDiGraph<'V, 'E>(InducedTables.build orig vs roots)
