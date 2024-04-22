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

module B2R2.MiddleEnd.BinGraph.SCC

open System.Collections.Generic

type private SCCInfo<'V when 'V: equality> = {
  /// Vertex ID -> DFNum
  DFNumMap: Dictionary<VertexID, int>
  /// DFNum -> Vertex
  Vertex: IVertex<'V>[]
  /// DFNum -> LowLink
  LowLink: int[]
}

let private initSCCInfo (g: IGraph<_, _>) =
  let len = g.Size + 1
  { DFNumMap = Dictionary<VertexID, int>()
    Vertex = Array.zeroCreate len
    LowLink = Array.zeroCreate len }

let inline private dfnum ctxt (v: IVertex<_>) =
  ctxt.DFNumMap[v.ID]

let inline private lowlink ctxt v =
  ctxt.LowLink[dfnum ctxt v]

let rec private assignSCC ctxt vNum stack (scc: HashSet<_>) =
  if not (List.isEmpty stack) then
    let wNum = List.head stack
    if wNum >= vNum then
      let stack = List.tail stack
      scc.Add ctxt.Vertex[wNum] |> ignore
      assignSCC ctxt vNum stack scc
    else stack
  else stack

let private createSCC ctxt v stack sccs =
  let vNum = dfnum ctxt v
  if lowlink ctxt v = vNum then
    let scc = HashSet<IVertex<_>> ()
    let stack = assignSCC ctxt vNum stack scc
    stack, scc :: sccs
  else stack, sccs

/// R.Tarjan. Depth-first search and linear graph algorithms
let rec private computeSCC (g: IGraph<_, _>) ctxt (v: IVertex<_>) n stack sccs =
  assert (not (ctxt.DFNumMap.ContainsKey v.ID))
  ctxt.DFNumMap[v.ID] <- n
  ctxt.LowLink[n] <- n
  ctxt.Vertex[n] <- v
  let n, stack, sccs =
    g.GetSuccs v
    |> Seq.fold (computeLowLink g ctxt v) (n + 1, n :: stack, sccs)
  let stack, sccs = createSCC ctxt v stack sccs
  n, stack, sccs

and private computeLowLink g ctxt v (n, stack, sccs) (w: IVertex<_>) =
  let vNum = dfnum ctxt v
  let vLink = lowlink ctxt v
  if ctxt.DFNumMap.ContainsKey w.ID then
    let wNum = dfnum ctxt w
    if List.contains wNum stack then ctxt.LowLink[vNum] <- min vLink wNum
    n, stack, sccs
  else
    let n, stack, sccs = computeSCC g ctxt w n stack sccs
    let wLink = lowlink ctxt w
    ctxt.LowLink[vNum] <- min vLink wLink
    n, stack, sccs

let compute (g: IGraph<_, _>) =
  let ctxt = initSCCInfo g
  g.Vertices
  |> Seq.fold (fun (n, acc) root ->
    if ctxt.DFNumMap.ContainsKey root.ID then n, acc
    else
      let n, _, sccs = computeSCC g ctxt root n [] []
      n, sccs :: acc) (1, [])
  |> snd
  |> List.concat
  |> ResizeArray
