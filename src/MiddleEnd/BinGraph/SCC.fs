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

/// Tarjan's strongly connected components algorithm.
module Tarjan =
  type private SCCStatus<'V when 'V: equality> = {
    mutable CurrentDFNum: int
    /// Vertex -> DFNum (depth-first number).
    DFNums: Dictionary<IVertex<'V>, int>
    /// DFNum -> Vertex
    Vertices: IVertex<'V>[]
    /// DFNum -> LowLink. LowLink is the smallest DFNum reachable from the
    /// current vertex.
    LowLinks: int[]
    /// DFNum -> bool. True if the vertex is on the stack.
    OnStackStatus: bool[]
    /// Stack for storing vertices of the current SCC.
    Stack: Stack<IVertex<'V>>
    /// List of strongly connected components.
    SCCs: List<HashSet<IVertex<'V>>>
  }

  let private initSCCStatus (g: IDiGraphAccessible<_, _>) =
    let len = g.Size
    { CurrentDFNum = 0
      DFNums = Dictionary<_, _>()
      Vertices = Array.zeroCreate len
      LowLinks = Array.zeroCreate len
      OnStackStatus = Array.zeroCreate len
      Stack = Stack ()
      SCCs = List () }

  let rec private computeSCC g status (v: IVertex<_>) =
    assert (not (status.DFNums.ContainsKey v))
    let dfnum = status.CurrentDFNum
    status.DFNums[v] <- dfnum
    status.Vertices[dfnum] <- v
    status.LowLinks[dfnum] <- dfnum
    status.CurrentDFNum <- dfnum + 1
    status.Stack.Push v
    status.OnStackStatus[dfnum] <- true
    for succ in (g: IDiGraphAccessible<_, _>).GetSuccs v do
      updateLowLink g status dfnum succ
    if status.LowLinks[dfnum] = dfnum then
      let scc = HashSet<IVertex<_>> ()
      let mutable doRepeat = true
      while doRepeat do
        let w = status.Stack.Pop ()
        status.OnStackStatus[status.DFNums[w]] <- false
        scc.Add w |> ignore
        doRepeat <- w <> v
      status.SCCs.Add scc
    else ()

  and private updateLowLink g status vNum (w: IVertex<_>) =
    if not (status.DFNums.ContainsKey w) then
      computeSCC g status w
      let vLowLink = status.LowLinks[vNum]
      let wLowLink = status.LowLinks[status.DFNums[w]]
      status.LowLinks[vNum] <- min vLowLink wLowLink
    elif status.OnStackStatus[status.DFNums[w]] then
      status.LowLinks[vNum] <- min status.LowLinks[vNum] status.DFNums[w]
    else ()

  let compute (g: IDiGraphAccessible<_, _>) =
    let status = initSCCStatus g
    for v in g.Vertices do
      if status.DFNums.ContainsKey v then ()
      else computeSCC g status v
    status.SCCs
