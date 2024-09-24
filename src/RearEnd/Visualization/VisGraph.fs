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

open B2R2.MiddleEnd.BinGraph
open System.Collections.Generic

/// The main graph type for visualization.
type VisGraph = IGraph<VisBBlock, VisEdge>

module VisGraph =
  let init () =
    ImperativeDiGraph<VisBBlock, VisEdge> ()
    :> VisGraph

  let ofCFG g roots =
    let newGraph = init ()
    let visited = Dictionary<VertexID, IVertex<VisBBlock>> ()
    (g: IGraph<_, _>).IterVertex (fun v ->
      if visited.ContainsKey v.ID then ()
      else
        let blk = VisBBlock (v.VData, false)
        let v', _ = newGraph.AddVertex blk
        visited[v.ID] <- v'
    )
    let roots = roots |> List.map (fun (root: IVertex<_>) -> visited[root.ID])
    (g: IGraph<_, _>).IterEdge (fun e ->
      let srcV = visited[e.First.ID]
      let dstV = visited[e.Second.ID]
      let edge = VisEdge e.Label
      newGraph.AddEdge (srcV, dstV, edge) |> ignore)
    newGraph, roots

  let getID (v: IVertex<_>) = v.ID

  let getPreds (vGraph: IGraph<_, _>) (v: IVertex<_>) = vGraph.GetPreds v

  let getSuccs (vGraph: IGraph<_, _>) (v: IVertex<_>) = vGraph.GetSuccs v

  let getVData (v: IVertex<_>) = v.VData

  let getIndex (v: IVertex<VisBBlock>) = v.VData.Index

  let getLayer (v: IVertex<VisBBlock>) = v.VData.Layer

  let setLayer (v: IVertex<VisBBlock>) layer = v.VData.Layer <- layer

  let getWidth (v: IVertex<VisBBlock>) = v.VData.Width

  let getHeight (v: IVertex<VisBBlock>) = v.VData.Height

  let getXPos (v: IVertex<VisBBlock>) = v.VData.Coordinate.X

  let getYPos (v: IVertex<VisBBlock>) = v.VData.Coordinate.Y
