(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Soomin Kim <soomink@kaist.ac.kr>
          Sang Kil Cha <sangkilc@kaist.ac.kr>

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

namespace B2R2.Visualization

open B2R2.BinGraph
open System.Collections.Generic

/// The main graph type for visualization.
type VisGraph = ControlFlowGraph<VisBBlock, VisEdge>

module VisGraph =
  let ofCFG (g: ControlFlowGraph<#BasicBlock, _>) (r: Vertex<#BasicBlock>) hdl =
    let newGraph = VisGraph ()
    let visited = Dictionary<ProgramPoint, Vertex<VisBBlock>> ()
    let getVisBBlock (oldV: Vertex<#BasicBlock>) =
      match visited.TryGetValue oldV.VData.PPoint with
      | false, _ ->
        let blk =
          match hdl with
          | None -> VisBBlock (oldV.VData :> BasicBlock, false)
          | Some hdl -> VisBBlock (oldV.VData :> BasicBlock, false, hdl)
        let v = newGraph.AddVertex blk
        visited.[oldV.VData.PPoint] <- v
        v
      | true, v -> v
    let root = getVisBBlock r
    g.IterEdge (fun src dst e ->
      if src.VData.IsDummyBlock () || dst.VData.IsDummyBlock () then ()
      else
        let srcV = getVisBBlock src
        let dstV = getVisBBlock dst
        let edge = VisEdge (e)
        newGraph.AddEdge srcV dstV edge)
    newGraph, root

  let getID v = Vertex<VisBBlock>.GetID v

  let getPreds (v: Vertex<VisBBlock>) = v.Preds

  let getSuccs (v: Vertex<VisBBlock>) = v.Succs

  let getVData (v: Vertex<VisBBlock>) = v.VData

  let getIndex (v: Vertex<VisBBlock>) = v.VData.Index

  let getLayer (v: Vertex<VisBBlock>) = v.VData.Layer

  let setLayer (v: Vertex<VisBBlock>) layer = v.VData.Layer <- layer

  let getWidth (v: Vertex<VisBBlock>) = v.VData.Width

  let getHeight (v: Vertex<VisBBlock>) = v.VData.Height

  let getXPos (v: Vertex<VisBBlock>) = v.VData.Coordinate.X

  let getYPos (v: Vertex<VisBBlock>) = v.VData.Coordinate.Y

  let getDFSOrder (g: VisGraph) root =
    let size = g.Size () - 1
    let _, _, dfsOrder, _ =
      g.FoldVertexDFS root Algorithms.dfsOrdering
        (Set.empty, [], Map.empty, size)
    dfsOrder
