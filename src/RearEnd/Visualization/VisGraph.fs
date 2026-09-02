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

open System.Collections.Generic
open B2R2.MiddleEnd.BinGraph

/// Represents a graph laid out for visualization.
type VisGraph = IMutableDiGraph<VisBBlock, VisEdge>

/// Provides the means of building a graph for visualization and of reading
/// the geometry the layout gives its vertices.
[<RequireQualifiedAccess>]
module VisGraph =
  /// Creates an empty graph for visualization.
  let init () =
    MutableDiGraph<VisBBlock, VisEdge>()
    :> VisGraph

  /// Builds a graph for visualization out of the given CFG, laying its blocks
  /// out for a font of the given character width and height. The roots of the
  /// given graph carry over, since what a graph is rooted at is what the
  /// layering reads it from.
  let ofCFG (g: IDiGraph<_, _>) charWidth charHeight =
    let newGraph = init ()
    let vblocks = Dictionary<VertexID, IVertex<VisBBlock>>()
    for v in g.Vertices do
      if vblocks.ContainsKey v.ID then
        ()
      else
        let blk = VisBBlock(v.VData, charWidth, charHeight)
        let v' = newGraph.AddVertex blk
        vblocks[v.ID] <- v'
    for e in g.Edges do
      let srcV = vblocks[e.First.ID]
      let dstV = vblocks[e.Second.ID]
      let edge = VisEdge e.Label
      newGraph.AddEdge(srcV, dstV, edge)
    (* A graph names its own first vertex as its root when it is told of no
       other, which is whichever vertex came first out of the given graph. *)
    let roots = g.Roots |> Array.map (fun r -> vblocks[r.ID])
    if Array.isEmpty roots then () else newGraph.SetRoots roots
    newGraph

  /// Returns the ID of the given vertex.
  let getID (v: IVertex<_>) = v.ID

  /// Returns the predecessors of the given vertex.
  let getPreds (vGraph: IDiGraph<_, _>) v = vGraph.GetPreds v

  /// Returns the successors of the given vertex.
  let getSuccs (vGraph: IDiGraph<_, _>) v = vGraph.GetSuccs v

  /// Returns the data that the given vertex carries.
  let getVData (v: IVertex<_>) = v.VData

  /// Returns the index of the given vertex within its layer.
  let getIndex (v: IVertex<VisBBlock>) = v.VData.Index

  /// Returns the layer that the given vertex belongs to.
  let getLayer (v: IVertex<VisBBlock>) = v.VData.Layer

  /// Sets the layer that the given vertex belongs to.
  let setLayer (v: IVertex<VisBBlock>) layer = v.VData.Layer <- layer

  /// Returns the width of the given vertex.
  let getWidth (v: IVertex<VisBBlock>) = v.VData.Width

  /// Returns the height of the given vertex.
  let getHeight (v: IVertex<VisBBlock>) = v.VData.Height

  /// Returns the x position of the given vertex.
  let getXPos (v: IVertex<VisBBlock>) = v.VData.Coordinate.X

  /// Returns the y position of the given vertex.
  let getYPos (v: IVertex<VisBBlock>) = v.VData.Coordinate.Y