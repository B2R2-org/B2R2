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

[<RequireQualifiedAccess>]
module internal B2R2.RearEnd.Visualization.CrossMinimization

open B2R2.MiddleEnd.BinGraph

/// The maximum number of iterations.
let [<Literal>] private MaxTrials = 128

let private computeMaxLayer (g: VisGraph) =
  g.FoldVertex((fun maxLayer v -> max (VisGraph.getLayer v) maxLayer), 0)

let private addVertexToLayer (layout: ResizeArray<_>[]) v =
  layout[VisGraph.getLayer v].Add(v)

/// Generates the initial layout of vertices based on their assigned layers.
/// A layout is an array of layers, where each layer is an array of vertices.
let private createInitialLayout g =
  let maxLayer = computeMaxLayer g
  let layerCount = maxLayer + 1
  let layout = Array.init layerCount (fun _ -> ResizeArray())
  g.IterVertex(addVertexToLayer layout)
  layout |> Array.map (fun layer ->
    layer |> Seq.iteri (fun i v -> v.VData.Index <- i)
    layer |> Seq.toArray)

let private getIndex v = (v: IVertex<VisBBlock>).VData.Index

let private computeBarycenterFromNeighbors neighbors =
  if Array.isEmpty neighbors then
    System.Double.MaxValue
  else
    let sum = Seq.sumBy getIndex neighbors
    let neighborCount = neighbors.Length
    float sum / float neighborCount

let private computeBarycenter g isDown v =
  let fnGetNeighbors =
    if isDown then (g: IDiGraph<_, _>).GetPreds
    else g.GetSuccs
  let neighbors = fnGetNeighbors v
  let barycenter = computeBarycenterFromNeighbors neighbors
  barycenter, v

let private reorderLayerByBarycenter g (layout: _[][]) isDown layer =
  let vertices = layout[layer]
  vertices
  |> Array.map (computeBarycenter g isDown)
  |> Array.sortBy fst
  |> Array.mapi (fun i (_, v) -> i, v)
  |> Array.fold (fun changed (i, v) ->
    let changed = changed || vertices[i] <> v
    vertices[i] <- v
    v.VData.Index <- i
    changed) false

let private phase1 g layout isDown from maxLayer =
  let layers =
    if isDown then [ from .. maxLayer ]
    else [ from .. -1 .. 0 ]
  List.fold (fun changed layer ->
    reorderLayerByBarycenter g layout isDown layer || changed) false layers

let rec private findLeastPoweredUpperBound value minimum =
  if value >= minimum then value
  else findLeastPoweredUpperBound (value <<< 1) minimum

let rec private climbUpTree (tree: int[]) cnt treeIndex =
  if treeIndex <= 0 then cnt, tree
  else
    let cnt =
      if treeIndex % 2 = 0 then (* Right child. *)
        cnt
      else (* Left child. *)
        cnt + tree[treeIndex + 1]
    let parentTreeIndex = (treeIndex - 1) / 2
    tree[parentTreeIndex] <- tree[parentTreeIndex] + 1
    climbUpTree tree cnt parentTreeIndex

let private allocateCompleteBinaryTree size =
  let v = findLeastPoweredUpperBound 1 size
  let treeSize = 2 * v - 1
  let leafStartingIndex = v - 1
  let tree = Array.zeroCreate treeSize
  tree, leafStartingIndex

let private countInversion (indices: _ list) layerSize =
  let tree, leafStartingIndex = allocateCompleteBinaryTree layerSize
  let cnt, _ =
    List.fold (fun (cnt, tree) index ->
      let treeIndex = leafStartingIndex + index
      (tree: _[])[treeIndex] <- tree[treeIndex] + 1
      climbUpTree tree cnt treeIndex) (0, tree) indices
  cnt

let private collectEdgeIndexPairs (layout: _[]) fnGetNeighbors layoutNum =
  Array.fold (fun (acc, i) v ->
    fnGetNeighbors v
    |> Array.fold (fun acc w -> (i, getIndex w) :: acc) acc,
    i + 1) ([], 0) layout[layoutNum]

/// Counts the number of edge crossings between two adjacent layers in the
/// layout. We are interested in the indices of endpoints who are located in the
/// current layer.
let private countBilayerEdgeCrossings (g: IDiGraph<_, _>) layout isDown
                                      layerNum =
  let layer = (layout: _[])[layerNum]
  let pairs, _ =
    if isDown then
      collectEdgeIndexPairs layout g.GetSuccs (layerNum - 1)
    else
      collectEdgeIndexPairs layout g.GetPreds (layerNum + 1)
  let pairs = List.sort pairs
  let endpoints = List.map snd pairs
  countInversion endpoints (Array.length layer)

let private collectBaryCenters bcByValues (bc, v) =
  match Map.tryFind bc bcByValues with
  | Some(vs) -> Map.add bc (v :: vs) bcByValues
  | None -> Map.add bc [ v ] bcByValues

let private reorderVertices (vertices: IVertex<VisBBlock>[]) idx (_, vs) =
  List.fold (fun i v ->
    vertices[i] <- v; v.VData.Index <- i; i + 1) idx vs

let private reverseOneLayer g layout isDown maxLayer layerNum =
  if countBilayerEdgeCrossings g layout isDown layerNum = 0 then false
  else
    let layer = layout[layerNum]
    let baryCenters = Array.map (computeBarycenter g isDown) layer
    let bcByValues = Array.fold collectBaryCenters Map.empty baryCenters
    let isReversed = Map.exists (fun _ vs -> List.length vs > 1) bcByValues
    let bcByValues = Map.toList bcByValues
    let bcByValues = List.sortBy fst bcByValues
    List.fold (reorderVertices layer) 0 bcByValues |> ignore
    if not isReversed then false
    else phase1 g layout isDown layerNum maxLayer

let private phase2 g layout isDown maxLayer =
  let layers =
    if isDown then [ 1 .. maxLayer ]
    else [ maxLayer - 1 .. -1 .. 0 ]
  layers |> List.fold (fun changed layer ->
     reverseOneLayer g layout isDown maxLayer layer || changed) false

let rec private performSugiyamaReorder g trials layout =
  if trials = MaxTrials then layout
  else
    let maxLayer = Array.length layout - 1
    let changed =
      [ phase1 g layout true 1 maxLayer
        phase1 g layout false (maxLayer - 1) maxLayer
        phase2 g layout false maxLayer
        phase2 g layout true maxLayer ]
      |> List.fold (fun changed b -> b || changed) false
    if not changed then layout
    else performSugiyamaReorder g (trials + 1) layout

let run g =
  createInitialLayout g
  |> performSugiyamaReorder g 0
