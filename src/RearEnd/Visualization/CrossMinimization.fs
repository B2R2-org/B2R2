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
  layout
  |> Array.map (fun layer ->
    Array.init layer.Count (fun i ->
      let v = layer[i]
      v.VData.Index <- i
      v
    )
  )

let private getIndex v = (v: IVertex<VisBBlock>).VData.Index

let private computeBarycenterFromNeighbors neighbors =
  if Array.isEmpty neighbors then
    System.Double.MaxValue
  else
    let sum = Array.sumBy getIndex neighbors
    let neighborCount = neighbors.Length
    float sum / float neighborCount

let private computeBarycenter g isDown v =
  let fnGetNeighbors =
    if isDown then (g: IDiGraph<_, _>).GetPreds
    else g.GetSuccs
  let neighbors = fnGetNeighbors v
  let barycenter = computeBarycenterFromNeighbors neighbors
  barycenter, v

let private barycenterSortKey (barycenter, v: IVertex<VisBBlock>) =
  barycenter, getIndex v

let private writeVerticesToLayer (layer: _[]) (vertices: _[]) =
  let mutable changed = false
  for i = 0 to vertices.Length - 1 do
    let v: IVertex<VisBBlock> = vertices[i]
    if layer[i] <> v then changed <- true else ()
    layer[i] <- v
    v.VData.Index <- i
  changed

let private reorderLayerByBarycenter g (layout: _[][]) isDown layer =
  let vertices = layout[layer]
  let barycenters = vertices |> Array.map (computeBarycenter g isDown)
  barycenters |> Array.sortInPlaceBy barycenterSortKey
  barycenters |> Array.map snd |> writeVerticesToLayer vertices

let private phase1 g layout isDown from maxLayer =
  let mutable changed = false
  if isDown then
    for layer = from to maxLayer do
      changed <- reorderLayerByBarycenter g layout isDown layer || changed
  else
    for layer = from downto 0 do
      changed <- reorderLayerByBarycenter g layout isDown layer || changed
  changed

/// Checks if there is an edge crossing between two adjacent layers in the
/// layout. We only need a boolean answer in phase2, so tracking the running
/// maximum target index is enough.
let private hasBilayerEdgeCrossing (g: IDiGraph<_, _>) layout isDown layerNum =
  let vertices =
    if isDown then
      (layout: _[][])[layerNum - 1]
    else
      layout[layerNum + 1]
  let fnGetNeighbors =
    if isDown then (g: IDiGraph<_, _>).GetSuccs
    else g.GetPreds
  let mutable found = false
  let mutable prefixMax = -1
  let mutable i = 0
  while not found && i < vertices.Length do
    let neighbors = fnGetNeighbors vertices[i]
    if neighbors.Length > 0 then
      let mutable localMin = System.Int32.MaxValue
      let mutable localMax = System.Int32.MinValue
      for j = 0 to neighbors.Length - 1 do
        let idx = getIndex neighbors[j]
        if idx < localMin then localMin <- idx else ()
        if idx > localMax then localMax <- idx else ()
      if localMin < prefixMax then
        found <- true
      elif localMax > prefixMax then
        prefixMax <- localMax
      else
        ()
    else
      ()
    i <- i + 1
  found

let private countBilayerEdgeCrossings g (layout: _[][]) isDown layerNum =
  let vertices =
    if isDown then
      layout[layerNum - 1]
    else
      layout[layerNum + 1]
  let fnGetNeighbors =
    if isDown then (g: IDiGraph<_, _>).GetSuccs
    else g.GetPreds
  let targetCount = layout[layerNum].Length
  let bit = Array.zeroCreate (targetCount + 1)
  let inline add idx =
    let mutable i = idx + 1
    while i < bit.Length do
      bit[i] <- bit[i] + 1
      i <- i + (i &&& -i)
  let inline sum idx =
    let mutable acc = 0
    let mutable i = idx + 1
    while i > 0 do
      acc <- acc + bit[i]
      i <- i - (i &&& -i)
    acc
  let mutable seen = 0
  let mutable crossings = 0L
  for i = 0 to vertices.Length - 1 do
    let neighbors =
      fnGetNeighbors vertices[i]
      |> Array.map getIndex
    Array.sortInPlace neighbors
    for j = 0 to neighbors.Length - 1 do
      let idx = neighbors[j]
      crossings <- crossings + int64 (seen - sum idx)
      add idx
      seen <- seen + 1
  crossings

let private buildReversedTieLayer (baryCenters: _[]) =
  let reordered = Array.zeroCreate baryCenters.Length
  let mutable hasTie = false
  let mutable dst = 0
  let mutable start = 0
  while start < baryCenters.Length do
    let bc, _ = baryCenters[start]
    let mutable finish = start + 1
    while finish < baryCenters.Length && fst baryCenters[finish] = bc do
      finish <- finish + 1
    if finish - start > 1 then
      hasTie <- true
      for i = finish - 1 downto start do
        let _, (v: IVertex<VisBBlock>) = baryCenters[i]
        reordered[dst] <- v
        dst <- dst + 1
    else
      let _, v = baryCenters[start]
      reordered[dst] <- v
      dst <- dst + 1
    start <- finish
  hasTie, reordered

let private reverseOneLayer g layout isDown maxLayer layerNum =
  if not (hasBilayerEdgeCrossing g layout isDown layerNum) then
    false
  else
    let layer = layout[layerNum]
    let baryCenters = Array.map (computeBarycenter g isDown) layer
    baryCenters |> Array.sortInPlaceBy barycenterSortKey
    let hasTie, candidate = buildReversedTieLayer baryCenters
    if not hasTie then false
    else
      let before = countBilayerEdgeCrossings g layout isDown layerNum
      let original = Array.copy layer
      let changed = writeVerticesToLayer layer candidate
      if not changed then false
      else
        let after = countBilayerEdgeCrossings g layout isDown layerNum
        if after >= before then
          writeVerticesToLayer layer original |> ignore
          false
        else
          phase1 g layout isDown layerNum maxLayer || changed

let private phase2 g layout isDown maxLayer =
  let mutable changed = false
  if isDown then
    for layer = 1 to maxLayer do
      changed <- reverseOneLayer g layout isDown maxLayer layer || changed
  else
    for layer = maxLayer - 1 downto 0 do
      changed <- reverseOneLayer g layout isDown maxLayer layer || changed
  changed

let rec private performSugiyamaReorder g trials layout =
  if trials = MaxTrials then
    layout
  else
    let maxLayer = Array.length layout - 1
    let changed1 = phase1 g layout true 1 maxLayer
    let changed2 = phase1 g layout false (maxLayer - 1) maxLayer
    let changed3 = phase2 g layout false maxLayer
    let changed4 = phase2 g layout true maxLayer
    let changed = changed1 || changed2 || changed3 || changed4
    if not changed then layout
    else performSugiyamaReorder g (trials + 1) layout

let run g =
  createInitialLayout g
  |> performSugiyamaReorder g 0
