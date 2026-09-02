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
module internal B2R2.RearEnd.Visualization.CoordAssignment

open System
open System.Collections.Generic
open B2R2.MiddleEnd.BinGraph

type private VDirection =
  | Topmost
  | Bottommost

type HDirection =
  | Leftmost
  | Rightmost

type private VertexMap = Dictionary<IVertex<VisBBlock>, IVertex<VisBBlock>>

type FloatMap = Dictionary<IVertex<VisBBlock>, float>

/// The horizontal interval of two consecutive blocks.
[<Literal>]
let private BlockIntervalX = 100.0

/// The vertical interval of two consecutive blocks.
[<Literal>]
let private BlockIntervalY = 100.0

/// Threshold (in pixels) for correcting singleton-layer node positions.
/// When a layer contains only a single node, that node does not receive
/// horizontal spacing constraints from same-layer neighbors during the
/// Brandes coordinate assignment. As a result, its X position may become
/// an outlier compared to its connected predecessors/successors.
/// This threshold defines the minimum distance between the node's current
/// center X and the average center X of its neighboring nodes required
/// to trigger a corrective repositioning (pulling it toward neighbors).
let [<Literal>] private SingletonPullThreshold = 300.0

/// Inner segment is an edge between two dummy nodes
let private findIncidentInnerSegmentNode vGraph (v: IVertex<VisBBlock>) =
  if v.VData.IsDummy then
    VisGraph.getPreds vGraph v |> Seq.tryFind (fun v -> v.VData.IsDummy)
  else
    None

let private pairID (u: IVertex<VisBBlock>) (v: IVertex<VisBBlock>) =
  if u.VData.Layer > v.VData.Layer then u.ID, v.ID else v.ID, u.ID

let private addConflict u v conflicts = Set.add (pairID u v) conflicts

let private checkConflict u v conflicts = Set.contains (pairID u v) conflicts

/// Type1 conflict means inner segment and non-inner segment are crossing
let private markTypeOneConflict vGraph k0 k1 conflicts (v: IVertex<_>) =
  let mark conflicts u =
    let k = VisGraph.getIndex u
    if k < k0 || k1 < k then addConflict u v conflicts else conflicts
  Seq.fold mark conflicts <| VisGraph.getPreds vGraph v

let rec private scanConflicts vGraph upperLen vertices conflicts l k0 l1 =
  if l1 = Array.length vertices then
    conflicts
  else
    let v = vertices[l1]
    let w = findIncidentInnerSegmentNode vGraph v
    if w.IsSome || l1 = Array.length vertices - 1 then
      let k1 = if w.IsSome then Option.get w |> VisGraph.getIndex else upperLen
      let conflicts =
        vertices[l..l1]
        |> Array.fold (markTypeOneConflict vGraph k0 k1) conflicts
      scanConflicts vGraph upperLen vertices conflicts (l1 + 1) k1 (l1 + 1)
    else
      scanConflicts vGraph upperLen vertices conflicts l k0 (l1 + 1)

let private addTypeOneConflicts vGraph vLayout conflicts (layer, vertices) =
  if layer > 0 && layer < Array.length vLayout - 1 then
    let nUpperVertices = Array.length vLayout[layer - 1]
    scanConflicts vGraph nUpperVertices vertices conflicts 0 -1 0
  else
    conflicts

/// Alg 1 of Brandes et al.
let private findTypeOneConflicts vGraph vLayout =
  Array.mapi (fun layer vertices -> layer, vertices) vLayout
  |> Array.fold (addTypeOneConflicts vGraph vLayout) Set.empty

let private getLayerByDirection (vLayout: IVertex<_>[][]) idx = function
  | Leftmost -> vLayout[idx]
  | Rightmost -> Array.rev vLayout[idx]

let private getMedianNeighbors (sortedNeighbors: IVertex<VisBBlock>[]) hDir =
  let middle = float (sortedNeighbors.Length - 1) / 2.0
  let a = int (floor middle)
  let b = int (ceil middle)
  match hDir with
  | _ when a = b -> [ a ]
  | Leftmost -> [ a; b ]
  | Rightmost -> [ b; a ]

let private isBefore a b = function
  | Leftmost -> a < b
  | Rightmost -> a > b

/// Alg 2 of Brandes et al.
let private vAlign (vGraph: VisGraph) vLayout maxLayer conflicts vDir hDir =
  let layers, neighborFn =
    match vDir with
    | Topmost -> [ 0 .. (maxLayer - 1) ], vGraph.GetPreds
    | Bottommost -> [ (maxLayer - 1) .. -1 .. 0 ], vGraph.GetSuccs
  let root = VertexMap()
  let align = VertexMap()
  vGraph |> DiGraph.iterVertex (fun v -> root[v] <- v; align[v] <- v)
  layers
  |> List.iter (fun i ->
    let vertices = getLayerByDirection vLayout i hDir
    let mutable r =
      match hDir with
      | Leftmost -> Int32.MinValue
      | Rightmost -> Int32.MaxValue
    for v in vertices do
      let neighbors = neighborFn v
      if neighbors.Length = 0 then
        ()
      else
        let neighbors = Seq.toArray neighbors |> Array.sortBy VisGraph.getIndex
        let medians = getMedianNeighbors neighbors hDir
        for m in medians do
          let w = neighbors[m]
          if align[v] = v
              && not (checkConflict w v conflicts)
              && isBefore r (VisGraph.getIndex w) hDir
          then
            align[w] <- v
            root[v] <- root[w]
            align[v] <- root[v]
            r <- VisGraph.getIndex w
          else
            ()
        done
    done)
  root, align

let private inBound (v: IVertex<VisBBlock>) counts = function
  | Leftmost -> v.VData.Index > 0
  | Rightmost -> v.VData.Index < counts - 1

let private getPred (vertices: IVertex<VisBBlock>[]) idx = function
  | Leftmost -> vertices[idx - 1]
  | Rightmost -> vertices[idx + 1]

/// Compute the maximum width of blocks in the same block. Returns a map from
/// the root block to the maximum width of nodes in the same block.
let private computeBlockMaxWidths (root: VertexMap) (align: VertexMap) =
  let roots = root.Values |> Seq.distinct
  let blockMaxWidths = FloatMap()
  for root in roots do
    let mutable w = root
    let mutable maxWidth = root.VData.Width
    w <- align[w]
    while w <> root do
      maxWidth <- max maxWidth w.VData.Width
      w <- align[w]
    blockMaxWidths[root] <- maxWidth
  blockMaxWidths

let inline private getDelta (blockMaxWidths: FloatMap) u v = function
  | Leftmost -> blockMaxWidths[u] + BlockIntervalX
  | Rightmost -> blockMaxWidths[v] + BlockIntervalX

let fixShift (xs: FloatMap) (shift: FloatMap) (sink: VertexMap) u v delta =
  function
  | Leftmost -> shift[sink[u]] <- min (shift[sink[u]]) (xs[v] - xs[u] - delta)
  | Rightmost -> shift[sink[u]] <- max (shift[sink[u]]) (xs[v] - xs[u] + delta)

let private adjustX (xs: FloatMap) u v delta = function
  | Leftmost -> xs[v] <- max xs[v] (xs[u] + delta)
  | Rightmost -> xs[v] <- min xs[v] (xs[u] - delta)

let rec placeBlock vLayout hDir root align sink shift (xs: FloatMap) maxW v =
  if not (Double.IsNaN xs[v]) then
    ()
  else
    let mutable w = v
    xs[v] <- 0.0
    updateBlock vLayout hDir root align sink shift xs maxW v w
    w <- align[w]
    while w <> v do
      updateBlock vLayout hDir root align sink shift xs maxW v w
      w <- align[w]

and updateBlock vLayout hDir root (align: VertexMap) sink shift xs maxW v w =
  let vertices = (vLayout: IVertex<_>[][])[VisGraph.getLayer w]
  if inBound w vertices.Length hDir then
    let idx = Array.findIndex (fun v -> v = w) vertices
    let pred = getPred vertices idx hDir
    let u = (root: VertexMap)[pred]
    let delta = getDelta maxW u v hDir
    placeBlock vLayout hDir root align sink shift xs maxW u
    if (sink: VertexMap)[v] = v then sink[v] <- sink[u] else ()
    if sink[v] <> sink[u] then fixShift xs shift sink u v delta hDir
    else adjustX xs u v delta hDir
  else
    ()

/// Alg 3 of Brandes et al.
let private hCompact vGraph vLayout root align hDir =
  let sink = VertexMap()
  let shift = FloatMap()
  let xs = FloatMap()
  let blockMaxWidths = computeBlockMaxWidths root align
  (vGraph: VisGraph) |> DiGraph.iterVertex (fun v ->
    sink[v] <- v
    shift[v] <-
      if hDir = Leftmost then Double.PositiveInfinity
      else Double.NegativeInfinity
    xs[v] <- Double.NaN
  )
  (* The first iteration for (1) initializing the shift values and (2)
     x-coordinates of the root blocks. *)
  vGraph |> DiGraph.iterVertex (fun v ->
    if root[v] = v
    then placeBlock vLayout hDir root align sink shift xs blockMaxWidths v
    else ()
  )
  (* The second iteration for assigning the x-coordinates to all blocks. *)
  let newXs = FloatMap()
  vGraph |> DiGraph.iterVertex (fun v ->
    let s = shift[sink[root[v]]]
    let x = xs[root[v]]
    newXs[v] <- if Double.IsFinite(s) then x + s else x
  )
  newXs, hDir

let private alignAndCompact vGraph vLayout maxLayer conflicts vDir hDir =
  let root, align = vAlign vGraph vLayout maxLayer conflicts vDir hDir
  hCompact vGraph vLayout root align hDir

/// Reads the edge of the narrowest layer of the given assignment: its left
/// edge for a leftmost assignment and its right edge for a rightmost one. That
/// edge is what the assignment is shifted onto, so the narrowest layer is the
/// one every layer is measured against.
let getBound vLayout (xs: FloatMap, hDir) =
  vLayout
  |> Array.fold (fun (minWidth, bound) (vertices: IVertex<_>[]) ->
    let first = vertices[0]
    let last = vertices[vertices.Length - 1]
    let left = xs[first]
    let right = xs[last] + last.VData.Width
    let width = right - left
    if width < minWidth then width, (if hDir = Leftmost then left else right)
    else minWidth, bound
  ) (Double.PositiveInfinity, 0.0)
  |> fun (_, bound) -> bound, xs, hDir

let private alignToSmallestWidth vLayout xAlignments =
  List.map (getBound vLayout) xAlignments
  |> List.iter (fun (bound, xs: FloatMap, hDir) ->
    let currentBound =
      match hDir with
      | Leftmost ->
        xs.Keys
        |> Seq.map (fun v -> xs[v])
        |> Seq.min
      | Rightmost ->
        xs.Keys
        |> Seq.map (fun v -> xs[v] + v.VData.Width)
        |> Seq.max
    let delta = bound - currentBound
    xs.Keys
    |> Seq.toArray
    |> Array.iter (fun k -> xs[k] <- xs[k] + delta))
  xAlignments
  |> List.map fst

let private collectX (xPerV: Dictionary<IVertex<VisBBlock>, float list>) xs =
  for v in (xs: FloatMap).Keys do
    match xPerV.TryGetValue v with
    | true, acc -> xPerV[v] <- xs[v] :: acc
    | false, _ -> xPerV[v] <- [ xs[v] ]
  xPerV

/// Returns the median of the given sorted values, which for an even count is
/// the average of the two in the middle. How many alignments there are to take
/// the median of is for the caller enumerating them to know, not for this.
let private medianOf (sorted: float[]) =
  let n = sorted.Length
  if n % 2 = 0 then (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
  else sorted[n / 2]

let private setXPos (v: IVertex<VisBBlock>) x = v.VData.Coordinate.X <- x

(* The median of the alignments, taken per vertex and then shifted so that the
   whole layout is centred on nothing in particular. *)
let averageMedian (xAlignments: FloatMap list) =
  let xPerV = List.fold collectX (Dictionary()) xAlignments
  let medians = FloatMap()
  for KeyValue(v, xs) in xPerV do
    let xs = List.toArray xs
    Array.sortInPlace xs
    medians[v] <- medianOf xs
  let minX = medians.Values |> Seq.min
  let maxX = medians.Values |> Seq.max
  let mid = (minX + maxX) / 2.0
  for KeyValue(v, x) in medians do setXPos v (x - mid)

/// This algorithm is from Brandes et al., Fast and Simple Horizontal Coordinate
/// Assignment.
let private assignXCoordinates (vGraph: VisGraph) vLayout =
  let maxLayer = Array.length vLayout - 1
  let conflicts = findTypeOneConflicts vGraph vLayout
  [ alignAndCompact vGraph vLayout maxLayer conflicts Topmost Leftmost
    alignAndCompact vGraph vLayout maxLayer conflicts Topmost Rightmost
    alignAndCompact vGraph vLayout maxLayer conflicts Bottommost Leftmost
    alignAndCompact vGraph vLayout maxLayer conflicts Bottommost Rightmost ]
  |> alignToSmallestWidth vLayout
  |> averageMedian

let private assignYCoordinate y vertices =
  Array.iter (fun (v: IVertex<VisBBlock>) ->
    v.VData.Coordinate.Y <- y) vertices
  let maxHeight = Array.map VisGraph.getHeight vertices |> Array.max
  y + maxHeight + BlockIntervalY

let private assignYCoordinates vLayout =
  let maxLayer = Array.length vLayout - 1
  List.map (fun layer -> vLayout[layer]) [ 0 .. maxLayer ]
  |> List.fold assignYCoordinate 0.0 |> ignore

/// Returns the horizontal extent of the real vertices of the graph, a dummy
/// having no width to be measured by. Answers None for a graph of nothing but
/// dummies, there being no extent to speak of then.
let private realExtent (vGraph: VisGraph) =
  let mutable leftMost = Double.PositiveInfinity
  let mutable rightMost = Double.NegativeInfinity
  vGraph |> DiGraph.iterVertex (fun (v: IVertex<VisBBlock>) ->
    let blk = v.VData
    if blk.IsDummy then
      ()
    else
      leftMost <- min leftMost blk.Coordinate.X
      rightMost <- max rightMost (blk.Coordinate.X + blk.Width))
  if leftMost > rightMost then None else Some(leftMost, rightMost)

let private shiftXCoordinate shift (v: IVertex<VisBBlock>) =
  let blk = v.VData
  blk.Coordinate.X <- blk.Coordinate.X - shift

let private getCenterX (v: IVertex<VisBBlock>) =
  v.VData.Coordinate.X + v.VData.Width / 2.0

let private adjustIsolatedLayerNodePosition (vGraph: VisGraph) vLayout =
  (vLayout: IVertex<VisBBlock>[][])
  |> Array.iter (fun layer ->
    if layer.Length = 1 then
      let v = layer[0]
      let neighCenters =
        Seq.append (VisGraph.getPreds vGraph v) (VisGraph.getSuccs vGraph v)
        |> Seq.distinct
        |> Seq.map getCenterX
        |> Seq.toArray
      if neighCenters.Length > 0 then
        let targetCenterX = Array.average neighCenters
        let currentCenterX = getCenterX v
        let dx = targetCenterX - currentCenterX
        if abs dx >= SingletonPullThreshold then
          v.VData.Coordinate.X <- targetCenterX - v.VData.Width / 2.0
        else
          ()
      else
        ()
    else
      ())

let adjustCoordinates (vGraph: VisGraph) vLayout =
  adjustIsolatedLayerNodePosition vGraph vLayout
  match realExtent vGraph with
  | Some(leftMost, rightMost) ->
    let width = rightMost - leftMost
    vGraph |> DiGraph.iterVertex (shiftXCoordinate (rightMost - width / 2.0))
  | None ->
    ()

let run vGraph vLayout =
  assignXCoordinates vGraph vLayout
  assignYCoordinates vLayout
  adjustCoordinates vGraph vLayout