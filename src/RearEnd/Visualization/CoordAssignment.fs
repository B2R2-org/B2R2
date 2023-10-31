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

module internal B2R2.RearEnd.Visualization.CoordAssignment

open System
open System.Collections.Generic
open B2R2.MiddleEnd.BinGraph

type VDirection =
  | Topmost
  | Bottommost

type HDirection =
  | Leftmost
  | Rightmost

type VertexMap = Dictionary<IVertex<VisBBlock>, IVertex<VisBBlock>>
type FloatMap = Dictionary<IVertex<VisBBlock>, float>

/// The horizontal interval of two consecutive blocks.
[<Literal>]
let private BlockIntervalX = 50.0

/// The vertical interval of two consecutive blocks.
[<Literal>]
let private BlockIntervalY = 100.0

/// Inner segment is an edge between two dummy nodes
let findIncidentInnerSegmentNode vGraph (v: IVertex<VisBBlock>) =
  if v.VData.IsDummy then
    VisGraph.getPreds vGraph v |> Seq.tryFind (fun v -> v.VData.IsDummy)
  else None

let pairID (u: IVertex<VisBBlock>) (v: IVertex<VisBBlock>) =
  if u.VData.Layer > v.VData.Layer then u, v
  else v, u

let addConflict (u: IVertex<VisBBlock>) (v: IVertex<VisBBlock>) conflicts =
  Set.add (pairID u v) conflicts

let checkConflict (u: IVertex<VisBBlock>) (v: IVertex<VisBBlock>) conflicts =
  Set.contains (pairID u v) conflicts

/// Type1 conflict means inner segment and non-inner segment are crossing
let markTypeOneConflict vGraph k0 k1 conflicts (v: IVertex<_>) =
  let mark conflicts u =
    let k = VisGraph.getIndex u
    if k < k0 || k1 < k then addConflict u v conflicts
    else conflicts
  Seq.fold mark conflicts <| VisGraph.getPreds vGraph v

let rec findTypeOneConflictLoop vGraph upperLen vertices conflicts l k0 l1 =
  if l1 = Array.length vertices then conflicts
  else
    let v = vertices[l1]
    let w = findIncidentInnerSegmentNode vGraph v
    if w.IsSome || l1 = Array.length vertices - 1 then
      let k1 = if w.IsSome then Option.get w |> VisGraph.getIndex else upperLen
      let conflicts =
        vertices[l .. l1]
        |> Array.fold (markTypeOneConflict vGraph k0 k1) conflicts
      findTypeOneConflictLoop
        vGraph upperLen vertices conflicts (l1 + 1) k1 (l1 + 1)
    else
      findTypeOneConflictLoop vGraph upperLen vertices conflicts l k0 (l1 + 1)

let findTypeOneConflictAux vGraph (vLayout: _[][]) conflicts (layer, vertices) =
  if layer > 0 && layer < Array.length vLayout - 1 then
    let nUpperVertices = Array.length vLayout[layer - 1]
    findTypeOneConflictLoop vGraph nUpperVertices vertices conflicts 0 -1 0
  else conflicts

/// Alg 1 of Brandes et al.
let findTypeOneConflict vGraph vLayout =
  Array.mapi (fun layer vertices -> layer, vertices) vLayout
  |> Array.fold (findTypeOneConflictAux vGraph vLayout) Set.empty

let getLayerByDirection (vLayout: IVertex<_>[][]) idx = function
  | Leftmost -> vLayout[idx]
  | Rightmost -> Array.rev vLayout[idx]

let getMedianNeighbors (sortedNeighbors: IVertex<VisBBlock>[]) hDir =
  let middle = float (sortedNeighbors.Length - 1) / 2.0
  let a = int (floor middle)
  let b = int (ceil middle)
  match hDir with
  | _ when a = b -> [ a ]
  | Leftmost -> [ a; b ]
  | Rightmost -> [ b; a ]

let isBefore a b = function
  | Leftmost -> a < b
  | Rightmost -> a > b

/// Alg 2 of Brandes et al.
let vAlign (vGraph: IGraph<_, _>) vLayout maxLayer conflicts vDir hDir =
  let layers, neighborFn =
    match vDir with
    | Topmost ->
      [0 .. (maxLayer - 1)], (fun v -> vGraph.GetPreds v)
    | Bottommost ->
      [(maxLayer - 1) .. -1 .. 0], (fun v -> vGraph.GetSuccs v)
  let root = VertexMap ()
  let align = VertexMap ()
  (vGraph: VisGraph).IterVertex (fun v -> root[v] <- v; align[v] <- v)
  layers
  |> List.iter (fun i ->
    let vertices = getLayerByDirection vLayout i hDir
    let mutable r =
      match hDir with
      | Leftmost -> Int32.MinValue
      | Rightmost -> Int32.MaxValue
    for v in vertices do
      let neighbors = neighborFn v
      if neighbors.Count = 0 then ()
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
          else ()
        done
    done)
  root, align

let inBound (v: IVertex<VisBBlock>) counts = function
  | Leftmost -> v.VData.Index > 0
  | Rightmost -> v.VData.Index < counts - 1

let getPred (vertices: IVertex<VisBBlock>[]) idx = function
  | Leftmost -> vertices[idx - 1]
  | Rightmost -> vertices[idx + 1]

let fixShift (xs: FloatMap) (shift: FloatMap) (sink: VertexMap) u v = function
  | Leftmost ->
    shift[sink[u]] <-
      min (shift[sink[u]])
          (xs[v] - xs[u] - u.VData.Width - BlockIntervalX)
  | Rightmost ->
    shift[sink[u]] <-
      max (shift[sink[u]])
          (xs[v] - xs[u] + v.VData.Width + BlockIntervalX)

let adjustX (xs: FloatMap) u v = function
  | Leftmost ->
    xs[v] <-
      max xs[v]
          (xs[u] + u.VData.Width
                 + v.VData.Width / 2.0
                 + BlockIntervalX)
  | Rightmost ->
    xs[v] <-
      min xs[v]
          (xs[u] - v.VData.Width
                 - u.VData.Width / 2.0
                 - BlockIntervalX)

let rec placeBlock vLayout hDir root align sink shift (xs: FloatMap) v =
  if not (Double.IsNaN xs[v]) then ()
  else
    let mutable w = v
    xs[v] <- 0.0
    updateBlock vLayout hDir root align sink shift xs v w
    w <- align[w]
    while w <> v do
      updateBlock vLayout hDir root align sink shift xs v w
      w <- align[w]
and updateBlock vLayout hDir root (align: VertexMap) sink shift xs v w =
  let vertices = (vLayout: IVertex<_>[][])[VisGraph.getLayer w]
  if inBound w vertices.Length hDir then
    let idx = Array.findIndex (fun v -> v = w) vertices
    let u = (root: VertexMap)[getPred vertices idx hDir]
    placeBlock vLayout hDir root align sink shift xs u
    if (sink: VertexMap)[v] = v then sink[v] <- sink[u] else ()
    if sink[v] <> sink[u] then fixShift xs shift sink u v hDir
    else adjustX xs u v hDir
  else ()

/// Alg 3 of Brandes et al.
let hCompact vGraph vLayout (root: VertexMap) (align: VertexMap) hDir =
  let sink = VertexMap ()
  let shift = FloatMap ()
  let xs = FloatMap ()
  (vGraph: VisGraph).IterVertex (fun v ->
    sink[v] <- v
    shift[v] <-
      if hDir = Leftmost then Double.PositiveInfinity
      else Double.NegativeInfinity
    xs[v] <- Double.NaN
  )
  vGraph.IterVertex (fun v ->
    if root[v] = v then placeBlock vLayout hDir root align sink shift xs v
    else ()
  )
  vGraph.IterVertex (fun v ->
    xs[v] <- xs[root[v]]
    let s = shift[sink[root[v]]]
    if s < Double.PositiveInfinity && s > Double.NegativeInfinity then
      xs[v] <- xs[v] + s
    else ()
  )
  xs, hDir

let alignAndCompact vGraph vLayout maxLayer conflicts vDir hDir =
  let root, align = vAlign vGraph vLayout maxLayer conflicts vDir hDir
  hCompact vGraph vLayout root align hDir

let getBound vLayout (xs: FloatMap, hDir) =
  vLayout
  |> Array.fold (fun (minWidth, bound) (vertices: IVertex<_>[]) ->
    let left = xs[vertices[0]]
    let last = vertices[vertices.Length - 1]
    let right = xs[last] + last.VData.Width
    let width = right - left
    if width < minWidth then minWidth, if hDir = Leftmost then left else right
    else minWidth, bound) (Double.PositiveInfinity, 0.0)
  |> fun (_, bound) -> bound, xs, hDir

let alignToSmallestWidth vLayout xAlignments =
  List.map (getBound vLayout) xAlignments
  |> List.iter (fun (bound, xs: FloatMap, hDir) ->
    let delta =
      if hDir = Leftmost then bound - Seq.min xs.Values
      else bound - Seq.max xs.Values
    xs.Keys
    |> Seq.toArray
    |> Array.iter (fun k -> xs[k] <- xs[k] + delta))
  xAlignments
  |> List.map fst

let collectX xPerV (xs: FloatMap) =
  xs.Keys
  |> Seq.fold (fun xPerV v ->
    match Map.tryFind v xPerV with
    | Some (acc) -> Map.add v (xs[v] :: acc) xPerV
    | None -> Map.add v [xs[v]] xPerV) xPerV

let setXPos (v: IVertex<VisBBlock>) x =
  v.VData.Coordinate.X <- x

let averageMedian (xAlignments: FloatMap list) =
  let xPerV = List.fold collectX Map.empty xAlignments
  let xPerV = Map.map (fun v xs -> List.toArray xs) xPerV
  let xPerV = Map.map (fun v xs -> Array.sort xs) xPerV
  let medians =
    Map.map (fun v (xs: float[]) -> (xs[1] + xs[2]) / 2.0) xPerV
  let xs = Map.fold (fun xs _ x -> x :: xs) [] medians
  let minX = List.min xs
  let maxX = List.max xs
  let mid = minX + maxX / 2.0
  let medians = Map.map (fun _ xs -> xs - mid) medians
  Map.iter setXPos medians

/// This algorithm is from Brandes et al., Fast and Simple Horizontal Coordinate
/// Assignment.
let assignXCoordinates (vGraph: VisGraph) vLayout =
  let maxLayer = Array.length vLayout - 1
  let conflicts = findTypeOneConflict vGraph vLayout
  [ alignAndCompact vGraph vLayout maxLayer conflicts Topmost Leftmost
    alignAndCompact vGraph vLayout maxLayer conflicts Topmost Rightmost
    alignAndCompact vGraph vLayout maxLayer conflicts Bottommost Leftmost
    alignAndCompact vGraph vLayout maxLayer conflicts Bottommost Rightmost ]
  |> alignToSmallestWidth vLayout
  |> averageMedian

let assignYCoordinate y vertices =
  Array.iter (fun (v: IVertex<VisBBlock>) ->
    v.VData.Coordinate.Y <- y) vertices
  let maxHeight = Array.map VisGraph.getHeight vertices |> Array.max
  y + maxHeight + BlockIntervalY

let assignYCoordinates vLayout =
  let maxLayer = Array.length vLayout - 1
  List.map (fun layer -> vLayout[layer]) [ 0 .. maxLayer ]
  |> List.fold assignYCoordinate 0.0 |> ignore

let adjustXCoordinate (v: IVertex<VisBBlock>) =
  let coord = v.VData.Coordinate
  coord.X <- coord.X - v.VData.Width / 2.0

let getLeftCoordinate xs (v: IVertex<VisBBlock>) =
  let blk = v.VData
  if blk.IsDummy then xs
  else blk.Coordinate.X :: xs

let getRightCoordinate xs (v: IVertex<VisBBlock>) =
  let blk = v.VData
  if blk.IsDummy then xs
  else (blk.Coordinate.X + blk.Width) :: xs

let shiftXCoordinate shift (v: IVertex<VisBBlock>) =
  let blk = v.VData
  blk.Coordinate.X <- blk.Coordinate.X - shift

let adjustCoordinates (vGraph: VisGraph) =
  vGraph.IterVertex adjustXCoordinate
  let leftMost = vGraph.FoldVertex getLeftCoordinate [] |> List.min
  let rightMost = vGraph.FoldVertex getRightCoordinate [] |> List.max
  let width = rightMost - leftMost
  shiftXCoordinate (rightMost - width / 2.0) |> vGraph.IterVertex

let adjustWidthOfDummies (vGraph: VisGraph) =
  let maxWidth =
    vGraph.FoldVertex (fun maxWidth v -> max maxWidth v.VData.Width) 0.0
  vGraph.IterVertex (fun v -> v.VData.Width <- maxWidth)

let assignCoordinates vGraph vLayout =
  adjustWidthOfDummies vGraph
  assignXCoordinates vGraph vLayout
  assignYCoordinates vLayout
  adjustCoordinates vGraph
