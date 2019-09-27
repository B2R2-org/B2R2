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

module internal B2R2.Visualization.CoordAssignment

open System
open System.Collections.Generic
open B2R2.BinGraph

type VDirection =
  | Topmost
  | Bottommost

type HDirection =
  | Leftmost
  | Rightmost

type VertexMap = Dictionary<Vertex<VisBBlock>, Vertex<VisBBlock>>
type FloatMap = Dictionary<Vertex<VisBBlock>, float>

/// The horizontal interval of two consecutive blocks.
[<Literal>]
let private blockIntervalX = 50.0

/// The vertical interval of two consecutive blocks.
[<Literal>]
let private blockIntervalY = 100.0

/// Inner segment is an edge between two dummy nodes
let findIncidentInnerSegmentNode (v: Vertex<VisBBlock>) =
  if v.VData.IsDummy then
    VisGraph.getPreds v |> List.tryFind (fun v -> v.VData.IsDummy)
  else None

let pairID (u: Vertex<VisBBlock>) (v: Vertex<VisBBlock>) =
  if u.VData.Layer > v.VData.Layer then u, v
  else v, u

let addConflict (u: Vertex<VisBBlock>) (v: Vertex<VisBBlock>) conflicts =
  Set.add (pairID u v) conflicts

let checkConflict (u: Vertex<VisBBlock>) (v: Vertex<VisBBlock>) conflicts =
  Set.contains (pairID u v) conflicts

/// Type1 conflict means inner segment and non-inner segment are crossing
let markTypeOneConflict k0 k1 conflicts (v: Vertex<_>) =
  let mark conflicts u =
    let k = VisGraph.getIndex u
    if k < k0 || k1 < k then addConflict u v conflicts
    else conflicts
  List.fold mark conflicts <| VisGraph.getPreds v

let rec findTypeOneConflictLoop upperLen vertices conflicts l k0 l1 =
  if l1 = Array.length vertices then conflicts
  else
    let v = vertices.[l1]
    let w = findIncidentInnerSegmentNode v
    if w.IsSome || l1 = Array.length vertices - 1 then
      let k1 = if w.IsSome then Option.get w |> VisGraph.getIndex else upperLen
      let conflicts =
        Array.fold (markTypeOneConflict k0 k1) conflicts vertices.[l .. l1]
      findTypeOneConflictLoop upperLen vertices conflicts (l1 + 1) k1 (l1 + 1)
    else
      findTypeOneConflictLoop upperLen vertices conflicts l k0 (l1 + 1)

let findTypeOneConflictAux (vLayout: _ [][]) conflicts (layer, vertices) =
  if layer > 0 && layer < Array.length vLayout - 1 then
    let nUpperVertices = Array.length vLayout.[layer - 1]
    findTypeOneConflictLoop nUpperVertices vertices conflicts 0 -1 0
  else conflicts

/// Alg 1 of Brandes et al.
let findTypeOneConflict vLayout =
  Array.mapi (fun layer vertices -> layer, vertices) vLayout
  |> Array.fold (findTypeOneConflictAux vLayout) Set.empty

let getLayerByDirection (vLayout: Vertex<_> [][]) idx = function
  | Leftmost -> vLayout.[idx]
  | Rightmost -> Array.rev vLayout.[idx]

let getMedianNeighbors (sortedNeighbors: Vertex<VisBBlock> []) hDir =
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
let vAlign vGraph vLayout maxLayer conflicts vDir hDir =
  let layers, neighborFn =
    match vDir with
    | Topmost ->
      [0 .. (maxLayer - 1)], (fun (v: Vertex<VisBBlock>) -> v.Preds)
    | Bottommost ->
      [(maxLayer - 1) .. -1 .. 0], (fun (v: Vertex<VisBBlock>) -> v.Succs)
  let root = VertexMap ()
  let align = VertexMap ()
  (vGraph: VisGraph).IterVertex (fun v -> root.[v] <- v; align.[v] <- v)
  layers
  |> List.iter (fun i ->
    let vertices = getLayerByDirection vLayout i hDir
    let mutable r =
      match hDir with
      | Leftmost -> Int32.MinValue
      | Rightmost -> Int32.MaxValue
    for v in vertices do
      let neighbors = neighborFn v
      if List.isEmpty neighbors then ()
      else
        let neighbors = Array.ofList neighbors |> Array.sortBy VisGraph.getIndex
        let medians = getMedianNeighbors neighbors hDir
        for m in medians do
          let w = neighbors.[m]
          if align.[v] = v
            && not (checkConflict w v conflicts)
            && isBefore r (VisGraph.getIndex w) hDir
          then
            align.[w] <- v
            root.[v] <- root.[w]
            align.[v] <- root.[v]
            r <- VisGraph.getIndex w
          else ()
        done
    done)
  root, align

let inBound (v: Vertex<VisBBlock>) counts = function
  | Leftmost -> v.VData.Index > 0
  | Rightmost -> v.VData.Index < counts - 1

let getPred (vertices: Vertex<VisBBlock> []) idx = function
  | Leftmost -> vertices.[idx - 1]
  | Rightmost -> vertices.[idx + 1]

let fixShift (xs: FloatMap) (shift: FloatMap) (sink: VertexMap) u v = function
  | Leftmost ->
    shift.[sink.[u]] <-
      min (shift.[sink.[u]]) (xs.[v] - xs.[u] - u.VData.Width - blockIntervalX)
  | Rightmost ->
    shift.[sink.[u]] <-
      max (shift.[sink.[u]]) (xs.[v] - xs.[u] + v.VData.Width + blockIntervalX)

let adjustX (xs: FloatMap) u v = function
  | Leftmost ->
    xs.[v] <- max xs.[v] (xs.[u] + u.VData.Width + blockIntervalX)
  | Rightmost ->
    xs.[v] <-
      min xs.[v] (xs.[u] - v.VData.Width - u.VData.Width - blockIntervalX)

let rec placeBlock vLayout hDir root align sink shift xs v =
  if not (Double.IsNaN (xs: FloatMap).[v]) then ()
  else
    let mutable w = v
    xs.[v] <- 0.0
    updateBlock vLayout hDir root align sink shift xs v w
    w <- (align: VertexMap).[w]
    while w <> v do
      updateBlock vLayout hDir root align sink shift xs v w
      w <- (align: VertexMap).[w]
and updateBlock vLayout hDir root align sink shift xs v w =
  let vertices = (vLayout: Vertex<_> [][]).[VisGraph.getLayer w]
  if inBound w vertices.Length hDir then
    let idx = Array.findIndex (fun v -> v = w) vertices
    let u = (root: VertexMap).[getPred vertices idx hDir]
    placeBlock vLayout hDir root align sink shift xs u
    if (sink: VertexMap).[v] = v then sink.[v] <- sink.[u] else ()
    if sink.[v] <> sink.[u] then fixShift xs shift sink u v hDir
    else adjustX xs u v hDir
  else ()

/// Alg 3 of Brandes et al.
let hCompact vGraph vLayout (root: VertexMap) (align: VertexMap) hDir =
  let sink = VertexMap ()
  let shift = FloatMap ()
  let xs = FloatMap ()
  (vGraph: VisGraph).IterVertex (fun v ->
    sink.[v] <- v
    shift.[v] <-
      if hDir = Leftmost then Double.PositiveInfinity
      else Double.NegativeInfinity
    xs.[v] <- Double.NaN
  )
  vGraph.IterVertex (fun v ->
    if root.[v] = v then placeBlock vLayout hDir root align sink shift xs v
    else ()
  )
  vGraph.IterVertex (fun v ->
    xs.[v] <- xs.[root.[v]]
    let s = shift.[sink.[root.[v]]]
    if s < Double.PositiveInfinity && s > Double.NegativeInfinity then
      xs.[v] <- xs.[v] + s
    else ()
  )
  xs

let alignAndCompact vGraph vLayout maxLayer conflicts vDir hDir =
  let root, align = vAlign vGraph vLayout maxLayer conflicts vDir hDir
  hCompact vGraph vLayout root align hDir

let calcPosInfo (xs: FloatMap) acc (vertices: Vertex<_> []) =
  let left = xs.[vertices.[0]]
  let width = xs.[vertices.[Array.length vertices - 1]] - xs.[vertices.[0]]
  (left, width) :: acc

let getIndexInfo vLayout (xs: FloatMap) =
  let posInfos = Array.fold (calcPosInfo xs) [] vLayout
  let lefts, widths = List.unzip posInfos
  List.min lefts, List.min widths

let assign vLayout xAlignments =
  let posInfos = List.map (getIndexInfo vLayout) xAlignments
  let minLeft, _ = List.minBy (fun (_, width) -> width) posInfos
  List.iter (fun ((left, _), xs: FloatMap) ->
    xs.Keys
    |> Seq.toArray
    |> Array.iter (fun k ->
      xs.[k] <- xs.[k] + minLeft - left))
      (List.zip posInfos xAlignments)
  xAlignments

let collectX xPerV (xs: FloatMap) =
  xs.Keys
  |> Seq.fold (fun xPerV v ->
    match Map.tryFind v xPerV with
    | Some (acc) -> Map.add v (xs.[v] :: acc) xPerV
    | None -> Map.add v [xs.[v]] xPerV) xPerV

let setXPos (v: Vertex<VisBBlock>) x =
  let vData = v.VData
  vData.Coordinate.X <- x

let averageMedian (xAlignments: FloatMap list) =
  let xPerV = List.fold collectX Map.empty xAlignments
  let xPerV = Map.map (fun v xs -> List.toArray xs) xPerV
  let xPerV = Map.map (fun v xs -> Array.sort xs) xPerV
  let medians =
    Map.map (fun v (xs: float []) -> (xs.[1] + xs.[2]) / 2.0) xPerV
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
  let conflicts = findTypeOneConflict vLayout
  [ alignAndCompact vGraph vLayout maxLayer conflicts Topmost Leftmost
    alignAndCompact vGraph vLayout maxLayer conflicts Topmost Rightmost
    alignAndCompact vGraph vLayout maxLayer conflicts Bottommost Leftmost
    alignAndCompact vGraph vLayout maxLayer conflicts Bottommost Rightmost ]
  |> assign vLayout
  |> averageMedian

let assignYCoordinate y vertices =
  Array.iter (fun (v: Vertex<VisBBlock>) ->
    let vData = v.VData
    vData.Coordinate.Y <- y) vertices
  let maxHeight = Array.map VisGraph.getHeight vertices |> Array.max
  y + maxHeight + blockIntervalY

let assignYCoordinates vLayout =
  let maxLayer = Array.length vLayout - 1
  List.map (fun layer -> vLayout.[layer]) [ 0 .. maxLayer ]
  |> List.fold assignYCoordinate 0.0 |> ignore

let adjustXCoordinate (v: Vertex<VisBBlock>) =
  let coord = v.VData.Coordinate
  coord.X <- coord.X - v.VData.Width / 2.0

let getLeftCoordinate xs (v: Vertex<VisBBlock>) =
  let vData = v.VData
  if vData.IsDummy then xs
  else vData.Coordinate.X :: xs

let getRightCoordinate xs (v: Vertex<VisBBlock>) =
  let vData = v.VData
  if vData.IsDummy then xs
  else (vData.Coordinate.X + vData.Width) :: xs

let shiftXCoordinate shift (v: Vertex<VisBBlock>) =
  let vData = v.VData
  vData.Coordinate.X <- vData.Coordinate.X - shift

let adjustCoordinates (vGraph: VisGraph) =
  vGraph.IterVertex adjustXCoordinate
  let leftMost = vGraph.FoldVertex getLeftCoordinate [] |> List.min
  let rightMost = vGraph.FoldVertex getRightCoordinate [] |> List.max
  let width = rightMost - leftMost
  shiftXCoordinate (rightMost - width / 2.0) |> vGraph.IterVertex

let assignCoordinates vGraph vLayout =
  assignXCoordinates vGraph vLayout
  assignYCoordinates vLayout
  adjustCoordinates vGraph
