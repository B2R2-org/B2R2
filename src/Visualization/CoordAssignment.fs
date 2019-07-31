(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Soomin Kim <soomink@kaist.ac.kr>

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

open B2R2.BinGraph

type VDirection =
  | Topmost
  | Bottommost

type HDirection =
  | Leftmost
  | Rightmost

// The horizontal interval of two consecutive blocks.
[<Literal>]
let private blockIntervalX = 50.0

// The vertical interval of two consecutive blocks.
[<Literal>]
let private blockIntervalY = 100.0

// Inner segment is an edge between two dummy nodes
let hasInnerSegment (v: Vertex<VisBBlock>) =
  if v.VData.IsDummyBlock () then
    VisGraph.getPreds v |> List.exists (fun v -> v.VData.IsDummyBlock ())
  else false

let getInnerPred (v: Vertex<VisBBlock>) =
  VisGraph.getPreds v
  |> List.find (fun v -> v.VData.IsDummyBlock ())

// Type2 conflict means two inner segments are crossing
let markTypeTwoConflict v conflicts v0 =
  if hasInnerSegment v && hasInnerSegment v0 then
    let u = getInnerPred v
    let u0 = getInnerPred v0
    if u.VData.Index < u0.VData.Index then Set.add v conflicts
    else conflicts
  else conflicts

let rec findTypeTwoConflictLoop vertices conflicts i =
  if i = 0 || i = Array.length vertices then conflicts
  else
    let v = vertices.[i]
    let conflicts =
      Array.fold (markTypeTwoConflict v) conflicts vertices.[.. i - 1]
    findTypeTwoConflictLoop vertices conflicts (i + 1)

let findTypeTwoConflict_ conflicts (layer, vertices) =
  if layer > 0 then findTypeTwoConflictLoop vertices conflicts 0 else conflicts

// XXX: We need to resolve typeTwoConflicts before doing further processes
let findTypeTwoConflict vLayout =
  Array.mapi (fun layer vertices -> layer, vertices) vLayout
  |> Array.fold findTypeTwoConflict_ Set.empty

// Type1 conflict means inner segment and non-inner segment are crossing
let markTypeOneConflict_ v0 u0 u1 v conflicts u =
  let vPos = VisGraph.getIndex v
  let uPos = VisGraph.getIndex u
  if vPos < v0 && u0 < uPos then Set.add (u, v) conflicts
  elif v0 <= vPos && (uPos < u0 || u1 < uPos) then Set.add (u, v) conflicts
  else conflicts

let markTypeOneConflict v0 u0 u1 conflicts (v: Vertex<_>) =
  List.fold (markTypeOneConflict_ v0 u0 u1 v) conflicts <| VisGraph.getPreds v

let rec findTypeOneConflictLoop upperLen vertices conflicts v0 u0 i =
  if i = Array.length vertices then conflicts
  else
    let v = vertices.[i]
    if hasInnerSegment v || i = Array.length vertices - 1 then
      let u1 =
        if hasInnerSegment v then getInnerPred v |> VisGraph.getIndex
        else upperLen
      let conflicts =
        Array.fold (markTypeOneConflict v0 u0 u1) conflicts vertices.[.. i]
      let v1 = VisGraph.getIndex v
      findTypeOneConflictLoop upperLen vertices conflicts v1 u1 (i + 1)
    else
      findTypeOneConflictLoop upperLen vertices conflicts v0 u0 (i + 1)

let findTypeOneConflict_ (vLayout: _ [] []) conflicts (layer, vertices) =
  if layer > 0 then
    let nUpperVertices = Array.length vLayout.[layer - 1]
    findTypeOneConflictLoop nUpperVertices vertices conflicts -1 -1 0
  else conflicts

let findTypeOneConflict vLayout =
  Array.mapi (fun layer vertices -> layer, vertices) vLayout
  |> Array.fold (findTypeOneConflict_ vLayout) Set.empty

let preprocess vLayout =
  let typeTwoConflicts = findTypeTwoConflict vLayout
  let typeOneConflicts = findTypeOneConflict vLayout
#if DEBUG
  VisDebug.logn "TypeTwoConflicts:"
  typeTwoConflicts
  |> Set.iter (fun v -> sprintf "%d" <| VisGraph.getID v |> VisDebug.logn)
  VisDebug.logn "TypeOneConflicts:"
  typeOneConflicts
  |> Set.iter (fun (v, w) ->
    sprintf "%d %d" (VisGraph.getID v) (VisGraph.getID w) |> VisDebug.logn)
#endif
  typeTwoConflicts, typeOneConflicts

let setRootAlignR conflict vDir hDir v (root, align, r) um =
  let cond =
    match vDir, hDir with
    | Topmost, Leftmost ->
      Map.find v align = v &&
        not (Set.contains (um, v) conflict) &&
        r < VisGraph.getIndex um
    | Topmost, Rightmost ->
      Map.find v align = v &&
        not (Set.contains (um, v) conflict) &&
        r > VisGraph.getIndex um
    | Bottommost, Leftmost ->
      Map.find v align = v &&
        not (Set.contains (v, um) conflict) &&
        r < VisGraph.getIndex um
    | Bottommost, Rightmost ->
      Map.find v align = v &&
        not (Set.contains (v, um) conflict) &&
        r > VisGraph.getIndex um
  if cond then
    let align = Map.add um v align
    let root = Map.add v (Map.find um root) root
    let align = Map.add v (Map.find v root) align
    let r = VisGraph.getIndex um
    root, align, r
  else
    root, align, r

let vAlignBody conflicts vDir hDir (root, align, r) (v: Vertex<_>) =
  let vs =
    match vDir with
    | Topmost -> List.sortBy VisGraph.getIndex v.Preds |> List.toArray
    | Bottommost -> List.sortBy VisGraph.getIndex v.Succs |> List.toArray
  let d = Array.length vs
  if d > 0 then
    let lowMid = floor (float (d - 1) / 2.0) |> int
    let highMid = ceil (float (d - 1) / 2.0) |> int
    let vs =
      if lowMid = highMid then
        [ vs.[lowMid] ]
      else
        match hDir with
        | Leftmost -> [ vs.[lowMid] ; vs.[highMid] ]
        | Rightmost -> [ vs.[highMid] ; vs.[lowMid] ]
    List.fold (setRootAlignR conflicts vDir hDir v) (root, align, r) vs
  else
    root, align, r

let vAlignLoop (vLayout: Vertex<_> [][]) conflicts vDir hDir (r, align) layer =
  let rInit =
    match hDir with
    | Leftmost -> System.Int32.MinValue
    | Rightmost -> System.Int32.MaxValue
  let vertices =
    match hDir with
    | Leftmost -> vLayout.[layer]
    | Rightmost -> Array.rev vLayout.[layer]
  let root, align, _ =
    Array.fold (vAlignBody conflicts vDir hDir) (r, align, rInit) vertices
  root, align

let vAlign (vGraph: VisGraph) vLayout maxLayer conflicts vDir hDir =
  let layers =
    match vDir with
    | Topmost -> [1 .. maxLayer]
    | Bottommost -> [0 .. maxLayer - 1] |> List.rev
  let initMap =
    vGraph.FoldVertex (fun map v -> Map.add v v map) Map.empty
  List.fold (vAlignLoop vLayout conflicts vDir hDir) (initMap, initMap) layers

let isBorder vertices v = function
  | Leftmost -> VisGraph.getIndex v > 0
  | Rightmost -> VisGraph.getIndex v < Array.length vertices - 1

let calcShift sink shift xs u v = function
  | Leftmost ->
    min
      (Map.find (Map.find u sink) shift)
      (Map.find v xs - Map.find u xs - blockIntervalX)
  | Rightmost ->
    max
      (Map.find (Map.find u sink) shift)
      (Map.find v xs - Map.find u xs + blockIntervalX)

let calcXs xs v u w = function
  | Leftmost ->
    max (Map.find v xs) (Map.find u xs + VisGraph.getWidth w + blockIntervalX)
  | Rightmost ->
    min (Map.find v xs) (Map.find u xs - VisGraph.getWidth w - blockIntervalX)

let rec placeBlock vLayout root align hDir (sink, shift, xs) v =
  match Map.tryFind v xs with
  | Some (_) -> sink, shift, xs
  | None ->
    let xs = Map.add v 0.0 xs
    let w = v
    placeBlockLoop vLayout root align hDir sink shift xs v w

and placeBlockLoop (vLayout: Vertex<_> [][]) root align hDir sink shift xs v w =
  let sink, shift, xs =
    let vertices = vLayout.[VisGraph.getLayer w]
    if isBorder vertices w hDir then
      let idx = Array.findIndex (fun v -> v = w) vertices
      let u, w =
        match hDir with
        | Leftmost -> Map.find vertices.[idx - 1] root, vertices.[idx - 1]
        | Rightmost -> Map.find vertices.[idx + 1] root, vertices.[idx + 1]
      let sink, shift, xs =
        placeBlock vLayout root align hDir (sink, shift, xs) u
      let sink =
        if Map.find v sink = v then Map.add v (Map.find u sink) sink
        else sink
      let shift =
        if Map.find v sink <> Map.find u sink then
          Map.add (Map.find u sink) (calcShift sink shift xs u v hDir) shift
        else shift
      let xs =
        if Map.find v sink = Map.find u sink then
          Map.add v (calcXs xs v u w hDir) xs
        else xs
      sink, shift, xs
    else sink, shift, xs
  let w = Map.find w align
  if w <> v then placeBlockLoop vLayout root align hDir sink shift xs v w
  else sink, shift, xs

let updateXs root sink shift xs v =
  let w = Map.find v root
  let xs = Map.add v (Map.find w xs) xs
  let shiftValue = Map.find (Map.find w sink) shift
  if shiftValue < System.Double.MaxValue then
    Map.add v ((Map.find v xs) + shiftValue) xs
  else xs

let hCompact (vGraph: VisGraph) root vLayout rootMap align hDir =
  let folder sink v = Map.add v v sink
  let sink = vGraph.FoldVertex folder Map.empty
  let shift = Map.map (fun _ _ -> System.Double.MaxValue) sink
  let xs = Map.empty
  let sink, shift, xs =
    Map.fold
      (fun acc v w ->
        if v = w then placeBlock vLayout rootMap align hDir acc v else acc)
      (sink, shift, xs)
      rootMap
  vGraph.FoldVertexDFS root (updateXs rootMap sink shift) xs

let calcPosInfo xs acc (vertices: Vertex<_> []) =
  let left = Map.find vertices.[0] xs
  let width =
    Map.find vertices.[Array.length vertices - 1] xs - Map.find vertices.[0] xs
  (left, width) :: acc

let getIndexInfo vLayout xs =
  let posInfos = Array.fold (calcPosInfo xs) [] vLayout
  let lefts, widths = List.unzip posInfos
  List.min lefts, List.min widths

let alignAssignments vLayout xAlignments =
  let posInfos = List.map (getIndexInfo vLayout) xAlignments
  let minLeft, _ = List.minBy (fun (_, width) -> width) posInfos
  List.map (fun ((left, _), xs) ->
    Map.map (fun _ x -> x + minLeft - left) xs) (List.zip posInfos xAlignments)

let collectX xPerV xs =
  Map.fold (fun xPerV v x ->
    match Map.tryFind v xPerV with
    | Some (xs) -> Map.add v (x :: xs) xPerV
    | None -> Map.add v [x] xPerV) xPerV xs

let setXPos (v: Vertex<VisBBlock>) x =
  let vData = v.VData
  vData.Coordinate.X <- x

let averageMedian xAlignments =
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

let calcXAlignment vGraph root vLayout maxLayer t1cs xAlignments dir =
  let vDir, hDir = dir
  let rootMap, align = vAlign vGraph vLayout maxLayer t1cs vDir hDir
  let xs = hCompact vGraph root vLayout rootMap align hDir
#if DEBUG
  VisDebug.logn <| sprintf "vAlign Directions: %A %A" vDir hDir
  VisDebug.logn "Root:"
  Map.iter (fun k v ->
    sprintf "%d : %d" (VisGraph.getID k) (VisGraph.getID v)
    |> VisDebug.logn) rootMap
  VisDebug.logn "Align:"
  Map.iter (fun k v ->
    sprintf "%d : %d" (VisGraph.getID k) (VisGraph.getID v)
    |> VisDebug.logn) align
  VisDebug.logn "Xs:"
  Map.iter (fun k v ->
    sprintf "%d : %f %f" (VisGraph.getID k) v (v + VisGraph.getWidth k)
    |> VisDebug.logn) xs
#endif
  xs :: xAlignments

let assignXCoordinates (vGraph: VisGraph) root vLayout =
  let maxLayer = Array.length vLayout - 1
  let _typeTwoConflicts, typeOneConflicts = preprocess vLayout
  let xAlignments =
    List.fold
      (calcXAlignment vGraph root vLayout maxLayer typeOneConflicts)
      []
      [ (Topmost, Leftmost) ; (Topmost, Rightmost) ;
        (Bottommost, Leftmost) ; (Bottommost, Rightmost) ]
  let xAlignments = alignAssignments vLayout xAlignments
  averageMedian xAlignments

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
  if vData.IsDummyBlock () then xs
  else vData.Coordinate.X :: xs

let getRightCoordinate xs (v: Vertex<VisBBlock>) =
  let vData = v.VData
  if vData.IsDummyBlock () then xs
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

let assignCoordinates vGraph root vLayout =
  assignXCoordinates vGraph root vLayout
  assignYCoordinates vLayout
  adjustCoordinates vGraph
