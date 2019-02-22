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
let private hasInnerSegment v =
  if VGraph.getIsDummy v then List.exists VGraph.getIsDummy <| VGraph.getPreds v
  else false

let private getInnerPred v =
  List.find VGraph.getIsDummy <| VGraph.getPreds v

// Type2 conflict means two inner segments are crossing
let private markTypeTwoConflict v conflicts v0 =
  if hasInnerSegment v && hasInnerSegment v0 then
    let u = getInnerPred v
    let u0 = getInnerPred v0
    if VGraph.getPos u < VGraph.getPos u0 then Set.add v conflicts
    else conflicts
  else conflicts

let rec private findTypeTwoConflictLoop vertices conflicts i =
  if i = 0 || i = Array.length vertices then conflicts
  else
    let v = vertices.[i]
    let conflicts =
      Array.fold (markTypeTwoConflict v) conflicts vertices.[.. i - 1]
    findTypeTwoConflictLoop vertices conflicts (i + 1)

let findTypeTwoConflict_ conflicts (layer, vertices) =
  if layer > 0 then findTypeTwoConflictLoop vertices conflicts 0 else conflicts

// XXX: We need to resolve typeTwoConflicts before doing further processes
let private findTypeTwoConflict vLayout =
  Array.mapi (fun layer vertices -> layer, vertices) vLayout
  |> Array.fold findTypeTwoConflict_ Set.empty

// Type1 conflict means inner segment and non-inner segment are crossing
let private markTypeOneConflict_ v0 u0 u1 v conflicts u =
  let vPos = VGraph.getPos v
  let uPos = VGraph.getPos u
  if vPos < v0 && u0 < uPos then Set.add (u, v) conflicts
  elif v0 <= vPos && (uPos < u0 || u1 < uPos) then Set.add (u, v) conflicts
  else conflicts

let private markTypeOneConflict v0 u0 u1 conflicts (v: Vertex<_>) =
  List.fold (markTypeOneConflict_ v0 u0 u1 v) conflicts <| VGraph.getPreds v

let rec private findTypeOneConflictLoop upperLen vertices conflicts v0 u0 i =
  if i = Array.length vertices then conflicts
  else
    let v = vertices.[i]
    if hasInnerSegment v || i = Array.length vertices - 1 then
      let u1 =
        if hasInnerSegment v then getInnerPred v |> VGraph.getPos
        else upperLen
      let conflicts =
        Array.fold (markTypeOneConflict v0 u0 u1) conflicts vertices.[.. i]
      let v1 = VGraph.getPos v
      findTypeOneConflictLoop upperLen vertices conflicts v1 u1 (i + 1)
    else
      findTypeOneConflictLoop upperLen vertices conflicts v0 u0 (i + 1)

let private findTypeOneConflict_ (vLayout: _ [] []) conflicts (layer, vertices) =
  if layer > 0 then
    let nUpperVertices = Array.length vLayout.[layer - 1]
    findTypeOneConflictLoop nUpperVertices vertices conflicts -1 -1 0
  else conflicts

let private findTypeOneConflict vLayout =
  Array.mapi (fun layer vertices -> layer, vertices) vLayout
  |> Array.fold (findTypeOneConflict_ vLayout) Set.empty

let private preprocess vLayout =
  let typeTwoConflicts = findTypeTwoConflict vLayout
  let typeOneConflicts = findTypeOneConflict vLayout
#if DEBUG
  Dbg.logn "TypeTwoConflicts:"
  typeTwoConflicts
  |> Set.iter (fun v -> sprintf "%d" <| VGraph.getID v |> Dbg.logn)
  Dbg.logn "TypeOneConflicts:"
  typeOneConflicts
  |> Set.iter (fun (v, w) ->
            sprintf "%d %d" (VGraph.getID v) (VGraph.getID w) |> Dbg.logn)
#endif
  typeTwoConflicts, typeOneConflicts

let private setRootAlignR conflict vDir hDir v (root, align, r) um =
  let cond =
    match vDir, hDir with
    | Topmost, Leftmost ->
      Map.find v align = v &&
        not (Set.contains (um, v) conflict) &&
        r < VGraph.getPos um
    | Topmost, Rightmost ->
      Map.find v align = v &&
        not (Set.contains (um, v) conflict) &&
        r > VGraph.getPos um
    | Bottommost, Leftmost ->
      Map.find v align = v &&
        not (Set.contains (v, um) conflict) &&
        r < VGraph.getPos um
    | Bottommost, Rightmost ->
      Map.find v align = v &&
        not (Set.contains (v, um) conflict) &&
        r > VGraph.getPos um
  if cond then
    let align = Map.add um v align
    let root = Map.add v (Map.find um root) root
    let align = Map.add v (Map.find v root) align
    let r = VGraph.getPos um
    root, align, r
  else
    root, align, r

let private vAlignBody conflicts vDir hDir (root, align, r) (v: Vertex<_>) =
  let vs =
    match vDir with
    | Topmost -> List.sortBy VGraph.getPos v.Preds |> List.toArray
    | Bottommost -> List.sortBy VGraph.getPos v.Succs |> List.toArray
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

let private vAlignLoop (vLayout: Vertex<_> [] []) conflicts vDir hDir (root, align) layer =
  let rInit =
    match hDir with
    | Leftmost -> System.Int32.MinValue
    | Rightmost -> System.Int32.MaxValue
  let vertices =
    match hDir with
    | Leftmost -> vLayout.[layer]
    | Rightmost -> Array.rev vLayout.[layer]
  let root, align, _ =
    Array.fold (vAlignBody conflicts vDir hDir) (root, align, rInit) vertices
  root, align

let private vAlign (vGraph: VGraph) vLayout maxLayer conflicts vDir hDir =
  let layers =
    match vDir with
    | Topmost -> [1 .. maxLayer]
    | Bottommost -> [0 .. maxLayer - 1] |> List.rev
  let initMap =
    vGraph.FoldVertex (fun map v -> Map.add v v map) Map.empty
  List.fold (vAlignLoop vLayout conflicts vDir hDir) (initMap, initMap) layers

let private isBorder vertices v = function
  | Leftmost -> VGraph.getPos v > 0
  | Rightmost -> VGraph.getPos v < Array.length vertices - 1

let private calcShift sink shift xs u v = function
  | Leftmost ->
    min
      (Map.find (Map.find u sink) shift)
      (Map.find v xs - Map.find u xs - blockIntervalX)
  | Rightmost ->
    max
      (Map.find (Map.find u sink) shift)
      (Map.find v xs - Map.find u xs + blockIntervalX)

let private calcXs xs v u w = function
  | Leftmost ->
    max (Map.find v xs) (Map.find u xs + VGraph.getWidth w + blockIntervalX)
  | Rightmost ->
    min (Map.find v xs) (Map.find u xs - VGraph.getWidth w - blockIntervalX)

let rec private placeBlock vLayout root align hDir (sink, shift, xs) v =
  match Map.tryFind v xs with
  | Some (_) -> sink, shift, xs
  | None ->
    let xs = Map.add v 0.0 xs
    let w = v
    placeBlockLoop vLayout root align hDir sink shift xs v w

and placeBlockLoop (vLayout: Vertex<_> [] []) root align hDir sink shift xs v w =
  let sink, shift, xs =
    let vertices = vLayout.[VGraph.getLayer w]
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

let private updateXs root sink shift xs v =
  let w = Map.find v root
  let xs = Map.add v (Map.find w xs) xs
  let shiftValue = Map.find (Map.find w sink) shift
  if shiftValue < System.Double.MaxValue then
    Map.add v ((Map.find v xs) + shiftValue) xs
  else xs

let private hCompact (vGraph: VGraph) vLayout root align hDir =
  let folder sink v = Map.add v v sink
  let sink = vGraph.FoldVertex folder Map.empty
  let shift = Map.map (fun _ _ -> System.Double.MaxValue) sink
  let xs = Map.empty
  let sink, shift, xs =
    Map.fold
      (fun acc v w ->
        if v = w then placeBlock vLayout root align hDir acc v else acc)
      (sink, shift, xs)
      root
  vGraph.FoldVertexDFS (updateXs root sink shift) xs

let private calcPosInfo xs acc (vertices: Vertex<_> []) =
  let left = Map.find vertices.[0] xs
  let width =
    Map.find vertices.[Array.length vertices - 1] xs - Map.find vertices.[0] xs
  (left, width) :: acc

let private getPosInfo vLayout xs =
  let posInfos = Array.fold (calcPosInfo xs) [] vLayout
  let lefts, widths = List.unzip posInfos
  List.min lefts, List.min widths

let private alignAssignments vLayout xAlignments =
  let posInfos = List.map (getPosInfo vLayout) xAlignments
  let minLeft, _ = List.minBy (fun (_, width) -> width) posInfos
  List.map (fun ((left, _), xs) ->
    Map.map (fun _ x -> x + minLeft - left) xs) (List.zip posInfos xAlignments)

let private collectX xPerV xs =
  Map.fold (fun xPerV v x ->
    match Map.tryFind v xPerV with
    | Some (xs) -> Map.add v (x :: xs) xPerV
    | None -> Map.add v [x] xPerV) xPerV xs

let private setXPos (v: Vertex<VNode>) x =
  let vData = v.VData
  vData.XPos <- x

let private averageMedian (vGraph: VGraph) xAlignments =
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

let private calcXAlignment vGraph vLayout maxLayer t1cs xAlignments dir =
  let vDir, hDir = dir
  let root, align = vAlign vGraph vLayout maxLayer t1cs vDir hDir
  let xs = hCompact vGraph vLayout root align hDir
#if DEBUG
  Dbg.logn <| sprintf "vAlign Directions: %A %A" vDir hDir
  Dbg.logn "Root:"
  Map.iter (fun k v ->
    sprintf "%d : %d" (VGraph.getID k) (VGraph.getID v) |> Dbg.logn) root
  Dbg.logn "Align:"
  Map.iter
    (fun k v -> sprintf "%d : %d" (VGraph.getID k) (VGraph.getID v) |> Dbg.logn)
    align
  Dbg.logn "Xs:"
  Map.iter
    (fun k v ->
      sprintf "%d : %f %f" (VGraph.getID k) v (v + VGraph.getWidth k)
      |> Dbg.logn)
    xs
#endif
  xs :: xAlignments

let private assignXCoordinates (vGraph: VGraph) vLayout =
  let maxLayer = Array.length vLayout - 1
  let _typeTwoConflicts, typeOneConflicts = preprocess vLayout
  let xAlignments =
    List.fold
      (calcXAlignment vGraph vLayout maxLayer typeOneConflicts)
      []
      [ (Topmost, Leftmost) ; (Topmost, Rightmost) ;
        (Bottommost, Leftmost) ; (Bottommost, Rightmost) ]
  let xAlignments = alignAssignments vLayout xAlignments
  averageMedian vGraph xAlignments

let private assignYCoordinate y vertices =
  Array.iter (fun (v: Vertex<VNode>) ->
    let vData = v.VData
    vData.YPos <- y) vertices
  let maxHeight = Array.map VGraph.getHeight vertices |> Array.max
  y + maxHeight + blockIntervalY

let private assignYCoordinates vLayout =
  let maxLayer = Array.length vLayout - 1
  List.map (fun layer -> vLayout.[layer]) [ 0 .. maxLayer ]
  |> List.fold assignYCoordinate 0.0 |> ignore

let private adjustXCoordinate (v: Vertex<VNode>) =
  let vData = v.VData
  vData.XPos <- vData.XPos - vData.Width / 2.0

let private getLeftCoordinate coords (v: Vertex<VNode>) =
  let vData = v.VData
  if vData.IsDummy then coords
  else vData.XPos :: coords

let private getRightCoordinate coords (v: Vertex<VNode>) =
  let vData = v.VData
  if vData.IsDummy then coords
  else (vData.XPos + vData.Width) :: coords

let private shiftXCoordinate shift (v: Vertex<VNode>) =
  let vData = v.VData
  vData.XPos <- vData.XPos - shift

let private adjustCoordinates (vGraph: VGraph) =
  vGraph.IterVertex adjustXCoordinate
  let leftMost = vGraph.FoldVertex getLeftCoordinate [] |> List.min
  let rightMost = vGraph.FoldVertex getRightCoordinate [] |> List.max
  let width = rightMost - leftMost
  shiftXCoordinate (rightMost - width / 2.0) |> vGraph.IterVertex

let assignCoordinates vGraph vLayout =
  assignXCoordinates vGraph vLayout
  assignYCoordinates vLayout
  adjustCoordinates vGraph
