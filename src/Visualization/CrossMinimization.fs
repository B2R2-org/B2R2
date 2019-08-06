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

module internal B2R2.Visualization.CrossMinimization

open B2R2.BinGraph

/// The maximum number of iterations.
let [<Literal>] private maxCnt = 128

let private findIndex v vs =
  Array.findIndex (fun w -> v = w) vs

let private computeMaxLayer (vGraph: VisGraph) =
  vGraph.FoldVertex (fun layer v ->
    let l = VisGraph.getLayer v
    if layer < l then l else layer) 0

let private generateVPerLayer vGraph =
  let maxLayer = computeMaxLayer vGraph
  let vPerLayer = Array.create (maxLayer + 1) []
  let folder (vPerLayer: Vertex<VisBBlock> list []) v =
    let layer = VisGraph.getLayer v
    vPerLayer.[layer] <- v :: vPerLayer.[layer]
    vPerLayer
  vGraph.FoldVertex folder vPerLayer

let private alignVertices vertices =
  let arr = Array.zeroCreate (List.length vertices)
  List.fold (fun i (v: Vertex<VisBBlock>) ->
    Array.set arr i v ; i + 1) 0 vertices
  |> ignore
  arr

let private generateVLayout vPerLayer =
  Array.map (fun vertices -> alignVertices vertices) vPerLayer

let private baryCenter (vLayout: Vertex<_> [][]) layer isDown (v: Vertex<_>) =
  let nodes = if isDown then v.Preds else v.Succs
  if List.isEmpty nodes then System.Double.MaxValue, v
  else
    let vertices = if isDown then vLayout.[layer - 1] else vLayout.[layer + 1]
    let xs = List.fold (fun acc v -> acc + findIndex v vertices) 0 nodes
    float xs / float (List.length nodes), v

let private bcReorderOneLayer (vLayout: Vertex<_> [] []) isDown layer =
  let vertices = vLayout.[layer]
  let baryCenters = Array.map (baryCenter vLayout layer isDown) vertices
  let baryCenters = Array.sortBy fst baryCenters
#if DEBUG
  VisDebug.logn "BcReorder Before:"
  Array.iter (fun v ->
    sprintf "%d" (VisGraph.getID v) |> VisDebug.logn) vertices
  VisDebug.logn "BcReorder BaryCenters:"
  baryCenters
  |> Array.iter (fun (bc, v) ->
                 sprintf "%d : %f" (VisGraph.getID v) bc |> VisDebug.logn)
#endif
  Array.iteri (fun i (_, v) -> vertices.[i] <- v) baryCenters

let private phase1 vLayout isDown from maxLayer =
  let layers =
    if isDown then [from .. maxLayer] else [0 .. from] |> List.rev
  List.iter (bcReorderOneLayer vLayout isDown) layers

let rec private calcFirstIndex idx wlen =
  if idx < wlen then calcFirstIndex (idx * 2) wlen else idx

let rec private countLoop (tree: int []) southseq cnt index =
  if index > 0 then
    let cnt = if index % 2 <> 0 then cnt + tree.[index + 1] else cnt
    let index = (index - 1) / 2
    tree.[index] <- tree.[index] + 1
    countLoop tree southseq cnt index
  else cnt, tree

let private countCross southseq wlen =
  let firstIndex = calcFirstIndex 1 wlen
  let treeSize = 2 * firstIndex - 1
  let firstIndex = firstIndex - 1
  let tree = Array.zeroCreate (treeSize)
  let cnt, _ =
    List.fold (fun (cnt, (tree: int [])) item ->
      let index = firstIndex + item
      tree.[index] <- tree.[index] + 1
      countLoop tree southseq cnt index) (0, tree) southseq
  cnt

let private bilayerCount (vLayout: Vertex<_> [] []) isDown layer =
  let vs, ws =
    if isDown then vLayout.[layer - 1], vLayout.[layer]
    else vLayout.[layer + 1], vLayout.[layer]
  let pairs, _ =
    Array.fold (fun (acc, i) (v: Vertex<_>) ->
      if isDown then
        List.fold (fun acc w -> (i, findIndex w ws) :: acc) acc v.Succs, i + 1
      else
        List.fold (fun acc w -> (i, findIndex w ws) :: acc) acc v.Preds, i + 1
    ) ([], 0) vs
  let pairs = List.sort pairs
  let southseq = List.map snd pairs
  countCross southseq (Array.length ws)

let private collectBaryCenters bcByValues (bc, v) =
  match Map.tryFind bc bcByValues with
  | Some (vs) -> Map.add bc (v :: vs) bcByValues
  | None -> Map.add bc [v] bcByValues

let private reorderVertices (vertices: Vertex<_> []) idx (_, vs) =
  List.fold (fun idx v -> vertices.[idx] <- v; idx + 1) idx vs

let private reverseOneLayer vLayout isDown maxLayer layer =
  let count = bilayerCount vLayout isDown layer
  if count <> 0 then
    let vertices = vLayout.[layer]
    let baryCenters =
      Array.map (baryCenter vLayout layer isDown) vertices
    let bcByValues =
      Array.fold collectBaryCenters Map.empty baryCenters
    let isReversed =
      Map.exists (fun _ vs -> List.length vs > 1) bcByValues
    let bcByValues = Map.toList bcByValues
    let bcByValues = List.sortBy fst bcByValues
#if DEBUG
    VisDebug.logn <| sprintf "Cross Count: %d" count
    VisDebug.logn "Before:"
    Array.iter (fun v ->
      sprintf "%d" (VisGraph.getID v) |> VisDebug.logn) vertices
#endif
    List.fold (reorderVertices vertices) 0 bcByValues |> ignore
#if DEBUG
    VisDebug.logn "BaryCenters:"
    Array.iter (fun (bc, v) ->
      sprintf "%d: %f" (VisGraph.getID v) bc |> VisDebug.logn) baryCenters
    VisDebug.logn "After:"
    vertices
    |> Array.iter (fun (v: Vertex<_>) ->
      sprintf "%d" (v.GetID ()) |> VisDebug.logn)
#endif
    if isReversed then phase1 vLayout isDown layer maxLayer

let private phase2 vLayout isDown maxLayer =
  let layers =
    if isDown then [1 .. maxLayer] else [0 .. maxLayer - 1] |> List.rev
  List.iter (reverseOneLayer vLayout isDown maxLayer) layers

let rec private sugiyamaReorder vLayout cnt hashSet =
  if cnt = maxCnt then ()
  else
    let maxLayer = Array.length vLayout - 1
#if DEBUG
    VisDebug.logn "Phase1 DOWN"
#endif
    phase1 vLayout true 1 maxLayer
#if DEBUG
    VisDebug.logn "Phase1 UP"
#endif
    phase1 vLayout false (maxLayer - 1) maxLayer
#if DEBUG
    VisDebug.logn "Phase2 UP"
#endif
    phase2 vLayout false maxLayer
#if DEBUG
    VisDebug.logn "Phase2 DOWN"
#endif
    phase2 vLayout true maxLayer
    let hashCode = vLayout.GetHashCode ()
    if not (Set.contains hashCode hashSet) then
      sugiyamaReorder vLayout (cnt + 1) (Set.add hashCode hashSet)

let private setPos vLayout =
  Array.iter (fun vertices ->
    Array.iteri (fun i (v: Vertex<VisBBlock>) ->
      let vData = v.VData
      vData.Index <- i) vertices) vLayout

let minimizeCrosses vGraph =
  let vPerLayer = generateVPerLayer vGraph
  let vLayout = generateVLayout vPerLayer
  sugiyamaReorder vLayout 0 (Set.add (vLayout.GetHashCode ()) Set.empty)
  setPos vLayout
#if DEBUG
  VisDebug.logn "vLayout:"
  Array.iteri
    (fun layer arr ->
      sprintf "%d:" layer |> VisDebug.logn
      sprintf "%A\n" (Array.map VisGraph.getID arr) |> VisDebug.logn)
    vLayout
#endif
  vLayout
