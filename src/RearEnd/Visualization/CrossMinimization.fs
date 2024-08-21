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

module internal B2R2.RearEnd.Visualization.CrossMinimization

open B2R2.MiddleEnd.BinGraph

type VLayout = IVertex<VisBBlock>[][]

/// The maximum number of iterations.
let [<Literal>] private MaxCnt = 128

let private computeMaxLayer (vGraph: VisGraph) =
  vGraph.FoldVertex (fun layer v ->
    let l = VisGraph.getLayer v
    if layer < l then l else layer) 0

let private generateVPerLayer vGraph =
  let maxLayer = computeMaxLayer vGraph
  let vPerLayer = Array.create (maxLayer + 1) []
  let folder (vPerLayer: IVertex<VisBBlock> list []) v =
    let layer = VisGraph.getLayer v
    vPerLayer[layer] <- v :: vPerLayer[layer]
    vPerLayer
  vGraph.FoldVertex folder vPerLayer

let private alignVertices vertices =
  let arr = Array.zeroCreate (List.length vertices)
  List.fold (fun i (v: IVertex<VisBBlock>) ->
    Array.set arr i v; v.VData.Index <- i; i + 1) 0 vertices
  |> ignore
  arr

let private generateVLayout vPerLayer =
  Array.map alignVertices vPerLayer

let private baryCenter (vGraph: IGraph<_, _>) isDown (v: IVertex<VisBBlock>) =
  let neighbor =
    if isDown then vGraph.GetPreds v
    else vGraph.GetSuccs v
  if neighbor.Length = 0 then System.Double.MaxValue, v
  else
    let xs = neighbor |> Seq.fold (fun acc v -> acc + v.VData.Index) 0
    float xs / float neighbor.Length, v

let private bcReorderOneLayer vGraph (vLayout: VLayout) isDown layer =
  let vertices = vLayout[layer]
  vertices
  |> Array.map (baryCenter vGraph isDown)
  |> Array.sortBy fst
  |> Array.iteri (fun i (_, v) ->
    v.VData.Index <- i
    vertices[i] <- v)

let private phase1 vGraph vLayout isDown from maxLayer =
  let layers = if isDown then [from .. maxLayer] else [from .. -1 .. 0]
  List.iter (bcReorderOneLayer vGraph vLayout isDown) layers

let rec private calcFirstIndex idx wlen =
  if idx < wlen then calcFirstIndex (idx * 2) wlen else idx

let rec private countLoop (tree: int[]) southseq cnt index =
  if index > 0 then
    let cnt = if index % 2 <> 0 then cnt + tree[index + 1] else cnt
    let index = (index - 1) / 2
    tree[index] <- tree[index] + 1
    countLoop tree southseq cnt index
  else cnt, tree

let private countCross southseq wlen =
  let firstIndex = calcFirstIndex 1 wlen
  let treeSize = 2 * firstIndex - 1
  let firstIndex = firstIndex - 1
  let tree = Array.zeroCreate (treeSize)
  let cnt, _ =
    List.fold (fun (cnt, (tree: int[])) item ->
      let index = firstIndex + item
      tree[index] <- tree[index] + 1
      countLoop tree southseq cnt index) (0, tree) southseq
  cnt

let private bilayerCount vGraph (vLayout: VLayout) isDown layer =
  let myLayer = vLayout[layer]
  let pairs, _ =
    if isDown then
      Array.fold (fun (acc, i) (v: IVertex<VisBBlock>) ->
        (vGraph: IGraph<_, _>).GetSuccs v
        |> Seq.fold (fun acc w -> (i, w.VData.Index) :: acc) acc,
        i + 1) ([], 0) vLayout[layer - 1]
    else
      Array.fold (fun (acc, i) (v: IVertex<VisBBlock>) ->
        vGraph.GetPreds v
        |> Seq.fold (fun acc w -> (i, w.VData.Index) :: acc) acc,
        i + 1) ([], 0) vLayout[layer + 1]
  let pairs = List.sort pairs
  let southseq = List.map snd pairs
  countCross southseq (Array.length myLayer)

let private collectBaryCenters bcByValues (bc, v) =
  match Map.tryFind bc bcByValues with
  | Some (vs) -> Map.add bc (v :: vs) bcByValues
  | None -> Map.add bc [v] bcByValues

let private reorderVertices (vertices: IVertex<VisBBlock>[]) idx (_, vs) =
  List.fold (fun i v ->
    vertices[i] <- v; v.VData.Index <- i; i + 1) idx vs

let private reverseOneLayer vGraph vLayout isDown maxLayer layer =
  let count = bilayerCount vGraph vLayout isDown layer
  if count <> 0 then
    let vertices = vLayout[layer]
    let baryCenters = Array.map (baryCenter vGraph isDown) vertices
    let bcByValues = Array.fold collectBaryCenters Map.empty baryCenters
    let isReversed = Map.exists (fun _ vs -> List.length vs > 1) bcByValues
    let bcByValues = Map.toList bcByValues
    let bcByValues = List.sortBy fst bcByValues
    List.fold (reorderVertices vertices) 0 bcByValues |> ignore
    if isReversed then phase1 vGraph vLayout isDown layer maxLayer

let private phase2 vGraph vLayout isDown maxLayer =
  let layers = if isDown then [1 .. maxLayer] else [maxLayer - 1 .. -1 .. 0]
  List.iter (reverseOneLayer vGraph vLayout isDown maxLayer) layers

let rec private sugiyamaReorder vGraph vLayout cnt hashSet =
  if cnt = MaxCnt then ()
  else
    let maxLayer = Array.length vLayout - 1
    phase1 vGraph vLayout true 1 maxLayer
    phase1 vGraph vLayout false (maxLayer - 1) maxLayer
    phase2 vGraph vLayout false maxLayer
    phase2 vGraph vLayout true maxLayer
    let hashCode = vLayout.GetHashCode ()
    if not (Set.contains hashCode hashSet) then
      sugiyamaReorder vGraph vLayout (cnt + 1) (Set.add hashCode hashSet)

let minimizeCrosses vGraph =
  let vLayout = generateVPerLayer vGraph |> generateVLayout
  sugiyamaReorder vGraph vLayout 0 (Set.add (vLayout.GetHashCode ()) Set.empty)
  vLayout
