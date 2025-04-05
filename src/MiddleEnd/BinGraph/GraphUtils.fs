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

/// Several useful functions for directed graphs.
module internal B2R2.MiddleEnd.BinGraph.GraphUtils

open System.Collections.Generic
open B2R2

#if DEBUG
let checkVertexInGraph (g: IDiGraphAccessible<_, _>) (v: IVertex<_>) =
  let v' = g.FindVertexByData v.VData
  if v.ID = v'.ID then ()
  else raise VertexNotFoundException
#endif

/// Make a dummy vertex for an analysis without having to use `AddVertex` method
/// of a graph. With this, we don't have to modify the graph itself.
let makeDummyVertex<'V when 'V: equality> () =
  { new IVertex<'V> with
      member _.ID = -1
      member _.VData = Terminator.impossible ()
      member _.HasData = false
      member this.CompareTo (other: obj) =
        match other with
        | :? IVertex<'V> as other -> this.ID.CompareTo other.ID
        | _ -> Terminator.impossible ()
      member _.ToString (_, _) = "DummyVertex" }

let reverse (inGraph: IDiGraphAccessible<_, _>) roots outGraph =
  outGraph
  |> inGraph.FoldVertex (fun (outGraph: IDiGraph<_, _>) v ->
    outGraph.AddVertex (v.VData, v.ID) |> snd)
  |> inGraph.FoldEdge (fun outGraph edge ->
    let src = outGraph.FindVertexByID edge.First.ID
    let dst = outGraph.FindVertexByID edge.Second.ID
    outGraph.AddEdge (dst, src, edge.Label))
  |> fun outGraph -> (* renew root vertices *)
    roots |> Seq.map (fun (root: IVertex<_>) ->
      assert (inGraph.HasVertex root.ID)
      outGraph.FindVertexByID root.ID)
    |> outGraph.SetRoots

let computeDepthFirstNumbers (g: IDiGraphAccessible<_, _>) =
  let dfNums = Dictionary<IVertex<_>, int> ()
  Traversal.DFS.foldRevPostorder g (fun cnt v ->
    dfNums[v] <- cnt
    cnt + 1
  ) 0 |> ignore
  dfNums

let findBackEdges (g: IDiGraphAccessible<_, _>) =
  let dfNums = computeDepthFirstNumbers g
  let backEdges = Dictionary ()
  g.IterEdge (fun e ->
    if dfNums[e.First] >= dfNums[e.Second] then backEdges[e.First] <- e.Second
    else ())
  backEdges

let findRegularExits (g: IDiGraphAccessible<_, _>) =
  g.Vertices
  |> Array.fold (fun acc v ->
    if (g.GetSuccs v).Length = 0 then v :: acc else acc) []

let findExitsAfterRemovingBackEdges (g: IDiGraphAccessible<_, _>) =
  let backEdges = findBackEdges g
  g.Vertices
  |> Array.fold (fun exits v ->
    g.GetSuccEdges v
    |> Array.exists (fun e ->
      match backEdges.TryGetValue e.First with
      | true, dst -> dst <> e.Second
      | false, _ -> true)
    |> function
      | true -> exits
      | false -> v :: exits
  ) []

/// Find exit nodes of a digraph. An exit node is a node that has no outgoing
/// edges. In case the given graph has no such exit nodes (e.g., infinite
/// loops), we remove back edges and find exit nodes again, in which case we
/// consider loop tails as exit nodes.
let findExits (g: IDiGraphAccessible<_, _>) =
  findRegularExits g
  |> function
    | [] -> findExitsAfterRemovingBackEdges g
    | exits -> exits
