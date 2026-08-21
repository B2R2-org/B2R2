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
[<RequireQualifiedAccess>]
module internal B2R2.MiddleEnd.BinGraph.GraphUtils

open System.Collections.Generic

/// Copies the given collection into an array of its own. `Seq.toArray` grows
/// a buffer as it goes unless the collection happens to tell it a count, and
/// the accessors that use this sit inside the traversal loops, where the one
/// allocation of the result is all that can be afforded.
let toArray (xs: #ICollection<'T>) =
  let arr: 'T[] = Array.zeroCreate xs.Count
  xs.CopyTo(arr, 0)
  arr

/// Copies the given list into an array back to front, applying the given
/// mapping. An adjacency list that grows at its front holds its neighbors in
/// the reverse of the order they were added, and this is what hands them back
/// in that order without a second list to reverse them through.
let toArrayInReverse mapping xs =
  let arr = Array.zeroCreate (List.length xs)
  let mutable i = arr.Length - 1
  for x in xs do
    arr[i] <- mapping x
    i <- i - 1
  arr

/// Copies the given list into an array back to front, as `toArrayInReverse`
/// does, with nothing read out of its elements.
let toReversedArray xs = toArrayInReverse id xs

/// Identifies the dummy root, the node that an analysis puts above every root
/// of a graph so that a graph of many roots reads as one of a single root. It
/// belongs to no graph, hence this is the one ID a graph never hands out; a
/// caller that picks IDs itself, through `AddVertex(data, vid)`, has to leave
/// it alone.
[<Literal>]
let DummyVertexID = -1

/// Raises `ArgumentException` when the given ID is the reserved one, so that
/// no vertex of a graph ever collides with the dummy root of an analysis.
let checkVertexIDNotReserved (vid: VertexID) =
  if vid <> DummyVertexID then ()
  else invalidArg (nameof vid) $"Vertex ID {vid} is reserved"

/// Raises `VertexNotFoundException` for a vertex looked up by its ID.
let raiseVertexNotFoundByID (vid: VertexID) =
  raise <| VertexNotFoundException $"No vertex with ID {vid}"

/// Raises `VertexNotFoundException` for a vertex looked up by its data.
let raiseVertexNotFoundByData data =
  raise <| VertexNotFoundException $"No vertex with data {data}"

/// Raises `VertexNotFoundException` for a vertex looked up by a predicate.
let raiseVertexNotFoundByPredicate () =
  raise <| VertexNotFoundException "No vertex satisfying the predicate"

/// Raises `VertexNotFoundException` when no vertex of the given vertex's ID
/// belongs to the given graph. Analyses use this to reject a vertex of another
/// graph up front, rather than failing later with an obscure lookup error. It
/// asks of the ID rather than of the vertex, since a post-dominance query is
/// answered on the transposed graph, where the counterpart of the given vertex
/// shares nothing but its ID.
let checkVertexInGraph (g: IDiGraphAccessible<_, _>) (v: IVertex<_>) =
  if g.HasVertexByID v.ID then () else raiseVertexNotFoundByID v.ID

/// Collects the vertices that are reachable from the roots of the given graph.
let computeReachables (g: IDiGraphAccessible<_, _>) =
  let reachables = HashSet<IVertex<_>>()
  Traversal.DFS.iterPreorderWithRoots g (g.GetRoots()) (fun v ->
    reachables.Add v |> ignore)
  reachables

let computeDepthFirstNumbers (g: IDiGraphAccessible<_, _>) =
  let dfNums = Dictionary<IVertex<_>, int>()
  Traversal.DFS.foldRevPostorder g (fun cnt v ->
    dfNums[v] <- cnt
    cnt + 1
  ) 0 |> ignore
  dfNums

/// Collects the back edges of the given graph, each of them identified by the
/// IDs of its endpoints. A vertex can be the source of more than one back
/// edge, hence the edges, not their sources, are what the result holds.
let findBackEdges (g: IDiGraphAccessible<_, _>) =
  let dfNums = computeDepthFirstNumbers g
  let backEdges = HashSet<VertexID * VertexID>()
  g.IterEdge(fun e ->
    if dfNums[e.First] < dfNums[e.Second] then ()
    else backEdges.Add(e.First.ID, e.Second.ID) |> ignore)
  backEdges

let findRegularExits (g: IDiGraphAccessible<_, _>) =
  g.Vertices
  |> Array.fold (fun acc v ->
    if (g.GetSuccs v).Length = 0 then v :: acc else acc) []

let findExitsAfterRemovingBackEdges (g: IDiGraphAccessible<_, _>) =
  let backEdges = findBackEdges g
  let isBackEdge (e: Edge<_, _>) =
    backEdges.Contains(e.First.ID, e.Second.ID)
  g.Vertices
  |> Array.fold (fun exits v ->
    if g.GetSuccEdges v |> Array.forall isBackEdge then v :: exits else exits
  ) []

/// Finds exit nodes of a digraph. An exit node is a node that has no outgoing
/// edges. In case the given graph has no such exit nodes (e.g., infinite
/// loops), we remove back edges and find exit nodes again, in which case we
/// consider loop tails as exit nodes.
let findExits (g: IDiGraphAccessible<_, _>) =
  findRegularExits g
  |> function
    | [] -> findExitsAfterRemovingBackEdges g
    | exits -> exits
