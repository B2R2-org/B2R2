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

/// Raises `ArgumentException` when a vertex of the given ID already belongs to
/// the graph. Letting the new vertex take the place of the old one would leave
/// the edges of the old one behind, each of them still spanning a vertex the
/// graph no longer holds.
let checkVertexIDNotTaken taken (vid: VertexID) =
  if not taken then ()
  else invalidArg (nameof vid) $"Vertex ID {vid} is already in use"

/// Raises `VertexNotFoundException` for a vertex looked up by its ID.
let raiseVertexNotFoundByID (vid: VertexID) =
  raise <| VertexNotFoundException $"No vertex with ID {vid}"

/// Raises `VertexNotFoundException` for a vertex looked up by its data.
let raiseVertexNotFoundByData data =
  raise <| VertexNotFoundException $"No vertex with data {data}"

/// Raises `VertexNotFoundException` for a vertex looked up by a predicate.
let raiseVertexNotFoundByPredicate () =
  raise <| VertexNotFoundException "No vertex satisfying the predicate"

/// Answers the one root of a graph whose roots are the given ones, raising
/// `NoRootVertexException` or `MultipleRootVerticesException` when there is
/// not exactly one of them. Every graph owes a caller this, and what differs
/// between them is no more than the collection its roots sit in.
let singleRoot (roots: #IReadOnlyList<IVertex<'V>>) =
  match roots.Count with
  | 1 -> roots[0]
  | 0 -> raise NoRootVertexException
  | _ -> raise MultipleRootVerticesException

/// Finds the vertex the given predicate answers true for, out of the ones the
/// given lookup reaches, raising `VertexNotFoundException` when there is no
/// such vertex. Scanning a collection of its own is all of this that belongs
/// to a graph rather than to the protocol every graph answers.
let findVertexBy (tryFind: (IVertex<'V> -> bool) -> _ option) fn =
  match tryFind fn with
  | Some v -> v
  | None -> raiseVertexNotFoundByPredicate ()

/// Finds the vertex carrying the given data, out of the ones the given lookup
/// reaches, answering None when there is no such vertex.
let tryFindVertexByData (tryFind: (IVertex<'V> -> bool) -> _ option) data =
  tryFind (fun v -> v.VData = data)

/// Finds the vertex carrying the given data, as `tryFindVertexByData` does,
/// raising `VertexNotFoundException` when there is no such vertex.
let findVertexByData tryFind data =
  match tryFindVertexByData tryFind data with
  | Some v -> v
  | None -> raiseVertexNotFoundByData data

/// Raises `VertexNotFoundException` when no vertex of the given vertex's ID
/// belongs to the given graph. Analyses use this to reject a vertex of another
/// graph up front, rather than failing later with an obscure lookup error. It
/// asks of the ID rather than of the vertex, since a post-dominance query is
/// answered on the transposed graph, where the counterpart of the given vertex
/// shares nothing but its ID.
let checkVertexInGraph (g: IDiGraph<_, _>) (v: IVertex<_>) =
  if g.Contains v then () else raiseVertexNotFoundByID v.ID

/// Collects the vertices that are reachable from the roots of the given graph.
let computeReachables (g: IDiGraph<_, _>) =
  let reachables = HashSet<IVertex<_>>()
  Traversal.DFS.iterPreorderWithRoots g (g.Roots) (fun v ->
    reachables.Add v |> ignore)
  reachables

let findRegularExits (g: IDiGraph<_, _>) =
  g.Vertices
  |> Array.fold (fun acc v ->
    if (g.GetSuccs v).Length = 0 then v :: acc else acc) []

let findExitsAfterRemovingRetreatingEdges (g: IDiGraph<_, _>) =
  let retreating = Loop.RetreatingEdge.findAll g
  let isRetreating (e: Edge<_, _>) = retreating.Contains e
  g.Vertices
  |> Array.fold (fun exits v ->
    if g.GetSuccEdges v |> Array.forall isRetreating then v :: exits else exits
  ) []

/// Finds exit nodes of a digraph. An exit node is a node that has no outgoing
/// edges. In case the given graph has no such exit nodes (e.g., infinite
/// loops), we remove retreating edges and find exit nodes again, in which case
/// we consider loop tails as exit nodes.
let findExits (g: IDiGraph<_, _>) =
  findRegularExits g
  |> function
    | [] -> findExitsAfterRemovingRetreatingEdges g
    | exits -> exits
