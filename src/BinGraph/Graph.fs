(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>
          Soomin Kim <soomink@kaist.ac.kr>

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

namespace B2R2.BinGraph

open System.Collections.Generic

/// Missing vertex.
exception VertexNotFoundException

/// Multiple vertices found when looking for a vertex containing certain data
exception MultipleVerticesFoundException

/// Missing edge.
exception EdgeNotFoundException

/// Trying to access dummy node's data
exception DummyDataAccessException

/// When a graph has multiple entry points.
exception MultipleEntryException

/// A unique ID for a vertex.
type VertexID = int

/// A data type for vertex. A VertexData should have an ID.
[<AbstractClass>]
type VertexData (id) =
  member __.ID: VertexID = id

module VertexData =
  let private freshID = ref 0

  let genID () = System.Threading.Interlocked.Increment (freshID)

/// Edge ID is a tuple of two node IDs (source node ID, destination node ID).
type EdgeID = VertexID * VertexID

/// A vertex in a directed graph. The vertex data (v) is optional, and if it is
/// None, we will consider the vertex as a dummy node. Dummy nodes are useful
/// for representing entry/exit node in a CFG.
type Vertex<'V when 'V :> VertexData> (?v: 'V) =
  member __.VData =
    match v with
    | Some v -> v
    | None -> raise DummyDataAccessException

  /// We sometimes need to access ID of dummy vertex for example calculating
  /// dominators.
  member __.GetID () =
    match v with
    | Some v -> v.ID
    | None -> 0

  /// Check whether vertex is dummy node.
  member __.IsDummy () = Option.isNone v

  /// List of predecessors.
  member val Preds: Vertex<'V> list = [] with get, set

  /// List of successors.
  member val Succs: Vertex<'V> list = [] with get, set

  /// Return the ID of the given vertex.
  static member GetID (v: Vertex<#VertexData>) = v.GetID ()

  // Each vertex has a unique ID, so ID can be used to check equality.
  override __.Equals obj =
    match obj with
    | :? Vertex<'V> as obj ->  __.GetID () = obj.GetID ()
    | _ -> false

  override __.GetHashCode () = __.GetID ()

  override __.ToString () =
    match v with
    | Some v -> sprintf "Vertex<%s>" <| v.ToString ()
    | None -> "DummyVertex"

  // Each vertex has a unique ID, so ID can be used for comparison.
  interface System.IComparable with
    member __.CompareTo obj =
      match obj with
      | :? Vertex<'V> as v -> compare (__.GetID ()) (v.GetID ())
      | _ -> failwith "Invalid comparison"

/// An edge in a directed graph.
type Edge<'E> = Edge of 'E

/// A directed graph.
/// Disclaimer: Our graph implementation is imperative.
[<AbstractClass>]
type DiGraph<'V, 'E when 'V :> VertexData> () =
  let unreachables = HashSet<Vertex<'V>> ()
  let exits = HashSet<Vertex<'V>> ()

  /// A list of unreachable nodes. We always add nodes into this list first, and
  /// then later remove it from the list when adding edges.
  member val internal Unreachables = unreachables with get

  /// A list of exit nodes, which do not have any successors.
  member val internal Exits = exits with get

  /// Is this empty? A graph is empty when there is no vertex in the graph.
  abstract IsEmpty: unit -> bool

  /// Number of vertices.
  abstract Size: unit -> int

  /// Add a vertex into the graph, and return a reference to the added vertex.
  abstract AddVertex: 'V -> Vertex<'V>

  /// Remove the given vertex from the graph.
  abstract RemoveVertex: Vertex<'V> -> unit

  /// Check the existence of the given vertex from the graph.
  abstract Exists: Vertex<'V> -> bool

  /// Find a vertex that has the given VertexData, from the graph. It will raise
  /// an exception if such a vertex does not exist. Note that this function can
  /// be used only when each vertex always has unique VertexData.
  abstract FindVertexByData: 'V -> Vertex<'V>

  abstract TryFindVertexByData: 'V -> Vertex<'V> option

  /// Add an edge from src to dst.
  abstract AddEdge: src: Vertex<'V> -> dst: Vertex<'V> -> 'E -> unit

  /// Remove the edge that spans from src to dst.
  abstract RemoveEdge: src: Vertex<'V> -> dst: Vertex<'V> -> unit

  /// find the data of the edge that spans from src to dst.
  abstract FindEdgeData: src: Vertex<'V> -> dst: Vertex<'V> -> 'E

  /// Return a new transposed (i.e., reversed) graph.
  abstract Reverse: unit -> DiGraph<'V, 'E>

  /// Fold every vertex (the order can be arbitrary).
  abstract FoldVertex: ('a -> Vertex<'V> -> 'a) -> 'a -> 'a

  /// Iterate every vertex (the order can be arbitrary).
  abstract IterVertex: (Vertex<'V> -> unit) -> unit

  /// Fold every edge in the graph (the order can be arbitrary).
  abstract FoldEdge: ('a -> Vertex<'V> -> Vertex<'V> -> 'E -> 'a) -> 'a -> 'a

  /// Fold every edge in the graph (the order can be arbitrary).
  abstract IterEdge: (Vertex<'V> -> Vertex<'V> -> 'E -> unit) -> unit

  abstract GetVertices: unit -> Set<Vertex<'V>>

  member __.FindVertexByID id =
    let folder acc (v: Vertex<_>) = if v.GetID () = id then Some v else acc
    match __.FoldVertex folder None with
    | Some v -> v
    | None -> raise VertexNotFoundException

  member __.TryFindVertexByID id =
    let folder acc (v: Vertex<_>) = if v.GetID () = id then Some v else acc
    __.FoldVertex folder None

  member __.FindVertexBy fn =
    let folder acc (v: Vertex<_>) = if fn v then Some v else acc
    match __.FoldVertex folder None with
    | Some v -> v
    | None -> raise VertexNotFoundException

  member __.TryFindVertexBy fn =
    let folder acc (v: Vertex<_>) = if fn v then Some v else acc
    __.FoldVertex folder None

  /// Fold every vertex in the graph in a depth-first manner starting from the
  /// root node.
  /// N.B. We should try to fold on every single vertex, as there is no easy way
  /// to check unreachable graphs from a root node.
  member __.FoldVertexDFS root fn acc =
    let visited: HashSet<int> = new HashSet<int> ()
    let rec foldLoop acc = function
      | [] -> acc
      | v :: tovisit when Vertex<_>.GetID v |> visited.Contains ->
        foldLoop acc tovisit
      | v :: tovisit ->
        visited.Add (v.GetID ()) |> ignore
        List.fold (fun tovisit s -> s :: tovisit) tovisit v.Succs
        |> foldLoop (fn acc v)
    let acc = foldLoop acc [root]
    __.GetVertices () |> Set.toList |> foldLoop acc

  /// Fold every vertex in the graph in a breadth-first manner starting from the
  /// root node.
  member __.FoldVertexBFS root fn acc =
    let visited: HashSet<int> = new HashSet<int> ()
    let queue: Queue<Vertex<'V>> = new Queue<Vertex<'V>> ()
    let enqueue vertices = vertices |> List.iter (fun v -> queue.Enqueue (v))
    let rec foldLoop acc =
      if queue.Count = 0 then acc
      else let v = queue.Dequeue ()
           if visited.Contains (v.GetID ()) then foldLoop acc
           else visited.Add (v.GetID ()) |> ignore
                enqueue v.Succs
                fn acc v |> foldLoop
    enqueue [root]
    foldLoop acc

  /// Iterate every vertex in the graph in a depth-first manner starting from
  /// the root node.
  member __.IterVertexDFS root fn =
    let visited: HashSet<int> = new HashSet<int> ()
    let rec iterLoop = function
      | [] -> ()
      | v :: tovisit when Vertex<_>.GetID v |> visited.Contains ->
        iterLoop tovisit
      | v :: tovisit ->
        visited.Add (v.GetID ()) |> ignore
        fn v
        List.fold (fun tovisit s -> s :: tovisit) tovisit v.Succs
        |> iterLoop
    iterLoop [root]
    __.GetVertices () |> Set.toList |> iterLoop

  /// Iterate every vertex in the graph in a breadth-first manner starting from
  /// the root node.
  member __.IterVertexBFS root fn =
    let visited: HashSet<int> = new HashSet<int> ()
    let queue: Queue<Vertex<'V>> = new Queue<Vertex<'V>> ()
    let enqueue vertices = vertices |> List.iter (fun v -> queue.Enqueue (v))
    let rec iterLoop () =
      if queue.Count = 0 then ()
      else let v = queue.Dequeue ()
           if visited.Contains (v.GetID ()) then iterLoop ()
           else visited.Add (v.GetID ()) |> ignore
                enqueue v.Succs
                fn v
                iterLoop ()
    enqueue [root]
    iterLoop ()

  /// Fold every edge in the graph in a depth-first manner starting from the
  /// root node. We do not provide BFS-style folding function for edges.
  member __.FoldEdgeDFS root fn acc =
    let inline foldEdgeDFSAux acc tovisit fn (v: Vertex<'V>) =
      let rec foldLoop (acc, tovisit) = function
        | succ :: succs ->
          let acc = fn acc v succ
          let tovisit = succ :: tovisit
          foldLoop (acc, tovisit) succs
        | [] -> acc, tovisit
      foldLoop (acc, tovisit) v.Succs
    let visited : HashSet<int> = new HashSet<int> ()
    let rec foldLoop acc = function
      | [] -> acc
      | v :: tovisit when Vertex<_>.GetID v |> visited.Contains ->
        foldLoop acc tovisit
      | v :: tovisit ->
        visited.Add (v.GetID ()) |> ignore
        foldEdgeDFSAux acc tovisit fn v ||> foldLoop
    let acc = foldLoop acc [root]
    __.GetVertices () |> Set.toList |> foldLoop acc

  /// Iterate every edge in the graph in a depth-first manner starting from the
  /// root node. N.B. we do not provide BFS-style folding function for edges.
  member __.IterEdgeDFS root fn =
    let inline iterEdgeDFSAux tovisit fn (v: Vertex<'V>) =
      let rec iterLoop tovisit = function
        | succ :: succs ->
          fn v succ
          let tovisit = succ :: tovisit
          iterLoop tovisit succs
        | [] -> tovisit
      iterLoop tovisit v.Succs
    let visited : HashSet<int> = new HashSet<int> ()
    let rec iterLoop = function
      | [] -> ()
      | v :: tovisit when Vertex<_>.GetID v |> visited.Contains ->
        iterLoop tovisit
      | v :: tovisit ->
        visited.Add (v.GetID ()) |> ignore
        iterEdgeDFSAux tovisit fn v |> iterLoop
    iterLoop [root]
    __.GetVertices () |> Set.toList |> iterLoop

  /// Return the DOT-representation of this graph.
  member __.ToDOTStr name vToStrFn (_eToStrFn: Edge<'E> -> string) =
    let inline strAppend (s: string) (sb: System.Text.StringBuilder) =
      sb.Append(s)
    let folder sb src dst _edata =
      strAppend (vToStrFn src) sb
      |> strAppend " -> "
      |> strAppend (vToStrFn dst)
      |> strAppend " [label=\""
      |> strAppend "\"];\n"
    let sb = System.Text.StringBuilder ()
    let sb = strAppend "digraph " sb |> strAppend name |> strAppend " {\n"
    let sb = __.FoldEdge folder sb
    sb.Append("}\n").ToString()

// vim: set tw=80 sts=2 sw=2:
