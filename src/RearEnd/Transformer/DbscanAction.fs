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

namespace B2R2.RearEnd.Transformer

open System
open System.Collections.Generic
open System.Threading

[<Struct>]
type DbscanStatus =
  | Unvisited
  | Visited
  | Noise

/// DBSCAN element.
type DbscanElement =
  { mutable Status: DbscanStatus
    Fingerprint: HashSet<int>
    ElementName: string }
with
  static member Init(fp: Fingerprint) =
    { Status = Unvisited
      Fingerprint = fp.Patterns |> List.map fst |> HashSet
      ElementName = fp.Annotation }

/// The `dbscan` action.
type DbscanAction() =
  let buildDistanceCache cancellationToken (elms: DbscanElement[]) =
    let cancellationToken: CancellationToken = cancellationToken
    let cacheSize = elms.Length * (elms.Length - 1) / 2
    let cache = Array.zeroCreate<float> cacheSize
    let index i j = j * (j - 1) / 2 + i
    for i = 0 to elms.Length - 1 do
      for j = i + 1 to elms.Length - 1 do
        cancellationToken.ThrowIfCancellationRequested()
        let e1, e2 = elms[i], elms[j]
        let smaller, larger =
          if e1.Fingerprint.Count <= e2.Fingerprint.Count then
            e1.Fingerprint, e2.Fingerprint
          else
            e2.Fingerprint, e1.Fingerprint
        let mutable intersection = 0
        for hash in smaller do
          if larger.Contains hash then
            intersection <- intersection + 1
          else
            ()
        let overlap = (* overlap coefficient *)
          if smaller.Count = 0 then
            0.0
          else
            float intersection / float smaller.Count
        let dist = 1.0 - overlap
        cache[index i j] <- dist
    cache, index

  let dist (cache: float[]) index i j =
    if i = j then
      0.0
    elif i < j then
      cache[index i j]
    else
      cache[index j i]

  let findNeighbors cancellationToken count cache index i eps =
    let cancellationToken: CancellationToken = cancellationToken
    let neighbors = ResizeArray<int>()
    for j = 0 to count - 1 do
      cancellationToken.ThrowIfCancellationRequested()
      if dist cache index i j <= eps then
        neighbors.Add j |> ignore
      else
        ()
    neighbors

  let cluster cancellationToken eps minpts (fingerprints: Fingerprint[]) =
    let cancellationToken: CancellationToken = cancellationToken
    let elms = fingerprints |> Array.map DbscanElement.Init
    let cache, cacheIndex = buildDistanceCache cancellationToken elms
    let clusters = List<string[]>() (* List<List<string>> *)
    for i in 0 .. (elms.Length - 1) do
      cancellationToken.ThrowIfCancellationRequested()
      if elms[i].Status <> Unvisited then
        ()
      else
        let neighbors =
          findNeighbors cancellationToken elms.Length cache cacheIndex i eps
        if neighbors.Count < minpts then
          elms[i].Status <- Noise
        else
          let cluster = List<string> () (* List<string> *)
          elms[i].Status <- Visited
          cluster.Add elms[i].ElementName |> ignore
          let queue = Queue<int>()
          let enqueued = HashSet<int>()
          for neighbor in neighbors do
            if neighbor <> i && enqueued.Add neighbor then
              queue.Enqueue neighbor
            else
              ()
          while queue.Count > 0 do
            cancellationToken.ThrowIfCancellationRequested()
            let n = queue.Dequeue()
            if elms[n].Status = Noise then
              elms[n].Status <- Visited
              cluster.Add elms[n].ElementName |> ignore
            elif elms[n].Status <> Unvisited then
              ()
            else
              elms[n].Status <- Visited
              cluster.Add elms[n].ElementName |> ignore
              let newNeighbors =
                findNeighbors
                  cancellationToken
                  elms.Length
                  cache
                  cacheIndex
                  n
                  eps
              if newNeighbors.Count >= minpts then
                for neighbor in newNeighbors do
                  if enqueued.Add neighbor then
                    queue.Enqueue neighbor
                  else
                    ()
              else
                ()
          clusters.Add(cluster.ToArray()) |> ignore
    [| box { Clusters = clusters.ToArray() } |]

  let transform cancellationToken args collection =
    let args: string list = args
    let eps, minPts =
      match args with
      | eps :: minPts :: [] ->
        Convert.ToDouble eps, Convert.ToInt32 minPts
      | eps :: [] ->
        Convert.ToDouble eps, 3
      | [] ->
        0.2, 3
      | _ ->
        invalidArg (nameof args) "Too many arguments given."
    { Values =
        collection.Values
        |> Array.map unbox<Fingerprint>
        |> cluster cancellationToken eps minPts }

  interface IAction with
    member _.ActionID with get() = "dbscan"
    member _.Signature
      with get() =
        "Fingerprint collection -> dbscan [eps=<n>] [min-points=<n>]"
        + " -> Cluster array"
    member _.Description with get() =
      """
    Take in an array of fingerprints and return an array of clustered
    fingerprints. User may specify eps and min-points. If not, we use a default
    value of eps=0.2 and min-points=3.
"""
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      transform cancellationToken args collection
