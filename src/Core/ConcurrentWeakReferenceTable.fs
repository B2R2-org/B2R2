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

namespace B2R2

open System
open System.Threading
open System.Runtime.InteropServices

type private Node<'T> = {
  Value         : 'T
  Hash          : int
  mutable Next  : Node<'T>
}

[<AutoOpen>]
module private ConcurrentWeakReferenceTableHelper =
  let inline (===) e1 e2 =
    LanguagePrimitives.PhysicalEquality e1 e2

  let inline (!==) e1 e2 =
    LanguagePrimitives.PhysicalEquality e1 e2 |> not

  let rec nextIntegerNotDivisibleBy357 sz =
    if sz % 3 = 0 || sz % 5 = 0 || sz % 7 = 0 then
      nextIntegerNotDivisibleBy357 (sz + 2)
    else sz

  let inline nextSize currentSize =
    nextIntegerNotDivisibleBy357 <| currentSize * 2

  let createEmptyNodeRef _ = Unchecked.defaultof<_>

  let createEmptyLockRef _ = new Object ()

  let inline getBucketNo hc _buckets =
      (hc &&& 0x7fffffff) % (Array.length _buckets)

  let concurrency = Environment.ProcessorCount

/// <summary>
///   Weak-reference table that supports concurrency.
/// </summary>
type ConcurrentWeakReferenceTable<'T when 'T : equality and 'T : not struct>() =
  let mutable capacity = 31
  let mutable maxPerBucket = 251
  let mutable buckets = Array.init capacity createEmptyNodeRef
  let locks = Array.init concurrency createEmptyLockRef

  member private __.TryGetValue (x, hc, [<Out>] res : byref<'T>) =
    let _buckets = buckets
    let bucketNo = getBucketNo hc _buckets
    let mutable t = Volatile.Read<Node<WeakReference<'T>>>(&_buckets.[bucketNo])
    let mutable found = false
    while t !== Unchecked.defaultof<_> do
      if hc = t.Hash then (* Fast Check *)
        match t.Value.TryGetTarget () with
        | true, v when v.Equals x ->
          res <- v; t <- Unchecked.defaultof<_>; found <- true
        | _ -> t <- t.Next
      else t <- t.Next
    found

  member private __.AcquireLocks st ed =
    let mutable acquired = 0
    let mutable idx = st
    while idx < ed do
      let lockTaken = ref false
      Monitor.Enter (locks.[idx], lockTaken)
      if !lockTaken then acquired <- acquired + 1
      idx <- idx + 1
    acquired

  member private __.ReleaseLocks st ed =
    let mutable idx = st
    while idx < ed do Monitor.Exit locks.[idx]; idx <- idx + 1

  member private __.Resize () =
    let _buckets = buckets
    (* First of All acquire Lock0 to resize *)
    let mutable locksAcquired = __.AcquireLocks 0 1
    (* Confirm that any other thread does not call `resize ()` *)
    if _buckets === buckets then
      let nsize = nextSize capacity
      let nbuckets = Array.init nsize createEmptyNodeRef
      for head in buckets do
        let mutable t = head
        while t !== Unchecked.defaultof<_> do
          match t.Value.TryGetTarget () with
          | true, _ ->
            let no = getBucketNo t.Hash nbuckets
            (* Create new node and link *)
            Volatile.Write<Node<WeakReference<'T>>>
              (&nbuckets.[no], { t with Next = nbuckets.[no] })
          | false, _ -> ()
          t <- t.Next
      (* Acquire other Locks *)
      locksAcquired <- locksAcquired + __.AcquireLocks 1 locks.Length
      capacity <- nsize
      buckets <- nbuckets
    __.ReleaseLocks 0 locksAcquired

  member private __.AddValueInternal (x, hc, factory, [<Out>] sz: byref<int>) =
      let _buckets = buckets
      let bucketNo = getBucketNo hc _buckets
      let lockNo = bucketNo % concurrency
      let lockTaken = ref false
      let mutable hd = Unchecked.defaultof<_>
      Monitor.Enter (locks.[lockNo], lockTaken)
      if buckets === _buckets then
        let mutable t = _buckets.[bucketNo]
        let mutable found = false
        let mutable res = Unchecked.defaultof<_>
        let mutable prev = Unchecked.defaultof<_>
        sz <- 0
        (* XXX: We assume that no duplicate entry exists *)
        while t !== Unchecked.defaultof<_> do
          match t.Value.TryGetTarget () with
          | true, v ->
            (* Set first none-empty cell as head *)
            if hd === Unchecked.defaultof<_> then hd <- t
            prev <- t
            if v.Equals x then
              res <- v; found <- true; t <- Unchecked.defaultof<_>
            else t <- t.Next; sz <- sz + 1
          | false, _ -> (* Erase GC-ed Cell *)
            if prev !== Unchecked.defaultof<_> then (* Head is dead *)
              Volatile.Write<Node<WeakReference<'T>>> (&prev.Next, t.Next)
            t <- t.Next
        if found then (* Insertion from other thread while waiting lock *)
          Volatile.Write<Node<WeakReference<'T>>> (&_buckets.[bucketNo], hd)
          if !lockTaken then Monitor.Exit (locks.[lockNo]) |> ignore
          sz <- 0; res
        else
          let hd = Volatile.Read<Node<WeakReference<'T>>>(&_buckets.[bucketNo])
          let nV = factory x
          let nVCell = WeakReference<'T> (nV)
          Volatile.Write<Node<WeakReference<'T>>>
            (&_buckets.[bucketNo], { Value = nVCell
                                     Hash  = hc
                                     Next  = hd })
          if !lockTaken then Monitor.Exit (locks.[lockNo]) |> ignore
          nV
      else
        if !lockTaken then Monitor.Exit (locks.[lockNo]) |> ignore
        __.AddValueInternal (x, hc, factory, &sz)

  member private __.AddValue x hc factory =
    let nV, sz = __.AddValueInternal (x, hc, factory)
    if sz > maxPerBucket then __.Resize ()
    nV

  member __.GetOrApplyAndAdd x factory =
    let hc = x.GetHashCode ()
    match __.TryGetValue (x, hc) with
    | true, v -> v
    | _ -> __.AddValue x hc factory

  member __.GetOrAdd x = __.GetOrApplyAndAdd x id
