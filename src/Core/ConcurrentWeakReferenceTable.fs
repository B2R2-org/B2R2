(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Minkyu Jung <hestati@kaist.ac.kr>

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

type private Node<'T> =
  {
    Value: 'T
    Next: Node<'T>
  }

[<AutoOpen>]
module private ConcurrentWeakReferenceTableHelper =
  let inline (===) e1 e2 =
    LanguagePrimitives.PhysicalEquality e1 e2

  let inline nextSize currentSize =
    let rec nextIntegerNotDivisibleBy357 sz =
      if sz % 3 = 0 || sz % 5 = 0 || sz % 7 = 0 then
        nextIntegerNotDivisibleBy357 (sz + 2)
      else sz
    nextIntegerNotDivisibleBy357 <| currentSize * 2

  let createEmptyNodeRef _ = ref Unchecked.defaultof<_>
  let createEmptyLockRef _ = ref (Object())

  let getBucketNo hashcode _buckets =
      (hashcode &&& 0x7fffffff) % (Array.length _buckets)

/// <summary>
///   Weak-reference table that supports concurrency.
/// </summary>
type ConcurrentWeakReferenceTable<'T when 'T : equality and 'T : not struct>() =
  let mutable capacity = 31
  let mutable maxPerBucket = 251
  let concurrency = Environment.ProcessorCount
  let mutable buckets = Array.init capacity createEmptyNodeRef
  let locks = Array.init concurrency createEmptyLockRef

  member private __.GetBucketNoAndLockNo hashcode _buckets =
    let bucketNo = getBucketNo hashcode _buckets
    bucketNo, bucketNo % concurrency

  member private __.GetValue x hashcode =
    let _buckets = buckets
    let bucketNo = getBucketNo hashcode _buckets
    let mutable res = None
    let v = ref (Unchecked.defaultof<_>)
    let mutable t = Volatile.Read<Node<WeakReference<'T>>>(_buckets.[bucketNo])
    while not (t === Unchecked.defaultof<_>) do
      let h = t.Value
      if h.TryGetTarget(v) then
        let v = (!v)
        if v.Equals(x) then res <- Some v; t <- Unchecked.defaultof<_>
                       else t <- t.Next
      else
        t <- t.Next
    res

  member private __.AcquireLocks st ed =
    let mutable acquired = 0
    for idx in st .. (ed - 1) do
      let lockTaken = ref false
      try Monitor.Enter(locks.[idx], lockTaken)
      finally ()
      if (!lockTaken) then
        acquired <- acquired + 1
    acquired

  member private __.ReleaseLocks st ed =
    for idx in st .. (ed - 1) do Monitor.Exit (locks.[idx])

  member private __.Resize () =
    let _buckets = buckets
    let mutable locksAcquired = 0
    try
      (* First of All acquire Lock0 to resize *)
      locksAcquired <- locksAcquired + __.AcquireLocks 0 1
      (* Confirm any other thread does resize *)
      if _buckets === buckets then
        let nsize = nextSize capacity
        let nbuckets = Array.init nsize createEmptyNodeRef
        for lst in buckets do
          let mutable t = (!lst)
          while not (t === Unchecked.defaultof<_>) do
            let elem = t.Value
            let v = ref (Unchecked.defaultof<_>)
            if elem.TryGetTarget(v) then
              let no = getBucketNo ((!v).GetHashCode()) nbuckets
              Volatile.Write(nbuckets.[no], { Value = elem
                                              Next = !nbuckets.[no] })
            t <- t.Next
        (* Acquire other Locks *)
        locksAcquired <- locksAcquired + __.AcquireLocks 1 locks.Length
        capacity <- nsize
        buckets <- nbuckets
    finally
      __.ReleaseLocks 0 locksAcquired

  member private __.AddValueInternal x hashcode valueFactory =
    let _buckets = buckets
    let (bucketNo, lockNo) = __.GetBucketNoAndLockNo hashcode _buckets
    let lockTaken = ref false
    try
      Monitor.Enter(locks.[lockNo], lockTaken)
      if buckets === _buckets then
        let mutable t = (!_buckets.[bucketNo])
        let mutable res = None
        let mutable size = 0
        let mutable out = Unchecked.defaultof<_>
        (* XXX: We assume that no duplicate entry exists *)
        while not (t === Unchecked.defaultof<_>) do
          let h = t.Value
          let v = ref Unchecked.defaultof<_>
          match h.TryGetTarget(v) with
          | true ->
            let v = (!v)
            if v.Equals(x) then res <- Some v; t <- Unchecked.defaultof<_>
            else
              out <- { Value = h; Next = out }
              t <- t.Next; size <- size + 1
          | false -> t <- t.Next (* Erase GC-ed cell *)
        match res with
        | Some v -> v, 0
        | None ->
          let newValue = valueFactory x
          let newValueCell = WeakReference<'T>(newValue)
          Volatile.Write(_buckets.[bucketNo], { Value = newValueCell
                                                Next = out })
          newValue, size
      else __.AddValueInternal x hashcode valueFactory
    finally
      if (!lockTaken) then Monitor.Exit(locks.[lockNo]) |> ignore

  member private __.AddValue x hashcode valueFactory =
    let (newValue, sz) = __.AddValueInternal x hashcode valueFactory
    if sz > maxPerBucket then __.Resize()
    newValue

  member __.GetOrApplyAndAdd x valueFactory =
    let hashCode = x.GetHashCode()
    match __.GetValue x hashCode with
    | Some value -> value
    | None -> __.AddValue x hashCode valueFactory

  member __.GetOrAdd x = __.GetOrApplyAndAdd x id
