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

namespace B2R2.Collections

open System
open System.Collections.Generic
open System.Threading
open System.Runtime.InteropServices
open B2R2

/// Represents a Least Recently Used (LRU) cache that does not support
/// concurrency.
type LRUCache<'K, 'V when 'K: equality and 'V: equality>(capacity: int) =
  let dict = Dictionary<'K, DoublyLinkedKeyValue<'K, 'V>>()
  let mutable head: DoublyLinkedKeyValue<'K, 'V> = null
  let mutable tail: DoublyLinkedKeyValue<'K, 'V> = null
  let mutable size = 0

  member inline private _.InsertBack v =
    if isNull head then head <- v else tail.Next <- v
    v.Prev <- tail
    v.Next <- null
    v.RefCount <- v.RefCount + 1
    tail <- v
    size <- size + 1

  member inline private _.Remove(v: DoublyLinkedKeyValue<'K, 'V>) =
    if isNull v.Prev then head <- v.Next else v.Prev.Next <- v.Next
    if isNull v.Next then tail <- v.Prev else v.Next.Prev <- v.Prev
    size <- size - 1

  member _.Count with get() = size

  member this.TryGet(key: 'K) =
    match dict.TryGetValue key with
    | true, v ->
      this.Remove v
      this.InsertBack v
      Ok v.Value
    | false, _ -> Error ErrorCase.ItemNotFound

  /// Try to retrieve a value as well as its ref count.
  member this.TryGet(key: 'K, [<Out>] refCount: int byref) =
    match dict.TryGetValue key with
    | true, v ->
      this.Remove v
      this.InsertBack v
      refCount <- v.RefCount
      Ok v.Value
    | false, _ -> Error ErrorCase.ItemNotFound

  member this.Add(key: 'K, value: 'V) =
    let v = DoublyLinkedKeyValue(null, null, key, value)
    dict[key] <- v
    this.InsertBack v
    if size > capacity then
      dict.Remove head.Key |> ignore
      this.Remove head
    else ()

  member _.Clear() =
    dict.Clear()
    head <- null
    tail <- null
    size <- 0

/// Represents a cacheable operation, which will be executed when there's no
/// already cached item.
type ICacheableOperation<'Arg, 'V when 'V: equality> =
  abstract Perform: 'Arg -> 'V

/// Represents Least Recently Used (LRU) cache supporting concurrency. The
/// capacity decides how many entries to store.
type ConcurrentLRUCache<'K, 'V when 'K: equality and 'V: equality>
  (capacity: int) =
  let dict = Dictionary<'K, DoublyLinkedKeyValue<'K, 'V>>()
  let lock = Object()
  let mutable head: DoublyLinkedKeyValue<'K, 'V> = null
  let mutable tail: DoublyLinkedKeyValue<'K, 'V> = null
  let mutable size = 0

  member inline private _.AcquireLock() =
    try Monitor.Enter(lock)
    finally ()

  member inline private _.ReleaseLock() =
    Monitor.Exit(lock)

  member private _.InsertBack v =
    if isNull head then head <- v else tail.Next <- v
    v.Prev <- tail
    v.Next <- null
    tail <- v
    size <- size + 1
    v

  member private _.Remove(v: DoublyLinkedKeyValue<'K, 'V>) =
    if isNull v.Prev then head <- v.Next else v.Prev.Next <- v.Next
    if isNull v.Next then tail <- v.Prev else v.Next.Prev <- v.Prev
    size <- size - 1

  member _.Count with get() = size

  member this.GetOrAdd(key: 'K, op: ICacheableOperation<_, 'V>, arg) =
    this.AcquireLock()
    let v =
      match dict.TryGetValue key with
      | true, v ->
        this.Remove v
        this.InsertBack v
      | _ ->
        if size >= capacity then
          dict.Remove head.Key |> ignore
          this.Remove head
        let v = DoublyLinkedKeyValue(null, null, key, op.Perform arg)
        dict.Add(key, v)
        this.InsertBack v
    this.ReleaseLock()
    v.Value

  member this.Clear() =
    this.AcquireLock()
    dict.Clear()
    head <- null
    tail <- null
    size <- 0
    this.ReleaseLock()
