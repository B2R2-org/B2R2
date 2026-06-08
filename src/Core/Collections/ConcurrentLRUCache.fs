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

/// Represents Least Recently Used (LRU) cache supporting concurrency. The
/// capacity must be positive and decides how many entries to store.
type ConcurrentLRUCache<'K, 'V when 'K: equality and 'V: equality>
  public(capacity: int) =
  let dict = Dictionary<'K, DoublyLinkedKeyValue<'K, 'V>>()
  let lock = Object()
  let mutable head: DoublyLinkedKeyValue<'K, 'V> = null
  let mutable tail: DoublyLinkedKeyValue<'K, 'V> = null
  let mutable size = 0

  do
    if capacity <= 0 then
      invalidArg (nameof capacity) "capacity must be positive"
    else
      ()

  /// Gets the number of entries currently stored in the cache.
  member _.Count with get() = size

  member inline private _.AcquireLock() =
    try Monitor.Enter lock
    finally ()

  member inline private _.ReleaseLock() =
    Monitor.Exit lock

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

  /// Tries to retrieve a cached value while holding the cache lock. When the
  /// key exists, the entry is promoted to the most recently used position.
  member private this.TryGetCached key =
    this.AcquireLock()
    try
      match dict.TryGetValue key with
      | true, v ->
        this.Remove v
        this.InsertBack v |> ignore
        Some v.Value
      | _ -> None
    finally
      this.ReleaseLock()

  /// Gets the value for the given key, or computes and adds it on a cache miss.
  /// The cache lock is not held while <paramref name="factory"/> creates the
  /// value, so concurrent misses for the same key may compute the value more
  /// than once. Before inserting, this method checks the cache again and
  /// returns the already cached value if another thread inserted it first.
  member this.GetOrAdd(key: 'K, factory: ICacheValueFactory<_, 'V>, arg) =
    match this.TryGetCached key with
    | Some value -> value
    | None ->
      let value = factory.Create arg
      this.AcquireLock()
      try
        match dict.TryGetValue key with
        | true, v ->
          this.Remove v
          this.InsertBack v |> ignore
          v.Value
        | _ ->
          if size >= capacity then
            dict.Remove head.Key |> ignore
            this.Remove head
          else
            ()
          let v = DoublyLinkedKeyValue(null, null, key, value)
          dict.Add(key, v)
          this.InsertBack v |> ignore
          value
      finally
        this.ReleaseLock()

  /// Removes all entries from the cache.
  member this.Clear() =
    this.AcquireLock()
    try
      dict.Clear()
      head <- null
      tail <- null
      size <- 0
    finally
      this.ReleaseLock()

/// Represents a factory that creates a value on a cache miss.
and ICacheValueFactory<'Arg, 'V when 'V: equality> =
  /// Creates a value for the given argument.
  abstract Create: 'Arg -> 'V
