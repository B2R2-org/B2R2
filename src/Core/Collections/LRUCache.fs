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

open System.Collections.Generic
open System.Runtime.InteropServices
open B2R2

/// Represents a Least Recently Used (LRU) cache that does not support
/// concurrency. The capacity must be positive.
type LRUCache<'K, 'V when 'K: equality and 'V: equality>(capacity: int) =
  let dict = Dictionary<'K, DoublyLinkedKeyValue<'K, 'V>>()
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

  /// Tries to retrieve the value for the given key. When the key exists, the
  /// entry is promoted to the most recently used position.
  member this.TryGet(key: 'K) =
    match dict.TryGetValue key with
    | true, v ->
      this.Remove v
      this.InsertBack v
      Ok v.Value
    | false, _ -> Error ErrorCase.ItemNotFound

  /// Tries to retrieve the value and reference count for the given key. When
  /// the key exists, the entry is promoted to the most recently used position.
  member this.TryGet(key: 'K, [<Out>] refCount: int byref) =
    match dict.TryGetValue key with
    | true, v ->
      this.Remove v
      this.InsertBack v
      refCount <- v.RefCount
      Ok v.Value
    | false, _ -> Error ErrorCase.ItemNotFound

  /// Adds or replaces a value in the cache. Replacing an existing key removes
  /// the old entry and inserts the new value as the most recently used entry.
  member this.Add(key: 'K, value: 'V) =
    match dict.TryGetValue key with
    | true, old -> this.Remove old
    | false, _ -> ()
    let v = DoublyLinkedKeyValue(null, null, key, value)
    dict[key] <- v
    this.InsertBack v
    if size > capacity then
      dict.Remove head.Key |> ignore
      this.Remove head
    else
      ()

  /// Removes all entries from the cache.
  member _.Clear() =
    dict.Clear()
    head <- null
    tail <- null
    size <- 0
