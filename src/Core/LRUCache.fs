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
open System.Collections.Generic
open System.Threading

[<AllowNullLiteral>]
type private DoublyLinkedListNode<'K, 'V when 'K: equality and 'V: equality>
  (prev, next, key, value) =
  let mutable prev = prev
  let mutable next = next

  member __.Prev
    with get(): DoublyLinkedListNode<'K, 'V> = prev and set(n) = prev <- n

  member __.Next
    with get(): DoublyLinkedListNode<'K, 'V> = next and set(n) = next <- n

  member __.Key with get(): 'K = key

  member __.Value with get(): 'V = value

  override __.GetHashCode () = value.GetHashCode ()

  override __.Equals rhs =
    match rhs with
    | :? DoublyLinkedListNode<'K, 'V> as rhs -> __.Value = rhs.Value
    | _ -> false

/// Least Recently Used Cache that does not support concurrency.
type LRUCache<'K, 'V when 'K: equality and 'V: equality> (capacity: int) =
  let dict = Dictionary<'K, DoublyLinkedListNode<'K, 'V>> ()
  let mutable head: DoublyLinkedListNode<'K, 'V> = null
  let mutable tail: DoublyLinkedListNode<'K, 'V> = null
  let mutable size = 0

  member inline private __.InsertBack v =
    if head = null then head <- v else tail.Next <- v
    v.Prev <- tail
    v.Next <- null
    tail <- v
    size <- size + 1

  member inline private __.Remove (v: DoublyLinkedListNode<'K, 'V>) =
    if v.Prev = null then head <- v.Next else v.Prev.Next <- v.Next
    if v.Next = null then tail <- v.Prev else v.Next.Prev <- v.Prev
    size <- size - 1

  member __.Count with get () = size

  member __.TryGet (key: 'K) =
    match dict.TryGetValue key with
    | true, v ->
      __.Remove v
      __.InsertBack v
      Ok v.Value
    | false, _ -> Error ErrorCase.ItemNotFound

  member __.Add (key: 'K, value: 'V) =
    let v = DoublyLinkedListNode (null, null, key, value)
    dict[key] <- v
    __.InsertBack v
    if size > capacity then
      dict.Remove head.Key |> ignore
      __.Remove head
    else ()

  member __.Clear () =
    dict.Clear ()
    head <- null
    tail <- null
    size <- 0

/// This is a cacheable operation, which will be executed when there's no
/// already cached item.
type ICacheableOperation<'Arg, 'V when 'V: equality> =
  abstract Perform: 'Arg -> 'V

/// Least Recently Used Cache supporting concurrency. The capacity decides how
/// many entries to store.
type ConcurrentLRUCache<'K, 'V when 'K: equality and 'V: equality>
  (capacity: int) =
  let dict = Dictionary<'K, DoublyLinkedListNode<'K, 'V>> ()
  let lock = Object ()
  let mutable head: DoublyLinkedListNode<'K, 'V> = null
  let mutable tail: DoublyLinkedListNode<'K, 'V> = null
  let mutable size = 0

  member inline private __.AcquireLock () =
    try Monitor.Enter (lock)
    finally ()

  member inline private __.ReleaseLock () =
    Monitor.Exit (lock)

  member private __.InsertBack v =
    if head = null then head <- v else tail.Next <- v
    v.Prev <- tail
    v.Next <- null
    tail <- v
    size <- size + 1
    v

  member private __.Remove (v: DoublyLinkedListNode<'K, 'V>) =
    if v.Prev = null then head <- v.Next else v.Prev.Next <- v.Next
    if v.Next = null then tail <- v.Prev else v.Next.Prev <- v.Prev
    size <- size - 1

  member __.Count with get () = size

  member __.GetOrAdd (key: 'K) (op: ICacheableOperation<_, 'V>) arg =
    __.AcquireLock ()
    let v =
      match dict.TryGetValue key with
      | true, v ->
        __.Remove v
        __.InsertBack v
      | _ ->
        if size >= capacity then
          dict.Remove head.Key |> ignore
          __.Remove head
        let v = DoublyLinkedListNode (null, null, key, op.Perform arg)
        dict.Add (key, v)
        __.InsertBack v
    __.ReleaseLock ()
    v.Value

  member __.Clear () =
    __.AcquireLock ()
    dict.Clear ()
    head <- null
    tail <- null
    size <- 0
    __.ReleaseLock ()
