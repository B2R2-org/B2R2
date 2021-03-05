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

[<CustomEquality; NoComparison>]
type private DoubleLinkedListNode<'K, 'T when 'K: equality and 'T: equality> = {
  mutable Prev: DoubleLinkedListNode<'K, 'T>
  mutable Next: DoubleLinkedListNode<'K, 'T>
  Key: 'K
  Value: 'T
}
with
  override __.GetHashCode () = hash __.Value
  override __.Equals rhs =
    match rhs with
    | :? DoubleLinkedListNode<'K, 'T> as rhs -> __.Value = rhs.Value
    | _ -> false

/// This is a cacheable operation, which will be executed when there's no
/// already cached item.
type ICacheableOperation<'Arg, 'V when 'V: equality> =
  abstract Perform: 'Arg -> 'V

/// Least Recently Used Cache supporting concurrency. The capacity decides how
/// many entries to store.
type LRUCache<'K, 'V when 'K: equality and 'V: equality> (capacity: int) =
  let nil = Unchecked.defaultof<DoubleLinkedListNode<_, _>>
  let dict = Dictionary<'K, DoubleLinkedListNode<'K, 'V>> ()
  let lock = ref (new Object ())
  let mutable head = nil
  let mutable tail = nil
  let mutable size = 0

  member inline private __.AcquireLock () =
    try Monitor.Enter (lock)
    finally ()

  member inline private __.ReleaseLock () =
    Monitor.Exit (lock)

  member private __.InsertBack v =
    if head = nil then head <- v else tail.Next <- v
    v.Prev <- tail
    v.Next <- nil
    tail <- v
    size <- size + 1
    v

  member private __.Remove v =
    if v.Prev = nil then head <- v.Next else v.Prev.Next <- v.Next
    if v.Next = nil then tail <- v.Prev else v.Next.Prev <- v.Prev
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
        let v = { Prev = nil; Next = nil; Key = key; Value = op.Perform arg }
        dict.Add (key, v)
        __.InsertBack v
    __.ReleaseLock ()
    v.Value

  member __.Clear () =
    __.AcquireLock ()
    dict.Clear ()
    head <- nil
    tail <- nil
    size <- 0
    __.ReleaseLock ()