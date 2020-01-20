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

[<CustomEquality; NoComparison>]
type private DoubleLinkedListNode<'T when 'T : equality> = {
  mutable Prev  : DoubleLinkedListNode<'T>
  mutable Next  : DoubleLinkedListNode<'T>
  Value : 'T
}
with
  override __.GetHashCode () = hash __.Value
  override __.Equals x =
    match x with
    | :? DoubleLinkedListNode<'T> as v -> v.Value = __.Value
    | _ -> false

/// Least Recently Used Cache supporting concurrency.
type ConcurrentLRU<'K, 'V when 'K : equality and 'V : equality>(capacity: int) =
  let nil = Unchecked.defaultof<DoubleLinkedListNode<_>>
  let dict = new Collections.Generic.Dictionary<'K, DoubleLinkedListNode<'V>> ()
  let lock = ref (new Object ())
  let mutable head = nil
  let mutable tail = nil
  let mutable size = 0

  member private __.AcquireLock () =
    try Monitor.Enter (lock)
    finally ()

  member private __.ReleaseLock () =
    Monitor.Exit (lock)

  member private __.InsertBack o =
    if head = nil then head <- o (* empty *)
                  else tail.Next <- o
    o.Prev <- tail
    o.Next <- nil
    tail <- o
    size <- size + 1
    o

  member private __.Remove o =
    if o.Prev = nil then head <- o.Next
                    else o.Prev.Next <- o.Next
    if o.Next = nil then tail <- o.Prev
                    else o.Next.Prev <- o.Prev
    size <- size - 1

  member __.Count with get () = size

  member __.GetOrAdd (key: 'K) (proc: 'K -> 'V) =
    __.AcquireLock ()
    let o =
      match dict.TryGetValue key with
      | true, out ->
        __.Remove out
        __.InsertBack out
      | _ ->
        if size >= capacity then __.Remove head
        let out = { Prev = nil; Next = nil; Value = proc key }
        dict.Add (key, out)
        __.InsertBack out
    __.ReleaseLock ()
    o.Value

  member __.Clear () =
    __.AcquireLock ()
    dict.Clear ()
    head <- nil
    tail <- nil
    size <- 0
    __.ReleaseLock ()
