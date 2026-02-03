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

open B2R2.Collections.FingerTree

/// An element for our random access queue.
type private RandomAccessQueueElem<'T>(v) =
  member val Val: 'T = v
  override this.ToString() = this.Val.ToString()
  interface IMeasured<Size> with
    member _.Measurement = Size(1u)

/// Represents an interval-tree-based map: an interval of type (Addr) -> a
/// RandomAccessQueueElement ('a).
type RandomAccessQueue<'T> =
  private
    RandomAccessQueue of FingerTree<Size, RandomAccessQueueElem<'T>>

/// Provides functions for creating or manipulating random access queues.
[<RequireQualifiedAccess>]
module RandomAccessQueue =

  /// Empty interval tree.
  [<CompiledName ("Empty")>]
  let empty: RandomAccessQueue<_> = RandomAccessQueue Empty

  /// Checks if the given queue is empty.
  [<CompiledName ("IsEmpty")>]
  let isEmpty (q: RandomAccessQueue<_>) = q = RandomAccessQueue Empty

  /// Returns the length of the queue.
  [<CompiledName ("Length")>]
  let length (RandomAccessQueue q) =
    ((q :> IMeasured<_>).Measurement).Value |> int

  /// Splits the queue based on the given index into two (left and right). The
  /// left queue will contain the entry at the given index.
  [<CompiledName ("SplitAt")>]
  let splitAt i (RandomAccessQueue q) =
    let l, r = Op.Split((fun (elt: Size) -> i < elt.Value), q)
    RandomAccessQueue l, RandomAccessQueue r

  let private snoc q v = Op.Snoc(q, RandomAccessQueueElem v)

  /// Adds an item to the queue.
  [<CompiledName ("Enqueue")>]
  let enqueue v (RandomAccessQueue q) = snoc q v |> RandomAccessQueue

  /// Removes an item from the queue.
  [<CompiledName ("Dequeue")>]
  let dequeue q =
    splitAt 1u q
    |> fun (RandomAccessQueue hd, tl) ->
      let elm = Op.HeadL hd
      elm.Val, tl

  /// Returns the first element of the queue.
  [<CompiledName ("Head")>]
  let head (RandomAccessQueue q) =
    let elm = Op.HeadL q
    elm.Val

  /// Returns the last element of the queue.
  [<CompiledName ("HeadR")>]
  let headr (RandomAccessQueue q) =
    let elm = Op.HeadR q
    elm.Val

  /// Returns the tail of the queue.
  [<CompiledName ("Tail")>]
  let tail (RandomAccessQueue q) = Op.TailL q |> RandomAccessQueue

  /// Returns the tail of the queue in reverse order.
  [<CompiledName ("TailR")>]
  let tailr (RandomAccessQueue q) = Op.TailR q |> RandomAccessQueue

  /// Inserts an element at the given index.
  [<CompiledName ("InsertAt")>]
  let insertAt i v q =
    splitAt i q
    |> fun (RandomAccessQueue hd, RandomAccessQueue tl) ->
      Op.Concat(snoc hd v, tl) |> RandomAccessQueue

  /// Finds the first element that satisfies the given predicate.
  [<CompiledName ("Find")>]
  let find pred (RandomAccessQueue q) =
    let rec loop cnt q =
      match Op.ViewL q with
      | Nil -> None
      | Cons(hd: RandomAccessQueueElem<_>, tl) ->
        if pred hd.Val then Some cnt else loop (cnt + 1) tl
    loop 0 q

  /// Finds the last element that satisfies the given predicate.
  [<CompiledName ("FindBack")>]
  let rec findBack pred (RandomAccessQueue q) =
    match Op.ViewR q with
    | Nil -> None
    | Cons(hd: RandomAccessQueueElem<_>, tl) ->
      let tl = RandomAccessQueue tl
      if pred hd.Val then length tl |> Some else findBack pred tl

  /// Concatenates two queues.
  [<CompiledName ("Concat")>]
  let concat (RandomAccessQueue q1) (RandomAccessQueue q2) =
    Op.Concat(q1, q2) |> RandomAccessQueue

  /// Converts the queue to a list.
  [<CompiledName ("ToList")>]
  let toList (RandomAccessQueue q) =
    foldr (fun (elt: RandomAccessQueueElem<_>) acc -> elt.Val :: acc) q []
