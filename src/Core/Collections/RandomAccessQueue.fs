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

/// Represents an error raised when an operation requires a non-empty random
/// access queue.
exception EmptyRandomAccessQueueException

/// Represents an element for our random access queue.
type private RandomAccessQueueElem<'T>(v) =
  member val Val: 'T = v
  override this.ToString() = this.Val.ToString()
  interface IMeasured<Size> with
    member _.Measurement = Size(1u)

/// Represents a random access queue: a sequence of elements that can be
/// accessed by index.
type RandomAccessQueue<'T> =
  private
    RandomAccessQueue of FingerTree<Size, RandomAccessQueueElem<'T>>

/// Provides functions for creating or manipulating random access queues.
[<RequireQualifiedAccess>]
module RandomAccessQueue =

  /// Returns an empty random access queue.
  [<CompiledName ("Empty")>]
  let empty: RandomAccessQueue<_> = RandomAccessQueue Empty

  /// Checks if the given queue is empty.
  [<CompiledName ("IsEmpty")>]
  let isEmpty (q: RandomAccessQueue<_>) = q = RandomAccessQueue Empty

  /// Returns the length of the queue.
  [<CompiledName ("Length")>]
  let length (RandomAccessQueue q) =
    ((q :> IMeasured<_>).Measurement).Value |> int

  /// <summary>
  /// Splits the queue based on the given index into two (left and right). The
  /// left queue contains the first <c>i</c> elements. If <c>i</c> is less than
  /// or equal to zero, the left queue is empty. If <c>i</c> is greater than or
  /// equal to the queue length, the right queue is empty.
  /// </summary>
  [<CompiledName ("SplitAt")>]
  let splitAt i ((RandomAccessQueue q) as queue) =
    if i <= 0 then empty, queue
    elif i >= length queue then queue, empty
    else
      let i = uint32 i
      let l, r = Op.Split((fun (elt: Size) -> i < elt.Value), q)
      RandomAccessQueue l, RandomAccessQueue r

  let private snoc q v = Op.Snoc(q, RandomAccessQueueElem v)

  let private viewHead (RandomAccessQueue q) =
    match Op.ViewL q with
    | Nil -> raise EmptyRandomAccessQueueException
    | Cons(elm, tl) -> elm, RandomAccessQueue tl

  let private viewLast (RandomAccessQueue q) =
    match Op.ViewR q with
    | Nil -> raise EmptyRandomAccessQueueException
    | Cons(elm, rest) -> elm, RandomAccessQueue rest

  /// Enqueues an element to the queue.
  [<CompiledName ("Enqueue")>]
  let enqueue v (RandomAccessQueue q) = snoc q v |> RandomAccessQueue

  /// Dequeues the oldest element from the queue.
  [<CompiledName ("Dequeue")>]
  let dequeue q =
    let elm, tl = viewHead q
    elm.Val, tl

  /// Returns the first element of the queue. Raises
  /// EmptyRandomAccessQueueException if the queue is empty.
  [<CompiledName ("Head")>]
  let head q =
    let elm, _ = viewHead q
    elm.Val

  /// Returns the last element of the queue. Raises
  /// EmptyRandomAccessQueueException if the queue is empty.
  [<CompiledName ("HeadR")>]
  let headr q =
    let elm, _ = viewLast q
    elm.Val

  /// Returns the queue without its first element. Raises
  /// EmptyRandomAccessQueueException if the queue is empty.
  [<CompiledName ("Tail")>]
  let tail q =
    let _, tl = viewHead q
    tl

  /// Returns the queue without its last element. Raises
  /// EmptyRandomAccessQueueException if the queue is empty.
  [<CompiledName ("TailR")>]
  let tailr q =
    let _, rest = viewLast q
    rest

  /// Inserts an element at the given index. If the index is less than or equal
  /// to zero, the element is inserted at the front. If the index is greater
  /// than or equal to the queue length, the element is appended at the end.
  [<CompiledName ("InsertAt")>]
  let insertAt i v q =
    splitAt i q
    |> fun (RandomAccessQueue hd, RandomAccessQueue tl) ->
      Op.Concat(snoc hd v, tl) |> RandomAccessQueue

  /// Returns the element at the given index, or None if the index is out of
  /// range.
  [<CompiledName ("TryGetAt")>]
  let tryGetAt i q =
    if i < 0 || i >= length q then None
    else
      let _, rest = splitAt i q
      let elm, _ = viewHead rest
      Some elm.Val

  /// Returns the element at the given index. Raises IndexOutOfRangeException if
  /// the index is out of range.
  [<CompiledName ("GetAt")>]
  let getAt i q =
    match tryGetAt i q with
    | Some v -> v
    | None -> raise (System.IndexOutOfRangeException())

  /// Finds the index of the first element that satisfies the given predicate.
  [<CompiledName ("TryFindIndex")>]
  let tryFindIndex pred (RandomAccessQueue q) =
    let rec loop cnt q =
      match Op.ViewL q with
      | Nil -> None
      | Cons(hd: RandomAccessQueueElem<_>, tl) ->
        if pred hd.Val then Some cnt else loop (cnt + 1) tl
    loop 0 q

  /// Finds the index of the last element that satisfies the given predicate.
  [<CompiledName ("TryFindIndexBack")>]
  let rec tryFindIndexBack pred (RandomAccessQueue q) =
    match Op.ViewR q with
    | Nil -> None
    | Cons(hd: RandomAccessQueueElem<_>, tl) ->
      let tl = RandomAccessQueue tl
      if pred hd.Val then length tl |> Some else tryFindIndexBack pred tl

  /// Concatenates two queues.
  [<CompiledName ("Concat")>]
  let concat (RandomAccessQueue q1) (RandomAccessQueue q2) =
    Op.Concat(q1, q2) |> RandomAccessQueue

  /// Converts the queue to a list.
  [<CompiledName ("ToList")>]
  let toList (RandomAccessQueue q) =
    foldr (fun (elt: RandomAccessQueueElem<_>) acc -> elt.Val :: acc) q []
