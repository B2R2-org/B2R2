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

/// Represents an error raised when an operation requires a non-empty
/// persistent queue.
exception EmptyPersistentQueueException

/// Represents a persistent queue. Uses two lists internally to represent the
/// queue.
type PersistentQueue<'T> =
  private PQ of 'T list * 'T list

/// Provides functions to create or manipulate persistent queues.
[<RequireQualifiedAccess>]
module PersistentQueue =

  /// Represents an empty queue.
  [<CompiledName ("Empty")>]
  let empty = PQ([], [])

  /// Checks whether the given queue is empty.
  [<CompiledName ("IsEmpty")>]
  let isEmpty q =
    match q with
    | PQ([], []) -> true
    | _ -> false

  /// Enqueues an element to the queue.
  [<CompiledName ("Enqueue")>]
  let enqueue elt q =
    match q with
    | PQ(front, back) -> PQ(elt :: front, back)

  /// Dequeues the oldest element from the queue.
  [<CompiledName ("Dequeue")>]
  let dequeue q =
    match q with
    | PQ([], []) -> raise EmptyPersistentQueueException
    | PQ(front, elt :: back) -> elt, PQ(front, back)
    | PQ(front, []) ->
      let back = List.rev front
      back.Head, PQ([], back.Tail)

  /// Filters elements based on the given predicate.
  [<CompiledName ("Filter")>]
  let filter pred q =
    match q with
    | PQ(front, back) -> PQ(List.filter pred front, List.filter pred back)
