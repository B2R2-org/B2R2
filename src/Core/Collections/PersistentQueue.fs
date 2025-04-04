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

/// Persistent queue using two lists.
type PersistentQueue<'T> =
  private PQ of 'T list * 'T list

[<RequireQualifiedAccess>]
module PersistentQueue =

  /// An empty queue.
  [<CompiledName ("Empty")>]
  let empty = PQ ([], [])

  /// Check if the given queue is empty.
  [<CompiledName ("IsEmpty")>]
  let isEmpty q =
    match q with
    | PQ ([], []) -> true
    | _ -> false

  /// Enqueue an element to the queue.
  [<CompiledName ("Enqueue")>]
  let enqueue q elt =
    match q with
    | PQ (front, back) -> PQ (elt :: front, back)

  /// Dequeue an element from the queue.
  [<CompiledName ("Dequeue")>]
  let dequeue q =
    match q with
    | PQ ([], []) -> raise (System.InvalidOperationException ())
    | PQ (front, elt :: back) -> elt, PQ (front, back)
    | PQ (front, []) ->
      let back = List.rev front
      back.Head, PQ ([], back.Tail)

  /// Filter elements based on the given predicate.
  [<CompiledName ("Filter")>]
  let filter pred q =
    match q with
    | PQ (front, back) -> PQ (List.filter pred front, List.filter pred back)
