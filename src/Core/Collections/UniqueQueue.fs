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

/// A queue that only stores unique elements.
type UniqueQueue<'T> () =
  let queue = Queue<'T> ()
  let set = HashSet<'T> ()

  /// Enqueue an element only if it is not already in the queue.
  member __.Enqueue (x: 'T) =
    if set.Add x |> not then ()
    else queue.Enqueue x

  /// Dequeue an element. If the element is not in the queue, it raises an
  /// exception.
  member __.Dequeue () =
    let x = queue.Dequeue ()
    if set.Remove x then x
    else B2R2.Terminator.impossible ()

  /// Try to dequeue an element.
  member __.TryDequeue ([<Out>] result: byref<'T>) =
    if not <| queue.TryDequeue (&result) then false
    else set.Remove result

  /// Get the number of elements in the queue.
  member __.Count = queue.Count

  /// Clear the queue.
  member __.Clear () = queue.Clear ()

  /// Check if the queue is empty.
  member __.IsEmpty with get () = queue.Count = 0

