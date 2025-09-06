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

namespace B2R2.MiddleEnd.ControlFlowAnalysis

open System.Collections.Generic

/// A priority queue to store the ICFGActions.
type CFGActionQueue() =
  let pq = PriorityQueue<CFGAction, Priority<int>>()
  let mutable count = 0

  let toPriority p =
    let myCount = count
    count <- count + 1
    (-p, myCount)

  /// Count the number of actions in the queue.
  member _.Count with get() = pq.Count

  /// Push an action to the queue.
  member _.Push(judge: IPrioritizable, action) =
    pq.Enqueue(action, toPriority (action.Priority judge))

  /// Pop an action from the queue.
  member _.Pop() = pq.Dequeue()

  /// Peek the action with the highest priority.
  member _.Peek() = pq.Peek()

  /// Check if the queue is empty.
  member _.IsEmpty() = pq.Count = 0

  /// Clear the queue.
  member _.Clear() = pq.Clear()

  member _.UnorderedItems with get() = pq.UnorderedItems

and private Priority<'P> = 'P * int