(*
  B2R2 - the Next-Generation Reversing Platform

  Copyright (c) SoftSec Lab. @ KAIST, since 2016

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*)

namespace B2R2.Core.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2.Collections

[<TestClass>]
type PersistentQueueTests() =

  let rec toList q acc =
    if PersistentQueue.isEmpty q then List.rev acc
    else
      let elt, q = PersistentQueue.dequeue q
      toList q (elt :: acc)

  let toList q = toList q []

  [<TestMethod>]
  member _.``Empty Queue``() =
    Assert.AreEqual<bool>(true, PersistentQueue.isEmpty PersistentQueue.empty)

  [<TestMethod>]
  member _.``FIFO``() =
    let q =
      PersistentQueue.empty
      |> PersistentQueue.enqueue 1
      |> PersistentQueue.enqueue 2
      |> PersistentQueue.enqueue 3
    Assert.AreEqual<int list>([ 1; 2; 3 ], toList q)

  [<TestMethod>]
  member _.``Persistence``() =
    let q1 = PersistentQueue.empty |> PersistentQueue.enqueue 1
    let q2 = q1 |> PersistentQueue.enqueue 2
    Assert.AreEqual<int list>([ 1 ], toList q1)
    Assert.AreEqual<int list>([ 1; 2 ], toList q2)

  [<TestMethod>]
  member _.``Dequeue From Empty Queue``() =
    Assert.Throws<EmptyPersistentQueueException>(fun () ->
      PersistentQueue.dequeue PersistentQueue.empty |> ignore)
    |> ignore

  [<TestMethod>]
  member _.``Filter Front Only Queue``() =
    let q =
      PersistentQueue.empty
      |> PersistentQueue.enqueue 1
      |> PersistentQueue.enqueue 2
      |> PersistentQueue.enqueue 3
      |> PersistentQueue.filter (fun n -> n % 2 = 1)
    Assert.AreEqual<int list>([ 1; 3 ], toList q)

  [<TestMethod>]
  member _.``Filter Mixed Front And Back Queue``() =
    let q =
      PersistentQueue.empty
      |> PersistentQueue.enqueue 1
      |> PersistentQueue.enqueue 2
      |> PersistentQueue.enqueue 3
    let _, q = PersistentQueue.dequeue q
    let q =
      q
      |> PersistentQueue.enqueue 4
      |> PersistentQueue.enqueue 5
    Assert.AreEqual<int list>([ 2; 3; 4; 5 ], toList q)

    let q = q |> PersistentQueue.filter (fun n -> n % 2 = 0)
    Assert.AreEqual<int list>([ 2; 4 ], toList q)

  [<TestMethod>]
  member _.``Filter Removes All Elements``() =
    let q =
      PersistentQueue.empty
      |> PersistentQueue.enqueue 1
      |> PersistentQueue.enqueue 2
      |> PersistentQueue.filter (fun _ -> false)
    Assert.AreEqual<bool>(true, PersistentQueue.isEmpty q)
