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

open System
open System.Runtime.CompilerServices
open System.Threading.Tasks
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2.Collections

[<AllowNullLiteral>]
type WeakBucketTableItem(value: int, text: string) =
  let mutable initializedHash = 0
  member _.Value = value
  member _.Text = text
  member _.InitializedHash
    with get() = initializedHash
    and set v = initializedHash <- v

module private WeakBucketTableTestHelper =
  [<MethodImpl(MethodImplOptions.NoInlining)>]
  let addWeakEntry (table: WeakBucketTable<WeakBucketTableItem>) =
    let item = WeakBucketTableItem(1, "item")
    table.Intern(item, 1) |> ignore
    WeakReference<WeakBucketTableItem>(item)

[<TestClass>]
type WeakBucketTableTests() =
  let makeTable threshold =
    WeakBucketTable<WeakBucketTableItem>(
      (fun lhs rhs -> lhs.Value = rhs.Value),
      (fun item hash -> item.InitializedHash <- hash),
      threshold
    )

  [<TestMethod>]
  member _.``InternReturnsLiveCanonicalValue``() =
    let table = makeTable 16
    let item1 = WeakBucketTableItem(1, "first")
    let item2 = WeakBucketTableItem(1, "second")
    let interned1 = table.Intern(item1, 1)
    let interned2 = table.Intern(item2, 1)
    Assert.AreEqual<bool>(true, Object.ReferenceEquals(interned1, interned2))
    Assert.AreEqual<string>("first", interned2.Text)
    Assert.AreEqual<int>(1, table.Count)

  [<TestMethod>]
  member _.``InternHandlesHashCollisions``() =
    let table = makeTable 16
    let item1 = WeakBucketTableItem(1, "one")
    let item2 = WeakBucketTableItem(2, "two")
    let interned1 = table.Intern(item1, 10)
    let interned2 = table.Intern(item2, 10)
    Assert.AreEqual<bool>(false, Object.ReferenceEquals(interned1, interned2))
    Assert.AreEqual<int>(1, interned1.Value)
    Assert.AreEqual<int>(2, interned2.Value)
    Assert.AreEqual<int>(1, table.BucketCount)

  [<TestMethod>]
  member _.``InternInitializesOnlyInsertedValues``() =
    let table = makeTable 16
    let item1 = WeakBucketTableItem(1, "first")
    let item2 = WeakBucketTableItem(1, "second")
    table.Intern(item1, 7) |> ignore
    table.Intern(item2, 7) |> ignore
    Assert.AreEqual<int>(7, item1.InitializedHash)
    Assert.AreEqual<int>(0, item2.InitializedHash)

  [<TestMethod>]
  member _.``InternIsThreadSafe``() =
    let table = makeTable 64
    let values =
      [| for _ in 0 .. 99 ->
           Task.Run(fun () ->
             table.Intern(WeakBucketTableItem(1, "item"), 1)) |]
      |> Task.WhenAll
      |> fun task -> task.Result
    let first = values[0]
    let allSame =
      values |> Array.forall (fun v -> Object.ReferenceEquals(v, first))
    Assert.AreEqual<bool>(true, allSame)
    Assert.AreEqual<int>(1, table.Count)

  [<TestMethod>]
  member _.``ClearRemovesEntries``() =
    let table = makeTable 16
    table.Intern(WeakBucketTableItem(1, "one"), 1) |> ignore
    table.Intern(WeakBucketTableItem(2, "two"), 2) |> ignore
    table.Clear()
    Assert.AreEqual<int>(0, table.Count)
    Assert.AreEqual<int>(0, table.BucketCount)
    let item = WeakBucketTableItem(1, "new")
    let interned = table.Intern(item, 1)
    Assert.AreEqual<bool>(true, Object.ReferenceEquals(item, interned))
    Assert.AreEqual<int>(1, table.Count)

  [<TestMethod>]
  member _.``SweepRemovesDeadWeakReferences``() =
    let table = makeTable 2
    let weakRef = WeakBucketTableTestHelper.addWeakEntry table
    GC.Collect()
    GC.WaitForPendingFinalizers()
    GC.Collect()
    table.Sweep()
    match weakRef.TryGetTarget() with
    | true, _ -> Assert.Inconclusive("GC kept the weakly referenced item alive")
    | false, _ -> Assert.AreEqual<int>(0, table.Count)
