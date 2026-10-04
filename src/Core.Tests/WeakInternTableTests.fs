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

namespace B2R2.Core.Tests

open System
open System.Runtime.CompilerServices
open System.Threading.Tasks
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2.Collections

[<AllowNullLiteral>]
type WeakInternTableItem(value: int, text: string, hash: int) =
  member _.Value = value
  member _.Text = text
  member _.Hash = hash

/// Looks an item up by its value, and makes one with the given text, counting
/// how many it has made.
[<Struct>]
type WeakInternTableKey(value: int, text: string, made: int ref) =
  interface IInternKey<WeakInternTableItem> with
    member _.Matches item = item.Value = value
    member _.Create hash =
      made.Value <- made.Value + 1
      WeakInternTableItem(value, text, hash)

module private WeakInternTableTestHelper =
  let key value text = WeakInternTableKey(value, text, ref 0)

  [<MethodImpl(MethodImplOptions.NoInlining)>]
  let addWeakEntry (table: WeakInternTable<WeakInternTableItem>) =
    let item = table.Intern(key 1 "item", 1)
    WeakReference<WeakInternTableItem>(item)

  let collect () =
    GC.Collect()
    GC.WaitForPendingFinalizers()
    GC.Collect()

open WeakInternTableTestHelper

[<TestClass>]
type WeakInternTableTests() =
  [<TestMethod>]
  member _.``InternReturnsLiveCanonicalValue``() =
    let table = WeakInternTable<WeakInternTableItem>()
    let interned1 = table.Intern(key 1 "first", 1)
    let interned2 = table.Intern(key 1 "second", 1)
    Assert.AreEqual<bool>(true, Object.ReferenceEquals(interned1, interned2))
    Assert.AreEqual<string>("first", interned2.Text)
    Assert.AreEqual<int>(1, table.Count)

  [<TestMethod>]
  member _.``InternHandlesHashCollisions``() =
    let table = WeakInternTable<WeakInternTableItem>()
    let interned1 = table.Intern(key 1 "one", 10)
    let interned2 = table.Intern(key 2 "two", 10)
    Assert.AreEqual<bool>(false, Object.ReferenceEquals(interned1, interned2))
    Assert.AreEqual<int>(1, interned1.Value)
    Assert.AreEqual<int>(2, interned2.Value)
    Assert.AreEqual<int>(2, table.Count)

  [<TestMethod>]
  member _.``InternMakesOnlyMissingValues``() =
    let table = WeakInternTable<WeakInternTableItem>()
    let made = ref 0
    table.Intern(WeakInternTableKey(1, "first", made), 7) |> ignore
    table.Intern(WeakInternTableKey(1, "second", made), 7) |> ignore
    Assert.AreEqual<int>(1, made.Value)

  [<TestMethod>]
  member _.``InternMakesAValueUnderItsHash``() =
    let table = WeakInternTable<WeakInternTableItem>()
    Assert.AreEqual<int>(7, (table.Intern(key 1 "item", 7)).Hash)

  [<TestMethod>]
  member _.``InternIsThreadSafe``() =
    let table = WeakInternTable<WeakInternTableItem>()
    let values =
      [| for _ in 0 .. 99 ->
           Task.Run(fun () -> table.Intern(key 1 "item", 1)) |]
      |> Task.WhenAll
      |> fun task -> task.Result
    let first = values[0]
    let allSame =
      values |> Array.forall (fun v -> Object.ReferenceEquals(v, first))
    Assert.AreEqual<bool>(true, allSame)
    Assert.AreEqual<int>(1, table.Count)

  [<TestMethod>]
  member _.``InternKeepsManyValuesCanonical``() =
    (* Enough values for the table to grow many times over, with only a few
       hashes among them, so that every probe runs past others. *)
    let table = WeakInternTable<WeakInternTableItem>()
    let items = Array.init 20000 (fun i -> table.Intern(key i "item", i % 64))
    let same (item: WeakInternTableItem) =
      let again = table.Intern(key item.Value "again", item.Value % 64)
      Object.ReferenceEquals(item, again)
    Assert.AreEqual<bool>(true, Array.forall same items)
    Assert.AreEqual<int>(items.Length, table.Count)

  [<TestMethod>]
  member _.``ClearRemovesEntries``() =
    let table = WeakInternTable<WeakInternTableItem>()
    let old = table.Intern(key 1 "one", 1)
    table.Intern(key 2 "two", 2) |> ignore
    table.Clear()
    Assert.AreEqual<int>(0, table.Count)
    let interned = table.Intern(key 1 "new", 1)
    Assert.AreEqual<bool>(false, Object.ReferenceEquals(old, interned))
    Assert.AreEqual<int>(1, table.Count)

  [<TestMethod>]
  member _.``CompactRemovesCollectedValues``() =
    let table = WeakInternTable<WeakInternTableItem>()
    let weakRef = addWeakEntry table
    collect ()
    table.Compact()
    match weakRef.TryGetTarget() with
    | true, _ -> Assert.Inconclusive("GC kept the weakly referenced item alive")
    | false, _ -> Assert.AreEqual<int>(0, table.Count)

  [<TestMethod>]
  member _.``ACollectedValueIsMadeAgain``() =
    (* The slot a collected value leaves behind is passed over, not taken for
       a match: the next lookup of it makes it anew. *)
    let table = WeakInternTable<WeakInternTableItem>()
    let weakRef = addWeakEntry table
    collect ()
    match weakRef.TryGetTarget() with
    | true, _ ->
      Assert.Inconclusive("GC kept the weakly referenced item alive")
    | false, _ ->
      let made = ref 0
      table.Intern(WeakInternTableKey(1, "next", made), 1) |> ignore
      Assert.AreEqual<int>(1, made.Value)
