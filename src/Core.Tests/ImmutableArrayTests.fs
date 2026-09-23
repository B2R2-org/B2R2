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
open System.Collections.Immutable
open System.Runtime.InteropServices
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2.Collections

/// Tests the way out of an immutable array. What matters about these beyond
/// the results they give is that they walk by index: a traversal is what the
/// module exists to keep free of the allocation the Seq module would make.
[<TestClass>]
type ImmutableArrayTests() =

  static let sample = ImmutableArray.ofArray [| 3; 1; 4; 1; 5 |]

  /// Measures what the given function allocates on this thread, having run it
  /// once beforehand so that nothing it sets up for good is counted.
  static let allocatedBy (f: unit -> int) =
    f () |> ignore
    GC.Collect()
    GC.WaitForPendingFinalizers()
    GC.Collect()
    let before = GC.GetAllocatedBytesForCurrentThread()
    f () |> ignore
    GC.GetAllocatedBytesForCurrentThread() - before

  /// Wrapping shares the storage rather than copying it, which is the whole
  /// reason a cached array is handed over as an immutable one at all.
  [<TestMethod>]
  member _.``ofArray shares the storage of the array it wraps``() =
    let backing = [| 1; 2; 3 |]
    let wrapped = ImmutableArray.ofArray backing
    let inner = ImmutableCollectionsMarshal.AsArray wrapped
    Assert.AreEqual<bool>(true, obj.ReferenceEquals(backing, inner))

  /// Going back the other way copies, so that what a caller gets is its own
  /// to write into.
  [<TestMethod>]
  member _.``toArray copies the storage it reads``() =
    let backing = [| 1; 2; 3 |]
    let copied = ImmutableArray.toArray (ImmutableArray.ofArray backing)
    CollectionAssert.AreEqual(backing, copied)
    Assert.AreEqual<bool>(false, obj.ReferenceEquals(backing, copied))

  [<TestMethod>]
  member _.``toList keeps the order the array holds``() =
    Assert.AreEqual<int list>([ 3; 1; 4; 1; 5 ], ImmutableArray.toList sample)
    Assert.AreEqual<int list>([], ImmutableArray.toList ImmutableArray.Empty)

  [<TestMethod>]
  member _.``map and mapi walk every element in order``() =
    CollectionAssert.AreEqual([| 6; 2; 8; 2; 10 |],
                              ImmutableArray.map (fun x -> x * 2) sample)
    CollectionAssert.AreEqual([| 0; 1; 2; 3; 4 |],
                              ImmutableArray.mapi (fun i _ -> i) sample)
    CollectionAssert.AreEqual([||], ImmutableArray.map id ImmutableArray.Empty)

  [<TestMethod>]
  member _.``filter and choose keep only what they are asked for``() =
    CollectionAssert.AreEqual([| 4 |],
                              ImmutableArray.filter (fun x -> x > 3) sample
                              |> Array.filter (fun x -> x < 5))
    let odd x = if x % 2 = 1 then Some(x * 10) else None
    CollectionAssert.AreEqual([| 30; 10; 10; 50 |],
                              ImmutableArray.choose odd sample)
    CollectionAssert.AreEqual([||],
                              ImmutableArray.filter (fun _ -> false) sample)

  [<TestMethod>]
  member _.``fold threads the accumulator through in order``() =
    Assert.AreEqual<int>(14, ImmutableArray.fold (+) 0 sample)
    Assert.AreEqual<string>("31415",
                            ImmutableArray.fold (fun s x -> s + string x) ""
                                                sample)

  /// A search answers with the first element that matches, and stops there.
  [<TestMethod>]
  member _.``tryFind and tryFindIndex answer with the first match``() =
    Assert.AreEqual<int option>(Some 1,
                                ImmutableArray.tryFind (fun x -> x < 3) sample)
    Assert.AreEqual<int option>(Some 1,
                                ImmutableArray.tryFindIndex (fun x -> x < 3)
                                                            sample)
    Assert.AreEqual<int option>(None,
                                ImmutableArray.tryFind (fun x -> x > 9) sample)
    Assert.AreEqual<int option>(None,
                                ImmutableArray.tryFindIndex (fun x -> x > 9)
                                                            sample)

  [<TestMethod>]
  member _.``exists and forall answer over the whole array``() =
    Assert.AreEqual<bool>(true, ImmutableArray.exists (fun x -> x = 5) sample)
    Assert.AreEqual<bool>(false, ImmutableArray.exists (fun x -> x = 9) sample)
    Assert.AreEqual<bool>(true, ImmutableArray.forall (fun x -> x > 0) sample)
    Assert.AreEqual<bool>(false, ImmutableArray.forall (fun x -> x > 1) sample)
    Assert.AreEqual<bool>(false,
                          ImmutableArray.exists (fun _ -> true)
                                                ImmutableArray.Empty)
    Assert.AreEqual<bool>(true,
                          ImmutableArray.forall (fun _ -> false)
                                                ImmutableArray.Empty)

  /// The point of walking by index: a traversal that answers with a single
  /// value allocates nothing at all, where the Seq module would box the
  /// struct enumerator the immutable array hands it.
  [<TestMethod>]
  member _.``a traversal answering with one value allocates nothing``() =
    let big = ImmutableArray.ofArray (Array.init 10000 id)
    Assert.AreEqual<int64>(0L,
                           allocatedBy (fun () ->
                             ImmutableArray.fold (+) 0 big))
    Assert.AreEqual<int64>(0L,
                           allocatedBy (fun () ->
                             if ImmutableArray.exists (fun x -> x = 9999) big
                             then 1 else 0))
