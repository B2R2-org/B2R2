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
open B2R2.Collections.FingerTree

type private TestSize(s) =
  new() = TestSize(0u)
  member _.Value: uint32 = s
  override _.ToString() = s.ToString()
  interface IMonoid<TestSize> with
    member _.Zero = TestSize(0u)
    member _.Combine(rhs: TestSize) = TestSize(s + rhs.Value)

type private FingerTreeElem(v) =
  member _.Value: int = v
  override _.ToString() = v.ToString()
  interface IMeasured<TestSize> with
    member _.Measurement = TestSize(1u)

[<TestClass>]
type FingerTreeTests() =

  let empty: FingerTree<TestSize, FingerTreeElem> = Empty

  let snoc value tree = Op.Snoc(tree, FingerTreeElem value)

  let cons value tree = Op.Cons(FingerTreeElem value, tree)

  let ofList values = List.fold (fun tree value -> snoc value tree) empty values

  let toList tree =
    foldr (fun (elt: FingerTreeElem) acc -> elt.Value :: acc) tree []

  let length (tree: FingerTree<TestSize, FingerTreeElem>) =
    ((tree :> IMeasured<_>).Measurement).Value

  [<TestMethod>]
  member _.``Cons And Snoc Preserve Order``() =
    let tree =
      empty
      |> snoc 2
      |> snoc 3
      |> cons 1
      |> cons 0
      |> snoc 4
    Assert.AreEqual<int list>([ 0; 1; 2; 3; 4 ], toList tree)
    Assert.AreEqual<uint32>(5u, length tree)

  [<TestMethod>]
  member _.``Foldl And Foldr Traverse In Logical Order``() =
    let tree = ofList [ 1 .. 16 ]
    let left =
      foldl (fun acc (elt: FingerTreeElem) -> acc @ [ elt.Value ]) [] tree
    let right =
      foldr (fun (elt: FingerTreeElem) acc -> elt.Value :: acc) tree []
    Assert.AreEqual<int list>([ 1 .. 16 ], left)
    Assert.AreEqual<int list>([ 1 .. 16 ], right)

  [<TestMethod>]
  member _.``ViewL Removes Elements From The Front``() =
    let rec drain acc (tree: FingerTree<TestSize, FingerTreeElem>) =
      match Op.ViewL tree with
      | Nil -> List.rev acc
      | Cons(elt, rest) -> drain (elt.Value :: acc) rest
    Assert.AreEqual<int list>([ 1 .. 12 ], ofList [ 1 .. 12 ] |> drain [])

  [<TestMethod>]
  member _.``ViewR Removes Elements From The Back``() =
    let rec drain acc (tree: FingerTree<TestSize, FingerTreeElem>) =
      match Op.ViewR tree with
      | Nil -> acc
      | Cons(elt, rest) -> drain (elt.Value :: acc) rest
    Assert.AreEqual<int list>([ 1 .. 12 ], ofList [ 1 .. 12 ] |> drain [])

  [<TestMethod>]
  member _.``Split Keeps Triggering Element On The Right``() =
    let tree = ofList [ 0 .. 9 ]
    let left, right = Op.Split((fun (size: TestSize) -> 5u < size.Value), tree)
    Assert.AreEqual<int list>([ 0; 1; 2; 3; 4 ], toList left)
    Assert.AreEqual<int list>([ 5; 6; 7; 8; 9 ], toList right)
    Assert.AreEqual<uint32>(5u, length left)
    Assert.AreEqual<uint32>(5u, length right)

  [<TestMethod>]
  member _.``TakeUntil And DropUntil Follow Split Semantics``() =
    let tree = ofList [ 0 .. 6 ]
    let pred (size: TestSize) = 3u < size.Value
    Assert.AreEqual<int list>([ 0; 1; 2 ], Op.TakeUntil(pred, tree) |> toList)
    Assert.AreEqual<int list>([ 3; 4; 5; 6 ],
                              Op.DropUntil(pred, tree) |> toList)

  [<TestMethod>]
  member _.``Concat Preserves Both Sides``() =
    let left = ofList [ 1 .. 8 ]
    let right = ofList [ 9 .. 20 ]
    let tree = Op.Concat(left, right)
    Assert.AreEqual<int list>([ 1 .. 20 ], toList tree)
    Assert.AreEqual<uint32>(20u, length tree)

  [<TestMethod>]
  member _.``Lookup Uses Initial Measure``() =
    let tree = ofList [ 10; 20; 30 ]
    let measure, elt = Op.Lookup((fun (size: TestSize) -> 2u < size.Value),
                                 TestSize(1u),
                                 tree)
    Assert.AreEqual<uint32>(2u, measure.Value)
    Assert.AreEqual<int>(20, elt.Value)

  [<TestMethod>]
  member _.``Head And Tail Raise On Empty Tree``() =
    Assert.Throws<EmptyTreeException>(fun () -> Op.HeadL empty |> ignore)
    |> ignore
    Assert.Throws<EmptyTreeException>(fun () -> Op.HeadR empty |> ignore)
    |> ignore
    Assert.Throws<EmptyTreeException>(fun () -> Op.TailL empty |> ignore)
    |> ignore
    Assert.Throws<EmptyTreeException>(fun () -> Op.TailR empty |> ignore)
    |> ignore
