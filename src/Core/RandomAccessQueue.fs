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

namespace B2R2

open B2R2.FingerTree

/// An element for our random access queue.
type RandomAccessQueueElem<'T> (v) =
  member val Val: 'T = v
  override __.ToString () = __.Val.ToString ()
  interface IMeasured<Size> with
    member __.Measurement = Size (1u)

/// Interval tree-based map: an interval of type (Addr) -> an
/// RandomAccessQueueElement ('a).
type RandomAccessQueue<'T> =
  private
    RandomAccessQueue of FingerTree<Size, RandomAccessQueueElem<'T>>

/// A helper module for RandomAccessQueue<'a>.
[<RequireQualifiedAccess>]
module RandomAccessQueue =

  /// Empty interval tree.
  let empty: RandomAccessQueue<_> = RandomAccessQueue Empty

  let isEmpty (q: RandomAccessQueue<_>) = q = RandomAccessQueue Empty

  let length (RandomAccessQueue q) =
    ((q :> IMeasured<_>).Measurement).Value |> int

  /// Split the queue based on the given index into two (left and right). The
  /// left queue will contain the entry at the given index.
  let splitAt i (RandomAccessQueue q) =
    let l, r = Op.Split (fun (elt: Size) -> i < elt.Value) q
    RandomAccessQueue l, RandomAccessQueue r

  let private snoc q v =
    Op.Snoc q (RandomAccessQueueElem v)

  let enqueue v (RandomAccessQueue q) =
    snoc q v |> RandomAccessQueue

  let dequeue q =
    let (RandomAccessQueue hd), tl = splitAt 1u q
    let elm = Op.HeadL hd
    elm.Val, tl

  let head (RandomAccessQueue q) =
    let elm = Op.HeadL q
    elm.Val

  let headr (RandomAccessQueue q) =
    let elm = Op.HeadR q
    elm.Val

  let tail (RandomAccessQueue q) = Op.TailL q |> RandomAccessQueue

  let tailr (RandomAccessQueue q) = Op.TailR q |> RandomAccessQueue

  let insertAt i v q =
    let (RandomAccessQueue hd, RandomAccessQueue tl) = splitAt i q
    Op.Concat (snoc hd v) tl |> RandomAccessQueue

  let find pred (RandomAccessQueue q) =
    let rec loop cnt q =
      match Op.ViewL q with
      | Nil -> None
      | Cons (hd: RandomAccessQueueElem<_>, tl) ->
        if pred hd.Val then Some cnt else loop (cnt + 1) tl
    loop 0 q

  let rec findBack pred (RandomAccessQueue q) =
    match Op.ViewR q with
    | Nil -> None
    | Cons (hd: RandomAccessQueueElem<_>, tl) ->
      let tl = RandomAccessQueue tl
      if pred hd.Val then length tl |> Some else findBack pred tl

  let concat (RandomAccessQueue q1) (RandomAccessQueue q2) =
    Op.Concat q1 q2 |> RandomAccessQueue

  let toList (RandomAccessQueue q) =
    foldr (fun (elt: RandomAccessQueueElem<_>) acc -> elt.Val :: acc) q []

// vim: set tw=80 sts=2 sw=2:
