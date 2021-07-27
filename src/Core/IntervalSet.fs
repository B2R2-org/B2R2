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

/// An element for our interval set.
type IntervalSetElem (interval) =
  member val Val: AddrRange = interval
with
  member __.Min = __.Val.Min
  member __.Max = __.Val.Max
  override __.ToString () = __.Val.ToString ()
  interface IMeasured<InterMonoid<Addr>> with
    member __.Measurement =
      InterMonoid<Addr> (Ordered(Key(__.Val.Min)), Priority(Prio(__.Val.Max)))

/// Interval tree-based set, which stores intervals (AddrRange) that can
/// overlap unlike ARMap.
type IntervalSet =
  private
    IntervalSet of FingerTree<InterMonoid<Addr>, IntervalSetElem>

/// Helper module for IntervalSet.
module IntervalSet =

  /// Empty interval tree.
  let empty: IntervalSet = IntervalSet Empty

  /// Add an item to the interval tree.
  let add (i: AddrRange) (IntervalSet m) =
    let l, r =
      Op.Split (fun (e: InterMonoid<Addr>) -> Key i.Min <= e.GetMin ()) m
    IntervalSet <| Op.Concat l (Op.Cons (IntervalSetElem i) r)

  /// Check whether the given address interval is included in any of the
  /// intervals in the interval set.
  let includeRange (range: AddrRange) (IntervalSet s) =
    let il = range.Min
    let ih = range.Max
    if Prio il <= ((s :> IMeasured<_>).Measurement).GetMax () then
      let z = (s.Monoid :> IMonoid<InterMonoid<Addr>>).Zero
      let (_, x, _) =
        Op.SplitTree (fun (e: InterMonoid<Addr>) -> Prio il <= e.GetMax()) z s
      x.Min <= ih
    else false

  /// Find all overlapping intervals.
  let findAll (range: AddrRange) (IntervalSet s) =
    let il = range.Min
    let ih = range.Max
    let dropMatcher (e: InterMonoid<Addr>) = Prio il <= e.GetMax ()
    let rec matches acc xs =
      let v = Op.DropUntil dropMatcher xs
      match Op.ViewL v with
      | Nil -> acc
      | Cons (x: IntervalSetElem, xs) -> matches (x.Val :: acc) xs
    Op.TakeUntil (fun (elt: InterMonoid<Addr>) -> Key ih < elt.GetMin ()) s
    |> matches []

  /// Find and return the first matching interval from the given range.
  let tryFind range s =
    findAll range s
    |> List.tryHead

  /// Find and return the first matching interval from the given address.
  let tryFindByAddr addr s =
    tryFind (AddrRange (addr, addr)) s

  /// Check whether the given address exists in the interval set.
  let containsAddr addr s = includeRange (AddrRange (addr, addr)) s

  /// Check whether the exact interval exists in the interval set.
  let contains (i: AddrRange) (IntervalSet s) =
    let _, r =
      Op.Split (fun (e: InterMonoid<Addr>) -> Key i.Min <= e.GetMin ()) s
    let rec containLoop r =
      match Op.ViewL r with
      | Nil -> false
      | Cons (x: IntervalSetElem, _) when x.Min = i.Min && x.Max = i.Max -> true
      | Cons (x, xs) ->
        if i.Min = x.Min then containLoop xs
        else false
    containLoop r

  /// Assuming the given AddrRange is in the set, remove the range.
  let remove (range: AddrRange) (IntervalSet s) =
    let l, r =
      Op.Split (fun (e: InterMonoid<Addr>) -> Key range.Min <= e.GetMin ()) s
    let rec rmLoop l r =
      match Op.ViewL r with
      | Nil -> raise InvalidAddrRangeException
      | Cons (x: IntervalSetElem, xs)
        when x.Min = range.Min && x.Max = range.Max ->
        Op.Concat l xs
      | Cons (x, xs) ->
        if range.Min = x.Min then rmLoop (Op.Snoc l x) xs
        else raise InvalidAddrRangeException
    IntervalSet <| rmLoop l r

  /// Fold the set.
  let fold fn acc (IntervalSet s) =
    foldl (fun acc (elt: IntervalSetElem) -> fn acc elt.Val) acc s

  /// Iterate the set.
  let iter fn s = fold (fun _ elt -> fn elt) () s

// vim: set tw=80 sts=2 sw=2:
