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

open B2R2
open B2R2.Collections.FingerTree

/// An element for our interval set.
type private IntervalSetElem(interval) =
  member val Val: AddrRange = interval
with
  member this.Min = this.Val.Min
  member this.Max = this.Val.Max
  override this.ToString() = this.Val.ToString()
  interface IMeasured<InterMonoid<Addr>> with
    member this.Measurement =
      InterMonoid<Addr>(Ordered(Key(this.Val.Min)),
                        Priority(Prio(this.Val.Max)))

/// <summary>
/// Represents an interval-tree-based set, which stores intervals (<see
/// cref='T:B2R2.AddrRange'/>) that can overlap unlike ARMap.
/// </summary>
type IntervalSet =
  private
    IntervalSet of FingerTree<InterMonoid<Addr>, IntervalSetElem>

/// Provides functions for creating or manipulating interval sets.
module IntervalSet =

  /// Empty interval tree.
  [<CompiledName("Empty")>]
  let empty: IntervalSet = IntervalSet Empty

  /// Adds an item to the interval tree.
  [<CompiledName("Add")>]
  let add (i: AddrRange) (IntervalSet m) =
    let l, r =
      Op.Split((fun (e: InterMonoid<Addr>) -> Key i.Min <= e.GetMin()), m)
    IntervalSet <| Op.Concat(l, Op.Cons(IntervalSetElem i, r))

  /// Checks whether the given address interval is included in any of the
  /// intervals in the interval set.
  [<CompiledName("IncludeRange")>]
  let includeRange (range: AddrRange) (IntervalSet s) =
    let il = range.Min
    let ih = range.Max
    if Prio il <= ((s :> IMeasured<_>).Measurement).GetMax() then
      let z = (s.Monoid :> IMonoid<InterMonoid<Addr>>).Zero
      let (_, x, _) =
        Op.SplitTree((fun (e: InterMonoid<Addr>) -> Prio il <= e.GetMax()),
          z, s)
      x.Min <= ih
    else false

  /// Finds all overlapping intervals in the given range.
  [<CompiledName("FindAll")>]
  let findAll (range: AddrRange) (IntervalSet s) =
    let il = range.Min
    let ih = range.Max
    let dropMatcher (e: InterMonoid<Addr>) = Prio il <= e.GetMax()
    let rec matches acc xs =
      let v = Op.DropUntil(dropMatcher, xs)
      match Op.ViewL v with
      | Nil -> acc
      | Cons(x: IntervalSetElem, xs) -> matches (x.Val :: acc) xs
    Op.TakeUntil((fun (elt: InterMonoid<Addr>) -> Key ih < elt.GetMin()), s)
    |> matches []

  /// Finds and returns the first matching interval from the given range.
  [<CompiledName("TryFind")>]
  let tryFind range s =
    findAll range s
    |> List.tryHead

  /// Finds and returns the first matching interval from the given address.
  [<CompiledName("TryFindByAddr")>]
  let tryFindByAddr addr s = tryFind (AddrRange(addr, addr)) s

  /// Checks whether the given address exists in the interval set.
  [<CompiledName("ContainsAddr")>]
  let containsAddr addr s = includeRange (AddrRange(addr, addr)) s

  /// Checks whether the exact interval exists in the interval set.
  [<CompiledName("Contains")>]
  let contains (i: AddrRange) (IntervalSet s) =
    let _, r =
      Op.Split((fun (e: InterMonoid<Addr>) -> Key i.Min <= e.GetMin()), s)
    let rec containLoop r =
      match Op.ViewL r with
      | Nil -> false
      | Cons(x: IntervalSetElem, _) when x.Min = i.Min && x.Max = i.Max -> true
      | Cons(x, xs) ->
        if i.Min = x.Min then containLoop xs
        else false
    containLoop r

  /// Removes the given range assuming it is in the set. Raises an exception if
  /// the range is not in the set.
  [<CompiledName("Remove")>]
  let remove (range: AddrRange) (IntervalSet s) =
    let l, r =
      Op.Split((fun (e: InterMonoid<Addr>) -> Key range.Min <= e.GetMin()), s)
    let rec rmLoop l r =
      match Op.ViewL r with
      | Nil -> raise InvalidAddrRangeException
      | Cons(x: IntervalSetElem, xs)
        when x.Min = range.Min && x.Max = range.Max ->
        Op.Concat(l, xs)
      | Cons(x, xs) ->
        if range.Min = x.Min then rmLoop (Op.Snoc(l, x)) xs
        else raise InvalidAddrRangeException
    IntervalSet <| rmLoop l r

  /// Folds the elements in the interval set.
  [<CompiledName("Fold")>]
  let fold fn acc (IntervalSet s) =
    foldl (fun acc (elt: IntervalSetElem) -> fn acc elt.Val) acc s

  /// Iterates the elements in the interval set.
  [<CompiledName("Iter")>]
  let iter fn s = fold (fun _ elt -> fn elt) () s
