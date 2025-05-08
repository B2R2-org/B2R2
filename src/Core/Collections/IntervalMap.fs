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

/// An element for our interval map.
type private IntervalMapElem<'V> (k, v) =
  member val Key: AddrRange = k
  member val Val: 'V = v
  member this.Min = this.Key.Min
  member this.Max = this.Key.Max
  override this.ToString () = this.Key.ToString ()
  interface IMeasured<InterMonoid<Addr>> with
    member this.Measurement =
      InterMonoid<Addr> (Ordered(Key(this.Key.Min)),
                         Priority(Prio(this.Key.Max)))

/// <summary>
/// Represents an interval map, which is a map based on an interval tree. This
/// maps an interval (i.e., <see cref='T:B2R2.AddrRange'/>) to a value of type
/// 'V. We currently implement this using the functional finger tree. Intervals
/// in this map are not necessarily disjoint and can overlap. To disallow
/// overlapping intervals, consider using NoOverlapIntervalMap instead.
/// </summary>
type IntervalMap<'V> =
  private
    IntervalMap of FingerTree<InterMonoid<Addr>, IntervalMapElem<'V>>

/// <summary>
/// Provides functions for creating or manipulating interval maps.
/// </summary>
[<RequireQualifiedAccess>]
module IntervalMap =

  /// Empty interval tree.
  [<CompiledName("Empty")>]
  let empty: IntervalMap<'V> = IntervalMap Empty

  /// Checks if the given interval tree is empty.
  [<CompiledName("IsEmpty")>]
  let isEmpty (m: IntervalMap<'V>) = m = IntervalMap Empty

  /// Adds an item to the interval tree.
  [<CompiledName("Add")>]
  let add (i: AddrRange) v (IntervalMap m) =
    let l, r =
      Op.Split (fun (e: InterMonoid<Addr>) -> Key i.Min <= e.GetMin ()) m
    IntervalMap <| Op.Concat l (Op.Cons (IntervalMapElem (i, v)) r)

  let private findAllwithPredicate (range: AddrRange) (IntervalMap m) pred =
    let il = range.Min
    let ih = range.Max
    let dropMatcher (e: InterMonoid<Addr>) = Prio il <= e.GetMax ()
    let rec matches xs =
      let v = Op.DropUntil dropMatcher xs
      match Op.ViewL v with
      | Nil -> []
      | Cons (x: IntervalMapElem<_>, xs) ->
        if pred x.Key then x.Val :: matches xs
        else matches xs
    Op.TakeUntil (fun (elt: InterMonoid<Addr>) -> Key ih < elt.GetMin ()) m
    |> matches

  /// Finds all overlapping intervals in the given range.
  [<CompiledName("FindAll")>]
  let findAll range m =
    findAllwithPredicate range m (fun _ -> true)

  /// Finds the first interval that exactly matches the given range.
  [<CompiledName("TryFind")>]
  let tryFind range (m: IntervalMap<'V>) =
    findAllwithPredicate range m (fun k -> k = range)
    |> List.tryHead

  /// Finds an interval that has the same low bound (Min) as the given address.
  /// If there is no such interval, this function returns None.
  [<CompiledName("TryFindByMin")>]
  let tryFindByMin (addr: Addr) (IntervalMap m) =
    let comp (elt: InterMonoid<Addr>) = Key addr <= elt.GetMin ()
    if Prio addr <= ((m :> IMeasured<_>).Measurement).GetMax () then
      let z = (m.Monoid :> IMonoid<InterMonoid<Addr>>).Zero
      let _, x, _ = Op.SplitTree comp z m
      if x.Min = addr then Some (x.Val) else None
    else None

  /// Checks whether the given address interval is included in any of the
  /// intervals in the interval map.
  [<CompiledName("IncludeRange")>]
  let includeRange (range: AddrRange) (IntervalMap m) =
    let il = range.Min
    let ih = range.Max
    if Prio il <= ((m :> IMeasured<_>).Measurement).GetMax () then
      let z = (m.Monoid :> IMonoid<InterMonoid<Addr>>).Zero
      let _, x, _ =
        Op.SplitTree (fun (e: InterMonoid<Addr>) -> Prio il <= e.GetMax()) z m
      x.Min <= ih
    else false

  /// Checks whether the given address exists in the interval tree.
  [<CompiledName("ContainsAddr")>]
  let containsAddr addr m = includeRange (AddrRange (addr, addr)) m

  /// Checks whether the exact range exists in the interval tree.
  [<CompiledName("Contains")>]
  let contains (range: AddrRange) (m: IntervalMap<'V>) =
    match tryFind range m with
    | None -> false
    | _ -> true

  /// Replaces the item in the interval tree that exactly matches the given
  /// range with the new value. This function will raise an exception if there
  /// is no exactly matching interval.
  [<CompiledName("Replace")>]
  let replace (i: AddrRange) (v: 'V) (IntervalMap m) =
    let l, r =
      Op.Split (fun (e: InterMonoid<Addr>) -> Key i.Min <= e.GetMin ()) m
    let rec replaceLoop l r =
      match Op.ViewL r with
      | Nil -> raise InvalidAddrRangeException
      | Cons (x: IntervalMapElem<'V>, xs)
        when x.Min = i.Min && x.Max = i.Max ->
        Op.Concat l (Op.Cons (IntervalMapElem (i, v)) xs)
      | Cons (x, xs) ->
        if i.Min = x.Min then replaceLoop (Op.Snoc l x) xs
        else raise InvalidAddrRangeException
    IntervalMap <| replaceLoop l r

  /// Adds a new mapping to the IntervalMap in case there is no exactly matching
  /// interval. If there is a matching interval, this function will replace the
  /// existing mapping with the new one.
  [<CompiledName("AddOrReplace")>]
  let addOrReplace (i: AddrRange) (v: 'V) m =
    if contains i m then replace i v m
    else add i v m

  /// Removes the exactly matched interval from the map.
  [<CompiledName("Remove")>]
  let remove (i: AddrRange) (IntervalMap m) =
    let l, r =
      Op.Split (fun (e: InterMonoid<Addr>) -> Key i.Min <= e.GetMin ()) m
    let rec rmLoop l r =
      match Op.ViewL r with
      | Nil -> raise InvalidAddrRangeException
      | Cons (x: IntervalMapElem<'V>, xs)
        when x.Min = i.Min && x.Max = i.Max ->
        Op.Concat l xs
      | Cons (x, xs) ->
        if i.Min = x.Min then rmLoop (Op.Snoc l x) xs
        else raise InvalidAddrRangeException
    IntervalMap <| rmLoop l r

  /// Folds the elements of the interval map.
  [<CompiledName("Fold")>]
  let fold fn acc (IntervalMap m) =
    foldl (fun acc (elt: IntervalMapElem<'V>) -> fn acc elt.Key elt.Val) acc m

  /// Iterates the elements of the interval map.
  [<CompiledName("Iter")>]
  let iter fn m = fold (fun _ range elt -> fn range elt) () m
