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

open System.Collections.Generic
open B2R2
open B2R2.Collections.FingerTree

/// An element for our interval map.
type private IntervalMapElem<'V>(k, v) =
  member val Key: AddrRange = k
  member val Val: 'V = v
  member this.Min = this.Key.Min
  member this.Max = this.Key.Max
  override this.ToString() = this.Key.ToString()
  interface IMeasured<InterMonoid<Addr>> with
    member this.Measurement =
      InterMonoid<Addr>(Ordered(Key(this.Key.Min)),
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

  /// Returns the number of mappings in the interval map.
  [<CompiledName("Count")>]
  let count (IntervalMap m) =
    foldl (fun acc (_: IntervalMapElem<'V>) -> acc + 1) 0 m

  let private rangeExists i tree =
    let rec loop tree =
      match Op.ViewL tree with
      | Nil -> false
      | Cons(x: IntervalMapElem<_>, xs) ->
        if x.Min = i.Min then
          if x.Max = i.Max then true
          else loop xs
        else false
    loop tree

  /// Adds a mapping to the interval map. Overlapping intervals are allowed, but
  /// an exact duplicate range is not.
  [<CompiledName("Add")>]
  let add (i: AddrRange) v (IntervalMap m) =
    let l, r =
      Op.Split((fun (e: InterMonoid<Addr>) -> Key i.Min <= e.Min), m)
    if rangeExists i r then raise InvalidAddrRangeException
    else IntervalMap <| Op.Concat(l, Op.Cons(IntervalMapElem(i, v), r))

  let private findAllwithPredicate (range: AddrRange) (IntervalMap m) pred =
    let il = range.Min
    let ih = range.Max
    let dropMatcher (e: InterMonoid<Addr>) = Prio il <= e.Max
    let rec matches xs =
      let v = Op.DropUntil(dropMatcher, xs)
      match Op.ViewL v with
      | Nil -> []
      | Cons(x: IntervalMapElem<_>, xs) ->
        if pred x.Key then x.Val :: matches xs
        else matches xs
    Op.TakeUntil((fun (elt: InterMonoid<Addr>) -> Key ih < elt.Min), m)
    |> matches

  /// Finds all values whose intervals overlap with the given range.
  [<CompiledName("FindAll")>]
  let findAll range m = findAllwithPredicate range m (fun _ -> true)

  /// Finds the value whose interval exactly matches the given range only when
  /// there is exactly one matching interval.
  [<CompiledName("TryFindExactlyOne")>]
  let tryFindExactlyOne range (m: IntervalMap<'V>) =
    findAllwithPredicate range m (fun k -> k = range)
    |> function
      | [ v ] -> Some v
      | _ -> None

  /// Finds the value whose interval exactly matches the given range when there
  /// is exactly one matching interval; raises KeyNotFoundException otherwise.
  [<CompiledName("FindExactlyOne")>]
  let findExactlyOne range m =
    match tryFindExactlyOne range m with
    | Some v -> v
    | None -> raise (KeyNotFoundException())

  /// Finds the value whose interval has the same low bound (Min) as the given
  /// address only when there is exactly one matching interval.
  [<CompiledName("TryFindExactlyOneByMin")>]
  let tryFindExactlyOneByMin (addr: Addr) (IntervalMap m) =
    let _, r =
      Op.Split((fun (e: InterMonoid<Addr>) -> Key addr <= e.Min), m)
    let rec loop found xs =
      match Op.ViewL xs with
      | Nil -> found
      | Cons(x: IntervalMapElem<'V>, xs) ->
        if x.Min = addr then
          match found with
          | None -> loop (Some x.Val) xs
          | Some _ -> None
        else found
    loop None r

  /// Finds the value whose interval has the same low bound (Min) as the given
  /// address when there is exactly one such interval; raises
  /// KeyNotFoundException otherwise.
  [<CompiledName("FindExactlyOneByMin")>]
  let findExactlyOneByMin addr m =
    match tryFindExactlyOneByMin addr m with
    | Some v -> v
    | None -> raise (KeyNotFoundException())

  /// Finds the value whose interval overlaps with the given range only when
  /// there is exactly one such interval.
  [<CompiledName("TryFindOverlappingOne")>]
  let tryFindOverlappingOne range m =
    findAll range m
    |> function
      | [ v ] -> Some v
      | _ -> None

  /// Finds the value whose interval overlaps with the given range when there is
  /// exactly one such interval; raises KeyNotFoundException otherwise.
  [<CompiledName("FindOverlappingOne")>]
  let findOverlappingOne range m =
    match tryFindOverlappingOne range m with
    | Some v -> v
    | None -> raise (KeyNotFoundException())

  /// Finds the value whose interval contains the given address only when there
  /// is exactly one such interval.
  [<CompiledName("TryFindOverlappingOneByAddr")>]
  let tryFindOverlappingOneByAddr addr m =
    tryFindOverlappingOne (AddrRange.singleton addr) m

  /// Finds the value whose interval contains the given address when there is
  /// exactly one such interval; raises KeyNotFoundException otherwise.
  [<CompiledName("FindOverlappingOneByAddr")>]
  let findOverlappingOneByAddr addr m =
    match tryFindOverlappingOneByAddr addr m with
    | Some v -> v
    | None -> raise (KeyNotFoundException())

  /// Checks whether the given address interval overlaps with any of the
  /// intervals in the interval map.
  [<CompiledName("OverlapsRange")>]
  let overlapsRange (range: AddrRange) (IntervalMap m) =
    let il = range.Min
    let ih = range.Max
    if Prio il <= ((m :> IMeasured<_>).Measurement).Max then
      let z = (m.Monoid :> IMonoid<InterMonoid<Addr>>).Zero
      let _, x, _ =
        Op.SplitTree((fun (e: InterMonoid<Addr>) -> Prio il <= e.Max),
          z, m)
      x.Min <= ih
    else false

  /// Checks whether the given address exists in the interval tree.
  [<CompiledName("ContainsAddr")>]
  let containsAddr addr m =
    overlapsRange (AddrRange.singleton addr) m

  /// Checks whether the exact range exists in the interval tree.
  [<CompiledName("ContainsRange")>]
  let containsRange (range: AddrRange) (m: IntervalMap<'V>) =
    match tryFindExactlyOne range m with
    | None -> false
    | _ -> true

  /// Replaces the value for the interval that exactly matches the given range.
  /// Raises InvalidAddrRangeException if there is no such interval.
  [<CompiledName("Replace")>]
  let replace (i: AddrRange) (v: 'V) (IntervalMap m) =
    let l, r =
      Op.Split((fun (e: InterMonoid<Addr>) -> Key i.Min <= e.Min), m)
    let rec replaceLoop l r =
      match Op.ViewL r with
      | Nil -> raise InvalidAddrRangeException
      | Cons(x: IntervalMapElem<'V>, xs)
        when x.Min = i.Min && x.Max = i.Max ->
        Op.Concat(l, Op.Cons(IntervalMapElem(i, v), xs))
      | Cons(x, xs) ->
        if i.Min = x.Min then replaceLoop (Op.Snoc(l, x)) xs
        else raise InvalidAddrRangeException
    IntervalMap <| replaceLoop l r

  /// Adds a new mapping to the IntervalMap in case there is no exactly matching
  /// interval. If there is a matching interval, this function will replace the
  /// existing mapping with the new one.
  [<CompiledName("AddOrReplace")>]
  let addOrReplace (i: AddrRange) (v: 'V) m =
    if containsRange i m then replace i v m
    else add i v m

  /// Removes the interval that exactly matches the given range. Raises
  /// InvalidAddrRangeException if there is no such interval.
  [<CompiledName("Remove")>]
  let remove (i: AddrRange) (IntervalMap m) =
    let l, r =
      Op.Split((fun (e: InterMonoid<Addr>) -> Key i.Min <= e.Min), m)
    let rec rmLoop l r =
      match Op.ViewL r with
      | Nil -> raise InvalidAddrRangeException
      | Cons(x: IntervalMapElem<'V>, xs)
        when x.Min = i.Min && x.Max = i.Max ->
        Op.Concat(l, xs)
      | Cons(x, xs) ->
        if i.Min = x.Min then rmLoop (Op.Snoc(l, x)) xs
        else raise InvalidAddrRangeException
    IntervalMap <| rmLoop l r

  /// Folds the elements of the interval map.
  [<CompiledName("Fold")>]
  let fold fn acc (IntervalMap m) =
    foldl (fun acc (elt: IntervalMapElem<'V>) -> fn acc elt.Key elt.Val) acc m

  /// Iterates the elements of the interval map.
  [<CompiledName("Iter")>]
  let iter fn m = fold (fun _ range elt -> fn range elt) () m
