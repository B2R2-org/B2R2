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
/// cref='T:B2R2.AddrRange'/>) that can overlap unlike NoOverlapIntervalMap.
/// </summary>
type IntervalSet =
  private
    IntervalSet of FingerTree<InterMonoid<Addr>, IntervalSetElem>

/// Provides functions for creating or manipulating interval sets.
[<RequireQualifiedAccess>]
module IntervalSet =

  /// Empty interval tree.
  [<CompiledName("Empty")>]
  let empty: IntervalSet = IntervalSet Empty

  /// Checks if the given interval tree is empty.
  [<CompiledName("IsEmpty")>]
  let isEmpty (s: IntervalSet) = s = IntervalSet Empty

  /// Returns the number of intervals in the interval set.
  [<CompiledName("Count")>]
  let count (IntervalSet s) =
    foldl (fun acc (_: IntervalSetElem) -> acc + 1) 0 s

  let private rangeExists i tree =
    let rec loop tree =
      match Op.ViewL tree with
      | Nil -> false
      | Cons(x: IntervalSetElem, xs) ->
        if x.Min = i.Min then
          if x.Max = i.Max then true
          else loop xs
        else false
    loop tree

  /// Adds an interval to the interval set. Overlapping intervals are allowed,
  /// but an exact duplicate range is not.
  [<CompiledName("Add")>]
  let add (i: AddrRange) (IntervalSet m) =
    let l, r =
      Op.Split((fun (e: InterMonoid<Addr>) -> Key i.Min <= e.Min), m)
    if rangeExists i r then raise InvalidAddrRangeException
    else IntervalSet <| Op.Concat(l, Op.Cons(IntervalSetElem i, r))

  /// Checks whether the given address interval overlaps with any of the
  /// intervals in the interval set.
  [<CompiledName("OverlapsRange")>]
  let overlapsRange (range: AddrRange) (IntervalSet s) =
    let il = range.Min
    let ih = range.Max
    if Prio il <= ((s :> IMeasured<_>).Measurement).Max then
      let z = (s.Monoid :> IMonoid<InterMonoid<Addr>>).Zero
      let (_, x, _) =
        Op.SplitTree((fun (e: InterMonoid<Addr>) -> Prio il <= e.Max),
          z, s)
      x.Min <= ih
    else false

  /// Finds all intervals that overlap with the given range. The returned list
  /// follows the interval tree traversal order.
  [<CompiledName("FindAll")>]
  let findAll (range: AddrRange) (IntervalSet s) =
    let il = range.Min
    let ih = range.Max
    let dropMatcher (e: InterMonoid<Addr>) = Prio il <= e.Max
    let rec matches acc xs =
      let v = Op.DropUntil(dropMatcher, xs)
      match Op.ViewL v with
      | Nil -> acc
      | Cons(x: IntervalSetElem, xs) -> matches (x.Val :: acc) xs
    Op.TakeUntil((fun (elt: InterMonoid<Addr>) -> Key ih < elt.Min), s)
    |> matches []
    |> List.rev

  /// Finds the interval that overlaps with the given range only when there is
  /// exactly one such interval.
  [<CompiledName("TryFindOverlappingOne")>]
  let tryFindOverlappingOne range s =
    findAll range s
    |> function
      | [ v ] -> Some v
      | _ -> None

  /// Finds the interval that overlaps with the given range when there is
  /// exactly one such interval; raises KeyNotFoundException otherwise.
  [<CompiledName("FindOverlappingOne")>]
  let findOverlappingOne range s =
    match tryFindOverlappingOne range s with
    | Some v -> v
    | None -> raise (KeyNotFoundException())

  /// Finds the interval that contains the given address only when there is
  /// exactly one such interval.
  [<CompiledName("TryFindOverlappingOneByAddr")>]
  let tryFindOverlappingOneByAddr addr s =
    tryFindOverlappingOne (AddrRange.singleton addr) s

  /// Finds the interval that contains the given address when there is exactly
  /// one such interval; raises KeyNotFoundException otherwise.
  [<CompiledName("FindOverlappingOneByAddr")>]
  let findOverlappingOneByAddr addr s =
    match tryFindOverlappingOneByAddr addr s with
    | Some v -> v
    | None -> raise (KeyNotFoundException())

  /// Finds the interval whose low bound (Min) equals the given address only
  /// when there is exactly one such interval.
  [<CompiledName("TryFindExactlyOneByMin")>]
  let tryFindExactlyOneByMin (addr: Addr) (IntervalSet s) =
    let _, r =
      Op.Split((fun (e: InterMonoid<Addr>) -> Key addr <= e.Min), s)
    let rec loop found xs =
      match Op.ViewL xs with
      | Nil -> found
      | Cons(x: IntervalSetElem, xs) ->
        if x.Min = addr then
          match found with
          | None -> loop (Some x.Val) xs
          | Some _ -> None
        else found
    loop None r

  /// Finds the interval whose low bound (Min) equals the given address when
  /// there is exactly one such interval; raises KeyNotFoundException otherwise.
  [<CompiledName("FindExactlyOneByMin")>]
  let findExactlyOneByMin addr s =
    match tryFindExactlyOneByMin addr s with
    | Some v -> v
    | None -> raise (KeyNotFoundException())

  /// Checks whether the given address exists in the interval set.
  [<CompiledName("ContainsAddr")>]
  let containsAddr addr s =
    overlapsRange (AddrRange.singleton addr) s

  /// Checks whether the exact interval exists in the interval set.
  [<CompiledName("ContainsRange")>]
  let containsRange (i: AddrRange) (IntervalSet s) =
    let _, r =
      Op.Split((fun (e: InterMonoid<Addr>) -> Key i.Min <= e.Min), s)
    let rec containLoop r =
      match Op.ViewL r with
      | Nil -> false
      | Cons(x: IntervalSetElem, _) when x.Min = i.Min && x.Max = i.Max -> true
      | Cons(x, xs) ->
        if i.Min = x.Min then containLoop xs
        else false
    containLoop r

  /// Removes the interval that exactly matches the given range. Raises
  /// InvalidAddrRangeException if there is no such interval.
  [<CompiledName("Remove")>]
  let remove (range: AddrRange) (IntervalSet s) =
    let l, r =
      Op.Split((fun (e: InterMonoid<Addr>) -> Key range.Min <= e.Min), s)
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
