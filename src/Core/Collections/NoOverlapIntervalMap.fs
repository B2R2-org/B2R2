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

/// <summary>
/// Represents a non-overlapping interval map. By interval map, we mean a map
/// based on an interval tree, which maps an interval (i.e., AddrRange) to a
/// value. We currently implement this using a red-black tree, which follows the
/// implementation of the paper written by Kimball Germane and Matthew Might:
/// "Deletion: The Curse of the Red-Black Tree", Journal of Functional
/// Programming, vol. 24, no. 4, 2014.
/// </summary>
type NoOverlapIntervalMap<'V> =
  private
  | RBLeaf of RBColor
  | RBNode of RBColor
            * AddrRange
            * 'V
            * NoOverlapIntervalMap<'V>
            * NoOverlapIntervalMap<'V>

and internal RBColor =
  /// Red
  | R
  /// Black
  | B
  /// Double Black
  | DB
  /// Negative Black
  | NB

/// Provides functions for creating or manipulating non-overlapping interval
/// maps.
[<RequireQualifiedAccess>]
module NoOverlapIntervalMap =

  let private (++) col1 col2 =
    match col1, col2 with
    | R, B
    | B, R -> B
    | B, B -> DB
    | _, _ -> R

  let private whiten = function
    | DB -> B
    | B -> R
    | R -> NB
    | NB -> Terminator.impossible ()

  let private toBlack = function
    | RBLeaf DB -> RBLeaf B
    | RBNode(R, k, v, l, r)
    | RBNode(DB, k, v, l, r) -> RBNode(B, k, v, l, r)
    | n -> n

  let rec private balance = function
    | ((DB|B) as l, zk, zv, RBNode(R, yk, yv, RBNode(R, xk, xv, a, b), c), d)
    | ((DB|B) as l, zk, zv, RBNode(R, xk, xv, a, RBNode(R, yk, yv, b, c)), d)
    | ((DB|B) as l, xk, xv, a, RBNode(R, zk, zv, RBNode(R, yk, yv, b, c), d))
    | ((DB|B) as l, xk, xv, a, RBNode(R, yk, yv, b, RBNode(R, zk, zv, c, d))) ->
      RBNode(whiten l, yk, yv, RBNode(B, xk, xv, a, b), RBNode(B, zk, zv, c, d))
    | (DB, zk, zv, RBNode(NB, xk, xv, RBNode(B, wk, wv, a, b),
       RBNode(B, yk, yv, c, d)), e) ->
      RBNode(B, yk, yv, balance (B, xk, xv, RBNode(R, wk, wv, a, b), c),
        RBNode(B, zk, zv, d, e))
    | (DB, xk, xv, a,
       RBNode(NB, zk, zv, RBNode(B, yk, yv, b, c), RBNode(B, wk, wv, d, e))) ->
      RBNode(B, yk, yv, RBNode(B, xk, xv, a, b),
        balance (B, zk, zv, c, RBNode(R, wk, wv, d, e)))
    | node ->
      RBNode(node)

  let private fnAdd k v tree isReplace =
    let rec ins = function
      | RBLeaf _ ->
        RBNode(R, k, v, RBLeaf B, RBLeaf B)
      | RBNode(c, k', v', l, r) ->
        if k' = k then
          if isReplace then RBNode(c, k', v, l, r)
          else raise RangeOverlapException
        elif k.Min < k'.Min && k.Max < k'.Min then
          balance (c, k', v', ins l, r)
        elif k.Min > k'.Max && k.Max > k'.Max then
          balance (c, k', v', l, ins r)
        else
          raise RangeOverlapException
    ins tree |> toBlack

  /// <summary>
  ///   Adds a mapping from an interval to the value in the interval tree.
  /// </summary>
  /// <param name="k">AddrRange as a key.</param>
  /// <param name="v">The value to be added.</param>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   A new interval tree.
  /// </returns>
  /// <exception cref="T:B2R2.RangeOverlapException">
  ///   Thrown when there is an existing (overlapping) interval in the tree.
  /// </exception>
  [<CompiledName("Add")>]
  let add k v tree =
    fnAdd k v tree false

  /// <summary>
  ///   Adds a mapping from an interval to the value in the interval tree,
  ///   taking separate min and max parameters instead of an AddrRange.
  /// </summary>
  /// <param name="min">The min value of the interval.</param>
  /// <param name="max">The max value of the interval.</param>
  /// <param name="v">The value to be added.</param>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   A new interval tree.
  /// </returns>
  /// <exception cref="T:B2R2.RangeOverlapException">
  ///   Thrown when there is an existing (overlapping) interval in the tree.
  /// </exception>
  [<CompiledName("AddByBounds")>]
  let addByBounds min max v tree =
    add (AddrRange.create min max) v tree

  /// <summary>
  ///   Replaces the value for an existing range if it exactly matches the
  ///   given range. If ranges overlap, this function will still raise
  ///   RangeOverlapException.
  /// </summary>
  /// <param name="k">AddrRange as a key.</param>
  /// <param name="v">The value to be added.</param>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   A new interval tree.
  /// </returns>
  [<CompiledName("Replace")>]
  let replace k v tree = fnAdd k v tree true

  let rec private findLoop isExact k = function
    | RBLeaf _ ->
      Error ErrorCase.ItemNotFound
    | RBNode(_, k', v', l, r) ->
      if k = k' then Ok(k', v')
      elif k.Min < k'.Min && k.Max < k'.Min then findLoop isExact k l
      elif k.Min > k'.Max && k.Max > k'.Max then findLoop isExact k r
      elif (not isExact) && k.Min >= k'.Min && k.Max <= k'.Max then Ok(k', v')
      else Error ErrorCase.ItemNotFound

  let rec private del isExact k = function
    | RBLeaf _ ->
      raise (KeyNotFoundException())
    | RBNode(c, k', v', l, r) ->
      if k = k' then
        delAndBalance isExact (c, l, r)
      elif k.Min < k'.Min && k.Max < k'.Min then
        bubble (c, k', v', del isExact k l, r)
      elif k.Min > k'.Max && k.Max > k'.Max then
        bubble (c, k', v', l, del isExact k r)
      elif not isExact && k.Min >= k'.Min && k.Max <= k'.Max then
        delAndBalance isExact (c, l, r)
      else
        raise RangeOverlapException

  and private delAndBalance isExact = function
    | c, RBLeaf _, RBLeaf _ -> RBLeaf(B ++ c)
    | B, RBLeaf _, RBNode(_, nk, nv, nl, nr)
    | B, RBNode(_, nk, nv, nl, nr), RBLeaf _ -> RBNode(B, nk, nv, nl, nr)
    | c, l, r -> let k, v = findMax l in bubble (c, k, v, del isExact k l, r)

  and private findMax = function
    | RBLeaf _ -> failwith "Max binding not found"
    | RBNode(_, k, v, _, RBLeaf _) -> k, v
    | RBNode(_, _, _, _, r) -> findMax r

  and private bubble = function
    | (nc, nk, nv, RBNode(lc, lk, lv, a, b), RBNode(rc, rk, rv, c, d))
      when lc = DB || rc = DB ->
      balance (B ++ nc, nk, nv, RBNode(whiten lc, lk, lv, a, b),
        RBNode(whiten rc, rk, rv, c, d))
    | (nc, nk, nv, RBLeaf DB, RBNode(rc, rk, rv, c, d)) ->
      balance (B ++ nc, nk, nv, RBLeaf B, RBNode(whiten rc, rk, rv, c, d))
    | (nc, nk, nv, RBNode(rc, rk, rv, c, d), RBLeaf DB) ->
      balance (B ++ nc, nk, nv, RBNode(whiten rc, rk, rv, c, d), RBLeaf B)
    | node ->
      RBNode node

  /// <summary>
  ///   Removes a mapping that matches exactly with the given range. To remove a
  ///   mapping that covers the given address, use removeByAddr.
  /// </summary>
  /// <param name="k">The interval to find.</param>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   A new interval tree.
  /// </returns>
  [<CompiledName("Remove")>]
  let remove k tree =
    del true k tree |> toBlack

  /// <summary>
  ///   Removes a mapping that matches with the given address. Unlike remove,
  ///   this function will remove an interval that includes the given address.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   A new interval tree.
  /// </returns>
  [<CompiledName("RemoveByAddr")>]
  let removeByAddr addr tree =
    del false (AddrRange.singleton addr) tree |> toBlack

  /// Returns an empty map.
  [<CompiledName("Empty")>]
  let empty =
    RBLeaf B

  /// <summary>
  ///   Checks if the given interval map is empty.
  /// </summary>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   Returns true if the tree is empty, false otherwise.
  /// </returns>
  [<CompiledName("IsEmpty")>]
  let isEmpty tree =
    match tree with
    | RBLeaf B -> true
    | _ -> false

  /// <summary>
  ///   Checks whether a given Addr exists in any of the ranges in the map.
  /// </summary>
  /// <param name="addr">Address.</param>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   True if the interval tree contains an interval that includes the given
  ///   address, false otherwise.
  /// </returns>
  [<CompiledName("ContainsAddr")>]
  let containsAddr addr tree =
    findLoop false (AddrRange.singleton addr) tree |> Result.isOk

  /// <summary>
  ///   Checks whether the exact range exists in the interval map.
  /// </summary>
  /// <param name="range">The address range.</param>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   True if the interval tree contains the interval, false otherwise.
  /// </returns>
  [<CompiledName("ContainsRange")>]
  let containsRange range tree = findLoop true range tree |> Result.isOk

  /// <summary>
  ///   Finds the mapping that exactly matches with the given range.
  /// </summary>
  /// <param name="range">The address range.</param>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   The value associated with the given interval.
  /// </returns>
  [<CompiledName("Find")>]
  let find range tree =
    match findLoop true range tree with
    | Ok(_, v) -> v
    | _ -> raise (KeyNotFoundException())

  /// <summary>
  ///   Finds an interval stored in the interval tree map, which includes the
  ///   given address.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   The found interval.
  /// </returns>
  [<CompiledName("FindRangeByAddr")>]
  let findRangeByAddr addr tree =
    match findLoop false (AddrRange.singleton addr) tree with
    | Ok(k, _) -> k
    | _ -> raise (KeyNotFoundException())

  /// <summary>
  ///   Finds an interval stored in the interval tree map, which includes the
  ///   given address.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   The found interval wrapped with option.
  /// </returns>
  [<CompiledName("TryFindRangeByAddr")>]
  let tryFindRangeByAddr addr tree =
    match findLoop false (AddrRange.singleton addr) tree with
    | Ok(k, _) -> Some k
    | _ -> None

  /// <summary>
  ///   Finds the mapping that exactly matches with the given range and returns
  ///   an option-wrapped type.
  /// </summary>
  /// <param name="range">The address range.</param>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   The value associated with the given interval.
  /// </returns>
  [<CompiledName("TryFind")>]
  let tryFind range tree =
    match findLoop true range tree with
    | Ok(_, v) -> Some v
    | _ -> None

  /// <summary>
  ///   Finds the mapping that matches with the given address and returns an
  ///   option-wrapped type.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   The value associated with the given address.
  /// </returns>
  [<CompiledName("TryFindByAddr")>]
  let tryFindByAddr addr tree =
    match findLoop false (AddrRange.singleton addr) tree with
    | Ok(_, v) -> Some v
    | _ -> None

  let rec private findPreviousByAddrLoop addr candidate = function
    | RBLeaf _ ->
      candidate
    | RBNode(_, k, v, l, r) ->
      if addr > k.Max then findPreviousByAddrLoop addr (Some(k, v)) r
      else findPreviousByAddrLoop addr candidate l

  /// <summary>
  ///   Finds the nearest interval below the given address and returns an
  ///   option-wrapped type. The returned interval does not include the given
  ///   address.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   The nearest lower interval and its associated value.
  /// </returns>
  [<CompiledName("TryFindPreviousByAddr")>]
  let tryFindPreviousByAddr addr tree =
    findPreviousByAddrLoop addr None tree

  let rec private findNextByAddrLoop addr candidate = function
    | RBLeaf _ ->
      candidate
    | RBNode(_, k, v, l, r) ->
      if addr < k.Min then findNextByAddrLoop addr (Some(k, v)) l
      else findNextByAddrLoop addr candidate r

  /// <summary>
  ///   Finds the nearest interval above the given address and returns an
  ///   option-wrapped type. The returned interval does not include the given
  ///   address.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   The nearest upper interval and its associated value.
  /// </returns>
  [<CompiledName("TryFindNextByAddr")>]
  let tryFindNextByAddr addr tree =
    findNextByAddrLoop addr None tree

  /// <summary>
  ///   Finds the mapping that matches with the given address. Unlike find, this
  ///   function can return a range that covers the given address.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   The value associated with the given address.
  /// </returns>
  [<CompiledName("FindByAddr")>]
  let findByAddr addr tree =
    match findLoop false (AddrRange.singleton addr) tree with
    | Ok(_, v) -> v
    | _ -> raise (KeyNotFoundException())

  let rec private sizeAux acc tree =
    match tree with
    | RBLeaf _ -> acc
    | RBNode(_, _, _, l, r) -> sizeAux (sizeAux (acc + 1) l) r

  /// <summary>
  ///   Returns the number of bindings in the interval map.
  /// </summary>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   The number of bindings.
  /// </returns>
  [<CompiledName("Count")>]
  let count tree = sizeAux 0 tree

  /// <summary>
  ///   Iterates over the tree.
  /// </summary>
  /// <param name="fn">Iterator.</param>
  /// <param name="tree">The interval tree.</param>
  [<CompiledName("Iter")>]
  let rec iter fn tree =
    match tree with
    | RBLeaf _ -> ()
    | RBNode(_, k, v, l, r) -> iter fn l; fn k v; iter fn r

  /// <summary>
  ///   Folds over the tree.
  /// </summary>
  /// <param name="fn">Folder.</param>
  /// <param name="acc">Accumulator.</param>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   Accumulated value.
  /// </returns>
  [<CompiledName("Fold")>]
  let rec fold fn acc tree =
    match tree with
    | RBLeaf _ ->
      acc
    | RBNode(_, k, v, l, r) ->
      let acc = fold fn acc l
      let acc = fn acc k v
      fold fn acc r

  /// <summary>
  ///   Returns a sequence of overlapping mappings of the given interval.
  /// </summary>
  /// <param name="k">The key interval.</param>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   A sequence of mappings.
  /// </returns>
  [<CompiledName("FindOverlaps")>]
  let findOverlaps (k: AddrRange) tree =
    let rec loop acc = function
      | RBLeaf _ ->
        acc
      | RBNode(_, k', v', l, r) ->
        let acc = if k.Min < k'.Min then loop acc l else acc
        let acc =
          if k.Max < k'.Min || k.Min > k'.Max then acc
          else (k', v') :: acc
        let acc = if k.Max > k'.Max then loop acc r else acc
        acc
    loop [] tree
