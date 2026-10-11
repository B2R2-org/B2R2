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

/// <summary>
/// Implements the functions of the NoOverlapIntervalMap module, which is what
/// to call instead. F# compiles a module without beforefieldinit, so
/// ReadyToRun cannot precompile a module function generic over a reference
/// type and leaves it to be compiled at its first call; the static members
/// of a generic class it precompiles.
/// </summary>
and NoOverlapIntervalMapOps<'V> private() =
  static let (++) col1 col2 =
    match col1, col2 with
    | R, B
    | B, R -> B
    | B, B -> DB
    | _, _ -> R

  static let whiten = function
    | DB -> B
    | B -> R
    | R -> NB
    | NB -> Terminator.impossible ()

  static let toBlack = function
    | RBLeaf DB -> RBLeaf B
    | RBNode(R, k, v, l, r)
    | RBNode(DB, k, v, l, r) -> RBNode(B, k, v, l, r)
    | n -> n

  static let rec balance = function
    | ((DB|B) as l, zk, zv, RBNode(R, yk, yv, RBNode(R, xk, xv, a, b), c), d)
    | ((DB|B) as l, zk, zv, RBNode(R, xk, xv, a, RBNode(R, yk, yv, b, c)), d)
    | ((DB|B) as l, xk, xv, a, RBNode(R, zk, zv, RBNode(R, yk, yv, b, c), d))
    | ((DB|B) as l, xk, xv, a, RBNode(R, yk, yv, b, RBNode(R, zk, zv, c, d))) ->
      RBNode(whiten l, yk, yv, RBNode(B, xk, xv, a, b), RBNode(B, zk, zv, c, d))
    | (DB, zk, zv, RBNode(NB,
                          xk,
                          xv,
                          RBNode(B, wk, wv, a, b),
                          RBNode(B, yk, yv, c, d)), e) ->
      let balance = balance (B, xk, xv, RBNode(R, wk, wv, a, b), c)
      RBNode(B, yk, yv, balance, RBNode(B, zk, zv, d, e))
    | (DB,
       xk,
       xv,
       a,
       RBNode(NB, zk, zv, RBNode(B, yk, yv, b, c), RBNode(B, wk, wv, d, e))) ->
      let balance = balance (B, zk, zv, c, RBNode(R, wk, wv, d, e))
      RBNode(B, yk, yv, RBNode(B, xk, xv, a, b), balance)
    | node ->
      RBNode(node)

  /// Inserts v at k. A recursive closure would be lifted out of this class,
  /// into one that ReadyToRun cannot precompile for, so the values it would
  /// capture are passed along instead.
  static let rec ins k v isReplace = function
    | RBLeaf _ ->
      RBNode(R, k, v, RBLeaf B, RBLeaf B)
    | RBNode(c, k', v', l, r) ->
      if k' = k then
        if isReplace then RBNode(c, k', v, l, r)
        else raise RangeOverlapException
      elif k.Min < k'.Min && k.Max < k'.Min then
        balance (c, k', v', ins k v isReplace l, r)
      elif k.Min > k'.Max && k.Max > k'.Max then
        balance (c, k', v', l, ins k v isReplace r)
      else
        raise RangeOverlapException

  static let fnAdd k v tree isReplace = ins k v isReplace tree |> toBlack

  /// Finds the node holding k, or the one whose range covers it unless
  /// isExact.
  static let rec findLoop isExact k = function
    | RBLeaf _ ->
      Error ErrorCase.ItemNotFound
    | RBNode(_, k', v', l, r) ->
      if k = k' then
        Ok(struct (k', v'))
      elif k.Min < k'.Min && k.Max < k'.Min then
        findLoop isExact k l
      elif k.Min > k'.Max && k.Max > k'.Max then
        findLoop isExact k r
      elif (not isExact) && k.Min >= k'.Min && k.Max <= k'.Max then
        Ok(struct (k', v'))
      else
        Error ErrorCase.ItemNotFound

  static let rec del isExact k = function
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

  and delAndBalance isExact = function
    | c, RBLeaf _, RBLeaf _ -> RBLeaf(B ++ c)
    | B, RBLeaf _, RBNode(_, nk, nv, nl, nr)
    | B, RBNode(_, nk, nv, nl, nr), RBLeaf _ -> RBNode(B, nk, nv, nl, nr)
    | c, l, r -> let k, v = findMax l in bubble (c, k, v, del isExact k l, r)

  and findMax = function
    | RBLeaf _ -> failwith "Max binding not found"
    | RBNode(_, k, v, _, RBLeaf _) -> k, v
    | RBNode(_, _, _, _, r) -> findMax r

  and bubble = function
    | (nc, nk, nv, RBNode(lc, lk, lv, a, b), RBNode(rc, rk, rv, c, d))
      when lc = DB || rc = DB ->
      let lc = RBNode(whiten lc, lk, lv, a, b)
      balance (B ++ nc, nk, nv, lc, RBNode(whiten rc, rk, rv, c, d))
    | (nc, nk, nv, RBLeaf DB, RBNode(rc, rk, rv, c, d)) ->
      balance (B ++ nc, nk, nv, RBLeaf B, RBNode(whiten rc, rk, rv, c, d))
    | (nc, nk, nv, RBNode(rc, rk, rv, c, d), RBLeaf DB) ->
      balance (B ++ nc, nk, nv, RBNode(whiten rc, rk, rv, c, d), RBLeaf B)
    | node ->
      RBNode node

  static let rec findPreviousByAddrLoop addr candidate = function
    | RBLeaf _ ->
      candidate
    | RBNode(_, k, v, l, r) ->
      if addr > k.Max then findPreviousByAddrLoop addr (Some(k, v)) r
      else findPreviousByAddrLoop addr candidate l

  static let rec findNextByAddrLoop addr candidate = function
    | RBLeaf _ ->
      candidate
    | RBNode(_, k, v, l, r) ->
      if addr < k.Min then findNextByAddrLoop addr (Some(k, v)) l
      else findNextByAddrLoop addr candidate r

  static let rec sizeAux acc tree =
    match tree with
    | RBLeaf _ -> acc
    | RBNode(_, _, _, l, r) -> sizeAux (sizeAux (acc + 1) l) r

  static let rec iter fn tree =
    match tree with
    | RBLeaf _ -> ()
    | RBNode(_, k, v, l, r) -> iter fn l; fn k v; iter fn r

  static let rec fold fn acc tree =
    match tree with
    | RBLeaf _ ->
      acc
    | RBNode(_, k, v, l, r) ->
      let acc = fold fn acc l
      let acc = fn acc k v
      fold fn acc r

  static let rec findOverlapsLoop (k: AddrRange) acc = function
    | RBLeaf _ ->
      acc
    | RBNode(_, k', v', l, r) ->
      let acc = if k.Min < k'.Min then findOverlapsLoop k acc l else acc
      let acc =
        if k.Max < k'.Min || k.Min > k'.Max then acc else (k', v') :: acc
      let acc = if k.Max > k'.Max then findOverlapsLoop k acc r else acc
      acc

  /// Returns an empty map.
  static member Empty: NoOverlapIntervalMap<'V> = RBLeaf B

  /// Implements NoOverlapIntervalMap.add.
  static member Add(k, v, tree: NoOverlapIntervalMap<'V>) = fnAdd k v tree false

  /// Implements NoOverlapIntervalMap.addByBounds.
  static member AddByBounds(min, max, v, tree: NoOverlapIntervalMap<'V>) =
    fnAdd (AddrRange.create min max) v tree false

  /// Implements NoOverlapIntervalMap.replace.
  static member Replace(k, v, tree: NoOverlapIntervalMap<'V>) =
    fnAdd k v tree true

  /// Implements NoOverlapIntervalMap.remove.
  static member Remove(k, tree: NoOverlapIntervalMap<'V>) =
    del true k tree |> toBlack

  /// Implements NoOverlapIntervalMap.removeByAddr.
  static member RemoveByAddr(addr, tree: NoOverlapIntervalMap<'V>) =
    del false (AddrRange.singleton addr) tree |> toBlack

  /// Implements NoOverlapIntervalMap.isEmpty.
  static member IsEmpty(tree: NoOverlapIntervalMap<'V>) =
    match tree with
    | RBLeaf B -> true
    | _ -> false

  /// Implements NoOverlapIntervalMap.containsAddr.
  static member ContainsAddr(addr, tree: NoOverlapIntervalMap<'V>) =
    findLoop false (AddrRange.singleton addr) tree |> Result.isOk

  /// Implements NoOverlapIntervalMap.containsRange.
  static member ContainsRange(range, tree: NoOverlapIntervalMap<'V>) =
    findLoop true range tree |> Result.isOk

  /// Implements NoOverlapIntervalMap.find.
  static member Find(range, tree: NoOverlapIntervalMap<'V>) =
    match findLoop true range tree with
    | Ok(struct (_, v)) -> v
    | _ -> raise (KeyNotFoundException())

  /// Implements NoOverlapIntervalMap.findRangeByAddr.
  static member FindRangeByAddr(addr, tree: NoOverlapIntervalMap<'V>) =
    match findLoop false (AddrRange.singleton addr) tree with
    | Ok(struct (k, _)) -> k
    | _ -> raise (KeyNotFoundException())

  /// Implements NoOverlapIntervalMap.tryFindRangeByAddr.
  static member TryFindRangeByAddr(addr, tree: NoOverlapIntervalMap<'V>) =
    match findLoop false (AddrRange.singleton addr) tree with
    | Ok(struct (k, _)) -> Some k
    | _ -> None

  /// Implements NoOverlapIntervalMap.tryFind.
  static member TryFind(range, tree: NoOverlapIntervalMap<'V>) =
    match findLoop true range tree with
    | Ok(struct (_, v)) -> Some v
    | _ -> None

  /// Implements NoOverlapIntervalMap.tryFindByAddr.
  static member TryFindByAddr(addr, tree: NoOverlapIntervalMap<'V>) =
    match findLoop false (AddrRange.singleton addr) tree with
    | Ok(struct (_, v)) -> Some v
    | _ -> None

  /// Implements NoOverlapIntervalMap.tryFindPreviousByAddr.
  static member TryFindPreviousByAddr(addr, tree: NoOverlapIntervalMap<'V>) =
    findPreviousByAddrLoop addr None tree

  /// Implements NoOverlapIntervalMap.tryFindNextByAddr.
  static member TryFindNextByAddr(addr, tree: NoOverlapIntervalMap<'V>) =
    findNextByAddrLoop addr None tree

  /// Implements NoOverlapIntervalMap.findByAddr.
  static member FindByAddr(addr, tree: NoOverlapIntervalMap<'V>) =
    match findLoop false (AddrRange.singleton addr) tree with
    | Ok(struct (_, v)) -> v
    | _ -> raise (KeyNotFoundException())

  /// Implements NoOverlapIntervalMap.count.
  static member Count(tree: NoOverlapIntervalMap<'V>) = sizeAux 0 tree

  /// Implements NoOverlapIntervalMap.iter.
  static member Iter(fn, tree: NoOverlapIntervalMap<'V>) = iter fn tree

  /// Implements NoOverlapIntervalMap.fold.
  static member Fold(fn, acc, tree: NoOverlapIntervalMap<'V>) = fold fn acc tree

  /// Implements NoOverlapIntervalMap.findOverlaps.
  static member FindOverlaps(k: AddrRange, tree: NoOverlapIntervalMap<'V>) =
    findOverlapsLoop k [] tree

/// Provides functions for creating or manipulating non-overlapping interval
/// maps.
[<RequireQualifiedAccess>]
module NoOverlapIntervalMap =

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
  let inline add k v tree = NoOverlapIntervalMapOps<_>.Add(k, v, tree)

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
  let inline addByBounds min max v tree =
    NoOverlapIntervalMapOps<_>.AddByBounds(min, max, v, tree)

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
  let inline replace k v tree = NoOverlapIntervalMapOps<_>.Replace(k, v, tree)

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
  let inline remove k tree = NoOverlapIntervalMapOps<_>.Remove(k, tree)

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
  let inline removeByAddr addr tree =
    NoOverlapIntervalMapOps<_>.RemoveByAddr(addr, tree)

  /// Returns an empty map.
  [<CompiledName("Empty")>]
  let inline empty<'V>: NoOverlapIntervalMap<'V> =
    NoOverlapIntervalMapOps<'V>.Empty

  /// <summary>
  ///   Checks if the given interval map is empty.
  /// </summary>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   Returns true if the tree is empty, false otherwise.
  /// </returns>
  [<CompiledName("IsEmpty")>]
  let inline isEmpty tree = NoOverlapIntervalMapOps<_>.IsEmpty(tree)

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
  let inline containsAddr addr tree =
    NoOverlapIntervalMapOps<_>.ContainsAddr(addr, tree)

  /// <summary>
  ///   Checks whether the exact range exists in the interval map.
  /// </summary>
  /// <param name="range">The address range.</param>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   True if the interval tree contains the interval, false otherwise.
  /// </returns>
  [<CompiledName("ContainsRange")>]
  let inline containsRange range tree =
    NoOverlapIntervalMapOps<_>.ContainsRange(range, tree)

  /// <summary>
  ///   Finds the mapping that exactly matches with the given range.
  /// </summary>
  /// <param name="range">The address range.</param>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   The value associated with the given interval.
  /// </returns>
  [<CompiledName("Find")>]
  let inline find range tree = NoOverlapIntervalMapOps<_>.Find(range, tree)

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
  let inline findRangeByAddr addr tree =
    NoOverlapIntervalMapOps<_>.FindRangeByAddr(addr, tree)

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
  let inline tryFindRangeByAddr addr tree =
    NoOverlapIntervalMapOps<_>.TryFindRangeByAddr(addr, tree)

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
  let inline tryFind range tree =
    NoOverlapIntervalMapOps<_>.TryFind(range, tree)

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
  let inline tryFindByAddr addr tree =
    NoOverlapIntervalMapOps<_>.TryFindByAddr(addr, tree)

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
  let inline tryFindPreviousByAddr addr tree =
    NoOverlapIntervalMapOps<_>.TryFindPreviousByAddr(addr, tree)

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
  let inline tryFindNextByAddr addr tree =
    NoOverlapIntervalMapOps<_>.TryFindNextByAddr(addr, tree)

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
  let inline findByAddr addr tree =
    NoOverlapIntervalMapOps<_>.FindByAddr(addr, tree)

  /// <summary>
  ///   Returns the number of bindings in the interval map.
  /// </summary>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   The number of bindings.
  /// </returns>
  [<CompiledName("Count")>]
  let inline count tree = NoOverlapIntervalMapOps<_>.Count(tree)

  /// <summary>
  ///   Iterates over the tree.
  /// </summary>
  /// <param name="fn">Iterator.</param>
  /// <param name="tree">The interval tree.</param>
  [<CompiledName("Iter")>]
  let inline iter fn tree = NoOverlapIntervalMapOps<_>.Iter(fn, tree)

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
  let inline fold fn acc tree = NoOverlapIntervalMapOps<_>.Fold(fn, acc, tree)

  /// <summary>
  ///   Returns a sequence of overlapping mappings of the given interval.
  /// </summary>
  /// <param name="k">The key interval.</param>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   A sequence of mappings.
  /// </returns>
  [<CompiledName("FindOverlaps")>]
  let inline findOverlaps (k: AddrRange) tree =
    NoOverlapIntervalMapOps<_>.FindOverlaps(k, tree)
