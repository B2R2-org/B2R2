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

/// <summary>
/// Represents a non-overlapping interval map. By interval map, we mean a map
/// based on an interval tree, which maps an interval (i.e., AddrRange) to a
/// value. We currently implement this using a red-black tree, which follows the
/// implementation of the paper written by Kimball Germane and Matthew Might:
/// "Deletion: The Curse of the Red-Black Tree", Journal of Functional
/// Programming, vol. 24, no. 4, 2014.
/// </summary>
type NoOverlapIntervalMap<'V>

/// Provides functions for creating or manipulating non-overlapping interval
/// maps.
[<RequireQualifiedAccess>]
module NoOverlapIntervalMap =
  /// Return an empty map.
  [<CompiledName("Empty")>]
  val empty: NoOverlapIntervalMap<'V>

  /// <summary>
  ///   Check if the give interval map is empty.
  /// </summary>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   Returns true if the tree is empty, false otherwise.
  /// </returns>
  [<CompiledName("IsEmpty")>]
  val isEmpty: tree: NoOverlapIntervalMap<'V> -> bool

  /// <summary>
  ///   Add a mapping from an interval to the value in the interval tree.
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
  val add:
       k: AddrRange
    -> v: 'V
    -> tree: NoOverlapIntervalMap<'V>
    -> NoOverlapIntervalMap<'V>

  /// <summary>
  ///   This function is the same as add except that this one takes in two
  ///   separate parameters for min and max, instead of taking in an AddrRange
  ///   as input.
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
  [<CompiledName("AddRange")>]
  val addRange:
       min: Addr
    -> max: Addr
    -> v: 'V
    -> tree: NoOverlapIntervalMap<'V>
    -> NoOverlapIntervalMap<'V>

  /// <summary>
  ///   This function is the same as add except that it will overwrite the
  ///   existing range if it exactly matches with the given range. If ranges
  ///   overlap, this function will still raise RangeOverlapException.
  /// </summary>
  /// <param name="k">AddrRange as a key.</param>
  /// <param name="v">The value to be added.</param>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   A new interval tree.
  /// </returns>
  [<CompiledName("Replace")>]
  val replace:
       k: AddrRange
    -> v: 'V
    -> tree: NoOverlapIntervalMap<'V>
    -> NoOverlapIntervalMap<'V>

  /// <summary>
  ///   Remove a mapping that matches exactly with the given range. To remove a
  ///   mapping that covers the given address, use removeAddr.
  /// </summary>
  /// <param name="k">The interval to find.</param>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   A new interval tree.
  /// </returns>
  [<CompiledName("Remove")>]
  val remove:
       k: AddrRange
    -> tree: NoOverlapIntervalMap<'V>
    -> NoOverlapIntervalMap<'V>

  /// <summary>
  ///   Remove a mapping that matches with the given address. Unlike remove,
  ///   this function will remove an interval that includes the given address.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   A new interval tree.
  /// </returns>
  [<CompiledName("RemoveAddr")>]
  val removeAddr:
       addr: Addr
    -> tree: NoOverlapIntervalMap<'V>
    -> NoOverlapIntervalMap<'V>

  /// <summary>
  ///   Check whether a given Addr exists in any of the ranges in the map.
  /// </summary>
  /// <param name="addr">Address.</param>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   True if the interval tree contains an interval that includes the given
  ///   address, false otherwise.
  /// </returns>
  [<CompiledName("ContainsAddr")>]
  val containsAddr:
       addr: Addr
    -> tree: NoOverlapIntervalMap<'V>
    -> bool

  /// <summary>
  ///   Check whether the exact range exists in the interval map.
  /// </summary>
  /// <param name="range">The address range.</param>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   True if the interval tree contains the interval, false otherwise.
  /// </returns>
  [<CompiledName("ContainsRange")>]
  val containsRange:
       range: AddrRange
    -> tree: NoOverlapIntervalMap<'V>
    -> bool

  /// <summary>
  ///   Find the mapping that exactly matches with the given range.
  /// </summary>
  /// <param name="range">The address range.</param>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   The value associated with the given interval.
  /// </returns>
  [<CompiledName("Find")>]
  val find: range: AddrRange -> tree: NoOverlapIntervalMap<'V> -> 'V

  /// <summary>
  ///   Find the mapping that matches with the given range. Unlike find, this
  ///   function can return a range that covers the given address.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   The value associated with the given address.
  /// </returns>
  [<CompiledName("FindByAddr")>]
  val findByAddr: addr: Addr -> tree: NoOverlapIntervalMap<'V> -> 'V

  /// <summary>
  ///   Find an interval stored in the interval tree map, which includes the
  ///   given address.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   The found interval wrapped with option.
  /// </returns>
  [<CompiledName("TryFindKey")>]
  val tryFindKey:
       addr: Addr
    -> tree: NoOverlapIntervalMap<'V>
    -> AddrRange option

  /// <summary>
  ///   Same as find, except that this returns an option-wrapped type.
  /// </summary>
  /// <param name="range">The address range.</param>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   The value associated with the given interval.
  /// </returns>
  [<CompiledName("TryFind")>]
  val tryFind:
       range: AddrRange
    -> tree: NoOverlapIntervalMap<'V>
    -> 'V option

  /// <summary>
  ///   Same as findByAddr, except that this returns an option-wrapped type.
  /// </summary>
  /// <param name="addr">The address.</param>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   The value associated with the given address.
  /// </returns>
  [<CompiledName("TryFindByAddr")>]
  val tryFindByAddr:
       addr: Addr
    -> tree: NoOverlapIntervalMap<'V>
    -> 'V option

  /// <summary>
  ///   Return the number of bindings in the interval map.
  /// </summary>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   The number of bindings.
  /// </returns>
  [<CompiledName("Count")>]
  val count: tree: NoOverlapIntervalMap<'V> -> int

  /// <summary>
  ///   Iterate over the tree.
  /// </summary>
  /// <param name="fn">Iterator.</param>
  /// <param name="tree">The interval tree.</param>
  [<CompiledName("Iterate")>]
  val iter:
       fn: (AddrRange -> 'V -> unit)
    -> tree: NoOverlapIntervalMap<'V>
    -> unit

  /// <summary>
  ///   Fold over the tree.
  /// </summary>
  /// <param name="fn">Folder.</param>
  /// <param name="acc">Accumulator.</param>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   Accumulated value.
  /// </returns>
  [<CompiledName("Fold")>]
  val fold:
       fn: ('b -> AddrRange -> 'V -> 'b)
    -> acc: 'b
    -> tree: NoOverlapIntervalMap<'V>
    -> 'b

  /// <summary>
  ///   Return a sequence of overlapping mappings of the given interval.
  /// </summary>
  /// <param name="k">The key interval.</param>
  /// <param name="tree">The interval tree.</param>
  /// <returns>
  ///   A sequence of mappings.
  /// </returns>
  [<CompiledName("GetOverlaps")>]
  val getOverlaps:
       k: AddrRange
    -> tree: NoOverlapIntervalMap<'V>
    -> (AddrRange * 'V) list
