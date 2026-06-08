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

open System
open System.Numerics

/// Represents an error raised when a register set is created with an invalid
/// size.
exception InvalidRegisterSetSizeException

/// Represents a set of register IDs. This is an efficient and
/// architecture-agnostic set data structure that internally uses bit arrays.
/// Since RegisterIDs always start from 0 for any architecture, we can use it
/// directly as an index to the bit array.
type RegisterSet(maxNumElems: int) =
  let computeBucketCount maxNumElems =
    if maxNumElems < 0 then raise InvalidRegisterSetSizeException
    elif maxNumElems = 0 then 0
    else ((maxNumElems - 1) / 64) + 1

  let arr: int64[] = Array.zeroCreate (computeBucketCount maxNumElems)

  let checkIndex idx =
    if idx < 0 || idx >= maxNumElems then
      raise (ArgumentOutOfRangeException(nameof idx))
    else
      ()

  let checkCompatibility (other: RegisterSet) =
    if other.MaxNumElems <> maxNumElems then
      raise (ArgumentException "RegisterSet sizes must match.")
    else
      ()

  new() = RegisterSet(378) (* Number of registers for AARCH64 = 378 *)

  /// Gets the maximum number of elements that this set can hold.
  member _.MaxNumElems with get() = maxNumElems

  /// Gets the bit array representing the set.
  member internal _.BitArray with get() = arr

  /// Gets the number of buckets in the bit array.
  member _.BucketCount with get() = arr.Length

  /// Returns the bucket and the offset from the given index.
  member inline private _.GetBucketAndOffset idx =
    struct (idx / 64, idx &&& 0x3F)

  /// Adds a register to the set by marking the corresponding bit.
  member this.Add(idx: int) =
    checkIndex idx
    let struct (bucket, offset) = this.GetBucketAndOffset idx
    arr[bucket] <- arr[bucket] ||| (1L <<< offset)

  /// Removes a register from the set by unmarking the corresponding bit.
  member this.Remove(idx: int) =
    checkIndex idx
    let struct (bucket, offset) = this.GetBucketAndOffset idx
    arr[bucket] <- arr[bucket] &&& ~~~(1L <<< offset)

  /// Updates the current register set by making a union with the given set.
  member _.Union(other: RegisterSet) =
    checkCompatibility other
    let otherArray = other.BitArray
    for i = 0 to otherArray.Length - 1 do
      arr[i] <- arr[i] ||| otherArray[i]

  /// Updates the current register set by making an intersection with the given
  /// set.
  member _.Intersect(other: RegisterSet) =
    checkCompatibility other
    let otherArray = other.BitArray
    for i = 0 to otherArray.Length - 1 do
      arr[i] <- arr[i] &&& otherArray[i]

  /// Checks if the set contains the given register indexed by <c>idx</c>.
  member this.Contains(idx: int) =
    checkIndex idx
    let struct (bucket, offset) = this.GetBucketAndOffset idx
    (arr[bucket] &&& (1L <<< offset)) <> 0L

  /// Checks if the set is empty.
  member _.IsEmpty() =
    arr |> Array.forall (fun x -> x = 0L)

  /// Clears the set.
  member _.Clear() =
    Array.Clear arr

  /// Iterates over the set and applies the given function to each element.
  member _.Iterate fn =
    for i = 0 to arr.Length - 1 do
      let mutable bucket = arr[i]
      while bucket <> 0L do
        let offset = BitOperations.TrailingZeroCount bucket
        fn (i * 64 + offset)
        bucket <- bucket &&& (bucket - 1L)
