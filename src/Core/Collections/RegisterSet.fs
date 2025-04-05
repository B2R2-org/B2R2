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

/// RegisterSet is an efficient set data structure for managing a set of
/// registers. Since RegisterID always starts from 0, we can use it directly as
/// an index to the bit array.
type RegisterSet (maxNumElems: int) =
  let arr: int64[] = Array.zeroCreate ((maxNumElems + 63) / 64)

  new () = RegisterSet (378) (* Number of registers for AARCH64 = 378 *)

  /// Get the bucket and the offset from the given index.
  member inline private _.GetBucketAndOffset idx =
    struct (idx / 64, idx &&& 0x3F)

  /// Maximum number of elements that this set can hold.
  member _.MaxNumElems with get() = maxNumElems

  /// The bit array representing the set.
  member _.BitArray with get() = arr

  /// Add a register to the set by marking the corresponding bit.
  member this.Add (idx: int) =
    if idx >= this.MaxNumElems then raise (IndexOutOfRangeException ()) else ()
    let struct (bucket, offset) = this.GetBucketAndOffset idx
    arr[bucket] <- arr[bucket] ||| (1L <<< offset)

  /// Remove a register from the set by unmarking the corresponding bit.
  member this.Remove (idx: int) =
    if idx >= this.MaxNumElems then raise (IndexOutOfRangeException ()) else ()
    let struct (bucket, offset) = this.GetBucketAndOffset idx
    arr[bucket] <- arr[bucket] &&& ~~~(1L <<< offset)

  /// Update the current register set by making a union with the given set.
  member this.Union (other: RegisterSet) =
    assert (other.MaxNumElems = this.MaxNumElems)
    let otherArray = other.BitArray
    for i = 0 to otherArray.Length - 1 do
      arr[i] <- arr[i] ||| otherArray[i]

  /// Update the current register set by making an intersection with the given
  /// set.
  member this.Intersect (other: RegisterSet) =
    assert (other.MaxNumElems = this.MaxNumElems)
    let otherArray = other.BitArray
    for i = 0 to otherArray.Length - 1 do
      arr[i] <- arr[i] &&& otherArray[i]

  /// Check if the set contains the given register indexed by `idx`.
  member this.Contains (idx: int) =
    let struct (bucket, offset) = this.GetBucketAndOffset idx
    (arr[bucket] &&& (1L <<< offset)) <> 0L

  /// Check if the set is empty.
  member _.IsEmpty () =
    arr |> Array.forall (fun x -> x = 0L)

  /// Clear the set.
  member _.Clear () =
    for i = 0 to arr.Length - 1 do
      arr.[i] <- 0L

  /// Iterate over the set and apply the given function to each element.
  member inline this.Iterate ([<InlineIfLambda>] fn) =
    for i = 0 to this.BitArray.Length - 1 do
      let mutable bucket = this.BitArray[i]
      while bucket <> 0L do
        let offset = BitOperations.TrailingZeroCount bucket
        fn (i * 64 + offset)
        bucket <- bucket ^^^ (bucket &&& (- bucket))
