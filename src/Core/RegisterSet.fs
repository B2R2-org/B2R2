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

/// RegisterSet is an efficient set data structure for managing a set of
/// registers. Since RegisterID always starts from 0, we can use it directly as
/// an index to the bit array.
type RegisterSet (maxNumElems: int) =
  let arr: uint64[] = Array.zeroCreate ((maxNumElems + 63) / 64)

  new () = RegisterSet (378) (* Number of registers for AARCH64 = 378 *)

  /// Get the bucket and the offset from the given index.
  member inline private __.GetBucketAndOffset idx =
    struct (idx / 64, idx &&& 0x3F)

  /// Maximum number of elements that this set can hold.
  member __.MaxNumElems with get() = maxNumElems

  /// The bit array representing the set.
  member __.BitArray with get() = arr

  /// Add a register to the set by marking the corresponding bit.
  member __.Add (idx: int) =
    let struct (bucket, offset) = __.GetBucketAndOffset idx
    arr[bucket] <- arr[bucket] ||| (1UL <<< offset)

  /// Remove a register from the set by unmarking the corresponding bit.
  member __.Remove (idx: int) =
    let struct (bucket, offset) = __.GetBucketAndOffset idx
    arr[bucket] <- arr[bucket] &&& ~~~(1UL <<< offset)

  /// Update the current register set by making a union with the given set.
  member __.Union (other: RegisterSet) =
    assert (other.MaxNumElems = __.MaxNumElems)
    let otherArray = other.BitArray
    for i = 0 to otherArray.Length - 1 do
      arr[i] <- arr[i] ||| otherArray[i]

  /// Update the current register set by making an intersection with the given
  /// set.
  member __.Intersect (other: RegisterSet) =
    assert (other.MaxNumElems = __.MaxNumElems)
    let otherArray = other.BitArray
    for i = 0 to otherArray.Length - 1 do
      arr[i] <- arr[i] &&& otherArray[i]

  /// Check if the set contains the given register indexed by `idx`.
  member __.Contains (idx: int) =
    let struct (bucket, offset) = __.GetBucketAndOffset idx
    (arr[bucket] &&& (1UL <<< offset)) <> 0UL

  /// Check if the set is empty.
  member __.IsEmpty () =
    arr |> Array.forall (fun x -> x = 0UL)

  /// Clear the set.
  member __.Clear () =
    for i = 0 to arr.Length - 1 do
      arr.[i] <- 0UL
