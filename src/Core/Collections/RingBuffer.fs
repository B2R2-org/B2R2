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

/// Represents a fixed-capacity FIFO buffer backed by circular storage.
/// Writing to a full buffer does not overwrite existing elements.
type RingBuffer<'T>(capacity: int) =
  let checkCapacity capacity =
    if capacity <= 0 then
      raise (ArgumentOutOfRangeException(nameof capacity))
    else
      capacity

  let capacity = checkCapacity capacity
  let storage = Array.zeroCreate<'T> capacity
  let mutable readCursor = 0
  let mutable writeCursor = 0
  let mutable count = 0

  /// Holds the fixed capacity of the buffer.
  member _.Capacity = capacity

  /// Holds the number of elements currently buffered.
  member _.Count = count

  /// Indicates whether the buffer holds no elements.
  member _.IsEmpty = count = 0

  /// Indicates whether the buffer is at capacity.
  member _.IsFull = count = capacity

  /// Writes as many leading elements of the source as fit, returning the number
  /// accepted; a full buffer accepts none.
  member _.Write(src: 'T[]) =
    ArgumentNullException.ThrowIfNull src
    let n = min src.Length (capacity - count)
    for i in 0 .. n - 1 do
      storage[writeCursor] <- src[i]
      writeCursor <- (writeCursor + 1) % capacity
    count <- count + n
    n

  /// Reads up to the requested number of elements, returning those available.
  /// An empty buffer returns an empty array.
  member _.Read(maxCount: int) =
    if maxCount < 0 then
      raise (ArgumentOutOfRangeException(nameof maxCount))
    else
      ()
    let n = min maxCount count
    let dst = Array.zeroCreate<'T> n
    for i in 0 .. n - 1 do
      dst[i] <- storage[readCursor]
      readCursor <- (readCursor + 1) % capacity
    count <- count - n
    dst
