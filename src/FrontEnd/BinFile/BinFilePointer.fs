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

namespace B2R2.FrontEnd.BinFile

open B2R2

/// Represents a pointer to binary, which is used to exclusively point to a
/// region of a binary that is (1) mapped to both VM and file, (2) mapped to VM
/// only, or (3) mapped to file only. For the other cases, the pointer is
/// considered invalid (null). The pointer internally holds inclusive ranges of
/// the virtual addresses and the file offsets.
type BinFilePointer =
  struct
    /// The first (inclusive) virtual address of the pointed region.
    val Addr: Addr
    /// The last (inclusive) virtual address of the pointed region.
    val MaxAddr: Addr
    /// <summary>
    /// The first (inclusive) file offset corresponding to <see cref="Addr"/>.
    /// This is -1 for a null pointer.
    /// </summary>
    val Offset: int
    /// <summary>
    /// The last (inclusive) file offset corresponding to <see cref="MaxAddr"/>.
    /// For a virtual (VM-only) region this is less than <see cref="Offset"/>,
    /// and it is -1 for a null pointer.
    /// </summary>
    val MaxOffset: int

    /// <summary>
    /// Creates a binary pointer over the inclusive virtual-address range
    /// [<paramref name="addr"/> .. <paramref name="maxAddr"/>] and the
    /// inclusive file-offset range [<paramref name="offset"/> .. <paramref
    /// name="maxOffset"/>].  To represent a virtual (VM-only) region with no
    /// file backing, pass an <paramref name="offset"/> greater than <paramref
    /// name="maxOffset"/>.
    /// </summary>
    /// <param name="addr">First virtual address of the region.</param> <param
    /// name="maxAddr">Last (inclusive) virtual address of the region.</param>
    /// <param name="offset">First file offset mapped to <paramref
    /// name="addr"/>.</param> <param name="maxOffset">Last (inclusive) file
    /// offset mapped to <paramref name="maxAddr"/>.</param>
    new(addr, maxAddr, offset, maxOffset) =
      { Addr = addr
        MaxAddr = maxAddr
        Offset = offset
        MaxOffset = maxOffset }
  end
with
  /// Checks if the pointer currently points to file-backed bytes.
  member inline this.CanReadFileBytes with get() =
    this.Offset >= 0
    && this.Addr <= this.MaxAddr
    && this.Offset <= this.MaxOffset

  /// Checks if the pointer is null.
  member inline this.IsNull with get() =
    this.Addr = 0UL
    && this.MaxAddr = 0UL
    && this.Offset = -1
    && this.MaxOffset = -1

  /// Checks if the pointer is virtual, meaning that it currently points to a
  /// region that is mapped to VM but not to the file.
  member inline this.IsVirtual with get() = this.Offset > this.MaxOffset

  /// <summary>
  /// Returns the number of file bytes available from the current offset up to
  /// (and including) the max offset. This is zero or negative when the pointer
  /// is virtual (i.e., not backed by the file), so callers should guard with
  /// <see cref="IsVirtual"/> before using this to slice file contents.
  /// </summary>
  member inline this.ReadableAmount with get() =
    this.MaxOffset - this.Offset + 1

  /// <summary>
  /// Checks if the pointer can read the given number of bytes within its
  /// virtual address range. The check is purely address-based (it does not
  /// consider the file offset), so a virtual pointer can still report
  /// <c>true</c>. Returns <c>false</c> for a non-positive size.
  /// </summary>
  member inline this.CanRead(size: int) =
    size > 0
    && this.Addr <= this.MaxAddr
    && uint64 (size - 1) <= this.MaxAddr - this.Addr

  /// <summary>
  /// Advances the pointer forward by the given (non-negative) amount of bytes.
  /// The address moves forward unconditionally, while the file offset is
  /// clamped to one past the max offset, marking the pointer as virtual once it
  /// leaves the file-backed region. The amount is assumed to be non-negative
  /// and small enough not to overflow the address; callers must check whether
  /// the result can read file bytes before dereferencing.
  /// </summary>
  member inline this.Advance(amount: int) =
    BinFilePointer(
      this.Addr + uint64 amount,
      this.MaxAddr,
      min (this.MaxOffset + 1) (this.Offset + amount),
      this.MaxOffset)

  /// <summary>
  /// Advances the pointer forward by the given amount of bytes. See the
  /// <c>int</c> overload for the offset-clamping and validity semantics.
  /// </summary>
  member inline this.Advance(amount: uint32) =
    BinFilePointer(
      this.Addr + uint64 amount,
      this.MaxAddr,
      min (this.MaxOffset + 1) (this.Offset + int amount),
      this.MaxOffset)

  /// Returns a null pointer.
  static member inline Null = BinFilePointer(0UL, 0UL, -1, -1)

  /// Advances the given pointer forward by the given amount of bytes. This is a
  /// static counterpart of the instance `Advance` method, provided for piping
  /// and interop convenience.
  static member Advance(p: BinFilePointer, amount: int) =
    p.Advance amount

  override this.ToString() =
    $"{this.Addr:x}-{this.MaxAddr:x} ({this.Offset:x} of {this.MaxOffset:x})"
