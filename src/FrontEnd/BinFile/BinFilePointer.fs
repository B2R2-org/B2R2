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
    /// Virtual address.
    val Addr: Addr
    /// Max virtual address.
    val MaxAddr: Addr
    /// File offset.
    val Offset: int
    /// Max offset that this pointer can point to.
    val MaxOffset: int

    /// Initializer
    new (addr, maxAddr, offset, maxOffset) =
      { Addr = addr
        MaxAddr = maxAddr
        Offset = offset
        MaxOffset = maxOffset }
  end
with
  /// Checks if the pointer is valid.
  member inline this.IsValid with get () =
    this.Addr <= this.MaxAddr && this.Offset <= this.MaxOffset

  /// Checks if the pointer is null.
  member inline this.IsNull with get () =
    this.Addr = 0UL
    && this.MaxAddr = 0UL
    && this.Offset = -1
    && this.MaxOffset = -1

  /// Checks if the pointer is virtual, meaning that it currently points to a
  /// region that is mapped to VM but not to the file.
  member inline this.IsVirtual with get () =
    this.Offset > this.MaxOffset

  /// Returns the amount of bytes that can be read from the pointer.
  member inline this.ReadableAmount with get () =
    int (this.MaxAddr - this.Addr + 1UL)

  /// Checks if the pointer can read the given size of bytes.
  member inline this.CanRead (size: int) =
    this.Addr + uint64 size - 1UL <= this.MaxAddr

  /// Returns a null pointer.
  static member Null = BinFilePointer (0UL, 0UL, -1, -1)

  /// Advances the pointer by a given amount.
  static member Advance (p: BinFilePointer) amount =
    BinFilePointer (
      p.Addr + uint64 amount,
      p.MaxAddr,
      min (p.MaxOffset + 1) (p.Offset + amount),
      p.MaxOffset)

  override this.ToString () =
    $"{this.Addr:x}-{this.MaxAddr:x} ({this.Offset:x} of {this.MaxOffset:x})"
