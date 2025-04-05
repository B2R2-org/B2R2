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
open System

/// A pointer to binary, which is used to exclusively point to a portion of a
/// binary, e.g., a section. It holds both the virtual address as well as the
/// file offset. Both Offset and MaxOffset are inclusive.
type BinFilePointer =
  struct
    /// Virtual address.
    val Addr: Addr
    /// File offset.
    val Offset: int
    /// Max offset that this pointer can point to.
    val MaxOffset: int

    /// Initializer
    new (addr, offset, max) = { Addr = addr; Offset = offset; MaxOffset = max }
  end
with
  static member Null = BinFilePointer (0UL, 0, 0)

  static member inline IsValid (ptr: BinFilePointer) =
    ptr.Offset <= ptr.MaxOffset

  static member inline IsValidAccess (ptr: BinFilePointer) size =
    (ptr.Offset + size - 1) <= ptr.MaxOffset

  static member OfSection (s: Section) =
    BinFilePointer (s.Address,
      Convert.ToInt32 s.FileOffset,
      Convert.ToInt32 s.FileOffset + Convert.ToInt32 s.Size - 1)

  static member OfSectionOpt section =
    match section with
    | Some s -> BinFilePointer.OfSection s
    | None -> BinFilePointer.Null

  static member IsNull ptr =
    ptr = BinFilePointer.Null

  static member Advance (p: BinFilePointer) amount =
    BinFilePointer (p.Addr + uint64 amount, p.Offset + amount, p.MaxOffset)

  override this.ToString () =
    $"{this.Addr:x} ({this.Offset:x} of {this.MaxOffset:x})"
