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

/// Can be used to access the binary content of a file via a virtual address or
/// a file offset.
type IContentAddressable =
  /// The size of the associated binary file.
  abstract member Length: int

  /// The raw file content as a byte array.
  abstract member RawBytes: byte[]

  /// The raw file content as a ByteSpan.
  abstract member Span: ByteSpan

  /// <summary>
  ///   Translate a virtual address into a relative offset to the binary file.
  /// </summary>
  /// <param name="addr">Virtual address.</param>
  /// <returns>
  ///   Returns an offset to the binary for a given virtual address.
  /// </returns>
  /// <exception cref="T:B2R2.FrontEnd.BinFile.InvalidAddrReadException">
  ///   Thrown when the given address is out of a valid address range.
  /// </exception>
  abstract member GetOffset: addr: Addr -> int

  /// Slice a portion of the associated binary file based on the given virtual
  /// `addr` and its `size`.
  abstract member Slice: addr: Addr * size: int -> ByteSpan

  /// Slice a maximum possible portion of the associated binary file based on
  /// the given virtual `addr`.
  abstract member Slice: addr: Addr -> ByteSpan

  /// Slice a portion of the associated binary file based on the given file
  /// `offset` and its `size`.
  abstract member Slice: offset: int * size: int -> ByteSpan

  /// Slice a maximum possible portion of the associated binary file based on
  /// the given file `offset`.
  abstract member Slice: offset: int -> ByteSpan

  /// Slice a portion of the associated binary file based on the given pointer
  /// `ptr` and its `size`.
  abstract member Slice: ptr: BinFilePointer * size: int -> ByteSpan

  /// Slice a maximum possible portion of the associated binary file based on
  /// the given virtual `addr`.
  abstract member Slice: ptr: BinFilePointer -> ByteSpan

  /// <summary>
  ///   Check if the given address is valid for the associated binary. We say a
  ///   given address is valid for the binary if the address is within the range
  ///   of statically computable segment ranges.
  /// </summary>
  /// <returns>
  ///   Returns true if the address is within a valid range, false otherwise.
  /// </returns>
  abstract member IsValidAddr: Addr -> bool

  /// <summary>
  ///   Check if the given address range is valid. This function returns true
  ///   only if the whole range of the addressess are valid (for every address
  ///   in the range, IsValidAddr should return true).
  /// </summary>
  /// <returns>
  ///   Returns true if the whole range of addresses is within a valid range,
  ///   false otherwise.
  /// </returns>
  abstract member IsValidRange: AddrRange -> bool

  /// <summary>
  ///   Check if the given address is valid and there is an actual mapping from
  ///   the associated binary file to the corresponding memory. Unlike
  ///   IsValidAddr, this function checks if we can decide the actual value of
  ///   the given address from the binary. For example, a program header of an
  ///   ELF file may contain 100 bytes in size, but when it is mapped to a
  ///   segment in memory, the size of the segment can be larger than the size
  ///   of the program header. This function checks if the given address is in
  ///   the range of the segment that has a direct mapping to the file's program
  ///   header.
  /// </summary>
  /// <returns>
  ///   Returns true if the address is within a mapped address range, false
  ///   otherwise.
  /// </returns>
  abstract member IsInFileAddr: Addr -> bool

  /// <summary>
  ///   Check if the given address range is valid and there exists a
  ///   corresponding region in the actual binary file. This function returns
  ///   true only if the whole range of the addressess are valid (for every
  ///   address in the range, IsInFileAddr should return true).
  /// </summary>
  /// <returns>
  ///   Returns true if the whole range of addresses is within a valid range,
  ///   false otherwise.
  /// </returns>
  abstract member IsInFileRange: AddrRange -> bool

  /// <summary>
  ///   Check if the given address is executable address for this binary. We say
  ///   a given address is executable if the address is within an executable
  ///   segment. Note we consider the addresses of known read-only sections
  ///   (such as .rodata) as non-executable, even though those sections are
  ///   within an executable segment. For object files, we simply consider a
  ///   .text section's address range as executable.
  /// </summary>
  /// <returns>
  ///   Returns true if the address is executable, false otherwise.
  /// </returns>
  abstract member IsExecutableAddr: Addr -> bool

  /// <summary>
  ///   Given a range r, return a list of address ranges (intervals) that are
  ///   within r, and that are not in-file.
  /// </summary>
  /// <returns>
  ///   Returns an empty list when the given range r is valid, i.e.,
  ///   `IsInFileRange r = true`.
  /// </returns>
  abstract member GetNotInFileIntervals: AddrRange -> seq<AddrRange>

