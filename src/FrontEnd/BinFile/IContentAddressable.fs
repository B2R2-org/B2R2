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

/// <summary>
/// Represents an interface for accessing the raw binary content of a file via a
/// virtual address.
/// </summary>
type IContentAddressable =
  /// <summary>
  /// Slices the raw binary content into a read-only span of bytes of the
  /// specified length starting from the specified address.
  /// </summary>
  /// <returns>
  /// Returns a read-only span of bytes starting from the specified address.
  /// </returns>
  abstract Slice: addr: Addr * len: int -> System.ReadOnlySpan<byte>

  /// <summary>
  /// Checks if the given address is valid for the associated binary. We say a
  /// given address is valid for the binary if the address is within the range
  /// of statically computable segment ranges.
  /// </summary>
  /// <returns>
  /// Returns true if the address is within a valid range, false otherwise.
  /// </returns>
  abstract IsValidAddr: Addr -> bool

  /// <summary>
  /// Checks if the given address range is valid. This function returns true
  /// only if the whole range of the addressess are valid (for every address in
  /// the range, IsValidAddr should return true).
  /// </summary>
  /// <returns>
  /// Returns true if the whole range of addresses is within a valid range,
  /// false otherwise.
  /// </returns>
  abstract IsValidRange: AddrRange -> bool

  /// <summary>
  /// Checks if the given address is valid and there is an actual mapping from
  /// the associated binary file to the corresponding memory. Unlike
  /// IsValidAddr, this function checks if we can decide the actual value of the
  /// given address from the binary. For example, a program header of an ELF
  /// file may contain 100 bytes in size, but when it is mapped to a segment in
  /// memory, the size of the segment can be larger than the size of the program
  /// header. This function checks if the given address is in the range of the
  /// segment that has a direct mapping to the file's program header.
  /// </summary>
  /// <returns>
  /// Returns true if the address is within a mapped address range, false
  /// otherwise.
  /// </returns>
  abstract IsAddrMappedToFile: Addr -> bool

  /// <summary>
  /// Checks if the given address range is valid and there exists a
  /// corresponding region in the actual binary file. This function returns true
  /// only if the whole range of the addressess are valid (for every address in
  /// the range, IsAddrMappedToFile should return true).
  /// </summary>
  /// <returns>
  /// Returns true if the whole range of addresses is within a valid range,
  /// false otherwise.
  /// </returns>
  abstract IsRangeMappedToFile: AddrRange -> bool

  /// <summary>
  /// Checks if the given address is executable address for this binary. We say
  /// a given address is executable if the address is within an executable
  /// segment. Note we consider the addresses of known read-only sections (such
  /// as .rodata) as non-executable, even though those sections are within an
  /// executable segment. For object files, we simply consider a .text section's
  /// address range as executable.
  /// </summary>
  /// <returns>
  /// Returns true if the address is executable, false otherwise.
  /// </returns>
  abstract IsExecutableAddr: Addr -> bool

  /// <summary>
  /// Retrieves a file pointer that has its boundary aligned to the regions
  /// defined by file structures. Specifically, we split four types of regions
  /// in a binary file: (1) VM and file-mapped regions, (2) VM-only regions, and
  /// (3) file-only regions, and (4) unmapped regions. A returned pointer will
  /// exclusively point to one of the first two regions, or it will be a null
  /// pointer for the rest cases. To retrieve a pointer for (3), use
  /// format-specific member functions.
  /// <remark>
  /// Case (1) is the most common case, where the address is mapped to a file
  /// offset. Case (2) is a region that has its virtual address but not mapped
  /// to the file. For example, segments in ELF files often have such a region
  /// that is only available in the VMA.
  /// </remark>
  /// </summary>
  abstract GetBoundedPointer: addr: Addr -> BinFilePointer

  /// <summary>
  /// Returns an array of VM-mapped regions. By a VM-mapped region, we mean a
  /// consecutive region that has a corresponding mapping in the virtual memory.
  /// For example, an entire segment of an ELF file is considered a VM-mapped
  /// region.
  /// </summary>
  abstract GetVMMappedRegions: unit -> AddrRange[]

  /// <summary>
  /// Returns an array of VM-mapped regions that have the given permission. By
  /// a VM-mapped region, we mean a region that has a corresponding mapping in
  /// the virtual memory. For example, an entire segment of an ELF file is
  /// considered a VM-mapped region.
  /// </summary>
  abstract GetVMMappedRegions: perm: Permission -> AddrRange[]
