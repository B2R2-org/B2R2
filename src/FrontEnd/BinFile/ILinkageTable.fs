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
/// Represents an interface for accessing the linkage table of a binary file.
/// </summary>
type ILinkageTable =
  /// <summary>
  /// Return a list of all the linkage table entries from the binary.
  /// </summary>
  /// <returns>
  /// An array of linkage table entries, e.g., PLT entries for ELF files.
  /// </returns>
  abstract GetLinkageTableEntries: unit -> LinkageTableEntry[]

  /// <summary>
  /// Return if a given address is an address of a linkage table entry.
  /// </summary>
  /// <returns>
  /// True if the address is a linkage table address, false otherwise.
  /// </returns>
  abstract IsLinkageTable: Addr -> bool
