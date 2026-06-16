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

/// Represents an interface for accessing the relocation table in a binary file.
type IRelocationTable =
  /// <summary>
  /// Returns an array of all the relocations in the binary.
  /// </summary>
  abstract GetRelocations: unit -> BinRelocation[]

  /// <summary>
  /// Checks if the given address has relocation information.
  /// </summary>
  /// <returns>
  /// True if the address has relocation information, false otherwise.
  /// </returns>
  abstract ContainsRelocation: Addr -> bool

  /// <summary>
  /// Returns a relocation target address of the given virtual address if there
  /// is a corresponding relocation entry.
  /// </summary>
  /// <param name="relocAddr">Virtual address to be relocated.</param>
  /// <returns>
  /// Returns a relocated address for a given virtual address.
  /// </returns>
  abstract TryGetRelocatedAddr: relocAddr: Addr -> Result<Addr, ErrorCase>

  /// <summary>
  /// Tries to resolve the relocation at the given address to a function that
  /// is defined within this binary itself (rather than imported from another
  /// module). This covers a relocation targeting a locally-defined function
  /// and an ifunc resolver referenced by an IRELATIVE-style relocation, both
  /// of which occur in statically linked binaries.
  /// </summary>
  /// <param name="relocAddr">Virtual address to be relocated.</param>
  /// <returns>
  /// Returns the address of the internal function on success.
  /// </returns>
  abstract TryGetInternalFunctionAddr:
    relocAddr: Addr -> Result<Addr, ErrorCase>
