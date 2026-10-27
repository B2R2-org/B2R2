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

open System.Collections.Immutable
open B2R2

/// <summary>
/// Represents an interface for accessing the relocation table in a binary
/// file. The array it returns is the storage the file itself keeps, handed
/// over rather than copied, which matters here more than anywhere: a large
/// image relocates hundreds of thousands of slots.
/// </summary>
type IRelocationTable =
  /// <summary>
  /// Returns an array of all the relocations in the binary.
  /// </summary>
  abstract Relocations: ImmutableArray<BinRelocation>

  /// <summary>
  /// Checks if the given address has relocation information.
  /// </summary>
  /// <returns>
  /// True if the address has relocation information, false otherwise.
  /// </returns>
  abstract IsRelocationAddr: Addr -> bool

  /// <summary>
  /// Tries to compute the value that the relocation at the given address
  /// writes into its slot, using only what the binary itself records.
  /// </summary>
  /// <param name="relocAddr">Virtual address to be relocated.</param>
  /// <returns>
  /// Returns the relocation value on success.
  /// </returns>
  abstract TryComputeRelocationValue:
    relocAddr: Addr -> Result<Addr, ErrorCase>

  /// <summary>
  /// Tries to resolve the value that the relocation at the given address
  /// writes into its slot. Where <see
  /// cref="IRelocationTable.TryComputeRelocationValue"/> can only compute a
  /// number, this names the symbol that the loader binds the slot to. A slot
  /// that the program can overwrite after loading has no such value, as what
  /// the loader wrote is no longer what a call through the slot reaches.
  /// </summary>
  /// <param name="relocAddr">Virtual address of the slot.</param>
  /// <returns>
  /// Returns the format-agnostic relocation value on success.
  /// </returns>
  abstract TryResolveRelocationValue:
    relocAddr: Addr -> Result<BinRelocationValue, ErrorCase>

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
