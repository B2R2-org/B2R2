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

/// Represents a format-agnostic relocation: a location in the binary image
/// whose contents are patched at link/load time, optionally referencing a
/// symbol and applying a constant addend.
type BinRelocation =
  { /// <summary>
    /// Virtual address of the relocation site, i.e., the location being
    /// patched. This is the value accepted by
    /// <see cref="IRelocationTable.TryGetRelocatedAddr"/>.
    /// </summary>
    Address: Addr
    /// Name of the symbol referenced by this relocation, if any. None for
    /// symbol-less relocations such as PE base relocations or ELF relative
    /// relocations that use only an addend.
    SymbolName: string option
    /// Constant addend applied when computing the relocated value, if the
    /// format carries one. None for PE base relocations.
    Addend: int64 option }
