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

namespace B2R2.FrontEnd.BinLifter

open B2R2

/// Provides an interface for producing disassembly, which is used to accumulate
/// disassembly strings and to return them as a single string or an array of
/// AsmWords when requested.
type IDisasmBuilder =
  /// Word size of the target architecture.
  abstract WordSize: WordSize

  /// Whether to show the address in the disassembly.
  abstract ShowAddress: bool with get, set

  /// Whether to show symbols in the disassembly. Even though this is true,
  /// symbols are not shown if there is no corresponding symbol for the address.
  abstract ShowSymbol: bool with get, set

  /// Accumulates an AsmWord whose kind and value are given into the disassembly
  /// builder.
  abstract Accumulate: kind: AsmWordKind -> value: string -> unit

  /// Accumulates a symbol that is mapped from the given address into the
  /// disassembly builder. The final disassembly string uses the provided prefix
  /// and suffix. When the symbol is not found, we use the noSymbolMapper
  /// function to generate a string.
  abstract AccumulateSymbol:
       addr: Addr
     * prefix: AsmWord
     * suffix: AsmWord
     * noSymbolMapper: (Addr -> AsmWord[])
    -> unit

  /// Accumulates an address marker (address of an instruction preceding the
  /// disassembly) into the disassembly builder.
  abstract AccumulateAddrMarker: Addr -> unit

  /// Returns a string representation of the accumulated disassembly.
  abstract ToString: unit -> string

  /// Returns an array of AsmWords representing the accumulated disassembly.
  abstract ToAsmWords: unit -> AsmWord[]
