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

/// Represents a format-agnostic symbol-table entry.
type BinSymbol =
  { /// Symbol name.
    Name: string
    /// Virtual address of the symbol. 0 for an undefined/imported symbol that
    /// has no location within this binary.
    Address: Addr
    /// Coarse, format-agnostic classification of the symbol.
    Kind: BinSymbolKind
    /// Linkage binding of the symbol.
    Binding: BinSymbolBinding
    /// Whether the symbol is defined within this binary (has a concrete
    /// location here), as opposed to being undefined and resolved elsewhere.
    IsDefined: bool
    /// Size of the symbol in bytes, when the format records it. None for
    /// formats that do not carry a symbol size (e.g., PE and Mach-O).
    Size: uint64 option
    /// Library/version that provides the symbol, for versioned or
    /// dynamically-bound symbols (e.g., an ELF version such as "GLIBC_2.2.5" or
    /// a Mach-O dylib). None when the symbol carries no such information.
    LibraryName: string option }

/// Represents a coarse, format-agnostic classification of a symbol.
and BinSymbolKind =
  /// A function (code) symbol.
  | FunctionSymbol
  /// A data object symbol.
  | DataSymbol
  /// A symbol naming a section.
  | SectionSymbol
  /// A symbol naming a source file.
  | FileSymbol
  /// Any other or unclassified symbol.
  | OtherSymbol

/// Represents the linkage binding of a symbol.
and BinSymbolBinding =
  /// Visible only within the object that defines it.
  | LocalBinding
  /// Globally visible and may be referenced by other objects.
  | GlobalBinding
  /// Like global, but may be overridden by a non-weak definition.
  | WeakBinding
  /// Binding information is unavailable for this format.
  | UnknownBinding
