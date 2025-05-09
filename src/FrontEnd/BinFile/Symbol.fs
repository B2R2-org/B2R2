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
/// Represents a symbol object defined in a file-format-agnostic way.
/// </summary>
type Symbol = {
  /// Address of the symbol.
  Address: Addr
  /// Symbol name.
  Name: string
  /// Symbol kind.
  Kind: SymbolKind
  /// Symbol visibility (static or dynamic).
  Visibility: SymbolVisibility
  /// Corresponding library name.
  LibraryName: string
  /// ARM32-specific linker symbol. For other architectures, this will be set to
  /// None.
  ARMLinkerSymbol: ARMLinkerSymbol
}

/// Represents a kind of symbol.
and SymbolKind =
  /// The symbol type is not specified.
  | SymNoType
  /// The symbol is associated with a data object, such as a variable.
  | SymObjectType
  /// The symbol is associated with a general function.
  | SymFunctionType
  /// The symbol is associated with an external (imported) function.
  | SymExternFunctionType
  /// The symbol is associated with a trampoline instruction, such as PLT.
  | SymTrampolineType
  /// The symbol is associated with a section.
  | SymSectionType
  /// The symbol gives the name of the source file associated with the obj file.
  | SymFileType
  /// The symbol is associated with a forwarding entry.
  | SymForwardType of bin: string * func: string

/// Represents the visibility of a symbol, which indicates whether the symbol is
/// visible by external modules or not.
and SymbolVisibility =
  /// Static symbols do not need to be visible by external modules, and can be
  /// stripped off.
  | StaticSymbol = 1
  /// Dynamic symbols cannot be stripped off. This should be visible to externs.
  | DynamicSymbol = 2

/// Represents an ARM-specific symbol type for ELF binaries, which are used to
/// distinguish between ARM and Thumb instructions. For other CPU architectures,
/// this will be set to None.
and ARMLinkerSymbol =
  | ARM = 1
  | Thumb = 2
  | None = 3
