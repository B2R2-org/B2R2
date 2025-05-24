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

namespace B2R2.FrontEnd.BinFile.ELF

/// Provides a general classification for the associated entity.
type SymbolType =
  /// Symbol's type is not specified.
  | STT_NOTYPE = 0uy
  /// This symbol is associated with a data object, such as variable and an
  /// array.
  | STT_OBJECT = 1uy
  /// This symbol is associated with a function.
  | STT_FUNC = 2uy
  /// This symbol is associated with a section. Symbol table entries of this
  /// type exist primarily for relocation and normally have STBLocal binding.
  | STT_SECTION = 3uy
  /// This symbol represents the name of the source file associated with the
  /// object file.
  | STT_FILE = 4uy
  /// This symbol labels an uninitialized common block.
  | STT_COMMON = 5uy
  /// The symbol specifies a Thread-Local Storage entity.
  | STT_TLS = 6uy
  /// The lower bound of OS-specific symbol type.
  | STT_LOOS = 10uy
  /// A symbol with type STT_GNU_IFUNC is a function, but the symbol does not
  /// provide the address of the function as usual. Instead, the symbol provides
  /// the address of a function which returns a pointer to the actual function.
  | STT_GNU_IFUNC = 10uy
  /// The upper bound of OS-specific binding type.
  | STT_HIOS = 12uy
  /// The lower bound of processor-specific symbol type.
  | STT_LOPROC = 13uy
  /// The upper bound of processor-specific symbol type.
  | STT_HIPROC = 15uy

/// Provides functions to convert a SymbolType to a string and vice versa.
[<RequireQualifiedAccess>]
module SymbolType =
  open B2R2

  /// Converts a SymbolType to a string.
  [<CompiledName "ToString">]
  let toString = function
    | SymbolType.STT_NOTYPE -> "NOTYPE"
    | SymbolType.STT_OBJECT -> "OBJECT"
    | SymbolType.STT_FUNC -> "FUNC"
    | SymbolType.STT_SECTION -> "SECTION"
    | SymbolType.STT_FILE -> "FILE"
    | SymbolType.STT_COMMON -> "COMMON"
    | SymbolType.STT_TLS -> "TLS"
    | SymbolType.STT_GNU_IFUNC -> "GNU_IFUNC"
    | _ -> Terminator.futureFeature ()
