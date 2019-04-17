(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>

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

namespace B2R2.BinFile

open B2R2

/// Raised when accessing an invalid address of a binary file.
exception InvalidAddrReadException

/// Raised when an unexpected file format is detected.
exception FileFormatMismatchException

/// Raised when an invalid file type is encountered.
exception InvalidFileTypeException

/// Kinds of a symbol.
type SymbolKind =
  /// The symbol type is not specified.
  | NoType = 0
  /// The symbol is associated with a data object, such as a variable.
  | ObjectType = 1
  /// The symbol is associated with a general function.
  | FunctionType = 2
  /// The symbol is associated with an external (imported) function.
  | ExternFunctionType = 3
  /// The symbol is associated with a section.
  | SectionType = 4
  /// The symbol gives the name of the source file associated with the obj file.
  | FileType = 5

/// Is the symbol used for static target or dynamic target?
type TargetKind =
  /// Static symbols.
  | StaticSymbol = 1
  /// Dynamic symbols.
  | DynamicSymbol = 2

/// A symbol object defined in a file-format-agnostic way.
type Symbol = {
  /// Address of the symbol.
  Address: Addr
  /// Symbol name.
  Name: string
  /// Symbol kind.
  Kind: SymbolKind
  /// Symbol target.
  Target: TargetKind
  /// Corresponding library name.
  LibraryName: string
}

/// Kinds of sections.
type SectionKind =
  /// Executable section.
  | ExecutableSection = 1
  /// Writable section.
  | WritableSection = 2
  /// Linkage table, such as PLT, section.
  | LinkageTableSection = 3
  /// Extra section.
  | ExtraSection = 4

/// A section object defined in a file-format-agnostic way. A Section in B2R2
/// should be located inside a segment.
type Section = {
  /// Address of the section.
  Address: Addr
  /// Section kind.
  Kind: SectionKind
  /// Size of the section.
  Size: uint64
  /// Name of the section.
  Name: string
}
with
  /// Convert the section into an AddrRange based on its starting address and
  /// the size.
  member __.ToAddrRange () =
    AddrRange (__.Address, __.Address + __.Size)

/// Linkage table entry object, which basically refers to PLT or IAT.
type LinkageTableEntry = {
  /// Target function name for dynamic linking.
  FuncName: string
  /// Corresponding library name.
  LibraryName: string
  /// Trampoline code address, e.g., PLT.
  TrampolineAddress: Addr
  /// The address of the table that stores the actual target address, e.g., GOT.
  TableAddress: Addr
}

/// FileType represents categories for binary files.
type FileType =
  /// Executable.
  | ExecutableFile = 1
  /// Core (core dump).
  | CoreFile = 2
  /// Library.
  | LibFile = 3
  /// Object.
  | ObjFile = 4
  /// Other types.
  | UnknownFile = 5

/// File permission. Each permission corresponds to a bit, and thus, multiple
/// permissions can be OR-ed.
[<System.FlagsAttribute>]
type Permission =
  /// File is readable.
  | Readable   = 4
  /// File is writable.
  | Writable   = 2
  /// File is executable.
  | Executable = 1

/// A segment is a block of code/data that is loaded in the real memory at
/// runtime. A segment can contain multiple sections in it.
type Segment = {
  /// Address of the segment.
  Address: Addr
  /// Size of the segment.
  Size: uint64
  /// Permission of the segment.
  Permission: Permission
}
