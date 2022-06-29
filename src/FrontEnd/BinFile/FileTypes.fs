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

open System
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
  | NoType
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

/// Is the symbol used for static target (static link editor) or dynamic target
/// (dynamic linker)?
type TargetKind =
  /// Static symbols are used by link editor, and can be stripped off.
  | StaticSymbol = 1
  /// Dynamic symbols cannot be stripped off.
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
  /// Corresponding ArchOperationMode for this symbol, which is only meaningful
  /// for ARM.
  ArchOperationMode: ArchOperationMode
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
  /// File offset of the section.
  FileOffset: uint64
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
    AddrRange (__.Address, __.Address + __.Size - 1UL)

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
[<Flags>]
type Permission =
  /// File is readable.
  | Readable = 4
  /// File is writable.
  | Writable = 2
  /// File is executable.
  | Executable = 1

module Permission =
  /// Permission to string.
  [<CompiledName ("ToString")>]
  let toString (p: Permission) =
    let r = if p.HasFlag Permission.Readable then "r" else "-"
    let w = if p.HasFlag Permission.Writable then "w" else "-"
    let x = if p.HasFlag Permission.Executable then "x" else "-"
    r + w + x

/// A segment is a block of code/data that is loaded in the real memory at
/// runtime. A segment can contain multiple sections in it.
type Segment = {
  /// Address of the segment.
  Address: Addr
  /// Offset in the file.
  Offset: uint64
  /// Size of the segment.
  Size: uint64
  /// Size of the corresponding segment in file. This can be smaller than
  /// `Size` in which case the missing part is filled with zeros.
  SizeInFile: uint64
  /// Permission of the segment.
  Permission: Permission
}
