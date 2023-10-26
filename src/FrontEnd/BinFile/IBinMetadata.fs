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

module FileType =
  /// <summary>
  ///   Convert <see cref="T:B2R2.FrontEnd.BinFile.FileType">FileType</see> to
  ///   string.
  /// </summary>
  /// <param name="ty">A FileType to convert.</param>
  /// <returns>
  ///   A converted string.
  /// </returns>
  [<CompiledName ("ToString")>]
  let toString = function
    | FileType.ExecutableFile -> "Executable"
    | FileType.CoreFile -> "Core dump"
    | FileType.LibFile -> "Library"
    | FileType.ObjFile -> "Object"
    | _ -> "Unknown"

/// Basic metadata of a binary file.
type IBinMetadata =
  /// The file path where this file is located.
  abstract Path: string

  /// The format of this file: ELF, PE, Mach-O, or etc.
  abstract Format: FileFormat

  /// The ISA that this file expects to run on.
  abstract ISA: ISA

  /// What kind of binary is this?
  abstract Type: FileType

  /// The entry point of this binary (the start address that this binary runs
  /// at). Note that some binaries (e.g., PE DLL files) do not have a specific
  /// entry point, and EntryPoint will return None in such a case.
  abstract EntryPoint: Addr option

  /// The base address of the associated binary at which it is prefered to be
  /// loaded in memory.
  abstract BaseAddress: Addr
