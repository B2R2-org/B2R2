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

/// <summary>
/// Represents the file format of a binary.
/// </summary>
type FileFormat =
  /// Raw binary without any specific file format: a sequence of bytes.
  | RawBinary = 1
  /// ELF binary.
  | ELFBinary = 2
  /// PE binary.
  | PEBinary = 3
  /// Mach-O binary.
  | MachBinary = 4
  /// Wasm binary.
  | WasmBinary = 5

/// <summary>
/// Provides functions to work with <see
/// cref='T:B2R2.FrontEnd.BinFile.FileFormat'/>.
/// </summary>
[<RequireQualifiedAccess>]
module FileFormat =
  /// Transforms a string into a FileFormat.
  [<CompiledName "OfString">]
  let ofString (str: string) =
    match str.ToLowerInvariant () with
    | "elf" -> FileFormat.ELFBinary
    | "pe" -> FileFormat.PEBinary
    | "mach" | "mach-o" -> FileFormat.MachBinary
    | "wasm" -> FileFormat.WasmBinary
    | _ -> FileFormat.RawBinary

  /// Transforms a FileFormat into a string.
  [<CompiledName "ToString">]
  let toString fmt =
    match fmt with
    | FileFormat.RawBinary -> "Raw"
    | FileFormat.ELFBinary -> "ELF"
    | FileFormat.PEBinary -> "PE"
    | FileFormat.MachBinary -> "Mach-O"
    | FileFormat.WasmBinary -> "Wasm"
    | _ -> invalidArg (nameof fmt) "Unknown FileFormat used."

  /// Checks whether the given format is ELF.
  [<CompiledName "IsELF">]
  let isELF fmt = fmt = FileFormat.ELFBinary

  /// Checks whether the given format is PE.
  [<CompiledName "IsPE">]
  let isPE fmt = fmt = FileFormat.PEBinary

  /// Checks whether the given format is Mach-O.
  [<CompiledName "IsMach">]
  let isMach fmt = fmt = FileFormat.MachBinary
