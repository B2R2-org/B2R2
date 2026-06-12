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
  | RawBinary = 0
  /// Raw binary in hexadecimal format, which is a sequence of hexadecimal
  /// digits (0-9, A-F) representing the binary data.
  | HexBinary = 1
  /// ELF binary.
  | ELFBinary = 2
  /// PE binary.
  | PEBinary = 3
  /// Mach-O binary.
  | MachBinary = 4
  /// Wasm binary.
  | WasmBinary = 5
  /// Python binary.
  | PythonBinary = 6

/// <summary>
/// Provides functions to work with <see
/// cref='T:B2R2.FrontEnd.BinFile.FileFormat'/>.
/// </summary>
[<RequireQualifiedAccess>]
module FileFormat =
  /// <summary>
  /// Transforms a string into a <see
  /// cref='T:B2R2.FrontEnd.BinFile.FileFormat'/>.  The match is
  /// case-insensitive, and any unrecognized string is treated as a raw binary,
  /// i.e., it maps to <c>RawBinary</c>.
  /// </summary>
  [<CompiledName "OfString">]
  let ofString (str: string) =
    match str.ToLowerInvariant() with
    | "elf" -> FileFormat.ELFBinary
    | "pe" -> FileFormat.PEBinary
    | "mach" | "mach-o" | "macho" -> FileFormat.MachBinary
    | "wasm" -> FileFormat.WasmBinary
    | "python" -> FileFormat.PythonBinary
    | "hex" -> FileFormat.HexBinary
    | _ -> FileFormat.RawBinary

  /// <summary>
  /// Transforms a <see cref='T:B2R2.FrontEnd.BinFile.FileFormat'/> into a
  /// string. Raises <see
  /// cref='T:B2R2.FrontEnd.BinFile.InvalidFileFormatException'/> when the value
  /// is not one of the defined cases (e.g., an out-of-range enum value).
  /// </summary>
  [<CompiledName "ToString">]
  let toString fmt =
    match fmt with
    | FileFormat.RawBinary -> "Raw"
    | FileFormat.ELFBinary -> "ELF"
    | FileFormat.PEBinary -> "PE"
    | FileFormat.MachBinary -> "Mach-O"
    | FileFormat.WasmBinary -> "Wasm"
    | FileFormat.PythonBinary -> "Python"
    | FileFormat.HexBinary -> "Hex"
    | _ -> raise InvalidFileFormatException

  /// Checks whether the given format is ELF.
  [<CompiledName "IsELF">]
  let isELF fmt = fmt = FileFormat.ELFBinary

  /// Checks whether the given format is PE.
  [<CompiledName "IsPE">]
  let isPE fmt = fmt = FileFormat.PEBinary

  /// Checks whether the given format is Mach-O.
  [<CompiledName "IsMach">]
  let isMach fmt = fmt = FileFormat.MachBinary

  /// Checks whether the given format is Wasm.
  [<CompiledName "IsWasm">]
  let isWasm fmt = fmt = FileFormat.WasmBinary

  /// Checks whether the given format is Python.
  [<CompiledName "IsPython">]
  let isPython fmt = fmt = FileFormat.PythonBinary

  /// Checks whether the given format is a raw binary.
  [<CompiledName "IsRaw">]
  let isRaw fmt = fmt = FileFormat.RawBinary

  /// Checks whether the given format is a hexadecimal binary.
  [<CompiledName "IsHex">]
  let isHex fmt = fmt = FileFormat.HexBinary
