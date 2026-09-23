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
/// Provides low-level functions to create a binary file object. This is used by
/// the <see cref='T:B2R2.FrontEnd.BinHandle'/> module internally, and hence, it
/// is recommended to use the <see cref='T:B2R2.FrontEnd.BinHandle'/> module
/// instead, in most cases.
/// </summary>
[<RequireQualifiedAccess>]
module FileFactory =
  open B2R2.FrontEnd.BinFile.FileHelper

  /// <summary>
  /// Creates a binary file object from the given path and byte array
  /// representing the raw content of the file.
  /// <param name="path">The path to the binary file.</param>
  /// <param name="bytes">The raw content of the binary file.</param>
  /// <param name="fmt">The file format of the binary file.</param>
  /// <param name="isa">The target ISA of the binary file.</param>
  /// <param name="regFactory">The register factory for the target ISA.</param>
  /// <param name="baseAddrOpt">An optional base address for the binary
  /// file.
  /// </param>
  /// </summary>
  let load path bytes fmt isa regFactory baseAddrOpt =
    match fmt with
    | FileFormat.ELFBinary ->
      ELFBinFile(path, bytes, baseAddrOpt, Some regFactory) :> IBinFile
    | FileFormat.PEBinary ->
      PEBinFile(path, bytes, baseAddrOpt, [||]) :> IBinFile
    | FileFormat.MachBinary ->
      MachBinFile(path, bytes, isa, baseAddrOpt, Some regFactory) :> IBinFile
    | FileFormat.WasmBinary ->
      WasmBinFile(path, bytes, baseAddrOpt) :> IBinFile
    | FileFormat.PythonBinary ->
      PythonBinFile(path, bytes) :> IBinFile
    | FileFormat.HexBinary ->
      RawBinFile(path, parseHexBytes bytes, isa, baseAddrOpt) :> IBinFile
    | FileFormat.RawBinary ->
      RawBinFile(path, bytes, isa, baseAddrOpt) :> IBinFile
    | _ ->
      raise InvalidFileFormatException

  /// <summary>
  /// Creates an ELF binary file object.
  /// </summary>
  let loadELF path bytes regFactory baseAddrOpt =
    ELFBinFile(path, bytes, baseAddrOpt, Some regFactory)

  /// <summary>
  /// Creates a PE binary file object from the bytes of its PDB. An empty
  /// <c>rawpdb</c> names no PDB, and one is then looked for beside the image.
  /// <param name="path">The path to the binary file.</param>
  /// <param name="bytes">The raw content of the binary file.</param>
  /// <param name="baseAddrOpt">An optional base address for the binary
  /// file.
  /// </param>
  /// <param name="rawpdb">The raw content of the PDB, or an empty array to
  /// name none.
  /// </param>
  /// </summary>
  let loadPE path bytes baseAddrOpt (rawpdb: byte[]) =
    PEBinFile(path, bytes, baseAddrOpt, rawpdb)

  /// <summary>
  /// Creates a PE binary file object from the path to its PDB, which is read
  /// a block at a time rather than into one array. It is the way to name a
  /// PDB too large to hold in an array, which the biggest of them are.
  /// <param name="path">The path to the binary file.</param>
  /// <param name="bytes">The raw content of the binary file.</param>
  /// <param name="baseAddrOpt">An optional base address for the binary
  /// file.
  /// </param>
  /// <param name="pdbPath">The path to the PDB of the binary file.</param>
  /// </summary>
  let loadPEWithPDBPath path bytes baseAddrOpt (pdbPath: string) =
    PEBinFile(path, bytes, baseAddrOpt, pdbPath)

  /// <summary>
  /// Creates a binary file object from the given path and byte array, along
  /// with the debug file at the given path: a file sitting beside the binary
  /// that carries the symbols the binary itself does not. Only a PE reads one
  /// today, and it is a PDB; a format whose separate debug file this reader
  /// does not read yet is loaded as if no path had been given.
  /// <param name="path">The path to the binary file.</param>
  /// <param name="bytes">The raw content of the binary file.</param>
  /// <param name="fmt">The file format of the binary file.</param>
  /// <param name="isa">The target ISA of the binary file.</param>
  /// <param name="regFactory">The register factory for the target ISA.</param>
  /// <param name="baseAddrOpt">An optional base address for the binary
  /// file.
  /// </param>
  /// <param name="debugPath">The path to the debug file.</param>
  /// </summary>
  let loadWithDebugFile path bytes fmt isa regFactory baseAddrOpt debugPath =
    match fmt with
    | FileFormat.PEBinary ->
      PEBinFile(path, bytes, baseAddrOpt, (debugPath: string)) :> IBinFile
    | _ ->
      load path bytes fmt isa regFactory baseAddrOpt

  /// <summary>
  /// Creates a Mach-O binary file object.
  /// </summary>
  let loadMach path bytes isa regFactory baseAddrOpt =
    MachBinFile(path, bytes, isa, baseAddrOpt, Some regFactory)
