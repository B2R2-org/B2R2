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

namespace B2R2.FrontEnd.BinFile.PE

open System
open B2R2.FrontEnd.BinLifter

/// <summary>
/// Represents the CLI header of a managed image, which the specification
/// calls IMAGE_COR20_HEADER and which a native image does not carry.
/// </summary>
type internal CorHeader =
  { /// The major version of the runtime the image needs.
    MajorRuntimeVersion: uint16
    /// The minor version of that runtime.
    MinorRuntimeVersion: uint16
    /// Where the metadata of the image is.
    MetadataDirectory: DataDirectory
    /// What a runtime is to make of the image.
    Flags: CorFlags
    /// The token of the entry point, or its address where the image is
    /// entered through native code instead.
    EntryPointTokenOrRelativeVirtualAddress: int
    /// Where the managed resources of the image are.
    ResourcesDirectory: DataDirectory
    /// Where the strong name signature of the image is.
    StrongNameSignatureDirectory: DataDirectory
    /// Where the code manager table is; every image leaves this empty.
    CodeManagerTableDirectory: DataDirectory
    /// Where the vtable fixups are, which only a mixed-mode image has.
    VtableFixupsDirectory: DataDirectory
    /// Where the export address table jumps are.
    ExportAddressTableJumpsDirectory: DataDirectory
    /// Where the native header of a precompiled image is.
    ManagedNativeHeaderDirectory: DataDirectory }

[<RequireQualifiedAccess>]
module internal CorHeader =
  /// The number of bytes a CLI header takes on disk.
  let [<Literal>] Size = 72

  /// Returns the CLI header at the given offset of the file, or none where
  /// there is none to read: an image naming no CLI header, one naming a
  /// header no section maps, and one the file leaves no room for all read as
  /// the native image they are indistinguishable from here.
  let tryParse (bytes: byte[]) (reader: IBinReader) offset =
    if offset < 0 || int64 offset + int64 Size > int64 bytes.Length then
      None
    else
      let span = ReadOnlySpan(bytes, offset, Size)
      Some { MajorRuntimeVersion = reader.ReadUInt16(span, 4)
             MinorRuntimeVersion = reader.ReadUInt16(span, 6)
             MetadataDirectory = DataDirectory.read span reader 8
             Flags =
               reader.ReadInt32(span, 16) |> LanguagePrimitives.EnumOfValue
             EntryPointTokenOrRelativeVirtualAddress =
               reader.ReadInt32(span, 20)
             ResourcesDirectory = DataDirectory.read span reader 24
             StrongNameSignatureDirectory = DataDirectory.read span reader 32
             CodeManagerTableDirectory = DataDirectory.read span reader 40
             VtableFixupsDirectory = DataDirectory.read span reader 48
             ExportAddressTableJumpsDirectory =
               DataDirectory.read span reader 56
             ManagedNativeHeaderDirectory = DataDirectory.read span reader 64 }
