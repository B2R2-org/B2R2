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
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.FileHelper

/// <summary>
/// Represents a section header in a PE file.
/// </summary>
type internal SectionHeader =
  { /// The name of the section, which the eight bytes of its field hold. A
    /// name too long to fit there is kept in the COFF string table, and what
    /// the field holds is then a slash and the offset it is kept at.
    Name: string
    /// How many bytes the section takes up in memory.
    VirtualSize: int
    /// Where the section is loaded, relative to the image base.
    VirtualAddress: int
    /// How many bytes the section takes up in the file.
    SizeOfRawData: int
    /// Where the bytes of the section are in the file.
    PointerToRawData: int
    /// Where the relocations of the section are in the file.
    PointerToRelocations: int
    /// Where the line numbers of the section are in the file.
    PointerToLineNumbers: int
    /// How many relocations the section has.
    NumberOfRelocations: uint16
    /// How many line numbers the section has.
    NumberOfLineNumbers: uint16
    /// What the section holds and how it is to be mapped.
    SectionCharacteristics: SectionCharacteristics }

[<RequireQualifiedAccess>]
module internal SectionHeaders =
  /// The number of bytes one section header takes on disk.
  let [<Literal>] EntrySize = 40

  /// The number of bytes the name field of a section header takes.
  let [<Literal>] private NameSize = 8

  /// Returns the section header the given offset of the given span reads as.
  let private read (span: ByteSpan) (reader: IBinReader) offset =
    { Name = readCStringOfSize span offset NameSize
      VirtualSize = reader.ReadInt32(span, offset + 8)
      VirtualAddress = reader.ReadInt32(span, offset + 12)
      SizeOfRawData = reader.ReadInt32(span, offset + 16)
      PointerToRawData = reader.ReadInt32(span, offset + 20)
      PointerToRelocations = reader.ReadInt32(span, offset + 24)
      PointerToLineNumbers = reader.ReadInt32(span, offset + 28)
      NumberOfRelocations = reader.ReadUInt16(span, offset + 32)
      NumberOfLineNumbers = reader.ReadUInt16(span, offset + 34)
      SectionCharacteristics =
        reader.ReadUInt32(span, offset + 36) |> LanguagePrimitives.EnumOfValue }

  /// Returns whether the file has room for the whole of the table.
  let private fits (bytes: byte[]) offset count =
    offset >= 0 && count >= 0
    && int64 offset + int64 count * int64 EntrySize <= int64 bytes.Length

  /// Returns the section headers the given offset of the file holds, as many
  /// of them as the COFF header counts. A count the file leaves no room for
  /// is no count of a table, which makes the file itself invalid.
  let parse (bytes: byte[]) reader offset count =
    if not (fits bytes offset count) then
      raise InvalidFileFormatException
    else
      let span = ReadOnlySpan(bytes, offset, count * EntrySize)
      let headers = Array.zeroCreate count
      for i = 0 to count - 1 do
        headers[i] <- read span reader (i * EntrySize)
      headers
