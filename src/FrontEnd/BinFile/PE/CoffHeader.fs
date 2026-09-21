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

/// <summary>
/// Represents the COFF file header, which every PE file carries and which an
/// object file begins with.
/// </summary>
type internal CoffHeader =
  { /// The machine the file was built for.
    Machine: Machine
    /// How many sections the file has.
    NumberOfSections: int16
    /// When the file was created, counted in seconds since the epoch.
    TimeDateStamp: int
    /// Where the COFF symbol table is in the file, which is zero for an image
    /// whose symbols live in a PDB of its own.
    PointerToSymbolTable: int
    /// How many entries that table has.
    NumberOfSymbols: int
    /// How many bytes the optional header takes, which is zero for an object
    /// file, that having none.
    SizeOfOptionalHeader: int16
    /// The attributes of the file.
    Characteristics: Characteristics }

[<RequireQualifiedAccess>]
module internal CoffHeader =
  /// The number of bytes a COFF header takes on disk.
  let [<Literal>] Size = 20

  /// Returns the COFF header the given offset of the file holds.
  let parse (bytes: byte[]) (reader: IBinReader) offset =
    if offset < 0 || int64 offset + int64 Size > int64 bytes.Length then
      raise InvalidFileFormatException
    else
      let span = ReadOnlySpan(bytes, offset, Size)
      { Machine = reader.ReadUInt16(span, 0) |> LanguagePrimitives.EnumOfValue
        NumberOfSections = reader.ReadInt16(span, 2)
        TimeDateStamp = reader.ReadInt32(span, 4)
        PointerToSymbolTable = reader.ReadInt32(span, 8)
        NumberOfSymbols = reader.ReadInt32(span, 12)
        SizeOfOptionalHeader = reader.ReadInt16(span, 16)
        Characteristics =
          reader.ReadUInt16(span, 18) |> LanguagePrimitives.EnumOfValue }
