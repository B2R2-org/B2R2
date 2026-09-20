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

/// Provides functions to parse Mach-O FAT binary headers.
[<RequireQualifiedAccess>]
module internal B2R2.FrontEnd.BinFile.Mach.Fat

open System
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile

/// Size of a fat_arch entry.
let [<Literal>] private ArchSize = 20

/// Size of a fat_arch_64 entry, which widens the offset and the size.
let [<Literal>] private ArchSize64 = 32

let private readFatArch (span: ByteSpan) (reader: IBinReader) offset =
  { CPUType = reader.ReadInt32(span, offset) |> LanguagePrimitives.EnumOfValue
    CPUSubType =
      reader.ReadInt32(span, offset + 4) |> LanguagePrimitives.EnumOfValue
    Offset = reader.ReadUInt32(span, offset + 8) |> uint64
    Size = reader.ReadUInt32(span, offset + 12) |> uint64
    Align = reader.ReadInt32(span, offset + 16) }

let private readFatArch64 (span: ByteSpan) (reader: IBinReader) offset =
  { CPUType = reader.ReadInt32(span, offset) |> LanguagePrimitives.EnumOfValue
    CPUSubType =
      reader.ReadInt32(span, offset + 4) |> LanguagePrimitives.EnumOfValue
    Offset = reader.ReadUInt64(span, offset + 8)
    Size = reader.ReadUInt64(span, offset + 16)
    Align = reader.ReadInt32(span, offset + 24) }

/// Returns the size of one entry of the architecture table, which the magic
/// tells apart. A FAT header is always big-endian, whichever host wrote it.
let private archSizeOf (bytes: byte[]) (reader: IBinReader) =
  let magic: Magic =
    reader.ReadUInt32(bytes, 0) |> LanguagePrimitives.EnumOfValue
  match magic with
  | Magic.FAT_MAGIC -> ArchSize
  | Magic.FAT_MAGIC_64 -> ArchSize64
  | _ -> raise InvalidFileFormatException

/// Parses the FAT binary header and returns an array of `FatArch` records.
let parseArchs (bytes: byte[]) =
  let reader = BinReader.Init Endian.Big
  let entrySize = archSizeOf bytes reader
  let nArch = reader.ReadInt32(bytes, 4)
  if nArch < 0 || 8 + entrySize * nArch > bytes.Length then
    raise InvalidFileFormatException
  else
    let span = ReadOnlySpan(bytes, 8, entrySize * nArch)
    let archs = Array.zeroCreate nArch
    for i = 0 to nArch - 1 do
      let offset = i * entrySize
      archs[i] <-
        if entrySize = ArchSize64 then readFatArch64 span reader offset
        else readFatArch span reader offset
    archs

let private matchingISA (isa: ISA) fatArch =
  let arch, wordSize =
    CPUType.toArchWordSizeTuple fatArch.CPUType fatArch.CPUSubType
  isa.Arch = arch && isa.WordSize = wordSize

/// Parses the FAT binary header and returns the `FatArch` record that matches
/// the given ISA.
let parseArch bytes isa =
  parseArchs bytes
  |> Array.tryFind (matchingISA isa)
  |> function Some arch -> arch | None -> raise InvalidISAException
