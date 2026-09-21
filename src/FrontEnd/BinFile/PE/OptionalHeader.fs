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
/// Represents the optional header of a PE image, which says where the image
/// wants to be loaded and how it is to be run. An object file carries none,
/// which is what "optional" means of it.
/// </summary>
type internal OptionalHeader =
  { /// Which of the two forms of this header the image has.
    Magic: PEMagic
    /// The major version of the linker that built the image.
    MajorLinkerVersion: byte
    /// The minor version of that linker.
    MinorLinkerVersion: byte
    /// How many bytes of the image hold code.
    SizeOfCode: int
    /// How many bytes of it hold initialized data.
    SizeOfInitializedData: int
    /// How many bytes of it hold uninitialized data.
    SizeOfUninitializedData: int
    /// Where the image is entered, relative to the image base.
    AddressOfEntryPoint: int
    /// Where the code of the image begins, relative to the image base.
    BaseOfCode: int
    /// Where its data begins; a 64-bit image has no field for this.
    BaseOfData: int
    /// Where the image wants to be loaded.
    ImageBase: uint64
    /// What the address of a section is made a multiple of.
    SectionAlignment: int
    /// What the file offset of a section is made a multiple of.
    FileAlignment: int
    /// The major version of the operating system the image needs.
    MajorOperatingSystemVersion: uint16
    /// The minor version of that operating system.
    MinorOperatingSystemVersion: uint16
    /// The major version of the image itself.
    MajorImageVersion: uint16
    /// The minor version of the image itself.
    MinorImageVersion: uint16
    /// The major version of the subsystem the image needs.
    MajorSubsystemVersion: uint16
    /// The minor version of that subsystem.
    MinorSubsystemVersion: uint16
    /// How many bytes the image takes in memory once loaded.
    SizeOfImage: int
    /// How many bytes the headers take, rounded up to the file alignment.
    SizeOfHeaders: int
    /// The checksum of the image, which only a driver is checked on.
    CheckSum: uint32
    /// The subsystem the image is to be run under.
    Subsystem: Subsystem
    /// What a loader is to make of the image.
    DllCharacteristics: DllCharacteristics
    /// How many bytes of stack are set aside for the image.
    SizeOfStackReserve: uint64
    /// How many of them are committed up front.
    SizeOfStackCommit: uint64
    /// How many bytes of heap are set aside for the image.
    SizeOfHeapReserve: uint64
    /// How many of them are committed up front.
    SizeOfHeapCommit: uint64
    /// How many data directories the image means the header to end with.
    NumberOfRvaAndSizes: int
    /// The data directories themselves, of which there are always sixteen.
    Directories: DataDirectory[] }
with
  /// Returns the data directory naming the table of the given kind.
  member this.Directory(kind: DirectoryKind) = this.Directories[int kind]

[<RequireQualifiedAccess>]
module internal OptionalHeader =
  /// The number of bytes the optional header of a 32-bit image takes.
  let [<Literal>] PE32Size = 224

  /// The number of bytes the optional header of a 64-bit image takes.
  let [<Literal>] PE32PlusSize = 240

  /// Returns how many bytes the optional header of the given form takes,
  /// which is what the section header table follows it at. The field the COFF
  /// header has for this says the same of every image in use, and this is
  /// what a reader of one can go by where the two disagree.
  let sizeOf magic =
    if magic = PEMagic.PE32 then PE32Size else PE32PlusSize

  /// Returns where the data directories begin within the header.
  let private directoryOffset magic =
    if magic = PEMagic.PE32 then 96 else 112

  /// Returns where the image base sits, along with the fields that follow it
  /// up to the section alignment, the width of that one field moving them.
  let private readImageBase (span: ByteSpan) (reader: IBinReader) magic =
    if magic = PEMagic.PE32 then reader.ReadUInt32(span, 28) |> uint64
    else reader.ReadUInt64(span, 24)

  /// Returns the base of data, which a 64-bit image has no field for and
  /// which every reader of one takes as zero.
  let private readBaseOfData (span: ByteSpan) (reader: IBinReader) magic =
    if magic = PEMagic.PE32 then reader.ReadInt32(span, 24) else 0

  /// Returns one of the four sizes the header ends with. Each is a word of
  /// the image's own width, so which of them is meant says where it sits.
  let private readSize (span: ByteSpan) (reader: IBinReader) magic idx =
    if magic = PEMagic.PE32 then reader.ReadUInt32(span, 72 + idx * 4) |> uint64
    else reader.ReadUInt64(span, 72 + idx * 8)

  /// Returns how many data directories the header says it ends with.
  let private readDirectoryCount (span: ByteSpan) (reader: IBinReader) magic =
    reader.ReadInt32(span, if magic = PEMagic.PE32 then 92 else 108)

  /// Returns the data directories the header ends with. All sixteen of them
  /// are read: NumberOfRvaAndSizes says how many the image means a loader to
  /// follow, not how many the header has room for.
  let private readDirectories (span: ByteSpan) reader magic =
    let start = directoryOffset magic
    let entSize = DataDirectory.EntrySize
    let dirs = Array.zeroCreate DataDirectory.Count
    for i = 0 to DataDirectory.Count - 1 do
      dirs[i] <- DataDirectory.read span reader (start + i * entSize)
    dirs

  let private read (span: ByteSpan) (reader: IBinReader) magic =
    { Magic = magic
      MajorLinkerVersion = span[2]
      MinorLinkerVersion = span[3]
      SizeOfCode = reader.ReadInt32(span, 4)
      SizeOfInitializedData = reader.ReadInt32(span, 8)
      SizeOfUninitializedData = reader.ReadInt32(span, 12)
      AddressOfEntryPoint = reader.ReadInt32(span, 16)
      BaseOfCode = reader.ReadInt32(span, 20)
      BaseOfData = readBaseOfData span reader magic
      ImageBase = readImageBase span reader magic
      SectionAlignment = reader.ReadInt32(span, 32)
      FileAlignment = reader.ReadInt32(span, 36)
      MajorOperatingSystemVersion = reader.ReadUInt16(span, 40)
      MinorOperatingSystemVersion = reader.ReadUInt16(span, 42)
      MajorImageVersion = reader.ReadUInt16(span, 44)
      MinorImageVersion = reader.ReadUInt16(span, 46)
      MajorSubsystemVersion = reader.ReadUInt16(span, 48)
      MinorSubsystemVersion = reader.ReadUInt16(span, 50)
      SizeOfImage = reader.ReadInt32(span, 56)
      SizeOfHeaders = reader.ReadInt32(span, 60)
      CheckSum = reader.ReadUInt32(span, 64)
      Subsystem = reader.ReadUInt16(span, 68) |> LanguagePrimitives.EnumOfValue
      DllCharacteristics =
        reader.ReadUInt16(span, 70) |> LanguagePrimitives.EnumOfValue
      SizeOfStackReserve = readSize span reader magic 0
      SizeOfStackCommit = readSize span reader magic 1
      SizeOfHeapReserve = readSize span reader magic 2
      SizeOfHeapCommit = readSize span reader magic 3
      NumberOfRvaAndSizes = readDirectoryCount span reader magic
      Directories = readDirectories span reader magic }

  /// Returns whether the file has room at the given offset for that many
  /// bytes of header.
  let private fits (bytes: byte[]) offset size =
    offset >= 0 && int64 offset + int64 size <= int64 bytes.Length

  /// Returns which of the two forms the header at the given offset has.
  let private readMagic (bytes: byte[]) (reader: IBinReader) offset =
    if not (fits bytes offset 2) then
      raise InvalidFileFormatException
    else
      match reader.ReadUInt16(ReadOnlySpan(bytes, offset, 2), 0) with
      | 0x10bus -> PEMagic.PE32
      | 0x20bus -> PEMagic.PE32Plus
      | _ -> raise InvalidFileFormatException

  /// Returns the optional header the given offset of the file holds.
  let parse (bytes: byte[]) reader offset =
    let magic = readMagic bytes reader offset
    let size = sizeOf magic
    if not (fits bytes offset size) then
      raise InvalidFileFormatException
    else
      read (ReadOnlySpan(bytes, offset, size)) reader magic
