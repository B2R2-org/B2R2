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

namespace B2R2.FrontEnd.BinFile.Mach

open System
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile

/// Represents the header of Mach-O file format.
type Header =
  { /// Magic number.
    Magic: Magic
    /// Word size.
    Class: WordSize
    /// CPU type.
    CPUType: CPUType
    /// CPU subtype.
    CPUSubType: CPUSubType
    /// File type.
    FileType: FileType
    /// The number of load commands.
    NumCmds: uint32
    /// The number of bytes occupied by the load commands following the header
    /// structure.
    SizeOfCmds: uint32
    /// A set of bit flags indicating the state of certain optional features of
    /// the Mach-O file format.
    Flags: MachFlag }
with
  /// Checks if the given bytes represent a valid Mach-O FAT file format.
  static member IsFat(bytes: byte[]) =
    let reader = BinReader.Init Endian.Little
    match Magic.read (ReadOnlySpan bytes) reader with
    | Magic.FAT_CIGAM | Magic.FAT_MAGIC -> true
    | _ -> false

[<RequireQualifiedAccess>]
module internal Header =
  let isMach (bytes: byte[]) offset =
    let span = ReadOnlySpan(bytes, int offset, 4)
    let reader = BinReader.Init Endian.Little
    match Magic.read span reader with
    | Magic.MH_CIGAM | Magic.MH_CIGAM_64
    | Magic.MH_MAGIC | Magic.MH_MAGIC_64
    | Magic.FAT_CIGAM | Magic.FAT_MAGIC -> true
    | _ -> false

  let inline private readCPUType (span: ByteSpan) (reader: IBinReader) =
    reader.ReadInt32(span, 4) |> LanguagePrimitives.EnumOfValue

  let inline private readCPUSubType (span: ByteSpan) (reader: IBinReader) =
    reader.ReadInt32(span, 8) |> LanguagePrimitives.EnumOfValue

  let inline private readFileType (span: ByteSpan) (reader: IBinReader) =
    reader.ReadInt32(span, 12) |> LanguagePrimitives.EnumOfValue

  let inline private readFlags (span: ByteSpan) (reader: IBinReader) =
    reader.ReadInt32(span, 24) |> LanguagePrimitives.EnumOfValue

  let private readClass span reader =
    match Magic.read span reader with
    | Magic.MH_MAGIC | Magic.MH_CIGAM -> WordSize.Bit32
    | Magic.MH_MAGIC_64 | Magic.MH_CIGAM_64 -> WordSize.Bit64
    | _ -> raise InvalidFileFormatException

  let magicToEndian = function
    | Magic.MH_MAGIC | Magic.MH_MAGIC_64 | Magic.FAT_MAGIC -> Endian.Little
    | Magic.MH_CIGAM | Magic.MH_CIGAM_64 | Magic.FAT_CIGAM -> Endian.Big
    | _ -> raise InvalidFileFormatException

  let readEndianness span reader =
    Magic.read span reader
    |> magicToEndian

  /// Detect the endianness and return an appropriate IBinReader.
  let private getMachBinReader span =
    let reader = BinReader.Init Endian.Little
    let endian = readEndianness span reader
    BinReader.Init endian

  let private parseHeader bytes offset =
    let headerSpan = ReadOnlySpan(bytes, int offset, 28)
    let reader = getMachBinReader headerSpan
    { Magic = Magic.read headerSpan reader
      Class = readClass headerSpan reader
      CPUType = readCPUType headerSpan reader
      CPUSubType = readCPUSubType headerSpan reader
      FileType = readFileType headerSpan reader
      NumCmds = reader.ReadUInt32(headerSpan, 16)
      SizeOfCmds = reader.ReadUInt32(headerSpan, 20)
      Flags = readFlags headerSpan reader }

  let private computeMachOffset bytes isa =
    if Header.IsFat bytes then
      let fatArch = Fat.parseArch bytes isa
      uint64 fatArch.Offset
    else 0UL

  let private computeBaseAddr machHdr baseAddr =
    if machHdr.Flags.HasFlag MachFlag.MH_PIE then defaultArg baseAddr 0UL
    else 0UL

  let private toISA hdr =
    let cputype = hdr.CPUType
    let cpusubtype = hdr.CPUSubType
    let arch, wordSize = CPUType.toArchWordSizeTuple cputype cpusubtype
    let endian = magicToEndian hdr.Magic
    ISA(arch, endian, wordSize)

  /// Parse the Mach-O file format header, and return a Toolbox.
  let parse bytes baseAddrOpt isa =
    let offset = computeMachOffset bytes isa
    if isMach bytes offset then
      let hdr = parseHeader bytes offset
      let baseAddr = computeBaseAddr hdr baseAddrOpt
      let reader = BinReader.Init(magicToEndian hdr.Magic)
      let isa = toISA hdr
      struct (hdr, reader, baseAddr, offset, isa)
    else raise InvalidFileFormatException

  /// Checks if the file has a valid Mach-O header and returns the ISA if it
  /// does.
  let getISA bytes isa =
    let offset = computeMachOffset bytes isa
    if isMach bytes offset then
      let hdr = parseHeader bytes offset
      Ok(toISA hdr)
    else Error ErrorCase.InvalidFormat
