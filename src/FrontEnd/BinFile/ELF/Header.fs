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

namespace B2R2.FrontEnd.BinFile.ELF

open System
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.FileHelper

/// Represents the ELF header. This type corresponds to "struct ElfN_Ehdr" in
/// the ELF specification.
type Header = {
  /// 32-bit or 64-bit.
  Class: WordSize
  /// Little or big endian.
  Endian: Endian
  /// ELF version.
  Version: uint32
  /// OS ABI.
  OSABI: OSABI
  /// ABI version.
  OSABIVersion: uint32
  /// ELF file type (e_type).
  ELFType: ELFType
  /// Target instruction set architecture (e_machine).
  MachineType: MachineType
  /// Entry point address (e_entry).
  EntryPoint: uint64
  /// Program header table offset (e_phoff).
  PHdrTblOffset: uint64
  /// Section header table offset (e_shoff).
  SHdrTblOffset: uint64
  /// Processor-specific flags (e_flags).
  ELFFlags: uint32
  /// ELF header size (e_ehsize).
  HeaderSize: uint16
  /// Size of a program header table entry (e_phentsize).
  PHdrEntrySize: uint16
  /// Number of entries in the program header table (e_phnum).
  PHdrNum: uint16
  /// Size of a section header table entry (e_shentsize).
  SHdrEntrySize: uint16
  /// Number of entries in the section header table (e_shnum).
  SHdrNum: uint16
  /// Section header string table index (e_shstrndx).
  SHdrStrIdx: uint16
}

[<RequireQualifiedAccess>]
module internal Header =
  /// Checks if the file has a valid ELF header.
  let private isELF (span: ByteSpan) =
    let elfMagicNumber = [| 0x7fuy; 0x45uy; 0x4cuy; 0x46uy |]
    span.Length > 4
    && span.Slice(0, 4).SequenceEqual (ReadOnlySpan elfMagicNumber)

  let private getEndianness (span: ByteSpan) =
    match span[5] with
    | 0x1uy -> Endian.Little
    | 0x2uy -> Endian.Big
    | _ -> raise InvalidEndianException

  let private getClass (span: ByteSpan) =
    match span[4] with
    | 0x1uy -> WordSize.Bit32
    | 0x2uy -> WordSize.Bit64
    | _ -> raise InvalidWordSizeException

  let private getELFType (span: ByteSpan) (reader: IBinReader) =
    reader.ReadUInt16 (span, 16)
    |> LanguagePrimitives.EnumOfValue: ELFType

  let private computeNewBaseAddr etype baseAddr =
    match etype with
    | ELFType.ET_EXEC -> 0UL (* Non-PIEs must have zero base. *)
    | _ -> defaultArg baseAddr 0UL

  let private getELFMachineType (span: ByteSpan) (reader: IBinReader) =
    reader.ReadInt16 (span, 18)
    |> LanguagePrimitives.EnumOfValue: MachineType

  let private parseFromSpan span (reader: IBinReader) endian baseAddrOpt =
    let cls = getClass span
    let etype = getELFType span reader
    let baseAddr = computeNewBaseAddr etype baseAddrOpt
    let hdr =
      { Class = cls
        Endian = endian
        Version = reader.ReadUInt32 (span, 6)
        OSABI = span[7] |> LanguagePrimitives.EnumOfValue
        OSABIVersion = span[8] |> uint32
        ELFType = etype
        MachineType = getELFMachineType span reader
        EntryPoint = readUIntByWordSize span reader cls 24 + baseAddr
        PHdrTblOffset = readUIntByWordSizeAndOffset span reader cls 28 32
        SHdrTblOffset = readUIntByWordSizeAndOffset span reader cls 32 40
        ELFFlags = reader.ReadUInt32 (span, selectByWordSize cls 36 48)
        HeaderSize = reader.ReadUInt16 (span, selectByWordSize cls 40 52)
        PHdrEntrySize = reader.ReadUInt16 (span, selectByWordSize cls 42 54)
        PHdrNum = reader.ReadUInt16 (span, selectByWordSize cls 44 56)
        SHdrEntrySize = reader.ReadUInt16 (span, selectByWordSize cls 46 58)
        SHdrNum = reader.ReadUInt16 (span, selectByWordSize cls 48 60)
        SHdrStrIdx = reader.ReadUInt16 (span, selectByWordSize cls 50 62) }
    struct (hdr, baseAddr)

  let private getELFFlags span (reader: IBinReader) cls =
    reader.ReadUInt32 (span=span, offset=selectByWordSize cls 36 48)

  let private getMIPSISA span reader cls =
    match getELFFlags span reader cls &&& 0xf0000000u with
    | 0x00000000u
    | 0x10000000u
    | 0x20000000u
    | 0x30000000u
    | 0x40000000u
    | 0x50000000u
    | 0x70000000u
    | 0x90000000u -> ISA (Architecture.MIPS, reader.Endianness, WordSize.Bit32)
    | 0x60000000u
    | 0x80000000u
    | 0xa0000000u -> ISA (Architecture.MIPS, reader.Endianness, WordSize.Bit64)
    | c -> failwithf "invalid MIPS arch (%02x)" c

  let private toISA (span: ByteSpan) (reader: IBinReader) cls = function
    | MachineType.EM_386 -> ISA (Architecture.Intel, WordSize.Bit32)
    | MachineType.EM_X86_64 -> ISA (Architecture.Intel, WordSize.Bit64)
    | MachineType.EM_ARM ->
      ISA (Architecture.ARMv7, reader.Endianness, WordSize.Bit32)
    | MachineType.EM_AARCH64 ->
      ISA (Architecture.ARMv8, reader.Endianness, WordSize.Bit64)
    | MachineType.EM_MIPS
    | MachineType.EM_MIPS_RS3_LE -> getMIPSISA span reader cls
    | MachineType.EM_PPC ->
      ISA (Architecture.PPC, reader.Endianness, WordSize.Bit32)
    | MachineType.EM_PPC64 ->
      ISA (Architecture.PPC, reader.Endianness, WordSize.Bit64)
    | MachineType.EM_RISCV ->
      ISA (Architecture.RISCV, reader.Endianness, WordSize.Bit64)
    | MachineType.EM_SPARCV9 ->
      ISA (Architecture.SPARC, reader.Endianness, WordSize.Bit64)
    | MachineType.EM_S390 ->
      ISA (Architecture.S390, reader.Endianness, cls)
    | MachineType.EM_SH ->
      ISA (Architecture.SH4, reader.Endianness)
    | MachineType.EM_PARISC ->
      ISA (Architecture.PARISC, cls)
    | MachineType.EM_AVR ->
      ISA Architecture.AVR
    | _ -> raise InvalidISAException

  /// Parses the ELF header and return the parsed header information along with
  /// other data types to read the rest of the ELF file, such as BinReader, its
  /// base address, and the ISA.
  let parse baseAddrOpt (bytes: byte[]) =
    let span = ReadOnlySpan bytes
    if not <| isELF span then raise InvalidFileFormatException
    else
      let endian = getEndianness span
      let reader = BinReader.Init endian
      let struct (hdr, baseAddr) = parseFromSpan span reader endian baseAddrOpt
      let isa = toISA span reader hdr.Class hdr.MachineType
      struct (hdr, reader, baseAddr, isa)

  /// Checks if the file has a valid ELF header and returns the ISA if it does.
  let getISA (bytes: byte[]) =
    let span = ReadOnlySpan bytes
    if isELF span then
      let endian = getEndianness span
      let reader = BinReader.Init endian
      let cls = getClass span
      Ok (toISA span reader cls (getELFMachineType span reader))
    else Error ErrorCase.InvalidFormat
