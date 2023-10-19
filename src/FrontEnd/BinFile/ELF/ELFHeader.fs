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
open System.IO
open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.FileHelper

/// File type.
type ELFFileType =
  /// No file type.
  | ET_NONE = 0x0us
  /// Relocatable file.
  | ET_REL = 0x1us
  /// Executable file.
  | ET_EXEC = 0x2us
  /// Shared object file.
  | ET_DYN = 0x3us
  /// Core file.
  | ET_CORE = 0x4us

module ELFFileType =
  let toString = function
    | ELFFileType.ET_REL -> "Relocatable"
    | ELFFileType.ET_EXEC -> "Executable"
    | ELFFileType.ET_DYN -> "Shared Object"
    | ELFFileType.ET_CORE -> "Core"
    | _ -> "Unknown"

/// ABI type.
type OSABI =
  /// UNIX System V ABI.
  | ELFOSABI_SYSV = 0uy
  /// HP-UX ABI.
  | ELFOSABI_HPUX = 1uy
  /// NetBSD ABI.
  | ELFOSABI_NETBSD = 2uy
  /// Linux ABI.
  | ELFOSABI_GNU = 3uy
  /// Linux ABI.
  | ELFOSABI_LINUX = 3uy
  /// Solaris ABI.
  | ELFOSABI_SOLARIS = 6uy
  /// IBM AIX ABI.
  | ELFOSABI_AIX = 7uy
  /// SGI Irix ABI.
  | ELFOSABI_IRIX = 8uy
  /// FreeBSD ABI.
  | ELFOSABI_FREEBSD = 9uy
  /// Compaq TRU64 UNIX ABI.
  | ELFOSABI_TRU64 = 10uy
  /// Novell Modesto ABI.
  | ELFOSABI_MODESTO = 11uy
  /// OpenBSD ABI.
  | ELFOSABI_OPENBSD = 12uy
  /// ARM EABI.
  | ELFOSABI_ARM_AEABI = 64uy
  /// ARM.
  | ELFOSABI_ARM = 97uy
  /// Standalone (embedded) application.
  | ELFOSABI_STANDALONE = 255uy

module OSABI =
  let toString = function
    | OSABI.ELFOSABI_SYSV -> "UNIX System V"
    | OSABI.ELFOSABI_HPUX -> "HP-UX"
    | OSABI.ELFOSABI_NETBSD -> "NetBSD"
    | OSABI.ELFOSABI_GNU | OSABI.ELFOSABI_LINUX -> "Linux"
    | OSABI.ELFOSABI_SOLARIS -> "Solaris"
    | OSABI.ELFOSABI_AIX -> "AIX"
    | OSABI.ELFOSABI_IRIX -> "IRIX"
    | OSABI.ELFOSABI_FREEBSD -> "FreeBSD"
    | OSABI.ELFOSABI_TRU64 -> "TRU64"
    | OSABI.ELFOSABI_MODESTO -> "Modesto"
    | OSABI.ELFOSABI_OPENBSD -> "OpenBSD"
    | OSABI.ELFOSABI_ARM_AEABI -> "ARM EABI"
    | OSABI.ELFOSABI_ARM -> "ARM"
    | OSABI.ELFOSABI_STANDALONE -> "Standalone"
    | _ -> "Unknown"

/// ELF header.
type ELFHeader = {
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
  ELFFileType: ELFFileType
  /// Target instruction set architecture (e_machine).
  MachineType: Architecture
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

/// This is a basic toolbox for parsing ELF, which is returned from parsing an
/// ELF header.
type ELFToolbox = {
  Stream: Stream
  Reader: IBinReader
  BaseAddress: Addr
  Header: ELFHeader
}

module internal Header =
  /// Check if the file has a valid ELF header.
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

  let private getELFFileType (span: ByteSpan) (reader: IBinReader) =
    reader.ReadUInt16 (span, 16)
    |> LanguagePrimitives.EnumOfValue: ELFFileType

  let private computeNewBaseAddr ftype baseAddr =
    match ftype with
    | ELFFileType.ET_EXEC -> 0UL (* Non-PIEs must have zero base. *)
    | _ -> defaultArg baseAddr 0UL

  let private getELFFlags span (reader: IBinReader) cls =
    reader.ReadUInt32 (span=span, offset=pickNum cls 36 48)

  let private getMIPSArch span reader cls =
    match getELFFlags span reader cls &&& 0xf0000000u with
    | 0x00000000u
    | 0x10000000u
    | 0x20000000u
    | 0x30000000u
    | 0x40000000u
    | 0x50000000u
    | 0x70000000u
    | 0x90000000u -> Arch.MIPS32
    | 0x60000000u
    | 0x80000000u
    | 0xa0000000u -> Arch.MIPS64
    | c -> failwithf "invalid MIPS arch (%02x)" c

  let private getArch (span: ByteSpan) (reader: IBinReader) cls =
    match reader.ReadInt16 (span, 18) with
    | 0x03s -> Arch.IntelX86
    | 0x3es -> Arch.IntelX64
    | 0x28s -> Arch.ARMv7
    | 0xb7s -> Arch.AARCH64
    | 0x08s | 0x0as -> getMIPSArch span reader cls
    | 0x53s -> Arch.AVR
    | 0x2as -> Arch.SH4
    | 0x14s -> Arch.PPC32
    | 0x2bs -> Arch.SPARC
    | 0xf3s -> Arch.RISCV64 (* FIXME: RISCV *)
    | _ -> Arch.UnknownISA

  let parseFromSpan span (reader: IBinReader) endian baseAddrOpt =
    let cls = getClass span
    let ftype = getELFFileType span reader
    let baseAddr = computeNewBaseAddr ftype baseAddrOpt
    let hdr =
      { Class = cls
        Endian = endian
        Version = reader.ReadUInt32 (span, 6)
        OSABI = span[7] |> LanguagePrimitives.EnumOfValue
        OSABIVersion = span[8] |> uint32
        ELFFileType = ftype
        MachineType = getArch span reader cls
        EntryPoint = readNative span reader cls 24 24 + baseAddr
        PHdrTblOffset = readNative span reader cls 28 32
        SHdrTblOffset = readNative span reader cls 32 40
        ELFFlags = reader.ReadUInt32 (span, pickNum cls 36 48)
        HeaderSize = reader.ReadUInt16 (span, pickNum cls 40 52)
        PHdrEntrySize = reader.ReadUInt16 (span, pickNum cls 42 54)
        PHdrNum = reader.ReadUInt16 (span, pickNum cls 44 56)
        SHdrEntrySize = reader.ReadUInt16 (span, pickNum cls 46 58)
        SHdrNum = reader.ReadUInt16 (span, pickNum cls 48 60)
        SHdrStrIdx = reader.ReadUInt16 (span, pickNum cls 50 62) }
    struct (hdr, baseAddr)

  /// Parse the ELF header and return a toolbox, which includes ELF header,
  /// preferred base address, and IBinReader.
  let parse baseAddrOpt (stream: Stream) =
    let buf = readChunk stream 0UL 64 (* ELF header is maximum 64-byte long. *)
    let span = ReadOnlySpan buf
    if not <| isELF span then raise InvalidFileFormatException
    else
      let endian = getEndianness span
      let reader = BinReader.Init endian
      let struct (hdr, baseAddr) = parseFromSpan span reader endian baseAddrOpt
      { Stream = stream
        Reader = reader
        BaseAddress = baseAddr
        Header = hdr }

  /// Check if the file has a valid ELF header, and return an ISA.
  let getISA (span: ByteSpan) =
    if isELF span then
      let endian = getEndianness span
      let reader = BinReader.Init endian
      let cls = getClass span
      let arch = getArch span reader cls
      Ok (ISA.Init arch endian)
    else Error ErrorCase.InvalidFileFormat