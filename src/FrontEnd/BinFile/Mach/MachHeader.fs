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
open B2R2.FrontEnd.BinFile

/// Usage of the file.
type MachFileType =
  /// Intermediate object files.
  | MH_OBJECT = 0x1
  /// Standard executable programs.
  | MH_EXECUTE = 0x2
  /// Fixed VM shared library file.
  | MH_FVMLIB = 0x3
  /// Core file.
  | MH_CORE = 0x4
  /// Preloaded executable file.
  | MH_PRELOAD = 0x5
  /// Dynamically bound shared library file.
  | MH_DYLIB = 0x6
  /// Dynamically bound shared library file.
  | MH_DYLINKER = 0x7
  /// Dynamically bound bundle file.
  | MH_BUNDLE = 0x8
  /// Shared library stub for static linking only, no section contents.
  | MH_DYLIB_STUB = 0x9
  /// Companion file with only debug sections.
  | MH_DSYM = 0xa
  /// x86_64 kexts.
  | MH_KEXT_BUNDLE = 0xb

/// Attribute of the file.
[<FlagsAttribute>]
type MachFlag =
  /// The object file has no undefined references.
  | MH_NOUNDEFS = 0x1
  /// The object file is the output of an incremental link against a base file
  /// and can't be linked against a base file and can't be link edited again.
  | MH_INCRLINK = 0x2
  /// The object file is input for the dynamic linker and can't be statically
  /// link edited again.
  | MH_DYLDLINK = 0x4
  /// The object file's undefined references are bound by the dynamic linker
  /// when loaded.
  | MH_BINDATLOAD = 0x8
  /// The file has its dynamic undefined references prebound.
  | MH_PREBOUND = 0x10
  /// The file has its read-only and read-write segments split.
  | MH_SPLIT_SEGS = 0x20
  /// the shared library init routine is to be run lazily via catching memory
  /// faults to its writeable segments (obsolete).
  | MH_LAZY_INIT = 0x40
  /// The image is using two-level name space bindings.
  | MH_TWOLEVEL = 0x80
  /// The executable is forcing all images to use flat name space bindings.
  | MH_FORCE_FLAT = 0x100
  /// This umbrella guarantees no multiple defintions of symbols in its
  /// sub-images so the two-level namespace hints can always be used.
  | MH_NOMULTIDEFS = 0x200
  /// Do not have dyld notify the prebinding agent about this executable.
  | MH_NOFIXPREBINDING = 0x400
  /// the binary is not prebound but can have its prebinding redone. only used
  /// when MH_PREBOUND is not set.
  | MH_PREBINDABLE = 0x800
  /// Indicates that this binary binds to all two-level namespace modules of
  /// its dependent libraries. only used when MH_PREBINDABLE and MH_TWOLEVEL
  /// are both set.
  | MH_ALLMODSBOUND = 0x1000
  /// Safe to divide up the sections into sub-sections via symbols for dead code
  /// stripping.
  | MH_SUBSECTIONS_VIA_SYMBOLS = 0x2000
  /// The binary has been canonicalized via the unprebind operation.
  | MH_CANONICAL = 0x4000
  /// The final linked image contains external weak symbols.
  | MH_WEAK_DEFINES = 0x8000
  /// The final linked image uses weak symbols.
  | MH_BINDS_TO_WEAK = 0x10000
  /// When this bit is set, all stacks in the task will be given stack execution
  /// privilege. Only used in MH_EXECUTE filetypes.
  | MH_ALLOW_STACK_EXECUTION = 0x20000
  /// When this bit is set, the binary declares it is safe for use in processes
  /// with uid zero.
  | MH_ROOT_SAFE = 0x40000
  /// When this bit is set, the binary declares it is safe for use in processes
  /// when issetugid() is true.
  | MH_SETUID_SAFE = 0x80000
  /// When this bit is set on a dylib, the static linker does not need to
  /// examine dependent dylibs to see if any are re-exported.
  | MH_NO_REEXPORTED_DYLIBS = 0x100000
  /// When this bit is set, the OS will load the main executable at a random
  /// address.
  | MH_PIE = 0x200000
  /// Only for use on dylibs.  When linking against a dylib that has this bit
  /// set, the static linker will automatically not create a LC_LOAD_DYLIB load
  /// command to the dylib if no symbols are being referenced from the dylib.
  | MH_DEAD_STRIPPABLE_DYLIB = 0x400000
  /// Contains a section of type ThreadLocalVariables.
  | MH_HAS_TLV_DESCRIPTORS = 0x800000
  /// When this bit is set, the OS will run the main executable with a
  /// non-executable heap even on platforms (e.g. i386) that don't require it.
  /// Only used in MH_EXECUTE filetypes.
  | MH_NO_HEAP_EXECUTION = 0x1000000
  /// The code was linked for use in an application extension.
  | MH_APP_EXTENSION_SAFE = 0x02000000

/// Mach-O file format header.
type MachHeader = {
  /// Magic number.
  Magic: Magic
  /// Word size.
  Class: WordSize
  /// CPU type.
  CPUType: CPUType
  /// CPU subtype.
  CPUSubType: CPUSubType
  /// File type.
  FileType: MachFileType
  /// The number of load commands.
  NumCmds: uint32
  /// The number of bytes occupied by the load commands following the header
  /// structure.
  SizeOfCmds: uint32
  /// A set of bit flags indicating the state of certain optional features of
  /// the Mach-O file format.
  Flags: MachFlag
}

/// This is a basic toolbox for parsing Mach-O binaries, which is returned from
/// parsing a Mach-O header.
type MachToolbox = {
  Bytes: byte[]
  Reader: IBinReader
  BaseAddress: Addr
  Header: MachHeader
  /// Offset from the start of the file to the Mach-O file format header. This
  /// is only meaningful for universal binaries.
  MachOffset: uint64
}

module Header =
  let isMach (bytes: byte[]) offset =
    let span = ReadOnlySpan (bytes, int offset, 4)
    let reader = BinReader.Init Endian.Little
    match Magic.read span reader with
    | Magic.MH_CIGAM | Magic.MH_CIGAM_64
    | Magic.MH_MAGIC | Magic.MH_MAGIC_64
    | Magic.FAT_CIGAM | Magic.FAT_MAGIC -> true
    | _ -> false

  let isFat (bytes: byte[]) =
    let reader = BinReader.Init Endian.Little
    match Magic.read (ReadOnlySpan bytes) reader with
    | Magic.FAT_CIGAM | Magic.FAT_MAGIC -> true
    | _ -> false

  let inline private readCPUType (span: ByteSpan) (reader: IBinReader) =
    reader.ReadInt32 (span, 4) |> LanguagePrimitives.EnumOfValue

  let inline private readCPUSubType (span: ByteSpan) (reader: IBinReader) =
    reader.ReadInt32 (span, 8) |> LanguagePrimitives.EnumOfValue

  let inline private readFileType (span: ByteSpan) (reader: IBinReader) =
    reader.ReadInt32 (span, 12) |> LanguagePrimitives.EnumOfValue

  let inline private readFlags (span: ByteSpan) (reader: IBinReader) =
    reader.ReadInt32 (span, 24) |> LanguagePrimitives.EnumOfValue

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
    let headerSpan = ReadOnlySpan (bytes, int offset, 28)
    let reader = getMachBinReader headerSpan
    { Magic = Magic.read headerSpan reader
      Class = readClass headerSpan reader
      CPUType = readCPUType headerSpan reader
      CPUSubType = readCPUSubType headerSpan reader
      FileType = readFileType headerSpan reader
      NumCmds = reader.ReadUInt32 (headerSpan, 16)
      SizeOfCmds = reader.ReadUInt32 (headerSpan, 20)
      Flags = readFlags headerSpan reader }

  let private computeMachOffset bytes isa =
    if isFat bytes then
      let fatArch = Fat.loadArch bytes isa
      uint64 fatArch.Offset
    else 0UL

  let private computeBaseAddr machHdr baseAddr =
    if machHdr.Flags.HasFlag MachFlag.MH_PIE then defaultArg baseAddr 0UL
    else 0UL

  /// Parse the Mach-O file format header, and return a MachToolbox.
  let parse bytes baseAddrOpt isa =
    let offset = computeMachOffset bytes isa
    if isMach bytes offset then
      let hdr = parseHeader bytes offset
      let baseAddr = computeBaseAddr hdr baseAddrOpt
      { Bytes = bytes
        Reader = BinReader.Init (magicToEndian hdr.Magic)
        BaseAddress = baseAddr
        Header = hdr
        MachOffset = offset }
    else raise InvalidFileFormatException
