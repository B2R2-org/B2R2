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
open B2R2.FrontEnd.BinFile.FileHelper

/// Load command type.
type LoadCmdType =
  /// Defines a segment of this file to be mapped into the address space of the
  /// process that loads this file. It also includes all the sections contained
  /// by the segment.
  | LC_SEGMENT = 0x01
  /// The symbol table for this file.
  | LC_SYMTAB = 0x02
  /// The gdb symbol table info (obsolete).
  | LC_SYMSEG = 0x03
  /// This command defines the initial thread state of the main thread of the
  /// process. LC_THREAD is similar to LC_UNIXTHREAD but does not cause the kernel
  /// to allocate a stack.
  | LC_THREAD = 0x04
  /// This command defines the initial thread state of the main thread of the
  /// process.
  | LC_UNIXTHREAD = 0x05
  /// Load a specified fixed VM shared library.
  | LC_LOADFVMLIB = 0x06
  /// Fixed VM shared library identification.
  | LC_IDFVMLIB = 0x07
  /// Object identification info (obsolete).
  | LC_IDENT = 0x08
  /// Fixed VM file inclusion (internal use).
  | LC_FVMFILE = 0x09
  /// Prepage command (internal use).
  | LC_PREPAGE = 0x0A
  /// Dynamic link-edit symbol table info.
  | LC_DYSYMTAB = 0x0B
  /// Load a dynamically linked shared library.
  | LC_LOAD_DYLIB = 0x0C
  /// This command Specifies the install name of a dynamic shared library.
  | LC_ID_DYLIB = 0x0D
  /// Load a dynamic linker.
  | LC_LOAD_DYLINKER = 0x0E
  /// Dynamic linker identification.
  | LC_ID_DYLINKER = 0x0F
  /// Modules prebound for a dynamically linked shared library.
  | LC_PREBOUND_DYLIB = 0x10
  /// Image routines.
  | LC_ROUTINES = 0x11
  /// Sub framework.
  | LC_SUB_FRAMEWORK = 0x12
  /// Sub umbrella.
  | LC_SUB_UMBRELLA = 0x13
  /// Sub client.
  | LC_SUB_CLIENT = 0x14
  /// Sub library.
  | LC_SUB_LIBRARY = 0x15
  /// Two-level namespace lookup hints
  | LC_TWOLEVEL_HINTS = 0x16
  /// Prebind checksum.
  | LC_PREBIND_CKSUM = 0x17
  /// Load a dynamically linked shared library that is allowed to be missing.
  | LC_LOAD_WEAK_DYLIB = 0x80000018
  /// 64-bit segment of this file to be mapped.
  | LC_SEGMENT64 = 0x19
  /// 64-bit image routines.
  | LC_ROUTINES64 = 0x1A
  /// The uuid.
  | LC_UUID = 0x1B
  /// Runpath additions.
  | LC_RPATH = 0x8000001C
  /// Local of code signature.
  | LC_CODE_SIGNATURE = 0x1D
  /// Local of info to split segments
  | LC_SEGMENT_SPLIT_INFO = 0x1E
  /// Load and re-export dylib.
  | LC_REEXPORT_DYLIB = 0x8000001F
  /// Delay load of dylib until first use.
  | LC_LAZY_LOAD_DYLIB = 0x20
  /// Encrypted segment information.
  | LC_ENCRYPTION_INFO = 0x21
  /// Compressed dyld information.
  | LC_DYLD_INFO = 0x22
  /// Compressed dyld information only.
  | LC_DYLD_INFO_ONLY = 0x80000022
  /// Load upward dylib.
  | LC_LOAD_UPWARD_DYLIB = 0x80000023
  /// Build for MacOSX min OS version.
  | LC_VERSION_MIN_MACOSX = 0x24
  /// Build for iPhoneOS min OS version.
  | LC_VERSION_MIN_IPHONEOS = 0x25
  /// Compressed table of function start addresses.
  | LC_FUNCTION_STARTS = 0x26
  /// String for dyld to treat like environment variable.
  | LC_DYLD_ENVIRONMENT = 0x27
  /// Replacement for LC_UNIXTHREAD.
  | LC_MAIN = 0x80000028
  /// Table of non-instructions in __text.
  | LC_DATA_IN_CODE = 0x29
  /// Source version used to build binary.
  | LC_SOURCE_VERSION = 0x2A
  /// Code signing DRs copied from linked dylibs.
  | LC_DYLIB_CODE_SIGN_DRS = 0x2B
  /// 64-bit encrypted segment information.
  | LC_ENCRYPTION_INFO_64 = 0x2C
  /// Linker options in MH_OBJECT files.
  | LC_LINKER_OPTION = 0x2D
  /// Optimization hints in MH_OBJECT files.
  | LC_LINKER_OPTIMIZATION_HINT = 0x2E
  /// Build for AppleTV min OS version.
  | LC_VERSION_MIN_TVOS = 0x2F
  /// Build for Watch min OS version
  | LC_VERSION_MIN_WATCHOS = 0x30

/// The load command structures are located directly after the header of the
/// object file, and they specify both the logical structure of the file and the
/// layout of the file in virtual memory.
type LoadCommand =
  | Segment of SegCmd
  | SymTab of SymTabCmd
  | DySymTab of DySymTabCmd
  | DyLib of DyLibCmd
  | DyLdInfo of DyLdInfoCmd
  | FuncStarts of FuncStartsCmd
  | Main of MainCmd
  | Unhandled of UnhandledCommand

/// Segment command.
and SegCmd = {
  Cmd: LoadCmdType
  CmdSize: uint32
  /// The offset of the sections in the segment. If the segment has sections
  /// then the section structures directly follow the segment command and their
  /// size is in the size of the command.
  SecOff: int
  /// Segment name.
  SegCmdName: string
  /// The starting virtual memory address of this segment
  VMAddr: Addr
  /// The number of bytes of virtual memory occupied by this segment.
  VMSize: uint64
  /// The offset in this file of the data to be mapped at VMAddr.
  FileOff: Addr
  /// The number of bytes occupied by this segment on disk
  FileSize: uint64
  /// The maximum permitted virtual memory protections of this segment
  MaxProt: int
  /// The initial virtual memory protections of this segment.
  InitProt: int
  /// The number of section data structures following this load command.
  NumSecs: uint32
  /// A set of flags that affect the loading of this segment.
  SegFlag: uint32
}

/// Symbol table command.
and SymTabCmd = {
  Cmd: LoadCmdType
  CmdSize: uint32
  /// An integer containing the byte offset from the start of the file to the
  /// location of the symbol table entries.
  SymOff: int
  /// An integer indicating the number of entries in the symbol table.
  NumOfSym: uint32
  /// An integer containing the byte offset from the start of the image to the
  /// location of the string table.
  StrOff: int
  /// An integer indicating the size (in bytes) of the string table.
  StrSize: uint32
}

/// Dynamic symbol table command.
and DySymTabCmd = {
  Cmd: LoadCmdType
  CmdSize: uint32
  /// An integer indicating the index of the first symbol in the group of local
  /// symbols.
  IdxLocalSym: uint32
  /// An integer indicating the total number of symbols in the group of local
  /// symbols.
  NumLocalSym: uint32
  /// An integer indicating the index of the first symbol in the group of
  /// defined external symbols.
  IdxExtSym: uint32
  /// An integer indicating the total number of symbols in the group of defined
  /// external symbols.
  NumExtSym: uint32
  /// An integer indicating the index of the first symbol in the group of
  /// undefined external symbols.
  IdxUndefSym: uint32
  /// An integer indicating the total number of symbols in the group of
  /// undefined external symbols.
  NumUndefSym: uint32
  /// An integer indicating the byte offset from the start of the file to the
  /// table of contents data.
  TOCOffset: uint32
  /// An integer indicating the number of entries in the table of contents.
  NumTOCContents: uint32
  /// An integer indicating the byte offset from the start of the file to the
  /// module table data.
  ModTabOff: uint32
  /// An integer indicating the number of entries in the module table.
  NumModTab: uint32
  /// An integer indicating the byte offset from the start of the file to the
  /// external reference table data.
  ExtRefSymOff: uint32
  /// An integer indicating the number of entries in the external reference
  /// table.
  NumExtRefSym: uint32
  /// An integer indicating the byte offset from the start of the file to the
  /// indirect symbol table data.
  IndirectSymOff: uint32
  /// An integer indicating the number of entries in the indirect symbol table.
  NumIndirectSym: uint32
  /// An integer indicating the byte offset from the start of the file to the
  /// external relocation table data.
  ExtRelOff: uint32
  /// An integer indicating the number of entries in the external relocation
  /// table.
  NumExtRel: uint32
  /// An integer indicating the byte offset from the start of the file to the
  /// local relocation table data.
  LocalRelOff: uint32
  /// An integer indicating the number of entries in the local relocation table.
  NumLocalRel: uint32
}

/// DYLD information command (dyld_info_command).
and DyLdInfoCmd = {
  Cmd: LoadCmdType
  CmdSize: uint32
  /// File offset to rebase info.
  RebaseOff: int
  /// The size of rebase info.
  RebaseSize: uint32
  /// File offset to binding info
  BindOff: int
  /// The size of binding info.
  BindSize: uint32
  /// File offset to weak binding info.
  WeakBindOff: int
  /// The size of weak binding info.
  WeakBindSize: uint32
  /// File offset to lazy binding info.
  LazyBindOff: int
  /// The size of lazy binding info.
  LazyBindSize: uint32
  /// File offset to export info.
  ExportOff: int
  /// The size of export info.
  ExportSize: uint32
}

/// Function starts command (LC_FUNCTION_STARTS).
and FuncStartsCmd = {
  Cmd: LoadCmdType
  CmdSize: uint32
  DataOffset: int
  DataSize: uint32
}

/// Main command.
and MainCmd = {
  Cmd: LoadCmdType
  CmdSize: uint32
  /// Offset of main().
  EntryOff: Addr
  /// Initial stack size, if not zero.
  StackSize: uint64
}

/// Dynamic library command: the data used by the dynamic linker to match a
/// shared library against the files that have linked to it.
and DyLibCmd = {
  Cmd: LoadCmdType
  CmdSize: uint32
  /// Library's path name.
  DyLibName: string
  /// Library's build time stamp.
  DyLibTimeStamp: uint32
  /// Library's current version number.
  DyLibCurVer: uint32
  /// Library's compatibility vers number.
  DyLibCmpVer: uint32
}

/// This type represents a load command unhandled by B2R2.
and UnhandledCommand = {
  Cmd: LoadCmdType
  CmdSize: uint32
}

module internal LoadCommand =
  let [<Literal>] TextSegName = "__TEXT"

  let parseSegCmd toolBox cmdOffset cmdType cmdSize span =
    let reader = toolBox.Reader
    let cls = toolBox.Header.Class
    { Cmd = cmdType
      CmdSize = uint32 cmdSize
      SecOff = cmdOffset + pickNum cls 56 72
      SegCmdName = readCString span 8
      VMAddr = readNative span reader cls 24 24 + toolBox.BaseAddress
      VMSize = readNative span reader cls 28 32
      FileOff = readNative span reader cls 32 40
      FileSize = readNative span reader cls 36 48
      MaxProt = reader.ReadInt32 (span, pickNum cls 40 56)
      InitProt = reader.ReadInt32 (span, pickNum cls 44 60)
      NumSecs = reader.ReadUInt32 (span, pickNum cls 48 64)
      SegFlag = reader.ReadUInt32 (span, pickNum cls 52 68) }

  let parseSymCmd toolBox cmdType cmdSize (span: ByteSpan) =
    let reader = toolBox.Reader
    { Cmd = cmdType
      CmdSize = uint32 cmdSize
      SymOff = reader.ReadInt32 (span, 8)
      NumOfSym = reader.ReadUInt32 (span, 12)
      StrOff = reader.ReadInt32 (span, 16)
      StrSize = reader.ReadUInt32 (span, 20) }

  let parseDySymCmd toolBox cmdType cmdSize (span: ByteSpan) =
    let reader = toolBox.Reader
    { Cmd = cmdType
      CmdSize = uint32 cmdSize
      IdxLocalSym = reader.ReadUInt32 (span, 8)
      NumLocalSym = reader.ReadUInt32 (span, 12)
      IdxExtSym = reader.ReadUInt32 (span, 16)
      NumExtSym = reader.ReadUInt32 (span, 20)
      IdxUndefSym = reader.ReadUInt32 (span, 24)
      NumUndefSym = reader.ReadUInt32 (span, 28)
      TOCOffset = reader.ReadUInt32 (span, 32)
      NumTOCContents = reader.ReadUInt32 (span, 36)
      ModTabOff = reader.ReadUInt32 (span, 40)
      NumModTab = reader.ReadUInt32 (span, 44)
      ExtRefSymOff = reader.ReadUInt32 (span, 48)
      NumExtRefSym = reader.ReadUInt32 (span, 52)
      IndirectSymOff = reader.ReadUInt32 (span, 56)
      NumIndirectSym = reader.ReadUInt32 (span, 60)
      ExtRelOff = reader.ReadUInt32 (span, 64)
      NumExtRel = reader.ReadUInt32 (span, 68)
      LocalRelOff = reader.ReadUInt32 (span, 72)
      NumLocalRel = reader.ReadUInt32 (span, 76) }

  let parseMainCmd toolBox cmdType cmdSize (span: ByteSpan) =
    let reader = toolBox.Reader
    { Cmd = cmdType
      CmdSize = uint32 cmdSize
      EntryOff = reader.ReadUInt64 (span, 8) + toolBox.BaseAddress
      StackSize = reader.ReadUInt64 (span, 16) }

  /// Read lc_str string.
  let readLCStr toolBox cmdSize (span: ByteSpan) =
    let strOffset = toolBox.Reader.ReadInt32 (span, 8)
    let strLen = cmdSize - strOffset
    ByteArray.extractCStringFromSpan (span.Slice (strOffset, strLen)) 0

  let parseDyLibCmd toolBox cmdType cmdSize (span: ByteSpan) =
    let reader = toolBox.Reader
    { Cmd = cmdType
      CmdSize = uint32 cmdSize
      DyLibName = readLCStr toolBox cmdSize span
      DyLibTimeStamp = reader.ReadUInt32 (span, 12)
      DyLibCurVer = reader.ReadUInt32 (span, 16)
      DyLibCmpVer = reader.ReadUInt32 (span, 20) }

  let parseDyLdInfo toolBox cmdType cmdSize (span: ByteSpan) =
    let reader = toolBox.Reader
    { Cmd = cmdType
      CmdSize = uint32 cmdSize
      RebaseOff = reader.ReadInt32 (span, 8)
      RebaseSize = reader.ReadUInt32 (span, 12)
      BindOff = reader.ReadInt32 (span, 16)
      BindSize = reader.ReadUInt32 (span, 20)
      WeakBindOff = reader.ReadInt32 (span, 24)
      WeakBindSize = reader.ReadUInt32 (span, 28)
      LazyBindOff = reader.ReadInt32 (span, 32)
      LazyBindSize = reader.ReadUInt32 (span, 36)
      ExportOff = reader.ReadInt32 (span, 40)
      ExportSize = reader.ReadUInt32 (span, 44) }

  let parseFuncStarts toolBox cmdType cmdSize (span: ByteSpan) =
    let reader = toolBox.Reader
    { Cmd = cmdType
      CmdSize = uint32 cmdSize
      DataOffset = reader.ReadInt32 (span, 8)
      DataSize = reader.ReadUInt32 (span, 12) }

  let parseCmd ({ Bytes = bytes; Reader = reader } as toolBox) offset =
    let cmdHdr = ReadOnlySpan (bytes, int offset, 8)
    let cmdType = reader.ReadInt32 (cmdHdr, 0) |> LanguagePrimitives.EnumOfValue
    let cmdSize = reader.ReadInt32 (cmdHdr, 4)
    let cmdOffset = int (offset - toolBox.MachOffset)
    let span = ReadOnlySpan (bytes, int offset, cmdSize)
    let command =
      match cmdType with
      | LoadCmdType.LC_SEGMENT
      | LoadCmdType.LC_SEGMENT64 ->
        Segment (parseSegCmd toolBox cmdOffset cmdType cmdSize span)
      | LoadCmdType.LC_SYMTAB ->
        SymTab (parseSymCmd toolBox cmdType cmdSize span)
      | LoadCmdType.LC_DYSYMTAB ->
        DySymTab (parseDySymCmd toolBox cmdType cmdSize span)
      | LoadCmdType.LC_MAIN ->
        Main (parseMainCmd toolBox cmdType cmdSize span)
      | LoadCmdType.LC_LOAD_DYLIB ->
        DyLib (parseDyLibCmd toolBox cmdType cmdSize span)
      | LoadCmdType.LC_DYLD_INFO
      | LoadCmdType.LC_DYLD_INFO_ONLY ->
        DyLdInfo (parseDyLdInfo toolBox cmdType cmdSize span)
      | LoadCmdType.LC_FUNCTION_STARTS ->
        FuncStarts (parseFuncStarts toolBox cmdType cmdSize span)
      | _ ->
        Unhandled { Cmd = cmdType; CmdSize = uint32 cmdSize }
    struct (command, uint64 cmdSize)

  let parse ({ Header = hdr } as toolBox) =
    let mutable cmdOffset = pickNum hdr.Class 28UL 32UL + toolBox.MachOffset
    let numCmds = Convert.ToInt32 hdr.NumCmds
    let cmds = Array.zeroCreate numCmds
    for i = 0 to numCmds - 1 do
      let struct (cmd, cmdSize) = parseCmd toolBox cmdOffset
      cmds[i] <- cmd
      cmdOffset <- cmdOffset + cmdSize
    cmds
