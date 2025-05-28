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

open B2R2

/// Represents a load command in a Mach-O file. Load commands are used to
/// specify the logical structure and the layout of the Mach-O file.
type LoadCommand =
  /// Segment command (LC_SEGMENT or LC_SEGMENT_64).
  | Segment of cmd: CmdType * size: uint32 * SegCmd
  /// Symbol table command (LC_SYMTAB).
  | SymTab of cmd: CmdType * size: uint32* SymTabCmd
  /// Dynamic symbol table command (LC_DYSYMTAB).
  | DySymTab of cmd: CmdType * size: uint32* DySymTabCmd
  /// Dynamic shared library command (LC_LOAD_DYLIB).
  | DyLib of cmd: CmdType * size: uint32* DyLibCmd
  /// Dynamic linker information command (LC_DYLD_INFO or LC_DYLD_INFO_ONLY).
  | DyLdInfo of cmd: CmdType * size: uint32* DyLdInfoCmd
  /// Function starts command (LC_FUNCTION_STARTS).
  | FuncStarts of cmd: CmdType * size: uint32* FuncStartsCmd
  /// Main command (LC_MAIN).
  | Main of cmd: CmdType * size: uint32* MainCmd
  /// Unhandled command.
  | Unhandled of cmd: CmdType * size: uint32

/// Represents a segment command.
and SegCmd = {
  /// The offset of the sections in the segment. If the segment has sections
  /// then the section structures directly follow the segment command and their
  /// size is in the size of the command.
  SecOff: int
  /// Segment name.
  SegCmdName: string
  /// The starting virtual memory address of this segment.
  VMAddr: Addr
  /// The number of bytes of virtual memory occupied by this segment.
  VMSize: uint64
  /// The offset in this file of the data to be mapped at VMAddr.
  FileOff: Addr
  /// The number of bytes occupied by this segment on disk.
  FileSize: uint64
  /// The maximum permitted virtual memory protections of this segment.
  MaxProt: int
  /// The initial virtual memory protections of this segment.
  InitProt: int
  /// The number of section data structures following this load command.
  NumSecs: uint32
  /// A set of flags that affect the loading of this segment.
  SegFlag: uint32
}

/// Represents a symbol table command.
and SymTabCmd = {
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

/// Represents a dynamic symbol table command.
and DySymTabCmd = {
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

/// Represents a DYLD information command (dyld_info_command).
and DyLdInfoCmd = {
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

/// Represents a function starts command (LC_FUNCTION_STARTS).
and FuncStartsCmd = {
  DataOffset: int
  DataSize: uint32
}

/// Represents a main command.
and MainCmd = {
  /// Offset of main().
  EntryOff: Addr
  /// Initial stack size, if not zero.
  StackSize: uint64
}

/// Represents a dynamic library command: the data used by the dynamic linker to
/// match a shared library against the files that have linked to it.
and DyLibCmd = {
  /// Library's path name.
  DyLibName: string
  /// Library's build time stamp.
  DyLibTimeStamp: uint32
  /// Library's current version number.
  DyLibCurVer: uint32
  /// Library's compatibility vers number.
  DyLibCmpVer: uint32
}
