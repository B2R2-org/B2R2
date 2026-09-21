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
type internal LoadCommand =
  /// Segment command (LC_SEGMENT or LC_SEGMENT_64).
  | Segment of cmd: CmdType * size: uint32 * SegCmd
  /// Symbol table command (LC_SYMTAB).
  | SymTab of cmd: CmdType * size: uint32 * SymTabCmd
  /// Dynamic symbol table command (LC_DYSYMTAB).
  | DySymTab of cmd: CmdType * size: uint32 * DySymTabCmd
  /// Dynamic shared library command: LC_LOAD_DYLIB, or one of the variants
  /// that load a library on their own terms (LC_LOAD_WEAK_DYLIB,
  /// LC_REEXPORT_DYLIB, LC_LOAD_UPWARD_DYLIB, LC_LAZY_LOAD_DYLIB). They share
  /// this case because a dylib ordinal counts every one of them, in the order
  /// they appear, so leaving any out would shift the rest.
  | DyLib of cmd: CmdType * size: uint32 * DyLibCmd
  /// Dynamic shared library identification command (LC_ID_DYLIB), carrying
  /// the name this library announces for itself. Kept apart from DyLib so
  /// that it takes no library ordinal, which only a loaded one has.
  | DyLibId of cmd: CmdType * size: uint32 * DyLibCmd
  /// Linker option command (LC_LINKER_OPTION), carrying the arguments an
  /// object file asks the linker for, as clang's autolinking writes -lfoo
  /// and -framework Bar. Only an MH_OBJECT holds them; by the time it is
  /// linked, what it needed is named by LC_LOAD_DYLIB instead.
  | LinkerOption of cmd: CmdType * size: uint32 * options: string[]
  /// Dynamic linker command (LC_LOAD_DYLINKER), carrying the path to the
  /// dynamic linker requested by this binary.
  | DyLinker of cmd: CmdType * size: uint32 * path: string
  /// Runpath command (LC_RPATH), carrying a runtime library search path.
  | Rpath of cmd: CmdType * size: uint32 * path: string
  /// Universally unique identifier command (LC_UUID), carrying the sixteen
  /// bytes that name this particular build of the binary.
  | Uuid of cmd: CmdType * size: uint32 * uuid: byte[]
  /// Dynamic linker information command (LC_DYLD_INFO or LC_DYLD_INFO_ONLY).
  | DyLdInfo of cmd: CmdType * size: uint32 * DyLdInfoCmd
  /// Function starts command (LC_FUNCTION_STARTS).
  | FuncStarts of cmd: CmdType * size: uint32 * FuncStartsCmd
  /// Chained fixups command (LC_DYLD_CHAINED_FIXUPS).
  | ChainedFixups of cmd: CmdType * size: uint32 * ChainedFixupsCmd
  /// Exports trie command (LC_DYLD_EXPORTS_TRIE), which carries the export
  /// trie that LC_DYLD_INFO used to embed.
  | ExportsTrie of cmd: CmdType * size: uint32 * ExportsTrieCmd
  /// Code signature command (LC_CODE_SIGNATURE), which points at the
  /// superblob in __LINKEDIT that names the code, hashes it page by page and
  /// carries whatever entitlements and signer go with it.
  | CodeSign of cmd: CmdType * size: uint32 * CodeSignCmd
  /// Data-in-code command (LC_DATA_IN_CODE), which lists the ranges of a text
  /// section that hold data rather than instructions.
  | DataInCode of cmd: CmdType * size: uint32 * DataInCodeCmd
  /// Encryption information command (LC_ENCRYPTION_INFO or
  /// LC_ENCRYPTION_INFO_64), which names the part of the image that ships
  /// encrypted, as the App Store leaves a text segment.
  | EncryptionInfo of cmd: CmdType * size: uint32 * EncryptionInfoCmd
  /// Fileset entry command (LC_FILESET_ENTRY), which names one of the images
  /// a container holds, as a kernel collection names each of its kexts.
  | FilesetEntry of cmd: CmdType * size: uint32 * FilesetEntryCmd
  /// Main command (LC_MAIN).
  | Main of cmd: CmdType * size: uint32 * MainCmd
  /// Thread state command (LC_THREAD or LC_UNIXTHREAD), which is how a binary
  /// older than LC_MAIN names its entry point: as the program counter of the
  /// initial thread rather than as an offset. None when the command carries no
  /// state this parser knows the layout of.
  | Thread of cmd: CmdType * size: uint32 * pc: Addr option
  /// Image routines command (LC_ROUTINES or LC_ROUTINES64), which names the
  /// initialization routine of a library built before the __mod_init_func
  /// pointer array took the job over. None when the command names none,
  /// which is what a zero init_address says.
  | Routines of cmd: CmdType * size: uint32 * initAddr: Addr option
  /// Build version command: LC_BUILD_VERSION, or one of the LC_VERSION_MIN_*
  /// commands it replaced. An older one names its platform by which of the
  /// four commands it is rather than by a field, and carries no tool table,
  /// so both forms are read into the one record.
  | BuildVersion of cmd: CmdType * size: uint32 * BuildVersionCmd
  /// Unhandled command.
  | Unhandled of cmd: CmdType * size: uint32

/// Represents a segment command.
and internal SegCmd =
  { /// The offset of the sections in the segment. If the segment has sections
    /// then the section structures directly follow the segment command
    ///  and their size is in the size of the command.
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
    SegFlag: uint32 }

/// Represents a symbol table command.
and internal SymTabCmd =
  { /// An integer containing the byte offset from the start of the file to the
    /// location of the symbol table entries.
    SymOff: int
    /// An integer indicating the number of entries in the symbol table.
    NumOfSym: uint32
    /// An integer containing the byte offset from the start of the image to the
    /// location of the string table.
    StrOff: int
    /// An integer indicating the size (in bytes) of the string table.
    StrSize: uint32 }

/// Represents a dynamic symbol table command.
and internal DySymTabCmd =
  { /// An integer indicating the index of the first symbol in the group
    /// of local symbols.
    IdxLocalSym: uint32
    /// An integer indicating the total number of symbols in the group of local
    /// symbols.
    NumLocalSym: uint32
    /// An integer indicating the index of the first symbol in the group of
    /// defined external symbols.
    IdxExtSym: uint32
    /// An integer indicating the total number of symbols in the group
    /// of defined external symbols.
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
    /// An integer indicating the number of entries in the indirect
    /// symbol table.
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
    /// An integer indicating the number of entries in the local
    /// relocation table.
    NumLocalRel: uint32 }

/// Represents a DYLD information command (dyld_info_command).
and internal DyLdInfoCmd =
  { /// File offset to rebase info.
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
    ExportSize: uint32 }

/// Represents a function starts command (LC_FUNCTION_STARTS).
and internal FuncStartsCmd =
  { DataOffset: int
    DataSize: uint32 }

/// Represents a chained fixups command (LC_DYLD_CHAINED_FIXUPS). It points to
/// the dyld_chained_fixups_header located in the __LINKEDIT segment.
and internal ChainedFixupsCmd =
  { /// File offset to the chained fixups data.
    FixupsDataOffset: int
    /// Size of the chained fixups data.
    FixupsDataSize: uint32 }

/// Represents an exports trie command (LC_DYLD_EXPORTS_TRIE). It points to the
/// export trie in the __LINKEDIT segment.
and internal ExportsTrieCmd =
  { /// File offset to the export trie.
    TrieOffset: int
    /// Size of the export trie.
    TrieSize: uint32 }

/// Represents a code signature command (LC_CODE_SIGNATURE). It points to the
/// CS_SuperBlob in the __LINKEDIT segment, which sits at the very end of a
/// signed image because everything before it is what the signature covers.
and internal CodeSignCmd =
  { /// File offset to the superblob.
    BlobOffset: int
    /// Size of the superblob.
    BlobSize: uint32 }

/// Represents a data-in-code command (LC_DATA_IN_CODE). It points to a table
/// of data_in_code_entry records in the __LINKEDIT segment, each of which
/// gives an image-relative start, a length, and the kind of data.
and internal DataInCodeCmd =
  { /// File offset to the table.
    TableOffset: int
    /// Size of the table.
    TableSize: uint32 }

/// Represents an encryption information command (LC_ENCRYPTION_INFO and
/// LC_ENCRYPTION_INFO_64). The 64-bit form only pads the 32-bit one out, so
/// the three fields read here sit at the same offsets in both.
and internal EncryptionInfoCmd =
  { /// File offset of the encrypted range, from the start of the image.
    CryptOffset: int
    /// The number of bytes that are encrypted.
    CryptSize: uint32
    /// The encryption system in use. Zero means the range is not encrypted
    /// yet, which is what a linker writes and only a re-signer replaces.
    CryptId: uint32 }

/// Represents a fileset entry command (LC_FILESET_ENTRY). The load commands
/// of the image it names give offsets into the container rather than into the
/// image, which is what tells a fileset apart from a universal binary.
and internal FilesetEntryCmd =
  { /// The address the image is mapped at.
    EntryVMAddr: Addr
    /// The offset of the image within the container file.
    EntryFileOffset: uint64
    /// What the container calls the image, e.g., com.apple.kernel.
    EntryName: string }

/// Represents a main command.
and internal MainCmd =
  { /// Offset of main() from the start of the Mach-O header, which is where
    /// the image begins, so it is a file offset rather than an address.
    EntryOff: uint64
    /// Initial stack size, if not zero.
    StackSize: uint64 }

/// Represents a dynamic library command: the data used by the dynamic linker to
/// match a shared library against the files that have linked to it.
and internal DyLibCmd =
  { /// Library's path name.
    DyLibName: string
    /// Library's build time stamp.
    DyLibTimeStamp: uint32
    /// Library's current version number.
    DyLibCurVer: uint32
    /// Library's compatibility vers number.
    DyLibCmpVer: uint32 }

/// Represents a build version command (LC_BUILD_VERSION), which names what the
/// image was built for and with. The LC_VERSION_MIN_* commands it replaced
/// name the same thing in less detail, and are read into this too: one of them
/// names its platform by being the command it is, and names no tool at all.
and internal BuildVersionCmd =
  { /// The platform the image is built to run on.
    Platform: Platform
    /// The oldest version of that platform the image runs on, packed with the
    /// major version in the upper sixteen bits and the minor and the patch
    /// version in a byte each below it.
    MinOSVersion: uint32
    /// The version of the SDK the image was built against, packed the same
    /// way. Zero when the image names none.
    SDKVersion: uint32
    /// The tools that built the image, in the order the command names them.
    /// Empty for an LC_VERSION_MIN_* command, which carries no tool table.
    BuildTools: BuildTool[] }

/// Represents one entry of the tool table that an LC_BUILD_VERSION carries.
and internal BuildTool =
  { /// The tool that took part in building the image.
    Tool: BuildToolKind
    /// The tool's version, packed the way a platform version is.
    ToolVersion: uint32 }
