(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>

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

namespace B2R2.BinFile.Mach

open System
open B2R2
open B2R2.BinFile

/// Magic number for Mach-O header.
type Magic =
  /// The file is intended for use on a CPU with the same endianness as the
  /// computer on which the compiler is running (32-bit CPU).
  | MHMagic = 0xFEEDFACEu
  /// The byte ordering scheme of the target machine is the reverse of the host
  /// CPU (32-bit CPU).
  | MHCigam = 0xCEFAEDFEu
  /// The file is intended for use on a CPU with the same endianness as the
  /// computer on which the compiler is running (64-bit CPU).
  | MHMagic64 = 0xFEEDFACFu
  /// The byte ordering scheme of the target machine is the reverse of the host
  /// CPU (64-bit CPU).
  | MHCigam64 = 0xCFFAEDFEu
  /// The file is intended for use on multiple architectures (FAT binary). This
  /// value is used on a big-endian host.
  | FATMagic = 0xCAFEBABEu
  /// The file is intended for use on multiple architectures (FAT binary). This
  /// value is used on a little-endian host.
  | FATCigam = 0xBEBAFECAu

/// CPUType indicates the architecture.
type CPUType =
  | Any = 0xFFFFFFFF
  | VAX = 0x00000001
  | ROMP = 0x00000002
  | NS32032 = 0x00000004
  | NS32332 = 0x00000005
  | MC680x0 = 0x00000006
  | I386 = 0x00000007
  | X64 = 0x01000007
  | MIPS = 0x00000008
  | NS32532 = 0x00000009
  | HPPA = 0x0000000B
  | ARM = 0x0000000C
  | MC88000 = 0x0000000D
  | SPARC = 0x0000000E
  | I860 = 0x0000000F
  | I860LITTLE = 0x00000010
  | RS6000 = 0x00000011
  | POWERPC = 0x00000012
  | ABI64 = 0x01000000
  | POWERPC64 = 0x01000012
  | VEO = 0x000000FF
  | ARM64 = 0x0100000C

/// CPUSubType specifies the exact model of the CPU.
type CPUSubType =
  | MIPSAll = 0
  | MIPSR2300 = 1
  | MIPSR2600 = 2
  | MIPSR2800 = 3
  | MIPSR2000A = 4

/// Usage of the file.
type MachFileType =
  /// Intermediate object files.
  | MHObject = 0x1
  /// Standard executable programs.
  | MHExecute = 0x2
  /// Fixed VM shared library file.
  | MHFvmlib = 0x3
  /// Core file.
  | MHCore = 0x4
  /// Preloaded executable file.
  | MHPreload = 0x5
  /// Dynamically bound shared library file.
  | MHDylib = 0x6
  /// Dynamically bound shared library file.
  | MHDylinker = 0x7
  /// Dynamically bound bundle file.
  | MHDybundle = 0x8
  /// Shared library stub for static linking only, no section contents.
  | MHDylibStub = 0x9
  /// Companion file with only debug sections.
  | MHDsym = 0xa
  /// x86_64 kexts.
  | MHKextBundle = 0xb

/// Attribute of the file.
[<FlagsAttribute>]
type MachFlag =
  /// The object file has no undefined references.
  | MHNoUndefs = 0x1
  /// The object file is the output of an incremental link against a base file
  /// and can't be linked against a base file and can't be link edited again.
  | MHIncrLink = 0x2
  /// The object file is input for the dynamic linker and can't be statically
  /// link edited again.
  | MHDYLDLink = 0x4
  /// The object file's undefined references are bound by the dynamic linker
  /// when loaded.
  | MHBinDatLoad = 0x8
  /// The file has its dynamic undefined references prebound.
  | MHPreBound = 0x10
  /// The file has its read-only and read-write segments split.
  | MHSplitSegs = 0x20
  /// the shared library init routine is to be run lazily via catching memory
  /// faults to its writeable segments (obsolete).
  | MHLazyInit = 0x40
  /// The image is using two-level name space bindings.
  | MHTwoLevel = 0x80
  /// The executable is forcing all images to use flat name space bindings.
  | MHForceFlat = 0x100
  /// This umbrella guarantees no multiple defintions of symbols in its
  /// sub-images so the two-level namespace hints can always be used.
  | MHNoMultiDefs = 0x200
  /// Do not have dyld notify the prebinding agent about this executable.
  | MHNoFixPrebinding = 0x400
  /// the binary is not prebound but can have its prebinding redone. only used
  /// when MHPreBound is not set.
  | MHPrebindable = 0x800
  /// Indicates that this binary binds to all two-level namespace modules of
  /// its dependent libraries. only used when MH_PREBINDABLE and MH_TWOLEVEL
  /// are both set.
  | MHAllModsBound = 0x1000
  /// Safe to divide up the sections into sub-sections via symbols for dead code
  /// stripping.
  | MHSubsectionsViaSymbols = 0x2000
  /// The binary has been canonicalized via the unprebind operation.
  | MHCanonical = 0x4000
  /// The final linked image contains external weak symbols.
  | MHWeakDefines = 0x8000
  /// The final linked image uses weak symbols.
  | MHBindsToWeak = 0x10000
  /// When this bit is set, all stacks in the task will be given stack execution
  /// privilege. Only used in MHExecute filetypes.
  | MHAllowStackExecution = 0x20000
  /// When this bit is set, the binary declares it is safe for use in processes
  /// with uid zero.
  | MHRootSafe = 0x40000
  /// When this bit is set, the binary declares it is safe for use in processes
  /// when issetugid() is true.
  | MHSetUIDSafe = 0x80000
  /// When this bit is set on a dylib, the static linker does not need to
  /// examine dependent dylibs to see if any are re-exported.
  | MHNoReexportedDylibs = 0x100000
  /// When this bit is set, the OS will load the main executable at a random
  /// address.
  | MHPIE = 0x200000
  /// Only for use on dylibs.  When linking against a dylib that has this bit
  /// set, the static linker will automatically not create a LCLoadDyLib load
  /// command to the dylib if no symbols are being referenced from the dylib.
  | MHDeadStrippableDYLIB = 0x400000
  /// Contains a section of type ThreadLocalVariables.
  | MHHasTLVDescriptors = 0x800000
  /// When this bit is set, the OS will run the main executable with a
  /// non-executable heap even on platforms (e.g. i386) that don't require it.
  /// Only used in MHExecute filetypes.
  | MHNoHeapExecution = 0x1000000
  /// The code was linked for use in an application extension.
  | MHAppExtensionSafe = 0x02000000

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

/// Load command type.
type LoadCmdType =
  /// Defines a segment of this file to be mapped into the address space of the
  /// process that loads this file. It also includes all the sections contained
  /// by the segment.
  | LCSegment = 0x01
  /// The symbol table for this file.
  | LCSymTab = 0x02
  /// The gdb symbol table info (obsolete).
  | LCSymSeg = 0x03
  /// This command defines the initial thread state of the main thread of the
  /// process. LCThread is similar to LCUnixThread but does not cause the kernel
  /// to allocate a stack.
  | LCThread = 0x04
  /// This command defines the initial thread state of the main thread of the
  /// process.
  | LCUnixThread = 0x05
  /// Load a specified fixed VM shared library.
  | LCLoadFVMLib = 0x06
  /// Fixed VM shared library identification.
  | LCIDFVMLib = 0x07
  /// Object identification info (obsolete).
  | LCIdent = 0x08
  /// Fixed VM file inclusion (internal use).
  | LCFVMFile = 0x09
  /// Prepage command (internal use).
  | LCPrepage = 0x0A
  /// Dynamic link-edit symbol table info.
  | LCDySymTab = 0x0B
  /// Load a dynamically linked shared library.
  | LCLoadDyLib = 0x0C
  /// This command Specifies the install name of a dynamic shared library.
  | LCIDDyLib = 0x0D
  /// Load a dynamic linker.
  | LCLoadDyLink = 0x0E
  /// Dynamic linker identification.
  | LCIDDyLink = 0x0F
  /// Modules prebound for a dynamically linked shared library.
  | LCPreboundDyLib = 0x10
  /// Image routines.
  | LCRoutines = 0x11
  /// Sub framework.
  | LCSubFramework = 0x12
  /// Sub umbrella.
  | LCSubUmbrella = 0x13
  /// Sub client.
  | LCSubClient = 0x14
  /// Sub library.
  | LCSubLib = 0x15
  /// Two-level namespace lookup hints
  | LCTwoLevelHints = 0x16
  /// Prebind checksum.
  | LCPrebindCksum = 0x17
  /// Load a dynamically linked shared library that is allowed to be missing.
  | LCLoadWeakDyLib = 0x80000018
  /// 64-bit segment of this file to be mapped.
  | LCSegment64 = 0x19
  /// 64-bit image routines.
  | LCRoutines64 = 0x1A
  /// The uuid.
  | LCUUID = 0x1B
  /// Runpath additions.
  | LCRunPath = 0x8000001C
  /// Local of code signature.
  | LCCodeSign = 0x1D
  /// Local of info to split segments
  | LCSegSplitInfo = 0x1E
  /// Load and re-export dylib.
  | LCReExportDyLib = 0x1F
  /// Delay load of dylib until first use.
  | LCLazyLoadDyLib = 0x20
  /// Encrypted segment information.
  | LCEncSegInfo = 0x21
  /// Compressed dyld information.
  | LCDyLDInfo = 0x22
  /// Compressed dyld information only.
  | LCDyLDInfoOnly = 0x80000022
  /// Load upward dylib.
  | LCLoadUpwardDyLib = 0x80000023
  /// Build for MacOSX min OS version.
  | LCVerMinMacOSX = 0x24
  /// Build for iPhoneOS min OS version.
  | LCVerMinIphoneOS = 0x25
  /// Compressed table of function start addresses.
  | LCFunStarts = 0x26
  /// String for dyld to treat like environment variable.
  | LCDyLDEnv = 0x27
  /// Replacement for LC_UNIXTHREAD.
  | LCMain = 0x80000028
  /// Table of non-instructions in __text.
  | LCDataInCode = 0x29
  /// Source version used to build binary.
  | LCSourceVer = 0x2A
  /// Code signing DRs copied from linked dylibs.
  | LCDyLibCodeSigDRS = 0x2B
  /// 64-bit encrypted segment information.
  | LCEncInfo64 = 0x2C
  /// Linker options in MH_OBJECT files.
  | LCLinkOpt = 0x2D
  /// Optimization hints in MH_OBJECT files.
  | LCLinkOptimizeHint = 0x2E
  /// Build for Watch min OS version
  | LCVerMinWatchOS = 0x30

/// The load command structures are located directly after the header of the
/// object file, and they specify both the logical structure of the file and the
/// layout of the file in virtual memory.
type LoadCommand =
  | Segment of SegCmd
  | SymTab of SymTabCmd
  | DySymTab of DySymTabCmd
  | DyLib of DyLibCmd
  | Main of MainCmd
  | Unhandled of UnhandledCommand

/// Segment command.
and SegCmd = {
  /// The offset of the sections in the segment. If the segment has sections
  /// then the section structures directly follow the segment command and their
  /// size is in the size of the command.
  SecOff: int
  /// Segment name.
  SegName: string
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

/// Main command.
and MainCmd = {
  /// Offset of main().
  EntryOff: Addr
  /// Initial stack size, if not zero.
  StackSize: uint64
}

/// Dynamic library command: the data used by the dynamic linker to match a
/// shared library against the files that have linked to it.
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

/// This type represents a load command unhandled by B2R2.
and UnhandledCommand = {
  Cmd: LoadCmdType
  CmdSize: uint32
}

/// Section type.
type SectionType =
  /// Regular section.
  | Regular = 0x0
  /// Zero fill on demand section.
  | ZeroFill = 0x1
  /// Section with only literal C strings.
  | CStringLiterals = 0x2
  /// Section with only 4 byte literals.
  | FourByteLiterals = 0x3
  /// Section with only 8 byte literals.
  | EightByteLiterals = 0x4
  /// section with only pointers to literals.
  | LiteralPointers = 0x5
  /// Section with only non-lazy symbol pointers .
  | NonLazySymbolPointers = 0x6
  /// Section with only lazy symbol pointers.
  | LazySymbolPointers = 0x7
  /// Section with only symbol stubs, byte size of stub in the reserved2 field.
  | SymbolStubs = 0x8
  /// Section with only function pointers for initialization.
  | ModInitFuncPointers = 0x9
  /// Section with only function pointers for termination.
  | ModTermFuncPointers = 0xa
  /// Section contains symbols that are to be coalesced.
  | Coalesced = 0xb
  /// Zero fill on demand section (this can be larger than 4 gigabytes).
  | GBZeroFill = 0xc
  /// Section with only pairs of function pointers for interposing.
  | Interposing = 0xd
  /// Section with only 16 byte literals.
  | SixteenByteLiterals = 0xe
  /// Section contains DTrace Object Format.
  | DTraceDOF = 0xf
  /// Section with only lazy symbol pointers to lazy loaded dylibs.
  | LazyDyLibSymbolPointers = 0x10
  /// Template of initial values for TLVs.
  | ThreadLocalRegular = 0x11
  /// Template of initial values for TLVs.
  | ThreadLocalZeroFill = 0x12
  /// TLV descriptors.
  | ThreadLocalVariables = 0x13
  /// Pointers to TLV descriptors.
  | ThreadLocalVariablePointers = 0x14
  /// Functions to call to initialize TLV values .
  | ThreadLocalInitFunctionPointers = 0x15

/// Section attribute.
[<FlagsAttribute>]
type SectionAttribute =
  /// Section contains only true machine instructions.
  | AttrPureInstructions = 0x80000000
  /// Section contains coalesced symbols that are not to be in a ranlib table of
  /// contents.
  | AttrNoTOC = 0x40000000
  /// OK to strip static symbols in this section in files with the MH_DYLDLINK
  /// flag.
  | AttrStripStaticSyms = 0x20000000
  /// No dead stripping.
  | AttrNoDeadStrip = 0x10000000
  /// Blocks are live if they reference live blocks.
  | AttrLiveSupport = 0x08000000
  /// Used with i386 code stubs written on by dyld.
  | AttrSelfModifyingCode = 0x04000000
  /// Debug section.
  | AttrDebug = 0x02000000
  /// Section has external relocation entries.
  | AttrExtReloc = 0x00000200
  /// Section has local relocation entries.
  | AttrLocReloc = 0x00000100

/// Mach-O section.
type MachSection = {
  /// Section name.
  SecName: string
  /// The name of the segment that should eventually contain this section.
  SegName: string
  /// The virtual memory address of this section.
  SecAddr: Addr
  /// The size of this section.
  SecSize: uint64
  /// The offset to this section in the file.
  SecOffset: uint32
  /// The section’s byte alignment.
  SecAlignment: uint32
  /// The file offset of the first relocation entry for this section.
  SecRelOff: uint32
  /// The number of relocation entries located at SecRelOff for this section.
  SecNumOfReloc: uint32
  /// Section type.
  SecType: SectionType
  /// Section attributes.
  SecAttrib: SectionAttribute
  /// Reserved field 1.
  SecReserved1: int
  /// Reserved field 2.
  SecReserved2: int
}

/// Section information.
type SectionInfo = {
  SecByAddr  : ARMap<MachSection>
  SecByName  : Map<string, MachSection>
  SecByNum   : MachSection []
}

/// Symbol type (N_TYPE).
type SymbolType =
  /// The symbol is undefined.
  | NUndef = 0x0
  /// The symbol is absolute. The linker does not update the value of an
  /// absolute symbol.
  | NAbs = 0x2
  /// The symbol is defined in the section number given in n_sect.
  | NSect = 0xe
  /// The symbol is undefined and the image is using a prebound value for the
  /// symbol.
  | NPreBnd = 0xc
  /// The symbol is defined to be the same as another symbol.
  | NIndirect = 0xa
  /// Global symbol.
  | NGSym = 0x20
  /// Procedure name (f77 kludge).
  | NFName = 0x22
  /// Procedure.
  | NFun = 0x24
  /// Static symbol.
  | NStSym = 0x26
  /// .lcomm symbol.
  | NLCSym = 0x28
  /// Begin nsect sym.
  | NBnSym = 0x2e
  /// AST file path.
  | NAST = 0x32
  /// Emitted with gcc2_compiled and in gcc source.
  | NOpt = 0x3c
  /// Register sym.
  | NRSym = 0x40
  /// Source line.
  | NSLine = 0x44
  /// End nsect sym.
  | NEnSym = 0x4e
  /// Structure element.
  | NSSym = 0x60
  /// Source file name.
  | NSO = 0x64
  /// Object file name.
  | NOSO = 0x66
  /// Local symbol.
  | NLSym = 0x80
  /// Include file beginning.
  | NBIncl = 0x82
  /// "#included" file name: name,,n_sect,0,address.
  | NSOL = 0x84
  /// Compiler parameters.
  | NParams = 0x86
  /// Compiler version.
  | NVersion = 0x88
  /// Compiler optimization level.
  | NOLevel = 0x8a
  /// Parameter.
  | NPSym = 0xa0
  /// Include file end.
  | NEIncl = 0xa2
  /// Alternate entry.
  | NEntry = 0xa4
  /// Left bracket.
  | NLBrac = 0xc0
  /// Deleted include file.
  | NExcl = 0xc2
  /// Right bracket.
  | NRBrac = 0xe0
  /// Begin common.
  | NBComm = 0xe2
  /// End common.
  | NEComm = 0xe4
  /// End common (local name).
  | NEComL = 0xe8
  /// Second stab entry with length information.
  | NLeng = 0xfe
  /// Global pascal symbol.
  | NPC = 0x30

/// Mach-O symbol.
type MachSymbol = {
  /// Symbol name.
  SymName    : string
  /// Symbol type (N_TYPE field of n_type).
  SymType    : SymbolType
  /// Is this an external symbol?
  IsExternal : bool
  /// The number of the section that this symbol can be found.
  SecNum     : byte
  /// Providing additional information about the nature of this symbol for
  /// non-stab symbols.
  SymDesc    : int16
  /// External library version info.
  VerInfo    : DyLibCmd option
  /// Address of the symbol.
  SymAddr    : Addr
}

/// Symbol info
type SymInfo = {
  /// All symbols.
  Symbols: MachSymbol []
  /// Address to symbol mapping.
  SymbolMap: Map<Addr, MachSymbol>
  /// Linkage table.
  LinkageTable: LinkageTableEntry list
}

/// Main mach-o file structure.
type Mach = {
  /// Entry point.
  EntryPoint: Addr
  /// Header.
  MachHdr: MachHeader
  /// Segments.
  Segments: SegCmd list
  /// Segment address map.
  SegmentMap: ARMap<SegCmd>
  /// Sections.
  Sections: SectionInfo
  /// Symbol info.
  SymInfo: SymInfo
  /// BinReader.
  BinReader: BinReader
}
